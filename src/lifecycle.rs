use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use log::{error, info};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::Mutex;
use tokio::sync::mpsc::{channel, Receiver};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::{sleep, Duration};

use crate::config::{ServerConfig, TargetConfigs};
use crate::{config, iptables_util, tcp, udp, QuickAction};

type ServerTask = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

struct PreparedServer {
    task: ServerTask,
    stop: oneshot::Sender<()>,
}

fn start_servers(
    tasks: Vec<PreparedServer>,
    servers: &mut JoinSet<io::Result<()>>,
) -> Vec<oneshot::Sender<()>> {
    tasks
        .into_iter()
        .map(|server| {
            servers.spawn(server.task);
            server.stop
        })
        .collect()
}

async fn stop_servers(
    stops: Vec<oneshot::Sender<()>>,
    servers: &mut JoinSet<io::Result<()>>,
) -> io::Result<()> {
    for stop in stops {
        let _ = stop.send(());
    }
    while let Some(result) = servers.join_next().await {
        result.map_err(io::Error::other)??;
    }
    Ok(())
}

async fn supervise_until<T>(
    servers: &mut JoinSet<io::Result<()>>,
    work: impl Future<Output = T>,
) -> io::Result<T> {
    tokio::pin!(work);
    loop {
        tokio::select! {
            biased;
            finished = servers.join_next(), if !servers.is_empty() => {
                finished.expect("nonempty listener set").map_err(io::Error::other)??;
            }
            result = &mut work => return Ok(result),
        }
    }
}

fn relevant_event(event: &Event, paths: &HashSet<PathBuf>) -> bool {
    matches!(
        event.kind,
        EventKind::Any | EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    ) && event.paths.iter().any(|path| paths.contains(path))
}

struct ConfigWatcher {
    watcher: RecommendedWatcher,
    parents: HashSet<PathBuf>,
    paths: Arc<Mutex<HashSet<PathBuf>>>,
}

impl ConfigWatcher {
    fn refresh(&mut self, config_paths: &[String]) -> io::Result<()> {
        let mut paths = HashSet::new();
        for config_path in config_paths {
            let path = std::path::absolute(config_path)?;
            let parent = std::fs::canonicalize(path.parent().unwrap_or(Path::new("/")))?;
            let name = path
                .file_name()
                .ok_or_else(|| io::Error::other("Invalid config path"))?;
            paths.insert(parent.join(name));
            paths.insert(std::fs::canonicalize(&path)?);
        }
        let parents: HashSet<_> = paths
            .iter()
            .filter_map(|path| path.parent().map(Path::to_path_buf))
            .collect();
        for parent in parents.difference(&self.parents) {
            self.watcher
                .watch(parent, RecursiveMode::NonRecursive)
                .map_err(io::Error::other)?;
        }
        *self.paths.lock() = paths;
        for parent in self.parents.difference(&parents) {
            // Deleted target directories may have already lost their OS watch.
            let _ = self.watcher.unwatch(parent);
        }
        self.parents = parents;
        Ok(())
    }
}

fn watch_configs(config_paths: &[String]) -> io::Result<(ConfigWatcher, Receiver<Event>)> {
    let (tx, rx) = channel(1);
    let paths = Arc::new(Mutex::new(HashSet::new()));
    let event_paths = paths.clone();
    let watcher = notify::recommended_watcher(move |result: notify::Result<Event>| match result {
        Ok(event) if relevant_event(&event, &event_paths.lock()) => {
            let _ = tx.try_send(event);
        }
        Ok(_) => {}
        Err(error) => error!("Config watch error: {error}"),
    })
    .map_err(io::Error::other)?;
    let mut watcher = ConfigWatcher {
        watcher,
        paths,
        parents: HashSet::new(),
    };
    watcher.refresh(config_paths)?;
    Ok((watcher, rx))
}

async fn prepare_servers(
    configs: Vec<ServerConfig>,
    admissions: &mut tcp::Admissions,
    tunnels: &crate::tunnel::Registry,
) -> io::Result<Vec<PreparedServer>> {
    let mut tasks = Vec::new();
    let mut listeners = HashSet::new();
    for config in configs {
        let ServerConfig {
            address,
            use_iptables,
            target_configs,
        } = config;
        let is_tcp = matches!(&target_configs, TargetConfigs::Tcp { .. });
        if !listeners.insert((is_tcp, address)) {
            return Err(io::Error::other(format!("Duplicate listener: {address}")));
        }
        let (stop, stopped) = oneshot::channel();
        let task: ServerTask = match target_configs {
            TargetConfigs::Tcp {
                tcp_max_connections,
                tcp_nodelay,
                tcp_keepalive,
                targets,
            } => {
                let task = tcp::prepare_tcp_server(
                    address,
                    use_iptables,
                    tcp_nodelay,
                    tcp_keepalive,
                    targets.into_vec(),
                    tcp_max_connections,
                    admissions.for_listener(address),
                    tunnels,
                )
                .await?;
                Box::pin(async move {
                    tokio::select! {
                        biased;
                        result = task => result,
                        _ = stopped => Ok(()),
                    }
                })
            }
            TargetConfigs::Udp {
                targets,
                udp_max_associations,
                udp_queue_capacity,
            } => Box::pin(udp::prepare_udp_server(
                address,
                use_iptables,
                udp_max_associations,
                udp_queue_capacity,
                targets.into_vec(),
                stopped,
            )?),
        };
        tasks.push(PreparedServer {
            task: Box::pin(async move {
                task.await.map_err(|error| {
                    io::Error::new(error.kind(), format!("Listener {address} failed: {error}"))
                })
            }),
            stop,
        });
    }
    Ok(tasks)
}

#[cfg(test)]
async fn prepare(
    configs: Vec<ServerConfig>,
    admissions: &mut tcp::Admissions,
) -> io::Result<Vec<PreparedServer>> {
    prepare_servers(configs, admissions, &crate::tunnel::Registry::default()).await
}

async fn prepare_runtime(
    config: config::RuntimeConfig,
    admissions: &mut tcp::Admissions,
    store: &mut crate::tunnel::Store,
) -> io::Result<(Vec<PreparedServer>, crate::tunnel::Prepared)> {
    let tunnels = store.prepare(&config)?;
    let servers = prepare_servers(config.servers, admissions, &tunnels.registry).await?;
    Ok((servers, tunnels))
}

fn firewall_addresses(configs: &[ServerConfig]) -> HashSet<SocketAddr> {
    configs
        .iter()
        .filter(|config| config.use_iptables)
        .map(|config| config.address)
        .collect()
}

async fn clear_rules(addresses: &HashSet<SocketAddr>) -> io::Result<()> {
    for address in addresses {
        iptables_util::clear_matching_iptables(*address).await?;
    }
    Ok(())
}

pub async fn run_standalone(config: ServerConfig, dry_run: bool) -> io::Result<()> {
    let tasks = prepare_servers(
        vec![config],
        &mut tcp::Admissions::default(),
        &crate::tunnel::Registry::default(),
    )
    .await?;
    if dry_run {
        info!("Dry run complete");
        return Ok(());
    }
    let mut servers = JoinSet::new();
    // Retains the stop senders; dropping them would cancel the listeners.
    let _stops = start_servers(tasks, &mut servers);
    while let Some(result) = servers.join_next().await {
        result.map_err(io::Error::other)??;
    }
    Ok(())
}

pub async fn run(
    paths: Vec<String>,
    urls: Vec<String>,
    quick: Option<QuickAction>,
) -> io::Result<()> {
    if quick == Some(QuickAction::ClearIptablesAll) {
        iptables_util::clear_all_iptables().await?;
        info!("iptables cleared of all tobaru rules");
        return Ok(());
    }
    let watch = if quick.is_none() {
        Some(watch_configs(&paths)?)
    } else {
        None
    };
    let configs = config::load_runtime_config(paths.clone(), urls.clone()).await?;
    if configs.is_empty() {
        return Err(io::Error::other("No server configs found"));
    }
    if quick == Some(QuickAction::ClearIptablesMatching) {
        let addresses = configs
            .servers
            .iter()
            .map(|config| config.address)
            .collect();
        clear_rules(&addresses).await?;
        return Ok(());
    }
    let mut firewall = firewall_addresses(&configs.servers);
    let mut admissions = tcp::Admissions::default();
    let mut tunnels = crate::tunnel::Store::default();
    let (tasks, prepared_tunnels) = prepare_runtime(configs, &mut admissions, &mut tunnels).await?;
    if quick == Some(QuickAction::DryRun) {
        info!("Dry run complete");
        return Ok(());
    }
    let (mut watcher, mut changes) =
        watch.expect("normal startup installs config watches before loading");
    clear_rules(&firewall).await?;
    let mut servers = JoinSet::new();
    let mut tunnel_generation = prepared_tunnels.start(&mut servers);
    let mut stops = start_servers(tasks, &mut servers);

    loop {
        if supervise_until(&mut servers, changes.recv())
            .await?
            .is_none()
        {
            return Err(io::Error::other("Config watcher stopped"));
        }
        let replacement = supervise_until(&mut servers, async {
            sleep(Duration::from_secs(3)).await;
            while changes.try_recv().is_ok() {}
            watcher.refresh(&paths)?;
            let configs = config::load_runtime_config(paths.clone(), urls.clone()).await?;
            if configs.is_empty() {
                return Err(io::Error::other("No server configs found"));
            }
            let firewall = firewall_addresses(&configs.servers);
            Ok::<_, io::Error>((
                prepare_runtime(configs, &mut admissions, &mut tunnels).await?,
                firewall,
            ))
        })
        .await?;
        let ((tasks, prepared_tunnels), new_firewall) = match replacement {
            Ok(replacement) => replacement,
            Err(error) => {
                error!("Config reload rejected; keeping running listeners: {error}");
                continue;
            }
        };
        tunnel_generation.retire();
        stop_servers(stops, &mut servers).await?;
        let stale_rules = firewall.union(&new_firewall).copied().collect();
        clear_rules(&stale_rules).await?;
        firewall = new_firewall;
        tunnel_generation = prepared_tunnels.start(&mut servers);
        stops = start_servers(tasks, &mut servers);
        info!("Config reload complete");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{CreateKind, DataChange, MetadataKind, ModifyKind, RemoveKind, RenameMode};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct WatchFiles(PathBuf);

    impl WatchFiles {
        fn new() -> Self {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let parent = PathBuf::from(std::env::var_os("HOME").unwrap()).join("tmp");
            std::fs::create_dir_all(&parent).unwrap();
            loop {
                let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
                let root = parent.join(format!("tobaru-watch-{}-{id}", std::process::id()));
                match std::fs::create_dir(&root) {
                    Ok(()) => {
                        let files = Self(std::fs::canonicalize(root).unwrap());
                        std::fs::create_dir(files.0.join("a")).unwrap();
                        std::fs::create_dir(files.0.join("b")).unwrap();
                        return files;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("Cannot create watcher test directory: {error}"),
                }
            }
        }
    }

    impl Drop for WatchFiles {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn assert_file_changes_observed(
        changes: &mut Receiver<Event>,
        path: &Path,
        contents: &str,
    ) {
        // Drain setup/retarget notifications before making a fresh content edit.
        tokio::time::timeout(Duration::from_secs(3), async {
            while let Ok(event) =
                tokio::time::timeout(Duration::from_millis(100), changes.recv()).await
            {
                event.expect("Config watcher stopped while settling");
            }
        })
        .await
        .expect("Config watcher did not settle before editing");
        let targets = HashSet::from([path.to_path_buf()]);
        std::fs::write(path, contents).unwrap();
        let mut last_event = None;
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            let mut retry = tokio::time::interval(Duration::from_millis(20));
            loop {
                tokio::select! {
                    // The production queue coalesces events. Retry a write if a stale
                    // rename notification occupied its single slot.
                    _ = retry.tick() => std::fs::write(path, contents).unwrap(),
                    event = changes.recv() => {
                        let event = event.unwrap();
                        // FSEvents can deliver Create/Metadata before Data for one write.
                        // The single-slot queue retains a reload trigger, not every kind.
                        if relevant_event(&event, &targets) {
                            break;
                        }
                        last_event = Some(event);
                    }
                }
            }
        })
        .await;
        assert!(
            result.is_ok(),
            "No reload event for {} after {contents:?}; last event: {last_event:?}",
            path.display()
        );
    }

    #[tokio::test]
    async fn config_watches_capture_changes_before_the_first_load() {
        let files = WatchFiles::new();
        let path = files.0.join("config.json");
        std::fs::write(&path, "old").unwrap();
        let (_watcher, mut changes) = watch_configs(&[path.to_str().unwrap().into()]).unwrap();
        let replacement = files.0.join("replacement.json");
        std::fs::write(&replacement, "new").unwrap();
        std::fs::rename(replacement, &path).unwrap();
        let event = tokio::time::timeout(Duration::from_secs(3), changes.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(event.paths.contains(&path));
        assert_eq!(std::fs::read_to_string(path).unwrap(), "new");
    }

    #[tokio::test]
    async fn config_watches_follow_symlink_targets_and_retargeted_links() {
        let files = WatchFiles::new();
        let first = files.0.join("a/config.json");
        let second = files.0.join("b/config.json");
        let link = files.0.join("config.json");
        std::fs::write(&first, "first").unwrap();
        std::fs::write(&second, "second").unwrap();
        std::os::unix::fs::symlink(&first, &link).unwrap();
        let paths = [link.to_str().unwrap().into()];
        let (mut watcher, mut changes) = watch_configs(&paths).unwrap();
        assert_file_changes_observed(&mut changes, &first, "initial target edited").await;
        assert_eq!(
            std::fs::read_to_string(&link).unwrap(),
            "initial target edited"
        );

        let replacement = files.0.join("replacement.json");
        std::os::unix::fs::symlink(&second, &replacement).unwrap();
        std::fs::rename(&replacement, &link).unwrap();
        std::fs::remove_dir_all(files.0.join("a")).unwrap();
        watcher.refresh(&paths).unwrap();
        assert_eq!(
            *watcher.paths.lock(),
            HashSet::from([link.clone(), second.clone()])
        );
        assert_eq!(
            watcher.parents,
            HashSet::from([files.0.clone(), files.0.join("b")])
        );
        assert_file_changes_observed(&mut changes, &second, "retargeted to b").await;
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "retargeted to b");

        std::fs::create_dir(files.0.join("a")).unwrap();
        std::fs::write(&first, "recreated").unwrap();
        std::os::unix::fs::symlink(&first, &replacement).unwrap();
        std::fs::rename(replacement, &link).unwrap();
        std::fs::remove_dir_all(files.0.join("b")).unwrap();
        watcher.refresh(&paths).unwrap();
        assert_eq!(
            *watcher.paths.lock(),
            HashSet::from([link.clone(), first.clone()])
        );
        assert_eq!(
            watcher.parents,
            HashSet::from([files.0.clone(), files.0.join("a")])
        );
        assert_file_changes_observed(&mut changes, &first, "retargeted to recreated a").await;
        assert_eq!(
            std::fs::read_to_string(&link).unwrap(),
            "retargeted to recreated a"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn listener_failures_interrupt_reload_work() {
        for panic in [false, true] {
            let mut servers = JoinSet::new();
            servers.spawn(async move {
                sleep(Duration::from_secs(1)).await;
                assert!(!panic, "listener panic");
                Err(io::Error::other("listener failure"))
            });
            let start = tokio::time::Instant::now();
            let result = supervise_until(&mut servers, sleep(Duration::from_secs(3))).await;
            assert!(result.is_err());
            assert_eq!(start.elapsed(), Duration::from_secs(1));
        }
    }

    #[tokio::test]
    async fn shutdown_does_not_discard_completed_listener_errors() {
        let mut servers = JoinSet::new();
        servers.spawn(async { Err(io::Error::other("listener failure")) });
        tokio::task::yield_now().await;
        assert_eq!(
            stop_servers(vec![], &mut servers)
                .await
                .unwrap_err()
                .to_string(),
            "listener failure"
        );
    }

    #[test]
    fn watch_filter_handles_atomic_save_and_recreation() {
        let path = PathBuf::from("/srv/config.yaml");
        let paths = HashSet::from([path.clone()]);
        for kind in [
            EventKind::Any,
            EventKind::Create(CreateKind::File),
            EventKind::Modify(ModifyKind::Any),
            EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::Any)),
            EventKind::Modify(ModifyKind::Name(RenameMode::Any)),
            EventKind::Remove(RemoveKind::File),
        ] {
            assert!(relevant_event(
                &Event::new(kind).add_path(path.clone()),
                &paths
            ));
            assert!(!relevant_event(
                &Event::new(kind).add_path("/srv/unrelated".into()),
                &paths
            ));
        }
        assert!(!relevant_event(
            &Event::new(EventKind::Access(notify::event::AccessKind::Any)).add_path(path),
            &paths
        ));
    }

    #[tokio::test]
    async fn standalone_http_config_uses_validated_defaults_and_cache_headers() {
        let files = WatchFiles::new();
        for cache_secs in [0, 60, 3600] {
            let config = config::static_http_server(
                "127.0.0.1:0".parse().unwrap(),
                files.0.to_str().unwrap().into(),
                cache_secs,
            )
            .await
            .unwrap();
            assert!(!config.use_iptables);
            let TargetConfigs::Tcp { targets, .. } = &config.target_configs else {
                panic!("TCP expected")
            };
            let target = targets.iter().next().unwrap();
            assert!(target.server_tls.is_none());
            let Some(config::IpMaskSelection::Literal(mask)) = target.allowlist.iter().next()
            else {
                panic!("literal allowlist expected")
            };
            assert_eq!(mask.0, std::net::Ipv6Addr::UNSPECIFIED);
            assert_eq!(mask.1, 0);
            let config::TcpAction::Http(http) = &target.action else {
                panic!("HTTP expected")
            };
            assert!(http.http_protocols.http1 && http.http_protocols.http2);
            assert!(http.http_paths.is_empty());
            let config::HttpPathAction::ServeDirectory(directory) = &http.default_http_action
            else {
                panic!("directory expected")
            };
            assert_eq!(
                directory.response_headers["Cache-Control"],
                format!("max-age={cache_secs}")
            );
            assert!(directory.response_id_header_name.is_none());
            assert_eq!(directory.not_found_content.as_deref(), Some("Not Found"));
            run_standalone(config, true).await.unwrap();
        }
    }

    #[tokio::test]
    async fn standalone_http_validates_roots_and_propagates_bind_failures() {
        let files = WatchFiles::new();
        let file = files.0.join("file");
        std::fs::write(&file, "not a directory").unwrap();
        for path in [file, files.0.join("missing")] {
            assert!(config::static_http_server(
                "127.0.0.1:0".parse().unwrap(),
                path.to_str().unwrap().into(),
                0
            )
            .await
            .is_err());
        }
        let occupied = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = occupied.local_addr().unwrap();
        let config = config::static_http_server(address, files.0.to_str().unwrap().into(), 0)
            .await
            .unwrap();
        run_standalone(config.clone(), true).await.unwrap();
        let error = tokio::time::timeout(Duration::from_secs(5), run_standalone(config, false))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert!(error
            .to_string()
            .contains(&format!("Listener {address} failed:")));
    }

    #[tokio::test]
    async fn directory_not_found_preflight_respects_enabled_protocols() {
        for protocols in [vec!["http1"], vec!["http2"], vec!["http1", "http2"]] {
            for name in ["x-request-id", "keep-alive"] {
                let config = serde_json::from_value(serde_json::json!({
                    "address":"0.0.0.0:0", "transport":"tcp", "iptables":false,
                    "target":{
                        "allowlist":"127.0.0.1", "protocol":"http",
                        "http_protocols":protocols,
                        "default_http_action":{
                            "type":"serve-directory", "path":".",
                            "not_found_content":"Not Found", "response_id_header_name":name
                        }
                    }
                }))
                .unwrap();
                let result = run_standalone(config, true).await;
                assert_eq!(
                    result.is_err(),
                    name == "keep-alive" && protocols.contains(&"http2"),
                    "{protocols:?}, {name}: {result:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn preflight_rejects_duplicate_masks_and_missing_tls_files() {
        for value in [
            serde_json::json!({"address":"127.0.0.1:1", "transport":"tcp", "target":{"allowlist":["127.0.0.1", "127.0.0.1"], "location":"127.0.0.1:2"}}),
            serde_json::json!({"address":"127.0.0.1:1", "transport":"udp", "target":{"allowlist":["127.0.0.1", "127.0.0.1"], "location":"127.0.0.1:2"}}),
            serde_json::json!({"address":"127.0.0.1:1", "transport":"tcp", "target":{"allowlist":"127.0.0.1", "server_tls":{"cert":"/does/not/exist", "key":"/does/not/exist"}, "location":"127.0.0.1:2"}}),
            serde_json::json!({"address":"127.0.0.1:1", "transport":"tcp", "target":{"allowlist":"127.0.0.1", "server_tls":{"mode":"passthrough"}, "protocol":"http", "default_http_action":"close"}}),
        ] {
            let config = serde_json::from_value(value).unwrap();
            assert!(prepare(vec![config], &mut tcp::Admissions::default())
                .await
                .is_err());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tcp_reload_keeps_active_connections_in_the_admission_budget() {
        use tokio::io::AsyncReadExt;
        use tokio::net::{TcpListener, TcpStream};
        async fn connect(address: SocketAddr) -> TcpStream {
            loop {
                match TcpStream::connect(address).await {
                    Ok(stream) => return stream,
                    Err(_) => sleep(Duration::from_millis(5)).await,
                }
            }
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            let backend = TcpListener::bind("0.0.0.0:0").await.unwrap();
            let reservation = TcpListener::bind("0.0.0.0:0").await.unwrap();
            let bound = reservation.local_addr().unwrap();
            let address = SocketAddr::from(([127, 0, 0, 1], bound.port()));
            drop(reservation);
            let config: ServerConfig = serde_json::from_value(serde_json::json!({
                "address":bound.to_string(), "transport":"tcp", "tcp_max_connections":1,
                "target":{"allowlist":"127.0.0.1/32", "location":format!("127.0.0.1:{}", backend.local_addr().unwrap().port())}
            })).unwrap();
            let mut admissions = tcp::Admissions::default();
            let mut servers = JoinSet::new();
            let stops = start_servers(prepare(vec![config.clone()], &mut admissions).await.unwrap(), &mut servers);
            let first_client = connect(address).await;
            let (first_backend, _) = backend.accept().await.unwrap();
            stop_servers(stops, &mut servers).await.unwrap();
            let stops = start_servers(prepare(vec![config], &mut admissions).await.unwrap(), &mut servers);
            let mut rejected = connect(address).await;
            assert!(matches!(rejected.read(&mut [0]).await, Ok(0) | Err(_)));
            assert!(tokio::time::timeout(Duration::from_millis(30), backend.accept()).await.is_err());
            drop(first_client);
            drop(first_backend);
            let mut clients = Vec::new();
            let accepted = loop {
                clients.push(connect(address).await);
                if let Ok(accepted) = tokio::time::timeout(Duration::from_millis(10), backend.accept()).await {
                    break accepted.unwrap();
                }
            };
            drop(clients);
            drop(accepted);
            stop_servers(stops, &mut servers).await.unwrap();
        }).await.expect("TCP admission/reload timed out");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn udp_stop_joins_active_associations_before_rebinding() {
        use tokio::net::UdpSocket;
        tokio::time::timeout(Duration::from_secs(10), async {
            let backend = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let reservation = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let address = reservation.local_addr().unwrap();
            let destination = SocketAddr::from(([127, 0, 0, 1], address.port()));
            drop(reservation);
            let config: ServerConfig = serde_json::from_value(serde_json::json!({
                "address":address.to_string(), "transport":"udp",
                "target":{"allowlist":"127.0.0.1/32", "location":format!("127.0.0.1:{}", backend.local_addr().unwrap().port())}
            })).unwrap();
            let mut servers = JoinSet::new();
            for round in 0..3 {
                let stops = start_servers(prepare(vec![config.clone()], &mut tcp::Admissions::default()).await.unwrap(), &mut servers);
                let mut clients = Vec::new();
                let mut bytes = [0; 16];
                for index in 0..24 {
                    let client = UdpSocket::bind("0.0.0.0:0").await.unwrap();
                    let packet = [round, index];
                    let mut retry = tokio::time::interval(Duration::from_millis(5));
                    loop {
                        tokio::select! {
                            _ = retry.tick() => { client.send_to(&packet, destination).await.unwrap(); }
                            received = backend.recv_from(&mut bytes) => {
                                let (length, _) = received.unwrap();
                                if bytes[..length] == packet { break; }
                            }
                        }
                    }
                    clients.push(client);
                }
                stop_servers(stops, &mut servers).await.unwrap();
                assert!(servers.is_empty());
                let rebound = UdpSocket::bind(address).await.unwrap();
                drop(rebound);
            }
        }).await.expect("UDP stop/rebind timed out");
    }
}
