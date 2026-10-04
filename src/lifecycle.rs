use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use log::{error, info};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc::{channel, Receiver};
use tokio::task::JoinSet;
use tokio::time::{sleep, Duration};

use crate::config::{ServerConfig, TargetConfigs};
use crate::{config, iptables_util, tcp, udp, QuickAction};

type ServerTask = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

fn relevant_event(event: &Event, paths: &HashSet<PathBuf>) -> bool {
    matches!(
        event.kind,
        EventKind::Any | EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    ) && event.paths.iter().any(|path| paths.contains(path))
}

fn watch_configs(config_paths: &[String]) -> io::Result<(RecommendedWatcher, Receiver<()>)> {
    let mut paths = HashSet::new();
    let mut parents = HashSet::new();
    for config_path in config_paths {
        let path = std::path::absolute(config_path)?;
        let parent = path.parent().unwrap_or(Path::new("/"));
        let parent = std::fs::canonicalize(parent)?;
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::other("Invalid config path"))?;
        paths.insert(parent.join(name));
        parents.insert(parent);
    }
    let (tx, rx) = channel(1);
    let mut watcher =
        notify::recommended_watcher(move |result: notify::Result<Event>| match result {
            Ok(event) if relevant_event(&event, &paths) => {
                let _ = tx.try_send(());
            }
            Ok(_) => {}
            Err(error) => error!("Config watch error: {error}"),
        })
        .map_err(io::Error::other)?;
    for parent in parents {
        watcher
            .watch(&parent, RecursiveMode::NonRecursive)
            .map_err(io::Error::other)?;
    }
    Ok((watcher, rx))
}

async fn prepare(configs: Vec<ServerConfig>) -> io::Result<Vec<ServerTask>> {
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
        let task: ServerTask = match target_configs {
            TargetConfigs::Tcp {
                tcp_nodelay,
                tcp_keepalive,
                targets,
            } => Box::pin(
                tcp::prepare_tcp_server(
                    address,
                    use_iptables,
                    tcp_nodelay,
                    tcp_keepalive,
                    targets.into_vec(),
                )
                .await?,
            ),
            TargetConfigs::Udp { targets } => Box::pin(udp::prepare_udp_server(
                address,
                use_iptables,
                targets.into_vec(),
            )?),
        };
        tasks.push(Box::pin(async move {
            task.await.map_err(|error| {
                io::Error::new(error.kind(), format!("Listener {address} failed: {error}"))
            })
        }) as ServerTask);
    }
    Ok(tasks)
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
    let configs = config::load_server_configs(paths.clone(), urls.clone()).await?;
    if configs.is_empty() {
        return Err(io::Error::other("No server configs found"));
    }
    if quick == Some(QuickAction::ClearIptablesMatching) {
        clear_rules(&configs.iter().map(|config| config.address).collect()).await?;
        return Ok(());
    }
    let mut firewall = firewall_addresses(&configs);
    let tasks = prepare(configs).await?;
    if quick == Some(QuickAction::DryRun) {
        info!("Dry run complete");
        return Ok(());
    }
    let (_watcher, mut changes) = watch_configs(&paths)?;
    clear_rules(&firewall).await?;
    let mut servers = JoinSet::new();
    for task in tasks {
        servers.spawn(task);
    }

    loop {
        tokio::select! {
            finished = servers.join_next(), if !servers.is_empty() => {
                match finished.expect("nonempty listener set") {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => return Err(error),
                    Err(error) => return Err(io::Error::other(format!("Listener task failed: {error}"))),
                }
            }
            changed = changes.recv() => {
                if changed.is_none() { return Err(io::Error::other("Config watcher stopped")); }
                sleep(Duration::from_secs(3)).await;
                while changes.try_recv().is_ok() {}
                let replacement = async {
                    let configs = config::load_server_configs(paths.clone(), urls.clone()).await?;
                    if configs.is_empty() { return Err(io::Error::other("No server configs found")); }
                    let firewall = firewall_addresses(&configs);
                    Ok::<_, io::Error>((prepare(configs).await?, firewall))
                }.await;
                let (tasks, new_firewall) = match replacement {
                    Ok(replacement) => replacement,
                    Err(error) => {
                        error!("Config reload rejected; keeping running listeners: {error}");
                        continue;
                    }
                };
                servers.abort_all();
                while servers.join_next().await.is_some() {}
                let stale_rules = firewall.union(&new_firewall).copied().collect();
                clear_rules(&stale_rules).await?;
                firewall = new_firewall;
                for task in tasks { servers.spawn(task); }
                info!("Config reload complete");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{CreateKind, ModifyKind, RemoveKind};

    #[test]
    fn watch_filter_handles_atomic_save_and_recreation() {
        let path = PathBuf::from("/srv/config.yaml");
        let paths = HashSet::from([path.clone()]);
        for kind in [
            EventKind::Create(CreateKind::File),
            EventKind::Modify(ModifyKind::Any),
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
    async fn preflight_rejects_duplicate_masks_and_missing_tls_files() {
        for value in [
            serde_json::json!({"address":"127.0.0.1:1", "transport":"tcp", "target":{"allowlist":["127.0.0.1", "127.0.0.1"], "location":"127.0.0.1:2"}}),
            serde_json::json!({"address":"127.0.0.1:1", "transport":"udp", "target":{"allowlist":["127.0.0.1", "127.0.0.1"], "location":"127.0.0.1:2"}}),
            serde_json::json!({"address":"127.0.0.1:1", "transport":"tcp", "target":{"allowlist":"127.0.0.1", "server_tls":{"cert":"/does/not/exist", "key":"/does/not/exist"}, "location":"127.0.0.1:2"}}),
        ] {
            let config = serde_json::from_value(value).unwrap();
            assert!(prepare(vec![config]).await.is_err());
        }
    }
}
