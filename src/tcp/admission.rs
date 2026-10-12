use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

#[derive(Default)]
pub(crate) struct Admissions {
    listeners: HashMap<SocketAddr, Weak<Admission>>,
}

impl Admissions {
    pub fn for_listener(&mut self, address: SocketAddr) -> Arc<Admission> {
        self.listeners
            .retain(|_, counter| counter.strong_count() != 0);
        if let Some(counter) = self.listeners.get(&address).and_then(Weak::upgrade) {
            return counter;
        }
        let counter = Arc::new(Admission::default());
        self.listeners.insert(address, Arc::downgrade(&counter));
        counter
    }
}

#[derive(Default)]
pub(crate) struct Admission {
    active: AtomicUsize,
}

impl Admission {
    #[allow(deprecated)] // fetch_update supports the Rust 1.88 MSRV.
    pub fn try_acquire(self: &Arc<Self>, limit: Option<NonZeroUsize>) -> Option<Permit> {
        self.active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
                if limit.is_some_and(|limit| active >= limit.get()) {
                    None
                } else {
                    active.checked_add(1)
                }
            })
            .ok()?;
        Some(Permit(self.clone()))
    }
}

pub(crate) struct Permit(Arc<Admission>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_survives_reload_removal_and_limit_changes() {
        let mut registry = Admissions::default();
        let address = "127.0.0.1:9000".parse().unwrap();
        let first = registry.for_listener(address);
        let one = first.try_acquire(None).unwrap();
        let two = first.try_acquire(None).unwrap();
        drop(first);
        let replacement = registry.for_listener(address);
        assert!(replacement.try_acquire(NonZeroUsize::new(1)).is_none());
        drop(one);
        assert!(replacement.try_acquire(NonZeroUsize::new(1)).is_none());
        drop(two);
        let permit = replacement.try_acquire(NonZeroUsize::new(1)).unwrap();
        assert!(replacement.try_acquire(NonZeroUsize::new(1)).is_none());
        drop(permit);
        drop(replacement);
        let fresh = registry.for_listener("127.0.0.1:9001".parse().unwrap());
        assert_eq!(registry.listeners.len(), 1);
        assert_eq!(fresh.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn cancellation_releases_the_connection_permit() {
        let admission = Arc::new(Admission::default());
        let permit = admission.try_acquire(NonZeroUsize::new(1)).unwrap();
        let task = tokio::spawn(async move {
            let _permit = permit;
            std::future::pending::<()>().await;
        });
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(admission.try_acquire(NonZeroUsize::new(1)).is_some());
    }
}
