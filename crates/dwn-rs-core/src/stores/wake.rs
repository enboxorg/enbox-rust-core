//! Process-local wake hints for consumers of a durable store feed.
//!
//! A wake only tells a consumer to drain the durable feed again. Wake delivery
//! is not durable: implementations may coalesce, duplicate, or drop wakes, and
//! consumers must use the feed cursor rather than wake delivery as their source
//! of truth.

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, Weak,
    },
};

use thiserror::Error;
use tokio::sync::mpsc;

/// Failure reported while publishing a wake hint.
#[derive(Debug, Clone, Error)]
pub enum WakeError {
    /// The configured publisher could not accept the wake.
    #[error("Failed to publish wake: {0}")]
    PublishError(String),
}

/// Boxed, pinned, `Send` future used throughout the wake API to erase concrete
/// future types behind trait-object boundaries.
pub type WakeFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A hint that a tenant's durable feed may have new work to drain.
///
/// This value is neither a delivered event nor a checkpoint. Receiving it does
/// not guarantee that the referenced position is still retained, and failing to
/// receive it does not mean that the feed is current.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wake {
    /// Tenant whose durable feed should be drained.
    pub tenant: String,
    /// Feed position that caused the hint.
    ///
    /// Consumers may use this to avoid obviously redundant drains, but must not
    /// persist or acknowledge it as a checkpoint. Only a cursor returned by the
    /// durable feed establishes consumer progress.
    pub position: u64,
}

/// Publishes best-effort wake hints after durable store changes.
///
/// Implementations should return promptly and must not wait for consumers to
/// process a wake. Slow, closed, or failing consumers must not block unrelated
/// store commits or tenants.
pub trait WakePublisher: Send + Sync {
    /// Offers a wake hint to the configured delivery mechanism.
    fn publish(&self, wake: Wake) -> Result<(), WakeError>;
}

/// No-op publisher for configurations without live consumers.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopWakePublisher;

impl WakePublisher for NoopWakePublisher {
    fn publish(&self, _wake: Wake) -> Result<(), WakeError> {
        Ok(())
    }
}

/// Retains `()` as a backwards-compatible no-op publisher.
impl WakePublisher for () {
    fn publish(&self, _wake: Wake) -> Result<(), WakeError> {
        Ok(())
    }
}

/// Cloneable handle used by stores to publish wake hints.
#[derive(Clone)]
pub struct WakePublishHandler {
    inner: Arc<dyn WakePublisher>,
}

impl Default for WakePublishHandler {
    fn default() -> Self {
        Self::new(Arc::new(NoopWakePublisher))
    }
}

/// WakePublishHandler is a wrapper around a WakePublisher that provides a convenient
/// interface for publishing wake notifications.
impl WakePublishHandler {
    /// Wraps a shared wake publisher.
    pub fn new(inner: Arc<dyn WakePublisher>) -> Self {
        Self { inner }
    }

    /// Offers a wake hint to the wrapped publisher.
    pub fn publish(&self, wake: Wake) -> Result<(), WakeError> {
        self.inner.publish(wake)
    }
}

/// User-provided async callback invoked each time a [`Wake`] is published for
/// the subscribed tenant. The callback receives the wake by value and returns a
/// future that resolves to `()`.
pub type WakeSubscriptionListener =
    Box<dyn Fn(Wake) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync + 'static>;

/// Consumer side of a wake delivery mechanism.
///
/// Consumers must continue to treat the durable feed as authoritative
/// regardless of the concrete subscriber implementation.
pub trait WakeSubscriber: Send + Sync {
    /// Registers a [`WakeSubscriptionListener`] for the given tenant and
    /// returns a handle that can later remove it.
    fn subscribe(
        &self,
        tenant: &str,
        listener: WakeSubscriptionListener,
    ) -> WakeFuture<'_, Box<dyn WakeSubscriptionHandle>>;

    // Closes the subscriber and removes all registered listeners. After this
    // call, no further wakes will be delivered to any listener.
    fn clear(&self) -> WakeFuture<'_, ()>;
}

/// Handle returned by [`WakeSubscriber::subscribe`] that removes the listener
/// when [`close`](WakeSubscriptionHandle::close) is called or the handle is
/// dropped.
pub trait WakeSubscriptionHandle: Send + Sync {
    /// Removes the associated listener so it will no longer be called on
    /// subsequent publishes.
    fn close(&self) -> WakeFuture<'_, ()>;
}

struct WakeRegistration {
    id: u64,
    sender: mpsc::Sender<Wake>,
    task: tokio::task::AbortHandle,
}

#[derive(Default)]
struct InProcessBusInner {
    next_id: AtomicU64,
    listeners: Mutex<HashMap<String, Vec<WakeRegistration>>>,
}

/// Process-local, best-effort wake delivery for consumers of a durable feed.
///
/// Each listener has a bounded queue. Publication never awaits listener work;
/// a wake is coalesced when that listener's queue is full. Clones share the same
/// registrations, and dropping the last bus clone closes all listener tasks.
#[derive(Clone, Default)]
pub struct InProcessWakeBus {
    inner: Arc<InProcessBusInner>,
}

impl InProcessWakeBus {
    /// Creates a new bus with no registered listeners.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(InProcessBusInner::default()),
        }
    }
}

impl WakePublisher for InProcessWakeBus {
    fn publish(&self, wake: Wake) -> Result<(), WakeError> {
        let mut listeners = self.inner.lock_listeners();
        let mut remove_tenant = false;
        if let Some(subscribers) = listeners.get_mut(&wake.tenant) {
            subscribers.retain(
                |subscriber| match subscriber.sender.try_send(wake.clone()) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => true,
                    Err(mpsc::error::TrySendError::Closed(_)) => false,
                },
            );
            remove_tenant = subscribers.is_empty();
        }
        if remove_tenant {
            listeners.remove(&wake.tenant);
        }
        Ok(())
    }
}

impl InProcessBusInner {
    fn lock_listeners(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<WakeRegistration>>> {
        self.listeners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn remove(&self, tenant: &str, id: u64) {
        let mut listeners = self.lock_listeners();
        let mut remove_tenant = false;
        if let Some(subscribers) = listeners.get_mut(tenant) {
            subscribers.retain(|subscriber| {
                if subscriber.id == id {
                    subscriber.task.abort();
                    false
                } else {
                    true
                }
            });
            remove_tenant = subscribers.is_empty();
        }
        if remove_tenant {
            listeners.remove(tenant);
        }
    }

    fn clear(&self) {
        let mut listeners = self.lock_listeners();
        for subscriber in listeners.values().flatten() {
            subscriber.task.abort();
        }
        listeners.clear();
    }
}

impl Drop for InProcessBusInner {
    fn drop(&mut self) {
        let listeners = self
            .listeners
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for subscriber in listeners.values().flatten() {
            subscriber.task.abort();
        }
    }
}

async fn run_listener(listener: WakeSubscriptionListener, mut receiver: mpsc::Receiver<Wake>) {
    while let Some(wake) = receiver.recv().await {
        listener(wake).await;
    }
}

impl WakeSubscriber for InProcessWakeBus {
    fn subscribe(
        &self,
        tenant: &str,
        listener: WakeSubscriptionListener,
    ) -> WakeFuture<'_, Box<dyn WakeSubscriptionHandle>> {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let tenant = tenant.to_owned();
        let inner = Arc::downgrade(&self.inner);
        let bus_inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let (sender, receiver) = mpsc::channel(1);
            let task = tokio::spawn(run_listener(listener, receiver));
            bus_inner
                .lock_listeners()
                .entry(tenant.clone())
                .or_default()
                .push(WakeRegistration {
                    id,
                    sender,
                    task: task.abort_handle(),
                });

            Box::new(InProcessSubscriptionHandle { id, tenant, inner })
                as Box<dyn WakeSubscriptionHandle>
        })
    }

    fn clear(&self) -> WakeFuture<'_, ()> {
        self.inner.clear();
        Box::pin(async {})
    }
}

/// Handle that identifies a single listener registration within an
/// [`InProcessWakeBus`] and can remove it on [`close`](WakeSubscriptionHandle::close).
struct InProcessSubscriptionHandle {
    id: u64,
    tenant: String,
    inner: Weak<InProcessBusInner>,
}

impl InProcessSubscriptionHandle {
    fn remove(&self) {
        if let Some(inner) = self.inner.upgrade() {
            inner.remove(&self.tenant, self.id);
        }
    }
}

impl Drop for InProcessSubscriptionHandle {
    fn drop(&mut self) {
        self.remove();
    }
}

impl WakeSubscriptionHandle for InProcessSubscriptionHandle {
    fn close(&self) -> WakeFuture<'_, ()> {
        self.remove();
        Box::pin(async {})
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tokio::{
        sync::{mpsc, oneshot},
        time::timeout,
    };

    use super::*;

    fn recording_listener(sender: mpsc::UnboundedSender<Wake>) -> WakeSubscriptionListener {
        Box::new(move |wake| {
            let _ = sender.send(wake);
            Box::pin(async {})
        })
    }

    fn wake(tenant: &str, position: u64) -> Wake {
        Wake {
            tenant: tenant.to_owned(),
            position,
        }
    }

    #[test]
    fn noop_publisher_is_the_default() {
        WakePublishHandler::default()
            .publish(wake("did:example:alice", 1))
            .unwrap();
    }

    #[tokio::test]
    async fn isolates_tenants() {
        let bus = InProcessWakeBus::new();
        let (alice_tx, mut alice_rx) = mpsc::unbounded_channel();
        let (bob_tx, mut bob_rx) = mpsc::unbounded_channel();
        let _alice = bus
            .subscribe("did:example:alice", recording_listener(alice_tx))
            .await;
        let _bob = bus
            .subscribe("did:example:bob", recording_listener(bob_tx))
            .await;

        bus.publish(wake("did:example:alice", 7)).unwrap();

        assert_eq!(alice_rx.recv().await.unwrap().position, 7);
        assert!(timeout(Duration::from_millis(20), bob_rx.recv())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn notifies_multiple_listeners_for_a_tenant() {
        let bus = InProcessWakeBus::new();
        let (first_tx, mut first_rx) = mpsc::unbounded_channel();
        let (second_tx, mut second_rx) = mpsc::unbounded_channel();
        let _first = bus
            .subscribe("did:example:alice", recording_listener(first_tx))
            .await;
        let _second = bus
            .subscribe("did:example:alice", recording_listener(second_tx))
            .await;

        bus.publish(wake("did:example:alice", 11)).unwrap();

        assert_eq!(first_rx.recv().await.unwrap().position, 11);
        assert_eq!(second_rx.recv().await.unwrap().position, 11);
    }

    #[tokio::test]
    async fn cloned_bus_shares_registrations() {
        let subscriber = InProcessWakeBus::new();
        let publisher = subscriber.clone();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let _subscription = subscriber
            .subscribe("did:example:alice", recording_listener(sender))
            .await;

        publisher.publish(wake("did:example:alice", 13)).unwrap();

        assert_eq!(receiver.recv().await.unwrap().position, 13);
    }

    #[tokio::test]
    async fn explicit_close_and_handle_drop_remove_registrations() {
        let bus = InProcessWakeBus::new();
        let (closed_tx, mut closed_rx) = mpsc::unbounded_channel();
        let closed = bus
            .subscribe("did:example:alice", recording_listener(closed_tx))
            .await;
        closed.close().await;

        let (dropped_tx, mut dropped_rx) = mpsc::unbounded_channel();
        let dropped = bus
            .subscribe("did:example:alice", recording_listener(dropped_tx))
            .await;
        drop(dropped);

        bus.publish(wake("did:example:alice", 1)).unwrap();

        assert_eq!(closed_rx.recv().await, None);
        assert_eq!(dropped_rx.recv().await, None);
    }

    #[tokio::test]
    async fn closing_bus_removes_all_registrations() {
        let bus = InProcessWakeBus::new();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let _subscription = bus
            .subscribe("did:example:alice", recording_listener(sender))
            .await;

        bus.close().await;
        bus.publish(wake("did:example:alice", 1)).unwrap();

        assert_eq!(receiver.recv().await, None);
    }

    #[tokio::test]
    async fn dropping_handle_cancels_an_in_flight_listener_task() {
        struct DropSignal(Option<oneshot::Sender<()>>);

        impl Drop for DropSignal {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(());
                }
            }
        }

        let bus = InProcessWakeBus::new();
        let started = Arc::new(tokio::sync::Notify::new());
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let signal = Arc::new(DropSignal(Some(dropped_tx)));
        let subscription = bus
            .subscribe(
                "did:example:alice",
                Box::new({
                    let started = Arc::clone(&started);
                    let signal = Arc::clone(&signal);
                    move |_| {
                        let started = Arc::clone(&started);
                        let signal = Arc::clone(&signal);
                        Box::pin(async move {
                            started.notify_one();
                            let _signal = signal;
                            std::future::pending::<()>().await;
                        })
                    }
                }),
            )
            .await;
        drop(signal);
        bus.publish(wake("did:example:alice", 1)).unwrap();
        started.notified().await;

        drop(subscription);

        timeout(Duration::from_millis(100), dropped_rx)
            .await
            .expect("listener task must be cancelled")
            .expect("drop signal sender must remain alive until cancellation");
    }

    #[tokio::test]
    async fn subscription_handle_does_not_keep_bus_alive() {
        let bus = InProcessWakeBus::new();
        let weak_inner = Arc::downgrade(&bus.inner);
        let (sender, _receiver) = mpsc::unbounded_channel();
        let subscription = bus
            .subscribe("did:example:alice", recording_listener(sender))
            .await;

        drop(bus);

        assert!(weak_inner.upgrade().is_none());
        drop(subscription);
    }

    #[tokio::test]
    async fn duplicate_wakes_are_safe_and_may_be_delivered() {
        let bus = InProcessWakeBus::new();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let _subscription = bus
            .subscribe("did:example:alice", recording_listener(sender))
            .await;

        bus.publish(wake("did:example:alice", 3)).unwrap();
        assert_eq!(receiver.recv().await.unwrap().position, 3);
        bus.publish(wake("did:example:alice", 3)).unwrap();
        assert_eq!(receiver.recv().await.unwrap().position, 3);
    }

    #[tokio::test]
    async fn slow_listener_does_not_block_publication_or_other_tenants() {
        let bus = InProcessWakeBus::new();
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let _slow = bus
            .subscribe(
                "did:example:alice",
                Box::new({
                    let started = Arc::clone(&started);
                    let release = Arc::clone(&release);
                    move |_| {
                        let started = Arc::clone(&started);
                        let release = Arc::clone(&release);
                        Box::pin(async move {
                            started.notify_one();
                            release.notified().await;
                        })
                    }
                }),
            )
            .await;
        let (bob_tx, mut bob_rx) = mpsc::unbounded_channel();
        let _bob = bus
            .subscribe("did:example:bob", recording_listener(bob_tx))
            .await;

        bus.publish(wake("did:example:alice", 1)).unwrap();
        started.notified().await;

        timeout(Duration::from_millis(20), async {
            for position in 2..100 {
                bus.publish(wake("did:example:alice", position)).unwrap();
            }
            bus.publish(wake("did:example:bob", 5)).unwrap();
        })
        .await
        .expect("publication must not await a slow listener");
        assert_eq!(bob_rx.recv().await.unwrap().position, 5);
        release.notify_one();
    }

    #[tokio::test]
    async fn failed_listener_is_isolated_from_other_listeners() {
        let bus = InProcessWakeBus::new();
        let _failing = bus
            .subscribe(
                "did:example:alice",
                Box::new(|_| Box::pin(async { panic!("injected listener failure") })),
            )
            .await;
        let (healthy_tx, mut healthy_rx) = mpsc::unbounded_channel();
        let _healthy = bus
            .subscribe("did:example:alice", recording_listener(healthy_tx))
            .await;

        bus.publish(wake("did:example:alice", 1)).unwrap();
        assert_eq!(healthy_rx.recv().await.unwrap().position, 1);
        tokio::task::yield_now().await;
        bus.publish(wake("did:example:alice", 2)).unwrap();
        assert_eq!(healthy_rx.recv().await.unwrap().position, 2);
    }
}
