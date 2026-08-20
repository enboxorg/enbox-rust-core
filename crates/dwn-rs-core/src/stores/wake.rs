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

/// Provides the default no-op publisher for configurations without live consumers.
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
        Self::new(Arc::new(()))
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
    Box<dyn Fn(Wake) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// Consumer side of a wake delivery mechanism.
///
/// The registration and deterministic close contract will be added with the
/// in-process wake bus. Consumers must continue to treat the durable feed as
/// authoritative regardless of the concrete subscriber implementation.
pub trait WakeSubscriber: Send + Sync {
    /// Registers a [`WakeSubscriptionListener`] for the given tenant and
    /// returns a handle that can later remove it.
    fn subscribe(
        &self,
        tenant: &str,
        listener: WakeSubscriptionListener,
    ) -> WakeFuture<'_, Box<dyn WakeSubscriptionHandle>>;
}

/// Handle returned by [`WakeSubscriber::subscribe`] that removes the listener
/// when [`unsubscribe`](WakeSubscriptionHandle::unsubscribe) is called.
pub trait WakeSubscriptionHandle: Send + Sync {
    /// Removes the associated listener so it will no longer be called on
    /// subsequent publishes.
    fn unsubscribe(&self) -> WakeFuture<'_, ()>;
}

struct WakeRegistration {
    id: u64,
    sender: mpsc::Sender<Wake>,
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

    /// Removes every listener registered with this bus.
    ///
    /// Closing drops the bus-owned senders, which also allows the corresponding
    /// listener tasks to finish once any wake already being handled completes.
    pub fn close(&self) -> WakeFuture<'_, ()> {
        self.inner.clear();
        Box::pin(async {})
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
