use std::sync::Arc;

use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum WakeError {
    #[error("Failed to publish wake: {0}")]
    PublishError(String),
}

/// Wake represents a notification that a new message has been published
/// to a tenant's stream, containing the tenant and the position sequence
/// of the message in the stream.
pub struct Wake {
    pub tenant: String,
    pub position: u64,
}

/// WakePublisher is a trait that defines the interface for publishing wake notifications.
pub trait WakePublisher: Send + Sync {
    fn publish(&self, wake: Wake) -> Result<(), WakeError>;
}

/// NoopWakePublisher is a no-op implementation of the WakePublisher trait that does nothing when
/// publishing a wake notification.
impl WakePublisher for () {
    fn publish(&self, _wake: Wake) -> Result<(), WakeError> {
        Ok(())
    }
}

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
    pub fn new(inner: Arc<dyn WakePublisher>) -> Self {
        Self { inner }
    }

    pub fn publish(&self, wake: Wake) -> Result<(), WakeError> {
        self.inner.publish(wake)
    }
}

pub trait WakeSubscriber {}
