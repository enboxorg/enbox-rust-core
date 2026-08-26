use std::future::Future;
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot, Mutex};

use crate::stores::{
    EventSubscriptionClose, SubscriptionError, SubscriptionListener, SubscriptionMessage,
};
use crate::ProgressToken;

/// Result of projecting one message from an event-log subscription.
pub(crate) enum DeliveryDecision {
    Forward(SubscriptionMessage),
    Suppress,
    Fail {
        cursor: ProgressToken,
        error: SubscriptionError,
    },
}

/// Coordinates the listener installed in the event log with the subscription handle returned
/// after replay has completed.
#[derive(Clone)]
pub(crate) struct GuardedSubscription {
    state: Arc<Mutex<GuardState>>,
    sender: mpsc::UnboundedSender<GuardCommand>,
}

#[derive(Default)]
struct GuardState {
    close: Option<EventSubscriptionClose>,
    close_requested: bool,
}

enum GuardCommand {
    Message(SubscriptionMessage),
    Flush(oneshot::Sender<()>),
}

impl GuardedSubscription {
    /// Installs the event-log close callback. If delivery failed during replay, the callback is
    /// invoked immediately so the subscription cannot become live after its terminal error.
    pub(crate) async fn install_close(&self, close: EventSubscriptionClose) {
        let should_close = {
            let mut state = self.state.lock().await;
            state.close = Some(close.clone());
            state.close_requested
        };
        if should_close {
            let _ = close().await;
        }
    }

    /// Waits until all messages enqueued before this call have been projected.
    pub(crate) async fn flush(&self) {
        let (done, wait) = oneshot::channel();
        if self.sender.send(GuardCommand::Flush(done)).is_ok() {
            let _ = wait.await;
        }
    }

    async fn close(&self) {
        let close = {
            let mut state = self.state.lock().await;
            state.close_requested = true;
            state.close.clone()
        };
        if let Some(close) = close {
            let _ = close().await;
        }
    }
}

/// Wraps a synchronous event-log listener with one serialized asynchronous projection queue.
///
/// The event log only enqueues messages. The worker applies `processor` in feed order, forwards or
/// suppresses each result, and fences the stream after the first terminal failure.
pub(crate) fn create_guarded_subscription<P, F>(
    listener: SubscriptionListener,
    processor: P,
) -> (SubscriptionListener, GuardedSubscription)
where
    P: Fn(SubscriptionMessage) -> F + Send + Sync + 'static,
    F: Future<Output = DeliveryDecision> + Send + 'static,
{
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let guard = GuardedSubscription {
        state: Arc::default(),
        sender: sender.clone(),
    };
    let worker_guard = guard.clone();

    tokio::spawn(async move {
        let mut terminal = false;
        while let Some(command) = receiver.recv().await {
            let message = match command {
                GuardCommand::Message(message) => message,
                GuardCommand::Flush(done) => {
                    let _ = done.send(());
                    continue;
                }
            };
            if terminal {
                continue;
            }

            match processor(message).await {
                DeliveryDecision::Forward(message) => listener(message),
                DeliveryDecision::Suppress => {}
                DeliveryDecision::Fail { cursor, error } => {
                    terminal = true;
                    worker_guard.close().await;
                    listener(SubscriptionMessage::Error { cursor, error });
                }
            }
        }
    });

    let guarded_listener: SubscriptionListener = Box::new(move |message| {
        let _ = sender.send(GuardCommand::Message(message));
    });
    (guarded_listener, guard)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::RwLock;

    use super::*;
    use crate::stores::SubscriptionErrorCode;

    fn token(position: &str) -> ProgressToken {
        ProgressToken {
            stream_id: "stream".to_string(),
            epoch: "epoch".to_string(),
            position: position.to_string(),
            message_cid: None,
        }
    }

    fn position(message: &SubscriptionMessage) -> &str {
        match message {
            SubscriptionMessage::Eose { cursor }
            | SubscriptionMessage::Error { cursor, .. }
            | SubscriptionMessage::Event { cursor, .. } => &cursor.position,
        }
    }

    #[tokio::test]
    async fn serializes_projection_suppresses_and_fences_after_failure() {
        let delivered = Arc::new(RwLock::new(Vec::new()));
        let delivered_for_listener = delivered.clone();
        let listener: SubscriptionListener = Box::new(move |message| {
            delivered_for_listener.write().unwrap().push(message);
        });
        let (guarded, guard) = create_guarded_subscription(listener, |message| async move {
            match position(&message) {
                "2" => DeliveryDecision::Suppress,
                "3" => DeliveryDecision::Fail {
                    cursor: token("3"),
                    error: SubscriptionError {
                        code: SubscriptionErrorCode::DeliveryFailed,
                        detail: "terminal".to_string(),
                    },
                },
                _ => DeliveryDecision::Forward(message),
            }
        });
        let close_count = Arc::new(AtomicUsize::new(0));
        let close_count_for_callback = close_count.clone();
        guard
            .install_close(Arc::new(move || {
                close_count_for_callback.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(()) })
            }))
            .await;

        for position in ["1", "2", "3", "4"] {
            guarded(SubscriptionMessage::Eose {
                cursor: token(position),
            });
        }
        guard.flush().await;

        let delivered = delivered.read().unwrap();
        assert_eq!(delivered.len(), 2);
        assert_eq!(position(&delivered[0]), "1");
        assert!(matches!(delivered[1], SubscriptionMessage::Error { .. }));
        assert_eq!(close_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn closes_immediately_when_failure_precedes_close_installation() {
        let listener: SubscriptionListener = Box::new(|_| {});
        let (guarded, guard) = create_guarded_subscription(listener, |message| async move {
            DeliveryDecision::Fail {
                cursor: token(position(&message)),
                error: SubscriptionError {
                    code: SubscriptionErrorCode::DeliveryAuthorizationFailed,
                    detail: "expired".to_string(),
                },
            }
        });
        guarded(SubscriptionMessage::Eose { cursor: token("1") });
        guard.flush().await;

        let close_count = Arc::new(AtomicUsize::new(0));
        let close_count_for_callback = close_count.clone();
        guard
            .install_close(Arc::new(move || {
                close_count_for_callback.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(()) })
            }))
            .await;
        assert_eq!(close_count.load(Ordering::SeqCst), 1);
    }
}
