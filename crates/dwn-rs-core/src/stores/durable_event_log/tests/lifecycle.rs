//! Close semantics and registry bookkeeping: one cleanup path, idempotent
//! close, and wake registrations that belong to exactly one subscription.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::support::*;
use crate::stores::durable_event_log::DurableEventLogConfig;
use crate::stores::wake::InProcessWakeBus;
use crate::stores::{EventLog, EventLogSubscribeOptions, EventSubscription, SubscriptionMessage};

async fn close(subscription: &EventSubscription) {
    (subscription.close)().await.expect("close succeeds");
}

fn from_start() -> Option<EventLogSubscribeOptions> {
    Some(EventLogSubscribeOptions {
        cursor: Some(token(0, None)),
        filters: None,
    })
}

#[tokio::test]
async fn replacing_a_subscription_id_closes_the_replay_in_progress() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(2, Some("cid-2")))));
    let mut replay = harness.reader.push_gated_page(page(
        vec![entry(1, "cid-1"), entry(2, "cid-2")],
        token(2, Some("cid-2")),
        true,
    ));

    let (first_listener, mut first_recorder) = recorder();
    let (second_listener, mut second_recorder) = recorder();
    let log = &harness.log;

    let replaced = async {
        log.subscribe(TENANT, "sub-1", first_listener, from_start())
            .await
            .expect("first subscribe")
    };

    let replacement = async {
        replay.entered().await;
        let subscription = log
            .subscribe(TENANT, "sub-1", second_listener, None)
            .await
            .expect("replacement subscribe");
        replay.release();
        subscription
    };

    let (replaced, replacement) = tokio::join!(replaced, replacement);

    // The replaced subscription stops cooperatively: no events, and no EOSE.
    first_recorder.expect_quiet(QUIET_WINDOW).await;
    second_recorder.expect_quiet(QUIET_WINDOW).await;

    close(&replaced).await;
    close(&replacement).await;
}

#[tokio::test]
async fn a_replaced_subscription_stops_receiving_wakes() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(0, None))));
    harness
        .reader
        .push_page(page(vec![entry(1, "cid-1")], token(1, Some("cid-1")), true));

    let (first_listener, mut first_recorder) = recorder();
    let _replaced = harness
        .log
        .subscribe(TENANT, "sub-1", first_listener, None)
        .await
        .expect("first subscribe");

    let (second_listener, mut second_recorder) = recorder();
    let _replacement = harness
        .log
        .subscribe(TENANT, "sub-1", second_listener, None)
        .await
        .expect("replacement subscribe");

    harness.publish_wake(TENANT, 1);

    assert_eq!(
        second_recorder.expect_event().await.seq.as_deref(),
        Some("1")
    );
    first_recorder.expect_quiet(QUIET_WINDOW).await;
    assert_eq!(
        harness.reader.paging_reads().len(),
        1,
        "the replaced registration must not drain in parallel"
    );
}

#[tokio::test]
async fn close_is_idempotent_and_ends_delivery() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(0, None))));
    harness
        .reader
        .push_page(page(vec![entry(1, "cid-1")], token(1, Some("cid-1")), true));

    let (listener, mut recorder) = recorder();
    let subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    close(&subscription).await;
    close(&subscription).await;

    harness.publish_wake(TENANT, 1);
    harness.reader.expect_no_read_within(QUIET_WINDOW).await;
    recorder.expect_quiet(QUIET_WINDOW).await;
}

#[tokio::test]
async fn close_waits_for_an_in_flight_drain_and_delivers_nothing_after() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(0, None))));
    let mut drain = harness.reader.push_gated_page(page(
        vec![entry(1, "cid-1"), entry(2, "cid-2")],
        token(2, Some("cid-2")),
        true,
    ));

    let (listener, mut recorder) = recorder();
    let subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    harness.publish_wake(TENANT, 2);
    drain.entered().await;

    let closing = async {
        close(&subscription).await;
    };
    let releasing = async {
        settle().await;
        drain.release();
    };
    tokio::join!(closing, releasing);

    // Close is a delivery barrier: the page in flight is abandoned, not delivered.
    recorder.expect_quiet(QUIET_WINDOW).await;
    harness.publish_wake(TENANT, 3);
    harness.reader.expect_no_read_within(QUIET_WINDOW).await;
}

#[tokio::test]
async fn closing_from_inside_a_listener_callback_completes() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(0, None))));
    harness.reader.push_page(page(
        vec![entry(1, "cid-1"), entry(2, "cid-2"), entry(3, "cid-3")],
        token(3, Some("cid-3")),
        true,
    ));

    // A listener cannot await, so it hands the close off to its own task, the
    // way an application callback would.
    let handle: Arc<Mutex<Option<EventSubscription>>> = Arc::new(Mutex::new(None));
    let closed = Arc::new(AtomicBool::new(false));
    let (done_sender, done) = tokio::sync::oneshot::channel();
    let done_sender = Arc::new(Mutex::new(Some(done_sender)));

    let hook_handle = Arc::clone(&handle);
    let hook_closed = Arc::clone(&closed);
    let (listener, mut recorder) = recorder_with_hook(move |message: &SubscriptionMessage| {
        if hook_closed.swap(true, Ordering::AcqRel) {
            return;
        }
        assert!(matches!(message, SubscriptionMessage::Event { .. }));

        let subscription = hook_handle.lock().expect("handle lock").take();
        let done_sender = Arc::clone(&done_sender);
        tokio::spawn(async move {
            if let Some(subscription) = subscription {
                close(&subscription).await;
            }
            if let Some(sender) = done_sender.lock().expect("sender lock").take() {
                let _ = sender.send(());
            }
        });
    });

    let subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");
    *handle.lock().expect("handle lock") = Some(subscription);

    harness.publish_wake(TENANT, 3);
    assert_eq!(recorder.expect_event().await.seq.as_deref(), Some("1"));

    tokio::time::timeout(HARNESS_TIMEOUT, done)
        .await
        .expect("closing from a listener callback must not deadlock")
        .expect("close task finished");

    harness.publish_wake(TENANT, 4);
    harness.reader.expect_no_read_within(QUIET_WINDOW).await;
}

#[tokio::test]
async fn closing_one_subscription_leaves_the_others_running() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(0, None))));
    harness
        .reader
        .push_page(page(vec![entry(1, "cid-1")], token(1, Some("cid-1")), true));

    let (first_listener, mut first_recorder) = recorder();
    let first = harness
        .log
        .subscribe(TENANT, "sub-1", first_listener, None)
        .await
        .expect("first subscribe");

    let (second_listener, mut second_recorder) = recorder();
    let _second = harness
        .log
        .subscribe(TENANT, "sub-2", second_listener, None)
        .await
        .expect("second subscribe");

    close(&first).await;
    harness.publish_wake(TENANT, 1);

    assert_eq!(
        second_recorder.expect_event().await.seq.as_deref(),
        Some("1")
    );
    first_recorder.expect_quiet(QUIET_WINDOW).await;
    assert_eq!(
        harness.reader.paging_reads().len(),
        1,
        "only the surviving subscription drains"
    );
}

#[tokio::test]
async fn closing_one_adapter_leaves_another_on_the_same_bus_running() {
    let bus = InProcessWakeBus::new();
    let mut closing = scripted_harness().bus(bus.clone()).build();
    let surviving = scripted_harness().bus(bus.clone()).build();

    for harness in [&closing, &surviving] {
        harness
            .reader
            .set_bounds(Some((token(0, None), token(0, None))));
    }
    surviving
        .reader
        .push_page(page(vec![entry(1, "cid-1")], token(1, Some("cid-1")), true));

    let (closing_listener, mut closing_recorder) = recorder();
    let _closing_subscription = closing
        .log
        .subscribe(TENANT, "sub-1", closing_listener, None)
        .await
        .expect("subscribe on the adapter that closes");

    let (surviving_listener, mut surviving_recorder) = recorder();
    let _surviving_subscription = surviving
        .log
        .subscribe(TENANT, "sub-1", surviving_listener, None)
        .await
        .expect("subscribe on the surviving adapter");

    closing.log.close().await;
    publish_wake(&bus, TENANT, 1);

    // Closing one adapter must not clear registrations shared through the bus.
    assert_eq!(
        surviving_recorder.expect_event().await.seq.as_deref(),
        Some("1")
    );
    closing_recorder.expect_quiet(QUIET_WINDOW).await;
    closing.reader.expect_no_read_within(QUIET_WINDOW).await;
}

#[tokio::test(start_paused = true)]
async fn closing_the_adapter_closes_every_subscription_and_the_idle_timer() {
    let mut harness = scripted_harness()
        .config(DurableEventLogConfig {
            idle_redrain_interval: Some(Duration::from_secs(30)),
            ..test_config()
        })
        .build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(0, None))));

    let (alice_listener, mut alice_recorder) = recorder();
    let _alice = harness
        .log
        .subscribe(TENANT, "sub-alice", alice_listener, None)
        .await
        .expect("alice subscribe");

    let (bob_listener, mut bob_recorder) = recorder();
    let _bob = harness
        .log
        .subscribe(OTHER_TENANT, "sub-bob", bob_listener, None)
        .await
        .expect("bob subscribe");

    settle().await;
    harness.log.close().await;

    harness.publish_wake(TENANT, 1);
    harness.publish_wake(OTHER_TENANT, 1);
    tokio::time::advance(Duration::from_secs(120)).await;
    settle().await;

    assert!(
        harness.reader.paging_reads().is_empty(),
        "neither wakes nor the idle timer may drain after close"
    );
    alice_recorder.expect_quiet(QUIET_WINDOW).await;
    bob_recorder.expect_quiet(QUIET_WINDOW).await;
}
