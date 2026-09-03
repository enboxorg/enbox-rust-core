//! Initial-write attachment (plan §1.8, option 1) and feed-backed delivery of
//! every message type the durable feed carries.

use super::support::*;
use crate::stores::durable_event_log::DurableEventLogConfig;
use crate::stores::{EventLog, EventLogSubscribeOptions};

fn from_start() -> Option<EventLogSubscribeOptions> {
    Some(EventLogSubscribeOptions {
        cursor: Some(token(0, None)),
        filters: None,
    })
}

#[tokio::test]
async fn replay_and_live_delivery_both_attach_the_initial_write() {
    let resolver = StubResolver::resolving(initial_write_message());
    let harness = scripted_harness().resolver(resolver.shared()).build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(1, Some("cid-1")))));
    harness
        .reader
        .push_page(page(vec![entry(1, "cid-1")], token(1, Some("cid-1")), true));
    harness
        .reader
        .push_page(page(vec![entry(2, "cid-2")], token(2, Some("cid-2")), true));

    let (listener, mut recorder) = recorder();
    let _subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, from_start())
        .await
        .expect("cursor subscribe");

    let replayed = recorder.expect_event().await;
    assert!(
        replayed.event.initial_write.is_some(),
        "replayed events carry the resolved initial write"
    );
    assert_eq!(recorder.expect_eose().await, token(1, Some("cid-1")));

    harness.publish_wake(TENANT, 2);

    let live = recorder.expect_event().await;
    assert!(
        live.event.initial_write.is_some(),
        "live events resolve through the same delivery path"
    );
    assert_eq!(resolver.calls(), 2);
}

#[tokio::test]
async fn without_a_resolver_the_readers_initial_write_is_preserved() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(0, None))));

    let mut prefilled = entry(1, "cid-1");
    prefilled.event.initial_write = Some(initial_write_message());
    harness
        .reader
        .push_page(page(vec![prefilled], token(1, Some("cid-1")), true));

    let (listener, mut recorder) = recorder();
    let _subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    harness.publish_wake(TENANT, 1);

    let delivered = recorder.expect_event().await;
    assert!(
        delivered.event.initial_write.is_some(),
        "an adapter without a resolver must not clear what the reader attached"
    );
}

#[tokio::test]
async fn a_resolver_failure_during_replay_fails_the_open() {
    let resolver = StubResolver::resolving(initial_write_message());
    resolver.fail_next(1);
    let harness = scripted_harness().resolver(resolver.shared()).build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(1, Some("cid-1")))));
    harness
        .reader
        .push_page(page(vec![entry(1, "cid-1")], token(1, Some("cid-1")), true));

    let (listener, mut recorder) = recorder();
    let Err(error) = harness
        .log
        .subscribe(TENANT, "sub-1", listener, from_start())
        .await
    else {
        panic!("a replay-time resolver failure must fail the open");
    };

    assert!(
        error
            .to_string()
            .contains("initial-write resolution failed"),
        "unexpected error: {error}"
    );
    recorder.expect_quiet(QUIET_WINDOW).await;

    // The failed open cleaned up, so later wakes reach nothing.
    harness.publish_wake(TENANT, 2);
    harness.reader.expect_no_read_within(QUIET_WINDOW).await;
}

#[tokio::test]
async fn a_resolver_failure_during_a_live_drain_keeps_the_cursor() {
    let sink = ErrorSink::new();
    let resolver = StubResolver::resolving(initial_write_message());
    resolver.fail_next(1);
    let harness = scripted_harness()
        .resolver(resolver.shared())
        .config(DurableEventLogConfig {
            on_error: Some(sink.sink()),
            ..test_config()
        })
        .build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(0, None))));
    harness
        .reader
        .push_page(page(vec![entry(1, "cid-1")], token(1, Some("cid-1")), true));
    harness
        .reader
        .push_page(page(vec![entry(1, "cid-1")], token(1, Some("cid-1")), true));

    let (listener, mut recorder) = recorder();
    let _subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    harness.publish_wake(TENANT, 1);
    let errors = sink.await_errors(1).await;
    assert!(
        errors[0].contains("initial-write resolution failed"),
        "unexpected background error: {errors:?}"
    );
    recorder.expect_quiet(QUIET_WINDOW).await;

    // The affected entry is not skipped: the retry re-reads from the same cursor.
    harness.publish_wake(TENANT, 1);
    let delivered = recorder.expect_event().await;
    assert_eq!(delivered.seq.as_deref(), Some("1"));
    assert!(delivered.event.initial_write.is_some());

    let reads = harness.reader.paging_reads();
    assert_eq!(reads[0].cursor, reads[1].cursor);
}
