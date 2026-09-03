//! Live drain behavior: wakes as hints, one drain per subscription, and the
//! terminal error that ends one.

use std::time::Duration;

use super::support::*;
use crate::stores::durable_event_log::DurableEventLogConfig;
use crate::stores::{EventLog, EventLogSubscribeOptions, ProgressGapReason, SubscriptionErrorCode};
use crate::Value;

/// Bounds with existing history, so a no-cursor subscription starts above them.
fn existing_history(harness: &ScriptedHarness, head: u64, cid: &str) {
    harness
        .reader
        .set_bounds(Some((token(0, None), token(head, Some(cid)))));
}

#[tokio::test]
async fn no_cursor_subscriptions_deliver_only_new_events_and_never_send_eose() {
    let harness = scripted_harness().build();
    existing_history(&harness, 3, "cid-3");
    harness
        .reader
        .push_page(page(vec![entry(4, "cid-4")], token(4, Some("cid-4")), true));

    let (listener, mut recorder) = recorder();
    let _subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    harness.publish_wake(TENANT, 4);

    let delivered = recorder.expect_event().await;
    assert_eq!(delivered.seq.as_deref(), Some("4"));
    // Delivery starts at the frozen head, so nothing already in the feed replays.
    assert_eq!(
        harness.reader.paging_reads()[0].cursor,
        Some(token(3, Some("cid-3")))
    );
    recorder.expect_quiet(QUIET_WINDOW).await;
}

#[tokio::test]
async fn a_wake_during_installation_drains_once_the_subscription_is_live() {
    let harness = scripted_harness().build();
    harness.reader.set_bounds(None);
    // Freeze the empty-feed anchor read so the wake lands while the phase is Replay.
    let mut anchor = harness
        .reader
        .push_gated_zero_limit_page(empty_page(token(0, None), true));
    harness
        .reader
        .push_page(page(vec![entry(1, "cid-1")], token(1, Some("cid-1")), true));

    let (listener, mut recorder) = recorder();
    let log = &harness.log;
    let subscribe = async {
        log.subscribe(TENANT, "sub-1", listener, None)
            .await
            .expect("no-cursor subscribe")
    };

    let subscription = async {
        anchor.entered().await;
        harness.publish_wake(TENANT, 1);
        settle().await;
        anchor.release();
    };

    let (subscription, ()) = tokio::join!(subscribe, subscription);
    let _subscription = subscription;

    let delivered = recorder.expect_event().await;
    assert_eq!(delivered.seq.as_deref(), Some("1"));
    assert_eq!(harness.reader.paging_reads().len(), 1);
}

#[tokio::test]
async fn a_wake_during_replay_drains_after_eose() {
    let harness = scripted_harness().build();
    existing_history(&harness, 2, "cid-2");
    let mut replay = harness.reader.push_gated_page(page(
        vec![entry(1, "cid-1"), entry(2, "cid-2")],
        token(2, Some("cid-2")),
        true,
    ));
    harness
        .reader
        .push_page(page(vec![entry(3, "cid-3")], token(3, Some("cid-3")), true));

    let (listener, mut recorder) = recorder();
    let log = &harness.log;
    let subscribe = async {
        log.subscribe(
            TENANT,
            "sub-1",
            listener,
            Some(EventLogSubscribeOptions {
                cursor: Some(token(0, None)),
                filters: None,
            }),
        )
        .await
        .expect("cursor subscribe")
    };

    let waker = async {
        replay.entered().await;
        harness.publish_wake(TENANT, 3);
        settle().await;
        replay.release();
    };

    let (subscription, ()) = tokio::join!(subscribe, waker);
    let _subscription = subscription;

    // The wake queued during replay must not overtake EOSE.
    let replayed = recorder.expect_events(2).await;
    assert_eq!(replayed[1].seq.as_deref(), Some("2"));
    assert_eq!(recorder.expect_eose().await, token(2, Some("cid-2")));

    let live = recorder.expect_event().await;
    assert_eq!(live.seq.as_deref(), Some("3"));
}

#[tokio::test]
async fn a_wake_during_an_active_drain_produces_exactly_one_follow_up_drain() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(0, None))));
    let mut first = harness.reader.push_gated_page(page(
        vec![entry(1, "cid-1")],
        token(1, Some("cid-1")),
        true,
    ));
    harness
        .reader
        .push_page(page(vec![entry(2, "cid-2")], token(2, Some("cid-2")), true));

    let (listener, mut recorder) = recorder();
    let _subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    harness.publish_wake(TENANT, 1);
    first.entered().await;

    // Both wakes arrive while the drain holds its claim; they coalesce into one.
    harness.publish_wake(TENANT, 2);
    harness.publish_wake(TENANT, 2);
    settle().await;
    first.release();

    let delivered = recorder.expect_events(2).await;
    let positions: Vec<_> = delivered
        .iter()
        .map(|event| event.seq.clone().expect("seq"))
        .collect();
    assert_eq!(positions, vec!["1".to_string(), "2".to_string()]);

    harness.reader.expect_no_read_within(QUIET_WINDOW).await;
    assert_eq!(
        harness.reader.paging_reads().len(),
        2,
        "coalesced wakes must not each start their own drain"
    );
    recorder.expect_quiet(QUIET_WINDOW).await;
}

#[tokio::test]
async fn a_drain_stops_at_drained_and_resumes_from_the_stored_cursor() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(0, None))));
    harness.reader.push_pages([
        page(vec![entry(1, "cid-1")], token(1, Some("cid-1")), true),
        page(vec![entry(2, "cid-2")], token(2, Some("cid-2")), true),
    ]);

    let (listener, mut recorder) = recorder();
    let _subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    harness.publish_wake(TENANT, 1);
    assert_eq!(recorder.expect_event().await.seq.as_deref(), Some("1"));
    harness.reader.expect_no_read_within(QUIET_WINDOW).await;

    harness.publish_wake(TENANT, 2);
    assert_eq!(recorder.expect_event().await.seq.as_deref(), Some("2"));

    let reads = harness.reader.paging_reads();
    assert_eq!(reads.len(), 2);
    assert_eq!(reads[0].cursor, Some(token(0, None)));
    assert_eq!(reads[1].cursor, Some(token(1, Some("cid-1"))));
}

#[tokio::test]
async fn multi_page_drains_honor_the_read_limit() {
    let harness = scripted_harness()
        .config(DurableEventLogConfig {
            read_limit: 2,
            ..test_config()
        })
        .build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(0, None))));
    harness.reader.push_pages([
        page(
            vec![entry(1, "cid-1"), entry(2, "cid-2")],
            token(2, Some("cid-2")),
            false,
        ),
        page(vec![entry(3, "cid-3")], token(3, Some("cid-3")), true),
    ]);

    let (listener, mut recorder) = recorder();
    let _subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    harness.publish_wake(TENANT, 3);

    let delivered = recorder.expect_events(3).await;
    let positions: Vec<_> = delivered
        .iter()
        .map(|event| event.seq.clone().expect("seq"))
        .collect();
    assert_eq!(
        positions,
        vec!["1".to_string(), "2".to_string(), "3".to_string()]
    );

    let reads = harness.reader.paging_reads();
    assert_eq!(reads.len(), 2, "one wake, one drain, two pages");
    assert!(reads.iter().all(|read| read.limit == Some(2)));
}

#[tokio::test]
async fn wakes_for_other_tenants_are_ignored() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(0, None))));

    let (listener, mut recorder) = recorder();
    let _subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    harness.publish_wake(OTHER_TENANT, 1);

    harness.reader.expect_no_read_within(QUIET_WINDOW).await;
    recorder.expect_quiet(QUIET_WINDOW).await;
}

#[tokio::test]
async fn a_transient_failure_keeps_the_cursor_and_retries_on_the_next_wake() {
    let sink = ErrorSink::new();
    let harness = scripted_harness()
        .config(DurableEventLogConfig {
            on_error: Some(sink.sink()),
            ..test_config()
        })
        .build();
    existing_history(&harness, 2, "cid-2");
    harness
        .reader
        .push_error(error_factory(|| transient_error("feed unavailable")));
    harness
        .reader
        .push_page(page(vec![entry(3, "cid-3")], token(3, Some("cid-3")), true));

    let (listener, mut recorder) = recorder();
    let _subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    harness.publish_wake(TENANT, 3);
    let errors = sink.await_errors(1).await;
    assert!(
        errors[0].contains("feed unavailable"),
        "unexpected background error: {errors:?}"
    );
    recorder.expect_quiet(QUIET_WINDOW).await;

    // The subscription survives, and the retry resumes from the same cursor.
    harness.publish_wake(TENANT, 3);
    assert_eq!(recorder.expect_event().await.seq.as_deref(), Some("3"));

    let reads = harness.reader.paging_reads();
    assert_eq!(reads[0].cursor, Some(token(2, Some("cid-2"))));
    assert_eq!(reads[1].cursor, Some(token(2, Some("cid-2"))));
}

#[tokio::test]
async fn a_live_progress_gap_sends_one_terminal_error_and_closes() {
    let harness = scripted_harness().build();
    existing_history(&harness, 2, "cid-2");
    harness.reader.push_error(error_factory(|| {
        progress_gap_error(
            token(2, Some("cid-2")),
            token(9, None),
            ProgressGapReason::TokenTooOld,
        )
    }));

    let (listener, mut recorder) = recorder();
    let _subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    harness.publish_wake(TENANT, 3);

    let (cursor, error) = recorder.expect_error().await;
    assert_eq!(cursor, token(2, Some("cid-2")));
    assert_eq!(error.code, SubscriptionErrorCode::ProgressGap);
    assert!(
        error.detail.contains("TokenTooOld"),
        "terminal error should carry the gap reason: {}",
        error.detail
    );

    // The subscription is closed and deregistered: later wakes do nothing.
    harness.publish_wake(TENANT, 4);
    harness.reader.expect_no_read_within(QUIET_WINDOW).await;
    recorder.expect_quiet(QUIET_WINDOW).await;
}

#[tokio::test(start_paused = true)]
async fn dropped_wakes_are_recovered_by_idle_polling() {
    let harness = scripted_harness()
        .config(DurableEventLogConfig {
            idle_redrain_interval: Some(Duration::from_secs(30)),
            ..test_config()
        })
        .build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(0, None))));
    harness
        .reader
        .push_page(page(vec![entry(1, "cid-1")], token(1, Some("cid-1")), true));

    let (listener, mut recorder) = recorder();
    let _subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    // Let the idle timer register its first deadline before the clock jumps;
    // a paused clock only fires deadlines that already exist.
    settle().await;

    // No wake is ever published: the idle timer alone must find the row.
    tokio::time::advance(Duration::from_secs(30)).await;

    assert_eq!(recorder.expect_event().await.seq.as_deref(), Some("1"));
}

#[tokio::test]
async fn delivered_events_carry_the_upstream_envelope() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(0, None))));

    let mut boolean = entry(1, "cid-1");
    boolean
        .indexes
        .insert("isLatestBaseState".to_string(), Value::Bool(true));
    boolean.indexes.insert(
        "protocol".to_string(),
        Value::String("http://example.com/notes".to_string()),
    );
    boolean.encoded_data = Some("aGVsbG8".to_string());

    let mut stringly = entry(2, "cid-2");
    stringly.indexes.insert(
        "isLatestBaseState".to_string(),
        Value::String("true".to_string()),
    );

    harness
        .reader
        .push_page(page(vec![boolean, stringly], token(2, Some("cid-2")), true));

    let (listener, mut recorder) = recorder();
    let _subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    harness.publish_wake(TENANT, 2);

    let delivered = recorder.expect_events(2).await;
    assert_eq!(delivered[0].seq.as_deref(), Some("1"));
    assert_eq!(delivered[0].message_cid.as_deref(), Some("cid-1"));
    assert_eq!(delivered[0].is_latest_base_state, Some(true));
    assert_eq!(
        delivered[0].protocol.as_deref(),
        Some("http://example.com/notes")
    );
    assert_eq!(delivered[0].encoded_data.as_deref(), Some("aGVsbG8"));
    // The event token takes stream and epoch from the page cursor.
    assert_eq!(delivered[0].cursor, token(1, Some("cid-1")));

    // Indexes stored as strings carry the same meaning as boolean indexes.
    assert_eq!(delivered[1].is_latest_base_state, Some(true));
    assert_eq!(delivered[1].protocol, None);
    assert_eq!(delivered[1].encoded_data, None);
}
