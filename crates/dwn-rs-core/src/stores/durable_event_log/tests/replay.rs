//! Cursor-mode replay up to the frozen head, and the EOSE that ends it.
//!
//! Replay runs inline in `subscribe()`, so every failure below is an open
//! failure returned to the caller rather than a terminal subscription message.

use super::support::*;
use crate::errors::EventLogError;
use crate::stores::durable_event_log::DurableEventLogConfig;
use crate::stores::{EventLog, EventLogSubscribeOptions, ProgressGapInfo, ProgressGapReason};

const OTHER_EPOCH: &str = "01JBQ0OTHEREPOCH0000000000";

fn resume(cursor: crate::ProgressToken) -> Option<EventLogSubscribeOptions> {
    Some(EventLogSubscribeOptions {
        cursor: Some(cursor),
        filters: None,
    })
}

fn expect_gap(error: EventLogError) -> ProgressGapInfo {
    match error {
        EventLogError::ProgressGap(gap) => *gap,
        other => panic!("expected a progress gap, got {other:?}"),
    }
}

fn expect_internal(error: EventLogError, contains: &str) {
    let rendered = error.to_string();
    assert!(
        rendered.contains(contains),
        "expected an internal error mentioning {contains:?}, got {rendered:?}"
    );
}

#[tokio::test]
async fn replay_delivers_in_order_then_a_single_eose() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(3, Some("cid-3")))));
    harness.reader.push_page(page(
        vec![entry(1, "cid-1"), entry(2, "cid-2"), entry(3, "cid-3")],
        token(3, Some("cid-3")),
        true,
    ));

    let (listener, mut recorder) = recorder();
    let _subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, resume(token(0, None)))
        .await
        .expect("cursor subscribe");

    let delivered = recorder.expect_events(3).await;
    for (index, event) in delivered.iter().enumerate() {
        let position = (index + 1).to_string();
        assert_eq!(event.seq.as_ref(), Some(&position));
        assert_eq!(event.cursor.position, position);
        assert_eq!(event.message_cid, Some(format!("cid-{position}")));
        // All events from one page share that page's stream and epoch.
        assert_eq!(event.cursor.stream_id, token(0, None).stream_id);
        assert_eq!(event.cursor.epoch, EPOCH);
    }

    assert_eq!(recorder.expect_eose().await, token(3, Some("cid-3")));
    recorder.expect_quiet(QUIET_WINDOW).await;
}

#[tokio::test]
async fn replay_stops_at_the_frozen_head_and_later_rows_arrive_live() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(2, Some("cid-2")))));
    // The page overshoots the frozen head: position 3 was committed during replay.
    harness.reader.push_page(page(
        vec![entry(1, "cid-1"), entry(2, "cid-2"), entry(3, "cid-3")],
        token(3, Some("cid-3")),
        true,
    ));
    harness
        .reader
        .push_page(page(vec![entry(3, "cid-3")], token(3, Some("cid-3")), true));

    let (listener, mut recorder) = recorder();
    let _subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, resume(token(0, None)))
        .await
        .expect("cursor subscribe");

    let replayed = recorder.expect_events(2).await;
    assert_eq!(replayed[0].seq.as_deref(), Some("1"));
    assert_eq!(replayed[1].seq.as_deref(), Some("2"));
    assert_eq!(recorder.expect_eose().await, token(2, Some("cid-2")));

    harness.publish_wake(TENANT, 3);

    let live = recorder.expect_event().await;
    assert_eq!(live.seq.as_deref(), Some("3"));
    assert_eq!(live.cursor.position, "3");

    // Live delivery resumes from the frozen head, not from the overshooting scan.
    let reads = harness.reader.paging_reads();
    assert_eq!(reads.len(), 2);
    assert_eq!(reads[0].cursor, Some(token(0, None)));
    assert_eq!(reads[1].cursor, Some(token(2, Some("cid-2"))));
}

#[tokio::test]
async fn eose_uses_the_frozen_head_when_filters_match_nothing() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(4, None))));
    harness.reader.push_page(empty_page(token(4, None), true));

    let (listener, mut recorder) = recorder();
    let requested = token(1, Some("cid-1"));
    let _subscription = harness
        .log
        .subscribe(
            TENANT,
            "sub-1",
            listener,
            Some(EventLogSubscribeOptions {
                cursor: Some(requested.clone()),
                filters: Some(index_filters("protocol", "http://example.com/notes")),
            }),
        )
        .await
        .expect("cursor subscribe");

    let eose = recorder.expect_eose().await;
    // The frozen high-water token, including one without a message CID — never
    // an echo of the input cursor.
    assert_eq!(eose, token(4, None));
    assert_ne!(eose, requested);

    let reads = harness.reader.paging_reads();
    assert_eq!(reads.len(), 1);
    assert!(
        reads[0].filters.is_some(),
        "replay reads carry the subscription filters"
    );
}

#[tokio::test]
async fn an_empty_feed_replays_from_the_position_zero_anchor() {
    let harness = scripted_harness().build();
    harness.reader.set_bounds(None);

    let (listener, mut recorder) = recorder();
    let _subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, resume(token(0, None)))
        .await
        .expect("cursor subscribe");

    assert_eq!(recorder.expect_eose().await, token(0, None));
    assert!(
        harness.reader.paging_reads().is_empty(),
        "an empty feed has nothing to replay"
    );
    recorder.expect_quiet(QUIET_WINDOW).await;
}

#[tokio::test]
async fn a_cursor_at_the_frozen_head_sends_eose_without_reading() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(3, Some("cid-3")))));

    let (listener, mut recorder) = recorder();
    let _subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, resume(token(3, Some("cid-3"))))
        .await
        .expect("cursor subscribe");

    assert_eq!(recorder.expect_eose().await, token(3, Some("cid-3")));
    assert!(harness.reader.paging_reads().is_empty());
}

#[tokio::test]
async fn replay_advances_over_filtered_and_deleted_positions() {
    let harness = scripted_harness()
        .config(DurableEventLogConfig {
            read_limit: 2,
            ..test_config()
        })
        .build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(5, None))));
    harness.reader.push_pages([
        page(vec![entry(1, "cid-1")], token(2, None), false),
        // Drained below the frozen head still leaves replay unfinished.
        empty_page(token(4, None), true),
        page(vec![entry(5, "cid-5")], token(5, Some("cid-5")), true),
    ]);

    let (listener, mut recorder) = recorder();
    let _subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, resume(token(0, None)))
        .await
        .expect("cursor subscribe");

    let delivered = recorder.expect_events(2).await;
    assert_eq!(delivered[0].seq.as_deref(), Some("1"));
    assert_eq!(delivered[1].seq.as_deref(), Some("5"));

    // EOSE is the frozen token itself, not the scan cursor that reached it.
    assert_eq!(recorder.expect_eose().await, token(5, None));

    let reads = harness.reader.paging_reads();
    let cursors: Vec<_> = reads.iter().map(|read| read.cursor.clone()).collect();
    assert_eq!(
        cursors,
        vec![
            Some(token(0, None)),
            Some(token(2, None)),
            Some(token(4, None)),
        ]
    );
    assert!(reads.iter().all(|read| read.limit == Some(2)));
}

#[tokio::test]
async fn a_progress_gap_during_cursor_validation_fails_the_open() {
    let harness = scripted_harness().build();
    let requested = token(1, Some("cid-1"));
    let gapped = requested.clone();
    harness.reader.push_zero_limit_error(error_factory(move || {
        progress_gap_error(
            gapped.clone(),
            token(9, None),
            ProgressGapReason::TokenTooOld,
        )
    }));

    let (listener, mut recorder) = recorder();
    let Err(error) = harness
        .log
        .subscribe(TENANT, "sub-1", listener, resume(requested.clone()))
        .await
    else {
        panic!("a gapped cursor cannot open a subscription");
    };

    let gap = expect_gap(error);
    assert_eq!(gap.reason, ProgressGapReason::TokenTooOld);
    assert_eq!(gap.requested, requested);
    assert!(
        harness.reader.bounds_calls().is_empty(),
        "validation fails before the frozen head is captured"
    );

    // Nothing was installed, so a later wake reaches no subscription.
    harness.publish_wake(TENANT, 2);
    harness.reader.expect_no_read_within(QUIET_WINDOW).await;
    recorder.expect_quiet(QUIET_WINDOW).await;
}

#[tokio::test]
async fn a_frozen_head_behind_the_requested_cursor_is_a_progress_gap() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(2, Some("cid-2")))));

    let (listener, mut recorder) = recorder();
    let requested = token(5, Some("cid-5"));
    let Err(error) = harness
        .log
        .subscribe(TENANT, "sub-1", listener, resume(requested.clone()))
        .await
    else {
        panic!("a cursor ahead of the feed head cannot open a subscription");
    };

    let gap = expect_gap(error);
    assert_eq!(gap.reason, ProgressGapReason::TokenTooNew);
    assert_eq!(gap.requested, requested);
    assert_eq!(gap.latest_available, token(2, Some("cid-2")));
    assert_eq!(gap.oldest_available, token(0, None));

    harness.publish_wake(TENANT, 6);
    harness.reader.expect_no_read_within(QUIET_WINDOW).await;
    recorder.expect_quiet(QUIET_WINDOW).await;
}

#[tokio::test]
async fn a_cursor_from_another_epoch_is_a_progress_gap() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(3, Some("cid-3")))));

    let (listener, _recorder) = recorder();
    let requested = tenant_token(TENANT, OTHER_EPOCH, 1, Some("cid-1"));
    let Err(error) = harness
        .log
        .subscribe(TENANT, "sub-1", listener, resume(requested.clone()))
        .await
    else {
        panic!("a cursor from a replaced epoch cannot open a subscription");
    };

    let gap = expect_gap(error);
    assert_eq!(gap.reason, ProgressGapReason::EpochMismatch);
    assert_eq!(gap.requested, requested);
    assert_eq!(gap.latest_available, token(3, Some("cid-3")));

    harness.publish_wake(TENANT, 4);
    harness.reader.expect_no_read_within(QUIET_WINDOW).await;
}

#[tokio::test]
async fn a_cursor_from_another_stream_is_a_progress_gap() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(3, Some("cid-3")))));

    let (listener, _recorder) = recorder();
    let requested = tenant_token(OTHER_TENANT, EPOCH, 1, Some("cid-1"));
    let Err(error) = harness
        .log
        .subscribe(TENANT, "sub-1", listener, resume(requested.clone()))
        .await
    else {
        panic!("a cursor from another tenant's stream cannot open a subscription");
    };

    let gap = expect_gap(error);
    assert_eq!(gap.reason, ProgressGapReason::StreamMismatch);
    assert_eq!(gap.requested, requested);

    harness.publish_wake(TENANT, 4);
    harness.reader.expect_no_read_within(QUIET_WINDOW).await;
}

#[tokio::test]
async fn a_replay_page_without_a_scan_cursor_fails_the_open() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(3, Some("cid-3")))));
    harness
        .reader
        .push_page(page_without_cursor(vec![entry(1, "cid-1")], false));

    let (listener, mut recorder) = recorder();
    let Err(error) = harness
        .log
        .subscribe(TENANT, "sub-1", listener, resume(token(0, None)))
        .await
    else {
        panic!("a page without a scan cursor cannot be replayed");
    };

    expect_internal(error, "no replay scan cursor");
    // The cursor is checked before any entry is delivered.
    recorder.expect_quiet(QUIET_WINDOW).await;

    harness.publish_wake(TENANT, 4);
    harness.reader.expect_no_read_within(QUIET_WINDOW).await;
}

#[tokio::test]
async fn out_of_order_replay_entries_fail_the_open() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(3, Some("cid-3")))));
    harness.reader.push_page(page(
        vec![entry(2, "cid-2"), entry(1, "cid-1")],
        token(3, Some("cid-3")),
        true,
    ));

    let (listener, mut recorder) = recorder();
    let Err(error) = harness
        .log
        .subscribe(TENANT, "sub-1", listener, resume(token(0, None)))
        .await
    else {
        panic!("entries must be strictly increasing within a page");
    };

    expect_internal(error, "strictly increasing");
    // The entry ahead of the fault was already delivered; the open still fails.
    assert_eq!(recorder.drain_event_positions(), vec!["2".to_string()]);

    harness.publish_wake(TENANT, 4);
    harness.reader.expect_no_read_within(QUIET_WINDOW).await;
}

#[tokio::test]
async fn a_replay_scan_cursor_that_does_not_advance_fails_the_open() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(5, None))));
    harness.reader.push_page(empty_page(token(1, None), false));

    let (listener, _recorder) = recorder();
    let Err(error) = harness
        .log
        .subscribe(TENANT, "sub-1", listener, resume(token(1, Some("cid-1"))))
        .await
    else {
        panic!("replay must make forward progress toward the frozen head");
    };

    expect_internal(error, "did not advance");

    harness.publish_wake(TENANT, 6);
    harness.reader.expect_no_read_within(QUIET_WINDOW).await;
}

#[tokio::test]
async fn a_replay_scan_cursor_from_another_epoch_fails_the_open() {
    let harness = scripted_harness().build();
    harness
        .reader
        .set_bounds(Some((token(0, None), token(5, None))));
    harness.reader.push_page(empty_page(
        tenant_token(TENANT, OTHER_EPOCH, 3, None),
        false,
    ));

    let (listener, _recorder) = recorder();
    let Err(error) = harness
        .log
        .subscribe(TENANT, "sub-1", listener, resume(token(0, None)))
        .await
    else {
        panic!("a mid-replay epoch change cannot be replayed across");
    };

    expect_internal(error, "epoch does not match");

    harness.publish_wake(TENANT, 6);
    harness.reader.expect_no_read_within(QUIET_WINDOW).await;
}
