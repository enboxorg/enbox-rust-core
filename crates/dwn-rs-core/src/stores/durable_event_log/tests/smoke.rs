//! Adapter surface that does not depend on replay or drain behavior, plus the
//! minimum end-to-end coverage that proves the harness itself works.

use std::time::Duration;

use super::support::*;
use crate::errors::EventLogError;
use crate::stores::durable_event_log::DurableEventLogConfig;
use crate::stores::{
    EventLog, EventLogReadOptions, EventLogReplayBounds, EventLogTrimBound, KeyValues,
};
use crate::MessageEvent;

#[tokio::test]
async fn emit_is_unsupported() {
    let harness = scripted_harness().build();
    let event = MessageEvent {
        message: write_message(None),
        initial_write: None,
    };

    let error = harness
        .log
        .emit(TENANT, event, KeyValues::new(), "cid-1")
        .await
        .expect_err("the adapter never writes to the feed");

    match error {
        EventLogError::UnsupportedReadOption(operation) => assert_eq!(operation, "emit"),
        other => panic!("expected an unsupported-operation error, got {other:?}"),
    }
    assert!(
        harness.reader.reads().is_empty(),
        "emit must not touch the reader"
    );
}

#[tokio::test]
async fn trim_is_unsupported() {
    let harness = scripted_harness().build();

    let error = harness
        .log
        .trim(TENANT, EventLogTrimBound::Sequence(1))
        .await
        .expect_err("the adapter never trims feed history");

    match error {
        EventLogError::UnsupportedReadOption(operation) => assert_eq!(operation, "trim"),
        other => panic!("expected an unsupported-operation error, got {other:?}"),
    }
}

#[tokio::test]
async fn read_delegates_to_the_reader() {
    let harness = scripted_harness().build();
    let scripted = page(vec![entry(1, "cid-1")], token(1, Some("cid-1")), true);
    harness.reader.push_page(scripted.clone());

    let options = EventLogReadOptions {
        cursor: Some(token(0, None)),
        limit: Some(7),
        filters: None,
    };
    let result = harness
        .log
        .read(TENANT, Some(options.clone()))
        .await
        .expect("read passes through");

    assert_eq!(result, scripted);

    harness
        .log
        .read(TENANT, None)
        .await
        .expect("default options are accepted");

    let reads = harness.reader.reads();
    assert_eq!(reads.len(), 2);
    assert_eq!(reads[0].tenant, TENANT);
    assert_eq!(reads[0].cursor, options.cursor);
    assert_eq!(reads[0].limit, options.limit);
    assert_eq!(reads[1].cursor, None);
    assert_eq!(reads[1].limit, None);
}

#[tokio::test]
async fn get_replay_bounds_reports_reader_bounds() {
    let harness = scripted_harness().build();

    assert_eq!(
        harness
            .log
            .get_replay_bounds(TENANT)
            .await
            .expect("empty feed bounds"),
        None
    );

    harness
        .reader
        .set_bounds(Some((token(0, None), token(3, Some("cid-3")))));

    assert_eq!(
        harness.log.get_replay_bounds(TENANT).await.expect("bounds"),
        Some(EventLogReplayBounds {
            oldest: token(0, None),
            latest: token(3, Some("cid-3")),
        })
    );
}

#[tokio::test]
async fn subscribe_after_close_is_rejected() {
    let mut harness = scripted_harness().build();
    harness.log.close().await;

    let (listener, _recorder) = recorder();
    let Err(error) = harness.log.subscribe(TENANT, "sub-1", listener, None).await else {
        panic!("a closed adapter accepts no subscriptions");
    };

    assert!(matches!(error, EventLogError::Closed), "got {error:?}");
    assert!(
        harness.reader.reads().is_empty(),
        "a rejected subscribe must not read the feed"
    );
}

#[tokio::test]
async fn configured_read_limit_is_clamped_to_at_least_one() {
    let harness = scripted_harness()
        .config(DurableEventLogConfig {
            read_limit: 0,
            ..test_config()
        })
        .build();

    let (listener, _recorder) = recorder();
    let _subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    harness.publish_wake(TENANT, 1);

    let reads = harness.reader.await_reads(2).await;
    // The first read is the empty-feed anchor capture, which always uses limit 0.
    assert_eq!(reads[0].limit, Some(0));
    assert_eq!(reads[1].limit, Some(1));
}

#[tokio::test(start_paused = true)]
async fn a_zero_idle_interval_disables_polling() {
    let harness = scripted_harness()
        .config(DurableEventLogConfig {
            idle_redrain_interval: Some(Duration::ZERO),
            ..test_config()
        })
        .build();

    let (listener, mut recorder) = recorder();
    let _subscription = harness
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    let after_open = harness.reader.read_count();
    tokio::time::advance(Duration::from_secs(300)).await;
    tokio::task::yield_now().await;

    assert_eq!(
        harness.reader.read_count(),
        after_open,
        "a disabled idle timer must never poll the feed"
    );
    recorder.expect_quiet(QUIET_WINDOW).await;
}
