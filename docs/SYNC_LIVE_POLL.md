# Live and poll sync reconciliation

Rust `NativeSyncEngine` mirrors the dual-mode behavior of TypeScript `SyncEngineLevel` in `enbox/packages/agent/src/sync-engine-level.ts`.

## Modes

| TS | Rust | Behavior |
|----|------|----------|
| `startPollSync()` | `poll_reconcile()` / `SqliteNativeDwn::poll_reconcile_with_http()` | Pull-only SMT reconciliation via `MessagesSync` |
| `startLiveSync()` | `start_sync({ mode: Live })` | Initial SMT catch-up, then live link tracking |
| `enterDegradedPoll()` | `enter_degraded_poll()` | Clears live link, sets `DegradedPoll` status, recommends 15s poll interval |
| Live subscription drop + repair | `reconcile_after_live_disconnect()` | `enter_degraded_poll()` then `poll_reconcile()` |

## Live path

- **TS:** Opens `MessagesSubscribe` WebSocket subscriptions to remote DWNs and a local EventLog subscription for push-on-write.
- **Rust (today):** Subscription delivery is wired through `handle_remote_subscription_message()` / `handle_local_subscription_message()` with echo suppression and cursor monotonicity checks. WebSocket `MessagesSubscribe` client transport is tracked separately (#112 covers RecordsSubscribe loopback; agent live pull uses MessagesSubscribe in TS).

## Poll path

Both stacks use SMT diff/repair (`MessagesSync` pull) as the authoritative reconciliation mechanism. Poll runs are pull-only and safe to repeat; applied message CIDs are tracked in the echo cache to avoid push loops after live pull.

## Status mapping

| TS link status | Rust `SyncRunStatus` |
|----------------|----------------------|
| `live` | `Started` (after successful live start catch-up) |
| `degraded_poll` | `DegradedPoll` |
| `repairing` | `Repairing` (progress token gap) |
| idle / caught up | `Completed` |

## Tests

- Unit: `crates/dwn-rs-core/src/sync.rs` (`poll_reconcile`, `enter_degraded_poll`, `reconcile_after_live_disconnect`)
- Integration: `crates/dwn-rs-stores/tests/sync_integration.rs` (`http_poll_reconcile_pulls_incremental_records`, `live_poll_handoff_catches_up_after_subscription_drop`)
