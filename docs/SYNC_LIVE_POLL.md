# Live and poll sync reconciliation

> **Status:** Rust-native `NativeSyncEngine` reconciles via `MessagesSync` / SMT diff — an
> **intentional Rust extension**. Upstream Enbox removed the legacy sync state surfaces
> (`25821eda`, `chore(sync): remove legacy sync state surfaces`) and reconciles durable message
> feeds through `MessagesQuery`. This document describes the Rust extension as implemented; it is
> **not** current-upstream parity. The durable-feed migration is tracked in #187/#188/#192.

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
- Durable-feed integration replacement: tracked by #187/#188/#211 after removal of the legacy StateIndex/`MessagesSync` scenarios.
