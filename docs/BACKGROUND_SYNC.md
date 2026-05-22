# Mobile Background Sync Entry Points

## Goal

Mobile apps must be able to trigger bounded Rust sync work from native background execution without a foreground React Native app, Bun, Node, or a long-lived JavaScript runtime. Every API below is safe to call repeatedly and can resume after process death through durable checkpoints.

## Core Entry Points

The FFI facade should expose a small set of background-safe calls. Names are provisional, but the inputs are required.

### `sync_once(request)`

Runs one bounded unit of sync work for a tenant.

Required request fields:

- `tenant`: tenant DID whose local DWN state is being synchronized.
- `remote`: remote DWN endpoint or peer identifier.
- `direction`: `pull`, `push`, or `bidirectional`.
- `deadline`: absolute monotonic deadline or max duration enforced in Rust.
- `connectivity`: current network constraints from the native platform.

Optional request fields:

- `protocol`: protocol URI for scoped sync; omitted means global sync.
- `max_records`: max message records to process before yielding.
- `max_bytes`: max data bytes to upload/download before yielding.
- `allow_metered`: whether metered network use is allowed.
- `allow_roaming`: whether roaming network use is allowed.
- `reason`: `push_notification`, `periodic`, `manual`, `repair`, or `startup_resume`.

Result fields:

- `status`: `completed`, `partial`, `no_connectivity`, `cancelled`, `deadline_exceeded`, or `failed`.
- `checkpoint`: latest durable checkpoint key and progress metadata.
- `records_pushed`, `records_pulled`, `bytes_uploaded`, `bytes_downloaded`.
- `next_recommended_delay`: optional platform scheduling hint.
- `error`: typed error details when `status` is `failed`.

### `resume_pending(request)`

Continues previously checkpointed work for a tenant under the same deadline and connectivity rules.

Required request fields:

- `tenant`
- `deadline`
- `connectivity`

Optional request fields:

- `remote`
- `protocol`
- `direction`
- `max_records`
- `max_bytes`

This entry point lets native startup, notification wake, WorkManager, or BGTaskScheduler resume partial work without reconstructing higher-level JS state.

### `sync_status(query)`

Reads durable sync state without performing network work.

Query fields:

- `tenant`
- `remote` optional
- `protocol` optional

Result fields:

- Latest local root and known remote root if available.
- Pending prefixes or queued operation counts.
- Last successful sync timestamp.
- Last failure code and retry hint.

## Connectivity Input

Rust should not infer mobile network policy from platform-specific APIs. The host passes a normalized snapshot:

- `online`: whether a usable network is currently available.
- `expensive`: true for metered, constrained, or low-data-mode connections.
- `roaming`: whether the device is roaming.
- `background_restricted`: whether the OS says background work is currently restricted.
- `power_save`: whether battery saver/low-power mode is active.
- `preferred_max_bytes`: platform-provided or app-configured byte budget.

If policy denies the requested work, Rust returns `no_connectivity` or `partial` with the existing checkpoint unchanged.

## Durable Checkpoints

Checkpoint identity should include:

- `tenant`
- `remote`
- `protocol` or `global`
- `direction`

Checkpoint state should include:

- Last local StateIndex root observed by the sync attempt.
- Last remote root observed by the sync attempt.
- Pending `MessagesSync` diff prefixes.
- Queued local message CIDs for push.
- Queued remote message CIDs for pull.
- Data transfer cursors for large records.
- Last subscription `ProgressToken` when live replay contributed to sync.
- Retry count, last error code, and next eligible retry time.

Checkpoints must be written before crossing a deadline-sensitive boundary: before starting a network page, before large data transfer, after each accepted batch, and before returning `partial`.

## Idempotency And Locking

Background sync may be started by multiple native triggers. The Rust core should enforce a per-scope lease keyed by tenant, remote, protocol/global, and direction.

Rules:

- If the same scope is already running, a second caller should return the active operation status or `already_running`.
- Replaying the same checkpoint must not duplicate RecordsWrite data or corrupt StateIndex state.
- Push and pull operations must tolerate messages already present on either side.
- Cancellation returns after storing a checkpoint for work that can safely resume.

## Direction Semantics

`pull`:

- Compare local and remote roots.
- Request remote subtree/leaves/diff data.
- Fetch missing messages and large data as budgets allow.
- Persist messages/data before updating local StateIndex.

`push`:

- Compare local and remote roots.
- Enumerate local-only messages.
- Upload messages and required data as budgets allow.
- Treat already-present remote records as success.

`bidirectional`:

- Pull first to reduce conflict risk.
- Push after local state is updated.
- Stop at deadline boundaries and checkpoint the remaining direction.

## Android Constraints

Recommended native caller:

- Use WorkManager for periodic, retryable, and network-constrained sync.
- Use a foreground service only for user-visible long-running data transfer.
- Pass WorkManager network constraints into `connectivity` instead of letting Rust inspect Android APIs.
- Expect Doze, App Standby, and OEM restrictions to delay work.
- Keep each Rust call bounded by the worker's remaining time budget.

Silent notification wake should enqueue WorkManager work or call `sync_once` only with a short deadline and byte budget.

## iOS Constraints

Recommended native caller:

- Use `BGAppRefreshTask` for short metadata sync.
- Use `BGProcessingTask` for longer work only when the app has the entitlement and the task is scheduled by iOS.
- Use the task expiration handler to cancel the Rust operation handle.
- Pass Low Data Mode, Low Power Mode, and reachability into `connectivity`.
- Use background URLSession only as a higher-level transport integration if iOS must own long transfers.

iOS may provide very short execution windows. Rust APIs must return `partial` quickly when the deadline is near and rely on checkpoints for future continuation.

## FFI Shape

The binding layer should mirror the strategy in [`BINDINGS.md`](BINDINGS.md):

- UniFFI exposes typed request/result records and enums for Swift/Kotlin.
- Long operations return an `OperationHandle` that supports `cancel()`.
- Data transfers use stream handles or file paths, not embedded large JSON.
- Errors map to typed `SyncError`, `StoreError`, `NetworkError`, `Cancelled`, and `DeadlineExceeded` categories.

## Non-Goals

- No background API may require a JavaScript runtime.
- No API should assume React Native is alive.
- No API should require a foreground UI.
- No mobile binding should expose SQLite table details.
- No background task should run unbounded sync work without deadline and byte budgets.
