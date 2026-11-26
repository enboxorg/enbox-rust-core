# Mobile Integration Skeleton

`dwn-rs-core` builds as both `rlib` and `cdylib`, so Android and iOS bindings can link the Rust core without Bun, Node, or a JavaScript runtime. The mobile-facing Rust API lives in `dwn_rs_core::mobile`.

## Build Targets

Android targets can be added with `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android` and built with `cargo +1.98.1 build-android-arm64`.

iOS targets can be added with `rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios` and built with `cargo +1.98.1 build-ios-arm64`.

Bindings should wrap `EnboxCore` (the `enbox-ffi` facade) or an FFI handle that owns the same components:

- `EnboxCore` and its single `IdentityVault` for the agent identity, vault password gate, and credential store.
- `MobileSecureStorage` for Keychain, Keystore, or app-group secure storage access.
- `MobileMessageProcessor` for DWN `process_message` calls.
- `MobileSyncBridge` for foreground and background sync.

## Password-gated vault, not a host lock flag

Access is gated by the vault password, not by a host-maintained lock flag or an `unlock(reason)` callback. `EnboxCore` owns the one lock truth: the vault's in-memory CEK. A freshly opened core starts locked and writes nothing; every gated surface reads the vault's own state.

The host never unlocks the vault without the password. The platform layer stores the vault password in the Keychain (iOS, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` with an access-control policy) or Keystore (Android, `setUserAuthenticationRequired`), performs the Face ID / Touch ID / `BiometricPrompt` challenge, and then hands the recovered password to the Rust core:

```text
open(databasePath)
  → initialize_vault({ password, recoveryPhrase?, dwnEndpoints? })   # first run only
  → unlock(password) / unlock_with_reason(password, "user_resume")   # later launches
  → lock()                                                           # background, logout, timeout
  → vault_status()                                                   # {initialized, locked, lastBackup, lastRestore}
```

`unlock_with_reason` records the host's audit label only after a successful password unlock; the reason is cleared on `lock` and on any locking failure. `change_password`, `reset_password_with_recovery_phrase`, `backup_vault`, and `restore_vault` cover the rest of the lifecycle. Any failed reset or restore ends locked with the stored vault unchanged.

Because the same vault backs registration tokens and delegate keys, a mobile host that wants background sync must keep the password available to the app while the vault is unlocked for that work (for example, retrieve it once after biometric success and avoid persisting it outside platform secure storage). There is no shadow unlock flag to fall back on.

> **Superseded model.** The earlier `#22` design had the host own a lock flag and pass a biometric reason into an `unlock(reason)` callback (the `MobileBiometricVault` seam). It could not keep lock state authoritative once the vault persisted a password-wrapped CEK. The `MobileCore` runtime-status bookkeeping below survives as telemetry only; it no longer gates access and must not be treated as lock state.

## Runtime Entry Points

The runtime status skeleton exposes these lifecycle-safe entry points through `enbox-ffi`:

- `initialize_runtime(MobileInitializeRequest)` records device/app-group/database configuration.
- `unlock_with_reason(password, reason)` unlocks the vault and records the audit label.
- `lock()` clears the vault key and clears the recorded unlock reason.
- `process_message(MobileProcessMessageRequest)` is gated on an unlocked vault.
- `sync_once(MobileSyncRequest)` is for foreground sync.
- `background_sync(MobileBackgroundSyncRequest)` is callable from Android WorkManager or iOS background task hooks and returns `NoConnectivity` without panicking when networking is unavailable.

Native apps should provide production implementations for the secure-storage and biometric seams. The in-memory implementations are smoke-test fixtures only.
