# Mobile Integration Skeleton

`dwn-rs-core` builds as both `rlib` and `cdylib`, so Android and iOS bindings can link the Rust core without Bun, Node, or a JavaScript runtime. The mobile-facing Rust API lives in `dwn_rs_core::mobile`.

## Build Targets

Android targets can be added with `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android` and built with `cargo +1.89.0 build-android-arm64`.

iOS targets can be added with `rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios` and built with `cargo +1.89.0 build-ios-arm64`.

Bindings should wrap `MobileCore` or an FFI handle that owns the same components:

- `MobileBiometricVault` for platform lock/unlock and secure enclave/biometric prompts.
- `MobileSecureStorage` for Keychain, Keystore, or app-group secure storage access.
- `MobileMessageProcessor` for DWN `process_message` calls.
- `MobileSyncBridge` for foreground and background sync.

## Runtime Entry Points

The skeleton exposes these lifecycle-safe entry points:

- `initialize(MobileInitializeRequest)` records device/app-group/database configuration.
- `unlock(reason)` and `lock()` delegate to the platform vault callback.
- `process_message(MobileProcessMessageRequest)` is gated on initialized and unlocked state.
- `sync_once(MobileSyncRequest)` is for foreground sync.
- `background_sync(MobileBackgroundSyncRequest)` is callable from Android WorkManager or iOS background task hooks and returns `NoConnectivity` without panicking when networking is unavailable.

Native apps should provide production implementations for the callback traits. The in-memory implementations are smoke-test fixtures only.
