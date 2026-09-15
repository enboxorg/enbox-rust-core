//! Enbox user-agent runtime: identity, vault, registration, and legacy connect helpers.
//!
//! "Agent" here means the Enbox user-agent runtime that owns a DID, a key
//! manager, and a secret store on behalf of one user. It does not mean a
//! delegated software/AI principal acting under a grant; that principal is
//! described by the protocol and permission types in `dwn-rs-core`.
//!
//! Owned surfaces:
//!
//! - [`agent`] owns agent identity and the vault key lifecycle (BIP-39
//!   derivation, portable DIDs, key manager and secret-store traits).
//! - [`auth`] owns tenant registration/setup and the legacy
//!   connect/delegate-grant helpers.
//! - [`SqliteSecretStore`] (feature `sqlite`) owns the SQLite secret-store
//!   backend. Future agent/runtime work lands here: vault lifecycle, DWN-backed
//!   stores, read-through/protocol caches, and sessions. Permission and
//!   headless-auth helpers land under [`auth`].
//!
//! Consumed seams:
//!
//! - DWN message, protocol, permission, and encryption types come from
//!   `dwn-rs-core`. The agent never redefines them.
//! - The SQLite backend shares one database file with `dwn-rs-stores`; the
//!   `agent_secrets` table schema stays owned by the `dwn-rs-stores`
//!   migration.
//! - Host applications inject storage and network capability through the
//!   traits in [`agent`] (`SecretStore`, `AgentKeyManager`,
//!   `PortableDidStore`, `DidProvider`) and [`auth`] (`TenantRegistrationClient`,
//!   `ProtocolEndpoint`). There is no composed runtime type.
//!
//! Host-application exclusions: keychain/Secure Enclave/TPM binding, UI for
//! registration approval, and background-task scheduling stay with the host.
//!
//! Legacy sync (`dwn_rs_core::sync`) and the mobile runtime skeleton
//! (`dwn_rs_core::runtime::mobile`) remain in `dwn-rs-core` and are not agent
//! extension points.
//!
//! Admission constraint: runtime seams for DWN-backed state, caches, sync
//! coordination, or remote access take DWN processing capability (the engine's
//! message processing entry point), not raw `MessageStore`/`DataStore` write
//! access for DWN state. Secret and key-material seams stay separate from DWN
//! store seams.
//!
//! [`SqliteSecretStore`] is an unencrypted key/value backend. Unlike the
//! TypeScript `SecretStore`, it does not encrypt at rest; the host binds the
//! database file to platform storage.
//!
//! Runtime conventions for agent work:
//!
//! - Per-operation cancellation is future drop: dropping the future returned
//!   by a backend or helper cancels that operation.
//! - Session and lifecycle cancellation uses
//!   `tokio_util::sync::CancellationToken`, introduced by the child that
//!   first implements sessions.
//! - Time-dependent behaviour takes an injectable clock. The seam arrives
//!   with the first TTL/expiry-bearing child instead of being retrofitted
//!   onto the calls that stamp timestamps today.
//! - Remote and cache outcomes keep transport failure, authoritative empty,
//!   integrity/authentication failure, and session-expired distinguishable.
//!   Remote material never counts as admitted state without normal DWN
//!   admission.
//! - Backend traits are dyn-compatible: hosts inject `Arc<dyn Trait>`
//!   backends at runtime; concrete backends stay `Clone`.
//! - Fallible operations return the typed [`agent::AgentIdentityError`];
//!   every failure carries a stable code through `code()`.
//! - Secret-bearing types never print secrets: `Debug` omits private keys,
//!   content-encryption keys, salts, derived private JWKs, delegate keys,
//!   and registration/refresh tokens, while serde shapes stay complete.
//! - No process-global state: independently constructed services in one
//!   process do not observe each other.

pub mod agent;
pub mod auth;
#[cfg(feature = "sqlite")]
mod secrets_store;
#[cfg(feature = "sqlite")]
pub use self::secrets_store::SqliteSecretStore;
