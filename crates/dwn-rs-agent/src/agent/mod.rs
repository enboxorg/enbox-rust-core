mod derivation;
mod did_jwk;
mod errors;
mod memory;
mod providers;
mod service;

pub use self::derivation::*;
pub(crate) use self::did_jwk::*;
pub use self::errors::*;
pub use self::memory::*;
pub use self::providers::*;
pub use self::service::*;

#[cfg(test)]
pub(crate) const RECOVERY_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
