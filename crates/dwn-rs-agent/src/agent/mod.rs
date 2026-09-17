use std::collections::BTreeMap;
use std::fmt::{Debug, Display};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bip39::{Language, Mnemonic};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256, Sha512};
use ssi_dids_core::document::verification_method::ValueOrReference;
use ssi_dids_core::document::{DIDVerificationMethod, Service, VerificationRelationships};
use ssi_dids_core::{DIDBuf, Document};
use ssi_jwk::{Algorithm, Base64urlUInt, OctetParams, Params, JWK};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

mod derivation;
mod did_jwk;
mod errors;
mod memory;
mod providers;
mod service;
mod traits;
mod types;

pub use self::derivation::*;
pub(crate) use self::did_jwk::*;
pub use self::errors::*;
pub use self::memory::*;
pub use self::providers::*;
pub use self::service::*;
pub use self::traits::*;
pub use self::types::*;

