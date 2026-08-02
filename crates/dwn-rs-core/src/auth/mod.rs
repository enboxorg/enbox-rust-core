pub mod authorization;
pub mod jws;
pub mod resolver;
pub mod universal_resolver;

pub use authorization::Authorization;
pub use jws::{
    ed25519_jwk, JwkSigner, Jws, JwsError, JwsPublicKeyResolver, JwsSignature, PrivateJwkSigner,
    StaticPublicKeyResolver, JWK,
};
pub use universal_resolver::UniversalResolver;

#[allow(deprecated)]
pub use jws::{
    GeneralJws, GeneralJwsPrivateJwk, GeneralJwsPublicJwk, GeneralJwsPublicKeyResolver,
    GeneralJwsSignature, GeneralJwsSigner, JwsPrivateJwk, JwsPublicJwk, SignatureEntry, JWS,
};
