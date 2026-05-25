pub mod authorization;
pub mod jws;
pub mod universal_resolver;

pub use authorization::Authorization;
pub use jws::{
    JwkSigner, Jws, JwsError, JwsPrivateJwk, JwsPublicJwk, JwsPublicKeyResolver, JwsSignature,
    PrivateJwkSigner, StaticPublicKeyResolver,
};
pub use universal_resolver::UniversalResolver;

#[allow(deprecated)]
pub use jws::{
    GeneralJws, GeneralJwsPrivateJwk, GeneralJwsPublicJwk, GeneralJwsPublicKeyResolver,
    GeneralJwsSignature, GeneralJwsSigner, SignatureEntry, JWS,
};
