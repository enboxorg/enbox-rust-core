pub mod authorization;
pub mod jws;

pub use authorization::Authorization;
pub use jws::{
    JwkSigner, Jws, JwsError, JwsPrivateJwk, JwsPublicJwk, JwsPublicKeyResolver, JwsSignature,
    PrivateJwkSigner, StaticPublicKeyResolver,
};

#[allow(deprecated)]
pub use jws::{
    GeneralJws, GeneralJwsPrivateJwk, GeneralJwsPublicJwk, GeneralJwsPublicKeyResolver,
    GeneralJwsSignature, GeneralJwsSigner, SignatureEntry, JWS,
};
