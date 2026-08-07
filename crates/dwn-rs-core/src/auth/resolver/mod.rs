pub mod error;

pub use error::Error;
pub use ssi_dids_core::document::{Metadata as DocumentMetadata, Resource};
pub use ssi_dids_core::resolution::{
    DIDResolver, Metadata as ResolutionMetadata, Output as ResolutionOutput,
};
use ssi_dids_core::Document;

use error::ResolverError;

pub struct Resolution {
    pub document: Document,
    pub document_metadata: DocumentMetadata,
}

pub trait Resolver: Send + Sync {
    fn resolve(&self, did: &str) -> Result<Resolution, ResolverError>;
}
