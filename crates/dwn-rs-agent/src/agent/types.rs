use super::*;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<bool>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, JsonValue>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortableDid {
    pub uri: String,
    pub document: Document,
    pub metadata: DidMetadata,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub private_keys: Vec<JWK>,
}

impl Debug for PortableDid {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PortableDid")
            .field("uri", &self.uri)
            .field("document", &self.document)
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityMetadata {
    pub name: String,
    pub tenant: String,
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected_did: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortableIdentity {
    pub portable_did: PortableDid,
    pub metadata: IdentityMetadata,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentDerivedKeys {
    pub identity_private_jwk: JWK,
    pub signing_private_jwk: JWK,
    pub encryption_private_jwk: JWK,
    pub vault_content_encryption_key: Vec<u8>,
    pub vault_unlock_salt: Vec<u8>,
}

impl Debug for AgentDerivedKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentDerivedKeys")
            .finish_non_exhaustive()
    }
}

impl AgentDerivedKeys {
    pub fn private_jwks(&self) -> Vec<JWK> {
        vec![
            self.identity_private_jwk.clone(),
            self.signing_private_jwk.clone(),
            self.encryption_private_jwk.clone(),
        ]
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentDidCreateRequest {
    pub identity_private_jwk: JWK,
    pub signing_private_jwk: JWK,
    pub encryption_private_jwk: JWK,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dwn_endpoints: Vec<String>,
}

impl Debug for AgentDidCreateRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentDidCreateRequest")
            .field("dwn_endpoints", &self.dwn_endpoints)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentIdentityInitializeRequest {
    pub recovery_phrase: Option<String>,
    #[serde(default)]
    pub dwn_endpoints: Vec<String>,
}

impl Debug for AgentIdentityInitializeRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentIdentityInitializeRequest")
            .field("has_recovery_phrase", &self.recovery_phrase.is_some())
            .field("dwn_endpoints", &self.dwn_endpoints)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentIdentityInitialization {
    pub recovery_phrase: String,
    pub portable_did: PortableDid,
    pub key_uris: Vec<String>,
    pub vault_content_encryption_key: Vec<u8>,
    pub vault_unlock_salt: Vec<u8>,
}

impl Debug for AgentIdentityInitialization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentIdentityInitialization")
            .field("portable_did", &self.portable_did)
            .field("key_uris", &self.key_uris)
            .finish_non_exhaustive()
    }
}
