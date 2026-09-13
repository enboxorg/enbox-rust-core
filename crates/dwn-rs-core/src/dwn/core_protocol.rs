//! Core protocol registry for immutable system protocols (e.g. permissions).
//!
//! Mirrors TypeScript `CoreProtocolRegistry` from `@enbox/dwn-sdk-js`.

use std::collections::BTreeMap;

use crate::encryption::protocol::{
    encryption_protocol_definition, pre_process_encryption_write,
    validate_encryption_record_schema, GrantKeyError,
};
use crate::encryption::ENCRYPTION_PROTOCOL_URI;
use crate::interfaces::messages::protocols::Definition;
use crate::permissions::{
    permissions_protocol_definition, post_process_permissions_write, pre_process_permissions_write,
    validate_permissions_record_schema, PERMISSIONS_PROTOCOL_URI,
};
use crate::{Descriptor, Message};

/// Bundled store references passed to core protocol post-processing hooks.
pub struct CoreProtocolStores<'a, MessageStore, DataStore> {
    pub message_store: &'a MessageStore,
    pub data_store: &'a DataStore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegisteredCoreProtocol {
    Permissions,
    Encryption,
}

/// Failure from a core protocol hook. The permissions protocol reports
/// unstructured details; the encryption protocol reports typed failures so
/// reply status is classified by variant, never by string prefix.
#[derive(Debug)]
pub enum CoreProtocolError {
    Detail(String),
    GrantKey(GrantKeyError),
}

impl std::fmt::Display for CoreProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Detail(detail) => formatter.write_str(detail),
            Self::GrantKey(error) => std::fmt::Display::fmt(error, formatter),
        }
    }
}

impl From<GrantKeyError> for CoreProtocolError {
    fn from(error: GrantKeyError) -> Self {
        Self::GrantKey(error)
    }
}

/// Registry of core protocols owned by a DWN instance.
#[derive(Debug, Clone, Default)]
pub struct CoreProtocolRegistry {
    protocols: BTreeMap<String, RegisteredCoreProtocol>,
}

impl CoreProtocolRegistry {
    /// Register the permissions core protocol.
    pub fn register_permissions(&mut self) {
        self.protocols.insert(
            PERMISSIONS_PROTOCOL_URI.to_string(),
            RegisteredCoreProtocol::Permissions,
        );
    }

    /// Create a registry with all core protocols pre-registered.
    pub fn with_core_protocols() -> Self {
        let mut registry = Self::default();
        registry.register_permissions();
        registry.register_encryption();
        registry
    }

    /// Register the encryption core protocol.
    pub fn register_encryption(&mut self) {
        self.protocols.insert(
            ENCRYPTION_PROTOCOL_URI.to_string(),
            RegisteredCoreProtocol::Encryption,
        );
    }

    pub fn has(&self, uri: &str) -> bool {
        self.protocols.contains_key(uri)
    }

    pub fn get_definition(&self, uri: &str) -> Option<Definition> {
        match self.protocols.get(uri)? {
            RegisteredCoreProtocol::Permissions => Some(permissions_protocol_definition()),
            RegisteredCoreProtocol::Encryption => Some(encryption_protocol_definition()),
        }
    }

    pub fn map_error_to_status_code(&self, error_code: &str) -> Option<i32> {
        if !self.has(PERMISSIONS_PROTOCOL_URI) {
            return None;
        }
        if error_code.starts_with("PermissionsProtocol") {
            return Some(if error_code.contains("Unauthorized") {
                401
            } else {
                400
            });
        }
        None
    }

    pub fn validate_record(
        &self,
        message: &Message<Descriptor>,
        _data: Option<&[u8]>,
    ) -> Result<(), CoreProtocolError> {
        if self.has(PERMISSIONS_PROTOCOL_URI) {
            validate_permissions_record_schema(message)
                .map_err(|error| CoreProtocolError::Detail(error.to_string()))?;
        }
        if self.has(ENCRYPTION_PROTOCOL_URI) {
            validate_encryption_record_schema(message)?;
        }
        Ok(())
    }

    pub async fn pre_process_write<MessageStore>(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
        message_store: &MessageStore,
    ) -> Result<(), CoreProtocolError>
    where
        MessageStore: crate::stores::MessageStore + Sync,
    {
        if self.has(PERMISSIONS_PROTOCOL_URI) {
            pre_process_permissions_write(tenant, message, message_store)
                .await
                .map_err(|error| CoreProtocolError::Detail(error.to_string()))?;
        }
        if self.has(ENCRYPTION_PROTOCOL_URI) {
            pre_process_encryption_write(tenant, message, message_store).await?;
        }
        Ok(())
    }

    pub async fn post_process_write<MessageStore, DataStore>(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
        stores: CoreProtocolStores<'_, MessageStore, DataStore>,
    ) -> Result<(), String>
    where
        MessageStore: crate::stores::MessageStore + Sync,
        DataStore: crate::stores::DataStore + Sync,
    {
        if self.has(PERMISSIONS_PROTOCOL_URI) {
            post_process_permissions_write(
                tenant,
                message,
                stores.message_store,
                stores.data_store,
            )
            .await
            .map_err(|error| error.to_string())?;
        }
        Ok(())
    }
}
