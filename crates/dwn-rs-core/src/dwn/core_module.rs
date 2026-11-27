//! Core module registry for immutable system modules (e.g. permissions).
//!
//! Mirrors TypeScript `CoreModuleRegistry` from `@enbox/dwn-sdk-js`.

use std::collections::BTreeMap;

use crate::encryption::module::{
    encryption_module_definition, pre_process_encryption_write, validate_encryption_record_schema,
    GrantKeyError,
};
use crate::encryption::ENCRYPTION_MODULE_URI;
use crate::interfaces::messages::modules::Definition;
use crate::permissions::{
    permissions_module_definition, post_process_permissions_write, pre_process_permissions_write,
    validate_permissions_record_schema, PERMISSIONS_MODULE_URI,
};
use crate::{Descriptor, Message};

/// Bundled store references passed to core module post-processing hooks.
pub struct CoreModuleStores<'a, MessageStore, DataStore> {
    pub message_store: &'a MessageStore,
    pub data_store: &'a DataStore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegisteredCoreModule {
    Permissions,
    Encryption,
}

/// Failure from a core module hook. The permissions module reports
/// unstructured details; the encryption module reports typed failures so
/// reply status is classified by variant, never by string prefix.
#[derive(Debug)]
pub enum CoreModuleError {
    Detail(String),
    GrantKey(GrantKeyError),
}

impl std::fmt::Display for CoreModuleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Detail(detail) => formatter.write_str(detail),
            Self::GrantKey(error) => std::fmt::Display::fmt(error, formatter),
        }
    }
}

impl From<GrantKeyError> for CoreModuleError {
    fn from(error: GrantKeyError) -> Self {
        Self::GrantKey(error)
    }
}

/// Registry of core modules owned by a DWN instance.
#[derive(Debug, Clone, Default)]
pub struct CoreModuleRegistry {
    modules: BTreeMap<String, RegisteredCoreModule>,
}

impl CoreModuleRegistry {
    /// Register the permissions core module.
    pub fn register_permissions(&mut self) {
        self.modules.insert(
            PERMISSIONS_MODULE_URI.to_string(),
            RegisteredCoreModule::Permissions,
        );
    }

    /// Create a registry with all core modules pre-registered.
    pub fn with_core_modules() -> Self {
        let mut registry = Self::default();
        registry.register_permissions();
        registry.register_encryption();
        registry
    }

    /// Register the encryption core module.
    pub fn register_encryption(&mut self) {
        self.modules.insert(
            ENCRYPTION_MODULE_URI.to_string(),
            RegisteredCoreModule::Encryption,
        );
    }

    pub fn has(&self, uri: &str) -> bool {
        self.modules.contains_key(uri)
    }

    pub fn get_definition(&self, uri: &str) -> Option<Definition> {
        match self.modules.get(uri)? {
            RegisteredCoreModule::Permissions => Some(permissions_module_definition()),
            RegisteredCoreModule::Encryption => Some(encryption_module_definition()),
        }
    }

    pub fn map_error_to_status_code(&self, error_code: &str) -> Option<i32> {
        if !self.has(PERMISSIONS_MODULE_URI) {
            return None;
        }
        if error_code.starts_with("PermissionsModule") {
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
    ) -> Result<(), CoreModuleError> {
        if self.has(PERMISSIONS_MODULE_URI) {
            validate_permissions_record_schema(message)
                .map_err(|error| CoreModuleError::Detail(error.to_string()))?;
        }
        if self.has(ENCRYPTION_MODULE_URI) {
            validate_encryption_record_schema(message)?;
        }
        Ok(())
    }

    pub async fn pre_process_write<MessageStore>(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
        message_store: &MessageStore,
    ) -> Result<(), CoreModuleError>
    where
        MessageStore: crate::stores::MessageStore + Sync,
    {
        if self.has(PERMISSIONS_MODULE_URI) {
            pre_process_permissions_write(tenant, message, message_store)
                .await
                .map_err(|error| CoreModuleError::Detail(error.to_string()))?;
        }
        if self.has(ENCRYPTION_MODULE_URI) {
            pre_process_encryption_write(tenant, message, message_store).await?;
        }
        Ok(())
    }

    pub async fn post_process_write<MessageStore, DataStore>(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
        stores: CoreModuleStores<'_, MessageStore, DataStore>,
    ) -> Result<(), String>
    where
        MessageStore: crate::stores::MessageStore + Sync,
        DataStore: crate::stores::DataStore + Sync,
    {
        if self.has(PERMISSIONS_MODULE_URI) {
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
