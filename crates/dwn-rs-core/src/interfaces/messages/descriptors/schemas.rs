//! JSON-schema identifiers (URLs) for each handler-backed message descriptor.
//!
//! Single source of truth for the per-method schema URLs: referenced both by the
//! `#[descriptor(schema = …)]` attribute (which surfaces them as `ConcreteDescriptor::SCHEMA_ID`)
//! and by the `SCHEMA_SOURCES` registry in `dwn::validation`, so the URL literal is written once.
//!
//! `MessagesQuery` is intentionally absent — it is a `no_handler`, spec-parity-only descriptor with
//! no published `messages-query.json` schema, so its `SCHEMA_ID` is `None`.

pub const MESSAGES_READ_SCHEMA: &str =
    "https://identity.foundation/dwn/json-schemas/messages-read.json";
pub const MESSAGES_SUBSCRIBE_SCHEMA: &str =
    "https://identity.foundation/dwn/json-schemas/messages-subscribe.json";
pub const MESSAGES_SYNC_SCHEMA: &str =
    "https://identity.foundation/dwn/json-schemas/messages-sync.json";

pub const PROTOCOLS_CONFIGURE_SCHEMA: &str =
    "https://identity.foundation/dwn/json-schemas/protocols-configure.json";
pub const PROTOCOLS_QUERY_SCHEMA: &str =
    "https://identity.foundation/dwn/json-schemas/protocols-query.json";

pub const RECORDS_COUNT_SCHEMA: &str =
    "https://identity.foundation/dwn/json-schemas/records-count.json";
pub const RECORDS_DELETE_SCHEMA: &str =
    "https://identity.foundation/dwn/json-schemas/records-delete.json";
pub const RECORDS_QUERY_SCHEMA: &str =
    "https://identity.foundation/dwn/json-schemas/records-query.json";
pub const RECORDS_READ_SCHEMA: &str =
    "https://identity.foundation/dwn/json-schemas/records-read.json";
pub const RECORDS_SUBSCRIBE_SCHEMA: &str =
    "https://identity.foundation/dwn/json-schemas/records-subscribe.json";
pub const RECORDS_WRITE_SCHEMA: &str =
    "https://identity.foundation/dwn/json-schemas/records-write.json";
