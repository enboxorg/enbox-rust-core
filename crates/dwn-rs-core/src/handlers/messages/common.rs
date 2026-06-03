use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::SecondsFormat;
use futures_util::TryStreamExt;
use k256::sha2::{Digest, Sha256};
use serde_json::Value as JsonValue;

use crate::auth::JwsPublicKeyResolver;
use crate::cid::generate_cid_from_json;
use crate::descriptors::{
    Descriptor, Messages, MessagesSubscribeDescriptor, MessagesSyncDescriptor, Records,
};
use crate::dwn::{DwnReply, MethodHandler, MethodHandlerRequest};
use crate::errors::EventLogError;
use crate::filters::message_filters::Messages as MessagesFilter;
use crate::filters::{Filter, FilterKey, Filters};
use crate::interfaces::messages::descriptors::messages::{ReadDescriptor, SyncAction};
use crate::permissions::{self, AuthorizationContext};
use crate::stores::{EventLogSubscribeOptions, EventSubscription, StateHash, SubscriptionListener};
use crate::{Fields, Message};

use super::SubscribeReply;

const MAX_SYNC_DEPTH: usize = 256;
const MAX_INLINE_DATA_SIZE: u64 = 30_000;

static DEFAULT_HASHES: OnceLock<Vec<StateHash>> = OnceLock::new();

pub(crate) fn parse_message(
    raw_message: &JsonValue,
    prefix: &str,
) -> Result<Message<Descriptor>, String> {
    serde_json::from_value(raw_message.clone()).map_err(|err| format!("{prefix}: {err}"))
}

pub(crate) fn messages_subscribe_descriptor(
    message: &Message<Descriptor>,
) -> Result<&MessagesSubscribeDescriptor, String> {
    match &message.descriptor {
        Descriptor::Messages(messages) => match messages.as_ref() {
            Messages::Subscribe(descriptor) => Ok(descriptor),
            _ => Err(
                "MessagesSubscribeParseFailed: expected MessagesSubscribe descriptor".to_string(),
            ),
        },
        _ => Err("MessagesSubscribeParseFailed: expected MessagesSubscribe descriptor".to_string()),
    }
}

pub(crate) fn messages_read_descriptor(
    message: &Message<Descriptor>,
) -> Result<&ReadDescriptor, String> {
    match &message.descriptor {
        Descriptor::Messages(messages) => match messages.as_ref() {
            Messages::Read(descriptor) => Ok(descriptor),
            _ => Err("MessagesReadParseFailed: expected MessagesRead descriptor".to_string()),
        },
        _ => Err("MessagesReadParseFailed: expected MessagesRead descriptor".to_string()),
    }
}

pub(crate) fn messages_sync_descriptor(
    message: &Message<Descriptor>,
) -> Result<&MessagesSyncDescriptor, String> {
    match &message.descriptor {
        Descriptor::Messages(messages) => match messages.as_ref() {
            Messages::Sync(descriptor) => Ok(descriptor),
            _ => Err("MessagesSyncParseFailed: expected MessagesSync descriptor".to_string()),
        },
        _ => Err("MessagesSyncParseFailed: expected MessagesSync descriptor".to_string()),
    }
}

pub(crate) fn messages_filters_to_filters(filters: &[MessagesFilter]) -> Option<Filters> {
    if filters.is_empty() {
        return None;
    }
    Some(Filters::from(
        filters
            .iter()
            .map(messages_filter_to_filter_map)
            .collect::<Vec<_>>(),
    ))
}

pub(crate) fn messages_filter_to_filter_map(
    filter: &MessagesFilter,
) -> BTreeMap<FilterKey, Filter<crate::Value>> {
    let mut map = BTreeMap::new();
    insert_messages_string_filter(&mut map, "interface", filter.interface.as_ref());
    insert_messages_string_filter(&mut map, "method", filter.method.as_ref());
    insert_messages_string_filter(&mut map, "protocol", filter.protocol.as_ref());
    if let Some(message_timestamp) = filter.message_timestamp {
        map.insert(
            FilterKey::Index("messageTimestamp".to_string()),
            Filter::Equal(crate::Value::String(
                message_timestamp.to_rfc3339_opts(SecondsFormat::Micros, true),
            )),
        );
    }
    map
}

pub(crate) fn insert_messages_string_filter(
    map: &mut BTreeMap<FilterKey, Filter<crate::Value>>,
    key: &str,
    value: Option<&String>,
) {
    if let Some(value) = value {
        map.insert(
            FilterKey::Index(key.to_string()),
            Filter::Equal(crate::Value::String(value.clone())),
        );
    }
}

pub(crate) fn subscribe_reply(
    reply: DwnReply,
    subscription: Option<EventSubscription>,
) -> SubscribeReply {
    SubscribeReply {
        reply,
        subscription,
    }
}

pub(crate) fn event_log_error_reply(error: EventLogError) -> DwnReply {
    match error {
        EventLogError::ProgressGap(gap_info) => {
            let mut error = serde_json::to_value(&*gap_info)
                .unwrap_or_else(|_| JsonValue::Object(serde_json::Map::new()));
            if let Some(error) = error.as_object_mut() {
                error.insert(
                    "code".to_string(),
                    JsonValue::String("ProgressGap".to_string()),
                );
            }
            DwnReply::new(410, "Progress token gap").with_body("error", error)
        }
        error => store_error_reply(error.to_string()),
    }
}

pub(crate) fn validate_sync_descriptor(descriptor: &MessagesSyncDescriptor) -> Result<(), String> {
    match descriptor.action {
        SyncAction::Root => Ok(()),
        SyncAction::Subtree | SyncAction::Leaves => {
            let prefix = descriptor.prefix.as_deref().ok_or_else(|| {
                "MessagesSyncInvalidPrefix: prefix is required for subtree and leaves actions"
                    .to_string()
            })?;
            parse_bit_prefix(prefix).map(|_| ())
        }
        SyncAction::Diff => {
            let depth = descriptor.depth.ok_or_else(|| {
                "MessagesSyncInvalidDepth: depth is required for diff action".to_string()
            })?;
            let depth = usize::from(depth);
            if depth > MAX_SYNC_DEPTH {
                return Err(format!(
                    "MessagesSyncInvalidDepth: depth must be <= {MAX_SYNC_DEPTH}, got {depth}"
                ));
            }
            let hashes = descriptor.hashes.as_ref().ok_or_else(|| {
                "MessagesSyncInvalidHashes: hashes are required for diff action".to_string()
            })?;
            for prefix in hashes.keys() {
                parse_bit_prefix(prefix)?;
                if prefix.len() != depth {
                    return Err(format!(
                        "MessagesSyncInvalidPrefix: diff prefix length must equal depth {depth}, got {}",
                        prefix.len()
                    ));
                }
            }
            Ok(())
        }
    }
}

pub(crate) fn parse_bit_prefix(prefix: &str) -> Result<Vec<bool>, String> {
    if prefix.len() > MAX_SYNC_DEPTH {
        return Err(format!(
            "MessagesSyncInvalidPrefix: length must be <= {MAX_SYNC_DEPTH}, got {}",
            prefix.len()
        ));
    }
    let mut bits = Vec::with_capacity(prefix.len());
    for byte in prefix.bytes() {
        match byte {
            b'0' => bits.push(false),
            b'1' => bits.push(true),
            _ => {
                return Err(format!(
                    "MessagesSyncInvalidPrefix: must contain only '0' and '1' characters, got: {prefix}"
                ))
            }
        }
    }
    Ok(bits)
}

pub(crate) fn strip_encoded_data(message: &mut JsonValue) -> Option<String> {
    message
        .as_object_mut()?
        .remove("encodedData")?
        .as_str()
        .map(str::to_string)
}

pub(crate) fn records_write_data_reference(
    message: &Message<Descriptor>,
) -> Option<(String, String, u64)> {
    let descriptor = match &message.descriptor {
        Descriptor::Records(records) => match records.as_ref() {
            Records::Write(descriptor) => descriptor,
            _ => return None,
        },
        _ => return None,
    };
    let record_id = match &message.fields {
        Fields::Write(fields) => fields.record_id.clone(),
        Fields::InitialWriteField(fields) => fields.write_fields.record_id.clone(),
        _ => None,
    }?;
    Some((record_id, descriptor.data_cid.clone(), descriptor.data_size))
}

pub(crate) fn default_hash_hex(depth: usize) -> Result<String, String> {
    default_hash(depth).map(|hash| state_hash_hex(&hash))
}

pub(crate) fn default_hash(depth: usize) -> Result<StateHash, String> {
    if depth > MAX_SYNC_DEPTH {
        return Err(format!(
            "MessagesSyncInvalidDepth: depth must be <= {MAX_SYNC_DEPTH}, got {depth}"
        ));
    }
    Ok(default_hashes()[depth])
}

pub(crate) fn default_hashes() -> &'static [StateHash] {
    DEFAULT_HASHES
        .get_or_init(|| {
            let mut hashes = vec![[0u8; 32]; MAX_SYNC_DEPTH + 1];
            for depth in (0..MAX_SYNC_DEPTH).rev() {
                hashes[depth] = hash_children(&hashes[depth + 1], &hashes[depth + 1]);
            }
            hashes
        })
        .as_slice()
}

pub(crate) fn hash_children(left: &StateHash, right: &StateHash) -> StateHash {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

pub(crate) fn state_hash_hex(hash: &StateHash) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn store_error_reply(detail: String) -> DwnReply {
    DwnReply::new(500, detail)
}
