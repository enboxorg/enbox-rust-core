use std::{collections::BTreeMap, future::Future};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    descriptors::{Protocols, Records},
    errors::EventLogError,
    permissions::PERMISSIONS_PROTOCOL_URI,
    stores::{
        EventLogReadOptions, EventLogReadResult, KeyValues, ProgressGapCode, ProgressGapInfo,
        ProgressGapReason,
    },
    Descriptor, Message, ProgressToken, Value,
};

const GLOBAL_DOMAIN: &str = "";

/// Fingerprint is a 32-byte array representing the SHA256 digest of a message CID,
/// used for calculating the replication fingerprint for a tenant.
pub type Fingerprint = [u8; 32];

/// FeedPosition is a u64 representing the position of a message in the replication
/// feed for a tenant.
pub type FeedPosition = u64;

// FeedCursorState represents the state of a replication feed cursor, including the expected
// stream ID, the head position, the oldest replayable position, the message CID at the
// current position, and the replication bounds.
pub struct FeedCursorState<'a> {
    pub expected_stream_id: &'a str,
    pub head: FeedPosition,
    pub oldest_replayable: FeedPosition,
    pub message_cid_at_position: Option<&'a str>,
    pub bounds: Option<&'a ReplicationBounds>,
}

/// Replication bounds represents the range of available replication feed entries for
/// a given tenant. Lower bound is the oldest ProgressToken available, and upper bound
/// is the latest ProgressToken available.
pub type ReplicationBounds = (ProgressToken, ProgressToken);

/// ReplicationFeedReader is a trait that defines the interface for reading from a replication feed.
pub trait ReplicationFeedReader: Default {
    /// Returns an available feed that matches the given filters
    /// after theprovided cursor.
    fn log_read(
        &self,
        tenant: &str,
        options: EventLogReadOptions,
    ) -> impl Future<Output = Result<Vec<EventLogReadResult>, EventLogError>> + Send;

    /// Return the oldest, and latest ProgressTokens for a tenant
    fn log_bounds(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<ReplicationBounds, EventLogError>> + Send;

    /// Fingerprint returns the replication fingerprint for a given tenant.
    fn fingerprint(
        &self,
        tenant: &str,
        scopes: &[String],
    ) -> impl Future<Output = Result<String, EventLogError>> + Send;

    /// Return the current stream epoch
    fn epoch(&self) -> impl Future<Output = Result<u64, EventLogError>> + Send;
}

#[derive(Debug, Clone, Error)]
pub enum WakeError {
    #[error("Failed to publish wake: {0}")]
    PublishError(String),
}

pub struct Wake {
    pub tenant: String,
    pub position: u64,
}

pub trait WakePublisher {
    fn publish(&self, wake: Wake) -> impl Future<Output = Result<(), WakeError>> + Send;
}

pub trait WakeSubscriber {}

/// Derive a stream ID from a tenant DID. The stream ID is the first 8 bytes of
/// the SHA256 hash of the tenant DID, represented as a hex string.
pub fn derive_stream_id(tenant: &str) -> String {
    sha2::Sha256::digest(tenant)
        .iter()
        .take(8)
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

/// Returns true if the given message is a feed message, which is defined as a message
/// that has a descriptor of type Records::Write, Records::Delete, or Protocols::Configure.
pub fn is_feed_message(msg: Message<Descriptor>) -> bool {
    match &msg.descriptor {
        Descriptor::Records(records) => {
            matches!(records.as_ref(), Records::Write(_) | Records::Delete(_))
        }
        Descriptor::Protocols(protocols) => {
            matches!(protocols.as_ref(), Protocols::Configure(_))
        }
        _ => false,
    }
}

/// Returns the string value of a key in the given indexes, if it exists and is a string.
fn string_index<'a>(indexes: &'a KeyValues, key: &str) -> Option<&'a str> {
    match indexes.get(key) {
        Some(Value::String(value)) => Some(value),
        _ => None,
    }
}

/// Returns the fingerprint scopes for a given message descriptor and indexes. The scopes are
/// derived from the protocol and tag.protocol indexes, if they exist. If the protocol is
/// PERMISSIONS_PROTOCOL_URI, the permission scopes are also derived from the tag.protocol index,
/// if it exists. The GLOBAL_DOMAIN scope is always included.
pub fn fingerprint_scopes(descriptor_tag_proto: Option<&str>, indexes: &KeyValues) -> Vec<String> {
    let mut scopes = vec![GLOBAL_DOMAIN.to_owned()];

    let Some(protocol) = string_index(indexes, "protocol") else {
        return scopes;
    };

    scopes.push(format!("protocol:{}", protocol));

    let tagged_protocol = string_index(indexes, "tag.protocol").or(descriptor_tag_proto);

    if protocol == PERMISSIONS_PROTOCOL_URI {
        if let Some(tagged_protocol) = tagged_protocol {
            scopes.push(format!("perm:{}", tagged_protocol));
        }
    }

    scopes
}

/// Compres two sets of scopes and returns true if they are equal, ignoring order. This is used to determine
/// if the fingerprint scopes have changed between two messages.
pub fn scopes_unchanged(given: &[String], current: &[String]) -> bool {
    let mut given = given.to_vec();
    let mut current = current.to_vec();
    given.sort_unstable();
    current.sort_unstable();

    given == current
}

/// Return the SHA256 digest of the message CID, for it's contribution into the fingerprint
/// calculation.
pub fn cid_contribution(message_cid: &str) -> Fingerprint {
    Sha256::digest(message_cid.as_bytes()).into()
}

/// XOR the contribution Fingerprint into the current target fingerprint.
pub fn xor_in_place(target: &mut Fingerprint, contribution: Fingerprint) {
    for (t, c) in target.iter_mut().zip(contribution.iter()) {
        *t ^= *c;
    }
}

/// Fold the message CID into the fingerprint for each of the given scopes. This is used to update
/// the fingerprint for a tenant when a new message is added to the replication feed.
pub fn fold_cid_into_domain(
    fingerprints: &mut BTreeMap<(String, String), Fingerprint>,
    tenant: &str,
    message_cid: &str,
    scopes: &[String],
) {
    let contribution = cid_contribution(message_cid);

    for scope in scopes {
        let fingerprint = fingerprints
            .entry((tenant.to_string(), scope.clone()))
            .or_insert_with(|| [0u8; 32]);

        xor_in_place(fingerprint, contribution);
    }
}

/// Build a ProgressToken given tenant, epoch, position and message_cid
pub fn build_token(
    tenant: &str,
    epoch: &str,
    seq: u64,
    message_cid: Option<impl Into<String>>,
) -> ProgressToken {
    ProgressToken {
        stream_id: derive_stream_id(tenant),
        epoch: epoch.to_string(),
        position: seq.to_string(),
        message_cid: message_cid.map(|cid| cid.into()),
    }
}

/// Validate the given Progress token against expectations
pub fn validate_feed_cursor(
    cursor: &ProgressToken,
    state: FeedCursorState,
) -> Result<FeedPosition, EventLogError> {
    if cursor.stream_id != state.expected_stream_id {
        return Err(progress_gap(
            cursor,
            state.bounds,
            ProgressGapReason::StreamMismatch,
        ));
    }

    if cursor.epoch != state.head.to_string() {
        return Err(progress_gap(
            cursor,
            state.bounds,
            ProgressGapReason::EpochMismatch,
        ));
    }

    let position = cursor
        .position
        .parse::<u64>()
        .map_err(EventLogError::InvalidProgressToken)?;

    if position > state.head {
        return Err(progress_gap(
            cursor,
            state.bounds,
            ProgressGapReason::TokenTooNew,
        ));
    }

    if position < state.oldest_replayable {
        return Err(progress_gap(
            cursor,
            state.bounds,
            ProgressGapReason::TokenTooOld,
        ));
    }

    if let (Some(expected), Some(actual)) =
        (cursor.message_cid.as_ref(), state.message_cid_at_position)
    {
        if expected != actual {
            return Err(progress_gap(
                cursor,
                state.bounds,
                ProgressGapReason::MessageMismatch,
            ));
        }
    }

    Ok(position)
}

fn progress_gap(
    requested: &ProgressToken,
    bounds: Option<&ReplicationBounds>,
    reason: ProgressGapReason,
) -> EventLogError {
    let (oldest_available, latest_available) = bounds
        .cloned()
        .unwrap_or_else(|| (requested.clone(), requested.clone()));

    EventLogError::ProgressGap(Box::new(ProgressGapInfo {
        requested: requested.clone(),
        oldest_available,
        latest_available,
        reason,
        code: ProgressGapCode::ProgressGap,
    }))
}
