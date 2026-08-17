use std::{collections::BTreeMap, future::Future};

use sha2::{Digest, Sha256};

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
    pub expected_epoch: &'a str,
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
pub trait ReplicationFeedReader {
    /// Returns an available feed that matches the given filters
    /// after theprovided cursor.
    fn log_read(
        &self,
        tenant: &str,
        options: EventLogReadOptions,
    ) -> impl Future<Output = Result<EventLogReadResult, EventLogError>> + Send;

    /// Return the oldest, and latest ProgressTokens for a tenant
    fn log_bounds(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<Option<ReplicationBounds>, EventLogError>> + Send;

    /// Fingerprint returns the replication fingerprint for a given tenant.
    fn fingerprint(
        &self,
        tenant: &str,
        scopes: &[String],
    ) -> impl Future<Output = Result<Fingerprint, EventLogError>> + Send;

    /// Return the current stream epoch
    fn epoch(&self) -> impl Future<Output = Result<String, EventLogError>> + Send;
}

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
pub fn is_feed_message(msg: &Message<Descriptor>) -> bool {
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
    given.dedup();
    current.sort_unstable();
    current.dedup();

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

/// Parse a canonical, non-negative decimal feed position.
///
/// Feed positions are strings on the wire but numeric in store implementations.
/// Leading zeroes and an explicit `+` are rejected so each position has exactly
/// one external representation. Position zero is the empty-feed anchor.
pub fn parse_feed_position(position: &str) -> Result<FeedPosition, EventLogError> {
    let parsed = position
        .parse::<FeedPosition>()
        .map_err(|_| EventLogError::InvalidProgressToken(position.to_string()))?;

    if parsed.to_string() != position {
        return Err(EventLogError::InvalidProgressToken(position.to_string()));
    }

    Ok(parsed)
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

    if cursor.epoch != state.expected_epoch {
        return Err(progress_gap(
            cursor,
            state.bounds,
            ProgressGapReason::EpochMismatch,
        ));
    }

    let position = parse_feed_position(&cursor.position)?;

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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sha2::{Digest, Sha256};

    use super::{
        build_token, cid_contribution, derive_stream_id, fingerprint_scopes, fold_cid_into_domain,
        is_feed_message, parse_feed_position, scopes_unchanged, validate_feed_cursor, xor_in_place,
        FeedCursorState,
    };
    use crate::descriptors::{Messages, Protocols, Records};
    use crate::errors::EventLogError;
    use crate::permissions::PERMISSIONS_PROTOCOL_URI;
    use crate::stores::{KeyValues, ProgressGapReason};
    use crate::{Descriptor, Fields, Message, ProgressToken, Value};

    const TENANT: &str = "did:example:alice";
    const EPOCH: &str = "epoch-1";

    fn message(descriptor: Descriptor) -> Message<Descriptor> {
        Message {
            descriptor,
            fields: Fields::default(),
        }
    }

    fn token(position: u64, message_cid: Option<&str>) -> ProgressToken {
        build_token(TENANT, EPOCH, position, message_cid)
    }

    fn assert_gap(error: EventLogError, reason: ProgressGapReason, requested: &ProgressToken) {
        let EventLogError::ProgressGap(gap) = error else {
            panic!("expected ProgressGap, got {error:?}");
        };
        assert_eq!(gap.reason, reason);
        assert_eq!(&gap.requested, requested);
        assert_eq!(gap.oldest_available, token(0, None));
        assert_eq!(gap.latest_available, token(8, Some("cid-8")));
    }

    fn cursor_state<'a>(
        expected_stream_id: &'a str,
        message_cid_at_position: Option<&'a str>,
        bounds: &'a (ProgressToken, ProgressToken),
    ) -> FeedCursorState<'a> {
        FeedCursorState {
            expected_stream_id,
            expected_epoch: EPOCH,
            head: 8,
            oldest_replayable: 2,
            message_cid_at_position,
            bounds: Some(bounds),
        }
    }

    #[test]
    fn derives_stream_id_from_first_eight_sha256_bytes() {
        assert_eq!(derive_stream_id(TENANT), "6742201863cf8f21");
        assert_eq!(derive_stream_id(TENANT).len(), 16);
    }

    #[test]
    fn identifies_only_durable_feed_message_methods() {
        let included = [
            Descriptor::Records(Box::new(Records::Write(Default::default()))),
            Descriptor::Records(Box::new(Records::Delete(Default::default()))),
            Descriptor::Protocols(Box::new(Protocols::Configure(Default::default()))),
        ];
        for descriptor in included {
            assert!(is_feed_message(&message(descriptor)));
        }

        let excluded = [
            Descriptor::Records(Box::new(Records::Read(Default::default()))),
            Descriptor::Records(Box::new(Records::Count(Default::default()))),
            Descriptor::Records(Box::new(Records::Query(Default::default()))),
            Descriptor::Records(Box::new(Records::Subscribe(Default::default()))),
            Descriptor::Protocols(Box::new(Protocols::Query(Default::default()))),
            Descriptor::Messages(Box::new(Messages::Read(Default::default()))),
            Descriptor::Messages(Box::new(Messages::Query(Default::default()))),
            Descriptor::Messages(Box::new(Messages::Subscribe(Default::default()))),
            Descriptor::Messages(Box::new(Messages::Sync(Default::default()))),
        ];
        for descriptor in excluded {
            assert!(!is_feed_message(&message(descriptor)));
        }
    }

    #[test]
    fn derives_global_protocol_and_permission_fingerprint_scopes() {
        assert_eq!(fingerprint_scopes(None, &KeyValues::new()), vec![""]);

        let mut protocol_indexes = KeyValues::new();
        protocol_indexes.insert(
            "protocol".to_string(),
            Value::String("https://example.com/chat".to_string()),
        );
        assert_eq!(
            fingerprint_scopes(None, &protocol_indexes),
            vec!["", "protocol:https://example.com/chat"]
        );

        let mut permission_indexes = KeyValues::new();
        permission_indexes.insert(
            "protocol".to_string(),
            Value::String(PERMISSIONS_PROTOCOL_URI.to_string()),
        );
        permission_indexes.insert(
            "tag.protocol".to_string(),
            Value::String("https://example.com/from-index".to_string()),
        );
        assert_eq!(
            fingerprint_scopes(
                Some("https://example.com/from-descriptor"),
                &permission_indexes
            ),
            vec![
                "".to_string(),
                format!("protocol:{PERMISSIONS_PROTOCOL_URI}"),
                "perm:https://example.com/from-index".to_string(),
            ]
        );

        permission_indexes.remove("tag.protocol");
        assert_eq!(
            fingerprint_scopes(
                Some("https://example.com/from-descriptor"),
                &permission_indexes
            )
            .last()
            .map(String::as_str),
            Some("perm:https://example.com/from-descriptor")
        );
    }

    #[test]
    fn compares_fingerprint_scopes_as_sets() {
        let left = vec!["".to_string(), "protocol:p".to_string()];
        let reordered_with_duplicate = vec![
            "protocol:p".to_string(),
            "".to_string(),
            "protocol:p".to_string(),
        ];
        assert!(scopes_unchanged(&left, &reordered_with_duplicate));
        assert!(!scopes_unchanged(&left, &["".to_string()]));
    }

    #[test]
    fn folds_cid_contributions_with_xor_per_tenant_and_scope() {
        let contribution = cid_contribution("cid-1");
        assert_eq!(contribution.as_slice(), Sha256::digest(b"cid-1").as_slice());

        let mut folded = [0_u8; 32];
        xor_in_place(&mut folded, contribution);
        assert_eq!(folded, contribution);
        xor_in_place(&mut folded, contribution);
        assert_eq!(folded, [0_u8; 32]);

        let scopes = vec!["".to_string(), "protocol:p".to_string()];
        let mut fingerprints = BTreeMap::new();
        fold_cid_into_domain(&mut fingerprints, TENANT, "cid-1", &scopes);
        for scope in &scopes {
            assert_eq!(
                fingerprints.get(&(TENANT.to_string(), scope.clone())),
                Some(&contribution)
            );
        }
        assert!(!fingerprints.contains_key(&("did:example:bob".to_string(), "".to_string())));

        fold_cid_into_domain(&mut fingerprints, TENANT, "cid-1", &scopes);
        for scope in &scopes {
            assert_eq!(
                fingerprints.get(&(TENANT.to_string(), scope.clone())),
                Some(&[0_u8; 32])
            );
        }
    }

    #[test]
    fn builds_tokens_with_canonical_positions_and_optional_cids() {
        assert_eq!(
            token(42, Some("cid-42")),
            ProgressToken {
                stream_id: "6742201863cf8f21".to_string(),
                epoch: EPOCH.to_string(),
                position: "42".to_string(),
                message_cid: Some("cid-42".to_string()),
            }
        );
        assert_eq!(token(0, None).message_cid, None);
    }

    #[test]
    fn validates_a_feed_cursor() {
        let bounds = (token(0, None), token(8, Some("cid-8")));
        let cursor = token(4, Some("cid-4"));
        assert_eq!(
            validate_feed_cursor(
                &cursor,
                cursor_state(&derive_stream_id(TENANT), Some("cid-4"), &bounds)
            )
            .unwrap(),
            4
        );
    }

    #[test]
    fn rejects_stream_mismatch_with_structured_bounds() {
        let bounds = (token(0, None), token(8, Some("cid-8")));
        let cursor = token(4, Some("cid-4"));
        let error =
            validate_feed_cursor(&cursor, cursor_state("wrong-stream", None, &bounds)).unwrap_err();
        assert_gap(error, ProgressGapReason::StreamMismatch, &cursor);
    }

    #[test]
    fn rejects_epoch_mismatch_with_structured_bounds() {
        let bounds = (token(0, None), token(8, Some("cid-8")));
        let mut cursor = token(4, Some("cid-4"));
        cursor.epoch = "stale-epoch".to_string();
        let error = validate_feed_cursor(
            &cursor,
            cursor_state(&derive_stream_id(TENANT), None, &bounds),
        )
        .unwrap_err();
        assert_gap(error, ProgressGapReason::EpochMismatch, &cursor);
    }

    #[test]
    fn rejects_too_new_cursor_with_structured_bounds() {
        let bounds = (token(0, None), token(8, Some("cid-8")));
        let cursor = token(9, None);
        let error = validate_feed_cursor(
            &cursor,
            cursor_state(&derive_stream_id(TENANT), None, &bounds),
        )
        .unwrap_err();
        assert_gap(error, ProgressGapReason::TokenTooNew, &cursor);
    }

    #[test]
    fn rejects_too_old_cursor_with_structured_bounds() {
        let bounds = (token(0, None), token(8, Some("cid-8")));
        let cursor = token(1, None);
        let error = validate_feed_cursor(
            &cursor,
            cursor_state(&derive_stream_id(TENANT), None, &bounds),
        )
        .unwrap_err();
        assert_gap(error, ProgressGapReason::TokenTooOld, &cursor);
    }

    #[test]
    fn rejects_message_mismatch_with_structured_bounds() {
        let bounds = (token(0, None), token(8, Some("cid-8")));
        let cursor = token(4, Some("stale-cid"));
        let error = validate_feed_cursor(
            &cursor,
            cursor_state(&derive_stream_id(TENANT), Some("current-cid"), &bounds),
        )
        .unwrap_err();
        assert_gap(error, ProgressGapReason::MessageMismatch, &cursor);
    }

    #[test]
    fn parses_canonical_feed_positions() {
        assert_eq!(parse_feed_position("0").unwrap(), 0);
        assert_eq!(parse_feed_position("1").unwrap(), 1);
        assert_eq!(
            parse_feed_position(&u64::MAX.to_string()).unwrap(),
            u64::MAX
        );
    }

    #[test]
    fn rejects_noncanonical_feed_positions() {
        for position in [
            "",
            "-1",
            "+1",
            "00",
            "01",
            " 1",
            "1 ",
            "18446744073709551616",
        ] {
            assert!(matches!(
                parse_feed_position(position),
                Err(EventLogError::InvalidProgressToken(value)) if value == position
            ));
        }
    }
}
