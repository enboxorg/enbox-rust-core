use std::{collections::BTreeMap, fmt::Display, future::Future};

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

/// The global domain scope is always included in the fingerprint scopes for a tenant.
const GLOBAL_DOMAIN: &str = "";

/// Fixed-width fingerprint of the messages visible in one or more feed scopes.
///
/// A fingerprint is the XOR aggregate of the SHA-256 CID contributions in the
/// requested scopes. The byte representation is used by stores; [`Display`] and
/// [`Fingerprint::hex`] provide the canonical 64-character lowercase hexadecimal
/// representation used at API boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Fingerprint {
    fingerprint: [u8; 32],
}

impl From<[u8; 32]> for Fingerprint {
    fn from(bytes: [u8; 32]) -> Self {
        Self { fingerprint: bytes }
    }
}

impl Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

impl Fingerprint {
    /// Borrows the fixed-width byte representation used by storage backends.
    pub fn as_slice(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// Returns the canonical 64-character lowercase hexadecimal representation.
    pub fn hex(&self) -> String {
        hex::encode(self.fingerprint)
    }
}

/// Numeric position of an entry in a tenant's replication feed.
///
/// Position zero is reserved for the empty-feed anchor. Actual entries begin at
/// one and increase monotonically; positions are not reused after deletion.
pub type FeedPosition = u64;

/// Feed snapshot and expectations used to validate a [`ProgressToken`].
///
/// Backends should construct this state from one consistent read snapshot so a
/// concurrent writer cannot change the head or entry identity during validation.
pub struct FeedCursorState<'a> {
    /// Stream identifier derived for the tenant being read.
    pub expected_stream_id: &'a str,
    /// Epoch of the feed snapshot being read.
    pub expected_epoch: &'a str,
    /// Highest position allocated in the snapshot, including deleted entries.
    pub head: FeedPosition,
    /// Earliest position from which an exclusive resume is still supported.
    pub oldest_replayable: FeedPosition,
    /// CID currently stored at the cursor position, if that entry still exists.
    pub message_cid_at_position: Option<&'a str>,
    /// Bounds to include in a structured progress-gap error.
    pub bounds: Option<&'a ReplicationBounds>,
}

/// Oldest and latest resumable tokens for a tenant, in that order.
///
/// Either token can identify a scan position without a `message_cid` when no
/// entry exists at that position, for example after deletion.
pub type ReplicationBounds = (ProgressToken, ProgressToken);

/// Reads the durable, ordered message feed used by replication handlers.
///
/// This is the storage contract behind `MessagesQuery` and `MessagesSubscribe`.
/// The [DWN specification] defines the normative protocol messages, filters, and
/// replies; this trait defines the persistence and resume semantics that backend
/// implementations must share.
///
/// Each tenant has an independent, monotonically increasing sequence of numeric
/// positions. Stores operate on positions as [`FeedPosition`] values, while
/// [`ProgressToken::position`] and [`EventLogEntry::seq`](crate::stores::EventLogEntry::seq)
/// expose their canonical, unpadded decimal representation. Position zero is the
/// anchor for an empty feed and is never assigned to an entry.
///
/// A cursor is exclusive: a read resumes with the first eligible entry after its
/// position. The cursor returned by [`log_read`](Self::log_read) is also the scan
/// high-water mark, not necessarily the position of the last returned event. A
/// scan can advance across deleted or filtered-out positions; in that case its
/// token may omit `message_cid`.
///
/// A feed epoch identifies the position namespace. Ordinary inserts, updates,
/// and deletes retain the epoch; clearing the store replaces it and invalidates
/// cursors from the previous epoch.
///
/// [DWN specification]: https://dwn-spec.pages.dev/
pub trait ReplicationFeedReader {
    /// Reads an ordered page of events for `tenant`.
    ///
    /// `options.cursor` is validated and treated as an exclusive starting
    /// position. Filters affect which events are returned, but the result cursor
    /// records how far the feed was scanned. `drained` is true when that scan has
    /// reached the captured tenant head.
    ///
    /// A limit of zero still validates the cursor and filters, but performs no
    /// scan and does not advance the cursor. Without an input cursor, the result
    /// uses the position-zero anchor.
    fn log_read(
        &self,
        tenant: &str,
        options: EventLogReadOptions,
    ) -> impl Future<Output = Result<EventLogReadResult, EventLogError>> + Send;

    /// Returns the oldest and latest resumable tokens for `tenant`.
    ///
    /// Backends use these bounds when reporting why a supplied cursor cannot be
    /// resumed. An empty feed has no entry bounds.
    fn log_bounds(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<Option<ReplicationBounds>, EventLogError>> + Send;

    /// Returns the aggregate fingerprint for `tenant` over the requested scopes.
    ///
    /// Scope order and duplicates do not affect the result. [`Fingerprint`]
    /// retains its fixed-width bytes inside the store and formats as the
    /// canonical 64-character lowercase hexadecimal value at the API boundary.
    fn fingerprint(
        &self,
        tenant: &str,
        scopes: &[String],
    ) -> impl Future<Output = Result<Fingerprint, EventLogError>> + Send;

    /// Returns the current non-empty stream epoch shared by all tenants.
    ///
    /// Implementations must return the current persisted value rather than a
    /// cached startup value so that a completed `clear` is immediately visible.
    fn epoch(&self) -> impl Future<Output = Result<String, EventLogError>> + Send;
}

/// Derives the stable stream identifier for a tenant.
///
/// The identifier is the first eight bytes of the SHA-256 digest of `tenant`,
/// encoded as 16 lowercase hexadecimal characters. All backends must use this
/// helper so tokens for the same tenant identify the same stream.
pub fn derive_stream_id(tenant: &str) -> String {
    sha2::Sha256::digest(tenant)
        .iter()
        .take(8)
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

/// Returns whether a message belongs in the durable replication feed.
///
/// The feed contains `RecordsWrite`, `RecordsDelete`, and `ProtocolsConfigure`
/// messages. Other methods remain available through their own interfaces but do
/// not consume a feed position or affect fingerprints.
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

/// Returns a string-valued index, treating missing and differently typed values alike.
fn string_index<'a>(indexes: &'a KeyValues, key: &str) -> Option<&'a str> {
    match indexes.get(key) {
        Some(Value::String(value)) => Some(value),
        _ => None,
    }
}

/// Derives the fingerprint scopes affected by a message.
///
/// Every message contributes to the global scope (`""`). A string-valued
/// `protocol` index adds `protocol:<uri>`. Permission-protocol messages can also
/// add `perm:<uri>` for their target protocol; a string-valued `tag.protocol`
/// index takes precedence over `descriptor_tag_proto` when both are available.
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

/// Compares two scope collections as sets.
///
/// Ordering and duplicate values are ignored. Stores use this when replacing a
/// message with the same CID: changing its fingerprint membership would make the
/// existing aggregate inconsistent.
pub fn scopes_unchanged(given: &[String], current: &[String]) -> bool {
    let mut given = given.to_vec();
    let mut current = current.to_vec();
    given.sort_unstable();
    given.dedup();
    current.sort_unstable();
    current.dedup();

    given == current
}

/// Computes one message CID's fixed-width fingerprint contribution.
///
/// The contribution is the SHA-256 digest of the CID string's UTF-8 bytes.
pub fn cid_contribution(message_cid: &str) -> Fingerprint {
    Into::<[u8; 32]>::into(Sha256::digest(message_cid.as_bytes())).into()
}

/// XORs `contribution` into `target` in place.
///
/// XOR is self-inverse, so applying the same contribution once adds it to an
/// aggregate and applying it again removes it.
pub fn xor_in_place(target: &mut Fingerprint, contribution: &Fingerprint) {
    for (t, c) in target
        .fingerprint
        .iter_mut()
        .zip(contribution.fingerprint.iter())
    {
        *t ^= *c;
    }
}

/// Applies a CID contribution to each `(tenant, scope)` aggregate.
///
/// Missing aggregates start at zero. Because the fold uses XOR, this same helper
/// is used both when adding an entry and when removing it. Callers must therefore
/// invoke it exactly once for each corresponding state transition.
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
            .or_default();

        xor_in_place(fingerprint, &contribution);
    }
}

/// Builds a progress token for a feed position.
///
/// The tenant determines the stream ID, and `seq` is encoded as its canonical
/// decimal string. `message_cid` should be present only when the token identifies
/// an existing entry at that exact position; scan high-water tokens may omit it.
pub fn build_token(
    tenant: &str,
    epoch: &str,
    seq: u64,
    message_cid: Option<&str>,
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
///
/// Returns [`EventLogError::InvalidProgressToken`] when the value is malformed,
/// non-canonical, negative, or outside the range of [`FeedPosition`].
pub fn parse_feed_position(position: &str) -> Result<FeedPosition, EventLogError> {
    let parsed = position
        .parse::<FeedPosition>()
        .map_err(|_| EventLogError::InvalidProgressToken(position.to_string()))?;

    if parsed.to_string() != position {
        return Err(EventLogError::InvalidProgressToken(position.to_string()));
    }

    Ok(parsed)
}

/// Validates a progress token against a consistent feed snapshot.
///
/// Validation checks the stream and epoch, parses the canonical position, and
/// ensures the position lies between `oldest_replayable` and `head`. When both
/// the token and the current entry provide a CID, they must match. A token may
/// omit its CID because it can represent a scan high-water position rather than
/// a delivered entry.
///
/// Returns the parsed numeric position on success. Stream, epoch, range, and CID
/// mismatches return a structured [`EventLogError::ProgressGap`]; malformed
/// positions return [`EventLogError::InvalidProgressToken`].
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
        FeedCursorState, Fingerprint,
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
    fn fingerprint_display_is_exactly_64_lowercase_hex_characters() {
        let fingerprint = Fingerprint::from([
            0x00, 0x01, 0x09, 0x0a, 0x0f, 0x10, 0x1f, 0x20, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f,
            0x80, 0x90, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0xff, 0x08, 0x17, 0x26, 0x35, 0x44,
            0x53, 0x62, 0x71, 0x8a,
        ]);

        let displayed = fingerprint.to_string();

        assert_eq!(displayed.len(), 64);
        assert_eq!(
            displayed,
            "0001090a0f101f202a3b4c5d6e7f8090abbccddeeff0ff08172635445362718a"
        );
        assert!(displayed
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character)));
    }

    #[test]
    fn fingerprint_as_slice_exposes_original_bytes() {
        let bytes = std::array::from_fn(|index| index as u8);
        let fingerprint = Fingerprint::from(bytes);

        assert_eq!(fingerprint.as_slice(), &bytes);
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

        let mut folded = [0_u8; 32].into();
        xor_in_place(&mut folded, &contribution);
        assert_eq!(folded, contribution);
        xor_in_place(&mut folded, &contribution);
        assert_eq!(folded, [0_u8; 32].into());

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
                Some(&[0_u8; 32].into())
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
