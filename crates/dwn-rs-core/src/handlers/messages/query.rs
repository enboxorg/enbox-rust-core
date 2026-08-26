use std::collections::BTreeSet;
use std::sync::Arc;

use crate::auth::resolver::DidResolver;
use crate::descriptors::messages::record_id;
use crate::descriptors::records::strip_encoded_data;
use crate::descriptors::Records;
use crate::handlers::messages::authorization::{
    authorize_query_or_subscribe, MessageAuthorizationKind, QueryAuthorization,
};
use crate::handlers::messages::common::{event_log_error_reply, messages_filters_to_filters};
use crate::handlers::records::common::fetch_initial_write_message;
use crate::permissions::{AuthorizationValidationError, PERMISSIONS_PROTOCOL_URI};
use crate::replies::messages::{Query, QueryEntry};
use crate::stores::replication_feed_reader::{
    permission_fingerprint_scope, protocol_fingerprint_scope, GLOBAL_DOMAIN,
};
use crate::stores::{EventLogEntry, EventLogReadOptions, MessageStore, ReplicationFeedReader};
use crate::{
    descriptors, message_filters, replies, Descriptor, Handler, HandlerContext, Message, Response,
    Value,
};

#[derive(Clone)]
pub struct MessagesQueryHandler<MS, RS> {
    message_store: MS,
    did_resolver: Option<Arc<dyn DidResolver>>,
    replication_feed_reader: Option<RS>,
}

impl<MS, RS> Handler for MessagesQueryHandler<MS, RS>
where
    MS: MessageStore + Clone + Send + Sync + 'static,
    RS: ReplicationFeedReader + Clone + Send + Sync + 'static,
{
    type Reply = Query;
    type Descriptor = descriptors::MessagesQueryDescriptor;

    async fn handle(
        &self,
        ctx: crate::HandlerContext<'_, Self::Descriptor>,
    ) -> replies::Response<Self::Reply> {
        let HandlerContext {
            tenant,
            message,
            descriptor,
            ..
        } = ctx;

        let auth_context = match crate::permissions::validate_authorization_signature(
            &message,
            self.did_resolver.as_deref(),
            true,
        )
        .await
        {
            Ok(Some(authorization)) => authorization,
            Ok(None) => {
                return Response::unauthorized(
                    "MessagesQueryMissingAuthorization: authorization is required",
                )
            }
            Err(err) => match err {
                AuthorizationValidationError::BadRequest(detail) => {
                    return Response::bad_request(format!(
                        "MessagesQueryInvalidAuthorization: {}",
                        detail
                    ));
                }
                AuthorizationValidationError::Unauthorized(detail) => {
                    return Response::unauthorized(format!(
                        "MessagesQueryInvalidAuthorization: {}",
                        detail
                    ));
                }
                err => {
                    return Response::bad_request(format!(
                        "MessagesQueryInvalidAuthorization: {}",
                        err
                    ));
                }
            },
        };

        let authorization = match authorize_query_or_subscribe(
            tenant,
            &message,
            &descriptor.filters,
            &auth_context,
            &self.message_store,
            MessageAuthorizationKind::Query,
        )
        .await
        {
            Ok(authorization) => QueryAuthorization::from(authorization),
            Err(details) => {
                return Response::unauthorized(details.to_string());
            }
        };

        let Some(reader) = &self.replication_feed_reader else {
            return Response::not_implemented("replication feed not supported");
        };

        let options = EventLogReadOptions {
            cursor: descriptor.cursor.clone(),
            filters: messages_filters_to_filters(
                &descriptor.filters,
                authorization.include_shadow_filters,
            ),
            limit: descriptor.limit,
        };

        let result = match reader.log_read(tenant, options).await {
            Ok(result) => result,
            Err(err) => return event_log_error_reply(err),
        };

        let entries = match self
            .build_entries(
                tenant,
                result.events,
                descriptor.cids_only.unwrap_or(false),
                &authorization,
            )
            .await
        {
            Ok(entries) => entries,
            Err(err) => return Response::internal_error(err),
        };

        let fingerprint = match query_fingerprint_scopes(&descriptor.filters) {
            Some(scopes) => match reader.fingerprint(tenant, &scopes).await {
                Ok(fingerprint) => Some(fingerprint.hex()),
                Err(err) => return Response::internal_error(err.to_string()),
            },
            None => None,
        };

        let reply = Query {
            entries: Some(entries),
            fingerprint,
            cursor: result.cursor,
            drained: Some(result.drained),
            role_record_id: authorization.role_record_id,
            ..Default::default()
        };

        Response::ok().with_reply(reply)
    }
}

impl<MS, RS> MessagesQueryHandler<MS, RS>
where
    MS: MessageStore + Clone + Send + Sync + 'static,
{
    pub fn new(
        message_store: MS,
        replication_feed_reader: Option<RS>,
        did_resolver: Option<Arc<dyn DidResolver>>,
    ) -> Self {
        Self {
            message_store,
            did_resolver,
            replication_feed_reader,
        }
    }

    async fn build_entries(
        &self,
        tenant: &str,
        events: Vec<EventLogEntry>,
        cids_only: bool,
        authorization: &QueryAuthorization,
    ) -> Result<Vec<QueryEntry>, String> {
        let mut entries = Vec::new();
        for event in events {
            let entry = self
                .build_entry(tenant, event, cids_only, authorization)
                .await?;
            entries.push(entry);
        }
        Ok(entries)
    }

    async fn build_entry(
        &self,
        tenant: &str,
        event: EventLogEntry,
        cids_only: bool,
        authorization: &QueryAuthorization,
    ) -> Result<QueryEntry, String> {
        let cid = match event.message_cid {
            Some(ref cid) => cid.parse().map_err(|err| format!("Invalid CID: {}", err))?,
            None => event
                .event
                .message
                .message_cid()
                .map_err(|err| err.to_string())?,
        };

        let protocol = match event.indexes.get("protocol") {
            Some(Value::String(proto)) => Some(proto.clone()),
            _ => None,
        };

        let is_latest_base_state = match event.indexes.get("isLatestBaseState") {
            Some(Value::Bool(true)) => true,
            Some(Value::String(s)) if s == "true" => true,
            _ => false,
        };

        let mut entry = QueryEntry {
            seq: event.seq.to_string(),
            cid,
            is_latest_base_state,
            protocol,
            message: None,
            encoded_data: None,
            initial_write: None,
        };

        if cids_only {
            return Ok(entry);
        }

        let mut message = event.event.message.clone();
        let inline_data = match &message.descriptor {
            Descriptor::Records(records) if matches!(records.as_ref(), Records::Write(_)) => {
                strip_encoded_data(&mut message)
                    .map_err(|err| format!("Failed to strip encoded data: {}", err))?
            }
            _ => None,
        };

        entry.message = Some(message);

        let encoded_data = event
            .encoded_data
            .as_ref()
            .or(inline_data.as_ref())
            .cloned();

        if authorization.include_encoded_data {
            entry.encoded_data = encoded_data;
        }

        if authorization.include_delete_initial_write {
            entry.initial_write = self.entry_initial_write(tenant, &event).await?;
        }

        Ok(entry)
    }

    async fn entry_initial_write(
        &self,
        tenant: &str,
        event: &EventLogEntry,
    ) -> Result<Option<Message<Descriptor>>, String> {
        if !matches!(
            event.event.message.descriptor,
            Descriptor::Records(ref records) if matches!(records.as_ref(), Records::Delete(_))
        ) {
            return Ok(None);
        }

        let mut initial_write = match &event.event.initial_write {
            Some(initial_write) => initial_write.clone().into(),
            None => {
                let Some(record_id) = record_id(&event.event.message) else {
                    return Ok(None);
                };

                let Some(initial_write) =
                    fetch_initial_write_message(tenant, &record_id, &self.message_store).await?
                else {
                    return Ok(None);
                };

                initial_write
            }
        };

        strip_encoded_data(&mut initial_write)
            .map_err(|err| format!("Failed to strip encoded data from initial write: {}", err))?;

        Ok(Some(initial_write))
    }
}

fn query_fingerprint_scopes(filters: &[message_filters::Messages]) -> Option<Vec<String>> {
    if filters.is_empty() {
        return Some(vec![GLOBAL_DOMAIN.to_string()]);
    }

    let mut protocols = BTreeSet::new();
    for filter in filters {
        if !is_protocol_only_filter(filter) {
            return None;
        }

        let protocol = filter.protocol.as_deref()?;

        if protocol.is_empty() || protocol == PERMISSIONS_PROTOCOL_URI {
            return None;
        }

        protocols.insert(protocol.to_string());
    }

    let mut scopes = Vec::with_capacity(protocols.len() * 2);
    for protocol in protocols {
        scopes.push(protocol_fingerprint_scope(&protocol));
        scopes.push(permission_fingerprint_scope(&protocol));
    }

    Some(scopes)
}

fn is_protocol_only_filter(filter: &message_filters::Messages) -> bool {
    filter
        .protocol
        .as_ref()
        .is_some_and(|protocol| !protocol.is_empty())
        && filter.interface.is_none()
        && filter.method.is_none()
        && filter.protocol_path.is_none()
        && filter.protocol_path_prefix.is_none()
        && filter.context_id_prefix.is_none()
        && filter.message_timestamp.is_none()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::ops::Bound;
    use std::sync::{Arc, Mutex};

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use bytes::Bytes;
    use serde_json::json;
    use ssi_jwk::Algorithm;

    use super::*;
    use crate::auth::{ed25519_jwk, Jws, PrivateJwkSigner, StaticPublicKeyResolver, JWK};
    use crate::cid::{generate_cid_from_json, generate_dag_pb_cid_from_bytes};
    use crate::descriptors::{
        DeleteDescriptor, MessagesQueryDescriptor, Records, RecordsWriteDescriptor,
    };
    use crate::dwn::{Handler, MethodHandlerRequest};
    use crate::errors::{EventLogError, MessageStoreError, StoreError};
    use crate::events::stream::MessageEvent;
    use crate::handlers::messages::authorization::{
        MessagesAuthorization, MessagesRoleAuthorization, QueryAuthorization,
    };
    use crate::handlers::records::common::ResolvedProtocolRole;
    use crate::stores::replication_feed_reader::{Fingerprint, ReplicationBounds};
    use crate::stores::{EventLogEntry, EventLogReadOptions, EventLogReadResult, MessageStore};
    use crate::fields::WriteFields;
    use crate::{Fields, MapValue, ProgressToken, RangeFilter};

    // -----------------------------------------------------------------------
    // Test infrastructure
    // -----------------------------------------------------------------------

    const TENANT: &str = "did:example:alice";

    fn protocol_filter(protocol: &str) -> message_filters::Messages {
        message_filters::Messages {
            protocol: Some(protocol.to_string()),
            ..Default::default()
        }
    }

    // -- MockReader ---------------------------------------------------------

    #[derive(Clone)]
    struct MockReader {
        reads: Arc<Mutex<VecDeque<Result<EventLogReadResult, EventLogError>>>>,
        fingerprints: Arc<Mutex<VecDeque<Result<Fingerprint, EventLogError>>>>,
    }

    impl MockReader {
        fn new(
            read: Result<EventLogReadResult, EventLogError>,
            fingerprint: Result<Fingerprint, EventLogError>,
        ) -> Self {
            Self {
                reads: Arc::new(Mutex::new(VecDeque::from([read]))),
                fingerprints: Arc::new(Mutex::new(VecDeque::from([fingerprint]))),
            }
        }

        fn with_read(result: Result<EventLogReadResult, EventLogError>) -> Self {
            Self::new(result, Ok(Fingerprint::default()))
        }
    }

    impl ReplicationFeedReader for MockReader {
        async fn log_read(
            &self,
            _tenant: &str,
            _options: EventLogReadOptions,
        ) -> Result<EventLogReadResult, EventLogError> {
            self.reads
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(EventLogReadResult::default()))
        }

        async fn log_bounds(
            &self,
            _tenant: &str,
        ) -> Result<Option<ReplicationBounds>, EventLogError> {
            Ok(None)
        }

        async fn fingerprint(
            &self,
            _tenant: &str,
            _scopes: &[String],
        ) -> Result<Fingerprint, EventLogError> {
            self.fingerprints
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(Fingerprint::default()))
        }

        async fn epoch(&self) -> Result<String, EventLogError> {
            Ok("test-epoch".to_string())
        }
    }

    // -- StubMessageStore ---------------------------------------------------

    #[derive(Clone, Default)]
    struct StubMessageStore {
        rows: Arc<Mutex<BTreeMap<(String, String), Message<Descriptor>>>>,
    }

    impl StubMessageStore {
        fn insert(&self, tenant: &str, record_id: &str, message: Message<Descriptor>) {
            self.rows
                .lock()
                .unwrap()
                .insert((tenant.to_string(), record_id.to_string()), message);
        }
    }

    impl MessageStore for StubMessageStore {
        async fn open(&mut self) -> Result<(), MessageStoreError> {
            Ok(())
        }
        async fn close(&mut self) {}
        async fn put<D: crate::descriptors::MessageDescriptor + Send>(
            &self,
            _tenant: &str,
            _message: Message<D>,
            _indexes: MapValue,
        ) -> Result<(), MessageStoreError> {
            Ok(())
        }
        async fn get(
            &self,
            _tenant: &str,
            _cid: &str,
        ) -> Result<Option<Message<Descriptor>>, MessageStoreError> {
            Ok(None)
        }
        async fn query(
            &self,
            tenant: &str,
            filters: crate::filters::Filters,
            _sort: Option<crate::MessageSort>,
            _pagination: Option<crate::Pagination>,
        ) -> Result<crate::stores::MessageQueryResult, MessageStoreError> {
            // Support fetching initial write by entryId (recordId).
            let entry_id = filters.into_iter().find_map(|filter| {
                filter
                    .get(&crate::filters::FilterKey::Index("entryId".to_string()))
                    .and_then(|f| match f {
                        crate::filters::Filter::Equal(Value::String(v)) => Some(v.clone()),
                        _ => None,
                    })
            });
            let messages = match entry_id {
                Some(id) => self
                    .rows
                    .lock()
                    .unwrap()
                    .get(&(tenant.to_string(), id))
                    .cloned()
                    .into_iter()
                    .collect(),
                None => vec![],
            };
            Ok(crate::stores::MessageQueryResult {
                messages,
                cursor: None,
            })
        }
        async fn count(
            &self,
            _tenant: &str,
            _filters: crate::filters::Filters,
            _sort: Option<crate::MessageSort>,
        ) -> Result<u64, MessageStoreError> {
            Ok(0)
        }
        async fn delete(&self, _tenant: &str, _cid: &str) -> Result<(), MessageStoreError> {
            Ok(())
        }
        async fn clear(&self) -> Result<(), MessageStoreError> {
            Ok(())
        }
    }

    // -- FailingMessageStore ------------------------------------------------

    #[derive(Clone)]
    struct FailingMessageStore;

    impl MessageStore for FailingMessageStore {
        async fn open(&mut self) -> Result<(), MessageStoreError> {
            Ok(())
        }
        async fn close(&mut self) {}
        async fn put<D: crate::descriptors::MessageDescriptor + Send>(
            &self,
            _: &str,
            _: Message<D>,
            _: MapValue,
        ) -> Result<(), MessageStoreError> {
            Ok(())
        }
        async fn get(&self, _: &str, _: &str) -> Result<Option<Message<Descriptor>>, MessageStoreError> {
            Ok(None)
        }
        async fn query(
            &self,
            _: &str,
            _: crate::filters::Filters,
            _: Option<crate::MessageSort>,
            _: Option<crate::Pagination>,
        ) -> Result<crate::stores::MessageQueryResult, MessageStoreError> {
            Err(MessageStoreError::StoreError(StoreError::InternalException(
                "store exploded".to_string(),
            )))
        }
        async fn count(
            &self,
            _: &str,
            _: crate::filters::Filters,
            _: Option<crate::MessageSort>,
        ) -> Result<u64, MessageStoreError> {
            Ok(0)
        }
        async fn delete(&self, _: &str, _: &str) -> Result<(), MessageStoreError> {
            Ok(())
        }
        async fn clear(&self) -> Result<(), MessageStoreError> {
            Ok(())
        }
    }

    // -- Signing helpers ----------------------------------------------------

    fn test_signer() -> PrivateJwkSigner {
        let key_id = format!("{TENANT}#key1");
        PrivateJwkSigner::new(
            &key_id,
            Algorithm::EdDSA,
            ed25519_jwk(
                "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
                Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"),
                Some(&key_id),
            )
            .unwrap(),
        )
    }

    fn test_resolver() -> StaticPublicKeyResolver {
        let key_id = format!("{TENANT}#key1");
        let jwk: JWK =
            ed25519_jwk("A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg", None, Some(&key_id))
                .unwrap();
        StaticPublicKeyResolver::new(BTreeMap::from([(key_id, jwk)]))
    }

    fn parse_time(value: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    async fn signed_query_message(
        filters: Vec<message_filters::Messages>,
        cursor: Option<ProgressToken>,
        cids_only: Option<bool>,
    ) -> serde_json::Value {
        let descriptor = MessagesQueryDescriptor {
            message_timestamp: parse_time("2025-06-01T00:00:00.000000Z"),
            filters,
            permission_grant_ids: None,
            cursor,
            limit: None,
            cids_only,
        };
        let descriptor_json = serde_json::to_value(&descriptor).unwrap();
        let payload = json!({
            "descriptorCid": generate_cid_from_json(&descriptor_json).unwrap().to_string(),
        });
        let signature = Jws::create(
            serde_json::to_vec(&payload).unwrap().as_slice(),
            &[test_signer()],
        )
        .await
        .unwrap();
        json!({
            "descriptor": descriptor_json,
            "authorization": { "signature": signature },
        })
    }

    // -- Handler constructors -----------------------------------------------

    fn handler_with_reader(
        reader: MockReader,
    ) -> MessagesQueryHandler<StubMessageStore, MockReader> {
        MessagesQueryHandler::new(
            StubMessageStore::default(),
            Some(reader),
            Some(Arc::new(test_resolver())),
        )
    }

    fn handler_without_reader() -> MessagesQueryHandler<StubMessageStore, MockReader> {
        MessagesQueryHandler::new(
            StubMessageStore::default(),
            None,
            Some(Arc::new(test_resolver())),
        )
    }

    fn handler_with_failing_store(
        reader: MockReader,
    ) -> MessagesQueryHandler<FailingMessageStore, MockReader> {
        MessagesQueryHandler::new(
            FailingMessageStore,
            Some(reader),
            Some(Arc::new(test_resolver())),
        )
    }

    // -- Run helpers --------------------------------------------------------

    async fn run_query(
        handler: &impl Handler<Reply = replies::messages::Query>,
        filters: Vec<message_filters::Messages>,
        cursor: Option<ProgressToken>,
        cids_only: Option<bool>,
    ) -> Response<replies::messages::Query> {
        let msg = signed_query_message(filters, cursor, cids_only).await;
        handler
            .run(MethodHandlerRequest::new(TENANT, &msg, None))
            .await
    }

    // -- Token / message builders -------------------------------------------

    fn token(position: u64, message_cid: Option<&str>) -> ProgressToken {
        ProgressToken {
            stream_id: TENANT.to_string(),
            epoch: "test-epoch".to_string(),
            position: position.to_string(),
            message_cid: message_cid.map(str::to_string),
        }
    }

    fn records_write_message_with_inline(encoded_data: Option<&str>) -> Message<Descriptor> {
        let data = Bytes::from_static(b"hello");
        let descriptor = RecordsWriteDescriptor {
            protocol: "http://example.com/notes".to_string(),
            protocol_path: "note".to_string(),
            recipient: None,
            schema: None,
            tags: None,
            parent_id: None,
            data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
            data_size: data.len() as u64,
            date_created: parse_time("2025-01-01T00:00:00.000000Z"),
            message_timestamp: parse_time("2025-01-01T00:00:00.000000Z"),
            published: None,
            date_published: None,
            data_format: "text/plain".to_string(),
            permission_grant_id: None,
            squash: None,
        };
        let mut wire = json!({
            "descriptor": descriptor,
            "recordId": "record-1",
            "contextId": "record-1",
        });
        if let Some(ed) = encoded_data {
            wire["encodedData"] = json!(ed);
        }
        serde_json::from_value(wire).unwrap()
    }

    fn records_write_message() -> Message<Descriptor> {
        records_write_message_with_inline(None)
    }

    fn delete_message(record_id: &str) -> Message<Descriptor> {
        Message {
            descriptor: Descriptor::Records(Box::new(Records::Delete(Box::new(
                DeleteDescriptor {
                    message_timestamp: parse_time("2025-01-02T00:00:00.000000Z"),
                    record_id: record_id.to_string(),
                    prune: false,
                },
            )))),
            fields: Fields::Write(WriteFields {
                record_id: Some(record_id.to_string()),
                ..Default::default()
            }),
        }
    }

    fn protocols_configure_message() -> Message<Descriptor> {
        serde_json::from_value(json!({
            "descriptor": {
                "interface": "Protocols",
                "method": "Configure",
                "messageTimestamp": "2025-01-01T00:00:00.000000Z",
                "definition": {
                    "protocol": "http://example.com/notes",
                    "published": true,
                    "types": { "note": {} },
                    "structure": { "note": {} }
                }
            }
        }))
        .unwrap()
    }

    fn entry(seq: u64, message: Message<Descriptor>) -> EventLogEntry {
        let message_cid = message
            .message_cid()
            .ok()
            .map(|c| c.to_string())
            .unwrap_or_else(|| format!("bafk-test-cid-{seq}"));
        EventLogEntry {
            seq: seq.to_string(),
            event: MessageEvent {
                message,
                initial_write: None,
            },
            indexes: MapValue::new(),
            message_cid: Some(message_cid),
            encoded_data: None,
        }
    }

    fn page(
        events: Vec<EventLogEntry>,
        cursor: Option<ProgressToken>,
        drained: bool,
    ) -> EventLogReadResult {
        EventLogReadResult {
            events,
            cursor,
            drained,
        }
    }

    // -- Authorization helpers ----------------------------------------------

    fn owner_authorization() -> QueryAuthorization {
        QueryAuthorization::from(MessagesAuthorization::Owner)
    }

    fn full_grant_authorization() -> QueryAuthorization {
        QueryAuthorization::from(MessagesAuthorization::Grant {
            metadata_only: false,
        })
    }

    fn metadata_only_grant_authorization() -> QueryAuthorization {
        QueryAuthorization::from(MessagesAuthorization::Grant {
            metadata_only: true,
        })
    }

    fn role_authorization(metadata_only: bool) -> QueryAuthorization {
        QueryAuthorization::from(MessagesAuthorization::Role(MessagesRoleAuthorization {
            author: "did:example:bob".to_string(),
            metadata_only,
            resolved_role: ResolvedProtocolRole {
                protocol: "http://example.com/notes".to_string(),
                protocol_path: "thread/participant".to_string(),
                context_id_prefix: Some("thread-1".to_string()),
                role_record_id: "role-record-1".to_string(),
            },
        }))
    }

    // =======================================================================
    // Fingerprint-scope unit tests (existing)
    // =======================================================================

    #[test]
    fn empty_filters_use_the_global_fingerprint_domain() {
        assert_eq!(
            query_fingerprint_scopes(&[]),
            Some(vec![GLOBAL_DOMAIN.to_string()])
        );
    }

    #[test]
    fn protocol_only_filters_include_protocol_and_permission_domains() {
        assert_eq!(
            query_fingerprint_scopes(&[
                protocol_filter("https://example.com/zeta"),
                protocol_filter("https://example.com/alpha"),
                protocol_filter("https://example.com/alpha"),
            ]),
            Some(vec![
                "protocol:https://example.com/alpha".to_string(),
                "perm:https://example.com/alpha".to_string(),
                "protocol:https://example.com/zeta".to_string(),
                "perm:https://example.com/zeta".to_string(),
            ])
        );
    }

    #[test]
    fn explicit_core_protocol_has_no_fingerprint() {
        assert_eq!(
            query_fingerprint_scopes(&[
                protocol_filter("https://example.com/notes"),
                protocol_filter(PERMISSIONS_PROTOCOL_URI),
            ]),
            None
        );
    }

    #[test]
    fn noncanonical_filters_do_not_have_a_fingerprint() {
        let cases = [
            message_filters::Messages::default(),
            message_filters::Messages {
                protocol: Some(String::new()),
                ..Default::default()
            },
            message_filters::Messages {
                protocol: Some("https://example.com/notes".to_string()),
                interface: Some("Records".to_string()),
                ..Default::default()
            },
            message_filters::Messages {
                protocol: Some("https://example.com/notes".to_string()),
                method: Some("Write".to_string()),
                ..Default::default()
            },
            message_filters::Messages {
                protocol: Some("https://example.com/notes".to_string()),
                protocol_path: Some("note".to_string()),
                ..Default::default()
            },
            message_filters::Messages {
                protocol: Some("https://example.com/notes".to_string()),
                protocol_path_prefix: Some("note".to_string()),
                ..Default::default()
            },
            message_filters::Messages {
                protocol: Some("https://example.com/notes".to_string()),
                context_id_prefix: Some("context".to_string()),
                ..Default::default()
            },
            message_filters::Messages {
                protocol: Some("https://example.com/notes".to_string()),
                message_timestamp: Some(RangeFilter::Criterion(
                    Bound::Included("2025-01-01T00:00:00Z".to_string()),
                    Bound::Unbounded,
                )),
                ..Default::default()
            },
        ];

        for filter in cases {
            assert_eq!(query_fingerprint_scopes(&[filter]), None);
        }
    }

    // =======================================================================
    // Basic feed response
    // =======================================================================

    #[tokio::test]
    async fn owner_gets_ordered_entries() {
        let msg = protocols_configure_message();
        let handler = handler_with_reader(MockReader::with_read(Ok(page(
            vec![entry(1, msg.clone()), entry(2, msg.clone()), entry(3, msg)],
            Some(token(3, None)),
            true,
        ))));
        let reply = run_query(&handler, vec![], None, None).await;
        assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
        let entries = reply.reply.entries.unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].seq, "1");
        assert_eq!(entries[1].seq, "2");
        assert_eq!(entries[2].seq, "3");
    }

    #[tokio::test]
    async fn entry_fields_are_populated() {
        let msg = records_write_message();
        let mut e = entry(7, msg);
        e.indexes.insert("protocol".to_string(), Value::String("http://example.com/notes".to_string()));
        e.indexes.insert("isLatestBaseState".to_string(), Value::Bool(true));

        let handler = handler_with_reader(MockReader::with_read(Ok(page(
            vec![e],
            Some(token(7, None)),
            true,
        ))));
        let reply = run_query(&handler, vec![], None, None).await;
        assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
        let e = &reply.reply.entries.unwrap()[0];
        assert_eq!(e.seq, "7");
        assert!(e.message.is_some());
        assert_eq!(e.protocol.as_deref(), Some("http://example.com/notes"));
        assert!(e.is_latest_base_state);
    }

    #[tokio::test]
    async fn cursor_and_drained_match_reader_result() {
        let cursor = token(42, Some("bafk-42"));
        let handler = handler_with_reader(MockReader::with_read(Ok(page(
            vec![],
            Some(cursor.clone()),
            false,
        ))));
        let reply = run_query(&handler, vec![], None, None).await;
        assert_eq!(reply.status.code, 200);
        assert_eq!(reply.reply.cursor, Some(cursor));
        assert_eq!(reply.reply.drained, Some(false));
    }

    #[tokio::test]
    async fn pagination_resumes_without_duplication() {
        let msg = protocols_configure_message();
        let cursor_after_first = token(1, None);

        let reader = MockReader {
            reads: Arc::new(Mutex::new(VecDeque::from([
                Ok(page(
                    vec![entry(1, msg.clone())],
                    Some(cursor_after_first.clone()),
                    false,
                )),
                Ok(page(vec![entry(2, msg)], Some(token(2, None)), true)),
            ]))),
            fingerprints: Arc::new(Mutex::new(VecDeque::from([
                Ok(Fingerprint::default()),
                Ok(Fingerprint::default()),
            ]))),
        };
        let handler = handler_with_reader(reader);

        let first = run_query(&handler, vec![], None, None).await;
        assert_eq!(first.reply.entries.unwrap()[0].seq, "1");
        assert_eq!(first.reply.drained, Some(false));

        let second = run_query(&handler, vec![], Some(cursor_after_first), None).await;
        assert_eq!(second.reply.entries.unwrap()[0].seq, "2");
        assert_eq!(second.reply.drained, Some(true));
    }

    // =======================================================================
    // cidsOnly
    // =======================================================================

    #[tokio::test]
    async fn cids_only_retains_feed_metadata_only() {
        let msg = records_write_message();
        let mut e = entry(5, msg);
        e.encoded_data = Some("c2hvdWxkLW5vdC1hcHBlYXI".to_string());
        e.indexes.insert("protocol".to_string(), Value::String("http://example.com/notes".to_string()));

        let handler = handler_with_reader(MockReader::with_read(Ok(page(
            vec![e],
            Some(token(5, None)),
            true,
        ))));
        let reply = run_query(&handler, vec![], None, Some(true)).await;
        assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
        let e = &reply.reply.entries.unwrap()[0];
        assert_eq!(e.seq, "5");
        assert_eq!(e.protocol.as_deref(), Some("http://example.com/notes"));
        assert!(e.message.is_none(), "cidsOnly must omit message");
        assert!(e.encoded_data.is_none(), "cidsOnly must omit encodedData");
        assert!(e.initial_write.is_none(), "cidsOnly must omit initialWrite");
    }

    #[tokio::test]
    async fn cids_only_still_returns_fingerprint_and_cursor() {
        let fp = Fingerprint::from([0xAB; 32]);
        let cursor = token(10, None);
        let handler = handler_with_reader(MockReader::new(
            Ok(page(vec![], Some(cursor.clone()), true)),
            Ok(fp.clone()),
        ));
        let reply = run_query(&handler, vec![], None, Some(true)).await;
        assert_eq!(reply.status.code, 200);
        assert_eq!(reply.reply.fingerprint, Some(fp.hex()));
        assert_eq!(reply.reply.cursor, Some(cursor));
    }

    // =======================================================================
    // Authorization shaping (via build_entry/build_entries)
    // =======================================================================

    #[tokio::test]
    async fn owner_gets_full_data_and_shadow_filters() {
        let auth = owner_authorization();
        assert!(auth.include_encoded_data);
        assert!(auth.include_shadow_filters);
        assert!(!auth.include_delete_initial_write);
        assert!(auth.role_record_id.is_none());
    }

    #[tokio::test]
    async fn unscoped_grant_gets_full_data_and_shadow_filters() {
        let auth = full_grant_authorization();
        assert!(auth.include_encoded_data);
        assert!(auth.include_shadow_filters);
        assert!(!auth.include_delete_initial_write);
    }

    #[tokio::test]
    async fn metadata_only_grant_gets_neither_data_nor_shadow_filters() {
        let auth = metadata_only_grant_authorization();
        assert!(!auth.include_encoded_data);
        assert!(!auth.include_shadow_filters);
    }

    #[tokio::test]
    async fn role_gets_role_record_id_no_shadow_and_delete_initial_writes() {
        let auth = role_authorization(false);
        assert!(auth.include_encoded_data);
        assert!(!auth.include_shadow_filters);
        assert!(auth.include_delete_initial_write);
        assert_eq!(auth.role_record_id.as_deref(), Some("role-record-1"));
    }

    #[tokio::test]
    async fn metadata_only_role_suppresses_data() {
        let auth = role_authorization(true);
        assert!(!auth.include_encoded_data);
        assert!(!auth.include_shadow_filters);
        assert!(auth.include_delete_initial_write);
        assert_eq!(auth.role_record_id.as_deref(), Some("role-record-1"));
    }

    // =======================================================================
    // Initial writes
    // =======================================================================

    #[tokio::test]
    async fn role_delete_uses_event_initial_write_when_present() {
        let handler: MessagesQueryHandler<StubMessageStore, MockReader> =
            MessagesQueryHandler::new(StubMessageStore::default(), None, None);

        let initial_write_msg = records_write_message();
        let iw: Message<crate::descriptors::records::WriteDescriptor> =
            serde_json::from_value(serde_json::to_value(&initial_write_msg).unwrap()).unwrap();

        let mut e = entry(1, delete_message("record-1"));
        e.event.initial_write = Some(iw);

        let result = handler
            .build_entry(TENANT, e, false, &role_authorization(false))
            .await
            .unwrap();
        assert!(
            result.initial_write.is_some(),
            "role-authorized delete should include initial_write from event"
        );
    }

    #[tokio::test]
    async fn role_delete_falls_back_to_message_store() {
        let store = StubMessageStore::default();
        store.insert(TENANT, "record-1", records_write_message());

        let handler: MessagesQueryHandler<StubMessageStore, MockReader> =
            MessagesQueryHandler::new(store, None, None);

        let e = entry(1, delete_message("record-1"));
        let result = handler
            .build_entry(TENANT, e, false, &role_authorization(false))
            .await
            .unwrap();
        assert!(
            result.initial_write.is_some(),
            "should fall back to message store for initial_write"
        );
    }

    #[tokio::test]
    async fn initial_write_has_no_inline_encoded_data() {
        let store = StubMessageStore::default();
        let inline = URL_SAFE_NO_PAD.encode(b"hello");
        store.insert(TENANT, "record-1", records_write_message_with_inline(Some(&inline)));

        let handler: MessagesQueryHandler<StubMessageStore, MockReader> =
            MessagesQueryHandler::new(store, None, None);

        let e = entry(1, delete_message("record-1"));
        let result = handler
            .build_entry(TENANT, e, false, &role_authorization(false))
            .await
            .unwrap();

        let iw = result.initial_write.unwrap();
        let iw_json = serde_json::to_value(&iw).unwrap();
        assert!(
            iw_json.get("encodedData").is_none(),
            "initial_write must have inline encodedData stripped"
        );
    }

    #[tokio::test]
    async fn missing_initial_write_returns_none() {
        let handler: MessagesQueryHandler<StubMessageStore, MockReader> =
            MessagesQueryHandler::new(StubMessageStore::default(), None, None);

        let e = entry(1, delete_message("nonexistent-record"));
        let result = handler
            .build_entry(TENANT, e, false, &role_authorization(false))
            .await
            .unwrap();
        assert!(
            result.initial_write.is_none(),
            "missing initial_write should be None"
        );
    }

    #[tokio::test]
    async fn owner_does_not_attach_initial_writes() {
        let store = StubMessageStore::default();
        store.insert(TENANT, "record-1", records_write_message());

        let handler: MessagesQueryHandler<StubMessageStore, MockReader> =
            MessagesQueryHandler::new(store, None, None);

        let e = entry(1, delete_message("record-1"));
        let result = handler
            .build_entry(TENANT, e, false, &owner_authorization())
            .await
            .unwrap();
        assert!(
            result.initial_write.is_none(),
            "owner should not get initial_write"
        );
    }

    #[tokio::test]
    async fn grant_does_not_attach_initial_writes() {
        let store = StubMessageStore::default();
        store.insert(TENANT, "record-1", records_write_message());

        let handler: MessagesQueryHandler<StubMessageStore, MockReader> =
            MessagesQueryHandler::new(store, None, None);

        let e = entry(1, delete_message("record-1"));
        let result = handler
            .build_entry(TENANT, e, false, &full_grant_authorization())
            .await
            .unwrap();
        assert!(
            result.initial_write.is_none(),
            "grant should not get initial_write"
        );
    }

    // =======================================================================
    // Fingerprints (handler-level)
    // =======================================================================

    #[tokio::test]
    async fn fingerprint_scopes_passed_to_reader_and_hex_appears_in_reply() {
        let fp = Fingerprint::from([0xDE; 32]);
        let handler = handler_with_reader(MockReader::new(
            Ok(EventLogReadResult::default()),
            Ok(fp.clone()),
        ));
        let reply = run_query(
            &handler,
            vec![protocol_filter("https://example.com/notes")],
            None,
            None,
        )
        .await;
        assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
        assert_eq!(reply.reply.fingerprint, Some(fp.hex()));
    }

    #[tokio::test]
    async fn fingerprint_omitted_for_noncanonical_filters() {
        let handler =
            handler_with_reader(MockReader::with_read(Ok(EventLogReadResult::default())));
        let reply = run_query(
            &handler,
            vec![message_filters::Messages {
                protocol: Some("https://example.com/notes".to_string()),
                interface: Some("Records".to_string()),
                ..Default::default()
            }],
            None,
            None,
        )
        .await;
        assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
        assert!(reply.reply.fingerprint.is_none());
    }

    #[tokio::test]
    async fn fingerprint_uses_global_scope_for_empty_filters() {
        let fp = Fingerprint::from([0xCD; 32]);
        let handler = handler_with_reader(MockReader::new(
            Ok(EventLogReadResult::default()),
            Ok(fp.clone()),
        ));
        let reply = run_query(&handler, vec![], None, None).await;
        assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
        assert_eq!(reply.reply.fingerprint, Some(fp.hex()));
    }

    // =======================================================================
    // §8  Progress and reply semantics
    // =======================================================================

    #[tokio::test]
    async fn seq_is_serialized_as_a_decimal_string() {
        let handler = handler_with_reader(MockReader::with_read(Ok(page(
            vec![
                entry(0, protocols_configure_message()),
                entry(42, protocols_configure_message()),
                entry(99999, protocols_configure_message()),
            ],
            Some(token(99999, None)),
            true,
        ))));
        let reply = run_query(&handler, vec![], None, None).await;
        assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
        let entries = reply.reply.entries.unwrap();
        assert_eq!(entries[0].seq, "0");
        assert_eq!(entries[1].seq, "42");
        assert_eq!(entries[2].seq, "99999");
    }

    #[tokio::test]
    async fn cursor_is_the_readers_high_water_mark() {
        let high_water = token(50, Some("bafk-hw"));
        let handler = handler_with_reader(MockReader::with_read(Ok(page(
            vec![],
            Some(high_water.clone()),
            false,
        ))));
        let reply = run_query(&handler, vec![], None, None).await;
        assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
        assert_eq!(reply.reply.cursor, Some(high_water));
    }

    #[tokio::test]
    async fn cursor_returned_even_when_no_event_matched() {
        let cursor = token(10, None);
        let handler = handler_with_reader(MockReader::with_read(Ok(page(
            vec![],
            Some(cursor.clone()),
            true,
        ))));
        let reply = run_query(&handler, vec![], None, None).await;
        assert_eq!(reply.status.code, 200);
        assert!(reply.reply.entries.unwrap().is_empty());
        assert_eq!(reply.reply.cursor, Some(cursor));
    }

    #[tokio::test]
    async fn drained_is_always_returned_on_success() {
        for drained_value in [true, false] {
            let handler = handler_with_reader(MockReader::with_read(Ok(page(
                vec![],
                None,
                drained_value,
            ))));
            let reply = run_query(&handler, vec![], None, None).await;
            assert_eq!(reply.status.code, 200);
            assert_eq!(reply.reply.drained, Some(drained_value));
        }
    }

    #[tokio::test]
    async fn progress_gap_returns_410_with_structured_error() {
        use crate::stores::{ProgressGapCode, ProgressGapInfo, ProgressGapReason};

        let reasons = [
            (ProgressGapReason::TokenTooOld, "token_too_old"),
            (ProgressGapReason::EpochMismatch, "epoch_mismatch"),
            (ProgressGapReason::StreamMismatch, "stream_mismatch"),
            (ProgressGapReason::TokenTooNew, "token_too_new"),
            (ProgressGapReason::MessageMismatch, "message_mismatch"),
        ];

        for (reason, expected_reason_str) in reasons {
            let requested = token(5, Some("bafk-req"));
            let oldest = token(0, None);
            let latest = token(100, Some("bafk-latest"));

            let gap = EventLogError::ProgressGap(Box::new(ProgressGapInfo {
                requested: requested.clone(),
                oldest_available: oldest.clone(),
                latest_available: latest.clone(),
                reason,
                code: ProgressGapCode::ProgressGap,
            }));

            let handler = handler_with_reader(MockReader::with_read(Err(gap)));
            let reply = run_query(&handler, vec![], None, None).await;

            assert_eq!(
                reply.status.code, 410,
                "expected 410 for {expected_reason_str}"
            );

            let error = reply.reply.error.expect("expected error in reply");
            assert_eq!(error.code, ProgressGapCode::ProgressGap);

            let reason_json = serde_json::to_value(&error.reason).unwrap();
            assert_eq!(reason_json.as_str().unwrap(), expected_reason_str);

            assert_eq!(error.requested, requested);
            assert_eq!(error.oldest_available, oldest);
            assert_eq!(error.latest_available, latest);
        }
    }

    #[tokio::test]
    async fn other_reader_failures_return_500() {
        let handler = handler_with_reader(MockReader::with_read(Err(
            EventLogError::StoreError(StoreError::InternalException("db went away".to_string())),
        )));
        let reply = run_query(&handler, vec![], None, None).await;
        assert_eq!(reply.status.code, 500);
        assert!(reply.status.detail.contains("db went away"));
    }

    #[tokio::test]
    async fn missing_reader_returns_501() {
        let handler = handler_without_reader();
        let reply = run_query(&handler, vec![], None, None).await;
        assert_eq!(reply.status.code, 501);
    }

    // =======================================================================
    // §6  Encoded-data precedence and suppression
    // =======================================================================

    #[tokio::test]
    async fn owner_returns_detached_encoded_data() {
        let handler: MessagesQueryHandler<StubMessageStore, MockReader> =
            MessagesQueryHandler::new(StubMessageStore::default(), None, None);

        let mut e = entry(1, records_write_message());
        e.encoded_data = Some("ZGV0YWNoZWQ".to_string());

        let result = handler
            .build_entry(TENANT, e, false, &owner_authorization())
            .await
            .unwrap();
        assert_eq!(result.encoded_data.as_deref(), Some("ZGV0YWNoZWQ"));
    }

    #[tokio::test]
    async fn full_grant_returns_detached_encoded_data() {
        let handler: MessagesQueryHandler<StubMessageStore, MockReader> =
            MessagesQueryHandler::new(StubMessageStore::default(), None, None);

        let mut e = entry(1, records_write_message());
        e.encoded_data = Some("Z3JhbnQ".to_string());

        let result = handler
            .build_entry(TENANT, e, false, &full_grant_authorization())
            .await
            .unwrap();
        assert_eq!(result.encoded_data.as_deref(), Some("Z3JhbnQ"));
    }

    #[tokio::test]
    async fn metadata_only_grant_omits_encoded_data() {
        let handler: MessagesQueryHandler<StubMessageStore, MockReader> =
            MessagesQueryHandler::new(StubMessageStore::default(), None, None);

        let mut e = entry(1, records_write_message());
        e.encoded_data = Some("c2VjcmV0".to_string());

        let result = handler
            .build_entry(TENANT, e, false, &metadata_only_grant_authorization())
            .await
            .unwrap();
        assert!(result.encoded_data.is_none());
    }

    #[tokio::test]
    async fn metadata_only_role_omits_encoded_data() {
        let handler: MessagesQueryHandler<StubMessageStore, MockReader> =
            MessagesQueryHandler::new(StubMessageStore::default(), None, None);

        let mut e = entry(1, records_write_message());
        e.encoded_data = Some("c2VjcmV0".to_string());

        let result = handler
            .build_entry(TENANT, e, false, &role_authorization(true))
            .await
            .unwrap();
        assert!(result.encoded_data.is_none());
    }

    #[tokio::test]
    async fn message_never_retains_inline_encoded_data() {
        let handler: MessagesQueryHandler<StubMessageStore, MockReader> =
            MessagesQueryHandler::new(StubMessageStore::default(), None, None);

        let inline = URL_SAFE_NO_PAD.encode(b"hello");
        let e = entry(1, records_write_message_with_inline(Some(&inline)));

        let result = handler
            .build_entry(TENANT, e, false, &owner_authorization())
            .await
            .unwrap();

        let msg = result.message.as_ref().expect("message should be present");
        let msg_json = serde_json::to_value(msg).unwrap();
        assert!(
            msg_json.get("encodedData").is_none(),
            "inline encodedData must be stripped from the message body"
        );
        assert_eq!(
            result.encoded_data.as_deref(),
            Some(inline.as_str()),
            "stripped inline data should be returned as detached encodedData"
        );
    }

    #[tokio::test]
    async fn detached_takes_precedence_over_inline() {
        let handler: MessagesQueryHandler<StubMessageStore, MockReader> =
            MessagesQueryHandler::new(StubMessageStore::default(), None, None);

        let inline = URL_SAFE_NO_PAD.encode(b"inline");
        let mut e = entry(1, records_write_message_with_inline(Some(&inline)));
        e.encoded_data = Some("ZGV0YWNoZWQ".to_string());

        let result = handler
            .build_entry(TENANT, e, false, &owner_authorization())
            .await
            .unwrap();
        assert_eq!(
            result.encoded_data.as_deref(),
            Some("ZGV0YWNoZWQ"),
            "detached encodedData takes precedence over inline"
        );
    }

    #[tokio::test]
    async fn cids_only_omits_message_and_encoded_data() {
        let handler: MessagesQueryHandler<StubMessageStore, MockReader> =
            MessagesQueryHandler::new(StubMessageStore::default(), None, None);

        let mut e = entry(1, records_write_message());
        e.encoded_data = Some("c2hvdWxkLW5vdC1hcHBlYXI".to_string());

        let result = handler
            .build_entry(TENANT, e, true, &owner_authorization())
            .await
            .unwrap();
        assert!(result.message.is_none(), "cidsOnly must omit message");
        assert!(
            result.encoded_data.is_none(),
            "cidsOnly must omit encodedData"
        );
    }

    // =======================================================================
    // Errors
    // =======================================================================

    #[tokio::test]
    async fn missing_authorization_returns_400() {
        let handler =
            handler_with_reader(MockReader::with_read(Ok(EventLogReadResult::default())));
        let msg = json!({
            "descriptor": {
                "interface": "Messages",
                "method": "Query",
                "messageTimestamp": "2025-06-01T00:00:00.000000Z",
            },
        });
        let reply = handler
            .run(MethodHandlerRequest::new(TENANT, &msg, None))
            .await;
        assert_eq!(reply.status.code, 400);
    }

    #[tokio::test]
    async fn invalid_signature_returns_400() {
        let handler =
            handler_with_reader(MockReader::with_read(Ok(EventLogReadResult::default())));
        let msg = json!({
            "descriptor": {
                "interface": "Messages",
                "method": "Query",
                "messageTimestamp": "2025-06-01T00:00:00.000000Z",
            },
            "authorization": { "signature": { "payload": "bad", "signatures": [] } },
        });
        let reply = handler
            .run(MethodHandlerRequest::new(TENANT, &msg, None))
            .await;
        assert!(
            reply.status.code == 400 || reply.status.code == 401,
            "expected 400 or 401, got {}",
            reply.status.code
        );
    }

    #[tokio::test]
    async fn authorization_denial_returns_401() {
        // Use a different tenant so the owner check fails and no grant/role is present.
        let handler =
            handler_with_reader(MockReader::with_read(Ok(EventLogReadResult::default())));
        let msg = signed_query_message(vec![], None, None).await;
        let reply = handler
            .run(MethodHandlerRequest::new("did:example:other-tenant", &msg, None))
            .await;
        assert_eq!(reply.status.code, 401);
    }

    #[tokio::test]
    async fn fingerprint_failure_returns_500() {
        let handler = handler_with_reader(MockReader::new(
            Ok(EventLogReadResult::default()),
            Err(EventLogError::StoreError(StoreError::InternalException(
                "fingerprint store broke".to_string(),
            ))),
        ));
        // Empty filters → global scope → fingerprint will be called.
        let reply = run_query(&handler, vec![], None, None).await;
        assert_eq!(reply.status.code, 500);
        assert!(reply.status.detail.contains("fingerprint store broke"));
    }

    #[tokio::test]
    async fn initial_write_store_failure_returns_500() {
        let handler: MessagesQueryHandler<FailingMessageStore, MockReader> =
            handler_with_failing_store(MockReader::with_read(Ok(page(
                vec![entry(1, delete_message("record-1"))],
                Some(token(1, None)),
                true,
            ))));

        // The role authorization triggers initial_write fetch, which calls the
        // failing message store's query method.
        // We can't go through run_query because we need the role auth path.
        // Instead, test via build_entry directly.
        let e = entry(1, delete_message("record-1"));
        let result = handler
            .build_entry(TENANT, e, false, &role_authorization(false))
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("store exploded"));
    }
}
