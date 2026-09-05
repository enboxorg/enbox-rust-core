//! JSON Schema validation for inbound DWN messages.
//!
//! Validates messages in `Dwn::process_message` using the same schema corpus
//! as `@enbox/dwn-sdk-js`.

use std::collections::HashMap;
use std::sync::OnceLock;

use jsonschema::{Draft, Registry, Resource, Validator};
use serde::Deserialize;
use serde_json::Value;

use crate::descriptors::MESSAGES_QUERY_SCHEMA;
use crate::dwn::MessageKind;
use crate::errors::{DwnError, DwnErrorCode};
use crate::interfaces::messages::descriptors::{
    MESSAGES_READ_SCHEMA, MESSAGES_SUBSCRIBE_SCHEMA, MESSAGES_SYNC_SCHEMA,
    PROTOCOLS_CONFIGURE_SCHEMA, PROTOCOLS_QUERY_SCHEMA, RECORDS_COUNT_SCHEMA,
    RECORDS_DELETE_SCHEMA, RECORDS_QUERY_SCHEMA, RECORDS_READ_SCHEMA, RECORDS_SUBSCRIBE_SCHEMA,
    RECORDS_WRITE_SCHEMA,
};
use crate::{Descriptor, Message, Response};

// Test-only tally of `validate_message` calls on the current thread, so "schema validation
// runs once per admitted message" is provable rather than asserted. A `#[tokio::test]` drives
// a current-thread runtime, so one message's whole pipeline lands on the counting thread.
#[cfg(test)]
thread_local! {
    pub(crate) static VALIDATE_MESSAGE_CALLS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

fn schema_error(detail: impl Into<String>) -> DwnError {
    DwnError::new(DwnErrorCode::SchemaValidatorFailure, detail)
}

static VALIDATORS: OnceLock<Result<HashMap<String, Validator>, DwnError>> = OnceLock::new();

const SCHEMA_SOURCES: &[(&str, &str)] = &[
    (
        "https://identity.foundation/dwn/json-schemas/authorization.json",
        include_str!("../../schemas/authorization.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/authorization-delegated-grant.json",
        include_str!("../../schemas/authorization-delegated-grant.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/authorization-owner.json",
        include_str!("../../schemas/authorization-owner.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/defs.json",
        include_str!("../../schemas/definitions.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/general-jws.json",
        include_str!("../../schemas/general-jws.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/jwk-verification-method.json",
        include_str!("../../schemas/jwk-verification-method.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/jwk/general-jwk.json",
        include_str!("../../schemas/jwk/general-jwk.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/jwk/public-jwk.json",
        include_str!("../../schemas/jwk/public-jwk.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/messages-filter.json",
        include_str!("../../schemas/interface-methods/messages-filter.json"),
    ),
    (
        MESSAGES_READ_SCHEMA,
        include_str!("../../schemas/interface-methods/messages-read.json"),
    ),
    (
        MESSAGES_SUBSCRIBE_SCHEMA,
        include_str!("../../schemas/interface-methods/messages-subscribe.json"),
    ),
    (
        MESSAGES_SYNC_SCHEMA,
        include_str!("../../schemas/interface-methods/messages-sync.json"),
    ),
    (
        MESSAGES_QUERY_SCHEMA,
        include_str!("../../schemas/interface-methods/messages-query.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/number-range-filter.json",
        include_str!("../../schemas/interface-methods/number-range-filter.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/pagination-cursor.json",
        include_str!("../../schemas/interface-methods/pagination-cursor.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/progress-token.json",
        include_str!("../../schemas/interface-methods/progress-token.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/protocol-definition.json",
        include_str!("../../schemas/interface-methods/protocol-definition.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/protocol-rule-set.json",
        include_str!("../../schemas/interface-methods/protocol-rule-set.json"),
    ),
    (
        PROTOCOLS_CONFIGURE_SCHEMA,
        include_str!("../../schemas/interface-methods/protocols-configure.json"),
    ),
    (
        PROTOCOLS_QUERY_SCHEMA,
        include_str!("../../schemas/interface-methods/protocols-query.json"),
    ),
    (
        RECORDS_COUNT_SCHEMA,
        include_str!("../../schemas/interface-methods/records-count.json"),
    ),
    (
        RECORDS_DELETE_SCHEMA,
        include_str!("../../schemas/interface-methods/records-delete.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/records-filter.json",
        include_str!("../../schemas/interface-methods/records-filter.json"),
    ),
    (
        RECORDS_QUERY_SCHEMA,
        include_str!("../../schemas/interface-methods/records-query.json"),
    ),
    (
        RECORDS_READ_SCHEMA,
        include_str!("../../schemas/interface-methods/records-read.json"),
    ),
    (
        RECORDS_SUBSCRIBE_SCHEMA,
        include_str!("../../schemas/interface-methods/records-subscribe.json"),
    ),
    (
        RECORDS_WRITE_SCHEMA,
        include_str!("../../schemas/interface-methods/records-write.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/records-write-data-encoded.json",
        include_str!("../../schemas/interface-methods/records-write-data-encoded.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/records-write-unidentified.json",
        include_str!("../../schemas/interface-methods/records-write-unidentified.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/string-range-filter.json",
        include_str!("../../schemas/interface-methods/string-range-filter.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/generic-signature-payload.json",
        include_str!("../../schemas/signature-payloads/generic-signature-payload.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/records-write-signature-payload.json",
        include_str!("../../schemas/signature-payloads/records-write-signature-payload.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/permissions/permission-grant-data.json",
        include_str!("../../schemas/permissions/permission-grant-data.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/permissions/permission-request-data.json",
        include_str!("../../schemas/permissions/permission-request-data.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/permissions/permission-revocation-data.json",
        include_str!("../../schemas/permissions/permission-revocation-data.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/permissions/permissions-definitions.json",
        include_str!("../../schemas/permissions/permissions-definitions.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/permissions/scopes.json",
        include_str!("../../schemas/permissions/scopes.json"),
    ),
];

fn build_validators() -> Result<HashMap<String, Validator>, DwnError> {
    let resources = SCHEMA_SOURCES
        .iter()
        .map(|(id, source)| {
            let schema: Value = serde_json::from_str(source)
                .map_err(|err| schema_error(format!("invalid embedded schema {id}: {err}")))?;
            let resource = Resource::from_contents(schema);
            Ok(((*id).to_string(), resource))
        })
        .collect::<Result<Vec<_>, DwnError>>()?;
    let registry = Registry::new()
        .draft(Draft::Draft202012)
        .extend(resources)
        .map_err(|err| schema_error((format!("schema registry must compile: {err}"))))?
        .prepare()
        .map_err(|err| schema_error((format!("schema registration err: {err}"))))?;
    SCHEMA_SOURCES
        .iter()
        .map(|(id, source)| {
            let schema: Value = serde_json::from_str(source)
                .map_err(|err| schema_error(format!("invalid embedded schema {id}: {err}")))?;
            let validator = jsonschema::options()
                .with_draft(Draft::Draft202012)
                .with_registry(&registry)
                .build(&schema)
                .map_err(|err| schema_error(format!("validator for {id} must compile: {err}")))?;
            Ok((id.to_string(), validator))
        })
        .collect()
}

fn validators() -> Result<&'static HashMap<String, Validator>, DwnError> {
    VALIDATORS
        .get_or_init(build_validators)
        .as_ref()
        .map_err(Clone::clone)
}

/// Schema-validate a raw message against the embedded DWN schema corpus.
///
/// `detail` carries no code prefix: upstream renders this stage through
/// `messageReplyFromError`, and [`ingress_rejection`] reproduces that shape.
pub fn validate_message(raw_message: &Value) -> Result<(), DwnError> {
    #[cfg(test)]
    VALIDATE_MESSAGE_CALLS.with(|calls| calls.set(calls.get() + 1));

    let kind = MessageKind::from_message(raw_message)?;
    let schema_not_found = || {
        DwnError::new(
            DwnErrorCode::SchemaValidatorSchemaNotFound,
            format!(
                "schema for {}{} not found",
                kind.interface().as_str(),
                kind.method(),
            ),
        )
    };
    let schema_id = kind.schema_id().ok_or_else(schema_not_found)?;
    let validator = validators()?.get(schema_id).ok_or_else(schema_not_found)?;
    if let Some(error) = validator.iter_errors(raw_message).next() {
        return Err(schema_error(error.to_string()));
    }
    Ok(())
}

/// Recognize and schema-validate, before dispatch picks a handler.
///
/// `DWN-AUTH-006` requires replicated, forwarded, and replayed messages to clear *normal
/// destination admission*; this is what those paths must reuse rather than re-implement.
/// No such path exists yet (#188), so nothing here proves that invariant.
pub(crate) fn admit_message(raw_message: &Value) -> Result<MessageKind, DwnError> {
    let kind = MessageKind::from_message(raw_message)?;
    validate_message(raw_message)?;
    Ok(kind)
}

/// Deserialize an admitted message into the typed envelope.
///
/// Borrows rather than consumes: `serde_json::from_value` would clone the whole message,
/// leaving forwarding, `$delivery` fan-out, and the subscription id without the original.
pub(crate) fn parse_message(raw_message: &Value) -> Result<Message<Descriptor>, DwnError> {
    Message::<Descriptor>::deserialize(raw_message).map_err(|err| {
        DwnError::new(
            DwnErrorCode::MessageParseFailed,
            format!("Failed to parse message: {err}"),
        )
    })
}

/// Full ingress for an entry point that holds wire JSON.
///
/// Dispatch runs the two stages separately — [`admit_message`] before handler lookup,
/// [`parse_message`] inside `Handler::run` — so neither runs twice.
pub fn ingest_message(raw_message: &Value) -> Result<(MessageKind, Message<Descriptor>), DwnError> {
    let kind = admit_message(raw_message)?;
    Ok((kind, parse_message(raw_message)?))
}

/// Render an admission rejection as its reply.
///
/// Upstream prefixes schema-failure details with the error code and repeats it in
/// `status.errorCode`, but reports the interface/method check as a bare detail. Both shapes
/// are preserved; the code is on the [`DwnError`] regardless.
pub fn ingress_rejection<R: Default>(error: DwnError) -> Response<R> {
    match error.code {
        DwnErrorCode::SchemaValidatorFailure | DwnErrorCode::SchemaValidatorSchemaNotFound => {
            Response::bad_request_error(error)
        }
        _ => Response::bad_request(error.detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dwn::current_handler_kinds;

    /// Completeness guard for the descriptor-derived schema lookup: every handler-backed kind must
    /// declare a `schema_id` that resolves to an embedded validator. Catches a future
    /// `#[descriptor]` that forgets `schema_id = …` (→ `None`) or points at a URL missing from
    /// `SCHEMA_SOURCES` — failures the old hand-maintained `schema_id_for_kind` match would have
    /// surfaced only at runtime on a live message.
    #[test]
    fn every_handler_kind_has_an_embedded_schema() {
        for kind in current_handler_kinds() {
            let schema_id = kind.schema_id().unwrap_or_else(|| {
                panic!("handler kind {} has no schema_id", kind.as_str());
            });
            assert!(
                validators().unwrap().contains_key(schema_id),
                "handler kind {} declares schema {schema_id}, which is not embedded in SCHEMA_SOURCES",
                kind.as_str(),
            );
        }
    }

    #[test]
    fn current_encrypted_records_write_matches_embedded_schema() {
        let message = serde_json::json!({
            "recordId": "record1",
            "contextId": "context1",
            "authorization": {},
            "encryption": {
                "algorithm": "A256CTR",
                "initializationVector": "oKGio6SlpqeoqaqrrK2urw",
                "keyEncryption": [{
                    "algorithm": "X25519-HKDF-SHA256+A256KW",
                    "keyId": "Qae4_6ZxDDA_vn260RVhSSBbdzwqIE0b2eWfSC7o50Q",
                    "derivationScheme": "protocolPath",
                    "ephemeralPublicKey": {
                        "kty": "OKP",
                        "crv": "X25519",
                        "x": "KodzRXbFA4L-ip7jNU5hFa1oOMbl6jOVQufMsijug28"
                    },
                    "encryptedKey": "KihbqckheDvgI4ZRJNu3el6L0dM8GLhXp_trR3P-vEpVs_pRpJbwjg"
                }]
            },
            "descriptor": {
                "interface": "Records",
                "method": "Write",
                "messageTimestamp": "2025-01-01T00:00:00.000000Z",
                "dateCreated": "2025-01-01T00:00:00.000000Z",
                "dataCid": "bafkreighhqlnlu3xumutodqyjeg6dkd6bhuhqydnemkjgoyn7eveukkfai",
                "dataSize": 38,
                "dataFormat": "text/plain",
                "protocol": "https://example.com/protocol/jwe",
                "protocolPath": "thread/message"
            }
        });

        validate_message(&message).expect("current encrypted RecordsWrite must validate");
    }
}

/// Ingress admission: every entry point into a node runs the same checks, in the same
/// order, and rejects with the same reply.
#[cfg(test)]
mod ingress_tests {
    use std::cell::Cell;
    use std::future::Future;
    use std::sync::{Arc, Mutex};

    use serde_json::json;

    use super::*;
    use crate::descriptors::records::{QueryDescriptor, RecordsMethod};
    use crate::dwn::{Dwn, Handler, HandlerContext, MethodHandlerRequest};
    use crate::fields::Fields;
    use crate::testing::{
        signed_write_message, unsigned_count_message, unsigned_query_message,
        unsigned_read_message, WriteSpec,
    };
    use crate::Reply;

    const TENANT: &str = "did:example:alice";
    const TIMESTAMP: &str = "2025-01-01T00:00:00.000000Z";

    /// A handler that records the message it was handed, so a 200 means "admitted" and the
    /// recording shows *what* the pipeline parsed.
    #[derive(Clone, Default)]
    struct AdmittedQueryHandler {
        seen: Arc<Mutex<Vec<Message<Descriptor>>>>,
    }

    impl Handler for AdmittedQueryHandler {
        type Descriptor = QueryDescriptor;
        type Reply = Reply;

        // Same `+ Send` bound as every real handler; see the `handlers` module in `lib.rs`.
        #[allow(clippy::manual_async_fn)]
        fn handle(
            &self,
            ctx: HandlerContext<'_, Self::Descriptor>,
        ) -> impl Future<Output = Response<Self::Reply>> + Send {
            async move {
                self.seen.lock().unwrap().push(ctx.message);
                Response::ok()
            }
        }
    }

    fn valid_query() -> Value {
        unsigned_query_message(json!({ "protocol": "http://example.com/notes" }))
    }

    /// The same input through dispatch and through the shared ingress must produce the same
    /// decision, the same reply, and — when admitted — the same `Message<Descriptor>`. That
    /// last part is what proves dispatch's `admit_message` + `run`'s `parse_message` compose
    /// back into `ingest_message` rather than drifting apart.
    ///
    /// The records subscribe entry point is held to the same equivalence in
    /// `handlers::records::tests`. `Handler::run` is deliberately not a separate leg here: it
    /// is post-admission, like an upstream handler.
    #[tokio::test]
    async fn every_entry_point_admits_and_rejects_identically() {
        let cases = [
            (
                "missing method",
                json!({ "descriptor": { "interface": "Records" } }),
            ),
            (
                "unknown method",
                json!({ "descriptor": { "interface": "Records", "method": "Bogus" } }),
            ),
            (
                "schema failure",
                json!({ "descriptor": { "interface": "Records", "method": "Query" } }),
            ),
            ("valid query", valid_query()),
        ];

        for (name, raw) in cases {
            let handler = AdmittedQueryHandler::default();
            let seen = handler.seen.clone();
            let mut dwn = Dwn::default();
            dwn.register(handler);

            let dispatched = dwn.process_message(TENANT, raw.clone()).await;
            let admitted = ingest_message(&raw);
            let shared: Response<Reply> = match &admitted {
                Ok(_) => Response::ok(),
                Err(error) => ingress_rejection(error.clone()),
            };

            assert_eq!(
                dispatched.status, shared.status,
                "{name}: dispatch vs shared ingress"
            );

            let seen = seen.lock().unwrap();
            match admitted {
                Ok((_, message)) => assert_eq!(
                    seen.as_slice(),
                    std::slice::from_ref(&message),
                    "{name}: dispatch parsed a different message than the shared ingress"
                ),
                Err(_) => assert!(
                    seen.is_empty(),
                    "{name}: rejected message reached the handler"
                ),
            }
        }
    }

    /// Admission covers every registered handler, not just typed ones: a raw
    /// [`crate::dwn::MethodHandler`] — which the default registry is built from — is never
    /// reached by a message that does not pass schema validation.
    #[tokio::test]
    async fn a_raw_method_handler_is_not_reached_without_admission() {
        // `Dwn::default()`'s stub handlers answer 501 for anything they are reached with.
        let dwn = Dwn::default();

        let admitted = dwn.process_message(TENANT, valid_query()).await;
        assert_eq!(admitted.status.code, 501);

        let rejected = dwn
            .process_message(
                TENANT,
                json!({ "descriptor": { "interface": "Records", "method": "Query" } }),
            )
            .await;
        assert_eq!(rejected.status.code, 400);
        assert_eq!(
            rejected.status.error_code.as_deref(),
            Some("SchemaValidatorFailure")
        );
    }

    /// The stage `Handler::run` still owns. Dispatch admits, `run` parses; neither repeats
    /// the other's work.
    #[tokio::test]
    async fn run_parses_an_admitted_message_without_revalidating_it() {
        let raw = valid_query();

        VALIDATE_MESSAGE_CALLS.with(|calls| calls.set(0));
        let reply = AdmittedQueryHandler::default()
            .run(MethodHandlerRequest::new(TENANT, &raw, None))
            .await;

        assert_eq!(reply.status.code, 200);
        assert_eq!(VALIDATE_MESSAGE_CALLS.with(Cell::get), 0);
    }

    /// The reply detail and status code of each rejection, pinned verbatim. Only schema
    /// failures carry `errorCode`, matching upstream: `validateMessageIntegrity` reports the
    /// interface/method check itself and routes only schema errors through
    /// `messageReplyFromError`.
    #[tokio::test]
    async fn rejection_replies_keep_their_status_detail_and_error_code() {
        let mut dwn = Dwn::default();
        dwn.register(AdmittedQueryHandler::default());

        let missing = dwn
            .process_message(TENANT, json!({ "descriptor": { "interface": "Records" } }))
            .await;
        assert_eq!(missing.status.code, 400);
        assert_eq!(
            missing.status.detail,
            "Both interface and method must be present, interface: Records, method: undefined"
        );
        assert_eq!(missing.status.error_code, None);

        let unknown = dwn
            .process_message(
                TENANT,
                json!({ "descriptor": { "interface": "Records", "method": "Bogus" } }),
            )
            .await;
        assert_eq!(unknown.status.code, 400);
        assert_eq!(
            unknown.status.detail,
            "Unknown interface/method combination, interface: Records, method: Bogus"
        );
        assert_eq!(unknown.status.error_code, None);

        let schema = dwn
            .process_message(
                TENANT,
                json!({ "descriptor": { "interface": "Records", "method": "Query" } }),
            )
            .await;
        assert_eq!(schema.status.code, 400);
        assert!(
            schema.status.detail.starts_with("SchemaValidatorFailure: "),
            "unexpected detail: {}",
            schema.status.detail
        );
        assert_eq!(
            schema.status.error_code.as_deref(),
            Some("SchemaValidatorFailure")
        );
    }

    /// Schema validation precedes deserialization, so a message that fails both is reported as
    /// a schema failure. `dataSize` is `{"type": "number"}` in the schema but `u64` in the
    /// typed descriptor, which is the one shape that clears schema and then fails to parse.
    #[tokio::test]
    async fn schema_validation_runs_before_typed_deserialization() {
        let mut fractional_size = signed_write_message(WriteSpec::new(TIMESTAMP)).await;
        fractional_size["descriptor"]["dataSize"] = json!(1.5);

        let error = ingest_message(&fractional_size).expect_err("u64 cannot hold 1.5");
        assert_eq!(error.code, DwnErrorCode::MessageParseFailed);
        assert!(
            error.detail.starts_with("Failed to parse message: "),
            "unexpected detail: {}",
            error.detail
        );

        let mut also_schema_invalid = fractional_size.clone();
        also_schema_invalid["descriptor"]
            .as_object_mut()
            .unwrap()
            .remove("messageTimestamp");

        let error = ingest_message(&also_schema_invalid).expect_err("schema rejects it first");
        assert_eq!(error.code, DwnErrorCode::SchemaValidatorFailure);
    }

    /// Ingress deserializes from a borrow, so the caller keeps the wire JSON — peer
    /// forwarding and `$delivery` fan-out re-emit the original bytes — and the typed message
    /// it produces still CIDs to the same identity.
    ///
    /// The expected CID is a checked-in literal, not `generate_message_cid_from_json(&raw)`:
    /// `Message::cid()` is implemented in terms of that function, so comparing the two would
    /// pass even if both changed together. `signed_write_message` is deterministic — a fixed
    /// JWK and Ed25519's deterministic signatures — so this pins the whole
    /// JSON → `Message<Descriptor>` → JSON round trip that ingress now performs in one place.
    #[tokio::test]
    async fn ingress_leaves_the_raw_message_intact_and_preserves_message_cid() {
        let raw = signed_write_message(WriteSpec::new(TIMESTAMP)).await;
        let before = raw.clone();

        let (kind, message) = ingest_message(&raw).expect("signed write is admitted");

        assert_eq!(kind, MessageKind::Records(RecordsMethod::Write));
        assert_eq!(raw, before);
        assert_eq!(
            message.cid().unwrap().to_string(),
            "bafyreiaobbfej4hmwrzfaxcem33fa4fvlqwbjs25xfatk57d3lzhdx3qya"
        );
    }

    /// `Fields` is `#[serde(untagged)]` and `WriteFields` defaults every member, so *every*
    /// message resolves to `Fields::Write` regardless of interface. Pinned so a future
    /// "reject mismatched field variants" conversion is not written against a false premise.
    #[tokio::test]
    async fn untagged_fields_resolve_every_message_to_the_write_variant() {
        let filter = json!({ "protocol": "http://example.com/notes" });
        let messages = [
            ("query", unsigned_query_message(filter.clone())),
            ("count", unsigned_count_message(filter.clone())),
            ("read", unsigned_read_message(filter)),
            (
                "write",
                signed_write_message(WriteSpec::new(TIMESTAMP)).await,
            ),
        ];

        for (name, raw) in messages {
            let (_, message) = ingest_message(&raw).expect("fixture is admitted");
            assert!(
                matches!(message.fields, Fields::Write(_)),
                "{name} did not resolve to Fields::Write"
            );
        }
    }

    /// Dispatch derives only the handler key; admission happens once, inside `Handler::run`.
    #[tokio::test]
    async fn schema_is_validated_once_per_processed_message() {
        let mut dwn = Dwn::default();
        dwn.register(AdmittedQueryHandler::default());

        VALIDATE_MESSAGE_CALLS.with(|calls| calls.set(0));
        let reply = dwn.process_message(TENANT, valid_query()).await;

        assert_eq!(reply.status.code, 200);
        assert_eq!(VALIDATE_MESSAGE_CALLS.with(Cell::get), 1);
    }
}
