use thiserror::Error;

use crate::{
    descriptors::RECORDS,
    handlers::records::{
        common::{authorize_protocol_query_or_subscribe, ResolvedProtocolRole},
        RecordsAuthorizationKind,
    },
    message_filters,
    permissions::{self, errors::PermissionError, AuthorizationContext},
    stores::MessageStore,
    Descriptor, Message,
};

#[derive(Error, Debug)]
pub(crate) enum MessageAuthorizationError {
    #[error("role-authorized message filters require Records, protocol, protocolPath, and contextIdPrefix to be specified")]
    InvalidRoleMessage,

    #[error(
        "role-authorized message filters must all be for the same protocol and contextIdPrefix"
    )]
    ShareProtoContext,

    #[error("role-authorized message filters must contain at least one filter")]
    ExpectedMessage,

    #[error("message failed authorization: {0}")]
    AuthorizationFailed(#[from] PermissionError),

    #[error("missing protocol role in authorization context")]
    MissingProtocolRole,

    #[error("protocol error: {0}")]
    ProtocolAuthorization(String),

    #[error(
        "role-authorized message filters resolved to inconsistent protocol roles from records"
    )]
    InconsistentResolvedRole,

    #[error("message failed authorization")]
    Unauthorized,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MessagesRoleAuthorization {
    pub author: String,
    pub metadata_only: bool,
    pub resolved_role: ResolvedProtocolRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MessagesAuthorization {
    Owner,
    Grant { metadata_only: bool },
    Role(MessagesRoleAuthorization),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageAuthorizationKind {
    Query,
    Subscribe,
}

#[derive(Debug, Clone)]
struct ExactRoleFilter<'a> {
    protocol: &'a str,
    protocol_path: &'a str,
    context_id_prefix: &'a str,
}

pub(crate) async fn authorize_query_or_subscribe<MS>(
    tenant: &str,
    message: &Message<Descriptor>,
    filters: &[message_filters::Messages],
    auth: &AuthorizationContext,
    messages_store: &MS,
    kind: MessageAuthorizationKind,
) -> Result<MessagesAuthorization, MessageAuthorizationError>
where
    MS: MessageStore + Clone + Send + Sync + 'static,
{
    if auth.author == tenant && auth.signer == tenant {
        return Ok(MessagesAuthorization::Owner);
    }

    if auth.permission_grant_ids().is_some() {
        return authorize_grant(tenant, message, filters, auth, messages_store).await;
    }

    if auth.protocol_role().is_some() {
        return authorize_role(tenant, message, filters, auth, messages_store, kind).await;
    }

    Err(MessageAuthorizationError::Unauthorized)
}

async fn authorize_grant<MS>(
    tenant: &str,
    message: &Message<Descriptor>,
    filters: &[message_filters::Messages],
    auth: &AuthorizationContext,
    messages_store: &MS,
) -> Result<MessagesAuthorization, MessageAuthorizationError>
where
    MS: MessageStore + Clone + Send + Sync + 'static,
{
    let access = permissions::authorize_messages_subscribe_and_query(
        tenant,
        message,
        filters,
        auth,
        messages_store,
    )
    .await?;

    Ok(MessagesAuthorization::Grant {
        metadata_only: access.metadata_only,
    })
}

async fn authorize_author_delegate_if_present<MS>(
    _tenant: &str,
    message: &Message<Descriptor>,
    filters: &[message_filters::Messages],
    auth: &AuthorizationContext,
    messages_store: &MS,
) -> Result<bool, MessageAuthorizationError>
where
    MS: MessageStore + Clone + Send + Sync + 'static,
{
    let access = permissions::authorize_delegated_messages_subscribe_and_query(
        message,
        filters,
        auth,
        messages_store,
    )
    .await?;

    Ok(access.is_some_and(|access| access.metadata_only))
}

async fn authorize_role<MS>(
    tenant: &str,
    message: &Message<Descriptor>,
    filters: &[message_filters::Messages],
    auth: &AuthorizationContext,
    messages_store: &MS,
    kind: MessageAuthorizationKind,
) -> Result<MessagesAuthorization, MessageAuthorizationError>
where
    MS: MessageStore + Clone + Send + Sync + 'static,
{
    let exact_filters = require_exact_role_filters(filters)?;

    auth.protocol_role()
        .ok_or(MessageAuthorizationError::MissingProtocolRole)?;

    let metadata_only =
        authorize_author_delegate_if_present(tenant, message, filters, auth, messages_store)
            .await?;

    let records_kind = match kind {
        MessageAuthorizationKind::Query => RecordsAuthorizationKind::Query,
        MessageAuthorizationKind::Subscribe => RecordsAuthorizationKind::Subscribe,
    };

    let mut resolved: Option<ResolvedProtocolRole> = None;

    for filter in exact_filters {
        let record_filter = message_filters::Records {
            protocol: Some(filter.protocol.to_string()),
            protocol_path: Some(filter.protocol_path.to_string()),
            context_id: Some(filter.context_id_prefix.to_string()),
            ..Default::default()
        };

        let candidate = authorize_protocol_query_or_subscribe(
            tenant,
            &record_filter,
            auth,
            messages_store,
            records_kind,
        )
        .await
        .map_err(|err| MessageAuthorizationError::ProtocolAuthorization(err.to_string()))?;

        if let Some(first) = &resolved {
            if first != &candidate {
                return Err(MessageAuthorizationError::InconsistentResolvedRole);
            }
        } else {
            resolved = Some(candidate);
        }
    }

    let resolved_role = resolved.ok_or(MessageAuthorizationError::ExpectedMessage)?;

    Ok(MessagesAuthorization::Role(MessagesRoleAuthorization {
        author: auth.author.clone(),
        metadata_only,
        resolved_role,
    }))
}

fn require_exact_role_filters(
    filters: &[message_filters::Messages],
) -> Result<Vec<ExactRoleFilter<'_>>, MessageAuthorizationError> {
    if filters.is_empty() {
        return Err(MessageAuthorizationError::ExpectedMessage);
    }

    let mut exact_role_filters = Vec::new();

    for filter in filters {
        let Some(protocol) = filter.protocol.as_deref() else {
            return Err(MessageAuthorizationError::InvalidRoleMessage);
        };

        let Some(protocol_path) = filter.protocol_path.as_deref() else {
            return Err(MessageAuthorizationError::InvalidRoleMessage);
        };

        let Some(context_id_prefix) = filter.context_id_prefix.as_deref() else {
            return Err(MessageAuthorizationError::InvalidRoleMessage);
        };

        if filter.interface.as_deref() != Some(RECORDS)
            || filter.protocol_path_prefix.is_some()
            || protocol.is_empty()
            || protocol_path.is_empty()
            || context_id_prefix.is_empty()
        {
            return Err(MessageAuthorizationError::InvalidRoleMessage);
        }

        exact_role_filters.push(ExactRoleFilter {
            protocol,
            protocol_path,
            context_id_prefix,
        });
    }

    if let Some(first) = exact_role_filters.clone().first() {
        let invalid_msg = exact_role_filters.iter().any(|f| {
            f.protocol != first.protocol || f.context_id_prefix != first.context_id_prefix
        });

        if invalid_msg {
            return Err(MessageAuthorizationError::ShareProtoContext);
        }
    } else {
        return Err(MessageAuthorizationError::ExpectedMessage);
    }

    Ok(exact_role_filters)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jws::{AuthorizationPayloadData, PermissionGrantInvocation};
    use crate::permissions::VerifiedAuthorizationPayload;
    use crate::stores::{memory::MemoryMessageStore, MessageStore};
    use crate::Value;
    use std::collections::BTreeMap;

    const TENANT: &str = "did:example:tenant";
    const AUTHOR: &str = "did:example:alice";
    const PROTOCOL: &str = "https://example.com/protocol/chat";
    const ROLE: &str = "thread/participant";
    const CONTEXT: &str = "thread-1/message-1";

    fn exact_filter(path: &str) -> message_filters::Messages {
        message_filters::Messages {
            interface: Some(RECORDS.to_string()),
            protocol: Some(PROTOCOL.to_string()),
            protocol_path: Some(path.to_string()),
            context_id_prefix: Some(CONTEXT.to_string()),
            ..Default::default()
        }
    }

    fn role_authorization() -> AuthorizationContext {
        authorization_context(AUTHOR, AUTHOR, None, Some(ROLE))
    }

    fn authorization_context(
        author: &str,
        signer: &str,
        grant_ids: Option<Vec<String>>,
        protocol_role: Option<&str>,
    ) -> AuthorizationContext {
        AuthorizationContext {
            signer: signer.to_string(),
            author: author.to_string(),
            payload: VerifiedAuthorizationPayload::Generic(AuthorizationPayloadData {
                descriptor_cid: String::new(),
                delegated_grant_id: None,
                permission_grant_id: None,
                permission_grant_ids: grant_ids.clone(),
                protocol_role: protocol_role.map(str::to_string),
            }),
            permission_grant_invocation: grant_ids
                .map(PermissionGrantInvocation::Multi)
                .unwrap_or(PermissionGrantInvocation::None),
            author_delegated_grant: None,
        }
    }

    fn protocol_message() -> Message<Descriptor> {
        serde_json::from_value(serde_json::json!({
            "descriptor": {
                "interface": "Protocols",
                "method": "Configure",
                "messageTimestamp": "2024-12-31T00:00:00.000000Z",
                "definition": {
                    "protocol": PROTOCOL,
                    "published": false,
                    "types": {
                        "thread": {},
                        "participant": {},
                        "message": {},
                        "image": {},
                        "blocked": {}
                    },
                    "structure": {
                        "thread": {
                            "participant": { "$role": true },
                            "message": {
                                "$actions": [{ "role": ROLE, "can": ["read"] }]
                            },
                            "image": {
                                "$actions": [{ "role": ROLE, "can": ["read"] }]
                            },
                            "blocked": {}
                        }
                    }
                }
            }
        }))
        .expect("protocol message must deserialize")
    }

    fn role_record() -> Message<Descriptor> {
        serde_json::from_value(serde_json::json!({
            "descriptor": {
                "interface": "Records",
                "method": "Write",
                "messageTimestamp": "2025-01-01T00:00:00.000000Z",
                "dateCreated": "2025-01-01T00:00:00.000000Z",
                "dataCid": "bafkreighhqlnlu3xumutodqyjeg6dkd6bhuhqydnemkjgoyn7eveukkfai",
                "dataSize": 0,
                "dataFormat": "application/json",
                "protocol": PROTOCOL,
                "protocolPath": ROLE,
                "recipient": AUTHOR
            },
            "recordId": "role-record-1",
            "contextId": "thread-1"
        }))
        .expect("role record must deserialize")
    }

    async fn role_store() -> (MemoryMessageStore, Message<Descriptor>) {
        let store = MemoryMessageStore::default();
        let protocol = protocol_message();
        store
            .put(
                TENANT,
                protocol.clone(),
                BTreeMap::from([
                    (
                        "interface".to_string(),
                        Value::String("Protocols".to_string()),
                    ),
                    ("method".to_string(), Value::String("Configure".to_string())),
                    ("protocol".to_string(), Value::String(PROTOCOL.to_string())),
                    ("published".to_string(), Value::Bool(false)),
                    ("isLatestBaseState".to_string(), Value::Bool(true)),
                    (
                        "messageTimestamp".to_string(),
                        Value::String("2024-12-31T00:00:00.000000Z".to_string()),
                    ),
                ]),
            )
            .await
            .expect("protocol must be stored");
        store
            .put(
                TENANT,
                role_record(),
                BTreeMap::from([
                    (
                        "interface".to_string(),
                        Value::String("Records".to_string()),
                    ),
                    ("method".to_string(), Value::String("Write".to_string())),
                    ("protocol".to_string(), Value::String(PROTOCOL.to_string())),
                    ("protocolPath".to_string(), Value::String(ROLE.to_string())),
                    ("recipient".to_string(), Value::String(AUTHOR.to_string())),
                    (
                        "contextId".to_string(),
                        Value::String("thread-1".to_string()),
                    ),
                    ("isLatestBaseState".to_string(), Value::Bool(true)),
                    (
                        "messageTimestamp".to_string(),
                        Value::String("2025-01-01T00:00:00.000000Z".to_string()),
                    ),
                ]),
            )
            .await
            .expect("role record must be stored");
        (store, protocol)
    }

    #[test]
    fn exact_role_filter_validation_accepts_one_or_multiple_paths() {
        let one_filter = [exact_filter("thread/message")];
        let one = require_exact_role_filters(&one_filter).expect("one exact filter must be valid");
        assert_eq!(one.len(), 1);

        let multiple_filters = [exact_filter("thread/message"), exact_filter("thread/image")];
        let multiple = require_exact_role_filters(&multiple_filters)
            .expect("different paths in one protocol and context must be valid");
        assert_eq!(multiple.len(), 2);
    }

    #[test]
    fn exact_role_filter_validation_rejects_invalid_shapes() {
        assert!(matches!(
            require_exact_role_filters(&[]),
            Err(MessageAuthorizationError::ExpectedMessage)
        ));

        let mut cases = Vec::new();
        let mut filter = exact_filter("thread/message");
        filter.interface = Some("Protocols".to_string());
        cases.push(filter);
        let mut filter = exact_filter("thread/message");
        filter.protocol = None;
        cases.push(filter);
        let mut filter = exact_filter("thread/message");
        filter.protocol_path = None;
        cases.push(filter);
        let mut filter = exact_filter("thread/message");
        filter.protocol_path_prefix = Some("thread".to_string());
        cases.push(filter);
        let mut filter = exact_filter("thread/message");
        filter.context_id_prefix = None;
        cases.push(filter);

        for filter in cases {
            assert!(matches!(
                require_exact_role_filters(&[filter]),
                Err(MessageAuthorizationError::InvalidRoleMessage)
            ));
        }

        for clear in ["protocol", "path", "context"] {
            let mut filter = exact_filter("thread/message");
            match clear {
                "protocol" => filter.protocol = Some(String::new()),
                "path" => filter.protocol_path = Some(String::new()),
                "context" => filter.context_id_prefix = Some(String::new()),
                _ => unreachable!(),
            }
            assert!(matches!(
                require_exact_role_filters(&[filter]),
                Err(MessageAuthorizationError::InvalidRoleMessage)
            ));
        }
    }

    #[test]
    fn exact_role_filter_validation_rejects_different_protocol_or_context() {
        let mut other_protocol = exact_filter("thread/image");
        other_protocol.protocol = Some("https://example.com/protocol/other".to_string());
        assert!(matches!(
            require_exact_role_filters(&[exact_filter("thread/message"), other_protocol]),
            Err(MessageAuthorizationError::ShareProtoContext)
        ));

        let mut other_context = exact_filter("thread/image");
        other_context.context_id_prefix = Some("thread-2/message-1".to_string());
        assert!(matches!(
            require_exact_role_filters(&[exact_filter("thread/message"), other_context]),
            Err(MessageAuthorizationError::ShareProtoContext)
        ));
    }

    #[tokio::test]
    async fn role_adapter_authorizes_query_and_subscribe_with_consistent_role_state() {
        let (store, message) = role_store().await;
        let filters = [exact_filter("thread/message"), exact_filter("thread/image")];

        for kind in [
            MessageAuthorizationKind::Query,
            MessageAuthorizationKind::Subscribe,
        ] {
            let authorization = authorize_role(
                TENANT,
                &message,
                &filters,
                &role_authorization(),
                &store,
                kind,
            )
            .await
            .expect("both paths must resolve the same role");

            let MessagesAuthorization::Role(role) = authorization else {
                panic!("expected role authorization");
            };
            assert_eq!(role.author, AUTHOR);
            assert!(!role.metadata_only);
            assert_eq!(role.resolved_role.protocol, PROTOCOL);
            assert_eq!(role.resolved_role.protocol_path, ROLE);
            assert_eq!(
                role.resolved_role.context_id_prefix.as_deref(),
                Some(CONTEXT)
            );
            assert_eq!(role.resolved_role.role_record_id, "role-record-1");
        }
    }

    #[tokio::test]
    async fn role_adapter_rejects_when_any_path_is_unauthorized() {
        let (store, message) = role_store().await;
        let result = authorize_role(
            TENANT,
            &message,
            &[
                exact_filter("thread/message"),
                exact_filter("thread/blocked"),
            ],
            &role_authorization(),
            &store,
            MessageAuthorizationKind::Query,
        )
        .await;

        assert!(matches!(
            result,
            Err(MessageAuthorizationError::ProtocolAuthorization(_))
        ));
    }

    #[tokio::test]
    async fn shared_dispatch_distinguishes_owner_delegate_role_and_missing_mode() {
        let (store, message) = role_store().await;
        let filters = [exact_filter("thread/message")];

        let owner = authorize_query_or_subscribe(
            TENANT,
            &message,
            &filters,
            &authorization_context(TENANT, TENANT, None, None),
            &store,
            MessageAuthorizationKind::Query,
        )
        .await
        .expect("tenant signed by tenant must be owner");
        assert_eq!(owner, MessagesAuthorization::Owner);

        let delegated_owner = authorize_query_or_subscribe(
            TENANT,
            &message,
            &filters,
            &authorization_context(TENANT, AUTHOR, None, None),
            &store,
            MessageAuthorizationKind::Query,
        )
        .await;
        assert!(matches!(
            delegated_owner,
            Err(MessageAuthorizationError::Unauthorized)
        ));

        let role = authorize_query_or_subscribe(
            TENANT,
            &message,
            &filters,
            &role_authorization(),
            &store,
            MessageAuthorizationKind::Query,
        )
        .await
        .expect("valid role invocation must dispatch to role authorization");
        assert!(matches!(role, MessagesAuthorization::Role(_)));

        let missing_mode = authorize_query_or_subscribe(
            TENANT,
            &message,
            &filters,
            &authorization_context(AUTHOR, AUTHOR, None, None),
            &store,
            MessageAuthorizationKind::Query,
        )
        .await;
        assert!(matches!(
            missing_mode,
            Err(MessageAuthorizationError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn explicit_grant_failure_does_not_fall_back_to_valid_role() {
        let (store, message) = role_store().await;
        let result = authorize_query_or_subscribe(
            TENANT,
            &message,
            &[exact_filter("thread/message")],
            &authorization_context(
                AUTHOR,
                AUTHOR,
                Some(vec!["missing-grant".to_string()]),
                Some(ROLE),
            ),
            &store,
            MessageAuthorizationKind::Query,
        )
        .await;

        assert!(matches!(
            result,
            Err(MessageAuthorizationError::AuthorizationFailed(_))
        ));
    }
}
