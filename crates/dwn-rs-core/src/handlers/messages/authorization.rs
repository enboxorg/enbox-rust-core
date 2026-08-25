use thiserror::Error;

use crate::{
    descriptors::RECORDS,
    handlers::records::common::ResolvedProtocolRole,
    message_filters,
    permissions::{
        self,
        errors::{GrantError, PermissionError},
        AuthorizationContext,
    },
    stores::MessageStore,
    Descriptor, Message,
};

#[derive(Error, Debug)]
pub(crate) enum MessageAuthorizationError {
    #[error("role-authorized message filters require Records, protocol, protocolPathPrefix, and contextIdPrefix to be specified")]
    InvalidRoleMessage,

    #[error("role-authorized message filters must all be for the same protocol, protocolPathPrefix, and contextIdPrefix")]
    ShareProtoContext,

    #[error("role-authorized message filters must contain at least one filter")]
    ExpectedMessage,

    #[error("message failed authorization: {0}")]
    AuthorizationFailed(#[from] PermissionError),

    #[error("missing protocol role in authorization context")]
    MissingProtocolRole,
}

pub(crate) struct MessagesRoleAuthorization {
    pub author: String,
    pub metadata_only: bool,
    pub resolved_role: ResolvedProtocolRole,
}

pub(crate) enum MessagesAuthorization {
    Owner,
    Grant { metadata_only: bool },
    Role(MessagesRoleAuthorization),
}

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
) -> Result<MessagesAuthorization, MessageAuthorizationError>
where
    MS: MessageStore + Clone + Send + Sync + 'static,
{
    if auth.author == tenant {
        return Ok(MessagesAuthorization::Owner);
    }

    if auth.permission_grant_ids().is_some() {
        return authorize_grant(tenant, message, filters, auth, messages_store).await;
    }

    if auth.protocol_role().is_some() {
        return authorize_role(tenant, message, filters, auth, messages_store).await;
    }

    return Err(MessageAuthorizationError::AuthorizationFailed(
        PermissionError::InvalidGrant(GrantError::Unauthorized),
    ));
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
) -> Result<MessagesAuthorization, MessageAuthorizationError>
where
    MS: MessageStore + Clone + Send + Sync + 'static,
{
    let exact_filters = require_exact_role_filters(filters)?;

    let invoked_role = auth
        .protocol_role()
        .ok_or(MessageAuthorizationError::MissingProtocolRole)?;

    let metadata_only =
        authorize_author_delegate_if_present(tenant, message, filters, auth, messages_store)
            .await?;

    todo!();
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

        let Some(protocol_path) = filter.protocol_path_prefix.as_deref() else {
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
            f.protocol != first.protocol && f.context_id_prefix != first.context_id_prefix
        });

        if invalid_msg {
            return Err(MessageAuthorizationError::ShareProtoContext);
        }
    } else {
        return Err(MessageAuthorizationError::ExpectedMessage);
    }

    Ok(exact_role_filters)
}
