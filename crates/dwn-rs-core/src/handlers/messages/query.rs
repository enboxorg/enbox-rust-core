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
            filters: messages_filters_to_filters(&descriptor.filters, authorization.include_shadow_filters),
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

        let is_latest_base_state = matches!(
            event.indexes.get("isLatestBaseState"),
            Some(Value::Bool(true))
        );

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
            Descriptor::Records(_) => strip_encoded_data(&mut message)
                .map_err(|err| format!("Failed to strip encoded data: {}", err))?,
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

        entry.initial_write = self.entry_initial_write(tenant, &event).await?;

        return Ok(entry);
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

        let initial_write = match &event.event.initial_write {
            Some(initial_write) => initial_write.clone().into(),
            None => {
                let Some(record_id) = record_id(&event.event.message) else {
                    return Ok(None);
                };

                fetch_initial_write_message(tenant, &record_id, &self.message_store)
                    .await?
                    .ok_or_else(|| {
                        format!(
                            "Initial write message not found for recordId: {}",
                            record_id
                        )
                    })?
            }
        };

        strip_encoded_data(&mut initial_write.clone())
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
    use std::ops::Bound;

    use super::*;
    use crate::RangeFilter;

    fn protocol_filter(protocol: &str) -> message_filters::Messages {
        message_filters::Messages {
            protocol: Some(protocol.to_string()),
            ..Default::default()
        }
    }

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
}
