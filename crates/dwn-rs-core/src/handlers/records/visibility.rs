//! Canonical Records collection visibility plan.
//!
//! Covers `DWN-REC-001`: every read surface derives its visible population
//! from this one plan, so a record readable by one method is readable by all
//! for equivalent input. Covers `DWN-REC-005`: snapshot and event selection
//! stay distinct projections over the same authorization.
//!
//! Query, Count, and both Subscribe paths previously built their
//! authorization and store filters in four parallel inline blocks. This module
//! is the single implementation behind all of them: [`authorize_collection`]
//! resolves who the requester is, and [`collection_filters`] projects that
//! outcome onto store filters for one [`PlanMode`]. Authorization and
//! projection stay distinct phases sharing one auth outcome, so the
//! event-log path builds both filter sets without authorizing twice.

use crate::descriptors::records::DateSort;
use crate::filters::message_filters::Records as RecordsFilter;
use crate::filters::Filters;
use crate::permissions::{self, AuthorizationContext};
use crate::{Descriptor, Message};

use super::common::{
    authorize_protocol_query_or_subscribe, filter_includes_published_records,
    non_owner_records_event_filters, non_owner_records_filters, owner_records_event_filter,
    owner_records_filter, published_records_event_filter, published_records_filter,
    should_protocol_authorize,
};
use super::RecordsAuthorizationKind;

/// Which projection of visible state a filter set selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanMode {
    /// Current latest writes only.
    Snapshot,
    /// Writes and deletes for event delivery.
    Event,
}

/// Who a collection request is authorized as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisibilityClass {
    Owner,
    Published,
    NonOwner,
}

/// The outcome of collection authorization: everything [`collection_filters`]
/// needs, and nothing it must recompute.
#[derive(Debug, Clone)]
pub(crate) struct CollectionAuthorization {
    pub visibility: VisibilityClass,
    pub author: Option<String>,
    pub protocol_authorized: bool,
    /// Whether an invoked grant covered the request at open. Retained for
    /// delivery-time revalidation of mutable grant state.
    pub grant_authorized: bool,
}

/// Resolves the visibility plan for one collection request: anonymous
/// published fast path, grant check, invoked-role check, then owner versus
/// non-owner classification. Role policy is resolved at `request_timestamp`,
/// never blindly newest.
pub(crate) async fn authorize_collection<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    filter: &RecordsFilter,
    signature: Option<&AuthorizationContext>,
    message_store: &MessageStore,
    request_timestamp: &str,
    kind: RecordsAuthorizationKind,
) -> Result<CollectionAuthorization, String>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    if filter_includes_published_records(filter) && signature.is_none() {
        return Ok(CollectionAuthorization {
            visibility: VisibilityClass::Published,
            author: None,
            protocol_authorized: false,
            grant_authorized: false,
        });
    }
    let signature = signature
        .ok_or_else(|| "AuthenticateJwsMissing: authorization signature is required".to_string())?;
    let grant_authorized = permissions::authorize_records_query_or_subscribe_with_grant(
        tenant,
        message,
        filter,
        signature,
        message_store,
    )
    .await
    .map_err(|error| error.to_string())?;
    if should_protocol_authorize(signature) {
        authorize_protocol_query_or_subscribe(
            tenant,
            filter,
            signature,
            message_store,
            request_timestamp,
            kind,
        )
        .await?;
    }
    let protocol_authorized = should_protocol_authorize(signature) || grant_authorized;
    if signature.author == tenant {
        Ok(CollectionAuthorization {
            visibility: VisibilityClass::Owner,
            author: Some(signature.author.clone()),
            protocol_authorized,
            grant_authorized,
        })
    } else {
        Ok(CollectionAuthorization {
            visibility: VisibilityClass::NonOwner,
            author: Some(signature.author.clone()),
            protocol_authorized,
            grant_authorized,
        })
    }
}

/// Projects an authorized plan onto store filters for one [`PlanMode`].
pub(crate) fn collection_filters(
    auth: &CollectionAuthorization,
    filter: &RecordsFilter,
    date_sort: Option<&DateSort>,
    mode: PlanMode,
) -> Filters {
    match (auth.visibility, mode) {
        (VisibilityClass::Published, PlanMode::Snapshot) => {
            Filters::from(published_records_filter(filter, date_sort))
        }
        (VisibilityClass::Published, PlanMode::Event) => {
            Filters::from(published_records_event_filter(filter))
        }
        (VisibilityClass::Owner, PlanMode::Snapshot) => {
            Filters::from(owner_records_filter(filter, date_sort))
        }
        (VisibilityClass::Owner, PlanMode::Event) => {
            Filters::from(owner_records_event_filter(filter))
        }
        (VisibilityClass::NonOwner, PlanMode::Snapshot) => {
            let author = auth
                .author
                .as_deref()
                .expect("non-owner authorization always carries the semantic author");
            Filters::from(non_owner_records_filters(
                filter,
                date_sort,
                author,
                auth.protocol_authorized,
            ))
        }
        (VisibilityClass::NonOwner, PlanMode::Event) => {
            let author = auth
                .author
                .as_deref()
                .expect("non-owner authorization always carries the semantic author");
            Filters::from(non_owner_records_event_filters(
                filter,
                author,
                auth.protocol_authorized,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;
    use crate::auth::jws::{AuthorizationPayloadData, PermissionGrantInvocation};
    use crate::permissions::VerifiedAuthorizationPayload;
    use crate::stores::memory::MemoryMessageStore;
    use crate::stores::{KeyValues, MessageStore};
    use crate::{Filter, FilterKey, Value};

    const PLAN_TENANT: &str = "did:example:alice";
    const PLAN_AUTHOR: &str = "did:example:bob";

    fn auth_ctx(author: &str) -> AuthorizationContext {
        AuthorizationContext {
            signer: author.to_string(),
            author: author.to_string(),
            payload: VerifiedAuthorizationPayload::Generic(AuthorizationPayloadData {
                descriptor_cid: String::new(),
                delegated_grant_id: None,
                permission_grant_id: None,
                permission_grant_ids: None,
                protocol_role: None,
            }),
            permission_grant_invocation: PermissionGrantInvocation::None,
            author_delegated_grant: None,
        }
    }

    fn write_row(record_id: &str, published: bool) -> (Message<Descriptor>, KeyValues) {
        let message: Message<Descriptor> = serde_json::from_value(json!({
            "descriptor": {
                "interface": "Records",
                "method": "Write",
                "messageTimestamp": "2025-01-01T00:00:00.000000Z",
                "dateCreated": "2025-01-01T00:00:00.000000Z",
                "dataCid": "bafkreighhqlnlu3xumutodqyjeg6dkd6bhuhqydnemkjgoyn7eveukkfai",
                "dataSize": 0,
                "dataFormat": "application/json",
                "protocol": "https://example.com/protocol/threads",
                "protocolPath": "thread/message",
                "recipient": PLAN_TENANT
            },
            "recordId": record_id,
            "contextId": "thread-1"
        }))
        .expect("write row must deserialize");
        let indexes = BTreeMap::from([
            (
                "interface".to_string(),
                Value::String("Records".to_string()),
            ),
            ("method".to_string(), Value::String("Write".to_string())),
            ("recordId".to_string(), Value::String(record_id.to_string())),
            ("published".to_string(), Value::Bool(published)),
            ("isLatestBaseState".to_string(), Value::Bool(true)),
            (
                "messageTimestamp".to_string(),
                Value::String("2025-01-01T00:00:00.000000Z".to_string()),
            ),
        ]);
        (message, indexes)
    }

    fn published_clause(set: &BTreeMap<FilterKey, Filter<Value>>) -> Option<bool> {
        match set.get(&FilterKey::Index("published".to_string())) {
            Some(Filter::Equal(Value::Bool(published))) => Some(*published),
            _ => None,
        }
    }

    // Covers: DWN-REC-001, DWN-AUTH-001
    #[test]
    fn visibility_classes_select_expected_filter_shapes() {
        let filter = RecordsFilter::default();

        let owner = CollectionAuthorization {
            visibility: VisibilityClass::Owner,
            author: Some(PLAN_TENANT.to_string()),
            protocol_authorized: false,
            grant_authorized: false,
        };
        let owner_sets = collection_filters(&owner, &filter, None, PlanMode::Snapshot).set;
        assert_eq!(owner_sets.len(), 1, "owner sees one un-narrowed set");
        assert!(
            !owner_sets[0].contains_key(&FilterKey::Index("author".to_string())),
            "owner set must not narrow by author"
        );
        assert!(
            !owner_sets[0].contains_key(&FilterKey::Index("recipient".to_string())),
            "owner set must not narrow by recipient"
        );

        let published = CollectionAuthorization {
            visibility: VisibilityClass::Published,
            author: None,
            protocol_authorized: false,
            grant_authorized: false,
        };
        let published_sets = collection_filters(&published, &filter, None, PlanMode::Snapshot).set;
        assert_eq!(published_sets.len(), 1);
        assert_eq!(
            published_clause(&published_sets[0]),
            Some(true),
            "published set exposes published records only"
        );

        let non_owner = CollectionAuthorization {
            visibility: VisibilityClass::NonOwner,
            author: Some(PLAN_AUTHOR.to_string()),
            protocol_authorized: false,
            grant_authorized: false,
        };
        let non_owner_sets = collection_filters(&non_owner, &filter, None, PlanMode::Snapshot).set;
        assert_eq!(
            non_owner_sets.len(),
            3,
            "non-owner without grant/role sees published plus author plus recipient sets"
        );
        assert!(non_owner_sets
            .iter()
            .any(|set| published_clause(set) == Some(true)));
        assert!(non_owner_sets.iter().any(|set| {
            set.get(&FilterKey::Index("author".to_string()))
                == Some(&Filter::Equal(Value::String(PLAN_AUTHOR.to_string())))
        }));
    }

    // Covers: DWN-REC-005
    #[test]
    fn snapshot_and_event_modes_differ_only_in_method_selection() {
        let owner = CollectionAuthorization {
            visibility: VisibilityClass::Owner,
            author: Some(PLAN_TENANT.to_string()),
            protocol_authorized: false,
            grant_authorized: false,
        };
        let filter = RecordsFilter::default();
        let snapshot = collection_filters(&owner, &filter, None, PlanMode::Snapshot).set;
        let event = collection_filters(&owner, &filter, None, PlanMode::Event).set;
        assert_eq!(snapshot.len(), 1);
        assert_eq!(event.len(), 1);

        assert_eq!(
            snapshot[0].get(&FilterKey::Index("method".to_string())),
            Some(&Filter::Equal(Value::String("Write".to_string()))),
            "snapshot selects latest writes only"
        );
        assert!(
            snapshot[0].contains_key(&FilterKey::Index("isLatestBaseState".to_string())),
            "snapshot is pinned to latest base state"
        );
        match event[0].get(&FilterKey::Index("method".to_string())) {
            Some(Filter::OneOf(methods)) => assert!(
                methods.contains(&Value::String("Write".to_string()))
                    && methods.contains(&Value::String("Delete".to_string())),
                "event selects writes and deletes, got {methods:?}"
            ),
            other => panic!("event must select writes and deletes, got {other:?}"),
        }
        assert!(
            !event[0].contains_key(&FilterKey::Index("isLatestBaseState".to_string())),
            "event delivery is not pinned to latest base state"
        );
    }

    // Covers: DWN-REC-001
    #[tokio::test]
    async fn owner_and_anonymous_agree_on_published_population() {
        let store = MemoryMessageStore::default();
        for (record_id, published) in [("published-record", true), ("private-record", false)] {
            let (message, indexes) = write_row(record_id, published);
            store
                .put(PLAN_TENANT, message, indexes)
                .await
                .expect("seed row must store");
        }
        let filter = RecordsFilter::default();

        let owner_ctx = auth_ctx(PLAN_TENANT);
        let (probe, _) = write_row("probe", true);
        let owner = authorize_collection(
            PLAN_TENANT,
            &probe,
            &filter,
            Some(&owner_ctx),
            &store,
            "2025-01-01T00:00:00.000000Z",
            RecordsAuthorizationKind::Query,
        )
        .await
        .expect("owner must authorize");
        assert_eq!(owner.visibility, VisibilityClass::Owner);
        let owner_filters = collection_filters(&owner, &filter, None, PlanMode::Snapshot);
        let owner_found = store
            .query(PLAN_TENANT, owner_filters.clone(), None, None, None)
            .await
            .expect("owner query must succeed");
        assert_eq!(owner_found.messages.len(), 2);
        let owner_count = store
            .count(PLAN_TENANT, owner_filters, None, None)
            .await
            .expect("owner count must succeed");
        assert_eq!(
            owner_count, 2,
            "count over the same plan must equal the query population"
        );

        let anonymous = authorize_collection(
            PLAN_TENANT,
            &probe,
            &filter,
            None,
            &store,
            "2025-01-01T00:00:00.000000Z",
            RecordsAuthorizationKind::Query,
        )
        .await
        .expect("anonymous published request must authorize");
        assert_eq!(anonymous.visibility, VisibilityClass::Published);
        let anon_found = store
            .query(
                PLAN_TENANT,
                collection_filters(&anonymous, &filter, None, PlanMode::Snapshot),
                None,
                None,
                None,
            )
            .await
            .expect("anonymous query must succeed");
        assert_eq!(
            anon_found.messages.len(),
            1,
            "anonymous sees published only"
        );
    }
}
