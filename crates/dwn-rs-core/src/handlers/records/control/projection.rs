use super::visibility::{names_record, pins_audience_key};
use crate::canonical_rfc3339;
use crate::permissions::message_signer;

use super::*;

/// Where a candidate ranks as the current audience for its scope.
///
/// A real tenant signature outranks everything, then the oldest creation, then
/// the lowest record id. Tenant priority is by *actual signer*: a delegated
/// mint and an owner countersignature do not borrow it, which is what stops a
/// delegate from installing a current key the tenant never signed for. Oldest
/// rather than newest is deliberate — it makes a later flood of non-tenant
/// audiences inert instead of letting the most recent writer take over a role.
pub(crate) fn projection_rank(
    tenant: &str,
    record: &Message<Descriptor>,
) -> Option<(bool, String, String)> {
    let descriptor = records_write_descriptor(record).ok()?;
    Some((
        message_signer(record)? != tenant,
        canonical_rfc3339(descriptor.date_created),
        record_id(record)?,
    ))
}

/// The record id of the audience currently representing `scope`.
///
/// Ranks over every stored audience in the scope rather than the page in hand,
/// so the winner does not depend on the caller's filters, sort or pagination.
async fn current_audience_record_id<MessageStore>(
    tenant: &str,
    scope: &AudienceScope,
    message_store: &MessageStore,
) -> Result<Option<String>, ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let mut filter = filter_map([
        ("interface", string_filter(RECORDS_INTERFACE)),
        ("method", string_filter(WRITE_METHOD)),
        ("protocol", string_filter(&scope.protocol)),
        (
            "protocolPath",
            string_filter(ControlKind::Audience.protocol_path()),
        ),
        ("isLatestBaseState", bool_filter(true)),
    ]);
    for (tag, value) in [
        ("protocol", scope.protocol.as_str()),
        ("rolePath", scope.role_path.as_str()),
        ("contextId", scope.context_id.as_str()),
    ] {
        filter.insert(FilterKey::Index(format!("tag.{tag}")), string_filter(value));
    }

    let stored = message_store
        .query(tenant, Filters::from(filter), None, None, None)
        .await
        .map_err(|error| ControlValidationError::Internal(error.to_string()))?;

    Ok(stored
        .messages
        .iter()
        .filter_map(|record| projection_rank(tenant, record).map(|rank| (rank, record)))
        .min_by(|(left, _), (right, _)| left.cmp(right))
        .and_then(|(_, record)| record_id(record)))
}

/// Narrows a page of records to one current audience per scope.
///
/// Only audiences are projected; deliveries are addressed key material and each
/// one stands alone. A caller that named a record by id, or pinned its whole
/// four-field identity, bypasses projection entirely — that caller asked for a
/// specific stored key, and answering with a different one would be wrong. A
/// three-field tuple names a role's directory, not a record, so it does not
/// bypass.
///
/// Selection never injects: a winner that fails the caller's own filters was
/// not in the page and does not join it here.
pub(crate) async fn project_current_audiences<MessageStore>(
    tenant: &str,
    filter: Option<&RecordsFilter>,
    records: Vec<Message<Descriptor>>,
    message_store: &MessageStore,
) -> Result<Vec<Message<Descriptor>>, ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    // Identify which records are subject to projection at all, keeping each
    // one's decision beside it so the second pass re-derives nothing.
    let mut projected_scopes = BTreeSet::new();
    let subject: Vec<Option<AudienceScope>> = records
        .iter()
        .map(|record| {
            if ControlKind::of(record) != Some(ControlKind::Audience) {
                return None;
            }
            let id = AudienceId::from_message(record, ControlKind::Audience).ok()?;
            let bypassed = filter.is_some_and(|filter| {
                names_record(filter, record) || pins_audience_key(filter, &id)
            });
            if bypassed {
                return None;
            }
            projected_scopes.insert(id.scope.clone());
            Some(id.scope)
        })
        .collect();

    if projected_scopes.is_empty() {
        return Ok(records);
    }

    let mut current = BTreeMap::new();
    for scope in projected_scopes {
        let winner = current_audience_record_id(tenant, &scope, message_store).await?;
        current.insert(scope, winner);
    }

    Ok(records
        .into_iter()
        .zip(subject)
        .filter(|(record, scope)| match scope {
            // Not an audience, or exempt from projection.
            None => true,
            Some(scope) => {
                current.get(scope).and_then(Option::as_ref) == record_id(record).as_ref()
            }
        })
        .map(|(record, _)| record)
        .collect())
}

/// Fetches storage pages until the caller's visible limit is met or the store
/// is exhausted, applying projection and control visibility to each.
///
/// A storage page is not a reply page. Projection drops superseded audiences
/// and visibility drops control records the requester may not see, so filtering
/// one storage page and returning would hand back a short page — or an empty
/// one — while the records that belong in it sit on the next page. A caller
/// asking for one record, newest first, would see nothing at all when the
/// newest candidate happens to be superseded.
///
/// Each refill asks for only the capacity still unfilled, which is what keeps
/// the page and its cursor in step. Asking for the full limit again and
/// trimming the surplus would be silent data loss: the trimmed records sit
/// before the cursor this returns, so continuing the query skips them and no
/// caller can ever reach them.
///
/// The returned cursor is the last storage page's, so a caller resumes after
/// everything actually examined rather than re-reading what was filtered out.
pub(crate) async fn collect_visible_page<MessageStore, Fetch, Fut>(
    tenant: &str,
    request: &Message<Descriptor>,
    signature: Option<&AuthorizationContext>,
    filter: &RecordsFilter,
    limit: Option<u64>,
    message_store: &MessageStore,
    mut fetch: Fetch,
) -> Result<(Vec<Message<Descriptor>>, Option<Cursor>), ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
    // The remaining visible capacity, so each refill asks for what it still
    // needs rather than for the whole page again.
    Fetch: FnMut(Option<Cursor>, Option<u64>) -> Fut,
    Fut: std::future::Future<Output = Result<(Vec<Message<Descriptor>>, Option<Cursor>), String>>,
{
    let mut visible: Vec<Message<Descriptor>> = Vec::new();
    let mut cursor = None;

    loop {
        let remaining = limit.map(|limit| limit.saturating_sub(visible.len() as u64));
        let (page, next) = fetch(cursor.clone(), remaining)
            .await
            .map_err(ControlValidationError::Internal)?;
        let exhausted = page.is_empty() || next.is_none();
        cursor = next;

        let projected =
            project_current_audiences(tenant, Some(filter), page, message_store).await?;
        visible.extend(
            filter_visible_controls(
                tenant,
                request,
                signature,
                Some(filter),
                projected,
                message_store,
            )
            .await?,
        );

        match limit {
            // Never overshoots: each fetch asked for exactly the capacity left,
            // and projection and visibility only remove.
            Some(limit) if (visible.len() as u64) < limit && !exhausted => continue,
            Some(_) => return Ok((visible, cursor)),
            None if exhausted => return Ok((visible, cursor)),
            None => continue,
        }
    }
}
