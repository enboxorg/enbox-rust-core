use super::*;

/// Lifecycle rules shared by both control kinds.
///
/// Immutability is checked as "is this an initial write" rather than "does a
/// previous version exist": an update that arrives before its initial write
/// must be refused on its own terms.
fn validate_lifecycle(
    message: &Message<Descriptor>,
    author: &str,
) -> Result<(), ControlValidationError> {
    let descriptor =
        records_write_descriptor(message).map_err(|error| unexpected(error.to_string()))?;

    if !is_initial_write(message, author).map_err(&unexpected)? {
        return Err(unexpected("encryption control records are immutable"));
    }
    if descriptor.published == Some(true) {
        return Err(unexpected(
            "encryption control records must not be published",
        ));
    }
    if descriptor.data_size > MAX_CONTROL_DATA_SIZE {
        return Err(unexpected(format!(
            "encryption control records must be at most {MAX_CONTROL_DATA_SIZE} bytes, got {}",
            descriptor.data_size
        )));
    }
    Ok(())
}

/// Referential admission: everything decidable before the record's data is in
/// hand, and before the writer's authority is considered.
///
/// Failures here are referential — the record points at something that is not
/// there, or is not what it claims — and are reported as bad requests.
/// Authorization failures are a separate stage precisely so a writer cannot
/// learn what exists by watching which error it gets.
pub(crate) async fn validate_referential_integrity<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    kind: ControlKind,
    author: &str,
    message_store: &MessageStore,
) -> Result<(), ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    validate_lifecycle(message, author)?;

    let descriptor =
        records_write_descriptor(message).map_err(|error| unexpected(error.to_string()))?;
    let id = AudienceId::from_message(message, kind)?;
    let timestamp = crate::canonical_rfc3339(descriptor.message_timestamp);
    resolve_role_audience_definition(tenant, &id, &timestamp, message_store).await?;

    let fields = write_fields(message).map_err(|error| unexpected(error.to_string()))?;
    match kind {
        ControlKind::Audience => {
            // An audience publishes a public key and an owner seal. Both are
            // meant to be readable by the node, so an envelope would only hide
            // what admission has to check.
            if fields.encryption.is_some() {
                return Err(unexpected("audience control records must be plaintext"));
            }
        }
        ControlKind::Delivery => {
            // A delivery hands a private key to one recipient, so it is always
            // encrypted and always addressed. Its ciphertext is never opened
            // here: admission inspects the public metadata only.
            if fields.encryption.is_none() {
                return Err(unexpected("delivery control records must be encrypted"));
            }
            let Some(recipient) = descriptor.recipient.as_deref() else {
                return Err(control_error(
                    DwnErrorCode::EncryptionControlValidateDeliveryRecipientMissing,
                    "delivery control records must have a recipient",
                ));
            };
            validate_delivery_references(tenant, message, &id, recipient, message_store).await?;
        }
    }
    Ok(())
}

/// A delivery must reference a stored audience and go to a current role holder.
///
/// The audience lookup is by the whole four-field identity, key id included, so
/// a delivery of a superseded key still resolves: the key stops being *current*
/// without ceasing to exist, and recipients who were sent it keep needing it.
async fn validate_delivery_references<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    id: &AudienceId,
    recipient: &str,
    message_store: &MessageStore,
) -> Result<(), ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let authority = required_string_tag(message, "recipientAuthority", ControlKind::Delivery)?;
    if authority != RECIPIENT_AUTHORITY_ROLE_HOLDER {
        return Err(control_error(
            DwnErrorCode::EncryptionControlValidateDeliveryRecipientAuthorityInvalid,
            format!("unsupported delivery recipient authority '{authority}'"),
        ));
    }

    if !stored_audience_exists(tenant, id, message_store).await? {
        return Err(control_error(
            DwnErrorCode::EncryptionControlValidateDeliveryAudienceMissing,
            "delivery control record references a missing audience",
        ));
    }

    let holds_role = role_record_exists(
        tenant,
        recipient,
        &id.scope.protocol,
        &id.scope.role_path,
        Some(id.scope.context_id.as_str()),
        message_store,
    )
    .await
    .map_err(&unexpected)?;
    if !holds_role {
        return Err(control_error(
            DwnErrorCode::EncryptionControlValidateDeliveryRecipientRoleRecordMissing,
            "delivery recipient does not hold the referenced role",
        ));
    }
    Ok(())
}

/// Whether an audience with this exact identity is retained.
pub(crate) async fn stored_audience_exists<MessageStore>(
    tenant: &str,
    id: &AudienceId,
    message_store: &MessageStore,
) -> Result<bool, ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let mut filter = filter_map([
        ("interface", string_filter(RECORDS_INTERFACE)),
        ("method", string_filter(WRITE_METHOD)),
        ("protocol", string_filter(&id.scope.protocol)),
        (
            "protocolPath",
            string_filter(ControlKind::Audience.protocol_path()),
        ),
        ("isLatestBaseState", bool_filter(true)),
    ]);
    for (tag, value) in [
        ("protocol", id.scope.protocol.as_str()),
        ("rolePath", id.scope.role_path.as_str()),
        ("contextId", id.scope.context_id.as_str()),
        ("keyId", id.key_id.as_str()),
    ] {
        // Tags index as `tag.<name>`, the same shape
        // `records_filter_to_filter_map` builds for caller tag filters.
        filter.insert(FilterKey::Index(format!("tag.{tag}")), string_filter(value));
    }
    let result = message_store
        .query(
            tenant,
            Filters::from(filter),
            None,
            Some(Pagination::with_limit(1)),
            None,
        )
        .await
        .map_err(|error| unexpected(error.to_string()))?;
    Ok(!result.messages.is_empty())
}

/// Payload validation, once the record's data is available.
///
/// A delivery's ciphertext is deliberately not decrypted or parsed: node
/// admission has no private key and must not need one, so the producer's
/// payload format imposes nothing here.
pub(crate) async fn validate_payload<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    kind: ControlKind,
    data: &[u8],
    message_store: &MessageStore,
) -> Result<(), ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    if kind == ControlKind::Delivery {
        return Ok(());
    }

    let descriptor =
        records_write_descriptor(message).map_err(|error| unexpected(error.to_string()))?;
    let id = AudienceId::from_message(message, kind)?;
    let payload = AudiencePayload::parse(data)?;

    if payload.claimed_id() != id {
        return Err(control_error(
            DwnErrorCode::EncryptionControlValidateAudienceTagsMismatch,
            "audience tags must match payload fields",
        ));
    }
    payload.verify_key_id()?;

    let timestamp = crate::canonical_rfc3339(descriptor.message_timestamp);
    let role = resolve_role_audience_definition(tenant, &id, &timestamp, message_store).await?;
    let role_key = role
        .rule_set
        .key_agreement
        .as_ref()
        .map(|agreement| &agreement.public_key_jwk)
        .ok_or_else(|| {
            control_error(
                DwnErrorCode::EncryptionControlValidateAudienceRolePathInvalid,
                "governing role has no $keyAgreement",
            )
        })?;
    payload.verify_seal_key_id(role_key)?;
    Ok(())
}
