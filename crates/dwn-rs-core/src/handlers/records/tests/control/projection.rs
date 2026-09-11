//! One current audience per scope, across every collection surface.

use crate::handlers::records::subscribe::RecordsEventLogSubscribeHandler;

use super::*;

/// A third, so a role can be minted for more than twice over.
fn third_audience_key_jwk() -> JWK {
    serde_json::from_value(json!({
        "kty": "OKP", "crv": "X25519",
        "x": "CNSkk1wnrEbN3ZaX8JMCQxY-nVFpppoRuO3HCNXzJ2Y"
    }))
    .unwrap()
}

/// Attaches a signature to a raw message so the projection comparator can read
/// its actual signer.
async fn signed_as(
    mut message: serde_json::Value,
    signer: crate::auth::PrivateJwkSigner,
) -> Message<Descriptor> {
    let descriptor = message["descriptor"].clone();
    let signature = signature_for_descriptor(
        &descriptor,
        json!({
            "recordId": message["recordId"].as_str().unwrap(),
            "contextId": "",
        }),
        signer,
    )
    .await;
    message["authorization"] = json!({ "signature": signature });
    serde_json::from_value(message).expect("candidate fixture must deserialize")
}

fn projection_candidate(record_id: &str, date_created: &str) -> serde_json::Value {
    json!({
        "descriptor": {
            "interface": "Records", "method": "Write",
            "protocol": CONTROL_PROTOCOL, "protocolPath": AUDIENCE_PATH,
            "dataCid": "bafkreighhqlnlu3xumutodqyjeg6dkd6bhuhqydnemkjgoyn7eveukkfai",
            "dataSize": 0, "dataFormat": "application/json",
            "dateCreated": date_created,
            "messageTimestamp": date_created
        },
        "recordId": record_id
    })
}

// Covers: DWN-REC-004
// The current audience for a role is the one a real tenant signature vouches
// for, then the oldest, then the lowest record id — and that answer must not
// depend on the order candidates arrive in. Oldest-first is what makes a later
// flood of non-tenant audiences inert rather than letting the most recent
// writer take over a role.
#[tokio::test]
async fn the_current_audience_is_the_same_whatever_order_candidates_arrive_in() {
    // Three candidates spanning every dimension the comparator uses. The
    // tenant-signed one is deliberately the newest and last by id, so a winner
    // chosen on either of those would be visible.
    let candidates = [
        signed_as(
            projection_candidate(
                "zzz-newest-but-tenant-signed",
                "2025-06-01T00:00:00.000000Z",
            ),
            test_signer(),
        )
        .await,
        signed_as(
            projection_candidate("aaa-oldest", "2025-01-01T00:00:00.000000Z"),
            bob_signer(),
        )
        .await,
        signed_as(
            projection_candidate("bbb-same-date", "2025-01-01T00:00:00.000000Z"),
            bob_signer(),
        )
        .await,
    ];
    let ranks: Vec<_> = candidates
        .iter()
        .map(|message| {
            crate::handlers::records::control::projection::projection_rank(CONTROL_TENANT, message)
                .expect("every candidate ranks")
        })
        .collect();

    let winner = ranks
        .iter()
        .enumerate()
        .min_by(|(_, left), (_, right)| left.cmp(right))
        .unwrap()
        .0;
    assert_eq!(
        winner, 0,
        "an actual tenant signature outranks age and record id"
    );

    // Every arrival order agrees on the same winner.
    for permutation in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let chosen = permutation
            .iter()
            .map(|&index| (index, &ranks[index]))
            .min_by(|(_, left), (_, right)| left.cmp(right))
            .unwrap()
            .0;
        assert_eq!(
            chosen, winner,
            "arrival order {permutation:?} must not change the current audience"
        );
    }

    // Among non-tenant candidates the oldest wins, and a tie breaks on the
    // lower record id.
    assert_eq!(
        [&ranks[1], &ranks[2]].into_iter().min().unwrap(),
        &ranks[1],
        "oldest creation wins, so a later flood cannot take over the role"
    );
}

// Covers: DWN-REC-004, DWN-REC-005
// Collections show one current audience per role; direct Read still does not
// project. A caller that pinned a specific stored key by its full four-field
// identity keeps getting that key — it asked for a particular stored key, and
// answering with a different one would be wrong — while a three-field tuple
// names the role's directory and is projected.
#[tokio::test]
async fn collections_project_one_current_audience_but_exact_keys_bypass() {
    let fixture = control_fixture().await;

    // Two valid audiences for the same role. The older one is the current key.
    let older = admit_audience_signed(
        &fixture,
        &audience_key_jwk(),
        CONTROL_TENANT,
        test_signer(),
        "2025-01-01T00:01:00.000000Z",
        None,
    )
    .await;
    let newer = admit_audience_signed(
        &fixture,
        &other_audience_key_jwk(),
        CONTROL_TENANT,
        test_signer(),
        "2025-01-01T00:02:00.000000Z",
        None,
    )
    .await;

    let query_handler = RecordsQueryHandler::new(fixture.message_store.clone(), None);
    let count_handler = RecordsCountHandler::new(fixture.message_store.clone(), None);

    // A three-field tuple names the role's directory, so it is projected to one.
    let directory = signed_request(
        unsigned_query_message(exact_tuple_filter(None)),
        test_signer(),
        None,
    )
    .await;
    let reply = query_handler.run(CONTROL_TENANT, &directory, None).await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
    assert_eq!(
        reply.reply.entries.as_ref().map(Vec::len),
        Some(1),
        "two stored audiences project to one current audience"
    );

    // Count reports the same projected population, not the stored one.
    let directory_count = signed_request(
        unsigned_count_message(exact_tuple_filter(None)),
        test_signer(),
        None,
    )
    .await;
    let reply = count_handler
        .run(CONTROL_TENANT, &directory_count, None)
        .await;
    assert_eq!(
        reply.reply.count,
        Some(1),
        "Count must agree with Query: {}",
        reply.status.detail
    );

    // Pinning the whole identity bypasses projection, for either key.
    for (label, key_id) in [("current", &older), ("superseded", &newer)] {
        let exact = signed_request(
            unsigned_query_message(exact_tuple_filter(Some(key_id))),
            test_signer(),
            None,
        )
        .await;
        let reply = query_handler.run(CONTROL_TENANT, &exact, None).await;
        assert_eq!(
            reply.reply.entries.as_ref().map(Vec::len),
            Some(1),
            "a fully pinned {label} key must come back as asked: {}",
            reply.status.detail
        );
    }
}

// Covers: DWN-REC-005, DWN-REC-008
// A storage page is not a reply page. Projection removes superseded audiences,
// so filtering one storage page and returning would hand back a short page —
// here an empty one, because the only record on the first page is the one
// projection drops.
//
// The delegate's audience sorts first but loses the projection to the tenant's,
// which is what puts a non-current record alone on page one.
#[tokio::test]
async fn a_query_page_refills_past_records_projection_removed() {
    let fixture = control_fixture().await;
    let grant_id = issue_write_grant(&fixture, "member", "2025-01-01T00:00:30.000000Z").await;

    // Written first, by a delegate: ordered first, but never current.
    let delegate_key = admit_audience_signed(
        &fixture,
        &audience_key_jwk(),
        "did:example:bob",
        bob_signer(),
        "2025-01-01T00:01:00.000000Z",
        Some(&grant_id),
    )
    .await;
    // Written second, by the tenant: an actual tenant signature outranks age.
    let tenant_key = admit_audience_signed(
        &fixture,
        &other_audience_key_jwk(),
        CONTROL_TENANT,
        test_signer(),
        "2025-01-01T00:02:00.000000Z",
        None,
    )
    .await;

    let mut request = unsigned_query_message(exact_tuple_filter(None));
    request["descriptor"]["pagination"] = json!({ "limit": 1 });
    let query = signed_request(request, test_signer(), None).await;

    let query_handler = RecordsQueryHandler::new(fixture.message_store.clone(), None);
    let reply = query_handler.run(CONTROL_TENANT, &query, None).await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);

    let entries = reply.reply.entries.unwrap_or_default();
    assert_eq!(
        entries.len(),
        1,
        "the page must refill past the record projection removed rather than come back empty"
    );
    let returned = crate::descriptors::records::records_write_descriptor(
        &serde_json::from_value::<Message<Descriptor>>(serde_json::to_value(&entries[0]).unwrap())
            .unwrap(),
    )
    .unwrap()
    .tags
    .as_ref()
    .and_then(|tags| tags.get("keyId"))
    .cloned();
    assert_eq!(
        returned,
        Some(Value::String(tenant_key)),
        "the refilled page must hold the current audience, not the delegate's"
    );
    assert_ne!(
        returned,
        Some(Value::String(delegate_key)),
        "the superseded audience must not be what filled the page"
    );
}

// Covers: DWN-REC-005, ENBOX-ENC-003
// A broad Count must report the population Query would return. Counting through
// the store would include superseded audiences and deliveries the requester
// cannot read, so a protocol-wide count needs the same passes a control-only
// one gets.
#[tokio::test]
async fn a_protocol_wide_count_agrees_with_query() {
    const RECIPIENT: &str = "did:example:bob";
    let fixture = control_fixture().await;

    // Two audiences for one role (one superseded) plus a delivery to Bob.
    admit_audience_signed(
        &fixture,
        &audience_key_jwk(),
        CONTROL_TENANT,
        test_signer(),
        "2025-01-01T00:01:00.000000Z",
        None,
    )
    .await;
    let key_id = admit_audience_signed(
        &fixture,
        &other_audience_key_jwk(),
        CONTROL_TENANT,
        test_signer(),
        "2025-01-01T00:02:00.000000Z",
        None,
    )
    .await;
    grant_member_role(
        &fixture.message_store,
        RECIPIENT,
        "2025-01-01T00:03:00.000000Z",
    )
    .await;
    let ciphertext = Bytes::from_static(b"sealed key material");
    let delivery = control_write(
        DELIVERY_PATH,
        delivery_tags("member", "", &key_id, "roleHolder"),
        &ciphertext,
        "2025-01-01T00:04:00.000000Z",
        |spec| {
            spec.recipient = Some(RECIPIENT.to_string());
            spec.encryption = Some(delivery_envelope());
        },
    )
    .await;
    assert_eq!(
        fixture
            .handler
            .run(CONTROL_TENANT, &delivery, Some(ciphertext))
            .await
            .status
            .code,
        202
    );

    let query_handler = RecordsQueryHandler::new(fixture.message_store.clone(), None);
    let count_handler = RecordsCountHandler::new(fixture.message_store.clone(), None);

    // A protocol-wide request, pinning no path at all.
    let broad = json!({ "protocol": CONTROL_PROTOCOL });
    for (label, signer) in [
        ("an unrelated requester", signer_for("did:example:mallory")),
        ("the tenant", test_signer()),
    ] {
        let query =
            signed_request(unsigned_query_message(broad.clone()), signer.clone(), None).await;
        let counted = signed_request(unsigned_count_message(broad.clone()), signer, None).await;

        let query_reply = query_handler.run(CONTROL_TENANT, &query, None).await;
        let count_reply = count_handler.run(CONTROL_TENANT, &counted, None).await;
        let visible = query_reply
            .reply
            .entries
            .as_ref()
            .map(Vec::len)
            .unwrap_or(0) as u64;

        assert_eq!(
            count_reply.reply.count,
            Some(visible),
            "{label}: Count must report the population Query returns, got {:?} vs {visible}: {}",
            count_reply.reply.count,
            count_reply.status.detail
        );
    }
}

// Covers: DWN-REC-005
// Selection ranks over the whole stored scope, independently of the caller's
// filters — but the winner it picks is then *intersected* with those filters,
// never injected past them. A caller narrowing to one key must not be handed a
// different key merely because that one is current.
#[tokio::test]
async fn projection_never_injects_a_winner_the_caller_filtered_out() {
    let fixture = control_fixture().await;

    // The older key wins the projection.
    let current = admit_audience_signed(
        &fixture,
        &audience_key_jwk(),
        CONTROL_TENANT,
        test_signer(),
        "2025-01-01T00:01:00.000000Z",
        None,
    )
    .await;
    let superseded = admit_audience_signed(
        &fixture,
        &other_audience_key_jwk(),
        CONTROL_TENANT,
        test_signer(),
        "2025-01-01T00:02:00.000000Z",
        None,
    )
    .await;

    let query_handler = RecordsQueryHandler::new(fixture.message_store.clone(), None);

    // Pinning the superseded key returns exactly it: the projection bypass
    // applies, and the current key is not substituted.
    let pinned = signed_request(
        unsigned_query_message(exact_tuple_filter(Some(&superseded))),
        test_signer(),
        None,
    )
    .await;
    let reply = query_handler.run(CONTROL_TENANT, &pinned, None).await;
    let returned = returned_key_ids(&reply);
    assert_eq!(
        returned,
        vec![superseded.clone()],
        "a pinned key must come back as asked, not replaced by the current one"
    );
    assert!(
        !returned.contains(&current),
        "the projection winner must never be injected past the caller's filter"
    );
}

fn returned_key_ids(reply: &crate::Response<crate::replies::records::Query>) -> Vec<String> {
    reply
        .reply
        .entries
        .as_ref()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| {
                    let message: Message<Descriptor> =
                        serde_json::from_value(serde_json::to_value(entry).ok()?).ok()?;
                    match crate::descriptors::records::records_write_descriptor(&message)
                        .ok()?
                        .tags
                        .as_ref()?
                        .get("keyId")?
                    {
                        Value::String(key_id) => Some(key_id.clone()),
                        _ => None,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

// Covers: DWN-REC-005, ENBOX-ENC-003
// Visibility is applied inside the collection, not after it, so a page whose
// storage slice holds nothing the requester may see must keep scanning rather
// than hand back a short page. Here every record before the requester's own
// delivery is addressed to someone else: a page that stopped at the storage
// slice would come back empty and the reader would conclude there was nothing.
#[tokio::test]
async fn query_pages_refill_past_deliveries_the_requester_cannot_see() {
    const READER: &str = "did:example:bob";
    let fixture = control_fixture().await;
    let key_id = fixture.audience_key_id.clone();
    admit_audience(&fixture, &key_id, "2025-01-01T00:01:00.000000Z").await;

    // One audience key, delivered to each role holder in turn — the ordinary
    // shape. The requester's own delivery is written last, so it sits behind
    // every hidden one in ascending order.
    let ciphertext = Bytes::from_static(b"sealed key material");
    for (index, recipient) in [
        "did:example:carol",
        "did:example:dave",
        "did:example:erin",
        READER,
    ]
    .into_iter()
    .enumerate()
    {
        let timestamp = format!("2025-01-01T00:0{}:00.000000Z", index + 2);
        grant_member_role(&fixture.message_store, recipient, &timestamp).await;
        let delivery = control_write(
            DELIVERY_PATH,
            delivery_tags("member", "", &key_id, "roleHolder"),
            &ciphertext,
            &timestamp,
            |spec| {
                spec.recipient = Some(recipient.to_string());
                spec.encryption = Some(delivery_envelope());
            },
        )
        .await;
        let reply = fixture
            .handler
            .run(CONTROL_TENANT, &delivery, Some(ciphertext.clone()))
            .await;
        assert_eq!(
            reply.status.code, 202,
            "every delivery must be admitted, or the page proves nothing: {}",
            reply.status.detail
        );
    }

    let query_handler = RecordsQueryHandler::new(fixture.message_store.clone(), None);
    let mut cursor: Option<serde_json::Value> = None;
    let mut seen = Vec::new();
    // One record per page, so the requester's delivery can only arrive by the
    // page refilling past the three it may not see.
    for round in 0..4 {
        let mut request = unsigned_query_message(json!({
            "protocol": CONTROL_PROTOCOL,
            "protocolPath": DELIVERY_PATH,
        }));
        request["descriptor"]["pagination"] = match &cursor {
            Some(cursor) => json!({ "limit": 1, "cursor": cursor }),
            None => json!({ "limit": 1 }),
        };
        let query = signed_request(request, signer_for(READER), None).await;
        let reply = query_handler.run(CONTROL_TENANT, &query, None).await;
        assert_eq!(reply.status.code, 200, "{}", reply.status.detail);

        let entries = reply.reply.entries.clone().unwrap_or_default();
        if round == 0 {
            assert_eq!(
                entries.len(),
                1,
                "the first page must refill past the hidden deliveries rather than come back empty"
            );
        }
        for entry in &entries {
            let message: Message<Descriptor> =
                serde_json::from_value(serde_json::to_value(entry).unwrap()).unwrap();
            seen.push(
                crate::descriptors::records::records_write_descriptor(&message)
                    .unwrap()
                    .recipient
                    .clone(),
            );
        }
        cursor = reply
            .reply
            .cursor
            .as_ref()
            .map(|cursor| serde_json::to_value(cursor).unwrap());
        if cursor.is_none() {
            break;
        }
    }

    assert_eq!(
        seen,
        vec![Some(READER.to_string())],
        "paging must surface exactly the requester's own delivery, once, and no other recipient's"
    );
}

// Covers: DWN-REC-005, DWN-REC-008
// A subscription is a live query, so an audience must stop being disclosed the
// moment it stops being current — the projection is re-run at delivery, not
// frozen at open. Here the stream opens while a delegate's audience is the only
// one for the role; the tenant's own later mint takes the role over and is
// delivered, and the delegate's next mint arrives already superseded and is
// suppressed without ending the stream.
#[tokio::test]
async fn a_live_audience_is_disclosed_only_while_it_is_the_current_one() {
    let wake_bus = InProcessWakeBus::new();
    let fixture =
        control_fixture_on(MemoryMessageStore::default().with_waker_publisher(wake_bus.clone()))
            .await;
    let grant_id = issue_write_grant(&fixture, "member", "2025-01-01T00:00:30.000000Z").await;

    // Bob mints first: with no tenant audience for the role, his is current.
    admit_audience_signed(
        &fixture,
        &audience_key_jwk(),
        "did:example:bob",
        bob_signer(),
        "2025-01-01T00:01:00.000000Z",
        Some(&grant_id),
    )
    .await;

    let event_log = DurableEventLog::new(fixture.message_store.clone(), wake_bus, None, None);
    let delivered = Arc::new(RwLock::new(Vec::new()));
    let delivered_for_listener = delivered.clone();
    let handler = RecordsEventLogSubscribeHandler::new(
        fixture.message_store.clone(),
        event_log,
        Some(Arc::new(test_resolver())),
    );
    // The three-field scope: a role's directory, which is projected. Pinning
    // the key id instead would bypass projection and prove nothing.
    let request = signed_records_subscribe_message(
        RecordsFilter {
            protocol: Some(CONTROL_PROTOCOL.to_string()),
            protocol_path: Some(AUDIENCE_PATH.to_string()),
            tags: Some(BTreeMap::from([
                (
                    "protocol".to_string(),
                    Filter::Equal(Value::String(CONTROL_PROTOCOL.to_string())),
                ),
                (
                    "rolePath".to_string(),
                    Filter::Equal(Value::String("member".to_string())),
                ),
                (
                    "contextId".to_string(),
                    Filter::Equal(Value::String(String::new())),
                ),
            ])),
            ..Default::default()
        },
        None,
        "2025-01-01T00:10:00.000000Z",
    )
    .await;
    let result = handler
        .handle_subscribe(
            CONTROL_TENANT,
            &request,
            Box::new(move |message| delivered_for_listener.write().unwrap().push(message)),
        )
        .await;
    assert_eq!(
        result.reply.status.code, 200,
        "{}",
        result.reply.status.detail
    );
    assert_eq!(
        result.reply.reply.entries.as_ref().map(Vec::len),
        Some(1),
        "the snapshot holds the delegate's audience while it is the only one"
    );

    // The tenant's own mint: an actual tenant signature outranks age, so this
    // becomes current and must be delivered.
    admit_audience_signed(
        &fixture,
        &other_audience_key_jwk(),
        CONTROL_TENANT,
        test_signer(),
        "2025-01-01T00:11:00.000000Z",
        None,
    )
    .await;
    for _ in 0..500 {
        if !delivered.read().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        delivered.read().unwrap().len(),
        1,
        "the audience that took the role over must be delivered live"
    );

    // A third mint by the delegate arrives already superseded: suppressed, and
    // the stream stays open rather than failing.
    admit_audience_signed(
        &fixture,
        &third_audience_key_jwk(),
        "did:example:bob",
        bob_signer(),
        "2025-01-01T00:12:00.000000Z",
        Some(&grant_id),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let delivered = delivered.read().unwrap();
    assert_eq!(
        delivered.len(),
        1,
        "an audience that is no longer current must not be disclosed live"
    );
    assert!(
        matches!(delivered[0], SubscriptionMessage::Event { .. }),
        "the stream must stay live, not close"
    );
}
