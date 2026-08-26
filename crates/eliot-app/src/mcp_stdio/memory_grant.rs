//! Opaque memory offers for a bound task session.
//!
//! An offer is durably committed before it is returned. That is not a
//! delivery claim. The same authenticated task session returning the signed
//! token in `eliot_task_action_request` is the acknowledgement. Redemption is
//! appended to the TaskContract in the same revision-CAS transaction as the
//! consuming action, so a failed transition cannot burn a token.

use super::*;

const MEMORY_GRANT_TOKEN_PREFIX: &str = "mg1";
const MEMORY_GRANT_TTL_MINUTES: i64 = 15;

pub(super) fn experience_prior_record_ref(index: usize, prior: &ExperienceBrief) -> String {
    format!("experience-prior:{index}:{}", prior.essence)
}

pub(super) fn memory_grant_prior_fingerprint(prior: &ExperienceBrief) -> Result<String> {
    canonical_struct_hash(prior)
}

pub(super) fn memory_grant_guidance_hash(prior: &ExperienceBrief) -> Result<String> {
    canonical_struct_hash(&json!({
        "essence": prior.essence,
        "underlying_mechanism": prior.underlying_mechanism,
        "why_it_may_apply": prior.why_it_may_apply,
        "why_it_may_not_apply": prior.why_it_may_not_apply,
        "current_mismatches": prior.current_mismatches,
        "required_local_check": prior.required_local_check,
        "recommended_first_probe": prior.recommended_first_probe,
        "forbidden_direct_inference": prior.forbidden_direct_inference,
        "maturity_and_authority": prior.maturity_and_authority,
    }))
}

fn memory_grant_mac_input(offer: &MemoryGrantOfferRecord) -> Result<String> {
    canonical_struct_hash(&json!({
        "domain": MEMORY_DELIVERY_GRANT_SCHEMA_VERSION,
        "grant_id": offer.grant_id,
        "project_id": offer.project_id,
        "task_id": offer.task_id,
        "session_id": offer.session_id,
        "packet_id": offer.packet_id,
        "packet_revision_fence": offer.packet_revision_fence,
        "task_memory_revision": offer.task_memory_revision,
        "task_contract_ref": offer.task_contract_ref,
        "auth_generation": offer.auth_generation,
        "prior_fingerprint": offer.prior_fingerprint,
        "guidance_hash": offer.guidance_hash,
        "offer_write_id": offer.offer_write_id,
        "expires_at_unix": offer.expires_at.unix_timestamp(),
    }))
}

fn memory_grant_token(offer: &MemoryGrantOfferRecord, signing_key: &[u8; 32]) -> Result<String> {
    let mac_input = memory_grant_mac_input(offer)?;
    let mac = blake3::keyed_hash(signing_key, mac_input.as_bytes())
        .to_hex()
        .to_string();
    Ok(format!(
        "{MEMORY_GRANT_TOKEN_PREFIX}:{}:{}:{mac}",
        offer.grant_id,
        offer.expires_at.unix_timestamp()
    ))
}

fn constant_time_text_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

struct ParsedMemoryGrantToken<'a> {
    grant_id: &'a str,
    expires_at_unix: i64,
    mac: &'a str,
}

fn parse_memory_grant_token(token: &str) -> Result<ParsedMemoryGrantToken<'_>> {
    let parts = token.split(':').collect::<Vec<_>>();
    anyhow::ensure!(
        parts.len() == 4 && parts[0] == MEMORY_GRANT_TOKEN_PREFIX,
        "memory grant token has an invalid wire shape"
    );
    uuid::Uuid::parse_str(parts[1]).context("memory grant token has an invalid grant id")?;
    anyhow::ensure!(
        parts[3].len() == 64 && parts[3].bytes().all(|byte| byte.is_ascii_hexdigit()),
        "memory grant token has an invalid MAC"
    );
    Ok(ParsedMemoryGrantToken {
        grant_id: parts[1],
        expires_at_unix: parts[2]
            .parse::<i64>()
            .context("memory grant token has an invalid expiry")?,
        mac: parts[3],
    })
}

pub(super) fn memory_grant_ids_from_tokens(tokens: &[String]) -> Result<BTreeSet<String>> {
    let mut grant_ids = BTreeSet::new();
    for token in tokens {
        let parsed = parse_memory_grant_token(token)?;
        anyhow::ensure!(
            grant_ids.insert(parsed.grant_id.to_owned()),
            "opaque memory grant tokens must resolve to unique grant ids"
        );
    }
    Ok(grant_ids)
}

async fn issue_memory_grant_offer(
    state: &McpState,
    context: AuthenticatedRequestContext,
    task: &TaskContract,
    packet: &CanonicalPacketRefs,
    prior: &ExperienceBrief,
) -> Result<(String, MemoryGrantOfferRecord)> {
    let grant_uuid = uuid::Uuid::now_v7();
    let grant_id = grant_uuid.to_string();
    let offer_write_id = WriteId::from_uuid(grant_uuid);
    let offered_at = time::OffsetDateTime::now_utc();
    let expires_at = offered_at + time::Duration::minutes(MEMORY_GRANT_TTL_MINUTES);
    let mut offer = MemoryGrantOfferRecord {
        schema_version: MEMORY_DELIVERY_GRANT_SCHEMA_VERSION.to_owned(),
        grant_id: grant_id.clone(),
        project_id: task.project_id,
        task_id: task.task_id,
        session_id: context.session_id,
        packet_id: packet.packet_id.clone(),
        packet_revision_fence: packet.packet_revision_fence,
        task_memory_revision: task.memory_revision,
        task_contract_ref: packet.task_contract_ref.clone(),
        auth_generation: state.auth_generation.clone(),
        prior_fingerprint: memory_grant_prior_fingerprint(prior)?,
        guidance_hash: memory_grant_guidance_hash(prior)?,
        offer_write_id,
        token_hash: String::new(),
        expires_at,
        offered_at,
    };
    let token = memory_grant_token(&offer, &state.memory_grant_signing_key)?;
    offer.token_hash = blake3::hash(token.as_bytes()).to_hex().to_string();
    let input_hash = canonical_struct_hash(&offer)?;
    let receipt = state
        .writer
        .submit_observability(ObservabilityWriteEnvelope {
            schema_version: OBSERVABILITY_SCHEMA_VERSION.to_owned(),
            write_id: offer_write_id,
            project_id: task.project_id,
            task_id: Some(task.task_id),
            session_id: Some(context.session_id),
            kind: ObservabilityKind::MemoryGrantOffer,
            record_id: grant_id,
            payload: serde_json::to_value(&offer)?,
            input_hash: input_hash.clone(),
            created_at: offered_at,
        })
        .await?;
    anyhow::ensure!(
        receipt.kind == ObservabilityKind::MemoryGrantOffer
            && receipt.write_id == offer_write_id
            && receipt.input_hash == input_hash
            && matches!(
                receipt.status,
                ObservabilityWriteStatus::Committed | ObservabilityWriteStatus::IdempotentReplay
            ),
        "memory grant offer did not commit with the expected identity"
    );
    Ok((token, offer))
}

pub(super) async fn attach_memory_grant_offers(
    state: &McpState,
    context: AuthenticatedRequestContext,
    request: &OperatorQueryRequest,
    snapshot: &OperatorSnapshot,
    records: &mut [OperatorRecordView],
) -> Result<()> {
    if state.profile != McpAccessProfile::CodexController
        || request.projection != OperatorProjectionKind::TaskCognition
    {
        return Ok(());
    }
    let (Some(bound_project_id), Some(bound_task_id)) =
        (context.bound_project_id, context.bound_task_id)
    else {
        return Ok(());
    };
    anyhow::ensure!(
        request.project_id == Some(bound_project_id) && request.task_id == Some(bound_task_id),
        "opaque memory offers require the exact Governor-bound project and task"
    );
    let view = snapshot
        .task_cognition
        .iter()
        .find(|view| view.task_contract.task_id == bound_task_id)
        .context("bound task cognition is unavailable for opaque memory offers")?;
    let packet = canonical_packet_refs(state, &view.task_contract)?;
    let priors = view
        .experience_priors
        .iter()
        .enumerate()
        .map(|(index, prior)| (experience_prior_record_ref(index, prior), prior))
        .collect::<BTreeMap<_, _>>();

    for record in records
        .iter_mut()
        .filter(|record| record.record_kind == "experience_brief")
    {
        let prior = priors
            .get(&record.record_ref)
            .context("operator experience record does not map to the active private prior")?;
        let fingerprint = memory_grant_prior_fingerprint(prior)?;
        let guidance_hash = memory_grant_guidance_hash(prior)?;
        anyhow::ensure!(
            packet.experience_prior_guidance.get(&fingerprint) == Some(&guidance_hash),
            "operator experience prior is stale or absent from active packet authority"
        );
        let (token, offer) =
            issue_memory_grant_offer(state, context, &view.task_contract, &packet, prior).await?;
        record.fields.extend([
            operator::operator_field("memory_grant_token", token, true),
            operator::operator_field("memory_grant_expires_at", offer.expires_at, false),
            operator::operator_field(
                "memory_grant_evidence_ceiling",
                "offered_until_same_session_action_request_returns_token",
                false,
            ),
        ]);
    }
    Ok(())
}

pub(super) async fn resolve_memory_grant_ref(
    state: &McpState,
    project_id: ProjectId,
    task: &TaskContract,
    session_id: SessionId,
    token: &str,
    packet: &CanonicalPacketRefs,
    redeemed_at: time::OffsetDateTime,
) -> Result<ActionMemoryGrantRef> {
    let parsed = parse_memory_grant_token(token)?;
    let offer = state
        .store
        .memory_grant_offer_by_id(project_id, task.task_id, session_id, parsed.grant_id)
        .await?
        .context("memory grant offer does not resolve in the authenticated task session")?;
    anyhow::ensure!(
        offer.schema_version == MEMORY_DELIVERY_GRANT_SCHEMA_VERSION
            && offer.project_id == project_id
            && offer.task_id == task.task_id
            && offer.session_id == session_id
            && offer.grant_id == parsed.grant_id
            && offer.offer_write_id.as_uuid() == uuid::Uuid::parse_str(parsed.grant_id)?,
        "memory grant offer identity is invalid"
    );
    anyhow::ensure!(
        offer.packet_id == packet.packet_id
            && offer.packet_revision_fence == packet.packet_revision_fence
            && offer.task_memory_revision == task.memory_revision
            && offer.task_contract_ref == packet.task_contract_ref
            && offer.auth_generation == state.auth_generation,
        "memory grant offer is stale for the active packet, task, or auth generation"
    );
    anyhow::ensure!(
        packet
            .experience_prior_guidance
            .get(&offer.prior_fingerprint)
            == Some(&offer.guidance_hash),
        "memory grant offer does not resolve to an active private experience prior"
    );
    anyhow::ensure!(
        parsed.expires_at_unix == offer.expires_at.unix_timestamp()
            && redeemed_at <= offer.expires_at,
        "memory grant token is expired or has a substituted expiry"
    );
    anyhow::ensure!(
        constant_time_text_eq(
            &offer.token_hash,
            &blake3::hash(token.as_bytes()).to_hex().to_string()
        ),
        "memory grant token hash is invalid"
    );
    let expected = memory_grant_token(&offer, &state.memory_grant_signing_key)?;
    let expected_parsed = parse_memory_grant_token(&expected)?;
    anyhow::ensure!(
        constant_time_text_eq(parsed.mac, expected_parsed.mac),
        "memory grant token MAC is invalid"
    );

    Ok(ActionMemoryGrantRef {
        schema_version: ACTION_MEMORY_GRANT_REF_SCHEMA_VERSION.to_owned(),
        project_id,
        task_id: task.task_id,
        session_id,
        grant_id: offer.grant_id,
        offer_write_id: offer.offer_write_id,
        packet_id: offer.packet_id,
        packet_revision_fence: offer.packet_revision_fence,
        task_memory_revision: offer.task_memory_revision,
        task_contract_ref: offer.task_contract_ref,
        prior_fingerprint: offer.prior_fingerprint,
        guidance_hash: offer.guidance_hash,
        expires_at: offer.expires_at,
        redeemed_at,
        evidence_class: ActionMemoryGrantEvidenceClass::AgentReturnedOpaqueGrantAfterServerOffer,
    })
}

pub(super) fn append_memory_grant_redemptions(
    task: &mut TaskContract,
    action_write_id: WriteId,
    action_request_hash: &str,
    provenance: &ActionProvenanceSet,
) -> Result<()> {
    anyhow::ensure!(
        action_request_hash.len() == 64
            && action_request_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        "action request hash must be a canonical 32-byte hex digest"
    );
    anyhow::ensure!(
        provenance.task_id == task.task_id
            && provenance.provenance_set_id == format!("eliot/provenance-set/{action_write_id}"),
        "memory grant redemption must bind the consuming action provenance"
    );

    let mut existing = BTreeMap::new();
    for redemption in &task.memory_grant_redemptions {
        anyhow::ensure!(
            redemption.schema_version == ACTION_MEMORY_GRANT_REDEMPTION_SCHEMA_VERSION
                && redemption.project_id == task.project_id
                && redemption.task_id == task.task_id
                && existing
                    .insert(redemption.grant_id.clone(), redemption.clone())
                    .is_none(),
            "stored memory grant redemption history is malformed or duplicated"
        );
    }

    for grant in &provenance.memory_grant_refs {
        anyhow::ensure!(
            grant.schema_version == ACTION_MEMORY_GRANT_REF_SCHEMA_VERSION
                && grant.project_id == task.project_id
                && grant.task_id == task.task_id
                && grant.packet_id == provenance.packet_id
                && grant.packet_revision_fence == provenance.packet_revision_fence
                && grant.task_contract_ref == provenance.task_contract_ref,
            "memory grant reference does not match the consuming task provenance"
        );
        let redemption = ActionMemoryGrantRedemption {
            schema_version: ACTION_MEMORY_GRANT_REDEMPTION_SCHEMA_VERSION.to_owned(),
            project_id: grant.project_id,
            task_id: grant.task_id,
            session_id: grant.session_id,
            grant_id: grant.grant_id.clone(),
            offer_write_id: grant.offer_write_id,
            action_write_id,
            action_request_hash: action_request_hash.to_owned(),
            provenance_set_id: provenance.provenance_set_id.clone(),
            provenance_set_hash: provenance.hash.clone(),
            packet_id: grant.packet_id.clone(),
            packet_revision_fence: grant.packet_revision_fence,
            task_memory_revision: grant.task_memory_revision,
            task_contract_ref: grant.task_contract_ref.clone(),
            prior_fingerprint: grant.prior_fingerprint.clone(),
            guidance_hash: grant.guidance_hash.clone(),
            redeemed_at: grant.redeemed_at,
        };
        if let Some(previous) = existing.get(&grant.grant_id) {
            anyhow::ensure!(
                previous == &redemption,
                "opaque memory grant was already redeemed by a different action"
            );
        } else {
            existing.insert(grant.grant_id.clone(), redemption.clone());
            task.memory_grant_redemptions.push(redemption);
        }
    }
    anyhow::ensure!(
        task.memory_grant_redemptions.len() <= 64,
        "TaskContract memory grant redemption history exceeds its bounded limit"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> MemoryGrantOfferRecord {
        let grant_uuid = uuid::Uuid::from_u128(7);
        MemoryGrantOfferRecord {
            schema_version: MEMORY_DELIVERY_GRANT_SCHEMA_VERSION.to_owned(),
            grant_id: grant_uuid.to_string(),
            project_id: ProjectId::from_uuid(uuid::Uuid::from_u128(1)),
            task_id: TaskId::from_uuid(uuid::Uuid::from_u128(2)),
            session_id: SessionId::from_uuid(uuid::Uuid::from_u128(3)),
            packet_id: "packet-public-id".to_owned(),
            packet_revision_fence: MemoryRevision::new(4),
            task_memory_revision: MemoryRevision::new(6),
            task_contract_ref: "eliot/task/public@4".to_owned(),
            auth_generation: uuid::Uuid::from_u128(5).to_string(),
            prior_fingerprint: "private-prior-fingerprint".to_owned(),
            guidance_hash: "private-guidance-hash".to_owned(),
            offer_write_id: WriteId::from_uuid(grant_uuid),
            token_hash: String::new(),
            expires_at: time::OffsetDateTime::from_unix_timestamp(2_000_000_000)
                .expect("fixed timestamp is valid"),
            offered_at: time::OffsetDateTime::from_unix_timestamp(1_999_999_000)
                .expect("fixed timestamp is valid"),
        }
    }

    fn task() -> TaskContract {
        TaskContract {
            task_id: TaskId::from_uuid(uuid::Uuid::from_u128(2)),
            project_id: ProjectId::from_uuid(uuid::Uuid::from_u128(1)),
            title: "opaque grant redemption".to_owned(),
            status: TaskContractStatus::Open,
            acceptance_items: Vec::new(),
            action_lease_id: None,
            understanding_proof_hash: None,
            action_provenance: None,
            memory_grant_redemptions: Vec::new(),
            observation_ids: Vec::new(),
            verification_ids: Vec::new(),
            verification_scopes: Vec::new(),
            completion_proof: None,
            completion_write_id: None,
            memory_revision: MemoryRevision::new(6),
            project_sequence: eliot_types::ProjectSequence::new(6),
            write_id: WriteId::from_uuid(uuid::Uuid::from_u128(6)),
        }
    }

    fn provenance(action_write_id: WriteId) -> ActionProvenanceSet {
        let offer = offer();
        ActionProvenanceSet {
            provenance_set_id: format!("eliot/provenance-set/{action_write_id}"),
            task_id: offer.task_id,
            packet_id: offer.packet_id.clone(),
            packet_revision_fence: offer.packet_revision_fence,
            task_contract_ref: offer.task_contract_ref.clone(),
            current_truth_refs: vec![offer.task_contract_ref.clone()],
            exact_evidence_refs: vec!["receipt:task".to_owned()],
            memory_delivery_refs: Vec::new(),
            memory_grant_refs: vec![ActionMemoryGrantRef {
                schema_version: ACTION_MEMORY_GRANT_REF_SCHEMA_VERSION.to_owned(),
                project_id: offer.project_id,
                task_id: offer.task_id,
                session_id: offer.session_id,
                grant_id: offer.grant_id,
                offer_write_id: offer.offer_write_id,
                packet_id: offer.packet_id,
                packet_revision_fence: offer.packet_revision_fence,
                task_memory_revision: offer.task_memory_revision,
                task_contract_ref: offer.task_contract_ref,
                prior_fingerprint: offer.prior_fingerprint,
                guidance_hash: offer.guidance_hash,
                expires_at: offer.expires_at,
                redeemed_at: offer.offered_at + time::Duration::seconds(1),
                evidence_class:
                    ActionMemoryGrantEvidenceClass::AgentReturnedOpaqueGrantAfterServerOffer,
            }],
            negative_memory_check_ref: "negative-memory:packet-public-id".to_owned(),
            planned_verifier_ref: "verifier:test".to_owned(),
            source_scope: ActionSourceScope {
                kind: "read_only".to_owned(),
                worktree_ref: None,
                branch: None,
                baseline_commit: None,
                baseline_dirty_state_hash: None,
                artifact_paths: Vec::new(),
            },
            resolved_at: offer.offered_at + time::Duration::seconds(1),
            resolver_version: ACTION_PROVENANCE_RESOLVER_VERSION_V3.to_owned(),
            hash: "b".repeat(64),
        }
    }

    #[test]
    fn public_token_is_opaque_and_mac_bound() -> Result<()> {
        let key = [9_u8; 32];
        let offer = offer();
        let token = memory_grant_token(&offer, &key)?;
        assert!(!token.contains(&offer.prior_fingerprint));
        assert!(!token.contains(&offer.guidance_hash));
        assert!(!token.contains("claim:"));
        let parsed = parse_memory_grant_token(&token)?;
        assert_eq!(parsed.grant_id, offer.grant_id);

        let mut substituted = offer;
        substituted.packet_revision_fence = MemoryRevision::new(5);
        assert_ne!(
            parse_memory_grant_token(&memory_grant_token(&substituted, &key)?)?.mac,
            parsed.mac
        );
        let packet_bound_mac = parse_memory_grant_token(&memory_grant_token(&substituted, &key)?)?
            .mac
            .to_owned();
        substituted.task_memory_revision = MemoryRevision::new(7);
        assert_ne!(
            parse_memory_grant_token(&memory_grant_token(&substituted, &key)?)?.mac,
            packet_bound_mac,
            "task revision must be part of the grant MAC domain"
        );
        Ok(())
    }

    #[test]
    fn malformed_and_tampered_tokens_fail_closed() -> Result<()> {
        let key = [3_u8; 32];
        let offer = offer();
        let token = memory_grant_token(&offer, &key)?;
        assert!(parse_memory_grant_token("mg1:not-a-uuid:1:00").is_err());
        let mut tampered = token.clone().into_bytes();
        let last = tampered
            .last_mut()
            .context("memory grant token should not be empty")?;
        *last = if *last == b'0' { b'1' } else { b'0' };
        let tampered = String::from_utf8(tampered)?;
        let parsed = parse_memory_grant_token(&tampered)?;
        let expected = parse_memory_grant_token(&token)?;
        assert!(!constant_time_text_eq(parsed.mac, expected.mac));
        Ok(())
    }

    #[test]
    fn redemption_is_idempotent_for_one_action_and_rejects_another() -> Result<()> {
        let action_write_id = WriteId::from_uuid(uuid::Uuid::from_u128(8));
        let mut task = task();
        let initial_provenance = provenance(action_write_id);
        let request_hash = "a".repeat(64);

        append_memory_grant_redemptions(
            &mut task,
            action_write_id,
            &request_hash,
            &initial_provenance,
        )?;
        assert_eq!(task.memory_grant_redemptions.len(), 1);
        let committed = task.memory_grant_redemptions[0].clone();

        append_memory_grant_redemptions(
            &mut task,
            action_write_id,
            &request_hash,
            &initial_provenance,
        )?;
        assert_eq!(task.memory_grant_redemptions, vec![committed.clone()]);

        let different_write_id = WriteId::from_uuid(uuid::Uuid::from_u128(9));
        let different = provenance(different_write_id);
        assert!(
            append_memory_grant_redemptions(
                &mut task,
                different_write_id,
                &"c".repeat(64),
                &different,
            )
            .is_err()
        );
        assert_eq!(task.memory_grant_redemptions, vec![committed]);
        Ok(())
    }
}
