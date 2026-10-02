//! Original-owner evidence capture for issue #1774.
//!
//! An installation survey reply is a bounded observation, not a semantic
//! capability verdict. This module captures the exact Kernel result through
//! the Governor's existing `CaptureObservation` path and returns an ordinary
//! `VerifierObservation` lineage. Adapter, provider, model, authentication,
//! billing and serializer dimensions stay unknown unless another original
//! owner supplies them.

use std::collections::BTreeMap;

use eliot_contracts::{OperationId, canonical_json_bytes, sha256_hex};
use eliot_governor::{
    CanonicalWriteEnvelope, CompositionReadiness, GovernorComposition, KernelGenerationPort,
};
use eliot_installation::{
    INSTALLATION_SURVEY_PROBE_OPERATION, InstallationSurveyProbeRequest,
    InstallationSurveyProbeResult, ManagedEnvironmentAction,
};
use eliot_protocol::{
    HOST_REQUEST_RESULT_BODY_WIRE_ID, HostRequestEnvelope, HostRequestKind,
    HostRequestResultBody, HostRequestResultClass, HostRequestResultLineage, LocalReadAttempt,
    host_request_operation_id,
};
use eliot_store_api::{
    EffectClass, EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
    NamedReadOperation, NamedReadRequest, NamedReadResponse, OrderingHead, OrderingHeadExpectation,
    OrderingScopeId, ReadConsistency, ScopeId, SecurityContext, TransitionClass,
    WriteReceipt, WriteReceiptStatus, generated_operation_manifests,
    operation_manifest_set_digest, validate_store_receipt_envelope, CanonicalReadClient,
    EVIDENCE_PACK_MAX_RECORDS,
};

use crate::capability_evidence_wiring::commit_leg_identity;
use crate::kernel_context_read_client::KernelContextReadClient;

const OBSERVE_CAPABILITY: &str = "eliot.observe";

pub(super) enum PriorRuntimeScopeChange {
    NoExactChange,
    Changed { previous: String, observed: String },
}

/// Returns the exact original survey request only when its retained tool bytes
/// are bound to the authenticated observe envelope.
pub(super) fn decode_original_survey_request(
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) -> Result<InstallationSurveyProbeRequest, String> {
    if envelope.identity.capability != OBSERVE_CAPABILITY
        || tool.get("name").and_then(serde_json::Value::as_str) != Some(OBSERVE_CAPABILITY)
    {
        return Err("installation survey tool is not the admitted observe capability".to_owned());
    }
    let tool_bytes = canonical_json_bytes(tool)
        .map_err(|error| format!("installation survey tool cannot be canonicalized: {error}"))?;
    if sha256_hex(&tool_bytes) != envelope.identity.payload_sha256 {
        return Err("installation survey tool does not match the admitted envelope payload".to_owned());
    }
    eliot_installation::decode_installation_survey_observation(tool)
        .map_err(|error| format!("decode original installation survey request: {error}"))?
        .ok_or_else(|| "admitted observe tool is not the installation survey request".to_owned())
}

/// Chooses whether post-change evidence can restrict one exact prior runtime.
/// Changes to an existing runtime require both exact image hashes. A first
/// installation has no prior image; it never selects unrelated restrictions.
pub(super) fn decide_prior_runtime_scope_change(
    request: &InstallationSurveyProbeRequest,
    result: &InstallationSurveyProbeResult,
) -> Result<PriorRuntimeScopeChange, String> {
    validate_result_hashes(result)?;
    if request.request.action != ManagedEnvironmentAction::Register
        && request.completed_change_transaction_id.is_none()
    {
        return Err("installation change lacks its original completed transaction".to_owned());
    }
    let changes_existing_runtime = matches!(
        request.request.action,
        ManagedEnvironmentAction::Update
            | ManagedEnvironmentAction::Repair
            | ManagedEnvironmentAction::Reconfigure
    );
    if changes_existing_runtime
        && (result.previous_runtime_hash.is_none() || result.runtime_hash.is_none())
    {
        return Err(
            "completed installation change lacks an exact prior or current runtime hash; post-change capability evidence is refused"
                .to_owned(),
        );
    }

    match (
        result.previous_runtime_hash.as_deref(),
        result.runtime_hash.as_deref(),
    ) {
        (Some(previous), Some(observed)) if previous != observed => {
            Ok(PriorRuntimeScopeChange::Changed {
                previous: previous.to_owned(),
                observed: observed.to_owned(),
            })
        }
        _ => Ok(PriorRuntimeScopeChange::NoExactChange),
    }
}

/// Captures an authenticated Kernel installation result as raw Governor-owned
/// observation evidence, then returns the same bytes as a non-admitting
/// observe result. The host envelope remains the observation scope and
/// operation identity; the canonical write uses the existing daemon-owned
/// request identity producer and the live Kernel fence.
pub(super) async fn capture_installation_survey_observation<P>(
    governor: &GovernorComposition<P>,
    reads: &KernelContextReadClient,
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    result: &InstallationSurveyProbeResult,
) -> Result<HostRequestResultBody, String>
where
    P: KernelGenerationPort + ?Sized,
{
    let scope = validate_live_observe_binding(governor, reads, envelope, attempt)?;
    validate_result_hashes(result)?;

    let host_operation_id = host_request_operation_id(envelope);
    let (operation_id, idempotency_key, subject) =
        capture_operation_identity(&host_operation_id, result)?;

    // Reconcile the exact original operation before constructing a new
    // expectation. A committed receipt carries the ordering sequence used by
    // its transition, so a retry revalidates the original prepared write even
    // if another owner has since advanced that head.
    let prior_receipt = reads
        .kernel()
        .as_ref()
        .receipt(operation_id.clone())
        .await
        .map_err(|error| format!("reconcile installation observation receipt: {error}"))?;
    let ordering_head = match prior_receipt.as_ref() {
        Some(receipt) => ordering_head_from_receipt(receipt, &scope, &envelope.state_fence)?,
        None => read_ordering_head(reads, &scope, &envelope.state_fence).await?,
    };

    let mut identity = commit_leg_identity(&idempotency_key, &envelope.state_fence)?;
    // ClockReading::default() is a valid explicitly unknown observation, so
    // the existing owner identity can be normalized once for canonical replay
    // without inventing a timestamp. The admitted attempt expiry is retained
    // separately and is not part of the prepared content hash.
    identity.request.metadata.clock = eliot_contracts::ClockReading::default();
    identity.deadline_unix_ms = attempt.expires_at_unix_ms;
    identity
        .validate()
        .map_err(|error| format!("installation observation request identity: {error}"))?;

    let command = NamedMutationRequest {
        operation: NamedMutationOperation::CaptureObservation,
        parameters: BTreeMap::from([("subject".to_owned(), serde_json::json!(subject))]),
    };
    let manifest_digest = operation_manifest_set_digest(
        &generated_operation_manifests()
            .map_err(|error| format!("canonical operation catalogue: {error}"))?,
    )
    .map_err(|error| format!("canonical operation manifest digest: {error}"))?;
    let write_envelope = CanonicalWriteEnvelope {
        operation_id: operation_id.clone(),
        request: identity.request.metadata.clone(),
        idempotency_key: idempotency_key.clone(),
        scope_id: scope.clone(),
        task_id: None,
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: eliot_canonical::supported_admission_contract_set_digest()
            .map_err(|error| error.to_string())?,
        operation_manifest_digest: manifest_digest.clone(),
        semantic_commands: vec![command.clone()],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: vec![ordering_head],
    };
    write_envelope
        .validate()
        .map_err(|error| format!("installation observation envelope: {error}"))?;
    let prepared = write_envelope
        .prepare()
        .map_err(|error| format!("prepare installation observation: {error}"))?;

    let receipt = match prior_receipt {
        Some(receipt) => receipt,
        None => governor
            .commit_canonical(&identity, write_envelope)
            .await
            .map_err(|error| format!("commit installation observation: {error}"))?,
    };
    validate_capture_receipt(
        &receipt,
        &identity,
        &prepared,
        &operation_id,
        &idempotency_key,
        &manifest_digest,
        &envelope.state_fence,
    )?;

    let evidence_pack = read_evidence_pack(reads, &scope, &envelope.state_fence, &subject).await?;
    validate_evidence_pack(
        &evidence_pack,
        &scope,
        &envelope.state_fence,
        &subject,
        &command,
    )?;
    let receipt_ref = receipt
        .require_reconciliation_envelope()
        .map_err(|error| format!("installation observation receipt envelope: {error}"))?
        .identity
        .receipt_id
        .as_str()
        .to_owned();

    let response = serde_json::json!({
        "operation": INSTALLATION_SURVEY_PROBE_OPERATION,
        "request_sha256": envelope.envelope_sha256,
        "result": result,
    });
    let response_bytes = canonical_json_bytes(&response).map_err(|error| error.to_string())?;
    let result_digest = sha256_hex(&response_bytes);
    let body = HostRequestResultBody {
        wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: HostRequestResultBody::CONTRACT_VERSION,
        operation_id: attempt.operation_id.clone(),
        request_sha256: envelope.envelope_sha256.clone(),
        result_digest: result_digest.clone(),
        response,
        attempt: Some(attempt.clone()),
        lineage: Some(HostRequestResultLineage {
            output_artifact_ref: None,
            output_digest: result_digest,
            producer_ref: None,
            source_revisions: None,
            source_state_fence: None,
            input_refs: None,
            transformation_lineage: None,
            closure_refs: None,
            policy_fence: None,
            origin_evidence_refs: Some(vec![receipt_ref]),
            semantic_receipt_ref: None,
            result_class: HostRequestResultClass::VerifierObservation,
            proof_ceiling: None,
            influence_state: eliot_security_contracts::InfluenceState::Unknown,
            instruction_taint: None,
        }),
        evidence: None,
    };
    body.validate_observe_submission()
        .map_err(|error| format!("installation observation result body: {error}"))?;
    Ok(body)
}

fn validate_live_observe_binding<P>(
    governor: &GovernorComposition<P>,
    reads: &KernelContextReadClient,
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
) -> Result<ScopeId, String>
where
    P: KernelGenerationPort + ?Sized,
{
    envelope
        .validate_for_admission()
        .map_err(|error| format!("installation observation host envelope: {error}"))?;
    attempt
        .validate()
        .map_err(|error| format!("installation observation attempt: {error}"))?;
    if governor.readiness() != CompositionReadiness::Ready {
        return Err("installation observation Governor is not ready".to_owned());
    }
    if envelope.kind != HostRequestKind::Invocation
        || envelope.identity.capability != OBSERVE_CAPABILITY
        || attempt.facet_method != OBSERVE_CAPABILITY
        || attempt.operation_id != host_request_operation_id(envelope)
        || attempt.authority_epoch != envelope.state_fence.authority_epoch
        || attempt.expires_at_unix_ms > envelope.identity.deadline_unix_ms
        || envelope
            .identity
            .session_id
            .as_deref()
            .is_some_and(|session| session != attempt.session_id.as_str())
    {
        return Err("installation observation is not bound to the original admitted observe attempt".to_owned());
    }
    let governor_fence = governor.kernel_snapshot().state_fence();
    let live_fence = reads.kernel().kernel_fence();
    if envelope.state_fence != *governor_fence || live_fence != *governor_fence {
        return Err("installation observation Governor, Kernel and host fences do not match".to_owned());
    }

    let selected_scope = envelope
        .identity
        .work_scope_id
        .as_deref()
        .filter(|scope| !scope.trim().is_empty() && !scope.chars().any(char::is_control))
        .or_else(|| {
            envelope
                .identity
                .session_id
                .as_deref()
                .filter(|scope| !scope.trim().is_empty() && !scope.chars().any(char::is_control))
        })
        .ok_or_else(|| "installation observation has no admitted work-scope or session".to_owned())?;
    if selected_scope != attempt.scope_id {
        return Err("installation observation attempt does not bind the admitted host scope".to_owned());
    }
    ScopeId::new(selected_scope.to_owned())
        .map_err(|error| format!("installation observation scope: {error}"))
}

fn validate_result_hashes(result: &InstallationSurveyProbeResult) -> Result<(), String> {
    for (name, hash) in [
        ("runtime_hash", result.runtime_hash.as_deref()),
        (
            "previous_runtime_hash",
            result.previous_runtime_hash.as_deref(),
        ),
    ] {
        if hash.is_some_and(|value| !eliot_governor::is_evidence_ref(value)) {
            return Err(format!(
                "Kernel installation survey {name} is not a lowercase SHA-256 digest"
            ));
        }
    }
    Ok(())
}

pub(super) async fn read_ordering_head(
    reads: &KernelContextReadClient,
    scope: &ScopeId,
    fence: &eliot_contracts::StateFence,
) -> Result<OrderingHeadExpectation, String> {
    let response = reads
        .execute_named(NamedReadRequest {
            operation: NamedReadOperation::GetOrderingHeads,
            scope_id: None,
            consistency: ReadConsistency::ExactFence,
            state_fence: fence.clone(),
            parameters: BTreeMap::new(),
        })
        .await
        .map_err(|error| format!("read installation observation ordering head: {error}"))?;
    response
        .validate()
        .map_err(|error| format!("installation observation ordering-head shape: {error}"))?;
    if response.operation != NamedReadOperation::GetOrderingHeads || response.state_fence != *fence {
        return Err("installation observation ordering-head read changed operation or fence".to_owned());
    }
    let heads: Vec<OrderingHead> = serde_json::from_value(response.payload)
        .map_err(|error| format!("decode installation observation ordering heads: {error}"))?;
    for head in &heads {
        head.validate()
            .map_err(|error| format!("installation observation ordering head is invalid: {error}"))?;
    }
    let ordering_scope = OrderingScopeId::new(format!("scope:{}", scope.as_str()))
        .map_err(|error| format!("installation observation ordering scope: {error}"))?;
    let mut matching = heads.iter().filter(|head| head.scope == ordering_scope);
    let head = matching.next();
    if matching.next().is_some() {
        return Err("installation observation ordering head is ambiguous".to_owned());
    }
    if head.is_some_and(|head| head.state_fence != *fence) {
        return Err("installation observation ordering head belongs to another fence".to_owned());
    }
    Ok(OrderingHeadExpectation {
        scope: ordering_scope,
        expected_sequence: head.map_or(1, |head| head.sequence),
        state_fence: fence.clone(),
    })
}

pub(super) fn ordering_head_from_receipt(
    receipt: &WriteReceipt,
    scope: &ScopeId,
    fence: &eliot_contracts::StateFence,
) -> Result<OrderingHeadExpectation, String> {
    receipt
        .validate()
        .map_err(|error| format!("reconciled installation receipt is malformed: {error}"))?;
    if receipt.status != WriteReceiptStatus::Committed || receipt.state_fence != *fence {
        return Err("reconciled installation receipt is not committed at the live fence".to_owned());
    }
    let ordering_scope = OrderingScopeId::new(format!("scope:{}", scope.as_str()))
        .map_err(|error| format!("installation observation ordering scope: {error}"))?;
    if receipt.ordering_sequences.len() != 1 {
        return Err("reconciled installation receipt does not carry one exact ordering head".to_owned());
    }
    let head = receipt
        .ordering_sequences
        .iter()
        .find(|head| head.scope == ordering_scope)
        .ok_or_else(|| "reconciled installation receipt names another ordering scope".to_owned())?;
    head.validate()
        .map_err(|error| format!("reconciled installation receipt ordering head is invalid: {error}"))?;
    if head.state_fence != *fence {
        return Err("reconciled installation receipt ordering head belongs to another fence".to_owned());
    }
    let expected_sequence = original_ordering_predecessor(head.sequence)?;
    Ok(OrderingHeadExpectation {
        scope: ordering_scope,
        // Store receipts contain `plan.next_ordering_heads`, which are the
        // post-commit sequence. Replaying the original envelope requires the
        // exact CAS predecessor, not the sequence written by that commit.
        expected_sequence,
        state_fence: fence.clone(),
    })
}

fn original_ordering_predecessor(post_commit_sequence: u64) -> Result<u64, String> {
    post_commit_sequence
        .checked_sub(1)
        .filter(|sequence| *sequence > 0)
        .ok_or_else(|| {
            "reconciled installation receipt has no valid original ordering predecessor".to_owned()
        })
}

async fn read_evidence_pack(
    reads: &KernelContextReadClient,
    scope: &ScopeId,
    fence: &eliot_contracts::StateFence,
    subject: &str,
) -> Result<NamedReadResponse, String> {
    reads
        .execute_named(NamedReadRequest {
            operation: NamedReadOperation::GetEvidencePack,
            scope_id: Some(scope.clone()),
            consistency: ReadConsistency::ExactFence,
            state_fence: fence.clone(),
            parameters: BTreeMap::from([
                ("subject".to_owned(), serde_json::json!(subject)),
                (
                    "max_records".to_owned(),
                    serde_json::json!(EVIDENCE_PACK_MAX_RECORDS.to_string()),
                ),
            ]),
        })
        .await
        .map_err(|error| format!("read installation observation evidence pack: {error}"))
}

fn validate_evidence_pack(
    response: &NamedReadResponse,
    scope: &ScopeId,
    fence: &eliot_contracts::StateFence,
    subject: &str,
    command: &NamedMutationRequest,
) -> Result<(), String> {
    response
        .validate()
        .map_err(|error| format!("installation observation evidence-pack shape: {error}"))?;
    if response.operation != NamedReadOperation::GetEvidencePack || response.state_fence != *fence
    {
        return Err("installation observation evidence pack changed operation or fence".to_owned());
    }
    let records = response.payload["records"]
        .as_array()
        .ok_or_else(|| "installation observation evidence pack has no records array".to_owned())?;
    let parameters = serde_json::json!({"subject": subject});
    if response.payload["version"] != 1
        || response.payload["subject"] != subject
        || response.payload["scope_id"] != scope.as_str()
        || response.payload["provenance"]["truncated"] != false
        || records.is_empty()
        || response.payload["provenance"]["returned"].as_u64()
            != Some(records.len() as u64)
        || response.payload["provenance"]["matched_total"].as_u64()
            != Some(records.len() as u64)
        || response.payload["provenance"]["state_fence"] != serde_json::json!(fence)
        || records.iter().any(|row| {
            row["operation"] != "CaptureObservation" || row["parameters"] != parameters
        })
        || command.operation != NamedMutationOperation::CaptureObservation
        || command.parameters != BTreeMap::from([("subject".to_owned(), serde_json::json!(subject))])
    {
        return Err("installation observation evidence pack is incomplete or substituted".to_owned());
    }
    Ok(())
}

fn validate_capture_receipt(
    receipt: &WriteReceipt,
    identity: &eliot_protocol::RequestIdentity,
    prepared: &eliot_canonical::PreparedTransition,
    operation_id: &OperationId,
    idempotency_key: &str,
    manifest_digest: &eliot_store_api::OperationManifestDigest,
    fence: &eliot_contracts::StateFence,
) -> Result<(), String> {
    receipt
        .validate()
        .map_err(|error| format!("installation observation receipt is malformed: {error}"))?;
    validate_store_receipt_envelope(&identity.request.metadata, prepared, receipt)
        .map_err(|error| format!("installation observation receipt does not bind its prepared write: {error}"))?;
    if receipt.status != WriteReceiptStatus::Committed
        || receipt.operation_id != *operation_id
        || receipt.idempotency_key != idempotency_key
        || receipt.canonical_request_hash != prepared.identity.canonical_request_hash
        || receipt.transition_class != TransitionClass::CaptureCandidate
        || receipt.operation_manifest_digest != *manifest_digest
        || receipt.state_fence != *fence
        || receipt.envelope.is_none()
    {
        return Err("installation observation receipt does not match the original capture".to_owned());
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{
        PriorRuntimeScopeChange, capture_operation_identity,
        decide_prior_runtime_scope_change, validate_result_hashes,
    };
    use eliot_installation::{
        InstallationSurveyProbeRequest, InstallationSurveyProbeResult,
        ManagedCapabilityAdvertisement, ManagedCapabilityState, ManagedCapabilityStatus,
        ManagedEnvironmentAction, ManagedEnvironmentChangeRequest, MissingQualification,
        PlatformHandle,
    };
    use std::path::PathBuf;

    fn result() -> InstallationSurveyProbeResult {
        InstallationSurveyProbeResult {
            advertisement: ManagedCapabilityAdvertisement {
                family_id: handle("family:test"),
                category: eliot_installation::IntegrationCategory::Toolchain,
                target_identity: Some(handle("candidate:test")),
                state: ManagedCapabilityState {
                    status: ManagedCapabilityStatus::Declared {
                        probe_id: handle("probe:test"),
                    },
                    missing: vec![MissingQualification::NotProbedByAnAdmittedExecutor],
                },
                requalified_against: test_requalification_binding(),
            },
            runtime_hash: Some("a".repeat(64)),
            previous_runtime_hash: Some("b".repeat(64)),
        }
    }

    #[test]
    fn installation_survey_capture_reconciles_the_exact_original_observation() {
        let first = capture_operation_identity("hostreq:first", &result()).expect("identity");
        let replay = capture_operation_identity("hostreq:first", &result()).expect("replay");
        let other_request = capture_operation_identity("hostreq:second", &result()).expect("other request");
        let mut changed_result = result();
        changed_result.runtime_hash = Some("c".repeat(64));
        let other_bytes = capture_operation_identity("hostreq:first", &changed_result)
            .expect("changed result");

        assert_eq!(first, replay);
        assert_ne!(first, other_request);
        assert_ne!(first, other_bytes);
    }

    #[test]
    fn installation_survey_capture_refuses_malformed_current_or_previous_hashes() {
        let mut value = result();
        assert!(validate_result_hashes(&value).is_ok());
        value.previous_runtime_hash = Some("not-a-digest".to_owned());
        assert!(validate_result_hashes(&value).is_err());
        value.previous_runtime_hash = None;
        value.runtime_hash = Some("A".repeat(64));
        assert!(validate_result_hashes(&value).is_err());
    }

    #[test]
    fn installation_survey_capture_keeps_missing_runtime_and_probe_gaps_explicit() {
        let mut value = result();
        value.runtime_hash = None;
        value.previous_runtime_hash = None;

        assert!(validate_result_hashes(&value).is_ok());
        assert_eq!(value.runtime_hash, None);
        assert_eq!(value.previous_runtime_hash, None);
        assert!(matches!(
            &value.advertisement.state.status,
            ManagedCapabilityStatus::Declared { .. }
        ));
        assert_eq!(
            value.advertisement.state.missing,
            vec![MissingQualification::NotProbedByAnAdmittedExecutor]
        );
    }

    #[test]
    fn installation_survey_change_decision_keeps_unchanged_and_new_hashes_exact() {
        let mut value = result();
        let request = post_change_request(ManagedEnvironmentAction::Update);
        value.previous_runtime_hash = Some("a".repeat(64));
        value.runtime_hash = Some("a".repeat(64));
        assert!(matches!(
            decide_prior_runtime_scope_change(&request, &value),
            Ok(PriorRuntimeScopeChange::NoExactChange)
        ));

        value.runtime_hash = Some("c".repeat(64));
        assert!(matches!(
            decide_prior_runtime_scope_change(&request, &value),
            Ok(PriorRuntimeScopeChange::Changed { previous, observed })
                if previous == "a".repeat(64) && observed == "c".repeat(64)
        ));
    }

    #[test]
    fn installation_survey_post_change_refuses_missing_exact_hashes() {
        let mut request = post_change_request(ManagedEnvironmentAction::Repair);
        let mut value = result();
        value.previous_runtime_hash = None;
        assert!(decide_prior_runtime_scope_change(&request, &value).is_err());
        value.previous_runtime_hash = Some("b".repeat(64));
        value.runtime_hash = None;
        assert!(decide_prior_runtime_scope_change(&request, &value).is_err());
        value.runtime_hash = Some("c".repeat(64));
        request.completed_change_transaction_id = None;
        assert!(decide_prior_runtime_scope_change(&request, &value).is_err());
    }

    #[test]
    fn installation_survey_registration_may_preserve_explicit_unknown_hashes() {
        let request = post_change_request(ManagedEnvironmentAction::Register);
        let mut value = result();
        value.previous_runtime_hash = None;
        value.runtime_hash = None;
        assert!(matches!(
            decide_prior_runtime_scope_change(&request, &value),
            Ok(PriorRuntimeScopeChange::NoExactChange)
        ));
        let installed = post_change_request(ManagedEnvironmentAction::Install);
        value.runtime_hash = Some("c".repeat(64));
        assert!(matches!(
            decide_prior_runtime_scope_change(&installed, &value),
            Ok(PriorRuntimeScopeChange::NoExactChange)
        ));
    }

    #[test]
    fn installation_survey_capture_replays_the_original_ordering_predecessor() {
        use super::original_ordering_predecessor;

        assert_eq!(original_ordering_predecessor(8).expect("predecessor"), 7);
        assert!(original_ordering_predecessor(1).is_err());
    }

    fn handle(value: &str) -> PlatformHandle {
        PlatformHandle::new(value.to_owned()).expect("valid handle")
    }

    fn test_requalification_binding() -> eliot_installation::RequalificationBinding {
        use eliot_installation::InstallationProfile;
        eliot_installation::RequalificationBinding {
            catalogue_origin: handle("catalogue:test"),
            catalogue_revision: 1,
            catalogue_publication_ref: handle("publication:test"),
            catalogue_accepted_by: handle("owner:test"),
            confirmed_owner: handle("owner:test"),
            profile: InstallationProfile::PortableDev,
            runtime_state_roots_digest: handle("roots:test"),
            setup_revision: 1,
            configuration_snapshot_ref: handle("snapshot:test"),
            survey_content_digest: handle(&"a".repeat(64)),
        }
    }

    fn post_change_request(action: ManagedEnvironmentAction) -> InstallationSurveyProbeRequest {
        let handle = |value: &str| PlatformHandle::new(value.to_owned()).expect("valid handle");
        InstallationSurveyProbeRequest {
            store_path: PathBuf::from(r"C:\eliot\installation.redb"),
            publication_transaction_id: handle("publication:test"),
            completed_change_transaction_id: Some(handle("change:test")),
            request: ManagedEnvironmentChangeRequest {
                request_id: handle("request:test"),
                requester_and_reason: handle("reason:test"),
                action,
                target_family: handle("family:test"),
                exact_candidate: handle("candidate:test"),
                expected_delta: handle("delta:test"),
                source_assurance_refs: Vec::new(),
                affected_refs: Vec::new(),
                impact_class: handle("impact:test"),
                required_owner: handle("owner:test"),
                rollback_plan: handle("rollback:test"),
                verifier: handle("verifier:test"),
                budget: handle("budget:test"),
                stop_condition: handle("stop:test"),
            },
        }
    }
}

fn capture_operation_identity(
    host_operation_id: &str,
    result: &InstallationSurveyProbeResult,
) -> Result<(OperationId, String, String), String> {
    validate_result_hashes(result)?;
    let result_bytes = canonical_json_bytes(result).map_err(|error| error.to_string())?;
    let result_digest = sha256_hex(&result_bytes);
    let operation = OperationId::new(format!("{host_operation_id}:{result_digest}"))
        .map_err(|error| error.to_string())?;
    let subject = String::from_utf8(result_bytes).map_err(|error| error.to_string())?;
    Ok((operation.clone(), operation.as_str().to_owned(), subject))
}
