//! Authenticated owner-facts pull handling for process-stream admission.
//!
//! The daemon re-reads current named owners before answering a Kernel pull.
//! TestD request metadata can select an already retained catalog generation,
//! but the generated process-stream source ID requires its own durable,
//! pre-capture admission; it is not a governing-document source reference.

use std::time::{SystemTime, UNIX_EPOCH};

use eliot_blob_api::wire::{
    BLOB_PROCESS_STREAM_OWNER_FACTS_WIRE_ID, BLOB_PROCESS_STREAM_OWNER_FACTS_WIRE_REVISION,
    BlobProcessStreamOwnerFactsPullOutcome, BlobProcessStreamOwnerFactsPullPurpose,
    BlobProcessStreamOwnerFactsPullRequest, BlobProcessStreamOwnerFactsPullResponse,
    BlobProcessStreamOwnerFactsUnavailableReason, BlobProcessStreamVerifiedOwnerFacts,
};
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use serde::Serialize;

use crate::DaemonComposition;

/// The independently read current generation admission selected by the
/// authenticated pull's retained module/generation selectors.
///
/// Catalog and admission documents are canonical metadata only. Kernel must
/// deserialize these exact bytes into the shared Module Registry types and
/// re-run its owner-readback validator before using them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentModuleCatalogGeneration {
    pub owner_readback_json: String,
    pub owner_readback_sha256: String,
    pub generation_admission_json: String,
    pub generation_admission_sha256: String,
}

/// Canonical current WorkScope and admitted source documents returned only
/// after the fresh named-owner read and matched guard validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentWorkScopeSourceReceipt {
    pub work_scope_ref: String,
    pub work_scope_snapshot_json: String,
    pub work_scope_snapshot_sha256: String,
    pub matched_guard_receipt_json: String,
    pub matched_guard_receipt_sha256: String,
    pub canonical_source_receipt_ref: String,
    pub canonical_source_receipt_json: String,
    pub canonical_source_receipt_sha256: String,
}

/// Exact current Config-owned S-04 policy and full residency template.
/// Revisions/digests identify the Policy owner envelope; the JSON members are
/// canonical projections of its admitted typed value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentBlobPolicyResidency {
    pub policy_json: String,
    pub policy_sha256: String,
    pub residency_json: String,
    pub residency_sha256: String,
    pub policy_owner_revision: u64,
    pub policy_owner_digest: String,
}

/// Reads and decodes the current Human-admitted Config value for this exact
/// WorkScope. A policy setting for another scope, owner, or StateFence is not
/// transferable to this process stream.
pub fn read_current_blob_policy_residency(
    composition: &DaemonComposition,
    state_fence: &eliot_contracts::StateFence,
    work_scope_ref: &str,
) -> Result<CurrentBlobPolicyResidency, String> {
    let owner = composition
        .current_testd_blob_policy_owner_readback(state_fence)?
        .ok_or_else(|| "current Policy owner is unavailable".to_owned())?;
    if owner.state_fence() != state_fence || owner.snapshot().scope_id != work_scope_ref {
        return Err("current Policy owner is outside this WorkScope or StateFence".to_owned());
    }
    let selected = owner
        .snapshot()
        .blob_process_policy()
        .map_err(|error| format!("current Config Blob policy is invalid: {error}"))?
        .ok_or_else(|| "current Config has no admitted Blob process policy".to_owned())?;
    let policy_bytes = canonical_json_bytes(&selected.policy)
        .map_err(|error| format!("canonical Blob policy encoding failed: {error}"))?;
    let residency_bytes = canonical_json_bytes(&selected.residency)
        .map_err(|error| format!("canonical Blob residency encoding failed: {error}"))?;
    Ok(CurrentBlobPolicyResidency {
        policy_sha256: sha256_hex(&policy_bytes),
        policy_json: String::from_utf8(policy_bytes)
            .map_err(|error| format!("Blob policy UTF-8 encoding failed: {error}"))?,
        residency_sha256: sha256_hex(&residency_bytes),
        residency_json: String::from_utf8(residency_bytes)
            .map_err(|error| format!("Blob residency UTF-8 encoding failed: {error}"))?,
        policy_owner_revision: owner.revision(),
        policy_owner_digest: owner.canonical_digest().to_owned(),
    })
}

/// Packages the exact owner-read WorkScope and its admitted governing-source
/// closure in canonical form. This is deliberately independent from a newly
/// generated process-stream SourceId, which is admitted in a separate owner.
pub fn canonical_current_work_scope_source_receipt(
    snapshot: &eliot_governor::WorkScopeBindingSnapshot,
) -> Result<CurrentWorkScopeSourceReceipt, String> {
    snapshot
        .validate()
        .map_err(|error| format!("WorkScope source admission is invalid: {error}"))?;
    let source = snapshot
        .source_admission()
        .ok_or_else(|| "WorkScope owner has no retained source admission".to_owned())?;
    let work_scope_bytes = canonical_json_bytes(snapshot)
        .map_err(|error| format!("canonical WorkScope owner encoding failed: {error}"))?;
    let guard_bytes = canonical_json_bytes(&snapshot.guard_receipt)
        .map_err(|error| format!("canonical WorkScope guard encoding failed: {error}"))?;
    // This preserves the complete owner-admitted governing-source set,
    // including its original per-source refs, digests, statuses, authority
    // basis, and generation. The transport digest is only a commitment to this
    // canonical projection; it does not replace any source digest.
    let source_bytes = canonical_json_bytes(source)
        .map_err(|error| format!("canonical source admission encoding failed: {error}"))?;
    let source_receipt_sha256 = sha256_hex(&source_bytes);
    Ok(CurrentWorkScopeSourceReceipt {
        work_scope_ref: snapshot.binding.scope.scope_ref.clone(),
        work_scope_snapshot_sha256: sha256_hex(&work_scope_bytes),
        work_scope_snapshot_json: String::from_utf8(work_scope_bytes)
            .map_err(|error| format!("WorkScope owner UTF-8 encoding failed: {error}"))?,
        matched_guard_receipt_sha256: sha256_hex(&guard_bytes),
        matched_guard_receipt_json: String::from_utf8(guard_bytes)
            .map_err(|error| format!("WorkScope guard UTF-8 encoding failed: {error}"))?,
        canonical_source_receipt_ref: source.sources.scope_ref.clone(),
        canonical_source_receipt_json: String::from_utf8(source_bytes)
            .map_err(|error| format!("source admission UTF-8 encoding failed: {error}"))?,
        canonical_source_receipt_sha256,
    })
}

#[derive(Serialize)]
struct ModuleCatalogOwnerReadbackWire<'a> {
    owner_revision: u64,
    snapshot: &'a serde_json::Value,
}

/// Freshly reads the canonical Module Registry owner, then selects exactly
/// one accepted generation by the immutable selectors retained on the
/// admitted TestD job. Neither selector is treated as proof.
pub fn read_current_module_catalog_generation(
    composition: &DaemonComposition,
    state_fence: &eliot_contracts::StateFence,
    expected_module_id: Option<&str>,
    expected_generation_id: Option<&str>,
) -> Result<CurrentModuleCatalogGeneration, String> {
    let (Some(module_id), Some(generation_id)) = (expected_module_id, expected_generation_id)
    else {
        return Err("admitted job omitted exact module/generation selectors".to_owned());
    };
    let readback = composition.current_testd_blob_module_catalog_owner_readback(state_fence)?;
    let entry = readback
        .snapshot
        .entries
        .iter()
        .find(|entry| entry.module_id.as_str() == module_id)
        .ok_or_else(|| "fresh Module Registry owner omitted selected module".to_owned())?;
    let admission = entry
        .accepted_generation
        .as_ref()
        .ok_or_else(|| "fresh Module Registry owner has no accepted generation".to_owned())?;
    if entry.module_id.as_str() != module_id
        || admission.execution.generation_id.as_str() != generation_id
        || admission.candidate.module_id.as_str() != module_id
        || admission.state_fence != *state_fence
        || admission.catalog_revision > readback.snapshot.catalog_revision
    {
        return Err(
            "fresh Module Registry generation differs from retained selectors or fence".to_owned(),
        );
    }
    admission
        .validate()
        .map_err(|error| format!("fresh Module Registry generation is invalid: {error}"))?;
    readback
        .verify_generation_admission(
            readback.owner_revision,
            readback.snapshot.catalog_revision,
            state_fence,
            admission,
        )
        .map_err(|error| format!("fresh Module Registry generation readback failed: {error}"))?;
    let snapshot_value = serde_json::to_value(&readback.snapshot)
        .map_err(|error| format!("Module Registry snapshot serialization failed: {error}"))?;
    let readback_wire = ModuleCatalogOwnerReadbackWire {
        owner_revision: readback.owner_revision,
        snapshot: &snapshot_value,
    };
    let readback_bytes = canonical_json_bytes(&readback_wire)
        .map_err(|error| format!("canonical Module Registry readback encoding failed: {error}"))?;
    let admission_bytes = canonical_json_bytes(admission)
        .map_err(|error| format!("canonical generation admission encoding failed: {error}"))?;
    Ok(CurrentModuleCatalogGeneration {
        owner_readback_sha256: sha256_hex(&readback_bytes),
        owner_readback_json: String::from_utf8(readback_bytes)
            .map_err(|error| format!("Module Registry readback UTF-8 encoding failed: {error}"))?,
        generation_admission_sha256: sha256_hex(&admission_bytes),
        generation_admission_json: String::from_utf8(admission_bytes)
            .map_err(|error| format!("generation admission UTF-8 encoding failed: {error}"))?,
    })
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn unavailable_blob_owner_facts(
    request: &BlobProcessStreamOwnerFactsPullRequest,
    reason: BlobProcessStreamOwnerFactsUnavailableReason,
) -> Result<BlobProcessStreamOwnerFactsPullResponse, String> {
    let response = BlobProcessStreamOwnerFactsPullResponse {
        wire_id: BLOB_PROCESS_STREAM_OWNER_FACTS_WIRE_ID.to_owned(),
        wire_revision: BLOB_PROCESS_STREAM_OWNER_FACTS_WIRE_REVISION,
        pull_ref: request.pull_ref.clone(),
        purpose: request.purpose,
        job_id: request.job_id.clone(),
        invocation_id: request.invocation_id.clone(),
        process_binding_sha256: request.process_binding_sha256.clone(),
        outer_request_sha256: request.outer_request_sha256.clone(),
        observed_state_fence: request.state_fence.clone(),
        outcome: BlobProcessStreamOwnerFactsPullOutcome::Unavailable { reason },
    };
    response
        .validate_for_request(request)
        .map_err(|error| format!("invalid blob owner-facts response: {error}"))?;
    Ok(response)
}

fn available_launch_owner_facts(
    composition: &DaemonComposition,
    request: &BlobProcessStreamOwnerFactsPullRequest,
    scope: &CurrentWorkScopeSourceReceipt,
    policy: &CurrentBlobPolicyResidency,
    catalog: &CurrentModuleCatalogGeneration,
    source_admission: Option<(&str, &str, &str, &str)>,
) -> Result<BlobProcessStreamOwnerFactsPullResponse, String> {
    let authority: eliot_receipts::AuthorityBinding =
        serde_json::from_str(&request.kernel_authority_binding_json)
            .map_err(|error| format!("Kernel authority binding is invalid: {error}"))?;
    let causal: eliot_receipts::CausalBinding =
        serde_json::from_str(&request.kernel_causal_binding_json)
            .map_err(|error| format!("Kernel causal binding is invalid: {error}"))?;
    if authority.state_fence != request.state_fence
        || authority.authority_epoch != request.state_fence.authority_epoch
        || causal.state_fence != request.state_fence
        || (causal.transaction_sequence.value() > 1
            && causal.parent_receipt_id.as_ref().is_none_or(|parent| {
                !causal
                    .predecessor_receipt_ids
                    .iter()
                    .any(|item| item == parent)
            }))
    {
        return Err(
            "Kernel causal or authority binding differs from the authenticated fence".to_owned(),
        );
    }
    let task_binding = match request.task_id.as_deref() {
        Some(task_ref) => {
            Some(composition.current_testd_blob_task_binding(task_ref, &request.state_fence)?)
        }
        None => None,
    };
    let session_binding = match request.session_id.as_deref() {
        Some(session_ref) => Some(
            composition.current_testd_blob_session_binding(session_ref, &request.state_fence)?,
        ),
        None => None,
    };
    let task_binding_bytes = task_binding
        .as_ref()
        .map(canonical_json_bytes)
        .transpose()
        .map_err(|error| format!("TaskBinding encoding failed: {error}"))?;
    let session_binding_bytes = session_binding
        .as_ref()
        .map(canonical_json_bytes)
        .transpose()
        .map_err(|error| format!("SessionBinding encoding failed: {error}"))?;
    let product_id = eliot_contracts::ProductId::new(request.product_id.clone())
        .map_err(|error| format!("authenticated ProductId is invalid: {error}"))?;
    let (work_scope_receipt_binding, work_scope_receipt_binding_json, work_scope_receipt_binding_sha256) = composition
        .current_testd_blob_work_scope_receipt_binding(&request.state_fence, &product_id)?;
    if work_scope_receipt_binding.scope_id.as_str() != scope.work_scope_ref
        || work_scope_receipt_binding.state_fence != request.state_fence
        || work_scope_receipt_binding.resource_generation != request.state_fence.resource_generation
    {
        return Err("current receipt-grade WorkScope binding differs from owner snapshot".to_owned());
    }
    let (stage_operation_binding_json, stage_operation_binding_sha256,
         stage_authority_binding_json, stage_authority_binding_sha256,
         stage_causal_binding_json, stage_causal_binding_sha256,
         read_operation_binding_json, read_operation_binding_sha256,
         read_authority_binding_json, read_authority_binding_sha256,
         read_causal_binding_json, read_causal_binding_sha256) =
        if request.purpose == BlobProcessStreamOwnerFactsPullPurpose::SourceReadback {
            let operation_json = request.kernel_operation_binding_json.clone()
                .ok_or_else(|| "SourceReadback lacks Kernel operation binding".to_owned())?;
            let operation_sha = request.kernel_operation_binding_sha256.clone()
                .ok_or_else(|| "SourceReadback lacks Kernel operation digest".to_owned())?;
            (None, None, None, None, None, None,
             Some(operation_json), Some(operation_sha),
             Some(request.kernel_authority_binding_json.clone()), Some(request.kernel_authority_binding_sha256.clone()),
             Some(request.kernel_causal_binding_json.clone()), Some(request.kernel_causal_binding_sha256.clone()))
        } else if request.purpose != BlobProcessStreamOwnerFactsPullPurpose::LaunchGrant {
            let operation_json = request.kernel_operation_binding_json.clone()
                .ok_or_else(|| "stage owner-facts pull lacks Kernel operation binding".to_owned())?;
            let operation_sha = request.kernel_operation_binding_sha256.clone()
                .ok_or_else(|| "stage owner-facts pull lacks Kernel operation digest".to_owned())?;
            (Some(operation_json), Some(operation_sha),
             Some(request.kernel_authority_binding_json.clone()), Some(request.kernel_authority_binding_sha256.clone()),
             Some(request.kernel_causal_binding_json.clone()), Some(request.kernel_causal_binding_sha256.clone()),
             None, None, None, None, None, None)
        } else {
            (None, None, None, None, None, None, None, None, None, None, None, None)
        };
    let facts = BlobProcessStreamVerifiedOwnerFacts {
        work_scope_binding_sha256: scope.work_scope_snapshot_sha256.clone(),
        work_scope_binding_json: scope.work_scope_snapshot_json.clone(),
        work_scope_receipt_binding_json: work_scope_receipt_binding_json.clone(),
        work_scope_receipt_binding_sha256: work_scope_receipt_binding_sha256.clone(),
        matched_guard_receipt_json: scope.matched_guard_receipt_json.clone(),
        matched_guard_receipt_sha256: scope.matched_guard_receipt_sha256.clone(),
        canonical_source_receipt_json: scope.canonical_source_receipt_json.clone(),
        canonical_source_receipt_sha256: scope.canonical_source_receipt_sha256.clone(),
        policy_json: policy.policy_json.clone(),
        policy_sha256: policy.policy_sha256.clone(),
        residency_json: policy.residency_json.clone(),
        residency_sha256: policy.residency_sha256.clone(),
        causal_binding_json: request.kernel_causal_binding_json.clone(),
        causal_binding_sha256: request.kernel_causal_binding_sha256.clone(),
        authority_binding_json: request.kernel_authority_binding_json.clone(),
        authority_binding_sha256: request.kernel_authority_binding_sha256.clone(),
        stage_operation_binding_json,
        stage_operation_binding_sha256,
        stage_authority_binding_json,
        stage_authority_binding_sha256,
        stage_causal_binding_json,
        stage_causal_binding_sha256,
        read_operation_binding_json,
        read_operation_binding_sha256,
        read_authority_binding_json,
        read_authority_binding_sha256,
        read_causal_binding_json,
        read_causal_binding_sha256,
        currentness_sha256: String::new(),
        task_binding_sha256: task_binding_bytes.as_ref().map(|bytes| sha256_hex(bytes)),
        task_binding_json: task_binding_bytes
            .as_ref()
            .map(|bytes| String::from_utf8(bytes.clone()))
            .transpose()
            .map_err(|error| format!("TaskBinding is not UTF-8: {error}"))?,
        session_binding_sha256: session_binding_bytes
            .as_ref()
            .map(|bytes| sha256_hex(bytes)),
        session_binding_json: session_binding_bytes
            .as_ref()
            .map(|bytes| String::from_utf8(bytes.clone()))
            .transpose()
            .map_err(|error| format!("SessionBinding is not UTF-8: {error}"))?,
    };
    #[derive(Serialize)]
    struct Currentness<'a> {
        state_fence: &'a eliot_contracts::StateFence,
        work_scope_ref: &'a str,
        work_scope_sha256: &'a str,
        guard_sha256: &'a str,
        source_sha256: &'a str,
        policy_owner_revision: u64,
        policy_owner_digest: &'a str,
        policy_sha256: &'a str,
        residency_sha256: &'a str,
        catalog_owner_sha256: &'a str,
        generation_admission_sha256: &'a str,
        causal_binding_sha256: &'a str,
        authority_binding_sha256: &'a str,
        process_binding_sha256: &'a str,
        source_root_identity_sha256: &'a str,
        stage_operation_binding_sha256: Option<&'a str>,
        stage_authority_binding_sha256: Option<&'a str>,
        stage_causal_binding_sha256: Option<&'a str>,
        read_operation_binding_sha256: Option<&'a str>,
        read_authority_binding_sha256: Option<&'a str>,
        read_causal_binding_sha256: Option<&'a str>,
        task_binding_sha256: Option<&'a str>,
        session_binding_sha256: Option<&'a str>,
    }
    let currentness_bytes = canonical_json_bytes(&Currentness {
        state_fence: &request.state_fence,
        work_scope_ref: &scope.work_scope_ref,
        work_scope_sha256: &scope.work_scope_snapshot_sha256,
        guard_sha256: &scope.matched_guard_receipt_sha256,
        source_sha256: &scope.canonical_source_receipt_sha256,
        policy_owner_revision: policy.policy_owner_revision,
        policy_owner_digest: &policy.policy_owner_digest,
        policy_sha256: &policy.policy_sha256,
        residency_sha256: &policy.residency_sha256,
        catalog_owner_sha256: &catalog.owner_readback_sha256,
        generation_admission_sha256: &catalog.generation_admission_sha256,
        causal_binding_sha256: &request.kernel_causal_binding_sha256,
        authority_binding_sha256: &request.kernel_authority_binding_sha256,
        process_binding_sha256: &request.process_binding_sha256,
        source_root_identity_sha256: &request.source_root_identity_sha256,
        stage_operation_binding_sha256: facts.stage_operation_binding_sha256.as_deref(),
        stage_authority_binding_sha256: facts.stage_authority_binding_sha256.as_deref(),
        stage_causal_binding_sha256: facts.stage_causal_binding_sha256.as_deref(),
        read_operation_binding_sha256: facts.read_operation_binding_sha256.as_deref(),
        read_authority_binding_sha256: facts.read_authority_binding_sha256.as_deref(),
        read_causal_binding_sha256: facts.read_causal_binding_sha256.as_deref(),
        task_binding_sha256: facts.task_binding_sha256.as_deref(),
        session_binding_sha256: facts.session_binding_sha256.as_deref(),
    })
    .map_err(|error| format!("currentness input encoding failed: {error}"))?;
    let currentness_sha256 = sha256_hex(&currentness_bytes);
    let facts = BlobProcessStreamVerifiedOwnerFacts {
        currentness_sha256: currentness_sha256.clone(),
        ..facts
    };
    facts
        .validate()
        .map_err(|error| format!("verified owner facts are invalid: {error}"))?;
    let facts_bytes = canonical_json_bytes(&facts)
        .map_err(|error| format!("verified owner facts encoding failed: {error}"))?;
    let facts_sha256 = sha256_hex(&facts_bytes);
    let facts_json = String::from_utf8(facts_bytes)
        .map_err(|error| format!("verified owner facts are not UTF-8: {error}"))?;
    let policy_ref = serde_json::from_str::<serde_json::Value>(&policy.policy_json)
        .ok()
        .and_then(|value| {
            value
                .get("policy_ref")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .ok_or_else(|| "selected policy has no typed policy reference".to_owned())?;
    let response = BlobProcessStreamOwnerFactsPullResponse {
        wire_id: BLOB_PROCESS_STREAM_OWNER_FACTS_WIRE_ID.to_owned(),
        wire_revision: BLOB_PROCESS_STREAM_OWNER_FACTS_WIRE_REVISION,
        pull_ref: request.pull_ref.clone(),
        purpose: request.purpose,
        job_id: request.job_id.clone(),
        invocation_id: request.invocation_id.clone(),
        process_binding_sha256: request.process_binding_sha256.clone(),
        outer_request_sha256: request.outer_request_sha256.clone(),
        observed_state_fence: request.state_fence.clone(),
        outcome: BlobProcessStreamOwnerFactsPullOutcome::Available {
            work_scope_ref: scope.work_scope_ref.clone(),
            owner_facts_ref: facts_sha256.clone(),
            owner_facts_sha256: facts_sha256,
            work_scope_snapshot_sha256: scope.work_scope_snapshot_sha256.clone(),
            matched_guard_receipt_ref: scope.matched_guard_receipt_sha256.clone(),
            matched_guard_receipt_sha256: scope.matched_guard_receipt_sha256.clone(),
            canonical_source_receipt_ref: scope.canonical_source_receipt_ref.clone(),
            canonical_source_receipt_sha256: scope.canonical_source_receipt_sha256.clone(),
            policy_ref,
            policy_sha256: policy.policy_sha256.clone(),
            residency_ref: policy.residency_sha256.clone(),
            residency_sha256: policy.residency_sha256.clone(),
            causal_receipt_ref: request.kernel_causal_binding_sha256.clone(),
            causal_receipt_sha256: request.kernel_causal_binding_sha256.clone(),
            authority_ref: request.kernel_authority_binding_sha256.clone(),
            authority_sha256: request.kernel_authority_binding_sha256.clone(),
            currentness_sha256,
            owner_facts_json: facts_json,
            module_catalog_owner_readback_json: catalog.owner_readback_json.clone(),
            module_catalog_owner_readback_sha256: catalog.owner_readback_sha256.clone(),
            generation_admission_json: catalog.generation_admission_json.clone(),
            generation_admission_sha256: catalog.generation_admission_sha256.clone(),
            process_source_admission_json: source_admission.map(|(json, _, _, _)| json.to_owned()),
            process_source_admission_sha256: source_admission.map(|(_, digest, _, _)| digest.to_owned()),
            source_admission_write_receipt_json: source_admission.map(|(_, _, json, _)| json.to_owned()),
            source_admission_write_receipt_sha256: source_admission.map(|(_, _, _, digest)| digest.to_owned()),
        },
    };
    response
        .validate_for_request(request)
        .map_err(|error| format!("invalid available owner-facts response: {error}"))?;
    Ok(response)
}

fn source_readback_admission(
    composition: &DaemonComposition,
    request: &BlobProcessStreamOwnerFactsPullRequest,
) -> Result<(String, String, String, String), String> {
    use eliot_blob_api::wire::ProcessStreamKind;
    use eliot_store_api::blob_process_source_admission::{
        BlobProcessSourceAdmissionIdentity, BlobProcessSourceAdmissionPhase,
    };
    use eliot_process::stream_sink::ProcessStreamSinkOpenRequest;

    let binding = request.process_stream_binding.as_ref()
        .ok_or_else(|| "SourceReadback lacks its retained Store stream binding".to_owned())?;
    let identity = BlobProcessSourceAdmissionIdentity {
        work_scope_ref: request.expected_work_scope_ref.clone()
            .ok_or_else(|| "SourceReadback lacks its retained WorkScope selector".to_owned())?,
        session_id: binding.session_id.clone(),
        source_id: binding.source_id.clone(),
        process_binding_sha256: request.process_binding_sha256.clone(),
    };
    let readback = composition.current_testd_blob_process_source_admission(
        &identity,
        &request.state_fence,
    )?.ok_or_else(|| "current process-source Ready admission is absent".to_owned())?;
    readback.validate_for(&identity, &request.state_fence)
        .map_err(|error| format!("current process-source admission is invalid: {error}"))?;
    let admission = &readback.admission;
    if admission.phase != BlobProcessSourceAdmissionPhase::Ready
        || admission.pending_operation_id != request.source_admission_operation_id.as_deref().unwrap_or_default()
        || admission.identity.session_id != binding.session_id
        || admission.identity.source_id != binding.source_id
        || admission.identity.process_binding_sha256 != request.process_binding_sha256
    {
        return Err("current process-source admission differs from the exact Ready selectors".to_owned());
    }
    let open: ProcessStreamSinkOpenRequest = serde_json::from_str(&admission.open_request_json)
        .map_err(|error| format!("retained source Open request is invalid: {error}"))?;
    open.validate().map_err(|error| format!("retained source Open request failed validation: {error}"))?;
    let requested_binding: serde_json::Value = serde_json::from_str(&request.process_binding_json)
        .map_err(|error| format!("SourceReadback process binding is invalid: {error}"))?;
    let original_binding = serde_json::to_value(open.binding())
        .map_err(|error| format!("retained Open process binding cannot be encoded: {error}"))?;
    let open_policy_json = serde_json::to_string(open.policy())
        .map_err(|error| format!("retained Open policy cannot be encoded: {error}"))?;
    let requested_kind = request.process_stream_kind
        .ok_or_else(|| "SourceReadback lacks stdout/stderr selector".to_owned())?;
    if original_binding != requested_binding
        || open.session_id().as_str() != binding.session_id
        || open.source_id().as_str() != binding.source_id
        || open.terminal_id().as_str() != binding.terminal_id
        || open.stream() != requested_kind
        || open_policy_json != request.process_stream_policy_json.as_deref().unwrap_or_default()
        || admission.process_binding_json != request.process_binding_json
        || admission.process_binding_sha256 != request.process_binding_sha256
    {
        return Err("SourceReadback selectors differ from the original admitted Open".to_owned());
    }
    let ready = admission.ready.as_ref()
        .ok_or_else(|| "Ready source admission lacks its committed owner result".to_owned())?;
    if ready.ready_operation_id != request.ready_operation_id.as_deref().unwrap_or_default()
        || ready.whole_source_sha256 != request.whole_source_sha256.as_deref().unwrap_or_default()
        || ready.whole_source_byte_length != request.whole_source_byte_length.unwrap_or_default()
    {
        return Err("SourceReadback differs from the admitted Ready whole-source commitment".to_owned());
    }
    let ready_receipt: serde_json::Value = serde_json::from_str(&ready.blob_ready_receipt_json)
        .map_err(|error| format!("retained BlobReadyReceipt is invalid: {error}"))?;
    let ready_id = ready_receipt.get("receipt")
        .and_then(|receipt| receipt.get("identity"))
        .and_then(|identity| identity.get("receipt_id"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "retained BlobReadyReceipt omits receipt identity".to_owned())?;
    let content_hash = ready_receipt.get("locator")
        .and_then(|locator| locator.get("hash"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "retained BlobReadyReceipt omits its immutable locator hash".to_owned())?;
    if ready_id != request.ready_receipt_ref.as_deref().unwrap_or_default()
        || format!("blob:{content_hash}") != request.process_stream_locator.as_deref().unwrap_or_default()
    {
        return Err("SourceReadback does not carry the exact owner-issued Ready receipt".to_owned());
    }
    let admission_bytes = canonical_json_bytes(&readback)
        .map_err(|error| format!("process-source readback encoding failed: {error}"))?;
    let admission_json = String::from_utf8(admission_bytes)
        .map_err(|error| format!("process-source readback is not UTF-8: {error}"))?;
    // The Ready WriteReceipt is supplied by the Kernel's correlated Ready PULL
    // and must agree with the RequestIdentity retained in the Ready row.
    let receipt = request.source_admission_write_receipt_json.as_deref()
        .ok_or_else(|| "SourceReadback lacks the committed Ready WriteReceipt".to_owned())?;
    let receipt_sha = request.source_admission_write_receipt_sha256.as_deref()
        .ok_or_else(|| "SourceReadback lacks the Ready WriteReceipt digest".to_owned())?;
    if sha256_hex(receipt.as_bytes()) != receipt_sha {
        return Err("Ready WriteReceipt digest does not match its exact bytes".to_owned());
    }
    let receipt_value: eliot_store_api::WriteReceipt = serde_json::from_str(receipt)
        .map_err(|error| format!("Ready WriteReceipt is invalid: {error}"))?;
    receipt_value.validate().map_err(|error| format!("Ready WriteReceipt failed validation: {error}"))?;
    let owner_identity: eliot_contracts::RequestIdentity = serde_json::from_str(
        &ready.ready_request_identity_json,
    ).map_err(|error| format!("Ready RequestIdentity is invalid: {error}"))?;
    owner_identity.validate()
        .map_err(|error| format!("Ready RequestIdentity failed validation: {error}"))?;
    let envelope = receipt_value.envelope.as_ref()
        .ok_or_else(|| "Ready WriteReceipt lacks its canonical envelope".to_owned())?;
    let expected_authority: eliot_receipts::AuthorityBinding = serde_json::from_str(
        &request.kernel_authority_binding_json,
    ).map_err(|error| format!("SourceReadback authority binding is invalid: {error}"))?;
    let expected_causal: eliot_receipts::CausalBinding = serde_json::from_str(
        &request.kernel_causal_binding_json,
    ).map_err(|error| format!("SourceReadback causal binding is invalid: {error}"))?;
    if receipt_value.status != eliot_store_api::WriteReceiptStatus::Committed
        || receipt_value.operation_id.as_str() != ready.ready_operation_id
        || receipt_value.idempotency_key != owner_identity.idempotency_key
        || envelope.core.request != owner_identity.request
        || envelope.core.operation.operation_id.as_str() != ready.ready_operation_id
        || envelope.core.operation.idempotency_key != owner_identity.idempotency_key
        || envelope.core.operation.state_fence != request.state_fence
        || envelope.core.authority != expected_authority
        || envelope.core.causal != expected_causal
    {
        return Err("Ready WriteReceipt does not bind the stored Ready CAS and exact Kernel authority/cause".to_owned());
    }
    Ok((
        admission_json.clone(),
        sha256_hex(admission_json.as_bytes()),
        receipt.to_owned(),
        receipt_sha.to_owned(),
    ))
}

/// Produces a closed owner answer for one Kernel-retained pull.
///
/// Launch grants resolve the current named WorkScope, module generation, and
/// Config policy owners. Stream-open/readback purposes require their separate
/// durable process-source admission and remain unavailable until that exact
/// row has been written/read or found current. Governing-document references
/// are a distinct identity domain from generated process-stream source IDs.
pub fn resolve_blob_owner_facts(
    composition: &DaemonComposition,
    request: &BlobProcessStreamOwnerFactsPullRequest,
) -> Result<BlobProcessStreamOwnerFactsPullResponse, String> {
    request
        .validate()
        .map_err(|error| format!("invalid blob owner-facts pull: {error}"))?;
    if unix_ms() >= request.deadline_ms {
        return unavailable_blob_owner_facts(
            request,
            BlobProcessStreamOwnerFactsUnavailableReason::DeadlineElapsed,
        );
    }
    if request.purpose == BlobProcessStreamOwnerFactsPullPurpose::SourceReadback {
        let Some(expected_scope_ref) = request.expected_work_scope_ref.as_deref() else {
            return unavailable_blob_owner_facts(
                request,
                BlobProcessStreamOwnerFactsUnavailableReason::ScopeGuardUnavailable,
            );
        };
        let catalog = match read_current_module_catalog_generation(
            composition,
            &request.state_fence,
            request.expected_module_id.as_deref(),
            request.expected_generation_id.as_deref(),
        ) {
            Ok(value) => value,
            Err(_) => return unavailable_blob_owner_facts(
                request,
                BlobProcessStreamOwnerFactsUnavailableReason::StaleBinding,
            ),
        };
        let readback = match composition.current_testd_blob_work_scope_readback(&request.state_fence) {
            Ok(Some(value)) => value,
            _ => return unavailable_blob_owner_facts(
                request,
                BlobProcessStreamOwnerFactsUnavailableReason::ScopeGuardUnavailable,
            ),
        };
        if readback.snapshot.binding.scope.scope_ref != expected_scope_ref {
            return unavailable_blob_owner_facts(
                request,
                BlobProcessStreamOwnerFactsUnavailableReason::StaleBinding,
            );
        }
        let scope = match canonical_current_work_scope_source_receipt(&readback.snapshot) {
            Ok(value) if value.work_scope_snapshot_sha256 == readback.value_digest => value,
            _ => return unavailable_blob_owner_facts(
                request,
                BlobProcessStreamOwnerFactsUnavailableReason::StaleBinding,
            ),
        };
        let policy = match read_current_blob_policy_residency(
            composition,
            &request.state_fence,
            expected_scope_ref,
        ) {
            Ok(value) => value,
            Err(_) => return unavailable_blob_owner_facts(
                request,
                BlobProcessStreamOwnerFactsUnavailableReason::PolicyUnavailable,
            ),
        };
        let (source_readback_json, source_readback_sha256, ready_receipt_json, ready_receipt_sha256) =
            match source_readback_admission(composition, request) {
                Ok(value) => value,
                Err(_) => return unavailable_blob_owner_facts(
                    request,
                    BlobProcessStreamOwnerFactsUnavailableReason::SourceReceiptUnavailable,
                ),
            };
        return available_launch_owner_facts(
            composition,
            request,
            &scope,
            &policy,
            &catalog,
            Some((
                &source_readback_json,
                &source_readback_sha256,
                &ready_receipt_json,
                &ready_receipt_sha256,
            )),
        );
    }
    if request.purpose != BlobProcessStreamOwnerFactsPullPurpose::LaunchGrant {
        return unavailable_blob_owner_facts(
            request,
            BlobProcessStreamOwnerFactsUnavailableReason::SourceReceiptUnavailable,
        );
    }
    let Some(expected_scope_ref) = request.expected_work_scope_ref.as_deref() else {
        return unavailable_blob_owner_facts(
            request,
            BlobProcessStreamOwnerFactsUnavailableReason::ScopeGuardUnavailable,
        );
    };
    let catalog = match read_current_module_catalog_generation(
        composition,
        &request.state_fence,
        request.expected_module_id.as_deref(),
        request.expected_generation_id.as_deref(),
    ) {
        Ok(value) => value,
        Err(_) => {
            return unavailable_blob_owner_facts(
                request,
                BlobProcessStreamOwnerFactsUnavailableReason::StaleBinding,
            );
        }
    };
    let reason = if unix_ms() >= request.deadline_ms {
        BlobProcessStreamOwnerFactsUnavailableReason::DeadlineElapsed
    } else {
        match composition.current_testd_blob_work_scope_readback(&request.state_fence) {
            Err(_) => BlobProcessStreamOwnerFactsUnavailableReason::StaleBinding,
            Ok(None) => BlobProcessStreamOwnerFactsUnavailableReason::ScopeGuardUnavailable,
            Ok(Some(readback)) => {
                let snapshot = &readback.snapshot;
                if expected_scope_ref != snapshot.binding.scope.scope_ref.as_str() {
                    BlobProcessStreamOwnerFactsUnavailableReason::StaleBinding
                } else {
                    match snapshot.source_admission.as_ref() {
                        None => {
                            BlobProcessStreamOwnerFactsUnavailableReason::SourceReceiptUnavailable
                        }
                        Some(source)
                            if source.sources.scope_ref != snapshot.binding.scope.scope_ref
                                || source.sources.generation
                                    != snapshot.binding.governing_source_generation =>
                        {
                            BlobProcessStreamOwnerFactsUnavailableReason::SourceReceiptUnavailable
                        }
                        Some(_) => {
                            let scope = match canonical_current_work_scope_source_receipt(snapshot)
                            {
                                Ok(value)
                                    if value.work_scope_snapshot_sha256
                                        == readback.value_digest =>
                                {
                                    value
                                }
                                _ => {
                                    return unavailable_blob_owner_facts(
                                        request,
                                        BlobProcessStreamOwnerFactsUnavailableReason::StaleBinding,
                                    );
                                }
                            };
                            let policy = match read_current_blob_policy_residency(
                                composition,
                                &request.state_fence,
                                snapshot.binding.scope.scope_ref.as_str(),
                            ) {
                                Ok(value) => value,
                                Err(_) => {
                                    return unavailable_blob_owner_facts(
                                        request,
                                        BlobProcessStreamOwnerFactsUnavailableReason::PolicyUnavailable,
                                    );
                                }
                            };
                            return match available_launch_owner_facts(
                                composition,
                                request,
                                &scope,
                                &policy,
                                &catalog,
                                None,
                            ) {
                                Ok(response) => Ok(response),
                                Err(_) => unavailable_blob_owner_facts(
                                    request,
                                    BlobProcessStreamOwnerFactsUnavailableReason::AuthorityUnavailable,
                                ),
                            };
                        }
                    }
                }
            }
        }
    };
    unavailable_blob_owner_facts(request, reason)
}
