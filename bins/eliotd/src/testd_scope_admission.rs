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
    BlobProcessStreamOwnerFactsAvailable, BlobProcessStreamOwnerFactsPullRequest,
    BlobProcessStreamOwnerFactsPullResponse, BlobProcessStreamOwnerFactsUnavailableReason,
    BlobProcessStreamVerifiedOwnerFacts,
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

fn verified_owner_facts(
    composition: &DaemonComposition,
    request: &BlobProcessStreamOwnerFactsPullRequest,
    scope: &CurrentWorkScopeSourceReceipt,
    policy: &CurrentBlobPolicyResidency,
    catalog: &CurrentModuleCatalogGeneration,
) -> Result<(BlobProcessStreamVerifiedOwnerFacts, String, String), String> {
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
    Ok((facts, facts_json, facts_sha256))
}

fn available_launch_owner_facts(
    composition: &DaemonComposition,
    request: &BlobProcessStreamOwnerFactsPullRequest,
    scope: &CurrentWorkScopeSourceReceipt,
    policy: &CurrentBlobPolicyResidency,
    catalog: &CurrentModuleCatalogGeneration,
    source_admission: Option<(&str, &str, &str, &str)>,
) -> Result<BlobProcessStreamOwnerFactsPullResponse, String> {
    let (_, facts_json, facts_sha256) =
        verified_owner_facts(composition, request, scope, policy, catalog)?;
    let facts: BlobProcessStreamVerifiedOwnerFacts = serde_json::from_str(&facts_json)
        .map_err(|error| format!("verified owner facts did not round trip: {error}"))?;
    let currentness_sha256 = facts.currentness_sha256.clone();
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
        outcome: BlobProcessStreamOwnerFactsPullOutcome::Available(Box::new(
            BlobProcessStreamOwnerFactsAvailable {
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
        )),
    };
    response
        .validate_for_request(request)
        .map_err(|error| format!("invalid available owner-facts response: {error}"))?;
    Ok(response)
}

fn store_open_source_admission(
    composition: &DaemonComposition,
    request: &BlobProcessStreamOwnerFactsPullRequest,
) -> Result<(String, String, String, String), String> {
    use eliot_store_api::blob_process_source_admission::{
        BlobProcessSourceAdmission, BlobProcessSourceAdmissionIdentity,
        BlobProcessSourceAdmissionPhase,
    };
    use eliot_process::stream_sink::ProcessStreamSinkOpenRequest;

    let scope_ref = request.expected_work_scope_ref.as_deref()
        .ok_or_else(|| "StoreOpen lacks its retained WorkScope selector".to_owned())?;
    let pending_json = request.source_admission_json.as_deref()
        .ok_or_else(|| "StoreOpen lacks its exact Pending admission".to_owned())?;
    let pending_sha = request.source_admission_sha256.as_deref()
        .ok_or_else(|| "StoreOpen lacks its Pending admission digest".to_owned())?;
    let receipt_json = request.source_admission_write_receipt_json.as_deref()
        .ok_or_else(|| "StoreOpen lacks its Pending WriteReceipt".to_owned())?;
    let receipt_sha = request.source_admission_write_receipt_sha256.as_deref()
        .ok_or_else(|| "StoreOpen lacks its Pending WriteReceipt digest".to_owned())?;
    if sha256_hex(pending_json.as_bytes()) != pending_sha
        || sha256_hex(receipt_json.as_bytes()) != receipt_sha
    {
        return Err("StoreOpen Pending proof digest mismatch".to_owned());
    }
    let pending: BlobProcessSourceAdmission = serde_json::from_str(pending_json)
        .map_err(|error| format!("StoreOpen Pending admission is invalid: {error}"))?;
    pending.validate().map_err(|error| format!("StoreOpen Pending admission failed validation: {error}"))?;
    let identity = BlobProcessSourceAdmissionIdentity {
        work_scope_ref: scope_ref.to_owned(),
        session_id: pending.identity.session_id.clone(),
        source_id: pending.identity.source_id.clone(),
        process_binding_sha256: request.process_binding_sha256.clone(),
    };
    if pending.phase != BlobProcessSourceAdmissionPhase::Pending
        || pending.owner_revision != 1
        || pending.identity != identity
        || pending.state_fence != request.state_fence
        || pending.pending_operation_id != request.source_admission_operation_id.as_deref().unwrap_or_default()
        || pending.process_binding_json != request.process_binding_json
        || pending.open_request_json != request.open_request_json.as_deref().unwrap_or_default()
    {
        return Err("StoreOpen selectors differ from the exact Pending source admission".to_owned());
    }
    let open: ProcessStreamSinkOpenRequest = serde_json::from_str(&pending.open_request_json)
        .map_err(|error| format!("StoreOpen Open request is invalid: {error}"))?;
    open.validate().map_err(|error| format!("StoreOpen Open request failed validation: {error}"))?;
    if sha256_hex(pending.process_binding_json.as_bytes()) != pending.process_binding_sha256
        || sha256_hex(pending.open_request_json.as_bytes()) != pending.open_request_sha256
        || open.binding().state_fence() != &request.state_fence
        || open.session_id().as_str() != pending.identity.session_id
        || open.source_id().as_str() != pending.identity.source_id
    {
        return Err("StoreOpen Pending source does not bind the exact Open request".to_owned());
    }
    let scope_readback = composition.current_testd_blob_work_scope_readback(&request.state_fence)?
        .ok_or_else(|| "StoreOpen WorkScope owner is unavailable".to_owned())?;
    if scope_readback.snapshot.binding.scope.scope_ref != scope_ref
        || scope_readback.owner_revision != pending.work_scope_owner_revision
        || scope_readback.value_digest != pending.work_scope_owner_digest
    {
        return Err("StoreOpen Pending source is stale against the current WorkScope".to_owned());
    }
    let current = composition.current_testd_blob_process_source_admission(
        &identity, &request.state_fence,
    )?.ok_or_else(|| "StoreOpen Pending source row is absent".to_owned())?;
    current.validate_for(&identity, &request.state_fence)
        .map_err(|error| format!("StoreOpen current source row is invalid: {error}"))?;
    if current.admission != pending || current.value_digest != pending_sha || current.owner_revision != 1 {
        return Err("StoreOpen Pending source row differs from its exact CAS".to_owned());
    }
    let receipt: eliot_store_api::WriteReceipt = serde_json::from_str(receipt_json)
        .map_err(|error| format!("StoreOpen Pending WriteReceipt is invalid: {error}"))?;
    receipt.validate().map_err(|error| format!("StoreOpen Pending WriteReceipt failed validation: {error}"))?;
    let envelope = receipt.envelope.as_ref()
        .ok_or_else(|| "StoreOpen Pending WriteReceipt has no canonical envelope".to_owned())?;
    let original_identity: eliot_contracts::RequestIdentity = serde_json::from_str(
        &pending.pending_request_identity_json,
    ).map_err(|error| format!("Pending source RequestIdentity is invalid: {error}"))?;
    let expected_authority: eliot_receipts::AuthorityBinding = serde_json::from_str(
        &request.kernel_authority_binding_json,
    ).map_err(|error| format!("StoreOpen authority binding is invalid: {error}"))?;
    let expected_causal: eliot_receipts::CausalBinding = serde_json::from_str(
        &request.kernel_causal_binding_json,
    ).map_err(|error| format!("StoreOpen causal binding is invalid: {error}"))?;
    let pending_sequence = envelope.core.causal.transaction_sequence.value();
    let expected_sequence = pending_sequence.checked_add(1)
        .ok_or_else(|| "StoreOpen causal sequence is exhausted".to_owned())?;
    if receipt.status != eliot_store_api::WriteReceiptStatus::Committed
        || receipt.operation_id.as_str() != pending.pending_operation_id
        || envelope.core.operation.operation_id.as_str() != pending.pending_operation_id
        || envelope.core.request != original_identity.request
        || receipt.idempotency_key != original_identity.idempotency_key
        || envelope.core.authority != expected_authority
        || expected_causal.state_fence != request.state_fence
        || expected_causal.transaction_sequence.value() != expected_sequence
        || expected_causal.parent_receipt_id.as_ref() != Some(&envelope.identity.receipt_id)
        || expected_causal.predecessor_receipt_ids != vec![envelope.identity.receipt_id.clone()]
    {
        return Err("StoreOpen owner context is not the exact successor of Pending".to_owned());
    }
    let readback_bytes = canonical_json_bytes(&current)
        .map_err(|error| format!("StoreOpen named readback cannot be encoded: {error}"))?;
    let readback_json = String::from_utf8(readback_bytes)
        .map_err(|error| format!("StoreOpen named readback is not UTF-8: {error}"))?;
    Ok((
        readback_json.clone(),
        sha256_hex(readback_json.as_bytes()),
        receipt_json.to_owned(),
        receipt_sha.to_owned(),
    ))
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

async fn commit_source_admission_update(
    composition: &DaemonComposition,
    request: &BlobProcessStreamOwnerFactsPullRequest,
    identity: &eliot_contracts::RequestIdentity,
    operation_id: &str,
    expected_revision: u64,
    expected_digest: &str,
    admission: &eliot_store_api::blob_process_source_admission::BlobProcessSourceAdmission,
    scope: &eliot_governor::WorkScopeBindingSnapshot,
) -> Result<eliot_store_api::WriteReceipt, String> {
    use eliot_canonical::CanonicalWriteEnvelope;
    use eliot_store_api::{
        EffectClass, EventProjectionRelationIntents, ScopeId, SecurityContext,
        TransitionClass, blob_process_source_admission_mutation,
        generated_operation_manifests, operation_manifest_set_digest,
        supported_admission_contract_set_digest,
    };

    let authority: eliot_receipts::AuthorityBinding = serde_json::from_str(
        &request.kernel_authority_binding_json,
    ).map_err(|error| format!("source-admission authority is invalid: {error}"))?;
    let causal: eliot_receipts::CausalBinding = serde_json::from_str(
        &request.kernel_causal_binding_json,
    ).map_err(|error| format!("source-admission cause is invalid: {error}"))?;
    let operation: eliot_receipts::OperationBinding = serde_json::from_str(
        request.kernel_operation_binding_json.as_deref()
            .ok_or_else(|| "source-admission operation binding is absent".to_owned())?,
    ).map_err(|error| format!("source-admission operation binding is invalid: {error}"))?;
    let operation_sha256 = request.kernel_operation_binding_sha256.as_deref()
        .ok_or_else(|| "source-admission operation digest is absent".to_owned())?;
    let operation_id = eliot_contracts::OperationId::new(operation_id.to_owned())
        .map_err(|error| format!("source-admission operation ID is invalid: {error}"))?;
    if identity.validate().is_err()
        || identity.request.state_fence != request.state_fence
        || identity.request.metadata.state_fence != request.state_fence
        || authority.state_fence != request.state_fence
        || authority.authority_epoch != request.state_fence.authority_epoch
        || causal.state_fence != request.state_fence
        || operation.operation_id != operation_id
        || operation.request_id != identity.request.metadata.request_id
        || operation.idempotency_key != identity.idempotency_key
        || operation.operation_kind != eliot_blob_api::wire::BLOB_PROCESS_STREAM_WIRE_ID
        || operation.effect != EffectClass::ReversibleMutation
        || operation.state_fence != request.state_fence
        || sha256_hex(request.kernel_operation_binding_json.as_deref().unwrap_or_default().as_bytes())
            != operation_sha256
        || identity.request.metadata.product_id.as_str() != request.product_id
        || identity.request.metadata.source_id.as_str() != request.source_id
        || identity.request.metadata.task_id.as_ref().map(ToString::to_string)
            != request.task_id
        || identity.request.metadata.session_id.as_ref().map(ToString::to_string)
            != request.session_id
        || identity.request.metadata.request_id.as_str() != operation.request_id.as_str()
    {
        return Err("source-admission identity, operation, authority, or cause does not match its retained PULL".to_owned());
    }
    let command = blob_process_source_admission_mutation(
        admission,
        expected_revision,
        expected_digest,
        &admission.admission_ref().map_err(|error| error.to_string())?,
    ).map_err(|error| format!("source-admission mutation is invalid: {error}"))?;
    let manifests = generated_operation_manifests()
        .map_err(|error| format!("current operation catalogue is unavailable: {error}"))?;
    let envelope = CanonicalWriteEnvelope {
        operation_id,
        request: identity.request.metadata.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        scope_id: ScopeId::new(scope.binding.scope.scope_ref.as_str())
            .map_err(|error| format!("WorkScope identity is invalid: {error}"))?,
        task_id: identity.request.metadata.task_id.as_ref().map(ToString::to_string),
        transition_class: TransitionClass::RecoverySchema,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: supported_admission_contract_set_digest()
            .map_err(|error| format!("admission contract set is unavailable: {error}"))?,
        operation_manifest_digest: operation_manifest_set_digest(&manifests)
            .map_err(|error| format!("operation manifest set is invalid: {error}"))?,
        semantic_commands: vec![command],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext {
            authority_binding: Some(authority),
            causal_binding: Some(causal),
            ..SecurityContext::default()
        },
        required_proof_and_approval_refs: Vec::new(),
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: Vec::new(),
    };
    let prepared = envelope.prepare()
        .map_err(|error| format!("source-admission canonical preparation failed: {error}"))?;
    if prepared.security.authority_binding.as_ref()
            != Some(&serde_json::from_str::<eliot_receipts::AuthorityBinding>(
                &request.kernel_authority_binding_json,
            ).map_err(|error| format!("source-admission authority is invalid: {error}"))?)
        || prepared.security.causal_binding.as_ref()
            != Some(&serde_json::from_str::<eliot_receipts::CausalBinding>(
                &request.kernel_causal_binding_json,
            ).map_err(|error| format!("source-admission cause is invalid: {error}"))?)
    {
        return Err("canonical preparation changed the retained source authority or cause".to_owned());
    }
    composition.commit_blob_process_source_admission(
        identity,
        envelope,
        &scope.binding,
        &scope.source_admission.as_ref()
            .ok_or_else(|| "current WorkScope has no admitted source closure".to_owned())?.sources,
        &scope.source_admission.as_ref()
            .ok_or_else(|| "current WorkScope has no admitted source privacy".to_owned())?.privacy,
    ).await
}

async fn resolve_source_admission_update(
    composition: &DaemonComposition,
    request: &BlobProcessStreamOwnerFactsPullRequest,
) -> Result<BlobProcessStreamOwnerFactsPullResponse, String> {
    use eliot_blob_api::wire::{
        BlobProcessStreamOwnerFactsPullPurpose, BlobProcessStreamOwnerFactsPullOutcome,
    };
    use eliot_store_api::blob_process_source_admission::{
        BlobProcessSourceAdmission, BlobProcessSourceAdmissionIdentity,
        BlobProcessSourceAdmissionPhase, BlobProcessSourceReadyCommitment,
    };
    use eliot_process::stream_sink::ProcessStreamSinkOpenRequest;

    if !matches!(request.purpose,
        BlobProcessStreamOwnerFactsPullPurpose::OpenAdmission
            | BlobProcessStreamOwnerFactsPullPurpose::ReadyAttach)
    {
        return Err("source admission updater received an unrelated PULL purpose".to_owned());
    }
    if unix_ms() >= request.deadline_ms {
        return Err("source admission update deadline elapsed".to_owned());
    }
    let expected_scope_ref = request.expected_work_scope_ref.as_deref()
        .ok_or_else(|| "source admission PULL lacks its retained WorkScope selector".to_owned())?;
    let catalog = read_current_module_catalog_generation(
        composition,
        &request.state_fence,
        request.expected_module_id.as_deref(),
        request.expected_generation_id.as_deref(),
    )?;
    let work_scope = composition.current_testd_blob_work_scope_readback(&request.state_fence)?
        .ok_or_else(|| "current matched WorkScope readback is unavailable".to_owned())?;
    let snapshot = &work_scope.snapshot;
    if snapshot.binding.scope.scope_ref != expected_scope_ref {
        return Err("source admission PULL selected another WorkScope".to_owned());
    }
    let scope = canonical_current_work_scope_source_receipt(snapshot)?;
    if scope.work_scope_snapshot_sha256 != work_scope.value_digest {
        return Err("current WorkScope digest differs from its owner readback".to_owned());
    }
    let source_owner = snapshot.source_admission.as_ref()
        .ok_or_else(|| "current WorkScope lacks its admitted source closure".to_owned())?;
    let policy = read_current_blob_policy_residency(
        composition,
        &request.state_fence,
        expected_scope_ref,
    )?;
    let owner_identity_json = request.owner_update_identity_json.as_deref()
        .ok_or_else(|| "source admission PULL lacks its exact owner RequestIdentity".to_owned())?;
    let owner_identity_sha256 = request.owner_update_identity_sha256.as_deref()
        .ok_or_else(|| "source admission PULL lacks its owner identity digest".to_owned())?;
    let owner_identity: eliot_contracts::RequestIdentity = serde_json::from_str(owner_identity_json)
        .map_err(|error| format!("owner RequestIdentity is invalid: {error}"))?;
    let canonical_identity = canonical_json_bytes(&owner_identity)
        .map_err(|error| format!("owner RequestIdentity cannot be canonicalized: {error}"))?;
    if sha256_hex(owner_identity_json.as_bytes()) != owner_identity_sha256
        || canonical_identity.as_slice() != owner_identity_json.as_bytes()
    {
        return Err("source admission RequestIdentity is not its exact canonical payload".to_owned());
    }
    let operation_id = match request.purpose {
        BlobProcessStreamOwnerFactsPullPurpose::OpenAdmission => request.source_admission_operation_id.as_deref(),
        BlobProcessStreamOwnerFactsPullPurpose::ReadyAttach => request.ready_operation_id.as_deref(),
        _ => None,
    }.ok_or_else(|| "source admission operation ID is absent".to_owned())?;
    let process_binding: eliot_process::ProcessExecutionBinding = serde_json::from_str(
        &request.process_binding_json,
    ).map_err(|error| format!("retained process binding is invalid: {error}"))?;
    let process_binding_bytes = canonical_json_bytes(&process_binding)
        .map_err(|error| format!("process binding cannot be encoded: {error}"))?;
    if sha256_hex(&process_binding_bytes) != request.process_binding_sha256
        || String::from_utf8(process_binding_bytes).ok().as_deref()
            != Some(request.process_binding_json.as_str())
        || owner_identity.request.state_fence != request.state_fence
        || owner_identity.request.metadata.state_fence != request.state_fence
        || owner_identity.request.metadata.product_id.as_str() != request.product_id
        || owner_identity.request.metadata.source_id.as_str() != request.source_id
        || owner_identity.request.metadata.task_id.as_ref().map(ToString::to_string)
            != request.task_id
        || owner_identity.request.metadata.session_id.as_ref().map(ToString::to_string)
            != request.session_id
        || owner_identity.deadline_unix_ms != request.deadline_ms
        || request.outer_request_sha256 != sha256_hex(owner_identity_json.as_bytes())
    {
        return Err("source admission owner identity differs from its exact Kernel PULL".to_owned());
    }
    let admission_identity = match request.purpose {
        BlobProcessStreamOwnerFactsPullPurpose::OpenAdmission => {
            let open_json = request.open_request_json.as_deref()
                .ok_or_else(|| "OpenAdmission PULL lacks its exact Open request".to_owned())?;
            let open_sha256 = request.open_request_sha256.as_deref()
                .ok_or_else(|| "OpenAdmission PULL lacks its Open request digest".to_owned())?;
            if sha256_hex(open_json.as_bytes()) != open_sha256 {
                return Err("Open request digest differs from its exact bytes".to_owned());
            }
            let open: ProcessStreamSinkOpenRequest = serde_json::from_str(open_json)
                .map_err(|error| format!("Open request is invalid: {error}"))?;
            open.validate().map_err(|error| format!("Open request failed validation: {error}"))?;
            let open_binding = canonical_json_bytes(open.binding())
                .map_err(|error| format!("Open process binding cannot be encoded: {error}"))?;
            if String::from_utf8(open_binding.clone()).ok().as_deref()
                    != Some(request.process_binding_json.as_str())
                || sha256_hex(&open_binding) != request.process_binding_sha256
                || open.binding().state_fence() != &request.state_fence
                || open.session_id().as_str() != request.session_id.as_deref().unwrap_or_default()
            {
                return Err("Open request differs from the exact admitted process binding".to_owned());
            }
            BlobProcessSourceAdmissionIdentity {
                work_scope_ref: expected_scope_ref.to_owned(),
                session_id: open.session_id().as_str().to_owned(),
                source_id: open.source_id().as_str().to_owned(),
                process_binding_sha256: request.process_binding_sha256.clone(),
            }
        }
        BlobProcessStreamOwnerFactsPullPurpose::ReadyAttach => {
            let pending_json = request.source_admission_json.as_deref()
                .ok_or_else(|| "ReadyAttach PULL lacks its exact Pending admission".to_owned())?;
            let pending_sha256 = request.source_admission_sha256.as_deref()
                .ok_or_else(|| "ReadyAttach PULL lacks its Pending admission digest".to_owned())?;
            if sha256_hex(pending_json.as_bytes()) != pending_sha256 {
                return Err("Pending admission digest differs from its exact bytes".to_owned());
            }
            let pending: BlobProcessSourceAdmission = serde_json::from_str(pending_json)
                .map_err(|error| format!("Pending admission is invalid: {error}"))?;
            pending.validate().map_err(|error| format!("Pending admission failed validation: {error}"))?;
            if pending.phase != BlobProcessSourceAdmissionPhase::Pending
                || pending.owner_revision != 1
                || pending.identity.work_scope_ref != expected_scope_ref
                || pending.identity.process_binding_sha256 != request.process_binding_sha256
                || pending.state_fence != request.state_fence
                || Some(pending.pending_operation_id.as_str()) != request.source_admission_operation_id.as_deref()
                || pending.work_scope_owner_revision != work_scope.owner_revision
                || pending.work_scope_owner_digest != work_scope.value_digest
                || pending.open_request_json.is_empty()
            {
                return Err("ReadyAttach Pending admission differs from the fresh source owner".to_owned());
            }
            let current = composition.current_testd_blob_process_source_admission(
                &pending.identity,
                &request.state_fence,
            )?.ok_or_else(|| "fresh Pending process-source owner row is absent".to_owned())?;
            current.validate_for(&pending.identity, &request.state_fence)
                .map_err(|error| format!("fresh Pending source row is invalid: {error}"))?;
            if current.admission != pending {
                return Err("fresh Pending row differs from the exact ReadyAttach predecessor".to_owned());
            }
            let pending_receipt_json = request.source_admission_write_receipt_json.as_deref()
                .ok_or_else(|| "ReadyAttach PULL lacks the Pending WriteReceipt".to_owned())?;
            let pending_receipt_sha = request.source_admission_write_receipt_sha256.as_deref()
                .ok_or_else(|| "ReadyAttach PULL lacks the Pending WriteReceipt digest".to_owned())?;
            if sha256_hex(pending_receipt_json.as_bytes()) != pending_receipt_sha {
                return Err("Pending WriteReceipt digest differs from its exact bytes".to_owned());
            }
            let pending_receipt: eliot_store_api::WriteReceipt = serde_json::from_str(pending_receipt_json)
                .map_err(|error| format!("Pending WriteReceipt is invalid: {error}"))?;
            pending_receipt.validate().map_err(|error| format!("Pending WriteReceipt failed validation: {error}"))?;
            let pending_envelope = pending_receipt.envelope.as_ref()
                .ok_or_else(|| "Pending WriteReceipt lacks its canonical envelope".to_owned())?;
            let pending_identity: eliot_contracts::RequestIdentity = serde_json::from_str(
                &pending.pending_request_identity_json,
            ).map_err(|error| format!("Pending RequestIdentity is invalid: {error}"))?;
            let expected_authority: eliot_receipts::AuthorityBinding = serde_json::from_str(
                &request.kernel_authority_binding_json,
            ).map_err(|error| format!("Ready authority binding is invalid: {error}"))?;
            let expected_causal: eliot_receipts::CausalBinding = serde_json::from_str(
                &request.kernel_causal_binding_json,
            ).map_err(|error| format!("Ready causal binding is invalid: {error}"))?;
            let pending_receipt_id = &pending_envelope.identity.receipt_id;
            let expected_sequence = pending_envelope.core.causal.transaction_sequence.value()
                .checked_add(1).ok_or_else(|| "Pending transaction sequence exhausted".to_owned())?;
            if pending_receipt.status != eliot_store_api::WriteReceiptStatus::Committed
                || pending_receipt.operation_id.as_str() != pending.pending_operation_id
                || pending_envelope.core.operation.operation_id.as_str() != pending.pending_operation_id
                || pending_envelope.core.operation.state_fence != request.state_fence
                || pending_envelope.core.request != pending_identity.request
                || pending_receipt.idempotency_key != pending_identity.idempotency_key
                || pending_envelope.core.authority != expected_authority
                || expected_causal.state_fence != request.state_fence
                || expected_causal.transaction_sequence.value() != expected_sequence
                || expected_causal.parent_receipt_id.as_ref() != Some(pending_receipt_id)
                || expected_causal.predecessor_receipt_ids != vec![pending_receipt_id.clone()]
            {
                return Err("ReadyAttach is not chained to the exact Pending WriteReceipt".to_owned());
            }
            pending.identity
        }
        _ => unreachable!("purpose was checked above"),
    };
    if admission_identity.process_binding_sha256 != request.process_binding_sha256
        || admission_identity.work_scope_ref != expected_scope_ref
    {
        return Err("source admission identity differs from the request process or scope".to_owned());
    }
    let existing = composition.current_testd_blob_process_source_admission(
        &admission_identity,
        &request.state_fence,
    )?;
    let (expected_revision, expected_digest, admission) = match request.purpose {
        BlobProcessStreamOwnerFactsPullPurpose::OpenAdmission => {
            let (_, facts_json, facts_sha256) = verified_owner_facts(
                composition, request, &scope, &policy, &catalog,
            )?;
            let open_json = request.open_request_json.as_deref().unwrap_or_default();
            let admission = BlobProcessSourceAdmission {
                schema: eliot_store_api::blob_process_source_admission::BLOB_PROCESS_SOURCE_ADMISSION_SCHEMA.to_owned(),
                phase: BlobProcessSourceAdmissionPhase::Pending,
                owner_revision: 1,
                state_fence: request.state_fence.clone(),
                identity: admission_identity.clone(),
                pending_operation_id: operation_id.to_owned(),
                pending_request_identity_json: owner_identity_json.to_owned(),
                pending_request_identity_sha256: owner_identity_sha256.to_owned(),
                process_binding_json: request.process_binding_json.clone(),
                process_binding_sha256: request.process_binding_sha256.clone(),
                open_request_json: open_json.to_owned(),
                open_request_sha256: request.open_request_sha256.clone().unwrap_or_default(),
                work_scope_owner_revision: work_scope.owner_revision,
                work_scope_owner_digest: work_scope.value_digest.clone(),
                owner_facts_json: facts_json,
                owner_facts_sha256: facts_sha256,
                ready: None,
            };
            admission.validate().map_err(|error| format!("new Pending admission is invalid: {error}"))?;
            (0, "absent".to_owned(), admission)
        }
        BlobProcessStreamOwnerFactsPullPurpose::ReadyAttach => {
            let pending_json = request.source_admission_json.as_deref().unwrap_or_default();
            let pending_sha = request.source_admission_sha256.as_deref().unwrap_or_default();
            let pending: BlobProcessSourceAdmission = serde_json::from_str(pending_json)
                .map_err(|error| format!("Pending admission is invalid: {error}"))?;
            let current = existing.as_ref().ok_or_else(|| "Pending source admission row is absent".to_owned())?;
            current.validate_for(&admission_identity, &request.state_fence)
                .map_err(|error| format!("Pending source admission readback is invalid: {error}"))?;
            let retrying_ready = current.admission.phase == BlobProcessSourceAdmissionPhase::Ready
                && current.owner_revision == 2
                && current.admission.ready.as_ref().is_some_and(|ready| {
                    Some(ready.ready_operation_id.as_str()) == request.ready_operation_id.as_deref()
                        && ready.ready_request_identity_json == owner_identity_json
                        && ready.pending_admission_json == pending_json
                        && ready.pending_admission_sha256 == pending_sha
                        && Some(ready.blob_ready_receipt_json.as_str()) == request.blob_ready_receipt_json.as_deref()
                        && Some(ready.blob_ready_receipt_sha256.as_str()) == request.blob_ready_receipt_sha256.as_deref()
                        && Some(ready.whole_source_sha256.as_str()) == request.whole_source_sha256.as_deref()
                        && Some(ready.whole_source_byte_length) == request.whole_source_byte_length
                });
            let exact_pending = current.admission == pending
                && current.value_digest == pending_sha
                && current.owner_revision == 1;
            if (!exact_pending && !retrying_ready)
                || pending.phase != BlobProcessSourceAdmissionPhase::Pending
            {
                return Err("ReadyAttach CAS predecessor differs from fresh Pending source read".to_owned());
            }
            let receipt_json = request.blob_ready_receipt_json.as_deref()
                .ok_or_else(|| "ReadyAttach lacks the owner-issued BlobReadyReceipt".to_owned())?;
            let receipt_sha = request.blob_ready_receipt_sha256.as_deref()
                .ok_or_else(|| "ReadyAttach lacks the BlobReadyReceipt digest".to_owned())?;
            if sha256_hex(receipt_json.as_bytes()) != receipt_sha {
                return Err("BlobReadyReceipt digest differs from its exact bytes".to_owned());
            }
            let ready_receipt: serde_json::Value = serde_json::from_str(receipt_json)
                .map_err(|error| format!("BlobReadyReceipt JSON is invalid: {error}"))?;
            let receipt_id = ready_receipt.pointer("/receipt/identity/receipt_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "BlobReadyReceipt omitted its receipt identity".to_owned())?;
            let locator_hash = ready_receipt.pointer("/locator/hash")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "BlobReadyReceipt omitted its immutable locator hash".to_owned())?;
            let whole_sha = request.whole_source_sha256.as_deref()
                .ok_or_else(|| "ReadyAttach lacks whole-source digest".to_owned())?;
            let whole_length = request.whole_source_byte_length
                .ok_or_else(|| "ReadyAttach lacks whole-source length".to_owned())?;
            let open: ProcessStreamSinkOpenRequest = serde_json::from_str(&pending.open_request_json)
                .map_err(|error| format!("Pending Open request is invalid: {error}"))?;
            open.validate().map_err(|error| format!("Pending Open request failed validation: {error}"))?;
            if ready_receipt.get("plaintext_sha256").and_then(serde_json::Value::as_str)
                    != Some(whole_sha)
                || ready_receipt.get("plaintext_length").and_then(serde_json::Value::as_u64)
                    != Some(whole_length)
                || locator_hash.is_empty()
                || open.binding().state_fence() != &request.state_fence
                || open.session_id().as_str() != pending.identity.session_id.as_str()
                || open.source_id().as_str() != pending.identity.source_id.as_str()
            {
                return Err("BlobReadyReceipt differs from its whole-source commitment".to_owned());
            }
            let ready_identity_sha = owner_identity_sha256.to_owned();
            let ready_op = request.ready_operation_id.as_deref()
                .ok_or_else(|| "ReadyAttach lacks its Ready operation ID".to_owned())?;
            let ready = BlobProcessSourceReadyCommitment {
                ready_operation_id: ready_op.to_owned(),
                ready_request_identity_json: owner_identity_json.to_owned(),
                ready_request_identity_sha256: ready_identity_sha,
                pending_admission_json: pending_json.to_owned(),
                pending_admission_sha256: pending_sha.to_owned(),
                whole_source_sha256: whole_sha.to_owned(),
                whole_source_byte_length: whole_length,
                blob_ready_receipt_json: receipt_json.to_owned(),
                blob_ready_receipt_sha256: receipt_sha.to_owned(),
            };
            let admission = BlobProcessSourceAdmission {
                schema: pending.schema.clone(),
                phase: BlobProcessSourceAdmissionPhase::Ready,
                owner_revision: 2,
                state_fence: pending.state_fence.clone(),
                identity: pending.identity.clone(),
                pending_operation_id: pending.pending_operation_id.clone(),
                pending_request_identity_json: pending.pending_request_identity_json.clone(),
                pending_request_identity_sha256: pending.pending_request_identity_sha256.clone(),
                process_binding_json: pending.process_binding_json.clone(),
                process_binding_sha256: pending.process_binding_sha256.clone(),
                open_request_json: pending.open_request_json.clone(),
                open_request_sha256: pending.open_request_sha256.clone(),
                work_scope_owner_revision: pending.work_scope_owner_revision,
                work_scope_owner_digest: pending.work_scope_owner_digest.clone(),
                owner_facts_json: pending.owner_facts_json.clone(),
                owner_facts_sha256: pending.owner_facts_sha256.clone(),
                ready: Some(ready),
            };
            admission.validate().map_err(|error| format!("new Ready admission is invalid: {error}"))?;
            (1, pending_sha.to_owned(), admission)
        }
        _ => unreachable!("purpose was checked above"),
    };
    if let Some(current) = existing.as_ref() {
        current.validate_for(&admission_identity, &request.state_fence)
            .map_err(|error| format!("existing source admission is invalid: {error}"))?;
        let exact_owner_update = match request.purpose {
            BlobProcessStreamOwnerFactsPullPurpose::OpenAdmission =>
                current.owner_revision == admission.owner_revision && current.admission == admission,
            BlobProcessStreamOwnerFactsPullPurpose::ReadyAttach => {
                let predecessor: BlobProcessSourceAdmission = serde_json::from_str(
                    request.source_admission_json.as_deref().unwrap_or_default(),
                ).map_err(|error| format!("Pending admission is invalid: {error}"))?;
                (current.owner_revision == predecessor.owner_revision && current.admission == predecessor)
                    || (current.owner_revision == admission.owner_revision && current.admission == admission)
            }
            _ => false,
        };
        if !exact_owner_update {
            return Err("existing source row differs from this exact idempotent owner update".to_owned());
        }
    }
    let operation_identity: eliot_contracts::RequestIdentity = serde_json::from_str(owner_identity_json)
        .map_err(|error| format!("source admission RequestIdentity is invalid: {error}"))?;
    let write_receipt = commit_source_admission_update(
        composition,
        request,
        &operation_identity,
        operation_id,
        expected_revision,
        &expected_digest,
        &admission,
        snapshot,
    ).await?;
    validate_source_admission_write_receipt(request, &write_receipt, &operation_identity, operation_id)?;
    let readback = composition.current_testd_blob_process_source_admission(
        &admission_identity,
        &request.state_fence,
    )?.ok_or_else(|| "committed process-source row is absent from fresh named readback".to_owned())?;
    readback.validate_for(&admission_identity, &request.state_fence)
        .map_err(|error| format!("committed source readback is invalid: {error}"))?;
    if readback.admission != admission
        || readback.owner_revision != admission.owner_revision
        || readback.state_fence != request.state_fence
    {
        return Err("fresh source readback does not equal the committed Pending/Ready update".to_owned());
    }
    let readback_bytes = canonical_json_bytes(&readback)
        .map_err(|error| format!("source admission readback cannot be encoded: {error}"))?;
    let readback_json = String::from_utf8(readback_bytes)
        .map_err(|error| format!("source admission readback is not UTF-8: {error}"))?;
    let write_receipt_bytes = canonical_json_bytes(&write_receipt)
        .map_err(|error| format!("source admission WriteReceipt cannot be encoded: {error}"))?;
    let write_receipt_json = String::from_utf8(write_receipt_bytes)
        .map_err(|error| format!("source admission WriteReceipt is not UTF-8: {error}"))?;
    let write_receipt_sha256 = sha256_hex(write_receipt_json.as_bytes());
    available_launch_owner_facts(
        composition,
        request,
        &scope,
        &policy,
        &catalog,
        Some((
            &readback_json,
            &sha256_hex(readback_json.as_bytes()),
            &write_receipt_json,
            &write_receipt_sha256,
        )),
    )
}

fn validate_source_admission_write_receipt(
    request: &BlobProcessStreamOwnerFactsPullRequest,
    receipt: &eliot_store_api::WriteReceipt,
    identity: &eliot_contracts::RequestIdentity,
    operation_id: &str,
) -> Result<(), String> {
    let envelope = receipt.envelope.as_ref()
        .ok_or_else(|| "source admission WriteReceipt has no canonical envelope".to_owned())?;
    let authority: eliot_receipts::AuthorityBinding = serde_json::from_str(
        &request.kernel_authority_binding_json,
    ).map_err(|error| format!("source admission authority is invalid: {error}"))?;
    let causal: eliot_receipts::CausalBinding = serde_json::from_str(
        &request.kernel_causal_binding_json,
    ).map_err(|error| format!("source admission cause is invalid: {error}"))?;
    receipt.validate().map_err(|error| format!("source admission WriteReceipt failed validation: {error}"))?;
    if receipt.status != eliot_store_api::WriteReceiptStatus::Committed
        || receipt.operation_id.as_str() != operation_id
        || receipt.idempotency_key != identity.idempotency_key
        || envelope.core.request != identity.request
        || envelope.core.operation.operation_id.as_str() != operation_id
        || envelope.core.operation.idempotency_key != identity.idempotency_key
        || envelope.core.operation.state_fence != request.state_fence
        || envelope.core.authority != authority
        || envelope.core.causal != causal
    {
        return Err("source admission WriteReceipt differs from exact PULL identity, authority, or cause".to_owned());
    }
    Ok(())
}

/// Produces a closed owner answer for one Kernel-retained pull.
///
/// Launch grants resolve the current named WorkScope, module generation, and
/// Config policy owners. Stream-open/readback purposes require their separate
/// durable process-source admission and remain unavailable until that exact
/// row has been written/read or found current. Governing-document references
/// are a distinct identity domain from generated process-stream source IDs.
pub async fn resolve_blob_owner_facts(
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
    if matches!(
        request.purpose,
        BlobProcessStreamOwnerFactsPullPurpose::OpenAdmission
            | BlobProcessStreamOwnerFactsPullPurpose::ReadyAttach
    ) {
        return match resolve_source_admission_update(composition, request).await {
            Ok(response) => Ok(response),
            Err(_) => unavailable_blob_owner_facts(
                request,
                BlobProcessStreamOwnerFactsUnavailableReason::SourceReceiptUnavailable,
            ),
        };
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
    if request.purpose == BlobProcessStreamOwnerFactsPullPurpose::StoreOpen {
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
        let (readback_json, readback_sha, receipt_json, receipt_sha) =
            match store_open_source_admission(composition, request) {
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
            Some((&readback_json, &readback_sha, &receipt_json, &receipt_sha)),
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

#[cfg(test)]
mod source_admission_cas_tests {
    use super::*;
    use eliot_contracts::{
        EpochId, EpochLineageId, ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex,
    };
    use eliot_store_api::blob_process_source_admission::{
        BLOB_PROCESS_SOURCE_ADMISSION_SCHEMA, BlobProcessSourceAdmission,
        BlobProcessSourceAdmissionIdentity, BlobProcessSourceAdmissionPhase,
        BlobProcessSourceReadyCommitment, blob_process_source_admission_mutation,
    };
    use std::num::NonZeroU64;

    fn fence() -> StateFence {
        StateFence::new(
            EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                    .expect("test lineage"),
                NonZeroU64::new(1).expect("nonzero sequence"),
            )
            .expect("test epoch"),
            ResourceGeneration::new(1).expect("test generation"),
        )
    }

    fn object_json() -> String {
        "{}".to_owned()
    }

    fn pending_admission() -> BlobProcessSourceAdmission {
        let identity = BlobProcessSourceAdmissionIdentity {
            work_scope_ref: "scope-test".to_owned(),
            session_id: "session-test".to_owned(),
            source_id: "source-test".to_owned(),
            process_binding_sha256: sha256_hex(b"{}"),
        };
        BlobProcessSourceAdmission {
            schema: BLOB_PROCESS_SOURCE_ADMISSION_SCHEMA.to_owned(),
            phase: BlobProcessSourceAdmissionPhase::Pending,
            owner_revision: 1,
            state_fence: fence(),
            identity,
            pending_operation_id: "pending-operation-test".to_owned(),
            pending_request_identity_json: object_json(),
            pending_request_identity_sha256: sha256_hex(b"{}"),
            process_binding_json: object_json(),
            process_binding_sha256: sha256_hex(b"{}"),
            open_request_json: object_json(),
            open_request_sha256: sha256_hex(b"{}"),
            work_scope_owner_revision: 1,
            work_scope_owner_digest: sha256_hex(b"work-scope"),
            owner_facts_json: object_json(),
            owner_facts_sha256: sha256_hex(b"{}"),
            ready: None,
        }
    }

    #[test]
    fn pending_to_ready_uses_exact_absence_and_pending_cas_bases() {
        let pending = pending_admission();
        let admission_ref = pending.admission_ref().expect("canonical source ref");
        let pending_insert = blob_process_source_admission_mutation(
            &pending,
            0,
            "absent",
            &admission_ref,
        );
        assert!(pending_insert.is_ok(), "first Pending node must use exact absence CAS");

        let pending_json = String::from_utf8(
            canonical_json_bytes(&pending).expect("canonical Pending bytes"),
        )
        .expect("UTF-8 Pending JSON");
        let pending_sha = sha256_hex(pending_json.as_bytes());
        let mut ready = pending.clone();
        ready.phase = BlobProcessSourceAdmissionPhase::Ready;
        ready.owner_revision = 2;
        ready.ready = Some(BlobProcessSourceReadyCommitment {
            ready_operation_id: "ready-operation-test".to_owned(),
            ready_request_identity_json: object_json(),
            ready_request_identity_sha256: sha256_hex(b"{}"),
            pending_admission_json: pending_json.clone(),
            pending_admission_sha256: pending_sha.clone(),
            whole_source_sha256: sha256_hex(b"stored source"),
            whole_source_byte_length: 13,
            blob_ready_receipt_json: object_json(),
            blob_ready_receipt_sha256: sha256_hex(b"{}"),
        });
        assert!(
            blob_process_source_admission_mutation(&ready, 1, &pending_sha, &admission_ref)
                .is_ok(),
            "Ready must CAS from the exact Pending record",
        );
        assert!(
            blob_process_source_admission_mutation(&ready, 1, &sha256_hex(b"foreign"), &admission_ref)
                .is_err(),
            "a foreign Pending digest must not be accepted as the Ready predecessor",
        );

        let ready_commit = ready.ready.as_mut().expect("Ready commitment");
        ready_commit.pending_admission_json = object_json();
        ready_commit.pending_admission_sha256 = sha256_hex(b"substituted");
        assert!(
            blob_process_source_admission_mutation(&ready, 1, &pending_sha, &admission_ref)
                .is_err(),
            "substituted Pending bytes must refuse the Ready transition",
        );
        assert!(
            blob_process_source_admission_mutation(&ready, 2, &pending_sha, &admission_ref)
                .is_err(),
            "an unexpected owner revision must refuse the Ready transition",
        );
    }
}
