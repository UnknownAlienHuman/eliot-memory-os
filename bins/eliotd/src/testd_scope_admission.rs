//! Authenticated owner-facts pull handling for process-stream admission.
//!
//! The daemon re-reads current named owners before answering a Kernel pull.
//! TestD request metadata can select an already retained catalog generation,
//! but the generated process-stream source ID requires its own durable,
//! pre-capture admission; it is not a governing-document source reference.

use std::time::{SystemTime, UNIX_EPOCH};

use eliot_blob_api::wire::{
    BLOB_PROCESS_STREAM_OWNER_FACTS_WIRE_ID, BLOB_PROCESS_STREAM_OWNER_FACTS_WIRE_REVISION,
    BlobProcessStreamOwnerFactsPullOutcome, BlobProcessStreamOwnerFactsPullRequest,
    BlobProcessStreamOwnerFactsPullResponse, BlobProcessStreamOwnerFactsUnavailableReason,
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

/// Packages the exact owner-read WorkScope and selected admitted source record
/// in canonical form. The source reference remains the original owner value;
/// the JSON digest commits only the canonical transport projection, not a new
/// receipt identity or content digest.
pub fn canonical_current_work_scope_source_receipt(
    snapshot: &eliot_governor::WorkScopeBindingSnapshot,
    governing_source_ref: &str,
) -> Result<CurrentWorkScopeSourceReceipt, String> {
    snapshot
        .validate()
        .map_err(|error| format!("WorkScope source admission is invalid: {error}"))?;
    let source = snapshot
        .source_admission()
        .ok_or_else(|| "WorkScope owner has no retained source admission".to_owned())?;
    let source_record = source
        .sources
        .sources
        .iter()
        .find(|item| item.source_ref == governing_source_ref)
        .ok_or_else(|| "current WorkScope admission omits the requested governing source".to_owned())?;
    let work_scope_bytes = canonical_json_bytes(snapshot)
        .map_err(|error| format!("canonical WorkScope owner encoding failed: {error}"))?;
    let guard_bytes = canonical_json_bytes(&snapshot.guard_receipt)
        .map_err(|error| format!("canonical WorkScope guard encoding failed: {error}"))?;
    // The source record retains its original owner reference and original
    // content digest. Hashing its canonical projection commits this bounded
    // transport representation; it does not replace or reinterpret the
    // source's own digest.
    let source_bytes = canonical_json_bytes(source_record)
        .map_err(|error| format!("canonical source record encoding failed: {error}"))?;
    let source_receipt_sha256 = sha256_hex(&source_bytes);
    Ok(CurrentWorkScopeSourceReceipt {
        work_scope_ref: snapshot.binding.scope.scope_ref.clone(),
        work_scope_snapshot_sha256: sha256_hex(&work_scope_bytes),
        work_scope_snapshot_json: String::from_utf8(work_scope_bytes)
            .map_err(|error| format!("WorkScope owner UTF-8 encoding failed: {error}"))?,
        matched_guard_receipt_sha256: sha256_hex(&guard_bytes),
        matched_guard_receipt_json: String::from_utf8(guard_bytes)
            .map_err(|error| format!("WorkScope guard UTF-8 encoding failed: {error}"))?,
        canonical_source_receipt_ref: source_record.source_ref.clone(),
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
        return Err("fresh Module Registry generation differs from retained selectors or fence".to_owned());
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

/// Produces a closed owner answer for one Kernel-retained pull.
///
/// A positive result requires process-source admission that binds the
/// stream's generated source ID to the exact admitted process operation,
/// WorkScope, and governing-source closure, plus Blob-specific policy,
/// residency, causal, and authority owners. WorkScope governing-document
/// references are a distinct identity domain from process-stream source IDs.
/// Until the independent process-source owner is installed, this composition
/// cannot produce an `Available` result.
pub fn resolve_blob_owner_facts(
    composition: &DaemonComposition,
    request: &BlobProcessStreamOwnerFactsPullRequest,
) -> Result<BlobProcessStreamOwnerFactsPullResponse, String> {
    request
        .validate()
        .map_err(|error| format!("invalid blob owner-facts pull: {error}"))?;
    let reason = if unix_ms() >= request.deadline_ms {
        BlobProcessStreamOwnerFactsUnavailableReason::DeadlineElapsed
    } else {
        match composition.current_testd_blob_work_scope(&request.state_fence) {
            Err(_) => BlobProcessStreamOwnerFactsUnavailableReason::StaleBinding,
            Ok(None) => BlobProcessStreamOwnerFactsUnavailableReason::ScopeGuardUnavailable,
            Ok(Some(snapshot)) => {
                match request.expected_work_scope_ref.as_deref() {
                    Some(expected) if expected != snapshot.binding.scope.scope_ref.as_str() => {
                        BlobProcessStreamOwnerFactsUnavailableReason::StaleBinding
                    }
                    // Without a verified Kernel-selected scope ref, the
                    // current singleton owner snapshot is not evidence that
                    // its scope governs this product/source/task identity.
                    None => BlobProcessStreamOwnerFactsUnavailableReason::ScopeGuardUnavailable,
                    Some(_) => match snapshot.source_admission.as_ref() {
                        None => BlobProcessStreamOwnerFactsUnavailableReason::SourceReceiptUnavailable,
                        Some(source)
                            if source.sources.scope_ref != snapshot.binding.scope.scope_ref
                                || source.sources.generation
                                    != snapshot.binding.governing_source_generation =>
                        {
                            BlobProcessStreamOwnerFactsUnavailableReason::SourceReceiptUnavailable
                        }
                        Some(_) => {
                            if read_current_blob_policy_residency(
                                composition,
                                &request.state_fence,
                                snapshot.binding.scope.scope_ref.as_str(),
                            )
                            .is_err()
                            {
                                return unavailable_blob_owner_facts(
                                    request,
                                    BlobProcessStreamOwnerFactsUnavailableReason::PolicyUnavailable,
                                );
                            }
                            // request.source_id is minted for this output
                            // stream, not selected from the governing source
                            // document set. It needs a separate durable
                            // pre-capture admission bound to the process
                            // operation and this WorkScope.
                            BlobProcessStreamOwnerFactsUnavailableReason::SourceReceiptUnavailable
                        }
                    },
                }
            }
        }
    };
    unavailable_blob_owner_facts(request, reason)
}
