//! Governor preparation of the Selection Integrity chain (issue #1728).
//!
//! I12.13 `Selection integrity` requires that "every membership-changing
//! transformation — ranking, pruning, deduplication, summarization, context
//! compilation and export — appends an immutable stage to one chain receipt",
//! and that `untrusted_input_influenced_membership = unknown` "is admissible
//! and is itself a finding: it lowers the claim ceiling of the resulting packet
//! instead of being resolved by assumption".
//!
//! This module is the **producer join** issue step 3 asks for. It is not a
//! second receipt family and not a new authority: it reads the facts the
//! admission owner already produced ([`AdmissionInput`] before admission and
//! [`AdmissionResult`] after it) and writes them into the one shared
//! [`SelectionIntegrityReceipt`] that `eliot-security-contracts` owns and
//! `eliot-store-api::SecurityContext` already carries.
//!
//! Which side of each comparison is authoritative:
//!
//! - **Initial membership** comes from `AdmissionInput.candidates`, the
//!   caller's own candidate set read *before* ranking or admission could alter
//!   it. Nothing downstream may restate it.
//! - **Per-member disposition** is the membership accounting of the stage that
//!   actually ran, joined to the admission owner's own [`OmissionRecord`]
//!   reasons. A member the owner withheld without an omission record gets an
//!   explicit unattributed reason, so a gap is named rather than silently
//!   dropped.
//! - **Final membership** comes from the owner's `AdmittedContextSet` records,
//!   and an all-rejected result is recorded as an honestly empty final set
//!   rather than padded with a fake candidate.
//!
//! The function is pure: no Store IO, no minted authority, and it returns a
//! stage candidate to its caller exactly as issue step 3 requires of "a pure
//! transformer".

use std::collections::{BTreeMap, BTreeSet};

use eliot_canonical::CanonicalWriteEnvelope;
use eliot_context_contracts::{
    AdmissionDisposition, AdmissionInput, AdmissionResult, AdmittedContextSet, ContextCandidate,
    ContextError, ContextOutcome, ContextRecipe, OmissionReason, OmissionRecord,
};
use eliot_contracts::{OperationId, StateFence, sha256_hex};
use eliot_protocol::RequestIdentity;
use eliot_security_contracts::{
    SELECTION_INTEGRITY_SCHEMA, SelectionChainHead, SelectionChainSeal, SelectionInfluenceState,
    SelectionIntegrityReceipt, SelectionMember, SelectionMemberDisposition,
    SelectionMemberDispositionKind, SelectionStage, SelectionStageKind, SelectionStageLink,
    selection_member_digest,
};
use eliot_store_api::{
    EffectClass, EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
    OrderingHeadExpectation, OrderingScopeId, RevisionHeadExpectation, ScopeId, SecurityContext,
    TransitionClass, WriteReceipt, generated_operation_manifests, operation_manifest_set_digest,
};

use crate::composition::{CompositionError, GovernorComposition, KernelGenerationPort};

/// Exact transformer and configuration revision of the admission/prune stage.
///
/// Naming the transformer *and* its configuration revision is what stops a
/// later serializer from reconstructing — or overstating — why an earlier stage
/// removed a rival.
pub const ADMISSION_TRANSFORMER_REVISION: &str = "a17a.admission-prune.v1";

/// Stable stage identity of the ordinal-zero initial-membership binding.
pub const INITIAL_MEMBERSHIP_STAGE_ID: &str = "governor-initial-candidates";

/// Stable stage identity of the admission/prune stage.
pub const ADMISSION_STAGE_ID: &str = "governor-admission-prune";

/// Reason recorded for a member the admission owner withheld without an
/// omission record of its own, so the stage names an explicit chain gap
/// instead of implying the member was silently dropped.
pub const UNATTRIBUTED_WITHHELD_REASON: &str =
    "admission owner withheld this member without an omission record";

/// Refusal raised while preparing one selection chain.
///
/// A refusal never degrades into a partial chain: an uninstrumented or
/// truncated history is an explicit gap, never inferred safe.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SelectionChainError {
    /// The admission owner's own contract rejected its input or result.
    #[error("selection chain: admission contract rejected the boundary: {0}")]
    Contract(#[from] ContextError),
    /// The shared security contract refused this chain.
    ///
    /// The original typed error is carried verbatim; a refused binding is
    /// never collapsed into a generic string.
    #[error("selection chain: security contract refused the chain: {0}")]
    Security(#[from] eliot_security_contracts::SecurityContractError),
    /// The admission result is not the one this chain was prepared for.
    #[error("selection chain: admission result does not bind the presented input")]
    InputBindingMismatch,
    /// An incomplete admission outcome produced no membership to seal.
    ///
    /// The issue requires an explicit pending/incomplete artifact under its
    /// allowed non-effecting policy, never a fully evidenced normal packet
    /// advertised from an unproven compilation.
    #[error("selection chain: admission is incomplete and yields no sealed membership")]
    IncompleteAdmission,
}

/// Exact facts one transformation boundary observed about itself.
///
/// The Governor supplies these; it never reads a store, resolves a recipe, or
/// interprets a verdict. `untrusted_influence` is the boundary's own honest
/// statement — `Unknown` is admissible, never defaulted to `Absent`.
#[derive(Clone, Debug)]
pub struct SelectionStageObservation<'a> {
    /// Stable identity of this boundary's stage.
    pub stage_id: &'a str,
    /// Which kind of membership-changing transformation ran.
    pub stage: SelectionStageKind,
    /// Exact transformer identity and configuration revision.
    pub transformer_identity_and_config_revision: &'a str,
    /// Exact disclosure-closure reference this boundary was read under.
    pub disclosure_closure_ref: &'a str,
    /// Counterevidence or minority items this boundary suppressed.
    pub suppressed_counterevidence_refs: Vec<String>,
    /// Budget or policy forced omissions this boundary made.
    pub budget_or_policy_omission_refs: Vec<String>,
    /// The boundary's own untrusted-influence statement.
    pub untrusted_influence: SelectionInfluenceState,
    /// Evidence backing a `Present` or `Unknown` influence statement.
    pub influence_evidence_refs: Vec<String>,
}

/// Prepares the complete selection chain for one admission boundary and the
/// context compilation that follows it.
///
/// `compile_observation` is the context-compilation/export stage when the
/// caller ran one; omitting it records an honest two-stage chain that ends at
/// admission rather than pretending a compilation happened. Either way the
/// returned chain is validated through the receipt's own `validate()` before
/// it is returned, so this function cannot manufacture a stage-discontinuous
/// history.
///
/// # Errors
///
/// Returns [`SelectionChainError`] when the admission owner's contract rejects
/// the boundary, when the result does not bind the presented input, when the
/// outcome is incomplete, or when the security contract refuses the chain.
pub fn prepare_selection_chain(
    input: &AdmissionInput,
    result: &AdmissionResult,
    recipe: &ContextRecipe,
    compile_observation: Option<&SelectionStageObservation<'_>>,
) -> Result<SelectionIntegrityReceipt, SelectionChainError> {
    // Rule 10: validate the ORIGINAL recorded admission decision and its own
    // omission traces before converting them. Recomputing a fresh checksum over
    // what we hold would replace the proof, not check it.
    input.validate()?;
    result.validate_for(input)?;
    if result.binding != input.binding || result.input_digest != input.canonical_digest()? {
        return Err(SelectionChainError::InputBindingMismatch);
    }

    let state_fence = input.binding.state_fence.clone();
    let selection_id = input.binding.decision_id.as_str().to_owned();
    let recipe_revision = recipe.recipe_sha256.clone();
    let disclosure_closure_ref = recipe.canonical_policy_digest()?;

    let initial_candidate_members: Vec<SelectionMember> =
        input.candidates.candidates.iter().map(member_of).collect();

    let initial_stage = initial_membership_stage(
        &initial_candidate_members,
        &disclosure_closure_ref,
        &state_fence,
    )?;

    let admitted = match &result.outcome {
        ContextOutcome::Complete(admitted) => admitted,
        ContextOutcome::Incomplete(_) => return Err(SelectionChainError::IncompleteAdmission),
    };
    let output_members: Vec<SelectionMember> = admitted
        .records
        .iter()
        .map(|record| member_of(&record.candidate))
        .collect();
    let final_output_refs: Vec<String> = output_members
        .iter()
        .map(|member| member.member_ref.clone())
        .collect();
    let rejected_candidate_refs = rejected_refs(&initial_candidate_members, &final_output_refs);

    // Ordinal one: the admission/prune boundary itself.
    let admission_observation = SelectionStageObservation {
        stage_id: ADMISSION_STAGE_ID,
        stage: SelectionStageKind::Prune,
        transformer_identity_and_config_revision: ADMISSION_TRANSFORMER_REVISION,
        disclosure_closure_ref: &disclosure_closure_ref,
        suppressed_counterevidence_refs: suppressed_counterevidence(&result.evidence.omissions),
        budget_or_policy_omission_refs: budget_or_policy_omissions(&result.evidence.omissions),
        untrusted_influence: SelectionInfluenceState::Unknown,
        influence_evidence_refs: influence_evidence(result),
    };
    let admission_stage = build_stage(
        &admission_observation,
        1,
        SelectionStageLink::FromPredecessor {
            predecessor_stage_id: INITIAL_MEMBERSHIP_STAGE_ID.to_owned(),
        },
        &initial_candidate_members,
        &output_members,
        &result.evidence.omissions,
        &state_fence,
    )?;

    let mut stages = vec![initial_stage, admission_stage];

    // Ordinal two: the context-compilation/export boundary, when the caller
    // supplies its observation. This is the last stage whose output is the
    // delivered packet, so it is the stage a seal is taken against.
    if let Some(compile) = compile_observation {
        stages.push(build_stage(
            compile,
            2,
            SelectionStageLink::FromPredecessor {
                predecessor_stage_id: ADMISSION_STAGE_ID.to_owned(),
            },
            &output_members,
            &output_members,
            &result.evidence.omissions,
            &state_fence,
        )?);
    }

    let observed_influence = stages
        .iter()
        .map(|stage| stage.untrusted_input_influenced_membership)
        .max()
        .unwrap_or(SelectionInfluenceState::Absent);

    let receipt = SelectionIntegrityReceipt {
        schema: SELECTION_INTEGRITY_SCHEMA.to_owned(),
        contract_version: eliot_security_contracts::CONTRACT_VERSION,
        selection_id,
        root_context_ref: input.binding.scope_id.as_str().to_owned(),
        recipe_revision,
        initial_candidate_digest: selection_member_digest(&initial_candidate_members)?,
        initial_candidate_members,
        admitted_candidate_refs: final_output_refs.clone(),
        rejected_candidate_refs,
        transformation_stages: stages,
        final_output_refs,
        chain_untrusted_influence: observed_influence,
        state_fence,
        revision: 1,
    };
    receipt.validate()?;
    Ok(receipt)
}

/// Seals one delivered packet against the chain that produced it.
///
/// The recipe revision, chain-head digest, ordered final membership, the exact
/// delivered bytes and the exact delivered expansion handles are all bound
/// here, and the seal is verified through its own `verify_against` before it is
/// returned, so this function can never hand back a seal that does not bind
/// this chain. A consumer re-runs that verification against the same receipt
/// and the bytes it is about to act on.
///
/// # Errors
///
/// Returns an error when the chain does not validate, when the head or final
/// membership cannot be bound, or when the seal refuses this chain.
pub fn seal_delivered_packet(
    receipt: &SelectionIntegrityReceipt,
    delivered_packet_bytes: &[u8],
    delivered_expansion_handle_ids: &[String],
) -> Result<SelectionChainSeal, SelectionChainError> {
    // Rule 10: validate the ORIGINAL recorded chain before sealing against it.
    receipt.validate()?;
    let chain_head = receipt.derive_chain_head(receipt.revision, &chain_append_key(receipt))?;
    let final_output_members = receipt
        .transformation_stages
        .last()
        .map(|stage| stage.output_members.clone())
        .unwrap_or_default();
    let seal = SelectionChainSeal {
        selection_id: receipt.selection_id.clone(),
        chain_head_digest: chain_head.chain_head_digest,
        recipe_revision: receipt.recipe_revision.clone(),
        final_output_refs: receipt.final_output_refs.clone(),
        final_output_digest: selection_member_digest(&final_output_members)?,
        final_output_members,
        packet_bytes_digest: eliot_contracts::sha256_hex(delivered_packet_bytes),
        expansion_handle_ids: delivered_expansion_handle_ids.to_vec(),
        membership_page_refs: Vec::new(),
    };
    seal.verify_against(
        receipt,
        delivered_packet_bytes,
        delivered_expansion_handle_ids,
    )?;
    Ok(seal)
}

/// Reports whether a selection chain lowers the dependent packet's claim
/// ceiling.
///
/// I12.13 makes unknown untrusted influence "itself a finding" that lowers the
/// claim ceiling rather than being resolved by assumption. A later clean stage
/// cannot raise it, because the chain ceiling is a maximum over the stages
/// (enforced by `validate_outcome`).
#[must_use]
pub fn selection_claim_ceiling(receipt: &SelectionIntegrityReceipt) -> SelectionInfluenceState {
    eliot_security_contracts::selection_claim_ceiling(receipt)
}

/// Reports which admitted dispositions keep a member inside the membership.
///
/// The vocabulary belongs to the admission owner; this only names the two
/// dispositions that preserve membership, so a `HandleOnly` member is never
/// recorded as removed.
#[must_use]
pub fn disposition_keeps_membership(disposition: AdmissionDisposition) -> bool {
    matches!(
        disposition,
        AdmissionDisposition::Include | AdmissionDisposition::HandleOnly
    )
}

/// The kept final admitted/rendered equality check, verified against the chain.
///
/// This compares the chain's own final membership with the membership the
/// admission owner actually produced, so a substituted chain or a substituted
/// final set fails here rather than at a consumer. The owner-issued
/// membership is the compared value; the chain is what it is verified against.
#[must_use]
pub fn final_membership_matches(
    receipt: &SelectionIntegrityReceipt,
    admitted: &AdmittedContextSet,
) -> bool {
    admitted
        .records
        .iter()
        .map(|record| record.candidate.atom_id.as_str().to_owned())
        .collect::<Vec<String>>()
        == receipt.final_output_refs
}

/// The stable append identity of one chain.
///
/// It is derived from the chain's own identity and revision, so the same
/// append replays under the same identity and a different chain never collides
/// with it.
fn chain_append_key(receipt: &SelectionIntegrityReceipt) -> String {
    format!(
        "selection-chain-append:{}@{}",
        receipt.selection_id, receipt.revision
    )
}

/// Hashes one candidate into the shared selection member shape.
///
/// Identity, revision and representation are the three hashed legs. A display
/// label or a count is never hashed in their place, and the representation leg
/// binds the exact measured digest the candidate was admitted with, so a
/// same-identity member whose content changed cannot satisfy a stage link.
fn member_of(candidate: &ContextCandidate) -> SelectionMember {
    SelectionMember {
        member_ref: candidate.atom_id.as_str().to_owned(),
        member_revision: candidate.source.revision.clone(),
        representation_ref: candidate.measurement.digest.clone(),
    }
}

fn retained_disposition(member: &SelectionMember) -> SelectionMemberDisposition {
    SelectionMemberDisposition {
        member_ref: member.member_ref.clone(),
        disposition: SelectionMemberDispositionKind::Retained,
        reason: None,
        derived_output_ref: None,
        source_evidence_ref: None,
    }
}

/// Builds the ordinal-zero stage that binds the caller's candidate set as it
/// stood *before* admission could alter it.
///
/// Its own input and output are that same set, so the chain starts from the
/// declared initial membership by construction rather than by a claim in a
/// comment, and every initial member is accounted for as retained.
///
/// # Errors
///
/// Returns an error when the initial membership cannot be digested.
fn initial_membership_stage(
    initial_candidate_members: &[SelectionMember],
    disclosure_closure_ref: &str,
    state_fence: &StateFence,
) -> Result<SelectionStage, SelectionChainError> {
    let digest = selection_member_digest(initial_candidate_members)?;
    Ok(SelectionStage {
        stage_id: INITIAL_MEMBERSHIP_STAGE_ID.to_owned(),
        ordinal: 0,
        input_link: None,
        stage: SelectionStageKind::Rerank,
        transformer_identity_and_config_revision: ADMISSION_TRANSFORMER_REVISION.to_owned(),
        input_digest: digest.clone(),
        input_members: initial_candidate_members.to_vec(),
        output_digest: digest,
        output_members: initial_candidate_members.to_vec(),
        member_dispositions: initial_candidate_members
            .iter()
            .map(retained_disposition)
            .collect(),
        suppressed_counterevidence_refs: Vec::new(),
        budget_or_policy_omission_refs: Vec::new(),
        untrusted_input_influenced_membership: SelectionInfluenceState::Absent,
        influence_evidence_refs: Vec::new(),
        disclosure_closure_ref: disclosure_closure_ref.to_owned(),
        state_fence: state_fence.clone(),
    })
}

/// Builds one immutable stage with the membership accounting of the boundary
/// that actually ran.
fn build_stage(
    observation: &SelectionStageObservation<'_>,
    ordinal: usize,
    input_link: SelectionStageLink,
    input_members: &[SelectionMember],
    output_members: &[SelectionMember],
    omissions: &[OmissionRecord],
    state_fence: &eliot_contracts::StateFence,
) -> Result<SelectionStage, SelectionChainError> {
    let output_refs: BTreeSet<&str> = output_members
        .iter()
        .map(|member| member.member_ref.as_str())
        .collect();
    let member_dispositions = input_members
        .iter()
        .map(|member| {
            if output_refs.contains(member.member_ref.as_str()) {
                retained_disposition(member)
            } else {
                // A removed member names the owner's own authored reason, so a
                // later serializer cannot reconstruct or overstate why a rival
                // left the membership.
                let reason = omissions
                    .iter()
                    .find(|record| record.atom_id.as_str() == member.member_ref)
                    .map_or_else(|| UNATTRIBUTED_WITHHELD_REASON.to_owned(), omission_reason);
                SelectionMemberDisposition {
                    member_ref: member.member_ref.clone(),
                    disposition: SelectionMemberDispositionKind::Removed,
                    reason: Some(reason),
                    derived_output_ref: None,
                    source_evidence_ref: None,
                }
            }
        })
        .collect();
    Ok(SelectionStage {
        stage_id: observation.stage_id.to_owned(),
        ordinal,
        input_link: Some(input_link),
        stage: observation.stage,
        transformer_identity_and_config_revision: observation
            .transformer_identity_and_config_revision
            .to_owned(),
        input_digest: selection_member_digest(input_members)?,
        input_members: input_members.to_vec(),
        output_digest: selection_member_digest(output_members)?,
        output_members: output_members.to_vec(),
        member_dispositions,
        suppressed_counterevidence_refs: observation.suppressed_counterevidence_refs.clone(),
        budget_or_policy_omission_refs: observation.budget_or_policy_omission_refs.clone(),
        untrusted_input_influenced_membership: observation.untrusted_influence,
        influence_evidence_refs: observation.influence_evidence_refs.clone(),
        disclosure_closure_ref: observation.disclosure_closure_ref.to_owned(),
        state_fence: state_fence.clone(),
    })
}

/// Renders one owner-authored omission reason, preserving both the reason code
/// and the competing constraint that displaced the member.
fn omission_reason(record: &OmissionRecord) -> String {
    format!(
        "{}: {}",
        omission_reason_code(record.reason),
        record.competing_constraint
    )
}

fn omission_reason_code(reason: OmissionReason) -> &'static str {
    match reason {
        OmissionReason::Capacity => "capacity",
        OmissionReason::ProtectedReserve => "protected_reserve",
        OmissionReason::Stale => "stale",
        OmissionReason::Blocked => "blocked",
        OmissionReason::UnknownMeasurement => "unknown_measurement",
        OmissionReason::MeasurementUnavailable => "measurement_unavailable",
        OmissionReason::Privacy => "privacy",
        OmissionReason::Authority => "authority",
        OmissionReason::Unavailable => "unavailable",
        OmissionReason::Policy => "policy",
    }
}

/// Every member of the initial set the admission owner did not carry into the
/// final membership.
fn rejected_refs(initial: &[SelectionMember], final_output_refs: &[String]) -> Vec<String> {
    initial
        .iter()
        .filter(|member| !final_output_refs.contains(&member.member_ref))
        .map(|member| member.member_ref.clone())
        .collect()
}

/// Withheld members kept for a reason that is not a boundedness cost.
///
/// These are the counterevidence and minority items a prune suppressed, so the
/// chain preserves them instead of presenting the surviving membership as if
/// the rivals had never existed.
fn suppressed_counterevidence(omissions: &[OmissionRecord]) -> Vec<String> {
    omissions
        .iter()
        .filter(|record| {
            matches!(
                record.reason,
                OmissionReason::Blocked | OmissionReason::Policy | OmissionReason::Privacy
            )
        })
        .map(|record| record.atom_id.as_str().to_owned())
        .collect()
}

/// Withheld members kept because a budget or a protection reserve displaced
/// them, recorded separately from policy suppression so boundedness never
/// hides behind a policy label.
fn budget_or_policy_omissions(omissions: &[OmissionRecord]) -> Vec<String> {
    omissions
        .iter()
        .filter(|record| {
            matches!(
                record.reason,
                OmissionReason::Capacity
                    | OmissionReason::ProtectedReserve
                    | OmissionReason::UnknownMeasurement
                    | OmissionReason::MeasurementUnavailable
            )
        })
        .map(|record| record.atom_id.as_str().to_owned())
        .collect()
}

/// Evidence references backing the admission stage's influence statement.
///
/// The admission owner's per-candidate `rule_evidence` is its own binding for
/// the decision it took, so it is the honest evidence reference for a
/// membership change the owner cannot attribute to a deterministic transformer
/// alone.
fn influence_evidence(result: &AdmissionResult) -> Vec<String> {
    let mut refs: Vec<String> = result
        .evidence
        .decisions
        .iter()
        .map(|decision| decision.rule_evidence.as_str().to_owned())
        .collect();
    refs.sort();
    refs.dedup();
    refs
}

/// The chain-head key this commit appends under.
///
/// `expected_chain_head` is the compare-and-swap expectation the caller read
/// from the current head: the rebuildable head this transition is allowed to
/// advance. A caller that presents a different head is refused before the
/// envelope is built, so two concurrent appends cannot both advance one linear
/// chain and silently fork it.
#[must_use]
pub fn selection_chain_head_expectation_key(
    expected_chain_head: &eliot_security_contracts::SelectionChainHead,
) -> String {
    format!(
        "selection-chain-head:{}#{}@{}",
        expected_chain_head.selection_id,
        expected_chain_head.chain_head_ordinal,
        expected_chain_head.chain_revision
    )
}

/// Builds the append-only `SecurityContext` this commit carries.
///
/// The chain and the head travel inside `SecurityContext`, which
/// `CanonicalRequestView` hash-binds into `identity.canonical_request_hash`.
/// That is what makes an append durable evidence rather than an in-memory
/// vector: the same identity with the same bytes replays, the same identity
/// with changed content fails the canonical request hash at every gate, and a
/// concurrent append against a different head fails the compare-and-swap
/// expectation this call is given.
///
/// The head is derived from the receipt's own stages here, not accepted as
/// presented, and the seal is verified against the exact delivered bytes
/// before the envelope is built. `expected_chain_head` is the head the caller
/// observed; when it names a different chain prefix than the one this receipt
/// carries, the append is refused as a fork rather than committed.
///
/// # Errors
///
/// Returns an error when the chain, head, or seal fails its binding.
pub fn selection_chain_security_context(
    receipt: &SelectionIntegrityReceipt,
    expected_chain_head: &SelectionChainHead,
    delivered_packet_bytes: &[u8],
    delivered_expansion_handle_ids: &[String],
) -> Result<SecurityContext, SelectionChainError> {
    // Rule 10: the caller's observed head is a *proven claim* about the current
    // head, not a predictable name. It is verified against this receipt's own
    // recomputed prefix digest, so a head that merely exists cannot pass.
    receipt.verify_chain_head(expected_chain_head)?;
    // Rule 10: the seal is compared against THIS chain, and the chain is
    // validated through the original `validate()` first.
    let seal = seal_delivered_packet(
        receipt,
        delivered_packet_bytes,
        delivered_expansion_handle_ids,
    )?;
    let head = receipt.derive_chain_head(
        expected_chain_head.chain_revision.saturating_add(1),
        &selection_chain_head_expectation_key(expected_chain_head),
    )?;
    Ok(SecurityContext {
        source_assurance: Vec::new(),
        disclosure_closure: None,
        transformation_lineage: Vec::new(),
        influence_closure: None,
        purge_entry: None,
        selection_integrity: Some(receipt.clone()),
        selection_chain_head: Some(head),
        selection_chain_seal: Some(seal),
    })
}

/// The one canonical ordering scope a selection-chain append serializes under.
///
/// A selection chain is a single linear history, so its appends share one
/// ordering scope: two concurrent appends contend here rather than each
/// advancing its own fork.
pub const SELECTION_CHAIN_ORDERING_SCOPE: &str = "scope:selection-chain";

/// The revision key a chain head is arbitrated under.
///
/// The head is rebuildable from the immutable stages, so the store arbitrates
/// only this revision and never interprets a stage.
pub const SELECTION_CHAIN_REVISION_KEY: &str = "owner/selection-chain";

/// The exact canonical envelope one selection-chain append commits.
///
/// The envelope reuses the established owner-path identity types the store
/// already keys on: `operation_id` is derived from the chain identity and the
/// head the caller observed, `idempotency_key` is the admitted identity key,
/// and `semantic_commands` carries one `AppendAuditEvent` under the
/// `CaptureCandidate` / `Candidate` ceiling. `security` carries the chain, its
/// advanced head and its seal, and `CanonicalRequestView` hash-binds all of it
/// into `identity.canonical_request_hash` — which is what makes this durable
/// append evidence rather than an in-memory vector.
///
/// `expected_revision_heads` carries the chain revision the caller observed, so
/// two concurrent appends against the same head cannot both succeed.
///
/// # Errors
///
/// Returns [`CompositionError`] when the envelope fails its own validation.
pub fn selection_chain_envelope(
    identity: &RequestIdentity,
    receipt: &SelectionIntegrityReceipt,
    expected_chain_head: &SelectionChainHead,
    delivered_packet_bytes: &[u8],
    delivered_expansion_handle_ids: &[String],
    expected_ordering_sequence: u64,
) -> Result<CanonicalWriteEnvelope, CompositionError> {
    let owner_refusal =
        |message: String| CompositionError::Owner(format!("selection chain: {message}"));
    identity
        .validate()
        .map_err(|error| owner_refusal(format!("identity invalid: {error}")))?;
    let fence: StateFence = identity.request.metadata.state_fence.clone();
    if receipt.state_fence != fence {
        return Err(owner_refusal(
            "selection chain fence does not match the admitted request fence".to_owned(),
        ));
    }
    let security = selection_chain_security_context(
        receipt,
        expected_chain_head,
        delivered_packet_bytes,
        delivered_expansion_handle_ids,
    )
    .map_err(|error| owner_refusal(error.to_string()))?;
    // The append identity is the chain identity plus the head the caller
    // observed: the same chain appending from the same head under the same
    // idempotency key replays its receipt, while the same chain appending from
    // a different head is a different operation and cannot overwrite it.
    let operation_id = OperationId::new(format!(
        "selection-chain:{}:{}@{}",
        receipt.selection_id,
        expected_chain_head.chain_head_ordinal,
        expected_chain_head.chain_revision
    ))
    .map_err(|error| owner_refusal(format!("operation identity invalid: {error}")))?;
    let manifest_digest = operation_manifest_set_digest(
        &generated_operation_manifests()
            .map_err(|error| owner_refusal(format!("manifest set unavailable: {error}")))?,
    )
    .map_err(|error| owner_refusal(format!("manifest digest: {error}")))?;
    let parameters = selection_chain_parameters(
        &operation_id,
        &identity.idempotency_key,
        receipt,
        &security,
        delivered_packet_bytes,
    );
    let envelope = CanonicalWriteEnvelope {
        operation_id,
        request: identity.request.metadata.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        scope_id: ScopeId::new("governor")
            .map_err(|error| owner_refusal(format!("scope identity invalid: {error}")))?,
        task_id: identity
            .request
            .metadata
            .task_id
            .as_ref()
            .map(|task| task.as_str().to_owned()),
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: security.selection_chain_head.as_ref().map_or_else(
            || receipt.revision.to_string(),
            |head| head.chain_head_digest.clone(),
        ),
        operation_manifest_digest: manifest_digest,
        semantic_commands: vec![NamedMutationRequest {
            operation: NamedMutationOperation::AppendAuditEvent,
            parameters,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security,
        required_proof_and_approval_refs: Vec::new(),
        expected_revision_heads: vec![RevisionHeadExpectation {
            key: eliot_store_api::RevisionKey::new(SELECTION_CHAIN_REVISION_KEY)
                .map_err(|error| owner_refusal(format!("revision key invalid: {error}")))?,
            expected_revision: expected_chain_head.chain_revision.max(1),
            state_fence: fence.clone(),
        }],
        expected_ordering_heads: vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new(SELECTION_CHAIN_ORDERING_SCOPE)
                .map_err(|error| owner_refusal(format!("ordering scope invalid: {error}")))?,
            expected_sequence: expected_ordering_sequence,
            state_fence: fence,
        }],
    };
    envelope
        .validate()
        .map_err(|error| owner_refusal(format!("envelope invalid: {error}")))?;
    Ok(envelope)
}

/// The exact named-operation parameters one selection-chain append commits.
///
/// `chain_head_digest` and `packet_bytes_digest` are recomputed from this
/// append's own derived head and the exact delivered bytes, so the persisted
/// audit record carries the same digests the sealed transition hash-binds.
fn selection_chain_parameters(
    operation_id: &OperationId,
    idempotency_key: &str,
    receipt: &SelectionIntegrityReceipt,
    security: &SecurityContext,
    delivered_packet_bytes: &[u8],
) -> BTreeMap<String, serde_json::Value> {
    let mut parameters = BTreeMap::new();
    for (name, value) in [
        (
            "operation_id",
            serde_json::Value::String(operation_id.as_str().to_owned()),
        ),
        (
            "idempotency_key",
            serde_json::Value::String(idempotency_key.to_owned()),
        ),
        (
            "selection_id",
            serde_json::Value::String(receipt.selection_id.clone()),
        ),
        (
            "chain_head_digest",
            serde_json::Value::String(
                security
                    .selection_chain_head
                    .as_ref()
                    .map_or_else(String::new, |head| head.chain_head_digest.clone()),
            ),
        ),
        (
            "packet_bytes_digest",
            serde_json::Value::String(sha256_hex(delivered_packet_bytes)),
        ),
    ] {
        parameters.insert(name.to_owned(), value);
    }
    parameters
}

/// Commits one selection-chain append through the single named Store path.
///
/// This is the production join the issue's step 4 requires. The chain, its
/// advanced head and its seal travel inside the hash-bound envelope, the
/// chain head is arbitrated by an expected revision and the appends are
/// serialized by one ordering scope, so:
///
/// - the same identity with the same bytes replays its receipt;
/// - the same identity with changed content fails the canonical request hash;
/// - two concurrent appends cannot both advance the same head, and therefore
///   cannot overwrite each other or fork one linear chain.
///
/// The commit returns the Store `WriteReceipt`. The caller reconciles it under
/// the original operation identity; a lost acknowledgement is reconciled
/// through the existing canonical receipt read, never by re-appending.
///
/// # Errors
///
/// Returns [`CompositionError`] when the envelope cannot be built or the
/// canonical commit refuses.
pub async fn commit_selection_chain<P: KernelGenerationPort + ?Sized>(
    composition: &GovernorComposition<P>,
    identity: &RequestIdentity,
    receipt: &SelectionIntegrityReceipt,
    expected_chain_head: &SelectionChainHead,
    delivered_packet_bytes: &[u8],
    delivered_expansion_handle_ids: &[String],
    expected_ordering_sequence: u64,
) -> Result<WriteReceipt, CompositionError> {
    let envelope = selection_chain_envelope(
        identity,
        receipt,
        expected_chain_head,
        delivered_packet_bytes,
        delivered_expansion_handle_ids,
        expected_ordering_sequence,
    )?;
    composition.commit_canonical(identity, envelope).await
}
