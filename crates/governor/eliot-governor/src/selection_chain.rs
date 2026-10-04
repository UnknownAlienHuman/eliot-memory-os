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
//!   actually ran, joined to *that boundary's own* authored rows. A stage never
//!   borrows another boundary's reason: a member that left the membership
//!   without its own stage naming why is refused as
//!   [`SelectionChainError::UnattributedRemoval`], and a member the admission
//!   owner withheld without an omission record gets an explicit unattributed
//!   reason, so a gap is named rather than silently dropped.
//! - **Final membership** comes from the last stage the chain actually ran: the
//!   owner's `AdmittedContextSet` records through admission, and the
//!   compilation's own output when a compile stage ran. An all-rejected result
//!   is recorded as an honestly empty final set rather than padded with a fake
//!   candidate.
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
    /// A member left a stage's membership without that stage naming why.
    ///
    /// The reason belongs to the boundary that removed the member. Borrowing
    /// another boundary's omission record here would produce a receipt that
    /// validates but misstates which transformation did the work, so the chain
    /// is refused instead and the gap is named.
    #[error(
        "selection chain: stage removed member {member_ref} without its own authored disposition"
    )]
    UnattributedRemoval {
        /// Identity of the member that left the membership unattributed.
        member_ref: String,
    },
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
    /// The membership accounting of *this* boundary, in this boundary's own
    /// words.
    ///
    /// One row per member this boundary actually changed the disposition of,
    /// carrying that boundary's own reason (or derived output / admitted source
    /// evidence). A row this boundary did not author is never inferred from a
    /// different boundary's evidence: `build_stage` either consumes a row here,
    /// or derives `Retained` because the member is still in the output, or
    /// refuses. That refusal is the point — a member that left the membership
    /// without its own boundary naming why is an explicit chain gap
    /// ([`SelectionChainError::UnattributedRemoval`]), never a reason borrowed
    /// from admission and relabelled as the compilation's.
    pub member_dispositions: Vec<SelectionMemberDisposition>,
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
    let admission_stage = build_admission_stage(
        &initial_candidate_members,
        &output_members,
        &final_output_refs,
        &disclosure_closure_ref,
        &state_fence,
        result,
    )?;

    let mut stages = vec![initial_stage, admission_stage];

    // Ordinal two: the context-compilation/export boundary, when the caller
    // supplies its observation. This is the last stage whose output is the
    // delivered packet, so it is the stage a seal is taken against. Its
    // membership accounting is the compilation's own: a compilation that
    // dropped an admitted member must name that member in its observation, and
    // `build_stage` refuses the chain when it does not.
    if let Some(compile) = compile_observation {
        let compiled_members = compile_output_members(compile, &output_members);
        stages.push(build_stage(
            compile,
            2,
            SelectionStageLink::FromPredecessor {
                predecessor_stage_id: ADMISSION_STAGE_ID.to_owned(),
            },
            &output_members,
            &compiled_members,
            &state_fence,
        )?);
    }

    let observed_influence = stages
        .iter()
        .map(|stage| stage.untrusted_input_influenced_membership)
        .max()
        .unwrap_or(SelectionInfluenceState::Absent);

    // The chain's final membership is the LAST stage's output, not the admission
    // stage's. `seal_delivered_packet` and the security contract's
    // `verify_against` both compare the sealed ordered membership against
    // `final_output_refs`, so this field must name the membership that is
    // actually delivered or the two can disagree on a chain with a compile stage.
    let chain_final_output_refs = last_stage_output_refs(&stages);

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
        final_output_refs: chain_final_output_refs,
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
/// This compares the chain's own admitted membership with the membership the
/// admission owner actually produced, so a substituted chain or a substituted
/// final set fails here rather than at a consumer. The owner-issued membership
/// is the compared value; the chain is what it is verified against.
///
/// The compared membership is the ADMITTED stage's output, not the chain's last
/// stage: `eliot-context-assembly` renders admitted records by projection and
/// admits and renders the same identities, so the admitted set is the authority
/// for this equality. A chain whose final stage dropped or replaced a member
/// fails the security contract's own `SelectionIntegrityProof` check instead,
/// which is where a compile-stage membership change belongs. When the chain has
/// no compile stage, the admitted stage IS the last stage and this is the
/// pre-existing end-to-end equality check unchanged.
#[must_use]
pub fn final_membership_matches(
    receipt: &SelectionIntegrityReceipt,
    admitted: &AdmittedContextSet,
) -> bool {
    let admitted_refs: Vec<String> = admitted
        .records
        .iter()
        .map(|record| record.candidate.atom_id.as_str().to_owned())
        .collect();
    let chain_admitted_refs = receipt
        .transformation_stages
        .iter()
        .find(|stage| stage.stage_id == ADMISSION_STAGE_ID)
        .map(|stage| {
            stage
                .output_members
                .iter()
                .map(|member| member.member_ref.clone())
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();
    admitted_refs == chain_admitted_refs
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

/// The admission boundary's own membership accounting.
///
/// Every initial candidate the owner did not carry into the final membership
/// gets one row here, and the reason is the admission owner's own omission
/// record. A member the owner withheld without an omission record is named as
/// an explicit gap ([`UNATTRIBUTED_WITHHELD_REASON`]) rather than dropped: the
/// stage says "withheld, unattributed" instead of implying a measured reason.
fn admission_dispositions(
    initial_candidate_members: &[SelectionMember],
    final_output_refs: &[String],
    omissions: &[OmissionRecord],
) -> Vec<SelectionMemberDisposition> {
    initial_candidate_members
        .iter()
        .filter(|member| !final_output_refs.contains(&member.member_ref))
        .map(|member| SelectionMemberDisposition {
            member_ref: member.member_ref.clone(),
            disposition: SelectionMemberDispositionKind::Removed,
            reason: Some(
                omissions
                    .iter()
                    .find(|record| record.atom_id.as_str() == member.member_ref)
                    .map_or_else(|| UNATTRIBUTED_WITHHELD_REASON.to_owned(), omission_reason),
            ),
            derived_output_ref: None,
            source_evidence_ref: None,
        })
        .collect()
}

/// The membership the compilation boundary actually emitted.
///
/// The admitted set is the compilation's *input*; its output is what the
/// boundary itself reports through the dispositions it authored. A compilation
/// that introduced a new member names it with `Admitted` plus its source
/// evidence, and a compilation that derived a replacement names the
/// `derived_output_ref` that took the input member's place. Anything else leaves
/// the admitted membership unchanged, which is the honest outcome for the
/// `ContextCompile` stage: `eliot-context-assembly` renders admitted records by
/// projection and never selects, so its output membership IS its input.
fn compile_output_members(
    observation: &SelectionStageObservation<'_>,
    admitted_members: &[SelectionMember],
) -> Vec<SelectionMember> {
    let mut output = admitted_members.to_vec();
    for disposition in &observation.member_dispositions {
        match disposition.disposition {
            // An admitted expansion introduces a member whose identity,
            // revision and representation come from the named source evidence,
            // not from a restatement of the input.
            SelectionMemberDispositionKind::Admitted => {
                let Some(evidence) = &disposition.source_evidence_ref else {
                    continue;
                };
                output.push(SelectionMember {
                    member_ref: disposition.member_ref.clone(),
                    member_revision: evidence.clone(),
                    representation_ref: evidence.clone(),
                });
            }
            // A derived output replaces the input member it names, so the output
            // membership carries the derived identity at the position the
            // removed input held.
            SelectionMemberDispositionKind::Derived => {
                let Some(derived) = &disposition.derived_output_ref else {
                    continue;
                };
                if let Some(position) = output
                    .iter()
                    .position(|member| member.member_ref == disposition.member_ref)
                {
                    output[position] = SelectionMember {
                        member_ref: derived.clone(),
                        member_revision: derived.clone(),
                        representation_ref: derived.clone(),
                    };
                }
            }
            SelectionMemberDispositionKind::Retained | SelectionMemberDispositionKind::Removed => {}
        }
    }
    output
}

/// Builds the ordinal-one stage: the admission/prune boundary itself.
///
/// The observation this stage records is the admission owner's own, so its
/// untrusted influence stays the `Unknown` the owner declared — it is never
/// defaulted to `Absent` — and every omission reference comes from the recorded
/// `result.evidence.omissions` rather than from a freshly derived set.
///
/// # Errors
///
/// Returns an error when the membership accounting cannot attribute a removal
/// or the shared stage builder refuses this boundary.
fn build_admission_stage(
    initial_candidate_members: &[SelectionMember],
    output_members: &[SelectionMember],
    final_output_refs: &[String],
    disclosure_closure_ref: &str,
    state_fence: &StateFence,
    result: &AdmissionResult,
) -> Result<SelectionStage, SelectionChainError> {
    let admission_observation = SelectionStageObservation {
        stage_id: ADMISSION_STAGE_ID,
        stage: SelectionStageKind::Prune,
        transformer_identity_and_config_revision: ADMISSION_TRANSFORMER_REVISION,
        disclosure_closure_ref,
        suppressed_counterevidence_refs: suppressed_counterevidence(&result.evidence.omissions),
        budget_or_policy_omission_refs: budget_or_policy_omissions(&result.evidence.omissions),
        untrusted_influence: SelectionInfluenceState::Unknown,
        influence_evidence_refs: influence_evidence(result),
        member_dispositions: admission_dispositions(
            initial_candidate_members,
            final_output_refs,
            &result.evidence.omissions,
        ),
    };
    build_stage(
        &admission_observation,
        1,
        SelectionStageLink::FromPredecessor {
            predecessor_stage_id: INITIAL_MEMBERSHIP_STAGE_ID.to_owned(),
        },
        initial_candidate_members,
        output_members,
        state_fence,
    )
}

/// Builds one immutable stage with the membership accounting of the boundary
/// that actually ran.
///
/// `Retained` is derived from the membership itself — a member still present in
/// the output was not changed, so no author had to narrate it. Every other
/// disposition comes from `observation.member_dispositions`, which is the
/// boundary's own vocabulary. A removed member with no authored row is
/// [`SelectionChainError::UnattributedRemoval`]: an uninstrumented membership
/// change is an explicit gap, never a reason borrowed from another stage.
fn build_stage(
    observation: &SelectionStageObservation<'_>,
    ordinal: usize,
    input_link: SelectionStageLink,
    input_members: &[SelectionMember],
    output_members: &[SelectionMember],
    state_fence: &eliot_contracts::StateFence,
) -> Result<SelectionStage, SelectionChainError> {
    let output_refs: BTreeSet<&str> = output_members
        .iter()
        .map(|member| member.member_ref.as_str())
        .collect();
    let authored: BTreeMap<&str, &SelectionMemberDisposition> = observation
        .member_dispositions
        .iter()
        .map(|disposition| (disposition.member_ref.as_str(), disposition))
        .collect();
    let member_dispositions = input_members
        .iter()
        .map(|member| {
            if output_refs.contains(member.member_ref.as_str()) {
                Ok(retained_disposition(member))
            } else {
                authored
                    .get(member.member_ref.as_str())
                    .map(|disposition| (*disposition).clone())
                    .ok_or_else(|| SelectionChainError::UnattributedRemoval {
                        member_ref: member.member_ref.clone(),
                    })
            }
        })
        .collect::<Result<Vec<SelectionMemberDisposition>, SelectionChainError>>()?;
    // A row this boundary authored for a member that is neither in the input
    // membership nor in the output membership, and that it neither derived nor
    // admitted, is refused rather than silently dropped: it would restate the
    // stage's accounting with content the membership cannot support. A `Removed`
    // row for a member that WAS in the input and left the output is the ordinary
    // prune case and must NOT be caught here — only a row naming a member this
    // stage never saw is an unattributed claim. `Derived` and `Admitted` rows
    // are exactly the rows the security contract requires for a member this
    // stage introduced, and they legitimately name a member outside the input.
    let input_refs: BTreeSet<&str> = input_members
        .iter()
        .map(|member| member.member_ref.as_str())
        .collect();
    let unsupported = observation.member_dispositions.iter().find(|disposition| {
        !matches!(
            disposition.disposition,
            SelectionMemberDispositionKind::Derived | SelectionMemberDispositionKind::Admitted
        ) && !input_refs.contains(disposition.member_ref.as_str())
            && !output_refs.contains(disposition.member_ref.as_str())
    });
    if let Some(disposition) = unsupported {
        return Err(SelectionChainError::UnattributedRemoval {
            member_ref: disposition.member_ref.clone(),
        });
    }
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

/// The chain's final membership, taken from the last stage that actually ran.
///
/// This is the membership a seal is taken against, so it is read from the chain
/// rather than restated from the admission stage: a chain that ends at a
/// compilation stage delivers the compilation's output, and naming the
/// admission stage's membership here would let a seal and a receipt disagree
/// about what was delivered. A chain always has at least the initial and
/// admission stages, so the empty fallback is unreachable in practice and is
/// kept as the honest representation of a genuinely empty membership.
fn last_stage_output_refs(stages: &[SelectionStage]) -> Vec<String> {
    stages
        .last()
        .map(|stage| {
            stage
                .output_members
                .iter()
                .map(|member| member.member_ref.clone())
                .collect()
        })
        .unwrap_or_default()
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
        admission_contract_set_digest: eliot_canonical::supported_admission_contract_set_digest()
            .map_err(CompositionError::Canonical)?,
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

/// Drives one whole selection-chain append from the admission boundary to the
/// sealed delivery, in the order the steps in this module already state.
///
/// This is the production entry seam the chain was missing: every step below is
/// an existing function of this module, called once and in the order their own
/// doc comments require, and no step is re-implemented or re-interpreted here.
///
/// 1. [`prepare_selection_chain`] reads the admission owner's recorded
///    [`AdmissionInput`] and [`AdmissionResult`] and writes the one shared
///    [`SelectionIntegrityReceipt`]. Its `compile_observation` is the caller's
///    own [`SelectionStageObservation`] for the context-compilation/export
///    boundary it actually ran; omitting it records the honest chain that ends
///    at admission. A refusal here is never downgraded: an incomplete outcome
///    stays [`SelectionChainError::IncompleteAdmission`] rather than becoming a
///    chain with a fabricated stage.
/// 2. [`commit_selection_chain`] is the ONLY Store write: the chain, its
///    advanced head and its seal travel inside the hash-bound
///    `CanonicalWriteEnvelope`, and the append is arbitrated by the chain
///    revision the caller observed.
/// 3. [`seal_delivered_packet`] re-derives and re-verifies the seal against the
///    exact delivered bytes and expansion handles. It is a pure recompute of
///    what step 2 already verified inside the envelope, returned here so the
///    caller and its consumer read the same seal rather than trusting that a
///    commit happened.
/// 4. [`selection_chain_envelope`] returns the committed envelope itself, so
///    the caller can log or hand on the exact bytes that were submitted.
///
/// The returned fourth member is
/// [`selection_chain_head_expectation_key`] of the head the caller observed —
/// the stable compare-and-swap identity this append arbitrates under, and the
/// key a reconciling reader of a lost acknowledgement must present.
///
/// This adds no owner, no store, and no transport: it takes the same public
/// types the steps above take, so a caller in `bins/eliotd` reaches the whole
/// instrument without holding a borrow this module would have to manufacture.
///
/// # Errors
///
/// Returns [`CompositionError`] when any composed step refuses: the chain is
/// not prepared, the commit is refused, or the seal does not bind these bytes.
#[allow(
    clippy::too_many_arguments,
    reason = "the append is one transaction over an exact set of recorded coordinates; grouping them would hide a binding"
)]
pub async fn drive_selection_chain<P: KernelGenerationPort + ?Sized>(
    composition: &GovernorComposition<P>,
    identity: &RequestIdentity,
    input: &AdmissionInput,
    result: &AdmissionResult,
    recipe: &ContextRecipe,
    compile_observation: Option<&SelectionStageObservation<'_>>,
    expected_chain_head: &SelectionChainHead,
    delivered_packet_bytes: &[u8],
    delivered_expansion_handle_ids: &[String],
    expected_ordering_sequence: u64,
) -> Result<
    (
        WriteReceipt,
        CanonicalWriteEnvelope,
        SelectionChainSeal,
        String,
    ),
    CompositionError,
> {
    let receipt = prepare_selection_chain(input, result, recipe, compile_observation)
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
    let write_receipt = commit_selection_chain(
        composition,
        identity,
        &receipt,
        expected_chain_head,
        delivered_packet_bytes,
        delivered_expansion_handle_ids,
        expected_ordering_sequence,
    )
    .await?;
    let seal = seal_delivered_packet(
        &receipt,
        delivered_packet_bytes,
        delivered_expansion_handle_ids,
    )
    .map_err(|error| CompositionError::Owner(error.to_string()))?;
    let envelope = selection_chain_envelope(
        identity,
        &receipt,
        expected_chain_head,
        delivered_packet_bytes,
        delivered_expansion_handle_ids,
        expected_ordering_sequence,
    )?;
    Ok((
        write_receipt,
        envelope,
        seal,
        selection_chain_head_expectation_key(expected_chain_head),
    ))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "tests use expects for fixed-valid protocol fixtures"
    )]

    use super::*;
    use eliot_context_contracts::{
        AdmissionDecisionEvidence, AdmissionMeasuredCost, AdmissionMeasurement,
        AdmissionMeasurementBinding, AdmissionPriorityClass, AdmissionRecord,
        AdmissionRuleIdentity, AdmittedAtom, AtomAvailability, AtomRepresentation, AuthorityClass,
        CONTEXT_CONTRACT_VERSION, CandidatePriority, CapacityLimits, ContextBinding,
        ContextCandidateSet, ContextEconomyReceipt, DecisionContextIncomplete, DecisionRevision,
        DecisionSafetyFloor, EconomyAllocations, LossPolicy, MeasurementAggregationMode,
        MeasurementCompositionProfile, MeasurementRef, MeasurementUnit, NonRecoverableReason,
        PriorityPolicyIdentity, PrivacyClass, ProofBinding, ProviderDisposition, ProviderId,
        ProviderRole, ProviderRoleDenominator, RepresentationKind, RoleLossRule,
        SafetyFloorIdentity, SafetyFloorMember, SemanticRole, SourceSnapshot,
        SuppliedOmissionBinding, canonical_digest,
    };
    use eliot_contracts::{
        ArtifactId, ClockReading, DecisionId, EpochId, EpochLineageId, ProductId, RequestId,
        RequestMetadata, ResourceGeneration, SessionId, SourceId, TaskId, TaskRevision,
    };
    use eliot_evidence::{Assertability, EpistemicStatus};
    use eliot_learning_contracts::AgentAttemptId;
    use eliot_receipts::{ProofCeiling, RequestBinding, WorkScopeId};
    use eliot_security_contracts::{
        MAX_SELECTION_MEMBERS, MAX_SELECTION_STAGES, SecurityContractError,
    };

    /// Admitted member of the fixture boundary; the only member that survives.
    const KEPT: &str = "atom:kept";
    /// Rival the owner withheld under `Blocked`: preserved as counterevidence.
    const COUNTEREVIDENCE: &str = "atom:counterevidence";
    /// Rival the owner withheld under `Capacity`: preserved as a budget omission.
    const BUDGETED: &str = "atom:budgeted";

    const SERIALIZER: &str = "json-v1";
    const SERIALIZER_VERSION: &str = "1";
    const ROUTE: &str = "route:selection-chain";
    const MODEL: &str = "model:selection-chain";
    const ADMISSION_RULE: &str = "admission-rule";
    /// Exact transformer/config revision the compile stage reports for itself.
    const COMPILE_TRANSFORMER: &str = "a17a.context-compile.v1";

    /// One complete admission boundary plus the delivered bytes a consumer reads.
    struct Boundary {
        input: AdmissionInput,
        result: AdmissionResult,
        admitted: AdmittedContextSet,
        bytes: Vec<u8>,
        handles: Vec<String>,
    }

    fn artifact(value: &str) -> ArtifactId {
        ArtifactId::new(value).expect("fixture artifact identity")
    }

    /// A syntactically valid lowercase SHA-256 hex digest over fixture bytes.
    fn digest(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn epoch() -> EpochId {
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
            std::num::NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch")
    }

    fn fence() -> StateFence {
        let mut fence = StateFence::new(epoch(), ResourceGeneration::new(1).expect("generation"));
        fence.task_revision = Some(TaskRevision::new(1).expect("revision"));
        fence
    }

    /// A second generation: the fence of a different owning attempt.
    fn foreign_fence() -> StateFence {
        StateFence::new(epoch(), ResourceGeneration::new(2).expect("generation"))
    }

    fn binding() -> ContextBinding {
        ContextBinding {
            task_id: TaskId::new("task:selection-chain").expect("task"),
            attempt_id: AgentAttemptId::new("attempt:selection-chain").expect("attempt"),
            scope_id: WorkScopeId::new("scope:selection-chain").expect("scope"),
            state_fence: fence(),
            decision_id: DecisionId::new("decision:selection-chain").expect("decision"),
            operation_id: None,
        }
    }

    fn decision_revision() -> DecisionRevision {
        DecisionRevision {
            decision_id: binding().decision_id.clone(),
            recipe_revision: TaskRevision::new(1).expect("revision"),
            policy_sha256: digest('a'),
        }
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "the fixture mirrors the production field type `Option<ProofBinding>`; a fixture that returned the bare value would hide the optionality the contract declares"
    )]
    fn provider_evidence(name: &str) -> Option<ProofBinding> {
        Some(ProofBinding {
            evidence_id: artifact(&format!("evidence:{name}")),
            ceiling: ProofCeiling::Observation,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "a candidate fixture states every field the contract declares, and grouping them would hide one"
    )]
    fn candidate(
        binding: &ContextBinding,
        atom: &str,
        provider: &str,
        role: SemanticRole,
        availability: AtomAvailability,
        policy: LossPolicy,
        representation: AtomRepresentation,
        measurement: char,
    ) -> ContextCandidate {
        ContextCandidate {
            binding: binding.clone(),
            atom_id: artifact(atom),
            provider_role: ProviderRole {
                provider: ProviderId::new(provider).expect("provider"),
                role,
            },
            source_range: None,
            source: SourceSnapshot {
                source_id: SourceId::new(format!("source:{atom}")).expect("source"),
                owner: ProviderId::new(provider).expect("owner"),
                snapshot_id: artifact("snapshot:selection-chain"),
                revision: "r1".to_owned(),
                content_sha256: digest('c'),
                predecessor: None,
            },
            learning: None,
            representation,
            loss_policy: policy,
            availability,
            protected: true,
            privacy: PrivacyClass::Public,
            authority: AuthorityClass::DecisionRelevant,
            status: EpistemicStatus::Observed,
            assertability: Assertability::NonAssertableUnverified,
            measurement: MeasurementRef {
                digest: digest(measurement),
                serializer: SERIALIZER.to_owned(),
            },
            dependencies: Vec::new(),
            proof: ProofBinding {
                evidence_id: artifact("evidence:candidate"),
                ceiling: ProofCeiling::Observation,
            },
        }
    }

    fn measurement(
        binding: &ContextBinding,
        candidate: &ContextCandidate,
        cost: u64,
    ) -> AdmissionMeasurement {
        AdmissionMeasurement {
            measurement_id: artifact(&format!("measurement:{}", candidate.atom_id)),
            atom_id: candidate.atom_id.clone(),
            representation: candidate.representation.kind(),
            unit: MeasurementUnit::Utf8Bytes,
            binding: AdmissionMeasurementBinding {
                context: binding.clone(),
                schema_version: CONTEXT_CONTRACT_VERSION,
                input_digest: candidate.measurement.digest.clone(),
                subject_digest: canonical_digest(candidate).expect("candidate subject digest"),
                output_digest: digest('9'),
                serializer_id: SERIALIZER.to_owned(),
                serializer_version: SERIALIZER_VERSION.to_owned(),
                serializer_options_digest: digest('7'),
                route_id: ROUTE.to_owned(),
                model_id: MODEL.to_owned(),
            },
            cost: AdmissionMeasuredCost::ExactUtf8Bytes { value: cost },
            observation: None,
        }
    }

    fn omission(candidate: &ContextCandidate, reason: OmissionReason, cost: u64) -> OmissionRecord {
        OmissionRecord {
            atom_id: candidate.atom_id.clone(),
            source_id: artifact(candidate.source.source_id.as_str()),
            provider_role: candidate.provider_role.clone(),
            decision: decision_revision(),
            task_revision: TaskRevision::new(1).expect("revision"),
            reason,
            competing_constraint: format!(
                "the {} slot was displaced by the admitted goal",
                candidate.atom_id
            ),
            measured_cost: Some(cost),
            allowed_representation: candidate.loss_policy,
            expansion: None,
            non_recoverable_reason: Some(NonRecoverableReason::SourceUnavailable),
            authorization_requirement: "decision owner".to_owned(),
            privacy_requirement: "restricted".to_owned(),
            proof_requirement: "observation".to_owned(),
            expires: None,
            invalidation: None,
            digest: digest('d'),
        }
    }

    fn supplied(atom: &str, policy: LossPolicy) -> SuppliedOmissionBinding {
        SuppliedOmissionBinding {
            atom_id: artifact(atom),
            policy,
            expansion: None,
            non_recoverable_reason: Some(NonRecoverableReason::SourceUnavailable),
            authorization_requirement: "decision owner".to_owned(),
            privacy_requirement: "restricted".to_owned(),
            proof_requirement: "observation".to_owned(),
            expires: None,
            invalidation: None,
        }
    }

    /// Resigns an economy receipt over its own content, as its owner does.
    fn seal_economy(economy: &mut ContextEconomyReceipt) {
        let mut unsigned = economy.clone();
        unsigned.receipt_digest = digest('0');
        economy.receipt_digest = canonical_digest(&unsigned).expect("economy receipt digest");
    }

    /// Resigns an admission result over its own content, as its owner does.
    fn seal_result(result: &mut AdmissionResult) {
        let mut unsigned = result.clone();
        unsigned.result_digest = digest('0');
        result.result_digest = canonical_digest(&unsigned).expect("admission result digest");
    }

    /// A complete admission boundary: one admitted member and two named rivals.
    ///
    /// `kept_atom` names the admitted identity, so two calls produce two chains
    /// under the SAME `selection_id` (the decision) with different recorded
    /// membership — the divergent-history case the head must refuse.
    #[allow(
        clippy::too_many_lines,
        reason = "the fixture is one immutable admission closure; splitting it would hide a binding"
    )]
    fn boundary(kept_atom: &str) -> Boundary {
        let binding = binding();
        let kept = candidate(
            &binding,
            kept_atom,
            "provider:kept",
            SemanticRole::Goal,
            AtomAvailability::PresentCurrent,
            LossPolicy::NonDroppable,
            AtomRepresentation::Whole {
                content: "the admitted goal".to_owned(),
            },
            '1',
        );
        let counter = candidate(
            &binding,
            COUNTEREVIDENCE,
            "provider:counterevidence",
            SemanticRole::Negative,
            AtomAvailability::Blocked,
            LossPolicy::Summarizable,
            AtomRepresentation::Summary {
                content: "the competing claim".to_owned(),
                source_digest: digest('e'),
            },
            '2',
        );
        let budgeted = candidate(
            &binding,
            BUDGETED,
            "provider:budgeted",
            SemanticRole::Optional,
            AtomAvailability::Unavailable,
            LossPolicy::Summarizable,
            AtomRepresentation::Summary {
                content: "the verbose rival".to_owned(),
                source_digest: digest('f'),
            },
            '3',
        );

        let capacity = CapacityLimits {
            route_capacity: 100,
            fixed_overhead: 10,
            output_reserve: 20,
            review_reserve: 20,
        };
        let slot = |candidate: &ContextCandidate| candidate.provider_role.clone();
        let denominator = ProviderRoleDenominator {
            requested: vec![slot(&kept), slot(&counter), slot(&budgeted)],
            dispositions: vec![
                ProviderDisposition {
                    slot: slot(&kept),
                    state: AtomAvailability::PresentCurrent,
                    evidence: None,
                },
                ProviderDisposition {
                    slot: slot(&counter),
                    state: AtomAvailability::Blocked,
                    evidence: provider_evidence(COUNTEREVIDENCE),
                },
                ProviderDisposition {
                    slot: slot(&budgeted),
                    state: AtomAvailability::Unavailable,
                    evidence: provider_evidence(BUDGETED),
                },
            ],
        };
        let mut recipe = ContextRecipe {
            schema_version: CONTEXT_CONTRACT_VERSION,
            binding: binding.clone(),
            decision: decision_revision(),
            recipe_sha256: digest('0'),
            denominator: denominator.clone(),
            mandatory_roles: vec![SemanticRole::Goal],
            role_policies: vec![
                RoleLossRule {
                    role: SemanticRole::Goal,
                    loss_policy: LossPolicy::NonDroppable,
                    required: true,
                    allowed_representations: vec![RepresentationKind::Whole],
                },
                RoleLossRule {
                    role: SemanticRole::Negative,
                    loss_policy: LossPolicy::Summarizable,
                    required: false,
                    allowed_representations: vec![
                        RepresentationKind::Whole,
                        RepresentationKind::Summary,
                    ],
                },
                RoleLossRule {
                    role: SemanticRole::Optional,
                    loss_policy: LossPolicy::Summarizable,
                    required: false,
                    allowed_representations: vec![
                        RepresentationKind::Whole,
                        RepresentationKind::Summary,
                    ],
                },
            ],
            capacity,
            predecessor: None,
            invalidation: None,
        };
        recipe.recipe_sha256 = recipe
            .canonical_policy_digest()
            .expect("recipe policy digest");

        // Only the admitted goal is mandatory floor material; the two rivals are
        // accounted for by the owner's omission records instead.
        let floor = DecisionSafetyFloor {
            binding: binding.clone(),
            mandatory_atoms: vec![kept.atom_id.clone()],
            mandatory_roles: vec![SemanticRole::Goal],
            providers: ProviderRoleDenominator {
                requested: vec![slot(&kept)],
                dispositions: vec![ProviderDisposition {
                    slot: slot(&kept),
                    state: AtomAvailability::PresentCurrent,
                    evidence: None,
                }],
            },
            members: vec![SafetyFloorMember {
                atom_id: kept.atom_id.clone(),
                role: SemanticRole::Goal,
                availability: AtomAvailability::PresentCurrent,
                measurement: Some(kept.measurement.clone()),
                required_dependencies: Vec::new(),
            }],
            interpretation_dependencies: Vec::new(),
            rule_evidence: artifact("floor-rule"),
            capacity,
        };

        let input = AdmissionInput {
            schema_version: CONTEXT_CONTRACT_VERSION,
            binding: binding.clone(),
            recipe: recipe.clone(),
            candidates: ContextCandidateSet {
                binding: binding.clone(),
                candidates: vec![kept.clone(), counter.clone(), budgeted.clone()],
                denominator: denominator.clone(),
            },
            learning_tickets: Vec::new(),
            floor: SafetyFloorIdentity {
                floor_id: artifact("floor"),
                decision: recipe.decision.clone(),
                floor: floor.clone(),
            },
            priority: PriorityPolicyIdentity {
                policy_id: artifact("priority"),
                decision: recipe.decision.clone(),
                priorities: vec![
                    CandidatePriority {
                        atom_id: kept.atom_id.clone(),
                        class: AdmissionPriorityClass::Required,
                        ordinal: 0,
                    },
                    CandidatePriority {
                        atom_id: counter.atom_id.clone(),
                        class: AdmissionPriorityClass::Normal,
                        ordinal: 1,
                    },
                    CandidatePriority {
                        atom_id: budgeted.atom_id.clone(),
                        class: AdmissionPriorityClass::Low,
                        ordinal: 2,
                    },
                ],
            },
            rule: AdmissionRuleIdentity {
                rule_id: artifact("rule"),
                decision: recipe.decision.clone(),
                rule_sha256: digest('b'),
            },
            measurement_profile: MeasurementCompositionProfile {
                profile_id: artifact("profile"),
                schema_version: CONTEXT_CONTRACT_VERSION,
                serializer_id: SERIALIZER.to_owned(),
                serializer_version: SERIALIZER_VERSION.to_owned(),
                serializer_options_digest: digest('7'),
                route_id: ROUTE.to_owned(),
                model_id: MODEL.to_owned(),
                unit: MeasurementUnit::Utf8Bytes,
                aggregation: MeasurementAggregationMode::QualifiedUtf8Contribution,
                qualification: artifact("qualification"),
                capacity,
            },
            supplied_omissions: vec![
                supplied(COUNTEREVIDENCE, LossPolicy::Summarizable),
                supplied(BUDGETED, LossPolicy::Summarizable),
            ],
            measurements: vec![
                measurement(&binding, &kept, 4),
                measurement(&binding, &counter, 2),
                measurement(&binding, &budgeted, 3),
            ],
        };
        input.validate().expect("fixture admission input");

        let profile_digest = input
            .measurement_profile
            .canonical_digest()
            .expect("measurement profile digest");
        let omissions = vec![
            omission(&counter, OmissionReason::Blocked, 2),
            omission(&budgeted, OmissionReason::Capacity, 3),
        ];
        let mut economy = ContextEconomyReceipt {
            binding: binding.clone(),
            decision_id: binding.decision_id.clone(),
            measurement: MeasurementRef {
                digest: profile_digest.clone(),
                serializer: SERIALIZER.to_owned(),
            },
            requested: vec![
                kept.atom_id.clone(),
                counter.atom_id.clone(),
                budgeted.atom_id.clone(),
            ],
            admitted: vec![kept.atom_id.clone()],
            displaced: vec![counter.atom_id.clone(), budgeted.atom_id.clone()],
            omissions: omissions.clone(),
            applied_rule: artifact("economy-rule"),
            allocations: EconomyAllocations {
                fixed_overhead: capacity.fixed_overhead,
                output_reserve: capacity.output_reserve,
                review_reserve: capacity.review_reserve,
                admitted_required: 4,
                admitted_optional: 0,
                remaining_headroom: 46,
                route_capacity: capacity.route_capacity,
            },
            recipe_digest: input.recipe.recipe_sha256.clone(),
            policy_sha256: input.recipe.decision.policy_sha256.clone(),
            receipt_digest: digest('0'),
        };
        seal_economy(&mut economy);

        let mut admitted = AdmittedContextSet {
            binding: binding.clone(),
            records: vec![AdmittedAtom {
                candidate: kept.clone(),
                disposition: AdmissionDisposition::Include,
                rule_evidence: artifact(ADMISSION_RULE),
            }],
            admissions: vec![AdmissionRecord {
                atom_id: kept.atom_id.clone(),
                provider_role: kept.provider_role.clone(),
                disposition: AdmissionDisposition::Include,
                rule_evidence: artifact(ADMISSION_RULE),
            }],
            floor: input.floor.floor.clone(),
            economy: economy.clone(),
        };
        seal_economy(&mut admitted.economy);
        let admitted_digest = admitted
            .canonical_payload_digest()
            .expect("admitted payload digest");
        admitted
            .economy
            .measurement
            .digest
            .clone_from(&admitted_digest);
        seal_economy(&mut admitted.economy);

        let mut result = AdmissionResult {
            schema_version: CONTEXT_CONTRACT_VERSION,
            binding: binding.clone(),
            input_digest: input.canonical_digest().expect("admission input digest"),
            recipe_digest: input.recipe.recipe_sha256.clone(),
            profile_digest,
            floor_id: input.floor.floor_id.clone(),
            selection_digest: admitted_digest,
            outcome: ContextOutcome::Complete(admitted.clone()),
            evidence: AdmissionDecisionEvidence {
                binding: binding.clone(),
                decisions: vec![
                    AdmissionRecord {
                        atom_id: kept.atom_id.clone(),
                        provider_role: kept.provider_role.clone(),
                        disposition: AdmissionDisposition::Include,
                        rule_evidence: artifact(ADMISSION_RULE),
                    },
                    AdmissionRecord {
                        atom_id: counter.atom_id.clone(),
                        provider_role: counter.provider_role.clone(),
                        disposition: AdmissionDisposition::Blocked,
                        rule_evidence: artifact(ADMISSION_RULE),
                    },
                    AdmissionRecord {
                        atom_id: budgeted.atom_id.clone(),
                        provider_role: budgeted.provider_role.clone(),
                        disposition: AdmissionDisposition::Unavailable,
                        rule_evidence: artifact(ADMISSION_RULE),
                    },
                ],
                omissions: omissions.clone(),
                supplied_omissions: input.supplied_omissions.clone(),
                incomplete: None,
                economy: Some(admitted.economy.clone()),
                proof_ceiling: ProofCeiling::Observation,
            },
            result_digest: digest('0'),
        };
        seal_result(&mut result);
        result
            .validate_for(&input)
            .expect("fixture admission result");

        Boundary {
            input,
            result,
            admitted,
            bytes: b"{\"packet\":\"selection-chain-fixture\"}".to_vec(),
            handles: vec!["handle:expansion-1".to_owned()],
        }
    }

    /// The same boundary, reported by its owner as an explicit incomplete gap.
    fn incomplete_result(input: &AdmissionInput) -> AdmissionResult {
        let mut incomplete = DecisionContextIncomplete::new(artifact("floor-rule"));
        incomplete.unavailable = vec![input.candidates.candidates[0].atom_id.clone()];
        incomplete.validate().expect("fixture incomplete decision");
        let mut result = AdmissionResult {
            schema_version: CONTEXT_CONTRACT_VERSION,
            binding: input.binding.clone(),
            input_digest: input.canonical_digest().expect("admission input digest"),
            recipe_digest: input.recipe.recipe_sha256.clone(),
            profile_digest: input
                .measurement_profile
                .canonical_digest()
                .expect("measurement profile digest"),
            floor_id: input.floor.floor_id.clone(),
            selection_digest: canonical_digest(&incomplete).expect("incomplete selection digest"),
            outcome: ContextOutcome::Incomplete(incomplete.clone()),
            evidence: AdmissionDecisionEvidence {
                binding: input.binding.clone(),
                decisions: input
                    .candidates
                    .candidates
                    .iter()
                    .map(|candidate| AdmissionRecord {
                        atom_id: candidate.atom_id.clone(),
                        provider_role: candidate.provider_role.clone(),
                        disposition: AdmissionDisposition::Revalidate,
                        rule_evidence: artifact(ADMISSION_RULE),
                    })
                    .collect(),
                omissions: Vec::new(),
                supplied_omissions: Vec::new(),
                incomplete: Some(incomplete),
                economy: None,
                proof_ceiling: ProofCeiling::Observation,
            },
            result_digest: digest('0'),
        };
        seal_result(&mut result);
        result
            .validate_for(input)
            .expect("fixture incomplete admission result");
        result
    }

    /// An honest context-compilation stage: it selected nothing and names no
    /// member change, so its output membership is its input membership.
    fn compile_observation(disclosure_closure_ref: &str) -> SelectionStageObservation<'_> {
        SelectionStageObservation {
            stage_id: "governor-context-compile",
            stage: SelectionStageKind::ContextCompile,
            transformer_identity_and_config_revision: COMPILE_TRANSFORMER,
            disclosure_closure_ref,
            suppressed_counterevidence_refs: Vec::new(),
            budget_or_policy_omission_refs: Vec::new(),
            untrusted_influence: SelectionInfluenceState::Absent,
            influence_evidence_refs: Vec::new(),
            member_dispositions: Vec::new(),
        }
    }

    fn request_identity(state_fence: &StateFence) -> RequestIdentity {
        let metadata = RequestMetadata {
            request_id: RequestId::new("req-selection-chain").expect("request id"),
            session_id: Some(SessionId::new("session-selection-chain").expect("session")),
            task_id: Some(TaskId::new("task:selection-chain").expect("task")),
            product_id: ProductId::new("product:selection-chain").expect("product"),
            source_id: SourceId::new("source:governor").expect("source"),
            state_fence: state_fence.clone(),
            clock: ClockReading::default(),
        };
        RequestIdentity {
            request: RequestBinding {
                metadata,
                state_fence: state_fence.clone(),
            },
            idempotency_key: "idem-selection-chain-1".to_owned(),
            deadline_unix_ms: 1_800_000_000_000,
            cancellation_id: "cancel-selection-chain-1".to_owned(),
        }
    }

    /// Prepares the two-stage chain a complete admission boundary produces.
    fn chain(boundary: &Boundary) -> SelectionIntegrityReceipt {
        let receipt = prepare_selection_chain(
            &boundary.input,
            &boundary.result,
            &boundary.input.recipe,
            None,
        )
        .expect("a complete admission prepares a chain");
        receipt.validate().expect("prepared chain validates");
        receipt
    }

    /// Position of the admission stage, read from the chain rather than assumed.
    fn admission_ordinal(receipt: &SelectionIntegrityReceipt) -> usize {
        receipt
            .transformation_stages
            .iter()
            .position(|stage| stage.stage_id == ADMISSION_STAGE_ID)
            .expect("admission stage")
    }

    /// The admitted membership the owner actually produced.
    fn admitted_refs(admitted: &AdmittedContextSet) -> Vec<String> {
        admitted
            .records
            .iter()
            .map(|record| record.candidate.atom_id.as_str().to_owned())
            .collect()
    }

    #[test]
    fn prepare_selection_chain_records_every_membership_change_and_its_own_reason() {
        let boundary = boundary(KEPT);
        let receipt = chain(&boundary);

        // The chain order is read back from the chain itself.
        let ordinals: Vec<usize> = receipt
            .transformation_stages
            .iter()
            .map(|stage| stage.ordinal)
            .collect();
        assert_eq!(
            ordinals,
            (0..receipt.transformation_stages.len()).collect::<Vec<_>>()
        );
        assert_eq!(
            receipt.transformation_stages[0].stage_id,
            INITIAL_MEMBERSHIP_STAGE_ID
        );
        assert_eq!(
            receipt.transformation_stages[1].stage_id,
            ADMISSION_STAGE_ID
        );

        // The initial membership is the caller's own pre-admission candidate set.
        let candidate_refs: Vec<String> = boundary
            .input
            .candidates
            .candidates
            .iter()
            .map(|candidate| candidate.atom_id.as_str().to_owned())
            .collect();
        let initial_refs: Vec<String> = receipt
            .initial_candidate_members
            .iter()
            .map(|member| member.member_ref.clone())
            .collect();
        assert_eq!(initial_refs, candidate_refs);

        // The final membership is the membership the owner admitted.
        let admitted_refs = admitted_refs(&boundary.admitted);
        assert_eq!(receipt.final_output_refs, admitted_refs);
        assert!(final_membership_matches(&receipt, &boundary.admitted));

        // Every rival is named with the boundary's OWN reason, not silently lost.
        let stage = &receipt.transformation_stages[admission_ordinal(&receipt)];
        let removed: BTreeSet<&str> = stage
            .member_dispositions
            .iter()
            .filter(|row| row.disposition == SelectionMemberDispositionKind::Removed)
            .map(|row| row.member_ref.as_str())
            .collect();
        assert_eq!(removed, BTreeSet::from([COUNTEREVIDENCE, BUDGETED]));
        for (atom, reason) in [
            (COUNTEREVIDENCE, OmissionReason::Blocked),
            (BUDGETED, OmissionReason::Capacity),
        ] {
            let row = stage
                .member_dispositions
                .iter()
                .find(|row| row.member_ref == atom)
                .expect("removal row");
            let owner_record = boundary
                .result
                .evidence
                .omissions
                .iter()
                .find(|record| record.atom_id.as_str() == atom)
                .expect("owner omission record");
            assert_eq!(owner_record.reason, reason);
            let recorded = row.reason.as_deref().expect("a removal names a reason");
            assert!(
                recorded.contains(&owner_record.competing_constraint),
                "recorded reason {recorded} must carry the owner's own constraint"
            );
            assert_ne!(recorded, UNATTRIBUTED_WITHHELD_REASON);
        }
        // Counterevidence and boundedness cost are preserved separately.
        assert_eq!(
            stage.suppressed_counterevidence_refs,
            vec![COUNTEREVIDENCE.to_owned()]
        );
        assert_eq!(
            stage.budget_or_policy_omission_refs,
            vec![BUDGETED.to_owned()]
        );

        // The admission boundary's own untrusted influence is never defaulted.
        assert_eq!(
            selection_claim_ceiling(&receipt),
            SelectionInfluenceState::Unknown
        );
        assert_ne!(
            selection_claim_ceiling(&receipt),
            SelectionInfluenceState::Absent
        );
    }

    #[test]
    fn a_later_clean_compile_stage_does_not_launder_an_unknown_stage() {
        let boundary = boundary(KEPT);
        let disclosure = boundary
            .input
            .recipe
            .canonical_policy_digest()
            .expect("disclosure closure reference");
        let compile = compile_observation(&disclosure);
        let receipt = prepare_selection_chain(
            &boundary.input,
            &boundary.result,
            &boundary.input.recipe,
            Some(&compile),
        )
        .expect("a compilation stage prepares a chain");
        receipt.validate().expect("prepared chain validates");

        let stage = receipt.transformation_stages.last().expect("compile stage");
        assert_eq!(stage.stage, SelectionStageKind::ContextCompile);
        assert_eq!(stage.stage_id, compile.stage_id);
        assert_eq!(
            stage.untrusted_input_influenced_membership,
            SelectionInfluenceState::Absent
        );
        // The chain ceiling is the maximum over the stages, so the later clean
        // stage cannot raise what the admission stage recorded as unknown.
        assert_eq!(
            selection_claim_ceiling(&receipt),
            SelectionInfluenceState::Unknown
        );
        assert_eq!(
            selection_claim_ceiling(&receipt),
            receipt.transformation_stages[admission_ordinal(&receipt)]
                .untrusted_input_influenced_membership
        );
        assert_eq!(receipt.final_output_refs, admitted_refs(&boundary.admitted));
    }

    #[test]
    fn the_stage_grammar_is_closed_and_a_malformed_stage_is_refused() {
        let boundary = boundary(KEPT);
        let receipt = chain(&boundary);
        let stage = &receipt.transformation_stages[admission_ordinal(&receipt)];

        let wire = serde_json::to_value(stage).expect("stage wire form");
        assert_eq!(
            serde_json::from_value::<SelectionStage>(wire.clone()).expect("closed grammar decodes"),
            *stage
        );

        // An undeclared disposition is not a stage.
        let mut unknown_disposition = wire.clone();
        unknown_disposition["member_dispositions"][0]["disposition"] =
            serde_json::json!("LAUNDERED");
        let error = serde_json::from_value::<SelectionStage>(unknown_disposition)
            .expect_err("an undeclared disposition is not a stage");
        assert!(
            error.to_string().contains("unknown variant"),
            "unexpected refusal: {error}"
        );

        // An undeclared member is not a stage either.
        let mut unknown_member = wire;
        unknown_member["member_dispositions"][0]["grade"] = serde_json::json!("A");
        let error = serde_json::from_value::<SelectionStage>(unknown_member)
            .expect_err("an undeclared field is not a stage");
        assert!(
            error.to_string().contains("unknown field"),
            "unexpected refusal: {error}"
        );
    }

    #[test]
    fn a_stage_outside_the_contiguous_ordinal_sequence_is_refused() {
        let boundary = boundary(KEPT);
        let receipt = chain(&boundary);
        let ordinal = admission_ordinal(&receipt);

        let mut broken = receipt.clone();
        broken.transformation_stages[ordinal].ordinal = ordinal + 3;
        assert_eq!(
            broken.validate(),
            Err(SecurityContractError::SelectionStageOrder {
                stage_id: ADMISSION_STAGE_ID.to_owned(),
                ordinal,
            })
        );
    }

    #[test]
    fn a_non_contiguous_member_list_leaves_a_member_unaccounted_for() {
        let boundary = boundary(KEPT);
        let receipt = chain(&boundary);
        let ordinal = admission_ordinal(&receipt);

        let mut broken = receipt.clone();
        broken.transformation_stages[ordinal]
            .member_dispositions
            .retain(|row| row.member_ref != COUNTEREVIDENCE);
        assert_eq!(
            broken.validate(),
            Err(SecurityContractError::SelectionMemberLoss {
                stage_id: ADMISSION_STAGE_ID.to_owned(),
                ordinal,
                member_ref: COUNTEREVIDENCE.to_owned(),
            })
        );
    }

    #[test]
    fn a_breaking_linkage_change_across_appends_is_refused() {
        let boundary = boundary(KEPT);
        let receipt = chain(&boundary);
        let ordinal = admission_ordinal(&receipt);

        // The stage still names its predecessor by identity, and its declared
        // digest is recomputed over the tampered input, yet it silently consumes
        // a narrower membership than that predecessor produced.
        let mut broken = receipt.clone();
        broken.transformation_stages[ordinal]
            .input_members
            .retain(|member| member.member_ref != COUNTEREVIDENCE);
        broken.transformation_stages[ordinal].input_digest =
            selection_member_digest(&broken.transformation_stages[ordinal].input_members)
                .expect("tampered stage input digest");
        assert_eq!(
            broken.validate(),
            Err(SecurityContractError::SelectionStageLinkBroken {
                stage_id: ADMISSION_STAGE_ID.to_owned(),
                ordinal,
            })
        );
    }

    #[test]
    fn a_compile_stage_that_names_an_unattributed_membership_change_is_refused() {
        let boundary = boundary(KEPT);
        let disclosure = boundary
            .input
            .recipe
            .canonical_policy_digest()
            .expect("disclosure closure reference");
        let mut compile = compile_observation(&disclosure);
        compile.member_dispositions = vec![SelectionMemberDisposition {
            member_ref: "atom:never-consumed".to_owned(),
            disposition: SelectionMemberDispositionKind::Removed,
            reason: Some("this stage never consumed that member".to_owned()),
            derived_output_ref: None,
            source_evidence_ref: None,
        }];
        assert_eq!(
            prepare_selection_chain(
                &boundary.input,
                &boundary.result,
                &boundary.input.recipe,
                Some(&compile),
            ),
            Err(SelectionChainError::UnattributedRemoval {
                member_ref: "atom:never-consumed".to_owned(),
            })
        );
    }

    #[test]
    fn the_sealed_final_membership_is_the_delivered_membership() {
        let boundary = boundary(KEPT);
        let receipt = chain(&boundary);
        let seal =
            seal_delivered_packet(&receipt, &boundary.bytes, &boundary.handles).expect("seal");

        assert_eq!(seal.final_output_refs, admitted_refs(&boundary.admitted));
        seal.verify_against(&receipt, &boundary.bytes, &boundary.handles)
            .expect("the seal binds this chain and these delivered bytes");

        // Changed packet bytes cannot substitute, whatever the member count.
        let rewritten = b"{\"packet\":\"selection-chain-fixture-v2\"}".to_vec();
        assert_eq!(
            seal.verify_against(&receipt, &rewritten, &boundary.handles),
            Err(SecurityContractError::SelectionSealPacketBytes)
        );
        // A swapped expansion handle set is the handle failure it is.
        assert_eq!(
            seal.verify_against(&receipt, &boundary.bytes, &[]),
            Err(SecurityContractError::SelectionSealExpansionHandles)
        );

        // An ordered final membership that is not the chain's own is refused even
        // though the seal recomputes its own digest over the substituted members.
        let mut substituted = seal.clone();
        substituted.final_output_members.push(SelectionMember {
            member_ref: "atom:never-admitted".to_owned(),
            member_revision: "r1".to_owned(),
            representation_ref: digest('1'),
        });
        substituted.final_output_refs = substituted
            .final_output_members
            .iter()
            .map(|member| member.member_ref.clone())
            .collect();
        substituted.final_output_digest =
            selection_member_digest(&substituted.final_output_members).expect("substituted digest");
        assert_eq!(
            substituted.verify_against(&receipt, &boundary.bytes, &boundary.handles),
            Err(SecurityContractError::SelectionSealFinalMembership)
        );

        // And the owner-issued admitted membership is the compared value: a
        // substituted final set fails the kept equality check here.
        let mut foreign_candidate = boundary.admitted.records[0].candidate.clone();
        foreign_candidate.atom_id = artifact("atom:kept-other");
        let mut foreign_admitted = boundary.admitted.clone();
        foreign_admitted.records.push(AdmittedAtom {
            candidate: foreign_candidate,
            disposition: AdmissionDisposition::Include,
            rule_evidence: artifact(ADMISSION_RULE),
        });
        assert!(final_membership_matches(&receipt, &boundary.admitted));
        assert!(!final_membership_matches(&receipt, &foreign_admitted));
    }

    #[test]
    fn a_chain_head_that_does_not_match_the_prior_prefix_is_refused() {
        let first = boundary(KEPT);
        let second = boundary("atom:kept-other");
        let first_receipt = chain(&first);
        let second_receipt = chain(&second);

        // Two chains under the SAME decision identity with different membership.
        assert_eq!(first_receipt.selection_id, second_receipt.selection_id);
        let head = first_receipt
            .derive_chain_head(first_receipt.revision, &chain_append_key(&first_receipt))
            .expect("observed chain head");
        first_receipt
            .verify_chain_head(&head)
            .expect("a derived head binds its own stage prefix");

        // A divergent chain cannot append onto this prefix.
        assert_eq!(
            second_receipt.verify_chain_head(&head),
            Err(SecurityContractError::SelectionChainHeadDigest)
        );
        assert!(matches!(
            selection_chain_security_context(&second_receipt, &head, &first.bytes, &first.handles),
            Err(SelectionChainError::Security(
                SecurityContractError::SelectionChainHeadDigest
            ))
        ));

        let mut wrong_prefix = head.clone();
        wrong_prefix.chain_head_digest = digest('8');
        assert_eq!(
            first_receipt.verify_chain_head(&wrong_prefix),
            Err(SecurityContractError::SelectionChainHeadDigest)
        );

        let mut foreign_chain = head.clone();
        foreign_chain.selection_id = "decision:other".to_owned();
        assert_eq!(
            first_receipt.verify_chain_head(&foreign_chain),
            Err(SecurityContractError::SelectionChainHeadIdentity)
        );

        let mut beyond = head.clone();
        beyond.chain_head_ordinal = first_receipt.transformation_stages.len();
        assert_eq!(
            first_receipt.verify_chain_head(&beyond),
            Err(SecurityContractError::SelectionChainHeadOrdinal {
                expected: first_receipt.transformation_stages.len(),
                observed: first_receipt.transformation_stages.len(),
            })
        );
    }

    #[test]
    fn the_append_is_arbitrated_under_the_chain_head_the_caller_observed() {
        let boundary = boundary(KEPT);
        let receipt = chain(&boundary);
        let observed = receipt
            .derive_chain_head(receipt.revision, "selection-chain-append:observed")
            .expect("observed chain head");
        let identity = request_identity(&receipt.state_fence);

        let first = selection_chain_envelope(
            &identity,
            &receipt,
            &observed,
            &boundary.bytes,
            &boundary.handles,
            7,
        )
        .expect("the first append builds its envelope");

        // The same append observed at the same head is the same operation, byte
        // for byte, so a retry replays instead of forking.
        let replayed = selection_chain_envelope(
            &identity,
            &receipt,
            &observed,
            &boundary.bytes,
            &boundary.handles,
            7,
        )
        .expect("the replayed append builds the same envelope");
        assert_eq!(first, replayed);
        assert_eq!(
            first.operation_id.as_str(),
            format!(
                "selection-chain:{}:{}@{}",
                receipt.selection_id, observed.chain_head_ordinal, observed.chain_revision
            )
        );

        // The head this append advances is derived from this chain's own prefix
        // and carries the caller's compare-and-swap identity.
        let security = selection_chain_security_context(
            &receipt,
            &observed,
            &boundary.bytes,
            &boundary.handles,
        )
        .expect("append security context");
        let advanced = security
            .selection_chain_head
            .as_ref()
            .expect("advanced chain head");
        assert_eq!(advanced.chain_revision, observed.chain_revision + 1);
        assert_eq!(
            advanced.chain_head_digest,
            receipt
                .derive_chain_head(
                    observed.chain_revision + 1,
                    &selection_chain_head_expectation_key(&observed),
                )
                .expect("advanced head")
                .chain_head_digest
        );
        assert_eq!(
            advanced.append_idempotency_key,
            selection_chain_head_expectation_key(&observed)
        );

        let expectation = first
            .expected_revision_heads
            .first()
            .expect("the chain revision compare-and-swap expectation");
        assert_eq!(
            expectation.expected_revision,
            observed.chain_revision.max(1)
        );
        assert_eq!(
            first
                .expected_ordering_heads
                .first()
                .map(|head| head.scope.as_str()),
            Some(SELECTION_CHAIN_ORDERING_SCOPE)
        );

        // A second appender that observed the ADVANCED head is a different
        // operation under a different expectation, never an overwrite of this one.
        let second = selection_chain_envelope(
            &identity,
            &receipt,
            advanced,
            &boundary.bytes,
            &boundary.handles,
            8,
        )
        .expect("the next append builds its envelope");
        assert_ne!(first.operation_id, second.operation_id);
        assert_eq!(
            second
                .expected_revision_heads
                .first()
                .expect("the next chain revision expectation")
                .expected_revision,
            observed.chain_revision + 1
        );
    }

    #[test]
    fn the_stage_and_member_bounds_are_the_shared_contract_bounds() {
        let boundary = boundary(KEPT);
        let receipt = chain(&boundary);

        let mut stage_bound = receipt.clone();
        let admission = stage_bound
            .transformation_stages
            .last()
            .expect("admission stage")
            .clone();
        while stage_bound.transformation_stages.len() <= MAX_SELECTION_STAGES {
            stage_bound.transformation_stages.push(admission.clone());
        }
        assert_eq!(
            stage_bound.transformation_stages.len(),
            MAX_SELECTION_STAGES + 1
        );
        assert_eq!(
            stage_bound.validate(),
            Err(SecurityContractError::SelectionStageLimitExceeded {
                count: MAX_SELECTION_STAGES + 1,
                bound: MAX_SELECTION_STAGES,
            })
        );

        let mut member_bound = receipt;
        member_bound.initial_candidate_members = (0..=MAX_SELECTION_MEMBERS)
            .map(|index| SelectionMember {
                member_ref: format!("atom:bulk-{index}"),
                member_revision: "r1".to_owned(),
                representation_ref: digest('1'),
            })
            .collect();
        assert_eq!(
            member_bound.initial_candidate_members.len(),
            MAX_SELECTION_MEMBERS + 1
        );
        assert_eq!(
            member_bound.validate(),
            Err(SecurityContractError::SelectionMemberLimitExceeded {
                field: "initial_candidate_members",
                count: MAX_SELECTION_MEMBERS + 1,
                bound: MAX_SELECTION_MEMBERS,
            })
        );
    }

    #[test]
    fn chain_state_stays_private_to_the_owning_attempt() {
        let boundary = boundary(KEPT);
        let receipt = chain(&boundary);
        let head = receipt
            .derive_chain_head(receipt.revision, "selection-chain-append:observed")
            .expect("observed chain head");

        // A result recorded for another attempt is not this chain's evidence.
        let mut foreign_attempt = boundary.result.clone();
        foreign_attempt.binding.attempt_id = AgentAttemptId::new("attempt:other").expect("attempt");
        assert_eq!(
            prepare_selection_chain(
                &boundary.input,
                &foreign_attempt,
                &boundary.input.recipe,
                None,
            ),
            Err(SelectionChainError::Contract(
                ContextError::IdentityConflict
            ))
        );

        // The chain's state fence is its own binding, so an append presented under
        // another attempt's fence is refused before an envelope is built.
        let foreign_identity = request_identity(&foreign_fence());
        assert!(matches!(
            selection_chain_envelope(
                &foreign_identity,
                &receipt,
                &head,
                &boundary.bytes,
                &boundary.handles,
                1,
            ),
            Err(CompositionError::Owner(ref message))
                if message.contains("selection chain fence does not match")
        ));
        let owning_identity = request_identity(&receipt.state_fence);
        assert_eq!(receipt.state_fence, boundary.input.binding.state_fence);
        selection_chain_envelope(
            &owning_identity,
            &receipt,
            &head,
            &boundary.bytes,
            &boundary.handles,
            1,
        )
        .expect("the owning attempt's append is admitted");
    }

    #[test]
    fn an_incomplete_admission_falls_through_without_inventing_a_next_stage() {
        let boundary = boundary(KEPT);
        let incomplete = incomplete_result(&boundary.input);
        assert!(matches!(incomplete.outcome, ContextOutcome::Incomplete(_)));

        // The honest answer is the refusal itself: no chain, no sealed membership
        // and no compiled next probe is manufactured from an unproven boundary.
        assert_eq!(
            prepare_selection_chain(&boundary.input, &incomplete, &boundary.input.recipe, None,),
            Err(SelectionChainError::IncompleteAdmission)
        );
        // A compile observation cannot rescue an incomplete admission either.
        let disclosure = boundary
            .input
            .recipe
            .canonical_policy_digest()
            .expect("disclosure closure reference");
        let compile = compile_observation(&disclosure);
        assert_eq!(
            prepare_selection_chain(
                &boundary.input,
                &incomplete,
                &boundary.input.recipe,
                Some(&compile),
            ),
            Err(SelectionChainError::IncompleteAdmission)
        );
    }
}
