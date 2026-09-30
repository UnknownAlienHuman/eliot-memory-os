//! One-call owner adapters over the frozen context compatibility surface (#40).
//!
//! Current owners are `eliot-context-contracts` (A-15 vocabulary),
//! `eliot-context-candidates` (A-16a), `eliot-context-admission` (A-17a) and
//! `eliot-context-assembly` (A-18). Every adapter below validates nothing
//! beyond an identity echo: it invokes exactly one owner exactly once, checks
//! that the owner result echoes the request identity, and returns the owner
//! result unchanged. Owner errors pass through untouched with no fallback.
//!
//! The legacy crate-root surface (`ContextCompiler`, `CueIndex`,
//! `OrientationRequest`, `decode_legacy_cue_kind` and the frozen DTOs) keeps
//! byte-identical behavior because `tests/admission_integrity.rs` and the #832
//! battery pin it; it must not be extended. New callers use the re-exported
//! owner vocabulary plus these adapters.
//!
//! ## Facade disposition table (exact; every public item has one row)
//!
//! Dispositions form a closed set: `LegacyFrozen`, `ReexportOwner`,
//! `AdapterEntry`, `FacadeSurface`.
//!
//! ## Bounded removal plan (#40 A4)
//!
//! 1. Legacy rows are frozen: no behavior change, no extension, no new callers.
//! 2. Delete the legacy rows after the #832 cue-kind battery and the
//!    `tests/admission_integrity.rs` fixtures migrate to owner-cell suites (or
//!    a relocated legacy battery) and zero-consumer status is re-verified.
//!    Measured consumer status at the #1862 owner-boundary rework: the frozen
//!    `ContextCompiler` rows again have zero product consumers — the
//!    `bins/eliotd` `eliot.packet` production call to
//!    `ContextCompiler::compile_with_campaign_learning_state` and its
//!    `#[allow(deprecated)]` were removed, so no binary reaches a legacy
//!    compiler and only this crate's own tests import the crate root. The
//!    crate itself is NOT zero-consumer: `campaign_publication` and its
//!    publication helpers below are imported by the `bins/eliotd` campaign
//!    source boundary (`campaign_packet`, `campaign_context_owner`,
//!    `campaign_task_controller`), so step 3 stays blocked until those
//!    consumers move to the owner cells.
//! 3. Delete this crate after every consumer migrates, per issue #40 A4.
//!
//! ## Smaller-shape recipe callers (#1724 A6)
//!
//! #1724 acceptance: "Existing smaller-shape callers migrate explicitly or
//! remain bounded compatibility consumers, never a parallel current owner." The
//! smaller shape is the crate-root `ContextRecipe`/`ContextCompiler` pair —
//! `recipe_revision: TaskRevision`, `total_cost`, per-ROLE maxima and
//! `required_roles` — whose owner is the A-15
//! `eliot_context_contracts::ContextRecipe`, plus the `campaign_publication`
//! body that carries it. The two are not wire-equivalent and this crate holds
//! both, so "is it a second current owner?" is answered per caller, not per
//! type. Measured on this tree, `git grep` over `crates/**` and `bins/**`:
//!
//! | caller | classification |
//! |---|---|
//! | `ContextCompiler::compile`, `compile_with_revocation` | bounded compatibility consumer; `#[deprecated]`, `LegacyFrozen`, and only `tests/admission_integrity.rs` calls them |
//! | `ContextCompiler::compile_with_campaign_learning_state` | bounded compatibility consumer; zero product callers, recorded in `cognitive-donor-map.toml` and `cognitive-edge-map.toml` |
//! | `CampaignCompiledContext`, `CampaignLearningStateCompileInput`, `CampaignContextRolePolicy`, `CampaignContextCompileError` | bounded compatibility consumer; zero callers outside this crate |
//! | `compile_plan`/`compile_control_unfinalized` in `crates/eliot-engine` and `crates/eliot-app` | NOT this surface; those are `eliot_engine::context::ContextCompiler`, a different type with its own owner, and they never name a crate-root item here |
//! | `bins/eliotd` `campaign_packet.rs`, `campaign_context_owner.rs`, `campaign_task_controller.rs` | bounded compatibility consumer over `campaign_publication`; they re-derive through `ApprovedRecipeCatalogue::resolve` and `GoverningContextRequirements::authorize` and select nothing |
//! | `ContextRecipe`/`RoleBudget`/`ContextInput`/`CompiledContext`/`PacketQualityScorecard` in `crates/smart/eliot-context/src/lib.rs` | bounded compatibility consumer; `LegacyFrozen` rows, no external caller |
//!
//! The one shape that is NOT bounded is the current owner, and it is reached
//! through the re-export rows below: `eliot_context_contracts::ContextRecipe`
//! plus the `adapt_*` adapters. There is no third path.

use thiserror::Error;

/// Closed refusal vocabulary for the facade.
///
/// Owner failures pass through untouched (transparent variants); the only
/// facade-side refusal names the exact failed identity check.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FacadeError {
    /// An owner response does not echo the request identity.
    #[error("owner response identity check failed at {what}")]
    ResponseIdentityMismatch {
        /// Stable check name, never caller payload.
        what: &'static str,
    },
    /// A nested A-15 contract rejection from the candidates or admission cell.
    #[error(transparent)]
    Contract(#[from] eliot_context_contracts::ContextError),
    /// The A-18 assembly cell rejected the input or result.
    #[error(transparent)]
    Assembly(#[from] eliot_context_assembly::AssemblyError),
}

/// Every public facade item with its exact disposition.
///
/// `(item, disposition, owner-or-replacement)`. Legacy rows are frozen
/// compatibility material with the removal plan from the module docs;
/// re-export rows resolve by type identity to the current owner.
pub const FACADE_DISPOSITIONS: [(&str, &str, &str); 64] = [
    ("CONTRACT_NAME", "LegacyFrozen", "frozen wire name"),
    ("CONTRACT_VERSION", "LegacyFrozen", "frozen wire revision"),
    (
        "ContextError",
        "LegacyFrozen",
        "frozen vocabulary; owner is eliot-context-contracts::ContextError",
    ),
    (
        "ContextRole",
        "LegacyFrozen",
        "frozen vocabulary; owner roles are SemanticRole/ProviderRole",
    ),
    (
        "AdmissionDisposition",
        "LegacyFrozen",
        "frozen vocabulary; owner shape evolved in eliot-context-contracts",
    ),
    (
        "AdmissionDecision",
        "LegacyFrozen",
        "frozen record; owner is contracts AdmissionRecord",
    ),
    (
        "ContextAtom",
        "LegacyFrozen",
        "frozen atom; owner is contracts ContextCandidate",
    ),
    (
        "ContextRecipe",
        "LegacyFrozen",
        "frozen recipe; owner shape evolved in eliot-context-contracts",
    ),
    (
        "RoleBudget",
        "LegacyFrozen",
        "frozen budget; owner is contracts capacity vocabulary",
    ),
    (
        "ContextInput",
        "LegacyFrozen",
        "frozen read set; owner is contracts AdmissionInput",
    ),
    (
        "PacketQualityScorecard",
        "LegacyFrozen",
        "frozen scorecard; owner is contracts QualityScorecard",
    ),
    (
        "CompiledContext",
        "LegacyFrozen",
        "frozen view; owner is assembly ActiveUnderstandingView",
    ),
    (
        "ContextCompiler",
        "LegacyFrozen",
        "DEPRECATED; owner pipeline is candidates/admission/assembly",
    ),
    (
        "AttentionResolution",
        "LegacyFrozen",
        "frozen vocabulary; owner shape evolved in eliot-context-contracts",
    ),
    (
        "CriticalAttention",
        "LegacyFrozen",
        "frozen item; owner is contracts CriticalAttentionProjection",
    ),
    (
        "LegacyContextCueKind",
        "LegacyFrozen",
        "frozen historical spelling vocabulary for the legacy decoder",
    ),
    (
        "LegacyCueKindError",
        "LegacyFrozen",
        "frozen decoder refusal vocabulary",
    ),
    (
        "ActivationCue",
        "LegacyFrozen",
        "frozen cue envelope; cue owners are the A-10/A-11 cells",
    ),
    (
        "CueActivation",
        "LegacyFrozen",
        "frozen activation result; cue owners are the A-14a cells",
    ),
    (
        "CueIndex",
        "LegacyFrozen",
        "DEPRECATED; cue owners are eliot-cue-index/activation",
    ),
    (
        "OrientationRequest",
        "LegacyFrozen",
        "DEPRECATED; no admitted owner cell yet",
    ),
    (
        "OrientationPacket",
        "LegacyFrozen",
        "frozen packet; no admitted owner cell yet",
    ),
    (
        "minimum_assertability_for_lineage",
        "LegacyFrozen",
        "frozen revocation projection; owner follows revocation migration",
    ),
    (
        "revoked_derivative_invalidation_set",
        "LegacyFrozen",
        "frozen revocation projection; owner follows revocation migration",
    ),
    (
        "bounded_quarantine_scope_for_incomplete_lineage",
        "LegacyFrozen",
        "frozen revocation projection; owner follows revocation migration",
    ),
    (
        "decode_legacy_cue_kind",
        "LegacyFrozen",
        "DEPRECATED; frozen #832 decoder, no owner conversion exists",
    ),
    // Campaign source surface added by #1862. It carries the current A-15
    // `ContextRecipe` and `SessionDeliverySnapshot` around the frozen legacy
    // `ContextInput`, so it is compatibility material for a boundary the owner
    // cells still have to own: no new callers, and it is named here so facade
    // retirement can see its `bins/eliotd` product consumer instead of
    // inheriting a silent one.
    (
        "campaign_publication",
        "LegacyFrozen",
        "campaign source publication over frozen ContextInput; owner cells A-15/A-16a/A-17a/A-18",
    ),
    (
        "campaign_publication::CONTEXT_RECIPE_CAMPAIGN_OWNER_ID",
        "LegacyFrozen",
        "owner label read by the campaign source boundary; not an admitted owner identity",
    ),
    (
        "campaign_publication::ContextSourceDocument",
        "LegacyFrozen",
        "frozen document union; owner is A-15 ContextRecipe/SessionDeliverySnapshot",
    ),
    (
        "campaign_publication::ContextCampaignRecipeBody",
        "LegacyFrozen",
        "frozen recipe+compiler-input body; embeds the frozen ContextInput",
    ),
    (
        "campaign_publication::ContextSourcePublication",
        "LegacyFrozen",
        "frozen store-neutral publication; owner is the campaign source boundary",
    ),
    (
        "campaign_publication::ContextPublicationError",
        "LegacyFrozen",
        "frozen campaign publication refusal vocabulary",
    ),
    (
        "campaign_publication::context_recipe_publication",
        "LegacyFrozen",
        "no NEW callers; campaign source re-homing is #40 removal work",
    ),
    (
        "campaign_publication::context_delivery_publication",
        "LegacyFrozen",
        "no NEW callers; campaign source re-homing is #40 removal work",
    ),
    (
        "campaign_publication::context_recipe_body_digest",
        "LegacyFrozen",
        "donor digest helper; no NEW callers since the #1862 rework",
    ),
    (
        "campaign_publication::context_delivery_body_digest",
        "LegacyFrozen",
        "donor digest helper; no NEW callers since the #1862 rework",
    ),
    // #1724 A6. This public item had NO row, so the table's own claim that
    // "every public item has one row" was false and a live product consumer of
    // the frozen surface was inheriting a silent classification. It has exactly
    // one production caller, `bins/eliotd/src/campaign_packet.rs`, which imports
    // it to build the admission-closure floor identity; it re-derives rather than
    // decides, because it calls `ApprovedRecipeCatalogue::resolve` and
    // `GoverningContextRequirements::authorize` on the way out.
    (
        "campaign_publication::context_safety_floor_identity",
        "LegacyFrozen",
        "frozen floor-identity projection over the owner catalogue; no NEW callers",
    ),
    (
        "CampaignContextCompileError",
        "LegacyFrozen",
        "refusal vocabulary of the removed legacy campaign compile edge; no NEW callers",
    ),
    (
        "CampaignLearningStateCompileInput",
        "LegacyFrozen",
        "legacy compile DTO; no NEW callers since the #1862 rework",
    ),
    (
        "CampaignCompiledContext",
        "LegacyFrozen",
        "legacy compiled view DTO; no NEW callers since the #1862 rework",
    ),
    (
        "CampaignContextRolePolicy",
        "LegacyFrozen",
        "frozen semantic-to-compiler role projection; owner is A-15 RoleLossRule",
    ),
    ("AdmissionInput", "ReexportOwner", "eliot-context-contracts"),
    (
        "AdmissionResult",
        "ReexportOwner",
        "eliot-context-contracts",
    ),
    (
        "AdmittedContextSet",
        "ReexportOwner",
        "eliot-context-contracts",
    ),
    (
        "ContextCandidate",
        "ReexportOwner",
        "eliot-context-contracts",
    ),
    (
        "ContextCandidateSet",
        "ReexportOwner",
        "eliot-context-contracts",
    ),
    (
        "QualityScorecard",
        "ReexportOwner",
        "eliot-context-contracts",
    ),
    (
        "SerializedContextMeasurement",
        "ReexportOwner",
        "eliot-context-contracts",
    ),
    (
        "AttentionInput",
        "ReexportOwner",
        "eliot-context-candidates",
    ),
    (
        "CandidatePolicy",
        "ReexportOwner",
        "eliot-context-candidates",
    ),
    (
        "CandidateRequest",
        "ReexportOwner",
        "eliot-context-candidates",
    ),
    ("CueInput", "ReexportOwner", "eliot-context-candidates"),
    (
        "EpistemicInput",
        "ReexportOwner",
        "eliot-context-candidates",
    ),
    ("EvidenceInput", "ReexportOwner", "eliot-context-candidates"),
    (
        "OpaqueProjection",
        "ReexportOwner",
        "eliot-context-candidates",
    ),
    (
        "ContextCandidateSetResult",
        "ReexportOwner",
        "eliot-context-candidates",
    ),
    (
        "ActiveUnderstandingViewResult",
        "ReexportOwner",
        "eliot-context-assembly",
    ),
    ("AssemblyPolicy", "ReexportOwner", "eliot-context-assembly"),
    (
        "adapt_construct_candidates",
        "AdapterEntry",
        "one A-16a call",
    ),
    ("adapt_admit_context", "AdapterEntry", "one A-17a call"),
    ("adapt_assemble_view", "AdapterEntry", "one A-18 call"),
    ("FacadeError", "FacadeSurface", "closed refusal vocabulary"),
    (
        "facade",
        "FacadeSurface",
        "this module; the only owner-adapter surface, and where the table lives",
    ),
    (
        "FACADE_DISPOSITIONS",
        "FacadeSurface",
        "this table, machine-counted",
    ),
];

/// Constructs whole-unit candidates through A-16a exactly once.
///
/// The caller supplies the complete owner-typed projection closure; the
/// facade invents no projection, priority, or measurement. The returned set
/// must echo the request binding before it is handed back unchanged.
///
/// # Errors
///
/// Returns [`FacadeError::Contract`] when the owner rejects the closure, and
/// [`FacadeError::ResponseIdentityMismatch`] when the result binding differs
/// from the request binding.
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors the owner call one-for-one"
)]
pub fn adapt_construct_candidates(
    request: &eliot_context_candidates::CandidateRequest,
    recipe: &eliot_context_contracts::ContextRecipe,
    task_frame: &eliot_context_candidates::OpaqueProjection,
    attention_and_conflicts: Option<&eliot_context_candidates::AttentionInput>,
    epistemic_position: Option<&eliot_context_candidates::EpistemicInput>,
    cue_activation_result: Option<&eliot_context_candidates::CueInput>,
    negative_memory: &eliot_context_candidates::OpaqueProjection,
    evidence: Option<&eliot_context_candidates::EvidenceInput>,
    affordances: &eliot_context_candidates::OpaqueProjection,
    policy: &eliot_context_candidates::CandidatePolicy,
) -> Result<eliot_context_candidates::ContextCandidateSetResult, FacadeError> {
    let result = eliot_context_candidates::construct_context_candidates(
        request,
        recipe,
        task_frame,
        attention_and_conflicts,
        epistemic_position,
        cue_activation_result,
        negative_memory,
        evidence,
        affordances,
        policy,
    )?;
    if result.set.binding != request.binding {
        return Err(FacadeError::ResponseIdentityMismatch {
            what: "candidates.binding",
        });
    }
    Ok(result)
}

/// Admits one candidate set through A-17a exactly once.
///
/// The caller supplies the complete owner-typed [`AdmissionInput`](eliot_context_contracts::AdmissionInput);
/// the facade invents no priority, omission binding, or measurement profile.
/// The returned result is validated against the same input through the
/// owner validation before it is handed back unchanged.
///
/// # Errors
///
/// Returns [`FacadeError::Contract`] when the owner rejects the input or the
/// result fails owner validation.
pub fn adapt_admit_context(
    input: &eliot_context_contracts::AdmissionInput,
) -> Result<eliot_context_contracts::AdmissionResult, FacadeError> {
    let result = eliot_context_admission::admit_context(input)?;
    result.validate_for(input)?;
    Ok(result)
}

/// Assembles one admitted set through A-18 exactly once.
///
/// The caller supplies the admitted set, recipe, quality verdict, policy, and
/// measurement callback; the facade re-runs no admission and invents no
/// measurement. The returned envelope must echo the exact admitted set before
/// it is handed back unchanged.
///
/// # Errors
///
/// Returns [`FacadeError::Assembly`] when the owner rejects the projection,
/// and [`FacadeError::ResponseIdentityMismatch`] when the echoed admitted set
/// differs from the supplied one.
pub fn adapt_assemble_view<F>(
    admitted: &eliot_context_contracts::AdmittedContextSet,
    recipe: &eliot_context_contracts::ContextRecipe,
    quality: eliot_context_contracts::QualityScorecard,
    policy: &eliot_context_assembly::AssemblyPolicy,
    measure: F,
) -> Result<eliot_context_assembly::ActiveUnderstandingViewResult, FacadeError>
where
    F: FnOnce(
        &[u8],
    ) -> Result<
        eliot_context_contracts::SerializedContextMeasurement,
        eliot_context_contracts::ContextError,
    >,
{
    let result =
        eliot_context_assembly::assemble_active_view(admitted, recipe, quality, policy, measure)?;
    if result.admitted != *admitted {
        return Err(FacadeError::ResponseIdentityMismatch {
            what: "assembly.admitted",
        });
    }
    Ok(result)
}
