//! Public input, output, and error types of the synthesis owner.
//!
//! All types are plain deterministic data: no I/O handles, no clocks, no
//! interior mutability. Iteration order is fixed by construction (`Vec` input
//! order for semantic relationships, sorted keys inside canonical digests),
//! so equal semantic inputs always produce equal semantic digests.

use std::fmt::{Display, Formatter, Result as FmtResult};

use crate::bounds::{DIAGNOSTIC_VALUE_PREFIX, MAX_HANDLE_BYTES, MAX_TEXT_BYTES, REDACTED_SUFFIX};
use crate::digest::{CanonicalWriter, is_digest_hex};

// ---------- closed vocabularies ----------

/// Closed requester-origin set (I9.4 `requester`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RequesterOrigin {
    /// Human principal.
    Human,
    /// Explicitly admitted agent principal.
    AdmittedAgent,
    /// Schedule-policy principal.
    SchedulePolicy,
}

/// Canonical wire spelling of a requester origin.
#[must_use]
pub const fn requester_origin_as_str(origin: RequesterOrigin) -> &'static str {
    match origin {
        RequesterOrigin::Human => "human",
        RequesterOrigin::AdmittedAgent => "admitted-agent",
        RequesterOrigin::SchedulePolicy => "schedule-policy",
    }
}

/// Parses a requester-origin wire spelling; unknown spellings stay unparsed.
#[must_use]
pub fn parse_requester_origin(value: &str) -> Option<RequesterOrigin> {
    match value {
        "human" => Some(RequesterOrigin::Human),
        "admitted-agent" => Some(RequesterOrigin::AdmittedAgent),
        "schedule-policy" => Some(RequesterOrigin::SchedulePolicy),
        _ => None,
    }
}

/// Evidence grade ladder (I21.2). Ordering is rigour ordering: `E0 < E3`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum EvidenceGrade {
    /// Orienting evidence; not admissible for a material decision.
    E0,
    /// Grounded evidence; every material statement resolves to a handle.
    E1,
    /// Corroborated evidence; independent families plus rivals represented.
    E2,
    /// Science-grade evidence; frozen protocol, freeze, audit, research debts.
    E3,
}

/// Canonical wire spelling of an evidence grade.
#[must_use]
pub const fn evidence_grade_as_str(grade: EvidenceGrade) -> &'static str {
    match grade {
        EvidenceGrade::E0 => "E0",
        EvidenceGrade::E1 => "E1",
        EvidenceGrade::E2 => "E2",
        EvidenceGrade::E3 => "E3",
    }
}

/// Parses an evidence-grade spelling; unknown spellings stay unparsed.
#[must_use]
pub fn parse_evidence_grade(value: &str) -> Option<EvidenceGrade> {
    match value {
        "E0" => Some(EvidenceGrade::E0),
        "E1" => Some(EvidenceGrade::E1),
        "E2" => Some(EvidenceGrade::E2),
        "E3" => Some(EvidenceGrade::E3),
        _ => None,
    }
}

/// Observed freshness of a governed source card.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Freshness {
    /// Fresh under the governing fence.
    Fresh,
    /// Stale: retained with limits, never precision-raising.
    Stale,
    /// Freshness was not observed; stays explicit.
    Unknown,
}

/// Supported precision level of one citation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Precision {
    /// Exact precision as supplied.
    Exact,
    /// Qualified precision; hedges preserved.
    Qualified,
    /// No precision support; promotes nothing.
    Unsupported,
}

/// What kind of precision a citation or claim asserts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PrecisionKind {
    /// Document-level prose claim.
    Documentary,
    /// Numeric quantity, unit, or population-wide statement.
    Numeric,
    /// Timestamp, interval, or temporal ordering.
    Time,
    /// Software, document, or protocol version.
    Version,
    /// Causal mechanism or causal direction.
    Causal,
    /// Any other general assertion.
    General,
}

/// Material claim shape carried by the grounded draft.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ClaimKind {
    /// General factual assertion.
    Factual,
    /// Numeric quantity or population-wide statement.
    Numeric,
    /// Temporal assertion.
    Time,
    /// Version assertion.
    Version,
    /// Causal mechanism assertion.
    Causal,
    /// Absence assertion; needs complete suitable authoritative coverage.
    Absence,
}

/// Rank of a source authority tier (strongest first).
#[must_use]
pub const fn source_authority_rank(authority: SourceAuthority) -> u64 {
    match authority {
        SourceAuthority::Authoritative => 0,
        SourceAuthority::Competent => 1,
        SourceAuthority::Limited => 2,
        SourceAuthority::Unknown => 3,
    }
}

/// Rank of a citation precision level (strongest first).
#[must_use]
pub const fn precision_rank(precision: Precision) -> u64 {
    match precision {
        Precision::Exact => 0,
        Precision::Qualified => 1,
        Precision::Unsupported => 2,
    }
}

/// Rank of a precision kind for canonical ordering.
#[must_use]
pub const fn precision_kind_rank(kind: PrecisionKind) -> u64 {
    match kind {
        PrecisionKind::Documentary => 0,
        PrecisionKind::Numeric => 1,
        PrecisionKind::Time => 2,
        PrecisionKind::Version => 3,
        PrecisionKind::Causal => 4,
        PrecisionKind::General => 5,
    }
}

/// Rank of an omission kind for canonical ordering.
#[must_use]
pub const fn omission_kind_rank(kind: OmissionKind) -> u64 {
    match kind {
        OmissionKind::Claims => 0,
        OmissionKind::Rivals => 1,
        OmissionKind::References => 2,
        OmissionKind::Probes => 3,
        OmissionKind::Unknowns => 4,
        OmissionKind::Work => 5,
        OmissionKind::OutputBytes => 6,
        OmissionKind::Concilium => 7,
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ClaimDisposition {
    /// Retained with accepted support.
    Supported,
    /// Coherent support and undefeated counter-evidence coexist.
    Contested,
    /// No accepted support survived projection.
    Unsupported,
    /// A reference left the authorized set; rejected, never sourced.
    OutsideManifest,
    /// Required precision is unsupported; qualifiers preserved.
    PrecisionLimited,
    /// Absence proven under complete suitable authoritative coverage.
    AbsentScopeComplete,
    /// Absence unprovable: coverage partial, sampled, or unknown.
    AbsentScopeIncomplete,
    /// Byte-identical repeat of an already projected claim.
    DuplicateCollapsed,
    /// Withheld by privacy, budget, or policy; reopening reference kept.
    Withheld,
}

/// Canonical wire spelling of a claim disposition.
#[must_use]
pub const fn claim_disposition_as_str(disposition: ClaimDisposition) -> &'static str {
    match disposition {
        ClaimDisposition::Supported => "supported",
        ClaimDisposition::Contested => "contested",
        ClaimDisposition::Unsupported => "unsupported",
        ClaimDisposition::OutsideManifest => "outside-manifest",
        ClaimDisposition::PrecisionLimited => "precision-limited",
        ClaimDisposition::AbsentScopeComplete => "absent-scope-complete",
        ClaimDisposition::AbsentScopeIncomplete => "absent-scope-incomplete",
        ClaimDisposition::DuplicateCollapsed => "duplicate-collapsed",
        ClaimDisposition::Withheld => "withheld",
    }
}

/// Overall outcome of one synthesis call (candidate ceiling only).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SynthesisDisposition {
    /// Complete candidate brief; every input role projected.
    Complete,
    /// Candidate brief with explicit omissions or residue.
    Partial,
    /// Work budget exhausted before the matrix closed.
    Exhausted,
    /// Evidence cannot support a useful brief; nothing invented.
    Abstained,
    /// Cancellation, deadline, or stale policy stopped projection.
    Blocked,
    /// No claim survived projection with support.
    Unsupported,
    /// Live opposed rivals on one claim; both sides preserved.
    Conflicted,
    /// Coverage unknown and nothing supported; unknown stays unknown.
    Unknown,
}

/// Canonical wire spelling of a synthesis disposition.
#[must_use]
pub const fn synthesis_disposition_as_str(disposition: SynthesisDisposition) -> &'static str {
    match disposition {
        SynthesisDisposition::Complete => "complete",
        SynthesisDisposition::Partial => "partial",
        SynthesisDisposition::Exhausted => "exhausted",
        SynthesisDisposition::Abstained => "abstained",
        SynthesisDisposition::Blocked => "blocked",
        SynthesisDisposition::Unsupported => "unsupported",
        SynthesisDisposition::Conflicted => "conflicted",
        SynthesisDisposition::Unknown => "unknown",
    }
}

/// Maps a native disposition to the `#634` guest `candidate-disposition`
/// spelling so the downstream adapter can prove component parity without
/// redefining the native outcome.
#[must_use]
pub const fn guest_parity_disposition(disposition: SynthesisDisposition) -> &'static str {
    match disposition {
        SynthesisDisposition::Complete => "candidate",
        SynthesisDisposition::Partial | SynthesisDisposition::Exhausted => "partial",
        SynthesisDisposition::Abstained => "abstention",
        SynthesisDisposition::Blocked => "blocked",
        SynthesisDisposition::Unsupported | SynthesisDisposition::Unknown => "unsupported",
        SynthesisDisposition::Conflicted => "conflict",
    }
}

/// The seven I9.7 preservation dimensions, checked independently.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub enum PreservationDimension {
    /// Load-bearing source elements represented.
    Coverage,
    /// Alternatives, minority, and temporal distinctions not erased.
    Preservation,
    /// No unsupported additions.
    Faithfulness,
    /// Every material conclusion traceable.
    Lineage,
    /// Sources can be reopened from the brief.
    Reversibility,
    /// Transformation never raises the authority ceiling.
    SourceAuthority,
    /// Revocation and omission propagate to reopening references.
    DependencyClosure,
}

/// All seven preservation dimensions in canonical order.
#[must_use]
pub const fn preservation_dimensions() -> [PreservationDimension; 7] {
    use PreservationDimension::{
        Coverage, DependencyClosure, Faithfulness, Lineage, Preservation, Reversibility,
        SourceAuthority,
    };
    [
        Coverage,
        Preservation,
        Faithfulness,
        Lineage,
        Reversibility,
        SourceAuthority,
        DependencyClosure,
    ]
}

/// Canonical wire spelling of a preservation dimension.
#[must_use]
pub const fn preservation_dimension_as_str(dimension: PreservationDimension) -> &'static str {
    match dimension {
        PreservationDimension::Coverage => "coverage",
        PreservationDimension::Preservation => "preservation",
        PreservationDimension::Faithfulness => "faithfulness",
        PreservationDimension::Lineage => "lineage",
        PreservationDimension::Reversibility => "reversibility",
        PreservationDimension::SourceAuthority => "source-authority",
        PreservationDimension::DependencyClosure => "dependency-closure",
    }
}

/// Coverage denominator kind (I21.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DenominatorKind {
    /// Frozen scope fully covered; the only basis for an absence claim.
    CompleteScope,
    /// Sampled with a declared method; absence stays unproven.
    Sampled,
    /// Denominator unknown; unknown stays unknown.
    Unknown,
}

/// Counter-search status backing absence reasoning.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CounterSearchStatus {
    /// Counter-search ran to completion on the frozen scope.
    Complete,
    /// Counter-search partial or interrupted.
    Partial,
    /// Counter-search never ran.
    NotRun,
}

/// Claim-specific source authority tier (strongest first).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SourceAuthority {
    /// Authoritative for this claim.
    Authoritative,
    /// Competent for this claim.
    Competent,
    /// Limited for this claim.
    Limited,
    /// Authority not observed.
    Unknown,
}

/// Stance of a rival position toward one target claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RivalStance {
    /// Rival supports the target claim.
    Supports,
    /// Rival opposes the target claim.
    Opposes,
    /// Rival offers an alternative framing.
    Alternative,
}

/// Why a supplied probe was not recommended.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ProbeResidueReason {
    /// Fewer than two distinct outcome alternatives or no live target.
    Nondiscriminative,
    /// Discriminates only unknown or invented handles.
    UnknownTarget,
    /// Neither allowlisted nor covered by a policy-authorized transform.
    Unauthorized,
    /// Cut by the probe budget with the denominator preserved.
    Budget,
}

/// Which independent bound produced an omission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OmissionKind {
    /// Claim bound cut the matrix.
    Claims,
    /// Rival bound cut the portfolio.
    Rivals,
    /// Reference bound cut evidence projection.
    References,
    /// Probe bound cut recommendations.
    Probes,
    /// Unknown bound cut the gap list.
    Unknowns,
    /// Work budget exhausted projection.
    Work,
    /// Output byte budget elided optional sections.
    OutputBytes,
    /// Concilium suppressed by policy.
    Concilium,
}

// ---------- input types ----------

/// One governed source card from the acquisition boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceCard {
    /// Exact authorized handle; the only citable spelling.
    pub handle: String,
    /// Grade the evidence was produced under; never upgraded by quotation.
    pub grade: EvidenceGrade,
    /// Claim-specific authority tier.
    pub authority: SourceAuthority,
    /// Observed freshness.
    pub freshness: Freshness,
    /// Competence scope in one short phrase.
    pub competence: String,
    /// Privacy class governing allowed use.
    pub privacy_class: String,
    /// Allowed-use statement.
    pub allowed_use: String,
    /// Canonical lineage group; `"unknown"` keeps unknown independence.
    pub lineage_group: String,
    /// `true` when the evidence was transformed after admission.
    pub transformed: bool,
}

/// One exact citation inside the allowed reference manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Citation {
    /// Cited source handle; must stay inside the authorized set.
    pub source_handle: String,
    /// Precision this citation supports.
    pub precision: Precision,
    /// Kind of precision asserted.
    pub kind: PrecisionKind,
}

/// One counterclaim preserved against its parent claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Counterclaim {
    /// Counterclaim artifact handle.
    pub counterclaim_id: String,
    /// Material shape of the counterclaim.
    pub kind: ClaimKind,
    /// Source handle carrying the counterclaim.
    pub source_handle: String,
    /// Exact citations backing the counterclaim.
    pub citations: Vec<Citation>,
    /// Original counterclaim statement, preserved verbatim.
    pub statement: String,
}

/// One grounded structured claim from the A-03 validated draft.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructuredClaim {
    /// Claim artifact handle.
    pub claim_id: String,
    /// Material shape of the claim.
    pub kind: ClaimKind,
    /// Original claim statement, preserved verbatim.
    pub statement: String,
    /// Accepted supporting citations.
    pub support: Vec<Citation>,
    /// Preserved counterclaims; never dropped.
    pub counterclaims: Vec<Counterclaim>,
    /// `true` only when a grounded relation backs a causal claim.
    pub grounded_relation: bool,
    /// Scope, time, version, unit, or modality qualifiers.
    pub scope_note: String,
}

/// One rival position from the grounded portfolio.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructuredRival {
    /// Rival artifact handle.
    pub rival_id: String,
    /// Rival position, preserved verbatim.
    pub position: String,
    /// Stance toward the target claim.
    pub stance: RivalStance,
    /// Target claim handle.
    pub target_claim: String,
    /// Minority positions are retained, never resolved away.
    pub minority: bool,
    /// Exact citations backing the rival.
    pub evidence: Vec<Citation>,
}

/// One unknown carried by the grounded draft.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DraftUnknown {
    /// Unknown artifact handle.
    pub unknown_id: String,
    /// Unknown detail, preserved verbatim.
    pub detail: String,
}

/// Provenance basis of one supplied probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProbeBasis {
    /// Supplied structured discriminative question or probe.
    SuppliedDiscriminative,
    /// Canonical transform already authorized by the policy.
    CanonicalTransform(String),
}

/// One supplied structured discriminative probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructuredProbe {
    /// Probe artifact handle.
    pub probe_id: String,
    /// Provenance basis of this probe.
    pub basis: ProbeBasis,
    /// Rival, unknown, or claim handles this probe distinguishes.
    pub discriminates: Vec<String>,
    /// Outcome alternatives; two distinct outcomes keep it discriminative.
    pub outcomes: Vec<String>,
    /// Verifier or owner of the probe outcome.
    pub verifier: String,
    /// Owning role for probe execution (recommendation only).
    pub owner: String,
    /// Cost class in one short phrase.
    pub cost_class: String,
    /// Applicability conditions in one short phrase.
    pub applicability: String,
}

/// Inert Concilium input carried by the grounded draft.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DraftConcilium {
    /// Decision owner the recommendation is bound to.
    pub owner: String,
    /// Evidence handles under review.
    pub evidence_refs: Vec<String>,
    /// Positions under review.
    pub positions: Vec<String>,
    /// Review objective.
    pub review_objective: String,
}

/// Source omitted from representation with its exact reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OmittedSource {
    /// Omitted source handle.
    pub handle: String,
    /// Exact reason (unavailable, withheld, out-of-scope, degraded).
    pub reason: String,
}

/// Governed immutable acquisition boundary (I9.3 `ResearchPack`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResearchPack {
    /// Digest of the governed pack content (see [`crate::pack_content_digest`]).
    pub pack_digest: String,
    /// Exact governed question.
    pub question: String,
    /// Bound task identity.
    pub task_id: String,
    /// Bound scope identity.
    pub scope_id: String,
    /// Bound fence epoch.
    pub fence_epoch: String,
    /// Bound fence generation.
    pub fence_generation: u64,
    /// Owning bundle digest.
    pub bundle_digest: String,
    /// Allowed-reference-manifest digest (I21.7).
    pub manifest_digest: String,
    /// Governed source cards; the only citable set.
    pub sources: Vec<SourceCard>,
    /// Coverage denominator handles (I21.6).
    pub source_denominator: Vec<String>,
    /// Denominator kind backing absence reasoning.
    pub coverage_denominator: DenominatorKind,
    /// Counter-search status backing absence reasoning.
    pub counter_search: CounterSearchStatus,
    /// Missing source classes with reasons.
    pub missing_source_classes: Vec<String>,
    /// Denominator members not represented, with reasons.
    pub omitted_sources: Vec<OmittedSource>,
}

/// Exact A-03 validated grounded structured draft.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroundedDraft {
    /// Digest of the draft content (see [`crate::draft_content_digest`]).
    pub draft_digest: String,
    /// Grounding digest binding the draft to admitted grounding.
    pub grounding_digest: String,
    /// Bound task identity.
    pub task_id: String,
    /// Bound scope identity.
    pub scope_id: String,
    /// Exact question; must equal the pack question.
    pub question: String,
    /// Material claims under synthesis.
    pub claims: Vec<StructuredClaim>,
    /// Rival portfolio under synthesis.
    pub rivals: Vec<StructuredRival>,
    /// Unknowns under synthesis.
    pub unknowns: Vec<DraftUnknown>,
    /// Supplied discriminative probes.
    pub probes: Vec<StructuredProbe>,
    /// Inert Concilium input.
    pub concilium: DraftConcilium,
}

/// Pre-handler input-validation receipt, inherited exactly, never re-proved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputReceipt {
    /// Receipt digest binding the validated input.
    pub receipt_digest: String,
    /// Task identity the receipt was issued for.
    pub task_id: String,
    /// Scope identity the receipt was issued for.
    pub scope_id: String,
    /// Fence epoch the receipt was issued under.
    pub fence_epoch: String,
    /// Fence generation the receipt was issued under.
    pub fence_generation: u64,
    /// Bundle digest the receipt covers.
    pub bundle_digest: String,
    /// Manifest digest the receipt covers.
    pub manifest_digest: String,
    /// Grounding digest the receipt covers.
    pub grounding_digest: String,
    /// Input-validator revision that issued the receipt.
    pub validator_revision: String,
}

/// Immutable synthesis policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SynthesisPolicy {
    /// Digest of the governing policy revision.
    pub policy_digest: String,
    /// Policy revision label.
    pub revision: String,
    /// Newest fence generation this policy revision governs.
    pub valid_through_generation: u64,
    /// `false` forces abstention instead of a partial brief.
    pub allow_partial: bool,
    /// `true` authorizes supplied discriminative probes without allowlisting.
    pub authorize_supplied_discriminative: bool,
    /// Probe handles explicitly allowlisted by the governor.
    pub probe_allowlist: Vec<String>,
    /// Canonical transforms the policy already authorizes.
    pub canonical_transforms: Vec<String>,
    /// `false` suppresses the Concilium recommendation into an omission.
    pub concilium_allowed: bool,
    /// Freshness floor below which evidence is capped, never promoted.
    pub freshness_floor: Freshness,
}

/// Independent output and work bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SynthesisBounds {
    /// Input byte ceiling.
    pub max_input_bytes: u64,
    /// Output byte ceiling.
    pub max_output_bytes: u64,
    /// Claim-matrix ceiling.
    pub max_claims: u64,
    /// Rival-portfolio ceiling.
    pub max_rivals: u64,
    /// Evidence-reference ceiling.
    pub max_references: u64,
    /// Recommended-probe ceiling.
    pub max_probes: u64,
    /// Work-unit ceiling.
    pub max_work: u64,
}

/// Cancellation, deadline, and clock view supplied by the caller.
///
/// The operation owns no clock: `now_ms` is observed caller data, and a
/// present deadline without an observed `now_ms` never fires.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancellationView {
    /// Pre-handler cancellation flag.
    pub cancelled: bool,
    /// Caller-observed now in milliseconds, when observed.
    pub now_ms: Option<u64>,
    /// Wall deadline in milliseconds, when bounded.
    pub deadline_ms: Option<u64>,
}

/// Validated job binding (I9.4 `DreamJobAdmission` projection).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobBinding {
    /// Operation identity.
    pub operation_id: String,
    /// Job-class wire spelling; only `research-synthesis` is accepted.
    pub job_class: String,
    /// Idempotency key binding this attempt.
    pub idempotency_key: String,
    /// Requester principal.
    pub requester_principal: String,
    /// Requester origin.
    pub requester_origin: RequesterOrigin,
    /// Requester session.
    pub requester_session: String,
    /// Task identity.
    pub task_id: String,
    /// Attempt identity.
    pub attempt_id: String,
    /// Scope identity.
    pub scope_id: String,
    /// Fence epoch.
    pub fence_epoch: String,
    /// Fence generation.
    pub fence_generation: u64,
}

/// The single input of the pure synthesis operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SynthesisRequest {
    /// Schema revision; only [`SYNTHESIS_SCHEMA_REVISION`](crate::bounds::SYNTHESIS_SCHEMA_REVISION) is implemented.
    pub schema_revision: u32,
    /// Validated job binding.
    pub binding: JobBinding,
    /// Governed immutable research pack.
    pub pack: ResearchPack,
    /// Exact grounded structured draft.
    pub draft: GroundedDraft,
    /// Inherited pre-handler validation receipt.
    pub receipt: InputReceipt,
    /// Immutable synthesis policy.
    pub policy: SynthesisPolicy,
    /// Independent bounds.
    pub bounds: SynthesisBounds,
    /// Cancellation and deadline view.
    pub cancellation: CancellationView,
}

// ---------- output types ----------

/// One projected row of the claim/counterclaim matrix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimVerdict {
    /// Input claim or counterclaim handle.
    pub claim_id: String,
    /// `true` for counterclaim rows, `false` for claim rows.
    pub is_counterclaim: bool,
    /// Material shape of the input.
    pub kind: ClaimKind,
    /// Exactly one disposition for this input.
    pub disposition: ClaimDisposition,
    /// Retained supporting source handles, canonical order.
    pub support: Vec<String>,
    /// Retained counter-evidence source handles, canonical order.
    pub counter_evidence: Vec<String>,
    /// Exact citations projected into the brief, canonical order.
    pub citations: Vec<String>,
    /// Weakest grade across accepted support; never inflated.
    pub weakest_grade: EvidenceGrade,
    /// Weakest claim-specific authority across accepted support.
    pub authority: SourceAuthority,
    /// Canonical lineage groups behind this verdict.
    pub lineage_groups: Vec<String>,
    /// Precision and freshness notes; hedges preserved verbatim.
    pub precision_notes: Vec<String>,
    /// Absence basis when the kind is absence.
    pub absence_basis: String,
}

/// One retained rival position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RivalPosition {
    /// Rival artifact handle.
    pub rival_id: String,
    /// Rival position, preserved verbatim.
    pub position: String,
    /// Stance toward the target claim.
    pub stance: RivalStance,
    /// Target claim handle.
    pub target_claim: String,
    /// Minority positions are retained, never resolved away.
    pub minority: bool,
    /// Retained evidence handles, canonical order.
    pub evidence: Vec<String>,
    /// Weakest grade across retained evidence.
    pub weakest_grade: EvidenceGrade,
}

/// One recommended discriminative probe (recommendation only).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecommendedProbe {
    /// Probe artifact handle.
    pub probe_id: String,
    /// Rival, unknown, or claim handles this probe distinguishes.
    pub discriminates: Vec<String>,
    /// Outcome alternatives (always at least two distinct entries).
    pub outcomes: Vec<String>,
    /// Verifier of the probe outcome.
    pub verifier: String,
    /// Owning role for probe execution.
    pub owner: String,
    /// Cost class in one short phrase.
    pub cost_class: String,
    /// Applicability conditions in one short phrase.
    pub applicability: String,
}

/// One supplied probe kept out of the recommendations with its reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeResidue {
    /// Supplied probe handle.
    pub probe_id: String,
    /// Why the probe was not recommended.
    pub reason: ProbeResidueReason,
    /// Exact machine-readable explanation.
    pub detail: String,
}

/// Sources grouped by canonical authoritative lineage (I21.6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependenceGroup {
    /// Canonical lineage group, or `"unknown"` for unknown independence.
    pub lineage_group: String,
    /// Member source handles, canonical order.
    pub members: Vec<String>,
    /// Distinct authoritative roots behind the group.
    pub independent_roots: u64,
    /// `true` only for the unknown-independence group.
    pub unknown: bool,
}

/// Inert Concilium recommendation: names evidence, positions, and review
/// objective. It creates no meeting, message, job, budget, or agent; the
/// effect count is therefore always zero.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConciliumRecommendation {
    /// Decision owner the recommendation is bound to.
    pub owner: String,
    /// Evidence handles under review.
    pub evidence_refs: Vec<String>,
    /// Positions under review.
    pub positions: Vec<String>,
    /// Review objective.
    pub review_objective: String,
    /// Always zero; the recommendation creates nothing.
    pub effect_count: u64,
    /// `true` when policy suppressed the recommendation into an omission.
    pub suppressed: bool,
}

/// Visible coverage report with gaps (I21.6 `CoverageReceipt` projection).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageReport {
    /// Denominator kind backing absence reasoning.
    pub denominator: DenominatorKind,
    /// Counter-search status backing absence reasoning.
    pub counter_search: CounterSearchStatus,
    /// Missing source classes with reasons.
    pub missing_classes: Vec<String>,
    /// Denominator members not represented, with reasons.
    pub omitted_sources: Vec<OmittedSource>,
    /// Eligible sources actually represented, canonical order.
    pub represented_sources: Vec<String>,
    /// Sources actually cited, canonical order.
    pub cited_sources: Vec<String>,
}

/// One bounded omission with its preserved denominator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Omission {
    /// Which independent bound produced the omission.
    pub kind: OmissionKind,
    /// Exact machine-readable explanation with a reopening reference.
    pub detail: String,
    /// Declared denominator the omission was cut from.
    pub denominator: u64,
    /// Items actually omitted.
    pub omitted: u64,
}

/// One I9.7 preservation verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreservationVerdict {
    /// Dimension under check.
    pub dimension: PreservationDimension,
    /// Whether the dimension passed.
    pub passed: bool,
    /// Whether the verdict is known (`false` keeps the unknown explicit).
    pub known: bool,
    /// Human-readable note.
    pub note: String,
}

/// Candidate research brief: claims, counterclaims, exact citations, source
/// dependence, rivals, unknowns, probes, and an inert Concilium plan kept
/// separate. It never converts the pack into project truth.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResearchBrief {
    /// Deterministic brief identity derived from the input digest.
    pub brief_id: String,
    /// Pack digest this brief answers.
    pub pack_digest: String,
    /// Exact governed question.
    pub question: String,
    /// Typed claim/counterclaim matrix, input order preserved.
    pub claim_matrix: Vec<ClaimVerdict>,
    /// Retained rival portfolio, input order preserved.
    pub rivals: Vec<RivalPosition>,
    /// Preserved unknowns, canonical order.
    pub unknowns: Vec<String>,
    /// Recommended discriminative probes, input order preserved.
    pub probes: Vec<RecommendedProbe>,
    /// Supplied probes kept out of the recommendations.
    pub probe_residue: Vec<ProbeResidue>,
    /// Inert Concilium recommendation.
    pub concilium: ConciliumRecommendation,
    /// Visible coverage report with gaps.
    pub coverage: CoverageReport,
    /// Source dependence by canonical lineage.
    pub dependence: Vec<DependenceGroup>,
    /// Brief disposition.
    pub disposition: SynthesisDisposition,
    /// Seven I9.7 preservation verdicts, canonical order.
    pub preservation: Vec<PreservationVerdict>,
    /// Bounded omissions with preserved denominators.
    pub omitted: Vec<Omission>,
    /// Digest of the exact brief bytes (order-sensitive).
    pub raw_digest: String,
    /// Digest of the canonical brief bytes (order-insensitive).
    pub semantic_digest: String,
}

/// Candidate-only outcome of one synthesis call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SynthesisOutcome {
    /// Overall disposition at candidate ceiling.
    pub disposition: SynthesisDisposition,
    /// Candidate brief; `None` when blocked before projection.
    pub brief: Option<ResearchBrief>,
    /// Seven I9.7 preservation verdicts, canonical order.
    pub preservation: Vec<PreservationVerdict>,
    /// Exact inherited input-validation receipt (evidence, not re-proof).
    pub inherited_receipt: InputReceipt,
    /// Digest of the canonical request bytes.
    pub input_digest: String,
    /// Digest of the outcome: brief semantic digest or error digest.
    pub output_digest: String,
    /// Work units actually consumed.
    pub work_used: u64,
    /// Bounded omissions with preserved denominators.
    pub omitted: Vec<Omission>,
}

// ---------- errors ----------

/// Typed synthesis failure: malformed input or an internal defect.
///
/// Diagnostics are bounded and redacted: field values longer than
/// [`crate::bounds::DIAGNOSTIC_VALUE_PREFIX`]
/// characters are cut with a marker, and secrets never enter a diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SynthesisError {
    /// Field-level shape failure.
    Malformed {
        /// Offending field path.
        field: String,
        /// Bounded human-readable detail.
        detail: String,
    },
    /// A known but wrong job, profile, or closed-schema spelling.
    KindMismatch {
        /// Expected spelling.
        want: String,
        /// Observed spelling.
        got: String,
        /// Bounded human-readable detail.
        detail: String,
    },
    /// Unsupported envelope revision.
    UnsupportedSchema {
        /// Implemented revision.
        want_revision: u32,
        /// Observed revision.
        got_revision: u32,
        /// Bounded human-readable detail.
        detail: String,
    },
    /// Cross-binding failure between job, pack, draft, and receipt.
    ReferenceMismatch {
        /// Binding path that failed.
        field: String,
        /// Expected value (digest or identity).
        want: String,
        /// Observed value (digest or identity).
        got: String,
    },
    /// A handle outside the authorized set would need fresh sourcing.
    AcquisitionRejected {
        /// Offending handle.
        handle: String,
        /// Bounded human-readable detail.
        detail: String,
    },
    /// An independent bound rejected the input before projection.
    BudgetExceeded {
        /// Bounded human-readable detail.
        detail: String,
    },
    /// Internal defect: an invariant the stages must uphold broke.
    Internal {
        /// Bounded human-readable detail.
        detail: String,
    },
}

impl Display for SynthesisError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Malformed { field, detail } => {
                write!(formatter, "malformed {field}: {detail}")
            }
            Self::KindMismatch { want, got, detail } => {
                write!(formatter, "kind mismatch: want {want}, got {got}: {detail}")
            }
            Self::UnsupportedSchema {
                want_revision,
                got_revision,
                detail,
            } => write!(
                formatter,
                "unsupported schema: want revision {want_revision}, got {got_revision}: {detail}"
            ),
            Self::ReferenceMismatch { field, want, got } => {
                write!(
                    formatter,
                    "reference mismatch at {field}: want {want}, got {got}"
                )
            }
            Self::AcquisitionRejected { handle, detail } => {
                write!(formatter, "outside-manifest reference {handle}: {detail}")
            }
            Self::BudgetExceeded { detail } => {
                write!(formatter, "budget exceeded: {detail}")
            }
            Self::Internal { detail } => {
                write!(formatter, "internal synthesis failure: {detail}")
            }
        }
    }
}

impl std::error::Error for SynthesisError {}

// ---------- small public helpers ----------

/// Bounds a diagnostic value: keeps the prefix, marks redaction.
#[must_use]
pub fn redact_value(value: &str) -> String {
    if value.len() <= DIAGNOSTIC_VALUE_PREFIX {
        value.to_owned()
    } else {
        let mut out = String::with_capacity(DIAGNOSTIC_VALUE_PREFIX + REDACTED_SUFFIX.len());
        out.push_str(&value[..DIAGNOSTIC_VALUE_PREFIX]);
        out.push_str(REDACTED_SUFFIX);
        out
    }
}

/// Returns `true` when `value` is a non-empty handle within the ceiling.
#[must_use]
pub fn is_handle(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_HANDLE_BYTES
}

/// Returns `true` when `value` is non-empty prose within the ceiling.
#[must_use]
pub fn is_text(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_TEXT_BYTES
}

/// Returns `true` when `value` is shaped like a 64-character hex digest.
#[must_use]
pub fn is_digest(value: &str) -> bool {
    is_digest_hex(value)
}

// ---------- canonical encodings ----------

fn write_citation(citation: &Citation, writer: &mut CanonicalWriter) {
    writer.text("citation.source", &citation.source_handle);
    writer.text(
        "citation.precision",
        match citation.precision {
            Precision::Exact => "exact",
            Precision::Qualified => "qualified",
            Precision::Unsupported => "unsupported",
        },
    );
    writer.text(
        "citation.kind",
        match citation.kind {
            PrecisionKind::Documentary => "documentary",
            PrecisionKind::Numeric => "numeric",
            PrecisionKind::Time => "time",
            PrecisionKind::Version => "version",
            PrecisionKind::Causal => "causal",
            PrecisionKind::General => "general",
        },
    );
}

fn write_source_card(card: &SourceCard, writer: &mut CanonicalWriter) {
    writer.text("source.handle", &card.handle);
    writer.text("source.grade", evidence_grade_as_str(card.grade));
    writer.integer("source.authority", source_authority_rank(card.authority));
    writer.text(
        "source.freshness",
        match card.freshness {
            Freshness::Fresh => "fresh",
            Freshness::Stale => "stale",
            Freshness::Unknown => "unknown",
        },
    );
    writer.text("source.competence", &card.competence);
    writer.text("source.privacy", &card.privacy_class);
    writer.text("source.allowed_use", &card.allowed_use);
    writer.text("source.lineage", &card.lineage_group);
    writer.flag("source.transformed", card.transformed);
}

/// Canonical pack bytes. `semantic` sorts order-irrelevant sets; raw mode
/// preserves input order so replays stay comparable on both digests.
#[must_use]
pub fn pack_canonical_bytes(pack: &ResearchPack, semantic: bool) -> Vec<u8> {
    let mut writer = CanonicalWriter::new();
    writer.text("pack.question", &pack.question);
    writer.text("pack.task", &pack.task_id);
    writer.text("pack.scope", &pack.scope_id);
    writer.text("pack.fence_epoch", &pack.fence_epoch);
    writer.integer("pack.fence_generation", pack.fence_generation);
    writer.text("pack.bundle", &pack.bundle_digest);
    writer.text("pack.manifest", &pack.manifest_digest);
    writer.text(
        "pack.denominator_kind",
        match pack.coverage_denominator {
            DenominatorKind::CompleteScope => "complete-scope",
            DenominatorKind::Sampled => "sampled",
            DenominatorKind::Unknown => "unknown",
        },
    );
    writer.text(
        "pack.counter_search",
        match pack.counter_search {
            CounterSearchStatus::Complete => "complete",
            CounterSearchStatus::Partial => "partial",
            CounterSearchStatus::NotRun => "not-run",
        },
    );
    let mut cards: Vec<&SourceCard> = pack.sources.iter().collect();
    if semantic {
        cards.sort_by(|left, right| left.handle.cmp(&right.handle));
    }
    for card in cards {
        let mut section = CanonicalWriter::new();
        write_source_card(card, &mut section);
        writer.section("pack.source", &section.finish());
    }
    let mut denominator = pack.source_denominator.clone();
    if semantic {
        denominator.sort();
    }
    for handle in &denominator {
        writer.text("pack.denominator", handle);
    }
    let mut missing = pack.missing_source_classes.clone();
    if semantic {
        missing.sort();
    }
    for class in &missing {
        writer.text("pack.missing_class", class);
    }
    let mut omitted: Vec<(&str, &str)> = pack
        .omitted_sources
        .iter()
        .map(|entry| (entry.handle.as_str(), entry.reason.as_str()))
        .collect();
    if semantic {
        omitted.sort_unstable();
    }
    for (handle, reason) in omitted {
        let mut section = CanonicalWriter::new();
        section.text("omitted.handle", handle);
        section.text("omitted.reason", reason);
        writer.section("pack.omitted", &section.finish());
    }
    writer.finish()
}

fn write_counterclaim(counter: &Counterclaim, writer: &mut CanonicalWriter, semantic: bool) {
    writer.text("counterclaim.id", &counter.counterclaim_id);
    writer.text("counterclaim.source", &counter.source_handle);
    writer.text("counterclaim.statement", &counter.statement);
    let mut citations = counter.citations.clone();
    if semantic {
        citations.sort_by(|left, right| {
            left.source_handle
                .cmp(&right.source_handle)
                .then_with(|| precision_rank(left.precision).cmp(&precision_rank(right.precision)))
                .then_with(|| precision_kind_rank(left.kind).cmp(&precision_kind_rank(right.kind)))
        });
    }
    for citation in &citations {
        let mut section = CanonicalWriter::new();
        write_citation(citation, &mut section);
        writer.section("counterclaim.citation", &section.finish());
    }
}

/// Canonical bytes of one counterclaim, raw or semantic.
#[must_use]
pub fn counterclaim_canonical_bytes(counter: &Counterclaim, semantic: bool) -> Vec<u8> {
    let mut writer = CanonicalWriter::new();
    write_counterclaim(counter, &mut writer, semantic);
    writer.finish()
}

fn write_claim(claim: &StructuredClaim, writer: &mut CanonicalWriter, semantic: bool) {
    writer.text("claim.id", &claim.claim_id);
    writer.text("claim.statement", &claim.statement);
    writer.text("claim.scope", &claim.scope_note);
    writer.flag("claim.grounded_relation", claim.grounded_relation);
    let mut support = claim.support.clone();
    if semantic {
        support.sort_by(|left, right| {
            left.source_handle
                .cmp(&right.source_handle)
                .then_with(|| precision_rank(left.precision).cmp(&precision_rank(right.precision)))
                .then_with(|| precision_kind_rank(left.kind).cmp(&precision_kind_rank(right.kind)))
        });
    }
    for citation in &support {
        let mut section = CanonicalWriter::new();
        write_citation(citation, &mut section);
        writer.section("claim.support", &section.finish());
    }
    let mut counters: Vec<&Counterclaim> = claim.counterclaims.iter().collect();
    if semantic {
        counters.sort_by(|left, right| left.counterclaim_id.cmp(&right.counterclaim_id));
    }
    for counter in counters {
        let mut section = CanonicalWriter::new();
        write_counterclaim(counter, &mut section, semantic);
        writer.section("claim.counterclaim", &section.finish());
    }
}

/// Canonical draft bytes, raw or semantic like the pack encoding.
#[must_use]
pub fn draft_canonical_bytes(draft: &GroundedDraft, semantic: bool) -> Vec<u8> {
    let mut writer = CanonicalWriter::new();
    writer.text("draft.grounding", &draft.grounding_digest);
    writer.text("draft.task", &draft.task_id);
    writer.text("draft.scope", &draft.scope_id);
    writer.text("draft.question", &draft.question);
    let mut claims: Vec<&StructuredClaim> = draft.claims.iter().collect();
    if semantic {
        claims.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
    }
    for claim in claims {
        let mut section = CanonicalWriter::new();
        write_claim(claim, &mut section, semantic);
        writer.section("draft.claim", &section.finish());
    }
    let mut rivals: Vec<&StructuredRival> = draft.rivals.iter().collect();
    if semantic {
        rivals.sort_by(|left, right| left.rival_id.cmp(&right.rival_id));
    }
    for rival in rivals {
        let mut section = CanonicalWriter::new();
        section.text("rival.id", &rival.rival_id);
        section.text("rival.position", &rival.position);
        section.text("rival.target", &rival.target_claim);
        section.flag("rival.minority", rival.minority);
        writer.section("draft.rival", &section.finish());
    }
    let mut unknowns: Vec<&DraftUnknown> = draft.unknowns.iter().collect();
    if semantic {
        unknowns.sort_by(|left, right| left.unknown_id.cmp(&right.unknown_id));
    }
    for unknown in unknowns {
        let mut section = CanonicalWriter::new();
        section.text("unknown.id", &unknown.unknown_id);
        section.text("unknown.detail", &unknown.detail);
        writer.section("draft.unknown", &section.finish());
    }
    let mut probes: Vec<&StructuredProbe> = draft.probes.iter().collect();
    if semantic {
        probes.sort_by(|left, right| left.probe_id.cmp(&right.probe_id));
    }
    for probe in probes {
        let mut section = CanonicalWriter::new();
        section.text("probe.id", &probe.probe_id);
        for target in &probe.discriminates {
            section.text("probe.target", target);
        }
        for outcome in &probe.outcomes {
            section.text("probe.outcome", outcome);
        }
        writer.section("draft.probe", &section.finish());
    }
    writer.text("concilium.owner", &draft.concilium.owner);
    writer.text("concilium.objective", &draft.concilium.review_objective);
    writer.finish()
}

/// Canonical bytes of one structured claim, raw or semantic.
#[must_use]
pub fn claim_canonical_bytes(claim: &StructuredClaim, semantic: bool) -> Vec<u8> {
    let mut writer = CanonicalWriter::new();
    write_claim(claim, &mut writer, semantic);
    writer.finish()
}
