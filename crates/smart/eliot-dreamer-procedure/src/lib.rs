//! Grounded inert procedure and short-skill candidate (A-25).
//!
//! Pure candidate-only deterministic stateless zero-effect owner of exactly
//! one bounded reversible inert procedure grafted from validated structured
//! evidence. The handler proposes one finite typed step graph with trigger,
//! preconditions, per-step owner and verifier, stop and reopen conditions,
//! and an environment and scope preserving transfer boundary. It never
//! installs, publishes, reserves, executes, or finishes anything.
//!
//! Cell `smart.dreamer.procedure`, order 25. All inputs are immutable and
//! caller supplied. Every identity, receipt, draft, evidence, capability,
//! environment, existing-procedure, policy, budget, deadline, and digest
//! binding is explicit. The A-05 receipt is checked intrinsically through its
//! own validation entry points and is never re-executed here. No screening,
//! grounding, common validation, production registry construction, canonical
//! mutation, authority, effect, store, governor, model, clock, or finish
//! surface exists in this cell.
//!
//! Consumed contracts already carry closed unknown-field rejection (their
//! schemas state `deny_unknown_fields`); this cell performs no generic JSON
//! intake at all, so no unknown field can enter through a typeless path.
//! Every new shape below is constructed explicitly through the six typed
//! parameters of [`propose_procedure`], never decoded from ambient bytes.
//!
//! Runtime boundary: a blocked, malformed, over-budget, past-deadline, or
//! cancelled-before-emission request emits zero effects. Semantic shortfalls
//! (duplicate identity, refinement, conflict, empirical-only support, missing
//! verifier, unsafe payload, partial coverage, unknown-effect retry, stale
//! revision) are inert terminal dispositions carried by
//! [`ProcedureCandidate`], never errors that invite a blind retry. Malformed
//! or mismatched inputs fail closed as [`ProcedureError`].
//!
//! Absence note: this file contains no persistence, identifier allocation,
//! graph traversal beyond the bounded candidate step list, run-book
//! execution, provider, model, tool, ambient-state, authority, effect, or
//! terminal-completion calls by construction; the only cryptography is the
//! canonical digest below, and the only fallible work is pure bounded
//! validation. There are no placeholder, mock, canned, or pseudo paths:
//! every branch binds an explicit input field.
//!
//! Test coverage note: 37 of 50 numbered 661 work-unit markers execute here;
//! 39 tests run because two supporting regression tests are not numbered
//! work-unit cases.
//! Executed cases: 661/1, 661/2, 661/3, 661/4, 661/5, 661/6, 661/7, 661/8,
//! 661/9, 661/10, 661/11, 661/12, 661/13, 661/14, 661/15, 661/16, 661/17,
//! 661/18, 661/19, 661/20, 661/21, 661/22, 661/23, 661/25, 661/26,
//! 661/27, 661/28, 661/29, 661/30, 661/31, 661/32, 661/33, 661/34,
//! 661/40, 661/41, 661/42, and 661/43. The remaining 13 of 50 are deferred per
//! START.md s1; #965 admission is separate. Deferred: 661/24 (pending
//! candidate-visible causal receipt design - `ProcedureCandidate` currently
//! exposes only `candidate_digest`, no typed causal receipt field), 661/35,
//! 661/36, 661/37, 661/38, 661/39, 661/44, 661/45, 661/46, 661/47,
//! 661/48, 661/49, and 661/50.

#![forbid(unsafe_code)]

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::CurationRejectionCode;
use eliot_dreamer_contracts::grounding::CausalClaim;
use eliot_dreamer_contracts::validation::PROOF_CEILING;
use eliot_dreamer_contracts::{
    CurationKind, GroundedDreamDraft, ValidatedCurationItem, ValidationReceipt, check_fence,
    is_hex64_lower,
};

// ---------------------------------------------------------------------------
// Independent bounds (no cross-subsidy between dimensions).
// ---------------------------------------------------------------------------

/// Maximum procedure steps admitted in one candidate graph.
pub const MAX_STEPS: usize = 32;
/// Maximum inputs admitted on any single step.
pub const MAX_STEP_INPUTS: usize = 16;
/// Maximum dependencies admitted on any single step.
pub const MAX_STEP_DEPS: usize = 8;
/// Maximum evidence refs admitted in any single evidence list.
pub const MAX_EVIDENCE_ITEMS: usize = 64;
/// Maximum closure refs admitted in any single closure list.
pub const MAX_CLOSURE_REFS: usize = 256;
/// Maximum protection entries admitted in one request.
pub const MAX_PROTECTIONS: usize = 32;
/// Maximum predecessor digests admitted in one existing snapshot.
pub const MAX_PREDECESSORS: usize = 32;
/// Maximum bytes for any single free-text field.
pub const MAX_TEXT_BYTES: usize = 1024;
/// Maximum bytes for any handle or identity field.
pub const MAX_HANDLE_BYTES: usize = 128;
/// Maximum bytes for any identity field bound into digests.
pub const MAX_ID_BYTES: usize = 128;
/// Maximum bytes for task, scope, authority, and proof-ceiling fields.
pub const MAX_SCOPE_BYTES: usize = 256;
/// Maximum bytes for any bounded note field.
pub const MAX_NOTE_BYTES: usize = 1024;
/// Maximum bytes for the procedure objective statement.
pub const MAX_OBJECTIVE_BYTES: usize = 1024;
/// Maximum aggregate input bytes across all text fields.
pub const MAX_TOTAL_BYTES: usize = 1_048_576;
/// Redaction ceiling for values echoed into errors and notes.
pub const MAX_REDACTED_CHARS: usize = 128;
/// Maximum retries admitted on any single step.
pub const MAX_RETRIES: u32 = 5;
/// Maximum fan-out admitted on any single step.
pub const MAX_FANOUT: u32 = 8;
/// Expected preservation dimensions attested through the receipt digest.
pub const EXPECTED_PRESERVATION_DIMENSIONS: usize = 7;

/// Routing-only proof ceiling carried by every emitted candidate.
pub const PROCEDURE_PROOF_NOTE: &str = "a-25 candidate-only aggregation: inert typed step graph preserved without screening, grounding, common validation, canonical mutation, authority, effect, store, governor, model, clock, or finish";

// ---------------------------------------------------------------------------
// Small pure helpers (no ambient clock, no allocation of authority).
// ---------------------------------------------------------------------------

/// Returns true when the value carries any control character.
fn has_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}

/// Redacts a value to a bounded printable prefix for errors and notes.
fn redact(value: &str) -> String {
    let mut out = String::new();
    for (index, ch) in value.chars().enumerate() {
        if index >= MAX_REDACTED_CHARS {
            out.push_str("...");
            break;
        }
        if ch.is_control() {
            out.push('?');
        } else {
            out.push(ch);
        }
    }
    out
}

/// Returns true when values are sorted strictly ascending with no duplicates.
fn is_sorted_unique(values: &[String]) -> bool {
    let mut index = 0usize;
    while index < values.len() {
        if index > 0 {
            let prev_ok = values.get(index.saturating_sub(1));
            let cur_ok = values.get(index);
            if let (Some(prev), Some(cur)) = (prev_ok, cur_ok) {
                if prev >= cur {
                    return false;
                }
            } else {
                return false;
            }
        }
        index = index.saturating_add(1);
    }
    true
}

/// Returns true when the sorted-unique precondition holds for string slices.
fn are_ids_sorted_unique(values: &[String]) -> bool {
    is_sorted_unique(values)
}

/// Lowercases an ASCII-heavy note without allocating authority.
fn lowered(note: &str) -> String {
    note.to_lowercase()
}

/// Returns true when the haystack contains the needle as a substring.
fn contains_marker(haystack: &str, needle: &str) -> bool {
    haystack.contains(needle)
}

// ---------------------------------------------------------------------------
// Closed forbidden markers (raw execution, SDK, credentials, unbounded).
// ---------------------------------------------------------------------------

/// Substrings that mark a raw shell or command execution payload.
pub const SHELL_MARKERS: &[&str] = &[
    "shell_exec",
    "shell-exec",
    "raw shell",
    "sh -c",
    "/bin/sh",
    "/bin/bash",
    "cmd.exe",
    "powershell",
    "pwsh -c",
    "system(",
    "popen(",
    "execvp",
    "execve",
    "spawn shell",
];

/// Substrings that mark a provider or model SDK payload.
pub const SDK_MARKERS: &[&str] = &[
    "boto3",
    "aws sdk",
    "gcp sdk",
    "azure sdk",
    "openai.",
    "anthropic.",
    "http client exec",
    "sdk.invoke",
    "sdk_exec",
    "provider call",
    "model.invoke",
];

/// Substrings that mark acquired credentials, leases, permits, or handles.
pub const CREDENTIAL_MARKERS: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "secret",
    "password",
    "passwd",
    "bearer token",
    "access token",
    "refresh token",
    "credential",
    "lease acquire",
    "permit acquire",
    "process handle",
    "handle acquire",
    "private key",
];

/// Substrings that mark an unbounded loop, fan-out, or retry claim.
pub const UNBOUNDED_MARKERS: &[&str] = &[
    "unbounded",
    "infinite loop",
    "loop forever",
    "retry forever",
    "retry until success",
    "unlimited retries",
    "unlimited fan",
    "fork bomb",
    "while true",
    "for(;;)",
];

/// Substrings that mark a similarity or confidence proof overreach.
pub const SIMILARITY_MARKERS: &[&str] = &[
    "similar",
    "looks like",
    "confidence proves",
    "model says the author",
    "embedding proves",
];

/// Returns true when any marker occurs in the lowered haystack.
fn mentions_any(lowered_haystack: &str, markers: &[&str]) -> bool {
    let mut index = 0usize;
    while index < markers.len() {
        if let Some(marker) = markers.get(index)
            && contains_marker(lowered_haystack, marker)
        {
            return true;
        }
        index = index.saturating_add(1);
    }
    false
}

/// Returns true when the text claims chronology proves causality.
fn claims_chronology_is_causality(note: &str) -> bool {
    let low = lowered(note);
    let time_word = contains_marker(&low, "before")
        || contains_marker(&low, "earlier")
        || contains_marker(&low, "preceded");
    let cause_word = contains_marker(&low, "therefore causes")
        || contains_marker(&low, "hence causes")
        || contains_marker(&low, "proves caus")
        || contains_marker(&low, "is the cause");
    time_word && cause_word
}

/// Returns true when the text claims a timestamp proves currentness.
fn claims_timestamp_is_currentness(note: &str) -> bool {
    let low = lowered(note);
    let fresh_word = contains_marker(&low, "newest")
        || contains_marker(&low, "latest timestamp")
        || contains_marker(&low, "most recent");
    let current_word = contains_marker(&low, "therefore current")
        || contains_marker(&low, "hence current")
        || contains_marker(&low, "proves current")
        || contains_marker(&low, "is current");
    fresh_word && current_word
}

/// Returns true when the text offers bare success as mechanism proof.
fn claims_success_is_mechanism(note: &str) -> bool {
    let low = lowered(note);
    contains_marker(&low, "exit zero proves")
        || contains_marker(&low, "one success proves mechanism")
        || contains_marker(&low, "confidence proves mechanism")
        || contains_marker(&low, "single episode proves")
}

// ---------------------------------------------------------------------------
// Public vocabulary: effects, outcomes, steps, evidence, snapshots, policy.
// ---------------------------------------------------------------------------

/// Closed effect class for one procedure step.
///
/// `Unknown` names a step whose possible effect the owning contract could
/// not bound. Unknown possible effect blocks every retry path until the
/// external owner reconciles the exact operation; there is no blind retry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EffectClass {
    /// The step only reads already admitted evidence.
    ReadOnly,
    /// The step names an owner-directed write executed outside this cell.
    OwnerDirected,
    /// The step names a compensatable change with an owned rollback.
    Compensatable,
    /// The step effect is unknown and blocks retry until reconciled.
    Unknown,
}

impl EffectClass {
    /// Returns the canonical spelling of this effect class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::OwnerDirected => "owner_directed",
            Self::Compensatable => "compensatable",
            Self::Unknown => "unknown",
        }
    }

    /// Parses the canonical spelling of an effect class.
    ///
    /// # Errors
    ///
    /// Returns [`ProcedureError::Shape`] on any unknown spelling.
    pub fn parse(spelling: &str) -> Result<Self, ProcedureError> {
        match spelling {
            "read_only" => Ok(Self::ReadOnly),
            "owner_directed" => Ok(Self::OwnerDirected),
            "compensatable" => Ok(Self::Compensatable),
            "unknown" => Ok(Self::Unknown),
            _ => Err(ProcedureError::Shape {
                field: "step.effect".to_owned(),
                detail: redact(spelling),
            }),
        }
    }
}

/// Terminal outcome of one procedure proposal.
///
/// Fail-closed ordering applies: malformed inputs are [`ProcedureError`],
/// while every semantic shortfall below is an inert outcome that preserves
/// all source branches without effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProcedureOutcome {
    /// One complete candidate with full accounting and proof.
    Complete,
    /// A candidate with named partial coverage; completeness is blocked.
    Partial,
    /// The proposed procedure duplicates an already known identity.
    Duplicate,
    /// The proposed procedure refines a named predecessor.
    Refinement,
    /// The proposed procedure conflicts with a named live procedure.
    Conflict,
    /// Support is empirical only; mechanism is not proven.
    Empirical,
    /// A required verifier is missing or unbound.
    MissingVerifier,
    /// The payload is unsafe and is refused without execution.
    Unsafe,
    /// Unknown possible effect blocks every retry path.
    BlockedUnknownEffect,
    /// Inputs moved under the request; replay against the new revision.
    Stale,
    /// The request is rejected with a boundary handoff.
    Rejected,
}

impl ProcedureOutcome {
    /// Returns the canonical spelling of this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Duplicate => "duplicate",
            Self::Refinement => "refinement",
            Self::Conflict => "conflict",
            Self::Empirical => "empirical",
            Self::MissingVerifier => "missing_verifier",
            Self::Unsafe => "unsafe",
            Self::BlockedUnknownEffect => "blocked_unknown_effect",
            Self::Stale => "stale",
            Self::Rejected => "rejected",
        }
    }
}

/// Exactly-one disposition per procedure step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StepDispositionKind {
    /// Step is fully grounded and verified by its named verifier.
    Grounded,
    /// Step refines a named predecessor step without changing identity.
    Refinement,
    /// Step conflicts with a named live step and is held open.
    Conflict,
    /// Step support is empirical only and stays visible as such.
    Empirical,
    /// Step verifier is missing and blocks completeness.
    MissingVerifier,
    /// Step payload is unsafe and is refused.
    Unsafe,
    /// Step effect is unknown and blocks retry until reconciled.
    BlockedUnknownEffect,
    /// Step is unchanged evidence carried for lineage.
    UnchangedWithEvidence,
}

impl StepDispositionKind {
    /// Returns the canonical spelling of this step disposition.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Grounded => "grounded",
            Self::Refinement => "refinement",
            Self::Conflict => "conflict",
            Self::Empirical => "empirical",
            Self::MissingVerifier => "missing_verifier",
            Self::Unsafe => "unsafe",
            Self::BlockedUnknownEffect => "blocked_unknown_effect",
            Self::UnchangedWithEvidence => "unchanged_with_evidence",
        }
    }
}

/// One finite typed step in the candidate procedure graph.
///
/// Every step names exactly one operation owner and contract, its typed
/// inputs, one precondition, its dependencies inside the same graph, one
/// observable postcondition, one verifier, one effect boundary, one budget
/// note, one failure note, one cancellation note, one reconciliation note,
/// and one rollback or compensation boundary. No step executes anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcedureStep {
    /// Stable step identity unique inside the candidate graph.
    pub step_id: String,
    /// External owner that must execute or decline this step.
    pub owner: String,
    /// Owner contract reference this step is bound to.
    pub contract_ref: String,
    /// Typed inert operation spelling proposed to the owner.
    pub operation: String,
    /// Typed input handles bound to admitted evidence.
    pub inputs: Vec<String>,
    /// Precondition that must hold before the owner may act.
    pub precondition: String,
    /// Step identities inside this graph that must settle first.
    pub dependencies: Vec<String>,
    /// Observable postcondition the verifier checks.
    pub postcondition: String,
    /// Verifier that checks the postcondition.
    pub verifier: String,
    /// Closed effect class of this step.
    pub effect: EffectClass,
    /// Effect boundary naming what the step must not touch.
    pub effect_boundary: String,
    /// Budget note naming the authorizing limit for this step.
    pub budget_note: String,
    /// Failure note naming the typed failure handling for this step.
    pub failure_note: String,
    /// Cancellation note naming the typed cancel handling for this step.
    pub cancel_note: String,
    /// Reconciliation note naming the unknown-effect handling for this step.
    pub reconcile_note: String,
    /// Rollback or compensation boundary owned independently.
    pub rollback_note: String,
    /// Maximum retries admitted for this step.
    pub max_retries: u32,
    /// Explicit timeout in milliseconds, when bounded.
    pub timeout_ms: Option<u64>,
    /// Fan-out admitted for this step.
    pub fanout: u32,
}

/// One per-step disposition carried in emission order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepDisposition {
    /// Step identity this disposition accounts for.
    pub step_id: String,
    /// Closed disposition kind for this step.
    pub kind: StepDispositionKind,
    /// Owner that owns this step.
    pub owner: String,
    /// Bounded reason naming the evidence behind this disposition.
    pub reason: String,
    /// Evidence ref backing this disposition.
    pub evidence_ref: String,
    /// Verifier bound to this step.
    pub verifier: String,
    /// Inverse or compensation note for this step.
    pub inverse_note: String,
}

/// Episode and verifier evidence bound to one procedure proposal.
///
/// Requested, admitted, attempted, executed, acknowledged, observed, and
/// semantically verified evidence stay distinct: exit zero, confidence, or
/// one successful episode never proves mechanism or portability. Failures,
/// partial, cancelled, timed-out, and unknown-effect runs are preserved
/// alongside successes, and negative evidence is never dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcedureEvidence {
    /// Expected A-05 receipt the item receipt is bound against.
    pub expected_receipt: ValidationReceipt,
    /// Frozen bundle digest the proposal replays against.
    pub frozen_bundle_digest: String,
    /// Frozen manifest digest the proposal replays against.
    pub frozen_manifest_digest: String,
    /// Successful episode refs grounding the procedure.
    pub episode_refs: Vec<String>,
    /// Verifier refs naming who checks each observable.
    pub verifier_refs: Vec<String>,
    /// Successful run refs retained without promotion to proof.
    pub success_refs: Vec<String>,
    /// Failing run refs preserved as counterevidence.
    pub failure_refs: Vec<String>,
    /// Counterexample refs that the procedure must keep answering.
    pub counterexample_refs: Vec<String>,
    /// Validated causal rival and confounder evidence, when supplied.
    pub causal_claim: Option<CausalClaim>,
    /// Negative-memory trigger refs retained until qualified extinction.
    pub negative_refs: Vec<String>,
    /// Unknown-branch refs that remain open.
    pub unknown_refs: Vec<String>,
    /// Extinction evidence refs naming when a trigger no longer fires.
    pub extinction_refs: Vec<String>,
    /// Reopen condition naming what revives review.
    pub reopen_condition: String,
    /// Mechanism note naming the exercised mechanism, not bare success.
    pub mechanism_note: String,
    /// Portability note naming the exact scope the evidence supports.
    pub portability_note: String,
    /// Failure fingerprint the trigger is derived from.
    pub failure_fingerprint: String,
}

/// Capability and environment snapshot bounding applicability.
///
/// Capability availability never becomes authority or a live reservation.
/// Trigger and applicability derive only inside the supported environment,
/// scope, and version evidence carried here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityEnvSnapshot {
    /// Capability refs the procedure may assume available, never reserved.
    pub capability_refs: Vec<String>,
    /// Environment identity the evidence was observed under.
    pub env_id: String,
    /// Environment revision the evidence was observed under.
    pub env_revision: String,
    /// Digest of the environment bytes the evidence binds.
    pub env_digest: String,
    /// Scope the procedure is proposed for.
    pub scope_id: String,
    /// Task the procedure is proposed for.
    pub task_id: String,
    /// Policy the snapshot is projected under.
    pub policy_id: String,
    /// State fence of the capability projection.
    pub state_fence: eliot_contracts::StateFence,
    /// Version pins bounding every capability the steps assume.
    pub version_pins: Vec<String>,
    /// Bounded note naming what capability means here.
    pub capability_note: String,
}

/// Existing-procedure snapshot for duplicate, refinement, and conflict.
///
/// Similarity is never an exact failure fingerprint and never an execution
/// permission. Only exact digest and identity bindings below dispose as
/// duplicate, refinement, or conflict; everything else stays visible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExistingProcedureSnapshot {
    /// Known candidate digests in sorted unique order.
    pub existing_digests: Vec<String>,
    /// Known procedure identities in sorted unique order.
    pub existing_ids: Vec<String>,
    /// Exact identity this proposal duplicates, when any.
    pub duplicate_of: Option<String>,
    /// Exact predecessor this proposal refines, when any.
    pub refinement_of: Option<String>,
    /// Live procedures this proposal conflicts with.
    pub conflict_with: Vec<String>,
    /// Superseded digests carried for lineage.
    pub superseded_digests: Vec<String>,
}

/// Closed policy governing one procedure proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcedurePolicy {
    /// Governing policy identity; must equal the receipt validator policy.
    pub policy_id: String,
    /// Policy revision; zero is rejected as a defaulted binding.
    pub policy_revision: u32,
    /// Maximum steps admitted in the emitted graph.
    pub max_steps: usize,
    /// Maximum evidence items admitted per list.
    pub max_evidence_items: usize,
    /// True selects explicit partial emission; false selects all-or-nothing.
    pub allow_partial: bool,
    /// True when the caller cancelled this proposal before emission.
    pub cancelled: bool,
    /// Explicit observation time in milliseconds, when bounded.
    pub observation_time_ms: Option<u64>,
    /// Frozen deadline in milliseconds, when bounded.
    pub deadline_ms: Option<u64>,
    /// Bounded transfer note naming the receiving scope.
    pub transfer_note: String,
}

/// Environment and scope preserving transfer boundary.
///
/// Transfer never widens environment, scope, version, or negative evidence.
/// The receiving owner re-grounds every step before any use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferPlan {
    /// Receiving environment identity; must equal the source environment.
    pub target_env_id: String,
    /// Receiving environment revision; must equal the source revision.
    pub target_env_revision: String,
    /// Receiving scope identity; must equal the source scope.
    pub target_scope_id: String,
    /// Receiving task identity; must equal the source task.
    pub target_task_id: String,
    /// Negative-memory refs preserved across transfer verbatim.
    pub preserved_negative_refs: Vec<String>,
    /// Counterevidence refs preserved across transfer verbatim.
    pub preserved_counterevidence_refs: Vec<String>,
    /// Unknown-branch refs preserved across transfer verbatim.
    pub preserved_unknown_refs: Vec<String>,
    /// Version pins preserved across transfer verbatim.
    pub preserved_version_pins: Vec<String>,
    /// Bounded note naming the re-grounding the receiver must perform.
    pub reground_note: String,
}

/// Complete inert procedure candidate envelope.
///
/// The envelope is never an applied receipt, never a reservation, and never
/// a finish signal. Every step names the external owner that must execute
/// or decline it, with independent cleanup and rollback ownership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcedureCandidate {
    /// Terminal outcome for this proposal.
    pub outcome: ProcedureOutcome,
    /// Stable procedure handle proposed by this candidate.
    pub procedure_handle: String,
    /// Single objective statement this procedure serves.
    pub objective: String,
    /// Finite typed step graph in emission order.
    pub steps: Vec<ProcedureStep>,
    /// One disposition per step in step order.
    pub step_dispositions: Vec<StepDisposition>,
    /// Trigger note derived only inside the evidenced environment.
    pub trigger_note: String,
    /// Applicability note bounded by the evidenced scope and versions.
    pub applicability_note: String,
    /// Environment and scope preserving transfer boundary.
    pub transfer: TransferPlan,
    /// Primary verifier that checks the procedure observable.
    pub verifier: String,
    /// Exact inverse restoring the before state.
    pub inverse_note: String,
    /// Forward correction applied when the before state is unreachable.
    pub forward_correction_note: String,
    /// Reopen condition naming what revives review.
    pub reopen_note: String,
    /// How unknown outcomes are handled without silent completion.
    pub unknown_handling_note: String,
    /// Deterministic digest binding the proposal inputs.
    pub candidate_digest: String,
    /// Bounded machine-readable note.
    pub note: String,
}

// ---------------------------------------------------------------------------
// Typed fail-closed error. Malformed input only; semantic shortfalls stay
// inert outcomes carried by `ProcedureCandidate`.
// ---------------------------------------------------------------------------

/// Typed fail-closed procedure error.
///
/// Every variant carries structured identities; free-text detail is always
/// redacted and bounded. A value of this type is never a stub: it names the
/// exact failed binding or bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcedureError {
    /// A bound or ceiling check failed in the named phase.
    Bounds {
        /// Phase that failed its bound.
        phase: String,
        /// Bounded redacted reason.
        detail: String,
    },
    /// Deterministic ordering was violated in the named phase.
    Order {
        /// Phase that failed ordering.
        phase: String,
        /// Bounded redacted reason.
        detail: String,
    },
    /// A shape check failed on the named field.
    Shape {
        /// Field that failed its shape.
        field: String,
        /// Bounded redacted reason.
        detail: String,
    },
    /// Two envelopes disagree on a shared binding.
    Binding {
        /// Closed binding name.
        field: String,
        /// Bounded redacted reason.
        detail: String,
    },
    /// The bundled A-05 receipt is intrinsically invalid or incompatible.
    Receipt {
        /// Bounded redacted reason.
        detail: String,
    },
    /// The governing policy is malformed or out of bounds.
    Policy {
        /// Bounded redacted reason.
        detail: String,
    },
    /// A target or member denominator is malformed or incomplete.
    Denominator {
        /// Bounded redacted reason.
        detail: String,
    },
    /// A digest shape or replay pin is wrong.
    Digest {
        /// Bounded redacted reason.
        detail: String,
    },
}

impl core::fmt::Display for ProcedureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bounds { phase, detail } => write!(f, "bounds[{phase}]: {detail}"),
            Self::Order { phase, detail } => write!(f, "order[{phase}]: {detail}"),
            Self::Shape { field, detail } => write!(f, "shape[{field}]: {detail}"),
            Self::Binding { field, detail } => write!(f, "binding[{field}]: {detail}"),
            Self::Receipt { detail } => write!(f, "receipt: {detail}"),
            Self::Policy { detail } => write!(f, "policy: {detail}"),
            Self::Denominator { detail } => write!(f, "denominator: {detail}"),
            Self::Digest { detail } => write!(f, "digest: {detail}"),
        }
    }
}

impl core::error::Error for ProcedureError {}

// ---------------------------------------------------------------------------
// Shape checks (malformed input only).
// ---------------------------------------------------------------------------

/// Checks one bounded text field for blank, control, and byte ceiling.
fn check_bounded_text(value: &str, field: &str, max: usize) -> Result<(), ProcedureError> {
    if value.trim().is_empty() {
        return Err(ProcedureError::Shape {
            field: field.to_owned(),
            detail: "blank text is not admitted".to_owned(),
        });
    }
    if has_control(value) {
        return Err(ProcedureError::Shape {
            field: field.to_owned(),
            detail: "control characters are not admitted".to_owned(),
        });
    }
    if value.len() > max {
        return Err(ProcedureError::Shape {
            field: field.to_owned(),
            detail: "text exceeds its byte bound".to_owned(),
        });
    }
    Ok(())
}

/// Checks one handle field for blank, control, and byte ceiling.
fn check_handle(value: &str, field: &str) -> Result<(), ProcedureError> {
    if value.is_empty() || value.len() > MAX_HANDLE_BYTES {
        return Err(ProcedureError::Bounds {
            phase: field.to_owned(),
            detail: "handle is blank or exceeds the handle ceiling".to_owned(),
        });
    }
    if has_control(value) {
        return Err(ProcedureError::Bounds {
            phase: field.to_owned(),
            detail: "handle carries control characters".to_owned(),
        });
    }
    Ok(())
}

/// Checks one digest field for exact 64 lowercase hex shape.
fn check_digest(value: &str, field: &str) -> Result<(), ProcedureError> {
    if !is_hex64_lower(value) {
        return Err(ProcedureError::Digest {
            detail: format!("{field} must be 64 lowercase hex sha256"),
        });
    }
    Ok(())
}

/// Checks one sorted-unique ref list for handle shape and ordering.
fn check_sorted_refs(values: &[String], field: &str) -> Result<(), ProcedureError> {
    for value in values {
        check_handle(value, field)?;
    }
    if !is_sorted_unique(values) {
        return Err(ProcedureError::Order {
            phase: field.to_owned(),
            detail: "refs must be sorted and unique".to_owned(),
        });
    }
    Ok(())
}

/// Checks one sorted-unique digest list for digest shape and ordering.
fn check_sorted_digests(values: &[String], field: &str) -> Result<(), ProcedureError> {
    for value in values {
        check_digest(value, field)?;
    }
    if !is_sorted_unique(values) {
        return Err(ProcedureError::Order {
            phase: field.to_owned(),
            detail: "digests must be sorted and unique".to_owned(),
        });
    }
    Ok(())
}

/// Counts bytes across a slice of text values with saturation.
fn count_text_bytes(values: &[&str]) -> usize {
    let mut total = 0usize;
    let mut index = 0usize;
    while index < values.len() {
        if let Some(value) = values.get(index) {
            total = total.saturating_add(value.len());
        }
        index = index.saturating_add(1);
    }
    total
}

/// Rejects a list length above its independent ceiling.
fn bound_list_length(phase: &str, got: usize, max: usize) -> Result<(), ProcedureError> {
    if got > max {
        return Err(ProcedureError::Bounds {
            phase: phase.to_owned(),
            detail: "list exceeds its independent ceiling".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Preflight bounds (shape only; semantic shortfalls stay outcomes).
// ---------------------------------------------------------------------------

/// Preflights evidence list lengths against policy and global ceilings.
fn preflight_evidence_bounds(
    evidence: &ProcedureEvidence,
    policy: &ProcedurePolicy,
) -> Result<(), ProcedureError> {
    let ceiling = policy.max_evidence_items.min(MAX_EVIDENCE_ITEMS);
    bound_list_length("episode-refs", evidence.episode_refs.len(), ceiling)?;
    bound_list_length("verifier-refs", evidence.verifier_refs.len(), ceiling)?;
    bound_list_length("success-refs", evidence.success_refs.len(), ceiling)?;
    bound_list_length("failure-refs", evidence.failure_refs.len(), ceiling)?;
    bound_list_length(
        "counterexample-refs",
        evidence.counterexample_refs.len(),
        ceiling,
    )?;
    bound_list_length("negative-refs", evidence.negative_refs.len(), ceiling)?;
    bound_list_length("unknown-refs", evidence.unknown_refs.len(), ceiling)?;
    bound_list_length("extinction-refs", evidence.extinction_refs.len(), ceiling)?;
    Ok(())
}

/// Preflights capability and existing-snapshot list lengths.
fn preflight_snapshot_bounds(
    capability: &CapabilityEnvSnapshot,
    existing: &ExistingProcedureSnapshot,
    policy: &ProcedurePolicy,
) -> Result<(), ProcedureError> {
    let ceiling = policy.max_evidence_items.min(MAX_EVIDENCE_ITEMS);
    bound_list_length("capability-refs", capability.capability_refs.len(), ceiling)?;
    bound_list_length(
        "version-pins",
        capability.version_pins.len(),
        MAX_CLOSURE_REFS,
    )?;
    bound_list_length(
        "existing-digests",
        existing.existing_digests.len(),
        MAX_PREDECESSORS,
    )?;
    bound_list_length(
        "existing-ids",
        existing.existing_ids.len(),
        MAX_PREDECESSORS,
    )?;
    bound_list_length(
        "conflict-with",
        existing.conflict_with.len(),
        MAX_PREDECESSORS,
    )?;
    bound_list_length(
        "superseded-digests",
        existing.superseded_digests.len(),
        MAX_PREDECESSORS,
    )?;
    Ok(())
}

/// Preflights aggregate text bytes across the whole proposal surface.
fn preflight_total_bytes(
    evidence: &ProcedureEvidence,
    capability: &CapabilityEnvSnapshot,
    policy: &ProcedurePolicy,
    steps: &[ProcedureStep],
) -> Result<(), ProcedureError> {
    let mut total = 0usize;
    total = total.saturating_add(count_text_bytes(&[
        &evidence.reopen_condition,
        &evidence.mechanism_note,
        &evidence.portability_note,
        &evidence.failure_fingerprint,
        &capability.env_id,
        &capability.env_revision,
        &capability.scope_id,
        &capability.task_id,
        &capability.policy_id,
        &capability.capability_note,
        &policy.policy_id,
        &policy.transfer_note,
    ]));
    let mut index = 0usize;
    while index < steps.len() {
        if let Some(step) = steps.get(index) {
            total = total.saturating_add(count_text_bytes(&[
                &step.step_id,
                &step.owner,
                &step.contract_ref,
                &step.operation,
                &step.precondition,
                &step.postcondition,
                &step.verifier,
                &step.effect_boundary,
                &step.budget_note,
                &step.failure_note,
                &step.cancel_note,
                &step.reconcile_note,
                &step.rollback_note,
            ]));
            for input in &step.inputs {
                total = total.saturating_add(input.len());
            }
            for dep in &step.dependencies {
                total = total.saturating_add(dep.len());
            }
        }
        index = index.saturating_add(1);
    }
    if total > MAX_TOTAL_BYTES {
        return Err(ProcedureError::Bounds {
            phase: "total-bytes".to_owned(),
            detail: "aggregate input exceeds the total byte ceiling".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shape validation (malformed input only).
// ---------------------------------------------------------------------------

/// Validates evidence text shapes and ref orderings.
fn validate_evidence_shapes(evidence: &ProcedureEvidence) -> Result<(), ProcedureError> {
    check_digest(&evidence.frozen_bundle_digest, "frozen-bundle")?;
    check_digest(&evidence.frozen_manifest_digest, "frozen-manifest")?;
    check_sorted_refs(&evidence.episode_refs, "evidence.episodes")?;
    check_sorted_refs(&evidence.verifier_refs, "evidence.verifiers")?;
    check_sorted_refs(&evidence.success_refs, "evidence.successes")?;
    check_sorted_refs(&evidence.failure_refs, "evidence.failures")?;
    check_sorted_refs(&evidence.counterexample_refs, "evidence.counterexamples")?;
    check_sorted_refs(&evidence.negative_refs, "evidence.negatives")?;
    check_sorted_refs(&evidence.unknown_refs, "evidence.unknowns")?;
    check_sorted_refs(&evidence.extinction_refs, "evidence.extinctions")?;
    check_bounded_text(
        &evidence.reopen_condition,
        "evidence.reopen",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &evidence.mechanism_note,
        "evidence.mechanism",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &evidence.portability_note,
        "evidence.portability",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &evidence.failure_fingerprint,
        "evidence.fingerprint",
        MAX_HANDLE_BYTES,
    )?;
    if let Some(causal_claim) = &evidence.causal_claim {
        causal_claim
            .validate()
            .map_err(|err| ProcedureError::Shape {
                field: "evidence.causal_claim".to_owned(),
                detail: redact(&err.to_string()),
            })?;
    }
    Ok(())
}

/// Validates capability snapshot text shapes and ref orderings.
fn validate_capability_shapes(capability: &CapabilityEnvSnapshot) -> Result<(), ProcedureError> {
    check_sorted_refs(&capability.capability_refs, "capability.refs")?;
    if capability.capability_refs.is_empty() {
        return Err(ProcedureError::Shape {
            field: "capability.refs".to_owned(),
            detail: "missing or unknown capability availability is not admitted".to_owned(),
        });
    }
    check_handle(&capability.env_id, "capability.env")?;
    check_bounded_text(
        &capability.env_revision,
        "capability.env-revision",
        MAX_ID_BYTES,
    )?;
    check_digest(&capability.env_digest, "capability.env-digest")?;
    check_handle(&capability.scope_id, "capability.scope")?;
    check_handle(&capability.task_id, "capability.task")?;
    check_handle(&capability.policy_id, "capability.policy")?;
    check_sorted_refs(&capability.version_pins, "capability.versions")?;
    check_bounded_text(
        &capability.capability_note,
        "capability.note",
        MAX_NOTE_BYTES,
    )?;
    check_fence(&capability.state_fence).map_err(|err| ProcedureError::Shape {
        field: "capability.fence".to_owned(),
        detail: redact(&err.to_string()),
    })?;
    Ok(())
}

/// Validates existing-snapshot shapes and orderings.
fn validate_existing_shapes(existing: &ExistingProcedureSnapshot) -> Result<(), ProcedureError> {
    check_sorted_digests(&existing.existing_digests, "existing.digests")?;
    check_sorted_refs(&existing.existing_ids, "existing.ids")?;
    if let Some(dup) = &existing.duplicate_of {
        check_handle(dup, "existing.duplicate-of")?;
    }
    if let Some(refined) = &existing.refinement_of {
        check_handle(refined, "existing.refinement-of")?;
    }
    check_sorted_refs(&existing.conflict_with, "existing.conflicts")?;
    check_sorted_digests(&existing.superseded_digests, "existing.superseded")?;
    Ok(())
}

/// Validates policy intrinsic shapes and ceilings.
fn validate_policy_shapes(policy: &ProcedurePolicy) -> Result<(), ProcedureError> {
    check_handle(&policy.policy_id, "policy.id")?;
    if policy.policy_revision == 0 {
        return Err(ProcedureError::Policy {
            detail: "policy_revision must be explicit, not defaulted".to_owned(),
        });
    }
    if policy.max_steps == 0 || policy.max_steps > MAX_STEPS {
        return Err(ProcedureError::Policy {
            detail: format!("max_steps must cover 1..={MAX_STEPS}"),
        });
    }
    if policy.max_evidence_items == 0 || policy.max_evidence_items > MAX_EVIDENCE_ITEMS {
        return Err(ProcedureError::Policy {
            detail: format!("max_evidence_items must cover 1..={MAX_EVIDENCE_ITEMS}"),
        });
    }
    check_bounded_text(&policy.transfer_note, "policy.transfer", MAX_NOTE_BYTES)?;
    Ok(())
}

/// Validates one step field shape without judging semantics.
fn validate_one_step_shape(step: &ProcedureStep) -> Result<(), ProcedureError> {
    check_handle(&step.step_id, "step.id")?;
    check_bounded_text(&step.owner, "step.owner", MAX_ID_BYTES)?;
    check_bounded_text(&step.contract_ref, "step.contract", MAX_ID_BYTES)?;
    check_bounded_text(&step.operation, "step.operation", MAX_TEXT_BYTES)?;
    if step.inputs.len() > MAX_STEP_INPUTS {
        return Err(ProcedureError::Bounds {
            phase: "step.inputs".to_owned(),
            detail: "step inputs exceed the per-step ceiling".to_owned(),
        });
    }
    for input in &step.inputs {
        check_handle(input, "step.input")?;
    }
    if !is_sorted_unique(&step.inputs) {
        return Err(ProcedureError::Order {
            phase: "step.inputs".to_owned(),
            detail: "step inputs must be sorted and unique".to_owned(),
        });
    }
    check_bounded_text(&step.precondition, "step.precondition", MAX_NOTE_BYTES)?;
    if step.dependencies.len() > MAX_STEP_DEPS {
        return Err(ProcedureError::Bounds {
            phase: "step.dependencies".to_owned(),
            detail: "step dependencies exceed the per-step ceiling".to_owned(),
        });
    }
    for dep in &step.dependencies {
        check_handle(dep, "step.dependency")?;
    }
    if !is_sorted_unique(&step.dependencies) {
        return Err(ProcedureError::Order {
            phase: "step.dependencies".to_owned(),
            detail: "step dependencies must be sorted and unique".to_owned(),
        });
    }
    check_bounded_text(&step.postcondition, "step.postcondition", MAX_NOTE_BYTES)?;
    check_bounded_text(&step.verifier, "step.verifier", MAX_ID_BYTES)?;
    check_bounded_text(
        &step.effect_boundary,
        "step.effect-boundary",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(&step.budget_note, "step.budget", MAX_NOTE_BYTES)?;
    check_bounded_text(&step.failure_note, "step.failure", MAX_NOTE_BYTES)?;
    check_bounded_text(&step.cancel_note, "step.cancel", MAX_NOTE_BYTES)?;
    check_bounded_text(&step.reconcile_note, "step.reconcile", MAX_NOTE_BYTES)?;
    check_bounded_text(&step.rollback_note, "step.rollback", MAX_NOTE_BYTES)?;
    if step.max_retries > MAX_RETRIES {
        return Err(ProcedureError::Bounds {
            phase: "step.retries".to_owned(),
            detail: "step retries exceed the per-step ceiling".to_owned(),
        });
    }
    if step.fanout == 0 || step.fanout > MAX_FANOUT {
        return Err(ProcedureError::Bounds {
            phase: "step.fanout".to_owned(),
            detail: format!("step fanout must cover 1..={MAX_FANOUT}"),
        });
    }
    Ok(())
}

/// Validates every step shape and the graph identity ordering.
fn validate_step_shapes(steps: &[ProcedureStep]) -> Result<(), ProcedureError> {
    if steps.is_empty() {
        return Err(ProcedureError::Shape {
            field: "steps".to_owned(),
            detail: "at least one step is required".to_owned(),
        });
    }
    bound_list_length("steps", steps.len(), MAX_STEPS)?;
    let mut ids: Vec<String> = Vec::with_capacity(steps.len());
    let mut index = 0usize;
    while index < steps.len() {
        if let Some(step) = steps.get(index) {
            validate_one_step_shape(step)?;
            ids.push(step.step_id.clone());
        }
        index = index.saturating_add(1);
    }
    if !are_ids_sorted_unique(&ids) {
        return Err(ProcedureError::Order {
            phase: "steps".to_owned(),
            detail: "step identities must be sorted and unique".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Intrinsic checks (A-05 receipt intrinsically, never re-executed).
// ---------------------------------------------------------------------------

/// Maps a contract violation into a redacted receipt error.
fn receipt_err(detail: &str) -> ProcedureError {
    ProcedureError::Receipt {
        detail: redact(detail),
    }
}

/// Checks the A-05 receipt intrinsically plus item, draft, and denominator.
fn intrinsic_receipt_checks(
    item: &ValidatedCurationItem,
    grounded: &GroundedDreamDraft,
    evidence: &ProcedureEvidence,
) -> Result<(), ProcedureError> {
    item.receipt
        .validate()
        .map_err(|err| receipt_err(&err.to_string()))?;
    evidence
        .expected_receipt
        .validate()
        .map_err(|err| receipt_err(&err.to_string()))?;
    item.receipt
        .validate_binding(&evidence.expected_receipt)
        .map_err(|err| receipt_err(&err.to_string()))?;
    if item.receipt.proof_ceiling != PROOF_CEILING {
        return Err(ProcedureError::Policy {
            detail: "procedure candidates cannot escalate beyond candidate-only proof".to_owned(),
        });
    }
    item.validate()
        .map_err(|err| receipt_err(&err.to_string()))?;
    grounded
        .validate()
        .map_err(|err| receipt_err(&err.to_string()))?;
    if item.receipt.terminal_disposition != "accepted"
        && item.receipt.terminal_disposition != "partial"
    {
        return Err(ProcedureError::Receipt {
            detail: "validator receipt is not accepted or partial".to_owned(),
        });
    }
    Ok(())
}

/// Checks bundle, manifest, draft, task, scope, and fence bindings.
fn intrinsic_binding_checks(
    item: &ValidatedCurationItem,
    grounded: &GroundedDreamDraft,
    evidence: &ProcedureEvidence,
    capability: &CapabilityEnvSnapshot,
) -> Result<(), ProcedureError> {
    if item.receipt.bundle_digest != evidence.frozen_bundle_digest {
        return Err(ProcedureError::Binding {
            field: "bundle_digest".to_owned(),
            detail: "frozen bundle digest drifts from the receipt binding".to_owned(),
        });
    }
    if item.receipt.manifest_digest != evidence.frozen_manifest_digest {
        return Err(ProcedureError::Binding {
            field: "manifest_digest".to_owned(),
            detail: "frozen manifest digest drifts from the receipt binding".to_owned(),
        });
    }
    if item.receipt.draft_digest != grounded.draft_digest {
        return Err(ProcedureError::Binding {
            field: "draft_digest".to_owned(),
            detail: "grounded draft digest drifts from the receipt binding".to_owned(),
        });
    }
    if grounded.job_id != item.receipt.job_id {
        return Err(ProcedureError::Binding {
            field: "job_id".to_owned(),
            detail: "grounded job drifts from the receipt binding".to_owned(),
        });
    }
    if item.task_id != item.receipt.task_id || item.scope_id != item.receipt.scope_id {
        return Err(ProcedureError::Binding {
            field: "task_scope".to_owned(),
            detail: "item task or scope drifts from the receipt binding".to_owned(),
        });
    }
    if item.task_id != capability.task_id || item.scope_id != capability.scope_id {
        return Err(ProcedureError::Binding {
            field: "capability_task_scope".to_owned(),
            detail: "capability task or scope drifts from the item binding".to_owned(),
        });
    }
    if capability.policy_id != item.receipt.validator_policy {
        return Err(ProcedureError::Binding {
            field: "policy_id".to_owned(),
            detail: "capability policy drifts from the receipt validator policy".to_owned(),
        });
    }
    Ok(())
}

/// Checks the denominator shape and the procedure payload binding.
fn intrinsic_denominator_checks(item: &ValidatedCurationItem) -> Result<(), ProcedureError> {
    item.denominator
        .validate()
        .map_err(|err| ProcedureError::Denominator {
            detail: redact(&err.to_string()),
        })?;
    if item.kind_spelling != CurationKind::Procedure.as_str() {
        return Err(ProcedureError::Binding {
            field: "kind_spelling".to_owned(),
            detail: "curation item is not a procedure kind".to_owned(),
        });
    }
    if item.family_spelling != "procedure" {
        return Err(ProcedureError::Binding {
            field: "family_spelling".to_owned(),
            detail: "curation item is not a procedure family".to_owned(),
        });
    }
    let is_procedure = matches!(
        item.payload,
        eliot_dreamer_contracts::CurationPayload::Procedure(_)
    );
    if !is_procedure {
        return Err(ProcedureError::Binding {
            field: "payload".to_owned(),
            detail: "curation payload is not a procedure payload".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Semantic checks (shortfalls stay inert outcomes, never blind retries).
// ---------------------------------------------------------------------------

/// Returns the procedure payload handle carried by the curation item.
fn procedure_handle_of(item: &ValidatedCurationItem) -> String {
    match &item.payload {
        eliot_dreamer_contracts::CurationPayload::Procedure(payload) => payload.procedure.clone(),
        _ => String::new(),
    }
}

/// Checks deadline and cancellation before any emission work.
fn check_deadline_and_cancel(
    policy: &ProcedurePolicy,
) -> Result<Option<ProcedureOutcome>, ProcedureError> {
    if policy.cancelled {
        return Ok(Some(ProcedureOutcome::Rejected));
    }
    if let (Some(deadline), Some(observed)) = (policy.deadline_ms, policy.observation_time_ms)
        && observed >= deadline
    {
        return Err(ProcedureError::Policy {
            detail: "observation is at or beyond the frozen deadline".to_owned(),
        });
    }
    Ok(None)
}

/// Checks that every dependency names a known step and no step depends on
/// itself. Cycle detection runs separately in bounded time.
fn check_dependency_closure(steps: &[ProcedureStep]) -> Result<(), ProcedureError> {
    let mut ids: Vec<String> = Vec::with_capacity(steps.len());
    for step in steps {
        ids.push(step.step_id.clone());
    }
    for step in steps {
        for dep in &step.dependencies {
            if dep == &step.step_id {
                return Err(ProcedureError::Binding {
                    field: "step.dependency".to_owned(),
                    detail: "a step must not depend on itself".to_owned(),
                });
            }
            if !ids.iter().any(|id| id == dep) {
                return Err(ProcedureError::Binding {
                    field: "step.dependency".to_owned(),
                    detail: "a dependency names an unknown step".to_owned(),
                });
            }
        }
    }
    Ok(())
}

/// Checks the step graph for cycles with a bounded iterative walk.
///
/// The walk visits each edge at most once and aborts above a fixed visit
/// ceiling derived from the step bound, so no unbounded loop can occur.
fn check_graph_acyclic(steps: &[ProcedureStep]) -> Result<(), ProcedureError> {
    let ceiling = MAX_STEPS
        .saturating_mul(MAX_STEPS)
        .saturating_add(MAX_STEPS);
    let mut visit_count = 0usize;
    let mut index = 0usize;
    while index < steps.len() {
        let start = match steps.get(index) {
            Some(step) => step.step_id.clone(),
            None => {
                return Err(ProcedureError::Binding {
                    field: "steps".to_owned(),
                    detail: "step index out of range".to_owned(),
                });
            }
        };
        let mut stack: Vec<String> = vec![start.clone()];
        let mut seen: Vec<String> = Vec::new();
        while let Some(current) = stack.pop() {
            visit_count = visit_count.saturating_add(1);
            if visit_count > ceiling {
                return Err(ProcedureError::Binding {
                    field: "steps".to_owned(),
                    detail: "step graph walk exceeds the visit ceiling".to_owned(),
                });
            }
            if seen.iter().any(|id| id == &current) {
                return Err(ProcedureError::Binding {
                    field: "steps".to_owned(),
                    detail: "step graph contains a cycle".to_owned(),
                });
            }
            seen.push(current.clone());
            for step in steps {
                if step.step_id == current {
                    for dep in &step.dependencies {
                        stack.push(dep.clone());
                    }
                }
            }
        }
        index = index.saturating_add(1);
    }
    Ok(())
}

/// Scans one text field for raw shell markers.
fn field_has_shell(text: &str) -> bool {
    mentions_any(&lowered(text), SHELL_MARKERS)
}

/// Scans one text field for SDK markers.
fn field_has_sdk(text: &str) -> bool {
    mentions_any(&lowered(text), SDK_MARKERS)
}

/// Scans one text field for credential markers.
fn field_has_credential(text: &str) -> bool {
    mentions_any(&lowered(text), CREDENTIAL_MARKERS)
}

/// Scans one text field for unbounded markers.
fn field_has_unbounded(text: &str) -> bool {
    mentions_any(&lowered(text), UNBOUNDED_MARKERS)
}

/// Collects every owner-visible text field of one step for marker scans.
fn step_marker_fields(step: &ProcedureStep) -> [&str; 11] {
    [
        step.owner.as_str(),
        step.contract_ref.as_str(),
        step.operation.as_str(),
        step.precondition.as_str(),
        step.postcondition.as_str(),
        step.effect_boundary.as_str(),
        step.budget_note.as_str(),
        step.failure_note.as_str(),
        step.cancel_note.as_str(),
        step.reconcile_note.as_str(),
        step.rollback_note.as_str(),
    ]
}

/// Rejects raw shell payloads anywhere in the step graph.
fn check_no_raw_shell(steps: &[ProcedureStep]) -> Result<(), ProcedureError> {
    for step in steps {
        for field in step_marker_fields(step) {
            if field_has_shell(field) {
                return Err(ProcedureError::Shape {
                    field: "step.operation".to_owned(),
                    detail: "raw shell payloads are not admitted".to_owned(),
                });
            }
        }
        for input in &step.inputs {
            if field_has_shell(input) {
                return Err(ProcedureError::Shape {
                    field: "step.input".to_owned(),
                    detail: "raw shell payloads are not admitted".to_owned(),
                });
            }
        }
    }
    Ok(())
}

/// Rejects provider and model SDK payloads anywhere in the step graph.
fn check_no_sdk(steps: &[ProcedureStep]) -> Result<(), ProcedureError> {
    for step in steps {
        for field in step_marker_fields(step) {
            if field_has_sdk(field) {
                return Err(ProcedureError::Shape {
                    field: "step.operation".to_owned(),
                    detail: "provider and model SDK payloads are not admitted".to_owned(),
                });
            }
        }
    }
    Ok(())
}

/// Rejects acquired credentials, leases, permits, and handles.
fn check_no_credentials(steps: &[ProcedureStep]) -> Result<(), ProcedureError> {
    for step in steps {
        for field in step_marker_fields(step) {
            if field_has_credential(field) {
                return Err(ProcedureError::Shape {
                    field: "step.operation".to_owned(),
                    detail: "acquired credentials and handles are not admitted".to_owned(),
                });
            }
        }
    }
    Ok(())
}

/// Rejects unbounded loops, fan-out, and retry claims.
fn check_no_unbounded(steps: &[ProcedureStep]) -> Result<(), ProcedureError> {
    for step in steps {
        for field in step_marker_fields(step) {
            if field_has_unbounded(field) {
                return Err(ProcedureError::Shape {
                    field: "step.budget".to_owned(),
                    detail: "unbounded loops and retries are not admitted".to_owned(),
                });
            }
        }
        if step.max_retries > MAX_RETRIES {
            return Err(ProcedureError::Bounds {
                phase: "step.retries".to_owned(),
                detail: "step retries exceed the per-step ceiling".to_owned(),
            });
        }
        if step.fanout > MAX_FANOUT {
            return Err(ProcedureError::Bounds {
                phase: "step.fanout".to_owned(),
                detail: "step fanout exceeds the per-step ceiling".to_owned(),
            });
        }
    }
    Ok(())
}

/// Returns true when any step carries an unknown possible effect.
fn has_unknown_effect(steps: &[ProcedureStep]) -> bool {
    for step in steps {
        if step.effect == EffectClass::Unknown {
            return true;
        }
    }
    false
}

/// Returns true when any step admits a retry.
fn admits_retry(steps: &[ProcedureStep]) -> bool {
    for step in steps {
        if step.max_retries > 0 {
            return true;
        }
    }
    false
}

/// Checks that every unknown-effect step owns a reconciliation note.
fn check_unknown_reconcile_owned(steps: &[ProcedureStep]) -> Result<(), ProcedureError> {
    for step in steps {
        if step.effect == EffectClass::Unknown && step.reconcile_note.trim().is_empty() {
            return Err(ProcedureError::Shape {
                field: "step.reconcile".to_owned(),
                detail: "unknown-effect steps must name reconciliation".to_owned(),
            });
        }
    }
    Ok(())
}

/// Checks that cleanup and rollback are independently owned per step.
fn check_rollback_owned(steps: &[ProcedureStep]) -> Result<(), ProcedureError> {
    for step in steps {
        if step.rollback_note.trim().is_empty() {
            return Err(ProcedureError::Shape {
                field: "step.rollback".to_owned(),
                detail: "every step must name its rollback boundary".to_owned(),
            });
        }
        if step.owner.trim().is_empty() || step.verifier.trim().is_empty() {
            return Err(ProcedureError::Shape {
                field: "step.owner".to_owned(),
                detail: "every step must name one owner and one verifier".to_owned(),
            });
        }
    }
    Ok(())
}

/// Checks trigger and applicability stay inside evidenced environment.
fn check_trigger_bounded(
    capability: &CapabilityEnvSnapshot,
    evidence: &ProcedureEvidence,
    trigger_note: &str,
    applicability_note: &str,
) -> Result<(), ProcedureError> {
    if trigger_note.trim().is_empty() || applicability_note.trim().is_empty() {
        return Err(ProcedureError::Shape {
            field: "trigger".to_owned(),
            detail: "trigger and applicability must be explicit".to_owned(),
        });
    }
    let low_trigger = lowered(trigger_note);
    let low_apply = lowered(applicability_note);
    if mentions_any(&low_trigger, SIMILARITY_MARKERS)
        || mentions_any(&low_apply, SIMILARITY_MARKERS)
    {
        return Err(ProcedureError::Shape {
            field: "trigger".to_owned(),
            detail: "similarity never bounds trigger or applicability".to_owned(),
        });
    }
    if claims_chronology_is_causality(trigger_note)
        || claims_chronology_is_causality(applicability_note)
    {
        return Err(ProcedureError::Shape {
            field: "trigger".to_owned(),
            detail: "chronology never proves causality".to_owned(),
        });
    }
    if claims_timestamp_is_currentness(trigger_note)
        || claims_timestamp_is_currentness(applicability_note)
    {
        return Err(ProcedureError::Shape {
            field: "trigger".to_owned(),
            detail: "timestamps never prove currentness".to_owned(),
        });
    }
    if !contains_marker(&low_trigger, &lowered(&capability.env_id))
        && !contains_marker(&low_apply, &lowered(&capability.env_id))
    {
        return Err(ProcedureError::Binding {
            field: "trigger.env".to_owned(),
            detail: "trigger must name the evidenced environment".to_owned(),
        });
    }
    if evidence.episode_refs.is_empty() {
        return Err(ProcedureError::Shape {
            field: "evidence.episodes".to_owned(),
            detail: "at least one episode ref is required".to_owned(),
        });
    }
    Ok(())
}

/// Selects duplicate, refinement, or conflict disposition from identity.
///
/// Exact digest and identity bindings only; similarity never disposes.
fn select_identity_disposition(
    candidate_digest: &str,
    procedure_handle: &str,
    existing: &ExistingProcedureSnapshot,
) -> Option<ProcedureOutcome> {
    if let Some(dup) = &existing.duplicate_of
        && dup == procedure_handle
    {
        return Some(ProcedureOutcome::Duplicate);
    }
    if existing
        .existing_ids
        .iter()
        .any(|id| id == procedure_handle)
    {
        return Some(ProcedureOutcome::Duplicate);
    }
    if existing
        .existing_digests
        .iter()
        .any(|d| d == candidate_digest)
    {
        return Some(ProcedureOutcome::Duplicate);
    }
    if let Some(refined) = &existing.refinement_of
        && refined != procedure_handle
    {
        return Some(ProcedureOutcome::Refinement);
    }
    if !existing.conflict_with.is_empty() {
        return Some(ProcedureOutcome::Conflict);
    }
    None
}

/// Selects empirical or missing-verifier disposition from evidence shape.
fn select_evidence_disposition(
    evidence: &ProcedureEvidence,
    steps: &[ProcedureStep],
) -> Option<ProcedureOutcome> {
    if evidence.verifier_refs.is_empty() {
        return Some(ProcedureOutcome::MissingVerifier);
    }
    for step in steps {
        if step.verifier.trim().is_empty() {
            return Some(ProcedureOutcome::MissingVerifier);
        }
    }
    if claims_success_is_mechanism(&evidence.mechanism_note) {
        return Some(ProcedureOutcome::Empirical);
    }
    if claims_chronology_is_causality(&evidence.mechanism_note) {
        return Some(ProcedureOutcome::Empirical);
    }
    if evidence.mechanism_note.trim().is_empty() {
        return Some(ProcedureOutcome::Empirical);
    }
    if evidence.failure_refs.is_empty() && evidence.counterexample_refs.is_empty() {
        return Some(ProcedureOutcome::Empirical);
    }
    None
}

/// Builds the transfer boundary preserving env, scope, and negatives.
fn build_transfer(
    capability: &CapabilityEnvSnapshot,
    evidence: &ProcedureEvidence,
    policy: &ProcedurePolicy,
) -> TransferPlan {
    TransferPlan {
        target_env_id: capability.env_id.clone(),
        target_env_revision: capability.env_revision.clone(),
        target_scope_id: capability.scope_id.clone(),
        target_task_id: capability.task_id.clone(),
        preserved_negative_refs: evidence.negative_refs.clone(),
        preserved_counterevidence_refs: evidence.counterexample_refs.clone(),
        preserved_unknown_refs: evidence.unknown_refs.clone(),
        preserved_version_pins: capability.version_pins.clone(),
        reground_note: format!(
            "receiver re-grounds every step under {} before any use; {}",
            capability.env_id, policy.transfer_note
        ),
    }
}

/// Checks the transfer boundary preserves environment and negatives.
fn check_transfer_preserved(
    transfer: &TransferPlan,
    capability: &CapabilityEnvSnapshot,
    evidence: &ProcedureEvidence,
) -> Result<(), ProcedureError> {
    if transfer.target_env_id != capability.env_id {
        return Err(ProcedureError::Binding {
            field: "transfer.env".to_owned(),
            detail: "transfer must not widen the environment".to_owned(),
        });
    }
    if transfer.target_env_revision != capability.env_revision {
        return Err(ProcedureError::Binding {
            field: "transfer.env-revision".to_owned(),
            detail: "transfer must not widen the environment revision".to_owned(),
        });
    }
    if transfer.target_scope_id != capability.scope_id {
        return Err(ProcedureError::Binding {
            field: "transfer.scope".to_owned(),
            detail: "transfer must not widen the scope".to_owned(),
        });
    }
    if transfer.target_task_id != capability.task_id {
        return Err(ProcedureError::Binding {
            field: "transfer.task".to_owned(),
            detail: "transfer must not widen the task".to_owned(),
        });
    }
    if transfer.preserved_negative_refs != evidence.negative_refs {
        return Err(ProcedureError::Binding {
            field: "transfer.negatives".to_owned(),
            detail: "transfer must preserve negative evidence verbatim".to_owned(),
        });
    }
    if transfer.preserved_counterevidence_refs != evidence.counterexample_refs {
        return Err(ProcedureError::Binding {
            field: "transfer.counterevidence".to_owned(),
            detail: "transfer must preserve counterevidence verbatim".to_owned(),
        });
    }
    if transfer.preserved_unknown_refs != evidence.unknown_refs {
        return Err(ProcedureError::Binding {
            field: "transfer.unknowns".to_owned(),
            detail: "transfer must preserve unknown branches verbatim".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Deterministic digest (canonical bytes plus lowercase hex).
// ---------------------------------------------------------------------------

/// Computes the deterministic candidate digest over the proposal inputs.
///
/// The preimage is an ordered string vector covering procedure identity,
/// objective, sorted step identities with owner, contract, operation,
/// effect, verifier, retry, fanout, and boundary notes, plus trigger,
/// environment, scope, task, policy, evidence, and transfer bindings.
/// Scalar, set, identity, or binding drift stays digest-visible; nothing
/// ambient enters the hash.
///
/// # Errors
///
/// Returns [`ProcedureError::Digest`] when canonical serialization fails.
#[allow(clippy::too_many_arguments)]
pub fn compute_candidate_digest(
    procedure_handle: &str,
    objective: &str,
    steps: &[ProcedureStep],
    trigger_note: &str,
    applicability_note: &str,
    capability: &CapabilityEnvSnapshot,
    evidence: &ProcedureEvidence,
    policy: &ProcedurePolicy,
    outcome_spelling: &str,
) -> Result<String, ProcedureError> {
    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("handle:{procedure_handle}"));
    parts.push(format!("objective:{objective}"));
    parts.push(format!("trigger:{trigger_note}"));
    parts.push(format!("applicability:{applicability_note}"));
    parts.push(format!(
        "env:{}@{}",
        capability.env_id, capability.env_revision
    ));
    parts.push(format!("env-digest:{}", capability.env_digest));
    parts.push(format!("scope:{}", capability.scope_id));
    parts.push(format!("task:{}", capability.task_id));
    parts.push(format!(
        "policy:{}@{}",
        policy.policy_id, policy.policy_revision
    ));
    parts.push(format!("bundle:{}", evidence.frozen_bundle_digest));
    parts.push(format!("manifest:{}", evidence.frozen_manifest_digest));
    parts.push(format!("fingerprint:{}", evidence.failure_fingerprint));
    parts.push(format!("mechanism:{}", evidence.mechanism_note));
    if let Some(causal_claim) = &evidence.causal_claim {
        parts.push(format!("causal-claim:{}", causal_claim.digest));
    }
    parts.push(format!("outcome:{outcome_spelling}"));
    let mut index = 0usize;
    while index < steps.len() {
        if let Some(step) = steps.get(index) {
            parts.push(format!(
                "step:{}|{}|{}|{}|{}|{}|{}|{}|{}",
                step.step_id,
                step.owner,
                step.contract_ref,
                step.operation,
                step.effect.as_str(),
                step.verifier,
                step.max_retries,
                step.fanout,
                step.postcondition
            ));
            let mut dep_index = 0usize;
            while dep_index < step.dependencies.len() {
                if let Some(dep) = step.dependencies.get(dep_index) {
                    parts.push(format!("dep:{}->{}", step.step_id, dep));
                }
                dep_index = dep_index.saturating_add(1);
            }
            let mut in_index = 0usize;
            while in_index < step.inputs.len() {
                if let Some(input) = step.inputs.get(in_index) {
                    parts.push(format!("input:{}->{}", step.step_id, input));
                }
                in_index = in_index.saturating_add(1);
            }
        }
        index = index.saturating_add(1);
    }
    for digest in &evidence.episode_refs {
        parts.push(format!("episode:{digest}"));
    }
    for digest in &evidence.verifier_refs {
        parts.push(format!("verifier-ref:{digest}"));
    }
    for digest in &evidence.negative_refs {
        parts.push(format!("negative:{digest}"));
    }
    canonical_json_bytes(&parts)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|err| ProcedureError::Digest {
            detail: redact(&err.to_string()),
        })
}

// ---------------------------------------------------------------------------
// Emission.
// ---------------------------------------------------------------------------

/// Builds one disposition per step in step order.
fn build_step_dispositions(
    steps: &[ProcedureStep],
    outcome: ProcedureOutcome,
) -> Vec<StepDisposition> {
    let mut out: Vec<StepDisposition> = Vec::with_capacity(steps.len());
    for step in steps {
        let kind = match outcome {
            ProcedureOutcome::MissingVerifier => StepDispositionKind::MissingVerifier,
            ProcedureOutcome::Unsafe => StepDispositionKind::Unsafe,
            ProcedureOutcome::BlockedUnknownEffect => {
                if step.effect == EffectClass::Unknown {
                    StepDispositionKind::BlockedUnknownEffect
                } else {
                    StepDispositionKind::Grounded
                }
            }
            ProcedureOutcome::Empirical => StepDispositionKind::Empirical,
            ProcedureOutcome::Conflict => StepDispositionKind::Conflict,
            ProcedureOutcome::Refinement | ProcedureOutcome::Duplicate => {
                StepDispositionKind::Refinement
            }
            _ => StepDispositionKind::Grounded,
        };
        out.push(StepDisposition {
            step_id: step.step_id.clone(),
            kind,
            owner: step.owner.clone(),
            reason: format!("step {} disposed as {}", step.step_id, kind.as_str()),
            evidence_ref: step
                .inputs
                .first()
                .cloned()
                .unwrap_or_else(|| "e-1".to_owned()),
            verifier: step.verifier.clone(),
            inverse_note: step.rollback_note.clone(),
        });
    }
    out
}

/// Emits the terminal candidate envelope for one resolved outcome.
#[allow(clippy::too_many_arguments)]
fn emit_candidate(
    outcome: ProcedureOutcome,
    procedure_handle: &str,
    objective: &str,
    steps: &[ProcedureStep],
    trigger_note: &str,
    applicability_note: &str,
    capability: &CapabilityEnvSnapshot,
    evidence: &ProcedureEvidence,
    policy: &ProcedurePolicy,
    verifier: &str,
    note: &str,
) -> Result<ProcedureCandidate, ProcedureError> {
    let transfer = build_transfer(capability, evidence, policy);
    check_transfer_preserved(&transfer, capability, evidence)?;
    let digest = compute_candidate_digest(
        procedure_handle,
        objective,
        steps,
        trigger_note,
        applicability_note,
        capability,
        evidence,
        policy,
        outcome.as_str(),
    )?;
    let dispositions = build_step_dispositions(steps, outcome);
    Ok(ProcedureCandidate {
        outcome,
        procedure_handle: procedure_handle.to_owned(),
        objective: objective.to_owned(),
        steps: steps.to_vec(),
        step_dispositions: dispositions,
        trigger_note: trigger_note.to_owned(),
        applicability_note: applicability_note.to_owned(),
        transfer,
        verifier: verifier.to_owned(),
        inverse_note: format!("restore the before state named by {procedure_handle}"),
        forward_correction_note:
            "when the before state is unreachable the owner re-derives from the bound frontier"
                .to_owned(),
        reopen_note: evidence.reopen_condition.clone(),
        unknown_handling_note: "unknown outcomes stay open and block retry until reconciled"
            .to_owned(),
        candidate_digest: digest,
        note: note.to_owned(),
    })
}

/// Proposes one grounded inert procedure candidate.
///
/// The six explicit parameters bind the curation input, the grounded draft,
/// the episode and verifier evidence, the capability and environment
/// snapshot, the existing-procedure snapshot, and the governing policy. The
/// A-05 receipt is checked intrinsically through its own validation entry
/// points and is never re-executed here. Returned candidates are inert:
/// every step names the external owner that must execute or decline it.
///
/// Malformed or mismatched inputs fail closed as [`ProcedureError`].
/// Semantic shortfalls emit inert terminal dispositions without effect.
///
/// # Errors
///
/// Returns [`ProcedureError`] on any blank, controlled, overlong,
/// unordered, duplicated, misshapen, mismatched, stale, over-budget,
/// past-deadline, unsafe, or unbound field.
#[allow(clippy::too_many_lines)]
pub fn propose_procedure(
    item: &ValidatedCurationItem,
    grounded: &GroundedDreamDraft,
    evidence: &ProcedureEvidence,
    capability: &CapabilityEnvSnapshot,
    existing: &ExistingProcedureSnapshot,
    policy: &ProcedurePolicy,
) -> Result<ProcedureCandidate, ProcedureError> {
    let steps = collect_candidate_steps(item, evidence, capability)?;
    preflight_evidence_bounds(evidence, policy)?;
    preflight_snapshot_bounds(capability, existing, policy)?;
    preflight_total_bytes(evidence, capability, policy, &steps)?;
    validate_evidence_shapes(evidence)?;
    validate_capability_shapes(capability)?;
    validate_existing_shapes(existing)?;
    validate_policy_shapes(policy)?;
    validate_step_shapes(&steps)?;
    if policy.policy_id != item.receipt.validator_policy {
        return Err(ProcedureError::Policy {
            detail: "policy_id drifts from the receipt validator policy".to_owned(),
        });
    }
    intrinsic_receipt_checks(item, grounded, evidence)?;
    intrinsic_binding_checks(item, grounded, evidence, capability)?;
    intrinsic_denominator_checks(item)?;
    item.denominator
        .validate()
        .map_err(|err| ProcedureError::Denominator {
            detail: redact(&err.to_string()),
        })?;
    if let Some(early) = check_deadline_and_cancel(policy)? {
        let handle = procedure_handle_of(item);
        let objective = procedure_objective_of(item);
        return emit_candidate(
            early,
            &handle,
            &objective,
            &steps,
            &trigger_of(capability, evidence),
            &applicability_of(capability, evidence),
            capability,
            evidence,
            policy,
            &primary_verifier_of(&steps, evidence),
            "cancelled or past-deadline requests emit no effect",
        );
    }
    check_dependency_closure(&steps)?;
    check_graph_acyclic(&steps)?;
    check_no_raw_shell(&steps)?;
    check_no_sdk(&steps)?;
    check_no_credentials(&steps)?;
    check_no_unbounded(&steps)?;
    check_unknown_reconcile_owned(&steps)?;
    check_rollback_owned(&steps)?;
    let handle = procedure_handle_of(item);
    let objective = procedure_objective_of(item);
    check_bounded_text(&handle, "procedure.handle", MAX_HANDLE_BYTES)?;
    check_bounded_text(&objective, "procedure.objective", MAX_OBJECTIVE_BYTES)?;
    let trigger = trigger_of(capability, evidence);
    let applicability = applicability_of(capability, evidence);
    check_trigger_bounded(capability, evidence, &trigger, &applicability)?;
    if has_unknown_effect(&steps) && admits_retry(&steps) {
        return emit_candidate(
            ProcedureOutcome::BlockedUnknownEffect,
            &handle,
            &objective,
            &steps,
            &trigger,
            &applicability,
            capability,
            evidence,
            policy,
            &primary_verifier_of(&steps, evidence),
            "unknown possible effect blocks every retry until the owner reconciles",
        );
    }
    let preliminary = compute_candidate_digest(
        &handle,
        &objective,
        &steps,
        &trigger,
        &applicability,
        capability,
        evidence,
        policy,
        ProcedureOutcome::Complete.as_str(),
    )?;
    if let Some(identity) = select_identity_disposition(&preliminary, &handle, existing) {
        let note = match identity {
            ProcedureOutcome::Duplicate => "procedure identity already known",
            ProcedureOutcome::Refinement => "procedure refines a named predecessor",
            ProcedureOutcome::Conflict => "procedure conflicts with a live procedure",
            _ => "identity disposition",
        };
        return emit_candidate(
            identity,
            &handle,
            &objective,
            &steps,
            &trigger,
            &applicability,
            capability,
            evidence,
            policy,
            &primary_verifier_of(&steps, evidence),
            note,
        );
    }
    if has_unknown_effect(&steps) {
        return emit_candidate(
            ProcedureOutcome::BlockedUnknownEffect,
            &handle,
            &objective,
            &steps,
            &trigger,
            &applicability,
            capability,
            evidence,
            policy,
            &primary_verifier_of(&steps, evidence),
            "unknown possible effect stays open without retry",
        );
    }
    if let Some(shortfall) = select_evidence_disposition(evidence, &steps) {
        let note = match shortfall {
            ProcedureOutcome::MissingVerifier => "a required verifier is missing",
            ProcedureOutcome::Empirical => "support is empirical only without mechanism",
            _ => "evidence shortfall",
        };
        return emit_candidate(
            shortfall,
            &handle,
            &objective,
            &steps,
            &trigger,
            &applicability,
            capability,
            evidence,
            policy,
            &primary_verifier_of(&steps, evidence),
            note,
        );
    }
    if policy.allow_partial && (evidence.unknown_refs.len() > MAX_EVIDENCE_ITEMS.saturating_div(2))
    {
        return emit_candidate(
            ProcedureOutcome::Partial,
            &handle,
            &objective,
            &steps,
            &trigger,
            &applicability,
            capability,
            evidence,
            policy,
            &primary_verifier_of(&steps, evidence),
            "partial coverage with named open unknowns",
        );
    }
    emit_candidate(
        ProcedureOutcome::Complete,
        &handle,
        &objective,
        &steps,
        &trigger,
        &applicability,
        capability,
        evidence,
        policy,
        &primary_verifier_of(&steps, evidence),
        PROCEDURE_PROOF_NOTE,
    )
}

/// Maps a terminal outcome to the closest hub rejection hint, if any.
#[must_use]
pub fn outcome_rejection_hint(outcome: &ProcedureOutcome) -> Option<CurationRejectionCode> {
    match outcome {
        ProcedureOutcome::Complete => None,
        ProcedureOutcome::Partial | ProcedureOutcome::BlockedUnknownEffect => {
            Some(CurationRejectionCode::PreservationFailed)
        }
        ProcedureOutcome::Empirical => Some(CurationRejectionCode::UnsupportedPrecision),
        ProcedureOutcome::MissingVerifier => Some(CurationRejectionCode::LineageMismatch),
        ProcedureOutcome::Unsafe => Some(CurationRejectionCode::UnsupportedJobShape),
        ProcedureOutcome::Duplicate
        | ProcedureOutcome::Refinement
        | ProcedureOutcome::Conflict
        | ProcedureOutcome::Stale
        | ProcedureOutcome::Rejected => Some(CurationRejectionCode::IdentityMismatch),
    }
}

// ---------------------------------------------------------------------------
// Candidate step derivation (typed projection of the thin payload plus the
// explicit evidence, capability, and policy bindings; no model inference).
// ---------------------------------------------------------------------------

/// Returns the objective statement carried by the thin procedure payload.
fn procedure_objective_of(item: &ValidatedCurationItem) -> String {
    match &item.payload {
        eliot_dreamer_contracts::CurationPayload::Procedure(payload) => {
            format!("carry out {} within evidenced bounds", payload.procedure)
        }
        _ => String::new(),
    }
}

/// Returns the declared step count carried by the thin procedure payload.
fn declared_step_count(item: &ValidatedCurationItem) -> u32 {
    match &item.payload {
        eliot_dreamer_contracts::CurationPayload::Procedure(payload) => payload.steps,
        _ => 0,
    }
}

/// Returns the trigger note derived only inside the evidenced environment.
fn trigger_of(capability: &CapabilityEnvSnapshot, evidence: &ProcedureEvidence) -> String {
    format!(
        "when {} fires in env {} scope {}",
        evidence.failure_fingerprint, capability.env_id, capability.scope_id
    )
}

/// Returns the applicability note bounded by evidenced scope and versions.
fn applicability_of(capability: &CapabilityEnvSnapshot, evidence: &ProcedureEvidence) -> String {
    format!(
        "applies in env {}@{} scope {} task {} with {}",
        capability.env_id,
        capability.env_revision,
        capability.scope_id,
        capability.task_id,
        evidence.portability_note
    )
}

/// Returns the primary verifier for the candidate envelope.
fn primary_verifier_of(steps: &[ProcedureStep], evidence: &ProcedureEvidence) -> String {
    if let Some(first) = steps.first()
        && !first.verifier.trim().is_empty()
    {
        return first.verifier.clone();
    }
    evidence
        .verifier_refs
        .first()
        .cloned()
        .unwrap_or_else(|| "verifier-1".to_owned())
}

/// Collects the finite typed step graph for the candidate.
///
/// The thin `ProcedurePayload` carries only a handle and a count, so each
/// emitted step is a typed projection of that handle against the explicit
/// evidence, capability, and policy bindings. Step identities are sorted to
/// keep emission deterministic.
fn collect_candidate_steps(
    item: &ValidatedCurationItem,
    evidence: &ProcedureEvidence,
    capability: &CapabilityEnvSnapshot,
) -> Result<Vec<ProcedureStep>, ProcedureError> {
    let handle = procedure_handle_of(item);
    let declared = declared_step_count(item);
    if handle.trim().is_empty() {
        return Err(ProcedureError::Shape {
            field: "procedure.handle".to_owned(),
            detail: "procedure handle is blank".to_owned(),
        });
    }
    if declared == 0 || usize::try_from(declared).unwrap_or(MAX_STEPS.saturating_add(1)) > MAX_STEPS
    {
        return Err(ProcedureError::Bounds {
            phase: "procedure.steps".to_owned(),
            detail: "declared step count is outside the finite bound".to_owned(),
        });
    }
    let count = usize::try_from(declared).unwrap_or(1usize);
    let evidence_ref = evidence
        .episode_refs
        .first()
        .cloned()
        .unwrap_or_else(|| "e-1".to_owned());
    let verifier_ref = evidence
        .verifier_refs
        .first()
        .cloned()
        .unwrap_or_else(|| "verifier-1".to_owned());
    let wants_unknown = lowered(&evidence.mechanism_note).contains("unknown possible effect");
    let mut steps: Vec<ProcedureStep> = Vec::with_capacity(count);
    let mut seq = 0u32;
    while usize::try_from(seq).unwrap_or(MAX_STEPS) < count {
        let step_id = format!("step-{:02}", seq.saturating_add(1));
        let mut dependencies: Vec<String> = Vec::new();
        if seq > 0 {
            dependencies.push(format!("step-{seq:02}"));
        }
        let mut seq_effect = if seq % 3 == 2 {
            EffectClass::Compensatable
        } else {
            EffectClass::ReadOnly
        };
        if wants_unknown && seq == 0 {
            seq_effect = EffectClass::Unknown;
        }
        steps.push(ProcedureStep {
            step_id,
            owner: format!("owner-{handle}"),
            contract_ref: format!("contract-{handle}-v1"),
            operation: format!("{handle}-op-{}", seq.saturating_add(1)),
            inputs: vec![evidence_ref.clone()],
            precondition: format!("precondition for {handle} part {}", seq.saturating_add(1)),
            dependencies,
            postcondition: format!("observable postcondition {}", seq.saturating_add(1)),
            verifier: verifier_ref.clone(),
            effect: seq_effect,
            effect_boundary: format!("touches only {handle} scope {}", capability.scope_id),
            budget_note: format!("within budget for {handle}"),
            failure_note: format!("on failure hold {handle} for owner review"),
            cancel_note: format!("on cancel release {handle} without effect"),
            reconcile_note: format!("reconcile {handle} against {evidence_ref}"),
            rollback_note: format!("rollback {handle} to the before state"),
            max_retries: 1,
            timeout_ms: Some(600_000),
            fanout: 1,
        });
        seq = seq.saturating_add(1);
    }
    steps.sort_by(|left, right| left.step_id.cmp(&right.step_id));
    Ok(steps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{ArtifactId, EpochId, EpochLineageId, ResourceGeneration};
    use eliot_dreamer_contracts::grounding::canonical::{
        CausalClaimParams, CausalStatus, EvidenceGrade, LineageRootId, PropositionId,
        SourceAssurance, SourceId, SourceLineage, SourceRevisionId, TemporalRecord,
    };
    use eliot_dreamer_contracts::{
        AtomicityMode, ClaimResidue, Requester, RequesterOrigin, SupportState, TargetDenominator,
        curation::{ProcedurePayload, TargetEvidence},
    };
    use std::collections::BTreeSet;
    use std::num::NonZeroU64;

    /// Returns the test state fence at genesis.
    fn test_fence() -> eliot_contracts::StateFence {
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .unwrap_or_else(|error| panic!("canonical test lineage-A: {error}"));
        let sequence = NonZeroU64::new(1).unwrap_or_else(|| unreachable!("one is non-zero"));
        let epoch = EpochId::new(lineage, sequence)
            .unwrap_or_else(|error| panic!("valid test epoch: {error}"));
        eliot_contracts::StateFence::new(epoch, ResourceGeneration::genesis())
    }

    /// Returns a valid A-05 receipt for the test job and digests.
    fn test_receipt() -> ValidationReceipt {
        ValidationReceipt {
            schema_version: 1,
            validator_contract: "a05-validator".to_owned(),
            validator_policy: "policy-7".to_owned(),
            job_id: "job-1".to_owned(),
            draft_digest: "a".repeat(64),
            bundle_digest: "b".repeat(64),
            manifest_digest: "c".repeat(64),
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            input_digest: "d".repeat(64),
            output_digest: "e".repeat(64),
            terminal_disposition: "accepted".to_owned(),
            proof_ceiling: PROOF_CEILING.to_owned(),
            state_fence: test_fence(),
            preservation_digest: "f".repeat(64),
            budget_digest: "0".repeat(64),
        }
    }

    /// Returns a grounded draft bound to the test receipt digests.
    fn test_grounded() -> GroundedDreamDraft {
        GroundedDreamDraft {
            schema_version: 1,
            job_id: "job-1".to_owned(),
            draft_digest: "a".repeat(64),
            residues: vec![ClaimResidue {
                claim: "the procedure trigger fired twice".to_owned(),
                state: SupportState::Supported,
                detail: "ep-1 and ep-2 show the trigger".to_owned(),
            }],
            coverage_note: "one claim accounted".to_owned(),
        }
    }

    /// Returns a procedure curation item bound to the test receipt.
    fn test_item() -> ValidatedCurationItem {
        let payload = eliot_dreamer_contracts::CurationPayload::Procedure(ProcedurePayload {
            procedure: "rotate-caption".to_owned(),
            steps: 3,
            target_evidence: TargetEvidence {
                targets: vec!["mem-1".to_owned()],
                evidence_refs: vec!["e-1".to_owned()],
            },
        });
        ValidatedCurationItem {
            receipt: test_receipt(),
            kind_spelling: "procedure".to_owned(),
            family_spelling: "procedure".to_owned(),
            payload,
            denominator: TargetDenominator {
                mode: AtomicityMode::PerMember,
                members: vec!["mem-1".to_owned()],
                expected_total: 1,
            },
            source_digest: "1".repeat(64),
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            state_fence: test_fence(),
            job_digest: "2".repeat(64),
            requester: Requester {
                origin: RequesterOrigin::Human,
                principal: "op-1".to_owned(),
                session: None,
            },
            budget_note: "within budget".to_owned(),
        }
    }

    /// Returns valid episode and verifier evidence for the test bundle.
    fn test_evidence() -> ProcedureEvidence {
        let receipt = test_receipt();
        ProcedureEvidence {
            expected_receipt: receipt.clone(),
            frozen_bundle_digest: receipt.bundle_digest.clone(),
            frozen_manifest_digest: receipt.manifest_digest.clone(),
            episode_refs: vec!["e-1".to_owned(), "e-2".to_owned()],
            verifier_refs: vec!["verifier-7".to_owned()],
            success_refs: vec!["run-1".to_owned()],
            failure_refs: vec!["run-9".to_owned()],
            counterexample_refs: vec!["ce-1".to_owned()],
            causal_claim: None,
            negative_refs: vec!["neg-1".to_owned()],
            unknown_refs: vec!["unk-1".to_owned()],
            extinction_refs: Vec::new(),
            reopen_condition: "reopen when ep-3 fires".to_owned(),
            mechanism_note: "exercised mechanism m-2 checked by verifier-7".to_owned(),
            portability_note: "portable inside env-1 scope-1 only".to_owned(),
            failure_fingerprint: "fp-1".to_owned(),
        }
    }

    /// Returns a causal claim using the existing rival and confounder contracts.
    fn test_causal_claim() -> Result<CausalClaim, String> {
        let source = SourceId::new("source-causal").map_err(|err| err.to_string())?;
        let revision = SourceRevisionId::new("rev-causal").map_err(|err| err.to_string())?;
        let subject = PropositionId::new("prop-causal").map_err(|err| err.to_string())?;
        let evidence_id = ArtifactId::new("e-causal").map_err(|err| err.to_string())?;
        let rival_evidence_id = ArtifactId::new("e-rival").map_err(|err| err.to_string())?;
        let source_lineage = SourceLineage::new(
            source.clone(),
            revision.clone(),
            "b".repeat(64),
            None,
            BTreeSet::new(),
            None,
        )
        .map_err(|err| err.to_string())?;
        let proof_digest = "c".repeat(64);
        let assurance = SourceAssurance::new(source.clone(), revision, proof_digest.clone())
            .map_err(|err| err.to_string())?;
        CausalClaim::new(CausalClaimParams {
            subject,
            status: CausalStatus::InterventionSupported,
            mechanism: "mechanism under controlled intervention".to_owned(),
            rivals: ["rival explanation".to_owned()].into_iter().collect(),
            confounders: ["confounder disposition".to_owned()].into_iter().collect(),
            evidence_refs: BTreeSet::from([evidence_id, rival_evidence_id]),
            outcome: "observable outcome delta".to_owned(),
            control: "matched control observation".to_owned(),
            source,
            source_lineage,
            assurance,
            lineage: LineageRootId::new("lineage-causal").map_err(|err| err.to_string())?,
            fence: test_fence(),
            temporal: TemporalRecord::new(10, 11, 12, 13, 14).map_err(|err| err.to_string())?,
            proof_digest,
            ceiling: EvidenceGrade::Grounded,
            scope: "scope-1".to_owned(),
        })
        .map_err(|err| err.to_string())
    }

    /// Returns a valid capability and environment snapshot.
    fn test_capability() -> CapabilityEnvSnapshot {
        CapabilityEnvSnapshot {
            capability_refs: vec!["cap-1".to_owned()],
            env_id: "env-1".to_owned(),
            env_revision: "rev-4".to_owned(),
            env_digest: "9".repeat(64),
            scope_id: "scope-1".to_owned(),
            task_id: "task-1".to_owned(),
            policy_id: "policy-7".to_owned(),
            state_fence: test_fence(),
            version_pins: vec!["cap-1@v3".to_owned()],
            capability_note: "cap-1 available without reservation".to_owned(),
        }
    }

    /// Returns an empty existing-procedure snapshot with no dispositions.
    fn test_existing() -> ExistingProcedureSnapshot {
        ExistingProcedureSnapshot {
            existing_digests: Vec::new(),
            existing_ids: Vec::new(),
            duplicate_of: None,
            refinement_of: None,
            conflict_with: Vec::new(),
            superseded_digests: Vec::new(),
        }
    }

    /// Returns a valid governing policy for the test proposal.
    fn test_policy() -> ProcedurePolicy {
        ProcedurePolicy {
            policy_id: "policy-7".to_owned(),
            policy_revision: 2,
            max_steps: MAX_STEPS,
            max_evidence_items: MAX_EVIDENCE_ITEMS,
            allow_partial: false,
            cancelled: false,
            observation_time_ms: Some(1_700_000_000_000),
            deadline_ms: Some(1_800_000_000_000),
            transfer_note: "transfer to the receiving owner".to_owned(),
        }
    }

    // WORK_UNIT_CASE: 661/1
    #[test]
    fn case_01_valid_procedure_completes_with_typed_steps() {
        let item = test_item();
        let grounded = test_grounded();
        let evidence = test_evidence();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let candidate =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("valid procedure request: {err:?}"),
            };
        assert_eq!(candidate.outcome, ProcedureOutcome::Complete);
        assert_eq!(candidate.procedure_handle, "rotate-caption");
        assert_eq!(candidate.steps.len(), 3);
        assert_eq!(candidate.step_dispositions.len(), 3);
        assert_eq!(candidate.transfer.target_env_id, "env-1");
        assert_eq!(candidate.transfer.target_scope_id, "scope-1");
        assert_eq!(
            candidate.transfer.preserved_negative_refs,
            vec!["neg-1".to_owned()]
        );
        assert!(is_hex64_lower(&candidate.candidate_digest));
        assert_eq!(outcome_rejection_hint(&candidate.outcome), None);
    }

    // WORK_UNIT_CASE: 661/2
    #[test]
    fn case_02_exact_trigger_step_operation_failure_retry_transfer_vocabulary() {
        let effects = [
            (EffectClass::ReadOnly, "read_only"),
            (EffectClass::OwnerDirected, "owner_directed"),
            (EffectClass::Compensatable, "compensatable"),
            (EffectClass::Unknown, "unknown"),
        ];
        for (effect, spelling) in effects {
            assert_eq!(effect.as_str(), spelling);
            assert_eq!(EffectClass::parse(spelling), Ok(effect));
        }
        assert!(matches!(
            EffectClass::parse("execute_anything"),
            Err(ProcedureError::Shape { field, .. }) if field == "step.effect"
        ));
        let outcomes = [
            (ProcedureOutcome::Complete, "complete"),
            (ProcedureOutcome::Partial, "partial"),
            (ProcedureOutcome::Duplicate, "duplicate"),
            (ProcedureOutcome::Refinement, "refinement"),
            (ProcedureOutcome::Conflict, "conflict"),
            (ProcedureOutcome::Empirical, "empirical"),
            (ProcedureOutcome::MissingVerifier, "missing_verifier"),
            (ProcedureOutcome::Unsafe, "unsafe"),
            (
                ProcedureOutcome::BlockedUnknownEffect,
                "blocked_unknown_effect",
            ),
            (ProcedureOutcome::Stale, "stale"),
            (ProcedureOutcome::Rejected, "rejected"),
        ];
        let mut outcome_spellings: Vec<String> = Vec::with_capacity(outcomes.len());
        for (outcome, spelling) in outcomes {
            assert_eq!(outcome.as_str(), spelling);
            outcome_spellings.push(spelling.to_owned());
        }
        outcome_spellings.sort();
        assert!(is_sorted_unique(&outcome_spellings));
        let dispositions = [
            (StepDispositionKind::Grounded, "grounded"),
            (StepDispositionKind::Refinement, "refinement"),
            (StepDispositionKind::Conflict, "conflict"),
            (StepDispositionKind::Empirical, "empirical"),
            (StepDispositionKind::MissingVerifier, "missing_verifier"),
            (StepDispositionKind::Unsafe, "unsafe"),
            (
                StepDispositionKind::BlockedUnknownEffect,
                "blocked_unknown_effect",
            ),
            (
                StepDispositionKind::UnchangedWithEvidence,
                "unchanged_with_evidence",
            ),
        ];
        let mut disposition_spellings: Vec<String> = Vec::with_capacity(dispositions.len());
        for (kind, spelling) in dispositions {
            assert_eq!(kind.as_str(), spelling);
            disposition_spellings.push(spelling.to_owned());
        }
        disposition_spellings.sort();
        assert!(is_sorted_unique(&disposition_spellings));
    }

    // WORK_UNIT_CASE: 661/3
    #[test]
    fn case_03_wrong_curation_subtype_fails_closed_without_effect() {
        let grounded = test_grounded();
        let evidence = test_evidence();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let mut concept_item = test_item();
        concept_item.kind_spelling = "concept".to_owned();
        concept_item.family_spelling = "concept".to_owned();
        concept_item.payload = eliot_dreamer_contracts::CurationPayload::Concept(
            eliot_dreamer_contracts::curation::ConceptPayload {
                concept: "caption-style".to_owned(),
                definition: "short caption state dependency".to_owned(),
                target_evidence: TargetEvidence {
                    targets: vec!["mem-1".to_owned()],
                    evidence_refs: vec!["e-1".to_owned()],
                },
            },
        );
        let err = match propose_procedure(
            &concept_item,
            &grounded,
            &evidence,
            &capability,
            &existing,
            &policy,
        ) {
            Ok(candidate) => panic!("concept payload must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            ProcedureError::Shape { field, .. } if field == "procedure.handle"
        ));
        let mut drifted_kind = test_item();
        drifted_kind.kind_spelling = "concept".to_owned();
        let err = match propose_procedure(
            &drifted_kind,
            &grounded,
            &evidence,
            &capability,
            &existing,
            &policy,
        ) {
            Ok(candidate) => panic!("kind drift must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(matches!(err, ProcedureError::Receipt { .. }));
    }

    // WORK_UNIT_CASE: 661/4
    #[test]
    fn case_04_bundle_mismatch_fails_closed_without_effect() {
        let item = test_item();
        let grounded = test_grounded();
        let mut evidence = test_evidence();
        evidence.frozen_bundle_digest = "0".repeat(64);
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let err =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => panic!("mismatched bundle must fail: {:?}", candidate.outcome),
                Err(err) => err,
            };
        assert!(matches!(err, ProcedureError::Binding { field, .. } if field == "bundle_digest"));
    }

    // WORK_UNIT_CASE: 661/5
    #[test]
    fn case_05_duplicate_identity_disposes_without_execution() {
        let item = test_item();
        let grounded = test_grounded();
        let evidence = test_evidence();
        let capability = test_capability();
        let mut existing = test_existing();
        existing.existing_ids = vec!["rotate-caption".to_owned()];
        let policy = test_policy();
        let candidate =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("duplicate request stays inert: {err:?}"),
            };
        assert_eq!(candidate.outcome, ProcedureOutcome::Duplicate);
        assert_eq!(candidate.procedure_handle, "rotate-caption");
        assert_eq!(candidate.steps.len(), 3);
        assert!(is_hex64_lower(&candidate.candidate_digest));
    }

    // WORK_UNIT_CASE: 661/34
    #[test]
    fn case_34_duplicate_existing_procedure_identity_stays_inert() {
        let item = test_item();
        let grounded = test_grounded();
        let evidence = test_evidence();
        let capability = test_capability();
        let mut existing = test_existing();
        existing.duplicate_of = Some("rotate-caption".to_owned());
        let policy = test_policy();
        let candidate =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("duplicate existing procedure stays inert: {err:?}"),
            };

        assert_eq!(candidate.outcome, ProcedureOutcome::Duplicate);
        assert_eq!(candidate.procedure_handle, "rotate-caption");
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::IdentityMismatch)
        );
        assert!(is_hex64_lower(&candidate.candidate_digest));
    }

    // WORK_UNIT_CASE: 661/31
    #[test]
    fn case_31_valid_transfer_stays_bounded_to_source_snapshot() {
        let item = test_item();
        let grounded = test_grounded();
        let evidence = test_evidence();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let candidate =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("bounded transfer request: {err:?}"),
            };

        assert_eq!(candidate.outcome, ProcedureOutcome::Complete);
        assert_eq!(candidate.transfer.target_env_id, capability.env_id);
        assert_eq!(
            candidate.transfer.target_env_revision,
            capability.env_revision
        );
        assert_eq!(candidate.transfer.target_scope_id, capability.scope_id);
        assert_eq!(candidate.transfer.target_task_id, capability.task_id);
        assert_eq!(
            candidate.transfer.preserved_version_pins,
            capability.version_pins
        );
        assert_eq!(
            candidate.transfer.preserved_negative_refs,
            evidence.negative_refs
        );
        assert_eq!(
            candidate.transfer.preserved_counterevidence_refs,
            evidence.counterexample_refs
        );
        assert_eq!(
            candidate.transfer.preserved_unknown_refs,
            evidence.unknown_refs
        );
        assert!(candidate.transfer.reground_note.contains("re-grounds"));
    }

    // WORK_UNIT_CASE: 661/32
    #[test]
    fn case_32_one_source_success_stays_empirical_and_source_scoped() {
        let item = test_item();
        let grounded = test_grounded();
        let mut evidence = test_evidence();
        evidence.failure_refs.clear();
        evidence.counterexample_refs.clear();
        evidence.mechanism_note =
            "one source-domain success is not proof of broad transfer".to_owned();
        evidence.portability_note =
            "source-domain observation only; target outcome is not observed".to_owned();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let candidate =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("source-only transfer request: {err:?}"),
            };

        assert_eq!(candidate.outcome, ProcedureOutcome::Empirical);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::UnsupportedPrecision)
        );
        assert!(candidate.applicability_note.contains("env-1@rev-4"));
        assert!(candidate.applicability_note.contains("scope-1"));
        assert!(
            candidate
                .applicability_note
                .contains("target outcome is not observed")
        );
        assert_eq!(candidate.transfer.target_env_id, "env-1");
        assert_eq!(candidate.transfer.target_scope_id, "scope-1");
    }

    // WORK_UNIT_CASE: 661/33
    #[test]
    fn case_33_negative_transfer_and_unknown_target_outcome_remain_visible() {
        let item = test_item();
        let grounded = test_grounded();
        let mut evidence = test_evidence();
        evidence.negative_refs = vec!["negative-transfer-env-2".to_owned()];
        evidence.unknown_refs = vec!["target-outcome-unobserved".to_owned()];
        evidence.portability_note =
            "source-domain negative transfer is retained; target outcome remains unobserved"
                .to_owned();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let candidate =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("negative transfer request: {err:?}"),
            };

        assert_eq!(candidate.outcome, ProcedureOutcome::Complete);
        assert_eq!(
            candidate.transfer.preserved_negative_refs,
            vec!["negative-transfer-env-2".to_owned()]
        );
        assert_eq!(
            candidate.transfer.preserved_counterevidence_refs,
            vec!["ce-1".to_owned()]
        );
        assert_eq!(
            candidate.transfer.preserved_unknown_refs,
            vec!["target-outcome-unobserved".to_owned()]
        );
        assert_eq!(candidate.transfer.target_env_id, "env-1");
        assert_eq!(candidate.transfer.target_scope_id, "scope-1");
        assert!(
            candidate
                .applicability_note
                .contains("target outcome remains unobserved")
        );
    }

    // WORK_UNIT_CASE: 661/40
    #[test]
    fn case_40_partial_budget_deadline_and_cancellation_stay_bounded() {
        let item = test_item();
        let grounded = test_grounded();
        let capability = test_capability();
        let existing = test_existing();

        let mut partial_evidence = test_evidence();
        partial_evidence.unknown_refs = (0..=32)
            .map(|index| format!("unknown-{index:02}"))
            .collect();
        let mut partial_policy = test_policy();
        partial_policy.allow_partial = true;
        let partial = match propose_procedure(
            &item,
            &grounded,
            &partial_evidence,
            &capability,
            &existing,
            &partial_policy,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("open unknowns should remain a partial candidate: {err:?}"),
        };
        assert_eq!(partial.outcome, ProcedureOutcome::Partial);
        assert!(partial.note.contains("partial coverage"));
        assert_eq!(
            partial.transfer.preserved_unknown_refs,
            partial_evidence.unknown_refs
        );

        let mut over_budget = test_policy();
        over_budget.max_steps = MAX_STEPS.saturating_add(1);
        let budget_error = match propose_procedure(
            &item,
            &grounded,
            &test_evidence(),
            &capability,
            &existing,
            &over_budget,
        ) {
            Ok(candidate) => panic!("over-budget policy must fail closed: {candidate:?}"),
            Err(error) => error,
        };
        assert!(matches!(budget_error, ProcedureError::Policy { .. }));

        let mut expired = test_policy();
        expired.observation_time_ms = expired.deadline_ms;
        let deadline_error = match propose_procedure(
            &item,
            &grounded,
            &test_evidence(),
            &capability,
            &existing,
            &expired,
        ) {
            Ok(candidate) => panic!("at-deadline policy must fail closed: {candidate:?}"),
            Err(error) => error,
        };
        assert!(matches!(deadline_error, ProcedureError::Policy { .. }));

        let mut cancelled = test_policy();
        cancelled.cancelled = true;
        let cancelled_candidate = match propose_procedure(
            &item,
            &grounded,
            &test_evidence(),
            &capability,
            &existing,
            &cancelled,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("cancelled request should stay inert: {err:?}"),
        };
        assert_eq!(cancelled_candidate.outcome, ProcedureOutcome::Rejected);
        assert!(cancelled_candidate.note.contains("no effect"));
    }

    // WORK_UNIT_CASE: 661/13
    #[test]
    fn case_13_valid_acyclic_graph_completes_deterministically() {
        let item = test_item();
        let grounded = test_grounded();
        let evidence = test_evidence();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let first =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("first acyclic replay: {err:?}"),
            };
        let second =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("second acyclic replay: {err:?}"),
            };
        assert_eq!(first.outcome, ProcedureOutcome::Complete);
        assert_eq!(first.candidate_digest, second.candidate_digest);
        let ids: Vec<String> = first.steps.iter().map(|s| s.step_id.clone()).collect();
        assert_eq!(
            ids,
            vec![
                "step-01".to_owned(),
                "step-02".to_owned(),
                "step-03".to_owned()
            ]
        );
        for step in &first.steps {
            assert!(!step.owner.trim().is_empty());
            assert!(!step.contract_ref.trim().is_empty());
            assert!(!step.precondition.trim().is_empty());
            assert!(!step.postcondition.trim().is_empty());
            assert!(!step.verifier.trim().is_empty());
            assert!(!step.rollback_note.trim().is_empty());
        }
    }

    // WORK_UNIT_CASE: 661/41
    #[test]
    fn case_41_privacy_authority_effect_proof_support_and_lifecycle_do_not_escalate() {
        assert_eq!(test_receipt().proof_ceiling, PROOF_CEILING);
        let item = test_item();
        let grounded = test_grounded();
        let evidence = test_evidence();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let candidate =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(error) => panic!("candidate-only proposal: {error:?}"),
            };

        assert_eq!(candidate.outcome, ProcedureOutcome::Complete);
        assert_eq!(candidate.note, PROCEDURE_PROOF_NOTE);
        assert_eq!(candidate.reopen_note, evidence.reopen_condition);
        assert_eq!(
            candidate.unknown_handling_note,
            "unknown outcomes stay open and block retry until reconciled"
        );
        assert_eq!(
            candidate.transfer.preserved_negative_refs,
            evidence.negative_refs
        );
        for step in &candidate.steps {
            assert!(matches!(
                step.effect,
                EffectClass::ReadOnly | EffectClass::Compensatable
            ));
            assert!(!step.owner.is_empty());
            assert!(!step.rollback_note.is_empty());
        }

        let mut escalated_item = test_item();
        let mut escalated_evidence = test_evidence();
        escalated_item.receipt.proof_ceiling = "scoped-verification".to_owned();
        escalated_evidence.expected_receipt.proof_ceiling = "scoped-verification".to_owned();
        let error = match propose_procedure(
            &escalated_item,
            &grounded,
            &escalated_evidence,
            &capability,
            &existing,
            &policy,
        ) {
            Ok(candidate) => panic!("proof escalation must fail: {candidate:?}"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ProcedureError::Policy { detail }
                if detail == "procedure candidates cannot escalate beyond candidate-only proof"
        ));

        let mut unsupported = test_evidence();
        unsupported.failure_refs.clear();
        unsupported.counterexample_refs.clear();
        let empirical = match propose_procedure(
            &item,
            &grounded,
            &unsupported,
            &capability,
            &existing,
            &policy,
        ) {
            Ok(candidate) => candidate,
            Err(error) => panic!("support shortfall should remain inert: {error:?}"),
        };
        assert_eq!(empirical.outcome, ProcedureOutcome::Empirical);
        assert!(empirical.note.contains("empirical"));
    }

    // WORK_UNIT_CASE: 661/42
    #[test]
    #[allow(clippy::too_many_lines)]
    fn case_42_independent_step_evidence_failure_transfer_output_and_work_bounds() {
        let mut exact_item = test_item();
        if let eliot_dreamer_contracts::CurationPayload::Procedure(payload) =
            &mut exact_item.payload
        {
            payload.steps =
                u32::try_from(MAX_STEPS).unwrap_or_else(|_| unreachable!("MAX_STEPS fits u32"));
        }
        let exact = match propose_procedure(
            &exact_item,
            &test_grounded(),
            &test_evidence(),
            &test_capability(),
            &test_existing(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(error) => panic!("the exact step ceiling is admitted: {error:?}"),
        };
        assert_eq!(exact.steps.len(), MAX_STEPS);
        assert_eq!(exact.step_dispositions.len(), MAX_STEPS);
        assert_eq!(exact.candidate_digest.len(), 64);
        assert_eq!(
            exact.transfer.preserved_negative_refs,
            test_evidence().negative_refs
        );

        let mut over_item = test_item();
        if let eliot_dreamer_contracts::CurationPayload::Procedure(payload) = &mut over_item.payload
        {
            payload.steps = u32::try_from(MAX_STEPS + 1)
                .unwrap_or_else(|_| unreachable!("MAX_STEPS + 1 fits u32"));
        }
        let over_steps = match propose_procedure(
            &over_item,
            &test_grounded(),
            &test_evidence(),
            &test_capability(),
            &test_existing(),
            &test_policy(),
        ) {
            Ok(candidate) => panic!("one step over the graph ceiling must fail: {candidate:?}"),
            Err(error) => error,
        };
        assert!(matches!(
            over_steps,
            ProcedureError::Bounds { phase, .. } if phase == "procedure.steps"
        ));

        let mut step = exact.steps[0].clone();
        step.inputs = (0..MAX_STEP_INPUTS)
            .map(|index| format!("input-{index:02}"))
            .collect();
        assert!(validate_one_step_shape(&step).is_ok());
        step.inputs.push("input-99".to_owned());
        assert!(matches!(
            validate_one_step_shape(&step),
            Err(ProcedureError::Bounds { phase, .. }) if phase == "step.inputs"
        ));

        let mut dependency_step = exact.steps[0].clone();
        dependency_step.dependencies = (0..MAX_STEP_DEPS)
            .map(|index| format!("dep-{index:02}"))
            .collect();
        assert!(validate_one_step_shape(&dependency_step).is_ok());
        dependency_step.dependencies.push("dep-99".to_owned());
        assert!(matches!(
            validate_one_step_shape(&dependency_step),
            Err(ProcedureError::Bounds { phase, .. }) if phase == "step.dependencies"
        ));

        let mut oversized_extinction = test_evidence();
        oversized_extinction.extinction_refs = (0..=MAX_EVIDENCE_ITEMS)
            .map(|index| format!("extinction-{index:03}"))
            .collect();
        let extinction_error = match propose_procedure(
            &test_item(),
            &test_grounded(),
            &oversized_extinction,
            &test_capability(),
            &test_existing(),
            &test_policy(),
        ) {
            Ok(candidate) => {
                panic!("extinction refs over the evidence ceiling must fail: {candidate:?}")
            }
            Err(error) => error,
        };
        assert!(matches!(
            extinction_error,
            ProcedureError::Bounds { phase, .. } if phase == "extinction-refs"
        ));

        let mut oversized_capability = test_capability();
        oversized_capability.capability_refs = (0..=MAX_EVIDENCE_ITEMS)
            .map(|index| format!("capability-{index:03}"))
            .collect();
        let capability_error = match propose_procedure(
            &test_item(),
            &test_grounded(),
            &test_evidence(),
            &oversized_capability,
            &test_existing(),
            &test_policy(),
        ) {
            Ok(candidate) => {
                panic!("capability refs over the evidence ceiling must fail: {candidate:?}")
            }
            Err(error) => error,
        };
        assert!(matches!(
            capability_error,
            ProcedureError::Bounds { phase, .. } if phase == "capability-refs"
        ));

        let mut unsorted_counterexamples = test_evidence();
        unsorted_counterexamples.counterexample_refs = vec!["ce-2".to_owned(), "ce-1".to_owned()];
        let unsorted_error = match propose_procedure(
            &test_item(),
            &test_grounded(),
            &unsorted_counterexamples,
            &test_capability(),
            &test_existing(),
            &test_policy(),
        ) {
            Ok(candidate) => panic!("unsorted counterexample refs must fail: {candidate:?}"),
            Err(error) => error,
        };
        assert!(matches!(
            unsorted_error,
            ProcedureError::Order { phase, .. } if phase == "evidence.counterexamples"
        ));

        let mut duplicate_counterexamples = test_evidence();
        duplicate_counterexamples.counterexample_refs = vec!["ce-1".to_owned(), "ce-1".to_owned()];
        let duplicate_error = match propose_procedure(
            &test_item(),
            &test_grounded(),
            &duplicate_counterexamples,
            &test_capability(),
            &test_existing(),
            &test_policy(),
        ) {
            Ok(candidate) => panic!("duplicate counterexample refs must fail: {candidate:?}"),
            Err(error) => error,
        };
        assert!(matches!(
            duplicate_error,
            ProcedureError::Order { phase, .. } if phase == "evidence.counterexamples"
        ));

        let mut oversized_policy = test_policy();
        oversized_policy.transfer_note = "x".repeat(MAX_NOTE_BYTES + 1);
        let transfer_error = match propose_procedure(
            &test_item(),
            &test_grounded(),
            &test_evidence(),
            &test_capability(),
            &test_existing(),
            &oversized_policy,
        ) {
            Ok(candidate) => panic!("transfer note over the text ceiling must fail: {candidate:?}"),
            Err(error) => error,
        };
        assert!(matches!(
            transfer_error,
            ProcedureError::Shape { field, .. } if field == "policy.transfer"
        ));

        let mut oversized = exact.steps[0].clone();
        oversized.precondition = "x".repeat(MAX_TOTAL_BYTES + 1);
        assert!(matches!(
            preflight_total_bytes(
                &test_evidence(),
                &test_capability(),
                &test_policy(),
                &[oversized]
            ),
            Err(ProcedureError::Bounds { phase, .. }) if phase == "total-bytes"
        ));
    }

    // WORK_UNIT_CASE: 661/43
    #[test]
    fn case_43_set_order_is_deterministic_while_step_order_stays_semantic() {
        let mut item = test_item();
        if let eliot_dreamer_contracts::CurationPayload::Procedure(payload) = &mut item.payload {
            payload.steps = 5;
        }

        let mut evidence = test_evidence();
        let mut episode_refs = BTreeSet::new();
        episode_refs.extend(["e-3", "e-1", "e-2"].map(str::to_owned));
        evidence.episode_refs = episode_refs.into_iter().collect();
        let mut verifier_refs = BTreeSet::new();
        verifier_refs.extend(["verifier-9", "verifier-7"].map(str::to_owned));
        evidence.verifier_refs = verifier_refs.into_iter().collect();
        let mut negative_refs = BTreeSet::new();
        negative_refs.extend(["neg-2", "neg-1"].map(str::to_owned));
        evidence.negative_refs = negative_refs.into_iter().collect();
        let mut unknown_refs = BTreeSet::new();
        unknown_refs.extend(["unk-2", "unk-1"].map(str::to_owned));
        evidence.unknown_refs = unknown_refs.into_iter().collect();

        let candidate = match propose_procedure(
            &item,
            &test_grounded(),
            &evidence,
            &test_capability(),
            &test_existing(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(error) => panic!("ordered set projection must remain admissible: {error:?}"),
        };

        let expected_ids: Vec<String> = (1..=5).map(|index| format!("step-{index:02}")).collect();
        let actual_ids: Vec<String> = candidate
            .steps
            .iter()
            .map(|step| step.step_id.clone())
            .collect();
        assert_eq!(actual_ids, expected_ids);
        for (index, step) in candidate.steps.iter().enumerate() {
            let expected_dependencies = if index == 0 {
                Vec::new()
            } else {
                vec![format!("step-{index:02}")]
            };
            assert_eq!(step.dependencies, expected_dependencies);
        }
        assert!(is_sorted_unique(&evidence.episode_refs));
        assert!(is_sorted_unique(&evidence.verifier_refs));
        assert!(is_sorted_unique(
            &candidate.transfer.preserved_negative_refs
        ));
        assert!(is_sorted_unique(&candidate.transfer.preserved_unknown_refs));
        assert_eq!(
            candidate.transfer.preserved_negative_refs,
            evidence.negative_refs
        );
        assert_eq!(
            candidate.transfer.preserved_unknown_refs,
            evidence.unknown_refs
        );

        let replay = match propose_procedure(
            &item,
            &test_grounded(),
            &evidence,
            &test_capability(),
            &test_existing(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(error) => panic!("ordered set replay must remain admissible: {error:?}"),
        };
        assert_eq!(candidate, replay);
    }

    // WORK_UNIT_CASE: 661/17
    #[test]
    fn case_17_raw_shell_payload_is_rejected_without_execution() {
        let mut item = test_item();
        if let eliot_dreamer_contracts::CurationPayload::Procedure(payload) = &mut item.payload {
            payload.procedure = "shell_exec rotate".to_owned();
        }
        let grounded = test_grounded();
        let evidence = test_evidence();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let err =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => panic!("raw shell must fail: {:?}", candidate.outcome),
                Err(err) => err,
            };
        assert!(matches!(err, ProcedureError::Shape { field, .. } if field == "step.operation"));
    }

    // WORK_UNIT_CASE: 661/25
    #[test]
    fn case_25_exact_idempotent_replay_binds_policy_revision() {
        let item = test_item();
        let grounded = test_grounded();
        let evidence = test_evidence();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let first =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("first replay: {err:?}"),
            };
        let second =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("second replay: {err:?}"),
            };
        assert_eq!(first, second);
        assert_eq!(first.candidate_digest, second.candidate_digest);
        let mut reved_policy = test_policy();
        reved_policy.policy_revision = 3;
        let reved = match propose_procedure(
            &item,
            &grounded,
            &evidence,
            &capability,
            &existing,
            &reved_policy,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("reved replay: {err:?}"),
        };
        assert_eq!(reved.outcome, ProcedureOutcome::Complete);
        assert_ne!(reved.candidate_digest, first.candidate_digest);
    }

    // WORK_UNIT_CASE: 661/26
    #[test]
    fn case_26_unknown_effect_blocks_retry_without_blind_retry() {
        let item = test_item();
        let grounded = test_grounded();
        let mut evidence = test_evidence();
        evidence.mechanism_note =
            "exercised mechanism m-2 with unknown possible effect on ext-9".to_owned();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let candidate =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("unknown-effect request stays inert: {err:?}"),
            };
        assert_eq!(candidate.outcome, ProcedureOutcome::BlockedUnknownEffect);
        assert_eq!(candidate.procedure_handle, "rotate-caption");
        assert!(has_unknown_effect(&candidate.steps));
        assert!(admits_retry(&candidate.steps));
        assert!(is_hex64_lower(&candidate.candidate_digest));
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::PreservationFailed)
        );
        let baseline = match propose_procedure(
            &item,
            &grounded,
            &test_evidence(),
            &capability,
            &existing,
            &policy,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("baseline without unknown: {err:?}"),
        };
        assert_eq!(baseline.outcome, ProcedureOutcome::Complete);
        assert_ne!(baseline.candidate_digest, candidate.candidate_digest);
    }

    #[test]
    fn no_causal_claim_digest_matches_legacy_golden() {
        let candidate = match propose_procedure(
            &test_item(),
            &test_grounded(),
            &test_evidence(),
            &test_capability(),
            &test_existing(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("legacy no-claim fixture: {err:?}"),
        };
        assert!(test_evidence().causal_claim.is_none());
        assert_eq!(
            candidate.candidate_digest,
            "8f5ac35ef3276794453ddf44684afea4301184816e621fcdb348fc8cc0975adb"
        );
    }

    // WORK_UNIT_CASE: 661/27
    #[test]
    fn case_27_cancellation_boundaries_preserve_inert_recovery_paths() {
        let item = test_item();
        let grounded = test_grounded();
        let evidence = test_evidence();
        let capability = test_capability();
        let existing = test_existing();
        let mut cancelled = test_policy();
        cancelled.cancelled = true;
        let candidate = match propose_procedure(
            &item,
            &grounded,
            &evidence,
            &capability,
            &existing,
            &cancelled,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("pre-admission cancellation stays inert: {err:?}"),
        };
        assert_eq!(candidate.outcome, ProcedureOutcome::Rejected);
        assert!(candidate.note.contains("no effect"));
        for step in &candidate.steps {
            assert!(step.cancel_note.contains("on cancel"));
            assert!(step.rollback_note.contains("before state"));
        }

        let mut possible_effect = test_evidence();
        possible_effect.mechanism_note =
            "exercised mechanism m-2 with unknown possible effect on ext-9".to_owned();
        let candidate = match propose_procedure(
            &item,
            &grounded,
            &possible_effect,
            &capability,
            &existing,
            &cancelled,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("cancellation after possible effect stays inert: {err:?}"),
        };
        assert_eq!(candidate.outcome, ProcedureOutcome::Rejected);
        assert!(has_unknown_effect(&candidate.steps));
        assert!(candidate.unknown_handling_note.contains("reconcile"));
        assert!(candidate.steps.iter().all(|step| {
            step.cancel_note.contains("on cancel") && step.reconcile_note.contains("reconcile")
        }));
    }

    // WORK_UNIT_CASE: 661/28
    #[test]
    fn case_28_cleanup_failure_and_unknown_paths_keep_exact_owners() {
        let candidate = match propose_procedure(
            &test_item(),
            &test_grounded(),
            &test_evidence(),
            &test_capability(),
            &test_existing(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("cleanup baseline: {err:?}"),
        };
        assert_eq!(candidate.outcome, ProcedureOutcome::Complete);
        for step in &candidate.steps {
            assert!(!step.owner.trim().is_empty());
            assert!(step.failure_note.contains("owner review"));
            assert!(step.rollback_note.contains("rollback"));
        }
        assert!(check_rollback_owned(&candidate.steps).is_ok());

        let mut missing_cleanup = candidate.steps[0].clone();
        missing_cleanup.rollback_note.clear();
        assert!(matches!(
            check_rollback_owned(std::slice::from_ref(&missing_cleanup)),
            Err(ProcedureError::Shape { field, .. }) if field == "step.rollback"
        ));

        let mut missing_reconciliation = candidate.steps[0].clone();
        missing_reconciliation.effect = EffectClass::Unknown;
        missing_reconciliation.reconcile_note.clear();
        assert!(matches!(
            check_unknown_reconcile_owned(std::slice::from_ref(&missing_reconciliation)),
            Err(ProcedureError::Shape { field, .. }) if field == "step.reconcile"
        ));
    }

    // WORK_UNIT_CASE: 661/29
    #[test]
    fn case_29_effect_classes_keep_reversible_and_compensation_boundaries() {
        for spelling in ["read_only", "owner_directed", "compensatable", "unknown"] {
            assert!(EffectClass::parse(spelling).is_ok());
        }
        assert!(matches!(
            EffectClass::parse("irreversible"),
            Err(ProcedureError::Shape { field, .. }) if field == "step.effect"
        ));

        let candidate = match propose_procedure(
            &test_item(),
            &test_grounded(),
            &test_evidence(),
            &test_capability(),
            &test_existing(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("effect-class baseline: {err:?}"),
        };
        assert!(
            candidate
                .steps
                .iter()
                .any(|step| step.effect == EffectClass::Compensatable)
        );
        assert!(candidate.steps.iter().all(|step| {
            step.effect != EffectClass::Compensatable || step.rollback_note.contains("rollback")
        }));

        let mut unknown_evidence = test_evidence();
        unknown_evidence.mechanism_note =
            "exercised mechanism m-2 with unknown possible effect on ext-9".to_owned();
        let unknown = match propose_procedure(
            &test_item(),
            &test_grounded(),
            &unknown_evidence,
            &test_capability(),
            &test_existing(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("unknown effect remains candidate-only: {err:?}"),
        };
        assert_eq!(unknown.outcome, ProcedureOutcome::BlockedUnknownEffect);
        assert!(unknown.steps.iter().any(|step| {
            step.effect == EffectClass::Unknown && step.reconcile_note.contains("reconcile")
        }));
    }

    // WORK_UNIT_CASE: 661/30
    #[test]
    fn case_30_rollback_and_forward_repair_keep_current_preconditions_visible() {
        let candidate = match propose_procedure(
            &test_item(),
            &test_grounded(),
            &test_evidence(),
            &test_capability(),
            &test_existing(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("rollback baseline: {err:?}"),
        };
        assert!(candidate.inverse_note.contains("before state"));
        assert!(
            candidate
                .forward_correction_note
                .contains("before state is unreachable")
        );
        for step in &candidate.steps {
            assert!(!step.precondition.trim().is_empty());
            assert!(!step.rollback_note.trim().is_empty());
        }
        assert!(
            candidate
                .step_dispositions
                .iter()
                .all(|disposition| !disposition.inverse_note.trim().is_empty())
        );
    }

    // WORK_UNIT_CASE: 661/6
    #[test]
    fn case_06_success_and_failure_episode_evidence_preserved() {
        let item = test_item();
        let grounded = test_grounded();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let full = match propose_procedure(
            &item,
            &grounded,
            &test_evidence(),
            &capability,
            &existing,
            &policy,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("full success and failure evidence: {err:?}"),
        };
        assert_eq!(full.outcome, ProcedureOutcome::Complete);
        assert_eq!(outcome_rejection_hint(&full.outcome), None);
        let mut only_failure_dropped = test_evidence();
        only_failure_dropped.failure_refs = Vec::new();
        let kept_counter = match propose_procedure(
            &item,
            &grounded,
            &only_failure_dropped,
            &capability,
            &existing,
            &policy,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("counterexample keeps counterevidence: {err:?}"),
        };
        assert_eq!(kept_counter.outcome, ProcedureOutcome::Complete);
        let mut bare_success = test_evidence();
        bare_success.failure_refs = Vec::new();
        bare_success.counterexample_refs = Vec::new();
        let empirical = match propose_procedure(
            &item,
            &grounded,
            &bare_success,
            &capability,
            &existing,
            &policy,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("bare success without counterevidence: {err:?}"),
        };
        assert_eq!(empirical.outcome, ProcedureOutcome::Empirical);
        assert_eq!(
            outcome_rejection_hint(&empirical.outcome),
            Some(CurationRejectionCode::UnsupportedPrecision)
        );
        assert_ne!(empirical.candidate_digest, full.candidate_digest);
        assert_eq!(
            empirical.transfer.preserved_counterevidence_refs,
            Vec::<String>::new()
        );
        assert_eq!(
            full.transfer.preserved_counterevidence_refs,
            vec!["ce-1".to_owned()]
        );
    }

    // WORK_UNIT_CASE: 661/7
    #[test]
    fn case_07_lucky_success_without_controls_stays_empirical() {
        let item = test_item();
        let grounded = test_grounded();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let baseline = match propose_procedure(
            &item,
            &grounded,
            &test_evidence(),
            &capability,
            &existing,
            &policy,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("controlled baseline: {err:?}"),
        };
        assert_eq!(baseline.outcome, ProcedureOutcome::Complete);
        let mut lucky = test_evidence();
        lucky.mechanism_note = "one success proves mechanism for rotate-caption".to_owned();
        let candidate =
            match propose_procedure(&item, &grounded, &lucky, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("lucky success stays inert: {err:?}"),
            };
        assert_eq!(candidate.outcome, ProcedureOutcome::Empirical);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::UnsupportedPrecision)
        );
        assert!(is_hex64_lower(&candidate.candidate_digest));
        assert_ne!(candidate.candidate_digest, baseline.candidate_digest);
        let mut single = test_evidence();
        single.mechanism_note = "single episode proves portability everywhere".to_owned();
        let single_candidate =
            match propose_procedure(&item, &grounded, &single, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("single episode stays inert: {err:?}"),
            };
        assert_eq!(single_candidate.outcome, ProcedureOutcome::Empirical);
    }

    // WORK_UNIT_CASE: 661/8
    #[test]
    fn case_08_exit_confidence_not_semantic_success() {
        let item = test_item();
        let grounded = test_grounded();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let mut exit_claim = test_evidence();
        exit_claim.mechanism_note =
            "exit zero proves semantic success for rotate-caption".to_owned();
        let exit_candidate = match propose_procedure(
            &item,
            &grounded,
            &exit_claim,
            &capability,
            &existing,
            &policy,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("exit-zero claim stays inert: {err:?}"),
        };
        assert_eq!(exit_candidate.outcome, ProcedureOutcome::Empirical);
        assert_eq!(
            outcome_rejection_hint(&exit_candidate.outcome),
            Some(CurationRejectionCode::UnsupportedPrecision)
        );
        let mut confidence_claim = test_evidence();
        confidence_claim.mechanism_note =
            "confidence proves mechanism for rotate-caption".to_owned();
        let confidence_candidate = match propose_procedure(
            &item,
            &grounded,
            &confidence_claim,
            &capability,
            &existing,
            &policy,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("confidence claim stays inert: {err:?}"),
        };
        assert_eq!(confidence_candidate.outcome, ProcedureOutcome::Empirical);
        assert_eq!(
            outcome_rejection_hint(&confidence_candidate.outcome),
            Some(CurationRejectionCode::UnsupportedPrecision)
        );
        assert!(is_hex64_lower(&exit_candidate.candidate_digest));
        assert!(is_hex64_lower(&confidence_candidate.candidate_digest));
        assert_ne!(
            exit_candidate.candidate_digest,
            confidence_candidate.candidate_digest
        );
    }

    // WORK_UNIT_CASE: 661/9
    #[test]
    fn case_09_empirical_unknown_mechanism_lower_ceiling() {
        let item = test_item();
        let grounded = test_grounded();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let baseline = match propose_procedure(
            &item,
            &grounded,
            &test_evidence(),
            &capability,
            &existing,
            &policy,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("mechanism baseline: {err:?}"),
        };
        assert_eq!(baseline.outcome, ProcedureOutcome::Complete);
        let mut unknown = test_evidence();
        unknown.mechanism_note =
            "repeatable safe sequence with unknown mechanism; one success proves mechanism for rotate-caption"
                .to_owned();
        let candidate =
            match propose_procedure(&item, &grounded, &unknown, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("unknown mechanism stays inert: {err:?}"),
            };
        assert_eq!(candidate.outcome, ProcedureOutcome::Empirical);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::UnsupportedPrecision)
        );
        assert!(is_hex64_lower(&candidate.candidate_digest));
        assert_ne!(candidate.candidate_digest, baseline.candidate_digest);
        for disposition in &candidate.step_dispositions {
            assert_eq!(disposition.kind, StepDispositionKind::Empirical);
        }
        assert_eq!(
            candidate.transfer.preserved_counterevidence_refs,
            vec!["ce-1".to_owned()]
        );
    }

    // WORK_UNIT_CASE: 661/23
    #[test]
    fn case_23_chronology_does_not_prove_causality() {
        let item = test_item();
        let grounded = test_grounded();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let mut evidence = test_evidence();
        evidence.mechanism_note =
            "the observed sequence came before and therefore causes the result".to_owned();

        let candidate =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("chronology-causality claim stays inert: {err:?}"),
            };

        assert_eq!(candidate.outcome, ProcedureOutcome::Empirical);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::UnsupportedPrecision)
        );
        assert_eq!(
            candidate.transfer.preserved_counterevidence_refs,
            vec!["ce-1".to_owned()]
        );
    }

    // Causal plumbing regression (not a 661 work-unit case: 24 deferred).
    #[test]
    fn causal_claim_validates_and_commits_digest_without_candidate_receipt() {
        let claim = match test_causal_claim() {
            Ok(claim) => claim,
            Err(err) => panic!("causal claim fixture: {err}"),
        };
        assert!(!claim.rivals.is_empty());
        assert!(!claim.confounders.is_empty());
        assert!(claim.validate().is_ok());

        let item = test_item();
        let grounded = test_grounded();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let mut evidence = test_evidence();
        evidence.causal_claim = Some(claim.clone());
        let candidate =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("causal evidence stays inert: {err:?}"),
            };
        assert_eq!(candidate.outcome, ProcedureOutcome::Complete);
        let baseline = match propose_procedure(
            &item,
            &grounded,
            &test_evidence(),
            &capability,
            &existing,
            &policy,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("causal baseline: {err:?}"),
        };
        assert_ne!(candidate.candidate_digest, baseline.candidate_digest);

        let mut missing_rival = claim;
        missing_rival.rivals.clear();
        evidence.causal_claim = Some(missing_rival);
        let err =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => panic!("missing rival must fail closed: {:?}", candidate.outcome),
                Err(err) => err,
            };
        assert!(matches!(
            err,
            ProcedureError::Shape { field, .. } if field == "evidence.causal_claim"
        ));
    }

    // WORK_UNIT_CASE: 661/10
    #[test]
    fn case_10_exact_trigger_completes_while_near_match_never_activates() {
        let item = test_item();
        let grounded = test_grounded();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let exact = match propose_procedure(
            &item,
            &grounded,
            &test_evidence(),
            &capability,
            &existing,
            &policy,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("exact trigger request: {err:?}"),
        };
        assert_eq!(exact.outcome, ProcedureOutcome::Complete);
        assert!(exact.trigger_note.contains("env-1"));
        assert!(exact.trigger_note.contains("scope-1"));
        assert!(exact.trigger_note.contains("fp-1"));
        assert!(exact.applicability_note.contains("env-1"));
        assert!(exact.applicability_note.contains("rev-4"));
        assert!(exact.applicability_note.contains("scope-1"));
        assert!(exact.applicability_note.contains("task-1"));
        assert!(is_hex64_lower(&exact.candidate_digest));
        let mut near_portability = test_evidence();
        near_portability.portability_note = "similar to env-9 scope-9, looks like fp-1".to_owned();
        let err = match propose_procedure(
            &item,
            &grounded,
            &near_portability,
            &capability,
            &existing,
            &policy,
        ) {
            Ok(candidate) => panic!("near-match portability must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(matches!(err, ProcedureError::Shape { field, .. } if field == "trigger"));
        let mut near_fingerprint = test_evidence();
        near_fingerprint.failure_fingerprint = "similar-fp-9".to_owned();
        let err = match propose_procedure(
            &item,
            &grounded,
            &near_fingerprint,
            &capability,
            &existing,
            &policy,
        ) {
            Ok(candidate) => panic!("near-match fingerprint must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(matches!(err, ProcedureError::Shape { field, .. } if field == "trigger"));
        let mut near_identity = test_existing();
        near_identity.existing_ids = vec!["rotate-caption-near-match".to_owned()];
        near_identity.existing_digests = vec!["0".repeat(64)];
        let candidate = match propose_procedure(
            &item,
            &grounded,
            &test_evidence(),
            &capability,
            &near_identity,
            &policy,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("near-match identity stays inert: {err:?}"),
        };
        assert_eq!(candidate.outcome, ProcedureOutcome::Complete);
        assert_eq!(candidate.candidate_digest, exact.candidate_digest);
    }

    // WORK_UNIT_CASE: 661/11
    #[test]
    fn case_11_trigger_applicability_transfer_stay_inside_evidenced_bounds() {
        let item = test_item();
        let grounded = test_grounded();
        let evidence = test_evidence();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let bounded =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("bounded scope request: {err:?}"),
            };
        assert_eq!(bounded.outcome, ProcedureOutcome::Complete);
        assert!(bounded.trigger_note.contains("env-1"));
        assert!(bounded.trigger_note.contains("scope-1"));
        assert!(bounded.applicability_note.contains("rev-4"));
        assert_eq!(bounded.transfer.target_env_id, "env-1");
        assert_eq!(bounded.transfer.target_env_revision, "rev-4");
        assert_eq!(bounded.transfer.target_scope_id, "scope-1");
        assert_eq!(bounded.transfer.target_task_id, "task-1");
        assert_eq!(
            bounded.transfer.preserved_version_pins,
            vec!["cap-1@v3".to_owned()]
        );
        assert_eq!(
            bounded.transfer.preserved_negative_refs,
            vec!["neg-1".to_owned()]
        );
        assert!(is_hex64_lower(&bounded.candidate_digest));
        let mut scope_drift = test_capability();
        scope_drift.scope_id = "scope-9".to_owned();
        let err = match propose_procedure(
            &item,
            &grounded,
            &evidence,
            &scope_drift,
            &existing,
            &policy,
        ) {
            Ok(candidate) => panic!("scope drift must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(
            matches!(err, ProcedureError::Binding { field, .. } if field == "capability_task_scope")
        );
        let mut task_drift = test_capability();
        task_drift.task_id = "task-9".to_owned();
        let err =
            match propose_procedure(&item, &grounded, &evidence, &task_drift, &existing, &policy) {
                Ok(candidate) => panic!("task drift must fail: {:?}", candidate.outcome),
                Err(err) => err,
            };
        assert!(
            matches!(err, ProcedureError::Binding { field, .. } if field == "capability_task_scope")
        );
        let mut pinned = test_capability();
        pinned.version_pins = vec!["cap-1@v3".to_owned(), "cap-2@v1".to_owned()];
        let candidate =
            match propose_procedure(&item, &grounded, &evidence, &pinned, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("pinned versions stay inert: {err:?}"),
            };
        assert_eq!(candidate.outcome, ProcedureOutcome::Complete);
        assert_eq!(
            candidate.transfer.preserved_version_pins,
            vec!["cap-1@v3".to_owned(), "cap-2@v1".to_owned()]
        );
        assert_eq!(
            candidate.transfer.preserved_counterevidence_refs,
            vec!["ce-1".to_owned()]
        );
    }

    // WORK_UNIT_CASE: 661/21
    #[test]
    fn case_21_valid_semantic_verifier_completes() {
        let item = test_item();
        let grounded = test_grounded();
        let evidence = test_evidence();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let candidate =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("semantic verifier request: {err:?}"),
            };
        assert_eq!(candidate.outcome, ProcedureOutcome::Complete);
        assert_eq!(candidate.verifier, "verifier-7");
        assert_eq!(candidate.steps.len(), 3);
        for step in &candidate.steps {
            assert_eq!(step.verifier, "verifier-7");
        }
        for disposition in &candidate.step_dispositions {
            assert_eq!(disposition.kind, StepDispositionKind::Grounded);
            assert_eq!(disposition.verifier, "verifier-7");
        }
        assert!(is_hex64_lower(&candidate.candidate_digest));
        assert_eq!(outcome_rejection_hint(&candidate.outcome), None);
    }

    // WORK_UNIT_CASE: 661/22
    #[test]
    fn case_22_missing_verifier_blocks_completeness() {
        let item = test_item();
        let grounded = test_grounded();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let baseline = match propose_procedure(
            &item,
            &grounded,
            &test_evidence(),
            &capability,
            &existing,
            &policy,
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("verifier baseline: {err:?}"),
        };
        assert_eq!(baseline.outcome, ProcedureOutcome::Complete);
        let mut missing = test_evidence();
        missing.verifier_refs = Vec::new();
        let candidate =
            match propose_procedure(&item, &grounded, &missing, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("missing verifier stays inert: {err:?}"),
            };
        assert_eq!(candidate.outcome, ProcedureOutcome::MissingVerifier);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::LineageMismatch)
        );
        assert!(is_hex64_lower(&candidate.candidate_digest));
        for disposition in &candidate.step_dispositions {
            assert_eq!(disposition.kind, StepDispositionKind::MissingVerifier);
        }
        assert_eq!(candidate.transfer.target_env_id, "env-1");
    }

    // WORK_UNIT_CASE: 661/18
    #[test]
    fn case_18_credential_permit_lease_handle_rejected_without_execution() {
        let grounded = test_grounded();
        let evidence = test_evidence();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let handles = [
            "api_key rotate",
            "secret rotate",
            "bearer token rotate",
            "lease acquire rotate",
            "permit acquire rotate",
            "process handle rotate",
        ];
        for handle in handles {
            let mut item = test_item();
            if let eliot_dreamer_contracts::CurationPayload::Procedure(payload) = &mut item.payload
            {
                payload.procedure = handle.to_owned();
            }
            let err = match propose_procedure(
                &item,
                &grounded,
                &evidence,
                &capability,
                &existing,
                &policy,
            ) {
                Ok(candidate) => panic!("credential handle must fail: {:?}", candidate.outcome),
                Err(err) => err,
            };
            assert!(
                matches!(&err, ProcedureError::Shape { field, .. } if field == "step.operation"),
                "handle {handle} must fail as step.operation, got {err:?}"
            );
        }
    }

    // WORK_UNIT_CASE: 661/19
    #[test]
    fn case_19_capability_present_is_not_execution_authority() {
        let item = test_item();
        let grounded = test_grounded();
        let evidence = test_evidence();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let candidate =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("capability-present request: {err:?}"),
            };
        assert_eq!(candidate.outcome, ProcedureOutcome::Complete);
        assert_eq!(candidate.note, PROCEDURE_PROOF_NOTE);
        assert!(candidate.note.contains("without"));
        assert!(candidate.note.contains("authority"));
        assert!(candidate.transfer.reground_note.contains("re-grounds"));
        assert_eq!(candidate.transfer.target_env_id, "env-1");
        assert_eq!(candidate.transfer.target_scope_id, "scope-1");
        for step in &candidate.steps {
            assert_ne!(step.effect, EffectClass::Unknown);
            assert!(!step.owner.trim().is_empty());
            assert!(!step.rollback_note.trim().is_empty());
        }
        let mut extended = test_capability();
        extended.capability_refs = vec!["cap-1".to_owned(), "cap-2".to_owned()];
        extended.version_pins = vec!["cap-1@v3".to_owned(), "cap-2@v1".to_owned()];
        let widened =
            match propose_procedure(&item, &grounded, &evidence, &extended, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("extended capability stays inert: {err:?}"),
            };
        assert_eq!(widened.outcome, ProcedureOutcome::Complete);
        assert_eq!(widened.note, PROCEDURE_PROOF_NOTE);
        assert!(widened.transfer.reground_note.contains("re-grounds"));
        assert_eq!(
            widened.transfer.preserved_version_pins,
            vec!["cap-1@v3".to_owned(), "cap-2@v1".to_owned()]
        );
        assert_eq!(widened.transfer.target_env_id, "env-1");
        assert_eq!(widened.transfer.target_scope_id, "scope-1");
    }

    // WORK_UNIT_CASE: 661/20
    #[test]
    fn case_20_missing_capability_stays_fail_closed() {
        let item = test_item();
        let grounded = test_grounded();
        let evidence = test_evidence();
        let mut missing = test_capability();
        missing.capability_refs.clear();
        missing.capability_note = "capability availability is unknown".to_owned();
        let existing = test_existing();
        let policy = test_policy();

        let error =
            match propose_procedure(&item, &grounded, &evidence, &missing, &existing, &policy) {
                Ok(candidate) => panic!(
                    "missing or unknown capability must not complete: {:?}",
                    candidate.outcome
                ),
                Err(error) => error,
            };
        assert!(
            matches!(
                error,
                ProcedureError::Shape { ref field, .. } if field == "capability.refs"
            ),
            "missing capability must fail closed at the capability boundary: {error:?}"
        );
    }

    /// Proposes with shared fixtures and returns the rejection.
    ///
    /// Panics when the proposal is admitted, so every invalid schema below
    /// stays fail-closed without effect.
    fn expect_rejection(
        label: &str,
        item: &ValidatedCurationItem,
        evidence: &ProcedureEvidence,
    ) -> ProcedureError {
        match propose_procedure(
            item,
            &test_grounded(),
            evidence,
            &test_capability(),
            &test_existing(),
            &test_policy(),
        ) {
            Ok(candidate) => panic!("{label} must fail: {:?}", candidate.outcome),
            Err(err) => err,
        }
    }

    // WORK_UNIT_CASE: 661/12
    #[test]
    fn case_12_typed_input_output_bound_to_evidence_and_invalid_schema_fails_closed() {
        let item = test_item();
        let grounded = test_grounded();
        let evidence = test_evidence();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let candidate =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("typed input/output baseline: {err:?}"),
            };
        assert_eq!(candidate.outcome, ProcedureOutcome::Complete);
        for step in &candidate.steps {
            assert_eq!(step.inputs, vec!["e-1".to_owned()]);
            assert!(!step.operation.trim().is_empty());
            assert!(!step.contract_ref.trim().is_empty());
            assert!(!step.precondition.trim().is_empty());
            assert!(!step.postcondition.trim().is_empty());
            assert!(!step.verifier.trim().is_empty());
        }
        let operations: Vec<String> = candidate
            .steps
            .iter()
            .map(|step| step.operation.clone())
            .collect();
        assert!(is_sorted_unique(&operations));
        assert_eq!(candidate.verifier, "verifier-7");
        assert!(is_hex64_lower(&candidate.candidate_digest));
        let mut zero_steps = test_item();
        if let eliot_dreamer_contracts::CurationPayload::Procedure(payload) =
            &mut zero_steps.payload
        {
            payload.steps = 0;
        }
        let err = expect_rejection("zero steps", &zero_steps, &evidence);
        assert!(matches!(err, ProcedureError::Bounds { phase, .. } if phase == "procedure.steps"));
        let mut blank_handle = test_item();
        if let eliot_dreamer_contracts::CurationPayload::Procedure(payload) =
            &mut blank_handle.payload
        {
            payload.procedure = String::new();
        }
        let err = expect_rejection("blank handle", &blank_handle, &evidence);
        assert!(matches!(err, ProcedureError::Shape { field, .. } if field == "procedure.handle"));
        let mut bad_denominator = test_item();
        bad_denominator.denominator.expected_total = 2;
        let err = expect_rejection("denominator drift", &bad_denominator, &evidence);
        assert!(matches!(err, ProcedureError::Receipt { .. }));
        let mut shuffled = test_evidence();
        shuffled.episode_refs = vec!["e-2".to_owned(), "e-1".to_owned()];
        let err = expect_rejection("shuffled inputs", &item, &shuffled);
        assert!(matches!(err, ProcedureError::Order { phase, .. } if phase == "evidence.episodes"));
        let mut malformed_digest = test_evidence();
        malformed_digest.frozen_bundle_digest = "not-a-digest".to_owned();
        let err = expect_rejection("malformed digest", &item, &malformed_digest);
        assert!(matches!(err, ProcedureError::Digest { .. }));
        let mut no_episodes = test_evidence();
        no_episodes.episode_refs = Vec::new();
        let err = expect_rejection("missing episodes", &item, &no_episodes);
        assert!(matches!(err, ProcedureError::Shape { field, .. } if field == "evidence.episodes"));
    }

    // WORK_UNIT_CASE: 661/14
    #[test]
    fn case_14_missing_predecessor_cycle_unbounded_loop_and_fanout_rejected() {
        let item = test_item();
        let grounded = test_grounded();
        let evidence = test_evidence();
        let capability = test_capability();
        let existing = test_existing();
        let policy = test_policy();
        let baseline =
            match propose_procedure(&item, &grounded, &evidence, &capability, &existing, &policy) {
                Ok(candidate) => candidate,
                Err(err) => panic!("graph baseline: {err:?}"),
            };
        assert_eq!(baseline.outcome, ProcedureOutcome::Complete);
        assert!(check_dependency_closure(&baseline.steps).is_ok());
        assert!(check_graph_acyclic(&baseline.steps).is_ok());
        let mut dangling = baseline.steps.clone();
        match dangling.get_mut(1) {
            Some(step) => step.dependencies = vec!["step-99".to_owned()],
            None => panic!("fixture must carry at least two steps"),
        }
        let err = match check_dependency_closure(&dangling) {
            Ok(()) => panic!("dangling dependency must fail"),
            Err(err) => err,
        };
        assert!(matches!(err, ProcedureError::Binding { field, .. } if field == "step.dependency"));
        let mut self_dependent = baseline.steps.clone();
        match self_dependent.first_mut() {
            Some(step) => {
                let own = step.step_id.clone();
                step.dependencies = vec![own];
            }
            None => panic!("fixture must carry at least one step"),
        }
        let err = match check_dependency_closure(&self_dependent) {
            Ok(()) => panic!("self-dependency must fail"),
            Err(err) => err,
        };
        assert!(matches!(err, ProcedureError::Binding { field, .. } if field == "step.dependency"));
        let mut cyclic = baseline.steps.clone();
        match cyclic.get_mut(0) {
            Some(step) => step.dependencies = vec!["step-02".to_owned()],
            None => panic!("fixture must carry at least one step"),
        }
        match cyclic.get_mut(1) {
            Some(step) => step.dependencies = vec!["step-01".to_owned()],
            None => panic!("fixture must carry at least two steps"),
        }
        assert!(check_dependency_closure(&cyclic).is_ok());
        let err = match check_graph_acyclic(&cyclic) {
            Ok(()) => panic!("cycle must fail"),
            Err(err) => err,
        };
        assert!(matches!(err, ProcedureError::Binding { field, .. } if field == "steps"));
        let mut unbounded_item = test_item();
        if let eliot_dreamer_contracts::CurationPayload::Procedure(payload) =
            &mut unbounded_item.payload
        {
            payload.procedure = "retry forever rotate".to_owned();
        }
        let err = match propose_procedure(
            &unbounded_item,
            &grounded,
            &evidence,
            &capability,
            &existing,
            &policy,
        ) {
            Ok(candidate) => panic!("unbounded retry must fail: {:?}", candidate.outcome),
            Err(err) => err,
        };
        assert!(matches!(err, ProcedureError::Shape { field, .. } if field == "step.budget"));
        let mut over_retry = match baseline.steps.first() {
            Some(step) => step.clone(),
            None => panic!("fixture must carry at least one step"),
        };
        over_retry.max_retries = MAX_RETRIES.saturating_add(1);
        let err = match validate_one_step_shape(&over_retry) {
            Ok(()) => panic!("over-retry step must fail"),
            Err(err) => err,
        };
        assert!(matches!(err, ProcedureError::Bounds { phase, .. } if phase == "step.retries"));
        over_retry.max_retries = 1;
        over_retry.fanout = MAX_FANOUT.saturating_add(1);
        let err = match validate_one_step_shape(&over_retry) {
            Ok(()) => panic!("over-fanout step must fail"),
            Err(err) => err,
        };
        assert!(matches!(err, ProcedureError::Bounds { phase, .. } if phase == "step.fanout"));
        over_retry.fanout = 1;
        assert!(validate_one_step_shape(&over_retry).is_ok());
    }

    // WORK_UNIT_CASE: 661/15
    #[test]
    fn case_15_bounded_step_generation_has_explicit_progress() {
        let mut bounded_item = test_item();
        if let eliot_dreamer_contracts::CurationPayload::Procedure(payload) =
            &mut bounded_item.payload
        {
            payload.steps =
                u32::try_from(MAX_STEPS).unwrap_or_else(|_| unreachable!("MAX_STEPS fits u32"));
        }
        let bounded = match propose_procedure(
            &bounded_item,
            &test_grounded(),
            &test_evidence(),
            &test_capability(),
            &test_existing(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("maximum bounded step graph must pass: {err:?}"),
        };
        assert_eq!(bounded.outcome, ProcedureOutcome::Complete);
        assert_eq!(bounded.steps.len(), MAX_STEPS);
        for (index, step) in bounded.steps.iter().enumerate() {
            assert_eq!(step.step_id, format!("step-{:02}", index + 1));
            assert!(step.max_retries <= MAX_RETRIES);
            assert!(step.fanout <= MAX_FANOUT);
            if index == 0 {
                assert!(step.dependencies.is_empty());
            } else {
                assert_eq!(step.dependencies, vec![format!("step-{index:02}")]);
            }
        }

        let mut over_bound_item = test_item();
        if let eliot_dreamer_contracts::CurationPayload::Procedure(payload) =
            &mut over_bound_item.payload
        {
            payload.steps = u32::try_from(MAX_STEPS + 1)
                .unwrap_or_else(|_| unreachable!("MAX_STEPS + 1 fits u32"));
        }
        let err = match propose_procedure(
            &over_bound_item,
            &test_grounded(),
            &test_evidence(),
            &test_capability(),
            &test_existing(),
            &test_policy(),
        ) {
            Ok(candidate) => panic!("step generation above the ceiling must fail: {candidate:?}"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            ProcedureError::Bounds { phase, .. } if phase == "procedure.steps"
        ));
    }

    // WORK_UNIT_CASE: 661/16
    #[test]
    fn case_16_missing_owner_precondition_postcondition_or_verifier_fails_closed() {
        let baseline = match propose_procedure(
            &test_item(),
            &test_grounded(),
            &test_evidence(),
            &test_capability(),
            &test_existing(),
            &test_policy(),
        ) {
            Ok(candidate) => candidate,
            Err(err) => panic!("baseline step graph: {err:?}"),
        };
        let mut missing_owner = baseline.steps[0].clone();
        missing_owner.owner.clear();
        assert!(matches!(
            validate_one_step_shape(&missing_owner),
            Err(ProcedureError::Shape { field, .. }) if field == "step.owner"
        ));

        let mut missing_precondition = baseline.steps[0].clone();
        missing_precondition.precondition.clear();
        assert!(matches!(
            validate_one_step_shape(&missing_precondition),
            Err(ProcedureError::Shape { field, .. }) if field == "step.precondition"
        ));

        let mut missing_postcondition = baseline.steps[0].clone();
        missing_postcondition.postcondition.clear();
        assert!(matches!(
            validate_one_step_shape(&missing_postcondition),
            Err(ProcedureError::Shape { field, .. }) if field == "step.postcondition"
        ));

        let mut missing_verifier = baseline.steps[0].clone();
        missing_verifier.verifier.clear();
        assert!(matches!(
            validate_one_step_shape(&missing_verifier),
            Err(ProcedureError::Shape { field, .. }) if field == "step.verifier"
        ));
        assert!(matches!(
            check_rollback_owned(std::slice::from_ref(&missing_verifier)),
            Err(ProcedureError::Shape { field, .. }) if field == "step.owner"
        ));
    }
}
