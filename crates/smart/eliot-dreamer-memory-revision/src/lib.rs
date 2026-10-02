//! Advisory negative-memory extinction candidates (#223, order 79).
//!
//! [`propose`] consumes one owner-neutral [`FailureObservation`], its
//! [`MemoryRevisionEvidence`] refs, the admitted task/safety projections, and
//! the frozen self-query/accepted-source refs — all by value, all already
//! admitted or projected by their owners — and emits one
//! [`NegativeMemoryExtinctionCandidate`]. The candidate narrows only advisory
//! activation/influence fields and preserves every history field; without
//! adequate adjudication only reversible suppress/quarantine/archive is
//! proposed, and a recurring failure with the same causal hypothesis yields
//! Mechanism Review rather than another equivalent retry.
//!
//! The exact deterministic trigger identity a candidate bears on travels as
//! its own member, as a typed and observation/fence-bound [`ExactTrigger`]
//! beside the composite failure fingerprint, because the governing donor states
//! the two apart: "Exact deterministic trigger can block/requires probe within
//! matching scope. Semantic similarity only warns."
//! (`docs/architecture/I12-19-negative-memory.md:3`, restated by
//! `crates/smart/eliot-dreamer-memory-revision/module.toml:104` `omission_semantics`
//! and its gate `W9-MR-EXACT-TRIGGER-VERSUS-SIMILARITY` at line 159). One
//! opaque fingerprint string carries neither, so it could only ever prove
//! shape.
//!
//! The closed [`ExactTrigger`] shape is derived from what this crate's own
//! measured producer already carries — `FailureObservation::trigger` and
//! `FailureObservation::state_fence`, bound to the observation handle they were
//! read under — and adds no vocabulary. The candidate's existing
//! [`NegativeMemoryExtinctionCandidate::validate`] is the single place the shape
//! is enforced, so a composite near-match can neither be promoted into the
//! exact-trigger slot nor satisfy an exact-trigger requirement by omission;
//! [`NegativeMemoryExtinctionCandidate::recheck_exact_trigger`] then decides the
//! requirement itself, on the recorded identity compared with the governing
//! exact-trigger identities.
//!
//! That construction-time binding is not re-derived: `validate` takes no owner
//! input, so it compares the recorded trigger only against members of the same
//! record, and the recorded identity is re-decided against the Governor owner's
//! governing set out of band. Each side states this limit where its own check
//! is — in [`ExactTrigger`], in
//! [`NegativeMemoryExtinctionCandidate::validate`], and in `module.toml`'s
//! `superseded_field_family_owners` — rather than claiming a provenance binding
//! it does not enforce.
//!
//! There are no parallel observation, evidence, query, or projection types
//! here: failure/revision shapes stay with `eliot-observation-contracts`,
//! self-query/accepted-source shapes stay with `eliot-dreamer-contracts`,
//! and task/safety projections stay with `eliot-context-contracts`. That
//! boundary is also what decided the candidate's own field family: a field
//! contract that named twenty-one members of this candidate, nineteen of which
//! were in fact the `FailureFingerprint` field list (`docs/architecture/I12-19-negative-memory.md:6-17`)
//! or the `MemoryRevisionEvidence` field list
//! (`docs/architecture/I12-21-memory-ecology-residual-experience-and-transfer.md:100-110`)
//! and one the `MemoryLifecycleEvaluation` list (same file `:117-128`),
//! is the stale side, because `I12-21:97-98` requires exactly that split —
//! "not a second memory system". The corrected family is therefore the twelve
//! members declared below, each already bound by [`finish`] to what
//! [`RevisionIntake`] holds, and it is recorded with the sentence it was
//! decided by in this crate's own `module.toml` row `field_family_authority`
//! and held member by member in `src/field_family_tests.rs`.
//!
//! The bound
//! freeze revision is embedded at compile time and verified before any intake
//! is read, so an absent or drifted schema freeze produces no candidate. This
//! crate performs no compilation, admission, briefing, or model work, owns no
//! reactive path, and promotes nothing: output is candidate-only for the
//! Governor transition path.

#![forbid(unsafe_code)]

#[cfg(test)]
mod exact_trigger_gate_tests;
#[cfg(test)]
mod field_family_tests;

use std::collections::BTreeSet;

use eliot_context_contracts::{ContextError, SafetyProjection, TaskProjection};
use eliot_contracts::{ArtifactId, ContractVersion, StateFence, canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::self_query::{
    AcceptedSourceProjection, SelfQueryContractError, SelfQueryInput,
};
use eliot_observation_contracts::{
    FailureObservation, FailureOmission, MemoryRevisionEvidence, ObservationError,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Freeze identity this consumer builds against.
///
/// See `crates/smart/cognitive-rev12-contract-schema-freeze.toml`.
pub const FREEZE_ID: &str = "cognitive-rev12-contract-schema-freeze-2026-09-22-r13";
/// Contract version carried by every candidate emitted here.
pub const CANDIDATE_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Maximum revision-evidence refs carried by one intake.
pub const MAX_REVISION_EVIDENCE: usize = 32;
/// Maximum closure members enumerated by one denominator.
pub const MAX_CLOSURE_MEMBERS: usize = 1024;
/// Maximum missing-evidence entries named by one candidate.
pub const MAX_MISSING_ENTRIES: usize = 256;
/// Maximum characters accepted for one identity echo.
pub const MAX_ID_CHARS: usize = 1024;

/// Revision failure: intake contract violations fail closed with a reason.
///
/// Evidence insufficiency is not an error: it yields an inconclusive or
/// unsupported candidate naming the exact missing evidence.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RevisionError {
    /// An owner input rejected its own shape.
    #[error("dreamer memory revision: observation contract: {0}")]
    Observation(#[from] ObservationError),
    /// A task/safety projection rejected its own shape.
    #[error("dreamer memory revision: context contract: {0}")]
    Context(#[from] ContextError),
    /// The self-query input or accepted-source projection rejected its shape.
    #[error("dreamer memory revision: self-query contract: {0}")]
    SelfQuery(#[from] SelfQueryContractError),
    /// A scope identity does not match its governing scope.
    #[error("dreamer memory revision: scope mismatch at {field}")]
    ScopeMismatch { field: &'static str },
    /// A fence is incompatible with its governing fence.
    #[error("dreamer memory revision: fence mismatch at {field}")]
    FenceMismatch { field: &'static str },
    /// A checked digest or pinned identity does not match what it claims.
    #[error("dreamer memory revision: digest mismatch at {field}")]
    DigestMismatch { field: &'static str },
    /// A cited source triple is stale or uncited.
    #[error("dreamer memory revision: stale citation at {field}")]
    StaleCitation { field: &'static str },
    /// A bound on intake size is exceeded.
    #[error("dreamer memory revision: out of bounds: {field}")]
    Bounds { field: &'static str },
    /// The candidate is not canonically encodable.
    #[error("dreamer memory revision: candidate is not digestible")]
    NotDigestible,
}

/// Reversible advisory narrowing only.
///
/// Suppress, quarantine, and archive are the A14.4 reversible operators. No
/// purge field exists by design: irreversible extinction is never emitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryNarrowing {
    /// Propose suppressing advisory activation.
    pub suppress_activation: bool,
    /// Propose quarantine (reserved for Governor adjudication).
    pub quarantine: bool,
    /// Propose archive (reserved for Governor adjudication).
    pub archive: bool,
}

/// Candidate disposition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CandidateDisposition {
    /// Narrow advisory activation/influence after new evidence.
    AdvisoryNarrow,
    /// Recurrence with the same hypothesis: Governor Mechanism Review.
    MechanismReview,
}

/// Candidate terminal state. No state implies support, truth, or promotion.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CandidateState {
    Complete,
    Inconclusive,
    Unsupported,
}

/// Independently recheckable closure denominator.
///
/// `enumerated` is the sorted union of the observation journal refs and the
/// revision evidence refs at the named `fence`; `exclusions` carries the
/// closed-class omissions verbatim. Any third party holding the same refs at
/// the same fence recomputes the identical `recheck_digest`: that is the
/// recheck rule, not a second enumeration capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClosureDenominator {
    /// Named fence the closure was enumerated at.
    pub fence: StateFence,
    /// Sorted closure member handles.
    pub enumerated: Vec<ArtifactId>,
    /// Closed-class exclusions carried verbatim.
    pub exclusions: Vec<FailureOmission>,
    /// Frozen digest over the fence, members, and exclusions.
    pub recheck_digest: String,
    /// True when the closure is nonempty.
    pub complete: bool,
}

impl ClosureDenominator {
    /// Compute the frozen recheck digest.
    pub fn compute_digest(&self) -> Result<String, RevisionError> {
        if self.enumerated.len() > MAX_CLOSURE_MEMBERS {
            return Err(RevisionError::Bounds {
                field: "denominator.enumerated",
            });
        }
        canonical_json_bytes(&(&self.fence, &self.enumerated, &self.exclusions))
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| RevisionError::NotDigestible)
    }
}

/// The exact deterministic trigger a candidate bears on, bound to the
/// observation and the fence within which it matched.
///
/// Every member is an echo of what this crate's own measured producer already
/// carries, and nothing else: [`FailureObservation::trigger`] for the matched
/// identity and [`FailureObservation::state_fence`] for the fence it was read
/// under, plus the observation handle those two were read under. No composite
/// fingerprint content belongs in this shape. The governing donor states the two
/// apart — "Exact deterministic trigger can block/requires probe within matching
/// scope. Semantic similarity only warns."
/// (`docs/architecture/I12-19-negative-memory.md:3`), and `module.toml`'s `fence`
/// row names the same binding: "Task scope plus `StateFence` revisions; exact
/// deterministic trigger scope for block/probe."
///
/// The matching scope and task are not restated here as untyped text. They live
/// on the observation itself as its own `ObservationScope`
/// (`FailureObservation::scope`), and the binding is a recorded chain rather
/// than a copied value: [`Self::observation_ref`] names the exact observation
/// whose scope `validate_intake` proved equal to both admitted projections'
/// scope before any classification, and [`Self::state_fence`] names the fence
/// that observation was read under. Restating `WorkScopeId` as a `String` here
/// would create the string facade of an existing typed owner
/// (`crates/foundation/eliot-contracts/AGENTS.md`: "Reuse an existing owner and
/// never create a third same-meaning type, package, wrapper, or string
/// facade"), and restating it as the typed owner would add a dependency edge on
/// `eliot-receipts` that this package does not hold.
///
/// These three members are echoes of an owner record the candidate does not
/// carry, so their agreement with [`FailureObservation::observation_id`],
/// [`FailureObservation::trigger`] and [`FailureObservation::state_fence`] is
/// established once, where that record is reachable -- in the `ExactTrigger`
/// literal in `finish` at src/lib.rs:957 -- and is never re-read afterwards,
/// because `validate` is given no owner input. What
/// `validate` re-derives is internal coherence only: [`Self::observation_ref`]
/// against the candidate's own `observation_ref`, and [`Self::state_fence`]
/// against `denominator.fence`. The one member a downstream holder re-decides
/// against a value this record does not carry is [`ExactTrigger::identity`],
/// through [`NegativeMemoryExtinctionCandidate::recheck_exact_trigger`].
///
/// This type carries no validator of its own:
/// [`NegativeMemoryExtinctionCandidate::validate`] is the single place the
/// closed shape is enforced, exactly as it already recomputes
/// [`ClosureDenominator`]'s digest, so no second check can exist beside it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExactTrigger {
    /// Verbatim exact deterministic trigger identity, compared verbatim
    /// against the governing exact trigger identities the Governor owner
    /// supplies and never against [`NegativeMemoryExtinctionCandidate::fingerprint`].
    pub identity: String,
    /// Observation handle this exact trigger fired under.
    pub observation_ref: ArtifactId,
    /// Fence the exact trigger was read under, which stays compatible with the
    /// closure fence recorded on the candidate.
    pub state_fence: StateFence,
}

/// One advisory negative-memory extinction candidate.
///
/// History fields are echoed verbatim from the observation; only
/// [`AdvisoryNarrowing`] narrows, and only reversibly. Every `Complete`
/// state carries the exact independently recheckable [`ClosureDenominator`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryExtinctionCandidate {
    /// Exact contract version; must equal [`CANDIDATE_CONTRACT_VERSION`].
    pub contract_version: ContractVersion,
    /// Stable candidate identity.
    pub candidate_id: ArtifactId,
    /// Observation handle this candidate bears on.
    pub observation_ref: ArtifactId,
    /// Exact deterministic trigger this candidate bears on: the typed,
    /// observation/fence-bound [`ExactTrigger`] built from
    /// [`FailureObservation::trigger`] and [`FailureObservation::state_fence`].
    ///
    /// This is the only member an exact-trigger requirement may be decided on,
    /// and it is a separate member from `fingerprint` precisely so a composite
    /// fingerprint cannot stand in for it: the governing donor
    /// (`docs/architecture/I12-19-negative-memory.md:3`) states "Exact
    /// deterministic trigger can block/requires probe within matching scope.
    /// Semantic similarity only warns." See
    /// [`NegativeMemoryExtinctionCandidate::recheck_exact_trigger`].
    ///
    /// No stored candidate exists to migrate: this cell declares
    /// `owned_mutable_state = []` and `state_class = STATELESS`
    /// (`module.toml:22` and `:196`), so the required member is read
    /// only from a candidate this crate just proposed. The only construction
    /// site is [`finish`].
    pub trigger: ExactTrigger,
    /// Composite failure fingerprint echoed verbatim. This is the semantic
    /// content of the owner failure memory — the trigger, failed-action and
    /// outcome identity as the owner admitted them — and never the exact
    /// trigger: a similarity of this value only warns. Decide exact-trigger
    /// requirements on `trigger`, and note that `validate` refuses this exact
    /// value in `trigger.identity`, so a near match can never be promoted into
    /// the exact-trigger slot.
    pub fingerprint: String,
    /// Posed self-query digest this candidate was assessed under.
    pub query_digest: String,
    /// Reversible advisory narrowing.
    pub narrowing: AdvisoryNarrowing,
    /// Candidate disposition.
    pub disposition: CandidateDisposition,
    /// Closure denominator with the recheck rule.
    pub denominator: ClosureDenominator,
    /// Terminal state.
    pub state: CandidateState,
    /// Exact missing evidence; empty when `Complete`.
    pub missing: Vec<String>,
    /// Frozen digest over the candidate shape, excluding this field.
    pub digest: String,
}

impl NegativeMemoryExtinctionCandidate {
    /// Compute the frozen digest over the candidate shape.
    pub fn compute_digest(&self) -> Result<String, RevisionError> {
        canonical_json_bytes(&(
            &self.contract_version,
            &self.candidate_id,
            &self.observation_ref,
            &self.trigger,
            &self.fingerprint,
            &self.query_digest,
            &self.narrowing,
            &self.disposition,
            &self.denominator,
            &self.state,
            &self.missing,
        ))
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| RevisionError::NotDigestible)
    }

    /// Validate version, bounds, the closed exact-trigger shape,
    /// state/denominator coherence, and the digest.
    ///
    /// The exact-trigger block below is the only enforcement of the
    /// exact/near-match distinction this crate performs on shape: the recorded
    /// trigger must be a bounded identity, must not be the composite
    /// [`Self::fingerprint`], must name the observation this candidate bears on,
    /// and must stay fence-compatible with the closure denominator. The matching
    /// scope and task are the named observation's own scope, which
    /// `validate_intake` proved equal to both admitted projections' scope before
    /// anything was classified. [`Self::recheck_exact_trigger`] then decides the
    /// exact-trigger requirement itself against the governing exact-trigger
    /// identities; a candidate refused by either check is not a candidate.
    ///
    /// Every comparison in the exact-trigger block is between two members this
    /// same record carries, because `validate` takes no owner input: nothing in
    /// its signature reaches a `FailureObservation`, a `TaskProjection` or a
    /// `SafetyProjection`. What is therefore proven here about
    /// `trigger.identity` is that it is bounded and control-character-free
    /// (src/lib.rs:392), that it is not the composite `fingerprint`
    /// (src/lib.rs:406), and that it is committed to by `digest`
    /// (src/lib.rs:462) -- not that it equals
    /// [`FailureObservation::trigger`]. That equality is established only where
    /// the owner record is reachable: `validate_intake` revalidates the
    /// observation at src/lib.rs:732, and the `ExactTrigger` literal in `finish`
    /// copies `observation.trigger` and `observation.state_fence` verbatim at
    /// src/lib.rs:957. `validate` never re-reads either, so a writer who
    /// rewrites `trigger.identity`, or `trigger.state_fence` together with
    /// `denominator.fence`, and recomputes
    /// `denominator.recheck_digest` and `digest` produces a record this function
    /// accepts. That residual is reported rather than papered over: closing it
    /// here would need either an owner value this function is not given or a
    /// keyed mechanism, and this crate holds no keyed primitive to name.
    /// The identity is instead re-decided out of band, against a value the
    /// record does not carry, by [`Self::recheck_exact_trigger`] (src/lib.rs:505),
    /// which compares it verbatim with the Governor owner's governing set and
    /// which `finish` calls on every candidate it emits (src/lib.rs:984).
    pub fn validate(&self) -> Result<(), RevisionError> {
        if self.contract_version != CANDIDATE_CONTRACT_VERSION {
            return Err(RevisionError::DigestMismatch {
                field: "candidate.contract_version",
            });
        }
        if self.missing.len() > MAX_MISSING_ENTRIES {
            return Err(RevisionError::Bounds {
                field: "candidate.missing",
            });
        }
        // The exact trigger is an identity, checked exactly like
        // `intake.candidate_id`, and never folded into `fingerprint`.
        if self.trigger.identity.trim().is_empty()
            || self.trigger.identity.chars().any(char::is_control)
            || self.trigger.identity.chars().count() > MAX_ID_CHARS
        {
            return Err(RevisionError::DigestMismatch {
                field: "candidate.trigger.identity",
            });
        }
        // A composite fingerprint is the semantic near-match description, so it
        // can never occupy the exact-trigger slot: that is the promotion a
        // "valid near match" would need, and the donor separates them
        // ("Exact deterministic trigger can block/requires probe within matching
        // scope. Semantic similarity only warns.",
        // `docs/architecture/I12-19-negative-memory.md:3`).
        if self.trigger.identity == self.fingerprint {
            return Err(RevisionError::ScopeMismatch {
                field: "candidate.trigger.identity",
            });
        }
        if self.trigger.observation_ref != self.observation_ref {
            return Err(RevisionError::ScopeMismatch {
                field: "candidate.trigger.observation_ref",
            });
        }
        // The counterpart compared here is `self.denominator.fence`, the closure
        // fence this same record carries -- NOT the governing task fence. That
        // task fence is reachable only inside `finish`: it lives on
        // `RevisionIntake::task` (src/lib.rs:680) and is copied into the
        // denominator at src/lib.rs:944, so no member of `validate`'s `&self`
        // is the task fence and none is re-read here. `validate_intake` applies
        // the same rule one step earlier, comparing `observation.state_fence`
        // against that same `intake.task.binding.state_fence` at src/lib.rs:756,
        // so the two transported members carry that comparison into the record.
        // `StateFence::is_compatible_with`
        // (crates/foundation/eliot-contracts/src/lib.rs:981-989) requires exact
        // `EpochId` lineage-and-sequence equality and equal
        // `resource_generation`, so no foreign authority epoch or resource
        // generation survives; a rewriter who restates BOTH members consistently
        // still gets a valid record, which `validate`'s doc comment records as
        // an open residual instead of claiming this check closed it.
        if !self
            .trigger
            .state_fence
            .is_compatible_with(&self.denominator.fence)
        {
            return Err(RevisionError::FenceMismatch {
                field: "candidate.trigger.state_fence",
            });
        }
        if self.denominator.recheck_digest != self.denominator.compute_digest()? {
            return Err(RevisionError::DigestMismatch {
                field: "candidate.denominator.recheck_digest",
            });
        }
        match self.state {
            CandidateState::Complete => {
                if !self.missing.is_empty() || !self.denominator.complete {
                    return Err(RevisionError::DigestMismatch {
                        field: "candidate.complete_denominator",
                    });
                }
            }
            CandidateState::Inconclusive | CandidateState::Unsupported => {
                if self.missing.is_empty() {
                    return Err(RevisionError::DigestMismatch {
                        field: "candidate.missing",
                    });
                }
            }
        }
        if self.digest != self.compute_digest()? {
            return Err(RevisionError::DigestMismatch {
                field: "candidate.digest",
            });
        }
        Ok(())
    }

    /// Recheck the exact-trigger requirement against the exact trigger
    /// identities that govern it, never against the fingerprint's shape.
    ///
    /// `governing_triggers` is the verbatim exact-trigger set the Governor owner
    /// supplies: `SafetyProjection::negative_memory_triggers` in
    /// `eliot-context-contracts`, whose own owner states the entries "are copied
    /// verbatim; this contract never invents trigger prose", and which the bound
    /// freeze's `denominator_note` records as exact trigger identities copied
    /// verbatim from the Governor owner
    /// (`crates/smart/cognitive-rev12-contract-schema-freeze.toml:455`).
    /// The slice is passed in rather than the projection so a holder can recheck
    /// with the governing set it actually holds.
    ///
    /// The requirement is decided on exactly one comparison: verbatim equality
    /// of [`ExactTrigger::identity`] with a member of `governing_triggers`. Neither the
    /// presence nor the shape nor any containment or similarity of
    /// [`Self::fingerprint`] is consulted, because the governing donor
    /// (`docs/architecture/I12-19-negative-memory.md:3`) states "Exact
    /// deterministic trigger can block/requires probe within matching scope.
    /// Semantic similarity only warns."
    ///
    /// `classify` proposes [`CandidateState::Unsupported`] only when an exact
    /// trigger fired, so both directions are refused here: a candidate recorded
    /// `Unsupported` whose exact trigger is not in the governing set (a
    /// near-match over otherwise valid content), and a candidate that is not
    /// `Unsupported` while an exact trigger is in that set. The refusal is the
    /// existing typed [`RevisionError::ScopeMismatch`] naming the exact field —
    /// never a boolean, never a message string, and no tenth
    /// [`RevisionError`] variant that `bins/eliotd`'s exhaustive
    /// `From<RevisionError>` match would break.
    ///
    /// [`propose`] calls this once over the candidate it emits. A downstream
    /// holder of the candidate calls it again with its own governing set, which
    /// is what lets the consumer re-decide the exact-trigger requirement with
    /// the operation instead of with the shape of one opaque string.
    pub fn recheck_exact_trigger(
        &self,
        governing_triggers: &[String],
    ) -> Result<(), RevisionError> {
        let exact_trigger_fired = governing_triggers
            .iter()
            .any(|identity| identity == &self.trigger.identity);
        if exact_trigger_fired != (self.state == CandidateState::Unsupported) {
            return Err(RevisionError::ScopeMismatch {
                field: "candidate.exact_trigger",
            });
        }
        Ok(())
    }
}

// The freeze-binding block below sits after the serde-carrying types so the
// generated protected-wire inventory in
// `crates/foundation/eliot-contracts/tests/data/shipped_serde_boundaries.toml`
// records a small uniform line offset for those declarations instead of one
// larger than the whole block. Either way that inventory is a generated
// snapshot whose accepted sync belongs to the #929 owner, not to this crate.

/// Exact bytes of the Wave 1 static field contract freeze this consumer is
/// bound to, read at compile time from its owning path.
///
/// `include_bytes!` is the fail-closed choice: a missing, moved, or renamed
/// freeze is a compile error in this crate, so no build of this consumer can
/// ship against an absent schema-freeze input. A runtime path lookup was
/// rejected because it would depend on the process working directory and on
/// the repository layout surviving packaging, which is a hidden failure source
/// rather than a closed one. The accepted cost is that the freeze bytes are
/// embedded in every consumer binary; the same trade is already taken for the
/// typed WIT and toolchain contracts in `eliot-context-compiler-wasm`, which
/// read their owning artifacts the same way so they cannot drift by
/// hand-copying.
pub const FREEZE_BYTES: &[u8] = include_bytes!("../../cognitive-rev12-contract-schema-freeze.toml");

/// Lowercase sha256 over the exact [`FREEZE_BYTES`].
///
/// Recorded out of band in the `CC-W9-REV12-HANDOFF` handoff row of
/// `crates/smart/cognitive-contract-challenges.toml` because a digest of a
/// file's own bytes cannot live inside those bytes. Only the digest is pinned
/// here: the freeze's own `[readback].rule` states the rule as sha256 over the
/// exact file bytes, so pinning the byte length as well would invent a second
/// rule the freeze does not state. The length is recorded next to the digest
/// in the handoff row and checked by `scripts/read_freeze_digest.py`.
pub const REQUIRED_FREEZE_DIGEST: &str =
    "891e1e46ebfa9778ea61a49890f13a603ce251c5d7ce6185f96398ed97020456";

/// Typed freeze-binding divergence.
///
/// Distinct from [`RevisionError::DigestMismatch`]: that variant reports drift
/// in a candidate's own digest, while these report that this crate is not bound
/// to the freeze revision it claims. Both sides are named so the divergence is
/// diagnosable without opening the freeze.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FreezeVerificationError {
    /// The embedded freeze declares a different `freeze_id` than this crate pins.
    #[error(
        "dreamer memory revision: freeze id divergence: crate pins {expected}, freeze declares {observed}"
    )]
    FreezeIdDivergence {
        /// `freeze_id` this crate pins.
        expected: String,
        /// `freeze_id` the embedded freeze declares.
        observed: String,
    },
    /// The embedded freeze bytes do not hash to [`REQUIRED_FREEZE_DIGEST`].
    #[error(
        "dreamer memory revision: freeze digest divergence: pinned {expected}, observed {observed}"
    )]
    FreezeDigestDivergence {
        /// Digest this crate pins.
        expected: String,
        /// Digest computed over the embedded freeze bytes.
        observed: String,
    },
    /// The embedded freeze does not declare exactly one well-formed column-0
    /// `freeze_id` line; the count of matching lines is reported.
    #[error(
        "dreamer memory revision: freeze declares {observed} column-0 freeze_id lines, exactly one is required"
    )]
    FreezeIdUnreadable {
        /// Number of matching `freeze_id` lines found.
        observed: usize,
    },
    /// The embedded freeze bytes are not valid UTF-8, so no `freeze_id` line
    /// can be read from them at all.
    #[error("dreamer memory revision: freeze bytes are not valid UTF-8; no freeze_id is readable")]
    FreezeBytesNotUtf8,
}

/// Read the single column-0 `freeze_id` the embedded freeze declares.
///
/// The column-0 anchor is load-bearing: it is what keeps the freeze's own
/// `supersedes_freeze_id` line from being read as the current identity. An
/// unterminated, repeated, or absent declaration is reported as a count, never
/// as a best-effort value.
fn declared_freeze_id(source: &str) -> Result<&str, FreezeVerificationError> {
    const PREFIX: &str = "freeze_id = \"";
    let mut declared: Option<&str> = None;
    let mut lines = 0usize;
    for line in source.lines() {
        let Some(rest) = line.strip_prefix(PREFIX) else {
            continue;
        };
        lines += 1;
        declared = rest.strip_suffix('"');
    }
    match (lines, declared) {
        (1, Some(value)) => Ok(value),
        (lines, _) => Err(FreezeVerificationError::FreezeIdUnreadable { observed: lines }),
    }
}

/// Verify that this crate is bound to the exact freeze revision it pins.
///
/// Compares the `freeze_id` declared by the embedded [`FREEZE_BYTES`] against
/// [`FREEZE_ID`] and the sha256 of those exact bytes against
/// [`REQUIRED_FREEZE_DIGEST`]. A freeze that is absent cannot reach this
/// function: [`FREEZE_BYTES`] would not have compiled. Divergence is always a
/// typed [`FreezeVerificationError`], never a boolean and never a best-effort
/// identity.
pub fn verify_freeze_binding() -> Result<(), FreezeVerificationError> {
    let source = std::str::from_utf8(FREEZE_BYTES)
        .map_err(|_| FreezeVerificationError::FreezeBytesNotUtf8)?;
    let observed_id = declared_freeze_id(source)?;
    if observed_id != FREEZE_ID {
        return Err(FreezeVerificationError::FreezeIdDivergence {
            expected: FREEZE_ID.to_owned(),
            observed: observed_id.to_owned(),
        });
    }
    let observed_digest = sha256_hex(FREEZE_BYTES);
    if observed_digest != REQUIRED_FREEZE_DIGEST {
        return Err(FreezeVerificationError::FreezeDigestDivergence {
            expected: REQUIRED_FREEZE_DIGEST.to_owned(),
            observed: observed_digest,
        });
    }
    Ok(())
}

impl From<FreezeVerificationError> for RevisionError {
    /// Collapses the typed divergence onto the existing
    /// [`RevisionError::DigestMismatch`] field discriminator instead of adding
    /// a tenth [`RevisionError`] variant, because
    /// `impl From<RevisionError> for ExperienceDriverError` in
    /// `bins/eliotd/src/experience_runtime.rs` matches all nine current
    /// variants exhaustively with no wildcard arm: a tenth variant would break
    /// the `eliotd` build outright rather than fail closed. The cost is that
    /// [`propose`] loses the expected and observed values at this one
    /// boundary. A caller that needs them calls [`verify_freeze_binding`]
    /// directly and gets the typed [`FreezeVerificationError`]; adding a
    /// `RevisionError` arm on the `eliotd` side is the follow-up that would
    /// let the typed values cross.
    fn from(error: FreezeVerificationError) -> Self {
        let field = match error {
            FreezeVerificationError::FreezeIdDivergence { .. } => "freeze.freeze_id",
            FreezeVerificationError::FreezeDigestDivergence { .. } => "freeze.digest",
            FreezeVerificationError::FreezeIdUnreadable { .. } => "freeze.freeze_id.declarations",
            FreezeVerificationError::FreezeBytesNotUtf8 => "freeze.bytes",
        };
        RevisionError::DigestMismatch { field }
    }
}

/// Complete validated intake for one extinction assessment.
pub struct RevisionIntake<'a> {
    /// Owner-neutral failure observation, by value.
    pub observation: &'a FailureObservation,
    /// Revision evidence refs bearing on the observation.
    pub evidence: &'a [MemoryRevisionEvidence],
    /// Admitted task projection (CC-004).
    pub task: &'a TaskProjection,
    /// Admitted safety projection (CC-004).
    pub safety: &'a SafetyProjection,
    /// Frozen self-query input (A-03 owner).
    pub query: &'a SelfQueryInput,
    /// Accepted-source projection the query cites against.
    pub sources: &'a AcceptedSourceProjection,
    /// Posed digest echo to recheck against the query.
    pub pose_digest: &'a str,
    /// Stable identity for the emitted candidate.
    pub candidate_id: &'a ArtifactId,
}

fn check_candidate_id(value: &ArtifactId) -> Result<(), RevisionError> {
    if value.as_str().trim().is_empty()
        || value.as_str().chars().any(char::is_control)
        || value.as_str().chars().count() > MAX_ID_CHARS
    {
        return Err(RevisionError::DigestMismatch {
            field: "intake.candidate_id",
        });
    }
    Ok(())
}

/// The advisory outcome [`propose`] reaches over an intake that validated.
///
/// It is the classification half of [`propose`], deliberately separate from
/// intake validation so a refusal is always a decision about *adequacy* and
/// never about shape. No field here is owner-supplied: every value is derived
/// from the validated intake by [`classify`].
struct ProposalOutcome {
    /// Disposition the emitted candidate carries.
    disposition: CandidateDisposition,
    /// Terminal candidate state.
    state: CandidateState,
    /// Exact missing-evidence entries; empty when the intake is complete.
    missing: Vec<String>,
    /// Reversible advisory narrowing. Never irreversible.
    narrowing: AdvisoryNarrowing,
}

/// Validate the whole intake and return the rechecked self-query digest.
///
/// Every owner shape is revalidated here and then the cross-owner bindings are
/// checked against each other: evidence against the observation, both
/// projections against the task scope, every fence against the task's
/// governing fence, the posed digest against the recomputed query digest, and
/// every cited source triple against the accepted-source projection. A
/// violation is a [`RevisionError`] naming the exact field. Nothing is
/// classified from an intake that did not pass.
fn validate_intake(intake: &RevisionIntake<'_>) -> Result<String, RevisionError> {
    intake.observation.validate()?;
    if intake.evidence.len() > MAX_REVISION_EVIDENCE {
        return Err(RevisionError::Bounds {
            field: "intake.evidence",
        });
    }
    for evidence in intake.evidence {
        evidence.validate()?;
        if evidence.observation_ref != intake.observation.observation_id {
            return Err(RevisionError::ScopeMismatch {
                field: "intake.evidence.observation_ref",
            });
        }
    }
    intake.task.validate()?;
    intake.safety.validate()?;
    if intake.observation.scope.work_scope != intake.task.binding.scope_id
        || intake.observation.scope.work_scope != intake.safety.binding.scope_id
    {
        return Err(RevisionError::ScopeMismatch {
            field: "intake.observation.scope",
        });
    }
    let governing = &intake.task.binding.state_fence;
    if !intake.observation.state_fence.is_compatible_with(governing)
        || !intake
            .safety
            .binding
            .state_fence
            .is_compatible_with(governing)
    {
        return Err(RevisionError::FenceMismatch {
            field: "intake.projection_fence",
        });
    }
    for evidence in intake.evidence {
        if !evidence
            .state_fence
            .is_compatible_with(&intake.observation.state_fence)
        {
            return Err(RevisionError::FenceMismatch {
                field: "intake.evidence_fence",
            });
        }
        if evidence.scope.work_scope != intake.observation.scope.work_scope {
            return Err(RevisionError::ScopeMismatch {
                field: "intake.evidence.scope",
            });
        }
    }
    intake.query.validate()?;
    let query_digest = intake.query.input_digest()?;
    if intake.pose_digest != query_digest {
        return Err(RevisionError::DigestMismatch {
            field: "intake.pose_digest",
        });
    }
    intake.sources.validate()?;
    if let Some(source) = &intake.query.source {
        intake
            .sources
            .check_cited(&source.source_handle, &source.revision, &source.digest)?;
    }
    for anchor in &intake.query.anchors {
        intake.sources.check_cited(
            &anchor.source_handle,
            &anchor.revision,
            &anchor.source_digest,
        )?;
    }
    if !intake.sources.fence.is_compatible_with(governing) {
        return Err(RevisionError::FenceMismatch {
            field: "intake.sources_fence",
        });
    }
    Ok(query_digest)
}

/// Classify a validated intake into the advisory outcome it earns.
///
/// Two refusals precede any coverage scoring, and each names the exact reason:
/// a safety negative-memory trigger makes the candidate `Unsupported`, and a
/// same-hypothesis recurrence routes to Governor Mechanism Review instead of
/// another equivalent retry. Otherwise coverage completeness decides the
/// state, and only a fully covered intake may propose suppressing advisory
/// activation — an incomplete one names every missing evidence entry and
/// suppresses nothing.
///
/// The first refusal is the only exact-trigger comparison in this crate and it
/// is verbatim equality between the observation's exact trigger identity and a
/// governing exact trigger identity. It never reads `fingerprint`, so a
/// semantic near-match cannot make the candidate `Unsupported` here;
/// [`NegativeMemoryExtinctionCandidate::recheck_exact_trigger`] then binds the
/// recorded state to that same comparison.
fn classify(intake: &RevisionIntake<'_>) -> ProposalOutcome {
    if intake
        .safety
        .negative_memory_triggers
        .iter()
        .any(|trigger| trigger == &intake.observation.trigger)
    {
        return ProposalOutcome {
            disposition: CandidateDisposition::AdvisoryNarrow,
            state: CandidateState::Unsupported,
            missing: vec!["safety.negative_memory_triggers".to_owned()],
            narrowing: AdvisoryNarrowing {
                suppress_activation: false,
                quarantine: false,
                archive: false,
            },
        };
    }
    if intake
        .evidence
        .iter()
        .any(|evidence| evidence.same_hypothesis_recurrence)
    {
        return ProposalOutcome {
            disposition: CandidateDisposition::MechanismReview,
            state: CandidateState::Inconclusive,
            missing: vec!["mechanism-review-required".to_owned()],
            narrowing: AdvisoryNarrowing {
                suppress_activation: false,
                quarantine: false,
                archive: false,
            },
        };
    }

    let mut missing = Vec::new();
    if !intake.observation.coverage_complete() {
        missing.push("observation.coverage".to_owned());
    }
    for (index, evidence) in intake.evidence.iter().enumerate() {
        if !evidence.coverage_complete() {
            missing.push(format!("revision.evidence[{index}].coverage"));
        }
    }
    if intake.evidence.is_empty() {
        missing.push("revision.evidence_refs".to_owned());
    }
    let complete = missing.is_empty();
    ProposalOutcome {
        disposition: CandidateDisposition::AdvisoryNarrow,
        state: if complete {
            CandidateState::Complete
        } else {
            CandidateState::Inconclusive
        },
        missing,
        narrowing: AdvisoryNarrowing {
            suppress_activation: complete,
            quarantine: false,
            archive: false,
        },
    }
}

/// Propose one advisory extinction candidate over validated intake.
///
/// The freeze binding is verified first, so a crate not bound to the exact
/// revision it pins fails closed before any intake is read. Intake contract
/// violations (invalid shapes, scope/fence mismatch, stale citations, digest
/// drift) fail closed as [`RevisionError`]. Valid intake with insufficient
/// evidence yields `Ok` with state `Inconclusive` or `Unsupported` and the
/// exact missing evidence named.
///
/// Validation ([`validate_intake`]) is kept separate from classification
/// ([`classify`]) so that every contract violation is still refused before any
/// adequacy decision is taken, and so neither half can grow to obscure the
/// order in which they run.
pub fn propose(
    intake: &RevisionIntake<'_>,
) -> Result<NegativeMemoryExtinctionCandidate, RevisionError> {
    verify_freeze_binding()?;
    let query_digest = validate_intake(intake)?;
    let outcome = classify(intake);
    finish(
        intake,
        query_digest,
        outcome.disposition,
        outcome.state,
        outcome.missing,
        outcome.narrowing,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish(
    intake: &RevisionIntake<'_>,
    query_digest: String,
    disposition: CandidateDisposition,
    state: CandidateState,
    missing: Vec<String>,
    narrowing: AdvisoryNarrowing,
) -> Result<NegativeMemoryExtinctionCandidate, RevisionError> {
    let mut members = BTreeSet::new();
    for handle in &intake.observation.journal_refs {
        members.insert(handle.clone());
    }
    for evidence in intake.evidence {
        for handle in &evidence.evidence_refs {
            members.insert(handle.clone());
        }
    }
    let enumerated: Vec<ArtifactId> = members.into_iter().collect();
    let mut exclusions = Vec::new();
    exclusions.extend(intake.observation.omissions.iter().cloned());
    for evidence in intake.evidence {
        exclusions.extend(evidence.omissions.iter().cloned());
    }
    let mut denominator = ClosureDenominator {
        fence: intake.task.binding.state_fence.clone(),
        enumerated,
        exclusions,
        recheck_digest: String::new(),
        complete: false,
    };
    denominator.complete = !denominator.enumerated.is_empty();
    denominator.recheck_digest = denominator.compute_digest()?;
    check_candidate_id(intake.candidate_id)?;
    let mut candidate = NegativeMemoryExtinctionCandidate {
        contract_version: CANDIDATE_CONTRACT_VERSION,
        candidate_id: intake.candidate_id.clone(),
        observation_ref: intake.observation.observation_id.clone(),
        trigger: ExactTrigger {
            identity: intake.observation.trigger.clone(),
            observation_ref: intake.observation.observation_id.clone(),
            state_fence: intake.observation.state_fence.clone(),
        },
        fingerprint: intake.observation.fingerprint.clone(),
        query_digest,
        narrowing,
        disposition,
        denominator,
        state,
        missing,
        digest: String::new(),
    };
    if candidate.state == CandidateState::Complete
        && (!candidate.denominator.complete || !candidate.missing.is_empty())
    {
        candidate.state = CandidateState::Inconclusive;
        if candidate.missing.is_empty() {
            candidate
                .missing
                .push("revision.enumerated_closure".to_owned());
        }
        candidate.narrowing.suppress_activation = false;
    }
    candidate.digest = candidate.compute_digest()?;
    candidate.validate()?;
    candidate.recheck_exact_trigger(&intake.safety.negative_memory_triggers)?;
    Ok(candidate)
}
