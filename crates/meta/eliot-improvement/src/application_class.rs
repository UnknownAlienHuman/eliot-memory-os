//! Application-class boundaries for improvement delivery.
//!
//! Implements `docs/architecture/I12-24-meta-learning-and-improvement-delivery.md`
//! I12.24:78-95: advisory output is the default; pre-authorized reversible
//! tuning is bounded with one experiment per control surface plus automatic
//! rollback, and never covers authority/privacy/finish/verifier/durability/
//! reserve surfaces; code/module/config changes require a work item with
//! canary plus rollback; protected schema/authority/verifier/privacy/
//! Architecture/forgetting changes require an explicit owner decision with a
//! migration/proof record.
//!
//! That paragraph restates what the document requires; it is NOT a claim that
//! every clause is enforced today. Two of them are not, because the owner
//! records they rest on do not exist in this repository — "Which classes are
//! reachable, and which clauses are therefore enforced" below says which two,
//! and why.
//!
//! Also upholds I12.24:3: improvement output never silently rewrites code,
//! policy, or memory authority. Every gate below is fail-closed and records
//! nothing / mutates nothing on its own; callers attach the returned decision
//! to the normal Governor/Architecture promotion path.
//!
//! # Which classes are reachable, and which clauses are therefore enforced
//!
//! [`classify`] reads four fields, and only two of them are evidence that
//! exists to be read today:
//!
//! - `target_surface` is recorded on every [`crate::ImprovementCandidate`].
//! - `touches_protected` is [`is_prohibited_tuning_surface`] over that recorded
//!   surface, so it is a comparison against the owner's closed rule rather than
//!   a spelled constant. [`ChangeDescriptor::validate`] re-checks that
//!   agreement, and refuses a hand-built descriptor whose `touches_protected`
//!   or tuning/work-item flags contradict its recorded surface, so the class a
//!   descriptor reaches cannot be one its surface forbids.
//! - `bounded_tuning` stands for the DECLARED SAFE RANGE of I12.24:85, and the
//!   I12.24:20-38 candidate schema lists no such field.
//! - `has_work_item_ref` stands for a REAL work item, and I12.24:65 places
//!   that work item after "decision owner selects reject / investigate / work
//!   item / experiment" — downstream of the candidate, not on it.
//!
//! [`ChangeDescriptor::from_recorded_surface`] is the only descriptor builder
//! in the repository: both production sites, `intake::prepare_intake` and
//! `bins/eliotd/src/improvement_intake_dispatch.rs`, call it, and neither takes
//! a flag through any other route. It exposes no parameter for the last two
//! flags, so a descriptor built anywhere classifies as
//! [`ApplicationClass::Advisory`] or [`ApplicationClass::Protected`], and a
//! `Protected` one is refused with
//! [`ImprovementError::ApplicationClassViolation`].
//!
//! ## The measured absence behind the two unreachable classes (issue #1867 W5)
//!
//! The two middle classes are unreachable because the owner records they stand
//! for do not exist in this repository, which was measured rather than assumed:
//!
//! - **No declared safe range.** No record type in this repository is one.
//!   Searching the concept under every phrasing in use — `safe range`,
//!   `declared range`, `tuning range`, `authorized range`, `pre-authorized
//!   range`, `tuning authoriz*` — across `*.rs`, `*.toml`, `*.md`, `*.json`
//!   and `*.yaml` returns only prose: this crate's own comments, the
//!   `eliotd` dispatch comments that quote I12.24:85, a latency string in
//!   `eliot-dreamer-maintenance-plan`, a reconciliation phrase in
//!   `eliot-watchdog-core`, and the governing document's own I12.24:85 line.
//!   No `struct` or `enum` is one, and the nearest records were each checked
//!   and rejected: `ContextRecipe` (`eliot-context-contracts`) is an immutable
//!   compilation recipe with a canonical digest and no interval over a
//!   tunable value; `CapacityLimits` is a route-capacity budget, not a safe
//!   range; and `eliot-maintenance`'s `improvement_pipeline` records —
//!   `ExperimentPlan`, `RollbackContract`, `AdmittedResourceCeiling`,
//!   `AdmittedScopeRefinement` — are a different crate's contract that this
//!   crate does not depend on, whose `effect_ceiling` is fixed at
//!   `advisory-only` (`IMPROVEMENT_EFFECT_CEILING`) and which therefore
//!   cannot express a tuning or delivery class at all.
//! - **No real work item.** Every candidate-shaped record reachable from this
//!   crate was checked and none carries one. `ImprovementCandidate`
//!   (I12.24:20-38) has no work-item field: its `delivery_target` is the
//!   free-form string "work item / module / config path" and names nothing;
//!   `OwnerDecisionKind::WorkItem` is a decision-OWNER selection recorded by
//!   [`record_owner_decision`](crate::record_owner_decision), which this
//!   crate's own callers document as a pure constructor that "cannot tell a
//!   real principal from a fabricated one" — so sourcing the flag from it
//!   would be the fabricated `true` this module exists to prevent; and
//!   `ImprovementCandidate` carries no impact tests, immutable candidate or
//!   canary record either, which are the rest of I12.24:91.
//!
//! ## What that costs, stated plainly
//!
//! [`check_class_gate`] itself HAS a live caller —
//! `enforce_advisory_class_gate` in `bins/eliotd/src/improvement_intake_dispatch.rs`
//! runs it. But two I12.24:78-95 clauses have no REACHABLE class, and this
//! module claims no enforcement for them:
//!
//! - I12.24:86 "one experiment per control surface, automatic rollback". The
//!   `live_experiments_on_surface` argument of [`check_class_gate`] is read in
//!   exactly ONE place — the [`ApplicationClass::PreAuthorizedTuning`] arm —
//!   which `classify` cannot return, so no call site reads it. The
//!   [`ApplicationClass::Advisory`] arm returns before examining any argument,
//!   and the [`ApplicationClass::CodeModuleConfig`] arm never references the
//!   argument at all.
//! - I12.24:90-91, the normal work item with impact tests, immutable candidate,
//!   canary and rollback, and with it the automatic-rollback requirement that
//!   rides on the tuning arm.
//!
//! The per-surface concurrency bound that IS enforced in this crate is a
//! different rule with a different owner:
//! [`CandidateBoundPolicy::max_active`](crate::candidate_bounds::CandidateBoundPolicy),
//! applied by the bounded backlog at admission. Naming that here is not a
//! substitute for I12.24:86 and must not be read as one.
//!
//! This unreachability is a stated ceiling, not a gap to be papered over with
//! an invented `true`. Closing it requires an owner to issue the declared safe
//! range and the real work item as records this crate can read; it is not
//! closed by widening a parameter list.

use serde::{Deserialize, Serialize};

use crate::{ImprovementError, ImprovementSurface};

/// Application class of a proposed improvement change (I12.24:78-95).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationClass {
    Advisory,
    PreAuthorizedTuning,
    CodeModuleConfig,
    Protected,
}

/// Minimal descriptor used to classify and gate a proposed change.
///
/// No constructor in this repository builds a value with `bounded_tuning` or
/// `has_work_item_ref` set to `true`, because the owner records those two flags
/// stand for do not exist here; the module header records the measured absence.
/// The fields stay public so [`Self::validate`] can be applied to a
/// hand-built descriptor and refuse one that disagrees with its recorded
/// surface.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChangeDescriptor {
    pub target_surface: ImprovementSurface,
    /// Whether a DECLARED SAFE RANGE (I12.24:85) authorises this change as
    /// pre-authorized tuning. The I12.24:20-38 candidate schema carries no safe
    /// range, so no candidate source can set this honestly; see
    /// [`Self::from_recorded_surface`].
    pub bounded_tuning: bool,
    pub touches_protected: bool,
    /// Whether a REAL work item (I12.24:65, I12.24:90) carries this change. An
    /// intake candidate carries none, because the work item is created after
    /// the decision owner selects it; see [`Self::from_recorded_surface`].
    pub has_work_item_ref: bool,
}

impl ChangeDescriptor {
    /// The descriptor a candidate's OWN recorded surface can honestly support.
    ///
    /// `touches_protected` is derived from that surface through the owner's
    /// closed rule ([`is_prohibited_tuning_surface`]). The other two class
    /// flags are deliberately NOT parameters of this constructor, because the
    /// evidence they stand for does not exist at the point a candidate is
    /// assembled: I12.24:85 admits pre-authorized tuning only inside a declared
    /// safe range and the I12.24:20-38 schema lists none, and I12.24:90 admits
    /// code/module/config delivery as a normal work item that I12.24:65 places
    /// after the decision owner's selection.
    ///
    /// Accepting them as arguments here would let a caller select a class it
    /// holds no evidence for — the fabricated `true` this crate must not
    /// contain. A descriptor built here is consequently always
    /// [`ApplicationClass::Advisory`] or [`ApplicationClass::Protected`]; the
    /// two evidence-bound classes stay unreachable until a candidate carries
    /// that evidence. Because every field is the closed rule over the recorded
    /// surface, a descriptor built here also passes [`Self::validate`].
    ///
    /// This is the ONLY descriptor builder in the repository. `git grep` finds
    /// exactly two call sites, `intake::prepare_intake` and
    /// `bins/eliotd/src/improvement_intake_dispatch.rs`, and no `ChangeDescriptor`
    /// struct literal anywhere, so no path exists that sets either flag.
    pub fn from_recorded_surface(target_surface: ImprovementSurface) -> Self {
        Self {
            target_surface,
            bounded_tuning: false,
            touches_protected: is_prohibited_tuning_surface(target_surface),
            has_work_item_ref: false,
        }
    }

    /// Fail-closed check of the descriptor's OWN internal consistency.
    ///
    /// This runs before every class arm, so it must not depend on the class
    /// the caller believes the descriptor has. It derives everything from the
    /// recorded `target_surface` and the owner's closed rules already in this
    /// module:
    ///
    /// 1. `touches_protected` MUST equal
    ///    [`is_prohibited_tuning_surface`] over `target_surface`. Under-claiming
    ///    it on a `Verifier`/`Scheduler` surface would classify as
    ///    [`ApplicationClass::Advisory`] or
    ///    [`ApplicationClass::PreAuthorizedTuning`] and escape the
    ///    owner-decision path of I12.24:93-94 entirely; over-claiming it would
    ///    route an ordinary surface into that path.
    /// 2. `bounded_tuning` MUST NOT be asserted on a prohibited surface.
    ///    I12.24:87 admits pre-authorized tuning only where it "never changes
    ///    authority, privacy, finish semantics, Decision Safety Floor,
    ///    ContextAtomPolicy, verifier definition, canonical durability,
    ///    Kernel/Watchdog reserve or last-resort recovery capacity", and
    ///    [`is_prohibited_tuning_surface`] is this crate's own encoding of
    ///    exactly that rule for the surfaces it records.
    /// 3. `has_work_item_ref` MUST NOT be asserted on a prohibited surface
    ///    either. [`classify`] gives `touches_protected` precedence, so such a
    ///    descriptor is classified [`ApplicationClass::Protected`] and the
    ///    work-item claim is silently discarded; a verifier/scheduler change is
    ///    delivered as the explicit owner decision and migration/proof of
    ///    I12.24:93-94, not as the work item of I12.24:90-91.
    pub fn validate(&self) -> Result<(), ImprovementError> {
        let prohibited = is_prohibited_tuning_surface(self.target_surface);
        if self.touches_protected != prohibited {
            return Err(ImprovementError::ApplicationClassViolation);
        }
        if prohibited && (self.bounded_tuning || self.has_work_item_ref) {
            return Err(ImprovementError::ApplicationClassViolation);
        }
        Ok(())
    }
}

/// Classify a change into its application class (I12.24:78-95).
///
/// Precedence: `touches_protected` dominates everything; otherwise a bounded
/// tuning flag selects pre-authorized tuning; otherwise a work-item reference
/// selects code/module/config delivery; anything else stays advisory.
///
/// The two middle flags are evidence claims, and the module documentation
/// records which of them a candidate can actually make. As measured there,
/// neither can be made by any descriptor this repository can build, so this
/// function returns [`ApplicationClass::Advisory`] or
/// [`ApplicationClass::Protected`] in practice. The middle arms are kept
/// because the owner records they need are a missing prerequisite, not a
/// rejected requirement.
pub fn classify(change: &ChangeDescriptor) -> ApplicationClass {
    if change.touches_protected {
        ApplicationClass::Protected
    } else if change.bounded_tuning {
        ApplicationClass::PreAuthorizedTuning
    } else if change.has_work_item_ref {
        ApplicationClass::CodeModuleConfig
    } else {
        ApplicationClass::Advisory
    }
}

/// Whether a surface is prohibited for pre-authorized tuning.
///
/// Rationale (I12.24:78-95): the verifier definition surface would let a
/// tuner rewrite its own oracle, and the scheduler surface carries
/// reserve/scheduling authority; both must stay on the explicit owner-decision
/// (protected or work-item) path and can never be pre-authorized tuning.
///
/// # Part of the I12.24:87-88 prohibited set is UNREPRESENTABLE, not merely unprohibited
///
/// This function matches two of the seven [`ImprovementSurface`] variants.
/// I12.24:87-88 prohibits tuning a wider set — authority, privacy, finish
/// semantics, the Decision Safety Floor, `ContextAtomPolicy`, verifier
/// definition, canonical durability, Kernel/Watchdog reserve, and last-resort
/// recovery capacity — and the closed enum has no variant for several of them:
/// privacy, finish semantics, canonical durability and `ContextAtomPolicy` are
/// not surfaces a candidate can be recorded on at all. A change that touched
/// one of them could not name it, so this rule cannot refuse on those grounds;
/// the category is absent from the taxonomy rather than correctly classified.
///
/// That is a ceiling of [`ImprovementSurface`], which is fixed at the crate
/// root and is not widened here. Whether a `Memory` or `Rule` change in fact
/// reaches privacy or durability is NOT decidable from the surface record, and
/// this function does not claim to decide it. The variant list and this match
/// are the honest statement of coverage.
pub fn is_prohibited_tuning_surface(surface: ImprovementSurface) -> bool {
    matches!(
        surface,
        ImprovementSurface::Verifier | ImprovementSurface::Scheduler
    )
}

/// Enforce the gate for an application class (I12.24:78-95, I12.24:3).
///
/// Advisory always succeeds and records/mutates nothing. Pre-authorized
/// tuning requires a bounded change on a non-prohibited surface, zero live
/// experiments on that surface, and a non-empty rollback reference.
/// Code/module/config delivery requires a present non-empty work-item
/// reference and a non-empty rollback reference. Protected changes require
/// explicit owner approval plus a present non-empty migration/proof
/// reference.
///
/// # Which of those clauses a call site actually reaches
///
/// `live_experiments_on_surface` is read in exactly ONE place: the
/// [`ApplicationClass::PreAuthorizedTuning`] arm. The
/// [`ApplicationClass::CodeModuleConfig`] arm never references it — it checks
/// only `work_item_ref` and `rollback_ref` — and [`ApplicationClass::Advisory`]
/// returns before any argument is examined, so this summary above describes
/// exactly one read of that parameter and no other.
///
/// Since no descriptor [`ChangeDescriptor::from_recorded_surface`] can build
/// selects [`ApplicationClass::PreAuthorizedTuning`], both call sites pass a
/// value that is provably never read, and neither enforces I12.24:86. See the
/// module header for the measured absence and for the per-surface bound that IS
/// enforced elsewhere. `rollback_ref` is a caller-authored reference string
/// that nothing in this crate resolves, so a non-empty value is a shape
/// requirement, not a rollback capability.
///
/// [`ChangeDescriptor::validate`] runs first, so a descriptor inconsistent
/// with its recorded surface is refused for every class, including
/// [`ApplicationClass::Advisory`].
pub fn check_class_gate(
    class: ApplicationClass,
    change: &ChangeDescriptor,
    live_experiments_on_surface: usize,
    rollback_ref: &str,
    work_item_ref: Option<&str>,
    owner_approved: bool,
    migration_proof_ref: Option<&str>,
) -> Result<(), ImprovementError> {
    change.validate()?;
    match class {
        ApplicationClass::Advisory => Ok(()),
        ApplicationClass::PreAuthorizedTuning => {
            if !change.bounded_tuning {
                return Err(ImprovementError::ApplicationClassViolation);
            }
            if is_prohibited_tuning_surface(change.target_surface) {
                return Err(ImprovementError::ApplicationClassViolation);
            }
            if live_experiments_on_surface != 0 {
                return Err(ImprovementError::ApplicationClassViolation);
            }
            if rollback_ref.trim().is_empty() {
                return Err(ImprovementError::ApplicationClassViolation);
            }
            Ok(())
        }
        ApplicationClass::CodeModuleConfig => {
            match work_item_ref {
                Some(value) if !value.trim().is_empty() => {}
                _ => return Err(ImprovementError::MissingField("work_item_ref")),
            }
            if rollback_ref.trim().is_empty() {
                return Err(ImprovementError::MissingField("rollback"));
            }
            Ok(())
        }
        ApplicationClass::Protected => {
            if !owner_approved {
                return Err(ImprovementError::ApplicationClassViolation);
            }
            match migration_proof_ref {
                Some(value) if !value.trim().is_empty() => Ok(()),
                _ => Err(ImprovementError::MissingField("migration_proof_ref")),
            }
        }
    }
}
