//! Application-class boundaries for improvement delivery.
//!
//! Enforces `docs/architecture/I12-24-meta-learning-and-improvement-delivery.md`
//! I12.24:78-95: advisory output is the default; pre-authorized reversible
//! tuning is bounded with one experiment per control surface plus automatic
//! rollback, and never covers authority/privacy/finish/verifier/durability/
//! reserve surfaces; code/module/config changes require a work item with
//! canary plus rollback; protected schema/authority/verifier/privacy/
//! Architecture/forgetting changes require an explicit owner decision with a
//! migration/proof record.
//!
//! Also upholds I12.24:3: improvement output never silently rewrites code,
//! policy, or memory authority. Every gate below is fail-closed and records
//! nothing / mutates nothing on its own; callers attach the returned decision
//! to the normal Governor/Architecture promotion path.
//!
//! # Which classes a candidate descriptor can actually reach
//!
//! [`classify`] reads four fields, and only two of them are evidence a
//! candidate can supply today:
//!
//! - `target_surface` is recorded on every [`crate::ImprovementCandidate`].
//! - `touches_protected` is [`is_prohibited_tuning_surface`] over that recorded
//!   surface, so it is a comparison against the owner's closed rule rather than
//!   a spelled constant.
//! - `bounded_tuning` stands for the DECLARED SAFE RANGE of I12.24:85, and the
//!   I12.24:20-38 candidate schema lists no such field. A descriptor therefore
//!   cannot honestly assert it.
//! - `has_work_item_ref` stands for a REAL work item, and I12.24:65 places
//!   that work item after "decision owner selects reject / investigate / work
//!   item / experiment" — downstream of the candidate, not on it.
//!
//! [`ChangeDescriptor::from_recorded_surface`] is how a production intake path
//! builds its descriptor, and it exposes no parameter for the last two flags.
//! (The other builder, `intake::prepare_intake`, takes all three flags from an
//! [`IntakeRequest`](crate::IntakeRequest) supplied by the caller; that entry
//! has no production request source, and its fields are the same unanswered
//! question, not an answer to it.) A descriptor built here always classifies as
//! [`ApplicationClass::Advisory`] or [`ApplicationClass::Protected`];
//! [`ApplicationClass::PreAuthorizedTuning`] and
//! [`ApplicationClass::CodeModuleConfig`] are unreachable until an owner
//! supplies the safe range or the work item they rest on. That unreachability
//! is a stated ceiling, not a gap to be papered over with an invented `true`.

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
    /// that evidence.
    pub fn from_recorded_surface(target_surface: ImprovementSurface) -> Self {
        Self {
            target_surface,
            bounded_tuning: false,
            touches_protected: is_prohibited_tuning_surface(target_surface),
            has_work_item_ref: false,
        }
    }

    pub fn validate(&self) -> Result<(), ImprovementError> {
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
/// records which of them a candidate can actually make.
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
