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
    pub bounded_tuning: bool,
    pub touches_protected: bool,
    pub has_work_item_ref: bool,
}

impl ChangeDescriptor {
    pub fn validate(&self) -> Result<(), ImprovementError> {
        Ok(())
    }
}

/// Classify a change into its application class (I12.24:78-95).
///
/// Precedence: `touches_protected` dominates everything; otherwise a bounded
/// tuning flag selects pre-authorized tuning; otherwise a work-item reference
/// selects code/module/config delivery; anything else stays advisory.
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
