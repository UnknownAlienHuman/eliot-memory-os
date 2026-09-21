//! Product command surface for backup/restore classes (issue #1873).
//!
//! CLI-shaped argument DTOs plus `preview` orchestration that the product
//! binary calls without owning backup semantics: class-string parsing, the
//! requested-vs-structurally-selected consistency check (never a silent
//! upgrade or downgrade), and restore-plan preview derived from the governed
//! [`RestorePlan::compile`](super::RestorePlan::compile) (which validates the
//! bundle, lineage advance, and class denominator). Issuance, isolated
//! restore, and cutover live in [`portable_recovery`](super::portable_recovery)
//! and [`isolated_restore`](super::isolated_restore); this module only binds
//! product arguments to those typed entrypoints.

use serde::{Deserialize, Serialize};

use super::{
    BackupBundle, BackupClass, BackupError, RestoreContext, RestoreEvidenceLevel, RestorePlan,
    RestoreStep, text,
};

/// Parses one CLI-supplied backup class name into its typed class.
pub fn parse_backup_class(value: &str) -> Result<BackupClass, BackupError> {
    match value {
        "full_recovery" => Ok(BackupClass::FullRecovery),
        "canonical_only_degraded" => Ok(BackupClass::CanonicalOnlyDegraded),
        "scope_export" => Ok(BackupClass::ScopeExport),
        _ => Err(BackupError::InvalidField {
            field: "backup.class",
            reason: "unknown backup class",
        }),
    }
}

/// CLI-shaped arguments for `backup create`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupCreateArgs {
    pub backup_id: String,
    pub class: String,
    pub scope_id: Option<String>,
}

impl BackupCreateArgs {
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.backup_id, "backup.backup_id")?;
        text(&self.class, "backup.class")?;
        if let Some(scope_id) = &self.scope_id {
            text(scope_id, "backup.scope_id")?;
        }
        Ok(())
    }
}

/// Dry-run preview of `backup create`: requested class, structural selection,
/// and the class-bound proof ceiling, without issuing anything.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupCreatePreview {
    pub backup_id: String,
    pub requested_class: BackupClass,
    pub selected: BackupClass,
    pub evidence_level: RestoreEvidenceLevel,
    pub canonical_only: bool,
    pub ors_required: bool,
}

/// Previews one backup creation without issuing it.
///
/// Refuses when the requested class does not match the structural selection:
/// a `full_recovery` request without an ORS snapshot is never silently
/// downgraded, and a degraded/scope request carrying one is never silently
/// upgraded.
pub fn preview_backup_create(
    args: &BackupCreateArgs,
    ors_snapshot_present: bool,
) -> Result<BackupCreatePreview, BackupError> {
    args.validate()?;
    let requested = parse_backup_class(&args.class)?;
    let selected = BackupClass::select(args.scope_id.is_some(), ors_snapshot_present)?;
    if selected != requested {
        return Err(BackupError::InvalidField {
            field: "backup.class",
            reason: "requested class does not match structural selection",
        });
    }
    Ok(BackupCreatePreview {
        backup_id: args.backup_id.clone(),
        requested_class: requested,
        selected,
        evidence_level: selected.evidence_level(),
        canonical_only: selected.is_canonical_only(),
        ors_required: selected.is_full_recovery(),
    })
}

/// Dry-run preview of `restore plan`: governed step names plus the
/// purge-first, ORS-suspension, and class-ceiling bindings, without executing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestorePreview {
    pub plan_id: String,
    pub step_names: Vec<String>,
    pub purge_first: bool,
    pub suspends_ors_operations: bool,
    pub canonical_only: bool,
    pub evidence_level: RestoreEvidenceLevel,
}

/// Previews one restore plan without executing it.
///
/// Compiles the governed plan, which validates the bundle, checksums, class
/// denominator, and lineage advance; any invalid archive fails here, before
/// any isolated root is touched.
pub fn preview_restore(
    bundle: &BackupBundle,
    target: &RestoreContext,
) -> Result<RestorePreview, BackupError> {
    let plan = RestorePlan::compile(bundle, target.clone())?;
    let step_names: Vec<String> = plan.steps.iter().map(|step| format!("{step:?}")).collect();
    Ok(RestorePreview {
        plan_id: plan.plan_id.clone(),
        purge_first: plan.steps.get(0..2)
            == Some(
                &[
                    RestoreStep::PrepareIsolatedRoot,
                    RestoreStep::ApplyPurgeLedger,
                ][..],
            ),
        suspends_ors_operations: plan.steps.contains(&RestoreStep::SuspendOrsOperations),
        canonical_only: bundle.manifest.class.is_canonical_only(),
        evidence_level: bundle.manifest.class.evidence_level(),
        step_names,
    })
}
