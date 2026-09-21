//! Isolated restore driver with a separate cutover authorization (issue #1873).
//!
//! Restore executes only into an isolated root under the system temp
//! directory: production paths are refused, and no code path here performs
//! cutover. The driver compiles the governed [`RestorePlan`](super::RestorePlan)
//! (which validates the bundle and the lineage advance), asserts purge-first
//! ordering, imports pending ORS operations as suspended recovery through
//! [`suspended_recovery_entries`](super::suspended_recovery_entries), and mints
//! the fresh lineage through [`RestoredFence::mint`](super::RestoredFence).
//! Cutover needs a separate owner authorization: without one the request is
//! refused with [`CutoverNotAuthorized`](super::BackupError::CutoverNotAuthorized).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use eliot_contracts::{EpochId, ResourceGeneration};
use serde::{Deserialize, Serialize};

use super::{
    BackupBundle, BackupError, RestoreContext, RestoreHistoricalAuthority, RestorePlan,
    RestoreStep, RestoredFence, digest, suspended_recovery_entries, text,
};

/// Isolated filesystem root for one restore, always under the temp directory.
///
/// Created roots are removed best-effort on drop. Existing paths open only
/// when they already live under the temp directory (resume); anything else is
/// refused so a restore can never target production state from this driver.
#[derive(Debug)]
pub struct IsolatedRoot {
    root: PathBuf,
}

static ISOLATED_ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);

impl IsolatedRoot {
    /// Creates one fresh isolated root for `label`.
    pub fn create(label: &str) -> Result<Self, BackupError> {
        if label.trim().is_empty()
            || label
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        {
            return Err(BackupError::InvalidField {
                field: "restore.root_label",
                reason: "label must be non-blank ASCII alphanumeric, dash, or underscore",
            });
        }
        let counter = ISOLATED_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut root = std::env::temp_dir();
        root.push(format!(
            "eliot-isolated-restore-{}-{counter}-{label}",
            std::process::id()
        ));
        std::fs::create_dir(&root).map_err(|error| BackupError::Target(error.to_string()))?;
        Ok(Self { root })
    }

    /// Opens an existing isolated root for resume.
    pub fn open_existing(path: PathBuf) -> Result<Self, BackupError> {
        if !path.starts_with(std::env::temp_dir()) {
            return Err(BackupError::InvalidField {
                field: "restore.root",
                reason: "isolated roots live under the system temp dir",
            });
        }
        if !path.is_dir() {
            return Err(BackupError::InvalidField {
                field: "restore.root",
                reason: "isolated root must be an existing directory",
            });
        }
        Ok(Self { root: path })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for IsolatedRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// One planned isolated restore: governed plan, suspended ORS evidence, and
/// the freshly minted lineage, all bound to an isolated root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolatedRestorePlan {
    pub plan: RestorePlan,
    pub suspended_entries: Vec<RestoreHistoricalAuthority>,
    pub restored_fence: RestoredFence,
    pub root: PathBuf,
    pub bundle_sha256: String,
    pub canonical_only: bool,
}

impl IsolatedRestorePlan {
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.plan.plan_id, "restore.plan_id")?;
        digest(&self.bundle_sha256, "restore.bundle_sha256")?;
        if !self.root.starts_with(std::env::temp_dir()) {
            return Err(BackupError::InvalidField {
                field: "restore.root",
                reason: "isolated roots live under the system temp dir",
            });
        }
        self.restored_fence.validate()?;
        for entry in &self.suspended_entries {
            entry.validate()?;
        }
        Ok(())
    }
}

/// Plans one isolated restore into `root`.
///
/// Compiles the governed plan (validating the bundle, checksums, schema,
/// purge binding, class denominator, and lineage advance), asserts the
/// purge-first step order, imports pending ORS work as suspended recovery
/// (empty for archives without an ORS snapshot), and mints the fresh
/// Authority Epoch plus Host/Kernel generation the caller proposes. The
/// minted fence must equal the plan's fence: the caller cannot smuggle a
/// different lineage past the plan.
pub fn plan_isolated_restore(
    bundle: &BackupBundle,
    target: RestoreContext,
    authority_epoch: EpochId,
    resource_generation: ResourceGeneration,
    root: &IsolatedRoot,
) -> Result<IsolatedRestorePlan, BackupError> {
    let plan = RestorePlan::compile(bundle, target)?;
    if plan.steps.get(0..2)
        != Some(
            &[
                RestoreStep::PrepareIsolatedRoot,
                RestoreStep::ApplyPurgeLedger,
            ][..],
        )
    {
        return Err(BackupError::PlanMismatch);
    }
    let suspended_entries = match &bundle.ors_snapshot {
        Some(snapshot) => suspended_recovery_entries(snapshot)?,
        None => Vec::new(),
    };
    let restored_fence = RestoredFence::mint(
        &bundle.export_fence.state_fence,
        authority_epoch,
        resource_generation,
    )?;
    if restored_fence != plan.restored_fence {
        return Err(BackupError::PlanMismatch);
    }
    let isolated = IsolatedRestorePlan {
        bundle_sha256: plan.bundle_sha256.clone(),
        canonical_only: bundle.manifest.class.is_canonical_only(),
        plan,
        suspended_entries,
        restored_fence,
        root: root.path().to_path_buf(),
    };
    isolated.validate()?;
    Ok(isolated)
}

/// Separate Human/System Owner authorization for cutover of one exact plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CutoverAuthorization {
    pub plan_id: String,
    pub bundle_sha256: String,
    pub authorized_by: String,
    pub statement: String,
}

impl CutoverAuthorization {
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.plan_id, "cutover.plan_id")?;
        digest(&self.bundle_sha256, "cutover.bundle_sha256")?;
        text(&self.authorized_by, "cutover.authorized_by")?;
        text(&self.statement, "cutover.statement")?;
        Ok(())
    }
}

/// Cutover receipt for one authorized isolated restore.
///
/// Carries the plan's freshly minted epoch and generation plus the class
/// ceiling (`canonical_only`): a degraded archive can never cut over into
/// operational recovery. Issuable only through [`authorize_cutover`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CutoverReceipt {
    pub plan_id: String,
    pub bundle_sha256: String,
    pub new_authority_epoch: EpochId,
    pub new_resource_generation: ResourceGeneration,
    pub authorized_by: String,
    pub canonical_only: bool,
}

impl CutoverReceipt {
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.plan_id, "cutover.plan_id")?;
        digest(&self.bundle_sha256, "cutover.bundle_sha256")?;
        text(&self.authorized_by, "cutover.authorized_by")?;
        Ok(())
    }
}

/// Authorizes cutover for one isolated restore plan.
///
/// `None` is refused with `CutoverNotAuthorized`: no restore cuts over
/// without a separate owner authorization. A mismatched plan or bundle
/// identity is refused with `PlanMismatch`: authorization never transfers
/// between restores.
pub fn authorize_cutover(
    plan: &IsolatedRestorePlan,
    auth: Option<&CutoverAuthorization>,
) -> Result<CutoverReceipt, BackupError> {
    let Some(auth) = auth else {
        return Err(BackupError::CutoverNotAuthorized);
    };
    auth.validate()?;
    if auth.plan_id != plan.plan.plan_id || auth.bundle_sha256 != plan.bundle_sha256 {
        return Err(BackupError::PlanMismatch);
    }
    let receipt = CutoverReceipt {
        plan_id: plan.plan.plan_id.clone(),
        bundle_sha256: plan.bundle_sha256.clone(),
        new_authority_epoch: plan.restored_fence.authority_epoch.clone(),
        new_resource_generation: plan.restored_fence.resource_generation,
        authorized_by: auth.authorized_by.clone(),
        canonical_only: plan.canonical_only,
    };
    receipt.validate()?;
    Ok(receipt)
}
