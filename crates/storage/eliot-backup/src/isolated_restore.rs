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
//!
//! # The candidate root is validated before any cutover (issue #1141, A6)
//!
//! A13.7 requires that "Restore occurs in an isolated area and verifies schema
//! and format compatibility; provenance and integrity; privacy purge and
//! revocation closure; …" and that "Cutover requires separate authority". The
//! ordering those two sentences impose is that everything the isolated root
//! must prove is proven *inside that root*, and the plan that names it is
//! itself proved before it may authorize a cutover.
//!
//! Two gaps that allowed the ordering to be skipped are closed here:
//!
//! * [`IsolatedRestorePlan::validate`] did not compare the identities this
//!   struct records twice — the outer `bundle_sha256`/`restored_fence` and the
//!   nested `plan.bundle_sha256`/`plan.restored_fence`. `authorize_cutover`
//!   matches the authorization against the *outer* value, so a plan that
//!   disagreed with itself could be cut over against an authorization minted
//!   for a different bundle. Both positions are now compared, and the recorded
//!   root must still be a real directory, so a plan naming a root that no
//!   longer exists cannot be authorized.
//! * [`authorize_cutover`] did not call [`IsolatedRestorePlan::validate`] at
//!   all, so any plan value — deserialized, hand-built, or validated and then
//!   drifted — reached cutover unchecked. It now validates first, before it
//!   looks at the authorization.
//!
//! What this file still does not do is perform the cutover. It mints the
//! authorization receipt; applying it to a current state is a separate owner
//! decision outside this crate, and the receipt exists precisely so that owner
//! can check the exact plan and bundle it is acting on.

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
    /// Proves this plan may be used as the basis of a cutover.
    ///
    /// Issue #1141, A6: the ordering A13.7 requires is that the isolated
    /// candidate root is validated and its plan proved *before* any current
    /// state can be cut over. This method is that proof, and
    /// [`authorize_cutover`] runs it before it looks at any authorization.
    ///
    /// The two positions this struct records for the same identities are
    /// compared here. The outer `bundle_sha256` and `restored_fence` are the
    /// positions a cutover authorization is matched against; the nested
    /// `plan.bundle_sha256` and `plan.restored_fence` are the positions the
    /// governed executor works from. This is a coherence check between two
    /// recorded positions of one plan, not an authenticity proof — what the
    /// bundle actually is was established by
    /// [`RestorePlan::compile`](super::RestorePlan::compile), and the digest is
    /// carried so a mismatch is a refusal rather than a silent preference for
    /// one copy.
    ///
    /// The root must still be a directory under the system temp directory. A
    /// plan whose candidate root has been removed, or that names a production
    /// path, cannot be the validated isolated rehearsal that a cutover is
    /// supposed to rest on.
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.plan.plan_id, "restore.plan_id")?;
        digest(&self.bundle_sha256, "restore.bundle_sha256")?;
        if !self.root.starts_with(std::env::temp_dir()) {
            return Err(BackupError::InvalidField {
                field: "restore.root",
                reason: "isolated roots live under the system temp dir",
            });
        }
        if !self.root.is_dir() {
            return Err(BackupError::InvalidField {
                field: "restore.root",
                reason: "isolated candidate root must still exist as a directory",
            });
        }
        // Issue #1141, A6: the outer recorded bundle identity and the plan's own
        // must be the same value. `authorize_cutover` matches the owner
        // authorization against `self.bundle_sha256`, so a plan whose two
        // copies disagree would be authorized against a bundle its own
        // executor never validated.
        if self.bundle_sha256 != self.plan.bundle_sha256 {
            return Err(BackupError::PlanMismatch);
        }
        self.restored_fence.validate()?;
        // The same two positions for the minted lineage. `RestoredFence` is
        // the Authority Epoch and resource generation the restore would make
        // current, so a plan whose outer and inner copies disagree has no
        // single lineage to cut over to.
        if self.restored_fence != self.plan.restored_fence {
            return Err(BackupError::PlanMismatch);
        }
        for entry in &self.suspended_entries {
            entry.validate()?;
        }
        Ok(())
    }
}

/// Plans one isolated restore into `root`.
///
/// Compiles the governed plan (validating the bundle, checksums, schema,
/// purge binding, class denominator, and lineage advance), binds the correlated
/// operation identity the restore request carried, asserts the purge-first step
/// order, imports pending ORS work as suspended recovery (empty for archives
/// without an ORS snapshot), and mints the fresh Authority Epoch plus
/// Host/Kernel generation the caller proposes. The minted fence must equal the
/// plan's fence: the caller cannot smuggle a different lineage past the plan.
///
/// `operation_id` is the request's own operation identity, carried through
/// unchanged and never re-derived. It is part of the durable journal stream key
/// this plan will address, so a blank or control-bearing value is refused here
/// as [`BackupError::InvalidField`] rather than becoming a default key under
/// which two operations could collide.
pub fn plan_isolated_restore(
    bundle: &BackupBundle,
    target: RestoreContext,
    operation_id: &str,
    authority_epoch: EpochId,
    resource_generation: ResourceGeneration,
    root: &IsolatedRoot,
) -> Result<IsolatedRestorePlan, BackupError> {
    let mut plan = RestorePlan::compile(bundle, target)?;
    // The correlated operation identity the restore request carried is bound
    // BEFORE anything derives a journal identity from this plan. It is the
    // request's own value, carried through unchanged: without it the durable
    // stream key would be a function of the archive alone, so two operations
    // over byte-identical bundles would share one stream and the second would
    // read back the first's final receipt.
    plan.bind_operation(operation_id)?;
    // Issue #1141, A6: A13.7 orders the isolated rehearsal ahead of cutover —
    // "restore to isolated root; validate format/schema/checksums; apply privacy
    // purge ledger; rebuild projections/indexes; verify receipt/event chain" —
    // and ARCH-RES-03 requires that purge and revocation closure precede any
    // import. The prior check asserted only the first two steps, so a plan that
    // opened correctly and then imported before purging was admitted.
    //
    // This asserts the ordering *properties* A13.7 states rather than
    // re-listing the plan's steps: the candidate root is prepared first, the
    // purge ledger is applied second, every subsequent import / rebuild /
    // verification step comes after the purge, and the root is finalized last.
    // `expected_restore_steps` remains the single definition of which steps a
    // plan contains; this only checks that they are ordered as the normative
    // sequence requires.
    if plan.steps.first() != Some(&RestoreStep::PrepareIsolatedRoot)
        || plan.steps.get(1) != Some(&RestoreStep::ApplyPurgeLedger)
        || plan.steps.last() != Some(&RestoreStep::FinalizeIsolatedRoot)
    {
        return Err(BackupError::PlanMismatch);
    }
    // Nothing may re-enter the root-preparation or purge phases after the
    // imports have begun: a second purge would reorder ARCH-RES-03's
    // purge-before-import obligation relative to already-applied data. The
    // three checks above already establish that the plan holds at least three
    // steps, so the slice is in range; `get` is used anyway so a future change
    // to the ordering cannot turn this into a panic.
    if let Some(tail) = plan.steps.get(2..plan.steps.len().saturating_sub(1))
        && (tail.contains(&RestoreStep::PrepareIsolatedRoot)
            || tail.contains(&RestoreStep::ApplyPurgeLedger))
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
///
/// Issue #1141, A6: the plan is validated *before* the authorization is even
/// looked at. A13.7 orders the isolated rehearsal ahead of cutover, so a plan
/// that has not been proved — a deserialized value, a hand-built one, or one
/// that drifted after it was validated — must be refused on its own state
/// rather than become current because some authorization named its id. The
/// validation covers the recorded bundle identity, the recorded lineage and
/// the still-existing isolated candidate root; see
/// [`IsolatedRestorePlan::validate`].
pub fn authorize_cutover(
    plan: &IsolatedRestorePlan,
    auth: Option<&CutoverAuthorization>,
) -> Result<CutoverReceipt, BackupError> {
    plan.validate()?;
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
