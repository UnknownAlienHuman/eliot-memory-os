//! Production restore driver: mint → coordinate → import → reconcile
//! (issues #959/#960/#963, lane G).
//!
//! Architecture: A13.7 Backups, Restore, and Migration (isolated restore
//! executes through its owners; cutover stays separate authority); A12.3
//! One Governed Write Path (every store effect below crosses the single
//! canonical gateway path with unknown-commit recovery); I1.8 Exact
//! Ownership and Call Paths (one logical Governor: the Governor-built
//! coordination transition and per-import transitions arrive already
//! admitted; the Kernel verifies identity, fence, admission, anchor, and
//! receipts before and after each effect); I5.19 Write submission,
//! execution and receipts (each effect reconciles by exact operation
//! identity; unknown stays unknown for the caller to disposition); I5.27
//! Canonical operation identity.
//!
//! What this module owns: the single production composition of the
//! restore wires. Given the live coordinator handles (journal,
//! channels), the verified destination binding, the compiled plan and
//! validated bundle, the constructed destination, the live fence, the
//! provisioning proofs, one Governor-built coordination transition, and
//! the Governor-built per-import transitions, it mints the admission,
//! builds the coordination decision, commits the coordination row,
//! executes each restore-class import, and reconciles every import by
//! identity. One attempt per effect, observed outcomes returned as data:
//! the driver never retries, never synthesizes receipts, and never
//! replays blindly — a `NotApplied` or `Unknown` reconciliation is
//! reported for the #963 caller to disposition, exactly as I5.19
//! requires.
//!
//! This driver performs no rehearsal-phase work and touches none of it:
//! `restore()`/`request_cutover()` are unchanged. It is the production
//! caller the H5 site invokes once #963 wires it to the operator path;
//! until then it is the compiled composition proof that the wires fit.
//!
//! Capability cell: Kernel restore ownership (production restore
//! composition). Forbidden authority: no plan/bundle invention (both
//! arrive compiled/validated), no identity minting beyond the minter's
//! deterministic restore identity, no receipt synthesis, no blind retry,
//! no cutover/activation/retirement.

use std::num::NonZeroU64;
use std::path::Path;

use eliot_backup::{BackupBundle, BackupError, RestoreContext, RestorePlan};
use eliot_contracts::{EpochId, EpochLineageId, RequestMetadata, ResourceGeneration, StateFence};
use eliot_store_api::{
    OrderingHeadExpectation, PreparedTransition, RevisionHeadExpectation, WriteReceipt,
};

use super::backup_coordination::CoordinationDecision;
use super::backup_owner_clients::{
    AuthorizationExpectation, BackupOwnerChannels, CanonicalStoreImportClient,
    ImportReconciliation, OwnerChannelError, VerifiedDestinationBinding,
    verify_destination_authorization,
};
use super::backup_restore::KernelBackupRestore;
use super::backup_restore_admission::{
    KernelRestoreAdmission, RestoreAdmissionMintRequest, RestoreProvisioningProof,
    mint_restore_admission,
};
use super::backup_restore_ports::{
    KernelIsolatedDestination, KernelRestoreJournal, check_kernel_effect_fence, kernel_to_backup,
};
use eliot_ors::CapabilityIntroductionProjection;

/// One Governor-built coordination commit: the coordination transition
/// plus its execution context and expectations.
pub struct CoordinationCommit {
    /// Request metadata bound to the coordination transition.
    pub context: RequestMetadata,
    /// Governor-built coordination transition (single coordination
    /// operation under the restore identity).
    pub transition: PreparedTransition,
    /// Expected revision heads for the commit.
    pub revision_heads: Vec<RevisionHeadExpectation>,
    /// Expected ordering heads for the commit.
    pub ordering_heads: Vec<OrderingHeadExpectation>,
}

/// One Governor-built restore-class import with its execution context.
pub struct RestoreImport {
    /// Request metadata bound to the import transition.
    pub context: RequestMetadata,
    /// Governor-built restore transition (RecoverySchema, carrying the
    /// admission decision digest in its proof handles).
    pub transition: PreparedTransition,
    /// Expected revision heads for the import.
    pub revision_heads: Vec<RevisionHeadExpectation>,
    /// Expected ordering heads for the import.
    pub ordering_heads: Vec<OrderingHeadExpectation>,
}

/// Production restore composition request binding every live handle.
///
/// All plan/bundle/transition material arrives compiled, validated, and
/// Governor-built; the driver binds and sequences but never invents.
pub struct ProductionRestoreRequest<'a> {
    /// Owner-held restore journal (mint anchor readback + import anchor
    /// re-fetch).
    pub journal: &'a KernelRestoreJournal,
    /// Live owner channels (store import client + gateway).
    pub channels: &'a BackupOwnerChannels,
    /// Host-issued verified destination binding.
    pub verified: &'a VerifiedDestinationBinding,
    /// Compiled restore plan being executed.
    pub plan: &'a RestorePlan,
    /// Archive the plan was compiled from.
    pub bundle: &'a BackupBundle,
    /// Constructed isolated destination bound to the plan target.
    pub destination: &'a KernelIsolatedDestination,
    /// Caller-live authority fence.
    pub live_fence: &'a StateFence,
    /// Destination-store provisioning attestations.
    pub provisioning: RestoreProvisioningProof,
    /// Governor-built coordination commit.
    pub coordination: CoordinationCommit,
    /// Governor-built restore-class imports in execution order.
    pub imports: Vec<RestoreImport>,
    /// Console-presented capability introductions, verified live against
    /// owner/ORS readback by the journal owner before any effect (F-AUR-1).
    /// An empty list verifies vacuously (a restore with no capability
    /// introductions has nothing to compare).
    pub introductions: Vec<CapabilityIntroductionProjection>,
}

/// Observed outcome of one restore-class import: its receipt plus its
/// identity reconciliation.
#[derive(Clone, Debug)]
pub struct RestoreImportOutcome {
    /// Import operation identity string.
    pub operation_id: String,
    /// Committed import receipt.
    pub receipt: WriteReceipt,
    /// Identity reconciliation of the import.
    pub reconciliation: ImportReconciliation,
}

/// Observed outcome of one production restore composition: the
/// coordination receipt and row key plus every import outcome.
///
/// The minted admission and coordination decision travel with the
/// outcome (both `Clone`): the #963 caller needs their bound fields to
/// assemble the Store-side request mapping (identity, target,
/// provisioning, fence, digests) without re-deriving or re-spelling
/// anything the minter already bound.
#[derive(Clone, Debug)]
pub struct ProductionRestoreOutcome {
    /// Committed coordination receipt (bridge anchor).
    pub coordination_receipt: WriteReceipt,
    /// Row key the bridge re-fetches (restore operation identity).
    pub coordination_row_key: String,
    /// Minted admission all effects below executed under.
    pub admission: KernelRestoreAdmission,
    /// Coordination decision the row committed.
    pub decision: CoordinationDecision,
    /// Per-import outcomes in execution order.
    pub imports: Vec<RestoreImportOutcome>,
}

/// Drives one production restore composition end to end.
///
/// Mints the admission from live owner state, builds the coordination
/// decision, commits the coordination row, executes each restore-class
/// import under the admission, and reconciles every import by exact
/// identity. Any refusal aborts the composition closed with its exact
/// cause; effects already committed stay committed and receipted (no
/// destructive rollback — the caller reconciles by identity and resumes
/// with the same restore identity, which replays converge on).
pub async fn drive_production_restore(
    request: ProductionRestoreRequest<'_>,
) -> Result<ProductionRestoreOutcome, OwnerChannelError> {
    let ProductionRestoreRequest {
        journal,
        channels,
        verified,
        plan,
        bundle,
        destination,
        live_fence,
        provisioning,
        coordination,
        imports,
        introductions,
    } = request;
    let admission: KernelRestoreAdmission = mint_restore_admission(RestoreAdmissionMintRequest {
        plan,
        bundle,
        verified,
        journal,
        destination,
        live_fence,
        provisioning,
    })
    .map_err(OwnerChannelError::Backup)?;
    // F-AUR-1: console-presented capability introductions are compared
    // against live owner/ORS readback by the journal owner before any
    // effect (subject, fence, order, phase). Shape-only checks never
    // suffice; this gate refuses forged/stale/active rows closed.
    journal
        .verify_introductions_fenced(&introductions)
        .map_err(kernel_to_backup)
        .map_err(OwnerChannelError::Backup)?;
    let decision =
        CoordinationDecision::from_admission(&admission).map_err(OwnerChannelError::Backup)?;
    let client: CanonicalStoreImportClient = channels.store_import_client(verified);
    let CoordinationCommit {
        context: coord_context,
        transition: coord_transition,
        revision_heads: coord_revisions,
        ordering_heads: coord_orderings,
    } = coordination;
    let (coordination_receipt, coordination_row_key) = client
        .commit_coordination_row(
            verified,
            &coord_context,
            coord_transition,
            &admission.identity().operation_id,
            coord_revisions,
            coord_orderings,
            &admission,
            &decision,
            journal,
            &introductions,
        )
        .await?;
    let mut outcomes = Vec::with_capacity(imports.len());
    for import in imports {
        let RestoreImport {
            context,
            transition,
            revision_heads,
            ordering_heads,
        } = import;
        let operation_id = transition.identity.operation_id.clone();
        let fence = transition.state_fence.clone();
        let receipt = client
            .import_restore_transition(
                verified,
                &context,
                transition,
                &operation_id,
                revision_heads,
                ordering_heads,
                &admission,
                journal,
            )
            .await?;
        let reconciliation = client.reconcile_import(&fence, operation_id.clone()).await;
        outcomes.push(RestoreImportOutcome {
            operation_id: operation_id.to_string(),
            receipt,
            reconciliation,
        });
    }
    Ok(ProductionRestoreOutcome {
        coordination_receipt,
        coordination_row_key,
        admission,
        decision,
        imports: outcomes,
    })
}

/// Operator-bound production restore call (#963, H5 contract).
///
/// Everything the driver needs arrives already bound: the owner-held
/// journal and channels, Host-issued destination authorization bytes with
/// their binding expectation, the compiled plan and validated bundle, the
/// constructed destination, the live fence, provisioning proofs, and the
/// Governor-built coordination commit plus restore-class imports. The two
/// Governor-built transitions are REQUIRED inputs owned by the
/// Governor/eliotd lane (open): this caller never synthesizes, defaults,
/// or re-spells them. Truly-missing inputs are a caller-side refusal to
/// invoke, never fabricated material.
#[allow(
    dead_code,
    reason = "no H5 operator path calls into the driver yet (#963 open); remove when wired"
)]
pub struct ProductionRestoreCall<'a> {
    /// Owner-held restore journal (must already admit production).
    pub journal: &'a KernelRestoreJournal,
    /// Live owner channels (from `KernelComposition::backup_owner_channels`).
    pub channels: &'a BackupOwnerChannels,
    /// Host-issued destination authorization bytes (operator-supplied).
    pub destination_authorization: &'a [u8],
    /// Binding expectation the authorization must satisfy.
    pub authorization: AuthorizationExpectation<'a>,
    /// Compiled restore plan being executed.
    pub plan: &'a RestorePlan,
    /// Archive the plan was compiled from.
    pub bundle: &'a BackupBundle,
    /// Constructed isolated destination bound to the plan target.
    pub destination: &'a KernelIsolatedDestination,
    /// Caller-live authority fence.
    pub live_fence: &'a StateFence,
    /// Destination-store provisioning attestations.
    pub provisioning: RestoreProvisioningProof,
    /// Governor-built coordination commit (owning lane: Governor/eliotd).
    pub coordination: CoordinationCommit,
    /// Governor-built restore-class imports in execution order (owning
    /// lane: Governor/eliotd).
    pub imports: Vec<RestoreImport>,
    /// Console-presented capability introductions, verified live against
    /// owner/ORS readback by the journal owner before any effect (F-AUR-1).
    pub introductions: Vec<CapabilityIntroductionProjection>,
}

/// Invokes production restore for the H5 operator path.
///
/// Real gates before delegating to [`drive_production_restore`]: the
/// journal must already admit production durable recovery, the
/// destination authorization must verify against its expectation, and the
/// bundle must validate with its digest equal to the plan's bound archive.
/// Any refusal fails closed with the exact owner cause; nothing is
/// defaulted, minted, or retried here.
#[allow(
    dead_code,
    reason = "no H5 operator path calls into the driver yet (#963 open); remove when wired"
)]
pub async fn drive_production(
    call: ProductionRestoreCall<'_>,
) -> Result<ProductionRestoreOutcome, OwnerChannelError> {
    let ProductionRestoreCall {
        journal,
        channels,
        destination_authorization,
        authorization,
        plan,
        bundle,
        destination,
        live_fence,
        provisioning,
        coordination,
        imports,
        introductions,
    } = call;
    journal
        .require_production_admitted()
        .map_err(kernel_to_backup)
        .map_err(OwnerChannelError::Backup)?;
    let verified = verify_destination_authorization(destination_authorization, &authorization)
        .map_err(OwnerChannelError::Backup)?;
    bundle.validate().map_err(OwnerChannelError::Backup)?;
    let bundle_sha256 = bundle.bundle_sha256().map_err(OwnerChannelError::Backup)?;
    if plan.bundle_sha256 != bundle_sha256 {
        return Err(OwnerChannelError::Backup(BackupError::PlanMismatch));
    }
    drive_production_restore(ProductionRestoreRequest {
        journal,
        channels,
        verified: &verified,
        plan,
        bundle,
        destination,
        live_fence,
        provisioning,
        coordination,
        imports,
        introductions,
    })
    .await
}

/// Operator-supplied target descriptors for one production restore.
///
/// Planning inputs only (operator CLI precedent): they select the
/// restore target, never authorize it. Authority arrives exclusively
/// through the verified destination authorization, the live fence, and
/// the owner-held journal below.
pub struct DispatchTargetDescriptors<'a> {
    /// Isolated-restore target identity (planning input, not authority).
    pub target_id: &'a str,
    /// Target authority lineage UUID text (planning input).
    pub target_lineage: &'a str,
    /// Target authority sequence, nonzero (planning input).
    pub target_sequence: u64,
    /// Target Host/Kernel resource generation, nonzero (planning input).
    pub target_generation: u64,
}

/// Builds the governed target context from operator descriptors.
///
/// Every descriptor is validated with an exact cause; nothing is
/// defaulted. Lineage, sequence, and generation flow into
/// [`RestorePlan::compile`](eliot_backup::RestorePlan::compile), which
/// additionally proves the lineage advance against the archive.
fn dispatch_target_context(
    target: &DispatchTargetDescriptors<'_>,
) -> Result<RestoreContext, BackupError> {
    if target.target_id.trim().is_empty() || target.target_id.chars().any(char::is_control) {
        return Err(BackupError::InvalidField {
            field: "restore.target_id",
            reason: "must be non-blank with no control characters",
        });
    }
    let lineage_id =
        EpochLineageId::new(target.target_lineage).map_err(|_| BackupError::InvalidField {
            field: "restore.target_lineage",
            reason: "target lineage is not a canonical UUID",
        })?;
    let sequence = NonZeroU64::new(target.target_sequence).ok_or(BackupError::InvalidField {
        field: "restore.target_sequence",
        reason: "target sequence must be nonzero",
    })?;
    let authority_epoch =
        EpochId::new(lineage_id, sequence).map_err(|_| BackupError::InvalidField {
            field: "restore.target_sequence",
            reason: "target authority epoch is not admissible",
        })?;
    let resource_generation = ResourceGeneration::new(target.target_generation).map_err(|_| {
        BackupError::InvalidField {
            field: "restore.target_generation",
            reason: "target resource generation must be nonzero",
        }
    })?;
    let context = RestoreContext {
        target_id: target.target_id.to_owned(),
        target_authority_epoch: authority_epoch,
        target_resource_generation: resource_generation,
    };
    context.validate()?;
    Ok(context)
}

/// Operator dispatch assembly for one production restore (issue #963 H5).
///
/// Takes ONLY operator-legitimate inputs — archive bytes, authorization
/// bytes, planning descriptors, the live fence, console-presented
/// capability introductions, provisioning attestations, and the
/// Governor-built transitions — plus the owner-held journal, channels,
/// and adapter work root from production composition. Performs the full
/// assembly with real owner calls, in order: decode and validate the
/// archive; compile the governed plan; verify the destination
/// authorization against its plan/bundle-bound expectation; open the
/// constructed isolated destination under the adapter work root; require
/// live fence currency plus production admission on the owner-held
/// journal; validate provisioning shapes; then delegate to
/// [`drive_production_restore`]. Refuses closed with the exact owner
/// cause at every step; nothing is defaulted, minted (beyond the
/// minter's deterministic restore identity), or retried. The
/// destination pinning required later by cutover stays with the prepare
/// flow (no pin file is fabricated here).
pub async fn dispatch_production_restore(
    journal: &KernelRestoreJournal,
    channels: &BackupOwnerChannels,
    work_root: &Path,
    archive_bytes: &[u8],
    destination_authorization: &[u8],
    target: DispatchTargetDescriptors<'_>,
    live_fence: &StateFence,
    introductions: Vec<CapabilityIntroductionProjection>,
    provisioning: RestoreProvisioningProof,
    coordination: CoordinationCommit,
    imports: Vec<RestoreImport>,
) -> Result<ProductionRestoreOutcome, OwnerChannelError> {
    // 1. Decode/validate operator-supplied archive bytes (real decode,
    // fail-closed; never a substituted or defaulted bundle).
    let bundle = BackupBundle::decode(archive_bytes).map_err(OwnerChannelError::Backup)?;
    bundle.validate().map_err(OwnerChannelError::Backup)?;
    // 2. Compile the governed plan (stateless, real; lineage advance
    // proven inside against the archive).
    let plan = KernelBackupRestore::compile_plan(&bundle, dispatch_target_context(&target)?)
        .map_err(kernel_to_backup)
        .map_err(OwnerChannelError::Backup)?;
    let transaction = plan.transaction().map_err(OwnerChannelError::Backup)?;
    // 3. Verify the destination authorization against its
    // plan/bundle-bound expectation (real verifier, never file bytes).
    let config_digest = bundle
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == "config")
        .map(|artifact| artifact.sha256.as_str());
    let expectation = AuthorizationExpectation {
        target_id: plan.target.target_id.as_str(),
        transaction_id: transaction.transaction_id.as_str(),
        expected_manifest_digest: config_digest,
        kernel_work_root: work_root,
    };
    let verified = verify_destination_authorization(destination_authorization, &expectation)
        .map_err(OwnerChannelError::Backup)?;
    // 4. Open the constructed isolated destination under the adapter
    // work root bound to the plan target (constructed, never accepted
    // as an arbitrary path; foreign or source-bound labels refuse).
    let destination = KernelIsolatedDestination::open(work_root, plan.target.target_id.as_str())
        .map_err(kernel_to_backup)
        .map_err(OwnerChannelError::Backup)?;
    // 5. Require live fence currency plus production admission on the
    // owner-held journal (both re-read live, never caller asserts).
    if verified.fence_authority_generation() != live_fence.resource_generation.value() {
        return Err(OwnerChannelError::Backup(BackupError::FenceMismatch {
            subject: "destination authority generation is not current".to_owned(),
        }));
    }
    check_kernel_effect_fence(live_fence, &bundle).map_err(OwnerChannelError::Backup)?;
    journal
        .require_production_admitted()
        .map_err(kernel_to_backup)
        .map_err(OwnerChannelError::Backup)?;
    // 6. Provisioning proof shape validation (real; store truth stays
    // with the bridge readback — never claimed here).
    provisioning.validate().map_err(OwnerChannelError::Backup)?;
    // 7. Console-presented capability introductions plus the
    // Governor-built coordination commit and restore-class imports
    // arrive as params (owning lanes: console operator and
    // Governor/eliotd; never synthesized, never defaulted — the exact
    // producer contract is documented on each type).
    // 8. Delegate to the existing composition (no gate logic duplicated
    // here — mint, decision, introductions gate, commit, per-import
    // enforcement, anchor re-fetch, and reconciliation all run inside).
    drive_production_restore(ProductionRestoreRequest {
        journal,
        channels,
        verified: &verified,
        plan: &plan,
        bundle: &bundle,
        destination: &destination,
        live_fence,
        provisioning,
        coordination,
        imports,
        introductions,
    })
    .await
}
