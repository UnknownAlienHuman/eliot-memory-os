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

use eliot_backup::{BackupBundle, BackupError, RestorePlan};
use eliot_contracts::{RequestMetadata, StateFence};
use eliot_store_api::{
    OrderingHeadExpectation, PreparedTransition, RevisionHeadExpectation, WriteReceipt,
};

use super::backup_coordination::CoordinationDecision;
use super::backup_owner_clients::{
    AuthorizationExpectation, BackupOwnerChannels, CanonicalStoreImportClient, ImportReconciliation,
    OwnerChannelError, VerifiedDestinationBinding, verify_destination_authorization,
};
use super::backup_restore_admission::{
    KernelRestoreAdmission, RestoreAdmissionMintRequest, RestoreProvisioningProof,
    mint_restore_admission,
};
use super::backup_restore_ports::{
    KernelIsolatedDestination, KernelRestoreJournal, kernel_to_backup,
};

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
    } = call;
    journal
        .require_production_admitted()
        .map_err(kernel_to_backup)
        .map_err(OwnerChannelError::Backup)?;
    let verified =
        verify_destination_authorization(destination_authorization, &authorization)
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
    })
    .await
}
