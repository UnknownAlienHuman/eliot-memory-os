//! Kernel-owned production restore adapter (issue #960, lane F).
//!
//! Architecture: A13.7 Backups, Restore, and Migration (isolated restore,
//! purge-first, suspended ORS import, new lineage, separate cutover
//! authority); A13.6 Operational Recovery State (only identities, opaque
//! envelopes, epochs, suspended leases, checkpoints, intents, manifests,
//! anchors); I5.13 backup classes (full denominator, degraded ceiling,
//! key-material rule); I14.21 unknown-commit recovery (reconcile by identity,
//! never blind retry); A0.3 Hard Boundaries (no revived authority, no minted
//! epochs, no fabricated receipts); I1.8 exact ownership and call paths (one
//! logical Governor, two internal checks — this adapter never invents
//! semantics, authorizes them, and commits them alone).
//! Implementation: the single existing journaled state machine
//! ([`RestorePlan::execute_with_journal`](eliot_backup::RestorePlan::execute_with_journal))
//! drives execution and resumption — same-transaction resume is a second call
//! with the same bundle and target context, never a second engine. I5.19
//! intent-before-effect ordering and I5.27 canonical operation identity come
//! from that engine, not from this file.
//!
//! What this file owns: the thin [`KernelBackupRestore`] execution body plus
//! the [`RestoreTarget`](eliot_backup::RestoreTarget) adapter
//! (`apply_restore_effect` / `reconcile_restore_effect`) over the accepted
//! per-phase owner methods. Every phase maps to its responsible owner
//! through [`phase_owner`], and the apply path executes the genuine owner
//! operation through the live #962 owner channels with the exact bindings
//! the coordinator supplies:
//!
//! ```text
//! prepare/finalize ......... kernel-restore-owner (destination staging,
//!                              fence gate, observed evidence, verified
//!                              Host-issued destination authorization);
//! purge .................... purge owner (`PurgeOwnerClient::validate_entries`,
//!                              staged purge-first before any import);
//! canonical/receipt/
//! projection/rebuild/verify . canonical owner (`CanonicalOwnerClient`
//!                              validation plus chain coverage over observed
//!                              destination state);
//! sealed blobs ............. blob owner (`BlobOwnerClient::restore_blob`
//!                              with backup-bound restoration receipts, the
//!                              admitted key manifest, and the destination
//!                              scope; re-sealed bytes staged, never
//!                              plaintext);
//! ORS suspension ........... ORS owner (`OrsOwnerClient::suspend`,
//!                              persisted as suspended evidence, never
//!                              runnable);
//! live store import ........ canonical-store owner
//!                              (`CanonicalStoreImportClient` through the
//!                              retained `KernelStoreGateway`; the
//!                              backup-specific Store wire stays #975-owned);
//! lease invalidation ........ supervision-lease owner
//!                              (`InvalidationOwnerClient::revoke_lease`,
//!                              cutover-gated, invoked by the #961 cutover
//!                              executor with a terminal ticket).
//! ```
//!
//! The Host-issued destination authorization gates every effect: `restore`
//! reads the pinned `destination-authorization.json` the Host-authorized
//! preparation flow wrote, verifies it through
//! [`verify_destination_authorization`](super::backup_owner_clients::verify_destination_authorization)
//! (wire/issuer identity, exact target/transaction binding, digest shapes,
//! work-root containment, manifest agreement), and every effect client
//! binds the resulting verification. An absent or invalid authorization
//! refuses with the exact missing owner before any effect — rehearsal
//! without Host admission is refused, not staged.
//!
//! ```text
//! prepare/finalize ......... kernel-restore-owner (destination staging,
//!                              fence gate, observed evidence);
//! purge .................... purge owner (`apply_purge_ledger`, staged
//!                              purge-first before any import);
//! canonical/receipt/
//! projection/rebuild/verify . canonical owner (`import_*`, chain + count
//!                              verification over observed destination state);
//! sealed blobs ............. blob owner (`DestinationRestoreAdapter::
//!                              restore_blob_sealed` with backup-bound
//!                              restoration receipts, the admitted key
//!                              manifest, and the destination scope;
//!                              re-sealed bytes staged, never plaintext);
//! ORS suspension ........... ORS owner (`suspended_recovery_entries`,
//!                              persisted as suspended evidence, never
//!                              runnable);
//! ```
//!
//! Effects whose bindings are absent refuse fail-closed with the exact
//! responsible capability; reconciliation answers from persisted identity
//! receipts (`Applied` on exact transaction/phase/input match, `NotApplied`
//! otherwise). All effects in this target are synchronous and local with a
//! persisted identity receipt per phase, so no ambiguous external commit
//! exists here and no `Unknown` outcome is manufactured: live store imports
//! reconcile through `CanonicalStoreImportClient` by exact operation
//! identity, never by downgrading readback to a blind re-apply here.
//!
//! Capability cell: Kernel restore ownership (isolated import execution).
//! Forbidden authority: no ORS row reinterpretation, no epoch minting, no
//! cutover, no activation/retirement of any installation, no second phase
//! engine, no archive/phase algorithm, no invented target methods, no
//! Value-based escapes.

use std::path::PathBuf;

use eliot_backup::{
    BackupBlob, BackupBundle, BackupError, BlobRestorationReceipt, CanonicalRecord,
    CutoverAuthorization, CutoverReceipt, DestinationRestoreAdapter, DestinationScope,
    IsolatedRestorePlan, OrsSnapshotFence, RestoreAppliedEffect, RestoreArchiveDisposition,
    RestoreArchiveDispositionKind, RestoreContext, RestoreEffectReceipt, RestoreEvidence,
    RestoreHistoricalAuthority, RestoreIntent, RestoreObligationState, RestoreOwnerObligation,
    RestorePhase, RestorePlan, RestoreReceipt, RestoreReconciliation, RestoreStep, RestoreTarget,
    RestoredFence, RestoredSealedBlob, WrappedKeyManifest, authorize_cutover,
    suspended_recovery_entries,
};
use eliot_backup::{ObservedLineageLimit, OwnerTrustBinding, RestoreObligations, RestoreProvenance};
use eliot_contracts::{EpochId, ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex};
use eliot_security_contracts::PurgeLedgerEntry;
use eliot_store_api::WriteReceipt;
use serde::Serialize;

use super::backup_restore_ports::{
    DestinationManifestEvidence, KernelIsolatedDestination, KernelRestoreError, KernelRestoreJournal,
    check_kernel_effect_fence,
};

/// Maps one accepted restore step to its responsible owner.
///
/// The owner vocabulary matches the obligation owner ids carried in restore
/// evidence, so every executed phase is attributable to exactly one owner.
#[must_use]
pub const fn phase_owner(step: &RestoreStep) -> &'static str {
    match step {
        RestoreStep::PrepareIsolatedRoot | RestoreStep::FinalizeIsolatedRoot => {
            "kernel-restore-owner"
        }
        RestoreStep::ApplyPurgeLedger => owners::PURGE,
        RestoreStep::ImportSealedBlobs => owners::BLOB,
        RestoreStep::ImportCanonicalEvents
        | RestoreStep::ImportReceipts
        | RestoreStep::ImportProjections
        | RestoreStep::RebuildProjections
        | RestoreStep::VerifyReceiptEventChain => owners::CANONICAL,
        RestoreStep::SuspendOrsOperations => owners::ORS,
    }
}

/// Owner obligation identifiers and missing-binding capabilities shared by
/// the phase matrix, refusal errors, and evidence.
mod owners {
    pub const PURGE: &str = "purge-owner";
    pub const CANONICAL: &str = "canonical-owner";
    pub const REFERENCE: &str = "reference-owner";
    pub const BLOB: &str = "blob-owner";
    pub const ORS: &str = "ors-owner";
    pub const RECONCILIATION: &str = "reconciliation-owner";
    pub const WATCHDOG: &str = "watchdog-owner";
    pub const EXTERNAL_SOURCE: &str = "external-source-owner";
    pub const RUNTIME: &str = "runtime-owner";
    pub const SESSION: &str = "session-owner";
    pub const LEASE: &str = "lease-owner";
    pub const ROUTE: &str = "route-owner";
    pub const USER_BROKER: &str = "user-broker-owner";
    /// Missing destination blob-scope admission (#956/#958) for sealed-blob
    /// restoration under destination ownership.
    pub const BLOB_SCOPE_BINDING: &str = "blob-destination-scope";
}

/// Live #962 owner channels this adapter executes through.
///
/// Replacement (a replacement replaces): the staging-only owner clients
/// previously defined in this file are superseded by the live
/// [`backup_owner_clients`](super::backup_owner_clients) wire, which
/// executes every effect through its responsible owner's accepted API under
/// a verified Host-issued destination authorization. The `owners`
/// obligation vocabulary above is retained for phase attribution and
/// evidence; every effect call site below binds the live clients.
use super::backup_owner_clients::{
    AuthorizationExpectation, BlobOwnerClient, CanonicalOwnerClient, OrsOwnerClient,
    PurgeOwnerClient, VerifiedDestinationBinding, verify_destination_authorization,
};

/// Outcome of one Kernel-executed isolated restore: the journaled receipt,
/// target-observed evidence when this process executed finalize (or the
/// resumed run's evidence file re-validated), suspended work, the exact
/// applied phase log, and the observed paths. No cutover, activation, or
/// retirement is performed or reported.
#[derive(Clone, Debug, PartialEq)]
pub struct KernelRestoreOutcome {
    pub receipt: RestoreReceipt,
    pub evidence: Option<RestoreEvidence>,
    pub suspended_entries: Vec<RestoreHistoricalAuthority>,
    pub phase_log: Vec<String>,
    pub destination_root: PathBuf,
    pub journal_owner: String,
}

/// Kernel-owned production restore adapter.
///
/// Owns the admitted durable journal and the constructed (not accepted)
/// isolated destination. Execution binds one archive, one plan context, the
/// Kernel's current effect fence, key material, and the destination blob
/// scope. The adapter never mints epochs, never activates authority, and
/// never performs cutover. Re-running with the same bundle and target
/// context resumes the same transaction from the durable ORS journal instead
/// of re-applying.
pub struct KernelBackupRestore {
    journal: KernelRestoreJournal,
    work_root: PathBuf,
}

impl KernelBackupRestore {
    /// Binds the restore owner to an owner-handled journal and work root.
    ///
    /// The journal must already bind the actual existing ORS owner
    /// ([`KernelRestoreJournal::bind_owner`]) because no second database may
    /// be opened here; it starts unadmitted and unbound, and [`restore`](Self::restore)
    /// binds admission plus the transaction stream. There is no file-backed
    /// constructor: a second writer path must not exist even as an option.
    pub fn bind(journal: KernelRestoreJournal, work_root: PathBuf) -> Self {
        Self { journal, work_root }
    }

    /// Returns the bound journal (admission, stream binding, inspection).
    pub fn journal(&mut self) -> &mut KernelRestoreJournal {
        &mut self.journal
    }

    /// Compiles the governed plan for one archive and target context.
    ///
    /// Runs the accepted [`RestorePlan::compile`](eliot_backup::RestorePlan::compile)
    /// validation (bundle, checksums, schema, purge binding, class
    /// denominator, lineage advance) with no effects, for composition
    /// diagnostics before execution.
    pub fn compile_plan(
        bundle: &BackupBundle,
        target: RestoreContext,
    ) -> Result<RestorePlan, KernelRestoreError> {
        bundle
            .validate()
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        RestorePlan::compile(bundle, target)
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))
    }

    /// Executes (or resumes) one isolated restore under the Kernel effect fence.
    ///
    /// `kernel_fence` is the Kernel's current authority fence supplied by the
    /// production caller (never caller arithmetic inside this adapter): the
    /// archive fence must be compatible with it before any effect, otherwise
    /// the restore is refused with zero target effects. Blob-carrying
    /// archives require exact key coverage plus the destination blob scope;
    /// a fixture-flagged journal admission refuses as not admitted for
    /// production. `manifest_evidence`, when supplied, binds the
    /// owner-approved destination scope: its shapes validate, its work root
    /// must canonicalize-equal this Kernel's own work root, and its manifest
    /// digest must equal the archive's `config` artifact when the archive
    /// carries one; the values pin at prepare and any drift refuses later
    /// effects and cutover. Coordinator failures propagate typed in
    /// [`KernelRestoreError::TargetFailed`]; the primary error is preserved,
    /// never flattened into a fabricated success.
    pub fn restore(
        &mut self,
        bundle: &BackupBundle,
        target: RestoreContext,
        kernel_fence: &StateFence,
        keys: Option<&WrappedKeyManifest>,
        blob_scope: Option<&DestinationScope>,
        manifest_evidence: Option<DestinationManifestEvidence>,
    ) -> Result<KernelRestoreOutcome, KernelRestoreError> {
        bundle
            .validate()
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        self.journal.require_production_admitted()?;
        if !bundle
            .export_fence
            .state_fence
            .is_compatible_with(kernel_fence)
        {
            return Err(KernelRestoreError::FenceMismatch(
                "archive fence is not compatible with the Kernel effect fence".to_owned(),
            ));
        }
        if let Some(manifest) = keys {
            BlobOwnerClient::ensure_key_coverage(&bundle.blobs, manifest)
                .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        } else if !bundle.blobs.is_empty() {
            return Err(KernelRestoreError::CapabilityMissing {
                capability: "blob_key_material",
            });
        }
        if !bundle.blobs.is_empty() && blob_scope.is_none() {
            return Err(KernelRestoreError::CapabilityMissing {
                capability: owners::BLOB_SCOPE_BINDING,
            });
        }
        if let Some(evidence) = manifest_evidence.as_ref() {
            self.check_manifest_evidence(bundle, evidence)?;
        }
        let plan = RestorePlan::compile(bundle, target.clone())
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        self.journal
            .bind_plan_stream(&plan, bundle, kernel_fence)?;
        let destination = KernelIsolatedDestination::open(&self.work_root, &target.target_id)?;
        // #962 issuer gate: the Host-authorized preparation flow pinned the
        // destination authorization before restore; every effect below binds
        // its verification. Absence refuses with the exact missing owner.
        let verified =
            self.verify_destination_binding(&destination, &plan, bundle, manifest_evidence.as_ref())?;
        let receipts = match keys {
            Some(manifest) => BlobOwnerClient::issue_receipts(
                bundle.manifest.backup_id.as_str(),
                manifest,
                &bundle.blobs,
            )
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?,
            None => Vec::new(),
        };
        let mut target_impl = KernelRestoreTarget::new(
            &destination,
            kernel_fence.clone(),
            keys,
            blob_scope,
            receipts,
            manifest_evidence,
            verified,
        );
        let receipt = plan
            .execute_with_journal(bundle, &mut target_impl, &mut self.journal)
            .map_err(KernelRestoreError::TargetFailed)?;
        let suspended = suspended_entries(bundle)?;
        let evidence = target_impl
            .final_evidence
            .clone()
            .or_else(|| read_resumed_evidence(&target_impl.root));
        let journal_owner = match self.journal.bound_stream() {
            Some(stream) => format!("{}:{stream}", self.journal.owner_label()),
            None => self.journal.owner_label().to_owned(),
        };
        Ok(KernelRestoreOutcome {
            receipt,
            evidence,
            suspended_entries: suspended,
            phase_log: target_impl.calls,
            destination_root: target_impl.root,
            journal_owner,
        })
    }

    /// Checks owner-approved manifest evidence against this Kernel's work
    /// root and the archive's `config` artifact before effects: shapes
    /// validate, the admitted work root must canonicalize-equal this
    /// Kernel's own work root, and the admitted manifest digest must equal
    /// the archive's `config` artifact when the archive carries one. The
    /// values pin at prepare and any drift refuses later effects and
    /// cutover.
    fn check_manifest_evidence(
        &self,
        bundle: &BackupBundle,
        evidence: &DestinationManifestEvidence,
    ) -> Result<(), KernelRestoreError> {
        evidence.validate()?;
        let own_root = std::fs::canonicalize(&self.work_root)
            .map_err(|error| KernelRestoreError::DestinationInvalid(error.to_string()))?;
        let admitted_root = std::fs::canonicalize(&evidence.kernel_work_root).map_err(
            |error| KernelRestoreError::DestinationInvalid(error.to_string()),
        )?;
        if own_root != admitted_root {
            return Err(KernelRestoreError::DestinationInvalid(
                "admitted work root does not match the Kernel work root".to_owned(),
            ));
        }
        if let Some(config) = bundle
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == "config")
            && config.sha256 != evidence.manifest_digest
        {
            return Err(KernelRestoreError::FenceMismatch(
                "destination manifest".to_owned(),
            ));
        }
        Ok(())
    }

    /// Reads the Host-issued destination authorization pinned by the
    /// Host-authorized preparation flow and verifies it for this exact
    /// plan, bundle, and work root.
    ///
    /// Wire/issuer identity, exact target/transaction binding, digest
    /// shapes, work-root containment, and manifest agreement are all
    /// re-proven through the #962 verifier. When owner-approved manifest
    /// evidence is supplied, its projection must agree with the issuer
    /// bytes. Any refusal fails closed with the exact missing owner before
    /// any effect; cutover re-verifies freshness through this same gate.
    fn verify_destination_binding(
        &self,
        destination: &KernelIsolatedDestination,
        plan: &RestorePlan,
        bundle: &BackupBundle,
        manifest_evidence: Option<&DestinationManifestEvidence>,
    ) -> Result<VerifiedDestinationBinding, KernelRestoreError> {
        let transaction = plan
            .transaction()
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        let expected_manifest_digest = bundle
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == "config")
            .map(|artifact| artifact.sha256.as_str());
        let auth_bytes = destination.read_destination_authorization()?;
        let verified = verify_destination_authorization(
            &auth_bytes,
            &AuthorizationExpectation {
                target_id: plan.target.target_id.as_str(),
                transaction_id: transaction.transaction_id.as_str(),
                expected_manifest_digest,
                kernel_work_root: &self.work_root,
            },
        )
        .map_err(KernelRestoreError::TargetFailed)?;
        if let Some(evidence) = manifest_evidence {
            evidence.validate()?;
            if evidence.manifest_digest != verified.manifest_digest()
                || evidence.roots_digest != verified.roots_digest()
                || evidence.registry_revision != verified.registry_revision()
            {
                return Err(KernelRestoreError::DestinationInvalid(
                    "destination admission drifted from the Host-issued authorization".to_owned(),
                ));
            }
        }
        Ok(verified)
    }

    /// Validates cutover inputs without effects: separate cutover
    /// authorization, receipt/plan/target binding, observed evidence with
    /// its complete validation denominator (any applicable unresolved
    /// effect, missing receipt, or unknown reconciliation without its
    /// complete current denominator refuses qualification).
    fn check_cutover_inputs(
        plan: &RestorePlan,
        bundle: &BackupBundle,
        receipt: &RestoreReceipt,
        evidence: Option<&RestoreEvidence>,
        auth: Option<&CutoverAuthorization>,
    ) -> Result<(), KernelRestoreError> {
        let auth = auth.ok_or(KernelRestoreError::CutoverNotAuthorized)?;
        auth.validate()
            .map_err(|error| KernelRestoreError::OwnerEvidenceInvalid(error.to_string()))?;
        if receipt.plan_id != plan.plan_id
            || receipt.bundle_sha256 != plan.bundle_sha256
            || receipt.target_id != plan.target.target_id
        {
            return Err(KernelRestoreError::ArchiveInvalid(
                "restore receipt does not bind this plan and target".to_owned(),
            ));
        }
        let evidence = evidence.ok_or(KernelRestoreError::OwnerEvidenceInvalid(
            "no observed restore evidence".to_owned(),
        ))?;
        evidence.validate().map_err(KernelRestoreError::TargetFailed)?;
        evidence
            .validate_against_plan(plan, bundle)
            .map_err(KernelRestoreError::TargetFailed)?;
        require_cutover_obligations(&evidence.obligations, bundle)
            .map_err(KernelRestoreError::TargetFailed)?;
        Ok(())
    }

    /// Loads the pinned destination admission and re-proves the Host-issued
    /// authorization for cutover: readback reconciliation with owner
    /// evidence gates the decision; any drift refuses instead of cutting
    /// over.
    fn load_verified_destination_admission(
        &self,
        destination: &KernelIsolatedDestination,
        plan: &RestorePlan,
        bundle: &BackupBundle,
    ) -> Result<PinnedDestinationAdmission, KernelRestoreError> {
        let admission_bytes = std::fs::read(destination.root().join(DESTINATION_ADMISSION_FILE))
            .map_err(|_| {
                KernelRestoreError::DestinationInvalid(
                    "no owner-approved destination admission pinned".to_owned(),
                )
            })?;
        let pinned: PinnedDestinationAdmission =
            serde_json::from_slice(&admission_bytes).map_err(|_| {
                KernelRestoreError::DestinationInvalid(
                    "pinned destination admission is corrupt".to_owned(),
                )
            })?;
        self.verify_destination_binding(destination, plan, bundle, Some(&pinned.evidence))?;
        Ok(pinned)
    }

    /// Validates the #961 cutover path for one completed isolated restore:
    /// owner-approved isolated destination, separate cutover authority,
    /// epoch lineage strictly newer than every observed value, and a
    /// complete validation denominator in the observed evidence.
    ///
    /// Consumes only authenticated evidence: the accepted owner
    /// authorization (bound to this exact plan and bundle), the completed
    /// restore receipt (bound to this exact plan, bundle, and target), the
    /// observed restore evidence (validated, plan-bound, and obligation
    /// complete — any applicable unresolved effect, missing receipt, or
    /// unknown reconciliation without its complete current denominator
    /// refuses cutover qualification; suspension is not resolution), the
    /// pinned destination admission (owner-approved manifest evidence bound
    /// at prepare — absent without Host admission, and cutover refuses
    /// without it), the ORS owner's durably held stream binding
    /// (destination and transaction cross-check — a rotated authority or
    /// drifted archive refuses instead of continuing), and the freshly
    /// re-validated restored fence (lineage advance re-proven here with no
    /// caller arithmetic on epochs). The accepted [`authorize_cutover`](eliot_backup::authorize_cutover)
    /// mints the receipt; a degraded archive keeps its `canonical_only`
    /// marking and is never upgraded. The decision is journaled to the
    /// bound ORS stream with the exact observed predecessor, preserving
    /// intent-before-effect ordering for cutover too.
    ///
    /// This path performs NO activation, retirement, route/process mutation,
    /// or live-authority invalidation: cutover execution belongs to the
    /// installer/Hume owner (#961), whose files are untouched here.
    /// Rehearsal is safe by construction — there is simply no effect to
    /// rehearse beyond validation and journaling the decision.
    pub fn request_cutover(
        &mut self,
        plan: &RestorePlan,
        bundle: &BackupBundle,
        receipt: &RestoreReceipt,
        evidence: Option<&RestoreEvidence>,
        destination: &KernelIsolatedDestination,
        auth: Option<&CutoverAuthorization>,
    ) -> Result<CutoverReceipt, KernelRestoreError> {
        Self::check_cutover_inputs(plan, bundle, receipt, evidence, auth)?;
        let auth = auth.ok_or(KernelRestoreError::CutoverNotAuthorized)?;
        if destination.label() != plan.target.target_id
            || !destination.root().starts_with(&self.work_root)
        {
            return Err(KernelRestoreError::DestinationInvalid(
                "cutover destination is not the plan-admitted isolated root".to_owned(),
            ));
        }
        let pinned =
            self.load_verified_destination_admission(destination, plan, bundle)?;
        let transaction = plan
            .transaction()
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        if pinned.transaction_id != transaction.transaction_id
            || pinned.target_id != plan.target.target_id
        {
            return Err(KernelRestoreError::JournalBindingConflict);
        }
        plan.restored_fence
            .validate()
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        let stream = self
            .journal
            .bound_stream()
            .ok_or(KernelRestoreError::JournalNotAdmitted)?;
        let durable = self
            .journal
            .read_durable_binding(stream)
            .map_err(KernelRestoreError::TargetFailed)?
            .ok_or(KernelRestoreError::JournalNotAdmitted)?;
        if durable.transaction_id != transaction.transaction_id
            || durable.destination_ref != plan.target.target_id
            || durable.source_archive_id != bundle.manifest.backup_id
        {
            return Err(KernelRestoreError::JournalBindingConflict);
        }
        let carrier = IsolatedRestorePlan {
            plan: plan.clone(),
            suspended_entries: suspended_entries(bundle)?,
            restored_fence: plan.restored_fence.clone(),
            root: destination.root().to_path_buf(),
            bundle_sha256: plan.bundle_sha256.clone(),
            canonical_only: bundle.manifest.class.is_canonical_only(),
        };
        let cutover = authorize_cutover(&carrier, Some(auth))
            .map_err(KernelRestoreError::TargetFailed)?;
        cutover
            .validate()
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        let decision = ObservedCutoverDecision {
            plan_id: plan.plan_id.clone(),
            bundle_sha256: plan.bundle_sha256.clone(),
            target_id: plan.target.target_id.clone(),
            destination: destination.root().to_string_lossy().into_owned(),
            authorized_by: auth.authorized_by.clone(),
            manifest_digest: pinned.evidence.manifest_digest.clone(),
            roots_digest: pinned.evidence.roots_digest.clone(),
            registry_revision: pinned.evidence.registry_revision,
            new_authority_epoch: cutover.new_authority_epoch.clone(),
            new_resource_generation: cutover.new_resource_generation,
            canonical_only: cutover.canonical_only,
        };
        let payload_bytes = canonical_json_bytes(&decision)
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        let payload = String::from_utf8(payload_bytes.clone()).map_err(|_| {
            KernelRestoreError::ArchiveInvalid(
                "cutover decision payload is not UTF-8".to_owned(),
            )
        })?;
        let plan_bytes = canonical_json_bytes(&plan.plan_id)
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        let request_bytes = canonical_json_bytes(&(
            transaction.transaction_id.as_str(),
            plan.plan_id.as_str(),
            auth.authorized_by.as_str(),
        ))
        .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        self.journal
            .append_decision_row(
                format!("cutover-decision-{}", sha256_hex(&plan_bytes)),
                sha256_hex(&request_bytes),
                payload,
            )
            .map_err(KernelRestoreError::TargetFailed)?;
        Ok(cutover)
    }
}

fn suspended_entries(
    bundle: &BackupBundle,
) -> Result<Vec<RestoreHistoricalAuthority>, KernelRestoreError> {
    match &bundle.ors_snapshot {
        Some(snapshot) => suspended_recovery_entries(snapshot)
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string())),
        None => Ok(Vec::new()),
    }
}

/// Requires the validation denominator for cutover qualification: every
/// applicable owner obligation satisfied by its exact owner, with
/// blob/ORS suspension excused exactly when the archive carries no blobs
/// or ORS snapshot to suspend.
///
/// A `MissingCapability` or `Unknown` anywhere — unresolved effects, stale
/// authority, unverifiable keys, incomplete closure, absent denominator —
/// refuses with the exact obligation slot: suspension is not resolution
/// and a `FullRecovery` class is not operational readiness. An applicable
/// obligation left `NotAttempted` contradicts the archive the evidence was
/// built from and fails as corruption rather than qualifying. Known-zero
/// unresolved work passes only through a satisfied reconciliation
/// obligation backed by its complete current denominator, which only the
/// exact reconciliation owner can issue.
fn require_cutover_obligations(
    obligations: &RestoreObligations,
    bundle: &BackupBundle,
) -> Result<(), BackupError> {
    fn require(
        capability: &'static str,
        obligation: &RestoreOwnerObligation,
        applicable: bool,
    ) -> Result<(), BackupError> {
        match obligation.state {
            RestoreObligationState::Satisfied => Ok(()),
            RestoreObligationState::NotAttempted if !applicable => Ok(()),
            RestoreObligationState::NotAttempted => Err(BackupError::RestoreJournalCorrupt),
            _ => Err(BackupError::RestoreCapabilityUnsupported { capability }),
        }
    }
    let list: [(&RestoreOwnerObligation, &'static str, bool); 13] = [
        (&obligations.purge, owners::PURGE, true),
        (
            &obligations.canonical_validation,
            owners::CANONICAL,
            true,
        ),
        (
            &obligations.reference_validation,
            owners::REFERENCE,
            true,
        ),
        (
            &obligations.blob_validation,
            owners::BLOB,
            !bundle.blobs.is_empty(),
        ),
        (
            &obligations.ors_suspension,
            owners::ORS,
            bundle.ors_snapshot.is_some(),
        ),
        (
            &obligations.unresolved_effect_reconciliation,
            owners::RECONCILIATION,
            true,
        ),
        (&obligations.watchdog_signals, owners::WATCHDOG, true),
        (
            &obligations.external_source_revalidation,
            owners::EXTERNAL_SOURCE,
            true,
        ),
        (&obligations.runtime_invalidation, owners::RUNTIME, true),
        (&obligations.session_invalidation, owners::SESSION, true),
        (&obligations.lease_invalidation, owners::LEASE, true),
        (&obligations.route_invalidation, owners::ROUTE, true),
        (
            &obligations.user_broker_invalidation,
            owners::USER_BROKER,
            true,
        ),
    ];
    for (obligation, capability, applicable) in list {
        require(capability, obligation, applicable)?;
    }
    Ok(())
}

/// Re-reads the evidence file of a resumed run whose finalize executed in a
/// previous process. Best effort: the bytes are deterministic for the
/// transaction, so a present and valid file yields the identical value the
/// coordinator certified; absence or invalidity yields `None` rather than
/// self-attested evidence this process never observed.
fn read_resumed_evidence(root: &std::path::Path) -> Option<RestoreEvidence> {
    let bytes = std::fs::read(root.join("evidence.json")).ok()?;
    let evidence: RestoreEvidence = serde_json::from_slice(&bytes).ok()?;
    evidence.validate().ok()?;
    Some(evidence)
}

/// Kernel-observed cutover decision journaled to the bound ORS stream: the
/// exact validated authorization, bound plan/archive/destination, and the
/// new lineage the accepted cutover function minted. Observation of a
/// validated decision, never an activation.
#[derive(Serialize)]
struct ObservedCutoverDecision {
    plan_id: String,
    bundle_sha256: String,
    target_id: String,
    destination: String,
    authorized_by: String,
    manifest_digest: String,
    roots_digest: String,
    registry_revision: u64,
    new_authority_epoch: EpochId,
    new_resource_generation: ResourceGeneration,
    canonical_only: bool,
}

/// Pinned destination admission: the owner-approved manifest evidence bound
/// to one restore transaction and target. Written once at prepare,
/// re-verified before later effects and at cutover; any drift refuses.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedDestinationAdmission {
    transaction_id: String,
    target_id: String,
    evidence: DestinationManifestEvidence,
}

/// Admission file name inside the isolated destination.
const DESTINATION_ADMISSION_FILE: &str = "destination-admission.json";

/// Kernel-observed prepare evidence: the exact intent executed, bound to the
/// compiled plan and the constructed destination. Observation, not authority.
#[derive(Serialize)]
struct ObservedPrepare {
    transaction_id: String,
    plan_id: String,
    destination: String,
    outcome: String,
}

/// Kernel-observed blob restoration: re-sealed digest, consumed receipt, and
/// lineage binding. No plaintext or key bytes cross this boundary.
#[derive(Serialize)]
struct ObservedBlobRestore {
    resealed_sha256: String,
    receipt_id: String,
    key_lineage: String,
    source_plaintext_sha256: String,
}

/// Reconcile observation for one intent: exact applied receipt, proven
/// non-attempt, or undecidable bytes. Undecidable never becomes success.
enum ObservedEffect {
    Applied(RestoreAppliedEffect),
    NotAttempted,
    Undecidable,
}

/// Kernel restore target over the accepted effect seam.
///
/// Every applicable phase re-checks the Kernel effect fence before touching
/// state, executes the genuine responsible-owner operation with the exact
/// bindings the coordinator supplies, persists exact bytes, and returns an
/// observed receipt. Reconciliation answers from persisted identity receipts
/// only.
struct KernelRestoreTarget<'a> {
    root: PathBuf,
    kernel_fence: StateFence,
    keys: Option<&'a WrappedKeyManifest>,
    blob_scope: Option<&'a DestinationScope>,
    receipts: Vec<BlobRestorationReceipt>,
    manifest_evidence: Option<DestinationManifestEvidence>,
    verified: VerifiedDestinationBinding,
    calls: Vec<String>,
    final_evidence: Option<RestoreEvidence>,
}

impl<'a> KernelRestoreTarget<'a> {
    fn new(
        destination: &KernelIsolatedDestination,
        kernel_fence: StateFence,
        keys: Option<&'a WrappedKeyManifest>,
        blob_scope: Option<&'a DestinationScope>,
        receipts: Vec<BlobRestorationReceipt>,
        manifest_evidence: Option<DestinationManifestEvidence>,
        verified: VerifiedDestinationBinding,
    ) -> Self {
        Self {
            root: destination.root().to_path_buf(),
            kernel_fence,
            keys,
            blob_scope,
            receipts,
            manifest_evidence,
            verified,
            calls: Vec::new(),
            final_evidence: None,
        }
    }

    /// Re-checks the Kernel effect fence before an applicable phase.
    fn gate(&self, bundle: &BackupBundle) -> Result<(), BackupError> {
        check_kernel_effect_fence(&self.kernel_fence, bundle)
    }

    fn write_file(&self, relative: &str, bytes: &[u8]) -> Result<(), BackupError> {
        // Atomic temp-write + rename: a crash never leaves a torn receipt
        // that later reads as success. An unparseable receipt still reports
        // Unknown (rollback disposition), never a fabricated outcome.
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| BackupError::Target(error.to_string()))?;
        }
        let tmp = path.with_extension("tmp-restore");
        std::fs::write(&tmp, bytes).map_err(|error| BackupError::Target(error.to_string()))?;
        std::fs::rename(&tmp, &path).map_err(|error| BackupError::Target(error.to_string()))
    }

    fn phase_receipt_path(&self, phase: &RestorePhase) -> Result<PathBuf, BackupError> {
        let bytes = canonical_json_bytes(phase)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        Ok(self
            .root
            .join("phase-receipts")
            .join(format!("{}.json", sha256_hex(&bytes))))
    }

    fn effect_receipt(
        intent: &RestoreIntent,
        evidence_bytes: &[u8],
    ) -> Result<RestoreEffectReceipt, BackupError> {
        let phase_bytes = canonical_json_bytes(&intent.phase)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        Ok(RestoreEffectReceipt {
            transaction_id: intent.transaction_id.clone(),
            phase: intent.phase.clone(),
            input_digest: intent.input_digest.clone(),
            external_identity_sha256: sha256_hex(&phase_bytes),
            evidence_sha256: sha256_hex(evidence_bytes),
        })
    }

    fn persist_applied(
        &self,
        intent: &RestoreIntent,
        applied: &RestoreAppliedEffect,
    ) -> Result<(), BackupError> {
        let bytes = canonical_json_bytes(applied)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        let relative = self
            .phase_receipt_path(&intent.phase)?
            .strip_prefix(&self.root)
            .map_err(|_| BackupError::RestoreJournalCorrupt)?
            .to_string_lossy()
            .into_owned();
        self.write_file(&relative, &bytes)
    }

    fn load_applied(
        &self,
        intent: &RestoreIntent,
    ) -> Result<ObservedEffect, BackupError> {
        let path = self.phase_receipt_path(&intent.phase)?;
        if !path.exists() {
            return Ok(ObservedEffect::NotAttempted);
        }
        let bytes = std::fs::read(&path).map_err(|error| BackupError::Target(error.to_string()))?;
        let applied: RestoreAppliedEffect = match serde_json::from_slice(&bytes) {
            Ok(applied) => applied,
            // Torn or foreign bytes: the effect state cannot be established
            // from this observation. Propagate Unknown so the coordinator
            // takes the explicit rollback-required disposition (I14.21);
            // never guess, never blind-retry.
            Err(_) => return Ok(ObservedEffect::Undecidable),
        };
        if applied.receipt.transaction_id != intent.transaction_id
            || applied.receipt.phase != intent.phase
            || applied.receipt.input_digest != intent.input_digest
        {
            return Err(BackupError::RestoreJournalCorrupt);
        }
        Ok(ObservedEffect::Applied(applied))
    }

    /// Re-verifies the pinned destination admission before a post-prepare
    /// effect. Unadmitted restores skip; admitted ones require the exact
    /// pinned transaction, target, and manifest evidence — any drift
    /// refuses the effect instead of continuing under changed authority.
    fn check_destination_admission(
        &self,
        intent: &RestoreIntent,
        plan_target_id: &str,
    ) -> Result<(), BackupError> {
        let Some(expected) = self.manifest_evidence.as_ref() else {
            return Ok(());
        };
        let bytes = std::fs::read(self.root.join(DESTINATION_ADMISSION_FILE))
            .map_err(|_| BackupError::RestoreJournalCorrupt)?;
        let pinned: PinnedDestinationAdmission =
            serde_json::from_slice(&bytes).map_err(|_| BackupError::RestoreJournalCorrupt)?;
        if pinned.transaction_id != intent.transaction_id
            || pinned.target_id != plan_target_id
            || pinned.evidence != *expected
        {
            return Err(BackupError::FenceMismatch {
                subject: "destination admission".to_owned(),
            });
        }
        Ok(())
    }

    fn find_blob<'b>(
        bundle: &'b BackupBundle,
        hash: &str,
    ) -> Result<&'b BackupBlob, BackupError> {
        bundle
            .blobs
            .iter()
            .find(|blob| blob.locator.hash.as_str() == hash)
            .ok_or(BackupError::PlanMismatch)
    }

    fn find_event<'b>(
        records: &'b [CanonicalRecord],
        record_id: &str,
    ) -> Result<&'b CanonicalRecord, BackupError> {
        records
            .iter()
            .find(|record| record.record_id == record_id)
            .ok_or(BackupError::PlanMismatch)
    }

    fn staged_bytes(&self, relative: &str) -> Result<Vec<u8>, BackupError> {
        std::fs::read(self.root.join(relative))
            .map_err(|error| BackupError::Target(error.to_string()))
    }

    fn count_dir(&self, relative: &str) -> Result<usize, BackupError> {
        let path = self.root.join(relative);
        if !path.exists() {
            return Ok(0);
        }
        let mut count = 0;
        let entries =
            std::fs::read_dir(&path).map_err(|error| BackupError::Target(error.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|error| BackupError::Target(error.to_string()))?;
            if entry
                .file_type()
                .map_err(|error| BackupError::Target(error.to_string()))?
                .is_file()
            {
                count += 1;
            }
        }
        Ok(count)
    }

    fn apply_prepare(
        &mut self,
        plan: &RestorePlan,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        self.prepare_isolated(&plan.target, &plan.restored_fence)?;
        self.gate(bundle)?;
        if let Some(evidence) = self.manifest_evidence.clone() {
            let pinned = PinnedDestinationAdmission {
                transaction_id: intent.transaction_id.clone(),
                target_id: plan.target.target_id.clone(),
                evidence,
            };
            let bytes = canonical_json_bytes(&pinned)
                .map_err(|error| BackupError::Serialization(error.to_string()))?;
            self.write_file(DESTINATION_ADMISSION_FILE, &bytes)?;
        }
        let observed = ObservedPrepare {
            transaction_id: intent.transaction_id.clone(),
            plan_id: plan.plan_id.clone(),
            destination: self.root.to_string_lossy().into_owned(),
            outcome: "prepared".to_owned(),
        };
        let evidence_bytes = canonical_json_bytes(&observed)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        let applied = RestoreAppliedEffect {
            receipt: Self::effect_receipt(intent, &evidence_bytes)?,
            final_evidence: None,
        };
        self.persist_applied(intent, &applied)?;
        self.calls.push("prepare".to_owned());
        Ok(applied)
    }

    fn apply_blob(
        &mut self,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
        hash: &str,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        self.gate(bundle)?;
        let blob = Self::find_blob(bundle, hash)?;
        let client = BlobOwnerClient::bind(
            self.receipts.clone(),
            self.keys,
            self.blob_scope,
            &self.verified,
        )?;
        let adapter = DestinationRestoreAdapter::bind(self.root.as_path())?;
        let restored: RestoredSealedBlob =
            client.restore_blob(&self.verified, &adapter, blob)?;
        self.write_file(&format!("blobs/{hash}"), &restored.resealed_bytes)?;
        let observed = ObservedBlobRestore {
            resealed_sha256: restored.resealed_sha256.clone(),
            receipt_id: restored.receipt_id.clone(),
            key_lineage: restored.key_lineage.clone(),
            source_plaintext_sha256: restored.source_plaintext_sha256.clone(),
        };
        let evidence_bytes = canonical_json_bytes(&observed)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        let applied = RestoreAppliedEffect {
            receipt: Self::effect_receipt(intent, &evidence_bytes)?,
            final_evidence: None,
        };
        self.persist_applied(intent, &applied)?;
        self.calls.push(format!("blob:{hash}"));
        Ok(applied)
    }

    fn apply_event(
        &mut self,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
        record_id: &str,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        self.gate(bundle)?;
        let record = Self::find_event(&bundle.canonical_events, record_id)?;
        self.import_canonical_event(record)?;
        let evidence_bytes = self.staged_bytes(&format!("events/{record_id}.json"))?;
        let applied = RestoreAppliedEffect {
            receipt: Self::effect_receipt(intent, &evidence_bytes)?,
            final_evidence: None,
        };
        self.persist_applied(intent, &applied)?;
        self.calls.push(format!("event:{record_id}"));
        Ok(applied)
    }

    fn apply_receipt_phase(
        &mut self,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
        operation_id: &str,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        self.gate(bundle)?;
        let receipt = bundle
            .receipts
            .iter()
            .find(|receipt| receipt.operation_id.to_string() == operation_id)
            .ok_or(BackupError::PlanMismatch)?;
        self.import_receipt(receipt)?;
        let evidence_bytes = self.staged_bytes(&format!("receipts/{operation_id}.json"))?;
        let applied = RestoreAppliedEffect {
            receipt: Self::effect_receipt(intent, &evidence_bytes)?,
            final_evidence: None,
        };
        self.persist_applied(intent, &applied)?;
        self.calls.push(format!("receipt:{operation_id}"));
        Ok(applied)
    }

    fn apply_projection(
        &mut self,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
        record_id: &str,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        self.gate(bundle)?;
        let record = Self::find_event(&bundle.projections, record_id)?;
        self.import_projection(record)?;
        let evidence_bytes = self.staged_bytes(&format!("projections/{record_id}.json"))?;
        let applied = RestoreAppliedEffect {
            receipt: Self::effect_receipt(intent, &evidence_bytes)?,
            final_evidence: None,
        };
        self.persist_applied(intent, &applied)?;
        self.calls.push(format!("projection:{record_id}"));
        Ok(applied)
    }

    fn apply_suspend(
        &mut self,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        self.gate(bundle)?;
        let snapshot = bundle.ors_snapshot.as_ref().ok_or(BackupError::PlanMismatch)?;
        self.suspend_ors_operations(snapshot)?;
        let evidence_bytes = self.staged_bytes("suspended_ors.json")?;
        let applied = RestoreAppliedEffect {
            receipt: Self::effect_receipt(intent, &evidence_bytes)?,
            final_evidence: None,
        };
        self.persist_applied(intent, &applied)?;
        self.calls.push("suspend-ors".to_owned());
        Ok(applied)
    }

    fn apply_rebuild(
        &mut self,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        self.gate(bundle)?;
        if self.count_dir("blobs")? != bundle.blobs.len()
            || self.count_dir("events")? != bundle.canonical_events.len()
            || self.count_dir("receipts")? != bundle.receipts.len()
            || self.count_dir("projections")? != bundle.projections.len()
        {
            return Err(BackupError::RestoreEvidenceIncomplete);
        }
        let marker = serde_json::json!({
            "blobs": bundle.blobs.len(),
            "events": bundle.canonical_events.len(),
            "receipts": bundle.receipts.len(),
            "projections": bundle.projections.len(),
        });
        let evidence_bytes = serde_json::to_vec(&marker)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file("rebuild.json", &evidence_bytes)?;
        let applied = RestoreAppliedEffect {
            receipt: Self::effect_receipt(intent, &evidence_bytes)?,
            final_evidence: None,
        };
        self.persist_applied(intent, &applied)?;
        self.calls.push("rebuild".to_owned());
        Ok(applied)
    }

    fn apply_verify(
        &mut self,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        self.gate(bundle)?;
        self.verify_receipt_event_chain(&bundle.receipts, &bundle.canonical_events)?;
        let marker = serde_json::json!({
            "verified": true,
            "receipts": bundle.receipts.len(),
            "events": bundle.canonical_events.len(),
        });
        let evidence_bytes = serde_json::to_vec(&marker)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file("verify.json", &evidence_bytes)?;
        let applied = RestoreAppliedEffect {
            receipt: Self::effect_receipt(intent, &evidence_bytes)?,
            final_evidence: None,
        };
        self.persist_applied(intent, &applied)?;
        self.calls.push("verify".to_owned());
        Ok(applied)
    }

    fn apply_purge_phase(
        &mut self,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        self.gate(bundle)?;
        self.apply_purge_ledger(&bundle.purge_ledger)?;
        let evidence_bytes = self.staged_bytes("purge_ledger.json")?;
        let applied = RestoreAppliedEffect {
            receipt: Self::effect_receipt(intent, &evidence_bytes)?,
            final_evidence: None,
        };
        self.persist_applied(intent, &applied)?;
        self.calls.push("purge".to_owned());
        Ok(applied)
    }

    #[allow(clippy::too_many_lines)]
    fn apply_phase(
        &mut self,
        plan: &RestorePlan,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        match &intent.phase {
            RestorePhase::Pending => Err(BackupError::RestorePhaseMismatch),
            RestorePhase::PrepareIsolatedRoot => self.apply_prepare(plan, bundle, intent),
            RestorePhase::ApplyPurgeLedger => self.apply_purge_phase(bundle, intent),
            RestorePhase::ImportSealedBlob { hash } => self.apply_blob(bundle, intent, hash),
            RestorePhase::ImportCanonicalEvent { record_id } => {
                self.apply_event(bundle, intent, record_id)
            }
            RestorePhase::ImportReceipt { operation_id } => {
                self.apply_receipt_phase(bundle, intent, operation_id)
            }
            RestorePhase::ImportProjection { record_id } => {
                self.apply_projection(bundle, intent, record_id)
            }
            RestorePhase::SuspendOrsOperations => self.apply_suspend(bundle, intent),
            RestorePhase::RebuildProjections => self.apply_rebuild(bundle, intent),
            RestorePhase::VerifyReceiptEventChain => self.apply_verify(bundle, intent),
            RestorePhase::FinalizeIsolatedRoot => self.apply_finalize(plan, bundle, intent),
        }
    }

    fn obligation(
        owner_id: &str,
        evidence_ref: String,
        state: RestoreObligationState,
    ) -> RestoreOwnerObligation {
        RestoreOwnerObligation {
            owner_id: owner_id.to_owned(),
            evidence_ref,
            state,
        }
    }

    /// Reads the persisted phase-receipt digest for one obligation group.
    ///
    /// Every phase the coordinator journaled as receipt-persisted left its
    /// observed applied record under the destination; a journaled effect
    /// without its observation is corruption, never success.
    fn group_ref(&self, phases: &[RestorePhase]) -> Result<String, BackupError> {
        let mut digests = Vec::with_capacity(phases.len());
        for phase in phases {
            let path = self.phase_receipt_path(phase)?;
            let bytes = std::fs::read(&path)
                .map_err(|_| BackupError::RestoreJournalCorrupt)?;
            digests.push(sha256_hex(&bytes));
        }
        Ok(format!(
            "kernel-restore-phase-receipt:{}",
            sha256_hex(digests.join(",").as_bytes())
        ))
    }

    fn canonical_phases(bundle: &BackupBundle) -> Vec<RestorePhase> {
        let mut phases = Vec::new();
        phases.extend(bundle.canonical_events.iter().map(|record| {
            RestorePhase::ImportCanonicalEvent {
                record_id: record.record_id.clone(),
            }
        }));
        phases.extend(bundle.receipts.iter().map(|receipt| {
            RestorePhase::ImportReceipt {
                operation_id: receipt.operation_id.to_string(),
            }
        }));
        phases.extend(bundle.projections.iter().map(|record| {
            RestorePhase::ImportProjection {
                record_id: record.record_id.clone(),
            }
        }));
        phases.push(RestorePhase::RebuildProjections);
        phases.push(RestorePhase::VerifyReceiptEventChain);
        phases
    }

    #[allow(clippy::too_many_lines)]
    fn apply_finalize(
        &mut self,
        plan: &RestorePlan,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        self.gate(bundle)?;
        let purge_ref = self.group_ref(&[RestorePhase::ApplyPurgeLedger])?;
        let canonical = Self::canonical_phases(bundle);
        let canonical_ref = self.group_ref(&canonical)?;
        let blob_phases: Vec<RestorePhase> = bundle
            .blobs
            .iter()
            .map(|blob| RestorePhase::ImportSealedBlob {
                hash: blob.locator.hash.to_string(),
            })
            .collect();
        let blob_obligation = if blob_phases.is_empty() {
            Self::obligation(
                owners::BLOB,
                "kernel-restore:archive-carries-no-blobs".to_owned(),
                RestoreObligationState::NotAttempted,
            )
        } else {
            let blob_ref = self.group_ref(&blob_phases)?;
            Self::obligation(owners::BLOB, blob_ref, RestoreObligationState::Satisfied)
        };
        let ors_obligation = if bundle.ors_snapshot.is_some() {
            let ors_ref = self.group_ref(&[RestorePhase::SuspendOrsOperations])?;
            Self::obligation(owners::ORS, ors_ref, RestoreObligationState::Satisfied)
        } else {
            Self::obligation(
                owners::ORS,
                "kernel-restore:archive-carries-no-ors-snapshot".to_owned(),
                RestoreObligationState::NotAttempted,
            )
        };
        let missing = |owner_id: &str| {
            Self::obligation(
                owner_id,
                format!("kernel-restore:unbound:{owner_id}"),
                RestoreObligationState::MissingCapability,
            )
        };
        let obligations = RestoreObligations {
            purge: Self::obligation(owners::PURGE, purge_ref, RestoreObligationState::Satisfied),
            canonical_validation: Self::obligation(
                owners::CANONICAL,
                canonical_ref.clone(),
                RestoreObligationState::Satisfied,
            ),
            reference_validation: Self::obligation(
                owners::REFERENCE,
                canonical_ref,
                RestoreObligationState::Satisfied,
            ),
            blob_validation: blob_obligation,
            ors_suspension: ors_obligation,
            unresolved_effect_reconciliation: Self::obligation(
                owners::RECONCILIATION,
                "kernel-restore:reconciliation-denominator-absent".to_owned(),
                RestoreObligationState::Unknown,
            ),
            watchdog_signals: missing(owners::WATCHDOG),
            external_source_revalidation: missing(owners::EXTERNAL_SOURCE),
            runtime_invalidation: missing(owners::RUNTIME),
            session_invalidation: missing(owners::SESSION),
            lease_invalidation: missing(owners::LEASE),
            route_invalidation: missing(owners::ROUTE),
            user_broker_invalidation: missing(owners::USER_BROKER),
        };
        let build_digest = bundle
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == "host_dependency_build")
            .map_or_else(
                || bundle.manifest.integrity_sha256.clone(),
                |artifact| artifact.sha256.clone(),
            );
        let validation_bytes = canonical_json_bytes(&(
            plan.plan_id.as_str(),
            bundle.bundle_sha256()?.as_str(),
        ))
        .map_err(|error| BackupError::Serialization(error.to_string()))?;
        let owner = OwnerTrustBinding {
            owner_id: "kernel-restore-owner".to_owned(),
            trust_binding_ref: "trust-binding-kernel-restore-owner-restore-1".to_owned(),
        };
        let evidence = RestoreEvidence {
            target_id: plan.target.target_id.clone(),
            isolated_root: true,
            purge_applied: true,
            blobs_imported: true,
            projections_rebuilt: true,
            receipt_event_chain_verified: true,
            ors_suspended: bundle.ors_snapshot.is_some(),
            active_authority_restored: false,
            authority_epoch: plan.restored_fence.authority_epoch.clone(),
            resource_generation: plan.restored_fence.resource_generation,
            provenance: RestoreProvenance {
                transaction_id: intent.transaction_id.clone(),
                plan_id: plan.plan_id.clone(),
                operation_id: format!("restore-operation-{}", plan.plan_id),
                phase: RestorePhase::FinalizeIsolatedRoot,
                source_archive_id: bundle.manifest.backup_id.clone(),
                source_class: bundle.manifest.class,
                source_digest: bundle.bundle_sha256()?,
                source_endpoint_ref: bundle.manifest.source_adapter.clone(),
                isolated_destination_ref: plan.target.target_id.clone(),
                expected_predecessor_ref: "none".to_owned(),
                schema_revision: bundle.manifest.schema_generation.clone(),
                build_manifest_digest: build_digest,
                purge_ledger_revision: bundle.manifest.purge_ledger_revision,
                owner: owner.clone(),
                observed_generation: plan.restored_fence.resource_generation,
                observed_epoch: plan.restored_fence.authority_epoch.clone(),
                validation_digest: sha256_hex(&validation_bytes),
            },
            obligations,
            observed_lineage_limits: vec![ObservedLineageLimit {
                owner_id: owner.owner_id.clone(),
                observed_epoch: bundle.export_fence.state_fence.authority_epoch.clone(),
                observed_generation: bundle.export_fence.state_fence.resource_generation,
            }],
            owner_epoch: None,
            reconciliation_denominator: None,
            operational_validation: None,
            historical_authority: match &bundle.ors_snapshot {
                Some(snapshot) => suspended_recovery_entries(snapshot)?,
                None => Vec::new(),
            },
            archive_disposition: RestoreArchiveDisposition {
                disposition: RestoreArchiveDispositionKind::Current,
                compatibility_ref: "ecxf-1-current".to_owned(),
            },
        };
        evidence.validate()?;
        let evidence_bytes = canonical_json_bytes(&evidence)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file("evidence.json", &evidence_bytes)?;
        let applied = RestoreAppliedEffect {
            receipt: Self::effect_receipt(intent, &evidence_bytes)?,
            final_evidence: Some(evidence.clone()),
        };
        self.persist_applied(intent, &applied)?;
        self.final_evidence = Some(evidence);
        self.calls.push("finalize".to_owned());
        Ok(applied)
    }
}

impl RestoreTarget for KernelRestoreTarget<'_> {
    fn prepare_isolated(
        &mut self,
        context: &RestoreContext,
        restored_fence: &RestoredFence,
    ) -> Result<(), BackupError> {
        context.validate()?;
        restored_fence.validate()?;
        for dir in [
            "blobs",
            "events",
            "receipts",
            "projections",
            "phase-receipts",
        ] {
            std::fs::create_dir_all(self.root.join(dir))
                .map_err(|error| BackupError::Target(error.to_string()))?;
        }
        Ok(())
    }

    fn apply_purge_ledger(&mut self, entries: &[PurgeLedgerEntry]) -> Result<(), BackupError> {
        PurgeOwnerClient::bind(entries, &self.verified).validate_entries()?;
        let bytes = canonical_json_bytes(&entries)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file("purge_ledger.json", &bytes)?;
        Ok(())
    }

    fn import_sealed_blob(&mut self, _blob: &BackupBlob) -> Result<(), BackupError> {
        // The legacy single-argument form cannot carry the restoration
        // receipt, the admitted key manifest, or the destination scope that
        // destination-owned re-sealing requires: refusing here instead of
        // staging sealed bytes without ownership. The journaled apply path
        // supplies the full binding.
        Err(BackupError::RestoreCapabilityUnsupported {
            capability: owners::BLOB_SCOPE_BINDING,
        })
    }

    fn import_canonical_event(&mut self, record: &CanonicalRecord) -> Result<(), BackupError> {
        CanonicalOwnerClient::validate_event(record)?;
        let bytes = canonical_json_bytes(&record.payload)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file(&format!("events/{}.json", record.record_id), &bytes)?;
        Ok(())
    }

    fn import_receipt(&mut self, receipt: &WriteReceipt) -> Result<(), BackupError> {
        CanonicalOwnerClient::validate_receipt(receipt)?;
        let bytes = canonical_json_bytes(receipt)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file(&format!("receipts/{}.json", receipt.operation_id), &bytes)?;
        Ok(())
    }

    fn import_projection(&mut self, record: &CanonicalRecord) -> Result<(), BackupError> {
        CanonicalOwnerClient::validate_event(record)?;
        let bytes = canonical_json_bytes(&record.payload)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file(&format!("projections/{}.json", record.record_id), &bytes)?;
        Ok(())
    }

    fn suspend_ors_operations(&mut self, snapshot: &OrsSnapshotFence) -> Result<(), BackupError> {
        let entries = OrsOwnerClient::suspend(snapshot)?;
        let bytes = canonical_json_bytes(&entries)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file("suspended_ors.json", &bytes)?;
        Ok(())
    }

    fn rebuild_projections(&mut self, _restored_fence: &RestoredFence) -> Result<(), BackupError> {
        // The legacy form lacks the bundle counts that make a rebuild claim
        // verifiable; the journaled apply path verifies observed destination
        // state instead of attesting an unanchorable marker.
        Err(BackupError::RestoreCapabilityNotAttempted {
            capability: "projection-rebuild-counts",
        })
    }

    fn verify_receipt_event_chain(
        &mut self,
        receipts: &[WriteReceipt],
        events: &[CanonicalRecord],
    ) -> Result<(), BackupError> {
        CanonicalOwnerClient::verify_chain(receipts, events)
    }

    fn finalize_isolated(
        &mut self,
        _restored_fence: &RestoredFence,
    ) -> Result<RestoreEvidence, BackupError> {
        // Plan-bound evidence (plan/bundle identity, transaction digests,
        // obligation receipts) cannot be assembled from the fence alone: the
        // receipt-bearing apply path assembles it instead. Legacy callers
        // must migrate to that seam rather than receive unbound evidence.
        Err(BackupError::RestoreTargetReceiptRequired)
    }

    fn apply_restore_effect(
        &mut self,
        plan: &RestorePlan,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        if intent.transaction_id.is_empty() {
            return Err(BackupError::RestoreJournalCorrupt);
        }
        if !matches!(
            intent.phase,
            RestorePhase::Pending | RestorePhase::PrepareIsolatedRoot
        ) {
            self.check_destination_admission(intent, plan.target.target_id.as_str())?;
        }
        self.apply_phase(plan, bundle, intent)
    }

    fn reconcile_restore_effect(
        &mut self,
        intent: &RestoreIntent,
    ) -> Result<RestoreReconciliation, BackupError> {
        // Every effect in this target is synchronous and local with one
        // persisted identity receipt per phase, so reconciliation reads the
        // observation back by exact identity: a present receipt bound to this
        // transaction, phase, and input digest is Applied; its absence is
        // NotApplied and the coordinator re-applies idempotently (byte
        // staging overwrites, re-sealing mints fresh bytes with a fresh
        // receipt — no prior receipt exists to contradict). Bytes that parse
        // as nothing are Undecidable and propagate as Unknown: the
        // coordinator takes the explicit rollback-required disposition
        // (I14.21) with no new identity and no blind retry. Async
        // owner-channel unknowns belong to the #962 wire layer, which must
        // upgrade reconciliation there, never downgrade readback here.
        match &intent.phase {
            RestorePhase::Pending => Err(BackupError::RestorePhaseMismatch),
            _ => match self.load_applied(intent)? {
                ObservedEffect::Applied(applied) => Ok(RestoreReconciliation::Applied(applied)),
                ObservedEffect::NotAttempted => Ok(RestoreReconciliation::NotApplied),
                ObservedEffect::Undecidable => Ok(RestoreReconciliation::Unknown),
            },
        }
    }
}
