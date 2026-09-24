//! Kernel-owned cross-owner backup capture coordinator (issue #959).
//!
//! Architecture: I5.13 backup classes (full denominator, degraded ceiling,
//! key-material rule); A13.6 Operational Recovery State (only identities,
//! opaque envelopes, epochs, suspended leases, checkpoints, intents, manifests,
//! anchors — never semantic claims); I14.21 unknown-commit recovery (reconcile
//! by identity, never blind retry); I14.3 Control Reserve (bounded capture
//! work; no unbounded waits inside a held transaction); I7.20 agent-facing
//! error contract (typed refusals with exact reason, never silence or
//! fabricated success).
//!
//! I5.13 sentences this coordinator is bound by:
//!
//! - The ORS and canonical export are not one cross-store transaction: the
//!   manifest records their relation, and every ORS item restores as
//!   `suspended_recovery`. No global-transaction type exists anywhere in this
//!   file; per-owner snapshots stay independent and only their recorded
//!   `SnapshotRelation` is validated.
//! - A legitimate independent snapshot with bounded unresolved operations may
//!   form a `full_recovery` archive when all required material and coherent
//!   relations are preserved; those operations restore suspended and are
//!   reconciled before replay. Unresolved operations are not archive
//!   corruption, and archive validity is not completed effect reconciliation.
//! - An optional forensic `HostStateAuditFence` is never restored as active
//!   authority and never satisfies a class denominator.
//! - The backup contains key lineage and format metadata, never plaintext
//!   master or data keys; equal bytes under different obligations remain
//!   distinct logical objects.
//!
//! What this file owns: the thin `KernelBackupCapture` execution body that
//! admits, freezes, gates, relates, bounds, builds, verifies, and publishes
//! exactly once. Build and verification run through the existing accepted
//! `BackupBundle` API (`build` / `validate` / `encode` / `decode` /
//! `bundle_sha256`); validation may repeat freely — one admitted
//! capture/publication operation is the identity boundary, never a once-only
//! validation guard. Publication reconciles a lost response by operation
//! identity through `PublicationPort::reconcile`, never by byte-equality or
//! process exit. Verification-only decodes and validates with zero restore
//! calls and zero installation mutation.
//!
//! Capability cell: Kernel capture ownership (cross-owner capture execution).
//! Forbidden authority: no ORS row reinterpretation, no epoch minting, no
//! cutover, no activation/retirement of any installation, no second archive
//! format, no invented restore or target methods, and no recovered, activated,
//! cut-over, or finished claims.

use std::path::{Path, PathBuf};

use eliot_backup::{
    BackupArtifact, BackupBlob, BackupBundle, BackupClass, BackupInput, CanonicalRecord,
    ExportFence, HostStateAuditFence, OrsSnapshotFence, WatchdogSpoolFence,
};
use eliot_contracts::StateFence;
use eliot_security_contracts::PurgeLedgerEntry;
use eliot_store_api::WriteReceipt;

use super::backup_capture_ports::{
    CaptureCallerAuth, CapturePorts, FrozenCapturePlan, KernelCaptureError, PublicationPort,
    PublishedArchive, SnapshotRelation, require_capture_admitted,
};

/// Owner order for per-owner budget accounting: canonical, blob, purge, ORS,
/// watchdog, host.
const OWNER_COUNT: usize = 6;

/// One capture request: the admitted caller, the frozen plan, and owned clones
/// of the already-accepted owner evidence.
///
/// A single struct with owned vectors and options keeps test construction
/// direct: no live owner handle, database read path, or snapshot service
/// travels here.
#[derive(Clone, Debug, PartialEq)]
pub struct CaptureRequest {
    /// Admitted caller authentication behind the capture.
    pub caller: CaptureCallerAuth,
    /// Frozen class, scope, source, schema, build, policy, and budgets.
    pub plan: FrozenCapturePlan,
    /// Coherent canonical export fence binding the capture.
    pub export_fence: ExportFence,
    /// Canonical event records carried by the capture.
    pub canonical_events: Vec<CanonicalRecord>,
    /// Canonical projection records carried by the capture.
    pub projections: Vec<CanonicalRecord>,
    /// Canonical write receipts carried by the capture.
    pub receipts: Vec<WriteReceipt>,
    /// Sealed blob envelopes carried by the capture (never plaintext).
    pub blobs: Vec<BackupBlob>,
    /// Purge ledger entries carried by the capture.
    pub purge_ledger: Vec<PurgeLedgerEntry>,
    /// Logical ORS snapshot fence, when the class carries one.
    pub ors_snapshot: Option<OrsSnapshotFence>,
    /// Count of suspended recovery entries derived from the ORS snapshot.
    pub suspended_count: u64,
    /// Checksummed config, policy, module, and build manifest artifacts.
    pub artifacts: Vec<BackupArtifact>,
    /// Bounded Watchdog spool fence, when the class carries one.
    pub watchdog_spool: Option<WatchdogSpoolFence>,
    /// Optional forensic Host audit fence (never active authority).
    pub host_audit: Option<HostStateAuditFence>,
}

/// Builds one owned capture request from the validated per-execution port
/// bundle plus the frozen plan: the production caller validates owner-evidence
/// shapes through the bundle, then crosses the owned request into `capture`.
/// This keeps the ref-borrowed adapter (`CapturePorts`) on the production
/// path instead of beside it.
pub fn request_from_ports(
    ports: &CapturePorts<'_>,
    plan: FrozenCapturePlan,
    suspended_count: u64,
) -> Result<CaptureRequest, KernelCaptureError> {
    ports.validate_shapes()?;
    Ok(CaptureRequest {
        caller: ports.caller.clone(),
        plan,
        export_fence: ports.export_fence.clone(),
        canonical_events: ports.canonical_events.to_vec(),
        projections: ports.projections.to_vec(),
        receipts: ports.receipts.to_vec(),
        blobs: ports.blobs.to_vec(),
        purge_ledger: ports.purge_ledger.to_vec(),
        ors_snapshot: ports.ors_snapshot.cloned(),
        suspended_count,
        artifacts: ports.artifacts.to_vec(),
        watchdog_spool: ports.watchdog_spool.cloned(),
        host_audit: ports.host_audit.cloned(),
    })
}
/// Terminal state of one capture or verification.
///
/// Capture reports completeness only: it never claims recovered, activated,
/// cut-over, or finished — no such variant or string exists here.
#[derive(Clone, Debug, PartialEq)]
pub enum CaptureState {
    /// The archive built, validated, encoded, and published completely.
    Complete,
    /// The archive is structurally valid but cannot claim completeness.
    Incomplete { reason: String },
    /// A required capability is explicitly unsupported here.
    Unsupported { reason: String },
    /// The capture was cancelled before completion.
    Cancelled,
    /// The capture outcome could not be decided from observed evidence.
    Unknown { reason: String },
}

/// Outcome of one capture or verification: the requested class, exact
/// source and archive identities, verification level, member dispositions,
/// and terminal state.
#[derive(Clone, Debug, PartialEq)]
pub struct CaptureReport {
    /// Archive backup identity bound at build.
    pub backup_id: String,
    /// Requested backup class.
    pub class: BackupClass,
    /// Deterministic digest of the complete encoded archive.
    pub archive_sha256: String,
    /// Publication operation identity (or the verify-only identity).
    pub operation_id: String,
    /// Terminal capture state (never recovered, activated, cut-over, or
    /// finished).
    pub state: CaptureState,
    /// Verification level performed (`build-validate-publish` for capture,
    /// `decode-validate-relation` for verification-only).
    pub verification_level: &'static str,
    /// Exactly one disposition per expected source member.
    pub member_dispositions: Vec<(String, String)>,
    /// Publication receipt identity, or the suspended-operations marker.
    pub receipt_identity: Option<String>,
}

/// Kernel-owned cross-owner backup capture coordinator.
///
/// Binds the Kernel work root the capture operates under. The coordinator
/// owns no live owner channel: every capture consumes already-accepted owner
/// evidence through `CaptureRequest`, builds and verifies through the accepted
/// `BackupBundle` API, and publishes once through the admitted `PublicationPort`.
pub struct KernelBackupCapture {
    work_root: PathBuf,
}

impl KernelBackupCapture {
    /// Binds the capture owner to the Kernel work root.
    pub fn bind(work_root: PathBuf) -> Self {
        Self { work_root }
    }

    /// Returns the bound work root.
    #[must_use]
    pub fn work_root(&self) -> &Path {
        &self.work_root
    }

    /// Executes one admitted capture: admit, freeze, gate, relate, bound,
    /// build, verify, publish exactly once.
    ///
    /// Order: (a) caller admission and frozen-plan validation before touching
    /// evidence; (b) class capability gate with no silent downgrade;
    /// (c) snapshot-relation build and validation; (d) complete-denominator
    /// check; (e) per-owner and cumulative budget check; (f) exact
    /// `BackupBundle` build, repeated validation, and encoding; (g) a single
    /// `publish_once` under the operation identity and idempotency key, with a
    /// lost response reconciled by identity through `reconcile` (never a
    /// second publish). Bounded unresolved operations are not corruption: a
    /// `full_recovery` capture with suspended entries still completes and
    /// records the suspended marker as its receipt identity.
    #[allow(
        clippy::unused_self,
        reason = "governed owner seam keeps &self receivers; the work root binds composition"
    )]
    pub fn capture(
        &self,
        request: &CaptureRequest,
        publisher: &mut impl PublicationPort,
    ) -> Result<CaptureReport, KernelCaptureError> {
        require_capture_admitted(&request.caller)?;
        request.plan.validate()?;
        gate_class_capability(request)?;
        let relation = snapshot_relation(request);
        Self::validate_snapshot_relation(&relation)?;
        let member_dispositions = check_denominator(request)?;
        check_budgets(request)?;
        let bundle = BackupBundle::build(assemble_input(request))
            .map_err(|error| KernelCaptureError::ArchiveInvalid(error.to_string()))?;
        bundle
            .validate()
            .map_err(|error| KernelCaptureError::ArchiveInvalid(error.to_string()))?;
        let bytes = bundle
            .encode()
            .map_err(|error| KernelCaptureError::ArchiveInvalid(error.to_string()))?;
        let archive_sha256 = bundle
            .bundle_sha256()
            .map_err(|error| KernelCaptureError::ArchiveInvalid(error.to_string()))?;
        let backup_id = bundle.manifest.backup_id.clone();
        let operation_id = format!("capture-publish-{backup_id}");
        let idempotency_key = format!("{backup_id}:{archive_sha256}");
        let receipt = match publisher.publish_once(&operation_id, &idempotency_key, &bytes) {
            Ok(receipt) => receipt,
            Err(KernelCaptureError::PublicationUnknown(_)) => publisher.reconcile(&operation_id)?,
            Err(other) => return Err(other),
        };
        let archive = PublishedArchive {
            backup_id: backup_id.clone(),
            archive_sha256: archive_sha256.clone(),
            operation_id: operation_id.clone(),
            idempotency_key,
            durability_note: "owner-durable".to_owned(),
        };
        if receipt.operation_id != archive.operation_id
            || receipt.archive_sha256 != archive.archive_sha256
            || !receipt.durable
        {
            return Err(KernelCaptureError::PublicationUnknown(operation_id));
        }
        let state =
            if request.suspended_count > 0 && request.plan.class != BackupClass::FullRecovery {
                CaptureState::Incomplete {
                    reason: "bounded suspended operations exceed degraded class ceiling".to_owned(),
                }
            } else {
                CaptureState::Complete
            };
        let receipt_identity = if request.suspended_count > 0 {
            Some(format!("suspended:{}", request.suspended_count))
        } else {
            Some(operation_id.clone())
        };
        Ok(CaptureReport {
            backup_id,
            class: request.plan.class,
            archive_sha256,
            operation_id,
            state,
            verification_level: "build-validate-publish",
            member_dispositions,
            receipt_identity,
        })
    }

    /// Verifies one archive without restoration effects or installation
    /// mutation: admitted gate, `BackupBundle::decode` plus repeated
    /// validation, and an exact kernel-fence compatibility check. No
    /// publication happens here and nothing is mutated (`&self` only); the
    /// report state follows class completeness.
    #[allow(
        clippy::unused_self,
        reason = "governed owner seam keeps &self receivers; the work root binds composition"
    )]
    pub fn verify_only(
        &self,
        bytes: &[u8],
        caller: &CaptureCallerAuth,
        kernel_fence: &StateFence,
    ) -> Result<CaptureReport, KernelCaptureError> {
        require_capture_admitted(caller)?;
        let bundle = BackupBundle::decode(bytes)
            .map_err(|error| KernelCaptureError::ArchiveInvalid(error.to_string()))?;
        bundle
            .validate()
            .map_err(|error| KernelCaptureError::ArchiveInvalid(error.to_string()))?;
        if bundle.export_fence.state_fence != *kernel_fence {
            return Err(KernelCaptureError::RelationIncoherent(
                "kernel fence does not admit archive".to_owned(),
            ));
        }
        let archive_sha256 = bundle
            .bundle_sha256()
            .map_err(|error| KernelCaptureError::ArchiveInvalid(error.to_string()))?;
        let backup_id = bundle.manifest.backup_id.clone();
        let class = bundle.manifest.class;
        let member_dispositions = member_disposition_list(
            &bundle.canonical_events,
            &bundle.projections,
            &bundle.receipts,
            &bundle.blobs,
            &bundle.purge_ledger,
            &bundle.artifacts,
        );
        let state = if class == BackupClass::FullRecovery {
            CaptureState::Complete
        } else {
            CaptureState::Incomplete {
                reason: "degraded class; operational recovery unavailable".to_owned(),
            }
        };
        Ok(CaptureReport {
            operation_id: format!("verify-only-{backup_id}"),
            backup_id,
            class,
            archive_sha256,
            state,
            verification_level: "decode-validate-relation",
            member_dispositions,
            receipt_identity: None,
        })
    }

    /// Validates one recorded snapshot relation for tests and the coordinator:
    /// timestamps alone fail, and empty cursors or lineage refuse as
    /// incoherent. No global transaction is assumed.
    pub fn validate_snapshot_relation(
        relation: &SnapshotRelation,
    ) -> Result<(), KernelCaptureError> {
        relation.validate_relation()
    }
}

/// Stable class name for capability refusals.
fn class_name(class: BackupClass) -> &'static str {
    match class {
        BackupClass::FullRecovery => "full_recovery",
        BackupClass::CanonicalOnlyDegraded => "canonical_only_degraded",
        BackupClass::ScopeExport => "scope_export",
    }
}

/// Enforces the class capability gate: `full_recovery` requires the ORS
/// snapshot, the Watchdog spool, and manifest artifacts, refusing without
/// silent downgrade; `scope_export` requires the frozen scope to match the
/// export evidence exactly. Degraded classes carry no installation recovery
/// and are bounded by bundle validation instead.
fn gate_class_capability(request: &CaptureRequest) -> Result<(), KernelCaptureError> {
    if request.plan.class == BackupClass::FullRecovery {
        if request.ors_snapshot.is_none() {
            return Err(KernelCaptureError::ClassCapabilityUnsupported {
                class: class_name(request.plan.class),
                capability: "ors_snapshot",
            });
        }
        if request.watchdog_spool.is_none() {
            return Err(KernelCaptureError::ClassCapabilityUnsupported {
                class: class_name(request.plan.class),
                capability: "watchdog_spool",
            });
        }
        if request.artifacts.is_empty() {
            return Err(KernelCaptureError::ClassCapabilityUnsupported {
                class: class_name(request.plan.class),
                capability: "config_policy_module_build_manifests",
            });
        }
    }
    if request.plan.class == BackupClass::ScopeExport {
        let frozen = request.plan.scope_id.as_deref();
        let observed = request
            .export_fence
            .scope_id
            .as_ref()
            .map(eliot_store_api::ScopeId::as_str);
        if frozen != observed {
            return Err(KernelCaptureError::RelationIncoherent(
                "scope mismatch between frozen plan and export fence".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Builds the exact cross-owner snapshot relation from validated request
/// evidence: cursors from the ORS snapshot when present, otherwise from the
/// observed canonical coverage; lineage from the export state fence;
/// checkpoints, cutovers, and spool signals from their owners. Capture times
/// stay empty here: production composition records per-owner capture times,
/// and times alone never satisfy the relation.
fn snapshot_relation(request: &CaptureRequest) -> SnapshotRelation {
    let receipt_cursor = request
        .ors_snapshot
        .as_ref()
        .map_or(request.receipts.len() as u64, |snapshot| {
            snapshot.last_receipt_cursor
        });
    let event_cursor = request
        .ors_snapshot
        .as_ref()
        .map_or(request.canonical_events.len() as u64, |snapshot| {
            snapshot.last_event_cursor
        });
    let outbox_cursor = request
        .ors_snapshot
        .as_ref()
        .map_or(0, |snapshot| snapshot.last_outbox_cursor);
    let ors_compatible = request
        .ors_snapshot
        .as_ref()
        .is_none_or(|snapshot| snapshot.state_fence == request.export_fence.state_fence);
    let watchdog_compatible = request
        .watchdog_spool
        .as_ref()
        .is_none_or(|spool| spool.state_fence == request.export_fence.state_fence);
    let purge_compatible = request.purge_ledger.iter().all(|entry| {
        entry
            .state_fence
            .is_compatible_with(&request.export_fence.state_fence)
    });
    let receipt_compatible = request.receipts.iter().all(|receipt| {
        receipt
            .state_fence
            .is_compatible_with(&request.export_fence.state_fence)
    });
    SnapshotRelation {
        installation_id: request.export_fence.export_id.clone(),
        store_generation: request.export_fence.store_generation.clone(),
        authority_lineage: request
            .export_fence
            .state_fence
            .authority_epoch
            .lineage_id
            .as_str()
            .to_owned(),
        receipt_cursor,
        event_cursor,
        outbox_cursor,
        pending_operation_ids: request
            .ors_snapshot
            .as_ref()
            .map(|snapshot| snapshot.pending_operation_ids.clone())
            .unwrap_or_default(),
        pending_operation_hashes: Vec::new(),
        checkpoint_ids: request
            .ors_snapshot
            .as_ref()
            .map(|snapshot| snapshot.job_checkpoint_ids.clone())
            .unwrap_or_default(),
        cutover_ids: request
            .ors_snapshot
            .as_ref()
            .map(|snapshot| snapshot.generation_cutover_ids.clone())
            .unwrap_or_default(),
        spool_signal_digests: request
            .watchdog_spool
            .as_ref()
            .map(|spool| spool.unresolved_signal_digests.clone())
            .unwrap_or_default(),
        spool_gaps: Vec::new(),
        capture_time_ms_per_owner: Vec::new(),
        fence_compatible: ors_compatible
            && watchdog_compatible
            && purge_compatible
            && receipt_compatible,
        timestamps_only: false,
    }
}

/// Builds exactly one `captured` disposition per expected source member.
/// Domain prefixes keep obligation domains disjoint so equal bytes under
/// different obligations never coalesce into one logical object.
fn member_disposition_list(
    events: &[CanonicalRecord],
    projections: &[CanonicalRecord],
    receipts: &[WriteReceipt],
    blobs: &[BackupBlob],
    purge_ledger: &[PurgeLedgerEntry],
    artifacts: &[BackupArtifact],
) -> Vec<(String, String)> {
    let mut dispositions = Vec::new();
    for event in events {
        dispositions.push((
            format!("canonical:{}", event.record_id),
            "captured".to_owned(),
        ));
    }
    for projection in projections {
        dispositions.push((
            format!("projection:{}", projection.record_id),
            "captured".to_owned(),
        ));
    }
    for receipt in receipts {
        dispositions.push((
            format!("receipt:{}", receipt.operation_id),
            "captured".to_owned(),
        ));
    }
    for blob in blobs {
        dispositions.push((
            format!("blob:{}", blob.locator.hash.as_str()),
            "captured".to_owned(),
        ));
    }
    for entry in purge_ledger {
        dispositions.push((format!("purge:{}", entry.purge_id), "captured".to_owned()));
    }
    for artifact in artifacts {
        dispositions.push((
            format!("artifact:{}", artifact.artifact_id),
            "captured".to_owned(),
        ));
    }
    dispositions
}

/// Checks the complete reconciliation denominator: a consistent export fence,
/// exactly one blob per reachability hash and no unreferenced blob, an event
/// range matching the carried canonical events, and exactly one disposition
/// per expected member. Expired or mixed-generation evidence (an inconsistent
/// fence) cannot stitch into a complete result.
fn check_denominator(
    request: &CaptureRequest,
) -> Result<Vec<(String, String)>, KernelCaptureError> {
    if !request.export_fence.consistent {
        return Err(KernelCaptureError::RelationIncoherent(
            "export fence is not consistent".to_owned(),
        ));
    }
    for hash in &request.export_fence.blob_reachability_manifest {
        let count = request
            .blobs
            .iter()
            .filter(|blob| blob.locator.hash == *hash)
            .count();
        if count != 1 {
            return Err(KernelCaptureError::DenominatorIncomplete(format!(
                "blob {} has {count} members, want exactly one",
                hash.as_str()
            )));
        }
    }
    for blob in &request.blobs {
        if !request
            .export_fence
            .blob_reachability_manifest
            .contains(&blob.locator.hash)
        {
            return Err(KernelCaptureError::DenominatorIncomplete(format!(
                "blob {} is not referenced by the export fence",
                blob.locator.hash.as_str()
            )));
        }
    }
    if request.export_fence.event_range.count != request.canonical_events.len() as u64 {
        return Err(KernelCaptureError::DenominatorIncomplete(format!(
            "event range count {} does not match {} canonical events",
            request.export_fence.event_range.count,
            request.canonical_events.len()
        )));
    }
    let dispositions = member_disposition_list(
        &request.canonical_events,
        &request.projections,
        &request.receipts,
        &request.blobs,
        &request.purge_ledger,
        &request.artifacts,
    );
    for event in &request.canonical_events {
        let want = format!("canonical:{}", event.record_id);
        let count = dispositions.iter().filter(|entry| entry.0 == want).count();
        if count != 1 {
            return Err(KernelCaptureError::DenominatorIncomplete(format!(
                "canonical event {} has {count} dispositions, want exactly one",
                event.record_id
            )));
        }
    }
    let mut seen = Vec::with_capacity(dispositions.len());
    for entry in &dispositions {
        if seen.contains(entry) {
            return Err(KernelCaptureError::DenominatorIncomplete(format!(
                "member {} has a duplicate disposition",
                entry.0
            )));
        }
        seen.push(entry.clone());
    }
    Ok(dispositions)
}

/// Serialized byte length of one evidence value for budget accounting.
fn json_len(value: &impl serde::Serialize) -> Result<u64, KernelCaptureError> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len() as u64)
        .map_err(|_| KernelCaptureError::ArchiveInvalid("evidence serialization failed".to_owned()))
}

/// Per-owner evidence byte and item counts in `OWNER_COUNT` order for budget
/// accounting. Blob bytes are exact sealed-envelope lengths; every other owner
/// is measured over its canonical JSON encoding.
fn evidence_counts(
    request: &CaptureRequest,
) -> Result<([u64; OWNER_COUNT], [u64; OWNER_COUNT]), KernelCaptureError> {
    let mut canonical_bytes: u64 = 0;
    for record in request
        .canonical_events
        .iter()
        .chain(request.projections.iter())
    {
        canonical_bytes = canonical_bytes.saturating_add(json_len(record)?);
    }
    for receipt in &request.receipts {
        canonical_bytes = canonical_bytes.saturating_add(json_len(receipt)?);
    }
    let mut blob_bytes: u64 = 0;
    for blob in &request.blobs {
        blob_bytes = blob_bytes.saturating_add(blob.sealed_bytes.len() as u64);
    }
    let mut purge_bytes: u64 = 0;
    for entry in &request.purge_ledger {
        purge_bytes = purge_bytes.saturating_add(json_len(entry)?);
    }
    let mut ors_bytes: u64 = 0;
    let mut ors_items: u64 = 0;
    if let Some(snapshot) = request.ors_snapshot.as_ref() {
        ors_bytes = json_len(snapshot)?;
        ors_items = snapshot.pending_operation_ids.len() as u64;
    }
    let mut watchdog_bytes: u64 = 0;
    let mut watchdog_items: u64 = 0;
    if let Some(spool) = request.watchdog_spool.as_ref() {
        watchdog_bytes = json_len(spool)?;
        watchdog_items = spool.unresolved_signal_digests.len() as u64;
    }
    let mut host_bytes: u64 = 0;
    for artifact in &request.artifacts {
        host_bytes = host_bytes.saturating_add(artifact.bytes.len() as u64);
    }
    let mut host_items: u64 = request.artifacts.len() as u64;
    if let Some(audit) = request.host_audit.as_ref() {
        host_bytes = host_bytes.saturating_add(json_len(audit)?);
        host_items = host_items.saturating_add(1);
    }
    let bytes = [
        canonical_bytes,
        blob_bytes,
        purge_bytes,
        ors_bytes,
        watchdog_bytes,
        host_bytes,
    ];
    let items = [
        request.canonical_events.len() as u64
            + request.projections.len() as u64
            + request.receipts.len() as u64,
        request.blobs.len() as u64,
        request.purge_ledger.len() as u64,
        ors_items,
        watchdog_items,
        host_items,
    ];
    Ok((bytes, items))
}

/// Enforces the frozen budgets over per-owner and cumulative byte and work
/// counts before any archive build work begins.
fn check_budgets(request: &CaptureRequest) -> Result<(), KernelCaptureError> {
    let (bytes, items) = evidence_counts(request)?;
    request.plan.budgets.check_cumulative(&bytes)?;
    request.plan.budgets.check_work_items(&items)?;
    Ok(())
}

/// Assembles the exact `BackupInput` from validated request fields: the
/// archive identity binds the canonical export identity (nothing invented),
/// class, source, and schema come from the frozen plan, and every evidence
/// section crosses byte-identical. The purge revision binds the carried
/// ledger: zero with an empty ledger, the entry count otherwise.
fn assemble_input(request: &CaptureRequest) -> BackupInput {
    BackupInput {
        backup_id: request.export_fence.export_id.clone(),
        class: request.plan.class,
        source_adapter: request.plan.source_adapter.clone(),
        schema_generation: request.plan.schema_generation.clone(),
        export_fence: request.export_fence.clone(),
        canonical_events: request.canonical_events.clone(),
        projections: request.projections.clone(),
        receipts: request.receipts.clone(),
        blobs: request.blobs.clone(),
        purge_ledger: request.purge_ledger.clone(),
        ors_snapshot: request.ors_snapshot.clone(),
        artifacts: request.artifacts.clone(),
        watchdog_spool: request.watchdog_spool.clone(),
        host_audit: request.host_audit.clone(),
        missing_features: Vec::new(),
        purge_ledger_revision: if request.purge_ledger.is_empty() {
            0
        } else {
            request.purge_ledger.len() as u64
        },
    }
}
