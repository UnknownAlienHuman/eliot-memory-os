//! Bounded logical ORS backup-snapshot contracts (issue #953).
//!
//! I05-13: a logical `OrsSnapshotFence` export only. Pages carry digests and
//! durable lineage, never raw payload bytes; the snapshot is
//! `suspended_recovery` material and never runnable authority. It never copies
//! a live `redb` file, mutates durable state, or advances a canonical ordering
//! head.
//! I05-16: every entry carries the common durable fields that travel with the
//! opaque payload; an inapplicable field stays an explicit `None` rather than a
//! silent omission.
//! I05-22: the wire shape is explicitly versioned; an unsupported or unknown
//! schema stays blocked, never reinterpreted.
//! I05-27: source identity, generation, schema, canonical dependency fence and
//! high-water are compared against owner-established current state, and import
//! binds exact source, archive, and destination identities. Source-equals-
//! destination, missing admission, or unbound evidence is rejected, never
//! relabelled.
//! I14-21: unknown stays reconciling. Import receipts keep an explicit
//! per-entry outcome including `Unresolved`, and a zero-unresolved claim
//! requires complete current owner validation.
//! I07-20: every disposition carries a typed closed reason and a stable reason
//! code, never free prose and never a count standing in for a decision.
//!
//! Storage-free: no `redb`, no filesystem, no `eliot-backup` dependency.
//! Distinct from `snapshot_model`; every new name starts `OrsBackup`/`Backup`.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::OrsError;

/// Schema version of the backup-snapshot wire shape.
///
/// Version 2 binds a store-observed capture point, a full per-family
/// denominator, and a page-token chain. A version 1 request is not silently
/// upgraded: [`OrsBackupSourceIdentity::new`] refuses it with
/// [`OrsError::MigrationRequired`].
pub const BACKUP_SNAPSHOT_SCHEMA_VERSION: u16 = 2;
/// Hard ceiling for entries in one backup page (mirrors `MAX_RECOVERY_PAGE`).
pub const MAX_BACKUP_PAGE_ENTRIES: u16 = 256;
/// Hard ceiling for pages in one backup snapshot.
pub const MAX_BACKUP_PAGES: u16 = 256;
/// Hard ceiling for the declared aggregate byte budget of one backup request.
pub const MAX_BACKUP_BYTES: u64 = 16 * 1024 * 1024;
/// Hard ceiling for installation, admission, and marker identifier length.
pub const MAX_BACKUP_ID_LEN: usize = 256;
/// Hard ceiling for one captured physical durable member key.
///
/// Every ORS key form the store writes is far shorter than this; a physical row
/// key beyond the bound cannot be represented in a page and fails the capture
/// closed with [`OrsError::ProjectionLimitExceeded`] rather than being
/// truncated into a colliding identity.
pub const MAX_BACKUP_MEMBER_KEY_BYTES: usize = 1024;
/// Hard ceiling for aggregate work units (row observations) in one capture.
///
/// The budget is charged once per observed row across the whole capture, not
/// per page, so a large table cannot be re-read `MAX_BACKUP_PAGES` times inside
/// one budget.
pub const MAX_BACKUP_WORK_UNITS: u64 = 1_048_576;
/// Hard ceiling for the wall-clock duration of one capture, in milliseconds.
pub const MAX_BACKUP_DURATION_MS: u64 = 60_000;
/// Hard ceiling for the physical table census observed in one capture.
pub const MAX_BACKUP_TABLE_CENSUS: usize = 512;
/// Hard ceiling for a capture page-token validity window, in milliseconds.
pub const MAX_BACKUP_TOKEN_TTL_MS: i64 = 3_600_000;
/// Lowercase 64-hex digest shape check (local copy: `model` is private).
fn require_digest(value: &str, field: &'static str) -> Result<(), OrsError> {
    let ok = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    if ok {
        Ok(())
    } else {
        Err(OrsError::InvalidField {
            field,
            reason: "digest must be 64 lowercase hex characters",
        })
    }
}
/// SHA-256 hex helper local to this module.
fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
/// Bounded installation identifier check shared by source and destination.
fn require_installation_id(value: &str, field: &'static str) -> Result<(), OrsError> {
    if value.is_empty() || value.len() > MAX_BACKUP_ID_LEN {
        return Err(OrsError::InvalidField {
            field,
            reason: "installation id must be non-empty and bounded",
        });
    }
    Ok(())
}
/// Bounded opaque identifier check for record ids and markers.
fn require_record_id(value: &str, field: &'static str) -> Result<(), OrsError> {
    if value.is_empty() || value.len() > MAX_BACKUP_ID_LEN || value.chars().any(char::is_control) {
        return Err(OrsError::InvalidField {
            field,
            reason: "record identity must be non-empty, bounded, and control-free",
        });
    }
    Ok(())
}
/// Bounded check for one durable identity a member carries.
fn require_durable_identity(
    value: &str,
    field: &'static str,
    max_len: usize,
) -> Result<(), OrsError> {
    if value.is_empty() || value.len() > max_len || value.chars().any(char::is_control) {
        return Err(OrsError::InvalidField {
            field,
            reason: "durable identity must be non-empty, bounded, and control-free",
        });
    }
    Ok(())
}
/// Source identity bound into every backup request and snapshot.
///
/// Every field is compared by the store against an owner-established current
/// value read from durable ORS state at the capture point, never accepted as a
/// caller assertion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrsBackupSourceIdentity {
    /// Installation-scoped authority lineage identity observed at the source.
    pub installation_id: String,
    /// ORS authority generation (epoch) observed at the source.
    pub ors_generation: u64,
    /// Must equal [`BACKUP_SNAPSHOT_SCHEMA_VERSION`].
    pub schema_version: u16,
    /// Digest the source store computed over its observed capture point.
    pub store_binding_digest: String,
}
impl OrsBackupSourceIdentity {
    /// Validate and bind a backup source identity.
    pub fn new(
        installation_id: String,
        ors_generation: u64,
        schema_version: u16,
        store_binding_digest: String,
    ) -> Result<Self, OrsError> {
        require_installation_id(&installation_id, "source_installation_id")?;
        if schema_version != BACKUP_SNAPSHOT_SCHEMA_VERSION {
            return Err(OrsError::MigrationRequired {
                reason: format!(
                    "backup schema {schema_version} unsupported, expected {BACKUP_SNAPSHOT_SCHEMA_VERSION}"
                ),
            });
        }
        require_digest(&store_binding_digest, "source_store_binding_digest")?;
        Ok(Self {
            installation_id,
            ors_generation,
            schema_version,
            store_binding_digest,
        })
    }
}
/// Canonical dependency fence bound with a backup request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrsBackupFence {
    /// Digest of the owner-established fence token inputs.
    pub fence_digest: String,
    /// Greatest durable monotonic order observed at the capture point.
    pub high_water_order: u64,
    pub captured_at_ms: i64,
    /// Digest the source store computed over its current canonical heads.
    pub canonical_dependency_fence: String,
}
impl OrsBackupFence {
    /// Validate and bind a backup fence.
    pub fn new(
        fence_digest: String,
        high_water_order: u64,
        captured_at_ms: i64,
        canonical_dependency_fence: String,
    ) -> Result<Self, OrsError> {
        require_digest(&fence_digest, "backup_fence_digest")?;
        require_digest(
            &canonical_dependency_fence,
            "backup_canonical_dependency_fence",
        )?;
        Ok(Self {
            fence_digest,
            high_water_order,
            captured_at_ms,
            canonical_dependency_fence,
        })
    }
}
/// The owner-established current state observed at one capture point.
///
/// The store fills this from durable ORS state inside the capture's single read
/// consistency point and compares every field against the request. Nothing here
/// is caller-supplied.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupCapturePoint {
    /// Digest binding source identity, schema marker, epoch, lineage,
    /// high-water, canonical dependency fence, and the observed table census.
    pub binding_digest: String,
    /// Current durable ORS schema/policy marker read from the base meta table.
    pub schema_marker: String,
    /// Current installation-scoped authority lineage identity.
    pub lineage_id: String,
    /// Current authority epoch in force for that lineage.
    pub authority_epoch: u64,
    /// Greatest durable monotonic order observed at the capture point.
    pub high_water_order: u64,
    /// Digest over the current canonical dependency heads.
    pub canonical_dependency_fence: String,
    /// Digest over the observed physical table census.
    pub table_census_digest: String,
    /// Row families observed materialized at the capture point.
    pub materialized_families: u32,
    /// Declared row families observed absent at the capture point.
    pub absent_families: u32,
    /// Aggregate row observations spent under this capture.
    pub work_units: u64,
    /// Aggregate digest-material bytes bound for the whole snapshot.
    pub total_bytes: u64,
    /// Capture point opened at (unix milliseconds).
    pub opened_at_ms: i64,
    /// Capture point closed at (unix milliseconds).
    pub closed_at_ms: i64,
}
impl BackupCapturePoint {
    /// Deterministic digest over the stable observed state of this point.
    ///
    /// Work, bytes, and wall-clock timings are deliberately excluded: they
    /// describe one execution, not the owner-established state a request must
    /// match, so including them would make the binding unreproducible.
    #[allow(
        clippy::too_many_arguments,
        reason = "one captured-state tuple; splitting it would let a caller bind only part of the observed state"
    )]
    pub fn binding_digest(
        schema_marker: &str,
        lineage_id: &str,
        authority_epoch: u64,
        high_water_order: u64,
        canonical_dependency_fence: &str,
        table_census_digest: &str,
    ) -> String {
        let mut material = String::new();
        material.push_str(schema_marker);
        material.push(':');
        material.push_str(lineage_id);
        material.push(':');
        material.push_str(&authority_epoch.to_string());
        material.push(':');
        material.push_str(&high_water_order.to_string());
        material.push(':');
        material.push_str(canonical_dependency_fence);
        material.push(':');
        material.push_str(table_census_digest);
        sha256_hex(material.as_bytes())
    }
}
/// Every durable ORS row family classifiable for backup disposition.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RowFamilyKind {
    /// Base schema, policy, and order marker rows.
    StoreMeta,
    /// Opaque recovery payload envelopes.
    Envelopes,
    /// Durable writer reservations.
    Reservations,
    /// Ordering Scope reservation index.
    ReservationOrders,
    /// Durable operation rows.
    Operations,
    /// Current Ordering Scope reservation heads.
    ScopeHeads,
    /// Terminal Ordering Scope observations.
    ScopeTerminals,
    /// Current typed operational records.
    OperationalCurrent,
    /// Historical typed operational records.
    OperationalHistory,
    /// Pending recovery-inbox items.
    RecoveryInbox,
    /// Disposed recovery-inbox history.
    RecoveryInboxHistory,
    /// Process start replay intents.
    ProcessStartReplay,
    /// Authority handoff evidence.
    AuthorityHandoffs,
    /// Process execution evidence.
    ProcessEvidence,
    /// Staged supervision-lease tickets.
    SupervisionLeaseStaged,
    /// Current supervision-lease revisions.
    SupervisionLeaseCurrent,
    /// Supervision-lease history.
    SupervisionLeaseHistory,
    /// Supervision-lease commit results.
    SupervisionLeaseResults,
    /// Supervision-lease stage resolutions.
    SupervisionStageResolutions,
    /// Local store rebind replay state.
    StoreRebindReplay,
    /// Local store failure retention.
    StoreFailureRetention,
    /// Unknown-commit recovery rows.
    UnknownCommitRecovery,
    /// Generation cutover ownership.
    CutoverOwnership,
    /// Host request rows.
    HostRequests,
    /// Activation result retention.
    ActivationResultRetention,
    /// Native worker claims.
    NativeWorkerClaims,
    /// Worker replay streams.
    ReplayStreams,
    /// Worker replay requests.
    ReplayRequests,
    /// Worker replay events.
    ReplayEvents,
    /// Worker replay acknowledgements.
    ReplayAcks,
    /// Doctor attempts.
    DoctorAttempts,
    /// Doctor effects.
    DoctorEffects,
    /// Doctor budgets.
    DoctorBudgets,
    /// Durable recovery problems.
    RecoveryProblems,
    /// Durable grant-closure commits.
    GrantClosureCurrent,
    /// Legacy grant-closure rows kept as an explicit migration input.
    GrantClosureLegacy,
    /// Immutable grant-closure second-phase links.
    GrantClosureSecondPhase,
    /// Grant-graph revision watermarks.
    GrantGraphRevisionCurrent,
    /// Restore-journal intents.
    RestoreJournalIntents,
    /// Restore-journal results.
    RestoreJournalResults,
    /// Restore-journal schema and binding markers.
    RestoreJournalMeta,
}
/// Backup disposition of one row family.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RowDisposition {
    /// Restores into a live ORS as `suspended_recovery` only.
    Restorable,
    /// Historical evidence; never restores as live state.
    NonrestorableHistorical,
    /// Forensic-only (I14-21: unknown stays reconciling).
    ForensicOnly,
    /// Declared by the admitted generation but not materialized in this source
    /// installation. The exclusion is source-bound and explicit: the family is
    /// never read and never silently omitted.
    OutsideAdmittedGeneration,
}
/// How the admitted generation materializes one row family's physical table.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RowFamilyPresence {
    /// The store always materializes the table at open; an absent table is
    /// durable schema damage and fails closed.
    AlwaysMaterialized,
    /// The store creates the table on first write. An absent table is a legal
    /// empty family and is recorded as
    /// [`RowDisposition::OutsideAdmittedGeneration`].
    CreatedOnFirstWrite,
}
impl RowFamilyKind {
    /// Physical ORS table name this family is declared under.
    ///
    /// The census is keyed by physical name so the store can enumerate the
    /// tables it actually holds and refuse any table with no disposition
    /// instead of dropping it from the denominator.
    #[allow(
        clippy::too_many_lines,
        reason = "the row-family census is one auditable table of physical name, kind, presence, and restore disposition"
    )]
    pub const fn table_name(self) -> &'static str {
        match self {
            Self::StoreMeta => "ors_meta_v1",
            Self::Envelopes => "ors_envelopes_v1",
            Self::Reservations => "ors_reservations_v1",
            Self::ReservationOrders => "ors_reservation_orders_v1",
            Self::Operations => "ors_operations_v1",
            Self::ScopeHeads => "ors_scope_heads_v1",
            Self::ScopeTerminals => "ors_scope_terminals_v1",
            Self::OperationalCurrent => "ors_operational_current_v1",
            Self::OperationalHistory => "ors_operational_history_v1",
            Self::RecoveryInbox => "ors_recovery_inbox_v1",
            Self::RecoveryInboxHistory => "ors_recovery_inbox_history_v1",
            Self::ProcessStartReplay => "ors_process_start_replay_v1",
            Self::AuthorityHandoffs => "ors_authority_handoffs_v1",
            Self::ProcessEvidence => "ors_process_evidence_v1",
            Self::SupervisionLeaseStaged => "ors_supervision_lease_staged_v1",
            Self::SupervisionLeaseCurrent => "ors_supervision_lease_current_v1",
            Self::SupervisionLeaseHistory => "ors_supervision_lease_history_v1",
            Self::SupervisionLeaseResults => "ors_supervision_lease_results_v1",
            Self::SupervisionStageResolutions => "ors_supervision_lease_stage_resolutions_v1",
            Self::StoreRebindReplay => "ors_store_rebind_replay_v1",
            Self::StoreFailureRetention => "ors_store_failure_retention_v1",
            Self::UnknownCommitRecovery => "ors_unknown_commit_recovery_v1",
            Self::CutoverOwnership => "ors_cutover_ownership_v1",
            Self::HostRequests => "ors_host_requests_v1",
            Self::ActivationResultRetention => "ors_agent_activation_results_v1",
            Self::NativeWorkerClaims => "ors_native_worker_claims_v1",
            Self::ReplayStreams => "ors_replay_streams_v1",
            Self::ReplayRequests => "ors_replay_requests_v1",
            Self::ReplayEvents => "ors_replay_events_v1",
            Self::ReplayAcks => "ors_replay_acks_v1",
            Self::DoctorAttempts => "ors_doctor_attempts_v1",
            Self::DoctorEffects => "ors_doctor_effects_v1",
            Self::DoctorBudgets => "ors_doctor_budgets_v1",
            Self::RecoveryProblems => "ors_recovery_problems_v1",
            Self::GrantClosureCurrent => "ors_grant_closure_current_v2",
            Self::GrantClosureLegacy => "ors_grant_closure_current_v1",
            Self::GrantClosureSecondPhase => "ors_grant_closure_second_phase_v1",
            Self::GrantGraphRevisionCurrent => "ors_grant_graph_revision_current_v1",
            Self::RestoreJournalIntents => "ors_restore_journal_intents_v1",
            Self::RestoreJournalResults => "ors_restore_journal_results_v1",
            Self::RestoreJournalMeta => "ors_restore_journal_meta_v1",
        }
    }
    /// How the admitted generation materializes this family's table.
    pub const fn presence(self) -> RowFamilyPresence {
        match self {
            // Created on first write by the owning path, so a fresh store never
            // materializes them. Opening one of these inside a single read
            // consistency point on a store that never wrote it would fail the
            // whole capture, so each carries an explicit absent disposition.
            Self::StoreFailureRetention
            | Self::CutoverOwnership
            | Self::HostRequests
            | Self::GrantClosureLegacy => RowFamilyPresence::CreatedOnFirstWrite,
            _ => RowFamilyPresence::AlwaysMaterialized,
        }
    }
    /// Static restore-safety disposition for one materialized row family.
    #[allow(
        clippy::too_many_lines,
        reason = "the row-family restore policy is one auditable statement of which ORS state may cross a restore boundary"
    )]
    pub const fn disposition(self) -> RowDisposition {
        match self {
            // Local rebind/failure debugging state and the legacy migration
            // input never cross a restore boundary.
            Self::StoreRebindReplay | Self::StoreFailureRetention | Self::GrantClosureLegacy => {
                RowDisposition::ForensicOnly
            }
            // Schema, policy, order, and binding markers are identity evidence
            // the canonical owner re-derives; they are never restored as data.
            Self::StoreMeta | Self::RestoreJournalMeta => RowDisposition::ForensicOnly,
            // Historical dispositions, past handoffs, old routes, old
            // activations, old worker claims, finished acknowledgements, and
            // diagnostic activity are evidence of what happened, never state.
            Self::RecoveryInboxHistory
            | Self::AuthorityHandoffs
            | Self::SupervisionLeaseHistory
            | Self::SupervisionLeaseResults
            | Self::SupervisionStageResolutions
            | Self::CutoverOwnership
            | Self::HostRequests
            | Self::ActivationResultRetention
            | Self::NativeWorkerClaims
            | Self::ReplayAcks
            | Self::DoctorAttempts
            | Self::DoctorEffects
            | Self::DoctorBudgets
            | Self::RestoreJournalResults => RowDisposition::NonrestorableHistorical,
            _ => RowDisposition::Restorable,
        }
    }
}
/// Disposition binding for one row family.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RowFamilyDisposition {
    pub kind: RowFamilyKind,
    /// Physical ORS table name this family is declared under.
    pub table_name: &'static str,
    /// How the admitted generation materializes the table.
    pub presence: RowFamilyPresence,
    /// Restore disposition when the table is materialized.
    pub disposition: RowDisposition,
}
impl RowFamilyDisposition {
    /// Bind a family to its static census entry.
    pub const fn of(kind: RowFamilyKind) -> Self {
        Self {
            kind,
            table_name: kind.table_name(),
            presence: kind.presence(),
            disposition: kind.disposition(),
        }
    }
}
/// The frozen row-family census: every ORS row family with an exact
/// disposition, so no table can disappear because its name was absent from an
/// older checklist.
#[allow(
    clippy::too_many_lines,
    reason = "the row-family census is one auditable list where each line records the restore rationale for one physical ORS table"
)]
pub fn row_family_census() -> Vec<RowFamilyDisposition> {
    vec![
        // Schema, policy, and order markers: identity evidence, not data.
        RowFamilyDisposition::of(RowFamilyKind::StoreMeta),
        // Opaque envelopes re-imported without interpretation.
        RowFamilyDisposition::of(RowFamilyKind::Envelopes),
        // Reservation rows re-stage as pending, never executing.
        RowFamilyDisposition::of(RowFamilyKind::Reservations),
        // Ordering index without execution meaning.
        RowFamilyDisposition::of(RowFamilyKind::ReservationOrders),
        // Canonical operation evidence, re-imported suspended only.
        RowFamilyDisposition::of(RowFamilyKind::Operations),
        // Ordering observations; the canonical owner re-verifies every head.
        RowFamilyDisposition::of(RowFamilyKind::ScopeHeads),
        // Terminal observations, never fresh heads.
        RowFamilyDisposition::of(RowFamilyKind::ScopeTerminals),
        // Current typed records are evidence snapshots, never live authority.
        RowFamilyDisposition::of(RowFamilyKind::OperationalCurrent),
        // Historical typed records carry the retry and checkpoint lineage.
        RowFamilyDisposition::of(RowFamilyKind::OperationalHistory),
        // Inbox items re-enter through the canonical import owner.
        RowFamilyDisposition::of(RowFamilyKind::RecoveryInbox),
        // Inbox history is evidence, never disposition.
        RowFamilyDisposition::of(RowFamilyKind::RecoveryInboxHistory),
        // Start intents replay as unknown, never running.
        RowFamilyDisposition::of(RowFamilyKind::ProcessStartReplay),
        // Past handoffs never re-fence authority.
        RowFamilyDisposition::of(RowFamilyKind::AuthorityHandoffs),
        // Process evidence is observational only.
        RowFamilyDisposition::of(RowFamilyKind::ProcessEvidence),
        // Staged lease tickets never execute on restore.
        RowFamilyDisposition::of(RowFamilyKind::SupervisionLeaseStaged),
        // Lease heads are evidence; old leases never activate.
        RowFamilyDisposition::of(RowFamilyKind::SupervisionLeaseCurrent),
        // Lease history is audit evidence only.
        RowFamilyDisposition::of(RowFamilyKind::SupervisionLeaseHistory),
        // Lease results re-verify, never apply.
        RowFamilyDisposition::of(RowFamilyKind::SupervisionLeaseResults),
        // Stage resolutions are historical facts.
        RowFamilyDisposition::of(RowFamilyKind::SupervisionStageResolutions),
        // Local rebind debugging state, never restored as data.
        RowFamilyDisposition::of(RowFamilyKind::StoreRebindReplay),
        // Local failure retention, never restored as data.
        RowFamilyDisposition::of(RowFamilyKind::StoreFailureRetention),
        // Unknown stays quarantined, no blind retry.
        RowFamilyDisposition::of(RowFamilyKind::UnknownCommitRecovery),
        // Old cutover ownership never re-owns.
        RowFamilyDisposition::of(RowFamilyKind::CutoverOwnership),
        // Old host routes never re-dispatch.
        RowFamilyDisposition::of(RowFamilyKind::HostRequests),
        // Old activation results never re-acknowledge.
        RowFamilyDisposition::of(RowFamilyKind::ActivationResultRetention),
        // Old worker claims never re-admit.
        RowFamilyDisposition::of(RowFamilyKind::NativeWorkerClaims),
        // Replay state replays suspended, never drives workers.
        RowFamilyDisposition::of(RowFamilyKind::ReplayStreams),
        // Replay acquisitions re-resolve, never execute.
        RowFamilyDisposition::of(RowFamilyKind::ReplayRequests),
        // Replay events are evidence, never commands.
        RowFamilyDisposition::of(RowFamilyKind::ReplayEvents),
        // Acknowledgements are historical facts.
        RowFamilyDisposition::of(RowFamilyKind::ReplayAcks),
        // Diagnostic attempts are evidence only.
        RowFamilyDisposition::of(RowFamilyKind::DoctorAttempts),
        // Diagnostic effects are evidence only.
        RowFamilyDisposition::of(RowFamilyKind::DoctorEffects),
        // Budget ledgers re-verify, never spend.
        RowFamilyDisposition::of(RowFamilyKind::DoctorBudgets),
        // Visible problems stay visible across restore.
        RowFamilyDisposition::of(RowFamilyKind::RecoveryProblems),
        // Closure rows are committed facts, never grants.
        RowFamilyDisposition::of(RowFamilyKind::GrantClosureCurrent),
        // Legacy closure bytes are an explicit migration input only.
        RowFamilyDisposition::of(RowFamilyKind::GrantClosureLegacy),
        // Second-phase links replay idempotently.
        RowFamilyDisposition::of(RowFamilyKind::GrantClosureSecondPhase),
        // Revision watermarks re-advance only forward.
        RowFamilyDisposition::of(RowFamilyKind::GrantGraphRevisionCurrent),
        // Journal intents replay idempotently.
        RowFamilyDisposition::of(RowFamilyKind::RestoreJournalIntents),
        // Journal results are historical answers.
        RowFamilyDisposition::of(RowFamilyKind::RestoreJournalResults),
        // Journal schema and binding markers are identity evidence.
        RowFamilyDisposition::of(RowFamilyKind::RestoreJournalMeta),
    ]
}
/// Whether one declared row family was materialized in the captured source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RowFamilyAvailability {
    /// The physical table was present and read inside the capture point.
    Materialized,
    /// The physical table was declared but absent in this source installation.
    ///
    /// The family is an explicit source-bound exclusion, never a silent
    /// omission and never a hidden table creation.
    DeclaredAbsent,
}
/// Per-family observed denominator for one captured snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RowFamilyCensus {
    pub kind: RowFamilyKind,
    pub availability: RowFamilyAvailability,
    /// Effective disposition: an absent family reports
    /// [`RowDisposition::OutsideAdmittedGeneration`].
    pub disposition: RowDisposition,
    /// Rows the source physically held for this family.
    pub observed_rows: u64,
    /// Rows this snapshot actually carries for this family.
    pub captured: u64,
    /// Rows the owner-declared cursor excluded from this family.
    ///
    /// `observed_rows == captured + window_rows` is the exact member
    /// denominator: a member dropped between the store and the page shows up as
    /// a gap instead of being absorbed into a count.
    pub window_rows: u64,
    /// Captured rows whose opaque payload could not be read.
    pub unavailable: u64,
    /// Digest binding this family's members in capture order.
    pub member_digest: String,
}
impl RowFamilyCensus {
    /// Deterministic digest binding one family's members in capture order.
    pub fn member_digest(kind: RowFamilyKind, entries: &[OrsBackupEntry]) -> String {
        let mut material = String::new();
        material.push_str(kind.table_name());
        material.push(':');
        for entry in entries.iter().filter(|entry| entry.family == kind) {
            material.push_str(&entry.member_key);
            material.push('/');
            material.push_str(&entry.record_id);
            material.push('/');
            material.push_str(&entry.order.to_string());
            material.push('/');
            material.push_str(&entry.payload_digest);
            material.push('/');
            material.push_str(entry.crypto.content_sha256.as_str());
            material.push(';');
        }
        sha256_hex(material.as_bytes())
    }
}
/// Per-family count carried by one page, used to prove member completeness.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupPageFamilyCount {
    pub kind: RowFamilyKind,
    pub captured: u64,
}
/// Stored effect class per backup entry (bytes stay in the store).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredEffectClass {
    /// Staged but not committed.
    Staged,
    /// Possibly committed, unresolved.
    Possible,
    /// Unknown; remains reconciling (I14-21).
    Unknown,
    /// Terminal effect.
    Terminal,
}
/// Retry and checkpoint lineage class of one durable record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryCheckpointClass {
    /// The record is not a retry or checkpoint record.
    NotApplicable,
    /// The record is a durable retry record; its retry lineage is opaque and
    /// only the canonical owner may interpret or replay it.
    Retry,
    /// The record is a durable job checkpoint; its checkpoint lineage is
    /// opaque and only the canonical owner may resume it.
    JobCheckpoint,
}
/// Generation lineage carried by one durable record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupGenerationLineage {
    pub cutover_id: String,
    pub route_scope: String,
    pub old_generation: Option<u64>,
    pub new_generation: u64,
    pub old_epoch: u64,
    pub new_epoch: u64,
}
/// Cryptographic identity of one stored opaque payload.
///
/// Import never treats a bare digest as sufficient: an entry whose key,
/// signature, or content schema identity is absent or unsupported stays
/// [`BackupBlockReason::UnknownCryptographicIdentity`] and is never activated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupEntryCryptoIdentity {
    /// Secret provider holding the payload key, when the payload is encrypted.
    pub key_provider: Option<String>,
    /// Provider-held key identity, never key material.
    pub key_id: Option<String>,
    /// Digest of the exact ciphertext or locator-bound bytes.
    pub content_sha256: String,
    /// Detached signature digest over the entry, when the source signed it.
    pub signature_sha256: Option<String>,
    /// Versioned content schema the source wrote.
    pub content_schema_version: u16,
}
impl BackupEntryCryptoIdentity {
    /// Typed reason this identity is not usable, or `None` when it is complete.
    ///
    /// A missing key id, a missing provider, a missing or malformed signature
    /// digest, and an unsupported content schema each keep the entry blocked;
    /// a digest shape alone never clears the entry.
    pub fn unknown_reason(&self, record_id: &str) -> Option<BackupBlockReason> {
        if self.content_schema_version != BACKUP_SNAPSHOT_SCHEMA_VERSION {
            return Some(BackupBlockReason::UnsupportedContentSchema {
                declared: self.content_schema_version,
            });
        }
        let has_key = self
            .key_provider
            .as_deref()
            .is_some_and(|provider| !provider.is_empty())
            && self.key_id.as_deref().is_some_and(|key| !key.is_empty());
        if !has_key {
            return Some(BackupBlockReason::UnknownCryptographicIdentity {
                record_id: record_id.to_owned(),
            });
        }
        if self
            .signature_sha256
            .as_deref()
            .is_none_or(|signature| signature.len() != 64)
        {
            return Some(BackupBlockReason::UnknownCryptographicIdentity {
                record_id: record_id.to_owned(),
            });
        }
        None
    }
}
/// Typed cause of an unreadable opaque payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpaqueUnavailableCause {
    /// The stored row bytes could not be read through the capture point.
    UnreadableRow,
    /// The row declared a payload digest that does not match the bytes held.
    DeclaredDigestMismatch,
    /// The row carries no recoverable content identity at all.
    MissingContentIdentity,
}
/// Whether one entry's opaque payload was readable at the capture point.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupEntryAvailability {
    /// The stored row and its declared payload digest agreed.
    Available,
    /// The opaque payload could not be read or did not match its declared
    /// digest. The snapshot can never report `Complete` while this is present.
    OpaqueUnavailable {
        /// Bounded typed cause; never payload bytes.
        cause: OpaqueUnavailableCause,
    },
}
/// Durable lineage preserved for one backup entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupEntryLineage {
    /// Owning subject of the durable record.
    pub subject_id: String,
    /// Stable ORS operation kind: retry, job checkpoint, generation cutover.
    pub operation_kind: String,
    /// Retry or checkpoint lineage class.
    pub retry_checkpoint_class: RetryCheckpointClass,
    /// Durable monotonic order when the family has one.
    pub source_order: Option<u64>,
    /// Capture high-water this entry was observed at.
    pub high_water_order: u64,
    pub authority_epoch: u64,
    pub lineage_id: String,
    pub state_fence_sha256: String,
    /// Generation lineage when the record carries a cutover record.
    pub generation: Option<BackupGenerationLineage>,
    /// Terminal receipt identity lineage.
    pub receipt_id: Option<String>,
    /// Terminal receipt digest lineage.
    pub receipt_sha256: Option<String>,
    pub payload_length: u64,
    pub created_at_ms: i64,
    pub cleanup_after_ms: Option<i64>,
}
/// One backup entry: digests and lineage only, never raw payload (redaction).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrsBackupEntry {
    /// Operation or durable identity this member carries.
    ///
    /// A family may hold several members under one operation identity (one
    /// lifecycle transition per history row), so this is not the member's
    /// uniqueness key; see [`OrsBackupEntry::member_key`].
    pub record_id: String,
    /// The exact physical durable key this member was read from.
    ///
    /// Uniqueness inside a family is `(member_key)`, and a repeated
    /// `(record_id, payload_digest)` pair is a duplicate member.
    pub member_key: String,
    pub family: RowFamilyKind,
    /// Capture-order index of this member inside the snapshot.
    pub order: u64,
    /// Digest of the stored row bytes held by the store.
    pub payload_digest: String,
    pub effect_class: StoredEffectClass,
    /// Retry/checkpoint, receipt, order, and generation lineage.
    pub lineage: BackupEntryLineage,
    /// Key, signature, and content-schema identity of the opaque payload.
    pub crypto: BackupEntryCryptoIdentity,
    /// Whether the opaque payload was readable at the capture point.
    pub availability: BackupEntryAvailability,
}
/// Bounded logical backup export request.
///
/// The byte, page, work, and duration budgets are aggregate: they bound the
/// whole capture, not each page of it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsBackupRequest {
    pub source: OrsBackupSourceIdentity,
    pub fence: OrsBackupFence,
    /// Exclusive lower capture-order bound for pagination.
    pub after_order: u64,
    /// Entries per page, `1..=MAX_BACKUP_PAGE_ENTRIES`.
    pub page_entries: u16,
    /// Aggregate byte budget, `1..=MAX_BACKUP_BYTES`.
    pub max_bytes: u64,
    /// Aggregate page budget, `1..=MAX_BACKUP_PAGES`.
    pub max_pages: u16,
    /// Aggregate work-unit budget, `1..=MAX_BACKUP_WORK_UNITS`.
    pub max_work_units: u64,
    /// Aggregate duration budget, `1..=MAX_BACKUP_DURATION_MS`.
    pub max_duration_ms: u64,
    /// Absolute expiry of this capture's page token (unix milliseconds).
    pub token_expires_at_ms: i64,
    /// Page-token validity window declared by the owner (unix milliseconds).
    pub token_ttl_ms: i64,
}
impl OrsBackupRequest {
    /// Validate and bind a backup request.
    #[allow(
        clippy::too_many_arguments,
        reason = "a backup request is one bounded tuple; splitting it would let a caller bind only part of the aggregate budgets"
    )]
    pub fn new(
        source: OrsBackupSourceIdentity,
        fence: OrsBackupFence,
        after_order: u64,
        page_entries: u16,
        max_bytes: u64,
        max_pages: u16,
        max_work_units: u64,
        max_duration_ms: u64,
        token_expires_at_ms: i64,
        token_ttl_ms: i64,
    ) -> Result<Self, OrsError> {
        if page_entries == 0 || page_entries > MAX_BACKUP_PAGE_ENTRIES {
            return Err(OrsError::InvalidCursorLimit);
        }
        if max_bytes == 0 || max_bytes > MAX_BACKUP_BYTES {
            return Err(OrsError::InvalidField {
                field: "backup_max_bytes",
                reason: "aggregate byte budget must be within 1 and MAX_BACKUP_BYTES",
            });
        }
        if max_pages == 0 || max_pages > MAX_BACKUP_PAGES {
            return Err(OrsError::InvalidField {
                field: "backup_max_pages",
                reason: "page budget must be within 1 and MAX_BACKUP_PAGES",
            });
        }
        if max_work_units == 0 || max_work_units > MAX_BACKUP_WORK_UNITS {
            return Err(OrsError::InvalidField {
                field: "backup_max_work_units",
                reason: "work budget must be within 1 and MAX_BACKUP_WORK_UNITS",
            });
        }
        if max_duration_ms == 0 || max_duration_ms > MAX_BACKUP_DURATION_MS {
            return Err(OrsError::InvalidField {
                field: "backup_max_duration_ms",
                reason: "duration budget must be within 1 and MAX_BACKUP_DURATION_MS",
            });
        }
        if token_ttl_ms <= 0 || token_ttl_ms > MAX_BACKUP_TOKEN_TTL_MS {
            return Err(OrsError::InvalidField {
                field: "backup_token_ttl_ms",
                reason: "page-token validity window must be within 1 and MAX_BACKUP_TOKEN_TTL_MS",
            });
        }
        if token_expires_at_ms != 0 && token_expires_at_ms - fence.captured_at_ms != token_ttl_ms {
            return Err(OrsError::InvalidField {
                field: "backup_token_expires_at_ms",
                reason: "page-token expiry must equal capture time plus the declared validity window",
            });
        }
        Ok(Self {
            source,
            fence,
            after_order,
            page_entries,
            max_bytes,
            max_pages,
            max_work_units,
            max_duration_ms,
            token_expires_at_ms,
            token_ttl_ms,
        })
    }
    /// Deterministic capture token for this source identity, fence, and cursor.
    ///
    /// Every page of one capture re-derives this token and validation refuses
    /// any page whose recorded token differs, so pages captured at different
    /// points, from different sources, or at different cursors cannot be mixed.
    pub fn page_fence_token(&self) -> String {
        page_fence_token(&self.source, &self.fence, self.after_order)
    }
    /// Absolute expiry of this capture, derived from the declared window.
    pub fn effective_expiry_ms(&self) -> i64 {
        if self.token_expires_at_ms == 0 {
            self.fence.captured_at_ms.saturating_add(self.token_ttl_ms)
        } else {
            self.token_expires_at_ms
        }
    }
    /// True when this capture's page token may still be served at `now_ms`.
    pub fn token_is_live(&self, now_ms: i64) -> bool {
        now_ms < self.effective_expiry_ms()
    }
}
/// The single derivation of a capture's page token.
///
/// Export, validation, and import all call this, so a page token cannot be
/// produced by one path and checked by another.
pub fn page_fence_token(
    source: &OrsBackupSourceIdentity,
    fence: &OrsBackupFence,
    after_order: u64,
) -> String {
    let mut material = String::new();
    material.push_str(&source.installation_id);
    material.push(':');
    material.push_str(&source.ors_generation.to_string());
    material.push(':');
    material.push_str(&source.store_binding_digest);
    material.push(':');
    material.push_str(&fence.fence_digest);
    material.push(':');
    material.push_str(&fence.high_water_order.to_string());
    material.push(':');
    material.push_str(&fence.canonical_dependency_fence);
    material.push(':');
    material.push_str(&after_order.to_string());
    sha256_hex(material.as_bytes())
}
/// One page of a backup snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsBackupPage {
    /// Zero-based page index; pages must be continuous.
    pub page_index: u32,
    pub entries: Vec<OrsBackupEntry>,
    /// Digest binding this page (see [`OrsBackupPage::page_digest`]).
    pub page_digest: String,
    /// True only on the final page.
    pub is_last: bool,
    /// Capture token every page of this capture must carry.
    pub fence_token: String,
    /// Digest of the preceding page, or `None` for page zero.
    pub predecessor_digest: Option<String>,
    /// Per-family member counts this page carries.
    pub family_counts: Vec<BackupPageFamilyCount>,
    /// Declared member count, bound by the page digest.
    pub entry_count: u64,
    /// Page issuance time (unix milliseconds).
    pub issued_at_ms: i64,
    /// Page token expiry (unix milliseconds).
    pub expires_at_ms: i64,
}
impl OrsBackupPage {
    /// Deterministic digest binding this page to its capture token, chain
    /// position, window, and exact member set.
    pub fn page_digest(&self) -> String {
        let mut material = String::new();
        material.push_str(&self.fence_token);
        material.push(':');
        material.push_str(&self.page_index.to_string());
        material.push(':');
        material.push_str(self.predecessor_digest.as_deref().unwrap_or(""));
        material.push(':');
        material.push_str(&self.issued_at_ms.to_string());
        material.push(':');
        material.push_str(&self.expires_at_ms.to_string());
        material.push(':');
        material.push_str(&self.entry_count.to_string());
        material.push(':');
        for count in &self.family_counts {
            material.push_str(count.kind.table_name());
            material.push('=');
            material.push_str(&count.captured.to_string());
            material.push(';');
        }
        material.push(':');
        for entry in &self.entries {
            material.push_str(entry.family.table_name());
            material.push('/');
            material.push_str(&entry.member_key);
            material.push('/');
            material.push_str(&entry.record_id);
            material.push('/');
            material.push_str(&entry.order.to_string());
            material.push('/');
            material.push_str(&entry.payload_digest);
            material.push('/');
            material.push_str(entry.crypto.content_sha256.as_str());
            material.push(';');
        }
        sha256_hex(material.as_bytes())
    }
}
/// Completeness of a backup snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupCompleteness {
    /// Every bound page present, every member captured and readable.
    Complete,
    /// Truncated but usable with a stated reason.
    Partial {
        /// Why the snapshot is partial.
        reason: String,
    },
    /// Unusable as an export; retained for forensics.
    Incomplete {
        /// Why the snapshot is incomplete.
        reason: String,
    },
}
/// Bounded logical backup snapshot: digest-bound pages, never authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsBackupSnapshot {
    pub source: OrsBackupSourceIdentity,
    pub fence: OrsBackupFence,
    /// Ordered pages starting at index zero.
    pub pages: Vec<OrsBackupPage>,
    /// Denominator digest binding source, fence, capture point, and pages.
    pub denominator_digest: String,
    pub entry_count: u64,
    pub total_bytes: u64,
    pub completeness: BackupCompleteness,
    /// The owner-established current state this snapshot was captured at.
    pub capture_point: BackupCapturePoint,
    /// Exact per-family denominator for every declared row family.
    pub family_denominator: Vec<RowFamilyCensus>,
    /// Exclusive lower capture-order bound this snapshot started after.
    pub after_order: u64,
}
impl OrsBackupSnapshot {
    /// Recompute the denominator digest over source, fence, capture point, every
    /// page digest, and every family member digest.
    #[allow(
        clippy::too_many_lines,
        reason = "the denominator digest is one auditable statement of everything the snapshot binds"
    )]
    pub fn snapshot_digest(&self) -> String {
        let mut material = String::new();
        material.push_str(&self.source.installation_id);
        material.push(':');
        material.push_str(&self.source.ors_generation.to_string());
        material.push(':');
        material.push_str(&self.source.store_binding_digest);
        material.push(':');
        material.push_str(&self.fence.fence_digest);
        material.push(':');
        material.push_str(&self.fence.high_water_order.to_string());
        material.push(':');
        material.push_str(&self.fence.canonical_dependency_fence);
        material.push(':');
        material.push_str(&self.capture_point.binding_digest);
        material.push(':');
        material.push_str(&self.after_order.to_string());
        material.push(':');
        for census in &self.family_denominator {
            material.push_str(census.kind.table_name());
            material.push('=');
            material.push_str(&census.observed_rows.to_string());
            material.push('/');
            material.push_str(&census.captured.to_string());
            material.push('/');
            material.push_str(&census.unavailable.to_string());
            material.push('/');
            material.push_str(&census.member_digest);
            material.push(';');
        }
        material.push(':');
        for page in &self.pages {
            material.push_str(&page.page_digest);
            material.push(':');
        }
        sha256_hex(material.as_bytes())
    }
    /// Full validation: the shared member validator, the whole-snapshot page
    /// chain, the completeness rules, and the denominator digest.
    pub fn validate(&self) -> Result<(), OrsError> {
        self.validate_members()?;
        check_page_chain(self)?;
        check_completeness(self)?;
        if self.denominator_digest != self.snapshot_digest() {
            return Err(OrsError::InvalidField {
                field: "backup_denominator_digest",
                reason: "denominator digest does not bind this snapshot's pages and family census",
            });
        }
        Ok(())
    }
    /// Member-level validation: capture token rebinding, per-page shape and
    /// counts, duplicate and missing members, denominator agreement, and
    /// payload availability.
    ///
    /// This is the real completeness gate and it runs during export *and* during
    /// import, so an untrusted page is never triaged on shape alone. Whole-
    /// snapshot page position and chaining live in [`Self::validate`], so a
    /// single page taken from the middle of a capture validates on its own.
    #[allow(
        clippy::too_many_lines,
        reason = "member completeness is one ordered proof over pages, members, and the family denominator"
    )]
    pub fn validate_members(&self) -> Result<(), OrsError> {
        require_digest(
            &self.source.store_binding_digest,
            "source_store_binding_digest",
        )?;
        require_digest(&self.fence.fence_digest, "backup_fence_digest")?;
        require_digest(
            &self.fence.canonical_dependency_fence,
            "backup_canonical_dependency_fence",
        )?;
        require_digest(&self.capture_point.binding_digest, "backup_capture_binding")?;
        require_digest(
            &self.capture_point.table_census_digest,
            "backup_table_census",
        )?;
        if self.source.installation_id != self.capture_point.lineage_id {
            return Err(OrsError::FenceMismatch);
        }
        if self.source.ors_generation != self.capture_point.authority_epoch {
            return Err(OrsError::StaleWriterEpoch);
        }
        if self.source.store_binding_digest != self.capture_point.binding_digest {
            return Err(OrsError::OrderingHeadMismatch);
        }
        if self.fence.canonical_dependency_fence != self.capture_point.canonical_dependency_fence
            || self.fence.high_water_order != self.capture_point.high_water_order
        {
            return Err(OrsError::OrderingHeadMismatch);
        }
        if self.pages.is_empty() {
            return Err(OrsError::InvalidField {
                field: "backup_pages",
                reason: "snapshot must carry at least one page",
            });
        }
        if self.pages.len() > usize::from(MAX_BACKUP_PAGES) {
            return Err(OrsError::InvalidField {
                field: "backup_max_pages",
                reason: "snapshot exceeds MAX_BACKUP_PAGES",
            });
        }
        let expected_token = page_fence_token(&self.source, &self.fence, self.after_order);
        let expiry = self.pages[0].expires_at_ms;
        let mut counted: u64 = 0;
        let mut bytes: u64 = 0;
        let mut seen: BTreeSet<(RowFamilyKind, String)> = BTreeSet::new();
        let mut seen_members: BTreeSet<(RowFamilyKind, String, String)> = BTreeSet::new();
        let mut captured_per_family = FamilyCountAccumulator::default();
        let mut last_order: Option<u64> = None;
        for page in &self.pages {
            check_page_shape(page, &expected_token, expiry)?;
            for entry in &page.entries {
                require_digest(&entry.payload_digest, "backup_payload_digest")?;
                require_durable_identity(
                    &entry.record_id,
                    "backup_entry_record_id",
                    MAX_BACKUP_MEMBER_KEY_BYTES,
                )?;
                require_durable_identity(
                    &entry.member_key,
                    "backup_entry_member_key",
                    MAX_BACKUP_MEMBER_KEY_BYTES,
                )?;
                require_digest(&entry.crypto.content_sha256, "backup_content_sha256")?;
                require_digest(
                    &entry.lineage.state_fence_sha256,
                    "backup_entry_state_fence",
                )?;
                if let Some(signature) = entry.crypto.signature_sha256.as_deref() {
                    require_digest(signature, "backup_entry_signature_sha256")?;
                }
                if entry.order <= self.after_order {
                    return Err(OrsError::InvalidField {
                        field: "backup_entry_order",
                        reason: "member order must be above the declared after_order bound",
                    });
                }
                if last_order.is_some_and(|previous| entry.order <= previous) {
                    return Err(OrsError::InvalidField {
                        field: "backup_entry_order",
                        reason: "member order must strictly increase across the snapshot",
                    });
                }
                last_order = Some(entry.order);
                if !seen.insert((entry.family, entry.member_key.clone())) {
                    return Err(OrsError::DuplicateConflict);
                }
                if !seen_members.insert((
                    entry.family,
                    entry.record_id.clone(),
                    entry.payload_digest.clone(),
                )) {
                    return Err(OrsError::DuplicateConflict);
                }
                captured_per_family.add(entry.family);
                counted = counted
                    .checked_add(1)
                    .ok_or(OrsError::ProjectionLimitExceeded)?;
                let digest_bytes = u64::try_from(entry.payload_digest.len())
                    .map_err(|_| OrsError::ProjectionLimitExceeded)?;
                bytes = bytes
                    .checked_add(digest_bytes)
                    .ok_or(OrsError::ProjectionLimitExceeded)?;
            }
        }
        if counted != self.entry_count {
            return Err(OrsError::InvalidField {
                field: "backup_entry_count",
                reason: "declared entry count does not match pages",
            });
        }
        if bytes != self.total_bytes {
            return Err(OrsError::InvalidField {
                field: "backup_total_bytes",
                reason: "declared total bytes does not match pages",
            });
        }
        check_family_denominator(self, &captured_per_family)
    }
    /// Builds the single-page view a quarantined import validates, so the
    /// shared member validator runs on the untrusted page itself.
    ///
    /// The capture point here is the source's *declared* point, rebound from
    /// the import request. The destination cannot re-observe the source's
    /// physical table census, so the census digest in this view is derived from
    /// the per-family census the page itself declares and the source's declared
    /// binding digest; it is never invented. The destination separately
    /// re-checks its own current policy marker, authority generation, and
    /// evidence provider, and this view proves the page is internally coherent
    /// and belongs to the declared source before any entry is triaged.
    pub fn for_import_page(
        import: &OrsBackupImportRequest,
        page: &OrsBackupPage,
    ) -> Result<Self, OrsError> {
        let mut census_material = String::new();
        for count in &page.family_counts {
            census_material.push_str(count.kind.table_name());
            census_material.push('=');
            census_material.push_str(&count.captured.to_string());
            census_material.push(';');
        }
        let capture_point = BackupCapturePoint {
            binding_digest: import.source.store_binding_digest.clone(),
            schema_marker: String::new(),
            lineage_id: import.source.installation_id.clone(),
            authority_epoch: import.source.ors_generation,
            high_water_order: import.fence.high_water_order,
            canonical_dependency_fence: import.fence.canonical_dependency_fence.clone(),
            table_census_digest: sha256_hex(census_material.as_bytes()),
            materialized_families: u32::try_from(page.family_counts.len()).unwrap_or(u32::MAX),
            absent_families: 0,
            work_units: page.entry_count,
            total_bytes: 0,
            opened_at_ms: page.issued_at_ms,
            closed_at_ms: page.issued_at_ms,
        };
        let mut total_bytes = 0_u64;
        for entry in &page.entries {
            total_bytes = total_bytes
                .checked_add(
                    u64::try_from(entry.payload_digest.len())
                        .map_err(|_| OrsError::ProjectionLimitExceeded)?,
                )
                .ok_or(OrsError::ProjectionLimitExceeded)?;
        }
        Ok(Self {
            source: import.source.clone(),
            fence: import.fence.clone(),
            pages: vec![page.clone()],
            denominator_digest: String::new(),
            entry_count: page.entry_count,
            total_bytes,
            completeness: BackupCompleteness::Complete,
            family_denominator: import_page_census(page),
            capture_point,
            after_order: import.after_order,
        })
    }
}
/// Per-family captured counts accumulated while walking a snapshot.
#[derive(Default)]
struct FamilyCountAccumulator {
    counts: Vec<(RowFamilyKind, u64)>,
}
impl FamilyCountAccumulator {
    fn add(&mut self, kind: RowFamilyKind) {
        match self.counts.iter_mut().find(|(key, _)| *key == kind) {
            Some((_, count)) => *count += 1,
            None => self.counts.push((kind, 1)),
        }
    }
    fn get(&self, kind: RowFamilyKind) -> u64 {
        self.counts
            .iter()
            .find(|(key, _)| *key == kind)
            .map_or(0, |(_, count)| *count)
    }
}
/// Derives the full per-family census a single import page must satisfy.
///
/// Every declared family appears exactly once, so the shared validator still
/// refuses a page that omits a declared family or overstates a member count.
fn import_page_census(page: &OrsBackupPage) -> Vec<RowFamilyCensus> {
    row_family_census()
        .iter()
        .map(|declared| {
            let captured = page
                .family_counts
                .iter()
                .find(|count| count.kind == declared.kind)
                .map_or(0, |count| count.captured);
            let members: Vec<OrsBackupEntry> = page
                .entries
                .iter()
                .filter(|entry| entry.family == declared.kind)
                .cloned()
                .collect();
            let unavailable = members
                .iter()
                .filter(|entry| !matches!(entry.availability, BackupEntryAvailability::Available))
                .count();
            RowFamilyCensus {
                kind: declared.kind,
                availability: RowFamilyAvailability::Materialized,
                disposition: declared.disposition,
                observed_rows: captured,
                captured,
                window_rows: 0,
                unavailable: u64::try_from(unavailable).unwrap_or(u64::MAX),
                member_digest: RowFamilyCensus::member_digest(declared.kind, &page.entries),
            }
        })
        .collect()
}
/// Validate one page in isolation: capture token, expiry window, entry bound,
/// declared counts, and the page's own digest over its members.
///
/// Whole-snapshot position and chaining are deliberately not checked here, so a
/// single page from the middle of a capture can be validated before import.
fn check_page_shape(
    page: &OrsBackupPage,
    expected_token: &str,
    expected_expiry: i64,
) -> Result<(), OrsError> {
    require_digest(&page.page_digest, "backup_page_digest")?;
    if page.entries.len() > usize::from(MAX_BACKUP_PAGE_ENTRIES) {
        return Err(OrsError::InvalidCursorLimit);
    }
    if page.fence_token != expected_token {
        return Err(OrsError::InvalidField {
            field: "backup_page_fence_token",
            reason: "page was captured under a different source, fence, or cursor",
        });
    }
    if page.expires_at_ms != expected_expiry {
        return Err(OrsError::InvalidField {
            field: "backup_page_expires_at_ms",
            reason: "every page of one capture must carry the same token expiry",
        });
    }
    if page.expires_at_ms <= page.issued_at_ms {
        return Err(OrsError::InvalidField {
            field: "backup_page_expires_at_ms",
            reason: "page token must expire strictly after it was issued",
        });
    }
    if page.page_digest != page.page_digest() {
        return Err(OrsError::InvalidField {
            field: "backup_page_digest",
            reason: "page digest does not bind its own members, token, and chain position",
        });
    }
    let counted =
        u64::try_from(page.entries.len()).map_err(|_| OrsError::ProjectionLimitExceeded)?;
    if counted != page.entry_count {
        return Err(OrsError::InvalidField {
            field: "backup_page_entry_count",
            reason: "declared page entry count does not match its members",
        });
    }
    let mut declared: u64 = 0;
    for count in &page.family_counts {
        let observed = page
            .entries
            .iter()
            .filter(|entry| entry.family == count.kind)
            .fold(0_u64, |total, _| total.saturating_add(1));
        if observed != count.captured {
            return Err(OrsError::InvalidField {
                field: "backup_page_family_counts",
                reason: "declared per-family page count does not match its members",
            });
        }
        declared = declared
            .checked_add(count.captured)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
    }
    if declared != counted {
        return Err(OrsError::InvalidField {
            field: "backup_page_family_counts",
            reason: "per-family page counts do not cover every member",
        });
    }
    Ok(())
}
/// Enforce whole-snapshot page position, chaining, and final-page marking.
///
/// A page served from an independent capture cannot be spliced into this
/// sequence: its index must continue from zero and its recorded predecessor
/// digest must equal the previous page's digest.
fn check_page_chain(snapshot: &OrsBackupSnapshot) -> Result<(), OrsError> {
    let mut predecessor: Option<String> = None;
    for (index, page) in snapshot.pages.iter().enumerate() {
        let expected = u32::try_from(index).map_err(|_| OrsError::InvalidField {
            field: "backup_page_index",
            reason: "page index exceeds u32 range",
        })?;
        if page.page_index != expected {
            return Err(OrsError::InvalidField {
                field: "backup_page_index",
                reason: "pages must be continuous from zero",
            });
        }
        if page.predecessor_digest.as_deref() != predecessor.as_deref() {
            return Err(OrsError::InvalidField {
                field: "backup_page_predecessor",
                reason: "page does not chain to the preceding page of this capture",
            });
        }
        if page.is_last && index + 1 != snapshot.pages.len() {
            return Err(OrsError::InvalidField {
                field: "backup_page_is_last",
                reason: "only the final page of a capture may be marked last",
            });
        }
        predecessor = Some(page.page_digest.clone());
    }
    if !snapshot.pages.last().is_some_and(|page| page.is_last) {
        return Err(OrsError::InvalidField {
            field: "backup_page_is_last",
            reason: "the final page of a capture must be marked last",
        });
    }
    Ok(())
}

/// Enforce that the declared denominator covers exactly the captured members.
fn check_family_denominator(
    snapshot: &OrsBackupSnapshot,
    captured_per_family: &FamilyCountAccumulator,
) -> Result<(), OrsError> {
    let census = row_family_census();
    if snapshot.family_denominator.len() != census.len() {
        return Err(OrsError::InvalidField {
            field: "backup_family_denominator",
            reason: "denominator must carry exactly one row per declared ORS row family",
        });
    }
    let mut unavailable_total: u64 = 0;
    for declared in &census {
        let observed = snapshot
            .family_denominator
            .iter()
            .find(|row| row.kind == declared.kind)
            .ok_or(OrsError::InvalidField {
                field: "backup_family_denominator",
                reason: "denominator omits a declared ORS row family",
            })?;
        let captured = captured_per_family.get(declared.kind);
        if observed.captured != captured
            || observed.observed_rows < captured.saturating_add(observed.window_rows)
            || observed.observed_rows != captured.saturating_add(observed.window_rows)
        {
            return Err(OrsError::InvalidField {
                field: "backup_family_denominator",
                reason: "denominator member count does not match the captured members",
            });
        }
        match observed.availability {
            RowFamilyAvailability::Materialized => {
                if declared.presence == RowFamilyPresence::AlwaysMaterialized
                    && observed.disposition != declared.disposition
                {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "backup_family_census",
                        reason:
                            "a materialized always-present row family carries a foreign disposition"
                                .to_owned(),
                    });
                }
                require_digest(&observed.member_digest, "backup_family_member_digest")?;
            }
            RowFamilyAvailability::DeclaredAbsent => {
                if declared.presence == RowFamilyPresence::AlwaysMaterialized {
                    return Err(OrsError::MigrationRequired {
                        reason: format!(
                            "row family {:?} is always materialized by the admitted generation but its table {} is absent",
                            declared.kind, declared.table_name
                        ),
                    });
                }
                if observed.captured != 0
                    || observed.observed_rows != 0
                    || observed.window_rows != 0
                    || observed.disposition != RowDisposition::OutsideAdmittedGeneration
                {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "backup_family_census",
                        reason: "an absent row family must be an explicit empty exclusion"
                            .to_owned(),
                    });
                }
            }
        }
        unavailable_total = unavailable_total
            .checked_add(observed.unavailable)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
    }
    let observed_unavailable = snapshot
        .pages
        .iter()
        .flat_map(|page| page.entries.iter())
        .filter(|entry| !matches!(entry.availability, BackupEntryAvailability::Available))
        .fold(0_u64, |total, _| total.saturating_add(1));
    if observed_unavailable != unavailable_total {
        return Err(OrsError::InvalidField {
            field: "backup_family_unavailable",
            reason: "declared unavailable count does not match unreadable members",
        });
    }
    Ok(())
}
/// Enforce completeness rules: `Complete` needs every member and no gap.
fn check_completeness(snapshot: &OrsBackupSnapshot) -> Result<(), OrsError> {
    match &snapshot.completeness {
        BackupCompleteness::Complete => {
            if snapshot.entry_count == 0 {
                return Err(OrsError::InvalidField {
                    field: "backup_completeness",
                    reason: "complete snapshot must carry entries",
                });
            }
            let unavailable = snapshot
                .family_denominator
                .iter()
                .fold(0_u64, |total, row| total.saturating_add(row.unavailable));
            if unavailable > 0 {
                return Err(OrsError::InvalidField {
                    field: "backup_completeness",
                    reason: "an opaque payload is unavailable, so the snapshot cannot be complete",
                });
            }
            if snapshot.total_bytes == 0 {
                return Err(OrsError::InvalidField {
                    field: "backup_total_bytes",
                    reason: "complete snapshot must carry a non-zero digest-material byte total",
                });
            }
            Ok(())
        }
        BackupCompleteness::Partial { reason } | BackupCompleteness::Incomplete { reason } => {
            if reason.is_empty() {
                return Err(OrsError::InvalidField {
                    field: "backup_completeness",
                    reason: "partial snapshots must state a reason",
                });
            }
            Ok(())
        }
    }
}
/// Destination identity for a backup import.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrsBackupDestination {
    pub installation_id: String,
    /// Admission receipt authorizing the import into this isolated install.
    pub admission_receipt: String,
    /// Whether canonical evidence is bound (checked at import, not here).
    pub evidence_bound: bool,
    /// Canonical purge-ledger revision this import was admitted against.
    pub purge_ledger_revision: String,
    /// Durable ORS policy/schema marker observed in the destination.
    pub destination_policy_marker: String,
    /// Detached admission signature the current evidence provider authenticates.
    pub admission_signature: Vec<u8>,
    /// Authority epoch the destination admitted this import under.
    pub destination_epoch: u64,
    /// Installation-scoped lineage the destination minted for this restore.
    pub destination_lineage_id: String,
}
impl OrsBackupDestination {
    /// Validate identifier shapes; evidence binding is checked at import.
    #[allow(
        clippy::too_many_arguments,
        reason = "one destination identity tuple; splitting it would let a caller bind only part of it"
    )]
    pub fn new(
        installation_id: String,
        admission_receipt: String,
        evidence_bound: bool,
        purge_ledger_revision: String,
        destination_policy_marker: String,
        admission_signature: Vec<u8>,
        destination_epoch: u64,
        destination_lineage_id: String,
    ) -> Result<Self, OrsError> {
        require_installation_id(&installation_id, "destination_installation_id")?;
        require_record_id(&admission_receipt, "backup_admission_receipt")?;
        require_record_id(&purge_ledger_revision, "backup_purge_ledger_revision")?;
        require_record_id(
            &destination_policy_marker,
            "backup_destination_policy_marker",
        )?;
        if admission_signature.is_empty()
            || admission_signature.len() > crate::MAX_INBOX_SIGNATURE_BYTES
        {
            return Err(OrsError::InvalidField {
                field: "backup_admission_signature",
                reason: "admission signature must be non-empty and bounded",
            });
        }
        if destination_epoch == 0 {
            return Err(OrsError::InvalidField {
                field: "backup_destination_epoch",
                reason: "destination epoch must be greater than zero",
            });
        }
        require_installation_id(&destination_lineage_id, "destination_lineage_id")?;
        Ok(Self {
            installation_id,
            admission_receipt,
            evidence_bound,
            purge_ledger_revision,
            destination_policy_marker,
            admission_signature,
            destination_epoch,
            destination_lineage_id,
        })
    }
}
/// Explicit import input: the only struct here that accepts deserialization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrsBackupImportRequest {
    /// Denominator digest of the snapshot under import.
    pub snapshot_digest: String,
    pub source: OrsBackupSourceIdentity,
    pub destination: OrsBackupDestination,
    /// The source's capture fence, replayed so the destination can rebind it.
    pub fence: OrsBackupFence,
    /// Exclusive lower capture-order bound the snapshot was taken after.
    pub after_order: u64,
}
/// Typed reason an entry is blocked: it stays blocked, never activated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupBlockReason {
    /// The key or signature identity is absent or unknown.
    UnknownCryptographicIdentity { record_id: String },
    /// The content schema version is not the admitted one.
    UnsupportedContentSchema { declared: u16 },
    /// The entry's opaque payload could not be read at the source.
    OpaquePayloadUnavailable { cause: OpaqueUnavailableCause },
    /// The destination's current policy/schema marker does not match.
    CurrentPolicyMarkerMismatch { declared: String, current: String },
    /// The destination's current authority epoch is above the declared one, so
    /// the import would revive a fenced epoch.
    DestinationEpochBelowCurrent { declared: u64, current: u64 },
    /// The import carries no current canonical evidence for the admission.
    MissingCanonicalEvidence,
    /// A durable recovery problem for this identity is still unreconciled.
    UnreconciledRecoveryProblem { record_id: String },
    /// The current owner validation does not cover this exact member set.
    MemberSetMismatch { record_id: String },
}
impl BackupBlockReason {
    /// Stable reason code carried in diagnostics (I07-20).
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnknownCryptographicIdentity { .. } => "UNKNOWN_CRYPTO_IDENTITY",
            Self::UnsupportedContentSchema { .. } => "UNSUPPORTED_CONTENT_SCHEMA",
            Self::OpaquePayloadUnavailable { .. } => "OPAQUE_PAYLOAD_UNAVAILABLE",
            Self::CurrentPolicyMarkerMismatch { .. } => "CURRENT_POLICY_MARKER_MISMATCH",
            Self::DestinationEpochBelowCurrent { .. } => "STALE_AUTHORITY_EPOCH",
            Self::MissingCanonicalEvidence => "NEEDS_EVIDENCE",
            Self::UnreconciledRecoveryProblem { .. } => "RECOVERY_REQUIRED",
            Self::MemberSetMismatch { .. } => "DESCENDANT_CLOSURE_INCOMPLETE",
        }
    }
}
/// Typed reason an entry is rejected: a durable decision, never a retry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupRejectReason {
    /// The same key with the same bytes is already durably stored.
    DuplicateReplay,
    /// The same key with different bytes is a durable identity conflict.
    IdentityConflict { record_id: String },
    /// The destination already durably disposed this identity.
    DurablyDisposed { record_id: String },
    /// The identity is under a durably revoked authority in the destination.
    RevokedAuthority { subject_id: String },
    /// The identity belongs to a durably revoked grant closure.
    RevokedGrantClosure { operation_id: String },
    /// The entry's authority epoch is fenced by the destination's current
    /// authority lineage.
    FencedAuthorityEpoch {
        entry_epoch: u64,
        current_epoch: u64,
    },
}
impl BackupRejectReason {
    /// Stable reason code carried in diagnostics (I07-20).
    pub const fn code(&self) -> &'static str {
        match self {
            Self::DuplicateReplay => "IDENTITY_ALREADY_STORED",
            Self::IdentityConflict { .. } => "IDENTITY_CONFLICT",
            Self::DurablyDisposed { .. } => "STALE_STATE_FENCE",
            Self::RevokedAuthority { .. } => "AUTHORITY_REVOKED",
            Self::RevokedGrantClosure { .. } => "CAPABILITY_GRANT_REVOKED",
            Self::FencedAuthorityEpoch { .. } => "STALE_AUTHORITY_EPOCH",
        }
    }
}
/// Typed reason an entry is retained for forensics only.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupForensicReason {
    /// Historical session/lease/route/grant row is never re-activated.
    HistoricalAuthorityRow,
    /// Forensic-only row never crosses a restore boundary.
    ForensicOnlyRow,
    /// The row family is declared by the admitted generation but is not
    /// materialized in this source installation.
    OutsideAdmittedGeneration,
}
impl BackupForensicReason {
    /// Stable reason code carried in diagnostics (I07-20).
    pub const fn code(self) -> &'static str {
        match self {
            Self::HistoricalAuthorityRow => "HISTORICAL_AUTHORITY_EVIDENCE",
            Self::ForensicOnlyRow => "FORENSIC_ONLY_EVIDENCE",
            Self::OutsideAdmittedGeneration => "OUTSIDE_ADMITTED_GENERATION",
        }
    }
}
/// Typed reason an entry stays unresolved for the canonical owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupUnresolvedReason {
    /// Quarantined for the canonical reconciliation owner; no authority.
    AwaitingCanonicalReconciliation,
    /// The stored effect class is already unknown, so it stays reconciling.
    UnknownEffectOutcome,
}
impl BackupUnresolvedReason {
    /// Stable reason code carried in diagnostics (I07-20).
    pub const fn code(self) -> &'static str {
        match self {
            Self::AwaitingCanonicalReconciliation => "UNKNOWN_OUTCOME",
            Self::UnknownEffectOutcome => "UNKNOWN_COMMIT",
        }
    }
}
/// Per-entry import outcome; unknown stays reconciling, never retried blindly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerEntryOutcome {
    /// Entry imported as `suspended_recovery` evidence.
    Imported,
    /// Entry rejected with a typed durable reason.
    Rejected {
        /// Why the entry was rejected.
        reason: BackupRejectReason,
    },
    /// Entry retained for forensics only.
    Forensic {
        /// Why the entry is forensic-only.
        reason: BackupForensicReason,
    },
    /// Entry blocked with a typed reason; it stays blocked, never activated.
    Blocked {
        /// Why the entry was blocked.
        reason: BackupBlockReason,
    },
    /// Entry unresolved; remains reconciling (I14-21).
    Unresolved {
        /// Why the entry is unresolved.
        reason: BackupUnresolvedReason,
    },
}
impl PerEntryOutcome {
    /// Stable reason code for this outcome, or `None` for a plain import.
    pub fn reason_code(&self) -> Option<&'static str> {
        match self {
            Self::Imported => None,
            Self::Rejected { reason } => Some(reason.code()),
            Self::Forensic { reason } => Some(reason.code()),
            Self::Blocked { reason } => Some(reason.code()),
            Self::Unresolved { reason } => Some(reason.code()),
        }
    }
}
/// Completeness of the current owner validation behind a zero-unresolved claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerValidationDisposition {
    /// Every entry was validated against current owner state.
    Complete,
    /// Some entries could not be validated against current owner state.
    Partial,
}
/// Current owner validation that a zero-unresolved claim must present.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentOwnerValidation {
    /// Snapshot denominator digest this validation covers.
    pub snapshot_digest: String,
    /// Identity of the canonical owner that performed the validation.
    pub owner_id: String,
    /// When the owner performed the validation (unix milliseconds).
    pub validated_at_ms: i64,
    /// Number of entries the owner actually validated.
    pub validated_entry_count: u64,
    /// Effect identities the owner could not resolve.
    pub unresolved_effect_identities: Vec<String>,
    /// Digest of the owner state the validation observed.
    pub provider_digest: String,
    /// Whether that validation was complete.
    pub disposition: OwnerValidationDisposition,
}
impl CurrentOwnerValidation {
    /// Validate the shape of a current owner validation.
    pub fn validate(&self) -> Result<(), OrsError> {
        require_digest(&self.snapshot_digest, "owner_validation_snapshot_digest")?;
        require_record_id(&self.owner_id, "owner_validation_owner_id")?;
        require_digest(&self.provider_digest, "owner_validation_provider_digest")?;
        if self.validated_at_ms <= 0 {
            return Err(OrsError::InvalidField {
                field: "owner_validation_validated_at_ms",
                reason: "current owner validation must carry an observation time",
            });
        }
        for identity in &self.unresolved_effect_identities {
            require_record_id(identity, "owner_validation_unresolved_effect")?;
        }
        Ok(())
    }
}
/// Result of the zero-unresolved gate carried on an import receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerZeroGate {
    /// The current owner validation is complete and no entry is unresolved.
    Satisfied,
    /// The gate refuses; the named reason is the exact blocker.
    Refused { reason: BackupBlockReason },
}
/// Import receipt with explicit per-entry outcomes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrsBackupImportReceipt {
    /// Snapshot denominator digest this receipt binds.
    pub snapshot_digest: String,
    pub source_installation: String,
    pub destination_installation: String,
    /// Per-entry outcomes keyed by record id.
    pub per_entry: Vec<(String, PerEntryOutcome)>,
    pub unresolved_count: u64,
    pub import_at_ms: i64,
    /// Canonical purge-ledger revision the import was admitted against.
    pub purge_ledger_revision: String,
    /// Stable reason codes for every non-imported entry, in outcome order.
    pub reason_codes: Vec<String>,
    /// Current owner validation the receipt's zero claim rests on.
    pub owner_validation: CurrentOwnerValidation,
    /// Outcome of the zero-unresolved gate for that validation.
    pub owner_zero_gate: OwnerZeroGate,
}
impl OrsBackupImportReceipt {
    /// Validate and bind an import receipt.
    #[allow(
        clippy::too_many_arguments,
        reason = "an import receipt is one immutable bound tuple; splitting it would permit a partial receipt"
    )]
    pub fn new(
        snapshot_digest: String,
        source_installation: String,
        destination_installation: String,
        per_entry: Vec<(String, PerEntryOutcome)>,
        unresolved_count: u64,
        import_at_ms: i64,
        purge_ledger_revision: String,
        owner_validation: CurrentOwnerValidation,
    ) -> Result<Self, OrsError> {
        require_digest(&snapshot_digest, "backup_snapshot_digest")?;
        require_installation_id(&source_installation, "source_installation_id")?;
        require_installation_id(&destination_installation, "destination_installation_id")?;
        require_record_id(&purge_ledger_revision, "backup_purge_ledger_revision")?;
        if import_at_ms <= 0 {
            return Err(OrsError::InvalidField {
                field: "backup_import_at_ms",
                reason: "import receipt must carry an observation time",
            });
        }
        owner_validation.validate()?;
        let reason_codes: Vec<String> = per_entry
            .iter()
            .filter_map(|(_, outcome)| outcome.reason_code())
            .map(str::to_owned)
            .collect();
        let validation = owner_validation.clone();
        let mut receipt = Self {
            snapshot_digest,
            source_installation,
            destination_installation,
            per_entry,
            unresolved_count,
            import_at_ms,
            purge_ledger_revision,
            reason_codes,
            owner_validation,
            owner_zero_gate: OwnerZeroGate::Refused {
                reason: BackupBlockReason::MissingCanonicalEvidence,
            },
        };
        receipt.owner_zero_gate = receipt.evaluate_owner_zero_gate(&validation);
        Ok(receipt)
    }
    /// Explicit gate: succeeds only when a complete current owner validation
    /// covers this exact snapshot and no entry remains unresolved.
    ///
    /// A new empty target never means old effects are resolved: the caller must
    /// present the canonical owner's own validation, it must bind this
    /// snapshot, cover every entry, and name no unresolved effect identity.
    pub fn known_zero_unresolved(&self, owner: &CurrentOwnerValidation) -> Result<(), OrsError> {
        if self.evaluate_owner_zero_gate(owner) == OwnerZeroGate::Satisfied {
            Ok(())
        } else {
            Err(OrsError::ReconciliationMismatch)
        }
    }
    /// Re-runs the zero-unresolved gate over an owner validation and returns the
    /// exact typed outcome instead of a bare error.
    pub fn evaluate_owner_zero_gate(&self, owner: &CurrentOwnerValidation) -> OwnerZeroGate {
        if owner.validate().is_err() {
            return OwnerZeroGate::Refused {
                reason: BackupBlockReason::MissingCanonicalEvidence,
            };
        }
        zero_unresolved_blocker(
            &self.snapshot_digest,
            &self.per_entry,
            self.unresolved_count,
            owner,
        )
        .map_or(OwnerZeroGate::Satisfied, |reason| OwnerZeroGate::Refused {
            reason,
        })
    }
}
/// The exact blocker that refuses a zero-unresolved claim, or `None` when a
/// complete current owner validation supports the claim.
fn zero_unresolved_blocker(
    snapshot_digest: &str,
    per_entry: &[(String, PerEntryOutcome)],
    unresolved_count: u64,
    owner: &CurrentOwnerValidation,
) -> Option<BackupBlockReason> {
    if owner.snapshot_digest != snapshot_digest
        || owner.disposition != OwnerValidationDisposition::Complete
    {
        return Some(BackupBlockReason::MissingCanonicalEvidence);
    }
    let covered = u64::try_from(per_entry.len()).unwrap_or(u64::MAX);
    if owner.validated_entry_count != covered {
        return Some(BackupBlockReason::MemberSetMismatch {
            record_id: owner.owner_id.clone(),
        });
    }
    if !owner.unresolved_effect_identities.is_empty() {
        return Some(BackupBlockReason::UnreconciledRecoveryProblem {
            record_id: owner.owner_id.clone(),
        });
    }
    if unresolved_count > 0
        || per_entry
            .iter()
            .any(|(_, outcome)| matches!(outcome, PerEntryOutcome::Unresolved { .. }))
    {
        return Some(BackupBlockReason::UnreconciledRecoveryProblem {
            record_id: owner.owner_id.clone(),
        });
    }
    None
}
/// Reject imports that relabel identity or arrive without bound evidence.
pub fn validate_import_binding(
    source: &OrsBackupSourceIdentity,
    dest: &OrsBackupDestination,
) -> Result<(), OrsError> {
    if source.installation_id == dest.installation_id {
        return Err(OrsError::InvalidField {
            field: "source_installation_id",
            reason: "source and destination installations must differ",
        });
    }
    if source.installation_id == dest.destination_lineage_id {
        return Err(OrsError::CanonicalEvidence(
            "backup restore must mint a new authority lineage, never reuse the source lineage"
                .to_owned(),
        ));
    }
    if dest.installation_id != dest.destination_lineage_id {
        return Err(OrsError::CanonicalEvidence(
            "backup import destination lineage does not name this installation".to_owned(),
        ));
    }
    if dest.admission_receipt.is_empty() {
        return Err(OrsError::CanonicalEvidence(
            "backup import lacks an admission receipt".to_owned(),
        ));
    }
    if !dest.evidence_bound {
        return Err(OrsError::CanonicalEvidence(
            "backup import lacks bound canonical evidence".to_owned(),
        ));
    }
    if dest.admission_signature.is_empty() {
        return Err(OrsError::CanonicalEvidence(
            "backup import lacks a detached admission signature".to_owned(),
        ));
    }
    Ok(())
}
/// Freeze check: any canonical head advance across import is rejected.
pub fn check_canonical_frozen(pre: &str, post: &str) -> Result<(), OrsError> {
    require_digest(pre, "backup_canonical_pre")?;
    require_digest(post, "backup_canonical_post")?;
    if pre == post {
        Ok(())
    } else {
        Err(OrsError::OrderingHeadMismatch)
    }
}
