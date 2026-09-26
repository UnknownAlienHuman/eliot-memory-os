use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::canonical_json_bytes;
use eliot_platform::PlatformHandle;
use eliot_process::ProcessStreamKind;
use eliot_receipts::{
    AuthorityBinding, GRANT_CLOSURE_SCHEMA, GRANT_CLOSURE_VERSION, GrantClosureOrsReceiptRef,
    ReceiptDispositionKind, ReceiptEnvelope, ReceiptIdentity,
};
use eliot_runtime_contracts::{
    GenerationCutoverRecord as RuntimeGenerationCutoverRecord, GenerationCutoverState,
    SignedSupervisionLease, VerifiedSupervisionLease, VerifiedSupervisionLeaseTerminalTransition,
};
use redb::{
    Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[path = "persistence_codec.rs"]
mod persistence_codec;
use persistence_codec::{
    LegacyGrantClosureRecord, LegacyGrantClosureState, decode, decode_legacy_grant_closure_record,
    decode_named, encode, is_current_grant_closure_shape,
};

#[path = "store/persistence_models.rs"]
mod persistence_models;
use persistence_models::{
    DurableGrantClosureRecord, DurableGrantClosureSecondPhaseRecord, DurableGrantGraphRevision,
    DurableInboxRecord, DurableOperationalRecord, DurableSupervisionLeaseResult,
    GRANT_CLOSURE_SECOND_PHASE_SCHEMA, GRANT_CLOSURE_SECOND_PHASE_VERSION, OperationalKind,
    ScopeReservationHead,
};

#[path = "store/restore_journal.rs"]
mod restore_journal;

#[path = "store/backup_snapshot.rs"]
mod backup_snapshot;

mod recovery_projection;

use crate::cutover_ownership::{
    GenerationCutoverOwnership, GenerationCutoverOwnershipReceipt, StoredCutoverOwnership,
};
use crate::{
    AcceptedPending, ActivationLifecycleRecord, ActivationLifecycleState,
    ActivationRecoverySnapshot, ActivationResultRetentionPhase, ActivationResultRetentionRecord,
    ActiveSessionBinding, AdmissionReservation, AdmissionReservationActivation,
    AdmissionReservationReceipt, AdmissionReservationRelease, AuthorityActivationReceipt,
    AuthorityHandoffBegin, AuthorityHandoffRecord, AuthorityHandoffState, AuthorityRevocation,
    AuthorityRevocationReceipt, AuthoritySnapshotReceipt, BACKUP_VERIFICATION_RESULT_RECORD_TYPE,
    BackupVerificationDisposition, BackupVerificationResultRecord, CanonicalDisposition,
    CanonicalReconciliation, CapabilityGrantActivation, CapabilityGrantProjection,
    CapabilityGrantRevocation, CapabilityIntroductionActivation, CapabilityIntroductionFence,
    CapabilityIntroductionProjection, CapabilityIntroductionReceipt, DeliveryAcknowledgement,
    DeliveryCursorReceipt, DeliveryCursorState, EpochIdentity, EpochLineage,
    GenerationCutoverReceipt, GenerationCutoverRecord, GenerationCutoverSnapshot,
    GenerationTransition, GenerationTransitionReceipt, GrantClosureCommit,
    GrantClosureCommitReceipt, GrantClosureFenceReceipt, GrantClosureFenceRequest,
    GrantClosureProjection, GrantClosureState, HostRequestRecord, HostRequestState, JobCheckpoint,
    KernelAuthoritySnapshot, LegacyUnscopedBackupVerificationClass, NativeWorkerClaimAdmission,
    NativeWorkerClaimRecord, NativeWorkerClaimStageOutcome, NativeWorkerClaimState, OpaqueLabel,
    OperationIdentity, OperationalMutationReceipt, OperationalPhase, OperationalRecordContext,
    OperationalRecordInput, OrsError, OrsSnapshotReceipt, OrsSnapshotRequest, PendingOperationPage,
    ProcessEvidenceRecord, ProcessStartReplayAbort, ProcessStartReplayRecord,
    ProcessStartReplayState, ProcessStreamRecoveryFence, ProcessStreamRecoveryLoadError,
    ProcessStreamRecoveryProjection, ProcessStreamRecoveryRevalidation,
    ProcessStreamRecoveryStatusProjection, ProcessStreamRecoveryWriteOutcome,
    ProcessStreamRetirementProof, ProcessStreamSourceResolver, RecoveredAuthoritySnapshot,
    RecoveryCursor, RecoveryInboxDisposition, RecoveryInboxItem, RecoveryInboxReceipt,
    RecoveryPage, RecoveryPayloadEnvelope, RecoveryProblem, RecoveryProblemKind, ReservationRecord,
    ReservationRequest, ReservationState, ReservedScope, RetryState, ScopeTerminalReceipt,
    ScopeTerminalView, SessionBindingReceipt, SessionDetach, StageReceipt, StagedOperation,
    StateFenceSnapshot, StreamRecoveryActivation, SupervisionLeaseCommitTicket,
    SupervisionLeasePrepareRequest, SupervisionLeaseProjection, SupervisionLeaseReceipt,
    SupervisionLeaseReceiptInput, SupervisionLeaseRecord, SupervisionLeaseSnapshot,
    SupervisionLeaseStageReceipt, SupervisionLeaseStageResolution,
    SupervisionLeaseStageResolutionDisposition, SupervisionLeaseTicketReconciliation,
    UnknownCommitOutcome, UnknownCommitRecord, UserBrokerFence, UserBrokerRegistration,
    UserBrokerRegistrationReceipt, WorkerReplayAck, WorkerReplayAckRecord, WorkerReplayBegin,
    WorkerReplayCursors, WorkerReplayDraft, WorkerReplayEvent, WorkerReplayRequestDecision,
    WorkerReplayRequestRecord, WorkerReplayStreamRecord, WriterReservationToken,
    is_replay_terminal_phase, parse_replay_stream_id, require_replay_claim_binding,
    signed_supervision_lease_from_verified, signed_terminal_supervision_lease_from_verified,
};

const META: TableDefinition<&str, &str> = TableDefinition::new("ors_meta_v1");
const ENVELOPES: TableDefinition<&str, &str> = TableDefinition::new("ors_envelopes_v1");
const RESERVATIONS: TableDefinition<&str, &str> = TableDefinition::new("ors_reservations_v1");
const RESERVATION_ORDERS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_reservation_orders_v1");
const OPERATIONS: TableDefinition<&str, &str> = TableDefinition::new("ors_operations_v1");
const SCOPE_HEADS: TableDefinition<&str, &str> = TableDefinition::new("ors_scope_heads_v1");
const SCOPE_TERMINALS: TableDefinition<&str, &str> = TableDefinition::new("ors_scope_terminals_v1");
const OPERATIONAL_CURRENT: TableDefinition<&str, &str> =
    TableDefinition::new("ors_operational_current_v1");
const OPERATIONAL_HISTORY: TableDefinition<&str, &str> =
    TableDefinition::new("ors_operational_history_v1");
const RECOVERY_INBOX: TableDefinition<&str, &str> = TableDefinition::new("ors_recovery_inbox_v1");
const RECOVERY_INBOX_HISTORY: TableDefinition<&str, &str> =
    TableDefinition::new("ors_recovery_inbox_history_v1");
const PROCESS_START_REPLAY: TableDefinition<&str, &str> =
    TableDefinition::new("ors_process_start_replay_v1");
const AUTHORITY_HANDOFFS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_authority_handoffs_v1");
const PROCESS_EVIDENCE: TableDefinition<&str, &str> =
    TableDefinition::new("ors_process_evidence_v1");
/// Versioned per-stream process-evidence recovery projections (issue #269).
///
/// One row per `(operation_id, stream)` identity, keyed `operation:stdout` or
/// `operation:stderr`, so stdout and stderr stay independent and exact. The
/// rows carry the immutable locator identity, exact durable coverage, the
/// typed transport/persistence state, the gap set and the reconciliation
/// owner/state — never stream bytes. This is one more table in the existing ORS
/// table family, owned by the same `RedbRecoveryStore` and written through the
/// same `persistence_codec`; it is not a second journal or table owner.
const PROCESS_STREAM_RECOVERY: TableDefinition<&str, &str> =
    TableDefinition::new("ors_process_stream_recovery_v1");
const SUPERVISION_LEASE_STAGED: TableDefinition<&str, &str> =
    TableDefinition::new("ors_supervision_lease_staged_v1");
const SUPERVISION_LEASE_CURRENT: TableDefinition<&str, &str> =
    TableDefinition::new("ors_supervision_lease_current_v1");
const SUPERVISION_LEASE_HISTORY: TableDefinition<&str, &str> =
    TableDefinition::new("ors_supervision_lease_history_v1");
const SUPERVISION_LEASE_RESULTS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_supervision_lease_results_v1");
const SUPERVISION_LEASE_STAGE_RESOLUTIONS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_supervision_lease_stage_resolutions_v1");
const STORE_REBIND_REPLAY: TableDefinition<&str, &str> =
    TableDefinition::new("ors_store_rebind_replay_v1");
const STORE_FAILURE_RETENTION: TableDefinition<&str, &str> =
    TableDefinition::new("ors_store_failure_retention_v1");
const UNKNOWN_COMMIT_RECOVERY: TableDefinition<&str, &str> =
    TableDefinition::new("ors_unknown_commit_recovery_v1");
/// Durable scan disclosure rows (issue #2900): one row per
/// `scan-disclosure:<installation>:<operation>` identity holding the exact
/// canonical receipt bytes under their digest plus the owner-admitted write
/// identity. A new table in the existing ORS family with the single
/// installation-bound scan-disclosure adapter as its one writer; it never
/// reuses [`UNKNOWN_COMMIT_RECOVERY`], because a scan disclosure receipt is
/// evidence with its own Prepared/Committed/Retired lifecycle, not a
/// canonical ordering write attempt.
const SCAN_DISCLOSURE_RECORDS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_scan_disclosure_v1");
/// Durable owner-backed `backup.verify` results (issue #2802; I5.27, I14.21).
///
/// One row per public request operation identity, so an exact replay of the same
/// operation reads back the same owner-proved result after a Kernel restart or
/// an Authority Epoch rotation, and a changed archive under the same identity is
/// a conflict rather than a second answer. It is a new table in the existing ORS
/// family with the single Kernel verify route as its one writer; it never reuses
/// [`UNKNOWN_COMMIT_RECOVERY`], because a read-only verification is not a
/// canonical write attempt and that table's own contract is one staged row per
/// admitted write attempt.
const BACKUP_VERIFICATION_RESULTS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_backup_verification_results_v1");
const CUTOVER_OWNERSHIP: TableDefinition<&str, &str> =
    TableDefinition::new("ors_cutover_ownership_v1");
const HOST_REQUESTS: TableDefinition<&str, &str> = TableDefinition::new("ors_host_requests_v1");
/// Durable bridge-event rows (issue #2561): one staged durable/control event
/// per `(stream_id, event_id)` identity with its bound canonical envelope
/// bytes. Disjoint from `HOST_REQUESTS`; keyed by `stream::event`.
const BRIDGE_EVENT_RECORDS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_bridge_event_records_v1");
/// Per-stream bridge-event cursor rows (issue #2561): durable/acked cursors
/// with staging provenance. Keyed by `stream_id`; never synthesized.
const BRIDGE_EVENT_CURSORS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_bridge_event_cursors_v1");
/// Durable bridge-event coverage gaps (issue #2561): forwarded gaps stay
/// visible without moving any cursor. Keyed by `gap_id`.
const BRIDGE_EVENT_GAPS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_bridge_event_gaps_v1");
/// Durable bridge-event Governor-handoff rows (issue #2561, I5(i)): one
/// coordinator-intake handoff per `(stream_id, event_id)` identity, persisted
/// at DURABLE stage time and marked reconciled by the event reconcile entry.
/// Keyed by `stream::event`. Disjoint from `HOST_REQUESTS`; the handoff binds
/// the staged envelope digest and the reconcile key, never a synthesized
/// intake or application claim.
const BRIDGE_EVENT_HANDOFFS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_bridge_event_handoffs_v1");
/// Maximum staged bridge-event rows. Mirrors the I14.2 canonical-writes pool
/// (2048 items): breach fails with [`OrsError::ProjectionLimitExceeded`]
/// (typed backpressure), never with silent loss.
const MAX_BRIDGE_EVENT_RECORDS: usize = 2048;
/// Maximum canonical envelope bytes staged per bridge event. Mirrors the I7.2
/// hard MCP structured response ceiling (256 KiB): larger envelopes fail with
/// [`OrsError::PayloadTooLarge`] instead of occupying unbounded durable
/// space.
const MAX_BRIDGE_EVENT_ENVELOPE_BYTES: usize = 256 * 1024;
/// Maximum rows served by one bridge-event pending page. Restart enumeration
/// walks pages with continuations; nothing materializes an unbounded page.
const MAX_BRIDGE_EVENT_PAGE: usize = 128;
/// Maximum handoff rows repaired by one recovery entry per stream namespace
/// (issue #2731, item 3): the bounded owner-recovery driver restores at most
/// this many missing handoffs, then reports its continuation flag so the next
/// legitimate recovery entry resumes. Bounded like the pending page so one
/// reconcile never holds the write lock for an unbounded sweep.
const MAX_BRIDGE_HANDOFF_REPAIR_PER_RECOVERY: usize = 64;
/// Maximum handoff rows retired by one recovery entry per stream namespace
/// (issue #2731, item 5). Same page-scale bound as the repair slice above:
/// retirement converges over successive legitimate recovery entries instead
/// of one unbounded sweep under the write lock.
const MAX_BRIDGE_HANDOFF_RETIRE_PER_RECOVERY: usize = 64;
/// Maximum recorded coverage gaps per stream. Breach fails with
/// [`OrsError::ProjectionLimitExceeded`]; gaps never compact cursors.
const MAX_BRIDGE_EVENT_GAPS_PER_STREAM: usize = 256;
/// Maximum live position rows retained per owner namespace (issue #2885,
/// item 2). One position exists only with its staged event, so this caps the
/// un-compacted exact-replay window beside the already-capped record, handoff
/// and commitment budgets. Position-prefix compaction drains the window over
/// successive legitimate recovery entries; a fresh position is admitted only
/// while the namespace holds fewer than this many position rows. Breach fails
/// with [`OrsError::ProjectionLimitExceeded`] (typed backpressure), never
/// with silent loss or an unbounded index.
const MAX_BRIDGE_POSITION_LIVE_PER_NAMESPACE: usize = 4096;
const MAX_BRIDGE_RECOVERY_STREAMS_PER_PAGE: usize = 4;
const MAX_BRIDGE_RECOVERY_WINDOWS: usize = 64;
const MAX_BRIDGE_RECOVERY_CUTS: usize = 4096;
const MAX_BRIDGE_RECOVERY_REPLY_BYTES: usize = 256 * 1024;
const BRIDGE_RECOVERY_WINDOW_TTL_MS: u64 = 5 * 60 * 1000;
const BRIDGE_OWNER_LIST_INDEX_SCHEMA_KEY: &str = "bridge_owner_list_index_schema";
const BRIDGE_OWNER_LIST_INDEX_SCHEMA_V2: &str = "v2";
const BRIDGE_OWNER_LIST_SEQUENCE_KEY: &str = "bridge_owner_list_sequence";
const BRIDGE_RECOVERY_WINDOW_SEQUENCE_KEY: &str = "bridge_recovery_window_sequence";
const BRIDGE_RECOVERY_LEGACY_UNPROVEN_KEY: &str = "bridge_recovery_legacy_unproven_v1";
/// Committed-and-acknowledged bridge-event rows retained per stream for
/// duplicate suppression. Compaction evicts only acked rows older than this
/// window; cursors are never evicted.
const RETAIN_BRIDGE_EVENT_ACKED_PER_STREAM: u64 = 512;
/// Stored phase of a durably staged bridge event. The stage entry is the
/// durable relation, so staging always persists `DURABLE`; `RECEIVED` is the
/// pre-stage transport fact answered without a row.
const BRIDGE_EVENT_PHASE_DURABLE: &str = "DURABLE";
/// Privacy disposition persisted on a staged bridge event (issue #2561, I7.23:
/// secret values, provider-forbidden hidden reasoning, and data outside the
/// `WorkScope` privacy boundary are never persisted merely to preserve
/// "rawness" — the ingest path stores the exact transport hash plus either
/// the allowed raw bytes or a deterministic redacted representation with a
/// redaction receipt). The decision is computed over the canonical envelope
/// bytes before any durable write and re-verified by the stage entry, so a
/// denied payload is redacted with its receipt, never persisted raw.
const BRIDGE_EVENT_PRIVACY_ALLOWED: &str = "allowed";
/// Privacy disposition stored when the canonical envelope bytes carry denied
/// content: only the deterministic redacted projection plus the redaction
/// receipt facts are staged.
const BRIDGE_EVENT_PRIVACY_REDACTED: &str = "redacted";
/// Redaction reason stored when denied content forces the redacted path. Uses
/// the closed wire reason vocabulary shared with the protocol redaction
/// receipt (`FORBIDDEN_CONTENT_DETECTED` / `DECLARED_OUT_OF_SCOPE`); this
/// owner only ever mints the detected reason.
const BRIDGE_EVENT_REDACTION_REASON_FORBIDDEN: &str = "FORBIDDEN_CONTENT_DETECTED";
/// Marker prefix of every deterministic redacted projection minted by this
/// owner. Distinct from the ACP journal marker: each minting owner names its
/// own deterministic projection so a receipt always names the projection its
/// owner actually stored.
const BRIDGE_EVENT_REDACTED_PROJECTION_MARKER: &str = "redacted/bridge-event-v1";
/// Byte patterns that must never persist as admissible staged bytes. Matched
/// case-insensitively against the lossy UTF-8 decoding of the canonical
/// envelope bytes: the operationalization, for this byte-only persistence
/// owner, of the I7.23 denied classes (secret values, provider-forbidden
/// hidden reasoning, data outside the `WorkScope` privacy boundary). The same
/// denied vocabulary is enforced by the ACP durable journal on its own path;
/// each owner scans the bytes it persists, so neither trusts the other.
const BRIDGE_EVENT_DENIED_CONTENT_TOKENS: &[&str] = &[
    "secret",
    "passwd",
    "password",
    "bearer",
    "hidden_reasoning",
    "provider_hidden",
    "api_key",
];
/// Maximum redacted classes carried by one bridge-event redaction.
const MAX_BRIDGE_EVENT_REDACTED_CLASSES: usize = 16;
/// Maximum staged bridge-event handoff rows. Mirrors the bridge-event record
/// bound: breach fails with [`OrsError::ProjectionLimitExceeded`] (typed
/// backpressure), never with silent loss of handoff state.
const MAX_BRIDGE_EVENT_HANDOFFS: usize = 2048;
/// Handoff state persisted at DURABLE stage time: the staged envelope is
/// durably held and handed toward Governor/coordinator intake, not yet
/// reconciled against a consumed frontier.
const BRIDGE_EVENT_HANDOFF_HANDED_OFF: &str = "handed_off";
/// Handoff state once the event reconcile entry binds the row to a
/// reconciliation key at or past its sequence.
const BRIDGE_EVENT_HANDOFF_RECONCILED: &str = "reconciled";
/// Durable bridge-stream owner bindings (issue #2729): one authenticated
/// owner binding per admitted stream namespace plus one per unscoped-gap
/// reporter occurrence. Keyed by the versioned namespace digest; the row
/// carries the full binding (installation/authority lineage, principal,
/// producer, creating session occurrence, stream incarnation) and its
/// revision. The last-staging connection stays observation metadata on the
/// cursor/event rows only — never scope material here.
const BRIDGE_STREAM_OWNERS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_bridge_stream_owners_v1");
/// Presenter-scope owner enumeration index for finite recovery windows.
/// Keys are `{scope_digest}::{binding_sequence:020}` and values are owner
/// namespaces. New owners are indexed atomically with their immutable row;
/// existing owner rows are indexed once during initialization.
const BRIDGE_STREAM_OWNER_LIST_INDEX: TableDefinition<&str, &str> =
    TableDefinition::new("ors_bridge_stream_owner_list_v1");
/// Persisted expiring recovery windows, bound to a presenter and an owner
/// inventory cutoff. A caller's key is only a lookup selector, never proof.
const BRIDGE_EVENT_RECOVERY_WINDOWS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_bridge_event_recovery_windows_v1");
/// Per-window stream and gap cuts, keyed `{window_key}::{owner_namespace}`.
const BRIDGE_EVENT_RECOVERY_CUTS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_bridge_event_recovery_cuts_v1");
/// Monotonic per-owner view revisions. Event, gap, acknowledgement, and
/// compaction writes bump this value so continuations detect changed views.
const BRIDGE_EVENT_RECOVERY_REVISIONS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_bridge_event_recovery_revisions_v1");
/// Owner-namespace domain for admitted event streams (issue #2729).
///
/// The namespace binds, in order: this literal, the authority lineage, the
/// Kernel-observed principal, the admitted producer, and the local stream
/// name. Connection, deadline, fence, epoch sequence, and generation are
/// transport/era binding and are never key material: the recovery transport
/// carries its own current identity while the recovered stream keeps its
/// original one (mirrors the #2571 logical-key rule).
const BRIDGE_STREAM_OWNER_NAMESPACE: &str = "eliot.bridge-event.stream-owner.v1";
/// Owner-namespace domain for connection-level (unscoped) coverage gaps
/// (issue #2729). Binds this literal, the authority lineage, and the
/// Kernel-observed principal, with the producer and stream slots fixed to
/// the explicit unbound marker: the gap has its own admitted
/// producer/session occurrence even when no stream is known, namespaced
/// through that owner's explicit continuity rather than a bare global gap
/// ID or a fabricated task.
const BRIDGE_GAP_OWNER_NAMESPACE: &str = "eliot.bridge-event.gap-owner.v1";
/// Version of the bridge-stream owner binding carried by every owner row.
const BRIDGE_STREAM_OWNER_VERSION: u16 = 1;
/// Incarnation assigned at the first admitted bind of a stream namespace.
/// Re-creation under a new incarnation belongs to retention/recreation
/// (#2731), which owns no writer here: the store assigns this value, never
/// the caller.
const BRIDGE_STREAM_OWNER_INITIAL_INCARNATION: u64 = 1;
/// Revision assigned at the first admitted bind of a stream namespace.
/// Expected-revision checks in the acknowledgement batch detect an owner
/// change between resolution and commit.
const BRIDGE_STREAM_OWNER_INITIAL_REVISION: u64 = 1;
/// Owner-row kind for an admitted event stream namespace.
const BRIDGE_STREAM_OWNER_KIND_STREAM: &str = "stream";
/// Owner-row kind for an unscoped-gap reporter occurrence namespace.
const BRIDGE_STREAM_OWNER_KIND_UNSCOPED_GAP: &str = "unscoped-gap";
/// Maximum bound owner namespaces. Mirrors the bridge-event record bound:
/// breach fails with [`OrsError::ProjectionLimitExceeded`] (typed
/// backpressure), never with silent loss of ownership state.
const MAX_BRIDGE_STREAM_OWNERS: usize = 2048;
/// Maximum acknowledgement items applied by one owner-checked batch.
/// Mirrors the reconcile consumed-frontier bound so one batch never exceeds
/// what one reconcile frame may present.
const MAX_BRIDGE_ACK_BATCH: usize = 1024;
/// Ordered bridge-event position index (issue #2730): one entry per admitted
/// stream position binding that position to exactly one logical event.
/// Keyed by `{owner_namespace}::{sequence:020}` (zero-padded so the byte
/// order is the numeric order); the value is the bound `event_id`. Written
/// atomically in the same ORS transaction as the event row, never updated,
/// never deleted: a compacted position keeps its binding forever, so one
/// admitted position identifies exactly one logical event for the life of
/// the stream incarnation. Only owner-checked rows are indexed; legacy
/// ownerless rows keep their existing scan-checked invariant and are never
/// inferred into this index.
const BRIDGE_EVENT_POSITIONS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_bridge_event_positions_v1");
/// Retained bridge-event replay commitments (issue #2730): the original
/// admitted identity and content commitment of compacted events. Keyed by
/// `{owner_namespace}::{event_id}`; written atomically in the same ORS
/// transaction that compacts the live row, so an exact replay after
/// compaction still answers from retained evidence with `fresh: false`
/// instead of minting a second logical event. Bounded per stream and in
/// total (see the caps below): once exact evidence legitimately expires,
/// the retained compacted boundary answers the explicit retired
/// disposition — never a fabricated duplicate and never a fresh insertion.
const BRIDGE_EVENT_REPLAY_COMMITMENTS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_bridge_event_replay_v1");
/// Maximum contiguous-frontier steps walked by one cursor advance (issue
/// #2730, item 4). One advance closes at most one page of adjacent
/// positions; the persisted cursor is the exact resume point, so a longer
/// reorder closure continues on the next legitimate stage/acknowledgement
/// entry, which reports a conservative frontier until then.
const MAX_BRIDGE_CURSOR_WALK: usize = 128;
/// Maximum retained replay commitments per owner namespace (issue #2730,
/// item 2): one retention window of exact post-compaction evidence beyond
/// the live window. Older compacted identities degrade to the retained
/// compacted-boundary retired disposition; they are never re-admitted.
const MAX_BRIDGE_EVENT_REPLAY_COMMITMENTS_PER_STREAM: usize = 512;
/// Maximum retained replay commitments in the whole store (issue #2730):
/// twice the live-record bound, so commitment scans stay bounded. Pressure
/// evicts the globally oldest compacted commitment first; the compacted
/// boundary still blocks re-admission, so acknowledgement never fails for
/// commitment pressure.
const MAX_BRIDGE_EVENT_REPLAY_COMMITMENTS: usize = 4096;
/// Version of the bridge replay-commitment row carried by every commitment.
const BRIDGE_REPLAY_COMMITMENT_VERSION: u16 = 1;
/// `META` marker recording the completed bridge position/replay index
/// migration (issue #2730, item 6).
const BRIDGE_REPLAY_INDEX_SCHEMA_KEY: &str = "bridge_replay_index_schema";
/// Expected value of [`BRIDGE_REPLAY_INDEX_SCHEMA_KEY`].
const BRIDGE_REPLAY_INDEX_SCHEMA_V1: &str = "eliot.ors.bridge-replay-index.v1";
/// Stage outcome disposition for a request whose exact replay evidence has
/// legitimately expired past the retained compacted boundary (issue #2730,
/// item 2): an explicit retired/unverifiable recovery disposition with
/// `fresh: false`. A missing row below the boundary is not a new event.
const BRIDGE_EVENT_DISPOSITION_RETIRED: &str = "retired";

/// One durably staged bridge-forwarded event (issue #2561).
///
/// Private to the store: the public boundary exchanges validated JSON only,
/// while the Kernel route owner holds the typed views. The row binds the
/// event identity to its exact canonical envelope bytes and digest, the
/// producer/generation/authority facts, the staging connection, and the
/// phase. Same-identity replays compare against this row; changed bytes never
/// overwrite it.
///
/// Privacy (I7.23) is decided before persistence: `transport_hash` is the
/// immutable hash of the original canonical envelope bytes; admissible rows
/// store those bytes verbatim (`redacted == false`), while rows whose bytes
/// carried denied content store only the deterministic redacted projection
/// (`redacted == true`) plus the redaction receipt facts. Rows written before
/// the privacy fields existed carry empty privacy facts and validate as
/// legacy admissible rows; every row written by the current stage entry
/// carries the full decision.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeEventRow {
    contract_version: u16,
    stream_id: String,
    event_id: String,
    sequence: u64,
    producer_id: String,
    producer_generation: u64,
    authority_epoch: String,
    envelope_sha256: String,
    envelope_bytes: Vec<u8>,
    staging_connection: String,
    staged_at_ms: u64,
    phase: String,
    /// Versioned owner namespace digest binding this event to its admitted
    /// stream owner (issue #2729). Empty on rows staged before owner
    /// binding existed: such legacy rows validate as before and stay
    /// preserved, but owner-checked reads never select them, so they are
    /// neither silently adopted nor deleted.
    #[serde(default)]
    owner_namespace: String,
    #[serde(default)]
    transport_hash: String,
    #[serde(default)]
    redacted: bool,
    #[serde(default)]
    redaction_reason: String,
    #[serde(default)]
    redacted_classes: Vec<String>,
    #[serde(default)]
    redaction_marker: String,
    #[serde(default)]
    redaction_version: u16,
}

impl BridgeEventRow {
    fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != crate::CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        bridge_identity_text(&self.stream_id, "stream_id")?;
        bridge_identity_text(&self.event_id, "event_id")?;
        if self.sequence == 0 {
            return Err(OrsError::InvalidField {
                field: "sequence",
                reason: "bridge event sequence must be nonzero",
            });
        }
        crate::model::validate_text(&self.producer_id, "producer_id")?;
        if self.producer_generation == 0 {
            return Err(OrsError::InvalidField {
                field: "producer_generation",
                reason: "bridge event producer generation must be nonzero",
            });
        }
        // Lineage-aware epoch text (`lineage:sequence`); compared exactly by
        // the route owner, never coerced to a scalar here.
        crate::model::validate_text(&self.authority_epoch, "authority_epoch")?;
        crate::model::validate_digest(&self.envelope_sha256, "envelope_sha256")?;
        if self.envelope_bytes.is_empty()
            || self.envelope_bytes.len() > MAX_BRIDGE_EVENT_ENVELOPE_BYTES
        {
            return Err(OrsError::PayloadTooLarge);
        }
        crate::model::validate_text(&self.staging_connection, "staging_connection")?;
        if self.phase != BRIDGE_EVENT_PHASE_DURABLE {
            return Err(OrsError::InvalidField {
                field: "phase",
                reason: "staged bridge events persist the DURABLE phase",
            });
        }
        if !self.owner_namespace.is_empty() {
            crate::model::validate_digest(&self.owner_namespace, "owner_namespace")?;
        }
        self.validate_privacy()
    }

    /// Validates the I7.23 disclosure/retention decision carried by this row.
    ///
    /// Admissible rows store the original bytes verbatim: the immutable
    /// transport hash must then bind both the stored bytes and the envelope
    /// identity digest. Redacted rows store only the deterministic projection
    /// recomputed here from the transport hash and the receipt classes, so a
    /// corrupted projection fails as an integrity mismatch instead of
    /// reporting redacted facts over foreign bytes. Rows predating the
    /// privacy fields (empty transport hash on an admissible row) validate as
    /// legacy rows against the envelope identity digest.
    fn validate_privacy(&self) -> Result<(), OrsError> {
        if !self.redacted {
            if !self.redaction_reason.is_empty()
                || !self.redacted_classes.is_empty()
                || !self.redaction_marker.is_empty()
                || self.redaction_version != 0
            {
                return Err(OrsError::InvalidField {
                    field: "redaction",
                    reason: "admissible bridge events carry no redaction facts",
                });
            }
            if self.transport_hash.is_empty() {
                // Legacy row predating the privacy decision: the stored bytes
                // are the verbatim envelope bound by the identity digest.
                if crate::model::sha256_hex(&self.envelope_bytes) != self.envelope_sha256 {
                    return Err(OrsError::PayloadIntegrityMismatch);
                }
                return Ok(());
            }
            crate::model::validate_digest(&self.transport_hash, "transport_hash")?;
            if self.transport_hash != self.envelope_sha256 {
                return Err(OrsError::PayloadIntegrityMismatch);
            }
            if crate::model::sha256_hex(&self.envelope_bytes) != self.transport_hash {
                return Err(OrsError::PayloadIntegrityMismatch);
            }
            return Ok(());
        }
        crate::model::validate_digest(&self.transport_hash, "transport_hash")?;
        if self.transport_hash != self.envelope_sha256 {
            return Err(OrsError::InvalidField {
                field: "transport_hash",
                reason: "redacted bridge events bind the original transport hash",
            });
        }
        if self.redaction_reason != BRIDGE_EVENT_REDACTION_REASON_FORBIDDEN {
            return Err(OrsError::InvalidField {
                field: "redaction_reason",
                reason: "bridge event redaction carries the detected-content reason",
            });
        }
        if self.redacted_classes.is_empty()
            || self.redacted_classes.len() > MAX_BRIDGE_EVENT_REDACTED_CLASSES
        {
            return Err(OrsError::InvalidField {
                field: "redacted_classes",
                reason: "bridge event redaction classes must be nonempty and bounded",
            });
        }
        for class in &self.redacted_classes {
            crate::model::validate_text(class, "redacted_classes")?;
        }
        if self.redaction_marker != BRIDGE_EVENT_REDACTED_PROJECTION_MARKER {
            return Err(OrsError::InvalidField {
                field: "redaction_marker",
                reason: "bridge event redaction carries this owner's projection marker",
            });
        }
        if self.redaction_version != crate::CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.redaction_version));
        }
        let expected = RedbRecoveryStore::bridge_event_redacted_projection_bytes(
            &self.transport_hash,
            &self.redacted_classes,
        );
        if self.envelope_bytes != expected {
            return Err(OrsError::PayloadIntegrityMismatch);
        }
        Ok(())
    }
}

impl persistence_codec::PersistedValue for BridgeEventRow {
    const RECORD_TYPE: &'static str = "bridge_event_record";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

/// One per-stream bridge-event cursor row (issue #2561).
///
/// Carries the durable/acked cursors with the staging provenance used by the
/// reconcile scope rule (presenting connection plus fenced old generations).
/// Cursor rows are created on first stage and updated on cursor movement;
/// they are never evicted, so no cursor resets and no unresolved stream is
/// discarded.
///
/// Issue #2730 keeps four frontiers distinct in this row: the highest
/// observed staged position (`last_observed_sequence`), the contiguous
/// durable frontier (`last_durable_sequence`), the producer receipt
/// acknowledgement (`last_acked_sequence`), and the compacted/retired
/// boundary (`last_compacted_sequence`). The downstream application
/// frontier stays separate in the handoff rows. A gap record explains
/// missing coverage; it never moves any field here.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeEventCursorRow {
    contract_version: u16,
    stream_id: String,
    last_durable_sequence: u64,
    last_acked_sequence: u64,
    last_staging_connection: String,
    last_producer_generation: u64,
    /// Versioned owner namespace digest this cursor belongs to (issue
    /// #2729). Empty on legacy rows; owner-checked cursors carry their
    /// namespace and are keyed by it. The staging connection/generation
    /// above stay observation metadata only — never scope material.
    #[serde(default)]
    owner_namespace: String,
    /// Highest staged sequence ever observed in this namespace (issue
    /// #2730). Advanced at stage time, preserved by every cursor write, and
    /// backfilled by the index migration; never moves backward, never reset.
    #[serde(default)]
    last_observed_sequence: u64,
    /// Highest compacted (payload-evicted) sequence in this namespace
    /// (issue #2730, item 2): the retained retired boundary. Advanced only
    /// by the acknowledgement compaction in the same transaction that
    /// writes the replay commitments; a missing row at or below this
    /// boundary is retired, never a new event.
    #[serde(default)]
    last_compacted_sequence: u64,
}

impl BridgeEventCursorRow {
    fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != crate::CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        bridge_identity_text(&self.stream_id, "stream_id")?;
        if self.last_acked_sequence > self.last_durable_sequence {
            return Err(OrsError::InvalidField {
                field: "last_acked_sequence",
                reason: "acked cursor must never pass the durable cursor",
            });
        }
        if self.last_compacted_sequence > self.last_acked_sequence {
            return Err(OrsError::InvalidField {
                field: "last_compacted_sequence",
                reason: "compacted boundary must never pass the acked cursor",
            });
        }
        if !self.owner_namespace.is_empty() {
            crate::model::validate_digest(&self.owner_namespace, "owner_namespace")?;
        }
        Ok(())
    }
}

impl persistence_codec::PersistedValue for BridgeEventCursorRow {
    const RECORD_TYPE: &'static str = "bridge_event_cursor";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

/// One durably recorded bridge-event coverage gap (issue #2561).
///
/// Gaps stay visible in coverage without moving any cursor: absent events are
/// accounted for, never converted into applied events.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeEventGapRow {
    contract_version: u16,
    gap_id: String,
    stream_id: String,
    start_sequence: u64,
    end_sequence: u64,
    reason_ref: String,
    staging_connection: String,
    recorded_at_ms: u64,
    /// Versioned owner namespace digest this gap is visible under (issue
    /// #2729): the stream namespace for scoped gaps, the reporter-occurrence
    /// namespace for unscoped gaps. Empty on legacy rows, which stay
    /// preserved but invisible to owner-checked recovery.
    #[serde(default)]
    owner_namespace: String,
}

impl BridgeEventGapRow {
    fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != crate::CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        // Gap identities are bare keys (never key-encoded with a separator),
        // so only blank/control text is refused here.
        crate::model::validate_text(&self.gap_id, "gap_id")?;
        // An empty stream marks an unscoped coverage gap: the forwarding port
        // only carries the gap, so stream scope is attached when the producer
        // presents it and left empty otherwise. Unscoped gaps reconcile at
        // top level under their staging connection, never under a stream.
        if !self.stream_id.is_empty() {
            bridge_identity_text(&self.stream_id, "stream_id")?;
        }
        if self.start_sequence == 0 || self.end_sequence == 0 {
            return Err(OrsError::InvalidField {
                field: "start_sequence",
                reason: "gap interval sequences must be nonzero",
            });
        }
        if self.end_sequence < self.start_sequence {
            return Err(OrsError::InvalidField {
                field: "end_sequence",
                reason: "gap interval must not end before it starts",
            });
        }
        crate::model::validate_text(&self.reason_ref, "reason_ref")?;
        crate::model::validate_text(&self.staging_connection, "staging_connection")?;
        if !self.owner_namespace.is_empty() {
            crate::model::validate_digest(&self.owner_namespace, "owner_namespace")?;
        }
        Ok(())
    }
}

impl persistence_codec::PersistedValue for BridgeEventGapRow {
    const RECORD_TYPE: &'static str = "bridge_event_gap";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

/// One durable Governor-handoff record for a staged bridge event (issue
/// #2561, I5(i)).
///
/// The handoff is the persisted leg of the intake conversion: the Kernel
/// route owner records it once the ORS bridge-event row is durably staged
/// (`handed_off`), and the event reconcile entry binds it to the
/// reconciliation key once the consumed frontier covers its sequence
/// (`reconciled`). The row carries the staged envelope digest and the
/// reconcile key only — never a synthesized intake, normalization, or
/// application claim. Those legs stay owned by the provider normalizer and
/// the Governor/coordinator intake; this row only proves the durable event
/// reached the handoff and whether reconcile has covered it.
///
/// Issue #2731 records the exact receiving-owner receipt on the reconciled
/// transition: the consumed sequence the receiver presented, with the owner
/// revision and incarnation that admitted it. That triple binds the
/// stream/incarnation/event/content identity below to the receiving
/// operation (the owner-checked consumed-frontier acceptance at that
/// binding), so the later retirement transaction can validate the receiver
/// evidence instead of trusting the bare `reconciled` string. It is custody
/// acceptance — the receiver took the delivery obligation into its recovery
/// scope — never an application claim: APPLIED, REJECTED and UNKNOWN stay
/// owned downstream and are never minted or confused here. Rows reconciled
/// before this evidence existed decode with empty fields and are treated as
/// carrying no receiver evidence: they keep validating and keep serving
/// reads, but they never become retirement-eligible on their old state
/// string alone. Legacy ownerless rows never carry evidence at all.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeEventHandoffRow {
    contract_version: u16,
    stream_id: String,
    event_id: String,
    sequence: u64,
    envelope_sha256: String,
    state: String,
    staging_connection: String,
    handed_off_at_ms: u64,
    #[serde(default)]
    reconcile_key: String,
    #[serde(default)]
    reconciled_at_ms: u64,
    /// Versioned owner namespace digest this handoff belongs to (issue
    /// #2729). Empty on legacy rows; owner-checked handoffs carry their
    /// stream namespace and are keyed by it.
    #[serde(default)]
    owner_namespace: String,
    /// Consumed sequence the receiver presented when this handoff reconciled
    /// (issue #2731, item 1): the receiving operation's durable-acceptance
    /// frontier. Always covers `sequence`; zero means no receiver evidence
    /// was recorded (legacy row).
    #[serde(default)]
    reconcile_acked_sequence: u64,
    /// Owner revision that admitted the reconciling presentation (issue
    /// #2731, item 1). Zero means no receiver evidence was recorded.
    #[serde(default)]
    reconcile_owner_revision: u64,
    /// Stream incarnation that admitted the reconciling presentation (issue
    /// #2731, item 1). Zero means no receiver evidence was recorded.
    #[serde(default)]
    reconcile_owner_incarnation: u64,
}

impl BridgeEventHandoffRow {
    fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != crate::CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        bridge_identity_text(&self.stream_id, "stream_id")?;
        bridge_identity_text(&self.event_id, "event_id")?;
        if self.sequence == 0 {
            return Err(OrsError::InvalidField {
                field: "sequence",
                reason: "bridge event handoff sequence must be nonzero",
            });
        }
        crate::model::validate_digest(&self.envelope_sha256, "envelope_sha256")?;
        if self.state != BRIDGE_EVENT_HANDOFF_HANDED_OFF
            && self.state != BRIDGE_EVENT_HANDOFF_RECONCILED
        {
            return Err(OrsError::InvalidField {
                field: "state",
                reason: "bridge event handoff is handed_off or reconciled",
            });
        }
        crate::model::validate_text(&self.staging_connection, "staging_connection")?;
        if self.state == BRIDGE_EVENT_HANDOFF_HANDED_OFF {
            if !self.reconcile_key.is_empty()
                || self.reconciled_at_ms != 0
                || self.reconcile_acked_sequence != 0
                || self.reconcile_owner_revision != 0
                || self.reconcile_owner_incarnation != 0
            {
                return Err(OrsError::InvalidField {
                    field: "reconcile_key",
                    reason: "an unreconciled handoff carries no reconcile receipt",
                });
            }
        } else {
            crate::model::validate_digest(&self.reconcile_key, "reconcile_key")?;
            if self.reconciled_at_ms == 0 {
                return Err(OrsError::InvalidField {
                    field: "reconciled_at_ms",
                    reason: "a reconciled handoff carries its reconcile time",
                });
            }
            // Receiver evidence (issue #2731, item 1) is all-or-nothing: a
            // reconciled row either carries the full presented receipt
            // (nonzero frontier covering its sequence with the admitting
            // revision/incarnation) or none of it (a row reconciled before
            // the receipt existed, which validates but never retires on its
            // old state string alone). Partial evidence fails closed as
            // corruption instead of retiring on a guess.
            let evidence_fields = [
                self.reconcile_acked_sequence,
                self.reconcile_owner_revision,
                self.reconcile_owner_incarnation,
            ];
            if evidence_fields != [0, 0, 0]
                && (evidence_fields.contains(&0) || self.reconcile_acked_sequence < self.sequence)
            {
                return Err(OrsError::InvalidField {
                    field: "reconcile_acked_sequence",
                    reason: "handoff receiver evidence must bind a covering frontier with its admitting revision and incarnation",
                });
            }
        }
        if !self.owner_namespace.is_empty() {
            crate::model::validate_digest(&self.owner_namespace, "owner_namespace")?;
        }
        Ok(())
    }

    /// Reports whether this row carries a complete receiving-owner receipt
    /// (issue #2731, item 1): the reconciled state with the full presented
    /// triple (covering frontier plus admitting revision/incarnation).
    /// Ownerless rows and rows reconciled before the receipt existed report
    /// false — their old state string alone is never receiver evidence.
    fn has_receiver_receipt(&self) -> bool {
        self.state == BRIDGE_EVENT_HANDOFF_RECONCILED
            && !self.owner_namespace.is_empty()
            && self.sequence != 0
            && self.reconcile_acked_sequence >= self.sequence
            && self.reconcile_owner_revision != 0
            && self.reconcile_owner_incarnation != 0
    }

    /// Reports whether this row may retire once its payload is gone (issue
    /// #2731, items 1, 4 and 5). A receipt-complete row covered by the
    /// receiver's acked cursor is eligible even above the retained
    /// compacted boundary: the boundary advances only past the retained
    /// 512-row acked window, so a stream that stops producing at or below
    /// the window would otherwise hold its receipt-complete charges
    /// against the table-global budget forever — the exact quiet-stream
    /// lifetime quota item 4 forbids. Otherwise the admitted terminal
    /// disposition still applies: still `handed_off` but covered by the
    /// receiver's acked cursor at or below the retained compacted
    /// boundary, whose missing row answers the explicit retired
    /// disposition instead of a fresh event. Pending rows (above the
    /// boundary without the exact receipt) and ownerless legacy rows never
    /// report true: unknown and pending work is never evicted to admit new
    /// work.
    fn retirement_eligible(&self, acked_cursor: u64, compacted_boundary: u64) -> bool {
        if self.owner_namespace.is_empty() || self.sequence == 0 {
            return false;
        }
        if self.has_receiver_receipt() && self.sequence <= acked_cursor {
            return true;
        }
        if self.sequence > compacted_boundary {
            return false;
        }
        if self.has_receiver_receipt() {
            return true;
        }
        self.state == BRIDGE_EVENT_HANDOFF_HANDED_OFF && self.sequence <= acked_cursor
    }
}

impl persistence_codec::PersistedValue for BridgeEventHandoffRow {
    const RECORD_TYPE: &'static str = "bridge_event_handoff";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

/// One retained bridge-event replay commitment (issue #2730, items 2-3).
///
/// Written atomically in the same acknowledgement transaction that compacts
/// the live row, so the original admitted identity and content commitment
/// outlives payload eviction. Replay binds the ORIGINAL admitted event
/// (`envelope_sha256` is the immutable hash of the original canonical
/// envelope bytes) together with its permitted representation facts
/// (`transport_hash` plus the redaction receipt when denied): an incoming
/// original envelope is never compared against a redacted marker as though
/// they were the same bytes, and a redaction-policy change never authorizes
/// another occurrence. Identity comparison covers the producer/source
/// generation, the authority lineage epoch text, and the identity-bearing
/// envelope fields — not just a digest-shaped value. Commitments are never
/// updated; per-stream and total pressure evicts the oldest first, and the
/// retained compacted boundary on the cursor row still blocks re-admission
/// afterwards.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeEventReplayCommitment {
    contract_version: u16,
    commitment_version: u16,
    owner_namespace: String,
    stream_id: String,
    event_id: String,
    sequence: u64,
    producer_id: String,
    producer_generation: u64,
    authority_epoch: String,
    envelope_sha256: String,
    transport_hash: String,
    redacted: bool,
    #[serde(default)]
    redacted_classes: Vec<String>,
    #[serde(default)]
    redaction_marker: String,
    #[serde(default)]
    redaction_version: u16,
    compacted_at_ms: u64,
    acked_at_compaction: u64,
}

impl BridgeEventReplayCommitment {
    fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != crate::CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        if self.commitment_version != BRIDGE_REPLAY_COMMITMENT_VERSION {
            return Err(OrsError::InvalidField {
                field: "commitment_version",
                reason: "bridge replay commitment carries the current commitment version",
            });
        }
        crate::model::validate_digest(&self.owner_namespace, "owner_namespace")?;
        bridge_identity_text(&self.stream_id, "stream_id")?;
        bridge_identity_text(&self.event_id, "event_id")?;
        if self.sequence == 0 {
            return Err(OrsError::InvalidField {
                field: "sequence",
                reason: "bridge event sequence must be nonzero",
            });
        }
        crate::model::validate_text(&self.producer_id, "producer_id")?;
        if self.producer_generation == 0 {
            return Err(OrsError::InvalidField {
                field: "producer_generation",
                reason: "bridge event producer generation must be nonzero",
            });
        }
        crate::model::validate_text(&self.authority_epoch, "authority_epoch")?;
        crate::model::validate_digest(&self.envelope_sha256, "envelope_sha256")?;
        crate::model::validate_digest(&self.transport_hash, "transport_hash")?;
        // The original commitment is representation-aware (issue #2730, item
        // 3): admissible rows bind the verbatim original bytes, so the
        // transport hash equals the original identity digest; redacted rows
        // bind the same original transport hash plus this owner's exact
        // projection receipt — never regenerated raw, never a bare marker.
        if self.transport_hash != self.envelope_sha256 {
            return Err(OrsError::InvalidField {
                field: "transport_hash",
                reason: "replay commitment binds the original transport hash",
            });
        }
        if self.redacted {
            if self.redacted_classes.is_empty()
                || self.redacted_classes.len() > MAX_BRIDGE_EVENT_REDACTED_CLASSES
            {
                return Err(OrsError::InvalidField {
                    field: "redacted_classes",
                    reason: "replay commitment redaction classes must be nonempty and bounded",
                });
            }
            for class in &self.redacted_classes {
                crate::model::validate_text(class, "redacted_classes")?;
            }
            if self.redaction_marker != BRIDGE_EVENT_REDACTED_PROJECTION_MARKER {
                return Err(OrsError::InvalidField {
                    field: "redaction_marker",
                    reason: "replay commitment redaction carries this owner's projection marker",
                });
            }
            if self.redaction_version != crate::CONTRACT_VERSION {
                return Err(OrsError::UnsupportedContractVersion(self.redaction_version));
            }
        } else if !self.redacted_classes.is_empty()
            || !self.redaction_marker.is_empty()
            || self.redaction_version != 0
        {
            return Err(OrsError::InvalidField {
                field: "redaction",
                reason: "admissible replay commitments carry no redaction facts",
            });
        }
        if self.acked_at_compaction == 0 {
            return Err(OrsError::InvalidField {
                field: "acked_at_compaction",
                reason: "replay commitment binds the acked frontier that retired it",
            });
        }
        if self.sequence > self.acked_at_compaction {
            return Err(OrsError::InvalidField {
                field: "acked_at_compaction",
                reason: "a compacted sequence never passes its retiring acked frontier",
            });
        }
        Ok(())
    }

    /// Key of this commitment: `{owner_namespace}::{event_id}`.
    fn record_key(&self) -> String {
        format!("{}::{}", self.owner_namespace, self.event_id)
    }
}

impl persistence_codec::PersistedValue for BridgeEventReplayCommitment {
    const RECORD_TYPE: &'static str = "bridge_event_replay_commitment";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

/// One ordered bridge-event position binding (issue #2730, item 1).
///
/// The value names the exactly one logical event admitted at
/// `{owner_namespace}::{sequence:020}`. Written once with its event row,
/// never updated, never deleted — including across compaction — so a
/// position can never be reused by another event.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeEventPosition {
    event_id: String,
}

impl BridgeEventPosition {
    fn validate(&self) -> Result<(), OrsError> {
        bridge_identity_text(&self.event_id, "event_id")
    }
}

impl persistence_codec::PersistedValue for BridgeEventPosition {
    const RECORD_TYPE: &str = "bridge_event_position";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

/// Validates one owner-namespace key component (issue #2729).
///
/// Components are non-blank, control-free, bounded text that never equals
/// the explicit unbound marker, so a real binding can never collide with
/// admitted unbound-capture state (mirrors the #2571 logical-key rule).
/// The `\x1f`-labeled digest encoding stays unambiguous because
/// `validate_text` already refuses control characters; no ad-hoc
/// concatenation is improvised.
fn bridge_owner_component(value: &str, field: &'static str) -> Result<(), OrsError> {
    crate::model::validate_text(value, field)?;
    if value == HOST_REQUEST_UNBOUND_MARKER {
        return Err(OrsError::InvalidField {
            field,
            reason: "owner binding components must not equal the unbound marker",
        });
    }
    Ok(())
}

/// Persisted recovery-window authority and finite owner-list cutoff.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeEventRecoveryWindowRow {
    version: u16,
    window_key: String,
    authority_lineage: String,
    principal: String,
    owner_scope_digest: String,
    owner_cutoff: u64,
    created_at_ms: u64,
    expires_at_ms: u64,
    stream_list_complete: bool,
    stream_list_continuation: Option<String>,
}

impl BridgeEventRecoveryWindowRow {
    fn validate(&self) -> Result<(), OrsError> {
        if self.version != 1 {
            return Err(OrsError::InvalidField {
                field: "recovery_window.version",
                reason: "recovery window row carries the current version",
            });
        }
        crate::model::validate_digest(&self.window_key, "window_key")?;
        bridge_owner_component(&self.authority_lineage, "owner_authority_lineage")?;
        bridge_owner_component(&self.principal, "owner_principal")?;
        crate::model::validate_digest(&self.owner_scope_digest, "owner_scope_digest")?;
        if self.created_at_ms == 0 || self.expires_at_ms <= self.created_at_ms {
            return Err(OrsError::InvalidField {
                field: "recovery_window.expiry",
                reason: "recovery window expiry must follow its creation time",
            });
        }
        Ok(())
    }
}

impl persistence_codec::PersistedValue for BridgeEventRecoveryWindowRow {
    const RECORD_TYPE: &'static str = "bridge_event_recovery_window";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

/// Store-issued finite cut for one owner namespace inside a recovery window.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeEventRecoveryCutRow {
    version: u16,
    window_key: String,
    namespace: String,
    owner_kind: String,
    local_stream: String,
    producer: String,
    owner_incarnation: u64,
    owner_revision: u64,
    expected_revision: u64,
    upper_sequence: u64,
    retention_floor: u64,
    durable_cursor: u64,
    acked_cursor: u64,
    last_staging_connection: String,
    last_producer_generation: u64,
}

impl BridgeEventRecoveryCutRow {
    fn validate(&self) -> Result<(), OrsError> {
        if self.version != 1 {
            return Err(OrsError::InvalidField {
                field: "recovery_cut.version",
                reason: "recovery cut row carries the current version",
            });
        }
        crate::model::validate_digest(&self.window_key, "window_key")?;
        crate::model::validate_digest(&self.namespace, "owner_namespace")?;
        if self.owner_kind != BRIDGE_STREAM_OWNER_KIND_STREAM
            && self.owner_kind != BRIDGE_STREAM_OWNER_KIND_UNSCOPED_GAP
        {
            return Err(OrsError::InvalidField {
                field: "recovery_cut.owner_kind",
                reason: "recovery cut is a stream or unscoped-gap owner",
            });
        }
        if self.expected_revision == 0 || self.owner_revision == 0 || self.owner_incarnation == 0 {
            return Err(OrsError::InvalidField {
                field: "recovery_cut.revision",
                reason: "recovery cuts require nonzero owner and view revisions",
            });
        }
        if self.retention_floor > self.upper_sequence
            || self.acked_cursor > self.durable_cursor
            || self.durable_cursor > self.upper_sequence
        {
            return Err(OrsError::InvalidField {
                field: "recovery_cut.interval",
                reason: "recovery cut cursors must fit its finite retained interval",
            });
        }
        if self.owner_kind == BRIDGE_STREAM_OWNER_KIND_STREAM {
            bridge_identity_text(&self.local_stream, "local_stream")?;
            bridge_owner_component(&self.producer, "producer_id")?;
            if !self.last_staging_connection.is_empty() {
                crate::model::validate_text(&self.last_staging_connection, "staging_connection")?;
            }
        } else if self.local_stream != HOST_REQUEST_UNBOUND_MARKER
            || self.producer != HOST_REQUEST_UNBOUND_MARKER
            || !self.last_staging_connection.is_empty()
            || self.last_producer_generation != 0
        {
            return Err(OrsError::InvalidField {
                field: "recovery_cut.owner_kind",
                reason: "unscoped-gap cuts carry only explicit unbound owner markers",
            });
        }
        Ok(())
    }
}

impl persistence_codec::PersistedValue for BridgeEventRecoveryCutRow {
    const RECORD_TYPE: &'static str = "bridge_event_recovery_cut";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeEventRecoveryRevisionRow {
    version: u16,
    namespace: String,
    revision: u64,
}

impl BridgeEventRecoveryRevisionRow {
    fn validate(&self) -> Result<(), OrsError> {
        if self.version != 1 || self.revision == 0 {
            return Err(OrsError::InvalidField {
                field: "recovery_revision",
                reason: "recovery revision row carries a nonzero current revision",
            });
        }
        crate::model::validate_digest(&self.namespace, "owner_namespace")
    }
}

impl persistence_codec::PersistedValue for BridgeEventRecoveryRevisionRow {
    const RECORD_TYPE: &'static str = "bridge_event_recovery_revision";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

enum BridgeRecoveryScopeSelector {
    Open,
    Streams {
        window_key: String,
        after_stream: u64,
        stream_limit: usize,
        selected_scope: serde_json::Value,
    },
    Stream {
        window_key: String,
        stream_id: String,
        after_sequence: u64,
        upper_sequence: u64,
        expected_revision: u64,
        retention_floor: u64,
        event_limit: usize,
        gap_offset: usize,
        gap_limit: usize,
        selected_scope: serde_json::Value,
    },
    UnscopedGaps {
        window_key: String,
        after_gap_scope: String,
        gap_offset: usize,
        gap_limit: usize,
        selected_scope: serde_json::Value,
    },
}

struct BridgeRecoveryOwnerPage {
    owners: Vec<(BridgeStreamOwnerRow, u64)>,
    continuation: Option<String>,
}

#[derive(Clone, Copy)]
struct BridgeRecoveryPageBudget {
    event_limit: usize,
    event_byte_limit: usize,
    gap_offset: usize,
    gap_limit: usize,
    gap_byte_limit: usize,
}

/// One authenticated bridge-stream owner binding (issue #2729).
///
/// Retained at the first admitted bind of a stream namespace — or of an
/// unscoped-gap reporter occurrence — through the existing Kernel owner:
/// the binding names the authority lineage, the Kernel-observed principal,
/// the admitted producer, the local stream (or the explicit unbound marker
/// for connection-level gaps), the stream incarnation, and the creating
/// session occurrence. The last-staging connection is observation metadata
/// on the cursor/event rows, never scope material here. Rows are immutable
/// once written in this scope: incarnation and revision are assigned by
/// the store, never by the caller, so an expected-owner/revision check
/// detects any owner change between resolution and commit.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeStreamOwnerRow {
    contract_version: u16,
    owner_version: u16,
    namespace: String,
    kind: String,
    local_stream: String,
    authority_lineage: String,
    principal: String,
    producer: String,
    creating_connection: String,
    creating_launch_nonce: String,
    creating_session_epoch: u64,
    incarnation: u64,
    revision: u64,
    created_at_ms: u64,
}

impl BridgeStreamOwnerRow {
    fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != crate::CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        if self.owner_version != BRIDGE_STREAM_OWNER_VERSION {
            return Err(OrsError::InvalidField {
                field: "owner_version",
                reason: "bridge stream owner binding carries the current owner version",
            });
        }
        crate::model::validate_digest(&self.namespace, "owner_namespace")?;
        if self.kind != BRIDGE_STREAM_OWNER_KIND_STREAM
            && self.kind != BRIDGE_STREAM_OWNER_KIND_UNSCOPED_GAP
        {
            return Err(OrsError::InvalidField {
                field: "owner_kind",
                reason: "bridge stream owner is a stream or an unscoped-gap occurrence",
            });
        }
        if self.local_stream == HOST_REQUEST_UNBOUND_MARKER {
            if self.kind != BRIDGE_STREAM_OWNER_KIND_UNSCOPED_GAP {
                return Err(OrsError::InvalidField {
                    field: "local_stream",
                    reason: "only an unscoped-gap occurrence binds the unbound scope",
                });
            }
        } else {
            bridge_identity_text(&self.local_stream, "local_stream")?;
        }
        bridge_owner_component(&self.authority_lineage, "authority_lineage")?;
        bridge_owner_component(&self.principal, "principal")?;
        if self.producer == HOST_REQUEST_UNBOUND_MARKER {
            if self.kind != BRIDGE_STREAM_OWNER_KIND_UNSCOPED_GAP {
                return Err(OrsError::InvalidField {
                    field: "producer",
                    reason: "only an unscoped-gap occurrence binds the unbound producer",
                });
            }
        } else {
            bridge_owner_component(&self.producer, "producer")?;
        }
        crate::model::validate_text(&self.creating_connection, "creating_connection")?;
        crate::model::validate_text(&self.creating_launch_nonce, "creating_launch_nonce")?;
        if self.creating_session_epoch == 0 {
            return Err(OrsError::InvalidField {
                field: "creating_session_epoch",
                reason: "bridge stream owner binds a nonzero creating session epoch",
            });
        }
        if self.incarnation != BRIDGE_STREAM_OWNER_INITIAL_INCARNATION {
            return Err(OrsError::InvalidField {
                field: "incarnation",
                reason: "bridge stream owner incarnation is store-assigned at first bind",
            });
        }
        if self.revision != BRIDGE_STREAM_OWNER_INITIAL_REVISION {
            return Err(OrsError::InvalidField {
                field: "revision",
                reason: "bridge stream owner revision is store-assigned at first bind",
            });
        }
        Ok(())
    }
}

impl persistence_codec::PersistedValue for BridgeStreamOwnerRow {
    const RECORD_TYPE: &'static str = "bridge_stream_owner";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

/// Right carried by one checked bridge-stream access object (issue
/// #2729). Read access never implies acknowledgement, append, or gap
/// publication: each entry resolves exactly the right it enforces, and
/// recovery of an old stream never permits a new event under the old
/// producer generation (the append entry keeps its own live-generation
/// gate at the route).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BridgeStreamRight {
    ReadRecover,
    Acknowledge,
    Append,
    PublishGap,
}

/// Checked internal access for one bridge-stream namespace (issue #2729).
/// Constructed only inside the store after the owner row is loaded and
/// the expected revision/incarnation are verified against it:
/// JSON-carried namespace/revision values are untrusted lookup inputs to
/// that check, never authority, and no caller-authored `authorized` flag
/// exists anywhere on this path.
struct BridgeStreamAccess {
    namespace: String,
    right: BridgeStreamRight,
}

impl BridgeStreamAccess {
    fn require(&self, right: BridgeStreamRight) -> Result<(), OrsError> {
        if self.right != right {
            return Err(OrsError::InvalidField {
                field: "owner_right",
                reason: "checked bridge-stream access carries exactly one operation right",
            });
        }
        Ok(())
    }
}

/// Kernel-derived owner evidence for one stream bind (issue #2729).
///
/// Built by the Kernel route from the retained Session and the presenting
/// fence only — never from bridge-authored session text. The store treats
/// every field as an untrusted input to the namespace digest and the
/// stored-row equality check, never as authority: a forged digest selects
/// at most another row, which then fails the field-equality check.
struct BridgeOwnerEvidence {
    lineage: String,
    principal: String,
    producer: String,
    local: String,
    connection: String,
    launch_nonce: String,
    session_epoch: u64,
}

/// One parsed acknowledgement-batch item: the resolved namespace with
/// its expected owner revision/incarnation, the presenter's lineage and
/// principal for the in-transaction equality recheck, and the requested
/// sequence.
struct BridgeAckItem {
    namespace: String,
    expected_revision: u64,
    expected_incarnation: u64,
    sequence: u64,
    lineage: String,
    principal: String,
}

/// Parsed inputs for one owner-checked stage (issue #2729): the bound
/// sidecar identity with its verified owner evidence and namespace, plus
/// the canonical envelope bytes with their digest.
struct BridgeCheckedStage {
    evidence: BridgeOwnerEvidence,
    stream_id: String,
    event_id: String,
    sequence: u64,
    producer_generation: u64,
    authority_epoch: String,
    presented_sha: String,
    staging_connection: String,
    namespace: String,
    key: String,
}

/// Parsed inputs for one owner-checked gap record (issue #2729): the gap
/// identity and interval with the presenter's lineage, principal, and
/// creating occurrence.
struct BridgeCheckedGap {
    gap_id: String,
    stream_id: String,
    start_sequence: u64,
    end_sequence: u64,
    reason_ref: String,
    staging_connection: String,
    lineage: String,
    principal: String,
    connection: String,
    launch_nonce: String,
    session_epoch: u64,
}

/// Resolved I7.23 disclosure staging for canonical envelope bytes.
///
/// Carries the enforced privacy decision (denied or admissible with its
/// classes), the immutable transport hash of the original bytes, and the
/// bytes to stage (verbatim originals or the deterministic redacted
/// projection). Built only by the stage entry through the privacy resolver.
struct BridgeEventPrivacyStaging {
    denied: bool,
    classes: Vec<String>,
    transport_hash: String,
    stored_bytes: Vec<u8>,
}

/// Builds the stage/lookup outcome object for one bridge-event row.
fn bridge_event_outcome(
    row: &BridgeEventRow,
    disposition: &str,
    durable: u64,
    acked: u64,
    fresh: bool,
    handoff: Option<&str>,
) -> serde_json::Value {
    let privacy_disposition = if row.redacted {
        BRIDGE_EVENT_PRIVACY_REDACTED
    } else {
        BRIDGE_EVENT_PRIVACY_ALLOWED
    };
    let redaction = if row.redacted {
        json!({
            "transport_hash": row.transport_hash,
            "reason": row.redaction_reason,
            "redacted_classes": row.redacted_classes,
            "marker": row.redaction_marker,
            "normalizer_version": format!("ors-bridge-ingest-v{}", row.redaction_version),
        })
    } else {
        serde_json::Value::Null
    };
    json!({
        "stream_id": row.stream_id,
        "event_id": row.event_id,
        "sequence": row.sequence,
        "phase": row.phase,
        "disposition": disposition,
        "envelope_sha256": row.envelope_sha256,
        "producer_id": row.producer_id,
        "producer_generation": row.producer_generation,
        "authority_epoch": row.authority_epoch,
        "staging_connection": row.staging_connection,
        "durable_cursor": durable,
        "acked_cursor": acked,
        "fresh": fresh,
        "privacy_disposition": privacy_disposition,
        "transport_hash": row.transport_hash,
        "redaction": redaction,
        "handoff": handoff,
    })
}

/// Validates non-blank identity text shared by bridge-event fields.
fn bridge_identity_text(value: &str, field: &'static str) -> Result<(), OrsError> {
    crate::model::validate_text(value, field)?;
    if value.contains("::") {
        return Err(OrsError::InvalidField {
            field,
            reason: "bridge event identity must not contain the key separator",
        });
    }
    Ok(())
}

/// Extracts validated general text from a bridge-event JSON object.
fn bridge_text(value: &serde_json::Value, field: &'static str) -> Result<String, OrsError> {
    let text =
        value
            .get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or(OrsError::InvalidField {
                field,
                reason: "bridge event field must be text",
            })?;
    crate::model::validate_text(text, field)?;
    Ok(text.to_owned())
}

/// Extracts the gap stream scope: empty (unscoped) or validated key text.
/// The forwarding port only carries the gap itself, so stream scope arrives
/// when the producer presents it and stays empty otherwise; unscoped gaps
/// reconcile at top level under their staging connection.
fn bridge_gap_stream_text(value: &serde_json::Value) -> Result<String, OrsError> {
    let text = value
        .get("stream_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(OrsError::InvalidField {
            field: "stream_id",
            reason: "bridge event gap must carry a stream scope",
        })?;
    if text.is_empty() {
        return Ok(String::new());
    }
    bridge_identity_text(text, "stream_id")?;
    Ok(text.to_owned())
}

/// Extracts validated key text (no key separator) from a bridge-event object.
fn bridge_key_text(value: &serde_json::Value, field: &'static str) -> Result<String, OrsError> {
    let text = bridge_text(value, field)?;
    if text.contains("::") {
        return Err(OrsError::InvalidField {
            field,
            reason: "bridge event identity must not contain the key separator",
        });
    }
    Ok(text)
}

/// Extracts a validated nonzero sequence from a bridge-event object.
fn bridge_sequence(value: &serde_json::Value, field: &'static str) -> Result<u64, OrsError> {
    let sequence =
        value
            .get(field)
            .and_then(serde_json::Value::as_u64)
            .ok_or(OrsError::InvalidField {
                field,
                reason: "bridge event sequence must be a non-negative integer",
            })?;
    if sequence == 0 {
        return Err(OrsError::InvalidField {
            field,
            reason: "bridge event sequence must be nonzero",
        });
    }
    Ok(sequence)
}

/// Extracts a validated nonzero generation/epoch counter.
fn bridge_generation(value: &serde_json::Value, field: &'static str) -> Result<u64, OrsError> {
    let generation =
        value
            .get(field)
            .and_then(serde_json::Value::as_u64)
            .ok_or(OrsError::InvalidField {
                field,
                reason: "bridge event generation must be a non-negative integer",
            })?;
    if generation == 0 {
        return Err(OrsError::InvalidField {
            field,
            reason: "bridge event generation must be nonzero",
        });
    }
    Ok(generation)
}
/// Transport-independent logical host-request index (issue #2571).
///
/// Maps one canonical logical key — the SHA-256 of the owner-namespaced
/// (session continuity, client occurrence, parent/task/scope binding,
/// capability, payload commitment) tuple — to the exact winning operation
/// (`operation_id`, `request_digest`). Written atomically in the same `RedDB`
/// write transaction as the winning operation row, never updated, never
/// deleted: an expired or terminal operation keeps its key bound forever, so
/// an old key can never be reused as a new effect. Rows staged before this
/// index existed simply have no entry and are never inferred; they stay
/// reachable only by exact operation/request identity.
const HOST_REQUEST_LOGICAL_KEYS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_host_request_logical_keys_v1");
/// Authenticated owner namespace for every logical host-request key
/// (issue #2571).
///
/// The namespace names the Kernel-admitted application-continuity domain:
/// keys are only ever derived from Kernel-issued session continuity plus the
/// client occurrence and commitment, never from bare text, a principal
/// alone, or a connection/deadline. The Bridge carries the identical literal
/// as its key-domain contract; the two must change together.
const HOST_REQUEST_LOGICAL_NAMESPACE: &str = "eliot.host-request.logical.v1";
/// Explicit admitted-unbound marker for parent/task/scope key components.
///
/// A real component value equal to this marker is rejected at derivation so
/// bindings can never collide with admitted unbound-capture state.
const HOST_REQUEST_UNBOUND_MARKER: &str = "-";

/// Content-addressed generated learning views retained atomically with their
/// authenticated local-read result (`eliot.packet`).
const CAMPAIGN_LEARNING_STATE_VIEWS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_campaign_learning_state_views_v1");
/// Immutable typed owner-source rows, keyed by source key plus body digest.
const CAMPAIGN_SOURCE_RECORDS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_campaign_source_records_v1");
/// Current owner-source heads, advanced only after a committed owner receipt.
const CAMPAIGN_SOURCE_HEADS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_campaign_source_heads_v1");
/// Pre-commit CAS reservations used to reconcile a crash after canonical
/// commit but before the ORS source projection is finalized.
const CAMPAIGN_SOURCE_PENDING: TableDefinition<&str, &str> =
    TableDefinition::new("ors_campaign_source_pending_v1");

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct CampaignSourceReservation {
    operation_id: String,
    request_digest: String,
    publication: eliot_store_api::CampaignSourcePublication,
}

const ACTIVATION_RESULT_RETENTION: TableDefinition<&str, &str> =
    TableDefinition::new("ors_agent_activation_results_v1");
const ACTIVATION_LIFECYCLES: TableDefinition<&str, &str> =
    TableDefinition::new("ors_agent_activation_lifecycles_v1");
const NATIVE_WORKER_CLAIMS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_native_worker_claims_v1");
const REPLAY_STREAMS: TableDefinition<&str, &str> = TableDefinition::new("ors_replay_streams_v1");
const REPLAY_REQUESTS: TableDefinition<&str, &str> = TableDefinition::new("ors_replay_requests_v1");
const REPLAY_EVENTS: TableDefinition<&str, &str> = TableDefinition::new("ors_replay_events_v1");
const REPLAY_ACKS: TableDefinition<&str, &str> = TableDefinition::new("ors_replay_acks_v1");
const DOCTOR_ATTEMPTS: TableDefinition<&str, &str> = TableDefinition::new("ors_doctor_attempts_v1");
const DOCTOR_EFFECTS: TableDefinition<&str, &str> = TableDefinition::new("ors_doctor_effects_v1");
const DOCTOR_BUDGETS: TableDefinition<&str, &str> = TableDefinition::new("ors_doctor_budgets_v1");
/// Visible durable Recovery Problems for staged opaque operations whose
/// payload cannot be decoded or trusted (issue #1925). Keyed by the staged
/// operation/checkpoint identity; retained until explicit disposition.
const RECOVERY_PROBLEMS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_recovery_problems_v1");
/// Durable grant-closure rows: one committed closure operation identity with
/// its exact commit bytes, phase, and order (issue #2100). Keyed by the
/// closure operation identity; rows never transition.
/// Legacy grant-closure rows are an explicit migration input only. Successful
/// startup moves their exact bytes into a versioned disposition row in the v2
/// table before removing the legacy row; no old wire shape is reinterpreted.
const GRANT_CLOSURE_LEGACY_CURRENT: TableDefinition<&str, &str> =
    TableDefinition::new("ors_grant_closure_current_v1");
const GRANT_CLOSURE_CURRENT: TableDefinition<&str, &str> =
    TableDefinition::new("ors_grant_closure_current_v2");
/// Immutable, versioned canonical second-phase links. The first-phase
/// `GRANT_CLOSURE_CURRENT` row is never rewritten; this table is keyed by the
/// exact same closure operation identity and is written in the same `RedDB`
/// transaction as the second-phase order reservation.
const GRANT_CLOSURE_SECOND_PHASE_CURRENT: TableDefinition<&str, &str> =
    TableDefinition::new("ors_grant_closure_second_phase_v1");
const GRANT_CLOSURE_SECOND_PHASE_KEY_PREFIX: &str = "grant_closure_second_phase:v1:";
/// The v2 table also carries namespaced, versioned migration-disposition rows
/// for legacy bytes that cannot be losslessly projected into a current receipt.
const GRANT_CLOSURE_MIGRATION_KEY_PREFIX: &str = "grant_closure_migration:v1:";
/// Durable grant-graph revision watermarks: the greatest graph revision
/// observed for one lineage root (issue #2100). Keyed by the authority root;
/// the stored revision only moves forward.
const GRANT_GRAPH_REVISION_CURRENT: TableDefinition<&str, &str> =
    TableDefinition::new("ors_grant_graph_revision_current_v1");
const NEXT_GLOBAL_ORDER: &str = "next_global_order";
/// Durable monotone revision of the process-stream recovery family (issue
/// #2884).
///
/// Advanced inside the same write transaction as every durable insert, evidence
/// advance and retirement of that family, so any movement of the family moves
/// this counter. An in-progress backup compares it against the revision it
/// froze and refuses a continued export with a typed movement disposition
/// instead of tearing the snapshot. An absent key is revision `0`, the legacy
/// state of a store written before this counter existed; the family's streamed
/// content root is what additionally binds that state.
const PROCESS_STREAM_RECOVERY_FAMILY_REVISION: &str = "process_stream_recovery_family_revision";

struct ClosureRowPlan {
    key: String,
    record: DurableOperationalRecord,
    transitioned: bool,
}

const GRANT_CLOSURE_MIGRATION_SCHEMA: &str = "eliot.ors.grant-closure-migration";
const GRANT_CLOSURE_MIGRATION_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum GrantClosureMigrationDisposition {
    /// The legacy table already contained a complete v2 row.
    CurrentShapeCopied,
    /// The v1 bytes are retained in the disposition and the absent v2 fields
    /// are named rather than replaced with defaults.
    LegacyShapeRetained,
    /// A complete v2 row was already present beside the retained v1 bytes.
    LegacyShapeSupersededByCurrent,
}

impl GrantClosureMigrationDisposition {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CurrentShapeCopied => "CURRENT_SHAPE_COPIED",
            Self::LegacyShapeRetained => "LEGACY_SHAPE_RETAINED",
            Self::LegacyShapeSupersededByCurrent => "LEGACY_SHAPE_SUPERSEDED_BY_CURRENT",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantClosureMigrationRecord {
    schema: String,
    version: u16,
    operation_id: String,
    legacy_key: String,
    target_grant_id: String,
    authority_root_ref: String,
    grant_graph_revision: u64,
    legacy_phase: OperationalPhase,
    legacy_state: String,
    legacy_operation_order: u64,
    source_row_sha256: String,
    legacy_row_json: String,
    disposition: GrantClosureMigrationDisposition,
    missing_fields: Vec<String>,
    current_key: Option<String>,
    current_operation_order: Option<u64>,
    reason: String,
}

const SUPERVISION_STAGE_RESOLUTION_SCHEMA_KEY: &str = "supervision_stage_resolution_schema";
const SUPERVISION_STAGE_RESOLUTION_SCHEMA_V1: &str = "eliot.ors.supervision-stage-resolution.v1";
/// Ceiling on table names enumerated at store open. Provenance checks and the
/// restore-journal family check both read this set, so the scan must be bounded
/// rather than proportional to a malformed database's table count.
const MAX_ORS_TABLES_SCANNED: usize = 4096;
/// Ceiling on a persisted marker value read during open, checked before the
/// value is copied out of Redb.
const MAX_ORS_MARKER_BYTES: usize = 256;
/// Base-`META` marker recording that this store has adopted the v2 restore
/// journal. It lives outside the journal table family so that deleting those
/// tables is detectable rather than silently re-created as an empty journal.
/// Owned by the journal initializer; see `store/restore_journal.rs`.
pub(super) const RESTORE_JOURNAL_ADOPTION_KEY: &str = "restore_journal_adoption";

fn current_unix_ms() -> Result<i64, OrsError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| OrsError::Storage(format!("system clock before Unix epoch: {error}")))?
        .as_millis();
    i64::try_from(millis)
        .map_err(|_| OrsError::Storage("system clock exceeds signed millisecond range".to_owned()))
}

fn current_unix_ms_u64() -> Result<u64, OrsError> {
    u64::try_from(current_unix_ms()?)
        .map_err(|_| OrsError::Storage("system clock is before Unix epoch".to_owned()))
}

/// Composition-injected canonical/readback authenticator. `Ok(())` is trusted only because
/// composition owns this provider; caller-created receipts never bypass it.
pub trait CanonicalEvidenceProvider: Send + Sync {
    fn verify_ordering_heads(
        &self,
        scopes: &[crate::ScopeReservationRequest],
    ) -> Result<(), OrsError>;

    fn verify_reconciliation(
        &self,
        token: &WriterReservationToken,
        reconciliation: &CanonicalReconciliation,
    ) -> Result<(), OrsError>;

    fn verify_receipt(&self, receipt: &ReceiptEnvelope) -> Result<(), OrsError>;

    fn verify_recovery_inbox(&self, item: &RecoveryInboxItem) -> Result<(), OrsError>;
}

struct RejectUnboundEvidence;

impl CanonicalEvidenceProvider for RejectUnboundEvidence {
    fn verify_ordering_heads(
        &self,
        _scopes: &[crate::ScopeReservationRequest],
    ) -> Result<(), OrsError> {
        Err(OrsError::CanonicalEvidence(
            "canonical ordering provider is not bound".to_owned(),
        ))
    }

    fn verify_reconciliation(
        &self,
        _token: &WriterReservationToken,
        _reconciliation: &CanonicalReconciliation,
    ) -> Result<(), OrsError> {
        Err(OrsError::CanonicalEvidence(
            "canonical readback provider is not bound".to_owned(),
        ))
    }

    fn verify_receipt(&self, _receipt: &ReceiptEnvelope) -> Result<(), OrsError> {
        Err(OrsError::CanonicalEvidence(
            "canonical receipt provider is not bound".to_owned(),
        ))
    }

    fn verify_recovery_inbox(&self, _item: &RecoveryInboxItem) -> Result<(), OrsError> {
        Err(OrsError::CanonicalEvidence(
            "recovery inbox signer provider is not bound".to_owned(),
        ))
    }
}

/// Durable operational store boundary. Implementations must preserve atomic method semantics.
pub trait OperationalRecoveryStore: Send + Sync {
    fn stage(&self, op: StagedOperation) -> Result<StageReceipt, OrsError>;
    fn mark_applying(&self, operation_id: crate::OperationIdentity) -> Result<(), OrsError>;
    fn record_outcome(&self, receipt: &ReceiptEnvelope) -> Result<(), OrsError>;
    fn schedule_retry(
        &self,
        operation_id: crate::OperationIdentity,
        retry: RetryState,
    ) -> Result<(), OrsError>;
    fn checkpoint_job(&self, checkpoint: JobCheckpoint) -> Result<(), OrsError>;
    fn record_delivery_cursor(
        &self,
        cursor: DeliveryCursorState,
    ) -> Result<DeliveryCursorReceipt, OrsError>;
    fn acknowledge_delivery(
        &self,
        ack: DeliveryAcknowledgement,
    ) -> Result<DeliveryCursorReceipt, OrsError>;
    fn stage_admission_reservation(
        &self,
        reservation: AdmissionReservation,
    ) -> Result<AdmissionReservationReceipt, OrsError>;
    fn activate_admission_reservation(
        &self,
        activation: AdmissionReservationActivation,
    ) -> Result<AdmissionReservationReceipt, OrsError>;
    fn release_admission_reservation(
        &self,
        release: AdmissionReservationRelease,
    ) -> Result<AdmissionReservationReceipt, OrsError>;
    fn apply_generation_transition(
        &self,
        transition: GenerationTransition,
    ) -> Result<GenerationTransitionReceipt, OrsError>;
    fn commit_generation_cutover(
        &self,
        cutover: GenerationCutoverRecord,
    ) -> Result<GenerationCutoverReceipt, OrsError>;
    /// Stages typed generation evidence in the canonical operational
    /// current/history path.
    fn stage_generation_cutover(
        &self,
        record: RuntimeGenerationCutoverRecord,
    ) -> Result<GenerationCutoverSnapshot, OrsError>;
    /// Commits typed generation evidence at the canonical ORS linearization
    /// point and returns its canonical receipt projection.
    fn commit_generation_cutover_state(
        &self,
        record: RuntimeGenerationCutoverRecord,
    ) -> Result<GenerationCutoverSnapshot, OrsError>;
    /// Reads the bounded committed generation route projection.
    fn latest_generation_cutovers(
        &self,
        limit: u16,
    ) -> Result<Vec<GenerationCutoverSnapshot>, OrsError>;
    /// Reconciles staged generation evidence without activating it.
    fn reconcile_staged_generation_cutovers(
        &self,
        limit: u16,
    ) -> Result<Vec<GenerationCutoverSnapshot>, OrsError>;
    fn bind_session(
        &self,
        binding: ActiveSessionBinding,
    ) -> Result<SessionBindingReceipt, OrsError>;
    fn detach_session(&self, detach: SessionDetach) -> Result<SessionBindingReceipt, OrsError>;
    fn register_user_broker(
        &self,
        registration: UserBrokerRegistration,
    ) -> Result<UserBrokerRegistrationReceipt, OrsError>;
    fn fence_user_broker(
        &self,
        fence: UserBrokerFence,
    ) -> Result<UserBrokerRegistrationReceipt, OrsError>;
    fn commit_authority_snapshot(
        &self,
        snapshot: KernelAuthoritySnapshot,
    ) -> Result<AuthoritySnapshotReceipt, OrsError>;
    /// Commits one replay snapshot only if the caller still owns the exact
    /// current receipt. A missing expected receipt is valid only for the
    /// first snapshot on an otherwise empty authority subject.
    fn commit_authority_snapshot_cas(
        &self,
        snapshot: KernelAuthoritySnapshot,
        expected: Option<&AuthoritySnapshotReceipt>,
    ) -> Result<AuthoritySnapshotReceipt, OrsError>;
    /// Loads one active opaque authority snapshot with fresh ORS integrity
    /// validation. The returned value is not Kernel authority.
    fn load_authority_snapshot(
        &self,
        subject_id: &crate::OperationIdentity,
    ) -> Result<Option<RecoveredAuthoritySnapshot>, OrsError>;
    fn revoke_authority(
        &self,
        revocation: AuthorityRevocation,
    ) -> Result<AuthorityRevocationReceipt, OrsError>;
    fn activate_capability_grant(
        &self,
        activation: CapabilityGrantActivation,
    ) -> Result<AuthorityActivationReceipt, OrsError>;
    fn revoke_capability_grant(
        &self,
        revocation: CapabilityGrantRevocation,
    ) -> Result<AuthorityRevocationReceipt, OrsError>;
    /// Reads one current capability-grant row after validating its opaque
    /// record, key, kind, subject, phase, and store-issued receipt.
    fn load_capability_grant(
        &self,
        subject_id: &crate::OperationIdentity,
    ) -> Result<Option<CapabilityGrantProjection>, OrsError>;
    /// Commits one grant-closure row binding a closure operation identity to
    /// its target, lineage root, exact graph revision, canonical digest,
    /// complete affected set, and survivor set (issue #2100).
    ///
    /// An exact recommit under one operation identity returns the durable
    /// receipt unchanged; any changed content under one identity fails with
    /// [`OrsError::DuplicateConflict`] and never overwrites. The row never
    /// transitions: this compatibility path is reserved for activation
    /// closures (`Active`); revocation closures must use
    /// [`Self::commit_grant_closure_fence`].
    fn commit_grant_closure(
        &self,
        closure: GrantClosureCommit,
    ) -> Result<GrantClosureCommitReceipt, OrsError>;
    /// Atomically verifies and commits one complete grant-closure revocation.
    ///
    /// The single `RedDB` write transaction checks the per-root graph revision
    /// against `request.declaration.grant_graph_revision` (or initializes an absent watermark
    /// to that exact nonzero revision), verifies every presented grant and
    /// introduction record against its current durable row, transitions only
    /// `Active` rows to `Fenced`, advances the watermark when needed, and
    /// writes the closure projection. Any mismatch aborts the transaction;
    /// there is no partial member fence or partial closure receipt. Exact
    /// replay under identical bytes returns the same composite receipt without
    /// a second transition.
    fn commit_grant_closure_fence(
        &self,
        request: GrantClosureFenceRequest,
    ) -> Result<GrantClosureFenceReceipt, OrsError>;
    /// Records the canonical second-phase receipt link for one already
    /// committed closure operation without rewriting its first-phase commit.
    ///
    /// The operation identity must already name a committed closure row. An
    /// identical link is idempotent; a different identity is an immutable
    /// conflict. The returned projection contains the durable second-phase
    /// link and the unchanged first-phase receipt.
    fn link_grant_closure_canonical_receipt(
        &self,
        operation_id: &crate::OperationIdentity,
        canonical_receipt: &ReceiptIdentity,
    ) -> Result<GrantClosureProjection, OrsError>;
    /// Reads one committed grant-closure row after validating its key,
    /// content, phase, and store-issued receipt. The returned value is
    /// operational evidence only; it grants no capability.
    fn load_grant_closure(
        &self,
        operation_id: &crate::OperationIdentity,
    ) -> Result<Option<GrantClosureProjection>, OrsError>;
    /// Advances the durable grant-graph revision watermark for one lineage
    /// root and returns the stored revision (issue #2100).
    ///
    /// The stored revision is the maximum of the retained value and the
    /// presented revision: it only moves forward. A nonzero revision is
    /// required. Callers compare the returned value with the presented
    /// revision to detect a stale presentation atomically.
    fn note_grant_graph_revision(
        &self,
        authority_root: &OpaqueLabel,
        revision: u64,
    ) -> Result<u64, OrsError>;
    /// Atomically advances every supplied lineage watermark. A stale or
    /// malformed member aborts the whole batch, so a global owner revision
    /// cannot race a closure on a root that has not yet been advanced.
    fn note_grant_graph_revisions(&self, revisions: &[(OpaqueLabel, u64)]) -> Result<(), OrsError>;
    /// Reads the durable grant-graph revision watermark for one lineage
    /// root, if any.
    fn load_grant_graph_revision(
        &self,
        authority_root: &OpaqueLabel,
    ) -> Result<Option<u64>, OrsError>;
    /// Scans the bounded selected set of committed grant-closure rows for
    /// one lineage selector in operation order (issues #2100/#686).
    ///
    /// `lineage` names a lineage root or one closure target grant.
    /// Selection happens inside the store before any bound applies:
    /// unrelated rows never count against `limit` and total table size
    /// never refuses a requested view. The whole selected set is read
    /// under ONE durable read snapshot together with the per-root
    /// revision watermark, so the returned response is self-consistent
    /// with no cross-page torn views and no paging cursor: rows arrive
    /// in increasing operation order, up to `limit` rows. A selected set
    /// larger than `limit` refuses with
    /// [`OrsError::ProjectionLimitExceeded`] instead of truncating, and
    /// the refusal happens before receipt/projection work. One selector
    /// resolving to more than one lineage root refuses with
    /// [`OrsError::IntegrityProblem`].
    fn scan_grant_closures_for_lineage(
        &self,
        lineage: &OpaqueLabel,
        limit: u16,
    ) -> Result<(Vec<GrantClosureProjection>, Option<u64>), OrsError>;
    fn activate_capability_introduction(
        &self,
        activation: CapabilityIntroductionActivation,
    ) -> Result<CapabilityIntroductionReceipt, OrsError>;
    fn fence_capability_introduction(
        &self,
        fence: CapabilityIntroductionFence,
    ) -> Result<CapabilityIntroductionReceipt, OrsError>;
    /// Reads one current capability-introduction row after validating its
    /// opaque record, key, kind, subject, phase, and store-issued receipt
    /// (issues #1110/#2100).
    ///
    /// Only `Active` and `Fenced` rows are returned. Any other phase under
    /// this kind is an integrity problem: introductions never reactivate, so
    /// a `Fenced` row is fence evidence, never activatable authority.
    fn load_capability_introduction(
        &self,
        subject_id: &crate::OperationIdentity,
    ) -> Result<Option<CapabilityIntroductionProjection>, OrsError>;
    fn logical_snapshot(&self, request: OrsSnapshotRequest)
    -> Result<OrsSnapshotReceipt, OrsError>;
    fn scan_pending(
        &self,
        cursor: RecoveryCursor,
        limit: u32,
    ) -> Result<PendingOperationPage, OrsError>;
    fn import_recovery_inbox(
        &self,
        item: RecoveryInboxItem,
    ) -> Result<RecoveryInboxReceipt, OrsError>;
    fn record_recovery_inbox_disposition(
        &self,
        item_id: crate::OperationIdentity,
        disposition: RecoveryInboxDisposition,
        receipt: &ReceiptEnvelope,
    ) -> Result<RecoveryInboxReceipt, OrsError>;
    fn stage_and_reserve(
        &self,
        request: ReservationRequest,
    ) -> Result<WriterReservationToken, OrsError>;
    fn mark_eligible(&self, token: &WriterReservationToken) -> Result<ReservationRecord, OrsError>;
    fn begin_execute(
        &self,
        token: &WriterReservationToken,
        writer_epoch: &EpochIdentity,
    ) -> Result<ReservationRecord, OrsError>;
    fn mark_unknown(
        &self,
        token: &WriterReservationToken,
        writer_epoch: &EpochIdentity,
        reason: OpaqueLabel,
    ) -> Result<ReservationRecord, OrsError>;
    fn reconcile(
        &self,
        reconciliation: &CanonicalReconciliation,
    ) -> Result<ReservationRecord, OrsError>;
    fn release(
        &self,
        token: &WriterReservationToken,
        writer_epoch: &EpochIdentity,
    ) -> Result<ReservationRecord, OrsError>;
    fn expire(
        &self,
        token: &WriterReservationToken,
        now_ms: i64,
        recovery_owner: &crate::RecoveryOwner,
    ) -> Result<ReservationRecord, OrsError>;
    fn recover_page(&self, cursor: RecoveryCursor) -> Result<RecoveryPage, OrsError>;
    fn get_envelope(
        &self,
        operation_id: &crate::OperationIdentity,
    ) -> Result<Option<RecoveryPayloadEnvelope>, OrsError>;
    /// Durably stages one complete opaque operation and reserves every
    /// declared Ordering Scope in one atomic ORS transaction, then proves the
    /// staging before returning `ACCEPTED_PENDING` (issue #1925, I5.5/I5.6).
    ///
    /// The returned [`AcceptedPending`] proves only that the full envelope
    /// was committed, read back, hash-validated, and indexed by operation
    /// identity. When the envelope cannot be durably staged this fails with
    /// [`OrsError::StagingNotDurable`] and no `ACCEPTED_PENDING` is emitted;
    /// when the staged bytes fail read-back validation a durable
    /// [`RecoveryProblem`] is retained and this fails with
    /// [`OrsError::RecoveryProblemRetained`]. Neither path deletes the staged
    /// record nor falls back to plaintext.
    fn accept_after_stage(&self, request: ReservationRequest) -> Result<AcceptedPending, OrsError>;
    /// Revalidates one staged envelope by identity without interpreting its
    /// payload (issue #1925).
    ///
    /// On hash mismatch, missing record bindings, or envelope corruption this
    /// retains a visible durable [`RecoveryProblem`] for disposition and fails
    /// with [`OrsError::RecoveryProblemRetained`]; the staged record remains
    /// available and is never silently dropped.
    fn verify_staged_envelope(
        &self,
        operation_id: &crate::OperationIdentity,
    ) -> Result<RecoveryPayloadEnvelope, OrsError>;
    /// Retains one caller-reported undecryptable-payload problem (missing key
    /// or decryption failure) without storing or returning payload bytes
    /// (issue #1925, I5.2).
    ///
    /// An exact replay under the same operation identity returns the durable
    /// record unchanged; a changed binding under the same identity fails with
    /// [`OrsError::DuplicateConflict`] and never overwrites. Plaintext
    /// fallback is forbidden by construction: this API accepts digests only.
    fn report_recovery_problem(
        &self,
        problem: RecoveryProblem,
    ) -> Result<RecoveryProblem, OrsError>;
    /// Loads one durable Recovery Problem by staged operation identity.
    fn load_recovery_problem(
        &self,
        operation_id: &crate::OperationIdentity,
    ) -> Result<Option<RecoveryProblem>, OrsError>;
    /// Lists retained Recovery Problems in operation-identity order, bounded
    /// by [`crate::MAX_RECOVERY_PAGE`].
    fn list_recovery_problems(&self, limit: u16) -> Result<Vec<RecoveryProblem>, OrsError>;
    /// Closes one retained Recovery Problem only from an explicit terminal
    /// receipt under the exact recovery owner (issue #1925).
    ///
    /// An exact replay of a resolved problem returns the durable record
    /// unchanged; resolving with a different receipt fails with
    /// [`OrsError::DuplicateConflict`]. Unresolved problems have no expiry
    /// path and are never cleaned up automatically.
    fn resolve_recovery_problem(
        &self,
        operation_id: &crate::OperationIdentity,
        receipt_id: &OpaqueLabel,
        recovery_owner: &crate::RecoveryOwner,
    ) -> Result<RecoveryProblem, OrsError>;
    fn fence_writer_epoch(
        &self,
        scopes: &[crate::OrderingScope],
        successor: &EpochLineage,
    ) -> Result<(), OrsError>;
    /// Stages one P-04 host-request operation before any acknowledgement.
    ///
    /// An exact replay under the same operation/request identity returns the
    /// durable record unchanged; a changed binding fails with
    /// [`OrsError::HostRequestIdentityConflict`].
    fn stage_host_request(
        &self,
        record: &crate::HostRequestRecord,
    ) -> Result<crate::HostRequestRecord, OrsError>;
    /// Advances one staged host-request operation to its next mechanical state.
    ///
    /// An exact repeat of an applied advance returns the durable record
    /// unchanged. An unknown operation returns `Ok(None)`; the caller stages
    /// first and this method never invents a record.
    fn advance_host_request(
        &self,
        operation_id: &crate::OperationIdentity,
        request_digest: &str,
        target: crate::HostRequestState,
        result_digest: Option<&str>,
    ) -> Result<Option<crate::HostRequestRecord>, OrsError>;
    /// Persists one bounded local-read result body alongside its digest
    /// (Implements #18: local read result).
    ///
    /// Atomically walks the mechanical lifecycle (`Admitted` → `Routed` →
    /// `Submitted` → `ResultReceived`, or a direct legal edge such as
    /// `Unknown`/`Reconciling`/`Submitted`/`PossiblyEffected` →
    /// `ResultReceived`) and stores the exact bounded response JSON with its
    /// digest. An exact replay (same digest and byte-identical body) returns
    /// the durable record unchanged without re-dispatch; a changed digest or
    /// body under the same identity fails as
    /// [`OrsError::HostRequestIdentityConflict`] and never overwrites the
    /// durable row. Rejection happens before any readback: the caller must
    /// have already validated tool linkage and descriptor binding.
    fn persist_host_request_result(
        &self,
        operation_id: &crate::OperationIdentity,
        request_digest: &str,
        result_digest: &str,
        result_response: &serde_json::Value,
    ) -> Result<Option<crate::HostRequestRecord>, OrsError>;
    /// Loads one host-request operation by exact operation/request identity.
    fn load_host_request(
        &self,
        operation_id: &crate::OperationIdentity,
        request_digest: &str,
    ) -> Result<Option<crate::HostRequestRecord>, OrsError>;
    /// Atomically claims one logical host-request key or returns its winner
    /// (issue #2571: cross-restart replay without double execution).
    ///
    /// In a single owner write transaction the logical key derived from the
    /// candidate is looked up: an absent key stages the candidate `Requested`
    /// row and claims the key for it; a present key loads the durable winner
    /// and returns it unchanged when the logical commitment matches. A
    /// present key with a different tool, payload, or incompatible
    /// semantic binding fails with
    /// [`OrsError::HostRequestIdentityConflict`] carrying the winner's
    /// identity. The caller distinguishes the two `Ok` cases by comparing
    /// the returned `(operation_id, request_digest)` with its candidate: an
    /// equal identity staged (or exactly replays) this candidate and may
    /// advance it; a different identity is another transport's winner and
    /// must be returned without dispatch. Storage failure is `Err` and never
    /// absence.
    fn resolve_or_stage_host_request(
        &self,
        record: &crate::HostRequestRecord,
    ) -> Result<crate::HostRequestRecord, OrsError>;
    /// Loads one host-request operation by logical key (issue #2571).
    ///
    /// `Ok(None)` means no operation was ever staged under this key in this
    /// store — including pre-index legacy rows, which are never inferred and
    /// stay reachable only by exact operation/request identity. Any storage
    /// or integrity failure is `Err` and can never become absence or
    /// authorize a fresh operation.
    fn load_host_request_by_logical_key(
        &self,
        logical_key: &str,
    ) -> Result<Option<crate::HostRequestRecord>, OrsError>;
    /// Durably stages one pending activation ticket before in-memory
    /// publication or daemon claim. A successor is admitted only through the
    /// exact durable `NotReady` predecessor and due-time gate.
    fn stage_activation_ticket(
        &self,
        record: &ActivationLifecycleRecord,
        now_unix_ms: u64,
    ) -> Result<ActivationLifecycleRecord, OrsError>;
    /// Claims one pending activation ticket for the authenticated daemon.
    /// Claim expiry never reopens semantic work; it transitions the ticket to
    /// durable reconciliation.
    fn claim_activation_ticket(
        &self,
        ticket_id: &str,
        claim_owner: &str,
        now_unix_ms: u64,
        claim_expires_at_unix_ms: u64,
    ) -> Result<Option<ActivationLifecycleRecord>, OrsError>;
    /// Atomically admits one exact result and advances its lifecycle row.
    /// Existing exact retention replays; changed identity or a terminal
    /// result-less lifecycle conflicts and never overwrites.
    fn commit_activation_result(
        &self,
        record: &ActivationResultRetentionRecord,
        claim_owner: &str,
        dependency_observation: Option<(&str, &str)>,
        now_unix_ms: u64,
    ) -> Result<ActivationResultRetentionRecord, OrsError>;
    /// Loads one immutable content-addressed campaign view by exact artifact
    /// identity. The view was committed with an admitted local-read result.
    fn load_campaign_learning_state_view(
        &self,
        view_id: &eliot_contracts::ArtifactId,
    ) -> Result<Option<eliot_store_api::CampaignLearningStateViewPublication>, OrsError>;
    /// Atomically reserves all exact owner source-head CAS expectations for
    /// one canonical operation before it reaches the owner store.
    fn reserve_campaign_source_publications(
        &self,
        operation_id: &eliot_contracts::OperationId,
        request_digest: &str,
        publications: &[eliot_store_api::CampaignSourcePublication],
    ) -> Result<(), OrsError>;
    /// Finalizes the reserved immutable source rows and advances their heads
    /// only after the exact canonical owner receipt is committed.
    fn commit_campaign_source_publications(
        &self,
        operation_id: &eliot_contracts::OperationId,
        request_digest: &str,
        publications: &[eliot_store_api::CampaignSourcePublication],
        receipt: &eliot_store_api::WriteReceipt,
    ) -> Result<(), OrsError>;
    /// Releases reservations only after a typed canonical receipt proves the
    /// owner operation did not commit.
    fn abort_campaign_source_publications(
        &self,
        operation_id: &eliot_contracts::OperationId,
        request_digest: &str,
        publications: &[eliot_store_api::CampaignSourcePublication],
    ) -> Result<(), OrsError>;
    /// Reads the requested immutable source revision and exact current owner
    /// head at the same ORS snapshot.
    fn load_campaign_source_revision(
        &self,
        lookup: &eliot_store_api::CampaignSourceRevisionLookup,
        read_state_fence: &eliot_contracts::StateFence,
    ) -> Result<eliot_store_api::CampaignSourceRevisionRead, OrsError>;
    /// Atomically retains one opaque Kernel activation result before its
    /// acknowledgement may be emitted. An exact replay returns the durable
    /// record; a changed ticket/result identity conflicts and never overwrites.
    fn retain_activation_result(
        &self,
        record: &ActivationResultRetentionRecord,
        claim_owner: &str,
        dependency_observation: Option<(&str, &str)>,
        now_unix_ms: u64,
    ) -> Result<ActivationResultRetentionRecord, OrsError>;
    /// Durably terminalizes one result-less ticket as cancelled, expired, or
    /// reconciling. Accepted/result-bearing states never transition here.
    fn terminate_activation_without_result(
        &self,
        ticket_id: &str,
        target: ActivationLifecycleState,
        reason: &str,
        now_unix_ms: u64,
    ) -> Result<Option<ActivationLifecycleRecord>, OrsError>;
    /// Loads one activation lifecycle row by exact ticket identity.
    fn load_activation_lifecycle(
        &self,
        ticket_id: &str,
    ) -> Result<Option<ActivationLifecycleRecord>, OrsError>;
    /// Loads retained activation results by exact ticket and result identity.
    fn load_activation_result(
        &self,
        ticket_id: &str,
        result_sha256: &str,
    ) -> Result<Option<ActivationResultRetentionRecord>, OrsError>;
    /// Loads lifecycle and result rows under one coherent ORS read snapshot.
    fn load_activation_recovery_snapshot(&self) -> Result<ActivationRecoverySnapshot, OrsError>;
    /// Prunes the oldest unreferenced retained activation results until both
    /// hard bounds are satisfied. Lifecycle-referenced rows are never pruned.
    fn prune_activation_results(&self) -> Result<u64, OrsError>;
    /// Stages one native-worker claim intent before any acknowledgement.
    ///
    /// An exact replay under the same claim identity returns
    /// [`crate::NativeWorkerClaimStageOutcome::Existing`] with the same
    /// receipt identity; a changed binding fails with
    /// [`OrsError::NativeWorkerClaimIdentityConflict`] and never overwrites.
    fn stage_native_worker_claim(
        &self,
        record: &crate::NativeWorkerClaimRecord,
    ) -> Result<crate::NativeWorkerClaimStageOutcome, OrsError>;
    /// Advances one staged claim to its next mechanical state.
    ///
    /// An exact repeat of an applied advance returns the durable record
    /// unchanged. An unknown claim returns `Ok(None)`; this method never
    /// invents a record.
    fn advance_native_worker_claim(
        &self,
        claim_id: &crate::OperationIdentity,
        target: crate::NativeWorkerClaimState,
        admission: Option<&crate::NativeWorkerClaimAdmission>,
    ) -> Result<Option<crate::NativeWorkerClaimRecord>, OrsError>;
    /// Loads one claim by exact claim identity.
    fn load_native_worker_claim(
        &self,
        claim_id: &crate::OperationIdentity,
    ) -> Result<Option<crate::NativeWorkerClaimRecord>, OrsError>;
    /// Looks up one durable replay request without acquiring anything.
    ///
    /// An unknown identity returns [`WorkerReplayRequestDecision::New`]; a
    /// retained identity with the same fingerprint returns
    /// [`WorkerReplayRequestDecision::Replay`] with the request's retained
    /// events in sequence order; a retained identity with a changed
    /// fingerprint returns [`WorkerReplayRequestDecision::Conflict`]. No
    /// claim binding is required: reads never execute.
    fn lookup_replay_request(
        &self,
        stream_id: &str,
        request_id: &str,
        fingerprint: &str,
    ) -> Result<WorkerReplayRequestDecision, OrsError>;
    /// Atomically acquires one durable replay request or reports its durable
    /// outcome.
    ///
    /// The first writer wins in one write transaction: an unknown identity is
    /// durably acquired and returns [`WorkerReplayRequestDecision::New`]; a
    /// retained acquisition returns `Replay` or `Conflict` exactly as
    /// [`OperationalRecoveryStore::lookup_replay_request`] does, so a
    /// retained acquisition is never a fresh request after a crash. The
    /// presented generation/epoch/fence must equal the bound claim record
    /// (read-only); a missing claim or a stale binding fails with
    /// [`OrsError::WorkerReplayStaleStream`] and acquires nothing.
    fn begin_replay_request(
        &self,
        begin: &WorkerReplayBegin,
    ) -> Result<WorkerReplayRequestDecision, OrsError>;
    /// Persists one replay draft under its exact stream with a durable
    /// identity and sequence.
    ///
    /// An identical draft under the same `(stream, request)` replays the same
    /// `event_id` and sequence instead of duplicating the event. A draft for
    /// a request that was never acquired fails with
    /// [`OrsError::ReservationNotFound`]; a stale binding fails with
    /// [`OrsError::WorkerReplayStaleStream`].
    fn append_replay_event(&self, draft: &WorkerReplayDraft)
    -> Result<WorkerReplayEvent, OrsError>;
    /// Returns the retained suffix strictly after `after_sequence` in
    /// sequence order, preserving gaps.
    ///
    /// A suffix longer than [`crate::MAX_REPLAY_PAGE`] fails with
    /// [`OrsError::ProjectionLimitExceeded`] instead of truncating silently;
    /// a prefix gap from retention pruning (events at or before
    /// `after_sequence` are gone) fails with
    /// [`OrsError::WorkerReplayIncomplete`] instead of returning an empty
    /// success on incomplete storage.
    fn replay_stream(
        &self,
        stream_id: &str,
        after_sequence: u64,
    ) -> Result<Vec<WorkerReplayEvent>, OrsError>;
    /// Verifies one acknowledgement against its exact durable event,
    /// persists the disposition, and advances only the cursor its phase
    /// allows (DURABLE advances the producer cursor, APPLIED or REJECTED the
    /// consumer cursor, UNKNOWN none).
    ///
    /// A foreign acknowledgement fails with
    /// [`OrsError::WorkerReplayAckMismatch`]; a stale binding fails with
    /// [`OrsError::WorkerReplayStaleStream`].
    fn acknowledge_replay_event(
        &self,
        ack: &WorkerReplayAck,
    ) -> Result<WorkerReplayCursors, OrsError>;
    /// Prunes the longest APPLIED-or-REJECTED event prefix of one stream,
    /// retaining the newest [`crate::MAX_REPLAY_PAGE`] terminal events.
    ///
    /// Returns the number of events removed. Pruning is retention
    /// maintenance, not execution: it requires no claim binding and never
    /// touches UNKNOWN (still reconciling) events.
    fn prune_replay_stream(&self, stream_id: &str) -> Result<u64, OrsError>;
    /// Loads one replay stream head without mutating anything.
    ///
    /// Read-only projection for the Kernel replay transport: an unknown
    /// stream returns `Ok(None)`; a stored head is validated before return.
    /// Used to answer `New` decisions with the exact next sequence and to
    /// build conflict evidence without acquiring.
    fn load_replay_stream_head(
        &self,
        stream_id: &str,
    ) -> Result<Option<WorkerReplayStreamRecord>, OrsError>;
    /// Loads one retained replay acquisition without mutating anything.
    ///
    /// Read-only projection for the Kernel replay transport: an unknown
    /// `(stream, request)` returns `Ok(None)`. Used to report the recorded
    /// fingerprint in `Conflict` decisions.
    fn load_replay_request_record(
        &self,
        stream_id: &str,
        request_id: &str,
    ) -> Result<Option<WorkerReplayRequestRecord>, OrsError>;
}

/// redb-backed ORS implementation. Every mutating method commits one short transaction.
pub struct RedbRecoveryStore {
    database: Database,
    evidence: Arc<dyn CanonicalEvidenceProvider>,
    #[cfg(feature = "test-support")]
    authority_handoff_failpoint:
        std::sync::Mutex<Option<Arc<crate::test_support::AuthorityHandoffPersistenceFailpoint>>>,
}

/// Narrow durable port for scan disclosure records (issue #2900).
///
/// The installation-bound scan-disclosure adapter writes, replays, reads and
/// retires through this port; the canonical Store/ORS owner behind it keeps
/// every atomicity, conflict and reconciliation semantic. The port is
/// object-safe so the adapter holds it behind `Arc`.
pub trait ScanDisclosureRecordOwner: Send + Sync {
    /// Stages one `Prepared` record; exact replay returns the durable
    /// winner, changed bindings conflict.
    fn stage_scan_disclosure(
        &self,
        record: &crate::ScanDisclosureOrsRecord,
    ) -> Result<crate::ScanDisclosureStageOutcome, OrsError>;

    /// Commits one staged record; unknown keys return `Ok(None)` and never
    /// invent state.
    fn commit_scan_disclosure(
        &self,
        operation_key: &str,
        request_hash: &str,
        writer_receipt: &str,
    ) -> Result<Option<crate::ScanDisclosureOrsRecord>, OrsError>;

    /// Loads one record with digest re-verification; unknown keys return
    /// `Ok(None)`.
    fn load_scan_disclosure(
        &self,
        operation_key: &str,
    ) -> Result<Option<crate::ScanDisclosureOrsRecord>, OrsError>;

    /// Retires one committed record under an explicit policy; unknown keys
    /// return `Ok(None)`.
    fn retire_scan_disclosure(
        &self,
        operation_key: &str,
        request_hash: &str,
        policy_revision: u64,
        successor_ref: Option<&str>,
    ) -> Result<Option<crate::ScanDisclosureOrsRecord>, OrsError>;

    /// Lists one installation's records bounded by `limit`, oldest first.
    fn list_scan_disclosures(
        &self,
        installation_id: &str,
        limit: u16,
    ) -> Result<Vec<crate::ScanDisclosureOrsRecord>, OrsError>;
}

impl ScanDisclosureRecordOwner for RedbRecoveryStore {
    fn stage_scan_disclosure(
        &self,
        record: &crate::ScanDisclosureOrsRecord,
    ) -> Result<crate::ScanDisclosureStageOutcome, OrsError> {
        RedbRecoveryStore::stage_scan_disclosure(self, record)
    }

    fn commit_scan_disclosure(
        &self,
        operation_key: &str,
        request_hash: &str,
        writer_receipt: &str,
    ) -> Result<Option<crate::ScanDisclosureOrsRecord>, OrsError> {
        RedbRecoveryStore::commit_scan_disclosure(self, operation_key, request_hash, writer_receipt)
    }

    fn load_scan_disclosure(
        &self,
        operation_key: &str,
    ) -> Result<Option<crate::ScanDisclosureOrsRecord>, OrsError> {
        RedbRecoveryStore::load_scan_disclosure(self, operation_key)
    }

    fn retire_scan_disclosure(
        &self,
        operation_key: &str,
        request_hash: &str,
        policy_revision: u64,
        successor_ref: Option<&str>,
    ) -> Result<Option<crate::ScanDisclosureOrsRecord>, OrsError> {
        RedbRecoveryStore::retire_scan_disclosure(
            self,
            operation_key,
            request_hash,
            policy_revision,
            successor_ref,
        )
    }

    fn list_scan_disclosures(
        &self,
        installation_id: &str,
        limit: u16,
    ) -> Result<Vec<crate::ScanDisclosureOrsRecord>, OrsError> {
        RedbRecoveryStore::list_scan_disclosures(self, installation_id, limit)
    }
}

impl RedbRecoveryStore {
    /// Exports one coherent backup page under a single read transaction.
    ///
    /// Delegates to the ORS-owned `backup_snapshot` projection; binds the
    /// request fence token so pages from different fences never mix.
    pub fn export_backup_page(
        &self,
        request: &crate::backup_snapshot::OrsBackupRequest,
        page_index: u32,
    ) -> Result<crate::backup_snapshot::OrsBackupPage, OrsError> {
        backup_snapshot::export_page(&self.database, request, page_index)
    }

    /// Exports a bounded coherent backup snapshot (all pages, one fence).
    ///
    /// Distinct from the report-only `logical_snapshot`: binds source
    /// installation/generation/schema, canonical fence, high-water/order,
    /// exact row-family denominator and digest chain.
    pub fn export_backup_snapshot(
        &self,
        request: &crate::backup_snapshot::OrsBackupRequest,
    ) -> Result<crate::backup_snapshot::OrsBackupSnapshot, OrsError> {
        backup_snapshot::export_snapshot(&self.database, request)
    }

    /// Opens the typed process-stream recovery family cursor for a backup
    /// (issue #2884).
    ///
    /// This is the only producer of a family cursor: it reads the durable family
    /// revision and the family's streamed content root under one read
    /// transaction, so the frozen snapshot identity can never mix two moments.
    /// The returned cursor names the start of the family; attach it with
    /// [`crate::backup_snapshot::OrsBackupRequest::with_process_stream_recovery_cursor`]
    /// so the family is paged under its own total order instead of being
    /// materialised whole and carried on the final operational page.
    ///
    /// Reading the family is not authority: the cursor carries no process,
    /// session or authority state and grants no restore path. Paging the family
    /// through more pages raises no authority either; every exported row still
    /// restores only through
    /// [`Self::import_process_stream_recovery_suspended`].
    pub fn open_backup_process_stream_recovery_family(
        &self,
    ) -> Result<crate::backup_snapshot::OrsFamilyCursor, OrsError> {
        backup_snapshot::open_process_stream_recovery_family(&self.database)
    }

    /// Triages one backup page as quarantined import outcomes without writing.
    ///
    /// Every entry returns imported/rejected/forensic/blocked/unresolved;
    /// unresolved entries stay quarantined for the existing canonical
    /// reconciliation owner. Never activates authority, never advances
    /// canonical ordering, never writes durable state.
    pub fn import_backup_page_quarantined(
        &self,
        import: &crate::backup_snapshot::OrsBackupImportRequest,
        page: &crate::backup_snapshot::OrsBackupPage,
    ) -> Result<Vec<(String, crate::backup_snapshot::PerEntryOutcome)>, OrsError> {
        backup_snapshot::import_page_quarantined(&self.database, &self.evidence, import, page)
    }

    /// Exact row-family backup disposition for every ORS row family.
    pub fn backup_row_family_denominator() -> Vec<crate::backup_snapshot::RowFamilyDisposition> {
        backup_snapshot::row_family_denominator()
    }

    /// Reconciles quarantined per-entry outcomes into one import receipt.
    ///
    /// Pure receipt binding over already-triaged outcomes; emits no store
    /// writes. A new empty target never means old effects are resolved:
    /// `unresolved_count` is counted from the outcomes, and
    /// `known_zero_unresolved` must attest complete current-owner validation
    /// before zero is trusted.
    pub fn reconcile_backup_import(
        import: &crate::backup_snapshot::OrsBackupImportRequest,
        per_entry: &[(String, crate::backup_snapshot::PerEntryOutcome)],
        import_at_ms: i64,
    ) -> Result<crate::backup_snapshot::OrsBackupImportReceipt, OrsError> {
        backup_snapshot::reconcile_import_receipt(import, per_entry, import_at_ms)
    }

    /// Replays a lost import response without any duplicate effect.
    ///
    /// Idempotent clone of the prior receipt: no store read, no store write,
    /// no re-triage, so a retried response can never double-apply outcomes.
    /// Unknown import outcomes stay quarantined for the existing canonical
    /// reconciliation owner; never blindly retried here.
    pub fn reconcile_lost_backup_import_response(
        prior: &crate::backup_snapshot::OrsBackupImportReceipt,
    ) -> crate::backup_snapshot::OrsBackupImportReceipt {
        backup_snapshot::reconcile_lost_import_response(prior)
    }
}

fn same_store_rebind_binding(
    left: &crate::StoreRebindReplayRecord,
    right: &crate::StoreRebindReplayRecord,
) -> bool {
    left.operation_id == right.operation_id
        && left.request_digest == right.request_digest
        && left.candidate_binding_digest == right.candidate_binding_digest
        && left.store_fence == right.store_fence
        && left.requirement_digest == right.requirement_digest
        && left.process_id == right.process_id
        && left.process_start_time_100ns == right.process_start_time_100ns
        && left.process_image_path == right.process_image_path
        && left.job_name == right.job_name
        && left.generation == right.generation
        && left.authority_epoch == right.authority_epoch
}

impl persistence_codec::PersistedValue for HostRequestRecord {
    const RECORD_TYPE: &'static str = "host_request";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

/// Durable pointer from one logical host-request key to its winning
/// operation (issue #2571).
///
/// The link carries identity only: the commitment lives in the operation
/// row and is re-checked on every resolve and load, so a divergent link can
/// never silently adopt another operation's result. Links are written once
/// with their row, never updated, never deleted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostRequestLogicalLink {
    operation_id: OperationIdentity,
    request_digest: String,
}

impl persistence_codec::PersistedValue for HostRequestLogicalLink {
    const RECORD_TYPE: &'static str = "host_request_logical_link";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        crate::model::validate_text(self.operation_id.as_str(), "host_request_operation_id")?;
        crate::model::validate_digest(&self.request_digest, "host_request_request_digest")?;
        Ok(())
    }
}

impl persistence_codec::PersistedValue for ActivationResultRetentionRecord {
    const RECORD_TYPE: &'static str = "activation_result_retention";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()?;
        if self.retention_order == 0 {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "retained activation result has no ORS retention order".to_owned(),
            });
        }
        Ok(())
    }
}

impl persistence_codec::PersistedValue for ActivationLifecycleRecord {
    const RECORD_TYPE: &'static str = "activation_lifecycle";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()?;
        if self.lifecycle_order == 0 {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "activation lifecycle has no ORS lifecycle order".to_owned(),
            });
        }
        Ok(())
    }
}

impl persistence_codec::PersistedValue for NativeWorkerClaimRecord {
    const RECORD_TYPE: &'static str = "native_worker_claim";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl persistence_codec::PersistedValue for GrantClosureMigrationRecord {
    const RECORD_TYPE: &'static str = "grant_closure_migration";

    #[allow(
        clippy::too_many_lines,
        reason = "migration disposition validation keeps identity, source digest, and row bindings together"
    )]
    fn validate_persisted(&self) -> Result<(), OrsError> {
        if self.schema != GRANT_CLOSURE_MIGRATION_SCHEMA
            || self.version != GRANT_CLOSURE_MIGRATION_VERSION
        {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "unsupported grant-closure migration schema or version".to_owned(),
            });
        }
        crate::model::validate_text(&self.operation_id, "grant_closure_migration_operation_id")
            .map_err(|error| OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: error.to_string(),
            })?;
        crate::model::validate_text(&self.legacy_key, "grant_closure_migration_legacy_key")
            .map_err(|error| OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: error.to_string(),
            })?;
        crate::model::validate_text(
            &self.target_grant_id,
            "grant_closure_migration_target_grant_id",
        )
        .map_err(|error| OrsError::IntegrityProblem {
            record_type: Self::RECORD_TYPE,
            reason: error.to_string(),
        })?;
        crate::model::validate_text(
            &self.authority_root_ref,
            "grant_closure_migration_authority_root_ref",
        )
        .map_err(|error| OrsError::IntegrityProblem {
            record_type: Self::RECORD_TYPE,
            reason: error.to_string(),
        })?;
        crate::model::validate_digest(
            &self.source_row_sha256,
            "grant_closure_migration_source_row_sha256",
        )
        .map_err(|error| OrsError::IntegrityProblem {
            record_type: Self::RECORD_TYPE,
            reason: error.to_string(),
        })?;
        crate::model::validate_text(&self.reason, "grant_closure_migration_reason").map_err(
            |error| OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: error.to_string(),
            },
        )?;
        if self.legacy_row_json.is_empty()
            || crate::model::sha256_hex(self.legacy_row_json.as_bytes()) != self.source_row_sha256
        {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "retained legacy row bytes do not match the source digest".to_owned(),
            });
        }
        if self.grant_graph_revision == 0 || self.legacy_operation_order == 0 {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "graph revision and legacy operation order must be nonzero".to_owned(),
            });
        }
        let expected_legacy_key = format!("grant_closure:{}", self.operation_id);
        if self.legacy_key != expected_legacy_key {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "legacy key does not match the operation identity".to_owned(),
            });
        }
        let expected_phase = match self.legacy_state.as_str() {
            "ACTIVE" => OperationalPhase::Active,
            "FENCED" | "REVOKED" => OperationalPhase::Fenced,
            _ => {
                return Err(OrsError::IntegrityProblem {
                    record_type: Self::RECORD_TYPE,
                    reason: "source state is not ACTIVE, FENCED, or REVOKED".to_owned(),
                });
            }
        };
        if self.legacy_phase != expected_phase {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "legacy phase does not match the legacy state".to_owned(),
            });
        }
        if self.missing_fields.iter().any(|field| {
            crate::model::validate_text(field, "grant_closure_migration_missing_field").is_err()
        }) || self
            .missing_fields
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "missing fields must be nonblank, sorted, and unique".to_owned(),
            });
        }
        match self.disposition {
            GrantClosureMigrationDisposition::CurrentShapeCopied => {
                if !self.missing_fields.is_empty()
                    || self.current_key.as_deref() != Some(expected_legacy_key.as_str())
                    || self.current_operation_order != Some(self.legacy_operation_order)
                {
                    return Err(OrsError::IntegrityProblem {
                        record_type: Self::RECORD_TYPE,
                        reason: "copied migration disposition is missing its current row binding"
                            .to_owned(),
                    });
                }
            }
            GrantClosureMigrationDisposition::LegacyShapeRetained => {
                if self.missing_fields.is_empty()
                    || self.current_key.is_some()
                    || self.current_operation_order.is_some()
                {
                    return Err(OrsError::IntegrityProblem {
                        record_type: Self::RECORD_TYPE,
                        reason: "retained legacy disposition does not name a complete migration"
                            .to_owned(),
                    });
                }
            }
            GrantClosureMigrationDisposition::LegacyShapeSupersededByCurrent => {
                if self.missing_fields.is_empty()
                    || self.current_key.as_deref() != Some(expected_legacy_key.as_str())
                    || self.current_operation_order.is_none_or(|order| order == 0)
                {
                    return Err(OrsError::IntegrityProblem {
                        record_type: Self::RECORD_TYPE,
                        reason: "superseded legacy disposition is missing its current row binding"
                            .to_owned(),
                    });
                }
            }
        }
        Ok(())
    }
}

impl persistence_codec::PersistedValue for DurableGrantClosureSecondPhaseRecord {
    const RECORD_TYPE: &'static str = "grant_closure_second_phase";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl persistence_codec::PersistedValue for crate::WorkerReplayEvent {
    const RECORD_TYPE: &'static str = "worker_replay_event";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl persistence_codec::PersistedValue for crate::WorkerReplayStreamRecord {
    const RECORD_TYPE: &'static str = "worker_replay_stream";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl persistence_codec::PersistedValue for crate::WorkerReplayRequestRecord {
    const RECORD_TYPE: &'static str = "worker_replay_request";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl persistence_codec::PersistedValue for crate::WorkerReplayAckRecord {
    const RECORD_TYPE: &'static str = "worker_replay_ack";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl persistence_codec::PersistedValue for crate::StoreFailureRetentionRecord {
    const RECORD_TYPE: &'static str = "store_failure_retention";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl persistence_codec::PersistedValue for crate::DoctorAttemptRecord {
    const RECORD_TYPE: &'static str = "doctor_attempt";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl persistence_codec::PersistedValue for crate::DoctorEffectRecord {
    const RECORD_TYPE: &'static str = "doctor_effect";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl persistence_codec::PersistedValue for crate::DoctorBudgetLedger {
    const RECORD_TYPE: &'static str = "doctor_budget";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

/// Binds the durable backup-verification result to the ORS codec, so its row is
/// encoded, decoded and re-validated exactly like every other record family in
/// this store: the same JSON codec, the same `IntegrityProblem` record-type
/// envelope on a bad decode, and the same fail-closed `validate()` gate on
/// every read. The record type is the published
/// [`BACKUP_VERIFICATION_RESULT_RECORD_TYPE`] so the Kernel verify route can
/// name the identity-conflict signal by contract instead of by a copied
/// literal.
///
/// The impl is declared in this file rather than beside its siblings in the
/// codec module because the record's type and `validate()` live in `model.rs`
/// and the whole of its persisted contract is exactly that `validate()`.
impl persistence_codec::PersistedValue for BackupVerificationResultRecord {
    const RECORD_TYPE: &'static str = BACKUP_VERIFICATION_RESULT_RECORD_TYPE;

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}
fn doctor_storage(error: impl std::fmt::Display) -> crate::DoctorLedgerError {
    crate::DoctorLedgerError::Storage(error.to_string())
}

fn map_ors_to_doctor(error: OrsError) -> crate::DoctorLedgerError {
    match error {
        OrsError::Encoding(reason) => crate::DoctorLedgerError::Encoding(reason),
        other => crate::DoctorLedgerError::Storage(other.to_string()),
    }
}

impl RedbRecoveryStore {
    #[cfg(test)]
    pub(crate) fn write_process_start_raw_for_test(
        &self,
        record: &ProcessStartReplayRecord,
    ) -> Result<(), OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        {
            let mut table = write.open_table(PROCESS_START_REPLAY).map_err(storage)?;
            let payload = encode(record)?;
            table
                .insert(record.operation_id.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)
    }

    #[cfg(test)]
    pub(crate) fn write_process_evidence_raw_for_test(
        &self,
        key: &str,
        record: &ProcessEvidenceRecord,
    ) -> Result<(), OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        {
            let mut table = write.open_table(PROCESS_EVIDENCE).map_err(storage)?;
            let payload = encode(record)?;
            table.insert(key, payload.as_str()).map_err(storage)?;
        }
        write.commit().map_err(storage)
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn substitute_authority_snapshot_metadata_for_test(
        &self,
        substitution: crate::test_support::AuthoritySnapshotMetadataSubstitution,
    ) -> Result<(), OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        let key = {
            let current = write.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
            current
                .iter()
                .map_err(storage)?
                .find_map(|entry| {
                    let (key, value) = entry.ok()?;
                    let record = decode_named::<DurableOperationalRecord>(
                        value.value(),
                        "operational_current",
                    )
                    .ok()?;
                    (record.kind == OperationalKind::AuthoritySnapshot)
                        .then(|| key.value().to_owned())
                })
                .ok_or(OrsError::AuthoritySnapshotUnavailable)?
        };
        let mut record = {
            let current = write.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
            let value = current
                .get(key.as_str())
                .map_err(storage)?
                .ok_or(OrsError::AuthoritySnapshotUnavailable)?;
            decode_named::<DurableOperationalRecord>(value.value(), "operational_current")?
        };
        let key =
            Self::operational_key(OperationalKind::AuthoritySnapshot, &record.input.subject_id);
        record.input.record_id = substitution.record_id;
        record.input.created_at_ms = substitution.created_at_ms;
        record.input.cleanup_after_ms = substitution.cleanup_after_ms;
        record.input.validate()?;
        record.operation_order = Self::next_operational_order(&write)?;
        Self::persist_operational_record(&write, &key, &record)?;
        write.commit().map_err(storage)
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn install_authority_handoff_failpoint(
        &self,
        failpoint: Arc<crate::test_support::AuthorityHandoffPersistenceFailpoint>,
    ) {
        if let Ok(mut slot) = self.authority_handoff_failpoint.lock() {
            *slot = Some(failpoint);
        }
    }

    /// Atomically reserves a process start, preserving every prior outcome.
    pub fn begin_process_start(
        &self,
        record: &ProcessStartReplayRecord,
    ) -> Result<Option<ProcessStartReplayRecord>, OrsError> {
        record.validate()?;
        let write = self.database.begin_write().map_err(storage)?;
        let key = record.operation_id.as_str();
        let existing = {
            let mut table = write.open_table(PROCESS_START_REPLAY).map_err(storage)?;
            if let Some(existing) = table.get(key).map_err(storage)? {
                let existing: ProcessStartReplayRecord = decode(existing.value())?;
                existing.validate()?;
                if existing.admission_digest != record.admission_digest
                    || existing.owner != record.owner
                {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "process_start_replay",
                        reason: "existing operation identity, digest, or owner conflicts"
                            .to_owned(),
                    });
                }
                Some(existing)
            } else {
                let payload = encode(&record)?;
                table.insert(key, payload.as_str()).map_err(storage)?;
                None
            }
        };
        write.commit().map_err(storage)?;
        Ok(existing)
    }

    /// Loads one process-start replay projection.
    pub fn load_process_start(
        &self,
        operation_id: &crate::OperationIdentity,
    ) -> Result<Option<ProcessStartReplayRecord>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(PROCESS_START_REPLAY).map_err(storage)?;
        table
            .get(operation_id.as_str())
            .map_err(storage)?
            .map(|value| {
                let record: ProcessStartReplayRecord = decode(value.value())?;
                record.validate()?;
                if record.operation_id != *operation_id {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "process_start_replay",
                        reason: "replay record operation identity does not match its key"
                            .to_owned(),
                    });
                }
                Ok(record)
            })
            .transpose()
    }

    /// Persists a replay projection without allowing identity replacement.
    pub fn persist_process_start(&self, record: &ProcessStartReplayRecord) -> Result<(), OrsError> {
        record.validate()?;
        let write = self.database.begin_write().map_err(storage)?;
        let key = record.operation_id.as_str();
        {
            let mut table = write.open_table(PROCESS_START_REPLAY).map_err(storage)?;
            let existing: Option<ProcessStartReplayRecord> = table
                .get(key)
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?;
            if let Some(existing) = &existing {
                existing.validate()?;
                if existing.admission_digest != record.admission_digest
                    || existing.owner != record.owner
                {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "process_start_replay",
                        reason: "identity replacement rejected".to_owned(),
                    });
                }
                let allowed = match (existing.state, record.state) {
                    (
                        ProcessStartReplayState::Reserved,
                        ProcessStartReplayState::Reserved
                        | ProcessStartReplayState::Completed
                        | ProcessStartReplayState::Unknown,
                    ) => true,
                    (ProcessStartReplayState::Completed, ProcessStartReplayState::Completed)
                    | (ProcessStartReplayState::Unknown, ProcessStartReplayState::Unknown) => {
                        *existing == *record
                    }
                    _ => false,
                };
                if !allowed {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "process_start_replay",
                        reason: "non-monotonic or conflicting replay transition".to_owned(),
                    });
                }
            }
            if existing.as_ref().is_none_or(|current| current != record) {
                let payload = encode(&record)?;
                table.insert(key, payload.as_str()).map_err(storage)?;
            }
        }
        write.commit().map_err(storage)
    }

    /// Compare-and-deletes exactly one reserved process-start record.
    pub fn abort_process_start(
        &self,
        operation_id: &crate::OperationIdentity,
        admission_digest: &str,
        owner: &eliot_process::ProcessOwnerBinding,
    ) -> Result<ProcessStartReplayAbort, OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        let key = operation_id.as_str();
        let mut table = write.open_table(PROCESS_START_REPLAY).map_err(storage)?;
        let existing = {
            let Some(value) = table.get(key).map_err(storage)? else {
                drop(table);
                return Err(OrsError::IntegrityProblem {
                    record_type: "process_start_replay",
                    reason: "reserved replay record disappeared before abort".to_owned(),
                });
            };
            decode::<ProcessStartReplayRecord>(value.value())?
        };
        existing.validate()?;
        if existing.operation_id != *operation_id
            || existing.admission_digest != admission_digest
            || existing.owner != *owner
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "process_start_replay",
                reason: "pre-effect abort identity mismatch".to_owned(),
            });
        }
        let result = if existing.state == ProcessStartReplayState::Reserved {
            table.remove(key).map_err(storage)?;
            ProcessStartReplayAbort::Released
        } else {
            ProcessStartReplayAbort::NotReleased
        };
        drop(table);
        write.commit().map_err(storage)?;
        Ok(result)
    }

    pub fn begin_store_rebind(
        &self,
        record: &crate::StoreRebindReplayRecord,
    ) -> Result<Option<crate::StoreRebindReplayRecord>, OrsError> {
        record.validate()?;
        let write = self.database.begin_write().map_err(storage)?;
        let key = format!(
            "{}::{}",
            record.operation_id.as_str(),
            record.request_digest.clone()
        );
        let existing = {
            let mut table = write.open_table(STORE_REBIND_REPLAY).map_err(storage)?;
            if let Some(existing) = table.get(key.as_str()).map_err(storage)? {
                let existing: crate::StoreRebindReplayRecord = decode(existing.value())?;
                existing.validate()?;
                if !same_store_rebind_binding(&existing, record) {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "store_rebind_replay",
                        reason: "existing Store rebind binding conflicts".to_owned(),
                    });
                }
                Some(existing)
            } else {
                let payload = encode(record)?;
                table
                    .insert(key.as_str(), payload.as_str())
                    .map_err(storage)?;
                None
            }
        };
        write.commit().map_err(storage)?;
        Ok(existing)
    }

    pub fn load_store_rebind(
        &self,
        operation_id: &crate::OperationIdentity,
        request_digest: &str,
    ) -> Result<Option<crate::StoreRebindReplayRecord>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(STORE_REBIND_REPLAY).map_err(storage)?;
        let key = format!("{}::{}", operation_id.as_str(), request_digest);
        table
            .get(key.as_str())
            .map_err(storage)?
            .map(|value| {
                let record: crate::StoreRebindReplayRecord = decode(value.value())?;
                record.validate()?;
                Ok(record)
            })
            .transpose()
    }

    pub fn persist_store_rebind(
        &self,
        record: &crate::StoreRebindReplayRecord,
    ) -> Result<(), OrsError> {
        record.validate()?;
        let write = self.database.begin_write().map_err(storage)?;
        {
            let mut table = write.open_table(STORE_REBIND_REPLAY).map_err(storage)?;
            let key = format!(
                "{}::{}",
                record.operation_id.as_str(),
                record.request_digest.clone()
            );
            let existing: Option<crate::StoreRebindReplayRecord> = table
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?;
            let mut next = record.clone();
            if let Some(existing) = &existing {
                existing.validate()?;
                if !same_store_rebind_binding(existing, record) {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "store_rebind_replay",
                        reason: "Store rebind replacement binding rejected".to_owned(),
                    });
                }
                match (existing.state, record.state) {
                    (
                        crate::StoreRebindReplayState::Pending,
                        crate::StoreRebindReplayState::Pending,
                    ) => {
                        // A repeated begin is idempotent and must not replace
                        // the original durable binding.
                        next = existing.clone();
                    }
                    (
                        crate::StoreRebindReplayState::Pending,
                        crate::StoreRebindReplayState::Committed,
                    ) => {
                        // The caller cannot choose the linearization point;
                        // the ORS write transaction assigns it atomically.
                        next.commit_order = Self::next_operational_order(&write)?;
                    }
                    (
                        crate::StoreRebindReplayState::Committed,
                        crate::StoreRebindReplayState::Committed,
                    ) => {
                        if existing.receipt != record.receipt {
                            return Err(OrsError::IntegrityProblem {
                                record_type: "store_rebind_replay",
                                reason: "committed receipt replacement rejected".to_owned(),
                            });
                        }
                        next = existing.clone();
                    }
                    _ => {
                        return Err(OrsError::IntegrityProblem {
                            record_type: "store_rebind_replay",
                            reason: "non-monotonic store rebind transition".to_owned(),
                        });
                    }
                }
            } else if next.state == crate::StoreRebindReplayState::Committed {
                // A direct committed write is still ordered by this
                // transaction, never by a caller-provided value.
                next.commit_order = Self::next_operational_order(&write)?;
            }
            next.validate()?;
            if existing.as_ref().is_none_or(|current| current != &next) {
                let payload = encode(&next)?;
                table
                    .insert(key.as_str(), payload.as_str())
                    .map_err(storage)?;
            }
        }
        write.commit().map_err(storage)
    }

    pub fn abort_store_rebind(
        &self,
        operation_id: &crate::OperationIdentity,
        request_digest: &str,
    ) -> Result<bool, OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        let key = format!("{}::{}", operation_id.as_str(), request_digest);
        let removed = {
            let mut table = write.open_table(STORE_REBIND_REPLAY).map_err(storage)?;
            let pending_bytes = table
                .get(key.as_str())
                .map_err(storage)?
                .map(|v| v.value().to_owned());
            if let Some(bytes) = pending_bytes {
                let existing: crate::StoreRebindReplayRecord = decode(&bytes)?;
                existing.validate()?;
                if existing.state == crate::StoreRebindReplayState::Pending {
                    table.remove(key.as_str()).map_err(storage)?;
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };
        write.commit().map_err(storage)?;
        Ok(removed)
    }

    pub fn load_all_store_rebinds(&self) -> Result<Vec<crate::StoreRebindReplayRecord>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(STORE_REBIND_REPLAY).map_err(storage)?;
        let mut records = Vec::new();
        for entry in table.iter().map_err(storage)? {
            let (_, value) = entry.map_err(storage)?;
            let record: crate::StoreRebindReplayRecord = decode(value.value())?;
            record.validate()?;
            records.push(record);
        }
        Ok(records)
    }

    /// Retains one closed typed Store failure bound to its exact admitted
    /// operation identity.
    ///
    /// The owner envelope is validated by the owner contract and stored
    /// verbatim; ORS never reinterprets disposition, retry, recovery, or
    /// provider prose, and never derives control meaning from
    /// `human_detail`. An exact replay under the same operation/request
    /// identity returns the durably stored record unchanged; a changed
    /// failure envelope, binding, or fence under the same identity fails
    /// with an integrity error. A retained `UNKNOWN_OUTCOME` failure with
    /// no reconciling receipt is the reconciling state: it is never
    /// reported as committed, terminal, unavailable, or safe-to-retry.
    /// There is no removal method: retained failures are terminal or
    /// reconciling evidence and restart must rehydrate them unchanged.
    pub fn retain_store_failure(
        &self,
        record: &crate::StoreFailureRetentionRecord,
    ) -> Result<Option<crate::StoreFailureRetentionRecord>, OrsError> {
        record.validate()?;
        let write = self.database.begin_write().map_err(storage)?;
        let key = record.record_key();
        let stored = {
            let mut table = write.open_table(STORE_FAILURE_RETENTION).map_err(storage)?;
            let retained_bytes = table
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| value.value().to_owned());
            let Some(bytes) = retained_bytes else {
                let payload = encode(record)?;
                table
                    .insert(key.as_str(), payload.as_str())
                    .map_err(storage)?;
                drop(table);
                write.commit().map_err(storage)?;
                return Ok(None);
            };
            let existing: crate::StoreFailureRetentionRecord = decode(&bytes)?;
            existing.validate()?;
            if !existing.same_binding(record) {
                return Err(OrsError::IntegrityProblem {
                    record_type: "store_failure_retention",
                    reason: "existing retained Store failure binding conflicts".to_owned(),
                });
            }
            if existing.failure != record.failure {
                return Err(OrsError::IntegrityProblem {
                    record_type: "store_failure_retention",
                    reason: "retained Store failure replacement rejected".to_owned(),
                });
            }
            // Monotonic reconciliation only: an unresolved retention may
            // bind its exact reconciling receipt, but a reconciled
            // retention is immutable and can never become unresolved.
            let mut next = existing.clone();
            match (&existing.reconciled_receipt, &record.reconciled_receipt) {
                (None, None) => {}
                (None, Some(_)) => {
                    next.reconciled_receipt
                        .clone_from(&record.reconciled_receipt);
                }
                (Some(stored), Some(incoming)) if stored == incoming => {}
                (Some(_), _) => {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "store_failure_retention",
                        reason: "reconciling receipt replacement rejected".to_owned(),
                    });
                }
            }
            next.validate()?;
            if next != existing {
                let payload = encode(&next)?;
                table
                    .insert(key.as_str(), payload.as_str())
                    .map_err(storage)?;
            }
            next
        };
        write.commit().map_err(storage)?;
        Ok(Some(stored))
    }

    /// Loads one retained Store failure by exact operation/request identity.
    ///
    /// The envelope is returned verbatim: disposition, retry directive,
    /// recovery action, mutation disposition, conflict observations, and
    /// evidence identity are exactly as retained, including
    /// `UNKNOWN_OUTCOME` as reconciling while no receipt is bound.
    pub fn load_store_failure(
        &self,
        operation_id: &crate::OperationIdentity,
        request_digest: &str,
    ) -> Result<Option<crate::StoreFailureRetentionRecord>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(STORE_FAILURE_RETENTION).map_err(storage)?;
        let key = format!("{}::{}", operation_id.as_str(), request_digest);
        table
            .get(key.as_str())
            .map_err(storage)?
            .map(|value| {
                let record: crate::StoreFailureRetentionRecord = decode(value.value())?;
                record.validate()?;
                Ok(record)
            })
            .transpose()
    }

    /// Binds the exact reconciling receipt to a retained unknown-outcome
    /// Store failure after the original operation was reconciled.
    ///
    /// An unknown operation returns `Ok(None)`; this method never invents
    /// a record, never retries, never reroutes, and never substitutes an
    /// operation: it only records that the exact retained operation was
    /// reconciled under the given receipt digest, so a later restart
    /// rehydrates the reconciled state instead of re-reconciling. A bound
    /// receipt is immutable, and reconciling a terminal
    /// (non-unknown-outcome) retention fails: terminal evidence stays
    /// terminal.
    pub fn mark_store_failure_reconciled(
        &self,
        operation_id: &crate::OperationIdentity,
        request_digest: &str,
        reconciling_receipt: &str,
    ) -> Result<Option<crate::StoreFailureRetentionRecord>, OrsError> {
        crate::model::validate_digest(reconciling_receipt, "store_failure_reconciled_receipt")?;
        let write = self.database.begin_write().map_err(storage)?;
        let key = format!("{}::{}", operation_id.as_str(), request_digest);
        let retained = {
            let mut table = write.open_table(STORE_FAILURE_RETENTION).map_err(storage)?;
            let retained_bytes = table
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| value.value().to_owned());
            let Some(bytes) = retained_bytes else {
                drop(table);
                write.commit().map_err(storage)?;
                return Ok(None);
            };
            let mut next: crate::StoreFailureRetentionRecord = decode(&bytes)?;
            next.validate()?;
            if next.failure.disposition != eliot_store_api::StoreFailureDisposition::UnknownOutcome
            {
                return Err(OrsError::InvalidField {
                    field: "store_failure_reconciled_receipt",
                    reason: "only unknown-outcome retention reconciles",
                });
            }
            match &next.reconciled_receipt {
                Some(existing) if existing == reconciling_receipt => {}
                Some(_) => {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "store_failure_retention",
                        reason: "reconciling receipt replacement rejected".to_owned(),
                    });
                }
                None => {
                    next.reconciled_receipt = Some(reconciling_receipt.to_owned());
                }
            }
            next.validate()?;
            let payload = encode(&next)?;
            table
                .insert(key.as_str(), payload.as_str())
                .map_err(storage)?;
            next
        };
        write.commit().map_err(storage)?;
        Ok(Some(retained))
    }

    /// Loads every retained Store failure for restart rehydration.
    ///
    /// Restart restores the same typed terminal or reconciling state
    /// without recomputation: terminal and unknown-outcome envelopes
    /// round-trip verbatim, and an unknown outcome never degrades to
    /// not-attempted, unavailable, or safe-to-retry.
    pub fn load_all_store_failures(
        &self,
    ) -> Result<Vec<crate::StoreFailureRetentionRecord>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(STORE_FAILURE_RETENTION).map_err(storage)?;
        let mut records = Vec::new();
        for entry in table.iter().map_err(storage)? {
            let (_, value) = entry.map_err(storage)?;
            let record: crate::StoreFailureRetentionRecord = decode(value.value())?;
            record.validate()?;
            records.push(record);
        }
        Ok(records)
    }

    /// Stages one Kernel-owned unknown-commit recovery record before the
    /// commit send (I14.21, issue #1690).
    ///
    /// The record must be open (no outcome, no evidence). An exact replay
    /// under the same idempotency key returns the durably stored record
    /// unchanged; a changed binding under the same key fails with an
    /// integrity error, so one key can never cover two different attempts.
    pub fn stage_unknown_commit(
        &self,
        record: &UnknownCommitRecord,
    ) -> Result<Option<UnknownCommitRecord>, OrsError> {
        record.validate()?;
        if !record.is_open() {
            return Err(OrsError::InvalidField {
                field: "unknown_commit_outcome",
                reason: "only an open unknown-commit record stages",
            });
        }
        let write = self.database.begin_write().map_err(storage)?;
        let key = record.record_key();
        let stored = {
            let mut table = write.open_table(UNKNOWN_COMMIT_RECOVERY).map_err(storage)?;
            let staged_bytes = table
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| value.value().to_owned());
            let Some(bytes) = staged_bytes else {
                let payload = encode(record)?;
                table
                    .insert(key.as_str(), payload.as_str())
                    .map_err(storage)?;
                drop(table);
                write.commit().map_err(storage)?;
                return Ok(None);
            };
            let existing: UnknownCommitRecord = decode(&bytes)?;
            existing.validate()?;
            if !existing.same_binding(record) {
                return Err(OrsError::IntegrityProblem {
                    record_type: "unknown_commit_recovery",
                    reason: "existing unknown-commit binding conflicts".to_owned(),
                });
            }
            existing
        };
        write.commit().map_err(storage)?;
        Ok(Some(stored))
    }

    /// Loads one unknown-commit recovery record by exact idempotency key.
    pub fn load_unknown_commit(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<UnknownCommitRecord>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(UNKNOWN_COMMIT_RECOVERY).map_err(storage)?;
        table
            .get(idempotency_key)
            .map_err(storage)?
            .map(|value| {
                let record: UnknownCommitRecord = decode(value.value())?;
                record.validate()?;
                Ok(record)
            })
            .transpose()
    }

    /// Lists every still-open unknown-commit record: the visible Problem
    /// State for Doctor/Human disposition (I14.21, issue #1690).
    ///
    /// Restart rehydrates the same open set: an unknown outcome never
    /// degrades to not-attempted, and a resolved record never reopens.
    pub fn list_open_unknown_commits(&self) -> Result<Vec<UnknownCommitRecord>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(UNKNOWN_COMMIT_RECOVERY).map_err(storage)?;
        let mut records = Vec::new();
        for entry in table.iter().map_err(storage)? {
            let (_, value) = entry.map_err(storage)?;
            let record: UnknownCommitRecord = decode(value.value())?;
            record.validate()?;
            if record.is_open() {
                records.push(record);
            }
        }
        Ok(records)
    }

    /// Resolves one open unknown-commit record with its receipt evidence
    /// (I14.21 evidence-backed disposition, issue #1690).
    ///
    /// Only an open record resolves, and only with a bound receipt digest:
    /// resolution without evidence fails, a second resolution fails, and a
    /// different digest never replaces the bound one. Returns `Ok(None)`
    /// for an unknown key; this method never invents a record and never
    /// retries a send.
    pub fn resolve_unknown_commit(
        &self,
        idempotency_key: &str,
        outcome: UnknownCommitOutcome,
        evidence_receipt_digest: &str,
    ) -> Result<Option<UnknownCommitRecord>, OrsError> {
        crate::model::validate_digest(evidence_receipt_digest, "unknown_commit_evidence")?;
        let write = self.database.begin_write().map_err(storage)?;
        let resolved = {
            let mut table = write.open_table(UNKNOWN_COMMIT_RECOVERY).map_err(storage)?;
            let staged_bytes = table
                .get(idempotency_key)
                .map_err(storage)?
                .map(|value| value.value().to_owned());
            let Some(bytes) = staged_bytes else {
                drop(table);
                write.commit().map_err(storage)?;
                return Ok(None);
            };
            let mut next: UnknownCommitRecord = decode(&bytes)?;
            next.validate()?;
            if !next.is_open() {
                return Err(OrsError::InvalidField {
                    field: "unknown_commit_outcome",
                    reason: "only an open unknown-commit record resolves",
                });
            }
            next.outcome = Some(outcome);
            next.evidence_receipt_digest = Some(evidence_receipt_digest.to_owned());
            next.validate()?;
            let payload = encode(&next)?;
            table
                .insert(idempotency_key, payload.as_str())
                .map_err(storage)?;
            next
        };
        write.commit().map_err(storage)?;
        Ok(Some(resolved))
    }

    /// Stages one scan disclosure record as `Prepared` (issue #2900).
    ///
    /// The stage is the atomic durable step: an exact replay of the same
    /// operation identity with the same binding returns the durable winner,
    /// while the same key with changed bytes or bindings conflicts and never
    /// overwrites. A crash between stage and commit leaves `Prepared`, which
    /// [`RedbRecoveryStore::reconcile_scan_disclosure`] resolves; the final
    /// `Committed` address is only ever occupied by commit.
    pub fn stage_scan_disclosure(
        &self,
        record: &crate::ScanDisclosureOrsRecord,
    ) -> Result<crate::ScanDisclosureStageOutcome, OrsError> {
        record.validate()?;
        if record.state != crate::ScanDisclosureRecordState::Prepared {
            return Err(OrsError::InvalidField {
                field: "scan_disclosure_state",
                reason: "only a prepared scan disclosure record stages",
            });
        }
        let write = self.database.begin_write().map_err(storage)?;
        let key = record.operation_key.clone();
        let stored = {
            let mut table = write.open_table(SCAN_DISCLOSURE_RECORDS).map_err(storage)?;
            let staged_bytes = table
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| value.value().to_owned());
            let Some(bytes) = staged_bytes else {
                let payload = encode(record)?;
                table
                    .insert(key.as_str(), payload.as_str())
                    .map_err(storage)?;
                drop(table);
                write.commit().map_err(storage)?;
                return Ok(crate::ScanDisclosureStageOutcome::Stored);
            };
            let existing: crate::ScanDisclosureOrsRecord = decode(&bytes)?;
            existing.validate()?;
            if !existing.same_binding(record) {
                return Err(OrsError::IntegrityProblem {
                    record_type: crate::SCAN_DISCLOSURE_RECORD_TYPE,
                    reason: "existing scan disclosure binding conflicts".to_owned(),
                });
            }
            existing
        };
        write.commit().map_err(storage)?;
        Ok(crate::ScanDisclosureStageOutcome::AlreadyBound(Box::new(
            stored,
        )))
    }

    /// Commits one staged scan disclosure record (issue #2900).
    ///
    /// Only a `Prepared` row commits, and only with the exact request hash it
    /// staged: the commit publishes the final content address in one atomic
    /// owner transaction. An exact `Committed` replay returns the same
    /// record; a changed binding under the same key conflicts. Returns
    /// `Ok(None)` for an unknown key: commit never invents a record, so a
    /// lost stage surfaces as unknown-commit for the caller to reconcile.
    pub fn commit_scan_disclosure(
        &self,
        operation_key: &str,
        request_hash: &str,
        writer_receipt: &str,
    ) -> Result<Option<crate::ScanDisclosureOrsRecord>, OrsError> {
        crate::model::validate_text(operation_key, "scan_disclosure_operation_key")?;
        crate::model::validate_digest(request_hash, "scan_disclosure_request_hash")?;
        crate::model::validate_text(writer_receipt, "scan_disclosure_writer_receipt")?;
        let write = self.database.begin_write().map_err(storage)?;
        let committed = {
            let mut table = write.open_table(SCAN_DISCLOSURE_RECORDS).map_err(storage)?;
            let staged_bytes = table
                .get(operation_key)
                .map_err(storage)?
                .map(|value| value.value().to_owned());
            let Some(bytes) = staged_bytes else {
                drop(table);
                write.commit().map_err(storage)?;
                return Ok(None);
            };
            let mut next: crate::ScanDisclosureOrsRecord = decode(&bytes)?;
            next.validate()?;
            if next.request_hash != request_hash {
                return Err(OrsError::IntegrityProblem {
                    record_type: crate::SCAN_DISCLOSURE_RECORD_TYPE,
                    reason: "scan disclosure commit binds a different request hash".to_owned(),
                });
            }
            match next.state {
                crate::ScanDisclosureRecordState::Prepared => {
                    next.state = crate::ScanDisclosureRecordState::Committed;
                    next.writer_receipt = writer_receipt.into();
                    next.validate()?;
                    let payload = encode(&next)?;
                    table
                        .insert(operation_key, payload.as_str())
                        .map_err(storage)?;
                    next
                }
                crate::ScanDisclosureRecordState::Committed => next,
                crate::ScanDisclosureRecordState::Retired
                | crate::ScanDisclosureRecordState::Superseded => {
                    return Err(OrsError::IntegrityProblem {
                        record_type: crate::SCAN_DISCLOSURE_RECORD_TYPE,
                        reason: "a retired scan disclosure record never recommits".to_owned(),
                    });
                }
            }
        };
        write.commit().map_err(storage)?;
        Ok(Some(committed))
    }

    /// Loads one scan disclosure record by exact operation key (issue #2900).
    ///
    /// The stored receipt bytes are re-hashed against their digest on every
    /// read: a digest mismatch fails closed as corruption instead of
    /// returning foreign bytes as a completed receipt. Returns `Ok(None)`
    /// for an unknown key.
    pub fn load_scan_disclosure(
        &self,
        operation_key: &str,
    ) -> Result<Option<crate::ScanDisclosureOrsRecord>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(SCAN_DISCLOSURE_RECORDS).map_err(storage)?;
        table
            .get(operation_key)
            .map_err(storage)?
            .map(|value| {
                let record: crate::ScanDisclosureOrsRecord = decode(value.value())?;
                record.validate()?;
                if record.operation_key != operation_key {
                    return Err(OrsError::IntegrityProblem {
                        record_type: crate::SCAN_DISCLOSURE_RECORD_TYPE,
                        reason: "scan disclosure record key does not match its row".to_owned(),
                    });
                }
                if crate::model::sha256_hex(record.receipt_bytes.as_bytes())
                    != record.receipt_digest
                {
                    return Err(OrsError::IntegrityProblem {
                        record_type: crate::SCAN_DISCLOSURE_RECORD_TYPE,
                        reason: "stored scan receipt bytes do not match their digest".to_owned(),
                    });
                }
                Ok(record)
            })
            .transpose()
    }

    /// Retires one committed scan disclosure record under an explicit policy
    /// (issue #2900).
    ///
    /// Retirement only marks: the row stays addressable as historical
    /// evidence and is never deleted. A `Prepared` row cannot retire
    /// (reconcile it first); an already-retired row replays only under the
    /// same policy. Returns `Ok(None)` for an unknown key.
    pub fn retire_scan_disclosure(
        &self,
        operation_key: &str,
        request_hash: &str,
        policy_revision: u64,
        successor_ref: Option<&str>,
    ) -> Result<Option<crate::ScanDisclosureOrsRecord>, OrsError> {
        crate::model::validate_text(operation_key, "scan_disclosure_operation_key")?;
        crate::model::validate_digest(request_hash, "scan_disclosure_request_hash")?;
        if policy_revision == 0 {
            return Err(OrsError::InvalidField {
                field: "scan_disclosure_policy_revision",
                reason: "policy revision must be non-zero",
            });
        }
        if let Some(successor) = successor_ref {
            crate::model::validate_text(successor, "scan_disclosure_supersedes_ref")?;
        }
        let write = self.database.begin_write().map_err(storage)?;
        let retired = {
            let mut table = write.open_table(SCAN_DISCLOSURE_RECORDS).map_err(storage)?;
            let staged_bytes = table
                .get(operation_key)
                .map_err(storage)?
                .map(|value| value.value().to_owned());
            let Some(bytes) = staged_bytes else {
                drop(table);
                write.commit().map_err(storage)?;
                return Ok(None);
            };
            let mut next: crate::ScanDisclosureOrsRecord = decode(&bytes)?;
            next.validate()?;
            if next.request_hash != request_hash {
                return Err(OrsError::IntegrityProblem {
                    record_type: crate::SCAN_DISCLOSURE_RECORD_TYPE,
                    reason: "scan disclosure retirement binds a different request hash".to_owned(),
                });
            }
            match next.state {
                crate::ScanDisclosureRecordState::Prepared => {
                    return Err(OrsError::InvalidField {
                        field: "scan_disclosure_state",
                        reason: "a prepared scan disclosure record reconciles before it retires",
                    });
                }
                crate::ScanDisclosureRecordState::Committed => {
                    next.state = if successor_ref.is_some() {
                        crate::ScanDisclosureRecordState::Superseded
                    } else {
                        crate::ScanDisclosureRecordState::Retired
                    };
                    next.supersedes_ref = successor_ref.map(str::to_owned);
                    next.retired_by_policy = Some(policy_revision);
                    next.validate()?;
                    let payload = encode(&next)?;
                    table
                        .insert(operation_key, payload.as_str())
                        .map_err(storage)?;
                    next
                }
                crate::ScanDisclosureRecordState::Retired
                | crate::ScanDisclosureRecordState::Superseded => {
                    if next.retired_by_policy != Some(policy_revision) {
                        return Err(OrsError::IntegrityProblem {
                            record_type: crate::SCAN_DISCLOSURE_RECORD_TYPE,
                            reason: "scan disclosure retirement policy conflicts".to_owned(),
                        });
                    }
                    next
                }
            }
        };
        write.commit().map_err(storage)?;
        Ok(Some(retired))
    }

    /// Lists scan disclosure records for one installation, oldest first,
    /// bounded by `limit` (issue #2900).
    ///
    /// Historical evidence stays addressable under retention policy: this is
    /// the bounded read new scans never mutate. Every returned row is
    /// validated before it leaves the store.
    pub fn list_scan_disclosures(
        &self,
        installation_id: &str,
        limit: u16,
    ) -> Result<Vec<crate::ScanDisclosureOrsRecord>, OrsError> {
        crate::model::validate_text(installation_id, "scan_disclosure_installation_id")?;
        if limit == 0 || limit > crate::MAX_SCAN_DISCLOSURE_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(SCAN_DISCLOSURE_RECORDS).map_err(storage)?;
        let mut records = Vec::new();
        for entry in table.iter().map_err(storage)? {
            let (_, value) = entry.map_err(storage)?;
            let record: crate::ScanDisclosureOrsRecord = decode(value.value())?;
            record.validate()?;
            if record.installation_id == installation_id {
                records.push(record);
            }
            if records.len() >= usize::from(limit) {
                break;
            }
        }
        records.sort_by(|left, right| left.operation_key.cmp(&right.operation_key));
        Ok(records)
    }

    /// Loads one durable `backup.verify` result by exact idempotency key
    /// (I14.21 readback, issue #2802).
    /// Loads one durable `backup.verify` result by exact durable row key
    /// (I14.21 readback, issue #2802, rescoped by #2883).
    ///
    /// The row key is a *byte key*, not an identity. Both production callers pass
    /// a 64-hex digest: the fresh-verify path passes the presented identity's own
    /// [`BackupVerificationResultRecord::record_key`], and the reconciliation path
    /// deliberately passes the *presented* `predecessor_namespace_digest`, so the
    /// route never has to compute a key for an operation it did not run. The
    /// parameter name is retained for that caller-supplied value, which is a
    /// digest and not caller text.
    ///
    /// The stored row is re-validated through the same ORS codec every sibling
    /// reader uses — `decode` runs the record's `PersistedValue::validate_persisted`,
    /// which for this record IS `validate()` — so a row whose own digests or owner
    /// spellings no longer hold is an integrity failure rather than a replayable
    /// answer, and a second explicit `validate()` here would be redundant.
    ///
    /// It additionally asserts that the decoded row's OWN key is the key it was
    /// read under, the way the sibling readers in this file do. That is strictly
    /// stronger than a shape check: it catches a row filed under a key that is not
    /// its own, which on this family would otherwise let a caller-presented digest
    /// address a row belonging to a different operation. `Ok(None)` means nothing
    /// is stored under that key; it is not an unknown answer, and a caller must not
    /// treat it as one.
    ///
    /// This reader is NOT the legacy/quarantine probe and must not be pointed at
    /// raw caller text: a pre-#2883 row cannot decode under the current contract,
    /// so it would surface as an integrity error rather than a typed legacy
    /// refusal. Use
    /// [`RedbRecoveryStore::legacy_unscoped_backup_verification_class`] for that
    /// question.
    pub fn load_backup_verification_result(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<BackupVerificationResultRecord>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read
            .open_table(BACKUP_VERIFICATION_RESULTS)
            .map_err(storage)?;
        table
            .get(idempotency_key)
            .map_err(storage)?
            .map(|value| {
                let record: BackupVerificationResultRecord = decode(value.value())?;
                if record.record_key()? != idempotency_key {
                    return Err(OrsError::IntegrityProblem {
                        record_type: BACKUP_VERIFICATION_RESULT_RECORD_TYPE,
                        reason: "table key does not match the row's own namespace digest"
                            .to_owned(),
                    });
                }
                Ok(record)
            })
            .transpose()
    }

    /// Classifies a raw caller key against the pre-#2883 legacy shape
    /// (instruction 9: legacy rows are quarantined, never certified or re-keyed).
    ///
    /// The probe exists for exactly one reason: a durable row under the caller's
    /// own text must be neither silently ignored nor silently adopted. Silently
    /// ignoring it would leave a caller re-running a key that already has a
    /// stored answer with no explanation, and silently adopting it would certify an
    /// answer that carries no principal, session, scope or fence ownership to the
    /// first caller who asks after an upgrade.
    ///
    /// It returns one of three classes, and the caller must honour all three
    /// differently — that is what makes the probe fail CLOSED rather than fail
    /// open: [`LegacyUnscopedBackupVerificationClass::Absent`] means the key is
    /// free and a fresh scoped row may be staged;
    /// [`LegacyUnscopedBackupVerificationClass::Legacy`] means pre-#2883 evidence
    /// that must be quarantined, never certified, re-keyed or projected; and
    /// [`LegacyUnscopedBackupVerificationClass::Unreadable`] means bytes are there
    /// that are neither shape, so NO verification result may be answered at all —
    /// staging over an unreadable row would destroy evidence and answer `ok` for a
    /// verification whose prior answer is still on disk.
    ///
    /// It returns `Legacy` only for the pre-#2883 shape, whose key was the
    /// caller's own text: a current-contract row carries a nested `identity` and no
    /// `idempotency_key` at all, and this is the ONLY path that produces the legacy
    /// class — a staged key is always a 64-hex namespace digest, so staging can
    /// never be where a legacy row is found. Nothing is migrated, re-keyed,
    /// backfilled or returned.
    pub fn legacy_unscoped_backup_verification_class(
        &self,
        idempotency_key: &str,
    ) -> Result<LegacyUnscopedBackupVerificationClass, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read
            .open_table(BACKUP_VERIFICATION_RESULTS)
            .map_err(storage)?;
        let Some(bytes) = table
            .get(idempotency_key)
            .map_err(storage)?
            .map(|value| value.value().to_owned())
        else {
            return Ok(LegacyUnscopedBackupVerificationClass::Absent);
        };
        Ok(crate::classify_backup_verification_key(
            &bytes,
            idempotency_key,
        ))
    }
    /// Stages one durable `backup.verify` result under its scoped namespace key.
    ///
    /// Persist-before-answer: the row is committed before the route answers, so a
    /// lost response reconciles to this same persisted result instead of
    /// re-deriving a differently-fenced one (I14.21). That reconcile is possible
    /// only because the durable key does not move: a lost response, a reconnect, a
    /// module re-registration and an Authority Epoch rotation all leave
    /// `record_key()` unchanged, so the retry addresses the row that was already
    /// committed instead of staging a second one under a different key.
    ///
    /// The durable key is [`BackupVerificationResultRecord::record_key`], the
    /// 64-hex namespace digest over principal, authority lineage, operation id and
    /// the four profile constants; its preimage is enumerated in exactly one place,
    /// [`BackupVerifyRequestIdentity::namespace_digest`]. Two principals who picked
    /// the same human idempotency text therefore can never reach each other's row.
    /// There is no in-band installation component: a row is only ever read out of
    /// one installation's ORS file, structurally, because that file owns it.
    ///
    /// The three outcomes are answers, not faults:
    /// - [`BackupVerificationDisposition::Stored`] — this candidate is now the
    ///   durable row.
    /// - [`BackupVerificationDisposition::AlreadyBound`] — an equal
    ///   `same_binding` canonical-request-hash match; the durable winner decides
    ///   the reply.
    /// - [`BackupVerificationDisposition::ForeignOperation`] — a row occupies this
    ///   key but its stored `principal` or `scope_id` differs from the candidate's.
    ///   Reach this on an ORDINARY, uncorrupted row: `scope_id` is NOT a key
    ///   component, so two sessions of one principal on one lineage with one
    ///   `operation_id` and one archive but different `WorkScope`s share one key,
    ///   and on a load-then-stage race the second writer reads the first's row here.
    ///   A different PRINCIPAL at the same key would be a SHA-256 collision and is
    ///   not reachable through the route. The existing row is NOT read back and NOT
    ///   returned, so no foreign projection leaves the store either way.
    ///
    /// There is deliberately no legacy class on this path, and no variant to
    /// carry one: a pre-#2883 row's key was caller text, so it cannot sit at a
    /// 64-hex staged key except in the corner where a pre-#2883 caller happened to
    /// choose a 64-hex idempotency key, and that row falls through to
    /// [`OrsError::IntegrityProblem`] and fails closed rather than being adopted.
    /// The legacy class is a LOAD-time classification in a different type,
    /// [`LegacyUnscopedBackupVerificationClass`], returned by
    /// [`RedbRecoveryStore::legacy_unscoped_backup_verification_class`].
    ///
    /// A row that is not a decodable current-contract row is still
    /// [`OrsError::IntegrityProblem`]: fail closed rather than classify corruption.
    pub fn stage_backup_verification_result(
        &self,
        record: &BackupVerificationResultRecord,
    ) -> Result<BackupVerificationDisposition, OrsError> {
        record.validate()?;
        let write = self.database.begin_write().map_err(storage)?;
        let key = record.record_key()?;
        let disposition = {
            let mut table = write
                .open_table(BACKUP_VERIFICATION_RESULTS)
                .map_err(storage)?;
            let staged_bytes = table
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| value.value().to_owned());
            let Some(bytes) = staged_bytes else {
                let payload = encode(record)?;
                table
                    .insert(key.as_str(), payload.as_str())
                    .map_err(storage)?;
                drop(table);
                write.commit().map_err(storage)?;
                return Ok(BackupVerificationDisposition::Stored);
            };
            // A pre-#2883 shape cannot deserialize into the current record, so the
            // two shapes are read separately instead of one being coerced into the
            // other. `decode` would fold a legacy row into `IntegrityProblem`,
            // which is what this path deliberately does with one.
            match serde_json::from_str::<BackupVerificationResultRecord>(&bytes) {
                Ok(existing) => {
                    existing.validate()?;
                    if existing.same_binding(record) {
                        BackupVerificationDisposition::AlreadyBound(Box::new(existing))
                    } else if existing.foreign_to(record) {
                        BackupVerificationDisposition::ForeignOperation
                    } else {
                        return Err(OrsError::IntegrityProblem {
                            record_type: BACKUP_VERIFICATION_RESULT_RECORD_TYPE,
                            reason: "existing backup-verification binding conflicts".to_owned(),
                        });
                    }
                }
                Err(_) => {
                    return Err(OrsError::IntegrityProblem {
                        record_type: BACKUP_VERIFICATION_RESULT_RECORD_TYPE,
                        reason: "existing backup-verification row is not readable under the current contract"
                            .to_owned(),
                    });
                }
            }
        };
        write.commit().map_err(storage)?;
        Ok(disposition)
    }

    /// Stages one P-04 host-request operation before any acknowledgement.
    ///
    /// Persist-before-ack: the `Requested` record is durably inserted before
    /// the caller may acknowledge admission or route the request. An exact
    /// replay under the same operation/request identity returns the durable
    /// record unchanged with its current state and result; a changed payload
    /// or binding under the same identity fails with
    /// [`OrsError::HostRequestIdentityConflict`].
    pub fn stage_host_request(
        &self,
        record: &crate::HostRequestRecord,
    ) -> Result<crate::HostRequestRecord, OrsError> {
        record.validate()?;
        if record.state != crate::HostRequestState::Requested {
            return Err(OrsError::InvalidField {
                field: "host_request_state",
                reason: "staging requires the requested state",
            });
        }
        let write = self.database.begin_write().map_err(storage)?;
        let staged = Self::stage_host_request_in(&write, record)?;
        write.commit().map_err(storage)?;
        Ok(staged)
    }

    /// Stages one validated `Requested` host-request row inside the caller's
    /// write transaction and returns the durable winner: the existing row on
    /// an exact replay, the candidate on a first stage. A changed binding
    /// under the same operation/request identity fails with
    /// [`OrsError::HostRequestIdentityConflict`]. Shared by
    /// [`Self::stage_host_request`] and
    /// [`Self::resolve_or_stage_host_request`] so the logical-key claim and
    /// the operation row always commit atomically.
    fn stage_host_request_in(
        write: &redb::WriteTransaction,
        record: &crate::HostRequestRecord,
    ) -> Result<crate::HostRequestRecord, OrsError> {
        let mut table = write.open_table(HOST_REQUESTS).map_err(storage)?;
        let key = record.record_key();
        if let Some(existing) = table.get(key.as_str()).map_err(storage)? {
            let existing: crate::HostRequestRecord = decode(existing.value())?;
            existing.validate()?;
            if !existing.same_binding(record) {
                return Err(OrsError::HostRequestIdentityConflict {
                    operation_id: record.operation_id.as_str().to_owned(),
                    request_digest: record.request_digest.clone(),
                });
            }
            Ok(existing)
        } else {
            let payload = encode(record)?;
            table
                .insert(key.as_str(), payload.as_str())
                .map_err(storage)?;
            Ok(record.clone())
        }
    }

    /// Loads one host-request operation by exact operation/request identity.
    pub fn load_host_request(
        &self,
        operation_id: &crate::OperationIdentity,
        request_digest: &str,
    ) -> Result<Option<crate::HostRequestRecord>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(HOST_REQUESTS).map_err(storage)?;
        let key = format!("{}::{}", operation_id.as_str(), request_digest);
        table
            .get(key.as_str())
            .map_err(storage)?
            .map(|value| {
                let record: crate::HostRequestRecord = decode(value.value())?;
                record.validate()?;
                Ok(record)
            })
            .transpose()
    }

    /// Derives the canonical logical key for one host-request record
    /// (issue #2571: the admitted correlation namespace).
    ///
    /// The key binds, in order: the fixed owner namespace
    /// (`eliot.host-request.logical.v1`), the closed request kind, the
    /// Kernel-issued session continuity, the stable client occurrence, the
    /// parent operation (or the explicit unbound marker), the task/scope
    /// binding (or the explicit admitted-unbound marker — recovery preserves
    /// an old task binding but never silently rebinds it), the capability,
    /// and the payload commitment. Connection, deadline, fence, epoch, and
    /// generation are transport/era binding and are never key material: the
    /// recovery transport carries its own current identity while the
    /// recovered operation keeps its original one. Only `Invocation` and
    /// `Cancellation` kinds are indexable; every other kind, and any record
    /// without a Kernel-issued session, yields `Ok(None)` and fails closed
    /// at the resolve entry instead of staging anonymously.
    ///
    /// The Bridge derives the identical key from its envelope fields; the
    /// canonical component order, separator, markers, and digest are part of
    /// the shared recovery contract and must change on both sides together.
    pub fn host_request_logical_key_for_record(
        record: &crate::HostRequestRecord,
    ) -> Result<Option<String>, OrsError> {
        if !matches!(
            record.kind,
            crate::HostRequestKind::Invocation | crate::HostRequestKind::Cancellation
        ) {
            return Ok(None);
        }
        let Some(session) = record.session_ref.as_ref() else {
            return Ok(None);
        };
        record.validate()?;
        Self::host_request_logical_key(
            record.kind,
            session.as_str(),
            record.request_id.as_str(),
            record.parent_operation_id.as_ref().map(OpaqueLabel::as_str),
            record.task_ref.as_ref().map(OpaqueLabel::as_str),
            record.scope_ref.as_ref().map(OpaqueLabel::as_str),
            record.capability_ref.as_str(),
            record.payload_digest.as_str(),
        )
        .map(Some)
    }

    /// Atomically claims one logical host-request key or returns its durable
    /// winner (issue #2571).
    ///
    /// One owner write transaction holds both the logical-key claim and the
    /// operation row: concurrent Bridges resolving a missing key converge on
    /// one record because the second writer observes the first writer's
    /// commit — a read-then-insert sequence without this transaction would be
    /// insufficient. Same key and same logical commitment returns the winner
    /// unchanged; a different tool, payload, or incompatible semantic
    /// binding fails with [`OrsError::HostRequestIdentityConflict`] carrying
    /// the winner's identity. The candidate keeps its own current transport
    /// binding; only the winner's original identity is ever returned. Failed
    /// or uncertain persistence is `Err`, never absence.
    pub fn resolve_or_stage_host_request(
        &self,
        record: &crate::HostRequestRecord,
    ) -> Result<crate::HostRequestRecord, OrsError> {
        record.validate()?;
        if record.state != crate::HostRequestState::Requested {
            return Err(OrsError::InvalidField {
                field: "host_request_state",
                reason: "logical resolution stages the requested state",
            });
        }
        let logical_key =
            Self::host_request_logical_key_for_record(record)?.ok_or(OrsError::InvalidField {
                field: "host_request_logical_key",
                reason: "only session-bound invocation and cancellation records carry a logical key",
            })?;
        let write = self.database.begin_write().map_err(storage)?;
        let outcome = {
            let mut links = write
                .open_table(HOST_REQUEST_LOGICAL_KEYS)
                .map_err(storage)?;
            if let Some(link_value) = links.get(logical_key.as_str()).map_err(storage)? {
                let link: HostRequestLogicalLink = decode(link_value.value())?;
                let winner = {
                    let operations = write.open_table(HOST_REQUESTS).map_err(storage)?;
                    let row_key =
                        format!("{}::{}", link.operation_id.as_str(), link.request_digest);
                    operations
                        .get(row_key.as_str())
                        .map_err(storage)?
                        .map(|value| {
                            let winner: crate::HostRequestRecord = decode(value.value())?;
                            winner.validate()?;
                            Ok::<_, OrsError>(winner)
                        })
                        .transpose()?
                        .ok_or_else(|| OrsError::IntegrityProblem {
                            record_type: "host_request_logical_link",
                            reason: "logical link points at a missing host-request row".to_owned(),
                        })?
                };
                let winner_key =
                    Self::host_request_logical_key_for_record(&winner)?.ok_or_else(|| {
                        OrsError::IntegrityProblem {
                            record_type: "host_request_logical_link",
                            reason: "linked host-request row carries no logical key".to_owned(),
                        }
                    })?;
                if winner_key != logical_key
                    || !Self::host_requests_share_logical_commitment(&winner, record)
                {
                    return Err(OrsError::HostRequestIdentityConflict {
                        operation_id: winner.operation_id.as_str().to_owned(),
                        request_digest: winner.request_digest.clone(),
                    });
                }
                winner
            } else {
                let staged = Self::stage_host_request_in(&write, record)?;
                let link = HostRequestLogicalLink {
                    operation_id: staged.operation_id.clone(),
                    request_digest: staged.request_digest.clone(),
                };
                let payload = encode(&link)?;
                links
                    .insert(logical_key.as_str(), payload.as_str())
                    .map_err(storage)?;
                staged
            }
        };
        write.commit().map_err(storage)?;
        Ok(outcome)
    }

    /// Loads one host-request operation by logical key (issue #2571).
    ///
    /// `Ok(None)` is authoritatively absent: no operation was ever staged
    /// under this key in this store. Pre-index legacy rows are never
    /// inferred and stay reachable only by exact operation/request identity.
    /// A dangling or divergent link fails closed as an integrity problem;
    /// storage failure fails closed as storage — neither can become absence
    /// or authorize a fresh operation.
    pub fn load_host_request_by_logical_key(
        &self,
        logical_key: &str,
    ) -> Result<Option<crate::HostRequestRecord>, OrsError> {
        crate::model::validate_digest(logical_key, "host_request_logical_key")?;
        let read = self.database.begin_read().map_err(storage)?;
        let link: Option<HostRequestLogicalLink> = {
            let links = read
                .open_table(HOST_REQUEST_LOGICAL_KEYS)
                .map_err(storage)?;
            links
                .get(logical_key)
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
        };
        let Some(link) = link else {
            return Ok(None);
        };
        let operations = read.open_table(HOST_REQUESTS).map_err(storage)?;
        let row_key = format!("{}::{}", link.operation_id.as_str(), link.request_digest);
        let record: crate::HostRequestRecord = operations
            .get(row_key.as_str())
            .map_err(storage)?
            .map(|value| decode(value.value()))
            .transpose()?
            .ok_or_else(|| OrsError::IntegrityProblem {
                record_type: "host_request_logical_link",
                reason: "logical link points at a missing host-request row".to_owned(),
            })?;
        record.validate()?;
        let recomputed = Self::host_request_logical_key_for_record(&record)?.ok_or_else(|| {
            OrsError::IntegrityProblem {
                record_type: "host_request_logical_link",
                reason: "linked host-request row carries no logical key".to_owned(),
            }
        })?;
        if recomputed != logical_key {
            return Err(OrsError::IntegrityProblem {
                record_type: "host_request_logical_link",
                reason: "logical link diverges from its host-request row".to_owned(),
            });
        }
        Ok(Some(record))
    }

    /// Returns the closed kind marker carried in every logical key.
    const fn host_request_kind_marker(kind: crate::HostRequestKind) -> &'static str {
        match kind {
            crate::HostRequestKind::Activation => "activation",
            crate::HostRequestKind::Invocation => "invocation",
            crate::HostRequestKind::Cancellation => "cancellation",
            crate::HostRequestKind::Status => "status",
            crate::HostRequestKind::Reconciliation => "reconciliation",
        }
    }

    /// Encodes one canonical logical key and returns its SHA-256.
    ///
    /// Components are joined with a control separator that validated text
    /// can never contain, then digested to a fixed-size key: no separator
    /// injection is possible, and the digest reveals no task or payload
    /// content. A presented `-` value is rejected so real bindings can never
    /// collide with the explicit unbound marker.
    #[allow(
        clippy::too_many_arguments,
        reason = "the logical key binds every commitment component explicitly so no binding is implicit at the call site"
    )]
    fn host_request_logical_key(
        kind: crate::HostRequestKind,
        session: &str,
        occurrence: &str,
        parent: Option<&str>,
        task: Option<&str>,
        scope: Option<&str>,
        capability: &str,
        payload_digest: &str,
    ) -> Result<String, OrsError> {
        const FIELD: &str = "host_request_logical_key";
        for component in [session, occurrence, capability] {
            crate::model::validate_text(component, FIELD)?;
        }
        for component in [parent, task, scope].into_iter().flatten() {
            crate::model::validate_text(component, FIELD)?;
        }
        crate::model::validate_digest(payload_digest, FIELD)?;
        for component in [session, occurrence, capability]
            .into_iter()
            .chain([parent, task, scope].into_iter().flatten())
        {
            if component == HOST_REQUEST_UNBOUND_MARKER {
                return Err(OrsError::InvalidField {
                    field: FIELD,
                    reason: "logical key components must not equal the unbound marker",
                });
            }
        }
        let unbound = HOST_REQUEST_UNBOUND_MARKER;
        let text = format!(
            "{namespace}\x1fkind={kind}\x1fsession={session}\x1foccurrence={occurrence}\x1fparent={parent}\x1ftask={task}\x1fscope={scope}\x1fcapability={capability}\x1fpayload={payload_digest}",
            namespace = HOST_REQUEST_LOGICAL_NAMESPACE,
            kind = Self::host_request_kind_marker(kind),
            parent = parent.unwrap_or(unbound),
            task = task.unwrap_or(unbound),
            scope = scope.unwrap_or(unbound),
        );
        Ok(crate::model::sha256_hex(text.as_bytes()))
    }

    /// Returns whether two records carry the same logical commitment.
    ///
    /// Compared: kind, occurrence, idempotency and cancellation derivation,
    /// parent, session/task/scope binding, capability, and payload digest.
    /// Excluded: the envelope digest, connection, absolute deadline, fence,
    /// epoch, and generation (transport/era binding that legitimately
    /// changes across restart — authority stays with the admission gate),
    /// plus ORS-owned progression (state, result, commit order).
    fn host_requests_share_logical_commitment(
        left: &crate::HostRequestRecord,
        right: &crate::HostRequestRecord,
    ) -> bool {
        left.kind == right.kind
            && left.request_id == right.request_id
            && left.idempotency_key == right.idempotency_key
            && left.cancellation_id == right.cancellation_id
            && left.parent_operation_id == right.parent_operation_id
            && left.session_ref == right.session_ref
            && left.task_ref == right.task_ref
            && left.scope_ref == right.scope_ref
            && left.capability_ref == right.capability_ref
            && left.payload_digest == right.payload_digest
    }

    /// Validates every logical link against its operation row (issue #2571).
    ///
    /// Each index entry must decode, point at an existing validated row, and
    /// recompute to its own index key. A dangling, divergent, or
    /// unindexable link fails closed as an integrity problem: links are
    /// never repaired by choosing a latest row, and pre-index rows without
    /// links are legacy, not damage, so they are skipped rather than
    /// backfilled — migration never infers namespace or continuity.
    fn validate_host_request_logical_index(write: &redb::WriteTransaction) -> Result<(), OrsError> {
        let links = write
            .open_table(HOST_REQUEST_LOGICAL_KEYS)
            .map_err(storage)?;
        let mut pending = Vec::new();
        for entry in links.iter().map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let link: HostRequestLogicalLink = decode(value.value())?;
            pending.push((key.value().to_owned(), link));
        }
        drop(links);
        let operations = write.open_table(HOST_REQUESTS).map_err(storage)?;
        for (key, link) in pending {
            let row_key = format!("{}::{}", link.operation_id.as_str(), link.request_digest);
            let record: crate::HostRequestRecord = operations
                .get(row_key.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
                .ok_or_else(|| OrsError::IntegrityProblem {
                    record_type: "host_request_logical_link",
                    reason: "logical link points at a missing host-request row".to_owned(),
                })?;
            record.validate()?;
            let recomputed =
                Self::host_request_logical_key_for_record(&record)?.ok_or_else(|| {
                    OrsError::IntegrityProblem {
                        record_type: "host_request_logical_link",
                        reason: "linked host-request row carries no logical key".to_owned(),
                    }
                })?;
            if recomputed != key {
                return Err(OrsError::IntegrityProblem {
                    record_type: "host_request_logical_link",
                    reason: "logical link diverges from its host-request row".to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Durably stages one pending activation ticket before it is published in
    /// memory or returned to a daemon claim.
    pub fn stage_activation_ticket(
        &self,
        record: &ActivationLifecycleRecord,
        now_unix_ms: u64,
    ) -> Result<ActivationLifecycleRecord, OrsError> {
        self.stage_activation_ticket_with_protection(record, now_unix_ms, &BTreeSet::new())
            .map(|(staged, _)| staged)
    }

    /// Stages one ticket while protecting live Kernel waiters from bounded
    /// retention pruning and returns every durable identity evicted by the
    /// same transaction. The returned list is the only safe way for a cache
    /// to mirror the ORS projection; it is never an authority decision.
    ///
    /// Lifecycle identity, successor binding, and capacity pruning all stay in
    /// one ORS write transaction: this entry owns that transaction, and the
    /// private steps below are ordinary calls on the very same
    /// `WriteTransaction`, so a partially staged ticket is never observable.
    pub fn stage_activation_ticket_with_protection(
        &self,
        record: &ActivationLifecycleRecord,
        now_unix_ms: u64,
        protected_ticket_ids: &BTreeSet<String>,
    ) -> Result<(ActivationLifecycleRecord, Vec<String>), OrsError> {
        record.validate()?;
        if record.state != ActivationLifecycleState::Pending
            || record.lifecycle_order != 0
            || record.result_sha256.is_some()
            || record.claim_owner.is_some()
            || record.successor_ticket_id.is_some()
            || record.terminal_reason.is_some()
        {
            return Err(OrsError::InvalidField {
                field: "activation_lifecycle_stage",
                reason: "staging requires one clean pending ticket without result or claim",
            });
        }
        if now_unix_ms >= record.kernel_deadline_unix_ms {
            return Err(OrsError::ActivationLifecycleExpired {
                ticket_id: record.ticket_id.clone(),
            });
        }
        let write = self.database.begin_write().map_err(storage)?;
        let key = record.record_key().to_owned();
        let existing: Option<ActivationLifecycleRecord> = {
            let table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
            table
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
        };
        if let Some(existing) = existing {
            if !existing.same_immutable_identity(record) {
                return Err(OrsError::ActivationLifecycleIdentityConflict { ticket_id: key });
            }
            write.commit().map_err(storage)?;
            return Ok((existing, Vec::new()));
        }

        let mut evicted_ticket_ids = Vec::new();
        let mut lifecycle_rows = Self::read_activation_lifecycle_rows(&write)?;
        Self::reject_staged_activation_identity_reuse(&lifecycle_rows, record, &key)?;
        Self::prune_activation_lifecycle_capacity(
            &write,
            &mut lifecycle_rows,
            protected_ticket_ids,
            &mut evicted_ticket_ids,
        )?;
        let order = Self::next_operational_order(&write)?;
        Self::bind_staged_activation_predecessor(
            &write,
            &lifecycle_rows,
            record,
            now_unix_ms,
            order,
            &key,
        )?;
        let mut next = record.clone();
        next.lifecycle_order = order;
        next.validate()?;
        let payload = encode(&next)?;
        let mut table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
        table
            .insert(key.as_str(), payload.as_str())
            .map_err(storage)?;
        drop(table);
        write.commit().map_err(storage)?;
        Ok((next, evicted_ticket_ids))
    }

    /// Reads and validates every durable activation lifecycle row, refusing a
    /// table whose stored key does not match the ticket identity it holds.
    pub(super) fn read_activation_lifecycle_rows(
        write: &redb::WriteTransaction,
    ) -> Result<Vec<ActivationLifecycleRecord>, OrsError> {
        let mut lifecycle_rows = Vec::new();
        let table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
        for entry in table.iter().map_err(storage)? {
            let (existing_key, value) = entry.map_err(storage)?;
            let existing: ActivationLifecycleRecord = decode(value.value())?;
            if existing_key.value() != existing.record_key() {
                return Err(OrsError::IntegrityProblem {
                    record_type: "activation_lifecycle",
                    reason: "table key does not match ticket identity".to_owned(),
                });
            }
            existing.validate()?;
            lifecycle_rows.push(existing);
        }
        Ok(lifecycle_rows)
    }

    /// Refuses staging a ticket that reuses an activation request identity, or
    /// a predecessor ticket/result pair an existing row already bound as a
    /// successor. One activation request and one predecessor pair admit exactly
    /// one staged ticket.
    pub(super) fn reject_staged_activation_identity_reuse(
        lifecycle_rows: &[ActivationLifecycleRecord],
        record: &ActivationLifecycleRecord,
        key: &str,
    ) -> Result<(), OrsError> {
        if lifecycle_rows.iter().any(|existing| {
            existing.activation_request_id == record.activation_request_id
                || existing.successor_of.as_ref().is_some_and(|successor| {
                    record.successor_of.as_ref().is_some_and(|candidate| {
                        successor.predecessor_ticket_id == candidate.predecessor_ticket_id
                            && successor.predecessor_result_sha256
                                == candidate.predecessor_result_sha256
                    })
                })
        }) {
            return Err(OrsError::ActivationLifecycleIdentityConflict {
                ticket_id: key.to_owned(),
            });
        }
        Ok(())
    }

    /// Makes room for one staged ticket when the lifecycle table is already at
    /// its bound, evicting exactly one unprotected terminal row that carries no
    /// successor from both the lifecycle and result-retention tables. A ticket
    /// with nothing evictable is a refusal, never a silent overflow.
    pub(super) fn prune_activation_lifecycle_capacity(
        write: &redb::WriteTransaction,
        lifecycle_rows: &mut Vec<ActivationLifecycleRecord>,
        protected_ticket_ids: &BTreeSet<String>,
        evicted_ticket_ids: &mut Vec<String>,
    ) -> Result<(), OrsError> {
        if lifecycle_rows.len() < crate::MAX_ACTIVATION_LIFECYCLE_RECORDS {
            return Ok(());
        }
        let removable = lifecycle_rows
            .iter()
            .filter(|existing| {
                !protected_ticket_ids.contains(&existing.ticket_id)
                    && existing.successor_ticket_id.is_none()
                    && matches!(
                        existing.state,
                        ActivationLifecycleState::ResultAccepted
                            | ActivationLifecycleState::Cancelled
                            | ActivationLifecycleState::Expired
                    )
            })
            .min_by_key(|existing| existing.lifecycle_order)
            .cloned();
        let Some(removable) = removable else {
            return Err(OrsError::ProjectionLimitExceeded);
        };
        {
            let mut table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
            table.remove(removable.record_key()).map_err(storage)?;
        }
        {
            let mut table = write
                .open_table(ACTIVATION_RESULT_RETENTION)
                .map_err(storage)?;
            table.remove(removable.record_key()).map_err(storage)?;
        }
        evicted_ticket_ids.push(removable.ticket_id.clone());
        lifecycle_rows.retain(|existing| existing.ticket_id != removable.ticket_id);
        Ok(())
    }

    /// Binds one staged successor ticket to its exact durable predecessor and
    /// publishes the consumed predecessor, still inside the staging
    /// transaction. The predecessor must be a deferred, not-yet-consumed row
    /// whose retained result and ticket digest match the successor binding, and
    /// whose `not_before` gate has opened.
    pub(super) fn bind_staged_activation_predecessor(
        write: &redb::WriteTransaction,
        lifecycle_rows: &[ActivationLifecycleRecord],
        record: &ActivationLifecycleRecord,
        now_unix_ms: u64,
        order: u64,
        key: &str,
    ) -> Result<(), OrsError> {
        let Some(successor) = &record.successor_of else {
            return Ok(());
        };
        let predecessor = lifecycle_rows
            .iter()
            .find(|existing| existing.ticket_id == successor.predecessor_ticket_id)
            .ok_or_else(|| OrsError::ActivationLifecycleIdentityConflict {
                ticket_id: key.to_owned(),
            })?;
        if predecessor.state != ActivationLifecycleState::DeferredNotReady
            || predecessor.ticket_sha256 != successor.predecessor_ticket_sha256
            || predecessor.result_sha256.as_deref()
                != Some(successor.predecessor_result_sha256.as_str())
            || predecessor.successor_ticket_id.is_some()
            || now_unix_ms < successor.not_before_unix_ms
        {
            return Err(OrsError::ActivationLifecycleIdentityConflict {
                ticket_id: key.to_owned(),
            });
        }
        let mut updated_predecessor = predecessor.clone();
        updated_predecessor.successor_ticket_id = Some(record.ticket_id.clone());
        updated_predecessor.lifecycle_order = order;
        updated_predecessor.validate()?;
        let predecessor_key = updated_predecessor.record_key().to_owned();
        let payload = encode(&updated_predecessor)?;
        let mut table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
        table
            .insert(predecessor_key.as_str(), payload.as_str())
            .map_err(storage)?;
        Ok(())
    }

    /// Claims one pending ticket for the authenticated daemon. An expired
    /// claim becomes durable reconciliation and is never silently reissued.
    pub fn claim_activation_ticket(
        &self,
        ticket_id: &str,
        claim_owner: &str,
        now_unix_ms: u64,
        claim_expires_at_unix_ms: u64,
    ) -> Result<Option<ActivationLifecycleRecord>, OrsError> {
        crate::model::validate_text(ticket_id, "activation_claim_ticket_id")?;
        crate::model::validate_text(claim_owner, "activation_claim_owner")?;
        if claim_expires_at_unix_ms <= now_unix_ms {
            return Err(OrsError::InvalidField {
                field: "activation_claim_expiry",
                reason: "claim expiry must be later than the admission time",
            });
        }
        let write = self.database.begin_write().map_err(storage)?;
        let existing: Option<ActivationLifecycleRecord> = {
            let table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
            table
                .get(ticket_id)
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
        };
        let Some(mut existing) = existing else {
            write.commit().map_err(storage)?;
            return Ok(None);
        };
        if existing.state == ActivationLifecycleState::Claimed {
            if existing.claim_owner.as_deref() == Some(claim_owner)
                && existing.claim_expires_at_unix_ms == Some(claim_expires_at_unix_ms)
                && existing
                    .claim_expires_at_unix_ms
                    .is_some_and(|expiry| expiry > now_unix_ms)
            {
                write.commit().map_err(storage)?;
                return Ok(Some(existing));
            }
            let mut reconciling = existing;
            reconciling.state = ActivationLifecycleState::Reconciling;
            reconciling.claim_owner = None;
            reconciling.claim_expires_at_unix_ms = None;
            reconciling.lifecycle_order = Self::next_operational_order(&write)?;
            reconciling.terminal_reason =
                Some("claim lease elapsed or ownership changed before result admission".to_owned());
            reconciling.validate()?;
            let payload = encode(&reconciling)?;
            let mut table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
            table
                .insert(reconciling.record_key(), payload.as_str())
                .map_err(storage)?;
            drop(table);
            write.commit().map_err(storage)?;
            return Err(OrsError::ActivationLifecycleStateConflict {
                ticket_id: ticket_id.to_owned(),
                state: ActivationLifecycleState::Reconciling,
                expected: ActivationLifecycleState::Pending,
            });
        }
        if existing.state != ActivationLifecycleState::Pending {
            return Err(OrsError::ActivationLifecycleStateConflict {
                ticket_id: ticket_id.to_owned(),
                state: existing.state,
                expected: ActivationLifecycleState::Pending,
            });
        }
        if now_unix_ms >= existing.kernel_deadline_unix_ms {
            existing.state = ActivationLifecycleState::Expired;
            existing.lifecycle_order = Self::next_operational_order(&write)?;
            existing.terminal_reason = Some("deadline elapsed before durable claim".to_owned());
            existing.validate()?;
            let payload = encode(&existing)?;
            let mut table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
            table
                .insert(existing.record_key(), payload.as_str())
                .map_err(storage)?;
            drop(table);
            write.commit().map_err(storage)?;
            return Err(OrsError::ActivationLifecycleExpired {
                ticket_id: ticket_id.to_owned(),
            });
        }
        existing.state = ActivationLifecycleState::Claimed;
        existing.claim_owner = Some(claim_owner.to_owned());
        existing.claim_expires_at_unix_ms = Some(claim_expires_at_unix_ms);
        existing.lifecycle_order = Self::next_operational_order(&write)?;
        existing.validate()?;
        let payload = encode(&existing)?;
        let mut table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
        table
            .insert(existing.record_key(), payload.as_str())
            .map_err(storage)?;
        drop(table);
        write.commit().map_err(storage)?;
        Ok(Some(existing))
    }

    /// Atomically inserts one result and advances the exact claimed lifecycle
    /// row. Result retention cannot exist without its lifecycle binding.
    pub fn commit_activation_result(
        &self,
        record: &ActivationResultRetentionRecord,
        claim_owner: &str,
        dependency_observation: Option<(&str, &str)>,
        now_unix_ms: u64,
    ) -> Result<ActivationResultRetentionRecord, OrsError> {
        self.commit_activation_result_with_protection(
            record,
            claim_owner,
            dependency_observation,
            now_unix_ms,
            &BTreeSet::new(),
        )
        .map(|(retained, _)| retained)
    }

    /// Commits one result while protecting live Kernel waiters and returns
    /// any bounded-retention identities evicted in the same transaction.
    ///
    /// Result admission, the deadline compare-and-set, lifecycle publication,
    /// and bounded-retention pruning all stay in one ORS write transaction:
    /// this entry owns that transaction, and the private steps below are
    /// ordinary calls on the very same `WriteTransaction`, so a result is never
    /// retained without its lifecycle publication.
    pub fn commit_activation_result_with_protection(
        &self,
        record: &ActivationResultRetentionRecord,
        claim_owner: &str,
        dependency_observation: Option<(&str, &str)>,
        now_unix_ms: u64,
        protected_ticket_ids: &BTreeSet<String>,
    ) -> Result<(ActivationResultRetentionRecord, Vec<String>), OrsError> {
        record.validate()?;
        crate::model::validate_text(claim_owner, "activation_result_claim_owner")?;
        if record.retention_order != 0 {
            return Err(OrsError::InvalidField {
                field: "activation_result_retention_order",
                reason: "caller-supplied retention order must be zero",
            });
        }
        let write = self.database.begin_write().map_err(storage)?;
        let key = record.record_key().to_owned();
        let existing_result: Option<ActivationResultRetentionRecord> = {
            let table = write
                .open_table(ACTIVATION_RESULT_RETENTION)
                .map_err(storage)?;
            table
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
        };
        let lifecycle: ActivationLifecycleRecord = {
            let table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
            let bytes = table.get(key.as_str()).map_err(storage)?.ok_or_else(|| {
                OrsError::ActivationLifecycleIdentityConflict {
                    ticket_id: key.clone(),
                }
            })?;
            let lifecycle: ActivationLifecycleRecord = decode(bytes.value())?;
            lifecycle.validate()?;
            drop(bytes);
            lifecycle
        };
        if lifecycle.ticket_sha256 != record.ticket_sha256
            || lifecycle.connection_id != record.connection_id
            || lifecycle.state_fence != record.state_fence
        {
            return Err(OrsError::ActivationLifecycleIdentityConflict { ticket_id: key });
        }
        if let Some(existing_result) = existing_result {
            if !existing_result.same_identity(record)
                || lifecycle.result_sha256.as_deref()
                    != Some(existing_result.result_sha256.as_str())
            {
                return Err(OrsError::ActivationResultRetentionIdentityConflict { ticket_id: key });
            }
            write.commit().map_err(storage)?;
            return Ok((existing_result, Vec::new()));
        }
        if lifecycle.state == ActivationLifecycleState::Claimed
            && lifecycle
                .claim_expires_at_unix_ms
                .is_some_and(|expiry| expiry <= now_unix_ms)
        {
            Self::reconcile_elapsed_activation_claim(write, lifecycle)?;
            return Err(OrsError::ActivationLifecycleStateConflict {
                ticket_id: key,
                state: ActivationLifecycleState::Reconciling,
                expected: ActivationLifecycleState::Claimed,
            });
        }
        if now_unix_ms >= lifecycle.kernel_deadline_unix_ms {
            Self::expire_activation_lifecycle_before_result(write, &lifecycle)?;
            return Err(OrsError::ActivationLifecycleExpired { ticket_id: key });
        }
        Self::require_claimed_activation_for_result(
            &lifecycle,
            claim_owner,
            dependency_observation,
            now_unix_ms,
            &key,
        )?;
        let (mut retained_rows, mut total_payload_bytes) =
            Self::read_activation_result_rows(&write)?;
        let mut lifecycle_rows = Self::read_activation_lifecycle_rows(&write)?;
        let evicted_ticket_ids = Self::prune_activation_result_capacity(
            &write,
            &mut retained_rows,
            &mut lifecycle_rows,
            &mut total_payload_bytes,
            record,
            protected_ticket_ids,
            &key,
        )?;
        let retained = Self::publish_activation_result_commit(&write, record, lifecycle)?;
        write.commit().map_err(storage)?;
        Ok((retained, evicted_ticket_ids))
    }

    /// Moves one claimed-but-expired-lease lifecycle to durable reconciliation
    /// before a result can be admitted against it. The caller hands over its
    /// write transaction: the reconciliation is committed here, and the caller
    /// returns the refusal without touching that transaction again. A result is
    /// never admitted against a claim this daemon no longer holds.
    pub(super) fn reconcile_elapsed_activation_claim(
        write: redb::WriteTransaction,
        lifecycle: ActivationLifecycleRecord,
    ) -> Result<(), OrsError> {
        let mut reconciling = lifecycle;
        reconciling.state = ActivationLifecycleState::Reconciling;
        reconciling.claim_owner = None;
        reconciling.claim_expires_at_unix_ms = None;
        reconciling.lifecycle_order = Self::next_operational_order(&write)?;
        reconciling.terminal_reason =
            Some("claim lease elapsed before durable result admission".to_owned());
        reconciling.validate()?;
        let payload = encode(&reconciling)?;
        let mut table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
        table
            .insert(reconciling.record_key(), payload.as_str())
            .map_err(storage)?;
        drop(table);
        write.commit().map_err(storage)
    }

    /// Publishes the durable deadline expiry for a result-less lifecycle. The
    /// caller hands over its write transaction, because publishing the expiry is
    /// itself the committed outcome of the refusal. A lifecycle that already
    /// carries a result, or has already left `Pending`/`Claimed`, is left
    /// exactly as it is: this returns without touching the transaction, so it
    /// aborts instead of committing, and the caller still returns the same
    /// deadline refusal either way.
    pub(super) fn expire_activation_lifecycle_before_result(
        write: redb::WriteTransaction,
        lifecycle: &ActivationLifecycleRecord,
    ) -> Result<(), OrsError> {
        if lifecycle.result_sha256.is_some()
            || !matches!(
                lifecycle.state,
                ActivationLifecycleState::Pending | ActivationLifecycleState::Claimed
            )
        {
            return Ok(());
        }
        let mut expired = lifecycle.clone();
        expired.state = ActivationLifecycleState::Expired;
        expired.claim_owner = None;
        expired.claim_expires_at_unix_ms = None;
        expired.lifecycle_order = Self::next_operational_order(&write)?;
        expired.terminal_reason =
            Some("deadline elapsed before durable result admission".to_owned());
        expired.validate()?;
        let payload = encode(&expired)?;
        let mut table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
        table
            .insert(expired.record_key(), payload.as_str())
            .map_err(storage)?;
        drop(table);
        write.commit().map_err(storage)
    }

    /// Requires that the lifecycle is still claimed by exactly this owner, and
    /// that a successor ticket presents a strictly newer observation of its own
    /// bound dependency after its `not_before` gate opened. A first-generation
    /// ticket presents no dependency observation at all.
    pub(super) fn require_claimed_activation_for_result(
        lifecycle: &ActivationLifecycleRecord,
        claim_owner: &str,
        dependency_observation: Option<(&str, &str)>,
        now_unix_ms: u64,
        key: &str,
    ) -> Result<(), OrsError> {
        if lifecycle.state != ActivationLifecycleState::Claimed
            || lifecycle.claim_owner.as_deref() != Some(claim_owner)
        {
            return Err(OrsError::ActivationLifecycleStateConflict {
                ticket_id: key.to_owned(),
                state: lifecycle.state,
                expected: ActivationLifecycleState::Claimed,
            });
        }
        match (lifecycle.successor_of.as_ref(), dependency_observation) {
            (None, None) => Ok(()),
            (Some(predecessor), Some((dependency_ref, observed_revision))) => {
                if dependency_ref != predecessor.dependency_ref
                    || observed_revision == predecessor.observed_dependency_revision
                    || now_unix_ms < predecessor.not_before_unix_ms
                {
                    return Err(OrsError::ActivationLifecycleIdentityConflict {
                        ticket_id: key.to_owned(),
                    });
                }
                Ok(())
            }
            _ => Err(OrsError::ActivationLifecycleIdentityConflict {
                ticket_id: key.to_owned(),
            }),
        }
    }

    /// Reads every durable result-retention row and its exact total payload
    /// size, refusing a size total that cannot be represented.
    pub(super) fn read_activation_result_rows(
        write: &redb::WriteTransaction,
    ) -> Result<(Vec<ActivationResultRetentionRecord>, usize), OrsError> {
        let mut retained_rows = Vec::new();
        {
            let table = write
                .open_table(ACTIVATION_RESULT_RETENTION)
                .map_err(storage)?;
            for entry in table.iter().map_err(storage)? {
                let (existing_key, value) = entry.map_err(storage)?;
                let existing: ActivationResultRetentionRecord = decode(value.value())?;
                if existing_key.value() != existing.record_key() {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "activation_result_retention",
                        reason: "table key does not match ticket identity".to_owned(),
                    });
                }
                retained_rows.push(existing);
            }
        }
        let total_payload_bytes = retained_rows.iter().try_fold(0usize, |total, row| {
            total
                .checked_add(row.payload_bytes())
                .ok_or_else(|| OrsError::IntegrityProblem {
                    record_type: "activation_result_retention",
                    reason: "retention payload size overflow".to_owned(),
                })
        })?;
        Ok((retained_rows, total_payload_bytes))
    }

    /// Makes bounded room for one more retained result, evicting the oldest
    /// unprotected accepted row that carries no successor from both the
    /// retention and lifecycle tables until the row count and total payload
    /// bounds both hold. The committed ticket itself is never its own eviction
    /// candidate, and a table with nothing evictable is a refusal.
    pub(super) fn prune_activation_result_capacity(
        write: &redb::WriteTransaction,
        retained_rows: &mut Vec<ActivationResultRetentionRecord>,
        lifecycle_rows: &mut Vec<ActivationLifecycleRecord>,
        total_payload_bytes: &mut usize,
        record: &ActivationResultRetentionRecord,
        protected_ticket_ids: &BTreeSet<String>,
        key: &str,
    ) -> Result<Vec<String>, OrsError> {
        let mut evicted_ticket_ids = Vec::new();
        while retained_rows.len() >= crate::MAX_ACTIVATION_RESULT_RETENTION_RECORDS
            || total_payload_bytes
                .checked_add(record.payload_bytes())
                .is_none_or(|total| total > crate::MAX_ACTIVATION_RESULT_TOTAL_PAYLOAD_BYTES)
        {
            let removable = lifecycle_rows
                .iter()
                .filter(|row| {
                    row.ticket_id != key
                        && !protected_ticket_ids.contains(&row.ticket_id)
                        && row.state == ActivationLifecycleState::ResultAccepted
                        && row.successor_ticket_id.is_none()
                })
                .min_by_key(|row| row.lifecycle_order)
                .map(|row| row.ticket_id.clone());
            let Some(removable_ticket_id) = removable else {
                return Err(OrsError::ProjectionLimitExceeded);
            };
            let Some(victim) = retained_rows
                .iter()
                .find(|row| row.ticket_id == removable_ticket_id)
            else {
                return Err(OrsError::ProjectionLimitExceeded);
            };
            *total_payload_bytes = total_payload_bytes.saturating_sub(victim.payload_bytes());
            retained_rows.retain(|row| row.ticket_id != removable_ticket_id);
            lifecycle_rows.retain(|row| row.ticket_id != removable_ticket_id);
            {
                let mut table = write
                    .open_table(ACTIVATION_RESULT_RETENTION)
                    .map_err(storage)?;
                table
                    .remove(removable_ticket_id.as_str())
                    .map_err(storage)?;
            }
            {
                let mut table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
                table
                    .remove(removable_ticket_id.as_str())
                    .map_err(storage)?;
            }
            evicted_ticket_ids.push(removable_ticket_id);
        }
        Ok(evicted_ticket_ids)
    }

    /// Publishes the retained result and the advanced lifecycle row in the
    /// caller's write transaction, allocating one shared operational order so
    /// the two projections advance as one durable step.
    pub(super) fn publish_activation_result_commit(
        write: &redb::WriteTransaction,
        record: &ActivationResultRetentionRecord,
        lifecycle: ActivationLifecycleRecord,
    ) -> Result<ActivationResultRetentionRecord, OrsError> {
        let order = Self::next_operational_order(write)?;
        let mut retained = record.clone();
        retained.retention_order = order;
        retained.validate()?;
        let mut next_lifecycle = lifecycle;
        next_lifecycle.state = match retained.phase {
            ActivationResultRetentionPhase::AcceptedTerminal => {
                ActivationLifecycleState::ResultAccepted
            }
            ActivationResultRetentionPhase::DeferredNotReady => {
                ActivationLifecycleState::DeferredNotReady
            }
        };
        next_lifecycle.result_sha256 = Some(retained.result_sha256.clone());
        next_lifecycle.claim_owner = None;
        next_lifecycle.claim_expires_at_unix_ms = None;
        next_lifecycle.terminal_reason = None;
        next_lifecycle.lifecycle_order = order;
        next_lifecycle.validate()?;
        {
            let payload = encode(&retained)?;
            let mut table = write
                .open_table(ACTIVATION_RESULT_RETENTION)
                .map_err(storage)?;
            table
                .insert(retained.record_key(), payload.as_str())
                .map_err(storage)?;
        }
        {
            let payload = encode(&next_lifecycle)?;
            let mut table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
            table
                .insert(next_lifecycle.record_key(), payload.as_str())
                .map_err(storage)?;
        }
        Ok(retained)
    }

    /// Terminalizes one result-less ticket without erasing accepted results.
    pub fn terminate_activation_without_result(
        &self,
        ticket_id: &str,
        target: ActivationLifecycleState,
        reason: &str,
        now_unix_ms: u64,
    ) -> Result<Option<ActivationLifecycleRecord>, OrsError> {
        crate::model::validate_text(ticket_id, "activation_terminal_ticket_id")?;
        crate::model::validate_text(reason, "activation_terminal_reason")?;
        if !matches!(
            target,
            ActivationLifecycleState::Cancelled
                | ActivationLifecycleState::Expired
                | ActivationLifecycleState::Reconciling
        ) {
            return Err(OrsError::InvalidField {
                field: "activation_terminal_target",
                reason: "resultless terminal target must be cancelled, expired, or reconciling",
            });
        }
        let write = self.database.begin_write().map_err(storage)?;
        let existing: Option<ActivationLifecycleRecord> = {
            let table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
            table
                .get(ticket_id)
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
        };
        let Some(mut existing) = existing else {
            write.commit().map_err(storage)?;
            return Ok(None);
        };
        if existing.state == target {
            if existing.terminal_reason.as_deref() != Some(reason) {
                return Err(OrsError::ActivationLifecycleIdentityConflict {
                    ticket_id: ticket_id.to_owned(),
                });
            }
            write.commit().map_err(storage)?;
            return Ok(Some(existing));
        }
        if existing.result_sha256.is_some()
            || matches!(
                existing.state,
                ActivationLifecycleState::DeferredNotReady
                    | ActivationLifecycleState::ResultAccepted
            )
        {
            return Err(OrsError::ActivationLifecycleIdentityConflict {
                ticket_id: ticket_id.to_owned(),
            });
        }
        let allowed = match target {
            ActivationLifecycleState::Cancelled => {
                existing.state == ActivationLifecycleState::Pending
            }
            ActivationLifecycleState::Expired => {
                matches!(
                    existing.state,
                    ActivationLifecycleState::Pending | ActivationLifecycleState::Claimed
                ) && now_unix_ms >= existing.kernel_deadline_unix_ms
            }
            ActivationLifecycleState::Reconciling => matches!(
                existing.state,
                ActivationLifecycleState::Pending | ActivationLifecycleState::Claimed
            ),
            _ => false,
        };
        if !allowed {
            return Err(OrsError::ActivationLifecycleIdentityConflict {
                ticket_id: ticket_id.to_owned(),
            });
        }
        existing.state = target;
        existing.claim_owner = None;
        existing.claim_expires_at_unix_ms = None;
        existing.terminal_reason = Some(reason.to_owned());
        existing.lifecycle_order = Self::next_operational_order(&write)?;
        existing.validate()?;
        let payload = encode(&existing)?;
        let mut table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
        table
            .insert(existing.record_key(), payload.as_str())
            .map_err(storage)?;
        drop(table);
        write.commit().map_err(storage)?;
        Ok(Some(existing))
    }

    /// Cancels a result-less ticket only when the caller proves the exact
    /// cancellation identity carried by its immutable activation request.
    /// The identity check is a prerequisite to the state CAS; a mismatched
    /// caller can never turn a pending row into `Cancelled`.
    pub fn cancel_activation_without_result(
        &self,
        ticket_id: &str,
        cancellation_id: &str,
        reason: &str,
        now_unix_ms: u64,
    ) -> Result<Option<ActivationLifecycleRecord>, OrsError> {
        crate::model::validate_text(cancellation_id, "activation_cancellation_id")?;
        let existing = self.load_activation_lifecycle(ticket_id)?.ok_or_else(|| {
            OrsError::ActivationLifecycleIdentityConflict {
                ticket_id: ticket_id.to_owned(),
            }
        })?;
        if existing.cancellation_id != cancellation_id {
            return Err(OrsError::ActivationLifecycleIdentityConflict {
                ticket_id: ticket_id.to_owned(),
            });
        }
        self.terminate_activation_without_result(
            ticket_id,
            ActivationLifecycleState::Cancelled,
            reason,
            now_unix_ms,
        )
    }

    /// Loads one activation lifecycle row by exact ticket identity.
    pub fn load_activation_lifecycle(
        &self,
        ticket_id: &str,
    ) -> Result<Option<ActivationLifecycleRecord>, OrsError> {
        crate::model::validate_text(ticket_id, "activation_lifecycle_ticket_id")?;
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
        table
            .get(ticket_id)
            .map_err(storage)?
            .map(|value| {
                let record: ActivationLifecycleRecord = decode(value.value())?;
                record.validate()?;
                Ok(record)
            })
            .transpose()
    }

    /// Loads one retained activation result by exact ticket and result identity.
    pub fn load_activation_result(
        &self,
        ticket_id: &str,
        result_sha256: &str,
    ) -> Result<Option<ActivationResultRetentionRecord>, OrsError> {
        crate::model::validate_text(ticket_id, "activation_result_ticket_id")?;
        crate::model::validate_digest(result_sha256, "activation_result_result_sha256")?;
        let read = self.database.begin_read().map_err(storage)?;
        let lifecycle_table = read.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
        let lifecycle: Option<ActivationLifecycleRecord> = lifecycle_table
            .get(ticket_id)
            .map_err(storage)?
            .map(|value| decode(value.value()))
            .transpose()?;
        let table = read
            .open_table(ACTIVATION_RESULT_RETENTION)
            .map_err(storage)?;
        let retained: Option<ActivationResultRetentionRecord> = table
            .get(ticket_id)
            .map_err(storage)?
            .map(|value| decode(value.value()))
            .transpose()?;
        let Some(retained) = retained else {
            return Ok(None);
        };
        retained.validate()?;
        let Some(lifecycle) = lifecycle else {
            return Err(OrsError::ActivationResultRetentionIdentityConflict {
                ticket_id: ticket_id.to_owned(),
            });
        };
        lifecycle.validate()?;
        if retained.result_sha256 != result_sha256
            || retained.ticket_sha256 != lifecycle.ticket_sha256
            || retained.connection_id != lifecycle.connection_id
            || retained.state_fence != lifecycle.state_fence
            || lifecycle.result_sha256.as_deref() != Some(retained.result_sha256.as_str())
            || !matches!(
                lifecycle.state,
                ActivationLifecycleState::ResultAccepted
                    | ActivationLifecycleState::DeferredNotReady
            )
        {
            return Err(OrsError::ActivationResultRetentionIdentityConflict {
                ticket_id: ticket_id.to_owned(),
            });
        }
        Ok(Some(retained))
    }

    /// Loads every retained activation result in ORS retention order.
    ///
    /// The projection is opaque to ORS callers; Kernel performs the typed
    /// ticket/result validation before restoring its result ledger.
    pub fn load_all_activation_results(
        &self,
    ) -> Result<Vec<ActivationResultRetentionRecord>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let lifecycle_table = read.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
        let table = read
            .open_table(ACTIVATION_RESULT_RETENTION)
            .map_err(storage)?;
        let mut records = Vec::new();
        for entry in table.iter().map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let record: ActivationResultRetentionRecord = decode(value.value())?;
            if key.value() != record.record_key() {
                return Err(OrsError::IntegrityProblem {
                    record_type: "activation_result_retention",
                    reason: "table key does not match ticket identity".to_owned(),
                });
            }
            record.validate()?;
            let lifecycle = lifecycle_table
                .get(key.value())
                .map_err(storage)?
                .ok_or_else(|| OrsError::ActivationResultRetentionIdentityConflict {
                    ticket_id: record.ticket_id.clone(),
                })?;
            let lifecycle: ActivationLifecycleRecord = decode(lifecycle.value())?;
            lifecycle.validate()?;
            if lifecycle.ticket_sha256 != record.ticket_sha256
                || lifecycle.connection_id != record.connection_id
                || lifecycle.state_fence != record.state_fence
                || lifecycle.result_sha256.as_deref() != Some(record.result_sha256.as_str())
                || !matches!(
                    lifecycle.state,
                    ActivationLifecycleState::ResultAccepted
                        | ActivationLifecycleState::DeferredNotReady
                )
            {
                return Err(OrsError::ActivationResultRetentionIdentityConflict {
                    ticket_id: record.ticket_id.clone(),
                });
            }
            records.push(record);
        }
        records.sort_by_key(|record| record.retention_order);
        Ok(records)
    }

    /// Loads lifecycle and retained-result rows under one coherent ORS read
    /// transaction. Cross-table integrity is checked before publication.
    pub fn load_activation_recovery_snapshot(
        &self,
    ) -> Result<ActivationRecoverySnapshot, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let lifecycle_table = read.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
        let mut lifecycles = Vec::new();
        for entry in lifecycle_table.iter().map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let record: ActivationLifecycleRecord = decode(value.value())?;
            if key.value() != record.record_key() {
                return Err(OrsError::IntegrityProblem {
                    record_type: "activation_lifecycle",
                    reason: "table key does not match ticket identity".to_owned(),
                });
            }
            record.validate()?;
            lifecycles.push(record);
        }
        drop(lifecycle_table);
        let result_table = read
            .open_table(ACTIVATION_RESULT_RETENTION)
            .map_err(storage)?;
        let mut results = Vec::new();
        for entry in result_table.iter().map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let record: ActivationResultRetentionRecord = decode(value.value())?;
            if key.value() != record.record_key() {
                return Err(OrsError::IntegrityProblem {
                    record_type: "activation_result_retention",
                    reason: "table key does not match ticket identity".to_owned(),
                });
            }
            record.validate()?;
            results.push(record);
        }
        drop(result_table);
        if lifecycles.len() > crate::MAX_ACTIVATION_LIFECYCLE_RECORDS
            || results.len() > crate::MAX_ACTIVATION_RESULT_RETENTION_RECORDS
        {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        let result_by_ticket = results
            .iter()
            .map(|record| (record.ticket_id.as_str(), record))
            .collect::<BTreeMap<_, _>>();
        for lifecycle in &lifecycles {
            match (
                &lifecycle.result_sha256,
                result_by_ticket.get(lifecycle.ticket_id.as_str()),
            ) {
                (None, None) => {}
                (Some(digest), Some(result)) if digest == &result.result_sha256 => {}
                _ => {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "activation_lifecycle",
                        reason: "lifecycle and retained-result bindings disagree".to_owned(),
                    });
                }
            }
            if let Some(successor) = &lifecycle.successor_of {
                let predecessor = lifecycles
                    .iter()
                    .find(|candidate| candidate.ticket_id == successor.predecessor_ticket_id)
                    .ok_or_else(|| OrsError::IntegrityProblem {
                        record_type: "activation_lifecycle",
                        reason: "successor predecessor is missing".to_owned(),
                    })?;
                if predecessor.state != ActivationLifecycleState::DeferredNotReady
                    || predecessor.ticket_sha256 != successor.predecessor_ticket_sha256
                    || predecessor.result_sha256.as_deref()
                        != Some(successor.predecessor_result_sha256.as_str())
                    || predecessor.successor_ticket_id.as_deref()
                        != Some(lifecycle.ticket_id.as_str())
                {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "activation_lifecycle",
                        reason: "successor predecessor binding is inconsistent".to_owned(),
                    });
                }
            }
        }
        for result in &results {
            if !lifecycles
                .iter()
                .any(|lifecycle| lifecycle.ticket_id == result.ticket_id)
            {
                return Err(OrsError::IntegrityProblem {
                    record_type: "activation_result_retention",
                    reason: "retained result has no lifecycle owner".to_owned(),
                });
            }
        }
        lifecycles.sort_by_key(|record| record.lifecycle_order);
        results.sort_by_key(|record| record.retention_order);
        Ok(ActivationRecoverySnapshot {
            lifecycles,
            results,
        })
    }

    /// Prunes the oldest retained activation results until the count and
    /// aggregate payload bounds are both satisfied.
    pub fn prune_activation_results(&self) -> Result<u64, OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        let removed = Self::prune_activation_results_in_write(&write)?;
        write.commit().map_err(storage)?;
        Ok(removed)
    }

    fn prune_activation_results_in_write(write: &redb::WriteTransaction) -> Result<u64, OrsError> {
        let protected = {
            let table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
            let mut protected = BTreeSet::new();
            for entry in table.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                let lifecycle: ActivationLifecycleRecord = decode(value.value())?;
                if lifecycle.state != ActivationLifecycleState::ResultAccepted
                    || lifecycle.successor_ticket_id.is_some()
                {
                    protected.insert(key.value().to_owned());
                }
            }
            protected
        };
        let mut rows = {
            let table = write
                .open_table(ACTIVATION_RESULT_RETENTION)
                .map_err(storage)?;
            let mut rows = Vec::new();
            for entry in table.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                let record: ActivationResultRetentionRecord = decode(value.value())?;
                if key.value() != record.record_key() {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "activation_result_retention",
                        reason: "table key does not match ticket identity".to_owned(),
                    });
                }
                rows.push((key.value().to_owned(), record));
            }
            rows
        };
        rows.sort_by_key(|(_, record)| record.retention_order);
        for pair in rows.windows(2) {
            if pair[0].1.retention_order == pair[1].1.retention_order {
                return Err(OrsError::IntegrityProblem {
                    record_type: "activation_result_retention",
                    reason: "retention order is not unique".to_owned(),
                });
            }
        }
        let mut total_payload_bytes = rows.iter().try_fold(0usize, |total, (_, record)| {
            total
                .checked_add(record.payload_bytes())
                .ok_or_else(|| OrsError::IntegrityProblem {
                    record_type: "activation_result_retention",
                    reason: "retention payload size overflow".to_owned(),
                })
        })?;
        let mut remove_keys = Vec::new();
        while rows.len().saturating_sub(remove_keys.len())
            > crate::MAX_ACTIVATION_RESULT_RETENTION_RECORDS
            || total_payload_bytes > crate::MAX_ACTIVATION_RESULT_TOTAL_PAYLOAD_BYTES
        {
            let candidate = rows
                .iter()
                .find(|(key, _)| !protected.contains(key) && !remove_keys.contains(key))
                .ok_or(OrsError::ProjectionLimitExceeded)?;
            total_payload_bytes = total_payload_bytes.saturating_sub(candidate.1.payload_bytes());
            remove_keys.push(candidate.0.clone());
        }
        if remove_keys.is_empty() {
            return Ok(0);
        }
        let mut table = write
            .open_table(ACTIVATION_RESULT_RETENTION)
            .map_err(storage)?;
        for key in &remove_keys {
            table.remove(key.as_str()).map_err(storage)?;
        }
        drop(table);
        let mut lifecycle_table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
        for key in &remove_keys {
            lifecycle_table.remove(key.as_str()).map_err(storage)?;
        }
        u64::try_from(remove_keys.len()).map_err(|_| OrsError::IntegrityProblem {
            record_type: "activation_result_retention",
            reason: "pruned record count exceeds counter".to_owned(),
        })
    }

    /// Advances one staged host-request operation to its next mechanical state.
    ///
    /// The transition table owns the anti-blind-retry fence: once an
    /// operation reaches `PossiblyEffected` it can only move forward to
    /// `ResultReceived` through reconciliation evidence, or to `Unknown` /
    /// `Reconciling`. The ORS write transaction assigns the monotonic commit
    /// order atomically when the operation first reaches a terminal state;
    /// the caller never supplies it.
    pub fn advance_host_request(
        &self,
        operation_id: &crate::OperationIdentity,
        request_digest: &str,
        target: crate::HostRequestState,
        result_digest: Option<&str>,
    ) -> Result<Option<crate::HostRequestRecord>, OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        let key = format!("{}::{}", operation_id.as_str(), request_digest);
        let existing: Option<crate::HostRequestRecord> = {
            let table = write.open_table(HOST_REQUESTS).map_err(storage)?;
            table
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
        };
        let Some(existing) = existing else {
            return Ok(None);
        };
        existing.validate()?;
        if existing.state == target {
            let replay_matches = match (&existing.result_digest, result_digest) {
                (Some(current), Some(replayed)) => current.as_str() == replayed,
                (None, None) => true,
                _ => false,
            };
            if !replay_matches {
                return Err(OrsError::HostRequestIdentityConflict {
                    operation_id: operation_id.as_str().to_owned(),
                    request_digest: request_digest.to_owned(),
                });
            }
            return Ok(Some(existing));
        }
        existing.state.transition_to(target)?;
        let effective_result = match (target, &existing.result_digest, result_digest) {
            (crate::HostRequestState::ResultReceived, _, Some(result)) => Some(result.to_owned()),
            (crate::HostRequestState::ResultReceived, _, None) => {
                return Err(OrsError::InvalidField {
                    field: "host_request_result_digest",
                    reason: "received requires a result digest",
                });
            }
            (crate::HostRequestState::Terminal, Some(current), None) => Some(current.clone()),
            (crate::HostRequestState::Terminal, Some(current), Some(replayed))
                if current.as_str() == replayed =>
            {
                Some(current.clone())
            }
            (crate::HostRequestState::Terminal, None, None) => None,
            (crate::HostRequestState::Terminal, _, _) => {
                return Err(OrsError::HostRequestIdentityConflict {
                    operation_id: operation_id.as_str().to_owned(),
                    request_digest: request_digest.to_owned(),
                });
            }
            (_, _, Some(_)) => {
                return Err(OrsError::InvalidField {
                    field: "host_request_result_digest",
                    reason: "result only for received or terminal states",
                });
            }
            (_, _, None) => None,
        };
        let mut next = existing.clone();
        next.state = target;
        next.result_digest = effective_result;
        if target.is_terminal() && next.commit_order == 0 {
            next.commit_order = Self::next_operational_order(&write)?;
        }
        next.validate()?;
        if next != existing {
            let payload = encode(&next)?;
            let mut table = write.open_table(HOST_REQUESTS).map_err(storage)?;
            table
                .insert(key.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(Some(next))
    }

    /// Persists one bounded local-read result body alongside its digest.
    ///
    /// See [`OperationalRecoveryStore::persist_host_request_result`] for the
    /// replay/conflict contract. The lifecycle walk stays inside the existing
    /// transition table: no new edge is introduced, so the anti-blind-retry
    /// fence is unchanged. A `Requested` operation cannot receive a result
    /// (it must be admitted first); terminal states without a result cannot
    /// gain one.
    #[allow(
        clippy::too_many_lines,
        reason = "the result-retention transaction keeps replay, lifecycle, and immutable-view joins together"
    )]
    pub fn persist_host_request_result(
        &self,
        operation_id: &crate::OperationIdentity,
        request_digest: &str,
        result_digest: &str,
        result_response: &serde_json::Value,
    ) -> Result<Option<crate::HostRequestRecord>, OrsError> {
        crate::model::validate_digest(result_digest, "host_request_result_digest")?;
        let campaign_view = campaign_view_publication(result_response)?;
        let key = format!("{}::{}", operation_id.as_str(), request_digest);
        let write = self.database.begin_write().map_err(storage)?;
        let existing: Option<crate::HostRequestRecord> = {
            let table = write.open_table(HOST_REQUESTS).map_err(storage)?;
            table
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
        };
        let Some(existing) = existing else {
            return Ok(None);
        };
        existing.validate()?;
        if existing.state == crate::HostRequestState::ResultReceived {
            let same_digest = existing.result_digest.as_deref() == Some(result_digest);
            let same_body = existing.result_response.as_ref() == Some(result_response);
            if same_digest && same_body {
                if let Some(publication) = campaign_view.as_ref() {
                    let view_key = publication.view_id.as_str();
                    let current = {
                        let table = write
                            .open_table(CAMPAIGN_LEARNING_STATE_VIEWS)
                            .map_err(storage)?;
                        table
                            .get(view_key)
                            .map_err(storage)?
                            .map(|value| {
                                decode::<eliot_store_api::CampaignLearningStateViewPublication>(
                                    value.value(),
                                )
                            })
                            .transpose()?
                    };
                    match current {
                        Some(current) if current == *publication => return Ok(Some(existing)),
                        Some(_) => return Err(campaign_view_identity_conflict(view_key)),
                        None => {
                            let encoded = encode(publication)?;
                            let mut table = write
                                .open_table(CAMPAIGN_LEARNING_STATE_VIEWS)
                                .map_err(storage)?;
                            table.insert(view_key, encoded.as_str()).map_err(storage)?;
                            drop(table);
                            write.commit().map_err(storage)?;
                            return Ok(Some(existing));
                        }
                    }
                }
                return Ok(Some(existing));
            }
            // Legacy digest-only row completed by the exact same digest: the
            // matching digest proves the same result, so binding the missing
            // body is monotonic completion, not an overwrite. Anything else
            // under the same identity stays a conflict.
            let completes_legacy = same_digest && existing.result_response.is_none();
            if !completes_legacy {
                return Err(OrsError::HostRequestIdentityConflict {
                    operation_id: operation_id.as_str().to_owned(),
                    request_digest: request_digest.to_owned(),
                });
            }
        } else if existing.state == crate::HostRequestState::Terminal {
            let same_digest = existing.result_digest.as_deref() == Some(result_digest);
            let same_body = existing.result_response.as_ref() == Some(result_response);
            if same_digest && same_body {
                return Ok(Some(existing));
            }
            // A terminal record either carries this exact result already
            // (handled above) or must never gain or replace one here.
            if existing.result_digest.is_some() || existing.result_response.is_some() {
                return Err(OrsError::HostRequestIdentityConflict {
                    operation_id: operation_id.as_str().to_owned(),
                    request_digest: request_digest.to_owned(),
                });
            }
            return Err(OrsError::InvalidTransition);
        }
        // Walk the mechanical lifecycle to `ResultReceived` inside the
        // existing table: direct when legal, otherwise via the canonical
        // `Admitted -> Routed -> Submitted` progression the synchronous local
        // dispatch stands in for (no router/submitter exists on this path).
        let mut state = existing.state;
        loop {
            if state == crate::HostRequestState::ResultReceived {
                break;
            }
            let next = if state == crate::HostRequestState::Admitted {
                crate::HostRequestState::Routed
            } else if state == crate::HostRequestState::Routed {
                crate::HostRequestState::Submitted
            } else {
                crate::HostRequestState::ResultReceived
            };
            state = state.transition_to(next)?;
        }
        let mut next = existing.clone();
        next.state = crate::HostRequestState::ResultReceived;
        next.result_digest = Some(result_digest.to_owned());
        next.result_response = Some(result_response.clone());
        if next.commit_order == 0 {
            next.commit_order = Self::next_operational_order(&write)?;
        }
        next.validate()?;
        if let Some(publication) = campaign_view.as_ref() {
            let view_key = publication.view_id.as_str();
            let current = {
                let table = write
                    .open_table(CAMPAIGN_LEARNING_STATE_VIEWS)
                    .map_err(storage)?;
                table
                    .get(view_key)
                    .map_err(storage)?
                    .map(|value| {
                        decode::<eliot_store_api::CampaignLearningStateViewPublication>(
                            value.value(),
                        )
                    })
                    .transpose()?
            };
            match current {
                Some(current) if current == *publication => {}
                Some(_) => return Err(campaign_view_identity_conflict(view_key)),
                None => {
                    let encoded = encode(publication)?;
                    let mut table = write
                        .open_table(CAMPAIGN_LEARNING_STATE_VIEWS)
                        .map_err(storage)?;
                    table.insert(view_key, encoded.as_str()).map_err(storage)?;
                }
            }
        }
        if next != existing {
            let payload = encode(&next)?;
            let mut table = write.open_table(HOST_REQUESTS).map_err(storage)?;
            table
                .insert(key.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(Some(next))
    }

    // Bridge-event privacy gate (I7.23 decision before persistence) and
    // handoff reader used by the stage entry below.
    /// Decides the I7.23 disclosure/retention disposition for one bridge
    /// event over its canonical envelope bytes, before any durable write.
    ///
    /// This is the production privacy gate the Kernel route owner calls
    /// before staging: it returns the exact decision object the stage entry
    /// requires (`privacy_disposition` plus `redacted_classes` and
    /// `redaction_reason`), computed from the same bytes the stage entry
    /// re-verifies, so the decision provably precedes persistence. Denied
    /// content (secret values, provider-forbidden hidden reasoning, data
    /// outside the `WorkScope` privacy boundary, operationalized as the denied
    /// token scan) selects the redacted path with the matched classes;
    /// anything else stages verbatim. The boundary exchanges validated JSON
    /// only, like every other bridge-event entry on this owner.
    pub fn bridge_event_privacy_decision(envelope_bytes: &[u8]) -> serde_json::Value {
        let (redacted, classes) = Self::privacy_decision_for(envelope_bytes);
        json!({
            "privacy_disposition": if redacted {
                BRIDGE_EVENT_PRIVACY_REDACTED
            } else {
                BRIDGE_EVENT_PRIVACY_ALLOWED
            },
            "redacted_classes": classes,
            "redaction_reason": if redacted {
                BRIDGE_EVENT_REDACTION_REASON_FORBIDDEN
            } else {
                ""
            },
        })
    }

    /// Builds the deterministic redacted projection for a transport hash and
    /// a set of redacted classes. The output is a pure function of its
    /// inputs: the same hash and class set always yields the same bytes, and
    /// the bytes carry no source content beyond the hash itself. The row
    /// validator recomputes this exact form, so a stored projection is
    /// verified, not trusted.
    fn bridge_event_redacted_projection_bytes(
        transport_hash_hex: &str,
        sorted_classes: &[String],
    ) -> Vec<u8> {
        format!(
            "{BRIDGE_EVENT_REDACTED_PROJECTION_MARKER}:hash={transport_hash_hex}:classes={}",
            sorted_classes.join(",")
        )
        .into_bytes()
    }

    /// Computes the raw disclosure decision over canonical envelope bytes:
    /// whether denied content is present and, when so, the sorted matched
    /// classes. Matched case-insensitively over the lossy UTF-8 decoding, so
    /// binary frames decoding to denied tokens are caught the same way.
    fn privacy_decision_for(envelope_bytes: &[u8]) -> (bool, Vec<String>) {
        let decoded = String::from_utf8_lossy(envelope_bytes).to_lowercase();
        let mut classes: Vec<String> = BRIDGE_EVENT_DENIED_CONTENT_TOKENS
            .iter()
            .filter(|token| decoded.contains(**token))
            .map(|token| (*token).to_owned())
            .collect();
        classes.sort();
        classes.dedup();
        classes.truncate(MAX_BRIDGE_EVENT_REDACTED_CLASSES);
        (!classes.is_empty(), classes)
    }

    /// Parses the presented pre-persistence privacy decision from a staged
    /// object: the disposition plus, on the redacted path, the bounded class
    /// list and the detected-content reason.
    fn presented_privacy_decision(
        staged: &serde_json::Value,
    ) -> Result<(bool, Vec<String>, String), OrsError> {
        let disposition = bridge_text(staged, "privacy_disposition")?;
        let redacted = match disposition.as_str() {
            x if x == BRIDGE_EVENT_PRIVACY_ALLOWED => false,
            x if x == BRIDGE_EVENT_PRIVACY_REDACTED => true,
            _ => {
                return Err(OrsError::InvalidField {
                    field: "privacy_disposition",
                    reason: "bridge event privacy disposition must be allowed or redacted",
                });
            }
        };
        let mut classes = Vec::new();
        if let Some(list) = staged.get("redacted_classes") {
            let items = list.as_array().ok_or(OrsError::InvalidField {
                field: "redacted_classes",
                reason: "bridge event redacted classes must be a bounded text list",
            })?;
            for item in items {
                let class = item.as_str().ok_or(OrsError::InvalidField {
                    field: "redacted_classes",
                    reason: "bridge event redacted classes must be a bounded text list",
                })?;
                crate::model::validate_text(class, "redacted_classes")?;
                classes.push(class.to_owned());
            }
        }
        if classes.len() > MAX_BRIDGE_EVENT_REDACTED_CLASSES {
            return Err(OrsError::InvalidField {
                field: "redacted_classes",
                reason: "bridge event redacted classes must be a bounded text list",
            });
        }
        classes.sort();
        classes.dedup();
        let reason = staged
            .get("redaction_reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned();
        if !reason.is_empty() {
            crate::model::validate_text(&reason, "redaction_reason")?;
        }
        Ok((redacted, classes, reason))
    }

    /// Resolves the I7.23 disclosure staging for one stage call: the
    /// presented pre-persistence decision must equal the decision this owner
    /// recomputes over the canonical envelope bytes, and denied bytes resolve
    /// to the deterministic redacted projection plus its receipt facts —
    /// never to verbatim raw. A decision mismatch fails closed instead of
    /// persisting a disputed form.
    fn bridge_event_privacy_staging(
        staged: &serde_json::Value,
        envelope_bytes: &[u8],
    ) -> Result<BridgeEventPrivacyStaging, OrsError> {
        let (presented_redacted, presented_classes, presented_reason) =
            Self::presented_privacy_decision(staged)?;
        let (denied, decided_classes) = Self::privacy_decision_for(envelope_bytes);
        if denied != presented_redacted
            || (denied && decided_classes != presented_classes)
            || (denied && presented_reason != BRIDGE_EVENT_REDACTION_REASON_FORBIDDEN)
            || (!denied && (!presented_classes.is_empty() || !presented_reason.is_empty()))
        {
            return Err(OrsError::InvalidField {
                field: "privacy_disposition",
                reason: "bridge event privacy decision does not match the staged bytes",
            });
        }
        let transport_hash = crate::model::sha256_hex(envelope_bytes);
        let stored_bytes = if denied {
            Self::bridge_event_redacted_projection_bytes(&transport_hash, &decided_classes)
        } else {
            envelope_bytes.to_vec()
        };
        Ok(BridgeEventPrivacyStaging {
            denied,
            classes: decided_classes,
            transport_hash,
            stored_bytes,
        })
    }

    /// Loads one staged bridge-event row inside a write transaction without
    /// enforcing the fresh-identity record bound: a read-only peek for
    /// cross-checks (handoff, migration) that must never fail for table
    /// pressure. The stage entry keeps using
    /// [`Self::load_bridge_event_row_in`], which owns the bound.
    fn peek_bridge_event_row_in(
        write: &redb::WriteTransaction,
        key: &str,
    ) -> Result<Option<BridgeEventRow>, OrsError> {
        let records = write.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
        records
            .get(key)
            .map_err(storage)?
            .map(|value| decode(value.value()))
            .transpose()
    }

    /// Loads one staged bridge-event row inside a write transaction for the
    /// idempotent-duplicate check. Enforces the record bound for fresh
    /// identities: a full table fails new identities with
    /// [`OrsError::ProjectionLimitExceeded`] while idempotent replays of
    /// stored identities still succeed.
    fn load_bridge_event_row_in(
        write: &redb::WriteTransaction,
        key: &str,
    ) -> Result<Option<BridgeEventRow>, OrsError> {
        let records = write.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
        if records.len().map_err(storage)? >= MAX_BRIDGE_EVENT_RECORDS as u64
            && records.get(key).map_err(storage)?.is_none()
        {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        records
            .get(key)
            .map_err(storage)?
            .map(|value| decode(value.value()))
            .transpose()
    }

    /// Reads the handoff state for one staged identity inside a transaction:
    /// the persisted state, or `None` when no handoff was recorded yet. A
    /// missing handoff is reported as absent, never synthesized.
    fn bridge_handoff_state_in(
        write: &redb::WriteTransaction,
        stream_id: &str,
        event_id: &str,
    ) -> Result<Option<String>, OrsError> {
        let handoffs = write.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
        let key = format!("{stream_id}::{event_id}");
        let row: Option<BridgeEventHandoffRow> = handoffs
            .get(key.as_str())
            .map_err(storage)?
            .map(|value| decode(value.value()))
            .transpose()?;
        match row {
            Some(row) => {
                row.validate()?;
                Ok(Some(row.state))
            }
            None => Ok(None),
        }
    }

    /// Durably stages one bridge-forwarded durable/control event before any
    /// acknowledgement (issue #2561, I7.2/I7.23).
    ///
    /// Persist-before-ack: the `(stream_id, event_id)` row — canonical
    /// envelope bytes with their bound digest, producer/generation/authority
    /// facts, staging connection, and phase — is durably inserted before the
    /// caller may answer `DURABLE`. An exact replay under the same identity
    /// returns the existing outcome with `fresh: false` (no second record, no
    /// duplicate normalization/application); changed bytes under the same
    /// identity fail with [`OrsError::DuplicateConflict`] and never overwrite
    /// the durable row. The per-stream durable cursor advances only over the
    /// contiguous staged frontier, so a forwarded gap accounts for missing
    /// coverage without converting absent events into applied ones. The table
    /// is disjoint from `HOST_REQUESTS`: events never ride the host-request
    /// envelope, and host-request reconciliation never reads this table.
    ///
    /// The boundary is intentionally narrow: inputs arrive as one validated
    /// JSON object (`stream_id`, `event_id`, `sequence`, `producer_id`,
    /// `producer_generation`, `authority_epoch`, `envelope` canonical JSON,
    /// `envelope_sha256`, `staging_connection`, plus the pre-persistence
    /// privacy decision `privacy_disposition` / `redacted_classes` /
    /// `redaction_reason`) and the outcome leaves as one JSON object
    /// (`phase`, `disposition`, cursors, `fresh`, privacy facts, handoff
    /// state). Typed bridge-event views live with the Kernel route owner,
    /// which validates both directions; the store binds bytes and cursors
    /// only.
    ///
    /// Disclosure/retention (I7.23) is enforced here, at the persistence
    /// site: the presented privacy decision must equal the decision this
    /// owner recomputes over the canonical envelope bytes, and denied bytes
    /// are staged as the deterministic redacted projection plus the redaction
    /// receipt facts — never as verbatim raw. A decision mismatch fails the
    /// stage instead of persisting a disputed form.
    pub fn stage_bridge_event(
        &self,
        staged: &serde_json::Value,
    ) -> Result<serde_json::Value, OrsError> {
        let stream_id = bridge_key_text(staged, "stream_id")?;
        let event_id = bridge_key_text(staged, "event_id")?;
        let sequence = bridge_sequence(staged, "sequence")?;
        let producer_id = bridge_text(staged, "producer_id")?;
        let producer_generation = bridge_generation(staged, "producer_generation")?;
        let authority_epoch = bridge_text(staged, "authority_epoch")?;
        let staging_connection = bridge_text(staged, "staging_connection")?;
        let envelope_value = staged
            .get("envelope")
            .cloned()
            .ok_or(OrsError::InvalidField {
                field: "envelope",
                reason: "bridge event must carry its canonical envelope JSON",
            })?;
        let envelope_bytes =
            canonical_json_bytes(&envelope_value).map_err(|_| OrsError::InvalidField {
                field: "envelope",
                reason: "bridge event envelope is not canonicalizable",
            })?;
        if envelope_bytes.len() > MAX_BRIDGE_EVENT_ENVELOPE_BYTES {
            return Err(OrsError::PayloadTooLarge);
        }
        let presented_sha = bridge_text(staged, "envelope_sha256")?;
        crate::model::validate_digest(&presented_sha, "envelope_sha256")?;
        if crate::model::sha256_hex(&envelope_bytes) != presented_sha {
            return Err(OrsError::PayloadIntegrityMismatch);
        }
        let staging = Self::bridge_event_privacy_staging(staged, &envelope_bytes)?;
        let key = format!("{stream_id}::{event_id}");
        let now_ms = current_unix_ms_u64()?;
        let write = self.database.begin_write().map_err(storage)?;
        let outcome = {
            let existing: Option<BridgeEventRow> = Self::load_bridge_event_row_in(&write, &key)?;
            if let Some(row) = existing {
                row.validate()?;
                if row.envelope_sha256 != presented_sha
                    || row.sequence != sequence
                    || row.producer_id != producer_id
                    || row.producer_generation != producer_generation
                    || row.authority_epoch != authority_epoch
                    || row.redacted != staging.denied
                    || row.transport_hash != staging.transport_hash
                    || !row.owner_namespace.is_empty()
                {
                    return Err(OrsError::DuplicateConflict);
                }
                let (durable, acked) = Self::bridge_cursors_in(&write, &stream_id)?;
                let handoff = Self::bridge_handoff_state_in(&write, &stream_id, &event_id)?;
                bridge_event_outcome(&row, "duplicate", durable, acked, false, handoff.as_deref())
            } else {
                let row = BridgeEventRow {
                    contract_version: crate::CONTRACT_VERSION,
                    stream_id: stream_id.clone(),
                    event_id: event_id.clone(),
                    sequence,
                    producer_id,
                    producer_generation,
                    authority_epoch,
                    envelope_sha256: presented_sha,
                    envelope_bytes: staging.stored_bytes,
                    staging_connection,
                    staged_at_ms: now_ms,
                    phase: BRIDGE_EVENT_PHASE_DURABLE.to_owned(),
                    // Legacy entry: no owner binding was presented, so the
                    // row stays ownerless. Owner-checked entries use
                    // `stage_bridge_event_checked`, which binds the admitted
                    // namespace here instead of leaving it empty.
                    owner_namespace: String::new(),
                    transport_hash: staging.transport_hash,
                    redacted: staging.denied,
                    redaction_reason: if staging.denied {
                        BRIDGE_EVENT_REDACTION_REASON_FORBIDDEN.to_owned()
                    } else {
                        String::new()
                    },
                    redacted_classes: staging.classes,
                    redaction_marker: if staging.denied {
                        BRIDGE_EVENT_REDACTED_PROJECTION_MARKER.to_owned()
                    } else {
                        String::new()
                    },
                    redaction_version: if staging.denied {
                        crate::CONTRACT_VERSION
                    } else {
                        0
                    },
                };
                row.validate()?;
                {
                    let mut records = write.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
                    records
                        .insert(key.as_str(), encode(&row)?.as_str())
                        .map_err(storage)?;
                }
                Self::mark_bridge_recovery_legacy_unproven_in(&write)?;
                let (durable, acked) = Self::advance_bridge_cursor_in(&write, &stream_id)?;
                let handoff = Self::bridge_handoff_state_in(&write, &stream_id, &event_id)?;
                bridge_event_outcome(&row, "accepted", durable, acked, true, handoff.as_deref())
            }
        };
        write.commit().map_err(storage)?;
        Ok(outcome)
    }

    /// Loads one staged bridge event by exact identity without mutating
    /// anything.
    ///
    /// Read-only projection for ack recovery: after owner commit but before
    /// acknowledgement, lookup returns the existing phase, disposition,
    /// digest, privacy facts, handoff state, and cursors, so a lost
    /// acknowledgement replays to the stored facts instead of duplicating
    /// normalization or application. Unknown identities return `Ok(None)`,
    /// never a synthesized event.
    pub fn load_bridge_event(
        &self,
        stream_id: &str,
        event_id: &str,
    ) -> Result<Option<serde_json::Value>, OrsError> {
        bridge_identity_text(stream_id, "stream_id")?;
        bridge_identity_text(event_id, "event_id")?;
        let read = self.database.begin_read().map_err(storage)?;
        let key = format!("{stream_id}::{event_id}");
        let row: Option<BridgeEventRow> = {
            let records = read.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
            records
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
        };
        let Some(row) = row else {
            return Ok(None);
        };
        row.validate()?;
        let handoff: Option<String> = {
            let handoffs = read.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
            handoffs
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
                .map(|row: BridgeEventHandoffRow| {
                    row.validate()?;
                    Ok::<String, OrsError>(row.state)
                })
                .transpose()?
        };
        let (durable, acked) = Self::bridge_cursors_for(&self.database, stream_id)?;
        Ok(Some(bridge_event_outcome(
            &row,
            "accepted",
            durable,
            acked,
            false,
            handoff.as_deref(),
        )))
    }

    /// Records the Governor-handoff for one durably staged bridge event
    /// (issue #2561, I5(i)).
    ///
    /// The Kernel route owner calls this after the ORS bridge-event row is
    /// staged: the handoff persists the staged envelope digest with the
    /// `handed_off` state, proving the durable event reached the intake
    /// handoff. An exact replay under the same identity and digest returns
    /// the existing handoff with `fresh: false`; changed bytes under the same
    /// identity fail with [`OrsError::DuplicateConflict`]. The handoff never
    /// synthesizes intake, normalization, or application: those legs stay
    /// owned by the provider normalizer and the Governor/coordinator intake,
    /// which consume this durable fact on recovery.
    ///
    /// The boundary is intentionally narrow: inputs arrive as one validated
    /// JSON object (`stream_id`, `event_id`, `sequence`, `envelope_sha256`,
    /// `staging_connection`) and the handoff receipt leaves as one JSON
    /// object.
    pub fn record_bridge_event_handoff(
        &self,
        handoff: &serde_json::Value,
    ) -> Result<serde_json::Value, OrsError> {
        let stream_id = bridge_key_text(handoff, "stream_id")?;
        let event_id = bridge_key_text(handoff, "event_id")?;
        let sequence = bridge_sequence(handoff, "sequence")?;
        let envelope_sha256 = bridge_text(handoff, "envelope_sha256")?;
        crate::model::validate_digest(&envelope_sha256, "envelope_sha256")?;
        let staging_connection = bridge_text(handoff, "staging_connection")?;
        let key = format!("{stream_id}::{event_id}");
        let now_ms = current_unix_ms_u64()?;
        let write = self.database.begin_write().map_err(storage)?;
        let outcome = {
            let existing: Option<BridgeEventHandoffRow> = {
                let handoffs = write.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
                if handoffs.len().map_err(storage)? >= MAX_BRIDGE_EVENT_HANDOFFS as u64
                    && handoffs.get(key.as_str()).map_err(storage)?.is_none()
                {
                    return Err(OrsError::ProjectionLimitExceeded);
                }
                handoffs
                    .get(key.as_str())
                    .map_err(storage)?
                    .map(|value| decode(value.value()))
                    .transpose()?
            };
            if let Some(row) = existing {
                row.validate()?;
                if row.envelope_sha256 != envelope_sha256
                    || row.sequence != sequence
                    || !row.owner_namespace.is_empty()
                {
                    return Err(OrsError::DuplicateConflict);
                }
                json!({
                    "stream_id": row.stream_id,
                    "event_id": row.event_id,
                    "sequence": row.sequence,
                    "envelope_sha256": row.envelope_sha256,
                    "state": row.state,
                    "staging_connection": row.staging_connection,
                    "fresh": false,
                })
            } else {
                let row = BridgeEventHandoffRow {
                    contract_version: crate::CONTRACT_VERSION,
                    stream_id: stream_id.clone(),
                    event_id: event_id.clone(),
                    sequence,
                    envelope_sha256: envelope_sha256.clone(),
                    state: BRIDGE_EVENT_HANDOFF_HANDED_OFF.to_owned(),
                    staging_connection: staging_connection.clone(),
                    handed_off_at_ms: now_ms,
                    reconcile_key: String::new(),
                    reconciled_at_ms: 0,
                    // Legacy entry: no owner binding was presented, so the
                    // row stays ownerless. `record_bridge_event_handoff_checked`
                    // binds the admitted namespace on the owner-checked path.
                    owner_namespace: String::new(),
                    reconcile_acked_sequence: 0,
                    reconcile_owner_revision: 0,
                    reconcile_owner_incarnation: 0,
                };
                row.validate()?;
                {
                    let mut handoffs = write.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
                    handoffs
                        .insert(key.as_str(), encode(&row)?.as_str())
                        .map_err(storage)?;
                }
                json!({
                    "stream_id": stream_id,
                    "event_id": event_id,
                    "sequence": sequence,
                    "envelope_sha256": envelope_sha256,
                    "state": BRIDGE_EVENT_HANDOFF_HANDED_OFF,
                    "staging_connection": staging_connection,
                    "fresh": true,
                })
            }
        };
        write.commit().map_err(storage)?;
        Ok(outcome)
    }

    /// Binds handed-off bridge events to one reconciliation key once the
    /// consumed frontier covers their sequences (issue #2561, I5(i)).
    ///
    /// The Kernel event reconcile entry calls this after applying the
    /// consumed frontier: every `handed_off` row on `stream_id` at or below
    /// `acked_sequence` becomes `reconciled` under `reconcile_key`, so the
    /// handoff durably records which reconciliation covered it. Rows already
    /// reconciled, rows above the frontier, and other streams are untouched;
    /// the bound is monotonic by construction of the acked frontier. Returns
    /// the stream, the frontier, and the reconciled row count.
    pub fn reconcile_bridge_event_handoffs(
        &self,
        stream_id: &str,
        acked_sequence: u64,
        reconcile_key: &str,
    ) -> Result<serde_json::Value, OrsError> {
        bridge_identity_text(stream_id, "stream_id")?;
        if acked_sequence == 0 {
            return Err(OrsError::InvalidField {
                field: "acked_sequence",
                reason: "handoff reconcile sequence must be nonzero",
            });
        }
        crate::model::validate_digest(reconcile_key, "reconcile_key")?;
        let now_ms = current_unix_ms_u64()?;
        let write = self.database.begin_write().map_err(storage)?;
        let mut reconciled = 0_u64;
        {
            let handoffs = write.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
            let mut due = Vec::new();
            for entry in handoffs.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                let row: BridgeEventHandoffRow = decode(value.value())?;
                row.validate()?;
                if row.stream_id == stream_id
                    && row.sequence <= acked_sequence
                    && row.state == BRIDGE_EVENT_HANDOFF_HANDED_OFF
                {
                    due.push(key.value().to_owned());
                }
            }
            if !due.is_empty() {
                drop(handoffs);
                let mut handoffs = write.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
                for key in due {
                    let mut row: BridgeEventHandoffRow = handoffs
                        .get(key.as_str())
                        .map_err(storage)?
                        .map(|value| decode(value.value()))
                        .transpose()?
                        .ok_or(OrsError::InvalidField {
                            field: "event_id",
                            reason: "bridge event handoff disappeared during reconcile",
                        })?;
                    row.validate()?;
                    if row.state != BRIDGE_EVENT_HANDOFF_HANDED_OFF {
                        continue;
                    }
                    BRIDGE_EVENT_HANDOFF_RECONCILED.clone_into(&mut row.state);
                    reconcile_key.clone_into(&mut row.reconcile_key);
                    row.reconciled_at_ms = now_ms;
                    row.validate()?;
                    handoffs
                        .insert(key.as_str(), encode(&row)?.as_str())
                        .map_err(storage)?;
                    reconciled += 1;
                }
            }
        }
        write.commit().map_err(storage)?;
        Ok(json!({
            "stream_id": stream_id,
            "acked_sequence": acked_sequence,
            "reconciled": reconciled,
        }))
    }

    /// Serves one bounded pending page for a stream in ascending sequence
    /// order: committed-but-unacknowledged rows for acknowledgement recovery.
    ///
    /// `after_sequence` resumes after the previous page (the acked cursor for
    /// the first page); `page_limit` must be within `1..=MAX_BRIDGE_EVENT_PAGE`
    /// or [`OrsError::InvalidCursorLimit`] fails the call instead of
    /// truncating silently. `continuation` resumes the walk, or is `None`
    /// when the tail is fully served. Restart enumerates these pages with a
    /// continuation; cursors are never reset and no generation's unresolved
    /// rows are discarded here.
    pub fn bridge_event_pending_page(
        &self,
        stream_id: &str,
        after_sequence: u64,
        page_limit: usize,
    ) -> Result<serde_json::Value, OrsError> {
        bridge_identity_text(stream_id, "stream_id")?;
        if page_limit == 0 || page_limit > MAX_BRIDGE_EVENT_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        let read = self.database.begin_read().map_err(storage)?;
        let mut rows: Vec<BridgeEventRow> = Vec::new();
        {
            let records = read.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
            for entry in records.iter().map_err(storage)? {
                let (_, value) = entry.map_err(storage)?;
                let row: BridgeEventRow = decode(value.value())?;
                row.validate()?;
                if row.stream_id == stream_id && row.sequence > after_sequence {
                    rows.push(row);
                }
            }
        }
        rows.sort_by_key(|row| row.sequence);
        let continuation = if rows.len() > page_limit {
            rows.truncate(page_limit);
            rows.last().map(|row| row.sequence)
        } else {
            None
        };
        let items: Vec<serde_json::Value> = rows
            .iter()
            .map(|row| {
                json!({
                    "event_id": row.event_id,
                    "sequence": row.sequence,
                    "phase": row.phase,
                    "disposition": "accepted",
                    "envelope_sha256": row.envelope_sha256,
                    "producer_id": row.producer_id,
                    "producer_generation": row.producer_generation,
                    "staging_connection": row.staging_connection,
                })
            })
            .collect();
        let (durable, acked) = Self::bridge_cursors_for(&self.database, stream_id)?;
        Ok(json!({
            "stream_id": stream_id,
            "durable_cursor": durable,
            "acked_cursor": acked,
            "items": items,
            "continuation": continuation,
        }))
    }

    /// Advances the per-stream acked cursor monotonically, never past the
    /// durable cursor, and compacts acknowledged rows past the retention
    /// window in the same transaction.
    ///
    /// Only durable rows at or below the new acked frontier are eligible,
    /// and only past `RETAIN_BRIDGE_EVENT_ACKED_PER_STREAM` newest acked rows
    /// per stream: staged-but-uncommitted rows, unacknowledged rows, the
    /// retention window (duplicate-suppression frontier), and the cursor facts
    /// themselves are never touched. Re-presentation of a compacted sequence
    /// at or below the acked cursor answers from the cursor frontier as a
    /// duplicate instead of minting a second logical event. Returns the cursor
    /// outcome plus the pruned row count.
    pub fn acknowledge_bridge_events(
        &self,
        stream_id: &str,
        sequence: u64,
    ) -> Result<serde_json::Value, OrsError> {
        bridge_identity_text(stream_id, "stream_id")?;
        if sequence == 0 {
            return Err(OrsError::InvalidField {
                field: "sequence",
                reason: "acknowledgement sequence must be nonzero",
            });
        }
        let write = self.database.begin_write().map_err(storage)?;
        let (durable, mut acked) = Self::bridge_cursors_in(&write, stream_id)?;
        if sequence > durable {
            return Err(OrsError::InvalidTransition);
        }
        if sequence > acked {
            acked = sequence;
            Self::write_bridge_cursors_in(&write, stream_id, durable, acked)?;
        }
        let floor = acked.saturating_sub(RETAIN_BRIDGE_EVENT_ACKED_PER_STREAM);
        let mut pruned = 0_u64;
        if floor > 0 {
            let victims: Vec<String> = {
                let records = write.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
                let mut found = Vec::new();
                for entry in records.iter().map_err(storage)? {
                    let (key, value) = entry.map_err(storage)?;
                    let row: BridgeEventRow = decode(value.value())?;
                    row.validate()?;
                    if row.stream_id == stream_id
                        && row.sequence <= floor
                        && row.phase == BRIDGE_EVENT_PHASE_DURABLE
                    {
                        found.push(key.value().to_owned());
                    }
                }
                found
            };
            if !victims.is_empty() {
                let mut records = write.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
                for victim in &victims {
                    records.remove(victim.as_str()).map_err(storage)?;
                    pruned += 1;
                }
            }
        }
        write.commit().map_err(storage)?;
        Ok(json!({
            "stream_id": stream_id,
            "durable_cursor": durable,
            "acked_cursor": acked,
            "pruned": pruned,
        }))
    }

    /// Records one forwarded coverage gap without touching any cursor.
    ///
    /// A successfully forwarded gap accounts for missing coverage: the gap
    /// row (identity, stream interval, reason, staging connection) stays
    /// visible in coverage while the durable/acked cursors do not move, so
    /// absent events are never converted into applied events. An exact replay
    /// under the same gap identity returns the existing acceptance; changed
    /// content under it fails with [`OrsError::DuplicateConflict`].
    pub fn record_bridge_event_gap(
        &self,
        gap: &serde_json::Value,
    ) -> Result<serde_json::Value, OrsError> {
        let gap_id = bridge_text(gap, "gap_id")?;
        let stream_id = bridge_gap_stream_text(gap)?;
        let start_sequence = bridge_sequence(gap, "start_sequence")?;
        let end_sequence = bridge_sequence(gap, "end_sequence")?;
        if end_sequence < start_sequence {
            return Err(OrsError::InvalidField {
                field: "end_sequence",
                reason: "gap interval must not end before it starts",
            });
        }
        let reason_ref = bridge_text(gap, "reason_ref")?;
        let staging_connection = bridge_text(gap, "staging_connection")?;
        let now_ms = current_unix_ms_u64()?;
        let write = self.database.begin_write().map_err(storage)?;
        {
            let gaps = write.open_table(BRIDGE_EVENT_GAPS).map_err(storage)?;
            if gaps.get(gap_id.as_str()).map_err(storage)?.is_none() {
                let mut stream_gaps = 0_usize;
                for entry in gaps.iter().map_err(storage)? {
                    let (_, value) = entry.map_err(storage)?;
                    let row: BridgeEventGapRow = decode(value.value())?;
                    row.validate()?;
                    if row.stream_id == stream_id {
                        stream_gaps += 1;
                    }
                }
                if stream_gaps >= MAX_BRIDGE_EVENT_GAPS_PER_STREAM {
                    return Err(OrsError::ProjectionLimitExceeded);
                }
            }
        }
        if let Some(existing) = {
            let gaps = write.open_table(BRIDGE_EVENT_GAPS).map_err(storage)?;
            gaps.get(gap_id.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
        } {
            let existing: BridgeEventGapRow = existing;
            existing.validate()?;
            if existing.stream_id != stream_id
                || existing.start_sequence != start_sequence
                || existing.end_sequence != end_sequence
                || existing.reason_ref != reason_ref
                || !existing.owner_namespace.is_empty()
            {
                return Err(OrsError::DuplicateConflict);
            }
            write.commit().map_err(storage)?;
            return Ok(json!({ "gap_id": gap_id, "accepted": true, "fresh": false }));
        }
        let row = BridgeEventGapRow {
            contract_version: crate::CONTRACT_VERSION,
            gap_id: gap_id.clone(),
            stream_id,
            start_sequence,
            end_sequence,
            reason_ref,
            staging_connection,
            recorded_at_ms: now_ms,
            // Legacy entry: no owner binding was presented, so the row
            // stays ownerless. `record_bridge_event_gap_checked` binds the
            // admitted namespace on the owner-checked path.
            owner_namespace: String::new(),
        };
        row.validate()?;
        {
            let mut gaps = write.open_table(BRIDGE_EVENT_GAPS).map_err(storage)?;
            gaps.insert(gap_id.as_str(), encode(&row)?.as_str())
                .map_err(storage)?;
        }
        Self::mark_bridge_recovery_legacy_unproven_in(&write)?;
        write.commit().map_err(storage)?;
        Ok(json!({ "gap_id": gap_id, "accepted": true, "fresh": true }))
    }

    /// Reconciles event ownership and cursors for the presenting connection.
    ///
    /// Scope rule, enforced here and nowhere else: no stream listing exists.
    /// The enumeration covers exactly the streams whose cursor row names the
    /// presenting connection as the last stager, plus streams whose last
    /// producer generation is older than `live_generation` (fenced
    /// old-generation unresolved streams are never discarded). Each covered
    /// stream reports its durable/acked cursors, its pending first page, and
    /// its recorded gaps; unscoped gaps (no stream scope) report at top level
    /// under the presenting connection only. The caller binds the reply
    /// digest as its reconciliation key; host-request reconciliation never
    /// reads these tables.
    pub fn reconcile_bridge_events(
        &self,
        connection_id: &str,
        live_generation: u64,
    ) -> Result<serde_json::Value, OrsError> {
        crate::model::validate_text(connection_id, "connection_id")?;
        if live_generation == 0 {
            return Err(OrsError::InvalidField {
                field: "live_generation",
                reason: "live producer generation must be nonzero",
            });
        }
        let read = self.database.begin_read().map_err(storage)?;
        let mut streams: Vec<(String, u64, u64, String, u64)> = Vec::new();
        {
            let cursors = read.open_table(BRIDGE_EVENT_CURSORS).map_err(storage)?;
            for entry in cursors.iter().map_err(storage)? {
                let (_, value) = entry.map_err(storage)?;
                let row: BridgeEventCursorRow = decode(value.value())?;
                row.validate()?;
                if row.last_staging_connection == connection_id
                    || row.last_producer_generation < live_generation
                {
                    streams.push((
                        row.stream_id.clone(),
                        row.last_durable_sequence,
                        row.last_acked_sequence,
                        row.last_staging_connection.clone(),
                        row.last_producer_generation,
                    ));
                }
            }
        }
        streams.sort_by(|left, right| left.0.cmp(&right.0));
        let mut covered = Vec::new();
        for (stream_id, durable, acked, stager, generation) in &streams {
            let page = self.bridge_event_pending_page(stream_id, *acked, MAX_BRIDGE_EVENT_PAGE)?;
            let gaps = self.bridge_gaps_for(stream_id, None)?;
            covered.push(json!({
                "stream_id": stream_id,
                "durable_cursor": durable,
                "acked_cursor": acked,
                "last_staging_connection": stager,
                "last_producer_generation": generation,
                "pending_first_page": page,
                "gaps": gaps,
            }));
        }
        // Unscoped gaps (no stream scope presented at forward time) reconcile
        // at top level under their staging connection, never under a stream.
        let unscoped_gaps = self.bridge_gaps_for("", Some(connection_id))?;
        Ok(json!({
            "connection_id": connection_id,
            "live_generation": live_generation,
            "streams": covered,
            "unscoped_gaps": unscoped_gaps,
        }))
    }

    /// Reads the recorded gaps for one stream scope, oldest first.
    ///
    /// `connection` restricts unscoped-gap reads to the presenting
    /// connection's own rows; scoped gaps ride their stream's visibility.
    fn bridge_gaps_for(
        &self,
        stream_id: &str,
        connection: Option<&str>,
    ) -> Result<Vec<serde_json::Value>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let gaps = read.open_table(BRIDGE_EVENT_GAPS).map_err(storage)?;
        let mut rows: Vec<BridgeEventGapRow> = Vec::new();
        for entry in gaps.iter().map_err(storage)? {
            let (_, value) = entry.map_err(storage)?;
            let row: BridgeEventGapRow = decode(value.value())?;
            row.validate()?;
            if row.stream_id == stream_id
                && connection.is_none_or(|allowed| row.staging_connection == allowed)
            {
                rows.push(row);
            }
        }
        rows.sort_by_key(|row| (row.start_sequence, row.gap_id.clone()));
        Ok(rows
            .iter()
            .map(|row| {
                json!({
                    "gap_id": row.gap_id,
                    "start_sequence": row.start_sequence,
                    "end_sequence": row.end_sequence,
                    "reason_ref": row.reason_ref,
                })
            })
            .collect())
    }

    /// Reads the per-stream durable/acked cursors inside a write transaction.
    /// Unknown streams report zero cursors; cursor state is never synthesized
    /// from turn, process, or host-request state.
    fn bridge_cursors_in(
        write: &redb::WriteTransaction,
        stream_id: &str,
    ) -> Result<(u64, u64), OrsError> {
        let cursors = write.open_table(BRIDGE_EVENT_CURSORS).map_err(storage)?;
        let row: Option<BridgeEventCursorRow> = cursors
            .get(stream_id)
            .map_err(storage)?
            .map(|value| decode(value.value()))
            .transpose()?;
        match row {
            Some(row) => {
                row.validate()?;
                Ok((row.last_durable_sequence, row.last_acked_sequence))
            }
            None => Ok((0, 0)),
        }
    }

    /// Reads the per-stream durable/acked cursors under a read transaction
    /// for mutation-free projections (lookup, pages, reconciliation).
    fn bridge_cursors_for(database: &Database, stream_id: &str) -> Result<(u64, u64), OrsError> {
        let read = database.begin_read().map_err(storage)?;
        let cursors = read.open_table(BRIDGE_EVENT_CURSORS).map_err(storage)?;
        let row: Option<BridgeEventCursorRow> = cursors
            .get(stream_id)
            .map_err(storage)?
            .map(|value| decode(value.value()))
            .transpose()?;
        match row {
            Some(row) => {
                row.validate()?;
                Ok((row.last_durable_sequence, row.last_acked_sequence))
            }
            None => Ok((0, 0)),
        }
    }

    /// Advances the durable cursor over the contiguous staged frontier and
    /// persists the cursor row with its staging provenance.
    fn advance_bridge_cursor_in(
        write: &redb::WriteTransaction,
        stream_id: &str,
    ) -> Result<(u64, u64), OrsError> {
        let (mut durable, acked) = Self::bridge_cursors_in(write, stream_id)?;
        let mut stager: Option<(String, u64)> = None;
        loop {
            let wanted = durable + 1;
            let found: Option<(String, u64)> = {
                let records = write.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
                let mut hit = None;
                for entry in records.iter().map_err(storage)? {
                    let (_, value) = entry.map_err(storage)?;
                    let row: BridgeEventRow = decode(value.value())?;
                    if row.stream_id == stream_id && row.sequence == wanted {
                        row.validate()?;
                        hit = Some((row.staging_connection.clone(), row.producer_generation));
                        break;
                    }
                }
                hit
            };
            let Some((connection, generation)) = found else {
                break;
            };
            durable = wanted;
            stager = Some((connection, generation));
        }
        let cursor = BridgeEventCursorRow {
            contract_version: crate::CONTRACT_VERSION,
            stream_id: stream_id.to_owned(),
            last_durable_sequence: durable,
            last_acked_sequence: acked,
            last_staging_connection: stager
                .as_ref()
                .map_or(String::new(), |(connection, _)| connection.clone()),
            last_producer_generation: stager.map_or(0, |(_, generation)| generation),
            // Legacy entry: cursors written without an owner-checked stage
            // stay ownerless; `advance_bridge_cursor_in_checked` binds the
            // admitted namespace on the owner-checked path.
            owner_namespace: String::new(),
            last_observed_sequence: durable,
            last_compacted_sequence: 0,
        };
        cursor.validate()?;
        {
            let mut cursors = write.open_table(BRIDGE_EVENT_CURSORS).map_err(storage)?;
            cursors
                .insert(stream_id, encode(&cursor)?.as_str())
                .map_err(storage)?;
        }
        Self::mark_bridge_recovery_legacy_unproven_in(write)?;
        Ok((durable, acked))
    }

    /// Persists the per-stream cursor row with its staging provenance.
    fn write_bridge_cursors_in(
        write: &redb::WriteTransaction,
        stream_id: &str,
        durable: u64,
        acked: u64,
    ) -> Result<(), OrsError> {
        let prior: Option<BridgeEventCursorRow> = {
            let cursors = write.open_table(BRIDGE_EVENT_CURSORS).map_err(storage)?;
            cursors
                .get(stream_id)
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
        };
        let cursor = BridgeEventCursorRow {
            contract_version: crate::CONTRACT_VERSION,
            stream_id: stream_id.to_owned(),
            last_durable_sequence: durable,
            last_acked_sequence: acked,
            last_staging_connection: prior
                .as_ref()
                .map_or(String::new(), |row| row.last_staging_connection.clone()),
            last_producer_generation: prior.as_ref().map_or(0, |row| row.last_producer_generation),
            // Legacy entry: preserves the prior ownerlessness; the
            // owner-checked path writes through
            // `write_bridge_cursors_in_checked` instead.
            owner_namespace: String::new(),
            last_observed_sequence: prior
                .as_ref()
                .map_or(durable, |row| row.last_observed_sequence.max(durable)),
            last_compacted_sequence: prior.as_ref().map_or(0, |row| row.last_compacted_sequence),
        };
        cursor.validate()?;
        let mut cursors = write.open_table(BRIDGE_EVENT_CURSORS).map_err(storage)?;
        cursors
            .insert(stream_id, encode(&cursor)?.as_str())
            .map_err(storage)?;
        drop(cursors);
        Self::mark_bridge_recovery_legacy_unproven_in(write)?;
        Ok(())
    }

    /// Extracts one required owner text field from a staged JSON object.
    fn bridge_owner_field(
        value: &serde_json::Value,
        field: &'static str,
    ) -> Result<String, OrsError> {
        let text =
            value
                .get(field)
                .and_then(serde_json::Value::as_str)
                .ok_or(OrsError::InvalidField {
                    field,
                    reason: "bridge event owner evidence must carry text",
                })?;
        bridge_owner_component(text, field)?;
        Ok(text.to_owned())
    }

    /// Extracts the creating session epoch from a staged JSON object.
    fn bridge_owner_epoch(value: &serde_json::Value) -> Result<u64, OrsError> {
        let epoch = value
            .get("owner_session_epoch")
            .and_then(serde_json::Value::as_u64)
            .ok_or(OrsError::InvalidField {
                field: "owner_session_epoch",
                reason: "bridge event owner evidence must carry a session epoch",
            })?;
        if epoch == 0 {
            return Err(OrsError::InvalidField {
                field: "owner_session_epoch",
                reason: "bridge event owner evidence binds a nonzero session epoch",
            });
        }
        Ok(epoch)
    }

    /// Extracts the Kernel-derived stream owner evidence from a staged
    /// JSON object (issue #2729). The producer and local stream ride the
    /// top-level identity fields; the lineage, principal, and creating
    /// occurrence ride the `owner_*` fields the Kernel route derived from
    /// the retained Session and the presenting fence.
    fn bridge_stream_evidence_from(
        staged: &serde_json::Value,
    ) -> Result<BridgeOwnerEvidence, OrsError> {
        let producer = bridge_key_text(staged, "producer_id")?;
        if producer == HOST_REQUEST_UNBOUND_MARKER {
            return Err(OrsError::InvalidField {
                field: "producer_id",
                reason: "owner-bound producers must not equal the unbound marker",
            });
        }
        let local = bridge_key_text(staged, "stream_id")?;
        if local == HOST_REQUEST_UNBOUND_MARKER {
            return Err(OrsError::InvalidField {
                field: "stream_id",
                reason: "owner-bound streams must not equal the unbound marker",
            });
        }
        Ok(BridgeOwnerEvidence {
            lineage: Self::bridge_owner_field(staged, "owner_authority_lineage")?,
            principal: Self::bridge_owner_field(staged, "owner_principal")?,
            producer,
            local,
            connection: bridge_text(staged, "owner_connection")?,
            launch_nonce: bridge_text(staged, "owner_launch_nonce")?,
            session_epoch: Self::bridge_owner_epoch(staged)?,
        })
    }

    /// Extracts the presenter identity (lineage plus principal) used for
    /// owner-scoped resolution and enumeration (issue #2729).
    fn bridge_owner_presenter_from(
        value: &serde_json::Value,
    ) -> Result<(String, String), OrsError> {
        Ok((
            Self::bridge_owner_field(value, "owner_authority_lineage")?,
            Self::bridge_owner_field(value, "owner_principal")?,
        ))
    }

    /// Computes the versioned owner-namespace digest for one admitted
    /// stream (issue #2729). The digest binds the namespace literal, the
    /// authority lineage, the principal, the producer, and the local
    /// stream as labeled `\x1f`-separated components — the same unambiguous
    /// encoding as the #2571 logical key — so distinct admitted producers
    /// using the same local name remain distinct namespaces.
    fn bridge_stream_owner_digest(
        lineage: &str,
        principal: &str,
        producer: &str,
        local: &str,
    ) -> Result<String, OrsError> {
        bridge_owner_component(lineage, "owner_authority_lineage")?;
        bridge_owner_component(principal, "owner_principal")?;
        bridge_owner_component(producer, "producer_id")?;
        bridge_owner_component(local, "stream_id")?;
        let text = format!(
            "{BRIDGE_STREAM_OWNER_NAMESPACE}\x1flineage={lineage}\x1fprincipal={principal}\x1fproducer={producer}\x1fstream={local}"
        );
        Ok(crate::model::sha256_hex(text.as_bytes()))
    }

    /// Computes the versioned owner-namespace digest for one
    /// connection-level gap reporter occurrence (issue #2729). The producer
    /// and stream slots are fixed to the explicit unbound marker by
    /// construction — never taken from caller input — so the namespace
    /// names the reporter's admitted occurrence without fabricating a
    /// producer or a task.
    fn bridge_gap_owner_digest(lineage: &str, principal: &str) -> Result<String, OrsError> {
        bridge_owner_component(lineage, "owner_authority_lineage")?;
        bridge_owner_component(principal, "owner_principal")?;
        let unbound = HOST_REQUEST_UNBOUND_MARKER;
        let text = format!(
            "{BRIDGE_GAP_OWNER_NAMESPACE}\x1flineage={lineage}\x1fprincipal={principal}\x1fproducer={unbound}\x1fstream={unbound}"
        );
        Ok(crate::model::sha256_hex(text.as_bytes()))
    }

    fn bridge_owner_scope_digest(lineage: &str, principal: &str) -> Result<String, OrsError> {
        bridge_owner_component(lineage, "owner_authority_lineage")?;
        bridge_owner_component(principal, "owner_principal")?;
        let text = format!(
            "{BRIDGE_STREAM_OWNER_NAMESPACE}\x1frecovery-list\x1flineage={lineage}\x1fprincipal={principal}"
        );
        Ok(crate::model::sha256_hex(text.as_bytes()))
    }

    fn bridge_owner_list_index_prefix(scope_digest: &str, owner_kind: &str) -> String {
        format!("{scope_digest}::{owner_kind}::")
    }

    fn bridge_owner_list_index_key(scope_digest: &str, owner_kind: &str, sequence: u64) -> String {
        format!(
            "{}{sequence:020}",
            Self::bridge_owner_list_index_prefix(scope_digest, owner_kind)
        )
    }

    fn decode_bridge_owner_index_namespace(value: &str) -> Result<String, OrsError> {
        let namespace: String =
            serde_json::from_str(value).map_err(|error| OrsError::IntegrityProblem {
                record_type: "bridge_stream_owner_list_index",
                reason: error.to_string(),
            })?;
        crate::model::validate_digest(&namespace, "owner_namespace")?;
        Ok(namespace)
    }

    fn bridge_recovery_cut_key(window_key: &str, namespace: &str) -> String {
        format!("{window_key}::{namespace}")
    }

    fn bridge_owner_list_cutoff_in(write: &redb::WriteTransaction) -> Result<u64, OrsError> {
        let meta = write.open_table(META).map_err(storage)?;
        let Some(value) = meta.get(BRIDGE_OWNER_LIST_SEQUENCE_KEY).map_err(storage)? else {
            return Ok(0);
        };
        value
            .value()
            .parse::<u64>()
            .map_err(|_| OrsError::IntegrityProblem {
                record_type: "bridge_owner_list_sequence",
                reason: "owner-list sequence is not an unsigned integer".to_owned(),
            })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "window cleanup, identity issuance, and cutoff commit share one transaction"
    )]
    fn create_bridge_recovery_window_in(
        write: &redb::WriteTransaction,
        lineage: &str,
        principal: &str,
    ) -> Result<BridgeEventRecoveryWindowRow, OrsError> {
        let now_ms = current_unix_ms_u64()?;
        let expired = {
            let windows = write
                .open_table(BRIDGE_EVENT_RECOVERY_WINDOWS)
                .map_err(storage)?;
            if windows.len().map_err(storage)? > MAX_BRIDGE_RECOVERY_WINDOWS as u64 {
                return Err(OrsError::ProjectionLimitExceeded);
            }
            let mut expired = Vec::new();
            for entry in windows.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                let row: BridgeEventRecoveryWindowRow = decode(value.value())?;
                row.validate()?;
                if row.window_key != key.value() {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_event_recovery_window",
                        reason: "window key does not match its table key".to_owned(),
                    });
                }
                if row.expires_at_ms <= now_ms {
                    expired.push(row.window_key);
                }
            }
            expired
        };
        if !expired.is_empty() {
            {
                let mut windows = write
                    .open_table(BRIDGE_EVENT_RECOVERY_WINDOWS)
                    .map_err(storage)?;
                for key in &expired {
                    windows.remove(key.as_str()).map_err(storage)?;
                }
            }
            let prefixes: Vec<String> = expired.iter().map(|key| format!("{key}::")).collect();
            let cut_keys = {
                let cuts = write
                    .open_table(BRIDGE_EVENT_RECOVERY_CUTS)
                    .map_err(storage)?;
                if cuts.len().map_err(storage)? > MAX_BRIDGE_RECOVERY_CUTS as u64 {
                    return Err(OrsError::ProjectionLimitExceeded);
                }
                let mut keys = Vec::new();
                for entry in cuts.iter().map_err(storage)? {
                    let (key, _) = entry.map_err(storage)?;
                    if prefixes
                        .iter()
                        .any(|prefix| key.value().starts_with(prefix))
                    {
                        keys.push(key.value().to_owned());
                    }
                }
                keys
            };
            let mut cuts = write
                .open_table(BRIDGE_EVENT_RECOVERY_CUTS)
                .map_err(storage)?;
            for key in cut_keys {
                cuts.remove(key.as_str()).map_err(storage)?;
            }
        }
        {
            let windows = write
                .open_table(BRIDGE_EVENT_RECOVERY_WINDOWS)
                .map_err(storage)?;
            if windows.len().map_err(storage)? >= MAX_BRIDGE_RECOVERY_WINDOWS as u64 {
                return Err(OrsError::ProjectionLimitExceeded);
            }
        }
        let scope = Self::bridge_owner_scope_digest(lineage, principal)?;
        let sequence = {
            let meta = write.open_table(META).map_err(storage)?;
            match meta
                .get(BRIDGE_RECOVERY_WINDOW_SEQUENCE_KEY)
                .map_err(storage)?
            {
                Some(value) => {
                    value
                        .value()
                        .parse::<u64>()
                        .map_err(|_| OrsError::IntegrityProblem {
                            record_type: "bridge_recovery_window_sequence",
                            reason: "window sequence is not an unsigned integer".to_owned(),
                        })?
                }
                None => 0,
            }
        }
        .checked_add(1)
        .ok_or(OrsError::ProjectionLimitExceeded)?;
        let cutoff = Self::bridge_owner_list_cutoff_in(write)?;
        let key_material = format!(
            "eliot.bridge-event.recovery-window.v1\x1f{lineage}\x1f{principal}\x1f{now_ms}\x1f{sequence}"
        );
        let window_key = crate::model::sha256_hex(key_material.as_bytes());
        let row = BridgeEventRecoveryWindowRow {
            version: 1,
            window_key: window_key.clone(),
            authority_lineage: lineage.to_owned(),
            principal: principal.to_owned(),
            owner_scope_digest: scope,
            owner_cutoff: cutoff,
            created_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(BRIDGE_RECOVERY_WINDOW_TTL_MS),
            stream_list_complete: false,
            stream_list_continuation: None,
        };
        row.validate()?;
        {
            let mut meta = write.open_table(META).map_err(storage)?;
            meta.insert(
                BRIDGE_RECOVERY_WINDOW_SEQUENCE_KEY,
                sequence.to_string().as_str(),
            )
            .map_err(storage)?;
        }
        let mut windows = write
            .open_table(BRIDGE_EVENT_RECOVERY_WINDOWS)
            .map_err(storage)?;
        windows
            .insert(window_key.as_str(), encode(&row)?.as_str())
            .map_err(storage)?;
        Ok(row)
    }

    fn load_bridge_recovery_window(
        database: &redb::ReadTransaction,
        window_key: &str,
        lineage: &str,
        principal: &str,
    ) -> Result<Option<BridgeEventRecoveryWindowRow>, OrsError> {
        crate::model::validate_digest(window_key, "window_key")?;
        let windows = database
            .open_table(BRIDGE_EVENT_RECOVERY_WINDOWS)
            .map_err(storage)?;
        let Some(value) = windows.get(window_key).map_err(storage)? else {
            return Ok(None);
        };
        let row: BridgeEventRecoveryWindowRow = decode(value.value())?;
        row.validate()?;
        if row.window_key != window_key {
            return Err(OrsError::IntegrityProblem {
                record_type: "bridge_event_recovery_window",
                reason: "window key does not match its table key".to_owned(),
            });
        }
        if row.authority_lineage != lineage || row.principal != principal {
            return Err(OrsError::RecoveryOwnerMismatch);
        }
        Ok(Some(row))
    }

    fn load_bridge_recovery_window_in(
        write: &redb::WriteTransaction,
        window_key: &str,
        lineage: &str,
        principal: &str,
    ) -> Result<Option<BridgeEventRecoveryWindowRow>, OrsError> {
        crate::model::validate_digest(window_key, "window_key")?;
        let windows = write
            .open_table(BRIDGE_EVENT_RECOVERY_WINDOWS)
            .map_err(storage)?;
        let Some(value) = windows.get(window_key).map_err(storage)? else {
            return Ok(None);
        };
        let row: BridgeEventRecoveryWindowRow = decode(value.value())?;
        row.validate()?;
        if row.window_key != window_key {
            return Err(OrsError::IntegrityProblem {
                record_type: "bridge_event_recovery_window",
                reason: "window key does not match its table key".to_owned(),
            });
        }
        if row.authority_lineage != lineage || row.principal != principal {
            return Err(OrsError::RecoveryOwnerMismatch);
        }
        Ok(Some(row))
    }

    fn save_bridge_recovery_window_in(
        write: &redb::WriteTransaction,
        row: &BridgeEventRecoveryWindowRow,
    ) -> Result<(), OrsError> {
        row.validate()?;
        let mut windows = write
            .open_table(BRIDGE_EVENT_RECOVERY_WINDOWS)
            .map_err(storage)?;
        windows
            .insert(row.window_key.as_str(), encode(row)?.as_str())
            .map_err(storage)?;
        Ok(())
    }

    fn load_bridge_recovery_cut(
        database: &redb::ReadTransaction,
        window_key: &str,
        namespace: &str,
    ) -> Result<Option<BridgeEventRecoveryCutRow>, OrsError> {
        crate::model::validate_digest(window_key, "window_key")?;
        crate::model::validate_digest(namespace, "owner_namespace")?;
        let key = Self::bridge_recovery_cut_key(window_key, namespace);
        let cuts = database
            .open_table(BRIDGE_EVENT_RECOVERY_CUTS)
            .map_err(storage)?;
        let Some(value) = cuts.get(key.as_str()).map_err(storage)? else {
            return Ok(None);
        };
        let row: BridgeEventRecoveryCutRow = decode(value.value())?;
        row.validate()?;
        if row.window_key != window_key || row.namespace != namespace {
            return Err(OrsError::IntegrityProblem {
                record_type: "bridge_event_recovery_cut",
                reason: "recovery cut identity does not match its table key".to_owned(),
            });
        }
        Ok(Some(row))
    }

    fn load_bridge_recovery_cut_in(
        write: &redb::WriteTransaction,
        window_key: &str,
        namespace: &str,
    ) -> Result<Option<BridgeEventRecoveryCutRow>, OrsError> {
        crate::model::validate_digest(window_key, "window_key")?;
        crate::model::validate_digest(namespace, "owner_namespace")?;
        let key = Self::bridge_recovery_cut_key(window_key, namespace);
        let cuts = write
            .open_table(BRIDGE_EVENT_RECOVERY_CUTS)
            .map_err(storage)?;
        let Some(value) = cuts.get(key.as_str()).map_err(storage)? else {
            return Ok(None);
        };
        let row: BridgeEventRecoveryCutRow = decode(value.value())?;
        row.validate()?;
        if row.window_key != window_key || row.namespace != namespace {
            return Err(OrsError::IntegrityProblem {
                record_type: "bridge_event_recovery_cut",
                reason: "recovery cut identity does not match its table key".to_owned(),
            });
        }
        Ok(Some(row))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "closed validation covers all tagged recovery selectors before any store access"
    )]
    fn parse_bridge_recovery_scope(
        scope: Option<&serde_json::Value>,
    ) -> Result<BridgeRecoveryScopeSelector, OrsError> {
        let Some(scope) = scope else {
            return Ok(BridgeRecoveryScopeSelector::Open);
        };
        if scope.is_null() {
            return Ok(BridgeRecoveryScopeSelector::Open);
        }
        let object = scope.as_object().ok_or(OrsError::InvalidField {
            field: "recovery_scope",
            reason: "recovery scope must be an object",
        })?;
        if object.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
            return Err(OrsError::InvalidField {
                field: "recovery_scope.version",
                reason: "recovery scope version 1 is required",
            });
        }
        let kind = object
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or(OrsError::InvalidField {
                field: "recovery_scope.kind",
                reason: "recovery scope requires a tagged kind",
            })?;
        let reject_unknown = |allowed: &[&str]| -> Result<(), OrsError> {
            if object.keys().any(|key| !allowed.contains(&key.as_str())) {
                return Err(OrsError::InvalidField {
                    field: "recovery_scope",
                    reason: "recovery scope carries an unsupported field",
                });
            }
            Ok(())
        };
        let number = |name: &'static str, default: Option<u64>| -> Result<u64, OrsError> {
            match object.get(name) {
                Some(value) => value.as_u64().ok_or(OrsError::InvalidField {
                    field: name,
                    reason: "recovery scope field must be an unsigned integer",
                }),
                None => default.ok_or(OrsError::InvalidField {
                    field: name,
                    reason: "recovery scope field is required",
                }),
            }
        };
        let text = |name: &'static str| -> Result<String, OrsError> {
            let value = object.get(name).and_then(serde_json::Value::as_str).ok_or(
                OrsError::InvalidField {
                    field: name,
                    reason: "recovery scope field must be text",
                },
            )?;
            crate::model::validate_text(value, name)?;
            Ok(value.to_owned())
        };
        let checked_limit = |name: &'static str, default: u64, maximum: usize| {
            let value = number(name, Some(default))?;
            let limit = usize::try_from(value).map_err(|_| OrsError::InvalidCursorLimit)?;
            if limit == 0 || limit > maximum {
                return Err(OrsError::InvalidCursorLimit);
            }
            Ok(limit)
        };
        match kind {
            "open" => {
                reject_unknown(&["version", "kind"])?;
                Ok(BridgeRecoveryScopeSelector::Open)
            }
            "streams" => {
                reject_unknown(&[
                    "version",
                    "kind",
                    "window_key",
                    "after_stream",
                    "stream_limit",
                ])?;
                let window_key = text("window_key")?;
                crate::model::validate_digest(&window_key, "window_key")?;
                let after_stream =
                    text("after_stream")?
                        .parse::<u64>()
                        .map_err(|_| OrsError::InvalidField {
                            field: "after_stream",
                            reason: "stream-list continuation must be a decimal owner cursor",
                        })?;
                let stream_limit = checked_limit(
                    "stream_limit",
                    MAX_BRIDGE_RECOVERY_STREAMS_PER_PAGE as u64,
                    MAX_BRIDGE_RECOVERY_STREAMS_PER_PAGE,
                )?;
                Ok(BridgeRecoveryScopeSelector::Streams {
                    window_key,
                    after_stream,
                    stream_limit,
                    selected_scope: scope.clone(),
                })
            }
            "stream" => {
                reject_unknown(&[
                    "version",
                    "kind",
                    "window_key",
                    "stream_id",
                    "after_sequence",
                    "upper_sequence",
                    "expected_revision",
                    "retention_floor",
                    "event_limit",
                    "gap_offset",
                    "gap_limit",
                ])?;
                let window_key = text("window_key")?;
                crate::model::validate_digest(&window_key, "window_key")?;
                let stream_id = text("stream_id")?;
                bridge_identity_text(&stream_id, "stream_id")?;
                let after_sequence = number("after_sequence", None)?;
                let upper_sequence = number("upper_sequence", None)?;
                let expected_revision = number("expected_revision", None)?;
                let retention_floor = number("retention_floor", None)?;
                let event_limit = checked_limit(
                    "event_limit",
                    MAX_BRIDGE_EVENT_PAGE as u64,
                    MAX_BRIDGE_EVENT_PAGE,
                )?;
                let gap_offset = usize::try_from(number("gap_offset", Some(0))?)
                    .map_err(|_| OrsError::InvalidCursorLimit)?;
                let gap_limit = checked_limit(
                    "gap_limit",
                    MAX_BRIDGE_EVENT_GAPS_PER_STREAM as u64,
                    MAX_BRIDGE_EVENT_GAPS_PER_STREAM,
                )?;
                Ok(BridgeRecoveryScopeSelector::Stream {
                    window_key,
                    stream_id,
                    after_sequence,
                    upper_sequence,
                    expected_revision,
                    retention_floor,
                    event_limit,
                    gap_offset,
                    gap_limit,
                    selected_scope: scope.clone(),
                })
            }
            "unscoped_gaps" => {
                reject_unknown(&[
                    "version",
                    "kind",
                    "window_key",
                    "after_gap_scope",
                    "gap_offset",
                    "gap_limit",
                ])?;
                let window_key = text("window_key")?;
                crate::model::validate_digest(&window_key, "window_key")?;
                let after_gap_scope = text("after_gap_scope")?;
                crate::model::validate_digest(&after_gap_scope, "after_gap_scope")?;
                let gap_offset = usize::try_from(number("gap_offset", Some(0))?)
                    .map_err(|_| OrsError::InvalidCursorLimit)?;
                let gap_limit = checked_limit(
                    "gap_limit",
                    MAX_BRIDGE_EVENT_GAPS_PER_STREAM as u64,
                    MAX_BRIDGE_EVENT_GAPS_PER_STREAM,
                )?;
                Ok(BridgeRecoveryScopeSelector::UnscopedGaps {
                    window_key,
                    after_gap_scope,
                    gap_offset,
                    gap_limit,
                    selected_scope: scope.clone(),
                })
            }
            _ => Err(OrsError::InvalidField {
                field: "recovery_scope.kind",
                reason: "recovery scope kind is unsupported",
            }),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "owner cursor, gap bound, and revision form one persisted finite cut"
    )]
    fn create_bridge_recovery_cut_in(
        write: &redb::WriteTransaction,
        window_key: &str,
        owner: &BridgeStreamOwnerRow,
    ) -> Result<BridgeEventRecoveryCutRow, OrsError> {
        if let Some(existing) =
            Self::load_bridge_recovery_cut_in(write, window_key, &owner.namespace)?
        {
            if existing.owner_kind != owner.kind
                || existing.local_stream != owner.local_stream
                || existing.producer != owner.producer
                || existing.owner_incarnation != owner.incarnation
                || existing.owner_revision != owner.revision
            {
                return Err(OrsError::RecoveryOwnerMismatch);
            }
            return Ok(existing);
        }
        let (durable_cursor, acked_cursor, observed_upper, compacted, stager, generation) =
            if owner.kind == BRIDGE_STREAM_OWNER_KIND_STREAM {
                let cursors = write.open_table(BRIDGE_EVENT_CURSORS).map_err(storage)?;
                match cursors.get(owner.namespace.as_str()).map_err(storage)? {
                    Some(value) => {
                        let cursor: BridgeEventCursorRow = decode(value.value())?;
                        cursor.validate()?;
                        if cursor.owner_namespace != owner.namespace
                            || cursor.stream_id != owner.local_stream
                        {
                            return Err(OrsError::RecoveryOwnerMismatch);
                        }
                        (
                            cursor.last_durable_sequence,
                            cursor.last_acked_sequence,
                            cursor
                                .last_observed_sequence
                                .max(cursor.last_durable_sequence),
                            cursor.last_compacted_sequence,
                            cursor.last_staging_connection,
                            cursor.last_producer_generation,
                        )
                    }
                    None => (0, 0, 0, 0, String::new(), 0),
                }
            } else {
                (0, 0, 0, 0, String::new(), 0)
            };
        let mut upper_sequence = observed_upper;
        if owner.kind == BRIDGE_STREAM_OWNER_KIND_STREAM {
            let prefix = format!("{}::", owner.namespace);
            let end = format!("{prefix}\u{10ffff}");
            let gaps = write.open_table(BRIDGE_EVENT_GAPS).map_err(storage)?;
            let mut count = 0_usize;
            for entry in gaps
                .range(prefix.as_str()..=end.as_str())
                .map_err(storage)?
            {
                let (key, value) = entry.map_err(storage)?;
                let gap: BridgeEventGapRow = decode(value.value())?;
                gap.validate()?;
                if gap.owner_namespace != owner.namespace
                    || key.value() != format!("{}::{}", owner.namespace, gap.gap_id)
                {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_event_gap",
                        reason: "gap key or owner does not match its indexed scope".to_owned(),
                    });
                }
                count = count.saturating_add(1);
                if count > MAX_BRIDGE_EVENT_GAPS_PER_STREAM {
                    return Err(OrsError::ProjectionLimitExceeded);
                }
                upper_sequence = upper_sequence.max(gap.end_sequence);
            }
        }
        let retention_floor = if upper_sequence == 0 {
            0
        } else {
            compacted.saturating_add(1).min(upper_sequence)
        };
        let expected_revision = Self::bridge_recovery_revision_for_in(write, &owner.namespace)?;
        let cut = BridgeEventRecoveryCutRow {
            version: 1,
            window_key: window_key.to_owned(),
            namespace: owner.namespace.clone(),
            owner_kind: owner.kind.clone(),
            local_stream: owner.local_stream.clone(),
            producer: owner.producer.clone(),
            owner_incarnation: owner.incarnation,
            owner_revision: owner.revision,
            expected_revision,
            upper_sequence,
            retention_floor,
            durable_cursor,
            acked_cursor,
            last_staging_connection: stager,
            last_producer_generation: generation,
        };
        cut.validate()?;
        {
            let cuts = write
                .open_table(BRIDGE_EVENT_RECOVERY_CUTS)
                .map_err(storage)?;
            if cuts.len().map_err(storage)? >= MAX_BRIDGE_RECOVERY_CUTS as u64 {
                return Err(OrsError::ProjectionLimitExceeded);
            }
        }
        let key = Self::bridge_recovery_cut_key(window_key, &owner.namespace);
        let mut cuts = write
            .open_table(BRIDGE_EVENT_RECOVERY_CUTS)
            .map_err(storage)?;
        cuts.insert(key.as_str(), encode(&cut)?.as_str())
            .map_err(storage)?;
        Ok(cut)
    }

    fn bridge_recovery_gap_page(
        database: &redb::ReadTransaction,
        namespace: &str,
        offset: usize,
        limit: usize,
        byte_limit: usize,
    ) -> Result<(Vec<serde_json::Value>, Option<u64>), OrsError> {
        crate::model::validate_digest(namespace, "owner_namespace")?;
        if offset > MAX_BRIDGE_EVENT_GAPS_PER_STREAM {
            return Err(OrsError::InvalidCursorLimit);
        }
        let prefix = format!("{namespace}::");
        let end = format!("{prefix}\u{10ffff}");
        let mut rows = Vec::new();
        {
            let gaps = database.open_table(BRIDGE_EVENT_GAPS).map_err(storage)?;
            for entry in gaps
                .range(prefix.as_str()..=end.as_str())
                .map_err(storage)?
            {
                let (key, value) = entry.map_err(storage)?;
                let row: BridgeEventGapRow = decode(value.value())?;
                row.validate()?;
                if row.owner_namespace != namespace
                    || key.value() != format!("{namespace}::{}", row.gap_id)
                {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_event_gap",
                        reason: "gap key or owner does not match its indexed scope".to_owned(),
                    });
                }
                if rows.len() >= MAX_BRIDGE_EVENT_GAPS_PER_STREAM {
                    return Err(OrsError::ProjectionLimitExceeded);
                }
                rows.push(row);
            }
        }
        rows.sort_by_key(|row| (row.start_sequence, row.gap_id.clone()));
        let start = offset.min(rows.len());
        let end_offset = start.saturating_add(limit).min(rows.len());
        let mut page = Vec::with_capacity(end_offset.saturating_sub(start));
        let mut page_bytes = 0_usize;
        for row in &rows[start..end_offset] {
            let item = json!({
                "gap_id": row.gap_id,
                "stream_id": row.stream_id,
                "start_sequence": row.start_sequence,
                "end_sequence": row.end_sequence,
                "reason_ref": row.reason_ref,
            });
            let item_bytes = serde_json::to_vec(&item)
                .map_err(|_| OrsError::ProjectionLimitExceeded)?
                .len();
            if page_bytes.saturating_add(item_bytes) > byte_limit {
                if page.is_empty() {
                    return Err(OrsError::ProjectionLimitExceeded);
                }
                break;
            }
            page_bytes = page_bytes.saturating_add(item_bytes);
            page.push(item);
        }
        let page_end = start.saturating_add(page.len());
        let continuation = (page_end < rows.len()).then_some(page_end as u64);
        Ok((page, continuation))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "bounded event and gap facts are assembled from one read snapshot"
    )]
    fn bridge_recovery_stream_page(
        database: &redb::ReadTransaction,
        owner: &BridgeStreamOwnerRow,
        cut: &BridgeEventRecoveryCutRow,
        owner_list_position: u64,
        after_sequence: u64,
        budget: BridgeRecoveryPageBudget,
    ) -> Result<(serde_json::Value, bool), OrsError> {
        let BridgeRecoveryPageBudget {
            event_limit,
            event_byte_limit,
            gap_offset,
            gap_limit,
            gap_byte_limit,
        } = budget;
        if owner.kind != BRIDGE_STREAM_OWNER_KIND_STREAM
            || cut.owner_kind != BRIDGE_STREAM_OWNER_KIND_STREAM
            || cut.namespace != owner.namespace
            || after_sequence > cut.upper_sequence
        {
            return Err(OrsError::RecoveryOwnerMismatch);
        }
        let mut indexed = Vec::new();
        if after_sequence < cut.upper_sequence {
            let start_sequence = after_sequence.saturating_add(1);
            let start = Self::bridge_position_key(&owner.namespace, start_sequence);
            let end = Self::bridge_position_key(&owner.namespace, cut.upper_sequence);
            let positions = database
                .open_table(BRIDGE_EVENT_POSITIONS)
                .map_err(storage)?;
            for entry in positions
                .range(start.as_str()..=end.as_str())
                .map_err(storage)?
                .take(event_limit.saturating_add(1))
            {
                let (key, value) = entry.map_err(storage)?;
                let (namespace, sequence) = Self::parse_bridge_position_key(key.value())?;
                if namespace != owner.namespace
                    || sequence <= after_sequence
                    || sequence > cut.upper_sequence
                {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_event_position",
                        reason: "position range escaped the declared stream interval".to_owned(),
                    });
                }
                let position: BridgeEventPosition = decode(value.value())?;
                position.validate()?;
                indexed.push((sequence, position.event_id));
            }
        }
        let mut has_more_events = indexed.len() > event_limit;
        if has_more_events {
            indexed.truncate(event_limit);
        }
        let mut items = Vec::with_capacity(indexed.len());
        let mut item_bytes_total = 0_usize;
        let mut included_sequences = Vec::with_capacity(indexed.len());
        {
            let records = database.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
            for (sequence, event_id) in &indexed {
                let key = format!("{}::{event_id}", owner.namespace);
                let Some(value) = records.get(key.as_str()).map_err(storage)? else {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_event_position",
                        reason: "declared retained position has no live event record".to_owned(),
                    });
                };
                let row: BridgeEventRow = decode(value.value())?;
                row.validate()?;
                if row.owner_namespace != owner.namespace
                    || row.stream_id != owner.local_stream
                    || row.event_id != *event_id
                    || row.sequence != *sequence
                {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_event_record",
                        reason: "position index and retained event identity disagree".to_owned(),
                    });
                }
                let item = json!({
                    "event_id": row.event_id,
                    "sequence": row.sequence,
                    "phase": row.phase,
                    "disposition": "accepted",
                    "envelope_sha256": row.envelope_sha256,
                    "producer_id": row.producer_id,
                    "producer_generation": row.producer_generation,
                    "staging_connection": row.staging_connection,
                    "covered_by_durable_cursor": row.sequence <= cut.durable_cursor,
                });
                let item_bytes = serde_json::to_vec(&item)
                    .map_err(|_| OrsError::ProjectionLimitExceeded)?
                    .len();
                if item_bytes_total.saturating_add(item_bytes) > event_byte_limit {
                    if items.is_empty() {
                        return Err(OrsError::ProjectionLimitExceeded);
                    }
                    has_more_events = true;
                    break;
                }
                item_bytes_total = item_bytes_total.saturating_add(item_bytes);
                included_sequences.push(*sequence);
                items.push(item);
            }
        }
        let continuation = if has_more_events {
            included_sequences.last().copied()
        } else {
            None
        };
        let (gaps, gap_continuation) = Self::bridge_recovery_gap_page(
            database,
            &owner.namespace,
            gap_offset,
            gap_limit,
            gap_byte_limit,
        )?;
        let last_event_sequence = included_sequences.last().copied().unwrap_or(after_sequence);
        let suffix_covered_by_gap = gaps.iter().any(|gap| {
            let start = gap
                .get("start_sequence")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(u64::MAX);
            let end = gap
                .get("end_sequence")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            start <= last_event_sequence.saturating_add(1) && end >= cut.upper_sequence
        });
        let suffix_proven = continuation.is_some()
            || gap_continuation.is_some()
            || after_sequence >= cut.upper_sequence
            || last_event_sequence >= cut.upper_sequence
            || suffix_covered_by_gap;
        let page = json!({
            "stream_id": owner.local_stream,
            "owner_list_position": owner_list_position,
            "durable_cursor": cut.durable_cursor,
            "acked_cursor": cut.acked_cursor,
            "last_staging_connection": cut.last_staging_connection,
            "last_producer_generation": cut.last_producer_generation,
            "producer_id": owner.producer,
            "owner_incarnation": owner.incarnation,
            "owner_revision": owner.revision,
            "expected_revision": cut.expected_revision,
            "retention_floor": cut.retention_floor,
            "upper_sequence": cut.upper_sequence,
            "pending_first_page": {
                "stream_id": owner.local_stream,
                "durable_cursor": cut.durable_cursor,
                "acked_cursor": cut.acked_cursor,
                "items": items,
                "continuation": continuation,
            },
            "gaps": gaps,
            "gap_continuation": gap_continuation,
        });
        Ok((page, suffix_proven))
    }

    fn index_bridge_stream_owner_in(
        write: &redb::WriteTransaction,
        row: &BridgeStreamOwnerRow,
    ) -> Result<(), OrsError> {
        let current = Self::bridge_owner_list_cutoff_in(write)?;
        let next = current
            .checked_add(1)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        let scope = Self::bridge_owner_scope_digest(&row.authority_lineage, &row.principal)?;
        let key = Self::bridge_owner_list_index_key(&scope, &row.kind, next);
        {
            let mut index = write
                .open_table(BRIDGE_STREAM_OWNER_LIST_INDEX)
                .map_err(storage)?;
            if index.get(key.as_str()).map_err(storage)?.is_some() {
                return Err(OrsError::DuplicateConflict);
            }
            index
                .insert(key.as_str(), encode(&row.namespace)?.as_str())
                .map_err(storage)?;
        }
        let mut meta = write.open_table(META).map_err(storage)?;
        meta.insert(BRIDGE_OWNER_LIST_SEQUENCE_KEY, next.to_string().as_str())
            .map_err(storage)?;
        Ok(())
    }

    fn bridge_recovery_owner_page_in(
        write: &redb::WriteTransaction,
        window: &BridgeEventRecoveryWindowRow,
        owner_kind: &str,
        after_sequence: u64,
        limit: usize,
    ) -> Result<BridgeRecoveryOwnerPage, OrsError> {
        let mut rows = Vec::with_capacity(limit);
        if after_sequence >= window.owner_cutoff {
            return Ok(BridgeRecoveryOwnerPage {
                owners: rows,
                continuation: None,
            });
        }
        let prefix = Self::bridge_owner_list_index_prefix(&window.owner_scope_digest, owner_kind);
        let start_sequence = after_sequence
            .checked_add(1)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        let start = format!("{prefix}{start_sequence:020}");
        let end = Self::bridge_owner_list_index_key(
            &window.owner_scope_digest,
            owner_kind,
            window.owner_cutoff,
        );
        let (has_more, last_sequence) = {
            let index = write
                .open_table(BRIDGE_STREAM_OWNER_LIST_INDEX)
                .map_err(storage)?;
            let owners = write.open_table(BRIDGE_STREAM_OWNERS).map_err(storage)?;
            let mut has_more = false;
            let mut last_sequence = None;
            for entry in index
                .range(start.as_str()..=end.as_str())
                .map_err(storage)?
                .take(limit.saturating_add(1))
            {
                let (key, value) = entry.map_err(storage)?;
                let sequence = key
                    .value()
                    .strip_prefix(prefix.as_str())
                    .and_then(|suffix| suffix.parse::<u64>().ok())
                    .ok_or(OrsError::IntegrityProblem {
                        record_type: "bridge_stream_owner_list_index",
                        reason: "owner-list key carries a malformed sequence".to_owned(),
                    })?;
                if sequence <= after_sequence || sequence > window.owner_cutoff {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_stream_owner_list_index",
                        reason: "owner-list page escaped the finite cutoff".to_owned(),
                    });
                }
                let namespace = Self::decode_bridge_owner_index_namespace(value.value())?;
                let Some(value) = owners.get(namespace.as_str()).map_err(storage)? else {
                    return Err(OrsError::RecoveryOwnerMismatch);
                };
                let row: BridgeStreamOwnerRow = decode(value.value())?;
                row.validate()?;
                if row.namespace != namespace
                    || row.kind != owner_kind
                    || row.authority_lineage != window.authority_lineage
                    || row.principal != window.principal
                {
                    return Err(OrsError::RecoveryOwnerMismatch);
                }
                if rows.len() == limit {
                    has_more = true;
                    break;
                }
                last_sequence = Some(sequence);
                rows.push((row, sequence));
            }
            (has_more, last_sequence)
        };
        let continuation = has_more.then(|| last_sequence.unwrap_or(after_sequence).to_string());
        Ok(BridgeRecoveryOwnerPage {
            owners: rows,
            continuation,
        })
    }

    fn bridge_recovery_owner_by_stream_in(
        write: &redb::WriteTransaction,
        window: &BridgeEventRecoveryWindowRow,
        stream_id: &str,
    ) -> Result<(BridgeStreamOwnerRow, u64), OrsError> {
        let prefix = Self::bridge_owner_list_index_prefix(
            &window.owner_scope_digest,
            BRIDGE_STREAM_OWNER_KIND_STREAM,
        );
        let end = Self::bridge_owner_list_index_key(
            &window.owner_scope_digest,
            BRIDGE_STREAM_OWNER_KIND_STREAM,
            window.owner_cutoff,
        );
        let index = write
            .open_table(BRIDGE_STREAM_OWNER_LIST_INDEX)
            .map_err(storage)?;
        let owners = write.open_table(BRIDGE_STREAM_OWNERS).map_err(storage)?;
        let mut found: Option<(BridgeStreamOwnerRow, u64)> = None;
        for entry in index
            .range(prefix.as_str()..=end.as_str())
            .map_err(storage)?
            .take(MAX_BRIDGE_STREAM_OWNERS.saturating_add(1))
        {
            let (key, value) = entry.map_err(storage)?;
            let sequence = key
                .value()
                .strip_prefix(prefix.as_str())
                .and_then(|suffix| suffix.parse::<u64>().ok())
                .ok_or(OrsError::IntegrityProblem {
                    record_type: "bridge_stream_owner_list_index",
                    reason: "owner-list key carries a malformed sequence".to_owned(),
                })?;
            if sequence > window.owner_cutoff {
                continue;
            }
            let namespace = Self::decode_bridge_owner_index_namespace(value.value())?;
            let Some(owner_value) = owners.get(namespace.as_str()).map_err(storage)? else {
                return Err(OrsError::RecoveryOwnerMismatch);
            };
            let row: BridgeStreamOwnerRow = decode(owner_value.value())?;
            row.validate()?;
            if row.namespace != namespace
                || row.kind != BRIDGE_STREAM_OWNER_KIND_STREAM
                || row.authority_lineage != window.authority_lineage
                || row.principal != window.principal
            {
                return Err(OrsError::RecoveryOwnerMismatch);
            }
            if row.local_stream == stream_id {
                if found.is_some() {
                    return Err(OrsError::RecoveryOwnerMismatch);
                }
                found = Some((row, sequence));
            }
        }
        found.ok_or(OrsError::RecoveryOwnerMismatch)
    }

    fn bridge_recovery_owner_sequence_in(
        write: &redb::WriteTransaction,
        window: &BridgeEventRecoveryWindowRow,
        owner_kind: &str,
        namespace: &str,
    ) -> Result<u64, OrsError> {
        let prefix = Self::bridge_owner_list_index_prefix(&window.owner_scope_digest, owner_kind);
        let end = Self::bridge_owner_list_index_key(
            &window.owner_scope_digest,
            owner_kind,
            window.owner_cutoff,
        );
        let index = write
            .open_table(BRIDGE_STREAM_OWNER_LIST_INDEX)
            .map_err(storage)?;
        for entry in index
            .range(prefix.as_str()..=end.as_str())
            .map_err(storage)?
            .take(MAX_BRIDGE_STREAM_OWNERS.saturating_add(1))
        {
            let (key, value) = entry.map_err(storage)?;
            let candidate = Self::decode_bridge_owner_index_namespace(value.value())?;
            if candidate == namespace {
                return key
                    .value()
                    .strip_prefix(prefix.as_str())
                    .and_then(|suffix| suffix.parse::<u64>().ok())
                    .ok_or(OrsError::IntegrityProblem {
                        record_type: "bridge_stream_owner_list_index",
                        reason: "owner-list key carries a malformed sequence".to_owned(),
                    });
            }
        }
        Err(OrsError::RecoveryOwnerMismatch)
    }

    fn bridge_recovery_next_gap_owner(
        read: &redb::ReadTransaction,
        window: &BridgeEventRecoveryWindowRow,
        after_sequence: u64,
    ) -> Result<Option<(BridgeStreamOwnerRow, u64)>, OrsError> {
        if after_sequence >= window.owner_cutoff {
            return Ok(None);
        }
        let prefix = Self::bridge_owner_list_index_prefix(
            &window.owner_scope_digest,
            BRIDGE_STREAM_OWNER_KIND_UNSCOPED_GAP,
        );
        let start_sequence = after_sequence
            .checked_add(1)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        let start = format!("{prefix}{start_sequence:020}");
        let end = Self::bridge_owner_list_index_key(
            &window.owner_scope_digest,
            BRIDGE_STREAM_OWNER_KIND_UNSCOPED_GAP,
            window.owner_cutoff,
        );
        let index = read
            .open_table(BRIDGE_STREAM_OWNER_LIST_INDEX)
            .map_err(storage)?;
        let owners = read.open_table(BRIDGE_STREAM_OWNERS).map_err(storage)?;
        let Some(entry) = index
            .range(start.as_str()..=end.as_str())
            .map_err(storage)?
            .next()
        else {
            return Ok(None);
        };
        let (key, value) = entry.map_err(storage)?;
        let sequence = key
            .value()
            .strip_prefix(prefix.as_str())
            .and_then(|suffix| suffix.parse::<u64>().ok())
            .ok_or(OrsError::IntegrityProblem {
                record_type: "bridge_stream_owner_list_index",
                reason: "gap-owner cursor carries a malformed sequence".to_owned(),
            })?;
        let namespace = Self::decode_bridge_owner_index_namespace(value.value())?;
        let Some(owner_value) = owners.get(namespace.as_str()).map_err(storage)? else {
            return Err(OrsError::RecoveryOwnerMismatch);
        };
        let owner: BridgeStreamOwnerRow = decode(owner_value.value())?;
        owner.validate()?;
        if owner.namespace != namespace
            || owner.kind != BRIDGE_STREAM_OWNER_KIND_UNSCOPED_GAP
            || owner.authority_lineage != window.authority_lineage
            || owner.principal != window.principal
            || sequence > window.owner_cutoff
        {
            return Err(OrsError::RecoveryOwnerMismatch);
        }
        Ok(Some((owner, sequence)))
    }

    fn bridge_recovery_unproven_scope_present(
        read: &redb::ReadTransaction,
        _window: &BridgeEventRecoveryWindowRow,
    ) -> Result<bool, OrsError> {
        let meta = read.open_table(META).map_err(storage)?;
        let marker = meta
            .get(BRIDGE_RECOVERY_LEGACY_UNPROVEN_KEY)
            .map_err(storage)?
            .map(|value| value.value().to_owned());
        match marker.as_deref() {
            Some("false") => Ok(false),
            Some("true") | None => Ok(true),
            Some(_) => Err(OrsError::IntegrityProblem {
                record_type: "bridge_recovery_legacy_unproven",
                reason: "legacy recovery marker is not boolean".to_owned(),
            }),
        }
    }

    fn bridge_recovery_empty_reply(
        window: &BridgeEventRecoveryWindowRow,
        status: &str,
        selected_scope: &serde_json::Value,
    ) -> serde_json::Value {
        json!({
            "window_key": window.window_key,
            "window_status": status,
            "selected_scope": selected_scope,
            "stream_list_complete": false,
            "stream_list_continuation": window.stream_list_continuation,
            "unscoped_gaps_complete": false,
            "unscoped_gaps_continuation": serde_json::Value::Null,
            "streams": [],
            "unscoped_gaps": [],
            "unproven_scope_present": true,
        })
    }

    fn bump_bridge_recovery_revision_in(
        write: &redb::WriteTransaction,
        namespace: &str,
    ) -> Result<u64, OrsError> {
        crate::model::validate_digest(namespace, "owner_namespace")?;
        let prior: Option<BridgeEventRecoveryRevisionRow> = {
            let revisions = write
                .open_table(BRIDGE_EVENT_RECOVERY_REVISIONS)
                .map_err(storage)?;
            revisions
                .get(namespace)
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
        };
        let revision = prior.map_or(1, |row| row.revision.saturating_add(1));
        if revision == u64::MAX {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        let row = BridgeEventRecoveryRevisionRow {
            version: 1,
            namespace: namespace.to_owned(),
            revision,
        };
        row.validate()?;
        let mut revisions = write
            .open_table(BRIDGE_EVENT_RECOVERY_REVISIONS)
            .map_err(storage)?;
        revisions
            .insert(namespace, encode(&row)?.as_str())
            .map_err(storage)?;
        Ok(revision)
    }

    fn bridge_recovery_revision_for_in(
        write: &redb::WriteTransaction,
        namespace: &str,
    ) -> Result<u64, OrsError> {
        let revisions = write
            .open_table(BRIDGE_EVENT_RECOVERY_REVISIONS)
            .map_err(storage)?;
        match revisions.get(namespace).map_err(storage)? {
            Some(value) => {
                let row: BridgeEventRecoveryRevisionRow = decode(value.value())?;
                row.validate()?;
                if row.namespace != namespace {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_event_recovery_revision",
                        reason: "recovery revision identity does not match its key".to_owned(),
                    });
                }
                Ok(row.revision)
            }
            None => Ok(1),
        }
    }

    fn bridge_recovery_revision_for(
        read: &redb::ReadTransaction,
        namespace: &str,
    ) -> Result<u64, OrsError> {
        let revisions = read
            .open_table(BRIDGE_EVENT_RECOVERY_REVISIONS)
            .map_err(storage)?;
        match revisions.get(namespace).map_err(storage)? {
            Some(value) => {
                let row: BridgeEventRecoveryRevisionRow = decode(value.value())?;
                row.validate()?;
                if row.namespace != namespace {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_event_recovery_revision",
                        reason: "recovery revision identity does not match its key".to_owned(),
                    });
                }
                Ok(row.revision)
            }
            None => Ok(1),
        }
    }

    fn rebuild_bridge_owner_list_index(write: &redb::WriteTransaction) -> Result<(), OrsError> {
        let marker: Option<String> = {
            let meta = write.open_table(META).map_err(storage)?;
            match meta
                .get(BRIDGE_OWNER_LIST_INDEX_SCHEMA_KEY)
                .map_err(storage)?
            {
                Some(value) if value.value().len() > MAX_ORS_MARKER_BYTES => {
                    return Err(OrsError::ProjectionLimitExceeded);
                }
                Some(value) => Some(value.value().to_owned()),
                None => None,
            }
        };
        match marker.as_deref() {
            Some(BRIDGE_OWNER_LIST_INDEX_SCHEMA_V2) => return Ok(()),
            Some("v1") => {
                let mut index = write
                    .open_table(BRIDGE_STREAM_OWNER_LIST_INDEX)
                    .map_err(storage)?;
                if index.len().map_err(storage)? > MAX_BRIDGE_STREAM_OWNERS as u64 {
                    return Err(OrsError::ProjectionLimitExceeded);
                }
                let keys: Vec<String> = index
                    .iter()
                    .map_err(storage)?
                    .map(|entry| {
                        entry
                            .map(|(key, _)| key.value().to_owned())
                            .map_err(storage)
                    })
                    .collect::<Result<_, _>>()?;
                for key in keys {
                    index.remove(key.as_str()).map_err(storage)?;
                }
            }
            Some(_) => {
                return Err(OrsError::MigrationRequired {
                    reason: "bridge owner-list index schema marker is not current".to_owned(),
                });
            }
            None => {}
        }
        let mut rows = {
            let owners = write.open_table(BRIDGE_STREAM_OWNERS).map_err(storage)?;
            let mut rows = Vec::new();
            for entry in owners.iter().map_err(storage)? {
                let (_, value) = entry.map_err(storage)?;
                let row: BridgeStreamOwnerRow = decode(value.value())?;
                row.validate()?;
                if rows.len() >= MAX_BRIDGE_STREAM_OWNERS {
                    return Err(OrsError::ProjectionLimitExceeded);
                }
                rows.push(row);
            }
            rows
        };
        rows.sort_by(|left, right| left.namespace.cmp(&right.namespace));
        let mut sequence = 0_u64;
        {
            let mut index = write
                .open_table(BRIDGE_STREAM_OWNER_LIST_INDEX)
                .map_err(storage)?;
            for row in rows {
                sequence = sequence
                    .checked_add(1)
                    .ok_or(OrsError::ProjectionLimitExceeded)?;
                let scope =
                    Self::bridge_owner_scope_digest(&row.authority_lineage, &row.principal)?;
                let key = Self::bridge_owner_list_index_key(&scope, &row.kind, sequence);
                index
                    .insert(key.as_str(), encode(&row.namespace)?.as_str())
                    .map_err(storage)?;
            }
        }
        let mut meta = write.open_table(META).map_err(storage)?;
        meta.insert(
            BRIDGE_OWNER_LIST_SEQUENCE_KEY,
            sequence.to_string().as_str(),
        )
        .map_err(storage)?;
        meta.insert(
            BRIDGE_OWNER_LIST_INDEX_SCHEMA_KEY,
            BRIDGE_OWNER_LIST_INDEX_SCHEMA_V2,
        )
        .map_err(storage)?;
        Ok(())
    }

    fn mark_bridge_recovery_legacy_unproven_in(
        write: &redb::WriteTransaction,
    ) -> Result<(), OrsError> {
        let mut meta = write.open_table(META).map_err(storage)?;
        meta.insert(BRIDGE_RECOVERY_LEGACY_UNPROVEN_KEY, "true")
            .map_err(storage)?;
        Ok(())
    }

    /// Records whether pre-owner legacy rows exist once at store open. Page
    /// reads consult this bounded metadata bit instead of sweeping event,
    /// cursor, gap, or handoff tables.
    fn initialize_bridge_recovery_legacy_unproven(
        write: &redb::WriteTransaction,
    ) -> Result<(), OrsError> {
        let prior = {
            let meta = write.open_table(META).map_err(storage)?;
            meta.get(BRIDGE_RECOVERY_LEGACY_UNPROVEN_KEY)
                .map_err(storage)?
                .map(|value| value.value().to_owned())
        };
        match prior.as_deref() {
            Some("true" | "false") => return Ok(()),
            Some(_) => {
                return Err(OrsError::IntegrityProblem {
                    record_type: "bridge_recovery_legacy_unproven",
                    reason: "legacy recovery marker is not boolean".to_owned(),
                });
            }
            None => {}
        }
        let owners = write.open_table(BRIDGE_STREAM_OWNERS).map_err(storage)?;
        let unproven = {
            let mut found = false;
            {
                let records = write.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
                for entry in records.iter().map_err(storage)? {
                    let (_, value) = entry.map_err(storage)?;
                    let row: BridgeEventRow = decode(value.value())?;
                    row.validate()?;
                    if row.owner_namespace.is_empty()
                        || owners
                            .get(row.owner_namespace.as_str())
                            .map_err(storage)?
                            .is_none()
                    {
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                let cursors = write.open_table(BRIDGE_EVENT_CURSORS).map_err(storage)?;
                for entry in cursors.iter().map_err(storage)? {
                    let (_, value) = entry.map_err(storage)?;
                    let row: BridgeEventCursorRow = decode(value.value())?;
                    row.validate()?;
                    if row.owner_namespace.is_empty()
                        || owners
                            .get(row.owner_namespace.as_str())
                            .map_err(storage)?
                            .is_none()
                    {
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                let gaps = write.open_table(BRIDGE_EVENT_GAPS).map_err(storage)?;
                for entry in gaps.iter().map_err(storage)? {
                    let (_, value) = entry.map_err(storage)?;
                    let row: BridgeEventGapRow = decode(value.value())?;
                    row.validate()?;
                    if row.owner_namespace.is_empty()
                        || owners
                            .get(row.owner_namespace.as_str())
                            .map_err(storage)?
                            .is_none()
                    {
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                let handoffs = write.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
                for entry in handoffs.iter().map_err(storage)? {
                    let (_, value) = entry.map_err(storage)?;
                    let row: BridgeEventHandoffRow = decode(value.value())?;
                    row.validate()?;
                    if row.owner_namespace.is_empty()
                        || owners
                            .get(row.owner_namespace.as_str())
                            .map_err(storage)?
                            .is_none()
                    {
                        found = true;
                        break;
                    }
                }
            }
            found
        };
        drop(owners);
        let mut meta = write.open_table(META).map_err(storage)?;
        meta.insert(
            BRIDGE_RECOVERY_LEGACY_UNPROVEN_KEY,
            if unproven { "true" } else { "false" },
        )
        .map_err(storage)?;
        Ok(())
    }

    /// Loads one owner row inside a write transaction (issue #2729). A
    /// missing row is [`OrsError::RecoveryOwnerMismatch`]: the namespace
    /// is unproven, never an empty success.
    fn load_bridge_owner_row_in(
        write: &redb::WriteTransaction,
        namespace: &str,
    ) -> Result<BridgeStreamOwnerRow, OrsError> {
        crate::model::validate_digest(namespace, "owner_namespace")?;
        let owners = write.open_table(BRIDGE_STREAM_OWNERS).map_err(storage)?;
        owners
            .get(namespace)
            .map_err(storage)?
            .map(|value| {
                let row: BridgeStreamOwnerRow = decode(value.value())?;
                row.validate()?;
                if row.namespace != namespace {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_stream_owner",
                        reason: "owner row identity does not match its key".to_owned(),
                    });
                }
                Ok(row)
            })
            .transpose()?
            .ok_or(OrsError::RecoveryOwnerMismatch)
    }

    /// Loads one owner row under a read transaction for mutation-free
    /// projections (issue #2729). Missing rows report
    /// [`OrsError::RecoveryOwnerMismatch`], never a synthesized binding.
    fn load_bridge_owner_row_for(
        database: &Database,
        namespace: &str,
    ) -> Result<BridgeStreamOwnerRow, OrsError> {
        crate::model::validate_digest(namespace, "owner_namespace")?;
        let read = database.begin_read().map_err(storage)?;
        let owners = read.open_table(BRIDGE_STREAM_OWNERS).map_err(storage)?;
        owners
            .get(namespace)
            .map_err(storage)?
            .map(|value| {
                let row: BridgeStreamOwnerRow = decode(value.value())?;
                row.validate()?;
                if row.namespace != namespace {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_stream_owner",
                        reason: "owner row identity does not match its key".to_owned(),
                    });
                }
                Ok(row)
            })
            .transpose()?
            .ok_or(OrsError::RecoveryOwnerMismatch)
    }

    /// Binds one stream owner namespace inside a write transaction (issue
    /// #2729): the first admitted bind durably retains the binding with
    /// its store-assigned incarnation and revision, while a later bind
    /// under the same namespace must present the identical binding —
    /// changed lineage, principal, producer, or local scope fails with
    /// [`OrsError::DuplicateConflict`] and never overwrites the retained
    /// owner. Enforces the owner-table bound for fresh namespaces.
    fn bind_bridge_stream_owner_in(
        write: &redb::WriteTransaction,
        evidence: &BridgeOwnerEvidence,
        kind: &str,
        namespace: &str,
        now_ms: u64,
    ) -> Result<BridgeStreamOwnerRow, OrsError> {
        let owners = write.open_table(BRIDGE_STREAM_OWNERS).map_err(storage)?;
        if owners.len().map_err(storage)? >= MAX_BRIDGE_STREAM_OWNERS as u64
            && owners.get(namespace).map_err(storage)?.is_none()
        {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        let existing: Option<BridgeStreamOwnerRow> = owners
            .get(namespace)
            .map_err(storage)?
            .map(|value| decode(value.value()))
            .transpose()?;
        if let Some(row) = existing {
            row.validate()?;
            if row.namespace != namespace
                || row.kind != kind
                || row.authority_lineage != evidence.lineage
                || row.principal != evidence.principal
                || row.producer != evidence.producer
                || row.local_stream != evidence.local
            {
                return Err(OrsError::DuplicateConflict);
            }
            return Ok(row);
        }
        drop(owners);
        let row = BridgeStreamOwnerRow {
            contract_version: crate::CONTRACT_VERSION,
            owner_version: BRIDGE_STREAM_OWNER_VERSION,
            namespace: namespace.to_owned(),
            kind: kind.to_owned(),
            local_stream: evidence.local.clone(),
            authority_lineage: evidence.lineage.clone(),
            principal: evidence.principal.clone(),
            producer: evidence.producer.clone(),
            creating_connection: evidence.connection.clone(),
            creating_launch_nonce: evidence.launch_nonce.clone(),
            creating_session_epoch: evidence.session_epoch,
            incarnation: BRIDGE_STREAM_OWNER_INITIAL_INCARNATION,
            revision: BRIDGE_STREAM_OWNER_INITIAL_REVISION,
            created_at_ms: now_ms,
        };
        row.validate()?;
        {
            let mut owners = write.open_table(BRIDGE_STREAM_OWNERS).map_err(storage)?;
            owners
                .insert(namespace, encode(&row)?.as_str())
                .map_err(storage)?;
        }
        Self::index_bridge_stream_owner_in(write, &row)?;
        Ok(row)
    }

    /// Verifies the presented expected revision/incarnation against the
    /// stored owner row and returns the checked access object (issue
    /// #2729). A mismatch is [`OrsError::StaleWriterEpoch`]: ownership
    /// changed between resolution and commit, so the batch must fail
    /// without mutating anything.
    fn check_bridge_stream_access(
        row: &BridgeStreamOwnerRow,
        expected_revision: u64,
        expected_incarnation: u64,
        right: BridgeStreamRight,
    ) -> Result<BridgeStreamAccess, OrsError> {
        if row.revision != expected_revision || row.incarnation != expected_incarnation {
            return Err(OrsError::StaleWriterEpoch);
        }
        Ok(BridgeStreamAccess {
            namespace: row.namespace.clone(),
            right,
        })
    }

    /// Reads the per-namespace durable/acked cursors inside a write
    /// transaction (issue #2729). Unknown namespaces report zero cursors;
    /// cursor state is never synthesized from transport provenance.
    fn bridge_cursors_in_checked(
        write: &redb::WriteTransaction,
        access: &BridgeStreamAccess,
    ) -> Result<(u64, u64), OrsError> {
        let cursors = write.open_table(BRIDGE_EVENT_CURSORS).map_err(storage)?;
        let row: Option<BridgeEventCursorRow> = cursors
            .get(access.namespace.as_str())
            .map_err(storage)?
            .map(|value| decode(value.value()))
            .transpose()?;
        match row {
            Some(row) => {
                row.validate()?;
                if row.owner_namespace != access.namespace {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_event_cursor",
                        reason: "checked cursor row carries a foreign owner namespace".to_owned(),
                    });
                }
                Ok((row.last_durable_sequence, row.last_acked_sequence))
            }
            None => Ok((0, 0)),
        }
    }

    /// Reads the per-namespace durable/acked cursors under a read
    /// transaction for mutation-free projections (issue #2729).
    fn bridge_cursors_for_checked(
        database: &Database,
        namespace: &str,
    ) -> Result<(u64, u64), OrsError> {
        crate::model::validate_digest(namespace, "owner_namespace")?;
        let read = database.begin_read().map_err(storage)?;
        let cursors = read.open_table(BRIDGE_EVENT_CURSORS).map_err(storage)?;
        let row: Option<BridgeEventCursorRow> = cursors
            .get(namespace)
            .map_err(storage)?
            .map(|value| decode(value.value()))
            .transpose()?;
        match row {
            Some(row) => {
                row.validate()?;
                if row.owner_namespace != namespace {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_event_cursor",
                        reason: "checked cursor row carries a foreign owner namespace".to_owned(),
                    });
                }
                Ok((row.last_durable_sequence, row.last_acked_sequence))
            }
            None => Ok((0, 0)),
        }
    }

    /// Advances the durable cursor over the contiguous staged frontier of
    /// one owner namespace and persists the cursor row keyed by that
    /// namespace (issue #2729). Only rows carrying the namespace advance
    /// it; legacy ownerless rows never move a checked cursor. The staging
    /// connection/generation recorded here stay observation metadata.
    ///
    /// Issue #2730 walk discipline: the walk follows the ordered position
    /// index with one direct probe per adjacent sequence — unrelated
    /// events are never decoded per step — and loads only the adjacent
    /// hit for its staging provenance. The increment is checked: a
    /// frontier complete at the integer maximum stays truthful instead of
    /// wrapping or looping. The walk is bounded to
    /// [`MAX_BRIDGE_CURSOR_WALK`] steps per entry; the persisted cursor is
    /// the exact resume point, so a longer reorder closure continues on
    /// the next legitimate stage/acknowledgement entry, which reports the
    /// conservative frontier until then. When the frontier does not move,
    /// the prior staging provenance is preserved — a fresh stream with no
    /// prior row records the presenting staging observation instead, so
    /// an out-of-order first event keeps its owner and provenance with a
    /// durable cursor of zero. The highest observed position and the
    /// compacted boundary are preserved by every write. A gap record
    /// explains missing coverage; it never moves this cursor.
    #[allow(
        clippy::too_many_lines,
        reason = "cursor advance keeps the bounded walk, provenance, and frontier preservation in one auditable step"
    )]
    fn advance_bridge_cursor_in_checked(
        write: &redb::WriteTransaction,
        access: &BridgeStreamAccess,
        local_stream: &str,
        staging_connection: &str,
        producer_generation: u64,
    ) -> Result<(u64, u64), OrsError> {
        let prior = Self::load_bridge_cursor_row_in(write, &access.namespace)?;
        if let Some(row) = &prior
            && !row.owner_namespace.is_empty()
            && row.owner_namespace != access.namespace
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "bridge_event_cursor",
                reason: "checked cursor row carries a foreign owner namespace".to_owned(),
            });
        }
        let (mut durable, acked) = prior.as_ref().map_or((0, 0), |row| {
            (row.last_durable_sequence, row.last_acked_sequence)
        });
        let observed = prior.as_ref().map_or(0, |row| row.last_observed_sequence);
        let compacted = prior.as_ref().map_or(0, |row| row.last_compacted_sequence);
        let mut stager: Option<(String, u64)> = prior.as_ref().map(|row| {
            (
                row.last_staging_connection.clone(),
                row.last_producer_generation,
            )
        });
        // A fresh stream has no prior provenance to preserve: the
        // presenting staging observation is the first last-stager fact,
        // recorded under its own observational meaning until a frontier
        // movement replaces it with the moved frontier's provenance. The
        // values arrive validated from the parsed stage request.
        if prior.is_none() {
            stager = Some((staging_connection.to_owned(), producer_generation));
        }
        let mut walked = 0_usize;
        loop {
            if walked >= MAX_BRIDGE_CURSOR_WALK {
                break;
            }
            let Some(wanted) = durable.checked_add(1) else {
                // The contiguous frontier is complete at the integer
                // maximum: report it truthfully. No position beyond it
                // exists, so there is nothing to probe and nothing to
                // wrap to.
                break;
            };
            let hit = Self::position_event_in(write, access, wanted)?;
            let Some(event_id) = hit else {
                break;
            };
            let key = format!("{}::{event_id}", access.namespace);
            let row: Option<BridgeEventRow> = {
                let records = write.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
                records
                    .get(key.as_str())
                    .map_err(storage)?
                    .map(|value| decode(value.value()))
                    .transpose()?
            };
            let Some(row) = row else {
                // The position index binds an event the walk needs, but
                // its row is gone without retained evidence at this
                // frontier: compaction only retires positions at or below
                // the acked frontier, which never exceeds the durable
                // frontier the walk extends. Preserve and fail closed
                // instead of skipping or guessing.
                return Err(OrsError::IntegrityProblem {
                    record_type: "bridge_event_record",
                    reason: "position index binds a missing event row".to_owned(),
                });
            };
            if row.owner_namespace != access.namespace || row.sequence != wanted {
                return Err(OrsError::IntegrityProblem {
                    record_type: "bridge_event_record",
                    reason: "position index and event row disagree".to_owned(),
                });
            }
            durable = wanted;
            walked += 1;
            stager = Some((row.staging_connection.clone(), row.producer_generation));
        }
        let (connection, generation) = stager.map_or((String::new(), 0), |held| held);
        let cursor = BridgeEventCursorRow {
            contract_version: crate::CONTRACT_VERSION,
            stream_id: local_stream.to_owned(),
            last_durable_sequence: durable,
            last_acked_sequence: acked,
            last_staging_connection: connection,
            last_producer_generation: generation,
            owner_namespace: access.namespace.clone(),
            last_observed_sequence: observed.max(durable),
            last_compacted_sequence: compacted,
        };
        cursor.validate()?;
        {
            let mut cursors = write.open_table(BRIDGE_EVENT_CURSORS).map_err(storage)?;
            cursors
                .insert(access.namespace.as_str(), encode(&cursor)?.as_str())
                .map_err(storage)?;
        }
        Ok((durable, acked))
    }

    /// Persists the per-namespace cursor row, preserving its staging
    /// observation metadata (issue #2729) together with the issue-#2730
    /// frontiers (highest observed position, compacted boundary), which
    /// only their own writers may move.
    fn write_bridge_cursors_in_checked(
        write: &redb::WriteTransaction,
        access: &BridgeStreamAccess,
        local_stream: &str,
        durable: u64,
        acked: u64,
    ) -> Result<(), OrsError> {
        let prior: Option<BridgeEventCursorRow> = {
            let cursors = write.open_table(BRIDGE_EVENT_CURSORS).map_err(storage)?;
            cursors
                .get(access.namespace.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
        };
        if let Some(row) = &prior {
            row.validate()?;
            if !row.owner_namespace.is_empty() && row.owner_namespace != access.namespace {
                return Err(OrsError::IntegrityProblem {
                    record_type: "bridge_event_cursor",
                    reason: "checked cursor row carries a foreign owner namespace".to_owned(),
                });
            }
        }
        let cursor = BridgeEventCursorRow {
            contract_version: crate::CONTRACT_VERSION,
            stream_id: local_stream.to_owned(),
            last_durable_sequence: durable,
            last_acked_sequence: acked,
            last_staging_connection: prior
                .as_ref()
                .map_or(String::new(), |row| row.last_staging_connection.clone()),
            last_producer_generation: prior.as_ref().map_or(0, |row| row.last_producer_generation),
            owner_namespace: access.namespace.clone(),
            last_observed_sequence: prior
                .as_ref()
                .map_or(durable, |row| row.last_observed_sequence.max(durable)),
            last_compacted_sequence: prior.as_ref().map_or(0, |row| row.last_compacted_sequence),
        };
        cursor.validate()?;
        let mut cursors = write.open_table(BRIDGE_EVENT_CURSORS).map_err(storage)?;
        cursors
            .insert(access.namespace.as_str(), encode(&cursor)?.as_str())
            .map_err(storage)?;
        Ok(())
    }

    /// Persists the per-namespace cursor row after acknowledgement
    /// compaction (issue #2730, item 2): the compacted boundary advances
    /// monotonically to the highest compacted sequence in the same
    /// transaction that writes the replay commitments, while staging
    /// provenance, the highest observed position, and the durable frontier
    /// are preserved. The boundary never passes the acked frontier; the
    /// row validator enforces that counter discipline.
    fn write_bridge_cursors_compacted_in(
        write: &redb::WriteTransaction,
        access: &BridgeStreamAccess,
        local_stream: &str,
        durable: u64,
        acked: u64,
        compacted_boundary: u64,
    ) -> Result<(), OrsError> {
        access.require(BridgeStreamRight::Acknowledge)?;
        let prior = Self::load_bridge_cursor_row_in(write, &access.namespace)?;
        if let Some(row) = &prior {
            row.validate()?;
            if !row.owner_namespace.is_empty() && row.owner_namespace != access.namespace {
                return Err(OrsError::IntegrityProblem {
                    record_type: "bridge_event_cursor",
                    reason: "checked cursor row carries a foreign owner namespace".to_owned(),
                });
            }
        }
        let compacted = prior
            .as_ref()
            .map_or(0, |row| row.last_compacted_sequence)
            .max(compacted_boundary);
        let cursor = BridgeEventCursorRow {
            contract_version: crate::CONTRACT_VERSION,
            stream_id: local_stream.to_owned(),
            last_durable_sequence: durable,
            last_acked_sequence: acked,
            last_staging_connection: prior
                .as_ref()
                .map_or(String::new(), |row| row.last_staging_connection.clone()),
            last_producer_generation: prior.as_ref().map_or(0, |row| row.last_producer_generation),
            owner_namespace: access.namespace.clone(),
            last_observed_sequence: prior
                .as_ref()
                .map_or(durable, |row| row.last_observed_sequence.max(durable)),
            last_compacted_sequence: compacted,
        };
        cursor.validate()?;
        let mut cursors = write.open_table(BRIDGE_EVENT_CURSORS).map_err(storage)?;
        cursors
            .insert(access.namespace.as_str(), encode(&cursor)?.as_str())
            .map_err(storage)?;
        Ok(())
    }

    /// Binds the staged sidecar identity fields to the canonical envelope
    /// before persistence (issue #2729, item 4). The sidecar
    /// stream/event/producer/sequence/epoch must equal the envelope's own
    /// fields exactly; a mismatch fails closed instead of persisting a row
    /// whose sidecar names a different event than its bytes.
    fn bridge_envelope_sidecar_bind(
        envelope: &serde_json::Value,
        stream_id: &str,
        event_id: &str,
        sequence: u64,
        producer_id: &str,
        producer_generation: u64,
        authority_epoch: &str,
    ) -> Result<(), OrsError> {
        const FIELD: &str = "envelope";
        const REASON: &str =
            "sidecar stream/event/producer/sequence fields must bind the canonical envelope";
        let bound = envelope
            .get("stream_id")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|text| text == stream_id)
            && envelope
                .get("event_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|text| text == event_id)
            && envelope.get("sequence").and_then(serde_json::Value::as_u64) == Some(sequence)
            && envelope
                .get("producer_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|text| text == producer_id)
            && envelope
                .get("producer_generation")
                .and_then(serde_json::Value::as_u64)
                == Some(producer_generation);
        if !bound {
            return Err(OrsError::InvalidField {
                field: FIELD,
                reason: REASON,
            });
        }
        let epoch = envelope
            .get("authority_epoch")
            .ok_or(OrsError::InvalidField {
                field: FIELD,
                reason: REASON,
            })?;
        let lineage = epoch
            .get("lineage_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(OrsError::InvalidField {
                field: FIELD,
                reason: REASON,
            })?;
        let sequence = epoch
            .get("sequence")
            .and_then(serde_json::Value::as_u64)
            .filter(|sequence| *sequence != 0)
            .ok_or(OrsError::InvalidField {
                field: FIELD,
                reason: REASON,
            })?;
        if format!("{lineage}:{sequence}") != authority_epoch {
            return Err(OrsError::InvalidField {
                field: FIELD,
                reason: REASON,
            });
        }
        Ok(())
    }

    /// Bridge-event replay identity helpers (issue #2730).
    ///
    /// Key of one ordered position entry: the namespace digest plus the
    /// zero-padded sequence, so byte order is numeric order (`u64::MAX`
    /// is 20 digits). The namespace digest never contains the separator;
    /// the sequence is formatted, never parsed from caller text.
    fn bridge_position_key(namespace: &str, sequence: u64) -> String {
        format!("{namespace}::{sequence:020}")
    }

    /// Splits one position key back into its namespace and sequence. A
    /// malformed key is an integrity failure, never a skipped row.
    fn parse_bridge_position_key(key: &str) -> Result<(String, u64), OrsError> {
        const RECORD_TYPE: &str = "bridge_event_position";
        let (namespace, padded) =
            key.rsplit_once("::")
                .ok_or_else(|| OrsError::IntegrityProblem {
                    record_type: RECORD_TYPE,
                    reason: "position key does not carry a namespace and sequence".to_owned(),
                })?;
        crate::model::validate_digest(namespace, "owner_namespace").map_err(|error| {
            OrsError::IntegrityProblem {
                record_type: RECORD_TYPE,
                reason: error.to_string(),
            }
        })?;
        let sequence: u64 = padded.parse().map_err(|_| OrsError::IntegrityProblem {
            record_type: RECORD_TYPE,
            reason: "position key sequence is not a number".to_owned(),
        })?;
        if sequence == 0 {
            return Err(OrsError::IntegrityProblem {
                record_type: RECORD_TYPE,
                reason: "position key sequence must be nonzero".to_owned(),
            });
        }
        Ok((namespace.to_owned(), sequence))
    }

    /// Probes the ordered position index for one sequence inside the checked
    /// namespace (issue #2730, item 4): one direct key read, never a decode
    /// of unrelated events. Returns the bound event identity, or `None` when
    /// the position was never admitted.
    fn position_event_in(
        write: &redb::WriteTransaction,
        access: &BridgeStreamAccess,
        sequence: u64,
    ) -> Result<Option<String>, OrsError> {
        let positions = write.open_table(BRIDGE_EVENT_POSITIONS).map_err(storage)?;
        let key = Self::bridge_position_key(&access.namespace, sequence);
        let entry: Option<BridgeEventPosition> = positions
            .get(key.as_str())
            .map_err(storage)?
            .map(|value| decode(value.value()))
            .transpose()?;
        Ok(entry.map(|position| position.event_id))
    }

    /// Bounds one namespace's position window before a fresh position is
    /// admitted (issue #2885, item 2). The count is a key-ordered range scan
    /// over the namespace's own `namespace::` keys — never a full-table scan —
    /// so it stays proportional to the namespace's live window, which
    /// position-prefix compaction drains. A namespace already at
    /// [`MAX_BRIDGE_POSITION_LIVE_PER_NAMESPACE`] fails closed with typed
    /// backpressure ([`OrsError::ProjectionLimitExceeded`]) instead of growing
    /// the index without bound; the next legitimate compaction entry retires
    /// the certified prefix and reopens the window.
    fn check_bridge_position_budget_in(
        write: &redb::WriteTransaction,
        access: &BridgeStreamAccess,
    ) -> Result<(), OrsError> {
        let positions = write.open_table(BRIDGE_EVENT_POSITIONS).map_err(storage)?;
        let prefix = format!("{}::", access.namespace);
        let prefix_end = format!("{}\u{10ffff}", access.namespace);
        let mut live = 0_u64;
        for entry in positions
            .range(prefix.as_str()..=prefix_end.as_str())
            .map_err(storage)?
        {
            let (key, value) = entry.map_err(storage)?;
            let (namespace, _sequence) = Self::parse_bridge_position_key(key.value())?;
            if namespace != access.namespace {
                return Err(OrsError::IntegrityProblem {
                    record_type: "bridge_event_position",
                    reason: "position key escapes its namespace".to_owned(),
                });
            }
            let _position: BridgeEventPosition = decode(value.value())?;
            live += 1;
            if live >= MAX_BRIDGE_POSITION_LIVE_PER_NAMESPACE as u64 {
                return Err(OrsError::ProjectionLimitExceeded);
            }
        }
        Ok(())
    }

    /// Loads one per-namespace cursor row inside a write transaction without
    /// synthesizing anything: `None` when the namespace never staged.
    fn load_bridge_cursor_row_in(
        write: &redb::WriteTransaction,
        namespace: &str,
    ) -> Result<Option<BridgeEventCursorRow>, OrsError> {
        let cursors = write.open_table(BRIDGE_EVENT_CURSORS).map_err(storage)?;
        cursors
            .get(namespace)
            .map_err(storage)?
            .map(|value| decode(value.value()))
            .transpose()
    }

    /// Loads one retained replay commitment inside a write transaction:
    /// `None` when the identity has no post-compaction evidence. A live row
    /// and a commitment never coexist; [`Self::check_bridge_retained_replay_in`]
    /// checks the live row first, so this is consulted only after the live
    /// row is gone.
    fn load_bridge_commitment_in(
        write: &redb::WriteTransaction,
        namespace: &str,
        event_id: &str,
    ) -> Result<Option<BridgeEventReplayCommitment>, OrsError> {
        let commitments = write
            .open_table(BRIDGE_EVENT_REPLAY_COMMITMENTS)
            .map_err(storage)?;
        let key = format!("{namespace}::{event_id}");
        let commitment: Option<BridgeEventReplayCommitment> = commitments
            .get(key.as_str())
            .map_err(storage)?
            .map(|value| decode(value.value()))
            .transpose()?;
        if let Some(commitment) = &commitment
            && (commitment.owner_namespace != namespace || commitment.event_id != event_id)
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "bridge_event_replay_commitment",
                reason: "commitment key does not match its retained identity".to_owned(),
            });
        }
        Ok(commitment)
    }

    /// Records one staged sequence in the highest-observed frontier (issue
    /// #2730, item 4): the maximum staged position ever seen in the
    /// namespace, kept distinct from the contiguous durable frontier, the
    /// producer receipt acknowledgement, and the downstream application
    /// frontier. Monotonic within the transaction; every other cursor field
    /// is preserved byte-for-byte.
    fn note_bridge_observation_in(
        write: &redb::WriteTransaction,
        access: &BridgeStreamAccess,
        local_stream: &str,
        sequence: u64,
    ) -> Result<(), OrsError> {
        let prior = Self::load_bridge_cursor_row_in(write, &access.namespace)?;
        let Some(row) = prior else {
            return Ok(());
        };
        if row.last_observed_sequence >= sequence {
            return Ok(());
        }
        if !row.owner_namespace.is_empty() && row.owner_namespace != access.namespace {
            return Err(OrsError::IntegrityProblem {
                record_type: "bridge_event_cursor",
                reason: "checked cursor row carries a foreign owner namespace".to_owned(),
            });
        }
        let next = BridgeEventCursorRow {
            contract_version: crate::CONTRACT_VERSION,
            stream_id: local_stream.to_owned(),
            last_durable_sequence: row.last_durable_sequence,
            last_acked_sequence: row.last_acked_sequence,
            last_staging_connection: row.last_staging_connection.clone(),
            last_producer_generation: row.last_producer_generation,
            owner_namespace: access.namespace.clone(),
            last_observed_sequence: sequence,
            last_compacted_sequence: row.last_compacted_sequence,
        };
        next.validate()?;
        let mut cursors = write.open_table(BRIDGE_EVENT_CURSORS).map_err(storage)?;
        cursors
            .insert(access.namespace.as_str(), encode(&next)?.as_str())
            .map_err(storage)?;
        Ok(())
    }

    /// Compares one stage request against a retained replay commitment over
    /// the full identity (issue #2730, items 1-3): producer/source generation,
    /// authority lineage epoch, the original content commitment, and the
    /// permitted representation facts. Identical payload bytes under a
    /// genuinely different event identity never reach this comparison — the
    /// caller selects the commitment by exact event identity first — while
    /// changed bytes, a changed producer/epoch, or a changed representation
    /// under the same identity never match.
    fn bridge_commitment_matches(
        commitment: &BridgeEventReplayCommitment,
        stage: &BridgeCheckedStage,
        staging: &BridgeEventPrivacyStaging,
    ) -> bool {
        commitment.owner_namespace == stage.namespace
            && commitment.stream_id == stage.stream_id
            && commitment.event_id == stage.event_id
            && commitment.sequence == stage.sequence
            && commitment.producer_id == stage.evidence.producer
            && commitment.producer_generation == stage.producer_generation
            && commitment.authority_epoch == stage.authority_epoch
            && commitment.envelope_sha256 == stage.presented_sha
            && commitment.transport_hash == staging.transport_hash
            && commitment.redacted == staging.denied
            && commitment.redacted_classes == staging.classes
    }

    /// Builds the exact-replay outcome from a retained replay commitment
    /// (issue #2730, item 2): the stored disposition with `fresh: false` over
    /// the current cursors. The redaction receipt is rebuilt from the retained
    /// representation facts only — forbidden raw content is never regenerated
    /// to answer a replay.
    fn bridge_event_outcome_from_commitment(
        commitment: &BridgeEventReplayCommitment,
        disposition: &str,
        durable: u64,
        acked: u64,
        handoff: Option<&str>,
    ) -> serde_json::Value {
        let privacy_disposition = if commitment.redacted {
            BRIDGE_EVENT_PRIVACY_REDACTED
        } else {
            BRIDGE_EVENT_PRIVACY_ALLOWED
        };
        let redaction = if commitment.redacted {
            json!({
                "transport_hash": commitment.transport_hash,
                "reason": BRIDGE_EVENT_REDACTION_REASON_FORBIDDEN,
                "redacted_classes": commitment.redacted_classes,
                "marker": commitment.redaction_marker,
                "normalizer_version": format!("ors-bridge-ingest-v{}", commitment.redaction_version),
            })
        } else {
            serde_json::Value::Null
        };
        json!({
            "stream_id": commitment.stream_id,
            "event_id": commitment.event_id,
            "sequence": commitment.sequence,
            "phase": BRIDGE_EVENT_PHASE_DURABLE,
            "disposition": disposition,
            "envelope_sha256": commitment.envelope_sha256,
            "producer_id": commitment.producer_id,
            "producer_generation": commitment.producer_generation,
            "authority_epoch": commitment.authority_epoch,
            "durable_cursor": durable,
            "acked_cursor": acked,
            "fresh": false,
            "privacy_disposition": privacy_disposition,
            "transport_hash": commitment.transport_hash,
            "redaction": redaction,
            "handoff": handoff,
            "owner_namespace": commitment.owner_namespace,
        })
    }

    /// Builds the explicit retired/unverifiable recovery disposition (issue
    /// #2730, item 2): the request names a position at or below the retained
    /// compacted boundary, but no exact identity/content evidence remains. It
    /// carries the true frontier facts with `fresh: false` and performs no
    /// mutation — a missing row below the boundary is not a new event, and no
    /// duplicate is fabricated. The phase names the durable frontier the
    /// cursors attest; the per-event meaning rides `disposition`, which the
    /// Kernel route forwards untouched for the #2732 consumer.
    fn bridge_event_retired_outcome(
        stage: &BridgeCheckedStage,
        staging: &BridgeEventPrivacyStaging,
        durable: u64,
        acked: u64,
        compacted_boundary: u64,
        handoff: Option<&str>,
    ) -> serde_json::Value {
        json!({
            "stream_id": stage.stream_id,
            "event_id": stage.event_id,
            "sequence": stage.sequence,
            "phase": BRIDGE_EVENT_PHASE_DURABLE,
            "disposition": BRIDGE_EVENT_DISPOSITION_RETIRED,
            "envelope_sha256": stage.presented_sha,
            "producer_id": stage.evidence.producer,
            "producer_generation": stage.producer_generation,
            "authority_epoch": stage.authority_epoch,
            "staging_connection": stage.staging_connection,
            "durable_cursor": durable,
            "acked_cursor": acked,
            "compacted_boundary": compacted_boundary,
            "fresh": false,
            "privacy_disposition": if staging.denied {
                BRIDGE_EVENT_PRIVACY_REDACTED
            } else {
                BRIDGE_EVENT_PRIVACY_ALLOWED
            },
            "transport_hash": staging.transport_hash,
            "redaction": serde_json::Value::Null,
            "handoff": handoff,
            "owner_namespace": stage.namespace,
        })
    }

    /// Pre-checks the pending handoff slot before any record/cursor mutation
    /// (issue #2730, item 5): when a handoff was already recorded under this
    /// identity with a different digest or sequence, the stage conflicts here
    /// instead of letting a later handoff check be the first detection of
    /// conflicting already-written content. A missing or exactly matching
    /// handoff passes; nothing is written by this check.
    fn check_bridge_handoff_compatible_in(
        write: &redb::WriteTransaction,
        access: &BridgeStreamAccess,
        stage: &BridgeCheckedStage,
    ) -> Result<(), OrsError> {
        let handoffs = write.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
        let row: Option<BridgeEventHandoffRow> = handoffs
            .get(stage.key.as_str())
            .map_err(storage)?
            .map(|value| decode(value.value()))
            .transpose()?;
        let Some(row) = row else {
            return Ok(());
        };
        row.validate()?;
        if row.owner_namespace != access.namespace
            || row.envelope_sha256 != stage.presented_sha
            || row.sequence != stage.sequence
        {
            return Err(OrsError::DuplicateConflict);
        }
        Ok(())
    }

    /// Persists one replay commitment and enforces the commitment bounds
    /// (issue #2730, item 2). Per-stream pressure evicts the oldest compacted
    /// commitment of that namespace first; total pressure evicts the globally
    /// oldest compacted commitment first. Eviction only degrades exact replays
    /// to the retained-boundary retired disposition — re-admission stays
    /// blocked — so acknowledgement never fails for commitment pressure.
    fn write_bridge_commitment_in(
        write: &redb::WriteTransaction,
        commitment: &BridgeEventReplayCommitment,
    ) -> Result<(), OrsError> {
        commitment.validate()?;
        let key = commitment.record_key();
        let mut commitments = write
            .open_table(BRIDGE_EVENT_REPLAY_COMMITMENTS)
            .map_err(storage)?;
        commitments
            .insert(key.as_str(), encode(commitment)?.as_str())
            .map_err(storage)?;
        let mut owned: Vec<(u64, String)> = Vec::new();
        for entry in commitments.iter().map_err(storage)? {
            let (existing_key, value) = entry.map_err(storage)?;
            let existing: BridgeEventReplayCommitment = decode(value.value())?;
            if existing.owner_namespace == commitment.owner_namespace {
                owned.push((existing.sequence, existing_key.value().to_owned()));
            }
        }
        owned.sort();
        while owned.len() > MAX_BRIDGE_EVENT_REPLAY_COMMITMENTS_PER_STREAM {
            let victim = owned
                .first()
                .map(|(_, victim_key)| victim_key.clone())
                .ok_or_else(|| OrsError::IntegrityProblem {
                    record_type: "bridge_event_replay_commitment",
                    reason: "commitment bound accounting disagrees with its rows".to_owned(),
                })?;
            commitments.remove(victim.as_str()).map_err(storage)?;
            owned.remove(0);
        }
        while commitments.len().map_err(storage)? > MAX_BRIDGE_EVENT_REPLAY_COMMITMENTS as u64 {
            let mut oldest: Option<(u64, u64, String)> = None;
            for entry in commitments.iter().map_err(storage)? {
                let (existing_key, value) = entry.map_err(storage)?;
                let existing: BridgeEventReplayCommitment = decode(value.value())?;
                let candidate = (
                    existing.compacted_at_ms,
                    existing.sequence,
                    existing_key.value().to_owned(),
                );
                if oldest.as_ref().is_none_or(|best| &candidate < best) {
                    oldest = Some(candidate);
                }
            }
            let (_, _, victim) = oldest.ok_or_else(|| OrsError::IntegrityProblem {
                record_type: "bridge_event_replay_commitment",
                reason: "commitment bound accounting disagrees with its rows".to_owned(),
            })?;
            commitments.remove(victim.as_str()).map_err(storage)?;
        }
        Ok(())
    }

    /// Durably stages one bridge-forwarded event under its admitted owner
    /// namespace before any acknowledgement (issue #2729).
    ///
    /// Behaves as [`Self::stage_bridge_event`] plus the owner relation:
    /// the sidecar identity is bound to the canonical envelope, the
    /// Kernel-derived owner evidence selects the versioned namespace
    /// (binding it at first admission), and the row, its key, and its
    /// cursor advance are all namespaced. Exact replays return the stored
    /// outcome; changed bytes, a changed producer/epoch, or a changed
    /// owner binding under the same identity fail with
    /// [`OrsError::DuplicateConflict`]. Disclosure staging is unchanged.
    ///
    /// Issue #2730 enforces both identity directions atomically inside
    /// the authorized stream incarnation, in one short ORS transaction,
    /// before any record/cursor/handoff mutation: the live row binds
    /// event identity to sequence and content; the ordered position index
    /// binds sequence back to the same event identity; a retained replay
    /// commitment answers exact post-compaction replays with `fresh:
    /// false`; a request below the retained compacted boundary without
    /// exact evidence answers the explicit retired disposition; and a
    /// conflicting pending handoff fails here instead of surfacing later.
    /// Identical payload bytes at two genuinely distinct event identities
    /// and positions remain legitimate stage requests.
    ///
    /// The retained-history decision itself lives in
    /// [`Self::check_bridge_retained_replay_in`]: live rows, retained
    /// replay commitments, and the compacted/retired boundary are
    /// consulted before anything fresh is allocated, and an existing
    /// disposition returns with `fresh: false`. Only a genuinely new
    /// identity falls through to
    /// [`Self::stage_fresh_bridge_event_checked`].
    pub fn stage_bridge_event_checked(
        &self,
        staged: &serde_json::Value,
    ) -> Result<serde_json::Value, OrsError> {
        let (stage, staging) = Self::parse_bridge_stage_checked(staged)?;
        let now_ms = current_unix_ms_u64()?;
        let write = self.database.begin_write().map_err(storage)?;
        let outcome = {
            let owner = Self::bind_bridge_stream_owner_in(
                &write,
                &stage.evidence,
                BRIDGE_STREAM_OWNER_KIND_STREAM,
                &stage.namespace,
                now_ms,
            )?;
            let access = Self::check_bridge_stream_access(
                &owner,
                BRIDGE_STREAM_OWNER_INITIAL_REVISION,
                BRIDGE_STREAM_OWNER_INITIAL_INCARNATION,
                BridgeStreamRight::Append,
            )?;
            match Self::check_bridge_retained_replay_in(&write, &access, &stage, &staging)? {
                Some(outcome) => outcome,
                None => Self::stage_fresh_bridge_event_checked(
                    &write, &access, &stage, &staging, now_ms,
                )?,
            }
        };
        write.commit().map_err(storage)?;
        Ok(outcome)
    }

    /// Decides one owner-checked stage request against retained history
    /// (issue #2730, item 2): live rows, retained replay commitments, and
    /// the stream's compacted/retired boundary are consulted before
    /// anything fresh is allocated, inside the authorized stream
    /// incarnation the caller already bound. Performs no mutation itself.
    ///
    /// Where exact identity/content evidence remains, the existing
    /// disposition returns with `fresh: false` — the live row's duplicate
    /// outcome, or the retained commitment's duplicate outcome after
    /// payload compaction. A frontier alone proves neither a particular
    /// event ID nor its bytes: when the request names a position at or
    /// below the retained compacted boundary with no exact evidence left,
    /// the explicit retired/unverifiable recovery disposition returns with
    /// `fresh: false`, never a fabricated duplicate or fresh insertion.
    /// Changed content under a live or committed identity, a position
    /// admitted under a different event, or a torn position binding with
    /// no retained evidence fails closed. Returns `Ok(None)` only for a
    /// genuinely new identity at a free position above the boundary; the
    /// caller still runs the pending-handoff compatibility check before
    /// any record/cursor mutation.
    fn check_bridge_retained_replay_in(
        write: &redb::WriteTransaction,
        access: &BridgeStreamAccess,
        stage: &BridgeCheckedStage,
        staging: &BridgeEventPrivacyStaging,
    ) -> Result<Option<serde_json::Value>, OrsError> {
        if let Some(row) = Self::load_bridge_event_row_in(write, &stage.key)? {
            row.validate()?;
            return Ok(Some(Self::replay_bridge_event_outcome_checked(
                write, access, &row, stage, staging,
            )?));
        }
        if let Some(commitment) =
            Self::load_bridge_commitment_in(write, &stage.namespace, &stage.event_id)?
        {
            if !Self::bridge_commitment_matches(&commitment, stage, staging) {
                return Err(OrsError::DuplicateConflict);
            }
            let (durable, acked) = Self::bridge_cursors_in_checked(write, access)?;
            let handoff = Self::bridge_handoff_state_checked_in(write, access, &stage.event_id)?;
            return Ok(Some(Self::bridge_event_outcome_from_commitment(
                &commitment,
                "duplicate",
                durable,
                acked,
                handoff.as_deref(),
            )));
        }
        let cursor = Self::load_bridge_cursor_row_in(write, &access.namespace)?;
        let (durable, acked, compacted) = cursor.as_ref().map_or((0, 0, 0), |row| {
            (
                row.last_durable_sequence,
                row.last_acked_sequence,
                row.last_compacted_sequence,
            )
        });
        // The admitted position identifies exactly one logical event: a
        // different occupant rejects this request before any mutation,
        // even below the compacted boundary. A same-identity occupant
        // with no retained row or commitment is noted here and resolved
        // against the boundary below.
        let torn_position = match Self::position_event_in(write, access, stage.sequence)? {
            None => false,
            Some(occupant) if occupant != stage.event_id => {
                return Err(OrsError::DuplicateConflict);
            }
            Some(_) => true,
        };
        if stage.sequence <= compacted {
            // Below the retained compacted boundary with no exact
            // evidence: retired, never a new event — including when the
            // position index still names this same identity (its
            // commitment may have expired under bound pressure).
            let handoff = Self::bridge_handoff_state_checked_in(write, access, &stage.event_id)?;
            return Ok(Some(Self::bridge_event_retired_outcome(
                stage,
                staging,
                durable,
                acked,
                compacted,
                handoff.as_deref(),
            )));
        }
        if torn_position {
            // Above the boundary the position must resolve to retained
            // evidence: a binding with no row and no commitment is a torn
            // write — fail closed and preserve it instead of guessing.
            return Err(OrsError::IntegrityProblem {
                record_type: "bridge_event_position",
                reason: "position index binds an event with no retained row or commitment"
                    .to_owned(),
            });
        }
        Ok(None)
    }

    /// Stages an identity with no retained evidence (issue #2730, items
    /// 1-2, 5): [`Self::check_bridge_retained_replay_in`] already
    /// established that no live row, no retained commitment, no occupant
    /// position, and no retired boundary blocks this identity. A
    /// conflicting pending handoff still fails before any record/cursor
    /// mutation; otherwise the row, its ordered position binding, its
    /// cursor advance, and its pending handoff commit in this one short
    /// ORS transaction.
    fn stage_fresh_bridge_event_checked(
        write: &redb::WriteTransaction,
        access: &BridgeStreamAccess,
        stage: &BridgeCheckedStage,
        staging: &BridgeEventPrivacyStaging,
        now_ms: u64,
    ) -> Result<serde_json::Value, OrsError> {
        access.require(BridgeStreamRight::Append)?;
        Self::check_bridge_handoff_compatible_in(write, access, stage)?;
        let outcome = Self::insert_bridge_event_row_checked(write, access, stage, staging, now_ms)?;
        Self::bump_bridge_recovery_revision_in(write, &access.namespace)?;
        Ok(outcome)
    }

    /// Parses and validates one owner-checked stage request (issue #2729):
    /// the sidecar identity, the Kernel-derived owner evidence, the
    /// sidecar-to-envelope bind, the digest, and the disclosure staging.
    fn parse_bridge_stage_checked(
        staged: &serde_json::Value,
    ) -> Result<(BridgeCheckedStage, BridgeEventPrivacyStaging), OrsError> {
        let stream_id = bridge_key_text(staged, "stream_id")?;
        let event_id = bridge_key_text(staged, "event_id")?;
        let sequence = bridge_sequence(staged, "sequence")?;
        let producer_id = bridge_text(staged, "producer_id")?;
        let producer_generation = bridge_generation(staged, "producer_generation")?;
        let authority_epoch = bridge_text(staged, "authority_epoch")?;
        let staging_connection = bridge_text(staged, "staging_connection")?;
        let evidence = Self::bridge_stream_evidence_from(staged)?;
        if evidence.producer != producer_id || evidence.local != stream_id {
            return Err(OrsError::InvalidField {
                field: "owner_evidence",
                reason: "owner evidence must name the staged producer and stream",
            });
        }
        let envelope_value = staged
            .get("envelope")
            .cloned()
            .ok_or(OrsError::InvalidField {
                field: "envelope",
                reason: "bridge event must carry its canonical envelope JSON",
            })?;
        Self::bridge_envelope_sidecar_bind(
            &envelope_value,
            &stream_id,
            &event_id,
            sequence,
            &producer_id,
            producer_generation,
            &authority_epoch,
        )?;
        let envelope_bytes =
            canonical_json_bytes(&envelope_value).map_err(|_| OrsError::InvalidField {
                field: "envelope",
                reason: "bridge event envelope is not canonicalizable",
            })?;
        if envelope_bytes.len() > MAX_BRIDGE_EVENT_ENVELOPE_BYTES {
            return Err(OrsError::PayloadTooLarge);
        }
        let presented_sha = bridge_text(staged, "envelope_sha256")?;
        crate::model::validate_digest(&presented_sha, "envelope_sha256")?;
        if crate::model::sha256_hex(&envelope_bytes) != presented_sha {
            return Err(OrsError::PayloadIntegrityMismatch);
        }
        let staging = Self::bridge_event_privacy_staging(staged, &envelope_bytes)?;
        let namespace = Self::bridge_stream_owner_digest(
            &evidence.lineage,
            &evidence.principal,
            &evidence.producer,
            &evidence.local,
        )?;
        let key = format!("{namespace}::{event_id}");
        let stage = BridgeCheckedStage {
            evidence,
            stream_id,
            event_id,
            sequence,
            producer_generation,
            authority_epoch,
            presented_sha,
            staging_connection,
            namespace,
            key,
        };
        Ok((stage, staging))
    }

    /// Answers an exact replay under an owner-checked identity (issue
    /// #2729). Changed bytes, producer, epoch, or owner binding under the
    /// same identity fail with [`OrsError::DuplicateConflict`]; the
    /// durable row is never overwritten.
    ///
    /// Issue #2730 binds the representation too: the redaction classes,
    /// marker, and version join the comparison, so a redaction-policy
    /// change under the same identity conflicts instead of answering a
    /// stale representation as a duplicate.
    fn replay_bridge_event_outcome_checked(
        write: &redb::WriteTransaction,
        access: &BridgeStreamAccess,
        row: &BridgeEventRow,
        stage: &BridgeCheckedStage,
        staging: &BridgeEventPrivacyStaging,
    ) -> Result<serde_json::Value, OrsError> {
        if row.owner_namespace != stage.namespace
            || row.envelope_sha256 != stage.presented_sha
            || row.sequence != stage.sequence
            || row.producer_id != stage.evidence.producer
            || row.producer_generation != stage.producer_generation
            || row.authority_epoch != stage.authority_epoch
            || row.redacted != staging.denied
            || row.transport_hash != staging.transport_hash
            || row.redacted_classes != staging.classes
            || row.redaction_marker
                != if staging.denied {
                    BRIDGE_EVENT_REDACTED_PROJECTION_MARKER
                } else {
                    ""
                }
            || row.redaction_version
                != if staging.denied {
                    crate::CONTRACT_VERSION
                } else {
                    0
                }
        {
            return Err(OrsError::DuplicateConflict);
        }
        let (durable, acked) = Self::bridge_cursors_in_checked(write, access)?;
        let handoff = Self::bridge_handoff_state_checked_in(write, access, &stage.event_id)?;
        Ok(Self::bridge_event_outcome_checked(
            row,
            "duplicate",
            durable,
            acked,
            false,
            handoff.as_deref(),
            &stage.namespace,
        ))
    }

    /// Reserves the pending-handoff slot and stages the handoff row in the
    /// same ORS transaction as its event (issue #2731, item 2): local
    /// acceptance is one atomic durable step — event row, ordered position
    /// binding, cursor advance, and pending handoff — so no crash or timeout
    /// between the former split commits can leave a staged event without its
    /// required handoff. A full handoff table fails the whole stage here with
    /// [`OrsError::ProjectionLimitExceeded`] (typed backpressure that reserves
    /// terminalization/recovery room at admission), never with a
    /// staged-but-handoff-less row. An already-recorded handoff is kept
    /// as-is; a conflicting one was already rejected by
    /// [`Self::check_bridge_handoff_compatible_in`]. This claims no
    /// Governor-store atomicity: the row is the local pending-delivery
    /// intent, reconciled against the receiver's exact receipt afterwards.
    fn insert_bridge_handoff_pending_in(
        write: &redb::WriteTransaction,
        access: &BridgeStreamAccess,
        stage: &BridgeCheckedStage,
        now_ms: u64,
    ) -> Result<(), OrsError> {
        access.require(BridgeStreamRight::Append)?;
        let handoffs = write.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
        if handoffs.get(stage.key.as_str()).map_err(storage)?.is_some() {
            return Ok(());
        }
        if handoffs.len().map_err(storage)? >= MAX_BRIDGE_EVENT_HANDOFFS as u64 {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        drop(handoffs);
        let row = BridgeEventHandoffRow {
            contract_version: crate::CONTRACT_VERSION,
            stream_id: stage.stream_id.clone(),
            event_id: stage.event_id.clone(),
            sequence: stage.sequence,
            envelope_sha256: stage.presented_sha.clone(),
            state: BRIDGE_EVENT_HANDOFF_HANDED_OFF.to_owned(),
            staging_connection: stage.staging_connection.clone(),
            handed_off_at_ms: now_ms,
            reconcile_key: String::new(),
            reconciled_at_ms: 0,
            owner_namespace: access.namespace.clone(),
            reconcile_acked_sequence: 0,
            reconcile_owner_revision: 0,
            reconcile_owner_incarnation: 0,
        };
        row.validate()?;
        let mut handoffs = write.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
        handoffs
            .insert(stage.key.as_str(), encode(&row)?.as_str())
            .map_err(storage)?;
        Ok(())
    }

    /// Inserts one fresh owner-checked row and advances its cursor (issue
    /// #2729). Runs inside the stage transaction owned by
    /// [`Self::stage_bridge_event_checked`].
    ///
    /// Issue #2730 commits the coherent local transition: the event row,
    /// its ordered position binding, and the cursor changes agree in this
    /// one short ORS transaction. The caller has already established that
    /// no live row, no retained commitment, no occupant position, no
    /// retired boundary, and no conflicting handoff blocks this identity,
    /// so the inserts below cannot create a second logical event.
    ///
    /// Issue #2731 extends the same transaction with the pending handoff
    /// (see [`Self::insert_bridge_handoff_pending_in`]): local acceptance
    /// stages the event plus its pending delivery intent atomically, so no
    /// crash or timeout between the former split commits can leave a staged
    /// event without its required handoff.
    fn insert_bridge_event_row_checked(
        write: &redb::WriteTransaction,
        access: &BridgeStreamAccess,
        stage: &BridgeCheckedStage,
        staging: &BridgeEventPrivacyStaging,
        now_ms: u64,
    ) -> Result<serde_json::Value, OrsError> {
        let row = BridgeEventRow {
            contract_version: crate::CONTRACT_VERSION,
            stream_id: stage.stream_id.clone(),
            event_id: stage.event_id.clone(),
            sequence: stage.sequence,
            producer_id: stage.evidence.producer.clone(),
            producer_generation: stage.producer_generation,
            authority_epoch: stage.authority_epoch.clone(),
            envelope_sha256: stage.presented_sha.clone(),
            envelope_bytes: staging.stored_bytes.clone(),
            staging_connection: stage.staging_connection.clone(),
            staged_at_ms: now_ms,
            phase: BRIDGE_EVENT_PHASE_DURABLE.to_owned(),
            owner_namespace: stage.namespace.clone(),
            transport_hash: staging.transport_hash.clone(),
            redacted: staging.denied,
            redaction_reason: if staging.denied {
                BRIDGE_EVENT_REDACTION_REASON_FORBIDDEN.to_owned()
            } else {
                String::new()
            },
            redacted_classes: staging.classes.clone(),
            redaction_marker: if staging.denied {
                BRIDGE_EVENT_REDACTED_PROJECTION_MARKER.to_owned()
            } else {
                String::new()
            },
            redaction_version: if staging.denied {
                crate::CONTRACT_VERSION
            } else {
                0
            },
        };
        row.validate()?;
        {
            let mut records = write.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
            records
                .insert(stage.key.as_str(), encode(&row)?.as_str())
                .map_err(storage)?;
        }
        {
            Self::check_bridge_position_budget_in(write, access)?;
            let position = BridgeEventPosition {
                event_id: stage.event_id.clone(),
            };
            position.validate()?;
            let mut positions = write.open_table(BRIDGE_EVENT_POSITIONS).map_err(storage)?;
            let position_key = Self::bridge_position_key(&access.namespace, stage.sequence);
            positions
                .insert(position_key.as_str(), encode(&position)?.as_str())
                .map_err(storage)?;
        }
        let (durable, acked) = Self::advance_bridge_cursor_in_checked(
            write,
            access,
            &stage.stream_id,
            &stage.staging_connection,
            stage.producer_generation,
        )?;
        Self::note_bridge_observation_in(write, access, &stage.stream_id, stage.sequence)?;
        Self::insert_bridge_handoff_pending_in(write, access, stage, now_ms)?;
        let handoff = Self::bridge_handoff_state_checked_in(write, access, &stage.event_id)?;
        Ok(Self::bridge_event_outcome_checked(
            &row,
            "accepted",
            durable,
            acked,
            true,
            handoff.as_deref(),
            &stage.namespace,
        ))
    }

    /// Builds the stage/lookup outcome object for one owner-checked row:
    /// the shared outcome plus the admitted namespace the row was verified
    /// under. The namespace is Kernel-internal scope evidence, never a
    /// foreign digest: conflict and lookup replies only carry it for the
    /// proven owner (see [`Self::load_bridge_event_conflict_view`]).
    fn bridge_event_outcome_checked(
        row: &BridgeEventRow,
        disposition: &str,
        durable: u64,
        acked: u64,
        fresh: bool,
        handoff: Option<&str>,
        namespace: &str,
    ) -> serde_json::Value {
        let mut outcome = bridge_event_outcome(row, disposition, durable, acked, fresh, handoff);
        if let Some(object) = outcome.as_object_mut() {
            object.insert(
                "owner_namespace".to_owned(),
                serde_json::Value::String(namespace.to_owned()),
            );
        }
        outcome
    }

    /// Reads the handoff state for one owner-checked identity inside a
    /// write transaction. The key is namespaced, so a foreign stream never
    /// shares a handoff slot with the proven owner.
    fn bridge_handoff_state_checked_in(
        write: &redb::WriteTransaction,
        access: &BridgeStreamAccess,
        event_id: &str,
    ) -> Result<Option<String>, OrsError> {
        Self::bridge_handoff_state_in(write, &access.namespace, event_id)
    }

    /// Loads the conflict view for one owner-checked identity (issue
    /// #2729, item 4). The query carries the presenter's owner evidence
    /// plus the presented producer, local stream, and event: the store
    /// derives the candidate namespace internally, then returns the stored
    /// facts only when the row exists under exactly that namespace. A
    /// foreign or unknown identity returns `Ok(None)` — indistinguishable
    /// by design — so a rejected caller never learns another stream's
    /// digest, cursors, or gap contents through the conflict response.
    ///
    /// Issue #2730 falls back to the retained replay commitment when the
    /// live row is compacted: a changed compacted replay still conflicts,
    /// now with the retained evidence instead of an empty view. The view
    /// stays owner-gated — the commitment is served only under the
    /// presenter's own derived namespace.
    #[allow(
        clippy::too_many_lines,
        reason = "conflict view keeps the live-row and retained-commitment branches in one auditable decision"
    )]
    pub fn load_bridge_event_conflict_view(
        &self,
        query: &serde_json::Value,
    ) -> Result<Option<serde_json::Value>, OrsError> {
        let (lineage, principal) = Self::bridge_owner_presenter_from(query)?;
        let producer = bridge_key_text(query, "producer_id")?;
        let local = bridge_key_text(query, "stream_id")?;
        let event_id = bridge_key_text(query, "event_id")?;
        let namespace = Self::bridge_stream_owner_digest(&lineage, &principal, &producer, &local)?;
        let read = self.database.begin_read().map_err(storage)?;
        let key = format!("{namespace}::{event_id}");
        let row: Option<BridgeEventRow> = {
            let records = read.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
            records
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
        };
        if let Some(row) = row {
            row.validate()?;
            if row.owner_namespace != namespace {
                return Ok(None);
            }
            // The record exists under the derived namespace, so its owner row
            // must exist too: the checked stage binds both atomically. The
            // read-grade access object records which right served this view.
            let owner = Self::load_bridge_owner_row_for(&self.database, &namespace)?;
            let access = Self::check_bridge_stream_access(
                &owner,
                owner.revision,
                owner.incarnation,
                BridgeStreamRight::ReadRecover,
            )?;
            let handoff: Option<String> = {
                let handoffs = read.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
                handoffs
                    .get(key.as_str())
                    .map_err(storage)?
                    .map(|value| decode(value.value()))
                    .transpose()?
                    .map(|row: BridgeEventHandoffRow| {
                        row.validate()?;
                        Ok::<String, OrsError>(row.state)
                    })
                    .transpose()?
            };
            let (durable, acked) =
                Self::bridge_cursors_for_checked(&self.database, &access.namespace)?;
            return Ok(Some(Self::bridge_event_outcome_checked(
                &row,
                "conflict",
                durable,
                acked,
                false,
                handoff.as_deref(),
                &access.namespace,
            )));
        }
        // No live row: consult the retained replay commitment before
        // answering unknown, so a changed compacted replay conflicts with
        // evidence. Served only under the derived namespace — a foreign
        // or unknown identity still returns `Ok(None)`.
        let commitment: Option<BridgeEventReplayCommitment> = {
            let commitments = read
                .open_table(BRIDGE_EVENT_REPLAY_COMMITMENTS)
                .map_err(storage)?;
            commitments
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
        };
        let Some(commitment) = commitment else {
            return Ok(None);
        };
        if commitment.owner_namespace != namespace || commitment.event_id != event_id {
            return Ok(None);
        }
        let owner = Self::load_bridge_owner_row_for(&self.database, &namespace)?;
        let access = Self::check_bridge_stream_access(
            &owner,
            owner.revision,
            owner.incarnation,
            BridgeStreamRight::ReadRecover,
        )?;
        let (durable, acked) = Self::bridge_cursors_for_checked(&self.database, &access.namespace)?;
        Ok(Some(Self::bridge_event_outcome_from_commitment(
            &commitment,
            "conflict",
            durable,
            acked,
            None,
        )))
    }

    /// Serves one bounded pending page inside an owner namespace (issue
    /// #2729). Same shape and bounds as
    /// [`Self::bridge_event_pending_page`], but rows are selected by the
    /// verified namespace instead of the bare local name, so a page
    /// continuation revalidated against the namespace can never walk into
    /// a foreign stream. Legacy ownerless rows are never served here.
    ///
    /// Issue #2730 marks every item with its coverage meaning: an item at
    /// or below the contiguous durable cursor is covered by it, while an
    /// individually durable out-of-order item is not — a durable event at
    /// sequence 3 never establishes that sequence 2 exists, was
    /// acknowledged, or was applied.
    pub fn bridge_event_pending_page_checked(
        &self,
        namespace: &str,
        after_sequence: u64,
        page_limit: usize,
    ) -> Result<serde_json::Value, OrsError> {
        let owner = Self::load_bridge_owner_row_for(&self.database, namespace)?;
        if owner.kind != BRIDGE_STREAM_OWNER_KIND_STREAM {
            return Err(OrsError::RecoveryOwnerMismatch);
        }
        // The read-grade access object records which right served this
        // page; callers re-resolve the namespace through the owner row on
        // every continuation.
        let access = Self::check_bridge_stream_access(
            &owner,
            owner.revision,
            owner.incarnation,
            BridgeStreamRight::ReadRecover,
        )?;
        if page_limit == 0 || page_limit > MAX_BRIDGE_EVENT_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        let (durable, acked) = Self::bridge_cursors_for_checked(&self.database, &access.namespace)?;
        let read = self.database.begin_read().map_err(storage)?;
        let mut rows: Vec<BridgeEventRow> = Vec::new();
        {
            let records = read.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
            for entry in records.iter().map_err(storage)? {
                let (_, value) = entry.map_err(storage)?;
                let row: BridgeEventRow = decode(value.value())?;
                row.validate()?;
                if row.owner_namespace == access.namespace && row.sequence > after_sequence {
                    rows.push(row);
                }
            }
        }
        rows.sort_by_key(|row| row.sequence);
        let continuation = if rows.len() > page_limit {
            rows.truncate(page_limit);
            rows.last().map(|row| row.sequence)
        } else {
            None
        };
        let items: Vec<serde_json::Value> = rows
            .iter()
            .map(|row| {
                json!({
                    "event_id": row.event_id,
                    "sequence": row.sequence,
                    "phase": row.phase,
                    "disposition": "accepted",
                    "envelope_sha256": row.envelope_sha256,
                    "producer_id": row.producer_id,
                    "producer_generation": row.producer_generation,
                    "staging_connection": row.staging_connection,
                    "covered_by_durable_cursor": row.sequence <= durable,
                })
            })
            .collect();
        Ok(json!({
            "stream_id": owner.local_stream,
            "durable_cursor": durable,
            "acked_cursor": acked,
            "items": items,
            "continuation": continuation,
        }))
    }

    /// Finds the stream owner rows matching one presenter and local name
    /// inside a write transaction (issue #2729). Used where the presented
    /// entry names no producer (acknowledgement frontier, scoped gap):
    /// exactly one match resolves; zero or several fail closed with
    /// [`OrsError::RecoveryOwnerMismatch`] instead of guessing.
    fn find_stream_owners_in(
        write: &redb::WriteTransaction,
        lineage: &str,
        principal: &str,
        local: &str,
    ) -> Result<Vec<BridgeStreamOwnerRow>, OrsError> {
        let owners = write.open_table(BRIDGE_STREAM_OWNERS).map_err(storage)?;
        let mut matched = Vec::new();
        for entry in owners.iter().map_err(storage)? {
            let (_, value) = entry.map_err(storage)?;
            let row: BridgeStreamOwnerRow = decode(value.value())?;
            row.validate()?;
            if row.kind == BRIDGE_STREAM_OWNER_KIND_STREAM
                && row.authority_lineage == lineage
                && row.principal == principal
                && row.local_stream == local
            {
                matched.push(row);
            }
        }
        Ok(matched)
    }

    /// Finds the stream owner rows matching one presenter and local name
    /// under a read transaction (issue #2729). Read-only counterpart of
    /// [`Self::find_stream_owners_in`] for the pre-commit resolution step.
    fn find_stream_owners_for(
        database: &Database,
        lineage: &str,
        principal: &str,
        local: &str,
    ) -> Result<Vec<BridgeStreamOwnerRow>, OrsError> {
        let read = database.begin_read().map_err(storage)?;
        let owners = read.open_table(BRIDGE_STREAM_OWNERS).map_err(storage)?;
        let mut matched = Vec::new();
        for entry in owners.iter().map_err(storage)? {
            let (_, value) = entry.map_err(storage)?;
            let row: BridgeStreamOwnerRow = decode(value.value())?;
            row.validate()?;
            if row.kind == BRIDGE_STREAM_OWNER_KIND_STREAM
                && row.authority_lineage == lineage
                && row.principal == principal
                && row.local_stream == local
            {
                matched.push(row);
            }
        }
        Ok(matched)
    }

    /// Resolves one acknowledgement-frontier entry to its admitted owner
    /// namespace without mutating anything (issue #2729, item 3). The
    /// evidence carries the presenter's lineage and principal plus the
    /// local stream; the producer comes from the retained binding, never
    /// from the entry. Zero or ambiguous matches fail the whole batch
    /// closed at the route: a foreign or stale item changes no cursor.
    pub fn resolve_bridge_ack_item(
        &self,
        evidence: &serde_json::Value,
        local_stream: &str,
    ) -> Result<serde_json::Value, OrsError> {
        let (lineage, principal) = Self::bridge_owner_presenter_from(evidence)?;
        bridge_identity_text(local_stream, "stream_id")?;
        let matched =
            Self::find_stream_owners_for(&self.database, &lineage, &principal, local_stream)?;
        let [row] = matched.as_slice() else {
            return Err(OrsError::RecoveryOwnerMismatch);
        };
        Ok(json!({
            "namespace": row.namespace,
            "incarnation": row.incarnation,
            "revision": row.revision,
        }))
    }

    /// Applies one accepted acknowledgement batch atomically (issue #2729,
    /// item 3). Every item carries the resolved namespace with its
    /// expected revision/incarnation plus the presenter's lineage and
    /// principal and the requested sequence. The single write transaction
    /// first validates every item — shape, contradictory duplicates,
    /// stored binding, expected revision/incarnation, lineage/principal
    /// equality, and phase/frontier — and only then advances the cursors
    /// and compacts. Any failure aborts the transaction, so a foreign or
    /// stale item changes no batch cursor or retained payload. The commit
    /// is the last fallible operation: after it, only infallible JSON
    /// assembly remains, so a storage/response failure past the commit is
    /// an unknown/replayable result, never evidence that nothing
    /// happened. No atomicity with the separate Governor store is
    /// claimed: handoff reconciliation stays a separate step owned by the
    /// route.
    pub fn acknowledge_bridge_event_batch(
        &self,
        batch: &serde_json::Value,
    ) -> Result<serde_json::Value, OrsError> {
        let items = batch
            .get("items")
            .and_then(serde_json::Value::as_array)
            .ok_or(OrsError::InvalidField {
                field: "ack_batch",
                reason: "acknowledgement batch must carry a bounded item list",
            })?;
        if items.is_empty() || items.len() > MAX_BRIDGE_ACK_BATCH {
            return Err(OrsError::InvalidField {
                field: "ack_batch",
                reason: "acknowledgement batch must be nonempty and bounded",
            });
        }
        let parsed = Self::parse_bridge_ack_batch(items)?;
        let write = self.database.begin_write().map_err(storage)?;
        let mut outcomes = Vec::with_capacity(parsed.len());
        for item in &parsed {
            let owner = Self::load_bridge_owner_row_in(&write, &item.namespace)?;
            if owner.kind != BRIDGE_STREAM_OWNER_KIND_STREAM
                || owner.authority_lineage != item.lineage
                || owner.principal != item.principal
            {
                return Err(OrsError::RecoveryOwnerMismatch);
            }
            let access = Self::check_bridge_stream_access(
                &owner,
                item.expected_revision,
                item.expected_incarnation,
                BridgeStreamRight::Acknowledge,
            )?;
            let (durable, mut acked) = Self::bridge_cursors_in_checked(&write, &access)?;
            let prior_acked = acked;
            if item.sequence > durable {
                return Err(OrsError::InvalidTransition);
            }
            if item.sequence > acked {
                acked = item.sequence;
                Self::write_bridge_cursors_in_checked(
                    &write,
                    &access,
                    &owner.local_stream,
                    durable,
                    acked,
                )?;
            }
            let pruned = Self::compact_bridge_events_in_checked(
                &write,
                &access,
                &owner.local_stream,
                durable,
                acked,
            )?;
            if acked > prior_acked || pruned > 0 {
                Self::bump_bridge_recovery_revision_in(&write, &access.namespace)?;
            }
            outcomes.push(json!({
                "namespace": access.namespace,
                "durable_cursor": durable,
                "acked_cursor": acked,
                "pruned": pruned,
            }));
        }
        write.commit().map_err(storage)?;
        Ok(json!({ "streams": outcomes }))
    }

    /// Parses and deduplicates one acknowledgement batch (issue #2729).
    /// Contradictory duplicate entries — the same namespace twice with a
    /// different sequence, lineage, principal, or expectation — fail the
    /// whole batch; exact duplicates collapse to one item.
    fn parse_bridge_ack_batch(items: &[serde_json::Value]) -> Result<Vec<BridgeAckItem>, OrsError> {
        let mut parsed: Vec<BridgeAckItem> = Vec::with_capacity(items.len());
        for item in items {
            let namespace = bridge_text(item, "namespace")?;
            crate::model::validate_digest(&namespace, "owner_namespace")?;
            let expected_revision = item
                .get("expected_revision")
                .and_then(serde_json::Value::as_u64)
                .ok_or(OrsError::InvalidField {
                    field: "expected_revision",
                    reason: "acknowledgement items must carry the expected owner revision",
                })?;
            let expected_incarnation = item
                .get("expected_incarnation")
                .and_then(serde_json::Value::as_u64)
                .ok_or(OrsError::InvalidField {
                    field: "expected_incarnation",
                    reason: "acknowledgement items must carry the expected stream incarnation",
                })?;
            if expected_revision == 0 || expected_incarnation == 0 {
                return Err(OrsError::InvalidField {
                    field: "expected_revision",
                    reason: "expected owner revision and incarnation must be nonzero",
                });
            }
            let sequence = item
                .get("sequence")
                .and_then(serde_json::Value::as_u64)
                .ok_or(OrsError::InvalidField {
                    field: "sequence",
                    reason: "acknowledgement sequence must be a non-negative integer",
                })?;
            if sequence == 0 {
                return Err(OrsError::InvalidField {
                    field: "sequence",
                    reason: "acknowledgement sequence must be nonzero",
                });
            }
            let (lineage, principal) = Self::bridge_owner_presenter_from(item)?;
            let candidate = BridgeAckItem {
                namespace,
                expected_revision,
                expected_incarnation,
                sequence,
                lineage,
                principal,
            };
            if let Some(prior) = parsed
                .iter()
                .find(|prior| prior.namespace == candidate.namespace)
            {
                if prior.sequence != candidate.sequence
                    || prior.expected_revision != candidate.expected_revision
                    || prior.expected_incarnation != candidate.expected_incarnation
                    || prior.lineage != candidate.lineage
                    || prior.principal != candidate.principal
                {
                    return Err(OrsError::InvalidField {
                        field: "ack_batch",
                        reason: "acknowledgement batch carries contradictory duplicate entries",
                    });
                }
                continue;
            }
            parsed.push(candidate);
        }
        Ok(parsed)
    }

    /// Builds the retained replay commitment for one evicted payload row
    /// (issues #2730 and #2731, item 4): the original admitted identity and
    /// content commitment with its representation facts, so the admitted
    /// identity and content commitment outlives payload eviction. Shared by
    /// window-driven compaction and receipt-driven retirement, so both
    /// eviction paths retain identical evidence.
    fn bridge_replay_commitment_for(
        victim: &BridgeEventRow,
        now_ms: u64,
        acked: u64,
    ) -> BridgeEventReplayCommitment {
        BridgeEventReplayCommitment {
            contract_version: crate::CONTRACT_VERSION,
            commitment_version: BRIDGE_REPLAY_COMMITMENT_VERSION,
            owner_namespace: victim.owner_namespace.clone(),
            stream_id: victim.stream_id.clone(),
            event_id: victim.event_id.clone(),
            sequence: victim.sequence,
            producer_id: victim.producer_id.clone(),
            producer_generation: victim.producer_generation,
            authority_epoch: victim.authority_epoch.clone(),
            envelope_sha256: victim.envelope_sha256.clone(),
            transport_hash: if victim.transport_hash.is_empty() {
                victim.envelope_sha256.clone()
            } else {
                victim.transport_hash.clone()
            },
            redacted: victim.redacted,
            redacted_classes: victim.redacted_classes.clone(),
            redaction_marker: victim.redaction_marker.clone(),
            redaction_version: victim.redaction_version,
            compacted_at_ms: now_ms,
            acked_at_compaction: acked,
        }
    }

    /// Compacts acknowledged rows of one owner namespace past the
    /// retention window inside the acknowledgement transaction (issue
    /// #2729). Only durable rows at or below the acked frontier minus the
    /// retained window are eligible; unacknowledged rows, the retention
    /// window, and the cursor facts are never touched.
    ///
    /// Issue #2730 retains identity before evicting payload: every
    /// compacted row first persists its original admitted commitment
    /// (identity, original content commitment, representation facts) in
    /// the same transaction, and the cursor's compacted boundary advances
    /// to the highest compacted sequence with it. The ordered position
    /// binding is never removed — one admitted position keeps naming its
    /// one logical event. Exact replays afterwards answer from the
    /// commitment with `fresh: false`; changed content under a committed
    /// identity conflicts instead of committing.
    #[allow(
        clippy::too_many_lines,
        reason = "compaction keeps commitment retention, eviction, and boundary advance in one auditable step"
    )]
    fn compact_bridge_events_in_checked(
        write: &redb::WriteTransaction,
        access: &BridgeStreamAccess,
        local_stream: &str,
        durable: u64,
        acked: u64,
    ) -> Result<u64, OrsError> {
        access.require(BridgeStreamRight::Acknowledge)?;
        let now_ms = current_unix_ms_u64()?;
        let floor = acked.saturating_sub(RETAIN_BRIDGE_EVENT_ACKED_PER_STREAM);
        if floor == 0 {
            return Ok(0);
        }
        let victims: Vec<BridgeEventRow> = {
            let records = write.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
            let mut found = Vec::new();
            for entry in records.iter().map_err(storage)? {
                let (_, value) = entry.map_err(storage)?;
                let row: BridgeEventRow = decode(value.value())?;
                row.validate()?;
                if row.owner_namespace == access.namespace
                    && row.sequence <= floor
                    && row.phase == BRIDGE_EVENT_PHASE_DURABLE
                {
                    found.push(row);
                }
            }
            found
        };
        if victims.is_empty() {
            return Ok(0);
        }
        let mut pruned = 0_u64;
        let mut compacted_boundary = 0_u64;
        for victim in &victims {
            let commitment = Self::bridge_replay_commitment_for(victim, now_ms, acked);
            // A legacy-shaped row predating the privacy decision stores
            // its verbatim bytes bound by the identity digest; its
            // commitment is the admissible form, never a projection.
            Self::write_bridge_commitment_in(write, &commitment)?;
            compacted_boundary = compacted_boundary.max(victim.sequence);
            pruned += 1;
        }
        {
            let mut records = write.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
            for victim in &victims {
                let key = format!("{}::{}", victim.owner_namespace, victim.event_id);
                records.remove(key.as_str()).map_err(storage)?;
            }
        }
        Self::write_bridge_cursors_compacted_in(
            write,
            access,
            local_stream,
            durable,
            acked,
            compacted_boundary,
        )?;
        Ok(pruned)
    }

    /// Rebuilds the bridge position index and reconciles replay state
    /// with the retained owner-bound records under one migration/version
    /// contract (issue #2730, item 6). Runs inside the store-open
    /// transaction owned by [`Self::initialize`], so restart preserves
    /// every replay-identity property the writers maintain.
    ///
    /// The contract: the `META` marker must be absent (first migration)
    /// or exactly [`BRIDGE_REPLAY_INDEX_SCHEMA_V1`]; any other value
    /// fails open closed with [`OrsError::MigrationRequired`]. On a first
    /// migration the full reconcile below runs and the marker is set; on
    /// later opens the marker is re-verified and only missing position
    /// entries are backfilled, keeping open-time work proportional to
    /// drift rather than history. Contradictory event/position mappings,
    /// mismatched keys, invalid counters, and missing required replay
    /// bindings fail closed with [`OrsError::IntegrityProblem`] instead
    /// of choosing the first or latest row; conflicting history is
    /// preserved, never silently deleted, and cursors are never reset —
    /// only the new `last_observed_sequence` field is deterministically
    /// backfilled where a unique correct value exists. Legacy ownerless
    /// rows stay preserved and are never inferred into the checked index.
    /// Forbidden raw content is never regenerated: the rebuild reads
    /// identity and commitment fields only, never `envelope_bytes`.
    fn rebuild_bridge_replay_index(write: &redb::WriteTransaction) -> Result<(), OrsError> {
        let marker: Option<String> = {
            let meta = write.open_table(META).map_err(storage)?;
            match meta.get(BRIDGE_REPLAY_INDEX_SCHEMA_KEY).map_err(storage)? {
                Some(value) if value.value().len() > MAX_ORS_MARKER_BYTES => {
                    return Err(OrsError::ProjectionLimitExceeded);
                }
                Some(value) => Some(value.value().to_owned()),
                None => None,
            }
        };
        match marker.as_deref() {
            None => {}
            Some(marker) if marker == BRIDGE_REPLAY_INDEX_SCHEMA_V1 => {}
            Some(_) => {
                return Err(OrsError::MigrationRequired {
                    reason: "bridge replay index schema marker is not the current version"
                        .to_owned(),
                });
            }
        }
        let first_migration = marker.is_none();
        if first_migration {
            Self::reconcile_bridge_replay_index(write)?;
            let mut meta = write.open_table(META).map_err(storage)?;
            meta.insert(
                BRIDGE_REPLAY_INDEX_SCHEMA_KEY,
                BRIDGE_REPLAY_INDEX_SCHEMA_V1,
            )
            .map_err(storage)?;
        } else {
            Self::backfill_bridge_positions(write)?;
        }
        Ok(())
    }

    /// Backfills position entries missing for live owner-bound rows
    /// (issue #2730, item 6): the idempotent steady-state half of the
    /// migration. Never deletes, never overwrites, never guesses — an
    /// occupant position under a different event fails closed.
    fn backfill_bridge_positions(write: &redb::WriteTransaction) -> Result<(), OrsError> {
        let live: Vec<(String, u64, String)> = {
            let records = write.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
            let mut live = Vec::new();
            for entry in records.iter().map_err(storage)? {
                let (_, value) = entry.map_err(storage)?;
                let row: BridgeEventRow = decode(value.value())?;
                if row.owner_namespace.is_empty() {
                    continue;
                }
                live.push((
                    row.owner_namespace.clone(),
                    row.sequence,
                    row.event_id.clone(),
                ));
            }
            live
        };
        for (namespace, sequence, event_id) in &live {
            let key = Self::bridge_position_key(namespace, *sequence);
            let occupant: Option<BridgeEventPosition> = {
                let positions = write.open_table(BRIDGE_EVENT_POSITIONS).map_err(storage)?;
                positions
                    .get(key.as_str())
                    .map_err(storage)?
                    .map(|value| decode(value.value()))
                    .transpose()?
            };
            match occupant {
                None => {
                    let position = BridgeEventPosition {
                        event_id: event_id.clone(),
                    };
                    position.validate()?;
                    let mut positions =
                        write.open_table(BRIDGE_EVENT_POSITIONS).map_err(storage)?;
                    positions
                        .insert(key.as_str(), encode(&position)?.as_str())
                        .map_err(storage)?;
                }
                Some(position) if position.event_id == *event_id => {}
                Some(_) => {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_event_position",
                        reason: "position index binds a different event than the retained record"
                            .to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Fully reconciles positions, commitments, cursors, and owners on
    /// first migration (issue #2730, item 6). Every contradiction fails
    /// closed; missing position entries are rebuilt from the retained
    /// owner-bound records; cursor `last_observed_sequence` gaps are
    /// backfilled from the deterministic maximum. Nothing is deleted and
    /// no cursor frontier moves.
    #[allow(
        clippy::too_many_lines,
        reason = "index migration keeps owner, record, commitment, position, and cursor reconciliation in one auditable pass"
    )]
    fn reconcile_bridge_replay_index(write: &redb::WriteTransaction) -> Result<(), OrsError> {
        let mut stream_owners: BTreeMap<String, String> = BTreeMap::new();
        {
            let owners = write.open_table(BRIDGE_STREAM_OWNERS).map_err(storage)?;
            for entry in owners.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                let row: BridgeStreamOwnerRow = decode(value.value())?;
                if row.namespace != key.value() {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_stream_owner",
                        reason: "owner row identity does not match its key".to_owned(),
                    });
                }
                if row.kind == BRIDGE_STREAM_OWNER_KIND_STREAM {
                    stream_owners.insert(row.namespace.clone(), row.local_stream.clone());
                }
            }
        }
        let mut record_positions: BTreeMap<(String, u64), String> = BTreeMap::new();
        let mut record_identities: BTreeMap<(String, String), u64> = BTreeMap::new();
        let mut observed_max: BTreeMap<String, u64> = BTreeMap::new();
        {
            let records = write.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
            for entry in records.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                let row: BridgeEventRow = decode(value.value())?;
                if row.owner_namespace.is_empty() {
                    continue;
                }
                let Some(local) = stream_owners.get(&row.owner_namespace) else {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_event_record",
                        reason: "record names an unbound owner namespace".to_owned(),
                    });
                };
                if local != &row.stream_id {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_event_record",
                        reason: "record stream does not match its owner binding".to_owned(),
                    });
                }
                let expected_key = format!("{}::{}", row.owner_namespace, row.event_id);
                if key.value() != expected_key {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_event_record",
                        reason: "record key does not match its owner namespace and event identity"
                            .to_owned(),
                    });
                }
                if let Some(prior) =
                    record_positions.get(&(row.owner_namespace.clone(), row.sequence))
                {
                    if prior != &row.event_id {
                        return Err(OrsError::IntegrityProblem {
                            record_type: "bridge_event_record",
                            reason: "duplicate stream position binds two event identities"
                                .to_owned(),
                        });
                    }
                } else {
                    record_positions.insert(
                        (row.owner_namespace.clone(), row.sequence),
                        row.event_id.clone(),
                    );
                }
                if let Some(prior) =
                    record_identities.get(&(row.owner_namespace.clone(), row.event_id.clone()))
                {
                    if prior != &row.sequence {
                        return Err(OrsError::IntegrityProblem {
                            record_type: "bridge_event_record",
                            reason: "event identity binds two stream positions".to_owned(),
                        });
                    }
                } else {
                    record_identities.insert(
                        (row.owner_namespace.clone(), row.event_id.clone()),
                        row.sequence,
                    );
                }
                observed_max
                    .entry(row.owner_namespace.clone())
                    .and_modify(|held| *held = (*held).max(row.sequence))
                    .or_insert(row.sequence);
            }
        }
        let mut commitment_identities: BTreeMap<(String, String), u64> = BTreeMap::new();
        {
            let commitments = write
                .open_table(BRIDGE_EVENT_REPLAY_COMMITMENTS)
                .map_err(storage)?;
            for entry in commitments.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                let commitment: BridgeEventReplayCommitment = decode(value.value())?;
                if !stream_owners.contains_key(&commitment.owner_namespace) {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_event_replay_commitment",
                        reason: "commitment names an unbound owner namespace".to_owned(),
                    });
                }
                let expected_key = commitment.record_key();
                if key.value() != expected_key {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_event_replay_commitment",
                        reason: "commitment key does not match its retained identity".to_owned(),
                    });
                }
                if record_identities.contains_key(&(
                    commitment.owner_namespace.clone(),
                    commitment.event_id.clone(),
                )) {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_event_replay_commitment",
                        reason: "live row and replay commitment overlap on one identity".to_owned(),
                    });
                }
                commitment_identities.insert(
                    (
                        commitment.owner_namespace.clone(),
                        commitment.event_id.clone(),
                    ),
                    commitment.sequence,
                );
                observed_max
                    .entry(commitment.owner_namespace.clone())
                    .and_modify(|held| *held = (*held).max(commitment.sequence))
                    .or_insert(commitment.sequence);
            }
        }
        {
            let positions = write.open_table(BRIDGE_EVENT_POSITIONS).map_err(storage)?;
            let mut indexed: BTreeMap<(String, u64), String> = BTreeMap::new();
            for entry in positions.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                let (namespace, sequence) = Self::parse_bridge_position_key(key.value())?;
                let position: BridgeEventPosition = decode(value.value())?;
                if let Some(prior) = indexed.get(&(namespace.clone(), sequence)) {
                    if prior != &position.event_id {
                        return Err(OrsError::IntegrityProblem {
                            record_type: "bridge_event_position",
                            reason: "position index binds two event identities".to_owned(),
                        });
                    }
                    continue;
                }
                indexed.insert((namespace.clone(), sequence), position.event_id.clone());
                if let Some(record_event) = record_positions.get(&(namespace.clone(), sequence)) {
                    if record_event != &position.event_id {
                        return Err(OrsError::IntegrityProblem {
                            record_type: "bridge_event_position",
                            reason:
                                "position index binds a different event than the retained record"
                                    .to_owned(),
                        });
                    }
                } else if let Some(committed) =
                    commitment_identities.get(&(namespace.clone(), position.event_id.clone()))
                    && committed != &sequence
                {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_event_position",
                        reason: "position index disagrees with the retained commitment".to_owned(),
                    });
                }
            }
        }
        Self::backfill_bridge_positions(write)?;
        {
            let cursors = write.open_table(BRIDGE_EVENT_CURSORS).map_err(storage)?;
            let mut rows: Vec<(String, BridgeEventCursorRow)> = Vec::new();
            for entry in cursors.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                let row: BridgeEventCursorRow = decode(value.value())?;
                rows.push((key.value().to_owned(), row));
            }
            drop(cursors);
            for (key, mut row) in rows {
                if row.owner_namespace.is_empty() {
                    continue;
                }
                if key != row.owner_namespace {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_event_cursor",
                        reason: "cursor key does not match its owner namespace".to_owned(),
                    });
                }
                if !stream_owners.contains_key(&row.owner_namespace) {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "bridge_event_cursor",
                        reason: "cursor names an unbound owner namespace".to_owned(),
                    });
                }
                let floor = observed_max
                    .get(&row.owner_namespace)
                    .copied()
                    .unwrap_or(row.last_durable_sequence)
                    .max(row.last_durable_sequence);
                if row.last_observed_sequence != floor {
                    row.last_observed_sequence = floor;
                    row.validate()?;
                    let mut cursors = write.open_table(BRIDGE_EVENT_CURSORS).map_err(storage)?;
                    cursors
                        .insert(key.as_str(), encode(&row)?.as_str())
                        .map_err(storage)?;
                }
            }
        }
        Ok(())
    }

    /// Records one forwarded coverage gap under its admitted owner
    /// namespace without touching any cursor (issue #2729, items 4-5).
    ///
    /// The gap JSON carries the presenter's owner evidence plus the
    /// occurrence the Kernel route derived from the retained Session. A
    /// scoped gap (nonempty stream) resolves to the stream's retained
    /// owner — exactly one match, never created by the gap itself — and
    /// rides that stream's visibility. An unscoped gap (empty stream)
    /// binds-or-creates the reporter-occurrence namespace, giving the
    /// connection-level observation its own admitted owner without a
    /// fabricated task or a bare global gap ID. Changed content under a
    /// known key fails with [`OrsError::DuplicateConflict`]; a gap for an
    /// unknown or ambiguous stream fails with
    /// [`OrsError::RecoveryOwnerMismatch`].
    pub fn record_bridge_event_gap_checked(
        &self,
        gap: &serde_json::Value,
    ) -> Result<serde_json::Value, OrsError> {
        let parsed = Self::parse_bridge_gap_checked(gap)?;
        let now_ms = current_unix_ms_u64()?;
        let write = self.database.begin_write().map_err(storage)?;
        let (namespace, key) = Self::resolve_bridge_gap_key_in(&write, &parsed, now_ms)?;
        {
            let gaps = write.open_table(BRIDGE_EVENT_GAPS).map_err(storage)?;
            if gaps.get(key.as_str()).map_err(storage)?.is_none() {
                let mut scoped_gaps = 0_usize;
                for entry in gaps.iter().map_err(storage)? {
                    let (_, value) = entry.map_err(storage)?;
                    let row: BridgeEventGapRow = decode(value.value())?;
                    row.validate()?;
                    if row.owner_namespace == namespace {
                        scoped_gaps += 1;
                    }
                }
                if scoped_gaps >= MAX_BRIDGE_EVENT_GAPS_PER_STREAM {
                    return Err(OrsError::ProjectionLimitExceeded);
                }
            }
        }
        if let Some(existing) = {
            let gaps = write.open_table(BRIDGE_EVENT_GAPS).map_err(storage)?;
            gaps.get(key.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
        } {
            let existing: BridgeEventGapRow = existing;
            existing.validate()?;
            if existing.owner_namespace != namespace
                || existing.stream_id != parsed.stream_id
                || existing.start_sequence != parsed.start_sequence
                || existing.end_sequence != parsed.end_sequence
                || existing.reason_ref != parsed.reason_ref
            {
                return Err(OrsError::DuplicateConflict);
            }
            write.commit().map_err(storage)?;
            return Ok(json!({ "gap_id": parsed.gap_id, "accepted": true, "fresh": false }));
        }
        let row = BridgeEventGapRow {
            contract_version: crate::CONTRACT_VERSION,
            gap_id: parsed.gap_id.clone(),
            stream_id: parsed.stream_id.clone(),
            start_sequence: parsed.start_sequence,
            end_sequence: parsed.end_sequence,
            reason_ref: parsed.reason_ref.clone(),
            staging_connection: parsed.staging_connection.clone(),
            recorded_at_ms: now_ms,
            owner_namespace: namespace,
        };
        row.validate()?;
        {
            let mut gaps = write.open_table(BRIDGE_EVENT_GAPS).map_err(storage)?;
            gaps.insert(key.as_str(), encode(&row)?.as_str())
                .map_err(storage)?;
        }
        Self::bump_bridge_recovery_revision_in(&write, &row.owner_namespace)?;
        write.commit().map_err(storage)?;
        Ok(json!({ "gap_id": parsed.gap_id, "accepted": true, "fresh": true }))
    }

    /// Parses and validates one owner-checked gap request (issue #2729):
    /// the gap identity and interval with the presenter's lineage,
    /// principal, and creating occurrence.
    fn parse_bridge_gap_checked(gap: &serde_json::Value) -> Result<BridgeCheckedGap, OrsError> {
        let start_sequence = bridge_sequence(gap, "start_sequence")?;
        let end_sequence = bridge_sequence(gap, "end_sequence")?;
        if end_sequence < start_sequence {
            return Err(OrsError::InvalidField {
                field: "end_sequence",
                reason: "gap interval must not end before it starts",
            });
        }
        let (lineage, principal) = Self::bridge_owner_presenter_from(gap)?;
        Ok(BridgeCheckedGap {
            gap_id: bridge_text(gap, "gap_id")?,
            stream_id: bridge_gap_stream_text(gap)?,
            start_sequence,
            end_sequence,
            reason_ref: bridge_text(gap, "reason_ref")?,
            staging_connection: bridge_text(gap, "staging_connection")?,
            lineage,
            principal,
            connection: bridge_text(gap, "owner_connection")?,
            launch_nonce: bridge_text(gap, "owner_launch_nonce")?,
            session_epoch: Self::bridge_owner_epoch(gap)?,
        })
    }

    /// Resolves the owner namespace and storage key for one checked gap
    /// inside the record transaction (issue #2729). Scoped gaps resolve
    /// to exactly one retained stream owner — the gap never creates
    /// stream ownership. Unscoped gaps bind-or-create the reporter's own
    /// occurrence namespace.
    fn resolve_bridge_gap_key_in(
        write: &redb::WriteTransaction,
        parsed: &BridgeCheckedGap,
        now_ms: u64,
    ) -> Result<(String, String), OrsError> {
        if parsed.stream_id.is_empty() {
            let namespace = Self::bridge_gap_owner_digest(&parsed.lineage, &parsed.principal)?;
            let evidence = BridgeOwnerEvidence {
                lineage: parsed.lineage.clone(),
                principal: parsed.principal.clone(),
                producer: HOST_REQUEST_UNBOUND_MARKER.to_owned(),
                local: HOST_REQUEST_UNBOUND_MARKER.to_owned(),
                connection: parsed.connection.clone(),
                launch_nonce: parsed.launch_nonce.clone(),
                session_epoch: parsed.session_epoch,
            };
            Self::bind_bridge_stream_owner_in(
                write,
                &evidence,
                BRIDGE_STREAM_OWNER_KIND_UNSCOPED_GAP,
                &namespace,
                now_ms,
            )?;
            let key = format!("{namespace}::{gap}", gap = parsed.gap_id);
            return Ok((namespace, key));
        }
        let matched = Self::find_stream_owners_in(
            write,
            &parsed.lineage,
            &parsed.principal,
            &parsed.stream_id,
        )?;
        let [owner] = matched.as_slice() else {
            return Err(OrsError::RecoveryOwnerMismatch);
        };
        let access = Self::check_bridge_stream_access(
            owner,
            owner.revision,
            owner.incarnation,
            BridgeStreamRight::PublishGap,
        )?;
        let key = format!("{}::{gap}", access.namespace, gap = parsed.gap_id);
        Ok((access.namespace, key))
    }

    /// Records the Governor-handoff for one owner-checked staged event
    /// (issue #2729, item 4). Verifies the namespace names a retained
    /// owner, then persists the handoff under the namespaced key with the
    /// staged envelope digest. Exact replays return the existing handoff;
    /// changed bytes fail with [`OrsError::DuplicateConflict`].
    ///
    /// Issue #2730 cross-checks the handoff against the retained event
    /// before writing it: the handoff binds a durably staged identity, so
    /// a live row must agree on digest and sequence, else the request
    /// conflicts instead of recording intake for another event's bytes. A
    /// retired identity (compacted row with a matching retained
    /// commitment, or a sequence at/below the retained compacted boundary)
    /// answers a retired receipt with `fresh: false` and writes nothing —
    /// the handoff never fabricates intake for an event with no retained
    /// evidence, and a handoff for a never-staged identity is an invalid
    /// transition rather than a synthesized intake claim.
    #[allow(
        clippy::too_many_lines,
        reason = "handoff record keeps the live, committed, retired, and unknown branches in one auditable decision"
    )]
    pub fn record_bridge_event_handoff_checked(
        &self,
        handoff: &serde_json::Value,
    ) -> Result<serde_json::Value, OrsError> {
        let namespace = bridge_text(handoff, "owner_namespace")?;
        crate::model::validate_digest(&namespace, "owner_namespace")?;
        let event_id = bridge_key_text(handoff, "event_id")?;
        let sequence = bridge_sequence(handoff, "sequence")?;
        let envelope_sha256 = bridge_text(handoff, "envelope_sha256")?;
        crate::model::validate_digest(&envelope_sha256, "envelope_sha256")?;
        let staging_connection = bridge_text(handoff, "staging_connection")?;
        let key = format!("{namespace}::{event_id}");
        let now_ms = current_unix_ms_u64()?;
        let write = self.database.begin_write().map_err(storage)?;
        let outcome = {
            let owner = Self::load_bridge_owner_row_in(&write, &namespace)?;
            let access = Self::check_bridge_stream_access(
                &owner,
                owner.revision,
                owner.incarnation,
                BridgeStreamRight::Append,
            )?;
            let existing: Option<BridgeEventHandoffRow> = {
                let handoffs = write.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
                if handoffs.len().map_err(storage)? >= MAX_BRIDGE_EVENT_HANDOFFS as u64
                    && handoffs.get(key.as_str()).map_err(storage)?.is_none()
                {
                    return Err(OrsError::ProjectionLimitExceeded);
                }
                handoffs
                    .get(key.as_str())
                    .map_err(storage)?
                    .map(|value| decode(value.value()))
                    .transpose()?
            };
            if let Some(row) = existing {
                row.validate()?;
                if row.owner_namespace != access.namespace
                    || row.envelope_sha256 != envelope_sha256
                    || row.sequence != sequence
                {
                    return Err(OrsError::DuplicateConflict);
                }
                json!({
                    "event_id": row.event_id,
                    "sequence": row.sequence,
                    "envelope_sha256": row.envelope_sha256,
                    "state": row.state,
                    "staging_connection": row.staging_connection,
                    "fresh": false,
                })
            } else if let Some(row) = Self::peek_bridge_event_row_in(&write, &key)? {
                row.validate()?;
                if row.owner_namespace != access.namespace
                    || row.envelope_sha256 != envelope_sha256
                    || row.sequence != sequence
                {
                    return Err(OrsError::DuplicateConflict);
                }
                let row = BridgeEventHandoffRow {
                    contract_version: crate::CONTRACT_VERSION,
                    stream_id: owner.local_stream.clone(),
                    event_id: event_id.clone(),
                    sequence,
                    envelope_sha256: envelope_sha256.clone(),
                    state: BRIDGE_EVENT_HANDOFF_HANDED_OFF.to_owned(),
                    staging_connection: staging_connection.clone(),
                    handed_off_at_ms: now_ms,
                    reconcile_key: String::new(),
                    reconciled_at_ms: 0,
                    owner_namespace: access.namespace.clone(),
                    reconcile_acked_sequence: 0,
                    reconcile_owner_revision: 0,
                    reconcile_owner_incarnation: 0,
                };
                row.validate()?;
                {
                    let mut handoffs = write.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
                    handoffs
                        .insert(key.as_str(), encode(&row)?.as_str())
                        .map_err(storage)?;
                }
                json!({
                    "event_id": event_id,
                    "sequence": sequence,
                    "envelope_sha256": envelope_sha256,
                    "state": BRIDGE_EVENT_HANDOFF_HANDED_OFF,
                    "staging_connection": staging_connection,
                    "fresh": true,
                })
            } else {
                Self::retired_handoff_receipt_in(
                    &write,
                    &access,
                    &event_id,
                    sequence,
                    &envelope_sha256,
                    &staging_connection,
                )?
            }
        };
        write.commit().map_err(storage)?;
        Ok(outcome)
    }

    /// Answers a handoff record for an identity with no live row (issue
    /// #2730, items 2 and 5) without writing anything. A retained
    /// commitment must match digest and sequence exactly, else the request
    /// conflicts; without a commitment, only a sequence at or below the
    /// retained compacted boundary answers retired. Anything else names a
    /// never-staged identity, which is an invalid transition — the
    /// handoff never synthesizes intake.
    fn retired_handoff_receipt_in(
        write: &redb::WriteTransaction,
        access: &BridgeStreamAccess,
        event_id: &str,
        sequence: u64,
        envelope_sha256: &str,
        staging_connection: &str,
    ) -> Result<serde_json::Value, OrsError> {
        if let Some(commitment) =
            Self::load_bridge_commitment_in(write, &access.namespace, event_id)?
        {
            if commitment.sequence != sequence || commitment.envelope_sha256 != envelope_sha256 {
                return Err(OrsError::DuplicateConflict);
            }
            return Ok(json!({
                "event_id": event_id,
                "sequence": sequence,
                "envelope_sha256": envelope_sha256,
                "state": BRIDGE_EVENT_DISPOSITION_RETIRED,
                "staging_connection": staging_connection,
                "fresh": false,
            }));
        }
        let compacted = Self::load_bridge_cursor_row_in(write, &access.namespace)?
            .map_or(0, |row| row.last_compacted_sequence);
        if compacted > 0 && sequence <= compacted {
            return Ok(json!({
                "event_id": event_id,
                "sequence": sequence,
                "envelope_sha256": envelope_sha256,
                "state": BRIDGE_EVENT_DISPOSITION_RETIRED,
                "staging_connection": staging_connection,
                "fresh": false,
            }));
        }
        Err(OrsError::InvalidTransition)
    }

    /// Binds owner-checked handed-off events to one reconciliation key
    /// once the consumed frontier covers their sequences (issue #2729,
    /// item 4). Only handoffs carrying the verified namespace reconcile;
    /// legacy ownerless rows and foreign namespaces are untouched. No
    /// cross-store atomicity with the Governor intake is claimed: this
    /// step is idempotent, so a lost answer replays safely.
    pub fn reconcile_bridge_event_handoffs_checked(
        &self,
        namespace: &str,
        acked_sequence: u64,
        reconcile_key: &str,
    ) -> Result<serde_json::Value, OrsError> {
        let owner = Self::load_bridge_owner_row_for(&self.database, namespace)?;
        let access = Self::check_bridge_stream_access(
            &owner,
            owner.revision,
            owner.incarnation,
            BridgeStreamRight::Acknowledge,
        )?;
        if acked_sequence == 0 {
            return Err(OrsError::InvalidField {
                field: "acked_sequence",
                reason: "handoff reconcile sequence must be nonzero",
            });
        }
        crate::model::validate_digest(reconcile_key, "reconcile_key")?;
        let now_ms = current_unix_ms_u64()?;
        let write = self.database.begin_write().map_err(storage)?;
        let mut reconciled = 0_u64;
        {
            let handoffs = write.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
            let mut due = Vec::new();
            for entry in handoffs.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                let row: BridgeEventHandoffRow = decode(value.value())?;
                row.validate()?;
                if row.owner_namespace == access.namespace
                    && row.sequence <= acked_sequence
                    && row.state == BRIDGE_EVENT_HANDOFF_HANDED_OFF
                {
                    due.push(key.value().to_owned());
                }
            }
            if !due.is_empty() {
                drop(handoffs);
                let mut handoffs = write.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
                for key in due {
                    let mut row: BridgeEventHandoffRow = handoffs
                        .get(key.as_str())
                        .map_err(storage)?
                        .map(|value| decode(value.value()))
                        .transpose()?
                        .ok_or(OrsError::InvalidField {
                            field: "event_id",
                            reason: "bridge event handoff disappeared during reconcile",
                        })?;
                    row.validate()?;
                    if row.state != BRIDGE_EVENT_HANDOFF_HANDED_OFF
                        || row.owner_namespace != access.namespace
                    {
                        continue;
                    }
                    BRIDGE_EVENT_HANDOFF_RECONCILED.clone_into(&mut row.state);
                    reconcile_key.clone_into(&mut row.reconcile_key);
                    row.reconciled_at_ms = now_ms;
                    // Receiving-owner receipt (issue #2731, item 1): the
                    // presented consumed frontier with the admitting owner
                    // revision/incarnation is recorded on the transition, so
                    // retirement validates this receipt instead of the bare
                    // state string. Custody acceptance only — the frontier
                    // never claims downstream application.
                    row.reconcile_acked_sequence = acked_sequence;
                    row.reconcile_owner_revision = owner.revision;
                    row.reconcile_owner_incarnation = owner.incarnation;
                    row.validate()?;
                    handoffs
                        .insert(key.as_str(), encode(&row)?.as_str())
                        .map_err(storage)?;
                    reconciled += 1;
                }
            }
        }
        write.commit().map_err(storage)?;
        Ok(json!({
            "namespace": access.namespace,
            "acked_sequence": acked_sequence,
            "reconciled": reconciled,
        }))
    }

    /// Repairs retained events lacking their required handoff during bounded
    /// owner recovery (issue #2731, item 3).
    ///
    /// For one admitted namespace, every live row without a handoff —
    /// including rows staged by the former split commits or left
    /// handoff-less by the expired-submit early return — gains its
    /// `handed_off` row under the ORIGINAL identity (same key, sequence,
    /// digest, staging connection). No new logical event is created: the
    /// row's identity facts are re-validated, the owner binding is checked
    /// against the expected revision/incarnation, and rows at or below the
    /// retained compacted boundary are skipped (their disposition is already
    /// the explicit retired one — historical observation retention there is
    /// not authority to mint fresh delivery evidence). A timeout after stage
    /// is not proof of non-acceptance, so expiry never blocks repair. At
    /// most [`MAX_BRIDGE_HANDOFF_REPAIR_PER_RECOVERY`] rows repair per call;
    /// `repair_continuation` reports whether more missing handoffs remain
    /// for the next legitimate recovery entry. A conflicting handoff fails
    /// the call with [`OrsError::DuplicateConflict`]; a full handoff table
    /// fails with [`OrsError::ProjectionLimitExceeded`] (truthful
    /// backpressure) instead of declaring the missing evidence complete.
    pub fn repair_bridge_event_handoffs_checked(
        &self,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, OrsError> {
        let namespace = bridge_text(request, "namespace")?;
        crate::model::validate_digest(&namespace, "owner_namespace")?;
        let expected_revision = request
            .get("expected_revision")
            .and_then(serde_json::Value::as_u64)
            .ok_or(OrsError::InvalidField {
                field: "expected_revision",
                reason: "handoff repair must carry the expected owner revision",
            })?;
        let expected_incarnation = request
            .get("expected_incarnation")
            .and_then(serde_json::Value::as_u64)
            .ok_or(OrsError::InvalidField {
                field: "expected_incarnation",
                reason: "handoff repair must carry the expected stream incarnation",
            })?;
        if expected_revision == 0 || expected_incarnation == 0 {
            return Err(OrsError::InvalidField {
                field: "expected_revision",
                reason: "expected owner revision and incarnation must be nonzero",
            });
        }
        let budget = request
            .get("budget")
            .map(|value| {
                value.as_u64().ok_or(OrsError::InvalidField {
                    field: "budget",
                    reason: "handoff repair budget must be a non-negative integer",
                })
            })
            .transpose()?
            .unwrap_or(MAX_BRIDGE_HANDOFF_REPAIR_PER_RECOVERY as u64);
        if budget == 0 || budget > MAX_BRIDGE_HANDOFF_REPAIR_PER_RECOVERY as u64 {
            return Err(OrsError::InvalidField {
                field: "budget",
                reason: "handoff repair budget must be within the per-recovery bound",
            });
        }
        let budget = usize::try_from(budget).map_err(|_| OrsError::InvalidField {
            field: "budget",
            reason: "handoff repair budget must fit the platform word",
        })?;
        let write = self.database.begin_write().map_err(storage)?;
        let outcome = Self::repair_bridge_handoffs_in(
            &write,
            &namespace,
            expected_revision,
            expected_incarnation,
            budget,
        )?;
        write.commit().map_err(storage)?;
        Ok(outcome)
    }

    /// Retires eligible handoff rows of one admitted namespace with a finite
    /// work budget and continuation (issue #2731, items 4 and 5).
    ///
    /// Only rows whose delivery obligation is terminal retire: an
    /// owner-checked row with no live payload left, carrying either the
    /// exact receiving-owner receipt (reconciled with the presented
    /// frontier plus its admitting revision/incarnation, covered by the
    /// acked cursor even above the compacted boundary so quiet streams
    /// release their charges) or the admitted terminal disposition
    /// (`handed_off` but covered by the receiver's acked cursor at or below
    /// the retained compacted boundary, whose missing row already answers
    /// the explicit retired disposition). A receipt-complete row whose
    /// payload is still retained terminalizes instead of lingering: its
    /// #2730 replay commitment is retained before the payload and handoff
    /// delete together. Retirement deletes exactly those rows — the
    /// capacity charge releases exactly once because a re-run finds no row
    /// to delete again — while the #2730 position binding, replay
    /// commitment, and compacted boundary keep answering old occurrences
    /// as retired, never fresh. Ownerless legacy rows, live payloads
    /// without receiver evidence, and torn record/handoff identities never
    /// retire: unknown and pending work is never evicted to admit new work,
    /// and legacy reconciled rows are never bulk-deleted by their old state
    /// string. Expected revision/incarnation are validated against the
    /// owner row in the same transaction, so an owner change between
    /// resolution and commit fails closed with
    /// [`OrsError::StaleWriterEpoch`]. At most
    /// [`MAX_BRIDGE_HANDOFF_RETIRE_PER_RECOVERY`] rows retire per call;
    /// `retirement_continuation` resumes the next legitimate recovery entry.
    /// If no safe retirement exists the table stays full and admission keeps
    /// answering backpressure — cursors are never reset and missing evidence
    /// is never declared complete.
    pub fn retire_bridge_event_handoffs_checked(
        &self,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, OrsError> {
        let namespace = bridge_text(request, "namespace")?;
        crate::model::validate_digest(&namespace, "owner_namespace")?;
        let expected_revision = request
            .get("expected_revision")
            .and_then(serde_json::Value::as_u64)
            .ok_or(OrsError::InvalidField {
                field: "expected_revision",
                reason: "handoff retirement must carry the expected owner revision",
            })?;
        let expected_incarnation = request
            .get("expected_incarnation")
            .and_then(serde_json::Value::as_u64)
            .ok_or(OrsError::InvalidField {
                field: "expected_incarnation",
                reason: "handoff retirement must carry the expected stream incarnation",
            })?;
        if expected_revision == 0 || expected_incarnation == 0 {
            return Err(OrsError::InvalidField {
                field: "expected_revision",
                reason: "expected owner revision and incarnation must be nonzero",
            });
        }
        let budget = request
            .get("budget")
            .map(|value| {
                value.as_u64().ok_or(OrsError::InvalidField {
                    field: "budget",
                    reason: "handoff retirement budget must be a non-negative integer",
                })
            })
            .transpose()?
            .unwrap_or(MAX_BRIDGE_HANDOFF_RETIRE_PER_RECOVERY as u64);
        if budget == 0 || budget > MAX_BRIDGE_HANDOFF_RETIRE_PER_RECOVERY as u64 {
            return Err(OrsError::InvalidField {
                field: "budget",
                reason: "handoff retirement budget must be within the per-recovery bound",
            });
        }
        let budget = usize::try_from(budget).map_err(|_| OrsError::InvalidField {
            field: "budget",
            reason: "handoff retirement budget must fit the platform word",
        })?;
        let write = self.database.begin_write().map_err(storage)?;
        let outcome = Self::retire_bridge_handoffs_in(
            &write,
            &namespace,
            expected_revision,
            expected_incarnation,
            budget,
        )?;
        write.commit().map_err(storage)?;
        Ok(outcome)
    }

    /// Repairs one namespace's missing handoffs inside the recovery
    /// transaction (issue #2731, items 3 and 4). The scan filters by the
    /// namespaced key prefix before decoding, so foreign and legacy rows
    /// cost no decode; every touched row is re-validated and
    /// namespace-checked, and the created handoff binds the row's exact
    /// identity facts. Candidates are live retained records at any
    /// sequence: a live record below the compacted boundary still carries
    /// a real delivery obligation (terminal retirement always deletes the
    /// record together with its handoff, so a retained record is pending
    /// or a legacy split — never terminal), and receipt-driven retirement
    /// may advance the boundary past interleaved pending sequences, so a
    /// boundary skip would blind repair to exactly the rows item 3 must
    /// restore. Terminalized rows have no retained record and are never
    /// candidates, so repair cannot resurrect them.
    fn repair_bridge_handoffs_in(
        write: &redb::WriteTransaction,
        namespace: &str,
        expected_revision: u64,
        expected_incarnation: u64,
        budget: usize,
    ) -> Result<serde_json::Value, OrsError> {
        let owner = Self::load_bridge_owner_row_in(write, namespace)?;
        if owner.kind != BRIDGE_STREAM_OWNER_KIND_STREAM {
            return Err(OrsError::RecoveryOwnerMismatch);
        }
        let access = Self::check_bridge_stream_access(
            &owner,
            expected_revision,
            expected_incarnation,
            BridgeStreamRight::Append,
        )?;
        let prefix = format!("{namespace}::");
        let mut candidates: Vec<BridgeEventRow> = Vec::new();
        {
            let records = write.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
            for entry in records.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                if !key.value().starts_with(prefix.as_str()) {
                    continue;
                }
                let row: BridgeEventRow = decode(value.value())?;
                row.validate()?;
                if row.owner_namespace != access.namespace {
                    continue;
                }
                candidates.push(row);
            }
        }
        candidates.sort_by_key(|row| row.sequence);
        let now_ms = current_unix_ms_u64()?;
        let mut missing: Vec<BridgeEventRow> = Vec::new();
        {
            let handoffs = write.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
            for row in &candidates {
                let key = format!("{}::{}", access.namespace, row.event_id);
                let existing: Option<BridgeEventHandoffRow> = handoffs
                    .get(key.as_str())
                    .map_err(storage)?
                    .map(|value| decode(value.value()))
                    .transpose()?;
                match existing {
                    None => missing.push(row.clone()),
                    Some(handoff) => {
                        handoff.validate()?;
                        if handoff.owner_namespace != access.namespace
                            || handoff.envelope_sha256 != row.envelope_sha256
                            || handoff.sequence != row.sequence
                        {
                            return Err(OrsError::DuplicateConflict);
                        }
                    }
                }
            }
        }
        let mut repaired = 0_u64;
        if !missing.is_empty() {
            let mut handoffs = write.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
            for row in missing.iter().take(budget) {
                // Exact per-row pressure enforcement: the slice either fits
                // its bounded charge or the call answers backpressure with
                // nothing committed.
                if handoffs.len().map_err(storage)? >= MAX_BRIDGE_EVENT_HANDOFFS as u64 {
                    return Err(OrsError::ProjectionLimitExceeded);
                }
                let key = format!("{}::{}", access.namespace, row.event_id);
                if handoffs.get(key.as_str()).map_err(storage)?.is_some() {
                    continue;
                }
                let handoff = BridgeEventHandoffRow {
                    contract_version: crate::CONTRACT_VERSION,
                    stream_id: row.stream_id.clone(),
                    event_id: row.event_id.clone(),
                    sequence: row.sequence,
                    envelope_sha256: row.envelope_sha256.clone(),
                    state: BRIDGE_EVENT_HANDOFF_HANDED_OFF.to_owned(),
                    staging_connection: row.staging_connection.clone(),
                    handed_off_at_ms: now_ms,
                    reconcile_key: String::new(),
                    reconciled_at_ms: 0,
                    owner_namespace: access.namespace.clone(),
                    reconcile_acked_sequence: 0,
                    reconcile_owner_revision: 0,
                    reconcile_owner_incarnation: 0,
                };
                handoff.validate()?;
                handoffs
                    .insert(key.as_str(), encode(&handoff)?.as_str())
                    .map_err(storage)?;
                repaired += 1;
            }
        }
        Ok(json!({
            "namespace": access.namespace,
            "repaired": repaired,
            "repair_continuation": missing.len() as u64 > repaired,
        }))
    }

    /// Collects one namespace's retirement-eligible handoffs with their keys
    /// (issue #2731, item 5): the per-row
    /// [`BridgeEventHandoffRow::retirement_eligible`] decision against the
    /// current acked cursor and compacted boundary, sorted by sequence then
    /// key so terminalization advances the boundary in order. Called by
    /// [`Self::retire_bridge_handoffs_in`]; kept separate so the recovery
    /// transaction stays within its line budget.
    fn bridge_retire_eligible_in(
        write: &redb::WriteTransaction,
        access: &BridgeStreamAccess,
        acked: u64,
        compacted: u64,
    ) -> Result<Vec<(u64, String, BridgeEventHandoffRow)>, OrsError> {
        let prefix = format!("{}::", access.namespace);
        let mut eligible: Vec<(u64, String, BridgeEventHandoffRow)> = Vec::new();
        let handoffs = write.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
        for entry in handoffs.iter().map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            if !key.value().starts_with(prefix.as_str()) {
                continue;
            }
            let row: BridgeEventHandoffRow = decode(value.value())?;
            row.validate()?;
            if row.owner_namespace != access.namespace {
                continue;
            }
            if row.retirement_eligible(acked, compacted) {
                eligible.push((row.sequence, key.value().to_owned(), row));
            }
        }
        eligible.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        Ok(eligible)
    }

    /// Retires one namespace's eligible handoffs inside the recovery
    /// transaction (issue #2731, items 4 and 5). Eligibility is evaluated
    /// per row by [`BridgeEventHandoffRow::retirement_eligible`] against
    /// the current acked cursor and compacted boundary; a receipt-complete
    /// row covered by the acked cursor is eligible even above the compacted
    /// boundary, so quiet streams that stop producing at or below the
    /// retained acked window still release their charges instead of holding
    /// the table-global budget forever. An eligible row with no live
    /// payload deletes by exact key. An eligible receipt-complete row whose
    /// payload is still retained terminalizes: its #2730 replay commitment
    /// is written first — the identical evidence window-driven compaction
    /// retains, under the same per-stream and total pressure bounds — then
    /// the payload record and the handoff row delete together and the
    /// compacted boundary advances past the terminalized sequences, so
    /// exact replays keep answering duplicate from the commitment, old
    /// occurrences below the boundary keep answering retired, and the
    /// repair step (which restores handoffs only for retained records)
    /// never resurrects them. Rows with a live payload but no receiver
    /// receipt are never touched: unknown or pending work is never evicted
    /// to admit new work, and a torn record/handoff identity mismatch fails
    /// closed by skipping the row instead of guessing. Deletes are by exact
    /// key, so the charge releases exactly once. At most `budget` rows
    /// delete or terminalize per call; `retirement_continuation` reports
    /// whether eligible rows remain for the next legitimate recovery entry.
    fn retire_bridge_handoffs_in(
        write: &redb::WriteTransaction,
        namespace: &str,
        expected_revision: u64,
        expected_incarnation: u64,
        budget: usize,
    ) -> Result<serde_json::Value, OrsError> {
        let owner = Self::load_bridge_owner_row_in(write, namespace)?;
        if owner.kind != BRIDGE_STREAM_OWNER_KIND_STREAM {
            return Err(OrsError::RecoveryOwnerMismatch);
        }
        let access = Self::check_bridge_stream_access(
            &owner,
            expected_revision,
            expected_incarnation,
            BridgeStreamRight::Acknowledge,
        )?;
        let cursor = Self::load_bridge_cursor_row_in(write, namespace)?;
        let (durable, acked, compacted) = cursor.as_ref().map_or((0, 0, 0), |row| {
            (
                row.last_durable_sequence,
                row.last_acked_sequence,
                row.last_compacted_sequence,
            )
        });
        let eligible = Self::bridge_retire_eligible_in(write, &access, acked, compacted)?;
        if eligible.is_empty() {
            return Ok(json!({
                "namespace": access.namespace,
                "retired": 0_u64,
                "terminalized": 0_u64,
                "retirement_continuation": false,
            }));
        }
        let now_ms = current_unix_ms_u64()?;
        let mut retired = 0_u64;
        let mut terminalized = 0_u64;
        let mut terminalized_boundary = compacted;
        let mut spent = 0_usize;
        for (_, key, row) in &eligible {
            if spent >= budget {
                break;
            }
            let record_key = format!("{}::{}", access.namespace, row.event_id);
            let record: Option<BridgeEventRow> = {
                let records = write.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
                records
                    .get(record_key.as_str())
                    .map_err(storage)?
                    .map(|value| decode(value.value()))
                    .transpose()?
            };
            let Some(record) = record else {
                let mut handoffs = write.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
                handoffs.remove(key.as_str()).map_err(storage)?;
                retired += 1;
                spent += 1;
                continue;
            };
            record.validate()?;
            // The handoff must bind the exact retained record; a torn
            // identity is skipped, never repaired by guessing here.
            if record.owner_namespace != access.namespace
                || record.event_id != row.event_id
                || record.sequence != row.sequence
                || record.envelope_sha256 != row.envelope_sha256
                || record.phase != BRIDGE_EVENT_PHASE_DURABLE
            {
                continue;
            }
            if !(row.has_receiver_receipt() && row.sequence <= acked) {
                continue;
            }
            let commitment = Self::bridge_replay_commitment_for(&record, now_ms, acked);
            Self::write_bridge_commitment_in(write, &commitment)?;
            {
                let mut records = write.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
                records.remove(record_key.as_str()).map_err(storage)?;
            }
            {
                let mut handoffs = write.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
                handoffs.remove(key.as_str()).map_err(storage)?;
            }
            terminalized += 1;
            spent += 1;
            terminalized_boundary = terminalized_boundary.max(row.sequence);
        }
        if terminalized_boundary > compacted {
            Self::write_bridge_cursors_compacted_in(
                write,
                &access,
                owner.local_stream.as_str(),
                durable,
                acked,
                terminalized_boundary,
            )?;
        }
        Ok(json!({
            "namespace": access.namespace,
            "retired": retired,
            "terminalized": terminalized,
            "retirement_continuation": eligible.len() as u64 > spent as u64,
        }))
    }

    /// Reconciles event ownership and cursors for one proven presenter
    /// (issue #2729, items 2, 4-6).
    ///
    /// Scope rule, enforced here and nowhere else: no stream listing
    /// exists. The enumeration covers exactly the stream namespaces whose
    /// retained owner binding matches the presenter's lineage and
    /// principal — never the last-staging connection, never bare
    /// generation ordering. Each covered stream reports its cursors, its
    /// pending first page, and its scoped gaps; unscoped gaps report under
    /// the presenter's reporter-occurrence namespaces only. Legacy
    /// ownerless rows stay preserved but unlisted; when any record, cursor,
    /// gap, or handoff row exists outside the proven scope (legacy or
    /// foreign), `unproven_scope_present` is true, so the answer is never
    /// an empty successful inventory. The generation argument is validated
    /// nonzero for wire discipline but never filters: generation ordering
    /// is not an ownership grant, and recovery of an old stream needs no
    /// new-generation permission.
    #[allow(
        clippy::too_many_lines,
        reason = "short cut issuance and one immutable page snapshot must keep their movement contract together"
    )]
    pub fn reconcile_bridge_events_for_owner(
        &self,
        presenter: &serde_json::Value,
        live_generation: u64,
        recovery_scope: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value, OrsError> {
        let (lineage, principal) = Self::bridge_owner_presenter_from(presenter)?;
        if live_generation == 0 {
            return Err(OrsError::InvalidField {
                field: "live_generation",
                reason: "live producer generation must be nonzero",
            });
        }
        let selector = Self::parse_bridge_recovery_scope(recovery_scope)?;
        let selected_scope = match &selector {
            BridgeRecoveryScopeSelector::Open => serde_json::Value::Null,
            BridgeRecoveryScopeSelector::Streams { selected_scope, .. }
            | BridgeRecoveryScopeSelector::Stream { selected_scope, .. }
            | BridgeRecoveryScopeSelector::UnscopedGaps { selected_scope, .. } => {
                selected_scope.clone()
            }
        };
        let now_ms = current_unix_ms_u64()?;
        let write = self.database.begin_write().map_err(storage)?;
        let (mut window, opening) = match &selector {
            BridgeRecoveryScopeSelector::Open => (
                Self::create_bridge_recovery_window_in(&write, &lineage, &principal)?,
                true,
            ),
            BridgeRecoveryScopeSelector::Streams { window_key, .. }
            | BridgeRecoveryScopeSelector::Stream { window_key, .. }
            | BridgeRecoveryScopeSelector::UnscopedGaps { window_key, .. } => (
                Self::load_bridge_recovery_window_in(&write, window_key, &lineage, &principal)?
                    .ok_or(OrsError::RecoveryOwnerMismatch)?,
                false,
            ),
        };
        if window.expires_at_ms <= now_ms {
            drop(write);
            return Ok(Self::bridge_recovery_empty_reply(
                &window,
                "expired",
                &selected_scope,
            ));
        }

        let mut stream_owners: Vec<(BridgeStreamOwnerRow, u64)> = Vec::new();
        let mut requested_stream: Option<(u64, u64, u64, usize, usize, usize)> = None;
        let mut requested_gap: Option<(usize, usize)> = None;
        match &selector {
            BridgeRecoveryScopeSelector::Open => {
                let page = Self::bridge_recovery_owner_page_in(
                    &write,
                    &window,
                    BRIDGE_STREAM_OWNER_KIND_STREAM,
                    0,
                    MAX_BRIDGE_RECOVERY_STREAMS_PER_PAGE,
                )?;
                stream_owners = page.owners;
                window.stream_list_continuation = page.continuation;
                window.stream_list_complete = window.stream_list_continuation.is_none();
            }
            BridgeRecoveryScopeSelector::Streams {
                after_stream,
                stream_limit,
                ..
            } => {
                let page = Self::bridge_recovery_owner_page_in(
                    &write,
                    &window,
                    BRIDGE_STREAM_OWNER_KIND_STREAM,
                    *after_stream,
                    *stream_limit,
                )?;
                stream_owners = page.owners;
                window.stream_list_continuation = page.continuation;
                window.stream_list_complete = window.stream_list_continuation.is_none();
            }
            BridgeRecoveryScopeSelector::Stream {
                stream_id,
                after_sequence,
                upper_sequence,
                expected_revision,
                retention_floor,
                event_limit,
                gap_offset,
                gap_limit,
                ..
            } => {
                let (owner, position) =
                    Self::bridge_recovery_owner_by_stream_in(&write, &window, stream_id)?;
                let cut = Self::load_bridge_recovery_cut_in(
                    &write,
                    &window.window_key,
                    &owner.namespace,
                )?
                .ok_or(OrsError::RecoveryOwnerMismatch)?;
                if cut.upper_sequence != *upper_sequence
                    || cut.expected_revision != *expected_revision
                    || cut.retention_floor != *retention_floor
                {
                    return Err(OrsError::RecoveryOwnerMismatch);
                }
                requested_stream = Some((
                    *after_sequence,
                    *upper_sequence,
                    *expected_revision,
                    *event_limit,
                    *gap_offset,
                    *gap_limit,
                ));
                stream_owners.push((owner, position));
            }
            BridgeRecoveryScopeSelector::UnscopedGaps {
                after_gap_scope,
                gap_offset,
                gap_limit,
                ..
            } => {
                requested_gap = Some((*gap_offset, *gap_limit));
                let owners = write.open_table(BRIDGE_STREAM_OWNERS).map_err(storage)?;
                let Some(value) = owners.get(after_gap_scope.as_str()).map_err(storage)? else {
                    return Err(OrsError::RecoveryOwnerMismatch);
                };
                let owner: BridgeStreamOwnerRow = decode(value.value())?;
                owner.validate()?;
                if owner.kind != BRIDGE_STREAM_OWNER_KIND_UNSCOPED_GAP
                    || owner.authority_lineage != lineage
                    || owner.principal != principal
                {
                    return Err(OrsError::RecoveryOwnerMismatch);
                }
                let _ = Self::bridge_recovery_owner_sequence_in(
                    &write,
                    &window,
                    BRIDGE_STREAM_OWNER_KIND_UNSCOPED_GAP,
                    &owner.namespace,
                )?;
                let _ = Self::create_bridge_recovery_cut_in(&write, &window.window_key, &owner)?;
            }
        }

        for (owner, _) in &stream_owners {
            let _ = Self::create_bridge_recovery_cut_in(&write, &window.window_key, owner)?;
        }
        let gap_owner_for_page = match &selector {
            BridgeRecoveryScopeSelector::UnscopedGaps {
                after_gap_scope, ..
            } => {
                let owners = write.open_table(BRIDGE_STREAM_OWNERS).map_err(storage)?;
                let value = owners
                    .get(after_gap_scope.as_str())
                    .map_err(storage)?
                    .ok_or(OrsError::RecoveryOwnerMismatch)?;
                let owner: BridgeStreamOwnerRow = decode(value.value())?;
                let position = Self::bridge_recovery_owner_sequence_in(
                    &write,
                    &window,
                    BRIDGE_STREAM_OWNER_KIND_UNSCOPED_GAP,
                    &owner.namespace,
                )?;
                Some((owner, position))
            }
            _ => Self::bridge_recovery_owner_page_in(
                &write,
                &window,
                BRIDGE_STREAM_OWNER_KIND_UNSCOPED_GAP,
                0,
                1,
            )?
            .owners
            .into_iter()
            .next(),
        };
        if let Some((owner, _)) = &gap_owner_for_page {
            let _ = Self::create_bridge_recovery_cut_in(&write, &window.window_key, owner)?;
        }
        if opening || matches!(selector, BridgeRecoveryScopeSelector::Streams { .. }) {
            Self::save_bridge_recovery_window_in(&write, &window)?;
        }
        write.commit().map_err(storage)?;

        // Cut issuance is a short write. All facts returned below, including
        // owner rows, cuts, revisions, cursors, events, and gaps, come from
        // this one immutable read snapshot; revision checks reject movement
        // between the write and this snapshot.
        let read = self.database.begin_read().map_err(storage)?;
        let Some(read_window) =
            Self::load_bridge_recovery_window(&read, &window.window_key, &lineage, &principal)?
        else {
            return Err(OrsError::RecoveryOwnerMismatch);
        };
        if read_window.expires_at_ms <= current_unix_ms_u64()? {
            return Ok(Self::bridge_recovery_empty_reply(
                &read_window,
                "expired",
                &selected_scope,
            ));
        }
        let mut moved = false;
        let mut stream_pages = Vec::with_capacity(stream_owners.len());
        for (listed_owner, position) in &stream_owners {
            let owners = read.open_table(BRIDGE_STREAM_OWNERS).map_err(storage)?;
            let Some(value) = owners
                .get(listed_owner.namespace.as_str())
                .map_err(storage)?
            else {
                return Err(OrsError::RecoveryOwnerMismatch);
            };
            let owner: BridgeStreamOwnerRow = decode(value.value())?;
            owner.validate()?;
            if owner.namespace != listed_owner.namespace
                || owner.local_stream != listed_owner.local_stream
                || owner.producer != listed_owner.producer
                || owner.revision != listed_owner.revision
            {
                return Err(OrsError::RecoveryOwnerMismatch);
            }
            let cut =
                Self::load_bridge_recovery_cut(&read, &read_window.window_key, &owner.namespace)?
                    .ok_or(OrsError::RecoveryOwnerMismatch)?;
            if Self::bridge_recovery_revision_for(&read, &owner.namespace)? != cut.expected_revision
                || cut.owner_revision != owner.revision
                || cut.owner_incarnation != owner.incarnation
            {
                moved = true;
                continue;
            }
            let (
                after_sequence,
                upper_sequence,
                expected_revision,
                event_limit,
                gap_offset,
                gap_limit,
            ) = requested_stream.unwrap_or((
                cut.acked_cursor,
                cut.upper_sequence,
                cut.expected_revision,
                MAX_BRIDGE_EVENT_PAGE,
                0,
                MAX_BRIDGE_EVENT_GAPS_PER_STREAM,
            ));
            if upper_sequence != cut.upper_sequence
                || expected_revision != cut.expected_revision
                || after_sequence > cut.upper_sequence
                || (cut.upper_sequence > 0
                    && after_sequence.saturating_add(1) < cut.retention_floor)
            {
                moved = true;
                continue;
            }
            let (mut page, suffix_proven) = Self::bridge_recovery_stream_page(
                &read,
                &owner,
                &cut,
                *position,
                after_sequence,
                BridgeRecoveryPageBudget {
                    event_limit,
                    event_byte_limit: 36 * 1024,
                    gap_offset,
                    gap_limit,
                    gap_byte_limit: 10 * 1024,
                },
            )?;
            if suffix_proven {
                // #2731 capacity accounting is an observation leg of the
                // same snapshot, separate from recovery completion proof.
                page["capacity"] = Self::bridge_capacity_accounting_for(&read, &owner.namespace)?;
                stream_pages.push(page);
            } else {
                moved = true;
            }
        }

        let mut unscoped_gaps = Vec::new();
        let mut unscoped_gap_cursor: Option<(String, u64)> = None;
        let mut unscoped_gaps_complete = true;
        if let Some((listed_gap_owner, position)) = &gap_owner_for_page {
            let owners = read.open_table(BRIDGE_STREAM_OWNERS).map_err(storage)?;
            let Some(value) = owners
                .get(listed_gap_owner.namespace.as_str())
                .map_err(storage)?
            else {
                return Err(OrsError::RecoveryOwnerMismatch);
            };
            let owner: BridgeStreamOwnerRow = decode(value.value())?;
            owner.validate()?;
            if owner.namespace != listed_gap_owner.namespace
                || owner.kind != BRIDGE_STREAM_OWNER_KIND_UNSCOPED_GAP
                || owner.authority_lineage != lineage
                || owner.principal != principal
            {
                return Err(OrsError::RecoveryOwnerMismatch);
            }
            let cut =
                Self::load_bridge_recovery_cut(&read, &read_window.window_key, &owner.namespace)?
                    .ok_or(OrsError::RecoveryOwnerMismatch)?;
            if Self::bridge_recovery_revision_for(&read, &owner.namespace)? == cut.expected_revision
            {
                let (offset, limit) =
                    requested_gap.unwrap_or((0, MAX_BRIDGE_EVENT_GAPS_PER_STREAM));
                let (mut page, next_offset) = Self::bridge_recovery_gap_page(
                    &read,
                    &owner.namespace,
                    offset,
                    limit,
                    10 * 1024,
                )?;
                for (index, gap) in page.iter_mut().enumerate() {
                    let object = gap
                        .as_object_mut()
                        .ok_or(OrsError::ProjectionLimitExceeded)?;
                    object.insert(
                        "gap_owner_scope".to_owned(),
                        serde_json::Value::String(owner.namespace.clone()),
                    );
                    object.insert(
                        "gap_owner_position".to_owned(),
                        serde_json::Value::from(*position),
                    );
                    object.insert(
                        "gap_offset".to_owned(),
                        serde_json::Value::from(offset.saturating_add(index)),
                    );
                }
                unscoped_gaps = page;
                if let Some(next_offset) = next_offset {
                    unscoped_gap_cursor = Some((owner.namespace.clone(), next_offset));
                } else if let Some((next_owner, _next_position)) =
                    Self::bridge_recovery_next_gap_owner(&read, &read_window, *position)?
                {
                    unscoped_gap_cursor = Some((next_owner.namespace, 0));
                }
                unscoped_gaps_complete = unscoped_gap_cursor.is_none();
            } else {
                moved = true;
            }
        }

        let unproven_scope_present =
            Self::bridge_recovery_unproven_scope_present(&read, &read_window)?;
        if moved {
            let mut response =
                Self::bridge_recovery_empty_reply(&read_window, "moved", &selected_scope);
            response["stream_list_complete"] =
                serde_json::Value::Bool(read_window.stream_list_complete);
            response["stream_list_continuation"] = read_window
                .stream_list_continuation
                .clone()
                .map_or(serde_json::Value::Null, serde_json::Value::String);
            return Ok(response);
        }
        let gap_continuation = unscoped_gap_cursor.map(|(after_gap_scope, gap_offset)| {
            json!({ "after_gap_scope": after_gap_scope, "gap_offset": gap_offset })
        });
        let response = json!({
            "window_key": read_window.window_key,
            "window_status": "active",
            "selected_scope": selected_scope,
            "stream_list_complete": read_window.stream_list_complete,
            "stream_list_continuation": read_window.stream_list_continuation,
            "unscoped_gaps_complete": unscoped_gaps_complete,
            "unscoped_gaps_continuation": gap_continuation,
            "streams": stream_pages,
            "unscoped_gaps": unscoped_gaps,
            "unproven_scope_present": unproven_scope_present,
        });
        if serde_json::to_vec(&response)
            .map_err(|_| OrsError::ProjectionLimitExceeded)?
            .len()
            > MAX_BRIDGE_RECOVERY_REPLY_BYTES
        {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        Ok(response)
    }

    /// Counts one namespace's #2730 ordered position rows with their total
    /// encoded bytes (issue #2731, item 4): key bytes plus serialized-record
    /// bytes, the accountable persisted size. Read-only — positions are
    /// owned, written, and capped by #2730/#2885 and are never mutated
    /// here. Called by [`Self::bridge_capacity_accounting_for`]; kept
    /// separate so the inventory stays within its line budget.
    fn bridge_position_accounting_for(
        read: &redb::ReadTransaction,
        namespace: &str,
    ) -> Result<(u64, u64), OrsError> {
        let stored = read.open_table(BRIDGE_EVENT_POSITIONS).map_err(storage)?;
        let prefix = format!("{namespace}::");
        let mut positions = 0_u64;
        let mut position_bytes = 0_u64;
        for entry in stored.iter().map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            if !key.value().starts_with(prefix.as_str()) {
                continue;
            }
            let (key_namespace, _) = Self::parse_bridge_position_key(key.value())?;
            if key_namespace != namespace {
                continue;
            }
            let position: BridgeEventPosition = decode(value.value())?;
            position.validate()?;
            positions += 1;
            position_bytes += (key.value().len() + value.value().len()) as u64;
        }
        Ok((positions, position_bytes))
    }

    /// Accounts one namespace's bridge-event capacity under its owner
    /// (issue #2731, item 4): pending live events, handoffs, retained replay
    /// commitments, the #2730 ordered position index, stream/cursor
    /// metadata, and scoped gaps with their total encoded bytes. Every byte
    /// count sums key bytes plus serialized-record bytes — the accountable
    /// persisted size, never the source payload length (which is not exact
    /// persisted size or heap use). Engine index structure and in-memory
    /// heap stay outside this measure; the global admission caps absorb
    /// them. The #2730 position index is owned, written, and capped by
    /// #2730/#2885 — this view only reads its per-namespace rows into the
    /// denominator so quiet streams cannot hide lifetime occupancy behind
    /// historical windows, and never writes, deletes, or resets it. Served
    /// inside the owner recovery inventory, where the receiver sizes
    /// backpressure against pending versus retained evidence.
    fn bridge_capacity_accounting_for(
        read: &redb::ReadTransaction,
        namespace: &str,
    ) -> Result<serde_json::Value, OrsError> {
        crate::model::validate_digest(namespace, "owner_namespace")?;
        let mut pending_events = 0_u64;
        let mut pending_event_bytes = 0_u64;
        {
            let records = read.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
            for entry in records.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                let row: BridgeEventRow = decode(value.value())?;
                row.validate()?;
                if row.owner_namespace == namespace {
                    pending_events += 1;
                    pending_event_bytes += (key.value().len() + value.value().len()) as u64;
                }
            }
        }
        let mut handoffs_count = 0_u64;
        let mut handoff_bytes = 0_u64;
        {
            let handoffs = read.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
            for entry in handoffs.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                let row: BridgeEventHandoffRow = decode(value.value())?;
                row.validate()?;
                if row.owner_namespace == namespace {
                    handoffs_count += 1;
                    handoff_bytes += (key.value().len() + value.value().len()) as u64;
                }
            }
        }
        let mut commitments = 0_u64;
        let mut commitment_bytes = 0_u64;
        {
            let retained = read
                .open_table(BRIDGE_EVENT_REPLAY_COMMITMENTS)
                .map_err(storage)?;
            for entry in retained.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                let commitment: BridgeEventReplayCommitment = decode(value.value())?;
                commitment.validate()?;
                if commitment.owner_namespace == namespace {
                    commitments += 1;
                    commitment_bytes += (key.value().len() + value.value().len()) as u64;
                }
            }
        }
        let mut gaps = 0_u64;
        let mut gap_bytes = 0_u64;
        {
            let stored = read.open_table(BRIDGE_EVENT_GAPS).map_err(storage)?;
            for entry in stored.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                let row: BridgeEventGapRow = decode(value.value())?;
                row.validate()?;
                if row.owner_namespace == namespace {
                    gaps += 1;
                    gap_bytes += (key.value().len() + value.value().len()) as u64;
                }
            }
        }
        let cursor_bytes = {
            let cursors = read.open_table(BRIDGE_EVENT_CURSORS).map_err(storage)?;
            cursors
                .get(namespace)
                .map_err(storage)?
                .map_or(0, |value| (namespace.len() + value.value().len()) as u64)
        };
        let (positions, position_bytes) = Self::bridge_position_accounting_for(read, namespace)?;
        let owner_bytes = {
            let owners = read.open_table(BRIDGE_STREAM_OWNERS).map_err(storage)?;
            owners
                .get(namespace)
                .map_err(storage)?
                .map_or(0, |value| (namespace.len() + value.value().len()) as u64)
        };
        let total_bytes = pending_event_bytes
            .saturating_add(handoff_bytes)
            .saturating_add(commitment_bytes)
            .saturating_add(position_bytes)
            .saturating_add(gap_bytes)
            .saturating_add(cursor_bytes)
            .saturating_add(owner_bytes);
        Ok(json!({
            "pending_events": pending_events,
            "pending_event_bytes": pending_event_bytes,
            "handoffs": handoffs_count,
            "handoff_bytes": handoff_bytes,
            "replay_commitments": commitments,
            "replay_commitment_bytes": commitment_bytes,
            "positions": positions,
            "position_bytes": position_bytes,
            "gaps": gaps,
            "gap_bytes": gap_bytes,
            "cursor_bytes": cursor_bytes,
            "owner_bytes": owner_bytes,
            "total_bytes": total_bytes,
        }))
    }

    /// Loads one immutable content-addressed campaign view.
    pub fn load_campaign_learning_state_view(
        &self,
        view_id: &eliot_contracts::ArtifactId,
    ) -> Result<Option<eliot_store_api::CampaignLearningStateViewPublication>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read
            .open_table(CAMPAIGN_LEARNING_STATE_VIEWS)
            .map_err(storage)?;
        let Some(value) = table.get(view_id.as_str()).map_err(storage)? else {
            return Ok(None);
        };
        let publication: eliot_store_api::CampaignLearningStateViewPublication =
            decode(value.value())?;
        publication
            .validate()
            .map_err(|_| OrsError::IntegrityProblem {
                record_type: "campaign_learning_state_view",
                reason: "stored content-addressed view failed validation".to_owned(),
            })?;
        if publication.view_id != *view_id {
            return Err(OrsError::IntegrityProblem {
                record_type: "campaign_learning_state_view",
                reason: "stored view key differs from its content identity".to_owned(),
            });
        }
        Ok(Some(publication))
    }

    /// Atomically reserves one or more source-head CAS operations before the
    /// corresponding canonical owner transition is applied.
    #[allow(
        clippy::too_many_lines,
        reason = "source-head reservation keeps CAS, replay, and pending-state joins in one transaction"
    )]
    pub fn reserve_campaign_source_publications(
        &self,
        operation_id: &eliot_contracts::OperationId,
        request_digest: &str,
        publications: &[eliot_store_api::CampaignSourcePublication],
    ) -> Result<(), OrsError> {
        eliot_store_api::validate_sha256_hex(request_digest, "campaign_source.request_digest")
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        if publications.is_empty() || publications.len() > 64 {
            return Err(OrsError::InvalidField {
                field: "campaign_source.publications",
                reason: "must contain between one and 64 source publications",
            });
        }
        let mut source_keys = BTreeSet::new();
        for publication in publications {
            publication
                .validate()
                .map_err(|error| OrsError::Contract(error.to_string()))?;
            let key = campaign_source_key(&publication.record)?;
            if !source_keys.insert(key.clone()) {
                return Err(campaign_source_identity_conflict(&key));
            }
        }

        let write = self.database.begin_write().map_err(storage)?;
        let operation_text = operation_id.as_str().to_owned();
        {
            let heads = write.open_table(CAMPAIGN_SOURCE_HEADS).map_err(storage)?;
            let mut pending = write.open_table(CAMPAIGN_SOURCE_PENDING).map_err(storage)?;
            for publication in publications {
                let key = campaign_source_key(&publication.record)?;
                let current = heads
                    .get(key.as_str())
                    .map_err(storage)?
                    .map(|value| decode::<eliot_store_api::CampaignSourceHead>(value.value()))
                    .transpose()?;
                let pending_row = pending
                    .get(key.as_str())
                    .map_err(storage)?
                    .map(|value| decode::<CampaignSourceReservation>(value.value()))
                    .transpose()?;

                match &publication.state {
                    eliot_store_api::CampaignSourcePublicationState::CurrentReference {
                        current_head,
                    } => {
                        if pending_row.is_some() || current.as_ref() != Some(current_head) {
                            return Err(campaign_source_identity_conflict(&key));
                        }
                        let row_key =
                            campaign_source_record_key(&key, &publication.record.content_digest);
                        let records = write.open_table(CAMPAIGN_SOURCE_RECORDS).map_err(storage)?;
                        let same_record = records
                            .get(row_key.as_str())
                            .map_err(storage)?
                            .map(|value| {
                                decode::<eliot_store_api::CampaignSourceRecord>(value.value())
                            })
                            .transpose()?
                            .is_some_and(|record| record == publication.record);
                        if !same_record {
                            return Err(campaign_source_identity_conflict(&key));
                        }
                    }
                    eliot_store_api::CampaignSourcePublicationState::NewRevision { .. } => {
                        let expected = publication.state.expected_head();
                        if current.as_ref() == Some(&publication.next_head()) {
                            // Exact replay after the canonical receipt and
                            // source head were both committed.
                            let row_key = campaign_source_record_key(
                                &key,
                                &publication.record.content_digest,
                            );
                            let records =
                                write.open_table(CAMPAIGN_SOURCE_RECORDS).map_err(storage)?;
                            let same_record = records
                                .get(row_key.as_str())
                                .map_err(storage)?
                                .map(|value| {
                                    decode::<eliot_store_api::CampaignSourceRecord>(value.value())
                                })
                                .transpose()?
                                .is_some_and(|record| record == publication.record);
                            if !same_record {
                                return Err(campaign_source_identity_conflict(&key));
                            }
                            if let Some(existing) = pending_row {
                                if existing.operation_id != operation_text
                                    || existing.request_digest != request_digest
                                    || existing.publication != *publication
                                {
                                    return Err(campaign_source_identity_conflict(&key));
                                }
                                pending.remove(key.as_str()).map_err(storage)?;
                            }
                            continue;
                        }

                        if let Some(existing) = pending_row {
                            if existing.operation_id == operation_text
                                && existing.request_digest == request_digest
                                && existing.publication == *publication
                            {
                                continue;
                            }
                            return Err(campaign_source_identity_conflict(&key));
                        }
                        if current.as_ref() != expected {
                            return Err(campaign_source_identity_conflict(&key));
                        }
                        let reservation = CampaignSourceReservation {
                            operation_id: operation_text.clone(),
                            request_digest: request_digest.to_owned(),
                            publication: publication.clone(),
                        };
                        let payload = encode(&reservation)?;
                        pending
                            .insert(key.as_str(), payload.as_str())
                            .map_err(storage)?;
                    }
                }
            }
        }
        write.commit().map_err(storage)
    }

    /// Commits all reserved immutable source rows and current heads in one
    /// ORS transaction after exact canonical receipt validation.
    #[allow(
        clippy::too_many_lines,
        reason = "source-head commit keeps receipt, reservation, row, and head joins atomic"
    )]
    pub fn commit_campaign_source_publications(
        &self,
        operation_id: &eliot_contracts::OperationId,
        request_digest: &str,
        publications: &[eliot_store_api::CampaignSourcePublication],
        receipt: &eliot_store_api::WriteReceipt,
    ) -> Result<(), OrsError> {
        receipt
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        if receipt.status != eliot_store_api::WriteReceiptStatus::Committed
            || receipt.operation_id != *operation_id
            || receipt.canonical_request_hash != request_digest
            || publications.is_empty()
            || publications.len() > 64
        {
            return Err(OrsError::ReconciliationMismatch);
        }
        for publication in publications {
            publication
                .validate()
                .map_err(|error| OrsError::Contract(error.to_string()))?;
            match &publication.state {
                eliot_store_api::CampaignSourcePublicationState::NewRevision { .. } => {
                    if publication.record.recorded_state_fence != receipt.state_fence {
                        return Err(OrsError::FenceMismatch);
                    }
                }
                eliot_store_api::CampaignSourcePublicationState::CurrentReference { .. } => {
                    if publication.read_receipt.read_state_fence != receipt.state_fence {
                        return Err(OrsError::FenceMismatch);
                    }
                }
            }
        }

        let write = self.database.begin_write().map_err(storage)?;
        let operation_text = operation_id.as_str();
        {
            let mut records = write.open_table(CAMPAIGN_SOURCE_RECORDS).map_err(storage)?;
            let mut heads = write.open_table(CAMPAIGN_SOURCE_HEADS).map_err(storage)?;
            let mut pending = write.open_table(CAMPAIGN_SOURCE_PENDING).map_err(storage)?;
            let mut seen = BTreeSet::new();
            for publication in publications {
                let key = campaign_source_key(&publication.record)?;
                if !seen.insert(key.clone()) {
                    return Err(campaign_source_identity_conflict(&key));
                }
                let row_key = campaign_source_record_key(&key, &publication.record.content_digest);
                let current_head = heads
                    .get(key.as_str())
                    .map_err(storage)?
                    .map(|value| decode::<eliot_store_api::CampaignSourceHead>(value.value()))
                    .transpose()?;
                let stored_record = records
                    .get(row_key.as_str())
                    .map_err(storage)?
                    .map(|value| decode::<eliot_store_api::CampaignSourceRecord>(value.value()))
                    .transpose()?;
                let reservation = pending
                    .get(key.as_str())
                    .map_err(storage)?
                    .map(|value| decode::<CampaignSourceReservation>(value.value()))
                    .transpose()?;

                match &publication.state {
                    eliot_store_api::CampaignSourcePublicationState::CurrentReference {
                        current_head: reference_head,
                    } => {
                        if reservation.is_some()
                            || current_head.as_ref() != Some(reference_head)
                            || stored_record.as_ref() != Some(&publication.record)
                        {
                            return Err(campaign_source_identity_conflict(&key));
                        }
                        // A current reference is an observation only. The
                        // exact head and immutable row are already durable;
                        // neither table is advanced or rewritten here.
                    }
                    eliot_store_api::CampaignSourcePublicationState::NewRevision { .. } => {
                        if current_head.as_ref() == Some(&publication.next_head())
                            && stored_record.as_ref() == Some(&publication.record)
                        {
                            // An exact replay after a complete source commit is
                            // idempotent even though the reservation has been
                            // cleared.
                            if let Some(existing) = reservation {
                                if existing.operation_id != operation_text
                                    || existing.request_digest != request_digest
                                    || existing.publication != *publication
                                {
                                    return Err(campaign_source_identity_conflict(&key));
                                }
                                pending.remove(key.as_str()).map_err(storage)?;
                            }
                            continue;
                        }
                        let Some(reservation) = reservation else {
                            return Err(campaign_source_identity_conflict(&key));
                        };
                        if reservation.operation_id != operation_text
                            || reservation.request_digest != request_digest
                            || reservation.publication != *publication
                            || current_head.as_ref() != publication.state.expected_head()
                        {
                            return Err(campaign_source_identity_conflict(&key));
                        }
                        if let Some(existing) = stored_record {
                            if existing != publication.record {
                                return Err(campaign_source_identity_conflict(&key));
                            }
                        } else {
                            let payload = encode(&publication.record)?;
                            records
                                .insert(row_key.as_str(), payload.as_str())
                                .map_err(storage)?;
                        }
                        let head = publication.next_head();
                        let payload = encode(&head)?;
                        heads
                            .insert(key.as_str(), payload.as_str())
                            .map_err(storage)?;
                        pending.remove(key.as_str()).map_err(storage)?;
                    }
                }
            }
        }
        write.commit().map_err(storage)
    }

    /// Releases reserved source heads after a typed negative canonical
    /// receipt proves this owner transition did not commit.
    pub fn abort_campaign_source_publications(
        &self,
        operation_id: &eliot_contracts::OperationId,
        request_digest: &str,
        publications: &[eliot_store_api::CampaignSourcePublication],
    ) -> Result<(), OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        {
            let mut pending = write.open_table(CAMPAIGN_SOURCE_PENDING).map_err(storage)?;
            for publication in publications {
                let key = campaign_source_key(&publication.record)?;
                let existing = pending
                    .get(key.as_str())
                    .map_err(storage)?
                    .map(|value| decode::<CampaignSourceReservation>(value.value()))
                    .transpose()?;
                if let Some(existing) = existing
                    && existing.operation_id == operation_id.as_str()
                    && existing.request_digest == request_digest
                    && existing.publication == *publication
                {
                    pending.remove(key.as_str()).map_err(storage)?;
                }
            }
        }
        write.commit().map_err(storage)
    }

    /// Loads a requested immutable source row and its current head under one
    /// durable read snapshot. Old exact references return `STALE` together
    /// with the newer head; request selectors never create owner evidence.
    #[allow(
        clippy::too_many_lines,
        reason = "source readback keeps row, head, digest, and read-receipt joins under one snapshot"
    )]
    pub fn load_campaign_source_revision(
        &self,
        lookup: &eliot_store_api::CampaignSourceRevisionLookup,
        read_state_fence: &eliot_contracts::StateFence,
    ) -> Result<eliot_store_api::CampaignSourceRevisionRead, OrsError> {
        lookup
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        read_state_fence
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        let read = self.database.begin_read().map_err(storage)?;
        let key = campaign_source_key_parts(lookup.role, &lookup.owner_id, &lookup.record_id)?;
        let heads = read.open_table(CAMPAIGN_SOURCE_HEADS).map_err(storage)?;
        let Some(head_value) = heads.get(key.as_str()).map_err(storage)? else {
            return Ok(eliot_store_api::CampaignSourceRevisionRead {
                status: eliot_store_api::CampaignSourceReadStatus::Missing,
                source: None,
                current_head: None,
                read_receipt: None,
                read_state_fence: read_state_fence.clone(),
            });
        };
        let head: eliot_store_api::CampaignSourceHead = decode(head_value.value())?;
        head.validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        if head.role != lookup.role
            || head.owner_id != lookup.owner_id
            || head.record_id != lookup.record_id
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "campaign_source_head",
                reason: "stored source head key differs from its typed identity".to_owned(),
            });
        }
        let requested_digest = lookup
            .expected_content_digest
            .as_deref()
            .unwrap_or(head.content_digest.as_str());
        let row_key = campaign_source_record_key(&key, requested_digest);
        let records = read.open_table(CAMPAIGN_SOURCE_RECORDS).map_err(storage)?;
        let source = records
            .get(row_key.as_str())
            .map_err(storage)?
            .map(|value| decode::<eliot_store_api::CampaignSourceRecord>(value.value()))
            .transpose()?;
        let source = source.filter(|record| {
            record.role == lookup.role
                && record.owner_id == lookup.owner_id
                && record.record_id == lookup.record_id
                && record.content_digest == requested_digest
                && lookup
                    .expected_revision
                    .as_ref()
                    .is_none_or(|revision| record.revision == *revision)
        });
        if let Some(source) = &source {
            source
                .validate()
                .map_err(|error| OrsError::Contract(error.to_string()))?;
        }
        let head_row_key = campaign_source_record_key(&key, &head.content_digest);
        let head_record = records
            .get(head_row_key.as_str())
            .map_err(storage)?
            .map(|value| decode::<eliot_store_api::CampaignSourceRecord>(value.value()))
            .transpose()?
            .ok_or(OrsError::IntegrityProblem {
                record_type: "campaign_source_record",
                reason: "current head has no matching immutable source row".to_owned(),
            })?;
        head_record
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        if !campaign_record_matches_head(&head_record, &head) {
            return Err(OrsError::IntegrityProblem {
                record_type: "campaign_source_record",
                reason: "current source head does not match its immutable owner row".to_owned(),
            });
        }
        let read_receipt = source
            .as_ref()
            .map(|record| {
                eliot_store_api::CampaignOwnerReadReceipt::from_record(record, read_state_fence)
            })
            .transpose()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        let matches_head = source.as_ref().is_some_and(|record| {
            record.revision == head.revision && record.content_digest == head.content_digest
        });
        let requested_is_head = lookup.expected_revision.is_none()
            || (lookup.expected_revision.as_ref() == Some(&head.revision)
                && lookup.expected_content_digest.as_deref() == Some(head.content_digest.as_str()));
        let result = if matches_head && requested_is_head {
            eliot_store_api::CampaignSourceRevisionRead {
                status: eliot_store_api::CampaignSourceReadStatus::Current,
                source,
                current_head: Some(head),
                read_receipt,
                read_state_fence: read_state_fence.clone(),
            }
        } else {
            eliot_store_api::CampaignSourceRevisionRead {
                status: eliot_store_api::CampaignSourceReadStatus::Stale,
                source,
                current_head: Some(head),
                read_receipt,
                read_state_fence: read_state_fence.clone(),
            }
        };
        result
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        Ok(result)
    }

    /// Stages one native-worker claim intent before any acknowledgement.
    ///
    /// Persist-before-ack: the record is durably inserted before the caller
    /// may issue the immutable admission receipt or initialize provider
    /// work. An exact replay under the same claim identity returns
    /// [`NativeWorkerClaimStageOutcome::Existing`] carrying the same receipt
    /// identity; a changed binding under the same identity fails with
    /// [`OrsError::NativeWorkerClaimIdentityConflict`] and never overwrites
    /// the durable row. Staging accepts the `Requested` intent entry state
    /// and the `Admitted` Wave-B admission state; both are validated for
    /// receipt coherence by the record itself. This table is disjoint from
    /// the `HostRequest` and `ProcessStart` tables: one writer per state.
    pub fn stage_native_worker_claim(
        &self,
        record: &crate::NativeWorkerClaimRecord,
    ) -> Result<crate::NativeWorkerClaimStageOutcome, OrsError> {
        record.validate()?;
        if !matches!(
            record.state,
            crate::NativeWorkerClaimState::Requested | crate::NativeWorkerClaimState::Admitted
        ) {
            return Err(OrsError::InvalidField {
                field: "native_worker_claim_state",
                reason: "staging requires the requested or admitted state",
            });
        }
        let write = self.database.begin_write().map_err(storage)?;
        let existing = {
            let mut table = write.open_table(NATIVE_WORKER_CLAIMS).map_err(storage)?;
            let key = record.record_key();
            if let Some(existing) = table.get(key.as_str()).map_err(storage)? {
                let existing: crate::NativeWorkerClaimRecord = decode(existing.value())?;
                existing.validate()?;
                if !existing.same_binding(record) {
                    return Err(OrsError::NativeWorkerClaimIdentityConflict {
                        claim_id: record.claim_id.as_str().to_owned(),
                    });
                }
                Some(existing)
            } else {
                let payload = encode(record)?;
                table
                    .insert(key.as_str(), payload.as_str())
                    .map_err(storage)?;
                None
            }
        };
        write.commit().map_err(storage)?;
        Ok(match existing {
            Some(durable) => crate::NativeWorkerClaimStageOutcome::Existing(durable),
            None => crate::NativeWorkerClaimStageOutcome::Stored(record.clone()),
        })
    }

    /// Loads one native-worker claim by exact claim identity.
    pub fn load_native_worker_claim(
        &self,
        claim_id: &crate::OperationIdentity,
    ) -> Result<Option<crate::NativeWorkerClaimRecord>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(NATIVE_WORKER_CLAIMS).map_err(storage)?;
        table
            .get(claim_id.as_str())
            .map_err(storage)?
            .map(|value| {
                let record: crate::NativeWorkerClaimRecord = decode(value.value())?;
                record.validate()?;
                if record.claim_id != *claim_id {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "native_worker_claim",
                        reason: "claim record identity does not match its key".to_owned(),
                    });
                }
                Ok(record)
            })
            .transpose()
    }

    /// Reverse-resolves one claim identity from its bound attempt and
    /// operation labels (T9-04 supplier core, issue #1108).
    ///
    /// Read-only: this performs no writes, creates no table, and grants no
    /// authority. It scans the existing claim rows with early exit on the
    /// first exact attempt-plus-operation match, mirroring the
    /// `replay_events_in` full-table scan precedent. The scan carries no row
    /// cap on purpose: a cap would turn a present row past the bound into a
    /// false unknown. A corrupt or unreadable row ends the scan without a
    /// match, so callers must confirm any hit with
    /// [`Self::load_native_worker_claim`] under the exact claim identity and
    /// treat `None` as "no durable binding observed", never as proof of
    /// absence. There is deliberately no reverse index and no second writer:
    /// the claim table stays the single owner of claim state.
    pub fn find_native_worker_claim_id_by_attempt_operation(
        &self,
        attempt_id: &str,
        operation_id: &str,
    ) -> Option<String> {
        if crate::model::validate_text(attempt_id, "native_worker_claim_attempt_id").is_err()
            || crate::model::validate_text(operation_id, "native_worker_claim_operation_id")
                .is_err()
        {
            return None;
        }
        let read = self.database.begin_read().ok()?;
        let table = read.open_table(NATIVE_WORKER_CLAIMS).ok()?;
        for row in table.iter().ok()? {
            let (_, value) = row.ok()?;
            let record: crate::NativeWorkerClaimRecord = decode(value.value()).ok()?;
            if record.attempt_id.as_str() == attempt_id
                && record.operation_id.as_str() == operation_id
            {
                return Some(record.claim_id.as_str().to_owned());
            }
        }
        None
    }

    /// Advances one staged claim to its next mechanical state.
    ///
    /// The transition table owns the anti-downgrade fence: `Terminal` is
    /// absorbing, `Unknown` may only become `Reconciling`, no state returns
    /// to `Requested`, and `Ready` is reachable only from `Admitted` (or
    /// from `Reconciling` as the resolution of previously admitted work).
    /// An exact repeat of an applied advance returns the durable record
    /// unchanged. An unknown claim returns `Ok(None)`; this method never
    /// invents a record and never retries blindly. Admission evidence binds
    /// the receipt identity on `Requested -> Admitted`, is accepted
    /// unchanged on an exact `Admitted -> Admitted` replay, and can never
    /// overwrite a bound receipt. The ORS write transaction assigns the
    /// monotonic commit order atomically when the claim first reaches its
    /// terminal state; the caller never supplies it.
    pub fn advance_native_worker_claim(
        &self,
        claim_id: &crate::OperationIdentity,
        target: crate::NativeWorkerClaimState,
        admission: Option<&crate::NativeWorkerClaimAdmission>,
    ) -> Result<Option<crate::NativeWorkerClaimRecord>, OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        let key = claim_id.as_str().to_owned();
        let existing: Option<crate::NativeWorkerClaimRecord> = {
            let table = write.open_table(NATIVE_WORKER_CLAIMS).map_err(storage)?;
            table
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
        };
        let Some(existing) = existing else {
            return Ok(None);
        };
        existing.validate()?;
        if existing.claim_id != *claim_id {
            return Err(OrsError::IntegrityProblem {
                record_type: "native_worker_claim",
                reason: "claim record identity does not match its key".to_owned(),
            });
        }
        if existing.state == target {
            if let Some(admission) = admission {
                admission.validate()?;
                if existing.receipt_digest.as_deref() != Some(admission.receipt_digest.as_str())
                    || existing.admitted_at_unix_ms != Some(admission.admitted_at_unix_ms)
                {
                    return Err(OrsError::NativeWorkerClaimIdentityConflict {
                        claim_id: claim_id.as_str().to_owned(),
                    });
                }
            }
            return Ok(Some(existing));
        }
        existing.state.transition_to(target)?;
        let mut next = existing.clone();
        next.state = target;
        if target == crate::NativeWorkerClaimState::Admitted {
            match (
                &existing.receipt_digest,
                existing.admitted_at_unix_ms,
                admission,
            ) {
                (None, None, Some(admission)) => {
                    admission.validate()?;
                    next.receipt_digest = Some(admission.receipt_digest.clone());
                    next.admitted_at_unix_ms = Some(admission.admitted_at_unix_ms);
                }
                (Some(_), Some(_), None) => {}
                (Some(digest), Some(at), Some(admission))
                    if digest == &admission.receipt_digest
                        && at == admission.admitted_at_unix_ms => {}
                (None, None, None) => {
                    return Err(OrsError::InvalidField {
                        field: "native_worker_claim_admission",
                        reason: "admission requires admission evidence",
                    });
                }
                _ => {
                    return Err(OrsError::NativeWorkerClaimIdentityConflict {
                        claim_id: claim_id.as_str().to_owned(),
                    });
                }
            }
        } else if admission.is_some() {
            return Err(OrsError::InvalidField {
                field: "native_worker_claim_admission",
                reason: "admission evidence only for the admitted state",
            });
        }
        if target.is_terminal() && next.commit_order == 0 {
            next.commit_order = Self::next_operational_order(&write)?;
        }
        next.validate()?;
        if next != existing {
            let payload = encode(&next)?;
            let mut table = write.open_table(NATIVE_WORKER_CLAIMS).map_err(storage)?;
            table
                .insert(key.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(Some(next))
    }

    /// Stages one Doctor attempt intent before any admission.
    ///
    /// Persist-before-ack: the `Requested` record is durably inserted before
    /// the Kernel admission gate may bind an admission receipt. An exact
    /// replay under the same attempt digest returns the durable row
    /// unchanged; a changed binding under the same digest fails with
    /// [`crate::DoctorLedgerError::AttemptIdentityConflict`] and never
    /// overwrites the durable row. This table is disjoint from every other
    /// ORS table: one writer per state.
    pub fn stage_doctor_attempt(
        &self,
        record: &crate::DoctorAttemptRecord,
    ) -> Result<crate::DoctorAttemptStageOutcome, crate::DoctorLedgerError> {
        record.validate().map_err(map_ors_to_doctor)?;
        if record.state != crate::DoctorAttemptState::Requested {
            return Err(doctor_storage("staging requires the requested state"));
        }
        let write = self.database.begin_write().map_err(doctor_storage)?;
        let existing = {
            let mut table = write.open_table(DOCTOR_ATTEMPTS).map_err(doctor_storage)?;
            let key = record.record_key();
            if let Some(existing) = table.get(key.as_str()).map_err(doctor_storage)? {
                let existing: crate::DoctorAttemptRecord =
                    decode(existing.value()).map_err(map_ors_to_doctor)?;
                if !existing.same_binding(record) {
                    return Err(crate::DoctorLedgerError::AttemptIdentityConflict {
                        attempt_digest: key,
                    });
                }
                Some(existing)
            } else {
                let payload = encode(record).map_err(map_ors_to_doctor)?;
                table
                    .insert(key.as_str(), payload.as_str())
                    .map_err(doctor_storage)?;
                None
            }
        };
        write.commit().map_err(doctor_storage)?;
        Ok(match existing {
            Some(durable) => crate::DoctorAttemptStageOutcome::Existing(durable),
            None => crate::DoctorAttemptStageOutcome::Stored(record.clone()),
        })
    }

    /// Loads one Doctor attempt by exact attempt digest.
    pub fn load_doctor_attempt(
        &self,
        attempt_digest: &crate::OperationIdentity,
    ) -> Result<Option<crate::DoctorAttemptRecord>, crate::DoctorLedgerError> {
        let read = self.database.begin_read().map_err(doctor_storage)?;
        let table = read.open_table(DOCTOR_ATTEMPTS).map_err(doctor_storage)?;
        table
            .get(attempt_digest.as_str())
            .map_err(doctor_storage)?
            .map(|value| {
                let record: crate::DoctorAttemptRecord =
                    decode(value.value()).map_err(map_ors_to_doctor)?;
                if record.attempt_digest != *attempt_digest {
                    return Err(doctor_storage(
                        "doctor attempt identity does not match its key",
                    ));
                }
                Ok(record)
            })
            .transpose()
    }

    /// Advances one staged Doctor attempt to its next mechanical state.
    ///
    /// The transition table owns the anti-blind-retry fence: `Unknown` may
    /// only become `Reconciling`, neither `Unknown` nor `Reconciling` returns
    /// to `Requested`, and `Terminal` is absorbing. An exact repeat of an
    /// applied advance returns the durable record unchanged: a same-state
    /// repeat carrying the bound admission evidence is accepted, and a
    /// same-state repeat carrying no evidence re-observes the durable row
    /// without touching the bound admission. Conflicting evidence fails
    /// without overwriting. An unknown
    /// attempt returns `Ok(None)`; this method never invents a record.
    /// Admission evidence binds the admission digest on
    /// `Requested -> Admitted` and `Requested -> Cancelled`, is accepted
    /// unchanged on an exact replay of an applied advance, and can never
    /// overwrite a bound admission. The ORS write transaction assigns the
    /// monotonic commit order atomically when the attempt first reaches a
    /// terminal state; the caller never supplies it.
    pub fn advance_doctor_attempt(
        &self,
        attempt_digest: &crate::OperationIdentity,
        target: crate::DoctorAttemptState,
        admission: Option<&crate::DoctorAttemptAdmission>,
    ) -> Result<Option<crate::DoctorAttemptRecord>, crate::DoctorLedgerError> {
        let write = self.database.begin_write().map_err(doctor_storage)?;
        let key = attempt_digest.as_str().to_owned();
        let existing: Option<crate::DoctorAttemptRecord> = {
            let table = write.open_table(DOCTOR_ATTEMPTS).map_err(doctor_storage)?;
            table
                .get(key.as_str())
                .map_err(doctor_storage)?
                .map(|value| decode(value.value()))
                .transpose()
                .map_err(map_ors_to_doctor)?
        };
        let Some(existing) = existing else {
            return Ok(None);
        };
        if existing.attempt_digest != *attempt_digest {
            return Err(doctor_storage(
                "doctor attempt identity does not match its key",
            ));
        }
        if existing.state == target {
            let replayed = match (
                &existing.admission_digest,
                existing.admitted_at_unix_nanos,
                admission,
            ) {
                (Some(digest), Some(at), Some(evidence)) => {
                    evidence.validate().map_err(map_ors_to_doctor)?;
                    evidence.admission_digest == *digest && evidence.admitted_at_unix_nanos == at
                }
                // A same-state re-observation that presents no evidence
                // changes nothing: the bound admission is returned
                // unchanged, so an at-least-once retry of an applied
                // non-admission advance stays idempotent. Conflicting
                // evidence below still fails without overwriting.
                (Some(..), Some(..), None) | (None, None, None) => true,
                _ => false,
            };
            if !replayed {
                return Err(crate::DoctorLedgerError::AttemptIdentityConflict {
                    attempt_digest: key,
                });
            }
            return Ok(Some(existing));
        }
        let from = existing.state;
        from.transition_to(target).map_err(map_ors_to_doctor)?;
        let mut next = existing.clone();
        match (from, target) {
            (
                crate::DoctorAttemptState::Requested,
                crate::DoctorAttemptState::Admitted | crate::DoctorAttemptState::Cancelled,
            ) => {
                let evidence =
                    admission.ok_or_else(|| doctor_storage("admission evidence is required"))?;
                evidence.validate().map_err(map_ors_to_doctor)?;
                next.admission_digest = Some(evidence.admission_digest.clone());
                next.admitted_at_unix_nanos = Some(evidence.admitted_at_unix_nanos);
            }
            (crate::DoctorAttemptState::Requested, crate::DoctorAttemptState::Expired) => {
                if admission.is_some() {
                    return Err(doctor_storage("an expired intent carries no admission"));
                }
            }
            _ => {
                if admission.is_some() {
                    return Err(doctor_storage(
                        "admission evidence binds only on first admission",
                    ));
                }
            }
        }
        next.state = target;
        if target.is_terminal() && next.commit_order == 0 {
            next.commit_order = Self::next_operational_order(&write).map_err(map_ors_to_doctor)?;
        }
        next.validate().map_err(map_ors_to_doctor)?;
        if next != existing {
            let payload = encode(&next).map_err(map_ors_to_doctor)?;
            let mut table = write.open_table(DOCTOR_ATTEMPTS).map_err(doctor_storage)?;
            table
                .insert(key.as_str(), payload.as_str())
                .map_err(doctor_storage)?;
        }
        write.commit().map_err(doctor_storage)?;
        Ok(Some(next))
    }

    /// Stages one Doctor effect intent before execution.
    ///
    /// Persist-before-effect: the `Intended` record is durably inserted
    /// before the named effect adapter may run. An exact replay under the
    /// same effect digest returns the durable row unchanged; a changed
    /// intent under the same digest fails with
    /// [`crate::DoctorLedgerError::EffectIdentityConflict`] and never
    /// overwrites the durable row.
    pub fn stage_doctor_effect(
        &self,
        record: &crate::DoctorEffectRecord,
    ) -> Result<crate::DoctorEffectStageOutcome, crate::DoctorLedgerError> {
        record.validate().map_err(map_ors_to_doctor)?;
        if record.state != crate::DoctorEffectState::Intended {
            return Err(doctor_storage("staging requires the intended state"));
        }
        let write = self.database.begin_write().map_err(doctor_storage)?;
        let existing = {
            let mut table = write.open_table(DOCTOR_EFFECTS).map_err(doctor_storage)?;
            let key = record.record_key();
            if let Some(existing) = table.get(key.as_str()).map_err(doctor_storage)? {
                let existing: crate::DoctorEffectRecord =
                    decode(existing.value()).map_err(map_ors_to_doctor)?;
                if !existing.same_binding(record) {
                    return Err(crate::DoctorLedgerError::EffectIdentityConflict {
                        effect_digest: key,
                    });
                }
                Some(existing)
            } else {
                let payload = encode(record).map_err(map_ors_to_doctor)?;
                table
                    .insert(key.as_str(), payload.as_str())
                    .map_err(doctor_storage)?;
                None
            }
        };
        write.commit().map_err(doctor_storage)?;
        Ok(match existing {
            Some(durable) => crate::DoctorEffectStageOutcome::Existing(durable),
            None => crate::DoctorEffectStageOutcome::Stored(record.clone()),
        })
    }

    /// Loads one Doctor effect by exact effect digest.
    pub fn load_doctor_effect(
        &self,
        effect_digest: &crate::OperationIdentity,
    ) -> Result<Option<crate::DoctorEffectRecord>, crate::DoctorLedgerError> {
        let read = self.database.begin_read().map_err(doctor_storage)?;
        let table = read.open_table(DOCTOR_EFFECTS).map_err(doctor_storage)?;
        table
            .get(effect_digest.as_str())
            .map_err(doctor_storage)?
            .map(|value| {
                let record: crate::DoctorEffectRecord =
                    decode(value.value()).map_err(map_ors_to_doctor)?;
                if record.effect_digest != *effect_digest {
                    return Err(doctor_storage(
                        "doctor effect identity does not match its key",
                    ));
                }
                Ok(record)
            })
            .transpose()
    }

    /// Binds the exact outcome or unknown state to one Doctor effect.
    ///
    /// A known report on `Intended`, `Unknown`, or `Reconciling` moves the
    /// effect to `Reported`; an unknown report on `Intended` moves it to
    /// `Unknown` with the effect digest as its reconciliation key. An exact
    /// repeat of an applied report returns the durable record unchanged; a
    /// different outcome under the same effect digest fails with
    /// [`crate::DoctorLedgerError::EffectIdentityConflict`]. An unknown
    /// effect returns `Ok(None)`; this method never invents a record and
    /// never retries blindly. The ORS write transaction assigns the
    /// monotonic commit order atomically when the effect first reaches its
    /// terminal state.
    pub fn record_doctor_effect_outcome(
        &self,
        effect_digest: &crate::OperationIdentity,
        report: &crate::DoctorEffectOutcomeReport,
    ) -> Result<Option<crate::DoctorEffectRecord>, crate::DoctorLedgerError> {
        report.validate().map_err(map_ors_to_doctor)?;
        let write = self.database.begin_write().map_err(doctor_storage)?;
        let key = effect_digest.as_str().to_owned();
        let existing: Option<crate::DoctorEffectRecord> = {
            let table = write.open_table(DOCTOR_EFFECTS).map_err(doctor_storage)?;
            table
                .get(key.as_str())
                .map_err(doctor_storage)?
                .map(|value| decode(value.value()))
                .transpose()
                .map_err(map_ors_to_doctor)?
        };
        let Some(existing) = existing else {
            return Ok(None);
        };
        if existing.effect_digest != *effect_digest {
            return Err(doctor_storage(
                "doctor effect identity does not match its key",
            ));
        }
        let mut next = existing.clone();
        if report.unknown {
            match existing.state {
                crate::DoctorEffectState::Intended => {
                    next.state = crate::DoctorEffectState::Unknown;
                    next.reconciliation_key = Some(existing.effect_digest.as_str().to_owned());
                }
                crate::DoctorEffectState::Unknown | crate::DoctorEffectState::Reconciling => {}
                crate::DoctorEffectState::Reported => {
                    return Err(crate::DoctorLedgerError::EffectIdentityConflict {
                        effect_digest: key,
                    });
                }
            }
        } else {
            let outcome = report
                .outcome_digest
                .clone()
                .ok_or_else(|| doctor_storage("a known outcome carries its exact digest"))?;
            match existing.state {
                crate::DoctorEffectState::Intended
                | crate::DoctorEffectState::Unknown
                | crate::DoctorEffectState::Reconciling => {
                    next.state = crate::DoctorEffectState::Reported;
                    next.outcome_digest = Some(outcome);
                    next.adapter_receipt_digest
                        .clone_from(&report.adapter_receipt_digest);
                    next.reconciliation_key = None;
                }
                crate::DoctorEffectState::Reported => {
                    if existing.outcome_digest.as_deref() != Some(outcome.as_str()) {
                        return Err(crate::DoctorLedgerError::EffectIdentityConflict {
                            effect_digest: key,
                        });
                    }
                }
            }
        }
        if next.state.is_terminal() && next.commit_order == 0 {
            next.commit_order = Self::next_operational_order(&write).map_err(map_ors_to_doctor)?;
        }
        next.validate().map_err(map_ors_to_doctor)?;
        if next != existing {
            let payload = encode(&next).map_err(map_ors_to_doctor)?;
            let mut table = write.open_table(DOCTOR_EFFECTS).map_err(doctor_storage)?;
            table
                .insert(key.as_str(), payload.as_str())
                .map_err(doctor_storage)?;
        }
        write.commit().map_err(doctor_storage)?;
        Ok(Some(next))
    }

    /// Loads one Doctor budget ledger by exact scope key.
    pub fn load_doctor_budget(
        &self,
        scope_key: &crate::OpaqueLabel,
    ) -> Result<Option<crate::DoctorBudgetLedger>, crate::DoctorLedgerError> {
        let read = self.database.begin_read().map_err(doctor_storage)?;
        let table = read.open_table(DOCTOR_BUDGETS).map_err(doctor_storage)?;
        table
            .get(scope_key.as_str())
            .map_err(doctor_storage)?
            .map(|value| {
                let ledger: crate::DoctorBudgetLedger =
                    decode(value.value()).map_err(map_ors_to_doctor)?;
                if ledger.scope_key != *scope_key {
                    return Err(doctor_storage("doctor budget scope does not match its key"));
                }
                Ok(ledger)
            })
            .transpose()
    }

    /// Persists one Doctor budget ledger row, replacing the prior row.
    ///
    /// Ledgers are Kernel-derived from durable admissions and outcomes,
    /// never caller-supplied authority: this method validates shape and
    /// replaces the row for its scope key so budget, cooldown, and
    /// quarantine enforcement survives restarts.
    pub fn store_doctor_budget(
        &self,
        ledger: &crate::DoctorBudgetLedger,
    ) -> Result<(), crate::DoctorLedgerError> {
        ledger.validate().map_err(map_ors_to_doctor)?;
        let write = self.database.begin_write().map_err(doctor_storage)?;
        {
            let mut table = write.open_table(DOCTOR_BUDGETS).map_err(doctor_storage)?;
            let key = ledger.record_key();
            let payload = encode(ledger).map_err(map_ors_to_doctor)?;
            table
                .insert(key.as_str(), payload.as_str())
                .map_err(doctor_storage)?;
        }
        write.commit().map_err(doctor_storage)
    }

    /// Reads the retained events of one stream, optionally scoped to one
    /// request, in sequence order.
    fn replay_events_in(
        table: &impl ReadableTable<&'static str, &'static str>,
        stream_id: &str,
        request_id: Option<&str>,
    ) -> Result<Vec<WorkerReplayEvent>, OrsError> {
        let prefix = WorkerReplayEvent::key_prefix_for(stream_id);
        let mut events = Vec::new();
        for row in table.iter().map_err(storage)? {
            let (key, value) = row.map_err(storage)?;
            if !key.value().starts_with(prefix.as_str()) {
                continue;
            }
            let event: WorkerReplayEvent = decode(value.value())?;
            if event.stream_id != stream_id {
                return Err(OrsError::IntegrityProblem {
                    record_type: "worker_replay_event",
                    reason: "event stream does not match its key".to_owned(),
                });
            }
            if request_id.is_some_and(|request| event.request_id != request) {
                continue;
            }
            events.push(event);
        }
        events.sort_by_key(|event| event.sequence);
        Ok(events)
    }

    /// Loads one native-worker claim inside a write transaction without
    /// mutating it. The replay journal only ever reads the claim table: the
    /// claim contour stays the single writer of claim state.
    fn load_claim_in(
        write: &redb::WriteTransaction,
        claim_id: &crate::OperationIdentity,
    ) -> Result<Option<crate::NativeWorkerClaimRecord>, OrsError> {
        let table = write.open_table(NATIVE_WORKER_CLAIMS).map_err(storage)?;
        table
            .get(claim_id.as_str())
            .map_err(storage)?
            .map(|value| {
                let record: crate::NativeWorkerClaimRecord = decode(value.value())?;
                record.validate()?;
                if record.claim_id != *claim_id {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "native_worker_claim",
                        reason: "claim record identity does not match its key".to_owned(),
                    });
                }
                Ok(record)
            })
            .transpose()
    }

    /// Loads one replay stream head inside a write transaction.
    fn load_stream_head_in(
        write: &redb::WriteTransaction,
        stream_id: &str,
    ) -> Result<Option<WorkerReplayStreamRecord>, OrsError> {
        let table = write.open_table(REPLAY_STREAMS).map_err(storage)?;
        table
            .get(stream_id)
            .map_err(storage)?
            .map(|value| {
                let head: WorkerReplayStreamRecord = decode(value.value())?;
                head.validate()?;
                if head.stream_id != stream_id {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "worker_replay_stream",
                        reason: "stream head identity does not match its key".to_owned(),
                    });
                }
                Ok(head)
            })
            .transpose()
    }

    /// Looks up one durable replay request without acquiring anything.
    ///
    /// Read-only: an unknown identity returns
    /// [`WorkerReplayRequestDecision::New`] and persists nothing, so a lookup
    /// can never manufacture an acquisition.
    pub fn lookup_replay_request(
        &self,
        stream_id: &str,
        request_id: &str,
        fingerprint: &str,
    ) -> Result<WorkerReplayRequestDecision, OrsError> {
        parse_replay_stream_id(stream_id)?;
        crate::model::validate_text(request_id, "worker_replay_request_id")?;
        crate::model::validate_text(fingerprint, "worker_replay_fingerprint")?;
        let read = self.database.begin_read().map_err(storage)?;
        let key = WorkerReplayRequestRecord::key_for(stream_id, request_id);
        let stored: Option<WorkerReplayRequestRecord> = {
            let table = read.open_table(REPLAY_REQUESTS).map_err(storage)?;
            table
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
        };
        let Some(stored) = stored else {
            return Ok(WorkerReplayRequestDecision::New);
        };
        if stored.stream_id != stream_id || stored.request_id != request_id {
            return Err(OrsError::IntegrityProblem {
                record_type: "worker_replay_request",
                reason: "request record identity does not match its key".to_owned(),
            });
        }
        if stored.fingerprint != fingerprint {
            return Ok(WorkerReplayRequestDecision::Conflict);
        }
        let events = {
            let table = read.open_table(REPLAY_EVENTS).map_err(storage)?;
            Self::replay_events_in(&table, stream_id, Some(request_id))?
        };
        Ok(WorkerReplayRequestDecision::Replay(events))
    }

    /// Atomically acquires one durable replay request or reports its durable
    /// outcome.
    ///
    /// Persist-before-ack: the claim gate runs first against the existing
    /// claim record (read-only); a missing claim or a stale
    /// generation/epoch/fence fails closed and acquires nothing. The stream
    /// head and the request record are then created in the same write
    /// transaction, so concurrent acquirers serialize on first-writer-wins
    /// and a retained acquisition is never a fresh request after a crash.
    /// This table never writes the claim table: one writer per state.
    pub fn begin_replay_request(
        &self,
        begin: &WorkerReplayBegin,
    ) -> Result<WorkerReplayRequestDecision, OrsError> {
        begin.validate()?;
        let (claim_id, _) = parse_replay_stream_id(&begin.stream_id)?;
        let write = self.database.begin_write().map_err(storage)?;
        let Some(claim) = Self::load_claim_in(&write, &claim_id)? else {
            return Err(OrsError::WorkerReplayStaleStream {
                stream_id: begin.stream_id.clone(),
            });
        };
        require_replay_claim_binding(
            &begin.stream_id,
            begin.producer_generation,
            begin.authority_epoch,
            &begin.fence_digest,
            &claim,
        )?;
        let key = WorkerReplayRequestRecord::key_for(&begin.stream_id, &begin.request_id);
        let stored: Option<WorkerReplayRequestRecord> = {
            let table = write.open_table(REPLAY_REQUESTS).map_err(storage)?;
            table
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
        };
        if let Some(stored) = stored {
            if stored.stream_id != begin.stream_id || stored.request_id != begin.request_id {
                return Err(OrsError::IntegrityProblem {
                    record_type: "worker_replay_request",
                    reason: "request record identity does not match its key".to_owned(),
                });
            }
            if stored.fingerprint != begin.fingerprint {
                return Ok(WorkerReplayRequestDecision::Conflict);
            }
            let events = {
                let table = write.open_table(REPLAY_EVENTS).map_err(storage)?;
                Self::replay_events_in(&table, &begin.stream_id, Some(begin.request_id.as_str()))?
            };
            return Ok(WorkerReplayRequestDecision::Replay(events));
        }
        if Self::load_stream_head_in(&write, &begin.stream_id)?.is_none() {
            let (head_claim_id, head_generation) = parse_replay_stream_id(&begin.stream_id)?;
            let head = WorkerReplayStreamRecord {
                contract_version: crate::CONTRACT_VERSION,
                stream_id: begin.stream_id.clone(),
                claim_id: head_claim_id,
                worker_generation: head_generation,
                producer_cursor: 0,
                consumer_cursor: 0,
                next_sequence: 1,
            };
            head.validate()?;
            let mut streams = write.open_table(REPLAY_STREAMS).map_err(storage)?;
            streams
                .insert(begin.stream_id.as_str(), encode(&head)?.as_str())
                .map_err(storage)?;
        }
        let record = WorkerReplayRequestRecord {
            stream_id: begin.stream_id.clone(),
            request_id: begin.request_id.clone(),
            fingerprint: begin.fingerprint.clone(),
            producer_generation: begin.producer_generation,
            authority_epoch: begin.authority_epoch,
            fence_digest: begin.fence_digest.clone(),
            acquired_at_unix_ms: current_unix_ms_u64()?,
        };
        record.validate()?;
        {
            let mut table = write.open_table(REPLAY_REQUESTS).map_err(storage)?;
            table
                .insert(key.as_str(), encode(&record)?.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(WorkerReplayRequestDecision::New)
    }

    /// Persists one replay draft under its exact stream with a durable
    /// identity and sequence.
    ///
    /// One write transaction: claim gate, acquisition check, idempotent
    /// replay of an identical draft (same `event_id` and sequence), otherwise
    /// assignment of the stream's next sequence. The claim table is only
    /// read; the event row is immutable once written.
    pub fn append_replay_event(
        &self,
        draft: &WorkerReplayDraft,
    ) -> Result<WorkerReplayEvent, OrsError> {
        draft.validate()?;
        let digest = draft.draft_digest()?;
        let (claim_id, _) = parse_replay_stream_id(&draft.stream_id)?;
        let write = self.database.begin_write().map_err(storage)?;
        let Some(claim) = Self::load_claim_in(&write, &claim_id)? else {
            return Err(OrsError::WorkerReplayStaleStream {
                stream_id: draft.stream_id.clone(),
            });
        };
        require_replay_claim_binding(
            &draft.stream_id,
            draft.producer_generation,
            draft.authority_epoch,
            &draft.fence_digest,
            &claim,
        )?;
        let request_key = WorkerReplayRequestRecord::key_for(&draft.stream_id, &draft.request_id);
        let request: WorkerReplayRequestRecord = {
            let table = write.open_table(REPLAY_REQUESTS).map_err(storage)?;
            table
                .get(request_key.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
                .ok_or(OrsError::ReservationNotFound)?
        };
        if request.stream_id != draft.stream_id || request.request_id != draft.request_id {
            return Err(OrsError::IntegrityProblem {
                record_type: "worker_replay_request",
                reason: "request record identity does not match its key".to_owned(),
            });
        }
        let replayed = {
            let table = write.open_table(REPLAY_EVENTS).map_err(storage)?;
            Self::replay_events_in(&table, &draft.stream_id, Some(draft.request_id.as_str()))?
                .into_iter()
                .find(|event| event.draft_digest == digest)
        };
        if let Some(replayed) = replayed {
            return Ok(replayed);
        }
        let mut head = Self::load_stream_head_in(&write, &draft.stream_id)?.ok_or_else(|| {
            OrsError::IntegrityProblem {
                record_type: "worker_replay_stream",
                reason: "stream head is missing for an acquired request".to_owned(),
            }
        })?;
        let sequence = head.next_sequence;
        head.next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| OrsError::IntegrityProblem {
                record_type: "worker_replay_stream",
                reason: "sequence counter exhausted".to_owned(),
            })?;
        head.validate()?;
        let stream_digest = crate::model::sha256_hex(draft.stream_id.as_bytes());
        let stream_tag = stream_digest
            .get(..16)
            .ok_or_else(|| OrsError::IntegrityProblem {
                record_type: "worker_replay_event",
                reason: "stream digest is unexpectedly short".to_owned(),
            })?;
        let event = WorkerReplayEvent {
            contract_version: crate::CONTRACT_VERSION,
            stream_id: draft.stream_id.clone(),
            event_id: format!("evt-{stream_tag}-{sequence:020}"),
            sequence,
            request_id: draft.request_id.clone(),
            fingerprint: request.fingerprint.clone(),
            producer_id: draft.producer_id.clone(),
            producer_generation: draft.producer_generation,
            authority_epoch: draft.authority_epoch,
            fence_digest: draft.fence_digest.clone(),
            causal_predecessor_refs: draft.causal_predecessor_refs.clone(),
            delivery_class: draft.delivery_class,
            ack_required: draft.ack_required,
            payload_type: draft.payload_type.clone(),
            payload: draft.payload.clone(),
            disposition: draft.disposition.clone(),
            trace_context: draft.trace_context.clone(),
            draft_digest: digest,
            durable_at_unix_ms: current_unix_ms_u64()?,
        };
        event.validate()?;
        {
            let mut events = write.open_table(REPLAY_EVENTS).map_err(storage)?;
            events
                .insert(event.record_key().as_str(), encode(&event)?.as_str())
                .map_err(storage)?;
            let mut streams = write.open_table(REPLAY_STREAMS).map_err(storage)?;
            streams
                .insert(head.stream_id.as_str(), encode(&head)?.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(event)
    }

    /// Returns the retained suffix strictly after `after_sequence` in
    /// sequence order, preserving gaps.
    ///
    /// Read-only. An oversized suffix fails with
    /// [`OrsError::ProjectionLimitExceeded`] instead of truncating silently;
    /// a pruned prefix covering `after_sequence` fails with
    /// [`OrsError::WorkerReplayIncomplete`] instead of returning an empty
    /// success on incomplete storage. A caught-up consumer (nothing retained
    /// after its cursor) honestly receives an empty suffix.
    pub fn replay_stream(
        &self,
        stream_id: &str,
        after_sequence: u64,
    ) -> Result<Vec<WorkerReplayEvent>, OrsError> {
        parse_replay_stream_id(stream_id)?;
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(REPLAY_EVENTS).map_err(storage)?;
        let events: Vec<WorkerReplayEvent> = Self::replay_events_in(&table, stream_id, None)?
            .into_iter()
            .filter(|event| event.sequence > after_sequence)
            .collect();
        let Some(first) = events.first() else {
            return Ok(Vec::new());
        };
        let want =
            after_sequence
                .checked_add(1)
                .ok_or_else(|| OrsError::WorkerReplayIncomplete {
                    stream_id: stream_id.to_owned(),
                    after_sequence,
                })?;
        if want < first.sequence {
            return Err(OrsError::WorkerReplayIncomplete {
                stream_id: stream_id.to_owned(),
                after_sequence,
            });
        }
        if events.len() > usize::from(crate::MAX_REPLAY_PAGE) {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        Ok(events)
    }

    /// Verifies one acknowledgement against its exact durable event,
    /// persists the disposition, and advances only the cursor its phase
    /// allows.
    ///
    /// One write transaction: claim gate, exact event binding (stream, event,
    /// sequence, generation, epoch, fence), ack persistence, monotonic cursor
    /// advance. UNKNOWN persists its disposition for reconciliation by the
    /// original identity and moves no cursor.
    pub fn acknowledge_replay_event(
        &self,
        ack: &WorkerReplayAck,
    ) -> Result<WorkerReplayCursors, OrsError> {
        ack.validate()?;
        let mismatch = || OrsError::WorkerReplayAckMismatch {
            stream_id: ack.stream_id.clone(),
            sequence: ack.sequence,
        };
        let (claim_id, _) = parse_replay_stream_id(&ack.stream_id)?;
        let write = self.database.begin_write().map_err(storage)?;
        let Some(claim) = Self::load_claim_in(&write, &claim_id)? else {
            return Err(OrsError::WorkerReplayStaleStream {
                stream_id: ack.stream_id.clone(),
            });
        };
        require_replay_claim_binding(
            &ack.stream_id,
            ack.producer_generation,
            ack.authority_epoch,
            &ack.fence_digest,
            &claim,
        )?;
        let event_key = WorkerReplayEvent::key_for(&ack.stream_id, ack.sequence);
        let event: WorkerReplayEvent = {
            let table = write.open_table(REPLAY_EVENTS).map_err(storage)?;
            table
                .get(event_key.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?
                .ok_or_else(&mismatch)?
        };
        if event.stream_id != ack.stream_id
            || event.sequence != ack.sequence
            || event.event_id != ack.event_id
            || event.producer_generation != ack.producer_generation
            || event.authority_epoch != ack.authority_epoch
            || event.fence_digest != ack.fence_digest
        {
            return Err(mismatch());
        }
        let stored = WorkerReplayAckRecord {
            stream_id: ack.stream_id.clone(),
            event_id: ack.event_id.clone(),
            sequence: ack.sequence,
            phase: ack.phase,
            acknowledged_at_unix_ms: current_unix_ms_u64()?,
        };
        stored.validate()?;
        {
            let mut acks = write.open_table(REPLAY_ACKS).map_err(storage)?;
            acks.insert(event_key.as_str(), encode(&stored)?.as_str())
                .map_err(storage)?;
        }
        let mut head = Self::load_stream_head_in(&write, &ack.stream_id)?.ok_or_else(|| {
            OrsError::IntegrityProblem {
                record_type: "worker_replay_stream",
                reason: "stream head is missing for an acknowledged event".to_owned(),
            }
        })?;
        if ack.phase.advances_producer_cursor() {
            head.producer_cursor = head.producer_cursor.max(ack.sequence);
        }
        if ack.phase.advances_consumer_cursor() {
            head.consumer_cursor = head.consumer_cursor.max(ack.sequence);
        }
        head.validate()?;
        {
            let mut streams = write.open_table(REPLAY_STREAMS).map_err(storage)?;
            streams
                .insert(head.stream_id.as_str(), encode(&head)?.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(WorkerReplayCursors {
            stream_id: ack.stream_id.clone(),
            producer_cursor: head.producer_cursor,
            consumer_cursor: head.consumer_cursor,
        })
    }

    /// Prunes the longest APPLIED-or-REJECTED event prefix of one stream,
    /// retaining the newest [`crate::MAX_REPLAY_PAGE`] terminal events.
    ///
    /// Retention maintenance, not execution: no claim binding is required, so
    /// old-generation history stays bounded too. The scan stops at the first
    /// event without an APPLIED/REJECTED acknowledgement, so UNKNOWN (still
    /// reconciling) events and their ack facts are never removed. Ack facts
    /// of pruned events are removed with them. Returns the number of events
    /// removed.
    pub fn prune_replay_stream(&self, stream_id: &str) -> Result<u64, OrsError> {
        parse_replay_stream_id(stream_id)?;
        let write = self.database.begin_write().map_err(storage)?;
        let events = {
            let table = write.open_table(REPLAY_EVENTS).map_err(storage)?;
            Self::replay_events_in(&table, stream_id, None)?
        };
        let mut prunable: Vec<String> = Vec::new();
        {
            let acks = write.open_table(REPLAY_ACKS).map_err(storage)?;
            for event in &events {
                let key = event.record_key();
                let terminal = match acks.get(key.as_str()).map_err(storage)? {
                    None => false,
                    Some(value) => {
                        let ack: WorkerReplayAckRecord = decode(value.value())?;
                        is_replay_terminal_phase(ack.phase)
                    }
                };
                if !terminal {
                    break;
                }
                prunable.push(key);
            }
        }
        let drop_count = prunable
            .len()
            .saturating_sub(usize::from(crate::MAX_REPLAY_PAGE));
        let mut removed: u64 = 0;
        if drop_count > 0 {
            let mut events_table = write.open_table(REPLAY_EVENTS).map_err(storage)?;
            let mut acks_table = write.open_table(REPLAY_ACKS).map_err(storage)?;
            for key in prunable.iter().take(drop_count) {
                events_table.remove(key.as_str()).map_err(storage)?;
                acks_table.remove(key.as_str()).map_err(storage)?;
                removed += 1;
            }
        }
        write.commit().map_err(storage)?;
        Ok(removed)
    }

    /// Loads one replay stream head without mutating anything.
    ///
    /// Read-only projection for the Kernel replay transport: an unknown
    /// stream returns `Ok(None)`; a stored head is validated before return.
    pub fn load_replay_stream_head(
        &self,
        stream_id: &str,
    ) -> Result<Option<WorkerReplayStreamRecord>, OrsError> {
        parse_replay_stream_id(stream_id)?;
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(REPLAY_STREAMS).map_err(storage)?;
        table
            .get(stream_id)
            .map_err(storage)?
            .map(|value| {
                let head: WorkerReplayStreamRecord = decode(value.value())?;
                head.validate()?;
                if head.stream_id != stream_id {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "worker_replay_stream",
                        reason: "stream head identity does not match its key".to_owned(),
                    });
                }
                Ok(head)
            })
            .transpose()
    }

    /// Loads one retained replay acquisition without mutating anything.
    ///
    /// Read-only projection for the Kernel replay transport: an unknown
    /// `(stream, request)` returns `Ok(None)`.
    pub fn load_replay_request_record(
        &self,
        stream_id: &str,
        request_id: &str,
    ) -> Result<Option<WorkerReplayRequestRecord>, OrsError> {
        parse_replay_stream_id(stream_id)?;
        crate::model::validate_text(request_id, "worker_replay_request_id")?;
        let read = self.database.begin_read().map_err(storage)?;
        let key = WorkerReplayRequestRecord::key_for(stream_id, request_id);
        let table = read.open_table(REPLAY_REQUESTS).map_err(storage)?;
        table
            .get(key.as_str())
            .map_err(storage)?
            .map(|value| {
                let stored: WorkerReplayRequestRecord = decode(value.value())?;
                stored.validate()?;
                if stored.stream_id != stream_id || stored.request_id != request_id {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "worker_replay_request",
                        reason: "request record identity does not match its key".to_owned(),
                    });
                }
                Ok(stored)
            })
            .transpose()
    }

    #[cfg(feature = "test-support")]
    pub fn insert_store_rebind_legacy_for_test(
        &self,
        record: &crate::StoreRebindReplayRecord,
    ) -> Result<(), OrsError> {
        record.validate()?;
        if record.state != crate::StoreRebindReplayState::Committed {
            return Err(OrsError::InvalidField {
                field: "store_rebind_state",
                reason: "legacy insert requires committed",
            });
        }
        let write = self.database.begin_write().map_err(storage)?;
        {
            let mut table = write.open_table(STORE_REBIND_REPLAY).map_err(storage)?;
            let key = format!(
                "{}::{}",
                record.operation_id.as_str(),
                record.request_digest.clone()
            );
            let payload = encode(record)?;
            table
                .insert(key.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)
    }

    /// Test-only admission hook without a freshness check.
    ///
    /// Production callers must use [`Self::begin_authority_handoff_fresh`],
    /// which samples the system clock inside the write transaction.
    #[cfg(test)]
    pub(crate) fn begin_authority_handoff(
        &self,
        record: &AuthorityHandoffRecord,
    ) -> Result<AuthorityHandoffBegin, OrsError> {
        self.begin_authority_handoff_with_now(record, None)
    }

    /// Test-only deterministic-clock admission hook.
    ///
    /// The freshness check is performed inside the same redb write
    /// transaction as the create-if-absent decision. Callers that already
    /// have a deterministic clock observation (for example, acceptance
    /// tests) can use this method to exercise the exact boundary.
    #[cfg(test)]
    pub(crate) fn begin_authority_handoff_at(
        &self,
        record: &AuthorityHandoffRecord,
        now_ms: i64,
    ) -> Result<AuthorityHandoffBegin, OrsError> {
        self.begin_authority_handoff_with_now(record, Some(now_ms))
    }

    /// Atomically reserves one typed authority handoff using a clock sample
    /// taken after the ORS write transaction has acquired its serialization
    /// point. This is the production fresh-admission entry point.
    pub fn begin_authority_handoff_fresh(
        &self,
        record: &AuthorityHandoffRecord,
    ) -> Result<AuthorityHandoffBegin, OrsError> {
        record.validate()?;
        if record.state != AuthorityHandoffState::Reserved {
            return Err(OrsError::IntegrityProblem {
                record_type: "authority_handoff",
                reason: "begin requires a RESERVED candidate".to_owned(),
            });
        }
        let write = self.database.begin_write().map_err(storage)?;
        let now_ms = current_unix_ms()?;
        let outcome = Self::begin_authority_handoff_in_write(&write, record, Some(now_ms))?;
        write.commit().map_err(storage)?;
        Ok(outcome)
    }

    #[cfg(test)]
    fn begin_authority_handoff_with_now(
        &self,
        record: &AuthorityHandoffRecord,
        now_ms: Option<i64>,
    ) -> Result<AuthorityHandoffBegin, OrsError> {
        record.validate()?;
        if record.state != AuthorityHandoffState::Reserved {
            return Err(OrsError::IntegrityProblem {
                record_type: "authority_handoff",
                reason: "begin requires a RESERVED candidate".to_owned(),
            });
        }
        let write = self.database.begin_write().map_err(storage)?;
        let outcome = Self::begin_authority_handoff_in_write(&write, record, now_ms)?;
        write.commit().map_err(storage)?;
        Ok(outcome)
    }

    fn begin_authority_handoff_in_write(
        write: &redb::WriteTransaction,
        record: &AuthorityHandoffRecord,
        now_ms: Option<i64>,
    ) -> Result<AuthorityHandoffBegin, OrsError> {
        if now_ms.is_some_and(|now| record.issued_at_ms > now || record.expires_at_ms <= now) {
            // An already-existing exact handoff remains replay evidence; the
            // freshness gate applies only to a new Reserved durable intent.
            let table = write.open_table(AUTHORITY_HANDOFFS).map_err(storage)?;
            let existing = table
                .get(record.handoff_id.as_str())
                .map_err(storage)?
                .is_some();
            drop(table);
            if !existing {
                return Err(OrsError::AuthorityHandoffNotFresh);
            }
        }
        let outcome = {
            let mut table = write.open_table(AUTHORITY_HANDOFFS).map_err(storage)?;
            if let Some(existing) = table.get(record.handoff_id.as_str()).map_err(storage)? {
                let existing: AuthorityHandoffRecord = decode(existing.value())?;
                existing.validate()?;
                if !existing.same_identity(record) {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "authority_handoff",
                        reason: "same handoff id has conflicting identity".to_owned(),
                    });
                }
                AuthorityHandoffBegin::Existing(existing)
            } else {
                let payload = encode(record)?;
                table
                    .insert(record.handoff_id.as_str(), payload.as_str())
                    .map_err(storage)?;
                AuthorityHandoffBegin::Acquired
            }
        };
        Ok(outcome)
    }

    /// Commits a handoff outcome without replacing its immutable identity.
    pub fn persist_authority_handoff(
        &self,
        record: &AuthorityHandoffRecord,
    ) -> Result<(), OrsError> {
        record.validate()?;
        let write = self.database.begin_write().map_err(storage)?;
        {
            let mut table = write.open_table(AUTHORITY_HANDOFFS).map_err(storage)?;
            let existing: Option<AuthorityHandoffRecord> = table
                .get(record.handoff_id.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?;
            let existing: AuthorityHandoffRecord =
                existing.ok_or(OrsError::AuthoritySnapshotUnavailable)?;
            existing.validate()?;
            if !existing.same_identity(record) {
                return Err(OrsError::IntegrityProblem {
                    record_type: "authority_handoff",
                    reason: "handoff identity replacement rejected".to_owned(),
                });
            }
            let allowed = match (existing.state, record.state) {
                (
                    AuthorityHandoffState::Reserved,
                    AuthorityHandoffState::Consumed | AuthorityHandoffState::Unknown,
                ) => true,
                (AuthorityHandoffState::Consumed, AuthorityHandoffState::Consumed)
                | (AuthorityHandoffState::Unknown, AuthorityHandoffState::Unknown) => {
                    existing == *record
                }
                _ => false,
            };
            if !allowed {
                return Err(OrsError::IntegrityProblem {
                    record_type: "authority_handoff",
                    reason: "non-monotonic or conflicting handoff transition".to_owned(),
                });
            }
            let payload = encode(record)?;
            table
                .insert(record.handoff_id.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        #[cfg(feature = "test-support")]
        if record.state == AuthorityHandoffState::Consumed
            && self
                .authority_handoff_failpoint
                .lock()
                .ok()
                .and_then(|slot| slot.as_ref().map(Arc::clone))
                .is_some_and(|failpoint| failpoint.take_consume_commit_failure())
        {
            return Err(OrsError::Storage(
                "test-only uncertain consume commit outcome".to_owned(),
            ));
        }
        Ok(())
    }

    /// Reads one handoff for bounded recovery/reconciliation.
    pub fn load_authority_handoff(
        &self,
        handoff_id: &crate::OperationIdentity,
    ) -> Result<Option<AuthorityHandoffRecord>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(AUTHORITY_HANDOFFS).map_err(storage)?;
        table
            .get(handoff_id.as_str())
            .map_err(storage)?
            .map(|value| {
                let record: AuthorityHandoffRecord = decode(value.value())?;
                record.validate()?;
                Ok(record)
            })
            .transpose()
    }

    /// Appends one observation-only evidence projection, preserving conflicts.
    pub fn persist_process_evidence(&self, record: &ProcessEvidenceRecord) -> Result<(), OrsError> {
        record.validate()?;
        let key = record.record_key()?;
        let write = self.database.begin_write().map_err(storage)?;
        {
            let mut table = write.open_table(PROCESS_EVIDENCE).map_err(storage)?;
            let existing: Option<ProcessEvidenceRecord> = table
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?;
            if let Some(existing) = existing {
                existing.validate()?;
                if existing != *record {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "process_evidence",
                        reason: "conflicting evidence replacement rejected".to_owned(),
                    });
                }
            } else {
                let payload = encode(record)?;
                table
                    .insert(key.as_str(), payload.as_str())
                    .map_err(storage)?;
            }
        }
        write.commit().map_err(storage)
    }

    /// Reads bounded observation-only evidence history for one operation.
    pub fn load_process_evidence(
        &self,
        operation_id: &crate::OperationIdentity,
    ) -> Result<Vec<ProcessEvidenceRecord>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(PROCESS_EVIDENCE).map_err(storage)?;
        // Process-evidence rows are written by ProcessEvidenceRecord::record_key with the
        // operation identity preserved verbatim. Keep the reader on that wire and bound the
        // physical prefix range inclusively so the U+10FFFF endpoint cannot hide a row.
        let prefix = format!("{}::", operation_id.as_str());
        let prefix_end = format!("{prefix}\u{10ffff}");
        let mut records = Vec::new();
        for entry in table
            .range(prefix.as_str()..=prefix_end.as_str())
            .map_err(storage)?
        {
            let (key, value) = entry.map_err(storage)?;
            let key = key.value();
            if !key.starts_with(prefix.as_str()) {
                break;
            }
            let record: ProcessEvidenceRecord = decode(value.value())?;
            record.validate()?;
            // Raw sibling identities can fall inside the physical prefix range (for example,
            // `op::sibling` while reading `op`). Decode the identity before applying the
            // canonical-key check so those rows are not misclassified as corruption.
            if record.operation_id != *operation_id {
                continue;
            }
            let canonical_key = record.record_key()?;
            if key != canonical_key {
                return Err(OrsError::IntegrityProblem {
                    record_type: "process_evidence",
                    reason: "evidence record does not match its canonical key".to_owned(),
                });
            }
            records.push(record);
            if records.len() > usize::from(crate::MAX_PROCESS_EVIDENCE_READBACK) {
                return Err(OrsError::IntegrityProblem {
                    record_type: "process_evidence",
                    reason: "evidence history exceeds the bounded readback limit".to_owned(),
                });
            }
        }
        // A prior/incorrect writer may have escaped the operation identity. Never silently
        // accept those rows, but only classify rows whose decoded identity is the requested
        // operation; encoded sibling identities remain outside this readback.
        if operation_id.as_str().contains(':') || operation_id.as_str().contains('%') {
            let encoded_prefix = format!("{}::", Self::encode_key_component(operation_id.as_str()));
            let encoded_prefix_end = format!("{encoded_prefix}\u{10ffff}");
            for entry in table
                .range(encoded_prefix.as_str()..=encoded_prefix_end.as_str())
                .map_err(storage)?
            {
                let (key, value) = entry.map_err(storage)?;
                let key = key.value();
                if !key.starts_with(encoded_prefix.as_str()) {
                    break;
                }
                let record: ProcessEvidenceRecord = decode(value.value())?;
                record.validate()?;
                if record.operation_id == *operation_id && key != record.record_key()? {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "process_evidence",
                        reason:
                            "encoded evidence key requires migration to the raw operation-id wire"
                                .to_owned(),
                    });
                }
            }
        }
        records.sort_by(|left, right| {
            left.observed_at_ms
                .cmp(&right.observed_at_ms)
                .then_with(|| left.evidence_digest.cmp(&right.evidence_digest))
                .then_with(|| left.record_key().ok().cmp(&right.record_key().ok()))
        });
        Ok(records)
    }

    /// Durable key of one `(operation, stream)` recovery projection.
    ///
    /// Stdout and stderr never share a key, so one stream can never satisfy,
    /// overwrite or be read back as the other.
    fn process_stream_recovery_key(
        operation_id: &crate::OperationIdentity,
        stream: ProcessStreamKind,
    ) -> String {
        format!(
            "{}:{}",
            operation_id.as_str(),
            ProcessStreamRecoveryProjection::stream_key(stream)
        )
    }

    /// Writes one process-stream recovery projection.
    ///
    /// The evidence axes are immutable after the first durable write. A later
    /// write may advance only availability, reconciliation and activation, and
    /// only when `evidence_axes_sha256` is unchanged and the activation
    /// transition is permitted. A conflicting evidence rewrite is rejected
    /// rather than overwriting retained history, so no revalidation path can
    /// rewrite typed transport or persistence state.
    ///
    /// This is the family's only durable writer, so it is also where the family
    /// revision advances (issue #2884): an inserted or advanced row moves the
    /// revision in the same transaction, which is what lets a backup
    /// continuation holding the family frozen detect the movement. An exact
    /// re-presentation that wrote nothing leaves the revision alone, so a
    /// replayed observation never looks like movement.
    pub fn put_process_stream_recovery(
        &self,
        projection: &ProcessStreamRecoveryProjection,
    ) -> Result<ProcessStreamRecoveryWriteOutcome, OrsError> {
        projection.validate()?;
        let key = projection.record_key()?;
        let incoming_axes = projection.evidence_axes_sha256()?;
        let write = self.database.begin_write().map_err(storage)?;
        let outcome = {
            let mut table = write.open_table(PROCESS_STREAM_RECOVERY).map_err(storage)?;
            let existing = table
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| decode::<ProcessStreamRecoveryProjection>(value.value()))
                .transpose()?;
            match existing {
                Some(existing) if existing == *projection => {
                    ProcessStreamRecoveryWriteOutcome::Unchanged
                }
                Some(existing) => {
                    if existing.evidence_axes_sha256()? != incoming_axes {
                        return Err(OrsError::IntegrityProblem {
                            record_type: "process_stream_recovery",
                            reason: "recovery evidence axes are immutable".to_owned(),
                        });
                    }
                    if !existing
                        .activation
                        .permits_transition_to(projection.activation)
                    {
                        return Err(OrsError::InvalidField {
                            field: "stream_recovery_activation",
                            reason: "durable activation transition is not permitted",
                        });
                    }
                    let payload = encode(projection)?;
                    table
                        .insert(key.as_str(), payload.as_str())
                        .map_err(storage)?;
                    ProcessStreamRecoveryWriteOutcome::Advanced
                }
                None => {
                    let payload = encode(projection)?;
                    table
                        .insert(key.as_str(), payload.as_str())
                        .map_err(storage)?;
                    ProcessStreamRecoveryWriteOutcome::Inserted
                }
            }
        };
        if outcome != ProcessStreamRecoveryWriteOutcome::Unchanged {
            Self::advance_process_stream_recovery_family_revision(&write)?;
        }
        write.commit().map_err(storage)?;
        Ok(outcome)
    }

    /// Reads both stream projections for one operation, in canonical order.
    ///
    /// Each row is read by its own exact key, decoded through the existing ORS
    /// codec, revalidated, and checked against its own operation and stream
    /// identity. A codec-version mismatch and an interrupted or unreadable row
    /// are distinct, explicit dispositions; neither is silently repaired,
    /// upgraded or dropped.
    pub fn load_process_stream_recovery(
        &self,
        operation_id: &crate::OperationIdentity,
    ) -> Result<Vec<ProcessStreamRecoveryProjection>, ProcessStreamRecoveryLoadError> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| Self::stream_recovery_read_error(&storage(error)))?;
        let table = read
            .open_table(PROCESS_STREAM_RECOVERY)
            .map_err(|error| Self::stream_recovery_read_error(&storage(error)))?;
        let mut projections = Vec::with_capacity(2);
        for stream in [ProcessStreamKind::Stdout, ProcessStreamKind::Stderr] {
            let key = Self::process_stream_recovery_key(operation_id, stream);
            let Some(value) = table
                .get(key.as_str())
                .map_err(|error| Self::stream_recovery_read_error(&storage(error)))?
            else {
                continue;
            };
            let projection: ProcessStreamRecoveryProjection =
                decode(value.value()).map_err(Self::stream_recovery_load_error)?;
            let canonical = projection
                .record_key()
                .map_err(Self::stream_recovery_load_error)?;
            if projection.operation_id != *operation_id
                || projection.stream != stream
                || canonical != key
            {
                return Err(ProcessStreamRecoveryLoadError::InterruptedRead {
                    reason: "durable row does not match its canonical operation/stream key"
                        .to_owned(),
                });
            }
            projections.push(projection);
        }
        Ok(projections)
    }

    /// Revalidates both stream projections for one operation and persists only
    /// the resulting availability observation.
    ///
    /// Returned outcomes are aligned with
    /// [`Self::load_process_stream_recovery`], so stdout and stderr stay
    /// independently observable. This path never writes transport, persistence
    /// or gaps: a failed revalidation records a typed availability fault and
    /// preserves the prior typed state exactly, and no outcome can promote
    /// `PARTIAL_SOURCE` or `SOURCE_UNAVAILABLE` to `COMPLETE_SOURCE`.
    pub fn revalidate_process_stream_recovery(
        &self,
        operation_id: &crate::OperationIdentity,
        fence: &ProcessStreamRecoveryFence,
        resolver: &dyn ProcessStreamSourceResolver,
    ) -> Result<Vec<ProcessStreamRecoveryRevalidation>, ProcessStreamRecoveryLoadError> {
        let mut outcomes = Vec::new();
        for projection in self.load_process_stream_recovery(operation_id)? {
            let outcome = projection.revalidate(fence, resolver);
            if let Some(availability) = outcome.availability() {
                let observed = projection
                    .with_availability(availability)
                    .map_err(Self::stream_recovery_load_error)?;
                self.put_process_stream_recovery(&observed)
                    .map_err(Self::stream_recovery_load_error)?;
            }
            outcomes.push(outcome);
        }
        Ok(outcomes)
    }

    /// Projects the available stream recovery state for one operation into the
    /// ORS status/recovery view.
    ///
    /// The view exposes availability, authenticated handles, the exact durable
    /// coverage and the exact gap set. It carries no stream bytes and no
    /// parser, evaluator, task or finish claim, so it can never assert semantic
    /// proof.
    pub fn process_stream_recovery_status(
        &self,
        operation_id: &crate::OperationIdentity,
    ) -> Result<Vec<ProcessStreamRecoveryStatusProjection>, ProcessStreamRecoveryLoadError> {
        Ok(self
            .load_process_stream_recovery(operation_id)?
            .iter()
            .map(ProcessStreamRecoveryStatusProjection::from_projection)
            .collect())
    }

    /// Retires one recovery projection after the owning operation contract has
    /// proven both terminal disposition and the evidence handoff readback.
    ///
    /// Retirement is not deletion: the row stays durable as terminal evidence so
    /// a mistaken retirement remains recoverable, which is why the Architecture
    /// forbids destroying it outright. Nothing here infers terminality from the
    /// projection; the terminal reservation state, its named recovery owner,
    /// its terminal receipt and the proven handoff digest must all agree.
    ///
    /// Because the retired row is written through the family's one write path,
    /// retirement advances the durable family revision in the same transaction
    /// (issue #2884). A backup that froze the family before this call therefore
    /// observes the movement and refuses to continue, instead of emitting a
    /// snapshot that silently mixes pre- and post-retirement evidence.
    pub fn retire_process_stream_recovery(
        &self,
        projection: &ProcessStreamRecoveryProjection,
        proof: &ProcessStreamRetirementProof,
    ) -> Result<ProcessStreamRecoveryWriteOutcome, OrsError> {
        projection.validate()?;
        proof.validate()?;
        let key = projection.record_key()?;
        let read = self.database.begin_read().map_err(storage)?;
        {
            let table = read.open_table(PROCESS_STREAM_RECOVERY).map_err(storage)?;
            let stored = table
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| decode::<ProcessStreamRecoveryProjection>(value.value()))
                .transpose()?
                .ok_or(OrsError::IntegrityProblem {
                    record_type: "process_stream_recovery",
                    reason: "the named recovery projection row is not durable".to_owned(),
                })?;
            if stored.evidence_axes_sha256()? != projection.evidence_axes_sha256()? {
                return Err(OrsError::IntegrityProblem {
                    record_type: "process_stream_recovery",
                    reason: "retirement target does not match the durable evidence axes".to_owned(),
                });
            }
        }
        let reservation_id = {
            let operations = read.open_table(OPERATIONS).map_err(storage)?;
            operations
                .get(projection.operation_id.as_str())
                .map_err(storage)?
                .map(|value| value.value().to_owned())
                .ok_or(OrsError::ReservationNotFound)?
        };
        if reservation_id != proof.reservation_id.as_str() {
            return Err(OrsError::ReconciliationMismatch);
        }
        let reservation = {
            let reservations = read.open_table(RESERVATIONS).map_err(storage)?;
            let value = reservations
                .get(reservation_id.as_str())
                .map_err(storage)?
                .ok_or(OrsError::ReservationNotFound)?;
            decode::<ReservationRecord>(value.value())?
        };
        if reservation.token.recovery_owner != proof.recovery_owner
            || projection.reconciliation.owner != proof.recovery_owner
        {
            return Err(OrsError::RecoveryOwnerMismatch);
        }
        if !reservation.state.is_terminal() {
            return Err(OrsError::UnsafeExpiry);
        }
        if reservation.terminal_receipt_id.as_ref() != Some(&proof.terminal_receipt_id)
            || projection.reconciliation.handoff_sha256.as_deref()
                != Some(proof.handoff_sha256.as_str())
        {
            return Err(OrsError::ReconciliationMismatch);
        }
        drop(read);
        let retired = projection.with_activation(StreamRecoveryActivation::Retired)?;
        self.put_process_stream_recovery(&retired)
    }

    /// Imports a recovery projection from backup/restore as suspended evidence.
    ///
    /// The incoming activation state is discarded: an imported projection is
    /// always `Suspended`, and an already-`Retired` projection stays `Retired`.
    /// A restore therefore can never revive old process, session or authority
    /// state through this record. Only the recovery projection row is written;
    /// no reservation, session or authority row is created, reactivated or
    /// otherwise revived.
    ///
    /// This stays the only durable restore route for the family (issue #2884):
    /// paging the family into more backup pages raises no authority, and every
    /// exported row still lands here as suspended evidence. The write advances
    /// the destination's family revision, so a backup taken of the destination
    /// while the restore is in flight observes the movement rather than
    /// certifying a half-restored family.
    pub fn import_process_stream_recovery_suspended(
        &self,
        projection: &ProcessStreamRecoveryProjection,
    ) -> Result<ProcessStreamRecoveryWriteOutcome, OrsError> {
        projection.validate()?;
        let imported = if projection.activation == StreamRecoveryActivation::Retired {
            projection.clone()
        } else {
            projection.with_activation(StreamRecoveryActivation::Suspended)?
        };
        self.put_process_stream_recovery(&imported)
    }

    /// Maps a codec failure onto its explicit recovery disposition.
    fn stream_recovery_load_error(error: OrsError) -> ProcessStreamRecoveryLoadError {
        match error {
            OrsError::UnsupportedContractVersion(found) => {
                ProcessStreamRecoveryLoadError::CodecVersionMismatch {
                    found,
                    current: crate::CONTRACT_VERSION,
                }
            }
            other => Self::stream_recovery_read_error(&other),
        }
    }

    /// Maps any storage or read failure onto the interrupted-read disposition.
    fn stream_recovery_read_error(error: &OrsError) -> ProcessStreamRecoveryLoadError {
        ProcessStreamRecoveryLoadError::InterruptedRead {
            reason: error.to_string(),
        }
    }

    fn supervision_ticket_matches_prepare(
        ticket: &SupervisionLeaseCommitTicket,
        request: &SupervisionLeasePrepareRequest,
    ) -> bool {
        ticket.ticket_id == request.ticket_id
            && ticket.operation_id == request.operation_id
            && ticket.lease_id == request.lease_id
            && ticket.expected_revision == request.expected_revision
            && ticket.operation == request.operation
            && ticket.binding == request.binding
    }

    fn supervision_stage_is_expired(stage: &SupervisionLeaseStageReceipt, now_ms: u64) -> bool {
        matches!(
            stage.ticket.operation,
            crate::SupervisionLeaseOperation::Commit | crate::SupervisionLeaseOperation::Renew
        ) && now_ms >= stage.ticket.binding.expires_at_ms
    }

    fn supervision_result_in_write(
        write: &redb::WriteTransaction,
        ticket_id: &crate::OperationIdentity,
    ) -> Result<Option<DurableSupervisionLeaseResult>, OrsError> {
        let results = write
            .open_table(SUPERVISION_LEASE_RESULTS)
            .map_err(storage)?;
        results
            .get(ticket_id.as_str())
            .map_err(storage)?
            .map(|value| {
                decode_named::<DurableSupervisionLeaseResult>(
                    value.value(),
                    "supervision_lease_result",
                )
            })
            .transpose()
    }

    fn supervision_resolution_in_write(
        write: &redb::WriteTransaction,
        ticket_id: &crate::OperationIdentity,
    ) -> Result<Option<SupervisionLeaseStageResolution>, OrsError> {
        let resolutions = write
            .open_table(SUPERVISION_LEASE_STAGE_RESOLUTIONS)
            .map_err(storage)?;
        resolutions
            .get(ticket_id.as_str())
            .map_err(storage)?
            .map(|value| {
                decode_named::<SupervisionLeaseStageResolution>(
                    value.value(),
                    "supervision_lease_stage_resolution",
                )
            })
            .transpose()
    }

    fn resolve_supervision_stage_in_write(
        write: &redb::WriteTransaction,
        stage: &SupervisionLeaseStageReceipt,
        disposition: SupervisionLeaseStageResolutionDisposition,
        resolved_at_ms: u64,
        reason: OpaqueLabel,
    ) -> Result<SupervisionLeaseStageResolution, OrsError> {
        stage.validate()?;
        if let Some(result) = Self::supervision_result_in_write(write, &stage.ticket.ticket_id)? {
            return if result.ticket == stage.ticket {
                Err(OrsError::SupervisionLeaseTicketAlreadyCommitted)
            } else {
                Err(OrsError::SupervisionLeaseTicketConflict)
            };
        }
        if let Some(existing) =
            Self::supervision_resolution_in_write(write, &stage.ticket.ticket_id)?
        {
            if existing.ticket == stage.ticket
                && existing.ticket_sha256 == stage.ticket_sha256
                && existing.disposition == disposition
                && existing.reason == reason
            {
                return Ok(existing);
            }
            return Err(OrsError::SupervisionLeaseTicketConflict);
        }
        let durable_stage = {
            let staged = write
                .open_table(SUPERVISION_LEASE_STAGED)
                .map_err(storage)?;
            staged
                .get(stage.ticket.lease_id.as_str())
                .map_err(storage)?
                .map(|value| {
                    decode_named::<SupervisionLeaseStageReceipt>(
                        value.value(),
                        "supervision_lease_staged",
                    )
                })
                .transpose()?
        }
        .ok_or(OrsError::SupervisionLeaseTicketNotStaged)?;
        if durable_stage != *stage {
            return Err(OrsError::SupervisionLeaseTicketConflict);
        }
        let resolution = SupervisionLeaseStageResolution::issue(
            stage.ticket.clone(),
            disposition,
            resolved_at_ms,
            Self::next_operational_order(write)?,
            reason,
        )?;
        {
            let encoded = encode(&resolution)?;
            let mut resolutions = write
                .open_table(SUPERVISION_LEASE_STAGE_RESOLUTIONS)
                .map_err(storage)?;
            if resolutions
                .insert(resolution.ticket.ticket_id.as_str(), encoded.as_str())
                .map_err(storage)?
                .is_some()
            {
                return Err(OrsError::SupervisionLeaseTicketConflict);
            }
        }
        {
            let mut staged = write
                .open_table(SUPERVISION_LEASE_STAGED)
                .map_err(storage)?;
            if staged
                .remove(stage.ticket.lease_id.as_str())
                .map_err(storage)?
                .is_none()
            {
                return Err(OrsError::SupervisionLeaseTicketNotStaged);
            }
        }
        Ok(resolution)
    }

    /// Reserves one supervision-lease revision and its canonical receipt
    /// preimage.  This method never accepts a caller-supplied revision or
    /// operation order and never publishes an authoritative lease.
    #[allow(
        clippy::too_many_lines,
        reason = "one ORS write transaction reserves the revision, receipt preimage and staged row"
    )]
    pub fn prepare_supervision_lease(
        &self,
        request: SupervisionLeasePrepareRequest,
    ) -> Result<SupervisionLeaseStageReceipt, OrsError> {
        request.validate()?;
        let write = self.database.begin_write().map_err(storage)?;
        if let Some(result) = Self::supervision_result_in_write(&write, &request.ticket_id)? {
            return if Self::supervision_ticket_matches_prepare(&result.ticket, &request) {
                Err(OrsError::SupervisionLeaseTicketAlreadyCommitted)
            } else {
                Err(OrsError::SupervisionLeaseTicketConflict)
            };
        }
        if let Some(resolution) = Self::supervision_resolution_in_write(&write, &request.ticket_id)?
        {
            return if Self::supervision_ticket_matches_prepare(&resolution.ticket, &request) {
                Err(OrsError::SupervisionLeaseTicketResolved)
            } else {
                Err(OrsError::SupervisionLeaseTicketConflict)
            };
        }
        let existing_stage = {
            let staged = write
                .open_table(SUPERVISION_LEASE_STAGED)
                .map_err(storage)?;
            staged
                .get(request.lease_id.as_str())
                .map_err(storage)?
                .map(|value| {
                    decode_named::<SupervisionLeaseStageReceipt>(
                        value.value(),
                        "supervision_lease_staged",
                    )
                })
                .transpose()?
        };
        if let Some(stage) = existing_stage {
            stage.validate()?;
            let same_request = Self::supervision_ticket_matches_prepare(&stage.ticket, &request);
            let now_ms = current_unix_ms_u64()?;
            if Self::supervision_stage_is_expired(&stage, now_ms) {
                Self::resolve_supervision_stage_in_write(
                    &write,
                    &stage,
                    SupervisionLeaseStageResolutionDisposition::Expired,
                    now_ms,
                    OpaqueLabel::new("active-ticket-window-elapsed")?,
                )?;
                if stage.ticket.ticket_id == request.ticket_id {
                    write.commit().map_err(storage)?;
                    return Err(if same_request {
                        OrsError::SupervisionLeaseTicketResolved
                    } else {
                        OrsError::SupervisionLeaseTicketConflict
                    });
                }
            } else if !same_request {
                return Err(OrsError::SupervisionLeaseTicketConflict);
            } else {
                write.commit().map_err(storage)?;
                return Ok(stage);
            }
        }

        // Ticket ids are global replay identities. The primary staged table
        // is lease-keyed, so scan its live set before allocating a second
        // lease under the same ticket id.
        {
            let staged = write
                .open_table(SUPERVISION_LEASE_STAGED)
                .map_err(storage)?;
            for row in staged.iter().map_err(storage)? {
                let (_, value) = row.map_err(storage)?;
                let stage: SupervisionLeaseStageReceipt =
                    decode_named(value.value(), "supervision_lease_staged")?;
                if stage.ticket.ticket_id == request.ticket_id {
                    return Err(OrsError::SupervisionLeaseTicketConflict);
                }
            }
        }
        if matches!(
            request.operation,
            crate::SupervisionLeaseOperation::Commit | crate::SupervisionLeaseOperation::Renew
        ) && current_unix_ms_u64()? >= request.binding.expires_at_ms
        {
            return Err(OrsError::SupervisionLeaseTicketExpired);
        }

        let current = {
            let table = write
                .open_table(SUPERVISION_LEASE_CURRENT)
                .map_err(storage)?;
            table
                .get(request.lease_id.as_str())
                .map_err(storage)?
                .map(|value| {
                    let snapshot: SupervisionLeaseSnapshot =
                        decode_named(value.value(), "supervision_lease_current")?;
                    snapshot.validate()?;
                    if snapshot.record.lease_id != request.lease_id {
                        return Err(OrsError::IntegrityProblem {
                            record_type: "supervision_lease_current",
                            reason: "current key does not match lease identity".to_owned(),
                        });
                    }
                    Ok(snapshot)
                })
                .transpose()?
        };
        let prior_state = current.as_ref().map(|snapshot| snapshot.record.state);
        match (current.as_ref(), request.expected_revision) {
            (None, None) => {}
            (Some(snapshot), Some(expected)) if snapshot.record.revision == expected => {}
            _ => return Err(OrsError::SupervisionLeaseStaleRevision),
        }
        if !request.operation.allowed_from(prior_state) {
            return Err(OrsError::InvalidTransition);
        }
        if current
            .as_ref()
            .is_some_and(|snapshot| !snapshot.record.binding.same_lineage_as(&request.binding))
        {
            return Err(OrsError::SupervisionLeaseBindingMismatch);
        }
        let revision = request
            .expected_revision
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| OrsError::IntegrityProblem {
                record_type: "supervision_lease_ticket",
                reason: "revision counter exhausted".to_owned(),
            })?;
        let record_id = crate::OperationIdentity::new(format!(
            "{}::r{:020}",
            request.lease_id.as_str(),
            revision
        ))?;
        let previous_receipt_sha256 = current
            .as_ref()
            .map(|snapshot| snapshot.receipt.receipt_sha256.clone());
        let ticket = SupervisionLeaseCommitTicket {
            ticket_id: request.ticket_id,
            operation_id: request.operation_id,
            lease_id: request.lease_id,
            record_id,
            expected_revision: request.expected_revision,
            revision,
            operation: request.operation,
            binding: request.binding,
            previous_receipt_sha256,
            reservation_order: Self::next_operational_order(&write)?,
        };
        ticket.validate()?;
        let ticket_sha256 = ticket.ticket_sha256()?;
        let stage = SupervisionLeaseStageReceipt {
            ticket,
            ticket_sha256,
            projection: SupervisionLeaseProjection::Staged,
        };
        stage.validate()?;
        {
            let mut staged = write
                .open_table(SUPERVISION_LEASE_STAGED)
                .map_err(storage)?;
            let encoded = encode(&stage)?;
            staged
                .insert(stage.ticket.lease_id.as_str(), encoded.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(stage)
    }

    /// Commits an active revision using the existing active/time-valid
    /// trust-anchor verification boundary.
    pub fn commit_supervision_lease(
        &self,
        ticket: &SupervisionLeaseCommitTicket,
        verified: &VerifiedSupervisionLease,
    ) -> Result<SupervisionLeaseSnapshot, OrsError> {
        if !matches!(
            ticket.operation,
            crate::SupervisionLeaseOperation::Commit | crate::SupervisionLeaseOperation::Renew
        ) {
            return Err(OrsError::InvalidTransition);
        }
        let artifact = signed_supervision_lease_from_verified(verified)?;
        self.commit_supervision_lease_artifact(ticket, artifact, None)
    }

    /// Replays an already linearized supervision-lease commit without asking
    /// the producer to sign the same revision again.
    ///
    /// The result row is written in the same redb transaction as the current
    /// and history projections.  A matching row is therefore authoritative
    /// evidence that the commit crossed the ORS linearization point even when
    /// the original caller lost its response.  A mismatching row is treated as
    /// a durable conflict rather than being interpreted as a caller retry.
    pub fn replay_supervision_lease_commit(
        &self,
        ticket: &SupervisionLeaseCommitTicket,
    ) -> Result<Option<SupervisionLeaseSnapshot>, OrsError> {
        let expected_ticket_sha256 = ticket.ticket_sha256()?;
        let read = self.database.begin_read().map_err(storage)?;
        let results = read
            .open_table(SUPERVISION_LEASE_RESULTS)
            .map_err(storage)?;
        let result = results
            .get(ticket.ticket_id.as_str())
            .map_err(storage)?
            .map(|value| {
                decode_named::<DurableSupervisionLeaseResult>(
                    value.value(),
                    "supervision_lease_result",
                )
            })
            .transpose()?;
        let Some(result) = result else {
            let resolutions = read
                .open_table(SUPERVISION_LEASE_STAGE_RESOLUTIONS)
                .map_err(storage)?;
            let resolution = resolutions
                .get(ticket.ticket_id.as_str())
                .map_err(storage)?
                .map(|value| {
                    decode_named::<SupervisionLeaseStageResolution>(
                        value.value(),
                        "supervision_lease_stage_resolution",
                    )
                })
                .transpose()?;
            return match resolution {
                Some(resolution) if resolution.ticket == *ticket => {
                    Err(OrsError::SupervisionLeaseTicketResolved)
                }
                Some(_) => Err(OrsError::SupervisionLeaseTicketConflict),
                None => Ok(None),
            };
        };
        result.snapshot.validate()?;
        if result.ticket != *ticket
            || result.snapshot.record.ticket_sha256 != expected_ticket_sha256
            || result.artifact != result.snapshot.record.artifact
        {
            return Err(OrsError::SupervisionLeaseTicketConflict);
        }
        drop(read);
        let current = self
            .load_current_supervision_lease(&ticket.lease_id)?
            .ok_or(OrsError::IntegrityProblem {
                record_type: "supervision_lease_current",
                reason: "durable commit result has no current projection".to_owned(),
            })?;
        if current != result.snapshot {
            return Err(OrsError::IntegrityProblem {
                record_type: "supervision_lease_current",
                reason: "durable current projection disagrees with commit result".to_owned(),
            });
        }
        Ok(Some(result.snapshot))
    }

    /// Commits a terminal revision only from a sealed transition token whose
    /// active predecessor is compared with the current durable ORS snapshot.
    pub fn commit_terminal_supervision_lease(
        &self,
        ticket: &SupervisionLeaseCommitTicket,
        verified: &VerifiedSupervisionLeaseTerminalTransition,
    ) -> Result<SupervisionLeaseSnapshot, OrsError> {
        if matches!(
            ticket.operation,
            crate::SupervisionLeaseOperation::Commit | crate::SupervisionLeaseOperation::Renew
        ) {
            return Err(OrsError::InvalidTransition);
        }
        let artifact = signed_terminal_supervision_lease_from_verified(verified)?;
        self.commit_supervision_lease_artifact(ticket, artifact, Some(verified))
    }

    /// The current revision, history row, replay row and stage removal are one
    /// local redb transaction. A durable no-commit resolution is consulted in
    /// the same database before absence can be interpreted as unstaged.
    #[allow(
        clippy::too_many_lines,
        reason = "one ORS write transaction atomically promotes current, history and replay state"
    )]
    fn commit_supervision_lease_artifact(
        &self,
        ticket: &SupervisionLeaseCommitTicket,
        artifact: SignedSupervisionLease,
        terminal: Option<&VerifiedSupervisionLeaseTerminalTransition>,
    ) -> Result<SupervisionLeaseSnapshot, OrsError> {
        ticket.validate()?;
        let ticket_sha256 = ticket.ticket_sha256()?;
        let expected = ticket.expected_payload()?;
        if artifact.payload != expected {
            return Err(OrsError::SupervisionLeaseBindingMismatch);
        }
        let write = self.database.begin_write().map_err(storage)?;
        let stage = {
            let staged = write
                .open_table(SUPERVISION_LEASE_STAGED)
                .map_err(storage)?;
            staged
                .get(ticket.lease_id.as_str())
                .map_err(storage)?
                .map(|value| {
                    decode_named::<SupervisionLeaseStageReceipt>(
                        value.value(),
                        "supervision_lease_staged",
                    )
                })
                .transpose()?
        };
        let Some(stage) = stage else {
            if let Some(result) = Self::supervision_result_in_write(&write, &ticket.ticket_id)? {
                result.snapshot.validate()?;
                if result.ticket != *ticket || result.artifact != artifact {
                    return Err(OrsError::SupervisionLeaseTicketConflict);
                }
                write.commit().map_err(storage)?;
                return Ok(result.snapshot);
            }
            if let Some(resolution) =
                Self::supervision_resolution_in_write(&write, &ticket.ticket_id)?
            {
                return if resolution.ticket == *ticket && resolution.ticket_sha256 == ticket_sha256
                {
                    Err(OrsError::SupervisionLeaseTicketResolved)
                } else {
                    Err(OrsError::SupervisionLeaseTicketConflict)
                };
            }
            return Err(OrsError::SupervisionLeaseTicketNotStaged);
        };
        stage.validate()?;
        if stage.ticket != *ticket || stage.ticket_sha256 != ticket_sha256 {
            return Err(OrsError::SupervisionLeaseTicketConflict);
        }
        if let Some(resolution) = Self::supervision_resolution_in_write(&write, &ticket.ticket_id)?
        {
            return Err(if resolution.ticket == *ticket {
                OrsError::IntegrityProblem {
                    record_type: "supervision_lease_staged",
                    reason: "ticket is both staged and durably resolved".to_owned(),
                }
            } else {
                OrsError::SupervisionLeaseTicketConflict
            });
        }
        let commit_now_ms = current_unix_ms_u64()?;
        if terminal.is_none() && Self::supervision_stage_is_expired(&stage, commit_now_ms) {
            Self::resolve_supervision_stage_in_write(
                &write,
                &stage,
                SupervisionLeaseStageResolutionDisposition::Expired,
                commit_now_ms,
                OpaqueLabel::new("active-ticket-window-elapsed")?,
            )?;
            write.commit().map_err(storage)?;
            return Err(OrsError::SupervisionLeaseTicketResolved);
        }
        let current = {
            let current = write
                .open_table(SUPERVISION_LEASE_CURRENT)
                .map_err(storage)?;
            current
                .get(ticket.lease_id.as_str())
                .map_err(storage)?
                .map(|value| {
                    let snapshot = decode_named::<SupervisionLeaseSnapshot>(
                        value.value(),
                        "supervision_lease_current",
                    )?;
                    snapshot
                        .validate()
                        .map_err(|error| OrsError::IntegrityProblem {
                            record_type: "supervision_lease_current",
                            reason: error.to_string(),
                        })?;
                    if snapshot.record.lease_id != ticket.lease_id {
                        return Err(OrsError::IntegrityProblem {
                            record_type: "supervision_lease_current",
                            reason: "current key does not match lease identity".to_owned(),
                        });
                    }
                    Ok(snapshot)
                })
                .transpose()?
        };
        match (current.as_ref(), ticket.expected_revision) {
            (None, None) => {}
            (Some(snapshot), Some(expected)) if snapshot.record.revision == expected => {}
            _ => return Err(OrsError::SupervisionLeaseStaleRevision),
        }
        if !ticket
            .operation
            .allowed_from(current.as_ref().map(|snapshot| snapshot.record.state))
        {
            return Err(OrsError::InvalidTransition);
        }
        if current
            .as_ref()
            .is_some_and(|snapshot| !snapshot.record.binding.same_lineage_as(&ticket.binding))
        {
            return Err(OrsError::SupervisionLeaseBindingMismatch);
        }
        if let Some(terminal) = terminal {
            Self::validate_terminal_supervision_predecessor(ticket, current.as_ref(), terminal)?;
        }
        let artifact_sha256 = artifact
            .envelope_digest()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        let operation_order = Self::next_operational_order(&write)?;
        let previous_receipt_sha256 = match ticket.previous_receipt_sha256.as_ref() {
            Some(expected_previous) => {
                let current = current
                    .as_ref()
                    .ok_or(OrsError::SupervisionLeaseStaleRevision)?;
                if current.receipt.receipt_sha256 != *expected_previous {
                    return Err(OrsError::SupervisionLeaseStaleRevision);
                }
                Some(current.receipt.receipt_sha256.clone())
            }
            None => None,
        };
        let receipt = SupervisionLeaseReceipt::issue(SupervisionLeaseReceiptInput {
            ticket_id: ticket.ticket_id.clone(),
            operation_id: ticket.operation_id.clone(),
            record_id: ticket.record_id.clone(),
            lease_id: ticket.lease_id.clone(),
            revision: ticket.revision,
            operation: ticket.operation,
            state: ticket.binding.state,
            operation_order,
            ticket_sha256: ticket_sha256.clone(),
            artifact_sha256,
            previous_receipt_sha256,
        })?;
        let record = SupervisionLeaseRecord {
            ticket_id: ticket.ticket_id.clone(),
            operation_id: ticket.operation_id.clone(),
            record_id: ticket.record_id.clone(),
            lease_id: ticket.lease_id.clone(),
            revision: ticket.revision,
            operation: ticket.operation,
            state: ticket.binding.state,
            projection: SupervisionLeaseProjection::for_state(ticket.binding.state),
            binding: ticket.binding.clone(),
            previous_receipt_sha256: ticket.previous_receipt_sha256.clone(),
            ticket_sha256,
            operation_order,
            artifact,
            receipt_sha256: receipt.receipt_sha256.clone(),
        };
        let snapshot = SupervisionLeaseSnapshot { record, receipt };
        snapshot.validate()?;
        let result = DurableSupervisionLeaseResult {
            ticket: ticket.clone(),
            artifact: snapshot.record.artifact.clone(),
            snapshot: snapshot.clone(),
        };
        Self::persist_supervision_snapshot(&write, &snapshot, &result)?;
        {
            let mut staged = write
                .open_table(SUPERVISION_LEASE_STAGED)
                .map_err(storage)?;
            staged.remove(ticket.lease_id.as_str()).map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(snapshot)
    }

    fn validate_terminal_supervision_predecessor(
        ticket: &SupervisionLeaseCommitTicket,
        current: Option<&SupervisionLeaseSnapshot>,
        terminal: &VerifiedSupervisionLeaseTerminalTransition,
    ) -> Result<(), OrsError> {
        let current = current.ok_or(OrsError::SupervisionLeaseBindingMismatch)?;
        let predecessor = terminal.predecessor();
        let prior_artifact = signed_supervision_lease_from_verified(terminal.prior_active())?;
        let prior_artifact_sha256 = prior_artifact
            .envelope_digest()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        if current.record.state != eliot_runtime_contracts::LeaseState::Active
            || current.record.projection != SupervisionLeaseProjection::Active
            || current.record.lease_id.as_str() != predecessor.lease_id
            || current.record.record_id.as_str() != predecessor.record_id
            || current.record.revision != predecessor.lease_revision
            || current.receipt.receipt_sha256 != predecessor.receipt_sha256
            || current.record.artifact != prior_artifact
            || prior_artifact_sha256 != predecessor.envelope_sha256
            || ticket.lease_id.as_str() != predecessor.lease_id
            || ticket.expected_revision != Some(predecessor.lease_revision)
            || ticket.previous_receipt_sha256.as_deref()
                != Some(predecessor.receipt_sha256.as_str())
        {
            return Err(OrsError::SupervisionLeaseBindingMismatch);
        }
        Ok(())
    }

    /// Durably resolves one exact elapsed active ticket without publishing a
    /// signed lease. The resolution and stage removal share one redb commit,
    /// and an exact retry returns the immutable prior resolution.
    pub fn expire_staged_supervision_lease(
        &self,
        ticket: &SupervisionLeaseCommitTicket,
    ) -> Result<SupervisionLeaseStageResolution, OrsError> {
        ticket.validate()?;
        let write = self.database.begin_write().map_err(storage)?;
        if let Some(result) = Self::supervision_result_in_write(&write, &ticket.ticket_id)? {
            return if result.ticket == *ticket {
                Err(OrsError::SupervisionLeaseTicketAlreadyCommitted)
            } else {
                Err(OrsError::SupervisionLeaseTicketConflict)
            };
        }
        if let Some(resolution) = Self::supervision_resolution_in_write(&write, &ticket.ticket_id)?
        {
            return if resolution.ticket != *ticket {
                Err(OrsError::SupervisionLeaseTicketConflict)
            } else if resolution.disposition == SupervisionLeaseStageResolutionDisposition::Expired
            {
                write.commit().map_err(storage)?;
                Ok(resolution)
            } else {
                Err(OrsError::SupervisionLeaseTicketResolved)
            };
        }
        let stage = {
            let staged = write
                .open_table(SUPERVISION_LEASE_STAGED)
                .map_err(storage)?;
            staged
                .get(ticket.lease_id.as_str())
                .map_err(storage)?
                .map(|value| {
                    decode_named::<SupervisionLeaseStageReceipt>(
                        value.value(),
                        "supervision_lease_staged",
                    )
                })
                .transpose()?
        }
        .ok_or(OrsError::SupervisionLeaseTicketNotStaged)?;
        if stage.ticket != *ticket || stage.ticket_sha256 != ticket.ticket_sha256()? {
            return Err(OrsError::SupervisionLeaseTicketConflict);
        }
        let now_ms = current_unix_ms_u64()?;
        if !Self::supervision_stage_is_expired(&stage, now_ms) {
            return Err(OrsError::SupervisionLeaseTicketNotExpired);
        }
        let resolution = Self::resolve_supervision_stage_in_write(
            &write,
            &stage,
            SupervisionLeaseStageResolutionDisposition::Expired,
            now_ms,
            OpaqueLabel::new("active-ticket-window-elapsed")?,
        )?;
        write.commit().map_err(storage)?;
        Ok(resolution)
    }

    /// Explicitly aborts one exact pre-commit stage. This is never called by
    /// protected-key failure recovery: an unknown signer/provider outcome
    /// must leave the stage available for exact resume.
    pub fn abort_staged_supervision_lease(
        &self,
        ticket: &SupervisionLeaseCommitTicket,
        reason: OpaqueLabel,
    ) -> Result<SupervisionLeaseStageResolution, OrsError> {
        ticket.validate()?;
        let write = self.database.begin_write().map_err(storage)?;
        if let Some(result) = Self::supervision_result_in_write(&write, &ticket.ticket_id)? {
            return if result.ticket == *ticket {
                Err(OrsError::SupervisionLeaseTicketAlreadyCommitted)
            } else {
                Err(OrsError::SupervisionLeaseTicketConflict)
            };
        }
        if let Some(resolution) = Self::supervision_resolution_in_write(&write, &ticket.ticket_id)?
        {
            return if resolution.ticket != *ticket {
                Err(OrsError::SupervisionLeaseTicketConflict)
            } else if (resolution.disposition
                == SupervisionLeaseStageResolutionDisposition::Aborted
                && resolution.reason == reason)
                || resolution.disposition == SupervisionLeaseStageResolutionDisposition::Expired
            {
                write.commit().map_err(storage)?;
                Ok(resolution)
            } else {
                Err(OrsError::SupervisionLeaseTicketResolved)
            };
        }
        let stage = {
            let staged = write
                .open_table(SUPERVISION_LEASE_STAGED)
                .map_err(storage)?;
            staged
                .get(ticket.lease_id.as_str())
                .map_err(storage)?
                .map(|value| {
                    decode_named::<SupervisionLeaseStageReceipt>(
                        value.value(),
                        "supervision_lease_staged",
                    )
                })
                .transpose()?
        }
        .ok_or(OrsError::SupervisionLeaseTicketNotStaged)?;
        if stage.ticket != *ticket || stage.ticket_sha256 != ticket.ticket_sha256()? {
            return Err(OrsError::SupervisionLeaseTicketConflict);
        }
        let resolved_at_ms = current_unix_ms_u64()?;
        if Self::supervision_stage_is_expired(&stage, resolved_at_ms) {
            let resolution = Self::resolve_supervision_stage_in_write(
                &write,
                &stage,
                SupervisionLeaseStageResolutionDisposition::Expired,
                resolved_at_ms,
                OpaqueLabel::new("active-ticket-window-elapsed")?,
            )?;
            write.commit().map_err(storage)?;
            return Ok(resolution);
        }
        let resolution = Self::resolve_supervision_stage_in_write(
            &write,
            &stage,
            SupervisionLeaseStageResolutionDisposition::Aborted,
            resolved_at_ms,
            reason,
        )?;
        write.commit().map_err(storage)?;
        Ok(resolution)
    }

    /// Reads an exact durable no-commit resolution. A reused ticket id with a
    /// different ticket is a conflict, never a cache miss.
    pub fn load_supervision_lease_stage_resolution(
        &self,
        ticket: &SupervisionLeaseCommitTicket,
    ) -> Result<Option<SupervisionLeaseStageResolution>, OrsError> {
        ticket.validate()?;
        let read = self.database.begin_read().map_err(storage)?;
        let resolutions = read
            .open_table(SUPERVISION_LEASE_STAGE_RESOLUTIONS)
            .map_err(storage)?;
        let resolution = resolutions
            .get(ticket.ticket_id.as_str())
            .map_err(storage)?
            .map(|value| {
                decode_named::<SupervisionLeaseStageResolution>(
                    value.value(),
                    "supervision_lease_stage_resolution",
                )
            })
            .transpose()?;
        match resolution {
            Some(resolution)
                if resolution.ticket == *ticket
                    && resolution.ticket_sha256 == ticket.ticket_sha256()? =>
            {
                Ok(Some(resolution))
            }
            Some(_) => Err(OrsError::SupervisionLeaseTicketConflict),
            None => Ok(None),
        }
    }

    /// Reconciles one exact ticket across all durable ORS outcomes.
    ///
    /// A live stage is returned unchanged for exact signer resume. An elapsed
    /// active stage is atomically replaced by its immutable expiry resolution.
    /// A committed result or prior no-commit resolution is returned as that
    /// exact durable outcome. Unknown tickets remain `None`; no outcome is
    /// guessed and no stage is aborted because a signer is unavailable.
    pub fn reconcile_supervision_lease_ticket(
        &self,
        ticket: &SupervisionLeaseCommitTicket,
    ) -> Result<Option<SupervisionLeaseTicketReconciliation>, OrsError> {
        ticket.validate()?;
        let write = self.database.begin_write().map_err(storage)?;
        let result = Self::supervision_result_in_write(&write, &ticket.ticket_id)?;
        let resolution = Self::supervision_resolution_in_write(&write, &ticket.ticket_id)?;
        let stage = {
            let staged = write
                .open_table(SUPERVISION_LEASE_STAGED)
                .map_err(storage)?;
            staged
                .get(ticket.lease_id.as_str())
                .map_err(storage)?
                .map(|value| {
                    decode_named::<SupervisionLeaseStageReceipt>(
                        value.value(),
                        "supervision_lease_staged",
                    )
                })
                .transpose()?
        };
        let stage_reuses_ticket = stage
            .as_ref()
            .is_some_and(|stage| stage.ticket.ticket_id == ticket.ticket_id);
        if result.is_some() && (resolution.is_some() || stage_reuses_ticket)
            || resolution.is_some() && stage_reuses_ticket
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "supervision_lease_ticket_reconciliation",
                reason: "ticket has multiple durable outcomes".to_owned(),
            });
        }
        if let Some(result) = result {
            result.snapshot.validate()?;
            if result.ticket != *ticket
                || result.artifact != result.snapshot.record.artifact
                || result.snapshot.record.ticket_sha256 != ticket.ticket_sha256()?
            {
                return Err(OrsError::SupervisionLeaseTicketConflict);
            }
            write.commit().map_err(storage)?;
            return Ok(Some(SupervisionLeaseTicketReconciliation::Committed(
                Box::new(result.snapshot),
            )));
        }
        if let Some(resolution) = resolution {
            if resolution.ticket != *ticket || resolution.ticket_sha256 != ticket.ticket_sha256()? {
                return Err(OrsError::SupervisionLeaseTicketConflict);
            }
            write.commit().map_err(storage)?;
            return Ok(Some(SupervisionLeaseTicketReconciliation::Resolved(
                resolution,
            )));
        }
        let Some(stage) = stage else {
            write.commit().map_err(storage)?;
            return Ok(None);
        };
        stage.validate()?;
        if stage.ticket != *ticket || stage.ticket_sha256 != ticket.ticket_sha256()? {
            return Err(OrsError::SupervisionLeaseTicketConflict);
        }
        let now_ms = current_unix_ms_u64()?;
        if Self::supervision_stage_is_expired(&stage, now_ms) {
            let resolution = Self::resolve_supervision_stage_in_write(
                &write,
                &stage,
                SupervisionLeaseStageResolutionDisposition::Expired,
                now_ms,
                OpaqueLabel::new("active-ticket-window-elapsed")?,
            )?;
            write.commit().map_err(storage)?;
            return Ok(Some(SupervisionLeaseTicketReconciliation::Resolved(
                resolution,
            )));
        }
        write.commit().map_err(storage)?;
        Ok(Some(SupervisionLeaseTicketReconciliation::Staged(stage)))
    }

    /// Returns an interrupted staged ticket without promoting it. An elapsed
    /// active stage is atomically resolved first and therefore returns `None`.
    pub fn reconcile_staged_supervision_lease(
        &self,
        lease_id: &crate::OperationIdentity,
    ) -> Result<Option<SupervisionLeaseStageReceipt>, OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        let stage = {
            let staged = write
                .open_table(SUPERVISION_LEASE_STAGED)
                .map_err(storage)?;
            staged
                .get(lease_id.as_str())
                .map_err(storage)?
                .map(|value| {
                    let stage: SupervisionLeaseStageReceipt =
                        decode_named(value.value(), "supervision_lease_staged")?;
                    stage.validate()?;
                    if stage.ticket.lease_id != *lease_id {
                        return Err(OrsError::IntegrityProblem {
                            record_type: "supervision_lease_staged",
                            reason: "staged key does not match lease identity".to_owned(),
                        });
                    }
                    Ok(stage)
                })
                .transpose()?
        };
        let Some(stage) = stage else {
            write.commit().map_err(storage)?;
            return Ok(None);
        };
        if Self::supervision_result_in_write(&write, &stage.ticket.ticket_id)?.is_some()
            || Self::supervision_resolution_in_write(&write, &stage.ticket.ticket_id)?.is_some()
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "supervision_lease_staged",
                reason: "staged ticket also has a durable terminal disposition".to_owned(),
            });
        }
        let now_ms = current_unix_ms_u64()?;
        if Self::supervision_stage_is_expired(&stage, now_ms) {
            Self::resolve_supervision_stage_in_write(
                &write,
                &stage,
                SupervisionLeaseStageResolutionDisposition::Expired,
                now_ms,
                OpaqueLabel::new("active-ticket-window-elapsed")?,
            )?;
            write.commit().map_err(storage)?;
            return Ok(None);
        }
        write.commit().map_err(storage)?;
        Ok(Some(stage))
    }

    /// Reconciles a bounded set of staged tickets for recovery. Elapsed active
    /// tickets are durably resolved in this local ORS; all other stages remain
    /// exact resume obligations for the Kernel signer.
    pub fn reconcile_staged_supervision_leases(
        &self,
        limit: u16,
    ) -> Result<Vec<SupervisionLeaseStageReceipt>, OrsError> {
        if limit == 0 || limit > crate::MAX_RECOVERY_PAGE {
            return Err(OrsError::InvalidSupervisionLeaseHistoryLimit);
        }
        let write = self.database.begin_write().map_err(storage)?;
        let mut stage_receipts = Vec::new();
        {
            let staged = write
                .open_table(SUPERVISION_LEASE_STAGED)
                .map_err(storage)?;
            for row in staged.iter().map_err(storage)? {
                let (key, value) = row.map_err(storage)?;
                let stage: SupervisionLeaseStageReceipt =
                    decode_named(value.value(), "supervision_lease_staged")?;
                stage.validate()?;
                if key.value() != stage.ticket.lease_id.as_str() {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "supervision_lease_staged",
                        reason: "staged key does not match lease identity".to_owned(),
                    });
                }
                stage_receipts.push(stage);
                if stage_receipts.len() == usize::from(limit) {
                    break;
                }
            }
        }
        stage_receipts.sort_by_key(|stage| stage.ticket.reservation_order);
        let now_ms = current_unix_ms_u64()?;
        let mut pending = Vec::with_capacity(stage_receipts.len());
        for stage in stage_receipts {
            if Self::supervision_result_in_write(&write, &stage.ticket.ticket_id)?.is_some()
                || Self::supervision_resolution_in_write(&write, &stage.ticket.ticket_id)?.is_some()
            {
                return Err(OrsError::IntegrityProblem {
                    record_type: "supervision_lease_staged",
                    reason: "staged ticket also has a durable terminal disposition".to_owned(),
                });
            }
            if Self::supervision_stage_is_expired(&stage, now_ms) {
                Self::resolve_supervision_stage_in_write(
                    &write,
                    &stage,
                    SupervisionLeaseStageResolutionDisposition::Expired,
                    now_ms,
                    OpaqueLabel::new("active-ticket-window-elapsed")?,
                )?;
            } else {
                pending.push(stage);
            }
        }
        write.commit().map_err(storage)?;
        Ok(pending)
    }

    /// Reads the current authoritative committed projection for a lease.
    pub fn load_current_supervision_lease(
        &self,
        lease_id: &crate::OperationIdentity,
    ) -> Result<Option<SupervisionLeaseSnapshot>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let current = read
            .open_table(SUPERVISION_LEASE_CURRENT)
            .map_err(storage)?;
        current
            .get(lease_id.as_str())
            .map_err(storage)?
            .map(|value| {
                let snapshot: SupervisionLeaseSnapshot =
                    decode_named(value.value(), "supervision_lease_current")?;
                snapshot.validate()?;
                if snapshot.record.lease_id != *lease_id {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "supervision_lease_current",
                        reason: "current key does not match lease identity".to_owned(),
                    });
                }
                Ok(snapshot)
            })
            .transpose()
    }

    /// Reads newest-first bounded committed history for one lease.
    pub fn load_supervision_lease_history(
        &self,
        lease_id: &crate::OperationIdentity,
        limit: u16,
    ) -> Result<Vec<SupervisionLeaseSnapshot>, OrsError> {
        if limit == 0 || limit > crate::MAX_RECOVERY_PAGE {
            return Err(OrsError::InvalidSupervisionLeaseHistoryLimit);
        }
        let read = self.database.begin_read().map_err(storage)?;
        let history = read
            .open_table(SUPERVISION_LEASE_HISTORY)
            .map_err(storage)?;
        let prefix = format!("{}::", Self::encode_key_component(lease_id.as_str()));
        let mut snapshots = Vec::new();
        for row in history.range(prefix.as_str()..).map_err(storage)? {
            let (key, value) = row.map_err(storage)?;
            if !key.value().starts_with(prefix.as_str()) {
                break;
            }
            let snapshot: SupervisionLeaseSnapshot =
                decode_named(value.value(), "supervision_lease_history")?;
            snapshot.validate()?;
            if snapshot.record.lease_id != *lease_id
                || key.value() != Self::supervision_history_key(lease_id, snapshot.record.revision)
            {
                return Err(OrsError::IntegrityProblem {
                    record_type: "supervision_lease_history",
                    reason: "history key does not match lease identity or revision".to_owned(),
                });
            }
            snapshots.push(snapshot);
        }
        snapshots.sort_by_key(|snapshot| std::cmp::Reverse(snapshot.record.revision));
        snapshots.truncate(usize::from(limit));
        Ok(snapshots)
    }

    fn encode_key_component(value: &str) -> String {
        let mut out = String::with_capacity(value.len());
        for ch in value.chars() {
            match ch {
                '%' => out.push_str("%25"),
                ':' => out.push_str("%3A"),
                _ => out.push(ch),
            }
        }
        out
    }

    fn supervision_history_key(lease_id: &crate::OperationIdentity, revision: u64) -> String {
        format!(
            "{}::{:020}",
            Self::encode_key_component(lease_id.as_str()),
            revision
        )
    }

    fn persist_supervision_snapshot(
        write: &redb::WriteTransaction,
        snapshot: &SupervisionLeaseSnapshot,
        result: &DurableSupervisionLeaseResult,
    ) -> Result<(), OrsError> {
        {
            let resolutions = write
                .open_table(SUPERVISION_LEASE_STAGE_RESOLUTIONS)
                .map_err(storage)?;
            if resolutions
                .get(result.ticket.ticket_id.as_str())
                .map_err(storage)?
                .is_some()
            {
                return Err(OrsError::SupervisionLeaseTicketResolved);
            }
        }
        let encoded = encode(snapshot)?;
        {
            let mut current = write
                .open_table(SUPERVISION_LEASE_CURRENT)
                .map_err(storage)?;
            current
                .insert(snapshot.record.lease_id.as_str(), encoded.as_str())
                .map_err(storage)?;
        }
        {
            let history_key =
                Self::supervision_history_key(&snapshot.record.lease_id, snapshot.record.revision);
            let mut history = write
                .open_table(SUPERVISION_LEASE_HISTORY)
                .map_err(storage)?;
            if history
                .get(history_key.as_str())
                .map_err(storage)?
                .is_some()
            {
                return Err(OrsError::SupervisionLeaseTicketConflict);
            }
            history
                .insert(history_key.as_str(), encoded.as_str())
                .map_err(storage)?;
        }
        {
            let encoded = encode(result)?;
            let mut results = write
                .open_table(SUPERVISION_LEASE_RESULTS)
                .map_err(storage)?;
            if results
                .get(result.ticket.ticket_id.as_str())
                .map_err(storage)?
                .is_some()
            {
                return Err(OrsError::SupervisionLeaseTicketConflict);
            }
            results
                .insert(result.ticket.ticket_id.as_str(), encoded.as_str())
                .map_err(storage)?;
        }
        Ok(())
    }

    /// Opens or creates an ORS database and converts interrupted execution to reconciliation.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, OrsError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(storage)?;
        }
        let database = Database::create(path).map_err(storage)?;
        let store = Self {
            database,
            evidence: Arc::new(RejectUnboundEvidence),
            #[cfg(feature = "test-support")]
            authority_handoff_failpoint: std::sync::Mutex::new(None),
        };
        store.initialize()?;
        store.recover_interrupted_execution()?;
        Ok(store)
    }

    /// Opens ORS with the composition-owned canonical/readback authenticator.
    pub fn open_with_evidence(
        path: impl AsRef<Path>,
        evidence: Arc<dyn CanonicalEvidenceProvider>,
    ) -> Result<Self, OrsError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(storage)?;
        }
        let database = Database::create(path).map_err(storage)?;
        let store = Self {
            database,
            evidence,
            #[cfg(feature = "test-support")]
            authority_handoff_failpoint: std::sync::Mutex::new(None),
        };
        store.initialize()?;
        store.recover_interrupted_execution()?;
        Ok(store)
    }

    /// Opens a Kernel-route test store with the structural Kernel-route evidence.
    ///
    /// Test-only composition seam (issue #2031): binds
    /// [`crate::test_support::KernelRouteEvidence`] so Kernel-route tests share
    /// one evidence binding instead of vendoring their own. Production
    /// composition keeps binding its own provider through
    /// [`Self::open_with_evidence`]. Compiled only with the `test-support`
    /// feature and never linked into production builds.
    #[cfg(feature = "test-support")]
    pub fn open_kernel_route_for_test(path: impl AsRef<Path>) -> Result<Self, OrsError> {
        Self::open_with_evidence(path, Arc::new(crate::test_support::KernelRouteEvidence))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "schema initialization keeps the durable table contract in one auditable transaction setup"
    )]
    fn initialize(&self) -> Result<(), OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        // Bounded: provenance below and the journal family check that follows
        // both depend on this set, so an unbounded table-name scan would be an
        // unbounded open-time cost on a malformed database.
        let mut table_names = BTreeSet::new();
        for table in write.list_tables().map_err(storage)? {
            table_names.insert(restore_journal::bound_table_name(table.name())?);
            if table_names.len() > MAX_ORS_TABLES_SCANNED {
                return Err(OrsError::ProjectionLimitExceeded);
            }
        }
        let store_is_empty = table_names.is_empty();
        let has_resolution_table = table_names.contains(SUPERVISION_LEASE_STAGE_RESOLUTIONS.name());
        let resolution_schema_marker = if table_names.contains(META.name()) {
            let meta = write.open_table(META).map_err(storage)?;
            // Bounded before it is copied out: a corrupt marker must not be able
            // to force an unbounded allocation during open.
            match meta
                .get(SUPERVISION_STAGE_RESOLUTION_SCHEMA_KEY)
                .map_err(storage)?
            {
                Some(value) if value.value().len() > MAX_ORS_MARKER_BYTES => {
                    return Err(OrsError::ProjectionLimitExceeded);
                }
                Some(value) => Some(value.value().to_owned()),
                None => None,
            }
        } else {
            None
        };
        let initialize_resolution_schema = if store_is_empty {
            true
        } else if has_resolution_table
            && resolution_schema_marker.as_deref() == Some(SUPERVISION_STAGE_RESOLUTION_SCHEMA_V1)
        {
            false
        } else {
            return Err(OrsError::MigrationRequired {
                reason: "supervision stage-resolution table/marker provenance is incomplete"
                    .to_owned(),
            });
        };
        // The base family — including the #1115 activation-lifecycle and
        // activation-retention tables — is materialized by one extracted helper
        // so this transaction reads as markers, then family, then journal, then
        // the activation validators.
        Self::initialize_ors_tables(&write, initialize_resolution_schema)?;
        // The journal initializer owns the family AND the base-META adoption
        // marker, so every entry point that can materialize the family — this
        // one plus `ensure_restore_journal_schema` and
        // `bind_restore_journal_stream` — enforces the same adoption rule. It
        // also re-checks the table ceiling as a postcondition, so the base
        // tables added above cannot push this transaction past the bound.
        restore_journal::initialize_restore_journal_schema(&write)?;
        Self::migrate_legacy_grant_closure_rows(&write)?;
        Self::validate_grant_closure_second_phase_table(&write)?;
        // #1115: the durable lifecycle records are validated in the same
        // transaction that materializes them, before the retention and
        // cross-table checks below, so a store that can open never carries a
        // lifecycle row that disagrees with its retained result.
        Self::validate_activation_lifecycle_table(&write)?;
        Self::validate_activation_result_retention_table(&write)?;
        Self::validate_activation_cross_table_bindings(&write)?;
        // #2571: every logical link must resolve to a row that recomputes
        // to its own key. Links are never repaired or backfilled here.
        Self::validate_host_request_logical_index(&write)?;
        // #2730: reconcile the bridge position index and replay
        // commitments with the retained owner-bound records under one
        // migration/version contract, then record the contract marker.
        // Contradictory mappings fail open closed; missing index entries
        // are rebuilt from the records — never inferred, never deleted.
        Self::rebuild_bridge_replay_index(&write)?;
        Self::rebuild_bridge_owner_list_index(&write)?;
        Self::initialize_bridge_recovery_legacy_unproven(&write)?;
        write.commit().map_err(storage)
    }

    /// Materializes the durable `backup.verify` result table (issue #2802).
    ///
    /// It is part of the base family and is created empty on every open exactly
    /// like every other base table, so a lookup on a store that never verified an
    /// archive reads authoritatively absent instead of failing on a missing
    /// table. No row is ever backfilled, inferred or migrated here: a
    /// verification result exists only once the Kernel verify route recorded one.
    fn materialize_backup_verification_table(
        write: &redb::WriteTransaction,
    ) -> Result<(), OrsError> {
        drop(
            write
                .open_table(BACKUP_VERIFICATION_RESULTS)
                .map_err(storage)?,
        );
        Ok(())
    }

    /// Materializes the base ORS table family and, when the store is new or
    /// already carries the exact v1 stage-resolution provenance, the
    /// stage-resolution schema marker.
    #[allow(
        clippy::too_many_lines,
        reason = "all ORS table openings participate in the same initialization transaction"
    )]
    fn initialize_ors_tables(
        write: &redb::WriteTransaction,
        initialize_resolution_schema: bool,
    ) -> Result<(), OrsError> {
        drop(write.open_table(META).map_err(storage)?);
        drop(write.open_table(ENVELOPES).map_err(storage)?);
        drop(write.open_table(RESERVATIONS).map_err(storage)?);
        drop(write.open_table(RESERVATION_ORDERS).map_err(storage)?);
        drop(write.open_table(OPERATIONS).map_err(storage)?);
        drop(write.open_table(SCOPE_HEADS).map_err(storage)?);
        drop(write.open_table(SCOPE_TERMINALS).map_err(storage)?);
        drop(write.open_table(OPERATIONAL_CURRENT).map_err(storage)?);
        drop(write.open_table(OPERATIONAL_HISTORY).map_err(storage)?);
        drop(write.open_table(RECOVERY_INBOX).map_err(storage)?);
        drop(write.open_table(RECOVERY_INBOX_HISTORY).map_err(storage)?);
        drop(write.open_table(PROCESS_START_REPLAY).map_err(storage)?);
        // #1862: the immutable campaign learning-state view and the campaign
        // source record/head/pending families are part of the base ORS table
        // contract, so they are materialized with the other base tables and
        // exist for the exact source-head CAS and view retention reads.
        drop(
            write
                .open_table(CAMPAIGN_LEARNING_STATE_VIEWS)
                .map_err(storage)?,
        );
        drop(write.open_table(CAMPAIGN_SOURCE_RECORDS).map_err(storage)?);
        drop(write.open_table(CAMPAIGN_SOURCE_HEADS).map_err(storage)?);
        drop(write.open_table(CAMPAIGN_SOURCE_PENDING).map_err(storage)?);
        drop(write.open_table(AUTHORITY_HANDOFFS).map_err(storage)?);
        drop(write.open_table(PROCESS_EVIDENCE).map_err(storage)?);
        drop(write.open_table(PROCESS_STREAM_RECOVERY).map_err(storage)?);
        drop(
            write
                .open_table(SUPERVISION_LEASE_STAGED)
                .map_err(storage)?,
        );
        drop(
            write
                .open_table(SUPERVISION_LEASE_CURRENT)
                .map_err(storage)?,
        );
        drop(
            write
                .open_table(SUPERVISION_LEASE_HISTORY)
                .map_err(storage)?,
        );
        drop(
            write
                .open_table(SUPERVISION_LEASE_RESULTS)
                .map_err(storage)?,
        );
        drop(
            write
                .open_table(SUPERVISION_LEASE_STAGE_RESOLUTIONS)
                .map_err(storage)?,
        );
        drop(write.open_table(STORE_REBIND_REPLAY).map_err(storage)?);
        drop(write.open_table(UNKNOWN_COMMIT_RECOVERY).map_err(storage)?);
        // #2802: part of the base family, materialized empty on every open like
        // every other base table, so a lookup on a store that never verified an
        // archive reads authoritatively absent. No row is backfilled or inferred.
        Self::materialize_backup_verification_table(write)?;
        drop(write.open_table(NATIVE_WORKER_CLAIMS).map_err(storage)?);
        drop(
            write
                .open_table(ACTIVATION_RESULT_RETENTION)
                .map_err(storage)?,
        );
        // #1115: the durable activation lifecycle table is part of the base
        // family, created in the same position and by the same single-pass
        // helper as every other base table, so a fresh store materializes it
        // before `validate_activation_lifecycle_table` reads it.
        drop(write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?);
        drop(write.open_table(REPLAY_STREAMS).map_err(storage)?);
        drop(write.open_table(REPLAY_REQUESTS).map_err(storage)?);
        drop(write.open_table(REPLAY_EVENTS).map_err(storage)?);
        drop(write.open_table(REPLAY_ACKS).map_err(storage)?);
        drop(write.open_table(DOCTOR_ATTEMPTS).map_err(storage)?);
        drop(write.open_table(DOCTOR_EFFECTS).map_err(storage)?);
        drop(write.open_table(DOCTOR_BUDGETS).map_err(storage)?);
        drop(write.open_table(RECOVERY_PROBLEMS).map_err(storage)?);
        // #2571: the logical host-request index is part of the base family,
        // materialized empty on every open like every other base table, so a
        // lookup on a pre-index store reads authoritatively absent instead
        // of failing on a missing table. Rows are never backfilled here.
        drop(
            write
                .open_table(HOST_REQUEST_LOGICAL_KEYS)
                .map_err(storage)?,
        );
        // #2729: the bridge-event family (records, cursors, gaps,
        // handoffs) plus the stream-owner index are part of the base
        // family, materialized empty on every open like every other base
        // table, so an owner-scoped lookup on a store that never staged
        // bridge events reads authoritatively absent instead of failing on
        // a missing table. Legacy rows are never backfilled here.
        drop(write.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?);
        drop(write.open_table(BRIDGE_EVENT_CURSORS).map_err(storage)?);
        drop(write.open_table(BRIDGE_EVENT_GAPS).map_err(storage)?);
        drop(write.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?);
        drop(write.open_table(BRIDGE_STREAM_OWNERS).map_err(storage)?);
        drop(
            write
                .open_table(BRIDGE_STREAM_OWNER_LIST_INDEX)
                .map_err(storage)?,
        );
        drop(
            write
                .open_table(BRIDGE_EVENT_RECOVERY_WINDOWS)
                .map_err(storage)?,
        );
        drop(
            write
                .open_table(BRIDGE_EVENT_RECOVERY_CUTS)
                .map_err(storage)?,
        );
        drop(
            write
                .open_table(BRIDGE_EVENT_RECOVERY_REVISIONS)
                .map_err(storage)?,
        );
        // #2730: the bridge position index and the replay-commitment table
        // are part of the base family, materialized empty on every open
        // like every other base table. The migration below reconciles
        // their contents with the retained owner-bound records.
        drop(write.open_table(BRIDGE_EVENT_POSITIONS).map_err(storage)?);
        drop(
            write
                .open_table(BRIDGE_EVENT_REPLAY_COMMITMENTS)
                .map_err(storage)?,
        );
        drop(write.open_table(GRANT_CLOSURE_CURRENT).map_err(storage)?);
        drop(
            write
                .open_table(GRANT_GRAPH_REVISION_CURRENT)
                .map_err(storage)?,
        );
        if initialize_resolution_schema {
            let mut meta = write.open_table(META).map_err(storage)?;
            meta.insert(
                SUPERVISION_STAGE_RESOLUTION_SCHEMA_KEY,
                SUPERVISION_STAGE_RESOLUTION_SCHEMA_V1,
            )
            .map_err(storage)?;
        }
        Ok(())
    }

    /// Binds every retained activation result to the durable lifecycle record
    /// that owns it (#1115).
    ///
    /// A result without a lifecycle owner, or one whose lifecycle names a
    /// different retained result, is a `MigrationRequired`/`IntegrityProblem`
    /// failure: the cross-table binding is a durable invariant, so open fails
    /// closed instead of admitting a store whose replay could publish a result
    /// under a lifecycle that never authorized it.
    fn validate_activation_cross_table_bindings(
        write: &redb::WriteTransaction,
    ) -> Result<(), OrsError> {
        let lifecycle_table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
        let mut lifecycles = BTreeMap::new();
        for entry in lifecycle_table.iter().map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let record: ActivationLifecycleRecord = decode(value.value())?;
            lifecycles.insert(key.value().to_owned(), record);
        }
        drop(lifecycle_table);
        let result_table = write
            .open_table(ACTIVATION_RESULT_RETENTION)
            .map_err(storage)?;
        for entry in result_table.iter().map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let result: ActivationResultRetentionRecord = decode(value.value())?;
            let lifecycle =
                lifecycles
                    .get(key.value())
                    .ok_or_else(|| OrsError::MigrationRequired {
                        reason: "existing activation result lacks a durable lifecycle owner"
                            .to_owned(),
                    })?;
            if lifecycle.result_sha256.as_deref() != Some(result.result_sha256.as_str()) {
                return Err(OrsError::IntegrityProblem {
                    record_type: "activation_lifecycle",
                    reason: "existing result and lifecycle bindings disagree".to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Validates the durable activation lifecycle table (#1115).
    ///
    /// Every row must be keyed by its own record identity and carry a non-zero
    /// lifecycle order, the table must stay inside its record bound, lifecycle
    /// orders must be unique, and every `NotReady` successor must bind exactly
    /// one `DeferredNotReady` predecessor by ticket digest and retained result
    /// digest. A violation is an `IntegrityProblem`, so a store whose lifecycle
    /// chain could no longer be replayed in order fails closed at open.
    fn validate_activation_lifecycle_table(write: &redb::WriteTransaction) -> Result<(), OrsError> {
        let table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
        let mut rows = Vec::new();
        for entry in table.iter().map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let record: ActivationLifecycleRecord = decode(value.value())?;
            if key.value() != record.record_key() || record.lifecycle_order == 0 {
                return Err(OrsError::IntegrityProblem {
                    record_type: "activation_lifecycle",
                    reason: "table key or lifecycle order is invalid".to_owned(),
                });
            }
            rows.push(record);
        }
        if rows.len() > crate::MAX_ACTIVATION_LIFECYCLE_RECORDS {
            return Err(OrsError::IntegrityProblem {
                record_type: "activation_lifecycle",
                reason: "lifecycle record bound exceeded".to_owned(),
            });
        }
        let mut lifecycle_orders = rows
            .iter()
            .map(|record| record.lifecycle_order)
            .collect::<Vec<_>>();
        lifecycle_orders.sort_unstable();
        if lifecycle_orders.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(OrsError::IntegrityProblem {
                record_type: "activation_lifecycle",
                reason: "lifecycle order is not unique".to_owned(),
            });
        }
        let mut successor_ticket_ids = BTreeSet::new();
        for successor_row in rows.iter().filter_map(|record| {
            record
                .successor_of
                .as_ref()
                .map(|binding| (record, binding))
        }) {
            let (successor_row, successor) = successor_row;
            if !successor_ticket_ids.insert(successor_row.ticket_id.clone()) {
                return Err(OrsError::IntegrityProblem {
                    record_type: "activation_lifecycle",
                    reason: "successor ticket identity is duplicated".to_owned(),
                });
            }
            let predecessor = rows
                .iter()
                .find(|record| record.ticket_id == successor.predecessor_ticket_id)
                .ok_or_else(|| OrsError::IntegrityProblem {
                    record_type: "activation_lifecycle",
                    reason: "successor predecessor is missing".to_owned(),
                })?;
            if predecessor.state != ActivationLifecycleState::DeferredNotReady
                || predecessor.ticket_sha256 != successor.predecessor_ticket_sha256
                || predecessor.result_sha256.as_deref()
                    != Some(successor.predecessor_result_sha256.as_str())
                || predecessor.successor_ticket_id.as_deref()
                    != Some(successor_row.ticket_id.as_str())
            {
                return Err(OrsError::IntegrityProblem {
                    record_type: "activation_lifecycle",
                    reason: "successor predecessor binding is invalid".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_activation_result_retention_table(
        write: &redb::WriteTransaction,
    ) -> Result<(), OrsError> {
        let table = write
            .open_table(ACTIVATION_RESULT_RETENTION)
            .map_err(storage)?;
        let mut rows = Vec::new();
        for entry in table.iter().map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let record: ActivationResultRetentionRecord = decode(value.value())?;
            if key.value() != record.record_key() {
                return Err(OrsError::IntegrityProblem {
                    record_type: "activation_result_retention",
                    reason: "table key does not match ticket identity".to_owned(),
                });
            }
            rows.push(record);
        }
        rows.sort_by_key(|record| record.retention_order);
        if rows.len() > crate::MAX_ACTIVATION_RESULT_RETENTION_RECORDS {
            return Err(OrsError::IntegrityProblem {
                record_type: "activation_result_retention",
                reason: "retention record bound exceeded".to_owned(),
            });
        }
        for pair in rows.windows(2) {
            if pair[0].retention_order == pair[1].retention_order {
                return Err(OrsError::IntegrityProblem {
                    record_type: "activation_result_retention",
                    reason: "retention order is not unique".to_owned(),
                });
            }
        }
        let total_payload_bytes = rows.iter().try_fold(0usize, |total, record| {
            total
                .checked_add(record.payload_bytes())
                .ok_or_else(|| OrsError::IntegrityProblem {
                    record_type: "activation_result_retention",
                    reason: "retention payload size overflow".to_owned(),
                })
        })?;
        if total_payload_bytes > crate::MAX_ACTIVATION_RESULT_TOTAL_PAYLOAD_BYTES {
            return Err(OrsError::IntegrityProblem {
                record_type: "activation_result_retention",
                reason: "retention payload bound exceeded".to_owned(),
            });
        }
        Ok(())
    }

    fn reconcile_interrupted_activation_tickets(&self) -> Result<(), OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        let mut rows = {
            let table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
            let mut rows = Vec::new();
            for entry in table.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                let record: ActivationLifecycleRecord = decode(value.value())?;
                if key.value() != record.record_key() {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "activation_lifecycle",
                        reason: "table key does not match ticket identity".to_owned(),
                    });
                }
                rows.push(record);
            }
            rows
        };
        let open_ids = rows
            .iter()
            .filter(|record| {
                matches!(
                    record.state,
                    ActivationLifecycleState::Pending | ActivationLifecycleState::Claimed
                )
            })
            .map(|record| record.ticket_id.clone())
            .collect::<BTreeSet<_>>();
        if open_ids.is_empty() {
            write.commit().map_err(storage)?;
            return Ok(());
        }
        let order = Self::next_operational_order(&write)?;
        for record in &mut rows {
            if record
                .successor_of
                .as_ref()
                .is_some_and(|successor| open_ids.contains(&successor.predecessor_ticket_id))
            {
                continue;
            }
            if open_ids.contains(&record.ticket_id) {
                record.state = ActivationLifecycleState::Reconciling;
                record.claim_owner = None;
                record.claim_expires_at_unix_ms = None;
                record.terminal_reason =
                    Some("restart interrupted activation lifecycle".to_owned());
                record.lifecycle_order = order;
                record.validate()?;
            } else if record
                .successor_ticket_id
                .as_ref()
                .is_some_and(|successor_id| open_ids.contains(successor_id))
            {
                record.successor_ticket_id = None;
                record.lifecycle_order = order;
                record.validate()?;
            }
        }
        {
            let mut table = write.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
            for record in &rows {
                let payload = encode(record)?;
                table
                    .insert(record.record_key(), payload.as_str())
                    .map_err(storage)?;
            }
        }
        write.commit().map_err(storage)
    }

    fn recover_interrupted_execution(&self) -> Result<(), OrsError> {
        self.reconcile_interrupted_activation_tickets()?;
        loop {
            let write = self.database.begin_write().map_err(storage)?;
            let mut interrupted = Vec::with_capacity(usize::from(crate::MAX_RECOVERY_PAGE));
            {
                let table = write.open_table(RESERVATIONS).map_err(storage)?;
                for row in table.iter().map_err(storage)? {
                    let (key, value) = row.map_err(storage)?;
                    let record: ReservationRecord = decode(value.value())?;
                    if record.state == ReservationState::Executing {
                        interrupted.push((key.value().to_owned(), record));
                        if interrupted.len() == usize::from(crate::MAX_RECOVERY_PAGE) {
                            break;
                        }
                    }
                }
            }
            if interrupted.is_empty() {
                return Ok(());
            }
            {
                let mut reservations = write.open_table(RESERVATIONS).map_err(storage)?;
                for (key, interrupted_record) in &interrupted {
                    let mut record = interrupted_record.clone();
                    record.state = ReservationState::Reconciling;
                    record.unknown_reason =
                        Some(OpaqueLabel::new("restart interrupted execution")?);
                    let payload = encode(&record)?;
                    reservations
                        .insert(key.as_str(), payload.as_str())
                        .map_err(storage)?;
                }
            }
            {
                let mut heads = write.open_table(SCOPE_HEADS).map_err(storage)?;
                for (_, record) in &interrupted {
                    for reserved in &record.token.scopes {
                        let key = reserved.scope.as_str();
                        let value = heads.get(key).map_err(storage)?.ok_or_else(|| {
                            OrsError::IntegrityProblem {
                                record_type: "scope_head",
                                reason: "interrupted reservation scope head is missing".to_owned(),
                            }
                        })?;
                        let mut head: ScopeReservationHead = decode(value.value())?;
                        drop(value);
                        head.recovery_blocked = true;
                        let payload = encode(&head)?;
                        heads.insert(key, payload.as_str()).map_err(storage)?;
                    }
                }
            }
            write.commit().map_err(storage)?;
        }
    }

    /// Returns one validated terminal sequence binding without exposing a writable receipt type.
    pub fn scope_terminal(
        &self,
        scope: &crate::OrderingScope,
        reserved_sequence: u64,
    ) -> Result<Option<ScopeTerminalView>, OrsError> {
        let key = format!("{}:{reserved_sequence:020}", scope.as_str());
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(SCOPE_TERMINALS).map_err(storage)?;
        table
            .get(key.as_str())
            .map_err(storage)?
            .map(|value| {
                decode::<ScopeTerminalReceipt>(value.value())
                    .map(|receipt| ScopeTerminalView::from_persisted(&receipt))
            })
            .transpose()
    }

    fn load_record(
        table: &impl ReadableTable<&'static str, &'static str>,
        reservation_id: &crate::OperationIdentity,
    ) -> Result<ReservationRecord, OrsError> {
        let value = table
            .get(reservation_id.as_str())
            .map_err(storage)?
            .ok_or(OrsError::ReservationNotFound)?;
        decode(value.value())
    }

    fn validate_token(
        stored: &ReservationRecord,
        supplied: &WriterReservationToken,
    ) -> Result<(), OrsError> {
        if stored.token != *supplied {
            return Err(OrsError::DuplicateConflict);
        }
        Ok(())
    }

    fn ensure_no_predecessor(
        table: &impl ReadableTable<&'static str, &'static str>,
        token: &WriterReservationToken,
    ) -> Result<(), OrsError> {
        for row in table.iter().map_err(storage)? {
            let (_, value) = row.map_err(storage)?;
            let record: ReservationRecord = decode(value.value())?;
            if !record.state.is_terminal()
                && record.token.reservation_order < token.reservation_order
                && shares_scope(&record.token, token)
            {
                return Err(OrsError::PredecessorPending);
            }
        }
        Ok(())
    }

    fn ensure_canonical_heads(
        write: &redb::WriteTransaction,
        token: &WriterReservationToken,
    ) -> Result<(), OrsError> {
        let heads = write.open_table(SCOPE_HEADS).map_err(storage)?;
        for reserved in &token.scopes {
            let value = heads
                .get(reserved.scope.as_str())
                .map_err(storage)?
                .ok_or_else(|| OrsError::IntegrityProblem {
                    record_type: "scope_head",
                    reason: "reserved scope head is missing".to_owned(),
                })?;
            let head: ScopeReservationHead = decode_named(value.value(), "scope_head")?;
            if head.canonical_head != reserved.expected_head {
                return Err(OrsError::OrderingHeadMismatch);
            }
        }
        Ok(())
    }

    fn clear_recovery_blocks(
        write: &redb::WriteTransaction,
        closed: &ReservationRecord,
    ) -> Result<(), OrsError> {
        let blocked_scopes: BTreeSet<_> = closed
            .token
            .scopes
            .iter()
            .map(|scope| scope.scope.clone())
            .collect();
        let mut still_blocked = BTreeSet::new();
        {
            let reservations = write.open_table(RESERVATIONS).map_err(storage)?;
            for row in reservations.iter().map_err(storage)? {
                let (_, value) = row.map_err(storage)?;
                let record: ReservationRecord = decode(value.value())?;
                if record.token.reservation_id != closed.token.reservation_id
                    && record.state == ReservationState::Reconciling
                {
                    for scope in &record.token.scopes {
                        if blocked_scopes.contains(&scope.scope) {
                            still_blocked.insert(scope.scope.clone());
                        }
                    }
                }
            }
        }
        let mut heads = write.open_table(SCOPE_HEADS).map_err(storage)?;
        for scope in blocked_scopes {
            let value = heads
                .get(scope.as_str())
                .map_err(storage)?
                .ok_or_else(|| OrsError::Storage("missing scope head".to_owned()))?;
            let mut head: ScopeReservationHead = decode(value.value())?;
            drop(value);
            head.recovery_blocked = still_blocked.contains(&scope);
            let payload = encode(&head)?;
            heads
                .insert(scope.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        Ok(())
    }

    fn record_scope_terminals(
        write: &redb::WriteTransaction,
        reconciliation: &CanonicalReconciliation,
    ) -> Result<(), OrsError> {
        let mut heads = write.open_table(SCOPE_HEADS).map_err(storage)?;
        let mut terminals = write.open_table(SCOPE_TERMINALS).map_err(storage)?;
        for observed in &reconciliation.scopes {
            let value = heads
                .get(observed.scope.as_str())
                .map_err(storage)?
                .ok_or_else(|| OrsError::IntegrityProblem {
                    record_type: "scope_head",
                    reason: "scope terminal has no durable head".to_owned(),
                })?;
            let mut head: ScopeReservationHead = decode_named(value.value(), "scope_head")?;
            drop(value);
            if head.canonical_head != observed.prior_head
                || observed.committed_sequence > head.last_reserved_sequence
                || observed.committed_sequence <= head.last_terminal_sequence
            {
                return Err(OrsError::OrderingHeadMismatch);
            }
            let gap = reconciliation.disposition == CanonicalDisposition::Rejected;
            if !gap {
                head.canonical_head = crate::ExpectedOrderingHead {
                    sequence: observed.committed_sequence,
                    head_sha256: observed.committed_head_sha256.clone(),
                    revision_head: observed.committed_revision_head.clone(),
                };
            }
            head.last_terminal_sequence = observed.committed_sequence;
            let terminal = ScopeTerminalReceipt {
                scope: observed.scope.clone(),
                reserved_sequence: observed.committed_sequence,
                disposition: reconciliation.disposition,
                gap,
                receipt_id: observed.receipt_id.clone(),
                receipt_sha256: reconciliation.receipt.identity.canonical_sha256.clone(),
            };
            let head_payload = encode(&head)?;
            heads
                .insert(observed.scope.as_str(), head_payload.as_str())
                .map_err(storage)?;
            let terminal_key = format!(
                "{}:{:020}",
                observed.scope.as_str(),
                observed.committed_sequence
            );
            let terminal_payload = encode(&terminal)?;
            terminals
                .insert(terminal_key.as_str(), terminal_payload.as_str())
                .map_err(storage)?;
        }
        Ok(())
    }

    /// Loads the durable reservation token bound to one staged operation
    /// identity. Used to bind a Recovery Problem to its epoch, fence, and
    /// recovery owner when the staged envelope itself cannot be decoded.
    fn staging_context(
        &self,
        operation_id: &crate::OperationIdentity,
    ) -> Result<WriterReservationToken, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let reservation_id = {
            let operations = read.open_table(OPERATIONS).map_err(storage)?;
            operations
                .get(operation_id.as_str())
                .map_err(storage)?
                .map(|value| value.value().to_owned())
                .ok_or(OrsError::ReservationNotFound)?
        };
        let reservation_id =
            OpaqueLabel::new(reservation_id).map_err(|error| OrsError::IntegrityProblem {
                record_type: "operation_index",
                reason: error.to_string(),
            })?;
        let reservations = read.open_table(RESERVATIONS).map_err(storage)?;
        let value = reservations
            .get(reservation_id.as_str())
            .map_err(storage)?
            .ok_or_else(|| OrsError::Storage("operation index is dangling".to_owned()))?;
        Ok(decode::<ReservationRecord>(value.value())?.token)
    }

    /// Retains one visible durable Recovery Problem for a staged operation
    /// whose envelope failed validation (issue #1925, I5.2).
    ///
    /// The problem carries digests only — never payload bytes — and the
    /// staged envelope and reservation rows are left untouched so the
    /// operation remains available for reconciliation or explicit disposition.
    /// An identical retained problem is returned unchanged; a conflicting
    /// binding under the same identity fails without overwriting.
    fn retain_staging_problem(
        &self,
        token: &WriterReservationToken,
        error: &OrsError,
        fingerprint: Option<(String, Option<String>)>,
    ) -> Result<RecoveryProblem, OrsError> {
        let (envelope_sha256, payload_sha256) = fingerprint.unwrap_or((String::new(), None));
        let kind = if payload_sha256.is_some() {
            RecoveryProblemKind::HashMismatch
        } else {
            RecoveryProblemKind::EnvelopeIntegrity
        };
        let problem = RecoveryProblem::new(
            token.operation_id.clone(),
            Some(token.reservation_id.clone()),
            kind,
            staging_problem_detail(error)?,
            (!envelope_sha256.is_empty()).then_some(envelope_sha256),
            payload_sha256,
            token.writer_epoch.clone(),
            token.state_fence.clone(),
            token.recovery_owner.clone(),
            current_unix_ms()?,
        )?;
        let write = self.database.begin_write().map_err(storage)?;
        {
            let problems = write.open_table(RECOVERY_PROBLEMS).map_err(storage)?;
            let key = problem.operation_or_checkpoint_id.as_str();
            if let Some(existing) = problems
                .get(key)
                .map_err(storage)?
                .map(|value| decode::<RecoveryProblem>(value.value()))
                .transpose()?
            {
                if existing.terminal_receipt_id.is_some() {
                    return Ok(existing);
                }
                if existing.kind == problem.kind
                    && existing.detail == problem.detail
                    && existing.envelope_sha256 == problem.envelope_sha256
                    && existing.payload_sha256 == problem.payload_sha256
                    && existing.authority_epoch == problem.authority_epoch
                    && existing.state_fence == problem.state_fence
                    && existing.recovery_owner == problem.recovery_owner
                    && existing.reservation_id == problem.reservation_id
                {
                    return Ok(existing);
                }
                return Err(OrsError::DuplicateConflict);
            }
        }
        let payload = encode(&problem)?;
        {
            let mut problems = write.open_table(RECOVERY_PROBLEMS).map_err(storage)?;
            problems
                .insert(
                    problem.operation_or_checkpoint_id.as_str(),
                    payload.as_str(),
                )
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(problem)
    }

    fn existing_token(
        write: &redb::WriteTransaction,
        request: &ReservationRequest,
    ) -> Result<Option<WriterReservationToken>, OrsError> {
        let reservation_id = {
            let operations = write.open_table(OPERATIONS).map_err(storage)?;
            operations
                .get(request.envelope.operation_or_checkpoint_id.as_str())
                .map_err(storage)?
                .map(|value| value.value().to_owned())
        };
        if let Some(reservation_id) = reservation_id {
            let reservation_id =
                OpaqueLabel::new(reservation_id).map_err(|error| OrsError::IntegrityProblem {
                    record_type: "operation_index",
                    reason: error.to_string(),
                })?;
            let record = {
                let reservations = write.open_table(RESERVATIONS).map_err(storage)?;
                let value = reservations
                    .get(reservation_id.as_str())
                    .map_err(storage)?
                    .ok_or_else(|| OrsError::Storage("operation index is dangling".to_owned()))?;
                decode::<ReservationRecord>(value.value())?
            };
            let envelope = {
                let envelopes = write.open_table(ENVELOPES).map_err(storage)?;
                let value = envelopes
                    .get(request.envelope.operation_or_checkpoint_id.as_str())
                    .map_err(storage)?
                    .ok_or_else(|| OrsError::Storage("operation envelope is missing".to_owned()))?;
                decode::<RecoveryPayloadEnvelope>(value.value())?
            };
            if request_matches(request, &record.token, &envelope) {
                return Ok(Some(record.token));
            }
            return Err(OrsError::DuplicateConflict);
        }
        let reservations = write.open_table(RESERVATIONS).map_err(storage)?;
        if reservations
            .get(request.reservation_id.as_str())
            .map_err(storage)?
            .is_some()
        {
            return Err(OrsError::DuplicateConflict);
        }
        Ok(None)
    }

    fn next_reservation_order(write: &redb::WriteTransaction) -> Result<u64, OrsError> {
        let mut meta = write.open_table(META).map_err(storage)?;
        let prior = meta
            .get(NEXT_GLOBAL_ORDER)
            .map_err(storage)?
            .map(|value| value.value().parse::<u64>())
            .transpose()
            .map_err(|error| OrsError::IntegrityProblem {
                record_type: "ors_meta_v1",
                reason: error.to_string(),
            })?
            .unwrap_or(0);
        let next = prior
            .checked_add(1)
            .ok_or_else(|| OrsError::Storage("reservation order counter exhausted".to_owned()))?;
        meta.insert(NEXT_GLOBAL_ORDER, next.to_string().as_str())
            .map_err(storage)?;
        Ok(next)
    }

    fn reserve_scope_sequences(
        write: &redb::WriteTransaction,
        request: &ReservationRequest,
    ) -> Result<Vec<ReservedScope>, OrsError> {
        let mut reserved_scopes = Vec::with_capacity(request.scopes.len());
        let mut heads = write.open_table(SCOPE_HEADS).map_err(storage)?;
        for requested in &request.scopes {
            let existing: Option<ScopeReservationHead> = heads
                .get(requested.scope.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?;
            let mut head = existing.map_or_else(
                || {
                    Ok(ScopeReservationHead {
                        writer_epoch: request.writer_epoch.current.clone(),
                        canonical_head: requested.expected_head.clone(),
                        last_reserved_sequence: requested.expected_head.sequence,
                        last_terminal_sequence: requested.expected_head.sequence,
                        recovery_blocked: false,
                    })
                },
                |decoded| {
                    if decoded.recovery_blocked {
                        return Err(OrsError::ScopeRecoveryRequired);
                    }
                    if decoded.writer_epoch != request.writer_epoch.current {
                        return Err(OrsError::StaleWriterEpoch);
                    }
                    if decoded.canonical_head != requested.expected_head {
                        return Err(OrsError::OrderingHeadMismatch);
                    }
                    Ok(decoded)
                },
            )?;
            let reserved_sequence = head
                .last_reserved_sequence
                .checked_add(1)
                .ok_or_else(|| OrsError::Storage("scope sequence exhausted".to_owned()))?;
            head.last_reserved_sequence = reserved_sequence;
            let payload = encode(&head)?;
            heads
                .insert(requested.scope.as_str(), payload.as_str())
                .map_err(storage)?;
            reserved_scopes.push(ReservedScope {
                scope: requested.scope.clone(),
                reserved_sequence,
                expected_head: requested.expected_head.clone(),
            });
        }
        Ok(reserved_scopes)
    }

    fn persist_new_reservation(
        write: &redb::WriteTransaction,
        envelope: &RecoveryPayloadEnvelope,
        record: &ReservationRecord,
    ) -> Result<(), OrsError> {
        let token = &record.token;
        {
            let mut envelopes = write.open_table(ENVELOPES).map_err(storage)?;
            let payload = encode(envelope)?;
            envelopes
                .insert(token.operation_id.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        {
            let mut reservations = write.open_table(RESERVATIONS).map_err(storage)?;
            let payload = encode(record)?;
            reservations
                .insert(token.reservation_id.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        let mut operations = write.open_table(OPERATIONS).map_err(storage)?;
        operations
            .insert(token.operation_id.as_str(), token.reservation_id.as_str())
            .map_err(storage)?;
        drop(operations);
        let order_key = format!("{:020}", token.reservation_order);
        let mut orders = write.open_table(RESERVATION_ORDERS).map_err(storage)?;
        if orders
            .insert(order_key.as_str(), token.reservation_id.as_str())
            .map_err(storage)?
            .is_some()
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "reservation_order",
                reason: "duplicate reservation order".to_owned(),
            });
        }
        Ok(())
    }

    pub(super) fn next_operational_order(write: &redb::WriteTransaction) -> Result<u64, OrsError> {
        let mut meta = write.open_table(META).map_err(storage)?;
        let prior = meta
            .get(NEXT_GLOBAL_ORDER)
            .map_err(storage)?
            .map(|value| value.value().parse::<u64>())
            .transpose()
            .map_err(|error| OrsError::IntegrityProblem {
                record_type: "ors_meta_v1",
                reason: error.to_string(),
            })?
            .unwrap_or(0);
        let next = prior
            .checked_add(1)
            .ok_or_else(|| OrsError::IntegrityProblem {
                record_type: "ors_meta_v1",
                reason: "operational order counter exhausted".to_owned(),
            })?;
        meta.insert(NEXT_GLOBAL_ORDER, next.to_string().as_str())
            .map_err(storage)?;
        Ok(next)
    }

    /// Reads the durable monotone revision of the process-stream recovery
    /// family (issue #2884).
    ///
    /// The single owner of the counter: the family's one write path advances it
    /// and the backup family cursor observes it. A store written before the
    /// counter existed reads as revision `0`, which is a real frozen value and
    /// not an error - the family's streamed content root binds that state.
    pub(super) fn process_stream_recovery_family_revision(
        read: &redb::ReadTransaction,
    ) -> Result<u64, OrsError> {
        let meta = read.open_table(META).map_err(storage)?;
        let revision = meta
            .get(PROCESS_STREAM_RECOVERY_FAMILY_REVISION)
            .map_err(storage)?
            .map(|value| value.value().parse::<u64>())
            .transpose()
            .map_err(|error| OrsError::IntegrityProblem {
                record_type: "ors_meta_v1",
                reason: error.to_string(),
            })?
            .unwrap_or(0);
        Ok(revision)
    }

    /// Advances the process-stream recovery family revision in the caller's
    /// open write transaction (issue #2884).
    ///
    /// Called only when a family row was actually inserted or advanced, in the
    /// same transaction as that write: an exact re-presentation that changed
    /// nothing must not look like movement to an in-progress backup. Because
    /// the counter is monotone and transaction-bound, retiring a row - which
    /// rewrites the row as terminal evidence rather than deleting it - moves it
    /// exactly like any other change.
    fn advance_process_stream_recovery_family_revision(
        write: &redb::WriteTransaction,
    ) -> Result<u64, OrsError> {
        let mut meta = write.open_table(META).map_err(storage)?;
        let prior = meta
            .get(PROCESS_STREAM_RECOVERY_FAMILY_REVISION)
            .map_err(storage)?
            .map(|value| value.value().parse::<u64>())
            .transpose()
            .map_err(|error| OrsError::IntegrityProblem {
                record_type: "ors_meta_v1",
                reason: error.to_string(),
            })?
            .unwrap_or(0);
        let next = prior
            .checked_add(1)
            .ok_or_else(|| OrsError::IntegrityProblem {
                record_type: "ors_meta_v1",
                reason: "process-stream recovery family revision counter exhausted".to_owned(),
            })?;
        meta.insert(
            PROCESS_STREAM_RECOVERY_FAMILY_REVISION,
            next.to_string().as_str(),
        )
        .map_err(storage)?;
        Ok(next)
    }

    fn operational_key(kind: OperationalKind, subject: &crate::OperationIdentity) -> String {
        format!("{}:{}", kind.key_prefix(), subject.as_str())
    }

    fn receipt_for(
        record: &DurableOperationalRecord,
    ) -> Result<OperationalMutationReceipt, OrsError> {
        let encoded = encode(record)?;
        OperationalMutationReceipt::issue(
            record.input.record_id.clone(),
            record.input.subject_id.clone(),
            record.operation_order,
            record.phase,
            crate::model::sha256_hex(encoded.as_bytes()),
        )
    }

    /// Issues the store receipt bound to one durable grant-closure row.
    ///
    /// The receipt binds the closure operation identity, the target grant
    /// identity, the monotonic row order, the committed phase, and the digest
    /// of the exact stored bytes. Recomputing it from the stored row makes an
    /// exact recommit return the identical receipt.
    fn closure_receipt_for(
        record: &DurableGrantClosureRecord,
    ) -> Result<OperationalMutationReceipt, OrsError> {
        crate::model::validate_grant_closure_contract(&record.commit)?;
        let encoded = encode(record)?;
        OperationalMutationReceipt::issue(
            OperationIdentity::new(record.commit.operation_id.as_str())?,
            OperationIdentity::new(record.commit.declaration.target_grant_id.as_str())?,
            record.operation_order,
            record.phase,
            crate::model::sha256_hex(encoded.as_bytes()),
        )
    }

    /// Reads the durable grant-graph revision watermark for one lineage
    /// root label under an already-open read snapshot.
    ///
    /// Sharing the caller's snapshot keeps selected closure rows and
    /// their revision mutually consistent; opening a second snapshot
    /// here would admit a torn rows-plus-watermark view.
    fn grant_graph_revision_in(
        read: &redb::ReadTransaction,
        authority_root: &str,
    ) -> Result<Option<u64>, OrsError> {
        let key = format!("grant_graph_revision:{authority_root}");
        let current = read
            .open_table(GRANT_GRAPH_REVISION_CURRENT)
            .map_err(storage)?;
        let Some(value) = current.get(key.as_str()).map_err(storage)? else {
            return Ok(None);
        };
        let row: DurableGrantGraphRevision = decode_named(value.value(), "grant_graph_revision")?;
        if row.root.as_str() != authority_root {
            return Err(OrsError::IntegrityProblem {
                record_type: "grant_graph_revision",
                reason: "current revision key or lineage root mismatch".to_owned(),
            });
        }
        Ok(Some(row.revision))
    }

    fn ensure_grant_closure_order_floor(
        write: &redb::WriteTransaction,
        operation_order: u64,
    ) -> Result<(), OrsError> {
        let mut meta = write.open_table(META).map_err(storage)?;
        let prior = meta
            .get(NEXT_GLOBAL_ORDER)
            .map_err(storage)?
            .map(|value| value.value().parse::<u64>())
            .transpose()
            .map_err(|error| OrsError::IntegrityProblem {
                record_type: "ors_meta_v1",
                reason: error.to_string(),
            })?
            .unwrap_or(0);
        if operation_order > prior {
            meta.insert(NEXT_GLOBAL_ORDER, operation_order.to_string().as_str())
                .map_err(storage)?;
        }
        Ok(())
    }

    fn grant_closure_migration_key(operation_id: &str) -> String {
        format!("{GRANT_CLOSURE_MIGRATION_KEY_PREFIX}{operation_id}")
    }

    fn grant_closure_current_key(operation_id: &str) -> String {
        format!("grant_closure:{operation_id}")
    }

    fn grant_closure_second_phase_key(operation_id: &str) -> String {
        format!("{GRANT_CLOSURE_SECOND_PHASE_KEY_PREFIX}{operation_id}")
    }

    fn decode_grant_closure_second_phase(
        value: &str,
    ) -> Result<DurableGrantClosureSecondPhaseRecord, OrsError> {
        decode_named::<DurableGrantClosureSecondPhaseRecord>(value, "grant_closure_second_phase")
    }

    fn validate_grant_closure_second_phase_binding(
        record: &DurableGrantClosureSecondPhaseRecord,
        key: &str,
        operation_id: &str,
    ) -> Result<(), OrsError> {
        if record.operation_id.as_str() != operation_id
            || key != Self::grant_closure_second_phase_key(operation_id)
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "grant_closure_second_phase",
                reason: "second-phase key or operation identity does not match its row".to_owned(),
            });
        }
        Ok(())
    }

    fn grant_closure_phase_is_committed(phase: OperationalPhase) -> bool {
        matches!(phase, OperationalPhase::Active | OperationalPhase::Fenced)
    }

    fn validate_grant_closure_second_phase_against_row(
        second_phase: &DurableGrantClosureSecondPhaseRecord,
        key: &str,
        closure: &DurableGrantClosureRecord,
    ) -> Result<(), OrsError> {
        Self::validate_grant_closure_second_phase_binding(
            second_phase,
            key,
            closure.commit.operation_id.as_str(),
        )?;
        if !Self::grant_closure_phase_is_committed(closure.phase) {
            return Err(OrsError::InvalidTransition);
        }
        if second_phase.operation_order <= closure.operation_order {
            return Err(OrsError::IntegrityProblem {
                record_type: "grant_closure_second_phase",
                reason: "second-phase order does not follow the committed first phase".to_owned(),
            });
        }
        if let Some(first_phase) = &closure.commit.canonical_receipt
            && first_phase != &second_phase.canonical_receipt
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "grant_closure_second_phase",
                reason: "second-phase link conflicts with the immutable first-phase receipt"
                    .to_owned(),
            });
        }
        Ok(())
    }

    fn grant_closure_second_phase_in(
        read: &redb::ReadTransaction,
        operation_id: &str,
    ) -> Result<Option<DurableGrantClosureSecondPhaseRecord>, OrsError> {
        let key = Self::grant_closure_second_phase_key(operation_id);
        let table = read
            .open_table(GRANT_CLOSURE_SECOND_PHASE_CURRENT)
            .map_err(storage)?;
        let Some(value) = table.get(key.as_str()).map_err(storage)? else {
            return Ok(None);
        };
        let record = Self::decode_grant_closure_second_phase(value.value())?;
        Self::validate_grant_closure_second_phase_binding(&record, key.as_str(), operation_id)?;
        Ok(Some(record))
    }

    fn grant_closure_second_phases_in(
        read: &redb::ReadTransaction,
    ) -> Result<BTreeMap<String, DurableGrantClosureSecondPhaseRecord>, OrsError> {
        let table = read
            .open_table(GRANT_CLOSURE_SECOND_PHASE_CURRENT)
            .map_err(storage)?;
        let mut records = BTreeMap::new();
        for entry in table.iter().map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let record = Self::decode_grant_closure_second_phase(value.value())?;
            Self::validate_grant_closure_second_phase_binding(
                &record,
                key.value(),
                record.operation_id.as_str(),
            )?;
            if records
                .insert(record.operation_id.clone(), record)
                .is_some()
            {
                return Err(OrsError::IntegrityProblem {
                    record_type: "grant_closure_second_phase",
                    reason: "duplicate second-phase operation identity".to_owned(),
                });
            }
        }
        Ok(records)
    }

    fn grant_closure_second_phase_identity(
        closure: &DurableGrantClosureRecord,
        second_phase: Option<&DurableGrantClosureSecondPhaseRecord>,
    ) -> Result<Option<ReceiptIdentity>, OrsError> {
        if let Some(second_phase) = second_phase {
            if let Some(first_phase) = &closure.commit.canonical_receipt
                && first_phase != &second_phase.canonical_receipt
            {
                return Err(OrsError::IntegrityProblem {
                    record_type: "grant_closure_second_phase",
                    reason: "second-phase link conflicts with the immutable first-phase receipt"
                        .to_owned(),
                });
            }
            Ok(Some(second_phase.canonical_receipt.clone()))
        } else {
            Ok(closure.commit.canonical_receipt.clone())
        }
    }

    fn grant_closure_projection_from_record(
        record: DurableGrantClosureRecord,
        second_phase: Option<ReceiptIdentity>,
    ) -> Result<GrantClosureProjection, OrsError> {
        let receipt = Self::closure_receipt_for(&record)?;
        Ok(GrantClosureProjection::from_store(
            record.commit,
            record.phase,
            record.operation_order,
            GrantClosureCommitReceipt::from_receipt(receipt),
            second_phase,
        ))
    }

    fn grant_closure_projection_from_read(
        read: &redb::ReadTransaction,
        record: DurableGrantClosureRecord,
    ) -> Result<GrantClosureProjection, OrsError> {
        let operation_id = record.commit.operation_id.as_str();
        let second_phase = Self::grant_closure_second_phase_in(read, operation_id)?;
        if let Some(second_phase) = second_phase.as_ref() {
            Self::validate_grant_closure_second_phase_against_row(
                second_phase,
                Self::grant_closure_second_phase_key(operation_id).as_str(),
                &record,
            )?;
        }
        let second_phase =
            Self::grant_closure_second_phase_identity(&record, second_phase.as_ref())?;
        Self::grant_closure_projection_from_record(record, second_phase)
    }

    fn validate_grant_closure_second_phase_table(
        write: &redb::WriteTransaction,
    ) -> Result<(), OrsError> {
        let rows = {
            let table = write
                .open_table(GRANT_CLOSURE_SECOND_PHASE_CURRENT)
                .map_err(storage)?;
            let mut rows = Vec::new();
            for entry in table.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                let record = Self::decode_grant_closure_second_phase(value.value())?;
                rows.push((key.value().to_owned(), record));
            }
            rows
        };
        for (key, second_phase) in rows {
            let operation_id = second_phase.operation_id.as_str();
            let current_key = Self::grant_closure_current_key(operation_id);
            let current = write.open_table(GRANT_CLOSURE_CURRENT).map_err(storage)?;
            let Some(value) = current.get(current_key.as_str()).map_err(storage)? else {
                return Err(OrsError::MigrationRequired {
                    reason: format!(
                        "grant-closure second-phase operation {operation_id} has no committed first-phase row"
                    ),
                });
            };
            let closure: DurableGrantClosureRecord = decode_named(value.value(), "grant_closure")?;
            Self::validate_grant_closure_second_phase_against_row(
                &second_phase,
                key.as_str(),
                &closure,
            )?;
        }
        Ok(())
    }

    fn grant_closure_state_label(state: GrantClosureState) -> &'static str {
        match state {
            GrantClosureState::Active => "ACTIVE",
            GrantClosureState::Revoked => "REVOKED",
        }
    }

    fn legacy_grant_closure_missing_fields(record: &LegacyGrantClosureRecord) -> Vec<String> {
        let mut fields = vec![
            "authority".to_owned(),
            "authority_receipt.authority_epoch".to_owned(),
            "authority_receipt.snapshot_id".to_owned(),
            "declaration.members[].parent_grant_id".to_owned(),
            "ors_member_receipts".to_owned(),
            "proof_ceiling".to_owned(),
        ];
        if !record.commit.preserved.is_empty() {
            fields.extend([
                "declaration.preserved[].canonical_request_hash".to_owned(),
                "declaration.preserved[].effect".to_owned(),
                "declaration.preserved[].holder_principal".to_owned(),
                "declaration.preserved[].operation_id".to_owned(),
                "declaration.preserved[].operation_name".to_owned(),
                "declaration.preserved[].resource_ref".to_owned(),
                "declaration.preserved[].scope_id".to_owned(),
                "declaration.preserved[].session_id".to_owned(),
            ]);
        }
        if !record.commit.fenced_introductions.is_empty() {
            fields.push("ors_introduction_receipts".to_owned());
        }
        fields.sort();
        fields.dedup();
        fields
    }

    fn current_grant_closure_matches_legacy(
        current: &DurableGrantClosureRecord,
        legacy: &LegacyGrantClosureRecord,
    ) -> bool {
        let current_affected = current
            .commit
            .declaration
            .members
            .iter()
            .map(|member| member.grant_id.as_str())
            .collect::<BTreeSet<_>>();
        let legacy_affected = legacy
            .commit
            .affected
            .iter()
            .map(OpaqueLabel::as_str)
            .collect::<BTreeSet<_>>();
        let current_preserved = current
            .commit
            .declaration
            .preserved
            .iter()
            .map(|preserved| {
                (
                    preserved.grant_id.as_str(),
                    preserved.covering_grant_id.as_str(),
                    preserved.covering_root_ref.as_str(),
                )
            })
            .collect::<BTreeSet<_>>();
        let legacy_preserved = legacy
            .commit
            .preserved
            .iter()
            .map(|preserved| {
                (
                    preserved.grant_id.as_str(),
                    preserved.covering_grant_id.as_str(),
                    preserved.covering_root.as_str(),
                )
            })
            .collect::<BTreeSet<_>>();
        let current_introductions = current
            .commit
            .fenced_introductions
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let legacy_introductions = legacy
            .commit
            .fenced_introductions
            .iter()
            .map(OpaqueLabel::as_str)
            .collect::<Vec<_>>();
        current.commit.operation_id.as_str() == legacy.commit.operation_id.as_str()
            && current.commit.idempotency_digest == legacy.commit.digest
            && current.commit.declaration.target_grant_id.as_str()
                == legacy.commit.target_id.as_str()
            && current.commit.declaration.authority_root_ref.as_str()
                == legacy.commit.authority_root.as_str()
            && current.commit.declaration.grant_graph_revision == legacy.commit.revision
            && Self::grant_closure_state_label(current.commit.state)
                == match legacy.commit.state {
                    LegacyGrantClosureState::Active => "ACTIVE",
                    LegacyGrantClosureState::Fenced => "REVOKED",
                }
            && current_affected == legacy_affected
            && current_preserved == legacy_preserved
            && current_introductions == legacy_introductions
    }

    fn grant_closure_migration_refusal(record: &GrantClosureMigrationRecord) -> OrsError {
        let missing = if record.missing_fields.is_empty() {
            "<current v2 row binding>".to_owned()
        } else {
            record.missing_fields.join(", ")
        };
        OrsError::MigrationRequired {
            reason: format!(
                "grant-closure operation {} from legacy key {} has migration disposition {}; exact missing v2 field(s): {}",
                record.operation_id,
                record.legacy_key,
                record.disposition.as_str(),
                missing
            ),
        }
    }

    fn decode_grant_closure_migration(
        value: &str,
    ) -> Result<GrantClosureMigrationRecord, OrsError> {
        decode_named::<GrantClosureMigrationRecord>(value, "grant_closure_migration")
    }

    fn grant_closure_migration_from_write(
        write: &redb::WriteTransaction,
        operation_id: &str,
    ) -> Result<Option<GrantClosureMigrationRecord>, OrsError> {
        let key = Self::grant_closure_migration_key(operation_id);
        let current = write.open_table(GRANT_CLOSURE_CURRENT).map_err(storage)?;
        current
            .get(key.as_str())
            .map_err(storage)?
            .map(|value| {
                let migration = Self::decode_grant_closure_migration(value.value())?;
                Self::validate_grant_closure_migration_binding(
                    &migration,
                    key.as_str(),
                    operation_id,
                )?;
                Ok(migration)
            })
            .transpose()
    }

    fn validate_grant_closure_migration_binding(
        record: &GrantClosureMigrationRecord,
        key: &str,
        operation_id: &str,
    ) -> Result<(), OrsError> {
        if record.operation_id != operation_id
            || record.legacy_key != Self::grant_closure_current_key(operation_id)
            || key != Self::grant_closure_migration_key(operation_id)
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "grant_closure_migration",
                reason: "migration key or operation identity does not match its disposition"
                    .to_owned(),
            });
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "schema migration validates and records each legacy row atomically before commit"
    )]
    fn migrate_legacy_grant_closure_rows(write: &redb::WriteTransaction) -> Result<(), OrsError> {
        let mut rows = {
            let legacy = write
                .open_table(GRANT_CLOSURE_LEGACY_CURRENT)
                .map_err(storage)?;
            let mut rows = Vec::new();
            for entry in legacy.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                rows.push((key.value().to_owned(), value.value().to_owned()));
            }
            rows
        };
        rows.sort_by(|left, right| left.0.cmp(&right.0));

        for (legacy_key, raw) in rows {
            let operation_id = legacy_key
                .strip_prefix("grant_closure:")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| OrsError::MigrationRequired {
                    reason: format!(
                        "legacy grant-closure row {legacy_key} has no exact grant_closure:<operation_id> identity"
                    ),
                })?;
            let operation_identity = OperationIdentity::new(operation_id).map_err(|error| {
                OrsError::MigrationRequired {
                    reason: format!(
                        "legacy grant-closure row {legacy_key} has invalid operation identity: {error}"
                    ),
                }
            })?;
            let migration_key = Self::grant_closure_migration_key(operation_identity.as_str());
            let source_sha256 = crate::model::sha256_hex(raw.as_bytes());
            if let Some(existing_migration) =
                Self::grant_closure_migration_from_write(write, operation_identity.as_str())?
            {
                Self::validate_grant_closure_migration_binding(
                    &existing_migration,
                    &migration_key,
                    operation_identity.as_str(),
                )?;
                if existing_migration.source_row_sha256 != source_sha256 {
                    return Err(OrsError::MigrationRequired {
                        reason: format!(
                            "legacy grant-closure row {legacy_key} changed after its recorded migration disposition"
                        ),
                    });
                }
                Self::ensure_grant_closure_order_floor(
                    write,
                    existing_migration.legacy_operation_order,
                )?;
                if let Some(current_key) = existing_migration.current_key.as_deref() {
                    let present = {
                        let current = write.open_table(GRANT_CLOSURE_CURRENT).map_err(storage)?;
                        current.get(current_key).map_err(storage)?.is_some()
                    };
                    if !present {
                        return Err(OrsError::IntegrityProblem {
                            record_type: "grant_closure_migration",
                            reason: format!(
                                "migration disposition for {legacy_key} names a missing current row"
                            ),
                        });
                    }
                }
                let mut legacy = write
                    .open_table(GRANT_CLOSURE_LEGACY_CURRENT)
                    .map_err(storage)?;
                legacy.remove(legacy_key.as_str()).map_err(storage)?;
                continue;
            }

            let current_key = Self::grant_closure_current_key(operation_identity.as_str());
            let existing_current = {
                let current = write.open_table(GRANT_CLOSURE_CURRENT).map_err(storage)?;
                current
                    .get(current_key.as_str())
                    .map_err(storage)?
                    .map(|value| {
                        decode_named::<DurableGrantClosureRecord>(value.value(), "grant_closure")
                    })
                    .transpose()?
            };

            if is_current_grant_closure_shape(&raw) {
                let record = decode_named::<DurableGrantClosureRecord>(&raw, "grant_closure")
                    .map_err(|error| OrsError::MigrationRequired {
                        reason: format!(
                            "legacy grant-closure row {legacy_key} has a v2 shape but failed current validation: {error}"
                        ),
                    })?;
                if record.commit.operation_id != operation_identity.as_str() {
                    return Err(OrsError::MigrationRequired {
                        reason: format!(
                            "legacy grant-closure row {legacy_key} carries operation identity {} instead of its key",
                            record.commit.operation_id
                        ),
                    });
                }
                Self::ensure_grant_closure_order_floor(write, record.operation_order)?;
                if let Some(existing) = existing_current {
                    if existing != record {
                        return Err(OrsError::MigrationRequired {
                            reason: format!(
                                "legacy grant-closure row {legacy_key} conflicts with the existing current v2 row"
                            ),
                        });
                    }
                } else {
                    let encoded = encode(&record)?;
                    let mut current = write.open_table(GRANT_CLOSURE_CURRENT).map_err(storage)?;
                    current
                        .insert(current_key.as_str(), encoded.as_str())
                        .map_err(storage)?;
                }
                let migration = GrantClosureMigrationRecord {
                    schema: GRANT_CLOSURE_MIGRATION_SCHEMA.to_owned(),
                    version: GRANT_CLOSURE_MIGRATION_VERSION,
                    operation_id: operation_identity.as_str().to_owned(),
                    legacy_key: legacy_key.clone(),
                    target_grant_id: record.commit.declaration.target_grant_id.clone(),
                    authority_root_ref: record.commit.declaration.authority_root_ref.clone(),
                    grant_graph_revision: record.commit.declaration.grant_graph_revision,
                    legacy_phase: record.phase,
                    legacy_state: match record.commit.state {
                        GrantClosureState::Active => "ACTIVE",
                        GrantClosureState::Revoked => "REVOKED",
                    }
                    .to_owned(),
                    legacy_operation_order: record.operation_order,
                    source_row_sha256: source_sha256,
                    legacy_row_json: raw.clone(),
                    disposition: GrantClosureMigrationDisposition::CurrentShapeCopied,
                    missing_fields: Vec::new(),
                    current_key: Some(current_key),
                    current_operation_order: Some(record.operation_order),
                    reason: "the legacy table row already carried the complete v2 contract; its exact fields were revalidated and copied"
                        .to_owned(),
                };
                let encoded = encode(&migration)?;
                let mut current = write.open_table(GRANT_CLOSURE_CURRENT).map_err(storage)?;
                current
                    .insert(migration_key.as_str(), encoded.as_str())
                    .map_err(storage)?;
                let mut legacy = write
                    .open_table(GRANT_CLOSURE_LEGACY_CURRENT)
                    .map_err(storage)?;
                legacy.remove(legacy_key.as_str()).map_err(storage)?;
                continue;
            }

            let legacy: LegacyGrantClosureRecord =
                decode_legacy_grant_closure_record(&raw).map_err(|error| {
                OrsError::MigrationRequired {
                    reason: format!(
                        "legacy grant-closure row {legacy_key} cannot be migrated losslessly: {error}"
                    ),
                }
            })?;
            if legacy.commit.operation_id.as_str() != operation_identity.as_str() {
                return Err(OrsError::MigrationRequired {
                    reason: format!(
                        "legacy grant-closure row {legacy_key} carries operation identity {} instead of its key",
                        legacy.commit.operation_id.as_str()
                    ),
                });
            }
            Self::ensure_grant_closure_order_floor(write, legacy.operation_order)?;
            let missing_fields = Self::legacy_grant_closure_missing_fields(&legacy);
            let (disposition, current_key, current_operation_order, reason) = if let Some(
                existing,
            ) =
                existing_current
            {
                if !Self::current_grant_closure_matches_legacy(&existing, &legacy) {
                    return Err(OrsError::MigrationRequired {
                        reason: format!(
                            "legacy grant-closure row {legacy_key} conflicts with the existing current v2 row"
                        ),
                    });
                }
                (
                        GrantClosureMigrationDisposition::LegacyShapeSupersededByCurrent,
                        Some(Self::grant_closure_current_key(operation_identity.as_str())),
                        Some(existing.operation_order),
                        "the retained v1 row is losslessly recorded beside an already matching current v2 row; absent v2 fields remain explicitly named"
                            .to_owned(),
                    )
            } else {
                (
                    GrantClosureMigrationDisposition::LegacyShapeRetained,
                    None,
                    None,
                    format!(
                        "the v1 row is retained byte-for-byte in the v2 migration disposition; no current authority is inferred; exact absent v2 fields: {}",
                        missing_fields.join(", ")
                    ),
                )
            };
            let migration = GrantClosureMigrationRecord {
                schema: GRANT_CLOSURE_MIGRATION_SCHEMA.to_owned(),
                version: GRANT_CLOSURE_MIGRATION_VERSION,
                operation_id: operation_identity.as_str().to_owned(),
                legacy_key: legacy_key.clone(),
                target_grant_id: legacy.commit.target_id.as_str().to_owned(),
                authority_root_ref: legacy.commit.authority_root.as_str().to_owned(),
                grant_graph_revision: legacy.commit.revision,
                legacy_phase: legacy.phase,
                legacy_state: legacy.commit.state.as_str().to_owned(),
                legacy_operation_order: legacy.operation_order,
                source_row_sha256: source_sha256,
                legacy_row_json: raw.clone(),
                disposition,
                missing_fields,
                current_key,
                current_operation_order,
                reason,
            };
            let encoded = encode(&migration)?;
            let mut current = write.open_table(GRANT_CLOSURE_CURRENT).map_err(storage)?;
            current
                .insert(migration_key.as_str(), encoded.as_str())
                .map_err(storage)?;
            let mut legacy = write
                .open_table(GRANT_CLOSURE_LEGACY_CURRENT)
                .map_err(storage)?;
            legacy.remove(legacy_key.as_str()).map_err(storage)?;
        }
        let current = write.open_table(GRANT_CLOSURE_CURRENT).map_err(storage)?;
        for entry in current.iter().map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let key_text = key.value();
            if !key_text.starts_with(GRANT_CLOSURE_MIGRATION_KEY_PREFIX) {
                continue;
            }
            let migration = Self::decode_grant_closure_migration(value.value())?;
            Self::validate_grant_closure_migration_binding(
                &migration,
                key_text,
                migration.operation_id.as_str(),
            )?;
            Self::ensure_grant_closure_order_floor(write, migration.legacy_operation_order)?;
            if let Some(current_key) = migration.current_key.as_deref() {
                let current_value =
                    current.get(current_key).map_err(storage)?.ok_or_else(|| {
                        OrsError::IntegrityProblem {
                            record_type: "grant_closure_migration",
                            reason: "migration disposition names a missing current row".to_owned(),
                        }
                    })?;
                let current_record: DurableGrantClosureRecord =
                    decode_named(current_value.value(), "grant_closure")?;
                if current_record.commit.operation_id != migration.operation_id
                    || Some(current_record.operation_order) != migration.current_operation_order
                {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "grant_closure_migration",
                        reason: "migration disposition does not bind the exact current row"
                            .to_owned(),
                    });
                }
                match migration.disposition {
                    GrantClosureMigrationDisposition::CurrentShapeCopied => {
                        let source = decode_named::<DurableGrantClosureRecord>(
                            &migration.legacy_row_json,
                            "grant_closure",
                        )?;
                        if current_record != source {
                            return Err(OrsError::IntegrityProblem {
                                record_type: "grant_closure_migration",
                                reason: "copied current row differs from retained source bytes"
                                    .to_owned(),
                            });
                        }
                    }
                    GrantClosureMigrationDisposition::LegacyShapeSupersededByCurrent => {
                        let source = decode_legacy_grant_closure_record(&migration.legacy_row_json)
                            .map_err(|error| OrsError::IntegrityProblem {
                                record_type: "grant_closure_migration",
                                reason: error.to_string(),
                            })?;
                        if !Self::current_grant_closure_matches_legacy(&current_record, &source) {
                            return Err(OrsError::IntegrityProblem {
                                record_type: "grant_closure_migration",
                                reason: "superseded current row differs from retained source shape"
                                    .to_owned(),
                            });
                        }
                    }
                    GrantClosureMigrationDisposition::LegacyShapeRetained => {
                        return Err(OrsError::IntegrityProblem {
                            record_type: "grant_closure_migration",
                            reason: "retained legacy disposition unexpectedly names a current row"
                                .to_owned(),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    fn persist_operational_record(
        write: &redb::WriteTransaction,
        key: &str,
        record: &DurableOperationalRecord,
    ) -> Result<(), OrsError> {
        let encoded = encode(record)?;
        {
            let mut current = write.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
            current.insert(key, encoded.as_str()).map_err(storage)?;
        }
        let history_key = format!("{:020}:{key}", record.operation_order);
        let mut history = write.open_table(OPERATIONAL_HISTORY).map_err(storage)?;
        history
            .insert(history_key.as_str(), encoded.as_str())
            .map_err(storage)?;
        Ok(())
    }

    fn mutate_operational(
        &self,
        kind: OperationalKind,
        input: OperationalRecordInput,
        require_existing: bool,
        allowed_prior: &[OperationalPhase],
        next_phase: OperationalPhase,
    ) -> Result<OperationalMutationReceipt, OrsError> {
        input.validate()?;
        let key = Self::operational_key(kind, &input.subject_id);
        let write = self.database.begin_write().map_err(storage)?;
        let existing = {
            let current = write.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
            current
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| {
                    decode_named::<DurableOperationalRecord>(value.value(), "operational_current")
                })
                .transpose()?
        };
        if let Some(existing) = existing {
            if existing.input.subject_id == input.subject_id
                && existing.input.record_id == input.record_id
                && existing.input != input
            {
                // The subject key plus operation identity is immutable.  This
                // check must precede every lifecycle transition so a changed
                // opaque payload cannot replace an Applying, Active, Fenced,
                // or Released row.
                return Err(OrsError::DuplicateConflict);
            }
            if existing.input.record_id == input.record_id {
                if existing.input == input && existing.phase == next_phase {
                    return Self::receipt_for(&existing);
                }
                return Err(OrsError::DuplicateConflict);
            }
            if !allowed_prior.contains(&existing.phase) {
                return Err(OrsError::InvalidTransition);
            }
            if !input
                .authority_epoch
                .succeeds(&existing.input.authority_epoch.current)
            {
                return Err(OrsError::InvalidEpochLineage);
            }
        } else if require_existing {
            return Err(OrsError::InvalidTransition);
        }
        let record = DurableOperationalRecord {
            kind,
            input,
            phase: next_phase,
            operation_order: Self::next_operational_order(&write)?,
            terminal_receipt_id: None,
            terminal_receipt_sha256: None,
            generation_cutover: None,
        };
        Self::persist_operational_record(&write, &key, &record)?;
        write.commit().map_err(storage)?;
        Self::receipt_for(&record)
    }

    fn transition_existing_operational(
        &self,
        kind: OperationalKind,
        subject: &crate::OperationIdentity,
        allowed_prior: &[OperationalPhase],
        next_phase: OperationalPhase,
        terminal_receipt: Option<&ReceiptEnvelope>,
    ) -> Result<OperationalMutationReceipt, OrsError> {
        let key = Self::operational_key(kind, subject);
        let write = self.database.begin_write().map_err(storage)?;
        let mut record = {
            let current = write.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
            let value = current
                .get(key.as_str())
                .map_err(storage)?
                .ok_or(OrsError::ReservationNotFound)?;
            decode_named::<DurableOperationalRecord>(value.value(), "operational_current")?
        };
        if record.phase == next_phase {
            if terminal_receipt.is_none()
                || record.terminal_receipt_id.as_ref().map(OpaqueLabel::as_str)
                    == terminal_receipt.map(|receipt| receipt.identity.receipt_id.as_str())
            {
                return Self::receipt_for(&record);
            }
            return Err(OrsError::DuplicateConflict);
        }
        if !allowed_prior.contains(&record.phase) {
            return Err(OrsError::InvalidTransition);
        }
        record.phase = next_phase;
        record.operation_order = Self::next_operational_order(&write)?;
        if let Some(receipt) = terminal_receipt {
            record.terminal_receipt_id =
                Some(OpaqueLabel::new(receipt.identity.receipt_id.as_str())?);
            record.terminal_receipt_sha256 = Some(receipt.identity.canonical_sha256.clone());
        }
        Self::persist_operational_record(&write, &key, &record)?;
        write.commit().map_err(storage)?;
        Self::receipt_for(&record)
    }

    fn generation_operational_input(
        record: &RuntimeGenerationCutoverRecord,
    ) -> Result<OperationalRecordInput, OrsError> {
        let epoch = record.old_epoch.value();
        let authority_epoch = EpochLineage {
            current: EpochIdentity {
                lineage_id: OpaqueLabel::new("generation-cutover")?,
                epoch,
            },
            predecessor: None,
        };
        let state_fence = StateFenceSnapshot::capture(
            &json!({
                "cutover_id": record.cutover_id,
                "route_scope": record.route_scope,
                "authority_epoch": epoch,
            }),
            epoch,
        )?;
        let payload =
            serde_json::to_vec(record).map_err(|error| OrsError::Encoding(error.to_string()))?;
        let payload_length = u64::try_from(payload.len()).map_err(|_| OrsError::PayloadTooLarge)?;
        OperationalRecordInput::immutable_locator(
            OperationalRecordContext {
                record_id: OpaqueLabel::new(format!("generation-cutover:{}", record.cutover_id))?,
                subject_id: OpaqueLabel::new(record.route_scope.clone())?,
                authority_epoch,
                state_fence,
                created_at_ms: 0,
                cleanup_after_ms: None,
            },
            PlatformHandle::new(format!("ors:generation-cutover:{}", record.cutover_id))
                .map_err(|error| OrsError::Contract(error.to_string()))?,
            crate::model::sha256_hex(&payload),
            payload_length,
        )
    }

    fn generation_snapshot(
        durable: &DurableOperationalRecord,
    ) -> Result<GenerationCutoverSnapshot, OrsError> {
        let record =
            durable
                .generation_cutover
                .clone()
                .ok_or_else(|| OrsError::IntegrityProblem {
                    record_type: "operational_record",
                    reason: "generation operational record has no typed cutover".to_owned(),
                })?;
        let receipt = GenerationCutoverReceipt::from_receipt(Self::receipt_for(durable)?);
        Ok(GenerationCutoverSnapshot::new(
            record,
            durable.operation_order,
            receipt,
        ))
    }

    fn decode_operational_current(
        write: &redb::WriteTransaction,
        key: &str,
    ) -> Result<Option<DurableOperationalRecord>, OrsError> {
        let current = write.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
        current
            .get(key)
            .map_err(storage)?
            .map(|value| {
                decode_named::<DurableOperationalRecord>(value.value(), "operational_current")
            })
            .transpose()
    }

    fn grant_graph_revision_from_write(
        write: &redb::WriteTransaction,
        authority_root: &str,
    ) -> Result<Option<DurableGrantGraphRevision>, OrsError> {
        let key = format!("grant_graph_revision:{authority_root}");
        let current = write
            .open_table(GRANT_GRAPH_REVISION_CURRENT)
            .map_err(storage)?;
        let Some(value) = current.get(key.as_str()).map_err(storage)? else {
            return Ok(None);
        };
        let row: DurableGrantGraphRevision = decode_named(value.value(), "grant_graph_revision")?;
        if row.root.as_str() != authority_root {
            return Err(OrsError::IntegrityProblem {
                record_type: "grant_graph_revision",
                reason: "current revision key or lineage root mismatch".to_owned(),
            });
        }
        Ok(Some(row))
    }

    fn plan_closure_row(
        write: &redb::WriteTransaction,
        authority: &AuthorityBinding,
        kind: OperationalKind,
        input: &crate::OperationalRecordInput,
    ) -> Result<ClosureRowPlan, OrsError> {
        crate::model::validate_grant_closure_input(authority, input)?;
        let key = Self::operational_key(kind, &input.subject_id);
        let current =
            Self::decode_operational_current(write, &key)?.ok_or(OrsError::InvalidTransition)?;
        if current.kind != kind
            || current.input.subject_id != input.subject_id
            || current.generation_cutover.is_some()
            || !input
                .authority_epoch
                .succeeds(&current.input.authority_epoch.current)
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "grant_closure_member",
                reason:
                    "current operational row identity, kind, or epoch disagrees with the request"
                        .to_owned(),
            });
        }
        let mut expected_input = input.clone();
        expected_input.record_id = current.input.record_id.clone();
        let (record, transitioned) = match current.phase {
            OperationalPhase::Active => {
                if current.input.record_id == input.record_id || current.input != expected_input {
                    return Err(OrsError::DuplicateConflict);
                }
                let mut next = current.clone();
                next.input = input.clone();
                next.phase = OperationalPhase::Fenced;
                next.operation_order = 0;
                next.terminal_receipt_id = None;
                next.terminal_receipt_sha256 = None;
                (next, true)
            }
            OperationalPhase::Fenced => {
                if current.input != *input {
                    return Err(OrsError::DuplicateConflict);
                }
                (current, false)
            }
            _ => return Err(OrsError::InvalidTransition),
        };
        Ok(ClosureRowPlan {
            key,
            record,
            transitioned,
        })
    }

    fn plan_grant_closure_member_rows(
        write: &redb::WriteTransaction,
        authority: &AuthorityBinding,
        revocations: &[CapabilityGrantRevocation],
    ) -> Result<Vec<ClosureRowPlan>, OrsError> {
        revocations
            .iter()
            .map(|revocation| {
                Self::plan_closure_row(
                    write,
                    authority,
                    OperationalKind::CapabilityGrant,
                    revocation.record(),
                )
            })
            .collect()
    }

    fn plan_grant_closure_introduction_rows(
        write: &redb::WriteTransaction,
        authority: &AuthorityBinding,
        fences: &[CapabilityIntroductionFence],
    ) -> Result<Vec<ClosureRowPlan>, OrsError> {
        fences
            .iter()
            .map(|fence| {
                Self::plan_closure_row(
                    write,
                    authority,
                    OperationalKind::CapabilityIntroduction,
                    fence.record(),
                )
            })
            .collect()
    }

    /// Persists one candidate transition before the cutover linearization
    /// point.  The candidate is stored in the canonical operational current
    /// and history projections and is never an active route.
    pub fn stage_generation_cutover(
        &self,
        record: RuntimeGenerationCutoverRecord,
    ) -> Result<GenerationCutoverSnapshot, OrsError> {
        record
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        if record.state != GenerationCutoverState::Armed {
            return Err(OrsError::InvalidTransition);
        }
        let input = Self::generation_operational_input(&record)?;
        let key = Self::operational_key(OperationalKind::GenerationTransition, &input.subject_id);
        let cutover_key =
            Self::operational_key(OperationalKind::GenerationCutover, &input.subject_id);
        let write = self.database.begin_write().map_err(storage)?;
        if let Some(existing) = Self::decode_operational_current(&write, &cutover_key)? {
            let committed = RuntimeGenerationCutoverRecord {
                state: GenerationCutoverState::Committed,
                ..record.clone()
            };
            if existing.kind == OperationalKind::GenerationCutover
                && existing.phase == OperationalPhase::Active
                && existing
                    .generation_cutover
                    .as_ref()
                    .is_some_and(|value| value == &committed)
            {
                return Self::generation_snapshot(&existing);
            }
        }
        if let Some(existing) = Self::decode_operational_current(&write, &key)? {
            if existing.kind == OperationalKind::GenerationTransition
                && existing.phase == OperationalPhase::Applying
                && existing.input == input
                && existing.generation_cutover.as_ref() == Some(&record)
            {
                return Self::generation_snapshot(&existing);
            }
            return Err(OrsError::DuplicateConflict);
        }
        let durable = DurableOperationalRecord {
            kind: OperationalKind::GenerationTransition,
            input,
            phase: OperationalPhase::Applying,
            operation_order: Self::next_operational_order(&write)?,
            terminal_receipt_id: None,
            terminal_receipt_sha256: None,
            generation_cutover: Some(record),
        };
        Self::persist_operational_record(&write, &key, &durable)?;
        write.commit().map_err(storage)?;
        Self::generation_snapshot(&durable)
    }

    /// Commits one staged transition and records the route atomically in the
    /// canonical operational current/history projections.  The commit record
    /// is the sole durable cutover linearization point.
    #[allow(
        clippy::too_many_lines,
        reason = "the cutover transaction validates route, epoch, receipt, and projection atomically"
    )]
    pub fn commit_generation_cutover_state(
        &self,
        record: RuntimeGenerationCutoverRecord,
    ) -> Result<GenerationCutoverSnapshot, OrsError> {
        record
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        if record.state != GenerationCutoverState::Armed {
            return Err(OrsError::InvalidTransition);
        }
        let expected_input = Self::generation_operational_input(&record)?;
        let route_key = Self::operational_key(
            OperationalKind::GenerationCutover,
            &expected_input.subject_id,
        );
        let transition_key = Self::operational_key(
            OperationalKind::GenerationTransition,
            &expected_input.subject_id,
        );
        let write = self.database.begin_write().map_err(storage)?;

        if let Some(existing) = Self::decode_operational_current(&write, &route_key)? {
            let committed = RuntimeGenerationCutoverRecord {
                state: GenerationCutoverState::Committed,
                ..record.clone()
            };
            if existing.kind == OperationalKind::GenerationCutover
                && existing.phase == OperationalPhase::Active
                && existing
                    .generation_cutover
                    .as_ref()
                    .is_some_and(|value| value == &committed)
            {
                return Self::generation_snapshot(&existing);
            }
        }

        let transition = Self::decode_operational_current(&write, &transition_key)?
            .ok_or(OrsError::ReservationNotFound)?;
        if transition.kind != OperationalKind::GenerationTransition
            || transition.phase != OperationalPhase::Applying
            || transition.input != expected_input
            || transition.generation_cutover.as_ref() != Some(&record)
        {
            return Err(OrsError::DuplicateConflict);
        }

        let existing_route = Self::decode_operational_current(&write, &route_key)?;
        if let Some(existing) = &existing_route {
            let prior =
                existing
                    .generation_cutover
                    .as_ref()
                    .ok_or_else(|| OrsError::IntegrityProblem {
                        record_type: "operational_current",
                        reason: "generation route is missing typed cutover".to_owned(),
                    })?;
            if existing.kind != OperationalKind::GenerationCutover
                || existing.phase != OperationalPhase::Active
                || prior.state != GenerationCutoverState::Committed
            {
                return Err(OrsError::InvalidTransition);
            }
            if prior.new_epoch.value() > record.old_epoch.value()
                || Some(prior.new_generation) != record.old_generation
            {
                return Err(OrsError::InvalidEpochLineage);
            }
        } else if record.old_generation.is_some() {
            return Err(OrsError::InvalidEpochLineage);
        }

        let global_epoch = {
            let current = write.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
            let mut maximum = None;
            for row in current.iter().map_err(storage)? {
                let (_, value) = row.map_err(storage)?;
                let candidate: DurableOperationalRecord =
                    decode_named(value.value(), "operational_current")?;
                if candidate.kind == OperationalKind::GenerationCutover
                    && candidate.phase == OperationalPhase::Active
                    && let Some(cutover) = candidate.generation_cutover
                {
                    if cutover.state != GenerationCutoverState::Committed {
                        return Err(OrsError::IntegrityProblem {
                            record_type: "operational_current",
                            reason: "active generation route is not committed".to_owned(),
                        });
                    }
                    maximum = Some(maximum.map_or(cutover.new_epoch.value(), |value: u64| {
                        value.max(cutover.new_epoch.value())
                    }));
                }
            }
            maximum
        };
        if let Some(global_epoch) = global_epoch
            && record.old_epoch.value() != global_epoch
        {
            return Err(OrsError::InvalidEpochLineage);
        }
        if global_epoch.is_none() && record.old_epoch.value() != 1 {
            return Err(OrsError::InvalidEpochLineage);
        }

        let committed = RuntimeGenerationCutoverRecord {
            state: GenerationCutoverState::Committed,
            ..record
        };
        let durable = DurableOperationalRecord {
            kind: OperationalKind::GenerationCutover,
            input: transition.input,
            phase: OperationalPhase::Active,
            operation_order: Self::next_operational_order(&write)?,
            terminal_receipt_id: None,
            terminal_receipt_sha256: None,
            generation_cutover: Some(committed),
        };
        Self::persist_operational_record(&write, &route_key, &durable)?;
        {
            let mut current = write.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
            current.remove(transition_key.as_str()).map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Self::generation_snapshot(&durable)
    }

    /// Returns the bounded latest committed route set from canonical current
    /// operational records, ordered by their durable operation order.
    pub fn latest_generation_cutovers(
        &self,
        limit: u16,
    ) -> Result<Vec<GenerationCutoverSnapshot>, OrsError> {
        if limit == 0 || limit > crate::MAX_RECOVERY_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
        let mut records = Vec::new();
        for row in table.iter().map_err(storage)? {
            let (_, value) = row.map_err(storage)?;
            let durable: DurableOperationalRecord =
                decode_named(value.value(), "operational_current")?;
            if durable.kind != OperationalKind::GenerationCutover
                || durable.phase != OperationalPhase::Active
            {
                continue;
            }
            let Some(record) = durable.generation_cutover.as_ref() else {
                // Older generic GenerationCutover records have no route
                // projection and are not allowed to become runtime authority.
                continue;
            };
            if record.state != GenerationCutoverState::Committed {
                return Err(OrsError::IntegrityProblem {
                    record_type: "operational_current",
                    reason: "active generation route is not committed".to_owned(),
                });
            }
            if records.len() == usize::from(limit) {
                return Err(OrsError::ProjectionLimitExceeded);
            }
            records.push(Self::generation_snapshot(&durable)?);
        }
        records.sort_by_key(GenerationCutoverSnapshot::operation_order);
        Ok(records)
    }

    /// Reconciles staged candidates through the normative
    /// `Reconciling -> FailedRequiresForwardCutover` runtime path.  The
    /// resulting records remain fenced evidence in the canonical current and
    /// history projections and can never activate a route.
    pub fn reconcile_staged_generation_cutovers(
        &self,
        limit: u16,
    ) -> Result<Vec<GenerationCutoverSnapshot>, OrsError> {
        if limit == 0 || limit > crate::MAX_RECOVERY_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
        let mut pending = Vec::new();
        for row in table.iter().map_err(storage)? {
            let (key, value) = row.map_err(storage)?;
            let durable: DurableOperationalRecord =
                decode_named(value.value(), "operational_current")?;
            let Some(record) = durable.generation_cutover.as_ref() else {
                continue;
            };
            if durable.kind == OperationalKind::GenerationTransition
                && matches!(
                    record.state,
                    GenerationCutoverState::Armed
                        | GenerationCutoverState::Reconciling
                        | GenerationCutoverState::FailedRequiresForwardCutover
                )
            {
                if pending.len() == usize::from(limit) {
                    return Err(OrsError::ProjectionLimitExceeded);
                }
                pending.push((key.value().to_owned(), durable));
            }
        }
        drop(table);
        drop(read);

        let write = self.database.begin_write().map_err(storage)?;
        let mut snapshots = Vec::with_capacity(pending.len());
        for (key, prior) in pending {
            let Some(prior_record) = prior.generation_cutover.clone() else {
                return Err(OrsError::IntegrityProblem {
                    record_type: "operational_current",
                    reason: "generation transition has no typed cutover".to_owned(),
                });
            };
            if prior_record.state == GenerationCutoverState::FailedRequiresForwardCutover {
                snapshots.push(Self::generation_snapshot(&prior)?);
                continue;
            }
            let reconciling = match prior_record.state {
                GenerationCutoverState::Armed => RuntimeGenerationCutoverRecord {
                    state: prior_record
                        .state
                        .transition_to(GenerationCutoverState::Reconciling)
                        .map_err(|error| OrsError::Contract(error.to_string()))?,
                    ..prior_record.clone()
                },
                GenerationCutoverState::Reconciling => prior_record.clone(),
                _ => return Err(OrsError::InvalidTransition),
            };
            if prior_record.state == GenerationCutoverState::Armed {
                let mut evidence = prior.clone();
                evidence.phase = OperationalPhase::Reconciling;
                evidence.operation_order = Self::next_operational_order(&write)?;
                evidence.generation_cutover = Some(reconciling.clone());
                Self::persist_operational_record(&write, &key, &evidence)?;
            }
            let failed = RuntimeGenerationCutoverRecord {
                state: reconciling
                    .state
                    .transition_to(GenerationCutoverState::FailedRequiresForwardCutover)
                    .map_err(|error| OrsError::Contract(error.to_string()))?,
                ..reconciling
            };
            let mut evidence = prior;
            evidence.phase = OperationalPhase::Fenced;
            evidence.operation_order = Self::next_operational_order(&write)?;
            evidence.generation_cutover = Some(failed);
            Self::persist_operational_record(&write, &key, &evidence)?;
            snapshots.push(Self::generation_snapshot(&evidence)?);
        }
        write.commit().map_err(storage)?;
        Ok(snapshots)
    }

    /// Stages an enriched cutover candidate before the durable linearization
    /// point (I14.14 step 7: classify every in-flight request and persist the
    /// record). The staged candidate is durable but never an active route:
    /// snapshots and recovery consult committed rows only.
    pub fn stage_cutover_ownership(
        &self,
        record: GenerationCutoverOwnership,
    ) -> Result<GenerationCutoverOwnership, OrsError> {
        record.validate()?;
        if record.state != GenerationCutoverState::Armed {
            return Err(OrsError::InvalidTransition);
        }
        if record.linearization_record_id.is_some() {
            return Err(OrsError::InvalidField {
                field: "cutover_ownership_linearization",
                reason: "a staged candidate has no linearization identity",
            });
        }
        let write = self.database.begin_write().map_err(storage)?;
        {
            let current = write.open_table(CUTOVER_OWNERSHIP).map_err(storage)?;
            if let Some(existing) = current.get(record.cutover_id.as_str()).map_err(storage)? {
                let stored: StoredCutoverOwnership =
                    decode_named(existing.value(), "cutover_ownership")?;
                if stored.record == record {
                    return Ok(stored.record);
                }
                return Err(OrsError::DuplicateConflict);
            }
        }
        let stored = StoredCutoverOwnership {
            operation_order: Self::next_operational_order(&write)?,
            record: record.clone(),
        };
        {
            let mut current = write.open_table(CUTOVER_OWNERSHIP).map_err(storage)?;
            current
                .insert(record.cutover_id.as_str(), encode(&stored)?.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(record)
    }

    /// Commits one staged enriched cutover in a single write transaction
    /// (I14.14 step 8: persist the record, switch new-admission routing to
    /// the candidate, issue a strictly newer epoch, fence old-generation
    /// authority, and fix the old-operation allowlist). The single
    /// `write.commit()` is the durable linearization point: crash before it
    /// leaves the old route active, crash after it reconstructs the candidate
    /// route from the committed record before accepting work.
    #[allow(
        clippy::too_many_lines,
        reason = "the ownership commit validates lineage, epoch, receipt, and projection atomically"
    )]
    pub fn commit_cutover_ownership(
        &self,
        cutover_id: &str,
    ) -> Result<
        (
            GenerationCutoverOwnership,
            GenerationCutoverOwnershipReceipt,
        ),
        OrsError,
    > {
        let write = self.database.begin_write().map_err(storage)?;
        let staged = {
            let current = write.open_table(CUTOVER_OWNERSHIP).map_err(storage)?;
            let Some(existing) = current.get(cutover_id).map_err(storage)? else {
                return Err(OrsError::ReservationNotFound);
            };
            let stored: StoredCutoverOwnership =
                decode_named(existing.value(), "cutover_ownership")?;
            stored
        };
        if staged.record.state == GenerationCutoverState::Committed {
            let receipt = GenerationCutoverOwnershipReceipt::from_committed(&staged.record)?;
            return Ok((staged.record, receipt));
        }
        if staged.record.state != GenerationCutoverState::Armed {
            return Err(OrsError::InvalidTransition);
        }
        let mut maximum_new_epoch = None;
        let mut prior_for_scope = None;
        {
            let current = write.open_table(CUTOVER_OWNERSHIP).map_err(storage)?;
            for row in current.iter().map_err(storage)? {
                let (_, value) = row.map_err(storage)?;
                let stored: StoredCutoverOwnership =
                    decode_named(value.value(), "cutover_ownership")?;
                if stored.record.state != GenerationCutoverState::Committed {
                    continue;
                }
                let epoch = stored.record.new_epoch.value();
                maximum_new_epoch =
                    Some(maximum_new_epoch.map_or(epoch, |prior: u64| prior.max(epoch)));
                if stored.record.scope.route_scope_hash == staged.record.scope.route_scope_hash {
                    let advances = prior_for_scope.as_ref().is_none_or(
                        |prior: &GenerationCutoverOwnership| {
                            stored.record.new_epoch.value() > prior.new_epoch.value()
                        },
                    );
                    if !advances {
                        return Err(OrsError::IntegrityProblem {
                            record_type: "cutover_ownership",
                            reason: "committed cutover epoch does not advance its scope".to_owned(),
                        });
                    }
                    prior_for_scope = Some(stored.record);
                }
            }
        }
        if let Some(prior) = prior_for_scope {
            if Some(prior.new_generation) != staged.record.old_generation
                || prior.new_epoch.value() != staged.record.old_epoch.value()
            {
                return Err(OrsError::InvalidEpochLineage);
            }
        } else if staged.record.old_generation.is_some() {
            return Err(OrsError::InvalidEpochLineage);
        }
        if let Some(maximum) = maximum_new_epoch
            && staged.record.new_epoch.value() <= maximum
        {
            return Err(OrsError::InvalidEpochLineage);
        }
        let order = Self::next_operational_order(&write)?;
        let committed = GenerationCutoverOwnership {
            state: GenerationCutoverState::Committed,
            linearization_record_id: Some(format!("ors:cutover-ownership:{cutover_id}#{order}")),
            ..staged.record.clone()
        };
        let stored = StoredCutoverOwnership {
            operation_order: order,
            record: committed.clone(),
        };
        {
            let mut current = write.open_table(CUTOVER_OWNERSHIP).map_err(storage)?;
            current
                .insert(cutover_id, encode(&stored)?.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        let receipt = GenerationCutoverOwnershipReceipt::from_committed(&committed)?;
        Ok((committed, receipt))
    }

    /// Loads one ownership record by cutover identity.
    pub fn load_cutover_ownership(
        &self,
        cutover_id: &str,
    ) -> Result<Option<GenerationCutoverOwnership>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let current = read.open_table(CUTOVER_OWNERSHIP).map_err(storage)?;
        let Some(existing) = current.get(cutover_id).map_err(storage)? else {
            return Ok(None);
        };
        let stored: StoredCutoverOwnership = decode_named(existing.value(), "cutover_ownership")?;
        Ok(Some(stored.record))
    }

    /// Returns the committed ownership rows ordered by their durable
    /// operation order. Recovery rebuilds the active route snapshot from
    /// exactly this set; staged candidates are excluded so a pre-commit
    /// candidate can never become active.
    pub fn latest_committed_cutover_ownership(
        &self,
        limit: u16,
    ) -> Result<Vec<GenerationCutoverOwnership>, OrsError> {
        if limit == 0 || limit > crate::MAX_RECOVERY_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        let read = self.database.begin_read().map_err(storage)?;
        let current = read.open_table(CUTOVER_OWNERSHIP).map_err(storage)?;
        let mut ordered: Vec<(u64, GenerationCutoverOwnership)> = Vec::new();
        for row in current.iter().map_err(storage)? {
            let (_, value) = row.map_err(storage)?;
            let stored: StoredCutoverOwnership = decode_named(value.value(), "cutover_ownership")?;
            if stored.record.state != GenerationCutoverState::Committed {
                continue;
            }
            if ordered.len() == usize::from(limit) {
                return Err(OrsError::ProjectionLimitExceeded);
            }
            ordered.push((stored.operation_order, stored.record));
        }
        ordered.sort_by_key(|(order, _)| *order);
        Ok(ordered.into_iter().map(|(_, record)| record).collect())
    }

    /// Fences staged candidates that never reached the linearization point.
    /// The resulting rows remain fenced evidence and can never activate a
    /// route: snapshot recovery consults committed rows only.
    pub fn reconcile_staged_cutover_ownership(
        &self,
        limit: u16,
    ) -> Result<Vec<GenerationCutoverOwnership>, OrsError> {
        if limit == 0 || limit > crate::MAX_RECOVERY_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        let pending = {
            let read = self.database.begin_read().map_err(storage)?;
            let current = read.open_table(CUTOVER_OWNERSHIP).map_err(storage)?;
            let mut pending = Vec::new();
            for row in current.iter().map_err(storage)? {
                let (key, value) = row.map_err(storage)?;
                let stored: StoredCutoverOwnership =
                    decode_named(value.value(), "cutover_ownership")?;
                if stored.record.state == GenerationCutoverState::Armed {
                    if pending.len() == usize::from(limit) {
                        return Err(OrsError::ProjectionLimitExceeded);
                    }
                    pending.push((key.value().to_owned(), stored));
                }
            }
            pending
        };
        let write = self.database.begin_write().map_err(storage)?;
        let mut fenced = Vec::with_capacity(pending.len());
        for (key, mut stored) in pending {
            stored.record.state = GenerationCutoverState::FailedRequiresForwardCutover;
            stored.operation_order = Self::next_operational_order(&write)?;
            {
                let mut current = write.open_table(CUTOVER_OWNERSHIP).map_err(storage)?;
                current
                    .insert(key.as_str(), encode(&stored)?.as_str())
                    .map_err(storage)?;
            }
            fenced.push(stored.record);
        }
        write.commit().map_err(storage)?;
        Ok(fenced)
    }

    /// Commits one authority replay snapshot with a receipt-fenced compare
    /// and swap. The expected receipt is checked while the write transaction
    /// owns the ORS serialization point; every successful replacement gets a
    /// new operation order and an additional history row.
    pub fn commit_authority_snapshot_cas(
        &self,
        snapshot: KernelAuthoritySnapshot,
        expected: Option<&AuthoritySnapshotReceipt>,
    ) -> Result<AuthoritySnapshotReceipt, OrsError> {
        let input = snapshot.0;
        input.validate()?;
        let key = Self::operational_key(OperationalKind::AuthoritySnapshot, &input.subject_id);
        let write = self.database.begin_write().map_err(storage)?;
        let existing = Self::decode_operational_current(&write, &key)?;
        match expected {
            None if existing.is_some() => return Err(OrsError::DuplicateConflict),
            None => {}
            Some(expected) => {
                let Some(existing) = existing.as_ref() else {
                    return Err(OrsError::DuplicateConflict);
                };
                if existing.kind != OperationalKind::AuthoritySnapshot
                    || existing.phase != OperationalPhase::Active
                    || existing.input.subject_id != input.subject_id
                    || existing.input.record_id != input.record_id
                {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "authority_snapshot",
                        reason: "current snapshot identity or phase is invalid".to_owned(),
                    });
                }
                existing.input.validate()?;
                if existing.input.authority_epoch != input.authority_epoch
                    || existing.input.state_fence != input.state_fence
                    || existing.input.created_at_ms != input.created_at_ms
                    || existing.input.cleanup_after_ms != input.cleanup_after_ms
                {
                    return Err(OrsError::FenceMismatch);
                }
                let actual = AuthoritySnapshotReceipt::from_receipt(Self::receipt_for(existing)?);
                if actual != *expected {
                    return Err(OrsError::DuplicateConflict);
                }
            }
        }
        let durable = DurableOperationalRecord {
            kind: OperationalKind::AuthoritySnapshot,
            input,
            phase: OperationalPhase::Active,
            operation_order: Self::next_operational_order(&write)?,
            terminal_receipt_id: None,
            terminal_receipt_sha256: None,
            generation_cutover: None,
        };
        Self::persist_operational_record(&write, &key, &durable)?;
        write.commit().map_err(storage)?;
        Ok(AuthoritySnapshotReceipt::from_receipt(Self::receipt_for(
            &durable,
        )?))
    }
    fn grant_closure_receipt_refs(
        plans: &[ClosureRowPlan],
    ) -> Result<Vec<GrantClosureOrsReceiptRef>, OrsError> {
        plans
            .iter()
            .map(|plan| {
                let receipt = Self::receipt_for(&plan.record)?;
                Ok(GrantClosureOrsReceiptRef {
                    record_id: receipt.record_id().as_str().to_owned(),
                    subject_id: receipt.subject_id().as_str().to_owned(),
                    operation_order: receipt.operation_order(),
                    state: GrantClosureState::Revoked,
                    state_sha256: receipt.state_sha256().to_owned(),
                })
            })
            .collect()
    }

    fn grant_closure_commit_from_request(
        request: &GrantClosureFenceRequest,
        member_plans: &[ClosureRowPlan],
        introduction_plans: &[ClosureRowPlan],
    ) -> Result<GrantClosureCommit, OrsError> {
        let commit = GrantClosureCommit {
            schema: GRANT_CLOSURE_SCHEMA.to_owned(),
            version: GRANT_CLOSURE_VERSION,
            operation_id: request.operation_id.clone(),
            idempotency_digest: request.idempotency_digest.clone(),
            declaration: request.declaration.clone(),
            authority: request.authority.clone(),
            proof_ceiling: request.proof_ceiling,
            authority_receipt: request.authority_receipt.clone(),
            ors_member_receipts: Self::grant_closure_receipt_refs(member_plans)?,
            fenced_introductions: request
                .fenced_introductions
                .iter()
                .map(|identity| identity.as_str().to_owned())
                .collect(),
            ors_introduction_receipts: Self::grant_closure_receipt_refs(introduction_plans)?,
            canonical_receipt: request.canonical_receipt.clone(),
            state: GrantClosureState::Revoked,
        };
        crate::model::validate_grant_closure_contract(&commit)?;
        Ok(commit)
    }

    fn grant_closure_fence_receipt(
        commit: &GrantClosureCommit,
        closure_record: &DurableGrantClosureRecord,
        member_plans: &[ClosureRowPlan],
        introduction_plans: &[ClosureRowPlan],
    ) -> Result<GrantClosureFenceReceipt, OrsError> {
        let closure_receipt =
            GrantClosureCommitReceipt::from_receipt(Self::closure_receipt_for(closure_record)?);
        let member_receipts = member_plans
            .iter()
            .map(|plan| {
                Ok(AuthorityRevocationReceipt::from_receipt(Self::receipt_for(
                    &plan.record,
                )?))
            })
            .collect::<Result<Vec<_>, OrsError>>()?;
        let introduction_receipts = introduction_plans
            .iter()
            .map(|plan| {
                Ok(CapabilityIntroductionReceipt::from_receipt(
                    Self::receipt_for(&plan.record)?,
                ))
            })
            .collect::<Result<Vec<_>, OrsError>>()?;
        Ok(GrantClosureFenceReceipt::from_parts(
            commit.clone(),
            closure_receipt,
            member_receipts,
            introduction_receipts,
        ))
    }

    /// Commits a complete owner-declared grant closure and all presented ORS
    /// member fences in one `RedDB` write transaction.
    #[allow(
        clippy::too_many_lines,
        reason = "the atomic transaction keeps revision, every member, and the closure receipt in one fail-closed sequence"
    )]
    pub fn commit_grant_closure_fence(
        &self,
        request: &GrantClosureFenceRequest,
    ) -> Result<GrantClosureFenceReceipt, OrsError> {
        request.validate()?;
        let closure_key = format!("grant_closure:{}", request.operation_id);
        let write = self.database.begin_write().map_err(storage)?;
        let existing = {
            let current = write.open_table(GRANT_CLOSURE_CURRENT).map_err(storage)?;
            current
                .get(closure_key.as_str())
                .map_err(storage)?
                .map(|value| {
                    decode_named::<DurableGrantClosureRecord>(value.value(), "grant_closure")
                })
                .transpose()?
        };
        if existing.is_none()
            && let Some(migration) =
                Self::grant_closure_migration_from_write(&write, request.operation_id.as_str())?
        {
            return Err(Self::grant_closure_migration_refusal(&migration));
        }
        let watermark = Self::grant_graph_revision_from_write(
            &write,
            request.declaration.authority_root_ref.as_str(),
        )?;
        if existing.is_none() {
            let Some(retained) = watermark.as_ref() else {
                return Err(OrsError::MigrationRequired {
                    reason:
                        "grant-closure fencing requires a pre-existing owner graph revision head"
                            .to_owned(),
                });
            };
            if retained.revision != request.declaration.grant_graph_revision {
                return Err(OrsError::InvalidField {
                    field: "grant_closure_revision",
                    reason: "durable grant-graph revision does not match the closure",
                });
            }
        }

        if let Some(existing) = existing {
            if existing.phase != OperationalPhase::Fenced {
                return Err(OrsError::DuplicateConflict);
            }
            if watermark.is_none() {
                return Err(OrsError::MigrationRequired {
                    reason: "committed grant closure has no durable graph-revision watermark"
                        .to_owned(),
                });
            }
            if watermark.as_ref().is_some_and(|retained| {
                retained.revision != request.declaration.grant_graph_revision
            }) {
                return Err(OrsError::InvalidField {
                    field: "grant_closure_revision",
                    reason: "durable grant-graph revision does not match the closure",
                });
            }
            let member_plans = Self::plan_grant_closure_member_rows(
                &write,
                &request.authority,
                &request.grant_revocations,
            )?;
            let introduction_plans = Self::plan_grant_closure_introduction_rows(
                &write,
                &request.authority,
                &request.introduction_fences,
            )?;
            if member_plans.iter().any(|plan| plan.transitioned)
                || introduction_plans.iter().any(|plan| plan.transitioned)
            {
                return Err(OrsError::MigrationRequired {
                    reason: "committed grant closure is missing one or more exact member fences"
                        .to_owned(),
                });
            }
            let commit = Self::grant_closure_commit_from_request(
                request,
                &member_plans,
                &introduction_plans,
            )?;
            if commit != existing.commit {
                return Err(OrsError::DuplicateConflict);
            }
            return Self::grant_closure_fence_receipt(
                &commit,
                &existing,
                &member_plans,
                &introduction_plans,
            );
        }

        let mut member_plans = Self::plan_grant_closure_member_rows(
            &write,
            &request.authority,
            &request.grant_revocations,
        )?;
        let mut introduction_plans = Self::plan_grant_closure_introduction_rows(
            &write,
            &request.authority,
            &request.introduction_fences,
        )?;
        for plan in member_plans
            .iter_mut()
            .chain(introduction_plans.iter_mut())
            .filter(|plan| plan.transitioned)
        {
            plan.record.operation_order = Self::next_operational_order(&write)?;
        }
        let commit =
            Self::grant_closure_commit_from_request(request, &member_plans, &introduction_plans)?;
        for plan in member_plans.iter().chain(introduction_plans.iter()) {
            if plan.transitioned {
                Self::persist_operational_record(&write, &plan.key, &plan.record)?;
            }
        }
        let closure_record = DurableGrantClosureRecord {
            commit,
            phase: OperationalPhase::Fenced,
            operation_order: Self::next_operational_order(&write)?,
        };
        let encoded = encode(&closure_record)?;
        {
            let mut current = write.open_table(GRANT_CLOSURE_CURRENT).map_err(storage)?;
            current
                .insert(closure_key.as_str(), encoded.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Self::grant_closure_fence_receipt(
            &closure_record.commit,
            &closure_record,
            &member_plans,
            &introduction_plans,
        )
    }

    /// Records the canonical second-phase receipt link for one already
    /// committed closure operation without rewriting its first-phase commit.
    pub fn link_grant_closure_canonical_receipt(
        &self,
        operation_id: &OperationIdentity,
        canonical_receipt: &ReceiptIdentity,
    ) -> Result<GrantClosureProjection, OrsError> {
        crate::model::validate_grant_closure_canonical_receipt(canonical_receipt)?;
        let operation_text = operation_id.as_str();
        let closure_key = Self::grant_closure_current_key(operation_text);
        let second_phase_key = Self::grant_closure_second_phase_key(operation_text);
        let write = self.database.begin_write().map_err(storage)?;
        let closure = {
            let current = write.open_table(GRANT_CLOSURE_CURRENT).map_err(storage)?;
            let Some(value) = current.get(closure_key.as_str()).map_err(storage)? else {
                drop(current);
                if let Some(migration) =
                    Self::grant_closure_migration_from_write(&write, operation_text)?
                {
                    return Err(Self::grant_closure_migration_refusal(&migration));
                }
                return Err(OrsError::ReservationNotFound);
            };
            let record: DurableGrantClosureRecord = decode_named(value.value(), "grant_closure")?;
            if record.commit.operation_id.as_str() != operation_text {
                return Err(OrsError::IntegrityProblem {
                    record_type: "grant_closure",
                    reason: "current grant-closure key or operation identity mismatch".to_owned(),
                });
            }
            record
        };
        if !Self::grant_closure_phase_is_committed(closure.phase) {
            return Err(OrsError::InvalidTransition);
        }
        if let Some(first_phase) = &closure.commit.canonical_receipt
            && first_phase != canonical_receipt
        {
            return Err(OrsError::DuplicateConflict);
        }
        let existing_second_phase = {
            let table = write
                .open_table(GRANT_CLOSURE_SECOND_PHASE_CURRENT)
                .map_err(storage)?;
            table
                .get(second_phase_key.as_str())
                .map_err(storage)?
                .map(|value| Self::decode_grant_closure_second_phase(value.value()))
                .transpose()?
        };
        if let Some(existing_second_phase) = existing_second_phase {
            Self::validate_grant_closure_second_phase_against_row(
                &existing_second_phase,
                second_phase_key.as_str(),
                &closure,
            )?;
            if existing_second_phase.canonical_receipt != *canonical_receipt {
                return Err(OrsError::DuplicateConflict);
            }
            return Self::grant_closure_projection_from_record(
                closure,
                Some(existing_second_phase.canonical_receipt),
            );
        }
        Self::ensure_grant_closure_order_floor(&write, closure.operation_order)?;
        let second_phase = DurableGrantClosureSecondPhaseRecord {
            schema: GRANT_CLOSURE_SECOND_PHASE_SCHEMA.to_owned(),
            version: GRANT_CLOSURE_SECOND_PHASE_VERSION,
            operation_id: operation_text.to_owned(),
            operation_order: Self::next_operational_order(&write)?,
            canonical_receipt: canonical_receipt.clone(),
        };
        second_phase.validate()?;
        let encoded = encode(&second_phase)?;
        {
            let mut table = write
                .open_table(GRANT_CLOSURE_SECOND_PHASE_CURRENT)
                .map_err(storage)?;
            if table
                .get(second_phase_key.as_str())
                .map_err(storage)?
                .is_some()
            {
                return Err(OrsError::DuplicateConflict);
            }
            table
                .insert(second_phase_key.as_str(), encoded.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Self::grant_closure_projection_from_record(closure, Some(canonical_receipt.clone()))
    }
}

impl OperationalRecoveryStore for RedbRecoveryStore {
    fn stage_generation_cutover(
        &self,
        record: RuntimeGenerationCutoverRecord,
    ) -> Result<GenerationCutoverSnapshot, OrsError> {
        RedbRecoveryStore::stage_generation_cutover(self, record)
    }

    fn commit_generation_cutover_state(
        &self,
        record: RuntimeGenerationCutoverRecord,
    ) -> Result<GenerationCutoverSnapshot, OrsError> {
        RedbRecoveryStore::commit_generation_cutover_state(self, record)
    }

    fn latest_generation_cutovers(
        &self,
        limit: u16,
    ) -> Result<Vec<GenerationCutoverSnapshot>, OrsError> {
        RedbRecoveryStore::latest_generation_cutovers(self, limit)
    }

    fn reconcile_staged_generation_cutovers(
        &self,
        limit: u16,
    ) -> Result<Vec<GenerationCutoverSnapshot>, OrsError> {
        RedbRecoveryStore::reconcile_staged_generation_cutovers(self, limit)
    }

    fn stage(&self, op: StagedOperation) -> Result<StageReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::Operation,
            op.0,
            false,
            &[],
            OperationalPhase::Staged,
        )
        .map(StageReceipt::from_receipt)
    }

    fn mark_applying(&self, operation_id: crate::OperationIdentity) -> Result<(), OrsError> {
        self.transition_existing_operational(
            OperationalKind::Operation,
            &operation_id,
            &[OperationalPhase::Staged],
            OperationalPhase::Applying,
            None,
        )?;
        Ok(())
    }

    fn record_outcome(&self, receipt: &ReceiptEnvelope) -> Result<(), OrsError> {
        receipt
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        let operation_id = OpaqueLabel::new(receipt.core.operation.operation_id.as_str())?;
        let key = Self::operational_key(OperationalKind::Operation, &operation_id);
        let read = self.database.begin_read().map_err(storage)?;
        let current = read.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
        let value = current
            .get(key.as_str())
            .map_err(storage)?
            .ok_or(OrsError::ReservationNotFound)?;
        let operation: DurableOperationalRecord =
            decode_named(value.value(), "operational_current")?;
        // Exact-tuple authority check (Implements #64): the receipt carries the
        // canonical `EpochId`; the persisted `EpochLineage` contour keeps its
        // shape and both tuple halves must agree. Equal sequences from
        // different lineages are unrelated. The retained `u64` snapshot contour
        // observes the canonical sequence; it never authorizes on its own.
        let receipt_epoch = &receipt.core.authority.authority_epoch;
        let receipt_fence = crate::StateFenceSnapshot::capture(
            &receipt.core.operation.state_fence,
            receipt_epoch.sequence.get(),
        )?;
        if operation.input.subject_id != operation_id
            || operation.input.authority_epoch.current.epoch != receipt_epoch.sequence.get()
            || operation.input.authority_epoch.current.lineage_id.as_str()
                != receipt_epoch.lineage_id.as_str()
            || operation.input.state_fence != receipt_fence
            || receipt.core.work_scope.state_fence != receipt.core.operation.state_fence
            || receipt.core.causal.state_fence != receipt.core.operation.state_fence
            || receipt.core.authority.state_fence != receipt.core.operation.state_fence
        {
            return Err(OrsError::ReconciliationMismatch);
        }
        drop(value);
        drop(current);
        drop(read);
        self.evidence.verify_receipt(receipt)?;
        let next_phase = match receipt.core.disposition.kind() {
            ReceiptDispositionKind::Unknown => OperationalPhase::Reconciling,
            ReceiptDispositionKind::Success
            | ReceiptDispositionKind::Partial
            | ReceiptDispositionKind::Failure
            | ReceiptDispositionKind::Cancelled => OperationalPhase::Terminal,
        };
        self.transition_existing_operational(
            OperationalKind::Operation,
            &operation_id,
            &[OperationalPhase::Applying],
            next_phase,
            Some(receipt),
        )?;
        Ok(())
    }

    fn schedule_retry(
        &self,
        operation_id: crate::OperationIdentity,
        retry: RetryState,
    ) -> Result<(), OrsError> {
        if retry.0.subject_id != operation_id {
            return Err(OrsError::DuplicateConflict);
        }
        let key = Self::operational_key(OperationalKind::Operation, &operation_id);
        let read = self.database.begin_read().map_err(storage)?;
        let current = read.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
        let value = current
            .get(key.as_str())
            .map_err(storage)?
            .ok_or(OrsError::ReservationNotFound)?;
        let operation: DurableOperationalRecord =
            decode_named(value.value(), "operational_current")?;
        if operation.phase != OperationalPhase::Terminal || operation.terminal_receipt_id.is_none()
        {
            return Err(OrsError::InvalidTransition);
        }
        drop(value);
        drop(current);
        drop(read);
        self.mutate_operational(
            OperationalKind::Retry,
            retry.0,
            false,
            &[],
            OperationalPhase::Staged,
        )?;
        Ok(())
    }

    fn checkpoint_job(&self, checkpoint: JobCheckpoint) -> Result<(), OrsError> {
        self.mutate_operational(
            OperationalKind::JobCheckpoint,
            checkpoint.0,
            false,
            &[OperationalPhase::Active, OperationalPhase::Suspended],
            OperationalPhase::Active,
        )?;
        Ok(())
    }

    fn record_delivery_cursor(
        &self,
        cursor: DeliveryCursorState,
    ) -> Result<DeliveryCursorReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::DeliveryCursor,
            cursor.0,
            false,
            &[OperationalPhase::Active],
            OperationalPhase::Active,
        )
        .map(DeliveryCursorReceipt::from_receipt)
    }

    fn acknowledge_delivery(
        &self,
        ack: DeliveryAcknowledgement,
    ) -> Result<DeliveryCursorReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::DeliveryCursor,
            ack.0,
            true,
            &[OperationalPhase::Active],
            OperationalPhase::Active,
        )
        .map(DeliveryCursorReceipt::from_receipt)
    }

    fn stage_admission_reservation(
        &self,
        reservation: AdmissionReservation,
    ) -> Result<AdmissionReservationReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::AdmissionReservation,
            reservation.0,
            false,
            &[],
            OperationalPhase::Staged,
        )
        .map(AdmissionReservationReceipt::from_receipt)
    }

    fn activate_admission_reservation(
        &self,
        activation: AdmissionReservationActivation,
    ) -> Result<AdmissionReservationReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::AdmissionReservation,
            activation.0,
            true,
            &[OperationalPhase::Staged],
            OperationalPhase::Active,
        )
        .map(AdmissionReservationReceipt::from_receipt)
    }

    fn release_admission_reservation(
        &self,
        release: AdmissionReservationRelease,
    ) -> Result<AdmissionReservationReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::AdmissionReservation,
            release.0,
            true,
            &[OperationalPhase::Staged, OperationalPhase::Active],
            OperationalPhase::Released,
        )
        .map(AdmissionReservationReceipt::from_receipt)
    }

    fn apply_generation_transition(
        &self,
        transition: GenerationTransition,
    ) -> Result<GenerationTransitionReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::GenerationTransition,
            transition.0,
            false,
            &[OperationalPhase::Active, OperationalPhase::Fenced],
            OperationalPhase::Applying,
        )
        .map(GenerationTransitionReceipt::from_receipt)
    }

    fn commit_generation_cutover(
        &self,
        cutover: GenerationCutoverRecord,
    ) -> Result<GenerationCutoverReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::GenerationCutover,
            cutover.0,
            false,
            &[OperationalPhase::Active, OperationalPhase::Fenced],
            OperationalPhase::Active,
        )
        .map(GenerationCutoverReceipt::from_receipt)
    }

    fn bind_session(
        &self,
        binding: ActiveSessionBinding,
    ) -> Result<SessionBindingReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::SessionBinding,
            binding.0,
            false,
            &[OperationalPhase::Suspended, OperationalPhase::Fenced],
            OperationalPhase::Active,
        )
        .map(SessionBindingReceipt::from_receipt)
    }

    fn detach_session(&self, detach: SessionDetach) -> Result<SessionBindingReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::SessionBinding,
            detach.0,
            true,
            &[OperationalPhase::Active],
            OperationalPhase::Suspended,
        )
        .map(SessionBindingReceipt::from_receipt)
    }

    fn register_user_broker(
        &self,
        registration: UserBrokerRegistration,
    ) -> Result<UserBrokerRegistrationReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::UserBroker,
            registration.0,
            false,
            &[OperationalPhase::Fenced],
            OperationalPhase::Active,
        )
        .map(UserBrokerRegistrationReceipt::from_receipt)
    }

    fn fence_user_broker(
        &self,
        fence: UserBrokerFence,
    ) -> Result<UserBrokerRegistrationReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::UserBroker,
            fence.0,
            true,
            &[OperationalPhase::Active],
            OperationalPhase::Fenced,
        )
        .map(UserBrokerRegistrationReceipt::from_receipt)
    }

    fn commit_authority_snapshot(
        &self,
        snapshot: KernelAuthoritySnapshot,
    ) -> Result<AuthoritySnapshotReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::AuthoritySnapshot,
            snapshot.0,
            false,
            &[OperationalPhase::Active, OperationalPhase::Fenced],
            OperationalPhase::Active,
        )
        .map(AuthoritySnapshotReceipt::from_receipt)
    }

    fn commit_authority_snapshot_cas(
        &self,
        snapshot: KernelAuthoritySnapshot,
        expected: Option<&AuthoritySnapshotReceipt>,
    ) -> Result<AuthoritySnapshotReceipt, OrsError> {
        RedbRecoveryStore::commit_authority_snapshot_cas(self, snapshot, expected)
    }

    fn load_authority_snapshot(
        &self,
        subject_id: &crate::OperationIdentity,
    ) -> Result<Option<RecoveredAuthoritySnapshot>, OrsError> {
        let key = Self::operational_key(OperationalKind::AuthoritySnapshot, subject_id);
        let read = self.database.begin_read().map_err(storage)?;
        let current = read.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
        let Some(value) = current.get(key.as_str()).map_err(storage)? else {
            return Ok(None);
        };
        let record: DurableOperationalRecord = decode_named(value.value(), "operational_current")?;
        if record.kind != OperationalKind::AuthoritySnapshot
            || record.phase != OperationalPhase::Active
            || &record.input.subject_id != subject_id
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "authority_snapshot",
                reason: "current authority snapshot key, kind, phase, or subject mismatch"
                    .to_owned(),
            });
        }
        record.input.validate()?;
        let receipt = AuthoritySnapshotReceipt::from_receipt(Self::receipt_for(&record)?);
        let snapshot = KernelAuthoritySnapshot::new(record.input)?;
        Ok(Some(RecoveredAuthoritySnapshot::from_store(
            snapshot,
            record.operation_order,
            receipt,
        )))
    }

    fn revoke_authority(
        &self,
        revocation: AuthorityRevocation,
    ) -> Result<AuthorityRevocationReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::AuthorityRevocation,
            revocation.0,
            false,
            &[OperationalPhase::Fenced],
            OperationalPhase::Fenced,
        )
        .map(AuthorityRevocationReceipt::from_receipt)
    }

    fn activate_capability_grant(
        &self,
        activation: CapabilityGrantActivation,
    ) -> Result<AuthorityActivationReceipt, OrsError> {
        let input = activation.0;
        if let Some(existing) = self.load_capability_grant(&input.subject_id)? {
            if existing.record() == &input && existing.phase() == OperationalPhase::Active {
                return Ok(AuthorityActivationReceipt::from_receipt(
                    existing.receipt().clone(),
                ));
            }
            if existing.record() == &input && existing.phase() == OperationalPhase::Applying {
                return self
                    .transition_existing_operational(
                        OperationalKind::CapabilityGrant,
                        &input.subject_id,
                        &[OperationalPhase::Applying],
                        OperationalPhase::Active,
                        None,
                    )
                    .map(AuthorityActivationReceipt::from_receipt);
            }
        }

        // `APPLYING` is the durable PendingActivation record. A crash after
        // this commit leaves an opaque, non-active row that a later exact
        // presentation can finish; it can never be recovered as live state.
        self.mutate_operational(
            OperationalKind::CapabilityGrant,
            input.clone(),
            false,
            &[OperationalPhase::Fenced, OperationalPhase::Released],
            OperationalPhase::Applying,
        )?;
        self.transition_existing_operational(
            OperationalKind::CapabilityGrant,
            &input.subject_id,
            &[OperationalPhase::Applying],
            OperationalPhase::Active,
            None,
        )
        .map(AuthorityActivationReceipt::from_receipt)
    }

    fn revoke_capability_grant(
        &self,
        revocation: CapabilityGrantRevocation,
    ) -> Result<AuthorityRevocationReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::CapabilityGrant,
            revocation.0,
            true,
            &[OperationalPhase::Active],
            OperationalPhase::Fenced,
        )
        .map(AuthorityRevocationReceipt::from_receipt)
    }

    fn load_capability_grant(
        &self,
        subject_id: &crate::OperationIdentity,
    ) -> Result<Option<CapabilityGrantProjection>, OrsError> {
        let key = Self::operational_key(OperationalKind::CapabilityGrant, subject_id);
        let read = self.database.begin_read().map_err(storage)?;
        let current = read.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
        let Some(value) = current.get(key.as_str()).map_err(storage)? else {
            return Ok(None);
        };
        let record: DurableOperationalRecord = decode_named(value.value(), "operational_current")?;
        if record.kind != OperationalKind::CapabilityGrant
            || record.input.subject_id != *subject_id
            || !matches!(
                record.phase,
                OperationalPhase::Applying
                    | OperationalPhase::Active
                    | OperationalPhase::Fenced
                    | OperationalPhase::Released
            )
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "capability_grant",
                reason: "current capability-grant key, kind, subject, or phase mismatch".to_owned(),
            });
        }
        record.input.validate()?;
        let receipt = Self::receipt_for(&record)?;
        Ok(Some(CapabilityGrantProjection::from_store(
            record.input,
            record.phase,
            record.operation_order,
            receipt,
        )))
    }

    fn commit_grant_closure(
        &self,
        closure: GrantClosureCommit,
    ) -> Result<GrantClosureCommitReceipt, OrsError> {
        crate::model::validate_grant_closure_contract(&closure)?;
        if closure.state != GrantClosureState::Active {
            return Err(OrsError::InvalidTransition);
        }
        let phase = crate::model::grant_closure_phase(closure.state);
        let key = format!("grant_closure:{}", closure.operation_id);
        let write = self.database.begin_write().map_err(storage)?;
        let existing = {
            let current = write.open_table(GRANT_CLOSURE_CURRENT).map_err(storage)?;
            current
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| {
                    decode_named::<DurableGrantClosureRecord>(value.value(), "grant_closure")
                })
                .transpose()?
        };
        if existing.is_none()
            && let Some(migration) =
                Self::grant_closure_migration_from_write(&write, closure.operation_id.as_str())?
        {
            return Err(Self::grant_closure_migration_refusal(&migration));
        }
        if let Some(existing) = existing {
            if existing.commit.operation_id != closure.operation_id {
                return Err(OrsError::IntegrityProblem {
                    record_type: "grant_closure",
                    reason: "current grant-closure key or operation identity mismatch".to_owned(),
                });
            }
            if existing.commit == closure && existing.phase == phase {
                return Ok(GrantClosureCommitReceipt::from_receipt(
                    Self::closure_receipt_for(&existing)?,
                ));
            }
            return Err(OrsError::DuplicateConflict);
        }
        let operation_order = Self::next_operational_order(&write)?;
        let record = DurableGrantClosureRecord {
            commit: closure,
            phase,
            operation_order,
        };
        let encoded = encode(&record)?;
        {
            let mut current = write.open_table(GRANT_CLOSURE_CURRENT).map_err(storage)?;
            current
                .insert(key.as_str(), encoded.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(GrantClosureCommitReceipt::from_receipt(
            Self::closure_receipt_for(&record)?,
        ))
    }

    fn commit_grant_closure_fence(
        &self,
        request: GrantClosureFenceRequest,
    ) -> Result<GrantClosureFenceReceipt, OrsError> {
        RedbRecoveryStore::commit_grant_closure_fence(self, &request)
    }

    fn link_grant_closure_canonical_receipt(
        &self,
        operation_id: &crate::OperationIdentity,
        canonical_receipt: &ReceiptIdentity,
    ) -> Result<GrantClosureProjection, OrsError> {
        RedbRecoveryStore::link_grant_closure_canonical_receipt(
            self,
            operation_id,
            canonical_receipt,
        )
    }

    fn load_grant_closure(
        &self,
        operation_id: &crate::OperationIdentity,
    ) -> Result<Option<GrantClosureProjection>, OrsError> {
        let key = format!("grant_closure:{}", operation_id.as_str());
        let read = self.database.begin_read().map_err(storage)?;
        let current = read.open_table(GRANT_CLOSURE_CURRENT).map_err(storage)?;
        if let Some(value) = current.get(key.as_str()).map_err(storage)? {
            let record: DurableGrantClosureRecord = decode_named(value.value(), "grant_closure")?;
            if record.commit.operation_id != operation_id.as_str() {
                return Err(OrsError::IntegrityProblem {
                    record_type: "grant_closure",
                    reason: "current grant-closure key or operation identity mismatch".to_owned(),
                });
            }
            return Ok(Some(Self::grant_closure_projection_from_read(
                &read, record,
            )?));
        }
        let migration_key = Self::grant_closure_migration_key(operation_id.as_str());
        let Some(value) = current.get(migration_key.as_str()).map_err(storage)? else {
            return Ok(None);
        };
        let migration = Self::decode_grant_closure_migration(value.value())?;
        Self::validate_grant_closure_migration_binding(
            &migration,
            migration_key.as_str(),
            operation_id.as_str(),
        )?;
        if migration.current_key.is_some() {
            return Err(OrsError::IntegrityProblem {
                record_type: "grant_closure_migration",
                reason: "migration disposition names a current row that is absent".to_owned(),
            });
        }
        Err(Self::grant_closure_migration_refusal(&migration))
    }

    fn scan_grant_closures_for_lineage(
        &self,
        lineage: &OpaqueLabel,
        limit: u16,
    ) -> Result<(Vec<GrantClosureProjection>, Option<u64>), OrsError> {
        if limit == 0 || limit > crate::MAX_RECOVERY_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        // One durable read snapshot covers the whole selected set and
        // the per-root revision watermark, so the returned response is
        // self-consistent with no paging cursor and no cross-page torn
        // views. Selection filters by lineage before any bound applies:
        // unrelated rows never refuse a requested view. An oversize
        // selected set refuses before receipt/projection work.
        let read = self.database.begin_read().map_err(storage)?;
        let current = read.open_table(GRANT_CLOSURE_CURRENT).map_err(storage)?;
        let second_phases = Self::grant_closure_second_phases_in(&read)?;
        let mut rows: Vec<(u64, DurableGrantClosureRecord)> = Vec::new();
        let mut resolved_root: Option<String> = None;
        for row in current.iter().map_err(storage)? {
            let (key, value) = row.map_err(storage)?;
            let key_text = key.value();
            if key_text.starts_with(GRANT_CLOSURE_MIGRATION_KEY_PREFIX) {
                let migration = Self::decode_grant_closure_migration(value.value())?;
                Self::validate_grant_closure_migration_binding(
                    &migration,
                    key_text,
                    migration.operation_id.as_str(),
                )?;
                if let Some(current_key) = migration.current_key.as_deref()
                    && current.get(current_key).map_err(storage)?.is_none()
                {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "grant_closure_migration",
                        reason: "migration disposition names a missing current row".to_owned(),
                    });
                }
                if migration.disposition == GrantClosureMigrationDisposition::LegacyShapeRetained
                    && (migration.authority_root_ref == lineage.as_str()
                        || migration.target_grant_id == lineage.as_str())
                {
                    return Err(Self::grant_closure_migration_refusal(&migration));
                }
                continue;
            }
            let record: DurableGrantClosureRecord = decode_named(value.value(), "grant_closure")?;
            let expected = format!("grant_closure:{}", record.commit.operation_id.as_str());
            if key.value() != expected.as_str() {
                return Err(OrsError::IntegrityProblem {
                    record_type: "grant_closure",
                    reason: "grant-closure key drifts from its committed operation identity"
                        .to_owned(),
                });
            }
            let commit = &record.commit;
            if commit.declaration.authority_root_ref.as_str() != lineage.as_str()
                && commit.declaration.target_grant_id.as_str() != lineage.as_str()
            {
                continue;
            }
            match resolved_root.as_deref() {
                Some(known) if known != commit.declaration.authority_root_ref.as_str() => {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "grant_closure",
                        reason: "one lineage selector resolves to more than one lineage root"
                            .to_owned(),
                    });
                }
                Some(_) => {}
                None => resolved_root = Some(commit.declaration.authority_root_ref.clone()),
            }
            rows.push((record.operation_order, record));
            if rows.len() > usize::from(limit) {
                return Err(OrsError::ProjectionLimitExceeded);
            }
        }
        rows.sort_by_key(|(order, _)| *order);
        // The watermark resolves to the matched lineage root when rows
        // matched, else to the selector itself; both reads share the
        // snapshot opened above.
        let watermark_root: &str = match resolved_root.as_deref() {
            Some(root) => root,
            None => lineage.as_str(),
        };
        let watermark = Self::grant_graph_revision_in(&read, watermark_root)?;
        let mut projections = Vec::with_capacity(rows.len());
        for (_, record) in rows {
            let second_phase = second_phases.get(record.commit.operation_id.as_str());
            if let Some(second_phase) = second_phase {
                Self::validate_grant_closure_second_phase_against_row(
                    second_phase,
                    Self::grant_closure_second_phase_key(record.commit.operation_id.as_str())
                        .as_str(),
                    &record,
                )?;
            }
            let second_phase_identity =
                Self::grant_closure_second_phase_identity(&record, second_phase)?;
            projections.push(Self::grant_closure_projection_from_record(
                record,
                second_phase_identity,
            )?);
        }
        Ok((projections, watermark))
    }

    fn note_grant_graph_revision(
        &self,
        authority_root: &OpaqueLabel,
        revision: u64,
    ) -> Result<u64, OrsError> {
        if revision == 0 {
            return Err(OrsError::InvalidField {
                field: "grant_closure_revision",
                reason: "must be greater than zero",
            });
        }
        let key = format!("grant_graph_revision:{}", authority_root.as_str());
        let write = self.database.begin_write().map_err(storage)?;
        let retained = {
            let current = write
                .open_table(GRANT_GRAPH_REVISION_CURRENT)
                .map_err(storage)?;
            current
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| {
                    decode_named::<DurableGrantGraphRevision>(value.value(), "grant_graph_revision")
                })
                .transpose()?
        };
        if let Some(retained) = retained.as_ref()
            && retained.root.as_str() != authority_root.as_str()
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "grant_graph_revision",
                reason: "current revision key or lineage root mismatch".to_owned(),
            });
        }
        let retained_revision = retained.as_ref().map_or(0, |row| row.revision);
        let stored = retained_revision.max(revision);
        if retained_revision != stored {
            let operation_order = Self::next_operational_order(&write)?;
            let row = DurableGrantGraphRevision {
                root: authority_root.clone(),
                revision: stored,
                operation_order,
            };
            let encoded = encode(&row)?;
            {
                let mut current = write
                    .open_table(GRANT_GRAPH_REVISION_CURRENT)
                    .map_err(storage)?;
                current
                    .insert(key.as_str(), encoded.as_str())
                    .map_err(storage)?;
            }
            write.commit().map_err(storage)?;
        }
        Ok(stored)
    }

    fn note_grant_graph_revisions(&self, revisions: &[(OpaqueLabel, u64)]) -> Result<(), OrsError> {
        if revisions.is_empty() {
            return Err(OrsError::InvalidField {
                field: "grant_graph_revisions",
                reason: "at least one lineage revision is required",
            });
        }
        let batch_revision = revisions[0].1;
        if revisions
            .iter()
            .any(|(_, revision)| *revision != batch_revision)
        {
            return Err(OrsError::InvalidField {
                field: "grant_graph_revisions",
                reason: "all lineage roots in one owner batch must share the revision",
            });
        }
        let write = self.database.begin_write().map_err(storage)?;
        let mut roots = BTreeSet::new();
        let mut pending = Vec::with_capacity(revisions.len());
        for (root, revision) in revisions {
            if *revision == 0 {
                return Err(OrsError::InvalidField {
                    field: "grant_graph_revision",
                    reason: "must be greater than zero",
                });
            }
            if !roots.insert(root.as_str().to_owned()) {
                return Err(OrsError::InvalidField {
                    field: "grant_graph_revisions",
                    reason: "lineage roots must be unique",
                });
            }
            let retained = Self::grant_graph_revision_from_write(&write, root.as_str())?;
            if retained
                .as_ref()
                .is_some_and(|current| current.revision > *revision)
            {
                return Err(OrsError::InvalidField {
                    field: "grant_graph_revision",
                    reason: "a stale lineage revision cannot advance the owner batch",
                });
            }
            if retained
                .as_ref()
                .is_none_or(|current| current.revision != *revision)
            {
                pending.push((root.clone(), *revision));
            }
        }
        if !pending.is_empty() {
            let mut current = write
                .open_table(GRANT_GRAPH_REVISION_CURRENT)
                .map_err(storage)?;
            for (root, revision) in pending {
                let row = DurableGrantGraphRevision {
                    root,
                    revision,
                    operation_order: Self::next_operational_order(&write)?,
                };
                let key = format!("grant_graph_revision:{}", row.root.as_str());
                let encoded = encode(&row)?;
                current
                    .insert(key.as_str(), encoded.as_str())
                    .map_err(storage)?;
            }
        }
        write.commit().map_err(storage)
    }

    fn load_grant_graph_revision(
        &self,
        authority_root: &OpaqueLabel,
    ) -> Result<Option<u64>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        Self::grant_graph_revision_in(&read, authority_root.as_str())
    }

    fn activate_capability_introduction(
        &self,
        activation: CapabilityIntroductionActivation,
    ) -> Result<CapabilityIntroductionReceipt, OrsError> {
        let input = activation.0;
        if let Some(existing) = self.load_capability_introduction(&input.subject_id)? {
            if existing.record() == &input && existing.phase() == OperationalPhase::Active {
                return Ok(CapabilityIntroductionReceipt::from_receipt(
                    existing.receipt().clone(),
                ));
            }
            // Restore never reactivates a fenced introduction (I6.15): an
            // exact replay of the committed activation is idempotent above,
            // and any other presentation against an existing row — a changed
            // payload, a new record over an `Active` row, or any record over
            // a `Fenced` row — is a typed state-machine refusal, never a
            // second activation.
            return Err(OrsError::InvalidTransition);
        }
        // Only a missing row may enter `Active`: `Fenced` rows are never
        // reactivated, so the allowed-prior set stays empty and any raced
        // duplicate still fails closed through the transition check.
        self.mutate_operational(
            OperationalKind::CapabilityIntroduction,
            input,
            false,
            &[],
            OperationalPhase::Active,
        )
        .map(CapabilityIntroductionReceipt::from_receipt)
    }

    fn fence_capability_introduction(
        &self,
        fence: CapabilityIntroductionFence,
    ) -> Result<CapabilityIntroductionReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::CapabilityIntroduction,
            fence.0,
            true,
            &[OperationalPhase::Active],
            OperationalPhase::Fenced,
        )
        .map(CapabilityIntroductionReceipt::from_receipt)
    }

    fn load_capability_introduction(
        &self,
        subject_id: &crate::OperationIdentity,
    ) -> Result<Option<CapabilityIntroductionProjection>, OrsError> {
        let key = Self::operational_key(OperationalKind::CapabilityIntroduction, subject_id);
        let read = self.database.begin_read().map_err(storage)?;
        let current = read.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
        let Some(value) = current.get(key.as_str()).map_err(storage)? else {
            return Ok(None);
        };
        let record: DurableOperationalRecord = decode_named(value.value(), "operational_current")?;
        if record.kind != OperationalKind::CapabilityIntroduction
            || record.input.subject_id != *subject_id
            || !matches!(
                record.phase,
                OperationalPhase::Active | OperationalPhase::Fenced
            )
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "capability_introduction",
                reason: "current capability-introduction key, kind, subject, or phase mismatch"
                    .to_owned(),
            });
        }
        record.input.validate()?;
        let receipt = Self::receipt_for(&record)?;
        Ok(Some(CapabilityIntroductionProjection::from_store(
            record.input,
            record.phase,
            record.operation_order,
            receipt,
        )))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one bounded read transaction binds reservations, envelopes, scope terminals, operational history, and inbox history"
    )]
    fn logical_snapshot(
        &self,
        request: OrsSnapshotRequest,
    ) -> Result<OrsSnapshotReceipt, OrsError> {
        if request.limit == 0 || request.limit > crate::MAX_RECOVERY_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        let read = self.database.begin_read().map_err(storage)?;
        let mut entries = BTreeMap::new();
        {
            let history = read.open_table(OPERATIONAL_HISTORY).map_err(storage)?;
            for row in history.iter().map_err(storage)? {
                let (_, value) = row.map_err(storage)?;
                let record: DurableOperationalRecord =
                    decode_named(value.value(), "operational_history")?;
                if record.operation_order > request.after_order {
                    let encoded = encode(&record)?;
                    entries.insert(
                        (
                            record.operation_order,
                            format!("o:{}", record.input.record_id.as_str()),
                        ),
                        crate::model::sha256_hex(encoded.as_bytes()),
                    );
                    if entries.len() > usize::from(request.limit) {
                        break;
                    }
                }
            }
        }
        {
            let orders = read.open_table(RESERVATION_ORDERS).map_err(storage)?;
            let reservations = read.open_table(RESERVATIONS).map_err(storage)?;
            let envelopes = read.open_table(ENVELOPES).map_err(storage)?;
            let heads = read.open_table(SCOPE_HEADS).map_err(storage)?;
            let terminals = read.open_table(SCOPE_TERMINALS).map_err(storage)?;
            let mut reservation_entries = 0_usize;
            for row in orders.iter().map_err(storage)? {
                let (order, reservation_id) = row.map_err(storage)?;
                let order =
                    order
                        .value()
                        .parse::<u64>()
                        .map_err(|error| OrsError::IntegrityProblem {
                            record_type: "reservation_order",
                            reason: error.to_string(),
                        })?;
                if order <= request.after_order {
                    continue;
                }
                let reservation_id = OpaqueLabel::new(reservation_id.value()).map_err(|error| {
                    OrsError::IntegrityProblem {
                        record_type: "reservation_order",
                        reason: error.to_string(),
                    }
                })?;
                let value = reservations
                    .get(reservation_id.as_str())
                    .map_err(storage)?
                    .ok_or_else(|| OrsError::IntegrityProblem {
                        record_type: "reservation_order",
                        reason: "snapshot found dangling reservation order".to_owned(),
                    })?;
                let record: ReservationRecord = decode_named(value.value(), "reservation")?;
                if record.token.reservation_order != order {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "reservation_order",
                        reason: "snapshot order index mismatch".to_owned(),
                    });
                }
                let mut encoded = encode(&record)?;
                if let Some(envelope) = envelopes
                    .get(record.token.operation_id.as_str())
                    .map_err(storage)?
                {
                    let envelope: RecoveryPayloadEnvelope =
                        decode_named(envelope.value(), "recovery_envelope")?;
                    encoded.push('\n');
                    encoded.push_str(&encode(&envelope)?);
                } else if !record.state.is_terminal() {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "recovery_envelope",
                        reason: "pending snapshot reservation has no envelope".to_owned(),
                    });
                }
                for reserved in &record.token.scopes {
                    let head = heads
                        .get(reserved.scope.as_str())
                        .map_err(storage)?
                        .ok_or_else(|| OrsError::IntegrityProblem {
                            record_type: "scope_head",
                            reason: "snapshot reservation has no scope head".to_owned(),
                        })?;
                    let head: ScopeReservationHead = decode_named(head.value(), "scope_head")?;
                    encoded.push('\n');
                    encoded.push_str(&encode(&head)?);
                    let terminal_key = format!(
                        "{}:{:020}",
                        reserved.scope.as_str(),
                        reserved.reserved_sequence
                    );
                    if let Some(terminal) = terminals.get(terminal_key.as_str()).map_err(storage)? {
                        let terminal: ScopeTerminalReceipt =
                            decode_named(terminal.value(), "scope_terminal")?;
                        encoded.push('\n');
                        encoded.push_str(&encode(&terminal)?);
                    }
                }
                entries.insert(
                    (
                        record.token.reservation_order,
                        format!("r:{}", record.token.reservation_id.as_str()),
                    ),
                    crate::model::sha256_hex(encoded.as_bytes()),
                );
                reservation_entries += 1;
                if reservation_entries > usize::from(request.limit) {
                    break;
                }
            }
        }
        {
            let history = read.open_table(RECOVERY_INBOX_HISTORY).map_err(storage)?;
            let mut inbox_entries = 0_usize;
            for row in history.iter().map_err(storage)? {
                let (_, value) = row.map_err(storage)?;
                let record: DurableInboxRecord =
                    decode_named(value.value(), "recovery_inbox_history")?;
                if record.operation_order > request.after_order {
                    let encoded = encode(&record)?;
                    entries.insert(
                        (
                            record.operation_order,
                            format!("i:{}", record.item.item_id.as_str()),
                        ),
                        crate::model::sha256_hex(encoded.as_bytes()),
                    );
                    inbox_entries += 1;
                    if inbox_entries > usize::from(request.limit) {
                        break;
                    }
                }
            }
        }
        let mut selected: Vec<_> = entries
            .into_iter()
            .take(usize::from(request.limit) + 1)
            .collect();
        let has_more = selected.len() > usize::from(request.limit);
        if has_more {
            selected.pop();
        }
        let next_after_order = has_more
            .then(|| selected.last().map(|entry| entry.0.0))
            .flatten();
        let entry_refs: Vec<_> = selected
            .into_iter()
            .map(|((order, identity), digest)| format!("{order}:{identity}:{digest}"))
            .collect();
        let snapshot_sha256 = crate::model::sha256_hex(entry_refs.join("\n").as_bytes());
        OrsSnapshotReceipt::issue(
            request.snapshot_at_ms,
            entry_refs,
            snapshot_sha256,
            next_after_order,
        )
    }

    fn scan_pending(
        &self,
        cursor: RecoveryCursor,
        limit: u32,
    ) -> Result<PendingOperationPage, OrsError> {
        if limit == 0 || limit > u32::from(crate::MAX_RECOVERY_PAGE) {
            return Err(OrsError::InvalidCursorLimit);
        }
        let bounded = u16::try_from(limit).map_err(|_| OrsError::InvalidCursorLimit)?;
        if cursor.limit != bounded {
            return Err(OrsError::InvalidCursorLimit);
        }
        recovery_projection::recover_page(self, cursor)
    }

    fn import_recovery_inbox(
        &self,
        item: RecoveryInboxItem,
    ) -> Result<RecoveryInboxReceipt, OrsError> {
        recovery_projection::import_recovery_inbox(self, item)
    }

    fn record_recovery_inbox_disposition(
        &self,
        item_id: crate::OperationIdentity,
        disposition: RecoveryInboxDisposition,
        receipt: &ReceiptEnvelope,
    ) -> Result<RecoveryInboxReceipt, OrsError> {
        if disposition == RecoveryInboxDisposition::Imported {
            return Err(OrsError::InvalidTransition);
        }
        receipt
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        self.evidence.verify_receipt(receipt)?;
        let write = self.database.begin_write().map_err(storage)?;
        let mut record = {
            let inbox = write.open_table(RECOVERY_INBOX).map_err(storage)?;
            let value = inbox
                .get(item_id.as_str())
                .map_err(storage)?
                .ok_or(OrsError::ReservationNotFound)?;
            decode_named::<DurableInboxRecord>(value.value(), "recovery_inbox")?
        };
        if record.item.envelope.operation_or_checkpoint_id.as_str()
            != receipt.core.operation.operation_id.as_str()
        {
            return Err(OrsError::ReconciliationMismatch);
        }
        // Exact-tuple authority check (Implements #64): the receipt carries the
        // canonical `EpochId`; the persisted `EpochLineage` contour keeps its
        // shape and both tuple halves must agree. Equal sequences from
        // different lineages are unrelated. The retained `u64` snapshot contour
        // observes the canonical sequence; it never authorizes on its own.
        let receipt_epoch = &receipt.core.authority.authority_epoch;
        let receipt_fence = crate::StateFenceSnapshot::capture(
            &receipt.core.operation.state_fence,
            receipt_epoch.sequence.get(),
        )?;
        if receipt_fence != record.item.envelope.state_fence
            || receipt_epoch.sequence.get() != record.item.envelope.authority_epoch.current.epoch
            || receipt_epoch.lineage_id.as_str()
                != record
                    .item
                    .envelope
                    .authority_epoch
                    .current
                    .lineage_id
                    .as_str()
            || receipt.core.work_scope.state_fence != receipt.core.operation.state_fence
            || receipt.core.causal.state_fence != receipt.core.operation.state_fence
            || receipt.core.authority.state_fence != receipt.core.operation.state_fence
        {
            return Err(OrsError::ReconciliationMismatch);
        }
        let receipt_kind = receipt.core.disposition.kind();
        let disposition_matches = match disposition {
            RecoveryInboxDisposition::Applied => matches!(
                receipt_kind,
                ReceiptDispositionKind::Success | ReceiptDispositionKind::Partial
            ),
            RecoveryInboxDisposition::Rejected | RecoveryInboxDisposition::DeadLetter => matches!(
                receipt_kind,
                ReceiptDispositionKind::Failure | ReceiptDispositionKind::Cancelled
            ),
            RecoveryInboxDisposition::Imported => false,
        };
        if !disposition_matches {
            return Err(OrsError::ReconciliationMismatch);
        }
        record.disposition = disposition;
        record.operation_order = Self::next_operational_order(&write)?;
        record.terminal_receipt_id = Some(OpaqueLabel::new(receipt.identity.receipt_id.as_str())?);
        record.terminal_receipt_sha256 = Some(receipt.identity.canonical_sha256.clone());
        let encoded = encode(&record)?;
        let operational_phase = match disposition {
            RecoveryInboxDisposition::Applied => OperationalPhase::Terminal,
            RecoveryInboxDisposition::Rejected | RecoveryInboxDisposition::DeadLetter => {
                OperationalPhase::Released
            }
            RecoveryInboxDisposition::Imported => unreachable!(),
        };
        let result = OperationalMutationReceipt::issue(
            record.item.item_id.clone(),
            record.item.envelope.operation_or_checkpoint_id.clone(),
            record.operation_order,
            operational_phase,
            crate::model::sha256_hex(encoded.as_bytes()),
        )?;
        let mut inbox = write.open_table(RECOVERY_INBOX).map_err(storage)?;
        inbox
            .insert(record.item.item_id.as_str(), encoded.as_str())
            .map_err(storage)?;
        drop(inbox);
        let history_key = format!(
            "{:020}:{}",
            record.operation_order,
            record.item.item_id.as_str()
        );
        let mut history = write.open_table(RECOVERY_INBOX_HISTORY).map_err(storage)?;
        history
            .insert(history_key.as_str(), encoded.as_str())
            .map_err(storage)?;
        drop(history);
        write.commit().map_err(storage)?;
        Ok(RecoveryInboxReceipt::from_receipt(result))
    }

    fn stage_and_reserve(
        &self,
        mut request: ReservationRequest,
    ) -> Result<WriterReservationToken, OrsError> {
        request.validate()?;
        request
            .scopes
            .sort_by(|left, right| left.scope.cmp(&right.scope));
        let write = self.database.begin_write().map_err(storage)?;
        if let Some(token) = Self::existing_token(&write, &request)? {
            return Ok(token);
        }
        self.evidence.verify_ordering_heads(&request.scopes)?;
        let reservation_order = Self::next_reservation_order(&write)?;
        let reserved_scopes = Self::reserve_scope_sequences(&write, &request)?;

        let token = WriterReservationToken {
            reservation_id: request.reservation_id.clone(),
            operation_id: request.envelope.operation_or_checkpoint_id.clone(),
            writer_epoch: request.writer_epoch,
            state_fence: request.envelope.state_fence.clone(),
            reservation_order,
            scopes: reserved_scopes,
            prepared_transition_sha256: request.prepared_transition_sha256,
            expires_at_ms: request.expires_at_ms,
            recovery_owner: request.recovery_owner,
        };
        let record = ReservationRecord {
            token: token.clone(),
            state: ReservationState::Reserved,
            unknown_reason: None,
            terminal_receipt_id: None,
        };
        Self::persist_new_reservation(&write, &request.envelope, &record)?;
        write.commit().map_err(storage)?;
        Ok(token)
    }

    fn mark_eligible(&self, token: &WriterReservationToken) -> Result<ReservationRecord, OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        let mut record;
        {
            let mut table = write.open_table(RESERVATIONS).map_err(storage)?;
            record = Self::load_record(&table, &token.reservation_id)?;
            Self::validate_token(&record, token)?;
            match record.state {
                ReservationState::Eligible => return Ok(record),
                ReservationState::Reserved => {}
                _ => return Err(OrsError::InvalidTransition),
            }
            Self::ensure_no_predecessor(&table, token)?;
            Self::ensure_canonical_heads(&write, token)?;
            record.state = ReservationState::Eligible;
            let payload = encode(&record)?;
            table
                .insert(token.reservation_id.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(record)
    }

    fn begin_execute(
        &self,
        token: &WriterReservationToken,
        writer_epoch: &EpochIdentity,
    ) -> Result<ReservationRecord, OrsError> {
        require_writer_epoch(token, writer_epoch)?;
        let write = self.database.begin_write().map_err(storage)?;
        let mut record;
        {
            let mut table = write.open_table(RESERVATIONS).map_err(storage)?;
            record = Self::load_record(&table, &token.reservation_id)?;
            Self::validate_token(&record, token)?;
            match record.state {
                ReservationState::Executing => return Ok(record),
                ReservationState::Eligible => {}
                _ => return Err(OrsError::InvalidTransition),
            }
            Self::ensure_no_predecessor(&table, token)?;
            Self::ensure_canonical_heads(&write, token)?;
            record.state = ReservationState::Executing;
            let payload = encode(&record)?;
            table
                .insert(token.reservation_id.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(record)
    }

    fn mark_unknown(
        &self,
        token: &WriterReservationToken,
        writer_epoch: &EpochIdentity,
        reason: OpaqueLabel,
    ) -> Result<ReservationRecord, OrsError> {
        require_writer_epoch(token, writer_epoch)?;
        let write = self.database.begin_write().map_err(storage)?;
        let mut record;
        {
            let mut table = write.open_table(RESERVATIONS).map_err(storage)?;
            record = Self::load_record(&table, &token.reservation_id)?;
            Self::validate_token(&record, token)?;
            match record.state {
                ReservationState::Reconciling
                    if record.unknown_reason.as_ref() == Some(&reason) =>
                {
                    return Ok(record);
                }
                ReservationState::Executing => {}
                _ => return Err(OrsError::InvalidTransition),
            }
            record.state = ReservationState::Reconciling;
            record.unknown_reason = Some(reason);
            let payload = encode(&record)?;
            table
                .insert(token.reservation_id.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        {
            let mut heads = write.open_table(SCOPE_HEADS).map_err(storage)?;
            for scope in &token.scopes {
                let value = heads
                    .get(scope.scope.as_str())
                    .map_err(storage)?
                    .ok_or_else(|| OrsError::Storage("missing scope head".to_owned()))?;
                let mut head: ScopeReservationHead = decode(value.value())?;
                drop(value);
                head.recovery_blocked = true;
                let payload = encode(&head)?;
                heads
                    .insert(scope.scope.as_str(), payload.as_str())
                    .map_err(storage)?;
            }
        }
        write.commit().map_err(storage)?;
        Ok(record)
    }

    fn reconcile(
        &self,
        reconciliation: &CanonicalReconciliation,
    ) -> Result<ReservationRecord, OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        let mut record;
        {
            let mut table = write.open_table(RESERVATIONS).map_err(storage)?;
            record = Self::load_record(&table, &reconciliation.reservation_id)?;
            if record.state.is_terminal() {
                if record.terminal_receipt_id.as_ref().map(OpaqueLabel::as_str)
                    == Some(reconciliation.receipt.identity.receipt_id.as_str())
                    && reconciliation_matches(&record.token, reconciliation).is_ok()
                {
                    self.evidence
                        .verify_reconciliation(&record.token, reconciliation)?;
                    return Ok(record);
                }
                return Err(OrsError::DuplicateConflict);
            }
            if !matches!(
                record.state,
                ReservationState::Executing | ReservationState::Reconciling
            ) {
                return Err(OrsError::InvalidTransition);
            }
            reconciliation_matches(&record.token, reconciliation)?;
            self.evidence
                .verify_reconciliation(&record.token, reconciliation)?;
            record.state = match reconciliation.disposition {
                CanonicalDisposition::Committed => ReservationState::Finalized,
                CanonicalDisposition::Rejected => ReservationState::Released,
            };
            record.unknown_reason = None;
            record.terminal_receipt_id = Some(OpaqueLabel::new(
                reconciliation.receipt.identity.receipt_id.as_str(),
            )?);
            let payload = encode(&record)?;
            table
                .insert(record.token.reservation_id.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        Self::record_scope_terminals(&write, reconciliation)?;
        Self::clear_recovery_blocks(&write, &record)?;
        write.commit().map_err(storage)?;
        Ok(record)
    }

    fn release(
        &self,
        token: &WriterReservationToken,
        writer_epoch: &EpochIdentity,
    ) -> Result<ReservationRecord, OrsError> {
        require_writer_epoch(token, writer_epoch)?;
        let write = self.database.begin_write().map_err(storage)?;
        let mut record;
        {
            let mut table = write.open_table(RESERVATIONS).map_err(storage)?;
            record = Self::load_record(&table, &token.reservation_id)?;
            Self::validate_token(&record, token)?;
            match record.state {
                ReservationState::Released if record.terminal_receipt_id.is_none() => {
                    return Ok(record);
                }
                ReservationState::Reserved | ReservationState::Eligible => {}
                _ => return Err(OrsError::InvalidTransition),
            }
            record.state = ReservationState::Released;
            let payload = encode(&record)?;
            table
                .insert(token.reservation_id.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(record)
    }

    fn expire(
        &self,
        token: &WriterReservationToken,
        now_ms: i64,
        recovery_owner: &crate::RecoveryOwner,
    ) -> Result<ReservationRecord, OrsError> {
        if &token.recovery_owner != recovery_owner {
            return Err(OrsError::RecoveryOwnerMismatch);
        }
        if now_ms < token.expires_at_ms {
            return Err(OrsError::InvalidExpiry);
        }
        let write = self.database.begin_write().map_err(storage)?;
        let record;
        {
            let table = write.open_table(RESERVATIONS).map_err(storage)?;
            record = Self::load_record(&table, &token.reservation_id)?;
            Self::validate_token(&record, token)?;
            if !record.state.is_terminal() {
                return Err(OrsError::UnsafeExpiry);
            }
        }
        {
            let mut envelopes = write.open_table(ENVELOPES).map_err(storage)?;
            envelopes
                .remove(token.operation_id.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(record)
    }

    fn recover_page(&self, cursor: RecoveryCursor) -> Result<RecoveryPage, OrsError> {
        recovery_projection::recover_page(self, cursor)
    }

    fn get_envelope(
        &self,
        operation_id: &crate::OperationIdentity,
    ) -> Result<Option<RecoveryPayloadEnvelope>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(ENVELOPES).map_err(storage)?;
        table
            .get(operation_id.as_str())
            .map_err(storage)?
            .map(|value| decode(value.value()))
            .transpose()
    }

    fn accept_after_stage(&self, request: ReservationRequest) -> Result<AcceptedPending, OrsError> {
        request
            .validate()
            .map_err(|error| OrsError::StagingNotDurable(error.to_string()))?;
        let token = self
            .stage_and_reserve(request)
            .map_err(|error| OrsError::StagingNotDurable(error.to_string()))?;
        // Read-back proof: the committed envelope must decode and validate,
        // and the operation index must resolve to this reservation. Only then
        // may ACCEPTED_PENDING be observed. A read-back validation failure
        // retains a durable Recovery Problem instead of deleting or
        // fabricating the staged payload.
        match self.get_envelope(&token.operation_id) {
            Ok(Some(envelope)) => {
                if envelope.operation_or_checkpoint_id != token.operation_id {
                    return Err(OrsError::StagingNotDurable(
                        "staged envelope identity does not match the reservation".to_owned(),
                    ));
                }
                let read = self.database.begin_read().map_err(storage)?;
                let indexed = {
                    let operations = read.open_table(OPERATIONS).map_err(storage)?;
                    operations
                        .get(token.operation_id.as_str())
                        .map_err(storage)?
                        .map(|value| value.value().to_owned())
                };
                if indexed.as_deref() != Some(token.reservation_id.as_str()) {
                    return Err(OrsError::StagingNotDurable(
                        "staged operation index is missing on read-back".to_owned(),
                    ));
                }
                Ok(AcceptedPending {
                    operation_id: token.operation_id.clone(),
                    reservation_id: token.reservation_id.clone(),
                    reservation_order: token.reservation_order,
                    prepared_transition_sha256: token.prepared_transition_sha256.clone(),
                })
            }
            Ok(None) => Err(OrsError::StagingNotDurable(
                "staged envelope is missing on read-back".to_owned(),
            )),
            Err(error) => {
                let fingerprint = {
                    let read = self.database.begin_read().map_err(storage)?;
                    let table = read.open_table(ENVELOPES).map_err(storage)?;
                    table
                        .get(token.operation_id.as_str())
                        .map_err(storage)?
                        .map(|value| raw_fingerprint(value.value()))
                };
                let retained = self.retain_staging_problem(&token, &error, fingerprint)?;
                Err(OrsError::RecoveryProblemRetained {
                    operation_id: retained.operation_or_checkpoint_id.as_str().to_owned(),
                })
            }
        }
    }

    fn verify_staged_envelope(
        &self,
        operation_id: &crate::OperationIdentity,
    ) -> Result<RecoveryPayloadEnvelope, OrsError> {
        let raw = {
            let read = self.database.begin_read().map_err(storage)?;
            let table = read.open_table(ENVELOPES).map_err(storage)?;
            table
                .get(operation_id.as_str())
                .map_err(storage)?
                .map(|value| value.value().to_owned())
        };
        let Some(raw) = raw else {
            return Err(OrsError::ReservationNotFound);
        };
        match decode::<RecoveryPayloadEnvelope>(raw.as_str()) {
            Ok(envelope) => {
                if envelope.operation_or_checkpoint_id != *operation_id {
                    let context = self.staging_context(operation_id)?;
                    let retained = self.retain_staging_problem(
                        &context,
                        &OrsError::IntegrityProblem {
                            record_type: "recovery_envelope",
                            reason: "envelope identity does not match its operation key".to_owned(),
                        },
                        Some(raw_fingerprint(&raw)),
                    )?;
                    return Err(OrsError::RecoveryProblemRetained {
                        operation_id: retained.operation_or_checkpoint_id.as_str().to_owned(),
                    });
                }
                Ok(envelope)
            }
            Err(error) => {
                let fingerprint = Some(raw_fingerprint(&raw));
                let context = self.staging_context(operation_id)?;
                let retained = self.retain_staging_problem(&context, &error, fingerprint)?;
                Err(OrsError::RecoveryProblemRetained {
                    operation_id: retained.operation_or_checkpoint_id.as_str().to_owned(),
                })
            }
        }
    }

    fn report_recovery_problem(
        &self,
        problem: RecoveryProblem,
    ) -> Result<RecoveryProblem, OrsError> {
        problem.validate()?;
        if !matches!(
            problem.kind,
            RecoveryProblemKind::MissingKey | RecoveryProblemKind::DecryptionFailure
        ) {
            return Err(OrsError::InvalidField {
                field: "recovery_problem_kind",
                reason: "external reports are limited to missing-key and decryption-failure causes",
            });
        }
        let write = self.database.begin_write().map_err(storage)?;
        {
            let problems = write.open_table(RECOVERY_PROBLEMS).map_err(storage)?;
            let key = problem.operation_or_checkpoint_id.as_str();
            if let Some(existing) = problems
                .get(key)
                .map_err(storage)?
                .map(|value| decode::<RecoveryProblem>(value.value()))
                .transpose()?
            {
                if existing == problem
                    || (existing.operation_or_checkpoint_id == problem.operation_or_checkpoint_id
                        && existing.kind == problem.kind
                        && existing.detail == problem.detail
                        && existing.envelope_sha256 == problem.envelope_sha256
                        && existing.payload_sha256 == problem.payload_sha256
                        && existing.authority_epoch == problem.authority_epoch
                        && existing.state_fence == problem.state_fence
                        && existing.recovery_owner == problem.recovery_owner
                        && existing.terminal_receipt_id == problem.terminal_receipt_id)
                {
                    return Ok(existing);
                }
                return Err(OrsError::DuplicateConflict);
            }
        }
        let payload = encode(&problem)?;
        {
            let mut problems = write.open_table(RECOVERY_PROBLEMS).map_err(storage)?;
            problems
                .insert(
                    problem.operation_or_checkpoint_id.as_str(),
                    payload.as_str(),
                )
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(problem)
    }

    fn load_recovery_problem(
        &self,
        operation_id: &crate::OperationIdentity,
    ) -> Result<Option<RecoveryProblem>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(RECOVERY_PROBLEMS).map_err(storage)?;
        table
            .get(operation_id.as_str())
            .map_err(storage)?
            .map(|value| decode(value.value()))
            .transpose()
    }

    fn list_recovery_problems(&self, limit: u16) -> Result<Vec<RecoveryProblem>, OrsError> {
        if limit == 0 || limit > crate::MAX_RECOVERY_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(RECOVERY_PROBLEMS).map_err(storage)?;
        let mut problems = Vec::new();
        for row in table.iter().map_err(storage)? {
            let (_, value) = row.map_err(storage)?;
            problems.push(decode::<RecoveryProblem>(value.value())?);
            if problems.len() == usize::from(limit) {
                break;
            }
        }
        Ok(problems)
    }

    fn resolve_recovery_problem(
        &self,
        operation_id: &crate::OperationIdentity,
        receipt_id: &OpaqueLabel,
        recovery_owner: &crate::RecoveryOwner,
    ) -> Result<RecoveryProblem, OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        let mut problem = {
            let table = write.open_table(RECOVERY_PROBLEMS).map_err(storage)?;
            table
                .get(operation_id.as_str())
                .map_err(storage)?
                .map(|value| decode::<RecoveryProblem>(value.value()))
                .transpose()?
                .ok_or(OrsError::ReservationNotFound)?
        };
        if &problem.recovery_owner != recovery_owner {
            return Err(OrsError::RecoveryOwnerMismatch);
        }
        if let Some(terminal) = &problem.terminal_receipt_id {
            if terminal == receipt_id {
                return Ok(problem);
            }
            return Err(OrsError::DuplicateConflict);
        }
        problem.terminal_receipt_id = Some(receipt_id.clone());
        let payload = encode(&problem)?;
        {
            let mut table = write.open_table(RECOVERY_PROBLEMS).map_err(storage)?;
            table
                .insert(operation_id.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(problem)
    }

    fn fence_writer_epoch(
        &self,
        scopes: &[crate::OrderingScope],
        successor: &EpochLineage,
    ) -> Result<(), OrsError> {
        successor.validate()?;
        if scopes.is_empty() {
            return Err(OrsError::EmptyScopeSet);
        }
        let unique: BTreeSet<_> = scopes.iter().cloned().collect();
        if unique.len() != scopes.len() {
            return Err(OrsError::DuplicateScope);
        }
        if unique.len() > usize::from(crate::MAX_RECOVERY_PAGE) {
            return Err(OrsError::InvalidCursorLimit);
        }
        let write = self.database.begin_write().map_err(storage)?;
        let mut affected_scopes = BTreeSet::new();
        {
            let reservations = write.open_table(RESERVATIONS).map_err(storage)?;
            for row in reservations.iter().map_err(storage)? {
                let (_, value) = row.map_err(storage)?;
                let record: ReservationRecord = decode(value.value())?;
                if !record.state.is_terminal()
                    && record.token.writer_epoch.current != successor.current
                {
                    for reserved in &record.token.scopes {
                        if unique.contains(&reserved.scope) {
                            affected_scopes.insert(reserved.scope.clone());
                        }
                    }
                }
            }
        }
        {
            let mut heads = write.open_table(SCOPE_HEADS).map_err(storage)?;
            for scope in &unique {
                let value = heads.get(scope.as_str()).map_err(storage)?.ok_or_else(|| {
                    OrsError::IntegrityProblem {
                        record_type: "scope_head",
                        reason: "scope has no writer epoch".to_owned(),
                    }
                })?;
                let mut head: ScopeReservationHead = decode(value.value())?;
                drop(value);
                if !successor.succeeds(&head.writer_epoch) {
                    return Err(OrsError::InvalidEpochLineage);
                }
                head.writer_epoch = successor.current.clone();
                head.recovery_blocked = affected_scopes.contains(scope);
                let payload = encode(&head)?;
                heads
                    .insert(scope.as_str(), payload.as_str())
                    .map_err(storage)?;
            }
        }
        let fenced_reason = OpaqueLabel::new("writer epoch fenced")?;
        loop {
            let mut affected = Vec::with_capacity(usize::from(crate::MAX_RECOVERY_PAGE));
            {
                let reservations = write.open_table(RESERVATIONS).map_err(storage)?;
                for row in reservations.iter().map_err(storage)? {
                    let (key, value) = row.map_err(storage)?;
                    let record: ReservationRecord = decode(value.value())?;
                    if !record.state.is_terminal()
                        && record.token.writer_epoch.current != successor.current
                        && record
                            .token
                            .scopes
                            .iter()
                            .any(|reserved| unique.contains(&reserved.scope))
                        && !(record.state == ReservationState::Reconciling
                            && record.unknown_reason.as_ref() == Some(&fenced_reason))
                    {
                        affected.push((key.value().to_owned(), record));
                        if affected.len() == usize::from(crate::MAX_RECOVERY_PAGE) {
                            break;
                        }
                    }
                }
            }
            if affected.is_empty() {
                break;
            }
            let mut reservations = write.open_table(RESERVATIONS).map_err(storage)?;
            for (key, mut record) in affected {
                record.state = ReservationState::Reconciling;
                record.unknown_reason = Some(fenced_reason.clone());
                let payload = encode(&record)?;
                reservations
                    .insert(key.as_str(), payload.as_str())
                    .map_err(storage)?;
            }
        }
        write.commit().map_err(storage)
    }

    fn stage_host_request(
        &self,
        record: &crate::HostRequestRecord,
    ) -> Result<crate::HostRequestRecord, OrsError> {
        RedbRecoveryStore::stage_host_request(self, record)
    }

    fn advance_host_request(
        &self,
        operation_id: &crate::OperationIdentity,
        request_digest: &str,
        target: crate::HostRequestState,
        result_digest: Option<&str>,
    ) -> Result<Option<crate::HostRequestRecord>, OrsError> {
        RedbRecoveryStore::advance_host_request(
            self,
            operation_id,
            request_digest,
            target,
            result_digest,
        )
    }

    fn persist_host_request_result(
        &self,
        operation_id: &crate::OperationIdentity,
        request_digest: &str,
        result_digest: &str,
        result_response: &serde_json::Value,
    ) -> Result<Option<crate::HostRequestRecord>, OrsError> {
        RedbRecoveryStore::persist_host_request_result(
            self,
            operation_id,
            request_digest,
            result_digest,
            result_response,
        )
    }

    fn load_host_request(
        &self,
        operation_id: &crate::OperationIdentity,
        request_digest: &str,
    ) -> Result<Option<crate::HostRequestRecord>, OrsError> {
        RedbRecoveryStore::load_host_request(self, operation_id, request_digest)
    }

    fn resolve_or_stage_host_request(
        &self,
        record: &crate::HostRequestRecord,
    ) -> Result<crate::HostRequestRecord, OrsError> {
        RedbRecoveryStore::resolve_or_stage_host_request(self, record)
    }

    fn load_host_request_by_logical_key(
        &self,
        logical_key: &str,
    ) -> Result<Option<crate::HostRequestRecord>, OrsError> {
        RedbRecoveryStore::load_host_request_by_logical_key(self, logical_key)
    }

    fn stage_activation_ticket(
        &self,
        record: &ActivationLifecycleRecord,
        now_unix_ms: u64,
    ) -> Result<ActivationLifecycleRecord, OrsError> {
        RedbRecoveryStore::stage_activation_ticket(self, record, now_unix_ms)
    }

    fn claim_activation_ticket(
        &self,
        ticket_id: &str,
        claim_owner: &str,
        now_unix_ms: u64,
        claim_expires_at_unix_ms: u64,
    ) -> Result<Option<ActivationLifecycleRecord>, OrsError> {
        RedbRecoveryStore::claim_activation_ticket(
            self,
            ticket_id,
            claim_owner,
            now_unix_ms,
            claim_expires_at_unix_ms,
        )
    }

    fn commit_activation_result(
        &self,
        record: &ActivationResultRetentionRecord,
        claim_owner: &str,
        dependency_observation: Option<(&str, &str)>,
        now_unix_ms: u64,
    ) -> Result<ActivationResultRetentionRecord, OrsError> {
        RedbRecoveryStore::commit_activation_result(
            self,
            record,
            claim_owner,
            dependency_observation,
            now_unix_ms,
        )
    }

    fn load_campaign_learning_state_view(
        &self,
        view_id: &eliot_contracts::ArtifactId,
    ) -> Result<Option<eliot_store_api::CampaignLearningStateViewPublication>, OrsError> {
        RedbRecoveryStore::load_campaign_learning_state_view(self, view_id)
    }

    fn reserve_campaign_source_publications(
        &self,
        operation_id: &eliot_contracts::OperationId,
        request_digest: &str,
        publications: &[eliot_store_api::CampaignSourcePublication],
    ) -> Result<(), OrsError> {
        RedbRecoveryStore::reserve_campaign_source_publications(
            self,
            operation_id,
            request_digest,
            publications,
        )
    }

    fn commit_campaign_source_publications(
        &self,
        operation_id: &eliot_contracts::OperationId,
        request_digest: &str,
        publications: &[eliot_store_api::CampaignSourcePublication],
        receipt: &eliot_store_api::WriteReceipt,
    ) -> Result<(), OrsError> {
        RedbRecoveryStore::commit_campaign_source_publications(
            self,
            operation_id,
            request_digest,
            publications,
            receipt,
        )
    }

    fn abort_campaign_source_publications(
        &self,
        operation_id: &eliot_contracts::OperationId,
        request_digest: &str,
        publications: &[eliot_store_api::CampaignSourcePublication],
    ) -> Result<(), OrsError> {
        RedbRecoveryStore::abort_campaign_source_publications(
            self,
            operation_id,
            request_digest,
            publications,
        )
    }

    fn load_campaign_source_revision(
        &self,
        lookup: &eliot_store_api::CampaignSourceRevisionLookup,
        read_state_fence: &eliot_contracts::StateFence,
    ) -> Result<eliot_store_api::CampaignSourceRevisionRead, OrsError> {
        RedbRecoveryStore::load_campaign_source_revision(self, lookup, read_state_fence)
    }

    fn retain_activation_result(
        &self,
        record: &ActivationResultRetentionRecord,
        claim_owner: &str,
        dependency_observation: Option<(&str, &str)>,
        now_unix_ms: u64,
    ) -> Result<ActivationResultRetentionRecord, OrsError> {
        RedbRecoveryStore::commit_activation_result(
            self,
            record,
            claim_owner,
            dependency_observation,
            now_unix_ms,
        )
    }

    fn terminate_activation_without_result(
        &self,
        ticket_id: &str,
        target: ActivationLifecycleState,
        reason: &str,
        now_unix_ms: u64,
    ) -> Result<Option<ActivationLifecycleRecord>, OrsError> {
        RedbRecoveryStore::terminate_activation_without_result(
            self,
            ticket_id,
            target,
            reason,
            now_unix_ms,
        )
    }

    fn load_activation_lifecycle(
        &self,
        ticket_id: &str,
    ) -> Result<Option<ActivationLifecycleRecord>, OrsError> {
        RedbRecoveryStore::load_activation_lifecycle(self, ticket_id)
    }

    fn load_activation_result(
        &self,
        ticket_id: &str,
        result_sha256: &str,
    ) -> Result<Option<ActivationResultRetentionRecord>, OrsError> {
        RedbRecoveryStore::load_activation_result(self, ticket_id, result_sha256)
    }

    fn load_activation_recovery_snapshot(&self) -> Result<ActivationRecoverySnapshot, OrsError> {
        RedbRecoveryStore::load_activation_recovery_snapshot(self)
    }

    fn prune_activation_results(&self) -> Result<u64, OrsError> {
        RedbRecoveryStore::prune_activation_results(self)
    }

    fn stage_native_worker_claim(
        &self,
        record: &crate::NativeWorkerClaimRecord,
    ) -> Result<crate::NativeWorkerClaimStageOutcome, OrsError> {
        RedbRecoveryStore::stage_native_worker_claim(self, record)
    }

    fn advance_native_worker_claim(
        &self,
        claim_id: &crate::OperationIdentity,
        target: crate::NativeWorkerClaimState,
        admission: Option<&crate::NativeWorkerClaimAdmission>,
    ) -> Result<Option<crate::NativeWorkerClaimRecord>, OrsError> {
        RedbRecoveryStore::advance_native_worker_claim(self, claim_id, target, admission)
    }

    fn load_native_worker_claim(
        &self,
        claim_id: &crate::OperationIdentity,
    ) -> Result<Option<crate::NativeWorkerClaimRecord>, OrsError> {
        RedbRecoveryStore::load_native_worker_claim(self, claim_id)
    }

    fn lookup_replay_request(
        &self,
        stream_id: &str,
        request_id: &str,
        fingerprint: &str,
    ) -> Result<WorkerReplayRequestDecision, OrsError> {
        RedbRecoveryStore::lookup_replay_request(self, stream_id, request_id, fingerprint)
    }

    fn begin_replay_request(
        &self,
        begin: &WorkerReplayBegin,
    ) -> Result<WorkerReplayRequestDecision, OrsError> {
        RedbRecoveryStore::begin_replay_request(self, begin)
    }

    fn append_replay_event(
        &self,
        draft: &WorkerReplayDraft,
    ) -> Result<WorkerReplayEvent, OrsError> {
        RedbRecoveryStore::append_replay_event(self, draft)
    }

    fn replay_stream(
        &self,
        stream_id: &str,
        after_sequence: u64,
    ) -> Result<Vec<WorkerReplayEvent>, OrsError> {
        RedbRecoveryStore::replay_stream(self, stream_id, after_sequence)
    }

    fn acknowledge_replay_event(
        &self,
        ack: &WorkerReplayAck,
    ) -> Result<WorkerReplayCursors, OrsError> {
        RedbRecoveryStore::acknowledge_replay_event(self, ack)
    }

    fn prune_replay_stream(&self, stream_id: &str) -> Result<u64, OrsError> {
        RedbRecoveryStore::prune_replay_stream(self, stream_id)
    }

    fn load_replay_stream_head(
        &self,
        stream_id: &str,
    ) -> Result<Option<WorkerReplayStreamRecord>, OrsError> {
        RedbRecoveryStore::load_replay_stream_head(self, stream_id)
    }

    fn load_replay_request_record(
        &self,
        stream_id: &str,
        request_id: &str,
    ) -> Result<Option<WorkerReplayRequestRecord>, OrsError> {
        RedbRecoveryStore::load_replay_request_record(self, stream_id, request_id)
    }
}

impl crate::DoctorRecoveryLedger for RedbRecoveryStore {
    fn stage_doctor_attempt(
        &self,
        record: &crate::DoctorAttemptRecord,
    ) -> Result<crate::DoctorAttemptStageOutcome, crate::DoctorLedgerError> {
        RedbRecoveryStore::stage_doctor_attempt(self, record)
    }

    fn load_doctor_attempt(
        &self,
        attempt_digest: &crate::OperationIdentity,
    ) -> Result<Option<crate::DoctorAttemptRecord>, crate::DoctorLedgerError> {
        RedbRecoveryStore::load_doctor_attempt(self, attempt_digest)
    }

    fn advance_doctor_attempt(
        &self,
        attempt_digest: &crate::OperationIdentity,
        target: crate::DoctorAttemptState,
        admission: Option<&crate::DoctorAttemptAdmission>,
    ) -> Result<Option<crate::DoctorAttemptRecord>, crate::DoctorLedgerError> {
        RedbRecoveryStore::advance_doctor_attempt(self, attempt_digest, target, admission)
    }

    fn stage_doctor_effect(
        &self,
        record: &crate::DoctorEffectRecord,
    ) -> Result<crate::DoctorEffectStageOutcome, crate::DoctorLedgerError> {
        RedbRecoveryStore::stage_doctor_effect(self, record)
    }

    fn load_doctor_effect(
        &self,
        effect_digest: &crate::OperationIdentity,
    ) -> Result<Option<crate::DoctorEffectRecord>, crate::DoctorLedgerError> {
        RedbRecoveryStore::load_doctor_effect(self, effect_digest)
    }

    fn record_doctor_effect_outcome(
        &self,
        effect_digest: &crate::OperationIdentity,
        report: &crate::DoctorEffectOutcomeReport,
    ) -> Result<Option<crate::DoctorEffectRecord>, crate::DoctorLedgerError> {
        RedbRecoveryStore::record_doctor_effect_outcome(self, effect_digest, report)
    }

    fn load_doctor_budget(
        &self,
        scope_key: &crate::OpaqueLabel,
    ) -> Result<Option<crate::DoctorBudgetLedger>, crate::DoctorLedgerError> {
        RedbRecoveryStore::load_doctor_budget(self, scope_key)
    }

    fn store_doctor_budget(
        &self,
        ledger: &crate::DoctorBudgetLedger,
    ) -> Result<(), crate::DoctorLedgerError> {
        RedbRecoveryStore::store_doctor_budget(self, ledger)
    }
}

/// Single coordinator facade. It owns no semantic policy and delegates one durable transition.
pub struct OrsCoordinator<S = RedbRecoveryStore> {
    store: S,
}

impl OrsCoordinator<RedbRecoveryStore> {
    /// Opens the concrete redb-backed coordinator.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, OrsError> {
        Ok(Self {
            store: RedbRecoveryStore::open(path)?,
        })
    }
}

impl<S: OperationalRecoveryStore> OrsCoordinator<S> {
    /// Injects one transactional store implementation.
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    /// Returns the injected store for bounded provider-specific observation.
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Stages typed generation evidence through the canonical ORS boundary.
    pub fn stage_generation_cutover(
        &self,
        record: RuntimeGenerationCutoverRecord,
    ) -> Result<GenerationCutoverSnapshot, OrsError> {
        self.store.stage_generation_cutover(record)
    }

    /// Commits typed generation evidence at the canonical ORS linearization
    /// point.
    pub fn commit_generation_cutover_state(
        &self,
        record: RuntimeGenerationCutoverRecord,
    ) -> Result<GenerationCutoverSnapshot, OrsError> {
        self.store.commit_generation_cutover_state(record)
    }

    /// Reads the bounded canonical generation route projection.
    pub fn latest_generation_cutovers(
        &self,
        limit: u16,
    ) -> Result<Vec<GenerationCutoverSnapshot>, OrsError> {
        self.store.latest_generation_cutovers(limit)
    }

    /// Reconciles interrupted candidates without activating them.
    pub fn reconcile_staged_generation_cutovers(
        &self,
        limit: u16,
    ) -> Result<Vec<GenerationCutoverSnapshot>, OrsError> {
        self.store.reconcile_staged_generation_cutovers(limit)
    }

    /// Atomically stages one envelope and reserves every declared scope.
    pub fn reserve(&self, request: ReservationRequest) -> Result<WriterReservationToken, OrsError> {
        self.store.stage_and_reserve(request)
    }

    /// Advances a head reservation to eligibility after all predecessors close.
    pub fn eligible(&self, token: &WriterReservationToken) -> Result<ReservationRecord, OrsError> {
        self.store.mark_eligible(token)
    }

    /// Starts execution under the exact immutable writer epoch.
    pub fn execute(
        &self,
        token: &WriterReservationToken,
        writer_epoch: &EpochIdentity,
    ) -> Result<ReservationRecord, OrsError> {
        self.store.begin_execute(token, writer_epoch)
    }

    /// Makes an ambiguous effect non-replayable until canonical reconciliation.
    pub fn unknown(
        &self,
        token: &WriterReservationToken,
        writer_epoch: &EpochIdentity,
        reason: OpaqueLabel,
    ) -> Result<ReservationRecord, OrsError> {
        self.store.mark_unknown(token, writer_epoch, reason)
    }

    /// Closes an executing/unknown reservation only from exact receipt/read-back evidence.
    pub fn reconcile(
        &self,
        reconciliation: &CanonicalReconciliation,
    ) -> Result<ReservationRecord, OrsError> {
        self.store.reconcile(reconciliation)
    }

    /// Releases work that has not executed under the exact writer epoch.
    pub fn release(
        &self,
        token: &WriterReservationToken,
        writer_epoch: &EpochIdentity,
    ) -> Result<ReservationRecord, OrsError> {
        self.store.release(token, writer_epoch)
    }

    /// Durably stages one complete opaque operation and returns
    /// `ACCEPTED_PENDING` only after the commit, read-back, hash validation,
    /// and operation-identity indexing are proven (issue #1925).
    pub fn accept_after_stage(
        &self,
        request: ReservationRequest,
    ) -> Result<AcceptedPending, OrsError> {
        self.store.accept_after_stage(request)
    }

    /// Revalidates one staged envelope by operation identity, retaining a
    /// durable Recovery Problem instead of deleting on failure (issue #1925).
    pub fn verify_staged_envelope(
        &self,
        operation_id: &crate::OperationIdentity,
    ) -> Result<RecoveryPayloadEnvelope, OrsError> {
        self.store.verify_staged_envelope(operation_id)
    }

    /// Retains one caller-reported missing-key/decryption-failure problem.
    /// Digest-only: no payload bytes are accepted or stored.
    pub fn report_recovery_problem(
        &self,
        problem: RecoveryProblem,
    ) -> Result<RecoveryProblem, OrsError> {
        self.store.report_recovery_problem(problem)
    }

    /// Loads one durable Recovery Problem by staged operation identity.
    pub fn load_recovery_problem(
        &self,
        operation_id: &crate::OperationIdentity,
    ) -> Result<Option<RecoveryProblem>, OrsError> {
        self.store.load_recovery_problem(operation_id)
    }

    /// Lists retained Recovery Problems in operation-identity order.
    pub fn list_recovery_problems(&self, limit: u16) -> Result<Vec<RecoveryProblem>, OrsError> {
        self.store.list_recovery_problems(limit)
    }

    /// Closes one retained Recovery Problem from an explicit terminal receipt
    /// under the exact recovery owner.
    pub fn resolve_recovery_problem(
        &self,
        operation_id: &crate::OperationIdentity,
        receipt_id: &OpaqueLabel,
        recovery_owner: &crate::RecoveryOwner,
    ) -> Result<RecoveryProblem, OrsError> {
        self.store
            .resolve_recovery_problem(operation_id, receipt_id, recovery_owner)
    }

    /// Stages one P-04 host-request operation before any acknowledgement.
    pub fn stage_host_request(
        &self,
        record: &HostRequestRecord,
    ) -> Result<HostRequestRecord, OrsError> {
        self.store.stage_host_request(record)
    }

    /// Advances one staged host-request operation to its next mechanical state.
    pub fn advance_host_request(
        &self,
        operation_id: &crate::OperationIdentity,
        request_digest: &str,
        target: HostRequestState,
        result_digest: Option<&str>,
    ) -> Result<Option<HostRequestRecord>, OrsError> {
        self.store
            .advance_host_request(operation_id, request_digest, target, result_digest)
    }

    /// Persists one bounded local-read result body alongside its digest.
    pub fn persist_host_request_result(
        &self,
        operation_id: &crate::OperationIdentity,
        request_digest: &str,
        result_digest: &str,
        result_response: &serde_json::Value,
    ) -> Result<Option<HostRequestRecord>, OrsError> {
        self.store.persist_host_request_result(
            operation_id,
            request_digest,
            result_digest,
            result_response,
        )
    }

    /// Loads one host-request operation by exact operation/request identity.
    pub fn load_host_request(
        &self,
        operation_id: &crate::OperationIdentity,
        request_digest: &str,
    ) -> Result<Option<HostRequestRecord>, OrsError> {
        self.store.load_host_request(operation_id, request_digest)
    }

    /// Atomically claims one logical host-request key or returns its winner.
    ///
    /// See [`OperationalRecoveryStore::resolve_or_stage_host_request`]: the
    /// caller compares the returned identity with its candidate to tell a
    /// fresh stage (equal identity, may advance) from another transport's
    /// winner (different identity, return without dispatch).
    pub fn resolve_or_stage_host_request(
        &self,
        record: &HostRequestRecord,
    ) -> Result<HostRequestRecord, OrsError> {
        self.store.resolve_or_stage_host_request(record)
    }

    /// Loads one host-request operation by logical key.
    ///
    /// See [`OperationalRecoveryStore::load_host_request_by_logical_key`]:
    /// `Ok(None)` is authoritatively absent, `Err` is never absence.
    pub fn load_host_request_by_logical_key(
        &self,
        logical_key: &str,
    ) -> Result<Option<HostRequestRecord>, OrsError> {
        self.store.load_host_request_by_logical_key(logical_key)
    }

    /// Durably stages one pending activation ticket before publication.
    pub fn stage_activation_ticket(
        &self,
        record: &ActivationLifecycleRecord,
        now_unix_ms: u64,
    ) -> Result<ActivationLifecycleRecord, OrsError> {
        self.store.stage_activation_ticket(record, now_unix_ms)
    }

    /// Claims one pending activation ticket for the authenticated daemon.
    pub fn claim_activation_ticket(
        &self,
        ticket_id: &str,
        claim_owner: &str,
        now_unix_ms: u64,
        claim_expires_at_unix_ms: u64,
    ) -> Result<Option<ActivationLifecycleRecord>, OrsError> {
        self.store.claim_activation_ticket(
            ticket_id,
            claim_owner,
            now_unix_ms,
            claim_expires_at_unix_ms,
        )
    }

    /// Atomically commits one result with its lifecycle CAS.
    pub fn commit_activation_result(
        &self,
        record: &ActivationResultRetentionRecord,
        claim_owner: &str,
        dependency_observation: Option<(&str, &str)>,
        now_unix_ms: u64,
    ) -> Result<ActivationResultRetentionRecord, OrsError> {
        self.store.commit_activation_result(
            record,
            claim_owner,
            dependency_observation,
            now_unix_ms,
        )
    }

    /// Loads one immutable content-addressed campaign view.
    pub fn load_campaign_learning_state_view(
        &self,
        view_id: &eliot_contracts::ArtifactId,
    ) -> Result<Option<eliot_store_api::CampaignLearningStateViewPublication>, OrsError> {
        self.store.load_campaign_learning_state_view(view_id)
    }

    /// Reserves all exact campaign source CAS heads before the canonical
    /// owner operation executes.
    pub fn reserve_campaign_source_publications(
        &self,
        operation_id: &eliot_contracts::OperationId,
        request_digest: &str,
        publications: &[eliot_store_api::CampaignSourcePublication],
    ) -> Result<(), OrsError> {
        self.store
            .reserve_campaign_source_publications(operation_id, request_digest, publications)
    }

    /// Finalizes typed campaign sources from the exact committed owner
    /// receipt.
    pub fn commit_campaign_source_publications(
        &self,
        operation_id: &eliot_contracts::OperationId,
        request_digest: &str,
        publications: &[eliot_store_api::CampaignSourcePublication],
        receipt: &eliot_store_api::WriteReceipt,
    ) -> Result<(), OrsError> {
        self.store.commit_campaign_source_publications(
            operation_id,
            request_digest,
            publications,
            receipt,
        )
    }

    /// Releases source reservations after an exact typed negative receipt.
    pub fn abort_campaign_source_publications(
        &self,
        operation_id: &eliot_contracts::OperationId,
        request_digest: &str,
        publications: &[eliot_store_api::CampaignSourcePublication],
    ) -> Result<(), OrsError> {
        self.store
            .abort_campaign_source_publications(operation_id, request_digest, publications)
    }

    /// Reads one immutable campaign owner source and its current head at one
    /// ORS snapshot.
    pub fn load_campaign_source_revision(
        &self,
        lookup: &eliot_store_api::CampaignSourceRevisionLookup,
        read_state_fence: &eliot_contracts::StateFence,
    ) -> Result<eliot_store_api::CampaignSourceRevisionRead, OrsError> {
        self.store
            .load_campaign_source_revision(lookup, read_state_fence)
    }

    /// Retains one opaque Kernel activation result before acknowledgement.
    pub fn retain_activation_result(
        &self,
        record: &ActivationResultRetentionRecord,
        claim_owner: &str,
        dependency_observation: Option<(&str, &str)>,
        now_unix_ms: u64,
    ) -> Result<ActivationResultRetentionRecord, OrsError> {
        self.store.commit_activation_result(
            record,
            claim_owner,
            dependency_observation,
            now_unix_ms,
        )
    }

    /// Terminalizes one result-less activation ticket.
    pub fn terminate_activation_without_result(
        &self,
        ticket_id: &str,
        target: ActivationLifecycleState,
        reason: &str,
        now_unix_ms: u64,
    ) -> Result<Option<ActivationLifecycleRecord>, OrsError> {
        self.store
            .terminate_activation_without_result(ticket_id, target, reason, now_unix_ms)
    }

    /// Loads one activation lifecycle row.
    pub fn load_activation_lifecycle(
        &self,
        ticket_id: &str,
    ) -> Result<Option<ActivationLifecycleRecord>, OrsError> {
        self.store.load_activation_lifecycle(ticket_id)
    }

    /// Loads one retained activation result by exact ticket and result identity.
    pub fn load_activation_result(
        &self,
        ticket_id: &str,
        result_sha256: &str,
    ) -> Result<Option<ActivationResultRetentionRecord>, OrsError> {
        self.store.load_activation_result(ticket_id, result_sha256)
    }

    /// Loads coherent activation lifecycle and result recovery state.
    pub fn load_activation_recovery_snapshot(
        &self,
    ) -> Result<ActivationRecoverySnapshot, OrsError> {
        self.store.load_activation_recovery_snapshot()
    }

    /// Prunes oldest unreferenced activation results under hard bounds.
    pub fn prune_activation_results(&self) -> Result<u64, OrsError> {
        self.store.prune_activation_results()
    }

    /// Stages one native-worker claim intent before any acknowledgement.
    pub fn stage_native_worker_claim(
        &self,
        record: &NativeWorkerClaimRecord,
    ) -> Result<NativeWorkerClaimStageOutcome, OrsError> {
        self.store.stage_native_worker_claim(record)
    }

    /// Advances one staged claim to its next mechanical state.
    pub fn advance_native_worker_claim(
        &self,
        claim_id: &crate::OperationIdentity,
        target: NativeWorkerClaimState,
        admission: Option<&NativeWorkerClaimAdmission>,
    ) -> Result<Option<NativeWorkerClaimRecord>, OrsError> {
        self.store
            .advance_native_worker_claim(claim_id, target, admission)
    }

    /// Loads one claim by exact claim identity.
    pub fn load_native_worker_claim(
        &self,
        claim_id: &crate::OperationIdentity,
    ) -> Result<Option<crate::NativeWorkerClaimRecord>, OrsError> {
        self.store.load_native_worker_claim(claim_id)
    }

    /// Looks up one durable replay request without acquiring anything.
    pub fn lookup_replay_request(
        &self,
        stream_id: &str,
        request_id: &str,
        fingerprint: &str,
    ) -> Result<WorkerReplayRequestDecision, OrsError> {
        self.store
            .lookup_replay_request(stream_id, request_id, fingerprint)
    }

    /// Atomically acquires one durable replay request or reports its durable
    /// outcome.
    pub fn begin_replay_request(
        &self,
        begin: &WorkerReplayBegin,
    ) -> Result<WorkerReplayRequestDecision, OrsError> {
        self.store.begin_replay_request(begin)
    }

    /// Persists one replay draft under its exact stream with a durable
    /// identity and sequence.
    pub fn append_replay_event(
        &self,
        draft: &WorkerReplayDraft,
    ) -> Result<WorkerReplayEvent, OrsError> {
        self.store.append_replay_event(draft)
    }

    /// Returns the retained suffix strictly after `after_sequence` in
    /// sequence order, preserving gaps.
    pub fn replay_stream(
        &self,
        stream_id: &str,
        after_sequence: u64,
    ) -> Result<Vec<WorkerReplayEvent>, OrsError> {
        self.store.replay_stream(stream_id, after_sequence)
    }

    /// Verifies one acknowledgement against its exact durable event,
    /// persists the disposition, and advances only the cursor its phase
    /// allows.
    pub fn acknowledge_replay_event(
        &self,
        ack: &WorkerReplayAck,
    ) -> Result<WorkerReplayCursors, OrsError> {
        self.store.acknowledge_replay_event(ack)
    }

    /// Prunes the longest APPLIED-or-REJECTED event prefix of one stream,
    /// retaining the newest [`crate::MAX_REPLAY_PAGE`] terminal events.
    pub fn prune_replay_stream(&self, stream_id: &str) -> Result<u64, OrsError> {
        self.store.prune_replay_stream(stream_id)
    }

    /// Loads one replay stream head without mutating anything.
    pub fn load_replay_stream_head(
        &self,
        stream_id: &str,
    ) -> Result<Option<WorkerReplayStreamRecord>, OrsError> {
        self.store.load_replay_stream_head(stream_id)
    }

    /// Loads one retained replay acquisition without mutating anything.
    pub fn load_replay_request_record(
        &self,
        stream_id: &str,
        request_id: &str,
    ) -> Result<Option<WorkerReplayRequestRecord>, OrsError> {
        self.store.load_replay_request_record(stream_id, request_id)
    }
}

fn request_matches(
    request: &ReservationRequest,
    token: &WriterReservationToken,
    envelope: &RecoveryPayloadEnvelope,
) -> bool {
    request.reservation_id == token.reservation_id
        && request.envelope == *envelope
        && request.writer_epoch == token.writer_epoch
        && request.prepared_transition_sha256 == token.prepared_transition_sha256
        && request.expires_at_ms == token.expires_at_ms
        && request.recovery_owner == token.recovery_owner
        && request.scopes.len() == token.scopes.len()
        && request
            .scopes
            .iter()
            .zip(&token.scopes)
            .all(|(left, right)| {
                left.scope == right.scope && left.expected_head == right.expected_head
            })
}

fn require_writer_epoch(
    token: &WriterReservationToken,
    supplied: &EpochIdentity,
) -> Result<(), OrsError> {
    if token.writer_epoch.current != *supplied {
        return Err(OrsError::StaleWriterEpoch);
    }
    Ok(())
}

/// Fingerprints one raw staged-envelope row without trusting it: the SHA-256
/// of the exact stored bytes plus the declared payload digest when it is
/// digest-shaped. Used only to bind a Recovery Problem to the corrupted row;
/// the bytes themselves are never interpreted.
fn raw_fingerprint(raw: &str) -> (String, Option<String>) {
    let envelope_sha256 = crate::model::sha256_hex(raw.as_bytes());
    let payload_sha256 = serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| Some(value.get("payload_sha256")?.as_str()?.to_owned()))
        .filter(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        });
    (envelope_sha256, payload_sha256)
}

/// Builds the bounded operator-visible cause for a staging validation
/// failure. Control characters are neutralized and the text is truncated so
/// the label bound always holds; no payload bytes are ever included.
fn staging_problem_detail(error: &OrsError) -> Result<OpaqueLabel, OrsError> {
    let collapsed: String = error
        .to_string()
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    let mut detail = collapsed.split_whitespace().collect::<Vec<_>>().join(" ");
    while detail.len() > 512 {
        detail.pop();
    }
    let trimmed = detail.trim();
    if trimmed.is_empty() {
        return Err(OrsError::StagingNotDurable(
            "staging failure has no reportable cause".to_owned(),
        ));
    }
    OpaqueLabel::new(trimmed).map_err(|_| {
        OrsError::StagingNotDurable("staging failure has no reportable cause".to_owned())
    })
}

fn shares_scope(left: &WriterReservationToken, right: &WriterReservationToken) -> bool {
    left.scopes.iter().any(|left_scope| {
        right
            .scopes
            .iter()
            .any(|right_scope| left_scope.scope == right_scope.scope)
    })
}

fn reconciliation_matches(
    token: &WriterReservationToken,
    reconciliation: &CanonicalReconciliation,
) -> Result<(), OrsError> {
    reconciliation
        .receipt
        .validate()
        .map_err(|error| OrsError::Contract(error.to_string()))?;
    let receipt = &reconciliation.receipt;
    if reconciliation.reservation_id != token.reservation_id
        || reconciliation.operation_id != token.operation_id
        || reconciliation.operation_id.as_str() != receipt.core.operation.operation_id.as_str()
        || reconciliation.reservation_order != token.reservation_order
        || reconciliation.state_fence != token.state_fence
        || reconciliation.recovery_owner != token.recovery_owner
        || reconciliation.scopes.len() != token.scopes.len()
    {
        return Err(OrsError::ReconciliationMismatch);
    }
    // The retained `u64` snapshot contour observes the receipt's canonical
    // `EpochId` sequence (Implements #64); it never authorizes on its own.
    let receipt_fence = crate::StateFenceSnapshot::capture(
        &receipt.core.operation.state_fence,
        receipt.core.authority.authority_epoch.sequence.get(),
    )?;
    if receipt_fence != token.state_fence
        || receipt.core.work_scope.state_fence != receipt.core.operation.state_fence
        || receipt.core.causal.state_fence != receipt.core.operation.state_fence
        || receipt.core.authority.state_fence != receipt.core.operation.state_fence
    {
        return Err(OrsError::ReconciliationMismatch);
    }
    let receipt_kind = receipt.core.disposition.kind();
    let disposition_matches = match reconciliation.disposition {
        CanonicalDisposition::Committed => matches!(
            receipt_kind,
            ReceiptDispositionKind::Success | ReceiptDispositionKind::Partial
        ),
        CanonicalDisposition::Rejected => matches!(
            receipt_kind,
            ReceiptDispositionKind::Failure | ReceiptDispositionKind::Cancelled
        ),
    };
    if receipt_kind == ReceiptDispositionKind::Unknown {
        return Err(OrsError::UnknownReceiptCannotResolve);
    }
    if !disposition_matches {
        return Err(OrsError::ReconciliationMismatch);
    }
    for (reserved, observed) in token.scopes.iter().zip(&reconciliation.scopes) {
        observed.prior_head.validate()?;
        crate::model::validate_digest(&observed.committed_head_sha256, "committed_head_sha256")?;
        if let Some(revision) = &observed.committed_revision_head {
            crate::model::validate_text(revision, "committed_revision_head")?;
        }
        if observed.scope != reserved.scope
            || observed.prior_head != reserved.expected_head
            || observed.committed_sequence != reserved.reserved_sequence
            || observed.committed_head_sha256 != receipt.identity.canonical_sha256
            || observed.receipt_id.as_str() != receipt.identity.receipt_id.as_str()
        {
            return Err(OrsError::ReconciliationMismatch);
        }
    }
    // No envelope-causal restatement is demanded here, deliberately. The
    // reserved-order binding is established above on the reconciliation
    // scopes (prior head, committed sequence, head digest, receipt id),
    // and the receipt operation, fence, disposition and structural
    // validity are checked by the surrounding clauses. A single-scope
    // causal equality against the reserved sequence would require the
    // producer to state a non-genesis chain position, but the canonical
    // causal model admits non-genesis positions only with a parent link,
    // the closed store issuance carries genesis, and no consumer reads
    // the envelope causal. Demanding the restatement therefore rejects
    // every live receipt while proving nothing the scope checks do not
    // already prove (issue #2031 native cases 15/19).
    Ok(())
}

fn storage(error: impl std::fmt::Display) -> OrsError {
    OrsError::Storage(error.to_string())
}

fn campaign_view_publication(
    response: &serde_json::Value,
) -> Result<Option<eliot_store_api::CampaignLearningStateViewPublication>, OrsError> {
    let Some(value) = response.get("campaign_learning_state_view") else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let publication: eliot_store_api::CampaignLearningStateViewPublication =
        serde_json::from_value(value.clone()).map_err(|_| OrsError::InvalidField {
            field: "host_request_result.campaign_learning_state_view",
            reason: "campaign view publication is not the closed typed envelope",
        })?;
    publication.validate().map_err(|_| OrsError::InvalidField {
        field: "host_request_result.campaign_learning_state_view",
        reason: "campaign view publication failed content-addressed binding validation",
    })?;
    Ok(Some(publication))
}

fn campaign_view_identity_conflict(view_id: &str) -> OrsError {
    OrsError::CampaignLearningStateViewConflict {
        view_id: view_id.to_owned(),
    }
}

fn campaign_source_key(record: &eliot_store_api::CampaignSourceRecord) -> Result<String, OrsError> {
    campaign_source_key_parts(record.role, &record.owner_id, &record.record_id)
}

fn campaign_source_key_parts(
    role: eliot_store_api::CampaignSourceRole,
    owner_id: &eliot_store_api::OwnerId,
    record_id: &eliot_store_api::CampaignOwnerRecordId,
) -> Result<String, OrsError> {
    let key_bytes = eliot_store_api::canonical_json_bytes(&(role, owner_id, record_id))
        .map_err(|error| OrsError::Contract(error.to_string()))?;
    Ok(eliot_store_api::sha256_hex(&key_bytes))
}

fn campaign_source_record_key(source_key: &str, content_digest: &str) -> String {
    format!("{source_key}::{content_digest}")
}

fn campaign_record_matches_head(
    record: &eliot_store_api::CampaignSourceRecord,
    head: &eliot_store_api::CampaignSourceHead,
) -> bool {
    record.role == head.role
        && record.owner_id == head.owner_id
        && record.record_id == head.record_id
        && record.revision == head.revision
        && record.content_digest == head.content_digest
        && record.recorded_state_fence == head.recorded_state_fence
        && record.slot_projection_digests == head.slot_projection_digests
}

fn campaign_source_identity_conflict(key: &str) -> OrsError {
    OrsError::CampaignSourcePublicationConflict {
        key: key.to_owned(),
    }
}

#[cfg(test)]
mod process_start_abort_tests {
    use super::*;
    use crate::OperationIdentity;
    use eliot_contracts::{EpochId, EpochLineageId};
    use serde_json::json;

    // Canonical `EpochId` fixture (Implements #64): lineage-aware exact tuple.
    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
            std::num::NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn process_start_receipt(
        operation_id: &str,
        permit_digest: &str,
    ) -> Result<eliot_process::ProcessStartReceipt, OrsError> {
        serde_json::from_value(json!({
            "binding": {
                "operation_id": operation_id,
                "process_tree_id": "tree-1",
                "job_id": "job-1",
                "image_id": "image-1",
                "session_id": "session-1",
                "generation": 1,
                "action_lease_ref": "lease-1",
                "authority_id": "authority-1",
                "authority_epoch": {
                    "lineage_id": TEST_LINEAGE_A,
                    "sequence": 1
                },
                "state_fence": {
                    "authority_epoch": {
                        "lineage_id": TEST_LINEAGE_A,
                        "sequence": 1
                    },
                    "generation": 1,
                    "nonce": "fence-1"
                },
                "request_digest": "11".repeat(32),
                "permit_digest": permit_digest,
                "effect_digest": "33".repeat(32),
                "validation_revision": 1
            },
            "identity": {
                "suspended": {
                    "process_id": "process-1",
                    "process_tree_id": "tree-1",
                    "job_id": "job-1",
                    "image_id": "image-1",
                    "session_id": "session-1",
                    "generation": 1,
                    "physical": {
                        "process_id": 1,
                        "start_time_100ns": 1,
                        "image_path": "C:\\ProgramData\\Eliot\\bin\\eliot-test.exe",
                        "executor_job_name": "Local\\Eliot-ORS-Abort-Test"
                    },
                    "created_suspended_at_unix_ms": 1,
                    "executable_sha256": "aa".repeat(32)
                },
                "resumed_at_unix_ms": 2
            },
            "lifecycle": "running"
        }))
        .map_err(|error| OrsError::IntegrityProblem {
            record_type: "test",
            reason: error.to_string(),
        })
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn reserved_abort_is_compare_delete_and_survives_reopen() -> Result<(), OrsError> {
        let path = std::env::temp_dir().join(format!(
            "eliot-process-start-abort-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        let owner = eliot_process::ProcessOwnerBinding::new(
            "testd",
            "a".repeat(64),
            test_epoch(1),
            eliot_process::Generation::new(1).map_err(|error| OrsError::IntegrityProblem {
                record_type: "test",
                reason: error.to_string(),
            })?,
        )
        .map_err(|error| OrsError::IntegrityProblem {
            record_type: "test",
            reason: error.to_string(),
        })?;
        let operation = OperationIdentity::new("abort-operation")?;
        let record = ProcessStartReplayRecord {
            operation_id: operation.clone(),
            admission_digest: "ab".repeat(32),
            owner: owner.clone(),
            state: ProcessStartReplayState::Reserved,
            receipt: None,
        };
        let store = RedbRecoveryStore::open(&path)?;
        assert!(store.begin_process_start(&record)?.is_none());
        let wrong_owner = eliot_process::ProcessOwnerBinding::new(
            "testd",
            "b".repeat(64),
            test_epoch(1),
            eliot_process::Generation::new(1).map_err(|error| OrsError::IntegrityProblem {
                record_type: "test",
                reason: error.to_string(),
            })?,
        )
        .map_err(|error| OrsError::IntegrityProblem {
            record_type: "test",
            reason: error.to_string(),
        })?;
        assert!(matches!(
            store.abort_process_start(&operation, &"cd".repeat(32), &owner),
            Err(OrsError::IntegrityProblem { .. })
        ));
        assert!(matches!(
            store.abort_process_start(&operation, &record.admission_digest, &wrong_owner),
            Err(OrsError::IntegrityProblem { .. })
        ));
        assert_eq!(
            store
                .load_process_start(&operation)?
                .ok_or_else(|| OrsError::IntegrityProblem {
                    record_type: "test",
                    reason: "mismatched abort deleted reservation".to_owned(),
                })?
                .state,
            ProcessStartReplayState::Reserved
        );
        assert_eq!(
            store.abort_process_start(&operation, &record.admission_digest, &owner)?,
            ProcessStartReplayAbort::Released
        );
        assert!(store.load_process_start(&operation)?.is_none());
        drop(store);
        let reopened = RedbRecoveryStore::open(&path)?;
        assert!(reopened.load_process_start(&operation)?.is_none());

        let completed_operation = OperationIdentity::new("abort-completed")?;
        let completed_reservation = ProcessStartReplayRecord {
            operation_id: completed_operation.clone(),
            admission_digest: "ef".repeat(32),
            owner: owner.clone(),
            state: ProcessStartReplayState::Reserved,
            receipt: None,
        };
        let completed = ProcessStartReplayRecord {
            state: ProcessStartReplayState::Completed,
            receipt: Some(process_start_receipt(
                completed_operation.as_str(),
                &"55".repeat(32),
            )?),
            ..completed_reservation.clone()
        };
        assert!(
            reopened
                .begin_process_start(&completed_reservation)?
                .is_none()
        );
        reopened.persist_process_start(&completed)?;
        assert_eq!(
            reopened.abort_process_start(
                &completed_operation,
                &completed.admission_digest,
                &completed.owner
            )?,
            ProcessStartReplayAbort::NotReleased
        );
        assert_eq!(
            reopened.load_process_start(&completed_operation)?,
            Some(completed.clone())
        );
        drop(reopened);
        let reopened = RedbRecoveryStore::open(&path)?;
        assert_eq!(
            reopened.load_process_start(&completed_operation)?,
            Some(completed)
        );

        let unknown_operation = OperationIdentity::new("abort-unknown")?;
        let unknown = ProcessStartReplayRecord {
            operation_id: unknown_operation.clone(),
            state: ProcessStartReplayState::Unknown,
            ..record
        };
        assert!(reopened.begin_process_start(&unknown)?.is_none());
        reopened.persist_process_start(&unknown)?;
        assert_eq!(
            reopened.abort_process_start(&unknown_operation, &unknown.admission_digest, &owner)?,
            ProcessStartReplayAbort::NotReleased
        );
        assert_eq!(
            reopened
                .load_process_start(&unknown_operation)?
                .ok_or_else(|| OrsError::IntegrityProblem {
                    record_type: "test",
                    reason: "unknown replay record disappeared".to_owned(),
                })?
                .state,
            ProcessStartReplayState::Unknown
        );
        let _ = std::fs::remove_file(path);
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test fixtures use expect for fail-fast setup"
)]
mod host_request_result_tests {
    use super::*;
    use crate::{HostRequestKind, HostRequestState, OpaqueLabel, OperationIdentity};
    use eliot_contracts::{EpochId, EpochLineageId};
    use serde_json::json;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch() -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            std::num::NonZeroU64::new(1).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn requested_fixture(operation: &str, digest: &str) -> crate::HostRequestRecord {
        let label = |value: &str| OpaqueLabel::new(value.to_owned()).expect("valid test label");
        crate::HostRequestRecord {
            contract_version: crate::CONTRACT_VERSION,
            operation_id: OperationIdentity::new(operation.to_owned()).expect("valid operation"),
            kind: HostRequestKind::Invocation,
            request_id: label("req-1"),
            idempotency_key: label("req-1:invoke"),
            cancellation_id: label("req-1:invoke:cancel"),
            parent_operation_id: None,
            request_digest: digest.to_owned(),
            payload_digest: "b".repeat(64),
            connection_ref: label("conn-1"),
            session_ref: Some(label("session-1")),
            task_ref: None,
            scope_ref: None,
            capability_ref: label("eliot.query"),
            fence_digest: "c".repeat(64),
            authority_epoch: test_epoch(),
            generation: 1,
            deadline_unix_ms: 9_999_999,
            state: HostRequestState::Requested,
            result_digest: None,
            result_response: None,
            commit_order: 0,
        }
    }

    fn temp_store() -> (RedbRecoveryStore, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "eliot-host-request-result-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        let store = RedbRecoveryStore::open(&path).expect("temp store opens");
        (store, path)
    }

    #[test]
    fn persist_result_is_exact_replay_and_rejects_changed_body() -> Result<(), OrsError> {
        let (store, path) = temp_store();
        let digest = "d".repeat(64);
        let operation =
            OperationIdentity::new(format!("hostreq:{digest}")).expect("valid operation");
        let staged = store.stage_host_request(&requested_fixture(operation.as_str(), &digest))?;
        assert_eq!(staged.state, HostRequestState::Requested);
        let admitted = store
            .advance_host_request(&operation, &digest, HostRequestState::Admitted, None)?
            .expect("admitted record must load");
        assert_eq!(admitted.state, HostRequestState::Admitted);

        // A `Requested` operation must never receive a result before admission.
        let (early_store, early_path) = temp_store();
        let early_digest = "e".repeat(64);
        let early_op =
            OperationIdentity::new(format!("hostreq:{early_digest}")).expect("valid operation");
        early_store.stage_host_request(&requested_fixture(early_op.as_str(), &early_digest))?;
        assert!(matches!(
            early_store.persist_host_request_result(
                &early_op,
                &early_digest,
                &"f".repeat(64),
                &json!({"response": "early"}),
            ),
            Err(OrsError::InvalidTransition)
        ));
        let _ = std::fs::remove_file(early_path);

        let body = json!({
            "request_id": "req-1",
            "idempotency_key": "req-1:invoke",
            "canonical_tool_name": "eliot.query",
            "content": {
                "operation": "GetEvidencePack",
                "evidence_pack": {"subject": "evidence-alpha"},
                "revision_heads": [{"key": "scope:scope-1", "revision": 3}],
            },
        });
        let result_digest =
            crate::model::sha256_hex(&serde_json::to_vec(&body).expect("test body must serialize"));
        let received = store
            .persist_host_request_result(&operation, &digest, &result_digest, &body)?
            .expect("resulted record must load");
        assert_eq!(received.state, HostRequestState::ResultReceived);
        assert_eq!(
            received.result_digest.as_deref(),
            Some(result_digest.as_str())
        );
        assert_eq!(received.result_response.as_ref(), Some(&body));
        assert_ne!(received.commit_order, 0, "terminal result must order");

        // Exact replay returns the durable row unchanged: no duplicate dispatch.
        let replay = store
            .persist_host_request_result(&operation, &digest, &result_digest, &body)?
            .expect("replay must load");
        assert_eq!(replay, received);

        // A changed payload digest or a forged body under the same identity is
        // rejected before any readback and never overwrites the durable row.
        assert!(matches!(
            store.persist_host_request_result(&operation, &digest, &"0".repeat(64), &body,),
            Err(OrsError::HostRequestIdentityConflict { .. })
        ));
        assert!(matches!(
            store.persist_host_request_result(
                &operation,
                &digest,
                &result_digest,
                &json!({"forged": true}),
            ),
            Err(OrsError::HostRequestIdentityConflict { .. })
        ));
        let kept = store
            .load_host_request(&operation, &digest)?
            .expect("durable row must survive conflicts");
        assert_eq!(kept, received);

        // The old digest-only advance still requires a digest for received.
        assert!(matches!(
            store.advance_host_request(
                &operation,
                &digest,
                HostRequestState::Terminal,
                Some("1".repeat(64).as_str()),
            ),
            Err(OrsError::HostRequestIdentityConflict { .. })
        ));

        drop(store);
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn legacy_digest_only_row_completes_with_exact_body() -> Result<(), OrsError> {
        let (store, path) = temp_store();
        let digest = "d".repeat(64);
        let operation =
            OperationIdentity::new(format!("hostreq:{digest}")).expect("valid operation");
        store.stage_host_request(&requested_fixture(operation.as_str(), &digest))?;
        for target in [
            HostRequestState::Admitted,
            HostRequestState::Routed,
            HostRequestState::Submitted,
        ] {
            store
                .advance_host_request(&operation, &digest, target, None)?
                .expect("walk must advance");
        }
        let result_digest = "f".repeat(64);
        let legacy = store
            .advance_host_request(
                &operation,
                &digest,
                HostRequestState::ResultReceived,
                Some(result_digest.as_str()),
            )?
            .expect("legacy row must store");
        assert_eq!(legacy.state, HostRequestState::ResultReceived);
        assert!(legacy.result_response.is_none());
        // The legacy row still loads (compatibility, never served as a body).
        let loaded = store
            .load_host_request(&operation, &digest)?
            .expect("legacy row must load");
        assert_eq!(loaded, legacy);

        // Completing it with the exact same digest binds the missing body;
        // anything else stays a conflict.
        let body = json!({"completed": "legacy-body"});
        let completed = store
            .persist_host_request_result(&operation, &digest, &result_digest, &body)?
            .expect("exact-digest completion must store");
        assert_eq!(
            completed.result_digest.as_deref(),
            Some(result_digest.as_str())
        );
        assert_eq!(completed.result_response.as_ref(), Some(&body));
        assert!(matches!(
            store.persist_host_request_result(&operation, &digest, &"0".repeat(64), &body,),
            Err(OrsError::HostRequestIdentityConflict { .. })
        ));

        drop(store);
        let _ = std::fs::remove_file(path);
        Ok(())
    }
}

#[cfg(test)]
mod unknown_commit_recovery_tests {
    use super::*;
    use crate::{UnknownCommitOutcome, UnknownCommitRecord};

    fn open_record(key: &str, operation: &str, scopes: &[&str]) -> UnknownCommitRecord {
        UnknownCommitRecord {
            idempotency_key: key.to_owned(),
            operation_id: crate::OperationIdentity::new(operation).expect("operation"),
            canonical_request_hash: "a".repeat(64),
            ordering_scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            outcome: None,
            evidence_receipt_digest: None,
        }
    }

    #[test]
    fn unknown_commit_round_trip_conflict_and_resolve() -> Result<(), OrsError> {
        let path = std::env::temp_dir().join(format!(
            "eliot-unknown-commit-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        let store = RedbRecoveryStore::open(&path)?;
        let record = open_record("key-1", "op-1", &["scope-a"]);
        assert!(store.stage_unknown_commit(&record)?.is_none());
        // Exact replay returns the stored record unchanged.
        let replayed = store
            .stage_unknown_commit(&record)?
            .expect("replay returns the record");
        assert_eq!(replayed, record);
        // Changed binding under the same key conflicts.
        let mut conflicting = record.clone();
        conflicting.canonical_request_hash = "b".repeat(64);
        assert!(matches!(
            store.stage_unknown_commit(&conflicting),
            Err(OrsError::IntegrityProblem { .. })
        ));
        // The open set carries the record; resolution binds evidence once.
        assert_eq!(store.list_open_unknown_commits()?.len(), 1);
        let resolved = store
            .resolve_unknown_commit("key-1", UnknownCommitOutcome::Committed, &"c".repeat(64))?
            .expect("resolution stores");
        assert_eq!(resolved.outcome, Some(UnknownCommitOutcome::Committed));
        assert!(store.list_open_unknown_commits()?.is_empty());
        // A resolved record never reopens.
        assert!(matches!(
            store.resolve_unknown_commit(
                "key-1",
                UnknownCommitOutcome::RolledBack,
                &"d".repeat(64)
            ),
            Err(OrsError::InvalidField { .. })
        ));
        // Unknown keys resolve to None without inventing records.
        assert!(
            store
                .resolve_unknown_commit(
                    "key-missing",
                    UnknownCommitOutcome::Committed,
                    &"e".repeat(64)
                )?
                .is_none()
        );
        drop(store);
        let _ = std::fs::remove_file(path);
        Ok(())
    }
}

#[cfg(test)]
mod capability_grant_identity_tests {
    use super::*;
    use crate::{EpochIdentity, OpaqueLabel, OperationIdentity};
    use eliot_platform::SecretReference;
    use serde_json::json;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn grant_input(
        record_id: &str,
        subject_id: &str,
        payload: &[u8],
    ) -> Result<OperationalRecordInput, OrsError> {
        let epoch = EpochLineage {
            current: EpochIdentity {
                lineage_id: OpaqueLabel::new(TEST_LINEAGE)?,
                epoch: 1,
            },
            predecessor: None,
        };
        let fence = StateFenceSnapshot::capture(
            &json!({
                "authority_epoch": {
                    "lineage_id": TEST_LINEAGE,
                    "sequence": 1
                },
                "generation": 1,
                "nonce": "grant-identity-test"
            }),
            1,
        )?;
        OperationalRecordInput::encrypted(
            OperationalRecordContext {
                record_id: OperationIdentity::new(record_id)?,
                subject_id: OperationIdentity::new(subject_id)?,
                authority_epoch: epoch,
                state_fence: fence,
                created_at_ms: 1,
                cleanup_after_ms: None,
            },
            SecretReference::new("test-provider", "grant-identity-key").map_err(|_error| {
                OrsError::InvalidField {
                    field: "test_secret_reference",
                    reason: "fixture secret reference must validate",
                }
            })?,
            payload.to_vec(),
        )
    }

    #[test]
    fn changed_payload_is_typed_conflict_and_preserves_every_grant_phase() -> Result<(), OrsError> {
        let path = std::env::temp_dir().join(format!(
            "eliot-ors-grant-identity-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        let store = RedbRecoveryStore::open(&path)?;
        for (suffix, phase) in [
            ("applying", OperationalPhase::Applying),
            ("active", OperationalPhase::Active),
            ("fenced", OperationalPhase::Fenced),
            ("released", OperationalPhase::Released),
        ] {
            let subject = format!("grant-{suffix}");
            let record = format!("operation-{suffix}");
            let original = grant_input(&record, &subject, b"original")?;
            store.mutate_operational(
                OperationalKind::CapabilityGrant,
                original.clone(),
                false,
                &[],
                phase,
            )?;
            let before = store
                .load_capability_grant(&OperationIdentity::new(&subject)?)?
                .ok_or(OrsError::IntegrityProblem {
                    record_type: "test",
                    reason: "grant identity fixture was not persisted".to_owned(),
                })?;
            let changed = grant_input(&record, &subject, b"changed")?;
            assert!(matches!(
                store.activate_capability_grant(CapabilityGrantActivation::new(changed)?),
                Err(OrsError::DuplicateConflict)
            ));
            assert_eq!(
                store
                    .load_capability_grant(&OperationIdentity::new(&subject)?)?
                    .ok_or(OrsError::IntegrityProblem {
                        record_type: "test",
                        reason: "grant identity row disappeared".to_owned(),
                    })?,
                before
            );
        }
        drop(store);
        let _ = std::fs::remove_file(path);
        Ok(())
    }
}
