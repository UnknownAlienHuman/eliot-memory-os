//! Structured diagnostics projection for the S-03 store bridge (issue #742).
//!
//! This module is the single owner of bridge diagnostics vocabulary,
//! redaction, bounded capture, and the typed projection from adapter results.
//! It changes no Store validation, transaction, idempotency, wire, or process
//! behavior: every entry is infallible, bounded, and free of provider,
//! credential, query-text, payload, URL, and record-content access.
//!
//! # Frozen call-site inventory
//!
//! Mechanically scanned on branch `feat/742-store-bridge-diagnostics` at base
//! `eee89cdc52e372861166b71c555758fe8ab3a384`. Line spans below refer to that
//! base. `W` marks the wiring pass that must attach the proposed emitter;
//! `S<n>` marks the owning call-site file when it is outside this work unit's
//! mutable scope (stitch target for the integrator, never edited here).
//!
//! | Boundary | Call site | Owning operation | Available evidence | Current sink | Proposed event | Test |
//! |---|---|---|---|---|---|---|
//! | `startup` | `main.rs:main:23-28` | process launch | `SERVICE_NAME`, terminal `Err(String)` | `stderr` + exit code | `emit_lifecycle` + `process_exit` | T2 T12 |
//! | `launch_config` | `launch_mode.rs:parse_launch_mode:135-200` | launch-mode decode | `LaunchMode` discriminant only (paths never logged) | `Err(String)` to `main` | `emit_received` / `emit_validation_rejected` | T2 |
//! | `launch_config` | `launch_mode.rs:prepare_launch:49-93` (W) | launch preparation | mode discriminant, `StoreLaunchConfig` digests via `launch_config_digest` | `Err(String)` to `main` | `emit_lifecycle` | T2 |
//! | `bootstrap_descriptor` | `main.rs:emit_bootstrap_descriptor:123-138` (W) | descriptor emission | neutral descriptor digest only | file write + `Err(String)` | `emit_lifecycle` | T2 |
//! | `compatibility_gate` | `main.rs:enforce_store_compatibility:105-120` via `compatibility.rs:require_compatibility_for_writer:203` (S) | I5.9 writer admission | compatibility `report` text (bounded record echo), digest echo | `stderr` | `emit_validation_rejected` on deny / `emit_lifecycle` on admit | T2 T9 |
//! | `observed_identity_binding` | `main.rs:bind_observed_identity:144-164` via `compatibility.rs:require_observed_identity_match:223` (S) | live-identity binding | `ObservedProviderIdentity` version triple + artifact digest | `stderr` | `emit_lifecycle` | T3 |
//! | `semantic_readiness_gate` | `main.rs:run:264-268` via `lib.rs:require_semantic_ready_for_pipe:1108` | semantic readiness | `ReadinessReceipt` status + expected/observed generation | `Err(String)` to `main` | `emit_validation_rejected` on deny | T3 T15 |
//! | `pipe_bind` | `main.rs:serve_handshake_loop:177-185` | pipe creation + authenticated admission | typed `Err(String)` stage only (peer expectation never logged) | `Err(String)` to `main` | `emit_lifecycle` | T2 T12 |
//! | `handshake_admit` | `main.rs:serve_handshake_loop:186-200` via `lib.rs:admit_handshake:1184` | EBP handshake admission | `ServerHello` config snapshot digests, negotiated version/limits | `Err(String)` to `main` | `emit_received` / `emit_validation_rejected` | T4 T5 |
//! | `handshake_respond` | `main.rs:serve_handshake_loop:203-213` | EBP `Ready` emission | `connection_id`, protocol version | `Err(String)` on send failure | `emit_lifecycle` | T8 T21 |
//! | `frame_receive` | `main.rs:serve_handshake_loop:216-219` | transport-loop receive | `request_id` when present, typed stage error | `Err(String)` (loop terminates) | `emit_received` / `emit_lifecycle` | T4 T12 |
//! | `session_validation` | `main.rs:serve_handshake_loop:220` via `lib.rs:validate_request_frame:1297` | session/fence/replay/capability admission | `request_id`, fence-match boolean, replay disposition, capability name | `frame_rejection_defect` | `emit_validation_rejected` | T4 T5 T13 T14 |
//! | `catalogue_admission` | `lib.rs:enforce_admitted_operation:1350` | generated-catalogue admission | operation manifest digest, catalogue entry identity | `Err(String)` to defect path | `emit_validation_rejected` | T5 T13 T14 T18 |
//! | `task_binding_gate` | `lib.rs:apply:586` via `task_binding_gate.rs:gate_apply:228` (S) | task-binding validation | `TaskBindingRejection` detail + `StoreError` mapping | `map_store_error` | `emit_validation_rejected` | T5 T14 |
//! | `frame_rejection` | `main.rs:frame_rejection_defect:39-94` | pre-dispatch defect projection | `request_id`, bounded `human_detail` only | `Response::Failure` | `emit_dispatch_outcome` | T4 T17 |
//! | `dispatch` | `request_dispatch.rs:dispatch:357` + `dispatch_request:362-471` | 13-arm closed dispatch | `Request` arm discriminant + admitted identity | `Response` | `emit_received` + `emit_attempted` + `emit_dispatch_outcome` | T6 T13 T14 |
//! | `mutation_result` | `request_dispatch.rs:response_for_transaction_receipt:221` | `Apply`/`ReservedWrite` receipt projection | `WriteReceipt` status + reconciliation envelope presence | `Response::Transaction` / `Response::Failure` | `emit_dispatch_outcome` | T6 T14 T16 T21 |
//! | `receipt_lookup` | `request_dispatch.rs:response_for_receipt_lookup:241` | exact-operation receipt query | `Option<WriteReceipt>` + envelope presence | `Response::Receipt` / `Response::Failure` | `emit_dispatch_outcome` | T11 T14 |
//! | `receipt_reconciliation` | `lib.rs:resolve_unknown_write:987` + `connection_manager.rs:classify_receipt_lookup:584` (S) | unknown-outcome reconciliation | `UnknownWriteGate` verdict, receipt by identity | `Response` | `emit_reconciled` / `emit_dispatch_outcome` | T11 T14 |
//! | `idempotency_decision` | conflict disposition + receipt-query path (W) | replay / conflict / first application | `StoreFailureDisposition::Conflict`, `StoreConflictObservation`, receipt identity | `Response::Failure` / `Response::Transaction` | `emit_dispatch_outcome` with `Conflict` | T7 T13 T19 |
//! | `backup_boundary` | `request_dispatch.rs:429-439` via `backup_dispatch.rs:dispatch_backup:40` (S) | backup envelope dispatch | `StoreBackupResponse` per-outcome state | `Response::Backup` / `Response::Failure` | `emit_dispatch_outcome` | T6 T14 |
//! | `recovery_boundary` | `request_dispatch.rs:map_recovery_dispatch_result:267` | recovery snapshot dispatch | `StoreRecoverySnapshot` / `StoreError` | `Response::Recovery` / `Response::Failure` | `emit_dispatch_outcome` | T14 T17 |
//! | `genesis_boundary` | `request_dispatch.rs:map_genesis_dispatch_result:277` | genesis dispatch | `WriteReceipt` / `StoreError` | `Response::Genesis` / `Response::Failure` | `emit_dispatch_outcome` | T14 T17 |
//! | `dreamer_ledger` | `request_dispatch.rs:dispatch_dreamer_job:325` + `map_dreamer_dispatch_result:306` | durable job ledger (#777 S2) | `DurableJobResponse::validate_for` verdict | `Response::DreamerJob` / typed unknown | `emit_dispatch_outcome` | T6 T10 T14 |
//! | `schema_migration` | `lib.rs:apply_initial_schema_migration:447` + `bootstrap_schema:471` + portable-dev init `launch_mode.rs:68-88` (W) | schema bootstrap | `MigrationReceipt` id/checksum/generation | `stdout` JSON receipt / `Err(String)` | `emit_lifecycle` | T9 |
//! | `connection_generation` | `lib.rs:replace_client_generation:1026` via `connection_manager.rs:replace_generation:381` (S) | client-generation rotation | generation counter, lease verdict, reconnect attempt | `Result` to caller | `emit_lifecycle` | T3 T20 |
//! | `response_send` | `main.rs:serve_handshake_loop:224-234` | EBP response emission | `connection_id`, `request_id`, protocol version | `Err(String)` (loop terminates) | `emit_lifecycle` on loss with `Unknown` preserved | T8 T21 |
//! | `shutdown` | transport-loop termination `main.rs:215-235` (W) | loop disposition | terminating stage (`receive` / `respond`) | `Err(String)` to `main` | `emit_lifecycle` with exact disposition | T12 |
//! | `process_exit` | `main.rs:main:23-28` (W) | exit-code projection | exit `0` / `1` only | process exit code | `emit_lifecycle` | T12 |
//!
//! # Explicitly unobservable at this partition (never guessed)
//!
//! | Missing stage | Missing contract | Owner challenged | Test guard |
//! |---|---|---|---|
//! | provider-internal transaction start | `PROVIDER_TX_START` evidence | `eliot-store-surreal-adapter` / Store API | T6 T16 |
//! | provider-internal rollback | `PROVIDER_ROLLBACK_EVIDENCE` | `eliot-store-surreal-adapter` / Store API | T6 T14 T21 |
//! | request-side cancellation intent | cancellation payload stays opaque to the bridge; only terminal `WriteReceiptStatus::Cancelled` is observed via receipt projection | Dreamer ledger contract (#777) | T10 |
//! | provider success prose as readiness | provider text never proves semantic readiness; only `ReadinessReceipt` + `require_semantic_ready_for_pipe` | bridge (this unit, T15) | T15 |
//!
//! # Redaction rule
//!
//! Redaction precedes formatting and is structural: this module accepts only
//! validated identities (`RequestId`, `OperationId`), length/control-char
//! validated references and digests, typed reason/recovery codes, and fieldless
//! status/disposition enums. Raw query text, request payloads, credentials,
//! tokens, DB URLs, record contents, evidence-handle expansion, `Debug` dumps,
//! and provider prose have no constructor here and cannot reach any sink,
//! including the `Display` fallback rendering (T22).

use std::collections::VecDeque;
use std::collections::vec_deque::Iter;
use std::fmt;
use std::io::Write as _;
use std::sync::OnceLock;

use eliot_contracts::{OperationId, RequestId};
use eliot_store_api::{
    MAX_STORE_FAILURE_DETAIL_LEN, MAX_STORE_FAILURE_REFERENCE_LEN, StoreBackupResponse,
    StoreBackupStatusOutcome, StoreFailure, StoreFailureDisposition, StoreFailureIdentityContext,
    StoreMutationDisposition, StoreReasonCode, StoreRecoveryAction, WriteReceipt,
    WriteReceiptStatus,
};
use eliot_store_surreal_adapter::SnapshotBudgetDiagnostics;

use crate::{CompatibilityVerdict, Request, Response, SERVICE_NAME};

/// Stable contract revision of this diagnostics projection.
pub const DIAGNOSTICS_CONTRACT_REVISION: &str = "eliot.s03.bridge-diagnostics.v1";

/// Bounded capture capacity of [`BoundedEventLog`]. Oldest events are dropped
/// first and every drop is counted; the buffer never grows past this bound.
pub const MAX_DIAGNOSTIC_EVENTS: usize = 512;

/// Closed vocabulary of bridge observation points. Each variant names exactly
/// one frozen call site from the inventory above; no variant observes a
/// provider-internal stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeBoundary {
    /// Process entry and launch orchestration (`main.rs:run`).
    Startup,
    /// Launch-mode decode and preparation (`launch_mode.rs`).
    LaunchConfig,
    /// One-shot descriptor emission (`main.rs:emit_bootstrap_descriptor`).
    BootstrapDescriptor,
    /// I5.9 compatibility admission, pre- and post-connect.
    CompatibilityGate,
    /// Live provider identity binding after connect.
    ObservedIdentityBinding,
    /// Semantic-readiness gate before pipe advertisement.
    SemanticReadinessGate,
    /// Named-pipe creation and authenticated client admission.
    PipeBind,
    /// `ClientHello` admission and session binding.
    HandshakeAdmit,
    /// `ServerHello`/`Ready` emission.
    HandshakeRespond,
    /// Transport-loop frame receive.
    FrameReceive,
    /// Session/fence/replay/capability validation.
    SessionValidation,
    /// Generated-catalogue admission before provider I/O.
    CatalogueAdmission,
    /// Task-binding validation on the apply path.
    TaskBindingGate,
    /// Pre-dispatch defect projection for rejected frames.
    FrameRejection,
    /// Closed 13-arm request dispatch.
    Dispatch,
    /// `Apply`/`ReservedWrite` receipt projection.
    MutationResult,
    /// Exact-operation receipt lookup.
    ReceiptLookup,
    /// Unknown-outcome reconciliation by operation identity.
    ReceiptReconciliation,
    /// Replay / conflict / first-application decision.
    IdempotencyDecision,
    /// Backup envelope dispatch.
    BackupBoundary,
    /// Recovery snapshot dispatch.
    RecoveryBoundary,
    /// Genesis dispatch.
    GenesisBoundary,
    /// Durable job ledger dispatch (#777 S2).
    DreamerLedger,
    /// Schema bootstrap and portable-dev initialization.
    SchemaMigration,
    /// Client-generation rotation and reconnect accounting.
    ConnectionGeneration,
    /// EBP response-frame emission.
    ResponseSend,
    /// Transport-loop termination disposition.
    Shutdown,
    /// Process exit-code projection.
    ProcessExit,
}

impl BridgeBoundary {
    /// Every observable bridge boundary, for partition-coverage guards.
    pub const ALL: &'static [Self] = &[
        Self::Startup,
        Self::LaunchConfig,
        Self::BootstrapDescriptor,
        Self::CompatibilityGate,
        Self::ObservedIdentityBinding,
        Self::SemanticReadinessGate,
        Self::PipeBind,
        Self::HandshakeAdmit,
        Self::HandshakeRespond,
        Self::FrameReceive,
        Self::SessionValidation,
        Self::CatalogueAdmission,
        Self::TaskBindingGate,
        Self::FrameRejection,
        Self::Dispatch,
        Self::MutationResult,
        Self::ReceiptLookup,
        Self::ReceiptReconciliation,
        Self::IdempotencyDecision,
        Self::BackupBoundary,
        Self::RecoveryBoundary,
        Self::GenesisBoundary,
        Self::DreamerLedger,
        Self::SchemaMigration,
        Self::ConnectionGeneration,
        Self::ResponseSend,
        Self::Shutdown,
        Self::ProcessExit,
    ];

    /// Stable machine code for this boundary.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::LaunchConfig => "launch_config",
            Self::BootstrapDescriptor => "bootstrap_descriptor",
            Self::CompatibilityGate => "compatibility_gate",
            Self::ObservedIdentityBinding => "observed_identity_binding",
            Self::SemanticReadinessGate => "semantic_readiness_gate",
            Self::PipeBind => "pipe_bind",
            Self::HandshakeAdmit => "handshake_admit",
            Self::HandshakeRespond => "handshake_respond",
            Self::FrameReceive => "frame_receive",
            Self::SessionValidation => "session_validation",
            Self::CatalogueAdmission => "catalogue_admission",
            Self::TaskBindingGate => "task_binding_gate",
            Self::FrameRejection => "frame_rejection",
            Self::Dispatch => "dispatch",
            Self::MutationResult => "mutation_result",
            Self::ReceiptLookup => "receipt_lookup",
            Self::ReceiptReconciliation => "receipt_reconciliation",
            Self::IdempotencyDecision => "idempotency_decision",
            Self::BackupBoundary => "backup_boundary",
            Self::RecoveryBoundary => "recovery_boundary",
            Self::GenesisBoundary => "genesis_boundary",
            Self::DreamerLedger => "dreamer_ledger",
            Self::SchemaMigration => "schema_migration",
            Self::ConnectionGeneration => "connection_generation",
            Self::ResponseSend => "response_send",
            Self::Shutdown => "shutdown",
            Self::ProcessExit => "process_exit",
        }
    }
}

/// Closed outcome vocabulary for one observed bridge event.
///
/// `Received`, `Attempted`, `Reconciled`, and `LifecycleObserved` require
/// call-site context and are recorded only by the matching `emit_*` entry.
/// [`classify_response`] projects only the subset observable from a single
/// typed [`Response`] and never fabricates the rest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestOutcome {
    /// The bridge received the request or launch input; nothing attempted yet.
    Received,
    /// The bridge handed the admitted request to the provider boundary. This
    /// is the bridge-side handoff only, never a provider-internal start claim.
    Attempted,
    /// A read-path or per-outcome payload was observed from owner evidence.
    /// This is receipt of typed owner data, never a commit claim.
    ReadCompleted,
    /// Session, catalogue, manifest, or task-gate validation refused the
    /// request before any provider I/O.
    ValidationRejected,
    /// A deterministic failure with no mutation attempted (unavailable,
    /// backpressured, deadline, migration-required).
    NotAttempted,
    /// Typed idempotency/identity conflict; distinct from replay and from
    /// first application.
    Conflict,
    /// A `WriteReceipt` with `Committed` status and a valid reconciliation
    /// envelope was observed from the receipt-issuing path.
    Committed,
    /// A terminal receipt with `Rejected`, `DeadLetter`, or `Cancelled`
    /// status; the exact status is preserved on the event.
    TerminalNonCommit,
    /// Reserved: no bridge call site observes provider rollback. The variant
    /// keeps the T14 vocabulary closed and distinct; the missing contract is
    /// `PROVIDER_ROLLBACK_EVIDENCE` (owner: `eliot-store-surreal-adapter`).
    /// Neither [`classify_response`] nor any `emit_*` entry returns it.
    RolledBack,
    /// The mutation crossed the provider boundary without proving its
    /// outcome. Same operation identity; reconciliation by receipt query.
    Unknown,
    /// An unknown outcome was resolved through owner reconciliation evidence.
    Reconciled,
    /// Internal defect or legacy string failure. Presence only; the defect
    /// prose is never copied into the event.
    Defect,
    /// A non-request lifecycle transition was observed (startup step, gate
    /// admission, shutdown disposition). Exact disposition travels in the
    /// typed reason code, never in prose.
    LifecycleObserved,
}

impl RequestOutcome {
    /// Stable machine code for this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Attempted => "attempted",
            Self::ReadCompleted => "read_completed",
            Self::ValidationRejected => "validation_rejected",
            Self::NotAttempted => "not_attempted",
            Self::Conflict => "conflict",
            Self::Committed => "committed",
            Self::TerminalNonCommit => "terminal_non_commit",
            Self::RolledBack => "rolled_back",
            Self::Unknown => "unknown",
            Self::Reconciled => "reconciled",
            Self::Defect => "defect",
            Self::LifecycleObserved => "lifecycle_observed",
        }
    }
}

/// Closed operation vocabulary admitted in [`BridgeDiagnosticEvent`].
/// Derived from the frozen 13-arm dispatch catalogue plus the launch phases;
/// no caller prose is ever admitted as an operation name.
pub const ADMITTED_OPERATIONS: &[&str] = &[
    "health",
    "readiness",
    "named",
    "apply",
    "receipt",
    "reserved_write",
    "backup",
    "revision_heads",
    "ordering_heads",
    "validation_snapshot",
    "recovery",
    "initialize_genesis",
    "dreamer_job",
    "startup",
    "launch_config",
    "bootstrap_descriptor",
    "compatibility_gate",
    "observed_identity_binding",
    "semantic_readiness_gate",
    "pipe_bind",
    "handshake",
    "frame",
    "catalogue_admission",
    "task_binding_gate",
    "mutation_result",
    "receipt_lookup",
    "reconciliation",
    "schema_migration",
    "connection_generation",
    "response_send",
    "shutdown",
    "process_exit",
];

/// Reports whether `operation` belongs to the closed admitted vocabulary.
#[must_use]
pub fn is_admitted_operation(operation: &str) -> bool {
    ADMITTED_OPERATIONS.contains(&operation)
}

/// Stable machine code for a typed failure disposition.
fn failure_disposition_code(disposition: StoreFailureDisposition) -> &'static str {
    match disposition {
        StoreFailureDisposition::DeterministicRejection => "deterministic_rejection",
        StoreFailureDisposition::Conflict => "conflict",
        StoreFailureDisposition::Denied => "denied",
        StoreFailureDisposition::Unavailable => "unavailable",
        StoreFailureDisposition::Backpressured => "backpressured",
        StoreFailureDisposition::DeadlineExceeded => "deadline_exceeded",
        StoreFailureDisposition::MigrationRequired => "migration_required",
        StoreFailureDisposition::Unsupported => "unsupported",
        StoreFailureDisposition::UnknownOutcome => "unknown_outcome",
        StoreFailureDisposition::InternalDefect => "internal_defect",
    }
}

/// Stable machine code for a typed recovery action.
fn recovery_action_code(action: StoreRecoveryAction) -> &'static str {
    match action {
        StoreRecoveryAction::None => "none",
        StoreRecoveryAction::RefreshStateFence => "refresh_state_fence",
        StoreRecoveryAction::RefreshRevisionHeads => "refresh_revision_heads",
        StoreRecoveryAction::WaitForCapacity => "wait_for_capacity",
        StoreRecoveryAction::RestoreStoreConnectivity => "restore_store_connectivity",
        StoreRecoveryAction::RunSchemaMigration => "run_schema_migration",
        StoreRecoveryAction::ResolveWriteReceipt => "resolve_write_receipt",
        StoreRecoveryAction::ReconcileUnknownOutcome => "reconcile_unknown_outcome",
        StoreRecoveryAction::RepairConfiguration => "repair_configuration",
        StoreRecoveryAction::EscalateInternalDefect => "escalate_internal_defect",
        StoreRecoveryAction::EnterManualRecovery => "enter_manual_recovery",
    }
}

/// Stable machine code for a typed receipt status.
fn receipt_status_code(status: WriteReceiptStatus) -> &'static str {
    match status {
        WriteReceiptStatus::Committed => "committed",
        WriteReceiptStatus::Rejected => "rejected",
        WriteReceiptStatus::DeadLetter => "dead_letter",
        WriteReceiptStatus::Cancelled => "cancelled",
    }
}

/// A validated bounded reference or digest admitted into a diagnostic event.
///
/// Construction mirrors the bridge's existing sanitization
/// (`request_dispatch.rs:sanitized_owned_reference` and the
/// `frame_rejection_defect` detail gate): empty, over-long, or
/// control-character-carrying values fail closed to `None` and are never
/// logged in any form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedRef(String);

impl BoundedRef {
    /// Validates an identity reference or digest against the failure-contract
    /// reference bound.
    #[must_use]
    pub fn reference(value: &str) -> Option<Self> {
        Self::checked(value, MAX_STORE_FAILURE_REFERENCE_LEN)
    }

    /// Validates additive human detail against the failure-contract detail
    /// bound. Detail never steers machine semantics.
    #[must_use]
    pub fn detail(value: &str) -> Option<Self> {
        Self::checked(value, MAX_STORE_FAILURE_DETAIL_LEN)
    }

    /// Returns the validated reference text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn checked(value: &str, max_len: usize) -> Option<Self> {
        if value.is_empty() || value.len() > max_len || value.chars().any(char::is_control) {
            return None;
        }
        Some(Self(value.to_owned()))
    }
}

/// Validated identities actually present at one bridge boundary.
///
/// Only typed identifiers and validated references are representable: there is
/// no field for payloads, queries, credentials, URLs, record contents, fence
/// bytes, or provider prose. A fence travels as presence plus an optional
/// caller-supplied digest, never as bytes or a `Debug` rendering.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BridgeIdentity {
    request_id: Option<RequestId>,
    operation_id: Option<OperationId>,
    idempotency_ref: Option<BoundedRef>,
    manifest_digest: Option<BoundedRef>,
    generation: Option<BoundedRef>,
    fence_digest: Option<BoundedRef>,
    fence_present: bool,
    evidence_ref: Option<BoundedRef>,
}

impl BridgeIdentity {
    /// Creates the empty identity; every field is absent.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Projects the admitted identity from a typed failure. The failure's
    /// `human_detail` prose is never copied.
    #[must_use]
    pub fn from_failure(failure: &StoreFailure) -> Self {
        Self {
            request_id: failure.request_id.clone(),
            operation_id: failure.operation_id.clone(),
            idempotency_ref: failure
                .idempotency_key_ref_or_digest
                .as_deref()
                .and_then(BoundedRef::reference),
            manifest_digest: None,
            generation: None,
            fence_digest: None,
            fence_present: failure.state_fence_ref_or_exact_safe_projection.is_some(),
            evidence_ref: failure
                .evidence_ref
                .as_deref()
                .and_then(BoundedRef::reference),
        }
    }

    /// Projects the admitted identity from a typed receipt. Only the operation
    /// identity, the validated idempotency key, and fence presence travel;
    /// receipt payloads never do.
    #[must_use]
    pub fn from_receipt(receipt: &WriteReceipt) -> Self {
        Self {
            request_id: None,
            operation_id: Some(receipt.operation_id.clone()),
            idempotency_ref: BoundedRef::reference(&receipt.idempotency_key),
            manifest_digest: None,
            generation: None,
            fence_digest: None,
            fence_present: true,
            evidence_ref: None,
        }
    }

    /// Projects the admitted identity from a dispatch failure context.
    #[must_use]
    pub fn from_context(context: &StoreFailureIdentityContext) -> Self {
        Self {
            request_id: context.request_id.clone(),
            operation_id: context.operation_id.clone(),
            idempotency_ref: context
                .idempotency_key_ref_or_digest
                .as_deref()
                .and_then(BoundedRef::reference),
            manifest_digest: None,
            generation: None,
            fence_digest: None,
            fence_present: context.state_fence_ref_or_exact_safe_projection.is_some(),
            evidence_ref: context
                .evidence_ref
                .as_deref()
                .and_then(BoundedRef::reference),
        }
    }

    /// Merges two identities; `other` wins every field it carries.
    #[must_use]
    pub fn merge(&self, other: &Self) -> Self {
        Self {
            request_id: other.request_id.clone().or_else(|| self.request_id.clone()),
            operation_id: other
                .operation_id
                .clone()
                .or_else(|| self.operation_id.clone()),
            idempotency_ref: other
                .idempotency_ref
                .clone()
                .or_else(|| self.idempotency_ref.clone()),
            manifest_digest: other
                .manifest_digest
                .clone()
                .or_else(|| self.manifest_digest.clone()),
            generation: other.generation.clone().or_else(|| self.generation.clone()),
            fence_digest: other
                .fence_digest
                .clone()
                .or_else(|| self.fence_digest.clone()),
            fence_present: self.fence_present || other.fence_present,
            evidence_ref: other
                .evidence_ref
                .clone()
                .or_else(|| self.evidence_ref.clone()),
        }
    }

    /// Binds the request identity.
    #[must_use]
    pub fn with_request(mut self, request_id: &RequestId) -> Self {
        self.request_id = Some(request_id.clone());
        self
    }

    /// Binds the operation identity.
    #[must_use]
    pub fn with_operation(mut self, operation_id: &OperationId) -> Self {
        self.operation_id = Some(operation_id.clone());
        self
    }

    /// Binds the idempotency reference or digest; invalid values are dropped.
    #[must_use]
    pub fn with_idempotency_ref(mut self, value: &str) -> Self {
        if let Some(valid) = BoundedRef::reference(value) {
            self.idempotency_ref = Some(valid);
        }
        self
    }

    /// Binds the operation-manifest digest; invalid values are dropped.
    #[must_use]
    pub fn with_manifest_digest(mut self, value: &str) -> Self {
        if let Some(valid) = BoundedRef::reference(value) {
            self.manifest_digest = Some(valid);
        }
        self
    }

    /// Binds the observed generation; invalid values are dropped.
    #[must_use]
    pub fn with_generation(mut self, value: &str) -> Self {
        if let Some(valid) = BoundedRef::reference(value) {
            self.generation = Some(valid);
        }
        self
    }

    /// Binds a caller-supplied fence digest; invalid values are dropped.
    #[must_use]
    pub fn with_fence_digest(mut self, value: &str) -> Self {
        if let Some(valid) = BoundedRef::reference(value) {
            self.fence_digest = Some(valid);
            self.fence_present = true;
        }
        self
    }

    /// Binds the evidence reference; invalid values are dropped.
    #[must_use]
    pub fn with_evidence_ref(mut self, value: &str) -> Self {
        if let Some(valid) = BoundedRef::reference(value) {
            self.evidence_ref = Some(valid);
        }
        self
    }

    /// Returns the bound request identity, if any.
    #[must_use]
    pub fn request_id(&self) -> Option<&RequestId> {
        self.request_id.as_ref()
    }

    /// Returns the bound operation identity, if any.
    #[must_use]
    pub fn operation_id(&self) -> Option<&OperationId> {
        self.operation_id.as_ref()
    }

    /// Returns the bound idempotency reference or digest, if any.
    #[must_use]
    pub fn idempotency_ref(&self) -> Option<&str> {
        self.idempotency_ref.as_ref().map(BoundedRef::as_str)
    }

    /// Returns the bound operation-manifest digest, if any.
    #[must_use]
    pub fn manifest_digest(&self) -> Option<&str> {
        self.manifest_digest.as_ref().map(BoundedRef::as_str)
    }

    /// Returns the bound observed generation, if any.
    #[must_use]
    pub fn generation(&self) -> Option<&str> {
        self.generation.as_ref().map(BoundedRef::as_str)
    }

    /// Returns the bound fence digest, if any.
    #[must_use]
    pub fn fence_digest(&self) -> Option<&str> {
        self.fence_digest.as_ref().map(BoundedRef::as_str)
    }

    /// Reports whether a fence was present at the observed boundary.
    #[must_use]
    pub const fn fence_present(&self) -> bool {
        self.fence_present
    }

    /// Returns the bound evidence reference, if any.
    #[must_use]
    pub fn evidence_ref(&self) -> Option<&str> {
        self.evidence_ref.as_ref().map(BoundedRef::as_str)
    }

    /// Projects the admitted identity from one closed dispatch request.
    ///
    /// Only typed identifiers actually present in the admitted shape travel:
    /// the transport request id, the operation identity, the idempotency
    /// key, and the operation-manifest digest. Request shapes without an
    /// identity (health, readiness, named reads, recovery, head reads,
    /// snapshots) project to the empty identity; fence presence is
    /// constant-present in request shapes and carries no digest, so it
    /// travels only on failure/receipt projections. Payloads, parameters,
    /// keys, scopes, and fences never travel.
    #[must_use]
    pub fn from_request(request: &Request) -> Self {
        match request {
            Request::Apply {
                context,
                transition,
                ..
            } => Self::new()
                .with_request(&context.request_id)
                .with_operation(&transition.identity.operation_id)
                .with_idempotency_ref(&transition.identity.idempotency_key)
                .with_manifest_digest(transition.operation_manifest_digest.as_str()),
            Request::ReservedWrite { request } => Self::new()
                .with_request(&request.context.request_id)
                .with_operation(&request.transition.identity.operation_id)
                .with_idempotency_ref(&request.transition.identity.idempotency_key)
                .with_manifest_digest(request.transition.operation_manifest_digest.as_str()),
            Request::Backup { request } => Self::new()
                .with_request(&request.context.request_id)
                .with_operation(&request.identity.operation_id)
                .with_idempotency_ref(&request.identity.idempotency_key),
            Request::InitializeGenesis { context, request } => Self::new()
                .with_request(&context.request_id)
                .with_operation(&request.operation_id)
                .with_idempotency_ref(&request.idempotency_key),
            Request::DreamerJob { context, request } => Self::new()
                .with_request(&context.request_id)
                .with_operation(&request.request_identity.operation.operation_id)
                .with_idempotency_ref(&request.request_identity.operation.idempotency_key),
            Request::Receipt { operation_id } => Self::new().with_operation(operation_id),
            Request::Health
            | Request::Readiness
            | Request::Named { .. }
            | Request::Recovery { .. }
            | Request::RevisionHeads { .. }
            | Request::OrderingHeads { .. }
            | Request::ValidationSnapshot => Self::new(),
        }
    }

    /// Projects the admitted identity from one closed dispatch response.
    ///
    /// Receipts contribute their operation identity, validated idempotency
    /// key, fence presence, and operation-manifest digest; typed failures
    /// contribute their admitted failure identity; the legacy unknown
    /// variant contributes its typed operation id only and its prose reason
    /// is never copied. Read-path payloads, backup per-outcome payloads,
    /// and the legacy string error carry no projectable identity and map
    /// to the empty identity; backup correlation travels on the request
    /// envelope identity instead.
    #[must_use]
    pub fn from_response(response: &Response) -> Self {
        match response {
            Response::Transaction { receipt } | Response::Genesis { receipt } => {
                Self::from_receipt(receipt)
                    .with_manifest_digest(receipt.operation_manifest_digest.as_str())
            }
            Response::Receipt { receipt } => receipt
                .as_ref()
                .map(|entry| {
                    Self::from_receipt(entry)
                        .with_manifest_digest(entry.operation_manifest_digest.as_str())
                })
                .unwrap_or_default(),
            Response::Failure { failure } => Self::from_failure(failure),
            Response::Unknown { operation_id, .. } => Self::new().with_operation(operation_id),
            Response::Health { .. }
            | Response::Readiness { .. }
            | Response::Named { .. }
            | Response::RevisionHeads { .. }
            | Response::OrderingHeads { .. }
            | Response::ValidationSnapshot { .. }
            | Response::Recovery { .. }
            | Response::DreamerJob { .. }
            | Response::Backup { .. }
            | Response::Error { .. } => Self::new(),
        }
    }

    fn render(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(request_id) = self.request_id.as_ref() {
            write!(formatter, " request={}", request_id.as_str())?;
        }
        if let Some(operation_id) = self.operation_id.as_ref() {
            write!(formatter, " operation_id={}", operation_id.as_str())?;
        }
        if let Some(idempotency_ref) = self.idempotency_ref() {
            write!(formatter, " idempotency_ref={idempotency_ref}")?;
        }
        if let Some(manifest_digest) = self.manifest_digest() {
            write!(formatter, " manifest={manifest_digest}")?;
        }
        if let Some(generation) = self.generation() {
            write!(formatter, " generation={generation}")?;
        }
        if let Some(fence_digest) = self.fence_digest() {
            write!(formatter, " fence={fence_digest}")?;
        } else if self.fence_present {
            write!(formatter, " fence=present")?;
        }
        if let Some(evidence_ref) = self.evidence_ref() {
            write!(formatter, " evidence_ref={evidence_ref}")?;
        }
        Ok(())
    }
}

/// One structured bridge diagnostic event.
///
/// Equality covers every machine-semantic field and excludes `detail`, mirroring
/// [`StoreFailure`]: diagnostic prose never steers machine recovery or equality.
#[derive(Clone, Debug, Eq)]
pub struct BridgeDiagnosticEvent {
    boundary: BridgeBoundary,
    operation: &'static str,
    outcome: RequestOutcome,
    identity: BridgeIdentity,
    reason: Option<StoreReasonCode>,
    recovery: Option<StoreRecoveryAction>,
    receipt_status: Option<WriteReceiptStatus>,
    failure_disposition: Option<StoreFailureDisposition>,
    detail: Option<BoundedRef>,
}

impl PartialEq for BridgeDiagnosticEvent {
    fn eq(&self, other: &Self) -> bool {
        self.boundary == other.boundary
            && self.operation == other.operation
            && self.outcome == other.outcome
            && self.identity == other.identity
            && self.reason == other.reason
            && self.recovery == other.recovery
            && self.receipt_status == other.receipt_status
            && self.failure_disposition == other.failure_disposition
    }
}

impl BridgeDiagnosticEvent {
    /// Creates an event from validated parts. Optional codes are attached by
    /// the `emit_*` entries, never parsed from prose.
    #[must_use]
    pub fn new(
        boundary: BridgeBoundary,
        operation: &'static str,
        outcome: RequestOutcome,
        identity: &BridgeIdentity,
    ) -> Self {
        Self {
            boundary,
            operation,
            outcome,
            identity: identity.clone(),
            reason: None,
            recovery: None,
            receipt_status: None,
            failure_disposition: None,
            detail: None,
        }
    }

    /// Returns the observed boundary.
    #[must_use]
    pub const fn boundary(&self) -> BridgeBoundary {
        self.boundary
    }

    /// Returns the admitted operation name.
    #[must_use]
    pub const fn operation(&self) -> &'static str {
        self.operation
    }

    /// Returns the observed outcome.
    #[must_use]
    pub const fn outcome(&self) -> RequestOutcome {
        self.outcome
    }

    /// Returns the validated boundary identity.
    #[must_use]
    pub const fn identity(&self) -> &BridgeIdentity {
        &self.identity
    }

    /// Returns the typed reason code, if any.
    #[must_use]
    pub fn reason(&self) -> Option<&StoreReasonCode> {
        self.reason.as_ref()
    }

    /// Returns the typed recovery action, if any.
    #[must_use]
    pub const fn recovery(&self) -> Option<StoreRecoveryAction> {
        self.recovery
    }

    /// Returns the exact receipt status behind the outcome, if any.
    #[must_use]
    pub const fn receipt_status(&self) -> Option<WriteReceiptStatus> {
        self.receipt_status
    }

    /// Returns the exact failure disposition behind the outcome, if any.
    #[must_use]
    pub const fn failure_disposition(&self) -> Option<StoreFailureDisposition> {
        self.failure_disposition
    }

    /// Returns the additive bounded detail, if any. Excluded from equality.
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_ref().map(BoundedRef::as_str)
    }
}

impl fmt::Display for BridgeDiagnosticEvent {
    /// Renders one bounded single-line record for fallback sinks. Every field
    /// is validated at construction, so rendering cannot leak unvalidated
    /// content and cannot grow without bound.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {} outcome={}",
            self.boundary.as_str(),
            self.operation,
            self.outcome.as_str()
        )?;
        self.identity.render(formatter)?;
        if let Some(reason) = self.reason.as_ref() {
            write!(formatter, " reason={}", reason.as_str())?;
        }
        if let Some(recovery) = self.recovery {
            write!(formatter, " recovery={}", recovery_action_code(recovery))?;
        }
        if let Some(status) = self.receipt_status {
            write!(formatter, " receipt={}", receipt_status_code(status))?;
        }
        if let Some(disposition) = self.failure_disposition {
            write!(
                formatter,
                " disposition={}",
                failure_disposition_code(disposition)
            )?;
        }
        if let Some(detail) = self.detail() {
            write!(formatter, " detail={detail}")?;
        }
        Ok(())
    }
}

/// Bounded capture buffer for bridge diagnostic events.
///
/// The buffer holds at most [`MAX_DIAGNOSTIC_EVENTS`] events; beyond that the
/// oldest event is dropped and the drop counter advances. The log is
/// caller-owned with no interior mutability and no locks, so emitting never
/// blocks on Store-critical synchronization and a failed sink cannot recurse,
/// stall, retry, or fabricate a receipt.
#[derive(Clone, Debug, Default)]
pub struct BoundedEventLog {
    events: VecDeque<BridgeDiagnosticEvent>,
    dropped: u64,
}

impl BoundedEventLog {
    /// Creates an empty bounded log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one event, dropping the oldest event past the bound.
    pub fn push(&mut self, event: BridgeDiagnosticEvent) {
        if self.events.len() >= MAX_DIAGNOSTIC_EVENTS {
            self.events.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.events.push_back(event);
    }

    /// Returns the number of retained events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Reports whether no event is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Returns the number of events dropped past the bound.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Iterates the retained events in emission order.
    pub fn iter(&self) -> Iter<'_, BridgeDiagnosticEvent> {
        self.events.iter()
    }

    /// Returns the most recently retained event, if any.
    #[must_use]
    pub fn last(&self) -> Option<&BridgeDiagnosticEvent> {
        self.events.back()
    }

    /// Discards every retained event; the drop counter is preserved.
    pub fn clear(&mut self) {
        self.events.clear();
    }
}

impl<'a> IntoIterator for &'a BoundedEventLog {
    type Item = &'a BridgeDiagnosticEvent;
    type IntoIter = Iter<'a, BridgeDiagnosticEvent>;

    fn into_iter(self) -> Self::IntoIter {
        self.events.iter()
    }
}

/// Projects one typed [`Response`] to its bridge outcome.
///
/// The projection reads only typed variants, receipt statuses, failure
/// dispositions, and mutation dispositions. It parses no strings, copies no
/// prose, and never upgrades an observation: `Unknown` stays unknown,
/// `Backup` per-outcome states keep their explicit meaning (only
/// `Complete` reads as completed), and the legacy `Error` string is never
/// inspected.
#[must_use]
pub fn classify_response(response: &Response) -> RequestOutcome {
    match response {
        Response::Transaction { receipt } | Response::Genesis { receipt } => match receipt.status {
            WriteReceiptStatus::Committed => RequestOutcome::Committed,
            WriteReceiptStatus::Rejected
            | WriteReceiptStatus::DeadLetter
            | WriteReceiptStatus::Cancelled => RequestOutcome::TerminalNonCommit,
        },
        Response::Receipt { .. }
        | Response::Health { .. }
        | Response::Readiness { .. }
        | Response::Named { .. }
        | Response::RevisionHeads { .. }
        | Response::OrderingHeads { .. }
        | Response::ValidationSnapshot { .. }
        | Response::Recovery { .. }
        | Response::DreamerJob { .. } => RequestOutcome::ReadCompleted,
        Response::Backup { response } => match response {
            StoreBackupResponse::Status { report } => match report.outcome {
                StoreBackupStatusOutcome::Complete => RequestOutcome::ReadCompleted,
                StoreBackupStatusOutcome::Reconciled => RequestOutcome::Reconciled,
                StoreBackupStatusOutcome::Unknown => RequestOutcome::Unknown,
                StoreBackupStatusOutcome::InProgress => RequestOutcome::Attempted,
                StoreBackupStatusOutcome::Expired => RequestOutcome::TerminalNonCommit,
            },
            StoreBackupResponse::Reconciled { .. } => RequestOutcome::Reconciled,
            StoreBackupResponse::Handle { .. }
            | StoreBackupResponse::Page { .. }
            | StoreBackupResponse::EndReceipt { .. }
            | StoreBackupResponse::Isolation { .. }
            | StoreBackupResponse::Restored { .. }
            | StoreBackupResponse::Validation { .. } => RequestOutcome::ReadCompleted,
        },
        Response::Failure { failure } => {
            if matches!(
                failure.mutation_disposition,
                StoreMutationDisposition::Unknown
            ) {
                return RequestOutcome::Unknown;
            }
            match failure.disposition {
                StoreFailureDisposition::UnknownOutcome => RequestOutcome::Unknown,
                StoreFailureDisposition::InternalDefect => RequestOutcome::Defect,
                StoreFailureDisposition::Conflict => RequestOutcome::Conflict,
                StoreFailureDisposition::DeterministicRejection
                | StoreFailureDisposition::Denied
                | StoreFailureDisposition::Unsupported => RequestOutcome::ValidationRejected,
                StoreFailureDisposition::Unavailable
                | StoreFailureDisposition::Backpressured
                | StoreFailureDisposition::DeadlineExceeded
                | StoreFailureDisposition::MigrationRequired => RequestOutcome::NotAttempted,
            }
        }
        Response::Unknown { .. } => RequestOutcome::Unknown,
        Response::Error { .. } => RequestOutcome::Defect,
    }
}

/// Projects the typed control codes from a failure. Only the validated reason
/// code and the typed recovery action travel; `human_detail` never does.
#[must_use]
pub fn project_failure_control(
    failure: &StoreFailure,
) -> (Option<StoreReasonCode>, Option<StoreRecoveryAction>) {
    (
        Some(failure.reason_code.clone()),
        Some(failure.recovery_action),
    )
}

/// Closed decision vocabulary of the installation-visible I5.9 compatibility
/// decision (issue #1932).
///
/// The two variants are the whole decision: the installation-visible record
/// qualified a canonical writer, or it did not. No variant claims liveness,
/// support, or a qualification the gate did not observe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityDecision {
    /// The installation-visible record qualifies this installation for
    /// canonical writes.
    WriterAdmitted,
    /// The installation is in explicit maintenance: queryable, running, and
    /// not a canonical writer.
    NonWriterMaintenance,
}

/// Bounded, typed projection of one installation-visible compatibility
/// decision (issue #1932, I5.9).
///
/// The decision itself is a fieldless typed value, so nothing about it can be
/// re-read as prose; the gate's report line travels only as a [`BoundedRef`]
/// re-validated here for length and control characters, so no unbounded or
/// unvalidated content reaches a sink through it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatibilityHealth {
    decision: CompatibilityDecision,
    decision_report: Option<BoundedRef>,
}

impl CompatibilityHealth {
    /// Returns the projected decision.
    #[must_use]
    pub const fn decision(&self) -> CompatibilityDecision {
        self.decision
    }

    /// Returns the bounded decision report line, when the gate produced one
    /// that passes the bound. A dropped report never changes the decision.
    #[must_use]
    pub fn decision_report(&self) -> Option<&str> {
        self.decision_report.as_ref().map(BoundedRef::as_str)
    }
}

/// Projects one installation-visible I5.9 compatibility verdict.
///
/// The projection reads only the typed verdict: the decision reached and the
/// gate's own bounded report line. It never re-evaluates the record, never
/// admits, and never upgrades an observation — a maintenance verdict projects
/// to [`CompatibilityDecision::NonWriterMaintenance`], the visible non-writer
/// readiness state the acceptance criteria require.
#[must_use]
pub fn project_compatibility_health(verdict: &CompatibilityVerdict) -> CompatibilityHealth {
    CompatibilityHealth {
        decision: if verdict.is_writer_admitted() {
            CompatibilityDecision::WriterAdmitted
        } else {
            CompatibilityDecision::NonWriterMaintenance
        },
        decision_report: BoundedRef::detail(verdict.report()),
    }
}

/// Records request/input receipt at one boundary. Infallible and bounded.
pub fn emit_received(
    log: &mut BoundedEventLog,
    boundary: BridgeBoundary,
    operation: &'static str,
    identity: &BridgeIdentity,
) {
    log.push(BridgeDiagnosticEvent::new(
        boundary,
        operation,
        RequestOutcome::Received,
        identity,
    ));
}

/// Records the bridge-to-provider handoff of one admitted dispatch.
/// This observes the handoff at the bridge boundary only; it never claims a
/// provider-internal start. Infallible and bounded.
pub fn emit_attempted(
    log: &mut BoundedEventLog,
    operation: &'static str,
    identity: &BridgeIdentity,
) {
    log.push(BridgeDiagnosticEvent::new(
        BridgeBoundary::Dispatch,
        operation,
        RequestOutcome::Attempted,
        identity,
    ));
}

/// Records a validation rejection before provider I/O. Infallible and bounded.
pub fn emit_validation_rejected(
    log: &mut BoundedEventLog,
    boundary: BridgeBoundary,
    operation: &'static str,
    identity: &BridgeIdentity,
    reason: Option<&StoreReasonCode>,
) {
    let mut event = BridgeDiagnosticEvent::new(
        boundary,
        operation,
        RequestOutcome::ValidationRejected,
        identity,
    );
    event.reason = reason.cloned();
    log.push(event);
}

/// Records the classified outcome of one dispatch response observed at
/// `boundary`. Reason, recovery, receipt status, and failure disposition are
/// projected from typed fields only; no prose is parsed or copied.
/// Infallible and bounded.
pub fn emit_dispatch_outcome(
    log: &mut BoundedEventLog,
    boundary: BridgeBoundary,
    operation: &'static str,
    identity: &BridgeIdentity,
    response: &Response,
) {
    let mut event =
        BridgeDiagnosticEvent::new(boundary, operation, classify_response(response), identity);
    match response {
        Response::Transaction { receipt } | Response::Genesis { receipt } => {
            event.receipt_status = Some(receipt.status);
        }
        Response::Failure { failure } => {
            let (reason, recovery) = project_failure_control(failure);
            event.reason = reason;
            event.recovery = recovery;
            event.failure_disposition = Some(failure.disposition);
        }
        Response::Receipt { .. }
        | Response::Health { .. }
        | Response::Readiness { .. }
        | Response::Named { .. }
        | Response::RevisionHeads { .. }
        | Response::OrderingHeads { .. }
        | Response::ValidationSnapshot { .. }
        | Response::Recovery { .. }
        | Response::DreamerJob { .. }
        | Response::Backup { .. }
        | Response::Unknown { .. }
        | Response::Error { .. } => {}
    }
    log.push(event);
}

/// Records reconciliation of a previously unknown outcome through owner
/// evidence. The caller folds the reconciling receipt into `identity` via
/// [`BridgeIdentity::from_receipt`] and [`BridgeIdentity::merge`] before
/// calling. Infallible and bounded.
pub fn emit_reconciled(
    log: &mut BoundedEventLog,
    operation: &'static str,
    identity: &BridgeIdentity,
) {
    log.push(BridgeDiagnosticEvent::new(
        BridgeBoundary::ReceiptReconciliation,
        operation,
        RequestOutcome::Reconciled,
        identity,
    ));
}

/// Records one non-request lifecycle transition (startup step, gate admission,
/// schema migration, generation rotation, shutdown disposition). The exact
/// disposition travels in the typed reason code. Infallible and bounded.
pub fn emit_lifecycle(
    log: &mut BoundedEventLog,
    boundary: BridgeBoundary,
    operation: &'static str,
    identity: &BridgeIdentity,
    reason: Option<&StoreReasonCode>,
) {
    let mut event = BridgeDiagnosticEvent::new(
        boundary,
        operation,
        RequestOutcome::LifecycleObserved,
        identity,
    );
    event.reason = reason.cloned();
    log.push(event);
}

/// Projects one closed dispatch request to its admitted operation name.
///
/// The mapping is total over the 13-arm catalogue and typed: every arm maps
/// to one [`ADMITTED_OPERATIONS`] entry and no caller prose is ever admitted
/// as an operation name.
#[must_use]
pub fn operation_name(request: &Request) -> &'static str {
    match request {
        Request::Health => "health",
        Request::Readiness => "readiness",
        Request::Named { .. } => "named",
        Request::Apply { .. } => "apply",
        Request::Receipt { .. } => "receipt",
        Request::ReservedWrite { .. } => "reserved_write",
        Request::Backup { .. } => "backup",
        Request::RevisionHeads { .. } => "revision_heads",
        Request::OrderingHeads { .. } => "ordering_heads",
        Request::ValidationSnapshot => "validation_snapshot",
        Request::Recovery { .. } => "recovery",
        Request::InitializeGenesis { .. } => "initialize_genesis",
        Request::DreamerJob { .. } => "dreamer_job",
    }
}

/// Projects one closed dispatch request to its owning result boundary.
///
/// Mutation, receipt, backup, recovery, genesis, and ledger arms observe
/// their dedicated result boundary; read-path arms observe [`Dispatch`].
/// The projection reads only the request arm discriminant: provider stages
/// stay unobserved and are never guessed.
///
/// [`Dispatch`]: BridgeBoundary::Dispatch
#[must_use]
pub fn dispatch_boundary(request: &Request) -> BridgeBoundary {
    match request {
        Request::Apply { .. } | Request::ReservedWrite { .. } => BridgeBoundary::MutationResult,
        Request::Receipt { .. } => BridgeBoundary::ReceiptLookup,
        Request::Backup { .. } => BridgeBoundary::BackupBoundary,
        Request::Recovery { .. } => BridgeBoundary::RecoveryBoundary,
        Request::InitializeGenesis { .. } => BridgeBoundary::GenesisBoundary,
        Request::DreamerJob { .. } => BridgeBoundary::DreamerLedger,
        Request::Health
        | Request::Readiness
        | Request::Named { .. }
        | Request::RevisionHeads { .. }
        | Request::OrderingHeads { .. }
        | Request::ValidationSnapshot => BridgeBoundary::Dispatch,
    }
}

/// Single-owner cell for the process startup subscriber.
///
/// The cell carries no data: installation is a pure ownership proof and a
/// duplicate installation observably fails instead of creating a second
/// owner. The sink itself is the process standard-error stream rendered
/// through the validated event projection, so reporting holds no
/// Store-critical lock and keeps no queue.
static STARTUP_SUBSCRIBER: OnceLock<()> = OnceLock::new();

/// Installs the process-wide bounded structured subscriber.
///
/// The first call installs and returns `true`; every later call observes
/// the existing owner and returns `false` without creating a second owner.
/// Only the process entry point calls this: reusable compositions never
/// install global subscribers, and tests capture through caller-owned
/// [`BoundedEventLog`] injection instead of this cell.
pub fn install_startup_subscriber() -> bool {
    STARTUP_SUBSCRIBER.set(()).is_ok()
}

/// Reports whether the process installed its startup subscriber.
#[must_use]
pub fn startup_subscriber_installed() -> bool {
    STARTUP_SUBSCRIBER.get().is_some()
}

/// Reports every retained scoped event to the installed startup sink.
///
/// Each event renders as one bounded line on the process standard-error
/// stream through the validated [`fmt::Display`] projection. The call is
/// infallible and wait-free from the caller's view: it holds no
/// Store-critical lock, keeps no queue, performs no retry, and ignores sink
/// errors, so a failed sink can neither recurse, stall, nor fabricate a
/// receipt. When the startup subscriber is not installed (reusable
/// compositions, tests) the call drops every event silently and changes no
/// behavior.
pub fn report_events(log: &BoundedEventLog) {
    if !startup_subscriber_installed() {
        return;
    }
    for event in log {
        let _ = writeln!(std::io::stderr(), "{SERVICE_NAME}: {event}");
    }
}

/// Closed vocabulary and order of the snapshot budget's accounted
/// dimensions. The projection compares adapter-provided labels against this
/// list and never renders those public strings directly.
const SNAPSHOT_BUDGET_FIELDS: [&str; 8] = [
    "snapshot.budget.v1.begins_in_progress",
    "snapshot.budget.v1.live_captures",
    "snapshot.budget.v1.retained_bytes",
    "snapshot.budget.v1.terminal_entries",
    "snapshot.budget.v1.terminal_bytes",
    "snapshot.budget.v1.enumeration_bytes",
    "snapshot.budget.v1.active_page_calls",
    "snapshot.budget.v1.cleanup_steps",
];
const SNAPSHOT_BUDGET_BYTE_LABEL: &str =
    "byte values are conservative snapshot.budget.v1 charges, not actual RSS/heap measurements; ";

/// Fixed, bounded view of the adapter's snapshot-budget counters. Byte values
/// are conservative `snapshot.budget.v1` charges, not RSS or heap measurements.
///
/// Unusable accounting and inconsistent numeric values retain only fixed-order
/// recorded counters, with every remaining value unknown. A label/order mismatch
/// produces a fixed marker so counters cannot be attributed to another dimension.
/// Caller-provided field strings are never rendered.
enum SnapshotBudgetProjection<'a> {
    AccountingUnusable(&'a SnapshotBudgetDiagnostics),
    Inconsistent(&'a SnapshotBudgetDiagnostics),
    DimensionLabelsInvalid(bool),
    Dimensions(&'a SnapshotBudgetDiagnostics),
}

impl<'a> SnapshotBudgetProjection<'a> {
    fn from_diagnostics(diagnostics: &'a SnapshotBudgetDiagnostics) -> Self {
        for (field, dimension) in SNAPSHOT_BUDGET_FIELDS
            .iter()
            .zip(diagnostics.dimensions.iter())
        {
            if dimension.field != *field {
                return Self::DimensionLabelsInvalid(diagnostics.accounting_usable);
            }
        }

        for dimension in &diagnostics.dimensions {
            if dimension.charged > dimension.limit
                || dimension.high_water < dimension.charged
                || dimension.high_water > dimension.limit
            {
                return Self::Inconsistent(diagnostics);
            }
        }

        if !diagnostics.accounting_usable {
            return Self::AccountingUnusable(diagnostics);
        }

        for dimension in &diagnostics.dimensions {
            if let Some(remaining) = dimension.remaining
                && dimension.limit.checked_sub(dimension.charged) != Some(remaining)
            {
                return Self::Inconsistent(diagnostics);
            }
        }

        Self::Dimensions(diagnostics)
    }
}

impl fmt::Display for SnapshotBudgetProjection<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccountingUnusable(diagnostics) => {
                write_recorded_dimensions(formatter, diagnostics, "unknown")
            }
            Self::Inconsistent(diagnostics) => {
                write_recorded_dimensions(formatter, diagnostics, "inconsistent")
            }
            Self::DimensionLabelsInvalid(accounting_usable) => {
                formatter.write_str(SNAPSHOT_BUDGET_BYTE_LABEL)?;
                write!(
                    formatter,
                    "accounting_usable={accounting_usable} state=inconsistent"
                )
            }
            Self::Dimensions(diagnostics) => {
                let state = if diagnostics
                    .dimensions
                    .iter()
                    .any(|dimension| dimension.remaining.is_none())
                {
                    "partial"
                } else {
                    "healthy"
                };
                formatter.write_str(SNAPSHOT_BUDGET_BYTE_LABEL)?;
                write!(formatter, "accounting_usable=true state={state}")?;
                for (field, dimension) in SNAPSHOT_BUDGET_FIELDS
                    .iter()
                    .zip(diagnostics.dimensions.iter())
                {
                    write!(
                        formatter,
                        " {field}{{limit={},charged={},high_water={},remaining=",
                        dimension.limit, dimension.charged, dimension.high_water
                    )?;
                    match dimension.remaining {
                        Some(remaining) => write!(formatter, "{remaining}")?,
                        None => formatter.write_str("unknown")?,
                    }
                    formatter.write_str("}")?;
                }
                Ok(())
            }
        }
    }
}

fn write_recorded_dimensions(
    formatter: &mut fmt::Formatter<'_>,
    diagnostics: &SnapshotBudgetDiagnostics,
    state: &str,
) -> fmt::Result {
    formatter.write_str(SNAPSHOT_BUDGET_BYTE_LABEL)?;
    write!(
        formatter,
        "accounting_usable={} state={state}; recorded charges",
        diagnostics.accounting_usable
    )?;
    for (field, dimension) in SNAPSHOT_BUDGET_FIELDS
        .iter()
        .zip(diagnostics.dimensions.iter())
    {
        write!(
            formatter,
            " {field}{{limit_recorded={},charged_recorded={},high_water_recorded={},remaining=unknown}}",
            dimension.limit, dimension.charged, dimension.high_water
        )?;
    }
    Ok(())
}

/// Reports the bounded snapshot-budget projection to the installed startup
/// diagnostic sink. The output contains only fixed dimension labels and
/// numeric values; it retains no capture payload or identity.
pub fn report_snapshot_budget(diagnostics: &SnapshotBudgetDiagnostics) {
    if !startup_subscriber_installed() {
        return;
    }
    let projection = SnapshotBudgetProjection::from_diagnostics(diagnostics);
    let _ = writeln!(std::io::stderr(), "{SERVICE_NAME}: {projection}");
}

#[cfg(test)]
mod snapshot_budget_tests {
    use super::{SNAPSHOT_BUDGET_FIELDS, SnapshotBudgetProjection};
    use eliot_store_surreal_adapter::{SnapshotBudgetDiagnostics, SnapshotBudgetDimension};

    fn healthy_diagnostics() -> SnapshotBudgetDiagnostics {
        SnapshotBudgetDiagnostics {
            accounting_usable: true,
            dimensions: std::array::from_fn(|index| SnapshotBudgetDimension {
                field: SNAPSHOT_BUDGET_FIELDS[index],
                limit: 8,
                charged: 3,
                high_water: 5,
                remaining: Some(5),
            }),
        }
    }

    #[test]
    fn healthy_budget_projection_keeps_the_fixed_order_and_values() {
        let rendered =
            SnapshotBudgetProjection::from_diagnostics(&healthy_diagnostics()).to_string();

        assert!(rendered.contains("accounting_usable=true state=healthy"));
        assert!(rendered.contains(
            "byte values are conservative snapshot.budget.v1 charges, not actual RSS/heap measurements"
        ));
        assert!(rendered.contains(
            "snapshot.budget.v1.begins_in_progress{limit=8,charged=3,high_water=5,remaining=5}"
        ));
        let positions = SNAPSHOT_BUDGET_FIELDS.map(|field| rendered.find(field));
        assert!(positions.iter().all(Option::is_some));
        assert!(positions.windows(2).all(|window| window[0] < window[1]));
    }

    #[test]
    fn unusable_accounting_projects_unknown_without_zero_headroom() {
        let mut diagnostics = healthy_diagnostics();
        diagnostics.accounting_usable = false;
        diagnostics.dimensions[0].remaining = Some(0);

        let rendered = SnapshotBudgetProjection::from_diagnostics(&diagnostics).to_string();

        assert!(rendered.contains("accounting_usable=false state=unknown; recorded charges"));
        assert!(rendered.contains(
            "snapshot.budget.v1.begins_in_progress{limit_recorded=8,charged_recorded=3,high_water_recorded=5,remaining=unknown}"
        ));
        assert!(!rendered.contains("remaining=0"));
    }

    #[test]
    fn unknown_remaining_is_not_projected_as_zero() {
        let mut diagnostics = healthy_diagnostics();
        diagnostics.dimensions[0].remaining = None;

        let rendered = SnapshotBudgetProjection::from_diagnostics(&diagnostics).to_string();

        assert!(rendered.contains("accounting_usable=true state=partial"));
        assert!(rendered.contains(
            "snapshot.budget.v1.begins_in_progress{limit=8,charged=3,high_water=5,remaining=unknown}"
        ));
    }

    #[test]
    fn inconsistent_numeric_accounting_is_not_projected_as_headroom() {
        let mut diagnostics = healthy_diagnostics();
        diagnostics.dimensions[0].remaining = Some(0);

        let rendered = SnapshotBudgetProjection::from_diagnostics(&diagnostics).to_string();

        assert!(rendered.contains("accounting_usable=true state=inconsistent"));
        assert!(!rendered.contains("remaining=0"));

        let mut impossible_peak = healthy_diagnostics();
        impossible_peak.dimensions[0].high_water = 9;

        let rendered_peak =
            SnapshotBudgetProjection::from_diagnostics(&impossible_peak).to_string();

        assert!(rendered_peak.contains("accounting_usable=true state=inconsistent"));
        assert!(rendered_peak.contains("high_water_recorded=9,remaining=unknown"));
        assert!(!rendered_peak.contains("remaining=0"));
    }

    #[test]
    fn unusable_accounting_with_forged_dimension_is_not_attributed() {
        let mut diagnostics = healthy_diagnostics();
        diagnostics.accounting_usable = false;
        diagnostics.dimensions[0].field = "captured payload or forged field";

        let rendered = SnapshotBudgetProjection::from_diagnostics(&diagnostics).to_string();

        assert!(rendered.contains("accounting_usable=false state=inconsistent"));
        assert!(!rendered.contains("captured payload or forged field"));
        assert!(!rendered.contains("charged_recorded="));
        assert!(!rendered.contains("remaining=0"));
    }
}

#[cfg(test)]
// Inline private-path proofs for issue #742. They stay inside this module
// because the closed boundary ledger, the emitters, and the frozen outcome
// vocabulary are not exported for testing, and no runtime flag may reach them.
#[allow(clippy::expect_used, clippy::too_many_lines)]
mod bridge_boundary_partition_tests {
    use std::collections::BTreeMap;

    use eliot_contracts::{
        ArtifactId, ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId,
        ResourceGeneration, SourceId, StateFence, TaskId,
    };
    use eliot_protocol::dreamer_job::{
        DurableJobRequest, DurableRequestIdentity, JobOperation, JobRole,
    };
    use eliot_store_api::{
        CONTRACT_VERSION, EffectClass, EventProjectionRelationIntents, NamedMutationOperation,
        NamedMutationRequest, NamedReadOperation, NamedReadRequest, OperationIdentity,
        OperationManifestDigest, OrderingHeadExpectation, OrderingScopeId,
        PolicyConfigSchemaVersions, PreparedTransition, ReadConsistency, RequestMeta,
        ReservedScopeBinding, ReservedWriteRequest, Resubmission, RevisionHeadExpectation,
        RevisionKey, STORE_FAILURE_CONTRACT_REVISION, ScopeId, SecurityContext,
        StoreBackupOperation, StoreBackupRequest, StoreBackupResponse, StoreBackupStatus,
        StoreBackupStatusOutcome, StoreEvidenceHandles, StoreFailure, StoreFailureDisposition,
        StoreGenesisRequest, StoreMutationDisposition, StoreReasonCode, StoreRecoveryAction,
        StoreRecoveryRequest, StoreRetryDirective, TransitionClass, WriteAdmissionParams,
        WriteAdmissionProjection, WriteReceipt, WriteReceiptStatus, WriterEpochBinding,
        bind_issue18_digests, generated_operation_manifests, operation_manifest_set_digest,
    };

    use crate::{Request, Response};

    use super::{
        ADMITTED_OPERATIONS, BoundedEventLog, BridgeBoundary, BridgeDiagnosticEvent,
        BridgeIdentity, MAX_DIAGNOSTIC_EVENTS, RequestOutcome, classify_response,
        dispatch_boundary, emit_attempted, emit_dispatch_outcome, emit_lifecycle, emit_received,
        emit_reconciled, emit_validation_rejected, is_admitted_operation, operation_name,
    };

    fn fence() -> StateFence {
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440742").expect("lineage");
        let sequence = std::num::NonZeroU64::new(7).expect("epoch sequence");
        StateFence::new(
            EpochId::new(lineage, sequence).expect("authority epoch"),
            ResourceGeneration::genesis(),
        )
    }

    fn request_meta() -> RequestMeta {
        RequestMeta {
            request_id: RequestId::new("request-742-partition").expect("request id"),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product-742-partition").expect("product id"),
            source_id: SourceId::new("source-742-partition").expect("source id"),
            state_fence: fence(),
            clock: ClockReading::default(),
        }
    }

    fn operation_identity() -> OperationIdentity {
        OperationIdentity {
            operation_id: OperationId::new("operation-742-partition").expect("operation id"),
            idempotency_key: "idempotency-742-partition".to_owned(),
            canonical_request_hash: "a".repeat(64),
        }
    }

    fn prepared_transition() -> PreparedTransition {
        let entries = generated_operation_manifests().expect("generated operation manifests");
        let operation_manifest_digest =
            operation_manifest_set_digest(&entries).expect("operation manifest set digest");
        let mut transition = PreparedTransition {
            contract_version: CONTRACT_VERSION,
            identity: operation_identity(),
            state_fence: fence(),
            scope_id: ScopeId::new("scope-742-partition").expect("scope id"),
            task_id: None,
            ordering_scopes: vec![
                OrderingScopeId::new("scope-742-partition").expect("ordering scope"),
            ],
            transition_class: TransitionClass::CaptureCandidate,
            requested_effect_ceiling: EffectClass::Candidate,
            admission_contract_set_digest: "b".repeat(64),
            operation_manifest_digest,
            admission_digest: String::new(),
            mutation_plan_digest: String::new(),
            semantic_source_revisions: Vec::new(),
            named_operations: vec![NamedMutationRequest {
                operation: NamedMutationOperation::CaptureObservation,
                parameters: BTreeMap::from([(
                    "subject".to_owned(),
                    serde_json::json!("observation-742-partition"),
                )]),
            }],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
        };
        bind_issue18_digests(&mut transition).expect("issue-18 digests bind");
        transition
    }

    fn reserved_write_request() -> ReservedWriteRequest {
        let transition = prepared_transition();
        let params = WriteAdmissionParams {
            reservation_id: "reservation-742-partition".to_owned(),
            reservation_order: 742,
            operation_id: transition.identity.operation_id.clone(),
            idempotency_key: transition.identity.idempotency_key.clone(),
            canonical_request_hash: transition.identity.canonical_request_hash.clone(),
            scopes: vec![ReservedScopeBinding {
                scope: OrderingScopeId::new("scope-742-partition").expect("ordering scope"),
                reserved_sequence: 7,
                expected_sequence: 6,
                expected_head_digest: "c".repeat(64),
            }],
            writer_epoch: WriterEpochBinding {
                lineage_id: "epoch-lineage-742-partition".to_owned(),
                epoch: 7,
                predecessor_lineage_id: None,
                predecessor_epoch: None,
            },
            state_fence: fence(),
            source_id: "source-742-partition".to_owned(),
            created_at_ms: 1_700_000_000_000,
            expires_at_ms: 1_700_000_060_000,
            recovery_owner: "recovery-owner-742-partition".to_owned(),
        };
        let admission = WriteAdmissionProjection::bind(&transition, params)
            .expect("reservation admission binds");
        ReservedWriteRequest {
            context: request_meta(),
            transition,
            admission,
            expected_revision_heads: vec![RevisionHeadExpectation {
                key: RevisionKey::new("revision-742-partition").expect("revision key"),
                expected_revision: 3,
                state_fence: fence(),
            }],
            expected_ordering_heads: vec![OrderingHeadExpectation {
                scope: OrderingScopeId::new("scope-742-partition").expect("ordering scope"),
                expected_sequence: 6,
                state_fence: fence(),
            }],
        }
    }

    fn backup_request() -> StoreBackupRequest {
        StoreBackupRequest {
            context: request_meta(),
            identity: operation_identity(),
            operation: StoreBackupOperation::Status {
                operation_id: OperationId::new("operation-742-backup").expect("operation id"),
            },
        }
    }

    fn durable_job_request() -> DurableJobRequest {
        let state_fence = fence();
        let context = request_meta();
        let operation = JobOperation::Status {
            job_id: TaskId::new("job-742-partition").expect("task id"),
            attempt_id: ArtifactId::new("attempt-742-partition").expect("artifact id"),
            expected_revision: 1,
            expected_fence: state_fence.clone(),
        };
        let operation_kind = operation.kind().as_str().to_owned();
        let fence_json = serde_json::to_value(&state_fence).expect("state fence json");
        let context_json = serde_json::to_value(&context).expect("request context json");
        let request_identity: DurableRequestIdentity = serde_json::from_value(serde_json::json!({
            "request": {
                "request": {
                    "metadata": context_json,
                    "state_fence": fence_json.clone(),
                },
                "idempotency_key": "transport-742-partition",
                "deadline_unix_ms": 600_000,
                "cancellation_id": "cancel-742-partition",
            },
            "operation": {
                "operation_id": "operation-742-dreamer",
                "request_id": "originating-742-partition",
                "idempotency_key": "idempotency-742-dreamer",
                "operation_kind": operation_kind,
                "effect": "CANDIDATE",
                "state_fence": fence_json,
            },
            "canonical_request_hash": "0".repeat(64),
        }))
        .expect("durable request identity decodes");
        DurableJobRequest {
            request_identity,
            role: JobRole::Requester,
            operation,
        }
    }

    /// One instance of every arm of the closed 13-arm dispatch catalogue, each
    /// paired with the operation name that arm must project to.
    fn catalogue_requests() -> Vec<(&'static str, Request)> {
        vec![
            ("health", Request::Health),
            ("readiness", Request::Readiness),
            (
                "named",
                Request::Named {
                    request: NamedReadRequest {
                        operation: NamedReadOperation::GetRevisionHeads,
                        scope_id: None,
                        consistency: ReadConsistency::ExactFence,
                        state_fence: fence(),
                        parameters: BTreeMap::new(),
                    },
                },
            ),
            (
                "apply",
                Request::Apply {
                    context: request_meta(),
                    transition: prepared_transition(),
                    expected_revision_heads: Vec::new(),
                    expected_ordering_heads: Vec::new(),
                },
            ),
            (
                "receipt",
                Request::Receipt {
                    operation_id: operation_identity().operation_id,
                },
            ),
            (
                "reserved_write",
                Request::ReservedWrite {
                    request: reserved_write_request(),
                },
            ),
            (
                "backup",
                Request::Backup {
                    request: backup_request(),
                },
            ),
            (
                "revision_heads",
                Request::RevisionHeads { keys: Vec::new() },
            ),
            (
                "ordering_heads",
                Request::OrderingHeads { scopes: Vec::new() },
            ),
            ("validation_snapshot", Request::ValidationSnapshot),
            (
                "recovery",
                Request::Recovery {
                    request: StoreRecoveryRequest {
                        contract_version: CONTRACT_VERSION,
                        state_fence: fence(),
                        records: Vec::new(),
                        include_receipts: false,
                        include_jobs: false,
                    },
                },
            ),
            (
                "initialize_genesis",
                Request::InitializeGenesis {
                    context: request_meta(),
                    request: StoreGenesisRequest {
                        contract_version: CONTRACT_VERSION,
                        operation_id: OperationId::new("operation-742-genesis")
                            .expect("operation id"),
                        idempotency_key: "idempotency-742-genesis".to_owned(),
                        canonical_request_hash: "d".repeat(64),
                        state_fence: fence(),
                        owner_records: Vec::new(),
                    },
                },
            ),
            (
                "dreamer_job",
                Request::DreamerJob {
                    context: request_meta(),
                    request: durable_job_request(),
                },
            ),
        ]
    }

    fn write_receipt(status: WriteReceiptStatus) -> WriteReceipt {
        WriteReceipt {
            operation_id: OperationId::new("operation-742-receipt").expect("operation id"),
            idempotency_key: "idempotency-742-receipt".to_owned(),
            canonical_request_hash: "e".repeat(64),
            transition_class: TransitionClass::CaptureCandidate,
            status,
            commit_id: None,
            state_fence: fence(),
            ordering_sequences: Vec::new(),
            revision_before_after: Vec::new(),
            applied_command_ids: Vec::new(),
            emitted_event_ids: Vec::new(),
            projection_refs: Vec::new(),
            outbox_refs: Vec::new(),
            operation_manifest_digest: OperationManifestDigest::new("f".repeat(64))
                .expect("operation manifest digest shape"),
            admission_digest: "1".repeat(64),
            mutation_plan_digest: "2".repeat(64),
            semantic_source_revisions: Vec::new(),
            policy_config_schema_versions: PolicyConfigSchemaVersions {
                policy_revision: None,
                config_profile: "operation-catalogue-profile-fixture".to_owned(),
                schema_revision: CONTRACT_VERSION,
            },
            error_code: None,
            resubmission: Resubmission::None,
            committed_at: None,
            envelope: None,
        }
    }

    fn typed_failure(
        disposition: StoreFailureDisposition,
        mutation_disposition: StoreMutationDisposition,
    ) -> StoreFailure {
        StoreFailure {
            contract_revision: STORE_FAILURE_CONTRACT_REVISION.to_owned(),
            disposition,
            reason_code: StoreReasonCode::new("bridge.failure.observed").expect("reason code"),
            request_id: Some(RequestId::new("request-742-failure").expect("request id")),
            operation_id: Some(OperationId::new("operation-742-failure").expect("operation id")),
            idempotency_key_ref_or_digest: Some("idempotency-742-failure".to_owned()),
            state_fence_ref_or_exact_safe_projection: None,
            mutation_disposition,
            retry_directive: StoreRetryDirective::DoNotRetry,
            recovery_action: StoreRecoveryAction::EscalateInternalDefect,
            conflict: None,
            retry_after_ms: None,
            retry_after_dependency_revision: None,
            evidence_ref: None,
            evidence_handles: StoreEvidenceHandles::default(),
            human_detail: Some("bounded bridge failure detail".to_owned()),
        }
    }

    /// One response per outcome the typed response projection can reach: every
    /// terminal receipt status, the empty and present receipt lookup, both
    /// legacy variants, all ten typed failure dispositions, the unknown
    /// mutation disposition override, and all five backup status outcomes.
    fn classified_responses() -> Vec<Response> {
        let mut responses = vec![
            Response::Transaction {
                receipt: write_receipt(WriteReceiptStatus::Committed),
            },
            Response::Transaction {
                receipt: write_receipt(WriteReceiptStatus::Rejected),
            },
            Response::Transaction {
                receipt: write_receipt(WriteReceiptStatus::DeadLetter),
            },
            Response::Transaction {
                receipt: write_receipt(WriteReceiptStatus::Cancelled),
            },
            Response::Genesis {
                receipt: write_receipt(WriteReceiptStatus::Committed),
            },
            Response::Receipt { receipt: None },
            Response::Receipt {
                receipt: Some(write_receipt(WriteReceiptStatus::Committed)),
            },
            Response::RevisionHeads { heads: Vec::new() },
            Response::OrderingHeads { heads: Vec::new() },
            Response::Unknown {
                operation_id: OperationId::new("operation-742-unknown").expect("operation id"),
                reason: "provider outcome unknown".to_owned(),
            },
            Response::Error {
                error: "legacy string failure".to_owned(),
            },
        ];
        for disposition in [
            StoreFailureDisposition::DeterministicRejection,
            StoreFailureDisposition::Denied,
            StoreFailureDisposition::Unsupported,
            StoreFailureDisposition::Unavailable,
            StoreFailureDisposition::Backpressured,
            StoreFailureDisposition::DeadlineExceeded,
            StoreFailureDisposition::MigrationRequired,
            StoreFailureDisposition::UnknownOutcome,
            StoreFailureDisposition::Conflict,
            StoreFailureDisposition::InternalDefect,
        ] {
            responses.push(Response::Failure {
                failure: typed_failure(disposition, StoreMutationDisposition::NotAttempted),
            });
        }
        responses.push(Response::Failure {
            failure: typed_failure(
                StoreFailureDisposition::DeterministicRejection,
                StoreMutationDisposition::Unknown,
            ),
        });
        for outcome in [
            StoreBackupStatusOutcome::Complete,
            StoreBackupStatusOutcome::Reconciled,
            StoreBackupStatusOutcome::Unknown,
            StoreBackupStatusOutcome::InProgress,
            StoreBackupStatusOutcome::Expired,
        ] {
            responses.push(Response::Backup {
                response: StoreBackupResponse::Status {
                    report: StoreBackupStatus {
                        operation_id: OperationId::new("operation-742-backup-status")
                            .expect("operation id"),
                        state_fence: fence(),
                        outcome,
                    },
                },
            });
        }
        responses
    }

    fn filler_identity(index: usize) -> BridgeIdentity {
        BridgeIdentity::new().with_generation(&format!("fill-{index}"))
    }

    // WORK_UNIT_CASE: 742/17
    #[test]
    fn every_inventoried_boundary_emits_one_owning_event_and_the_log_stays_bounded() {
        let identity = BridgeIdentity::new()
            .with_request(&RequestId::new("request-742-17").expect("request id"))
            .with_operation(&OperationId::new("operation-742-17").expect("operation id"))
            .with_idempotency_ref("idempotency-742-17")
            .with_generation("generation-742-17");
        let reason = StoreReasonCode::new("bridge.boundary.observed").expect("reason code");

        let mut log = BoundedEventLog::new();
        assert!(log.is_empty(), "a fresh bounded log retains nothing");

        // One request-receipt event per inventoried boundary: every boundary
        // in the closed ledger owns exactly one recorded event, and no
        // boundary is inflated into a second event by the same call.
        assert_eq!(
            BridgeBoundary::ALL.len(),
            28,
            "the closed bridge-boundary ledger has twenty-eight entries"
        );
        for &boundary in BridgeBoundary::ALL {
            emit_received(&mut log, boundary, boundary.as_str(), &identity);
        }
        assert_eq!(
            log.len(),
            BridgeBoundary::ALL.len(),
            "each emitting call records exactly one event"
        );
        assert_eq!(log.dropped(), 0, "no event is dropped below the bound");

        let mut counts: Vec<(&str, usize)> = BridgeBoundary::ALL
            .iter()
            .copied()
            .map(|boundary| (boundary.as_str(), 0))
            .collect();
        for event in &log {
            let code = event.boundary().as_str();
            let entry = counts
                .iter_mut()
                .find(|entry| entry.0 == code)
                .expect("a recorded boundary belongs to the closed ledger");
            entry.1 += 1;
            assert_eq!(
                event.operation(),
                code,
                "a boundary event records the stable machine code it observed"
            );
            assert_eq!(
                event.outcome(),
                RequestOutcome::Received,
                "a request-receipt event is recorded as received, never as an attempt"
            );
        }
        assert!(
            counts.iter().all(|(_, count)| *count == 1),
            "no owning boundary carries a duplicate inflated event"
        );

        // Every remaining public emitting entry adds exactly one event on the
        // boundary it owns, and names an admitted operation.
        let baseline = log.len();
        let mut expected = baseline;
        emit_attempted(&mut log, "apply", &identity);
        expected += 1;
        assert_eq!(log.len(), expected, "the handoff entry records one event");
        emit_validation_rejected(
            &mut log,
            BridgeBoundary::SessionValidation,
            "apply",
            &identity,
            Some(&reason),
        );
        expected += 1;
        assert_eq!(
            log.len(),
            expected,
            "the validation-rejection entry records one event"
        );
        emit_reconciled(&mut log, "reconciliation", &identity);
        expected += 1;
        assert_eq!(
            log.len(),
            expected,
            "the reconciliation entry records one event"
        );
        emit_lifecycle(
            &mut log,
            BridgeBoundary::Shutdown,
            "shutdown",
            &identity,
            Some(&reason),
        );
        expected += 1;
        assert_eq!(log.len(), expected, "the lifecycle entry records one event");
        let legacy_failure = Response::Error {
            error: "legacy string failure".to_owned(),
        };
        emit_dispatch_outcome(
            &mut log,
            BridgeBoundary::FrameRejection,
            "frame",
            &identity,
            &legacy_failure,
        );
        expected += 1;
        assert_eq!(
            log.len(),
            expected,
            "the classified-outcome entry records one event"
        );

        let owners: Vec<(BridgeBoundary, RequestOutcome)> = log
            .iter()
            .skip(baseline)
            .map(|event| (event.boundary(), event.outcome()))
            .collect();
        assert_eq!(
            owners,
            vec![
                (BridgeBoundary::Dispatch, RequestOutcome::Attempted),
                (
                    BridgeBoundary::SessionValidation,
                    RequestOutcome::ValidationRejected
                ),
                (
                    BridgeBoundary::ReceiptReconciliation,
                    RequestOutcome::Reconciled
                ),
                (BridgeBoundary::Shutdown, RequestOutcome::LifecycleObserved),
                (BridgeBoundary::FrameRejection, RequestOutcome::Defect),
            ],
            "each emitting entry records the boundary it owns and its own outcome"
        );
        assert!(
            log.iter()
                .skip(baseline)
                .all(|event| ADMITTED_OPERATIONS.contains(&event.operation())),
            "every call-site event names an admitted operation"
        );

        // Repeated output is bounded: the buffer never grows past
        // MAX_DIAGNOSTIC_EVENTS, every drop past the bound is counted once,
        // and the oldest events are the ones discarded.
        let filler_count = MAX_DIAGNOSTIC_EVENTS;
        for index in 0..filler_count {
            emit_lifecycle(
                &mut log,
                BridgeBoundary::Dispatch,
                "apply",
                &filler_identity(index),
                Some(&reason),
            );
        }
        assert_eq!(
            log.len(),
            MAX_DIAGNOSTIC_EVENTS,
            "the bounded log never grows past its capture capacity"
        );
        assert_eq!(
            log.dropped(),
            u64::try_from(baseline).expect("baseline event count fits in u64"),
            "every event pushed past the bound is counted as dropped exactly once"
        );
        let retained: Vec<usize> = log
            .iter()
            .filter_map(|event| event.identity().generation())
            .filter_map(|generation| {
                generation
                    .strip_prefix("fill-")
                    .and_then(|index| index.parse::<usize>().ok())
            })
            .collect();
        assert_eq!(
            retained.len(),
            MAX_DIAGNOSTIC_EVENTS,
            "every retained event is one of the bounded filler events"
        );
        assert_eq!(
            retained.first(),
            Some(&0),
            "the bound evicted exactly the oldest events: the first filler survives"
        );
        assert_eq!(
            retained.last(),
            Some(&(filler_count - 1)),
            "the newest emitted event is always retained"
        );
        assert!(
            retained.windows(2).all(|pair| pair[0] < pair[1]),
            "the bounded log preserves emission order and drops oldest-first"
        );
    }

    // WORK_UNIT_CASE: 742/23
    #[test]
    fn boundary_operation_and_outcome_partitions_stay_closed_and_rollback_stays_unobservable() {
        // The closed boundary ledger is a partition: one distinct, non-prose
        // machine code per entry.
        let codes: Vec<&'static str> = BridgeBoundary::ALL
            .iter()
            .copied()
            .map(BridgeBoundary::as_str)
            .collect();
        let mut distinct_codes = codes.clone();
        distinct_codes.sort_unstable();
        distinct_codes.dedup();
        assert_eq!(
            distinct_codes.len(),
            BridgeBoundary::ALL.len(),
            "every bridge boundary owns one distinct machine code"
        );
        assert!(
            codes
                .iter()
                .all(|code| !code.is_empty() && !code.contains(' ')),
            "a boundary machine code is never blank or prose"
        );

        // The admitted operation vocabulary is closed and duplicate-free, and
        // it admits no caller prose.
        let mut distinct_admitted = ADMITTED_OPERATIONS.to_vec();
        distinct_admitted.sort_unstable();
        let admitted_total = distinct_admitted.len();
        distinct_admitted.dedup();
        assert_eq!(
            distinct_admitted.len(),
            admitted_total,
            "the admitted operation vocabulary has no duplicate entry"
        );
        assert!(
            !is_admitted_operation("apply per caller prose"),
            "caller prose is never admitted as an operation name"
        );

        // The closed dispatch catalogue projects onto admitted operations and
        // onto the owning result boundaries, with no arm collapsed and no
        // boundary invented outside the ledger.
        let arms = catalogue_requests();
        assert_eq!(
            arms.len(),
            13,
            "the closed dispatch catalogue has thirteen arms"
        );
        let mut projected_operations: Vec<&'static str> = Vec::with_capacity(arms.len());
        let mut result_boundaries: Vec<BridgeBoundary> = Vec::with_capacity(arms.len());
        for (expected_operation, request) in &arms {
            let operation = operation_name(request);
            let boundary = dispatch_boundary(request);
            let boundary_code = boundary.as_str();
            assert_eq!(
                operation, *expected_operation,
                "an arm projects exactly its own admitted operation name"
            );
            assert!(
                ADMITTED_OPERATIONS.contains(&operation),
                "every projected operation name is admitted: {operation}"
            );
            assert!(
                BridgeBoundary::ALL.contains(&boundary),
                "every owning result boundary is in the closed ledger: {boundary_code}"
            );
            projected_operations.push(operation);
            result_boundaries.push(boundary);
        }
        let mut distinct_operations = projected_operations.clone();
        distinct_operations.sort_unstable();
        distinct_operations.dedup();
        assert_eq!(
            distinct_operations.len(),
            arms.len(),
            "no two dispatch arms collapse onto one operation name"
        );
        let mut ordered_boundaries: Vec<(&'static str, BridgeBoundary)> = result_boundaries
            .iter()
            .copied()
            .map(|boundary| (boundary.as_str(), boundary))
            .collect();
        ordered_boundaries.sort_unstable_by(|left, right| left.0.cmp(right.0));
        ordered_boundaries.dedup_by(|left, right| left.0 == right.0);
        let boundary_partition: Vec<BridgeBoundary> = ordered_boundaries
            .into_iter()
            .map(|entry| entry.1)
            .collect();
        assert_eq!(
            boundary_partition,
            vec![
                BridgeBoundary::BackupBoundary,
                BridgeBoundary::Dispatch,
                BridgeBoundary::DreamerLedger,
                BridgeBoundary::GenesisBoundary,
                BridgeBoundary::MutationResult,
                BridgeBoundary::ReceiptLookup,
                BridgeBoundary::RecoveryBoundary,
            ],
            "the catalogue arms partition onto exactly the owning result boundaries"
        );

        // Frozen identity distinction: read-path, head, snapshot, and recovery
        // arms project the empty identity; identity-bearing arms keep one.
        let identity_arms: Vec<bool> = arms
            .iter()
            .map(|(_, request)| {
                let projected = BridgeIdentity::from_request(request);
                projected.operation_id().is_some()
            })
            .collect();
        assert_eq!(
            identity_arms,
            vec![
                false, false, false, true, true, true, true, false, false, false, false, true,
                true,
            ],
            "only identity-bearing arms project an operation identity"
        );

        // The typed response projection reaches exactly the observable
        // outcomes; the reserved rollback outcome is unreachable.
        let responses = classified_responses();
        let classified: Vec<RequestOutcome> = responses.iter().map(classify_response).collect();
        assert!(
            !classified.contains(&RequestOutcome::RolledBack),
            "the response projection never produces the reserved rollback outcome"
        );
        let mut classified_pairs: Vec<(&'static str, RequestOutcome)> = classified
            .iter()
            .copied()
            .map(|outcome| (outcome.as_str(), outcome))
            .collect();
        classified_pairs.sort_unstable_by(|left, right| left.0.cmp(right.0));
        classified_pairs.dedup_by(|left, right| left.0 == right.0);
        let outcome_partition: Vec<RequestOutcome> =
            classified_pairs.into_iter().map(|entry| entry.1).collect();
        assert_eq!(
            outcome_partition,
            vec![
                RequestOutcome::Attempted,
                RequestOutcome::Committed,
                RequestOutcome::Conflict,
                RequestOutcome::Defect,
                RequestOutcome::NotAttempted,
                RequestOutcome::ReadCompleted,
                RequestOutcome::Reconciled,
                RequestOutcome::TerminalNonCommit,
                RequestOutcome::Unknown,
                RequestOutcome::ValidationRejected,
            ],
            "the response projection reaches exactly the ten observable outcomes and never rollback"
        );
        assert_eq!(
            classify_response(&Response::Error {
                error: "legacy string failure".to_owned(),
            }),
            RequestOutcome::Defect,
            "the legacy string failure stays a typed defect, never a commit"
        );
        assert_eq!(
            classify_response(&Response::Receipt { receipt: None }),
            RequestOutcome::ReadCompleted,
            "a receipt lookup with no receipt is a completed read, never a commit claim"
        );

        // No public emitting entry can record the reserved rollback outcome.
        let identity = BridgeIdentity::new()
            .with_operation(&OperationId::new("operation-742-23").expect("operation id"))
            .with_idempotency_ref("idempotency-742-23");
        let reason = StoreReasonCode::new("bridge.partition.observed").expect("reason code");
        let mut log = BoundedEventLog::new();
        emit_received(
            &mut log,
            BridgeBoundary::SessionValidation,
            "apply",
            &identity,
        );
        emit_attempted(&mut log, "apply", &identity);
        emit_validation_rejected(
            &mut log,
            BridgeBoundary::SessionValidation,
            "apply",
            &identity,
            Some(&reason),
        );
        emit_dispatch_outcome(
            &mut log,
            BridgeBoundary::MutationResult,
            "apply",
            &identity,
            &responses[0],
        );
        emit_reconciled(&mut log, "reconciliation", &identity);
        emit_lifecycle(
            &mut log,
            BridgeBoundary::SchemaMigration,
            "schema_migration",
            &identity,
            Some(&reason),
        );
        assert_eq!(
            log.len(),
            6,
            "each public emitting entry records exactly one event"
        );
        let emitted: Vec<RequestOutcome> = log.iter().map(BridgeDiagnosticEvent::outcome).collect();
        assert_eq!(
            emitted,
            vec![
                RequestOutcome::Received,
                RequestOutcome::Attempted,
                RequestOutcome::ValidationRejected,
                RequestOutcome::Committed,
                RequestOutcome::Reconciled,
                RequestOutcome::LifecycleObserved,
            ],
            "each emitting entry records its own call-site outcome"
        );
        assert!(
            emitted
                .iter()
                .all(|outcome| *outcome != RequestOutcome::RolledBack),
            "no emitting entry can record the reserved rollback outcome"
        );
        assert_eq!(
            RequestOutcome::RolledBack.as_str(),
            "rolled_back",
            "the reserved rollback vocabulary entry keeps its stable machine code"
        );
        assert!(
            log.iter()
                .all(|event| ADMITTED_OPERATIONS.contains(&event.operation())),
            "every recorded event names an admitted operation"
        );
    }
}
