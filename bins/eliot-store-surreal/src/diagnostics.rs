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
