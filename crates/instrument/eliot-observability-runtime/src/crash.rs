//! Structured crash evidence and the shared process panic reporter (I16.2).
//!
//! Crash capture is deliberately separate from lifecycle and recovery. The
//! installed hook takes a bounded snapshot with nonblocking operations and
//! hands it to one bounded writer queue. It records identities, bounded
//! original owner data, and evidence handles only; panic payloads, stacks,
//! environment, argv, and dumps never enter this schema (I15.4).

use std::cell::{Cell, RefCell};
use std::fmt;
use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread;
use std::time::Duration;

use eliot_contracts::{EpochId, StateFence};
use serde::{Deserialize, Serialize};

use crate::config::{MAX_CRASH_REPORT_BYTES, RollingLogPolicy};
use crate::rolling_log::{RollingLogAppendError, RollingLogAppendOutcome, RollingLogHandle};

const MAX_IDENTITY_CHARS: usize = 128;
const MAX_EVIDENCE_HANDLES: usize = 8;
const MAX_EVIDENCE_REFERENCE_CHARS: usize = 256;
const MAX_OPERATION_OWNER_EVIDENCE_BYTES: usize = 64 * 1024;
const MAX_GAP_RECORD_BYTES: usize = 4096;
const PANIC_WRITER_QUEUE_CAPACITY: usize = 1;
const ROLLING_APPEND_ACK_TIMEOUT: Duration = Duration::from_secs(5);

thread_local! {
    /// Prevents a panic inside capture from recursively re-entering capture.
    static PANIC_CAPTURE_ACTIVE: Cell<bool> = const { Cell::new(false) };
    /// Original admitted operation context, installed only for the current
    /// synchronous dispatch or Future poll. The guard never lives across an
    /// await, so executor migration cannot leave a context on the wrong thread.
    static ACTIVE_OPERATION_CONTEXT: RefCell<Option<CrashOperationContext>> = const { RefCell::new(None) };
    /// Failed scope installation must not inherit a previous scope or the
    /// process snapshot as positive context for the operation being polled.
    static OPERATION_CONTEXT_INSTALL_FAILED: Cell<bool> = const { Cell::new(false) };
}

struct OperationContextInstallFailureGuard(bool);

impl OperationContextInstallFailureGuard {
    fn enter() -> Self {
        let previous = OPERATION_CONTEXT_INSTALL_FAILED
            .try_with(|failed| failed.replace(true))
            .unwrap_or(true);
        Self(previous)
    }
}

impl Drop for OperationContextInstallFailureGuard {
    fn drop(&mut self) {
        let previous = self.0;
        let _ = OPERATION_CONTEXT_INSTALL_FAILED.try_with(|failed| failed.set(previous));
    }
}

/// Task-local context for the exact operation currently being dispatched.
///
/// `Unavailable` means an admitted operation is active but its original owner
/// data could not be joined. A panic under that scope must emit a context gap;
/// it must never fall back to the process snapshot and appear operation-bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CrashOperationContext {
    /// The scoped caller observed that no admitted operation was active.
    NoActiveOperation,
    /// Full bounded owner snapshot joined to the current admitted operation.
    Current {
        /// Full bounded runtime identities from the same admitted owner.
        runtime_context: Box<CrashRuntimeContext>,
        /// Original owner operation identifier when the action supplies one.
        operation_id: Option<String>,
        /// Canonical redacted bytes projected from the original Kernel-owned
        /// `AuditLineage` and, when already sealed, `TraceManifest` owner data.
        original_owner_evidence: String,
    },
    /// The operation is admitted, but its exact context producer/readback is
    /// unavailable or inconsistent.
    Unavailable,
    /// The process context cannot be safely joined, but the original owner
    /// evidence remains available for the typed crash gap record.
    UnavailableWithOwnerEvidence(String),
}

/// Restores the previous operation scope when a synchronous dispatch returns
/// or unwinds. Nested scopes therefore preserve their caller's exact context.
pub struct CrashOperationContextGuard {
    previous: Option<CrashOperationContext>,
    _not_send: PhantomData<Rc<()>>,
}

impl Drop for CrashOperationContextGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        let _ = ACTIVE_OPERATION_CONTEXT.try_with(|current| {
            if let Ok(mut current) = current.try_borrow_mut() {
                *current = previous;
            }
        });
    }
}

/// Enters one validated operation context for a synchronous owner call.
///
/// The returned RAII guard is intentionally not `Send`; callers must not keep
/// it across an await. Use [`scope_crash_operation`] for a Future.
pub fn enter_crash_operation(
    context: CrashOperationContext,
) -> Result<CrashOperationContextGuard, CrashReportError> {
    if let CrashOperationContext::Current {
        runtime_context: snapshot,
        operation_id,
        original_owner_evidence,
    } = &context
    {
        snapshot.validate()?;
        if let Some(operation_id) = operation_id {
            validate_identity(operation_id, "operation_id")?;
        }
        validate_original_owner_evidence_for_context(
            original_owner_evidence,
            snapshot,
            operation_id.as_deref(),
        )?;
    }
    if let CrashOperationContext::UnavailableWithOwnerEvidence(evidence) = &context {
        validate_original_owner_evidence(evidence)?;
    }
    ACTIVE_OPERATION_CONTEXT
        .try_with(|current| {
            let mut current = current
                .try_borrow_mut()
                .map_err(|_| CrashReportError::InvalidMetadata("operation_context.borrowed"))?;
            let previous = current.replace(context);
            Ok(CrashOperationContextGuard {
                previous,
                _not_send: PhantomData,
            })
        })
        .map_err(|_| CrashReportError::InvalidMetadata("operation_context.unavailable"))?
}

/// Runs one synchronous owner call under its exact admitted-operation context.
pub fn with_crash_operation<R>(context: CrashOperationContext, operation: impl FnOnce() -> R) -> R {
    // Observability setup never changes whether an already admitted action
    // runs. If a Current context cannot be installed, retain an explicit gap
    // scope and still execute the operation.
    let fallback = match &context {
        CrashOperationContext::UnavailableWithOwnerEvidence(evidence) => {
            CrashOperationContext::UnavailableWithOwnerEvidence(evidence.clone())
        }
        _ => CrashOperationContext::Unavailable,
    };
    let guard = enter_crash_operation(context)
        .or_else(|_| enter_crash_operation(fallback))
        .ok();
    let _install_failure = guard
        .is_none()
        .then(OperationContextInstallFailureGuard::enter);
    operation()
}

/// Scopes a Future by installing the context for each `poll` only.
///
/// The current executor thread is always the thread polling the operation, so
/// this follows task migration and restores the previous nested context after
/// every `Pending`, `Ready`, or unwind without holding a thread-local guard
/// across an await.
pub async fn scope_crash_operation<F>(context: CrashOperationContext, future: F) -> F::Output
where
    F: Future,
{
    let context = match &context {
        CrashOperationContext::Current {
            runtime_context: snapshot,
            operation_id,
            original_owner_evidence,
        } if snapshot.validate().is_err()
            || operation_id.as_deref().is_some_and(|operation_id| {
                validate_identity(operation_id, "operation_id").is_err()
            })
            || validate_original_owner_evidence_for_context(
                original_owner_evidence,
                snapshot,
                operation_id.as_deref(),
            )
            .is_err() =>
        {
            if validate_original_owner_evidence(original_owner_evidence).is_ok() {
                CrashOperationContext::UnavailableWithOwnerEvidence(original_owner_evidence.clone())
            } else {
                CrashOperationContext::Unavailable
            }
        }
        CrashOperationContext::UnavailableWithOwnerEvidence(evidence)
            if validate_original_owner_evidence(evidence).is_err() =>
        {
            CrashOperationContext::Unavailable
        }
        _ => context,
    };
    let mut future = Box::pin(future);
    std::future::poll_fn(move |task_context| {
        // A failed scope install must remain an explicit active-operation
        // gap. Poll the work either way so observability cannot change its
        // delivery semantics, but never let a panic fall through to the
        // unrelated process snapshot.
        let fallback = match &context {
            CrashOperationContext::UnavailableWithOwnerEvidence(evidence) => {
                CrashOperationContext::UnavailableWithOwnerEvidence(evidence.clone())
            }
            _ => CrashOperationContext::Unavailable,
        };
        let guard = enter_crash_operation(context.clone())
            .or_else(|_| enter_crash_operation(fallback))
            .ok();
        let _install_failure = guard
            .is_none()
            .then(OperationContextInstallFailureGuard::enter);
        future.as_mut().poll(task_context)
    })
    .await
}

/// Typed crash-report failure.
#[derive(Debug)]
pub enum CrashReportError {
    /// A required metadata field was blank, malformed, or outside its bound.
    InvalidMetadata(&'static str),
    /// The report exceeded its byte bound and was not written.
    OverBound {
        /// Rendered size in bytes.
        bytes: u64,
    },
    /// The report could not be serialized or written.
    Io(io::Error),
}

impl fmt::Display for CrashReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMetadata(field) => {
                write!(formatter, "crash report metadata rejected: {field}")
            }
            Self::OverBound { bytes } => {
                write!(formatter, "crash report of {bytes} bytes exceeds its bound")
            }
            Self::Io(error) => write!(formatter, "crash report write failed: {error}"),
        }
    }
}

impl std::error::Error for CrashReportError {}

/// Symbol artifact identity admitted with the exact executable being run.
///
/// The binary composition root maps the immutable installer record into this
/// shared runtime type. The reporter never resolves a sibling PDB or infers an
/// artifact from `current_exe`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrashExecutableRole {
    /// The Host executable and its admitted symbol file.
    Host,
    /// The Kernel executable and its admitted symbol file.
    Kernel,
}

impl CrashExecutableRole {
    fn canonical_symbol_ref(self) -> &'static str {
        match self {
            Self::Host => "symbols/host/eliot-host.pdb",
            Self::Kernel => "symbols/kernel/eliot-kernel.pdb",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SymbolArtifact {
    /// Executable role whose exact admitted digest is bound to this symbol.
    pub role: CrashExecutableRole,
    /// Canonical bundle-relative reference, for example
    /// `symbols/kernel/eliot-kernel.pdb`.
    pub artifact_ref: String,
    /// SHA-256 of the retained symbol artifact.
    pub artifact_sha256: String,
    /// SHA-256 of the executable that this symbol artifact resolves.
    pub executable_sha256: String,
    /// Original release source commit fingerprint (40 lowercase hex digits).
    pub build_fingerprint: String,
    /// Profile admitted by the release manifest, normally `release`.
    pub build_profile: String,
    /// Installer-admitted candidate/package generation retaining the artifact.
    pub retention_id: String,
    /// Exact release receipt reference that admits the retained artifact.
    pub retention_reference: String,
}

impl SymbolArtifact {
    /// Validates the symbol binding and its relationship to the report build.
    pub fn validate(&self, build_profile: &str) -> Result<(), CrashReportError> {
        validate_digest(&self.artifact_sha256, "symbol_artifact.artifact_sha256")?;
        validate_digest(&self.executable_sha256, "symbol_artifact.executable_sha256")?;
        if !is_lower_hex(&self.build_fingerprint, 40) {
            return Err(CrashReportError::InvalidMetadata(
                "symbol_artifact.build_fingerprint",
            ));
        }
        validate_identity(&self.build_profile, "symbol_artifact.build_profile")?;
        if self.build_profile != build_profile {
            return Err(CrashReportError::InvalidMetadata(
                "symbol_artifact.build_profile_mismatch",
            ));
        }
        validate_identity(&self.retention_id, "symbol_artifact.retention_id")?;
        if !is_bundle_relative_ref(&self.retention_reference)
            || self.retention_reference != "SHA256SUMS.json"
        {
            return Err(CrashReportError::InvalidMetadata(
                "symbol_artifact.retention_reference",
            ));
        }
        if !is_bundle_relative_ref(&self.artifact_ref)
            || self.artifact_ref != self.role.canonical_symbol_ref()
        {
            return Err(CrashReportError::InvalidMetadata(
                "symbol_artifact.artifact_ref",
            ));
        }
        Ok(())
    }
}

/// Typed handle for already-redacted evidence associated with the crash.
///
/// References are opaque evidence-store identifiers, never paths or payloads.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedEvidenceHandle {
    /// Opaque, bounded evidence identifier.
    pub reference: String,
    /// SHA-256 digest of the referenced evidence.
    pub digest: String,
}

impl RedactedEvidenceHandle {
    /// Validates a bounded opaque handle and its digest.
    pub fn validate(&self) -> Result<(), CrashReportError> {
        if self.reference.len() > MAX_EVIDENCE_REFERENCE_CHARS
            || !(self.reference.starts_with("evidence:")
                || self.reference.starts_with("blob:")
                || self.reference.starts_with("receipt:"))
            || !self.reference.is_ascii()
            || !self
                .reference
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
            || self.reference.contains("..")
            || self.reference.contains('\\')
        {
            return Err(CrashReportError::InvalidMetadata(
                "runtime_context.evidence_handle.reference",
            ));
        }
        validate_digest(&self.digest, "runtime_context.evidence_handle.digest")
    }
}

/// Which original owner supplied a retained evidence head.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum CrashOwnerHeadKind {
    /// Kernel's existing chained durable audit owner.
    KernelAuditChain,
    /// Host's existing durable state journal, which is not an audit chain.
    HostStateJournal,
}

/// Hash algorithm already used by the original evidence owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrashDigestAlgorithm {
    /// Existing Kernel audit chain hash algorithm.
    Blake3,
    /// Existing Host state journal checksum algorithm.
    Sha256,
}

/// Exact sequenced evidence head captured from its original owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrashOwnerHead {
    /// Owner whose head this is; journal checksums never masquerade as audit.
    pub kind: CrashOwnerHeadKind,
    /// Algorithm used by the original owner, not recomputed by crash capture.
    pub algorithm: CrashDigestAlgorithm,
    /// Last committed owner sequence.
    pub sequence: u64,
    /// Original owner's exact digest at that sequence.
    pub digest: String,
}

/// Required identity field that was not available when the snapshot was made.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingCrashContextField {
    /// Module generation was not yet admitted.
    ModuleGeneration,
    /// Process generation was not yet admitted.
    ProcessGeneration,
    /// Authority epoch was not yet admitted.
    AuthorityEpoch,
    /// The exact State Fence was not yet admitted.
    StateFence,
    /// No sequenced audit head existed yet.
    AuditHead,
}

/// Bounded runtime identity captured from the owning Host/Kernel composition.
///
/// `StateFence` and `EpochId` remain their original contract types. Optional
/// trace and work-scope references are explicit `None` values when no active
/// scope exists; other absent required observations are listed in
/// `missing_fields`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrashRuntimeContext {
    /// Current module generation, if known.
    pub module_generation_ref: Option<String>,
    /// Current process generation, if known.
    pub process_generation_ref: Option<String>,
    /// Exact admitted authority epoch, if known.
    pub authority_epoch: Option<EpochId>,
    /// Exact admitted State Fence, if known.
    pub state_fence: Option<StateFence>,
    /// Active trace handle, if one is active.
    pub active_trace_ref: Option<String>,
    /// Active work-scope handle, if one is active.
    pub work_scope_ref: Option<String>,
    /// Current Kernel audit sequence and hash, if that owner exists.
    pub audit_head: Option<CrashOwnerHead>,
    /// Current Host journal sequence and checksum, kept distinct from audit.
    pub journal_head: Option<CrashOwnerHead>,
    /// True when the owner journal snapshot could not be refreshed without
    /// waiting; `journal_head` is then explicitly unavailable.
    pub journal_head_gap: bool,
    /// Bounded, already-redacted handles only.
    pub evidence_handles: Vec<RedactedEvidenceHandle>,
    /// Required observations absent from this snapshot.
    pub missing_fields: Vec<MissingCrashContextField>,
}

/// Original owner observations used to assemble one bounded context snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrashRuntimeContextObservations {
    /// Module generation supplied by its current authority owner.
    pub module_generation_ref: Option<String>,
    /// Process generation supplied by its current process-incarnation owner.
    pub process_generation_ref: Option<String>,
    /// Exact state fence supplied by the current authority owner.
    pub state_fence: Option<StateFence>,
    /// Active trace handle when an original trace owner supplies one.
    pub active_trace_ref: Option<String>,
    /// Active work-scope handle when an original scope owner supplies one.
    pub work_scope_ref: Option<String>,
    /// Exact audit head supplied by its durable owner.
    pub audit_head: Option<CrashOwnerHead>,
    /// Already-redacted handles supplied by their evidence owner.
    pub evidence_handles: Vec<RedactedEvidenceHandle>,
    /// Exact state-journal head supplied by its durable owner.
    pub journal_head: Option<CrashOwnerHead>,
}

impl CrashRuntimeContext {
    /// Makes an explicit pre-composition context with every required slot
    /// declared missing.
    #[must_use]
    pub fn unavailable() -> Self {
        Self {
            module_generation_ref: None,
            process_generation_ref: None,
            authority_epoch: None,
            state_fence: None,
            active_trace_ref: None,
            work_scope_ref: None,
            audit_head: None,
            journal_head: None,
            journal_head_gap: false,
            evidence_handles: Vec::new(),
            missing_fields: vec![
                MissingCrashContextField::ModuleGeneration,
                MissingCrashContextField::ProcessGeneration,
                MissingCrashContextField::AuthorityEpoch,
                MissingCrashContextField::StateFence,
                MissingCrashContextField::AuditHead,
            ],
        }
    }

    /// Builds a snapshot from owner-supplied facts and explicitly declares
    /// every absent required observation.
    #[must_use]
    pub fn from_observations(observations: CrashRuntimeContextObservations) -> Self {
        let CrashRuntimeContextObservations {
            module_generation_ref,
            process_generation_ref,
            state_fence,
            active_trace_ref,
            work_scope_ref,
            audit_head,
            evidence_handles,
            journal_head,
        } = observations;
        let authority_epoch = state_fence
            .as_ref()
            .map(|fence| fence.authority_epoch.clone());
        let mut missing_fields = Vec::new();
        if module_generation_ref.is_none() {
            missing_fields.push(MissingCrashContextField::ModuleGeneration);
        }
        if process_generation_ref.is_none() {
            missing_fields.push(MissingCrashContextField::ProcessGeneration);
        }
        if authority_epoch.is_none() {
            missing_fields.push(MissingCrashContextField::AuthorityEpoch);
        }
        if state_fence.is_none() {
            missing_fields.push(MissingCrashContextField::StateFence);
        }
        if audit_head.is_none() {
            missing_fields.push(MissingCrashContextField::AuditHead);
        }
        Self {
            module_generation_ref,
            process_generation_ref,
            authority_epoch,
            state_fence,
            active_trace_ref,
            work_scope_ref,
            audit_head,
            journal_head,
            journal_head_gap: false,
            evidence_handles,
            missing_fields,
        }
    }

    /// Rejects over-bound or internally inconsistent runtime snapshots.
    pub fn validate(&self) -> Result<(), CrashReportError> {
        self.validate_identity_slots()?;
        self.validate_authority_fence()?;
        self.validate_owner_heads()?;
        self.validate_evidence_handles()?;
        self.validate_missing_fields()
    }

    fn validate_identity_slots(&self) -> Result<(), CrashReportError> {
        for (value, field) in [
            (&self.module_generation_ref, "module_generation_ref"),
            (&self.process_generation_ref, "process_generation_ref"),
            (&self.active_trace_ref, "active_trace_ref"),
            (&self.work_scope_ref, "work_scope_ref"),
        ] {
            if let Some(value) = value {
                validate_identity(value, field)?;
            }
        }
        Ok(())
    }

    fn validate_authority_fence(&self) -> Result<(), CrashReportError> {
        if let Some(fence) = &self.state_fence {
            fence
                .validate()
                .map_err(|_| CrashReportError::InvalidMetadata("runtime_context.state_fence"))?;
        }
        if let (Some(epoch), Some(fence)) = (&self.authority_epoch, &self.state_fence) {
            if epoch != &fence.authority_epoch {
                return Err(CrashReportError::InvalidMetadata(
                    "runtime_context.authority_epoch_mismatch",
                ));
            }
        } else if self.authority_epoch.is_some() != self.state_fence.is_some() {
            return Err(CrashReportError::InvalidMetadata(
                "runtime_context.authority_fence_pair",
            ));
        }
        Ok(())
    }

    fn validate_owner_heads(&self) -> Result<(), CrashReportError> {
        if self.journal_head_gap && self.journal_head.is_some() {
            return Err(CrashReportError::InvalidMetadata(
                "runtime_context.journal_head_gap",
            ));
        }
        for (head, expected_kind, expected_algorithm, field) in [
            (
                &self.audit_head,
                CrashOwnerHeadKind::KernelAuditChain,
                CrashDigestAlgorithm::Blake3,
                "runtime_context.audit_head",
            ),
            (
                &self.journal_head,
                CrashOwnerHeadKind::HostStateJournal,
                CrashDigestAlgorithm::Sha256,
                "runtime_context.journal_head",
            ),
        ] {
            let Some(head) = head else {
                continue;
            };
            if head.sequence == 0 {
                return Err(CrashReportError::InvalidMetadata(
                    "runtime_context.owner_head.sequence",
                ));
            }
            if head.kind != expected_kind || head.algorithm != expected_algorithm {
                return Err(CrashReportError::InvalidMetadata(field));
            }
            validate_digest(&head.digest, field)?;
        }
        Ok(())
    }

    fn validate_evidence_handles(&self) -> Result<(), CrashReportError> {
        if self.evidence_handles.len() > MAX_EVIDENCE_HANDLES {
            return Err(CrashReportError::InvalidMetadata(
                "runtime_context.evidence_handles",
            ));
        }
        for handle in &self.evidence_handles {
            handle.validate()?;
        }
        Ok(())
    }

    fn validate_missing_fields(&self) -> Result<(), CrashReportError> {
        for field in [
            (
                self.module_generation_ref.is_some(),
                MissingCrashContextField::ModuleGeneration,
            ),
            (
                self.process_generation_ref.is_some(),
                MissingCrashContextField::ProcessGeneration,
            ),
            (
                self.authority_epoch.is_some(),
                MissingCrashContextField::AuthorityEpoch,
            ),
            (
                self.state_fence.is_some(),
                MissingCrashContextField::StateFence,
            ),
            (
                self.audit_head.is_some(),
                MissingCrashContextField::AuditHead,
            ),
        ] {
            if field.0 == self.missing_fields.contains(&field.1) {
                return Err(CrashReportError::InvalidMetadata(
                    "runtime_context.missing_fields",
                ));
            }
        }
        if self.missing_fields.len() > 5
            || self
                .missing_fields
                .iter()
                .enumerate()
                .any(|(index, field)| self.missing_fields[..index].contains(field))
        {
            return Err(CrashReportError::InvalidMetadata(
                "runtime_context.missing_fields",
            ));
        }
        Ok(())
    }
}

/// Build and runtime context carried by every structured crash report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrashReportMetadata {
    /// Crashing process name, e.g. `eliot-kernel`.
    pub process: String,
    /// Package version of the crashing build.
    pub package_version: String,
    /// Build channel or profile revision that produced the executable.
    pub build_profile: String,
    /// Installation profile the process was serving.
    pub runtime_profile: String,
    /// Process identifier that crashed.
    pub process_id: u32,
    /// Panic class observed by the installed reporter.
    pub fault_class: String,
    /// Bounded static fault site; panic payload/location text is excluded.
    pub fault_site: String,
    /// Original admitted executable and symbol artifact identities.
    pub symbol_artifact: SymbolArtifact,
    /// Complete bounded runtime identity snapshot.
    pub runtime_context: CrashRuntimeContext,
    /// Original operation identifier when the admitted action supplies one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    /// Exact redacted original owner data for an operation-scoped capture.
    /// This field is included in the report digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_owner_evidence: Option<String>,
    /// Whether panic capture observed a scoped operation or an explicit
    /// no-active-operation state. `None` is retained for older reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_scope_status: Option<String>,
}

impl CrashReportMetadata {
    /// Validates bounded identities, exact State Fence binding, and symbols.
    pub fn validate(&self) -> Result<(), CrashReportError> {
        for (value, field) in [
            (&self.process, "process"),
            (&self.package_version, "package_version"),
            (&self.build_profile, "build_profile"),
            (&self.runtime_profile, "runtime_profile"),
            (&self.fault_class, "fault_class"),
            (&self.fault_site, "fault_site"),
        ] {
            validate_identity(value, field)?;
        }
        if self.process_id == 0 {
            return Err(CrashReportError::InvalidMetadata("process_id"));
        }
        if self.fault_class != "panic" || self.fault_site != "panic_hook" {
            return Err(CrashReportError::InvalidMetadata("fault_class_or_site"));
        }
        self.symbol_artifact.validate(&self.build_profile)?;
        self.runtime_context.validate()?;
        match self.operation_scope_status.as_deref() {
            Some("active_operation") => {
                let evidence = self.operation_owner_evidence.as_deref().ok_or(
                    CrashReportError::InvalidMetadata(
                        "operation_owner_evidence.active_operation_required",
                    ),
                )?;
                validate_original_owner_evidence_for_context(
                    evidence,
                    &self.runtime_context,
                    self.operation_id.as_deref(),
                )?;
            }
            Some("no_active_operation") => {
                if self.operation_owner_evidence.is_some() || self.operation_id.is_some() {
                    return Err(CrashReportError::InvalidMetadata(
                        "operation_owner_evidence.no_active_operation",
                    ));
                }
            }
            Some(_) => {
                return Err(CrashReportError::InvalidMetadata("operation_scope_status"));
            }
            None => {
                if let Some(evidence) = &self.operation_owner_evidence {
                    validate_original_owner_evidence_for_context(
                        evidence,
                        &self.runtime_context,
                        self.operation_id.as_deref(),
                    )?;
                }
            }
        }
        Ok(())
    }
}

/// One structured crash report: build identity plus a content digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrashReport {
    /// Stable report identity.
    pub report_id: String,
    /// Build, symbol, and runtime-generation metadata.
    pub metadata: CrashReportMetadata,
    /// Content digest over the full serialized metadata, including runtime
    /// context, executable identity, and the exact symbol artifact binding.
    pub digest: String,
}

impl CrashReport {
    /// Builds a report and derives its content digest with the existing digest
    /// owner used by this contract.
    pub fn new(report_id: &str, metadata: CrashReportMetadata) -> Result<Self, CrashReportError> {
        validate_identity(report_id, "report_id")?;
        metadata.validate()?;
        let bytes = serde_json::to_vec(&metadata)
            .map_err(|error| CrashReportError::Io(io::Error::other(error)))?;
        Ok(Self {
            report_id: report_id.to_owned(),
            digest: eliot_contracts::sha256_hex(&bytes),
            metadata,
        })
    }

    /// Renders the report as one bounded JSON document.
    pub fn to_bounded_json(&self) -> Result<Vec<u8>, CrashReportError> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| CrashReportError::Io(io::Error::other(error)))?;
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if size > MAX_CRASH_REPORT_BYTES {
            return Err(CrashReportError::OverBound { bytes: size });
        }
        Ok(bytes)
    }

    fn to_compact_bounded_json(&self) -> Result<String, CrashReportError> {
        let text = serde_json::to_string(self)
            .map_err(|error| CrashReportError::Io(io::Error::other(error)))?;
        let size = u64::try_from(text.len()).unwrap_or(u64::MAX);
        if size > MAX_CRASH_REPORT_BYTES {
            return Err(CrashReportError::OverBound { bytes: size });
        }
        Ok(text)
    }
}

/// One honest outcome of the best-effort crash evidence path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrashTelemetryOutcome {
    /// The reporter is installed; no panic has been captured yet.
    Installed,
    /// A bounded report was accepted by the writer queue.
    ReportQueued,
    /// The writer persisted a structured report.
    ReportWritten,
    /// A gap record was accepted by the writer queue.
    GapQueued,
    /// The writer persisted an explicit telemetry-gap record.
    GapWritten,
    /// A gap could not be persisted; its atomic status remains queryable.
    GapUnpersisted,
    /// The bounded queue was full and reported a telemetry gap.
    QueueSaturated,
    /// The background writer could not start or is no longer available.
    WriterUnavailable,
}

impl CrashTelemetryOutcome {
    fn as_u8(self) -> u8 {
        match self {
            Self::Installed => 0,
            Self::ReportQueued => 1,
            Self::ReportWritten => 2,
            Self::GapQueued => 3,
            Self::GapWritten => 4,
            Self::GapUnpersisted => 5,
            Self::QueueSaturated => 6,
            Self::WriterUnavailable => 7,
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::ReportQueued,
            2 => Self::ReportWritten,
            3 => Self::GapQueued,
            4 => Self::GapWritten,
            5 => Self::GapUnpersisted,
            6 => Self::QueueSaturated,
            7 => Self::WriterUnavailable,
            _ => Self::Installed,
        }
    }
}

/// Explicit reason a panic report could not be produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrashTelemetryGapReason {
    /// No immutable installer-admitted symbol binding was supplied.
    SymbolBindingUnavailable,
    /// The owner has not yet supplied the admitted runtime profile.
    RuntimeProfileUnavailable,
    /// The context snapshot was contended or poisoned at panic time.
    RuntimeContextUnavailable,
    /// An admitted operation was active, but its exact owner context was
    /// absent, inconsistent, or unavailable for this panic snapshot.
    ActiveOperationContextUnavailable,
    /// The bounded writer queue was full.
    QueueSaturated,
    /// The writer thread could not be started or has exited.
    WriterUnavailable,
    /// No composition-supplied bounded incident-retention policy was available.
    RetentionPolicyUnavailable,
    /// The admitted rolling retention policy refused or could not rotate a report.
    RetentionFailure,
    /// The evidence report failed metadata validation or exceeded its bound.
    ReportRejected,
    /// The evidence report could not be serialized or written.
    ReportWriteFailed,
    /// The requested process fault is outside Rust panic-hook coverage.
    UnsupportedNonPanicFault,
}

#[derive(Serialize)]
struct CrashTelemetryGapRecord<'a> {
    record_type: &'static str,
    report_id: &'a str,
    process: &'a str,
    reason: CrashTelemetryGapReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation_owner_evidence: Option<&'a str>,
}

enum CrashCapture {
    Report(Box<CrashReport>),
    Gap {
        report_id: String,
        process: String,
        reason: CrashTelemetryGapReason,
        operation_owner_evidence: Option<String>,
    },
}

struct CrashReporterState {
    process: String,
    package_version: String,
    runtime_profile: RwLock<Option<String>>,
    symbol_artifact: RwLock<Option<SymbolArtifact>>,
    report_sink: RwLock<Option<CrashReportSink>>,
    context: RwLock<CrashRuntimeContext>,
    context_gap: AtomicBool,
    journal_head_gap: AtomicBool,
    sender: SyncSender<CrashCapture>,
    overflow_gap: AtomicBool,
    outcome: AtomicU8,
    sequence: AtomicU64,
}

struct CrashReportSink {
    policy: RollingLogPolicy,
    handle: RollingLogHandle,
}

impl CrashReportSink {
    fn start(policy: RollingLogPolicy) -> Result<Self, CrashReportError> {
        if policy.directory.file_name().and_then(|name| name.to_str()) != Some("crash-reports")
            || policy.file_stem != "crash-evidence"
        {
            return Err(CrashReportError::InvalidMetadata(
                "retention_policy.incident_scope",
            ));
        }
        let handle = RollingLogHandle::start(&policy)
            .map_err(|error| CrashReportError::Io(io::Error::other(error)))?;
        Ok(Self { policy, handle })
    }
}

/// Cloneable handle for publishing owner-supplied runtime context and reading
/// the best-effort capture outcome.
#[derive(Clone)]
pub struct CrashReporterHandle {
    state: Arc<CrashReporterState>,
}

impl CrashReporterHandle {
    /// Marks the live runtime snapshot unavailable after a producer-side
    /// attachment or publication failure. A later capture records a typed gap
    /// until a complete context update succeeds.
    pub fn invalidate_runtime_context(&self) {
        self.state.context_gap.store(true, Ordering::Release);
    }

    /// Replaces the context snapshot from the owning composition boundary.
    ///
    /// This is called on the normal startup/update path. The panic hook uses
    /// only `try_read`, so it never waits for this lock.
    pub fn update_context(&self, context: CrashRuntimeContext) -> Result<(), CrashReportError> {
        self.state.context_gap.store(true, Ordering::Release);
        context.validate()?;
        let mut current = self
            .state
            .context
            .write()
            .map_err(|_| CrashReportError::InvalidMetadata("runtime_context.poisoned"))?;
        *current = context;
        self.state.context_gap.store(false, Ordering::Release);
        self.state.journal_head_gap.store(false, Ordering::Release);
        Ok(())
    }

    /// Replaces only the exact Host journal head without waiting for the
    /// context lock. If the owner cannot publish now, the next panic snapshot
    /// clears the old head and marks an explicit context gap.
    pub fn update_journal_head(&self, journal_head: Option<CrashOwnerHead>) {
        self.state.journal_head_gap.store(true, Ordering::Release);
        let Some(journal_head) = journal_head else {
            if let Ok(mut context) = self.state.context.try_write() {
                context.journal_head = None;
                context.journal_head_gap = true;
            }
            return;
        };
        let valid = journal_head.kind == CrashOwnerHeadKind::HostStateJournal
            && journal_head.algorithm == CrashDigestAlgorithm::Sha256
            && journal_head.sequence > 0
            && validate_digest(&journal_head.digest, "runtime_context.journal_head").is_ok();
        if !valid {
            return;
        }
        if let Ok(mut context) = self.state.context.try_write() {
            context.journal_head = Some(journal_head);
            context.journal_head_gap = false;
            self.state.journal_head_gap.store(false, Ordering::Release);
        }
    }

    /// Adds the immutable symbol binding after the owner admits the launch
    /// descriptor. A different binding is rejected for the process lifetime.
    pub fn update_symbol_artifact(
        &self,
        symbol_artifact: SymbolArtifact,
    ) -> Result<(), CrashReportError> {
        symbol_artifact.validate(&symbol_artifact.build_profile)?;
        let mut current = self
            .state
            .symbol_artifact
            .write()
            .map_err(|_| CrashReportError::InvalidMetadata("symbol_artifact.poisoned"))?;
        match current.as_ref() {
            Some(existing) if existing != &symbol_artifact => Err(
                CrashReportError::InvalidMetadata("symbol_artifact.binding_conflict"),
            ),
            Some(_) => Ok(()),
            None => {
                *current = Some(symbol_artifact);
                Ok(())
            }
        }
    }

    /// Adds the exact installation profile selected by the existing owner.
    pub fn update_runtime_profile(&self, runtime_profile: &str) -> Result<(), CrashReportError> {
        validate_identity(runtime_profile, "runtime_profile")?;
        let mut current = self
            .state
            .runtime_profile
            .write()
            .map_err(|_| CrashReportError::InvalidMetadata("runtime_profile.poisoned"))?;
        match current.as_deref() {
            Some(existing) if existing != runtime_profile => Err(
                CrashReportError::InvalidMetadata("runtime_profile.binding_conflict"),
            ),
            Some(_) => Ok(()),
            None => {
                *current = Some(runtime_profile.to_owned());
                Ok(())
            }
        }
    }

    /// Publishes the existing bounded rolling policy selected by the owning
    /// composition, with its directory and stem scoped to crash evidence.
    pub fn update_retention_policy(
        &self,
        policy: RollingLogPolicy,
    ) -> Result<(), CrashReportError> {
        policy
            .validate()
            .map_err(|_| CrashReportError::InvalidMetadata("retention_policy"))?;
        let mut current = self
            .state
            .report_sink
            .write()
            .map_err(|_| CrashReportError::InvalidMetadata("retention_policy.poisoned"))?;
        match current.as_ref() {
            Some(existing) if existing.policy != policy => Err(CrashReportError::InvalidMetadata(
                "retention_policy.binding_conflict",
            )),
            Some(_) => Ok(()),
            None => {
                *current = Some(CrashReportSink::start(policy)?);
                Ok(())
            }
        }
    }

    /// Returns the latest explicit report or telemetry-gap outcome.
    #[must_use]
    pub fn outcome(&self) -> CrashTelemetryOutcome {
        CrashTelemetryOutcome::from_u8(self.state.outcome.load(Ordering::Acquire))
    }

    /// Records that a non-panic fault mechanism is unsupported by this
    /// reporter. The returned status is explicit even when the process path
    /// has no durable telemetry sink available.
    pub fn unsupported_non_panic_fault(&self) -> CrashTelemetryOutcome {
        let report_id = self.state.next_report_id();
        self.state
            .enqueue_gap(report_id, CrashTelemetryGapReason::UnsupportedNonPanicFault)
    }
}

/// Inputs required to install the shared reporter from a composition root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrashReporterConfig {
    /// Stable process package name.
    pub process: String,
    /// Compiled package version.
    pub package_version: String,
    /// Runtime installation profile selected by the existing owner.
    pub runtime_profile: Option<String>,
    /// Original immutable symbol binding, or `None` for a visible gap.
    pub symbol_artifact: Option<SymbolArtifact>,
    /// Existing finite rolling retention bounds selected by the process
    /// composition and explicitly scoped to security incident evidence under
    /// its dedicated `crash-reports` directory.
    pub retention_policy: Option<RollingLogPolicy>,
    /// Initial context; the owner should refresh it as exact admission state
    /// becomes available.
    pub initial_context: CrashRuntimeContext,
}

/// Installs one shared process panic reporter.
///
/// Repeat installation with the same configuration is idempotent. A later
/// call with different process/build inputs is refused rather than replacing
/// the original hook. The installed hook chains the previous hook after its
/// bounded, nonblocking capture attempt.
pub fn install_crash_reporter(
    config: CrashReporterConfig,
) -> Result<CrashReporterHandle, CrashReportError> {
    validate_identity(&config.process, "process")?;
    if config.process.len() > 64 {
        return Err(CrashReportError::InvalidMetadata("process"));
    }
    validate_identity(&config.package_version, "package_version")?;
    if let Some(runtime_profile) = &config.runtime_profile {
        validate_identity(runtime_profile, "runtime_profile")?;
    }
    config.initial_context.validate()?;
    if let Some(symbol) = &config.symbol_artifact {
        validate_identity(&symbol.build_profile, "symbol_artifact.build_profile")?;
        symbol.validate(&symbol.build_profile)?;
    }

    let installation_lock = REPORTER_INSTALL_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = installation_lock
        .lock()
        .map_err(|_| CrashReportError::InvalidMetadata("reporter_install_lock"))?;
    if let Some(existing) = REPORTER.get() {
        if existing.process != config.process || existing.package_version != config.package_version
        {
            return Err(CrashReportError::InvalidMetadata(
                "reporter_installation_conflict",
            ));
        }
        let handle = CrashReporterHandle {
            state: Arc::clone(existing),
        };
        if let Some(runtime_profile) = config.runtime_profile.as_deref() {
            handle.update_runtime_profile(runtime_profile)?;
        }
        if let Some(symbol_artifact) = config.symbol_artifact {
            handle.update_symbol_artifact(symbol_artifact)?;
        }
        if let Some(retention_policy) = config.retention_policy {
            handle.update_retention_policy(retention_policy)?;
        }
        return Ok(handle);
    }

    let (sender, receiver) = mpsc::sync_channel(PANIC_WRITER_QUEUE_CAPACITY);
    let report_sink = config
        .retention_policy
        .map(CrashReportSink::start)
        .transpose()?;
    let state = Arc::new(CrashReporterState {
        process: config.process,
        package_version: config.package_version,
        runtime_profile: RwLock::new(config.runtime_profile),
        symbol_artifact: RwLock::new(config.symbol_artifact),
        report_sink: RwLock::new(report_sink),
        context: RwLock::new(config.initial_context),
        context_gap: AtomicBool::new(false),
        journal_head_gap: AtomicBool::new(false),
        sender,
        overflow_gap: AtomicBool::new(false),
        outcome: AtomicU8::new(CrashTelemetryOutcome::Installed.as_u8()),
        sequence: AtomicU64::new(0),
    });
    let worker_state = Arc::clone(&state);
    thread::Builder::new()
        .name("eliot-crash-evidence".to_owned())
        .spawn(move || crash_writer_loop(&receiver, &worker_state))
        .map_err(|_| CrashReportError::InvalidMetadata("crash_writer_unavailable"))?;

    let prior_hook = std::panic::take_hook();
    let hook_state = Arc::clone(&state);
    std::panic::set_hook(Box::new(move |info| {
        let capture_is_nested = PANIC_CAPTURE_ACTIVE
            .try_with(|active| active.replace(true))
            .unwrap_or(true);
        if !capture_is_nested {
            let capture_state = Arc::clone(&hook_state);
            let capture_result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    capture_state.capture_panic();
                }));
            let _ = PANIC_CAPTURE_ACTIVE.try_with(|active| active.set(false));
            if capture_result.is_err() {
                hook_state.overflow_gap.store(true, Ordering::Release);
                hook_state.outcome.store(
                    CrashTelemetryOutcome::GapUnpersisted.as_u8(),
                    Ordering::Release,
                );
            }
        }
        prior_hook(info);
    }));
    let _ = REPORTER.set(Arc::clone(&state));
    Ok(CrashReporterHandle { state })
}

static REPORTER: OnceLock<Arc<CrashReporterState>> = OnceLock::new();
static REPORTER_INSTALL_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

struct PanicOperationSnapshot {
    context: CrashRuntimeContext,
    operation_id: Option<String>,
    operation_owner_evidence: Option<String>,
    operation_scope_status: Option<String>,
}

impl CrashReporterState {
    fn next_report_id(&self) -> String {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        format!("{}-{}-{sequence}", self.process, std::process::id())
    }

    fn panic_artifact_and_profile(&self, report_id: &str) -> Option<(SymbolArtifact, String)> {
        let symbol_artifact = if let Ok(symbol_artifact) = self.symbol_artifact.try_read() {
            symbol_artifact.clone()
        } else {
            self.enqueue_gap(
                report_id.to_owned(),
                CrashTelemetryGapReason::SymbolBindingUnavailable,
            );
            return None;
        };
        let Some(symbol_artifact) = symbol_artifact else {
            self.enqueue_gap(
                report_id.to_owned(),
                CrashTelemetryGapReason::SymbolBindingUnavailable,
            );
            return None;
        };
        let runtime_profile = if let Ok(runtime_profile) = self.runtime_profile.try_read() {
            runtime_profile.clone()
        } else {
            self.enqueue_gap(
                report_id.to_owned(),
                CrashTelemetryGapReason::RuntimeProfileUnavailable,
            );
            return None;
        };
        let Some(runtime_profile) = runtime_profile else {
            self.enqueue_gap(
                report_id.to_owned(),
                CrashTelemetryGapReason::RuntimeProfileUnavailable,
            );
            return None;
        };
        Some((symbol_artifact, runtime_profile))
    }

    fn panic_operation_context(&self, report_id: &str) -> Option<PanicOperationSnapshot> {
        if OPERATION_CONTEXT_INSTALL_FAILED
            .try_with(Cell::get)
            .unwrap_or(true)
        {
            self.enqueue_gap(
                report_id.to_owned(),
                CrashTelemetryGapReason::ActiveOperationContextUnavailable,
            );
            return None;
        }
        let operation_context = match ACTIVE_OPERATION_CONTEXT.try_with(|current| {
            current
                .try_borrow()
                .map_or(Some(CrashOperationContext::Unavailable), |value| {
                    value.clone()
                })
        }) {
            Ok(context) => context,
            Err(_) => Some(CrashOperationContext::Unavailable),
        };
        let (context, operation_id, operation_owner_evidence, operation_scope_status) =
            match operation_context {
                Some(CrashOperationContext::Unavailable) => {
                    self.enqueue_gap(
                        report_id.to_owned(),
                        CrashTelemetryGapReason::ActiveOperationContextUnavailable,
                    );
                    return None;
                }
                Some(CrashOperationContext::UnavailableWithOwnerEvidence(evidence)) => {
                    self.enqueue_gap_with_owner_evidence(
                        report_id.to_owned(),
                        CrashTelemetryGapReason::ActiveOperationContextUnavailable,
                        evidence,
                    );
                    return None;
                }
                Some(CrashOperationContext::Current {
                    runtime_context,
                    operation_id,
                    original_owner_evidence,
                }) => (
                    *runtime_context,
                    operation_id,
                    Some(original_owner_evidence),
                    Some("active_operation".to_owned()),
                ),
                None | Some(CrashOperationContext::NoActiveOperation) => {
                    if self.context_gap.load(Ordering::Acquire) {
                        self.enqueue_gap(
                            report_id.to_owned(),
                            CrashTelemetryGapReason::RuntimeContextUnavailable,
                        );
                        return None;
                    }
                    let context = if let Ok(context) = self.context.try_read() {
                        context.clone()
                    } else {
                        self.enqueue_gap(
                            report_id.to_owned(),
                            CrashTelemetryGapReason::RuntimeContextUnavailable,
                        );
                        return None;
                    };
                    if self.context_gap.load(Ordering::Acquire) {
                        self.enqueue_gap(
                            report_id.to_owned(),
                            CrashTelemetryGapReason::RuntimeContextUnavailable,
                        );
                        return None;
                    }
                    (context, None, None, Some("no_active_operation".to_owned()))
                }
            };
        Some(PanicOperationSnapshot {
            context,
            operation_id,
            operation_owner_evidence,
            operation_scope_status,
        })
    }

    fn capture_panic(&self) {
        let report_id = self.next_report_id();
        let Some((symbol_artifact, runtime_profile)) = self.panic_artifact_and_profile(&report_id)
        else {
            return;
        };
        let Some(snapshot) = self.panic_operation_context(&report_id) else {
            return;
        };
        let mut context = snapshot.context;
        if self.journal_head_gap.load(Ordering::Acquire) {
            context.journal_head = None;
            context.journal_head_gap = true;
        }
        let metadata = CrashReportMetadata {
            process: self.process.clone(),
            package_version: self.package_version.clone(),
            build_profile: symbol_artifact.build_profile.clone(),
            runtime_profile,
            process_id: std::process::id(),
            fault_class: "panic".to_owned(),
            fault_site: "panic_hook".to_owned(),
            symbol_artifact,
            runtime_context: context,
            operation_id: snapshot.operation_id,
            operation_owner_evidence: snapshot.operation_owner_evidence,
            operation_scope_status: snapshot.operation_scope_status,
        };
        let capture = match CrashReport::new(&report_id, metadata) {
            Ok(report) => CrashCapture::Report(Box::new(report)),
            Err(error) => CrashCapture::Gap {
                report_id,
                process: self.process.clone(),
                reason: report_error_reason(&error),
                operation_owner_evidence: None,
            },
        };
        self.enqueue(capture);
    }

    fn enqueue_gap(
        &self,
        report_id: String,
        reason: CrashTelemetryGapReason,
    ) -> CrashTelemetryOutcome {
        self.enqueue(CrashCapture::Gap {
            report_id,
            process: self.process.clone(),
            reason,
            operation_owner_evidence: None,
        })
    }

    fn enqueue_gap_with_owner_evidence(
        &self,
        report_id: String,
        reason: CrashTelemetryGapReason,
        operation_owner_evidence: String,
    ) -> CrashTelemetryOutcome {
        self.enqueue(CrashCapture::Gap {
            report_id,
            process: self.process.clone(),
            reason,
            operation_owner_evidence: Some(operation_owner_evidence),
        })
    }

    fn enqueue(&self, capture: CrashCapture) -> CrashTelemetryOutcome {
        let is_gap = matches!(&capture, CrashCapture::Gap { .. });
        match self.sender.try_send(capture) {
            Ok(()) => {
                let outcome = if is_gap {
                    CrashTelemetryOutcome::GapQueued
                } else {
                    CrashTelemetryOutcome::ReportQueued
                };
                self.outcome.store(outcome.as_u8(), Ordering::Release);
                outcome
            }
            Err(TrySendError::Full(_)) => {
                self.overflow_gap.store(true, Ordering::Release);
                self.outcome.store(
                    CrashTelemetryOutcome::QueueSaturated.as_u8(),
                    Ordering::Release,
                );
                CrashTelemetryOutcome::QueueSaturated
            }
            Err(TrySendError::Disconnected(_)) => {
                self.outcome.store(
                    CrashTelemetryOutcome::WriterUnavailable.as_u8(),
                    Ordering::Release,
                );
                CrashTelemetryOutcome::WriterUnavailable
            }
        }
    }
}

fn crash_writer_loop(receiver: &mpsc::Receiver<CrashCapture>, state: &CrashReporterState) {
    while let Ok(capture) = receiver.recv() {
        match capture {
            CrashCapture::Report(report) => {
                let append_result = match report.to_compact_bounded_json() {
                    Ok(line) => state.append_record(&line),
                    Err(error) => Err(report_error_reason(&error)),
                };
                match append_result {
                    Ok(()) => state.outcome.store(
                        CrashTelemetryOutcome::ReportWritten.as_u8(),
                        Ordering::Release,
                    ),
                    Err(reason) => state.write_gap(&report.report_id, reason),
                }
            }
            CrashCapture::Gap {
                report_id,
                process,
                reason,
                operation_owner_evidence,
            } => state.write_gap_for(
                &report_id,
                &process,
                reason,
                operation_owner_evidence.as_deref(),
            ),
        }
        if state.overflow_gap.swap(false, Ordering::AcqRel) {
            let report_id = state.next_report_id();
            state.write_gap_for(
                &report_id,
                &state.process,
                CrashTelemetryGapReason::QueueSaturated,
                None,
            );
        }
    }
}

fn report_error_reason(error: &CrashReportError) -> CrashTelemetryGapReason {
    match error {
        CrashReportError::InvalidMetadata(_) | CrashReportError::OverBound { .. } => {
            CrashTelemetryGapReason::ReportRejected
        }
        CrashReportError::Io(_) => CrashTelemetryGapReason::ReportWriteFailed,
    }
}

fn validate_original_owner_evidence(value: &str) -> Result<(), CrashReportError> {
    if value.is_empty() || value.len() > MAX_OPERATION_OWNER_EVIDENCE_BYTES {
        return Err(CrashReportError::InvalidMetadata(
            "operation_owner_evidence.bound",
        ));
    }
    serde_json::from_str::<serde_json::Value>(value)
        .map(|_| ())
        .map_err(|_| CrashReportError::InvalidMetadata("operation_owner_evidence.json"))
}

fn validate_original_owner_evidence_for_context(
    value: &str,
    runtime_context: &CrashRuntimeContext,
    expected_operation_id: Option<&str>,
) -> Result<(), CrashReportError> {
    validate_original_owner_evidence(value)?;
    let owner: serde_json::Value = serde_json::from_str(value)
        .map_err(|_| CrashReportError::InvalidMetadata("operation_owner_evidence.json"))?;
    let lineage = owner
        .get("lineage")
        .and_then(serde_json::Value::as_object)
        .ok_or(CrashReportError::InvalidMetadata(
            "operation_owner_evidence.lineage",
        ))?;
    let trace_id = original_lineage_string(lineage, "trace_id")?;
    let operation_id = original_lineage_optional_string(lineage, "operation_id")?;
    let work_scope = original_lineage_optional_string(lineage, "work_scope")?;
    let module_generation = original_lineage_optional_string(lineage, "module_generation")?;
    let authority_epoch = original_lineage_string(lineage, "authority_epoch")?;
    let state_fence: StateFence =
        serde_json::from_value(lineage.get("state_fence").cloned().ok_or(
            CrashReportError::InvalidMetadata("operation_owner_evidence.state_fence"),
        )?)
        .map_err(|_| CrashReportError::InvalidMetadata("operation_owner_evidence.state_fence"))?;
    let request_identity =
        lineage
            .get("request_identity")
            .cloned()
            .ok_or(CrashReportError::InvalidMetadata(
                "operation_owner_evidence.request_identity",
            ))?;
    let request = request_identity
        .get("request")
        .and_then(serde_json::Value::as_object)
        .ok_or(CrashReportError::InvalidMetadata(
            "operation_owner_evidence.request_identity",
        ))?;
    let metadata = request
        .get("metadata")
        .and_then(serde_json::Value::as_object)
        .ok_or(CrashReportError::InvalidMetadata(
            "operation_owner_evidence.request_identity",
        ))?;
    let identity_request_id = metadata
        .get("request_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(CrashReportError::InvalidMetadata(
            "operation_owner_evidence.request_identity",
        ))?;
    let identity_fence =
        request
            .get("state_fence")
            .cloned()
            .ok_or(CrashReportError::InvalidMetadata(
                "operation_owner_evidence.request_identity",
            ))?;
    let identity_fence: StateFence = serde_json::from_value(identity_fence).map_err(|_| {
        CrashReportError::InvalidMetadata("operation_owner_evidence.request_identity")
    })?;
    let metadata_fence: StateFence =
        serde_json::from_value(metadata.get("state_fence").cloned().ok_or(
            CrashReportError::InvalidMetadata("operation_owner_evidence.request_identity"),
        )?)
        .map_err(|_| {
            CrashReportError::InvalidMetadata("operation_owner_evidence.request_identity")
        })?;
    validate_original_request_identity_bounds(&request_identity)?;
    let expected_authority_epoch = runtime_context
        .authority_epoch
        .as_ref()
        .map(|epoch| format!("{}:{}", epoch.lineage_id.as_str(), epoch.sequence))
        .ok_or(CrashReportError::InvalidMetadata(
            "operation_owner_evidence.authority_epoch",
        ))?;
    if runtime_context.active_trace_ref.as_deref() != Some(trace_id)
        || runtime_context.work_scope_ref.as_deref() != work_scope
        || runtime_context.module_generation_ref.as_deref() != module_generation
        || runtime_context.state_fence.as_ref() != Some(&state_fence)
        || identity_request_id != trace_id
        || identity_fence != state_fence
        || metadata_fence != state_fence
        || lineage.get("task_id") != metadata.get("task_id")
        || lineage.get("session_id") != metadata.get("session_id")
        || authority_epoch != expected_authority_epoch
        || operation_id != expected_operation_id
    {
        return Err(CrashReportError::InvalidMetadata(
            "operation_owner_evidence.context_mismatch",
        ));
    }
    if let Some(operation_id) = operation_id {
        validate_identity(operation_id, "operation_owner_evidence.operation_id")?;
    }
    Ok(())
}

fn validate_original_request_identity_bounds(
    request_identity: &serde_json::Value,
) -> Result<(), CrashReportError> {
    if request_identity
        .get("idempotency_key")
        .and_then(serde_json::Value::as_str)
        .is_none_or(str::is_empty)
        || request_identity
            .get("cancellation_id")
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
        || request_identity
            .get("deadline_unix_ms")
            .and_then(serde_json::Value::as_u64)
            .is_none_or(|deadline| deadline == 0)
    {
        return Err(CrashReportError::InvalidMetadata(
            "operation_owner_evidence.request_identity",
        ));
    }
    Ok(())
}

fn original_lineage_optional_string<'a>(
    lineage: &'a serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<Option<&'a str>, CrashReportError> {
    match lineage.get(field) {
        Some(serde_json::Value::String(value)) if !value.trim().is_empty() => Ok(Some(value)),
        Some(serde_json::Value::Null) | None => Ok(None),
        _ => Err(CrashReportError::InvalidMetadata(field)),
    }
}

fn original_lineage_string<'a>(
    lineage: &'a serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<&'a str, CrashReportError> {
    lineage
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or(CrashReportError::InvalidMetadata(field))
}

impl CrashReporterState {
    fn append_record(&self, rendered: &str) -> Result<(), CrashTelemetryGapReason> {
        let sink = self
            .report_sink
            .read()
            .ok()
            .and_then(|sink| sink.as_ref().map(|sink| sink.handle.writer()));
        let Some(writer) = sink else {
            return Err(CrashTelemetryGapReason::RetentionPolicyUnavailable);
        };
        let receipt = writer
            .try_send_with_ack(rendered)
            .map_err(|error| match error {
                RollingLogAppendError::OverBound => CrashTelemetryGapReason::ReportRejected,
                RollingLogAppendError::QueueFull => CrashTelemetryGapReason::QueueSaturated,
                RollingLogAppendError::WriterUnavailable => {
                    CrashTelemetryGapReason::WriterUnavailable
                }
            })?;
        match receipt.recv_timeout(ROLLING_APPEND_ACK_TIMEOUT) {
            Ok(RollingLogAppendOutcome::Written) => Ok(()),
            Ok(RollingLogAppendOutcome::RetentionFailure) => {
                Err(CrashTelemetryGapReason::RetentionFailure)
            }
            Ok(RollingLogAppendOutcome::StorageFailure)
            | Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                Err(CrashTelemetryGapReason::ReportWriteFailed)
            }
        }
    }

    fn write_gap(&self, report_id: &str, reason: CrashTelemetryGapReason) {
        self.write_gap_for(report_id, &self.process, reason, None);
    }

    fn write_gap_for(
        &self,
        report_id: &str,
        process: &str,
        reason: CrashTelemetryGapReason,
        operation_owner_evidence: Option<&str>,
    ) {
        let record = CrashTelemetryGapRecord {
            record_type: "crash_telemetry_gap",
            report_id,
            process,
            reason,
            operation_owner_evidence,
        };
        let Ok(text) = serde_json::to_string(&record) else {
            self.outcome.store(
                CrashTelemetryOutcome::GapUnpersisted.as_u8(),
                Ordering::Release,
            );
            return;
        };
        let write_result = if text.len() > MAX_GAP_RECORD_BYTES {
            Err(CrashTelemetryGapReason::ReportRejected)
        } else {
            self.append_record(&text)
        };
        if write_result.is_err() {
            tracing::error!(
                target: "eliot::crash_reporter",
                event = "crash_gap_unpersisted",
                process,
                report_id,
                reason = ?reason,
                "Crash telemetry gap could not be persisted"
            );
        }
        self.outcome.store(
            if write_result.is_ok() {
                CrashTelemetryOutcome::GapWritten.as_u8()
            } else {
                CrashTelemetryOutcome::GapUnpersisted.as_u8()
            },
            Ordering::Release,
        );
    }
}

fn validate_identity(value: &str, field: &'static str) -> Result<(), CrashReportError> {
    if value.is_empty()
        || value.len() > MAX_IDENTITY_CHARS
        || !value.is_ascii()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-_".contains(&byte))
    {
        return Err(CrashReportError::InvalidMetadata(field));
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), CrashReportError> {
    if !is_lower_hex(value, 64) {
        return Err(CrashReportError::InvalidMetadata(field));
    }
    Ok(())
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_bundle_relative_ref(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_EVIDENCE_REFERENCE_CHARS
        && value.is_ascii()
        && !value.starts_with('/')
        && !value.starts_with('\\')
        && !value.contains(':')
        && !value.contains('\\')
        && value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        })
}
