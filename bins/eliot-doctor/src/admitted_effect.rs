#![forbid(unsafe_code)]

//! Governed one-shot Doctor effect surface.
//!
//! This module wires the closed Slice 1 contract (`eliot-doctor-core`
//! identities, manifest, and dispositions) to exactly one narrow registered
//! automatic-safe named effect adapter that executes through the shared
//! governed `eliot-process` contour. It never mints authority, never reads
//! recipe or effect authority from caller-controlled surfaces, and never
//! claims a verified repair: the verified terminal disposition is
//! unreachable here by construction because the executor-side verification
//! axes are always recorded as not-executed, unassessed, and unbound.
//!
//! The concrete authenticated Kernel IPC binding is owned by the concurrent
//! Slice 2 work. Until that seam lands, the only honest client in this
//! tree reports the Kernel as not advertising the Doctor operation, so the
//! binary stays fail-closed with exit 78. The one-shot execution paths
//! below are written against the `KernelDoctorClient` trait abstraction and
//! become reachable once Slice 2 delivers authenticated admission material
//! plus the shared executor handle.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use eliot_doctor_core::{
    AdapterReceiptStatus, ArtifactBinding, CONTRACT_NAME, CONTRACT_VERSION, CleanupDisposition,
    ClosedRepairRequest, DoctorDisposition, DoctorError, EffectDisposition, EffectIntent,
    EffectOutcome, EvaluationOutcome, EvidenceHandle, IndependenceClass, IndependenceProfile,
    KERNEL_ADMISSION_REQUIRED, KernelAdmission, KernelDoctorClient, RepairAttemptIdentity,
    RepairClass, RepairEffectIdentity, RepairOperationRef, RepairRecipeManifest, RepairRequest,
    ScopeAttestation, VerificationExecution, VerificationReport, VerifiedAttempt, VerifierEvidence,
    disposition_for_verified_attempt,
};
use eliot_process::{
    ContractError, DescendantEvidence, EvidenceSinkError, ExitDisposition, OperationId,
    ProcessEvidence, ProcessEvidenceSink, ProcessExecutionView, ProcessExecutor, ProcessLifecycle,
    ProcessRequest,
};
use serde::Serialize;
use time::OffsetDateTime;

/// Exit code for a clean one-shot terminal that executed no effect and
/// claims no repair: diagnosed, cancelled, or escalated.
pub const EXIT_OK_NO_EFFECT: i32 = 0;
/// Exit code when the single admitted effect completed but no independent
/// verifier evidence exists yet. Never a verified repair claim.
pub const EXIT_PENDING_VERIFICATION: i32 = 10;
/// Exit code when the single admitted effect observably failed.
pub const EXIT_REPAIR_FAILED: i32 = 11;
/// Exit code for a partial effect outcome.
pub const EXIT_PARTIAL: i32 = 12;
/// Exit code for an exact unknown effect outcome. The reconciliation key in
/// the emitted report names the same effect; blind retry is forbidden.
pub const EXIT_UNKNOWN_EFFECT_OUTCOME: i32 = 13;
/// Exit code when one unknown outcome was reconciled by exact identity.
pub const EXIT_RECONCILING: i32 = 14;
/// Exit code when the attempt was quarantined.
pub const EXIT_QUARANTINED: i32 = 15;
/// Exit code for an internal fail-closed violation that must never happen.
pub const EXIT_INTERNAL: i32 = 70;
/// Exit code when the typed result or evidence could not be emitted.
pub const EXIT_EVIDENCE_FLUSH_FAILED: i32 = 74;
/// Exit code for missing, invalid, stale, or unadvertised Kernel admission,
/// and for any caller-supplied authority. Fail-closed without effect.
pub const EXIT_KERNEL_ADMISSION_REQUIRED: i32 = 78;

/// Residual naming the concurrent Slice 2 owner of the concrete
/// authenticated Kernel Doctor IPC binding.
pub const SLICE2_KERNEL_BINDING_RESIDUAL: &str =
    "issue-461 slice-2 authenticated kernel doctor ipc binding";
/// Residual naming the shared governed physical contour this adapter
/// executes through once Slice 2 binds it: the `eliot-process`
/// `ProcessExecutor` contract with the Windows executor behind the
/// issue-100 dispatch-validation port.
pub const PROCESS_CONTOUR_RESIDUAL: &str = "shared governed process contour: eliot-process ProcessExecutor via the windows executor (#100 dispatch validation port)";

/// Effect sequence bound by this adapter. Single-effect attempts only: a
/// rollback or compensation is another registered effect under a new
/// admission, never a second sequence number here.
pub const ADAPTER_EFFECT_SEQ: u32 = 0;
/// Observation cadence for the single admitted attempt. Matches the
/// physical executor's own watch interval so polling never outruns the
/// contour that owns deadline and cancellation.
pub const OBSERVE_POLL_INTERVAL_MS: u64 = 25;
/// Bound on retained executor evidence records. The one-shot shape needs at
/// most a handful; anything beyond the bound fails the sink instead of
/// growing without limit.
pub const EVIDENCE_COLLECTOR_CAPACITY: usize = 8;

/// Maps a closed terminal disposition to its typed process exit code. Exit
/// zero is returned only for terminals that executed no effect, so exit
/// zero is never a repair disposition. The verified terminal maps to the
/// internal error code because reaching it here would already be a
/// fail-closed violation.
#[must_use]
pub const fn exit_code_for_disposition(disposition: &DoctorDisposition) -> i32 {
    match disposition {
        DoctorDisposition::Diagnosed { .. }
        | DoctorDisposition::Cancelled { .. }
        | DoctorDisposition::Escalated { .. } => EXIT_OK_NO_EFFECT,
        DoctorDisposition::RepairedPendingVerification { .. } => EXIT_PENDING_VERIFICATION,
        DoctorDisposition::RepairedVerified { .. } => EXIT_INTERNAL,
        DoctorDisposition::RepairFailed { .. } => EXIT_REPAIR_FAILED,
        DoctorDisposition::Partial { .. } => EXIT_PARTIAL,
        DoctorDisposition::UnknownEffectOutcome { .. } => EXIT_UNKNOWN_EFFECT_OUTCOME,
        DoctorDisposition::Reconciling { .. } => EXIT_RECONCILING,
        DoctorDisposition::Quarantined { .. } => EXIT_QUARANTINED,
    }
}

/// Typed failure surface for bootstrap and one-shot execution. Admission and
/// validation failures exit 78 without effect; the defensive verifier
/// bypass exits 70; report serialization exits 74.
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    /// The closed admission check failed: missing, invalid, stale, or
    /// unadvertised admission, caller-supplied authority, diagnose-only
    /// execution, missing guarded approval, or an unregistered operation.
    #[error(transparent)]
    Admission(#[from] DoctorError),
    /// The Kernel-issued process request failed shape validation before
    /// any intent was recorded, so nothing executed.
    #[error(transparent)]
    ProcessContract(#[from] ContractError),
    /// The Kernel client failed before effect start, so no intent was
    /// durably recorded and nothing executed.
    #[error("kernel client failed before effect start")]
    KernelClient(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// A reconciliation request did not name this exact effect identity.
    #[error("reconciliation key does not name this exact effect")]
    ReconciliationKeyMismatch,
    /// Defensive tripwire: the verified terminal disposition was reached
    /// inside the effect executor, which must never happen because the
    /// executor-side verification axes never endorse.
    #[error("verified repair disposition is unreachable in the effect executor")]
    VerifierBypass,
    /// The typed one-shot report could not be serialized for emission.
    #[error("one-shot report serialization failed: {0}")]
    ReportRender(#[from] serde_json::Error),
}

impl AdapterError {
    /// Returns the typed exit code for this failure.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Admission(_)
            | Self::ProcessContract(_)
            | Self::KernelClient(_)
            | Self::ReconciliationKeyMismatch => EXIT_KERNEL_ADMISSION_REQUIRED,
            Self::VerifierBypass => EXIT_INTERNAL,
            Self::ReportRender(_) => EXIT_EVIDENCE_FLUSH_FAILED,
        }
    }
}

fn kernel_client_error<E>(error: E) -> AdapterError
where
    E: std::error::Error + Send + Sync + 'static,
{
    AdapterError::KernelClient(Box::new(error))
}

/// Bootstrap argument surface. The Doctor binary takes no recipe, effect,
/// operation, approval, or authority material from its command line: those
/// arrive only through the authenticated Kernel channel owned by Slice 2.
/// Any operational argument is rejected fail-closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapConfig;

impl BootstrapConfig {
    /// Creates the single runnable configuration: zero caller authority.
    #[must_use]
    pub const fn run() -> Self {
        Self
    }
}

/// Decoded bootstrap decision: print help, print version, or attempt the
/// authenticated one-shot bootstrap with zero caller authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapAction {
    /// Print usage and exit without touching admission or effects.
    Help,
    /// Print the contract identity and exit without touching admission.
    Version,
    /// Attempt the authenticated Kernel bootstrap for one shot.
    Run(BootstrapConfig),
}

/// Bootstrap decode failure. Both variants exit 78 without effect.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BootstrapError {
    /// An argument is not part of the bootstrap surface at all.
    #[error("unrecognized doctor argument (doctor takes no caller authority): {arg}")]
    UnrecognizedArgument {
        /// The offending argument, echoed for diagnosis only.
        arg: String,
    },
    /// An argument names recipe, effect, operation, approval, or authority
    /// material, which the command line is never allowed to supply.
    #[error("caller-supplied recipe/effect authority rejected: {arg}")]
    CallerAuthorityRejected {
        /// The offending argument, echoed for diagnosis only.
        arg: String,
    },
}

impl BootstrapError {
    /// Returns the typed exit code for this failure: always 78.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        EXIT_KERNEL_ADMISSION_REQUIRED
    }
}

const AUTHORITY_MARKERS: [&str; 5] = ["recipe", "effect", "operation", "approval", "authority"];

fn reject_bootstrap_arg(arg: &str) -> BootstrapError {
    let lowered = arg.to_ascii_lowercase();
    if AUTHORITY_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        BootstrapError::CallerAuthorityRejected {
            arg: arg.to_owned(),
        }
    } else {
        BootstrapError::UnrecognizedArgument {
            arg: arg.to_owned(),
        }
    }
}

/// Decodes the process argument vector into a bootstrap decision. Only the
/// program name plus at most one informational flag is accepted; anything
/// else is rejected without touching admission or effects.
pub fn decode_bootstrap_args(argv: &[String]) -> Result<BootstrapAction, BootstrapError> {
    let mut rest = argv.iter().skip(1);
    let Some(first) = rest.next() else {
        return Ok(BootstrapAction::Run(BootstrapConfig::run()));
    };
    if rest.next().is_some() {
        return Err(reject_bootstrap_arg(first));
    }
    match first.as_str() {
        "--help" | "-h" => Ok(BootstrapAction::Help),
        "--version" | "-V" => Ok(BootstrapAction::Version),
        _ => Err(reject_bootstrap_arg(first)),
    }
}

/// Renders the usage text: one-shot semantics, the no-authority rule, the
/// exit code contract, and the Slice 2 residual.
#[must_use]
pub fn help_text() -> String {
    format!(
        "eliot-doctor ({CONTRACT_NAME} {CONTRACT_VERSION}): governed one-shot doctor.\n\
         usage: eliot-doctor [--help] [--version]\n\
         Runs at most one Kernel-admitted attempt or one reconciliation request through\n\
         a single registered automatic-safe named effect adapter on the shared governed\n\
         process contour, emits one typed JSON report on stdout, flushes evidence, exits.\n\
         No recipe, effect, operation, approval, or authority material is accepted from\n\
         argv, stdin, or environment; admission arrives only via the authenticated Kernel\n\
         channel. Diagnose-only admissions never execute. Crash after intent but before\n\
         receipt stays UNKNOWN_EFFECT_OUTCOME; blind retry is forbidden.\n\
         exit 0: diagnosed/cancelled/escalated without effect (never a repair claim)\n\
         exit 10: effect completed, pending independent verification\n\
         exit 11: effect failed; 12: partial; 13: unknown effect outcome; 14: reconciling\n\
         exit 15: quarantined; 70: internal fail-closed violation\n\
         exit 74: result/evidence emission failed; 78: kernel admission required\n\
         residual: {SLICE2_KERNEL_BINDING_RESIDUAL}\n\
         contour: {PROCESS_CONTOUR_RESIDUAL}\n"
    )
}

/// Renders the contract identity line for `--version`.
#[must_use]
pub fn version_line() -> String {
    format!("{CONTRACT_NAME} {CONTRACT_VERSION}")
}

/// Renders the stable admission-required stderr line with the detail and
/// the residuals that name the missing Slice 2 seam.
#[must_use]
pub fn admission_required_line(detail: &str) -> String {
    format!(
        "{KERNEL_ADMISSION_REQUIRED}: operation={CONTRACT_NAME} version={CONTRACT_VERSION} detail={detail} residual={SLICE2_KERNEL_BINDING_RESIDUAL} contour={PROCESS_CONTOUR_RESIDUAL}"
    )
}

/// Honest Kernel client for the current tree: the Kernel does not advertise
/// the Doctor operation (verified: no importable doctor admission seam
/// exists in the kernel tree at the authority base), so advertisement
/// reports false and every authority-bearing method fails closed with a
/// typed error. The concurrent Slice 2 work replaces this binding with the
/// authenticated IPC client; until then every path exits 78 without effect.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UnadvertisedKernelClient;

impl UnadvertisedKernelClient {
    /// Creates the current-tree client: advertisement absent by verified fact.
    #[must_use]
    pub const fn current() -> Self {
        Self
    }
}

/// Typed failure for authority-bearing calls on an unadvertised operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum UnadvertisedKernelError {
    /// The Doctor operation is not advertised, so no admission exists.
    #[error("kernel does not advertise the doctor operation (KERNEL_ADMISSION_REQUIRED)")]
    NotAdvertised,
}

impl KernelDoctorClient for UnadvertisedKernelClient {
    type Error = UnadvertisedKernelError;

    fn advertise_doctor(&mut self) -> Result<bool, Self::Error> {
        Ok(false)
    }

    fn admit(&mut self, _request: &RepairRequest) -> Result<KernelAdmission, Self::Error> {
        Err(UnadvertisedKernelError::NotAdvertised)
    }

    fn record_intent(&mut self, _intent: &EffectIntent) -> Result<(), Self::Error> {
        Err(UnadvertisedKernelError::NotAdvertised)
    }

    fn execute(&mut self, _intent: &EffectIntent) -> Result<EffectOutcome, Self::Error> {
        Err(UnadvertisedKernelError::NotAdvertised)
    }

    fn reconcile(
        &mut self,
        _job_id: &str,
        _attempt_id: &str,
    ) -> Result<EffectOutcome, Self::Error> {
        Err(UnadvertisedKernelError::NotAdvertised)
    }
}

const SINK_LOCK_POISONED: &str = "evidence collector lock poisoned";
const SINK_AT_CAPACITY: &str = "evidence collector at capacity";

/// Bounded in-memory evidence sink for the single admitted attempt. Records
/// are drained exactly once by `close`; the typed report carries only
/// digests and byte counts, never raw stream content.
#[derive(Debug)]
pub struct EvidenceCollector {
    records: Mutex<Vec<ProcessEvidence>>,
    capacity: usize,
}

impl EvidenceCollector {
    /// Creates an empty collector bounded by `EVIDENCE_COLLECTOR_CAPACITY`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
            capacity: EVIDENCE_COLLECTOR_CAPACITY,
        }
    }

    /// Drains every retained record exactly once for typed projection, then
    /// drops them. Closing twice yields an empty vector, never a repeat.
    pub fn close(&self) -> Vec<ProcessEvidence> {
        self.records
            .lock()
            .map(|mut guard| std::mem::take(&mut *guard))
            .unwrap_or_default()
    }

    /// Returns the number of retained records.
    #[must_use]
    pub fn len(&self) -> usize {
        let Ok(guard) = self.records.lock() else {
            return 0;
        };
        guard.len()
    }

    /// Returns whether no record is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Projects the newest stdout/stderr stream digests bound to one exact
    /// request digest, or an empty projection when no record matches.
    /// Only digests and byte counts cross into the report.
    #[must_use]
    pub fn latest_streams(&self, request_digest: &str) -> StreamProjection {
        let mut projection = StreamProjection::default();
        let Ok(guard) = self.records.lock() else {
            return projection;
        };
        for record in guard.iter().rev() {
            if record.request_digest() != request_digest {
                continue;
            }
            if let Some(stdout) = record.stdout() {
                projection.stdout_sha256 = Some(stdout.observed_sha256().to_owned());
                projection.stdout_bytes = Some(stdout.observed_bytes());
            }
            if let Some(stderr) = record.stderr() {
                projection.stderr_sha256 = Some(stderr.observed_sha256().to_owned());
                projection.stderr_bytes = Some(stderr.observed_bytes());
            }
            return projection;
        }
        projection
    }
}

impl Default for EvidenceCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessEvidenceSink for EvidenceCollector {
    fn record(&self, evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
        let mut guard = self.records.lock().map_err(|_| EvidenceSinkError {
            message: SINK_LOCK_POISONED.to_owned(),
        })?;
        if guard.len() >= self.capacity {
            return Err(EvidenceSinkError {
                message: SINK_AT_CAPACITY.to_owned(),
            });
        }
        guard.push(evidence);
        Ok(())
    }
}

/// Stdout/stderr stream evidence projection: content digests and byte
/// counts only, never raw content.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StreamProjection {
    /// Observed stdout content digest, when the executor supplied one.
    pub stdout_sha256: Option<String>,
    /// Observed stdout byte count, when the executor supplied one.
    pub stdout_bytes: Option<u64>,
    /// Observed stderr content digest, when the executor supplied one.
    pub stderr_sha256: Option<String>,
    /// Observed stderr byte count, when the executor supplied one.
    pub stderr_bytes: Option<u64>,
}

/// Process evidence projection bound to one exact execution: the evidence
/// locator plus stream digests. The digest is the executor binding's own
/// request digest, validated as 64-character lowercase hex at construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedEvidence {
    /// Locator naming the exact executor evidence record.
    pub reference: String,
    /// Identity digest of that exact evidence record.
    pub digest: String,
    /// Stdout/stderr projections bound to the same record.
    pub streams: StreamProjection,
}

impl ObservedEvidence {
    /// Projects one exact evidence record from an identity-checked process
    /// view plus the newest matching collector streams.
    pub fn from_view(
        view: &ProcessExecutionView,
        streams: StreamProjection,
    ) -> Result<Self, AdapterError> {
        let digest = view.request_digest().to_owned();
        let reference = format!("eliot-process-evidence/request:{digest}");
        EvidenceHandle::new(reference.clone(), digest.clone())?;
        Ok(Self {
            reference,
            digest,
            streams,
        })
    }

    /// Projects one exact evidence record returned by reconciliation. The
    /// record is structurally validated first; its binding was already
    /// checked by the executor contour before it was emitted.
    pub fn from_evidence(evidence: &ProcessEvidence) -> Result<Self, AdapterError> {
        evidence.validate()?;
        let digest = evidence.request_digest().to_owned();
        let reference = format!("eliot-process-evidence/request:{digest}");
        EvidenceHandle::new(reference.clone(), digest.clone())?;
        let mut streams = StreamProjection::default();
        if let Some(stdout) = evidence.stdout() {
            streams.stdout_sha256 = Some(stdout.observed_sha256().to_owned());
            streams.stdout_bytes = Some(stdout.observed_bytes());
        }
        if let Some(stderr) = evidence.stderr() {
            streams.stderr_sha256 = Some(stderr.observed_sha256().to_owned());
            streams.stderr_bytes = Some(stderr.observed_bytes());
        }
        Ok(Self {
            reference,
            digest,
            streams,
        })
    }
}

/// Typed one-shot JSON report emitted exactly once on stdout. `exit_code`
/// mirrors `exit_code_for_disposition`; every other field names exact
/// identities and evidence, never raw content or authority material.
#[derive(Clone, Debug, Serialize)]
pub struct DoctorOneShotReport {
    /// The admitted contract operation.
    pub operation: String,
    /// Digest of the exact admitted attempt identity, when one was bound.
    /// Diagnose-only terminals bind no attempt and report none.
    pub attempt_digest: Option<String>,
    /// Digest of the exact effect identity, when an effect path ran.
    pub effect_digest: Option<String>,
    /// Closed effect axis (`not_executed`, `succeeded`, `failed`,
    /// `partial`, `unknown_outcome`), when an effect path ran.
    pub effect_disposition: Option<String>,
    /// Closed terminal disposition name.
    pub disposition: String,
    /// Cleanup axis (`not_required`, `pending`, `complete`, `failed`),
    /// when an effect path ran.
    pub cleanup: Option<String>,
    /// Exact reconciliation key: always the effect digest on unknown
    /// outcomes, naming the same effect for a later invocation.
    pub reconciliation_key: Option<String>,
    /// Locator of the exact executor evidence record, when observed.
    pub evidence_reference: Option<String>,
    /// Identity digest of that record, when observed.
    pub evidence_digest: Option<String>,
    /// Observed stdout content digest, when the executor supplied one.
    pub stdout_sha256: Option<String>,
    /// Observed stdout byte count, when the executor supplied one.
    pub stdout_bytes: Option<u64>,
    /// Observed stderr content digest, when the executor supplied one.
    pub stderr_sha256: Option<String>,
    /// Observed stderr byte count, when the executor supplied one.
    pub stderr_bytes: Option<u64>,
    /// Typed process exit code for this disposition.
    pub exit_code: i32,
}

/// The single emitted outcome: the closed disposition plus its pre-rendered
/// report wire. The wire is rendered once at construction so emission
/// cannot diverge from the returned disposition.
#[derive(Clone, Debug)]
pub struct OneShotOutcome {
    /// The closed terminal disposition for this one shot.
    pub disposition: DoctorDisposition,
    /// The typed report projected for this disposition.
    pub report: DoctorOneShotReport,
    /// The exact stdout wire for `report`, rendered once.
    pub wire: String,
}

impl OneShotOutcome {
    /// Returns the typed exit code carried by the report.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        self.report.exit_code
    }
}

const fn effect_disposition_name(value: EffectDisposition) -> &'static str {
    match value {
        EffectDisposition::NotExecuted => "not_executed",
        EffectDisposition::Succeeded => "succeeded",
        EffectDisposition::Failed => "failed",
        EffectDisposition::Partial => "partial",
        EffectDisposition::UnknownOutcome => "unknown_outcome",
    }
}

const fn cleanup_name(value: CleanupDisposition) -> &'static str {
    match value {
        CleanupDisposition::NotRequired => "not_required",
        CleanupDisposition::Pending => "pending",
        CleanupDisposition::Complete => "complete",
        CleanupDisposition::Failed => "failed",
    }
}

struct DispositionParts {
    effect_disposition: Option<EffectDisposition>,
    disposition: DoctorDisposition,
    observed: Option<ObservedEvidence>,
    reconciliation_key: Option<String>,
    cleanup: Option<CleanupDisposition>,
}

fn emit_outcome(
    attempt: Option<&RepairAttemptIdentity>,
    effect: Option<&RepairEffectIdentity>,
    parts: DispositionParts,
) -> Result<OneShotOutcome, AdapterError> {
    parts.disposition.validate()?;
    let streams = parts
        .observed
        .as_ref()
        .map_or_else(StreamProjection::default, |observed| {
            observed.streams.clone()
        });
    let report = DoctorOneShotReport {
        operation: CONTRACT_NAME.to_owned(),
        attempt_digest: attempt.map(|value| value.digest().to_owned()),
        effect_digest: effect.map(|value| value.digest().to_owned()),
        effect_disposition: parts
            .effect_disposition
            .map(effect_disposition_name)
            .map(str::to_owned),
        disposition: parts.disposition.name().to_owned(),
        cleanup: parts.cleanup.map(cleanup_name).map(str::to_owned),
        reconciliation_key: parts.reconciliation_key,
        evidence_reference: parts.observed.as_ref().map(|value| value.reference.clone()),
        evidence_digest: parts.observed.as_ref().map(|value| value.digest.clone()),
        stdout_sha256: streams.stdout_sha256,
        stdout_bytes: streams.stdout_bytes,
        stderr_sha256: streams.stderr_sha256,
        stderr_bytes: streams.stderr_bytes,
        exit_code: exit_code_for_disposition(&parts.disposition),
    };
    let wire = serde_json::to_string(&report)?;
    Ok(OneShotOutcome {
        disposition: parts.disposition,
        report,
        wire,
    })
}

fn unknown_outcome(
    attempt: &RepairAttemptIdentity,
    effect: &RepairEffectIdentity,
    view: Option<&ProcessExecutionView>,
    streams: StreamProjection,
) -> Result<OneShotOutcome, AdapterError> {
    let observed = view.map_or_else(
        || None,
        |observed_view| ObservedEvidence::from_view(observed_view, streams).ok(),
    );
    emit_outcome(
        Some(attempt),
        Some(effect),
        DispositionParts {
            effect_disposition: Some(EffectDisposition::UnknownOutcome),
            disposition: DoctorDisposition::UnknownEffectOutcome {
                attempt: attempt.clone(),
                reconciliation_key: effect.digest().to_owned(),
            },
            observed,
            reconciliation_key: Some(effect.digest().to_owned()),
            cleanup: Some(CleanupDisposition::Pending),
        },
    )
}

/// Inputs for exactly one admitted attempt execution. The process request
/// is owned here so the single consuming dispatch cannot be replayed, and
/// the client records durable intent before the dispatch so a crash after
/// intent but before receipt stays unknown instead of being retried blind.
pub struct AttemptInputs<'a, C> {
    /// Authenticated Kernel client for durable intent recording.
    pub client: &'a mut C,
    /// The closed admitted request from the Kernel channel.
    pub request: &'a ClosedRepairRequest,
    /// The exact admitted manifest revision.
    pub manifest: &'a RepairRecipeManifest,
    /// The Kernel-issued attempt identity string for this one shot.
    pub attempt_id: &'a str,
    /// Bounded evidence sink handed to the single dispatch.
    pub sink: Arc<EvidenceCollector>,
    /// The Kernel-issued permit-bound process request for this attempt.
    pub process_request: ProcessRequest,
    /// Admission time used for the closed validation round.
    pub now: OffsetDateTime,
}

/// Inputs for exactly one reconciliation request by exact effect identity.
/// No new effect executes here: the adapter observes the executor-owned
/// reconciliation evidence once and dispositions the unknown outcome.
pub struct ReconcileInputs<'a> {
    /// The closed admitted request from the Kernel channel.
    pub request: &'a ClosedRepairRequest,
    /// The exact admitted manifest revision.
    pub manifest: &'a RepairRecipeManifest,
    /// The Kernel-issued attempt identity string being reconciled.
    pub attempt_id: &'a str,
    /// The Kernel-delivered process operation identity to reconcile.
    pub operation_id: OperationId,
    /// The presented reconciliation key; must equal the effect digest.
    pub reconciliation_key: &'a str,
    /// Admission time used for the closed validation round.
    pub now: OffsetDateTime,
}

/// The single narrow registered automatic-safe named effect adapter.
///
/// The adapter binds exactly one manifest-resolved operation reference and
/// one shared governed executor. It executes at most one consuming
/// dispatch per process invocation, observes the executor-owned lifecycle
/// to a terminal or deadline bound, then folds the observation into the
/// closed Slice 1 dispositions. It performs no retry, no compensation, and
/// no verification: compensation is another registered effect under a new
/// admission, and verification belongs to the independent Wave E verifier.
pub struct AutomaticSafeAdapter<E> {
    executor: Arc<E>,
    operation: RepairOperationRef,
}

impl<E> AutomaticSafeAdapter<E> {
    /// Binds one manifest-resolved automatic-safe operation reference to
    /// the shared executor handle. The reference shape is validated now;
    /// manifest admission is re-proved on every execution.
    pub fn bind(executor: Arc<E>, operation: RepairOperationRef) -> Result<Self, AdapterError> {
        operation.validate()?;
        Ok(Self {
            executor,
            operation,
        })
    }

    /// Returns the single bound registered operation reference.
    #[must_use]
    pub const fn operation(&self) -> &RepairOperationRef {
        &self.operation
    }
}

impl<E: ProcessExecutor + 'static> AutomaticSafeAdapter<E> {
    fn check_executable(
        &self,
        request: &ClosedRepairRequest,
        manifest: &RepairRecipeManifest,
        attempt_id: &str,
        now: OffsetDateTime,
    ) -> Result<(RepairAttemptIdentity, RepairEffectIdentity), AdapterError> {
        if matches!(request.recipe.repair_class, RepairClass::DiagnoseOnly)
            || request.operations.is_empty()
        {
            return Err(AdapterError::Admission(DoctorError::DiagnoseEffects));
        }
        manifest.check_admitted(&self.operation)?;
        if !request.operations.contains(&self.operation) {
            return Err(AdapterError::Admission(DoctorError::OperationNotAdmitted));
        }
        let attempt = request.bind_attempt(manifest, attempt_id, &self.operation, now)?;
        let effect = request.bind_effect(&attempt, &self.operation, ADAPTER_EFFECT_SEQ)?;
        Ok((attempt, effect))
    }

    /// Executes exactly one admitted attempt through the shared governed
    /// executor, then projects exactly one closed outcome.
    ///
    /// The closed request is validated first, durable intent is recorded
    /// with the Kernel client, then a single consuming dispatch runs. Any
    /// failure on or after the recorded intent becomes the exact unknown
    /// effect outcome keyed by the effect digest; only pre-intent failures
    /// return errors. The verified terminal disposition is unreachable and
    /// trips the defensive bypass error instead of emitting.
    pub async fn execute_admitted_attempt<C>(
        &self,
        inputs: AttemptInputs<'_, C>,
    ) -> Result<OneShotOutcome, AdapterError>
    where
        C: KernelDoctorClient,
        C::Error: std::error::Error + Send + Sync + 'static,
    {
        let AttemptInputs {
            client,
            request,
            manifest,
            attempt_id,
            sink,
            process_request,
            now,
        } = inputs;
        let (attempt, effect) = self.check_executable(request, manifest, attempt_id, now)?;
        process_request.validate()?;
        let operation_id = process_request.operation_id().clone();
        let expected_request_digest = process_request.invocation_digest().to_owned();
        let expected_generation = process_request.generation();
        let intent = EffectIntent {
            job_id: request.request_id.clone(),
            attempt_id: attempt_id.to_owned(),
            recipe_digest: request.recipe_identity.digest().to_owned(),
            effect_digest: effect.digest().to_owned(),
        };
        client.record_intent(&intent).map_err(kernel_client_error)?;
        let sink_dyn: Arc<dyn ProcessEvidenceSink> = sink.clone();
        let Ok(start_receipt) = self.executor.start(process_request, sink_dyn).await else {
            return unknown_outcome(&attempt, &effect, None, StreamProjection::default());
        };
        if start_receipt.operation_id() != &operation_id
            || start_receipt.request_digest() != expected_request_digest
            || start_receipt.accepted_generation() != expected_generation
        {
            return unknown_outcome(&attempt, &effect, None, StreamProjection::default());
        }
        self.observe_until_terminal(
            &attempt,
            &effect,
            request,
            &operation_id,
            &expected_request_digest,
            &sink,
        )
        .await
    }

    async fn observe_until_terminal(
        &self,
        attempt: &RepairAttemptIdentity,
        effect: &RepairEffectIdentity,
        request: &ClosedRepairRequest,
        operation_id: &OperationId,
        expected_request_digest: &str,
        sink: &EvidenceCollector,
    ) -> Result<OneShotOutcome, AdapterError> {
        loop {
            let Ok(view) = self.executor.inspect(operation_id.clone()).await else {
                return unknown_outcome(attempt, effect, None, StreamProjection::default());
            };
            if view.operation_id() != operation_id
                || view.request_digest() != expected_request_digest
            {
                return unknown_outcome(attempt, effect, None, StreamProjection::default());
            }
            match view.lifecycle() {
                ProcessLifecycle::Exited
                | ProcessLifecycle::Failed
                | ProcessLifecycle::Reconciled
                | ProcessLifecycle::Quarantined => {
                    return finish_observed(
                        attempt,
                        effect,
                        request,
                        &view,
                        sink,
                        OffsetDateTime::now_utc(),
                    );
                }
                ProcessLifecycle::UnknownOutcome => {
                    let streams = sink.latest_streams(view.request_digest());
                    return unknown_outcome(attempt, effect, Some(&view), streams);
                }
                ProcessLifecycle::Created
                | ProcessLifecycle::Starting
                | ProcessLifecycle::Running
                | ProcessLifecycle::Cancelling => {
                    if OffsetDateTime::now_utc() >= request.deadline {
                        let streams = sink.latest_streams(view.request_digest());
                        return unknown_outcome(attempt, effect, Some(&view), streams);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(OBSERVE_POLL_INTERVAL_MS))
                        .await;
                }
            }
        }
    }

    /// Reconciles exactly one unknown outcome by exact effect identity
    /// through a single executor-owned reconciliation request. The
    /// presented key must equal the bound effect digest; anything else
    /// fails without touching the executor. A reconciled observation
    /// advances the unknown disposition to reconciling; anything
    /// inconclusive stays unknown under the same key.
    pub async fn reconcile_admitted_unknown(
        &self,
        inputs: ReconcileInputs<'_>,
    ) -> Result<OneShotOutcome, AdapterError> {
        let ReconcileInputs {
            request,
            manifest,
            attempt_id,
            operation_id,
            reconciliation_key,
            now,
        } = inputs;
        let (attempt, effect) = self.check_executable(request, manifest, attempt_id, now)?;
        if reconciliation_key != effect.digest() {
            return Err(AdapterError::ReconciliationKeyMismatch);
        }
        let Ok(evidence) = self.executor.reconcile(operation_id.clone()).await else {
            return unknown_outcome(&attempt, &effect, None, StreamProjection::default());
        };
        if evidence.operation_id() != &operation_id {
            return unknown_outcome(&attempt, &effect, None, StreamProjection::default());
        }
        let Ok(observed) = ObservedEvidence::from_evidence(&evidence) else {
            return unknown_outcome(&attempt, &effect, None, StreamProjection::default());
        };
        if !matches!(evidence.view().lifecycle(), ProcessLifecycle::Reconciled) {
            return unknown_outcome(&attempt, &effect, None, StreamProjection::default());
        }
        let unknown = DoctorDisposition::UnknownEffectOutcome {
            attempt: attempt.clone(),
            reconciliation_key: effect.digest().to_owned(),
        };
        let reconciling = DoctorDisposition::Reconciling {
            attempt: attempt.clone(),
            effect: effect.clone(),
        };
        let Ok(disposition) = unknown.advance(reconciling) else {
            return unknown_outcome(&attempt, &effect, None, StreamProjection::default());
        };
        emit_outcome(
            Some(&attempt),
            Some(&effect),
            DispositionParts {
                effect_disposition: None,
                disposition,
                observed: Some(observed),
                reconciliation_key: Some(effect.digest().to_owned()),
                cleanup: Some(CleanupDisposition::Pending),
            },
        )
    }
}

fn cleanup_for(view: &ProcessExecutionView) -> CleanupDisposition {
    if view
        .descendants()
        .is_some_and(DescendantEvidence::tree_terminated)
    {
        CleanupDisposition::NotRequired
    } else {
        CleanupDisposition::Pending
    }
}

fn effect_for_view(view: &ProcessExecutionView) -> EffectDisposition {
    let completed = matches!(
        view.lifecycle(),
        ProcessLifecycle::Exited | ProcessLifecycle::Reconciled
    ) && view
        .exit()
        .is_some_and(|exit| exit.disposition() == ExitDisposition::Completed);
    if completed {
        EffectDisposition::Succeeded
    } else {
        EffectDisposition::Failed
    }
}

fn finish_observed(
    attempt: &RepairAttemptIdentity,
    effect: &RepairEffectIdentity,
    request: &ClosedRepairRequest,
    view: &ProcessExecutionView,
    sink: &EvidenceCollector,
    observed_at: OffsetDateTime,
) -> Result<OneShotOutcome, AdapterError> {
    let streams = sink.latest_streams(view.request_digest());
    let Ok(observed) = ObservedEvidence::from_view(view, streams) else {
        return unknown_outcome(attempt, effect, Some(view), StreamProjection::default());
    };
    let Ok(handle) = EvidenceHandle::new(observed.reference.clone(), observed.digest.clone())
    else {
        return unknown_outcome(attempt, effect, Some(view), StreamProjection::default());
    };
    let Ok(independence) =
        IndependenceProfile::new(BTreeSet::from([IndependenceClass::SelfReported]))
    else {
        return unknown_outcome(attempt, effect, Some(view), StreamProjection::default());
    };
    let effect_disposition = effect_for_view(view);
    let verification = VerificationReport {
        attempt: attempt.clone(),
        effect: effect.clone(),
        evidence: VerifierEvidence {
            verification_execution: VerificationExecution::NotExecuted,
            evaluation: EvaluationOutcome::Unassessed,
            artifact_binding: ArtifactBinding::Unbound,
            scope: ScopeAttestation {
                fence_digest: request.fence.digest.clone(),
                observed_at,
                fence_current: false,
            },
            independence,
            evidence: vec![handle.clone()],
        },
        reported_at: observed_at,
    };
    let receipt = VerifiedAttempt {
        attempt: attempt.clone(),
        effect: effect.clone(),
        effect_disposition,
        adapter_receipt: AdapterReceiptStatus::Received(handle),
        verification,
        cleanup: cleanup_for(view),
        observed_at,
    };
    let Ok(disposition) = disposition_for_verified_attempt(&receipt, &request.fence) else {
        return unknown_outcome(attempt, effect, Some(view), StreamProjection::default());
    };
    if matches!(disposition, DoctorDisposition::RepairedVerified { .. }) {
        return Err(AdapterError::VerifierBypass);
    }
    emit_outcome(
        Some(attempt),
        Some(effect),
        DispositionParts {
            effect_disposition: Some(effect_disposition),
            disposition,
            observed: Some(observed),
            reconciliation_key: None,
            cleanup: Some(receipt.cleanup),
        },
    )
}

/// Projects a diagnose-only admission to its terminal without touching any
/// executor. Diagnose-only requests carry no operations by construction, so
/// there is no effect path here at all: execution is impossible, not merely
/// refused. Cancellation short-circuits to cancelled before diagnosis.
pub fn project_diagnosis(
    request: &ClosedRepairRequest,
    manifest: &RepairRecipeManifest,
    now: OffsetDateTime,
) -> Result<OneShotOutcome, AdapterError> {
    request.validate_closed(manifest, now)?;
    if !matches!(request.recipe.repair_class, RepairClass::DiagnoseOnly)
        || !request.operations.is_empty()
    {
        return Err(AdapterError::Admission(DoctorError::DiagnoseEffects));
    }
    let disposition = if request.cancellation {
        DoctorDisposition::Cancelled {
            request_id: request.request_id.clone(),
        }
    } else {
        DoctorDisposition::Diagnosed {
            request_id: request.request_id.clone(),
        }
    };
    emit_outcome(
        None,
        None,
        DispositionParts {
            effect_disposition: None,
            disposition,
            observed: None,
            reconciliation_key: None,
            cleanup: None,
        },
    )
}
