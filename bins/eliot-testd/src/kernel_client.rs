#![forbid(unsafe_code)]

//! Authenticated Kernel IPC client for testd (T6-X1, issue #20).
//!
//! This module binds the testd binary to the live Kernel front door and
//! speaks exactly one service exchange: the versioned
//! `eliot.kernel.testd-admission` wire carrying a full
//! [`TestdAdmissionRequest`] envelope to a typed
//! [`TestdAdmissionResponse`]. It never downgrades to a legacy open
//! [`KernelProcessAdmissionRequest`] shape: that admit entry is refused
//! fail-closed because a bare provider request cannot carry the admission
//! identity (job seed, invocation digest, epoch/generation binding) the
//! wire requires.
//!
//! Authority rules enforced here (mirroring
//! `bins/eliot-doctor/src/kernel_client.rs` pattern, never logic):
//!
//! - Bootstrap reads only the protected installation-owned front-door
//!   declaration. No job, invocation, fence, or authority value is taken
//!   from argv, stdin, or environment; those surfaces carry at most `--help`
//!   / `--version`.
//! - Generation binding comes from the live Kernel `ServerHello`, checked
//!   against the protected declaration (authority epoch exact tuple,
//!   generation, artifact digest, config snapshot digest). The live epoch is
//!   additionally retained from the authenticated health reply and is the
//!   only epoch the admitted driver binds against.
//! - The concrete [`ProcessRequest`] executed by the adapter is an in-memory
//!   composition value delivered with the dispatch contour. It is never
//!   deserialized from a wire type, never built from caller surfaces, and
//!   this module never mints a permit.
//! - One shot performs at most one submit and at most one process start.
//!   A lost submit reply exits the shot without effect and without retry;
//!   only the executor-owned unknown path may disposition an unknown
//!   outcome, keyed by the same request digest.
//! - Bare paths, PIDs, and service names are never identity. Identity is
//!   exactly (`job_id`, `invocation_digest`, `authority_epoch` exact tuple,
//!   `generation`, canonical digests). Path strings are validated for shape
//!   only where the contour requires an existing root; they never decide
//!   admission, replay, or reconciliation.
//!
//! Until the live Kernel dispatch contour lands, the client fails closed
//! after the authenticated bootstrap instead of inventing admission
//! material: `connect` mirrors the doctor bootstrap (`KernelClient::load` →
//! `probe` → `require_health_open` → `parse_live_epoch`) and fails closed
//! without ambient authority when the front door is unavailable, while
//! `advertise_testd` probes live health and flips to `true` only when the
//! composed Kernel advertises the exact testd wire. The Drive path below
//! already derives its executable binding from the admitted profile registry.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eliot_blob_api::wire::{
    BlobProcessStreamCallToken, BlobProcessStreamKernelOperationRequest,
    BlobProcessStreamKernelOutcome, BlobProcessStreamKernelRequest,
    BlobProcessStreamKernelResponse, BlobProcessStreamOperationResponse,
    ProcessStreamSinkBindingRef, ProcessStreamSinkCapabilityRef, ProcessStreamSinkWireResponse,
};
use eliot_cli::kernel_client::{KernelClient, KernelClientError};
use eliot_contracts::{EpochId, canonical_json_bytes, sha256_hex};
use eliot_instrument_api::{InstrumentInvocation, InstrumentKind};
use eliot_process::{ProcessEvidenceSink, ProcessExecutionError, ProcessExecutor, ProcessRequest};
use eliot_process::{
    ProcessStreamEvidence, ProcessStreamSinkAbortRequest, ProcessStreamSinkAppend,
    ProcessStreamSinkAppendDisposition, ProcessStreamSinkClient, ProcessStreamSinkError,
    ProcessStreamSinkFinalizeRequest, ProcessStreamSinkFuture, ProcessStreamSinkOpenRequest,
    ProcessStreamSinkReadback, ProcessStreamSinkSession, ProcessStreamSinkSessionView,
    ProcessStreamSinkState, ProcessStreamSinkTerminal, ProcessStreamSinkUnknownOutcome,
};
use eliot_store_api::{WriteReceipt, WriteReceiptStatus};
use eliot_testd_core::{
    KernelProcessAdmissionEvidence, KernelProcessAdmissionProvider, KernelProcessAdmissionRequest,
    TestJob, TestdBlobProcessStreamCallOutcome, TestdBlobProcessStreamReserve,
    TestdBlobProcessStreamTokenRef, TestdError, TestdStore, TestdTerminalCompletionNotice,
    TestdVerifierDispatchBinding, verification_receipt_sha256,
};
use serde::{Deserialize, Serialize};

/// Stable operation selector for the Kernel-owned testd admission wire.
///
/// Defined here because the base tree carries no Writer-B wire constant yet
/// (no `TESTD_ADMISSION_WIRE_ID` on base; searched before defining). The
/// single wire stays `eliot.kernel.testd-admission`.
pub const TESTD_ADMISSION_OPERATION: &str = "eliot.kernel.testd-admission";
/// Wire revision admitted by this client.
pub const TESTD_ADMISSION_OPERATION_VERSION: u16 = 1;
/// Authenticated receipt-publication operation on the same TestD Kernel
/// session used for admission.
pub const TESTD_TERMINAL_COMPLETION_OPERATION: &str = "eliot.kernel.testd-terminal-completion";
/// Version of the TestD terminal-completion wire.
pub const TESTD_TERMINAL_COMPLETION_OPERATION_VERSION: u16 = 1;
/// Advertisement for the testd admission operation: inert until the dispatch
/// slice lands. Testd fails closed with `KERNEL_ADMISSION_REQUIRED` while
/// this is `false`.
pub const TESTD_ADMISSION_ADVERTISED: bool = false;

/// Returns whether Kernel currently advertises the testd admission
/// operation.
///
/// Always `false` in slice 6: the tree stays fail-closed until the dispatch
/// slice wires the front-door dispatch arm.
pub fn advertise_testd_admission() -> bool {
    TESTD_ADMISSION_ADVERTISED
}

/// Routes one wire identity to the testd admission gate.
///
/// Returns `true` only for the exact
/// (`TESTD_ADMISSION_OPERATION`, `TESTD_ADMISSION_OPERATION_VERSION`) pair.
pub fn route_testd_admission(wire_id: &str, wire_version: u16) -> bool {
    wire_id == TESTD_ADMISSION_OPERATION && wire_version == TESTD_ADMISSION_OPERATION_VERSION
}

/// Closed TestD terminal notification. Its payload contains only the durable
/// job identity and the digest of the immutable finish receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdTerminalCompletionRequest {
    pub wire_id: String,
    pub wire_version: u16,
    pub job_id: String,
    pub receipt_sha256: String,
    pub request_digest: String,
}

impl TestdTerminalCompletionRequest {
    pub fn new(notice: &TestdTerminalCompletionNotice) -> Result<Self, TestdIpcError> {
        let mut request = Self {
            wire_id: TESTD_TERMINAL_COMPLETION_OPERATION.to_owned(),
            wire_version: TESTD_TERMINAL_COMPLETION_OPERATION_VERSION,
            job_id: notice.job_id.clone(),
            receipt_sha256: notice.receipt_sha256.clone(),
            request_digest: String::new(),
        };
        request.request_digest = request.canonical_request_digest()?;
        request.validate()?;
        Ok(request)
    }

    fn canonical_request_digest(&self) -> Result<String, TestdIpcError> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            wire_id: &'a str,
            wire_version: u16,
            job_id: &'a str,
            receipt_sha256: &'a str,
        }
        let canonical = Canonical {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            job_id: &self.job_id,
            receipt_sha256: &self.receipt_sha256,
        };
        canonical_json_bytes(&canonical)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|error| TestdIpcError::Contract(error.to_string()))
    }

    pub fn validate(&self) -> Result<(), TestdIpcError> {
        if self.wire_id != TESTD_TERMINAL_COMPLETION_OPERATION
            || self.wire_version != TESTD_TERMINAL_COMPLETION_OPERATION_VERSION
        {
            return Err(TestdIpcError::Contract(
                "unsupported TestD terminal-completion wire".to_owned(),
            ));
        }
        validate_wire_text(&self.job_id, "testd_terminal.job_id")?;
        validate_wire_digest(&self.receipt_sha256, "testd_terminal.receipt_sha256")?;
        validate_wire_digest(&self.request_digest, "testd_terminal.request_digest")?;
        if self.canonical_request_digest()? != self.request_digest {
            return Err(TestdIpcError::Contract(
                "TestD terminal-completion request digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Kernel reply. `Pending` is a nonterminal handoff state; only `Committed`
/// carries completion authority, and it must include the canonical receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "snake_case", deny_unknown_fields)]
pub enum TestdTerminalCompletionResponse {
    Pending {
        job_id: String,
        receipt_sha256: String,
        request_digest: String,
    },
    Committed {
        job_id: String,
        receipt_sha256: String,
        request_digest: String,
        receipt: WriteReceipt,
    },
}

/// Typed failure for the authenticated testd exchange. Every variant is
/// fail-closed: the one-shot driver maps each to exit 78 without effect,
/// except through the explicit executor-owned unknown-outcome path.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TestdIpcError {
    /// The protected front door is unavailable or the transport failed
    /// before a typed Kernel reply existed.
    #[error("kernel front door unavailable: {0}")]
    Transport(String),
    /// The live Kernel does not advertise the testd operation.
    #[error("kernel does not advertise the testd operation (KERNEL_ADMISSION_REQUIRED)")]
    NotAdvertised,
    /// The exchange violated the closed contract before any effect.
    #[error("kernel testd exchange violated the closed contract: {0}")]
    Contract(String),
    /// The submit reply was lost: the request may have reached the Kernel,
    /// but its outcome was not proven by an exact typed reply. Carry the
    /// exact submit identity so a later invocation can reconcile under the
    /// same identity; this shot must not retry blind.
    #[error(
        "kernel reply lost after submit of job {job_id}; reconcile by exact identity, never blind-retry"
    )]
    UnknownOutcome {
        /// Submitted job identity.
        job_id: String,
        /// Canonical digest of the submitted envelope.
        request_digest: String,
    },
}

impl From<KernelClientError> for TestdIpcError {
    fn from(error: KernelClientError) -> Self {
        Self::Transport(error.to_string())
    }
}

/// Validates bounded wire text without carrying platform or secret material.
fn validate_wire_text(value: &str, field: &'static str) -> Result<(), TestdIpcError> {
    if value.trim().is_empty() {
        return Err(TestdIpcError::Contract(format!(
            "{field} must be non-blank"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(TestdIpcError::Contract(format!(
            "{field} must not contain control characters"
        )));
    }
    if value.len() > 1024 {
        return Err(TestdIpcError::Contract(format!(
            "{field} must not exceed 1024 UTF-8 bytes"
        )));
    }
    Ok(())
}

/// Returns true when the value is a lowercase SHA-256 digest.
fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_wire_digest(value: &str, field: &'static str) -> Result<(), TestdIpcError> {
    if !is_lowercase_sha256(value) {
        return Err(TestdIpcError::Contract(format!(
            "{field} must be a lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| {
            u64::try_from(duration.as_millis().min(u128::from(u64::MAX))).unwrap_or(u64::MAX)
        })
}

/// Wire request presenting one testd admission for Kernel admission.
///
/// The closed invocation travels by digest: Kernel parses and validates the
/// presented [`InstrumentInvocation`] delivered with the dispatch contour,
/// and never accepts executable authority from the caller. `request_digest`
/// binds the exact envelope bytes, so a byte-different retry under one job
/// identity is an identity conflict, not a silent substitution. Bare paths
/// never appear here: roots are bound by digest through the contour grant,
/// never by string equality.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdAdmissionRequest {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Job identity seed bound into the admission identity.
    pub job_id: String,
    /// Invocation identity echoed from the presented invocation bytes.
    pub invocation_id: String,
    /// Canonical digest over the presented invocation bytes.
    pub invocation_digest: String,
    /// Claimed authority epoch; the gate proves it against live authority.
    pub authority_epoch: EpochId,
    /// Claimed resource generation; the gate proves it against live authority.
    pub generation: u64,
    /// Canonical digest over this request envelope.
    pub request_digest: String,
}

impl TestdAdmissionRequest {
    /// Current testd-admission wire contract version.
    pub const CONTRACT_VERSION: u16 = TESTD_ADMISSION_OPERATION_VERSION;

    /// Computes the canonical digest over the presenting envelope bytes.
    pub fn canonical_request_digest(&self) -> Result<String, TestdIpcError> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            wire_id: &'a str,
            wire_version: u16,
            job_id: &'a str,
            invocation_id: &'a str,
            invocation_digest: &'a str,
            authority_epoch: &'a EpochId,
            generation: u64,
        }
        let canonical = Canonical {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            job_id: &self.job_id,
            invocation_id: &self.invocation_id,
            invocation_digest: &self.invocation_digest,
            authority_epoch: &self.authority_epoch,
            generation: self.generation,
        };
        canonical_json_bytes(&canonical)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| {
                TestdIpcError::Contract(
                    "testd_admission.request_digest cannot canonicalize request".to_owned(),
                )
            })
    }

    /// Returns this request with its canonical request digest populated.
    pub fn with_computed_digest(mut self) -> Result<Self, TestdIpcError> {
        self.request_digest = self.canonical_request_digest()?;
        Ok(self)
    }

    /// Validates that the request digest equals the canonical digest.
    pub fn validate_canonical_digest(&self) -> Result<(), TestdIpcError> {
        if self.request_digest != self.canonical_request_digest()? {
            return Err(TestdIpcError::Contract(
                "testd_admission.request_digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    /// Validates the closed wire shape.
    pub fn validate(&self) -> Result<(), TestdIpcError> {
        if self.wire_id != TESTD_ADMISSION_OPERATION || self.wire_version != Self::CONTRACT_VERSION
        {
            return Err(TestdIpcError::Contract(
                "unsupported testd admission wire".to_owned(),
            ));
        }
        validate_wire_text(&self.job_id, "testd_admission.job_id")?;
        validate_wire_text(&self.invocation_id, "testd_admission.invocation_id")?;
        validate_wire_digest(&self.invocation_digest, "testd_admission.invocation_digest")?;
        validate_wire_digest(&self.request_digest, "testd_admission.request_digest")?;
        if self.generation == 0 {
            return Err(TestdIpcError::Contract(
                "testd_admission.generation must be non-zero".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Computes the canonical digest over one presented invocation.
///
/// This is the byte-identity the driver re-proves: the envelope digest must
/// equal this value exactly, otherwise the presentation fails closed before
/// any submit.
pub fn canonical_invocation_digest(
    invocation: &InstrumentInvocation,
) -> Result<String, TestdIpcError> {
    canonical_json_bytes(invocation)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| {
            TestdIpcError::Contract(
                "testd_admission.invocation_digest cannot canonicalize invocation".to_owned(),
            )
        })
}

/// Kernel-issued authority projection for one admitted testd job.
///
/// This is the exact admission receipt: it carries the bound job and
/// invocation digests, the live epoch/generation tuple, the evidence
/// reference for the single start, and cancellation. The admission digest
/// is canonical over every field, so rebuilding with the durable admission
/// time reproduces the exact same admission on replay.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdAdmission {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Admitted job identity.
    pub job_id: String,
    /// Digest of the exact presented invocation bytes.
    pub invocation_digest: String,
    /// Live authority epoch bound at admission.
    pub authority_epoch: EpochId,
    /// Live resource generation bound at admission.
    pub generation: u64,
    /// Evidence handle for the single consuming start (bounded, secret-free).
    pub evidence_ref: String,
    /// Whether the job was admitted cancelled; cancelled admissions never
    /// start a process.
    pub cancelled: bool,
    /// Admission time in Unix milliseconds.
    pub admitted_at_unix_ms: u64,
    /// Canonical digest over this admission envelope.
    pub admission_digest: String,
}

impl TestdAdmission {
    /// Current testd-admission wire contract version.
    pub const CONTRACT_VERSION: u16 = TESTD_ADMISSION_OPERATION_VERSION;

    /// Computes the canonical admission digest.
    pub fn compute_digest(&self) -> Result<String, TestdIpcError> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            wire_id: &'a str,
            wire_version: u16,
            job_id: &'a str,
            invocation_digest: &'a str,
            authority_epoch: &'a EpochId,
            generation: u64,
            evidence_ref: &'a str,
            cancelled: bool,
            admitted_at_unix_ms: u64,
        }
        let canonical = Canonical {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            job_id: &self.job_id,
            invocation_digest: &self.invocation_digest,
            authority_epoch: &self.authority_epoch,
            generation: self.generation,
            evidence_ref: &self.evidence_ref,
            cancelled: self.cancelled,
            admitted_at_unix_ms: self.admitted_at_unix_ms,
        };
        canonical_json_bytes(&canonical)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| {
                TestdIpcError::Contract(
                    "testd_admission.admission_digest cannot canonicalize admission".to_owned(),
                )
            })
    }

    /// Returns this admission with its canonical digest populated.
    pub fn with_computed_digest(mut self) -> Result<Self, TestdIpcError> {
        self.admission_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates the admission shape and its canonical digest.
    pub fn validate(&self) -> Result<(), TestdIpcError> {
        if self.wire_id != TESTD_ADMISSION_OPERATION || self.wire_version != Self::CONTRACT_VERSION
        {
            return Err(TestdIpcError::Contract(
                "unsupported testd admission wire".to_owned(),
            ));
        }
        validate_wire_text(&self.job_id, "testd_admission.job_id")?;
        validate_wire_text(&self.evidence_ref, "testd_admission.evidence_ref")?;
        validate_wire_digest(&self.invocation_digest, "testd_admission.invocation_digest")?;
        validate_wire_digest(&self.admission_digest, "testd_admission.admission_digest")?;
        if self.generation == 0 || self.admitted_at_unix_ms == 0 {
            return Err(TestdIpcError::Contract(
                "testd_admission generation and admission time must be non-zero".to_owned(),
            ));
        }
        if self.compute_digest()? != self.admission_digest {
            return Err(TestdIpcError::Contract(
                "testd_admission.admission_digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Typed reason a testd admission was not admitted.
///
/// Every rejection names its cause; a refused job takes no effect and
/// consumes no admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TestdAdmissionRejectionReason {
    /// Unknown admission wire identity or version.
    UnknownWireVersion,
    /// A wire or envelope field failed bounded shape validation.
    InvalidRequestField,
    /// Presented authority epoch disagrees with the live epoch.
    StaleEpoch,
    /// Presented generation disagrees with the live generation.
    StaleGeneration,
    /// Presented invocation digest disagrees with the presented bytes.
    InvocationMismatch,
    /// The invocation kind is not admitted on this wire.
    OperationNotAdmitted,
}

/// Typed refusal for one testd admission request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdAdmissionRejection {
    /// Echo of the submitted job identity.
    pub job_ref: String,
    /// Closed refusal cause.
    pub reason: TestdAdmissionRejectionReason,
    /// Bounded, secret-free detail (never a path, secret, or raw output).
    pub detail: String,
    /// Rejection time in Unix milliseconds.
    pub rejected_at_unix_ms: u64,
}

impl TestdAdmissionRejection {
    /// Validates the bounded refusal shape.
    pub fn validate(&self) -> Result<(), TestdIpcError> {
        validate_wire_text(&self.job_ref, "testd_admission.job_ref")?;
        validate_wire_text(&self.detail, "testd_admission.detail")?;
        if self.rejected_at_unix_ms == 0 {
            return Err(TestdIpcError::Contract(
                "testd_admission rejection time must be non-zero".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Typed conflict: the job identity exists with different terms.
///
/// Changed invocation, epoch, or generation under one job identity returns
/// `Conflict` and never overwrites the durable binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdAdmissionConflict {
    /// Echo of the submitted job identity.
    pub job_id: String,
    /// Changed dimensions, each a stable field name (never a value).
    pub changed_fields: Vec<String>,
    /// Bounded, secret-free detail.
    pub detail: String,
    /// Conflict time in Unix milliseconds.
    pub conflicted_at_unix_ms: u64,
}

impl TestdAdmissionConflict {
    /// Validates the bounded conflict shape.
    pub fn validate(&self) -> Result<(), TestdIpcError> {
        validate_wire_text(&self.job_id, "testd_admission.job_id")?;
        validate_wire_text(&self.detail, "testd_admission.detail")?;
        if self.changed_fields.is_empty() || self.changed_fields.len() > 32 {
            return Err(TestdIpcError::Contract(
                "testd_admission conflict must name one to thirty-two changed fields".to_owned(),
            ));
        }
        for field in &self.changed_fields {
            validate_wire_text(field, "testd_admission.changed_fields")?;
        }
        if self.conflicted_at_unix_ms == 0 {
            return Err(TestdIpcError::Contract(
                "testd_admission conflict time must be non-zero".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Typed Kernel answer for one testd admission request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum TestdAdmissionResponse {
    /// The job is admitted; the receipt is pending independent verification.
    Admitted(Box<TestdAdmission>),
    /// The job is refused without effect.
    Rejected(TestdAdmissionRejection),
    /// The job identity exists with different terms.
    Conflict(TestdAdmissionConflict),
}

impl TestdAdmissionResponse {
    /// Validates the typed union shape.
    pub fn validate(&self) -> Result<(), TestdIpcError> {
        match self {
            Self::Admitted(admission) => admission.validate(),
            Self::Rejected(rejection) => rejection.validate(),
            Self::Conflict(conflict) => conflict.validate(),
        }
    }
}

/// Durable binding retained from exactly one admitted Kernel reply, used to
/// check the pre-start intent without a second network round trip.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RetainedTestdAdmission {
    job_id: String,
    invocation_id: String,
    invocation_digest: String,
}

/// Authenticated Kernel front-door client for testd.
///
/// The client owns transport and typed exchange only: protected-config
/// bootstrap, live advertisement probe, one full-envelope submit, and the
/// idempotent intent check against the retained admission. It mints no
/// permit, builds no [`ProcessRequest`], and executes nothing.
pub struct KernelTestdIpcClient {
    client: Arc<Mutex<KernelClient>>,
    #[allow(
        dead_code,
        reason = "dispatch contour retains the live epoch for the lineage-aware binding once the delivery seam lands"
    )]
    live_epoch: Option<EpochId>,
    retained: Option<RetainedTestdAdmission>,
}

impl KernelTestdIpcClient {
    /// Opens the authenticated generation-bound bootstrap: loads the
    /// installation-owned protected front-door declaration, completes the
    /// EBP handshake (the live `ServerHello` is checked against the
    /// protected authority epoch, generation, artifact, and snapshot inside
    /// [`KernelClient`]), and probes health. Retains the live authority
    /// epoch echoed by the authenticated health reply for the
    /// lineage-aware identity binding.
    ///
    /// Mirrors `KernelDoctorIpcClient::connect`: the same load → probe →
    /// `require_health_open` → `parse_live_epoch` sequence, with transport
    /// failures staying transport failures. Without a live composed Kernel
    /// front door this fails closed; it never invents an epoch.
    pub fn connect() -> Result<Self, TestdIpcError> {
        let mut client = KernelClient::load().map_err(TestdIpcError::from)?;
        let health = client.probe().map_err(TestdIpcError::from)?;
        require_health_open(&health)?;
        let live_epoch = parse_live_epoch(&health)?;
        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            live_epoch: Some(live_epoch),
            retained: None,
        })
    }

    /// Returns the live authority epoch retained from the authenticated
    /// bootstrap, when the bootstrap completed.
    #[must_use]
    pub fn live_epoch(&self) -> Option<&EpochId> {
        self.live_epoch.as_ref()
    }

    /// Exchanges one exact closed Blob stream operation through the
    /// authenticated TestD→Kernel capability path. The opaque capability and
    /// single-use token are the only authority-bearing inputs; TestD never
    /// creates a RequestIdentity or retries an unknown transport result.
    pub fn blob_process_stream_exchange(
        &mut self,
        capability: ProcessStreamSinkCapabilityRef,
        call_token: BlobProcessStreamCallToken,
        operation: BlobProcessStreamKernelOperationRequest,
        job_id: &str,
    ) -> Result<BlobProcessStreamKernelResponse, TestdIpcError> {
        self.blob_stream_client()
            .exchange(capability, call_token, operation, job_id)
    }

    /// Returns a cloneable handle to this already-authenticated Kernel session
    /// for the concurrent stdout/stderr sink and readback adapters.
    pub fn blob_stream_client(&self) -> KernelTestdBlobStreamClient {
        KernelTestdBlobStreamClient {
            client: self.client.clone(),
        }
    }

    /// Sends the immutable terminal receipt reference through the existing
    /// authenticated Kernel session and waits for the daemon's committed
    /// canonical WriteReceipt. Pending replies never map to success.
    pub fn publish_terminal_completion(
        &mut self,
        notice: &TestdTerminalCompletionNotice,
        binding: &TestdVerifierDispatchBinding,
        job: &TestJob,
    ) -> Result<WriteReceipt, TestdIpcError> {
        let request = TestdTerminalCompletionRequest::new(notice)?;
        binding
            .validate_for_job(job)
            .map_err(|error| TestdIpcError::Contract(error.to_string()))?;
        if job.job_id != notice.job_id
            || job
                .verification_receipt
                .as_ref()
                .map(verification_receipt_sha256)
                .transpose()
                .map_err(|error| TestdIpcError::Contract(error.to_string()))?
                .as_deref()
                != Some(notice.receipt_sha256.as_str())
        {
            return Err(TestdIpcError::Contract(
                "terminal reference differs from the durable TestD row".to_owned(),
            ));
        }
        let identity = &binding.request_identity;
        identity
            .validate()
            .map_err(|error| TestdIpcError::Contract(error.to_string()))?;
        loop {
            if unix_ms() >= identity.deadline_unix_ms {
                return Err(TestdIpcError::UnknownOutcome {
                    job_id: notice.job_id.clone(),
                    request_digest: request.request_digest.clone(),
                });
            }
            let payload = serde_json::json!({"request": &request});
            let value = {
                let mut client = self.client.lock().map_err(|_| {
                    TestdIpcError::Transport("Kernel client lock poisoned".to_owned())
                })?;
                client.set_request_identity(identity.clone());
                client
                    .transact_json(TESTD_TERMINAL_COMPLETION_OPERATION, payload)
                    .map_err(|error| match error {
                        KernelClientError::UnknownOutcome(_) => TestdIpcError::UnknownOutcome {
                            job_id: notice.job_id.clone(),
                            request_digest: request.request_digest.clone(),
                        },
                        other => TestdIpcError::Transport(other.to_string()),
                    })?
            };
            let response: TestdTerminalCompletionResponse = serde_json::from_value(value)
                .map_err(|error| TestdIpcError::Contract(error.to_string()))?;
            match response {
                TestdTerminalCompletionResponse::Pending {
                    job_id,
                    receipt_sha256,
                    request_digest,
                } if job_id == notice.job_id
                    && receipt_sha256 == notice.receipt_sha256
                    && request_digest == request.request_digest =>
                {
                    thread::sleep(Duration::from_millis(200));
                }
                TestdTerminalCompletionResponse::Committed {
                    job_id,
                    receipt_sha256,
                    request_digest,
                    receipt,
                } => {
                    if job_id != notice.job_id
                        || receipt_sha256 != notice.receipt_sha256
                        || request_digest != request.request_digest
                    {
                        return Err(TestdIpcError::Contract(
                            "Kernel terminal receipt response does not echo the submitted owner reference"
                                .to_owned(),
                        ));
                    }
                    receipt
                        .validate()
                        .map_err(|error| TestdIpcError::Contract(error.to_string()))?;
                    let expected_operation = format!("{}/verifier-execution", binding.operation_id);
                    let expected_idempotency =
                        format!("{}:verifier-execution", identity.idempotency_key);
                    if receipt.status != WriteReceiptStatus::Committed
                        || receipt.operation_id.as_str() != expected_operation
                        || receipt.idempotency_key != expected_idempotency
                        || receipt.state_fence != identity.request.state_fence
                    {
                        return Err(TestdIpcError::Contract(
                            "Kernel terminal response lacks the exact committed verifier WriteReceipt"
                                .to_owned(),
                        ));
                    }
                    return Ok(receipt);
                }
                _ => {
                    return Err(TestdIpcError::Contract(
                        "Kernel terminal-completion response is not bound to the request"
                            .to_owned(),
                    ));
                }
            }
        }
    }

    /// Reports whether the live Kernel advertises the exact testd
    /// admission wire. Probes live health over a fresh authenticated
    /// bootstrap and returns the health advertisement bit: `true` only when
    /// the composed Kernel explicitly advertises the wire. Absent
    /// advertisement — or an unavailable front door — means not advertised:
    /// transport failures stay transport failures and never invent
    /// authority.
    pub fn advertise_testd(&mut self) -> Result<bool, TestdIpcError> {
        let mut client = KernelClient::load().map_err(TestdIpcError::from)?;
        let health = client.probe().map_err(TestdIpcError::from)?;
        require_health_open(&health)?;
        Ok(health_advertises_testd(&health))
    }

    /// Submits one full admission envelope and returns the typed Kernel
    /// answer. The envelope is validated locally first (exact wire pair
    /// plus canonical digest); the reply is parsed as the exact
    /// [`TestdAdmissionResponse`] union, validated, and echo-checked.
    /// Refusal and conflict answers return as typed data without effect;
    /// only transport loss before a typed reply becomes
    /// [`TestdIpcError::UnknownOutcome`], carrying the submit identity for
    /// exact-identity reconciliation instead of a blind retry.
    ///
    /// Until the dispatch contour lands, the tree is unadvertised
    /// (`TESTD_ADMISSION_ADVERTISED` is `false`), so this validates the
    /// envelope and then fails closed with [`TestdIpcError::NotAdvertised`]
    /// without touching transport or executor.
    pub fn submit_testd_admission(
        &mut self,
        request: &TestdAdmissionRequest,
    ) -> Result<TestdAdmissionResponse, TestdIpcError> {
        if !route_testd_admission(&request.wire_id, request.wire_version) {
            return Err(TestdIpcError::Contract(
                "testd admission wire identity or version is not the admitted pair".to_owned(),
            ));
        }
        request.validate()?;
        request.validate_canonical_digest()?;
        if !advertise_testd_admission() {
            return Err(TestdIpcError::NotAdvertised);
        }
        Err(TestdIpcError::Transport(
            "testd dispatch contour is not delivered to this invocation form".to_owned(),
        ))
    }

    /// Checks one pre-start intent against the retained admission without a
    /// second network round trip.
    pub fn record_intent(
        &mut self,
        job_id: &str,
        invocation_id: &str,
        invocation_digest: &str,
    ) -> Result<(), TestdIpcError> {
        let retained = self.retained.as_ref().ok_or_else(|| {
            TestdIpcError::Contract(
                "no admitted job is retained for this intent; submit the full envelope first"
                    .to_owned(),
            )
        })?;
        if retained.job_id == job_id
            && retained.invocation_id == invocation_id
            && retained.invocation_digest == invocation_digest
        {
            Ok(())
        } else {
            Err(TestdIpcError::Contract(
                "start intent does not match the retained Kernel admission binding".to_owned(),
            ))
        }
    }

    /// Records one admitted reply for later intent checks. Only call with a
    /// reply that already passed [`TestdAdmission::validate`] and the echo
    /// checks in [`submit_testd_admission`].
    #[allow(
        dead_code,
        reason = "dispatch contour retains the admission once the delivery seam lands; exercised by the module tests"
    )]
    fn retain_admission(&mut self, admission: &TestdAdmission, invocation_id: &str) {
        self.retained = Some(RetainedTestdAdmission {
            job_id: admission.job_id.clone(),
            invocation_id: invocation_id.to_owned(),
            invocation_digest: admission.invocation_digest.clone(),
        });
    }
}

/// Cloneable handle for the single authenticated Kernel session shared by
/// concurrent process-stream persistence pumps.
#[derive(Clone)]
pub struct KernelTestdBlobStreamClient {
    client: Arc<Mutex<KernelClient>>,
}

impl KernelTestdBlobStreamClient {
    /// Exchanges one exact closed capability operation, consuming the
    /// supplied one-use token and preserving unknown outcomes without retry.
    pub fn exchange(
        &self,
        capability: ProcessStreamSinkCapabilityRef,
        call_token: BlobProcessStreamCallToken,
        operation: BlobProcessStreamKernelOperationRequest,
        job_id: &str,
    ) -> Result<BlobProcessStreamKernelResponse, TestdIpcError> {
        let request = BlobProcessStreamKernelRequest::new(capability, call_token, operation)
            .map_err(|error| TestdIpcError::Contract(error.to_string()))?;
        let op_digest = request.operation_sha256.clone();
        let response = self
            .client
            .lock()
            .map_err(|_| TestdIpcError::Transport("Kernel client lock poisoned".to_owned()))?
            .blob_process_stream_exchange(request.clone())
            .map_err(|error| match error {
                KernelClientError::UnknownOutcome(_) => TestdIpcError::UnknownOutcome {
                    job_id: job_id.to_owned(),
                    request_digest: op_digest.clone(),
                },
                other => TestdIpcError::Transport(other.to_string()),
            })?;
        response
            .validate_for_request(&request)
            .map_err(|_| TestdIpcError::UnknownOutcome {
                job_id: job_id.to_owned(),
                request_digest: op_digest,
            })?;
        Ok(response)
    }
}

/// A bounded one-use token sequence shared by the sink and source-readback
/// adapters for one job. Tokens are consumed before a call and never put back,
/// including when transport outcome is unknown.
#[derive(Clone)]
pub struct KernelBlobStreamCallSequence {
    client: KernelTestdBlobStreamClient,
    capability: ProcessStreamSinkCapabilityRef,
    tokens: Arc<Mutex<VecDeque<BlobProcessStreamCallToken>>>,
    job_id: String,
    store: TestdStore,
    grant_deadline_ms: u64,
}

impl KernelBlobStreamCallSequence {
    /// Binds the authenticated session to the exact material projection after
    /// the caller has compared it with the durable TestdStore grant.
    pub fn new(
        client: KernelTestdBlobStreamClient,
        capability_ref: &str,
        tokens: &[TestdBlobProcessStreamTokenRef],
        job_id: &str,
        store: TestdStore,
        grant_deadline_ms: u64,
    ) -> Result<Self, TestdIpcError> {
        let capability = ProcessStreamSinkCapabilityRef {
            reference: capability_ref.to_owned(),
        };
        capability
            .validate()
            .map_err(|error| TestdIpcError::Contract(error.to_string()))?;
        if tokens.is_empty() || tokens.len() > 8_336 || grant_deadline_ms == 0 {
            return Err(TestdIpcError::Contract(
                "Blob process-stream grant has no bounded token sequence".to_owned(),
            ));
        }
        let mut values = VecDeque::with_capacity(tokens.len());
        for (index, token) in tokens.iter().enumerate() {
            if token.ordinal == 0
                || (index > 0 && token.ordinal != tokens[index - 1].ordinal.saturating_add(1))
                || token.reference.trim().is_empty()
                || token.reference.len() > 128
                || token.reference.chars().any(char::is_control)
                || tokens[..index]
                    .iter()
                    .any(|previous| previous.reference == token.reference)
            {
                return Err(TestdIpcError::Contract(
                    "Blob call tokens are malformed or out of sequence".to_owned(),
                ));
            }
            values.push_back(BlobProcessStreamCallToken {
                reference: token.reference.clone(),
                ordinal: token.ordinal,
            });
        }
        Ok(Self {
            client,
            capability,
            tokens: Arc::new(Mutex::new(values)),
            job_id: job_id.to_owned(),
            store,
            grant_deadline_ms,
        })
    }

    /// Derives a short operation deadline no later than the Kernel-issued
    /// launch-grant expiry.
    pub fn deadline_for_budget(&self, budget_ms: u64) -> Result<u64, TestdIpcError> {
        let now = unix_ms();
        let deadline = now
            .saturating_add(budget_ms.max(1))
            .min(self.grant_deadline_ms);
        if deadline <= now {
            return Err(TestdIpcError::Transport(
                "Kernel-issued Blob capability has expired".to_owned(),
            ));
        }
        Ok(deadline)
    }

    /// Sends one validated semantic operation with its next distinct owner
    /// token. No transport, Unknown, or Unavailable result is retried.
    pub fn exchange(
        &self,
        operation: BlobProcessStreamKernelOperationRequest,
    ) -> Result<BlobProcessStreamKernelResponse, TestdIpcError> {
        operation
            .validate()
            .map_err(|error| TestdIpcError::Contract(error.to_string()))?;
        let deadline_ms = match &operation {
            BlobProcessStreamKernelOperationRequest::SinkOpen { deadline_ms, .. }
            | BlobProcessStreamKernelOperationRequest::SinkAppend { deadline_ms, .. }
            | BlobProcessStreamKernelOperationRequest::SinkFinalize { deadline_ms, .. }
            | BlobProcessStreamKernelOperationRequest::SinkAbort { deadline_ms, .. }
            | BlobProcessStreamKernelOperationRequest::SinkReadback { deadline_ms, .. }
            | BlobProcessStreamKernelOperationRequest::SinkReconcile { deadline_ms, .. } => {
                *deadline_ms
            }
            BlobProcessStreamKernelOperationRequest::SourceReadback { request } => {
                request.deadline_ms
            }
        };
        if deadline_ms > self.grant_deadline_ms || unix_ms() >= deadline_ms {
            return Err(TestdIpcError::Transport(
                "Blob operation deadline exceeds its Kernel-issued grant".to_owned(),
            ));
        }
        // Keep one lock across token consumption and the authenticated
        // exchange. Stdout, stderr, and readback share this sequence, so a
        // successor token can never overtake the operation that issued it.
        let mut tokens = self.tokens.lock().map_err(|_| {
            TestdIpcError::Transport("Blob token sequence lock poisoned".to_owned())
        })?;
        let token = tokens.pop_front().ok_or_else(|| {
            TestdIpcError::Transport("Blob call token sequence exhausted".to_owned())
        })?;
        let request = BlobProcessStreamKernelRequest::new(
            self.capability.clone(),
            token.clone(),
            operation.clone(),
        )
        .map_err(|error| TestdIpcError::Contract(error.to_string()))?;
        let operation_sha256 = request.operation_sha256.clone();
        let call_state = self
            .store
            .reserve_blob_process_stream_call(
                &self.job_id,
                &self.capability.reference,
                &token.reference,
                token.ordinal,
                &operation_sha256,
            )
            .map_err(|error| TestdIpcError::Contract(error.to_string()))?;
        if matches!(call_state, TestdBlobProcessStreamReserve::Reserved) {
            self.store
                .mark_blob_process_stream_call_dispatched(
                    &self.job_id,
                    &self.capability.reference,
                    &token.reference,
                    token.ordinal,
                    &operation_sha256,
                )
                .map_err(|error| TestdIpcError::Contract(error.to_string()))?;
        }
        let response = self.client.exchange(
            self.capability.clone(),
            token.clone(),
            operation,
            &self.job_id,
        )?;
        let compact_outcome = match &response.outcome {
            BlobProcessStreamKernelOutcome::Completed { .. } => {
                let response_bytes = canonical_json_bytes(&response)
                    .map_err(|error| TestdIpcError::Contract(error.to_string()))?;
                TestdBlobProcessStreamCallOutcome::Completed {
                    response_sha256: sha256_hex(&response_bytes),
                    // This is the real retained ORS call-result reference
                    // echoed in its authenticated token receipt.
                    response_ref: Some(response.call_token.reference.clone()),
                }
            }
            BlobProcessStreamKernelOutcome::NotStarted { .. } => {
                TestdBlobProcessStreamCallOutcome::NotStarted
            }
            BlobProcessStreamKernelOutcome::Unavailable { .. } => {
                TestdBlobProcessStreamCallOutcome::Unavailable
            }
            BlobProcessStreamKernelOutcome::Unknown { .. } => {
                TestdBlobProcessStreamCallOutcome::Unknown
            }
        };
        if let Some(next_token) = response.next_call_token.as_ref() {
            self.store
                .complete_blob_process_stream_call_and_advance(
                    &self.job_id,
                    &self.capability.reference,
                    &token.reference,
                    token.ordinal,
                    &operation_sha256,
                    compact_outcome,
                    TestdBlobProcessStreamTokenRef {
                        reference: next_token.reference.clone(),
                        ordinal: next_token.ordinal,
                    },
                )
                .map_err(|error| TestdIpcError::Contract(error.to_string()))?;
            tokens.push_back(next_token.clone());
        } else {
            self.store
                .complete_blob_process_stream_call(
                    &self.job_id,
                    &self.capability.reference,
                    &token.reference,
                    token.ordinal,
                    &operation_sha256,
                    compact_outcome,
                )
                .map_err(|error| TestdIpcError::Contract(error.to_string()))?;
        }
        Ok(response)
    }
}

/// Authenticated provider-neutral process-stream sink backed by the Kernel's
/// opaque capability and one-use call-token sequence.
#[derive(Clone)]
pub struct KernelProcessStreamSinkClient {
    calls: KernelBlobStreamCallSequence,
    /// Exact Store-issued binding references returned by Open, retained only
    /// as a bounded live-session optimization. Restart recovery resolves the
    /// original persisted intent through the Kernel owner path.
    bindings: Arc<Mutex<BTreeMap<String, ProcessStreamSinkBindingRef>>>,
}

impl KernelProcessStreamSinkClient {
    /// Uses the same authenticated session and retained one-use token sequence
    /// as source readback.
    pub fn new(calls: KernelBlobStreamCallSequence) -> Self {
        Self {
            calls,
            bindings: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    fn open_sync(
        &self,
        request: ProcessStreamSinkOpenRequest,
    ) -> Result<ProcessStreamSinkSession, ProcessStreamSinkError> {
        request.validate()?;
        let body = Box::new(serde_json::to_value(&request).map_err(|_| sink_invalid())?);
        let deadline_ms = self
            .calls
            .deadline_for_budget(5_000)
            .map_err(map_sink_ipc_error)?;
        let response = self
            .calls
            .exchange(BlobProcessStreamKernelOperationRequest::SinkOpen { body, deadline_ms })
            .map_err(map_sink_ipc_error)?;
        let owner = completed_sink_response(response)?;
        let ProcessStreamSinkWireResponse::Opened { binding } = owner else {
            return Err(ProcessStreamSinkError::ProviderUnavailable);
        };
        let session = ProcessStreamSinkSession::from_open_request(request)?;
        ensure_binding_ref(&binding, &session)?;
        let mut bindings = self
            .bindings
            .lock()
            .map_err(|_| ProcessStreamSinkError::ProviderUnavailable)?;
        if bindings.len() >= 2 && !bindings.contains_key(session.session_id().as_str()) {
            return Err(ProcessStreamSinkError::ProviderUnavailable);
        }
        bindings.insert(session.session_id().as_str().to_owned(), binding);
        Ok(session)
    }

    fn append_sync(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkAppend,
    ) -> Result<ProcessStreamSinkAppendDisposition, ProcessStreamSinkError> {
        session.validate_append(&request)?;
        let expected_sequence = request
            .sequence()
            .checked_add(1)
            .ok_or(ProcessStreamSinkError::InvalidBinding)?;
        let expected_offset = request
            .offset()
            .checked_add(request.byte_length())
            .ok_or(ProcessStreamSinkError::InvalidBinding)?;
        let operation = BlobProcessStreamKernelOperationRequest::SinkAppend {
            binding: self.binding_for_session(&session)?,
            body: Box::new(serde_json::to_value(&request).map_err(|_| sink_invalid())?),
            deadline_ms: self
                .calls
                .deadline_for_budget(request.wait_budget_ms())
                .map_err(map_sink_ipc_error)?,
        };
        let owner =
            completed_sink_response(self.calls.exchange(operation).map_err(map_sink_ipc_error)?)?;
        let ProcessStreamSinkWireResponse::AppendDisposition { body } = owner else {
            return Err(ProcessStreamSinkError::ProviderUnavailable);
        };
        let disposition: ProcessStreamSinkAppendDisposition =
            serde_json::from_value(*body).map_err(|_| sink_invalid())?;
        match &disposition {
            ProcessStreamSinkAppendDisposition::Accepted {
                next_sequence,
                next_offset,
            }
            | ProcessStreamSinkAppendDisposition::Replayed {
                next_sequence,
                next_offset,
            } if *next_sequence == expected_sequence && *next_offset == expected_offset => {
                Ok(disposition)
            }
            ProcessStreamSinkAppendDisposition::Accepted { .. }
            | ProcessStreamSinkAppendDisposition::Replayed { .. } => {
                Err(ProcessStreamSinkError::InvalidBinding)
            }
            other => Ok(other),
        }
    }

    fn finalize_sync(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkFinalizeRequest,
    ) -> Result<ProcessStreamSinkTerminal, ProcessStreamSinkError> {
        session.validate_finalize(&request)?;
        let operation = BlobProcessStreamKernelOperationRequest::SinkFinalize {
            binding: self.binding_for_session(&session)?,
            body: Box::new(serde_json::to_value(&request).map_err(|_| sink_invalid())?),
            deadline_ms: self
                .calls
                .deadline_for_budget(request.wait_budget_ms())
                .map_err(map_sink_ipc_error)?,
        };
        let response = self
            .calls
            .exchange(operation.clone())
            .map_err(map_sink_ipc_error)?;
        let (owner, original_terminal) = completed_sink_response_with_terminal(response)?;
        if original_terminal.as_ref() != Some(&operation) {
            return Err(ProcessStreamSinkError::ProviderUnavailable);
        }
        let ProcessStreamSinkWireResponse::Finalized { body } = owner else {
            return Err(ProcessStreamSinkError::ProviderUnavailable);
        };
        terminal_from_projection(&session, TerminalCommand::Finalize(request), *body)
    }

    fn abort_sync(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkAbortRequest,
    ) -> Result<ProcessStreamSinkTerminal, ProcessStreamSinkError> {
        session.validate_abort(&request)?;
        let operation = BlobProcessStreamKernelOperationRequest::SinkAbort {
            binding: self.binding_for_session(&session)?,
            body: Box::new(serde_json::to_value(&request).map_err(|_| sink_invalid())?),
            deadline_ms: self
                .calls
                .deadline_for_budget(request.wait_budget_ms())
                .map_err(map_sink_ipc_error)?,
        };
        let response = self
            .calls
            .exchange(operation.clone())
            .map_err(map_sink_ipc_error)?;
        let (owner, original_terminal) = completed_sink_response_with_terminal(response)?;
        if original_terminal.as_ref() != Some(&operation) {
            return Err(ProcessStreamSinkError::ProviderUnavailable);
        }
        let ProcessStreamSinkWireResponse::Aborted { body } = owner else {
            return Err(ProcessStreamSinkError::ProviderUnavailable);
        };
        terminal_from_projection(&session, TerminalCommand::Abort(request), *body)
    }

    fn readback_sync(
        &self,
        session: ProcessStreamSinkSession,
    ) -> Result<ProcessStreamSinkReadback, ProcessStreamSinkError> {
        let operation = BlobProcessStreamKernelOperationRequest::SinkReadback {
            binding: self.binding_for_session(&session)?,
            deadline_ms: self
                .calls
                .deadline_for_budget(2_000)
                .map_err(map_sink_ipc_error)?,
        };
        let response = self.calls.exchange(operation).map_err(map_sink_ipc_error)?;
        let (owner, original_terminal) = completed_sink_response_with_terminal(response)?;
        let ProcessStreamSinkWireResponse::Readback { body } = owner else {
            return Err(ProcessStreamSinkError::ProviderUnavailable);
        };
        readback_from_projection(&session, original_terminal.as_ref(), *body)
    }

    fn reconcile_sync(
        &self,
        session: ProcessStreamSinkSession,
        outcome: ProcessStreamSinkUnknownOutcome,
    ) -> Result<ProcessStreamSinkReadback, ProcessStreamSinkError> {
        outcome.validate_against_session(&session)?;
        let operation = BlobProcessStreamKernelOperationRequest::SinkReconcile {
            binding: self.binding_for_session(&session)?,
            body: Box::new(serde_json::to_value(&outcome).map_err(|_| sink_invalid())?),
            deadline_ms: self
                .calls
                .deadline_for_budget(2_000)
                .map_err(map_sink_ipc_error)?,
        };
        let response = self.calls.exchange(operation).map_err(map_sink_ipc_error)?;
        let (owner, original_terminal) = completed_sink_response_with_terminal(response)?;
        let ProcessStreamSinkWireResponse::Readback { body } = owner else {
            return Err(ProcessStreamSinkError::ProviderUnavailable);
        };
        readback_from_projection(&session, original_terminal.as_ref(), *body)
    }

    fn binding_for_session(
        &self,
        session: &ProcessStreamSinkSession,
    ) -> Result<ProcessStreamSinkBindingRef, ProcessStreamSinkError> {
        let binding = self
            .bindings
            .lock()
            .map_err(|_| ProcessStreamSinkError::ProviderUnavailable)?
            .get(session.session_id().as_str())
            .cloned()
            .ok_or(ProcessStreamSinkError::BindingMismatch)?;
        ensure_binding_ref(&binding, session)?;
        Ok(binding)
    }
}

impl ProcessStreamSinkClient for KernelProcessStreamSinkClient {
    fn open(
        &self,
        request: ProcessStreamSinkOpenRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkSession> {
        let client = self.clone();
        blocking_sink_future(5_000, move || client.open_sync(request))
    }

    fn append(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkAppend,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkAppendDisposition> {
        let budget_ms = request.wait_budget_ms();
        let client = self.clone();
        blocking_sink_future(budget_ms, move || client.append_sync(session, request))
    }

    fn finalize(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkFinalizeRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkTerminal> {
        let budget_ms = request.wait_budget_ms();
        let client = self.clone();
        blocking_sink_future(budget_ms, move || client.finalize_sync(session, request))
    }

    fn abort(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkAbortRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkTerminal> {
        let budget_ms = request.wait_budget_ms();
        let client = self.clone();
        blocking_sink_future(budget_ms, move || client.abort_sync(session, request))
    }

    fn readback(
        &self,
        session: ProcessStreamSinkSession,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkReadback> {
        let client = self.clone();
        blocking_sink_future(2_000, move || client.readback_sync(session))
    }

    fn reconcile(
        &self,
        session: ProcessStreamSinkSession,
        outcome: ProcessStreamSinkUnknownOutcome,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkReadback> {
        let client = self.clone();
        blocking_sink_future(2_000, move || client.reconcile_sync(session, outcome))
    }
}

fn blocking_sink_future<T, F>(budget_ms: u64, operation: F) -> ProcessStreamSinkFuture<'static, T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ProcessStreamSinkError> + Send + 'static,
{
    Box::pin(async move {
        let blocking = tokio::task::spawn_blocking(operation);
        match tokio::time::timeout(Duration::from_millis(budget_ms.max(1)), blocking).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) | Err(_) => Err(ProcessStreamSinkError::UnknownOutcome),
        }
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalProjection {
    session_id: serde_json::Value,
    source_id: serde_json::Value,
    terminal_id: serde_json::Value,
    open_request_sha256: String,
    state: ProcessStreamSinkState,
    final_sequence: u64,
    final_offset: u64,
    admitted_chunks: u64,
    admitted_bytes: u64,
    admitted_sha256: String,
    command_identity: serde_json::Value,
    evidence: ProcessStreamEvidence,
    terminal_sha256: String,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
enum ReadbackProjection {
    Session {
        view: ProcessStreamSinkSessionView,
    },
    Terminal {
        terminal: serde_json::Value,
    },
    UnknownOutcome {
        outcome: ProcessStreamSinkUnknownOutcome,
    },
}

fn ensure_binding_ref(
    binding: &ProcessStreamSinkBindingRef,
    session: &ProcessStreamSinkSession,
) -> Result<(), ProcessStreamSinkError> {
    binding
        .validate()
        .map_err(|_| ProcessStreamSinkError::InvalidBinding)?;
    if binding.session_id != session.session_id().as_str()
        || binding.source_id != session.source_id().as_str()
        || binding.terminal_id != session.terminal_id().as_str()
        || binding.open_request_sha256 != session.open_request_sha256()
        || binding.binding_ref.trim().is_empty()
    {
        return Err(ProcessStreamSinkError::BindingMismatch);
    }
    Ok(())
}

fn completed_sink_response(
    response: BlobProcessStreamKernelResponse,
) -> Result<ProcessStreamSinkWireResponse, ProcessStreamSinkError> {
    match response.outcome {
        BlobProcessStreamKernelOutcome::Completed { response, .. } => match response.operation {
            BlobProcessStreamOperationResponse::Sink { response } => Ok(response),
            BlobProcessStreamOperationResponse::SourceReadback { .. } => {
                Err(ProcessStreamSinkError::UnknownOutcome)
            }
        },
        BlobProcessStreamKernelOutcome::Unknown { .. } => {
            Err(ProcessStreamSinkError::UnknownOutcome)
        }
        BlobProcessStreamKernelOutcome::NotStarted { .. }
        | BlobProcessStreamKernelOutcome::Unavailable { .. } => {
            Err(ProcessStreamSinkError::ProviderUnavailable)
        }
    }
}

fn completed_sink_response_with_terminal(
    response: BlobProcessStreamKernelResponse,
) -> Result<
    (
        ProcessStreamSinkWireResponse,
        Option<BlobProcessStreamKernelOperationRequest>,
    ),
    ProcessStreamSinkError,
> {
    match response.outcome {
        BlobProcessStreamKernelOutcome::Completed {
            response,
            original_terminal_request,
            ..
        } => match response.operation {
            BlobProcessStreamOperationResponse::Sink { response } => {
                Ok((response, original_terminal_request.map(|request| *request)))
            }
            BlobProcessStreamOperationResponse::SourceReadback { .. } => {
                Err(ProcessStreamSinkError::UnknownOutcome)
            }
        },
        BlobProcessStreamKernelOutcome::Unknown { .. } => {
            Err(ProcessStreamSinkError::UnknownOutcome)
        }
        BlobProcessStreamKernelOutcome::NotStarted { .. }
        | BlobProcessStreamKernelOutcome::Unavailable { .. } => {
            Err(ProcessStreamSinkError::ProviderUnavailable)
        }
    }
}

enum TerminalCommand {
    Finalize(ProcessStreamSinkFinalizeRequest),
    Abort(ProcessStreamSinkAbortRequest),
}

fn terminal_from_projection(
    session: &ProcessStreamSinkSession,
    command: TerminalCommand,
    body: serde_json::Value,
) -> Result<ProcessStreamSinkTerminal, ProcessStreamSinkError> {
    let projection: TerminalProjection =
        serde_json::from_value(*body).map_err(|_| sink_invalid())?;
    if projection.session_id
        != serde_json::to_value(session.session_id()).map_err(|_| sink_invalid())?
        || projection.source_id
            != serde_json::to_value(session.source_id()).map_err(|_| sink_invalid())?
        || projection.terminal_id
            != serde_json::to_value(session.terminal_id()).map_err(|_| sink_invalid())?
        || projection.open_request_sha256 != session.open_request_sha256()
        || projection.admitted_chunks != projection.final_sequence
        || projection.admitted_bytes != projection.final_offset
    {
        return Err(ProcessStreamSinkError::BindingMismatch);
    }
    let terminal = match command {
        TerminalCommand::Finalize(request) => ProcessStreamSinkTerminal::from_finalize(
            session.clone(),
            request,
            projection.state,
            projection.final_sequence,
            projection.final_offset,
            projection.admitted_sha256,
            projection.evidence,
        )?,
        TerminalCommand::Abort(request) => ProcessStreamSinkTerminal::from_abort(
            session.clone(),
            request,
            projection.state,
            projection.final_sequence,
            projection.final_offset,
            projection.admitted_sha256,
            projection.evidence,
        )?,
    };
    terminal.validate()?;
    if terminal.identity_sha256() != projection.terminal_sha256
        || serde_json::to_value(terminal.command_identity()).map_err(|_| sink_invalid())?
            != projection.command_identity
        || serde_json::to_value(&terminal).map_err(|_| sink_invalid())? != body
    {
        return Err(ProcessStreamSinkError::TerminalIdentityConflict);
    }
    Ok(terminal)
}

fn terminal_from_retained_operation(
    session: &ProcessStreamSinkSession,
    operation: &BlobProcessStreamKernelOperationRequest,
    body: serde_json::Value,
) -> Result<ProcessStreamSinkTerminal, ProcessStreamSinkError> {
    match operation {
        BlobProcessStreamKernelOperationRequest::SinkFinalize {
            binding,
            body: request_body,
            ..
        } => {
            ensure_binding_ref(binding, session)?;
            let request: ProcessStreamSinkFinalizeRequest =
                serde_json::from_value((**request_body).clone()).map_err(|_| sink_invalid())?;
            terminal_from_projection(session, TerminalCommand::Finalize(request), body)
        }
        BlobProcessStreamKernelOperationRequest::SinkAbort {
            binding,
            body: request_body,
            ..
        } => {
            ensure_binding_ref(binding, session)?;
            let request: ProcessStreamSinkAbortRequest =
                serde_json::from_value((**request_body).clone()).map_err(|_| sink_invalid())?;
            terminal_from_projection(session, TerminalCommand::Abort(request), body)
        }
        _ => Err(ProcessStreamSinkError::ProviderUnavailable),
    }
}

fn readback_from_projection(
    session: &ProcessStreamSinkSession,
    original_terminal: Option<&BlobProcessStreamKernelOperationRequest>,
    body: serde_json::Value,
) -> Result<ProcessStreamSinkReadback, ProcessStreamSinkError> {
    match serde_json::from_value::<ReadbackProjection>(body.clone()).map_err(|_| sink_invalid())? {
        ReadbackProjection::Session { view } => {
            if view.session_id() != session.session_id()
                || view.source_id() != session.source_id()
                || view.terminal_id() != session.terminal_id()
                || view.open_request_sha256() != session.open_request_sha256()
            {
                return Err(ProcessStreamSinkError::BindingMismatch);
            }
            Ok(ProcessStreamSinkReadback::Session { view })
        }
        ReadbackProjection::Terminal { terminal } => {
            let operation = original_terminal.ok_or(ProcessStreamSinkError::ProviderUnavailable)?;
            let terminal = terminal_from_retained_operation(session, operation, terminal)?;
            Ok(ProcessStreamSinkReadback::Terminal { terminal })
        }
        ReadbackProjection::UnknownOutcome { outcome } => {
            outcome.validate_against_session(session)?;
            Ok(ProcessStreamSinkReadback::UnknownOutcome { outcome })
        }
    }
}

fn map_sink_ipc_error(error: TestdIpcError) -> ProcessStreamSinkError {
    match error {
        TestdIpcError::UnknownOutcome { .. } => ProcessStreamSinkError::UnknownOutcome,
        _ => ProcessStreamSinkError::ProviderUnavailable,
    }
}

fn sink_invalid() -> ProcessStreamSinkError {
    ProcessStreamSinkError::InvalidRequest {
        reason: "Kernel sink response did not match its closed projection",
    }
}

impl KernelProcessAdmissionProvider for KernelTestdIpcClient {
    fn admit(
        &self,
        _request: &KernelProcessAdmissionRequest,
    ) -> Result<KernelProcessAdmissionEvidence, TestdError> {
        Err(TestdError::Contract(
            "legacy KernelProcessAdmissionRequest cannot carry the testd admission identity (job seed, invocation digest, epoch/generation binding); present the full TestdAdmissionRequest envelope via submit_testd_admission"
                .to_owned(),
        ))
    }
}

/// Thin admitted transport behind one exact admission envelope.
///
/// Implemented by [`KernelTestdIpcClient`] in production (through the
/// authenticated transact seam once the dispatch contour lands) and by
/// clearly-marked test doubles where a live Kernel is unavailable.
/// Transport failures stay transport failures; they are never mapped to
/// admission or success. A test double must validate the envelope and
/// echo-check the reply exactly like
/// [`KernelTestdIpcClient::submit_testd_admission`].
pub trait AdmittedTestdTransport {
    /// Submits one full admission envelope; the wire selector is a contract
    /// constant, never caller authority.
    fn submit_testd_admission(
        &mut self,
        request: &TestdAdmissionRequest,
    ) -> Result<TestdAdmissionResponse, TestdIpcError>;
}

impl AdmittedTestdTransport for KernelTestdIpcClient {
    fn submit_testd_admission(
        &mut self,
        request: &TestdAdmissionRequest,
    ) -> Result<TestdAdmissionResponse, TestdIpcError> {
        KernelTestdIpcClient::submit_testd_admission(self, request)
    }
}

/// Requires the authenticated health reply to report an open Kernel.
fn require_health_open(health: &serde_json::Value) -> Result<(), TestdIpcError> {
    if health.get("status").and_then(serde_json::Value::as_str) != Some("OPEN") {
        return Err(TestdIpcError::Transport(
            "kernel health handshake was not OPEN".to_owned(),
        ));
    }
    Ok(())
}

/// Parses the live authority epoch echoed by the authenticated health reply.
/// The value travels over the session the handshake already bound to the
/// protected declaration; it is never taken from argv, stdin, or
/// environment.
fn parse_live_epoch(health: &serde_json::Value) -> Result<EpochId, TestdIpcError> {
    let epoch_value = health.get("authority_epoch").ok_or_else(|| {
        TestdIpcError::Contract("kernel health reply carries no live authority epoch".to_owned())
    })?;
    serde_json::from_value(epoch_value.clone()).map_err(|_| {
        TestdIpcError::Contract(
            "kernel health reply authority epoch is not a lineaged epoch".to_owned(),
        )
    })
}

/// Reports whether the authenticated health reply explicitly advertises the
/// exact testd admission wire. Absent advertisement fields mean not
/// advertised: the check is fail-closed and never invents authority.
fn health_advertises_testd(health: &serde_json::Value) -> bool {
    if health
        .get("testd_admission_advertised")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        return true;
    }
    health
        .get("operations")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|operations| {
            operations
                .iter()
                .any(|operation| operation.as_str() == Some(TESTD_ADMISSION_OPERATION))
        })
}

/// Returns true for the read-only diagnose-equivalent path: any invocation
/// whose kind is not `TEST` binds no test execution identity and needs no
/// Kernel effect admission, so it must be answered from diagnosis evidence
/// rather than submitted. This check is pure: it reads the already-parsed
/// invocation, stages nothing, and advances nothing.
#[must_use]
pub fn is_testd_diagnose_only_invocation(invocation: &InstrumentInvocation) -> bool {
    !matches!(invocation.kind, InstrumentKind::Test)
}

/// Validates the envelope/invocation byte-identity without touching
/// transport or executor.
///
/// Re-derives the canonical invocation digest from the presented bytes and
/// proves the envelope echoes it, the invocation identity, and the claimed
/// fence. Identity is exactly (`job_id`, `invocation_digest`,
/// `authority_epoch` exact tuple, `generation`); bare paths never decide.
pub fn validate_envelope_invocation_binding(
    request: &TestdAdmissionRequest,
    invocation: &InstrumentInvocation,
) -> Result<(), TestdIpcError> {
    if !route_testd_admission(&request.wire_id, request.wire_version) {
        return Err(TestdIpcError::Contract(
            "testd admission wire identity or version is not the admitted pair".to_owned(),
        ));
    }
    request.validate()?;
    request.validate_canonical_digest()?;
    invocation
        .validate()
        .map_err(|error| TestdIpcError::Contract(error.to_string()))?;
    if invocation.request.request_id.as_str() != request.invocation_id {
        return Err(TestdIpcError::Contract(
            "testd admission invocation identity mismatch".to_owned(),
        ));
    }
    if canonical_invocation_digest(invocation)? != request.invocation_digest {
        return Err(TestdIpcError::Contract(
            "testd admission invocation digest mismatch".to_owned(),
        ));
    }
    if !invocation
        .request
        .state_fence
        .authority_epoch
        .is_same_authority(&request.authority_epoch)
    {
        return Err(TestdIpcError::Contract(
            "testd admission fence epoch disagrees with the envelope epoch".to_owned(),
        ));
    }
    if invocation.request.state_fence.resource_generation.value() != request.generation {
        return Err(TestdIpcError::Contract(
            "testd admission fence generation disagrees with the envelope generation".to_owned(),
        ));
    }
    Ok(())
}

/// Validates one concrete consuming [`ProcessRequest`] against the presented
/// invocation and the live epoch.
///
/// Checks the sealed request (`ProcessRequest::validate`, the same call
/// `issue_process_admission` makes), the fence exact-tuple binding against
/// the live epoch, and the job/operation/digest binding to the invocation.
/// Bare paths, PIDs, and service names are never compared here: they are
/// not identity.
pub fn validate_process_binding(
    process: &ProcessRequest,
    invocation: &InstrumentInvocation,
    live_epoch: &EpochId,
    expected_generation: u64,
) -> Result<(), TestdIpcError> {
    process
        .validate()
        .map_err(|error| TestdIpcError::Contract(error.to_string()))?;
    if !process
        .fence()
        .authority_epoch()
        .is_same_authority(live_epoch)
    {
        return Err(TestdIpcError::Contract(
            "testd process fence epoch disagrees with the live epoch".to_owned(),
        ));
    }
    if process.generation().get() != expected_generation {
        return Err(TestdIpcError::Contract(
            "testd process generation disagrees with the admitted generation".to_owned(),
        ));
    }
    if process.operation_id().as_str() != invocation.request.request_id.as_str() {
        return Err(TestdIpcError::Contract(
            "testd process operation disagrees with the invocation identity".to_owned(),
        ));
    }
    if !invocation
        .request
        .state_fence
        .authority_epoch
        .is_same_authority(live_epoch)
    {
        return Err(TestdIpcError::Contract(
            "testd invocation fence disagrees with the live epoch".to_owned(),
        ));
    }
    Ok(())
}

/// Material presented to one one-shot invocation by the dispatch contour.
///
/// Every identity-bearing value arrives with the authenticated dispatch,
/// never from argv, stdin, or environment. The byte-identity between the
/// envelope and the presented invocation bytes is re-proved by the driver;
/// a mismatch fails closed before any submit. The concrete
/// [`ProcessRequest`] is an in-memory composition value, never
/// deserialized.
pub struct PresentedAdmission {
    /// Full wire envelope: job seed, invocation digest, claimed
    /// epoch/generation, and canonical digest.
    pub request: TestdAdmissionRequest,
    /// Parsed invocation; must digest-match the envelope bytes exactly.
    pub invocation: InstrumentInvocation,
    /// Concrete IPC-delivered process request for the single consuming
    /// start. An in-memory composition value, never deserialized.
    pub process: ProcessRequest,
    /// Live Kernel epoch from the authenticated bootstrap, used for the
    /// lineage-aware binding. Never envelope bytes.
    pub epoch: EpochId,
    /// Bounded evidence handle for the single consuming start.
    pub evidence_ref: String,
    /// Cancellation flag; when true the driver projects cancellation
    /// without executing.
    pub cancelled: bool,
}

/// Typed outcome for exactly one admitted one-shot admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TestdDriveOutcome {
    /// A diagnose-equivalent (non-TEST) invocation was classified without
    /// admission or effect.
    Diagnosed {
        /// Echo of the presented job identity.
        job_id: String,
    },
    /// The single consuming process started; verification owns disposition.
    Completed {
        /// Echo of the presented job identity.
        job_id: String,
        /// Echo of the presented evidence handle.
        evidence_ref: String,
    },
    /// A cancelled admission was projected without executing.
    Cancelled {
        /// Echo of the presented job identity.
        job_id: String,
    },
    /// The start outcome is unknown: reconcile by the exact digest, never
    /// blind-retry.
    ReconcileRequired {
        /// Echo of the presented job identity.
        job_id: String,
        /// Canonical digest of the submitted envelope; the exact
        /// reconciliation key.
        reconciliation_key: String,
    },
}

/// Closed-profile Drive gate (issue #20): only registered profiles
/// drive. Fixed-argv profiles take no caller arguments: the fixed argv
/// comes from the registry binding (see `eliot_testd_core`), never from
/// the invocation. Slotted profiles (issue #1802, step 4) validate their
/// arguments through the slot schema. Anything else fails closed before
/// any submit or process start.
fn check_drive_profile(invocation: &InstrumentInvocation) -> Result<(), TestdIpcError> {
    if !eliot_testd_core::is_admitted_testd_profile(&invocation.profile) {
        return Err(TestdIpcError::Contract(
            "testd admits only the closed cargo-test tool-probe profile".to_owned(),
        ));
    }
    if !invocation.arguments.is_empty() {
        if eliot_testd_core::is_slotted_testd_profile(&invocation.profile) {
            eliot_testd_core::parse_testd_slot_suffix(&invocation.profile, &invocation.arguments)
                .map_err(|error| TestdIpcError::Contract(error.to_string()))?;
        } else {
            return Err(TestdIpcError::Contract(
                "the admitted profile takes fixed argv; caller arguments are refused".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Reconciles one unknown testd admission delivery without admitting again.
///
/// Lost-reply path: the caller retains a previously returned admission and,
/// on an uncertain delivery, proves it still binds the exact presented
/// envelope under live authority. The invocation digest and the
/// epoch/generation tuple are compared deterministically; nothing is
/// mutated and no new effect is minted. Returns `true` only when the
/// retained admission is exactly this delivery's admission.
pub fn reconcile_testd_delivery(
    admission: &TestdAdmission,
    request: &TestdAdmissionRequest,
    invocation_digest: &str,
    live_epoch: &EpochId,
) -> Result<bool, TestdIpcError> {
    admission.validate()?;
    request.validate()?;
    request.validate_canonical_digest()?;
    if !live_epoch.is_same_authority(&admission.authority_epoch) {
        return Err(TestdIpcError::Contract(
            "testd reconcile live epoch disagrees with the admission epoch".to_owned(),
        ));
    }
    Ok(admission.job_id == request.job_id
        && admission.invocation_digest == request.invocation_digest
        && admission.invocation_digest == invocation_digest
        && admission
            .authority_epoch
            .is_same_authority(&request.authority_epoch)
        && admission.authority_epoch.is_same_authority(live_epoch)
        && admission.generation == request.generation)
}

/// Drives exactly one admitted one-shot admission to exactly one typed
/// outcome.
///
/// Sequence: prove envelope/invocation byte-identity; route
/// diagnose-equivalent (non-TEST) invocations to the read-only path without
/// touching transport or executor; submit the full envelope once; map
/// refusal and conflict to fail-closed admission errors without effect;
/// validate the admitted reply and its echo plus the recomputed
/// lineage-aware digests; project cancelled admissions without executing;
/// then run the single consuming process through the bound executor and
/// return its one typed outcome. A lost submit reply exits the shot as a
/// transport failure without retry; executor-side unknown outcomes return
/// [`TestdDriveOutcome::ReconcileRequired`] keyed by the same digest,
/// never a blind retry.
pub async fn drive_presented_admission<T, E>(
    transport: &mut T,
    executor: Arc<E>,
    sink: Arc<dyn ProcessEvidenceSink>,
    presented: PresentedAdmission,
    _now_unix_ms: u64,
) -> Result<TestdDriveOutcome, TestdIpcError>
where
    T: AdmittedTestdTransport,
    E: ProcessExecutor + 'static,
{
    let PresentedAdmission {
        request,
        invocation,
        process,
        epoch,
        evidence_ref,
        cancelled,
    } = presented;
    validate_envelope_invocation_binding(&request, &invocation)?;
    validate_wire_text(&evidence_ref, "testd_admission.evidence_ref")?;
    if !epoch.is_same_authority(&request.authority_epoch) {
        return Err(TestdIpcError::Contract(
            "testd live epoch disagrees with the envelope epoch".to_owned(),
        ));
    }
    if is_testd_diagnose_only_invocation(&invocation) {
        return Ok(TestdDriveOutcome::Diagnosed {
            job_id: request.job_id.clone(),
        });
    }
    check_drive_profile(&invocation)?;
    validate_process_binding(&process, &invocation, &epoch, request.generation)?;
    let response = transport
        .submit_testd_admission(&request)
        .map_err(|error| match error {
            TestdIpcError::UnknownOutcome {
                job_id,
                request_digest,
            } => TestdIpcError::UnknownOutcome {
                job_id,
                request_digest,
            },
            other => other,
        })?;
    response.validate()?;
    let admission = match response {
        TestdAdmissionResponse::Admitted(admission) => admission,
        TestdAdmissionResponse::Rejected(rejection) => {
            if rejection.job_ref != request.job_id {
                return Err(TestdIpcError::Contract(
                    "kernel rejection did not echo the submitted job identity".to_owned(),
                ));
            }
            return Err(TestdIpcError::Contract(format!(
                "kernel refused testd admission: {:?}",
                rejection.reason
            )));
        }
        TestdAdmissionResponse::Conflict(conflict) => {
            if conflict.job_id != request.job_id {
                return Err(TestdIpcError::Contract(
                    "kernel conflict did not echo the submitted job identity".to_owned(),
                ));
            }
            return Err(TestdIpcError::Contract(
                "kernel reported testd admission conflict under this job identity".to_owned(),
            ));
        }
    };
    if admission.job_id != request.job_id {
        return Err(TestdIpcError::Contract(
            "kernel admission did not echo the submitted job identity".to_owned(),
        ));
    }
    if admission.invocation_digest != request.invocation_digest {
        return Err(TestdIpcError::Contract(
            "kernel admission invocation digest disagrees with the submitted envelope".to_owned(),
        ));
    }
    if !admission.authority_epoch.is_same_authority(&epoch) {
        return Err(TestdIpcError::Contract(
            "kernel admission epoch disagrees with the live epoch".to_owned(),
        ));
    }
    if cancelled || admission.cancelled {
        return Ok(TestdDriveOutcome::Cancelled {
            job_id: request.job_id.clone(),
        });
    }
    match executor.start(process, sink).await {
        Ok(_receipt) => Ok(TestdDriveOutcome::Completed {
            job_id: request.job_id.clone(),
            evidence_ref,
        }),
        Err(ProcessExecutionError::UnknownOutcome) => Ok(TestdDriveOutcome::ReconcileRequired {
            job_id: request.job_id.clone(),
            reconciliation_key: request.request_digest.clone(),
        }),
        Err(error) => Err(TestdIpcError::Contract(error.to_string())),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures intentionally panic when construction invariants fail"
)]
mod tests {
    use super::*;
    use eliot_contracts::EpochLineageId;
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const JOB_ID: &str = "job-testd-1";
    const INVOCATION_ID: &str = "operation-1";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("test lineage"),
            NonZeroU64::new(sequence).expect("test sequence"),
        )
        .expect("test epoch")
    }

    fn digest(byte: u8) -> String {
        (0..32).map(|_| format!("{byte:02x}")).collect()
    }

    fn test_invocation() -> InstrumentInvocation {
        serde_json::from_value(serde_json::json!({
            "request": {
                "request_id": INVOCATION_ID,
                "session_id": null,
                "task_id": null,
                "product_id": "product-1",
                "source_id": "source-1",
                "state_fence": {
                    "authority_epoch": {
                        "lineage_id": TEST_LINEAGE,
                        "sequence": 7
                    },
                    "resource_generation": 1,
                    "task_revision": null,
                    "policy_revision": null,
                    "integration_revision": null
                },
                "clock": {
                    "valid_time_ms": 1,
                    "known_time_ms": 1,
                    "transaction_sequence": null,
                    "monotonic_ns": 1
                }
            },
            "instrument": "eliot.instrument.test",
            "kind": "TEST",
            "profile": "cargo-test",
            "target": "C:\\source",
            "arguments": [],
            "input_artifacts": [],
            "declared_scope": "workspace",
            "requested_at": {
                "valid_time_ms": 1,
                "known_time_ms": 1,
                "transaction_sequence": null,
                "monotonic_ns": 1
            }
        }))
        .expect("test invocation")
    }

    fn test_envelope(job_id: &str) -> TestdAdmissionRequest {
        let invocation = test_invocation();
        let invocation_digest =
            canonical_invocation_digest(&invocation).expect("invocation digest");
        TestdAdmissionRequest {
            wire_id: TESTD_ADMISSION_OPERATION.to_owned(),
            wire_version: TESTD_ADMISSION_OPERATION_VERSION,
            job_id: job_id.to_owned(),
            invocation_id: invocation.request.request_id.as_str().to_owned(),
            invocation_digest,
            authority_epoch: test_epoch(7),
            generation: 1,
            request_digest: String::new(),
        }
        .with_computed_digest()
        .expect("envelope digest")
    }

    /// Test-only bootstrap for [`KernelTestdIpcClient`].
    ///
    /// Sources `client` through the real production path —
    /// [`KernelClient::load`], the same protected installation-owned
    /// front-door declaration [`KernelTestdIpcClient::connect`] uses — and
    /// pairs it with the caller-supplied epoch contour. Returns `None` when
    /// no composed Kernel front door is available; callers skip fail-closed
    /// there, exactly like production refuses to invent authority without
    /// the live bootstrap.
    fn testd_client_fixture(live_epoch: Option<EpochId>) -> Option<KernelTestdIpcClient> {
        KernelClient::load()
            .ok()
            .map(|client| KernelTestdIpcClient {
                client: Arc::new(Mutex::new(client)),
                live_epoch,
                retained: None,
            })
    }

    #[test]
    fn testd_admission_wire_identity_is_stable() {
        assert_eq!(TESTD_ADMISSION_OPERATION, "eliot.kernel.testd-admission");
        assert!(route_testd_admission(
            TESTD_ADMISSION_OPERATION,
            TESTD_ADMISSION_OPERATION_VERSION
        ));
        assert!(!route_testd_admission("eliot.kernel.unknown", 1));
        assert!(!route_testd_admission(TESTD_ADMISSION_OPERATION, 99));
        assert_eq!(TESTD_ADMISSION_OPERATION_VERSION, 1);
        assert!(!advertise_testd_admission());
        assert_eq!(TESTD_ADMISSION_ADVERTISED, false);
    }

    #[test]
    fn envelope_digest_round_trip_and_tamper_rejected() {
        let envelope = test_envelope(JOB_ID);
        assert!(envelope.validate().is_ok());
        assert!(envelope.validate_canonical_digest().is_ok());
        let mut tampered = envelope.clone();
        tampered.job_id = "job-other".to_owned();
        assert!(tampered.validate_canonical_digest().is_err());
        let mut bad_wire = envelope.clone();
        bad_wire.wire_id = "eliot.kernel.unknown".to_owned();
        bad_wire = bad_wire
            .with_computed_digest()
            .expect("recompute tampered digest");
        assert!(bad_wire.validate().is_err());
    }

    #[test]
    fn legacy_provider_admit_refuses_fail_closed() {
        let Some(client) = testd_client_fixture(None) else {
            // No composed Kernel front door: without the protected
            // declaration there is no transport to refuse through, and the
            // fixture never invents one.
            return;
        };
        let invocation = test_invocation();
        let request = KernelProcessAdmissionRequest {
            job_id: JOB_ID.to_owned(),
            project_id: "project-1".to_owned(),
            invocation,
            source_root: "C:\\source".to_owned(),
            target_root: "C:\\contour\\build".to_owned(),
            cache_root: "C:\\contour\\build".to_owned(),
        };
        let refused = client.admit(&request);
        assert!(matches!(refused, Err(TestdError::Contract(_))));
        // A bare provider request never mints admission material.
        assert!(client.live_epoch().is_none());
    }

    #[test]
    fn unadvertised_submit_validates_then_fails_closed_without_effect() {
        // Without a live composed front door the bootstrap fails closed as
        // transport; on a composed host it succeeds with a retained epoch.
        // This needs no fixture transport, so it always runs.
        match KernelTestdIpcClient::connect() {
            Ok(bootstrapped) => assert!(bootstrapped.live_epoch().is_some()),
            Err(TestdIpcError::Transport(_)) => {}
            Err(other) => panic!("connect must stay transport-fail-closed, got {other:?}"),
        }
        let Some(mut client) = testd_client_fixture(Some(test_epoch(7))) else {
            // No composed Kernel front door: the submit/advertise probes
            // below need the bootstrapped transport, which is never invented.
            return;
        };
        let envelope = test_envelope(JOB_ID);
        let refused = client.submit_testd_admission(&envelope);
        assert!(matches!(refused, Err(TestdIpcError::NotAdvertised)));
        // Live advertisement probes the composed Kernel and never invents
        // authority: without a composed front door this is either a closed
        // `Ok(false)` or a transport failure, never `Ok(true)`.
        assert_ne!(client.advertise_testd(), Ok(true));
    }

    #[test]
    fn health_probe_helpers_fail_closed() {
        let closed = serde_json::json!({"status": "CLOSED"});
        assert!(require_health_open(&closed).is_err());
        let open = serde_json::json!({"status": "OPEN"});
        assert!(require_health_open(&open).is_ok());
        assert!(parse_live_epoch(&open).is_err());
        let with_epoch = serde_json::json!({
            "status": "OPEN",
            "authority_epoch": {
                "lineage_id": TEST_LINEAGE,
                "sequence": 7
            }
        });
        assert_eq!(parse_live_epoch(&with_epoch), Ok(test_epoch(7)));
        assert!(!health_advertises_testd(&open));
        assert!(!health_advertises_testd(&with_epoch));
        let advertised = serde_json::json!({
            "status": "OPEN",
            "operations": [TESTD_ADMISSION_OPERATION]
        });
        assert!(health_advertises_testd(&advertised));
    }

    #[test]
    fn diagnose_only_classification_never_executes() {
        let invocation = test_invocation();
        assert!(!is_testd_diagnose_only_invocation(&invocation));
        let mut inspect = invocation.clone();
        inspect.kind = InstrumentKind::Inspect;
        assert!(is_testd_diagnose_only_invocation(&inspect));
        let envelope = test_envelope(JOB_ID);
        assert!(validate_envelope_invocation_binding(&envelope, &invocation).is_ok());
        // A changed invocation never binds: same job, different bytes.
        let mut changed = invocation.clone();
        changed.profile = "other-profile".to_owned();
        assert!(validate_envelope_invocation_binding(&envelope, &changed).is_err());
    }

    #[test]
    fn envelope_rejects_stale_epoch_and_generation() {
        let invocation = test_invocation();
        let mut envelope = test_envelope(JOB_ID);
        // Foreign epoch in the envelope disagrees with the invocation fence.
        envelope.authority_epoch = test_epoch(9);
        envelope = envelope
            .with_computed_digest()
            .expect("recompute stale digest");
        assert!(validate_envelope_invocation_binding(&envelope, &invocation).is_err());
        let mut envelope = test_envelope(JOB_ID);
        envelope.generation = 2;
        envelope = envelope
            .with_computed_digest()
            .expect("recompute stale digest");
        assert!(validate_envelope_invocation_binding(&envelope, &invocation).is_err());
    }

    #[test]
    fn reconcile_binds_same_digest_only() {
        let envelope = test_envelope(JOB_ID);
        let live = test_epoch(7);
        let admission = TestdAdmission {
            wire_id: TESTD_ADMISSION_OPERATION.to_owned(),
            wire_version: TESTD_ADMISSION_OPERATION_VERSION,
            job_id: JOB_ID.to_owned(),
            invocation_digest: envelope.invocation_digest.clone(),
            authority_epoch: test_epoch(7),
            generation: 1,
            evidence_ref: "evidence-1".to_owned(),
            cancelled: false,
            admitted_at_unix_ms: 1,
            admission_digest: String::new(),
        }
        .with_computed_digest()
        .expect("admission digest");
        assert!(
            reconcile_testd_delivery(&admission, &envelope, &envelope.invocation_digest, &live)
                .expect("reconcile")
        );
        // A different delivery never reconciles as this admission.
        let other = test_envelope("job-other");
        assert!(
            !reconcile_testd_delivery(&admission, &other, &other.invocation_digest, &live)
                .expect("reconcile")
        );
        // A stale live epoch never reconciles.
        assert!(
            reconcile_testd_delivery(
                &admission,
                &envelope,
                &envelope.invocation_digest,
                &test_epoch(9)
            )
            .is_err()
        );
        let _ = digest(0xa1);
    }

    #[test]
    fn retained_intent_requires_exact_binding() {
        let Some(mut client) = testd_client_fixture(Some(test_epoch(7))) else {
            // No composed Kernel front door: intent binding needs the
            // bootstrapped transport, which is never invented.
            return;
        };
        let envelope = test_envelope(JOB_ID);
        assert!(
            client
                .record_intent(JOB_ID, &envelope.invocation_id, &envelope.invocation_digest)
                .is_err()
        );
        client.retain_admission(
            &TestdAdmission {
                wire_id: TESTD_ADMISSION_OPERATION.to_owned(),
                wire_version: TESTD_ADMISSION_OPERATION_VERSION,
                job_id: JOB_ID.to_owned(),
                invocation_digest: envelope.invocation_digest.clone(),
                authority_epoch: test_epoch(7),
                generation: 1,
                evidence_ref: "evidence-1".to_owned(),
                cancelled: false,
                admitted_at_unix_ms: 1,
                admission_digest: digest(0xd1),
            },
            &envelope.invocation_id,
        );
        assert!(
            client
                .record_intent(JOB_ID, &envelope.invocation_id, &envelope.invocation_digest)
                .is_ok()
        );
        assert!(
            client
                .record_intent(JOB_ID, &envelope.invocation_id, &digest(0xee))
                .is_err()
        );
    }
}
