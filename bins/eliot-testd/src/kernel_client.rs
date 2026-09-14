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
//! Until the T6-X2 dispatch contour lands, the client fails closed after
//! the authenticated bootstrap instead of inventing admission material
//! ([`TESTD_DISPATCH_RESIDUAL`]).

use std::sync::Arc;

use eliot_contracts::{EpochId, canonical_json_bytes, sha256_hex};
use eliot_instrument_api::{InstrumentInvocation, InstrumentKind};
use eliot_process::{ProcessEvidenceSink, ProcessExecutionError, ProcessExecutor, ProcessRequest};
use eliot_testd_core::{
    KernelProcessAdmissionEvidence, KernelProcessAdmissionProvider, KernelProcessAdmissionRequest,
    TestdError,
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
/// Advertisement for the testd admission operation: inert until the dispatch
/// slice lands. Testd fails closed with `KERNEL_ADMISSION_REQUIRED` while
/// this is `false`.
pub const TESTD_ADMISSION_ADVERTISED: bool = false;

/// Residual naming the follow-up contour that delivers the session-bound
/// admission envelope plus the concrete IPC-delivered [`ProcessRequest`] to
/// a live one-shot invocation. Until it lands, the binary fails closed
/// after the authenticated bootstrap instead of inventing admission
/// material.
pub const TESTD_DISPATCH_RESIDUAL: &str = "issue-20 slice-6 follow-up: kernel dispatch contour delivering the session-bound TestdAdmissionRequest envelope, live epoch, and concrete ProcessRequest to the one-shot testd invocation";

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
    /// protected authority epoch, generation, artifact, and snapshot), and
    /// probes health. Retains the live authority epoch echoed by the
    /// authenticated health reply for the lineage-aware identity binding.
    ///
    /// Until the T6-X2 dispatch contour lands, this fails closed without
    /// opening ambient state: there is no session-bound admission to bind,
    /// so inventing one would manufacture authority.
    pub fn connect() -> Result<Self, TestdIpcError> {
        Err(TestdIpcError::Transport(format!(
            "protected testd front door requires the authenticated dispatch contour; residual={TESTD_DISPATCH_RESIDUAL}"
        )))
    }

    /// Returns the live authority epoch retained from the authenticated
    /// bootstrap, when the bootstrap completed.
    #[must_use]
    pub fn live_epoch(&self) -> Option<&EpochId> {
        self.live_epoch.as_ref()
    }

    /// Reports whether the live Kernel advertises the exact testd
    /// admission wire. Absent advertisement means not advertised: the check
    /// is fail-closed and never invents authority.
    pub fn advertise_testd(&mut self) -> Result<bool, TestdIpcError> {
        Ok(advertise_testd_admission())
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
#[allow(
    dead_code,
    reason = "dispatch contour probes health once the delivery seam lands; exercised by the module tests"
)]
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
#[allow(
    dead_code,
    reason = "dispatch contour retains the live epoch once the delivery seam lands; exercised by the module tests"
)]
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
#[allow(
    dead_code,
    reason = "dispatch contour probes advertisement once the delivery seam lands; exercised by the module tests"
)]
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
        let client = KernelTestdIpcClient {
            live_epoch: None,
            retained: None,
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
        let mut client = KernelTestdIpcClient {
            live_epoch: Some(test_epoch(7)),
            retained: None,
        };
        let envelope = test_envelope(JOB_ID);
        let refused = client.submit_testd_admission(&envelope);
        assert!(matches!(refused, Err(TestdIpcError::NotAdvertised)));
        assert_eq!(client.advertise_testd(), Ok(false));
        assert!(matches!(
            KernelTestdIpcClient::connect(),
            Err(TestdIpcError::Transport(_))
        ));
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
        let mut client = KernelTestdIpcClient {
            live_epoch: Some(test_epoch(7)),
            retained: None,
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
