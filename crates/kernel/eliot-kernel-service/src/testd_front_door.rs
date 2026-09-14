//! Testd P-07 front-door seam (Slice B, issue #20).
//!
//! Thin service-seam handler over the testd admission contour: it binds one
//! authenticated testd session from live Kernel authority, admits exactly one
//! test admission per call, and reconciles unknown deliveries without
//! admitting again. It owns no durable job store, scheduler, verifier,
//! execution plane, or dispatch table: every admission, conflict, rejection,
//! and reconciliation answer is derived from the presented wire plus live
//! Kernel authority. Durable job identity (`payload_digest`, project-local
//! sequencing, leases, retries) lives in `eliot_testd_core::TestdStore`,
//! owned by the testd binary; this seam never reimplements it.
//!
//! Authority rules (fail-closed, following `host_request_binding.rs:113-129`):
//!
//! * the admission context (service state, authority epoch, generation) is
//!   built from the live [`KernelService`] plus its consumed activation
//!   receipt on every call — never from request envelope bytes;
//! * the session epoch must be exactly the live epoch
//!   (`is_same_authority`) and the session generation must equal the live
//!   activation generation, otherwise the call fails before any admission
//!   input is touched;
//! * the wire matches exactly
//!   (`TESTD_ADMISSION_WIRE_ID`, `TESTD_ADMISSION_WIRE_VERSION`); anything else
//!   is a typed `UnknownWireVersion` rejection, never an admission;
//! * the presented fence is consumed, never minted: the envelope carries a
//!   [`FencingToken`](eliot_process::FencingToken) whose exact-tuple epoch
//!   and generation must agree with the live context, otherwise the attempt
//!   is refused as `StaleEpoch` / `StaleGeneration`;
//! * the closed envelope travels opaquely inside `closed_request_json` and is
//!   parsed only into the local [`TestdAdmissionEnvelope`]. The full
//!   instrument/process admission request
//!   (`eliot_testd_core::KernelProcessAdmissionRequest`) is validated by the
//!   testd owner (`issue_process_admission` binding checks); this seam proves
//!   only the front-door wire shape, the job-identity binding between the
//!   outer request and the envelope, and live authority agreement. No
//!   [`ProcessRequest`](eliot_process::ProcessRequest) is ever minted,
//!   carried, or accepted as a wire object here: the consuming process permit
//!   is issued by the Kernel execution owner downstream;
//! * an exact replay under one job identity rebuilds the original admission
//!   (no second admission);
//! * a changed job identity between the outer request and the envelope under
//!   one call returns `Conflict` and never overwrites anything durable;
//! * observation-only envelopes carry no operation and bind no process
//!   identity. Use [`is_testd_diagnosis_only_envelope`] to classify that
//!   read-only path without admission; submitting one to
//!   [`handle_testd_admission_attempt`] is refused with
//!   `OperationNotAdmitted` instead of admitted half-bound;
//! * cancellation travels through the separate
//!   [`handle_testd_cancellation`] control entry, which admits only
//!   cancellation-flagged envelopes; execution-carrying attempts submitted
//!   there fail closed without admission;
//! * a lost reply reconciles through [`reconcile_testd_delivery`], which
//!   re-derives the binding against the live epoch and compares digests
//!   only: it mutates nothing and mints no new admission.
//!
//! Wire identity note: no wire identity exists in `eliot-testd-core` on this
//! base (it defines `KernelProcessAdmissionRequest`, the store, and the
//! permit, but no front-door wire). `TESTD_ADMISSION_WIRE_ID` below is
//! therefore the single testd front-door wire identity; no second id is
//! introduced.
//!
//! Dependency note: `eliot-kernel-service` carries no `eliot-testd-core`
//! dependency on this base (no `Cargo.toml` change in this slice), so the
//! inner admission request is carried opaquely and its TEST-kind/binding
//! validation stays with the testd owner. The path
//! `eliot_testd_core::KernelProcessAdmissionRequest` names that owner type.

use eliot_contracts::{EpochId, canonical_json_bytes, sha256_hex};
use eliot_process::FencingToken;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{KernelService, KernelServiceError, KernelServiceState, validate_text};

/// Stable identity for the Kernel-owned testd admission wire.
///
/// Single front-door wire identity for testd (see the module docs: no wire
/// identity exists in `eliot-testd-core` on this base, so no second id is
/// introduced here).
pub const TESTD_ADMISSION_WIRE_ID: &str = "eliot.kernel.testd-admission";
/// Current version of the Kernel-owned testd admission wire.
pub const TESTD_ADMISSION_WIRE_VERSION: u16 = 1;
/// Advertisement for the testd admission operation: inert until the binary
/// slice lands. Testd's closed executor treats `false` as
/// `KERNEL_ADMISSION_REQUIRED` and performs nothing.
pub const TESTD_ADMISSION_ADVERTISED: bool = false;
/// Largest presented closed-request envelope admitted on this wire, in bytes.
pub const TESTD_MAX_ENVELOPE_BYTES: usize = 65_536;
/// Maximum changed-dimension entries admitted in one testd conflict report.
pub const TESTD_CONFLICT_MAX_FIELDS: usize = 32;

/// Returns whether Kernel currently advertises the testd admission operation.
///
/// Always `false` in this slice: the tree stays fail-closed until the binary
/// slice wires the front-door dispatch arm.
pub fn advertise_testd_admission() -> bool {
    TESTD_ADMISSION_ADVERTISED
}

/// Routes one wire identity to the testd admission gate.
///
/// Returns `true` only for the exact
/// (`TESTD_ADMISSION_WIRE_ID`, `TESTD_ADMISSION_WIRE_VERSION`) pair. The
/// binary-slice front-door arm calls this; every other wire stays inert.
pub fn route_testd_admission(wire_id: &str, wire_version: u16) -> bool {
    wire_id == TESTD_ADMISSION_WIRE_ID && wire_version == TESTD_ADMISSION_WIRE_VERSION
}

/// Returns true when the value is a lowercase SHA-256 digest.
fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Validates bounded wire text without carrying platform or secret material.
fn validate_wire_text(value: &str, field: &'static str) -> Result<(), KernelServiceError> {
    validate_text(value, field)
}

/// Validates a lowercase SHA-256 wire digest.
fn validate_wire_digest(value: &str, field: &'static str) -> Result<(), KernelServiceError> {
    if !is_lowercase_sha256(value) {
        return Err(KernelServiceError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

/// Explicit Kernel admission inputs for one testd admission.
///
/// The binary-slice dispatch arm builds this from live Kernel state; the
/// gate itself takes the live fence only, so admission never depends on
/// ambient authority. `authority_epoch` must be the live Kernel `EpochId`
/// from `KernelService::authority_epoch()`, and `generation` must be the
/// live activation generation. Neither value is ever taken from the request
/// envelope: the gate proves the presented fence agrees with this context
/// via exact-tuple `is_same_authority` and rejects mismatches before any
/// admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestdAdmissionContext {
    /// Live Kernel service state; admission requires `Ready`.
    pub service_state: KernelServiceState,
    /// Live authority epoch; the presented fence must match it exactly.
    pub authority_epoch: EpochId,
    /// Live resource generation; the presented fence must match it exactly.
    pub generation: u64,
}

impl TestdAdmissionContext {
    /// Builds the admission context, failing closed on a zero generation.
    /// The lineage-aware epoch is always non-zero by construction.
    pub fn new(
        service_state: KernelServiceState,
        authority_epoch: EpochId,
        generation: u64,
    ) -> Result<Self, KernelServiceError> {
        if generation == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "testd_admission.context",
                reason: "authority epoch and generation must be non-zero",
            });
        }
        Ok(Self {
            service_state,
            authority_epoch,
            generation,
        })
    }
}

/// Closed front-door envelope for one testd admission.
///
/// This is the only envelope shape this seam parses: the job identity, the
/// single admitted operation (when present), the cancellation flag, and the
/// consumed [`FencingToken`](eliot_process::FencingToken). The full
/// instrument/process admission request
/// (`eliot_testd_core::KernelProcessAdmissionRequest`) travels opaquely
/// inside the request's `closed_request_json` alongside this envelope's
/// JSON and is validated by the testd owner; this seam never interprets
/// instrument semantics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdAdmissionEnvelope {
    /// Testd job identity this admission binds.
    pub job_id: String,
    /// Single admitted operation, when the envelope carries execution work.
    /// `None` marks the observation-only path, which binds no process
    /// identity and needs no Kernel admission.
    pub operation_id: Option<String>,
    /// Whether this envelope cancels the job instead of executing it.
    /// Cancelled admissions bind no process identity.
    pub cancellation: bool,
    /// Consumed fence; validated against the live admission context and
    /// never minted here.
    pub fence: FencingToken,
}

/// Wire request presenting one testd admission for Kernel admission.
///
/// The closed envelope travels as opaque JSON: Kernel proves the wire
/// identity, the canonical request digest, the job-identity binding between
/// the outer request and the envelope, and live authority agreement, and
/// never accepts executable authority from the caller. `request_digest`
/// binds the exact envelope bytes, so a byte-different retry under one job
/// identity is an identity conflict, not a silent substitution.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdAdmissionAttemptRequest {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Testd job identity seed bound to the envelope job identity.
    pub job_id: String,
    /// Execution attempt sequence distinguishing several attempts of one job.
    pub attempt_seq: u32,
    /// Canonical JSON bytes of the presented closed envelope.
    pub closed_request_json: String,
    /// Opaque digest of the target resource envelope; compared byte-wise,
    /// never interpreted.
    pub target_resource_digest: String,
    /// Canonical digest over this request envelope.
    pub request_digest: String,
}

impl TestdAdmissionAttemptRequest {
    /// Current testd admission wire contract version.
    pub const CONTRACT_VERSION: u16 = TESTD_ADMISSION_WIRE_VERSION;

    /// Computes the canonical digest over the presenting envelope bytes.
    pub fn canonical_request_digest(&self) -> Result<String, KernelServiceError> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            wire_id: &'a str,
            wire_version: u16,
            job_id: &'a str,
            attempt_seq: u32,
            closed_request_json: &'a str,
            target_resource_digest: &'a str,
        }
        let canonical = Canonical {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            job_id: &self.job_id,
            attempt_seq: self.attempt_seq,
            closed_request_json: &self.closed_request_json,
            target_resource_digest: &self.target_resource_digest,
        };
        canonical_json_bytes(&canonical)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| KernelServiceError::InvalidField {
                field: "testd_admission.request_digest",
                reason: "cannot canonicalize request",
            })
    }

    /// Returns this request with its canonical request digest populated.
    pub fn with_computed_digest(mut self) -> Result<Self, KernelServiceError> {
        self.request_digest = self.canonical_request_digest()?;
        Ok(self)
    }

    /// Validates that the request digest equals the canonical digest.
    pub fn validate_canonical_digest(&self) -> Result<(), KernelServiceError> {
        if self.request_digest != self.canonical_request_digest()? {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "testd_admission.request_digest",
            });
        }
        Ok(())
    }

    /// Validates the closed wire shape.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        if self.wire_id != TESTD_ADMISSION_WIRE_ID || self.wire_version != Self::CONTRACT_VERSION {
            return Err(KernelServiceError::InvalidField {
                field: "testd_admission.wire",
                reason: "unsupported testd admission wire",
            });
        }
        validate_wire_text(&self.job_id, "testd_admission.job_id")?;
        if self.closed_request_json.is_empty()
            || self.closed_request_json.len() > TESTD_MAX_ENVELOPE_BYTES
        {
            return Err(KernelServiceError::InvalidField {
                field: "testd_admission.closed_request_json",
                reason: "closed request envelope is missing or exceeds its bound",
            });
        }
        validate_wire_digest(
            &self.target_resource_digest,
            "testd_admission.target_resource_digest",
        )?;
        validate_wire_digest(&self.request_digest, "testd_admission.request_digest")?;
        Ok(())
    }
}

/// Kernel-issued authority projection for one admitted testd job.
///
/// This is the front-door admission receipt only: it carries the wire
/// identity, the bound job and request digests, the admitted operation, and
/// cancellation. The admission digest is canonical over every field, so
/// rebuilding with the durable admission time reproduces the exact same
/// admission on replay. Durable job state (payload binding, sequencing,
/// leases) lives in the testd owner's store; this receipt binds the
/// front-door admission, never the durable job row.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdAdmission {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Admitted testd job identity.
    pub job_id: String,
    /// Canonical digest of the exact admitted request envelope.
    pub request_digest: String,
    /// Admitted operation. Cancelled admissions carry the presented
    /// operation but bind no process identity.
    pub operation_id: String,
    /// Whether the job was admitted cancelled; cancelled admissions never
    /// stage execution work.
    pub cancelled: bool,
    /// Admission time in Unix nanoseconds.
    pub admitted_at_unix_nanos: u64,
    /// Canonical digest over this admission envelope.
    pub admission_digest: String,
}

impl TestdAdmission {
    /// Current testd admission wire contract version.
    pub const CONTRACT_VERSION: u16 = TESTD_ADMISSION_WIRE_VERSION;

    /// Computes the canonical admission digest.
    pub fn compute_digest(&self) -> Result<String, KernelServiceError> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            wire_id: &'a str,
            wire_version: u16,
            job_id: &'a str,
            request_digest: &'a str,
            operation_id: &'a str,
            cancelled: bool,
            admitted_at_unix_nanos: u64,
        }
        let canonical = Canonical {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            job_id: &self.job_id,
            request_digest: &self.request_digest,
            operation_id: &self.operation_id,
            cancelled: self.cancelled,
            admitted_at_unix_nanos: self.admitted_at_unix_nanos,
        };
        canonical_json_bytes(&canonical)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| KernelServiceError::InvalidField {
                field: "testd_admission.admission_digest",
                reason: "cannot canonicalize admission",
            })
    }

    /// Returns this admission with its canonical digest populated.
    pub fn with_computed_digest(mut self) -> Result<Self, KernelServiceError> {
        self.admission_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates the admission shape and its canonical digest.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        if self.wire_id != TESTD_ADMISSION_WIRE_ID || self.wire_version != Self::CONTRACT_VERSION {
            return Err(KernelServiceError::InvalidField {
                field: "testd_admission.wire",
                reason: "unsupported testd admission wire",
            });
        }
        for (text, field) in [
            (&self.job_id, "testd_admission.job_id"),
            (&self.operation_id, "testd_admission.operation_id"),
        ] {
            validate_wire_text(text, field)?;
        }
        for (digest, field) in [
            (&self.request_digest, "testd_admission.request_digest"),
            (&self.admission_digest, "testd_admission.admission_digest"),
        ] {
            validate_wire_digest(digest, field)?;
        }
        if self.admitted_at_unix_nanos == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "testd_admission.admitted_at_unix_nanos",
                reason: "admission time must be non-zero",
            });
        }
        if self.compute_digest()? != self.admission_digest {
            return Err(KernelServiceError::InvalidField {
                field: "testd_admission.admission_digest",
                reason: "admission digest mismatch",
            });
        }
        Ok(())
    }
}

/// Typed reason a testd admission was not issued.
///
/// Every rejection names its cause; a refused attempt executes nothing.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TestdAdmissionRejectionReason {
    /// Unknown admission wire identity or version.
    UnknownWireVersion,
    /// A wire or envelope field failed bounded shape validation.
    InvalidRequestField,
    /// Presented fence epoch disagrees with the live epoch.
    StaleEpoch,
    /// Presented fence generation disagrees with the live generation.
    StaleGeneration,
    /// The envelope carries no operation; it binds no process identity and
    /// needs no Kernel admission.
    OperationNotAdmitted,
    /// The outer request and the envelope bind different job identities.
    JobConflict,
}

/// Typed rejection for one refused testd admission.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdAdmissionRejection {
    /// Refused job identity seed, as presented.
    pub job_ref: String,
    /// Typed refusal cause.
    pub reason: TestdAdmissionRejectionReason,
    /// Bounded detail naming the failing dimension.
    pub detail: String,
    /// Rejection time in Unix nanoseconds.
    pub rejected_at_unix_nanos: u64,
}

impl TestdAdmissionRejection {
    /// Validates the rejection shape.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_wire_text(&self.job_ref, "testd_admission.job_ref")?;
        validate_wire_text(&self.detail, "testd_admission.detail")?;
        if self.rejected_at_unix_nanos == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "testd_admission.rejected_at_unix_nanos",
                reason: "rejection time must be greater than zero",
            });
        }
        Ok(())
    }
}

/// Changed-terms conflict under one testd job identity.
///
/// The same job identity was presented with changed request terms. The
/// conflicting presentation executes nothing and never overwrites durable
/// state. `expected_digest` and `observed_digest` are the envelope-bound
/// and request-bound job digests.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdAdmissionConflict {
    /// Job identity both bindings were presented under.
    pub job_id: String,
    /// Envelope-bound job digest.
    pub expected_digest: String,
    /// Request-bound job digest.
    pub observed_digest: String,
    /// Bound dimensions that differ, in canonical field order.
    pub changed_fields: Vec<String>,
}

impl TestdAdmissionConflict {
    /// Validates the conflict shape.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_wire_text(&self.job_id, "testd_admission.job_id")?;
        validate_wire_digest(&self.expected_digest, "testd_admission.expected_digest")?;
        validate_wire_digest(&self.observed_digest, "testd_admission.observed_digest")?;
        if self.changed_fields.is_empty() || self.changed_fields.len() > TESTD_CONFLICT_MAX_FIELDS {
            return Err(KernelServiceError::InvalidField {
                field: "testd_admission.changed_fields",
                reason: "must name at least one changed dimension within the bound",
            });
        }
        for field in &self.changed_fields {
            validate_wire_text(field, "testd_admission.changed_fields")?;
        }
        Ok(())
    }
}

/// Kernel answer to one testd admission request.
///
/// Exactly one variant is returned: an admission, a typed rejection, or a
/// changed-terms conflict. A conflicting presentation never produces a
/// second live admission under the same identity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "SCREAMING_SNAKE_CASE",
    tag = "kind",
    content = "payload"
)]
pub enum TestdAdmissionResponse {
    /// The job was admitted; the admission is the authority projection.
    Admitted(Box<TestdAdmission>),
    /// The job was refused for the named typed reason.
    Rejected(TestdAdmissionRejection),
    /// The job identity conflicts with the presented bound terms.
    Conflict(TestdAdmissionConflict),
}

impl TestdAdmissionResponse {
    /// Validates the enclosed admission, rejection, or conflict.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        match self {
            Self::Admitted(admission) => admission.validate(),
            Self::Rejected(rejection) => rejection.validate(),
            Self::Conflict(conflict) => conflict.validate(),
        }
    }
}

/// Authenticated testd session bound from live Kernel authority.
///
/// All fields come from the Kernel service lineage and its consumed
/// activation receipt at bind time: the principal reference supplied by the
/// authenticated composition boundary (never a request-envelope value), the
/// live authority epoch, and the live activation generation. No request DTO
/// field contributes authority (A12.2: identity is established by the
/// harness/installation boundary, never self-declared).
#[derive(Clone, Debug)]
pub struct AuthenticatedTestdSession {
    principal_ref: String,
    authority_epoch: EpochId,
    generation: u64,
}

impl AuthenticatedTestdSession {
    /// Binds one testd session from live Kernel state.
    ///
    /// Fails closed when the generation is fenced, the service is not
    /// `Ready`, no candidate lineage or consumed activation receipt exists,
    /// the activation no longer agrees with the live epoch (revoked/stale
    /// activation), or the principal reference is not bounded wire text.
    /// An unactivated Kernel therefore admits no testd work through this
    /// seam.
    pub fn bind(service: &KernelService, principal_ref: &str) -> Result<Self, KernelServiceError> {
        validate_text(principal_ref, "testd_admission.principal")?;
        if service.generation_fenced() {
            return Err(KernelServiceError::GenerationFenced);
        }
        let state = service.state();
        if state != KernelServiceState::Ready {
            return Err(KernelServiceError::AdmissionClosed(state));
        }
        let candidate =
            service
                .candidate_binding()
                .ok_or(KernelServiceError::HandshakeMismatch {
                    field: "missing_candidate",
                })?;
        let activation =
            service
                .activation_receipt()
                .ok_or(KernelServiceError::HandshakeMismatch {
                    field: "missing_activation",
                })?;
        let live_epoch = service.authority_epoch();
        if !candidate.kernel_epoch.is_same_authority(&live_epoch) {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "testd_admission.authority_epoch",
            });
        }
        if !activation.authority_epoch.is_same_authority(&live_epoch) {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "testd_admission.authority_epoch",
            });
        }
        Ok(Self {
            principal_ref: principal_ref.to_owned(),
            authority_epoch: live_epoch,
            generation: activation.generation.value(),
        })
    }

    /// Returns the authenticated principal reference.
    #[must_use]
    pub fn principal_ref(&self) -> &str {
        &self.principal_ref
    }

    /// Returns the authority epoch bound at session time.
    #[must_use]
    pub fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }

    /// Returns the activation generation bound at session time.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Re-validates the session against live service authority.
    ///
    /// Returns the live `(epoch, generation)` the admission context must be
    /// built from. A session bound before an epoch advance, a generation
    /// cutover, a fence, or a drain is stale and fails here — before any
    /// admission input — so a replayed session can never smuggle old
    /// authority into a new epoch.
    fn live_authority(
        &self,
        service: &KernelService,
    ) -> Result<(EpochId, u64), KernelServiceError> {
        if service.generation_fenced() {
            return Err(KernelServiceError::GenerationFenced);
        }
        let state = service.state();
        if state != KernelServiceState::Ready {
            return Err(KernelServiceError::AdmissionClosed(state));
        }
        let activation =
            service
                .activation_receipt()
                .ok_or(KernelServiceError::HandshakeMismatch {
                    field: "missing_activation",
                })?;
        let live_epoch = service.authority_epoch();
        if !activation.authority_epoch.is_same_authority(&live_epoch) {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "testd_admission.authority_epoch",
            });
        }
        let live_generation = activation.generation.value();
        if !self.authority_epoch.is_same_authority(&live_epoch) {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "testd_admission.authority_epoch",
            });
        }
        if self.generation != live_generation {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "testd_admission.generation",
            });
        }
        Ok((live_epoch, live_generation))
    }

    /// Builds the admission context from live Kernel authority.
    ///
    /// The epoch and generation come from [`Self::live_authority`] — the
    /// live service plus its consumed activation — never from the request
    /// envelope. The gate re-proves the presented fence agrees with this
    /// context before any admission.
    pub fn admission_context(
        &self,
        service: &KernelService,
    ) -> Result<TestdAdmissionContext, KernelServiceError> {
        let (epoch, generation) = self.live_authority(service)?;
        TestdAdmissionContext::new(service.state(), epoch, generation)
    }
}

/// Refusal channel for testd validation helpers.
///
/// Validation helpers have no access to the response-building closure, so
/// they return the typed reason and detail; the gate maps the pair to a
/// `Rejected` response. Nothing is weakened: every refusal path is preserved.
type TestdRefusal = (TestdAdmissionRejectionReason, &'static str);

/// Validates the wire envelope and binds the presented closed envelope.
fn parse_testd_wire(
    request: &TestdAdmissionAttemptRequest,
) -> Result<TestdAdmissionEnvelope, TestdRefusal> {
    if !route_testd_admission(&request.wire_id, request.wire_version) {
        return Err((
            TestdAdmissionRejectionReason::UnknownWireVersion,
            "testd_admission.wire",
        ));
    }
    if let Err(error) = request.validate() {
        let reason = match error {
            KernelServiceError::InvalidField {
                field: "testd_admission.wire",
                ..
            } => TestdAdmissionRejectionReason::UnknownWireVersion,
            _ => TestdAdmissionRejectionReason::InvalidRequestField,
        };
        return Err((reason, "testd_admission.wire"));
    }
    if request.validate_canonical_digest().is_err() {
        return Err((
            TestdAdmissionRejectionReason::InvalidRequestField,
            "testd_admission.request_digest",
        ));
    }
    serde_json::from_str(&request.closed_request_json).map_err(|_| {
        (
            TestdAdmissionRejectionReason::InvalidRequestField,
            "testd_admission.closed_request",
        )
    })
}

/// Checks the presented fence against the live epoch and generation.
///
/// The fence is consumed, never minted: its exact-tuple epoch must agree
/// with the live context epoch and its generation must equal the live
/// generation, so a stale or foreign fence admits nothing.
fn check_testd_fence(
    context: &TestdAdmissionContext,
    envelope: &TestdAdmissionEnvelope,
) -> Result<(), TestdRefusal> {
    if envelope
        .fence
        .validate_canonical_against(&context.authority_epoch)
        .is_err()
    {
        return Err((
            TestdAdmissionRejectionReason::StaleEpoch,
            "testd_admission.authority_epoch",
        ));
    }
    if envelope.fence.generation().get() != context.generation {
        return Err((
            TestdAdmissionRejectionReason::StaleGeneration,
            "testd_admission.generation",
        ));
    }
    Ok(())
}

/// Reports the job-identity conflict between the outer request and the envelope.
fn testd_job_conflict(
    request: &TestdAdmissionAttemptRequest,
    envelope: &TestdAdmissionEnvelope,
) -> TestdAdmissionResponse {
    TestdAdmissionResponse::Conflict(TestdAdmissionConflict {
        job_id: request.job_id.clone(),
        expected_digest: sha256_hex(envelope.job_id.as_bytes()),
        observed_digest: sha256_hex(request.job_id.as_bytes()),
        changed_fields: vec!["job_id".to_owned()],
    })
}

/// Builds one deterministic admission from bound terms and one admission time.
///
/// Rebuilding with the durable admission time reproduces the exact same
/// admission on replay. Cancelled admissions carry the presented operation
/// but bind no process identity.
fn build_testd_admission(
    request: &TestdAdmissionAttemptRequest,
    operation_id: &str,
    cancelled: bool,
    admitted_at_unix_nanos: u64,
) -> Result<TestdAdmission, KernelServiceError> {
    TestdAdmission {
        wire_id: TESTD_ADMISSION_WIRE_ID.to_owned(),
        wire_version: TestdAdmission::CONTRACT_VERSION,
        job_id: request.job_id.clone(),
        request_digest: request.request_digest.clone(),
        operation_id: operation_id.to_owned(),
        cancelled,
        admitted_at_unix_nanos,
        admission_digest: String::new(),
    }
    .with_computed_digest()
}

/// Admits one testd job through the live Kernel authority.
///
/// One call admits at most one job: the session is re-validated against
/// live authority, the wire identity must match exactly, the presented
/// fence must agree with the live context, and the outer request and the
/// envelope must bind the same job identity. An exact replay returns the
/// original admission; changed job terms under one identity return
/// `Conflict`; observation-only envelopes without an operation are refused
/// with `OperationNotAdmitted`. The inner instrument/process admission
/// request (`eliot_testd_core::KernelProcessAdmissionRequest`) is validated
/// by the testd owner; this seam proves the front-door wire, binding, and
/// authority only, and mints no
/// [`ProcessRequest`](eliot_process::ProcessRequest). Only mechanical
/// failures (fenced generation, closed admission) surface as `Err`; every
/// typed refusal is an `Ok` response value.
pub fn handle_testd_admission_attempt(
    service: &KernelService,
    session: &AuthenticatedTestdSession,
    request: &TestdAdmissionAttemptRequest,
    now_unix_nanos: u64,
) -> Result<TestdAdmissionResponse, KernelServiceError> {
    let context = session.admission_context(service)?;
    if !route_testd_admission(&request.wire_id, request.wire_version) {
        if now_unix_nanos == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "testd_admission.now",
                reason: "admission time must be non-zero",
            });
        }
        return Ok(TestdAdmissionResponse::Rejected(TestdAdmissionRejection {
            job_ref: request.job_id.clone(),
            reason: TestdAdmissionRejectionReason::UnknownWireVersion,
            detail: "testd_admission.wire".to_owned(),
            rejected_at_unix_nanos: now_unix_nanos,
        }));
    }
    if now_unix_nanos == 0 {
        return Err(KernelServiceError::InvalidField {
            field: "testd_admission.now",
            reason: "admission time must be non-zero",
        });
    }
    validate_text(session.principal_ref(), "testd_admission.principal")?;
    let rejected = |reason: TestdAdmissionRejectionReason, detail: &'static str| {
        TestdAdmissionResponse::Rejected(TestdAdmissionRejection {
            job_ref: request.job_id.clone(),
            reason,
            detail: detail.to_owned(),
            rejected_at_unix_nanos: now_unix_nanos,
        })
    };
    let envelope = match parse_testd_wire(request) {
        Ok(envelope) => envelope,
        Err((reason, detail)) => return Ok(rejected(reason, detail)),
    };
    if envelope.job_id != request.job_id {
        let conflict = testd_job_conflict(request, &envelope);
        conflict.validate().map_err(|error| {
            KernelServiceError::Platform(format!("testd conflict report is malformed: {error}"))
        })?;
        return Ok(conflict);
    }
    if let Err((reason, detail)) = check_testd_fence(&context, &envelope) {
        return Ok(rejected(reason, detail));
    }
    let Some(operation_id) = envelope.operation_id.clone() else {
        return Ok(rejected(
            TestdAdmissionRejectionReason::OperationNotAdmitted,
            "testd_admission.operations",
        ));
    };
    if validate_wire_text(&operation_id, "testd_admission.operation_id").is_err() {
        return Ok(rejected(
            TestdAdmissionRejectionReason::InvalidRequestField,
            "testd_admission.operation_id",
        ));
    }
    let admission = build_testd_admission(
        request,
        &operation_id,
        envelope.cancellation,
        now_unix_nanos,
    )?;
    admission.validate().map_err(|error| {
        KernelServiceError::Platform(format!("testd admission failed validation: {error}"))
    })?;
    Ok(TestdAdmissionResponse::Admitted(Box::new(admission)))
}

/// Admits one testd cancellation through the separate control entry.
///
/// Cancellation is an admission outcome with no execution work — never a
/// second dispatch path. This entry parses the presented envelope and admits
/// only cancellation-flagged requests, delegating to
/// [`handle_testd_admission_attempt`]; an execution-carrying request
/// submitted here fails closed with `InvalidField` and admits nothing. A
/// request whose envelope cannot be parsed is delegated unchanged so the
/// gate reports its typed `InvalidRequestField` refusal. Cancel and
/// reconcile traffic therefore never shares an entrypoint with execution
/// admission results, while authority stays in the one gate.
pub fn handle_testd_cancellation(
    service: &KernelService,
    session: &AuthenticatedTestdSession,
    request: &TestdAdmissionAttemptRequest,
    now_unix_nanos: u64,
) -> Result<TestdAdmissionResponse, KernelServiceError> {
    if let Ok(envelope) =
        serde_json::from_str::<TestdAdmissionEnvelope>(&request.closed_request_json)
        && !envelope.cancellation
    {
        return Err(KernelServiceError::InvalidField {
            field: "testd_admission.cancellation",
            reason: "this control entry admits cancellation only",
        });
    }
    handle_testd_admission_attempt(service, session, request, now_unix_nanos)
}

/// Reconciles one unknown testd admission delivery without admitting again.
///
/// Lost-reply path: the caller retains a previously returned admission and,
/// on an uncertain delivery, proves it still binds the exact presented
/// envelope under live authority. The job binding is re-derived against the
/// live Kernel epoch (never envelope bytes) and the admission digest is
/// compared deterministically; nothing is mutated and no new admission is
/// minted. Returns `true` only when the retained admission is exactly this
/// delivery's admission — the caller must then treat the original admission
/// as the outcome. Returns `false` when it does not bind: that delivery
/// must escalate, never blind-retry as a new attempt.
pub fn reconcile_testd_delivery(
    service: &KernelService,
    session: &AuthenticatedTestdSession,
    admission: &TestdAdmission,
    request: &TestdAdmissionAttemptRequest,
    envelope: &TestdAdmissionEnvelope,
) -> Result<bool, KernelServiceError> {
    let (live_epoch, _) = session.live_authority(service)?;
    reconcile_testd_admission(admission, request, envelope, &live_epoch)
}

/// Re-derives one testd admission binding against live authority and
/// compares digests only.
///
/// This pure admission↔request check proves only that a retained admission
/// binds the exact presented envelope: the job identities must agree, the
/// presented fence must still agree with the live epoch, the cancelled and
/// operation terms must match, and the recomputed admission digest must
/// equal the retained one. It changes no service state and issues no new
/// authority. `authority_epoch` is the live Kernel `EpochId` (from
/// `KernelService::authority_epoch()`, supplied by the dispatch arm — never
/// envelope bytes).
pub fn reconcile_testd_admission(
    admission: &TestdAdmission,
    request: &TestdAdmissionAttemptRequest,
    envelope: &TestdAdmissionEnvelope,
    authority_epoch: &EpochId,
) -> Result<bool, KernelServiceError> {
    admission.validate()?;
    request.validate()?;
    request.validate_canonical_digest()?;
    if admission.job_id != request.job_id || admission.job_id != envelope.job_id {
        return Ok(false);
    }
    if admission.request_digest != request.request_digest {
        return Ok(false);
    }
    if admission.cancelled != envelope.cancellation {
        return Ok(false);
    }
    let Some(operation_id) = envelope.operation_id.as_deref() else {
        return Ok(false);
    };
    if admission.operation_id != operation_id {
        return Ok(false);
    }
    if envelope
        .fence
        .validate_canonical_against(authority_epoch)
        .is_err()
    {
        return Ok(false);
    }
    let recomputed = build_testd_admission(
        request,
        operation_id,
        envelope.cancellation,
        admission.admitted_at_unix_nanos,
    )?;
    Ok(recomputed.admission_digest == admission.admission_digest)
}

/// Classifies the read-only observation path without touching authority.
///
/// Returns `true` only for an observation-only envelope carrying no
/// operation: such a request binds no process identity and needs no Kernel
/// execution admission, so it must be answered from test evidence rather
/// than submitted to [`handle_testd_admission_attempt`] (the gate refuses
/// operation-less requests with `OperationNotAdmitted` instead of admitting
/// them half-bound). This check is pure: it reads the already-parsed
/// envelope, stages nothing, and advances nothing.
#[must_use]
pub fn is_testd_diagnosis_only_envelope(envelope: &TestdAdmissionEnvelope) -> bool {
    envelope.operation_id.is_none()
}
