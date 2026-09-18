// T6-X1 Slice 6 (issue #20): testd P-07 front-door seam proofs through the
// real owner path (`KernelService` to `Ready` plus the authenticated
// session binding and the typed testd admission gate over the durable
// first-writer-wins store).
//
// The store below reuses the exact fail-closed in-memory double pattern from
// `tests/doctor-front-door.rs` (first-writer-wins, exact replay returns the
// durable row, changed terms conflict, no row is ever overwritten). It is
// test-only scaffolding, never authority. The Kernel side is a real
// `KernelService` driven to `Ready` through reconcile/activate/publish_ready,
// so session binding, live-epoch context, and activation gating are proven
// against live authority, not canned values.
//
// Proven here: one admitted test execution through the seam with lost-reply
// reconciliation of the same digest (no second effect, no second admission);
// exact duplicate returns the prior admission; changed invocation/root/epoch
// returns a typed conflict; cancellation travels through its separate
// control entry (effect attempts submitted there fail closed); diagnose-only
// envelopes classify as the read-only path without admission; binding fails
// closed without activation and on stale epoch/peer, and a foreign-lineage
// fence is rejected before any durable write.
//
// Validation mirrors `eliot-testd-core` exactly while `Cargo.toml` stays
// frozen for this slice: `ProcessRequest::validate` is the same call
// `issue_process_admission` makes, epoch checks are exact-tuple
// `is_same_authority`, generation is exact equality, and identity is only
// (`job_id`, invocation digest, roots digest, epoch, generation, canonical
// digests). `StateFence` (via the shared doctor-core fence shape) proves the
// lineage binding. Bare paths, PIDs, and service names never decide
// admission, replay, or reconciliation: they appear only as digested bytes.
//
// DEFERRED (follow-up slices): T6-X2 worker/claim dispatch through the live
// contour, verifier/Governor disposition, binary IPC dispatch arm.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, HashMap};
use std::num::NonZeroU64;
use std::sync::Mutex;

use eliot_contracts::{
    AuthorityEpoch, EpochId, EpochLineageId, ResourceGeneration, canonical_json_bytes, sha256_hex,
};
use eliot_doctor_core::{StateFence, check_fence_against_epoch};
use eliot_kernel_service::{
    HostFileIdentity, HostJobBinding, HostJobIdentity, HostJobRoot, HostKernelCandidateBinding,
    HostProcessBinding, KernelActivationPermit, KernelActivationReceipt, KernelControlCommand,
    KernelReadyReceipt, KernelService, KernelServiceError, KernelServiceState, ProcessObservation,
    RestartBudget,
};
use eliot_platform::{KernelActivationNonce, PlatformHandle};
use eliot_process::{
    ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, EnvironmentInheritance,
    EnvironmentProjection, FencingToken, Generation, ImageId, JobId, KernelDispatchKey,
    OperationId, PermitIssuance, ProcessIntent, ProcessRequest, ProcessTreeId, ResourceLimits,
    SessionId,
};
use eliot_runtime_contracts::{
    HealthVector, RegisteredActivityWakePolicy, ServiceProcessState, SupervisionJournalEpoch,
    SupervisionLeaseIncarnationBinding, SupervisionObservationScope,
};
use serde::{Deserialize, Serialize};

const LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const LINEAGE_B: &str = "550e8400-e29b-41d4-a716-446655440001";
const EPOCH_SEQUENCE: u64 = 4;
const GENERATION: u64 = 7;
const NOW_UNIX_NANOS: u64 = 1_700_000_000_000_000_000;
const LATER_UNIX_NANOS: u64 = NOW_UNIX_NANOS + 61_000_000_000;

/// Stable identity for the Kernel-owned testd admission wire under test.
/// Mirrors `bins/eliot-testd/src/kernel_client.rs::TESTD_ADMISSION_OPERATION`;
/// the wire stays `eliot.kernel.testd-admission`.
const TESTD_ADMISSION_OPERATION: &str = "eliot.kernel.testd-admission";
/// Wire revision admitted by this seam.
const TESTD_ADMISSION_OPERATION_VERSION: u16 = 1;

/// Routes one wire identity to the testd admission gate. Returns `true`
/// only for the exact admitted pair.
fn route_testd_admission(wire_id: &str, wire_version: u16) -> bool {
    wire_id == TESTD_ADMISSION_OPERATION && wire_version == TESTD_ADMISSION_OPERATION_VERSION
}

fn validate_text(value: &str, field: &'static str) -> Result<(), KernelServiceError> {
    if value.trim().is_empty() {
        return Err(KernelServiceError::InvalidField {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(KernelServiceError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    if value.len() > 1024 {
        return Err(KernelServiceError::InvalidField {
            field,
            reason: "must not exceed 1024 UTF-8 bytes",
        });
    }
    Ok(())
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), KernelServiceError> {
    if !is_lowercase_sha256(value) {
        return Err(KernelServiceError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

/// Canonical digest over the presented invocation bytes (job, invocation,
/// profile, target). Changed invocation bytes change this digest; the bare
/// strings themselves are never compared for identity.
fn invocation_digest(
    job_id: &str,
    invocation_id: &str,
    profile: &str,
    target: &str,
    epoch: &EpochId,
    generation: u64,
) -> String {
    let bytes = canonical_json_bytes(&(job_id, invocation_id, profile, target, epoch, generation))
        .expect("canonical test digest");
    sha256_hex(&bytes)
}

/// Canonical digest over the contour roots tuple. The roots travel by digest
/// only; bare path equality never decides admission.
fn roots_digest(source: &str, target: &str, cache: &str) -> String {
    let bytes =
        canonical_json_bytes(&(source, target, cache)).expect("canonical test roots digest");
    sha256_hex(&bytes)
}

/// Wire request presenting one testd admission. Identity is exactly
/// (`job_id`, invocation digest, roots digest, epoch exact tuple,
/// generation, canonical digest). No bare path, PID, or service name
/// appears.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestdAdmissionRequest {
    wire_id: String,
    wire_version: u16,
    job_id: String,
    invocation_id: String,
    invocation_digest: String,
    target_roots_digest: String,
    authority_epoch: EpochId,
    generation: u64,
    cancelled: bool,
    request_digest: String,
}

impl TestdAdmissionRequest {
    fn canonical_request_digest(&self) -> Result<String, KernelServiceError> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            wire_id: &'a str,
            wire_version: u16,
            job_id: &'a str,
            invocation_id: &'a str,
            invocation_digest: &'a str,
            target_roots_digest: &'a str,
            authority_epoch: &'a EpochId,
            generation: u64,
            cancelled: bool,
        }
        let bytes = canonical_json_bytes(&Canonical {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            job_id: &self.job_id,
            invocation_id: &self.invocation_id,
            invocation_digest: &self.invocation_digest,
            target_roots_digest: &self.target_roots_digest,
            authority_epoch: &self.authority_epoch,
            generation: self.generation,
            cancelled: self.cancelled,
        })
        .map_err(|_| KernelServiceError::InvalidField {
            field: "testd_admission.request_digest",
            reason: "cannot canonicalize request",
        })?;
        Ok(sha256_hex(&bytes))
    }

    fn with_computed_digest(mut self) -> Result<Self, KernelServiceError> {
        self.request_digest = self.canonical_request_digest()?;
        Ok(self)
    }

    fn validate_canonical_digest(&self) -> Result<(), KernelServiceError> {
        if self.request_digest != self.canonical_request_digest()? {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "testd_admission.request_digest",
            });
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), KernelServiceError> {
        if self.wire_id != TESTD_ADMISSION_OPERATION
            || self.wire_version != TESTD_ADMISSION_OPERATION_VERSION
        {
            return Err(KernelServiceError::InvalidField {
                field: "testd_admission.wire",
                reason: "unsupported testd admission wire",
            });
        }
        validate_text(&self.job_id, "testd_admission.job_id")?;
        validate_text(&self.invocation_id, "testd_admission.invocation_id")?;
        validate_digest(&self.invocation_digest, "testd_admission.invocation_digest")?;
        validate_digest(
            &self.target_roots_digest,
            "testd_admission.target_roots_digest",
        )?;
        validate_digest(&self.request_digest, "testd_admission.request_digest")?;
        if self.generation == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "testd_admission.generation",
                reason: "generation must be non-zero",
            });
        }
        Ok(())
    }
}

/// Kernel-issued admission receipt for one testd job. Carries only digests
/// plus the epoch/generation tuple; never a bare path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestdAdmission {
    wire_id: String,
    wire_version: u16,
    job_id: String,
    invocation_digest: String,
    target_roots_digest: String,
    authority_epoch: EpochId,
    generation: u64,
    evidence_ref: String,
    cancelled: bool,
    admitted_at_unix_nanos: u64,
    admission_digest: String,
}

impl TestdAdmission {
    fn compute_digest(&self) -> Result<String, KernelServiceError> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            wire_id: &'a str,
            wire_version: u16,
            job_id: &'a str,
            invocation_digest: &'a str,
            target_roots_digest: &'a str,
            authority_epoch: &'a EpochId,
            generation: u64,
            evidence_ref: &'a str,
            cancelled: bool,
            admitted_at_unix_nanos: u64,
        }
        let bytes = canonical_json_bytes(&Canonical {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            job_id: &self.job_id,
            invocation_digest: &self.invocation_digest,
            target_roots_digest: &self.target_roots_digest,
            authority_epoch: &self.authority_epoch,
            generation: self.generation,
            evidence_ref: &self.evidence_ref,
            cancelled: self.cancelled,
            admitted_at_unix_nanos: self.admitted_at_unix_nanos,
        })
        .map_err(|_| KernelServiceError::InvalidField {
            field: "testd_admission.admission_digest",
            reason: "cannot canonicalize admission",
        })?;
        Ok(sha256_hex(&bytes))
    }

    fn with_computed_digest(mut self) -> Result<Self, KernelServiceError> {
        self.admission_digest = self.compute_digest()?;
        Ok(self)
    }

    fn validate(&self) -> Result<(), KernelServiceError> {
        if self.wire_id != TESTD_ADMISSION_OPERATION
            || self.wire_version != TESTD_ADMISSION_OPERATION_VERSION
        {
            return Err(KernelServiceError::InvalidField {
                field: "testd_admission.wire",
                reason: "unsupported testd admission wire",
            });
        }
        validate_text(&self.job_id, "testd_admission.job_id")?;
        validate_text(&self.evidence_ref, "testd_admission.evidence_ref")?;
        validate_digest(&self.invocation_digest, "testd_admission.invocation_digest")?;
        validate_digest(
            &self.target_roots_digest,
            "testd_admission.target_roots_digest",
        )?;
        validate_digest(&self.admission_digest, "testd_admission.admission_digest")?;
        if self.generation == 0 || self.admitted_at_unix_nanos == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "testd_admission.bounded_fields",
                reason: "generation and admission time must be non-zero",
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(
    dead_code,
    reason = "typed refusal axis documents the full closed cause set"
)]
enum TestdRejectionReason {
    UnknownWireVersion,
    InvalidRequestField,
    StaleEpoch,
    StaleGeneration,
    InvocationMismatch,
    OperationNotAdmitted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestdRejection {
    job_ref: String,
    reason: TestdRejectionReason,
    detail: String,
    rejected_at_unix_nanos: u64,
}

impl TestdRejection {
    fn validate(&self) -> Result<(), KernelServiceError> {
        validate_text(&self.job_ref, "testd_admission.job_ref")?;
        validate_text(&self.detail, "testd_admission.detail")?;
        if self.rejected_at_unix_nanos == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "testd_admission.rejected_at",
                reason: "rejection time must be non-zero",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestdConflict {
    job_id: String,
    changed_fields: Vec<String>,
    detail: String,
    conflicted_at_unix_nanos: u64,
}

impl TestdConflict {
    fn validate(&self) -> Result<(), KernelServiceError> {
        validate_text(&self.job_id, "testd_admission.job_id")?;
        validate_text(&self.detail, "testd_admission.detail")?;
        if self.changed_fields.is_empty() || self.changed_fields.len() > 32 {
            return Err(KernelServiceError::InvalidField {
                field: "testd_admission.changed_fields",
                reason: "must name one to thirty-two changed fields",
            });
        }
        if self.conflicted_at_unix_nanos == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "testd_admission.conflicted_at",
                reason: "conflict time must be non-zero",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TestdResponse {
    Admitted(TestdAdmission),
    Rejected(TestdRejection),
    Conflict(TestdConflict),
}

/// Read-only work kinds. Only `Test` binds execution identity; `Diagnose`
/// is the read-only path and never reaches admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestdWorkKind {
    Test,
    Diagnose,
}

fn is_testd_diagnose_only(kind: TestdWorkKind) -> bool {
    matches!(kind, TestdWorkKind::Diagnose)
}

#[derive(Clone, Debug)]
struct StoredTestdRow {
    request_digest: String,
    invocation_digest: String,
    target_roots_digest: String,
    authority_epoch: EpochId,
    generation: u64,
    admission: TestdAdmission,
}

/// Fail-closed in-memory testd admission store. First-writer-wins per job
/// identity: an exact replay returns the durable row, changed terms
/// conflict, and no row is ever overwritten. Test-only scaffolding, never
/// authority.
struct TestAdmissionStore {
    rows: Mutex<HashMap<String, StoredTestdRow>>,
    effects: Mutex<HashMap<String, String>>,
}

impl TestAdmissionStore {
    fn new() -> Self {
        Self {
            rows: Mutex::new(HashMap::new()),
            effects: Mutex::new(HashMap::new()),
        }
    }

    fn admit(
        &self,
        session: &AuthenticatedTestdSession,
        service: &KernelService,
        request: &TestdAdmissionRequest,
        now_unix_nanos: u64,
    ) -> Result<TestdResponse, KernelServiceError> {
        let (live_epoch, live_generation) = session.live_authority(service)?;
        if now_unix_nanos == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "testd_admission.now",
                reason: "admission time must be non-zero",
            });
        }
        if !route_testd_admission(&request.wire_id, request.wire_version) {
            return Ok(TestdResponse::Rejected(TestdRejection {
                job_ref: request.job_id.clone(),
                reason: TestdRejectionReason::UnknownWireVersion,
                detail: "testd_admission.wire".to_owned(),
                rejected_at_unix_nanos: now_unix_nanos,
            }));
        }
        if request.validate().is_err() || request.validate_canonical_digest().is_err() {
            return Ok(TestdResponse::Rejected(TestdRejection {
                job_ref: request.job_id.clone(),
                reason: TestdRejectionReason::InvalidRequestField,
                detail: "testd_admission.envelope".to_owned(),
                rejected_at_unix_nanos: now_unix_nanos,
            }));
        }
        if !request.authority_epoch.is_same_authority(&live_epoch) {
            return Ok(TestdResponse::Rejected(TestdRejection {
                job_ref: request.job_id.clone(),
                reason: TestdRejectionReason::StaleEpoch,
                detail: "testd_admission.authority_epoch".to_owned(),
                rejected_at_unix_nanos: now_unix_nanos,
            }));
        }
        if request.generation != live_generation {
            return Ok(TestdResponse::Rejected(TestdRejection {
                job_ref: request.job_id.clone(),
                reason: TestdRejectionReason::StaleGeneration,
                detail: "testd_admission.generation".to_owned(),
                rejected_at_unix_nanos: now_unix_nanos,
            }));
        }
        let mut rows = self.rows.lock().expect("test store is single-threaded");
        if let Some(durable) = rows.get(&request.job_id) {
            if durable.request_digest == request.request_digest
                && durable.invocation_digest == request.invocation_digest
                && durable.target_roots_digest == request.target_roots_digest
                && durable
                    .authority_epoch
                    .is_same_authority(&request.authority_epoch)
                && durable.generation == request.generation
            {
                return Ok(TestdResponse::Admitted(durable.admission.clone()));
            }
            let mut changed = Vec::new();
            if durable.invocation_digest != request.invocation_digest {
                changed.push("invocation_digest".to_owned());
            }
            if durable.target_roots_digest != request.target_roots_digest {
                changed.push("target_roots_digest".to_owned());
            }
            if !durable
                .authority_epoch
                .is_same_authority(&request.authority_epoch)
            {
                changed.push("authority_epoch".to_owned());
            }
            if durable.generation != request.generation {
                changed.push("generation".to_owned());
            }
            if changed.is_empty() {
                changed.push("request_digest".to_owned());
            }
            return Ok(TestdResponse::Conflict(TestdConflict {
                job_id: request.job_id.clone(),
                changed_fields: changed,
                detail: "testd_admission.terms".to_owned(),
                conflicted_at_unix_nanos: now_unix_nanos,
            }));
        }
        let admission = TestdAdmission {
            wire_id: TESTD_ADMISSION_OPERATION.to_owned(),
            wire_version: TESTD_ADMISSION_OPERATION_VERSION,
            job_id: request.job_id.clone(),
            invocation_digest: request.invocation_digest.clone(),
            target_roots_digest: request.target_roots_digest.clone(),
            authority_epoch: live_epoch.clone(),
            generation: live_generation,
            evidence_ref: format!("evidence-{}", request.job_id),
            cancelled: request.cancelled,
            admitted_at_unix_nanos: now_unix_nanos,
            admission_digest: String::new(),
        }
        .with_computed_digest()
        .map_err(|_| KernelServiceError::InvalidField {
            field: "testd_admission.admission_digest",
            reason: "cannot canonicalize admission",
        })?;
        admission
            .validate()
            .map_err(|_| KernelServiceError::InvalidField {
                field: "testd_admission.admission",
                reason: "admission shape is invalid",
            })?;
        // Cancelled admissions bind no effect intent.
        if !request.cancelled {
            let mut effects = self.effects.lock().expect("test store is single-threaded");
            effects.insert(admission.admission_digest.clone(), request.job_id.clone());
        }
        rows.insert(
            request.job_id.clone(),
            StoredTestdRow {
                request_digest: request.request_digest.clone(),
                invocation_digest: request.invocation_digest.clone(),
                target_roots_digest: request.target_roots_digest.clone(),
                authority_epoch: request.authority_epoch.clone(),
                generation: request.generation,
                admission: admission.clone(),
            },
        );
        Ok(TestdResponse::Admitted(admission))
    }

    /// Separate cancellation control entry: admits only
    /// cancellation-flagged envelopes. An effect-carrying request submitted
    /// here fails closed without admission.
    fn cancel(
        &self,
        session: &AuthenticatedTestdSession,
        service: &KernelService,
        request: &TestdAdmissionRequest,
        now_unix_nanos: u64,
    ) -> Result<TestdResponse, KernelServiceError> {
        if !request.cancelled {
            return Err(KernelServiceError::InvalidField {
                field: "testd_admission.cancellation",
                reason: "this control entry admits cancellation only",
            });
        }
        self.admit(session, service, request, now_unix_nanos)
    }

    /// Lost-reply reconciliation: re-derives the binding against live
    /// authority and compares digests only. Mutates nothing, mints no new
    /// effect.
    fn reconcile_delivery(
        &self,
        service: &KernelService,
        session: &AuthenticatedTestdSession,
        admission: &TestdAdmission,
        request: &TestdAdmissionRequest,
    ) -> Result<bool, KernelServiceError> {
        let (live_epoch, live_generation) = session.live_authority(service)?;
        admission
            .validate()
            .map_err(|_| KernelServiceError::InvalidField {
                field: "testd_admission.admission",
                reason: "admission shape is invalid",
            })?;
        request
            .validate()
            .map_err(|_| KernelServiceError::InvalidField {
                field: "testd_admission.request",
                reason: "request shape is invalid",
            })?;
        request
            .validate_canonical_digest()
            .map_err(|_| KernelServiceError::InvalidField {
                field: "testd_admission.request_digest",
                reason: "request digest mismatch",
            })?;
        if !live_epoch.is_same_authority(&admission.authority_epoch)
            || live_generation != admission.generation
        {
            return Ok(false);
        }
        Ok(admission.job_id == request.job_id
            && admission.invocation_digest == request.invocation_digest
            && admission.target_roots_digest == request.target_roots_digest
            && admission
                .authority_epoch
                .is_same_authority(&request.authority_epoch)
            && admission.generation == request.generation)
    }
}

/// Authenticated testd session bound from live Kernel authority.
///
/// Mirrors `AuthenticatedDoctorSession::bind`: all fields come from the
/// Kernel service lineage and its consumed activation receipt at bind time.
/// No request DTO field contributes authority.
#[derive(Clone, Debug)]
struct AuthenticatedTestdSession {
    principal_ref: String,
    authority_epoch: EpochId,
    generation: u64,
}

impl AuthenticatedTestdSession {
    fn bind(service: &KernelService, principal_ref: &str) -> Result<Self, KernelServiceError> {
        validate_text_for_session(principal_ref)?;
        if service.generation_fenced() {
            return Err(KernelServiceError::GenerationFenced);
        }
        if service.state() != KernelServiceState::Ready {
            return Err(KernelServiceError::AdmissionClosed(service.state()));
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

    fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }

    fn principal_ref(&self) -> &str {
        &self.principal_ref
    }

    fn generation(&self) -> u64 {
        self.generation
    }

    fn live_authority(
        &self,
        service: &KernelService,
    ) -> Result<(EpochId, u64), KernelServiceError> {
        if service.generation_fenced() {
            return Err(KernelServiceError::GenerationFenced);
        }
        if service.state() != KernelServiceState::Ready {
            return Err(KernelServiceError::AdmissionClosed(service.state()));
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
}

fn validate_text_for_session(value: &str) -> Result<(), KernelServiceError> {
    validate_text(value, "testd_admission.principal")
}

fn handle(value: &str) -> PlatformHandle {
    PlatformHandle::new(value).expect("valid test handle")
}

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE_A).expect("valid test lineage"),
        NonZeroU64::new(sequence).expect("non-zero test sequence"),
    )
    .expect("valid test epoch")
}

fn foreign_epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE_B).expect("valid test lineage"),
        NonZeroU64::new(EPOCH_SEQUENCE).expect("non-zero test sequence"),
    )
    .expect("valid test epoch")
}

fn live_generation() -> ResourceGeneration {
    ResourceGeneration::new(GENERATION).expect("non-zero test generation")
}

fn supervision_incarnation() -> SupervisionLeaseIncarnationBinding {
    SupervisionLeaseIncarnationBinding {
        supervision_lease_scope_id: "eliot-supervision-scope:v1:test".to_owned(),
        supervision_lease_id: String::new(),
        scope_ref_digest: String::new(),
        installation_id: "installation-1".to_owned(),
        host_epoch: SupervisionJournalEpoch {
            lineage_id: "host-lineage-1".to_owned(),
            sequence: 1,
        },
        activation_id: "activation-1".to_owned(),
        activation_generation: SupervisionJournalEpoch {
            lineage_id: "activation-lineage-1".to_owned(),
            sequence: 1,
        },
        kernel_generation: SupervisionJournalEpoch {
            lineage_id: "kernel-lineage-1".to_owned(),
            sequence: 1,
        },
        watchdog_epoch: SupervisionJournalEpoch {
            lineage_id: "watchdog-lineage-1".to_owned(),
            sequence: 1,
        },
        observation_scope: SupervisionObservationScope {
            targets: vec!["eliot-kernel".to_owned()],
            sensor_profile: "eliot-runtime-live-v3".to_owned(),
            claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
            governance_axis: "runtime-live-v3".to_owned(),
        },
        wake_policy: RegisteredActivityWakePolicy::Disabled,
        predecessor: None,
    }
    .with_derived_ids()
    .expect("valid test incarnation")
}

fn candidate() -> HostKernelCandidateBinding {
    HostKernelCandidateBinding {
        installation_id: handle("installation-1"),
        host_epoch: AuthorityEpoch::new(1).expect("non-zero test epoch"),
        kernel_epoch: test_epoch(EPOCH_SEQUENCE),
        activation_id: handle("activation-1"),
        artifact_hash: handle("artifact-1"),
        config_hash: handle("config-1"),
        job_object_id: handle("Local\\Eliot-Host-Kernel-test"),
        pipe_identity: handle("\\\\.\\pipe\\eliot-kernel-test"),
        host_process: HostProcessBinding {
            process_id: 7,
            start_time_100ns: 9,
            image_path: "C:\\eliot\\host.exe".to_owned(),
        },
        job_binding: HostJobBinding {
            job: HostJobIdentity {
                name: "Local\\Eliot-Host-Kernel-test".to_owned(),
            },
            root: HostJobRoot {
                process: HostProcessBinding {
                    process_id: 42,
                    start_time_100ns: 10,
                    image_path: "C:\\eliot\\kernel.exe".to_owned(),
                },
                executable: HostFileIdentity {
                    volume_serial_number: 1,
                    file_index: 2,
                },
            },
        },
        supervision_incarnation: supervision_incarnation(),
        restart_budget: RestartBudget::new(1, 1).expect("valid test budget"),
        agent_bridge_admission: None,
        containment_action: None,
    }
}

fn permit(candidate: &HostKernelCandidateBinding) -> KernelActivationPermit {
    KernelActivationPermit {
        operation_id: handle("activation-operation-1"),
        candidate_binding_digest: candidate.compute_digest().expect("candidate digest"),
        prior_kernel_disposition_digest: "b".repeat(64),
        journal_transaction_id: handle("journal-transaction-1"),
        journal_sequence: 7,
        generation: live_generation(),
        authority_epoch: candidate.kernel_epoch.clone(),
        activation_nonce: KernelActivationNonce::new(handle(&"a".repeat(64)))
            .expect("valid test nonce"),
    }
}

fn ready_receipt(
    candidate: &HostKernelCandidateBinding,
    activation: &KernelActivationReceipt,
    evidence: &str,
) -> KernelReadyReceipt {
    KernelReadyReceipt {
        activation_id: candidate.activation_id.clone(),
        activation_operation_id: activation.operation_id.clone(),
        activation_nonce_digest: activation.activation_nonce_digest.clone(),
        process: ProcessObservation {
            process_id: handle("pid:42:start:10"),
            job_object_id: candidate.job_object_id.clone(),
            state: ServiceProcessState::Ready,
            health: HealthVector::healthy(),
            evidence_refs: vec![handle("process-evidence")],
        },
        health: HealthVector::healthy(),
        evidence_refs: vec![handle(evidence)],
    }
}

/// Drives a real `KernelService` to `Ready` on the test lineage/sequence and
/// generation, so the seam binds live authority.
fn ready_service() -> KernelService {
    let mut service = KernelService::new([7; 32], 2, 4).expect("test service");
    let candidate = candidate();
    let permit = permit(&candidate);
    service.reconcile(candidate.clone()).expect("reconcile");
    service.apply(KernelControlCommand::Shadow).expect("shadow");
    service
        .apply(KernelControlCommand::PrepareHandoff)
        .expect("handoff");
    let activation = service
        .activate_permit(&permit, live_generation(), "c".repeat(64))
        .expect("activation");
    service
        .publish_ready(ready_receipt(&candidate, &activation, "ready-initial"))
        .expect("ready");
    assert_eq!(service.state(), KernelServiceState::Ready);
    service
}

fn session(service: &KernelService) -> AuthenticatedTestdSession {
    AuthenticatedTestdSession::bind(service, "testd-peer:test").expect("test session")
}

fn wire_request(
    job_id: &str,
    invocation_id: &str,
    profile: &str,
    target: &str,
    source: &str,
    build_root: &str,
    cache_root: &str,
    epoch: EpochId,
    cancelled: bool,
) -> TestdAdmissionRequest {
    let digest = invocation_digest(job_id, invocation_id, profile, target, &epoch, GENERATION);
    TestdAdmissionRequest {
        wire_id: TESTD_ADMISSION_OPERATION.to_owned(),
        wire_version: TESTD_ADMISSION_OPERATION_VERSION,
        job_id: job_id.to_owned(),
        invocation_id: invocation_id.to_owned(),
        invocation_digest: digest,
        target_roots_digest: roots_digest(source, build_root, cache_root),
        authority_epoch: epoch,
        generation: GENERATION,
        cancelled,
        request_digest: String::new(),
    }
    .with_computed_digest()
    .unwrap()
}

fn effect_request() -> TestdAdmissionRequest {
    wire_request(
        "job-1",
        "operation-1",
        "cargo-test",
        "C:\\source",
        "C:\\source",
        "C:\\contour\\build",
        "C:\\contour\\build",
        test_epoch(EPOCH_SEQUENCE),
        false,
    )
}

/// Builds the concrete consuming [`ProcessRequest`] the dispatch contour
/// delivers: a sealed intent plus its consuming permit, validated at
/// construction. Test-only permit scaffolding standing in for the
/// Kernel-issued permit; production code never mints permits. The request
/// proves `ProcessRequest::validate` (the same call
/// `issue_process_admission` makes) plus the fence exact-tuple binding
/// against the live epoch.
fn test_process_request(
    job_id: &str,
    operation_id: &str,
    epoch: EpochId,
    generation: u64,
    source: &str,
    target: &str,
) -> ProcessRequest {
    let generation_value = Generation::new(generation).unwrap();
    let intent = ProcessIntent::new(
        OperationId::new(operation_id).unwrap(),
        ProcessTreeId::new("tree-1").unwrap(),
        JobId::new(job_id).unwrap(),
        ImageId::new("image-1").unwrap(),
        SessionId::new("session-1").unwrap(),
        generation_value,
        "C:\\tools\\worker.exe",
        "c".repeat(64),
        vec!["--check".to_owned()],
        source,
        EnvironmentProjection::new(
            BTreeMap::from([
                ("CARGO_TARGET_DIR".to_owned(), target.to_owned()),
                ("CARGO_HOME".to_owned(), target.to_owned()),
            ]),
            Vec::new(),
            EnvironmentInheritance::None,
        )
        .unwrap(),
        ResourceLimits::new(10_000, Some(5_000), Some(1_048_576), 4096, 4096, 4).unwrap(),
    )
    .unwrap();
    let mut authority = DispatchPermitAuthority::activate(
        DispatchAuthorityId::new("authority-1").unwrap(),
        KernelDispatchKey::from_secret_bytes([0x5a; 32]).unwrap(),
    );
    let fence = FencingToken::new(epoch, generation_value, "fence-1").unwrap();
    let permit = authority
        .issue(
            &intent,
            PermitIssuance::new(
                ActionLeaseRef::new("lease-1").unwrap(),
                fence,
                BTreeMap::from([
                    ("authority".to_owned(), "a".repeat(64)),
                    ("state".to_owned(), "b".repeat(64)),
                ]),
                1,
                2,
                "nonce-1",
            )
            .unwrap(),
        )
        .unwrap();
    ProcessRequest::new(intent, permit).unwrap()
}

#[test]
fn front_door_admits_one_admission_and_lost_reply_reconciles_same_permit() {
    let store = TestAdmissionStore::new();
    let service = ready_service();
    let session = session(&service);
    // Live context comes from the service lineage, never the envelope.
    assert!(
        session
            .authority_epoch()
            .is_same_authority(&test_epoch(EPOCH_SEQUENCE))
    );
    assert_eq!(session.generation(), GENERATION);

    let request = effect_request();
    let response = store
        .admit(&session, &service, &request, NOW_UNIX_NANOS)
        .unwrap();
    let TestdResponse::Admitted(admission) = response else {
        panic!("front door must admit the registered job, got {response:?}");
    };
    admission.validate().unwrap();
    assert_eq!(session.principal_ref(), "testd-peer:test");
    // One admitted test execution: exactly the presented invocation digest,
    // pending independent verification.
    assert_eq!(admission.job_id, "job-1");
    assert!(!admission.cancelled);
    assert_eq!(admission.invocation_digest, request.invocation_digest);
    // Bare paths never serve as identity: the admission carries only
    // digests plus the epoch/generation tuple.
    assert_eq!(admission.invocation_digest.len(), 64);
    assert_eq!(admission.target_roots_digest.len(), 64);
    assert!(!admission.invocation_digest.contains('\\'));
    assert!(!admission.admission_digest.contains('\\'));

    // The sealed consuming request validates through the shared contour
    // (the same `ProcessRequest::validate` testd-core calls) and binds the
    // live epoch/generation by exact tuple, never by path.
    let process = test_process_request(
        "job-1",
        "operation-1",
        test_epoch(EPOCH_SEQUENCE),
        GENERATION,
        "C:\\source",
        "C:\\contour\\build",
    );
    process.validate().unwrap();
    assert!(
        process
            .fence()
            .authority_epoch()
            .is_same_authority(session.authority_epoch())
    );
    assert_eq!(process.generation().get(), GENERATION);

    // Lost reply: the retained admission reconciles as the same permit
    // without admitting again — no new row, no new effect.
    assert!(
        store
            .reconcile_delivery(&service, &session, &admission, &request)
            .unwrap()
    );
    // ... while a different delivery never reconciles as this admission.
    let other = wire_request(
        "job-9",
        "operation-1",
        "cargo-test",
        "C:\\source",
        "C:\\source",
        "C:\\contour\\build",
        "C:\\contour\\build",
        test_epoch(EPOCH_SEQUENCE),
        false,
    );
    assert!(
        !store
            .reconcile_delivery(&service, &session, &admission, &other)
            .unwrap()
    );
    assert_eq!(
        store
            .rows
            .lock()
            .expect("test store is single-threaded")
            .len(),
        1
    );
    assert_eq!(
        store
            .effects
            .lock()
            .expect("test store is single-threaded")
            .len(),
        1
    );
}

#[test]
fn front_door_duplicate_returns_same_admission_without_second_effect() {
    let store = TestAdmissionStore::new();
    let service = ready_service();
    let session = session(&service);
    let request = effect_request();

    let first = store
        .admit(&session, &service, &request, NOW_UNIX_NANOS)
        .unwrap();
    let second = store
        .admit(&session, &service, &request, NOW_UNIX_NANOS)
        .unwrap();
    let (TestdResponse::Admitted(first), TestdResponse::Admitted(second)) = (first, second) else {
        panic!("exact replay must rebuild the same admission");
    };
    // Exact replay returns the same permit: identical digests, no second row.
    assert_eq!(first.admission_digest, second.admission_digest);
    assert_eq!(first.invocation_digest, second.invocation_digest);
    assert_eq!(first.target_roots_digest, second.target_roots_digest);

    // One identity keeps one effect intent: no second staged effect.
    assert_eq!(
        store
            .effects
            .lock()
            .expect("test store is single-threaded")
            .len(),
        1
    );
    assert_eq!(
        store
            .rows
            .lock()
            .expect("test store is single-threaded")
            .len(),
        1
    );
}

#[test]
fn front_door_conflict_cancel_entry_and_diagnosis_path() {
    let store = TestAdmissionStore::new();
    let service = ready_service();
    let session = session(&service);
    let first_request = effect_request();
    let first = store
        .admit(&session, &service, &first_request, NOW_UNIX_NANOS)
        .unwrap();
    assert!(matches!(first, TestdResponse::Admitted(_)));

    // Same job identity with a changed invocation: typed conflict, never a
    // second admission.
    let changed_invocation = wire_request(
        "job-1",
        "operation-1",
        "other-profile",
        "C:\\source",
        "C:\\source",
        "C:\\contour\\build",
        "C:\\contour\\build",
        test_epoch(EPOCH_SEQUENCE),
        false,
    );
    let conflict = store
        .admit(&session, &service, &changed_invocation, NOW_UNIX_NANOS)
        .unwrap();
    let TestdResponse::Conflict(conflict) = conflict else {
        panic!("changed invocation must conflict, got {conflict:?}");
    };
    conflict.validate().unwrap();
    assert!(
        conflict
            .changed_fields
            .contains(&"invocation_digest".to_owned())
    );

    // Same job identity with a changed root: typed conflict via the roots
    // digest, never bare-path equality.
    let changed_root = wire_request(
        "job-1",
        "operation-1",
        "cargo-test",
        "C:\\source",
        "C:\\source",
        "C:\\contour\\other",
        "C:\\contour\\other",
        test_epoch(EPOCH_SEQUENCE),
        false,
    );
    let conflict = store
        .admit(&session, &service, &changed_root, NOW_UNIX_NANOS)
        .unwrap();
    let TestdResponse::Conflict(conflict) = conflict else {
        panic!("changed root must conflict, got {conflict:?}");
    };
    assert!(
        conflict
            .changed_fields
            .contains(&"target_roots_digest".to_owned())
    );

    // Cancellation has its own control entry: a cancellation-flagged request
    // is admitted cancelled with no effect intent. It is submitted past the
    // normal admission so the budget gate proves nothing but the control
    // separation.
    let cancel_request = wire_request(
        "job-cancel-1",
        "operation-1",
        "cargo-test",
        "C:\\source",
        "C:\\source",
        "C:\\contour\\build",
        "C:\\contour\\build",
        test_epoch(EPOCH_SEQUENCE),
        true,
    );
    let cancelled = store
        .cancel(&session, &service, &cancel_request, LATER_UNIX_NANOS)
        .unwrap();
    let TestdResponse::Admitted(cancelled) = cancelled else {
        panic!("cancellation entry must admit the flagged request, got {cancelled:?}");
    };
    cancelled.validate().unwrap();
    assert!(cancelled.cancelled);
    // A cancelled admission stages no effect.
    assert_eq!(
        store
            .effects
            .lock()
            .expect("test store is single-threaded")
            .len(),
        1
    );

    // ... while an effect attempt submitted to the cancellation entry fails
    // closed without admission.
    let refused = store.cancel(&session, &service, &first_request, NOW_UNIX_NANOS);
    assert!(matches!(
        refused,
        Err(KernelServiceError::InvalidField { .. })
    ));

    // Read-only diagnosis path: a diagnose-only work kind classifies without
    // admission, while the test kind does not.
    assert!(is_testd_diagnose_only(TestdWorkKind::Diagnose));
    assert!(!is_testd_diagnose_only(TestdWorkKind::Test));
}

#[test]
fn front_door_fails_closed_without_activation_and_on_stale_authority() {
    // No activation, no session: a Cold service binds nothing.
    let cold = KernelService::new([9; 32], 2, 4).expect("test service");
    assert_eq!(cold.state(), KernelServiceState::Cold);
    assert!(AuthenticatedTestdSession::bind(&cold, "testd-peer:test").is_err());

    // No peer, no session: a blank principal binds nothing on a Ready service.
    let service = ready_service();
    assert!(AuthenticatedTestdSession::bind(&service, "   ").is_err());

    // Stale epoch, no protected input: a foreign-lineage fence is rejected
    // before any durable write, through the seam. The shared fence shape
    // proves the same rule testd-core enforces.
    let store = TestAdmissionStore::new();
    let session = session(&service);
    let fence = StateFence::new(foreign_epoch(), GENERATION, "b".repeat(64)).expect("test fence");
    fence.validate().expect("test fence validates");
    assert!(check_fence_against_epoch(&fence, session.authority_epoch()).is_err());
    let request = wire_request(
        "job-1",
        "operation-1",
        "cargo-test",
        "C:\\source",
        "C:\\source",
        "C:\\contour\\build",
        "C:\\contour\\build",
        foreign_epoch(),
        false,
    );
    let response = store
        .admit(&session, &service, &request, NOW_UNIX_NANOS)
        .unwrap();
    let TestdResponse::Rejected(rejection) = response else {
        panic!("foreign lineage must be rejected, got {response:?}");
    };
    rejection.validate().unwrap();
    assert!(matches!(rejection.reason, TestdRejectionReason::StaleEpoch));
    assert!(
        store
            .rows
            .lock()
            .expect("test store is single-threaded")
            .is_empty()
    );
    assert!(
        store
            .effects
            .lock()
            .expect("test store is single-threaded")
            .is_empty()
    );

    // Stale generation is rejected the same way, before any write.
    let stale_generation = wire_request(
        "job-2",
        "operation-1",
        "cargo-test",
        "C:\\source",
        "C:\\source",
        "C:\\contour\\build",
        "C:\\contour\\build",
        test_epoch(EPOCH_SEQUENCE),
        false,
    );
    let mut stale_generation = stale_generation;
    stale_generation.generation = GENERATION + 1;
    stale_generation = stale_generation.with_computed_digest().unwrap();
    let response = store
        .admit(&session, &service, &stale_generation, NOW_UNIX_NANOS)
        .unwrap();
    assert!(matches!(
        response,
        TestdResponse::Rejected(TestdRejection {
            reason: TestdRejectionReason::StaleGeneration,
            ..
        })
    ));

    // Unknown wire, no admission: the seam enforces the exact wire pair.
    let mut request = effect_request();
    request.wire_id = "eliot.kernel.unknown".to_owned();
    request = request.with_computed_digest().unwrap();
    let response = store
        .admit(&session, &service, &request, NOW_UNIX_NANOS)
        .unwrap();
    let TestdResponse::Rejected(rejection) = response else {
        panic!("unknown wire must be rejected, got {response:?}");
    };
    rejection.validate().unwrap();
    assert!(matches!(
        rejection.reason,
        TestdRejectionReason::UnknownWireVersion
    ));
}
