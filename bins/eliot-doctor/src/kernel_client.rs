#![forbid(unsafe_code)]

//! Authenticated Kernel IPC client for the one-shot Doctor (Slice C, issue #461).
//!
//! This module binds the doctor binary to the live Kernel front door and
//! speaks exactly one service exchange: the versioned
//! `eliot.kernel.doctor-repair-attempt` wire carrying a full
//! [`DoctorRepairAttemptRequest`] envelope to a typed
//! [`DoctorRepairResponse`]. It never downgrades to the legacy open
//! [`eliot_doctor_core::RepairRequest`] shape: the legacy admit entry is
//! refused fail-closed because a bare `RepairRequest` cannot carry the
//! attempt/effect identity (attempt seed, effect sequence, target digest)
//! the wire requires.
//!
//! Authority rules enforced here:
//!
//! - Bootstrap reads only the protected installation-owned front-door
//!   declaration. No recipe, effect, operation, approval, lease, fence, or
//!   authority value is taken from argv, stdin, or environment; those
//!   surfaces carry at most `--help` / `--version`.
//! - Generation binding comes from the live Kernel `ServerHello`, checked
//!   inside [`KernelClient`] against the protected declaration (authority
//!   epoch exact tuple, generation, artifact digest, config snapshot
//!   digest). The live epoch is additionally retained from the authenticated
//!   health reply and is the only epoch the admitted driver binds against.
//! - The concrete [`ProcessRequest`] executed by the adapter is an in-memory
//!   composition value delivered with the dispatch contour. It is never
//!   deserialized from a wire type, never built from caller surfaces, and
//!   this module never mints a permit.
//! - One shot performs at most one submit and at most one effect dispatch.
//!   A lost submit reply exits the shot without effect and without retry;
//!   only the executor-owned
//!   [`reconcile_admitted_unknown`][eliot_doctor::admitted_effect::AutomaticSafeAdapter::reconcile_admitted_unknown]
//!   path may disposition an unknown outcome, keyed by the same effect
//!   digest.

use std::sync::Arc;

use eliot_cli::kernel_client::{KernelClient, KernelClientError};
use eliot_contracts::EpochId;
use eliot_doctor::admitted_effect::{
    AdapterError, AttemptInputs, AutomaticSafeAdapter, EvidenceCollector, OneShotOutcome,
    project_cancelled, project_diagnosis,
};
use eliot_doctor_core::{
    ClosedRepairRequest, DoctorError, EffectIntent, EffectOutcome, KernelAdmission,
    KernelDoctorClient, RepairClass, RepairRecipeManifest, RepairRequest,
};
use eliot_kernel_service::{
    DOCTOR_REPAIR_WIRE_ID, DOCTOR_REPAIR_WIRE_VERSION, DoctorRepairAttemptRequest,
    DoctorRepairRejection, DoctorRepairRejectionReason, DoctorRepairResponse, KernelServiceError,
    route_doctor_repair,
};
use eliot_process::{ProcessExecutor, ProcessRequest};
use time::OffsetDateTime;

/// Stable operation selector for the Kernel-owned Doctor repair-attempt
/// wire. Aliased to the service authority so the name cannot drift: the
/// wire stays `eliot.kernel.doctor-repair-attempt`.
pub const DOCTOR_REPAIR_OPERATION: &str = DOCTOR_REPAIR_WIRE_ID;
/// Wire revision admitted by this client. Aliased to the service authority.
#[allow(
    dead_code,
    reason = "Slice-C dispatch contour pins this version when the delivery seam lands; asserted by the wire-identity test"
)]
pub const DOCTOR_REPAIR_OPERATION_VERSION: u16 = DOCTOR_REPAIR_WIRE_VERSION;

/// Residual naming the follow-up contour that delivers the session-bound
/// attempt envelope plus the concrete IPC-delivered [`ProcessRequest`] to a
/// live one-shot invocation. Until it lands, the binary fails closed after
/// the authenticated bootstrap instead of inventing admission material.
pub const DOCTOR_DISPATCH_RESIDUAL: &str = "issue-461 slice-C follow-up: kernel dispatch contour delivering the session-bound DoctorRepairAttemptRequest envelope, closed request, manifest, live epoch, and concrete ProcessRequest to the one-shot doctor invocation";

/// Typed failure for the authenticated doctor exchange. Every variant is
/// fail-closed: the one-shot driver maps each to exit 78 without effect,
/// except through the explicit executor-owned unknown-outcome path.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DoctorIpcError {
    /// The protected front door is unavailable or the transport failed
    /// before a typed Kernel reply existed.
    #[error("kernel front door unavailable: {0}")]
    Transport(String),
    /// The live Kernel does not advertise the doctor operation.
    #[error("kernel does not advertise the doctor operation (KERNEL_ADMISSION_REQUIRED)")]
    NotAdvertised,
    /// The exchange violated the closed contract before any effect.
    #[error("kernel doctor exchange violated the closed contract: {0}")]
    Contract(String),
    /// The submit reply was lost: the request may have reached the Kernel,
    /// but its outcome was not proven by an exact typed reply. Carry the
    /// exact submit identity so a later invocation can reconcile under the
    /// same identity; this shot must not retry blind.
    #[error(
        "kernel reply lost after submit of attempt {attempt_id}; reconcile by exact identity, never blind-retry"
    )]
    UnknownOutcome {
        /// Submitted attempt identity seed.
        attempt_id: String,
        /// Canonical digest of the submitted envelope.
        request_digest: String,
    },
}

impl From<KernelClientError> for DoctorIpcError {
    fn from(error: KernelClientError) -> Self {
        Self::Transport(error.to_string())
    }
}

impl From<DoctorIpcError> for AdapterError {
    fn from(error: DoctorIpcError) -> Self {
        match error {
            DoctorIpcError::NotAdvertised => Self::Admission(DoctorError::OperationNotAdmitted),
            other => Self::KernelClient(Box::new(other)),
        }
    }
}

/// Maps a typed Kernel refusal cause to the closest closed doctor error.
/// Every mapping stays on the admission axis, so each exits 78 without
/// effect.
#[allow(
    dead_code,
    reason = "Slice-C dispatch contour reaches this refusal mapping through drive_admitted_attempt; exercised by the module tests"
)]
fn rejection_doctor_error(reason: DoctorRepairRejectionReason) -> DoctorError {
    use DoctorRepairRejectionReason as Reason;
    match reason {
        Reason::StaleEpoch | Reason::StaleFence | Reason::StaleGeneration => {
            DoctorError::InvalidFence
        }
        Reason::ExpiredDeadline | Reason::CooldownActive => DoctorError::DeadlineOrBudget,
        Reason::ExpiredLease => DoctorError::LeaseExpired,
        Reason::RecipeNotRegistered | Reason::RecipeDigestMismatch => {
            DoctorError::AdmissionMismatch
        }
        Reason::RecipeNotApplicable => DoctorError::RecipeNotApplicable,
        Reason::OperationNotAdmitted => DoctorError::OperationNotAdmitted,
        Reason::EffectNotAuthorized => DoctorError::EffectAuthorizationMismatch,
        Reason::ApprovalRequired => DoctorError::ApprovalRequired,
        Reason::ApprovalNotActivated => DoctorError::ApprovalMismatch,
        Reason::BudgetExhausted | Reason::Quarantined => DoctorError::BudgetExhausted,
        Reason::UnknownWireVersion | Reason::InvalidRequestField => DoctorError::IdentityMismatch,
    }
}

/// Durable binding retained from exactly one admitted Kernel reply, used to
/// check the pre-effect intent without a second network round trip.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RetainedAdmission {
    attempt_id: String,
    job_id: String,
    recipe_digest: String,
    effect_digest: Option<String>,
}

/// Authenticated Kernel front-door client for the one-shot Doctor.
///
/// The client owns transport and typed exchange only: protected-config
/// bootstrap, live advertisement probe, one full-envelope submit, and the
/// idempotent intent check against the retained admission. It mints no
/// permit, builds no [`ProcessRequest`], and executes nothing.
pub struct KernelDoctorIpcClient {
    client: KernelClient,
    #[allow(
        dead_code,
        reason = "Slice-C dispatch contour reads the live epoch for the lineage-aware binding; retained at bootstrap"
    )]
    live_epoch: Option<EpochId>,
    retained: Option<RetainedAdmission>,
}

impl KernelDoctorIpcClient {
    /// Opens the authenticated generation-bound bootstrap: loads the
    /// installation-owned protected front-door declaration, completes the
    /// EBP handshake (the live `ServerHello` is checked against the
    /// protected authority epoch, generation, artifact, and snapshot
    /// inside [`KernelClient`]), and probes health. Retains the live
    /// authority epoch echoed by the authenticated health reply for the
    /// lineage-aware identity binding.
    pub fn connect() -> Result<Self, DoctorIpcError> {
        let mut client = KernelClient::load().map_err(DoctorIpcError::from)?;
        let health = client.probe().map_err(DoctorIpcError::from)?;
        require_health_open(&health)?;
        let live_epoch = parse_live_epoch(&health)?;
        Ok(Self {
            client,
            live_epoch: Some(live_epoch),
            retained: None,
        })
    }

    /// Returns the live authority epoch retained from the authenticated
    /// bootstrap, when the bootstrap completed.
    #[allow(
        dead_code,
        reason = "Slice-C dispatch contour reads the live epoch for the lineage-aware binding; exercised by the module tests"
    )]
    #[must_use]
    pub fn live_epoch(&self) -> Option<&EpochId> {
        self.live_epoch.as_ref()
    }

    /// Submits one full repair-attempt envelope and returns the typed Kernel
    /// answer. The envelope is validated locally first (exact wire pair plus
    /// canonical digest); the reply is parsed as the exact
    /// [`DoctorRepairResponse`] union, validated, and echo-checked. Refusal
    /// and conflict answers return as typed data without effect; only
    /// transport loss before a typed reply becomes
    /// [`DoctorIpcError::UnknownOutcome`], carrying the submit identity for
    /// exact-identity reconciliation instead of a blind retry.
    #[allow(
        dead_code,
        reason = "Slice-C dispatch contour submits through drive_admitted_attempt; exercised by the module tests"
    )]
    pub fn submit_repair_attempt(
        &mut self,
        request: &DoctorRepairAttemptRequest,
    ) -> Result<DoctorRepairResponse, DoctorIpcError> {
        if !route_doctor_repair(&request.wire_id, request.wire_version) {
            return Err(DoctorIpcError::Contract(
                "doctor repair wire identity or version is not the admitted pair".to_owned(),
            ));
        }
        request
            .validate()
            .map_err(|error| DoctorIpcError::Contract(error.to_string()))?;
        request
            .validate_canonical_digest()
            .map_err(|error| DoctorIpcError::Contract(error.to_string()))?;
        let payload = serde_json::to_value(request)
            .map_err(|error| DoctorIpcError::Contract(error.to_string()))?;
        let reply = self
            .client
            .transact_json(DOCTOR_REPAIR_OPERATION, payload)
            .map_err(|error| match error {
                KernelClientError::UnknownOutcome(_) => DoctorIpcError::UnknownOutcome {
                    attempt_id: request.attempt_id.clone(),
                    request_digest: request.request_digest.clone(),
                },
                other => DoctorIpcError::Transport(other.to_string()),
            })?;
        let response: DoctorRepairResponse = serde_json::from_value(reply)
            .map_err(|error| DoctorIpcError::Contract(error.to_string()))?;
        response
            .validate()
            .map_err(|error| DoctorIpcError::Contract(error.to_string()))?;
        match &response {
            DoctorRepairResponse::Admitted(admission) => {
                if admission.attempt_id != request.attempt_id {
                    return Err(DoctorIpcError::Contract(
                        "kernel admission did not echo the submitted attempt identity".to_owned(),
                    ));
                }
                let envelope: ClosedRepairRequest =
                    serde_json::from_str(&request.closed_request_json)
                        .map_err(|error| DoctorIpcError::Contract(error.to_string()))?;
                self.retained = Some(RetainedAdmission {
                    attempt_id: admission.attempt_id.clone(),
                    job_id: envelope.request_id.clone(),
                    recipe_digest: admission.recipe_digest.clone(),
                    effect_digest: admission.effect_digest.clone(),
                });
            }
            DoctorRepairResponse::Rejected(rejection) => {
                if rejection.attempt_ref != request.attempt_id {
                    return Err(DoctorIpcError::Contract(
                        "kernel rejection did not echo the submitted attempt identity".to_owned(),
                    ));
                }
            }
            DoctorRepairResponse::Conflict(conflict) => {
                if conflict.attempt_id != request.attempt_id {
                    return Err(DoctorIpcError::Contract(
                        "kernel conflict did not echo the submitted attempt identity".to_owned(),
                    ));
                }
            }
        }
        Ok(response)
    }
}

impl KernelDoctorClient for KernelDoctorIpcClient {
    type Error = DoctorIpcError;

    fn advertise_doctor(&mut self) -> Result<bool, Self::Error> {
        let health = self.client.probe().map_err(DoctorIpcError::from)?;
        require_health_open(&health)?;
        Ok(health_advertises_doctor(&health))
    }

    fn admit(&mut self, _request: &RepairRequest) -> Result<KernelAdmission, Self::Error> {
        Err(DoctorIpcError::Contract(
            "legacy RepairRequest cannot carry the doctor repair-attempt identity (attempt seed, effect sequence, target digest); present the full DoctorRepairAttemptRequest envelope via submit_repair_attempt"
                .to_owned(),
        ))
    }

    fn record_intent(&mut self, intent: &EffectIntent) -> Result<(), Self::Error> {
        let retained = self.retained.as_ref().ok_or_else(|| {
            DoctorIpcError::Contract(
                "no admitted attempt is retained for this intent; submit the full envelope first"
                    .to_owned(),
            )
        })?;
        if intent.attempt_id == retained.attempt_id
            && intent.job_id == retained.job_id
            && intent.recipe_digest == retained.recipe_digest
            && Some(intent.effect_digest.as_str()) == retained.effect_digest.as_deref()
        {
            Ok(())
        } else {
            Err(DoctorIpcError::Contract(
                "effect intent does not match the retained Kernel admission binding".to_owned(),
            ))
        }
    }

    fn execute(&mut self, _intent: &EffectIntent) -> Result<EffectOutcome, Self::Error> {
        Err(DoctorIpcError::Contract(
            "effect execution is owned by AutomaticSafeAdapter over the shared governed ProcessExecutor contour, not by the IPC client"
                .to_owned(),
        ))
    }

    fn reconcile(
        &mut self,
        _job_id: &str,
        _attempt_id: &str,
    ) -> Result<EffectOutcome, Self::Error> {
        Err(DoctorIpcError::Contract(
            "reconciliation is owned by AutomaticSafeAdapter::reconcile_admitted_unknown by exact effect identity, not by the IPC client"
                .to_owned(),
        ))
    }
}

/// Thin admitted transport behind one exact attempt envelope.
///
/// Implemented by [`KernelDoctorIpcClient`] in production (through the
/// authenticated [`KernelClient::transact_json`]) and by clearly-marked test
/// doubles where a live Kernel is unavailable. Transport failures stay
/// transport failures; they are never mapped to admission or success. A
/// test double must validate the envelope and echo-check the reply exactly
/// like [`KernelDoctorIpcClient::submit_repair_attempt`].
#[allow(
    dead_code,
    reason = "Slice-C dispatch contour drives through this transport bound; exercised by the module tests"
)]
pub trait AdmittedDoctorTransport: KernelDoctorClient {
    /// Submits one full repair-attempt envelope; the wire selector is a
    /// contract constant, never caller authority.
    fn submit_repair_attempt(
        &mut self,
        request: &DoctorRepairAttemptRequest,
    ) -> Result<DoctorRepairResponse, DoctorIpcError>;
}

impl AdmittedDoctorTransport for KernelDoctorIpcClient {
    fn submit_repair_attempt(
        &mut self,
        request: &DoctorRepairAttemptRequest,
    ) -> Result<DoctorRepairResponse, DoctorIpcError> {
        KernelDoctorIpcClient::submit_repair_attempt(self, request)
    }
}

/// Requires the authenticated health reply to report an open Kernel.
fn require_health_open(health: &serde_json::Value) -> Result<(), DoctorIpcError> {
    if health.get("status").and_then(serde_json::Value::as_str) != Some("OPEN") {
        return Err(DoctorIpcError::Transport(
            "kernel health handshake was not OPEN".to_owned(),
        ));
    }
    Ok(())
}

/// Parses the live authority epoch echoed by the authenticated health reply.
/// The value travels over the session the handshake already bound to the
/// protected declaration; it is never taken from argv, stdin, or
/// environment.
fn parse_live_epoch(health: &serde_json::Value) -> Result<EpochId, DoctorIpcError> {
    let epoch_value = health.get("authority_epoch").ok_or_else(|| {
        DoctorIpcError::Contract("kernel health reply carries no live authority epoch".to_owned())
    })?;
    serde_json::from_value(epoch_value.clone()).map_err(|_| {
        DoctorIpcError::Contract(
            "kernel health reply authority epoch is not a lineaged epoch".to_owned(),
        )
    })
}

/// Reports whether the authenticated health reply explicitly advertises the
/// exact doctor repair-attempt wire. Absent advertisement fields mean not
/// advertised: the check is fail-closed and never invents authority.
fn health_advertises_doctor(health: &serde_json::Value) -> bool {
    if health
        .get("doctor_repair_advertised")
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
                .any(|operation| operation.as_str() == Some(DOCTOR_REPAIR_OPERATION))
        })
}

/// Material presented to one one-shot invocation by the dispatch contour.
///
/// Every identity-bearing value arrives with the authenticated dispatch,
/// never from argv, stdin, or environment. The byte-identity between the
/// envelope and the parsed closed request is re-proved by the driver; a
/// mismatch fails closed before any submit.
#[allow(
    dead_code,
    reason = "Slice-C dispatch contour constructs this presentation; exercised by the module tests"
)]
pub struct PresentedAttempt {
    /// Full wire envelope: attempt seed, effect sequence, opaque closed
    /// request bytes, target digest, and canonical digest.
    pub attempt: DoctorRepairAttemptRequest,
    /// Parsed closed request; must equal the envelope bytes exactly.
    pub request: ClosedRepairRequest,
    /// The exact admitted manifest revision the operations resolve against.
    pub manifest: RepairRecipeManifest,
    /// Concrete IPC-delivered process request for the single consuming
    /// dispatch. An in-memory composition value, never deserialized.
    pub process: ProcessRequest,
    /// Live Kernel epoch from the authenticated bootstrap, used for the
    /// lineage-aware attempt binding. Never envelope bytes.
    pub epoch: EpochId,
}

/// Drives exactly one admitted one-shot attempt to exactly one typed
/// outcome.
///
/// Sequence: prove envelope/closed byte-identity; route diagnose-only
/// admissions to the read-only [`project_diagnosis`] path without touching
/// transport or executor; submit the full envelope once; map refusal and
/// conflict to fail-closed admission errors without effect; validate the
/// admitted reply and its echo plus the recomputed lineage-aware attempt
/// and effect digests; project cancelled admissions without executing;
/// then run the single consuming effect through the bound
/// [`AutomaticSafeAdapter`] and return its one typed outcome. A lost submit
/// reply exits the shot as a transport failure without retry; executor-side
/// unknown outcomes stay reconcile-by-identity inside the adapter.
#[allow(
    dead_code,
    reason = "Slice-C one-shot entry: the dispatch contour binds the presentation once the delivery seam lands; exercised by the module tests"
)]
pub async fn drive_admitted_attempt<T, E>(
    transport: &mut T,
    executor: Arc<E>,
    sink: Arc<EvidenceCollector>,
    presented: PresentedAttempt,
    now: OffsetDateTime,
) -> Result<OneShotOutcome, AdapterError>
where
    T: AdmittedDoctorTransport,
    T::Error: std::error::Error + Send + Sync + 'static,
    E: ProcessExecutor + 'static,
{
    let PresentedAttempt {
        attempt,
        request,
        manifest,
        process,
        epoch,
    } = presented;
    let envelope: ClosedRepairRequest = serde_json::from_str(&attempt.closed_request_json)
        .map_err(|error| {
            AdapterError::KernelClient(Box::new(DoctorIpcError::Contract(error.to_string())))
        })?;
    if envelope != request {
        return Err(AdapterError::Admission(DoctorError::IdentityMismatch));
    }
    if matches!(request.recipe.repair_class, RepairClass::DiagnoseOnly) {
        return project_diagnosis(&request, &manifest, now);
    }
    let response = transport
        .submit_repair_attempt(&attempt)
        .map_err(AdapterError::from)?;
    let admission = match response {
        DoctorRepairResponse::Admitted(admission) => admission,
        DoctorRepairResponse::Rejected(rejection) => {
            return Err(map_rejection(&rejection));
        }
        DoctorRepairResponse::Conflict(_) => {
            return Err(AdapterError::Admission(DoctorError::IdentityMismatch));
        }
    };
    admission.validate().map_err(kernel_service_error)?;
    if admission.attempt_id != attempt.attempt_id {
        return Err(AdapterError::Admission(DoctorError::AdmissionMismatch));
    }
    if request.cancellation || admission.cancelled {
        return project_cancelled(&request, &manifest, now);
    }
    if request.operations.len() != 1 {
        return Err(AdapterError::Admission(DoctorError::OperationNotAdmitted));
    }
    let operation = request.operations[0].clone();
    if operation.operation_id() != admission.operation_id.as_str() {
        return Err(AdapterError::Admission(
            DoctorError::EffectAuthorizationMismatch,
        ));
    }
    let bound_attempt = request
        .bind_attempt_on_epoch(&manifest, &attempt.attempt_id, &operation, &epoch, now)
        .map_err(AdapterError::Admission)?;
    if bound_attempt.digest() != admission.attempt_digest {
        return Err(AdapterError::Admission(DoctorError::AdmissionMismatch));
    }
    let bound_effect = request
        .bind_effect(&bound_attempt, &operation, attempt.effect_seq)
        .map_err(AdapterError::Admission)?;
    if admission.effect_digest.as_deref() != Some(bound_effect.digest()) {
        return Err(AdapterError::Admission(DoctorError::AdmissionMismatch));
    }
    let adapter = AutomaticSafeAdapter::bind(executor, operation)?;
    adapter
        .execute_admitted_attempt(AttemptInputs {
            client: transport,
            request: &request,
            manifest: &manifest,
            attempt_id: attempt.attempt_id.as_str(),
            epoch: &epoch,
            sink,
            process_request: process,
            now,
        })
        .await
}

#[allow(
    dead_code,
    reason = "Slice-C dispatch contour reaches this mapping through drive_admitted_attempt; exercised by the module tests"
)]
fn kernel_service_error(error: KernelServiceError) -> AdapterError {
    AdapterError::KernelClient(Box::new(error))
}

#[allow(
    dead_code,
    reason = "Slice-C dispatch contour reaches this mapping through drive_admitted_attempt; exercised by the module tests"
)]
fn map_rejection(rejection: &DoctorRepairRejection) -> AdapterError {
    AdapterError::Admission(rejection_doctor_error(rejection.reason))
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::EpochLineageId;
    use eliot_doctor::admitted_effect::{
        EXIT_KERNEL_ADMISSION_REQUIRED, EXIT_OK_NO_EFFECT, EXIT_PENDING_VERIFICATION,
        EXIT_RECONCILING, EXIT_UNKNOWN_EFFECT_OUTCOME, ReconcileInputs,
    };
    use eliot_doctor_core::{
        ClosedRequestParams, DiagnosticBrief, DoctorDisposition, EvidenceHandle, RecoveryLease,
        RegisteredOperation, RepairRecipe, RepairRecipeIdentity, StateFence,
    };
    use eliot_instrument_api::EvidenceAxes;
    use eliot_kernel_service::{DOCTOR_RECOVERY_LEASE_OWNER, DoctorRepairAdmission};
    use eliot_platform::ClockObservation;
    use eliot_process::{
        ActionLeaseRef, CancellationRequest, DescendantEvidence, DispatchAuthorityId,
        DispatchPermitAuthority, DispatchValidationContext, EnvironmentProjection, ExitDisposition,
        ExitStatus, FencingToken, Generation, ImageId, JobId, KernelDispatchKey, OperationId,
        PermitIssuance, PhysicalProcessBinding, ProcessEvidence, ProcessEvidenceSink,
        ProcessExecutionError, ProcessExecutionView, ProcessHealth, ProcessHealthStatus, ProcessId,
        ProcessIntent, ProcessStartReceipt, ProcessState, ProcessTreeId, ResourceLimits, SessionId,
        SuspendedProcessIdentity,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::num::NonZeroU64;
    use std::sync::Mutex;
    use time::Duration;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const ATTEMPT_ID: &str = "attempt-doctor-1";
    const EFFECT_SEQ: u32 = 0;
    const OPERATION_ID: &str = "op-reconnect";

    fn digest(byte: u8) -> String {
        (0..32).map(|_| format!("{byte:02x}")).collect()
    }

    fn test_epoch() -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("test lineage"),
            NonZeroU64::new(7).expect("test sequence"),
        )
        .expect("test epoch")
    }

    fn nanos(when: OffsetDateTime) -> u64 {
        u64::try_from(when.unix_timestamp_nanos()).expect("test nanos")
    }

    fn test_brief() -> DiagnosticBrief {
        DiagnosticBrief {
            problem_id: "problem-1".to_owned(),
            component: "module-supervision".to_owned(),
            failure_class: "stale-session".to_owned(),
            symptom: "session does not resume".to_owned(),
            impact: "bounded supervision retry".to_owned(),
            evidence: vec![
                EvidenceHandle::new("evidence-ref-1", digest(0xe1)).expect("test evidence"),
            ],
            unknowns: Vec::new(),
        }
    }

    fn effect_recipe() -> RepairRecipe {
        RepairRecipe {
            recipe_id: "recipe-1".to_owned(),
            revision: 1,
            problem_classes: BTreeSet::from(["stale-session".to_owned()]),
            components: BTreeSet::from(["module-supervision".to_owned()]),
            repair_class: RepairClass::AutomaticSafe,
            prerequisites: Vec::new(),
            required_authority: "kernel.doctor-recovery".to_owned(),
            allowed_effects: BTreeSet::from([OPERATION_ID.to_owned()]),
            operations: vec![OPERATION_ID.to_owned()],
            expected_observables: vec!["observable-1".to_owned()],
            verification_contract: vec!["verify-1".to_owned()],
            rollback_or_compensation: vec!["rollback-1".to_owned()],
            attempt_budget: 3,
            cooldown: Duration::seconds(60),
            stop_conditions: Vec::new(),
        }
    }

    fn diagnose_recipe() -> RepairRecipe {
        RepairRecipe {
            allowed_effects: BTreeSet::new(),
            operations: Vec::new(),
            repair_class: RepairClass::DiagnoseOnly,
            ..effect_recipe()
        }
    }

    fn test_manifest() -> RepairRecipeManifest {
        RepairRecipeManifest {
            manifest_id: "manifest-1".to_owned(),
            manifest_revision: 1,
            operations: vec![RegisteredOperation {
                operation_id: OPERATION_ID.to_owned(),
                adapter_id: "automatic-safe".to_owned(),
                description: "reconnect one admitted generation".to_owned(),
                definition_digest: digest(0xd1),
            }],
        }
    }

    fn test_lease(now: OffsetDateTime) -> RecoveryLease {
        RecoveryLease {
            lease_id: "lease-1".to_owned(),
            owner: "kernel.doctor-recovery".to_owned(),
            expires_at: now + Duration::hours(1),
            allowed_effects: BTreeSet::from([OPERATION_ID.to_owned()]),
        }
    }

    fn effect_request(now: OffsetDateTime) -> (ClosedRepairRequest, RepairRecipeManifest) {
        let manifest = test_manifest();
        let operation = manifest.resolve(OPERATION_ID).expect("test operation");
        let request = ClosedRepairRequest::for_effect(ClosedRequestParams {
            request_id: "req-doctor-1".to_owned(),
            brief: test_brief(),
            recipe: effect_recipe(),
            operations: vec![operation],
            fence: StateFence::new(test_epoch(), 3, digest(0xf1)).expect("test fence"),
            lease: test_lease(now),
            approval: None,
            budget_units: 1,
            deadline: now + Duration::hours(1),
            cancellation: false,
            escalation_target: "governor".to_owned(),
        })
        .expect("effect request builds");
        (request, manifest)
    }

    fn diagnose_request(now: OffsetDateTime) -> (ClosedRepairRequest, RepairRecipeManifest) {
        let manifest = test_manifest();
        let request = ClosedRepairRequest::diagnose(ClosedRequestParams {
            request_id: "req-diagnose-1".to_owned(),
            brief: test_brief(),
            recipe: diagnose_recipe(),
            operations: Vec::new(),
            fence: StateFence::new(test_epoch(), 3, digest(0xf1)).expect("test fence"),
            lease: test_lease(now),
            approval: None,
            budget_units: 1,
            deadline: now + Duration::hours(1),
            cancellation: false,
            escalation_target: "governor".to_owned(),
        })
        .expect("diagnose request builds");
        (request, manifest)
    }

    fn test_envelope(
        request: &ClosedRepairRequest,
        attempt_id: &str,
        effect_seq: u32,
    ) -> DoctorRepairAttemptRequest {
        DoctorRepairAttemptRequest {
            wire_id: DOCTOR_REPAIR_WIRE_ID.to_owned(),
            wire_version: DOCTOR_REPAIR_WIRE_VERSION,
            attempt_id: attempt_id.to_owned(),
            effect_seq,
            closed_request_json: serde_json::to_string(request).expect("envelope json"),
            target_resource_digest: digest(0xb1),
            request_digest: String::new(),
        }
        .with_computed_digest()
        .expect("envelope digest")
    }

    /// Builds the admission exactly like the honest Kernel gate: the recipe
    /// identity from the registry shape, the manifest digest, and the
    /// lineage-aware attempt/effect binding under the live epoch.
    fn honest_admission(
        request: &ClosedRepairRequest,
        manifest: &RepairRecipeManifest,
        attempt_id: &str,
        effect_seq: u32,
        epoch: &EpochId,
        now: OffsetDateTime,
    ) -> DoctorRepairAdmission {
        let operation = manifest.resolve(OPERATION_ID).expect("test operation");
        let attempt = request
            .bind_attempt_on_epoch(manifest, attempt_id, &operation, epoch, now)
            .expect("test attempt identity");
        let effect = request
            .bind_effect(&attempt, &operation, effect_seq)
            .expect("test effect identity");
        let recipe_identity =
            RepairRecipeIdentity::bind(&request.recipe).expect("test recipe identity");
        DoctorRepairAdmission {
            wire_id: DOCTOR_REPAIR_WIRE_ID.to_owned(),
            wire_version: DOCTOR_REPAIR_WIRE_VERSION,
            attempt_id: attempt_id.to_owned(),
            attempt_digest: attempt.digest().to_owned(),
            effect_digest: Some(effect.digest().to_owned()),
            recipe_digest: recipe_identity.digest().to_owned(),
            manifest_digest: manifest.digest(),
            operation_id: OPERATION_ID.to_owned(),
            lease_id: "doctor-test-lease-1".to_owned(),
            lease_owner: DOCTOR_RECOVERY_LEASE_OWNER.to_owned(),
            lease_expires_unix_nanos: nanos(now + Duration::hours(1)),
            allowed_effects: BTreeSet::from([OPERATION_ID.to_owned()]),
            budget_units: request.budget_units,
            deadline_unix_nanos: nanos(request.deadline),
            approval_present: false,
            cancelled: false,
            admitted_at_unix_nanos: nanos(now),
            admission_digest: String::new(),
        }
        .with_computed_digest()
        .expect("admission digest")
    }

    fn test_rejection(now: OffsetDateTime) -> DoctorRepairRejection {
        DoctorRepairRejection {
            attempt_ref: ATTEMPT_ID.to_owned(),
            reason: DoctorRepairRejectionReason::OperationNotAdmitted,
            detail: "test refusal: no registered operation".to_owned(),
            retry_after_unix_nanos: None,
            quarantine_cause: None,
            rejected_at_unix_nanos: nanos(now),
        }
    }

    // ------------------------------------------------------------------
    // Clearly-marked test doubles. The transport doubles the unavailable
    // live Kernel (echo-checking the actual wire contract); the executor
    // stages REAL validated process state from the presented request
    // through the production contour types, so every adapter binding check
    // runs. The test permit authority below is test-only scaffolding
    // standing in for the Kernel-issued permit; production code never
    // mints permits.
    // ------------------------------------------------------------------

    #[derive(Clone)]
    enum FakeVerdict {
        Admitted(DoctorRepairAdmission),
        Rejected(DoctorRepairRejection),
    }

    #[derive(Clone, Debug)]
    struct FakeRetained {
        attempt_id: String,
        job_id: String,
        recipe_digest: String,
        effect_digest: Option<String>,
    }

    struct FakeTransport {
        verdict: Option<FakeVerdict>,
        advertise: bool,
        submits: usize,
        retained: Option<FakeRetained>,
    }

    impl FakeTransport {
        fn admitting(admission: DoctorRepairAdmission) -> Self {
            Self {
                verdict: Some(FakeVerdict::Admitted(admission)),
                advertise: true,
                submits: 0,
                retained: None,
            }
        }

        fn refusing(rejection: DoctorRepairRejection) -> Self {
            Self {
                verdict: Some(FakeVerdict::Rejected(rejection)),
                advertise: true,
                submits: 0,
                retained: None,
            }
        }

        fn closed() -> Self {
            Self {
                verdict: None,
                advertise: false,
                submits: 0,
                retained: None,
            }
        }
    }

    impl AdmittedDoctorTransport for FakeTransport {
        fn submit_repair_attempt(
            &mut self,
            request: &DoctorRepairAttemptRequest,
        ) -> Result<DoctorRepairResponse, DoctorIpcError> {
            self.submits += 1;
            if !route_doctor_repair(&request.wire_id, request.wire_version) {
                return Err(DoctorIpcError::Contract(
                    "fake transport: wire pair mismatch".to_owned(),
                ));
            }
            request
                .validate()
                .map_err(|error| DoctorIpcError::Contract(error.to_string()))?;
            request
                .validate_canonical_digest()
                .map_err(|error| DoctorIpcError::Contract(error.to_string()))?;
            let envelope: ClosedRepairRequest = serde_json::from_str(&request.closed_request_json)
                .map_err(|error| DoctorIpcError::Contract(error.to_string()))?;
            let Some(verdict) = self.verdict.clone() else {
                return Err(DoctorIpcError::Contract(
                    "fake transport: no verdict configured".to_owned(),
                ));
            };
            match verdict {
                FakeVerdict::Admitted(admission) => {
                    if admission.attempt_id != request.attempt_id {
                        return Err(DoctorIpcError::Contract(
                            "fake transport: admission echo mismatch".to_owned(),
                        ));
                    }
                    self.retained = Some(FakeRetained {
                        attempt_id: admission.attempt_id.clone(),
                        job_id: envelope.request_id.clone(),
                        recipe_digest: admission.recipe_digest.clone(),
                        effect_digest: admission.effect_digest.clone(),
                    });
                    Ok(DoctorRepairResponse::Admitted(Box::new(admission)))
                }
                FakeVerdict::Rejected(rejection) => {
                    if rejection.attempt_ref != request.attempt_id {
                        return Err(DoctorIpcError::Contract(
                            "fake transport: rejection echo mismatch".to_owned(),
                        ));
                    }
                    Ok(DoctorRepairResponse::Rejected(rejection))
                }
            }
        }
    }

    impl KernelDoctorClient for FakeTransport {
        type Error = DoctorIpcError;

        fn advertise_doctor(&mut self) -> Result<bool, Self::Error> {
            Ok(self.advertise)
        }

        fn admit(&mut self, _request: &RepairRequest) -> Result<KernelAdmission, Self::Error> {
            Err(DoctorIpcError::Contract(
                "legacy RepairRequest cannot carry the doctor repair-attempt identity; present the full envelope"
                    .to_owned(),
            ))
        }

        fn record_intent(&mut self, intent: &EffectIntent) -> Result<(), Self::Error> {
            let retained = self.retained.as_ref().ok_or_else(|| {
                DoctorIpcError::Contract("fake transport: no retained admission".to_owned())
            })?;
            if intent.attempt_id == retained.attempt_id
                && intent.job_id == retained.job_id
                && intent.recipe_digest == retained.recipe_digest
                && Some(intent.effect_digest.as_str()) == retained.effect_digest.as_deref()
            {
                Ok(())
            } else {
                Err(DoctorIpcError::Contract(
                    "fake transport: intent binding mismatch".to_owned(),
                ))
            }
        }

        fn execute(&mut self, _intent: &EffectIntent) -> Result<EffectOutcome, Self::Error> {
            Err(DoctorIpcError::Contract(
                "fake transport: execution belongs to the adapter".to_owned(),
            ))
        }

        fn reconcile(
            &mut self,
            _job_id: &str,
            _attempt_id: &str,
        ) -> Result<EffectOutcome, Self::Error> {
            Err(DoctorIpcError::Contract(
                "fake transport: reconciliation belongs to the adapter".to_owned(),
            ))
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum FakeMode {
        Success,
        UnknownOnStart,
    }

    struct FakeExecutorState {
        starts: usize,
        inspections: usize,
        reconciliations: usize,
        process: Option<ProcessState>,
    }

    struct FakeExecutor {
        state: Mutex<FakeExecutorState>,
        mode: FakeMode,
    }

    impl FakeExecutor {
        fn new(mode: FakeMode) -> Self {
            Self {
                state: Mutex::new(FakeExecutorState {
                    starts: 0,
                    inspections: 0,
                    reconciliations: 0,
                    process: None,
                }),
                mode,
            }
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, FakeExecutorState> {
            self.state.lock().expect("test lock")
        }
    }

    fn test_revisions() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("authority".to_owned(), digest(0xa1)),
            ("state".to_owned(), digest(0xb2)),
        ])
    }

    fn test_authority() -> DispatchPermitAuthority {
        DispatchPermitAuthority::activate(
            DispatchAuthorityId::new("doctor-test-authority").expect("test authority"),
            KernelDispatchKey::from_secret_bytes([0x5a; 32]).expect("test key"),
        )
    }

    /// Test-only issuance shape shared by the contour stand-in (which seals
    /// the presented request) and the fake executor (which must have issued
    /// the same one-shot nonce before the contour's replay check passes).
    /// Mirrors the native-worker-core test contour exactly.
    fn test_issuance(fence: FencingToken) -> PermitIssuance {
        PermitIssuance::new(
            ActionLeaseRef::new("doctor-test-lease").expect("test lease"),
            fence,
            test_revisions(),
            100,
            10_000,
            "nonce-doctor-test-1",
        )
        .expect("test issuance")
    }

    /// Builds the concrete process request the dispatch contour delivers:
    /// a sealed intent plus its consuming permit, validated at
    /// construction. Test-only permit scaffolding, never production
    /// authority.
    fn test_process_request() -> ProcessRequest {
        let generation = Generation::new(3).expect("test generation");
        let intent = ProcessIntent::new(
            OperationId::new(OPERATION_ID).expect("test operation"),
            ProcessTreeId::new("tree-doctor-1").expect("test tree"),
            JobId::new("job-doctor-1").expect("test job"),
            ImageId::new("image-doctor-1").expect("test image"),
            SessionId::new("session-doctor-1").expect("test session"),
            generation,
            "doctor-effect-host.exe",
            digest(0xc1),
            vec!["--admitted-effect".to_owned()],
            "C:/eliot/doctor",
            EnvironmentProjection::default(),
            ResourceLimits::new(5_000, Some(1_000), Some(1_048_576), 4_096, 4_096, 2)
                .expect("test limits"),
        )
        .expect("test intent");
        let fence =
            FencingToken::new(test_epoch(), generation, "fence-doctor-1").expect("test fence");
        let permit = test_authority()
            .issue(&intent, test_issuance(fence))
            .expect("test permit");
        ProcessRequest::new(intent, permit).expect("test process request")
    }

    fn observed_axes() -> EvidenceAxes {
        EvidenceAxes::observed()
    }

    /// Stages real validated process state from the presented request, like
    /// a physical executor resuming a suspended child.
    fn stage_running_state(request: ProcessRequest) -> Result<ProcessState, ProcessExecutionError> {
        request.validate()?;
        let fence = request.fence().clone();
        let intent = request.intent().clone();
        let mut authority = test_authority();
        // The validator re-issues the same test nonce first: the contour's
        // replay check requires the nonce in the validator's issued set,
        // exactly like the native-worker-core test contour.
        let _ = authority.issue(&intent, test_issuance(fence.clone()))?;
        let observed = SuspendedProcessIdentity::new(
            ProcessId::new("process-9")?,
            intent.process_tree_id().clone(),
            intent.job_id().clone(),
            intent.image_id().clone(),
            intent.session_id().clone(),
            intent.generation(),
            PhysicalProcessBinding::new(4242, 11, intent.executable(), "Local\\Eliot-Doctor-Test")?,
            120,
            intent.executable_sha256(),
        )?;
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(150),
                known_time_ms: Some(150),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            test_epoch(),
            test_revisions(),
            41,
        )?;
        let validated = authority.validate_and_consume(request, observed, &context)?;
        let mut process = ProcessState::from_validated(&validated);
        process.mark_resumed(
            151,
            ProcessHealth::new(ProcessHealthStatus::Healthy, true, 151, None)?,
        )?;
        Ok(process)
    }

    fn exit_descendants(
        process: &ProcessState,
        complete: bool,
    ) -> Result<DescendantEvidence, ProcessExecutionError> {
        let identity = process
            .view()
            .identity()
            .ok_or(ProcessExecutionError::NotFound)?
            .clone();
        // A completed terminal observation requires a complete terminated
        // tree with an evidence handle; anything less stays unknown by the
        // contour's own transition rule, never by test choice.
        let (process_ids, tree_terminated, evidence_ref) = if complete {
            (
                vec![ProcessId::new("descendant-9")?],
                true,
                Some("evidence-doctor-9".to_owned()),
            )
        } else {
            (Vec::new(), false, None)
        };
        Ok(DescendantEvidence::new(
            process.binding().clone(),
            identity.process_id().clone(),
            process_ids,
            complete,
            tree_terminated,
            evidence_ref,
        )?)
    }

    impl ProcessExecutor for FakeExecutor {
        async fn start(
            &self,
            request: ProcessRequest,
            sink: Arc<dyn ProcessEvidenceSink>,
        ) -> Result<ProcessStartReceipt, ProcessExecutionError> {
            let mut state = self.lock();
            state.starts += 1;
            let mode = self.mode;
            // Staging failures are fixture bugs, so they panic loudly here
            // instead of masquerading as executor unknown-outcomes. Only the
            // explicit mode branch below may report UnknownOutcome.
            let mut process = stage_running_state(request).expect("stage running state");
            let receipt = ProcessStartReceipt::new(&process).expect("start receipt");
            sink.record(
                ProcessEvidence::new(process.view(), None, None, observed_axes())
                    .expect("start evidence"),
            )
            .expect("evidence sink");
            match mode {
                FakeMode::Success => {
                    let descendants = exit_descendants(&process, true).expect("exit descendants");
                    process
                        .exit(
                            ExitStatus::new(ExitDisposition::Completed, Some(0), None, 200)
                                .expect("exit status"),
                            descendants,
                        )
                        .expect("exit");
                    state.process = Some(process);
                    Ok(receipt)
                }
                FakeMode::UnknownOnStart => {
                    let descendants = exit_descendants(&process, false).expect("exit descendants");
                    process
                        .exit(
                            ExitStatus::new(ExitDisposition::Unknown, None, None, 202)
                                .expect("exit status"),
                            descendants,
                        )
                        .expect("exit");
                    state.process = Some(process);
                    Err(ProcessExecutionError::UnknownOutcome)
                }
            }
        }

        async fn inspect(
            &self,
            _operation_id: OperationId,
        ) -> Result<ProcessExecutionView, ProcessExecutionError> {
            let mut state = self.lock();
            state.inspections += 1;
            state
                .process
                .as_ref()
                .map(ProcessState::view)
                .ok_or(ProcessExecutionError::NotFound)
        }

        async fn cancel(
            &self,
            _operation_id: OperationId,
        ) -> Result<eliot_process::CancellationReceipt, ProcessExecutionError> {
            let mut state = self.lock();
            let process = state
                .process
                .as_mut()
                .ok_or(ProcessExecutionError::NotFound)?;
            Ok(process.cancel(&CancellationRequest::new(process.binding().clone()))?)
        }

        async fn reconcile(
            &self,
            _operation_id: OperationId,
        ) -> Result<ProcessEvidence, ProcessExecutionError> {
            let mut state = self.lock();
            state.reconciliations += 1;
            let process = state
                .process
                .as_mut()
                .ok_or(ProcessExecutionError::NotFound)?;
            let identity = process
                .view()
                .identity()
                .ok_or(ProcessExecutionError::NotFound)?
                .clone();
            let descendants = DescendantEvidence::new(
                process.binding().clone(),
                identity.process_id().clone(),
                vec![ProcessId::new("descendant-9")?],
                true,
                true,
                Some("evidence-doctor-9".to_owned()),
            )?;
            process.reconcile(descendants)?;
            Ok(ProcessEvidence::new(
                process.view(),
                None,
                None,
                observed_axes(),
            )?)
        }
    }

    #[test]
    fn doctor_repair_wire_identity_is_stable() {
        assert_eq!(
            DOCTOR_REPAIR_OPERATION,
            "eliot.kernel.doctor-repair-attempt"
        );
        assert!(route_doctor_repair(
            DOCTOR_REPAIR_OPERATION,
            DOCTOR_REPAIR_OPERATION_VERSION
        ));
        assert_eq!(DOCTOR_REPAIR_OPERATION_VERSION, 1);
    }

    #[tokio::test]
    async fn admitted_effect_success_is_pending_verification() {
        let now = OffsetDateTime::now_utc();
        let (request, manifest) = effect_request(now);
        let epoch = test_epoch();
        let admission = honest_admission(&request, &manifest, ATTEMPT_ID, EFFECT_SEQ, &epoch, now);
        let expected_effect = admission.effect_digest.clone();
        let mut transport = FakeTransport::admitting(admission);
        let executor = Arc::new(FakeExecutor::new(FakeMode::Success));
        let presented = PresentedAttempt {
            attempt: test_envelope(&request, ATTEMPT_ID, EFFECT_SEQ),
            request: request.clone(),
            manifest: manifest.clone(),
            process: test_process_request(),
            epoch,
        };
        let outcome = drive_admitted_attempt(
            &mut transport,
            Arc::clone(&executor),
            Arc::new(EvidenceCollector::new()),
            presented,
            now,
        )
        .await
        .expect("admitted effect drives");
        assert!(matches!(
            outcome.disposition,
            DoctorDisposition::RepairedPendingVerification { .. }
        ));
        assert!(!matches!(
            outcome.disposition,
            DoctorDisposition::RepairedVerified { .. }
        ));
        assert_eq!(outcome.exit_code(), EXIT_PENDING_VERIFICATION);
        assert_eq!(
            outcome.report.effect_disposition.as_deref(),
            Some("succeeded")
        );
        assert_eq!(outcome.report.effect_digest, expected_effect);
        assert!(outcome.report.evidence_reference.is_some());
        assert_eq!(transport.submits, 1);
        assert_eq!(executor.lock().starts, 1);
    }

    #[tokio::test]
    async fn lost_reply_reconciles_same_digest_without_retry() {
        let now = OffsetDateTime::now_utc();
        let (request, manifest) = effect_request(now);
        let epoch = test_epoch();
        let admission = honest_admission(&request, &manifest, ATTEMPT_ID, EFFECT_SEQ, &epoch, now);
        let expected_effect = admission.effect_digest.clone();
        let mut transport = FakeTransport::admitting(admission);
        let executor = Arc::new(FakeExecutor::new(FakeMode::UnknownOnStart));
        let operation_id = test_process_request().operation_id().clone();
        let presented = PresentedAttempt {
            attempt: test_envelope(&request, ATTEMPT_ID, EFFECT_SEQ),
            request: request.clone(),
            manifest: manifest.clone(),
            process: test_process_request(),
            epoch,
        };
        let outcome = drive_admitted_attempt(
            &mut transport,
            Arc::clone(&executor),
            Arc::new(EvidenceCollector::new()),
            presented,
            now,
        )
        .await
        .expect("lost reply stays unknown");
        let reconciliation_key = match &outcome.disposition {
            DoctorDisposition::UnknownEffectOutcome {
                reconciliation_key, ..
            } => reconciliation_key.clone(),
            other => panic!("expected unknown outcome, got {other:?}"),
        };
        assert_eq!(outcome.exit_code(), EXIT_UNKNOWN_EFFECT_OUTCOME);
        // The reconciliation key names the same effect: no blind retry.
        assert_eq!(
            outcome.report.reconciliation_key.as_deref(),
            Some(reconciliation_key.as_str())
        );
        assert_eq!(outcome.report.effect_digest, expected_effect);
        assert_eq!(
            Some(reconciliation_key.as_str()),
            expected_effect.as_deref()
        );
        assert_eq!(executor.lock().starts, 1);

        let operation = manifest.resolve(OPERATION_ID).expect("test operation");
        let adapter =
            AutomaticSafeAdapter::bind(Arc::clone(&executor), operation).expect("adapter binds");
        let reconciled = adapter
            .reconcile_admitted_unknown(ReconcileInputs {
                request: &request,
                manifest: &manifest,
                attempt_id: ATTEMPT_ID,
                operation_id,
                reconciliation_key: reconciliation_key.as_str(),
                epoch: &test_epoch(),
                now,
            })
            .await
            .expect("same-digest reconcile advances");
        assert!(matches!(
            reconciled.disposition,
            DoctorDisposition::Reconciling { .. }
        ));
        assert_eq!(reconciled.exit_code(), EXIT_RECONCILING);
        assert_eq!(
            reconciled.report.reconciliation_key.as_deref(),
            Some(reconciliation_key.as_str())
        );
        // Exactly one effect dispatch across the unknown outcome and its
        // reconciliation: the retry never happened.
        assert_eq!(executor.lock().starts, 1);
        assert_eq!(executor.lock().reconciliations, 1);
    }

    #[tokio::test]
    async fn diagnose_only_never_touches_transport_or_executor() {
        let now = OffsetDateTime::now_utc();
        let (request, manifest) = diagnose_request(now);
        let mut transport = FakeTransport::closed();
        let executor = Arc::new(FakeExecutor::new(FakeMode::Success));
        let presented = PresentedAttempt {
            attempt: test_envelope(&request, "attempt-diagnose-1", 0),
            request,
            manifest,
            process: test_process_request(),
            epoch: test_epoch(),
        };
        let outcome = drive_admitted_attempt(
            &mut transport,
            Arc::clone(&executor),
            Arc::new(EvidenceCollector::new()),
            presented,
            now,
        )
        .await
        .expect("diagnosis projects");
        assert!(matches!(
            outcome.disposition,
            DoctorDisposition::Diagnosed { .. }
        ));
        assert_eq!(outcome.exit_code(), EXIT_OK_NO_EFFECT);
        assert_eq!(transport.submits, 0);
        assert_eq!(executor.lock().starts, 0);
    }

    #[tokio::test]
    async fn refused_attempt_takes_no_effect() {
        let now = OffsetDateTime::now_utc();
        let (request, manifest) = effect_request(now);
        let mut transport = FakeTransport::refusing(test_rejection(now));
        let executor = Arc::new(FakeExecutor::new(FakeMode::Success));
        let presented = PresentedAttempt {
            attempt: test_envelope(&request, ATTEMPT_ID, EFFECT_SEQ),
            request,
            manifest,
            process: test_process_request(),
            epoch: test_epoch(),
        };
        let error = drive_admitted_attempt(
            &mut transport,
            Arc::clone(&executor),
            Arc::new(EvidenceCollector::new()),
            presented,
            now,
        )
        .await
        .expect_err("refusal fails closed");
        assert!(matches!(
            error,
            AdapterError::Admission(DoctorError::OperationNotAdmitted)
        ));
        assert_eq!(error.exit_code(), EXIT_KERNEL_ADMISSION_REQUIRED);
        assert_eq!(transport.submits, 1);
        assert_eq!(executor.lock().starts, 0);
    }

    fn foreign_epoch() -> EpochId {
        EpochId::new(
            EpochLineageId::new("660e8400-e29b-41d4-a716-446655440001").expect("test lineage"),
            NonZeroU64::new(7).expect("test sequence"),
        )
        .expect("test epoch")
    }

    #[tokio::test]
    async fn foreign_lineage_epoch_fails_closed_without_effect() {
        let now = OffsetDateTime::now_utc();
        let (request, manifest) = effect_request(now);
        let epoch = test_epoch();
        let admission = honest_admission(&request, &manifest, ATTEMPT_ID, EFFECT_SEQ, &epoch, now);
        let mut transport = FakeTransport::admitting(admission);
        let executor = Arc::new(FakeExecutor::new(FakeMode::Success));
        // The admission was honestly bound under the request fence lineage,
        // but the dispatch presentation carries a foreign lineage: the
        // lineage-aware attempt binding must refuse before any intent or
        // effect, even though the envelope submit itself succeeds.
        let presented = PresentedAttempt {
            attempt: test_envelope(&request, ATTEMPT_ID, EFFECT_SEQ),
            request,
            manifest,
            process: test_process_request(),
            epoch: foreign_epoch(),
        };
        let error = drive_admitted_attempt(
            &mut transport,
            Arc::clone(&executor),
            Arc::new(EvidenceCollector::new()),
            presented,
            now,
        )
        .await
        .expect_err("foreign lineage fails closed");
        assert!(matches!(
            error,
            AdapterError::Admission(DoctorError::InvalidFence)
        ));
        assert_eq!(error.exit_code(), EXIT_KERNEL_ADMISSION_REQUIRED);
        assert_eq!(transport.submits, 1);
        assert_eq!(executor.lock().starts, 0);
    }
}
