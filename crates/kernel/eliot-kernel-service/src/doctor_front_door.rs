//! Doctor P-07 front-door seam (Slice A, issue #461).
//!
//! Thin service-seam handler over the landed T6-D1 admission gate
//! ([`admit_doctor_repair`](crate::admit_doctor_repair)): it binds one
//! authenticated Doctor session from live Kernel authority, admits exactly
//! one repair attempt per call, and reconciles unknown deliveries without
//! admitting again. It owns no ledger, registry, recipe, effect adapter,
//! verifier, or dispatch table: every admission, conflict, rejection, and
//! reconciliation answer comes from `doctor.rs` and the durable
//! [`DoctorRecoveryLedger`](eliot_ors::DoctorRecoveryLedger).
//!
//! Authority rules (fail-closed, following `host_request_binding.rs:113-129`):
//!
//! * the admission context (service state, authority epoch, generation) is
//!   built from the live [`KernelService`] plus its consumed activation
//!   receipt on every call — never from request envelope bytes;
//! * the session epoch must be exactly the live epoch
//!   (`is_same_authority`) and the session generation must equal the live
//!   activation generation, otherwise the call fails before any ledger
//!   input is touched;
//! * the wire matches exactly
//!   (`DOCTOR_REPAIR_WIRE_ID`, `DOCTOR_REPAIR_WIRE_VERSION`); anything else
//!   is a typed `UnknownWireVersion` rejection, never an admission;
//! * an exact replay under one attempt identity rebuilds the original
//!   admission (no second effect, no second budget admission);
//! * changed request, recipe, or effect terms under one identity return
//!   `Conflict` and never overwrite the durable binding;
//! * guarded attempts without a live activation-bound approval fail closed
//!   inside the gate (`ApprovalRequired` / `ApprovalNotActivated`); this
//!   seam adds no approval lookup and accepts no approval value as
//!   authority;
//! * a lost reply reconciles through
//!   [`reconcile_doctor_repair_delivery`], which re-derives the identities
//!   against the live epoch and compares digests only: it mutates nothing
//!   and mints no new effect;
//! * cancellation travels through the separate
//!   [`handle_doctor_repair_cancellation`] control entry, which admits only
//!   cancellation-flagged envelopes; effect attempts submitted there fail
//!   closed without admission;
//! * diagnose-only envelopes never reach admission at all: they carry no
//!   operation and bind no effect identity. Use
//!   [`is_doctor_diagnosis_only_envelope`] to classify that read-only path
//!   without touching the ledger.
//!
//! The admitted effect intent is durable before execution; the `Admitted`
//! answer is therefore a repair candidate pending independent verification
//! (`REPAIRED_PENDING_VERIFICATION` in issue #461 terms), never a verified
//! repair. Verification and semantic disposition belong to the verifier and
//! Governor owners (Wave E).

use eliot_contracts::EpochId;
use eliot_doctor_core::{ClosedRepairRequest, RepairClass};
use eliot_ors::DoctorRecoveryLedger;

use crate::{
    DoctorAdmissionContext, DoctorRecipeRegistry, DoctorRepairAdmission,
    DoctorRepairAttemptRequest, DoctorRepairRejection, DoctorRepairRejectionReason,
    DoctorRepairResponse, KernelService, KernelServiceError, KernelServiceState,
    admit_doctor_repair, reconcile_doctor_repair_admission, route_doctor_repair, validate_text,
};

/// Authenticated Doctor session bound from live Kernel authority.
///
/// All fields come from the Kernel service lineage and its consumed
/// activation receipt at bind time: the principal reference supplied by the
/// authenticated composition boundary (never a request-envelope value), the
/// live authority epoch, and the live activation generation. No request DTO
/// field contributes authority (A12.2: identity is established by the
/// harness/installation boundary, never self-declared).
#[derive(Clone, Debug)]
pub struct AuthenticatedDoctorSession {
    principal_ref: String,
    authority_epoch: EpochId,
    generation: u64,
}

impl AuthenticatedDoctorSession {
    /// Binds one Doctor session from live Kernel state.
    ///
    /// Fails closed when the generation is fenced, the service is not
    /// `Ready`, no candidate lineage or consumed activation receipt exists,
    /// the activation no longer agrees with the live epoch (revoked/stale
    /// activation), or the principal reference is not bounded wire text.
    /// An unactivated Kernel therefore admits no Doctor work through this
    /// seam.
    pub fn bind(service: &KernelService, principal_ref: &str) -> Result<Self, KernelServiceError> {
        validate_text(principal_ref, "doctor_repair.principal")?;
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
                field: "doctor_repair.authority_epoch",
            });
        }
        if !activation.authority_epoch.is_same_authority(&live_epoch) {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "doctor_repair.authority_epoch",
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
    /// ledger input — so a replayed session can never smuggle old authority
    /// into a new epoch.
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
                field: "doctor_repair.authority_epoch",
            });
        }
        let live_generation = activation.generation.value();
        if !self.authority_epoch.is_same_authority(&live_epoch) {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "doctor_repair.authority_epoch",
            });
        }
        if self.generation != live_generation {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "doctor_repair.generation",
            });
        }
        Ok((live_epoch, live_generation))
    }

    /// Builds the admission context from live Kernel authority.
    ///
    /// The epoch and generation come from [`Self::live_authority`] — the
    /// live service plus its consumed activation — never from the request
    /// envelope. The gate re-proves the presented fence agrees with this
    /// context before any effect.
    pub fn admission_context(
        &self,
        service: &KernelService,
    ) -> Result<DoctorAdmissionContext, KernelServiceError> {
        let (epoch, generation) = self.live_authority(service)?;
        DoctorAdmissionContext::new(service.state(), epoch, generation)
    }
}

/// Admits one Doctor repair attempt through the live Kernel authority.
///
/// One call admits at most one attempt: the session is re-validated against
/// live authority, the wire identity must match exactly, and the request is
/// delegated to [`admit_doctor_repair`] with a context built from the live
/// service. An exact replay returns the original admission without a second
/// effect or budget admission; changed terms under one identity return
/// `Conflict`; guarded attempts without a live activation-bound approval are
/// refused by the gate. Only mechanical failures (fenced generation, closed
/// admission, ledger storage) surface as `Err`; every typed refusal is an
/// `Ok` response value.
pub fn handle_doctor_repair_attempt<L: DoctorRecoveryLedger>(
    ledger: &L,
    registry: &DoctorRecipeRegistry,
    service: &KernelService,
    session: &AuthenticatedDoctorSession,
    request: &DoctorRepairAttemptRequest,
    now_unix_nanos: u64,
) -> Result<DoctorRepairResponse, KernelServiceError> {
    let context = session.admission_context(service)?;
    if !route_doctor_repair(&request.wire_id, request.wire_version) {
        if now_unix_nanos == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "doctor_repair.now",
                reason: "admission time must be non-zero",
            });
        }
        return Ok(DoctorRepairResponse::Rejected(DoctorRepairRejection {
            attempt_ref: request.attempt_id.clone(),
            reason: DoctorRepairRejectionReason::UnknownWireVersion,
            detail: "doctor_repair.wire".to_owned(),
            retry_after_unix_nanos: None,
            quarantine_cause: None,
            rejected_at_unix_nanos: now_unix_nanos,
        }));
    }
    admit_doctor_repair(
        ledger,
        registry,
        &context,
        session.principal_ref(),
        request,
        now_unix_nanos,
    )
}

/// Admits one Doctor cancellation through the separate control entry.
///
/// Cancellation is an admission outcome with no effect intent — never a
/// budget bypass and never a second dispatch path. This entry parses the
/// presented envelope and admits only cancellation-flagged requests,
/// delegating to [`handle_doctor_repair_attempt`]; an effect-carrying
/// request submitted here fails closed with `InvalidField` and admits
/// nothing. A request whose envelope cannot be parsed is delegated
/// unchanged so the gate reports its typed `InvalidRequestField` refusal.
/// Cancel and reconcile traffic therefore never shares an entrypoint with
/// effect admission results, while authority stays in the one gate.
pub fn handle_doctor_repair_cancellation<L: DoctorRecoveryLedger>(
    ledger: &L,
    registry: &DoctorRecipeRegistry,
    service: &KernelService,
    session: &AuthenticatedDoctorSession,
    request: &DoctorRepairAttemptRequest,
    now_unix_nanos: u64,
) -> Result<DoctorRepairResponse, KernelServiceError> {
    if let Ok(envelope) = serde_json::from_str::<ClosedRepairRequest>(&request.closed_request_json)
        && !envelope.cancellation
    {
        return Err(KernelServiceError::InvalidField {
            field: "doctor_repair.cancellation",
            reason: "this control entry admits cancellation only",
        });
    }
    handle_doctor_repair_attempt(ledger, registry, service, session, request, now_unix_nanos)
}

/// Reconciles one unknown Doctor admission delivery without admitting again.
///
/// Lost-reply path: the caller retains a previously returned admission and,
/// on an uncertain delivery, proves it still binds the exact presented
/// envelope under live authority. The attempt and effect identities are
/// re-derived against the live Kernel epoch (never envelope bytes) and the
/// lease projection is compared deterministically; the ledger is not
/// touched, no state advances, and no new effect is minted. Returns `true`
/// only when the retained admission is exactly this delivery's admission —
/// the caller must then treat the original admission as the outcome.
/// Returns `false` when it does not bind: that delivery must escalate,
/// never blind-retry as a new attempt.
pub fn reconcile_doctor_repair_delivery(
    service: &KernelService,
    session: &AuthenticatedDoctorSession,
    admission: &DoctorRepairAdmission,
    request: &DoctorRepairAttemptRequest,
    envelope: &ClosedRepairRequest,
) -> Result<bool, KernelServiceError> {
    let (live_epoch, _) = session.live_authority(service)?;
    reconcile_doctor_repair_admission(admission, request, envelope, &live_epoch)
}

/// Classifies the read-only diagnosis path without touching authority.
///
/// Returns `true` only for a diagnose-only envelope carrying no operation:
/// such a request binds no effect identity and needs no Kernel effect
/// admission, so it must be answered from diagnosis evidence rather than
/// submitted to [`handle_doctor_repair_attempt`] (the gate refuses
/// operation-less requests with `OperationNotAdmitted` instead of admitting
/// them half-bound). This check is pure: it reads the already-parsed
/// envelope, stages nothing, and advances nothing.
#[must_use]
pub fn is_doctor_diagnosis_only_envelope(envelope: &ClosedRepairRequest) -> bool {
    matches!(envelope.recipe.repair_class, RepairClass::DiagnoseOnly)
        && envelope.operations.is_empty()
}
