//! Kernel-to-InstrumentRunner process-owner composition.
//!
//! The runner cannot create a [`eliot_process::ProcessRequest`].  The request
//! contains a one-shot permit issued by the active Kernel authority and is
//! deliberately sealed by P-03.  This module gives the runtime composition
//! root one concrete adapter for handing that already-admitted request to the
//! runner while retaining the Kernel-derived owner/session binding.

use eliot_instrument_api::InstrumentInvocation;
use eliot_process::{ProcessCallerSession, ProcessRequest};
use thiserror::Error;

use crate::{InstrumentRequestPort, RunnerError};

/// A Kernel-issued process request plus the durable owner/session that admitted
/// it.
///
/// Implementations of [`KernelInstrumentAdmission`] must obtain both values
/// from the same Kernel admission decision.  The request remains the actual
/// authority proof; the caller session prevents a transport or stale owner
/// identity from being paired with it.
#[derive(Debug)]
pub struct KernelAdmittedProcess {
    request: ProcessRequest,
    caller: ProcessCallerSession,
}

impl KernelAdmittedProcess {
    /// Validates the exact owner/session/generation binding around one sealed
    /// Kernel request.
    ///
    /// This constructor accepts no authority material and cannot mint a
    /// request.  A caller still needs a non-forgeable [`ProcessRequest`] from
    /// the active Kernel authority.
    pub fn new(
        request: ProcessRequest,
        caller: ProcessCallerSession,
    ) -> Result<Self, KernelAdmissionError> {
        request
            .validate()
            .map_err(|error| KernelAdmissionError::InvalidRequest(error.to_string()))?;
        caller
            .validate()
            .map_err(|error| KernelAdmissionError::InvalidOwner(error.to_string()))?;
        if request.session_id() != caller.session_id() {
            return Err(KernelAdmissionError::OwnerBinding(
                "process request session differs from admitted caller session",
            ));
        }
        if request.generation() != caller.owner().generation()
            || request.fence().generation() != caller.owner().generation()
        {
            return Err(KernelAdmissionError::OwnerBinding(
                "process request generation differs from admitted owner generation",
            ));
        }
        if request.fence().authority_epoch() != caller.owner().authority_epoch() {
            return Err(KernelAdmissionError::OwnerBinding(
                "process request authority epoch differs from admitted owner epoch",
            ));
        }
        Ok(Self { request, caller })
    }

    /// Returns the exact Kernel-admitted caller binding for diagnostics and
    /// composition checks.
    #[must_use]
    pub const fn caller(&self) -> &ProcessCallerSession {
        &self.caller
    }

    /// Borrows the sealed request without consuming its one-shot permit.
    #[must_use]
    pub const fn request(&self) -> &ProcessRequest {
        &self.request
    }

    /// Transfers the one-shot request to the `InstrumentRunner`.
    #[must_use]
    pub fn into_request(self) -> ProcessRequest {
        self.request
    }
}

/// Failure returned by the Kernel-owned process admission implementation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum KernelAdmissionError {
    /// The active Kernel owner declined the requested BUILD admission.
    #[error("Kernel process admission rejected: {0}")]
    Rejected(String),
    /// The owner returned a request that fails the sealed P-03 contract.
    #[error("Kernel-admitted process request is invalid: {0}")]
    InvalidRequest(String),
    /// The request and server-derived owner/session do not describe one
    /// admitted operation.
    #[error("Kernel process owner binding failed: {0}")]
    OwnerBinding(&'static str),
    /// The owner/session projection itself is malformed.
    #[error("Kernel process owner is invalid: {0}")]
    InvalidOwner(String),
}

/// Sole composition hook for the active Kernel process-authority owner.
///
/// The implementation belongs to the Kernel/runtime composition root and must
/// route to the same `ProcessDispatchAuthorityController` that backs the
/// `ProcessExecutor`.  It returns a fresh one-shot request for each invocation
/// and never exposes a key, replay journal, or caller-created permit.
pub trait KernelInstrumentAdmission: Send + Sync {
    /// Admits one provider-neutral BUILD invocation and returns its sealed
    /// process request plus the exact Kernel-derived owner/session binding.
    fn admit(
        &self,
        invocation: &InstrumentInvocation,
    ) -> Result<KernelAdmittedProcess, KernelAdmissionError>;
}

/// Concrete `InstrumentRequestPort` backed by the Kernel admission hook.
///
/// This is the production bridge used by an application caller.  It does not
/// derive executable paths, argv, limits, environments, generations, or
/// fences from the invocation; those values arrive inside the Kernel-issued
/// sealed request.
pub struct KernelInstrumentRequestPort<'a> {
    admission: &'a dyn KernelInstrumentAdmission,
}

impl<'a> KernelInstrumentRequestPort<'a> {
    /// Creates a request port over the active Kernel admission owner.
    #[must_use]
    pub const fn new(admission: &'a dyn KernelInstrumentAdmission) -> Self {
        Self { admission }
    }
}

impl InstrumentRequestPort for KernelInstrumentRequestPort<'_> {
    fn bind(&self, invocation: &InstrumentInvocation) -> Result<ProcessRequest, RunnerError> {
        invocation
            .validate()
            .map_err(|error| RunnerError::InvalidInvocation(error.to_string()))?;
        let admitted = self
            .admission
            .admit(invocation)
            .map_err(|error| RunnerError::Binding(error.to_string()))?;
        if let Some(session_id) = invocation.request.session_id.as_ref()
            && session_id.as_str() != admitted.caller().session_id().as_str()
        {
            return Err(RunnerError::Binding(
                "Kernel owner session differs from instrument invocation session".to_owned(),
            ));
        }
        let request = admitted.request();
        if request.operation_id().as_str() != invocation.request.request_id.as_str() {
            return Err(RunnerError::IdentityMismatch);
        }
        if request.generation().get() != invocation.request.state_fence.resource_generation.value()
        {
            return Err(RunnerError::Binding(
                "Kernel request generation differs from invocation fence".to_owned(),
            ));
        }
        if request.fence().authority_epoch() != &invocation.request.state_fence.authority_epoch {
            return Err(RunnerError::Binding(
                "Kernel request authority epoch differs from invocation fence".to_owned(),
            ));
        }
        Ok(admitted.into_request())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ClockReading, ContractId, ProductId, RequestId, RequestMetadata, ResourceGeneration,
        SessionId as ContractSessionId, SourceId, StateFence,
    };
    use eliot_contracts::{EpochId, EpochLineageId};
    use eliot_instrument_api::{InstrumentInvocation, InstrumentKind};
    use eliot_process::{
        ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, EnvironmentInheritance,
        EnvironmentProjection, FencingToken, Generation, ImageId, JobId, KernelDispatchKey,
        OperationId, PermitIssuance, ProcessCallerSession, ProcessIntent, ProcessOwnerBinding,
        ProcessSessionClass, ProcessTreeId, ResourceLimits, SessionId,
    };
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;

    fn epoch() -> EpochId {
        let lineage = EpochLineageId::new("0198a8e0-2b4a-7c5e-8d11-000000000189")
            .expect("test epoch lineage");
        EpochId::new(lineage, NonZeroU64::new(7).expect("non-zero sequence")).expect("test epoch")
    }

    fn admitted_process() -> (ProcessRequest, ProcessCallerSession) {
        let authority_id = DispatchAuthorityId::new("kernel-build-authority").expect("authority");
        let operation_id = OperationId::new("build-operation-1898").expect("operation");
        let process_tree_id = ProcessTreeId::new("build-tree-1898").expect("tree");
        let job_id = JobId::new("build-job-1898").expect("job");
        let image_id = ImageId::new("cargo-image-1898").expect("image");
        let session_id = SessionId::new("eliotd-build-session-1898").expect("session");
        let generation = Generation::new(3).expect("generation");
        let fence = FencingToken::new(epoch(), generation, "build-fence-1898").expect("fence");
        let intent = ProcessIntent::new(
            operation_id,
            process_tree_id,
            job_id,
            image_id,
            session_id.clone(),
            generation,
            "C:\\Eliot\\modules\\cargo.exe",
            "a".repeat(64),
            vec!["build".to_owned(), "--message-format=json".to_owned()],
            "C:\\Eliot\\worktrees\\1898",
            EnvironmentProjection::new(
                BTreeMap::from([("CARGO_HOME".to_owned(), "C:\\Eliot\\cargo".to_owned())]),
                Vec::new(),
                EnvironmentInheritance::None,
            )
            .expect("environment"),
            ResourceLimits::new(30_000, Some(1_048_576), Some(1_048_576), 4096, 4096, 8)
                .expect("limits"),
        )
        .expect("intent");
        let mut authority = DispatchPermitAuthority::activate(
            authority_id,
            KernelDispatchKey::from_secret_bytes([0x4d; 32]).expect("key"),
        );
        let permit = authority
            .issue(
                &intent,
                PermitIssuance::new(
                    ActionLeaseRef::new("build-lease-1898").expect("lease"),
                    fence,
                    BTreeMap::from([("kernel".to_owned(), "b".repeat(64))]),
                    100,
                    10_000,
                    "build-nonce-1898",
                )
                .expect("issuance"),
            )
            .expect("permit");
        let request = ProcessRequest::new(intent, permit).expect("request");
        let owner =
            ProcessOwnerBinding::new("eliotd", "c".repeat(64), epoch(), generation).expect("owner");
        let caller =
            ProcessCallerSession::new(ProcessSessionClass::EliotdGeneration, owner, session_id)
                .expect("caller");
        (request, caller)
    }

    struct FixtureAdmission;

    impl KernelInstrumentAdmission for FixtureAdmission {
        fn admit(
            &self,
            _invocation: &InstrumentInvocation,
        ) -> Result<KernelAdmittedProcess, KernelAdmissionError> {
            let (request, caller) = admitted_process();
            KernelAdmittedProcess::new(request, caller)
        }
    }

    fn invocation(session_id: Option<&str>) -> InstrumentInvocation {
        InstrumentInvocation {
            request: RequestMetadata {
                request_id: RequestId::new("build-operation-1898").expect("request id"),
                session_id: session_id.map(|value| ContractSessionId::new(value).expect("session")),
                task_id: None,
                product_id: ProductId::new("eliot-product").expect("product"),
                source_id: SourceId::new("eliot-source").expect("source"),
                state_fence: StateFence::new(
                    epoch(),
                    ResourceGeneration::new(3).expect("resource generation"),
                ),
                clock: ClockReading {
                    valid_time_ms: Some(100),
                    known_time_ms: Some(100),
                    transaction_sequence: None,
                    monotonic_ns: Some(1),
                },
            },
            instrument: ContractId::new("eliot.instrument.build").expect("instrument"),
            kind: InstrumentKind::Build,
            profile: "debug".to_owned(),
            target: "artifact".to_owned(),
            arguments: vec!["--message-format=json".to_owned()],
            input_artifacts: Vec::new(),
            declared_scope: "workspace/build".to_owned(),
            requested_at: ClockReading {
                valid_time_ms: Some(100),
                known_time_ms: Some(100),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
        }
    }

    #[test]
    fn admitted_process_preserves_kernel_request_and_owner_identity() {
        let (request, caller) = admitted_process();
        let admitted = KernelAdmittedProcess::new(request, caller).expect("admitted");
        assert_eq!(
            admitted.request().operation_id().as_str(),
            "build-operation-1898"
        );
        assert_eq!(admitted.caller().owner().module_id(), "eliotd");
        assert_eq!(
            admitted.caller().class(),
            ProcessSessionClass::EliotdGeneration
        );
    }

    #[test]
    fn stale_owner_session_is_rejected_before_request_can_cross_runner_boundary() {
        let (request, mut caller) = admitted_process();
        let wrong_session = SessionId::new("other-session").expect("session");
        caller = ProcessCallerSession::new(
            ProcessSessionClass::EliotdGeneration,
            caller.owner().clone(),
            wrong_session,
        )
        .expect("caller shape");
        let error = KernelAdmittedProcess::new(request, caller).expect_err("stale owner");
        assert!(matches!(error, KernelAdmissionError::OwnerBinding(_)));
    }

    #[test]
    fn kernel_request_port_binds_exact_owner_request() {
        let admission = FixtureAdmission;
        let port = KernelInstrumentRequestPort::new(&admission);
        let request = port
            .bind(&invocation(Some("eliotd-build-session-1898")))
            .expect("Kernel owner request");

        assert_eq!(request.operation_id().as_str(), "build-operation-1898");
        assert_eq!(request.generation().get(), 3);
        assert_eq!(request.fence().authority_epoch(), &epoch());
    }

    #[test]
    fn kernel_request_port_rejects_stale_presented_session() {
        let admission = FixtureAdmission;
        let port = KernelInstrumentRequestPort::new(&admission);
        let error = port
            .bind(&invocation(Some("stale-session")))
            .expect_err("stale session");

        assert!(matches!(
            error,
            RunnerError::Binding(message) if message.contains("owner session")
        ));
    }
}
