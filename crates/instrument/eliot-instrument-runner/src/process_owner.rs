//! Kernel-to-InstrumentRunner process-owner composition.
//!
//! The runner cannot create a [`eliot_process::ProcessRequest`].  The request
//! contains a one-shot permit issued by the active Kernel authority and is
//! deliberately sealed by P-03.  This module gives the runtime composition
//! root one concrete adapter for handing that already-admitted request to the
//! runner while retaining the Kernel-derived owner/session binding.

use eliot_instrument_api::{InstrumentAdmissionGrant, InstrumentAdmissionRequest, InstrumentInvocation};
use eliot_process::{ProcessCallerSession, ProcessIntent, ProcessRequest};
use thiserror::Error;

use crate::{
    AdmittedStage, InstrumentRequestPort, ResolvedExecutableIdentity, RunnerError, StageIdentity,
    TestExecutionPlaneRoute,
};

/// Complete resolved terms required by the Kernel-owned stage admission.
///
/// All profile and candidate identities come from the immutable stage plan;
/// the instrument grant comes from #1814's shared admission gate; and the
/// process intent is a non-authoritative description that the TestD owner
/// must rederive from its durable job before issuing one sealed request.
pub struct KernelInstrumentAdmissionRequest<'a> {
    /// Typed invocation presented for this stage.
    pub invocation: &'a InstrumentInvocation,
    /// Exact #1814 admitted stage, including spec, parser, policies and caps.
    pub stage: &'a AdmittedStage,
    /// Durable profile/revision/stage/operation identity.
    pub identity: &'a StageIdentity,
    /// Owning external execution-plane route for this stage.
    pub route: &'a TestExecutionPlaneRoute,
    /// Profile definition digest from the resolved plan.
    pub profile_digest: &'a str,
    /// Stage DAG digest from the resolved plan.
    pub dag_digest: &'a str,
    /// Registry generation from the resolved plan.
    pub registry_generation: u64,
    /// Registry digest from the resolved plan.
    pub registry_digest: &'a str,
    /// Optional bound candidate identity digest from the stage plan.
    pub candidate_identity: Option<&'a str>,
    /// Exact typed request accepted by #1814 stage admission.
    pub instrument_request: &'a InstrumentAdmissionRequest,
    /// Machine-observed executable identity checked by that admission.
    pub executable: &'a ResolvedExecutableIdentity,
    /// Exact #1814 instrument grant, including its admitted spec/profile and
    /// observed executable commitments.
    pub instrument_grant: &'a InstrumentAdmissionGrant,
    /// Exact prospective process terms. It carries no permit or authority.
    pub process_intent: &'a ProcessIntent,
}

impl KernelInstrumentAdmissionRequest<'_> {
    /// Rechecks every stage, candidate, instrument-grant and process binding
    /// before the request can cross the Kernel owner boundary.
    pub fn validate(&self) -> Result<(), KernelAdmissionError> {
        self.invocation
            .validate()
            .map_err(|error| KernelAdmissionError::InvalidRequest(error.to_string()))?;
        self.instrument_request
            .validate()
            .map_err(|error| KernelAdmissionError::InvalidRequest(error.to_string()))?;
        self.process_intent
            .validate()
            .map_err(|error| KernelAdmissionError::InvalidRequest(error.to_string()))?;
        let invalid = |detail: &'static str| KernelAdmissionError::StageBinding(detail);
        let route_identity = self.route.stage();
        if !self.stage.external
            || !self.route.external()
            || self.identity.profile != self.stage.profile
            || self.identity.profile_revision != self.stage.profile_revision
            || self.identity.stage_id != self.stage.stage_id
            || route_identity.profile != self.identity.profile
            || route_identity.profile_revision != self.identity.profile_revision
            || route_identity.stage_id != self.identity.stage_id
            || route_identity
                .operation_id
                .as_ref()
                .is_some_and(|operation| self.identity.operation_id.as_ref() != Some(operation))
            || self.invocation.profile != self.stage.profile
            || self.invocation.instrument != self.stage.spec
            || self.invocation.kind != self.stage.kind
            || self.invocation.arguments != self.stage.argument_template
            || self.route.kind() != self.stage.kind
        {
            return Err(invalid("resolved stage, route, and invocation disagree"));
        }
        if self.registry_generation == 0
            || !is_lower_sha256(self.profile_digest)
            || !is_lower_sha256(self.dag_digest)
            || !is_lower_sha256(self.registry_digest)
            || self
                .candidate_identity
                .is_some_and(|identity| !is_lower_sha256(identity))
        {
            return Err(invalid("resolved profile or candidate identity is malformed"));
        }
        let grant = self.instrument_grant;
        if grant.grant_digest != grant.digest()
            || grant.profile != self.stage.profile
            || grant.profile_revision != self.stage.profile_revision
            || grant.kind_id != self.stage.spec.as_str()
            || grant.kind != self.stage.kind
            || grant.kind_version != self.stage.kind_version
            || grant.spec_digest != self.stage.spec_digest
            || grant.executable != self.stage.executable
            || grant.executable_version != self.stage.executable_version
            || grant.supply_digest
                != self
                    .stage
                    .supply_receipt
                    .as_ref()
                    .map(crate::SupplyChainReceipt::digest)
                    .unwrap_or_default()
            || grant.arguments != self.stage.argument_template
            || grant.environment_class != self.stage.environment_class
            || grant.credential_policy != self.stage.credential_policy
            || grant.network_policy != self.stage.network_policy
            || grant.timeout_ms != self.stage.timeout_ms
            || grant.max_output_bytes != self.stage.max_output_bytes
            || grant.parser != self.stage.parser
            || grant.parser_generation != self.stage.parser_generation
        {
            return Err(invalid("instrument grant differs from the admitted stage"));
        }
        if self.instrument_request.instrument != self.stage.spec
            || self.instrument_request.kind != self.stage.kind
            || self.instrument_request.profile != self.stage.profile
            || self.instrument_request.arguments != self.stage.argument_template
            || self.executable.canonical_path != grant.executable_path
            || self.executable.content_digest != grant.content_digest
            || self.executable.tool_version != grant.executable_version
            || self.executable.executable_file_name() != grant.executable
        {
            return Err(invalid("instrument admission facts differ from the grant"));
        }
        if self.process_intent.operation_id().as_str()
            != self.invocation.request.request_id.as_str()
            || self.process_intent.operation_id().as_str()
                != self.identity.operation_id.as_deref().unwrap_or_default()
            || self.process_intent.generation().get()
                != self
                    .invocation
                    .request
                    .state_fence
                    .resource_generation
                    .value()
            || self.process_intent.executable() != self.executable.canonical_path
            || self.process_intent.executable_sha256() != self.executable.content_digest
            || self.process_intent.argv() != self.executable.arguments
            || !is_lower_sha256(self.process_intent.effect_digest())
        {
            return Err(invalid("prospective process intent differs from the stage identity"));
        }
        let environment_digest = eliot_contracts::canonical_json_bytes(
            self.process_intent.environment(),
        )
        .map(|bytes| eliot_contracts::sha256_hex(&bytes))
        .map_err(|error| KernelAdmissionError::InvalidRequest(error.to_string()))?;
        if environment_digest != self.executable.environment_digest {
            return Err(invalid(
                "prospective process environment differs from the observed executable identity",
            ));
        }
        Ok(())
    }

    /// Digest of the immutable stage/candidate/grant/process association.
    pub fn binding_digest(&self) -> String {
        let candidate = self.candidate_identity.unwrap_or_default();
        let material = format!(
            "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            self.identity.digest(),
            candidate,
            self.profile_digest,
            self.dag_digest,
            self.registry_generation,
            self.registry_digest,
            self.instrument_grant.grant_digest,
            self.process_intent.effect_digest(),
            self.executable.identity_digest(),
        );
        eliot_contracts::sha256_hex(material.as_bytes())
    }
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

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
    stage_binding_digest: Option<String>,
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
        Ok(Self {
            request,
            caller,
            stage_binding_digest: None,
        })
    }

    /// Validates the exact process request against the complete stage terms
    /// returned by the Kernel/TestD owner.
    pub fn new_for_stage(
        request: ProcessRequest,
        caller: ProcessCallerSession,
        terms: &KernelInstrumentAdmissionRequest<'_>,
    ) -> Result<Self, KernelAdmissionError> {
        terms.validate()?;
        if request.intent() != terms.process_intent {
            return Err(KernelAdmissionError::StageBinding(
                "owner process request differs from the exact admitted process intent",
            ));
        }
        let binding_digest = terms.binding_digest();
        let mut admitted = Self::new(request, caller)?;
        admitted.stage_binding_digest = Some(binding_digest);
        Ok(admitted)
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

    /// Returns the stage/candidate/process digest bound when the owner issued
    /// this request.
    #[must_use]
    pub fn stage_binding_digest(&self) -> Option<&str> {
        self.stage_binding_digest.as_deref()
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
    /// Stage, candidate, instrument-grant, or process terms differ.
    #[error("Kernel stage process binding failed: {0}")]
    StageBinding(&'static str),
}

/// Sole composition hook for the active Kernel process-authority owner.
///
/// The implementation belongs to the Kernel/runtime composition root and must
/// route to the same `ProcessDispatchAuthorityController` that backs the
/// `ProcessExecutor`.  It returns a fresh one-shot request for each invocation
/// and never exposes a key, replay journal, or caller-created permit.
pub trait KernelInstrumentAdmission: Send + Sync {
    /// Admits one complete resolved stage/candidate/process tuple and returns
    /// its sealed request plus the exact Kernel-derived owner/session
    /// binding. Implementations must recheck the #1814 stage grant against
    /// the live TestD admission and dispatch authority before constructing the
    /// request.
    fn admit(
        &self,
        request: &KernelInstrumentAdmissionRequest<'_>,
    ) -> Result<KernelAdmittedProcess, KernelAdmissionError>;
}

/// Fail-closed [`KernelInstrumentAdmission`] for composition roots that bind
/// no live process-authority provider (issue #1813 W4).
///
/// This is the production default where no Kernel/testd admission owner is
/// reachable: every invocation is refused with a typed
/// [`KernelAdmissionError::Rejected`] naming the missing provider, so a stage
/// can never launch on invented authority.  Composition roots that own a real
/// provider (the Kernel dispatch authority, the testd dispatch authority)
/// must implement [`KernelInstrumentAdmission`] over that same authority
/// instead of using this refusal; test-only fixtures belong behind
/// `#[cfg(test)]`, never here.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UnprovisionedKernelAdmission;

impl KernelInstrumentAdmission for UnprovisionedKernelAdmission {
    fn admit(
        &self,
        _request: &KernelInstrumentAdmissionRequest<'_>,
    ) -> Result<KernelAdmittedProcess, KernelAdmissionError> {
        Err(KernelAdmissionError::Rejected(
            "no Kernel/testd process-admission provider is bound in this composition root; stage execution awaits the admitted provider (issue #1813 W4)"
                .to_owned(),
        ))
    }
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
    fn bind(&self, _invocation: &InstrumentInvocation) -> Result<ProcessRequest, RunnerError> {
        Err(RunnerError::Binding(
            "Kernel stage admission requires a resolved stage, candidate identity, instrument grant, and complete process terms"
                .to_owned(),
        ))
    }
}

impl KernelInstrumentRequestPort<'_> {
    /// Binds one stage only after every plan, candidate, grant, executable,
    /// and process-intent term is present and revalidated.
    pub fn bind_stage(
        &self,
        terms: &KernelInstrumentAdmissionRequest<'_>,
    ) -> Result<ProcessRequest, RunnerError> {
        terms
            .validate()
            .map_err(|error| RunnerError::Binding(error.to_string()))?;
        let admitted = self
            .admission
            .admit(terms)
            .map_err(|error| RunnerError::Binding(error.to_string()))?;
        if admitted.stage_binding_digest() != Some(terms.binding_digest().as_str()) {
            return Err(RunnerError::Binding(
                "Kernel stage binding differs from the resolved stage/candidate/process terms"
                    .to_owned(),
            ));
        }
        if admitted.request().intent() != terms.process_intent {
            return Err(RunnerError::Binding(
                "Kernel process request differs from the admitted process intent".to_owned(),
            ));
        }
        if let Some(session_id) = terms.invocation.request.session_id.as_ref()
            && session_id.as_str() != admitted.caller().session_id().as_str()
        {
            return Err(RunnerError::Binding(
                "Kernel owner session differs from instrument invocation session".to_owned(),
            ));
        }
        let request = admitted.request();
        if request.operation_id().as_str() != terms.invocation.request.request_id.as_str() {
            return Err(RunnerError::IdentityMismatch);
        }
        if request.generation().get()
            != terms
                .invocation
                .request
                .state_fence
                .resource_generation
                .value()
        {
            return Err(RunnerError::Binding(
                "Kernel request generation differs from invocation fence".to_owned(),
            ));
        }
        if request.fence().authority_epoch()
            != &terms.invocation.request.state_fence.authority_epoch
        {
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
