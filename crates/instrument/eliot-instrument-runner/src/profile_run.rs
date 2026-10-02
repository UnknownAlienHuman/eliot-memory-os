//! Deterministic stage orchestration, durable run records, and aggregation.
//!
//! This module extends [`InstrumentRunner`](crate::InstrumentRunner) toward
//! deterministic stage-DAG orchestration for issue #1813 without changing any
//! existing launch, inspection, or verdict behavior. The
//! [`StageOrchestrator`] walks an admitted profile DAG in topological order,
//! launches each external stage through the existing runner primitives, and
//! assembles one [`InstrumentRun`] per stage plus a [`ProfileAggregate`] that
//! retains every success, partial-failure, missing-stage, and evidence-handle
//! state.
//!
//! The orchestrator never synthesizes commands (every launch binds through a
//! caller-supplied [`InstrumentRequestPort`](crate::InstrumentRequestPort)),
//! never declares tasks complete (the aggregate is an observation, not a
//! finish decision), and never conceals missing or failed stages (unobserved
//! stages become explicit [`StageEvidence::Missing`] runs).
//!
//! A retained stage binds more than the kept bytes: [`StageEvidence::Retained`]
//! also carries the [`RetainedToolIdentity`] that produced them, so the exact
//! tool command, the environment projection, and the terminal exit outcome
//! travel with the artifact handle instead of being reconstructed from it
//! later.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use eliot_contracts::{ArtifactId, ModuleRuntimeClass, sha256_hex};
use eliot_graph_api::{GraphQuery, GraphRevision};
use eliot_instrument_api::{
    BuildClass, ExecutionStatus, InstrumentAdmissionGrant, InstrumentInvocation, InstrumentKind,
    TARGET_LAYOUT_REVISION,
};
use eliot_process::{
    ExitDisposition, ProcessEvidenceSink, ProcessExecutor, ProcessIntent, ProcessRequest,
};
use eliot_process_executor::ExecutableObservation;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::admission_submission::{
    AdmissionSubmission, AdmissionSubmissionReadback, PureTransformSubmission,
    prepare_admission_submission, prepare_pure_transform_submission,
};
use crate::profile::{
    AdmittedProfile, AdmittedStage, InstrumentRegistry, PureTransformHandler, ResolvedProfile,
    StageExecution, TargetLayout, WorkScope,
};
use crate::registry::{
    RegistryEntry, RegistryError, ResolvedExecutableIdentity, SupplyChainReceipt,
};
use crate::testd_port::{TestdAdmission, TestdAdmissionPort, TestdPortError, testd_dispatchable};
use crate::{
    InstrumentBinding, InstrumentRequestPort, InstrumentRunner, InstrumentStartReceipt,
    RunnerError, bridge_executor_observation,
};
use eliot_instrument_api::registry::ExternalStagePin;
use eliot_ipc::RequestIdentity;
use eliot_store_api::{
    CanonicalReadClient, NamedReadOperation, NamedReadRequest, NamedReadResponse, ReadConsistency,
    ScopeId, WriteReceipt, decode_resource_content, validate_resource_snapshot_read_params,
};

fn environment_binding(
    projection: &eliot_process::EnvironmentProjection,
) -> eliot_instrument_api::registry::EnvironmentProjectionBinding {
    eliot_instrument_api::registry::EnvironmentProjectionBinding {
        non_secret: projection.non_secret().clone(),
        secret_refs: projection
            .secret_refs()
            .iter()
            .map(
                |reference| eliot_instrument_api::registry::EnvironmentSecretReference {
                    provider: reference.provider().to_owned(),
                    key: reference.key().to_owned(),
                },
            )
            .collect(),
        inheritance: match projection.inheritance() {
            eliot_process::EnvironmentInheritance::None => {
                eliot_instrument_api::registry::EnvironmentInheritanceBinding::None
            }
            eliot_process::EnvironmentInheritance::Allowlisted => {
                eliot_instrument_api::registry::EnvironmentInheritanceBinding::Allowlisted
            }
        },
    }
}

/// Current-stage Kernel identity and profile-stage selection retained as
/// inert request input. These fields carry no permission: the Kernel
/// authenticates the current request identity and proves the scoped canonical
/// registry row before creating a process admission. Historical registration
/// identity is recovered only through its original receipt and ledger.
#[derive(Clone, Debug)]
pub struct RegistryLaunchSelection {
    /// Current stage/read request identity, forwarded unchanged to Kernel.
    pub request_identity: RequestIdentity,
    /// Fixed canonical registry scope selected by the original registration.
    pub scope_id: ScopeId,
    /// Owner-pinned profile, revision, stage, and registry generation.
    pub pin: ExternalStagePin,
    /// Admitted target layout carried by the current-stage request.
    pub layout: TargetLayout,
    /// Admitted work scope and request fence carried by the current-stage request.
    pub work_scope: WorkScope,
    /// Current typed process intent, sent unchanged to Kernel.
    pub intent: ProcessIntent,
}

/// Decodes the closed current Kernel identity and exact profile-stage
/// selection from retained bootstrap evidence.
///
/// # Errors
/// Returns a binding error for missing, unknown, malformed, or pre-bound data.
pub fn registry_launch_selection(value: &Value) -> Result<RegistryLaunchSelection, RunnerError> {
    let object = value
        .as_object()
        .ok_or_else(|| RunnerError::Binding("registry_selection is not an object".to_owned()))?;
    if object.len() != 6
        || [
            "request_identity",
            "scope_id",
            "pin",
            "layout",
            "work_scope",
            "intent",
        ]
        .iter()
        .any(|key| !object.contains_key(*key))
    {
        return Err(RunnerError::Binding(
            "registry_selection must contain exactly identity, scope, pin, layout, work scope, and intent".to_owned(),
        ));
    }
    let layout = object["layout"].as_object().ok_or_else(|| {
        RunnerError::Binding("registry_selection.layout is not an object".to_owned())
    })?;
    let work_scope = object["work_scope"].as_object().ok_or_else(|| {
        RunnerError::Binding("registry_selection.work_scope is not an object".to_owned())
    })?;
    if layout.len() != 3
        || ["source_root", "target_root", "cache_root"]
            .iter()
            .any(|key| !layout.contains_key(*key))
        || work_scope.len() != 2
        || ["declared_scope", "fence"]
            .iter()
            .any(|key| !work_scope.contains_key(*key))
    {
        return Err(RunnerError::Binding(
            "original layout or work scope has unknown or missing fields".to_owned(),
        ));
    }
    let text =
        |object: &serde_json::Map<String, Value>, key: &str| -> Result<String, RunnerError> {
            let value = object.get(key).and_then(Value::as_str).ok_or_else(|| {
                RunnerError::Binding(format!("registry selection field '{key}' is not text"))
            })?;
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(RunnerError::Binding(format!(
                    "registry selection field '{key}' is blank or contains control characters"
                )));
            }
            Ok(value.to_owned())
        };
    let selection = RegistryLaunchSelection {
        request_identity: decode_registry_selection(
            &object["request_identity"],
            "request_identity",
        )?,
        scope_id: decode_registry_selection(&object["scope_id"], "scope_id")?,
        pin: decode_registry_selection(&object["pin"], "pin")?,
        layout: TargetLayout::new(
            text(layout, "source_root")?,
            text(layout, "target_root")?,
            text(layout, "cache_root")?,
        )
        .map_err(|error| {
            RunnerError::Binding(format!("original target layout is invalid: {error}"))
        })?,
        work_scope: WorkScope::new(
            text(work_scope, "declared_scope")?,
            decode_registry_selection(&work_scope["fence"], "work_scope.fence")?,
        )
        .map_err(|error| {
            RunnerError::Binding(format!("original work scope is invalid: {error}"))
        })?,
        intent: decode_registry_selection(&object["intent"], "intent")?,
    };
    selection.request_identity.validate().map_err(|error| {
        RunnerError::Binding(format!(
            "original Kernel request identity is invalid: {error}"
        ))
    })?;
    if selection.pin.profile.trim().is_empty()
        || selection.pin.profile.chars().any(char::is_control)
        || selection.pin.stage_id.trim().is_empty()
        || selection.pin.stage_id.chars().any(char::is_control)
        || selection.pin.profile_revision == 0
        || selection.pin.registry_generation == 0
    {
        return Err(RunnerError::Binding(
            "registry profile and stage pins must be valid and nonzero".to_owned(),
        ));
    }
    if selection.work_scope.fence != selection.request_identity.request.state_fence {
        return Err(RunnerError::Binding(
            "original work scope fence differs from its Kernel request identity".to_owned(),
        ));
    }
    selection.intent.validate().map_err(|error| {
        RunnerError::Binding(format!("original process intent is invalid: {error}"))
    })?;
    if selection.intent.operation_id().as_str()
        != selection
            .request_identity
            .request
            .metadata
            .request_id
            .as_str()
        || selection.intent.generation().get()
            != selection
                .request_identity
                .request
                .state_fence
                .resource_generation
                .value()
        || selection.intent.instrument_admission_digest().is_some()
    {
        return Err(RunnerError::Binding(
            "original process intent differs from its Kernel request identity or is already grant-bound".to_owned(),
        ));
    }
    Ok(selection)
}

fn decode_registry_selection<T: DeserializeOwned>(
    value: &Value,
    field: &str,
) -> Result<T, RunnerError> {
    serde_json::from_value(value.clone())
        .map_err(|error| RunnerError::Binding(format!("{field} is invalid: {error}")))
}

/// Exact owner evidence returned for one admission read: the original
/// committed write receipt, its retained registration readback, and the
/// fresh current readback through the authenticated owner.
pub type AdmissionSubmissionOwnerReadback = (WriteReceipt, NamedReadResponse, NamedReadResponse);

/// Opaque result of live stage admission. Only `StageOrchestrator` can create
/// one; it is bound to the exact invocation and process request that passed
/// executable observation, profile admission, and canonical registry proof.
#[derive(Debug)]
pub struct AdmittedStageGrant {
    pub(crate) grant: InstrumentAdmissionGrant,
    identity: ResolvedExecutableIdentity,
    pub(crate) binding_seal: String,
}

impl AdmittedStageGrant {
    /// Returns the observed executable identity for owner-persisted pin
    /// metadata. The admission grant itself remains opaque.
    #[must_use]
    pub const fn executable_identity(&self) -> &ResolvedExecutableIdentity {
        &self.identity
    }
}

pub(crate) fn admitted_binding_seal(binding: &InstrumentBinding) -> Result<String, RunnerError> {
    let request = binding
        .process_request
        .as_ref()
        .ok_or(RunnerError::ReceiptMismatch)?;
    admitted_request_seal(&binding.invocation, request)
}

fn admitted_request_seal(
    invocation: &InstrumentInvocation,
    request: &ProcessRequest,
) -> Result<String, RunnerError> {
    let encoded = serde_json::to_vec(&(
        invocation,
        request.operation_id().as_str(),
        request.invocation_digest(),
        request.generation().get(),
        request.executable_sha256(),
        request.argv(),
    ))
    .map_err(|_| RunnerError::ReceiptMismatch)?;
    Ok(sha256_hex(&encoded))
}

/// Failures raised while planning or recording profile runs.
///
/// Launch failures never surface here: they become explicit
/// [`StageEvidence::Missing`] runs so the aggregate stays total.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProfileRunError {
    /// A required text value is blank or contains a control character.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText {
        /// Field that failed validation.
        field: &'static str,
    },
    /// A stage identity names revision zero, which is never admitted.
    #[error("stage '{stage}' names unversioned profile revision zero")]
    InvalidRevision {
        /// Offending stage identity.
        stage: String,
    },
    /// A candidate identity is not a lowercase SHA-256 digest.
    #[error("{field} must be a lowercase SHA-256 digest")]
    InvalidDigest {
        /// Field that failed validation.
        field: &'static str,
    },
    /// A candidate identity was already bound to a different value.
    #[error("candidate identity is already bound to this stage plan")]
    CandidateIdentityAlreadyBound,
    /// A retained exit outcome disagrees with its own disposition.
    #[error("exit outcome for disposition {disposition} is not admissible")]
    InvalidExitOutcome {
        /// Observed disposition that the exit code contradicts.
        disposition: String,
    },
}

/// Validates one required text value.
fn validate_text(value: &str, field: &'static str) -> Result<(), ProfileRunError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ProfileRunError::InvalidText { field });
    }
    Ok(())
}

/// Validates a lowercase SHA-256 digest without computing or normalizing it.
fn validate_digest(value: &str, field: &'static str) -> Result<(), ProfileRunError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(ProfileRunError::InvalidDigest { field });
    }
    Ok(())
}

/// Durable stage identity (I10.8.13).
///
/// The `(profile, revision, stage)` triple is stable across restarts; the
/// executor operation reference binds at launch. Re-execution under the same
/// identity never hides the first failed or unknown attempt: each attempt is
/// a separate [`InstrumentRun`] under the same stable triple.
#[derive(Clone)]
pub struct StageIdentity {
    /// Admitted profile name.
    pub profile: String,
    /// Exact admitted profile revision.
    pub profile_revision: u64,
    /// Durable stage identity within the profile revision.
    pub stage_id: String,
    /// Executor operation reference, bound at launch.
    pub operation_id: Option<String>,
}

impl StageIdentity {
    /// Plans an identity for a declared stage before launch.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileRunError::InvalidText`] when an identity is blank, or
    /// [`ProfileRunError::InvalidRevision`] when the revision is zero.
    pub fn planned(
        profile: String,
        profile_revision: u64,
        stage_id: String,
    ) -> Result<Self, ProfileRunError> {
        validate_text(&profile, "profile")?;
        validate_text(&stage_id, "stage_id")?;
        if profile_revision == 0 {
            return Err(ProfileRunError::InvalidRevision { stage: stage_id });
        }
        Ok(Self {
            profile,
            profile_revision,
            stage_id,
            operation_id: None,
        })
    }

    /// Binds the sealed executor operation reference after launch.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileRunError::InvalidText`] when the operation identity
    /// is blank or carries control characters.
    pub fn bound(mut self, operation_id: String) -> Result<Self, ProfileRunError> {
        validate_text(&operation_id, "operation_id")?;
        self.operation_id = Some(operation_id);
        Ok(self)
    }

    /// Deterministic identity over the stable triple plus bound operation.
    pub fn digest(&self) -> String {
        let operation = self.operation_id.as_deref().unwrap_or("");
        let material = format!(
            "{}\0{}\0{}\0{}",
            self.profile, self.profile_revision, self.stage_id, operation,
        );
        sha256_hex(material.as_bytes())
    }
}

/// Pins one external stage to the test execution plane (I10.8.15).
///
/// The route records which runtime class owns the stage and whether live
/// `testd` can dispatch its class today. Recording the route grants no
/// launch authority: physical execution still flows through the injected
/// [`ProcessExecutor`](eliot_process::ProcessExecutor) behind the owning
/// supervisor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestExecutionPlaneRoute {
    stage: StageIdentity,
    kind: InstrumentKind,
    external: bool,
}

impl TestExecutionPlaneRoute {
    /// Routes one planned stage through the test execution plane.
    pub fn route(stage: StageIdentity, kind: InstrumentKind, external: bool) -> Self {
        Self {
            stage,
            kind,
            external,
        }
    }

    /// Runtime class that owns external build/test stages.
    pub const fn plane() -> ModuleRuntimeClass {
        ModuleRuntimeClass::TestExecutionPlane
    }

    /// Durable stage identity carried by this route.
    pub fn stage(&self) -> &StageIdentity {
        &self.stage
    }

    /// Stage class carried by this route.
    pub const fn kind(&self) -> InstrumentKind {
        self.kind
    }

    /// Whether the stage dispatches through the plane (`false` marks an
    /// explicitly pure in-process transform).
    pub const fn external(&self) -> bool {
        self.external
    }

    /// Whether live `testd` can dispatch this stage class today.
    ///
    /// Only [`InstrumentKind::Test`] dispatches; every other class resolves
    /// through the registry but stays non-dispatchable via `testd`, reported
    /// here instead of failing the whole plan.
    pub fn dispatchable_via_testd(&self) -> bool {
        crate::testd_port::testd_dispatchable(self.kind)
    }
}

/// One planned stage: admitted declaration plus its plane route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedStage {
    /// Admitted declaration in topological position.
    pub stage: AdmittedStage,
    /// Plane route for the stage.
    pub route: TestExecutionPlaneRoute,
    /// Exact resolved WorkScope/layout/environment used for admission.
    /// External execution refuses plans that have no retained resolution.
    pub resolution: Option<ResolvedProfile>,
}

/// One deterministic stage plan expanded from an admitted profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagePlan {
    /// Admitted profile name.
    pub profile: String,
    /// Exact admitted revision.
    pub revision: u64,
    /// Registry generation the plan was compiled against.
    pub registry_generation: u64,
    /// Registry digest the plan was compiled against.
    pub registry_digest: String,
    /// Profile definition digest.
    pub profile_digest: String,
    /// Stage DAG digest.
    pub dag_digest: String,
    /// Optional complete candidate/configuration identity.
    ///
    /// Generic profile plans leave this absent. Candidate-bound callers set
    /// the identity returned by their existing candidate authority.
    pub candidate_identity: Option<String>,
    /// Planned stages in deterministic topological order.
    pub stages: Vec<PlannedStage>,
}

impl StagePlan {
    /// Binds one existing candidate identity to this plan.
    ///
    /// This validates only the identity's SHA-256 text shape; it does not
    /// compute a second candidate fingerprint. Repeating the same binding is
    /// harmless, while attempting to replace an existing identity fails.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileRunError::InvalidDigest`] for malformed identity text
    /// or [`ProfileRunError::CandidateIdentityAlreadyBound`] when a different
    /// identity is already present.
    pub fn bind_candidate_identity(
        &mut self,
        candidate_identity: impl Into<String>,
    ) -> Result<(), ProfileRunError> {
        let candidate_identity = candidate_identity.into();
        validate_digest(&candidate_identity, "candidate_identity")?;
        if let Some(bound) = &self.candidate_identity {
            if bound == &candidate_identity {
                return Ok(());
            }
            return Err(ProfileRunError::CandidateIdentityAlreadyBound);
        }
        self.candidate_identity = Some(candidate_identity);
        Ok(())
    }
}

/// Per-stage launch provisions supplied by the composition root.
///
/// The implementation belongs to the runtime composition root: it derives
/// each stage invocation from the admitted plan, returns the sealed process
/// request through its port, and supplies the governed evidence sink. The
/// orchestrator never invents invocations, requests, or sinks.
pub(crate) mod admission_proof_port_sealed {
    pub trait Sealed {}
}

#[allow(
    private_bounds,
    reason = "the private supertrait seals owner proof implementations to this runner crate"
)]
pub trait AdmissionSubmissionProofPort: admission_proof_port_sealed::Sealed + Send + Sync {
    /// Read-only access to the retained original registration proof.
    fn read_admission<'a>(
        &'a self,
        _submission: &'a AdmissionSubmission,
    ) -> Pin<
        Box<dyn Future<Output = Result<AdmissionSubmissionOwnerReadback, RunnerError>> + Send + 'a>,
    > {
        Box::pin(async {
            Err(RunnerError::Binding(
                "external stage lacks an owner-backed original registration proof".to_owned(),
            ))
        })
    }

    /// Read-only access to the retained original registration proof for a
    /// registered in-process transform. Implementations that only authorize
    /// process launches stay fail-closed for this separate path.
    fn read_pure_admission<'a>(
        &'a self,
        _submission: &'a PureTransformSubmission,
    ) -> Pin<
        Box<dyn Future<Output = Result<AdmissionSubmissionOwnerReadback, RunnerError>> + Send + 'a>,
    > {
        Box::pin(async {
            Err(RunnerError::Binding(
                "pure transform lacks an owner-backed original registration proof".to_owned(),
            ))
        })
    }
}

/// Explicit no-owner proof source for offline composition and cache-only
/// paths. It cannot authorize a launch; every read uses the trait's typed
/// refusal default.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UnprovisionedAdmissionProofPort;

impl admission_proof_port_sealed::Sealed for UnprovisionedAdmissionProofPort {}
impl AdmissionSubmissionProofPort for UnprovisionedAdmissionProofPort {}

/// Typed inputs retained from a canonical resource snapshot for an admitted
/// pure transform. Construction reads the snapshot through its owner so a
/// caller cannot pair arbitrary bytes with a chosen artifact identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PureTransformInput {
    source_read_request: NamedReadRequest,
    source_readback: NamedReadResponse,
    source_artifact: ArtifactId,
    source_bytes: Vec<u8>,
    source_byte_len: u64,
    source_content_base64: String,
    source_sha256: String,
    source_revision: u64,
    query: GraphQuery,
    graph_revision: GraphRevision,
}

impl PureTransformInput {
    /// Reads and retains the exact canonical resource snapshot used as input.
    ///
    /// The artifact identity is derived from the URI returned by the owner;
    /// callers provide only the exact named-read request and typed graph
    /// query. No caller-supplied readback, digest, or raw bytes are accepted.
    pub async fn retain_resource_snapshot<C: CanonicalReadClient + 'static>(
        client: Arc<C>,
        request: NamedReadRequest,
        query: GraphQuery,
        graph_revision: GraphRevision,
    ) -> Result<Self, RunnerError> {
        request
            .validate()
            .map_err(|error| RunnerError::Binding(format!("resource snapshot request: {error}")))?;
        if request.operation != NamedReadOperation::GetResourceSnapshot
            || request.scope_id.is_some()
            || request.consistency != ReadConsistency::ExactFence
        {
            return Err(RunnerError::Binding(
                "pure transform input requires an exact-fence resource snapshot read".to_owned(),
            ));
        }
        let requested_uri = validate_resource_snapshot_read_params(&request.parameters)
            .map_err(|error| RunnerError::Binding(format!("resource snapshot URI: {error}")))?;
        query
            .validate()
            .map_err(|error| RunnerError::Binding(format!("pure transform query: {error}")))?;
        if query
            .expected_revision
            .is_some_and(|expected| expected != graph_revision)
        {
            return Err(RunnerError::Binding(
                "pure transform graph revision differs from the typed query".to_owned(),
            ));
        }

        let readback = client
            .execute_named(request.clone())
            .await
            .map_err(|error| RunnerError::Binding(format!("resource snapshot read: {error}")))?;
        readback.validate().map_err(|error| {
            RunnerError::Binding(format!("resource snapshot readback: {error}"))
        })?;
        let response_fence = serde_json::to_value(readback.state_fence.clone())
            .map_err(|error| RunnerError::Binding(format!("resource snapshot fence: {error}")))?;
        if readback.operation != NamedReadOperation::GetResourceSnapshot
            || readback.state_fence != request.state_fence
            || readback.payload.get("state_fence") != Some(&response_fence)
        {
            return Err(RunnerError::Binding(
                "resource snapshot readback changed its operation or state fence".to_owned(),
            ));
        }
        let returned_uri = readback
            .payload
            .get("uri")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                RunnerError::Binding("resource snapshot readback omitted its URI".to_owned())
            })?;
        if returned_uri != requested_uri {
            return Err(RunnerError::Binding(
                "resource snapshot readback changed the requested URI".to_owned(),
            ));
        }
        let source_sha256 = readback
            .payload
            .get("content_sha256")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                RunnerError::Binding(
                    "resource snapshot readback omitted its original content digest".to_owned(),
                )
            })?
            .to_owned();
        let source_content_base64 = readback
            .payload
            .get("content_base64")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                RunnerError::Binding("resource snapshot readback omitted its content".to_owned())
            })?
            .to_owned();
        let source_revision = readback
            .payload
            .get("revision")
            .and_then(serde_json::Value::as_u64)
            .filter(|revision| *revision > 0)
            .ok_or_else(|| {
                RunnerError::Binding(
                    "resource snapshot readback omitted its positive owner revision".to_owned(),
                )
            })?;
        let source_bytes = decode_resource_content(&source_content_base64, &source_sha256)
            .map_err(|error| {
                RunnerError::Binding(format!("resource snapshot content proof: {error}"))
            })?;
        let source_byte_len = u64::try_from(source_bytes.len())
            .map_err(|error| RunnerError::Binding(format!("resource snapshot length: {error}")))?;
        let source_artifact = ArtifactId::new(returned_uri.to_owned())
            .map_err(|error| RunnerError::Binding(format!("resource snapshot URI: {error}")))?;

        Ok(Self {
            source_read_request: request,
            source_readback: readback,
            source_artifact,
            source_bytes,
            source_byte_len,
            source_content_base64,
            source_sha256,
            source_revision,
            query,
            graph_revision,
        })
    }

    fn verify_original_snapshot(&self) -> Result<(), RunnerError> {
        self.source_read_request.validate().map_err(|error| {
            RunnerError::Binding(format!("retained resource snapshot request: {error}"))
        })?;
        self.source_readback.validate().map_err(|error| {
            RunnerError::Binding(format!("retained resource snapshot readback: {error}"))
        })?;
        let requested_uri =
            validate_resource_snapshot_read_params(&self.source_read_request.parameters).map_err(
                |error| RunnerError::Binding(format!("retained resource snapshot URI: {error}")),
            )?;
        let response_fence = serde_json::to_value(self.source_readback.state_fence.clone())
            .map_err(|error| RunnerError::Binding(format!("retained snapshot fence: {error}")))?;
        if self.source_read_request.operation != NamedReadOperation::GetResourceSnapshot
            || self.source_read_request.consistency != ReadConsistency::ExactFence
            || self.source_read_request.scope_id.is_some()
            || self.source_readback.operation != NamedReadOperation::GetResourceSnapshot
            || self.source_readback.state_fence != self.source_read_request.state_fence
            || self.source_readback.payload.get("state_fence") != Some(&response_fence)
            || requested_uri != self.source_artifact.as_str()
            || self
                .source_readback
                .payload
                .get("uri")
                .and_then(serde_json::Value::as_str)
                != Some(self.source_artifact.as_str())
            || self
                .source_readback
                .payload
                .get("content_sha256")
                .and_then(serde_json::Value::as_str)
                != Some(self.source_sha256.as_str())
            || self
                .source_readback
                .payload
                .get("content_base64")
                .and_then(serde_json::Value::as_str)
                != Some(self.source_content_base64.as_str())
            || self
                .source_readback
                .payload
                .get("revision")
                .and_then(serde_json::Value::as_u64)
                != Some(self.source_revision)
        {
            return Err(RunnerError::Binding(
                "retained resource snapshot owner proof changed after validation".to_owned(),
            ));
        }
        let verified = decode_resource_content(&self.source_content_base64, &self.source_sha256)
            .map_err(|error| {
                RunnerError::Binding(format!("retained resource snapshot proof: {error}"))
            })?;
        if verified != self.source_bytes || verified.len() as u64 != self.source_byte_len {
            return Err(RunnerError::Binding(
                "retained resource snapshot bytes changed after owner validation".to_owned(),
            ));
        }
        Ok(())
    }
}

pub trait StageLauncher: Send + Sync {
    /// Derives the typed invocation for one planned stage.
    ///
    /// # Errors
    ///
    /// Returns a runner error when the stage invocation is unavailable; the
    /// orchestrator records the stage as missing instead of failing the plan.
    fn invocation(&self, stage: &PlannedStage) -> Result<InstrumentInvocation, RunnerError>;

    /// Returns the admitted request port for one planned stage.
    fn port(&self, stage: &PlannedStage) -> &dyn InstrumentRequestPort;

    /// Returns the governed evidence sink for one planned stage.
    fn sink(&self, stage: &PlannedStage) -> Arc<dyn ProcessEvidenceSink>;

    /// Supplies typed raw evidence and the typed request for an admitted pure
    /// transform. Existing external launchers do not silently acquire this
    /// capability.
    fn pure_input(&self, _stage: &PlannedStage) -> Result<PureTransformInput, RunnerError> {
        Err(RunnerError::Binding(
            "stage launcher has no retained input for the registered pure transform".to_owned(),
        ))
    }
}

/// Raw evidence state carried by one [`InstrumentRun`].
///
/// Retention alone establishes no outcome; omission and absence are explicit
/// typed states that can never become a successful aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StageEvidence {
    /// Material output retained under an immutable artifact handle.
    Retained {
        /// Stable handle for the retained bytes.
        artifact: eliot_contracts::ArtifactId,
        /// Exact retained byte length.
        byte_len: u64,
        /// Exact tool identity under which those bytes were produced.
        tool: RetainedToolIdentity,
    },
    /// Result of an admitted deterministic in-process transform. The raw
    /// lineage carries its canonical URI, original digest, Store revision,
    /// and length; `result_bytes` are the canonical typed result, never a
    /// process output claim.
    Transformed {
        /// Handle of the retained raw artifact consumed by the transform.
        source_artifact: ArtifactId,
        /// Exact byte length of that raw input.
        source_byte_len: u64,
        /// Original canonical Store content digest for the source snapshot.
        source_sha256: String,
        /// Original Store-local snapshot revision read for the transform.
        source_revision: u64,
        /// Canonically serialized deterministic result.
        result_bytes: Vec<u8>,
        /// Digest of the exact result bytes.
        result_digest: String,
    },
    /// Material output absent for an explicit, typed reason.
    Omitted {
        /// Why the output is absent.
        reason: String,
    },
    /// The stage never produced evidence: unavailable instrument, refused
    /// admission, failed launch, blocked dependency, or unobserved stage.
    Missing {
        /// Exact missing proof (I10.8.11).
        reason: String,
    },
}

impl StageEvidence {
    /// Whether the stage produced no evidence at all.
    pub const fn is_missing(&self) -> bool {
        matches!(self, Self::Missing { .. })
    }
}

/// Terminal exit observation of the process that produced one retained payload.
///
/// The disposition is the shared executor's own
/// [`ExitDisposition`](eliot_process::ExitDisposition), never a re-derived
/// guess, and the code is present exactly when the disposition admits one — the
/// same validity rule the process contract itself enforces. A retained payload
/// with no admissible exit observation is refused instead of defaulted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RetainedExitOutcome {
    /// Physical disposition observed by the shared process executor.
    pub disposition: ExitDisposition,
    /// Process exit code, present only for a `Completed` exit.
    pub code: Option<i32>,
}

impl RetainedExitOutcome {
    /// Whether this outcome is the exact shape its disposition admits.
    const fn is_admissible(&self) -> bool {
        match self.disposition {
            ExitDisposition::Completed => self.code.is_some(),
            ExitDisposition::Unknown => self.code.is_none(),
            _ => false,
        }
    }

    /// Canonical digest over the observed exit outcome.
    #[must_use]
    pub fn digest(&self) -> String {
        sha256_hex(format!("{:?}\0{:?}", self.disposition, self.code).as_bytes())
    }
}

/// Exact tool identity under which one retained payload was produced.
///
/// A retained artifact handle says *what* was kept; this says *which
/// invocation produced it*: the exact executable and argument vector, the
/// environment projection the launch was admitted under, and the terminal exit
/// outcome. Two runs of the same tool over different arguments, different
/// environments, or different exits therefore yield distinguishable retained
/// evidence by construction rather than by later reconstruction.
///
/// Arguments stay separated and are never rendered into a shell command line.
/// The environment is the launch's resolved projection digest, which the
/// executor itself documents as attested (the declared projection) rather than
/// machine-observed; this type preserves that distinction instead of
/// re-observing it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedToolIdentity {
    /// Executable selected by the authority and launched for this stage.
    pub executable: String,
    /// Exact argument vector handed to the executable.
    pub arguments: Vec<String>,
    /// Lowercase SHA-256 hex over the resolved environment projection.
    pub environment_digest: String,
    /// Observed terminal exit outcome of the producing process.
    pub exit: RetainedExitOutcome,
}

impl RetainedToolIdentity {
    /// Validates and seals the identity of one retained payload.
    ///
    /// Every value is checked rather than normalized: a blank or
    /// control-character-bearing executable or argument, a malformed
    /// environment digest, and an exit outcome that disagrees with its own
    /// disposition are all refused. Nothing is defaulted, so a retained handle
    /// can never claim an identity no producer observed.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileRunError::InvalidText`] for a blank or
    /// control-character-bearing command value,
    /// [`ProfileRunError::InvalidDigest`] for a malformed environment digest,
    /// and [`ProfileRunError::InvalidExitOutcome`] when the exit code does not
    /// match the observed disposition.
    pub fn sealed(
        executable: &str,
        arguments: &[String],
        environment_digest: &str,
        exit: RetainedExitOutcome,
    ) -> Result<Self, ProfileRunError> {
        validate_text(executable, "executable")?;
        for argument in arguments {
            validate_text(argument, "argument")?;
        }
        validate_digest(environment_digest, "environment_digest")?;
        if !exit.is_admissible() {
            return Err(ProfileRunError::InvalidExitOutcome {
                disposition: format!("{:?}", exit.disposition),
            });
        }
        Ok(Self {
            executable: executable.to_owned(),
            arguments: arguments.to_vec(),
            environment_digest: environment_digest.to_owned(),
            exit,
        })
    }

    /// Canonical digest over the whole retained tool identity.
    ///
    /// Two retained payloads that differ in any bound dimension — executable,
    /// arguments, environment projection, or exit outcome — never share it.
    #[must_use]
    pub fn digest(&self) -> String {
        let mut material = format!(
            "{}\0{}\0{}\0",
            self.executable,
            self.environment_digest,
            self.exit.digest()
        );
        for argument in &self.arguments {
            material.push('\0');
            material.push_str(argument);
        }
        sha256_hex(material.as_bytes())
    }
}

/// Target-layout evidence recorded for one launched stage (issue #1806).
///
/// Resolved configuration (layout revision, build class from the admitted
/// stage kind) stays separate from observed filesystem use (working
/// directory and output roots sealed from the launch request). Workspace
/// and checkout identities are recorded only when issued to this boundary;
/// they are never inferred from branch names, paths, or caller strings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageTargetLayout {
    /// Layout derivation revision in force at launch.
    pub layout_revision: u32,
    /// Build class selected from the admitted stage kind, when the kind
    /// has a dedicated class.
    pub build_class: Option<BuildClass>,
    /// Workspace identity, when issued to this boundary.
    pub workspace_id: Option<String>,
    /// Checkout (worktree) identity, when issued to this boundary.
    pub checkout_id: Option<String>,
    /// Working directory sealed from the launch request.
    pub working_directory_observed: String,
    /// `CARGO_TARGET_DIR` sealed from the launch request, when carried.
    pub target_root_observed: Option<String>,
    /// `CARGO_HOME` sealed from the launch request, when carried.
    pub cache_root_observed: Option<String>,
}

impl StageTargetLayout {
    /// Seals the layout evidence for one launched stage.
    ///
    /// Workspace and checkout identities are not issued to this boundary, so
    /// they stay explicitly absent: a declared but never-issued identity is
    /// never inferred from branch names, paths, or caller strings.
    #[must_use]
    pub fn sealed(planned: &PlannedStage, receipt: &InstrumentStartReceipt) -> Self {
        Self {
            layout_revision: TARGET_LAYOUT_REVISION,
            build_class: planned.stage.build_class(),
            workspace_id: None,
            checkout_id: None,
            working_directory_observed: receipt.working_directory.clone(),
            target_root_observed: receipt.target_root_observed.clone(),
            cache_root_observed: receipt.cache_root_observed.clone(),
        }
    }
}

/// Exact profile/spec/parser admission for a bounded pure transform.
///
/// This is copied from the compiled stage and carries no process grant or
/// executable identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PureTransformAdmission {
    /// Exact registered profile.
    pub profile: String,
    /// Exact profile revision.
    pub profile_revision: u64,
    /// Durable stage identity.
    pub stage_id: String,
    /// Existing registered transform identity.
    pub instrument: String,
    /// Exact transform contract digest.
    pub spec_digest: String,
    /// Exact registered parser identity.
    pub parser: String,
    /// Exact parser generation.
    pub parser_generation: u64,
}

impl PureTransformAdmission {
    fn from_stage(stage: &AdmittedStage) -> Self {
        Self {
            profile: stage.profile.clone(),
            profile_revision: stage.profile_revision,
            stage_id: stage.stage_id.clone(),
            instrument: stage.spec.as_str().to_owned(),
            spec_digest: stage.spec_digest.clone(),
            parser: stage.parser.as_str().to_owned(),
            parser_generation: stage.parser_generation,
        }
    }

    /// Deterministic identity over the retained pure admission fields.
    pub fn digest(&self) -> String {
        sha256_hex(
            format!(
                "{}\0{}\0{}\0{}\0{}\0{}\0{}",
                self.profile,
                self.profile_revision,
                self.stage_id,
                self.instrument,
                self.spec_digest,
                self.parser,
                self.parser_generation,
            )
            .as_bytes(),
        )
    }
}

/// One durable run record per stage (I16.17).
///
/// The record binds the durable [`StageIdentity`], the owning plane, the
/// execution axis, the raw evidence handle, and the machine-derived
/// executable digest. It carries no semantic verdict and no completion claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstrumentRun {
    /// Durable stage identity; the operation binds at launch.
    pub stage: StageIdentity,
    /// Runtime class that owns the stage.
    pub plane: ModuleRuntimeClass,
    /// Whether live `testd` can dispatch the stage class.
    pub testd_dispatchable: bool,
    /// Execution axis only; no semantic result is inferred.
    pub execution: ExecutionStatus,
    /// Raw evidence state.
    pub evidence: StageEvidence,
    /// Machine-derived executable identity digest, when observed.
    pub executable_digest: Option<String>,
    /// Process grant digest sealed by pre-launch admission, when admitted.
    ///
    /// The digest binds the matched spec revision, profile revision, and
    /// parser generation (I10.8.3): a run that never passed admission
    /// carries no grant. It travels into the aggregate digest so a changed
    /// executable/argument combination can never reuse an earlier receipt.
    pub grant_digest: Option<String>,
    /// Original validated external admission data, retained unchanged.
    pub admission_grant: Option<InstrumentAdmissionGrant>,
    /// Distinct process-free admission for pure in-process transforms.
    pub pure_admission: Option<PureTransformAdmission>,
    /// Candidate/configuration identity inherited from the stage plan, when
    /// this run belongs to a candidate-bound plan.
    pub candidate_identity: Option<String>,
    /// Target-layout evidence sealed at launch, when the stage launched.
    pub target_layout: Option<StageTargetLayout>,
}

impl InstrumentRun {
    /// Records a successful admitted in-process transform while preserving
    /// its raw input lineage. This record intentionally has neither an
    /// executor operation identity nor process grant/executable fields.
    fn transformed_in_plan(
        route: &TestExecutionPlaneRoute,
        input: &PureTransformInput,
        result_bytes: Vec<u8>,
        plan: &StagePlan,
    ) -> Self {
        let planned = plan.stages.iter().find(|planned| {
            planned.route.stage().profile == route.stage().profile
                && planned.route.stage().profile_revision == route.stage().profile_revision
                && planned.route.stage().stage_id == route.stage().stage_id
        });
        let Some(planned) = planned else {
            return Self::missing(route, "transformed stage does not belong to the bound plan");
        };
        if !matches!(planned.stage.execution, StageExecution::Pure { .. }) {
            return Self::missing(route, "transformed stage has no pure admission");
        }
        let pure_admission = PureTransformAdmission::from_stage(&planned.stage);
        let mut run = Self {
            stage: route.stage().clone(),
            plane: ModuleRuntimeClass::DerivedIndex,
            testd_dispatchable: false,
            execution: ExecutionStatus::Succeeded,
            evidence: StageEvidence::Transformed {
                source_artifact: input.source_artifact.clone(),
                source_byte_len: input.source_byte_len,
                source_sha256: input.source_sha256.clone(),
                source_revision: input.source_revision,
                result_digest: sha256_hex(&result_bytes),
                result_bytes,
            },
            executable_digest: None,
            grant_digest: None,
            admission_grant: None,
            pure_admission: Some(pure_admission),
            candidate_identity: plan.candidate_identity.clone(),
            target_layout: None,
        };
        run.candidate_identity.clone_from(&plan.candidate_identity);
        run
    }

    /// Records a launched stage whose terminal observation is still owned by
    /// the supervising lane.
    ///
    /// `target_layout` carries the layout evidence sealed at launch; a stage
    /// that launched without it records no layout claim.
    ///
    /// A malformed sealed operation identity fails closed into an explicit
    /// missing proof instead of an unbound launched run.
    pub fn launched(
        route: &TestExecutionPlaneRoute,
        operation_id: String,
        grant: &InstrumentAdmissionGrant,
        target_layout: Option<StageTargetLayout>,
    ) -> Self {
        Self::launched_observed(
            route,
            operation_id,
            grant,
            grant.content_digest.as_str(),
            target_layout,
        )
        .unwrap_or_else(|reason| Self::missing(route, reason))
    }

    /// Records a launched stage whose executable identity was OBSERVED by the
    /// launching lane (issue #1914, external audit 5918718113 — see also
    /// AUD4's "launched no admitted stage; no tool identity was observed").
    ///
    /// `observed_executable_digest` must be the digest this run measured over
    /// the exact executable bytes it admitted and launched. That measurement
    /// already exists upstream: `ExecutableObservation::observe_from_intent`
    /// re-hashes the executable at
    /// `Path::new(intent.executable())` and REFUSES unless the recomputed digest
    /// equals `intent.executable_sha256()`, so the value reaching this
    /// constructor is a machine observation of the bytes that ran, not a
    /// declared, planned or requested identity.
    ///
    /// Why this constructor exists: the run's `executable_digest` used to be
    /// taken from `grant.content_digest`, so whether a launched stage counted as
    /// identified depended on the GRANT's shape rather than on anything this run
    /// observed. `require_launched_stage` counts
    /// `runs.iter().filter(|run| run.executable_digest.is_some())`, so a route
    /// that genuinely launched every stage could still be refused as having
    /// "launched no admitted stage". The identity is now bound to the launch
    /// observation itself.
    ///
    /// The digest is still VALIDATED rather than trusted for its spelling, and a
    /// malformed observation fails closed into an explicit missing proof instead
    /// of a launched run claiming an identity no producer observed. The grant
    /// remains recorded as `grant_digest`; a grant whose `content_digest`
    /// disagrees with the observation is refused rather than preferred, because
    /// the observation is the later, measured fact.
    fn launched_observed(
        route: &TestExecutionPlaneRoute,
        operation_id: String,
        grant: &InstrumentAdmissionGrant,
        observed_executable_digest: &str,
        target_layout: Option<StageTargetLayout>,
    ) -> Result<Self, String> {
        validate_digest(observed_executable_digest, "observed executable identity")
            .map_err(|error| format!("launched stage identity is unverified: {error}"))?;
        if !observed_executable_digest.is_empty()
            && !grant.content_digest.is_empty()
            && grant.content_digest != observed_executable_digest
        {
            return Err(
                "launched stage identity differs from the sealed grant; the executable changed between admission and launch"
                    .to_owned(),
            );
        }
        let Ok(stage) = route.stage().clone().bound(operation_id) else {
            return Err("sealed operation identity is malformed".to_owned());
        };
        Ok(Self {
            stage,
            plane: TestExecutionPlaneRoute::plane(),
            testd_dispatchable: route.dispatchable_via_testd(),
            execution: ExecutionStatus::Accepted,
            evidence: StageEvidence::Omitted {
                reason: "launched; terminal observation is owned by the supervising lane"
                    .to_owned(),
            },
            executable_digest: Some(observed_executable_digest.to_owned()),
            grant_digest: Some(grant.grant_digest.clone()),
            admission_grant: Some(grant.clone()),
            pure_admission: None,
            candidate_identity: None,
            target_layout,
        })
    }

    /// Records a launched stage bound to its plan identity from birth (I10.8.4).
    ///
    /// The route's durable triple must belong to `plan`: a launched run for a
    /// foreign profile, revision, or stage fails closed into an explicit
    /// missing proof instead of a receipt that could satisfy another plan's
    /// aggregate. The plan's candidate identity binds at construction, so the
    /// same admitted profile observed through two entry points carries the
    /// same revision, executable identity, and aggregate membership instead
    /// of acquiring it by later mutation. Missing runs stay missing: this
    /// constructor never converts an unobserved stage into a launched one.
    pub fn launched_in_plan(
        route: &TestExecutionPlaneRoute,
        operation_id: String,
        grant: &InstrumentAdmissionGrant,
        observed_executable_digest: &str,
        target_layout: Option<StageTargetLayout>,
        plan: &StagePlan,
    ) -> Self {
        let belongs = plan.stages.iter().any(|planned| {
            planned.route.stage().profile == route.stage().profile
                && planned.route.stage().profile_revision == route.stage().profile_revision
                && planned.route.stage().stage_id == route.stage().stage_id
        });
        if !belongs {
            return Self::missing(route, "launched stage does not belong to the bound plan");
        }
        let mut run = match Self::launched_observed(
            route,
            operation_id,
            grant,
            observed_executable_digest,
            target_layout,
        ) {
            Ok(run) => run,
            Err(reason) => return Self::missing(route, reason),
        };
        run.candidate_identity.clone_from(&plan.candidate_identity);
        run
    }

    /// Records an explicit missing proof for a stage that never ran.
    pub fn missing(route: &TestExecutionPlaneRoute, reason: impl Into<String>) -> Self {
        Self {
            stage: route.stage().clone(),
            plane: TestExecutionPlaneRoute::plane(),
            testd_dispatchable: route.dispatchable_via_testd(),
            execution: ExecutionStatus::Unknown,
            evidence: StageEvidence::Missing {
                reason: reason.into(),
            },
            executable_digest: None,
            grant_digest: None,
            admission_grant: None,
            pure_admission: None,
            candidate_identity: None,
            target_layout: None,
        }
    }

    /// Finalizes one launched stage whose supervising lane retained the exact
    /// raw bytes under an immutable artifact handle.
    ///
    /// The sealed `tool` identity, the admission `grant`, and the
    /// `executable_digest` are observations the supervising lane made at
    /// launch and termination; this constructor records them without
    /// inventing a launch, a command, or an exit outcome. A malformed
    /// operation identity or executable digest is refused instead of
    /// recorded, so no retained handle can claim an identity no producer
    /// observed.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileRunError::InvalidText`] for a malformed operation
    /// identity or executable digest.
    #[allow(clippy::too_many_arguments)]
    pub fn finalize_retained(
        route: &TestExecutionPlaneRoute,
        operation_id: String,
        grant: &InstrumentAdmissionGrant,
        target_layout: Option<StageTargetLayout>,
        artifact: eliot_contracts::ArtifactId,
        byte_len: u64,
        tool: RetainedToolIdentity,
        executable_digest: String,
    ) -> Result<Self, ProfileRunError> {
        validate_text(&executable_digest, "executable_digest")?;
        let stage = route.stage().clone().bound(operation_id)?;
        Ok(Self {
            stage,
            plane: TestExecutionPlaneRoute::plane(),
            testd_dispatchable: route.dispatchable_via_testd(),
            execution: ExecutionStatus::Succeeded,
            evidence: StageEvidence::Retained {
                artifact,
                byte_len,
                tool,
            },
            executable_digest: Some(executable_digest),
            grant_digest: Some(grant.grant_digest.clone()),
            admission_grant: Some(grant.clone()),
            pure_admission: None,
            candidate_identity: None,
            target_layout,
        })
    }

    /// Whether the run may count toward a successful aggregate.
    ///
    /// Success requires successful execution, retained raw evidence, and an
    /// observed executable identity. Anything else stays visible in the
    /// aggregate instead of collapsing into success.
    pub fn is_success(&self) -> bool {
        if self.execution != ExecutionStatus::Succeeded {
            return false;
        }
        match &self.evidence {
            StageEvidence::Retained { .. } => {
                self.executable_digest.is_some()
                    && self.admission_grant.as_ref().is_some_and(|grant| {
                        Some(grant.grant_digest.as_str()) == self.grant_digest.as_deref()
                            && grant.digest() == grant.grant_digest
                            && grant.max_concurrency > 0
                    })
                    && self.pure_admission.is_none()
            }
            StageEvidence::Transformed {
                source_byte_len,
                source_sha256,
                source_revision,
                result_bytes,
                result_digest,
                ..
            } => {
                self.stage.operation_id.is_none()
                    && self.plane == ModuleRuntimeClass::DerivedIndex
                    && !self.testd_dispatchable
                    && self.executable_digest.is_none()
                    && self.grant_digest.is_none()
                    && self.admission_grant.is_none()
                    && self.pure_admission.as_ref().is_some_and(|admission| {
                        admission.profile == self.stage.profile
                            && admission.profile_revision == self.stage.profile_revision
                            && admission.stage_id == self.stage.stage_id
                            && validate_digest(&admission.spec_digest, "pure spec digest").is_ok()
                            && !admission.parser.trim().is_empty()
                            && admission.parser_generation > 0
                    })
                    && self.target_layout.is_none()
                    && *source_byte_len > 0
                    && *source_revision > 0
                    && validate_digest(source_sha256, "source_sha256").is_ok()
                    && result_digest == &sha256_hex(result_bytes)
            }
            StageEvidence::Omitted { .. } | StageEvidence::Missing { .. } => false,
        }
    }
}

/// Aggregate status over one profile run.
///
/// Missing or failed required stages dominate: they can never be represented
/// as [`AggregateStatus::Succeeded`].
///
/// The status serializes with its persisted profile-run record (issue #1802,
/// I18.6 step 9) under the same screaming wire case as the execution axis, so
/// a renamed status fails readback instead of decoding as another outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AggregateStatus {
    /// Every required stage succeeded and every optional stage succeeded.
    Succeeded,
    /// Every required stage succeeded; an optional stage did not.
    PartialFailure,
    /// A required stage failed, was cancelled, or was blocked.
    Failed,
    /// A required stage has no evidence: unavailable, refused, or unobserved.
    MissingRequired,
    /// A required stage has not reached a terminal successful state.
    Unknown,
}

/// Aggregate profile result retaining every per-stage state (I10.8.4).
///
/// Assembly is total over the declared plan: declared stages without an
/// observed run become explicit [`StageEvidence::Missing`] runs, so an
/// unavailable or failed required stage remains visible and the aggregate
/// can never represent it as successful.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileAggregate {
    /// Admitted profile name.
    pub profile: String,
    /// Exact admitted revision.
    pub revision: u64,
    /// Profile definition digest.
    pub profile_digest: String,
    /// Stage DAG digest.
    pub dag_digest: String,
    /// Candidate/configuration identity inherited from the plan, when bound.
    pub candidate_identity: Option<String>,
    /// Aggregate digest over definition plus ordered runs.
    pub aggregate_digest: String,
    /// Per-stage runs in plan order.
    pub runs: Vec<InstrumentRun>,
    /// Aggregate status; never successful over missing/failed required work.
    pub status: AggregateStatus,
}

impl ProfileAggregate {
    /// Assembles the aggregate over observed runs in plan order.
    ///
    /// Runs are matched to declared stages by the full durable stage
    /// identity (`profile`, `profile_revision`, `stage_id`): a run recorded
    /// for another profile or revision never satisfies this plan, even when
    /// the stage identities coincide. Extra runs for undeclared stages are
    /// ignored, and declared stages without a run become explicit missing
    /// proofs.
    pub fn assemble(plan: &StagePlan, runs: Vec<InstrumentRun>) -> Self {
        let mut observed = BTreeMap::new();
        for run in runs {
            if run.candidate_identity != plan.candidate_identity {
                continue;
            }
            observed
                .entry((
                    run.stage.profile.clone(),
                    run.stage.profile_revision,
                    run.stage.stage_id.clone(),
                ))
                .or_insert(run);
        }
        let mut ordered = Vec::with_capacity(plan.stages.len());
        for planned in &plan.stages {
            let key = (
                plan.profile.clone(),
                plan.revision,
                planned.route.stage().stage_id.clone(),
            );
            if let Some(run) = observed.remove(&key) {
                ordered.push(run);
            } else {
                let mut missing =
                    InstrumentRun::missing(&planned.route, "stage has no observed run");
                missing
                    .candidate_identity
                    .clone_from(&plan.candidate_identity);
                ordered.push(missing);
            }
        }
        let status = aggregate_status(plan, &ordered);
        let mut material = format!(
            "{}\0{}\0{}\0{}\0",
            plan.profile, plan.revision, plan.profile_digest, plan.dag_digest,
        );
        if let Some(candidate_identity) = &plan.candidate_identity {
            material.push_str(candidate_identity);
            material.push('\0');
        }
        for run in &ordered {
            material.push_str(&run.stage.digest());
            material.push('\0');
            let _ = write!(material, "{:?}", run.execution);
            material.push('\0');
            match &run.evidence {
                StageEvidence::Retained {
                    artifact,
                    byte_len,
                    tool,
                } => {
                    material.push_str(artifact.as_str());
                    material.push('\0');
                    material.push_str(&byte_len.to_string());
                    // The retained tool identity is part of the aggregate
                    // digest: the same bytes produced by a different
                    // executable, argument vector, environment projection, or
                    // exit outcome are a different piece of evidence.
                    material.push('\0');
                    material.push_str(&tool.digest());
                }
                StageEvidence::Transformed {
                    source_artifact,
                    source_byte_len,
                    source_sha256,
                    source_revision,
                    result_bytes,
                    result_digest,
                } => {
                    material.push_str(source_artifact.as_str());
                    material.push('\0');
                    material.push_str(&source_byte_len.to_string());
                    material.push('\0');
                    material.push_str(source_sha256);
                    material.push('\0');
                    material.push_str(&source_revision.to_string());
                    material.push('\0');
                    material.push_str(result_digest);
                    material.push('\0');
                    // Hash the bytes again while aggregating so a stale or
                    // caller-edited digest cannot hide a changed result.
                    material.push_str(&sha256_hex(result_bytes));
                }
                StageEvidence::Omitted { reason } | StageEvidence::Missing { reason } => {
                    material.push_str(reason);
                }
            }
            material.push('\0');
            material.push_str(run.executable_digest.as_deref().unwrap_or(""));
            material.push('\0');
            material.push_str(run.grant_digest.as_deref().unwrap_or(""));
            material.push('\0');
            material.push_str(
                &run.admission_grant
                    .as_ref()
                    .map(InstrumentAdmissionGrant::digest)
                    .unwrap_or_default(),
            );
            material.push('\0');
            material.push_str(
                &run.pure_admission
                    .as_ref()
                    .map(PureTransformAdmission::digest)
                    .unwrap_or_default(),
            );
            material.push('\0');
        }
        Self {
            profile: plan.profile.clone(),
            revision: plan.revision,
            profile_digest: plan.profile_digest.clone(),
            dag_digest: plan.dag_digest.clone(),
            candidate_identity: plan.candidate_identity.clone(),
            aggregate_digest: sha256_hex(material.as_bytes()),
            runs: ordered,
            status,
        }
    }

    /// Whether the aggregate represents fully successful verification.
    pub const fn is_success(&self) -> bool {
        matches!(self.status, AggregateStatus::Succeeded)
    }
}

/// Computes the aggregate status with required-stage dominance.
///
/// A missing required stage dominates a failed one, which dominates an
/// unknown one; optional stages can only downgrade success to partial
/// failure, never the reverse.
fn aggregate_status(plan: &StagePlan, runs: &[InstrumentRun]) -> AggregateStatus {
    let mut required_failure: Option<AggregateStatus> = None;
    for (planned, run) in plan.stages.iter().zip(runs.iter()) {
        if !planned.stage.required || run.is_success() {
            continue;
        }
        let failure = if run.evidence.is_missing() {
            AggregateStatus::MissingRequired
        } else if matches!(
            run.execution,
            ExecutionStatus::Failed | ExecutionStatus::Cancelled | ExecutionStatus::Blocked
        ) {
            AggregateStatus::Failed
        } else {
            AggregateStatus::Unknown
        };
        let worse = match required_failure {
            None => true,
            Some(current) => status_rank(failure) > status_rank(current),
        };
        if worse {
            required_failure = Some(failure);
        }
    }
    if let Some(failure) = required_failure {
        return failure;
    }
    let optional_failure = plan
        .stages
        .iter()
        .zip(runs.iter())
        .any(|(planned, run)| !planned.stage.required && !run.is_success());
    if optional_failure {
        AggregateStatus::PartialFailure
    } else {
        AggregateStatus::Succeeded
    }
}

/// Dominance rank for required-stage failures.
const fn status_rank(status: AggregateStatus) -> u8 {
    match status {
        AggregateStatus::MissingRequired => 3,
        AggregateStatus::Failed => 2,
        AggregateStatus::Unknown => 1,
        AggregateStatus::PartialFailure | AggregateStatus::Succeeded => 0,
    }
}

/// Deterministic stage-DAG orchestration over the existing runner.
///
/// Planning expands the admitted DAG; launching walks it in topological
/// order through [`InstrumentRunner::launch`]. Dependent stages of a stage
/// that never launched are recorded as blocked missing proofs instead of
/// launching against absent prerequisites. Independent stages always launch:
/// one failure never discards an unrelated sibling.
pub struct StageOrchestrator;

impl StageOrchestrator {
    /// Expands an admitted profile into a deterministic stage plan.
    ///
    /// Identities reuse admission-validated values, so planning is total:
    /// the same admission always yields the same plan.
    pub fn plan(admitted: &AdmittedProfile) -> StagePlan {
        let stages = admitted
            .stages
            .iter()
            .map(|stage| {
                let identity = StageIdentity {
                    profile: admitted.name.clone(),
                    profile_revision: admitted.revision,
                    stage_id: stage.stage_id.clone(),
                    operation_id: None,
                };
                PlannedStage {
                    route: TestExecutionPlaneRoute::route(identity, stage.kind, stage.external),
                    stage: stage.clone(),
                    resolution: None,
                }
            })
            .collect();
        StagePlan {
            profile: admitted.name.clone(),
            revision: admitted.revision,
            registry_generation: admitted.registry_generation,
            registry_digest: admitted.registry_digest.clone(),
            profile_digest: admitted.profile_digest.clone(),
            dag_digest: admitted.dag_digest.clone(),
            candidate_identity: None,
            stages,
        }
    }

    /// Binds a compiled profile plan to its exact caller-resolved scope, roots,
    /// environment, and registry identity. External admission requires this
    /// retained resolution and never reconstructs it from a ProcessRequest.
    pub fn plan_resolved(
        admitted: &AdmittedProfile,
        resolved: &ResolvedProfile,
    ) -> Result<StagePlan, crate::profile::ProfileError> {
        if admitted.name != resolved.name
            || admitted.revision != resolved.revision
            || admitted.registry_generation != resolved.registry_generation
            || admitted.registry_digest != resolved.registry_digest
            || admitted.profile_digest != resolved.profile_digest
            || admitted.dag_digest != resolved.dag_digest
            || admitted.stages.len() != resolved.stages.len()
        {
            return Err(crate::profile::ProfileError::Snapshot {
                detail: "resolved profile differs from the exact compiled admission".to_owned(),
            });
        }
        for (admitted_stage, resolved_stage) in admitted.stages.iter().zip(&resolved.stages) {
            if admitted_stage.stage_id != resolved_stage.stage_id
                || admitted_stage.spec != resolved_stage.spec
                || admitted_stage.kind != resolved_stage.kind
                || admitted_stage.required != resolved_stage.required
                || admitted_stage.external != resolved_stage.external
                || admitted_stage.depends_on != resolved_stage.depends_on
            {
                return Err(crate::profile::ProfileError::Snapshot {
                    detail: "resolved stage differs from the exact compiled admission".to_owned(),
                });
            }
        }
        let mut plan = Self::plan(admitted);
        for planned in &mut plan.stages {
            planned.resolution = Some(resolved.clone());
        }
        Ok(plan)
    }

    /// Launches every planned stage in topological order.
    ///
    /// The walk is total: launch, admission, and invocation failures become
    /// explicit missing runs, and dependents of a stage that never launched
    /// become blocked missing proofs. Terminal observation and evidence
    /// retention stay with the supervising lane; this walk never holds an
    /// ordering slot while a tool runs.
    pub async fn launch_plan<E: ProcessExecutor + 'static>(
        runner: &InstrumentRunner<E>,
        plan: &StagePlan,
        launcher: &dyn StageLauncher,
    ) -> Vec<InstrumentRun> {
        Self::launch_all(
            runner,
            None,
            plan,
            launcher,
            &UnprovisionedAdmissionProofPort,
        )
        .await
    }

    /// Launches every planned stage with new admission checked against the
    /// live registry.
    ///
    /// The plan must have been compiled against exactly this registry
    /// generation: a plan from a replaced generation records every stage as
    /// missing instead of launching under revoked admission. Each stage then
    /// admits through [`AdmittedStage::admit_live`], so a spec, parser,
    /// supply-chain receipt, or route replaced after compilation fails closed
    /// here without rewriting historical run evidence.
    pub async fn launch_plan_live<E: ProcessExecutor + 'static>(
        runner: &InstrumentRunner<E>,
        registry: &InstrumentRegistry,
        plan: &StagePlan,
        launcher: &dyn StageLauncher,
        proof: &dyn AdmissionSubmissionProofPort,
    ) -> Vec<InstrumentRun> {
        Self::launch_plan_live_with_proof(runner, registry, plan, launcher, proof).await
    }

    /// Launches a profile plan using an explicitly composition-retained
    /// registry owner proof port. This lets a runtime keep its authenticated
    /// proof provider at construction while a stage launcher supplies only
    /// per-stage invocation, request, and evidence provisions.
    pub async fn launch_plan_live_with_proof<E: ProcessExecutor + 'static>(
        runner: &InstrumentRunner<E>,
        registry: &InstrumentRegistry,
        plan: &StagePlan,
        launcher: &dyn StageLauncher,
        proof: &dyn AdmissionSubmissionProofPort,
    ) -> Vec<InstrumentRun> {
        if plan.registry_generation != registry.generation()
            || plan.registry_digest != registry.digest()
        {
            return plan
                .stages
                .iter()
                .map(|planned| {
                    let mut run = InstrumentRun::missing(
                        &planned.route,
                        "stage plan was compiled against a different registry generation",
                    );
                    run.candidate_identity.clone_from(&plan.candidate_identity);
                    run
                })
                .collect();
        }
        Self::launch_all(runner, Some(registry), plan, launcher, proof).await
    }

    /// Launches one already-bound external stage through the same live
    /// registry and original-registration proof gate used by profile walks.
    ///
    /// This is the narrow single-stage entry for existing application edges
    /// that already own a typed invocation and a Kernel-sealed request. The
    /// stage schema, executable receipt, live generation, and persisted
    /// registration readback remain the same admission path as
    /// [`Self::launch_plan_live`].
    pub async fn launch_admitted_stage_live<E: ProcessExecutor + 'static>(
        runner: &InstrumentRunner<E>,
        registry: &InstrumentRegistry,
        planned: &PlannedStage,
        binding: &mut InstrumentBinding,
        proof: &dyn AdmissionSubmissionProofPort,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<InstrumentStartReceipt, RunnerError> {
        let admitted = Self::admit_stage_live(registry, planned, binding, proof).await?;
        runner.launch_admitted(binding, &admitted, sink).await
    }

    /// Applies the live external-stage admission gate without starting a
    /// child. The returned opaque grant can be consumed by the runner after
    /// the caller completes any additional owner checks required by its
    /// execution contour.
    pub async fn admit_stage_live(
        registry: &InstrumentRegistry,
        planned: &PlannedStage,
        binding: &InstrumentBinding,
        proof: &dyn AdmissionSubmissionProofPort,
    ) -> Result<AdmittedStageGrant, RunnerError> {
        let process_request = binding
            .process_request
            .as_ref()
            .ok_or(RunnerError::ReceiptMismatch)?;
        Self::admit_stage_request_live(
            registry,
            planned,
            &binding.invocation,
            process_request,
            proof,
        )
        .await
    }

    /// Applies the same live gate to an owner-held, non-cloneable process
    /// request without taking ownership of it. This is the owner pre-start
    /// entry for callers whose consuming executor retains the request.
    pub async fn admit_stage_request_live(
        registry: &InstrumentRegistry,
        planned: &PlannedStage,
        invocation: &InstrumentInvocation,
        process_request: &ProcessRequest,
        proof: &dyn AdmissionSubmissionProofPort,
    ) -> Result<AdmittedStageGrant, RunnerError> {
        let route = &planned.route;
        let resolution = planned
            .resolution
            .as_ref()
            .ok_or(RunnerError::RegistryAdmission(
                eliot_instrument_api::registry::RegistryAdmissionError::Resolution,
            ))?;
        if resolution.name != route.stage().profile
            || resolution.revision != route.stage().profile_revision
            || resolution.registry_generation != registry.generation()
            || resolution.registry_digest != registry.digest()
        {
            return Err(RunnerError::RegistryAdmission(
                eliot_instrument_api::registry::RegistryAdmissionError::Resolution,
            ));
        }
        if !route.external() {
            return Err(RunnerError::Binding(
                TestdPlaneAdmission::refuse_pure_stage(route),
            ));
        }
        if let Some(reason) = Self::invocation_skew_reason(route, &planned.stage, invocation) {
            return Err(RunnerError::Binding(reason));
        }
        process_request
            .validate()
            .map_err(|error| RunnerError::Binding(error.to_string()))?;
        if invocation.declared_scope != resolution.scope.declared_scope
            || process_request.working_directory() != resolution.layout.source_root
            || process_request.fence().authority_epoch() != &resolution.scope.fence.authority_epoch
            || process_request.fence().generation().get()
                != resolution.scope.fence.resource_generation.get()
            || resolution.environment.class != planned.stage.environment_class
            || (planned.stage.environment_class == "isolated-process"
                && (process_request.environment().inheritance()
                    != eliot_process::EnvironmentInheritance::None
                    || !process_request.environment().secret_refs().is_empty()))
        {
            return Err(RunnerError::Binding(
                "ProcessIntent differs from the retained WorkScope, layout, or environment policy"
                    .to_owned(),
            ));
        }
        let limits = process_request.resource_limits();
        if planned
            .stage
            .timeout_ms
            .is_some_and(|ceiling| limits.wall_timeout_ms() > ceiling)
            || planned.stage.max_output_bytes.is_some_and(|ceiling| {
                limits.stdout_bytes() > ceiling || limits.stderr_bytes() > ceiling
            })
        {
            return Err(RunnerError::Binding(
                "ProcessIntent resource limits exceed the admitted stage ceiling".to_owned(),
            ));
        }
        if process_request.operation_id().as_str() != invocation.request.request_id.as_str() {
            return Err(RunnerError::IdentityMismatch);
        }
        let observed = ExecutableObservation::observe_from_intent(process_request.intent(), None)
            .map_err(|error| {
            RunnerError::ExecutableMismatch(format!(
                "stage executable could not be observed: {error}"
            ))
        })?;
        let mut identity = bridge_executor_observation(invocation.instrument.as_str(), observed)
            .map_err(|error| RunnerError::Binding(error.to_string()))?;
        let Some(file_identity) = identity.file_identity else {
            return Err(RunnerError::RegistryAdmission(
                eliot_instrument_api::registry::RegistryAdmissionError::Executable,
            ));
        };
        if process_request.intent().executable_file_identity() != Some(&file_identity) {
            return Err(RunnerError::RegistryAdmission(
                eliot_instrument_api::registry::RegistryAdmissionError::Resolution,
            ));
        }
        identity.tool_version = Self::recorded_tool_version(registry, &planned.stage, &identity)?;
        let submission = prepare_admission_submission(registry, &planned.stage, &identity)
            .map_err(|error| RunnerError::Binding(format!("stage admission refused: {error}")))?;
        let (receipt, original_readback, current_readback) =
            proof.read_admission(&submission).await?;
        AdmissionSubmissionReadback::verify(
            &submission,
            receipt,
            original_readback,
            current_readback,
        )
        .map_err(|error| {
            RunnerError::Binding(format!("canonical registry readback refused: {error}"))
        })?;
        let snapshot = registry
            .persist()
            .map_err(|error| RunnerError::Binding(format!("registry snapshot refused: {error}")))?;
        let snapshot_value = serde_json::to_value(snapshot)
            .map_err(|error| RunnerError::Binding(format!("registry snapshot refused: {error}")))?;
        let snapshot: eliot_instrument_api::registry::InstrumentRegistrySnapshot<
            serde_json::Value,
        > = serde_json::from_value(snapshot_value)
            .map_err(|error| RunnerError::Binding(format!("registry snapshot refused: {error}")))?;
        let observation = eliot_instrument_api::registry::ExternalExecutableObservation {
            canonical_path: identity.canonical_path.clone(),
            executable_file_name: identity.executable_file_name(),
            content_digest: identity.content_digest.clone(),
            file_identity,
            tool_version: identity.tool_version.clone(),
        };
        let pin = eliot_instrument_api::registry::ExternalStagePin {
            profile: route.stage().profile.clone(),
            profile_revision: route.stage().profile_revision,
            stage_id: route.stage().stage_id.clone(),
            registry_generation: snapshot.generation,
        };
        let resolved_execution = eliot_instrument_api::registry::ResolvedExecutionBinding {
            source_root: resolution.layout.source_root.clone(),
            environment_class: resolution.environment.class.clone(),
            environment_digest: resolution.environment.digest.clone(),
            environment_projection: environment_binding(
                resolution.environment.projection.as_ref().ok_or_else(|| {
                    RunnerError::Binding(
                        "resolved profile did not retain its exact environment projection"
                            .to_owned(),
                    )
                })?,
            ),
            declared_scope: resolution.scope.declared_scope.clone(),
            authority_epoch: resolution.scope.fence.authority_epoch.clone(),
            resource_generation: resolution.scope.fence.resource_generation.get(),
        };
        let process_limits = process_request.resource_limits();
        let process_execution = eliot_instrument_api::registry::ProcessExecutionProjection {
            working_directory: process_request.working_directory().to_owned(),
            environment_digest: eliot_process_executor::environment_projection_digest(
                process_request.environment(),
            ),
            environment_projection: environment_binding(process_request.environment()),
            executable_file_identity: process_request
                .intent()
                .executable_file_identity()
                .copied()
                .ok_or(RunnerError::RegistryAdmission(
                    eliot_instrument_api::registry::RegistryAdmissionError::Resolution,
                ))?,
            authority_epoch: process_request.fence().authority_epoch().clone(),
            resource_generation: process_request.fence().generation().get(),
            wall_timeout_ms: process_limits.wall_timeout_ms(),
            stdout_bytes: process_limits.stdout_bytes(),
            stderr_bytes: process_limits.stderr_bytes(),
        };
        let grant = eliot_instrument_api::registry::validate_external_stage(
            &snapshot,
            &pin,
            invocation,
            &observation,
            process_request.argv(),
            &resolved_execution,
            &process_execution,
        )
        .map_err(RunnerError::RegistryAdmission)?;
        if process_request.intent().instrument_admission_digest() != Some(grant.digest().as_str()) {
            return Err(RunnerError::RegistryAdmission(
                eliot_instrument_api::registry::RegistryAdmissionError::Resolution,
            ));
        }
        if let Some(reason) = Self::grant_at_use_skew_reason(
            route,
            &planned.stage,
            &grant,
            &identity,
            process_request,
            resolution,
        ) {
            return Err(RunnerError::Binding(reason));
        }
        Ok(AdmittedStageGrant {
            grant,
            identity,
            binding_seal: admitted_request_seal(invocation, process_request)?,
        })
    }

    /// Consumes a live gate result through the runner's single start path.
    /// The opaque result is bound to this exact invocation/request pair, so an
    /// owner may finish its durable pre-start checks before delegating here.
    pub async fn launch_admitted_stage<E: ProcessExecutor + 'static>(
        runner: &InstrumentRunner<E>,
        binding: &mut InstrumentBinding,
        admitted: &AdmittedStageGrant,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<InstrumentStartReceipt, RunnerError> {
        runner.launch_admitted(binding, admitted, sink).await
    }

    /// Walks one plan in topological order, with the live registry when the
    /// composition root still holds it.
    async fn launch_all<E: ProcessExecutor + 'static>(
        runner: &InstrumentRunner<E>,
        live: Option<&InstrumentRegistry>,
        plan: &StagePlan,
        launcher: &dyn StageLauncher,
        proof: &dyn AdmissionSubmissionProofPort,
    ) -> Vec<InstrumentRun> {
        let mut runs = Vec::with_capacity(plan.stages.len());
        let mut unlaunched: BTreeSet<String> = BTreeSet::new();
        for planned in &plan.stages {
            let route = &planned.route;
            let blocked_by = planned
                .stage
                .depends_on
                .iter()
                .find(|dependency| unlaunched.contains(*dependency));
            if let Some(dependency) = blocked_by {
                let mut run = InstrumentRun::missing(
                    route,
                    format!("blocked by unlaunched dependency '{dependency}'"),
                );
                run.candidate_identity.clone_from(&plan.candidate_identity);
                runs.push(run);
                unlaunched.insert(route.stage().stage_id.clone());
                continue;
            }
            let mut run = Self::launch_one(runner, live, plan, planned, launcher, proof).await;
            run.candidate_identity.clone_from(&plan.candidate_identity);
            if run.evidence.is_missing() {
                unlaunched.insert(route.stage().stage_id.clone());
            }
            runs.push(run);
        }
        runs
    }

    /// Refuses a launcher invocation that skews from the admitted stage.
    ///
    /// The route identity comes from the admitting profile while the stage
    /// carries its own recorded revision: both must agree, and the requested
    /// arguments must equal the admitted fixed template, before the owning
    /// port binds the invocation shape.
    fn invocation_skew_reason(
        route: &TestExecutionPlaneRoute,
        stage: &AdmittedStage,
        invocation: &InstrumentInvocation,
    ) -> Option<&'static str> {
        if invocation.instrument.as_str() != stage.spec.as_str() {
            return Some(
                "stage admission refused: invocation instrument differs from admitted stage",
            );
        }
        if invocation.kind != stage.kind {
            return Some("stage admission refused: invocation kind differs from admitted stage");
        }
        if invocation.profile.as_str() != route.stage().profile.as_str() {
            return Some("stage admission refused: invocation profile differs from admitted stage");
        }
        if route.stage().profile_revision != stage.profile_revision {
            return Some(
                "stage admission refused: route revision differs from admitted stage revision",
            );
        }
        if invocation.arguments != stage.argument_template {
            return Some(
                "stage admission refused: requested arguments differ from the admitted fixed template",
            );
        }
        None
    }

    /// Refuses a sealed grant/request pair that skews from the admitted stage.
    ///
    /// Revalidates the minted grant against the admitted route and stage at
    /// use, carries the observed canonical path, content digest, and supply
    /// receipt into the dispatch permit, and revalidates that same object at
    /// use: the sealed request must name the exact file the owner hashed,
    /// never an unrelated `PATH` resolution that happens to share a name.
    ///
    /// The grant's sealed argv is compared to the admitted VERIFICATION
    /// command, not to the admitted fixed `argument_template`. Those are
    /// deliberately different fields: `argument_template` bounds what a
    /// caller's `InstrumentInvocation.arguments` may be (empty for every
    /// builtin) and is never argv, while `verification_command` is the argv the
    /// stage actually runs. Comparing the grant's argv against the empty
    /// template refused every verification stage at use, which is the same
    /// unbound-argv defect seen from the other side: the check never asked
    /// whether the sealed argv was the one the profile admitted.
    fn grant_at_use_skew_reason(
        route: &TestExecutionPlaneRoute,
        stage: &AdmittedStage,
        grant: &InstrumentAdmissionGrant,
        observed: &ResolvedExecutableIdentity,
        process_request: &ProcessRequest,
        resolution: &ResolvedProfile,
    ) -> Option<String> {
        if grant.profile != route.stage().profile
            || grant.profile_revision != route.stage().profile_revision
        {
            return Some(
                "stage admission refused: grant profile differs from the admitted route".to_owned(),
            );
        }
        if grant.spec_digest != stage.spec_digest
            || grant.parser.as_str() != stage.parser.as_str()
            || grant.parser_generation != stage.parser_generation
            || grant.arguments != stage.verification_command
            || Some(grant.max_concurrency) != stage.max_concurrency
        {
            return Some(
                "stage admission refused: grant differs from the admitted stage".to_owned(),
            );
        }
        // The argv that actually reached the sealed request must be the same
        // admitted command the grant sealed. This is the check that makes the
        // recorded identity an argv/tool identity and not an executable-bytes
        // identity: without it, a stage could be sealed with one argv and
        // receipted under a grant naming another.
        if process_request.argv() != stage.verification_command.as_slice() {
            return Some(
                "stage admission refused: sealed request argv differs from the admitted verification command"
                    .to_owned(),
            );
        }
        let admitted_supply = stage
            .supply_receipt
            .as_ref()
            .map(SupplyChainReceipt::digest)
            .unwrap_or_default();
        if grant.supply_digest != admitted_supply {
            return Some(
                "stage admission refused: grant supply receipt differs from the admitted stage"
                    .to_owned(),
            );
        }
        if grant.executable_path != observed.canonical_path
            || grant.content_digest != observed.content_digest
            || grant.executable_file_identity != observed.file_identity
            || grant.executable_file_identity.is_none()
            || process_request.intent().executable_file_identity()
                != grant.executable_file_identity.as_ref()
        {
            return Some(
                "stage admission refused: grant carries a different executable object than observed"
                    .to_owned(),
            );
        }
        if process_request.executable_sha256() != grant.content_digest.as_str() {
            return Some(
                "stage admission refused: sealed request carries a different executable identity than the grant"
                    .to_owned(),
            );
        }
        if !matches!(
            std::fs::canonicalize(process_request.intent().executable()),
            Ok(canonical) if canonical.to_string_lossy().as_ref() == observed.canonical_path
        ) {
            return Some(
                "stage admission refused: sealed request names a different executable object than the observed identity"
                    .to_owned(),
            );
        }
        if grant.source_root.as_deref() != Some(resolution.layout.source_root.as_str())
            || grant.declared_scope.as_deref() != Some(resolution.scope.declared_scope.as_str())
            || grant.environment_digest.as_deref()
                != Some(
                    eliot_process_executor::environment_projection_digest(
                        process_request.environment(),
                    )
                    .as_str(),
                )
            || grant.authority_epoch.as_ref() != Some(process_request.fence().authority_epoch())
            || grant.resource_generation != Some(process_request.fence().generation().get())
        {
            return Some(
                "stage admission refused: grant differs from the retained execution binding"
                    .to_owned(),
            );
        }
        None
    }

    /// Reuses only the version in the admitted original supply receipt after
    /// the exact current spec, executable filename, bytes, and registry
    /// generation still match that receipt. No caller text or version probe
    /// supplies this value.
    /// Returns the version from the admitted supply receipt after verifying
    /// exact current spec, filename, observed bytes, receipt, and generation.
    ///
    /// The version is never accepted from caller text or probed in a child.
    pub fn recorded_tool_version(
        registry: &InstrumentRegistry,
        stage: &AdmittedStage,
        identity: &ResolvedExecutableIdentity,
    ) -> Result<Option<String>, RunnerError> {
        let spec = registry
            .spec(stage.spec.as_str())
            .ok_or_else(|| RunnerError::Binding("admitted executable spec is absent".to_owned()))?;
        let original = stage.supply_receipt.as_ref().ok_or_else(|| {
            RunnerError::RegistryAdmission(
                eliot_instrument_api::registry::RegistryAdmissionError::Executable,
            )
        })?;
        let current = registry.supply_chain(stage.spec.as_str()).ok_or_else(|| {
            RunnerError::RegistryAdmission(
                eliot_instrument_api::registry::RegistryAdmissionError::Executable,
            )
        })?;
        if spec.digest() != stage.spec_digest
            || original.digest() != current.digest()
            || original.spec_digest != spec.digest()
            || original.generation != registry.generation()
            || original.executable != identity.executable_file_name()
            || original.content_digest != identity.content_digest
        {
            return Err(RunnerError::RegistryAdmission(
                eliot_instrument_api::registry::RegistryAdmissionError::Executable,
            ));
        }
        Ok(original.tool_version.clone())
    }

    /// Binds and launches one stage through the existing runner primitives.
    ///
    /// The pre-launch closure runs in fixed order before any child process
    /// exists: the invocation profile, revision, and exact argument template
    /// are checked against the admitted stage before the owning port binds
    /// the invocation shape into the sealed process request (adapter schema
    /// authority), the executable hash/file identity resolves from the
    /// machine against the intent-sealed digest, the shared admission gate
    /// checks the fixed argument template and executable identity into a
    /// sealed grant (against the live registry through
    /// [`AdmittedStage::admit_live`] when the composition root still holds
    /// it, so a replaced spec, parser, receipt, or route fails closed), the
    /// grant is revalidated against the planned stage, the observed identity,
    /// and the sealed request at use — including that the sealed request
    /// names the same canonical object the owner hashed — and only then does
    /// the runner launch under [`InstrumentRunner::launch_admitted`]. A
    /// changed executable, an unknown identity, or an off-template argument
    /// combination becomes an explicit missing run here instead of a child
    /// process. The tool version comes only from the admitted original supply
    /// receipt, after its spec, file name, bytes, and generation are matched.
    async fn launch_one<E: ProcessExecutor + 'static>(
        runner: &InstrumentRunner<E>,
        live: Option<&InstrumentRegistry>,
        plan: &StagePlan,
        planned: &PlannedStage,
        launcher: &dyn StageLauncher,
        proof: &dyn AdmissionSubmissionProofPort,
    ) -> InstrumentRun {
        let route = &planned.route;
        match (&planned.stage.execution, route.external()) {
            (StageExecution::Pure { .. }, false) => {
                return Self::launch_pure_one(live, plan, planned, launcher, proof).await;
            }
            (StageExecution::External, true) => {}
            _ => {
                return InstrumentRun::missing(
                    route,
                    "stage execution discriminator disagrees with its admitted route",
                );
            }
        }
        let Some(registry) = live else {
            return InstrumentRun::missing(
                route,
                "external stage lacks a live owner registry and persisted admission".to_owned(),
            );
        };
        let invocation = match launcher.invocation(planned) {
            Ok(invocation) => invocation,
            Err(error) => {
                return InstrumentRun::missing(
                    route,
                    format!("stage invocation unavailable: {error}"),
                );
            }
        };
        if let Some(reason) = Self::invocation_skew_reason(route, &planned.stage, &invocation) {
            return InstrumentRun::missing(route, reason);
        }
        let process_request = match launcher.port(planned).bind(&invocation) {
            Ok(request) => request,
            Err(error) => {
                return InstrumentRun::missing(route, format!("stage admission refused: {error}"));
            }
        };
        let mut binding = match InstrumentBinding::from_request(invocation, process_request) {
            Ok(binding) => binding,
            Err(error) => {
                return InstrumentRun::missing(route, format!("stage admission refused: {error}"));
            }
        };
        let admitted = match Self::admit_stage_live(registry, planned, &binding, proof).await {
            Ok(admitted) => admitted,
            Err(error) => {
                return InstrumentRun::missing(route, format!("stage launch failed: {error}"));
            }
        };
        match runner
            .launch_admitted(&mut binding, &admitted, launcher.sink(planned))
            .await
        {
            Ok(receipt) => {
                let operation = receipt.process.operation_id().as_str().to_owned();
                let target_layout = StageTargetLayout::sealed(planned, &receipt);
                // Issue #1914: the run's executable identity is the digest THIS
                // lane observed over the exact bytes it admitted
                // (`observe_from_intent` re-hashed the file and refused on
                // mismatch), not a value copied from the request or the plan.
                InstrumentRun::launched_in_plan(
                    route,
                    operation,
                    &admitted.grant,
                    admitted.identity.content_digest.as_str(),
                    Some(target_layout),
                    plan,
                )
            }
            Err(error) => InstrumentRun::missing(route, format!("stage launch failed: {error}")),
        }
    }

    /// Runs the one registered pure transform through its typed code-owned
    /// handler. It still requires the same live snapshot and persisted owner
    /// receipt/readback as external admission, but never binds a process
    /// request, executor, testd lane, or synthetic executable identity.
    async fn launch_pure_one(
        live: Option<&InstrumentRegistry>,
        plan: &StagePlan,
        planned: &PlannedStage,
        launcher: &dyn StageLauncher,
        proof: &dyn AdmissionSubmissionProofPort,
    ) -> InstrumentRun {
        let route = &planned.route;
        let Some(registry) = live else {
            return InstrumentRun::missing(
                route,
                "pure transform lacks a live owner registry and persisted admission",
            );
        };
        if let Err(error) = planned.stage.refuse_if_revoked(registry) {
            return InstrumentRun::missing(
                route,
                format!("pure transform admission refused: {error}"),
            );
        }
        let Some(spec) = registry.pure_transform(planned.stage.spec.as_str()) else {
            return InstrumentRun::missing(
                route,
                "pure transform is absent from the live registry",
            );
        };
        let StageExecution::Pure { parser_generation } = &planned.stage.execution else {
            return InstrumentRun::missing(
                route,
                "pure transform stage lost its execution discriminator",
            );
        };
        if *parser_generation != spec.parser_generation {
            return InstrumentRun::missing(route, "pure transform parser generation is stale");
        }
        let submission = match prepare_pure_transform_submission(registry, &planned.stage) {
            Ok(submission) => submission,
            Err(error) => {
                return InstrumentRun::missing(
                    route,
                    format!("pure transform admission refused: {error}"),
                );
            }
        };
        let (receipt, original_readback, current_readback) =
            match proof.read_pure_admission(&submission).await {
                Ok(readback) => readback,
                Err(error) => {
                    return InstrumentRun::missing(
                        route,
                        format!("pure transform owner proof unavailable: {error}"),
                    );
                }
            };
        if let Err(error) = AdmissionSubmissionReadback::verify_pure_transform(
            &submission,
            &planned.stage,
            receipt,
            original_readback,
            current_readback,
        ) {
            return InstrumentRun::missing(
                route,
                format!("pure transform canonical registry readback refused: {error}"),
            );
        }
        let input = match launcher.pure_input(planned) {
            Ok(input) => input,
            Err(error) => {
                return InstrumentRun::missing(
                    route,
                    format!("pure transform input is unavailable: {error}"),
                );
            }
        };
        if let Err(error) = input.verify_original_snapshot() {
            return InstrumentRun::missing(
                route,
                format!("pure transform original source proof failed: {error}"),
            );
        }
        if input.source_bytes.len() > spec.max_input_bytes {
            return InstrumentRun::missing(
                route,
                "pure transform raw input exceeds its registered bound",
            );
        }
        if let Err(error) = input.query.validate() {
            return InstrumentRun::missing(
                route,
                format!("pure transform query is invalid: {error}"),
            );
        }
        if input
            .query
            .expected_revision
            .is_some_and(|expected| expected != input.graph_revision)
        {
            return InstrumentRun::missing(
                route,
                "pure transform graph revision differs from the typed query",
            );
        }
        let decoded = match spec.handler {
            PureTransformHandler::ScipGraphQuery => {
                let index = match eliot_instrument_scip::ScipIndex::decode(&input.source_bytes) {
                    Ok(index) => index,
                    Err(error) => {
                        return InstrumentRun::missing(
                            route,
                            format!("registered SCIP transform rejected retained input: {error}"),
                        );
                    }
                };
                match index.graph_result(&input.query, input.graph_revision) {
                    Ok(result) => result,
                    Err(error) => {
                        return InstrumentRun::missing(
                            route,
                            format!("registered SCIP transform failed: {error}"),
                        );
                    }
                }
            }
        };
        let result_bytes = match serde_json::to_vec(&decoded) {
            Ok(bytes) => bytes,
            Err(error) => {
                return InstrumentRun::missing(
                    route,
                    format!("registered pure result could not be encoded: {error}"),
                );
            }
        };
        InstrumentRun::transformed_in_plan(route, &input, result_bytes, plan)
    }
}

impl<E: ProcessExecutor + 'static> InstrumentRunner<E> {
    /// Runs one admitted profile end to end: plan, launch, aggregate.
    ///
    /// This is deterministic orchestration only. Stage commands come solely
    /// from the admitted plan through the caller-supplied [`StageLauncher`];
    /// the returned [`ProfileAggregate`] observes success, partial failure,
    /// missing stages, and evidence handles without declaring any task
    /// complete.
    pub async fn run_profile_stages(
        &self,
        admitted: &AdmittedProfile,
        launcher: &dyn StageLauncher,
    ) -> ProfileAggregate {
        let plan = StageOrchestrator::plan(admitted);
        let runs = StageOrchestrator::launch_plan(self, &plan, launcher).await;
        ProfileAggregate::assemble(&plan, runs)
    }

    /// Runs one admitted profile against the composition root's current
    /// registry and its original persisted registration proof.
    ///
    /// The owner-backed launcher supplies a read-only receipt/readback for
    /// each external stage. Registry-less callers must use
    /// [`Self::run_profile_stages`], whose external stages remain unlaunched.
    pub async fn run_profile_stages_live(
        &self,
        registry: &InstrumentRegistry,
        admitted: &AdmittedProfile,
        resolved: &ResolvedProfile,
        launcher: &dyn StageLauncher,
        proof: &dyn AdmissionSubmissionProofPort,
    ) -> ProfileAggregate {
        self.run_profile_stages_live_with_proof(registry, admitted, resolved, launcher, proof)
            .await
    }

    /// Runs one admitted profile with the owner proof port retained by the
    /// composition root, separate from per-stage launch provisions.
    pub async fn run_profile_stages_live_with_proof(
        &self,
        registry: &InstrumentRegistry,
        admitted: &AdmittedProfile,
        resolved: &ResolvedProfile,
        launcher: &dyn StageLauncher,
        proof: &dyn AdmissionSubmissionProofPort,
    ) -> ProfileAggregate {
        let plan = match StageOrchestrator::plan_resolved(admitted, resolved) {
            Ok(plan) => plan,
            Err(error) => {
                let plan = StageOrchestrator::plan(admitted);
                let runs = plan
                    .stages
                    .iter()
                    .map(|planned| {
                        InstrumentRun::missing(
                            &planned.route,
                            format!("resolved profile refused: {error}"),
                        )
                    })
                    .collect();
                return ProfileAggregate::assemble(&plan, runs);
            }
        };
        let runs =
            StageOrchestrator::launch_plan_live_with_proof(self, registry, &plan, launcher, proof)
                .await;
        ProfileAggregate::assemble(&plan, runs)
    }
}

/// Production [`StageLauncher`] serving composition-root-admitted invocations.
///
/// The composition root admits one typed [`InstrumentInvocation`] per planned
/// stage identity and hands the map to the orchestrator together with its
/// request port and evidence sink. Lookup is exact: a stage without an
/// admitted invocation fails into an explicit missing run through the
/// orchestrator's existing total-walk behavior, never into a synthesized
/// command or a silently skipped stage.
pub struct MappedStageLauncher<'p> {
    invocations: BTreeMap<String, InstrumentInvocation>,
    port: &'p dyn InstrumentRequestPort,
    sink: Arc<dyn ProcessEvidenceSink>,
}

impl<'p> MappedStageLauncher<'p> {
    /// Serves `invocations` through `port`, retaining evidence via `sink`.
    pub fn new(
        invocations: BTreeMap<String, InstrumentInvocation>,
        port: &'p dyn InstrumentRequestPort,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Self {
        Self {
            invocations,
            port,
            sink,
        }
    }
}

impl StageLauncher for MappedStageLauncher<'_> {
    fn invocation(&self, stage: &PlannedStage) -> Result<InstrumentInvocation, RunnerError> {
        let stage_id = stage.route.stage().stage_id.as_str();
        self.invocations.get(stage_id).cloned().ok_or_else(|| {
            RunnerError::Binding(format!("no admitted invocation for stage '{stage_id}'"))
        })
    }

    fn port(&self, _stage: &PlannedStage) -> &dyn InstrumentRequestPort {
        self.port
    }

    fn sink(&self, _stage: &PlannedStage) -> Arc<dyn ProcessEvidenceSink> {
        Arc::clone(&self.sink)
    }
}

/// Production [`TestdAdmissionPort`] behind the test execution plane (I10.8.15).
///
/// External build/test stages resolve through the provider registry first;
/// this admission records which of them live `eliot-testd` can dispatch
/// today. Only [`InstrumentKind::Test`] dispatches: every other class keeps
/// its registry resolution and is reported as the typed
/// [`TestdPortError::UnsupportedByTestd`] refusal instead of failing the plan.
pub struct TestdPlaneAdmission;

impl TestdPlaneAdmission {
    /// Admits one admitted `(instrument, kind)` pair behind the test execution
    /// plane without an invocation.
    ///
    /// This is the exact [`TestdAdmissionPort::admit`] decision over the
    /// admitted stage identity instead of a full provider-neutral invocation,
    /// so classification-only callers (the registry composition in
    /// [`compose_provider_dispatch`); issue #1813 W4: the governed describe
    /// path records per-stage testd admission without execution provisions)
    /// never fabricate invocation authority material such as a State Fence,
    /// session, or lease. The receipt still binds the registry-selected
    /// adapter and generation; only the invocation clone is absent, and no
    /// governed claim may rest on that absence.
    pub fn admit_parts(
        instrument: &eliot_contracts::ContractId,
        kind: InstrumentKind,
        entry: &RegistryEntry,
    ) -> Result<(String, u64), TestdPortError> {
        if entry.instrument.as_str() != instrument.as_str() {
            return Err(TestdPortError::Registry(RegistryError::Missing {
                instrument: instrument.as_str().to_owned(),
                kind,
            }));
        }
        if !entry.supports(kind) {
            return Err(TestdPortError::Registry(RegistryError::Unsupported {
                adapter: entry.adapter.clone(),
                kind,
            }));
        }
        if !testd_dispatchable(kind) {
            return Err(TestdPortError::UnsupportedByTestd { kind });
        }
        Ok((entry.adapter.clone(), entry.generation))
    }

    /// Refuses a pure in-process stage without an explicitly registered pure
    /// implementation (I10.8.4).
    ///
    /// Only an explicitly registered pure implementation may bypass the test
    /// execution plane; no such lane is bound on this path, so the stage
    /// records the returned explicit missing proof instead of escaping
    /// through a generic local command.
    pub fn refuse_pure_stage(route: &TestExecutionPlaneRoute) -> String {
        let _ = route;
        "pure in-process stage bypasses the plane; no in-process lane is bound".to_owned()
    }
}

impl TestdAdmissionPort for TestdPlaneAdmission {
    fn admit(
        &self,
        invocation: &InstrumentInvocation,
        entry: &RegistryEntry,
    ) -> Result<TestdAdmission, TestdPortError> {
        Self::admit_parts(&invocation.instrument, invocation.kind, entry)?;
        Ok(TestdAdmission::new(invocation.clone(), entry))
    }
}

/// The registry-composed dispatch decision for one admitted stage.
///
/// This is the single decision point where the current provider registry,
/// the host's observed platform, and Testd's dispatch capability meet. It
/// runs the whole pre-execution closure — exactly-one-entry resolution,
/// generation and fingerprint freshness, host support, then Testd
/// capability — and every rejection carries a typed
/// [`ProviderDisposition`](crate::ProviderDisposition) so the stage stays
/// counted in the declared denominator. A `Dispatch` decision is a
/// precondition only: it grants no process, no task acceptance, and no
/// Finish.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderDispatch {
    /// The provider resolved, is current, is supported on this host, and is
    /// dispatchable by Testd. The entry carries no process authority.
    Dispatch {
        /// The single current registry entry that owns the stage.
        entry: Box<RegistryEntry>,
    },
    /// The provider was refused. It remains in the declared denominator.
    Refused {
        /// The exact typed reason.
        disposition: crate::ProviderDisposition,
    },
}

impl ProviderDispatch {
    /// The owning entry, only on the dispatch path.
    #[must_use]
    pub fn entry(&self) -> Option<&RegistryEntry> {
        match self {
            Self::Dispatch { entry } => Some(entry),
            Self::Refused { .. } => None,
        }
    }

    /// The typed disposition for this stage.
    #[must_use]
    pub fn disposition(&self) -> crate::ProviderDisposition {
        match self {
            Self::Dispatch { .. } => crate::ProviderDisposition::Ready,
            Self::Refused { disposition } => disposition.clone(),
        }
    }

    /// Whether the stage may be dispatched.
    #[must_use]
    pub const fn is_dispatchable(&self) -> bool {
        matches!(self, Self::Dispatch { .. })
    }
}

/// Composes the current provider registry behind the Testd boundary.
///
/// Runs the whole pre-execution closure in order: exactly-one-entry
/// resolution, generation and fingerprint freshness, host support, then
/// admission of the resolved entry through
/// [`TestdPlaneAdmission::admit_parts`] behind the test execution plane.
/// The closure is total: no rejection is an `Err`, so a missing, duplicate,
/// ambiguous, stale, unsupported, or unmapped provider is reported as a
/// typed [`ProviderDispatch::Refused`] carrying its exact cause rather than
/// an error that could be dropped from a denominator. No process, build
/// root, task, budget, or Finish authority is created here; only Testd
/// dispatches.
///
/// Freshness inputs and the observed platform are supplied by the
/// composition root, which owns the machine observations. A dispatch
/// decision is a precondition only: the caller still has to run the
/// provider and the runner still has to bind a launch-sealed executable
/// identity before any result can take authoritative PASS.
#[must_use]
pub fn compose_provider_dispatch(
    registry: &crate::ProviderRegistry,
    instrument: &eliot_contracts::ContractId,
    kind: InstrumentKind,
    inputs: &crate::AvailabilityInputs<'_>,
) -> ProviderDispatch {
    let available = registry.availability_parts(instrument, kind, inputs);
    if !available.is_available() {
        return ProviderDispatch::Refused {
            disposition: available.disposition(),
        };
    }
    // `availability_parts` already ran the freshness-pinned resolution, so
    // the ready arm is exactly the single current entry it returned.
    let Some(entry) = available.entry() else {
        return ProviderDispatch::Refused {
            disposition: crate::ProviderDisposition::Unmapped,
        };
    };
    match TestdPlaneAdmission::admit_parts(instrument, kind, entry) {
        Ok(_) => ProviderDispatch::Dispatch {
            entry: Box::new(entry.clone()),
        },
        Err(TestdPortError::UnsupportedByTestd { kind }) => ProviderDispatch::Refused {
            disposition: crate::ProviderDisposition::UnsupportedByTestd {
                adapter: entry.adapter.clone(),
                kind,
            },
        },
        Err(TestdPortError::Registry(error)) => ProviderDispatch::Refused {
            disposition: crate::disposition_for_parts(instrument.as_str(), kind, &error),
        },
    }
}
