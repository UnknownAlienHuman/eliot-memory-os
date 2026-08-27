//! Production N4 Governor composition contracts.
//!
//! The daemon owns one value of [`GovernorComposition`].  This module only
//! composes pure Governor projections and the neutral Kernel transition port;
//! it does not open a store, construct a provider adapter, execute a process,
//! or infer readiness from a local fallback.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::{
    Governor, GovernorConfig, GovernorState, QueueLimits, STARTUP_ORDER, ServiceId,
    ServiceObservation,
};
use eliot_authority::{EffectAuthorizer, GrantGraph};
use eliot_canonical::{CanonicalError, CanonicalWriteEnvelope};
use eliot_change_monitor::ChangeMonitor;
use eliot_contracts::{
    AuthorityEpoch, OperationId, RequestMetadata, ResourceGeneration, SessionId, StateFence,
    TaskId, canonical_json_bytes, sha256_hex,
};
use eliot_coordination::CoordinationOwner;
use eliot_finish::{FinishDecisionReceipt, FinishService};
use eliot_maintenance::{
    MaintenanceController, MaintenanceError, MaintenanceJob, MaintenanceStateStore,
};
use eliot_module_registry::ModuleCatalog;
use eliot_module_registry::ModuleCatalogSnapshot;
use eliot_observation::{ObservationJournal, ObservationJournalEntry};
use eliot_session::{SessionLifecycleOwner, SessionLifecycleSnapshot, SessionState};
use eliot_skill::{SkillLifecycleView, SkillRegistry};
use eliot_store_api::{
    OrderingHeadExpectation, PreparedTransition, RevisionHeadExpectation, ScopeRevisionView,
    StoreHealth, WriteReceipt,
};
use eliot_task::{TaskLifecycleOwner, TaskLifecycleSnapshot, TaskState};
use eliot_workscope::{WorkScopeBindingOwner, WorkScopeBindingSnapshot};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

/// The only application write port exposed to the daemon.
///
/// The port accepts a Canonical-produced [`PreparedTransition`] and carries
/// it to the authenticated Kernel generation.  It deliberately does not
/// expose a store client, query surface, provider SDK, or completion API.
pub trait KernelTransitionPort: Send + Sync {
    /// Applies one prepared transition under the exact caller/fence binding.
    fn apply_prepared<'a>(
        &'a self,
        request: &RequestMetadata,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> KernelPortFuture<'a, WriteReceipt>;

    /// Reconciles one operation by its exact canonical identity.
    fn receipt(&self, operation_id: OperationId) -> KernelPortFuture<'_, Option<WriteReceipt>>;

    /// Returns a bounded Kernel-owned health observation.
    fn health(&self) -> KernelPortFuture<'_, StoreHealth>;
}

/// Object-safe future returned by a neutral Kernel transition port.
pub type KernelPortFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, KernelPortError>> + Send + 'a>>;

/// Typed failure at the neutral Kernel port.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum KernelPortError {
    /// The authenticated generation is stale or inconsistent with the request.
    #[error("Kernel generation contract mismatch: {0}")]
    Contract(String),
    /// The Kernel could not establish an outcome at the boundary.
    #[error("Kernel transition outcome is unknown: {0}")]
    Unknown(String),
    /// The authenticated Kernel generation is not currently admitted.
    #[error("Kernel generation is not admitted: {0}")]
    NotAdmitted(String),
}

/// Explicit Kernel-owned recovery route used before Governor readiness.
///
/// The route is deliberately split into closed operations so a production
/// adapter must perform the owner named reads, canonical head read, receipt
/// replay read, and durable-job read.  A digest in launch.json cannot
/// substitute for any one of these operations.
pub trait KernelRecoveryPort: Send + Sync {
    /// Reads one fixed owner projection under the exact fence and handoff.
    fn named_read(
        &self,
        request: KernelNamedReadRequest,
    ) -> Result<Option<KernelNamedReadReply>, KernelPortError>;

    /// Atomically seeds the complete Governor genesis owner set through the
    /// Canonical→Kernel→Store path.  Implementations must return success only
    /// for an idempotent all-absent genesis state; partial/unknown state must
    /// fail closed and never be filled locally.
    fn initialize_governor_genesis(
        &self,
        request: &GovernorGenesisRequest,
    ) -> Result<(), KernelPortError>;

    /// Reads the canonical revision and ordering heads.
    fn canonical_scope(
        &self,
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Result<ScopeRevisionView, KernelPortError>;

    /// Reads terminal receipts used for exact replay/reconciliation.
    fn receipts(
        &self,
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Result<Vec<WriteReceipt>, KernelPortError>;

    /// Reads all durable application jobs and their current revisions.
    fn durable_jobs(
        &self,
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Result<Vec<MaintenanceJob>, KernelPortError>;
}

/// Explicit Kernel-owned service observation route used after owner recovery.
///
/// Service observations are runtime admission evidence, not durable Governor
/// owner state. Keeping this route separate prevents them from being folded
/// into the owner recovery snapshot or its diagnostic digest.
pub trait KernelServiceObservationPort: Send + Sync {
    /// Reads the ordered Governor service observations under the exact fence.
    fn services(
        &self,
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Result<Vec<KernelServiceRecovery>, KernelPortError>;
}

/// Explicit durable-job persistence route retained by the one Maintenance
/// owner.  It is not an in-memory fallback and cannot be replaced by a second
/// scheduler or a direct store adapter in `eliotd`.
pub trait KernelDurableJobPort: Send + Sync {
    /// Loads one exact job identity from the Kernel-owned durable job ledger.
    fn load_durable_job(
        &self,
        job_id: &str,
        state_fence: &StateFence,
    ) -> Result<Option<MaintenanceJob>, KernelPortError>;

    /// Persists one validated job revision in the Kernel-owned durable ledger.
    fn save_durable_job(&self, job: &MaintenanceJob) -> Result<(), KernelPortError>;
}

/// Exact authenticated Kernel snapshot expected by N4.
///
/// `artifact_digest`, `protected_snapshot_digest`, and `principal` are all
/// part of the identity.  Matching only generation/epoch is insufficient for
/// a replaceable local service.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelGenerationSnapshot {
    /// Fixed Kernel service identity.
    pub service: String,
    /// Exact negotiated protocol string.
    pub protocol: String,
    /// Active resource generation.
    pub generation: ResourceGeneration,
    /// Active authority epoch.
    pub authority_epoch: AuthorityEpoch,
    /// SHA-256 of the admitted Kernel artifact.
    pub artifact_digest: String,
    /// SHA-256 of the protected full handoff snapshot.
    pub protected_snapshot_digest: String,
    /// Authenticated Kernel principal identity.
    pub principal: String,
}

impl KernelGenerationSnapshot {
    /// Validates the closed snapshot shape.
    pub fn validate(&self) -> Result<(), KernelPortError> {
        for (value, field) in [
            (&self.service, "service"),
            (&self.protocol, "protocol"),
            (&self.artifact_digest, "artifact_digest"),
            (&self.protected_snapshot_digest, "protected_snapshot_digest"),
            (&self.principal, "principal"),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(KernelPortError::Contract(format!(
                    "{field} must be non-blank and free of controls"
                )));
            }
        }
        for (value, field) in [
            (&self.artifact_digest, "artifact_digest"),
            (&self.protected_snapshot_digest, "protected_snapshot_digest"),
        ] {
            if value.len() != 64
                || value
                    .bytes()
                    .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(KernelPortError::Contract(format!(
                    "{field} must be a lowercase SHA-256 digest"
                )));
            }
        }
        if self.generation.value() == 0 || self.authority_epoch.value() == 0 {
            return Err(KernelPortError::Contract(
                "generation and authority_epoch must be non-zero".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns the exact state fence represented by this snapshot.
    #[must_use]
    pub const fn state_fence(&self) -> StateFence {
        StateFence::new(self.authority_epoch, self.generation)
    }
}

/// Exact snapshot expected from the Host-approved launch handoff.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelGenerationExpectation {
    /// Expected Kernel service identity.
    pub service: String,
    /// Expected negotiated protocol.
    pub protocol: String,
    /// Expected artifact digest.
    pub artifact_digest: String,
    /// Expected protected snapshot digest.
    pub protected_snapshot_digest: String,
    /// Expected authenticated principal.
    pub principal: String,
    /// Expected resource generation.
    pub generation: ResourceGeneration,
    /// Expected authority epoch.
    pub authority_epoch: AuthorityEpoch,
}

impl KernelGenerationExpectation {
    /// Converts an authenticated snapshot into a fixed expectation.
    pub fn from_snapshot(snapshot: &KernelGenerationSnapshot) -> Result<Self, KernelPortError> {
        snapshot.validate()?;
        Ok(Self {
            service: snapshot.service.clone(),
            protocol: snapshot.protocol.clone(),
            artifact_digest: snapshot.artifact_digest.clone(),
            protected_snapshot_digest: snapshot.protected_snapshot_digest.clone(),
            principal: snapshot.principal.clone(),
            generation: snapshot.generation,
            authority_epoch: snapshot.authority_epoch,
        })
    }

    /// Rejects every identity or fence mismatch before composition.
    pub fn admits(&self, observed: &KernelGenerationSnapshot) -> Result<(), KernelPortError> {
        observed.validate()?;
        if self.service != observed.service
            || self.protocol != observed.protocol
            || self.artifact_digest != observed.artifact_digest
            || self.protected_snapshot_digest != observed.protected_snapshot_digest
            || self.principal != observed.principal
            || self.generation != observed.generation
            || self.authority_epoch != observed.authority_epoch
        {
            return Err(KernelPortError::Contract(
                "observed Kernel snapshot does not match Host-approved expectation".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Fixed owner names used for duplicate-owner detection and recovery binding.
pub const OWNER_IDS: [&str; 16] = [
    "work_scope",
    "task",
    "session",
    "canonical",
    "authority",
    "budget",
    "config",
    "coordination",
    "finish",
    "problem",
    "observation",
    "read",
    "skill",
    "module_registry",
    "maintenance",
    "change_monitor",
];

/// Versioned payload schema for every named owner read.
pub const OWNER_SNAPSHOT_SCHEMA: &str = "eliot.governor.owner.snapshot.v1";
/// Bounded payload size accepted from the Kernel recovery route.
pub const MAX_OWNER_SNAPSHOT_BYTES: usize = 512 * 1024;

/// Closed owner selector for Kernel-backed named recovery reads.
///
/// The selector is intentionally not a free-form string.  A Kernel adapter
/// must implement every owner read in this set before the daemon can become
/// ready; an omitted owner is a recovery failure rather than an empty local
/// default.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryOwner {
    /// `WorkScope` projection.
    WorkScope,
    /// Task projection.
    Task,
    /// Session projection.
    Session,
    /// Canonical projection.
    Canonical,
    /// Authority projection.
    Authority,
    /// Budget projection.
    Budget,
    /// Config projection.
    Config,
    /// Coordination projection.
    Coordination,
    /// Finish projection.
    Finish,
    /// Problem projection.
    Problem,
    /// Observation projection.
    Observation,
    /// Read projection.
    Read,
    /// Skill projection.
    Skill,
    /// Module Registry projection.
    ModuleRegistry,
    /// Maintenance projection.
    Maintenance,
    /// Change Monitor projection.
    ChangeMonitor,
}

impl RecoveryOwner {
    /// Every owner in the required exact order.
    pub const ALL: [Self; 16] = [
        Self::WorkScope,
        Self::Task,
        Self::Session,
        Self::Canonical,
        Self::Authority,
        Self::Budget,
        Self::Config,
        Self::Coordination,
        Self::Finish,
        Self::Problem,
        Self::Observation,
        Self::Read,
        Self::Skill,
        Self::ModuleRegistry,
        Self::Maintenance,
        Self::ChangeMonitor,
    ];

    /// Stable wire identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkScope => "work_scope",
            Self::Task => "task",
            Self::Session => "session",
            Self::Canonical => "canonical",
            Self::Authority => "authority",
            Self::Budget => "budget",
            Self::Config => "config",
            Self::Coordination => "coordination",
            Self::Finish => "finish",
            Self::Problem => "problem",
            Self::Observation => "observation",
            Self::Read => "read",
            Self::Skill => "skill",
            Self::ModuleRegistry => "module_registry",
            Self::Maintenance => "maintenance",
            Self::ChangeMonitor => "change_monitor",
        }
    }
}

/// One exact named-read request sent to the authenticated Kernel generation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelNamedReadRequest {
    /// The closed owner being recovered.
    pub owner: RecoveryOwner,
    /// The expected active fence.
    pub state_fence: StateFence,
    /// The protected Kernel handoff digest.
    pub protected_snapshot_digest: String,
}

/// Single idempotent genesis seed request.  The Kernel implementation must
/// submit this through Canonical and persist all owner records atomically; it
/// is not a permission to create individual local defaults.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernorGenesisRequest {
    /// Genesis state fence.
    pub state_fence: StateFence,
    /// Protected Kernel handoff digest.
    pub protected_snapshot_digest: String,
    /// Stable idempotency identity for the seed transaction.
    pub operation_id: OperationId,
    /// Complete owner set that must be created atomically.
    pub owner_ids: Vec<RecoveryOwner>,
}

impl GovernorGenesisRequest {
    fn new(
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Result<Self, CompositionError> {
        let operation_id = OperationId::new(format!(
            "eliotd:governor-genesis:{}:{}",
            state_fence.authority_epoch.value(),
            state_fence.resource_generation.value()
        ))
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        Ok(Self {
            state_fence: state_fence.clone(),
            protected_snapshot_digest: protected_snapshot_digest.to_owned(),
            operation_id,
            owner_ids: RecoveryOwner::ALL.to_vec(),
        })
    }

    fn validate(
        &self,
        expected_fence: &StateFence,
        expected_digest: &str,
    ) -> Result<(), CompositionError> {
        if self.state_fence != *expected_fence
            || self.protected_snapshot_digest != expected_digest
            || !is_sha256(&self.protected_snapshot_digest)
            || self.owner_ids.as_slice() != RecoveryOwner::ALL.as_slice()
        {
            return Err(CompositionError::Recovery(
                "genesis seed request is not the complete exact owner transaction".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Evidence returned by one Kernel-owned named recovery read.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelNamedReadReply {
    /// The owner that was read.
    pub owner: RecoveryOwner,
    /// Fence observed by the Kernel while reading it.
    pub state_fence: StateFence,
    /// Durable owner revision observed by the Kernel.
    pub revision: u64,
    /// Closed schema identifier for the payload bytes.
    pub schema: String,
    /// Exact bounded canonical owner snapshot bytes read by the Kernel.
    pub payload: Vec<u8>,
    /// Digest of the exact canonical owner payload bytes.
    pub value_digest: String,
}

/// One service observation recovered from the Kernel-owned state/control
/// route.  It is used to drive the existing Governor startup state machine;
/// no local observation is fabricated by the daemon.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelServiceRecovery {
    /// Normative Governor service identity.
    pub service: ServiceId,
    /// Exact recovered observation.
    pub observation: ServiceObservation,
}

/// The complete typed result of Kernel recovery required before readiness.
///
/// Every field is provider-owned evidence.  The daemon never constructs this
/// value from the launch config, a protected digest, or an in-memory default.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernorRecoverySnapshot {
    /// Fence under which all reads were performed.
    pub state_fence: StateFence,
    /// Protected Kernel handoff digest used by every read.
    pub protected_snapshot_digest: String,
    /// Exactly one durable named read for each Governor owner.
    pub owner_reads: Vec<KernelNamedReadReply>,
    /// Canonical revision/order heads recovered by the Kernel.
    pub canonical_scope: ScopeRevisionView,
    /// Exact terminal receipts available for operation replay/reconciliation.
    pub receipts: Vec<WriteReceipt>,
    /// Durable application jobs recovered by the Kernel-owned job route.
    pub durable_jobs: Vec<MaintenanceJob>,
}

impl GovernorRecoverySnapshot {
    fn owner_read(&self, owner: RecoveryOwner) -> Result<&KernelNamedReadReply, CompositionError> {
        self.owner_reads
            .iter()
            .find(|read| read.owner == owner)
            .ok_or_else(|| {
                CompositionError::Recovery(format!("missing named read {}", owner.as_str()))
            })
    }

    fn validate(
        &self,
        expected_fence: &StateFence,
        expected_digest: &str,
    ) -> Result<(), CompositionError> {
        self.state_fence
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if &self.state_fence != expected_fence
            || self.protected_snapshot_digest != expected_digest
            || !is_sha256(&self.protected_snapshot_digest)
        {
            return Err(CompositionError::Recovery(
                "Kernel recovery is not bound to the active fence and protected snapshot"
                    .to_owned(),
            ));
        }

        let expected_owners: BTreeSet<RecoveryOwner> = RecoveryOwner::ALL.into_iter().collect();
        let observed_owners: BTreeSet<RecoveryOwner> =
            self.owner_reads.iter().map(|read| read.owner).collect();
        if self.owner_reads.len() != expected_owners.len() || observed_owners != expected_owners {
            return Err(CompositionError::Recovery(
                "Kernel recovery did not return exactly one named read per owner".to_owned(),
            ));
        }
        for read in &self.owner_reads {
            if read.state_fence != *expected_fence
                || read.revision == 0
                || read.schema != OWNER_SNAPSHOT_SCHEMA
                || read.payload.is_empty()
                || read.payload.len() > MAX_OWNER_SNAPSHOT_BYTES
                || !is_sha256(&read.value_digest)
                || sha256_hex(&read.payload) != read.value_digest
            {
                return Err(CompositionError::Recovery(format!(
                    "named read {} has invalid fence, revision, or payload digest",
                    read.owner.as_str()
                )));
            }
        }

        self.canonical_scope
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if self.canonical_scope.state_fence != *expected_fence {
            return Err(CompositionError::Recovery(
                "canonical named read returned a stale state fence".to_owned(),
            ));
        }
        let mut receipt_ids = BTreeSet::new();
        for receipt in &self.receipts {
            receipt
                .validate()
                .map_err(|error| CompositionError::Recovery(error.to_string()))?;
            if receipt.state_fence != *expected_fence
                || !receipt_ids.insert(receipt.operation_id.clone())
            {
                return Err(CompositionError::Recovery(
                    "receipt replay set has a duplicate or stale operation identity".to_owned(),
                ));
            }
        }
        let mut job_ids = BTreeSet::new();
        for job in &self.durable_jobs {
            job.validate()
                .map_err(|error| CompositionError::Recovery(error.to_string()))?;
            if job.state_fence != *expected_fence || !job_ids.insert(job.job_id.clone()) {
                return Err(CompositionError::Recovery(
                    "durable job recovery has a duplicate or stale identity".to_owned(),
                ));
            }
        }

        Ok(())
    }
}

/// Closed payload for a stateless or separately-read owner projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyOwnerSnapshot {
    /// Exact owner fence.
    pub state_fence: StateFence,
    /// Durable owner revision.
    pub revision: u64,
}

impl EmptyOwnerSnapshot {
    fn validate(&self, expected_fence: &StateFence) -> Result<(), CompositionError> {
        if self.state_fence != *expected_fence || self.revision == 0 {
            return Err(CompositionError::Recovery(
                "empty owner snapshot has a stale fence or zero revision".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Config owner payload bound to the exact protected config digest.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigOwnerSnapshot {
    /// Exact owner fence.
    pub state_fence: StateFence,
    /// Durable configuration revision.
    pub revision: u64,
    /// Digest of the immutable protected config bytes.
    pub config_digest: String,
}

/// Budget owner payload containing every durable reservation identity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetOwnerSnapshot {
    /// Exact owner fence.
    pub state_fence: StateFence,
    /// Durable budget revision.
    pub revision: u64,
    /// Reserved canonical operation identities.
    pub reserved_operations: Vec<OperationId>,
}

/// Problem projection payload containing its durable revision map.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProblemOwnerSnapshot {
    /// Exact owner fence.
    pub state_fence: StateFence,
    /// Durable problem revision map.
    pub revisions: BTreeMap<String, u64>,
}

/// Read owner payload bound to the canonical scope read.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadOwnerSnapshot {
    /// Exact owner fence.
    pub state_fence: StateFence,
    /// Durable read projection revision.
    pub revision: u64,
}

/// Authority payload sufficient to reject a missing grant-graph read.  A
/// non-empty graph is intentionally rejected until the authority crate
/// exposes its typed snapshot constructor; it must never be replaced by an
/// empty graph silently.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityOwnerSnapshot {
    /// Exact owner fence.
    pub state_fence: StateFence,
    /// Durable grant graph revision.
    pub grant_graph_revision: u64,
    /// Number of grants in the canonical graph.
    pub grant_count: u64,
    /// Number of effect-idempotency entries in the authority projection.
    pub authorized_effect_count: u64,
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Errors raised before daemon readiness.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CompositionError {
    /// A pure owner could not be built at the requested fence.
    #[error("owner construction failed: {0}")]
    Owner(String),
    /// Kernel snapshot or transition-port identity was not exact.
    #[error("Kernel provider mismatch: {0}")]
    Provider(String),
    /// Durable recovery did not prove the complete owner set.
    #[error("Governor recovery failed: {0}")]
    Recovery(String),
    /// A startup transition was attempted out of order.
    #[error("startup order violation: expected {expected}, observed {observed}")]
    StartupOrder { expected: String, observed: String },
    /// The composition is not ready for semantic work.
    #[error("Governor is not ready")]
    NotReady,
    /// Canonical admission rejected the envelope.
    #[error("canonical admission: {0}")]
    Canonical(#[from] CanonicalError),
    /// Kernel transition failed at the neutral port.
    #[error("Kernel transition: {0}")]
    Kernel(#[from] KernelPortError),
}

/// Exact current Canonical plan identity retained by the Governor owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalPlanBinding {
    pub plan_id: String,
    pub plan_revision: String,
    pub task_id: TaskId,
    pub work_scope_id: String,
}

impl CanonicalPlanBinding {
    /// Constructs a bounded current-plan identity.
    pub fn new(
        plan_id: impl Into<String>,
        plan_revision: impl Into<String>,
        task_id: TaskId,
        work_scope_id: impl Into<String>,
    ) -> Result<Self, CompositionError> {
        let binding = Self {
            plan_id: plan_id.into(),
            plan_revision: plan_revision.into(),
            task_id,
            work_scope_id: work_scope_id.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates the bounded plan identity without consulting evidence.
    pub fn validate(&self) -> Result<(), CompositionError> {
        if self.plan_id.trim().is_empty() || self.plan_id.chars().any(char::is_control) {
            return Err(CompositionError::Recovery(
                "canonical plan id is blank or contains control characters".to_owned(),
            ));
        }
        if self.plan_revision.trim().is_empty() || self.plan_revision.chars().any(char::is_control)
        {
            return Err(CompositionError::Recovery(
                "canonical plan revision is blank or contains control characters".to_owned(),
            ));
        }
        if self.work_scope_id.trim().is_empty() || self.work_scope_id.chars().any(char::is_control)
        {
            return Err(CompositionError::Recovery(
                "canonical work scope id is blank or contains control characters".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Persisted current-plan authority for one exact Governor fence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalAdmissionSnapshot {
    pub state_fence: StateFence,
    pub owner_revision: u64,
    pub current_plan: Option<CanonicalPlanBinding>,
}

impl CanonicalAdmissionSnapshot {
    /// Constructs a snapshot only after validating its complete bounded shape.
    pub fn new(
        state_fence: StateFence,
        owner_revision: u64,
        current_plan: Option<CanonicalPlanBinding>,
    ) -> Result<Self, CompositionError> {
        let snapshot = Self {
            state_fence,
            owner_revision,
            current_plan,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Validates snapshot identity and counters without choosing a plan.
    pub fn validate(&self) -> Result<(), CompositionError> {
        self.state_fence
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if self.owner_revision == 0 {
            return Err(CompositionError::Recovery(
                "canonical owner revision is zero".to_owned(),
            ));
        }
        if let Some(current_plan) = &self.current_plan {
            current_plan.validate()?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalAdmissionSnapshotWire {
    state_fence: StateFence,
    owner_revision: u64,
    current_plan: Option<CanonicalPlanBinding>,
}

impl<'de> Deserialize<'de> for CanonicalAdmissionSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = CanonicalAdmissionSnapshotWire::deserialize(deserializer)?;
        Self::new(wire.state_fence, wire.owner_revision, wire.current_plan)
            .map_err(serde::de::Error::custom)
    }
}

/// Canonical owner with no store or provider field.
#[derive(Clone, Debug)]
pub struct CanonicalAdmissionOwner {
    state_fence: StateFence,
    scope: ScopeRevisionView,
    snapshot: CanonicalAdmissionSnapshot,
}

/// One coherent semantic activation projection assembled from owner reads.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernorActivationSnapshot {
    pub state_fence: StateFence,
    pub principal_id: String,
    pub session_id: String,
    pub task_id: TaskId,
    pub work_unit_id: String,
    pub work_scope_id: String,
    pub task_revision: u64,
    pub plan_id: String,
    pub plan_revision: String,
}

impl CanonicalAdmissionOwner {
    /// Creates the sole semantic Canonical owner for one fence.
    pub fn new(
        state_fence: StateFence,
        scope: ScopeRevisionView,
        snapshot: CanonicalAdmissionSnapshot,
    ) -> Result<Self, CompositionError> {
        state_fence
            .validate()
            .map_err(|error| CompositionError::Owner(error.to_string()))?;
        scope
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if scope.state_fence != state_fence {
            return Err(CompositionError::Recovery(
                "canonical scope snapshot fence does not match owner fence".to_owned(),
            ));
        }
        snapshot.validate()?;
        if snapshot.state_fence != state_fence {
            return Err(CompositionError::Recovery(
                "canonical admission snapshot fence does not match owner fence".to_owned(),
            ));
        }
        Ok(Self {
            state_fence,
            scope,
            snapshot,
        })
    }

    /// Produces the immutable transition; no transport is touched here.
    pub fn prepare(
        &self,
        envelope: &CanonicalWriteEnvelope,
    ) -> Result<PreparedTransition, CompositionError> {
        if envelope.request.state_fence != self.state_fence {
            return Err(CompositionError::Provider(
                "Canonical request fence does not match the active Kernel fence".to_owned(),
            ));
        }
        Ok(envelope.prepare()?)
    }

    /// Sends only a Canonical-produced transition to the neutral Kernel port.
    async fn commit<P: KernelTransitionPort + ?Sized>(
        &self,
        port: &P,
        envelope: CanonicalWriteEnvelope,
    ) -> Result<WriteReceipt, CompositionError> {
        let expected_revision_heads = envelope.expected_revision_heads.clone();
        let expected_ordering_heads = envelope.expected_ordering_heads.clone();
        let request = envelope.request.clone();
        let transition = self.prepare(&envelope)?;
        Ok(port
            .apply_prepared(
                &request,
                transition,
                expected_revision_heads,
                expected_ordering_heads,
            )
            .await?)
    }

    /// Returns the active fence without exposing mutable canonical state.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Returns the canonical revision/order heads used for admission.
    #[must_use]
    pub const fn scope(&self) -> &ScopeRevisionView {
        &self.scope
    }

    /// Reads the exact current plan only under its retained state fence.
    pub fn read_current_plan(
        &self,
        state_fence: &StateFence,
    ) -> Result<CanonicalPlanBinding, CompositionError> {
        state_fence
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if self.state_fence != *state_fence
            || self.scope.state_fence != *state_fence
            || self.snapshot.state_fence != *state_fence
        {
            return Err(CompositionError::Recovery(
                "canonical plan read used a stale state fence".to_owned(),
            ));
        }
        self.snapshot.validate()?;
        self.snapshot.current_plan.clone().ok_or_else(|| {
            CompositionError::Recovery(
                "canonical current plan is absent; semantic activation is unavailable".to_owned(),
            )
        })
    }
}

/// Config projection bound to the Host-approved generation.
#[derive(Clone, Debug)]
pub struct ConfigOwner {
    state_fence: StateFence,
    snapshot_digest: String,
}

impl ConfigOwner {
    /// Returns the recovered configuration identity.
    #[must_use]
    pub fn snapshot_digest(&self) -> &str {
        &self.snapshot_digest
    }

    /// Returns the fence of the recovered configuration projection.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }
}

/// Budget projection bound to the active authority fence.
#[derive(Clone, Debug)]
pub struct BudgetOwner {
    state_fence: StateFence,
    reserved_operations: BTreeSet<OperationId>,
}

impl BudgetOwner {
    /// Returns the active budget fence.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Returns the number of durable reservations observed by this owner.
    #[must_use]
    pub fn reservation_count(&self) -> usize {
        self.reserved_operations.len()
    }
}

/// Problem projection owner.  Problems are not canonical store state.
#[derive(Clone, Debug)]
pub struct ProblemOwner {
    state_fence: StateFence,
    revisions: BTreeMap<String, u64>,
}

impl ProblemOwner {
    /// Returns the active problem fence.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Returns the number of recovered problem revisions.
    #[must_use]
    pub fn revision_count(&self) -> usize {
        self.revisions.len()
    }
}

/// Read projection owner. Reads are admitted through a future Kernel read
/// operation, never by opening a store from the daemon.
#[derive(Clone, Debug)]
pub struct ReadOwner {
    state_fence: StateFence,
    scope: ScopeRevisionView,
}

impl ReadOwner {
    fn new(state_fence: StateFence, scope: ScopeRevisionView) -> Result<Self, CompositionError> {
        if scope.state_fence != state_fence {
            return Err(CompositionError::Recovery(
                "read projection scope has a stale fence".to_owned(),
            ));
        }
        Ok(Self { state_fence, scope })
    }

    /// Returns the fence required for all future reads.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Returns the recovered canonical scope view used by read admission.
    #[must_use]
    pub const fn scope(&self) -> &ScopeRevisionView {
        &self.scope
    }
}

/// Maintenance persistence adapter backed by the authenticated Kernel job
/// route.  This type deliberately has no local map or default implementation.
pub struct KernelDurableJobStore<P: ?Sized> {
    kernel: Arc<P>,
    state_fence: StateFence,
}

impl<P: KernelDurableJobPort + ?Sized> KernelDurableJobStore<P> {
    fn new(kernel: Arc<P>, state_fence: StateFence) -> Self {
        Self {
            kernel,
            state_fence,
        }
    }
}

impl<P: KernelDurableJobPort + ?Sized> MaintenanceStateStore for KernelDurableJobStore<P> {
    fn load(&mut self, job_id: &str) -> Result<Option<MaintenanceJob>, MaintenanceError> {
        self.kernel
            .load_durable_job(job_id, &self.state_fence)
            .map_err(|error| MaintenanceError::Store(error.to_string()))
    }

    fn save(&mut self, job: &MaintenanceJob) -> Result<(), MaintenanceError> {
        if job.state_fence != self.state_fence {
            return Err(MaintenanceError::FenceMismatch);
        }
        self.kernel
            .save_durable_job(job)
            .map_err(|error| MaintenanceError::Store(error.to_string()))
    }
}

/// Authority owner retaining both effect policy and the validated grant graph.
#[derive(Clone, Debug)]
pub struct AuthorityOwner {
    /// Effect-level authorizer.
    pub effects: EffectAuthorizer,
    /// Recovered grant graph lineage.
    pub grants: GrantGraph,
}

impl AuthorityOwner {
    fn from_snapshot(
        snapshot: &AuthorityOwnerSnapshot,
        expected_fence: &StateFence,
    ) -> Result<Self, CompositionError> {
        if snapshot.state_fence != *expected_fence || snapshot.grant_graph_revision == 0 {
            return Err(CompositionError::Recovery(
                "authority snapshot has a stale fence or zero graph revision".to_owned(),
            ));
        }
        if snapshot.grant_count != 0 {
            return Err(CompositionError::Recovery(
                "authority grant payload is non-empty but no typed GrantGraph restore route is admitted"
                    .to_owned(),
            ));
        }
        if snapshot.authorized_effect_count != 0 {
            return Err(CompositionError::Recovery(
                "authority effect payload is non-empty but no typed EffectAuthorizer restore route is admitted"
                    .to_owned(),
            ));
        }
        let grants = GrantGraph::from_grants(std::iter::empty(), snapshot.grant_graph_revision)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        Ok(Self {
            effects: EffectAuthorizer::default(),
            grants,
        })
    }
}

/// All N4 owners, each represented by one field and one mutable projection.
pub struct GovernorOwners<P: ?Sized> {
    /// `WorkScope` identity/binding owner.
    pub work_scope: Option<WorkScopeBindingOwner>,
    /// Durable task lifecycle owner.
    pub task: TaskLifecycleOwner,
    /// Durable session lifecycle owner.
    pub session: SessionLifecycleOwner,
    /// Canonical semantic admission owner.
    pub canonical: CanonicalAdmissionOwner,
    /// Pure authority idempotency owner.
    pub authority: AuthorityOwner,
    /// Budget reservation projection owner.
    pub budget: BudgetOwner,
    /// Host-approved configuration projection owner.
    pub config: ConfigOwner,
    /// Durable application coordination owner.
    pub coordination: CoordinationOwner,
    /// Finish candidate projection owner.
    pub finish: FinishService,
    /// Problem projection owner.
    pub problem: ProblemOwner,
    /// Candidate observation journal owner.
    pub observation: ObservationJournal,
    /// Read admission projection owner.
    pub read: ReadOwner,
    /// Skill lifecycle owner.
    pub skill: SkillRegistry,
    /// Module Registry owner.
    pub module_registry: ModuleCatalog,
    /// Maintenance job owner.
    pub maintenance: MaintenanceController<KernelDurableJobStore<P>>,
    /// Change-monitor projection owner.
    pub change_monitor: ChangeMonitor,
}

impl<P: KernelDurableJobPort + ?Sized> GovernorOwners<P> {
    #[allow(
        clippy::too_many_lines,
        reason = "recovery reconstructs every closed owner in a fixed authority-sensitive order"
    )]
    fn from_recovery(
        kernel: Arc<P>,
        state_fence: &StateFence,
        config_snapshot_digest: String,
        recovery: &GovernorRecoverySnapshot,
    ) -> Result<Self, CompositionError> {
        let authority_epoch = state_fence.authority_epoch;
        let task_snapshot: TaskLifecycleSnapshot =
            decode_owner_snapshot(recovery, RecoveryOwner::Task)?;
        let task =
            TaskLifecycleOwner::from_snapshot(authority_epoch, state_fence.clone(), task_snapshot)
                .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let session_snapshot: SessionLifecycleSnapshot =
            decode_owner_snapshot(recovery, RecoveryOwner::Session)?;
        let session = SessionLifecycleOwner::from_snapshot(
            authority_epoch,
            state_fence.clone(),
            session_snapshot,
        )
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let authority_snapshot: AuthorityOwnerSnapshot =
            decode_owner_snapshot(recovery, RecoveryOwner::Authority)?;
        let authority = AuthorityOwner::from_snapshot(&authority_snapshot, state_fence)?;
        let budget_snapshot: BudgetOwnerSnapshot =
            decode_owner_snapshot(recovery, RecoveryOwner::Budget)?;
        if &budget_snapshot.state_fence != state_fence || budget_snapshot.revision == 0 {
            return Err(CompositionError::Recovery(
                "budget snapshot has a stale fence or zero revision".to_owned(),
            ));
        }
        let reserved_operation_count = budget_snapshot.reserved_operations.len();
        let reserved_operations = budget_snapshot
            .reserved_operations
            .into_iter()
            .collect::<BTreeSet<_>>();
        if reserved_operations.len() != reserved_operation_count {
            return Err(CompositionError::Recovery(
                "budget snapshot contains duplicate operation identities".to_owned(),
            ));
        }
        let config_snapshot: ConfigOwnerSnapshot =
            decode_owner_snapshot(recovery, RecoveryOwner::Config)?;
        if &config_snapshot.state_fence != state_fence
            || config_snapshot.revision == 0
            || config_snapshot.config_digest != config_snapshot_digest
        {
            return Err(CompositionError::Recovery(
                "config owner snapshot is not bound to the protected launch digest".to_owned(),
            ));
        }
        let coordination_wire: CoordinationOwner =
            decode_owner_snapshot(recovery, RecoveryOwner::Coordination)?;
        let coordination = CoordinationOwner::from_snapshot(coordination_wire)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let finish_receipts: Vec<FinishDecisionReceipt> =
            decode_owner_snapshot(recovery, RecoveryOwner::Finish)?;
        if finish_receipts
            .iter()
            .any(|receipt| &receipt.state_fence != state_fence)
        {
            return Err(CompositionError::Recovery(
                "finish receipt snapshot contains a stale state fence".to_owned(),
            ));
        }
        let finish = FinishService::from_receipts(finish_receipts)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let problem_snapshot: ProblemOwnerSnapshot =
            decode_owner_snapshot(recovery, RecoveryOwner::Problem)?;
        if &problem_snapshot.state_fence != state_fence
            || problem_snapshot
                .revisions
                .values()
                .any(|revision| *revision == 0)
        {
            return Err(CompositionError::Recovery(
                "problem owner snapshot has a stale fence or zero revision".to_owned(),
            ));
        }
        let observation_entries: Vec<ObservationJournalEntry> =
            decode_owner_snapshot(recovery, RecoveryOwner::Observation)?;
        let observation = ObservationJournal::from_entries(observation_entries)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let read_snapshot: ReadOwnerSnapshot =
            decode_owner_snapshot(recovery, RecoveryOwner::Read)?;
        if &read_snapshot.state_fence != state_fence || read_snapshot.revision == 0 {
            return Err(CompositionError::Recovery(
                "read owner snapshot has a stale fence or zero revision".to_owned(),
            ));
        }
        let skill_views: Vec<SkillLifecycleView> =
            decode_owner_snapshot(recovery, RecoveryOwner::Skill)?;
        if skill_views
            .iter()
            .any(|view| &view.state_fence != state_fence)
        {
            return Err(CompositionError::Recovery(
                "skill snapshot contains a stale state fence".to_owned(),
            ));
        }
        let skill = SkillRegistry::from_snapshot(skill_views)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let module_snapshot: ModuleCatalogSnapshot =
            decode_owner_snapshot(recovery, RecoveryOwner::ModuleRegistry)?;
        let module_registry = ModuleCatalog::from_snapshot(module_snapshot)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let change_snapshot: eliot_change_monitor::ChangeMonitorSnapshot =
            decode_owner_snapshot(recovery, RecoveryOwner::ChangeMonitor)?;
        let change_monitor = eliot_change_monitor::ChangeMonitor::from_snapshot(change_snapshot)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let work_scope = if let Ok(snapshot) =
            decode_owner_snapshot::<WorkScopeBindingSnapshot>(recovery, RecoveryOwner::WorkScope)
        {
            let owner = WorkScopeBindingOwner::from_snapshot(snapshot)
                .map_err(|error| CompositionError::Recovery(error.to_string()))?;
            owner
                .read_current(state_fence)
                .map_err(|error| CompositionError::Recovery(error.to_string()))?;
            Some(owner)
        } else {
            let empty: EmptyOwnerSnapshot =
                decode_owner_snapshot(recovery, RecoveryOwner::WorkScope)?;
            empty.validate(state_fence)?;
            None
        };
        let owner = RecoveryOwner::Maintenance;
        {
            let empty: EmptyOwnerSnapshot = decode_owner_snapshot(recovery, owner)?;
            empty.validate(state_fence)?;
        }
        let canonical_snapshot: CanonicalAdmissionSnapshot =
            decode_owner_snapshot(recovery, RecoveryOwner::Canonical)?;
        let canonical = CanonicalAdmissionOwner::new(
            state_fence.clone(),
            recovery.canonical_scope.clone(),
            canonical_snapshot,
        )?;
        let read = ReadOwner::new(state_fence.clone(), recovery.canonical_scope.clone())?;
        Ok(Self {
            work_scope,
            task,
            session,
            canonical,
            authority,
            budget: BudgetOwner {
                state_fence: state_fence.clone(),
                reserved_operations,
            },
            config: ConfigOwner {
                state_fence: state_fence.clone(),
                snapshot_digest: config_snapshot_digest,
            },
            coordination,
            finish,
            problem: ProblemOwner {
                state_fence: state_fence.clone(),
                revisions: problem_snapshot.revisions,
            },
            observation,
            read,
            skill,
            module_registry,
            maintenance: MaintenanceController::new(KernelDurableJobStore::new(
                kernel,
                state_fence.clone(),
            )),
            change_monitor,
        })
    }

    /// Returns the fixed owner identity list used for duplicate detection.
    #[must_use]
    pub const fn owner_ids(&self) -> [&'static str; 16] {
        OWNER_IDS
    }
}

/// Startup phase of the one Governor composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositionReadiness {
    /// No provider or recovery proof has been admitted.
    Constructing,
    /// Exact Kernel/provider and owner recovery have been admitted.
    Ready,
    /// Shutdown has begun; no new work may be admitted.
    Stopped,
}

/// One daemon-owned Governor composition. There is no second provider or
/// process executor hidden behind this value.
pub struct GovernorComposition<P: ?Sized> {
    kernel: Arc<P>,
    governor: Governor,
    owners: GovernorOwners<P>,
    snapshot: KernelGenerationSnapshot,
    recovery: GovernorRecoverySnapshot,
    service_observations: Vec<KernelServiceRecovery>,
    readiness: CompositionReadiness,
}

impl<P: KernelGenerationPort + ?Sized> GovernorComposition<P> {
    /// Builds one composition only after exact provider and recovery checks.
    pub fn new(
        kernel: Arc<P>,
        expected: &KernelGenerationExpectation,
        queues: QueueLimits,
    ) -> Result<Self, CompositionError> {
        let snapshot = kernel.snapshot().clone();
        expected
            .admits(&snapshot)
            .map_err(|error| CompositionError::Provider(error.to_string()))?;
        let state_fence = snapshot.state_fence();
        let recovery = recover_from_kernel(
            kernel.as_ref(),
            &state_fence,
            &snapshot.protected_snapshot_digest,
        )?;
        recovery.validate(&state_fence, &snapshot.protected_snapshot_digest)?;
        let service_observations = kernel
            .services(&state_fence, &snapshot.protected_snapshot_digest)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        validate_service_observations(&service_observations, &state_fence)?;
        let mut governor = Governor::new(GovernorConfig {
            authority_epoch: snapshot.authority_epoch,
            resource_generation: snapshot.generation,
            queues,
            background_pause_interactive_depth: 1,
        })
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
        governor
            .begin_startup()
            .map_err(|error| CompositionError::StartupOrder {
                expected: "Constructed -> Starting".to_owned(),
                observed: error.to_string(),
            })?;
        for service in STARTUP_ORDER {
            let recovered = service_observations
                .iter()
                .find(|candidate| candidate.service == service)
                .ok_or_else(|| {
                    CompositionError::Recovery(format!("missing service {service:?}"))
                })?;
            governor
                .admit_service(service, recovered.observation.clone())
                .map_err(|error| CompositionError::StartupOrder {
                    expected: format!("admit {service:?}"),
                    observed: error.to_string(),
                })?;
        }
        if governor.snapshot().state != GovernorState::Ready {
            return Err(CompositionError::NotReady);
        }
        let owners = GovernorOwners::from_recovery(
            kernel.clone(),
            &state_fence,
            snapshot.protected_snapshot_digest.clone(),
            &recovery,
        )?;
        Ok(Self {
            kernel,
            governor,
            owners,
            snapshot,
            recovery,
            service_observations,
            readiness: CompositionReadiness::Ready,
        })
    }

    /// Returns the one owner set.
    #[must_use]
    pub const fn owners(&self) -> &GovernorOwners<P> {
        &self.owners
    }

    /// Returns the authenticated Kernel snapshot admitted at construction.
    #[must_use]
    pub const fn kernel_snapshot(&self) -> &KernelGenerationSnapshot {
        &self.snapshot
    }

    /// Returns the provider-owned recovery evidence retained for exact replay
    /// and diagnostics.
    #[must_use]
    pub const fn recovery(&self) -> &GovernorRecoverySnapshot {
        &self.recovery
    }

    /// Returns the separate Kernel-owned service observations used for ordered
    /// Governor admission; these are not part of owner recovery.
    #[must_use]
    pub fn service_observations(&self) -> &[KernelServiceRecovery] {
        &self.service_observations
    }

    /// Returns current readiness; construction never returns a partially ready value.
    #[must_use]
    pub const fn readiness(&self) -> CompositionReadiness {
        self.readiness
    }

    /// Returns the Governor lifecycle projection.
    #[must_use]
    pub fn governor(&self) -> &Governor {
        &self.governor
    }

    /// Applies one Canonical-admitted transition through the sole retained
    /// Kernel port. Callers cannot provide a second client or bypass
    /// Canonical admission with an arbitrary transition.
    pub async fn commit_canonical(
        &self,
        envelope: CanonicalWriteEnvelope,
    ) -> Result<WriteReceipt, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        self.owners
            .canonical
            .commit(self.kernel.as_ref(), envelope)
            .await
    }

    /// Reads one coherent semantic activation from all required owner records.
    ///
    /// No semantic identity is accepted from the caller: coordination first
    /// proves one unique live work lease, then task, `WorkScope` and Canonical
    /// owners must agree on its exact fence and linked identities.
    pub fn read_unique_agent_activation(
        &self,
        now: u64,
    ) -> Result<GovernorActivationSnapshot, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        let state_fence = self.snapshot.state_fence();
        let work = self
            .owners
            .coordination
            .read_unique_active_work_lease(now, state_fence.authority_epoch, &state_fence)
            .map_err(|error| {
                CompositionError::Recovery(format!(
                    "unique coordination activation read failed: {error}"
                ))
            })?;
        let task_id = TaskId::new(work.work_item.task_id.clone())
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let lifecycle_session_id = SessionId::new(work.session.session_id.clone())
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let lifecycle_session = self
            .owners
            .session
            .session(&lifecycle_session_id)
            .ok_or_else(|| {
                CompositionError::Recovery(format!(
                    "missing session lifecycle record for {lifecycle_session_id}"
                ))
            })?;
        if lifecycle_session.session_id != lifecycle_session_id
            || lifecycle_session.status != SessionState::Active
            || lifecycle_session.authority_epoch != state_fence.authority_epoch
            || lifecycle_session.state_fence != state_fence
            || lifecycle_session.started_at == 0
            || lifecycle_session.heartbeat_at < lifecycle_session.started_at
            || lifecycle_session.expires_at == 0
            || lifecycle_session.expires_at < lifecycle_session.heartbeat_at
            || lifecycle_session.heartbeat_at > now
            || now > lifecycle_session.expires_at
        {
            return Err(CompositionError::Recovery(
                "session lifecycle record is not an exact active activation match".to_owned(),
            ));
        }
        if let Some(scoped_task_id) = &lifecycle_session.task_scope
            && scoped_task_id != task_id.as_str()
        {
            return Err(CompositionError::Recovery(
                "session lifecycle task scope disagrees with the selected task".to_owned(),
            ));
        }
        let task = self.owners.task.task(&task_id).ok_or_else(|| {
            CompositionError::Recovery(format!("missing task owner record for {task_id}"))
        })?;
        if task.task_id != task_id
            || task.state_fence != state_fence
            || task.revision == 0
            || !matches!(
                task.state,
                TaskState::ActionAuthorized | TaskState::Executing | TaskState::Verifying
            )
        {
            return Err(CompositionError::Recovery(
                "task owner record is not an exact actionable activation match".to_owned(),
            ));
        }
        if let Some(expected_revision) = state_fence.task_revision
            && expected_revision.value() != task.revision
        {
            return Err(CompositionError::Recovery(
                "task revision does not match the activation fence".to_owned(),
            ));
        }
        let scope_owner = self.owners.work_scope.as_ref().ok_or_else(|| {
            CompositionError::Recovery(
                "WorkScope binding is unbound; semantic activation is unavailable".to_owned(),
            )
        })?;
        let scope = scope_owner
            .read_current(&state_fence)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let plan = self.owners.canonical.read_current_plan(&state_fence)?;
        if plan.task_id != task_id || plan.work_scope_id != scope.binding.scope.scope_ref {
            return Err(CompositionError::Recovery(
                "canonical active plan does not match the selected task and WorkScope".to_owned(),
            ));
        }
        Ok(GovernorActivationSnapshot {
            state_fence,
            principal_id: work.session.principal_id,
            session_id: work.session.session_id,
            task_id,
            work_unit_id: work.work_item.work_item_id,
            work_scope_id: scope.binding.scope.scope_ref,
            task_revision: task.revision,
            plan_id: plan.plan_id,
            plan_revision: plan.plan_revision,
        })
    }

    /// Stops this composition without creating a second shutdown authority.
    pub fn stop(&mut self) {
        self.readiness = CompositionReadiness::Stopped;
    }
}

/// Supplies the exact authenticated generation snapshot for a Kernel port.
pub trait KernelGenerationSnapshotProvider {
    /// Returns the immutable snapshot established by authenticated handoff.
    fn snapshot(&self) -> &KernelGenerationSnapshot;
}

/// Authenticated Kernel generation client required by the daemon.
///
/// A pipe name or caller-supplied generation is not sufficient: an admitted
/// type must expose both the neutral transition port and the immutable
/// authenticated snapshot.
pub trait KernelGenerationPort:
    KernelTransitionPort
    + KernelGenerationSnapshotProvider
    + KernelRecoveryPort
    + KernelServiceObservationPort
    + KernelDurableJobPort
{
}

impl<T> KernelGenerationPort for T where
    T: KernelTransitionPort
        + KernelGenerationSnapshotProvider
        + KernelRecoveryPort
        + KernelServiceObservationPort
        + KernelDurableJobPort
{
}

fn recover_from_kernel<P: KernelRecoveryPort + ?Sized>(
    kernel: &P,
    state_fence: &StateFence,
    protected_snapshot_digest: &str,
) -> Result<GovernorRecoverySnapshot, CompositionError> {
    let mut canonical_scope = kernel
        .canonical_scope(state_fence, protected_snapshot_digest)
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
    let mut owner_reads = Vec::with_capacity(RecoveryOwner::ALL.len());
    let mut missing = 0usize;
    for owner in RecoveryOwner::ALL {
        let read = kernel
            .named_read(KernelNamedReadRequest {
                owner,
                state_fence: state_fence.clone(),
                protected_snapshot_digest: protected_snapshot_digest.to_owned(),
            })
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if let Some(read) = read {
            owner_reads.push(read);
        } else {
            missing += 1;
        }
    }
    if missing != 0 {
        if missing != RecoveryOwner::ALL.len()
            || state_fence.authority_epoch != AuthorityEpoch::genesis()
            || state_fence.resource_generation != ResourceGeneration::genesis()
            || state_fence.task_revision.is_some()
            || state_fence.policy_revision.is_some()
            || state_fence.integration_revision.is_some()
            || !canonical_scope.revision_heads.is_empty()
            || !canonical_scope.ordering_heads.is_empty()
        {
            return Err(CompositionError::Recovery(
                "Kernel returned partial or non-genesis owner state; local fill is forbidden"
                    .to_owned(),
            ));
        }
        let genesis_request = GovernorGenesisRequest::new(state_fence, protected_snapshot_digest)?;
        genesis_request.validate(state_fence, protected_snapshot_digest)?;
        kernel
            .initialize_governor_genesis(&genesis_request)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        owner_reads.clear();
        for owner in RecoveryOwner::ALL {
            let read = kernel
                .named_read(KernelNamedReadRequest {
                    owner,
                    state_fence: state_fence.clone(),
                    protected_snapshot_digest: protected_snapshot_digest.to_owned(),
                })
                .map_err(|error| CompositionError::Recovery(error.to_string()))?
                .ok_or_else(|| {
                    CompositionError::Recovery(
                        "genesis initialization did not produce every owner record".to_owned(),
                    )
                })?;
            owner_reads.push(read);
        }
        canonical_scope = kernel
            .canonical_scope(state_fence, protected_snapshot_digest)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
    }
    let receipts = kernel
        .receipts(state_fence, protected_snapshot_digest)
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
    let durable_jobs = kernel
        .durable_jobs(state_fence, protected_snapshot_digest)
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
    Ok(GovernorRecoverySnapshot {
        state_fence: state_fence.clone(),
        protected_snapshot_digest: protected_snapshot_digest.to_owned(),
        owner_reads,
        canonical_scope,
        receipts,
        durable_jobs,
    })
}

fn validate_service_observations(
    observations: &[KernelServiceRecovery],
    expected_fence: &StateFence,
) -> Result<(), CompositionError> {
    let mut services = BTreeSet::new();
    for recovered in observations {
        if !services.insert(recovered.service)
            || recovered.observation.generation != expected_fence.resource_generation
            || recovered.observation.authority_epoch != expected_fence.authority_epoch
            || recovered.observation.state != eliot_runtime_contracts::ServiceProcessState::Ready
            || !recovered.observation.health.is_fully_healthy()
        {
            return Err(CompositionError::Recovery(
                "service observation is incomplete, stale, or unhealthy".to_owned(),
            ));
        }
    }
    if services.len() != STARTUP_ORDER.len()
        || STARTUP_ORDER
            .iter()
            .any(|service| !services.contains(service))
    {
        return Err(CompositionError::Recovery(
            "Kernel service observation did not return every ordered Governor service".to_owned(),
        ));
    }
    Ok(())
}

fn decode_owner_snapshot<T: DeserializeOwned + Serialize>(
    recovery: &GovernorRecoverySnapshot,
    owner: RecoveryOwner,
) -> Result<T, CompositionError> {
    let read = recovery.owner_read(owner)?;
    let decoded: T = serde_json::from_slice(&read.payload).map_err(|error| {
        CompositionError::Recovery(format!(
            "owner {} payload schema rejected: {error}",
            owner.as_str()
        ))
    })?;
    let canonical = canonical_json_bytes(&decoded).map_err(|error| {
        CompositionError::Recovery(format!(
            "owner {} payload could not be canonicalized: {error}",
            owner.as_str()
        ))
    })?;
    if canonical != read.payload {
        return Err(CompositionError::Recovery(format!(
            "owner {} payload is not canonical JSON",
            owner.as_str()
        )));
    }
    Ok(decoded)
}

/// Explicit Host-approved config projection used by the daemon loader.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernorLaunchConfig {
    /// Daemon identity.
    pub instance_id: String,
    /// Exact Kernel generation snapshot expected from Host handoff.
    pub kernel: KernelGenerationExpectation,
    /// Digest of the protected full Governor launch snapshot.
    pub protected_snapshot_digest: String,
}

impl GovernorLaunchConfig {
    /// Validates that the launch config is itself a bounded protected snapshot.
    pub fn validate(&self) -> Result<(), CompositionError> {
        if self.instance_id.trim().is_empty() || self.instance_id.chars().any(char::is_control) {
            return Err(CompositionError::Provider(
                "instance_id must be non-blank and free of controls".to_owned(),
            ));
        }
        let snapshot = KernelGenerationSnapshot {
            service: self.kernel.service.clone(),
            protocol: self.kernel.protocol.clone(),
            generation: self.kernel.generation,
            authority_epoch: self.kernel.authority_epoch,
            artifact_digest: self.kernel.artifact_digest.clone(),
            protected_snapshot_digest: self.protected_snapshot_digest.clone(),
            principal: self.kernel.principal.clone(),
        };
        snapshot.validate()?;
        if snapshot.protected_snapshot_digest != self.kernel.protected_snapshot_digest {
            return Err(CompositionError::Provider(
                "launch config protected snapshot digest is not bound to Kernel expectation"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Compatibility alias retained for daemon callers that use `QueueLimits`.
pub type GovernorQueueLimits = QueueLimits;

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "tests use expects for fixed-valid protocol fixtures"
    )]

    use super::*;
    use crate::{STARTUP_ORDER, ServiceId};
    use eliot_contracts::{ClockReading, SessionId, TaskId};
    use eliot_coordination::{
        RegisterSession as CoordinationRegisterSession, WorkItem, WorkLeaseRequest, WorkState,
    };
    use eliot_runtime_contracts::{HealthVector, ServiceProcessState};
    use eliot_session::{RegisterSession, SessionCommand, SessionCommandContext};
    use eliot_store_api::ScopeId;
    use eliot_task::{TaskCommandContext, TaskLifecycleEvent, TaskProposal, TaskRecord};
    use std::sync::atomic::{AtomicBool, Ordering};

    struct FakeKernel {
        snapshot: KernelGenerationSnapshot,
        payloads: BTreeMap<RecoveryOwner, Vec<u8>>,
        missing: Option<RecoveryOwner>,
        genesis_all_absent: bool,
        genesis_seeded: Arc<AtomicBool>,
        service_observations: Option<Vec<KernelServiceRecovery>>,
        service_failure: bool,
    }

    impl KernelGenerationSnapshotProvider for FakeKernel {
        fn snapshot(&self) -> &KernelGenerationSnapshot {
            &self.snapshot
        }
    }

    impl KernelTransitionPort for FakeKernel {
        fn apply_prepared<'a>(
            &'a self,
            _request: &RequestMetadata,
            _transition: PreparedTransition,
            _expected_revision_heads: Vec<RevisionHeadExpectation>,
            _expected_ordering_heads: Vec<OrderingHeadExpectation>,
        ) -> KernelPortFuture<'a, WriteReceipt> {
            Box::pin(async { Err(KernelPortError::Unknown("test port".to_owned())) })
        }

        fn receipt(
            &self,
            _operation_id: OperationId,
        ) -> KernelPortFuture<'_, Option<WriteReceipt>> {
            Box::pin(async { Ok(None) })
        }

        fn health(&self) -> KernelPortFuture<'_, StoreHealth> {
            Box::pin(async { Err(KernelPortError::NotAdmitted("test port".to_owned())) })
        }
    }

    impl KernelRecoveryPort for FakeKernel {
        fn named_read(
            &self,
            request: KernelNamedReadRequest,
        ) -> Result<Option<KernelNamedReadReply>, KernelPortError> {
            if self.missing == Some(request.owner) {
                return Ok(None);
            }
            if self.genesis_all_absent && !self.genesis_seeded.load(Ordering::Acquire) {
                return Ok(None);
            }
            let payload = self
                .payloads
                .get(&request.owner)
                .cloned()
                .unwrap_or_else(|| {
                    owner_payload(
                        request.owner,
                        &request.state_fence,
                        &request.protected_snapshot_digest,
                    )
                });
            Ok(Some(KernelNamedReadReply {
                owner: request.owner,
                state_fence: request.state_fence,
                revision: 1,
                schema: OWNER_SNAPSHOT_SCHEMA.to_owned(),
                value_digest: sha256_hex(&payload),
                payload,
            }))
        }

        fn initialize_governor_genesis(
            &self,
            _request: &GovernorGenesisRequest,
        ) -> Result<(), KernelPortError> {
            self.genesis_seeded.store(true, Ordering::Release);
            Ok(())
        }

        fn canonical_scope(
            &self,
            state_fence: &StateFence,
            _protected_snapshot_digest: &str,
        ) -> Result<ScopeRevisionView, KernelPortError> {
            Ok(ScopeRevisionView {
                scope_id: ScopeId::new("governor").expect("scope"),
                revision_heads: Vec::new(),
                ordering_heads: Vec::new(),
                state_fence: state_fence.clone(),
            })
        }

        fn receipts(
            &self,
            _state_fence: &StateFence,
            _protected_snapshot_digest: &str,
        ) -> Result<Vec<WriteReceipt>, KernelPortError> {
            Ok(Vec::new())
        }

        fn durable_jobs(
            &self,
            _state_fence: &StateFence,
            _protected_snapshot_digest: &str,
        ) -> Result<Vec<MaintenanceJob>, KernelPortError> {
            Ok(Vec::new())
        }
    }

    impl KernelServiceObservationPort for FakeKernel {
        fn services(
            &self,
            state_fence: &StateFence,
            _protected_snapshot_digest: &str,
        ) -> Result<Vec<KernelServiceRecovery>, KernelPortError> {
            if self.service_failure {
                return Err(KernelPortError::Unknown(
                    "test service observation failure".to_owned(),
                ));
            }
            Ok(self
                .service_observations
                .clone()
                .unwrap_or_else(|| service_observations(state_fence)))
        }
    }

    impl KernelDurableJobPort for FakeKernel {
        fn load_durable_job(
            &self,
            _job_id: &str,
            _state_fence: &StateFence,
        ) -> Result<Option<MaintenanceJob>, KernelPortError> {
            Ok(None)
        }

        fn save_durable_job(&self, _job: &MaintenanceJob) -> Result<(), KernelPortError> {
            Ok(())
        }
    }

    fn snapshot() -> KernelGenerationSnapshot {
        KernelGenerationSnapshot {
            service: "eliot-kernel".to_owned(),
            protocol: "eliot.kernel.v1".to_owned(),
            generation: ResourceGeneration::genesis(),
            authority_epoch: AuthorityEpoch::genesis(),
            artifact_digest: "a".repeat(64),
            protected_snapshot_digest: "b".repeat(64),
            principal: "S-1-5-18".to_owned(),
        }
    }

    fn fake_kernel(snapshot: KernelGenerationSnapshot) -> FakeKernel {
        FakeKernel {
            snapshot,
            payloads: BTreeMap::new(),
            missing: None,
            genesis_all_absent: false,
            genesis_seeded: Arc::new(AtomicBool::new(false)),
            service_observations: None,
            service_failure: false,
        }
    }

    fn service_observations(state_fence: &StateFence) -> Vec<KernelServiceRecovery> {
        STARTUP_ORDER
            .into_iter()
            .map(|service| KernelServiceRecovery {
                service,
                observation: ServiceObservation {
                    state: ServiceProcessState::Ready,
                    health: HealthVector::healthy(),
                    generation: state_fence.resource_generation,
                    authority_epoch: state_fence.authority_epoch,
                },
            })
            .collect()
    }

    fn canonical_scope(state_fence: &StateFence) -> ScopeRevisionView {
        ScopeRevisionView {
            scope_id: ScopeId::new("governor").expect("scope"),
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
            state_fence: state_fence.clone(),
        }
    }

    fn owner_payload(
        owner: RecoveryOwner,
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Vec<u8> {
        let value = match owner {
            RecoveryOwner::WorkScope | RecoveryOwner::Maintenance => {
                serde_json::to_value(EmptyOwnerSnapshot {
                    state_fence: state_fence.clone(),
                    revision: 1,
                })
            }
            RecoveryOwner::Canonical => serde_json::to_value(CanonicalAdmissionSnapshot {
                state_fence: state_fence.clone(),
                owner_revision: 1,
                current_plan: None,
            }),
            RecoveryOwner::Task => serde_json::to_value(TaskLifecycleSnapshot {
                next_sequence: 1,
                tasks: BTreeMap::new(),
                events: Vec::new(),
            }),
            RecoveryOwner::Session => serde_json::to_value(SessionLifecycleSnapshot {
                next_sequence: 1,
                sessions: BTreeMap::new(),
                events: Vec::new(),
            }),
            RecoveryOwner::Authority => serde_json::to_value(AuthorityOwnerSnapshot {
                state_fence: state_fence.clone(),
                grant_graph_revision: 1,
                grant_count: 0,
                authorized_effect_count: 0,
            }),
            RecoveryOwner::Budget => serde_json::to_value(BudgetOwnerSnapshot {
                state_fence: state_fence.clone(),
                revision: 1,
                reserved_operations: Vec::new(),
            }),
            RecoveryOwner::Config => serde_json::to_value(ConfigOwnerSnapshot {
                state_fence: state_fence.clone(),
                revision: 1,
                config_digest: protected_snapshot_digest.to_owned(),
            }),
            RecoveryOwner::Coordination => serde_json::to_value(CoordinationOwner::new()),
            RecoveryOwner::Finish => serde_json::to_value(Vec::<FinishDecisionReceipt>::new()),
            RecoveryOwner::Problem => serde_json::to_value(ProblemOwnerSnapshot {
                state_fence: state_fence.clone(),
                revisions: BTreeMap::new(),
            }),
            RecoveryOwner::Observation => {
                serde_json::to_value(Vec::<ObservationJournalEntry>::new())
            }
            RecoveryOwner::Read => serde_json::to_value(ReadOwnerSnapshot {
                state_fence: state_fence.clone(),
                revision: 1,
            }),
            RecoveryOwner::Skill => serde_json::to_value(Vec::<SkillLifecycleView>::new()),
            RecoveryOwner::ModuleRegistry => serde_json::to_value(
                ModuleCatalog::new(state_fence.clone())
                    .expect("module")
                    .snapshot()
                    .expect("module snapshot"),
            ),
            RecoveryOwner::ChangeMonitor => {
                serde_json::to_value(eliot_change_monitor::ChangeMonitorSnapshot::default())
            }
        }
        .expect("owner payload");
        canonical_json_bytes(&value).expect("owner payload bytes")
    }

    fn activation_canonical_snapshot(fence: &StateFence) -> CanonicalAdmissionSnapshot {
        CanonicalAdmissionSnapshot {
            state_fence: fence.clone(),
            owner_revision: 1,
            current_plan: Some(CanonicalPlanBinding {
                plan_id: "plan:current".to_owned(),
                plan_revision: "1".to_owned(),
                task_id: TaskId::new("task-1").expect("task id"),
                work_scope_id: "scope:work".to_owned(),
            }),
        }
    }

    fn activation_task_snapshot(fence: &StateFence) -> TaskLifecycleSnapshot {
        let task_id = TaskId::new("task-1").expect("task id");
        TaskLifecycleSnapshot {
            next_sequence: 2,
            tasks: BTreeMap::from([(
                task_id.clone(),
                TaskRecord {
                    task_id: task_id.clone(),
                    project_ref: "project-1".to_owned(),
                    goal: "activate me".to_owned(),
                    state: TaskState::ActionAuthorized,
                    revision: 1,
                    last_sequence: 1,
                    last_event_id: "task-event-1".to_owned(),
                    state_fence: fence.clone(),
                },
            )]),
            events: vec![TaskLifecycleEvent {
                sequence: 1,
                event_id: "task-event-1".to_owned(),
                request_id: "task-request-1".to_owned(),
                task_id,
                actor_ref: "agent-1".to_owned(),
                from: None,
                to: TaskState::ActionAuthorized,
                command: None,
                state_fence: fence.clone(),
                authority_epoch: fence.authority_epoch,
                observed_at: ClockReading::default(),
            }],
        }
    }

    fn activation_coordination_snapshot(
        fence: &StateFence,
    ) -> eliot_coordination::CoordinationOwner {
        let mut owner = eliot_coordination::CoordinationOwner::new();
        owner
            .register_session(CoordinationRegisterSession {
                request_id: "coord-session-request".to_owned(),
                session_id: "session-1".to_owned(),
                principal_id: "principal-1".to_owned(),
                route_ref: "route-1".to_owned(),
                authority_epoch: fence.authority_epoch,
                state_fence: fence.clone(),
                now: 1,
                heartbeat_deadline: 100,
            })
            .expect("coordination session");
        owner
            .register_work(
                WorkItem {
                    work_item_id: "work-1".to_owned(),
                    task_id: "task-1".to_owned(),
                    state: WorkState::Ready,
                    state_fence: fence.clone(),
                    owner_session_id: None,
                    lease_id: None,
                    attempt: 0,
                    checkpoint_ref: None,
                    result_ref: None,
                },
                "coord-work-request",
                "principal-1",
                ClockReading::default(),
            )
            .expect("coordination work");
        owner
            .acquire_work(WorkLeaseRequest {
                request_id: "coord-lease-request".to_owned(),
                lease_id: "lease-1".to_owned(),
                work_item_id: "work-1".to_owned(),
                session_id: "session-1".to_owned(),
                authority_epoch: fence.authority_epoch,
                state_fence: fence.clone(),
                now: 2,
                lease_duration: 40,
            })
            .expect("coordination lease");
        owner
    }

    fn activation_ambiguous_coordination_snapshot(
        fence: &StateFence,
    ) -> eliot_coordination::CoordinationOwner {
        let mut owner = activation_coordination_snapshot(fence);
        owner
            .register_session(CoordinationRegisterSession {
                request_id: "coord-session-request-2".to_owned(),
                session_id: "session-2".to_owned(),
                principal_id: "principal-2".to_owned(),
                route_ref: "route-2".to_owned(),
                authority_epoch: fence.authority_epoch,
                state_fence: fence.clone(),
                now: 1,
                heartbeat_deadline: 100,
            })
            .expect("second coordination session");
        owner
            .register_work(
                WorkItem {
                    work_item_id: "work-2".to_owned(),
                    task_id: "task-2".to_owned(),
                    state: WorkState::Ready,
                    state_fence: fence.clone(),
                    owner_session_id: None,
                    lease_id: None,
                    attempt: 0,
                    checkpoint_ref: None,
                    result_ref: None,
                },
                "coord-work-request-2",
                "principal-2",
                ClockReading::default(),
            )
            .expect("second coordination work");
        owner
            .acquire_work(WorkLeaseRequest {
                request_id: "coord-lease-request-2".to_owned(),
                lease_id: "lease-2".to_owned(),
                work_item_id: "work-2".to_owned(),
                session_id: "session-2".to_owned(),
                authority_epoch: fence.authority_epoch,
                state_fence: fence.clone(),
                now: 2,
                lease_duration: 40,
            })
            .expect("second coordination lease");
        owner
    }

    fn activation_session_snapshot(fence: &StateFence) -> SessionLifecycleSnapshot {
        let mut owner = SessionLifecycleOwner::new(fence.authority_epoch, fence.clone())
            .expect("session owner");
        let session_id = SessionId::new("session-1").expect("session id");
        owner
            .register(RegisterSession {
                request_id: "session-request-1".to_owned(),
                event_id: "session-event-1".to_owned(),
                session_id: session_id.clone(),
                agent_id: "agent-1".to_owned(),
                model_route: "route-1".to_owned(),
                harness: "harness-1".to_owned(),
                role: "worker".to_owned(),
                project_scope: "scope-1".to_owned(),
                task_scope: Some("task-1".to_owned()),
                capability_profile_id: "profile-1".to_owned(),
                parent_session_id: None,
                policy_snapshot_id: "policy-1".to_owned(),
                authority_epoch: fence.authority_epoch,
                state_fence: fence.clone(),
                now: 1,
                expires_at: 100,
            })
            .expect("session register");
        owner
            .apply(
                session_id,
                SessionCommandContext {
                    request_id: "session-activate-request".to_owned(),
                    event_id: "session-activate-event".to_owned(),
                    actor_ref: "agent-1".to_owned(),
                    state_fence: fence.clone(),
                    authority_epoch: fence.authority_epoch,
                    observed_at: ClockReading::default(),
                    now: 2,
                },
                SessionCommand::Activate,
            )
            .expect("session activate");
        owner.snapshot()
    }

    fn activation_scope_snapshot(fence: &StateFence) -> eliot_workscope::WorkScopeBindingSnapshot {
        serde_json::from_value(serde_json::json!({
            "state_fence": fence,
            "owner_revision": 1,
            "binding": {
                "scope": {
                    "scope_ref": "scope:work",
                    "kind": "git_repo",
                    "lineage_ref": "lineage:work",
                    "instance_ref": "instance:work",
                    "root_identity": "root:work",
                    "generation": 1
                },
                "privacy_class": "INTERNAL",
                "governing_source_generation": 1
            },
            "guard_receipt": {
                "expected_scope_ref": "scope:work",
                "observed_scope_ref": "scope:work",
                "expected_lineage_ref": "lineage:work",
                "observed_lineage_ref": "lineage:work",
                "expected_instance_ref": "instance:work",
                "observed_instance_ref": "instance:work",
                "disposition": "MATCHED",
                "source_generation": 1
            }
        }))
        .expect("work scope binding")
    }

    fn activation_fake(observed: &KernelGenerationSnapshot) -> FakeKernel {
        let fence = observed.state_fence();
        let mut fake = fake_kernel(observed.clone());
        fake.payloads.insert(
            RecoveryOwner::Coordination,
            canonical_json_bytes(&activation_coordination_snapshot(&fence))
                .expect("coordination bytes"),
        );
        fake.payloads.insert(
            RecoveryOwner::Session,
            canonical_json_bytes(&activation_session_snapshot(&fence)).expect("session bytes"),
        );
        fake.payloads.insert(
            RecoveryOwner::Task,
            canonical_json_bytes(&activation_task_snapshot(&fence)).expect("task bytes"),
        );
        fake.payloads.insert(
            RecoveryOwner::WorkScope,
            canonical_json_bytes(&activation_scope_snapshot(&fence)).expect("scope bytes"),
        );
        fake.payloads.insert(
            RecoveryOwner::Canonical,
            canonical_json_bytes(&activation_canonical_snapshot(&fence)).expect("canonical bytes"),
        );
        fake
    }

    #[test]
    fn owner_set_has_one_identity_per_owner() {
        let ids = OWNER_IDS;
        let unique: BTreeSet<_> = ids.into_iter().collect();
        assert_eq!(ids.len(), 16);
        assert_eq!(unique.len(), ids.len());
    }

    #[test]
    fn provider_mismatch_is_rejected_before_owner_construction() {
        let observed = snapshot();
        let mut expected =
            KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        expected.authority_epoch = AuthorityEpoch::new(2).expect("epoch");
        let provider = Arc::new(fake_kernel(observed));
        let result = GovernorComposition::new(provider, &expected, QueueLimits::default());
        assert!(matches!(result, Err(CompositionError::Provider(_))));
    }

    #[test]
    fn kernel_recovery_is_ready_and_start_order_is_fixed() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let mut fake = fake_kernel(observed.clone());
        fake.payloads.insert(
            RecoveryOwner::Canonical,
            canonical_json_bytes(&activation_canonical_snapshot(&observed.state_fence()))
                .expect("canonical bytes"),
        );
        let provider = Arc::new(fake);
        let composition = GovernorComposition::new(provider, &expected, QueueLimits::default())
            .expect("composition");
        assert_eq!(composition.readiness(), CompositionReadiness::Ready);
        assert_eq!(STARTUP_ORDER[0], ServiceId::Config);
        assert_eq!(STARTUP_ORDER[15], ServiceId::Maintenance);
        let mut plan = composition
            .owners()
            .canonical
            .read_current_plan(&observed.state_fence())
            .expect("current canonical plan");
        assert_eq!(plan.plan_id, "plan:current");
        plan.plan_revision = "2".to_owned();
        assert_eq!(
            composition
                .owners()
                .canonical
                .read_current_plan(&observed.state_fence())
                .expect("current canonical plan")
                .plan_revision,
            "1"
        );
    }

    #[test]
    fn owner_recovery_snapshot_and_digest_exclude_service_observations() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let first = GovernorComposition::new(
            Arc::new(fake_kernel(observed.clone())),
            &expected,
            QueueLimits::default(),
        )
        .expect("first composition");

        let mut second_fake = fake_kernel(observed.clone());
        let mut reversed = service_observations(&observed.state_fence());
        reversed.reverse();
        second_fake.service_observations = Some(reversed);
        let second =
            GovernorComposition::new(Arc::new(second_fake), &expected, QueueLimits::default())
                .expect("second composition");

        assert_ne!(first.service_observations(), second.service_observations());
        assert_eq!(first.recovery(), second.recovery());
        let first_digest = sha256_hex(&serde_json::to_vec(first.recovery()).expect("recovery"));
        let second_digest = sha256_hex(&serde_json::to_vec(second.recovery()).expect("recovery"));
        assert_eq!(first_digest, second_digest);
        let encoded = serde_json::to_value(first.recovery()).expect("recovery JSON");
        assert!(encoded.get("services").is_none());
    }

    #[test]
    fn service_observation_failure_blocks_readiness() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let mut fake = fake_kernel(observed);
        fake.service_failure = true;
        let result = GovernorComposition::new(Arc::new(fake), &expected, QueueLimits::default());
        assert!(matches!(result, Err(CompositionError::Recovery(_))));
    }

    #[test]
    fn canonical_owner_rejects_invalid_plan_and_fence_bindings() {
        let observed = snapshot();
        let active_fence = observed.state_fence();
        let scope = canonical_scope(&active_fence);
        let valid_plan = CanonicalPlanBinding::new(
            "plan:current",
            "1",
            TaskId::new("task-1").expect("task id"),
            "scope:work",
        )
        .expect("plan");
        let valid_snapshot =
            CanonicalAdmissionSnapshot::new(active_fence.clone(), 1, Some(valid_plan.clone()))
                .expect("snapshot");
        let owner = CanonicalAdmissionOwner::new(
            active_fence.clone(),
            scope.clone(),
            valid_snapshot.clone(),
        )
        .expect("owner");

        let stale_fence = StateFence::new(
            AuthorityEpoch::genesis(),
            ResourceGeneration::new(2).expect("resource generation"),
        );
        assert!(owner.read_current_plan(&stale_fence).is_err());
        let stale_snapshot =
            CanonicalAdmissionSnapshot::new(stale_fence.clone(), 1, Some(valid_plan.clone()))
                .expect("stale snapshot");
        assert!(
            CanonicalAdmissionOwner::new(active_fence.clone(), scope.clone(), stale_snapshot)
                .is_err()
        );
        assert!(
            CanonicalAdmissionOwner::new(stale_fence, scope.clone(), valid_snapshot.clone())
                .is_err()
        );

        let mut stale_scope = scope;
        stale_scope.state_fence = StateFence::new(
            AuthorityEpoch::genesis(),
            ResourceGeneration::new(2).expect("resource generation"),
        );
        assert!(
            CanonicalAdmissionOwner::new(active_fence.clone(), stale_scope, valid_snapshot)
                .is_err()
        );

        assert!(
            CanonicalPlanBinding::new(
                "",
                "1",
                TaskId::new("task-1").expect("task id"),
                "scope:work"
            )
            .is_err()
        );
        assert!(
            CanonicalPlanBinding::new(
                "plan:current\n",
                "1",
                TaskId::new("task-1").expect("task id"),
                "scope:work"
            )
            .is_err()
        );
        assert!(
            CanonicalPlanBinding::new(
                "plan:current",
                "",
                TaskId::new("task-1").expect("task id"),
                "scope:work"
            )
            .is_err()
        );
        assert!(
            CanonicalPlanBinding::new(
                "plan:current",
                "revision\n1",
                TaskId::new("task-1").expect("task id"),
                "scope:work"
            )
            .is_err()
        );
        assert!(
            CanonicalPlanBinding::new(
                "plan:current",
                "1",
                TaskId::new("task-1").expect("task id"),
                ""
            )
            .is_err()
        );
        assert!(CanonicalAdmissionSnapshot::new(active_fence, 0, Some(valid_plan),).is_err());
    }

    #[test]
    fn canonical_genesis_null_deserializes_validates_and_denies_activation() {
        let observed = snapshot();
        let payload = owner_payload(
            RecoveryOwner::Canonical,
            &observed.state_fence(),
            &observed.protected_snapshot_digest,
        );
        let decoded: CanonicalAdmissionSnapshot =
            serde_json::from_slice(&payload).expect("genesis canonical payload");
        assert_eq!(decoded.current_plan, None);
        decoded.validate().expect("genesis null snapshot");
        assert_eq!(
            payload,
            canonical_json_bytes(&decoded).expect("canonical genesis payload bytes")
        );

        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let mut fake = activation_fake(&observed);
        fake.payloads.insert(RecoveryOwner::Canonical, payload);
        let composition =
            GovernorComposition::new(Arc::new(fake), &expected, QueueLimits::default())
                .expect("genesis null is recoverable");
        assert!(matches!(
            composition.read_unique_agent_activation(20),
            Err(CompositionError::Recovery(message))
                if message.contains("canonical current plan is absent")
        ));
    }

    #[test]
    fn canonical_recovery_rejects_the_old_empty_owner_snapshot() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let mut fake = fake_kernel(observed.clone());
        let payload = canonical_json_bytes(&EmptyOwnerSnapshot {
            state_fence: observed.state_fence().clone(),
            revision: 1,
        })
        .expect("old canonical payload");
        fake.payloads.insert(RecoveryOwner::Canonical, payload);
        let result = GovernorComposition::new(Arc::new(fake), &expected, QueueLimits::default());
        assert!(matches!(result, Err(CompositionError::Recovery(_))));

        let mut legacy = fake_kernel(observed.clone());
        let legacy_unscoped = serde_json::json!({
            "state_fence": observed.state_fence(),
            "owner_revision": 1,
            "current_plan": {
                "plan_id": "plan:current",
                "plan_revision": "1"
            }
        });
        legacy.payloads.insert(
            RecoveryOwner::Canonical,
            serde_json::to_vec(&legacy_unscoped).expect("legacy canonical payload"),
        );
        let result = GovernorComposition::new(Arc::new(legacy), &expected, QueueLimits::default());
        assert!(matches!(result, Err(CompositionError::Recovery(_))));
    }

    #[test]
    fn first_boot_requires_and_rechecks_atomic_genesis_seed() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let mut fake = fake_kernel(observed);
        fake.genesis_all_absent = true;
        let seeded = Arc::clone(&fake.genesis_seeded);
        let composition =
            GovernorComposition::new(Arc::new(fake), &expected, QueueLimits::default())
                .expect("genesis composition");
        assert!(seeded.load(Ordering::Acquire));
        assert_eq!(composition.readiness(), CompositionReadiness::Ready);
        assert_eq!(
            composition.recovery().owner_reads.len(),
            RecoveryOwner::ALL.len()
        );
    }

    #[test]
    fn restart_rehydrates_nonempty_task_and_session_snapshots() {
        let observed = snapshot();
        let fence = observed.state_fence();
        let mut task = TaskLifecycleOwner::new(fence.authority_epoch, fence.clone()).expect("task");
        let task_snapshot = {
            task.propose(TaskProposal {
                task_id: TaskId::new("task-1").expect("task id"),
                project_ref: "project-1".to_owned(),
                goal: "recover me".to_owned(),
                context: TaskCommandContext {
                    request_id: "task-request-1".to_owned(),
                    event_id: "task-event-1".to_owned(),
                    actor_ref: "actor-1".to_owned(),
                    state_fence: fence.clone(),
                    authority_epoch: fence.authority_epoch,
                    observed_at: ClockReading::default(),
                },
            })
            .expect("task proposal");
            task.snapshot()
        };
        let mut session =
            SessionLifecycleOwner::new(fence.authority_epoch, fence.clone()).expect("session");
        let session_snapshot = {
            session
                .register(RegisterSession {
                    request_id: "session-request-1".to_owned(),
                    event_id: "session-event-1".to_owned(),
                    session_id: SessionId::new("session-1").expect("session id"),
                    agent_id: "agent-1".to_owned(),
                    model_route: "route-1".to_owned(),
                    harness: "harness-1".to_owned(),
                    role: "worker".to_owned(),
                    project_scope: "scope-1".to_owned(),
                    task_scope: None,
                    capability_profile_id: "profile-1".to_owned(),
                    parent_session_id: None,
                    policy_snapshot_id: "policy-1".to_owned(),
                    authority_epoch: fence.authority_epoch,
                    state_fence: fence.clone(),
                    now: 1,
                    expires_at: 10,
                })
                .expect("session register");
            session.snapshot()
        };
        let mut fake = fake_kernel(observed.clone());
        fake.payloads.insert(
            RecoveryOwner::Task,
            canonical_json_bytes(&task_snapshot).expect("task bytes"),
        );
        fake.payloads.insert(
            RecoveryOwner::Session,
            canonical_json_bytes(&session_snapshot).expect("session bytes"),
        );
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let composition =
            GovernorComposition::new(Arc::new(fake), &expected, QueueLimits::default())
                .expect("composition");
        assert_eq!(composition.owners().task.snapshot(), task_snapshot);
        assert_eq!(composition.owners().session.snapshot(), session_snapshot);
    }

    #[test]
    fn unique_agent_activation_requires_and_returns_one_coherent_clone() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let composition = GovernorComposition::new(
            Arc::new(activation_fake(&observed)),
            &expected,
            QueueLimits::default(),
        )
        .expect("coherent composition");

        let first = composition
            .read_unique_agent_activation(20)
            .expect("activation");
        assert_eq!(first.principal_id, "principal-1");
        assert_eq!(first.session_id, "session-1");
        assert_eq!(first.task_id, TaskId::new("task-1").expect("task id"));
        assert_eq!(first.work_unit_id, "work-1");
        assert_eq!(first.work_scope_id, "scope:work");
        assert_eq!(first.plan_id, "plan:current");
        assert_eq!(first.plan_revision, "1");
        assert_eq!(
            first,
            composition.read_unique_agent_activation(20).expect("clone")
        );
    }

    #[test]
    fn activation_rejects_missing_or_invalid_lifecycle_session() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");

        let mut missing = activation_fake(&observed);
        missing.payloads.remove(&RecoveryOwner::Session);
        let composition =
            GovernorComposition::new(Arc::new(missing), &expected, QueueLimits::default())
                .expect("composition");
        assert!(composition.read_unique_agent_activation(20).is_err());

        let mut inactive_snapshot = activation_session_snapshot(&observed.state_fence());
        inactive_snapshot
            .sessions
            .get_mut(&SessionId::new("session-1").expect("session id"))
            .expect("session")
            .status = eliot_session::SessionState::Idle;
        let mut inactive = activation_fake(&observed);
        inactive.payloads.insert(
            RecoveryOwner::Session,
            canonical_json_bytes(&inactive_snapshot).expect("inactive session bytes"),
        );
        let composition =
            GovernorComposition::new(Arc::new(inactive), &expected, QueueLimits::default())
                .expect("composition");
        assert!(composition.read_unique_agent_activation(20).is_err());

        let mut expired_snapshot = activation_session_snapshot(&observed.state_fence());
        expired_snapshot
            .sessions
            .get_mut(&SessionId::new("session-1").expect("session id"))
            .expect("session")
            .expires_at = 10;
        let mut expired = activation_fake(&observed);
        expired.payloads.insert(
            RecoveryOwner::Session,
            canonical_json_bytes(&expired_snapshot).expect("expired session bytes"),
        );
        let composition =
            GovernorComposition::new(Arc::new(expired), &expected, QueueLimits::default())
                .expect("composition");
        assert!(composition.read_unique_agent_activation(20).is_err());
    }

    #[test]
    fn activation_rejects_session_scope_and_fence_disagreement() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");

        let mut scoped_snapshot = activation_session_snapshot(&observed.state_fence());
        scoped_snapshot
            .sessions
            .get_mut(&SessionId::new("session-1").expect("session id"))
            .expect("session")
            .task_scope = Some("task-other".to_owned());
        let mut scoped = activation_fake(&observed);
        scoped.payloads.insert(
            RecoveryOwner::Session,
            canonical_json_bytes(&scoped_snapshot).expect("scoped session bytes"),
        );
        let composition =
            GovernorComposition::new(Arc::new(scoped), &expected, QueueLimits::default())
                .expect("composition");
        assert!(composition.read_unique_agent_activation(20).is_err());

        let stale_fence = StateFence::new(
            AuthorityEpoch::genesis(),
            ResourceGeneration::new(2).expect("generation"),
        );
        let mut stale_scope = activation_scope_snapshot(&stale_fence);
        stale_scope.state_fence = stale_fence;
        let mut stale = activation_fake(&observed);
        stale.payloads.insert(
            RecoveryOwner::WorkScope,
            canonical_json_bytes(&stale_scope).expect("stale scope bytes"),
        );
        assert!(
            GovernorComposition::new(Arc::new(stale), &expected, QueueLimits::default(),).is_err()
        );

        let mut stale_task = activation_task_snapshot(&observed.state_fence());
        stale_task
            .tasks
            .get_mut(&TaskId::new("task-1").expect("task id"))
            .expect("task")
            .state_fence = StateFence::new(
            AuthorityEpoch::genesis(),
            ResourceGeneration::new(2).expect("generation"),
        );
        let mut stale_task_fake = activation_fake(&observed);
        stale_task_fake.payloads.insert(
            RecoveryOwner::Task,
            canonical_json_bytes(&stale_task).expect("stale task bytes"),
        );
        assert!(
            GovernorComposition::new(Arc::new(stale_task_fake), &expected, QueueLimits::default(),)
                .is_err()
        );

        let mut stale_session = activation_session_snapshot(&observed.state_fence());
        stale_session
            .sessions
            .get_mut(&SessionId::new("session-1").expect("session id"))
            .expect("session")
            .state_fence = StateFence::new(
            AuthorityEpoch::genesis(),
            ResourceGeneration::new(2).expect("generation"),
        );
        let mut stale_session_fake = activation_fake(&observed);
        stale_session_fake.payloads.insert(
            RecoveryOwner::Session,
            canonical_json_bytes(&stale_session).expect("stale session bytes"),
        );
        assert!(
            GovernorComposition::new(
                Arc::new(stale_session_fake),
                &expected,
                QueueLimits::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn activation_rejects_non_actionable_task_and_canonical_join_mismatch() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");

        let mut terminal_snapshot = activation_task_snapshot(&observed.state_fence());
        terminal_snapshot
            .tasks
            .get_mut(&TaskId::new("task-1").expect("task id"))
            .expect("task")
            .state = TaskState::DoneVerified;
        let mut terminal = activation_fake(&observed);
        terminal.payloads.insert(
            RecoveryOwner::Task,
            canonical_json_bytes(&terminal_snapshot).expect("terminal task bytes"),
        );
        let composition =
            GovernorComposition::new(Arc::new(terminal), &expected, QueueLimits::default())
                .expect("composition");
        assert!(composition.read_unique_agent_activation(20).is_err());

        let mismatched_plan = CanonicalAdmissionSnapshot {
            state_fence: observed.state_fence(),
            owner_revision: 1,
            current_plan: Some(CanonicalPlanBinding {
                plan_id: "plan:current".to_owned(),
                plan_revision: "1".to_owned(),
                task_id: TaskId::new("task-other").expect("task id"),
                work_scope_id: "scope:work".to_owned(),
            }),
        };
        mismatched_plan.validate().expect("plan shape");
        let mut mismatch = activation_fake(&observed);
        mismatch.payloads.insert(
            RecoveryOwner::Canonical,
            canonical_json_bytes(&mismatched_plan).expect("mismatched plan bytes"),
        );
        let composition =
            GovernorComposition::new(Arc::new(mismatch), &expected, QueueLimits::default())
                .expect("composition");
        assert!(composition.read_unique_agent_activation(20).is_err());
    }

    #[test]
    fn activation_rejects_ambiguous_coordination_without_map_order_selection() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let mut fake = activation_fake(&observed);
        fake.payloads.insert(
            RecoveryOwner::Coordination,
            canonical_json_bytes(&activation_ambiguous_coordination_snapshot(
                &observed.state_fence(),
            ))
            .expect("ambiguous coordination bytes"),
        );
        let composition =
            GovernorComposition::new(Arc::new(fake), &expected, QueueLimits::default())
                .expect("composition");
        assert!(composition.read_unique_agent_activation(20).is_err());
    }

    #[test]
    fn payload_digest_and_partial_owner_state_fail_closed() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let mut fake = fake_kernel(observed.clone());
        let mut payload = owner_payload(
            RecoveryOwner::Task,
            &observed.state_fence(),
            &observed.protected_snapshot_digest,
        );
        payload.push(b'x');
        fake.payloads.insert(RecoveryOwner::Task, payload);
        let result = GovernorComposition::new(Arc::new(fake), &expected, QueueLimits::default());
        assert!(matches!(result, Err(CompositionError::Recovery(_))));

        let mut partial = fake_kernel(observed.clone());
        partial.missing = Some(RecoveryOwner::Task);
        let result = GovernorComposition::new(Arc::new(partial), &expected, QueueLimits::default());
        assert!(matches!(result, Err(CompositionError::Recovery(_))));
    }

    #[test]
    fn recovery_rejects_semantically_valid_noncanonical_owner_bytes() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let payloads = [
            br#"{"tasks":{},"next_sequence":1,"events":[]}"#.as_slice(),
            br#"{ "events": [], "next_sequence": 1, "tasks": {} }"#.as_slice(),
        ];
        for payload in payloads {
            let mut fake = fake_kernel(observed.clone());
            fake.payloads.insert(RecoveryOwner::Task, payload.to_vec());
            let result =
                GovernorComposition::new(Arc::new(fake), &expected, QueueLimits::default());
            assert!(matches!(
                result,
                Err(CompositionError::Recovery(message))
                    if message.contains("owner task payload is not canonical JSON")
            ));
        }
    }
}
