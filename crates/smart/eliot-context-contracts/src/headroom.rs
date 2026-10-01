//! I14.29 `DownstreamHeadroomReservation`: bounded request/response evidence.
//!
//! Context owns budget *meaning*; the existing Kernel resource/lease owner
//! reserves physical capacity and mints the permit this contract carries as
//! evidence ([`CapacityPermitBinding`]). This module is that evidence's shape
//! and its fail-closed validation only. It opens no socket, holds no client,
//! and reads no owner counter.
//!
//! Two rules from I14.29 shape every type here:
//!
//! - "Pipelines that can consume all currently free capacity reserve downstream
//!   headroom explicitly" and "This reservation is separate from Kernel Control
//!   Reserve." A granted dimension is therefore proven by an owner-issued permit
//!   binding, never by a caller flag, a subtraction from a nominal window, a
//!   shape-valid identifier, or a matching content hash. A dimension whose owner
//!   permit is stale, revoked, or bound to another generation reads as
//!   [`HeadroomOutcome::Unknown`], never as granted.
//! - "`CPU_memory_GPU_disk_network_context_model_and_queue_reservations`" are
//!   independent dimensions. Each carries its own owner
//!   [`CapacityBottleneck`] and [`CapacityUnit`]; no arithmetic in this module
//!   ever joins two dimensions, and none of them joins a token count.
//!
//! I12.13's no-double-counting rule lives in [`HeadroomAllocationLedger`]:
//! overlapping purposes map onto the *same* declared allocation, so an existing
//! output or review reserve is referenced once and never added a second time.

use std::collections::BTreeSet;
use std::num::NonZeroU64;

use eliot_contracts::{ArtifactId, OperationId, StateFence, TaskId};
use eliot_receipts::WorkScopeBinding;
use eliot_runtime_contracts::{
    CapacityBottleneck, CapacityLimit, CapacityPermitBinding, CapacityRequest, CapacityUnit,
    RequestedOperationClass,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    CapacityLimits, ContextBinding, ContextError, OmissionRecord, canonical_digest,
    validate_digest, validate_text,
};

/// Exact wire revision of the downstream headroom reservation contract.
pub const DOWNSTREAM_HEADROOM_SCHEMA_VERSION: u32 = 1;

/// Version of the admitted Orientation demand profile stored with its approved
/// Context recipe. Every row is a recipe-owned resource formula result in one
/// owner unit; request identity and authority fields are filled from the
/// original admitted job when the Governor compiles the request.
pub const ORIENTATION_HEADROOM_PROFILE_VERSION: u32 = 1;
/// Version of the admitted Orientation headroom supplier carrier.
pub const ADMITTED_ORIENTATION_HEADROOM_SCHEMA_VERSION: u32 = 1;

/// One approved, independent downstream capacity demand for Orientation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrientationHeadroomDemandProfile {
    /// The independent owner dimension this recipe protects.
    pub dimension: HeadroomDimension,
    /// The measured or formula-derived positive demand in that owner's unit.
    pub quantity: HeadroomQuantity,
    /// Work class permitted for this downstream request by the approved recipe.
    pub operation: RequestedOperationClass,
    /// Existing capacity owner's requester identity.
    pub requesting_owner_ref: String,
    /// Source artifact for the measured peak or approved formula input.
    pub source_fact: ArtifactId,
}

impl OrientationHeadroomDemandProfile {
    fn validate(&self, profile_id: &str, profile_revision: &str) -> Result<(), ContextError> {
        let Some(value) = self.quantity.known() else {
            return Err(ContextError::InvalidField(
                "orientation_headroom.demand.quantity",
            ));
        };
        if value.get() == 0 || self.quantity.unit() != Some(self.dimension.owner_unit()) {
            return Err(ContextError::InvalidField(
                "orientation_headroom.demand.quantity",
            ));
        }
        if self.dimension.owner_bottleneck().is_none() {
            return Err(ContextError::InvalidField(
                "orientation_headroom.demand.dimension",
            ));
        }
        validate_text(&self.requesting_owner_ref, "orientation_headroom.requesting_owner")?;
        validate_text(self.source_fact.as_str(), "orientation_headroom.source_fact")?;
        validate_text(profile_id, "orientation_headroom.profile_id")?;
        validate_text(profile_revision, "orientation_headroom.profile_revision")
    }
}

/// Approved recipe-owned Orientation downstream demand profile.
///
/// This profile stores the source-backed demand facts, not live capacity or a
/// permit. The Governor binds these facts to the original job, operation,
/// generation and deadline to form a `DownstreamHeadroomRequest`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrientationHeadroomProfileV1 {
    /// Exact profile schema version.
    pub schema_version: u32,
    /// Capacity owner's approved profile identity.
    pub profile_id: String,
    /// Capacity owner's approved profile revision.
    pub profile_revision: String,
    /// Exact admitted consumer protected by each demand.
    pub consumer: HeadroomConsumer,
    /// Exact stage at which the owner acquires the demand.
    pub stage_id: ArtifactId,
    /// Nonempty, duplicate-free set of measured/formula-derived demands.
    pub demands: Vec<OrientationHeadroomDemandProfile>,
    /// Approved cancellation release policy; completion identity and expiry
    /// come from the original admitted job when this profile is compiled.
    pub release_on_cancel: bool,
}

impl OrientationHeadroomProfileV1 {
    /// Validate the approved recipe profile without consulting live capacity.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.schema_version != ORIENTATION_HEADROOM_PROFILE_VERSION {
            return Err(ContextError::InvalidField(
                "orientation_headroom.schema_version",
            ));
        }
        validate_text(&self.profile_id, "orientation_headroom.profile_id")?;
        validate_text(&self.profile_revision, "orientation_headroom.profile_revision")?;
        validate_text(self.stage_id.as_str(), "orientation_headroom.stage_id")?;
        if self.demands.is_empty() || self.demands.len() > HeadroomDimension::DENOMINATOR.len() {
            return Err(ContextError::Bounds {
                field: "orientation_headroom.demands",
            });
        }
        let mut seen = BTreeSet::new();
        for demand in &self.demands {
            demand.validate(&self.profile_id, &self.profile_revision)?;
            if !seen.insert(demand.dimension) {
                return Err(ContextError::Duplicate(
                    "orientation_headroom.demands.dimension",
                ));
            }
        }
        Ok(())
    }

    /// Compile profile facts into exact owner requests under the original
    /// operation and State Fence. The demand values and their source facts are
    /// copied from the approved profile without deriving from owner capacity.
    pub fn compile_request(
        &self,
        pipeline_id: ArtifactId,
        attempt_id: ArtifactId,
        binding: ContextBinding,
        route_id: String,
        serializer_id: String,
        recipe_digest: String,
        operation_id: &OperationId,
        state_fence: &StateFence,
        deadline_ms: u64,
        completion_artifact_id: ArtifactId,
    ) -> Result<DownstreamHeadroomRequest, ContextError> {
        self.validate()?;
        binding.validate()?;
        validate_text(completion_artifact_id.as_str(), "headroom.release.completion_receipt")?;
        if deadline_ms == 0
            || binding.state_fence != *state_fence
            || binding.operation_id.as_ref() != Some(operation_id)
        {
            return Err(ContextError::IdentityConflict);
        }
        let mut demands = Vec::with_capacity(self.demands.len());
        for demand in &self.demands {
            let Some(bottleneck) = demand.dimension.owner_bottleneck() else {
                return Err(ContextError::InvalidField(
                    "orientation_headroom.demand.dimension",
                ));
            };
            let Some(quantity) = demand.quantity.known() else {
                return Err(ContextError::InvalidField(
                    "orientation_headroom.demand.quantity",
                ));
            };
            let owner_request = CapacityRequest {
                operation: demand.operation,
                operation_id: operation_id.to_string(),
                requested_bottleneck: bottleneck,
                requested_limit: CapacityLimit {
                    unit: demand.dimension.owner_unit(),
                    quantity,
                },
                requesting_owner_ref: demand.requesting_owner_ref.clone(),
                requesting_generation_ref: state_fence.resource_generation,
                authority_epoch_ref: state_fence.authority_epoch.clone(),
                profile_id: self.profile_id.clone(),
                profile_revision: self.profile_revision.clone(),
                deadline_ms,
            };
            owner_request
                .validate()
                .map_err(|_| ContextError::InvalidField("orientation_headroom.capacity_request"))?;
            demands.push(HeadroomDemand {
                dimension: demand.dimension,
                quantity: demand.quantity.clone(),
                request: owner_request,
            });
        }
        let request = DownstreamHeadroomRequest {
            schema_version: DOWNSTREAM_HEADROOM_SCHEMA_VERSION,
            pipeline_id,
            attempt_id,
            stage_id: self.stage_id.clone(),
            consumer: self.consumer,
            binding,
            route_id,
            serializer_id,
            recipe_digest,
            demands,
            release: HeadroomReleaseCondition {
                completion_receipt: completion_artifact_id,
                release_on_cancel: self.release_on_cancel,
                expires_at_ms: deadline_ms,
            },
        };
        request.validate()?;
        Ok(request)
    }
}

/// Original admitted Orientation demand request plus its exact job and
/// candidate closure. This is the neutral handoff consumed by the runtime
/// owner; it grants no permit and is not a second reservation ledger.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmittedOrientationHeadroomSupplyV1 {
    /// Exact carrier schema version.
    pub schema_version: u32,
    /// Original request containing every actual per-dimension owner request.
    pub request: DownstreamHeadroomRequest,
    /// Canonical digest retained from the original request producer.
    pub request_digest: String,
    /// Exact Orientation candidate this demand protects.
    pub candidate_digest: String,
    /// Original pipeline identity duplicated for closure comparison.
    pub pipeline_id: ArtifactId,
    /// Original durable job and Governor task identities.
    pub job_id: TaskId,
    pub task_id: TaskId,
    /// Original attempt and full work-scope closure.
    pub attempt_id: ArtifactId,
    pub work_scope: WorkScopeBinding,
    /// Full original context binding and State Fence.
    pub context_binding: ContextBinding,
    pub state_fence: StateFence,
    /// Exact admitted operation identity.
    pub operation_id: OperationId,
    /// Original source revision used by the recipe/context supplier.
    pub source_revision: String,
    /// Original operation deadline.
    pub deadline_ms: u64,
    /// Exact completion artifact and its release policy.
    pub completion_artifact_id: ArtifactId,
    pub release: HeadroomReleaseCondition,
}

impl AdmittedOrientationHeadroomSupplyV1 {
    /// Reject any split between the original request and job/candidate closure.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.schema_version != ADMITTED_ORIENTATION_HEADROOM_SCHEMA_VERSION {
            return Err(ContextError::InvalidField(
                "admitted_orientation_headroom.schema_version",
            ));
        }
        self.request.validate()?;
        self.context_binding.validate()?;
        self.state_fence
            .validate()
            .map_err(|_| ContextError::InvalidFence)?;
        self.work_scope
            .state_fence
            .validate()
            .map_err(|_| ContextError::InvalidFence)?;
        validate_digest(&self.request_digest, "admitted_orientation_headroom.request_digest")?;
        validate_digest(
            &self.candidate_digest,
            "admitted_orientation_headroom.candidate_digest",
        )?;
        validate_text(
            &self.source_revision,
            "admitted_orientation_headroom.source_revision",
        )?;
        validate_text(self.job_id.as_str(), "admitted_orientation_headroom.job_id")?;
        validate_text(self.task_id.as_str(), "admitted_orientation_headroom.task_id")?;
        validate_text(
            self.operation_id.as_str(),
            "admitted_orientation_headroom.operation_id",
        )?;
        if self.request.canonical_digest()? != self.request_digest
            || self.request.pipeline_id != self.pipeline_id
            || self.request.attempt_id != self.attempt_id
            || self.request.binding != self.context_binding
            || self.request.binding.task_id != self.task_id
            || self.request.binding.operation_id.as_ref() != Some(&self.operation_id)
            || self.request.binding.state_fence != self.state_fence
            || self.work_scope.scope_id != self.context_binding.scope_id
            || self.work_scope.state_fence != self.state_fence
            || self.work_scope.resource_generation != self.state_fence.resource_generation
            || self.request.release != self.release
            || self.request.release.completion_receipt != self.completion_artifact_id
            || self.release.expires_at_ms != self.deadline_ms
            || self.request.demands.iter().any(|demand| {
                demand.request.operation_id != self.operation_id.as_str()
                    || demand.request.deadline_ms != self.deadline_ms
                    || demand.request.requesting_generation_ref
                        != self.state_fence.resource_generation
                    || !demand
                        .request
                        .authority_epoch_ref
                        .is_same_authority(&self.state_fence.authority_epoch)
            })
        {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }
}

/// One independent downstream capacity dimension.
///
/// The closed set is the denominator every result is checked against: a result
/// carries exactly one [`HeadroomDecision`] per value, never per value the
/// caller happened to ask about. Each dimension has exactly one owner
/// bottleneck and one owner unit, so a quantity in one dimension can never be
/// compared with, or added to, a quantity in another.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HeadroomDimension {
    /// Control-task slots on the Kernel runtime/control scheduler owner.
    Cpu,
    /// Protected memory bytes on the Kernel/runtime memory-budget owner.
    Memory,
    /// Accelerator device slots on the platform/device owner.
    Gpu,
    /// Disk queue/write slots on the declared spool owner.
    Disk,
    /// Pipe/message bytes on the IPC/control-channel owner.
    Network,
    /// Model invocation quota on the model/provider owner.
    ModelQuota,
    /// Runnable slots on the Kernel runtime/control scheduler owner.
    Queue,
}

impl HeadroomDimension {
    /// The complete independent denominator, in wire order.
    pub const DENOMINATOR: [Self; 7] = [
        Self::Cpu,
        Self::Memory,
        Self::Gpu,
        Self::Disk,
        Self::Network,
        Self::ModelQuota,
        Self::Queue,
    ];

    /// The exact frozen contract identifier.
    #[must_use]
    pub const fn as_contract_str(self) -> &'static str {
        match self {
            Self::Cpu => "CPU",
            Self::Memory => "MEMORY",
            Self::Gpu => "GPU",
            Self::Disk => "DISK",
            Self::Network => "NETWORK",
            Self::ModelQuota => "MODEL_QUOTA",
            Self::Queue => "QUEUE",
        }
    }

    /// The one owner bottleneck that can physically reserve this dimension.
    ///
    /// `Gpu` and `ModelQuota` have no row in the frozen I14
    /// `frozen_bottleneck_owner_map` denominator. They stay in this closed set
    /// so a pipeline that needs them is refused as unavailable rather than
    /// silently dropped from the denominator; see
    /// [`HeadroomOutcome::NotApplicable`].
    #[must_use]
    pub const fn owner_bottleneck(self) -> Option<CapacityBottleneck> {
        match self {
            Self::Cpu => Some(CapacityBottleneck::CpuControlTaskSlots),
            Self::Memory => Some(CapacityBottleneck::ProtectedMemoryBytes),
            Self::Disk => Some(CapacityBottleneck::DiskQueueWriteCapacity),
            Self::Network => Some(CapacityBottleneck::PipeMessageBytes),
            Self::Queue => Some(CapacityBottleneck::KernelRunnableControlSlots),
            Self::Gpu | Self::ModelQuota => None,
        }
    }

    /// The exact owner unit of this dimension.
    ///
    /// This is the owner vocabulary's unit, not a token count: a Context budget
    /// and a CPU or memory reservation are never the same measurement.
    #[must_use]
    pub const fn owner_unit(self) -> CapacityUnit {
        match self.owner_bottleneck() {
            Some(bottleneck) => bottleneck.unit(),
            None => CapacityUnit::Items,
        }
    }
}

/// One demanded amount in one dimension.
///
/// `Unknown` is its own state, never zero: an owner that could not determine a
/// dimension reports [`HeadroomQuantity::Unknown`], and this contract refuses to
/// read that as an empty demand that trivially fits.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum HeadroomQuantity {
    /// A positive owner-unit amount.
    Known {
        /// The owner unit; it must equal the dimension's owner unit.
        unit: CapacityUnit,
        /// Strictly positive amount; zero demand is not representable.
        value: NonZeroU64,
    },
    /// The owner could not determine this dimension. This is not zero.
    Unknown {
        /// Owner reason identity for the undetermined amount.
        reason: ArtifactId,
    },
}

impl HeadroomQuantity {
    /// Return the known amount, or `None` when the owner did not determine it.
    #[must_use]
    pub const fn known(&self) -> Option<NonZeroU64> {
        match self {
            Self::Known { value, .. } => Some(*value),
            Self::Unknown { .. } => None,
        }
    }

    /// The owner unit of a known amount, or `None` when it is undetermined.
    #[must_use]
    pub const fn unit(&self) -> Option<CapacityUnit> {
        match self {
            Self::Known { unit, .. } => Some(*unit),
            Self::Unknown { .. } => None,
        }
    }

    /// Refuse a known amount recorded in any unit other than `expected`.
    fn validate_unit(
        &self,
        expected: CapacityUnit,
        field: &'static str,
    ) -> Result<(), ContextError> {
        match self {
            Self::Known { unit, .. } if *unit != expected => Err(ContextError::InvalidField(field)),
            Self::Known { .. } | Self::Unknown { .. } => Ok(()),
        }
    }
}

/// The downstream consumer this reservation protects.
///
/// I14.29 names reduction, verification, synthesis, export and response
/// generation; I12.13 adds the decision-local tail and tool-result headroom a
/// long packet must leave behind.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HeadroomConsumer {
    /// Swarm reduction of already-collected material.
    Reducer,
    /// Verification of a candidate or artifact.
    Verifier,
    /// Synthesis of admitted material into a response.
    Synthesis,
    /// Export of a finished packet or artifact.
    Exporter,
    /// Response generation for the decision.
    Responder,
    /// Decision-local tail retained for the next step.
    DecisionTail,
    /// Tool-result headroom for an advertised tool.
    ToolResult,
}

/// The condition under which the owner releases the reservation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HeadroomReleaseCondition {
    /// Owner receipt identity for the terminal downstream completion.
    pub completion_receipt: ArtifactId,
    /// Whether the reservation returns on cancellation as well as completion.
    pub release_on_cancel: bool,
    /// Absolute expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl HeadroomReleaseCondition {
    fn validate(&self) -> Result<(), ContextError> {
        validate_text(
            self.completion_receipt.as_str(),
            "headroom.release.completion_receipt",
        )
    }
}

/// One demanded dimension plus the exact owner request submitted for it.
///
/// The [`CapacityRequest`] is the request the owner validates, not a summary of
/// it: a result can only be matched back through
/// [`CapacityPermitBinding::matches_request`], so a permit issued for a
/// different operation, bottleneck, unit, owner generation or profile revision
/// never matches.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HeadroomDemand {
    /// The independent dimension this demand names.
    pub dimension: HeadroomDimension,
    /// The bounded amount demanded in that dimension.
    pub quantity: HeadroomQuantity,
    /// The exact owner request submitted for this dimension.
    pub request: CapacityRequest,
}

impl HeadroomDemand {
    fn validate(&self) -> Result<(), ContextError> {
        self.quantity
            .validate_unit(self.dimension.owner_unit(), "headroom.demand.quantity")?;
        let Some(bottleneck) = self.dimension.owner_bottleneck() else {
            return Err(ContextError::InvalidField("headroom.demand.dimension"));
        };
        if self.request.requested_bottleneck != bottleneck
            || self.request.requested_limit.unit != self.dimension.owner_unit()
        {
            return Err(ContextError::InvalidField("headroom.demand.request"));
        }
        self.request
            .validate()
            .map_err(|_| ContextError::InvalidField("headroom.demand.request"))?;
        if let HeadroomQuantity::Known { value, .. } = &self.quantity
            && value.get() != self.request.requested_limit.quantity.get()
        {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }
}

/// The bounded request the runtime caller submits before optional filling.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DownstreamHeadroomRequest {
    /// Exact wire revision.
    pub schema_version: u32,
    /// Pipeline identity the reservation protects.
    pub pipeline_id: ArtifactId,
    /// Attempt identity within that pipeline.
    pub attempt_id: ArtifactId,
    /// Stage identity the reservation covers.
    pub stage_id: ArtifactId,
    /// The downstream consumer this reservation protects.
    pub consumer: HeadroomConsumer,
    /// Task/attempt/scope/decision/fence the reservation is bound to.
    pub binding: ContextBinding,
    /// Exact route identity.
    pub route_id: String,
    /// Exact serializer identity the budget was compiled against.
    pub serializer_id: String,
    /// Exact recipe revision this reservation was compiled under.
    pub recipe_digest: String,
    /// One entry per demanded dimension; duplicates are refused.
    pub demands: Vec<HeadroomDemand>,
    /// The owner's release condition.
    pub release: HeadroomReleaseCondition,
}

impl DownstreamHeadroomRequest {
    /// Validate the bounded request and bind its identity.
    ///
    /// No default is filled: a request that names no demand, an ownerless
    /// dimension, a mismatched owner request or a duplicated dimension fails
    /// here rather than reaching the owner.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.schema_version != DOWNSTREAM_HEADROOM_SCHEMA_VERSION {
            return Err(ContextError::InvalidField("headroom.schema_version"));
        }
        self.binding.validate()?;
        validate_text(self.pipeline_id.as_str(), "headroom.pipeline_id")?;
        validate_text(self.attempt_id.as_str(), "headroom.attempt_id")?;
        validate_text(self.stage_id.as_str(), "headroom.stage_id")?;
        validate_text(self.route_id.as_str(), "headroom.route_id")?;
        validate_text(self.serializer_id.as_str(), "headroom.serializer_id")?;
        validate_digest(&self.recipe_digest, "headroom.recipe_digest")?;
        self.release.validate()?;
        if self.demands.is_empty() || self.demands.len() > HeadroomDimension::DENOMINATOR.len() {
            return Err(ContextError::Bounds {
                field: "headroom.demands",
            });
        }
        let mut seen = BTreeSet::new();
        for demand in &self.demands {
            demand.validate()?;
            if !seen.insert(demand.dimension) {
                return Err(ContextError::Duplicate("headroom.demands.dimension"));
            }
        }
        Ok(())
    }

    /// The canonical digest an owner result must cite to match this request.
    pub fn canonical_digest(&self) -> Result<String, ContextError> {
        canonical_digest(self)
    }

    /// The demand submitted for one dimension, if it names one.
    #[must_use]
    pub fn demand(&self, dimension: HeadroomDimension) -> Option<&HeadroomDemand> {
        self.demands
            .iter()
            .find(|demand| demand.dimension == dimension)
    }
}

/// One dimension's owner outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum HeadroomOutcome {
    /// The owner reserved this dimension and issued a permit for it.
    ///
    /// The permit is the reservation. There is deliberately no `reserved`
    /// boolean and no caller-supplied capacity figure here: without an
    /// owner-minted [`CapacityPermitBinding`] this variant cannot be built.
    Granted {
        /// The owner-issued permit binding for this dimension.
        ///
        /// Boxed because the permit binding is an order of magnitude wider
        /// than this enum's other outcomes' payloads: one granted decision
        /// would otherwise make every decision in a result pay that width,
        /// including the refused and unknown ones that carry no permit. The
        /// box is a storage detail only — the wire shape is unchanged, and a
        /// grant is still read through [`CapacityPermitBinding`] by value.
        reservation: Box<CapacityPermitBinding>,
        /// The demand the owner actually admitted, in the owner unit.
        admitted_demand: HeadroomQuantity,
    },
    /// The owner refused this dimension; it holds no reservation for it.
    Refused {
        /// Owner refusal reason identity.
        reason: ArtifactId,
        /// Owner evidence references supporting the refusal.
        evidence_refs: Vec<ArtifactId>,
    },
    /// The owner could not determine this dimension, or its reservation is
    /// stale or revoked. Not granted, and not zero demand.
    Unknown {
        /// Owner reason identity.
        reason: ArtifactId,
        /// Owner evidence references for the undetermined or stale state.
        evidence_refs: Vec<ArtifactId>,
    },
    /// This dimension does not apply to this pipeline.
    ///
    /// The explicit form of "no GPU on this host" or "no model quota on this
    /// route". It exists so an inapplicable dimension is a recorded owner fact
    /// rather than a missing entry a reader could mistake for an omission.
    NotApplicable {
        /// Owner applicability-basis identity.
        basis: ArtifactId,
    },
}

impl HeadroomOutcome {
    /// The owner-issued permit for this dimension, when one was granted.
    ///
    /// `None` for every other outcome, so a caller cannot read a refusal,
    /// an unknown state or an inapplicable dimension as a reservation.
    #[must_use]
    pub const fn reservation(&self) -> Option<&CapacityPermitBinding> {
        match self {
            // Deref coercion through the box, at a binding with an explicit
            // type so the coercion site is this `let` and not the return value.
            // `Box::as_ref` is not usable here: this accessor is `const`, and
            // the box is a storage detail the caller must never see.
            Self::Granted { reservation, .. } => {
                let binding: &CapacityPermitBinding = reservation;
                Some(binding)
            }
            Self::Refused { .. } | Self::Unknown { .. } | Self::NotApplicable { .. } => None,
        }
    }

    fn validate(&self, field: &'static str) -> Result<(), ContextError> {
        match self {
            Self::Granted {
                reservation,
                admitted_demand,
            } => {
                reservation
                    .validate()
                    .map_err(|_| ContextError::InvalidField(field))?;
                admitted_demand.validate_unit(
                    reservation.bottleneck.unit(),
                    "headroom.decision.admitted_demand",
                )
            }
            Self::Refused {
                reason,
                evidence_refs,
            }
            | Self::Unknown {
                reason,
                evidence_refs,
            } => {
                validate_text(reason.as_str(), field)?;
                if evidence_refs.len() > 64 {
                    return Err(ContextError::Bounds {
                        field: "headroom.decision.evidence_refs",
                    });
                }
                Ok(())
            }
            Self::NotApplicable { basis } => validate_text(basis.as_str(), field),
        }
    }
}

/// The inverse of [`HeadroomDimension::owner_bottleneck`].
///
/// Returns the dimension a granted permit belongs to, or `None` when the owner
/// bottleneck has no row in this contract's closed denominator. A grant on such
/// a bottleneck cannot be attributed to a demanded dimension and is therefore
/// not a grant of any dimension here.
pub(crate) fn dimension_of(bottleneck: CapacityBottleneck) -> Option<HeadroomDimension> {
    HeadroomDimension::DENOMINATOR
        .into_iter()
        .find(|dimension| dimension.owner_bottleneck() == Some(bottleneck))
}

/// One dimension's outcome inside a result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HeadroomDecision {
    /// The dimension this decision is about.
    pub dimension: HeadroomDimension,
    /// The owner's outcome for that dimension.
    pub outcome: HeadroomOutcome,
}

impl HeadroomDecision {
    fn validate(&self) -> Result<(), ContextError> {
        self.outcome
            .validate("headroom.decision.outcome")
            .map_err(|error| match error {
                ContextError::InvalidField(_) => {
                    ContextError::InvalidField("headroom.decision.outcome")
                }
                other => other,
            })
    }
}

/// The owner's versioned answer to one [`DownstreamHeadroomRequest`].
///
/// This is validated owner evidence, not an IO client: it is plain data that
/// the pure compiler can check without a transport, and it carries the
/// owner-issued permit for every granted dimension.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DownstreamHeadroomResult {
    /// Exact wire revision.
    pub schema_version: u32,
    /// Canonical digest of the exact request this answers.
    pub request_digest: String,
    /// The binding the owner reserved under.
    pub binding: ContextBinding,
    /// Exactly one decision per value of [`HeadroomDimension`].
    pub decisions: Vec<HeadroomDecision>,
    /// Owner issuance time in Unix milliseconds.
    pub issued_at_ms: u64,
    /// Absolute expiry of this result in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Measurement references supporting each admitted amount.
    pub measurement_refs: Vec<ArtifactId>,
    /// Reconciliation references for the owner's release/reconcile path.
    pub reconciliation_refs: Vec<ArtifactId>,
}

impl DownstreamHeadroomResult {
    /// Validate this result against its request, the live fence and the clock.
    ///
    /// `current_fence` and `now_ms` are supplied by the caller at the moment of
    /// use, never read from this record, so a stale or revoked reservation
    /// cannot certify itself. Every check below fails closed:
    ///
    /// - the schema revision is exact and the cited request digest is the
    ///   canonical digest of *this* request;
    /// - the binding is the request's binding, fence included;
    /// - the decision set is exactly the independent
    ///   [`HeadroomDimension::DENOMINATOR`], once per value, so completeness is
    ///   checked against a closed set rather than a copy of the caller's list;
    /// - every granted permit validates under the owner's own contract and
    ///   matches the demand's request through
    ///   [`CapacityPermitBinding::matches_request`];
    /// - every granted permit carries the live fence's authority epoch and
    ///   requester generation, so a permit from a superseded generation reads
    ///   as unknown, never as granted;
    /// - every granted permit is still inside its own expiry at `now_ms`;
    /// - every demanded dimension reached a grant, refusal or unknown state,
    ///   and a demand the owner marked not-applicable is refused here rather
    ///   than read as satisfied.
    pub fn validate_against(
        &self,
        request: &DownstreamHeadroomRequest,
        current_fence: &crate::ContextBinding,
        now_ms: u64,
    ) -> Result<(), ContextError> {
        request.validate()?;
        if self.schema_version != DOWNSTREAM_HEADROOM_SCHEMA_VERSION {
            return Err(ContextError::InvalidField("headroom_result.schema_version"));
        }
        validate_digest(&self.request_digest, "headroom_result.request_digest")?;
        if self.request_digest != request.canonical_digest()? {
            return Err(ContextError::IdentityConflict);
        }
        if self.binding != request.binding || &self.binding != current_fence {
            return Err(ContextError::InvalidFence);
        }
        self.binding.validate()?;
        if self.expires_at_ms <= self.issued_at_ms || now_ms >= self.expires_at_ms {
            return Err(ContextError::InvalidField("headroom_result.expires_at_ms"));
        }
        let expected = HeadroomDimension::DENOMINATOR;
        if self.decisions.len() != expected.len() {
            return Err(ContextError::DenominatorMismatch);
        }
        let mut seen = BTreeSet::new();
        for decision in &self.decisions {
            decision.validate()?;
            if !seen.insert(decision.dimension) {
                return Err(ContextError::Duplicate(
                    "headroom_result.decisions.dimension",
                ));
            }
        }
        if seen != expected.iter().copied().collect::<BTreeSet<_>>() {
            return Err(ContextError::DenominatorMismatch);
        }
        for dimension in expected {
            let decision = self
                .decisions
                .iter()
                .find(|decision| decision.dimension == dimension)
                .ok_or(ContextError::DenominatorMismatch)?;
            let Some(demand) = request.demand(dimension) else {
                // An undemanded dimension must not carry a reservation: a
                // permit nobody asked for is not headroom for this pipeline.
                if decision.outcome.reservation().is_some() {
                    return Err(ContextError::IdentityConflict);
                }
                continue;
            };
            match &decision.outcome {
                HeadroomOutcome::Granted {
                    reservation,
                    admitted_demand,
                } => {
                    if !reservation.matches_request(&demand.request) {
                        return Err(ContextError::IdentityConflict);
                    }
                    let owner_dimension = dimension_of(reservation.bottleneck)
                        .ok_or(ContextError::DenominatorMismatch)?;
                    if owner_dimension != dimension {
                        return Err(ContextError::IdentityConflict);
                    }
                    // `HeadroomQuantity::unit` returns `None` for exactly one
                    // reason: the quantity is `HeadroomQuantity::Unknown`, i.e.
                    // the owner could not determine the admitted amount. An
                    // unstated unit is UNKNOWN, and unknown is neither zero
                    // nor "equal to whatever the owner's unit happens to be",
                    // so `None != Some(owner_unit)` refuses it here. That is
                    // deliberate fail-closed behaviour, not an over-refusal: a
                    // `Granted` outcome whose admitted amount the owner could
                    // not determine is a self-contradicting grant, and the
                    // module rule is that `Unknown` is its own state and never
                    // reads as satisfied. The right-hand side is wrapped in `Some(..)` so both
                    // sides share a type; that wrapping REFUSES rather than accepts, because
                    // `None != Some(owner_unit)` is true. It does not assert the owner's unit
                    // on the owner's behalf: `!=` never equates an absent unit with a
                    // stated one.
                    //
                    // Do NOT "fix" this by SUBSTITUTING the owner's unit, i.e.
                    // `admitted_demand.unit().unwrap_or(dimension.owner_unit())` or
                    // `.map(|u| u == dimension.owner_unit()).unwrap_or(true)`. Either turns an
                    // undetermined admission into an accepted one, which is the fabrication
                    // this contract exists to refuse.
                    if admitted_demand.unit() != Some(dimension.owner_unit())
                        || admitted_demand.known().is_none()
                    {
                        return Err(ContextError::UnknownMeasurement);
                    }
                    if !reservation
                        .authority_epoch_ref
                        .is_same_authority(&current_fence.state_fence.authority_epoch)
                        || reservation.requesting_generation_ref
                            != current_fence.state_fence.resource_generation
                        || now_ms >= reservation.expires_at_ms
                    {
                        return Err(ContextError::StaleFloor);
                    }
                }
                HeadroomOutcome::NotApplicable { .. } => {
                    return Err(ContextError::MissingFloor);
                }
                HeadroomOutcome::Refused { .. } | HeadroomOutcome::Unknown { .. } => {}
            }
        }
        Ok(())
    }

    /// The owner-issued reservation for one dimension, when it is granted.
    ///
    /// A stale, revoked, refused, unknown or inapplicable dimension yields
    /// `None` here and is refused by
    /// [`Self::validate_against`] before this accessor is reached on a bound
    /// result.
    #[must_use]
    pub fn reservation(&self, dimension: HeadroomDimension) -> Option<&CapacityPermitBinding> {
        self.decisions
            .iter()
            .find(|decision| decision.dimension == dimension)
            .and_then(|decision| decision.outcome.reservation())
    }
}

/// Why dependent action-ready publication is withheld.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum HeadroomRefusal {
    /// The reservation evidence itself failed validation.
    Stale {
        /// Owner reason identity.
        reason: ArtifactId,
    },
    /// A demanded dimension the owner did not grant.
    Unavailable {
        /// Dimensions that are refused, unknown or not applicable.
        dimensions: Vec<HeadroomDimension>,
    },
    /// The route, serializer or recipe changed after the reservation was issued.
    IdentityChanged {
        /// Owner reason identity for the observed change.
        reason: ArtifactId,
    },
    /// The final rendered output overflowed the reserved envelope.
    PostRenderOverflow {
        /// Owner reason identity for the overflow observation.
        reason: ArtifactId,
    },
}

/// The attempted recipe and omissions preserved when publication is withheld.
///
/// I12.13 requires the attempted recipe and the exact omissions to survive the
/// refusal, so a dependent operation is blocked without the packet looking
/// nominally complete.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HeadroomAttempt {
    /// The recipe revision this compilation actually attempted.
    pub attempted_recipe_digest: String,
    /// The exact omission records this compilation produced.
    pub omissions: Vec<OmissionRecord>,
    /// Why dependent action-ready publication is withheld.
    pub refusal: HeadroomRefusal,
}

impl std::fmt::Display for HeadroomAttempt {
    /// Names the recipe revision this compilation actually attempted and the
    /// owner-issued refusal that withheld publication.
    ///
    /// This is a diagnostic rendering, not authority: the digests and the
    /// refusal are the owner's records and are reproduced verbatim. Nothing is
    /// derived, defaulted or normalised here, so an error message can never
    /// restate a failed admission as a satisfied one.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "recipe {} withheld: {:?}",
            self.attempted_recipe_digest, self.refusal
        )
    }
}

/// The release instruction the owner must execute for one granted dimension.
///
/// I14.29 requires release or reconcile "through its owner" on failure,
/// cancellation and downstream completion. This is the instruction; the
/// non-clone permit handle stays with the issuing owner, so this record is
/// evidence of the intended terminal state and never itself a release.
///
/// The terminal check is the owner's own
/// [`eliot_runtime_contracts::CapacityReleaseEvidence::matches_binding`], not a
/// Context-side restatement of it: Context holds no permit handle and therefore
/// has no release authority to exercise, so it never re-decides whether a
/// release closed the permit it names.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HeadroomReleaseInstruction {
    /// The exact permit whose reservation is being released or reconciled.
    pub permit_id: String,
    /// The operation the permit was granted for.
    pub operation_id: String,
    /// The condition under which the owner terminates the reservation.
    pub condition: HeadroomReleaseCondition,
}

/// One independent purpose a Context packet must keep explicit.
///
/// I12.13: "Keep context occupancy, output, review/reasoning, decision-tail and
/// tool-result requirements explicit and separate."
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HeadroomPurpose {
    /// Context occupancy: admitted required plus optional material.
    ContextOccupancy,
    /// Response output capacity.
    Output,
    /// Review and reasoning capacity.
    ReviewReasoning,
    /// The decision-local tail a long packet leaves behind.
    DecisionTail,
    /// Advertised-tool result headroom.
    ToolResult,
}

impl HeadroomPurpose {
    /// The complete purpose denominator, in wire order.
    pub const DENOMINATOR: [Self; 5] = [
        Self::ContextOccupancy,
        Self::Output,
        Self::ReviewReasoning,
        Self::DecisionTail,
        Self::ToolResult,
    ];

    /// The exact frozen contract identifier.
    #[must_use]
    pub const fn as_contract_str(self) -> &'static str {
        match self {
            Self::ContextOccupancy => "CONTEXT_OCCUPANCY",
            Self::Output => "OUTPUT",
            Self::ReviewReasoning => "REVIEW_REASONING",
            Self::DecisionTail => "DECISION_TAIL",
            Self::ToolResult => "TOOL_RESULT",
        }
    }
}

/// One purpose's share of the declared route allocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PurposeAllocation {
    /// The purpose this share belongs to.
    pub purpose: HeadroomPurpose,
    /// The share, in the declared measurement unit of the route capacity.
    pub share: u64,
}

/// The no-double-counting ledger over one route's declared reserves.
///
/// Every reserve is read from the existing owner record
/// ([`CapacityLimits`]) rather than restated, so `output_reserve` and
/// `review_reserve` are *referenced* by the `Output` and `ReviewReasoning`
/// purposes and never added a second time. Context occupancy is the remainder
/// the ledger then measures against.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HeadroomAllocationLedger {
    /// The route capacity envelope these shares are measured against.
    pub capacity: CapacityLimits,
    /// One entry per purpose; a duplicate purpose is refused.
    pub allocations: Vec<PurposeAllocation>,
}

impl HeadroomAllocationLedger {
    /// Build a ledger from an existing capacity record, with no purpose shares.
    #[must_use]
    pub fn new(capacity: CapacityLimits) -> Self {
        Self {
            capacity,
            allocations: Vec::new(),
        }
    }

    /// Bind one purpose to its share of the declared allocation.
    ///
    /// A second bind for the same purpose is refused: that is the duplicate
    /// reserve I12.13 forbids. Use [`Self::bind_overlapping`] to map an
    /// overlapping purpose onto an already-declared allocation instead.
    pub fn bind(&mut self, purpose: HeadroomPurpose, share: u64) -> Result<(), ContextError> {
        if self.purpose(purpose).is_some() {
            return Err(ContextError::Duplicate("headroom.purpose"));
        }
        self.allocations.push(PurposeAllocation { purpose, share });
        Ok(())
    }

    /// Map an additional purpose onto an already-declared purpose's allocation.
    ///
    /// I12.13: "Map overlapping purposes to the same declared allocation where
    /// appropriate; do not add an existing output/review reserve twice." The
    /// added purpose therefore carries no quantity of its own: it shares the
    /// declared allocation and reuses that allocation's share verbatim.
    pub fn bind_overlapping(
        &mut self,
        purpose: HeadroomPurpose,
        onto: HeadroomPurpose,
    ) -> Result<(), ContextError> {
        if self.purpose(purpose).is_some() {
            return Err(ContextError::Duplicate("headroom.purpose"));
        }
        let share = self
            .purpose(onto)
            .ok_or(ContextError::MissingField("headroom.overlap_source"))?
            .share;
        self.allocations.push(PurposeAllocation { purpose, share });
        Ok(())
    }

    /// The share bound to one purpose, if any.
    #[must_use]
    pub fn purpose(&self, purpose: HeadroomPurpose) -> Option<&PurposeAllocation> {
        self.allocations
            .iter()
            .find(|allocation| allocation.purpose == purpose)
    }

    /// Checked sum over the declared route allocation.
    ///
    /// Refuses overflow rather than wrapping, and refuses a sum that exceeds the
    /// declared route capacity.
    pub fn total(&self) -> Result<u64, ContextError> {
        self.allocations
            .iter()
            .try_fold(0_u64, |total, allocation| {
                total
                    .checked_add(allocation.share)
                    .ok_or(ContextError::Overflow)
            })
    }

    /// Reconcile every purpose against the declared reserves.
    ///
    /// The ledger must bind the complete [`HeadroomPurpose`] denominator once
    /// each; `Output` must equal the declared `output_reserve` and
    /// `ReviewReasoning` the declared `review_reserve` exactly, so an existing
    /// reserve cannot be counted twice under a second name; the total must stay
    /// inside the declared route capacity with checked arithmetic.
    pub fn reconcile(&self) -> Result<(), ContextError> {
        self.capacity.validate()?;
        let mut seen = BTreeSet::new();
        for allocation in &self.allocations {
            if !seen.insert(allocation.purpose) {
                return Err(ContextError::Duplicate("headroom.purpose"));
            }
        }
        let expected = HeadroomPurpose::DENOMINATOR;
        if seen != expected.iter().copied().collect::<BTreeSet<_>>() {
            return Err(ContextError::DenominatorMismatch);
        }
        // Fail closed on the missing entry rather than asserting: this
        // validator is reachable from untrusted wire data, so it must return
        // a refusal, never panic, even on a path the denominator check above
        // already makes unreachable.
        let output_share = self
            .purpose(HeadroomPurpose::Output)
            .ok_or(ContextError::DenominatorMismatch)?
            .share;
        if output_share != self.capacity.output_reserve {
            return Err(ContextError::EconomyMismatch);
        }
        let review_share = self
            .purpose(HeadroomPurpose::ReviewReasoning)
            .ok_or(ContextError::DenominatorMismatch)?
            .share;
        if review_share != self.capacity.review_reserve {
            return Err(ContextError::EconomyMismatch);
        }
        if self.total()? > self.capacity.route_capacity {
            return Err(ContextError::CapacityExceeded);
        }
        Ok(())
    }

    /// The occupancy this ledger leaves for admitted material.
    ///
    /// The declared fixed overhead and the referenced output and review
    /// reserves are subtracted once, in the route's own declared measurement
    /// unit. No headroom dimension enters this arithmetic.
    pub fn occupancy_available(&self) -> Result<u64, ContextError> {
        self.capacity
            .route_capacity
            .checked_sub(self.capacity.fixed_overhead)
            .and_then(|value| value.checked_sub(self.capacity.output_reserve))
            .and_then(|value| value.checked_sub(self.capacity.review_reserve))
            .ok_or(ContextError::CapacityExceeded)
    }
}
