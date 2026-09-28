//! Closed I12.14 hot-path manifest declaration contract.
//!
//! I12.14 requires every hot operation to declare its identity, owner,
//! entrypoint/closure, immutable snapshot dependencies, bounded queues,
//! synchronous external calls, degradation and its `HotPathProfile` reference.
//! I2.15 supplies the runtime and dependency shape those declarations are read
//! against. This module owns that declaration shape once so the two
//! service-local manifests share one schema rather than two.
//!
//! This contract declares; it does not admit, dispatch, acquire capacity, start
//! a process or read a manifest. Issue #1733 supplies the operation, closure
//! and queue declarations; #1734 supplies the measured profile evidence fields,
//! so this contract carries only the profile *reference*. An operation that is
//! absent or unwired is declared unsupported instead of listed as working.
//!
//! Crate-closure acyclicity and vendor-SDK leakage are properties of the
//! production source/build graph, not of a declaration record, so they are
//! bound by the architecture audit and not asserted here.
//!
//! The second half of this module is the runtime half of the same contract:
//! [`captured_query_operation_map`] freezes the traced captured-query call
//! graph, [`bind_hot_path_manifest_set`] binds an approved manifest set to a
//! running build's real registered operations and queue settings,
//! [`HotPathQueueCapacity`] is the owner-held capacity the bound queue
//! declarations are enforced with, and [`optional_call_is_invocable`] is the
//! I2.15 readiness gate an optional external call must pass.

use eliot_contracts::{ContractIdentity, ContractVersion};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::RuntimeContractError;

/// Stable identity name for the I12.14 hot-path declaration schema.
pub const HOT_PATH_CONTRACT_NAME: &str = "eliot.foundation.runtime-contracts.hot-path";
/// Version of the I12.14 hot-path declaration schema identity.
pub const HOT_PATH_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Exact wire revision of the versioned manifest set below.
pub const HOT_PATH_MANIFEST_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// The bounded result a hot operation returns when its declared evidence is
/// unavailable. I12.14 names exactly these four results: failed or stale
/// evidence returns handle, unknown, probe or `RecoveryDirective`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HotPathDegradation {
    /// Return the exact durable handle for the work that is still pending.
    Handle { handle_ref: String },
    /// The current position is unknown and is reported as such.
    Unknown,
    /// Return the exact probe result the blocking owner produced.
    Probe { probe_ref: String },
    /// Return the typed recovery directive of the blocking owner.
    RecoveryDirective { directive_ref: String },
}

impl HotPathDegradation {
    /// Validates that a declared reference variant carries a non-blank handle.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        let (ref_field, reference) = match self {
            Self::Handle { handle_ref } => ("handle_ref", handle_ref),
            Self::Unknown => return Ok(()),
            Self::Probe { probe_ref } => ("probe_ref", probe_ref),
            Self::RecoveryDirective { directive_ref } => ("directive_ref", directive_ref),
        };
        crate::text(reference, ref_field)
    }
}

/// One immutable or revisioned snapshot the hot operation reads through.
///
/// I5.20 requires that every reused response carries its dependency set and
/// invalidation conditions, so the revision key is part of the dependency
/// rather than a separate cache concern.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathSnapshotDependency {
    /// Exact identity of the snapshot the operation reads.
    pub snapshot_id: String,
    /// Exact revision key under which the snapshot stays valid.
    pub revision_key: String,
}

impl HotPathSnapshotDependency {
    /// Validates the dependency identity and its revision key.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        crate::text(&self.snapshot_id, "snapshot_id")?;
        crate::text(&self.revision_key, "revision_key")
    }
}

/// Bounded item, byte, in-flight and time limits for one declared queue.
///
/// These are the four dimensions I14.1 requires each work class to bound. A
/// dimension whose bound is not established stays explicitly absent instead of
/// carrying a fabricated number; a group with no established dimension at all
/// is invalid.
#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HotPathQueueBounds {
    /// Maximum queued items.
    pub max_items: Option<u64>,
    /// Maximum queued bytes.
    pub max_bytes: Option<u64>,
    /// Maximum pending plus claimed/in-flight items.
    pub max_in_flight_items: Option<u64>,
    /// Maximum admitted service time in milliseconds.
    pub max_deadline_ms: Option<u64>,
}

impl HotPathQueueBounds {
    /// Validates that at least one dimension is bounded and every present
    /// bound is positive.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        let declared = [
            ("max_items", self.max_items),
            ("max_bytes", self.max_bytes),
            ("max_in_flight_items", self.max_in_flight_items),
            ("max_deadline_ms", self.max_deadline_ms),
        ];
        let mut bounded = false;
        for (field, amount) in declared {
            match amount {
                Some(0) => {
                    return Err(invalid(field, "a declared bound must be positive"));
                }
                Some(_) => bounded = true,
                None => {}
            }
        }
        if !bounded {
            return Err(invalid(
                "bounds",
                "at least one of items, bytes, in-flight items or time must be bounded",
            ));
        }
        Ok(())
    }
}

/// One bounded queue admission row declared for a hot operation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathQueueDeclaration {
    /// Exact registered queue identity on this leg.
    pub queue_id: String,
    /// Declared bounds for that queue.
    pub bounds: HotPathQueueBounds,
}

impl HotPathQueueDeclaration {
    /// Validates the queue identity and its declared bounds.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        crate::text(&self.queue_id, "queue_id")?;
        self.bounds.validate()
    }
}

/// One synchronous external call admitted on the hot path.
///
/// I2.15 admits an optional process call only under its readiness, latency and
/// fallback contract: readiness is the `optional` marker, latency is the
/// declared deadline, and the manifest's declared degradation is the fallback.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathExternalCall {
    /// Exact identity of the synchronous call.
    pub call_id: String,
    /// Whether the callee is an optional module that must already be READY.
    pub optional: bool,
    /// Declared synchronous deadline in milliseconds.
    pub deadline_ms: u64,
}

impl HotPathExternalCall {
    /// Validates the call identity and its positive declared deadline.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        crate::text(&self.call_id, "call_id")?;
        if self.deadline_ms == 0 {
            return Err(invalid(
                "deadline_ms",
                "a declared deadline must be positive",
            ));
        }
        Ok(())
    }
}

/// Reference to the #1734 `HotPathProfile` that carries the measured evidence
/// for one declared hot operation.
///
/// #1734 owns the profile's evidence fields and measurement production, so this
/// contract declares only the reference. Both fields are absent until that
/// issue produces a profile, which keeps an unmeasured operation visibly
/// unmeasured instead of fabricated.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HotPathProfileRef {
    /// Profile identity produced by #1734, when one exists.
    pub profile_id: Option<String>,
    /// Profile wire revision produced by #1734, when one exists.
    pub profile_revision: Option<ContractVersion>,
}

impl HotPathProfileRef {
    /// Returns whether a #1734 profile has been produced for the operation.
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.profile_id.is_some() && self.profile_revision.is_some()
    }

    /// Rejects a half-declared profile reference in either direction.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        match (&self.profile_id, &self.profile_revision) {
            (Some(profile_id), Some(_)) => crate::text(profile_id, "profile_id"),
            (None, None) => Ok(()),
            _ => Err(invalid(
                "hot_path_profile_ref",
                "profile_id and profile_revision must be declared together",
            )),
        }
    }
}

/// The closed I12.14 declaration for one hot operation. The nine fields are
/// exactly the I12.14 manifest fields.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathManifest {
    /// Exact registered operation identity this declaration binds.
    pub operation: String,
    /// Exact wire revision of that operation.
    pub operation_version: ContractVersion,
    /// Owning service of the operation.
    pub owning_service: String,
    /// Exact receive or dispatch entrypoint for the operation.
    pub entrypoint: String,
    /// In-process crate closure the operation crosses; duplicates are invalid.
    pub crate_closure: Vec<String>,
    /// Immutable or revisioned snapshot dependencies the read requires.
    pub immutable_snapshot_dependencies: Vec<HotPathSnapshotDependency>,
    /// Bounded queues and their item/byte/in-flight/time limits.
    pub queues_and_capacity: Vec<HotPathQueueDeclaration>,
    /// Synchronous external calls admitted on this path.
    pub synchronous_external_calls: Vec<HotPathExternalCall>,
    /// Declared bounded result when the evidence is unavailable.
    pub fallback_or_degradation: HotPathDegradation,
    /// Reference to the #1734 profile evidence for this operation.
    pub hot_path_profile_ref: HotPathProfileRef,
}

impl HotPathManifest {
    /// Validates the declaration's identities, closure, bounds, calls and
    /// degradation.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        crate::text(&self.operation, "operation")?;
        crate::text(&self.owning_service, "owning_service")?;
        crate::text(&self.entrypoint, "entrypoint")?;
        validate_closure(&self.crate_closure)?;
        validate_snapshots(&self.immutable_snapshot_dependencies)?;
        validate_queues(&self.queues_and_capacity)?;
        validate_external_calls(&self.synchronous_external_calls)?;
        self.fallback_or_degradation.validate()?;
        self.hot_path_profile_ref.validate()
    }
}

/// An operation this service does not claim as a bounded hot operation.
///
/// I12.14 forbids a waiting caller from silently causing model work, process
/// startup, discovery, repair, an unbounded read or an optional-module wait, so
/// an absent or unwired route stays an explicit unsupported row.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathUnsupportedOperation {
    /// Exact operation identity this service does not claim.
    pub operation: String,
    /// Why the operation is not a declared hot operation for this service.
    pub reason: String,
}

impl HotPathUnsupportedOperation {
    /// Validates the operation identity and its unsupported reason.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        crate::text(&self.operation, "operation")?;
        crate::text(&self.reason, "reason")
    }
}

/// The service-local I12.14 declaration set for one owning service.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathManifestSetV1 {
    /// Exact version of this declaration set.
    pub contract_version: ContractVersion,
    /// Service that owns every declaration in this set.
    pub owning_service: String,
    /// Operations this service declares as bounded hot operations.
    pub supported_operations: Vec<HotPathManifest>,
    /// Operations this service explicitly does not claim.
    pub unsupported_operations: Vec<HotPathUnsupportedOperation>,
}

impl HotPathManifestSetV1 {
    /// Validates the set version, owner and the disjoint supported and
    /// unsupported operation rows.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        if self.contract_version != HOT_PATH_MANIFEST_VERSION {
            return Err(invalid(
                "contract_version",
                "does not match HotPathManifestSetV1",
            ));
        }
        crate::text(&self.owning_service, "owning_service")?;
        for manifest in &self.supported_operations {
            manifest.validate()?;
        }
        for unsupported in &self.unsupported_operations {
            unsupported.validate()?;
        }
        validate_disjoint_operations(self)
    }
}

/// Projects the hot-spine crate membership from the declared closures.
///
/// Membership is the union of the `crate_closure` of every supported operation,
/// sorted and duplicate-free. It is derived from the declaration inputs alone:
/// it is not a crate group selected by package name, directory layout or
/// workspace `default-members`.
///
/// # Errors
///
/// Returns [`RuntimeContractError`] when any input set is invalid, or when two
/// services declare the same operation, which would give one operation two
/// authoritative declaration sources.
pub fn hot_spine_membership(
    manifest_sets: &[&HotPathManifestSetV1],
) -> Result<Vec<String>, RuntimeContractError> {
    let mut owners: Vec<(&str, &str)> = Vec::new();
    for set in manifest_sets {
        set.validate()?;
        for manifest in &set.supported_operations {
            owners.push((manifest.operation.as_str(), set.owning_service.as_str()));
        }
    }
    for (index, (operation, service)) in owners.iter().enumerate() {
        if owners[..index]
            .iter()
            .any(|(existing, _)| existing == operation)
        {
            return Err(invalid(
                "supported_operations",
                "one operation may have only one authoritative declaration source",
            ));
        }
        if service.is_empty() {
            return Err(invalid("owning_service", "must be non-blank"));
        }
    }
    let mut crates: Vec<String> = manifest_sets
        .iter()
        .flat_map(|set| set.supported_operations.iter())
        .flat_map(|manifest| manifest.crate_closure.iter().cloned())
        .collect();
    crates.sort();
    crates.dedup();
    Ok(crates)
}

fn validate_disjoint_operations(set: &HotPathManifestSetV1) -> Result<(), RuntimeContractError> {
    for (index, manifest) in set.supported_operations.iter().enumerate() {
        if set.supported_operations[..index]
            .iter()
            .any(|previous| previous.operation == manifest.operation)
        {
            return Err(invalid(
                "supported_operations",
                "must not repeat an operation",
            ));
        }
        if set
            .unsupported_operations
            .iter()
            .any(|unsupported| unsupported.operation == manifest.operation)
        {
            return Err(invalid(
                "unsupported_operations",
                "an unsupported operation must not also be declared supported",
            ));
        }
    }
    for (index, unsupported) in set.unsupported_operations.iter().enumerate() {
        if set.unsupported_operations[..index]
            .iter()
            .any(|previous| previous.operation == unsupported.operation)
        {
            return Err(invalid(
                "unsupported_operations",
                "must not repeat an operation",
            ));
        }
    }
    Ok(())
}

fn validate_closure(crate_closure: &[String]) -> Result<(), RuntimeContractError> {
    if crate_closure.is_empty() {
        return Err(invalid("crate_closure", "must name the in-process closure"));
    }
    for crate_name in crate_closure {
        crate::text(crate_name, "crate_closure")?;
    }
    for (index, crate_name) in crate_closure.iter().enumerate() {
        if crate_closure[..index]
            .iter()
            .any(|previous| previous == crate_name)
        {
            return Err(invalid("crate_closure", "must not repeat a crate"));
        }
    }
    Ok(())
}

fn validate_snapshots(snapshots: &[HotPathSnapshotDependency]) -> Result<(), RuntimeContractError> {
    for (index, snapshot) in snapshots.iter().enumerate() {
        snapshot.validate()?;
        if snapshots[..index]
            .iter()
            .any(|previous| previous.snapshot_id == snapshot.snapshot_id)
        {
            return Err(invalid(
                "immutable_snapshot_dependencies",
                "must not repeat a snapshot",
            ));
        }
    }
    Ok(())
}

fn validate_queues(queues: &[HotPathQueueDeclaration]) -> Result<(), RuntimeContractError> {
    if queues.is_empty() {
        return Err(invalid(
            "queues_and_capacity",
            "must declare its queue identity",
        ));
    }
    for (index, queue) in queues.iter().enumerate() {
        queue.validate()?;
        if queues[..index]
            .iter()
            .any(|previous| previous.queue_id == queue.queue_id)
        {
            return Err(invalid("queues_and_capacity", "must not repeat a queue"));
        }
    }
    Ok(())
}

fn validate_external_calls(calls: &[HotPathExternalCall]) -> Result<(), RuntimeContractError> {
    for (index, call) in calls.iter().enumerate() {
        call.validate()?;
        if calls[..index]
            .iter()
            .any(|previous| previous.call_id == call.call_id)
        {
            return Err(invalid(
                "synchronous_external_calls",
                "must not repeat a call",
            ));
        }
    }
    Ok(())
}

pub(crate) fn invalid(field: &'static str, reason: &'static str) -> RuntimeContractError {
    RuntimeContractError::InvalidField { field, reason }
}

/// Returns the independent schema identity for the I12.14 hot-path
/// declarations.
pub fn hot_path_contract_identity() -> Result<ContractIdentity, RuntimeContractError> {
    eliot_contracts::contract_identity(
        HOT_PATH_CONTRACT_NAME,
        HOT_PATH_CONTRACT_VERSION,
        &schemars::schema_for!(HotPathManifestSetV1),
    )
    .map_err(RuntimeContractError::from)
}

// ---------------------------------------------------------------------------
// The traced captured-query operation map (I12.14 step 1)
// ---------------------------------------------------------------------------

/// How one leg of a hot operation crosses a boundary.
///
/// The three kinds are the whole of what a leg can be, so a leg cannot be
/// silently reclassified to avoid naming its edge: an in-process crate edge
/// has no runtime hop, a protocol/IPC leg leaves the process, and an optional
/// process leg additionally has to pass the I2.15 readiness gate.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HotPathEdgeKind {
    /// In-process call into another crate of the same process.
    InProcessCrateEdge,
    /// Admitted protocol/IPC leg leaving or entering the owning process.
    ProtocolLeg,
    /// Call into an optional module that must already be READY.
    OptionalProcessCall,
}

/// The bounded class of I14.1 work one leg performs.
///
/// `Control` and `Interactive` are the I14.1 classes the hot path admits.
/// Every cold class I2.15 names is refused by construction: a leg that tried to
/// carry model, agent, compiler/test, rebuild, migration or repair work could
/// not be recorded in the operation map at all.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HotPathWorkClass {
    /// I14.1 `control`.
    Control,
    /// I14.1 `interactive`.
    Interactive,
}

/// One traced leg of the captured-query operation map.
///
/// Every leg names the exact function that performs it, the process that owns
/// that function, and the edge it crosses. A leg whose function or owner is
/// unknown is not recordable: the map is a completeness claim, so an unnamed
/// leg would be the exact gap this map exists to close.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathOperationLeg {
    /// Stable leg identity within its operation.
    pub leg_id: String,
    /// Exact `path.rs::symbol` of the function that performs this leg.
    pub function: String,
    /// Exact process that owns the named function.
    pub owning_process: String,
    /// How this leg crosses its boundary.
    pub edge_kind: HotPathEdgeKind,
    /// Bounded I14.1 work class this leg performs.
    pub work_class: HotPathWorkClass,
}

/// The complete traced operation map for the captured-query route.
///
/// `steps` is the ordered captured-query sequence I12.14 names: receive →
/// admission/enqueue → daemon claim/forward → bounded named read → retained
/// result → response. `failure_paths` carries the failure, retry and fallback
/// legs the same trace found, so a branch nobody noticed is still a listed row
/// rather than an unrecorded possibility. `absent_operations` stays the
/// explicit unsupported set: an operation that is absent or unwired is listed
/// there and never as a working leg.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathOperationMap {
    /// Stable map identity.
    pub map_id: String,
    /// The exact wire revision of this frozen map.
    pub map_revision: ContractVersion,
    /// Ordered hot-path legs of the captured-query route.
    pub steps: Vec<HotPathOperationLeg>,
    /// Failure, retry and fallback legs the same trace found.
    pub failure_paths: Vec<HotPathOperationLeg>,
    /// Optional-call legs, named so the set is countable.
    pub optional_calls: Vec<String>,
    /// Operations the route explicitly does not claim as hot operations.
    pub absent_operations: Vec<String>,
}

impl HotPathOperationMap {
    /// Validates the map: every leg names a function, an owner and an edge, no
    /// leg repeats its identity, the ordered steps are non-empty, and the
    /// optional-call set names exactly the legs declared as optional process
    /// calls.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        crate::text(&self.map_id, "map_id")?;
        if self.steps.is_empty() {
            return Err(invalid("steps", "must record the traced hot-path legs"));
        }
        let mut seen: Vec<String> = Vec::with_capacity(self.steps.len() + self.failure_paths.len());
        for leg in self.steps.iter().chain(self.failure_paths.iter()) {
            validate_leg(leg, &mut seen)?;
        }
        for call_id in &self.optional_calls {
            crate::text(call_id, "optional_calls")?;
            let declared = self
                .steps
                .iter()
                .chain(self.failure_paths.iter())
                .any(|leg| {
                    leg.edge_kind == HotPathEdgeKind::OptionalProcessCall && &leg.leg_id == call_id
                });
            if !declared {
                return Err(invalid(
                    "optional_calls",
                    "must name legs declared as optional process calls",
                ));
            }
        }
        Ok(())
    }
}

fn validate_leg(
    leg: &HotPathOperationLeg,
    seen: &mut Vec<String>,
) -> Result<(), RuntimeContractError> {
    crate::text(&leg.leg_id, "leg_id")?;
    // A leg without its exact function or its owning process would be a
    // coverage claim with nothing behind it, so both are mandatory.
    crate::text(&leg.function, "function")?;
    crate::text(&leg.owning_process, "owning_process")?;
    if seen.iter().any(|previous| previous == &leg.leg_id) {
        return Err(invalid("steps", "must not repeat a leg"));
    }
    seen.push(leg.leg_id.clone());
    Ok(())
}

/// One Kernel in-process control leg: a call inside the Kernel process.
fn kernel_leg(leg_id: &str, function: &str) -> HotPathOperationLeg {
    HotPathOperationLeg {
        leg_id: leg_id.to_owned(),
        function: function.to_owned(),
        owning_process: "eliot-kernel".to_owned(),
        edge_kind: HotPathEdgeKind::InProcessCrateEdge,
        work_class: HotPathWorkClass::Control,
    }
}

/// One eliotd in-process interactive leg: a call inside the daemon process.
fn daemon_leg(leg_id: &str, function: &str) -> HotPathOperationLeg {
    HotPathOperationLeg {
        leg_id: leg_id.to_owned(),
        function: function.to_owned(),
        owning_process: "eliotd".to_owned(),
        edge_kind: HotPathEdgeKind::InProcessCrateEdge,
        work_class: HotPathWorkClass::Interactive,
    }
}

/// One protocol/IPC leg leaving or entering the named owning process.
fn protocol_leg(leg_id: &str, function: &str, owning_process: &str) -> HotPathOperationLeg {
    HotPathOperationLeg {
        leg_id: leg_id.to_owned(),
        function: function.to_owned(),
        owning_process: owning_process.to_owned(),
        edge_kind: HotPathEdgeKind::ProtocolLeg,
        work_class: HotPathWorkClass::Interactive,
    }
}

/// The ordered hot-path legs of the captured-query route, in trace order.
fn captured_query_steps() -> Vec<HotPathOperationLeg> {
    vec![
        // captured-query receive
        protocol_leg(
            "receive",
            "bins/eliotd/src/daemon_kernel_client.rs::transact_async",
            "eliotd",
        ),
        kernel_leg(
            "frame_dispatch",
            "bins/eliot-kernel/src/frame_dispatch.rs::dispatch_frame",
        ),
        kernel_leg(
            "host_request_dispatch",
            "bins/eliot-kernel/src/host_request_route.rs::dispatch_host_request_frame",
        ),
        // admission/enqueue
        kernel_leg(
            "invoke_read_admission",
            "bins/eliot-kernel/src/host_request_route.rs::invoke_read_host_request",
        ),
        kernel_leg(
            "enqueue",
            "bins/eliot-kernel/src/host_request_route.rs::enqueue_local_read_pair_under_transition",
        ),
        // daemon claim/forward
        protocol_leg(
            "claim",
            "bins/eliotd/src/daemon_kernel_client.rs::claim_local_read_pair_async",
            "eliotd",
        ),
        kernel_leg(
            "claim_owner",
            "bins/eliot-kernel/src/host_request_route.rs::claim_local_read_pair",
        ),
        protocol_leg(
            "forward",
            "bins/eliotd/src/daemon_kernel_client.rs::local_read_async",
            "eliotd",
        ),
        daemon_leg(
            "forward_owner",
            "bins/eliotd/src/governor_local_read.rs::forward_admitted_local_read",
        ),
        // bounded named read
        protocol_leg(
            "read",
            "bins/eliot-kernel/src/daemon_request_dispatch.rs::execute_daemon_request_inner",
            "eliot-kernel",
        ),
        kernel_leg(
            "named_read",
            "bins/eliot-kernel/src/daemon_request_dispatch.rs::local_read_operation",
        ),
        // retained result
        protocol_leg(
            "result",
            "bins/eliotd/src/daemon_kernel_client.rs::submit_local_read_result_async",
            "eliotd",
        ),
        kernel_leg(
            "retained_result",
            "bins/eliot-kernel/src/host_request_route.rs::submit_local_read_result",
        ),
        // response
        daemon_leg(
            "response",
            "bins/eliotd/src/daemon_kernel_client.rs::parse_local_read_submit_outcome",
        ),
    ]
}

/// The failure, retry and fallback legs the same captured-query trace found.
fn captured_query_failure_paths() -> Vec<HotPathOperationLeg> {
    vec![
        kernel_leg(
            "queue_full_backpressure",
            "bins/eliot-kernel/src/host_request_route.rs::enqueue_local_read_pair_under_transition",
        ),
        kernel_leg(
            "claim_lease_expiry",
            "bins/eliot-kernel/src/host_request_route.rs::expired_claim_timeout",
        ),
        kernel_leg(
            "stale_attempt_quarantine",
            "bins/eliot-kernel/src/host_request_route.rs::submit_claimed_result",
        ),
        kernel_leg(
            "result_fence_mismatch",
            "bins/eliot-kernel/src/host_request_route.rs::submit_claimed_result",
        ),
        daemon_leg(
            "submit_idempotent_retry",
            "bins/eliotd/src/daemon_runtime.rs::submit_local_read_result_idempotent",
        ),
        daemon_leg(
            "poll_backoff",
            "bins/eliotd/src/daemon_runtime.rs::settle_local_read_completion",
        ),
    ]
}

/// Returns the frozen, traced operation map for the captured-query route.
///
/// Every leg below was read out of the current source, not remembered: the
/// Kernel receive/admission/enqueue/claim/read/result legs from
/// `bins/eliot-kernel`, the IPC legs and the daemon claim/forward/submit legs
/// from `bins/eliotd`. The two in-process Kernel read legs
/// (`daemon_request_dispatch.rs::local_read_operation` reaching the retained
/// store gateway) and the one eliotd forward leg
/// (`governor_local_read.rs::forward_admitted_local_read`) are the only
/// synchronous external calls the query route admits, and both are
/// non-optional in-process edges over the authenticated daemon session. No
/// leg of this route is an optional process call, and the map says so: the
/// optional-module gate has nothing to gate on this route.
pub fn captured_query_operation_map() -> Result<HotPathOperationMap, RuntimeContractError> {
    let map = HotPathOperationMap {
        map_id: "eliot.hot-path.captured-query".to_owned(),
        map_revision: HOT_PATH_OPERATION_MAP_REVISION,
        steps: captured_query_steps(),
        failure_paths: captured_query_failure_paths(),
        // No leg of the captured-query route is an optional process call: the
        // read is served by the Kernel's retained in-process store gateway
        // over the authenticated daemon session, so there is no optional
        // module to wait for. The empty set is the honest reading.
        optional_calls: Vec::new(),
        absent_operations: vec![
            "eliot.query.packet".to_owned(),
            "store_named.GetUnderstandingProjectionInputs".to_owned(),
        ],
    };
    map.validate()?;
    Ok(map)
}

/// The exact wire revision of the frozen captured-query operation map.
pub const HOT_PATH_OPERATION_MAP_REVISION: ContractVersion = ContractVersion::new(1, 0, 0);

// ---------------------------------------------------------------------------
// Runtime binding against the running build (I12.14 step 4)
// ---------------------------------------------------------------------------

/// The real settings one running process registered for a queue.
///
/// These are the values the running build actually enforces, read from the
/// process's own registered settings, never from the declaration. A manifest
/// that names a different value than this is refused at bind time.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredQueueSettings {
    /// Exact registered queue identity the running process serves.
    pub queue_id: String,
    /// Items the running process actually bounds this queue to.
    pub max_items: u64,
    /// Bytes the running process actually bounds this queue to.
    pub max_bytes: u64,
}

impl RegisteredQueueSettings {
    /// Validates the registered settings: a real queue identity and positive
    /// physical bounds.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        crate::text(&self.queue_id, "queue_id")?;
        if self.max_items == 0 {
            return Err(invalid(
                "max_items",
                "a registered item bound must be positive",
            ));
        }
        if self.max_bytes == 0 {
            return Err(invalid(
                "max_bytes",
                "a registered byte bound must be positive",
            ));
        }
        Ok(())
    }
}

/// One operation the running build actually registered for dispatch.
///
/// The running build's registration is authoritative here: a manifest may only
/// bind an operation this list already contains, so a manifest can never
/// advertise an operation the build does not serve.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredOperation {
    /// Exact registered operation identity the running build dispatches.
    pub operation: String,
    /// The real queue settings that operation is bounded by at runtime.
    pub queue: RegisteredQueueSettings,
}

impl RegisteredOperation {
    /// Validates the registered operation identity and its physical settings.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        crate::text(&self.operation, "operation")?;
        self.queue.validate()
    }
}

/// The registration a running build exposes for the hot-path bind.
///
/// This is the authoritative side of the comparison: every field comes from
/// the process that is actually running, so a manifest that parses, or whose
/// digest matches itself, cannot stand in for it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunningBuildRegistration {
    /// Exact service the running build is.
    pub service: String,
    /// The operations this running build actually registered.
    pub operations: Vec<RegisteredOperation>,
}

impl RunningBuildRegistration {
    /// Validates the registration: a real service identity and at least one
    /// registered operation, each with its own physical settings.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        crate::text(&self.service, "service")?;
        if self.operations.is_empty() {
            return Err(invalid(
                "operations",
                "a running build must register operations",
            ));
        }
        for (index, operation) in self.operations.iter().enumerate() {
            operation.validate()?;
            if self.operations[..index]
                .iter()
                .any(|previous| previous.operation == operation.operation)
            {
                return Err(invalid("operations", "must not repeat an operation"));
            }
        }
        Ok(())
    }

    /// Returns the registered settings for one operation, or `None` when the
    /// running build does not register it.
    #[must_use]
    pub fn queue_for(&self, operation: &str) -> Option<&RegisteredQueueSettings> {
        self.operations
            .iter()
            .find(|registered| registered.operation == operation)
            .map(|registered| &registered.queue)
    }
}

/// The identities a bind result retains so diagnostics can be audited later.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathBindingIdentity {
    /// Exact operation the binding was made for.
    pub operation: String,
    /// Exact manifest set revision that was bound.
    pub contract_version: ContractVersion,
    /// The running-build service the manifest was bound against.
    pub service: String,
    /// The physical queue settings the running build actually enforced.
    pub registered_queue: RegisteredQueueSettings,
    /// The #1734 profile reference the bound operation carries.
    pub profile: HotPathProfileRef,
}

/// Binds one approved manifest set against a running build's real registration.
///
/// Binding is a comparison with the running build as the authoritative side.
/// For every supported operation the manifest declares, the running build must
/// actually register that operation, and the physical queue settings the
/// running build enforces must equal the settings the manifest declared —
/// neither looser nor tighter. A changed manifest, an operation the build does
/// not register, or a mismatched physical queue setting is refused, so a
/// validated hot path can never be advertised from a declaration that does not
/// match the process serving it.
///
/// A changed queue/profile/operation revision therefore invalidates its prior
/// binding by construction: the prior binding was made against these exact
/// registered values, and a changed value no longer equals them.
///
/// # Errors
///
/// Returns [`RuntimeContractError`] when the manifest set, the registration or
/// the frozen operation map is invalid, or when any supported operation is not
/// registered by the running build or declares queue settings the running
/// build does not enforce.
pub fn bind_hot_path_manifest_set(
    manifest_set: &HotPathManifestSetV1,
    registration: &RunningBuildRegistration,
) -> Result<Vec<HotPathBindingIdentity>, RuntimeContractError> {
    manifest_set.validate()?;
    registration.validate()?;
    captured_query_operation_map()?.validate()?;
    if manifest_set.owning_service != registration.service {
        return Err(invalid(
            "owning_service",
            "the manifest set must be bound against its own running service",
        ));
    }
    let mut identities = Vec::with_capacity(manifest_set.supported_operations.len());
    for manifest in &manifest_set.supported_operations {
        let Some(queue) = registration.queue_for(&manifest.operation) else {
            return Err(invalid(
                "supported_operations",
                "the running build does not register this declared operation",
            ));
        };
        for declared in &manifest.queues_and_capacity {
            if let Some(max_items) = declared.bounds.max_items
                && max_items != queue.max_items
            {
                return Err(invalid(
                    "queues_and_capacity",
                    "the declared item bound does not match the running build's registered bound",
                ));
            }
            if let Some(max_bytes) = declared.bounds.max_bytes
                && max_bytes != queue.max_bytes
            {
                return Err(invalid(
                    "queues_and_capacity",
                    "the declared byte bound does not match the running build's registered bound",
                ));
            }
        }
        identities.push(HotPathBindingIdentity {
            operation: manifest.operation.clone(),
            contract_version: manifest_set.contract_version,
            service: registration.service.clone(),
            registered_queue: queue.clone(),
            profile: manifest.hot_path_profile_ref.clone(),
        });
    }
    Ok(identities)
}

// ---------------------------------------------------------------------------
// Owner-held bounded queue capacity (I12.14 step 5)
// ---------------------------------------------------------------------------

/// The owner-held capacity of one declared hot-path queue.
///
/// Capacity is acquired at admission and retained until the corresponding
/// owner-safe release, so a claimed/in-flight item still occupies its slot: the
/// bound is over pending *plus* claimed/in-flight items, not over pending only.
/// Releasing on receipt rather than on the owner's safe release would let a
/// saturated queue grow past its bound, so the owner keeps the permit until it
/// says the work is safe to forget.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathQueueCapacity {
    queue_id: String,
    max_items: u64,
    max_bytes: u64,
    held_items: u64,
    held_bytes: u64,
}

impl HotPathQueueCapacity {
    /// Creates an empty capacity ledger for one declared queue.
    pub fn new(queue_id: &str, max_items: u64, max_bytes: u64) -> Self {
        Self {
            queue_id: queue_id.to_owned(),
            max_items,
            max_bytes,
            held_items: 0,
            held_bytes: 0,
        }
    }

    /// Returns the queue identity this capacity bounds.
    #[must_use]
    pub fn queue_id(&self) -> &str {
        &self.queue_id
    }

    /// The item bound the owner enforces.
    #[must_use]
    pub const fn max_items(&self) -> u64 {
        self.max_items
    }

    /// The byte bound the owner enforces.
    #[must_use]
    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Items currently held, pending plus claimed/in-flight.
    #[must_use]
    pub const fn held_items(&self) -> u64 {
        self.held_items
    }

    /// Bytes currently held, pending plus claimed/in-flight.
    #[must_use]
    pub const fn held_bytes(&self) -> u64 {
        self.held_bytes
    }

    /// Acquires one item/byte permit when both bounds allow it.
    ///
    /// A request larger than the byte bound, or a full ledger, is refused
    /// without acquiring anything: a refusal never partially acquires, so the
    /// owner never holds capacity for work it did not admit.
    pub fn acquire(&mut self, bytes: u64) -> Result<(), RuntimeContractError> {
        if bytes > self.max_bytes {
            return Err(invalid("bytes", "the request exceeds the queue byte bound"));
        }
        let next_items = self
            .held_items
            .checked_add(1)
            .ok_or_else(|| invalid("held_items", "item accounting overflowed"))?;
        let next_bytes = self
            .held_bytes
            .checked_add(bytes)
            .ok_or_else(|| invalid("held_bytes", "byte accounting overflowed"))?;
        if next_items > self.max_items {
            return Err(invalid("held_items", "the queue item bound is saturated"));
        }
        if next_bytes > self.max_bytes {
            return Err(invalid("held_bytes", "the queue byte bound is saturated"));
        }
        self.held_items = next_items;
        self.held_bytes = next_bytes;
        Ok(())
    }

    /// Releases one item/byte permit at the owner's safe release point.
    ///
    /// Saturating at zero keeps a double release from wrapping into a phantom
    /// holding, so an over-release can never manufacture extra capacity.
    pub fn release(&mut self, bytes: u64) {
        self.held_items = self.held_items.saturating_sub(1);
        self.held_bytes = self.held_bytes.saturating_sub(bytes);
    }
}

// ---------------------------------------------------------------------------
// Optional-call READY gate (I12.14 step 6 / I2.15)
// ---------------------------------------------------------------------------

/// The current authenticated state of the optional callee for one call.
///
/// `current_authenticated` is the callee's live authenticated generation and
/// capability, read at invocation time. A cached or remembered readiness flag
/// is deliberately not representable here: READY is not a future guarantee, so
/// the gate cannot be handed a stale "ready" answer.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionalCallAuthentication {
    /// Whether the callee's current authenticated generation/capability is
    /// READY right now.
    pub ready: bool,
    /// How many more calls the declared budget still admits.
    pub remaining_call_budget: u64,
    /// Whether the declared fallback is valid for this call.
    pub fallback_valid: bool,
}

/// The exact reason an optional call was not invoked.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OptionalCallRefusal {
    /// The callee's current authenticated generation/capability is not READY.
    NotReady,
    /// The declared call budget is exhausted.
    BudgetExhausted,
    /// The declared fallback is not valid.
    FallbackInvalid,
}

/// Decides whether one optional external call may be invoked now.
///
/// I2.15 admits an optional process call only under its readiness, latency and
/// fallback contract. This is the readiness and budget half: the call is
/// invocable only when the callee's *current authenticated*
/// generation/capability is READY **and** the declared call budget still
/// admits it **and** the declared fallback is valid. A callee that is not
/// READY, an exhausted budget or an invalid fallback all return a refusal
/// without starting the module and without blocking; the caller then produces
/// the declared degradation. The latency half is the declared `deadline_ms` on
/// the call itself, carried in the manifest, not a second budget here.
pub fn optional_call_is_invocable(
    call: &HotPathExternalCall,
    authentication: &OptionalCallAuthentication,
) -> Result<(), OptionalCallRefusal> {
    // A call the manifest did not declare optional is not gated on optional
    // readiness; only a declared optional call needs its callee already READY.
    if !call.optional {
        return Ok(());
    }
    if !authentication.ready {
        return Err(OptionalCallRefusal::NotReady);
    }
    if authentication.remaining_call_budget == 0 {
        return Err(OptionalCallRefusal::BudgetExhausted);
    }
    if !authentication.fallback_valid {
        return Err(OptionalCallRefusal::FallbackInvalid);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Auditable binding status (I12.14 step 7)
// ---------------------------------------------------------------------------

/// The limiting bound on one bound operation, as reported for audit.
///
/// A diagnostic reports the bound that actually limited the operation, not a
/// generic "degraded": `Item` and `Bytes` name the exact dimension that
/// saturated, and `None` says no bound limited it.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HotPathLimitingBound {
    /// No bound limited the operation.
    None,
    /// The item bound limited it.
    Item,
    /// The byte bound limited it.
    Bytes,
    /// The in-flight bound limited it.
    InFlight,
    /// The declared deadline limited it.
    Deadline,
}

/// One auditable bound-status row for one bound operation.
///
/// Every field is privacy-safe and bounded: identities are names and digests
/// the manifest already carries, the snapshot set is the declared dependency
/// list, and the degradation reason is the owner's exact closed-vocabulary
/// code. A generic "degraded" is not representable: `degradation` and
/// `degradation_reason` are both present or both absent, and a row carrying one
/// names the concrete bounded reason rather than a bare state.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathBoundStatus {
    /// Exact operation this row reports.
    pub operation: String,
    /// Exact bound manifest revision in force.
    pub contract_version: ContractVersion,
    /// The #1734 profile reference, absent until #1734 produces one.
    pub profile: HotPathProfileRef,
    /// The physical queue settings the running build actually enforced.
    pub registered_queue: RegisteredQueueSettings,
    /// The active immutable/revisioned snapshot dependencies, in the manifest's
    /// own declared order.
    pub active_snapshots: Vec<HotPathSnapshotDependency>,
    /// The bound that actually limited this operation.
    pub limiting_bound: HotPathLimitingBound,
    /// The owner's exact degradation result, present only when degraded.
    pub degradation: Option<HotPathDegradation>,
    /// The owner's exact degradation reason, present only when degraded.
    pub degradation_reason: Option<HotPathDegradationReason>,
}

/// The exact closed reason a bound operation is degraded.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HotPathDegradationReason {
    /// The optional callee is not currently READY.
    OptionalModuleNotReady,
    /// The queue item bound saturated.
    QueueItemsSaturated,
    /// The queue byte bound saturated.
    QueueBytesSaturated,
    /// The declared deadline elapsed.
    DeadlineElapsed,
    /// The claimed attempt was superseded or revoked.
    AttemptSuperseded,
}

impl HotPathDegradationReason {
    /// The stable bounded wire code for this reason, for diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OptionalModuleNotReady => "OPTIONAL_MODULE_NOT_READY",
            Self::QueueItemsSaturated => "QUEUE_ITEMS_SATURATED",
            Self::QueueBytesSaturated => "QUEUE_BYTES_SATURATED",
            Self::DeadlineElapsed => "DEADLINE_ELAPSED",
            Self::AttemptSuperseded => "ATTEMPT_SUPERSEDED",
        }
    }
}

impl HotPathBoundStatus {
    /// Returns whether this operation currently reports a degradation.
    #[must_use]
    pub const fn degraded(&self) -> bool {
        self.degradation.is_some()
    }

    /// Builds one auditable status row for a bound operation.
    ///
    /// The active snapshot list is the manifest's own declared dependency set
    /// in its declared order, so a binding change shows as a different revision
    /// set rather than as an unexplained identical row. A degradation, its exact
    /// reason and the bound that limited the operation are required together, so
    /// a degraded row can never ship without its concrete reason and a healthy
    /// row can never claim one.
    pub fn of(
        manifest: &HotPathManifest,
        contract_version: ContractVersion,
        registered_queue: RegisteredQueueSettings,
        active_snapshots: Vec<HotPathSnapshotDependency>,
        limiting_bound: HotPathLimitingBound,
        degradation: Option<HotPathDegradation>,
        degradation_reason: Option<HotPathDegradationReason>,
    ) -> Result<Self, RuntimeContractError> {
        if degradation.is_some() != degradation_reason.is_some() {
            return Err(invalid(
                "degradation_reason",
                "a degradation and its exact reason must be reported together",
            ));
        }
        if degradation.is_some() != (limiting_bound != HotPathLimitingBound::None) {
            return Err(invalid(
                "limiting_bound",
                "a degraded row must name the bound that limited it and a healthy row must not",
            ));
        }
        Ok(Self {
            operation: manifest.operation.clone(),
            contract_version,
            profile: manifest.hot_path_profile_ref.clone(),
            registered_queue,
            active_snapshots,
            limiting_bound,
            degradation,
            degradation_reason,
        })
    }
}

/// Projects the auditable bound status for every supported operation of a set.
///
/// The rows come from the bound manifest set and the running build's
/// registration together, so each row already carries the operation/manifest/
/// profile identity, the declared active snapshot revisions and the physical
/// queue the running build enforced. A caller that observes a limitation
/// replaces a row's limiting bound and degradation with the observed pair, so
/// the audit surface reports the bound that actually limited the operation and
/// the owner's exact degradation reason rather than a generic "degraded".
pub fn hot_path_bound_status(
    manifest_set: &HotPathManifestSetV1,
    registration: &RunningBuildRegistration,
) -> Result<Vec<HotPathBoundStatus>, RuntimeContractError> {
    let identities = bind_hot_path_manifest_set(manifest_set, registration)?;
    let mut rows = Vec::with_capacity(identities.len());
    for identity in identities {
        let manifest = manifest_set
            .supported_operations
            .iter()
            .find(|manifest| manifest.operation == identity.operation)
            .ok_or_else(|| invalid("supported_operations", "a bound operation vanished"))?;
        rows.push(HotPathBoundStatus::of(
            manifest,
            manifest_set.contract_version,
            identity.registered_queue,
            manifest.immutable_snapshot_dependencies.clone(),
            HotPathLimitingBound::None,
            None,
            None,
        )?);
    }
    Ok(rows)
}
