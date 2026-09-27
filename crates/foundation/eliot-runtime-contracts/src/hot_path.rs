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
