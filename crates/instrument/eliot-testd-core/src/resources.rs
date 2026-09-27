//! Declared test/job resources, runtime leases, and lane scheduling policy.
//!
//! I2.22 requires that a test group *declare* its resource weight and its
//! exclusive resources, that stateful ports, services, and database volumes
//! receive *separate* leases, and that verification keeps priority over
//! background indexing, coverage, mutation, and Dreamer jobs. A worktree does
//! not isolate runtime resources, so exclusivity is decided here and recorded
//! on the job, never inferred from a directory.
//!
//! This module owns the declarations and the decision function. It owns no
//! clock, no durable store, and no process: [`TestdStore`](super::TestdStore)
//! persists the decision, and the worker executes the leased job.
//!
//! [`NextestLanePlan`] is the single derivation from those declarations to
//! the nextest serial sets that keep two tests claiming one exclusive
//! resource, or one serial group, from running concurrently. The plan renders
//! the `nextest.toml` and validates a checked-in file, so a drifted config
//! cannot be regenerated into agreement by accident, and
//! [`NextestLanePlan::serial_set_for`] reads the derived set off the
//! [`SchedulingDecision`] a work item already carries.

use std::collections::{BTreeMap, BTreeSet};

use super::nextest_partition;

use eliot_build_test_graph::InvalidResourceClaim;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use eliot_build_test_graph::{ResourceClaim, ResourceKind, ResourceWeight};

/// A declared claim was refused by the shared declaration owner.
fn invalid_claim(error: InvalidResourceClaim) -> ResourceError {
    ResourceError::InvalidClaim {
        field: error.field,
        reason: error.reason,
    }
}

/// Job classes ordered ahead of background work by I2.22.
///
/// The order in this enum is the admission order: an earlier variant is never
/// displaced by a later one. The control-plane variants are the classes a
/// background build must not displace; `Verification` is the only product
/// class the issue places ahead of the background classes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobClass {
    /// Kernel process plane.
    Kernel,
    /// Watchdog supervision plane.
    Watchdog,
    /// Control Reserve held back for the controller's own operator actions.
    ControlReserve,
    /// Verification of a candidate. Ordered ahead of every background class.
    Verification,
    /// Interactive product work driven by a human operator.
    Interactive,
    /// Background indexing.
    Indexing,
    /// Background coverage measurement.
    Coverage,
    /// Background mutation testing.
    Mutation,
    /// Dreamer / model background work.
    Dreamer,
}

impl JobClass {
    /// Every declared class, in admission order.
    pub const ALL: [Self; 9] = [
        Self::Kernel,
        Self::Watchdog,
        Self::ControlReserve,
        Self::Verification,
        Self::Interactive,
        Self::Indexing,
        Self::Coverage,
        Self::Mutation,
        Self::Dreamer,
    ];

    /// Whether a background job may be displaced by a foreground class.
    ///
    /// I2.22: "A background build cannot displace Kernel, Watchdog, Control
    /// Reserve, or interactive product work", and "Verification has priority
    /// over background indexing, coverage, mutation, and Dreamer jobs."
    #[must_use]
    pub const fn is_background(self) -> bool {
        matches!(
            self,
            Self::Indexing | Self::Coverage | Self::Mutation | Self::Dreamer
        )
    }

    /// Scheduling priority. Larger values claim first among ready heads.
    ///
    /// The classes I2.22 places ahead of background work are strictly greater
    /// than every background class, so a verification job and a background job
    /// queued under the same constrained capacity cannot be reordered against
    /// this policy. Relative order within each group is the declaration order
    /// of [`JobClass::ALL`]; no capacity quantity is invented here.
    #[must_use]
    pub const fn priority(self) -> i32 {
        match self {
            Self::Kernel => 90,
            Self::Watchdog => 80,
            Self::ControlReserve => 70,
            Self::Verification => 60,
            Self::Interactive => 50,
            Self::Indexing => 40,
            Self::Coverage => 30,
            Self::Mutation => 20,
            Self::Dreamer => 10,
        }
    }
}

/// Declared resource weight, exclusive claims, and serial grouping for one
/// test group or job.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestResourceProfile {
    /// Weight in [`ResourceWeight`]. Background work is `Light`; nothing
    /// declares a numeric weight outside the closed table.
    pub weight: ResourceWeight,
    /// Exclusive runtime resources this group requires.
    #[serde(default)]
    pub exclusive_resources: Vec<ResourceClaim>,
    /// Serial group name. Members of one group never run concurrently with
    /// each other, whether or not they declare an exclusive resource.
    pub serial_group: String,
}

impl TestResourceProfile {
    /// A parallel-safe declaration: light weight, no exclusive claim, no
    /// serial group.
    #[must_use]
    pub const fn parallel() -> Self {
        Self {
            weight: ResourceWeight::Light,
            exclusive_resources: Vec::new(),
            serial_group: String::new(),
        }
    }

    /// Validates the declaration and rejects duplicates.
    pub fn validate(&self) -> Result<(), ResourceError> {
        if !self.serial_group.is_empty()
            && (self.serial_group.trim().is_empty()
                || self.serial_group.chars().any(char::is_control)
                || self.serial_group.trim() != self.serial_group)
        {
            return Err(ResourceError::InvalidClaim {
                field: "serial_group",
                reason: "must be non-blank, control-free, and free of surrounding whitespace",
            });
        }
        let mut seen = BTreeSet::new();
        for claim in &self.exclusive_resources {
            claim.validate().map_err(invalid_claim)?;
            if !seen.insert((claim.kind, claim.name.clone())) {
                return Err(ResourceError::DuplicateClaim {
                    kind: claim.kind,
                    name: claim.name.clone(),
                });
            }
        }
        Ok(())
    }
}

/// One allocated runtime lease. Two jobs holding the same `(kind, name)` never
/// run concurrently; the second job is either refused or serialized.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLease {
    pub kind: ResourceKind,
    pub resource: String,
    /// Holder identity. For a serial group this is the group name, so a
    /// serialized member holds the group lease rather than its own.
    pub holder: String,
}

/// The scheduling decision recorded on a work item's execution record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulingDecision {
    pub job_class: JobClass,
    /// Priority this class claims with.
    pub priority: i32,
    pub weight: ResourceWeight,
    pub weight_units: u32,
    /// Leases this job holds. Empty for a fully parallel declaration.
    pub leases: Vec<ResourceLease>,
    /// Serial group this job was serialized behind, if any.
    pub serial_group: Option<String>,
    /// Background classes that cannot be claimed while this job is running.
    pub reserved_against: Vec<JobClass>,
}

impl SchedulingDecision {
    /// Number of background classes the running job displaces.
    #[must_use]
    pub fn reserved_against(&self) -> &[JobClass] {
        &self.reserved_against
    }
}

/// Typed rejections from resource declaration, lease allocation, and nextest
/// serial-set derivation. All are fail-closed: an unknown or conflicting
/// declaration is refused rather than silently downgraded.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ResourceError {
    #[error("invalid resource declaration ({field}): {reason}")]
    InvalidClaim {
        field: &'static str,
        reason: &'static str,
    },
    #[error("duplicate {kind:?} claim for {name} in one declaration")]
    DuplicateClaim { kind: ResourceKind, name: String },
    #[error("serial group {group} is already held by {holder}")]
    SerialGroupHeld { group: String, holder: String },
    #[error("exclusive {kind:?} resource {name} is already leased to {holder}")]
    ResourceLeased {
        kind: ResourceKind,
        name: String,
        holder: String,
    },
    #[error("serial group {group} has no declared members")]
    EmptySerialGroup { group: String },
}

/// The nextest serial sets derived from the declared test resource profiles.
///
/// One set is one nextest test group declared with `max-threads = 1`, holding
/// every declared test that is transitively bound to the same exclusive
/// resource or serial group. Two tests claiming the same resource, or
/// declaring the same serial group, are therefore always in one set and
/// cannot run concurrently; a test that declares neither is in no set and
/// runs unconstrained. The derivation and the rendering are in
/// [`nextest_partition`]; this type owns the decision record's view of them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NextestLanePlan {
    /// Serial sets, each with the exact, sorted test names it serializes.
    pub serial_groups: BTreeMap<String, Vec<String>>,
    /// Every declared identity to the serial set that holds it. Private:
    /// callers look a set up through [`Self::serial_set_for`].
    group_of_identity: BTreeMap<String, String>,
}

impl NextestLanePlan {
    /// Builds the plan from the declared profiles of every test, keyed by the
    /// nextest test name.
    ///
    /// Fails closed on an invalid declaration and on a test name no nextest
    /// filterset can match, rather than dropping the test from the plan.
    pub fn build(declared: &BTreeMap<String, TestResourceProfile>) -> Result<Self, ResourceError> {
        let plan = nextest_partition::exclusivity_plan(declared)?;
        Ok(Self {
            serial_groups: plan.sets,
            group_of_identity: plan.group_of_identity,
        })
    }

    /// The serial set holding the tests of one recorded scheduling decision,
    /// or `None` when that decision declared no exclusive resource and no
    /// serial group.
    ///
    /// The decision is the only input: it already carries the exclusive
    /// resources it was leased and the serial group it declared, so the
    /// nextest assignment is read off the execution record itself instead of
    /// a second declaration channel. Fails closed when a declared identity is
    /// absent from this plan, because reporting no serial set there would let
    /// two tests claiming one resource run concurrently.
    pub fn serial_set_for(
        &self,
        decision: &SchedulingDecision,
    ) -> Result<Option<String>, ResourceError> {
        let mut serial_set: Option<String> = None;
        for identity in nextest_partition::recorded_identities(decision) {
            let Some(group) = self.group_of_identity.get(&identity) else {
                return Err(ResourceError::InvalidClaim {
                    field: "nextest serial set",
                    reason: "declared resource or serial group is absent from the plan",
                });
            };
            if serial_set.is_none() {
                serial_set = Some(group.clone());
            }
        }
        Ok(serial_set)
    }

    /// Renders the deterministic `nextest.toml` for this plan.
    ///
    /// Each serial set becomes one `max-threads = 1` test group plus one
    /// override whose filter selects exactly its members, so nextest runs at
    /// most one of them at a time. The same declarations always render the
    /// same bytes.
    pub fn render_nextest_toml(&self) -> Result<String, ResourceError> {
        nextest_partition::render_nextest_toml(&self.serial_groups)
    }

    /// Validates a `nextest.toml` against this plan.
    ///
    /// Fails closed on any difference from the rendered plan. A file that
    /// drifted from the declarations is a configuration failure, not a reason
    /// to regenerate the declarations.
    pub fn validate_nextest_toml(&self, text: &str) -> Result<(), ResourceError> {
        if text != self.render_nextest_toml()? {
            return Err(ResourceError::InvalidClaim {
                field: "nextest.toml",
                reason: "does not match the serial sets derived from the declared test resource profiles",
            });
        }
        Ok(())
    }
}

/// One running job's held resources, as reconstructed from the durable record.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RunningHolder {
    leases: Vec<ResourceLease>,
    serial_group: String,
}

/// Allocation of runtime leases across the durable job set.
///
/// This is the in-memory policy the durable store consults before a claim. It
/// does not own the store, the clock, or a process.
#[derive(Clone, Debug, Default)]
pub struct ResourceLeaseAllocator {
    running: BTreeMap<String, RunningHolder>,
}

impl ResourceLeaseAllocator {
    /// A fresh allocator with nothing running.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocates the leases one job requires, or refuses with the first
    /// conflict. Refusal is the only outcome; a conflicting job never runs
    /// concurrently on a held resource.
    pub fn allocate(
        &mut self,
        job_id: &str,
        profile: &TestResourceProfile,
    ) -> Result<Vec<ResourceLease>, ResourceError> {
        if let Some(holder) = self.holder_of(profile) {
            return Err(holder);
        }
        let leases: Vec<ResourceLease> = profile
            .exclusive_resources
            .iter()
            .map(|claim| ResourceLease {
                kind: claim.kind,
                resource: claim.name.clone(),
                holder: job_id.to_owned(),
            })
            .collect();
        self.running.insert(
            job_id.to_owned(),
            RunningHolder {
                leases: leases.clone(),
                serial_group: profile.serial_group.clone(),
            },
        );
        Ok(leases)
    }

    /// The conflict that would refuse `profile`, or `None` when it is free.
    fn holder_of(&self, profile: &TestResourceProfile) -> Option<ResourceError> {
        for claim in &profile.exclusive_resources {
            if let Some((job, _)) = self.running.iter().find(|(_, held)| {
                held.leases
                    .iter()
                    .any(|lease| lease.kind == claim.kind && lease.resource == claim.name)
            }) {
                return Some(ResourceError::ResourceLeased {
                    kind: claim.kind,
                    name: claim.name.clone(),
                    holder: job.clone(),
                });
            }
        }
        if !profile.serial_group.is_empty()
            && let Some((job, _)) = self
                .running
                .iter()
                .find(|(_, held)| held.serial_group == profile.serial_group)
        {
            return Some(ResourceError::SerialGroupHeld {
                group: profile.serial_group.clone(),
                holder: job.clone(),
            });
        }
        None
    }

    /// Re-adopts the resources a durably running job already holds, so a
    /// restart reconstructs the same exclusivity state instead of freeing it.
    pub fn adopt_running(
        &mut self,
        job_id: String,
        leases: Vec<ResourceLease>,
        serial_group: String,
    ) {
        self.running.insert(
            job_id,
            RunningHolder {
                leases,
                serial_group,
            },
        );
    }

    /// Releases every lease held by one job and returns what it held.
    pub fn release(&mut self, job_id: &str) -> Vec<ResourceLease> {
        self.running
            .remove(job_id)
            .map_or_else(Vec::new, |held| held.leases)
    }

    /// Whether a candidate profile can be claimed without waiting.
    #[must_use]
    pub fn is_available(&self, profile: &TestResourceProfile) -> bool {
        self.holder_of(profile).is_none()
    }

    /// The current lease state, for the work item execution record.
    #[must_use]
    pub fn leases(&self) -> Vec<ResourceLease> {
        self.running
            .values()
            .flat_map(|held| held.leases.iter().cloned())
            .collect()
    }
}

/// Builds the scheduling decision for one job class and resource profile.
pub fn scheduling_decision(
    job_class: JobClass,
    profile: &TestResourceProfile,
    leases: Vec<ResourceLease>,
) -> Result<SchedulingDecision, ResourceError> {
    profile.validate()?;
    Ok(SchedulingDecision {
        job_class,
        priority: job_class.priority(),
        weight: profile.weight,
        weight_units: profile.weight.as_u32(),
        serial_group: if profile.serial_group.is_empty() {
            None
        } else {
            Some(profile.serial_group.clone())
        },
        leases,
        reserved_against: if job_class.is_background() {
            Vec::new()
        } else {
            JobClass::ALL
                .into_iter()
                .filter(|class| class.is_background())
                .collect()
        },
    })
}
