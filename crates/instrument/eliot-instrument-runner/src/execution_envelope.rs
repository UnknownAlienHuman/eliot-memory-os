//! Governed work-execution envelope: the lane tuple of a mutating work item
//! (I2.22, issue #1897).
//!
//! I2.22 gives every mutating work item a worktree, a `BuildFingerprint`, a
//! target/build mode, a fixture namespace, a runtime environment lease,
//! resource claims, a contract revision, and a candidate identity, and it
//! derives governed target roots as
//!
//! ```text
//! %LOCALAPPDATA%\Eliot\build\<workspace-id>\<worktree-id>\<build-mode>\<fingerprint>
//! ```
//!
//! [`ExecutionEnvelopeAllocator`] is the admitting composition root the
//! `TargetLayout` contract already reserves this role to: it derives the
//! governed roots, allocates the fixture namespace and the
//! runtime-environment lease, requires the declared resource claims, and
//! refuses a lane that collides with an already-allocated one. It never
//! creates a directory, never launches a process, and never admits evidence.
//!
//! # Non-governed local workflows
//!
//! Governed instruments use the allocated target root instead of the
//! repository `target/` directory. The one documented exception is the
//! repository's own local verification gate: `scripts/verify.ps1` is the sole
//! ordered gate-definition owner and the `just` and CI wrappers only select a
//! closed profile of it, so those gate runs are the non-governed local
//! workflow. They allocate no lane tuple and keep whatever target directory
//! the developer selects. Every instrument, verifier, fixture and
//! runtime-launch path goes through [`ExecutionEnvelope::governed_target_env`]
//! instead.
//!
//! # Relationship to the lease allocator
//!
//! I10.8.15 gives `eliot-testd` the worktree/sandbox manager and the test
//! scheduler, and `eliot_testd_core::resources` owns the closed
//! `ResourceKind` vocabulary and the `ResourceLeaseAllocator`. This crate is
//! not a dependent of that crate, so it names no second kind vocabulary and
//! performs no second lease allocation: [`RuntimeResourceClaim`] carries the
//! class label and resource name the declaring group already uses, and the
//! envelope's only resource duty is the fail-closed one I2.22 states — a
//! worktree cannot obtain an undeclared shared runtime resource.

use std::path::{Path, PathBuf};

use eliot_build_test_graph::{BuildFingerprint, GraphError};
use serde_json::Value;
use serde_json::json;
use thiserror::Error;

use crate::profile::{ProfileError, StageEnvironment, TargetLayout};

/// Environment variable that redirects a governed Cargo or test invocation
/// away from the repository `target/` directory onto the allocated lane root.
pub const GOVERNED_TARGET_DIR_ENV: &str = "CARGO_TARGET_DIR";

/// Name of the persisted lane record written inside the allocated lane root.
pub const LANE_RECORD_FILE: &str = "execution-envelope.json";

/// Fail-closed rejections from lane allocation, resource grants, and
/// persistence.
///
/// Every variant refuses the request; none of them degrades an undeclared or
/// colliding lane into a working one.
#[derive(Debug, Error)]
pub enum EnvelopeError {
    /// A required identity is blank or carries control characters.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText {
        /// Offending field.
        field: &'static str,
    },
    /// A build-root base is relative or traverses to a parent.
    #[error("build base is not an absolute parent-free root: {base}")]
    BaseNotAbsolute {
        /// Rejected base.
        base: String,
    },
    /// A workspace or worktree identity cannot be one path segment.
    #[error("{field} '{segment}' is not a single safe path segment")]
    UnsafePathSegment {
        /// Offending field.
        field: &'static str,
        /// Rejected segment.
        segment: String,
    },
    /// The build fingerprint failed its own validation.
    #[error(transparent)]
    InvalidFingerprint(#[from] GraphError),
    /// The derived roots failed the `TargetLayout` contract.
    #[error(transparent)]
    InvalidLayout(#[from] ProfileError),
    /// One work item declared the same resource claim twice.
    #[error("duplicate resource claim {class}/{resource} in one work item")]
    DuplicateClaim {
        /// Declared class.
        class: String,
        /// Declared resource.
        resource: String,
    },
    /// The work item already holds a lane; a work item has exactly one tuple.
    #[error("work item '{work_item_id}' already holds a lane")]
    WorkItemAlreadyAllocated {
        /// Re-allocated work item.
        work_item_id: String,
    },
    /// The derived lane element is already held by another work item, so two
    /// concurrent work items would share it.
    #[error("lane {element} '{value}' is already held by work item '{holder}'")]
    LaneCollision {
        /// Colliding element: `target_root`, `fixture_namespace` or
        /// `runtime_lease`.
        element: &'static str,
        /// Colliding value.
        value: String,
        /// Work item currently holding it.
        holder: String,
    },
    /// A shared runtime resource was requested that the work item never
    /// declared.
    #[error("resource {class}/{resource} was not declared by this work item")]
    UndeclaredResource {
        /// Requested class.
        class: String,
        /// Requested resource.
        resource: String,
    },
    /// The allocated lane root does not exist; the sandbox owner provisions
    /// it and this crate never creates a directory.
    #[error("lane root '{path}' is not a provisioned directory")]
    LaneRootAbsent {
        /// Absent lane root.
        path: String,
    },
    /// The lane record could not be written.
    #[error("persisting the lane record at '{path}' failed: {reason}")]
    Persist {
        /// Target record path.
        path: String,
        /// Underlying cause.
        reason: String,
    },
}

/// The target/build mode of a lane, spelled as the I2.22 cache modes.
///
/// The spelling is the stable path segment for the mode inside the governed
/// build root.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BuildMode {
    /// Interactive incremental: a separate worktree target, giving the best
    /// repeated feedback within one lane.
    InteractiveIncremental,
    /// Shared non-incremental plus `sccache`: reuse across agents and
    /// worktrees under an exact normalized fingerprint.
    SharedSccache,
    /// Release: a locked and declared cache whose proof depends on source,
    /// tool and run identity rather than on a cache hit.
    Release,
}

impl BuildMode {
    /// Every declared mode, in canonical order.
    pub const ALL: [Self; 3] = [
        Self::InteractiveIncremental,
        Self::SharedSccache,
        Self::Release,
    ];

    /// Stable path-segment spelling of the mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InteractiveIncremental => "interactive-incremental",
            Self::SharedSccache => "shared-sccache",
            Self::Release => "release",
        }
    }
}

/// One shared runtime resource a work item declares before execution.
///
/// I2.22 states that a worktree does not isolate runtime resources, so a
/// claim is what makes a resource obtainable at all: the class label and
/// resource name are the declaring group's own vocabulary, carried here
/// without re-declaring the owning kind enumeration.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RuntimeResourceClaim {
    /// Class label the declaring group uses for this resource kind, such as
    /// `port` or `database_volume`.
    pub class: String,
    /// Declared resource name, unique within one work item's claim set.
    pub resource: String,
}

/// The exclusive runtime environment one work item runs in.
///
/// The lease is keyed on the work item, never on the worktree, so two
/// concurrent work items sharing one worktree still hold separate leases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeEnvironmentLease {
    /// Lease identity, allocated per work item.
    pub lease_id: String,
    /// Holder work-item identity.
    pub work_item_id: String,
    /// Attested environment class and material digest for the leased
    /// environment.
    pub environment: StageEnvironment,
}

/// The mutable work item a lane tuple is allocated for.
///
/// The workspace identity and the candidate and contract revision are read
/// from [`WorkItemRequest::fingerprint`], which is their single owner.
#[derive(Clone, Debug)]
pub struct WorkItemRequest {
    /// Mutating work-item identity. One lane tuple exists per work item.
    pub work_item_id: String,
    /// Worktree identity. It isolates source writes, never runtime resources.
    pub worktree_id: String,
    /// Build fingerprint the work item runs under, carrying the workspace
    /// identity, the candidate identity, and the contract revision.
    pub fingerprint: BuildFingerprint,
    /// Target/build mode of this lane.
    pub build_mode: BuildMode,
    /// Admitted source root: the worktree directory the instrument runs in.
    pub source_root: String,
    /// Admitted cache root. I2.22 fixes the target-root shape only, so the
    /// cache root stays an admitted root rather than a derived one.
    pub cache_root: String,
    /// Runtime environment material attested into the lease.
    pub environment_material: String,
    /// Shared runtime resources this work item declares. A work item that
    /// needs none declares none and may still run; it simply cannot obtain
    /// any undeclared resource.
    pub resource_claims: Vec<RuntimeResourceClaim>,
}

/// The complete governed lane tuple of one mutating work item.
///
/// Construction goes through [`ExecutionEnvelopeAllocator::allocate`]; the
/// fields are public so a composition root can read the tuple it was handed
/// and so the persisted record and the emitted attribution can be compared
/// against it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionEnvelope {
    /// Work item this lane belongs to.
    pub work_item_id: String,
    /// Worktree identity segment of the governed build root.
    pub worktree_id: String,
    /// Build fingerprint: workspace, candidate, contract revision, closure,
    /// and build class in one owner.
    pub fingerprint: BuildFingerprint,
    /// Target/build mode of this lane.
    pub build_mode: BuildMode,
    /// Normalized fingerprint digest, used both as the build-root path
    /// segment and as the build fingerprint every emitted result reports.
    pub normalized_fingerprint: String,
    /// Admitted roots: the worktree source root, the derived governed target
    /// root, and the admitted cache root.
    pub layout: TargetLayout,
    /// Allocated fixture namespace, keyed on the work item.
    pub fixture_namespace: String,
    /// Allocated runtime-environment lease, keyed on the work item.
    pub runtime_lease: RuntimeEnvironmentLease,
    /// Declared shared runtime resources.
    pub resource_claims: Vec<RuntimeResourceClaim>,
}

impl ExecutionEnvelope {
    /// Workspace identity of the lane, from the fingerprint.
    #[must_use]
    pub fn workspace_id(&self) -> &str {
        &self.fingerprint.workspace
    }

    /// Candidate identity of the lane, from the fingerprint.
    #[must_use]
    pub fn candidate(&self) -> &str {
        &self.fingerprint.candidate
    }

    /// Contract revision of the lane, from the fingerprint.
    #[must_use]
    pub fn contract_revision(&self) -> &str {
        &self.fingerprint.contract_revision
    }

    /// The derived governed target root, never the repository `target/`.
    #[must_use]
    pub fn target_root(&self) -> &str {
        &self.layout.target_root
    }

    /// Process environment that points a governed Cargo or test invocation
    /// at the allocated target root.
    ///
    /// The same projection is applied to the build invocation and to the test
    /// invocation, so neither resolves the repository `target/` directory.
    /// Adapters that need the flag form of the same root read
    /// [`ExecutionEnvelope::target_root`].
    #[must_use]
    pub fn governed_target_env(&self) -> Vec<(String, String)> {
        vec![(
            GOVERNED_TARGET_DIR_ENV.to_owned(),
            self.layout.target_root.clone(),
        )]
    }

    /// Grants one declared shared runtime resource under this lane's lease.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::UndeclaredResource`] when the class and
    /// resource were not declared by this work item, so a worktree alone can
    /// never obtain an undeclared shared runtime resource.
    pub fn grant_declared_resource(
        &self,
        class: &str,
        resource: &str,
    ) -> Result<GrantedResource, EnvelopeError> {
        if !self
            .resource_claims
            .iter()
            .any(|claim| claim.class == class && claim.resource == resource)
        {
            return Err(EnvelopeError::UndeclaredResource {
                class: class.to_owned(),
                resource: resource.to_owned(),
            });
        }
        Ok(GrantedResource {
            work_item_id: self.work_item_id.clone(),
            runtime_lease_id: self.runtime_lease.lease_id.clone(),
            class: class.to_owned(),
            resource: resource.to_owned(),
        })
    }

    /// Lane attribution stamped on every artifact and result this lane emits.
    ///
    /// It carries the build fingerprint, the candidate identity, and the
    /// contract revision, so a result can be attributed to one lane without
    /// consulting the lane afterwards.
    #[must_use]
    pub fn attribution(&self) -> LaneAttribution {
        LaneAttribution {
            work_item_id: self.work_item_id.clone(),
            workspace_id: self.fingerprint.workspace.clone(),
            worktree_id: self.worktree_id.clone(),
            build_mode: self.build_mode.as_str().to_owned(),
            normalized_fingerprint: self.normalized_fingerprint.clone(),
            candidate: self.fingerprint.candidate.clone(),
            contract_revision: self.fingerprint.contract_revision.clone(),
            target_root: self.layout.target_root.clone(),
            fixture_namespace: self.fixture_namespace.clone(),
            runtime_lease_id: self.runtime_lease.lease_id.clone(),
        }
    }

    /// Persists the complete lane tuple as `LANE_RECORD_FILE` inside the
    /// allocated lane root.
    ///
    /// This is the lane existence check the `TargetLayout` contract reserves
    /// to the admitting composition root: the sandbox owner provisions the
    /// lane root, so a missing root is a typed [`EnvelopeError::LaneRootAbsent`]
    /// and this call never creates a directory.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::Persist`] when the record cannot be written.
    pub fn persist(&self) -> Result<PathBuf, EnvelopeError> {
        let path = Path::new(self.target_root()).join(LANE_RECORD_FILE);
        let record = serde_json::to_string_pretty(&self.record()).map_err(|error| {
            EnvelopeError::Persist {
                path: path.display().to_string(),
                reason: error.to_string(),
            }
        })?;
        std::fs::write(&path, record).map_err(|error| {
            let path = path.display().to_string();
            if !Path::new(&path).parent().is_some_and(Path::exists) {
                return EnvelopeError::LaneRootAbsent { path };
            }
            EnvelopeError::Persist {
                path,
                reason: error.to_string(),
            }
        })?;
        Ok(path)
    }

    /// The three lane elements that must stay distinct across concurrent work
    /// items: the governed target root, the fixture namespace, and the
    /// runtime-environment lease.
    fn lane_elements(&self) -> [(&'static str, &str); 3] {
        [
            ("target_root", &self.layout.target_root),
            ("fixture_namespace", &self.fixture_namespace),
            ("runtime_lease", &self.runtime_lease.lease_id),
        ]
    }

    /// The canonical persisted record: the complete lane tuple.
    fn record(&self) -> Value {
        let fingerprint = serde_json::to_value(&self.fingerprint).unwrap_or(Value::Null);
        json!({
            "work_item_id": self.work_item_id,
            "workspace_id": self.fingerprint.workspace,
            "worktree_id": self.worktree_id,
            "build_mode": self.build_mode.as_str(),
            "normalized_fingerprint": self.normalized_fingerprint,
            "build_fingerprint": fingerprint,
            "source_root": self.layout.source_root,
            "target_root": self.layout.target_root,
            "cache_root": self.layout.cache_root,
            "fixture_namespace": self.fixture_namespace,
            "runtime_lease": {
                "lease_id": self.runtime_lease.lease_id,
                "work_item_id": self.runtime_lease.work_item_id,
                "environment_class": self.runtime_lease.environment.class,
                "environment_digest": self.runtime_lease.environment.digest,
            },
            "resource_claims": self.resource_claims.iter().map(|claim| {
                json!({ "class": claim.class, "resource": claim.resource })
            }).collect::<Vec<Value>>(),
            "contract_revision": self.fingerprint.contract_revision,
            "candidate": self.fingerprint.candidate,
        })
    }
}

/// A shared runtime resource this lane may use, granted under its lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantedResource {
    /// Work item the grant belongs to.
    pub work_item_id: String,
    /// Runtime-environment lease the grant is held under.
    pub runtime_lease_id: String,
    /// Granted class.
    pub class: String,
    /// Granted resource.
    pub resource: String,
}

/// Lane attribution attached to emitted artifacts and results.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaneAttribution {
    /// Work item that emitted the result.
    pub work_item_id: String,
    /// Workspace identity of the lane.
    pub workspace_id: String,
    /// Worktree identity of the lane.
    pub worktree_id: String,
    /// Target/build mode of the lane.
    pub build_mode: String,
    /// Normalized build fingerprint of the lane.
    pub normalized_fingerprint: String,
    /// Candidate identity the result belongs to.
    pub candidate: String,
    /// Contract revision the result was produced under.
    pub contract_revision: String,
    /// Governed target root the result was produced in.
    pub target_root: String,
    /// Fixture namespace the result was produced under.
    pub fixture_namespace: String,
    /// Runtime-environment lease the result was produced under.
    pub runtime_lease_id: String,
}

/// The admitting composition root that allocates governed lane tuples.
///
/// The allocator holds the governed build-root base and the ledger of lanes it
/// has already handed out. It refuses a work item that already holds a lane
/// and refuses any derived target root, fixture namespace, or
/// runtime-environment lease already held by another work item, so two
/// concurrent work items in separate worktrees always receive distinct ones.
/// It performs no filesystem mutation: the sandbox owner provisions the lane
/// roots and the record is written by
/// [`ExecutionEnvelope::persist`].
pub struct ExecutionEnvelopeAllocator {
    build_base: String,
    allocated: Vec<ExecutionEnvelope>,
}

impl ExecutionEnvelopeAllocator {
    /// Creates an allocator over a governed build-root base.
    ///
    /// I2.22 spells the base `%LOCALAPPDATA%\Eliot\build`; the base is taken
    /// from the caller rather than read from the environment so the same
    /// allocator serves any governed root and the derived shape stays
    /// verifiable.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::BaseNotAbsolute`] when the base is relative
    /// or traverses to a parent, and [`EnvelopeError::InvalidText`] when it is
    /// blank or carries control characters.
    pub fn new(build_base: String) -> Result<Self, EnvelopeError> {
        validate_text(&build_base, "build_base")?;
        let path = Path::new(&build_base);
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(EnvelopeError::BaseNotAbsolute { base: build_base });
        }
        Ok(Self {
            build_base,
            allocated: Vec::new(),
        })
    }

    /// Allocates and persists-ready lane tuples are handed out here.
    #[must_use]
    pub fn allocated(&self) -> &[ExecutionEnvelope] {
        &self.allocated
    }

    /// Allocates the complete lane tuple for one mutating work item.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::InvalidText`], [`EnvelopeError::UnsafePathSegment`],
    /// [`EnvelopeError::BaseNotAbsolute`], [`EnvelopeError::InvalidFingerprint`],
    /// [`EnvelopeError::InvalidLayout`], [`EnvelopeError::DuplicateClaim`],
    /// [`EnvelopeError::WorkItemAlreadyAllocated`], or
    /// [`EnvelopeError::LaneCollision`].
    pub fn allocate(
        &mut self,
        request: WorkItemRequest,
    ) -> Result<ExecutionEnvelope, EnvelopeError> {
        for (field, value) in [
            ("work_item_id", request.work_item_id.as_str()),
            ("worktree_id", request.worktree_id.as_str()),
            ("source_root", request.source_root.as_str()),
            ("cache_root", request.cache_root.as_str()),
        ] {
            validate_text(value, field)?;
        }
        validate_segment(&request.worktree_id, "worktree_id")?;
        validate_segment(&request.fingerprint.workspace, "workspace")?;
        if self
            .allocated
            .iter()
            .any(|envelope| envelope.work_item_id == request.work_item_id)
        {
            return Err(EnvelopeError::WorkItemAlreadyAllocated {
                work_item_id: request.work_item_id,
            });
        }
        let mut claims = request.resource_claims;
        claims.sort();
        for pair in claims.windows(2) {
            if pair[0] == pair[1] {
                return Err(EnvelopeError::DuplicateClaim {
                    class: pair[0].class.clone(),
                    resource: pair[0].resource.clone(),
                });
            }
        }
        for claim in &claims {
            validate_text(&claim.class, "resource_claim.class")?;
            validate_text(&claim.resource, "resource_claim.resource")?;
        }
        let normalized_fingerprint = request.fingerprint.digest()?;
        let target_root = Path::new(&self.build_base)
            .join(&request.fingerprint.workspace)
            .join(&request.worktree_id)
            .join(request.build_mode.as_str())
            .join(&normalized_fingerprint)
            .display()
            .to_string();
        let layout = TargetLayout::new(request.source_root, target_root, request.cache_root)?;
        let fixture_namespace = format!("fx-{}", request.work_item_id);
        let runtime_lease = RuntimeEnvironmentLease {
            lease_id: format!("env-{}", request.work_item_id),
            work_item_id: request.work_item_id.clone(),
            environment: StageEnvironment::attest(
                request.fingerprint.environment_class.clone(),
                &request.environment_material,
            )?,
        };
        let envelope = ExecutionEnvelope {
            work_item_id: request.work_item_id,
            worktree_id: request.worktree_id,
            fingerprint: request.fingerprint,
            build_mode: request.build_mode,
            normalized_fingerprint,
            layout,
            fixture_namespace,
            runtime_lease,
            resource_claims: claims,
        };
        for (element, value) in envelope.lane_elements() {
            let held = self
                .allocated
                .iter()
                .find(|other| other.lane_elements().contains(&(element, value)));
            if let Some(holder) = held {
                return Err(EnvelopeError::LaneCollision {
                    element,
                    value: value.to_owned(),
                    holder: holder.work_item_id.clone(),
                });
            }
        }
        self.allocated.push(envelope.clone());
        Ok(envelope)
    }
}

fn validate_text(value: &str, field: &'static str) -> Result<(), EnvelopeError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(EnvelopeError::InvalidText { field });
    }
    Ok(())
}

fn validate_segment(value: &str, field: &'static str) -> Result<(), EnvelopeError> {
    validate_text(value, field)?;
    if value == "." || value == ".." || value.contains('/') || value.contains('\\') {
        return Err(EnvelopeError::UnsafePathSegment {
            field,
            segment: value.to_owned(),
        });
    }
    Ok(())
}
