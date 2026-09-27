//! Governed work-execution envelope: the I2.22 lane tuple (issue #1897).
//!
//! I2.22 gives every mutating work item the same closed tuple:
//!
//! ```text
//! worktree; BuildFingerprint; target/build mode; fixture namespace;
//! runtime environment lease; resource claims; contract revision;
//! candidate identity.
//! ```
//!
//! [`GovernedWorkEnvelope`] is that tuple as one allocatable, persistable
//! value. It owns three properties the rest of the system currently asserts
//! but does not hold:
//!
//! * the target root, derived exactly as
//!   `%LOCALAPPDATA%\Eliot\build\<workspace-id>\<worktree-id>\<build-mode>\
//!   <fingerprint>` and never from the repository `target/`
//!   ([`GovernedWorkEnvelope::derive_target_root`]);
//! * the fixture namespace and the runtime-environment lease set, both
//!   derived from the tuple rather than from the worktree, because
//!   "a worktree does not isolate runtime resources"
//!   ([`GovernedWorkEnvelope::fixture_namespace`],
//!   [`GovernedWorkEnvelope::runtime_leases`]);
//! * the declared resource claims, without which execution is refused
//!   ([`GovernedWorkEnvelope::admit`]).
//!
//! Two work items in different worktrees therefore receive different target
//! roots, fixture namespaces, and runtime leases from the tuple alone, and a
//! worktree by itself cannot reach a shared runtime resource: obtaining one
//! requires a declared claim plus a lease, and [`GovernedWorkEnvelope::admit`]
//! fails closed when the claim set is empty.
//!
//! The envelope allocates and records; it does not launch. Attaching the
//! identity to an emitted result is [`EnvelopedInstrumentResult`], which
//! carries the fingerprint digest, candidate identity, and contract revision
//! next to the runner's own governed result so a caller can attribute it to
//! the candidate that produced it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use eliot_build_test_graph::{BuildFingerprint, GraphError, ResourceClaim};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::GovernedInstrumentResult;

/// Directory name under the local application data root that anchors every
/// governed build lane. I2.22 fixes the target roots under `Eliot\build`.
pub const BUILD_ROOT_DIRECTORY: &str = "build";

/// Environment variable a governed Cargo invocation is bound to.
///
/// The envelope emits this instead of leaving `CARGO_TARGET_DIR` unset,
/// because an unset value is exactly how a governed instrument falls back to
/// the repository `target/` directory.
pub const CARGO_TARGET_DIR_ENV: &str = "CARGO_TARGET_DIR";

/// Target and cache mode of one governed work item.
///
/// I2.22 names three cache modes. They are a closed set because the mode is a
/// path segment of the governed build root: an open spelling would let two
/// work items with different cache semantics share one root.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildMode {
    /// Separate worktree target, best repeated feedback within one lane.
    InteractiveIncremental,
    /// Shared non-incremental reuse across agents and worktrees under an
    /// exact normalized fingerprint.
    SharedNonIncremental,
    /// Locked and declared cache for a release candidate.
    Release,
}

impl BuildMode {
    /// Every declared mode, in the order I2.22 lists them.
    pub const ALL: [Self; 3] = [
        Self::InteractiveIncremental,
        Self::SharedNonIncremental,
        Self::Release,
    ];

    /// The path segment this mode contributes to the governed build root.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InteractiveIncremental => "interactive-incremental",
            Self::SharedNonIncremental => "shared-non-incremental",
            Self::Release => "release",
        }
    }
}

/// One leased runtime environment resource held by a work item.
///
/// This is the envelope's record of what a work item holds. The allocator that
/// decides exclusivity against a live holder set is
/// `eliot_testd_core::ResourceLeaseAllocator`; the envelope carries the
/// outcome so a persisted work item keeps the leases it was admitted with.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEnvironmentLease {
    /// Leased resource class.
    pub kind: eliot_build_test_graph::ResourceKind,
    /// Leased resource name, equal to the claimed name.
    pub resource: String,
    /// Holder identity, equal to this work item's ID.
    pub holder: String,
}

/// The identity every emitted result is attributed to.
///
/// The doc requires the contract revision and candidate identity as distinct
/// tuple elements from the fingerprint; they are also separately present on
/// [`BuildFingerprint`]. The envelope reads them from the one fingerprint it
/// is given, so the two can never disagree: there is no second place to
/// declare either value.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateIdentity {
    /// Digest of the exact build inputs, from
    /// [`BuildFingerprint::digest`].
    pub build_fingerprint: String,
    /// Candidate the work item integrates, from
    /// [`BuildFingerprint::candidate`].
    pub candidate: String,
    /// Frozen contract revision this execution is bound to, from
    /// [`BuildFingerprint::contract_revision`].
    pub contract_revision: String,
}

/// The complete I2.22 tuple for one mutating work item.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedWorkEnvelope {
    /// Work item identity; also the lease holder.
    pub work_item_id: String,
    /// Workspace identity; the first segment of the governed build root.
    pub workspace_id: String,
    /// Worktree identity; the second segment. Distinct worktrees must carry
    /// distinct values: a worktree does not isolate runtime resources, so
    /// the envelope cannot infer isolation from the directory.
    pub worktree_id: String,
    /// Exact build inputs. The normalized fingerprint is its digest.
    pub fingerprint: BuildFingerprint,
    /// Target and cache mode; the third segment.
    pub build_mode: BuildMode,
    /// Exclusive runtime resources this item declared before execution.
    pub resource_claims: Vec<ResourceClaim>,
    /// Leases held for the declared claims, allocated independently of the
    /// worktree.
    pub runtime_leases: Vec<RuntimeEnvironmentLease>,
    /// The fingerprint's own directory below the local application data root.
    /// Governed instruments never build in the repository `target/`.
    pub local_app_data: PathBuf,
}

/// A governed result with the lane identity that produced it attached.
#[derive(Clone, Debug)]
pub struct EnvelopedInstrumentResult {
    /// The runner's governed result: invocation, executable identity, argv,
    /// raw output, and execution axis.
    pub result: GovernedInstrumentResult,
    /// Which candidate, fingerprint, and contract revision produced it.
    pub identity: CandidateIdentity,
}

/// Failures refusing a governed work item before it executes.
///
/// Every variant is fail-closed: a work item that cannot present a complete,
/// valid tuple does not run.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkEnvelopeError {
    /// A declared tuple element is unusable as a path segment or lease name.
    #[error("invalid work envelope {field}: {reason}")]
    InvalidElement {
        /// Offending tuple element.
        field: &'static str,
        /// Why it is refused.
        reason: &'static str,
    },
    /// The build fingerprint is not a valid fingerprint.
    #[error("work envelope build fingerprint is invalid: {0}")]
    InvalidFingerprint(#[from] GraphError),
    /// The work item declared no resource claim.
    ///
    /// This is the fail-closed half of "a worktree does not isolate runtime
    /// resources": a work item that has not declared what it will touch is
    /// refused, not admitted with an implicit empty claim set.
    #[error("work item {work_item_id} declared no resource claim")]
    UndeclaredResources {
        /// The refused work item.
        work_item_id: String,
    },
    /// A declared claim is not covered by a held lease.
    #[error("work item {work_item_id} holds no {kind:?} lease for claimed resource {name}")]
    UnleasedResource {
        /// The refused work item.
        work_item_id: String,
        /// Unleased claim class.
        kind: eliot_build_test_graph::ResourceKind,
        /// Unleased claim name.
        name: String,
    },
    /// A held lease is not covered by a declared claim.
    #[error("work item {work_item_id} holds {kind:?} lease {name} without declaring it")]
    UndeclaredLease {
        /// The refused work item.
        work_item_id: String,
        /// Unbacked lease class.
        kind: eliot_build_test_graph::ResourceKind,
        /// Unbacked lease name.
        name: String,
    },
    /// The fingerprint's own fields disagree with the tuple's identity.
    #[error("work envelope fingerprint {field} does not match the tuple {value}")]
    IdentityMismatch {
        /// Mismatching fingerprint field.
        field: &'static str,
        /// The tuple value it disagreed with.
        value: String,
    },
    /// The local application data root is not absolute.
    #[error("local_app_data must be an absolute path, not {0}")]
    RelativeLocalAppData(String),
}

/// The lane identity every mutating work item is allocated in, before any
/// runtime claim is made.
///
/// `local_app_data` is the `%LOCALAPPDATA%` root the governed build lanes
/// live under; it is a parameter rather than an environment read so the
/// caller that already resolved the user's local root keeps owning it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaneIdentity {
    /// Work item identity; also the lease holder.
    pub work_item_id: String,
    /// Workspace identity; the first segment of the governed build root.
    pub workspace_id: String,
    /// Worktree identity; the second segment. Distinct worktrees must carry
    /// distinct values: a worktree does not isolate runtime resources, so
    /// isolation cannot be inferred from the directory.
    pub worktree_id: String,
    /// Exact build inputs. The normalized fingerprint is its digest.
    pub fingerprint: BuildFingerprint,
    /// Target and cache mode; the third segment.
    pub build_mode: BuildMode,
    /// The `%LOCALAPPDATA%` root anchoring the governed build lanes.
    pub local_app_data: PathBuf,
}

impl GovernedWorkEnvelope {
    /// Allocates the complete tuple for one mutating work item.
    ///
    /// The exclusive resources are supplied afterwards, because I2.22 requires
    /// that a work item *declare* what it will touch and be granted a lease
    /// for each one before it executes; a worktree alone obtains neither.
    /// [`GovernedWorkEnvelope::admit`] is the gate that refuses an item whose
    /// declaration is empty.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError`] when any tuple element is not a usable
    /// path segment, when the fingerprint is invalid, or when the
    /// fingerprint's workspace contradicts the workspace declared beside it.
    pub fn allocate(
        identity: LaneIdentity,
        resource_claims: Vec<ResourceClaim>,
        runtime_leases: Vec<RuntimeEnvironmentLease>,
    ) -> Result<Self, WorkEnvelopeError> {
        let envelope = Self {
            work_item_id: identity.work_item_id,
            workspace_id: identity.workspace_id,
            worktree_id: identity.worktree_id,
            fingerprint: identity.fingerprint,
            build_mode: identity.build_mode,
            resource_claims,
            runtime_leases,
            local_app_data: identity.local_app_data,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Rejects a tuple that cannot execute, without deriving anything.
    ///
    /// # Errors
    ///
    /// Returns the first refusal in [`WorkEnvelopeError`].
    pub fn validate(&self) -> Result<(), WorkEnvelopeError> {
        for (value, field) in [
            (&self.work_item_id, "work_item_id"),
            (&self.workspace_id, "workspace_id"),
            (&self.worktree_id, "worktree_id"),
        ] {
            segment(value, field)?;
        }
        if !self.local_app_data.is_absolute() {
            return Err(WorkEnvelopeError::RelativeLocalAppData(
                self.local_app_data.to_string_lossy().into_owned(),
            ));
        }
        self.fingerprint.validate()?;
        if self.fingerprint.workspace != self.workspace_id {
            return Err(WorkEnvelopeError::IdentityMismatch {
                field: "workspace",
                value: self.workspace_id.clone(),
            });
        }
        Ok(())
    }

    /// The normalized fingerprint: the digest of the exact build inputs.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError::InvalidFingerprint`] when the fingerprint
    /// is not a valid fingerprint.
    pub fn normalized_fingerprint(&self) -> Result<String, WorkEnvelopeError> {
        Ok(self.fingerprint.digest()?)
    }

    /// The governed target and cache root of this work item.
    ///
    /// Exactly
    /// `%LOCALAPPDATA%\Eliot\build\<workspace-id>\<worktree-id>\<build-mode>\<fingerprint>`.
    /// The fingerprint segment is its digest, so two work items in the same
    /// worktree and mode that differ only in build inputs still receive
    /// different roots, and two work items in different worktrees always do.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError`] when the fingerprint or a path segment
    /// is invalid.
    pub fn derive_target_root(&self) -> Result<PathBuf, WorkEnvelopeError> {
        self.validate()?;
        Ok(self
            .local_app_data
            .join("Eliot")
            .join(BUILD_ROOT_DIRECTORY)
            .join(&self.workspace_id)
            .join(&self.worktree_id)
            .join(self.build_mode.as_str())
            .join(self.normalized_fingerprint()?))
    }

    /// The namespace this work item's fixtures live under.
    ///
    /// Fixture state is mutable and is not isolated by a worktree, so the
    /// namespace is derived from the whole lane identity — work item, mode,
    /// and normalized fingerprint — and two work items in different worktrees
    /// never share one.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError`] when the fingerprint or a tuple element
    /// is invalid.
    pub fn fixture_namespace(&self) -> Result<String, WorkEnvelopeError> {
        self.validate()?;
        Ok(format!(
            "fx-{}-{}-{}",
            self.work_item_id,
            self.build_mode.as_str(),
            self.normalized_fingerprint()?
        ))
    }

    /// The runtime-environment leases this work item holds, in stable order.
    ///
    /// The leases are whatever the allocator granted; the envelope never
    /// derives one from the worktree, because a worktree does not isolate
    /// runtime resources.
    #[must_use]
    pub fn runtime_leases(&self) -> &[RuntimeEnvironmentLease] {
        &self.runtime_leases
    }

    /// Refuses a work item that has not declared and been granted what it will
    /// touch, and returns the identity to attach to its result.
    ///
    /// This is the fail-closed admission gate. It requires a non-empty claim
    /// set, every claim covered by a held lease, and every held lease backed
    /// by a claim, so a worktree alone cannot obtain a shared runtime
    /// resource: the tuple is the only route to one.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError::UndeclaredResources`] for an empty claim
    /// set, [`WorkEnvelopeError::UnleasedResource`] for a claim without a
    /// lease, and [`WorkEnvelopeError::UndeclaredLease`] for a lease without
    /// a claim.
    pub fn admit(&self) -> Result<CandidateIdentity, WorkEnvelopeError> {
        self.validate()?;
        if self.resource_claims.is_empty() {
            return Err(WorkEnvelopeError::UndeclaredResources {
                work_item_id: self.work_item_id.clone(),
            });
        }
        let claimed: BTreeSet<(eliot_build_test_graph::ResourceKind, &str)> = self
            .resource_claims
            .iter()
            .map(|claim| (claim.kind, claim.name.as_str()))
            .collect();
        let held: BTreeSet<(eliot_build_test_graph::ResourceKind, &str)> = self
            .runtime_leases
            .iter()
            .map(|lease| (lease.kind, lease.resource.as_str()))
            .collect();
        for (kind, name) in &claimed {
            if !held.contains(&(*kind, name)) {
                return Err(WorkEnvelopeError::UnleasedResource {
                    work_item_id: self.work_item_id.clone(),
                    kind: *kind,
                    name: (*name).to_owned(),
                });
            }
        }
        for (kind, name) in &held {
            if !claimed.contains(&(*kind, name)) {
                return Err(WorkEnvelopeError::UndeclaredLease {
                    work_item_id: self.work_item_id.clone(),
                    kind: *kind,
                    name: (*name).to_owned(),
                });
            }
        }
        self.candidate_identity()
    }

    /// The identity to attach to every result this work item emits.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError::InvalidFingerprint`] when the fingerprint
    /// is not a valid fingerprint.
    pub fn candidate_identity(&self) -> Result<CandidateIdentity, WorkEnvelopeError> {
        Ok(CandidateIdentity {
            build_fingerprint: self.normalized_fingerprint()?,
            candidate: self.fingerprint.candidate.clone(),
            contract_revision: self.fingerprint.contract_revision.clone(),
        })
    }

    /// The exact environment a governed Cargo invocation of this work item
    /// runs with.
    ///
    /// The target root is bound explicitly, so the invocation cannot fall back
    /// to the repository `target/` directory the way it would with the
    /// variable unset. `CARGO_INCREMENTAL` is set only for the interactive
    /// mode: I2.22 keeps incremental compilation and cross-worktree reuse
    /// from being enabled together as a universal optimization.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError`] when the target root cannot be derived.
    pub fn cargo_environment(&self) -> Result<Vec<(String, String)>, WorkEnvelopeError> {
        let target_root = self.derive_target_root()?;
        let mut environment = vec![(CARGO_TARGET_DIR_ENV.to_owned(), path_text(&target_root))];
        if self.build_mode == BuildMode::InteractiveIncremental {
            environment.push(("CARGO_INCREMENTAL".to_owned(), "true".to_owned()));
        }
        Ok(environment)
    }

    /// Attaches this work item's identity to one emitted governed result.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError::InvalidFingerprint`] when the fingerprint
    /// is not a valid fingerprint.
    pub fn attach(
        &self,
        result: GovernedInstrumentResult,
    ) -> Result<EnvelopedInstrumentResult, WorkEnvelopeError> {
        Ok(EnvelopedInstrumentResult {
            result,
            identity: self.candidate_identity()?,
        })
    }
}

/// Rejects a tuple element that cannot be one path segment.
///
/// A segment is a single non-blank name: no separator, no `.` or `..`
/// traversal, and no control character. Without this check a declared
/// workspace or worktree identity could place the governed build root outside
/// its own lane.
fn segment(value: &str, field: &'static str) -> Result<(), WorkEnvelopeError> {
    let invalid = |reason: &'static str| WorkEnvelopeError::InvalidElement { field, reason };
    if value.trim().is_empty() || value.trim() != value {
        return Err(invalid(
            "must be non-blank and free of surrounding whitespace",
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid("must be free of control characters"));
    }
    if value == "." || value == ".." {
        return Err(invalid("must not be a relative path segment"));
    }
    if value.contains('/') || value.contains('\\') {
        return Err(invalid("must not contain a path separator"));
    }
    Ok(())
}

/// Renders a derived root for the environment, which is text, not a path.
fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
