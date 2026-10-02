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
//!   <fingerprint>` and never from the repository `target/`, under the caller's
//!   *actual* resolved local application-data root rather than a literal path
//!   ([`GovernedWorkEnvelope::derive_target_root`]);
//! * the fixture namespace, derived from the tuple rather than from the
//!   worktree, because "a worktree does not isolate runtime resources"
//!   ([`GovernedWorkEnvelope::fixture_namespace`]);
//! * the declared resource claims, without which execution is refused
//!   ([`GovernedWorkEnvelope::admit`]).
//!
//! Two work items in different worktrees therefore receive different target
//! roots and different fixture namespaces from the tuple alone. Their runtime
//! leases do **not** come from the tuple: "a worktree does not isolate runtime
//! resources", so a lease is exclusive only against the live holder set its
//! allocator owns (`eliot_testd_core::ResourceLeaseAllocator`). The envelope
//! carries the grant that allocator returned, and the two entry points that can
//! write that record — [`GovernedWorkEnvelope::allocate`] and
//! [`GovernedWorkEnvelope::with_granted_leases`] — bind it to this work item,
//! so two jobs cannot present one another's lease DTO. A worktree by itself
//! still cannot reach a shared runtime resource: obtaining one requires a
//! declared claim plus a lease, and [`GovernedWorkEnvelope::admit`] fails
//! closed when the claim set is empty.
//!
//! The envelope allocates and records; it does not launch. Callers attach the
//! lane identity to emitted results through [`CandidateIdentity`], which
//! carries the fingerprint digest, candidate identity, and contract revision
//! next to the execution's own governed result so a caller can attribute it to
//! the candidate that produced it. The instrument runner wraps its governed
//! results with this identity and the test daemon persists it on the
//! verification receipt; both read it from the one envelope, so the two can
//! never disagree.
//!
//! The tuple lives in the build/test graph for the same reason the resource
//! declaration does: a governed work item is admitted on the instrument plane
//! and executed on the test daemon, and both sides depend on this crate and
//! never on each other, so one envelope type here stops two competing lane
//! tuples from existing.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{BuildFingerprint, GraphError, ResourceClaim};

/// Directory name under the local application data root that anchors every
/// governed build lane. I2.22 fixes the target roots under `Eliot\build`.
pub const BUILD_ROOT_DIRECTORY: &str = "build";

/// Environment variable a governed Cargo invocation is bound to.
///
/// The envelope emits this instead of leaving `CARGO_TARGET_DIR` unset,
/// because an unset value is exactly how a governed instrument falls back to
/// the repository `target/` directory.
pub const CARGO_TARGET_DIR_ENV: &str = "CARGO_TARGET_DIR";

/// Environment variable a governed Cargo invocation's cache root is bound to.
///
/// The envelope emits this beside [`CARGO_TARGET_DIR_ENV`] and to the same
/// directory, because an unset `CARGO_HOME` is how a governed invocation reads
/// the user-global Cargo cache instead of its own lane's root.
pub const CARGO_HOME_ENV: &str = "CARGO_HOME";

/// Directory name under the local application data root that anchors every
/// governed fixture root. It is the fixture sibling of [`BUILD_ROOT_DIRECTORY`]:
/// fixture state is mutable runtime state, so it lives outside the build tree
/// while sharing the one admitted root both derivations are anchored to.
pub const FIXTURE_ROOT_DIRECTORY: &str = "fixtures";

/// Environment variable a governed child process's fixture namespace is bound
/// to.
///
/// Without it the child has no way to learn which namespace it was admitted
/// under, and every test it runs would resolve the same ambient fixture
/// location that its concurrent neighbours use.
pub const FIXTURE_NAMESPACE_ENV: &str = "ELIOT_TESTD_FIXTURE_NAMESPACE";

/// Environment variable a governed child process's physical fixture root is
/// bound to.
///
/// The namespace is the derived identity and this is the directory it resolves
/// to. A child that writes fixtures writes under this root, so two work items
/// with different namespaces touch different directories.
pub const FIXTURE_ROOT_ENV: &str = "ELIOT_TESTD_FIXTURE_ROOT";

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
/// Equal field values are not a grant: only a caller that received these
/// leases from that allocator may write them, and
/// [`WorkEnvelopeError::ForeignLeaseHolder`] refuses any record whose holder is
/// not this work item.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEnvironmentLease {
    /// Leased resource class.
    pub kind: crate::ResourceKind,
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
    ///
    /// Private on purpose: a lease record is only ever written by
    /// [`GovernedWorkEnvelope::allocate`] and
    /// [`GovernedWorkEnvelope::with_granted_leases`], both of which bind it to
    /// this work item and cross-check it against the declared claims. A caller
    /// cannot assemble a competing holder set beside the store's own.
    runtime_leases: Vec<RuntimeEnvironmentLease>,
    /// The fingerprint's own directory below the local application data root.
    /// Governed instruments never build in the repository `target/`.
    pub local_app_data: PathBuf,
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
        kind: crate::ResourceKind,
        /// Unleased claim name.
        name: String,
    },
    /// A held lease is not covered by a declared claim.
    #[error("work item {work_item_id} holds {kind:?} lease {name} without declaring it")]
    UndeclaredLease {
        /// The refused work item.
        work_item_id: String,
        /// Unbacked lease class.
        kind: crate::ResourceKind,
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
    /// The local application data root is not an existing canonical directory.
    ///
    /// The governed build root is derived below this root, so an unverified
    /// root places the lane outside the user's actual application-data tree —
    /// the issue text's literal `C:\Users\kleym` shape is not a product
    /// requirement, and neither is any other caller-supplied path.
    #[error("local_app_data must be an existing canonical directory, not {0}")]
    UnresolvedLocalAppData(String),
    /// A retained lease record names a holder that is not this work item.
    ///
    /// The lease set is written only from an allocator grant, and a grant names
    /// the job it was made for. A record naming any other holder is a copied
    /// DTO, not an allocation, and is refused before the tuple can execute: two
    /// jobs cannot hold one exclusive resource by presenting identical lease
    /// records, because the record is bound to the holder.
    #[error(
        "work item {work_item_id} presents a {kind:?} lease on {name} held by {holder}, not by itself"
    )]
    ForeignLeaseHolder {
        /// The work item presenting the record.
        work_item_id: String,
        /// Leased resource class of the foreign record.
        kind: crate::ResourceKind,
        /// Leased resource name of the foreign record.
        name: String,
        /// Holder the record names instead.
        holder: String,
    },
    /// A lease is bound to a holder while the resource claims are not yet bound
    /// to any allocation.
    ///
    /// I2.22 requires a work item to *declare* what it will touch before it is
    /// granted anything, so leases are attached to an item that already
    /// declared them. An empty claim set is legitimate for a parallel-safe
    /// declaration and is refused by [`GovernedWorkEnvelope::admit`], not here.
    #[error("work item {work_item_id} holds runtime leases but declared no resource claim")]
    UnclaimedLease {
        /// The refused work item.
        work_item_id: String,
    },
}

/// The lane identity every mutating work item is allocated in, before any
/// runtime claim is made.
///
/// `local_app_data` is the `%LOCALAPPDATA%` root the governed build lanes
/// live under; it is a parameter rather than an environment read so the
/// caller that already resolved the user's local root keeps owning it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

impl LaneIdentity {
    /// The namespace this work item's fixtures live under.
    ///
    /// The same derivation as [`GovernedWorkEnvelope::fixture_namespace`], read
    /// off the pre-allocation identity: a submitting owner declares its
    /// resource claims from this value, so the claims it declares and the
    /// namespace the store later derives cannot be two different derivations.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError`] when a tuple element or the fingerprint is
    /// invalid.
    pub fn fixture_namespace(&self) -> Result<String, WorkEnvelopeError> {
        validate_lane_elements(
            &self.work_item_id,
            &self.workspace_id,
            &self.worktree_id,
            &self.fingerprint,
        )?;
        fixture_namespace_of(&self.work_item_id, self.build_mode, &self.fingerprint)
    }

    /// The physical fixture directory this work item's fixtures live under.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError`] when a tuple element or the fingerprint is
    /// invalid.
    pub fn fixture_root(&self) -> Result<PathBuf, WorkEnvelopeError> {
        Ok(fixture_root_of(
            &self.local_app_data,
            &self.fixture_namespace()?,
        ))
    }

    /// The exact fixture bindings a governed child process of this lane runs
    /// with, before the envelope is allocated.
    ///
    /// This is the same pair [`GovernedWorkEnvelope::fixture_environment`]
    /// emits, read off the one pre-allocation identity, so a submitting owner
    /// can name in its declaration the very environment the admitted child will
    /// be given rather than only the claim the allocator grants a lease
    /// against. The two derivations are one: both resolve the root through
    /// [`Self::fixture_root`], which is a function of the retained namespace,
    /// so the lane and the envelope it allocates cannot describe two different
    /// lanes.
    ///
    /// Without this, the namespace a lane declares would reach disk only
    /// through the envelope, and the claims it declares before allocation would
    /// be checked against a derivation the owner cannot read.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError`] when a tuple element or the fingerprint is
    /// invalid.
    pub fn fixture_environment(&self) -> Result<Vec<(String, String)>, WorkEnvelopeError> {
        let namespace = self.fixture_namespace()?;
        let root = self.fixture_root()?;
        Ok(vec![
            (FIXTURE_NAMESPACE_ENV.to_owned(), namespace),
            (FIXTURE_ROOT_ENV.to_owned(), path_text(&root)),
        ])
    }

    /// The exclusive runtime resources this lane declares before it executes.
    ///
    /// The productive verifier run writes mutable fixture state, and a worktree
    /// does not isolate runtime state, so the fixture root it was allocated is
    /// an exclusive resource of its own. The claim is named by the derived
    /// fixture root rather than by a fixed label, so two work items with
    /// different namespaces claim different resources and receive different
    /// leases, while two work items that somehow resolved one root are refused
    /// by the allocator instead of sharing it.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError`] when the namespace cannot be derived.
    pub fn fixture_resource_claims(&self) -> Result<Vec<ResourceClaim>, WorkEnvelopeError> {
        let root = self.fixture_root()?;
        Ok(vec![ResourceClaim {
            kind: crate::ResourceKind::Fixture,
            name: path_text(&root),
        }])
    }
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
    /// Leases presented here are already bound: each one must name this work
    /// item as its holder, and a lease set presented by an item that declared
    /// no claim is refused. An item that has not been granted anything yet
    /// passes an empty set, which is the normal state between admission and
    /// the allocator's grant.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError`] when any tuple element is not a usable
    /// path segment, when the fingerprint is invalid, when the fingerprint's
    /// workspace contradicts the workspace declared beside it, or when the
    /// presented leases are not this work item's own.
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
        envelope.require_own_leases()?;
        Ok(envelope)
    }

    /// Attaches an allocator's actual grant to this retained envelope.
    ///
    /// This is the only other way the retained lease record is written, so the
    /// persisted tuple is always one `allocate` produced. The caller passes the
    /// `Vec<ResourceLease>` a live `eliot_testd_core::ResourceLeaseAllocator`
    /// returned for this job; matching field values supplied by a caller are
    /// not a grant, and the holder check below refuses any record the allocator
    /// could not have issued for this work item.
    ///
    /// The tuple itself is never rebuilt: the work item, workspace, worktree,
    /// fingerprint, build mode, local application data root and declared claims
    /// are read off this envelope, never re-derived from the current ambient
    /// environment. A replay therefore cannot substitute candidate, root, or
    /// lease identity for the retained one.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError`] when a granted record names another
    /// holder, or when leases are attached to an item that declared no claim.
    pub fn with_granted_leases(
        mut self,
        granted: Vec<RuntimeEnvironmentLease>,
    ) -> Result<Self, WorkEnvelopeError> {
        self.runtime_leases = granted;
        self.require_own_leases()?;
        Ok(self)
    }

    /// Requalifies a retained tuple before its work item executes again.
    ///
    /// This is the receipt and restart gate. A restart re-reads the persisted
    /// tuple and then asks the allocator what it currently holds, so the
    /// retained lease record is checked against the item that must own it
    /// before the item runs once more. Everything the tuple asserts is
    /// re-derived from the retained value itself; nothing is taken from the
    /// current ambient environment, so a replay cannot substitute candidate,
    /// root, or lease identity for the retained one.
    ///
    /// Unlike [`GovernedWorkEnvelope::admit`] this does not require a non-empty
    /// claim set, because a parallel-safe declaration legitimately claims
    /// nothing. It refuses a malformed tuple, a lease this item was never
    /// granted, and a lease set with no declaration behind it.
    ///
    /// # Errors
    ///
    /// Returns the first refusal in [`WorkEnvelopeError`].
    pub fn requalify(&self) -> Result<(), WorkEnvelopeError> {
        self.validate()?;
        self.require_own_leases()
    }

    /// Refuses a lease record this work item was never granted.
    ///
    /// A lease is a grant, not a name: the allocator that decides exclusivity
    /// binds every grant to the job it allocated for. Comparing the record's
    /// holder against this work item is what stops two jobs from holding one
    /// exclusive port, service, fixture, or database volume by presenting
    /// identical lease DTOs. An item that declared no claim may hold nothing.
    fn require_own_leases(&self) -> Result<(), WorkEnvelopeError> {
        if !self.runtime_leases.is_empty() && self.resource_claims.is_empty() {
            return Err(WorkEnvelopeError::UnclaimedLease {
                work_item_id: self.work_item_id.clone(),
            });
        }
        for lease in &self.runtime_leases {
            if lease.holder != self.work_item_id {
                return Err(WorkEnvelopeError::ForeignLeaseHolder {
                    work_item_id: self.work_item_id.clone(),
                    kind: lease.kind,
                    name: lease.resource.clone(),
                    holder: lease.holder.clone(),
                });
            }
        }
        Ok(())
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
        // I2.22 names `%LOCALAPPDATA%`; the product requirement is the ACTUAL
        // admitted local application-data root, not a literal path copied from
        // documentation. Requiring it to be an existing canonical directory is
        // what makes "the real root" checkable: a typo, a stale install
        // mapping, or a hard-coded user name fails closed here instead of
        // silently deriving every governed build root under a path that does
        // not exist. Canonicalization also refuses a symlink or reparse hop
        // between the admitted root and the lane it anchors.
        let canonical = std::fs::canonicalize(&self.local_app_data).map_err(|_| {
            WorkEnvelopeError::UnresolvedLocalAppData(
                self.local_app_data.to_string_lossy().into_owned(),
            )
        })?;
        if canonical != self.local_app_data || !canonical.is_dir() {
            return Err(WorkEnvelopeError::UnresolvedLocalAppData(
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
        fixture_namespace_of(&self.work_item_id, self.build_mode, &self.fingerprint)
    }

    /// The physical fixture directory this work item's fixtures live under.
    ///
    /// Exactly
    /// `%LOCALAPPDATA%\Eliot\fixtures\<fixture namespace>`. The namespace is
    /// the LAST path segment, so the one retained string and the physical
    /// directory cannot drift: there is no second name to keep in step with it.
    /// The namespace is derived from the whole lane tuple, so two work items
    /// never share one directory, and the directory lives outside the build
    /// root so the Cargo lane never owns or cleans runtime fixture state.
    ///
    /// This is the input that makes the stored namespace physical: the runtime
    /// claim a work item declares ([`LaneIdentity::fixture_resource_claims`]),
    /// the directory the Kernel creates per job, and every child environment
    /// that names it all resolve through this one function, so a namespace that
    /// is stored but not honoured has no way to reach disk.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError`] when the fingerprint or a tuple element
    /// is invalid.
    pub fn fixture_root(&self) -> Result<PathBuf, WorkEnvelopeError> {
        self.validate()?;
        Ok(fixture_root_of(
            &self.local_app_data,
            &self.fixture_namespace()?,
        ))
    }

    /// The exact fixture bindings a governed child process of this work item
    /// runs with.
    ///
    /// The namespace is the derived identity, the root is the directory it
    /// resolves to, and both are emitted together: a child that knows the root
    /// without the namespace cannot prove which lane allocated it, and a child
    /// that knows the namespace without the root still resolves an ambient
    /// fixture location. The root is read back from [`Self::fixture_root`],
    /// which resolves it from the one retained namespace, so the two values a
    /// child is given cannot name two different lanes. A work item with no
    /// fixture root therefore cannot be started by any governed instrument.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError`] when the fingerprint or a tuple element
    /// is invalid.
    pub fn fixture_environment(&self) -> Result<Vec<(String, String)>, WorkEnvelopeError> {
        let namespace = self.fixture_namespace()?;
        let root = self.fixture_root()?;
        Ok(vec![
            (FIXTURE_NAMESPACE_ENV.to_owned(), namespace),
            (FIXTURE_ROOT_ENV.to_owned(), path_text(&root)),
        ])
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
    /// This is the fail-closed admission gate, and it is the gate the execution
    /// path runs: a retained work item is admitted again before its process
    /// starts, not merely requalified for shape. It requires a non-empty claim
    /// set, every claim covered by a held lease, every held lease backed by a
    /// claim, and every held lease granted to this work item, so a worktree
    /// alone cannot obtain a shared runtime resource: the tuple is the only
    /// route to one, and the tuple carries who the grant was made for. A work
    /// item that declares nothing is refused here rather than executed with an
    /// implicit empty claim set, which is the only reading under which an empty
    /// persisted lease vector would be a sufficient runtime isolation record.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError::UndeclaredResources`] for an empty claim
    /// set, [`WorkEnvelopeError::UnleasedResource`] for a claim without a
    /// lease, [`WorkEnvelopeError::UndeclaredLease`] for a lease without a
    /// claim, and [`WorkEnvelopeError::ForeignLeaseHolder`] for a lease held by
    /// another work item.
    pub fn admit(&self) -> Result<CandidateIdentity, WorkEnvelopeError> {
        self.validate()?;
        self.require_own_leases()?;
        if self.resource_claims.is_empty() {
            return Err(WorkEnvelopeError::UndeclaredResources {
                work_item_id: self.work_item_id.clone(),
            });
        }
        let claimed: BTreeSet<(crate::ResourceKind, &str)> = self
            .resource_claims
            .iter()
            .map(|claim| (claim.kind, claim.name.as_str()))
            .collect();
        let held: BTreeSet<(crate::ResourceKind, &str)> = self
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
    /// Both governed roots are bound explicitly and to the *same* directory:
    /// `CARGO_TARGET_DIR` so the invocation cannot fall back to the repository
    /// `target/` directory the way it would with the variable unset, and
    /// `CARGO_HOME` so it cannot fall back to the user-global Cargo home. The
    /// equality is the concrete `TestD` `TargetRoots` policy — the
    /// `cache_root == target_root` rule — and its resolver
    /// (`TestdProcessToolIntent::validate_for_roots`), which refuses any pair
    /// that is not the same canonical directory. Emitting one variable without
    /// the other is what maintained a second, competing cache rule: an
    /// invocation with `CARGO_HOME` unset reads a cache outside this lane.
    ///
    /// `CARGO_INCREMENTAL` is set only for the interactive mode: I2.22 keeps
    /// incremental compilation and cross-worktree reuse from being enabled
    /// together as a universal optimization.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError`] when the target root cannot be derived.
    pub fn cargo_environment(&self) -> Result<Vec<(String, String)>, WorkEnvelopeError> {
        let target_root = self.derive_target_root()?;
        let root = path_text(&target_root);
        let mut environment = vec![
            (CARGO_TARGET_DIR_ENV.to_owned(), root.clone()),
            (CARGO_HOME_ENV.to_owned(), root),
        ];
        if self.build_mode == BuildMode::InteractiveIncremental {
            environment.push(("CARGO_INCREMENTAL".to_owned(), "true".to_owned()));
        }
        Ok(environment)
    }
}

/// The one fixture-namespace derivation, shared by the pre-allocation
/// [`LaneIdentity`] and the allocated [`GovernedWorkEnvelope`].
///
/// It reads only tuple elements, so the claims a submitting owner declares from
/// the lane identity and the namespace the store later derives are the same
/// value by construction rather than by two derivations agreeing.
fn fixture_namespace_of(
    work_item_id: &str,
    build_mode: BuildMode,
    fingerprint: &BuildFingerprint,
) -> Result<String, WorkEnvelopeError> {
    Ok(format!(
        "fx-{work_item_id}-{}-{}",
        build_mode.as_str(),
        fingerprint.digest()?
    ))
}

/// The physical fixture directory one namespace resolves to.
///
/// The namespace is the last segment, so the physical root is a FUNCTION of
/// the one retained value rather than a second name that has to be kept in
/// step with it. Every physical use of the namespace — the exclusive resource
/// claim, the directory the Kernel creates, and the root each child is told —
/// goes through here.
fn fixture_root_of(local_app_data: &Path, namespace: &str) -> PathBuf {
    local_app_data
        .join("Eliot")
        .join(FIXTURE_ROOT_DIRECTORY)
        .join(namespace)
}

/// Rejects a pre-allocation lane whose elements or fingerprint are unusable.
///
/// This is the [`LaneIdentity`] half of the element and fingerprint checks
/// [`GovernedWorkEnvelope::validate`] performs, so the claims an owner declares
/// before the envelope exists are derived from a tuple that would have been
/// admitted anyway.
fn validate_lane_elements(
    work_item_id: &str,
    workspace_id: &str,
    worktree_id: &str,
    fingerprint: &BuildFingerprint,
) -> Result<(), WorkEnvelopeError> {
    for (value, field) in [
        (work_item_id, "work_item_id"),
        (workspace_id, "workspace_id"),
        (worktree_id, "worktree_id"),
    ] {
        segment(value, field)?;
    }
    fingerprint.validate()?;
    Ok(())
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)] // test-only panic-acceptable (#838).
    use super::*;

    /// A real canonical directory for the local application-data root.
    ///
    /// The envelope requires one (`UnresolvedLocalAppData`), so a test that
    /// derives a root has to hand it a directory that actually exists rather
    /// than an invented path.
    fn canonical_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("eliot-envelope-{label}"));
        std::fs::create_dir_all(&root).expect("local app data root must create");
        std::fs::canonicalize(&root).expect("local app data root must canonicalize")
    }

    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => unreachable!("{error:?}"),
        }
    }

    fn fingerprint_for(candidate: &str) -> BuildFingerprint {
        BuildFingerprint {
            workspace: "eliot".to_owned(),
            candidate: candidate.to_owned(),
            toolchain: "rustc 1.89.0 (x86_64-pc-windows-msvc)".to_owned(),
            target: "x86_64-pc-windows-msvc".to_owned(),
            profile: "dev".to_owned(),
            features: Vec::new(),
            environment_class: "non-inheriting-productive-testd".to_owned(),
            source_closure_digest: crate::sha256_of(b"source-closure"),
            manifest_digest: crate::sha256_of(b"manifest"),
            build_script_digest: None,
            proc_macro_digest: None,
            build_class: "debug".to_owned(),
            contract_revision: "rev-1".to_owned(),
        }
    }

    fn lane_for(work_item_id: &str, candidate: &str, root: &Path) -> LaneIdentity {
        LaneIdentity {
            work_item_id: work_item_id.to_owned(),
            workspace_id: "eliot".to_owned(),
            worktree_id: "main-worktree".to_owned(),
            fingerprint: fingerprint_for(candidate),
            build_mode: BuildMode::InteractiveIncremental,
            local_app_data: root.to_owned(),
        }
    }

    /// Issue #1897 (AUD8): two DIFFERENT namespaces must resolve to two
    /// DIFFERENT physical roots, and the namespace must reach the child
    /// environment. A namespace that is stored, hashed and equality-checked but
    /// never resolved is inert, and this is the proof that it is not: every
    /// distinct lane gets its own directory, its own exclusive resource claim,
    /// and both fixture bindings in the environment a governed child runs with.
    #[test]
    fn distinct_fixture_namespaces_resolve_to_distinct_physical_roots() {
        let local_app_data = canonical_root("distinct-namespaces");
        let lane = lane_for("wi-1897-a", "candidate-a", &local_app_data);
        let other = lane_for("wi-1897-b", "candidate-b", &local_app_data);

        // The two lanes differ in BOTH work item and build inputs, so their
        // namespaces differ for both reasons a fixture root may differ.
        let namespace = ok(lane.fixture_namespace());
        let other_namespace = ok(other.fixture_namespace());
        assert_ne!(namespace, other_namespace);

        // The physical root is a function of the retained namespace: it is the
        // last path segment, so the stored string and the directory cannot
        // drift, and two namespaces cannot share one directory.
        let root = ok(lane.fixture_root());
        let other_root = ok(other.fixture_root());
        assert_ne!(root, other_root);
        assert_eq!(
            root.file_name().and_then(|n| n.to_str()),
            Some(namespace.as_str())
        );
        assert_eq!(
            root.parent(),
            Some(
                local_app_data
                    .join("Eliot")
                    .join(FIXTURE_ROOT_DIRECTORY)
                    .as_path()
            )
        );

        // The claim a submitting owner declares is named by that same derived
        // root, so the allocator grants two distinct exclusive leases instead of
        // letting two jobs touch one fixture tree.
        let claim = ok(lane.fixture_resource_claims());
        assert_eq!(claim.len(), 1);
        assert_eq!(claim[0].kind, crate::ResourceKind::Fixture);
        assert_eq!(claim[0].name, path_text(&root));
        let other_claim = ok(other.fixture_resource_claims());
        assert_ne!(claim[0].name, other_claim[0].name);

        // Both bindings reach the child environment, and each names the lane
        // that allocated it.
        let environment = ok(lane.fixture_environment());
        assert_eq!(
            environment,
            vec![
                (FIXTURE_NAMESPACE_ENV.to_owned(), namespace.clone()),
                (FIXTURE_ROOT_ENV.to_owned(), path_text(&root)),
            ]
        );
        assert_eq!(
            ok(other.fixture_environment()),
            vec![
                (FIXTURE_NAMESPACE_ENV.to_owned(), other_namespace),
                (FIXTURE_ROOT_ENV.to_owned(), path_text(&other_root)),
            ]
        );

        std::fs::remove_dir_all(&local_app_data).expect("local app data root must clean");
    }

    /// The pre-allocation lane and the allocated envelope derive ONE namespace,
    /// ONE physical root, and ONE pair of child bindings. The claims an owner
    /// declares before the envelope exists and the namespace the store later
    /// derives must be the same value by construction, not two derivations that
    /// happen to agree; the declared claim is what the allocator grants a lease
    /// against, so a second derivation would be a second directory. The same
    /// applies to the environment: the lane states what a child of it will be
    /// given, and the envelope admitted from that lane states the same thing,
    /// so the owner's declaration and the admitted child cannot describe two
    /// different lanes.
    #[test]
    fn lane_and_envelope_derive_one_namespace_and_one_root() {
        let local_app_data = canonical_root("one-derivation");
        let lane = lane_for("wi-1897-shared", "candidate-shared", &local_app_data);
        let lane_namespace = ok(lane.fixture_namespace());
        let lane_root = ok(lane.fixture_root());
        let lane_environment = ok(lane.fixture_environment());
        let claims = ok(lane.fixture_resource_claims());
        let envelope = ok(GovernedWorkEnvelope::allocate(
            lane,
            claims.clone(),
            Vec::new(),
        ));
        assert_eq!(ok(envelope.fixture_namespace()), lane_namespace);
        assert_eq!(ok(envelope.fixture_root()), lane_root);
        assert_eq!(
            ok(envelope.fixture_environment()),
            vec![
                (FIXTURE_NAMESPACE_ENV.to_owned(), lane_namespace.clone()),
                (FIXTURE_ROOT_ENV.to_owned(), path_text(&lane_root)),
            ]
        );
        // The two child environments are byte-identical, not merely equal in
        // each value separately: the namespace and the root are emitted as one
        // pair, and a child that received one half of it would resolve a
        // different lane than the one the other half names.
        assert_eq!(lane_environment, ok(envelope.fixture_environment()));
        // The claim the owner declared before allocation is exactly the claim
        // the allocated envelope carries, so the grant that backs it names one
        // directory.
        assert_eq!(envelope.resource_claims, claims);
        std::fs::remove_dir_all(&local_app_data).expect("local app data root must clean");
    }
}
