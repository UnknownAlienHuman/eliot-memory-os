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
//!   ([`GovernedWorkEnvelope::fixture_namespace`]), together with the physical
//!   fixture root derived from that one namespace and carried into the governed
//!   child environment ([`GovernedWorkEnvelope::derive_fixture_root`],
//!   [`GovernedWorkEnvelope::fixture_environment`]);
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
//! the candidate that produced it. The identity is attached on the ACTUAL
//! publication paths — every `RawArtifact` and the `VerificationReceipt` the
//! test daemon emits, and the receipt's own validation compares the content
//! against the retained envelope rather than accepting presence — and both read
//! it from the one envelope, so they can never disagree.
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
/// governed fixture namespace. I2.22 gives each mutating work item its own
/// fixture namespace, and a namespace only isolates anything once a physical
/// root is derived from it.
pub const FIXTURE_ROOT_DIRECTORY: &str = "fixtures";

/// Environment variable carrying the physical fixture root of one work item.
///
/// This is what makes the namespace an input to the fixture owner instead of a
/// stored label: the child that reads it creates and destroys state under a
/// directory no other work item can name, so two jobs cannot record different
/// namespace strings while touching one fixture.
pub const FIXTURE_ROOT_ENV: &str = "ELIOT_FIXTURE_ROOT";

/// Environment variable carrying the retained fixture namespace itself, beside
/// its physical root, so the child can name the namespace it was admitted in
/// without re-deriving it from ambient state.
pub const FIXTURE_NAMESPACE_ENV: &str = "ELIOT_FIXTURE_NAMESPACE";

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
    /// Non-incremental, fingerprint-exact lane root within one admitted
    /// checkout segment.
    ///
    /// I2.22 names this mode "shared non-incremental + sccache: reuse across
    /// agents and worktrees under an exact normalized fingerprint". What the
    /// implementation actually delivers is the part of that sentence a target
    /// root can carry, and the rest is spelled out here so no caller reads more
    /// into the mode than it holds:
    ///
    /// * NON-INCREMENTAL — held. `cargo_environment` sets `CARGO_INCREMENTAL`
    ///   only for [`BuildMode::InteractiveIncremental`], so an invocation in
    ///   this mode never reuses incremental state.
    /// * UNDER AN EXACT NORMALIZED FINGERPRINT — held. The governed target root
    ///   `%LOCALAPPDATA%\Eliot\build\<workspace-id>\<worktree-id>\<build-mode>\
    ///   \<fingerprint>` ends in the fingerprint digest, so anything reused from
    ///   it is bound to the exact build inputs.
    /// * SHARED — held only WITHIN one admitted checkout segment. I2.22's own
    ///   target-root shape carries `<worktree-id>`, so two admitted checkout
    ///   segments never receive one shared target root, and this variant must
    ///   not be read as cross-worktree target reuse.
    /// * Sccache — NOT held. This crate configures no compiler cache daemon and
    ///   owns no separate exact-fingerprint shared cache root. `CARGO_HOME` is
    ///   bound to the same lane root as `CARGO_TARGET_DIR`, which is the TestD
    ///   `TargetRoots` policy (`cache_root == target_root`) and is not a shared
    ///   cache, so no caller may read this variant as evidence that
    ///   cross-checkout reuse exists.
    ///
    /// The mode therefore labels safe, exact, non-incremental lane isolation
    /// that is never the repository `target/` directory. The cross-checkout
    /// reuse I2.22 describes is a separate exact-fingerprint cache owner, and
    /// until one exists it is not delivered by this variant.
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
    /// The fixture namespace this lane identity will own once allocated.
    ///
    /// The caller that admits a work item must name the namespace BEFORE the
    /// envelope exists, because the exclusive fixture claim it declares is
    /// named from it and the envelope is allocated from that claim set. This is
    /// the same one derivation
    /// [`GovernedWorkEnvelope::fixture_namespace`] reads, so the claim a job
    /// declares and the namespace its envelope records cannot differ.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError`] when the work-item identity or the
    /// fingerprint is invalid.
    pub fn fixture_namespace(&self) -> Result<String, WorkEnvelopeError> {
        segment(&self.work_item_id, "work_item_id")?;
        self.fingerprint.validate()?;
        fixture_namespace_of(&self.work_item_id, self.build_mode, &self.fingerprint)
    }

    /// The exclusive fixture claim this lane identity must declare.
    ///
    /// A mutating test work item touches fixture state, and fixture state is a
    /// stateful runtime resource: it receives its own lease, allocated
    /// independently of the worktree by the live
    /// `eliot_testd_core::ResourceLeaseAllocator`. The claim name IS the
    /// physical fixture root's final segment, so the leased resource and the
    /// directory the child is handed are the same thing.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError`] when the namespace cannot be derived.
    pub fn fixture_claim(&self) -> Result<ResourceClaim, WorkEnvelopeError> {
        Ok(ResourceClaim {
            kind: crate::ResourceKind::Fixture,
            name: self.fixture_namespace()?,
        })
    }
}

/// The one fixture-namespace derivation both the lane identity and the
/// allocated envelope read.
///
/// Work item, build mode, and normalized fingerprint: never the worktree, the
/// project id, or a counter. Two work items in different worktrees therefore
/// never share a namespace, and the caller that declares the exclusive claim
/// and the envelope that records it read the same function.
fn fixture_namespace_of(
    work_item_id: &str,
    build_mode: BuildMode,
    fingerprint: &BuildFingerprint,
) -> Result<String, WorkEnvelopeError> {
    Ok(format!(
        "fx-{}-{}-{}",
        work_item_id,
        build_mode.as_str(),
        fingerprint.digest()?
    ))
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
        fixture_namespace_of(
            &self.work_item_id,
            self.build_mode,
            &self.fingerprint,
        )
    }

    /// The physical directory this work item's fixture state lives under.
    ///
    /// Exactly
    /// `%LOCALAPPDATA%\Eliot\fixtures\<fixture namespace>`. Deriving the
    /// directory from the namespace is what makes the namespace real
    /// isolation rather than a stored label: two work items whose namespace
    /// strings differ cannot name the same directory, because the final path
    /// segment IS the namespace and the whole path hangs off the one admitted
    /// application-data root. A namespace recorded but never rooted would let
    /// two jobs store different strings while touching one fixture.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError`] when the fingerprint or a tuple element is
    /// invalid.
    pub fn derive_fixture_root(&self) -> Result<PathBuf, WorkEnvelopeError> {
        Ok(self
            .local_app_data
            .join("Eliot")
            .join(FIXTURE_ROOT_DIRECTORY)
            .join(self.fixture_namespace()?))
    }

    /// The exact fixture environment a governed child of this work item runs
    /// with.
    ///
    /// Both keys are emitted together from the one retained namespace:
    /// [`FIXTURE_ROOT_ENV`] carries the physical root the fixture owner must
    /// create and use, and [`FIXTURE_NAMESPACE_ENV`] carries the namespace that
    /// produced it. Emitting one without the other is what leaves a namespace
    /// inert — a child that can read the namespace but not the root keeps
    /// choosing its own directory — so the pair is produced by a single
    /// derivation and both sides are bound to the same retained value.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError`] when the fixture root cannot be derived.
    pub fn fixture_environment(&self) -> Result<Vec<(String, String)>, WorkEnvelopeError> {
        Ok(vec![
            (
                FIXTURE_ROOT_ENV.to_owned(),
                path_text(&self.derive_fixture_root()?),
            ),
            (
                FIXTURE_NAMESPACE_ENV.to_owned(),
                self.fixture_namespace()?,
            ),
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
    /// This is the fail-closed admission gate. It requires a non-empty claim
    /// set, every claim covered by a held lease, every held lease backed by a
    /// claim, and every held lease granted to this work item, so a worktree
    /// alone cannot obtain a shared runtime resource: the tuple is the only
    /// route to one, and the tuple carries who the grant was made for.
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
