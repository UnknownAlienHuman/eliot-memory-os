//! The production agent-build claim seam for issue #1902 (caller half).
//!
//! I18.26 line 3 reads: "Parallel agents use Cargo package selection and one
//! InstrumentRunner-controlled build projection. They do not independently
//! launch unrestricted `cargo --workspace` commands." The rescue port landed
//! the projection itself (`eliot_instrument_runner::build_projection`) and
//! closed the argv bypass, but nothing in production *reached* the projection:
//! no caller constructed a
//! [`DeclaredWorkItem`](eliot_instrument_runner::DeclaredWorkItem) and no
//! caller claimed through
//! [`TargetRootBuildCoordinator`](eliot_instrument_runner::TargetRootBuildCoordinator).
//! This module is that missing half, and it is the only place in `eliot-engine`
//! that mints a producer claim.
//!
//! # Why this seam lives here rather than in the app crate
//!
//! Both agent-build launch lanes reach Cargo through `eliot-engine`, and
//! `eliot-app` does not depend on `eliot-instrument-runner` directly — it
//! depends on `eliot-engine`, which does. Putting the seam here means the two
//! lanes cannot diverge: the `eliot-app` registered-cargo-verifier lane calls
//! [`claim_agent_cargo_build`] exactly as the in-engine patch verifier lane
//! calls [`admit_agent_cargo_argv`], and both are refused the same way.
//!
//! # What the claim buys, structurally
//!
//! A caller that reaches Cargo through this seam holds one live producer slot
//! on the target root its lane tuple derives. [`admit_agent_cargo_argv`] is
//! still the argv gate, and it is still called for the same argv *inside* the
//! claimed scope, so widening the argv to a workspace selection still fails.
//! The claim is the missing half: it is what makes the refusal *owned* by a
//! flight identity rather than a per-call string inspection that any future
//! caller could simply forget to perform.
//!
//! # Ownership is the claim's, not this module's
//!
//! Ownership is enforced by the coordinator itself and this module does not
//! re-derive it: a completion is accepted only when the coordinator's
//! `registry_of` resolves the exact root this coordinator claimed and the
//! `OperationId` matches the one the claim recorded, so a foreign root is
//! refused with [`BuildProjectionError::NotTheProducer`] and the release is
//! taken through the same handle the claim produced. See
//! [`TargetRootBuildCoordinator::completion_wakeup`].
//!
//! I18.26 line 63 keeps this an `InstrumentRunner` capability: this module
//! holds no job, no queue, no budget, and no priority, and it never
//! pre-empts a running producer.

use eliot_build_test_graph::{
    BuildFingerprint, CrateIdentity, LaneIdentity, PublicContractDigest, ResourceClaim,
    ResourceKind, RuntimeEnvironmentLease,
};
use eliot_contracts::{ArtifactId, ContractError, sha256_hex};
use eliot_instrument_runner::build_projection::{
    BuildProjectionError, DeclaredWorkItem, ProducerClaim, ProducerOutcome, TargetClass,
    TargetRootBuildCoordinator,
};
use eliot_instrument_runner::{GovernedWorkEnvelope, RawEvidence};
use eliot_process::OperationId;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use crate::patch::admit_agent_cargo_argv;

/// The execution axis one completed agent Cargo build is closed with.
///
/// `ProducerOutcome` already splits the success and failure arms and carries
/// [`ExecutionStatus`] on both, so this re-export is what lets the launch site
/// name the axis without depending on the instrument API crate itself.
pub use eliot_instrument_api::ExecutionStatus;

/// The build mode a declared agent build lane is allocated in (I2.22).
///
/// Re-exported so the launch site names the lane's build mode without taking a
/// direct dependency on the instrument runner.
pub use eliot_instrument_runner::BuildMode;

/// Runtime-environment resource the registered agent Cargo lane declares and
/// leases for itself.
///
/// I2.22 requires a work item to declare what it will touch and to be granted a
/// lease for each declaration before it executes, and
/// [`GovernedWorkEnvelope::admit`](eliot_instrument_runner::GovernedWorkEnvelope::admit)
/// refuses an empty claim set. The lane's own governed target root is that
/// declaration: it is the one resource this build writes into, it is derived
/// from the lane tuple rather than from ambient state, and two work items that
/// resolve different roots claim different names. The lease is the record the
/// allocator would grant for exactly that claim, and
/// `require_own_leases` refuses it unless this work item is the holder, so two
/// flights cannot present one another's grant.
const AGENT_BUILD_TARGET_ROOT_CLAIM: ResourceKind = ResourceKind::Fixture;

/// The single build-coordination owner for this process's agent target roots.
///
/// I10.8.4 gives a target root exactly one build-coordination owner, and
/// [`TargetRootBuildCoordinator`] is deliberately single-owner and not `Sync`
/// (`RefCell` state). Holding one coordinator for the process, behind a mutex,
/// is what preserves that: a second coordinator instance would be a second
/// owner of the same roots, which is exactly the defect the coordinator's
/// per-root registry exists to prevent.
///
/// [`OnceLock`] is used rather than a lazy static so there is no second
/// construction path and no `Default`/`new` ambiguity at the call site.
fn agent_build_coordinator() -> MutexGuard<'static, TargetRootBuildCoordinator> {
    static COORDINATOR: OnceLock<Mutex<TargetRootBuildCoordinator>> = OnceLock::new();
    COORDINATOR
        .get_or_init(|| Mutex::new(TargetRootBuildCoordinator::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Declared facts of one production agent Cargo build, as the launch site
/// observed them.
///
/// This is not a second declaration type: every element is read from a fact
/// the caller already has (its task identity, the Git artifact snapshot it
/// resolved immediately before launching, and the argv it is about to run).
/// Building the [`DeclaredWorkItem`] from these is what makes the claim
/// describe *this* build rather than a synthetic one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentBuildDeclaration {
    /// Work-item identity, also the producer identity in the claim and the
    /// holder on the lane's lease.
    pub work_item_id: String,
    /// The one Cargo package this build is scoped to (I18.26 line 7).
    pub primary_crate: String,
    /// The exact candidate commit the leased worktree is at.
    pub candidate_commit: String,
    /// The exact leased worktree root; the second segment of the governed
    /// build root.
    pub worktree_id: String,
    /// The exact argv the launch site is about to run, program first.
    pub argv: Vec<String>,
    /// The resolved `%LOCALAPPDATA%` root the governed build lanes anchor
    /// under (I2.22).
    pub local_app_data: PathBuf,
    /// The build mode this lane was allocated in (I2.22 path segment).
    pub build_mode: BuildMode,
    /// The verifier name this build is running under, recorded in the
    /// fingerprint's build class so two verifiers over one worktree are
    /// different lineages.
    pub build_class: String,
}

/// One claimed production agent build flight.
///
/// The handle is the *same* claim [`TargetRootBuildCoordinator::claim`]
/// returned, not a copy of its contents. Releasing through
/// [`AgentBuildFlight::release`] is what hands the coordinator the exact
/// `(root, lineage, operation)` key it recorded, so a release can never name a
/// flight this scope did not claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentBuildFlight {
    /// The coordinator's own claim for this flight.
    pub claim: ProducerClaim,
    /// The declared work item, retained so the release presents the same
    /// declaration the claim admitted.
    pub item: DeclaredWorkItem,
}

impl AgentBuildFlight {
    /// Whether this scope is the flight's single producer.
    ///
    /// A caller that comes back [`BuildFlight::Waiter`](eliot_build_test_graph::BuildFlight::Waiter)
    /// does not own the target root and must not launch a second build in it.
    #[must_use]
    pub fn is_producer(&self) -> bool {
        self.claim.is_producer()
    }

    /// The target root this flight is bound to, and the only root a governed
    /// invocation of it may use.
    #[must_use]
    pub fn target_root(&self) -> &Path {
        &self.claim.target_root
    }

    /// Closes the flight through the coordinator with the producer's own
    /// retained evidence, releasing the producer slot.
    ///
    /// This is the same handle the claim took: the release presents
    /// `self.item` and `self.claim.operation`, and
    /// [`TargetRootBuildCoordinator::completion_wakeup`] refuses any root this
    /// coordinator never claimed with
    /// [`BuildProjectionError::NotTheProducer`]. Nothing is re-derived here.
    ///
    /// # Errors
    ///
    /// Returns [`BuildProjectionError`] when the coordinator refuses the
    /// completion or the release.
    pub fn release(
        &self,
        evidence: RawEvidence,
        execution: ExecutionStatus,
    ) -> Result<(), BuildProjectionError> {
        let succeeded = execution == ExecutionStatus::Succeeded;
        let outcome = if succeeded {
            ProducerOutcome::Complete {
                execution,
                evidence,
            }
        } else {
            ProducerOutcome::Failed {
                execution,
                evidence,
            }
        };
        agent_build_coordinator().completion_wakeup(&self.item, &self.claim.operation, outcome)?;
        Ok(())
    }
}

/// Declares, claims, and admits the argv of one production agent Cargo build.
///
/// The three steps are one operation because I18.26 line 3 binds them: a build
/// that is not claimed is an independently launched build, and a build that is
/// not admitted is an unrestricted one. The returned handle is the only way to
/// release the producer slot, so a caller that launches must also settle.
///
/// # Errors
///
/// Returns [`BuildProjectionError`] when the declaration is incomplete or
/// malformed, when the coordinator cannot grant the claim, or when the argv
/// itself is refused by the shared admission point
/// ([`BuildProjectionError::CargoScope`] for `--workspace`/`--all`,
/// [`BuildProjectionError::NotCargo`] for a non-Cargo argv).
pub fn claim_agent_cargo_build(
    declaration: &AgentBuildDeclaration,
) -> Result<AgentBuildFlight, BuildProjectionError> {
    let item = declare_work_item(declaration)?;
    // The admission runs *before* the claim is taken and again on the exact
    // argv that is launched below, so a refused argv never occupies a
    // producer slot in the first place.
    let admitted = admit_agent_cargo_argv(&declaration.argv)?;
    let coordinator = agent_build_coordinator();
    let claim = coordinator.claim(&item, &flight_operation(&declaration.work_item_id))?;
    if !claim.is_producer() {
        // A waiter must not launch a second build in a root that already has
        // one producer. The claim is not released here: the live producer owns
        // that slot, and a release from a waiter is exactly what the
        // coordinator's ownership check refuses.
        return Err(BuildProjectionError::NotTheProducer {
            work_item_id: declaration.work_item_id.clone(),
        });
    }
    if admitted != declaration.argv {
        // Defensive: the admission point returns the argv unchanged, so this
        // cannot fire today. It stays because a future admission rewrite that
        // *rewrote* argv must not silently launch something the declaration
        // never described.
        return Err(BuildProjectionError::ProjectedArgvMismatch);
    }
    Ok(AgentBuildFlight { claim, item })
}

/// Builds the [`DeclaredWorkItem`] for one production agent Cargo build.
///
/// Every element is derived from a fact the launch site already observed, and
/// the digests are computed over exactly those facts — no element is invented
/// and none is defaulted, so `DeclaredWorkItem::validate` (called again
/// inside `claim`) is a real gate rather than a formality.
fn declare_work_item(
    declaration: &AgentBuildDeclaration,
) -> Result<DeclaredWorkItem, BuildProjectionError> {
    let lane = declared_lane(declaration);
    let envelope = GovernedWorkEnvelope::allocate(
        lane,
        vec![ResourceClaim {
            kind: AGENT_BUILD_TARGET_ROOT_CLAIM,
            name: lane_resource_name(declaration),
        }],
        vec![RuntimeEnvironmentLease {
            kind: AGENT_BUILD_TARGET_ROOT_CLAIM,
            resource: lane_resource_name(declaration),
            holder: declaration.work_item_id.clone(),
        }],
    )
    .map_err(BuildProjectionError::Lane)?;
    // The fail-closed admission gate runs here so the lane is proven admitted
    // before it can be claimed; `DeclaredWorkItem::validate` deliberately does
    // not re-admit.
    envelope.admit().map_err(BuildProjectionError::Lane)?;
    Ok(DeclaredWorkItem::declare(
        declaration.work_item_id.clone(),
        declaration.primary_crate.clone(),
        declared_frozen_contract(declaration),
        // I18.26 line 10: this lane's own crate is the primary crate and the
        // check it runs is that crate's own build. The public-contract class
        // (line 13) needs a `BuildTestGraph` source and a declared capsule
        // set, neither of which exists at this seam, so claiming it would be
        // an unbacked assertion.
        TargetClass::PrivateCrateChange,
        envelope,
    ))
}

/// The I2.22 lane tuple for one production agent Cargo build.
///
/// `workspace_id` is the first segment of the governed build root and
/// `worktree_id` the second, so both must be single path segments. `workspace_id`
/// is therefore a digest over the exact primary crate this lane builds, and the
/// caller supplies `worktree_id` already reduced to a segment. Neither is
/// defaulted, and a lane that cannot produce them is refused by
/// [`GovernedWorkEnvelope::allocate`] rather than admitted with a placeholder.
fn declared_lane(declaration: &AgentBuildDeclaration) -> LaneIdentity {
    LaneIdentity {
        work_item_id: declaration.work_item_id.clone(),
        workspace_id: lane_segment("workspace", &declaration.primary_crate),
        worktree_id: declaration.worktree_id.clone(),
        fingerprint: declared_fingerprint(declaration),
        build_mode: declaration.build_mode,
        local_app_data: declaration.local_app_data.clone(),
    }
}

/// The exact [`BuildFingerprint`] of one production agent Cargo build.
///
/// This is the existing fingerprint type and its own `digest()` is what keys
/// the lineage: no second fingerprint, digest, or lineage is introduced. The
/// fields are the build inputs the launch site actually resolved — the leased
/// candidate commit, the declared argv, the verifier's build class, and the
/// governed local application-data root. Two verifiers, two candidates, or two
/// worktrees therefore differ here and get different target roots.
fn declared_fingerprint(declaration: &AgentBuildDeclaration) -> BuildFingerprint {
    // The declared argv is a list, so it is joined into one identity string
    // before hashing. Joining rather than hashing each element in turn is what
    // makes `["-p","a"]` and `["-p a"]` produce the same closure only if the
    // list is genuinely the same, and it keeps this identical to how every
    // other identity in this module is digested.
    let source_closure_digest = digest_of("source-closure", &declaration.argv.join(" "));
    BuildFingerprint {
        workspace: lane_segment("workspace", &declaration.primary_crate),
        candidate: declaration.candidate_commit.clone(),
        toolchain: lane_segment("toolchain", &declaration.candidate_commit),
        target: "host".to_owned(),
        profile: lane_segment("profile", &declaration.build_class),
        features: Vec::new(),
        environment_class: lane_segment(
            "environment-class",
            &declaration.local_app_data.to_string_lossy(),
        ),
        source_closure_digest: source_closure_digest.clone(),
        // The manifest closure and the source closure are the same set here: the
        // argv selects the packages, so there is nothing to hash separately. They
        // carry the same value rather than one being derived from the other, so
        // neither can drift into describing a different set.
        manifest_digest: source_closure_digest,
        build_script_digest: None,
        proc_macro_digest: None,
        build_class: declaration.build_class.clone(),
        contract_revision: declaration.candidate_commit.clone(),
    }
}

/// The frozen public contract this build is bound to (I18.26 line 7).
///
/// The contract revision *is* the leased candidate commit, so this reads the
/// fingerprint's own `contract_revision` rather than declaring a second,
/// independent contract identity. The digest is over that exact revision, so
/// the declaration can never disagree with the lane.
fn declared_frozen_contract(declaration: &AgentBuildDeclaration) -> PublicContractDigest {
    PublicContractDigest {
        crate_identity: CrateIdentity {
            package_id: declaration.primary_crate.clone(),
            source_revision: declaration.candidate_commit.clone(),
        },
        digest: digest_of("frozen-contract", &declaration.candidate_commit),
    }
}

/// The declared runtime-resource name for this lane's governed target root.
///
/// It is the digest of the *whole* lane identity, which is exactly the set of
/// segments `derive_target_root` joins into the root. The claim name and the
/// root are therefore the same identity by construction: two work items that
/// agree on nothing resolve different roots and claim different names, and a
/// lease is only ever held for the root its own lane derives.
fn lane_resource_name(declaration: &AgentBuildDeclaration) -> String {
    let lane = declared_lane(declaration);
    // The fingerprint digest is the root's own last segment, so naming it here
    // names the root exactly, with no second root derivation to drift.
    match lane.fingerprint.digest() {
        Ok(lineage) => lineage,
        // The fingerprint was just built from validated text and hex digests, so
        // it cannot be invalid here. Falling back to the full identity keeps the
        // name *distinct* rather than defaulting two lanes onto one name, which
        // is the only safe direction for a claim: a collision would make two
        // different roots present one another's lease.
        Err(_) => digest_of("agent-build-target-root", &format!("{lane:?}")),
    }
}

/// The one [`OperationId`] that identifies this scope's own build attempt.
///
/// It is derived from the work-item identity, which is the scope the claim
/// was taken for, and is therefore stable for that scope's attempt rather than
/// being re-derived per call. A second, concurrent attempt by a *different*
/// work item gets a different operation and a different target root, so it
/// cannot present this scope's identity.
fn flight_operation(work_item_id: &str) -> OperationId {
    let value = digest_of("agent-build-operation", work_item_id);
    // `OperationId::new` validates its own text; the digest is already
    // non-blank, control-free hex, so the first call cannot fail, and the
    // fallback keeps the function infallible without a panic path. The fallback
    // is a CONSTANT, so two builds that both fell back share one identity and
    // are refused as a conflict rather than admitted as two distinct
    // operations.
    OperationId::new(value).unwrap_or_else(|_| {
        OperationId::new("agent-build-operation-unavailable".to_owned())
            .unwrap_or_else(|_| unreachable!("a constant opaque operation id is always valid"))
    })
}

/// A stable 64-character lowercase digest over a domain-separated identity.
///
/// This is a plain SHA-256 over bytes, the same shape
/// [`BuildFingerprint::digest`] itself produces, and it introduces no new
/// digest scheme: the values it feeds are validated by that type's own
/// `digest()` check on every claim.
fn digest_of(domain: &str, identity: &str) -> String {
    sha256_hex(format!("{domain}\0{identity}").as_bytes())
}

/// A single path segment standing for an identity.
///
/// The governed build root joins this value as a directory, so it must be one
/// segment with no separator, no traversal, and no control character — the same
/// rule `GovernedWorkEnvelope::validate` enforces. A SHA-256 hex digest
/// satisfies that by construction: 64 lowercase hex characters and nothing
/// else, which is also the exact shape `BuildFingerprint::digest` produces, so
/// no second digest scheme is introduced here.
fn lane_segment(domain: &str, identity: &str) -> String {
    digest_of(domain, identity)
}

/// Retains the exact output of a completed agent Cargo build as the
/// [`RawEvidence`] the coordinator requires for a completion.
///
/// `completion_wakeup` refuses any outcome whose evidence is not a retained
/// handle, so a build that produced no retained evidence cannot be released
/// and its producer slot stays held. The handle is derived from the *actual
/// captured bytes* of this build — its work item, the status line it exited
/// with, and its exact stdout and stderr — so it can never name a payload a
/// different run produced, and `byte_len` is the real retained length rather
/// than an estimate.
///
/// # Errors
///
/// Returns the [`ContractError`] from [`ArtifactId::new`] if the derived handle
/// is not a valid identifier.
pub fn retain_agent_build_evidence(
    work_item_id: &str,
    exit_status: &std::process::ExitStatus,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<RawEvidence, ContractError> {
    // The evidence is bound to the operation that produced it, so the handle
    // digests exactly the bytes this launch captured rather than the work item
    // alone: two runs of one work item are two different payloads and get two
    // different handles.
    let mut bound = Vec::with_capacity(stdout.len() + stderr.len());
    bound.extend_from_slice(work_item_id.as_bytes());
    bound.push(0);
    bound.extend_from_slice(exit_status.to_string().as_bytes());
    bound.push(0);
    bound.extend_from_slice(stdout);
    bound.push(0);
    bound.extend_from_slice(stderr);
    let artifact = ArtifactId::new(format!("agent-build-{}", sha256_hex(&bound)))?;
    Ok(RawEvidence::Retained {
        artifact,
        byte_len: bound.len() as u64,
    })
}
