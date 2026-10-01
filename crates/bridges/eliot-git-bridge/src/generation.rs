//! Staged generation update sequence for the Git bridge (issue #1797, W6).
//!
//! I10.14 staged update, contracted to this bridge's mechanics: a new
//! upstream (`git` executable) generation is staged as a separate immutable
//! value carrying its own declaration snapshot; the live generation is never
//! mutated in place and the previous generation is retained for recovery.
//! Route exposure requires an explicit compatibility check (same route
//! executable, same admitted operation set) before the switch. Shadow
//! traffic is limited to operations proven read-only, and only under an
//! owner-admitted data/privacy/budget envelope held outside this crate. A
//! switch additionally requires a caller-attested canary verdict from the
//! existing WorkScope/Governor owners, old in-flight work drains by exact
//! invocation identity, and rollback is another authorized forward cutover
//! to the retained generation, never restoration of old state or undo of
//! effects already performed. Incompatible durable-state changes are
//! refused here and belong to the established migration/recovery decision.
//!
//! Upstream package itself is never touched: staging records the
//! caller-observed upstream version string together with the caller-attested
//! upstream artifact digest, it does not install anything. Every staged value
//! is stamped with the bridge declaration revision, so a declaration-schema
//! change is a new admission rather than a silent update.
//!
//! Wiring: the crate root declares `mod generation;` and re-exports this
//! sequence. `GitBridge::stage_generation` and `GitBridge::load_admitted` feed
//! staged values built from `git_application_obligations().supported_operations`,
//! the dispatch path (`exec/exec_stdin`) records dispatched invocation identities in the
//! ledger, and the composition owner holding the `AdmittedLine` supplies the
//! canary verdict and performs the switch. The pre-exposure compatibility
//! check refuses route, declaration-revision, and operation-set drift, and
//! `AdmittedLine::check_bound` gates caller-presented declarations against
//! the live generation before status is projected.

use std::fmt;

use super::{GIT_DECLARATION_REVISION, is_artifact_digest};

/// Typed failures of the generation update sequence.
///
/// Every refusal happens before route exposure: no authority, no operation
/// identity, and no task decision is created on these paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GenerationError {
    /// A staging input was blank or the admitted operation set was empty.
    BlankField {
        /// Which staging input was blank.
        field: &'static str,
    },
    /// A caller-attested upstream artifact digest was not 64 hexadecimal
    /// characters. An unattested or malformed artifact binding is refused
    /// before anything is staged.
    ArtifactDigestShape {
        /// Stable detail naming the rejected input.
        detail: String,
    },
    /// The presented declaration names a different upstream artifact
    /// (version or digest) than the live generation. Artifacts are never
    /// substituted silently under the same declaration.
    ArtifactMismatch {
        /// Artifact identity named by the presented declaration.
        presented: String,
        /// Artifact identity recorded on the live generation.
        live: String,
    },
    /// The staged route executable differs from the admitted one. No
    /// provider is ever substituted under the same operation.
    RouteMismatch {
        /// Route executable recorded on the staged generation.
        staged: String,
        /// Route executable recorded on the admitted generation.
        admitted: String,
    },
    /// The staged admitted-operation set differs from the live one. A
    /// changed contract is a new admission, not an update.
    OperationsMismatch {
        /// Stable detail (operation counts on both sides).
        detail: String,
    },
    /// The canary verdict was not an acceptance. The switch does not run.
    CanaryNotAccepted {
        /// Owner-attested canary detail.
        detail: String,
    },
    /// No retained generation exists, so there is nothing to roll back to.
    /// A missing retained version is never reported as a successful
    /// rollback.
    NoRetainedGeneration,
    /// Old in-flight work is still open; the draining step is not complete.
    InFlightRemain {
        /// Open invocation identities still being drained.
        count: usize,
    },
    /// An identity was settled that was never dispatched under it. Draining
    /// tracks exact identities; unknown ones are refused, never absorbed.
    UnknownIdentity {
        /// Observed identity with no matching dispatch record.
        identity: String,
    },
}

impl fmt::Display for GenerationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlankField { field } => {
                write!(f, "staged generation field must not be blank: {field}")
            }
            Self::ArtifactDigestShape { detail } => {
                write!(
                    f,
                    "upstream artifact digest has an unexpected shape: {detail}"
                )
            }
            Self::ArtifactMismatch { presented, live } => write!(
                f,
                "presented artifact '{presented}' does not match live artifact '{live}'"
            ),
            Self::RouteMismatch { staged, admitted } => write!(
                f,
                "staged route '{staged}' does not match admitted route '{admitted}'"
            ),
            Self::OperationsMismatch { detail } => {
                write!(f, "staged declaration is not update-compatible: {detail}")
            }
            Self::CanaryNotAccepted { detail } => {
                write!(
                    f,
                    "canary verdict did not accept the staged generation: {detail}"
                )
            }
            Self::NoRetainedGeneration => {
                write!(f, "no retained generation is available for recovery")
            }
            Self::InFlightRemain { count } => {
                write!(f, "old in-flight work is still draining: {count} open")
            }
            Self::UnknownIdentity { identity } => write!(
                f,
                "settled identity was never dispatched under this generation: {identity}"
            ),
        }
    }
}

impl std::error::Error for GenerationError {}

/// One admitted upstream generation: route, observed upstream version,
/// caller-attested upstream artifact digest, declaration revision, and
/// the exact admitted operation set snapshotted from the bridge declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveGeneration {
    route_executable: String,
    upstream_version: String,
    upstream_artifact_digest: String,
    declaration_revision: u64,
    admitted_operations: Vec<String>,
}

impl ActiveGeneration {
    /// Returns the admitted route executable.
    #[must_use]
    pub fn route_executable(&self) -> &str {
        &self.route_executable
    }

    /// Returns the caller-observed upstream version recorded at staging.
    #[must_use]
    pub fn upstream_version(&self) -> &str {
        &self.upstream_version
    }

    /// Returns the caller-attested upstream artifact digest bound at staging.
    #[must_use]
    pub fn upstream_artifact_digest(&self) -> &str {
        &self.upstream_artifact_digest
    }

    /// Returns the bridge declaration revision this generation was staged under.
    #[must_use]
    pub fn declaration_revision(&self) -> u64 {
        self.declaration_revision
    }

    /// Returns the admitted operation snapshot bound to this generation.
    #[must_use]
    pub fn admitted_operations(&self) -> &[String] {
        &self.admitted_operations
    }
}

/// A staged upstream generation awaiting the compatibility check.
///
/// Immutable once staged: there is no method that mutates a staged value.
/// A staged generation becomes live only through [`AdmittedLine`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedGeneration {
    route_executable: String,
    upstream_version: String,
    upstream_artifact_digest: String,
    declaration_revision: u64,
    admitted_operations: Vec<String>,
}

impl StagedGeneration {
    /// Stages a new upstream generation separately from the live one.
    ///
    /// `admitted_operations` is the exact snapshot from the bridge
    /// declaration (the stitch caller passes
    /// `git_application_obligations().supported_operations`), so the
    /// declaration and the generation cannot drift apart. The upstream
    /// version is the caller-observed version string and
    /// `upstream_artifact_digest` is the caller-attested digest of the bound
    /// upstream artifact (64 hexadecimal characters): both are recorded,
    /// never installed or probed through dispatch. The staged value is
    /// stamped with the current bridge declaration revision.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationError::BlankField`] when any input is blank or
    /// the operation set is empty, or
    /// [`GenerationError::ArtifactDigestShape`] when the artifact digest is
    /// malformed.
    pub fn stage(
        route_executable: impl Into<String>,
        upstream_version: impl Into<String>,
        upstream_artifact_digest: impl Into<String>,
        admitted_operations: &[&str],
    ) -> Result<Self, GenerationError> {
        let route_executable = route_executable.into();
        let upstream_version = upstream_version.into();
        let upstream_artifact_digest = upstream_artifact_digest.into();
        if route_executable.trim().is_empty() {
            return Err(GenerationError::BlankField {
                field: "route_executable",
            });
        }
        if upstream_version.trim().is_empty() {
            return Err(GenerationError::BlankField {
                field: "upstream_version",
            });
        }
        if upstream_artifact_digest.trim().is_empty() {
            return Err(GenerationError::BlankField {
                field: "upstream_artifact_digest",
            });
        }
        if !is_artifact_digest(&upstream_artifact_digest) {
            return Err(GenerationError::ArtifactDigestShape {
                detail: "upstream_artifact_digest must be 64 hexadecimal characters".to_owned(),
            });
        }
        if admitted_operations.is_empty() {
            return Err(GenerationError::BlankField {
                field: "admitted_operations",
            });
        }
        Ok(Self {
            route_executable,
            upstream_version,
            upstream_artifact_digest,
            declaration_revision: GIT_DECLARATION_REVISION,
            admitted_operations: admitted_operations
                .iter()
                .map(|operation| (*operation).to_owned())
                .collect(),
        })
    }

    /// Returns the staged route executable.
    #[must_use]
    pub fn route_executable(&self) -> &str {
        &self.route_executable
    }

    /// Returns the staged upstream version.
    #[must_use]
    pub fn upstream_version(&self) -> &str {
        &self.upstream_version
    }

    /// Returns the staged upstream artifact digest.
    #[must_use]
    pub fn upstream_artifact_digest(&self) -> &str {
        &self.upstream_artifact_digest
    }

    /// Returns the bridge declaration revision stamped at staging.
    #[must_use]
    pub fn declaration_revision(&self) -> u64 {
        self.declaration_revision
    }

    /// Returns the staged admitted operation snapshot.
    #[must_use]
    pub fn admitted_operations(&self) -> &[String] {
        &self.admitted_operations
    }
}

/// Owner-attested canary verdict over the staged generation.
///
/// The canary itself runs under the existing WorkScope/Governor owners on
/// the explicitly bounded scope; this value only carries their verdict
/// across the switch boundary. There is no path that switches without one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanaryVerdict {
    accepted: bool,
    detail: String,
}

impl CanaryVerdict {
    /// Records an accepting canary verdict with the owner-observed detail.
    #[must_use]
    pub fn accepted(detail: impl Into<String>) -> Self {
        Self {
            accepted: true,
            detail: detail.into(),
        }
    }

    /// Records a rejecting canary verdict with the owner-observed detail.
    #[must_use]
    pub fn rejected(detail: impl Into<String>) -> Self {
        Self {
            accepted: false,
            detail: detail.into(),
        }
    }

    /// Reports whether the canary accepted the staged generation.
    #[must_use]
    pub fn is_accepted(&self) -> bool {
        self.accepted
    }

    /// Returns the owner-observed canary detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// Exact-identity ledger of dispatched but unsettled invocations.
///
/// The dispatch path notes every dispatched invocation identity and
/// settles it when the terminal outcome is reconciled. Noting
/// is idempotent: retries repeat the same invocation identity, so a second
/// note for an already open identity changes nothing. Settling an identity
/// that was never dispatched is refused.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InFlightLedger {
    entries: Vec<String>,
}

impl InFlightLedger {
    /// Creates an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Notes one dispatched invocation identity (idempotent on repeats).
    pub fn note_dispatched(&mut self, identity: impl Into<String>) {
        let identity = identity.into();
        if !self.entries.contains(&identity) {
            self.entries.push(identity);
        }
    }

    /// Settles one invocation identity after its outcome reconciled.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationError::UnknownIdentity`] when the identity was
    /// never dispatched under this ledger.
    pub fn note_settled(&mut self, identity: &str) -> Result<(), GenerationError> {
        let Some(position) = self.entries.iter().position(|entry| entry == identity) else {
            return Err(GenerationError::UnknownIdentity {
                identity: identity.to_owned(),
            });
        };
        self.entries.remove(position);
        Ok(())
    }

    /// Reports whether no invocation identity remains open.
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.entries.is_empty()
    }

    /// Counts the still-open invocation identities.
    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.entries.len()
    }
}

/// The admitted generation line: exactly one live generation plus the
/// retained previous generation kept available for recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedLine {
    current: ActiveGeneration,
    retained: Option<ActiveGeneration>,
}

impl AdmittedLine {
    /// Admits the first generation. Initial admission carries no canary:
    /// there is no previous generation to compare against yet.
    #[must_use]
    pub fn admit_initial(staged: StagedGeneration) -> Self {
        Self {
            current: ActiveGeneration {
                route_executable: staged.route_executable,
                upstream_version: staged.upstream_version,
                upstream_artifact_digest: staged.upstream_artifact_digest,
                declaration_revision: staged.declaration_revision,
                admitted_operations: staged.admitted_operations,
            },
            retained: None,
        }
    }

    /// Returns the live generation.
    #[must_use]
    pub fn current(&self) -> &ActiveGeneration {
        &self.current
    }

    /// Returns the retained previous generation, when one is kept.
    #[must_use]
    pub fn retained(&self) -> Option<&ActiveGeneration> {
        self.retained.as_ref()
    }

    /// Validates contract/protocol compatibility before route exposure.
    ///
    /// The route executable, the bridge declaration revision, and the
    /// admitted operation set must match exactly. The upstream version and
    /// artifact digest are intentionally not compared: they are the update
    /// payload, while compatibility is about contract and protocol identity.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationError::RouteMismatch`] or
    /// [`GenerationError::OperationsMismatch`] before anything is exposed.
    pub fn compatible_with_current(
        &self,
        staged: &StagedGeneration,
    ) -> Result<(), GenerationError> {
        if staged.route_executable != self.current.route_executable {
            return Err(GenerationError::RouteMismatch {
                staged: staged.route_executable.clone(),
                admitted: self.current.route_executable.clone(),
            });
        }
        if staged.declaration_revision != self.current.declaration_revision {
            return Err(GenerationError::OperationsMismatch {
                detail: format!(
                    "staged declaration revision {} does not match live revision {}",
                    staged.declaration_revision, self.current.declaration_revision
                ),
            });
        }
        if staged.admitted_operations != self.current.admitted_operations {
            return Err(GenerationError::OperationsMismatch {
                detail: format!(
                    "staged declaration admits {} operations, live generation admits {}",
                    staged.admitted_operations.len(),
                    self.current.admitted_operations.len()
                ),
            });
        }
        Ok(())
    }

    /// Performs the authenticated route switch to the staged generation.
    ///
    /// Requires the pre-exposure compatibility check and an accepting
    /// canary verdict. The previous live generation becomes the retained
    /// one; old in-flight work drains afterwards by exact identity in the
    /// caller-held [`InFlightLedger`]. A failed or unknown switch is
    /// reconciled under its original identity, never repeated under a new
    /// one; that reconciliation stays with the dispatch/receipt owners.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationError::RouteMismatch`],
    /// [`GenerationError::OperationsMismatch`], or
    /// [`GenerationError::CanaryNotAccepted`] without changing the line.
    pub fn switch(
        &mut self,
        staged: StagedGeneration,
        canary: &CanaryVerdict,
    ) -> Result<(), GenerationError> {
        self.compatible_with_current(&staged)?;
        if !canary.is_accepted() {
            return Err(GenerationError::CanaryNotAccepted {
                detail: canary.detail().to_owned(),
            });
        }
        let previous = std::mem::replace(
            &mut self.current,
            ActiveGeneration {
                route_executable: staged.route_executable,
                upstream_version: staged.upstream_version,
                upstream_artifact_digest: staged.upstream_artifact_digest,
                declaration_revision: staged.declaration_revision,
                admitted_operations: staged.admitted_operations,
            },
        );
        self.retained = Some(previous);
        Ok(())
    }

    /// Rolls back on a qualifying regression as another authorized forward
    /// cutover to the still-compatible retained generation.
    ///
    /// This restores neither old leases/epochs nor effects already
    /// performed; it only re-points the live generation at the retained
    /// artifact after re-checking compatibility.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationError::NoRetainedGeneration`] when nothing is
    /// retained (never reported as a successful rollback), or the
    /// compatibility/canary refusals of [`AdmittedLine::switch`].
    pub fn rollback_to_retained(&mut self, canary: &CanaryVerdict) -> Result<(), GenerationError> {
        let Some(retained) = self.retained.clone() else {
            return Err(GenerationError::NoRetainedGeneration);
        };
        if retained.route_executable != self.current.route_executable
            || retained.declaration_revision != self.current.declaration_revision
            || retained.admitted_operations != self.current.admitted_operations
        {
            return Err(GenerationError::OperationsMismatch {
                detail: "retained generation is no longer compatible with the live line".to_owned(),
            });
        }
        if !canary.is_accepted() {
            return Err(GenerationError::CanaryNotAccepted {
                detail: canary.detail().to_owned(),
            });
        }
        let regressed = std::mem::replace(&mut self.current, retained);
        self.retained = Some(regressed);
        Ok(())
    }

    /// Gates a caller-presented declaration against the live generation.
    ///
    /// The revision, route, upstream version, upstream artifact digest, and
    /// admitted-operation snapshot must all match the live generation
    /// exactly. A declaration for another artifact, another revision, or
    /// another operation set binds nothing here: the gate refuses before any
    /// route is exposed, creating no authority, no operation identity, and
    /// no task decision.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationError::RouteMismatch`],
    /// [`GenerationError::OperationsMismatch`], or
    /// [`GenerationError::ArtifactMismatch`] without changing the line.
    pub fn check_bound(
        &self,
        revision: u64,
        route_executable: &str,
        upstream_version: &str,
        upstream_artifact_digest: &str,
        admitted_operations: &[String],
    ) -> Result<(), GenerationError> {
        if route_executable != self.current.route_executable {
            return Err(GenerationError::RouteMismatch {
                staged: route_executable.to_owned(),
                admitted: self.current.route_executable.clone(),
            });
        }
        if revision != self.current.declaration_revision {
            return Err(GenerationError::OperationsMismatch {
                detail: format!(
                    "presented declaration revision {revision} does not match live revision {}",
                    self.current.declaration_revision
                ),
            });
        }
        if admitted_operations != self.current.admitted_operations.as_slice() {
            return Err(GenerationError::OperationsMismatch {
                detail: format!(
                    "presented declaration admits {} operations, live generation admits {}",
                    admitted_operations.len(),
                    self.current.admitted_operations.len()
                ),
            });
        }
        if upstream_version != self.current.upstream_version {
            return Err(GenerationError::ArtifactMismatch {
                presented: upstream_version.to_owned(),
                live: self.current.upstream_version.clone(),
            });
        }
        if upstream_artifact_digest != self.current.upstream_artifact_digest {
            return Err(GenerationError::ArtifactMismatch {
                presented: upstream_artifact_digest.to_owned(),
                live: self.current.upstream_artifact_digest.clone(),
            });
        }
        Ok(())
    }

    /// Confirms old in-flight work drained after the switch.
    ///
    /// The switch itself does not wait: draining happens afterwards by
    /// exact identity in the caller-held ledger, and this check names the
    /// completion of that step as a typed gate the dispatch owner invokes
    /// before treating the old generation as fully retired.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationError::InFlightRemain`] while identities stay
    /// open.
    pub fn require_drained(ledger: &InFlightLedger) -> Result<(), GenerationError> {
        if ledger.is_drained() {
            Ok(())
        } else {
            Err(GenerationError::InFlightRemain {
                count: ledger.in_flight_count(),
            })
        }
    }
}

/// First-argv tokens that mutate repository state through this bridge.
///
/// The mutating argv set is exactly the operations whose dispatch maps
/// failure to the uncertain-effect outcome (`worktree add`/`remove` and
/// `apply`); every other admitted operation is a read-only probe. Shadow
/// traffic duplicates no mutation.
const GIT_MUTATING_TOKENS: &[&str] = &["worktree", "apply"];

/// Reports whether `operation` may run as shadow traffic against a
/// generation that is not yet (or no longer) live.
///
/// Shadow requires all three: the operation is admitted on the generation
/// under test, the operation is proven read-only (never in
/// `GIT_MUTATING_TOKENS`), and the caller holds an admitted
/// data/privacy/budget envelope for the shadow run. The envelope itself
/// stays with its Governor/WorkScope owners; this predicate only consumes
/// their attestation and never duplicates mutations in shadow traffic.
#[must_use]
pub fn shadow_admits(
    admitted_operations: &[String],
    operation: &str,
    envelope_admitted: bool,
) -> bool {
    envelope_admitted
        && admitted_operations
            .iter()
            .any(|admitted| admitted.as_str() == operation)
        && !GIT_MUTATING_TOKENS.contains(&operation)
}
