//! Evidence-first `WorkScopeResolver` (issue #1787, resolver slice).
//!
//! Implements the I4.2 resolution order exactly:
//!
//! ```text
//! 1. current authenticated Session/Task binding with exact WorkspaceInstance identity;
//! 2. explicit Human/host binding token naming an existing WorkScope revision;
//! 3. resumed durable task with matching repository lineage and current instance evidence;
//! 4. host-observed cwd/open-file/resource handles plus VCS common-dir/worktree identity;
//! 5. previously registered WorkspaceInstance or verified relocation/attach receipt;
//! 6. repository-lineage evidence and exact resource bindings;
//! 7. detected manifest/service boundary as a new-scope candidate;
//! 8. provisional ad_hoc/new scope bound only to the current session.
//! ```
//!
//! The resolver evaluates tiers in order and the first tier with usable
//! evidence decides. Tiers without evidence are skipped, never treated as
//! negative votes. A tier that cannot prove one unique authenticated binding
//! returns the preserved candidate set (`AMBIGUOUS_RESULT`) with its
//! disambiguation reference instead of selecting a convenient candidate.
//!
//! Display name, nearest path, longest prefix, most recently used task, and
//! semantic similarity are never sufficient to bind an existing scope: no such
//! input exists on [`ResolutionRequest`], so no tier can consume them. Step 4
//! matches only on exact root identity or exact VCS identity, never on prefix
//! or proximity. Unambiguous is not authenticated: selecting one candidate
//! here never mints authority; owner-issued [`WorkScopeResolutionReceipt`]
//! authentication belongs to the issuance slice.

use super::{
    RepositoryLineageIdentity, ScopeBinding, ScopeRelocationOrAttachReceipt, ScopeResolution,
    WorkScopeCandidate, WorkScopeCandidateSet, WorkScopeError, WorkspaceInstanceIdentity, counter,
    text, unique,
};
use crate::guard::{IdentityLegOutcome, identity_legs};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One step of the I4.2 evidence-first order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionTier {
    SessionTaskBinding,
    BindingToken,
    ResumedTask,
    HostHandles,
    RegisteredOrReceipt,
    LineageEvidence,
    ManifestBoundary,
    ProvisionalAdHoc,
}

/// Tier 1: current authenticated session/task binding with exact instance identity.
///
/// `expected` is the retained binding from the session/task authorities;
/// `observed` is the current workspace observation. Selection additionally
/// requires the bound scope to be present in the candidate set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionTaskClaim {
    pub session_ref: String,
    pub task_ref: String,
    pub expected: ScopeBinding,
    pub observed: ScopeBinding,
}

/// Tier 2: explicit Human/host binding token naming a `WorkScope` revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BindingToken {
    pub token_ref: String,
    pub named_scope_ref: String,
    pub named_revision: u64,
}

/// Tier 3: resumed durable task with lineage and current instance evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResumedTaskEvidence {
    pub task_ref: String,
    pub lineage: RepositoryLineageIdentity,
    pub instance: WorkspaceInstanceIdentity,
}

/// Tier 4: host-observed handles plus VCS common-dir/worktree identity.
///
/// Matching is exact identity only: the observed root must equal a
/// candidate's root identity, or a present VCS identity must equal the
/// candidate's. Prefix, proximity, recency, and open-file counts never match.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostObservedHandles {
    pub observed_root_ref: String,
    pub vcs_identity_ref: Option<String>,
    pub open_file_refs: Vec<String>,
    pub resource_refs: Vec<String>,
}

/// Tier 5: previously registered instance or verified relocation/attach receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisteredInstanceEvidence {
    pub registered_instance_ref: Option<String>,
    pub relocation_receipt: Option<ScopeRelocationOrAttachReceipt>,
}

/// Tier 7: detected manifest/service boundary as a new-scope candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManifestBoundaryClaim {
    pub manifest_ref: String,
    pub root_ref: String,
}

/// One resolution attempt across the ordered tiers.
///
/// Every tier input is optional; absent tiers are skipped. The candidate set
/// is always present and is preserved verbatim into every ambiguous outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolutionRequest {
    pub candidates: WorkScopeCandidateSet,
    pub session_task: Option<SessionTaskClaim>,
    pub binding_token: Option<BindingToken>,
    pub resumed_task: Option<ResumedTaskEvidence>,
    pub host_handles: Option<HostObservedHandles>,
    pub registered: Option<RegisteredInstanceEvidence>,
    pub lineage: Option<RepositoryLineageIdentity>,
    pub manifest_boundary: Option<ManifestBoundaryClaim>,
}

/// What the ordered resolver decided, and where.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolutionOutcome {
    pub resolution: ScopeResolution,
    pub decided_at: Option<ResolutionTier>,
}

/// Evidence-first resolver over caller-supplied observations.
///
/// Stateless: it consumes authenticated bindings and observations supplied by
/// the session/task authorities and host observers, performs no IO, and mints
/// no authority. Owner issuance of [`WorkScopeResolutionReceipt`] is separate.
#[derive(Clone, Copy, Debug, Default)]
pub struct WorkScopeResolver;

fn unique_or_ambiguous(
    matched: Vec<WorkScopeCandidate>,
    whole: &WorkScopeCandidateSet,
    empty: ScopeResolution,
) -> ScopeResolution {
    let mut matched = matched;
    matched.sort_by(|left, right| {
        left.scope
            .scope_ref
            .cmp(&right.scope.scope_ref)
            .then(left.scope.instance_ref.cmp(&right.scope.instance_ref))
    });
    match matched.len() {
        1 => ScopeResolution::Unique(Box::new(matched.remove(0))),
        0 => empty,
        _ => ScopeResolution::Ambiguous(Box::new(whole.clone())),
    }
}

fn filter_candidates(
    set: &WorkScopeCandidateSet,
    mut matches: impl FnMut(&WorkScopeCandidate) -> bool,
) -> Vec<WorkScopeCandidate> {
    set.candidates
        .iter()
        .filter(|candidate| matches(candidate))
        .cloned()
        .collect()
}

impl SessionTaskClaim {
    /// Validates the tier-1 claim without resolving it.
    ///
    /// # Errors
    ///
    /// Returns an error when session/task references are blank or either
    /// binding is malformed.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.session_ref, "session_task.session_ref")?;
        text(&self.task_ref, "session_task.task_ref")?;
        self.expected.validate()?;
        self.observed.validate()
    }
}

impl BindingToken {
    /// Validates the tier-2 token without resolving it.
    ///
    /// # Errors
    ///
    /// Returns an error when token or scope references are blank or the named
    /// revision is zero.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.token_ref, "binding_token.token_ref")?;
        text(&self.named_scope_ref, "binding_token.named_scope_ref")?;
        counter(self.named_revision, "binding_token.named_revision")
    }
}

impl ResumedTaskEvidence {
    /// Validates the tier-3 evidence without resolving it.
    ///
    /// # Errors
    ///
    /// Returns an error when the task reference is blank or lineage/instance
    /// evidence is malformed.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.task_ref, "resumed_task.task_ref")?;
        self.lineage.validate()?;
        self.instance.validate()
    }
}

impl HostObservedHandles {
    /// Validates the tier-4 handles without resolving them.
    ///
    /// # Errors
    ///
    /// Returns an error when the observed root is blank, a handle reference
    /// is blank or duplicated, or the VCS identity is blank.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.observed_root_ref, "host_handles.observed_root_ref")?;
        if let Some(vcs) = &self.vcs_identity_ref {
            text(vcs, "host_handles.vcs_identity_ref")?;
        }
        for handle in self
            .open_file_refs
            .iter()
            .chain(self.resource_refs.iter())
        {
            text(handle, "host_handles.handle_ref")?;
        }
        unique(self.open_file_refs.iter(), "host_handles.open_file_refs")?;
        unique(self.resource_refs.iter(), "host_handles.resource_refs")
    }
}

impl RegisteredInstanceEvidence {
    /// Validates the tier-5 evidence without resolving it.
    ///
    /// # Errors
    ///
    /// Returns an error when neither a registered instance nor a relocation
    /// receipt is present, or when present evidence is malformed.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        if self.registered_instance_ref.is_none() && self.relocation_receipt.is_none() {
            return Err(WorkScopeError::EmptyCollection {
                field: "registered.evidence",
            });
        }
        if let Some(instance) = &self.registered_instance_ref {
            text(instance, "registered.registered_instance_ref")?;
        }
        if let Some(receipt) = &self.relocation_receipt {
            receipt.validate()?;
        }
        Ok(())
    }
}

impl ManifestBoundaryClaim {
    /// Validates the tier-7 claim without resolving it.
    ///
    /// # Errors
    ///
    /// Returns an error when manifest or root references are blank.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.manifest_ref, "manifest_boundary.manifest_ref")?;
        text(&self.root_ref, "manifest_boundary.root_ref")
    }
}

impl ResolutionRequest {
    /// Validates present tier inputs without resolving.
    ///
    /// # Errors
    ///
    /// Returns an error when any present tier evidence is malformed.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        if let Some(claim) = &self.session_task {
            claim.validate()?;
        }
        if let Some(token) = &self.binding_token {
            token.validate()?;
        }
        if let Some(task) = &self.resumed_task {
            task.validate()?;
        }
        if let Some(handles) = &self.host_handles {
            handles.validate()?;
        }
        if let Some(registered) = &self.registered {
            registered.validate()?;
        }
        if let Some(lineage) = &self.lineage {
            lineage.validate()?;
        }
        if let Some(boundary) = &self.manifest_boundary {
            boundary.validate()?;
        }
        Ok(())
    }
}

impl WorkScopeResolver {
    /// Resolves one request through the ordered tiers.
    ///
    /// Returns the first tier with usable evidence; tiers without evidence
    /// are skipped. With no tier evidence the candidate set's own disposition
    /// decides (tier 8: a `NewScope` disposition means the caller builds a
    /// provisional descriptor bound to the current session).
    ///
    /// # Errors
    ///
    /// Returns an error when present tier evidence is malformed. Malformed
    /// input fails; it never falls through to a weaker tier.
    pub fn resolve(request: &ResolutionRequest) -> Result<ResolutionOutcome, WorkScopeError> {
        request.validate()?;
        let set = &request.candidates;
        if let Some(claim) = &request.session_task {
            return Ok(Self::tier_session_task(set, claim));
        }
        if let Some(token) = &request.binding_token {
            return Ok(Self::tier_binding_token(set, token));
        }
        if let Some(task) = &request.resumed_task {
            return Ok(Self::tier_resumed_task(set, task));
        }
        if let Some(handles) = &request.host_handles {
            return Ok(Self::tier_host_handles(set, handles));
        }
        if let Some(registered) = &request.registered {
            return Ok(Self::tier_registered(set, registered));
        }
        if let Some(lineage) = &request.lineage {
            return Ok(Self::tier_lineage(set, lineage));
        }
        if let Some(boundary) = &request.manifest_boundary {
            let _ = boundary;
            return Ok(ResolutionOutcome {
                resolution: ScopeResolution::NewScope,
                decided_at: Some(ResolutionTier::ManifestBoundary),
            });
        }
        Ok(ResolutionOutcome {
            resolution: set.resolve(),
            decided_at: Some(ResolutionTier::ProvisionalAdHoc),
        })
    }

    fn tier_session_task(
        set: &WorkScopeCandidateSet,
        claim: &SessionTaskClaim,
    ) -> ResolutionOutcome {
        let decided_at = Some(ResolutionTier::SessionTaskBinding);
        match identity_legs(&claim.expected, &claim.observed) {
            IdentityLegOutcome::IdentityClear => {
                let matched = filter_candidates(set, |candidate| {
                    candidate.scope.scope_ref == claim.expected.scope.scope_ref
                        && candidate.scope.instance_ref == claim.expected.scope.instance_ref
                });
                ResolutionOutcome {
                    resolution: unique_or_ambiguous(
                        matched,
                        set,
                        ScopeResolution::StaleBinding,
                    ),
                    decided_at,
                }
            }
            IdentityLegOutcome::StaleBinding => ResolutionOutcome {
                resolution: ScopeResolution::StaleBinding,
                decided_at,
            },
            IdentityLegOutcome::DifferentInstance | IdentityLegOutcome::Ambiguous => {
                ResolutionOutcome {
                    resolution: ScopeResolution::Ambiguous(Box::new(set.clone())),
                    decided_at,
                }
            }
        }
    }

    fn tier_binding_token(set: &WorkScopeCandidateSet, token: &BindingToken) -> ResolutionOutcome {
        let matched = filter_candidates(set, |candidate| {
            candidate.scope.scope_ref == token.named_scope_ref
        });
        ResolutionOutcome {
            resolution: unique_or_ambiguous(matched, set, ScopeResolution::StaleBinding),
            decided_at: Some(ResolutionTier::BindingToken),
        }
    }

    fn tier_resumed_task(
        set: &WorkScopeCandidateSet,
        task: &ResumedTaskEvidence,
    ) -> ResolutionOutcome {
        let matched = filter_candidates(set, |candidate| {
            candidate.scope.lineage_ref.as_deref() == Some(task.lineage.lineage_ref.as_str())
                && candidate.scope.instance_ref == task.instance.instance_ref
        });
        ResolutionOutcome {
            resolution: unique_or_ambiguous(matched, set, ScopeResolution::StaleBinding),
            decided_at: Some(ResolutionTier::ResumedTask),
        }
    }

    fn tier_host_handles(
        set: &WorkScopeCandidateSet,
        handles: &HostObservedHandles,
    ) -> ResolutionOutcome {
        let matched = filter_candidates(set, |candidate| {
            candidate.instance.root_identity == handles.observed_root_ref
                || handles.vcs_identity_ref.as_deref().is_some_and(|vcs| {
                    candidate.instance.vcs_identity_ref.as_deref() == Some(vcs)
                })
        });
        ResolutionOutcome {
            resolution: unique_or_ambiguous(
                matched,
                set,
                ScopeResolution::Ambiguous(Box::new(set.clone())),
            ),
            decided_at: Some(ResolutionTier::HostHandles),
        }
    }

    fn tier_registered(
        set: &WorkScopeCandidateSet,
        registered: &RegisteredInstanceEvidence,
    ) -> ResolutionOutcome {
        let matched = filter_candidates(set, |candidate| {
            registered.registered_instance_ref.as_deref() == Some(candidate.scope.instance_ref.as_str())
                || registered
                    .relocation_receipt
                    .as_ref()
                    .is_some_and(|receipt| {
                        receipt.observed_instance.instance_ref == candidate.scope.instance_ref
                    })
        });
        ResolutionOutcome {
            resolution: unique_or_ambiguous(matched, set, ScopeResolution::StaleBinding),
            decided_at: Some(ResolutionTier::RegisteredOrReceipt),
        }
    }

    fn tier_lineage(set: &WorkScopeCandidateSet, lineage: &RepositoryLineageIdentity) -> ResolutionOutcome {
        let matched = filter_candidates(set, |candidate| {
            candidate.scope.lineage_ref.as_deref() == Some(lineage.lineage_ref.as_str())
        });
        ResolutionOutcome {
            resolution: unique_or_ambiguous(matched, set, ScopeResolution::Conflicted),
            decided_at: Some(ResolutionTier::LineageEvidence),
        }
    }
}
