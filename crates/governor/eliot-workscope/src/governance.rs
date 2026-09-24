//! Governing-source admission and task intake (issue #1791).
//!
//! Caller seam for the inputs that make scope/task admission meaningful:
//!
//! - who builds source candidates: the bootstrap-scanner/attach caller, only
//!   from an authenticated root ([`GoverningSourceCandidate::from_authenticated_root`])
//!   or from a read admitted by a valid [`DiscoveryReadLease`](super::DiscoveryReadLease)
//!   ([`GoverningSourceCandidate::from_discovery_lease`]). File names, recency,
//!   locations and model summaries never produce candidates;
//! - who promotes a candidate to `admitted`: an applicable authority/contract
//!   ([`AuthorityBasis`]) attached as the candidate's claim, checked by
//!   [`admit_governing_sources`]. Precedence between roles applies only when
//!   the project declared it ([`PrecedenceDeclaration`]); there is no
//!   hard-coded Architecture-over-Implementation default;
//! - who consumes conflicts: [`admit_governing_sources`] returns a
//!   [`SourceConflictSet`] with the required owner instead of selecting a
//!   winner, and [`source_readiness`] (called by
//!   [`ColdStartController::compile`](super::ColdStartController)) fails
//!   compilation for conflicted sets so no Material effect is eligible;
//! - who submits tasks: [`TaskIntakeCandidate`] keeps origin provenance and
//!   missing fields; promotion to a current binding requires the decision
//!   owner or a delegated binding ([`TaskIntakeCandidate::promote`]), while
//!   [`TaskIntakeCandidate::admit_exploratory`] offers a bounded exploratory
//!   binding that can never authorize Material effects. Missing task data is
//!   answered with [`task_selection_required`], the `TASK_SELECTION_REQUIRED`
//!   shape with a minimal valid intake example.

use super::{
    DiscoveryRead, DiscoveryReadLease, GoverningSource, GoverningSourceRole, GoverningSourceSet,
    SourceStatus, TaskBindingInput, WorkScopeError, counter, digest, text, unique,
};
use eliot_contracts::{StateFence, sha256_hex};
use eliot_security_contracts::{
    FreshnessStatus, IntegrityStatus, ObservationDomainRef, QuarantineState, SourceAssurance,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Authority or contract basis that can promote a source candidate to `admitted`.
///
/// A source becomes governing because one of these says so, never because of
/// its filename, recency, location or a model summary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "basis", content = "detail")]
pub enum AuthorityBasis {
    HumanOwner {
        owner_ref: String,
    },
    DelegatedTaskBinding {
        binding_ref: String,
        task_ref: String,
    },
    ProjectContract {
        contract_ref: String,
    },
}

impl AuthorityBasis {
    /// Validates the named authority references without granting anything.
    ///
    /// # Errors
    ///
    /// Returns an error when a reference is blank or carries control characters.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        match self {
            Self::HumanOwner { owner_ref } => text(owner_ref, "authority.owner_ref"),
            Self::DelegatedTaskBinding {
                binding_ref,
                task_ref,
            } => {
                text(binding_ref, "authority.binding_ref")?;
                text(task_ref, "authority.task_ref")
            }
            Self::ProjectContract { contract_ref } => text(contract_ref, "authority.contract_ref"),
        }
    }

    /// Owner identity this basis speaks for directly, if it names one.
    #[must_use]
    pub fn owner_ref(&self) -> Option<&str> {
        match self {
            Self::HumanOwner { owner_ref } => Some(owner_ref),
            Self::DelegatedTaskBinding { .. } | Self::ProjectContract { .. } => None,
        }
    }
}

/// Project-declared precedence of one governing role over another for one scope.
///
/// Precedence exists only when declared here. In particular there is no
/// implicit Architecture-over-Implementation rule: that pair applies only
/// when a declaration names it for the scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrecedenceDeclaration {
    pub scope_ref: String,
    pub higher: GoverningSourceRole,
    pub lower: GoverningSourceRole,
    pub declared_by: String,
}

impl PrecedenceDeclaration {
    /// Validates the declaration without applying it to any candidate.
    ///
    /// # Errors
    ///
    /// Returns an error when references are invalid or both roles are identical.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.scope_ref, "precedence.scope_ref")?;
        text(&self.declared_by, "precedence.declared_by")?;
        if self.higher == self.lower {
            return Err(WorkScopeError::DuplicateReference {
                field: "precedence roles",
            });
        }
        Ok(())
    }

    /// Returns whether this declaration orders `higher` over `lower` for `scope_ref`.
    #[must_use]
    pub fn applies_to(
        &self,
        scope_ref: &str,
        higher: GoverningSourceRole,
        lower: GoverningSourceRole,
    ) -> bool {
        self.scope_ref == scope_ref && self.higher == higher && self.lower == lower
    }
}

/// Where a governing-source candidate was observed.
///
/// Only authenticated roots and reads admitted by a valid discovery lease can
/// produce candidates.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "origin", content = "detail")]
pub enum SourceCandidateOrigin {
    AuthenticatedRoot { root_identity: String },
    DiscoveryLease { lease_ref: String },
}

impl SourceCandidateOrigin {
    /// Validates the origin reference without authorizing any read.
    ///
    /// # Errors
    ///
    /// Returns an error when the reference is blank or carries control characters.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        match self {
            Self::AuthenticatedRoot { root_identity } => {
                text(root_identity, "candidate.root_identity")
            }
            Self::DiscoveryLease { lease_ref } => text(lease_ref, "candidate.lease_ref"),
        }
    }
}

/// Exact source candidate: handle plus content digest, never authority.
///
/// The digest identifies the exact document snapshot; the attached `claim` is
/// the only path to `admitted`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoverningSourceCandidate {
    pub source_ref: String,
    pub digest: String,
    pub role: GoverningSourceRole,
    pub origin: SourceCandidateOrigin,
    pub applicable_scope_ref: String,
    pub applicable_generation: u64,
    pub assurance: SourceAssurance,
    pub domains: Vec<ObservationDomainRef>,
    pub claim: Option<AuthorityBasis>,
}

/// Field bundle for constructing a [`GoverningSourceCandidate`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewSourceCandidate {
    pub source_ref: String,
    pub digest: String,
    pub role: GoverningSourceRole,
    pub applicable_scope_ref: String,
    pub applicable_generation: u64,
    pub assurance: SourceAssurance,
    pub domains: Vec<ObservationDomainRef>,
    pub claim: Option<AuthorityBasis>,
}

impl GoverningSourceCandidate {
    /// Builds a candidate observed at an authenticated root.
    ///
    /// # Errors
    ///
    /// Returns an error when identity, digest, generation, assurance, domain
    /// or claim evidence is invalid.
    pub fn from_authenticated_root(
        params: NewSourceCandidate,
        root_identity: String,
    ) -> Result<Self, WorkScopeError> {
        text(&root_identity, "candidate.root_identity")?;
        Self::build(
            params,
            SourceCandidateOrigin::AuthenticatedRoot { root_identity },
        )
    }

    /// Builds a candidate observed under a discovery lease.
    ///
    /// The lease must admit the `governing_source_candidates` read at `now`
    /// and must cover `observed_root_ref`; anything else fails closed without
    /// producing a candidate.
    ///
    /// # Errors
    ///
    /// Returns an error when fields are invalid, the lease is expired,
    /// exhausted, does not admit the read, or covers a different root.
    pub fn from_discovery_lease(
        params: NewSourceCandidate,
        lease: &DiscoveryReadLease,
        observed_root_ref: &str,
        now: u64,
    ) -> Result<Self, WorkScopeError> {
        text(observed_root_ref, "candidate.observed_root_ref")?;
        if observed_root_ref != lease.candidate_root_ref {
            return Err(WorkScopeError::SourceIdentityMismatch);
        }
        lease
            .authorize(DiscoveryRead::GoverningSourceCandidates, now)
            .map_err(|_| WorkScopeError::InvalidSourceEvidence)?;
        Self::build(
            params,
            SourceCandidateOrigin::DiscoveryLease {
                lease_ref: lease.lease_ref.clone(),
            },
        )
    }

    fn build(
        params: NewSourceCandidate,
        origin: SourceCandidateOrigin,
    ) -> Result<Self, WorkScopeError> {
        let candidate = Self {
            source_ref: params.source_ref,
            digest: params.digest,
            role: params.role,
            origin,
            applicable_scope_ref: params.applicable_scope_ref,
            applicable_generation: params.applicable_generation,
            assurance: params.assurance,
            domains: params.domains,
            claim: params.claim,
        };
        candidate.validate()?;
        Ok(candidate)
    }

    /// Validates the candidate without promoting it to any authority.
    ///
    /// # Errors
    ///
    /// Returns an error when identity, digest, generation, assurance, domain
    /// or claim evidence is invalid.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.source_ref, "candidate.source_ref")?;
        digest(&self.digest, "candidate.digest")?;
        self.origin.validate()?;
        text(&self.applicable_scope_ref, "candidate.applicable_scope_ref")?;
        counter(
            self.applicable_generation,
            "candidate.applicable_generation",
        )?;
        if self.source_ref != self.assurance.source_ref {
            return Err(WorkScopeError::SourceIdentityMismatch);
        }
        self.assurance
            .validate()
            .map_err(|_| WorkScopeError::InvalidSourceEvidence)?;
        for domain in &self.domains {
            domain
                .validate()
                .map_err(|_| WorkScopeError::InvalidSourceEvidence)?;
        }
        if let Some(claim) = &self.claim {
            claim.validate()?;
        }
        Ok(())
    }

    fn into_record(self, status: SourceStatus) -> GoverningSource {
        let authority_basis = match status {
            SourceStatus::Admitted => self.claim.clone(),
            SourceStatus::Candidate
            | SourceStatus::Stale
            | SourceStatus::Superseded
            | SourceStatus::Conflicted
            | SourceStatus::Unavailable => None,
        };
        GoverningSource {
            source_ref: self.source_ref,
            role: self.role,
            assurance: self.assurance,
            applicable_generation: self.applicable_generation,
            status,
            domains: self.domains,
            digest: self.digest,
            authority_basis,
        }
    }
}

/// Conflict set returned instead of a silently selected winner.
///
/// `required_owner_ref` is caller-supplied and never inferred from filenames,
/// recency, locations or model output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceConflictSet {
    pub scope_ref: String,
    pub generation: u64,
    pub conflicting_refs: Vec<String>,
    pub required_owner_ref: String,
}

impl SourceConflictSet {
    /// Validates the conflict set without resolving it.
    ///
    /// # Errors
    ///
    /// Returns an error when references are invalid, duplicated or empty.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.scope_ref, "conflict.scope_ref")?;
        counter(self.generation, "conflict.generation")?;
        text(&self.required_owner_ref, "conflict.required_owner_ref")?;
        if self.conflicting_refs.is_empty() {
            return Err(WorkScopeError::EmptyCollection {
                field: "conflict.conflicting_refs",
            });
        }
        unique(self.conflicting_refs.iter(), "conflict.conflicting_refs")?;
        for conflicting in &self.conflicting_refs {
            text(conflicting, "conflict.conflicting_refs")?;
        }
        Ok(())
    }
}

/// Coverage of the admitted set, including explicit absence.
///
/// A scope is never forced to invent governing documents: an evidence-backed
/// "no governing document found / not applicable" state is valid coverage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "coverage", content = "detail")]
pub enum SourceCoverage {
    Complete,
    Partial,
    ExplicitAbsence { reason_ref: String },
}

/// Input to [`admit_governing_sources`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceAdmissionRequest {
    pub scope_ref: String,
    pub generation: u64,
    pub candidates: Vec<GoverningSourceCandidate>,
    pub precedences: Vec<PrecedenceDeclaration>,
    pub required_owner_ref: String,
    pub absence_reason_ref: Option<String>,
    pub state_fence: StateFence,
    pub expires_at: u64,
}

/// Outcome of [`admit_governing_sources`].
///
/// `admitted` holds only `admitted` records and is the sole input eligible
/// for readiness; `preserved` keeps every non-admitted record under its
/// honest status; `conflict` names the clash and the owner who must resolve it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoverningSourceAdmission {
    pub admitted: GoverningSourceSet,
    pub preserved: Vec<GoverningSource>,
    pub conflict: Option<SourceConflictSet>,
    pub coverage: SourceCoverage,
    pub applied_precedences: Vec<PrecedenceDeclaration>,
    pub state_fence: StateFence,
    pub expires_at: u64,
}

impl GoverningSourceAdmission {
    /// Returns whether the admission fence is still live at `now`.
    #[must_use]
    pub fn is_live(&self, now: u64) -> bool {
        now <= self.expires_at
    }
}

/// Validates an admission request without admitting anything.
///
/// # Errors
///
/// Returns an error when scope, generation, owner, fence, expiry, precedence
/// or candidate evidence is malformed, or when a candidate or precedence
/// names a different scope or generation.
fn validate_admission_request(request: &SourceAdmissionRequest) -> Result<(), WorkScopeError> {
    text(&request.scope_ref, "scope_ref")?;
    counter(request.generation, "generation")?;
    text(&request.required_owner_ref, "required_owner_ref")?;
    counter(request.expires_at, "expires_at")?;
    request
        .state_fence
        .validate()
        .map_err(|_| WorkScopeError::InvalidStateFence)?;
    if request.state_fence.resource_generation.value() != request.generation {
        return Err(WorkScopeError::StateFenceMismatch);
    }
    for precedence in &request.precedences {
        precedence.validate()?;
        if precedence.scope_ref != request.scope_ref {
            return Err(WorkScopeError::SourceSetMismatch);
        }
    }
    for candidate in &request.candidates {
        candidate.validate()?;
        if candidate.applicable_scope_ref != request.scope_ref
            || candidate.applicable_generation != request.generation
        {
            return Err(WorkScopeError::SourceSetMismatch);
        }
    }
    Ok(())
}

/// Splits candidates into eligible groups and honestly preserved records.
///
/// Stale or quarantined evidence never reaches grouping; unverified evidence
/// is held as a candidate, modified or provider-conflicted evidence is kept
/// as conflicted.
fn triage_candidates(
    candidates: Vec<GoverningSourceCandidate>,
) -> (
    BTreeMap<String, Vec<GoverningSourceCandidate>>,
    Vec<GoverningSource>,
) {
    let mut groups: BTreeMap<String, Vec<GoverningSourceCandidate>> = BTreeMap::new();
    let mut preserved: Vec<GoverningSource> = Vec::new();
    for candidate in candidates {
        if candidate.assurance.freshness != FreshnessStatus::Current {
            preserved.push(candidate.into_record(SourceStatus::Stale));
        } else if matches!(candidate.assurance.quarantine, QuarantineState::Quarantined) {
            preserved.push(candidate.into_record(SourceStatus::Conflicted));
        } else if candidate.assurance.integrity != IntegrityStatus::Verified {
            let status = match candidate.assurance.integrity {
                IntegrityStatus::Verified | IntegrityStatus::Unverified => SourceStatus::Candidate,
                IntegrityStatus::Modified | IntegrityStatus::Conflicted => SourceStatus::Conflicted,
            };
            preserved.push(candidate.into_record(status));
        } else {
            groups
                .entry(candidate.source_ref.clone())
                .or_default()
                .push(candidate);
        }
    }
    (groups, preserved)
}

/// Resolution of one handle group: admitted and preserved records, whether
/// the handle is conflicted, and which declared precedences were applied.
struct GroupResolution {
    admitted: Vec<GoverningSource>,
    preserved: Vec<GoverningSource>,
    conflicted: bool,
    applied: Vec<PrecedenceDeclaration>,
}

/// Resolves one handle group without ever selecting a silent winner.
///
/// One digest admits through its attached authority claim or stays a
/// candidate. Several digests resolve only through a single agreed owner
/// claim or one applicable project-declared precedence; disagreeing claims
/// and undeclared clashes stay conflicted.
fn resolve_group(
    group: Vec<GoverningSourceCandidate>,
    precedences: &[PrecedenceDeclaration],
    scope_ref: &str,
) -> GroupResolution {
    let mut digests: BTreeSet<&str> = BTreeSet::new();
    for candidate in &group {
        digests.insert(candidate.digest.as_str());
    }
    if digests.len() == 1 {
        let only = group.into_iter().next();
        let Some(candidate) = only else {
            return GroupResolution {
                admitted: Vec::new(),
                preserved: Vec::new(),
                conflicted: false,
                applied: Vec::new(),
            };
        };
        if candidate.claim.is_some() {
            return GroupResolution {
                admitted: vec![candidate.into_record(SourceStatus::Admitted)],
                preserved: Vec::new(),
                conflicted: false,
                applied: Vec::new(),
            };
        }
        return GroupResolution {
            admitted: Vec::new(),
            preserved: vec![candidate.into_record(SourceStatus::Candidate)],
            conflicted: false,
            applied: Vec::new(),
        };
    }
    let mut claimed: BTreeSet<String> = BTreeSet::new();
    for candidate in &group {
        if candidate.claim.is_some() {
            claimed.insert(candidate.digest.clone());
        }
    }
    if claimed.len() > 1 {
        return conflicted_group(group);
    }
    if let Some(winner_digest) = claimed.iter().next().cloned() {
        let mut admitted = Vec::new();
        let mut preserved = Vec::new();
        for candidate in group {
            if candidate.digest == winner_digest {
                admitted.push(candidate.into_record(SourceStatus::Admitted));
            } else {
                preserved.push(candidate.into_record(SourceStatus::Superseded));
            }
        }
        return GroupResolution {
            admitted,
            preserved,
            conflicted: false,
            applied: Vec::new(),
        };
    }
    if let Some(winner) = precedence_winner(&group, precedences, scope_ref) {
        let winner_role = winner.role;
        let winner_digest = winner.digest.clone();
        let applied: Vec<PrecedenceDeclaration> = precedences
            .iter()
            .filter(|declaration| {
                declaration.applies_to(scope_ref, winner_role, declaration.lower)
                    || declaration.applies_to(scope_ref, declaration.higher, winner_role)
            })
            .cloned()
            .collect();
        let mut admitted = Vec::new();
        let mut preserved = Vec::new();
        for candidate in group {
            if candidate.digest == winner_digest {
                admitted.push(candidate.into_record(SourceStatus::Admitted));
            } else {
                preserved.push(candidate.into_record(SourceStatus::Superseded));
            }
        }
        return GroupResolution {
            admitted,
            preserved,
            conflicted: false,
            applied,
        };
    }
    conflicted_group(group)
}

/// Preserves every member of an unresolvable group as conflicted.
fn conflicted_group(group: Vec<GoverningSourceCandidate>) -> GroupResolution {
    GroupResolution {
        admitted: Vec::new(),
        preserved: group
            .into_iter()
            .map(|candidate| candidate.into_record(SourceStatus::Conflicted))
            .collect(),
        conflicted: true,
        applied: Vec::new(),
    }
}
/// Admits governing sources from exact candidates without inferring authority.
///
/// Candidates promote to `admitted` only through an attached applicable
/// authority/contract claim. Incompatible documents (one handle, several
/// digests) resolve only through a single agreed owner claim or an applicable
/// project-declared precedence; disagreeing owner claims and undeclared
/// clashes become a [`SourceConflictSet`] with the required owner, and every
/// involved record is preserved as `conflicted`. Stale or quarantined
/// evidence is preserved as `stale`/`conflicted` and never admitted. No
/// branch selects a winner from filename, recency, location or model output.
///
/// # Errors
///
/// Returns an error when scope, generation, owner, fence, expiry, precedence
/// or candidate evidence is malformed, when a candidate or precedence names a
/// different scope/generation, or when no candidates exist without an explicit
/// absence reason.
pub fn admit_governing_sources(
    request: SourceAdmissionRequest,
) -> Result<GoverningSourceAdmission, WorkScopeError> {
    validate_admission_request(&request)?;
    if request.candidates.is_empty() {
        let Some(reason) = request.absence_reason_ref else {
            return Err(WorkScopeError::EmptyCollection { field: "sources" });
        };
        text(&reason, "absence_reason_ref")?;
        return Ok(GoverningSourceAdmission {
            admitted: GoverningSourceSet::new(
                request.scope_ref.clone(),
                request.generation,
                Vec::new(),
                Vec::new(),
            )?,
            preserved: Vec::new(),
            conflict: None,
            coverage: SourceCoverage::ExplicitAbsence {
                reason_ref: reason.clone(),
            },
            applied_precedences: Vec::new(),
            state_fence: request.state_fence,
            expires_at: request.expires_at,
        });
    }

    let (groups, mut preserved) = triage_candidates(request.candidates);
    let mut admitted: Vec<GoverningSource> = Vec::new();
    let mut conflicting: BTreeSet<String> = BTreeSet::new();
    let mut applied_precedences: Vec<PrecedenceDeclaration> = Vec::new();
    for (source_ref, group) in groups {
        let resolution = resolve_group(group, &request.precedences, &request.scope_ref);
        if resolution.conflicted {
            conflicting.insert(source_ref.clone());
        }
        admitted.extend(resolution.admitted);
        preserved.extend(resolution.preserved);
        applied_precedences.extend(resolution.applied);
    }

    let conflicting_refs: Vec<String> = conflicting.into_iter().collect();
    let conflict = if conflicting_refs.is_empty() {
        None
    } else {
        Some(SourceConflictSet {
            scope_ref: request.scope_ref.clone(),
            generation: request.generation,
            conflicting_refs: conflicting_refs.clone(),
            required_owner_ref: request.required_owner_ref.clone(),
        })
    };
    let coverage = if conflict.is_some() || !preserved.is_empty() {
        SourceCoverage::Partial
    } else {
        SourceCoverage::Complete
    };
    let admitted_set = GoverningSourceSet::new(
        request.scope_ref,
        request.generation,
        admitted,
        conflicting_refs,
    )?;
    if let Some(conflict) = &conflict {
        conflict.validate()?;
    }
    Ok(GoverningSourceAdmission {
        admitted: admitted_set,
        preserved,
        conflict,
        coverage,
        applied_precedences,
        state_fence: request.state_fence,
        expires_at: request.expires_at,
    })
}

/// Finds the winning digest through project-declared role precedence.
///
/// Returns a winner only when the group spans at least two roles, one role
/// beats every other declared comparison it takes part in, loses none, and
/// carries exactly one digest. Within-role divergence and contradictory
/// declarations never resolve silently.
fn precedence_winner(
    group: &[GoverningSourceCandidate],
    precedences: &[PrecedenceDeclaration],
    scope_ref: &str,
) -> Option<GoverningSourceCandidate> {
    let mut roles: BTreeMap<GoverningSourceRole, BTreeSet<&str>> = BTreeMap::new();
    for candidate in group {
        roles
            .entry(candidate.role)
            .or_default()
            .insert(candidate.digest.as_str());
    }
    if roles.len() < 2 {
        return None;
    }
    let mut beaten: BTreeSet<GoverningSourceRole> = BTreeSet::new();
    for declaration in precedences {
        let higher = roles.get(&declaration.higher);
        let lower = roles.get(&declaration.lower);
        if let (Some(higher), Some(lower)) = (higher, lower)
            && declaration.applies_to(scope_ref, declaration.higher, declaration.lower)
            && higher != lower
        {
            beaten.insert(declaration.lower);
        }
    }
    let unbeaten: Vec<GoverningSourceRole> = roles
        .iter()
        .filter(|(role, digests)| !beaten.contains(*role) && digests.len() == 1)
        .map(|(role, _)| *role)
        .collect();
    if unbeaten.len() != 1 {
        return None;
    }
    group
        .iter()
        .find(|candidate| candidate.role == unbeaten[0])
        .cloned()
}

/// Readiness of a governing-source set for scope-sensitive use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceReadiness {
    Admitted,
    Incomplete,
    Conflicted { conflicting_refs: Vec<String> },
}

/// Reports whether a source set is admitted, incomplete, or conflicted.
///
/// Conflicted sets name every clash and never name a winner; the cold-start
/// compiler fails them closed so no Material effect stays eligible.
///
/// # Panics
///
/// Never panics; all inputs are caller-owned data.
#[must_use]
pub fn source_readiness(set: &GoverningSourceSet) -> SourceReadiness {
    let mut refs: BTreeSet<&String> = set.unresolved_conflict_refs.iter().collect();
    refs.extend(
        set.sources
            .iter()
            .filter(|source| source.status == SourceStatus::Conflicted)
            .map(|source| &source.source_ref),
    );
    if !refs.is_empty() {
        return SourceReadiness::Conflicted {
            conflicting_refs: refs.into_iter().cloned().collect(),
        };
    }
    if !set.sources.is_empty()
        && set
            .sources
            .iter()
            .all(|source| source.status == SourceStatus::Admitted)
    {
        return SourceReadiness::Admitted;
    }
    SourceReadiness::Incomplete
}

/// Where a task-intake candidate came from.
///
/// Provenance is preserved verbatim through intake: host-visible prompt text
/// stays an observation and never becomes user authority by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskIntakeOrigin {
    HumanUi,
    AgentExplicit,
    HostVisiblePrompt,
    ResumedWork,
    Import,
}

/// Explicit task-intake candidate.
///
/// A task becomes current only when the applicable Human/Task owner or an
/// existing delegated task binding admits it through [`TaskIntakeCandidate::promote`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskIntakeCandidate {
    pub intake_ref: String,
    pub proposer_principal_ref: String,
    pub proposer_session_ref: String,
    pub route_ref: String,
    pub goal: Option<String>,
    pub acceptance_digest: Option<String>,
    pub constraints: Vec<String>,
    pub proposed_scope_ref: Option<String>,
    pub proposed_source_digests: Vec<String>,
    pub decision_owner_ref: Option<String>,
    pub task_controller_ref: Option<String>,
    pub origin: TaskIntakeOrigin,
    pub missing_fields: Vec<String>,
}

/// Field bundle for constructing a [`TaskIntakeCandidate`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewTaskIntake {
    pub intake_ref: String,
    pub proposer_principal_ref: String,
    pub proposer_session_ref: String,
    pub route_ref: String,
    pub goal: Option<String>,
    pub acceptance_digest: Option<String>,
    pub constraints: Vec<String>,
    pub proposed_scope_ref: Option<String>,
    pub proposed_source_digests: Vec<String>,
    pub decision_owner_ref: Option<String>,
    pub task_controller_ref: Option<String>,
    pub origin: TaskIntakeOrigin,
}

impl TaskIntakeCandidate {
    /// Builds an intake candidate, preserving provenance and missing fields.
    ///
    /// Missing goal, acceptance, owner or scope do not fail construction:
    /// they are recorded in `missing_fields` and block promotion until supplied.
    ///
    /// # Errors
    ///
    /// Returns an error when a supplied reference, digest, constraint or the
    /// computed missing-field list is malformed or duplicated.
    pub fn new(params: NewTaskIntake) -> Result<Self, WorkScopeError> {
        text(&params.intake_ref, "intake.intake_ref")?;
        text(
            &params.proposer_principal_ref,
            "intake.proposer_principal_ref",
        )?;
        text(&params.proposer_session_ref, "intake.proposer_session_ref")?;
        text(&params.route_ref, "intake.route_ref")?;
        if let Some(goal) = &params.goal {
            text(goal, "intake.goal")?;
        }
        if let Some(acceptance) = &params.acceptance_digest {
            text(acceptance, "intake.acceptance_digest")?;
        }
        unique(params.constraints.iter(), "intake.constraints")?;
        for constraint in &params.constraints {
            text(constraint, "intake.constraints")?;
        }
        if let Some(scope) = &params.proposed_scope_ref {
            text(scope, "intake.proposed_scope_ref")?;
        }
        unique(
            params.proposed_source_digests.iter(),
            "intake.proposed_source_digests",
        )?;
        for handle_digest in &params.proposed_source_digests {
            digest(handle_digest, "intake.proposed_source_digests")?;
        }
        if let Some(owner) = &params.decision_owner_ref {
            text(owner, "intake.decision_owner_ref")?;
        }
        if let Some(controller) = &params.task_controller_ref {
            text(controller, "intake.task_controller_ref")?;
        }
        let mut missing_fields = Vec::new();
        if params.goal.is_none() {
            missing_fields.push("goal".to_owned());
        }
        if params.acceptance_digest.is_none() {
            missing_fields.push("acceptance_digest".to_owned());
        }
        if params.decision_owner_ref.is_none() {
            missing_fields.push("decision_owner_ref".to_owned());
        }
        if params.proposed_scope_ref.is_none() {
            missing_fields.push("proposed_scope_ref".to_owned());
        }
        Ok(Self {
            intake_ref: params.intake_ref,
            proposer_principal_ref: params.proposer_principal_ref,
            proposer_session_ref: params.proposer_session_ref,
            route_ref: params.route_ref,
            goal: params.goal,
            acceptance_digest: params.acceptance_digest,
            constraints: params.constraints,
            proposed_scope_ref: params.proposed_scope_ref,
            proposed_source_digests: params.proposed_source_digests,
            decision_owner_ref: params.decision_owner_ref,
            task_controller_ref: params.task_controller_ref,
            origin: params.origin,
            missing_fields,
        })
    }

    /// Returns whether goal, acceptance, owner and scope are all present.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.missing_fields.is_empty()
    }

    /// Promotes the intake to a current-task binding input.
    ///
    /// Only the matching Human decision owner or an existing delegated task
    /// binding can promote; a project contract alone cannot, and
    /// host-visible prompt text never authorizes itself. The admitting owner
    /// assigns the task revision, so promotion invents no contract identity.
    ///
    /// # Errors
    ///
    /// Returns [`WorkScopeError::TaskAuthorityDenied`] when the basis is not
    /// the decision owner or a delegated binding, and an error when the
    /// intake is incomplete or the revision is zero.
    pub fn promote(
        &self,
        basis: &AuthorityBasis,
        task_revision: u64,
    ) -> Result<TaskBindingInput, WorkScopeError> {
        basis.validate()?;
        match basis {
            AuthorityBasis::HumanOwner { owner_ref }
                if self.decision_owner_ref.as_deref() == Some(owner_ref.as_str()) => {}
            AuthorityBasis::DelegatedTaskBinding { .. } => {}
            AuthorityBasis::HumanOwner { .. } | AuthorityBasis::ProjectContract { .. } => {
                return Err(WorkScopeError::TaskAuthorityDenied);
            }
        }
        if !self.is_complete() {
            return Err(WorkScopeError::EmptyCollection {
                field: "task_intake.missing_fields",
            });
        }
        counter(task_revision, "task_revision")?;
        let Some(acceptance_digest) = self.acceptance_digest.clone() else {
            return Err(WorkScopeError::EmptyCollection {
                field: "task_intake.missing_fields",
            });
        };
        Ok(TaskBindingInput::Current {
            task_ref: self.intake_ref.clone(),
            task_revision,
            acceptance_digest,
        })
    }

    /// Admits a bounded exploratory binding without task authority.
    ///
    /// Exploratory admission needs only a stated goal or question. The
    /// resulting binding compiles to read-only readiness and can never
    /// authorize scope-sensitive Material effects. When no acceptance digest
    /// was supplied, the binding carries the digest of the stated goal: a
    /// deterministic derivation of caller-owned text, not an authority grant.
    ///
    /// # Errors
    ///
    /// Returns an error when no goal or exploratory question is present.
    pub fn admit_exploratory(&self) -> Result<TaskBindingInput, WorkScopeError> {
        let Some(goal) = self.goal.clone() else {
            return Err(WorkScopeError::EmptyCollection {
                field: "task_intake.goal",
            });
        };
        let acceptance_digest = self
            .acceptance_digest
            .clone()
            .unwrap_or_else(|| sha256_hex(goal.as_bytes()));
        Ok(TaskBindingInput::Exploratory {
            task_ref: self.intake_ref.clone(),
            task_revision: 1,
            acceptance_digest,
        })
    }
}

/// Agent-facing `TASK_SELECTION_REQUIRED` response shape.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskSelectionRequired {
    pub scope_ref: String,
    pub minimal_intake_fields: Vec<String>,
    pub minimal_intake_example: TaskIntakeCandidate,
    pub exploratory_offer: String,
}

/// Builds the `TASK_SELECTION_REQUIRED` response for a scope.
///
/// The response carries the minimal valid intake shape (goal, acceptance,
/// owner, scope) with a complete example, and offers a bounded exploratory
/// task that cannot perform scope-sensitive Material effects.
///
/// # Errors
///
/// Returns an error when the scope reference is invalid.
pub fn task_selection_required(scope_ref: &str) -> Result<TaskSelectionRequired, WorkScopeError> {
    text(scope_ref, "scope_ref")?;
    let minimal_intake_example = TaskIntakeCandidate::new(NewTaskIntake {
        intake_ref: format!("intake:example:{scope_ref}"),
        proposer_principal_ref: "principal:example".to_owned(),
        proposer_session_ref: "session:example".to_owned(),
        route_ref: "route:example".to_owned(),
        goal: Some("state the user goal or exploratory question".to_owned()),
        acceptance_digest: Some("state the acceptance digest or expected artifact".to_owned()),
        constraints: Vec::new(),
        proposed_scope_ref: Some(scope_ref.to_owned()),
        proposed_source_digests: Vec::new(),
        decision_owner_ref: Some("state the decision owner ref".to_owned()),
        task_controller_ref: None,
        origin: TaskIntakeOrigin::HumanUi,
    })?;
    Ok(TaskSelectionRequired {
        scope_ref: scope_ref.to_owned(),
        minimal_intake_fields: [
            "goal",
            "acceptance_digest",
            "decision_owner_ref",
            "proposed_scope_ref",
        ]
        .iter()
        .map(ToString::to_string)
        .collect(),
        minimal_intake_example,
        exploratory_offer: "a bounded exploratory task may be admitted without task authority; it permits read-only orientation only and never scope-sensitive Material effects".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)] // test-only panic-acceptable (#838).
    use super::super::{
        ColdStartController, GoverningSourceRole, OnboardingLease, OnboardingLeaseState,
        PrivacyProfile, RepositoryLineageIdentity, ScopeIdentity, ScopeKind, TaskBindingState,
        WorkScopeCandidate, WorkspaceInstanceIdentity,
    };
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use eliot_security_contracts::PrivacyClass;
    use serde::de::DeserializeOwned;
    use std::num::NonZeroU64;

    use crate::ReadinessLifecycle;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
    const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn test_epoch() -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
            NonZeroU64::new(1).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn test_fence() -> StateFence {
        StateFence::new(test_epoch(), ResourceGeneration::genesis())
    }

    fn from_json<T: DeserializeOwned>(value: serde_json::Value) -> T {
        serde_json::from_value(value).expect("fixture is invalid")
    }

    fn assurance(source_ref: &str) -> SourceAssurance {
        from_json(serde_json::json!({
            "source_ref": source_ref,
            "provenance_ref": "artifact:test",
            "integrity": "VERIFIED",
            "freshness": "CURRENT",
            "competence": "DOMAIN_VERIFIED",
            "independence": "INDEPENDENT",
            "privacy_class": "INTERNAL",
            "instruction_taint": "CLEARED",
            "allowed_epistemic_use": ["OBSERVATION"],
            "allowed_effects": ["READ_ONLY"],
            "required_verifier": null,
            "quarantine": "NONE",
            "state_fence": {
                "authority_epoch": {"lineage_id": TEST_LINEAGE_A, "sequence": 1},
                "resource_generation": 1,
                "task_revision": null,
                "policy_revision": null,
                "integration_revision": null
            }
        }))
    }

    fn candidate_params(
        source_ref: &str,
        digest_value: &str,
        role: GoverningSourceRole,
        claim: Option<AuthorityBasis>,
    ) -> NewSourceCandidate {
        NewSourceCandidate {
            source_ref: source_ref.to_owned(),
            digest: digest_value.to_owned(),
            role,
            applicable_scope_ref: "scope:a".to_owned(),
            applicable_generation: 1,
            assurance: assurance(source_ref),
            domains: Vec::new(),
            claim,
        }
    }

    fn candidate_record() -> WorkScopeCandidate {
        let scope = ScopeIdentity {
            scope_ref: "scope:a".to_owned(),
            kind: ScopeKind::GitRepo,
            lineage_ref: Some("lineage:one".to_owned()),
            instance_ref: "instance:a".to_owned(),
            root_identity: "root:a".to_owned(),
            generation: 1,
        };
        WorkScopeCandidate {
            instance: WorkspaceInstanceIdentity {
                instance_ref: "instance:a".to_owned(),
                root_identity: "root:a".to_owned(),
                vcs_identity_ref: Some("vcs:one".to_owned()),
                generation: 1,
            },
            scope,
            lineage: Some(RepositoryLineageIdentity {
                lineage_ref: "lineage:one".to_owned(),
                object_store_ref: "store:one".to_owned(),
                initial_history_ref: "history:one".to_owned(),
                normalized_remote_ref: Some("remote:one".to_owned()),
                manifest_identity_ref: Some("manifest:one".to_owned()),
            }),
            privacy_class: PrivacyClass::Internal,
        }
    }

    fn compile_with(
        candidate: &WorkScopeCandidate,
        sources: &GoverningSourceSet,
        task: TaskBindingInput,
    ) -> Result<crate::OnboardingReadinessReceipt, WorkScopeError> {
        let lease = OnboardingLease {
            lease_ref: "onboarding:one".to_owned(),
            lineage_candidate_ref: "lineage:one".to_owned(),
            workspace_instance_candidate_ref: "instance:a".to_owned(),
            governing_source_generation: 1,
            compiler_epoch: 1,
            state: OnboardingLeaseState::Compiling,
            deadline: 10,
        };
        let privacy = PrivacyProfile {
            admitted_classes: vec![PrivacyClass::Internal],
        };
        ColdStartController.compile(
            "receipt:one",
            &lease,
            "principal:test",
            "session:test",
            &candidate.scope,
            &candidate.instance,
            candidate.lineage.as_ref(),
            candidate,
            sources,
            &test_fence(),
            "governance-profile:test",
            vec!["integration:evidence:one".to_owned()],
            "route-profile:test",
            "serializer:test",
            "serializer-version:test",
            "serializer-options:test",
            "tokenizer:test",
            "tokenizer-version:test",
            "tokenizer-hash:test",
            "projection-source:test",
            1,
            &privacy,
            task,
            1,
        )
    }

    fn admission_request(candidates: Vec<GoverningSourceCandidate>) -> SourceAdmissionRequest {
        SourceAdmissionRequest {
            scope_ref: "scope:a".to_owned(),
            generation: 1,
            candidates,
            precedences: Vec::new(),
            required_owner_ref: "owner:human".to_owned(),
            absence_reason_ref: None,
            state_fence: test_fence(),
            expires_at: 10,
        }
    }

    /// Acceptance A1: two conflicting instructions with no precedence or owner
    /// rule report as conflicted with no admitted winner, and readiness keeps
    /// a Material operation ineligible.
    #[test]
    fn conflicting_instructions_without_rule_report_conflict_and_block_material() {
        let first = GoverningSourceCandidate::from_authenticated_root(
            candidate_params(
                "source:instruction",
                DIGEST_A,
                GoverningSourceRole::Architecture,
                None,
            ),
            "root:a".to_owned(),
        )
        .expect("first candidate builds");
        let second = GoverningSourceCandidate::from_authenticated_root(
            candidate_params(
                "source:instruction",
                DIGEST_B,
                GoverningSourceRole::Implementation,
                None,
            ),
            "root:a".to_owned(),
        )
        .expect("second candidate builds");
        let admission = admit_governing_sources(admission_request(vec![first, second]))
            .expect("admission runs");
        assert!(admission.admitted.sources.is_empty());
        let conflict = admission.conflict.expect("conflict is reported");
        assert_eq!(
            conflict.conflicting_refs,
            vec!["source:instruction".to_owned()]
        );
        assert_eq!(conflict.required_owner_ref, "owner:human");
        assert!(
            admission
                .preserved
                .iter()
                .all(|source| source.status == SourceStatus::Conflicted)
        );
        assert!(matches!(
            source_readiness(&admission.admitted),
            SourceReadiness::Conflicted { .. }
        ));

        let record = candidate_record();
        let task = TaskBindingInput::Current {
            task_ref: "task:one".to_owned(),
            task_revision: 1,
            acceptance_digest: "digest:acceptance:one".to_owned(),
        };
        let error = compile_with(&record, &admission.admitted, task)
            .expect_err("conflicted sets never compile");
        assert_eq!(error, WorkScopeError::UnresolvedSourceConflict);
    }

    /// Acceptance A2: a Human owner admitting one exact digest plus a complete
    /// intake candidate yields the admitted record and a `READY_MATERIAL` binding.
    #[test]
    fn owner_admitted_digest_and_intake_compile_to_ready_material() {
        let owner = AuthorityBasis::HumanOwner {
            owner_ref: "owner:human".to_owned(),
        };
        let winner = GoverningSourceCandidate::from_authenticated_root(
            candidate_params(
                "source:instruction",
                DIGEST_A,
                GoverningSourceRole::Architecture,
                Some(owner.clone()),
            ),
            "root:a".to_owned(),
        )
        .expect("winning candidate builds");
        let loser = GoverningSourceCandidate::from_authenticated_root(
            candidate_params(
                "source:instruction",
                DIGEST_B,
                GoverningSourceRole::Implementation,
                None,
            ),
            "root:a".to_owned(),
        )
        .expect("losing candidate builds");
        let admission = admit_governing_sources(admission_request(vec![winner, loser]))
            .expect("admission runs");
        assert!(admission.conflict.is_none());
        assert_eq!(admission.coverage, SourceCoverage::Partial);
        assert_eq!(admission.admitted.sources.len(), 1);
        let admitted = &admission.admitted.sources[0];
        assert_eq!(admitted.digest, DIGEST_A);
        assert_eq!(admitted.authority_basis, Some(owner.clone()));
        assert_eq!(
            source_readiness(&admission.admitted),
            SourceReadiness::Admitted
        );

        let intake = TaskIntakeCandidate::new(NewTaskIntake {
            intake_ref: "intake:one".to_owned(),
            proposer_principal_ref: "principal:test".to_owned(),
            proposer_session_ref: "session:test".to_owned(),
            route_ref: "route:test".to_owned(),
            goal: Some("goal:test".to_owned()),
            acceptance_digest: Some("digest:acceptance:one".to_owned()),
            constraints: Vec::new(),
            proposed_scope_ref: Some("scope:a".to_owned()),
            proposed_source_digests: vec![DIGEST_A.to_owned()],
            decision_owner_ref: Some("owner:human".to_owned()),
            task_controller_ref: Some("controller:test".to_owned()),
            origin: TaskIntakeOrigin::HumanUi,
        })
        .expect("intake builds");
        assert!(intake.is_complete());
        let input = intake.promote(&owner, 3).expect("owner promotes intake");
        assert!(matches!(
            input,
            TaskBindingInput::Current {
                ref task_ref,
                task_revision: 3,
                ..
            } if task_ref == "intake:one"
        ));

        let record = candidate_record();
        let receipt = compile_with(&record, &admission.admitted, input).expect("receipt compiles");
        assert_eq!(receipt.readiness, ReadinessLifecycle::ReadyMaterial);
        assert!(matches!(
            receipt.task_binding,
            TaskBindingState::CurrentTaskContract { .. }
        ));
        assert_eq!(receipt.governing_source_generation, 1);
        assert_eq!(
            receipt.governing_source_set_ref,
            "governing-source-set:scope:a:1"
        );
    }
}
