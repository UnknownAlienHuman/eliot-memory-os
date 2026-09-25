//! Governing-source admission and task intake (issue #1791).
//!
//! Caller seam for the inputs that make scope/task admission meaningful:
//!
//! - who builds source candidates: the bootstrap-scanner/attach caller, only
//!   from an authenticated resolution receipt
//!   ([`GoverningSourceCandidate::from_authenticated_root`], which derives the
//!   root identity from the receipt and binds the candidate scope/generation
//!   to the authenticated selection) or from a read admitted by a valid
//!   [`DiscoveryReadLease`](super::DiscoveryReadLease)
//!   ([`GoverningSourceCandidate::from_discovery_lease`]). File names, recency,
//!   locations, model summaries, and bare caller-asserted identity strings
//!   never produce candidates;
//! - who promotes a candidate to `admitted`: an applicable authority/contract
//!   claim attached to the candidate and resolved against the admission
//!   request by [`admit_governing_sources`]. A Human claim applies only when
//!   it names the request's required owner; a delegation claim applies only
//!   when the delegated task names a proven current binding carried by the
//!   request; a contract claim applies only when the contract is listed as
//!   proven by the request. Inapplicable claims fail the request with
//!   [`WorkScopeError::TaskAuthorityDenied`](super::WorkScopeError::TaskAuthorityDenied)
//!   instead of promoting. Precedence between roles applies only when the
//!   project declared it with an applicable authority
//!   ([`PrecedenceDeclaration`]); there is no hard-coded
//!   Architecture-over-Implementation default, and a precedence-admitted
//!   winner carries the declaration authority as its basis;
//! - who consumes conflicts: [`admit_governing_sources`] returns a
//!   [`SourceConflictSet`] with the required owner instead of selecting a
//!   winner. Same-handle digest divergence with no agreed applicable claim or
//!   applicable declared precedence stays conflicted (there is no ordering
//!   oracle to call it version drift), and every preserved quarantined,
//!   provider-modified, or provider-conflicted record joins the conflict set
//!   and the unresolved references, so [`source_readiness`] (called by
//!   [`ColdStartController::compile`](super::ColdStartController)) fails
//!   compilation for conflicted sets and no Material effect is eligible;
//! - who submits tasks: [`TaskIntakeCandidate`] keeps origin provenance and
//!   missing fields; promotion to a current binding requires the decision
//!   owner directly or a delegation proven by presenting the existing current
//!   binding the delegation names ([`TaskIntakeCandidate::promote`]), while
//!   [`TaskIntakeCandidate::admit_exploratory`] offers a bounded exploratory
//!   binding that can never authorize Material effects. Missing task data is
//!   answered with [`task_selection_required`], the `TASK_SELECTION_REQUIRED`
//!   shape with a minimal valid intake example. The self-reported
//!   `missing_fields` list is never trusted: completeness is recomputed from
//!   the fields and a mismatch fails validation;
//! - how long admission lasts: the fence and expiry live on
//!   [`GoverningSourceAdmission`] together with the required owner, coverage,
//!   and applied precedences; [`GoverningSourceAdmission::is_live`] (and the
//!   [`GoverningSourceAdmission::require_live`] gate) is enforced by the
//!   Governor admission entry before an admission is retained or consumed.

use super::{
    DiscoveryRead, DiscoveryReadLease, GoverningSource, GoverningSourceRole, GoverningSourceSet,
    ResolutionAuthentication, SourceStatus, TaskBindingInput, TaskBindingState, WorkScopeError,
    WorkScopeResolutionReceipt, counter, digest, text, unique,
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
/// Precedence exists only when declared here with an applicable authority.
/// In particular there is no implicit Architecture-over-Implementation rule:
/// that pair applies only when a declaration names it for the scope, and the
/// declaration authority is what a precedence-admitted winner carries as its
/// basis.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrecedenceDeclaration {
    pub scope_ref: String,
    pub higher: GoverningSourceRole,
    pub lower: GoverningSourceRole,
    pub declared_by: String,
    pub authority: AuthorityBasis,
}

impl PrecedenceDeclaration {
    /// Validates the declaration without applying it to any candidate.
    ///
    /// Validation never applies the declaration: admission additionally
    /// requires the authority to be applicable to the request (the required
    /// owner, a proven delegation, or a proven contract), and inapplicable
    /// declarations resolve nothing.
    ///
    /// # Errors
    ///
    /// Returns an error when references are invalid, the authority is
    /// invalid, or both roles are identical.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.scope_ref, "precedence.scope_ref")?;
        text(&self.declared_by, "precedence.declared_by")?;
        self.authority.validate()?;
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
    /// The caller presents the authenticated resolution receipt, never a bare
    /// identity string: the receipt must validate with
    /// [`ResolutionAuthentication::Authenticated`], the candidate scope and
    /// generation must equal the authenticated selection, and the root
    /// identity is derived from the receipt. Anything else fails closed
    /// without producing a candidate.
    ///
    /// # Errors
    ///
    /// Returns an error when the receipt is not authenticated, names a
    /// different scope or generation, or when digest, generation, assurance,
    /// domain or claim evidence is invalid.
    pub fn from_authenticated_root(
        params: NewSourceCandidate,
        receipt: &WorkScopeResolutionReceipt,
    ) -> Result<Self, WorkScopeError> {
        receipt.validate()?;
        if receipt.authentication != ResolutionAuthentication::Authenticated {
            return Err(WorkScopeError::BindingReceiptMismatch);
        }
        if params.applicable_scope_ref != receipt.selected.scope_ref
            || params.applicable_generation != receipt.selected.generation
        {
            return Err(WorkScopeError::SourceSetMismatch);
        }
        Self::build(
            params,
            SourceCandidateOrigin::AuthenticatedRoot {
                root_identity: receipt.selected.root_identity.clone(),
            },
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

/// Proven contract the admission request may resolve contract claims against.
///
/// A contract claim is applicable only when the request carries the contract
/// here with the resolver that proved it; the admission crate holds no
/// contract registry, so existence is proven by the production caller that
/// built the request from live governor state, never by the claimant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProvenContract {
    pub contract_ref: String,
    pub proven_by_ref: String,
}

impl ProvenContract {
    /// Validates the proven contract without granting anything.
    ///
    /// # Errors
    ///
    /// Returns an error when a reference is blank or carries control characters.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.contract_ref, "proven_contract.contract_ref")?;
        text(&self.proven_by_ref, "proven_contract.proven_by_ref")
    }
}

/// Input to [`admit_governing_sources`].
///
/// Delegation claims resolve against `proven_current_bindings`: a delegation
/// is applicable only when it names the task of a current binding carried
/// here (the production caller populates these from live governor task
/// state). Contract claims resolve against `proven_contracts`. Human claims
/// resolve against `required_owner_ref`. Claims that resolve against none of
/// these fail the request; they never promote.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceAdmissionRequest {
    pub scope_ref: String,
    pub generation: u64,
    pub candidates: Vec<GoverningSourceCandidate>,
    pub precedences: Vec<PrecedenceDeclaration>,
    pub required_owner_ref: String,
    pub proven_current_bindings: Vec<TaskBindingState>,
    pub proven_contracts: Vec<ProvenContract>,
    pub absence_reason_ref: Option<String>,
    pub state_fence: StateFence,
    pub expires_at: u64,
}

impl SourceAdmissionRequest {
    /// Records one proven contract without granting anything.
    ///
    /// Lets callers that cannot name [`ProvenContract`] (it is not re-exported
    /// past this module) still resolve contract claims from plain references.
    ///
    /// # Errors
    ///
    /// Returns an error when a reference is blank, carries control characters,
    /// or duplicates an already proven contract.
    pub fn with_proven_contract(
        mut self,
        contract_ref: String,
        proven_by_ref: String,
    ) -> Result<Self, WorkScopeError> {
        let proven = ProvenContract {
            contract_ref,
            proven_by_ref,
        };
        proven.validate()?;
        if self
            .proven_contracts
            .iter()
            .any(|existing| existing.contract_ref == proven.contract_ref)
        {
            return Err(WorkScopeError::DuplicateReference {
                field: "proven_contract.contract_ref",
            });
        }
        self.proven_contracts.push(proven);
        Ok(self)
    }
}

/// Outcome of [`admit_governing_sources`].
///
/// `admitted` holds only `admitted` records and is the sole input eligible
/// for readiness; `preserved` keeps every non-admitted record under its
/// honest status; `conflict` names the clash and the owner who must resolve it.
/// `required_owner_ref` is the owner every Human claim resolved against, so
/// the fence-carrying result always names its authority next to the fence and
/// expiry instead of leaving them on a separate unreadable result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoverningSourceAdmission {
    pub admitted: GoverningSourceSet,
    pub preserved: Vec<GoverningSource>,
    pub conflict: Option<SourceConflictSet>,
    pub coverage: SourceCoverage,
    pub required_owner_ref: String,
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

    /// Fails closed when the admission fence is no longer live at `now`.
    ///
    /// Production callers enforce this before retaining or consuming an
    /// admission, so an expired fence can never stay eligible.
    ///
    /// # Errors
    ///
    /// Returns [`WorkScopeError::SourceSetMismatch`] when `now` is past
    /// `expires_at`.
    pub fn require_live(&self, now: u64) -> Result<(), WorkScopeError> {
        if self.is_live(now) {
            Ok(())
        } else {
            Err(WorkScopeError::SourceSetMismatch)
        }
    }

    /// Fails closed when any admitted record lacks an authority basis.
    ///
    /// Admission constructs admitted records only through an applicable claim
    /// or an applicable declared precedence, so this always holds; the gate
    /// exists so production callers (and any future readiness check) fail
    /// closed instead of trusting the invariant silently.
    ///
    /// # Errors
    ///
    /// Returns [`WorkScopeError::TaskAuthorityDenied`] when an admitted record
    /// carries no authority basis.
    pub fn require_admitted_authority(&self) -> Result<(), WorkScopeError> {
        if self
            .admitted
            .sources
            .iter()
            .all(|source| source.authority_basis.is_some())
        {
            Ok(())
        } else {
            Err(WorkScopeError::TaskAuthorityDenied)
        }
    }

    /// Validates the admission shape without re-resolving any authority.
    ///
    /// # Errors
    ///
    /// Returns an error when the required owner is invalid, the fence or
    /// expiry is malformed, a declaration is malformed, or the conflict set
    /// is malformed.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.required_owner_ref, "admission.required_owner_ref")?;
        counter(self.expires_at, "admission.expires_at")?;
        self.state_fence
            .validate()
            .map_err(|_| WorkScopeError::InvalidStateFence)?;
        for precedence in &self.applied_precedences {
            precedence.validate()?;
        }
        if let Some(conflict) = &self.conflict {
            conflict.validate()?;
            if conflict.required_owner_ref != self.required_owner_ref {
                return Err(WorkScopeError::SourceSetMismatch);
            }
        }
        Ok(())
    }
}

/// Borrowed admission scope used to resolve claim and declaration authority.
///
/// Built from the request before candidates move into triage, so resolution
/// always judges applicability against the same request the caller signed.
struct AdmissionContext<'a> {
    scope_ref: &'a str,
    required_owner_ref: &'a str,
    precedences: &'a [PrecedenceDeclaration],
    proven_current_bindings: &'a [TaskBindingState],
    proven_contracts: &'a [ProvenContract],
}

/// Returns whether a claim is applicable to an admission request.
///
/// A Human claim applies only when it names the request's required owner; a
/// delegation claim applies only when it names the task of a proven current
/// binding carried by the request; a contract claim applies only when the
/// request lists the contract as proven. Anything else promotes nothing.
#[must_use]
fn claim_is_applicable(claim: &AuthorityBasis, context: &AdmissionContext<'_>) -> bool {
    match claim {
        AuthorityBasis::HumanOwner { owner_ref } => {
            owner_ref.as_str() == context.required_owner_ref
        }
        AuthorityBasis::DelegatedTaskBinding { task_ref, .. } => context
            .proven_current_bindings
            .iter()
            .any(|binding| match binding {
                TaskBindingState::CurrentTaskContract {
                    task_ref: proven_ref,
                    ..
                } => proven_ref == task_ref,
                TaskBindingState::None_
                | TaskBindingState::Exploratory { .. }
                | TaskBindingState::Ambiguous { .. }
                | TaskBindingState::Stale { .. } => false,
            }),
        AuthorityBasis::ProjectContract { contract_ref } => context
            .proven_contracts
            .iter()
            .any(|proven| &proven.contract_ref == contract_ref),
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
    for proven in &request.proven_contracts {
        proven.validate()?;
    }
    unique(
        request
            .proven_contracts
            .iter()
            .map(|proven| &proven.contract_ref),
        "proven_contract.contract_ref",
    )?;
    for binding in &request.proven_current_bindings {
        match binding {
            TaskBindingState::CurrentTaskContract {
                task_ref,
                task_revision,
                acceptance_digest,
            } => {
                text(task_ref, "proven_binding.task_ref")?;
                counter(*task_revision, "proven_binding.task_revision")?;
                text(acceptance_digest, "proven_binding.acceptance_digest")?;
            }
            TaskBindingState::None_
            | TaskBindingState::Exploratory { .. }
            | TaskBindingState::Ambiguous { .. }
            | TaskBindingState::Stale { .. } => {
                return Err(WorkScopeError::SourceSetMismatch);
            }
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
/// One digest admits through its attached applicable authority claim or stays
/// a candidate; the admitted record is deterministic (lowest role among the
/// applicable-claimed candidates) instead of first-in-request-order. Several
/// digests resolve only through a single agreed applicable owner claim or one
/// applicable project-declared precedence, and the precedence winner carries
/// the declaration authority as its basis; disagreeing claims, inapplicable
/// claims, and undeclared clashes stay conflicted or fail the request. No
/// branch selects a winner from filename, recency, location or model output.
///
/// # Errors
///
/// Returns [`WorkScopeError::TaskAuthorityDenied`] when any candidate carries
/// a claim that is not applicable to the request.
fn resolve_group(
    group: Vec<GoverningSourceCandidate>,
    context: &AdmissionContext<'_>,
) -> Result<GroupResolution, WorkScopeError> {
    if group.is_empty() {
        return Ok(GroupResolution {
            admitted: Vec::new(),
            preserved: Vec::new(),
            conflicted: false,
            applied: Vec::new(),
        });
    }
    for candidate in &group {
        if let Some(claim) = &candidate.claim
            && !claim_is_applicable(claim, context)
        {
            return Err(WorkScopeError::TaskAuthorityDenied);
        }
    }
    let mut ordered = group;
    ordered.sort_by(|left, right| {
        left.role
            .cmp(&right.role)
            .then(left.digest.cmp(&right.digest))
    });
    let mut digests: BTreeSet<&str> = BTreeSet::new();
    for candidate in &ordered {
        digests.insert(candidate.digest.as_str());
    }
    if digests.len() == 1 {
        let mut admitted = Vec::new();
        let mut preserved = Vec::new();
        for candidate in ordered {
            if admitted.is_empty() && candidate.claim.is_some() {
                admitted.push(candidate.into_record(SourceStatus::Admitted));
            } else {
                preserved.push(candidate.into_record(SourceStatus::Candidate));
            }
        }
        return Ok(GroupResolution {
            admitted,
            preserved,
            conflicted: false,
            applied: Vec::new(),
        });
    }
    let mut claimed: BTreeSet<String> = BTreeSet::new();
    for candidate in &ordered {
        if candidate.claim.is_some() {
            claimed.insert(candidate.digest.clone());
        }
    }
    if claimed.len() > 1 {
        return Ok(conflicted_group(ordered));
    }
    if let Some(winner_digest) = claimed.iter().next().cloned() {
        let mut admitted = Vec::new();
        let mut preserved = Vec::new();
        for candidate in ordered {
            if candidate.digest == winner_digest {
                admitted.push(candidate.into_record(SourceStatus::Admitted));
            } else {
                preserved.push(candidate.into_record(SourceStatus::Superseded));
            }
        }
        return Ok(GroupResolution {
            admitted,
            preserved,
            conflicted: false,
            applied: Vec::new(),
        });
    }
    if let Some((winner, applied)) = precedence_winner(&ordered, context) {
        let winner_digest = winner.digest.clone();
        let winner_authority = applied
            .first()
            .map(|declaration| declaration.authority.clone());
        let mut admitted = Vec::new();
        let mut preserved = Vec::new();
        for candidate in ordered {
            if candidate.digest == winner_digest {
                let mut record = candidate.into_record(SourceStatus::Admitted);
                if record.authority_basis.is_none() {
                    record.authority_basis.clone_from(&winner_authority);
                }
                admitted.push(record);
            } else {
                preserved.push(candidate.into_record(SourceStatus::Superseded));
            }
        }
        return Ok(GroupResolution {
            admitted,
            preserved,
            conflicted: false,
            applied,
        });
    }
    Ok(conflicted_group(ordered))
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
/// authority/contract claim resolved against the request (required owner,
/// proven current bindings, proven contracts). Incompatible documents (one
/// handle, several digests) resolve only through a single agreed applicable
/// claim or an applicable project-declared precedence, and the precedence
/// winner carries the declaration authority; disagreeing or inapplicable
/// claims and undeclared clashes become a [`SourceConflictSet`] with the
/// required owner (inapplicable claims fail the request outright), and every
/// involved record is preserved as `conflicted`. Stale, quarantined, or
/// provider-flagged evidence is preserved under its honest status and its
/// handle joins the conflict set and the unresolved references, so readiness
/// observes it instead of losing it in the preserved list. No branch selects
/// a winner from filename, recency, location or model output.
///
/// # Errors
///
/// Returns an error when scope, generation, owner, fence, expiry, precedence,
/// proven-binding, or candidate evidence is malformed, when a candidate or
/// precedence names a different scope/generation, when a claim is not
/// applicable to the request, or when no candidates exist without an explicit
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
            required_owner_ref: request.required_owner_ref.clone(),
            applied_precedences: Vec::new(),
            state_fence: request.state_fence,
            expires_at: request.expires_at,
        });
    }

    let context = AdmissionContext {
        scope_ref: &request.scope_ref,
        required_owner_ref: &request.required_owner_ref,
        precedences: &request.precedences,
        proven_current_bindings: &request.proven_current_bindings,
        proven_contracts: &request.proven_contracts,
    };
    let (groups, mut preserved) = triage_candidates(request.candidates);
    let mut admitted: Vec<GoverningSource> = Vec::new();
    let mut conflicting: BTreeSet<String> = BTreeSet::new();
    let mut applied_precedences: Vec<PrecedenceDeclaration> = Vec::new();
    for (source_ref, group) in groups {
        let resolution = resolve_group(group, &context)?;
        if resolution.conflicted {
            conflicting.insert(source_ref.clone());
        }
        admitted.extend(resolution.admitted);
        preserved.extend(resolution.preserved);
        applied_precedences.extend(resolution.applied);
    }
    for record in &preserved {
        if record.status == SourceStatus::Conflicted {
            conflicting.insert(record.source_ref.clone());
        }
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
    let admission = GoverningSourceAdmission {
        admitted: admitted_set,
        preserved,
        conflict,
        coverage,
        required_owner_ref: request.required_owner_ref,
        applied_precedences,
        state_fence: request.state_fence,
        expires_at: request.expires_at,
    };
    admission.validate()?;
    admission.require_admitted_authority()?;
    Ok(admission)
}

/// Finds the winning digest through project-declared role precedence.
///
/// Returns a winner only when the group spans at least two roles, exactly one
/// role beats-or-ties every declared comparison it takes part in through an
/// applicable declaration authority, loses none, carries exactly one digest,
/// and at least one applicable declaration names the winner as higher. The
/// returned declarations are the applicable ones that order the winner above
/// a present lower role, sorted for determinism. Within-role divergence,
/// contradictory declarations, inapplicable declarations, and winner-less
/// single-digest roles never resolve silently.
///
/// Only declarations whose authority is applicable to the request participate:
/// a declaration anyone can utter with a bare name promotes nothing.
fn precedence_winner(
    group: &[GoverningSourceCandidate],
    context: &AdmissionContext<'_>,
) -> Option<(GoverningSourceCandidate, Vec<PrecedenceDeclaration>)> {
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
    let applicable: Vec<&PrecedenceDeclaration> = context
        .precedences
        .iter()
        .filter(|declaration| {
            declaration.applies_to(context.scope_ref, declaration.higher, declaration.lower)
                && claim_is_applicable(&declaration.authority, context)
        })
        .collect();
    let mut beaten: BTreeSet<GoverningSourceRole> = BTreeSet::new();
    for declaration in &applicable {
        let higher = roles.get(&declaration.higher);
        let lower = roles.get(&declaration.lower);
        if let (Some(higher), Some(lower)) = (higher, lower)
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
    let winner_role = unbeaten[0];
    let mut applied: Vec<PrecedenceDeclaration> = applicable
        .into_iter()
        .filter(|declaration| {
            declaration.higher == winner_role && roles.contains_key(&declaration.lower)
        })
        .cloned()
        .collect();
    if applied.is_empty() {
        return None;
    }
    applied.sort_by(|left, right| {
        left.higher
            .cmp(&right.higher)
            .then(left.lower.cmp(&right.lower))
            .then(left.declared_by.cmp(&right.declared_by))
    });
    group
        .iter()
        .find(|candidate| candidate.role == winner_role)
        .cloned()
        .map(|winner| (winner, applied))
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

    /// Returns the missing goal, acceptance, owner, and scope fields computed
    /// from the actual field values.
    ///
    /// This is the only completeness signal promotion trusts: the stored
    /// `missing_fields` list is provenance metadata, never authority.
    #[must_use]
    pub fn computed_missing_fields(&self) -> Vec<String> {
        let mut missing = Vec::new();
        if self.goal.is_none() {
            missing.push("goal".to_owned());
        }
        if self.acceptance_digest.is_none() {
            missing.push("acceptance_digest".to_owned());
        }
        if self.decision_owner_ref.is_none() {
            missing.push("decision_owner_ref".to_owned());
        }
        if self.proposed_scope_ref.is_none() {
            missing.push("proposed_scope_ref".to_owned());
        }
        missing
    }

    /// Returns whether goal, acceptance, owner and scope are all present.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.computed_missing_fields().is_empty()
    }

    /// Validates the intake candidate, including its self-reported missing list.
    ///
    /// A deserialized candidate whose stored `missing_fields` disagrees with
    /// the recomputed list is tampered input and fails closed here, so forged
    /// completeness can never bypass the owner gate through promotion.
    ///
    /// # Errors
    ///
    /// Returns an error when a supplied reference, digest, constraint, or the
    /// stored missing-field list is malformed, duplicated, or inconsistent
    /// with the actual fields.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.intake_ref, "intake.intake_ref")?;
        text(
            &self.proposer_principal_ref,
            "intake.proposer_principal_ref",
        )?;
        text(&self.proposer_session_ref, "intake.proposer_session_ref")?;
        text(&self.route_ref, "intake.route_ref")?;
        if let Some(goal) = &self.goal {
            text(goal, "intake.goal")?;
        }
        if let Some(acceptance) = &self.acceptance_digest {
            text(acceptance, "intake.acceptance_digest")?;
        }
        unique(self.constraints.iter(), "intake.constraints")?;
        for constraint in &self.constraints {
            text(constraint, "intake.constraints")?;
        }
        if let Some(scope) = &self.proposed_scope_ref {
            text(scope, "intake.proposed_scope_ref")?;
        }
        unique(
            self.proposed_source_digests.iter(),
            "intake.proposed_source_digests",
        )?;
        for handle_digest in &self.proposed_source_digests {
            digest(handle_digest, "intake.proposed_source_digests")?;
        }
        if let Some(owner) = &self.decision_owner_ref {
            text(owner, "intake.decision_owner_ref")?;
        }
        if let Some(controller) = &self.task_controller_ref {
            text(controller, "intake.task_controller_ref")?;
        }
        if self.missing_fields != self.computed_missing_fields() {
            return Err(WorkScopeError::InvalidSourceEvidence);
        }
        Ok(())
    }

    /// Promotes the intake to a current-task binding input.
    ///
    /// Only the matching Human decision owner promotes directly. A delegated
    /// binding promotes only when the caller presents the existing current
    /// binding the delegation names: `parent` must be the current task
    /// contract whose task matches the delegation, which proves the binding
    /// the delegation claims actually exists instead of trusting a nonblank
    /// reference. A project contract alone cannot promote, and host-visible
    /// prompt text never authorizes itself. The admitting owner assigns the
    /// task revision, so promotion invents no contract identity. Completeness
    /// is recomputed from the fields; a forged `missing_fields` list fails
    /// validation before any authority check.
    ///
    /// # Errors
    ///
    /// Returns [`WorkScopeError::TaskAuthorityDenied`] when the basis is not
    /// the decision owner or a proven delegated binding, an error when the
    /// intake is incomplete, tampered, or the revision is zero.
    pub fn promote(
        &self,
        basis: &AuthorityBasis,
        parent: &TaskBindingState,
        task_revision: u64,
    ) -> Result<TaskBindingInput, WorkScopeError> {
        self.validate()?;
        basis.validate()?;
        match basis {
            AuthorityBasis::HumanOwner { owner_ref }
                if self.decision_owner_ref.as_deref() == Some(owner_ref.as_str()) => {}
            AuthorityBasis::DelegatedTaskBinding { task_ref, .. } => {
                let TaskBindingState::CurrentTaskContract {
                    task_ref: parent_ref,
                    ..
                } = parent
                else {
                    return Err(WorkScopeError::TaskAuthorityDenied);
                };
                if parent_ref != task_ref {
                    return Err(WorkScopeError::TaskAuthorityDenied);
                }
            }
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
