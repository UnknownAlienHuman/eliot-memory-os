//! Lease/epoch-bound Problem and attention ownership (I13.8, I13.9).
//!
//! This module owns the *semantics* of ownership, not its issuance. I13.9 says
//! "Problem ownership is lease/epoch-bound" and that when the owner "Session,
//! agent, Module or Human delegation disappears, the Problem remains open, the
//! old owner is fenced, and ownership becomes `unassigned` until reassigned to
//! an eligible successor or escalated through Critical Attention". Two rules
//! follow, and both are enforced here rather than left to callers:
//!
//! 1. **Assignment eligibility comes from an externally issued lease.** An
//!    [`OwnerLeaseGrant`] is what the lease owner mints; a caller that only has
//!    a principal string can never reach [`AuthenticatedOwnerLease`], because
//!    that type's fields are private and its only construction path re-derives
//!    the lease owner's own durable commitment over the exact grant. There is
//!    deliberately no `unassigned` principal: an unowned record is
//!    [`Ownership::Unassigned`] carrying who was fenced, why, and the obligation
//!    that is now outstanding.
//!
//! 2. **The lease owner, not this crate, decides what a lease is.** The trust
//!    boundary is [`OwnerLeaseIssuer`]: an implementation registered by the
//!    lease owner at composition time returns the commitment it durably holds
//!    for a grant, or nothing. This crate re-derives the expected commitment
//!    itself and compares, so a grant that the issuer does not hold cannot be
//!    authenticated, and no `Problem`/`CriticalAttention` ever holds an issuer.
//!    This is the same boundary shape as the runtime-contracts supervision
//!    lease verifier/signer pair; it deliberately does not claim to verify the
//!    issuer's own key material, which is the issuer's responsibility.
//!
//! A delayed expiry for an already-renewed lease cannot unassign its successor:
//! the loss event carries the exact [`LeaseIdentity`] it observed dead, and
//! [`Ownership::record_loss`] refuses when the record's retained identity has
//! moved on. Loss never implies resolution — [`Ownership::Unassigned`] is a
//! live obligation, not a terminal state.

use eliot_contracts::{EpochId, StateFence, canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ArtifactId, OwnerRef, ProblemError};

/// Domain separator for the ownership-lease commitment.
const OWNER_LEASE_COMMITMENT_DOMAIN: &str = "eliot.problem.owner-lease.v1";

/// Closed I13.8 default-owner routes.
///
/// These are *roles*, not names: a route says which role is accountable, while
/// eligibility to actually hold the lease is established by
/// [`OwnerLeaseIssuer`]. A record with no eligible actor stays unassigned and
/// escalates through the admitted Human/critical-attention route rather than
/// being handed to a hardcoded name.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OwnerRoute {
    /// Task issues go to the Task Controller.
    TaskController,
    /// Security and integrity issues go to the System Owner / Recovery Principal.
    SystemOwnerRecoveryPrincipal,
    /// Architecture gaps go to the Architecture Owner.
    ArchitectureOwner,
    /// Verifier/evidence gaps go to the `WorkScope` Owner or Task Controller.
    WorkScopeOwnerOrTaskController,
    /// Module health goes to the module owner or Doctor.
    ModuleOwnerOrDoctor,
    /// Budget issues go to the Requester/System Owner according to policy.
    RequesterOrSystemOwner,
}

impl OwnerRoute {
    /// The I13.8 default route for one Problem class.
    ///
    /// The mapping is fixed by the document, so the route is derived from the
    /// record's own class rather than chosen by the caller raising a loss.
    #[must_use]
    pub const fn for_class(class: crate::ProblemClass) -> Self {
        match class {
            crate::ProblemClass::Operational
            | crate::ProblemClass::Integration
            | crate::ProblemClass::Cognitive
            | crate::ProblemClass::DataQuality => Self::TaskController,
            crate::ProblemClass::Security => Self::SystemOwnerRecoveryPrincipal,
            crate::ProblemClass::Cost => Self::RequesterOrSystemOwner,
        }
    }
}

/// Why an ownership lease stopped being current.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OwnerLossReason {
    /// The lease reached its expiry.
    LeaseExpired,
    /// The lease was revoked by its issuing authority.
    LeaseRevoked,
    /// The owner's Human delegation was withdrawn.
    DelegationWithdrawn,
    /// The owner Session disappeared.
    OwnerSessionLost,
    /// The owning Module or its owner disappeared.
    ModuleOwnerLost,
    /// A pre-existing record carried no ownership lease at all.
    ///
    /// The absence is named rather than back-filled with a plausible lease: a
    /// legacy record without a lease is migrated to unassigned ownership and
    /// the escalation obligation, never to a synthesized live lease.
    LegacyRecordWithoutLease,
}

/// The exact lease identity an owner-loss event observed.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseIdentity {
    /// Stable lease identity the lease owner issued.
    pub lease_id: String,
    /// The lease owner's own durable commitment over the issued grant.
    pub commitment: String,
    /// The ownership epoch the lease was issued under.
    pub ownership_epoch: u64,
}

impl LeaseIdentity {
    /// Whether this is exactly the lease identity named by `observed`.
    ///
    /// Exact over the whole tuple — lease id, commitment and ownership epoch —
    /// not just the identity string. A renewal keeps the lease id but changes
    /// the commitment and epoch, so this is what stops a delayed expiry for an
    /// already-renewed lease from unassigning its successor: the observed
    /// identity is no longer the one the record retains.
    #[must_use]
    pub fn is_exactly(&self, observed: &LeaseIdentity) -> bool {
        self == observed
    }

    /// Validates a lease identity and its commitment shape.
    pub fn validate(&self) -> Result<(), ProblemError> {
        crate::text(&self.lease_id, "lease_id")?;
        if !is_commitment(&self.commitment) {
            return Err(ProblemError::InvalidField {
                field: "lease.commitment",
                reason: "must be a lowercase SHA-256 digest",
            });
        }
        if self.ownership_epoch == 0 {
            return Err(ProblemError::InvalidField {
                field: "lease.ownership_epoch",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }
}

/// The ownership lease grant the lease owner mints for one obligation.
///
/// This is issuer input, not caller input: nothing in this crate accepts a
/// grant as proof of ownership on its own. It must be authenticated by the
/// lease owner through [`OwnerLeaseIssuer`] before any record accepts it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerLeaseGrant {
    /// Stable lease identity the lease owner issued.
    pub lease_id: String,
    /// The exact principal the lease owner named as holder.
    pub holder: OwnerRef,
    /// The authority epoch the lease was issued under.
    pub authority_epoch: EpochId,
    /// The state fence the lease is bound to.
    pub state_fence: StateFence,
    /// The ownership epoch this lease grants. Must be greater than the epoch
    /// the record currently holds, so a renewal is never a reuse.
    pub ownership_epoch: u64,
    /// Inclusive issue time in Unix milliseconds.
    pub issued_at_ms: u64,
    /// Exclusive expiry time in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl OwnerLeaseGrant {
    /// Validates the grant's own shape and internal bindings.
    ///
    /// A zero epoch, a reversed validity window, a fence whose authority is not
    /// the lease's epoch, or a non-fence epoch all refuse before the grant ever
    /// reaches the issuer.
    pub fn validate(&self) -> Result<(), ProblemError> {
        crate::text(&self.lease_id, "lease_id")?;
        self.holder.validate()?;
        crate::fence(&self.state_fence)?;
        if self.ownership_epoch == 0 {
            return Err(ProblemError::InvalidField {
                field: "lease.ownership_epoch",
                reason: "must be non-zero",
            });
        }
        if self.issued_at_ms == 0 || self.expires_at_ms <= self.issued_at_ms {
            return Err(ProblemError::InvalidField {
                field: "lease.validity_window",
                reason: "must be a positive ordered interval",
            });
        }
        if !self
            .state_fence
            .authority_epoch
            .is_same_authority(&self.authority_epoch)
        {
            return Err(ProblemError::InvalidField {
                field: "lease.authority_epoch",
                reason: "must be the same authority as the bound state fence",
            });
        }
        Ok(())
    }

    /// The deterministic commitment this crate re-derives for this grant.
    ///
    /// The lease owner stores this over the same domain-separated bytes, so
    /// equality is a comparison against owner-held state rather than against
    /// anything the caller restates.
    pub fn expected_commitment(&self) -> Result<String, ProblemError> {
        self.validate()?;
        let bytes = canonical_json_bytes(&(
            OWNER_LEASE_COMMITMENT_DOMAIN,
            &self.lease_id,
            &self.holder,
            &self.authority_epoch,
            &self.state_fence,
            self.ownership_epoch,
            self.issued_at_ms,
            self.expires_at_ms,
        ))
        .map_err(|_error| ProblemError::InvalidField {
            field: "lease.commitment",
            reason: "commitment could not be canonicalized",
        })?;
        Ok(sha256_hex(&bytes))
    }

    /// The identity of this grant once it has been authenticated.
    pub fn identity(&self, commitment: String) -> Result<LeaseIdentity, ProblemError> {
        let identity = LeaseIdentity {
            lease_id: self.lease_id.clone(),
            commitment,
            ownership_epoch: self.ownership_epoch,
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Whether the lease is inside its own validity window at `now_ms`.
    #[must_use]
    pub const fn is_current_at(&self, now_ms: u64) -> bool {
        self.issued_at_ms <= now_ms && now_ms < self.expires_at_ms
    }
}

/// An ownership lease authenticated against the lease owner's own state.
///
/// The fields are private: there is no public constructor, so the only way to
/// obtain one is through an [`OwnerLeaseAuthenticator`], which re-derives this
/// crate's expected commitment and compares it with what the
/// [`OwnerLeaseIssuer`] durably holds. A caller holding only a principal
/// string cannot fabricate one, which is the whole point: naming yourself the
/// owner is not ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedOwnerLease {
    grant: OwnerLeaseGrant,
    identity: LeaseIdentity,
}

impl AuthenticatedOwnerLease {
    /// The authenticated grant.
    #[must_use]
    pub const fn grant(&self) -> &OwnerLeaseGrant {
        &self.grant
    }

    /// The authenticated lease identity.
    #[must_use]
    pub const fn identity(&self) -> &LeaseIdentity {
        &self.identity
    }

    /// The holder the lease owner named.
    #[must_use]
    pub const fn holder(&self) -> &OwnerRef {
        &self.grant.holder
    }

    /// The ownership epoch this lease grants.
    #[must_use]
    pub const fn ownership_epoch(&self) -> u64 {
        self.grant.ownership_epoch
    }

    /// Whether this authenticated lease is the exact one named by `observed`.
    #[must_use]
    pub fn is_exactly(&self, observed: &LeaseIdentity) -> bool {
        self.identity.is_exactly(observed)
    }

    /// Whether the lease is inside its validity window at `now_ms`.
    #[must_use]
    pub const fn is_current_at(&self, now_ms: u64) -> bool {
        self.grant.is_current_at(now_ms)
    }

    /// Whether the lease is bound to this exact state fence.
    #[must_use]
    pub fn is_bound_to(&self, fence: &StateFence) -> bool {
        self.grant.state_fence == *fence
    }

    /// Authenticates one grant against the lease owner's own state.
    ///
    /// This is the only construction path for [`AuthenticatedOwnerLease`].
    /// The grant is validated first, the expected commitment is re-derived here
    /// rather than trusted from the issuer, and the issuer must return exactly
    /// that commitment. An issuer that does not hold the lease returns nothing
    /// and the grant is refused.
    pub fn authenticate(
        grant: &OwnerLeaseGrant,
        issuer: &dyn OwnerLeaseIssuer,
    ) -> Result<Self, ProblemError> {
        let expected = grant.expected_commitment()?;
        let held = issuer
            .commitment_for(grant)
            .ok_or(ProblemError::OwnerLeaseMismatch)?;
        if held != expected {
            return Err(ProblemError::OwnerLeaseMismatch);
        }
        Ok(Self {
            identity: grant.identity(expected)?,
            grant: grant.clone(),
        })
    }
}

/// The lease owner's own view of the ownership leases it holds.
///
/// The implementation lives with the lease owner, not here: this crate never
/// mints, renews, or stores a lease. Returning `None` for a grant the issuer
/// does not hold is the refusal that keeps a self-named owner out.
pub trait OwnerLeaseIssuer {
    /// The durable commitment this issuer holds for `grant`, or `None` when it
    /// holds no such lease.
    fn commitment_for(&self, grant: &OwnerLeaseGrant) -> Option<String>;
}

/// The visible obligation an owner loss leaves outstanding.
///
/// I13.9: an unassigned Problem is "not resolved, accepted risk or safe to
/// discard". This obligation is the visible, durable form of that, and it
/// survives restart because it is retained on the record itself.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipObligation {
    /// Stable obligation identity, derived from the subject and the ownership
    /// epoch it must supersede.
    pub obligation_id: String,
    /// The I13.8 default-owner route accountable for clearing this.
    pub route: OwnerRoute,
    /// The exact lease identity that was lost, or `None` for a legacy record
    /// that never carried a lease.
    pub lost_lease: Option<LeaseIdentity>,
    /// The ownership epoch the record held when the obligation was raised.
    pub ownership_epoch: u64,
    /// The record revision at which the obligation was raised.
    pub raised_at_revision: u64,
}

impl OwnershipObligation {
    /// Validates the obligation's identity, route and epoch.
    pub fn validate(&self) -> Result<(), ProblemError> {
        crate::text(&self.obligation_id, "obligation_id")?;
        if self.ownership_epoch == 0 {
            return Err(ProblemError::InvalidField {
                field: "obligation.ownership_epoch",
                reason: "must be non-zero",
            });
        }
        if self.raised_at_revision == 0 {
            return Err(ProblemError::InvalidField {
                field: "obligation.raised_at_revision",
                reason: "must be non-zero",
            });
        }
        if let Some(lost) = &self.lost_lease {
            lost.validate()?;
        }
        Ok(())
    }
}

/// Ownership of one Problem or attention obligation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum Ownership {
    /// A live lease-backed owner.
    Assigned(AssignedOwnership),
    /// No live owner. The obligation remains outstanding and visible.
    Unassigned(UnassignedOwnership),
}

impl Ownership {
    /// Validates the assigned or unassigned shape and its obligation.
    pub fn validate(&self) -> Result<(), ProblemError> {
        match self {
            Self::Assigned(assigned) => assigned.validate(),
            Self::Unassigned(unassigned) => unassigned.validate(),
        }
    }

    /// Returns the live assignment, or refuses with [`ProblemError::OwnerUnassigned`].
    ///
    /// Every mutating entry goes through this, which is how the fencing works:
    /// a record that lost its owner has no principal any caller can present, so
    /// the lost owner cannot come back and write.
    pub fn assigned(&self) -> Result<&AssignedOwnership, ProblemError> {
        match self {
            Self::Assigned(assigned) => Ok(assigned),
            Self::Unassigned(_) => Err(ProblemError::OwnerUnassigned),
        }
    }

    /// Whether a live owner exists.
    #[must_use]
    pub const fn is_assigned(&self) -> bool {
        matches!(self, Self::Assigned(_))
    }
}

/// A live, lease-backed owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignedOwnership {
    /// The principal the lease owner named.
    pub holder: OwnerRef,
    /// The lease owner's durable identity for the lease that grants ownership.
    pub lease: LeaseIdentity,
    /// The ownership epoch the record currently holds. I13.8 requires a new
    /// Authority Epoch on every reassignment, so this only ever advances.
    pub ownership_epoch: u64,
}

impl AssignedOwnership {
    /// Validates holder, lease identity and epoch.
    pub fn validate(&self) -> Result<(), ProblemError> {
        self.holder.validate()?;
        self.lease.validate()?;
        if self.ownership_epoch != self.lease.ownership_epoch {
            return Err(ProblemError::InvalidField {
                field: "ownership_epoch",
                reason: "must equal the epoch of the retained ownership lease",
            });
        }
        Ok(())
    }
}

/// No live owner, with the loss evidence and the outstanding obligation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnassignedOwnership {
    /// The principal that was fenced when its lease stopped being current.
    pub last_holder: OwnerRef,
    /// Why ownership was lost.
    pub reason: OwnerLossReason,
    /// The exact lease identity observed dead, or `None` for a legacy record
    /// that never carried a lease. A loss event for a different identity is
    /// stale and cannot unassign the current successor.
    pub lost_lease: Option<LeaseIdentity>,
    /// The ownership epoch that was in force when ownership was lost.
    pub ownership_epoch: u64,
    /// Evidence for the loss itself. Required whenever a lease was observed
    /// dead; absent only for the legacy-without-lease case, where there is
    /// nothing to point at and the absence is the finding.
    pub loss_evidence: Vec<ArtifactId>,
    /// The reassignment/escalation obligation this loss left outstanding.
    pub obligation: OwnershipObligation,
}

impl UnassignedOwnership {
    /// Validates the fenced holder, loss evidence and retained obligation.
    pub fn validate(&self) -> Result<(), ProblemError> {
        self.last_holder.validate()?;
        if self.ownership_epoch == 0 {
            return Err(ProblemError::InvalidField {
                field: "ownership_epoch",
                reason: "must be non-zero",
            });
        }
        match (&self.lost_lease, self.reason) {
            (Some(_), OwnerLossReason::LegacyRecordWithoutLease) => {
                return Err(ProblemError::InvalidField {
                    field: "lost_lease",
                    reason: "a legacy record without a lease cannot name a lost lease",
                });
            }
            (None, OwnerLossReason::LegacyRecordWithoutLease) => {}
            (None, _) => {
                return Err(ProblemError::InvalidField {
                    field: "lost_lease",
                    reason: "an owner loss must name the exact lease it observed dead",
                });
            }
            (Some(identity), _) => {
                identity.validate()?;
                crate::nonempty(&self.loss_evidence, "loss_evidence")?;
            }
        }
        let evidence = self
            .loss_evidence
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        crate::unique_text(&evidence, "loss_evidence")?;
        self.obligation.validate()?;
        if self.obligation.ownership_epoch != self.ownership_epoch
            || self.obligation.lost_lease != self.lost_lease
        {
            return Err(ProblemError::InvalidField {
                field: "obligation",
                reason: "must bind the lost lease and epoch it was raised for",
            });
        }
        Ok(())
    }
}

/// One observed owner-loss event from the lease owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerLeaseLoss {
    /// Why the lease stopped being current.
    pub reason: OwnerLossReason,
    /// The exact lease identity the lease owner observed dead.
    pub observed_lease: LeaseIdentity,
    /// Evidence for the loss event.
    pub evidence: Vec<ArtifactId>,
}

impl OwnerLeaseLoss {
    /// Validates the loss reason, observed identity and evidence.
    pub fn validate(&self) -> Result<(), ProblemError> {
        if self.reason == OwnerLossReason::LegacyRecordWithoutLease {
            return Err(ProblemError::InvalidField {
                field: "loss.reason",
                reason: "a legacy-without-lease migration is not an observed loss",
            });
        }
        self.observed_lease.validate()?;
        crate::nonempty(&self.evidence, "loss.evidence")?;
        let evidence = self
            .evidence
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        crate::unique_text(&evidence, "loss.evidence")
    }
}

/// Independent evidence that a resolution condition is satisfied.
///
/// The expected observables live on the record and were fixed when the
/// obligation was raised, not chosen by whoever closes it. Closure therefore
/// requires evidence the closer did not choose alone: every expected
/// observable must be covered, and the verifier must be independent of the
/// owner under the record's current fence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureEvidence {
    /// The competent verifier that read the subject back. It must not be the
    /// record's current owner.
    pub verifier: OwnerRef,
    /// The state fence the readback was taken under. It must be the record's
    /// current fence, so stale verification cannot close a moved record.
    pub verifier_fence: StateFence,
    /// The exact subject/version the verifier read back.
    pub verified_subject: String,
    /// The observables the verifier actually observed. Must cover every
    /// independently expected observable on the record.
    pub verified_observables: Vec<ArtifactId>,
}

impl ClosureEvidence {
    /// Validates the verifier, fence binding, subject and observed set.
    pub fn validate(&self) -> Result<(), ProblemError> {
        self.verifier.validate()?;
        crate::fence(&self.verifier_fence)?;
        crate::text(&self.verified_subject, "verified_subject")?;
        crate::nonempty(&self.verified_observables, "verified_observables")?;
        let observed = self
            .verified_observables
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        crate::unique_text(&observed, "verified_observables")
    }
}

/// An authorized, scoped waiver of a blocking obligation.
///
/// I13.7 names `waiver_authority` as a separate field from the owner, so the
/// owner cannot waive its own obligation: a waiver is a decision by a named
/// authority, bounded in scope and time, and it records its residual risk.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedWaiver {
    /// The authority that granted the waiver. It must equal the record's
    /// recorded `waiver_authority` and must not be the current owner.
    pub authority: OwnerRef,
    /// Stable reference to the admitted waiver decision.
    pub decision_ref: String,
    /// Exactly what the waiver does and does not cover.
    pub limits: String,
    /// Exclusive expiry of the waiver in Unix milliseconds.
    pub expires_at_ms: u64,
    /// What remains risky after the waiver is applied.
    pub residual_risk: String,
    /// Evidence backing the waiver decision.
    pub evidence: Vec<ArtifactId>,
}

impl AuthorizedWaiver {
    /// Validates the authority, decision, bounded scope and residual risk.
    pub fn validate(&self) -> Result<(), ProblemError> {
        self.authority.validate()?;
        crate::text(&self.decision_ref, "waiver.decision_ref")?;
        crate::text(&self.limits, "waiver.limits")?;
        crate::text(&self.residual_risk, "waiver.residual_risk")?;
        if self.expires_at_ms == 0 {
            return Err(ProblemError::InvalidField {
                field: "waiver.expires_at_ms",
                reason: "must be non-zero",
            });
        }
        crate::nonempty(&self.evidence, "waiver.evidence")?;
        let evidence = self
            .evidence
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        crate::unique_text(&evidence, "waiver.evidence")
    }
}

/// The retained record of an applied waiver.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaiverRecord {
    /// The authority that granted it.
    pub authority: OwnerRef,
    /// The admitted decision reference.
    pub decision_ref: String,
    /// What it covered and what it did not.
    pub limits: String,
    /// Exclusive expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Residual risk accepted by applying it.
    pub residual_risk: String,
    /// Evidence backing the decision.
    pub evidence: Vec<ArtifactId>,
}

impl WaiverRecord {
    /// Validates the retained waiver.
    pub fn validate(&self) -> Result<(), ProblemError> {
        AuthorizedWaiver {
            authority: self.authority.clone(),
            decision_ref: self.decision_ref.clone(),
            limits: self.limits.clone(),
            expires_at_ms: self.expires_at_ms,
            residual_risk: self.residual_risk.clone(),
            evidence: self.evidence.clone(),
        }
        .validate()
    }
}

/// The stable obligation identity for one lost assignment.
///
/// The identity binds the subject, the route and the ownership epoch the
/// successor must supersede, so a replayed loss under the same lease converges
/// on the same obligation while a genuinely new loss is distinguishable.
pub fn obligation_id(
    subject: &str,
    route: OwnerRoute,
    ownership_epoch: u64,
) -> Result<String, ProblemError> {
    crate::text(subject, "subject")?;
    if ownership_epoch == 0 {
        return Err(ProblemError::InvalidField {
            field: "ownership_epoch",
            reason: "must be non-zero",
        });
    }
    let bytes = canonical_json_bytes(&(
        "eliot.problem.ownership-obligation.v1",
        subject,
        format!("{route:?}"),
        ownership_epoch,
    ))
    .map_err(|_error| ProblemError::InvalidField {
        field: "obligation_id",
        reason: "identity could not be canonicalized",
    })?;
    Ok(sha256_hex(&bytes))
}

/// Whether a value is a lowercase SHA-256 digest.
///
/// Not `const`: the byte scan is not const on this toolchain, and nothing here
/// needs a compile-time commitment check.
fn is_commitment(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
