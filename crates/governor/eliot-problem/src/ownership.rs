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
//! the loss event carries the exact [`LeaseIdentity`] it observed dead, and each
//! record's `record_owner_loss` refuses when the record's retained identity has
//! moved on. Loss never implies resolution — [`Ownership::Unassigned`] is a
//! live obligation, not a terminal state: the obligation is discharged by
//! admitting an eligible successor under a strictly greater ownership epoch, and
//! [`Ownership::retained_epoch`] is what lets that successor clear the fenced
//! epoch instead of being refused because the record currently has no owner.
//!
//! The loss direction is fenced by the same trust boundary as the assignment
//! direction, which is the property that makes both halves of an owner-loss
//! event real at once. [`OwnerLeaseLoss`] has private fields and no
//! `Deserialize`, so an event cannot be spelled by a caller or decoded from
//! transport bytes; its only construction path, [`OwnerLeaseLoss::observed`],
//! asks the issuing owner itself — through
//! [`OwnerLeaseIssuer::revoked_lease`] — what it durably records about a grant
//! it no longer holds, and **re-derives** the observed identity from that grant
//! rather than accepting one. A caller holding only a principal string, or a
//! hand-written [`LeaseIdentity`], therefore has no way to reach this type at
//! all, and a caller that does hold the exact grant still cannot claim a loss
//! the issuer does not report.
//!
//! The one obligation with no lease identity behind it is the legacy migration:
//! a record that never carried a lease has no [`LeaseIdentity`] to lose, so its
//! [`Ownership::Unassigned`] variant carries `lost_lease: None` and an empty
//! `loss_evidence`. That absence is the finding rather than a gap to be filled —
//! it is never back-filled with a synthesized lease — and it is why
//! `UnassignedOwnership::validate` treats the legacy case and the observed-loss
//! case differently rather than treating every unassigned record alike.

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
///
/// It answers two questions about the same durable state. [`Self::commitment_for`]
/// is the assignment direction: what commitment does the issuer hold for a
/// grant it is still willing to have held. [`Self::revoked_lease`] is the loss
/// direction: what does the issuer itself record about a grant it issued and no
/// longer holds. The two are deliberately on one trait because the issuer, not
/// this crate, is what makes a lease real and what makes it stop being real —
/// splitting them would let one direction be answered by something other than
/// the party that owns the lease.
pub trait OwnerLeaseIssuer {
    /// The durable commitment this issuer holds for `grant`, or `None` when it
    /// holds no such lease.
    fn commitment_for(&self, grant: &OwnerLeaseGrant) -> Option<String>;

    /// The revocation this issuer durably records for `grant`, or `None` when it
    /// records no loss of it.
    ///
    /// The event's reason and evidence come from here rather than from whoever
    /// asks, so an expiry is the expiry the issuer observed, not one a caller
    /// declared. `None` is the refusal in both directions of the lifecycle: an
    /// issuer that has no record of losing this lease will not authenticate a
    /// loss of it.
    fn revoked_lease(&self, grant: &OwnerLeaseGrant) -> Option<OwnerLeaseRevocation>;
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

    /// The ownership epoch this record currently holds, assigned or not.
    ///
    /// Both variants retain the epoch: an assigned record holds the epoch of
    /// its live lease, and an unassigned one holds the epoch that was fenced
    /// when ownership was lost. Reading it from either variant is what lets a
    /// successor be admitted to a record that has lost its owner — the epoch
    /// still advances past the fenced one instead of restarting from nothing.
    ///
    /// This is deliberately *not* [`Self::assigned`]: that one is the fencing
    /// check and must keep refusing an unassigned record, because it is what
    /// stops a lost owner from writing. Only the epoch comparison a successor
    /// has to clear reads the unassigned epoch.
    #[must_use]
    pub const fn retained_epoch(&self) -> u64 {
        match self {
            Self::Assigned(assigned) => assigned.ownership_epoch,
            Self::Unassigned(unassigned) => unassigned.ownership_epoch,
        }
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
        if let OwnerLossReason::LegacyRecordWithoutLease = self.reason {
            // A legacy record never carried a lease, so naming one contradicts
            // the reason rather than describing a loss. The presence is itself
            // the finding, so it is asserted explicitly here rather than
            // ignored: an unexamined identity in this position would mean a
            // record could both deny ever having a lease and cite one.
            if self.lost_lease.is_some() {
                return Err(ProblemError::InvalidField {
                    field: "lost_lease",
                    reason: "a legacy record without a lease cannot name a lost lease",
                });
            }
        } else {
            // Every other loss is an observed event and must name the exact
            // lease identity it saw dead, with evidence pointing at it.
            let Some(identity) = &self.lost_lease else {
                return Err(ProblemError::InvalidField {
                    field: "lost_lease",
                    reason: "an owner loss must name the exact lease it observed dead",
                });
            };
            identity.validate()?;
            crate::nonempty(&self.loss_evidence, "loss_evidence")?;
            // The retained epoch is bound to the retained lease identity, exactly
            // as [`AssignedOwnership::validate`] binds them on the assigned
            // variant. This is not a shape nicety: [`Ownership::retained_epoch`]
            // reads the successor's epoch floor from *this* field when the record
            // is unassigned, so an epoch that disagreed with the fenced lease
            // would let a successor be admitted below the lease it must
            // supersede — the same reuse of a fenced epoch that a renewal is
            // refused for, arriving through the loss path instead.
            if identity.ownership_epoch != self.ownership_epoch {
                return Err(ProblemError::InvalidField {
                    field: "ownership_epoch",
                    reason: "must equal the epoch of the retained lost ownership lease",
                });
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

/// What the lease owner itself durably records about a grant it issued and no
/// longer holds.
///
/// This is the *issuer's* record, not the caller's claim about one. It is
/// deliberately the only place a reason and evidence for a loss are written
/// down: an [`OwnerLeaseLoss`] copies them out of a value the issuer returned,
/// so a caller cannot name its own expiry and attach its own artifacts to it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerLeaseRevocation {
    /// Why the issuing owner stopped holding this grant.
    pub reason: OwnerLossReason,
    /// The issuing owner's own evidence for the revocation.
    pub evidence: Vec<ArtifactId>,
}

impl OwnerLeaseRevocation {
    /// Validates the reason and the issuer's evidence.
    ///
    /// A legacy migration is refused here for the same reason it is refused on
    /// the event: it names the absence of a lease rather than the loss of one,
    /// so it is never something an issuer reports observing.
    pub fn validate(&self) -> Result<(), ProblemError> {
        if self.reason == OwnerLossReason::LegacyRecordWithoutLease {
            return Err(ProblemError::InvalidField {
                field: "loss.reason",
                reason: "a legacy-without-lease migration is not an observed loss",
            });
        }
        crate::nonempty(&self.evidence, "loss.evidence")?;
        let evidence = self
            .evidence
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        crate::unique_text(&evidence, "loss.evidence")
    }
}

/// One observed owner-loss event, authenticated against the issuing owner.
///
/// The fields are private and the type does not implement `Deserialize`, so an
/// event cannot be spelled as a struct literal by a caller and cannot be
/// decoded from transport bytes: both were ways to reach "this lease is dead"
/// with nothing but a principal string and an invented identity. The only
/// construction path is [`Self::observed`], which asks the issuer that granted
/// the lease and re-derives the observed identity from the grant itself. That
/// is what makes the first half of the owner-loss fence real evidence rather
/// than an assertion: the reason and the evidence are the issuer's own, and the
/// identity is derived, never restated.
///
/// The second half — that the identity still matches what the record holds when
/// the event is applied — belongs to the record's `record_owner_loss`, which
/// compares this identity against its *current* retained identity. Both are
/// needed: an issuer-authenticated event for a lease the record has since
/// moved on from is exactly the delayed expiry that must not unassign the
/// successor.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq)]
pub struct OwnerLeaseLoss {
    observed_lease: LeaseIdentity,
    revocation: OwnerLeaseRevocation,
}

impl OwnerLeaseLoss {
    /// The exact lease identity the issuing owner observed dead.
    ///
    /// Re-derived from the grant by [`Self::observed`], so it always names the
    /// lease the issuer was actually asked about.
    #[must_use]
    pub const fn observed_lease(&self) -> &LeaseIdentity {
        &self.observed_lease
    }

    /// Whether this issuer-observed loss names exactly the authenticated lease
    /// the current owner transition is using.
    #[must_use]
    pub fn is_observed_for(&self, identity: &LeaseIdentity) -> bool {
        self.observed_lease.is_exactly(identity)
    }

    /// Why the issuing owner stopped holding this lease.
    #[must_use]
    pub const fn reason(&self) -> OwnerLossReason {
        self.revocation.reason
    }

    /// The issuing owner's own evidence for the loss.
    #[must_use]
    pub fn evidence(&self) -> &[ArtifactId] {
        &self.revocation.evidence
    }

    /// The exact revocation the issuing owner returned for this grant.
    ///
    /// This can be retained with the canonical owner transition so a later
    /// issuer readback can distinguish an observed loss from an asserted one.
    #[must_use]
    pub const fn revocation(&self) -> &OwnerLeaseRevocation {
        &self.revocation
    }

    /// Observes the loss of `grant` against the issuer that granted it.
    ///
    /// The issuer is asked first: it returns the revocation it durably records
    /// for this exact grant, or nothing at all when it holds no such record. A
    /// `None` is the refusal — a caller cannot assert that a lease the issuer
    /// still considers held has stopped being current. The observed identity is
    /// then re-derived here from the grant's own domain-separated commitment,
    /// never taken from the caller, so the event names precisely the lease the
    /// issuer was asked about rather than one the caller preferred.
    pub fn observed(
        grant: &OwnerLeaseGrant,
        issuer: &dyn OwnerLeaseIssuer,
    ) -> Result<Self, ProblemError> {
        let revocation = issuer
            .revoked_lease(grant)
            .ok_or(ProblemError::OwnerLossNotObserved)?;
        revocation.validate()?;
        Ok(Self {
            observed_lease: grant.identity(grant.expected_commitment()?)?,
            revocation,
        })
    }

    /// Validates the retained reason, observed identity and issuer evidence.
    ///
    /// `observed` already holds every one of these, so this exists for a
    /// reloaded value and for the record-side check that runs before the event
    /// is applied.
    pub fn validate(&self) -> Result<(), ProblemError> {
        self.revocation.validate()?;
        self.observed_lease.validate()
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

/// The accepted replacement obligation an `I13.9` `superseded` Problem points at.
///
/// I13.7 closes blocking only on "verified resolution, authorized waiver or
/// supersession", so supersession is a third, distinct terminal route beside
/// resolution and waiver. A supersession is only meaningful when it names an
/// obligation some other authority actually accepted, so the reference is
/// compared against the Problem being superseded here: a replacement equal to
/// this record is a cycle, and a reference that names no accepted obligation
/// lets blocking disappear into a nonexistent identity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Supersession {
    /// The accepted replacement obligation this Problem is superseded by.
    pub replacement_obligation_ref: String,
    /// The principal that accepted the replacement obligation.
    pub replacement_holder: OwnerRef,
    /// Evidence backing that acceptance.
    pub evidence: Vec<ArtifactId>,
}

impl Supersession {
    /// Validates the replacement reference, its accepting holder and evidence.
    ///
    /// `superseded` names the Problem being superseded so the cycle refusal is
    /// exact: a replacement obligation that is this Problem would leave the
    /// blocking obligation pointing back at itself with nothing behind it.
    pub fn validate(&self, superseded: &str) -> Result<(), ProblemError> {
        crate::text(
            &self.replacement_obligation_ref,
            "supersession.replacement_obligation_ref",
        )?;
        if self.replacement_obligation_ref == superseded {
            return Err(ProblemError::InvalidField {
                field: "supersession.replacement_obligation_ref",
                reason: "a problem cannot be superseded by its own obligation",
            });
        }
        self.replacement_holder.validate()?;
        crate::nonempty(&self.evidence, "supersession.evidence")?;
        let evidence = self
            .evidence
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        crate::unique_text(&evidence, "supersession.evidence")
    }
}

/// The retained record of an applied supersession.
///
/// Returned by the supersession transition to the caller, which persists it in
/// the same committed transition as the state change. It is deliberately not a
/// `Problem` field: `accept_risk` returns its [`WaiverRecord`] the same way, and
/// the committed transition history is where both closures are read back from.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupersessionRecord {
    /// The accepted replacement obligation this Problem is superseded by.
    pub replacement_obligation_ref: String,
    /// The principal that accepted the replacement obligation.
    pub replacement_holder: OwnerRef,
    /// Evidence backing that acceptance.
    pub evidence: Vec<ArtifactId>,
}

impl SupersessionRecord {
    /// Validates the retained supersession against the same rules the input
    /// faced, so a reloaded record is held to the admission it was admitted
    /// under.
    pub fn validate(&self) -> Result<(), ProblemError> {
        Supersession {
            replacement_obligation_ref: self.replacement_obligation_ref.clone(),
            replacement_holder: self.replacement_holder.clone(),
            evidence: self.evidence.clone(),
        }
        .validate("")
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
