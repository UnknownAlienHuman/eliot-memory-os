//! One exact versioned cross-root quarantine evidence record, and the
//! restricted verified binding the closure owners execute.
//!
//! Architecture traceability: `ARCH-AUTH-01` and I6.15 keep Governor the
//! semantic owner of grant lineage and Kernel/ORS the mechanical
//! activation/revocation owner; I5.27 binds complete operation identity and
//! makes changed content under one identity a conflict; I6.10 keeps a
//! canonical proposal inactive until its activation receipt exists; A0.3
//! makes hidden creation of authority and false proof claims fail-closed;
//! I14.21 keeps possible effects explicitly reconciling.
//!
//! Issue #2976 splits the previous single structural relation label in two:
//!
//! 1. [`CrossRootQuarantineEvidence`] — the structural, serializable wire
//!    form of ONE owner quarantine decision. It is closed, deny-unknown,
//!    and complete: schema/version, the relation identity plus its
//!    recomputable commitment, exact parent/child grant identities **and**
//!    their immutable grant commitments, both authority roots, the graph
//!    snapshot/revision, the full [`AuthorityBinding`] with its State Fence
//!    and typed Authority Epoch, the policy revision, the closed semantic
//!    operation kind with its operation/idempotency/request commitment, the
//!    retained semantic decision reference, the closed [`QuarantineDisposition`],
//!    the optional mechanical enforcement reference, the owner receipt
//!    identity, and the issued/current/revoked status. Decoding it and
//!    [`CrossRootQuarantineEvidence::validate_shape`] establish SHAPE only.
//!    It is not authority and it is not an input to closure verdicts.
//! 2. [`VerifiedQuarantineBinding`] — the admitted form. Every field is
//!    private, it derives neither `Deserialize` nor `Serialize`, and its
//!    only constructors prove the presented evidence against the retained
//!    semantic decision (operation kind/identity, idempotency key,
//!    canonical request digest, relation and grant commitments, roots,
//!    policy/snapshot/revision, disposition, authority binding, and
//!    receipt, each compared within its own domain), resolve the claimed
//!    ORS reference against the exact retained enforcement result, and
//!    re-verify the retained semantic decision receipt, the applicable
//!    mechanical enforcement receipt, and CURRENT owner state (the
//!    structural relation re-read from the live graph or the admitted
//!    snapshot, parent/child commitments recomputed from CURRENT grants,
//!    the current graph revision, and the current State Fence) before the
//!    omission can satisfy a closure. A public deserializer therefore
//!    cannot produce the type that [`GrantGraph`](crate::GrantGraph)
//!    executes, and a caller-authored structural record authorizes no
//!    omission, even with an authentic receipt identity borrowed from
//!    another decision.
//!
//! One further clause decides WHICH of the two omitting dispositions may
//! close a given omission, and it is decided by the quarantined child's own
//! commitment-proven record rather than by the presenter: a child whose
//! record says it never became effective is omitted on exact current
//! `NeverAdmitted` readback with no revocation effect invented for it, and
//! a child that was previously active or possibly active is omitted only on
//! exact `RevokedAndFenced` Kernel/ORS evidence (see
//! `QuarantineOmissionEvidence::required_by`).
//!
//! # Purity boundary: this crate reads no Store, mints no canonical receipt,
//! authenticates no session, and cannot verify a Kernel/ORS durable record.
//! What this crate guarantees is that a verified binding replays stably
//! under one operation identity, conflicts under changed same-identity
//! content, and stays unreadable as completeness evidence until the owner
//! chain has presented the exact retained semantic decision, the exact
//! retained enforcement result, and the exact semantic and mechanical
//! receipts through the durable readback maps it already serves.

use std::collections::BTreeMap;

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_receipts::{AuthorityBinding, ReceiptIdentity};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::grants::{GrantGraph, GrantId, GrantRecoveryRecord, GrantStatus};
use crate::{AuthorityError, validate_digest, validate_text};

/// Closed operation kind of every quarantine verification, part of the
/// evidence identity so this operation can never collide with another
/// authority operation kind under one operation identity.
pub const QUARANTINE_EVIDENCE_OPERATION_KIND: &str = "authority.quarantine.verify";

/// Closed schema identity of the cross-root quarantine evidence record.
pub const QUARANTINE_EVIDENCE_SCHEMA: &str = "eliot.authority.cross-root-quarantine-evidence";

/// Closed schema version of the cross-root quarantine evidence record.
pub const QUARANTINE_EVIDENCE_VERSION: u16 = 1;

/// Closed quarantine disposition vocabulary (issue #2976, step 3).
///
/// Only [`QuarantineDisposition::NeverAdmitted`] and
/// [`QuarantineDisposition::RevokedAndFenced`] may satisfy a complete
/// omission, and only through a current [`VerifiedQuarantineBinding`],
/// which also binds the chosen disposition to the quarantined child's own
/// recorded admission state: `NeverAdmitted` is admissible only for a child
/// whose record says it never became effective, and `RevokedAndFenced` is
/// the only admissible class for a child that was previously active or
/// possibly active.
/// [`QuarantineDisposition::LegacyUnverified`] is never issued as evidence
/// content: it is the disposition of a structural relation with no current
/// binding. [`QuarantineDisposition::UnknownOrReconciling`] is validated
/// owner evidence whose enforcement outcome is still unknown, so it stays
/// visible and inert but never closes a denominator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineDisposition {
    NeverAdmitted,
    RevokedAndFenced,
    LegacyUnverified,
    UnknownOrReconciling,
}

/// Issued/current/revoked lifecycle of one quarantine evidence record.
///
/// Issuance is established by the owner receipt plus the durable receipt
/// readback, not by this flag: only [`QuarantineEvidenceStatus::Current`]
/// evidence admits a binding, and revocation is one-way — a revoked record
/// can be superseded only by a new explicit owner operation under a new
/// operation identity, never by re-presenting `Current` under the same one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineEvidenceStatus {
    Current,
    Revoked,
}

/// Explicit unresolved-effect disposition carried by mechanical enforcement
/// evidence (I14.21): unknown effects stay explicitly reconciling, never
/// silently erased.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnresolvedEffectDisposition {
    NoneOutstanding,
    ExplicitlyReconciling,
}

/// Mechanical enforcement reference: the exact Kernel/ORS revocation/fence
/// result plus the unresolved-effect disposition (issue #2976, step 3).
///
/// This reuses the canonical/ORS receipt and readback mechanisms: the ORS
/// reference must resolve through the retained enforcement results to
/// exactly this record, and the enforcement operation identity must
/// resolve through the durable receipt map to exactly this receipt. No
/// new generic signature is introduced.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuarantineEnforcementRef {
    /// Immutable enforcement operation identity; the durable readback key.
    pub operation_id: String,
    /// Exact canonical receipt identity of the completed enforcement.
    pub receipt: ReceiptIdentity,
    /// Durable ORS record/reference holding the fence/revocation result.
    pub ors_record_ref: String,
    /// Explicit disposition of unknown in-flight effects.
    pub unresolved_effects: UnresolvedEffectDisposition,
}

impl QuarantineEnforcementRef {
    /// Validates the closed structural shape of one mechanical
    /// enforcement reference only. Resolution against the retained
    /// enforcement result and receipt readback happen at admission.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::InvalidField`] for a blank identity or
    /// a malformed receipt.
    pub fn validate_shape(&self) -> Result<(), AuthorityError> {
        validate_text(
            &self.operation_id,
            "quarantine_evidence.enforcement.operation_id",
        )?;
        validate_text(
            &self.ors_record_ref,
            "quarantine_evidence.enforcement.ors_record_ref",
        )?;
        validate_receipt_identity(&self.receipt, "quarantine_evidence.enforcement.receipt")
    }
}

/// Structural quarantine evidence record: the decoded wire form of ONE
/// owner quarantine decision (issue #2976, step 2).
///
/// This is shape, not authority. Nothing here was proven by an owner, and
/// [`GrantGraph`](crate::GrantGraph) never accepts this type. Every consumer
/// of a satisfied omission reads [`VerifiedQuarantineBinding`], which is
/// produced only from retained evidence, its validated receipts, and a
/// CURRENT owner readback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CrossRootQuarantineEvidence {
    /// Closed schema identity.
    pub schema: String,
    /// Closed schema version.
    pub version: u16,
    /// Structural relation identity this evidence qualifies; the lookup key
    /// into the retained [`QuarantinedCrossRootRelation`](crate::QuarantinedCrossRootRelation).
    pub relation_id: String,
    /// Recomputable commitment of the exact structural relation.
    pub relation_commitment: String,
    /// Delegating parent grant; the crossing source.
    pub parent_grant_id: String,
    /// Quarantined child grant; the crossing dependent.
    pub child_grant_id: String,
    /// Immutable commitment of the parent grant at decision time.
    pub parent_grant_commitment: String,
    /// Immutable commitment of the child grant at decision time.
    pub child_grant_commitment: String,
    /// Exact parent root the edge leaves.
    pub parent_root: String,
    /// Exact child root the edge enters.
    pub child_root: String,
    /// Governor owner snapshot this decision was presented under.
    pub graph_snapshot_id: String,
    /// Graph revision this evidence is bound to: nonzero and never newer
    /// than the CURRENT revision at admission.
    pub graph_revision: u64,
    /// Fence/epoch binding of the quarantined edge, bound to the child.
    pub binding: AuthorityBinding,
    /// Policy/configuration revision the decision was taken under.
    pub policy_revision: String,
    /// Closed semantic operation kind; must equal
    /// [`QUARANTINE_EVIDENCE_OPERATION_KIND`].
    pub operation_kind: String,
    /// Operation identity of the quarantine verification.
    pub operation_id: String,
    /// Idempotency key of the exact operation.
    pub idempotency_key: String,
    /// Canonical request digest of the exact presented bytes.
    pub canonical_request_digest: String,
    /// Reference to the retained canonical semantic decision. A relation id
    /// is not this decision.
    pub semantic_decision_ref: String,
    /// Closed quarantine disposition.
    pub disposition: QuarantineDisposition,
    /// Mechanical enforcement reference. Required for
    /// [`QuarantineDisposition::RevokedAndFenced`], forbidden for
    /// [`QuarantineDisposition::NeverAdmitted`].
    pub enforcement: Option<QuarantineEnforcementRef>,
    /// Owner receipt identity of the semantic quarantine decision.
    pub owner_receipt: ReceiptIdentity,
    /// Issued/current/revoked lifecycle state.
    pub status: QuarantineEvidenceStatus,
}

impl CrossRootQuarantineEvidence {
    /// Validates the closed structural shape only. It proves nothing about
    /// owner provenance, current state, or enforcement.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::InvalidField`] for a foreign schema/version,
    /// a blank identity, a malformed commitment or digest, a zero revision,
    /// a non-crossing root pair, a foreign operation kind, a malformed
    /// receipt, or a `LegacyUnverified` disposition, which is never issued
    /// as evidence content, and [`AuthorityError::FenceMismatch`]/
    /// [`AuthorityError::EpochMismatch`] for an internally inconsistent
    /// binding.
    pub fn validate_shape(&self) -> Result<(), AuthorityError> {
        if self.schema != QUARANTINE_EVIDENCE_SCHEMA || self.version != QUARANTINE_EVIDENCE_VERSION
        {
            return Err(AuthorityError::InvalidField("quarantine_evidence.schema"));
        }
        for (value, field) in [
            (&self.relation_id, "quarantine_evidence.relation_id"),
            (&self.parent_grant_id, "quarantine_evidence.parent_grant_id"),
            (&self.child_grant_id, "quarantine_evidence.child_grant_id"),
            (&self.parent_root, "quarantine_evidence.parent_root"),
            (&self.child_root, "quarantine_evidence.child_root"),
            (
                &self.graph_snapshot_id,
                "quarantine_evidence.graph_snapshot_id",
            ),
            (&self.policy_revision, "quarantine_evidence.policy_revision"),
            (&self.operation_id, "quarantine_evidence.operation_id"),
            (&self.idempotency_key, "quarantine_evidence.idempotency_key"),
            (
                &self.semantic_decision_ref,
                "quarantine_evidence.semantic_decision_ref",
            ),
        ] {
            validate_text(value, field)?;
        }
        if self.operation_kind != QUARANTINE_EVIDENCE_OPERATION_KIND {
            return Err(AuthorityError::InvalidField(
                "quarantine_evidence.operation_kind",
            ));
        }
        validate_digest(
            &self.relation_commitment,
            "quarantine_evidence.relation_commitment",
        )?;
        validate_digest(
            &self.parent_grant_commitment,
            "quarantine_evidence.parent_grant_commitment",
        )?;
        validate_digest(
            &self.child_grant_commitment,
            "quarantine_evidence.child_grant_commitment",
        )?;
        validate_digest(
            &self.canonical_request_digest,
            "quarantine_evidence.canonical_request_digest",
        )?;
        if self.parent_root == self.child_root {
            return Err(AuthorityError::InvalidField("quarantine_evidence.roots"));
        }
        if self.graph_revision == 0 {
            return Err(AuthorityError::InvalidField(
                "quarantine_evidence.graph_revision",
            ));
        }
        self.binding
            .state_fence
            .validate()
            .map_err(|_| AuthorityError::FenceMismatch)?;
        if self.binding.authority_epoch != self.binding.state_fence.authority_epoch {
            return Err(AuthorityError::EpochMismatch);
        }
        if self.disposition == QuarantineDisposition::LegacyUnverified {
            return Err(AuthorityError::InvalidField(
                "quarantine_evidence.disposition_legacy_unverified",
            ));
        }
        if let Some(enforcement) = &self.enforcement {
            enforcement.validate_shape()?;
        }
        validate_receipt_identity(&self.owner_receipt, "quarantine_evidence.owner_receipt")?;
        Ok(())
    }
}

/// Shape-checks one owner-supplied receipt identity. The identity is never
/// derived here: both halves arrive from the durable boundary and are
/// compared exactly at admission.
fn validate_receipt_identity(
    identity: &ReceiptIdentity,
    field: &'static str,
) -> Result<(), AuthorityError> {
    validate_text(identity.receipt_id.as_str(), field)?;
    validate_digest(&identity.canonical_sha256, field)?;
    Ok(())
}

/// Canonical preimage of one structural quarantine relation commitment.
/// Private on purpose: it is the digest input, not a wire contract.
#[derive(Serialize)]
struct QuarantineRelationPreimage<'a> {
    relation_id: &'a str,
    parent_grant_id: &'a str,
    child_grant_id: &'a str,
    parent_root: &'a str,
    child_root: &'a str,
    quarantined_at_revision: u64,
}

/// Recomputable commitment of one retained structural relation: the
/// canonical digest of its exact edge, roots, and quarantine revision. The
/// relation id alone is not this commitment.
fn relation_commitment(
    relation_id: &str,
    parent_grant_id: &str,
    child_grant_id: &str,
    parent_root: &str,
    child_root: &str,
    quarantined_at_revision: u64,
) -> Result<String, AuthorityError> {
    let bytes = canonical_json_bytes(&QuarantineRelationPreimage {
        relation_id,
        parent_grant_id,
        child_grant_id,
        parent_root,
        child_root,
        quarantined_at_revision,
    })
    .map_err(|_| AuthorityError::InvalidField("quarantine_evidence.relation_commitment"))?;
    Ok(sha256_hex(&bytes))
}

/// Immutable commitment of one durable grant record: the canonical digest
/// of its complete wire bytes. This is the same commitment
/// [`grant_commitment`](crate::grant_commitment) computes from a live grant,
/// evaluated directly on the durable record so the Kernel boundary can
/// re-derive it without executing graph construction.
pub(crate) fn grant_record_commitment(
    record: &GrantRecoveryRecord,
) -> Result<String, AuthorityError> {
    let bytes = canonical_json_bytes(record)
        .map_err(|_| AuthorityError::InvalidField("quarantine_evidence.grant_commitment"))?;
    Ok(sha256_hex(&bytes))
}

/// Resolves one claimed mechanical enforcement reference against the
/// exact enforcement result the owner retained: the ORS reference must
/// resolve, and the resolved operation identity, receipt, and
/// unresolved-effect disposition must equal the claim. The receipt
/// readback at the call site then proves the resolved operation
/// completed to exactly that receipt.
fn resolve_retained_enforcement(
    enforcement: &QuarantineEnforcementRef,
    retained_enforcements: &BTreeMap<String, QuarantineEnforcementRef>,
) -> Result<(), AuthorityError> {
    let resolved = retained_enforcements
        .get(&enforcement.ors_record_ref)
        .ok_or(AuthorityError::StaleQuarantineEvidence(
            "quarantine_evidence.enforcement_unresolved",
        ))?;
    if resolved != enforcement {
        return Err(AuthorityError::IdentityConflict);
    }
    Ok(())
}

/// The closed pair of evidence classes that may close ONE closure omission
/// (issue #2976, items A3 and A4), decided from the quarantined CHILD'S OWN
/// recorded admission state.
///
/// The two classes are not interchangeable, and neither is chosen by the
/// presenter. A child whose own durable record says it never became
/// effective authority may be omitted on exact current `NeverAdmitted`
/// owner readback alone: no revocation effect is required for something
/// that never existed, and none is invented. A child that was previously
/// active, or whose record cannot prove it never was, may be omitted ONLY
/// on exact `RevokedAndFenced` Kernel/ORS evidence — the semantic
/// quarantine decision, a matching relation id, and absence from the
/// CURRENT admitted map prove nothing about whether the child ever became
/// effective.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QuarantineOmissionEvidence {
    /// Exact current `NeverAdmitted` owner readback.
    NeverAdmitted,
    /// Exact `RevokedAndFenced` Kernel/ORS enforcement result.
    RevokedAndFenced,
}

impl QuarantineOmissionEvidence {
    /// The evidence class this child's OWN durable record demands.
    ///
    /// Fail-closed by construction: only the explicit pre-activation status
    /// is positive proof that the child never became effective authority
    /// (I6.10 keeps a canonical proposal inactive until its activation
    /// receipt exists). Every other recorded status means the child was
    /// admitted or possibly was — `Active` directly, and the
    /// post-admission `Revoked`/`Expired`/`Stale` states — so only the
    /// exact revocation and enforcement evidence may close its omission.
    ///
    /// This decision deliberately never reads CURRENT admitted-map absence.
    /// A quarantined child is by construction absent from the admitted map,
    /// so CURRENT absence answers nothing about whether it ever became
    /// effective; reading the child's own record instead of asking is the
    /// repair item A4 names.
    ///
    /// The answer bounds what the omission MAY be closed with, not what it
    /// must be: a never-admitted child may still carry a genuine
    /// `RevokedAndFenced` enforcement result (a pending proposal is
    /// revocable), and that evidence is validated on its own terms.
    fn required_by(child: &GrantRecoveryRecord) -> Self {
        match child.status {
            GrantStatus::PendingActivation => Self::NeverAdmitted,
            GrantStatus::Active
            | GrantStatus::Revoked
            | GrantStatus::Expired
            | GrantStatus::Stale => Self::RevokedAndFenced,
        }
    }
}

/// Verified quarantine binding: the ONLY quarantine input executable
/// closure verdicts accept.
///
/// This type is the #2976 split made mechanical. It has no public field, no
/// public constructor other than the verified admissions below, and no
/// `Deserialize`/`Serialize` derive, so neither a decoded
/// [`CrossRootQuarantineEvidence`] nor a caller-authored literal can produce
/// it, and pure graph code can use a binding but can never construct one
/// from a `relation_id` alone. Its admission re-reads CURRENT owner state,
/// so stored field equality is never readback and moved heads refuse
/// instead of satisfying old omissions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedQuarantineBinding {
    relation_id: String,
    parent_grant_id: GrantId,
    child_grant_id: GrantId,
    parent_root: String,
    child_root: String,
    graph_revision: u64,
    state_fence: StateFence,
    operation_id: String,
    semantic_receipt: ReceiptIdentity,
    enforcement: Option<QuarantineEnforcementRef>,
    disposition: QuarantineDisposition,
}

impl VerifiedQuarantineBinding {
    /// Admits one live quarantine evidence record into executable closure
    /// state at the Governor semantic boundary.
    ///
    /// The readback is deliberately against arguments the caller cannot
    /// satisfy by repeating its own request: `graph` is the CURRENT
    /// restored graph, `current_fence` is the CURRENT owner fence,
    /// `canonical_receipts` is the CURRENT durable receipt map,
    /// `retained_decisions` holds the typed semantic decisions the owner
    /// retained keyed by decision reference, and `retained_enforcements`
    /// holds the exact enforcement results the owner retained keyed by
    /// ORS record reference. A stale record therefore fails closed
    /// instead of satisfying an omission, and a substituted decision
    /// reference, policy, or request digest fails before first admission
    /// even with the authentic receipt map.
    ///
    /// # Errors
    ///
    /// Returns every refusal of
    /// [`CrossRootQuarantineEvidence::validate_shape`] plus
    /// [`AuthorityError::IdentityConflict`] for changed same-identity
    /// content, [`AuthorityError::FenceMismatch`]/
    /// [`AuthorityError::EpochMismatch`] when the edge is not bound to the
    /// child's fence/epoch, and
    /// [`AuthorityError::StaleQuarantineEvidence`] when the record is
    /// revoked, names no CURRENT relation, disagrees with CURRENT revision
    /// or fence, resolves no retained semantic decision or enforcement
    /// result, lacks its durable receipt readback, or claims
    /// `NeverAdmitted` for a child whose own record shows it was previously
    /// active or possibly active.
    pub fn admit(
        evidence: &CrossRootQuarantineEvidence,
        graph: &GrantGraph,
        current_fence: &StateFence,
        canonical_receipts: &BTreeMap<String, ReceiptIdentity>,
        retained_decisions: &BTreeMap<String, CrossRootQuarantineEvidence>,
        retained_enforcements: &BTreeMap<String, QuarantineEnforcementRef>,
    ) -> Result<Self, AuthorityError> {
        evidence.validate_shape()?;
        let relation = graph.quarantine_by_relation(&evidence.relation_id).ok_or(
            AuthorityError::StaleQuarantineEvidence("quarantine_evidence.relation"),
        )?;
        let parent = graph
            .quarantine_parent_grant(&relation.parent_grant_id)
            .ok_or_else(|| AuthorityError::MissingParent(relation.parent_grant_id.clone()))?;
        Self::admit_resolved(
            evidence,
            &crate::grants::grant_to_recovery_record(parent),
            &crate::grants::grant_to_recovery_record(&relation.child),
            &relation.relation_id,
            &relation.parent_authority_root_ref,
            &relation.child.authority_root_ref,
            relation.quarantined_at_revision,
            graph.grant_is_admitted(&relation.child.grant_id),
            graph.revision(),
            current_fence,
            canonical_receipts,
            retained_decisions,
            retained_enforcements,
        )
    }

    /// Admits one restored quarantine evidence record into executable
    /// closure state at the Kernel trust boundary, under the same CURRENT
    /// readback as a live admission.
    ///
    /// `relation` is the necessary structural row from the admitted
    /// snapshot; `parent_record` and `child_record` are its CURRENT durable
    /// grant rows. Snapshot membership stays necessary but is never
    /// sufficient proof: commitments are recomputed from these rows, the
    /// evidence is proven against the retained semantic decision and the
    /// exact retained enforcement result, and the receipts are re-read
    /// from the durable map.
    ///
    /// # Errors
    ///
    /// Returns the same refusals as [`Self::admit`] for the shared readback
    /// clauses.
    #[allow(
        clippy::too_many_arguments,
        reason = "the trust-boundary restore carries the whole committed record explicitly"
    )]
    pub fn admit_restored(
        evidence: &CrossRootQuarantineEvidence,
        relation: &crate::QuarantinedCrossRootRecord,
        parent_record: &GrantRecoveryRecord,
        child_record: &GrantRecoveryRecord,
        child_admitted: bool,
        current_revision: u64,
        current_fence: &StateFence,
        canonical_receipts: &BTreeMap<String, ReceiptIdentity>,
        retained_decisions: &BTreeMap<String, CrossRootQuarantineEvidence>,
        retained_enforcements: &BTreeMap<String, QuarantineEnforcementRef>,
    ) -> Result<Self, AuthorityError> {
        evidence.validate_shape()?;
        Self::admit_resolved(
            evidence,
            parent_record,
            child_record,
            &relation.relation_id,
            &relation.parent_authority_root_ref,
            &child_record.authority_root_ref,
            relation.quarantined_at_revision,
            child_admitted,
            current_revision,
            current_fence,
            canonical_receipts,
            retained_decisions,
            retained_enforcements,
        )
    }

    /// Whether this binding may satisfy a complete omission. Only
    /// `NeverAdmitted` and `RevokedAndFenced` qualify; every other
    /// disposition keeps the closure partial with its exact frontier.
    #[must_use]
    pub const fn satisfies_omission(&self) -> bool {
        matches!(
            self.disposition,
            QuarantineDisposition::NeverAdmitted | QuarantineDisposition::RevokedAndFenced
        )
    }

    /// Structural relation identity this binding qualifies.
    #[must_use]
    pub fn relation_id(&self) -> &str {
        self.relation_id.as_str()
    }

    /// Crossing source identity.
    #[must_use]
    pub const fn parent_grant_id(&self) -> &GrantId {
        &self.parent_grant_id
    }

    /// Quarantined dependent identity.
    #[must_use]
    pub const fn child_grant_id(&self) -> &GrantId {
        &self.child_grant_id
    }

    /// Exact parent root the edge leaves.
    #[must_use]
    pub fn parent_root(&self) -> &str {
        self.parent_root.as_str()
    }

    /// Exact child root the edge enters.
    #[must_use]
    pub fn child_root(&self) -> &str {
        self.child_root.as_str()
    }

    /// Graph revision the evidence is bound to.
    #[must_use]
    pub const fn graph_revision(&self) -> u64 {
        self.graph_revision
    }

    /// State fence the binding was admitted under.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Operation identity of the quarantine verification.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        self.operation_id.as_str()
    }

    /// Owner receipt identity of the semantic quarantine decision.
    #[must_use]
    pub const fn semantic_receipt(&self) -> &ReceiptIdentity {
        &self.semantic_receipt
    }

    /// Mechanical enforcement reference, when the disposition carries one.
    #[must_use]
    pub const fn enforcement(&self) -> Option<&QuarantineEnforcementRef> {
        self.enforcement.as_ref()
    }

    /// Closed quarantine disposition of this binding.
    #[must_use]
    pub const fn disposition(&self) -> QuarantineDisposition {
        self.disposition
    }

    /// Shared admission body: structural shape, content readback against
    /// the retained semantic decision, exact edge/root correspondence,
    /// relation and grant commitments recomputed from CURRENT records,
    /// fence/epoch readback, revision currency, semantic receipt readback,
    /// the child's recorded admission state bound to the declared
    /// disposition, ORS-resolved disposition-gated mechanical readback, and
    /// non-revoked status.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one fail-closed readback covers the whole committed record"
    )]
    fn admit_resolved(
        evidence: &CrossRootQuarantineEvidence,
        parent_record: &GrantRecoveryRecord,
        child_record: &GrantRecoveryRecord,
        relation_id: &str,
        parent_root: &str,
        child_root: &str,
        quarantined_at_revision: u64,
        child_admitted: bool,
        current_revision: u64,
        current_fence: &StateFence,
        canonical_receipts: &BTreeMap<String, ReceiptIdentity>,
        retained_decisions: &BTreeMap<String, CrossRootQuarantineEvidence>,
        retained_enforcements: &BTreeMap<String, QuarantineEnforcementRef>,
    ) -> Result<Self, AuthorityError> {
        if evidence.status != QuarantineEvidenceStatus::Current {
            return Err(AuthorityError::StaleQuarantineEvidence(
                "quarantine_evidence.status",
            ));
        }
        // Content readback against the retained owner decision, not the
        // presenter's claim: the semantic decision reference must resolve
        // to the exact decision the owner retained, and every committed
        // field — operation kind/identity, idempotency key, canonical
        // request digest, relation and grant commitments, roots,
        // policy/snapshot/revision, disposition, authority binding,
        // enforcement, and receipt — must agree within its own domain. A
        // substituted reference, policy, or digest fails here, before
        // first admission, even with the authentic graph, fence,
        // operation, and receipt map: a real receipt for another decision
        // cannot certify this one merely because its identity exists.
        let retained = retained_decisions
            .get(&evidence.semantic_decision_ref)
            .ok_or(AuthorityError::StaleQuarantineEvidence(
                "quarantine_evidence.semantic_decision_unretained",
            ))?;
        if retained.status != QuarantineEvidenceStatus::Current {
            return Err(AuthorityError::StaleQuarantineEvidence(
                "quarantine_evidence.semantic_decision_revoked",
            ));
        }
        if retained != evidence {
            return Err(AuthorityError::IdentityConflict);
        }
        if evidence.relation_id != relation_id
            || evidence.parent_grant_id != parent_record.grant_id
            || evidence.child_grant_id != child_record.grant_id
            || evidence.parent_root != parent_root
            || evidence.child_root != child_root
        {
            return Err(AuthorityError::IdentityConflict);
        }
        if child_record.parent_grant_id.as_deref() != Some(parent_record.grant_id.as_str()) {
            return Err(AuthorityError::InvalidField("quarantine_evidence.edge"));
        }
        let expected_relation = relation_commitment(
            relation_id,
            &parent_record.grant_id,
            &child_record.grant_id,
            parent_root,
            child_root,
            quarantined_at_revision,
        )?;
        if evidence.relation_commitment != expected_relation {
            return Err(AuthorityError::IdentityConflict);
        }
        if evidence.parent_grant_commitment != grant_record_commitment(parent_record)?
            || evidence.child_grant_commitment != grant_record_commitment(child_record)?
        {
            return Err(AuthorityError::IdentityConflict);
        }
        if evidence.binding.state_fence != child_record.binding.state_fence {
            return Err(AuthorityError::FenceMismatch);
        }
        if !evidence
            .binding
            .authority_epoch
            .is_same_authority(&child_record.binding.authority_epoch)
        {
            return Err(AuthorityError::EpochMismatch);
        }
        // Owner readback, not self-consistency: the child's live binding
        // must still be the current fence this owner serves.
        if child_record.binding.state_fence != *current_fence {
            return Err(AuthorityError::StaleQuarantineEvidence(
                "quarantine_evidence.current_fence",
            ));
        }
        if evidence.graph_revision > current_revision {
            return Err(AuthorityError::StaleQuarantineEvidence(
                "quarantine_evidence.graph_revision",
            ));
        }
        if quarantined_at_revision > evidence.graph_revision {
            return Err(AuthorityError::StaleQuarantineEvidence(
                "quarantine_evidence.relation_revision",
            ));
        }
        // Semantic readback: the exact semantic operation must have
        // completed canonical reconciliation to exactly this receipt.
        // Absence from the durable map is not proof.
        if canonical_receipts.get(&evidence.operation_id) != Some(&evidence.owner_receipt) {
            return Err(AuthorityError::StaleQuarantineEvidence(
                "quarantine_evidence.semantic_readback",
            ));
        }
        match evidence.disposition {
            QuarantineDisposition::NeverAdmitted => {
                if evidence.enforcement.is_some() {
                    return Err(AuthorityError::InvalidField(
                        "quarantine_evidence.enforcement_never_admitted",
                    ));
                }
                // "This child was never admitted" is a claim about a child
                // the child's OWN durable record says was never admitted.
                // That record is already commitment-proven against this
                // evidence and the retained semantic decision above, so this
                // is a comparison of committed owner content, not a flag the
                // presenter supplied. A child whose record says it was
                // admitted, or cannot say it never was, refuses here and its
                // omission can be closed only by the exact
                // `RevokedAndFenced` Kernel/ORS evidence the
                // `RevokedAndFenced` arm requires. When the record does say
                // the child never became effective, the retained semantic
                // decision and the CURRENT absence below are sufficient and
                // no revocation effect is invented for it.
                if QuarantineOmissionEvidence::required_by(child_record)
                    != QuarantineOmissionEvidence::NeverAdmitted
                {
                    return Err(AuthorityError::StaleQuarantineEvidence(
                        "quarantine_evidence.never_admitted_previously_active",
                    ));
                }
                // CURRENT owner readback: the child is still absent from the
                // admitted map now.
                if child_admitted {
                    return Err(AuthorityError::StaleQuarantineEvidence(
                        "quarantine_evidence.never_admitted_active",
                    ));
                }
            }
            QuarantineDisposition::RevokedAndFenced => {
                let Some(enforcement) = &evidence.enforcement else {
                    return Err(AuthorityError::StaleQuarantineEvidence(
                        "quarantine_evidence.enforcement",
                    ));
                };
                resolve_retained_enforcement(enforcement, retained_enforcements)?;
                // Mechanical readback: the resolved exact Kernel/ORS fence
                // operation must have completed canonical reconciliation to
                // exactly this receipt, fencing this decision's child. This
                // is the class `QuarantineOmissionEvidence::required_by`
                // routes every previously-active or possibly-active child
                // to, so semantic quarantine alone can never close such an
                // omission.
                if canonical_receipts.get(&enforcement.operation_id) != Some(&enforcement.receipt) {
                    return Err(AuthorityError::StaleQuarantineEvidence(
                        "quarantine_evidence.mechanical_readback",
                    ));
                }
                if child_admitted {
                    return Err(AuthorityError::StaleQuarantineEvidence(
                        "quarantine_evidence.fenced_active",
                    ));
                }
            }
            QuarantineDisposition::UnknownOrReconciling => {
                // Validated owner evidence with an unknown enforcement
                // outcome: the binding constructs so the unknown stays
                // explicit, but it never satisfies an omission. A carried
                // enforcement reference must still resolve and read back
                // exactly.
                if let Some(enforcement) = &evidence.enforcement {
                    resolve_retained_enforcement(enforcement, retained_enforcements)?;
                    if canonical_receipts.get(&enforcement.operation_id)
                        != Some(&enforcement.receipt)
                    {
                        return Err(AuthorityError::StaleQuarantineEvidence(
                            "quarantine_evidence.mechanical_readback",
                        ));
                    }
                }
            }
            QuarantineDisposition::LegacyUnverified => {
                return Err(AuthorityError::StaleQuarantineEvidence(
                    "quarantine_evidence.disposition_legacy",
                ));
            }
        }
        Ok(Self {
            relation_id: evidence.relation_id.clone(),
            parent_grant_id: GrantId::new(evidence.parent_grant_id.clone())?,
            child_grant_id: GrantId::new(evidence.child_grant_id.clone())?,
            parent_root: evidence.parent_root.clone(),
            child_root: evidence.child_root.clone(),
            graph_revision: evidence.graph_revision,
            state_fence: evidence.binding.state_fence.clone(),
            operation_id: evidence.operation_id.clone(),
            semantic_receipt: evidence.owner_receipt.clone(),
            enforcement: evidence.enforcement.clone(),
            disposition: evidence.disposition,
        })
    }
}
