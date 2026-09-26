//! One exact authenticated root-transition operation, its owner evidence,
//! and the admitted form executable graph construction accepts.
//!
//! Architecture traceability: `ARCH-AUTH-01` and I6.15 keep Governor the
//! semantic owner of grant lineage and Kernel/ORS the mechanical activation
//! owner; I5.27 binds complete operation identity and makes changed content
//! under one identity a conflict; I6.10 keeps a canonical proposal inactive
//! until its activation receipt exists and reconciles an unknown
//! acknowledgement under the ORIGINAL identity instead of retrying a fresh
//! one; A0.3 makes hidden creation or expansion of authority fail-closed.
//!
//! #2962 splits the previous single `RootTransitionReceipt` DTO in two:
//!
//! 1. [`RootTransitionRecord`] — the structural, serializable wire form of one
//!    re-rooting operation. It is closed, deny-unknown, and complete: it
//!    carries the operation identity, idempotency key, canonical-request
//!    digest input, exact parent/child grant identities **and** their
//!    immutable grant commitments, both authority roots, the graph snapshot
//!    identity, the predecessor/current/expected-next graph revisions, the full
//!    [`AuthorityBinding`] with its State Fence and typed Authority Epoch, the
//!    policy revision, the deadline, the effect ceiling, and the retained
//!    semantic decision reference. Decoding it and
//!    [`RootTransitionRecord::validate_shape`] establish SHAPE only. It is not
//!    authority and it is not an input to executable graph construction.
//! 2. [`AdmittedRootTransition`] — the admitted form. Every field is private,
//!    it derives neither `Deserialize` nor `Serialize`, and its only
//!    constructor re-verifies the retained semantic decision, the Kernel
//!    activation receipt, and the CURRENT owner state (parent/child
//!    commitments recomputed from the live grants, the current graph
//!    revision, and the current State Fence) before the crossing can enter a
//!    graph. A public deserializer therefore cannot produce the type that
//!    [`GrantGraph`](crate::GrantGraph) executes, and a caller-authored
//!    structural record authorizes nothing.
//!
//! # Purity boundary: this crate reads no Store, mints no canonical receipt,
//! authenticates no session, and cannot verify a Kernel/ORS durable record.
//! The mechanical proof that a Kernel activation identity and its durable ORS
//! record exist belongs to the Kernel/ORS owner; what this crate guarantees is
//! that an admitted crossing is replay-stable under one operation identity,
//! conflicting under changed same-identity content, and unreadable as active
//! authority until the owner chain has presented that evidence.

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_receipts::{AuthorityBinding, AuthorityRequestSubject, EffectClass};
use eliot_runtime_contracts::AuthorityActivationReceipt;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::grants::{CapabilityGrant, effect_rank};
use crate::{AuthorityError, validate_digest, validate_text};

/// Closed operation kind of every authenticated root transition, part of the
/// canonical request preimage so this operation can never collide with another
/// P-07 operation kind under one operation identity.
pub const ROOT_TRANSITION_OPERATION_KIND: &str = "authority.root_transition.activate";

/// Closed schema identity of the transition activation receipt.
pub const ROOT_TRANSITION_RECEIPT_SCHEMA: &str = "eliot.authority.root-transition-activation";

/// Closed schema version of the transition activation receipt.
pub const ROOT_TRANSITION_RECEIPT_VERSION: u16 = 1;

/// Disposition of one transition activation, as reconciled by the
/// mechanical owner. Only [`RootTransitionDisposition::Committed`] is
/// authority; an unknown outcome stays one reconciling operation and a
/// terminal disposition never admits a crossing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RootTransitionDisposition {
    Committed,
    UnknownOutcome,
    Terminal,
}

/// Structural root-transition record: the decoded wire form of ONE
/// re-rooting operation (issue #2962, step 2).
///
/// This is shape, not authority. Nothing here was proven by an owner, and
/// [`GrantGraph`](crate::GrantGraph) never accepts this type. Every consumer of
/// an admitted crossing reads [`AdmittedRootTransition`], which is produced
/// only from a retained operation, its validated activation receipt, and a
/// CURRENT owner readback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootTransitionRecord {
    /// Owner-issued transition identity, unique per graph.
    pub transition_id: String,
    /// Operation identity of the authenticated activation. Under this
    /// identity, changed content is a conflict, never a second crossing.
    pub operation_id: String,
    /// Idempotency key of the exact operation.
    pub idempotency_key: String,
    /// Delegating parent grant; the crossing source.
    pub parent_grant_id: String,
    /// Re-rooted child grant; the crossing dependent.
    pub child_grant_id: String,
    /// Immutable commitment of the parent grant at admission time. Grant
    /// identities alone are not a commitment: a same-identity grant revision
    /// would otherwise re-authorize an old crossing.
    pub parent_grant_commitment: String,
    /// Immutable commitment of the child grant at admission time.
    pub child_grant_commitment: String,
    /// Exact parent root the edge leaves.
    pub from_authority_root_ref: String,
    /// Exact child root the edge enters.
    pub to_authority_root_ref: String,
    /// Owner principal authorizing the re-root; must equal the parent's
    /// holder, so a child cannot self-authorize a new root.
    pub issuer: String,
    /// Governor owner snapshot this operation was presented under.
    pub graph_snapshot_id: String,
    /// Graph revision this operation read before the crossing.
    pub predecessor_graph_revision: u64,
    /// Graph revision the crossing is expected to create.
    pub expected_next_graph_revision: u64,
    /// Graph revision this record was admitted at. Admission requires a
    /// nonzero revision at or before the graph revision being built.
    pub admitted_at_revision: u64,
    /// Policy/configuration revision the semantic decision was taken under.
    pub policy_revision: String,
    /// Deadline of the operation, after which the evidence is stale.
    pub deadline_unix_ms: u64,
    /// Effect ceiling the crossing may never exceed.
    pub effect_ceiling: EffectClass,
    /// Reference to the retained canonical semantic decision that admitted the
    /// re-root. A transition id is not this decision.
    pub semantic_decision_ref: String,
    /// Fence/epoch binding of the crossing, bound to the child grant.
    pub binding: AuthorityBinding,
}

impl RootTransitionRecord {
    /// Validates the closed structural shape only. It proves nothing about
    /// owner provenance, current state, or activation.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::InvalidField`] for a blank identity, a
    /// malformed grant commitment, a zero revision, a missing expected
    /// successor revision, or a non-crossing root pair, and
    /// [`AuthorityError::FenceMismatch`]/[`AuthorityError::EpochMismatch`] for
    /// an internally inconsistent binding.
    pub fn validate_shape(&self) -> Result<(), AuthorityError> {
        for (value, field) in [
            (&self.transition_id, "root_transition.transition_id"),
            (&self.operation_id, "root_transition.operation_id"),
            (&self.idempotency_key, "root_transition.idempotency_key"),
            (&self.parent_grant_id, "root_transition.parent_grant_id"),
            (&self.child_grant_id, "root_transition.child_grant_id"),
            (
                &self.from_authority_root_ref,
                "root_transition.from_authority_root_ref",
            ),
            (
                &self.to_authority_root_ref,
                "root_transition.to_authority_root_ref",
            ),
            (&self.issuer, "root_transition.issuer"),
            (&self.graph_snapshot_id, "root_transition.graph_snapshot_id"),
            (&self.policy_revision, "root_transition.policy_revision"),
            (
                &self.semantic_decision_ref,
                "root_transition.semantic_decision_ref",
            ),
        ] {
            validate_text(value, field)?;
        }
        validate_digest(
            &self.parent_grant_commitment,
            "root_transition.parent_grant_commitment",
        )?;
        validate_digest(
            &self.child_grant_commitment,
            "root_transition.child_grant_commitment",
        )?;
        if self.from_authority_root_ref == self.to_authority_root_ref {
            return Err(AuthorityError::InvalidField("root_transition.roots"));
        }
        if self.predecessor_graph_revision == 0
            || self.admitted_at_revision == 0
            || self.expected_next_graph_revision <= self.predecessor_graph_revision
        {
            return Err(AuthorityError::InvalidField("root_transition.revision"));
        }
        self.binding
            .state_fence
            .validate()
            .map_err(|_| AuthorityError::FenceMismatch)?;
        if self.binding.authority_epoch != self.binding.state_fence.authority_epoch {
            return Err(AuthorityError::EpochMismatch);
        }
        Ok(())
    }
}

/// The exact authenticated root-transition operation presented to P-07.
///
/// Private fields and a derived canonical request digest: the presented bytes
/// are a function of every bound field, so exact replay re-presents identical
/// bytes and any changed field under one operation identity is a different
/// request, never a silently accepted one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootTransitionActivationRequest {
    record: RootTransitionRecord,
    subject: AuthorityRequestSubject,
    canonical_request_digest: String,
}

/// Canonical preimage of one root-transition request. Private on purpose: it
/// is the digest input, not a wire contract.
#[derive(Serialize)]
struct RootTransitionCanonicalPreimage<'a> {
    operation_kind: &'static str,
    record: &'a RootTransitionRecord,
    subject: &'a AuthorityRequestSubject,
}

impl RootTransitionActivationRequest {
    /// Binds one structural record to one authenticated principal/session/scope
    /// subject and derives the canonical request digest.
    ///
    /// # Errors
    ///
    /// Returns the record's shape refusal, the subject's closed-shape refusal,
    /// or [`AuthorityError::InvalidField`] when canonical serialization fails.
    pub fn new(
        record: RootTransitionRecord,
        subject: AuthorityRequestSubject,
    ) -> Result<Self, AuthorityError> {
        record.validate_shape()?;
        subject
            .validate()
            .map_err(|_| AuthorityError::InvalidField("root_transition.subject"))?;
        let canonical_request_digest = canonical_request_digest(&record, &subject)?;
        Ok(Self {
            record,
            subject,
            canonical_request_digest,
        })
    }

    /// Exact structural record this operation presents.
    #[must_use]
    pub const fn record(&self) -> &RootTransitionRecord {
        &self.record
    }

    /// Authenticated principal/session/scope subject, proved by the transport
    /// adapter from its own session and rechecked by the mechanical owner.
    #[must_use]
    pub const fn subject(&self) -> &AuthorityRequestSubject {
        &self.subject
    }

    /// Canonical request digest of the exact presented bytes.
    #[must_use]
    pub fn canonical_request_digest(&self) -> &str {
        &self.canonical_request_digest
    }

    /// Governor owner snapshot identity this operation is presented under.
    #[must_use]
    pub fn graph_snapshot_id(&self) -> &str {
        self.record.graph_snapshot_id.as_str()
    }

    /// Retention-ledger key of this presentation. Namespacing transitions from
    /// grants and introductions keeps one identity from aliasing another
    /// family.
    #[must_use]
    pub fn ledger_key(&self) -> String {
        format!("transition:{}", self.record.transition_id)
    }
}

/// Transition-specific owner evidence: a versioned activation receipt that
/// binds the exact operation commitment, both grant commitments, both roots,
/// the graph snapshot/revision, the current fence/epoch, the Kernel activation
/// identity with its durable ORS record, and the reconciled disposition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootTransitionActivationReceipt {
    /// Closed schema identity.
    pub schema: String,
    /// Closed schema version.
    pub version: u16,
    /// Exact presented transition identity.
    pub transition_id: String,
    /// Exact presented operation identity.
    pub operation_id: String,
    /// Canonical request digest of the exact presented bytes.
    pub canonical_request_digest: String,
    /// Exact presented parent grant identity.
    pub parent_grant_id: String,
    /// Exact presented child grant identity.
    pub child_grant_id: String,
    /// Immutable parent grant commitment.
    pub parent_grant_commitment: String,
    /// Immutable child grant commitment.
    pub child_grant_commitment: String,
    /// Exact root the edge leaves.
    pub from_authority_root_ref: String,
    /// Exact root the edge enters.
    pub to_authority_root_ref: String,
    /// Graph snapshot the crossing was activated under.
    pub graph_snapshot_id: String,
    /// Graph revision the crossing was admitted at.
    pub admitted_graph_revision: u64,
    /// Fence and epoch the crossing is bound to.
    pub binding: AuthorityBinding,
    /// Kernel activation identity for the exact presented operation.
    pub kernel_activation: AuthorityActivationReceipt,
    /// Durable ORS record/reference holding the mechanical activation.
    pub ors_record_ref: String,
    /// Reconciled disposition of the operation.
    pub disposition: RootTransitionDisposition,
}

impl RootTransitionActivationReceipt {
    /// Proves that this receipt is the mechanical owner evidence for the exact
    /// retained operation, and that both the semantic commitment and the
    /// Kernel activation agree with it.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::InvalidField`] for a foreign schema/version or
    /// a blank/ill-formed identity, [`AuthorityError::IdentityConflict`] when
    /// any committed field disagrees with the presented request,
    /// [`AuthorityError::ReceiptMismatch`] when the Kernel activation receipt is
    /// not a validated `Active` receipt for the presented snapshot and epoch,
    /// and [`AuthorityError::StaleTransitionEvidence`] when a non-committed
    /// disposition is claimed as authority.
    pub fn validate(
        &self,
        request: &RootTransitionActivationRequest,
    ) -> Result<(), AuthorityError> {
        if self.schema != ROOT_TRANSITION_RECEIPT_SCHEMA
            || self.version != ROOT_TRANSITION_RECEIPT_VERSION
        {
            return Err(AuthorityError::InvalidField(
                "root_transition_receipt.schema",
            ));
        }
        for (value, field) in [
            (&self.transition_id, "root_transition_receipt.transition_id"),
            (&self.operation_id, "root_transition_receipt.operation_id"),
            (
                &self.parent_grant_id,
                "root_transition_receipt.parent_grant_id",
            ),
            (
                &self.child_grant_id,
                "root_transition_receipt.child_grant_id",
            ),
            (
                &self.from_authority_root_ref,
                "root_transition_receipt.from_authority_root_ref",
            ),
            (
                &self.to_authority_root_ref,
                "root_transition_receipt.to_authority_root_ref",
            ),
            (
                &self.graph_snapshot_id,
                "root_transition_receipt.graph_snapshot_id",
            ),
            (
                &self.ors_record_ref,
                "root_transition_receipt.ors_record_ref",
            ),
        ] {
            validate_text(value, field)?;
        }
        if self.admitted_graph_revision == 0 {
            return Err(AuthorityError::InvalidField(
                "root_transition_receipt.revision",
            ));
        }
        let record = request.record();
        if self.transition_id != record.transition_id
            || self.operation_id != record.operation_id
            || self.canonical_request_digest != request.canonical_request_digest()
            || self.parent_grant_id != record.parent_grant_id
            || self.child_grant_id != record.child_grant_id
            || self.parent_grant_commitment != record.parent_grant_commitment
            || self.child_grant_commitment != record.child_grant_commitment
            || self.from_authority_root_ref != record.from_authority_root_ref
            || self.to_authority_root_ref != record.to_authority_root_ref
            || self.graph_snapshot_id != record.graph_snapshot_id
            || self.binding != record.binding
        {
            return Err(AuthorityError::IdentityConflict);
        }
        self.kernel_activation
            .validate()
            .map_err(|_| AuthorityError::ReceiptMismatch)?;
        if self.kernel_activation.snapshot_id != record.graph_snapshot_id
            || !self
                .kernel_activation
                .authority_epoch
                .is_same_authority(&record.binding.state_fence.authority_epoch)
        {
            return Err(AuthorityError::ReceiptMismatch);
        }
        if self.disposition != RootTransitionDisposition::Committed {
            return Err(AuthorityError::StaleTransitionEvidence(
                "root_transition_receipt.disposition",
            ));
        }
        Ok(())
    }
}

/// Admitted root-transition evidence: the ONLY transition input executable
/// graph construction accepts.
///
/// This type is the #2962 split made mechanical. It has no public field, no
/// public constructor other than the verified admission below, and no
/// `Deserialize`/`Serialize` derive, so neither a decoded
/// [`RootTransitionRecord`] nor a caller-authored literal can produce it. Its
/// admission re-reads CURRENT owner state, so stored field equality is never
/// readback and moved heads refuse instead of activating old evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedRootTransition {
    record: RootTransitionRecord,
    canonical_request_digest: String,
    kernel_activation_id: String,
    ors_record_ref: String,
}

impl AdmittedRootTransition {
    /// Admits one live operation into executable graph state.
    ///
    /// The readback is deliberately against arguments the caller cannot
    /// satisfy by repeating its own request: `parent` and `child` are the
    /// CURRENT grants, `current_revision` is the CURRENT graph revision, and
    /// `current_fence` is the CURRENT owner fence. A stale record therefore
    /// fails closed instead of authorizing a crossing.
    ///
    /// # Errors
    ///
    /// Returns every refusal of [`RootTransitionActivationReceipt::validate`]
    /// plus [`AuthorityError::GrantNotNarrower`] for a crossing that is not a
    /// narrowing, [`AuthorityError::FenceMismatch`]/
    /// [`AuthorityError::EpochMismatch`] when the crossing is not bound to the
    /// child's fence/epoch or the child's binding is no longer the current
    /// fence, [`AuthorityError::EffectCeilingExceeded`] when the recorded effect
    /// ceiling exceeds the child or the binding ceiling,
    /// [`AuthorityError::InvalidField`] for a record that does not describe
    /// exactly this parent/child edge and root pair, and
    /// [`AuthorityError::StaleTransitionEvidence`] when the operation was
    /// admitted against moved graph revisions.
    pub fn admit(
        request: &RootTransitionActivationRequest,
        receipt: &RootTransitionActivationReceipt,
        parent: &CapabilityGrant,
        child: &CapabilityGrant,
        current_revision: u64,
        current_fence: &StateFence,
    ) -> Result<Self, AuthorityError> {
        receipt.validate(request)?;
        let admitted = Self::admit_record(
            request.record(),
            request.canonical_request_digest(),
            &receipt.kernel_activation.activation_id,
            &receipt.ors_record_ref,
            parent,
            child,
            current_revision,
            current_fence,
        )?;
        if receipt.admitted_graph_revision < request.record().predecessor_graph_revision
            || request.record().expected_next_graph_revision != current_revision + 1
        {
            return Err(AuthorityError::StaleTransitionEvidence(
                "root_transition.expected_next_graph_revision",
            ));
        }
        Ok(admitted)
    }

    /// Admits one restored admitted-evidence row into executable graph state
    /// under the same CURRENT readback as a live activation.
    ///
    /// # Errors
    ///
    /// Returns the same refusals as [`Self::admit`] for the shared readback
    /// clauses.
    pub fn admit_restored(
        row: &AdmittedRootTransitionRecord,
        parent: &CapabilityGrant,
        child: &CapabilityGrant,
        current_revision: u64,
        current_fence: &StateFence,
    ) -> Result<Self, AuthorityError> {
        Self::admit_record(
            &row.record,
            &row.canonical_request_digest,
            &row.kernel_activation_id,
            &row.ors_record_ref,
            parent,
            child,
            current_revision,
            current_fence,
        )
    }

    /// Emits the durable admitted-evidence row for the versioned recovery
    /// contract. The row carries the complete admitted commitment, so restore
    /// re-verifies it against CURRENT state instead of trusting copied fields.
    #[must_use]
    pub fn to_recovery_record(&self) -> AdmittedRootTransitionRecord {
        AdmittedRootTransitionRecord {
            record: self.record.clone(),
            canonical_request_digest: self.canonical_request_digest.clone(),
            kernel_activation_id: self.kernel_activation_id.clone(),
            ors_record_ref: self.ors_record_ref.clone(),
        }
    }

    /// Exact structural record admitted as authority.
    #[must_use]
    pub const fn record(&self) -> &RootTransitionRecord {
        &self.record
    }

    /// Operation identity that authorized this crossing.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        self.record.operation_id.as_str()
    }

    /// Canonical request digest of the admitted operation.
    #[must_use]
    pub fn canonical_request_digest(&self) -> &str {
        self.canonical_request_digest.as_str()
    }

    /// Kernel activation identity that mechanically activated the crossing.
    #[must_use]
    pub fn kernel_activation_id(&self) -> &str {
        self.kernel_activation_id.as_str()
    }

    /// Durable ORS record holding the mechanical activation.
    #[must_use]
    pub fn ors_record_ref(&self) -> &str {
        self.ors_record_ref.as_str()
    }

    /// Graph revision the crossing was admitted at.
    #[must_use]
    pub const fn admitted_at_revision(&self) -> u64 {
        self.record.admitted_at_revision
    }

    /// Shared admission body: structural shape, exact edge/root correspondence,
    /// issuer, narrowing, fence/epoch readback, effect ceiling, grant
    /// commitments recomputed from CURRENT grants, and revision currency.
    #[allow(
        clippy::too_many_arguments,
        reason = "one fail-closed readback covers the whole committed record"
    )]
    fn admit_record(
        record: &RootTransitionRecord,
        canonical_request_digest: &str,
        kernel_activation_id: &str,
        ors_record_ref: &str,
        parent: &CapabilityGrant,
        child: &CapabilityGrant,
        current_revision: u64,
        current_fence: &StateFence,
    ) -> Result<Self, AuthorityError> {
        record.validate_shape()?;
        validate_digest(
            canonical_request_digest,
            "root_transition.canonical_request_digest",
        )?;
        validate_text(kernel_activation_id, "root_transition.kernel_activation_id")?;
        validate_text(ors_record_ref, "root_transition.ors_record_ref")?;
        if child.grant_id.as_str() != record.child_grant_id
            || child.parent_grant_id.as_ref() != Some(&parent.grant_id)
        {
            return Err(AuthorityError::InvalidField("root_transition.edge"));
        }
        if parent.authority_root_ref != record.from_authority_root_ref
            || child.authority_root_ref != record.to_authority_root_ref
        {
            return Err(AuthorityError::InvalidField("root_transition.roots"));
        }
        if parent.holder.as_str() != record.issuer {
            return Err(AuthorityError::InvalidField("root_transition.issuer"));
        }
        // A crossing authorizes the re-root, never widening: the four narrowing
        // clauses still apply to the crossing edge itself.
        crate::grants::check_narrowing(parent, child)?;
        if record.binding.state_fence != child.binding.state_fence {
            return Err(AuthorityError::FenceMismatch);
        }
        if !record
            .binding
            .authority_epoch
            .is_same_authority(&child.binding.authority_epoch)
        {
            return Err(AuthorityError::EpochMismatch);
        }
        // Owner readback, not self-consistency: the child's live binding must
        // still be the current fence this owner serves.
        if child.binding.state_fence != *current_fence {
            return Err(AuthorityError::StaleTransitionEvidence(
                "root_transition.current_fence",
            ));
        }
        if record.parent_grant_commitment != grant_commitment(parent)?
            || record.child_grant_commitment != grant_commitment(child)?
        {
            return Err(AuthorityError::IdentityConflict);
        }
        if effect_rank(record.effect_ceiling) > effect_rank(child.authority.max_effect())
            || effect_rank(record.effect_ceiling) > effect_rank(record.binding.allowed_effect)
        {
            return Err(AuthorityError::EffectCeilingExceeded);
        }
        if record.admitted_at_revision == 0 || record.admitted_at_revision > current_revision {
            return Err(AuthorityError::StaleTransitionEvidence(
                "root_transition.admitted_at_revision",
            ));
        }
        Ok(Self {
            record: record.clone(),
            canonical_request_digest: canonical_request_digest.to_owned(),
            kernel_activation_id: kernel_activation_id.to_owned(),
            ors_record_ref: ors_record_ref.to_owned(),
        })
    }
}

/// Durable admitted-evidence row of the versioned grant-graph recovery
/// contract. It is the complete commitment an admitted crossing restores from:
/// a structural v1 record cannot produce this shape, so legacy cross-root data
/// restores only as inert quarantined evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmittedRootTransitionRecord {
    /// The exact admitted structural record.
    pub record: RootTransitionRecord,
    /// Canonical request digest of the admitted operation.
    pub canonical_request_digest: String,
    /// Kernel activation identity that mechanically activated the crossing.
    pub kernel_activation_id: String,
    /// Durable ORS record holding the mechanical activation.
    pub ors_record_ref: String,
}

/// Immutable commitment of one grant: the canonical digest of its complete
/// durable record. Grant identity alone is not a commitment, because a
/// same-identity grant revision would otherwise re-authorize an old crossing.
pub fn grant_commitment(grant: &CapabilityGrant) -> Result<String, AuthorityError> {
    let record = crate::grants::grant_to_recovery_record(grant);
    let bytes = canonical_json_bytes(&record)
        .map_err(|_| AuthorityError::InvalidField("root_transition.grant_commitment"))?;
    Ok(sha256_hex(&bytes))
}

/// Canonical request digest of one exact root-transition presentation.
fn canonical_request_digest(
    record: &RootTransitionRecord,
    subject: &AuthorityRequestSubject,
) -> Result<String, AuthorityError> {
    let bytes = canonical_json_bytes(&RootTransitionCanonicalPreimage {
        operation_kind: ROOT_TRANSITION_OPERATION_KIND,
        record,
        subject,
    })
    .map_err(|_| AuthorityError::InvalidField("root_transition.canonical_request_digest"))?;
    Ok(sha256_hex(&bytes))
}
