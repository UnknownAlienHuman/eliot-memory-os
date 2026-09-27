//! The compiled mechanical subset of one canonical authority decision (I6.10).
//!
//! # What this type is, and the three it is not
//!
//! Issue #1794 W1 requires the adjacent "snapshot" roles in this repository to
//! stay fully qualified instead of being collapsed into one universal object.
//! They are:
//!
//! 1. [`MechanicalAuthoritySubset`] (this module) — the *compiled mechanical
//!    subset* of one canonical `CapabilityGrant`. It is the immutable,
//!    content-committed payload I6.10 requires to be compiled before a
//!    token, lease, approval or operation permit becomes effective, and the
//!    only object a consumer may mechanically enforce against.
//! 2. `eliot_runtime_contracts::KernelAuthoritySnapshot` — a *route and
//!    generation projection* (snapshot id, authority epoch, active
//!    `ModuleGeneration`s, State Fence). It says which module routes are
//!    current; it carries no operation, scope, ceiling, approval or canonical
//!    source commitment and is not authority over an effect.
//! 3. `eliot_kernel_core::KernelAuthorityReplaySnapshot` — the *sealed process
//!    replay payload* committed through `DispatchSnapshotCodec` in the ORS
//!    `KernelAuthoritySnapshot` operational envelope. It retains P-03
//!    dispatch-permit and origin-challenge replay state. A process replay
//!    snapshot is not a semantic grant and does not cover one.
//!
//! Authority is never inferred from field-name similarity between these three:
//! only this module's payload is content-verified against a canonical source,
//! and only it can refuse an effect.
//!
//! # Why the commitment is content-bound
//!
//! [`MechanicalAuthoritySubset::content_commitment`] hashes the complete
//! compiled payload — operations, transition classes, scopes, effect, proof
//! and data-class ceilings, policy/configuration/lease revisions, fence and
//! typed epoch, expiry and heartbeat conditions, approval references, and the
//! canonical source commitment — through the repository's existing
//! versioned-digest convention: `canonical_json_bytes` over a struct carrying a
//! `domain_separator`, then `sha256_hex`, exactly as
//! `eliot_contracts::epoch_identity::epoch_identity_digest` and
//! `eliot_governor::route_registry::effective_route_key` do. Changing any
//! committed field therefore changes the commitment, which is what makes a
//! snapshot identity unusable for altered content: the ORIGINAL recorded
//! commitment is the value every consumer compares against, and a freshly
//! recomputed digest is never substituted for a missing or disagreeing one.
//!
//! # Which parts are proven to be a subset of the source authority
//!
//! The canonical `GrantRecoveryRecord` admits exactly three enforceable
//! dimensions, and [`MechanicalAuthoritySubset::compile`] proves the compiled
//! values against all of them: the named operation set and the resource/scope
//! set are the canonical grant's own admitted sets, and the effect ceiling may
//! not exceed the grant's own ceiling, the binding's ceiling, or the grant's
//! inherited source ceiling. Transition classes, data classes, revision
//! identities, heartbeat cadence and approval references have no field in the
//! canonical grant record; they are required, closed, non-empty, and inside the
//! content commitment, and this crate does not claim a subsetness proof it
//! cannot make from the source it was given.
//!
//! # Failure direction
//!
//! Every required group is required. [`MechanicalAuthoritySubset::compile`]
//! refuses an omitted or unresolved constraint instead of emitting a wildcard,
//! and [`MechanicalAuthoritySubset::admits`] denies a use site it cannot
//! positively place inside the committed ceilings.

use eliot_contracts::{EpochId, StateFence, canonical_json_bytes, sha256_hex};
use eliot_receipts::{AuthorityBinding, EffectClass, ProofCeiling};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::grants::{GrantRecoveryRecord, source_effect_rank};
use crate::{AuthorityError, validate_digest, validate_text};

/// Closed schema identity of the compiled mechanical subset.
pub const MECHANICAL_SUBSET_SCHEMA: &str = "eliot.authority.mechanical-subset";

/// Current mechanical-subset contract version.
///
/// Version 1 is the first complete I6.10 payload. The version is checked
/// against the closed constants before any field is interpreted, so a future
/// payload with different field meaning is never read under these semantics.
pub const MECHANICAL_SUBSET_VERSION: u16 = 1;

/// Domain separator of the mechanical-subset content commitment.
pub const MECHANICAL_SUBSET_DIGEST_DOMAIN: &str = "eliot.authority.mechanical-subset.v1";

/// Exact canonical source a compiled subset was derived from.
///
/// This is the I6.10 "source canonical receipt and snapshot hash" group. It
/// names the canonical decision that produced the subset, the digest of that
/// decision's canonical bytes, the immutable commitment of the exact grant
/// revision, and the grant-graph revision the compilation read. Grant identity
/// alone is not a commitment, so a same-identity grant revision cannot
/// re-authorize a compiled subset.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CanonicalSourceCommitment {
    /// Reference to the retained canonical decision the subset was compiled from.
    pub canonical_decision_ref: String,
    /// SHA-256 over the canonical bytes of that retained decision.
    pub canonical_decision_sha256: String,
    /// Grant identity the subset is compiled for.
    pub source_grant_id: String,
    /// Immutable commitment of the exact canonical grant revision.
    pub source_grant_commitment: String,
    /// Grant-graph revision the compilation read.
    pub source_graph_revision: u64,
}

impl CanonicalSourceCommitment {
    /// Validates every source field. A malformed or absent source is a refusal,
    /// never a placeholder.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::InvalidField`] for a blank identity, a
    /// malformed digest, or a zero grant-graph revision.
    pub fn validate(&self) -> Result<(), AuthorityError> {
        validate_text(
            &self.canonical_decision_ref,
            "mechanical_subset.source.canonical_decision_ref",
        )?;
        validate_digest(
            &self.canonical_decision_sha256,
            "mechanical_subset.source.canonical_decision_sha256",
        )?;
        validate_text(
            &self.source_grant_id,
            "mechanical_subset.source.source_grant_id",
        )?;
        validate_digest(
            &self.source_grant_commitment,
            "mechanical_subset.source.source_grant_commitment",
        )?;
        if self.source_graph_revision == 0 {
            return Err(AuthorityError::InvalidField(
                "mechanical_subset.source.source_graph_revision",
            ));
        }
        Ok(())
    }
}

/// One required approval/proof handle, bound to the approved action.
///
/// An approval authorizes the exact action only (I6.10 approval). A reference
/// to an existing approval record is therefore not sufficient: the approved
/// action hash must equal the digest of the action actually presented, so one
/// approval can never be reused for a different action, and an `allowed_once`
/// approval is spent by its first use.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalReference {
    /// The approval record this subset requires.
    pub approval_record_id: String,
    /// SHA-256 over the canonical bytes of the exact approved action.
    pub approved_action_hash: String,
    /// Whether the approval may authorize exactly one use.
    pub allowed_once: bool,
}

impl ApprovalReference {
    /// Validates one approval reference.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::InvalidField`] for a blank record identity or
    /// a malformed action digest.
    pub fn validate(&self) -> Result<(), AuthorityError> {
        validate_text(
            &self.approval_record_id,
            "mechanical_subset.approval.approval_record_id",
        )?;
        validate_digest(
            &self.approved_action_hash,
            "mechanical_subset.approval.approved_action_hash",
        )?;
        Ok(())
    }
}

/// The mechanically enforceable conditions the canonical source authority does
/// not itself carry.
///
/// [`MechanicalAuthoritySubset::compile`] requires every one of these to be
/// resolved. An omitted group refuses compilation; it never becomes a
/// wildcard, an "any" default, or an empty set the gate would read as
/// unrestricted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MechanicalSubsetConstraints {
    /// Named transition classes this snapshot may drive.
    pub transition_classes: Vec<String>,
    /// Exact data/observation-class ceiling labels the source admitted.
    pub data_classes: Vec<String>,
    /// Policy revision the semantic decision was taken under.
    pub policy_revision: String,
    /// Configuration revision the semantic decision was taken under.
    pub configuration_revision: String,
    /// Lease revision the semantic decision was taken under.
    pub lease_revision: String,
    /// Heartbeat cadence in milliseconds, when the source requires liveness.
    pub heartbeat_interval_ms: Option<u64>,
    /// Exact canonical source commitment.
    pub source: CanonicalSourceCommitment,
    /// Approval handles this snapshot requires before any effect.
    pub required_approvals: Vec<ApprovalReference>,
}

/// The complete immutable compiled mechanical subset of one canonical grant.
///
/// I6.10 "Kernel authority projection" field order, carried verbatim:
///
/// ```text
/// principal/session/token identity;
/// allowed named operations and transition classes;
/// exact scope/effect/data-class ceilings;
/// State Fence, policy/config/lease revisions and Authority Epoch;
/// expiry/heartbeat/revocation conditions;
/// required approval/proof handles;
/// source canonical receipt and snapshot hash.
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MechanicalAuthoritySubset {
    /// Closed schema identity.
    pub schema: String,
    /// Closed schema version.
    pub version: u16,
    /// Snapshot identity of this compiled subset. It names the projection, not
    /// the content: the content commitment is what binds the two together.
    pub governor_snapshot_id: String,
    /// Grant identity this subset admits.
    pub grant_id: String,
    /// Lineage domain.
    pub authority_root_ref: String,
    /// Holder principal identity.
    pub holder_principal: String,
    /// Session identity.
    pub session_id: String,
    /// Exact work-scope identity.
    pub scope_id: String,
    /// Capability-token identity the source issued for this admission.
    pub token_id: String,
    /// Named operations this snapshot admits.
    pub operations: Vec<String>,
    /// Named transition classes this snapshot admits.
    pub transition_classes: Vec<String>,
    /// Exact resource/scope ceiling set.
    pub scopes: Vec<String>,
    /// Effect ceiling; never above the source grant or binding ceiling.
    pub effect_ceiling: EffectClass,
    /// Proof ceiling; never above the binding ceiling.
    pub proof_ceiling: ProofCeiling,
    /// Exact data/observation-class ceiling set.
    pub data_classes: Vec<String>,
    /// Policy revision the semantic decision was taken under.
    pub policy_revision: String,
    /// Configuration revision the semantic decision was taken under.
    pub configuration_revision: String,
    /// Lease revision the semantic decision was taken under.
    pub lease_revision: String,
    /// Fence and typed authority epoch this snapshot is bound to.
    pub binding: AuthorityBinding,
    /// Logical issuance time in Unix milliseconds.
    pub issued_at_ms: i64,
    /// Logical expiry time in Unix milliseconds. `None` never expires by time.
    pub expires_at_ms: Option<i64>,
    /// Heartbeat cadence in milliseconds, when the source requires liveness.
    pub heartbeat_interval_ms: Option<u64>,
    /// One-shot use budget. An exhausted budget refuses at the point of use.
    pub max_uses: u32,
    /// Approval handles that must be satisfied before any effect.
    pub required_approvals: Vec<ApprovalReference>,
    /// Exact canonical source commitment.
    pub source: CanonicalSourceCommitment,
    /// Recorded digest over the complete compiled content.
    ///
    /// This is the ORIGINAL recorded value. It is never rewritten to match a
    /// payload, and a recomputed digest is never substituted for it.
    pub content_commitment: String,
}

impl MechanicalAuthoritySubset {
    /// Compiles the complete mechanical subset of one canonical grant record.
    ///
    /// The compiled operation and scope sets are the canonical grant's own
    /// admitted sets and the compiled ceilings are proven against the grant's
    /// ceiling, the binding's ceiling, and the grant's inherited source
    /// ceiling. An omitted, blank or duplicated constraint refuses; none of
    /// them becomes a wildcard, and no compiled value is derived from anything
    /// other than the canonical record, the presented binding, and the
    /// explicitly resolved constraints.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::InvalidField`] for a malformed, blank,
    /// duplicated or missing group, [`AuthorityError::IdentityConflict`] when
    /// the source commitment or holder disagrees with the canonical record,
    /// [`AuthorityError::FenceMismatch`] when the presented binding is not the
    /// canonical record's own binding, and
    /// [`AuthorityError::EffectCeilingExceeded`] when a ceiling exceeds the
    /// source grant, the binding, or the inherited source ceiling.
    #[allow(
        clippy::too_many_arguments,
        reason = "one compiler call names every I6.10 identity group exactly once"
    )]
    pub fn compile(
        grant: &GrantRecoveryRecord,
        governor_snapshot_id: &str,
        holder_principal: &str,
        session_id: &str,
        scope_id: &str,
        token_id: &str,
        binding: &AuthorityBinding,
        constraints: MechanicalSubsetConstraints,
    ) -> Result<Self, AuthorityError> {
        validate_text(
            governor_snapshot_id,
            "mechanical_subset.governor_snapshot_id",
        )?;
        validate_text(holder_principal, "mechanical_subset.holder_principal")?;
        validate_text(session_id, "mechanical_subset.session_id")?;
        validate_text(scope_id, "mechanical_subset.scope_id")?;
        validate_text(token_id, "mechanical_subset.token_id")?;
        constraints.source.validate()?;
        if constraints.source.source_grant_id != grant.grant_id {
            return Err(AuthorityError::IdentityConflict);
        }
        if grant.holder != holder_principal {
            return Err(AuthorityError::IdentityConflict);
        }
        if grant.binding != *binding {
            return Err(AuthorityError::FenceMismatch);
        }
        if grant.max_uses == 0 {
            return Err(AuthorityError::InvalidField("mechanical_subset.max_uses"));
        }
        if grant.expires_at <= grant.issued_at {
            return Err(AuthorityError::InvalidField(
                "mechanical_subset.expires_at_ms",
            ));
        }
        let issued_at_ms = i64::try_from(grant.issued_at)
            .map_err(|_| AuthorityError::InvalidField("mechanical_subset.issued_at_ms"))?;
        let expires_at_ms = i64::try_from(grant.expires_at)
            .map_err(|_| AuthorityError::InvalidField("mechanical_subset.expires_at_ms"))?;

        let transition_classes = closed_set(
            &constraints.transition_classes,
            "mechanical_subset.transition_classes",
        )?;
        let data_classes = closed_set(&constraints.data_classes, "mechanical_subset.data_classes")?;
        let required_approvals = closed_approvals(&constraints.required_approvals)?;
        validate_text(
            &constraints.policy_revision,
            "mechanical_subset.policy_revision",
        )?;
        validate_text(
            &constraints.configuration_revision,
            "mechanical_subset.configuration_revision",
        )?;
        validate_text(
            &constraints.lease_revision,
            "mechanical_subset.lease_revision",
        )?;

        // The three dimensions the canonical source authority itself enforces.
        let operations = closed_set(&grant.allowed_operations, "mechanical_subset.operations")?;
        let scopes = closed_set(&grant.allowed_resources, "mechanical_subset.scopes")?;
        if grant.max_effect > binding.allowed_effect {
            return Err(AuthorityError::EffectCeilingExceeded);
        }
        if let Some(source_ceiling) = grant.inherited_source_ceiling
            && grant.max_effect as u8 > source_effect_rank(source_ceiling)
        {
            return Err(AuthorityError::EffectCeilingExceeded);
        }

        let mut subset = Self {
            schema: MECHANICAL_SUBSET_SCHEMA.to_owned(),
            version: MECHANICAL_SUBSET_VERSION,
            governor_snapshot_id: governor_snapshot_id.to_owned(),
            grant_id: grant.grant_id.clone(),
            authority_root_ref: grant.authority_root_ref.clone(),
            holder_principal: holder_principal.to_owned(),
            session_id: session_id.to_owned(),
            scope_id: scope_id.to_owned(),
            token_id: token_id.to_owned(),
            operations,
            transition_classes,
            scopes,
            effect_ceiling: grant.max_effect,
            proof_ceiling: binding.proof_ceiling,
            data_classes,
            policy_revision: constraints.policy_revision,
            configuration_revision: constraints.configuration_revision,
            lease_revision: constraints.lease_revision,
            binding: binding.clone(),
            issued_at_ms,
            expires_at_ms: Some(expires_at_ms),
            heartbeat_interval_ms: constraints.heartbeat_interval_ms,
            max_uses: grant.max_uses,
            required_approvals,
            source: constraints.source,
            // Replaced immediately below. The digest input deliberately excludes
            // this field, so the recorded value is a fixed point of the digest
            // over every other field.
            content_commitment: String::new(),
        };
        subset.content_commitment = subset.content_commitment()?;
        Ok(subset)
    }

    /// Recomputes the commitment over the complete compiled content.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::InvalidField`] when canonical serialization
    /// fails.
    pub fn content_commitment(&self) -> Result<String, AuthorityError> {
        let bytes = canonical_json_bytes(&MechanicalSubsetDigestInput {
            domain_separator: MECHANICAL_SUBSET_DIGEST_DOMAIN,
            schema: &self.schema,
            version: self.version,
            governor_snapshot_id: &self.governor_snapshot_id,
            grant_id: &self.grant_id,
            authority_root_ref: &self.authority_root_ref,
            holder_principal: &self.holder_principal,
            session_id: &self.session_id,
            scope_id: &self.scope_id,
            token_id: &self.token_id,
            operations: &self.operations,
            transition_classes: &self.transition_classes,
            scopes: &self.scopes,
            effect_ceiling: &self.effect_ceiling,
            proof_ceiling: &self.proof_ceiling,
            data_classes: &self.data_classes,
            policy_revision: &self.policy_revision,
            configuration_revision: &self.configuration_revision,
            lease_revision: &self.lease_revision,
            binding: &self.binding,
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self.expires_at_ms,
            heartbeat_interval_ms: self.heartbeat_interval_ms,
            max_uses: self.max_uses,
            required_approvals: &self.required_approvals,
            source: &self.source,
        })
        .map_err(|_| AuthorityError::InvalidField("mechanical_subset.content_commitment"))?;
        Ok(sha256_hex(&bytes))
    }

    /// Proves this payload still matches its RECORDED content commitment.
    ///
    /// This is the content verification performed at the point of use: the
    /// recorded value is the expectation and the recomputed digest is the
    /// observation. A recomputed digest is never substituted for a missing or
    /// disagreeing recorded value, and the recorded value is never rewritten to
    /// match the payload.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::StaleTransitionEvidence`] for a foreign
    /// schema/version, a malformed recorded commitment, or a payload whose
    /// content no longer hashes to it.
    pub fn verify_recorded_commitment(&self) -> Result<(), AuthorityError> {
        if self.schema != MECHANICAL_SUBSET_SCHEMA || self.version != MECHANICAL_SUBSET_VERSION {
            return Err(AuthorityError::StaleTransitionEvidence(
                "mechanical_subset.schema_version",
            ));
        }
        validate_digest(
            &self.content_commitment,
            "mechanical_subset.content_commitment",
        )?;
        if self.content_commitment()? != self.content_commitment {
            return Err(AuthorityError::StaleTransitionEvidence(
                "mechanical_subset.content_commitment",
            ));
        }
        Ok(())
    }

    /// Mechanically decides one presented use site against this subset.
    ///
    /// This is the whole point of the compiled projection: the decision needs
    /// no semantic daemon, no canonical-store read, and no policy
    /// re-derivation. Every clause is a comparison against committed content,
    /// and the current revocation revision is supplied by the caller because
    /// revocation state is the mechanical owner's current state, not part of
    /// the immutable payload.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::StaleTransitionEvidence`] when the payload no
    /// longer matches its recorded commitment,
    /// [`AuthorityError::EpochMismatch`] when the presented typed epoch belongs
    /// to a different lineage, [`AuthorityError::FenceMismatch`] when the
    /// presented binding is not this snapshot's binding,
    /// [`AuthorityError::Revoked`] when a revocation revision newer than the
    /// committed source revision has already fenced this snapshot,
    /// [`AuthorityError::Expired`] at or after the committed expiry or past the
    /// committed heartbeat cadence, [`AuthorityError::UseBudgetExhausted`] when
    /// the committed one-shot budget is exhausted,
    /// [`AuthorityError::UnauthorizedOperation`] for a use site outside a
    /// committed operation or transition-class set,
    /// [`AuthorityError::UnauthorizedResource`] for a resource outside the
    /// committed scope set, [`AuthorityError::UnauthorizedDataClass`] for a
    /// data class outside the committed data-class set,
    /// [`AuthorityError::EffectCeilingExceeded`] for an effect or proof above
    /// a committed ceiling, and [`AuthorityError::ReceiptMismatch`] when a
    /// required approval is absent or does not bind the presented action.
    pub fn admits(
        &self,
        site: &AuthorityUseSite,
        current_revocation_revision: u64,
    ) -> Result<MechanicalAdmission, AuthorityError> {
        self.verify_recorded_commitment()?;
        if !site
            .authority_epoch
            .is_same_authority(&self.binding.authority_epoch)
        {
            return Err(AuthorityError::EpochMismatch);
        }
        if site.state_fence != self.binding.state_fence || site.binding != self.binding {
            return Err(AuthorityError::FenceMismatch);
        }
        if site.holder_principal != self.holder_principal
            || site.session_id != self.session_id
            || site.scope_id != self.scope_id
        {
            return Err(AuthorityError::IdentityConflict);
        }
        // A revocation at or after the revision this snapshot was compiled from
        // has already fenced it. A later, newer activation is a NEW snapshot
        // with its own revision and its own exact identity; it is never this
        // one resurrected.
        if current_revocation_revision >= self.source.source_graph_revision {
            return Err(AuthorityError::Revoked);
        }
        if let Some(expires) = self.expires_at_ms
            && site.now_ms >= expires
        {
            return Err(AuthorityError::Expired);
        }
        if let Some(cadence) = self.heartbeat_interval_ms
            && site.heartbeat_age_ms > cadence
        {
            return Err(AuthorityError::Expired);
        }
        if site.consumed_uses >= self.max_uses {
            return Err(AuthorityError::UseBudgetExhausted);
        }
        if !self
            .operations
            .iter()
            .any(|name| name == &site.operation_name)
        {
            return Err(AuthorityError::UnauthorizedOperation);
        }
        if !self
            .transition_classes
            .iter()
            .any(|class| class == &site.transition_class)
        {
            return Err(AuthorityError::UnauthorizedOperation);
        }
        if !self.scopes.iter().any(|scope| scope == &site.resource_ref) {
            return Err(AuthorityError::UnauthorizedResource);
        }
        if !self
            .data_classes
            .iter()
            .any(|class| class == &site.data_class)
        {
            return Err(AuthorityError::UnauthorizedDataClass);
        }
        if site.effect > self.effect_ceiling {
            return Err(AuthorityError::EffectCeilingExceeded);
        }
        if !site.proof_ceiling.is_at_most(self.proof_ceiling) {
            return Err(AuthorityError::EffectCeilingExceeded);
        }
        // An approval reference binds the APPROVED ACTION, not merely an
        // existing approval identity.
        let satisfied = self.required_approvals.iter().any(|approval| {
            approval.approved_action_hash == site.action_canonical_hash
                && (!approval.allowed_once || site.consumed_uses == 0)
        });
        if !satisfied {
            return Err(AuthorityError::ReceiptMismatch);
        }
        Ok(MechanicalAdmission {
            governor_snapshot_id: self.governor_snapshot_id.clone(),
            content_commitment: self.content_commitment.clone(),
            next_allowed_uses: self.max_uses - site.consumed_uses - 1,
        })
    }
}

/// One presented use site checked against a compiled mechanical subset.
///
/// The consumer supplies the CURRENT values; the subset supplies the compiled
/// commitments. Nothing here is derived from the subset, so a consumer can
/// never satisfy the gate by re-reading its own authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityUseSite {
    /// Holder principal presenting the use.
    pub holder_principal: String,
    /// Session presenting the use.
    pub session_id: String,
    /// Exact work scope presenting the use.
    pub scope_id: String,
    /// Current typed authority epoch.
    pub authority_epoch: EpochId,
    /// Current State Fence.
    pub state_fence: StateFence,
    /// Current full binding presented by the consumer.
    pub binding: AuthorityBinding,
    /// Named operation requested.
    pub operation_name: String,
    /// Transition class requested.
    pub transition_class: String,
    /// Exact resource reference requested.
    pub resource_ref: String,
    /// Data/observation class of the requested data.
    pub data_class: String,
    /// Effect requested.
    pub effect: EffectClass,
    /// Proof ceiling the consumer claims.
    pub proof_ceiling: ProofCeiling,
    /// SHA-256 over the canonical bytes of the exact requested action.
    pub action_canonical_hash: String,
    /// Current observation time in Unix milliseconds.
    pub now_ms: i64,
    /// Milliseconds since the last accepted heartbeat. Ignored when the
    /// compiled subset declared no heartbeat condition.
    pub heartbeat_age_ms: u64,
    /// Uses already consumed under this snapshot.
    pub consumed_uses: u32,
}

/// Mechanical admission of one use site against a committed subset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MechanicalAdmission {
    /// Governor owner snapshot identity the admission was decided under.
    pub governor_snapshot_id: String,
    /// Recorded content commitment the admission was decided under.
    pub content_commitment: String,
    /// Uses still available after this one is consumed.
    pub next_allowed_uses: u32,
}

/// Canonical digest preimage of one compiled mechanical subset.
///
/// `content_commitment` is deliberately absent: the recorded value is a fixed
/// point of this function over every other field.
#[derive(Serialize)]
struct MechanicalSubsetDigestInput<'a> {
    domain_separator: &'static str,
    schema: &'a str,
    version: u16,
    governor_snapshot_id: &'a str,
    grant_id: &'a str,
    authority_root_ref: &'a str,
    holder_principal: &'a str,
    session_id: &'a str,
    scope_id: &'a str,
    token_id: &'a str,
    operations: &'a [String],
    transition_classes: &'a [String],
    scopes: &'a [String],
    effect_ceiling: &'a EffectClass,
    proof_ceiling: &'a ProofCeiling,
    data_classes: &'a [String],
    policy_revision: &'a str,
    configuration_revision: &'a str,
    lease_revision: &'a str,
    binding: &'a AuthorityBinding,
    issued_at_ms: i64,
    expires_at_ms: Option<i64>,
    heartbeat_interval_ms: Option<u64>,
    max_uses: u32,
    required_approvals: &'a [ApprovalReference],
    source: &'a CanonicalSourceCommitment,
}

/// Normalizes one committed named set: non-empty, valid, and duplicate-free.
///
/// A duplicated entry is refused rather than silently collapsed, because a set
/// that normalizes differently on two compilations would make the content
/// commitment depend on how it was spelled. Sorted order is not required:
/// canonical JSON of the array as presented is the commitment input, so a
/// reordered set is a different commitment and therefore a different snapshot,
/// which is the fail-closed direction.
fn closed_set(values: &[String], field: &'static str) -> Result<Vec<String>, AuthorityError> {
    if values.is_empty() {
        return Err(AuthorityError::InvalidField(field));
    }
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        validate_text(value, field)?;
        if !seen.insert(value) {
            return Err(AuthorityError::InvalidField(field));
        }
    }
    Ok(values.to_vec())
}

/// Validates the required approval handles, refusing an absent set.
fn closed_approvals(
    approvals: &[ApprovalReference],
) -> Result<Vec<ApprovalReference>, AuthorityError> {
    if approvals.is_empty() {
        return Err(AuthorityError::InvalidField(
            "mechanical_subset.required_approvals",
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for approval in approvals {
        approval.validate()?;
        if !seen.insert(approval.approval_record_id.as_str()) {
            return Err(AuthorityError::InvalidField(
                "mechanical_subset.required_approvals",
            ));
        }
    }
    Ok(approvals.to_vec())
}
