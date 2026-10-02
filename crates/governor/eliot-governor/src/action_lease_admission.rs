//! Governor-owned action lease admission for Instrument Registry writes.
//!
//! The producer consumes current canonical grant state and the exact
//! activation/subset pair read from the live Kernel owner. It returns a
//! replacement registration ledger for the Registry owner to commit atomically
//! with the proposed instrument snapshot. This module performs no I/O and does
//! not manufacture canonical or Kernel evidence.

use std::collections::{BTreeMap, BTreeSet};

use eliot_authority::{
    ActionContract, ActionLease, ActionLeaseRecoveryRecord, AuthorityError, AuthorityUseSite,
    AuthorizedEffect, AuthorizedEffectRecoveryRecord, EffectAuthorizer,
    EffectAuthorizerRecoverySnapshot, EffectiveCapabilityPath, EffectiveCapabilitySnapshot,
    GrantGraphRecoverySnapshot, GrantId, LeaseId, LogicalTime, MechanicalAuthoritySubset,
    ProposedEffect, ReceiptObligation,
};
use eliot_contracts::canonical_json_bytes;
use eliot_kernel_core::CommittedAuthorityActivation as KernelCommittedAuthorityActivation;
use eliot_ors::OperationIdentity;
use eliot_protocol::{ProtocolError, RequestIdentity};
use eliot_receipts::{
    AuthorityBinding, OperationBinding, SessionBinding, StateFence, WorkScopeBinding,
};
use eliot_session::AgentSession;
use eliot_workscope::WorkScopeBindingSnapshot;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::authority_recovery::AuthorityOwner;

/// Closed registration-authority ledger identity persisted by the Registry.
pub const REGISTRATION_AUTHORITY_LEDGER_SCHEMA: &str =
    "eliot.governor.registration-authority-ledger";
/// Closed registration-authority ledger version.
pub const REGISTRATION_AUTHORITY_LEDGER_VERSION: u16 = 2;

/// Exact source and Kernel activation references for one grant on an admitted
/// delegation path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistrationGrantUseReference {
    pub grant_id: String,
    pub canonical_decision_ref: String,
    pub canonical_decision_sha256: String,
    pub source_grant_commitment: String,
    pub source_graph_revision: u64,
    pub mechanical_subset_commitment: String,
    pub kernel_snapshot_id: String,
    pub kernel_activation_id: String,
    pub ors_record_id: String,
    pub ors_subject_id: String,
}

/// Durable per-grant use ceiling. Counters are bound to the exact source and
/// activation generation so retries and restarts cannot reset a grant budget.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistrationGrantUseCounter {
    pub source: RegistrationGrantUseReference,
    pub max_uses: u32,
    pub consumed_uses: u32,
}

/// Exact lease authorization retained with its operation and source path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistrationActionLeaseRecord {
    pub request_identity: RequestIdentity,
    pub action_contract: ActionContract,
    pub operation: OperationBinding,
    pub expected_registry_revision: u64,
    pub operation_name: String,
    pub resource_ref: String,
    pub canonical_payload_sha256: String,
    pub executor_boundary: String,
    pub lease: ActionLeaseRecoveryRecord,
    pub authorization: AuthorizedEffectRecoveryRecord,
    pub supporting_grant_path: Vec<RegistrationGrantUseReference>,
    pub admitted_use_sites: Vec<RegistrationUseSiteRecord>,
    /// Exact validated WorkScope owner snapshot at registration. Its
    /// `root_identity` is an opaque owner reference, not a filesystem path.
    pub work_scope_binding_snapshot: WorkScopeBindingSnapshot,
}

/// Exact mechanical use-site facts captured when a new use was admitted.
/// `consumed_uses` is the pre-admission count, retained for exact retry proof.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistrationUseSiteRecord {
    pub source: RegistrationGrantUseReference,
    pub holder_principal: String,
    pub session_id: String,
    pub scope_id: String,
    pub authority_epoch: eliot_contracts::EpochId,
    pub state_fence: StateFence,
    pub binding: AuthorityBinding,
    pub operation_name: String,
    pub transition_class: String,
    pub resource_ref: String,
    pub data_class: String,
    pub effect: eliot_receipts::EffectClass,
    pub proof_ceiling: eliot_receipts::ProofCeiling,
    pub action_canonical_hash: String,
    pub admitted_at_ms: i64,
    pub heartbeat_age_ms: u64,
    pub consumed_uses: u32,
}

/// Complete owner-retained action admission ledger. The Registry reads and
/// replaces this closed value atomically with its instrument-spec snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistrationAuthorityLedger {
    pub schema: String,
    pub version: u16,
    pub grant_uses: Vec<RegistrationGrantUseCounter>,
    pub leases: Vec<RegistrationActionLeaseRecord>,
}

/// Canonical registry-owner read state. `Absent` is valid only when the
/// registry read proves that no registration row exists; an existing row with
/// missing authority data is not represented by this enum.
pub enum RegistrationAuthorityOwnerRead<'a> {
    Absent,
    Present(&'a str),
}

/// Owned copy of the exact canonical registry authority read used to produce
/// a candidate, retained so the Registry can bind CAS to the same pre-read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistrationAuthorityOwnerReadRecord {
    Absent,
    Present(String),
}

impl RegistrationAuthorityLedger {
    /// Decodes the exact current owner value. Missing owner data is not an
    /// empty ledger, and unknown fields are refused by the closed wire type.
    pub fn from_current_owner_json(value: &str) -> Result<Self, ActionLeaseAdmissionError> {
        let ledger: Self = serde_json::from_str(value)?;
        ledger.validate()?;
        Ok(ledger)
    }

    /// Validates closed schema identity, ordering, counters, lease state, and
    /// the one-to-one durable accounting relation between leases and grants.
    pub fn validate(&self) -> Result<(), ActionLeaseAdmissionError> {
        if self.schema != REGISTRATION_AUTHORITY_LEDGER_SCHEMA
            || self.version != REGISTRATION_AUTHORITY_LEDGER_VERSION
        {
            return Err(ActionLeaseAdmissionError::InvalidLedger(
                "schema or version mismatch",
            ));
        }
        if self
            .grant_uses
            .windows(2)
            .any(|pair| pair[0].source >= pair[1].source)
        {
            return Err(ActionLeaseAdmissionError::InvalidLedger(
                "grant-use rows must be unique and ordered",
            ));
        }
        let mut lease_keys = Vec::with_capacity(self.leases.len());
        let mut counted = BTreeMap::<RegistrationGrantUseReference, u32>::new();
        let mut grant_totals = BTreeMap::<String, (u32, u32)>::new();
        for counter in &self.grant_uses {
            if counter.max_uses == 0 || counter.consumed_uses > counter.max_uses {
                return Err(ActionLeaseAdmissionError::InvalidLedger(
                    "grant-use counter exceeds its retained ceiling",
                ));
            }
            validate_source_reference(&counter.source)?;
            let total = grant_totals
                .entry(counter.source.grant_id.clone())
                .or_insert((0, counter.max_uses));
            total.0 = total
                .0
                .checked_add(counter.consumed_uses)
                .ok_or(ActionLeaseAdmissionError::CounterOverflow)?;
            total.1 = total.1.min(counter.max_uses);
        }
        for record in &self.leases {
            record
                .request_identity
                .validate()
                .map_err(ActionLeaseAdmissionError::Protocol)?;
            let key = record.operation.idempotency_key.clone();
            if record.request_identity.idempotency_key != key
                || record.operation.request_id.as_str()
                    != record.request_identity.request.metadata.request_id.as_str()
                || record.operation.state_fence != record.request_identity.request.state_fence
                || record.lease.exact_idempotency_key != key
                || record.authorization.idempotency_key != key
                || record.authorization.operation != record.operation
                || record.authorization.action_id != record.action_contract.action_id
                || record.authorization.operation_name != record.operation_name
                || record.authorization.resource_ref != record.resource_ref
                || record.authorization.canonical_payload_sha256 != record.canonical_payload_sha256
                || record.authorization.executor_boundary != record.executor_boundary
                || record.authorization.lease_id != record.lease.lease_id
                || record.lease.lease_id != record.operation.operation_id.as_str()
                || record.work_scope_binding_snapshot.validate().is_err()
                || record.work_scope_binding_snapshot.state_fence != record.operation.state_fence
                || record.work_scope_binding_snapshot.binding.scope.scope_ref
                    != record.lease.work_scope.scope_id.as_str()
                || record.work_scope_binding_snapshot.binding.scope.generation
                    != record.lease.work_scope.resource_generation.value()
                || record.supporting_grant_path.is_empty()
                || record.admitted_use_sites.len() != 1
            {
                return Err(ActionLeaseAdmissionError::InvalidLedger(
                    "retained lease identity is inconsistent",
                ));
            }
            ActionLease::from_recovery_record(record.lease.clone())?;
            ProposedEffect::new(
                record.authorization.action_id.clone(),
                record.authorization.operation.clone(),
                record.authorization.operation_name.clone(),
                record.authorization.resource_ref.clone(),
                record.authorization.canonical_payload_sha256.clone(),
            )?;
            for source in &record.supporting_grant_path {
                validate_source_reference(source)?;
                let Some(counter) = self.grant_uses.iter().find(|row| row.source == *source) else {
                    return Err(ActionLeaseAdmissionError::InvalidLedger(
                        "lease references an unretained grant-use row",
                    ));
                };
                if counter.max_uses == 0 {
                    return Err(ActionLeaseAdmissionError::InvalidLedger(
                        "lease references a zero-use grant",
                    ));
                }
                let count = counted.entry(source.clone()).or_default();
                *count = count
                    .checked_add(1)
                    .ok_or(ActionLeaseAdmissionError::CounterOverflow)?;
            }
            let use_site = &record.admitted_use_sites[0];
            let leaf_source = record.supporting_grant_path.last().ok_or(
                ActionLeaseAdmissionError::InvalidLedger("supporting path is empty"),
            )?;
            let leaf_counter = self
                .grant_uses
                .iter()
                .find(|row| row.source == *leaf_source)
                .ok_or(ActionLeaseAdmissionError::InvalidLedger(
                    "leaf use-site references an unretained grant-use row",
                ))?;
            if use_site.source != *leaf_source
                || use_site.holder_principal != record.lease.holder
                || use_site.session_id != record.lease.session.session_id.as_str()
                || use_site.scope_id != record.lease.work_scope.scope_id.as_str()
                || use_site.state_fence != record.operation.state_fence
                || use_site.binding.state_fence != record.operation.state_fence
                || use_site.authority_epoch != use_site.binding.authority_epoch
                || use_site.binding != record.lease.authority_binding
                || use_site.transition_class.trim().is_empty()
                || use_site.data_class.trim().is_empty()
                || use_site.operation_name != record.operation_name
                || use_site.resource_ref != record.resource_ref
                || use_site.effect != record.operation.effect
                || use_site.action_canonical_hash != record.canonical_payload_sha256
                || use_site
                    .consumed_uses
                    .checked_add(1)
                    .map_or(true, |used| used > leaf_counter.max_uses)
            {
                return Err(ActionLeaseAdmissionError::InvalidLedger(
                    "retained mechanical use-site binding is inconsistent",
                ));
            }
            lease_keys.push(key);
        }
        if lease_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ActionLeaseAdmissionError::InvalidLedger(
                "lease rows must be unique and ordered",
            ));
        }
        for counter in &self.grant_uses {
            if counted.get(&counter.source).copied().unwrap_or(0) != counter.consumed_uses {
                return Err(ActionLeaseAdmissionError::InvalidLedger(
                    "grant-use counter disagrees with retained lease history",
                ));
            }
        }
        if grant_totals
            .values()
            .any(|(consumed, ceiling)| consumed > ceiling)
        {
            return Err(ActionLeaseAdmissionError::InvalidLedger(
                "grant-use history exceeds a retained grant ceiling",
            ));
        }
        Ok(())
    }

    /// Returns the canonical UTF-8 JSON bytes used by the Registry write.
    pub fn to_owner_json(&self) -> Result<String, ActionLeaseAdmissionError> {
        self.validate()?;
        let bytes =
            canonical_json_bytes(self).map_err(|_| ActionLeaseAdmissionError::Serialization)?;
        String::from_utf8(bytes).map_err(|_| ActionLeaseAdmissionError::Serialization)
    }

    /// Reads the original expected local Registry revision for an exact
    /// idempotency key from this validated retained owner ledger.
    pub fn retained_expected_registry_revision(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<u64>, ActionLeaseAdmissionError> {
        self.validate()?;
        Ok(self
            .leases
            .iter()
            .find(|record| record.operation.idempotency_key == idempotency_key)
            .map(|record| record.expected_registry_revision))
    }
}

impl RegistrationUseSiteRecord {
    fn from_source_and_site(
        source: RegistrationGrantUseReference,
        site: &AuthorityUseSite,
    ) -> Self {
        Self {
            source,
            holder_principal: site.holder_principal.clone(),
            session_id: site.session_id.clone(),
            scope_id: site.scope_id.clone(),
            authority_epoch: site.authority_epoch.clone(),
            state_fence: site.state_fence.clone(),
            binding: site.binding.clone(),
            operation_name: site.operation_name.clone(),
            transition_class: site.transition_class.clone(),
            resource_ref: site.resource_ref.clone(),
            data_class: site.data_class.clone(),
            effect: site.effect,
            proof_ceiling: site.proof_ceiling,
            action_canonical_hash: site.action_canonical_hash.clone(),
            admitted_at_ms: site.now_ms,
            heartbeat_age_ms: site.heartbeat_age_ms,
            consumed_uses: site.consumed_uses,
        }
    }

    fn matches_current_context(&self, site: &AuthorityUseSite) -> bool {
        self.holder_principal == site.holder_principal
            && self.session_id == site.session_id
            && self.scope_id == site.scope_id
            && self.authority_epoch == site.authority_epoch
            && self.state_fence == site.state_fence
            && self.binding == site.binding
            && self.operation_name == site.operation_name
            && self.transition_class == site.transition_class
            && self.resource_ref == site.resource_ref
            && self.data_class == site.data_class
            && self.effect == site.effect
            && self.proof_ceiling == site.proof_ceiling
            && self.action_canonical_hash == site.action_canonical_hash
    }
}

/// One exact pair returned by the current Kernel activation owner read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentGrantActivationEvidence {
    pub activation: KernelCommittedAuthorityActivation,
    pub mechanical_subset: MechanicalAuthoritySubset,
    pub current_revocation_revision: u64,
}

/// Inputs from the authenticated caller and current Governor/Kernel owners.
pub struct ActionLeaseAdmissionInput<'a> {
    pub holder_principal: &'a str,
    pub request_identity: &'a RequestIdentity,
    pub operation_identity: &'a OperationIdentity,
    pub operation: OperationBinding,
    /// Original request's expected local Registry revision, bound into its
    /// canonical request payload and retained for exact idempotent replay.
    pub expected_registry_revision: u64,
    pub action_contract: &'a ActionContract,
    pub operation_name: &'a str,
    pub resource_ref: &'a str,
    /// Exact canonical digest of the registration wire payload, computed by
    /// its owner after the action-contract checks.
    pub canonical_payload_sha256: &'a str,
    pub executor_boundary: &'a str,
    pub authority_owner: &'a AuthorityOwner,
    pub effective_capabilities: &'a EffectiveCapabilitySnapshot,
    pub activation_evidence: &'a [CurrentGrantActivationEvidence],
    pub work_scope: &'a WorkScopeBinding,
    pub work_scope_binding_snapshot: &'a WorkScopeBindingSnapshot,
    pub session: &'a SessionBinding,
    pub agent_session: &'a AgentSession,
    pub now: LogicalTime,
    pub registration_authority_owner_read: RegistrationAuthorityOwnerRead<'a>,
    pub effect_authorizer: &'a EffectAuthorizer,
}

/// Candidate result. The caller must durably commit both owner snapshots
/// before making `authorized_effect` available to any executor.
#[derive(Clone, Debug)]
pub struct ActionLeaseAdmissionCandidate {
    operation_identity: OperationIdentity,
    expected_registry_revision: u64,
    action_lease: ActionLease,
    authorized_effect: AuthorizedEffect,
    next_effect_authorizer: EffectAuthorizer,
    effect_authorizer: EffectAuthorizerRecoverySnapshot,
    source_registration_authority_read: RegistrationAuthorityOwnerReadRecord,
    registration_authority_json: String,
    supporting_grant_path: Vec<RegistrationGrantUseReference>,
}

impl ActionLeaseAdmissionCandidate {
    pub fn operation_identity(&self) -> &OperationIdentity {
        &self.operation_identity
    }

    pub fn expected_registry_revision(&self) -> u64 {
        self.expected_registry_revision
    }

    pub fn action_lease(&self) -> &ActionLease {
        &self.action_lease
    }

    pub fn authorized_effect(&self) -> &AuthorizedEffect {
        &self.authorized_effect
    }

    pub fn effect_authorizer_recovery(&self) -> &EffectAuthorizerRecoverySnapshot {
        &self.effect_authorizer
    }

    /// Next live authorizer value. Install only after the owning durable
    /// authority commit succeeds.
    pub fn next_effect_authorizer(&self) -> &EffectAuthorizer {
        &self.next_effect_authorizer
    }

    pub fn registration_authority_json(&self) -> &str {
        &self.registration_authority_json
    }

    pub fn supporting_grant_path(&self) -> &[RegistrationGrantUseReference] {
        &self.supporting_grant_path
    }

    pub fn source_registration_authority_read(&self) -> &RegistrationAuthorityOwnerReadRecord {
        &self.source_registration_authority_read
    }
}

/// Prepares one real Governor action lease and its durable registration
/// ledger replacement from current canonical grant and Kernel activation data.
pub fn admit_registration_action(
    input: ActionLeaseAdmissionInput<'_>,
) -> Result<ActionLeaseAdmissionCandidate, ActionLeaseAdmissionError> {
    validate_invocation(&input)?;
    let source_registration_authority_read = match &input.registration_authority_owner_read {
        RegistrationAuthorityOwnerRead::Absent => RegistrationAuthorityOwnerReadRecord::Absent,
        RegistrationAuthorityOwnerRead::Present(value) => {
            RegistrationAuthorityOwnerReadRecord::Present((*value).to_owned())
        }
    };
    if matches!(
        &input.registration_authority_owner_read,
        RegistrationAuthorityOwnerRead::Absent
    ) && input.expected_registry_revision != 0
    {
        return Err(AuthorityError::IdentityConflict.into());
    }
    let mut ledger = match input.registration_authority_owner_read {
        RegistrationAuthorityOwnerRead::Absent => RegistrationAuthorityLedger {
            schema: REGISTRATION_AUTHORITY_LEDGER_SCHEMA.to_owned(),
            version: REGISTRATION_AUTHORITY_LEDGER_VERSION,
            grant_uses: Vec::new(),
            leases: Vec::new(),
        },
        RegistrationAuthorityOwnerRead::Present(value) => {
            RegistrationAuthorityLedger::from_current_owner_json(value)?
        }
    };
    let graph_snapshot = input.authority_owner.grants.recovery_snapshot()?;
    graph_snapshot.validate()?;
    if input.effective_capabilities.grant_graph_revision()
        != input.authority_owner.grants.revision()
    {
        return Err(AuthorityError::StaleEffectAuthority("effective_grant_graph_revision").into());
    }
    input
        .effective_capabilities
        .validate_context(input.work_scope, input.session)?;
    let existing = ledger
        .leases
        .iter()
        .find(|record| record.operation.idempotency_key == input.operation.idempotency_key);
    let path = input.effective_capabilities.supporting_path(
        input.operation_name,
        input.resource_ref,
        input.operation.effect,
    )?;
    // A matching idempotency key is only a replay candidate. The branch below
    // must still prove the complete retained operation and current use-site
    // context before returning its original lease; it never adds a new use.
    let (supporting_grant_path, use_sites) =
        validate_path_evidence(&input, &graph_snapshot, path, &ledger, existing.is_some())?;
    let checked_proposal = input.action_contract.compile_proposal(
        input.operation.clone(),
        input.operation_name,
        input.resource_ref,
    )?;
    let proposed = ProposedEffect::new(
        checked_proposal.action_id,
        checked_proposal.operation,
        checked_proposal.operation_name,
        checked_proposal.resource_ref,
        input.canonical_payload_sha256,
    )?;

    if let Some(record) = existing {
        if record.request_identity != *input.request_identity
            || record.action_contract != *input.action_contract
            || record.operation != input.operation
            || record.expected_registry_revision != input.expected_registry_revision
            || record.operation_name != input.operation_name
            || record.resource_ref != input.resource_ref
            || record.executor_boundary != input.executor_boundary
            || record.work_scope_binding_snapshot != *input.work_scope_binding_snapshot
            || record.supporting_grant_path != supporting_grant_path
            || !record
                .admitted_use_sites
                .iter()
                .zip(&use_sites)
                .all(|(retained, current)| retained.matches_current_context(current))
        {
            return Err(AuthorityError::IdentityConflict.into());
        }
        let mut lease = ActionLease::from_recovery_record(record.lease.clone())?;
        let authorizer_snapshot = input.effect_authorizer.snapshot()?;
        let mut authorizer = match authorizer_snapshot
            .records
            .iter()
            .find(|stored| stored.idempotency_key == record.authorization.idempotency_key)
        {
            Some(stored) if stored != &record.authorization => {
                return Err(AuthorityError::IdentityConflict.into());
            }
            Some(_) => input.effect_authorizer.clone(),
            None => {
                let mut authorizer_snapshot = authorizer_snapshot;
                authorizer_snapshot
                    .records
                    .push(record.authorization.clone());
                authorizer_snapshot
                    .records
                    .sort_by(|left, right| left.idempotency_key.cmp(&right.idempotency_key));
                EffectAuthorizer::from_snapshot(authorizer_snapshot)?
            }
        };
        let authorized_effect = authorizer.authorize(
            &mut lease,
            proposed,
            input.executor_boundary,
            input.work_scope,
            input.session,
            input.now,
        )?;
        if !authorization_matches_record(&authorized_effect, record) {
            return Err(AuthorityError::IdentityConflict.into());
        }
        return Ok(ActionLeaseAdmissionCandidate {
            operation_identity: input.operation_identity.clone(),
            expected_registry_revision: record.expected_registry_revision,
            action_lease: lease,
            authorized_effect,
            next_effect_authorizer: authorizer.clone(),
            effect_authorizer: authorizer.snapshot()?,
            source_registration_authority_read,
            registration_authority_json: ledger.to_owner_json()?,
            supporting_grant_path,
        });
    }

    for source in &supporting_grant_path {
        let max_uses = source_max_uses(source, &graph_snapshot)?;
        let already_consumed = ledger
            .grant_uses
            .iter()
            .filter(|row| row.source.grant_id == source.grant_id)
            .try_fold(0_u32, |total, row| total.checked_add(row.consumed_uses))
            .ok_or(ActionLeaseAdmissionError::CounterOverflow)?;
        if let Some(counter) = ledger.grant_uses.iter().find(|row| row.source == *source) {
            if counter.max_uses != max_uses {
                return Err(AuthorityError::IdentityConflict.into());
            }
        }
        if already_consumed >= max_uses {
            return Err(AuthorityError::UseBudgetExhausted.into());
        }
    }

    let leaf_source = supporting_grant_path
        .last()
        .ok_or(AuthorityError::NoEffectivePath)?;
    let leaf_evidence = input
        .activation_evidence
        .iter()
        .find(|evidence| evidence.activation.ors_subject_id == leaf_source.grant_id)
        .ok_or(AuthorityError::StaleEffectAuthority(
            "kernel_activation_absent",
        ))?;
    leaf_evidence.mechanical_subset.admits(
        use_sites.first().ok_or(AuthorityError::NoEffectivePath)?,
        leaf_evidence.current_revocation_revision,
    )?;

    // Operation identity is the lease allocation. A GrantId is never reused
    // or translated into a lease identity.
    let lease_id = LeaseId::new(input.operation.operation_id.as_str().to_owned())?;
    let obligations = vec![
        ReceiptObligation::CanonicalEffectReceipt,
        ReceiptObligation::Named(input.action_contract.verifier_ref.clone()),
    ];
    let mut lease = input.effective_capabilities.issue_action_lease(
        lease_id,
        input.operation.idempotency_key.clone(),
        input.operation_name,
        input.resource_ref,
        input.operation.effect,
        obligations,
    )?;
    let mut authorizer = input.effect_authorizer.clone();
    let authorized_effect = authorizer.authorize(
        &mut lease,
        proposed,
        input.executor_boundary,
        input.work_scope,
        input.session,
        input.now,
    )?;
    let authorization = authorization_record(&authorized_effect);
    let lease_record = RegistrationActionLeaseRecord {
        request_identity: input.request_identity.clone(),
        action_contract: input.action_contract.clone(),
        operation: input.operation.clone(),
        expected_registry_revision: input.expected_registry_revision,
        operation_name: input.operation_name.to_owned(),
        resource_ref: input.resource_ref.to_owned(),
        canonical_payload_sha256: authorized_effect.proposal.canonical_payload_sha256.clone(),
        executor_boundary: input.executor_boundary.to_owned(),
        lease: lease.recovery_record(),
        authorization,
        supporting_grant_path: supporting_grant_path.clone(),
        admitted_use_sites: vec![RegistrationUseSiteRecord::from_source_and_site(
            leaf_source.clone(),
            use_sites.first().ok_or(AuthorityError::NoEffectivePath)?,
        )],
        work_scope_binding_snapshot: input.work_scope_binding_snapshot.clone(),
    };
    ledger.leases.push(lease_record);
    ledger.leases.sort_by(|left, right| {
        left.operation
            .idempotency_key
            .cmp(&right.operation.idempotency_key)
    });
    for source in &supporting_grant_path {
        let max_uses = source_max_uses(source, &graph_snapshot)?;
        match ledger
            .grant_uses
            .binary_search_by(|row| row.source.cmp(source))
        {
            Ok(index) => {
                let counter = &mut ledger.grant_uses[index];
                counter.consumed_uses = counter
                    .consumed_uses
                    .checked_add(1)
                    .ok_or(ActionLeaseAdmissionError::CounterOverflow)?;
            }
            Err(index) => ledger.grant_uses.insert(
                index,
                RegistrationGrantUseCounter {
                    source: source.clone(),
                    max_uses,
                    consumed_uses: 1,
                },
            ),
        }
    }
    ledger.validate()?;
    Ok(ActionLeaseAdmissionCandidate {
        operation_identity: input.operation_identity.clone(),
        expected_registry_revision: input.expected_registry_revision,
        action_lease: lease,
        authorized_effect,
        next_effect_authorizer: authorizer.clone(),
        effect_authorizer: authorizer.snapshot()?,
        source_registration_authority_read,
        registration_authority_json: ledger.to_owner_json()?,
        supporting_grant_path,
    })
}

fn validate_invocation(
    input: &ActionLeaseAdmissionInput<'_>,
) -> Result<(), ActionLeaseAdmissionError> {
    input
        .request_identity
        .validate()
        .map_err(ActionLeaseAdmissionError::Protocol)?;
    if input.now.value() >= input.request_identity.deadline_unix_ms
        || input.operation_identity.as_str() != input.operation.operation_id.as_str()
        || input.request_identity.idempotency_key != input.operation.idempotency_key
        || input.request_identity.request.metadata.request_id.as_str()
            != input.operation.request_id.as_str()
        || input.request_identity.request.state_fence != input.operation.state_fence
        || input.operation.state_fence != input.work_scope.state_fence
        || input.operation.state_fence != input.session.state_fence
        || input.action_contract.work_scope != *input.work_scope
        || input
            .request_identity
            .request
            .metadata
            .session_id
            .as_ref()
            .is_some_and(|session_id| session_id.as_str() != input.session.session_id.as_str())
        || input.executor_boundary.trim().is_empty()
        || input.holder_principal.trim().is_empty()
        || input.agent_session.session_id != input.session.session_id
        || input.agent_session.state_fence != input.session.state_fence
        || input.work_scope_binding_snapshot.state_fence != input.work_scope.state_fence
        || input.work_scope_binding_snapshot.validate().is_err()
        || input.work_scope_binding_snapshot.binding.scope.scope_ref
            != input.work_scope.scope_id.as_str()
        || input.work_scope_binding_snapshot.binding.scope.generation
            != input.work_scope.resource_generation.value()
    {
        return Err(AuthorityError::IdentityConflict.into());
    }
    input
        .request_identity
        .request
        .state_fence
        .validate()
        .map_err(|_| AuthorityError::FenceMismatch)?;
    Ok(())
}

fn validate_path_evidence(
    input: &ActionLeaseAdmissionInput<'_>,
    graph: &GrantGraphRecoverySnapshot,
    path: &EffectiveCapabilityPath,
    ledger: &RegistrationAuthorityLedger,
    exact_replay_candidate: bool,
) -> Result<(Vec<RegistrationGrantUseReference>, Vec<AuthorityUseSite>), ActionLeaseAdmissionError>
{
    if path.grant_path.is_empty()
        || path.authority_binding.state_fence != input.work_scope.state_fence
    {
        return Err(AuthorityError::NoEffectivePath.into());
    }
    let evidence_subjects = input
        .activation_evidence
        .iter()
        .map(|evidence| evidence.activation.ors_subject_id.as_str())
        .collect::<BTreeSet<_>>();
    if evidence_subjects.len() != input.activation_evidence.len()
        || input.activation_evidence.len() != path.grant_path.len()
        || path
            .grant_path
            .iter()
            .any(|grant_id| !evidence_subjects.contains(grant_id.as_str()))
    {
        return Err(AuthorityError::StaleEffectAuthority("kernel_activation_set_mismatch").into());
    }
    let hydrations = input.authority_owner.owner_hydrations.as_ref().ok_or(
        AuthorityError::StaleEffectAuthority("owner_hydrations_absent"),
    )?;
    if hydrations.grant_graph_revision != input.authority_owner.grants.revision()
        || hydrations.state_fence != input.work_scope.state_fence
    {
        return Err(AuthorityError::StaleEffectAuthority("owner_hydrations_stale").into());
    }
    input
        .authority_owner
        .authority_applicability()
        .revocation_source_revision
        .ok_or(AuthorityError::StaleEffectAuthority(
            "current_revocation_history_absent",
        ))?;
    let mut output = Vec::with_capacity(path.grant_path.len());
    let mut leaf_grant = None;
    let mut leaf_evidence = None;
    for grant_id in &path.grant_path {
        let grant_id_text = grant_id.as_str();
        let grant = graph
            .grants
            .iter()
            .find(|record| record.grant_id == grant_id_text)
            .ok_or_else(|| AuthorityError::MissingParent(grant_id.clone()))?;
        let evidence = input
            .activation_evidence
            .iter()
            .find(|evidence| evidence.activation.ors_subject_id == grant_id_text)
            .ok_or_else(|| AuthorityError::StaleEffectAuthority("kernel_activation_absent"))?;
        let activation = &evidence.activation;
        let subset = &evidence.mechanical_subset;
        activation.receipt.validate().map_err(|_| {
            AuthorityError::StaleEffectAuthority("kernel_activation_receipt_invalid")
        })?;
        subset.verify_recorded_commitment()?;
        if activation.ors_record_id.trim().is_empty()
            || activation.ors_subject_id != grant_id_text
            || activation.receipt.snapshot_id != subset.governor_snapshot_id
            || activation.receipt.authority_epoch != subset.binding.authority_epoch
            || activation.mechanical_subset_commitment != subset.content_commitment
            || activation.grant_graph_revision != subset.source.source_graph_revision
            || subset.grant_id != grant_id_text
            || subset.source.source_grant_id != grant_id_text
            || subset.authority_root_ref != grant.authority_root_ref
            || subset.holder_principal != grant.holder
            || subset.operations.iter().any(|operation| {
                !grant
                    .allowed_operations
                    .iter()
                    .any(|allowed| allowed == operation)
            })
            || subset.scopes.iter().any(|scope| {
                !grant
                    .allowed_resources
                    .iter()
                    .any(|allowed| allowed == scope)
            })
            || subset.effect_ceiling > grant.max_effect
            || subset.max_uses != grant.max_uses
            || subset.binding != grant.binding
            || subset.expires_at_ms.is_some_and(|expires| {
                expires <= 0 || i128::from(input.now.value()) >= i128::from(expires)
            })
        {
            return Err(
                AuthorityError::StaleEffectAuthority("kernel_activation_source_mismatch").into(),
            );
        }
        let admitted_hydration = hydrations
            .roots
            .iter()
            .find(|row| row.intent.grant_id == grant_id_text)
            .map(|row| {
                (
                    &row.intent.mechanical_subset,
                    &row.intent.mechanical_subset_commitment,
                )
            })
            .or_else(|| {
                hydrations
                    .members
                    .iter()
                    .find(|row| row.intent.grant_id == grant_id_text)
                    .map(|row| {
                        (
                            &row.intent.mechanical_subset,
                            &row.intent.mechanical_subset_commitment,
                        )
                    })
            })
            .ok_or(AuthorityError::StaleEffectAuthority(
                "canonical_hydration_absent",
            ))?;
        if admitted_hydration.0 != subset
            || admitted_hydration.1 != &activation.mechanical_subset_commitment
        {
            return Err(AuthorityError::StaleEffectAuthority(
                "canonical_hydration_activation_mismatch",
            )
            .into());
        }
        let source = RegistrationGrantUseReference {
            grant_id: grant_id_text.to_owned(),
            canonical_decision_ref: subset.source.canonical_decision_ref.clone(),
            canonical_decision_sha256: subset.source.canonical_decision_sha256.clone(),
            source_grant_commitment: subset.source.source_grant_commitment.clone(),
            source_graph_revision: subset.source.source_graph_revision,
            mechanical_subset_commitment: activation.mechanical_subset_commitment.clone(),
            kernel_snapshot_id: activation.receipt.snapshot_id.clone(),
            kernel_activation_id: activation.receipt.activation_id.clone(),
            ors_record_id: activation.ors_record_id.clone(),
            ors_subject_id: activation.ors_subject_id.clone(),
        };
        if activation_is_revoked(
            activation.grant_graph_revision,
            evidence.current_revocation_revision,
        ) {
            return Err(AuthorityError::Revoked.into());
        }
        if path.grant_path.last() == Some(grant_id) {
            leaf_grant = Some(grant);
            leaf_evidence = Some(evidence);
        }
        output.push(source);
    }
    let leaf_source = output.last().ok_or(AuthorityError::NoEffectivePath)?;
    let grant = leaf_grant.ok_or(AuthorityError::NoEffectivePath)?;
    let evidence = leaf_evidence.ok_or(AuthorityError::NoEffectivePath)?;
    if grant.binding != path.authority_binding {
        return Err(AuthorityError::StaleEffectAuthority("leaf_binding_mismatch").into());
    }
    let mut use_site = crate::instrument_registry_use_site::build_instrument_registry_use_site(
        grant,
        input.holder_principal,
        input.work_scope,
        input.work_scope_binding_snapshot,
        input.agent_session,
        input.request_identity,
        &input.operation,
        input.operation_name,
        input.resource_ref,
        input.canonical_payload_sha256,
        input.now,
    )?;
    use_site.consumed_uses = ledger
        .grant_uses
        .iter()
        .find(|row| row.source == *leaf_source)
        .map_or(0, |row| row.consumed_uses);
    // The canonical GrantGraph above intersects operation, resource and
    // effect authority along the path. Kernel's committed subsets carry
    // additional mechanical ceilings, so apply those to the same current use
    // site for every grant. Parent holder/session identities belong to their
    // own activation and intentionally are not compared with the leaf caller;
    // each subset was instead bound above to its canonical grant owner.
    for grant_id in &path.grant_path {
        let path_evidence = input
            .activation_evidence
            .iter()
            .find(|row| row.activation.ors_subject_id == grant_id.as_str())
            .ok_or(AuthorityError::StaleEffectAuthority(
                "kernel_activation_absent",
            ))?;
        let consumed_uses = ledger
            .grant_uses
            .iter()
            .filter(|row| row.source.grant_id == grant_id.as_str())
            .try_fold(0_u32, |total, row| total.checked_add(row.consumed_uses))
            .ok_or(ActionLeaseAdmissionError::CounterOverflow)?;
        validate_path_mechanical_ceiling(
            &path_evidence.mechanical_subset,
            path_evidence.activation.grant_graph_revision,
            path_evidence.current_revocation_revision,
            &use_site,
            consumed_uses,
            exact_replay_candidate,
        )?;
    }
    validate_current_leaf_standing(
        &evidence.mechanical_subset,
        evidence.activation.grant_graph_revision,
        evidence.current_revocation_revision,
        &use_site,
    )?;
    Ok((output, vec![use_site]))
}

/// Checks the mechanical ceilings that compose across one delegation path.
/// Principal/session identity is checked against each canonical grant during
/// path validation, while `MechanicalAuthoritySubset::admits` remains the
/// exact leaf check for the caller's current identity.
fn validate_path_mechanical_ceiling(
    subset: &MechanicalAuthoritySubset,
    activation_grant_graph_revision: u64,
    current_revocation_revision: u64,
    site: &AuthorityUseSite,
    consumed_uses: u32,
    exact_replay_candidate: bool,
) -> Result<(), ActionLeaseAdmissionError> {
    if subset.scope_id != site.scope_id
        || subset.binding.state_fence != site.state_fence
        || !subset
            .binding
            .authority_epoch
            .is_same_authority(&site.authority_epoch)
    {
        return Err(AuthorityError::IdentityConflict.into());
    }
    if activation_is_revoked(activation_grant_graph_revision, current_revocation_revision) {
        return Err(AuthorityError::Revoked.into());
    }
    if let Some(expires) = subset.expires_at_ms
        && site.now_ms >= expires
    {
        return Err(AuthorityError::Expired.into());
    }
    if subset
        .heartbeat_interval_ms
        .is_some_and(|cadence| site.heartbeat_age_ms > cadence)
    {
        return Err(AuthorityError::Expired.into());
    }
    // Only an existing retained operation can bypass a budget already charged
    // to that operation. New operations always consume a fresh use.
    if consumed_uses >= subset.max_uses && !exact_replay_candidate {
        return Err(AuthorityError::UseBudgetExhausted.into());
    }
    if !subset
        .operations
        .iter()
        .any(|name| name == &site.operation_name)
        || !subset
            .transition_classes
            .iter()
            .any(|class| class == &site.transition_class)
    {
        return Err(AuthorityError::UnauthorizedOperation.into());
    }
    if !subset
        .scopes
        .iter()
        .any(|scope| scope == &site.resource_ref)
    {
        return Err(AuthorityError::UnauthorizedResource.into());
    }
    if !subset
        .data_classes
        .iter()
        .any(|class| class == &site.data_class)
    {
        return Err(AuthorityError::UnauthorizedDataClass.into());
    }
    if site.effect > subset.effect_ceiling || !site.proof_ceiling.is_at_most(subset.proof_ceiling) {
        return Err(AuthorityError::EffectCeilingExceeded.into());
    }
    if !subset.required_approvals.iter().any(|approval| {
        approval.approved_action_hash == site.action_canonical_hash
            && (!approval.allowed_once || consumed_uses == 0 || exact_replay_candidate)
    }) {
        return Err(AuthorityError::ReceiptMismatch.into());
    }
    Ok(())
}

fn validate_current_leaf_standing(
    subset: &MechanicalAuthoritySubset,
    activation_grant_graph_revision: u64,
    current_revocation_revision: u64,
    site: &AuthorityUseSite,
) -> Result<(), ActionLeaseAdmissionError> {
    if activation_is_revoked(activation_grant_graph_revision, current_revocation_revision) {
        return Err(AuthorityError::Revoked.into());
    }
    if let Some(expires) = subset.expires_at_ms
        && site.now_ms >= expires
    {
        return Err(AuthorityError::Expired.into());
    }
    if subset
        .heartbeat_interval_ms
        .is_some_and(|cadence| site.heartbeat_age_ms > cadence)
    {
        return Err(AuthorityError::Expired.into());
    }
    if !subset
        .operations
        .iter()
        .any(|operation| operation == &site.operation_name)
        || !subset
            .transition_classes
            .iter()
            .any(|class| class == &site.transition_class)
    {
        return Err(AuthorityError::UnauthorizedOperation.into());
    }
    if !subset
        .scopes
        .iter()
        .any(|scope| scope == &site.resource_ref)
    {
        return Err(AuthorityError::UnauthorizedResource.into());
    }
    if !subset
        .data_classes
        .iter()
        .any(|class| class == &site.data_class)
    {
        return Err(AuthorityError::UnauthorizedDataClass.into());
    }
    if site.effect > subset.effect_ceiling || !site.proof_ceiling.is_at_most(subset.proof_ceiling) {
        return Err(AuthorityError::EffectCeilingExceeded.into());
    }
    if !subset
        .required_approvals
        .iter()
        .any(|approval| approval.approved_action_hash == site.action_canonical_hash)
    {
        return Err(AuthorityError::ReceiptMismatch.into());
    }
    Ok(())
}

fn activation_is_revoked(
    activation_grant_graph_revision: u64,
    current_revocation_revision: u64,
) -> bool {
    current_revocation_revision > 0
        && activation_grant_graph_revision <= current_revocation_revision
}

fn source_max_uses(
    source: &RegistrationGrantUseReference,
    graph: &GrantGraphRecoverySnapshot,
) -> Result<u32, ActionLeaseAdmissionError> {
    graph
        .grants
        .iter()
        .find(|record| record.grant_id == source.grant_id)
        .map(|record| record.max_uses)
        .ok_or_else(|| {
            let grant_id = GrantId::new(source.grant_id.clone())?;
            AuthorityError::MissingParent(grant_id).into()
        })
}

fn authorization_record(authorized: &AuthorizedEffect) -> AuthorizedEffectRecoveryRecord {
    AuthorizedEffectRecoveryRecord {
        idempotency_key: authorized.proposal.operation.idempotency_key.clone(),
        action_id: authorized.proposal.action_id.clone(),
        operation: authorized.proposal.operation.clone(),
        operation_name: authorized.proposal.operation_name.clone(),
        resource_ref: authorized.proposal.resource_ref.clone(),
        canonical_payload_sha256: authorized.proposal.canonical_payload_sha256.clone(),
        lease_id: authorized.lease_id.as_str().to_owned(),
        executor_boundary: authorized.executor_boundary.clone(),
        receipt_obligations: authorized.receipt_obligations.clone(),
    }
}

fn authorization_matches_record(
    authorized: &AuthorizedEffect,
    record: &RegistrationActionLeaseRecord,
) -> bool {
    authorization_record(authorized) == record.authorization
}

fn validate_source_reference(
    source: &RegistrationGrantUseReference,
) -> Result<(), ActionLeaseAdmissionError> {
    if [
        source.grant_id.as_str(),
        source.canonical_decision_ref.as_str(),
        source.source_grant_commitment.as_str(),
        source.mechanical_subset_commitment.as_str(),
        source.kernel_snapshot_id.as_str(),
        source.kernel_activation_id.as_str(),
        source.ors_record_id.as_str(),
        source.ors_subject_id.as_str(),
    ]
    .iter()
    .any(|value| value.trim().is_empty())
        || !is_sha256_hex(&source.canonical_decision_sha256)
        || source.source_graph_revision == 0
        || source.ors_subject_id != source.grant_id
    {
        return Err(ActionLeaseAdmissionError::InvalidLedger(
            "grant source reference is incomplete",
        ));
    }
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod registration_admission_tests {
    #![allow(clippy::expect_used, clippy::too_many_lines)]

    use super::{
        ActionLeaseAdmissionCandidate, ActionLeaseAdmissionError, ActionLeaseAdmissionInput,
        CurrentGrantActivationEvidence, RegistrationAuthorityOwnerRead, activation_is_revoked,
        admit_registration_action,
    };
    use crate::AdmittedHydrationsSnapshot;
    use crate::authority_recovery::{AuthorityOwner, AuthorityOwnerSnapshot};
    use eliot_authority::{
        ActionContract, AuthoritySet, CapabilityGrant, EffectAuthorizer, GrantGraph, GrantId,
        GrantStatus, LogicalTime, MechanicalAuthoritySubset, MechanicalSubsetConstraints,
        PrincipalRef, RevocationHistoryEvidence, RevocationOperationIdentity,
    };
    use eliot_contracts::{
        ClockReading, ContractId, EpochId, EpochLineageId, ProductId, ReceiptId,
        ResourceGeneration, SessionId, TaskId, TransactionSequence,
    };
    use eliot_kernel_core::{
        CommittedAuthorityActivation, GrantActivationIntent, GrantClosureMember, RootGrantHydration,
    };
    use eliot_ors::{
        CapabilityGrantActivation, EpochIdentity as OrsEpochIdentity, EpochLineage, OpaqueLabel,
        OperationalRecordContext, OperationalRecordInput, StateFenceSnapshot,
    };
    use eliot_platform::SecretReference;
    use eliot_protocol::RequestIdentity;
    use eliot_receipts::{
        AuthorityBinding, EffectClass, OperationBinding, ProofCeiling, RequestBinding,
        SessionBinding, WorkScopeBinding, WorkScopeId,
    };
    use eliot_runtime_contracts::{AuthorityActivationReceipt, AuthorityState};
    use eliot_security_contracts::PrivacyClass;
    use eliot_session::{AgentSession, SessionState};
    use eliot_store_api::TransitionClass;
    use eliot_workscope::{
        ScopeBinding, ScopeBindingDisposition, ScopeBindingGuardReceipt, ScopeIdentity, ScopeKind,
        WorkScopeBindingSnapshot,
    };
    use std::num::NonZeroU64;

    #[test]
    fn per_grant_revocation_watermark_only_invalidates_covered_activation() {
        assert!(!activation_is_revoked(7, 0));
        assert!(!activation_is_revoked(7, 6));
        assert!(activation_is_revoked(7, 7));
        assert!(activation_is_revoked(6, 7));
    }

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const REGISTER: &str = "instrument_registry.register";
    const ACTION_HASH: &str = "3f9a1c7d5e2b8a04c6d1f37e5b9042a8c6d0e3f75a1b2c3d4e5f60718293a4b5";
    const OTHER_ACTION_HASH: &str =
        "8c1d0f7a4b6e2391d5c70a8f3b62e9147d0c5a83f1e6b27d9048ac35f1e6b720";

    fn fixture_fence() -> eliot_contracts::StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
            NonZeroU64::new(1).expect("epoch sequence"),
        )
        .expect("epoch");
        eliot_contracts::StateFence::new(epoch, ResourceGeneration::new(1).expect("generation"))
    }

    fn fixture_binding(
        fence: &eliot_contracts::StateFence,
        allowed_effect: EffectClass,
        proof_ceiling: ProofCeiling,
    ) -> AuthorityBinding {
        AuthorityBinding {
            authority_id: ContractId::new("authority:registration").expect("authority id"),
            authority_owner: "authority-owner".to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state_fence: fence.clone(),
            allowed_effect,
            proof_ceiling,
        }
    }

    fn fixture_scope_snapshot(
        fence: &eliot_contracts::StateFence,
        scope_ref: &str,
        root_identity: &str,
    ) -> WorkScopeBindingSnapshot {
        let instance_ref = "instance:registration";
        WorkScopeBindingSnapshot::new(
            fence.clone(),
            1,
            ScopeBinding {
                scope: ScopeIdentity {
                    scope_ref: scope_ref.to_owned(),
                    kind: ScopeKind::Directory,
                    lineage_ref: None,
                    instance_ref: instance_ref.to_owned(),
                    root_identity: root_identity.to_owned(),
                    generation: 1,
                },
                privacy_class: PrivacyClass::Private,
                governing_source_generation: 1,
            },
            ScopeBindingGuardReceipt {
                expected_scope_ref: scope_ref.to_owned(),
                observed_scope_ref: scope_ref.to_owned(),
                expected_lineage_ref: None,
                observed_lineage_ref: None,
                expected_instance_ref: instance_ref.to_owned(),
                observed_instance_ref: instance_ref.to_owned(),
                disposition: ScopeBindingDisposition::Matched,
                source_generation: 1,
            },
        )
        .expect("valid WorkScope snapshot")
    }

    fn fixture_request(fence: &eliot_contracts::StateFence) -> RequestIdentity {
        let request_id =
            eliot_contracts::RequestId::new("request:registration").expect("request id");
        let metadata = eliot_contracts::RequestMetadata {
            request_id,
            session_id: Some(SessionId::new("session:leaf").expect("session id")),
            task_id: Some(TaskId::new("task:registration").expect("task id")),
            product_id: ProductId::new("product:registration").expect("product id"),
            source_id: eliot_contracts::SourceId::new("source:registration").expect("source id"),
            state_fence: fence.clone(),
            clock: ClockReading {
                valid_time_ms: Some(2_000),
                known_time_ms: Some(2_000),
                transaction_sequence: Some(TransactionSequence::genesis()),
                monotonic_ns: None,
            },
        };
        RequestIdentity {
            request: RequestBinding {
                metadata,
                state_fence: fence.clone(),
            },
            idempotency_key: "idem:registration".to_owned(),
            deadline_unix_ms: 9_000,
            cancellation_id: "cancel:registration".to_owned(),
        }
    }

    fn run_real_admission(
        ancestor_proof: ProofCeiling,
        ancestor_data_class: &str,
        ancestor_approval_hash: &str,
        operation_identity_override: Option<&str>,
        ancestor_allows_transition: bool,
        ancestor_expires_at: u64,
        ancestor_revocation_revision: u64,
    ) -> Result<ActionLeaseAdmissionCandidate, ActionLeaseAdmissionError> {
        run_real_admission_with_owner(
            ancestor_proof,
            ancestor_data_class,
            ancestor_approval_hash,
            operation_identity_override,
            ancestor_allows_transition,
            ancestor_expires_at,
            ancestor_revocation_revision,
            RegistrationAuthorityOwnerRead::Absent,
            None,
            false,
            3,
            2,
            None,
        )
    }

    fn run_real_admission_with_owner(
        ancestor_proof: ProofCeiling,
        ancestor_data_class: &str,
        ancestor_approval_hash: &str,
        operation_identity_override: Option<&str>,
        ancestor_allows_transition: bool,
        ancestor_expires_at: u64,
        ancestor_revocation_revision: u64,
        registration_authority_owner_read: RegistrationAuthorityOwnerRead<'_>,
        effect_authorizer: Option<&EffectAuthorizer>,
        approval_allowed_once: bool,
        parent_max_uses: u32,
        leaf_max_uses: u32,
        scope_snapshot_override: Option<WorkScopeBindingSnapshot>,
    ) -> Result<ActionLeaseAdmissionCandidate, ActionLeaseAdmissionError> {
        let fence = fixture_fence();
        let scope = WorkScopeBinding {
            scope_id: WorkScopeId::new("scope:registration").expect("scope id"),
            product_id: ProductId::new("product:registration").expect("product id"),
            resource_generation: ResourceGeneration::new(1).expect("generation"),
            state_fence: fence.clone(),
        };
        let scope_snapshot = scope_snapshot_override.unwrap_or_else(|| {
            fixture_scope_snapshot(&fence, "scope:registration", "root-identity:registration")
        });
        let session_id = SessionId::new("session:leaf").expect("session id");
        let session = SessionBinding {
            session_id: session_id.clone(),
            authority_epoch: fence.authority_epoch.clone(),
            state_fence: fence.clone(),
        };
        let agent_session = AgentSession {
            session_id,
            agent_id: "agent:leaf".to_owned(),
            model_route: "model-route".to_owned(),
            harness: "harness".to_owned(),
            role: "role".to_owned(),
            project_scope: "scope:registration".to_owned(),
            task_scope: Some("task:registration".to_owned()),
            capability_profile_id: "profile:registration".to_owned(),
            parent_session_id: None,
            started_at: 1_000,
            heartbeat_at: 1_900,
            expires_at: 8_000,
            status: SessionState::Active,
            policy_snapshot_id: "policy:current".to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state_fence: fence.clone(),
        };
        let leaf_binding = fixture_binding(
            &fence,
            EffectClass::ReversibleMutation,
            ProofCeiling::ScopedVerification,
        );
        let parent_binding =
            fixture_binding(&fence, EffectClass::ReversibleMutation, ancestor_proof);
        let registration_op = REGISTER.to_owned();
        let parent = CapabilityGrant {
            grant_id: GrantId::new("grant:delegator").expect("parent grant id"),
            parent_grant_id: None,
            authority_root_ref: "root:registration".to_owned(),
            issuer: PrincipalRef::new("principal:root").expect("root issuer"),
            holder: PrincipalRef::new("principal:delegator").expect("parent holder"),
            authority: AuthoritySet::new(
                [
                    registration_op.clone(),
                    "instrument_registry.read".to_owned(),
                ],
                ["scope:registration".to_owned(), "scope:other".to_owned()],
                EffectClass::ReversibleMutation,
            )
            .expect("parent authority"),
            inherited_source_ceiling: None,
            binding: fixture_binding(&fence, EffectClass::ReversibleMutation, ancestor_proof),
            issued_at: LogicalTime::new(1_000),
            expires_at: LogicalTime::new(ancestor_expires_at),
            max_uses: parent_max_uses,
            status: GrantStatus::Active,
        };
        let child = CapabilityGrant {
            grant_id: GrantId::new("grant:leaf").expect("leaf grant id"),
            parent_grant_id: Some(GrantId::new("grant:delegator").expect("parent ref")),
            authority_root_ref: "root:registration".to_owned(),
            issuer: PrincipalRef::new("principal:delegator").expect("child issuer"),
            holder: PrincipalRef::new("principal:leaf").expect("leaf holder"),
            authority: AuthoritySet::new(
                [registration_op],
                ["scope:registration".to_owned()],
                EffectClass::ReversibleMutation,
            )
            .expect("leaf authority"),
            inherited_source_ceiling: None,
            binding: leaf_binding.clone(),
            issued_at: LogicalTime::new(1_000),
            expires_at: LogicalTime::new(ancestor_expires_at.min(8_000)),
            max_uses: leaf_max_uses,
            status: GrantStatus::Active,
        };
        let graph = GrantGraph::from_grants([parent, child], 7).expect("canonical graph");
        let restore_operation = RevocationOperationIdentity::admit(
            "principal:owner",
            TaskId::new("task:registration").expect("task id"),
            "scope:registration",
            ReceiptId::new("receipt:history").expect("receipt id"),
            ClockReading {
                valid_time_ms: Some(2_000),
                known_time_ms: Some(2_000),
                transaction_sequence: Some(TransactionSequence::genesis()),
                monotonic_ns: None,
            },
        )
        .expect("revocation operation");
        let history = RevocationHistoryEvidence {
            state_fence: fence.clone(),
            source_revision: 7,
            closures: Vec::new(),
        };
        let private_class = serde_json::to_value(PrivacyClass::Private)
            .expect("privacy class")
            .as_str()
            .expect("privacy string")
            .to_owned();
        let root_record = graph
            .recovery_snapshot()
            .expect("graph snapshot")
            .grants
            .into_iter()
            .find(|record| record.grant_id == "grant:delegator")
            .expect("root grant record");
        let leaf_record = graph
            .recovery_snapshot()
            .expect("graph snapshot")
            .grants
            .into_iter()
            .find(|record| record.grant_id == "grant:leaf")
            .expect("leaf grant record");
        let canonical_source = |record: &eliot_authority::GrantRecoveryRecord| {
            eliot_authority::CanonicalSourceCommitment {
                canonical_decision_ref: format!("decision:{}", record.grant_id),
                canonical_decision_sha256: OTHER_ACTION_HASH.to_owned(),
                source_grant_id: record.grant_id.clone(),
                source_grant_commitment: eliot_contracts::sha256_hex(
                    &eliot_contracts::canonical_json_bytes(record).expect("canonical grant record"),
                ),
                source_graph_revision: 7,
            }
        };
        let mechanical_subset = |record: &eliot_authority::GrantRecoveryRecord,
                                 holder: &str,
                                 binding: &AuthorityBinding,
                                 proof_ceiling: ProofCeiling,
                                 data_class: &str,
                                 approved_hash: &str| {
            MechanicalAuthoritySubset::compile(
                record,
                &format!("snapshot:{}", record.grant_id),
                holder,
                "session:activation",
                "scope:registration",
                &format!("token:{}", record.grant_id),
                binding,
                MechanicalSubsetConstraints {
                    transition_classes: vec![
                        serde_json::to_value(
                            if ancestor_allows_transition || record.grant_id == "grant:leaf" {
                                TransitionClass::InstrumentRegistry
                            } else {
                                TransitionClass::TaskControl
                            },
                        )
                        .expect("transition class")
                        .as_str()
                        .expect("transition label")
                        .to_owned(),
                    ],
                    data_classes: vec![data_class.to_owned()],
                    policy_revision: "policy:current".to_owned(),
                    configuration_revision: "configuration:current".to_owned(),
                    lease_revision: "lease:current".to_owned(),
                    heartbeat_interval_ms: None,
                    source: canonical_source(record),
                    required_approvals: vec![eliot_authority::ApprovalReference {
                        approval_record_id: format!("approval:{}", record.grant_id),
                        approved_action_hash: approved_hash.to_owned(),
                        allowed_once: approval_allowed_once,
                    }],
                },
            )
            .expect("compiled mechanical subset")
        };
        let make_intent = |record: &eliot_authority::GrantRecoveryRecord,
                           holder: &str,
                           binding: AuthorityBinding,
                           proof_ceiling: ProofCeiling,
                           data_class: &str,
                           approved_hash: &str| {
            let subset = mechanical_subset(
                record,
                holder,
                &binding,
                proof_ceiling,
                data_class,
                approved_hash,
            );
            GrantActivationIntent {
                operation_id: format!("activation:{}", record.grant_id),
                grant_id: record.grant_id.clone(),
                parent_grant_id: record.parent_grant_id.clone(),
                authority_root_ref: record.authority_root_ref.clone(),
                snapshot_id: subset.governor_snapshot_id.clone(),
                grant_graph_revision: 7,
                holder_principal: holder.to_owned(),
                session_id: "session:activation".to_owned(),
                scope_id: "scope:registration".to_owned(),
                token_id: format!("token:{}", record.grant_id),
                binding,
                allowed_effect: record.max_effect,
                proof_ceiling,
                issued_at_ms: 1_000,
                expires_at_ms: Some(
                    i64::try_from(record.expires_at).expect("grant expiry fits i64"),
                ),
                receipt_obligations: vec!["canonical-registration".to_owned()],
                mechanical_subset_commitment: subset.content_commitment.clone(),
                mechanical_subset: subset,
            }
        };
        let parent_intent = make_intent(
            &root_record,
            "principal:delegator",
            parent_binding,
            ancestor_proof,
            ancestor_data_class,
            ancestor_approval_hash,
        );
        let leaf_intent = make_intent(
            &leaf_record,
            "principal:leaf",
            leaf_binding,
            ProofCeiling::ScopedVerification,
            &private_class,
            ACTION_HASH,
        );
        let secret = SecretReference::new("test-provider", "test-key").expect("secret");
        let sealed_record = |intent: &GrantActivationIntent| {
            let epoch = &intent.binding.authority_epoch;
            let input = OperationalRecordInput::encrypted(
                OperationalRecordContext {
                    record_id: eliot_ors::OperationIdentity::new(intent.operation_id.clone())
                        .expect("record id"),
                    subject_id: eliot_ors::OperationIdentity::new(intent.grant_id.clone())
                        .expect("subject id"),
                    authority_epoch: EpochLineage {
                        current: OrsEpochIdentity {
                            lineage_id: OpaqueLabel::new(epoch.lineage_id.as_str())
                                .expect("epoch lineage"),
                            epoch: epoch.sequence.get(),
                        },
                        predecessor: None,
                    },
                    state_fence: StateFenceSnapshot::capture(
                        &intent.binding.state_fence,
                        epoch.sequence.get(),
                    )
                    .expect("fence snapshot"),
                    created_at_ms: intent.issued_at_ms,
                    cleanup_after_ms: None,
                },
                secret.clone(),
                eliot_contracts::canonical_json_bytes(intent).expect("sealed intent bytes"),
            )
            .expect("operational record input");
            CapabilityGrantActivation::new(input).expect("opaque grant activation")
        };
        let parent_activation = RootGrantHydration {
            intent: parent_intent.clone(),
            durable_record: sealed_record(&parent_intent),
            observed_at_ms: 1_500,
        };
        let leaf_activation = GrantClosureMember {
            intent: leaf_intent.clone(),
            durable_record: sealed_record(&leaf_intent),
            observed_at_ms: 1_500,
        };
        let owner_snapshot = AuthorityOwnerSnapshot::new_with_owner_hydrations(
            fence.clone(),
            graph.recovery_snapshot().expect("graph snapshot"),
            EffectAuthorizer::default().snapshot().expect("authorizer"),
            AdmittedHydrationsSnapshot {
                schema: crate::OWNER_HYDRATION_SNAPSHOT_SCHEMA.to_owned(),
                version: crate::OWNER_HYDRATION_SNAPSHOT_VERSION,
                state_fence: fence.clone(),
                grant_graph_revision: 7,
                members: vec![leaf_activation.clone()],
                roots: vec![parent_activation.clone()],
                introductions: Vec::new(),
                preserved: Vec::new(),
            },
        )
        .expect("owner snapshot");
        let owner = AuthorityOwner::from_snapshot_with_revocation_history(
            &owner_snapshot,
            &fence,
            Some(&history),
            &restore_operation,
        )
        .expect("restored authority owner")
        .owner;
        let principal = PrincipalRef::new("principal:leaf").expect("leaf principal");
        let snapshot_now = 2_000_u64.min(ancestor_expires_at.saturating_sub(1));
        let effective = owner
            .grants
            .snapshot(
                eliot_authority::SnapshotId::new("operation:registration").expect("snapshot id"),
                &principal,
                &scope,
                &session,
                LogicalTime::new(snapshot_now),
            )
            .expect("effective capability snapshot");
        let mk_evidence = |intent: &GrantActivationIntent| {
            let receipt = AuthorityActivationReceipt {
                activation_id: format!("activation:{}", intent.grant_id),
                snapshot_id: intent.snapshot_id.clone(),
                authority_epoch: fence.authority_epoch.clone(),
                state: AuthorityState::Active,
            };
            CurrentGrantActivationEvidence {
                activation: CommittedAuthorityActivation::new(receipt, intent),
                mechanical_subset: intent.mechanical_subset.clone(),
                current_revocation_revision: if intent.grant_id == "grant:delegator" {
                    ancestor_revocation_revision
                } else {
                    0
                },
            }
        };
        let activation_evidence = vec![
            mk_evidence(&parent_activation.intent),
            mk_evidence(&leaf_activation.intent),
        ];
        let request = fixture_request(&fence);
        let operation_identity = eliot_ors::OperationIdentity::new(
            operation_identity_override.unwrap_or("operation:registration"),
        )
        .expect("original operation identity");
        let operation = OperationBinding {
            operation_id: eliot_contracts::OperationId::new("operation:registration")
                .expect("operation id"),
            request_id: request.request.metadata.request_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            operation_kind: REGISTER.to_owned(),
            effect: EffectClass::ReversibleMutation,
            state_fence: fence.clone(),
        };
        let contract = ActionContract::new(
            "action:registration",
            "task:registration",
            "register instrument",
            scope.clone(),
            "grant:leaf",
            Vec::<String>::new(),
            ["scope:registration".to_owned()],
            eliot_authority::ImpactClass::Reversible,
            Vec::<String>::new(),
            "registry row committed",
            "verifier:registration",
            "restore previous registry row",
            ["owner receipt absent".to_owned()],
        )
        .expect("ActionContract");
        let now = LogicalTime::new(2_000);
        admit_registration_action(ActionLeaseAdmissionInput {
            holder_principal: "principal:leaf",
            request_identity: &request,
            operation_identity: &operation_identity,
            operation,
            expected_registry_revision: 0,
            action_contract: &contract,
            operation_name: REGISTER,
            resource_ref: "scope:registration",
            canonical_payload_sha256: ACTION_HASH,
            executor_boundary: eliot_store_api::named_mutation_operation_name(
                eliot_store_api::NamedMutationOperation::ApplyInstrumentRegistryState,
            ),
            authority_owner: &owner,
            effective_capabilities: &effective,
            activation_evidence: &activation_evidence,
            work_scope: &scope,
            work_scope_binding_snapshot: &scope_snapshot,
            session: &session,
            agent_session: &agent_session,
            now,
            registration_authority_owner_read,
            effect_authorizer: effect_authorizer.unwrap_or(&owner.effects),
        })
    }

    #[test]
    fn two_grant_admission_intersects_ancestor_ceilings_and_preserves_holders() {
        let accepted = run_real_admission(
            ProofCeiling::ScopedVerification,
            "PRIVATE",
            ACTION_HASH,
            None,
            true,
            8_000,
            0,
        );
        assert!(
            accepted.is_ok(),
            "lawful delegated registration refused: {accepted:?}"
        );
        let candidate = accepted.expect("positive admission");
        assert_eq!(candidate.supporting_grant_path().len(), 2);
        assert_eq!(candidate.action_lease().holder.as_str(), "principal:leaf");

        let data_refusal = run_real_admission(
            ProofCeiling::ScopedVerification,
            "PUBLIC",
            ACTION_HASH,
            None,
            true,
            8_000,
            0,
        );
        assert!(matches!(
            data_refusal,
            Err(ActionLeaseAdmissionError::Authority(
                eliot_authority::AuthorityError::UnauthorizedDataClass
            ))
        ));

        let proof_refusal = run_real_admission(
            ProofCeiling::Observation,
            "PRIVATE",
            ACTION_HASH,
            None,
            true,
            8_000,
            0,
        );
        assert!(matches!(
            proof_refusal,
            Err(ActionLeaseAdmissionError::Authority(
                eliot_authority::AuthorityError::EffectCeilingExceeded
            ))
        ));

        let approval_refusal = run_real_admission(
            ProofCeiling::ScopedVerification,
            "PRIVATE",
            OTHER_ACTION_HASH,
            None,
            true,
            8_000,
            0,
        );
        assert!(matches!(
            approval_refusal,
            Err(ActionLeaseAdmissionError::Authority(
                eliot_authority::AuthorityError::ReceiptMismatch
            ))
        ));

        let transition_refusal = run_real_admission(
            ProofCeiling::ScopedVerification,
            "PRIVATE",
            ACTION_HASH,
            None,
            false,
            8_000,
            0,
        );
        assert!(matches!(
            transition_refusal,
            Err(ActionLeaseAdmissionError::Authority(
                eliot_authority::AuthorityError::UnauthorizedOperation
            ))
        ));

        let expiry_refusal = run_real_admission(
            ProofCeiling::ScopedVerification,
            "PRIVATE",
            ACTION_HASH,
            None,
            true,
            1_999,
            0,
        );
        assert!(matches!(
            expiry_refusal,
            Err(ActionLeaseAdmissionError::Authority(
                eliot_authority::AuthorityError::StaleEffectAuthority(
                    "kernel_activation_source_mismatch"
                )
            ))
        ));

        let revoked_ancestor_refusal = run_real_admission(
            ProofCeiling::ScopedVerification,
            "PRIVATE",
            ACTION_HASH,
            None,
            true,
            8_000,
            7,
        );
        assert!(matches!(
            revoked_ancestor_refusal,
            Err(ActionLeaseAdmissionError::Authority(
                eliot_authority::AuthorityError::Revoked
            ))
        ));

        // The current fixture has one leaf and the graph requires each child
        // budget to be no greater than its parent (leaf=2, ancestor=3). A
        // sibling allocation is needed to saturate the shared ancestor first.
    }

    #[test]
    fn actual_admission_producer_rejects_foreign_original_operation_allocation() {
        let refusal = run_real_admission(
            ProofCeiling::ScopedVerification,
            "PRIVATE",
            ACTION_HASH,
            Some("operation:foreign"),
            true,
            8_000,
            0,
        );
        assert!(matches!(
            refusal,
            Err(ActionLeaseAdmissionError::Authority(
                eliot_authority::AuthorityError::IdentityConflict
            ))
        ));
    }

    #[test]
    fn actual_admission_producer_replays_original_final_use_and_once_approval() {
        let admitted = run_real_admission_with_owner(
            ProofCeiling::ScopedVerification,
            "PRIVATE",
            ACTION_HASH,
            None,
            true,
            8_000,
            0,
            RegistrationAuthorityOwnerRead::Absent,
            None,
            true,
            1,
            1,
            None,
        )
        .expect("first lawful registration consumes the final allowed use");
        let original_ledger = admitted.registration_authority_json().to_owned();

        let replay = run_real_admission_with_owner(
            ProofCeiling::ScopedVerification,
            "PRIVATE",
            ACTION_HASH,
            None,
            true,
            8_000,
            0,
            RegistrationAuthorityOwnerRead::Present(&original_ledger),
            Some(admitted.next_effect_authorizer()),
            true,
            1,
            1,
            None,
        )
        .expect("exact replay returns the already-admitted allocation");

        assert_eq!(replay.registration_authority_json(), original_ledger);
        assert_eq!(
            replay.action_lease().recovery_record(),
            admitted.action_lease().recovery_record()
        );
        assert_eq!(
            replay.supporting_grant_path(),
            admitted.supporting_grant_path()
        );
    }

    #[test]
    fn actual_admission_retains_original_work_scope_root_and_refuses_foreign_binding() {
        let admitted = run_real_admission(
            ProofCeiling::ScopedVerification,
            "PRIVATE",
            ACTION_HASH,
            None,
            true,
            8_000,
            0,
        )
        .expect("current canonical WorkScope is admitted");
        let ledger = super::RegistrationAuthorityLedger::from_current_owner_json(
            admitted.registration_authority_json(),
        )
        .expect("persisted owner ledger decodes");
        assert_eq!(
            ledger.leases[0]
                .work_scope_binding_snapshot
                .binding
                .scope
                .scope_ref,
            "scope:registration"
        );
        assert_eq!(
            ledger.leases[0]
                .work_scope_binding_snapshot
                .binding
                .scope
                .root_identity,
            "root-identity:registration"
        );

        let original_ledger = admitted.registration_authority_json().to_owned();
        let foreign_root = run_real_admission_with_owner(
            ProofCeiling::ScopedVerification,
            "PRIVATE",
            ACTION_HASH,
            None,
            true,
            8_000,
            0,
            RegistrationAuthorityOwnerRead::Present(&original_ledger),
            Some(admitted.next_effect_authorizer()),
            false,
            3,
            2,
            Some(fixture_scope_snapshot(
                &fixture_fence(),
                "scope:registration",
                "root-identity:foreign",
            )),
        );
        assert!(matches!(
            foreign_root,
            Err(ActionLeaseAdmissionError::Authority(
                eliot_authority::AuthorityError::IdentityConflict
            ))
        ));

        let foreign_scope = run_real_admission_with_owner(
            ProofCeiling::ScopedVerification,
            "PRIVATE",
            ACTION_HASH,
            None,
            true,
            8_000,
            0,
            RegistrationAuthorityOwnerRead::Absent,
            None,
            false,
            3,
            2,
            Some(fixture_scope_snapshot(
                &fixture_fence(),
                "scope:foreign",
                "root-identity:registration",
            )),
        );
        assert!(matches!(
            foreign_scope,
            Err(ActionLeaseAdmissionError::Authority(
                eliot_authority::AuthorityError::IdentityConflict
            ))
        ));
    }
}

/// Typed refusal from the Governor producer.
#[derive(Debug, thiserror::Error)]
pub enum ActionLeaseAdmissionError {
    #[error(transparent)]
    Authority(#[from] AuthorityError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Protocol(ProtocolError),
    #[error("registration authority ledger is invalid: {0}")]
    InvalidLedger(&'static str),
    #[error("registration authority ledger use counter overflowed")]
    CounterOverflow,
    #[error("registration authority ledger serialization failed")]
    Serialization,
}
