use std::collections::{BTreeMap, BTreeSet};

use eliot_receipts::{
    OperationBinding, ReceiptDispositionKind, ReceiptEnvelope, SessionBinding, WorkScopeBinding,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ActionLease, AuthorityError, LeaseId, LogicalTime, ReceiptObligation, validate_digest,
    validate_text,
};

/// Exact action frame from which effect proposals are derived.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionContract {
    pub action_id: String,
    pub intent: String,
    pub work_scope: WorkScopeBinding,
    pub authority_ref: String,
    pub read_set: BTreeSet<String>,
    pub effect_set: BTreeSet<String>,
    pub expected_observable: String,
    pub verifier_ref: String,
    pub rollback_or_compensation: String,
    pub stop_conditions: BTreeSet<String>,
}

impl ActionContract {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action_id: impl Into<String>,
        intent: impl Into<String>,
        work_scope: WorkScopeBinding,
        authority_ref: impl Into<String>,
        read_set: impl IntoIterator<Item = String>,
        effect_set: impl IntoIterator<Item = String>,
        expected_observable: impl Into<String>,
        verifier_ref: impl Into<String>,
        rollback_or_compensation: impl Into<String>,
        stop_conditions: impl IntoIterator<Item = String>,
    ) -> Result<Self, AuthorityError> {
        let contract = Self {
            action_id: action_id.into(),
            intent: intent.into(),
            work_scope,
            authority_ref: authority_ref.into(),
            read_set: read_set.into_iter().collect(),
            effect_set: effect_set.into_iter().collect(),
            expected_observable: expected_observable.into(),
            verifier_ref: verifier_ref.into(),
            rollback_or_compensation: rollback_or_compensation.into(),
            stop_conditions: stop_conditions.into_iter().collect(),
        };
        for (value, field) in [
            (&contract.action_id, "action_id"),
            (&contract.intent, "intent"),
            (&contract.authority_ref, "authority_ref"),
            (&contract.expected_observable, "expected_observable"),
            (&contract.verifier_ref, "verifier_ref"),
            (
                &contract.rollback_or_compensation,
                "rollback_or_compensation",
            ),
        ] {
            validate_text(value, field)?;
        }
        if contract.effect_set.is_empty() || contract.stop_conditions.is_empty() {
            return Err(AuthorityError::InvalidField(
                "effect_set_or_stop_conditions",
            ));
        }
        for value in contract
            .read_set
            .iter()
            .chain(&contract.effect_set)
            .chain(&contract.stop_conditions)
        {
            validate_text(value, "action_contract_set")?;
        }
        contract
            .work_scope
            .state_fence
            .validate()
            .map_err(|_| AuthorityError::FenceMismatch)?;
        Ok(contract)
    }
}

/// Effect request only; this value carries no authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposedEffect {
    pub action_id: String,
    pub operation: OperationBinding,
    pub operation_name: String,
    pub resource_ref: String,
    pub canonical_payload_sha256: String,
}

impl ProposedEffect {
    pub fn new(
        action_id: impl Into<String>,
        operation: OperationBinding,
        operation_name: impl Into<String>,
        resource_ref: impl Into<String>,
        canonical_payload_sha256: impl Into<String>,
    ) -> Result<Self, AuthorityError> {
        let action_id = action_id.into();
        let operation_name = operation_name.into();
        let resource_ref = resource_ref.into();
        let canonical_payload_sha256 = canonical_payload_sha256.into();
        validate_text(&action_id, "action_id")?;
        validate_text(&operation_name, "operation_name")?;
        validate_text(&resource_ref, "resource_ref")?;
        validate_text(&operation.idempotency_key, "idempotency_key")?;
        validate_text(&operation.operation_kind, "operation_kind")?;
        validate_digest(&canonical_payload_sha256, "canonical_payload_sha256")?;
        operation
            .state_fence
            .validate()
            .map_err(|_| AuthorityError::FenceMismatch)?;
        Ok(Self {
            action_id,
            operation,
            operation_name,
            resource_ref,
            canonical_payload_sha256,
        })
    }
}

/// Exact proposal admitted by one `ActionLease`. It still has no execution API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedEffect {
    pub proposal: ProposedEffect,
    pub lease_id: LeaseId,
    pub executor_boundary: String,
    pub receipt_obligations: Vec<ReceiptObligation>,
}

/// Current validity of an authorized (pending) effect under I12.20 influence
/// revocation.
///
/// Historical admission records are never mutated: a revocation marks the
/// *current* standing of a dependent pending effect as contestable (first
/// challenge) or reopened (already contested, challenged again by a new
/// revoked root), while the stored [`AuthorizedEffect`] and every recovery
/// record stay byte-identical. Contested effects must be rebuilt from clean
/// inputs before further reliance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub enum DependentEffectState {
    Admissible,
    Contestable { revoked_roots: BTreeSet<String> },
    Reopened { revoked_roots: BTreeSet<String> },
}

impl DependentEffectState {
    /// Revoked roots currently challenging this effect, if any.
    pub fn revoked_roots(&self) -> Option<&BTreeSet<String>> {
        match self {
            Self::Admissible => None,
            Self::Contestable { revoked_roots } | Self::Reopened { revoked_roots } => {
                Some(revoked_roots)
            }
        }
    }

    /// True while the current standing is challenged and must be rebuilt
    /// from clean inputs before further reliance.
    pub fn is_contested(&self) -> bool {
        !matches!(self, Self::Admissible)
    }
}

/// Append-only revocation annotation over one pending effect.
///
/// Each annotation supersedes — never rewrites — the historical admission
/// record: the [`AuthorizedEffect`] stored under `idempotency_key` is left
/// untouched and the annotation is pushed as a new record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ContestedEffectAnnotation {
    pub idempotency_key: String,
    pub revoked_roots: BTreeSet<String>,
    pub reopened: bool,
}

/// Current semantic claim whose support can be challenged by a revocation.
/// The claim is an overlay; its historical admission record is never changed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RevocationDependentClaim {
    /// Stable justification, plan, answer, or pending-effect identity.
    pub id: String,
    /// Semantic class retained for operator/rebuild projections.
    pub kind: String,
    /// Exact material supports for the claim.
    pub support_refs: BTreeSet<String>,
}

/// Pure idempotency and lease admission registry.
///
/// The admission ledger (`authorized_by_idempotency`) is append-only history:
/// revocation propagation only adds current-state contest overlays
/// (`contest_state`) and append-only [`ContestedEffectAnnotation`] records.
/// It never mutates a stored [`AuthorizedEffect`].
#[derive(Clone, Debug, Default)]
pub struct EffectAuthorizer {
    authorized_by_idempotency: BTreeMap<String, AuthorizedEffect>,
    contest_state: BTreeMap<String, DependentEffectState>,
    contest_annotations: Vec<ContestedEffectAnnotation>,
    current_claims: BTreeMap<String, RevocationDependentClaim>,
}

pub const EFFECT_AUTHORIZER_RECOVERY_SCHEMA: &str = "eliot.authority.effect-authorizer-recovery";
pub const EFFECT_AUTHORIZER_RECOVERY_VERSION: u16 = 1;

/// Complete durable idempotency ledger state, in deterministic wire form.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EffectAuthorizerRecoverySnapshot {
    pub schema: String,
    pub version: u16,
    pub records: Vec<AuthorizedEffectRecoveryRecord>,
    /// Current contest/reopen overlays keyed by the exact effect or claim id.
    #[serde(default)]
    pub contest_state: BTreeMap<String, DependentEffectState>,
    /// Append-only forensic contest annotations in admission order.
    #[serde(default)]
    pub contest_annotations: Vec<ContestedEffectAnnotation>,
    /// Current justification/plan/answer claim overlays.
    #[serde(default)]
    pub current_claims: Vec<RevocationDependentClaim>,
}

/// One complete admitted effect retained by a recovery snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedEffectRecoveryRecord {
    pub idempotency_key: String,
    pub action_id: String,
    pub operation: OperationBinding,
    pub operation_name: String,
    pub resource_ref: String,
    pub canonical_payload_sha256: String,
    pub lease_id: String,
    pub executor_boundary: String,
    pub receipt_obligations: Vec<ReceiptObligation>,
}

impl EffectAuthorizerRecoverySnapshot {
    /// Validates both the deterministic wire shape and the ledger semantics
    /// that would be enforced when this snapshot is restored.
    pub fn validate(&self) -> Result<(), AuthorityError> {
        self.validate_wire()?;
        EffectAuthorizer::restore_records(self.records.clone()).map(|_| ())
    }

    fn validate_wire(&self) -> Result<(), AuthorityError> {
        if self.schema != EFFECT_AUTHORIZER_RECOVERY_SCHEMA {
            return Err(AuthorityError::InvalidField(
                "effect_authorizer_recovery.schema",
            ));
        }
        if self.version != EFFECT_AUTHORIZER_RECOVERY_VERSION {
            return Err(AuthorityError::InvalidField(
                "effect_authorizer_recovery.version",
            ));
        }
        let mut previous = None;
        for record in &self.records {
            validate_text(&record.idempotency_key, "idempotency_key")?;
            if let Some(previous) = previous
                && previous >= record.idempotency_key.as_str()
            {
                return Err(AuthorityError::InvalidField(
                    "effect_authorizer_recovery.records",
                ));
            }
            previous = Some(record.idempotency_key.as_str());
        }
        let claim_ids: BTreeSet<&str> = self
            .current_claims
            .iter()
            .map(|claim| claim.id.as_str())
            .collect();
        if claim_ids.len() != self.current_claims.len() {
            return Err(AuthorityError::InvalidField(
                "effect_authorizer_recovery.current_claims",
            ));
        }
        for claim in &self.current_claims {
            validate_text(&claim.id, "current_claim.id")?;
            validate_text(&claim.kind, "current_claim.kind")?;
            for support in &claim.support_refs {
                validate_text(support, "current_claim.support_ref")?;
            }
        }
        for (key, state) in &self.contest_state {
            validate_text(key, "effect_authorizer_recovery.contest_key")?;
            let Some(roots) = state.revoked_roots() else {
                return Err(AuthorityError::InvalidField(
                    "effect_authorizer_recovery.contest_state",
                ));
            };
            if roots.is_empty()
                || roots
                    .iter()
                    .any(|root| validate_text(root, "revoked_root").is_err())
            {
                return Err(AuthorityError::InvalidField(
                    "effect_authorizer_recovery.contest_state",
                ));
            }
            let known_effect = self
                .records
                .iter()
                .any(|record| record.idempotency_key == *key);
            let known_claim = key
                .strip_prefix("claim:")
                .is_some_and(|id| claim_ids.contains(id));
            if !known_effect && !known_claim {
                return Err(AuthorityError::InvalidField(
                    "effect_authorizer_recovery.contest_key",
                ));
            }
        }
        for annotation in &self.contest_annotations {
            validate_text(
                &annotation.idempotency_key,
                "contest_annotation.idempotency_key",
            )?;
            if annotation.revoked_roots.is_empty()
                || annotation
                    .revoked_roots
                    .iter()
                    .any(|root| validate_text(root, "contest_annotation.root").is_err())
            {
                return Err(AuthorityError::InvalidField(
                    "effect_authorizer_recovery.contest_annotations",
                ));
            }
        }
        Ok(())
    }
}

impl EffectAuthorizer {
    pub fn snapshot(&self) -> Result<EffectAuthorizerRecoverySnapshot, AuthorityError> {
        let records = self
            .authorized_by_idempotency
            .iter()
            .map(
                |(idempotency_key, authorized)| AuthorizedEffectRecoveryRecord {
                    idempotency_key: idempotency_key.clone(),
                    action_id: authorized.proposal.action_id.clone(),
                    operation: authorized.proposal.operation.clone(),
                    operation_name: authorized.proposal.operation_name.clone(),
                    resource_ref: authorized.proposal.resource_ref.clone(),
                    canonical_payload_sha256: authorized.proposal.canonical_payload_sha256.clone(),
                    lease_id: authorized.lease_id.as_str().to_owned(),
                    executor_boundary: authorized.executor_boundary.clone(),
                    receipt_obligations: authorized.receipt_obligations.clone(),
                },
            )
            .collect();
        let snapshot = EffectAuthorizerRecoverySnapshot {
            schema: EFFECT_AUTHORIZER_RECOVERY_SCHEMA.to_owned(),
            version: EFFECT_AUTHORIZER_RECOVERY_VERSION,
            records,
            contest_state: self.contest_state.clone(),
            contest_annotations: self.contest_annotations.clone(),
            current_claims: self.current_claims.values().cloned().collect(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn from_snapshot(
        snapshot: EffectAuthorizerRecoverySnapshot,
    ) -> Result<Self, AuthorityError> {
        snapshot.validate_wire()?;
        let EffectAuthorizerRecoverySnapshot {
            records,
            contest_state,
            contest_annotations,
            current_claims,
            schema: _,
            version: _,
        } = snapshot;
        let mut owner = Self::restore_records(records)?;
        owner.contest_state = contest_state;
        owner.contest_annotations = contest_annotations;
        owner.current_claims = current_claims
            .into_iter()
            .map(|claim| (claim.id.clone(), claim))
            .collect();
        Ok(owner)
    }

    fn restore_records(
        records: Vec<AuthorizedEffectRecoveryRecord>,
    ) -> Result<Self, AuthorityError> {
        let mut authorized_by_idempotency = BTreeMap::new();
        for record in records {
            if record.idempotency_key != record.operation.idempotency_key {
                return Err(AuthorityError::InvalidField(
                    "effect_authorizer_recovery.idempotency_key",
                ));
            }
            let proposal = ProposedEffect::new(
                record.action_id,
                record.operation,
                record.operation_name,
                record.resource_ref,
                record.canonical_payload_sha256,
            )?;
            let lease_id = LeaseId::new(record.lease_id)?;
            if record.receipt_obligations.is_empty() {
                return Err(AuthorityError::InvalidField("receipt_obligations"));
            }
            for obligation in &record.receipt_obligations {
                obligation.validate()?;
            }
            let authorized = AuthorizedEffect {
                proposal,
                lease_id,
                executor_boundary: {
                    validate_text(&record.executor_boundary, "executor_boundary")?;
                    record.executor_boundary
                },
                receipt_obligations: record.receipt_obligations,
            };
            if authorized_by_idempotency
                .insert(record.idempotency_key, authorized)
                .is_some()
            {
                return Err(AuthorityError::IdentityConflict);
            }
        }
        Ok(Self {
            authorized_by_idempotency,
            // Restored history starts admissible: revocation is current-state
            // and must be re-propagated from the live revoked set (rebuild
            // from clean inputs per I12.20), never resurrected from backup.
            contest_state: BTreeMap::new(),
            contest_annotations: Vec::new(),
            current_claims: BTreeMap::new(),
        })
    }

    pub fn authorize(
        &mut self,
        lease: &mut ActionLease,
        proposed: ProposedEffect,
        executor_boundary: impl Into<String>,
        current_work_scope: &WorkScopeBinding,
        current_session: &SessionBinding,
        now: LogicalTime,
    ) -> Result<AuthorizedEffect, AuthorityError> {
        self.authorize_with_revoked_roots(
            lease,
            proposed,
            executor_boundary,
            current_work_scope,
            current_session,
            now,
            None,
        )
    }

    /// Authorizes one effect, then propagates I12.20 influence revocation
    /// through the pending-effect closure in this file.
    ///
    /// When `revoked_roots` is `None` or empty this is exactly [`Self::authorize`]:
    /// the admission result is unchanged and no contest state is written. When
    /// non-empty, every current pending effect whose validity depended on a
    /// revoked root — including the effect just admitted — is marked
    /// contestable/reopened via [`Self::contest_dependent_effects`], while
    /// historical admission records stay immutable.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_with_revoked_roots(
        &mut self,
        lease: &mut ActionLease,
        proposed: ProposedEffect,
        executor_boundary: impl Into<String>,
        current_work_scope: &WorkScopeBinding,
        current_session: &SessionBinding,
        now: LogicalTime,
        revoked_roots: Option<&BTreeSet<String>>,
    ) -> Result<AuthorizedEffect, AuthorityError> {
        let executor_boundary = executor_boundary.into();
        validate_text(&executor_boundary, "executor_boundary")?;
        if let Some(existing) = self
            .authorized_by_idempotency
            .get(&proposed.operation.idempotency_key)
        {
            if same_logical_effect(&existing.proposal, &proposed) {
                return Ok(existing.clone());
            }
            return Err(AuthorityError::IdentityConflict);
        }
        lease.authorize(&proposed, current_work_scope, current_session, now)?;
        let authorized = AuthorizedEffect {
            proposal: proposed,
            lease_id: lease.lease_id.clone(),
            executor_boundary,
            receipt_obligations: lease.receipt_obligations.clone(),
        };
        self.authorized_by_idempotency.insert(
            authorized.proposal.operation.idempotency_key.clone(),
            authorized.clone(),
        );
        // I12.20 propagation on the production authorization path: contest
        // current dependent justifications/plans/pending effects without
        // touching history. Empty or absent revoked sets are a no-op.
        if let Some(revoked_roots) = revoked_roots {
            self.contest_dependent_effects(revoked_roots);
        }
        Ok(authorized)
    }

    /// Marks every CURRENT pending effect whose validity depended on a
    /// revoked root as contestable (first challenge) or reopened (already
    /// contested, challenged again by a new root), per I12.20 S1.
    ///
    /// Historical decisions are preserved: stored [`AuthorizedEffect`]
    /// values and recovery records are never mutated. Each newly challenged
    /// effect gains one append-only [`ContestedEffectAnnotation`] that
    /// supersedes without rewriting history. An empty `revoked_roots` set
    /// is a no-op returning `0`.
    ///
    /// Returns the number of effects whose current standing changed.
    pub fn contest_dependent_effects(&mut self, revoked_roots: &BTreeSet<String>) -> usize {
        if revoked_roots.is_empty() {
            return 0;
        }
        // Collect first so the contest-state mutation cannot disturb the
        // history ledger iteration.
        let challenged: Vec<(String, BTreeSet<String>)> = self
            .authorized_by_idempotency
            .iter()
            .filter_map(|(key, authorized)| {
                let matched = dependent_revoked_roots(authorized, revoked_roots);
                (!matched.is_empty()).then(|| (key.clone(), matched))
            })
            .collect();
        let mut changed = 0;
        for (key, matched) in challenged {
            let merged: BTreeSet<String> = match self.contest_state.get(&key) {
                None => matched,
                Some(previous) => match previous.revoked_roots() {
                    // Unreachable: only contested states are ever stored.
                    None => continue,
                    Some(previous_roots) => {
                        if matched.iter().all(|root| previous_roots.contains(root)) {
                            continue;
                        }
                        previous_roots.union(&matched).cloned().collect()
                    }
                },
            };
            let reopened = self.contest_state.contains_key(&key);
            let state = if reopened {
                DependentEffectState::Reopened {
                    revoked_roots: merged.clone(),
                }
            } else {
                DependentEffectState::Contestable {
                    revoked_roots: merged.clone(),
                }
            };
            self.contest_state.insert(key.clone(), state);
            self.contest_annotations.push(ContestedEffectAnnotation {
                idempotency_key: key,
                revoked_roots: merged,
                reopened,
            });
            changed += 1;
        }
        changed
    }

    /// Registers one current justification/plan/answer claim for a future
    /// revocation pass. The registry is an overlay; no historical record is
    /// rewritten and an identical registration is idempotent.
    pub fn register_current_claim(
        &mut self,
        claim: RevocationDependentClaim,
    ) -> Result<(), AuthorityError> {
        validate_text(&claim.id, "claim.id")?;
        validate_text(&claim.kind, "claim.kind")?;
        for support in &claim.support_refs {
            validate_text(support, "claim.support_ref")?;
        }
        if let Some(existing) = self.current_claims.get(&claim.id)
            && existing != &claim
        {
            return Err(AuthorityError::IdentityConflict);
        }
        self.current_claims.insert(claim.id.clone(), claim);
        Ok(())
    }

    /// Returns the current claim overlays in stable identity order.
    #[must_use]
    pub fn current_claims(&self) -> Vec<RevocationDependentClaim> {
        self.current_claims.values().cloned().collect()
    }

    /// Contests current justification/plan/answer claims by explicit support
    /// membership. The append-only annotation has a `claim:` namespace so it
    /// cannot overwrite pending-effect history.
    pub fn contest_current_claims(&mut self, revoked_roots: &BTreeSet<String>) -> usize {
        if revoked_roots.is_empty() {
            return 0;
        }
        let challenged = self
            .current_claims
            .values()
            .filter_map(|claim| {
                let matched = claim
                    .support_refs
                    .intersection(revoked_roots)
                    .cloned()
                    .collect::<BTreeSet<_>>();
                (!matched.is_empty()).then_some((claim.id.clone(), matched))
            })
            .collect::<Vec<_>>();
        let mut changed = 0;
        for (id, matched) in challenged {
            let key = format!("claim:{id}");
            let previous = self
                .contest_state
                .get(&key)
                .and_then(|state| state.revoked_roots().cloned());
            let merged = previous.clone().map_or(matched.clone(), |roots| {
                roots.union(&matched).cloned().collect()
            });
            if previous
                .as_ref()
                .is_some_and(|roots| roots.is_superset(&matched))
            {
                continue;
            }
            let reopened = self.contest_state.contains_key(&key);
            self.contest_state.insert(
                key.clone(),
                if reopened {
                    DependentEffectState::Reopened {
                        revoked_roots: merged.clone(),
                    }
                } else {
                    DependentEffectState::Contestable {
                        revoked_roots: merged.clone(),
                    }
                },
            );
            self.contest_annotations.push(ContestedEffectAnnotation {
                idempotency_key: key,
                revoked_roots: merged,
                reopened,
            });
            changed += 1;
        }
        changed
    }

    /// Current I12.20 standing of one pending effect. Never-contested effects
    /// and unknown keys report [`DependentEffectState::Admissible`].
    /// History is read-only here: this never mutates admission records.
    pub fn dependent_effect_state(&self, idempotency_key: &str) -> DependentEffectState {
        self.contest_state
            .get(idempotency_key)
            .cloned()
            .unwrap_or(DependentEffectState::Admissible)
    }

    /// Idempotency keys currently contested or reopened, in ledger order.
    pub fn contested_effect_keys(&self) -> Vec<String> {
        self.contest_state.keys().cloned().collect()
    }

    /// Append-only revocation annotations. Each entry supersedes without
    /// rewriting the historical admission record it annotates.
    pub fn contest_annotations(&self) -> &[ContestedEffectAnnotation] {
        &self.contest_annotations
    }
}

/// Revoked roots a pending effect directly depends on, for I12.20
/// revocation propagation.
///
/// A pending effect carries forward the influence of its action, resource,
/// operation, lease, and executor identities: when any of those identities
/// names a revoked root, the effect's current validity depended on the
/// revoked source and must be contested. Lineage held outside this file
/// (packets, plans, caches, module profiles) is the caller's closure to
/// traverse; this predicate covers the exact identity surface admitted here.
fn dependent_revoked_roots(
    authorized: &AuthorizedEffect,
    revoked_roots: &BTreeSet<String>,
) -> BTreeSet<String> {
    let proposal = &authorized.proposal;
    let mut matched = BTreeSet::new();
    for candidate in [
        proposal.action_id.as_str(),
        proposal.operation_name.as_str(),
        proposal.resource_ref.as_str(),
        proposal.operation.operation_kind.as_str(),
        proposal.operation.idempotency_key.as_str(),
        proposal.operation.operation_id.as_str(),
        proposal.operation.request_id.as_str(),
        authorized.lease_id.as_str(),
        authorized.executor_boundary.as_str(),
    ] {
        if revoked_roots.contains(candidate) {
            matched.insert(candidate.to_owned());
        }
    }
    matched
}

fn same_logical_effect(left: &ProposedEffect, right: &ProposedEffect) -> bool {
    left.action_id == right.action_id
        && left.canonical_payload_sha256 == right.canonical_payload_sha256
        && left.operation_name == right.operation_name
        && left.resource_ref == right.resource_ref
        && left.operation.operation_kind == right.operation.operation_kind
        && left.operation.effect == right.operation.effect
        && left.operation.state_fence == right.operation.state_fence
}

/// Effect outcome. Unknown outcome is explicitly non-terminal until reconciled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectOutcome {
    Committed,
    Rejected,
    Compensated,
    UnknownOutcome { reason: String },
}

/// Outcome projection over a provider-owned canonical receipt. Common receipt
/// identity, fence and authority fields are not duplicated here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectReceipt {
    pub authorized_effect: AuthorizedEffect,
    pub outcome: EffectOutcome,
    pub canonical_receipt: Option<ReceiptEnvelope>,
}

impl EffectReceipt {
    pub fn unknown(
        authorized_effect: AuthorizedEffect,
        reason: impl Into<String>,
    ) -> Result<Self, AuthorityError> {
        let reason = reason.into();
        validate_text(&reason, "unknown_outcome_reason")?;
        Ok(Self {
            authorized_effect,
            outcome: EffectOutcome::UnknownOutcome { reason },
            canonical_receipt: None,
        })
    }

    pub fn terminal(
        authorized_effect: AuthorizedEffect,
        outcome: EffectOutcome,
        canonical_receipt: ReceiptEnvelope,
    ) -> Result<Self, AuthorityError> {
        if matches!(outcome, EffectOutcome::UnknownOutcome { .. }) {
            return Err(AuthorityError::InvalidLifecycleTransition);
        }
        validate_terminal_receipt(&authorized_effect, &outcome, &canonical_receipt)?;
        Ok(Self {
            authorized_effect,
            outcome,
            canonical_receipt: Some(canonical_receipt),
        })
    }

    pub fn reconcile(
        self,
        outcome: EffectOutcome,
        canonical_receipt: ReceiptEnvelope,
    ) -> Result<Self, AuthorityError> {
        if !matches!(self.outcome, EffectOutcome::UnknownOutcome { .. }) {
            return Err(AuthorityError::InvalidLifecycleTransition);
        }
        Self::terminal(self.authorized_effect, outcome, canonical_receipt)
    }
}

fn validate_terminal_receipt(
    authorized: &AuthorizedEffect,
    outcome: &EffectOutcome,
    receipt: &ReceiptEnvelope,
) -> Result<(), AuthorityError> {
    receipt
        .validate()
        .map_err(|_| AuthorityError::ReceiptMismatch)?;
    if receipt.core.operation.operation_id != authorized.proposal.operation.operation_id
        || receipt.core.operation.idempotency_key != authorized.proposal.operation.idempotency_key
        || receipt.core.operation.state_fence != authorized.proposal.operation.state_fence
    {
        return Err(AuthorityError::ReceiptMismatch);
    }
    let disposition = receipt.core.disposition.kind();
    let valid = match outcome {
        EffectOutcome::Committed | EffectOutcome::Compensated => {
            disposition == ReceiptDispositionKind::Success
        }
        EffectOutcome::Rejected => matches!(
            disposition,
            ReceiptDispositionKind::Failure | ReceiptDispositionKind::Cancelled
        ),
        EffectOutcome::UnknownOutcome { .. } => false,
    };
    if !valid {
        return Err(AuthorityError::ReceiptMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod recovery_tests {
    use std::error::Error;

    use super::*;
    use eliot_contracts::{
        EpochId, EpochLineageId, OperationId, RequestId, ResourceGeneration, StateFence,
        canonical_json_bytes,
    };
    use eliot_receipts::EffectClass;
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(lineage).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    type TestResult = Result<(), Box<dyn Error>>;

    fn operation(key: &str) -> Result<OperationBinding, Box<dyn Error>> {
        Ok(OperationBinding {
            operation_id: OperationId::new("operation:test")?,
            request_id: RequestId::new("request:test")?,
            idempotency_key: key.to_owned(),
            operation_kind: "test.effect".to_owned(),
            effect: EffectClass::ReversibleMutation,
            state_fence: StateFence::new(
                test_epoch(TEST_LINEAGE_A, 1),
                ResourceGeneration::new(1)?,
            ),
        })
    }

    fn authorizer() -> Result<EffectAuthorizer, Box<dyn Error>> {
        let proposal = ProposedEffect::new(
            "action:test",
            operation("idem:test")?,
            "operation:test",
            "resource:test",
            "a".repeat(64),
        )?;
        let authorized = AuthorizedEffect {
            proposal,
            lease_id: LeaseId::new("lease:test")?,
            executor_boundary: "executor:test".to_owned(),
            receipt_obligations: vec![ReceiptObligation::CanonicalEffectReceipt],
        };
        let mut authorizer_state = EffectAuthorizer::default();
        authorizer_state
            .authorized_by_idempotency
            .insert("idem:test".to_owned(), authorized);
        Ok(authorizer_state)
    }

    #[test]
    fn recovery_roundtrip_preserves_complete_effect_ledger() -> TestResult {
        let authorizer = authorizer()?;
        let snapshot = authorizer.snapshot()?;
        let restored = EffectAuthorizer::from_snapshot(snapshot.clone())?;
        assert_eq!(restored.snapshot()?, snapshot);
        Ok(())
    }

    #[test]
    fn recovery_rejects_duplicate_key_substitution_and_malformed_digest() -> TestResult {
        let base = authorizer()?.snapshot()?;

        let mut duplicate = base.clone();
        duplicate.records.push(duplicate.records[0].clone());
        assert!(matches!(
            EffectAuthorizer::from_snapshot(duplicate),
            Err(AuthorityError::InvalidField(
                "effect_authorizer_recovery.records"
            ))
        ));

        let mut substituted_key = base.clone();
        substituted_key.records[0].idempotency_key = "idem:substituted".to_owned();
        assert!(matches!(
            EffectAuthorizer::from_snapshot(substituted_key),
            Err(AuthorityError::InvalidField(
                "effect_authorizer_recovery.idempotency_key"
            ))
        ));

        let mut malformed_digest = base;
        malformed_digest.records[0].canonical_payload_sha256 = "A".repeat(64);
        assert!(matches!(
            EffectAuthorizer::from_snapshot(malformed_digest),
            Err(AuthorityError::InvalidField("canonical_payload_sha256"))
        ));
        Ok(())
    }

    #[test]
    fn recovery_validate_is_semantic_and_empty_state_is_explicit() -> TestResult {
        let empty = EffectAuthorizer::default().snapshot()?;
        empty.validate()?;
        assert_eq!(
            EffectAuthorizer::from_snapshot(empty.clone())?.snapshot()?,
            empty
        );

        let mut invalid = authorizer()?.snapshot()?;
        invalid.records[0].operation_name.clear();
        assert!(matches!(
            invalid.validate(),
            Err(AuthorityError::InvalidField("operation_name"))
        ));

        let mut invalid_executor = authorizer()?.snapshot()?;
        invalid_executor.records[0].executor_boundary.clear();
        assert!(matches!(
            invalid_executor.validate(),
            Err(AuthorityError::InvalidField("executor_boundary"))
        ));
        Ok(())
    }

    #[test]
    fn recovery_json_roundtrip_and_unknown_fields_are_rejected() -> TestResult {
        let snapshot = authorizer()?.snapshot()?;
        let encoded = serde_json::to_string(&snapshot)?;
        let decoded: EffectAuthorizerRecoverySnapshot = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, snapshot);

        let mut unknown_top_level = serde_json::to_value(&snapshot)?;
        unknown_top_level
            .as_object_mut()
            .ok_or("snapshot was not a JSON object")?
            .insert("unexpected".to_owned(), serde_json::Value::Null);
        assert!(
            serde_json::from_value::<EffectAuthorizerRecoverySnapshot>(unknown_top_level).is_err()
        );

        let mut unknown_record = serde_json::to_value(&snapshot)?;
        let records = unknown_record
            .get_mut("records")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or("records was not a JSON array")?;
        records
            .first_mut()
            .ok_or("expected an effect record")?
            .as_object_mut()
            .ok_or("effect record was not a JSON object")?
            .insert("unexpected".to_owned(), serde_json::Value::Null);
        assert!(
            serde_json::from_value::<EffectAuthorizerRecoverySnapshot>(unknown_record).is_err()
        );
        Ok(())
    }

    #[test]
    fn recovery_order_and_canonical_bytes_are_insertion_independent() -> TestResult {
        fn authorized(key: &str) -> Result<AuthorizedEffectRecoveryRecord, Box<dyn Error>> {
            let operation = operation(key)?;
            Ok(AuthorizedEffectRecoveryRecord {
                idempotency_key: key.to_owned(),
                action_id: format!("action:{key}"),
                operation,
                operation_name: "operation:test".to_owned(),
                resource_ref: "resource:test".to_owned(),
                canonical_payload_sha256: "a".repeat(64),
                lease_id: format!("lease:{key}"),
                executor_boundary: "executor:test".to_owned(),
                receipt_obligations: vec![ReceiptObligation::CanonicalEffectReceipt],
            })
        }

        fn state(order: &[&str]) -> Result<EffectAuthorizer, Box<dyn Error>> {
            let mut state = EffectAuthorizer::default();
            for key in order {
                let record = authorized(key)?;
                let proposal = ProposedEffect::new(
                    record.action_id,
                    record.operation,
                    record.operation_name,
                    record.resource_ref,
                    record.canonical_payload_sha256,
                )?;
                let authorized_effect = AuthorizedEffect {
                    proposal,
                    lease_id: LeaseId::new(record.lease_id)?,
                    executor_boundary: record.executor_boundary,
                    receipt_obligations: record.receipt_obligations,
                };
                state
                    .authorized_by_idempotency
                    .insert((*key).to_owned(), authorized_effect);
            }
            Ok(state)
        }

        let first_state = state(&["idem:a", "idem:b"])?;
        let second_state = state(&["idem:b", "idem:a"])?;
        let first_canonical = first_state.snapshot()?;
        let second_canonical = second_state.snapshot()?;
        assert_eq!(first_canonical, second_canonical);
        assert_eq!(
            canonical_json_bytes(&first_canonical)?,
            canonical_json_bytes(&second_canonical)?
        );

        let mut reordered = first_canonical;
        reordered.records.reverse();
        assert!(matches!(
            reordered.validate(),
            Err(AuthorityError::InvalidField(
                "effect_authorizer_recovery.records"
            ))
        ));

        let mut substituted_operation_key = second_state.snapshot()?;
        substituted_operation_key.records[0]
            .operation
            .idempotency_key = "idem:other".to_owned();
        assert!(matches!(
            substituted_operation_key.validate(),
            Err(AuthorityError::InvalidField(
                "effect_authorizer_recovery.idempotency_key"
            ))
        ));
        Ok(())
    }
}
