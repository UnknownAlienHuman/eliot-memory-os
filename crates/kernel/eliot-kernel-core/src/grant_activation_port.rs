//! P-07 live grant/introduction activation and revocation port.
//!
//! This module is the one current P-07 owner for live capability-grant and
//! capability-introduction activation and revocation inside
//! `eliot-kernel-core`. Governor (`eliot-authority`) keeps owning semantic
//! admission, lineage evaluation and the pure grant/introduction contracts,
//! while ORS keeps owning durable envelopes and recovery. This port creates
//! no second grant graph, no second epoch and no durable store:
//!
//! - every intent is validated (identities, graph revision, binding, fence,
//!   epoch, effect/proof ceiling and expiry) before any mutation;
//! - one in-memory intent ledger keyed by operation identity records every
//!   committed receipt and every reconciling unknown for the process
//!   lifetime. The canonical digest binds the full intent payload, so exact
//!   replay under one operation identity returns the same receipt while a
//!   changed payload under one identity is
//!   [`KernelError::IdempotencyConflict`];
//! - revocation fences the revoked grant plus every recorded descendant and
//!   every dependent introduction;
//! - revocation of an unknown target, and effects declared unknown at
//!   revocation time, stay reconciling: they are recorded, never assumed
//!   fenced, and never retried blindly;
//! - stale epochs, future (unactivated) epochs and cross-lineage requests are
//!   rejected before mutation.
//!
//! The port stores no epoch and reads no clock. The single P-07 epoch owner
//! supplies its current [`AuthorityEpoch`] on every call and the caller
//! supplies the observation time for expiry checks, so this adapter can never
//! fence against a shadow epoch or a stale reading. Only canonical
//! [`AuthorityActivationReceipt`](eliot_runtime_contracts::AuthorityActivationReceipt)
//! and
//! [`AuthorityRevocationReceipt`](eliot_runtime_contracts::AuthorityRevocationReceipt)
//! values leave this port, and each one passes its own `validate()` before it
//! is returned. Durable write-ahead intent persistence stays with a later ORS
//! wave; until then restart reconciliation re-presents intents through this
//! same port.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard};

use eliot_contracts::{AuthorityEpoch, canonical_json_bytes, sha256_hex};
use eliot_receipts::{AuthorityBinding, EffectClass, ProofCeiling};
use eliot_runtime_contracts::{
    AuthorityActivationReceipt, AuthorityRevocationReceipt, AuthorityState,
};
use serde::Serialize;

use crate::error::{KernelError, validate_id, validate_text};

/// Live grant-activation intent presented to the one P-07 port.
///
/// The port validates every field before mutation and binds the full payload
/// into the idempotency digest, so any change under one operation identity is
/// an identity conflict rather than a second activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantActivationIntent {
    /// Idempotency identity. Ledger key and receipt-derivation root.
    pub operation_id: String,
    /// Grant identity to activate. Must be unrecorded: restore never
    /// reactivates a path, so a recorded identity is rejected.
    pub grant_id: String,
    /// Parent lineage. `None` only for an explicit authority root; otherwise
    /// the parent must be recorded, active, unexpired and on the exact same
    /// root and fence.
    pub parent_grant_id: Option<String>,
    /// Lineage domain. A parent on a different root is cross-lineage.
    pub authority_root_ref: String,
    /// Governor snapshot this activation is presented under.
    pub snapshot_id: String,
    /// Grant-graph revision. Zero is invalid; below the greatest revision
    /// observed for this root is stale.
    pub grant_graph_revision: u64,
    /// Holder principal the grant is activated for.
    pub holder_principal: String,
    /// Session the grant is activated for.
    pub session_id: String,
    /// Scope the grant is activated for.
    pub scope_id: String,
    /// Authority binding pinning owner, epoch, fence, effect and ceiling.
    pub binding: AuthorityBinding,
    /// Requested effect ceiling. Must not exceed the binding ceiling.
    pub allowed_effect: EffectClass,
    /// Requested proof ceiling. Must not exceed the binding ceiling.
    pub proof_ceiling: ProofCeiling,
    /// Logical issuance time in Unix milliseconds.
    pub issued_at_ms: i64,
    /// Logical expiry time in Unix milliseconds, if the grant expires.
    pub expires_at_ms: Option<i64>,
    /// Receipt obligations the effect path must discharge.
    pub receipt_obligations: Vec<String>,
}

/// Live grant-revocation intent presented to the one P-07 port.
///
/// Revocation fences the named grant plus every recorded descendant and every
/// dependent introduction. Revocation of an unknown grant records a
/// reconciling intent instead of fabricating a fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantRevocationIntent {
    /// Idempotency identity. Ledger key and receipt-derivation root.
    pub operation_id: String,
    /// Grant identity to fence.
    pub grant_id: String,
    /// Lineage domain. Must match the recorded grant root.
    pub authority_root_ref: String,
    /// Governor snapshot this revocation is presented under.
    pub snapshot_id: String,
    /// Grant-graph revision. Zero is invalid; below the greatest revision
    /// observed for this root is stale.
    pub grant_graph_revision: u64,
    /// Authority binding pinning owner, epoch and fence for this revocation.
    pub binding: AuthorityBinding,
    /// Effect operation identities whose outcome is unknown. They are
    /// recorded as reconciling and never closed or retried by this port.
    pub unknown_outcome_operations: Vec<String>,
    /// Receipt obligations the revocation path must discharge.
    pub receipt_obligations: Vec<String>,
}

/// Live introduction-activation intent presented to the one P-07 port.
///
/// Every supporting grant must be recorded, active, unexpired, on the same
/// root and fence, and its recorded ceilings must cover the requested
/// effect and proof ceiling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntroductionActivationIntent {
    /// Idempotency identity. Ledger key and receipt-derivation root.
    pub operation_id: String,
    /// Introduction identity to activate. Must be unrecorded.
    pub introduction_id: String,
    /// Governor snapshot this activation is presented under.
    pub snapshot_id: String,
    /// Lineage domain. Every supporting grant must share it.
    pub authority_root_ref: String,
    /// Grant-graph revision. Zero is invalid; below the greatest revision
    /// observed for this root is stale.
    pub grant_graph_revision: u64,
    /// Supporting grant identities. At least one is required.
    pub supporting_grant_ids: Vec<String>,
    /// Exact resource handle being introduced.
    pub resource_handle: String,
    /// Facet manifest reference for the introduced surface.
    pub facet_manifest_ref: String,
    /// Holder principal the introduction is activated for.
    pub holder_principal: String,
    /// Session the introduction is activated for.
    pub session_id: String,
    /// Scope the introduction is activated for.
    pub scope_id: String,
    /// Authority binding pinning owner, epoch, fence, effect and ceiling.
    pub binding: AuthorityBinding,
    /// Requested effect ceiling. Must not exceed the binding ceiling nor any
    /// supporting grant ceiling.
    pub allowed_effect: EffectClass,
    /// Requested proof ceiling. Must not exceed the binding ceiling nor any
    /// supporting grant ceiling.
    pub proof_ceiling: ProofCeiling,
    /// Logical issuance time in Unix milliseconds.
    pub issued_at_ms: i64,
    /// Logical expiry time in Unix milliseconds, if the introduction expires.
    pub expires_at_ms: Option<i64>,
    /// Receipt obligations the effect path must discharge.
    pub receipt_obligations: Vec<String>,
}

/// Live introduction-revocation intent presented to the one P-07 port.
///
/// Revocation of an unknown introduction records a reconciling intent instead
/// of fabricating a fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntroductionRevocationIntent {
    /// Idempotency identity. Ledger key and receipt-derivation root.
    pub operation_id: String,
    /// Introduction identity to fence.
    pub introduction_id: String,
    /// Lineage domain. Must match the recorded introduction root.
    pub authority_root_ref: String,
    /// Governor snapshot this revocation is presented under.
    pub snapshot_id: String,
    /// Grant-graph revision. Zero is invalid; below the greatest revision
    /// observed for this root is stale.
    pub grant_graph_revision: u64,
    /// Authority binding pinning owner, epoch and fence for this revocation.
    pub binding: AuthorityBinding,
    /// Effect operation identities whose outcome is unknown. They are
    /// recorded as reconciling and never closed or retried by this port.
    pub unknown_outcome_operations: Vec<String>,
    /// Receipt obligations the revocation path must discharge.
    pub receipt_obligations: Vec<String>,
}

/// Canonical receipt committed by one port operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommittedReceipt {
    /// Receipt that makes an exact authority projection active.
    Activation(AuthorityActivationReceipt),
    /// Receipt that fences an authority projection before reconciliation.
    Revocation(AuthorityRevocationReceipt),
}

impl CommittedReceipt {
    /// Re-validates the committed canonical receipt.
    ///
    /// # Errors
    ///
    /// Returns the contract rejection when the stored receipt no longer
    /// validates.
    pub fn validate(&self) -> Result<(), KernelError> {
        match self {
            Self::Activation(receipt) => receipt.validate()?,
            Self::Revocation(receipt) => receipt.validate()?,
        }
        Ok(())
    }

    fn into_activation(self) -> Result<AuthorityActivationReceipt, KernelError> {
        match self {
            Self::Activation(receipt) => Ok(receipt),
            Self::Revocation(_) => Err(KernelError::IdempotencyConflict),
        }
    }

    fn into_revocation(self) -> Result<AuthorityRevocationReceipt, KernelError> {
        match self {
            Self::Revocation(receipt) => Ok(receipt),
            Self::Activation(_) => Err(KernelError::IdempotencyConflict),
        }
    }
}

/// Recorded outcome of one operation identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntentDisposition {
    /// The operation committed exactly one canonical receipt.
    Committed(CommittedReceipt),
    /// The target or effect is unknown. Recorded only; reconcile by receipt
    /// before any retry. The static field and reason reproduce the original
    /// rejection exactly on replay.
    Reconciling {
        /// Field that named the unknown identity.
        field: &'static str,
        /// Stable reason, including the reconcile-before-retry rule.
        reason: &'static str,
    },
}

impl IntentDisposition {
    fn into_activation_receipt(self) -> Result<AuthorityActivationReceipt, KernelError> {
        match self {
            Self::Committed(receipt) => receipt.into_activation(),
            Self::Reconciling { field, reason } => Err(KernelError::InvalidField { field, reason }),
        }
    }

    fn into_revocation_receipt(self) -> Result<AuthorityRevocationReceipt, KernelError> {
        match self {
            Self::Committed(receipt) => receipt.into_revocation(),
            Self::Reconciling { field, reason } => Err(KernelError::InvalidField { field, reason }),
        }
    }
}

/// The one current P-07 live activation/revocation port.
///
/// All mutation happens under one mutex, so validation, intent recording and
/// live-state changes are atomic with respect to other port calls. The port
/// holds no epoch and reads no clock; both arrive per call from the single
/// P-07 epoch owner.
#[derive(Debug, Default)]
pub struct GrantActivationPort {
    ledger: Mutex<PortLedger>,
}

impl GrantActivationPort {
    /// Creates an empty port with no recorded intents, grants or revisions.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Activates one grant and returns its canonical activation receipt.
    ///
    /// Exact replay under one operation identity returns the same receipt. A
    /// changed payload under one identity, a duplicate grant identity, a
    /// stale or future epoch, a cross-lineage parent, an over-ceiling effect
    /// or proof claim, or an expired intent fails before any mutation.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::IdempotencyConflict`] for a changed payload,
    /// [`KernelError::StaleEpoch`] for a fenced epoch,
    /// [`KernelError::FenceMismatch`] for a future epoch or a cross-lineage
    /// parent or fence, [`KernelError::Expired`] for an expired intent, and
    /// [`KernelError::InvalidField`] for any other invalid identity,
    /// revision, binding, ceiling or lineage value.
    pub fn activate_grant(
        &self,
        request: &GrantActivationIntent,
        active_epoch: AuthorityEpoch,
        now_ms: i64,
    ) -> Result<AuthorityActivationReceipt, KernelError> {
        let mut ledger = self.lock_ledger();
        validate_id(&request.operation_id, "operation_id")?;
        let digest = request.digest()?;
        match ledger.resolve(&request.operation_id, &digest) {
            IntentResolve::Conflict => return Err(KernelError::IdempotencyConflict),
            IntentResolve::Replay(disposition) => {
                return disposition.into_activation_receipt();
            }
            IntentResolve::New => {}
        }
        validate_grant_activation(request, &ledger, active_epoch, now_ms)?;
        let operation_id = request.operation_id.clone();
        let receipt = AuthorityActivationReceipt {
            activation_id: format!("activation-{operation_id}"),
            snapshot_id: request.snapshot_id.clone(),
            authority_epoch: active_epoch,
            state: AuthorityState::Active,
        };
        receipt.validate()?;
        ledger.grants.insert(
            request.grant_id.clone(),
            LiveGrantRecord {
                parent_grant_id: request.parent_grant_id.clone(),
                authority_root_ref: request.authority_root_ref.clone(),
                binding: request.binding.clone(),
                allowed_effect: request.allowed_effect,
                proof_ceiling: request.proof_ceiling,
                expires_at_ms: request.expires_at_ms,
                status: LiveStatus::Active,
            },
        );
        ledger.note_revision(&request.authority_root_ref, request.grant_graph_revision);
        ledger.intents.insert(
            operation_id.clone(),
            PortIntentRecord {
                operation_id,
                digest,
                kind: IntentKind::GrantActivation,
                disposition: IntentDisposition::Committed(CommittedReceipt::Activation(
                    receipt.clone(),
                )),
                fenced: Vec::new(),
            },
        );
        Ok(receipt)
    }

    /// Revokes one grant, fences every recorded descendant and dependent
    /// introduction, and returns the canonical revocation receipt.
    ///
    /// Revocation of an unknown grant records a reconciling intent and fails
    /// without fabricating a fence. Effects declared unknown stay
    /// reconciling. Re-revocation re-confirms the fence at the presented
    /// epoch and returns a fresh receipt; only exact replay returns the same
    /// receipt.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::IdempotencyConflict`] for a changed payload,
    /// [`KernelError::StaleEpoch`] for a fenced epoch,
    /// [`KernelError::FenceMismatch`] for a future epoch or a cross-lineage
    /// root, and [`KernelError::InvalidField`] for any other invalid
    /// identity, revision or binding value, including an unknown grant
    /// identity, which is recorded as reconciling.
    pub fn revoke_grant(
        &self,
        request: &GrantRevocationIntent,
        active_epoch: AuthorityEpoch,
    ) -> Result<AuthorityRevocationReceipt, KernelError> {
        let mut ledger = self.lock_ledger();
        validate_id(&request.operation_id, "operation_id")?;
        let digest = request.digest()?;
        match ledger.resolve(&request.operation_id, &digest) {
            IntentResolve::Conflict => return Err(KernelError::IdempotencyConflict),
            IntentResolve::Replay(disposition) => {
                return disposition.into_revocation_receipt();
            }
            IntentResolve::New => {}
        }
        validate_id(&request.grant_id, "grant_id")?;
        validate_id(&request.authority_root_ref, "authority_root_ref")?;
        validate_id(&request.snapshot_id, "snapshot_id")?;
        for obligation in &request.receipt_obligations {
            validate_id(obligation, "receipt_obligation")?;
        }
        let mut unknown_effects = BTreeSet::new();
        for operation in &request.unknown_outcome_operations {
            validate_id(operation, "unknown_outcome_operation")?;
            unknown_effects.insert(operation.clone());
        }
        check_binding(&request.binding, active_epoch)?;
        let recorded_root = match ledger.grants.get(&request.grant_id) {
            None => {
                ledger.intents.insert(
                    request.operation_id.clone(),
                    PortIntentRecord {
                        operation_id: request.operation_id.clone(),
                        digest,
                        kind: IntentKind::GrantRevocation,
                        disposition: IntentDisposition::Reconciling {
                            field: "grant_id",
                            reason: "unknown grant lineage; reconcile by receipt before retry",
                        },
                        fenced: Vec::new(),
                    },
                );
                return Err(KernelError::InvalidField {
                    field: "grant_id",
                    reason: "unknown grant lineage; reconcile by receipt before retry",
                });
            }
            Some(record) => record.authority_root_ref.clone(),
        };
        if recorded_root != request.authority_root_ref {
            return Err(KernelError::FenceMismatch);
        }
        check_revision(
            &ledger,
            &request.authority_root_ref,
            request.grant_graph_revision,
        )?;
        let fenced = descendant_closure(
            &ledger.grants,
            &request.authority_root_ref,
            &request.grant_id,
        );
        for grant_id in &fenced {
            if let Some(target) = ledger.grants.get_mut(grant_id) {
                target.status = LiveStatus::Revoked;
            }
        }
        let fenced_set: BTreeSet<&str> = fenced.iter().map(String::as_str).collect();
        for introduction in ledger.introductions.values_mut() {
            if introduction.status == LiveStatus::Active
                && introduction
                    .supporting_grant_ids
                    .iter()
                    .any(|id| fenced_set.contains(id.as_str()))
            {
                introduction.status = LiveStatus::Revoked;
            }
        }
        note_unknown_effects(&mut ledger, &unknown_effects, &request.grant_id);
        let operation_id = request.operation_id.clone();
        let receipt = AuthorityRevocationReceipt {
            revocation_id: format!("revocation-{operation_id}"),
            snapshot_id: request.snapshot_id.clone(),
            authority_epoch: active_epoch,
            state: AuthorityState::Revoked,
        };
        receipt.validate()?;
        ledger.note_revision(&request.authority_root_ref, request.grant_graph_revision);
        ledger.intents.insert(
            operation_id.clone(),
            PortIntentRecord {
                operation_id,
                digest,
                kind: IntentKind::GrantRevocation,
                disposition: IntentDisposition::Committed(CommittedReceipt::Revocation(
                    receipt.clone(),
                )),
                fenced,
            },
        );
        Ok(receipt)
    }

    /// Activates one introduction and returns its canonical receipt.
    ///
    /// Every supporting grant must be recorded, active, unexpired, on the
    /// same root and fence, with ceilings covering the requested effect and
    /// proof. Replay, conflict, stale, future, cross-lineage, over-ceiling
    /// and expired cases behave exactly as in [`Self::activate_grant`].
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::activate_grant`], with the
    /// supporting-grant field naming the unverifiable lineage.
    pub fn activate_introduction(
        &self,
        request: &IntroductionActivationIntent,
        active_epoch: AuthorityEpoch,
        now_ms: i64,
    ) -> Result<AuthorityActivationReceipt, KernelError> {
        let mut ledger = self.lock_ledger();
        validate_id(&request.operation_id, "operation_id")?;
        let digest = request.digest()?;
        match ledger.resolve(&request.operation_id, &digest) {
            IntentResolve::Conflict => return Err(KernelError::IdempotencyConflict),
            IntentResolve::Replay(disposition) => {
                return disposition.into_activation_receipt();
            }
            IntentResolve::New => {}
        }
        validate_introduction_activation(request, &ledger, active_epoch, now_ms)?;
        let mut supporting = BTreeSet::new();
        for id in &request.supporting_grant_ids {
            supporting.insert(id.clone());
        }
        let operation_id = request.operation_id.clone();
        let receipt = AuthorityActivationReceipt {
            activation_id: format!("activation-{operation_id}"),
            snapshot_id: request.snapshot_id.clone(),
            authority_epoch: active_epoch,
            state: AuthorityState::Active,
        };
        receipt.validate()?;
        ledger.introductions.insert(
            request.introduction_id.clone(),
            LiveIntroductionRecord {
                authority_root_ref: request.authority_root_ref.clone(),
                supporting_grant_ids: supporting,
                status: LiveStatus::Active,
            },
        );
        ledger.note_revision(&request.authority_root_ref, request.grant_graph_revision);
        ledger.intents.insert(
            operation_id.clone(),
            PortIntentRecord {
                operation_id,
                digest,
                kind: IntentKind::IntroductionActivation,
                disposition: IntentDisposition::Committed(CommittedReceipt::Activation(
                    receipt.clone(),
                )),
                fenced: Vec::new(),
            },
        );
        Ok(receipt)
    }

    /// Revokes one introduction and returns the canonical revocation receipt.
    ///
    /// Revocation of an unknown introduction records a reconciling intent and
    /// fails without fabricating a fence. Effects declared unknown stay
    /// reconciling.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::revoke_grant`], with the
    /// introduction field naming the unknown identity.
    pub fn revoke_introduction(
        &self,
        request: &IntroductionRevocationIntent,
        active_epoch: AuthorityEpoch,
    ) -> Result<AuthorityRevocationReceipt, KernelError> {
        let mut ledger = self.lock_ledger();
        validate_id(&request.operation_id, "operation_id")?;
        let digest = request.digest()?;
        match ledger.resolve(&request.operation_id, &digest) {
            IntentResolve::Conflict => return Err(KernelError::IdempotencyConflict),
            IntentResolve::Replay(disposition) => {
                return disposition.into_revocation_receipt();
            }
            IntentResolve::New => {}
        }
        validate_id(&request.introduction_id, "introduction_id")?;
        validate_id(&request.authority_root_ref, "authority_root_ref")?;
        validate_id(&request.snapshot_id, "snapshot_id")?;
        for obligation in &request.receipt_obligations {
            validate_id(obligation, "receipt_obligation")?;
        }
        let mut unknown_effects = BTreeSet::new();
        for operation in &request.unknown_outcome_operations {
            validate_id(operation, "unknown_outcome_operation")?;
            unknown_effects.insert(operation.clone());
        }
        check_binding(&request.binding, active_epoch)?;
        let recorded_root = match ledger.introductions.get(&request.introduction_id) {
            None => {
                ledger.intents.insert(
                    request.operation_id.clone(),
                    PortIntentRecord {
                        operation_id: request.operation_id.clone(),
                        digest,
                        kind: IntentKind::IntroductionRevocation,
                        disposition: IntentDisposition::Reconciling {
                            field: "introduction_id",
                            reason: "unknown introduction lineage; reconcile by receipt before retry",
                        },
                        fenced: Vec::new(),
                    },
                );
                return Err(KernelError::InvalidField {
                    field: "introduction_id",
                    reason: "unknown introduction lineage; reconcile by receipt before retry",
                });
            }
            Some(record) => record.authority_root_ref.clone(),
        };
        if recorded_root != request.authority_root_ref {
            return Err(KernelError::FenceMismatch);
        }
        check_revision(
            &ledger,
            &request.authority_root_ref,
            request.grant_graph_revision,
        )?;
        if let Some(target) = ledger.introductions.get_mut(&request.introduction_id) {
            target.status = LiveStatus::Revoked;
        }
        note_unknown_effects(&mut ledger, &unknown_effects, &request.introduction_id);
        let operation_id = request.operation_id.clone();
        let receipt = AuthorityRevocationReceipt {
            revocation_id: format!("revocation-{operation_id}"),
            snapshot_id: request.snapshot_id.clone(),
            authority_epoch: active_epoch,
            state: AuthorityState::Revoked,
        };
        receipt.validate()?;
        ledger.note_revision(&request.authority_root_ref, request.grant_graph_revision);
        ledger.intents.insert(
            operation_id.clone(),
            PortIntentRecord {
                operation_id,
                digest,
                kind: IntentKind::IntroductionRevocation,
                disposition: IntentDisposition::Committed(CommittedReceipt::Revocation(
                    receipt.clone(),
                )),
                fenced: vec![request.introduction_id.clone()],
            },
        );
        Ok(receipt)
    }

    /// Returns the recorded disposition of one operation identity, if any.
    #[must_use]
    pub fn disposition(&self, operation_id: &str) -> Option<IntentDisposition> {
        let ledger = self.lock_ledger();
        ledger
            .intents
            .get(operation_id)
            .map(|record| record.disposition.clone())
    }

    /// Returns the sorted fenced target identities recorded by one
    /// revocation operation: the revoked grant plus every fenced descendant,
    /// or the single fenced introduction.
    ///
    /// Returns `None` for an unknown operation identity and for operations
    /// that are not revocations.
    #[must_use]
    pub fn revocation_closure(&self, operation_id: &str) -> Option<Vec<String>> {
        let ledger = self.lock_ledger();
        let record = ledger.intents.get(operation_id)?;
        if !matches!(
            record.kind,
            IntentKind::GrantRevocation | IntentKind::IntroductionRevocation
        ) {
            return None;
        }
        Some(record.fenced.clone())
    }

    /// Returns the sorted identities that stay reconciling: unknown
    /// revocation targets plus effects declared unknown at revocation time.
    /// They must be reconciled by receipt, never retried blindly.
    #[must_use]
    pub fn reconciling_operations(&self) -> Vec<String> {
        let ledger = self.lock_ledger();
        let mut operations = BTreeSet::new();
        for record in ledger.intents.values() {
            if matches!(record.disposition, IntentDisposition::Reconciling { .. }) {
                operations.insert(record.operation_id.clone());
            }
        }
        for operation in ledger.reconciling_effects.keys() {
            operations.insert(operation.clone());
        }
        operations.into_iter().collect()
    }

    /// Returns `true` only when the grant is recorded as revoked.
    ///
    /// An unknown grant is not assumed fenced; it stays reconciling until an
    /// explicit revocation commits.
    #[must_use]
    pub fn grant_revoked(&self, grant_id: &str) -> bool {
        let ledger = self.lock_ledger();
        ledger
            .grants
            .get(grant_id)
            .is_some_and(|record| record.status == LiveStatus::Revoked)
    }

    /// Returns `true` only when the introduction is recorded as revoked,
    /// either directly or through a fenced supporting grant.
    ///
    /// An unknown introduction is not assumed fenced; it stays reconciling
    /// until an explicit revocation commits.
    #[must_use]
    pub fn introduction_revoked(&self, introduction_id: &str) -> bool {
        let ledger = self.lock_ledger();
        ledger
            .introductions
            .get(introduction_id)
            .is_some_and(|record| record.status == LiveStatus::Revoked)
    }

    fn lock_ledger(&self) -> MutexGuard<'_, PortLedger> {
        self.ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Boundary crossed by one recorded operation identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IntentKind {
    GrantActivation,
    GrantRevocation,
    IntroductionActivation,
    IntroductionRevocation,
}

/// Result of resolving an operation identity against its recorded digest.
enum IntentResolve {
    /// The identity was never seen.
    New,
    /// The identity was seen with a different payload.
    Conflict,
    /// The identity was seen with the same payload.
    Replay(IntentDisposition),
}

/// Live enforcement state of one recorded operation identity.
#[derive(Clone, Debug)]
struct PortIntentRecord {
    operation_id: String,
    digest: String,
    kind: IntentKind,
    disposition: IntentDisposition,
    fenced: Vec<String>,
}

/// Live enforcement state of one recorded grant.
#[derive(Clone, Debug)]
struct LiveGrantRecord {
    parent_grant_id: Option<String>,
    authority_root_ref: String,
    binding: AuthorityBinding,
    allowed_effect: EffectClass,
    proof_ceiling: ProofCeiling,
    expires_at_ms: Option<i64>,
    status: LiveStatus,
}

/// Live enforcement state of one recorded introduction.
#[derive(Clone, Debug)]
struct LiveIntroductionRecord {
    authority_root_ref: String,
    supporting_grant_ids: BTreeSet<String>,
    status: LiveStatus,
}

/// Whether one recorded grant or introduction still carries live authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiveStatus {
    Active,
    Revoked,
}

/// Process-lifetime intent ledger and live lineage state.
#[derive(Debug, Default)]
struct PortLedger {
    intents: BTreeMap<String, PortIntentRecord>,
    grants: BTreeMap<String, LiveGrantRecord>,
    introductions: BTreeMap<String, LiveIntroductionRecord>,
    max_revision: BTreeMap<String, u64>,
    reconciling_effects: BTreeMap<String, String>,
}

impl PortLedger {
    fn resolve(&self, operation_id: &str, digest: &str) -> IntentResolve {
        let Some(record) = self.intents.get(operation_id) else {
            return IntentResolve::New;
        };
        if record.digest == digest {
            IntentResolve::Replay(record.disposition.clone())
        } else {
            IntentResolve::Conflict
        }
    }

    fn note_revision(&mut self, authority_root_ref: &str, grant_graph_revision: u64) {
        let current = self
            .max_revision
            .get(authority_root_ref)
            .copied()
            .unwrap_or(0);
        self.max_revision.insert(
            authority_root_ref.to_owned(),
            current.max(grant_graph_revision),
        );
    }
}

/// Ranks effect classes weakest-first, mirroring the authority issuance core
/// so this port never depends on Governor effect policy.
const fn effect_rank(effect: EffectClass) -> u8 {
    match effect {
        EffectClass::Read => 0,
        EffectClass::Candidate => 1,
        EffectClass::ReversibleMutation => 2,
        EffectClass::ExternalEffect => 3,
    }
}

/// Rejects a zero graph revision and a revision older than the greatest
/// revision observed for the lineage root.
fn check_revision(
    ledger: &PortLedger,
    authority_root_ref: &str,
    grant_graph_revision: u64,
) -> Result<(), KernelError> {
    if grant_graph_revision == 0 {
        return Err(KernelError::InvalidField {
            field: "grant_graph_revision",
            reason: "must be greater than zero",
        });
    }
    if let Some(&recorded) = ledger.max_revision.get(authority_root_ref)
        && grant_graph_revision < recorded
    {
        return Err(KernelError::InvalidField {
            field: "grant_graph_revision",
            reason: "stale grant-graph revision",
        });
    }
    Ok(())
}

/// Validates the binding owner, fence consistency and epoch currency.
///
/// A binding older than the active epoch is stale; a binding newer than the
/// active epoch names an unactivated future and fails as a fence mismatch,
/// mirroring exact route-fence enforcement.
fn check_binding(
    binding: &AuthorityBinding,
    active_epoch: AuthorityEpoch,
) -> Result<(), KernelError> {
    validate_text(&binding.authority_owner, "binding.authority_owner")?;
    binding.state_fence.validate()?;
    if binding.authority_epoch != binding.state_fence.authority_epoch {
        return Err(KernelError::FenceMismatch);
    }
    if binding.authority_epoch.value() < active_epoch.value() {
        return Err(KernelError::StaleEpoch {
            observed: binding.authority_epoch.value(),
            active: active_epoch.value(),
        });
    }
    if binding.authority_epoch != active_epoch {
        return Err(KernelError::FenceMismatch);
    }
    Ok(())
}

/// Rejects a requested effect or proof claim above the binding ceiling.
fn check_ceiling(
    allowed_effect: EffectClass,
    proof_ceiling: ProofCeiling,
    binding: &AuthorityBinding,
) -> Result<(), KernelError> {
    if effect_rank(allowed_effect) > effect_rank(binding.allowed_effect) {
        return Err(KernelError::InvalidField {
            field: "allowed_effect",
            reason: "exceeds binding effect ceiling",
        });
    }
    if !proof_ceiling.is_at_most(binding.proof_ceiling) {
        return Err(KernelError::InvalidField {
            field: "proof_ceiling",
            reason: "exceeds binding proof ceiling",
        });
    }
    Ok(())
}

/// Rejects an expiry that is not strictly later than issuance, and an intent
/// that is already expired at the observation time.
fn check_expiry(
    issued_at_ms: i64,
    expires_at_ms: Option<i64>,
    now_ms: i64,
) -> Result<(), KernelError> {
    if let Some(expires) = expires_at_ms {
        if expires <= issued_at_ms {
            return Err(KernelError::InvalidField {
                field: "expires_at_ms",
                reason: "expiry must be strictly later than issuance",
            });
        }
        if expires <= now_ms {
            return Err(KernelError::Expired {
                expires_at_ms: expires,
            });
        }
    }
    Ok(())
}

/// Records effects declared unknown at revocation time as reconciling.
/// First recording wins; unknown effects are never closed or retried here.
fn note_unknown_effects(
    ledger: &mut PortLedger,
    unknown_effects: &BTreeSet<String>,
    context_id: &str,
) {
    for operation in unknown_effects {
        if !ledger.reconciling_effects.contains_key(operation) {
            ledger
                .reconciling_effects
                .insert(operation.clone(), context_id.to_owned());
        }
    }
}

/// Returns the grant plus every transitive descendant on the same root, in
/// sorted order. Lineage that crosses roots is never followed.
fn descendant_closure(
    grants: &BTreeMap<String, LiveGrantRecord>,
    authority_root_ref: &str,
    grant_id: &str,
) -> Vec<String> {
    let mut fenced = BTreeSet::new();
    let mut frontier = vec![grant_id.to_owned()];
    while let Some(current) = frontier.pop() {
        if !fenced.insert(current.clone()) {
            continue;
        }
        for (candidate_id, candidate) in grants {
            if candidate.parent_grant_id.as_deref() == Some(current.as_str())
                && candidate.authority_root_ref == authority_root_ref
            {
                frontier.push(candidate_id.clone());
            }
        }
    }
    fenced.into_iter().collect()
}

/// Validates one grant activation against the recorded lineage before any
/// mutation.
fn validate_grant_activation(
    request: &GrantActivationIntent,
    ledger: &PortLedger,
    active_epoch: AuthorityEpoch,
    now_ms: i64,
) -> Result<(), KernelError> {
    validate_id(&request.grant_id, "grant_id")?;
    if let Some(parent) = &request.parent_grant_id {
        validate_id(parent, "parent_grant_id")?;
    }
    validate_id(&request.authority_root_ref, "authority_root_ref")?;
    validate_id(&request.snapshot_id, "snapshot_id")?;
    validate_id(&request.holder_principal, "holder_principal")?;
    validate_id(&request.session_id, "session_id")?;
    validate_id(&request.scope_id, "scope_id")?;
    for obligation in &request.receipt_obligations {
        validate_id(obligation, "receipt_obligation")?;
    }
    check_revision(
        ledger,
        &request.authority_root_ref,
        request.grant_graph_revision,
    )?;
    check_binding(&request.binding, active_epoch)?;
    check_ceiling(
        request.allowed_effect,
        request.proof_ceiling,
        &request.binding,
    )?;
    check_expiry(request.issued_at_ms, request.expires_at_ms, now_ms)?;
    if ledger.grants.contains_key(&request.grant_id) {
        return Err(KernelError::InvalidField {
            field: "grant_id",
            reason: "grant identity is already recorded; restore never reactivates a path",
        });
    }
    if let Some(parent_id) = &request.parent_grant_id {
        let Some(parent) = ledger.grants.get(parent_id) else {
            return Err(KernelError::InvalidField {
                field: "parent_grant_id",
                reason: "unknown parent lineage",
            });
        };
        if parent.authority_root_ref != request.authority_root_ref {
            return Err(KernelError::FenceMismatch);
        }
        if parent.binding.state_fence != request.binding.state_fence {
            return Err(KernelError::FenceMismatch);
        }
        if parent.status != LiveStatus::Active {
            return Err(KernelError::InvalidField {
                field: "parent_grant_id",
                reason: "parent lineage is fenced",
            });
        }
        if let Some(expires) = parent.expires_at_ms
            && expires <= now_ms
        {
            return Err(KernelError::InvalidField {
                field: "parent_grant_id",
                reason: "parent lineage is expired",
            });
        }
    }
    Ok(())
}

/// Validates one introduction activation against the recorded lineage before
/// any mutation.
fn validate_introduction_activation(
    request: &IntroductionActivationIntent,
    ledger: &PortLedger,
    active_epoch: AuthorityEpoch,
    now_ms: i64,
) -> Result<(), KernelError> {
    validate_id(&request.introduction_id, "introduction_id")?;
    validate_id(&request.snapshot_id, "snapshot_id")?;
    validate_id(&request.authority_root_ref, "authority_root_ref")?;
    validate_id(&request.resource_handle, "resource_handle")?;
    validate_id(&request.facet_manifest_ref, "facet_manifest_ref")?;
    validate_id(&request.holder_principal, "holder_principal")?;
    validate_id(&request.session_id, "session_id")?;
    validate_id(&request.scope_id, "scope_id")?;
    for obligation in &request.receipt_obligations {
        validate_id(obligation, "receipt_obligation")?;
    }
    for id in &request.supporting_grant_ids {
        validate_id(id, "supporting_grant_id")?;
    }
    if request.supporting_grant_ids.is_empty() {
        return Err(KernelError::InvalidField {
            field: "supporting_grant_ids",
            reason: "at least one supporting grant is required",
        });
    }
    check_revision(
        ledger,
        &request.authority_root_ref,
        request.grant_graph_revision,
    )?;
    check_binding(&request.binding, active_epoch)?;
    check_ceiling(
        request.allowed_effect,
        request.proof_ceiling,
        &request.binding,
    )?;
    check_expiry(request.issued_at_ms, request.expires_at_ms, now_ms)?;
    if ledger.introductions.contains_key(&request.introduction_id) {
        return Err(KernelError::InvalidField {
            field: "introduction_id",
            reason: "introduction identity is already recorded",
        });
    }
    for id in &request.supporting_grant_ids {
        let Some(grant) = ledger.grants.get(id) else {
            return Err(KernelError::InvalidField {
                field: "supporting_grant_ids",
                reason: "unknown supporting lineage",
            });
        };
        if grant.authority_root_ref != request.authority_root_ref {
            return Err(KernelError::FenceMismatch);
        }
        if grant.binding.state_fence != request.binding.state_fence {
            return Err(KernelError::FenceMismatch);
        }
        if grant.status != LiveStatus::Active {
            return Err(KernelError::InvalidField {
                field: "supporting_grant_ids",
                reason: "supporting lineage is fenced",
            });
        }
        if effect_rank(request.allowed_effect) > effect_rank(grant.allowed_effect) {
            return Err(KernelError::InvalidField {
                field: "allowed_effect",
                reason: "exceeds supporting grant ceiling",
            });
        }
        if !request.proof_ceiling.is_at_most(grant.proof_ceiling) {
            return Err(KernelError::InvalidField {
                field: "proof_ceiling",
                reason: "exceeds supporting grant ceiling",
            });
        }
        if let Some(expires) = grant.expires_at_ms
            && expires <= now_ms
        {
            return Err(KernelError::InvalidField {
                field: "supporting_grant_ids",
                reason: "supporting lineage is expired",
            });
        }
    }
    Ok(())
}

/// Canonical digest bytes for one grant-activation payload. Multi-value
/// fields enter as sorted sets so presentation order cannot fork an
/// operation identity.
#[derive(Serialize)]
struct GrantActivationDigestView<'a> {
    kind: &'static str,
    operation_id: &'a str,
    grant_id: &'a str,
    parent_grant_id: Option<&'a str>,
    authority_root_ref: &'a str,
    snapshot_id: &'a str,
    grant_graph_revision: u64,
    holder_principal: &'a str,
    session_id: &'a str,
    scope_id: &'a str,
    binding: &'a AuthorityBinding,
    allowed_effect: EffectClass,
    proof_ceiling: ProofCeiling,
    issued_at_ms: i64,
    expires_at_ms: Option<i64>,
    receipt_obligations: BTreeSet<&'a str>,
}

/// Canonical digest bytes for one grant-revocation payload.
#[derive(Serialize)]
struct GrantRevocationDigestView<'a> {
    kind: &'static str,
    operation_id: &'a str,
    grant_id: &'a str,
    authority_root_ref: &'a str,
    snapshot_id: &'a str,
    grant_graph_revision: u64,
    binding: &'a AuthorityBinding,
    unknown_outcome_operations: BTreeSet<&'a str>,
    receipt_obligations: BTreeSet<&'a str>,
}

/// Canonical digest bytes for one introduction-activation payload.
#[derive(Serialize)]
struct IntroductionActivationDigestView<'a> {
    kind: &'static str,
    operation_id: &'a str,
    introduction_id: &'a str,
    snapshot_id: &'a str,
    authority_root_ref: &'a str,
    grant_graph_revision: u64,
    supporting_grant_ids: BTreeSet<&'a str>,
    resource_handle: &'a str,
    facet_manifest_ref: &'a str,
    holder_principal: &'a str,
    session_id: &'a str,
    scope_id: &'a str,
    binding: &'a AuthorityBinding,
    allowed_effect: EffectClass,
    proof_ceiling: ProofCeiling,
    issued_at_ms: i64,
    expires_at_ms: Option<i64>,
    receipt_obligations: BTreeSet<&'a str>,
}

/// Canonical digest bytes for one introduction-revocation payload.
#[derive(Serialize)]
struct IntroductionRevocationDigestView<'a> {
    kind: &'static str,
    operation_id: &'a str,
    introduction_id: &'a str,
    authority_root_ref: &'a str,
    snapshot_id: &'a str,
    grant_graph_revision: u64,
    binding: &'a AuthorityBinding,
    unknown_outcome_operations: BTreeSet<&'a str>,
    receipt_obligations: BTreeSet<&'a str>,
}

/// Hashes canonical view bytes into the stable idempotency digest.
fn finalize_digest(view: &impl Serialize) -> Result<String, KernelError> {
    let bytes = canonical_json_bytes(view).map_err(|_| KernelError::InvalidField {
        field: "operation_id",
        reason: "intent digest serialization failed",
    })?;
    Ok(sha256_hex(&bytes))
}

impl GrantActivationIntent {
    fn digest(&self) -> Result<String, KernelError> {
        finalize_digest(&GrantActivationDigestView {
            kind: "grant-activation",
            operation_id: &self.operation_id,
            grant_id: &self.grant_id,
            parent_grant_id: self.parent_grant_id.as_deref(),
            authority_root_ref: &self.authority_root_ref,
            snapshot_id: &self.snapshot_id,
            grant_graph_revision: self.grant_graph_revision,
            holder_principal: &self.holder_principal,
            session_id: &self.session_id,
            scope_id: &self.scope_id,
            binding: &self.binding,
            allowed_effect: self.allowed_effect,
            proof_ceiling: self.proof_ceiling,
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self.expires_at_ms,
            receipt_obligations: self
                .receipt_obligations
                .iter()
                .map(String::as_str)
                .collect(),
        })
    }
}

impl GrantRevocationIntent {
    fn digest(&self) -> Result<String, KernelError> {
        finalize_digest(&GrantRevocationDigestView {
            kind: "grant-revocation",
            operation_id: &self.operation_id,
            grant_id: &self.grant_id,
            authority_root_ref: &self.authority_root_ref,
            snapshot_id: &self.snapshot_id,
            grant_graph_revision: self.grant_graph_revision,
            binding: &self.binding,
            unknown_outcome_operations: self
                .unknown_outcome_operations
                .iter()
                .map(String::as_str)
                .collect(),
            receipt_obligations: self
                .receipt_obligations
                .iter()
                .map(String::as_str)
                .collect(),
        })
    }
}

impl IntroductionActivationIntent {
    fn digest(&self) -> Result<String, KernelError> {
        finalize_digest(&IntroductionActivationDigestView {
            kind: "introduction-activation",
            operation_id: &self.operation_id,
            introduction_id: &self.introduction_id,
            snapshot_id: &self.snapshot_id,
            authority_root_ref: &self.authority_root_ref,
            grant_graph_revision: self.grant_graph_revision,
            supporting_grant_ids: self
                .supporting_grant_ids
                .iter()
                .map(String::as_str)
                .collect(),
            resource_handle: &self.resource_handle,
            facet_manifest_ref: &self.facet_manifest_ref,
            holder_principal: &self.holder_principal,
            session_id: &self.session_id,
            scope_id: &self.scope_id,
            binding: &self.binding,
            allowed_effect: self.allowed_effect,
            proof_ceiling: self.proof_ceiling,
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self.expires_at_ms,
            receipt_obligations: self
                .receipt_obligations
                .iter()
                .map(String::as_str)
                .collect(),
        })
    }
}

impl IntroductionRevocationIntent {
    fn digest(&self) -> Result<String, KernelError> {
        finalize_digest(&IntroductionRevocationDigestView {
            kind: "introduction-revocation",
            operation_id: &self.operation_id,
            introduction_id: &self.introduction_id,
            authority_root_ref: &self.authority_root_ref,
            snapshot_id: &self.snapshot_id,
            grant_graph_revision: self.grant_graph_revision,
            binding: &self.binding,
            unknown_outcome_operations: self
                .unknown_outcome_operations
                .iter()
                .map(String::as_str)
                .collect(),
            receipt_obligations: self
                .receipt_obligations
                .iter()
                .map(String::as_str)
                .collect(),
        })
    }
}
