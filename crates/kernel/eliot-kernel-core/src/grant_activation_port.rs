//! P-07 live grant/introduction activation and revocation port.
//!
//! This module is the one current P-07 owner for live capability-grant and
//! capability-introduction activation and revocation inside
//! `eliot-kernel-core`. Governor (`eliot-authority`) keeps owning semantic
//! admission, lineage evaluation and the pure grant/introduction contracts,
//! while ORS keeps owning durable envelopes and recovery. This port creates
//! no second grant graph or second epoch. The durable root-grant adapter uses
//! injected Governor hydration and the injected ORS boundary; ORS remains
//! opaque storage plus evidence:
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
//! supplies its current [`EpochId`] on every call and the caller
//! supplies the observation time for expiry checks, so this adapter can never
//! fence against a shadow epoch or a stale reading. Only canonical
//! [`AuthorityActivationReceipt`](eliot_runtime_contracts::AuthorityActivationReceipt)
//! and
//! [`AuthorityRevocationReceipt`](eliot_runtime_contracts::AuthorityRevocationReceipt)
//! values leave this port, and each one passes its own `validate()` before it
//! is returned. One authority-root grant follows hydrate, gate recheck, ORS
//! commit, exact ORS read-back, and only then live installation. Restart
//! recovery installs an active root only when the hydrated canonical record,
//! ORS row, and ORS-issued read-back receipt agree exactly.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use eliot_contracts::{EpochId, canonical_json_bytes, sha256_hex};
use eliot_ors::{
    CapabilityGrantActivation, CapabilityGrantProjection, CapabilityGrantRevocation,
    OperationIdentity, OperationalPhase, OperationalRecordInput, OperationalRecoveryStore,
    StateFenceSnapshot,
};
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

/// Complete Governor-owned material needed to activate one authority-root
/// grant. The hydration source must provide every field; the Kernel supplies
/// no semantic default and rejects child/delegated lineage in this slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootGrantHydration {
    /// Complete semantic activation intent from the canonical Governor owner.
    pub intent: GrantActivationIntent,
    /// Opaque ORS input bound to the same root-grant identity and fence.
    pub durable_record: CapabilityGrantActivation,
    /// Caller-supplied observation time for the activation gate.
    pub observed_at_ms: i64,
}

/// Injected boundary from the canonical Governor owner into P-07.
///
/// The boundary resolves the thin G-01 identity to one complete root-grant
/// intent and its already opaque ORS record. It owns semantic decoding and
/// rehydration; the Kernel only checks exact identity, fence, and lifecycle
/// agreement.
pub trait RootGrantHydrationSource: Send + Sync {
    /// Resolves a thin activation request to the complete canonical root.
    fn hydrate_root_grant(
        &self,
        request: &eliot_authority::GrantActivationRequest,
    ) -> Result<RootGrantHydration, KernelError>;

    /// Rehydrates the canonical root that corresponds to one ORS projection.
    fn rehydrate_root_grant(
        &self,
        projection: &CapabilityGrantProjection,
    ) -> Result<RootGrantHydration, KernelError>;
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
pub struct GrantActivationPort {
    ledger: Mutex<PortLedger>,
    durable: Option<DurableRootGrantBoundary>,
}

struct DurableRootGrantBoundary {
    hydration: Arc<dyn RootGrantHydrationSource>,
    store: Arc<dyn OperationalRecoveryStore>,
}

impl fmt::Debug for GrantActivationPort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrantActivationPort")
            .field("ledger", &self.ledger)
            .field("durable", &self.durable.is_some())
            .finish()
    }
}

impl Default for GrantActivationPort {
    fn default() -> Self {
        Self::new()
    }
}

impl GrantActivationPort {
    /// Creates an empty port with no recorded intents, grants or revisions.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ledger: Mutex::new(PortLedger::default()),
            durable: None,
        }
    }

    /// Injects the canonical Governor hydration source and the opaque ORS
    /// boundary for the one authority-root durable slice.
    #[must_use]
    pub fn with_durable_root_grant(
        hydration: Arc<dyn RootGrantHydrationSource>,
        store: Arc<dyn OperationalRecoveryStore>,
    ) -> Self {
        Self {
            ledger: Mutex::new(PortLedger::default()),
            durable: Some(DurableRootGrantBoundary { hydration, store }),
        }
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
    /// [`KernelError::FenceMismatch`] for a stale, future or cross-lineage
    /// epoch or a cross-lineage parent or fence, [`KernelError::Expired`] for
    /// an expired intent, and [`KernelError::InvalidField`] for any other
    /// invalid identity, revision, binding, ceiling or lineage value.
    pub fn activate_grant(
        &self,
        request: &GrantActivationIntent,
        active_epoch: EpochId,
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
        validate_grant_activation(request, &ledger, &active_epoch, now_ms)?;
        let operation_id = request.operation_id.clone();
        let receipt = AuthorityActivationReceipt {
            activation_id: format!("activation-{operation_id}"),
            snapshot_id: request.snapshot_id.clone(),
            authority_epoch: active_epoch.clone(),
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
    /// [`KernelError::FenceMismatch`] for a stale, future or cross-lineage
    /// epoch or a cross-lineage root, and [`KernelError::InvalidField`] for
    /// any other invalid identity, revision or binding value, including an
    /// unknown grant identity, which is recorded as reconciling.
    pub fn revoke_grant(
        &self,
        request: &GrantRevocationIntent,
        active_epoch: EpochId,
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
        check_binding(&request.binding, &active_epoch)?;
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
            authority_epoch: active_epoch.clone(),
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
        active_epoch: EpochId,
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
        validate_introduction_activation(request, &ledger, &active_epoch, now_ms)?;
        let mut supporting = BTreeSet::new();
        for id in &request.supporting_grant_ids {
            supporting.insert(id.clone());
        }
        let operation_id = request.operation_id.clone();
        let receipt = AuthorityActivationReceipt {
            activation_id: format!("activation-{operation_id}"),
            snapshot_id: request.snapshot_id.clone(),
            authority_epoch: active_epoch.clone(),
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
        active_epoch: EpochId,
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
        check_binding(&request.binding, &active_epoch)?;
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
            authority_epoch: active_epoch.clone(),
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
        ledger.revoked_grants.contains(grant_id)
            || ledger
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

    /// Recovers one durable active authority-root grant after a restart.
    ///
    /// Recovery reads only an ORS `ACTIVE` projection, asks the injected
    /// Governor owner to rehydrate the complete canonical record, and
    /// installs live state only after the canonical record, opaque ORS input,
    /// and ORS receipt agree. Any mismatch stays fail-closed.
    pub fn recover_root_grant(
        &self,
        grant_id: &str,
        active_epoch: &EpochId,
        now_ms: i64,
    ) -> Result<AuthorityActivationReceipt, KernelError> {
        let boundary = self.durable.as_ref().ok_or_else(|| {
            KernelError::RecoveryUnavailable("root-grant boundary is not bound".to_owned())
        })?;
        validate_id(grant_id, "grant_id")?;
        let subject_id = OperationIdentity::new(grant_id).map_err(KernelError::RecoveryState)?;
        let projection = boundary
            .store
            .load_capability_grant(&subject_id)
            .map_err(KernelError::RecoveryState)?
            .ok_or_else(|| {
                KernelError::RecoveryUnavailable(
                    "active root-grant projection is absent".to_owned(),
                )
            })?;
        if projection.phase() != OperationalPhase::Active {
            return Err(KernelError::RecoveryUnavailable(
                "root-grant projection is not active".to_owned(),
            ));
        }
        let hydration = boundary.hydration.rehydrate_root_grant(&projection)?;
        validate_rehydrated_root_grant(&hydration, &projection, active_epoch)?;
        if hydration.intent.grant_id != grant_id {
            return Err(KernelError::RecoveryUnavailable(
                "rehydrated root-grant identity disagrees with ORS".to_owned(),
            ));
        }

        let mut ledger = self.lock_ledger();
        let digest = hydration.intent.digest()?;
        match ledger.resolve(&hydration.intent.operation_id, &digest) {
            IntentResolve::Conflict => return Err(KernelError::IdempotencyConflict),
            IntentResolve::Replay(disposition) => {
                return disposition.into_activation_receipt();
            }
            IntentResolve::New => {}
        }
        validate_grant_activation(&hydration.intent, &ledger, active_epoch, now_ms)?;
        let receipt = runtime_activation_receipt(&hydration.intent, active_epoch)?;
        install_root_activation(&mut ledger, &hydration.intent, &receipt, digest);
        Ok(receipt)
    }

    fn activate_root_grant_durable(
        &self,
        request: &eliot_authority::GrantActivationRequest,
        active_epoch: &EpochId,
        boundary: &DurableRootGrantBoundary,
    ) -> Result<AuthorityActivationReceipt, eliot_authority::P07PortError> {
        check_binding(&request.binding, active_epoch).map_err(|error| map_thin_error(&error))?;
        let operation_id = thin_operation_id(
            "activate-grant",
            request.grant_id.as_str(),
            request.snapshot_id.as_str(),
            active_epoch,
        );
        let hydration = boundary
            .hydration
            .hydrate_root_grant(request)
            .map_err(|error| map_thin_error(&error))?;
        validate_root_hydration(&hydration, request, &operation_id, active_epoch)
            .map_err(|error| map_thin_error(&error))?;

        let mut ledger = self.lock_ledger();
        let digest = hydration
            .intent
            .digest()
            .map_err(|error| map_thin_error(&error))?;
        match ledger.resolve(&operation_id, &digest) {
            IntentResolve::Conflict => return Err(eliot_authority::P07PortError::InvalidBinding),
            IntentResolve::Replay(disposition) => {
                return disposition
                    .into_activation_receipt()
                    .map_err(|error| map_thin_error(&error));
            }
            IntentResolve::New => {}
        }
        validate_grant_activation(
            &hydration.intent,
            &ledger,
            active_epoch,
            hydration.observed_at_ms,
        )
        .map_err(|error| map_thin_error(&error))?;
        let durable_receipt = boundary
            .store
            .activate_capability_grant(hydration.durable_record.clone())
            .map_err(|error| map_ors_error(&error))?;
        let projection = boundary
            .store
            .load_capability_grant(
                &OperationIdentity::new(request.grant_id.as_str())
                    .map_err(|_| eliot_authority::P07PortError::InvalidBinding)?,
            )
            .map_err(|error| map_ors_error(&error))?
            .ok_or(eliot_authority::P07PortError::Unavailable)?;
        if projection.phase() != OperationalPhase::Active
            || projection.record() != hydration.durable_record.record()
            || projection.receipt() != durable_receipt.receipt()
        {
            return Err(eliot_authority::P07PortError::Unavailable);
        }
        let receipt = runtime_activation_receipt(&hydration.intent, active_epoch)
            .map_err(|error| map_thin_error(&error))?;
        install_root_activation(&mut ledger, &hydration.intent, &receipt, digest);
        Ok(receipt)
    }

    fn revoke_root_grant_durable(
        &self,
        request: &eliot_authority::GrantRevocationRequest,
        active_epoch: &EpochId,
        boundary: &DurableRootGrantBoundary,
    ) -> Result<AuthorityRevocationReceipt, eliot_authority::P07PortError> {
        check_binding(&request.binding, active_epoch).map_err(|error| map_thin_error(&error))?;
        let operation_id = thin_operation_id(
            "revoke-grant",
            request.grant_id.as_str(),
            request.snapshot_id.as_str(),
            active_epoch,
        );
        let subject_id = OperationIdentity::new(request.grant_id.as_str())
            .map_err(|_| eliot_authority::P07PortError::InvalidBinding)?;
        let prior = boundary
            .store
            .load_capability_grant(&subject_id)
            .map_err(|error| map_ors_error(&error))?
            .ok_or(eliot_authority::P07PortError::Unavailable)?;
        check_opaque_record_binding(prior.record(), &request.binding, active_epoch)
            .map_err(|error| map_thin_error(&error))?;

        let (hydration, revocation_record) =
            prepare_root_revocation(&prior, operation_id.as_str(), active_epoch, boundary)?;

        let mut ledger = self.lock_ledger();
        let digest = root_revocation_digest(hydration.as_ref(), request, operation_id.as_str())?;
        if let Some(digest) = digest.as_ref() {
            match ledger.resolve(&operation_id, digest) {
                IntentResolve::Conflict => {
                    return Err(eliot_authority::P07PortError::InvalidBinding);
                }
                IntentResolve::Replay(disposition) => {
                    return disposition
                        .into_revocation_receipt()
                        .map_err(|error| map_thin_error(&error));
                }
                IntentResolve::New => {}
            }
        }
        if let Some(hydration) = hydration.as_ref() {
            validate_root_intent_for_revocation(&hydration.intent, &ledger, active_epoch)
                .map_err(|error| map_thin_error(&error))?;
        }
        let durable_receipt = boundary
            .store
            .revoke_capability_grant(revocation_record.clone())
            .map_err(|error| map_ors_error(&error))?;
        let projection = boundary
            .store
            .load_capability_grant(&subject_id)
            .map_err(|error| map_ors_error(&error))?
            .ok_or(eliot_authority::P07PortError::Unavailable)?;
        if projection.phase() != OperationalPhase::Fenced
            || projection.record() != revocation_record.record()
            || projection.receipt() != durable_receipt.receipt()
        {
            return Err(eliot_authority::P07PortError::Unavailable);
        }
        let receipt = runtime_revocation_receipt(request, active_epoch)
            .map_err(|error| map_thin_error(&error))?;
        if let Some(hydration) = hydration {
            if let Some(grant) = ledger.grants.get_mut(request.grant_id.as_str()) {
                grant.status = LiveStatus::Revoked;
            } else {
                ledger
                    .revoked_grants
                    .insert(request.grant_id.as_str().to_owned());
            }
            let Some(digest) = digest else {
                return Err(eliot_authority::P07PortError::Unavailable);
            };
            ledger.intents.insert(
                operation_id.clone(),
                PortIntentRecord {
                    operation_id,
                    digest,
                    kind: IntentKind::GrantRevocation,
                    disposition: IntentDisposition::Committed(CommittedReceipt::Revocation(
                        receipt.clone(),
                    )),
                    fenced: vec![hydration.intent.grant_id],
                },
            );
        } else {
            ledger
                .revoked_grants
                .insert(request.grant_id.as_str().to_owned());
        }
        Ok(receipt)
    }

    fn lock_ledger(&self) -> MutexGuard<'_, PortLedger> {
        self.ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn prepare_root_revocation(
    prior: &CapabilityGrantProjection,
    operation_id: &str,
    active_epoch: &EpochId,
    boundary: &DurableRootGrantBoundary,
) -> Result<(Option<RootGrantHydration>, CapabilityGrantRevocation), eliot_authority::P07PortError>
{
    let hydration = if prior.phase() == OperationalPhase::Active {
        let hydration = boundary
            .hydration
            .rehydrate_root_grant(prior)
            .map_err(|error| map_thin_error(&error))?;
        validate_rehydrated_root_grant(&hydration, prior, active_epoch)
            .map_err(|error| map_thin_error(&error))?;
        Some(hydration)
    } else {
        if prior.record().record_id.as_str() != operation_id {
            return Err(eliot_authority::P07PortError::NotAdmitted);
        }
        None
    };
    let revocation_record = if prior.phase() == OperationalPhase::Active {
        let mut input = prior.record().clone();
        input.record_id = OperationIdentity::new(operation_id)
            .map_err(|_| eliot_authority::P07PortError::InvalidBinding)?;
        CapabilityGrantRevocation::new(input)
            .map_err(|_| eliot_authority::P07PortError::InvalidBinding)?
    } else {
        CapabilityGrantRevocation::new(prior.record().clone())
            .map_err(|_| eliot_authority::P07PortError::InvalidBinding)?
    };
    Ok((hydration, revocation_record))
}

fn root_revocation_digest(
    hydration: Option<&RootGrantHydration>,
    request: &eliot_authority::GrantRevocationRequest,
    operation_id: &str,
) -> Result<Option<String>, eliot_authority::P07PortError> {
    let Some(hydration) = hydration else {
        return Ok(None);
    };
    GrantRevocationIntent {
        operation_id: operation_id.to_owned(),
        grant_id: request.grant_id.as_str().to_owned(),
        authority_root_ref: hydration.intent.authority_root_ref.clone(),
        snapshot_id: request.snapshot_id.as_str().to_owned(),
        grant_graph_revision: hydration.intent.grant_graph_revision,
        binding: request.binding.clone(),
        unknown_outcome_operations: Vec::new(),
        receipt_obligations: Vec::new(),
    }
    .digest()
    .map(Some)
    .map_err(|error| map_thin_error(&error))
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
    revoked_grants: BTreeSet<String>,
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
/// The binding epoch must be the exact lineage-plus-sequence tuple carried by
/// both the binding fence and the active epoch. Stale, future and
/// cross-lineage epochs all fail closed as [`KernelError::FenceMismatch`]
/// without any scalar coercion, mirroring exact route-fence enforcement.
fn check_binding(binding: &AuthorityBinding, active_epoch: &EpochId) -> Result<(), KernelError> {
    validate_text(&binding.authority_owner, "binding.authority_owner")?;
    binding.state_fence.validate()?;
    if !binding
        .authority_epoch
        .is_same_authority(&binding.state_fence.authority_epoch)
    {
        return Err(KernelError::FenceMismatch);
    }
    check_canonical_epoch_binding(&binding.authority_epoch, active_epoch)?;
    Ok(())
}

/// Validates one canonical epoch binding without any scalar coercion.
///
/// The fence epoch authorizes only on exact lineage-plus-sequence equality
/// with the active epoch. Cross-lineage same-sequence inputs and any other
/// mismatch fail closed as [`KernelError::FenceMismatch`]; no numeric epoch is
/// extracted or compared across lineages.
///
/// # Errors
///
/// Returns [`KernelError::FenceMismatch`] when the canonical tuple does not
/// exactly match.
pub fn check_canonical_epoch_binding(
    fence_epoch: &EpochId,
    active_epoch: &EpochId,
) -> Result<(), KernelError> {
    if fence_epoch.is_same_authority(active_epoch) {
        Ok(())
    } else {
        Err(KernelError::FenceMismatch)
    }
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
    active_epoch: &EpochId,
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
    if ledger.grants.contains_key(&request.grant_id)
        || ledger.revoked_grants.contains(&request.grant_id)
    {
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
    active_epoch: &EpochId,
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

// ---------------------------------------------------------------------------
// Slice A retry (`#1110`): first real non-test `P07AuthorityPort` adapter.
//
// `eliot-authority` stays pure: it declares the thin port requests (exact
// grant/introduction/snapshot identities plus the caller-presented binding)
// and the single-variant `P07PortError`, while this module is the one P-07
// effecting owner. The adapter is thin-to-rich:
//
// - Revocation hydrates the Wave A rich intent from caller material plus the
//   in-memory ledger lineage recorded by an earlier rich activation (the
//   authority root and the greatest observed grant-graph revision for that
//   root). No GrantGraph is queried and no durable CAS is invented: without a
//   ledger entry there is no lineage to fence, so the call fail-closes.
// - Activation hydrates one authority-root grant through the injected
//   Governor boundary. The boundary supplies the complete semantic intent and
//   opaque ORS record; this port validates both, commits ORS, requires exact
//   read-back, and only then installs live state. Restart recovery rehydrates
//   the canonical root and requires agreement with the ORS projection and
//   receipt. Durable revoke follows the same read-back and exact-replay rules.
//   Child/delegated grants and introductions remain outside this durable slice.
// - The active epoch is always the caller-presented binding epoch: this port
//   holds no epoch and queries no second epoch owner. Revocation is
//   authority-removing, so fencing at the presented epoch is fail-closed;
//   granting authority at a presented epoch is not, so activation stays
//   unavailable (A13.2: a minimally live Kernel withholds unsupported
//   authority).
//
// Every `P07PortError::Unavailable` site below names the missing hydration or
// durability owner. Caller-material rejections surface as `InvalidBinding`
// and Kernel fence/epoch/expiry refusals as `NotAdmitted`, matching the
// `P07PortError` contract and the `eliotd` transport adapter; only genuinely
// missing owners stay `Unavailable`. Receipts on the valid path are computed by the Wave A rich calls from
// validated inputs plus ledger plus revision, and each passes `validate()`
// before it is returned: no canned receipt value exists here. Durable
// root-grant persistence, restart rehydration, and ORS read-back are covered
// here. Child/delegated grants, introductions, and descendant closure beyond
// the recorded in-memory lineage remain explicit residuals for follow-up
// waves; nothing here claims them.
// ---------------------------------------------------------------------------

/// Derives the thin-port operation identity for one target/snapshot/epoch.
///
/// Thin requests carry no operation identity, so Slice A binds `(operation
/// kind, target identity, snapshot identity, binding epoch)`. The epoch enters
/// as the exact canonical `(lineage_id, sequence)` tuple: equal sequences from
/// different lineages derive distinct identities. Exact replay of
/// one thin request re-derives the same identity and the rich canonical
/// digest then matches, returning the same receipt; any other caller-material
/// change under the derived identity fails as
/// [`KernelError::IdempotencyConflict`] inside the rich call. An epoch
/// advance (or a new snapshot) derives a fresh identity, which re-confirms
/// the fence with a fresh receipt.
fn thin_operation_id(kind: &str, target_id: &str, snapshot_id: &str, epoch: &EpochId) -> String {
    format!(
        "p07-{kind}-{target_id}-{snapshot_id}-{}-{}",
        epoch.lineage_id.as_str(),
        epoch.sequence.get()
    )
}

fn runtime_activation_receipt(
    intent: &GrantActivationIntent,
    active_epoch: &EpochId,
) -> Result<AuthorityActivationReceipt, KernelError> {
    let receipt = AuthorityActivationReceipt {
        activation_id: format!("activation-{}", intent.operation_id),
        snapshot_id: intent.snapshot_id.clone(),
        authority_epoch: active_epoch.clone(),
        state: AuthorityState::Active,
    };
    receipt.validate()?;
    Ok(receipt)
}

fn runtime_revocation_receipt(
    request: &eliot_authority::GrantRevocationRequest,
    active_epoch: &EpochId,
) -> Result<AuthorityRevocationReceipt, KernelError> {
    let operation_id = thin_operation_id(
        "revoke-grant",
        request.grant_id.as_str(),
        request.snapshot_id.as_str(),
        active_epoch,
    );
    let receipt = AuthorityRevocationReceipt {
        revocation_id: format!("revocation-{operation_id}"),
        snapshot_id: request.snapshot_id.as_str().to_owned(),
        authority_epoch: active_epoch.clone(),
        state: AuthorityState::Revoked,
    };
    receipt.validate()?;
    Ok(receipt)
}

fn install_root_activation(
    ledger: &mut PortLedger,
    intent: &GrantActivationIntent,
    receipt: &AuthorityActivationReceipt,
    digest: String,
) {
    ledger.grants.insert(
        intent.grant_id.clone(),
        LiveGrantRecord {
            parent_grant_id: None,
            authority_root_ref: intent.authority_root_ref.clone(),
            binding: intent.binding.clone(),
            allowed_effect: intent.allowed_effect,
            proof_ceiling: intent.proof_ceiling,
            expires_at_ms: intent.expires_at_ms,
            status: LiveStatus::Active,
        },
    );
    ledger.note_revision(&intent.authority_root_ref, intent.grant_graph_revision);
    ledger.intents.insert(
        intent.operation_id.clone(),
        PortIntentRecord {
            operation_id: intent.operation_id.clone(),
            digest,
            kind: IntentKind::GrantActivation,
            disposition: IntentDisposition::Committed(CommittedReceipt::Activation(
                receipt.clone(),
            )),
            fenced: Vec::new(),
        },
    );
}

fn validate_root_hydration(
    hydration: &RootGrantHydration,
    request: &eliot_authority::GrantActivationRequest,
    operation_id: &str,
    active_epoch: &EpochId,
) -> Result<(), KernelError> {
    if hydration.intent.operation_id != operation_id
        || hydration.intent.grant_id != request.grant_id.as_str()
        || hydration.intent.snapshot_id != request.snapshot_id.as_str()
        || hydration.intent.binding != request.binding
    {
        return Err(KernelError::RecoveryUnavailable(
            "hydrated root-grant identity disagrees with the thin request".to_owned(),
        ));
    }
    if hydration.intent.parent_grant_id.is_some() {
        return Err(KernelError::InvalidField {
            field: "parent_grant_id",
            reason: "the first durable slice accepts authority roots only",
        });
    }
    if hydration.durable_record.record().record_id.as_str() != operation_id
        || hydration.durable_record.record().subject_id.as_str() != request.grant_id.as_str()
    {
        return Err(KernelError::RecoveryUnavailable(
            "hydrated opaque root-grant record has a different identity".to_owned(),
        ));
    }
    check_opaque_record_binding(
        hydration.durable_record.record(),
        &request.binding,
        active_epoch,
    )
}

fn validate_rehydrated_root_grant(
    hydration: &RootGrantHydration,
    projection: &CapabilityGrantProjection,
    active_epoch: &EpochId,
) -> Result<(), KernelError> {
    if hydration.intent.parent_grant_id.is_some()
        || hydration.intent.operation_id != projection.record().record_id.as_str()
        || hydration.intent.grant_id != projection.record().subject_id.as_str()
        || hydration.durable_record.record() != projection.record()
        || projection.receipt().record_id() != &projection.record().record_id
        || projection.receipt().subject_id() != &projection.record().subject_id
    {
        return Err(KernelError::RecoveryUnavailable(
            "root-grant recovery triple agreement failed".to_owned(),
        ));
    }
    check_opaque_record_binding(projection.record(), &hydration.intent.binding, active_epoch)
}

fn check_opaque_record_binding(
    input: &OperationalRecordInput,
    binding: &AuthorityBinding,
    active_epoch: &EpochId,
) -> Result<(), KernelError> {
    if input.authority_epoch.current.lineage_id.as_str() != active_epoch.lineage_id.as_str()
        || input.authority_epoch.current.epoch != active_epoch.sequence.get()
    {
        return Err(KernelError::FenceMismatch);
    }
    input.state_fence.validate_against_epoch(active_epoch)?;
    let expected_fence =
        StateFenceSnapshot::capture(&binding.state_fence, active_epoch.sequence.get())?;
    if input.state_fence != expected_fence {
        return Err(KernelError::FenceMismatch);
    }
    Ok(())
}

fn validate_root_intent_for_revocation(
    intent: &GrantActivationIntent,
    ledger: &PortLedger,
    active_epoch: &EpochId,
) -> Result<(), KernelError> {
    validate_id(&intent.grant_id, "grant_id")?;
    validate_id(&intent.operation_id, "operation_id")?;
    validate_id(&intent.authority_root_ref, "authority_root_ref")?;
    validate_id(&intent.snapshot_id, "snapshot_id")?;
    validate_id(&intent.holder_principal, "holder_principal")?;
    validate_id(&intent.session_id, "session_id")?;
    validate_id(&intent.scope_id, "scope_id")?;
    for obligation in &intent.receipt_obligations {
        validate_id(obligation, "receipt_obligation")?;
    }
    if intent.parent_grant_id.is_some() {
        return Err(KernelError::InvalidField {
            field: "parent_grant_id",
            reason: "the first durable slice accepts authority roots only",
        });
    }
    check_revision(
        ledger,
        &intent.authority_root_ref,
        intent.grant_graph_revision,
    )?;
    check_binding(&intent.binding, active_epoch)?;
    check_ceiling(intent.allowed_effect, intent.proof_ceiling, &intent.binding)
}

fn map_ors_error(error: &eliot_ors::OrsError) -> eliot_authority::P07PortError {
    match error {
        eliot_ors::OrsError::InvalidTransition
        | eliot_ors::OrsError::InvalidEpochLineage
        | eliot_ors::OrsError::FenceMismatch => eliot_authority::P07PortError::NotAdmitted,
        eliot_ors::OrsError::DuplicateConflict => eliot_authority::P07PortError::InvalidBinding,
        _ => eliot_authority::P07PortError::Unavailable,
    }
}

/// Maps a rich-call rejection to the thin-port typed error.
///
/// `NotAdmitted` is a Kernel-side admission refusal (fenced/epoch-gated
/// authority, expiry, or reserve exhaustion — never a receipt).
/// `InvalidBinding` is caller-side material that is internally inconsistent
/// (owner/fence/epoch/ceiling/lineage/identity mismatch). `Unavailable` is
/// reserved for a genuinely missing hydration or durability owner (ORS,
/// recovery view, dependency). The mapping is fail-closed: no branch grants
/// authority and no secret or provider detail crosses the error surface.
fn map_thin_error(error: &KernelError) -> eliot_authority::P07PortError {
    use eliot_authority::P07PortError;
    match error {
        KernelError::FenceMismatch
        | KernelError::StaleEpoch { .. }
        | KernelError::Expired { .. }
        | KernelError::ControlReserveExhausted
        | KernelError::NormalCapacityExhausted { .. }
        | KernelError::ProtectedReserveExhausted { .. }
        | KernelError::EmergencySlotUnavailable { .. }
        | KernelError::ControlGuaranteeLost { .. } => P07PortError::NotAdmitted,
        KernelError::DependencyUnavailable(_)
        | KernelError::RecoveryUnavailable(_)
        | KernelError::RecoveryState(_) => P07PortError::Unavailable,
        _ => P07PortError::InvalidBinding,
    }
}

impl eliot_authority::P07AuthorityPort for GrantActivationPort {
    fn activate_grant(
        &self,
        request: &eliot_authority::GrantActivationRequest,
    ) -> Result<AuthorityActivationReceipt, eliot_authority::P07PortError> {
        use eliot_authority::P07PortError;
        let active_epoch = request.binding.authority_epoch.clone();
        if let Err(error) = check_binding(&request.binding, &active_epoch) {
            // Caller-material rejection: the presented binding is internally
            // inconsistent or stale against the presented epoch. No owner
            // repairs caller material; the caller re-presents through a
            // current Governor snapshot.
            return Err(map_thin_error(&error));
        }
        if let Some(boundary) = self.durable.as_ref() {
            return self.activate_root_grant_durable(request, &active_epoch, boundary);
        }
        {
            let ledger = self.lock_ledger();
            if ledger.grants.contains_key(request.grant_id.as_str()) {
                // Caller lifecycle violation: restore never reactivates a
                // path (I14.20), so a recorded grant identity cannot
                // activate again.
                return Err(P07PortError::InvalidBinding);
            }
        }
        // Missing owners: durable GrantGraph CAS plus the thin-request
        // hydration source for parent lineage, authority root, graph revision,
        // holder principal/session/scope, issuance/expiry times and receipt
        // obligations. A thin activation request carries none of them, and
        // I6.15 forbids this port from creating lineage, so Slice A
        // fail-closes instead of fabricating a holder, root or revision.
        // Durability/restart rehydration is an explicit follow-up residual.
        Err(P07PortError::Unavailable)
    }

    fn revoke_grant(
        &self,
        request: &eliot_authority::GrantRevocationRequest,
    ) -> Result<AuthorityRevocationReceipt, eliot_authority::P07PortError> {
        use eliot_authority::P07PortError;
        let active_epoch = request.binding.authority_epoch.clone();
        let rich = {
            if let Some(boundary) = self.durable.as_ref() {
                return self.revoke_root_grant_durable(request, &active_epoch, boundary);
            }
            let ledger = self.lock_ledger();
            let Some(authority_root_ref) = ledger
                .grants
                .get(request.grant_id.as_str())
                .map(|record| record.authority_root_ref.clone())
            else {
                // Missing owners: ledger lineage plus the durable GrantGraph
                // hydration source. The thin request carries no parent, root
                // or revision to hydrate a rich intent, so fencing an unknown
                // grant would fabricate authority state (I6.10/I6.15). No
                // reconciling record is written either: without root/revision
                // there is no well-formed intent to record. Durable
                // unknown-target tracking lands with the hydration-owner wave.
                return Err(P07PortError::Unavailable);
            };
            let Some(grant_graph_revision) = ledger.max_revision.get(&authority_root_ref).copied()
            else {
                // Missing owner: ledger-revision repair. A recorded grant
                // always notes its revision on activation, so this branch is
                // unreachable without a second writer breaking the ledger
                // invariant; Slice A fail-closes rather than inventing a
                // revision.
                return Err(P07PortError::Unavailable);
            };
            GrantRevocationIntent {
                operation_id: thin_operation_id(
                    "revoke-grant",
                    request.grant_id.as_str(),
                    request.snapshot_id.as_str(),
                    &active_epoch,
                ),
                grant_id: request.grant_id.as_str().to_owned(),
                authority_root_ref,
                snapshot_id: request.snapshot_id.as_str().to_owned(),
                grant_graph_revision,
                binding: request.binding.clone(),
                // The thin request expresses no unknown effects and declares
                // no receipt obligations: both are faithful absences, not
                // defaults. Callers that must record either use the rich
                // intent (or the later durable wave).
                unknown_outcome_operations: Vec::new(),
                receipt_obligations: Vec::new(),
            }
        };
        // The authority decision, descendant-closure fencing and receipt
        // computation happen inside the rich call under the port lock, from
        // validated inputs plus ledger plus revision. A racing fence between
        // the hydration read above and this call can only fail closed, never
        // grant, because validation re-runs under the mutation lock.
        self.revoke_grant(&rich, active_epoch).map_err(|error| {
            // Typed refusal: fence/epoch/expiry is a Kernel admission
            // refusal, inconsistent caller material is a binding failure, and
            // only a missing durable owner stays unavailable. The caller
            // re-presents through a current Governor snapshot.
            map_thin_error(&error)
        })
    }

    fn activate_introduction(
        &self,
        request: &eliot_authority::IntroductionActivationRequest,
    ) -> Result<AuthorityActivationReceipt, eliot_authority::P07PortError> {
        use eliot_authority::P07PortError;
        let active_epoch = request.binding.authority_epoch.clone();
        if let Err(error) = check_binding(&request.binding, &active_epoch) {
            // Caller-material rejection: the presented binding is internally
            // inconsistent or stale against the presented epoch. No owner
            // repairs caller material; the caller re-presents through a
            // current Governor snapshot.
            return Err(map_thin_error(&error));
        }
        {
            let ledger = self.lock_ledger();
            if ledger
                .introductions
                .contains_key(request.introduction_id.as_str())
            {
                // Caller lifecycle violation: a recorded introduction
                // identity cannot activate again.
                return Err(P07PortError::InvalidBinding);
            }
        }
        // Missing owners: durable GrantGraph CAS plus the thin-request
        // hydration source for supporting grants, resource handle, facet
        // manifest, holder principal/session/scope, graph revision,
        // issuance/expiry times and receipt obligations. A thin introduction
        // request carries none of them, and I6.15 forbids this port from
        // creating lineage, so Slice A fail-closes instead of fabricating a
        // supporting path, facet or holder. Durability/restart rehydration is
        // an explicit follow-up residual.
        Err(P07PortError::Unavailable)
    }

    fn revoke_introduction(
        &self,
        request: &eliot_authority::IntroductionRevocationRequest,
    ) -> Result<AuthorityRevocationReceipt, eliot_authority::P07PortError> {
        use eliot_authority::P07PortError;
        let active_epoch = request.binding.authority_epoch.clone();
        let rich = {
            let ledger = self.lock_ledger();
            let Some(authority_root_ref) = ledger
                .introductions
                .get(request.introduction_id.as_str())
                .map(|record| record.authority_root_ref.clone())
            else {
                // Missing owners: ledger lineage plus the durable GrantGraph
                // hydration source. The thin request carries no supporting
                // grants, root or revision to hydrate a rich intent, so
                // fencing an unknown introduction would fabricate authority
                // state (I6.10/I6.15). No reconciling record is written
                // either: without root/revision there is no well-formed
                // intent to record. Durable unknown-target tracking lands with
                // the hydration-owner wave.
                return Err(P07PortError::Unavailable);
            };
            let Some(grant_graph_revision) = ledger.max_revision.get(&authority_root_ref).copied()
            else {
                // Missing owner: ledger-revision repair. A recorded
                // introduction always notes its revision on activation, so
                // this branch is unreachable without a second writer breaking
                // the ledger invariant; Slice A fail-closes rather than
                // inventing a revision.
                return Err(P07PortError::Unavailable);
            };
            IntroductionRevocationIntent {
                operation_id: thin_operation_id(
                    "revoke-introduction",
                    request.introduction_id.as_str(),
                    request.snapshot_id.as_str(),
                    &active_epoch,
                ),
                introduction_id: request.introduction_id.as_str().to_owned(),
                authority_root_ref,
                snapshot_id: request.snapshot_id.as_str().to_owned(),
                grant_graph_revision,
                binding: request.binding.clone(),
                // The thin request expresses no unknown effects and declares
                // no receipt obligations: both are faithful absences, not
                // defaults. Callers that must record either use the rich
                // intent (or the later durable wave).
                unknown_outcome_operations: Vec::new(),
                receipt_obligations: Vec::new(),
            }
        };
        // The authority decision, fencing and receipt computation happen
        // inside the rich call under the port lock, from validated inputs plus
        // ledger plus revision. A racing fence between the hydration read
        // above and this call can only fail closed, never grant, because
        // validation re-runs under the mutation lock.
        self.revoke_introduction(&rich, active_epoch)
            .map_err(|error| {
                // Typed refusal: fence/epoch/expiry is a Kernel admission
                // refusal, inconsistent caller material is a binding failure, and
                // only a missing durable owner stays unavailable. The caller
                // re-presents through a current Governor snapshot.
                map_thin_error(&error)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::EpochLineageId;
    use std::num::NonZeroU64;

    fn canonical_epoch(lineage: &str, sequence: u64) -> Result<EpochId, KernelError> {
        let lineage_id = EpochLineageId::new(lineage).map_err(|_| KernelError::InvalidField {
            field: "lineage_id",
            reason: "must be a canonical UUID lineage",
        })?;
        let sequence = NonZeroU64::new(sequence).ok_or(KernelError::InvalidField {
            field: "sequence",
            reason: "must be greater than zero",
        })?;
        EpochId::new(lineage_id, sequence).map_err(|_| KernelError::InvalidField {
            field: "epoch_id",
            reason: "invalid canonical epoch",
        })
    }

    #[test]
    fn canonical_binding_rejects_cross_lineage_same_sequence() -> Result<(), KernelError> {
        let active = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 7)?;
        let same = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 7)?;
        let cross_lineage_same_sequence =
            canonical_epoch("6ba7b810-9dad-11d1-80b4-00c04fd430c8", 7)?;
        assert!(check_canonical_epoch_binding(&same, &active).is_ok());
        assert!(matches!(
            check_canonical_epoch_binding(&cross_lineage_same_sequence, &active),
            Err(KernelError::FenceMismatch)
        ));
        Ok(())
    }

    #[test]
    fn thin_error_mapping_keeps_typed_refusal() {
        use eliot_authority::P07PortError;
        assert!(matches!(
            map_thin_error(&KernelError::FenceMismatch),
            P07PortError::NotAdmitted
        ));
        assert!(matches!(
            map_thin_error(&KernelError::Expired { expires_at_ms: 1 }),
            P07PortError::NotAdmitted
        ));
        assert!(matches!(
            map_thin_error(&KernelError::InvalidField {
                field: "binding.authority_owner",
                reason: "must be non-blank",
            }),
            P07PortError::InvalidBinding
        ));
        assert!(matches!(
            map_thin_error(&KernelError::IdempotencyConflict),
            P07PortError::InvalidBinding
        ));
        assert!(matches!(
            map_thin_error(&KernelError::DependencyUnavailable("ors".to_owned())),
            P07PortError::Unavailable
        ));
        assert!(matches!(
            map_thin_error(&KernelError::RecoveryUnavailable("view".to_owned())),
            P07PortError::Unavailable
        ));
    }

    #[test]
    fn thin_port_types_caller_and_missing_owner_failures() -> Result<(), KernelError> {
        use eliot_authority::{
            GrantActivationRequest, GrantRevocationRequest, P07AuthorityPort, P07PortError,
        };
        use eliot_contracts::{ContractId, ResourceGeneration};
        use eliot_receipts::{EffectClass, ProofCeiling};

        fn grant_id(value: &str) -> Result<eliot_authority::GrantId, KernelError> {
            eliot_authority::GrantId::new(value).map_err(|_| KernelError::InvalidField {
                field: "grant_id",
                reason: "test grant identity must validate",
            })
        }
        fn snapshot_id(value: &str) -> Result<eliot_authority::SnapshotId, KernelError> {
            eliot_authority::SnapshotId::new(value).map_err(|_| KernelError::InvalidField {
                field: "snapshot_id",
                reason: "test snapshot identity must validate",
            })
        }

        let epoch = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 7)?;
        let fence = eliot_contracts::StateFence::new(epoch.clone(), ResourceGeneration::new(1)?);
        let binding = AuthorityBinding {
            authority_id: ContractId::new("authority:test")?,
            authority_owner: "test-owner".to_owned(),
            authority_epoch: epoch.clone(),
            state_fence: fence,
            allowed_effect: EffectClass::ExternalEffect,
            proof_ceiling: ProofCeiling::ObservedExternalEffect,
        };
        let port = GrantActivationPort::new();

        // Split binding epoch: fenced against the presented fence epoch, so
        // the Kernel refuses admission rather than reporting unavailable.
        let mut split = binding.clone();
        split.authority_epoch = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 8)?;
        let split_request = GrantActivationRequest {
            grant_id: grant_id("grant-split")?,
            snapshot_id: snapshot_id("snap-1")?,
            binding: split,
        };
        assert!(matches!(
            P07AuthorityPort::activate_grant(&port, &split_request),
            Err(P07PortError::NotAdmitted)
        ));

        // Blank owner: caller-material failure, never Unavailable.
        let mut blank = binding.clone();
        blank.authority_owner = "  ".to_owned();
        let blank_request = GrantActivationRequest {
            grant_id: grant_id("grant-blank")?,
            snapshot_id: snapshot_id("snap-1")?,
            binding: blank,
        };
        assert!(matches!(
            P07AuthorityPort::activate_grant(&port, &blank_request),
            Err(P07PortError::InvalidBinding)
        ));

        // Valid binding but no hydration owner: activation stays Unavailable,
        // unknown revocation stays Unavailable (no lineage is fabricated).
        let activation = GrantActivationRequest {
            grant_id: grant_id("grant-new")?,
            snapshot_id: snapshot_id("snap-1")?,
            binding: binding.clone(),
        };
        assert!(matches!(
            P07AuthorityPort::activate_grant(&port, &activation),
            Err(P07PortError::Unavailable)
        ));
        let revocation = GrantRevocationRequest {
            grant_id: grant_id("grant-unknown")?,
            snapshot_id: snapshot_id("snap-1")?,
            binding,
        };
        assert!(matches!(
            P07AuthorityPort::revoke_grant(&port, &revocation),
            Err(P07PortError::Unavailable)
        ));
        Ok(())
    }

    fn restart_test_binding(epoch: &EpochId) -> Result<AuthorityBinding, KernelError> {
        use eliot_contracts::{ContractId, ResourceGeneration};
        let fence = eliot_contracts::StateFence::new(epoch.clone(), ResourceGeneration::new(1)?);
        Ok(AuthorityBinding {
            authority_id: ContractId::new("authority:test")?,
            authority_owner: "test-owner".to_owned(),
            authority_epoch: epoch.clone(),
            state_fence: fence,
            allowed_effect: EffectClass::ExternalEffect,
            proof_ceiling: ProofCeiling::ObservedExternalEffect,
        })
    }

    fn restart_root_intent(binding: &AuthorityBinding) -> GrantActivationIntent {
        GrantActivationIntent {
            operation_id: "op-activate-root".to_owned(),
            grant_id: "grant-restart-root".to_owned(),
            parent_grant_id: None,
            authority_root_ref: "root-test".to_owned(),
            snapshot_id: "snap-1".to_owned(),
            grant_graph_revision: 2,
            holder_principal: "holder-1".to_owned(),
            session_id: "session-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            binding: binding.clone(),
            allowed_effect: EffectClass::Read,
            proof_ceiling: ProofCeiling::ScopedVerification,
            issued_at_ms: 1_000,
            expires_at_ms: None,
            receipt_obligations: vec!["obligation-1".to_owned()],
        }
    }

    #[test]
    fn rich_activation_replay_conflict_and_stale_revision_fail_closed() -> Result<(), KernelError> {
        let epoch = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 7)?;
        let binding = restart_test_binding(&epoch)?;
        let port = GrantActivationPort::new();
        let intent = restart_root_intent(&binding);

        let first = port.activate_grant(&intent, epoch.clone(), 1_000)?;
        assert!(matches!(
            first.state,
            eliot_runtime_contracts::AuthorityState::Active
        ));
        assert_eq!(first.activation_id, "activation-op-activate-root");
        // Exact replay returns the same receipt without a second activation.
        let replay = port.activate_grant(&intent, epoch.clone(), 1_000)?;
        assert_eq!(replay, first);
        // Changed payload under one operation identity conflicts.
        let mut changed = intent.clone();
        changed.holder_principal = "holder-2".to_owned();
        assert!(matches!(
            port.activate_grant(&changed, epoch.clone(), 1_000),
            Err(KernelError::IdempotencyConflict)
        ));
        // A recorded grant identity cannot activate again under a fresh
        // identity: restore never reactivates a path.
        let mut second = intent.clone();
        second.operation_id = "op-activate-root-again".to_owned();
        assert!(matches!(
            port.activate_grant(&second, epoch.clone(), 1_000),
            Err(KernelError::InvalidField { .. })
        ));
        // A revision older than the greatest observed for this root is stale.
        let stale_revoke = GrantRevocationIntent {
            operation_id: "op-revoke-stale".to_owned(),
            grant_id: "grant-restart-root".to_owned(),
            authority_root_ref: "root-test".to_owned(),
            snapshot_id: "snap-1".to_owned(),
            grant_graph_revision: 1,
            binding: binding.clone(),
            unknown_outcome_operations: Vec::new(),
            receipt_obligations: Vec::new(),
        };
        assert!(matches!(
            port.revoke_grant(&stale_revoke, epoch.clone()),
            Err(KernelError::InvalidField { .. })
        ));
        // Current-revision revocation fences the grant and commits one receipt.
        let revoke = GrantRevocationIntent {
            operation_id: "op-revoke-root".to_owned(),
            grant_graph_revision: 2,
            ..stale_revoke
        };
        let receipt = port.revoke_grant(&revoke, epoch.clone())?;
        assert!(matches!(
            receipt.state,
            eliot_runtime_contracts::AuthorityState::Revoked
        ));
        assert!(port.grant_revoked("grant-restart-root"));
        assert_eq!(
            port.revocation_closure("op-revoke-root"),
            Some(vec!["grant-restart-root".to_owned()])
        );
        Ok(())
    }

    #[test]
    fn restart_hydrates_nothing_and_reconciles_by_representation() -> Result<(), KernelError> {
        use eliot_authority::{
            GrantId, GrantRevocationRequest, P07AuthorityPort, P07PortError, SnapshotId,
        };

        fn thin_grant_id(value: &str) -> Result<GrantId, KernelError> {
            GrantId::new(value).map_err(|_| KernelError::InvalidField {
                field: "grant_id",
                reason: "test grant identity must validate",
            })
        }
        fn thin_snapshot_id(value: &str) -> Result<SnapshotId, KernelError> {
            SnapshotId::new(value).map_err(|_| KernelError::InvalidField {
                field: "snapshot_id",
                reason: "test snapshot identity must validate",
            })
        }

        let epoch = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 7)?;
        let binding = restart_test_binding(&epoch)?;
        let intent = restart_root_intent(&binding);

        // Simulated restart: a fresh port holds no ledger lineage.
        let restarted = GrantActivationPort::new();
        assert!(!restarted.grant_revoked("grant-restart-root"));
        // Thin revocation of unhydrated lineage fail-closes without
        // fabricating a fence.
        let thin_unknown = GrantRevocationRequest {
            grant_id: thin_grant_id("grant-restart-root")?,
            snapshot_id: thin_snapshot_id("snap-1")?,
            binding: binding.clone(),
        };
        assert!(matches!(
            P07AuthorityPort::revoke_grant(&restarted, &thin_unknown),
            Err(P07PortError::Unavailable)
        ));
        // Rich revocation of an unknown grant records a reconciling intent
        // instead of assuming a fence.
        let unknown_revoke = GrantRevocationIntent {
            operation_id: "op-revoke-unknown".to_owned(),
            grant_id: "grant-restart-root".to_owned(),
            authority_root_ref: "root-test".to_owned(),
            snapshot_id: "snap-1".to_owned(),
            grant_graph_revision: 2,
            binding: binding.clone(),
            unknown_outcome_operations: Vec::new(),
            receipt_obligations: Vec::new(),
        };
        assert!(matches!(
            restarted.revoke_grant(&unknown_revoke, epoch.clone()),
            Err(KernelError::InvalidField { .. })
        ));
        assert!(
            restarted
                .reconciling_operations()
                .contains(&"op-revoke-unknown".to_owned())
        );
        // Re-presenting the exact intent restores the same receipt root, and
        // the thin revocation path hydrates from that lineage.
        let restored = restarted.activate_grant(&intent, epoch.clone(), 1_000)?;
        assert_eq!(restored.activation_id, "activation-op-activate-root");
        assert!(matches!(
            restarted.disposition("op-activate-root"),
            Some(IntentDisposition::Committed(_))
        ));
        let thin_revoke = GrantRevocationRequest {
            grant_id: thin_grant_id("grant-restart-root")?,
            snapshot_id: thin_snapshot_id("snap-1")?,
            binding,
        };
        let fenced = P07AuthorityPort::revoke_grant(&restarted, &thin_revoke).map_err(|_| {
            KernelError::InvalidField {
                field: "binding",
                reason: "re-presented lineage must hydrate the thin revocation",
            }
        })?;
        assert!(matches!(
            fenced.state,
            eliot_runtime_contracts::AuthorityState::Revoked
        ));
        assert!(restarted.grant_revoked("grant-restart-root"));
        Ok(())
    }

    struct TestRootHydration {
        value: RootGrantHydration,
    }

    impl RootGrantHydrationSource for TestRootHydration {
        fn hydrate_root_grant(
            &self,
            _request: &eliot_authority::GrantActivationRequest,
        ) -> Result<RootGrantHydration, KernelError> {
            Ok(self.value.clone())
        }

        fn rehydrate_root_grant(
            &self,
            _projection: &CapabilityGrantProjection,
        ) -> Result<RootGrantHydration, KernelError> {
            Ok(self.value.clone())
        }
    }

    fn durable_root_fixture(
        epoch: &EpochId,
        binding: &AuthorityBinding,
    ) -> Result<(eliot_authority::GrantActivationRequest, RootGrantHydration), KernelError> {
        let operation_id = thin_operation_id("activate-grant", "grant-root", "snap-1", epoch);
        let intent = GrantActivationIntent {
            operation_id: operation_id.clone(),
            grant_id: "grant-root".to_owned(),
            parent_grant_id: None,
            authority_root_ref: "root-authority".to_owned(),
            snapshot_id: "snap-1".to_owned(),
            grant_graph_revision: 3,
            holder_principal: "holder-1".to_owned(),
            session_id: "session-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            binding: binding.clone(),
            allowed_effect: EffectClass::Read,
            proof_ceiling: ProofCeiling::ScopedVerification,
            issued_at_ms: 1_000,
            expires_at_ms: Some(10_000),
            receipt_obligations: vec!["obligation-1".to_owned()],
        };
        let authority_epoch = eliot_ors::EpochLineage {
            current: eliot_ors::EpochIdentity {
                lineage_id: eliot_ors::OpaqueLabel::new(epoch.lineage_id.as_str())?,
                epoch: epoch.sequence.get(),
            },
            predecessor: None,
        };
        let state_fence =
            eliot_ors::StateFenceSnapshot::capture(&binding.state_fence, epoch.sequence.get())?;
        let input = eliot_ors::OperationalRecordInput::encrypted(
            eliot_ors::OperationalRecordContext {
                record_id: eliot_ors::OperationIdentity::new(operation_id)?,
                subject_id: eliot_ors::OperationIdentity::new("grant-root")?,
                authority_epoch,
                state_fence,
                created_at_ms: 1_000,
                cleanup_after_ms: None,
            },
            eliot_platform::SecretReference::new("test-provider", "root-grant-key").map_err(
                |_error| KernelError::InvalidField {
                    field: "test_secret_reference",
                    reason: "fixture reference must validate",
                },
            )?,
            b"opaque-root-grant-record".to_vec(),
        )?;
        let durable_record = CapabilityGrantActivation::new(input)?;
        Ok((
            eliot_authority::GrantActivationRequest {
                grant_id: eliot_authority::GrantId::new("grant-root").map_err(|_| {
                    KernelError::InvalidField {
                        field: "grant_id",
                        reason: "fixture grant id must validate",
                    }
                })?,
                snapshot_id: eliot_authority::SnapshotId::new("snap-1").map_err(|_| {
                    KernelError::InvalidField {
                        field: "snapshot_id",
                        reason: "fixture snapshot id must validate",
                    }
                })?,
                binding: binding.clone(),
            },
            RootGrantHydration {
                intent,
                durable_record,
                observed_at_ms: 1_000,
            },
        ))
    }

    #[test]
    fn durable_root_activation_replay_recovery_and_revoke_are_exact()
    -> Result<(), Box<dyn std::error::Error>> {
        use eliot_authority::{P07AuthorityPort, P07PortError};
        use std::sync::Arc;

        let epoch = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 7)?;
        let binding = restart_test_binding(&epoch)?;
        let (request, hydration) = durable_root_fixture(&epoch, &binding)?;
        let hydration_source = Arc::new(TestRootHydration { value: hydration });
        let path = std::env::temp_dir().join(format!(
            "eliot-kernel-root-grant-{}-{}.redb",
            std::process::id(),
            epoch.sequence
        ));
        let _ = std::fs::remove_file(&path);

        let store = Arc::new(eliot_ors::RedbRecoveryStore::open(&path)?);
        let port =
            GrantActivationPort::with_durable_root_grant(hydration_source.clone(), store.clone());
        let first = P07AuthorityPort::activate_grant(&port, &request)
            .map_err(|error| format!("durable activation failed: {error:?}"))?;
        let replay = P07AuthorityPort::activate_grant(&port, &request)
            .map_err(|error| format!("in-process replay failed: {error:?}"))?;
        assert_eq!(replay, first);
        let subject = eliot_ors::OperationIdentity::new("grant-root")?;
        let projection = store
            .load_capability_grant(&subject)?
            .ok_or("active capability projection missing")?;
        assert_eq!(projection.phase(), OperationalPhase::Active);
        assert!(projection.operation_order() > 0);

        drop(port);
        drop(store);
        let reopened = Arc::new(eliot_ors::RedbRecoveryStore::open(&path)?);
        let restarted = GrantActivationPort::with_durable_root_grant(
            hydration_source.clone(),
            reopened.clone(),
        );
        let recovered = restarted.recover_root_grant("grant-root", &epoch, 1_000)?;
        assert_eq!(recovered, first);
        assert!(!restarted.grant_revoked("grant-root"));
        let restarted_replay = P07AuthorityPort::activate_grant(&restarted, &request)
            .map_err(|error| format!("restart replay failed: {error:?}"))?;
        assert_eq!(restarted_replay, first);

        let revoke = eliot_authority::GrantRevocationRequest {
            grant_id: request.grant_id.clone(),
            snapshot_id: request.snapshot_id.clone(),
            binding: request.binding.clone(),
        };
        let revoked = P07AuthorityPort::revoke_grant(&restarted, &revoke)
            .map_err(|error| format!("durable revoke failed: {error:?}"))?;
        assert!(matches!(revoked.state, AuthorityState::Revoked));
        assert!(restarted.grant_revoked("grant-root"));
        assert_eq!(
            reopened
                .load_capability_grant(&subject)?
                .ok_or("fenced capability projection missing")?
                .phase(),
            OperationalPhase::Fenced
        );
        let revoke_replay = P07AuthorityPort::revoke_grant(&restarted, &revoke)
            .map_err(|error| format!("revoke replay failed: {error:?}"))?;
        assert_eq!(revoke_replay, revoked);

        drop(restarted);
        drop(reopened);
        let reopened_again = Arc::new(eliot_ors::RedbRecoveryStore::open(&path)?);
        let after_revoke_restart =
            GrantActivationPort::with_durable_root_grant(hydration_source, reopened_again.clone());
        let revoke_after_restart =
            P07AuthorityPort::revoke_grant(&after_revoke_restart, &revoke)
                .map_err(|error| format!("durable revoke after restart failed: {error:?}"))?;
        assert_eq!(revoke_after_restart, revoked);
        assert!(after_revoke_restart.grant_revoked("grant-root"));

        let mut child_hydration = durable_root_fixture(&epoch, &binding)?.1;
        child_hydration.intent.parent_grant_id = Some("parent".to_owned());
        let child_source = Arc::new(TestRootHydration {
            value: child_hydration,
        });
        let child_port =
            GrantActivationPort::with_durable_root_grant(child_source, reopened_again.clone());
        assert!(matches!(
            P07AuthorityPort::activate_grant(&child_port, &request),
            Err(P07PortError::InvalidBinding)
        ));

        drop(child_port);
        drop(reopened_again);
        let _ = std::fs::remove_file(&path);
        Ok(())
    }
}
