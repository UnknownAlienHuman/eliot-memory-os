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
//!
//! Delegated descendant closure (lane C, `#2100`, remainder of `#1110`) builds
//! on the same rules without inventing a second graph owner:
//!
//! - the complete closure enumeration always comes from the injected Governor
//!   boundary ([`RootGrantHydrationSource::enumerate_grant_closure`]), never
//!   from the caller and never from process memory alone. Activation fetches
//!   the owner enumeration and requires byte equality with the presented one;
//!   revocation derives its fence set from the owner enumeration. A
//!   caller-supplied affected list, an empty-closure default, or an
//!   incomplete enumeration cannot commit a receipt;
//! - the thin P07 revocation never falls back to root-only fencing on a
//!   missing or singleton owner answer: a bound enumeration always takes the
//!   closure gate (a singleton is the owner's leaf attestation), and without
//!   the owner the port fences only when its own live lineage proves no live
//!   descendants, refusing otherwise;
//! - one exact graph revision binds the whole closure, enforced durably: the
//!   per-root revision watermark in ORS advances atomically with the stale
//!   check, so a superseded presentation fails closed even across restarts.
//!   The ORS per-row `Active`-to-`Fenced` transition stays the member-level
//!   compare-and-swap (exact replay returns the same receipt, a changed
//!   opaque payload under one record identity is
//!   [`KernelError::IdempotencyConflict`] at ORS, a fence from any other
//!   phase is refused);
//! - activation never resurrects: a `Fenced` or `Released` durable member row
//!   refuses before any mutation, on every activation path including the
//!   legacy single-root one;
//! - revocation commits one ORS fence per affected member with an exact
//!   read-back, then commits one durable closure row binding the operation,
//!   revision, digest, complete affected set, survivors, and receipt. A
//!   member already fenced under a previous closure with identical authority
//!   bytes is reconfirmed, never recommitted, so a fresh operation identity
//!   (new snapshot or epoch) re-confirms the fence instead of forking one.
//!   Restart rehydrates the same receipt and disposition by re-presentation
//!   through the owner enumeration; a missing, mixed-phase, or disagreeing
//!   ORS row stays fail-closed instead of restoring descendant authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use eliot_contracts::{EpochId, canonical_json_bytes, sha256_hex};
use eliot_ors::{
    CapabilityGrantActivation, CapabilityGrantProjection, CapabilityGrantRevocation,
    CapabilityIntroductionActivation, CapabilityIntroductionFence, GrantClosureFenceRequest,
    GrantClosureState, OpaqueLabel, OperationIdentity, OperationalMutationReceipt,
    OperationalPhase, OperationalRecordInput, OperationalRecoveryStore, StateFenceSnapshot,
};
/// Owner-declared exact-use alternate path retained while the rest of a
/// grant closure is fenced.
pub use eliot_receipts::GrantClosureAlternatePath as GrantClosureSurvivor;
/// Authoritative durable grant-closure receipt shared by Governor, Kernel and ORS.
pub use eliot_receipts::GrantClosureReceipt;
use eliot_receipts::{
    AuthorityBinding, EffectClass, GRANT_CLOSURE_SCHEMA, GRANT_CLOSURE_VERSION,
    GrantClosureAuthorityReceiptRef, GrantClosureDeclaration, GrantClosureMemberDeclaration,
    GrantClosureOrsReceiptRef, ProofCeiling,
};
use eliot_runtime_contracts::{
    AuthorityActivationReceipt, AuthorityRevocationReceipt, AuthorityState,
};
use serde::Serialize;

use crate::error::{KernelError, validate_id, validate_text};
use crate::introduction_lifecycle::{
    IntroductionHydration, introduction_fence_input, introduction_fence_record_id,
};

/// Live grant-activation intent presented to the one P-07 port.
///
/// The port validates every field before mutation and binds the full payload
/// into the idempotency digest, so any change under one operation identity is
/// an identity conflict rather than a second activation.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootGrantHydration {
    /// Complete semantic activation intent from the canonical Governor owner.
    pub intent: GrantActivationIntent,
    /// Opaque ORS input bound to the same root-grant identity and fence.
    pub durable_record: CapabilityGrantActivation,
    /// Caller-supplied observation time for the activation gate.
    pub observed_at_ms: i64,
}

/// The complete field set a Governor hydration source must return.
///
/// This is deliberately kept beside [`RootGrantHydration`] so an auditor can
/// compare the accepted issue brief with the port boundary without inferring
/// completeness from a constructor or from later live-state validation.
pub const ROOT_GRANT_HYDRATION_FIELDS: &[&str] = &[
    "intent.operation_id",
    "intent.grant_id",
    "intent.parent_grant_id",
    "intent.authority_root_ref",
    "intent.snapshot_id",
    "intent.grant_graph_revision",
    "intent.holder_principal",
    "intent.session_id",
    "intent.scope_id",
    "intent.binding",
    "intent.allowed_effect",
    "intent.proof_ceiling",
    "intent.issued_at_ms",
    "intent.expires_at_ms",
    "intent.receipt_obligations",
    "durable_record",
    "observed_at_ms",
];

impl RootGrantHydration {
    fn validate_fields(&self, active_epoch: &EpochId) -> Result<(), KernelError> {
        validate_id(&self.intent.operation_id, "hydration.intent.operation_id")?;
        validate_id(&self.intent.grant_id, "hydration.intent.grant_id")?;
        validate_id(
            &self.intent.authority_root_ref,
            "hydration.intent.authority_root_ref",
        )?;
        validate_id(&self.intent.snapshot_id, "hydration.intent.snapshot_id")?;
        validate_id(
            &self.intent.holder_principal,
            "hydration.intent.holder_principal",
        )?;
        validate_id(&self.intent.session_id, "hydration.intent.session_id")?;
        validate_id(&self.intent.scope_id, "hydration.intent.scope_id")?;
        for obligation in &self.intent.receipt_obligations {
            validate_id(obligation, "hydration.intent.receipt_obligation")?;
        }
        if self.intent.grant_graph_revision == 0 {
            return Err(KernelError::InvalidField {
                field: "hydration.intent.grant_graph_revision",
                reason: "grant graph revision must be nonzero",
            });
        }
        if self.intent.parent_grant_id.is_some() {
            return Err(KernelError::InvalidField {
                field: "hydration.intent.parent_grant_id",
                reason: "the first durable slice accepts authority roots only",
            });
        }
        check_binding(&self.intent.binding, active_epoch)?;
        check_ceiling(
            self.intent.allowed_effect,
            self.intent.proof_ceiling,
            &self.intent.binding,
        )?;
        check_expiry(
            self.intent.issued_at_ms,
            self.intent.expires_at_ms,
            self.observed_at_ms,
        )?;
        check_opaque_record_binding(
            self.durable_record.record(),
            &self.intent.binding,
            active_epoch,
        )
    }
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

    /// Enumerates the complete durable descendant closure for one grant at
    /// the owner graph revision.
    ///
    /// The Governor owner reads its durable `GrantGraph` at one exact revision
    /// and returns every affected member plus the owner-declared
    /// alternate-path survivors. The port validates the enumeration (exact
    /// revision, root, fence, epoch, acyclic parents, completeness against
    /// live lineage) before any mutation. The default implementation reports
    /// the missing owner so callers fail closed without fabricating a fence.
    fn enumerate_grant_closure(
        &self,
        _grant_id: &str,
    ) -> Result<GrantClosureEnumeration, KernelError> {
        Err(KernelError::DependencyUnavailable(
            "grant-closure enumeration owner is not bound".to_owned(),
        ))
    }

    /// Resolves a historical owner hydration for recovery of an already
    /// committed fenced row. It is never valid for new admission.
    fn historical_grant_hydration(
        &self,
        _grant_id: &str,
    ) -> Result<Option<GrantClosureMember>, KernelError> {
        Ok(None)
    }

    /// Returns every current owner-admitted grant hydration for complete
    /// restart projection. The default refuses rather than rebuilding a
    /// partial process cache.
    fn admitted_grant_hydrations(&self) -> Result<Vec<GrantClosureMember>, KernelError> {
        Err(KernelError::DependencyUnavailable(
            "complete grant hydration projection is not bound".to_owned(),
        ))
    }

    /// Returns every current owner-admitted introduction hydration for
    /// complete restart projection.
    fn admitted_introductions(&self) -> Result<Vec<IntroductionHydration>, KernelError> {
        Err(KernelError::DependencyUnavailable(
            "complete introduction hydration projection is not bound".to_owned(),
        ))
    }

    /// Resolves one exact admitted grant hydration for mechanical alternate
    /// path validation. This is a projection lookup, not semantic enumeration.
    fn hydrate_grant_member(&self, _grant_id: &str) -> Result<GrantClosureMember, KernelError> {
        Err(KernelError::DependencyUnavailable(
            "grant-closure hydration owner is not bound".to_owned(),
        ))
    }

    /// Resolves a thin introduction-activation request to the complete
    /// canonical introduction hydration.
    ///
    /// The Governor introduction-hydration owner serves the admitted intent
    /// plus its opaque ORS record; the port validates identity, fence, and
    /// lifecycle agreement before any mutation, mirroring the grant
    /// hydration gate. The default implementation reports the missing owner
    /// so callers fail closed without fabricating an introduction.
    fn hydrate_introduction(
        &self,
        _request: &eliot_authority::IntroductionActivationRequest,
    ) -> Result<IntroductionHydration, KernelError> {
        Err(KernelError::DependencyUnavailable(
            "introduction-hydration owner is not bound".to_owned(),
        ))
    }
}

/// Live introduction-activation intent presented to the one P-07 port.
///
/// Every supporting grant must be recorded, active, unexpired, on the same
/// root and fence, and its recorded ceilings must cover the requested
/// effect and proof ceiling.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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

/// One delegated member of a Governor-enumerated durable grant closure.
///
/// The member carries the complete semantic activation intent plus its opaque
/// ORS record, exactly like [`RootGrantHydration`] does for the authority
/// root. Unlike the first durable slice, `intent.parent_grant_id` may name the
/// delegating parent: the parent must appear earlier in the same enumeration
/// or already be recorded, active, and on the exact same root and fence.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantClosureMember {
    /// Complete semantic activation intent from the canonical Governor owner.
    pub intent: GrantActivationIntent,
    /// Opaque ORS input bound to the same member identity and fence.
    pub durable_record: CapabilityGrantActivation,
    /// Caller-supplied observation time for the member activation gate.
    pub observed_at_ms: i64,
}

/// Complete delegated closure declared by the canonical Governor owner at one
/// exact graph revision.
///
/// The enumeration is the only closure authority this port accepts: the fence
/// set is derived from these members, never from caller material and never
/// from process memory alone. `preserved` names descendants the owner keeps
/// usable under a surviving alternate authority path; every other recorded
/// descendant of the closure root must appear in `members` or revocation
/// refuses as an incomplete enumeration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantClosureEnumeration {
    /// Lineage domain. Every member must share it.
    pub authority_root_ref: String,
    /// Exact graph revision the closure was enumerated at. Zero is invalid;
    /// below the greatest revision observed for this root is stale.
    pub grant_graph_revision: u64,
    /// Closure members in parent-before-child order, root first. Exactly one
    /// member must be the authority root (`parent_grant_id` is `None`).
    pub members: Vec<GrantClosureMember>,
    /// Owner-declared alternate-path survivors. They are recorded, never
    /// fenced, and must be disjoint from `members`.
    pub preserved: Vec<GrantClosureSurvivor>,
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), KernelError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(KernelError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

fn validate_preserved_set(
    preserved: &[GrantClosureSurvivor],
    affected: &[String],
) -> Result<(), KernelError> {
    for survivor in preserved {
        for (value, field) in [
            (&survivor.grant_id, "closure_receipt.survivor_grant"),
            (
                &survivor.covering_grant_id,
                "closure_receipt.survivor_covering_grant",
            ),
            (
                &survivor.covering_root_ref,
                "closure_receipt.survivor_covering_root",
            ),
            (
                &survivor.operation_id,
                "closure_receipt.survivor_operation_id",
            ),
            (
                &survivor.operation_name,
                "closure_receipt.survivor_operation_name",
            ),
            (
                &survivor.resource_ref,
                "closure_receipt.survivor_resource_ref",
            ),
            (
                &survivor.holder_principal,
                "closure_receipt.survivor_holder_principal",
            ),
            (&survivor.session_id, "closure_receipt.survivor_session_id"),
            (&survivor.scope_id, "closure_receipt.survivor_scope_id"),
        ] {
            validate_id(value, field)?;
        }
        validate_sha256(
            &survivor.canonical_request_hash,
            "closure_receipt.survivor_canonical_request_hash",
        )?;
        if affected
            .iter()
            .any(|grant_id| grant_id == &survivor.grant_id)
        {
            return Err(KernelError::InvalidField {
                field: "closure_receipt.preserved_grants",
                reason: "a survivor must be disjoint from the affected set",
            });
        }
    }
    if preserved.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(KernelError::InvalidField {
            field: "closure_receipt.preserved_grants",
            reason: "survivors must be sorted and unique",
        });
    }
    Ok(())
}

/// The complete field set a Governor closure enumeration must return.
///
/// This is kept beside [`GrantClosureEnumeration`] so an auditor can compare
/// the accepted issue brief with the port boundary without inferring
/// completeness from a constructor.
pub const GRANT_CLOSURE_ENUMERATION_FIELDS: &[&str] = &[
    "authority_root_ref",
    "grant_graph_revision",
    "members[].intent.operation_id",
    "members[].intent.grant_id",
    "members[].intent.parent_grant_id",
    "members[].intent.authority_root_ref",
    "members[].intent.snapshot_id",
    "members[].intent.grant_graph_revision",
    "members[].intent.holder_principal",
    "members[].intent.session_id",
    "members[].intent.scope_id",
    "members[].intent.binding",
    "members[].intent.allowed_effect",
    "members[].intent.proof_ceiling",
    "members[].intent.issued_at_ms",
    "members[].intent.expires_at_ms",
    "members[].intent.receipt_obligations",
    "members[].durable_record",
    "members[].observed_at_ms",
    "preserved[].grant_id",
    "preserved[].covering_grant_id",
    "preserved[].covering_root_ref",
    "preserved[].operation_id",
    "preserved[].operation_name",
    "preserved[].resource_ref",
    "preserved[].effect",
    "preserved[].holder_principal",
    "preserved[].session_id",
    "preserved[].scope_id",
    "preserved[].canonical_request_hash",
];

/// Durable multi-descendant activation intent presented to the one P-07 port.
///
/// The closure members come from the injected Governor enumeration carried in
/// this intent; validation, idempotency, ORS commit, read-back, and live
/// installation follow the same gate order as the single-root durable path,
/// applied member by member in parent-before-child order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantClosureActivationIntent {
    /// Idempotency identity for the whole closure. Ledger key and
    /// receipt-derivation root.
    pub operation_id: String,
    /// Complete owner-enumerated closure at one exact graph revision.
    pub enumeration: GrantClosureEnumeration,
}

/// Durable multi-descendant revocation intent presented to the one P-07 port.
///
/// The intent carries no member list. The complete fence set comes from the
/// bound Governor declaration; Kernel validates its identity/revision/fence
/// contour and persists every declared member in one ORS transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantClosureRevocationIntent {
    /// Idempotency identity for the whole closure. Ledger key and
    /// receipt-derivation root.
    pub operation_id: String,
    /// Closure target: the delegation root to fence with its descendants.
    pub grant_id: String,
    /// Lineage domain. Must match the recorded target root.
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
    #[cfg(test)]
    durable: Option<DurableRootGrantBoundary>,
    #[cfg(not(test))]
    durable: DurableRootGrantBoundary,
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
            .field("durable", &self.durable_boundary().is_some())
            .finish()
    }
}

#[cfg(test)]
impl Default for GrantActivationPort {
    fn default() -> Self {
        Self::new()
    }
}

impl GrantActivationPort {
    /// Creates a ledger-only port for rich unit tests.
    ///
    /// Production P-07 construction is durable-only; this constructor is
    /// intentionally unavailable outside this module's tests.
    #[cfg(test)]
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
            #[cfg(test)]
            durable: Some(DurableRootGrantBoundary { hydration, store }),
            #[cfg(not(test))]
            durable: DurableRootGrantBoundary { hydration, store },
        }
    }

    #[cfg_attr(
        not(test),
        allow(
            clippy::unnecessary_wraps,
            reason = "the test-only ledger fixture is optional, while production is durable-only"
        )
    )]
    fn durable_boundary(&self) -> Option<&DurableRootGrantBoundary> {
        #[cfg(test)]
        {
            self.durable.as_ref()
        }
        #[cfg(not(test))]
        {
            Some(&self.durable)
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
    #[cfg(test)]
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
                closure_receipt: None,
                closure_member_receipts: Vec::new(),
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
    #[cfg(test)]
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
                        closure_receipt: None,
                        closure_member_receipts: Vec::new(),
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
                closure_receipt: None,
                closure_member_receipts: Vec::new(),
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
    #[cfg(test)]
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
        validate_introduction_activation(
            request,
            &ledger,
            &active_epoch,
            now_ms,
            IntroductionActivationMode::Fresh,
        )?;
        let mut supporting = BTreeSet::new();
        for id in &request.supporting_grant_ids {
            supporting.insert(id.clone());
        }
        let operation_id = request.operation_id.clone();
        let receipt = runtime_introduction_activation_receipt(request, &active_epoch)?;
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
                closure_receipt: None,
                closure_member_receipts: Vec::new(),
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
    #[cfg(test)]
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
                        closure_receipt: None,
                        closure_member_receipts: Vec::new(),
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
                closure_receipt: None,
                closure_member_receipts: Vec::new(),
            },
        );
        Ok(receipt)
    }

    /// Activates one Governor-hydrated introduction durably and returns its
    /// canonical receipt.
    ///
    /// The owner-presented hydration carries the complete semantic intent
    /// plus its opaque ORS record; the port validates both, commits the row
    /// verbatim, requires exact read-back, advances the durable revision
    /// watermark, and only then installs live state. Exact replay under one
    /// operation identity re-reads the durable row, revalidates the current
    /// supporting-grant fences, graph revision, expiry, live target state, and
    /// committed closure introduction-fence set, then returns the same receipt
    /// without another ORS write. A changed payload under one identity, a
    /// duplicate introduction identity, a moved revision/fence, revoked
    /// support, expired support, or a `Fenced` durable row fails before any
    /// mutation — restore never reactivates a fenced introduction.
    ///
    /// Supporting grants must already be recorded live (activation order:
    /// grants first, then introductions; after a restart the grants are
    /// rehydrated through the grant recovery paths before this call).
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::IdempotencyConflict`] for a changed payload,
    /// [`KernelError::IllegalTransition`] for a `Fenced` row presented for
    /// activation, [`KernelError::FenceMismatch`] for a stale, future or
    /// cross-lineage epoch or fence, [`KernelError::Expired`] for an expired
    /// intent, [`KernelError::RecoveryUnavailable`] when the durable
    /// boundary is missing or the read-back disagrees, and
    /// [`KernelError::InvalidField`] for any other invalid identity,
    /// revision, binding, ceiling, lineage, or disagreeing row value.
    #[allow(
        clippy::too_many_lines,
        reason = "the durable introduction gate keeps validation, ORS commit, read-back, watermark, and install together"
    )]
    pub fn activate_introduction_durable(
        &self,
        hydration: &IntroductionHydration,
        active_epoch: &EpochId,
        now_ms: i64,
    ) -> Result<AuthorityActivationReceipt, KernelError> {
        let boundary = self.durable_boundary().ok_or_else(|| {
            KernelError::RecoveryUnavailable(
                "introduction activation needs the durable root-grant boundary".to_owned(),
            )
        })?;
        hydration.validate_complete()?;
        let request = &hydration.intent;
        // The replay identity binds the exact opaque record in addition to
        // the semantic intent, so a changed encrypted payload under one
        // introduction identity is a conflict rather than a replay.
        let digest = hydrated_introduction_digest(hydration)?;
        let mut ledger = self.lock_ledger();
        let replay = match ledger.resolve(&request.operation_id, &digest) {
            IntentResolve::Conflict => return Err(KernelError::IdempotencyConflict),
            IntentResolve::Replay(disposition) => Some(disposition),
            IntentResolve::New => None,
        };
        verify_introduction_seal(&hydration.durable_record, request, active_epoch)?;
        if let Some(disposition) = replay {
            return revalidate_committed_introduction_activation(
                boundary,
                &ledger,
                hydration,
                active_epoch,
                now_ms,
                disposition,
            );
        }
        validate_introduction_activation(
            request,
            &ledger,
            active_epoch,
            now_ms,
            IntroductionActivationMode::Fresh,
        )?;
        // Durable row gate: only an absent row may be committed. An `Active`
        // row must carry the exact presented input (exact replay installs
        // through the idempotent ORS transition); a `Fenced` row is fence
        // evidence and refuses with the explicit state-machine guard.
        let subject =
            OperationIdentity::new(&request.introduction_id).map_err(KernelError::RecoveryState)?;
        match boundary
            .store
            .load_capability_introduction(&subject)
            .map_err(|error| map_ors_recovery_error(&error))?
        {
            Some(existing) if existing.phase() == OperationalPhase::Fenced => {
                return Err(KernelError::IllegalTransition {
                    machine: "capability-introduction",
                    from: "Fenced".to_owned(),
                    to: "Active".to_owned(),
                });
            }
            Some(existing)
                if existing.phase() == OperationalPhase::Active
                    && existing.record() != hydration.durable_record.record() =>
            {
                return Err(KernelError::InvalidField {
                    field: "introduction_id",
                    reason: "introduction identity is already recorded under a different input",
                });
            }
            Some(_) | None => {}
        }
        let durable_receipt = boundary
            .store
            .activate_capability_introduction(hydration.durable_record.clone())
            .map_err(|error| {
                map_introduction_transition_error(&error, &subject, boundary, "Active")
            })?;
        let projection = boundary
            .store
            .load_capability_introduction(&subject)
            .map_err(|error| map_ors_recovery_error(&error))?
            .ok_or_else(|| {
                KernelError::RecoveryUnavailable(
                    "introduction projection disappeared during activation".to_owned(),
                )
            })?;
        if projection.phase() != OperationalPhase::Active
            || projection.record() != hydration.durable_record.record()
            || projection.receipt() != durable_receipt.receipt()
        {
            return Err(KernelError::RecoveryUnavailable(
                "introduction activation ORS receipt/read-back disagreed".to_owned(),
            ));
        }
        check_closure_watermark(
            boundary,
            &request.authority_root_ref,
            request.grant_graph_revision,
        )?;
        let mut supporting = BTreeSet::new();
        for id in &request.supporting_grant_ids {
            supporting.insert(id.clone());
        }
        let operation_id = request.operation_id.clone();
        let receipt = runtime_introduction_activation_receipt(request, active_epoch)?;
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
                closure_receipt: None,
                closure_member_receipts: Vec::new(),
            },
        );
        Ok(receipt)
    }

    /// Revokes one introduction durably and returns the canonical revocation
    /// receipt.
    ///
    /// The live record names the lineage root; the durable row must read
    /// back `Active` and agree with the fence derived from its committed
    /// activation bytes. Revocation of an unknown introduction records a
    /// reconciling intent instead of fabricating a fence, mirroring the live
    /// path. Re-fencing an already-`Fenced` row refuses with the explicit
    /// state-machine guard instead of recommitting.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::IdempotencyConflict`] for a changed payload,
    /// [`KernelError::IllegalTransition`] for a `Fenced` row presented for
    /// fencing, [`KernelError::FenceMismatch`] for a stale, future or
    /// cross-lineage epoch or fence, [`KernelError::RecoveryUnavailable`]
    /// when the durable boundary or row is missing or the read-back
    /// disagrees, and [`KernelError::InvalidField`] for any other invalid
    /// identity or unknown lineage value.
    #[allow(
        clippy::too_many_lines,
        reason = "the durable introduction fence keeps derivation, idempotency, ORS CAS, read-back, watermark, and install together"
    )]
    pub fn revoke_introduction_durable(
        &self,
        request: &IntroductionRevocationIntent,
        active_epoch: &EpochId,
    ) -> Result<AuthorityRevocationReceipt, KernelError> {
        let boundary = self.durable_boundary().ok_or_else(|| {
            KernelError::RecoveryUnavailable(
                "introduction revocation needs the durable root-grant boundary".to_owned(),
            )
        })?;
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
                        closure_receipt: None,
                        closure_member_receipts: Vec::new(),
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
        // Durable fence gate: the row must read back `Active`. A `Fenced`
        // row is already fence evidence — re-fencing it through the
        // Active-only transition refuses with the explicit guard; an absent
        // row is live-only state that cannot take the durable fence path.
        let subject =
            OperationIdentity::new(&request.introduction_id).map_err(KernelError::RecoveryState)?;
        let activation_input = match boundary
            .store
            .load_capability_introduction(&subject)
            .map_err(|error| map_ors_recovery_error(&error))?
        {
            None => {
                return Err(KernelError::RecoveryUnavailable(
                    "introduction projection is absent; no durable row to fence".to_owned(),
                ));
            }
            Some(existing) if existing.phase() == OperationalPhase::Fenced => {
                return Err(KernelError::IllegalTransition {
                    machine: "capability-introduction",
                    from: "Fenced".to_owned(),
                    to: "Fenced".to_owned(),
                });
            }
            Some(existing) => existing.record().clone(),
        };
        let fence_record = introduction_fence_input(&activation_input, &request.operation_id)?;
        let durable_receipt = boundary
            .store
            .fence_capability_introduction(fence_record.clone())
            .map_err(|error| {
                map_introduction_transition_error(&error, &subject, boundary, "Fenced")
            })?;
        let projection = boundary
            .store
            .load_capability_introduction(&subject)
            .map_err(|error| map_ors_recovery_error(&error))?
            .ok_or_else(|| {
                KernelError::RecoveryUnavailable(
                    "introduction projection disappeared during revocation".to_owned(),
                )
            })?;
        if projection.phase() != OperationalPhase::Fenced
            || projection.record() != fence_record.record()
            || projection.receipt() != durable_receipt.receipt()
        {
            return Err(KernelError::RecoveryUnavailable(
                "introduction revocation ORS receipt/read-back disagreed".to_owned(),
            ));
        }
        check_closure_watermark(
            boundary,
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
                closure_receipt: None,
                closure_member_receipts: Vec::new(),
            },
        );
        Ok(receipt)
    }

    /// Rehydrates one committed introduction activation after a restart.
    ///
    /// The caller re-presents the Governor hydration; the port requires the
    /// durable row to read back `Active` with exact record agreement and the
    /// presented revision to bind the durable watermark before reinstalling
    /// live state. Exact replay performs the same read-only fence, revision,
    /// expiry, revoked-target, closure introduction-set, and stored-receipt
    /// checks before returning. A missing row, a `Fenced` row, or a
    /// disagreeing row stays fail-closed: absence of the durable introduction
    /// never restores introduction authority, and a fence is never
    /// resurrected.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::IdempotencyConflict`] for a changed payload,
    /// [`KernelError::IllegalTransition`] for a `Fenced` row presented for
    /// rehydration, [`KernelError::FenceMismatch`] for a stale, future or
    /// cross-lineage epoch or fence, [`KernelError::Expired`] for an expired
    /// intent, [`KernelError::RecoveryUnavailable`] when the durable
    /// boundary or row is missing or disagrees, and
    /// [`KernelError::InvalidField`] for any other invalid identity,
    /// revision, binding, ceiling, or lineage value.
    pub fn recover_introduction(
        &self,
        hydration: &IntroductionHydration,
        active_epoch: &EpochId,
        now_ms: i64,
    ) -> Result<AuthorityActivationReceipt, KernelError> {
        let boundary = self.durable_boundary().ok_or_else(|| {
            KernelError::RecoveryUnavailable(
                "introduction recovery needs the durable root-grant boundary".to_owned(),
            )
        })?;
        hydration.validate_complete()?;
        let request = &hydration.intent;
        let digest = hydrated_introduction_digest(hydration)?;
        let mut ledger = self.lock_ledger();
        let replay = match ledger.resolve(&request.operation_id, &digest) {
            IntentResolve::Conflict => return Err(KernelError::IdempotencyConflict),
            IntentResolve::Replay(disposition) => Some(disposition),
            IntentResolve::New => None,
        };
        if let Some(disposition) = replay {
            return revalidate_committed_introduction_activation(
                boundary,
                &ledger,
                hydration,
                active_epoch,
                now_ms,
                disposition,
            );
        }
        // Restore agreement first: only an `Active` row carrying the exact
        // presented input may be reinstalled. A `Fenced` row refuses with
        // the explicit guard; recovery never resurrects revoked authority.
        let subject =
            OperationIdentity::new(&request.introduction_id).map_err(KernelError::RecoveryState)?;
        match boundary
            .store
            .load_capability_introduction(&subject)
            .map_err(|error| map_ors_recovery_error(&error))?
        {
            None => {
                return Err(KernelError::RecoveryUnavailable(
                    "introduction projection is absent during recovery".to_owned(),
                ));
            }
            Some(existing) if existing.phase() == OperationalPhase::Fenced => {
                return Err(KernelError::IllegalTransition {
                    machine: "capability-introduction",
                    from: "Fenced".to_owned(),
                    to: "Active".to_owned(),
                });
            }
            Some(existing) if existing.record() != hydration.durable_record.record() => {
                return Err(KernelError::InvalidField {
                    field: "introduction_id",
                    reason: "durable introduction row disagrees with the re-presented input",
                });
            }
            Some(_) => {}
        }
        validate_introduction_activation(
            request,
            &ledger,
            active_epoch,
            now_ms,
            IntroductionActivationMode::Fresh,
        )?;
        verify_introduction_seal(&hydration.durable_record, request, active_epoch)?;
        check_closure_watermark(
            boundary,
            &request.authority_root_ref,
            request.grant_graph_revision,
        )?;
        let mut supporting = BTreeSet::new();
        for id in &request.supporting_grant_ids {
            supporting.insert(id.clone());
        }
        let operation_id = request.operation_id.clone();
        let receipt = runtime_introduction_activation_receipt(request, active_epoch)?;
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
                closure_receipt: None,
                closure_member_receipts: Vec::new(),
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

    /// Returns the revoked members of the explicit support closure under each
    /// root: the root itself plus every transitive descendant that is also
    /// revoked (I12.20 traverse-explicit-closure).
    ///
    /// This is the read-only query companion of the recovery
    /// never-resurrects precedent (`recover_introduction`,
    /// `recover_grant_closure_activation`): restore/compile gates use it to
    /// remove revoked support before requalification, so revoked lineage can
    /// never become active again after restore. Roots that are neither
    /// revoked grants nor revoked introductions contribute nothing, as do
    /// unknown identities; set semantics absorb cycles. No mutation, no new
    /// state.
    ///
    /// The traversal is the shared [`revoked_support_in_ledger`]
    /// implementation on the held ledger, so recovery paths that already own
    /// the port lock reuse the exact same closure without re-locking (a
    /// `&self` query under the held guard would deadlock on the mutex).
    #[must_use]
    pub fn revoked_support_closure(&self, roots: &[String]) -> BTreeSet<String> {
        let ledger = self.lock_ledger();
        revoked_support_in_ledger(&ledger, roots)
    }

    /// Kernel-owned revocation fan-out from one durable root revocation
    /// record to the revoked derived-handle set (I12.20 S1 traverse + S2
    /// explicit-closure scope, issue #1732).
    ///
    /// S1 marks the revoked root from the durable record itself: the record
    /// subject is the revoked authority root committed by the Kernel-owned
    /// revocation workflow (`revoke_closure_core` builds one
    /// [`CapabilityGrantRevocation`] per fenced member through
    /// `closure_member_revocation`). S2 bounds traversal to the explicit
    /// recorded closure: the set is the root plus every transitive
    /// descendant that is also revoked, including revoked introductions on
    /// those identities. The traversal is the shared
    /// [`Self::revoked_support_closure`] implementation, so no graph logic is
    /// duplicated here; unknown identities contribute nothing and set
    /// semantics absorb cycles.
    ///
    /// The query is read-only. Compile/restore gates remove the returned
    /// handles from derived artifacts before requalification; the
    /// closure-activation recovery gate in this file consumes the same
    /// traversal to refuse reinstalling revoked support before any durable
    /// write.
    #[must_use]
    pub fn revoked_handles_for_compile(
        &self,
        root_revocation: &CapabilityGrantRevocation,
    ) -> BTreeSet<String> {
        let root = root_revocation.record().subject_id.as_str().to_owned();
        self.revoked_support_closure(&[root])
    }

    /// Returns the greatest grant-graph revision observed for one lineage
    /// root, or `None` when no intent has been recorded under that root.
    ///
    /// This is the port-side half of exact revision enumeration: every
    /// activation, introduction, and revocation notes its presented revision,
    /// and any revision below the returned value fails closed as stale. ORS
    /// projections carry no semantic revision (the record stays opaque to
    /// ORS), so the revision itself always arrives bound inside the Governor
    /// hydration digest; this query only exposes the monotonic watermark the
    /// port enforces.
    #[must_use]
    pub fn grant_graph_revision(&self, authority_root_ref: &str) -> Option<u64> {
        let ledger = self.lock_ledger();
        ledger.max_revision.get(authority_root_ref).copied()
    }

    /// Returns the durable closure receipt committed by one closure
    /// operation, if any.
    ///
    /// Returns `None` for an unknown operation identity and for operations
    /// that are not closure activations or revocations. Restart rehydration
    /// repopulates the receipt so the query reads back restart-identical
    /// values.
    #[must_use]
    pub fn closure_receipt(&self, operation_id: &str) -> Option<GrantClosureReceipt> {
        let ledger = self.lock_ledger();
        ledger
            .intents
            .get(operation_id)
            .and_then(|record| record.closure_receipt.clone())
    }

    /// Rehydrates every committed closure row for the bound owner before any
    /// affected-descendant operation is admitted.
    ///
    /// The owner supplies the exact current roots, graph revision, and
    /// revocation-suppressed identities. ORS rows are read under their
    /// existing receipts; a missing member, stale graph head, malformed
    /// version, or incomplete coverage returns recovery-required and installs
    /// no partial live state. Rehydrated active introductions also recover
    /// their activation intent records, so a post-restart exact replay
    /// resolves to the read-only revalidation branch (row read-back, complete
    /// closure introduction-fence re-enumeration, watermark check) and returns
    /// the same committed disposition instead of refusing as a duplicate.
    #[allow(
        clippy::too_many_lines,
        reason = "restart rehydration validates every durable closure row before installing one coherent live projection"
    )]
    pub fn rehydrate_committed_authority(
        &self,
        authority_roots: &[String],
        expected_revision: u64,
        revoked_grants: &[String],
    ) -> Result<(), KernelError> {
        if expected_revision == 0 || authority_roots.is_empty() {
            return Err(KernelError::InvalidField {
                field: "owner_rehydration",
                reason: "requires a nonzero graph revision and at least one authority root",
            });
        }
        let boundary = self.durable_boundary().ok_or_else(|| {
            KernelError::RecoveryUnavailable(
                "owner rehydration requires the durable boundary".to_owned(),
            )
        })?;
        let page_limit = eliot_ors::MAX_RECOVERY_PAGE;
        let mut ledger = self.lock_ledger();
        let mut candidate = ledger.clone();
        // Preserve non-closure replay/reconciliation identities while
        // rebuilding every authority projection from the incoming owner and
        // durable rows. The projection is swapped only after all checks pass.
        candidate.grants.clear();
        candidate.revoked_grants.clear();
        candidate.introductions.clear();
        candidate.max_revision.clear();
        candidate.closure_targets.clear();
        let mut projections = Vec::new();
        for root in authority_roots {
            validate_id(root, "owner_rehydration.authority_root_ref")?;
            let label = OpaqueLabel::new(root).map_err(KernelError::RecoveryState)?;
            let stored_revision = boundary
                .store
                .load_grant_graph_revision(&label)
                .map_err(|error| map_ors_recovery_error(&error))?;
            if stored_revision != Some(expected_revision) {
                return Err(KernelError::RecoveryUnavailable(
                    "durable graph revision is absent or stale during owner rehydration".to_owned(),
                ));
            }
            let (rows, watermark) = boundary
                .store
                .scan_grant_closures_for_lineage(&label, page_limit)
                .map_err(|error| map_ors_recovery_error(&error))?;
            if watermark != Some(expected_revision) {
                return Err(KernelError::RecoveryUnavailable(
                    "closure rows and graph watermark are not one current revision".to_owned(),
                ));
            }
            projections.extend(rows);
        }
        let closure_commits = projections
            .iter()
            .map(|projection| projection.commit().clone())
            .collect::<Vec<_>>();
        let required = revoked_grants.iter().cloned().collect::<BTreeSet<_>>();
        let mut covered = BTreeSet::<String>::new();
        let mut recovered = Vec::new();
        let mut active_recovered = Vec::new();
        let mut operation_ids = BTreeSet::new();
        'projection: for projection in projections {
            let commit = projection.commit().clone();
            commit
                .validate()
                .map_err(|error| KernelError::RecoveryUnavailable(error.to_string()))?;
            if !authority_roots
                .iter()
                .any(|root| root == &commit.declaration.authority_root_ref)
                || commit.declaration.grant_graph_revision > expected_revision
            {
                return Err(KernelError::RecoveryUnavailable(
                    "committed closure is outside the current owner revision/root".to_owned(),
                ));
            }
            if !operation_ids.insert(commit.operation_id.clone()) {
                return Err(KernelError::RecoveryUnavailable(
                    "duplicate closure operation identity during rehydration".to_owned(),
                ));
            }
            let mut superseded = false;
            for (member, expected_receipt) in commit
                .declaration
                .members
                .iter()
                .zip(&commit.ors_member_receipts)
            {
                let subject =
                    OperationIdentity::new(&member.grant_id).map_err(KernelError::RecoveryState)?;
                let row = boundary
                    .store
                    .load_capability_grant(&subject)
                    .map_err(|error| map_ors_recovery_error(&error))?
                    .ok_or_else(|| {
                        KernelError::RecoveryUnavailable(
                            "closure member row is absent during rehydration".to_owned(),
                        )
                    })?;
                let expected_phase = match commit.state {
                    GrantClosureState::Active => OperationalPhase::Active,
                    GrantClosureState::Revoked => OperationalPhase::Fenced,
                };
                if commit.state == GrantClosureState::Active
                    && row.phase() == OperationalPhase::Fenced
                {
                    // A later durable revocation supersedes this historical
                    // activation receipt. The current fenced row is validated
                    // against that later Revoked closure below.
                    continue 'projection;
                }
                if row.phase() != expected_phase {
                    return Err(KernelError::RecoveryUnavailable(
                        "closure member phase disagrees with its durable receipt".to_owned(),
                    ));
                }
                let receipt_matches = row.receipt().record_id().as_str()
                    == expected_receipt.record_id
                    && row.receipt().subject_id().as_str() == expected_receipt.subject_id
                    && row.receipt().operation_order() == expected_receipt.operation_order
                    && row.receipt().state_sha256() == expected_receipt.state_sha256;
                if !receipt_matches {
                    if commit.state == GrantClosureState::Revoked
                        && row.phase() == OperationalPhase::Fenced
                    {
                        superseded = true;
                        break;
                    }
                    return Err(KernelError::RecoveryUnavailable(
                        "closure member receipt disagrees during rehydration".to_owned(),
                    ));
                }
            }
            if superseded {
                continue 'projection;
            }
            for (introduction_id, expected_receipt) in commit
                .fenced_introductions
                .iter()
                .zip(&commit.ors_introduction_receipts)
            {
                let subject =
                    OperationIdentity::new(introduction_id).map_err(KernelError::RecoveryState)?;
                let row = boundary
                    .store
                    .load_capability_introduction(&subject)
                    .map_err(|error| map_ors_recovery_error(&error))?
                    .ok_or_else(|| {
                        KernelError::RecoveryUnavailable(
                            "fenced introduction row is absent during rehydration".to_owned(),
                        )
                    })?;
                if row.phase() != OperationalPhase::Fenced
                    || row.receipt().record_id().as_str() != expected_receipt.record_id
                    || row.receipt().subject_id().as_str() != expected_receipt.subject_id
                    || row.receipt().operation_order() != expected_receipt.operation_order
                    || row.receipt().state_sha256() != expected_receipt.state_sha256
                {
                    return Err(KernelError::RecoveryUnavailable(
                        "fenced introduction receipt disagrees during rehydration".to_owned(),
                    ));
                }
            }
            if commit.state == GrantClosureState::Active {
                let member_receipts = commit
                    .ors_member_receipts
                    .iter()
                    .map(|reference| AuthorityActivationReceipt {
                        activation_id: reference.record_id.clone(),
                        snapshot_id: commit.authority_receipt.snapshot_id.clone(),
                        authority_epoch: commit.authority_receipt.authority_epoch.clone(),
                        state: AuthorityState::Active,
                    })
                    .collect::<Vec<_>>();
                let first = member_receipts.first().cloned().ok_or_else(|| {
                    KernelError::RecoveryUnavailable(
                        "active closure receipt has no member activation receipt".to_owned(),
                    )
                })?;
                first.validate()?;
                active_recovered.push((commit.clone(), first, member_receipts));
            }
            if commit.state == GrantClosureState::Revoked {
                covered.extend(
                    commit
                        .declaration
                        .members
                        .iter()
                        .map(|member| member.grant_id.clone()),
                );
                let receipt = AuthorityRevocationReceipt {
                    revocation_id: commit.authority_receipt.receipt_id.clone(),
                    snapshot_id: commit.authority_receipt.snapshot_id.clone(),
                    authority_epoch: commit.authority_receipt.authority_epoch.clone(),
                    state: AuthorityState::Revoked,
                };
                receipt.validate()?;
                recovered.push((commit, receipt));
            }
        }
        for hydration in boundary
            .hydration
            .admitted_grant_hydrations()
            .map_err(|error| KernelError::RecoveryUnavailable(error.to_string()))?
        {
            let subject = OperationIdentity::new(&hydration.intent.grant_id)
                .map_err(KernelError::RecoveryState)?;
            let Some(row) = boundary
                .store
                .load_capability_grant(&subject)
                .map_err(|error| map_ors_recovery_error(&error))?
            else {
                if hydration.intent.parent_grant_id.is_some() {
                    return Err(KernelError::RecoveryUnavailable(
                        "delegated grant has no durable activation or closure receipt".to_owned(),
                    ));
                }
                let digest = hydrated_grant_member_digest(&hydration)
                    .map_err(|error| KernelError::RecoveryUnavailable(error.to_string()))?;
                candidate.pending_activations.insert(
                    hydration.intent.operation_id.clone(),
                    PendingActivation {
                        operation_id: hydration.intent.operation_id.clone(),
                        digest,
                        intent: hydration.intent.clone(),
                        durable_record: hydration.durable_record.clone(),
                    },
                );
                continue;
            };
            let is_revoked = covered.contains(&hydration.intent.grant_id);
            let status = match row.phase() {
                OperationalPhase::Active if !is_revoked => LiveStatus::Active,
                OperationalPhase::Applying if !is_revoked => {
                    if hydration.intent.parent_grant_id.is_some() {
                        return Err(KernelError::RecoveryUnavailable(
                            "delegated Applying grant has no committed closure receipt".to_owned(),
                        ));
                    }
                    let digest = hydrated_grant_member_digest(&hydration)
                        .map_err(|error| KernelError::RecoveryUnavailable(error.to_string()))?;
                    candidate.pending_activations.insert(
                        hydration.intent.operation_id.clone(),
                        PendingActivation {
                            operation_id: hydration.intent.operation_id.clone(),
                            digest,
                            intent: hydration.intent.clone(),
                            durable_record: hydration.durable_record.clone(),
                        },
                    );
                    continue;
                }
                OperationalPhase::Fenced if is_revoked => LiveStatus::Revoked,
                _ => {
                    return Err(KernelError::RecoveryUnavailable(
                        "owner-admitted grant phase disagrees with durable closure coverage"
                            .to_owned(),
                    ));
                }
            };
            candidate.grants.insert(
                hydration.intent.grant_id.clone(),
                LiveGrantRecord {
                    authority_root_ref: hydration.intent.authority_root_ref.clone(),
                    binding: hydration.intent.binding.clone(),
                    allowed_effect: hydration.intent.allowed_effect,
                    proof_ceiling: hydration.intent.proof_ceiling,
                    expires_at_ms: hydration.intent.expires_at_ms,
                    status,
                },
            );
        }
        for hydration in boundary
            .hydration
            .admitted_introductions()
            .map_err(|error| KernelError::RecoveryUnavailable(error.to_string()))?
        {
            let subject = OperationIdentity::new(&hydration.intent.introduction_id)
                .map_err(KernelError::RecoveryState)?;
            let row = boundary
                .store
                .load_capability_introduction(&subject)
                .map_err(|error| map_ors_recovery_error(&error))?
                .ok_or_else(|| {
                    KernelError::RecoveryUnavailable(
                        "owner-admitted introduction has no durable projection".to_owned(),
                    )
                })?;
            let support_revoked = hydration
                .intent
                .supporting_grant_ids
                .iter()
                .any(|grant_id| covered.contains(grant_id));
            let status = match row.phase() {
                OperationalPhase::Active if !support_revoked => LiveStatus::Active,
                OperationalPhase::Applying if !support_revoked => continue,
                OperationalPhase::Fenced if support_revoked => LiveStatus::Revoked,
                _ => {
                    return Err(KernelError::RecoveryUnavailable(
                        "owner-admitted introduction phase disagrees with durable closure coverage"
                            .to_owned(),
                    ));
                }
            };
            candidate.introductions.insert(
                hydration.intent.introduction_id.clone(),
                LiveIntroductionRecord {
                    authority_root_ref: hydration.intent.authority_root_ref.clone(),
                    supporting_grant_ids: hydration
                        .intent
                        .supporting_grant_ids
                        .iter()
                        .cloned()
                        .collect(),
                    status,
                },
            );
            if status == LiveStatus::Active {
                // Post-restart exact replay (#2100 R4): the live install
                // alone would make an exact replay resolve as `New` and
                // refuse as an already-recorded identity. Restore the same
                // activation intent record the commit path installed,
                // derived from the same owner-presented inputs: the replay
                // digest over intent plus opaque bytes, and the activation
                // receipt over the operation identity, snapshot, and the
                // binding epoch the commit gate proved equal to the active
                // epoch. The replay branch still re-reads the row,
                // re-enumerates the complete closure introduction-fence set,
                // and re-checks the watermark read-only before returning it.
                let digest = hydrated_introduction_digest(&hydration)?;
                let receipt = runtime_introduction_activation_receipt(
                    &hydration.intent,
                    &hydration.intent.binding.authority_epoch,
                )?;
                let operation_id = hydration.intent.operation_id.clone();
                if let Some(existing) = candidate.intents.get(&operation_id) {
                    let same = existing.digest == digest
                        && existing.kind == IntentKind::IntroductionActivation
                        && existing.disposition
                            == IntentDisposition::Committed(CommittedReceipt::Activation(
                                receipt.clone(),
                            ));
                    if !same {
                        return Err(KernelError::IdempotencyConflict);
                    }
                } else {
                    candidate.intents.insert(
                        operation_id.clone(),
                        PortIntentRecord {
                            operation_id,
                            digest,
                            kind: IntentKind::IntroductionActivation,
                            disposition: IntentDisposition::Committed(
                                CommittedReceipt::Activation(receipt),
                            ),
                            fenced: Vec::new(),
                            closure_receipt: None,
                            closure_member_receipts: Vec::new(),
                        },
                    );
                }
            }
        }
        if !required.is_subset(&covered) {
            return Err(KernelError::RecoveryUnavailable(
                "owner reports revoked grants without a complete durable closure receipt"
                    .to_owned(),
            ));
        }
        for (commit, first, member_receipts) in active_recovered {
            if let Some(existing) = candidate.intents.get(&commit.operation_id) {
                if existing.closure_receipt.as_ref() != Some(&commit)
                    || existing.digest != commit.idempotency_digest
                    || existing.disposition
                        != IntentDisposition::Committed(CommittedReceipt::Activation(first.clone()))
                {
                    return Err(KernelError::IdempotencyConflict);
                }
                continue;
            }
            candidate.note_revision(
                &commit.declaration.authority_root_ref,
                commit.declaration.grant_graph_revision,
            );
            candidate.intents.insert(
                commit.operation_id.clone(),
                PortIntentRecord {
                    operation_id: commit.operation_id.clone(),
                    digest: commit.idempotency_digest.clone(),
                    kind: IntentKind::GrantActivation,
                    disposition: IntentDisposition::Committed(CommittedReceipt::Activation(first)),
                    fenced: Vec::new(),
                    closure_receipt: Some(commit.clone()),
                    closure_member_receipts: member_receipts,
                },
            );
            candidate.closure_targets.insert(
                commit.declaration.target_grant_id.clone(),
                commit.operation_id.clone(),
            );
        }
        for (commit, receipt) in recovered {
            if let Some(existing) = candidate.intents.get(&commit.operation_id) {
                if existing.closure_receipt.as_ref() != Some(&commit)
                    || existing.digest != commit.idempotency_digest
                    || existing.disposition
                        != IntentDisposition::Committed(CommittedReceipt::Revocation(
                            receipt.clone(),
                        ))
                {
                    return Err(KernelError::IdempotencyConflict);
                }
                continue;
            }
            let fenced = commit
                .declaration
                .members
                .iter()
                .map(|member| member.grant_id.clone())
                .collect::<Vec<_>>();
            for grant_id in &fenced {
                let historical = boundary
                    .hydration
                    .historical_grant_hydration(grant_id)
                    .map_err(|error| {
                        KernelError::RecoveryUnavailable(format!(
                            "revoked closure member historical hydration read failed: {error}"
                        ))
                    })?;
                let (authority_root_ref, binding, allowed_effect, proof_ceiling, expires_at_ms) =
                    if let Some(hydration) = historical {
                        (
                            hydration.intent.authority_root_ref,
                            hydration.intent.binding,
                            hydration.intent.allowed_effect,
                            hydration.intent.proof_ceiling,
                            hydration.intent.expires_at_ms,
                        )
                    } else {
                        if !commit
                            .declaration
                            .members
                            .iter()
                            .any(|member| &member.grant_id == grant_id)
                        {
                            return Err(KernelError::RecoveryUnavailable(
                                "revoked closure member is absent from its declaration".to_owned(),
                            ));
                        }
                        (
                            commit.declaration.authority_root_ref.clone(),
                            commit.authority.clone(),
                            commit.authority.allowed_effect,
                            commit.authority.proof_ceiling,
                            None,
                        )
                    };
                candidate.grants.insert(
                    grant_id.clone(),
                    LiveGrantRecord {
                        authority_root_ref,
                        binding,
                        allowed_effect,
                        proof_ceiling,
                        expires_at_ms,
                        status: LiveStatus::Revoked,
                    },
                );
            }
            for introduction_id in &commit.fenced_introductions {
                candidate.introductions.insert(
                    introduction_id.clone(),
                    LiveIntroductionRecord {
                        authority_root_ref: commit.declaration.authority_root_ref.clone(),
                        supporting_grant_ids: BTreeSet::new(),
                        status: LiveStatus::Revoked,
                    },
                );
            }
            candidate.note_revision(
                &commit.declaration.authority_root_ref,
                commit.declaration.grant_graph_revision,
            );
            candidate.intents.insert(
                commit.operation_id.clone(),
                PortIntentRecord {
                    operation_id: commit.operation_id.clone(),
                    digest: commit.idempotency_digest.clone(),
                    kind: IntentKind::GrantRevocation,
                    disposition: IntentDisposition::Committed(CommittedReceipt::Revocation(
                        receipt,
                    )),
                    fenced,
                    closure_receipt: Some(commit.clone()),
                    closure_member_receipts: Vec::new(),
                },
            );
            candidate.closure_targets.insert(
                commit.declaration.target_grant_id.clone(),
                commit.operation_id.clone(),
            );
        }
        for commit in &closure_commits {
            if commit.declaration.preserved.is_empty() {
                continue;
            }
            let affected = commit
                .declaration
                .members
                .iter()
                .map(|member| member.grant_id.as_str())
                .collect::<BTreeSet<_>>();
            let request = GrantClosureRevocationIntent {
                operation_id: commit.operation_id.clone(),
                grant_id: commit.declaration.target_grant_id.clone(),
                authority_root_ref: commit.declaration.authority_root_ref.clone(),
                snapshot_id: commit.authority_receipt.snapshot_id.clone(),
                grant_graph_revision: commit.declaration.grant_graph_revision,
                binding: commit.authority.clone(),
                unknown_outcome_operations: Vec::new(),
                receipt_obligations: Vec::new(),
            };
            for survivor in &commit.declaration.preserved {
                prove_survivor_membership(
                    &candidate,
                    boundary,
                    &commit.authority.authority_epoch,
                    &request,
                    &affected,
                    survivor,
                )?;
            }
        }
        *ledger = candidate;
        Ok(())
    }

    /// This is the restart-rehydration companion of [`Self::closure_receipt`]:
    /// after [`Self::recover_grant_closure_activation`] or
    /// [`Self::recover_grant_closure_revocation`] reinstalls the committed
    /// closure, the receipt is reachable by target identity without holding
    /// the closure operation identity.
    #[must_use]
    pub fn closure_receipt_for_target(&self, grant_id: &str) -> Option<GrantClosureReceipt> {
        let ledger = self.lock_ledger();
        let operation_id = ledger.closure_targets.get(grant_id)?;
        ledger
            .intents
            .get(operation_id)
            .and_then(|record| record.closure_receipt.clone())
    }

    /// Returns the sorted introduction identities fenced by one closure
    /// revocation, if any.
    ///
    /// The list is committed in the durable closure row and reinstalled on
    /// restart, so a fenced introduction never reads as usable again even
    /// though its supporting set is only recorded live at fence time.
    /// Returns `None` for an unknown operation identity and for operations
    /// that are not closure revocations.
    #[must_use]
    pub fn revocation_introductions(&self, operation_id: &str) -> Option<Vec<String>> {
        self.closure_receipt(operation_id)
            .map(|receipt| receipt.fenced_introductions)
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
        let boundary = self.durable_boundary().ok_or_else(|| {
            KernelError::RecoveryUnavailable("root-grant boundary is not bound".to_owned())
        })?;
        validate_id(grant_id, "grant_id")?;
        let subject_id = OperationIdentity::new(grant_id).map_err(KernelError::RecoveryState)?;
        let projection = boundary
            .store
            .load_capability_grant(&subject_id)
            .map_err(KernelError::RecoveryState)?
            .ok_or_else(|| {
                KernelError::RecoveryUnavailable("root-grant projection is absent".to_owned())
            })?;
        if !matches!(
            projection.phase(),
            OperationalPhase::Applying | OperationalPhase::Active
        ) {
            return Err(KernelError::RecoveryUnavailable(
                "root-grant projection is not pending or active".to_owned(),
            ));
        }
        let hydration = boundary.hydration.rehydrate_root_grant(&projection)?;
        validate_rehydrated_root_grant(&hydration, &projection, active_epoch)?;
        if hydration.intent.grant_id != grant_id {
            return Err(KernelError::RecoveryUnavailable(
                "rehydrated root-grant identity disagrees with ORS".to_owned(),
            ));
        }

        // APPLYING is the durable pending state and ACTIVE is the durable
        // committed-but-installable state.  Presenting the exact record to
        // ORS on every restart makes both states deterministic: APPLYING is
        // promoted to ACTIVE, while ACTIVE is an exact receipt replay.  The
        // live ledger is populated only after this fresh ORS read-back.
        let durable_receipt = boundary
            .store
            .activate_capability_grant(hydration.durable_record.clone())
            .map_err(|error| map_ors_recovery_error(&error))?;
        let projection = boundary
            .store
            .load_capability_grant(&subject_id)
            .map_err(|error| map_ors_recovery_error(&error))?
            .ok_or_else(|| {
                KernelError::RecoveryUnavailable(
                    "root-grant projection disappeared during recovery".to_owned(),
                )
            })?;
        if projection.phase() != OperationalPhase::Active
            || projection.record() != hydration.durable_record.record()
            || projection.receipt() != durable_receipt.receipt()
        {
            return Err(KernelError::RecoveryUnavailable(
                "root-grant recovery ORS receipt/read-back disagreed".to_owned(),
            ));
        }
        validate_rehydrated_root_grant(&hydration, &projection, active_epoch)?;

        let mut ledger = self.lock_ledger();
        let digest = hydrated_root_grant_digest(&hydration)?;
        match ledger.resolve(&hydration.intent.operation_id, &digest) {
            IntentResolve::Conflict => return Err(KernelError::IdempotencyConflict),
            IntentResolve::Replay(disposition) => {
                return disposition.into_activation_receipt();
            }
            IntentResolve::New => {}
        }
        validate_grant_activation(&hydration.intent, &ledger, active_epoch, now_ms)?;
        // Durable revision gate (`#2100`): recovery re-presents a superseded
        // revision only through a current owner enumeration, never by replaying
        // an older one after the watermark moved.
        check_closure_watermark(
            boundary,
            &hydration.intent.authority_root_ref,
            hydration.intent.grant_graph_revision,
        )?;
        let receipt = runtime_activation_receipt(&hydration.intent, active_epoch)?;
        install_root_activation(&mut ledger, &hydration.intent, &receipt, digest);
        Ok(receipt)
    }

    /// Activates one owner-enumerated grant closure and returns one receipt
    /// per member in enumeration order.
    ///
    /// The presented enumeration must equal the injected Governor owner's
    /// enumeration for the closure root: the owner attests the exact closure
    /// the durable graph admitted, and caller material alone never commits.
    /// Every member is validated (identities, exact shared revision, binding,
    /// fence, epoch, ceilings, expiry, opaque record agreement,
    /// parent-before-child order) before any mutation; a `Fenced` or
    /// `Released` durable row refuses, because restore never reactivates a
    /// path. Each member then follows the single-root durable gate (ORS
    /// commit, exact read-back), the per-root revision watermark advances
    /// atomically with the stale check, and one closure row binds the
    /// operation, revision, digest, and receipt before live installation.
    /// Exact replay under one operation identity returns the same receipts;
    /// a changed payload under one identity, a stale revision, or a
    /// duplicate grant identity fails before any mutation.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::IdempotencyConflict`] for a changed payload,
    /// [`KernelError::FenceMismatch`] for a stale, future or cross-lineage
    /// epoch or fence, [`KernelError::Expired`] for an expired member, and
    /// [`KernelError::InvalidField`] or [`KernelError::RecoveryUnavailable`]
    /// for any other invalid, incomplete, or disagreeing enumeration value.
    #[allow(
        clippy::too_many_lines,
        reason = "the closure activation gate keeps per-member validation, ORS commit, read-back, and install together"
    )]
    pub fn activate_grant_closure(
        &self,
        request: &GrantClosureActivationIntent,
        active_epoch: &EpochId,
    ) -> Result<Vec<AuthorityActivationReceipt>, KernelError> {
        let boundary = self.durable_boundary().ok_or_else(|| {
            KernelError::RecoveryUnavailable(
                "grant-closure activation needs the durable root-grant boundary".to_owned(),
            )
        })?;
        validate_id(&request.operation_id, "operation_id")?;
        validate_closure_enumeration(&request.enumeration, active_epoch)?;
        if !request.enumeration.preserved.is_empty() {
            return Err(KernelError::InvalidField {
                field: "enumeration.preserved",
                reason: "an activation closure fences nothing to survive",
            });
        }
        let digest = closure_activation_digest(&request.operation_id, &request.enumeration)?;

        let mut ledger = self.lock_ledger();
        match ledger.resolve(&request.operation_id, &digest) {
            IntentResolve::Conflict => return Err(KernelError::IdempotencyConflict),
            IntentResolve::Replay(_) => {
                let record = ledger.intents.get(&request.operation_id).ok_or_else(|| {
                    KernelError::RecoveryUnavailable(
                        "closure activation intent disappeared during replay".to_owned(),
                    )
                })?;
                if record.closure_member_receipts.is_empty() {
                    return Err(KernelError::IdempotencyConflict);
                }
                return Ok(record.closure_member_receipts.clone());
            }
            IntentResolve::New => {}
        }
        // Owner attestation, after the idempotency gate so a changed payload
        // under one identity keeps its typed conflict: the presented closure
        // must equal the Governor enumeration for the closure root.
        // Structural checks reject malformed material, but only the owner
        // proves the durable graph selected this exact closure at this
        // revision. A caller that can present acceptable ORS inputs cannot
        // drive an activation the owner never admitted. Exact replay returns
        // above without re-fetching: the owner attested the same bytes at
        // first commit.
        let closure_anchor = closure_anchor_grant(&request.enumeration)?;
        let owner_enumeration = boundary
            .hydration
            .enumerate_grant_closure(&closure_anchor)?;
        validate_closure_enumeration(&owner_enumeration, active_epoch).map_err(|_| {
            KernelError::RecoveryUnavailable(
                "closure owner enumeration failed validation".to_owned(),
            )
        })?;
        if owner_enumeration != request.enumeration {
            return Err(KernelError::InvalidField {
                field: "enumeration",
                reason: "the presented closure disagrees with the owner enumeration",
            });
        }
        check_revision(
            &ledger,
            &request.enumeration.authority_root_ref,
            request.enumeration.grant_graph_revision,
        )?;
        validate_closure_activation_members(
            &request.enumeration,
            &ledger,
            Some(boundary),
            active_epoch,
        )?;
        // Restore never reactivates: a `Fenced` or `Released` durable row
        // refuses before any mutation, and any other existing row must carry
        // the exact presented input.
        for member in &request.enumeration.members {
            match check_activation_row(
                boundary,
                &member.intent.grant_id,
                member.durable_record.record(),
            )? {
                ActivationRow::Fenced => {
                    return Err(KernelError::InvalidField {
                        field: "grant_id",
                        reason: "grant identity is fenced; restore never reactivates a path",
                    });
                }
                ActivationRow::Absent | ActivationRow::Active | ActivationRow::Applying => {}
            }
        }
        // Durable revision gate: the watermark advance is atomic with the
        // stale check, so a re-presented revision after a crash proceeds
        // while any lower revision fails closed even across restarts.
        check_closure_watermark(
            boundary,
            &request.enumeration.authority_root_ref,
            request.enumeration.grant_graph_revision,
        )?;

        // Durable linearization, member by member in parent-before-child
        // order: each ORS commit is atomic with an exact read-back, and a
        // crash between members is recovered by exact re-presentation (an
        // already-Active member replays its receipt; an Applying member is
        // promoted; nothing is installed live until every read-back agrees).
        // No ledger mutation happens above this point.
        let mut read_back: Vec<CapabilityGrantProjection> = Vec::new();
        for member in &request.enumeration.members {
            let durable_receipt = boundary
                .store
                .activate_capability_grant(member.durable_record.clone())
                .map_err(|error| map_ors_recovery_error(&error))?;
            let subject = OperationIdentity::new(&member.intent.grant_id)
                .map_err(KernelError::RecoveryState)?;
            let projection = boundary
                .store
                .load_capability_grant(&subject)
                .map_err(|error| map_ors_recovery_error(&error))?
                .ok_or_else(|| {
                    KernelError::RecoveryUnavailable(
                        "closure member projection disappeared during activation".to_owned(),
                    )
                })?;
            if projection.phase() != OperationalPhase::Active
                || projection.record() != member.durable_record.record()
                || projection.receipt() != durable_receipt.receipt()
            {
                return Err(KernelError::RecoveryUnavailable(
                    "closure member activation ORS receipt/read-back disagreed".to_owned(),
                ));
            }
            read_back.push(projection);
        }
        debug_assert_eq!(read_back.len(), request.enumeration.members.len());
        let receipts = request
            .enumeration
            .members
            .iter()
            .map(|member| runtime_activation_receipt(&member.intent, active_epoch))
            .collect::<Result<Vec<_>, _>>()?;
        let first = receipts.first().cloned().ok_or_else(|| {
            KernelError::RecoveryUnavailable(
                "closure enumeration lost its receipts during activation".to_owned(),
            )
        })?;
        let declaration = closure_declaration_from_enumeration(&request.enumeration)?;
        let ors_member_receipts = read_back
            .iter()
            .map(|projection| GrantClosureOrsReceiptRef {
                record_id: projection.receipt().record_id().as_str().to_owned(),
                subject_id: projection.receipt().subject_id().as_str().to_owned(),
                operation_order: projection.receipt().operation_order(),
                state: GrantClosureState::Active,
                state_sha256: projection.receipt().state_sha256().to_owned(),
            })
            .collect();
        let authority = request
            .enumeration
            .members
            .first()
            .map(|member| member.intent.binding.clone())
            .ok_or_else(|| {
                KernelError::RecoveryUnavailable(
                    "closure activation has no authority binding".to_owned(),
                )
            })?;
        let closure_receipt = GrantClosureReceipt {
            schema: GRANT_CLOSURE_SCHEMA.to_owned(),
            version: GRANT_CLOSURE_VERSION,
            operation_id: request.operation_id.clone(),
            idempotency_digest: digest.clone(),
            declaration,
            authority,
            proof_ceiling: closure_proof_ceiling(&request.enumeration),
            authority_receipt: GrantClosureAuthorityReceiptRef {
                receipt_id: format!("activation-{}", request.operation_id),
                snapshot_id: first.snapshot_id.clone(),
                authority_epoch: first.authority_epoch.clone(),
                state: GrantClosureState::Active,
            },
            ors_member_receipts,
            fenced_introductions: Vec::new(),
            ors_introduction_receipts: Vec::new(),
            canonical_receipt: None,
            state: GrantClosureState::Active,
        };
        closure_receipt
            .validate()
            .map_err(|error| KernelError::RecoveryUnavailable(error.to_string()))?;
        let stored_closure = ensure_closure_row(boundary, &closure_receipt)?;
        if stored_closure != closure_receipt {
            return Err(KernelError::RecoveryUnavailable(
                "activation closure commit/read-back disagrees".to_owned(),
            ));
        }
        for member in &request.enumeration.members {
            ledger.grants.insert(
                member.intent.grant_id.clone(),
                LiveGrantRecord {
                    authority_root_ref: member.intent.authority_root_ref.clone(),
                    binding: member.intent.binding.clone(),
                    allowed_effect: member.intent.allowed_effect,
                    proof_ceiling: member.intent.proof_ceiling,
                    expires_at_ms: member.intent.expires_at_ms,
                    status: LiveStatus::Active,
                },
            );
        }
        ledger.note_revision(
            &request.enumeration.authority_root_ref,
            request.enumeration.grant_graph_revision,
        );
        ledger.intents.insert(
            request.operation_id.clone(),
            PortIntentRecord {
                operation_id: request.operation_id.clone(),
                digest,
                kind: IntentKind::GrantActivation,
                disposition: IntentDisposition::Committed(CommittedReceipt::Activation(first)),
                fenced: Vec::new(),
                closure_receipt: Some(closure_receipt),
                closure_member_receipts: receipts.clone(),
            },
        );
        ledger
            .closure_targets
            .insert(closure_anchor, request.operation_id.clone());
        Ok(receipts)
    }

    /// Revokes one owner-enumerated grant closure and returns its durable
    /// closure receipt.
    ///
    /// The fence set is derived from the live lineage plus the injected
    /// Governor enumeration, which must agree exactly: every recorded live
    /// descendant of the target is either fenced or owner-declared preserved,
    /// and every fenced member carries a durable ORS row. Each unfenced
    /// member follows the single-root durable fence gate (ORS `Active`-to-
    /// `Fenced` compare-and-swap with exact read-back); a member already
    /// fenced under a previous closure with identical authority bytes is
    /// reconfirmed, never recommitted, so a fresh operation identity
    /// re-confirms the fence. The durable revision watermark advances
    /// atomically with the stale check, and one closure row binds the
    /// operation, revision, digest, affected set, survivors, and receipt
    /// before anything is installed live. Dependent introductions are fenced
    /// live. Exact replay returns the same receipt; a changed payload under
    /// one identity or a stale revision fails before any mutation.
    ///
    /// Without the durable boundary this stays ledger-only: the fence set is
    /// the recorded live descendant closure and no alternate-path survivor
    /// can be declared, because no Governor owner is bound to attest it.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::IdempotencyConflict`] for a changed payload,
    /// [`KernelError::FenceMismatch`] for a stale, future or cross-lineage
    /// epoch or fence, and [`KernelError::InvalidField`] or
    /// [`KernelError::RecoveryUnavailable`] for an unknown target, an
    /// incomplete enumeration, a missing or disagreeing durable row, or any
    /// other invalid value.
    pub fn revoke_grant_closure(
        &self,
        request: &GrantClosureRevocationIntent,
        active_epoch: &EpochId,
    ) -> Result<GrantClosureReceipt, KernelError> {
        let boundary = self.durable_boundary();
        let owner_enumeration = boundary
            .map(|boundary| {
                validate_id(&request.grant_id, "grant_id")?;
                boundary
                    .hydration
                    .enumerate_grant_closure(&request.grant_id)
            })
            .transpose()?;
        self.revoke_closure_core(request, active_epoch, boundary, owner_enumeration.as_ref())
    }

    /// Rehydrates one committed activation closure after a restart.
    ///
    /// The caller re-presents the closure intent; the port re-enumerates
    /// through the injected Governor owner and requires the owner
    /// enumeration to equal the presented one, every member ORS row to agree
    /// with its enumerated input (`Applying` rows are promoted through the
    /// exact pending-to-active transition; `Fenced` rows refuse, because
    /// recovery never resurrects revoked authority), and every member gate
    /// to hold at the observation time. The durable revision watermark and
    /// the closure row are re-verified (or completed when the crash landed
    /// between the member commits and the closure commit) before live state
    /// plus the original disposition is installed. A missing, incomplete, or
    /// disagreeing row stays fail-closed and admits nothing.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::activate_grant_closure`], with
    /// [`KernelError::RecoveryUnavailable`] naming the exact rehydration
    /// disagreement.
    #[allow(
        clippy::too_many_lines,
        reason = "the closure recovery gate keeps re-enumeration, ORS agreement, validation, and install together"
    )]
    pub fn recover_grant_closure_activation(
        &self,
        request: &GrantClosureActivationIntent,
        active_epoch: &EpochId,
        now_ms: i64,
    ) -> Result<Vec<AuthorityActivationReceipt>, KernelError> {
        let boundary = self.durable_boundary().ok_or_else(|| {
            KernelError::RecoveryUnavailable(
                "grant-closure recovery needs the durable root-grant boundary".to_owned(),
            )
        })?;
        validate_id(&request.operation_id, "operation_id")?;
        validate_closure_enumeration(&request.enumeration, active_epoch)?;
        if !request.enumeration.preserved.is_empty() {
            return Err(KernelError::InvalidField {
                field: "enumeration.preserved",
                reason: "an activation closure fences nothing to survive",
            });
        }
        let digest = closure_activation_digest(&request.operation_id, &request.enumeration)?;

        let mut ledger = self.lock_ledger();
        match ledger.resolve(&request.operation_id, &digest) {
            IntentResolve::Conflict => return Err(KernelError::IdempotencyConflict),
            IntentResolve::Replay(_) => {
                let record = ledger.intents.get(&request.operation_id).ok_or_else(|| {
                    KernelError::RecoveryUnavailable(
                        "closure activation intent disappeared during recovery".to_owned(),
                    )
                })?;
                if record.closure_member_receipts.is_empty() {
                    return Err(KernelError::IdempotencyConflict);
                }
                return Ok(record.closure_member_receipts.clone());
            }
            IntentResolve::New => {}
        }
        // Owner attestation after the idempotency gate, mirroring activation:
        // the re-presented closure must equal the current owner enumeration.
        let closure_anchor = closure_anchor_grant(&request.enumeration)?;
        let owner_enumeration = boundary
            .hydration
            .enumerate_grant_closure(&closure_anchor)?;
        validate_closure_enumeration(&owner_enumeration, active_epoch).map_err(|_| {
            KernelError::RecoveryUnavailable(
                "closure owner enumeration failed validation".to_owned(),
            )
        })?;
        if owner_enumeration != request.enumeration {
            return Err(KernelError::InvalidField {
                field: "enumeration",
                reason: "the presented closure disagrees with the owner enumeration",
            });
        }
        // I12.20 revocation fan-out (issue #1732): propagate durable
        // revocation into recovery before any durable write. The re-presented
        // affected set must carry no revoked support: the live revoked
        // fan-out over the explicit closure — the shared
        // `revoked_support_closure` traversal on the held ledger, so no graph
        // logic is duplicated and no re-lock can deadlock — is removed from
        // the reinstall set by refusing here. This runs ahead of the member
        // row loop below, which would otherwise promote an `Applying` row for
        // revoked support before the activation validators see it. Recovery
        // never reactivates a path.
        let affected = closure_affected_set(&request.enumeration);
        if !revoked_support_in_ledger(&ledger, &affected).is_empty() {
            return Err(KernelError::RecoveryUnavailable(
                "closure carries revoked support; recovery never reactivates a path".to_owned(),
            ));
        }
        // Every member row must agree with its enumerated input. An
        // `Applying` row is promoted through the exact pending-to-active
        // transition (the declared crash protocol); a `Fenced` or `Released`
        // row refuses, because recovery must never resurrect revoked
        // authority; any other phase or absence stays fail-closed.
        for member in &request.enumeration.members {
            match check_activation_row(
                boundary,
                &member.intent.grant_id,
                member.durable_record.record(),
            )? {
                ActivationRow::Absent => {
                    return Err(KernelError::RecoveryUnavailable(
                        "closure member projection is absent during recovery".to_owned(),
                    ));
                }
                ActivationRow::Fenced => {
                    return Err(KernelError::RecoveryUnavailable(
                        "closure member is fenced; recovery never reactivates a path".to_owned(),
                    ));
                }
                ActivationRow::Active => {}
                ActivationRow::Applying => {
                    let durable_receipt = boundary
                        .store
                        .activate_capability_grant(member.durable_record.clone())
                        .map_err(|error| map_ors_recovery_error(&error))?;
                    let subject = OperationIdentity::new(&member.intent.grant_id)
                        .map_err(KernelError::RecoveryState)?;
                    let projection = boundary
                        .store
                        .load_capability_grant(&subject)
                        .map_err(|error| map_ors_recovery_error(&error))?
                        .ok_or_else(|| {
                            KernelError::RecoveryUnavailable(
                                "closure member projection disappeared during recovery".to_owned(),
                            )
                        })?;
                    if projection.phase() != OperationalPhase::Active
                        || projection.record() != member.durable_record.record()
                        || projection.receipt() != durable_receipt.receipt()
                    {
                        return Err(KernelError::RecoveryUnavailable(
                            "closure member recovery ORS receipt/read-back disagreed".to_owned(),
                        ));
                    }
                }
            }
        }

        check_revision(
            &ledger,
            &request.enumeration.authority_root_ref,
            request.enumeration.grant_graph_revision,
        )?;
        validate_closure_activation_members(
            &request.enumeration,
            &ledger,
            Some(boundary),
            active_epoch,
        )?;
        // Member expiry is checked at the recovery observation time, exactly
        // like the single-root recovery path: a member expired at `now_ms`
        // cannot be reinstalled as live authority.
        for member in &request.enumeration.members {
            check_expiry(
                member.intent.issued_at_ms,
                member.intent.expires_at_ms,
                now_ms,
            )?;
        }
        check_closure_watermark(
            boundary,
            &request.enumeration.authority_root_ref,
            request.enumeration.grant_graph_revision,
        )?;
        let receipts = request
            .enumeration
            .members
            .iter()
            .map(|member| runtime_activation_receipt(&member.intent, active_epoch))
            .collect::<Result<Vec<_>, _>>()?;
        let first = receipts.first().cloned().ok_or_else(|| {
            KernelError::RecoveryUnavailable(
                "closure enumeration lost its receipts during recovery".to_owned(),
            )
        })?;
        let read_back = request
            .enumeration
            .members
            .iter()
            .map(|member| {
                let subject = OperationIdentity::new(&member.intent.grant_id)
                    .map_err(KernelError::RecoveryState)?;
                boundary
                    .store
                    .load_capability_grant(&subject)
                    .map_err(|error| map_ors_recovery_error(&error))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .enumerate()
            .map(|(index, projection)| {
                let member = &request.enumeration.members[index];
                projection
                    .ok_or_else(|| {
                        KernelError::RecoveryUnavailable(
                            "closure member projection is absent during recovery".to_owned(),
                        )
                    })
                    .and_then(|projection| {
                        if projection.phase() == OperationalPhase::Active
                            && projection.record() == member.durable_record.record()
                        {
                            Ok(projection)
                        } else {
                            Err(KernelError::RecoveryUnavailable(
                                "closure member recovery projection is not exact active state"
                                    .to_owned(),
                            ))
                        }
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let declaration = closure_declaration_from_enumeration(&request.enumeration)?;
        let authority = request
            .enumeration
            .members
            .first()
            .map(|member| member.intent.binding.clone())
            .ok_or_else(|| {
                KernelError::RecoveryUnavailable(
                    "closure recovery has no authority binding".to_owned(),
                )
            })?;
        let closure_receipt = GrantClosureReceipt {
            schema: GRANT_CLOSURE_SCHEMA.to_owned(),
            version: GRANT_CLOSURE_VERSION,
            operation_id: request.operation_id.clone(),
            idempotency_digest: digest.clone(),
            declaration,
            authority,
            proof_ceiling: closure_proof_ceiling(&request.enumeration),
            authority_receipt: GrantClosureAuthorityReceiptRef {
                receipt_id: format!("activation-{}", request.operation_id),
                snapshot_id: first.snapshot_id.clone(),
                authority_epoch: first.authority_epoch.clone(),
                state: GrantClosureState::Active,
            },
            ors_member_receipts: read_back
                .iter()
                .map(|projection| GrantClosureOrsReceiptRef {
                    record_id: projection.receipt().record_id().as_str().to_owned(),
                    subject_id: projection.receipt().subject_id().as_str().to_owned(),
                    operation_order: projection.receipt().operation_order(),
                    state: GrantClosureState::Active,
                    state_sha256: projection.receipt().state_sha256().to_owned(),
                })
                .collect(),
            fenced_introductions: Vec::new(),
            ors_introduction_receipts: Vec::new(),
            canonical_receipt: None,
            state: GrantClosureState::Active,
        };
        closure_receipt
            .validate()
            .map_err(|error| KernelError::RecoveryUnavailable(error.to_string()))?;
        let stored_closure = ensure_closure_row(boundary, &closure_receipt)?;
        if stored_closure != closure_receipt {
            return Err(KernelError::RecoveryUnavailable(
                "recovered activation closure commit/read-back disagrees".to_owned(),
            ));
        }
        for member in &request.enumeration.members {
            ledger.grants.insert(
                member.intent.grant_id.clone(),
                LiveGrantRecord {
                    authority_root_ref: member.intent.authority_root_ref.clone(),
                    binding: member.intent.binding.clone(),
                    allowed_effect: member.intent.allowed_effect,
                    proof_ceiling: member.intent.proof_ceiling,
                    expires_at_ms: member.intent.expires_at_ms,
                    status: LiveStatus::Active,
                },
            );
        }
        ledger.note_revision(
            &request.enumeration.authority_root_ref,
            request.enumeration.grant_graph_revision,
        );
        ledger.intents.insert(
            request.operation_id.clone(),
            PortIntentRecord {
                operation_id: request.operation_id.clone(),
                digest,
                kind: IntentKind::GrantActivation,
                disposition: IntentDisposition::Committed(CommittedReceipt::Activation(first)),
                fenced: Vec::new(),
                closure_receipt: Some(closure_receipt),
                closure_member_receipts: receipts.clone(),
            },
        );
        ledger
            .closure_targets
            .insert(closure_anchor, request.operation_id.clone());
        Ok(receipts)
    }

    /// Rehydrates one committed revocation closure after a restart.
    ///
    /// The caller re-presents the revocation intent; the port re-enumerates
    /// through the injected Governor owner, re-derives the exact fence set,
    /// and requires every member ORS row to read back `Fenced` with exact
    /// revocation-record agreement before reinstalling the live fence, the
    /// original disposition, and the closure receipt. A missing,
    /// non-`Fenced`, incomplete, or disagreeing row stays fail-closed:
    /// absence of the durable closure never restores descendant authority.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::revoke_grant_closure`], with
    /// [`KernelError::RecoveryUnavailable`] naming the exact rehydration
    /// disagreement.
    pub fn recover_grant_closure_revocation(
        &self,
        request: &GrantClosureRevocationIntent,
        active_epoch: &EpochId,
    ) -> Result<GrantClosureReceipt, KernelError> {
        let boundary = self.durable_boundary().ok_or_else(|| {
            KernelError::RecoveryUnavailable(
                "grant-closure recovery needs the durable root-grant boundary".to_owned(),
            )
        })?;
        validate_id(&request.operation_id, "operation_id")?;
        validate_id(&request.grant_id, "grant_id")?;
        let owner_enumeration = boundary
            .hydration
            .enumerate_grant_closure(&request.grant_id)?;
        self.revoke_closure_core(
            request,
            active_epoch,
            Some(boundary),
            Some(&owner_enumeration),
        )
    }

    /// Shared revocation-closure core behind the rich, thin, and recovery
    /// entry points. The owner enumeration is `Some` on every durable path
    /// (fetched by the caller or re-presented for recovery) and `None` only
    /// for the ledger-only path with no durable boundary.
    #[allow(
        clippy::too_many_lines,
        reason = "the closure revocation gate keeps derivation, idempotency, per-member CAS, read-back, and install together"
    )]
    fn revoke_closure_core(
        &self,
        request: &GrantClosureRevocationIntent,
        active_epoch: &EpochId,
        boundary: Option<&DurableRootGrantBoundary>,
        owner_enumeration: Option<&GrantClosureEnumeration>,
    ) -> Result<GrantClosureReceipt, KernelError> {
        validate_id(&request.operation_id, "operation_id")?;
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

        let mut ledger = self.lock_ledger();
        let boundary = boundary.ok_or_else(|| {
            KernelError::RecoveryUnavailable(
                "grant-closure revocation requires the durable owner boundary".to_owned(),
            )
        })?;
        // Derive the fence set before the idempotency gate: the digest binds
        // the complete affected set, so exact replay re-derives the same
        // digest while any changed member is a typed conflict. These are
        // read-only derivations; no mutation happens above the gate.
        let derived = derive_closure_fence(
            &ledger,
            request,
            Some(boundary),
            owner_enumeration,
            active_epoch,
        )?;
        let digest = closure_revocation_digest(request, &derived)?;
        match ledger.resolve(&request.operation_id, &digest) {
            IntentResolve::Conflict => return Err(KernelError::IdempotencyConflict),
            IntentResolve::Replay(_) => {
                let record = ledger.intents.get(&request.operation_id).ok_or_else(|| {
                    KernelError::RecoveryUnavailable(
                        "closure revocation intent disappeared during replay".to_owned(),
                    )
                })?;
                return record
                    .closure_receipt
                    .clone()
                    .ok_or(KernelError::IdempotencyConflict);
            }
            IntentResolve::New => {}
        }
        check_revision(
            &ledger,
            &request.authority_root_ref,
            request.grant_graph_revision,
        )?;
        if derived.unknown_target {
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
                    closure_receipt: None,
                    closure_member_receipts: Vec::new(),
                },
            );
            return Err(KernelError::InvalidField {
                field: "grant_id",
                reason: "unknown grant lineage; reconcile by receipt before retry",
            });
        }

        let enumeration = owner_enumeration.ok_or_else(|| {
            KernelError::RecoveryUnavailable(
                "grant-closure owner declaration is not bound".to_owned(),
            )
        })?;
        let declaration = closure_declaration_from_enumeration(enumeration)?;
        let authority_receipt = AuthorityRevocationReceipt {
            revocation_id: format!("revocation-{}", request.operation_id),
            snapshot_id: request.snapshot_id.clone(),
            authority_epoch: active_epoch.clone(),
            state: AuthorityState::Revoked,
        };
        authority_receipt.validate()?;
        let authority_receipt_ref = GrantClosureAuthorityReceiptRef {
            receipt_id: authority_receipt.revocation_id.clone(),
            snapshot_id: authority_receipt.snapshot_id.clone(),
            authority_epoch: authority_receipt.authority_epoch.clone(),
            state: GrantClosureState::Revoked,
        };
        let grant_revocations = derived
            .members
            .iter()
            .map(|member| {
                CapabilityGrantRevocation::new(member.fence_input.clone())
                    .map_err(KernelError::RecoveryState)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut introduction_ids = live_closure_introduction_ids(&ledger, &derived.affected)
            .into_iter()
            .collect::<BTreeSet<_>>();
        let operation_id =
            OperationIdentity::new(&request.operation_id).map_err(KernelError::RecoveryState)?;
        if let Some(present) = boundary
            .store
            .load_grant_closure(&operation_id)
            .map_err(|error| map_ors_recovery_error(&error))?
        {
            introduction_ids.extend(present.commit().fenced_introductions.iter().cloned());
        }
        let introduction_ids = introduction_ids.into_iter().collect::<Vec<_>>();
        let introduction_fences =
            closure_introduction_fences(boundary, &introduction_ids, &request.operation_id)?;
        let fenced_introductions = introduction_ids
            .iter()
            .map(OperationIdentity::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(KernelError::RecoveryState)?;
        let fence_request = GrantClosureFenceRequest {
            schema: GRANT_CLOSURE_SCHEMA.to_owned(),
            version: GRANT_CLOSURE_VERSION,
            operation_id: request.operation_id.clone(),
            idempotency_digest: digest.clone(),
            declaration,
            authority: request.binding.clone(),
            authority_receipt: authority_receipt_ref,
            proof_ceiling: closure_proof_ceiling(enumeration),
            canonical_receipt: None,
            state: GrantClosureState::Revoked,
            fenced_introductions,
            grant_revocations,
            introduction_fences,
        };
        let durable = boundary
            .store
            .commit_grant_closure_fence(fence_request)
            .map_err(|error| map_ors_recovery_error(&error))?;
        let closure_receipt = durable.commit().clone();
        closure_receipt
            .validate()
            .map_err(|error| KernelError::RecoveryUnavailable(error.to_string()))?;
        let projection = boundary
            .store
            .load_grant_closure(&operation_id)
            .map_err(|error| map_ors_recovery_error(&error))?
            .ok_or_else(|| {
                KernelError::RecoveryUnavailable(
                    "atomic closure commit is missing after durable return".to_owned(),
                )
            })?;
        if projection.commit() != &closure_receipt
            || projection.receipt() != durable.closure_receipt()
            || durable.member_receipts().len() != derived.members.len()
            || durable
                .member_receipts()
                .iter()
                .zip(&closure_receipt.ors_member_receipts)
                .any(|(receipt, expected)| !ors_receipt_matches(receipt.receipt(), expected))
            || durable.introduction_receipts().len() != introduction_ids.len()
            || durable
                .introduction_receipts()
                .iter()
                .zip(&closure_receipt.ors_introduction_receipts)
                .any(|(receipt, expected)| !ors_receipt_matches(receipt.receipt(), expected))
        {
            return Err(KernelError::RecoveryUnavailable(
                "atomic closure commit/read-back disagrees".to_owned(),
            ));
        }

        for grant_id in &derived.affected {
            if let Some(record) = ledger.grants.get_mut(grant_id) {
                record.status = LiveStatus::Revoked;
            } else {
                ledger.revoked_grants.insert(grant_id.clone());
            }
        }
        for introduction_id in &closure_receipt.fenced_introductions {
            if let Some(record) = ledger.introductions.get_mut(introduction_id) {
                record.status = LiveStatus::Revoked;
            } else {
                ledger.introductions.insert(
                    introduction_id.clone(),
                    LiveIntroductionRecord {
                        authority_root_ref: request.authority_root_ref.clone(),
                        supporting_grant_ids: BTreeSet::new(),
                        status: LiveStatus::Revoked,
                    },
                );
            }
        }
        let receipt = authority_receipt;
        ledger.note_revision(&request.authority_root_ref, request.grant_graph_revision);
        ledger.intents.insert(
            request.operation_id.clone(),
            PortIntentRecord {
                operation_id: request.operation_id.clone(),
                digest,
                kind: IntentKind::GrantRevocation,
                disposition: IntentDisposition::Committed(CommittedReceipt::Revocation(
                    receipt.clone(),
                )),
                fenced: derived.affected.clone(),
                closure_receipt: Some(closure_receipt.clone()),
                closure_member_receipts: Vec::new(),
            },
        );
        note_unknown_effects(&mut ledger, &unknown_effects, &request.operation_id);
        ledger
            .closure_targets
            .insert(request.grant_id.clone(), request.operation_id.clone());
        Ok(closure_receipt)
    }

    fn activate_root_grant_durable(
        &self,
        request: &eliot_authority::GrantActivationRequest,
        active_epoch: &EpochId,
        boundary: &DurableRootGrantBoundary,
    ) -> Result<AuthorityActivationReceipt, eliot_authority::P07PortError> {
        check_binding(&request.binding, active_epoch).map_err(|error| map_thin_error(&error))?;
        let hydration = boundary
            .hydration
            .hydrate_grant_member(request.grant_id.as_str())
            .map_err(|error| map_thin_error(&error))?;
        let operation_id = hydration.intent.operation_id.clone();
        validate_member_hydration(&hydration, request, active_epoch)
            .map_err(|error| map_thin_error(&error))?;

        let mut ledger = self.lock_ledger();
        let digest =
            hydrated_grant_member_digest(&hydration).map_err(|error| map_thin_error(&error))?;
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
        // Durable revision gate (`#2100`): the same per-root watermark the
        // closure paths enforce. A stale presentation fails closed here
        // instead of committing under a superseded revision.
        // Restore never reactivates: refuse a `Fenced` or `Released` durable
        // row before any mutation.
        check_activation_durability(
            boundary,
            &hydration.intent,
            hydration.durable_record.record(),
        )?;
        let pending = PendingActivation {
            operation_id: operation_id.clone(),
            digest: digest.clone(),
            intent: hydration.intent.clone(),
            durable_record: hydration.durable_record.clone(),
        };
        if ledger
            .pending_activations
            .insert(operation_id.clone(), pending)
            .is_some()
        {
            return Err(eliot_authority::P07PortError::InvalidBinding);
        }
        let pending_is_exact =
            ledger
                .pending_activations
                .get(&operation_id)
                .is_some_and(|pending| {
                    pending.operation_id == operation_id
                        && pending.digest == digest
                        && pending.intent == hydration.intent
                        && pending.durable_record == hydration.durable_record
                });
        if !pending_is_exact {
            ledger.pending_activations.remove(&operation_id);
            return Err(eliot_authority::P07PortError::InvalidBinding);
        }
        let result = (|| {
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
            install_root_activation(&mut ledger, &hydration.intent, &receipt, digest.clone());
            Ok(receipt)
        })();
        ledger.pending_activations.remove(&operation_id);
        result
    }

    /// Thin multi-descendant revocation: the Governor owner already declared
    /// the complete closure, so the thin request only supplies the target,
    /// snapshot, and binding. The operation identity reuses the single-root
    /// derivation (kind, target, snapshot, epoch tuple); a changed closure
    /// under one derived identity is a typed conflict, and a new snapshot or
    /// epoch derives a fresh identity that re-confirms the fence.
    fn revoke_grant_closure_durable_thin(
        &self,
        request: &eliot_authority::GrantRevocationRequest,
        active_epoch: &EpochId,
        boundary: &DurableRootGrantBoundary,
        enumeration: &GrantClosureEnumeration,
    ) -> Result<AuthorityRevocationReceipt, eliot_authority::P07PortError> {
        check_binding(&request.binding, active_epoch).map_err(|error| map_thin_error(&error))?;
        let rich = GrantClosureRevocationIntent {
            operation_id: thin_operation_id(
                "revoke-grant",
                request.grant_id.as_str(),
                request.snapshot_id.as_str(),
                active_epoch,
            ),
            grant_id: request.grant_id.as_str().to_owned(),
            authority_root_ref: enumeration.authority_root_ref.clone(),
            snapshot_id: request.snapshot_id.as_str().to_owned(),
            grant_graph_revision: enumeration.grant_graph_revision,
            binding: request.binding.clone(),
            // The thin request expresses no unknown effects and declares no
            // receipt obligations: both are faithful absences, not defaults.
            unknown_outcome_operations: Vec::new(),
            receipt_obligations: Vec::new(),
        };
        let receipt = self
            .revoke_closure_core(&rich, active_epoch, Some(boundary), Some(enumeration))
            .map_err(|error| map_thin_error(&error))?;
        let operation_id = thin_operation_id(
            "revoke-grant",
            request.grant_id.as_str(),
            request.snapshot_id.as_str(),
            active_epoch,
        );
        if receipt.operation_id != operation_id
            || receipt.declaration.target_grant_id != request.grant_id.as_str()
            || receipt.state != GrantClosureState::Revoked
        {
            return Err(eliot_authority::P07PortError::Unavailable);
        }
        runtime_revocation_receipt(request, active_epoch).map_err(|error| map_thin_error(&error))
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

/// Whether introduction validation is proving a fresh mutation or rechecking
/// the exact committed identity before an idempotent return.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IntroductionActivationMode {
    Fresh,
    Replay,
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
    /// Durable closure receipt committed by a closure operation, if any.
    /// Restart rehydration repopulates this alongside `disposition` and
    /// `fenced` so closure queries read back restart-identical values.
    closure_receipt: Option<GrantClosureReceipt>,
    /// Per-member activation receipts committed by a closure activation, in
    /// enumeration order. Empty for every non-closure operation.
    closure_member_receipts: Vec<AuthorityActivationReceipt>,
}

/// Live enforcement state of one recorded grant.
#[derive(Clone, Debug)]
struct LiveGrantRecord {
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

/// Gate-owned activation state retained while ORS crosses its durable
/// pending-to-active boundary. It is never served as live authority.
#[derive(Clone, Debug)]
struct PendingActivation {
    operation_id: String,
    digest: String,
    intent: GrantActivationIntent,
    durable_record: CapabilityGrantActivation,
}

/// Whether one recorded grant or introduction still carries live authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiveStatus {
    Active,
    Revoked,
}

/// Process-lifetime intent ledger and live lineage state.
#[derive(Clone, Debug, Default)]
struct PortLedger {
    intents: BTreeMap<String, PortIntentRecord>,
    pending_activations: BTreeMap<String, PendingActivation>,
    grants: BTreeMap<String, LiveGrantRecord>,
    revoked_grants: BTreeSet<String>,
    introductions: BTreeMap<String, LiveIntroductionRecord>,
    max_revision: BTreeMap<String, u64>,
    reconciling_effects: BTreeMap<String, String>,
    /// Closure target grant identity to closure operation identity, so a
    /// committed closure stays reachable by target after restart rehydration.
    closure_targets: BTreeMap<String, String>,
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

/// Returns the conservatively known revoked handles used by compile/recovery
/// gates. It intentionally does not derive a second lineage graph in Kernel:
/// every durable/process revocation marker is returned, and the caller
/// removes the complete set from the next candidate. The canonical owner
/// declaration and ORS receipts remain the only closure-membership authority.
fn revoked_support_in_ledger(ledger: &PortLedger, roots: &[String]) -> BTreeSet<String> {
    let mut revoked = ledger.revoked_grants.clone();
    revoked.extend(
        ledger
            .grants
            .iter()
            .filter(|(_, record)| record.status == LiveStatus::Revoked)
            .map(|(grant_id, _)| grant_id.clone()),
    );
    revoked.extend(
        ledger
            .introductions
            .iter()
            .filter(|(_, record)| record.status == LiveStatus::Revoked)
            .map(|(introduction_id, _)| introduction_id.clone()),
    );
    for root in roots {
        if ledger.revoked_grants.contains(root)
            || ledger
                .grants
                .get(root)
                .is_some_and(|record| record.status == LiveStatus::Revoked)
            || ledger
                .introductions
                .get(root)
                .is_some_and(|record| record.status == LiveStatus::Revoked)
        {
            revoked.insert(root.clone());
        }
    }
    revoked
}

/// Returns the recorded live target on the same root, in sorted order.
///
/// The Kernel ledger deliberately carries no parent edge: the process-lifetime
/// lineage graph was removed with the durable closure slice, so the owner
/// declaration and the durable ORS receipts are the only closure-membership
/// authority. [`derive_closure_fence`] reads the complete member set from the
/// injected Governor enumeration on every production path; this legacy
/// test-only helper cannot and must not re-derive descendants from
/// process-local state, so it returns the recorded target alone.
#[cfg(test)]
fn descendant_closure(
    grants: &BTreeMap<String, LiveGrantRecord>,
    authority_root_ref: &str,
    grant_id: &str,
) -> Vec<String> {
    if grants
        .get(grant_id)
        .is_some_and(|record| record.authority_root_ref == authority_root_ref)
    {
        vec![grant_id.to_owned()]
    } else {
        Vec::new()
    }
}

/// Returns the unique delegation anchor of one enumeration: the member
/// whose parent is `None` (a delegation root) or names a grant outside the
/// enumeration and outside its preserved alternate-path identities. Structure
/// validation requires exactly one.
fn closure_anchor_grant(enumeration: &GrantClosureEnumeration) -> Result<String, KernelError> {
    let preserved = enumeration
        .preserved
        .iter()
        .map(|survivor| survivor.grant_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut anchor: Option<&str> = None;
    for member in &enumeration.members {
        let is_anchor = member
            .intent
            .parent_grant_id
            .as_deref()
            .is_none_or(|parent| !seen.contains(parent) && !preserved.contains(parent));
        if is_anchor {
            if anchor.is_some() {
                return Err(KernelError::InvalidField {
                    field: "enumeration.members",
                    reason: "the closure enumeration must name exactly one delegation anchor",
                });
            }
            anchor = Some(member.intent.grant_id.as_str());
        }
        seen.insert(member.intent.grant_id.as_str());
    }
    anchor.map(str::to_owned).ok_or(KernelError::InvalidField {
        field: "enumeration.members",
        reason: "the closure enumeration must name exactly one delegation anchor",
    })
}

/// Returns the sorted affected set of one enumeration: every member identity.
fn closure_affected_set(enumeration: &GrantClosureEnumeration) -> Vec<String> {
    let mut affected = BTreeSet::new();
    for member in &enumeration.members {
        affected.insert(member.intent.grant_id.clone());
    }
    affected.into_iter().collect()
}

fn closure_proof_ceiling(enumeration: &GrantClosureEnumeration) -> ProofCeiling {
    enumeration
        .members
        .iter()
        .fold(ProofCeiling::ObservedExternalEffect, |ceiling, member| {
            ceiling
                .min(member.intent.proof_ceiling)
                .min(member.intent.binding.proof_ceiling)
        })
}

fn closure_declaration_from_enumeration(
    enumeration: &GrantClosureEnumeration,
) -> Result<GrantClosureDeclaration, KernelError> {
    let mut proof_ceiling = ProofCeiling::ObservedExternalEffect;
    let members = enumeration
        .members
        .iter()
        .map(|member| {
            proof_ceiling = proof_ceiling
                .min(member.intent.proof_ceiling)
                .min(member.intent.binding.proof_ceiling);
            GrantClosureMemberDeclaration {
                grant_id: member.intent.grant_id.clone(),
                parent_grant_id: member.intent.parent_grant_id.clone(),
            }
        })
        .collect();
    let declaration = GrantClosureDeclaration {
        schema: GRANT_CLOSURE_SCHEMA.to_owned(),
        version: GRANT_CLOSURE_VERSION,
        target_grant_id: closure_anchor_grant(enumeration)?,
        authority_root_ref: enumeration.authority_root_ref.clone(),
        grant_graph_revision: enumeration.grant_graph_revision,
        members,
        preserved: enumeration.preserved.clone(),
        proof_ceiling,
    };
    declaration
        .validate()
        .map_err(|error| KernelError::RecoveryUnavailable(error.to_string()))?;
    Ok(declaration)
}

/// Validates one Governor-enumerated closure structurally, before any
/// mutation and without consulting live state.
///
/// Every member must share the exact enumeration revision, root, and fence
/// contour; parents must appear earlier in parent-before-child order unless
/// they are explicitly retained as an owner-declared alternate path; opaque
/// records must agree triple-wise (record identity, subject identity, and
/// binding) with their semantic intent. The fence set itself is never taken
/// from caller material: only this validated enumeration feeds the fence
/// derivation.
#[allow(
    clippy::too_many_lines,
    reason = "the enumeration structural gate keeps revision, root, order, binding, and opaque agreement together"
)]
fn validate_closure_enumeration(
    enumeration: &GrantClosureEnumeration,
    active_epoch: &EpochId,
) -> Result<(), KernelError> {
    validate_id(
        &enumeration.authority_root_ref,
        "enumeration.authority_root_ref",
    )?;
    if enumeration.grant_graph_revision == 0 {
        return Err(KernelError::InvalidField {
            field: "enumeration.grant_graph_revision",
            reason: "grant graph revision must be nonzero",
        });
    }
    if enumeration.members.is_empty() {
        return Err(KernelError::InvalidField {
            field: "enumeration.members",
            reason: "a closure enumeration affects at least its target",
        });
    }
    let affected = enumeration
        .members
        .iter()
        .map(|member| member.intent.grant_id.clone())
        .collect::<Vec<_>>();
    validate_preserved_set(&enumeration.preserved, &affected)?;
    let preserved_ids = enumeration
        .preserved
        .iter()
        .map(|survivor| survivor.grant_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut anchor_count = 0u32;
    let mut contour: Option<&AuthorityBinding> = None;
    for member in &enumeration.members {
        let intent = &member.intent;
        validate_id(&intent.operation_id, "enumeration.member.operation_id")?;
        validate_id(&intent.grant_id, "enumeration.member.grant_id")?;
        if let Some(parent) = &intent.parent_grant_id {
            validate_id(parent, "enumeration.member.parent_grant_id")?;
            // A parent outside the enumeration is the closure anchor's
            // external delegator (mid-chain subtree or incremental
            // delegation): it must appear at most once and is resolved
            // against live lineage or a durable row by the caller, never
            // assumed here.
            if !seen.contains(parent.as_str()) && !preserved_ids.contains(parent.as_str()) {
                anchor_count += 1;
            }
        } else {
            anchor_count += 1;
        }
        validate_id(
            &intent.authority_root_ref,
            "enumeration.member.authority_root_ref",
        )?;
        validate_id(&intent.snapshot_id, "enumeration.member.snapshot_id")?;
        validate_id(
            &intent.holder_principal,
            "enumeration.member.holder_principal",
        )?;
        validate_id(&intent.session_id, "enumeration.member.session_id")?;
        validate_id(&intent.scope_id, "enumeration.member.scope_id")?;
        for obligation in &intent.receipt_obligations {
            validate_id(obligation, "enumeration.member.receipt_obligation")?;
        }
        if !seen.insert(intent.grant_id.as_str()) {
            return Err(KernelError::InvalidField {
                field: "enumeration.member.grant_id",
                reason: "duplicate closure member identity",
            });
        }
        if intent.authority_root_ref != enumeration.authority_root_ref {
            return Err(KernelError::FenceMismatch);
        }
        if intent.grant_graph_revision != enumeration.grant_graph_revision {
            return Err(KernelError::InvalidField {
                field: "enumeration.member.grant_graph_revision",
                reason: "every closure member carries the exact enumeration revision",
            });
        }
        check_binding(&intent.binding, active_epoch)?;
        check_ceiling(intent.allowed_effect, intent.proof_ceiling, &intent.binding)?;
        check_expiry(
            intent.issued_at_ms,
            intent.expires_at_ms,
            member.observed_at_ms,
        )?;
        if let Some(contour) = contour {
            if contour.authority_id != intent.binding.authority_id
                || contour.authority_owner != intent.binding.authority_owner
                || contour.state_fence != intent.binding.state_fence
                || !contour
                    .authority_epoch
                    .is_same_authority(&intent.binding.authority_epoch)
            {
                return Err(KernelError::FenceMismatch);
            }
        } else {
            contour = Some(&intent.binding);
        }
        if member.durable_record.record().record_id.as_str() != intent.operation_id
            || member.durable_record.record().subject_id.as_str() != intent.grant_id
        {
            return Err(KernelError::RecoveryUnavailable(
                "closure member opaque record disagrees with its semantic intent".to_owned(),
            ));
        }
        check_opaque_record_binding(
            member.durable_record.record(),
            &intent.binding,
            active_epoch,
        )?;
    }
    if anchor_count != 1 {
        return Err(KernelError::InvalidField {
            field: "enumeration.members",
            reason: "the closure enumeration must name exactly one delegation anchor",
        });
    }
    for survivor in &enumeration.preserved {
        if seen.contains(survivor.grant_id.as_str()) {
            return Err(KernelError::InvalidField {
                field: "enumeration.preserved",
                reason: "a survivor must be disjoint from the fenced members",
            });
        }
    }
    Ok(())
}

/// Validates every closure member for activation against the recorded lineage
/// plus the earlier enumeration members, before any mutation.
///
/// The enumeration must already be structurally valid. A member identity that
/// is already recorded (live or fenced) is rejected: restore never
/// reactivates a path. An anchor parent outside the enumeration (mid-chain
/// subtree or incremental delegation onto a recorded parent) resolves
/// through live lineage or a durable row instead.
fn validate_closure_activation_members(
    enumeration: &GrantClosureEnumeration,
    ledger: &PortLedger,
    boundary: Option<&DurableRootGrantBoundary>,
    active_epoch: &EpochId,
) -> Result<(), KernelError> {
    let mut working: BTreeMap<String, LiveGrantRecord> = ledger.grants.clone();
    // Member grant identities inside one enumeration, for external-parent
    // detection without re-walking the whole enumeration per member.
    let internal: BTreeSet<&str> = enumeration
        .members
        .iter()
        .map(|member| member.intent.grant_id.as_str())
        .collect();
    for member in &enumeration.members {
        let intent = &member.intent;
        if working.contains_key(&intent.grant_id)
            || ledger.revoked_grants.contains(&intent.grant_id)
        {
            return Err(KernelError::InvalidField {
                field: "enumeration.member.grant_id",
                reason: "grant identity is already recorded; restore never reactivates a path",
            });
        }
        if let Some(parent_id) = &intent.parent_grant_id {
            if internal.contains(parent_id.as_str()) {
                let Some(parent) = working.get(parent_id) else {
                    return Err(KernelError::InvalidField {
                        field: "enumeration.member.parent_grant_id",
                        reason: "unknown parent lineage",
                    });
                };
                if parent.status != LiveStatus::Active {
                    return Err(KernelError::InvalidField {
                        field: "enumeration.member.parent_grant_id",
                        reason: "parent lineage is fenced",
                    });
                }
                if let Some(expires) = parent.expires_at_ms
                    && expires <= member.observed_at_ms
                {
                    return Err(KernelError::InvalidField {
                        field: "enumeration.member.parent_grant_id",
                        reason: "parent lineage is expired",
                    });
                }
            } else {
                resolve_external_parent(
                    ledger,
                    boundary,
                    active_epoch,
                    &intent.authority_root_ref,
                    &intent.binding,
                    parent_id,
                    Some(member.observed_at_ms),
                )?;
            }
        }
        working.insert(
            intent.grant_id.clone(),
            LiveGrantRecord {
                authority_root_ref: intent.authority_root_ref.clone(),
                binding: intent.binding.clone(),
                allowed_effect: intent.allowed_effect,
                proof_ceiling: intent.proof_ceiling,
                expires_at_ms: intent.expires_at_ms,
                status: LiveStatus::Active,
            },
        );
    }
    Ok(())
}

/// One affected member with the exact opaque ORS input its durable fence
/// must commit or reconfirm.
struct ClosureFenceMember {
    fence_input: OperationalRecordInput,
}

/// Read-only fence derivation for one closure revocation: the complete
/// affected set, the owner-declared survivors, and the per-member opaque
/// inputs. No mutation happens here; the caller commits after the idempotency
/// gate.
struct DerivedClosureFence {
    affected: Vec<String>,
    preserved: Vec<GrantClosureSurvivor>,
    members: Vec<ClosureFenceMember>,
    fenced_introductions: Vec<String>,
    fenced_introduction_records: Vec<OperationalRecordInput>,
    unknown_target: bool,
}

/// Derives the exact fence set for one closure revocation without mutating
/// anything.
///
/// On the durable path the injected Governor enumeration is the fence
/// authority: it must validate structurally, bind the exact presented root
/// and revision, root at the requested target, and cover every recorded live
/// descendant (fenced or owner-declared preserved) — anything less refuses as
/// an incomplete enumeration. Every fenced member must carry a durable ORS
/// row: an `Active` row must match its enumerated activation input, a
/// `Fenced` row must match the derived revocation input, and any other phase
/// or absence stays fail-closed.
///
/// Production always requires the durable boundary and owner declaration.
/// The memory-only branch exists only inside the module's legacy test
/// fixture and can never commit from a production-constructed port.
#[allow(
    clippy::too_many_lines,
    reason = "the fence derivation keeps enumeration, completeness, and per-member ORS agreement together"
)]
fn derive_closure_fence(
    ledger: &PortLedger,
    request: &GrantClosureRevocationIntent,
    boundary: Option<&DurableRootGrantBoundary>,
    owner_enumeration: Option<&GrantClosureEnumeration>,
    active_epoch: &EpochId,
) -> Result<DerivedClosureFence, KernelError> {
    #[cfg(not(test))]
    let boundary = boundary.ok_or_else(|| {
        KernelError::RecoveryUnavailable(
            "production grant-closure fencing requires the durable owner boundary".to_owned(),
        )
    })?;
    #[cfg(test)]
    let boundary = match boundary {
        Some(boundary) => boundary,
        None => return derive_ledger_closure_fence(ledger, request),
    };
    let Some(enumeration) = owner_enumeration else {
        return Err(KernelError::RecoveryUnavailable(
            "grant-closure enumeration owner is not bound".to_owned(),
        ));
    };
    validate_closure_enumeration(enumeration, active_epoch)?;
    if enumeration.authority_root_ref != request.authority_root_ref {
        return Err(KernelError::FenceMismatch);
    }
    if enumeration.grant_graph_revision != request.grant_graph_revision {
        return Err(KernelError::InvalidField {
            field: "grant_graph_revision",
            reason: "the presented revision disagrees with the enumerated revision",
        });
    }
    let anchor_grant_id = closure_anchor_grant(enumeration)?;
    if anchor_grant_id != request.grant_id {
        return Err(KernelError::InvalidField {
            field: "grant_id",
            reason: "the closure target must be the enumerated delegation anchor",
        });
    }
    // A mid-chain anchor delegates under an external parent outside the
    // enumeration. That parent must carry live authority on the same root
    // and fence contour: a recorded active grant, or (on the durable path,
    // e.g. after a restart) an `Active` durable row bound to the presented
    // fence and epoch. Anything else refuses instead of fencing or
    // activating under a fenced, expired, or unknown parent.
    let anchor = enumeration
        .members
        .iter()
        .find(|member| member.intent.grant_id == anchor_grant_id)
        .ok_or(KernelError::InvalidField {
            field: "grant_id",
            reason: "the closure target must be the enumerated delegation anchor",
        })?;
    if anchor.intent.binding != request.binding {
        return Err(KernelError::FenceMismatch);
    }
    if anchor.intent.snapshot_id != request.snapshot_id {
        return Err(KernelError::RecoveryUnavailable(
            "thin revocation snapshot disagrees with the owner closure declaration".to_owned(),
        ));
    }
    if let Some(external_parent) = anchor.intent.parent_grant_id.as_deref().filter(|parent| {
        !enumeration
            .members
            .iter()
            .any(|member| member.intent.grant_id.as_str() == *parent)
    }) {
        resolve_external_parent(
            ledger,
            Some(boundary),
            active_epoch,
            &request.authority_root_ref,
            &request.binding,
            external_parent,
            None,
        )?;
    }
    let affected = closure_affected_set(enumeration);
    let affected_set: BTreeSet<&str> = affected.iter().map(String::as_str).collect();
    // Preserved-survivor membership (`#2100` C73-F1): every declared
    // survivor must prove covering authority at the current revision and
    // fence. A declaration from an older revision is never carried
    // silently and never dropped silently — each survivor is proven or
    // the enumeration refuses.
    for survivor in &enumeration.preserved {
        prove_survivor_membership(
            ledger,
            boundary,
            active_epoch,
            request,
            &affected_set,
            survivor,
        )?;
    }
    let mut members = Vec::with_capacity(enumeration.members.len());
    for member in &enumeration.members {
        if let Some(record) = ledger.grants.get(&member.intent.grant_id) {
            if record.authority_root_ref != request.authority_root_ref {
                return Err(KernelError::FenceMismatch);
            }
            if record.binding.state_fence != request.binding.state_fence {
                return Err(KernelError::FenceMismatch);
            }
        }
        let subject =
            OperationIdentity::new(&member.intent.grant_id).map_err(KernelError::RecoveryState)?;
        let projection = boundary
            .store
            .load_capability_grant(&subject)
            .map_err(|error| map_ors_recovery_error(&error))?
            .ok_or_else(|| {
                KernelError::RecoveryUnavailable(
                    "closure member projection is absent; no durable row to fence".to_owned(),
                )
            })?;
        let revocation_record =
            closure_member_revocation(member.durable_record.record(), &request.operation_id)?;
        let fence_input = match projection.phase() {
            OperationalPhase::Active => {
                if projection.record() != member.durable_record.record() {
                    return Err(KernelError::RecoveryUnavailable(
                        "closure member ORS row disagrees with its enumerated input".to_owned(),
                    ));
                }
                revocation_record.record().clone()
            }
            OperationalPhase::Fenced => {
                if projection.record() != revocation_record.record()
                    && !activation_bytes_equal(projection.record(), member.durable_record.record())
                {
                    return Err(KernelError::RecoveryUnavailable(
                        "closure member fence evidence disagrees with the derived revocation"
                            .to_owned(),
                    ));
                }
                projection.record().clone()
            }
            _ => {
                return Err(KernelError::RecoveryUnavailable(
                    "closure member ORS row is not fenceable".to_owned(),
                ));
            }
        };
        members.push(ClosureFenceMember { fence_input });
    }
    let fenced_introductions = live_closure_introduction_ids(ledger, &affected);
    let introduction_fences = closure_introduction_fences(
        boundary,
        &fenced_introductions,
        request.operation_id.as_str(),
    )?;
    let fenced_introduction_records = introduction_fences
        .iter()
        .map(|fence| fence.record().clone())
        .collect();
    Ok(DerivedClosureFence {
        affected,
        preserved: enumeration.preserved.clone(),
        members,
        fenced_introductions,
        fenced_introduction_records,
        unknown_target: false,
    })
}

/// Proves one declared survivor still carries covering authority at the
/// current revision and fence (`#2100` C73-F1).
///
/// A survivor is preserved, never fenced, so its survival must be proven
/// on every closure that carries it: a declaration from an older revision
/// is never carried silently, and a lapsed cover is never dropped
/// silently — each survivor is proven or the enumeration refuses:
///
/// - the survivor itself, when live-recorded, must be `Active` on the
///   closure root and fence contour (existing gate, kept);
/// - the declared covering grant must prove CURRENT authority: a live
///   `Active` record on the declared covering root and fence contour,
///   or (e.g. after a restart, before live rehydration) an `Active`
///   durable row bound to the presented fence and epoch. A covering
///   grant fenced by this same closure, recorded non-`Active`, revoked,
///   missing, or contour-mismatched refuses instead of preserving stale
///   authority.
///
/// # Errors
///
/// Returns [`KernelError::InvalidField`] for a non-live or
/// contour-disagreeing live record, [`KernelError::FenceMismatch`] for a
/// root or fence disagreement, and [`KernelError::RecoveryUnavailable`]
/// when no durable covering authority exists or the durable row
/// disagrees.
#[allow(
    clippy::too_many_arguments,
    reason = "the survivor gate binds ledger, store, epoch, request, affected set, and survivor explicitly"
)]
#[allow(
    clippy::too_many_lines,
    reason = "exact alternate-path proof keeps owner hydration, durable rows, and live contour checks together"
)]
fn prove_survivor_membership(
    ledger: &PortLedger,
    boundary: &DurableRootGrantBoundary,
    active_epoch: &EpochId,
    request: &GrantClosureRevocationIntent,
    affected_set: &BTreeSet<&str>,
    survivor: &GrantClosureSurvivor,
) -> Result<(), KernelError> {
    let survivor_hydration = boundary
        .hydration
        .hydrate_grant_member(&survivor.grant_id)?;
    let covering_hydration = boundary
        .hydration
        .hydrate_grant_member(&survivor.covering_grant_id)?;
    for hydration in [&survivor_hydration, &covering_hydration] {
        verify_grant_seal(&hydration.durable_record, &hydration.intent, active_epoch)?;
        if hydration
            .intent
            .expires_at_ms
            .is_some_and(|expires| expires <= hydration.observed_at_ms)
        {
            return Err(KernelError::Expired {
                expires_at_ms: hydration.intent.expires_at_ms.unwrap_or_default(),
            });
        }
        if hydration.intent.holder_principal != survivor.holder_principal
            || hydration.intent.session_id != survivor.session_id
            || hydration.intent.scope_id != survivor.scope_id
        {
            return Err(KernelError::InvalidField {
                field: "enumeration.preserved",
                reason: "exact use disagrees with admitted principal, session, or scope",
            });
        }
        check_opaque_record_binding(
            hydration.durable_record.record(),
            &request.binding,
            active_epoch,
        )?;
    }
    if survivor_hydration.intent.authority_root_ref != request.authority_root_ref
        || covering_hydration.intent.authority_root_ref != survivor.covering_root_ref
        || effect_rank(survivor.effect) > effect_rank(covering_hydration.intent.allowed_effect)
    {
        return Err(KernelError::InvalidField {
            field: "enumeration.preserved",
            reason: "exact use is outside the admitted root/effect contour",
        });
    }
    let survivor_subject =
        OperationIdentity::new(&survivor.grant_id).map_err(KernelError::RecoveryState)?;
    let survivor_projection = boundary
        .store
        .load_capability_grant(&survivor_subject)
        .map_err(|error| map_ors_recovery_error(&error))?
        .ok_or_else(|| {
            KernelError::RecoveryUnavailable(
                "preserved survivor has no durable authority row".to_owned(),
            )
        })?;
    if survivor_projection.phase() != OperationalPhase::Active
        || survivor_projection.record() != survivor_hydration.durable_record.record()
    {
        return Err(KernelError::RecoveryUnavailable(
            "preserved survivor durable row is not the exact active owner projection".to_owned(),
        ));
    }
    if let Some(record) = ledger.grants.get(&survivor.grant_id) {
        if record.status != LiveStatus::Active {
            return Err(KernelError::InvalidField {
                field: "enumeration.preserved",
                reason: "a declared survivor is not live authority",
            });
        }
        if record.authority_root_ref != request.authority_root_ref {
            return Err(KernelError::FenceMismatch);
        }
        if record.binding.state_fence != request.binding.state_fence {
            return Err(KernelError::FenceMismatch);
        }
    }
    if affected_set.contains(survivor.covering_grant_id.as_str()) {
        return Err(KernelError::InvalidField {
            field: "enumeration.preserved",
            reason: "a declared survivor cover is fenced by this closure",
        });
    }
    if ledger.revoked_grants.contains(&survivor.covering_grant_id) {
        return Err(KernelError::InvalidField {
            field: "enumeration.preserved",
            reason: "a declared survivor cover is fenced",
        });
    }
    if let Some(covering) = ledger.grants.get(&survivor.covering_grant_id) {
        if covering.status != LiveStatus::Active {
            return Err(KernelError::InvalidField {
                field: "enumeration.preserved",
                reason: "a declared survivor cover is not live authority",
            });
        }
        if covering.authority_root_ref != survivor.covering_root_ref {
            return Err(KernelError::InvalidField {
                field: "enumeration.preserved",
                reason: "a declared survivor cover disagrees with its declared root",
            });
        }
        if covering.binding.state_fence != request.binding.state_fence {
            return Err(KernelError::FenceMismatch);
        }
    }
    let subject =
        OperationIdentity::new(&survivor.covering_grant_id).map_err(KernelError::RecoveryState)?;
    let projection = boundary
        .store
        .load_capability_grant(&subject)
        .map_err(|error| map_ors_recovery_error(&error))?
        .ok_or_else(|| {
            KernelError::RecoveryUnavailable(
                "survivor covering path has no durable authority; stale survivor evidence"
                    .to_owned(),
            )
        })?;
    if projection.phase() != OperationalPhase::Active
        || projection.record() != covering_hydration.durable_record.record()
    {
        return Err(KernelError::RecoveryUnavailable(
            "survivor covering path is fenced or disagrees with its owner projection".to_owned(),
        ));
    }
    check_opaque_record_binding(projection.record(), &request.binding, active_epoch)?;
    Ok(())
}

/// Ledger-only fence derivation for the module's legacy unit fixture.
#[cfg(test)]
fn derive_ledger_closure_fence(
    ledger: &PortLedger,
    request: &GrantClosureRevocationIntent,
) -> Result<DerivedClosureFence, KernelError> {
    let known = ledger.grants.contains_key(&request.grant_id)
        || ledger.revoked_grants.contains(&request.grant_id);
    if !known {
        return Ok(DerivedClosureFence {
            affected: Vec::new(),
            preserved: Vec::new(),
            members: Vec::new(),
            fenced_introductions: Vec::new(),
            fenced_introduction_records: Vec::new(),
            unknown_target: true,
        });
    }
    if let Some(record) = ledger.grants.get(&request.grant_id)
        && record.authority_root_ref != request.authority_root_ref
    {
        return Err(KernelError::FenceMismatch);
    }
    Ok(DerivedClosureFence {
        affected: descendant_closure(
            &ledger.grants,
            &request.authority_root_ref,
            &request.grant_id,
        ),
        preserved: Vec::new(),
        members: Vec::new(),
        fenced_introductions: Vec::new(),
        fenced_introduction_records: Vec::new(),
        unknown_target: false,
    })
}

/// Derives the deterministic ORS revocation record identity for one closure
/// member: the closure operation identity plus the member grant identity.
/// Re-presentation after a crash re-derives the same identity, so an
/// already-`Fenced` member replays its receipt instead of forking a fence.
fn closure_member_revocation_id(operation_id: &str, grant_id: &str) -> String {
    format!("{operation_id}/revoke/{grant_id}")
}

/// Builds one member revocation record from its enumerated activation input:
/// the exact opaque bytes with only the revocation record identity swapped
/// in, mirroring the single-root revocation construction.
fn closure_member_revocation(
    activation_input: &OperationalRecordInput,
    operation_id: &str,
) -> Result<CapabilityGrantRevocation, KernelError> {
    let grant_id = activation_input.subject_id.as_str().to_owned();
    let mut input = activation_input.clone();
    input.record_id = OperationIdentity::new(closure_member_revocation_id(operation_id, &grant_id))
        .map_err(KernelError::RecoveryState)?;
    CapabilityGrantRevocation::new(input).map_err(KernelError::RecoveryState)
}

fn ors_receipt_matches(
    receipt: &OperationalMutationReceipt,
    expected: &GrantClosureOrsReceiptRef,
) -> bool {
    receipt.record_id().as_str() == expected.record_id
        && receipt.subject_id().as_str() == expected.subject_id
        && receipt.operation_order() == expected.operation_order
        && receipt.state_sha256() == expected.state_sha256
}

fn closure_introduction_fences(
    boundary: &DurableRootGrantBoundary,
    introduction_ids: &[String],
    operation_id: &str,
) -> Result<Vec<CapabilityIntroductionFence>, KernelError> {
    introduction_ids
        .iter()
        .map(|introduction_id| {
            let subject =
                OperationIdentity::new(introduction_id).map_err(KernelError::RecoveryState)?;
            let projection = boundary
                .store
                .load_capability_introduction(&subject)
                .map_err(|error| map_ors_recovery_error(&error))?
                .ok_or_else(|| {
                    KernelError::RecoveryUnavailable(
                        "dependent introduction projection is absent".to_owned(),
                    )
                })?;
            match projection.phase() {
                OperationalPhase::Active => {
                    introduction_fence_input(projection.record(), operation_id)
                }
                OperationalPhase::Fenced
                    if projection.record().record_id.as_str()
                        == introduction_fence_record_id(operation_id, introduction_id) =>
                {
                    CapabilityIntroductionFence::new(projection.record().clone())
                        .map_err(KernelError::RecoveryState)
                }
                OperationalPhase::Fenced => Err(KernelError::RecoveryUnavailable(
                    "dependent introduction was fenced by another closure operation".to_owned(),
                )),
                _ => Err(KernelError::RecoveryUnavailable(
                    "dependent introduction row is not fenceable".to_owned(),
                )),
            }
        })
        .collect()
}

/// Compares two opaque activation inputs field by field except the mutable
/// record identity: the same subject, epoch lineage, fence, payload bytes,
/// and times is the same fenced authority, even when a previous closure
/// operation fenced it first.
pub(crate) fn activation_bytes_equal(
    stored: &OperationalRecordInput,
    expected: &OperationalRecordInput,
) -> bool {
    stored.subject_id == expected.subject_id
        && stored.authority_epoch == expected.authority_epoch
        && stored.state_fence == expected.state_fence
        && stored.payload == expected.payload
        && stored.payload_sha256 == expected.payload_sha256
        && stored.payload_length == expected.payload_length
        && stored.created_at_ms == expected.created_at_ms
        && stored.cleanup_after_ms == expected.cleanup_after_ms
}

/// Durable shape of one member row that may still be activated.
enum ActivationRow {
    Absent,
    Active,
    Applying,
    /// A `Fenced` or `Released` row: restore never reactivates it. The
    /// caller decides the refusal kind (fresh activation rejects the
    /// re-presented identity; recovery refuses the resurrection).
    Fenced,
}

/// Durable pre-check before any activation commit: any existing row must
/// carry the exact presented input, and a `Fenced` or `Released` row is
/// reported (never reactivated) instead of overwritten.
fn check_activation_row(
    boundary: &DurableRootGrantBoundary,
    grant_id: &str,
    record: &OperationalRecordInput,
) -> Result<ActivationRow, KernelError> {
    let subject = OperationIdentity::new(grant_id).map_err(KernelError::RecoveryState)?;
    let existing = boundary
        .store
        .load_capability_grant(&subject)
        .map_err(|error| map_ors_recovery_error(&error))?;
    let Some(existing) = existing else {
        return Ok(ActivationRow::Absent);
    };
    match existing.phase() {
        OperationalPhase::Fenced | OperationalPhase::Released => Ok(ActivationRow::Fenced),
        OperationalPhase::Applying | OperationalPhase::Active => {
            if existing.record() != record {
                return Err(KernelError::InvalidField {
                    field: "grant_id",
                    reason: "grant identity is already recorded under a different input",
                });
            }
            if existing.phase() == OperationalPhase::Applying {
                Ok(ActivationRow::Applying)
            } else {
                Ok(ActivationRow::Active)
            }
        }
        _ => Err(KernelError::RecoveryUnavailable(
            "closure member ORS row is not activatable".to_owned(),
        )),
    }
}

/// Durable revision gate: advances the per-root watermark and refuses when a
/// newer revision already moved it further. The returned-watermark check
/// makes the stale refusal atomic with the advance: a re-presented revision
/// after a crash proceeds, while any lower revision fails closed even across
/// restarts.
fn check_closure_watermark(
    boundary: &DurableRootGrantBoundary,
    authority_root_ref: &str,
    grant_graph_revision: u64,
) -> Result<(), KernelError> {
    let root = OpaqueLabel::new(authority_root_ref).map_err(KernelError::RecoveryState)?;
    let stored = boundary
        .store
        .note_grant_graph_revision(&root, grant_graph_revision)
        .map_err(|error| map_ors_recovery_error(&error))?;
    if stored != grant_graph_revision {
        return Err(KernelError::InvalidField {
            field: "grant_graph_revision",
            reason: "stale grant-graph revision",
        });
    }
    Ok(())
}

/// Commits one closure row and verifies the exact read-back: the stored row
/// must reproduce the presented commit. A present row with the same commit
/// is an exact replay (crash between commit and install) and its stored
/// commit is returned; a present row with different content stays
/// fail-closed instead of overwriting.
fn ensure_closure_row(
    boundary: &DurableRootGrantBoundary,
    commit: &GrantClosureReceipt,
) -> Result<GrantClosureReceipt, KernelError> {
    let operation_id =
        OperationIdentity::new(&commit.operation_id).map_err(KernelError::RecoveryState)?;
    if let Some(existing) = boundary
        .store
        .load_grant_closure(&operation_id)
        .map_err(|error| map_ors_recovery_error(&error))?
    {
        if existing.commit() != commit {
            return Err(KernelError::RecoveryUnavailable(
                "durable closure row disagrees with the presented closure".to_owned(),
            ));
        }
        return Ok(existing.commit().clone());
    }
    let receipt = boundary
        .store
        .commit_grant_closure(commit.clone())
        .map_err(|error| map_ors_recovery_error(&error))?;
    let projection = boundary
        .store
        .load_grant_closure(&operation_id)
        .map_err(|error| map_ors_recovery_error(&error))?
        .ok_or_else(|| {
            KernelError::RecoveryUnavailable(
                "durable closure row disappeared during commit".to_owned(),
            )
        })?;
    if projection.commit() != commit || projection.receipt() != &receipt {
        return Err(KernelError::RecoveryUnavailable(
            "durable closure receipt/read-back disagreed".to_owned(),
        ));
    }
    Ok(commit.clone())
}

/// Durable pre-commit gates for the single-root activation path: the
/// per-root revision watermark and the restore-never-reactivates row check
/// (`#2100`). Both fail closed before the pending entry is staged.
fn check_activation_durability(
    boundary: &DurableRootGrantBoundary,
    intent: &GrantActivationIntent,
    record: &OperationalRecordInput,
) -> Result<(), eliot_authority::P07PortError> {
    check_closure_watermark(
        boundary,
        &intent.authority_root_ref,
        intent.grant_graph_revision,
    )
    .map_err(|error| map_thin_error(&error))?;
    match check_activation_row(boundary, &intent.grant_id, record) {
        Ok(ActivationRow::Fenced) => Err(eliot_authority::P07PortError::InvalidBinding),
        Ok(_) => Ok(()),
        Err(error) => Err(map_thin_error(&error)),
    }
}

/// Resolves an external delegation parent (a mid-chain anchor's parent
/// outside the enumeration, or an incremental delegation onto a recorded
/// parent) against live lineage or a durable row.
///
/// A recorded live grant must be active on the exact root and fence contour.
/// Otherwise, on the durable path, an `Active` durable row bound to the
/// presented fence and epoch attests the parent authority (e.g. after a
/// restart, before live rehydration). Fenced, released, expired (when an
/// observation time is given), missing, or contour-mismatched parents
/// refuse instead of fencing or activating underneath them.
#[allow(
    clippy::too_many_arguments,
    reason = "the external parent gate binds ledger, store, epoch, root, fence, and identity explicitly"
)]
fn resolve_external_parent(
    ledger: &PortLedger,
    boundary: Option<&DurableRootGrantBoundary>,
    active_epoch: &EpochId,
    authority_root_ref: &str,
    binding: &AuthorityBinding,
    parent_grant_id: &str,
    observation_ms: Option<i64>,
) -> Result<(), KernelError> {
    if let Some(record) = ledger.grants.get(parent_grant_id) {
        if record.authority_root_ref != authority_root_ref {
            return Err(KernelError::FenceMismatch);
        }
        if record.binding.state_fence != binding.state_fence {
            return Err(KernelError::FenceMismatch);
        }
        if record.status != LiveStatus::Active {
            return Err(KernelError::InvalidField {
                field: "enumeration.member.parent_grant_id",
                reason: "parent lineage is fenced",
            });
        }
        if let (Some(expires), Some(now_ms)) = (record.expires_at_ms, observation_ms)
            && expires <= now_ms
        {
            return Err(KernelError::InvalidField {
                field: "enumeration.member.parent_grant_id",
                reason: "parent lineage is expired",
            });
        }
        return Ok(());
    }
    if ledger.revoked_grants.contains(parent_grant_id) {
        return Err(KernelError::InvalidField {
            field: "enumeration.member.parent_grant_id",
            reason: "parent lineage is fenced",
        });
    }
    let Some(boundary) = boundary else {
        return Err(KernelError::InvalidField {
            field: "enumeration.member.parent_grant_id",
            reason: "unknown parent lineage",
        });
    };
    let subject = OperationIdentity::new(parent_grant_id).map_err(KernelError::RecoveryState)?;
    let projection = boundary
        .store
        .load_capability_grant(&subject)
        .map_err(|error| map_ors_recovery_error(&error))?
        .ok_or(KernelError::InvalidField {
            field: "enumeration.member.parent_grant_id",
            reason: "unknown parent lineage",
        })?;
    if projection.phase() != OperationalPhase::Active {
        return Err(KernelError::InvalidField {
            field: "enumeration.member.parent_grant_id",
            reason: "parent lineage is fenced",
        });
    }
    check_opaque_record_binding(projection.record(), binding, active_epoch)?;
    Ok(())
}

fn live_closure_introduction_ids(ledger: &PortLedger, affected: &[String]) -> Vec<String> {
    let affected = affected.iter().map(String::as_str).collect::<BTreeSet<_>>();
    ledger
        .introductions
        .iter()
        .filter(|(_, introduction)| {
            introduction.status == LiveStatus::Active
                && introduction
                    .supporting_grant_ids
                    .iter()
                    .any(|grant_id| affected.contains(grant_id.as_str()))
        })
        .map(|(introduction_id, _)| introduction_id.clone())
        .collect()
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
    mode: IntroductionActivationMode,
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
    if mode == IntroductionActivationMode::Fresh
        && ledger.introductions.contains_key(&request.introduction_id)
    {
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

/// Revalidates one exact committed introduction before an idempotent return.
///
/// This is deliberately read-only. It reuses the normal introduction
/// validation gate for every authority field, supporting-grant fence,
/// durable watermark, expiry, and ceiling; then it re-reads the ORS row,
/// re-enumerates the relevant committed closure introduction-fence set, and
/// proves the stored live projection and authority receipt are still the exact active
/// disposition. No ORS transition, watermark advance, or live-state mutation
/// occurs on this path.
fn revalidate_committed_introduction_activation(
    boundary: &DurableRootGrantBoundary,
    ledger: &PortLedger,
    hydration: &IntroductionHydration,
    active_epoch: &EpochId,
    now_ms: i64,
    disposition: IntentDisposition,
) -> Result<AuthorityActivationReceipt, KernelError> {
    let request = &hydration.intent;
    let support = request
        .supporting_grant_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let revoked = revoked_support_in_ledger(ledger, &request.supporting_grant_ids);
    if !revoked.is_disjoint(&support) {
        return Err(KernelError::InvalidField {
            field: "supporting_grant_ids",
            reason: "supporting lineage is fenced",
        });
    }
    validate_introduction_activation(
        request,
        ledger,
        active_epoch,
        now_ms,
        IntroductionActivationMode::Replay,
    )?;
    verify_introduction_seal(&hydration.durable_record, request, active_epoch)?;

    let live = ledger
        .introductions
        .get(&request.introduction_id)
        .ok_or_else(|| {
            KernelError::RecoveryUnavailable(
                "committed introduction is absent from the live projection during replay"
                    .to_owned(),
            )
        })?;
    if live.authority_root_ref != request.authority_root_ref || live.supporting_grant_ids != support
    {
        return Err(KernelError::RecoveryUnavailable(
            "committed introduction live projection disagrees with its stored operation".to_owned(),
        ));
    }
    if live.status == LiveStatus::Revoked {
        return Err(KernelError::IllegalTransition {
            machine: "capability-introduction",
            from: "Fenced".to_owned(),
            to: "Active".to_owned(),
        });
    }

    revalidate_committed_introduction_row(boundary, hydration)?;

    revalidate_relevant_closure_introduction_fences(
        boundary,
        ledger,
        &support,
        &request.introduction_id,
    )?;

    check_committed_introduction_watermark(
        boundary,
        &request.authority_root_ref,
        request.grant_graph_revision,
    )?;
    let stored = disposition.into_activation_receipt()?;
    let expected = runtime_introduction_activation_receipt(request, active_epoch)?;
    if stored != expected {
        return Err(KernelError::IdempotencyConflict);
    }
    Ok(stored)
}

/// Re-enumerates the complete introduction-fence set of every committed
/// closure that intersects this introduction or its current support. Each
/// durable fence is re-derived through the atomic closure path and matched to
/// the immutable ORS reference already stored in that closure receipt.
fn revalidate_relevant_closure_introduction_fences(
    boundary: &DurableRootGrantBoundary,
    ledger: &PortLedger,
    supporting_grants: &BTreeSet<String>,
    introduction_id: &str,
) -> Result<(), KernelError> {
    for record in ledger.intents.values() {
        let Some(commit) = &record.closure_receipt else {
            continue;
        };
        let affects_support = commit
            .declaration
            .members
            .iter()
            .any(|member| supporting_grants.contains(member.grant_id.as_str()));
        let fences_introduction = commit
            .fenced_introductions
            .iter()
            .any(|fenced| fenced == introduction_id);
        if !affects_support && !fences_introduction {
            continue;
        }
        let fences = closure_introduction_fences(
            boundary,
            &commit.fenced_introductions,
            &commit.operation_id,
        )?;
        if fences.len() != commit.fenced_introductions.len()
            || fences
                .iter()
                .zip(&commit.ors_introduction_receipts)
                .any(|(fence, expected)| {
                    fence.record().record_id.as_str() != expected.record_id.as_str()
                        || fence.record().subject_id.as_str() != expected.subject_id.as_str()
                })
        {
            return Err(KernelError::RecoveryUnavailable(
                "committed closure introduction-fence set is incomplete".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Re-reads the immutable introduction row and requires the exact active
/// presentation that the stored activation receipt committed.
fn revalidate_committed_introduction_row(
    boundary: &DurableRootGrantBoundary,
    hydration: &IntroductionHydration,
) -> Result<(), KernelError> {
    let subject = OperationIdentity::new(&hydration.intent.introduction_id)
        .map_err(KernelError::RecoveryState)?;
    let existing = boundary
        .store
        .load_capability_introduction(&subject)
        .map_err(|error| map_ors_recovery_error(&error))?
        .ok_or_else(|| {
            KernelError::RecoveryUnavailable(
                "committed introduction projection is absent during replay".to_owned(),
            )
        })?;
    if existing.phase() == OperationalPhase::Fenced {
        return Err(KernelError::IllegalTransition {
            machine: "capability-introduction",
            from: "Fenced".to_owned(),
            to: "Active".to_owned(),
        });
    }
    if existing.phase() != OperationalPhase::Active
        || existing.record() != hydration.durable_record.record()
    {
        return Err(KernelError::RecoveryUnavailable(
            "committed introduction row is not the exact active replay state".to_owned(),
        ));
    }
    Ok(())
}

/// Checks the durable graph head without advancing it. Exact replay is
/// read-only, but it still refuses once any later root revision has won.
fn check_committed_introduction_watermark(
    boundary: &DurableRootGrantBoundary,
    authority_root_ref: &str,
    grant_graph_revision: u64,
) -> Result<(), KernelError> {
    let root = OpaqueLabel::new(authority_root_ref).map_err(KernelError::RecoveryState)?;
    match boundary
        .store
        .load_grant_graph_revision(&root)
        .map_err(|error| map_ors_recovery_error(&error))?
    {
        Some(current) if current == grant_graph_revision => Ok(()),
        Some(current) if current > grant_graph_revision => Err(KernelError::InvalidField {
            field: "grant_graph_revision",
            reason: "stale grant-graph revision",
        }),
        Some(_) => Err(KernelError::RecoveryUnavailable(
            "durable graph revision is behind the committed introduction".to_owned(),
        )),
        None => Err(KernelError::RecoveryUnavailable(
            "durable graph revision is absent for a committed introduction".to_owned(),
        )),
    }
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

/// The durable root replay identity includes the exact opaque ORS input in
/// addition to the semantic grant intent.  This keeps a changed encrypted
/// payload, epoch lineage contour, or captured State Fence from becoming an
/// in-process replay after restart.
#[derive(Serialize)]
struct RootGrantDurableDigestView<'a> {
    intent: GrantActivationDigestView<'a>,
    durable_record: &'a OperationalRecordInput,
}

/// Canonical digest bytes for one grant-revocation payload.
#[derive(Serialize)]
#[cfg(test)]
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

/// Canonical digest bytes for one closure member: the semantic intent plus
/// the exact opaque ORS record, so a changed encrypted payload under one
/// member identity is a conflict rather than a replay.
#[derive(Serialize)]
struct GrantClosureMemberDigestView<'a> {
    intent: GrantActivationDigestView<'a>,
    durable_record: &'a OperationalRecordInput,
    observed_at_ms: i64,
}

/// Canonical digest bytes for one closure-activation payload. Members enter
/// in enumeration (parent-before-child) order, so a reordered enumeration is
/// a different payload.
#[derive(Serialize)]
struct GrantClosureActivationDigestView<'a> {
    kind: &'static str,
    operation_id: &'a str,
    authority_root_ref: &'a str,
    grant_graph_revision: u64,
    members: Vec<GrantClosureMemberDigestView<'a>>,
    preserved: BTreeSet<&'a GrantClosureSurvivor>,
}

/// Canonical digest bytes for one closure-revocation payload. The affected
/// set and survivors enter as sorted sets, so re-derivation after a restart
/// reproduces the same digest while any changed member is a typed conflict.
#[derive(Serialize)]
struct GrantClosureRevocationDigestView<'a> {
    kind: &'static str,
    operation_id: &'a str,
    target_grant_id: &'a str,
    authority_root_ref: &'a str,
    snapshot_id: &'a str,
    grant_graph_revision: u64,
    binding: &'a AuthorityBinding,
    affected: BTreeSet<&'a str>,
    member_fence_records: Vec<&'a OperationalRecordInput>,
    fenced_introductions: BTreeSet<&'a str>,
    fenced_introduction_records: Vec<&'a OperationalRecordInput>,
    preserved: BTreeSet<&'a GrantClosureSurvivor>,
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
    fn digest_view(&self) -> GrantActivationDigestView<'_> {
        GrantActivationDigestView {
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
        }
    }

    #[cfg(test)]
    fn digest(&self) -> Result<String, KernelError> {
        finalize_digest(&self.digest_view())
    }
}

fn hydrated_root_grant_digest(hydration: &RootGrantHydration) -> Result<String, KernelError> {
    finalize_digest(&RootGrantDurableDigestView {
        intent: hydration.intent.digest_view(),
        durable_record: hydration.durable_record.record(),
    })
}

fn hydrated_grant_member_digest(hydration: &GrantClosureMember) -> Result<String, KernelError> {
    finalize_digest(&RootGrantDurableDigestView {
        intent: hydration.intent.digest_view(),
        durable_record: hydration.durable_record.record(),
    })
}

/// Binds one closure operation identity to the complete owner-enumerated
/// closure: every member intent, every opaque ORS record, and the survivor
/// set. Reordered members, changed payloads, or a changed survivor set under
/// one identity are conflicts, never replays.
fn closure_activation_digest(
    operation_id: &str,
    enumeration: &GrantClosureEnumeration,
) -> Result<String, KernelError> {
    finalize_digest(&GrantClosureActivationDigestView {
        kind: "grant-closure-activation",
        operation_id,
        authority_root_ref: &enumeration.authority_root_ref,
        grant_graph_revision: enumeration.grant_graph_revision,
        members: enumeration
            .members
            .iter()
            .map(|member| GrantClosureMemberDigestView {
                intent: member.intent.digest_view(),
                durable_record: member.durable_record.record(),
                observed_at_ms: member.observed_at_ms,
            })
            .collect(),
        preserved: enumeration.preserved.iter().collect(),
    })
}

/// Binds one closure revocation identity to the target, the exact revision,
/// the complete affected set, and the survivor set. Re-derivation through the
/// owner enumeration after a restart reproduces the same digest.
fn closure_revocation_digest(
    request: &GrantClosureRevocationIntent,
    derived: &DerivedClosureFence,
) -> Result<String, KernelError> {
    finalize_digest(&GrantClosureRevocationDigestView {
        kind: "grant-closure-revocation",
        operation_id: &request.operation_id,
        target_grant_id: &request.grant_id,
        authority_root_ref: &request.authority_root_ref,
        snapshot_id: &request.snapshot_id,
        grant_graph_revision: request.grant_graph_revision,
        binding: &request.binding,
        affected: derived.affected.iter().map(String::as_str).collect(),
        member_fence_records: derived
            .members
            .iter()
            .map(|member| &member.fence_input)
            .collect(),
        fenced_introductions: derived
            .fenced_introductions
            .iter()
            .map(String::as_str)
            .collect(),
        fenced_introduction_records: derived.fenced_introduction_records.iter().collect(),
        preserved: derived.preserved.iter().collect(),
        unknown_outcome_operations: request
            .unknown_outcome_operations
            .iter()
            .map(String::as_str)
            .collect(),
        receipt_obligations: request
            .receipt_obligations
            .iter()
            .map(String::as_str)
            .collect(),
    })
}

#[cfg(test)]
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
    fn digest_view(&self) -> IntroductionActivationDigestView<'_> {
        IntroductionActivationDigestView {
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
        }
    }

    #[cfg(test)]
    fn digest(&self) -> Result<String, KernelError> {
        finalize_digest(&self.digest_view())
    }
}

/// The durable introduction replay identity includes the exact opaque ORS
/// input in addition to the semantic intent, mirroring the root-grant
/// durable digest: a changed encrypted payload under one introduction
/// identity is a conflict rather than a replay.
#[derive(Serialize)]
struct IntroductionDurableDigestView<'a> {
    intent: IntroductionActivationDigestView<'a>,
    durable_record: &'a OperationalRecordInput,
}

fn hydrated_introduction_digest(hydration: &IntroductionHydration) -> Result<String, KernelError> {
    finalize_digest(&IntroductionDurableDigestView {
        intent: hydration.intent.digest_view(),
        durable_record: hydration.durable_record.record(),
    })
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
//   Delegated-descendant activation and revocation flow through the closure
//   wave (`#2100`) in this same file; delegated introductions remain outside
//   the durable slice.
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
// here. The durable descendant-closure wave (`#2100`, lane C) lives in this
// same file beside Slice A: `activate_grant_closure`,
// `revoke_grant_closure`, `recover_grant_closure_activation`, and
// `recover_grant_closure_revocation` enumerate the complete closure through
// the injected Governor boundary at one exact revision, fence per member
// through ORS with read-back, and record one `GrantClosureReceipt`.
// Child/delegated introductions and incremental delegation onto already
// recorded parents remain explicit residuals for follow-up waves; nothing
// here claims them.
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

fn runtime_introduction_activation_receipt(
    intent: &IntroductionActivationIntent,
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
            closure_receipt: None,
            closure_member_receipts: Vec::new(),
        },
    );
}

fn validate_member_hydration(
    hydration: &GrantClosureMember,
    request: &eliot_authority::GrantActivationRequest,
    active_epoch: &EpochId,
) -> Result<(), KernelError> {
    let expected_operation_id = thin_operation_id(
        "activate-grant",
        request.grant_id.as_str(),
        request.snapshot_id.as_str(),
        active_epoch,
    );
    if hydration.intent.grant_id != request.grant_id.as_str()
        || hydration.intent.snapshot_id != request.snapshot_id.as_str()
        || hydration.intent.binding != request.binding
        || hydration.intent.operation_id != expected_operation_id
    {
        return Err(KernelError::InvalidField {
            field: "grant_activation",
            reason: "owner member hydration disagrees with the thin request",
        });
    }
    verify_grant_seal(&hydration.durable_record, &hydration.intent, active_epoch)
}

fn validate_rehydrated_root_grant(
    hydration: &RootGrantHydration,
    projection: &CapabilityGrantProjection,
    active_epoch: &EpochId,
) -> Result<(), KernelError> {
    hydration.validate_fields(active_epoch)?;
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
    check_exact_epoch_lineage(
        &input.authority_epoch,
        &binding.authority_epoch,
        active_epoch,
    )?;
    input
        .authority_epoch
        .validate()
        .map_err(|_| KernelError::FenceMismatch)?;
    input
        .state_fence
        .validate_against_lineage(&input.authority_epoch)
        .map_err(|_| KernelError::FenceMismatch)?;
    input.state_fence.validate_against_epoch(active_epoch)?;
    let expected_fence =
        StateFenceSnapshot::capture(&binding.state_fence, active_epoch.sequence.get())?;
    if input.state_fence != expected_fence {
        return Err(KernelError::FenceMismatch);
    }
    Ok(())
}

/// Proves the opaque↔intent seal for one presented grant record: the exact
/// identity contour plus full shape/integrity revalidation.
///
/// The contour binds the opaque bytes to the admitted intent (record and
/// subject identities must name the intent's operation and grant).
/// Integrity and shape re-run exactly the ORS construction validation
/// (epoch/fence agreement, payload length/SHA-256, secret-reference shape,
/// expiry) by reconstructing the typed record: presented bytes are proven
/// before they become the trust anchor, and ORS revalidates again on every
/// read. Epoch/fence agreement against the active epoch follows.
///
/// # Errors
///
/// Returns [`KernelError::InvalidField`] for a contour disagreement or a
/// malformed record, and [`KernelError::FenceMismatch`] for a stale,
/// future, or cross-lineage epoch or fence.
pub fn verify_grant_seal(
    record: &CapabilityGrantActivation,
    intent: &GrantActivationIntent,
    active_epoch: &EpochId,
) -> Result<(), KernelError> {
    if record.record().record_id.as_str() != intent.operation_id
        || record.record().subject_id.as_str() != intent.grant_id
    {
        return Err(KernelError::InvalidField {
            field: "durable_record",
            reason: "opaque record identity disagrees with the admitted grant intent",
        });
    }
    CapabilityGrantActivation::new(record.record().clone()).map_err(|_| {
        KernelError::InvalidField {
            field: "durable_record",
            reason: "opaque grant record failed seal validation",
        }
    })?;
    check_opaque_record_binding(record.record(), &intent.binding, active_epoch)
}

/// Proves the opaque↔intent seal for one presented introduction record,
/// mirroring [`verify_grant_seal`]: exact identity contour, full
/// shape/integrity reconstruction, then epoch/fence agreement.
///
/// # Errors
///
/// Returns [`KernelError::InvalidField`] for a contour disagreement or a
/// malformed record, and [`KernelError::FenceMismatch`] for a stale,
/// future, or cross-lineage epoch or fence.
pub fn verify_introduction_seal(
    record: &CapabilityIntroductionActivation,
    intent: &IntroductionActivationIntent,
    active_epoch: &EpochId,
) -> Result<(), KernelError> {
    if record.record().record_id.as_str() != intent.operation_id
        || record.record().subject_id.as_str() != intent.introduction_id
    {
        return Err(KernelError::InvalidField {
            field: "durable_record",
            reason: "opaque record identity disagrees with the admitted introduction intent",
        });
    }
    CapabilityIntroductionActivation::new(record.record().clone()).map_err(|_| {
        KernelError::InvalidField {
            field: "durable_record",
            reason: "opaque introduction record failed seal validation",
        }
    })?;
    check_opaque_record_binding(record.record(), &intent.binding, active_epoch)
}

/// Binds the persisted ORS lineage contour to both the canonical binding and
/// the caller's current epoch.  The predecessor is validated as part of the
/// same structured lineage; comparing only the current string/sequence pair
/// would allow a changed lineage edge to survive replay.
fn check_exact_epoch_lineage(
    record_lineage: &eliot_ors::EpochLineage,
    binding_epoch: &EpochId,
    active_epoch: &EpochId,
) -> Result<(), KernelError> {
    if record_lineage.current.lineage_id.as_str() != binding_epoch.lineage_id.as_str()
        || record_lineage.current.epoch != binding_epoch.sequence.get()
        || !binding_epoch.is_same_authority(active_epoch)
    {
        return Err(KernelError::FenceMismatch);
    }
    Ok(())
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

fn map_ors_recovery_error(error: &eliot_ors::OrsError) -> KernelError {
    match error {
        eliot_ors::OrsError::InvalidEpochLineage | eliot_ors::OrsError::FenceMismatch => {
            KernelError::FenceMismatch
        }
        eliot_ors::OrsError::DuplicateConflict => KernelError::IdempotencyConflict,
        _ => KernelError::RecoveryUnavailable(error.to_string()),
    }
}

/// Maps an introduction-row ORS failure to the typed port refusal.
///
/// An [`OrsError::InvalidTransition`](eliot_ors::OrsError::InvalidTransition)
/// is the explicit state-machine guard: the row exists under different
/// authority, so the transition refuses with its exact machine and phase
/// names instead of a generic recovery error. The `from` phase is re-read
/// from the row so a raced duplicate reports the phase that actually won.
/// Every other failure keeps the recovery mapping.
fn map_introduction_transition_error(
    error: &eliot_ors::OrsError,
    subject: &OperationIdentity,
    boundary: &DurableRootGrantBoundary,
    to: &'static str,
) -> KernelError {
    if matches!(error, eliot_ors::OrsError::InvalidTransition) {
        let from = boundary
            .store
            .load_capability_introduction(subject)
            .ok()
            .flatten()
            .map_or("committed", |row| match row.phase() {
                eliot_ors::OperationalPhase::Active => "Active",
                eliot_ors::OperationalPhase::Fenced => "Fenced",
                _ => "committed",
            });
        return KernelError::IllegalTransition {
            machine: "capability-introduction",
            from: from.to_owned(),
            to: to.to_owned(),
        };
    }
    map_ors_recovery_error(error)
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
        | KernelError::StaleEpochTuple { .. }
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
        if let Some(boundary) = self.durable_boundary() {
            return self.activate_root_grant_durable(request, &active_epoch, boundary);
        }
        #[cfg(not(test))]
        return Err(P07PortError::Unavailable);
        #[cfg(test)]
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
        #[cfg(test)]
        Err(P07PortError::Unavailable)
    }

    fn revoke_grant(
        &self,
        request: &eliot_authority::GrantRevocationRequest,
    ) -> Result<AuthorityRevocationReceipt, eliot_authority::P07PortError> {
        use eliot_authority::P07PortError;
        let active_epoch = request.binding.authority_epoch.clone();
        // Caller-material rejection runs before the owner is consulted: a
        // malformed, split-epoch or stale-epoch binding never reaches the
        // closure enumeration, the intent ledger, or ORS.
        if let Err(error) = check_binding(&request.binding, &active_epoch) {
            return Err(map_thin_error(&error));
        }
        if let Some(boundary) = self.durable_boundary() {
            // Owner-governed dispatch (`#2100`): the Governor enumeration
            // owner always governs — a singleton is the owner's leaf
            // attestation, so every bound enumeration takes the closure gate.
            // An unavailable enumeration is a typed refusal: the root-only
            // fallback is removed because a root fence can never prove
            // descendant completeness without the owner, and the port cannot
            // read descendant lineage from opaque ORS rows. The caller
            // re-presents through a bound canonical owner.
            let enumeration = boundary
                .hydration
                .enumerate_grant_closure(request.grant_id.as_str())
                .map_err(|error| map_thin_error(&error))?;
            return self.revoke_grant_closure_durable_thin(
                request,
                &active_epoch,
                boundary,
                &enumeration,
            );
        }
        #[cfg(not(test))]
        return Err(P07PortError::Unavailable);
        #[cfg(test)]
        let rich = {
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
        #[cfg(test)]
        return self.revoke_grant(&rich, active_epoch).map_err(|error| {
            // Typed refusal: fence/epoch/expiry is a Kernel admission
            // refusal, inconsistent caller material is a binding failure, and
            // only a missing durable owner stays unavailable. The caller
            // re-presents through a current Governor snapshot.
            map_thin_error(&error)
        });
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
        // Owner-hydrated durable activation (`#2100`/`#1110`): the Governor
        // introduction-hydration owner resolves the thin request to the
        // complete admitted intent plus its opaque ORS record, and the
        // durable gate validates identity, fence, and lifecycle agreement
        // before any mutation — mirroring the grant hydration gate with the
        // hydration's own observation time. Without the owner the request
        // stays fail-closed: a thin introduction request carries no
        // supporting grants, facet, holder, or revision, and I6.15 forbids
        // this port from creating lineage.
        let Some(boundary) = self.durable_boundary() else {
            return Err(P07PortError::Unavailable);
        };
        let hydration = boundary
            .hydration
            .hydrate_introduction(request)
            .map_err(|error| map_thin_error(&error))?;
        self.activate_introduction_durable(&hydration, &active_epoch, hydration.observed_at_ms)
            .map_err(|error| map_thin_error(&error))
    }

    fn revoke_introduction(
        &self,
        request: &eliot_authority::IntroductionRevocationRequest,
    ) -> Result<AuthorityRevocationReceipt, eliot_authority::P07PortError> {
        use eliot_authority::P07PortError;
        let active_epoch = request.binding.authority_epoch.clone();
        check_binding(&request.binding, &active_epoch).map_err(|error| map_thin_error(&error))?;
        let boundary = self.durable_boundary().ok_or(P07PortError::Unavailable)?;
        let hydration_request = eliot_authority::IntroductionActivationRequest {
            introduction_id: request.introduction_id.clone(),
            snapshot_id: request.snapshot_id.clone(),
            binding: request.binding.clone(),
        };
        let hydration = boundary
            .hydration
            .hydrate_introduction(&hydration_request)
            .map_err(|error| map_thin_error(&error))?;
        let rich = IntroductionRevocationIntent {
            operation_id: thin_operation_id(
                "revoke-introduction",
                request.introduction_id.as_str(),
                request.snapshot_id.as_str(),
                &active_epoch,
            ),
            introduction_id: request.introduction_id.as_str().to_owned(),
            authority_root_ref: hydration.intent.authority_root_ref.clone(),
            snapshot_id: request.snapshot_id.as_str().to_owned(),
            grant_graph_revision: hydration.intent.grant_graph_revision,
            binding: request.binding.clone(),
            unknown_outcome_operations: Vec::new(),
            receipt_obligations: Vec::new(),
        };
        self.revoke_introduction_durable(&rich, &active_epoch)
            .map_err(|error| map_thin_error(&error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::EpochLineageId;
    use std::num::NonZeroU64;
    use std::sync::Mutex;

    /// Canonical request digest carried by every declared alternate path in
    /// this module. No assertion compares it, and no test builds the request
    /// it would digest, so the fixture pins one shape-valid value instead of
    /// inventing a request.
    const PRESERVED_REQUEST_HASH: &str =
        "3f9a1c7d5e2b8a04c6d1f37e5b9042a8c6d0e3f75a1b2c3d4e5f60718293a4b5";

    /// Builds the owner-declared exact-use alternate path between a preserved
    /// descendant and its live cover.
    ///
    /// Every field is internally consistent with the closure fixture: the exact
    /// use is the member hydration's own `op.read` operation on `res:1` at the
    /// `Read` effect, admitted for the same principal, session, and scope the
    /// [`closure_member_fixture`] members carry, so the production
    /// `prove_survivor_membership` contour checks agree with the declaration.
    fn preserved_survivor_fixture(
        grant_id: &str,
        covering_grant_id: &str,
        covering_root_ref: &str,
    ) -> GrantClosureSurvivor {
        GrantClosureSurvivor {
            grant_id: grant_id.to_owned(),
            covering_grant_id: covering_grant_id.to_owned(),
            covering_root_ref: covering_root_ref.to_owned(),
            operation_id: "op-side-preserved-use".to_owned(),
            operation_name: "op.read".to_owned(),
            resource_ref: "res:1".to_owned(),
            effect: EffectClass::Read,
            holder_principal: "holder-1".to_owned(),
            session_id: "session-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            canonical_request_hash: PRESERVED_REQUEST_HASH.to_owned(),
        }
    }

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

        fn enumerate_grant_closure(
            &self,
            grant_id: &str,
        ) -> Result<GrantClosureEnumeration, KernelError> {
            // Single-root fixture attestation (`#2100`): the fixture owner
            // attests exactly its one admitted root as a singleton closure,
            // so thin revocations prove leaf completeness through the closure
            // gate instead of a root-only fallback. Unknown identities stay
            // a typed refusal, never an empty closure.
            if grant_id != self.value.intent.grant_id {
                return Err(KernelError::RecoveryUnavailable(
                    "fixture owner admits no closure for the requested grant".to_owned(),
                ));
            }
            Ok(GrantClosureEnumeration {
                authority_root_ref: self.value.intent.authority_root_ref.clone(),
                grant_graph_revision: self.value.intent.grant_graph_revision,
                members: vec![GrantClosureMember {
                    intent: self.value.intent.clone(),
                    durable_record: self.value.durable_record.clone(),
                    observed_at_ms: self.value.observed_at_ms,
                }],
                preserved: Vec::new(),
            })
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
    #[allow(
        clippy::too_many_lines,
        reason = "the mismatch, absence, and exact single-grant fence proof keeps its sequence visible"
    )]
    fn durable_root_revocation_refuses_mismatch_without_live_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        use eliot_authority::{P07AuthorityPort, P07PortError};
        use std::sync::{Arc, Mutex};

        struct MutableRootHydration {
            value: Mutex<RootGrantHydration>,
        }

        impl MutableRootHydration {
            fn replace(&self, value: RootGrantHydration) {
                *self
                    .value
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = value;
            }
        }

        impl RootGrantHydrationSource for MutableRootHydration {
            fn hydrate_root_grant(
                &self,
                _request: &eliot_authority::GrantActivationRequest,
            ) -> Result<RootGrantHydration, KernelError> {
                Ok(self
                    .value
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone())
            }

            fn rehydrate_root_grant(
                &self,
                _projection: &CapabilityGrantProjection,
            ) -> Result<RootGrantHydration, KernelError> {
                Ok(self
                    .value
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone())
            }

            fn enumerate_grant_closure(
                &self,
                grant_id: &str,
            ) -> Result<GrantClosureEnumeration, KernelError> {
                // Single-root fixture attestation (`#2100`): mirrors
                // `TestRootHydration` so the tampered value is attested
                // consistently and the closure gate refuses on the durable
                // row disagreement instead of fencing a caller narrative.
                let value = self
                    .value
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                if grant_id != value.intent.grant_id {
                    return Err(KernelError::RecoveryUnavailable(
                        "fixture owner admits no closure for the requested grant".to_owned(),
                    ));
                }
                Ok(GrantClosureEnumeration {
                    authority_root_ref: value.intent.authority_root_ref.clone(),
                    grant_graph_revision: value.intent.grant_graph_revision,
                    members: vec![GrantClosureMember {
                        intent: value.intent.clone(),
                        durable_record: value.durable_record.clone(),
                        observed_at_ms: value.observed_at_ms,
                    }],
                    preserved: Vec::new(),
                })
            }
        }

        let epoch = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 7)?;
        let binding = restart_test_binding(&epoch)?;
        let (request, hydration) = durable_root_fixture(&epoch, &binding)?;
        let revoke = eliot_authority::GrantRevocationRequest {
            grant_id: request.grant_id.clone(),
            snapshot_id: request.snapshot_id.clone(),
            binding: request.binding.clone(),
        };
        let revoke_operation_id = thin_operation_id(
            "revoke-grant",
            revoke.grant_id.as_str(),
            revoke.snapshot_id.as_str(),
            &epoch,
        );
        let path = std::env::temp_dir().join(format!(
            "eliot-kernel-root-grant-revoke-mismatch-{}-{}.redb",
            std::process::id(),
            epoch.sequence
        ));
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(eliot_ors::RedbRecoveryStore::open(&path)?);
        let hydration_source = Arc::new(MutableRootHydration {
            value: Mutex::new(hydration.clone()),
        });
        let port =
            GrantActivationPort::with_durable_root_grant(hydration_source.clone(), store.clone());

        P07AuthorityPort::activate_grant(&port, &request)
            .map_err(|error| format!("durable activation failed: {error:?}"))?;
        let subject = eliot_ors::OperationIdentity::new("grant-root")?;
        let active = store
            .load_capability_grant(&subject)?
            .ok_or("active capability projection missing")?;
        assert_eq!(active.phase(), OperationalPhase::Active);

        let mut tampered = hydration.clone();
        let key = match &tampered.durable_record.record().payload {
            eliot_ors::RecoveryPayload::Encrypted { key, .. } => key.clone(),
            eliot_ors::RecoveryPayload::ImmutableLocator { .. } => {
                return Err("fixture must use an encrypted root-grant payload".into());
            }
        };
        let ciphertext = b"changed-root-grant-revocation-record".to_vec();
        let mut record = tampered.durable_record.record().clone();
        record.payload = eliot_ors::RecoveryPayload::Encrypted {
            key,
            ciphertext: ciphertext.clone(),
        };
        record.payload_length = ciphertext.len() as u64;
        record.payload_sha256 = eliot_contracts::sha256_hex(&ciphertext);
        tampered.durable_record = CapabilityGrantActivation::new(record)?;
        hydration_source.replace(tampered);

        assert!(matches!(
            P07AuthorityPort::revoke_grant(&port, &revoke),
            Err(P07PortError::Unavailable | P07PortError::InvalidBinding)
        ));
        assert!(!port.grant_revoked("grant-root"));
        assert!(port.disposition(&revoke_operation_id).is_none());
        assert!(port.revocation_closure(&revoke_operation_id).is_none());
        assert!(port.reconciling_operations().is_empty());
        let active_after_mismatch = store
            .load_capability_grant(&subject)?
            .ok_or("mismatch refusal removed the capability projection")?;
        assert_eq!(active_after_mismatch.phase(), OperationalPhase::Active);
        assert_eq!(active_after_mismatch.record(), active.record());
        assert_eq!(active_after_mismatch.receipt(), active.receipt());

        let missing_path = std::env::temp_dir().join(format!(
            "eliot-kernel-root-grant-revoke-missing-{}-{}.redb",
            std::process::id(),
            epoch.sequence
        ));
        let _ = std::fs::remove_file(&missing_path);
        let missing_store = Arc::new(eliot_ors::RedbRecoveryStore::open(&missing_path)?);
        let missing_port = GrantActivationPort::with_durable_root_grant(
            hydration_source.clone(),
            missing_store.clone(),
        );
        assert!(matches!(
            P07AuthorityPort::revoke_grant(&missing_port, &revoke),
            Err(P07PortError::Unavailable)
        ));
        assert!(!missing_port.grant_revoked("grant-root"));
        assert!(missing_port.disposition(&revoke_operation_id).is_none());
        assert!(
            missing_port
                .revocation_closure(&revoke_operation_id)
                .is_none()
        );
        assert!(missing_port.reconciling_operations().is_empty());
        assert!(missing_store.load_capability_grant(&subject)?.is_none());

        hydration_source.replace(hydration);
        let revoked = P07AuthorityPort::revoke_grant(&port, &revoke)
            .map_err(|error| format!("durable revoke failed: {error:?}"))?;
        assert!(matches!(revoked.state, AuthorityState::Revoked));
        assert!(port.grant_revoked("grant-root"));
        assert_eq!(
            port.revocation_closure(&revoke_operation_id),
            Some(vec!["grant-root".to_owned()])
        );
        assert_eq!(
            store
                .load_capability_grant(&subject)?
                .ok_or("successful revoke removed the capability projection")?
                .phase(),
            OperationalPhase::Fenced
        );

        let revoked_state = revoked.state;
        let fenced_projection = store
            .load_capability_grant(&subject)?
            .ok_or("fenced capability projection missing after revoke")?;
        let fenced_record = fenced_projection.record().clone();
        let fenced_receipt = fenced_projection.receipt().clone();
        let fenced_closure = port
            .revocation_closure(&revoke_operation_id)
            .ok_or("successful revoke closure missing")?;
        let fenced_disposition = port
            .disposition(&revoke_operation_id)
            .ok_or("successful revoke disposition missing")?;

        let revoke_replay = P07AuthorityPort::revoke_grant(&port, &revoke)
            .map_err(|error| format!("in-process revoke replay failed: {error:?}"))?;
        assert_eq!(revoke_replay, revoked);
        assert_eq!(revoke_replay.state, revoked_state);
        let replayed_projection = store
            .load_capability_grant(&subject)?
            .ok_or("revoke replay removed the capability projection")?;
        assert_eq!(replayed_projection, fenced_projection);
        assert_eq!(replayed_projection.record(), &fenced_record);
        assert_eq!(replayed_projection.receipt(), &fenced_receipt);
        assert_eq!(
            port.revocation_closure(&revoke_operation_id),
            Some(fenced_closure.clone())
        );
        assert_eq!(
            port.disposition(&revoke_operation_id),
            Some(fenced_disposition.clone())
        );
        assert!(port.reconciling_operations().is_empty());

        drop(missing_port);
        drop(missing_store);
        drop(port);
        drop(store);

        let reopened_store = Arc::new(eliot_ors::RedbRecoveryStore::open(&path)?);
        let reopened_port =
            GrantActivationPort::with_durable_root_grant(hydration_source, reopened_store.clone());
        let restart_replay = P07AuthorityPort::revoke_grant(&reopened_port, &revoke)
            .map_err(|error| format!("restart revoke replay failed: {error:?}"))?;
        assert_eq!(restart_replay, revoked);
        assert!(matches!(restart_replay.state, AuthorityState::Revoked));
        assert!(reopened_port.grant_revoked("grant-root"));
        let restarted_projection = reopened_store
            .load_capability_grant(&subject)?
            .ok_or("restart revoke replay removed the capability projection")?;
        assert_eq!(restarted_projection, fenced_projection);
        assert_eq!(restarted_projection.phase(), OperationalPhase::Fenced);
        assert_eq!(restarted_projection.record(), &fenced_record);
        assert_eq!(restarted_projection.receipt(), &fenced_receipt);
        assert_eq!(fenced_closure, vec!["grant-root".to_owned()]);
        assert_eq!(
            reopened_port.revocation_closure(&revoke_operation_id),
            Some(fenced_closure.clone())
        );
        assert_eq!(
            reopened_port.disposition(&revoke_operation_id),
            Some(fenced_disposition.clone())
        );
        assert!(reopened_port.reconciling_operations().is_empty());

        drop(reopened_port);
        drop(reopened_store);
        let _ = std::fs::remove_file(missing_path);
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the restart/replay/revocation edge proof keeps its exact sequence visible"
    )]
    fn durable_root_activation_replay_recovery_and_revoke_are_exact()
    -> Result<(), Box<dyn std::error::Error>> {
        use eliot_authority::{P07AuthorityPort, P07PortError};
        use std::sync::Arc;

        let epoch = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 7)?;
        let binding = restart_test_binding(&epoch)?;
        let (request, hydration) = durable_root_fixture(&epoch, &binding)?;
        assert_eq!(
            ROOT_GRANT_HYDRATION_FIELDS,
            [
                "intent.operation_id",
                "intent.grant_id",
                "intent.parent_grant_id",
                "intent.authority_root_ref",
                "intent.snapshot_id",
                "intent.grant_graph_revision",
                "intent.holder_principal",
                "intent.session_id",
                "intent.scope_id",
                "intent.binding",
                "intent.allowed_effect",
                "intent.proof_ceiling",
                "intent.issued_at_ms",
                "intent.expires_at_ms",
                "intent.receipt_obligations",
                "durable_record",
                "observed_at_ms",
            ]
        );
        let path = std::env::temp_dir().join(format!(
            "eliot-kernel-root-grant-{}-{}.redb",
            std::process::id(),
            epoch.sequence
        ));
        let _ = std::fs::remove_file(&path);

        let store = Arc::new(eliot_ors::RedbRecoveryStore::open(&path)?);
        let mut incomplete = hydration.clone();
        incomplete.intent.holder_principal.clear();
        let incomplete_port = GrantActivationPort::with_durable_root_grant(
            Arc::new(TestRootHydration { value: incomplete }),
            store.clone(),
        );
        assert!(matches!(
            P07AuthorityPort::activate_grant(&incomplete_port, &request),
            Err(P07PortError::InvalidBinding)
        ));
        assert!(
            store
                .load_capability_grant(&eliot_ors::OperationIdentity::new("grant-root")?)?
                .is_none()
        );
        drop(incomplete_port);

        let hydration_source = Arc::new(TestRootHydration {
            value: hydration.clone(),
        });
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

        // A changed opaque payload under the same durable operation/subject
        // identity is a conflict after restart and leaves the ORS row intact.
        let mut changed_payload = hydration.clone();
        let mut changed_record = changed_payload.durable_record.record().clone();
        let key = match &changed_record.payload {
            eliot_ors::RecoveryPayload::Encrypted { key, .. } => key.clone(),
            eliot_ors::RecoveryPayload::ImmutableLocator { .. } => {
                return Err("fixture must use an encrypted root-grant payload".into());
            }
        };
        let ciphertext = b"changed-root-grant-record".to_vec();
        changed_record.payload = eliot_ors::RecoveryPayload::Encrypted {
            key,
            ciphertext: ciphertext.clone(),
        };
        changed_record.payload_length = ciphertext.len() as u64;
        changed_record.payload_sha256 = eliot_contracts::sha256_hex(&ciphertext);
        changed_payload.durable_record = CapabilityGrantActivation::new(changed_record)?;
        let changed_port = GrantActivationPort::with_durable_root_grant(
            Arc::new(TestRootHydration {
                value: changed_payload,
            }),
            reopened.clone(),
        );
        assert!(matches!(
            P07AuthorityPort::activate_grant(&changed_port, &request),
            Err(P07PortError::InvalidBinding)
        ));
        assert_eq!(
            reopened
                .load_capability_grant(&subject)?
                .ok_or("changed replay removed the active projection")?
                .record(),
            hydration.durable_record.record()
        );

        // Expiry remains a semantic admission refusal after restart; it does
        // not become an unavailable/no-result recovery outcome and does not
        // mutate the committed ORS projection.
        let expired_port = GrantActivationPort::with_durable_root_grant(
            Arc::new(TestRootHydration {
                value: hydration.clone(),
            }),
            reopened.clone(),
        );
        assert!(matches!(
            expired_port.recover_root_grant("grant-root", &epoch, 10_000),
            Err(KernelError::Expired {
                expires_at_ms: 10_000
            })
        ));
        drop(changed_port);
        drop(expired_port);

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

    // -----------------------------------------------------------------------
    // Lane C (`#2100`): durable descendant-closure enumeration, revision-bound
    // CAS/fencing, durable closure receipt, and restart rehydration.
    // -----------------------------------------------------------------------

    struct TestClosureHydration {
        enumeration: Mutex<GrantClosureEnumeration>,
    }

    impl TestClosureHydration {
        fn replace(&self, enumeration: GrantClosureEnumeration) {
            *self
                .enumeration
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = enumeration;
        }
    }

    impl RootGrantHydrationSource for TestClosureHydration {
        fn hydrate_root_grant(
            &self,
            _request: &eliot_authority::GrantActivationRequest,
        ) -> Result<RootGrantHydration, KernelError> {
            Err(KernelError::RecoveryUnavailable(
                "closure tests never hydrate single roots".to_owned(),
            ))
        }

        fn rehydrate_root_grant(
            &self,
            _projection: &CapabilityGrantProjection,
        ) -> Result<RootGrantHydration, KernelError> {
            Err(KernelError::RecoveryUnavailable(
                "closure tests never rehydrate single roots".to_owned(),
            ))
        }

        fn enumerate_grant_closure(
            &self,
            _grant_id: &str,
        ) -> Result<GrantClosureEnumeration, KernelError> {
            Ok(self
                .enumeration
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone())
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the closure fixture names every lineage identity"
    )]
    fn closure_member_fixture(
        epoch: &EpochId,
        binding: &AuthorityBinding,
        operation_id: &str,
        grant_id: &str,
        parent_grant_id: Option<&str>,
        authority_root_ref: &str,
        grant_graph_revision: u64,
    ) -> Result<GrantClosureMember, KernelError> {
        let intent = GrantActivationIntent {
            operation_id: operation_id.to_owned(),
            grant_id: grant_id.to_owned(),
            parent_grant_id: parent_grant_id.map(str::to_owned),
            authority_root_ref: authority_root_ref.to_owned(),
            snapshot_id: "snap-1".to_owned(),
            grant_graph_revision,
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
                subject_id: eliot_ors::OperationIdentity::new(grant_id)?,
                authority_epoch,
                state_fence,
                created_at_ms: 1_000,
                cleanup_after_ms: None,
            },
            eliot_platform::SecretReference::new("test-provider", "closure-grant-key").map_err(
                |_error| KernelError::InvalidField {
                    field: "test_secret_reference",
                    reason: "fixture reference must validate",
                },
            )?,
            format!("opaque-closure-record-{grant_id}").into_bytes(),
        )?;
        let durable_record = CapabilityGrantActivation::new(input)?;
        Ok(GrantClosureMember {
            intent,
            durable_record,
            observed_at_ms: 1_000,
        })
    }

    fn chain_enumeration(
        epoch: &EpochId,
        binding: &AuthorityBinding,
        grant_graph_revision: u64,
        preserved: Vec<GrantClosureSurvivor>,
    ) -> Result<GrantClosureEnumeration, KernelError> {
        let root = closure_member_fixture(
            epoch,
            binding,
            "op-chain-root",
            "grant-chain-root",
            None,
            "root-chain",
            grant_graph_revision,
        )?;
        let mid = closure_member_fixture(
            epoch,
            binding,
            "op-chain-mid",
            "grant-chain-mid",
            Some("grant-chain-root"),
            "root-chain",
            grant_graph_revision,
        )?;
        let leaf = closure_member_fixture(
            epoch,
            binding,
            "op-chain-leaf",
            "grant-chain-leaf",
            Some("grant-chain-mid"),
            "root-chain",
            grant_graph_revision,
        )?;
        let tip = closure_member_fixture(
            epoch,
            binding,
            "op-chain-tip",
            "grant-chain-tip",
            Some("grant-chain-leaf"),
            "root-chain",
            grant_graph_revision,
        )?;
        Ok(GrantClosureEnumeration {
            authority_root_ref: "root-chain".to_owned(),
            grant_graph_revision,
            members: vec![root, mid, leaf, tip],
            preserved,
        })
    }

    fn chain_revocation_intent(
        binding: &AuthorityBinding,
        operation_id: &str,
        grant_graph_revision: u64,
    ) -> GrantClosureRevocationIntent {
        GrantClosureRevocationIntent {
            operation_id: operation_id.to_owned(),
            grant_id: "grant-chain-root".to_owned(),
            authority_root_ref: "root-chain".to_owned(),
            snapshot_id: "snap-1".to_owned(),
            grant_graph_revision,
            binding: binding.clone(),
            unknown_outcome_operations: Vec::new(),
            receipt_obligations: Vec::new(),
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the closure activate/revoke/restart proof keeps its exact sequence visible"
    )]
    fn closure_activation_revocation_restart_are_exact() -> Result<(), Box<dyn std::error::Error>> {
        use eliot_authority::P07AuthorityPort;
        use std::sync::Arc;

        assert_eq!(
            GRANT_CLOSURE_ENUMERATION_FIELDS,
            [
                "authority_root_ref",
                "grant_graph_revision",
                "members[].intent.operation_id",
                "members[].intent.grant_id",
                "members[].intent.parent_grant_id",
                "members[].intent.authority_root_ref",
                "members[].intent.snapshot_id",
                "members[].intent.grant_graph_revision",
                "members[].intent.holder_principal",
                "members[].intent.session_id",
                "members[].intent.scope_id",
                "members[].intent.binding",
                "members[].intent.allowed_effect",
                "members[].intent.proof_ceiling",
                "members[].intent.issued_at_ms",
                "members[].intent.expires_at_ms",
                "members[].intent.receipt_obligations",
                "members[].durable_record",
                "members[].observed_at_ms",
                "preserved[].grant_id",
                "preserved[].covering_grant_id",
                "preserved[].covering_root_ref",
                "preserved[].operation_id",
                "preserved[].operation_name",
                "preserved[].resource_ref",
                "preserved[].effect",
                "preserved[].holder_principal",
                "preserved[].session_id",
                "preserved[].scope_id",
                "preserved[].canonical_request_hash",
            ]
        );

        let epoch = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 7)?;
        let binding = restart_test_binding(&epoch)?;
        let enumeration = chain_enumeration(&epoch, &binding, 5, Vec::new())?;
        let activation = GrantClosureActivationIntent {
            operation_id: "op-chain-activate".to_owned(),
            enumeration: enumeration.clone(),
        };
        let path = std::env::temp_dir().join(format!(
            "eliot-kernel-grant-closure-{}-{}.redb",
            std::process::id(),
            epoch.sequence
        ));
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(eliot_ors::RedbRecoveryStore::open(&path)?);
        let hydration_source = Arc::new(TestClosureHydration {
            enumeration: Mutex::new(enumeration),
        });
        let port =
            GrantActivationPort::with_durable_root_grant(hydration_source.clone(), store.clone());

        let receipts = port.activate_grant_closure(&activation, &epoch)?;
        assert_eq!(receipts.len(), 4);
        assert_eq!(receipts[0].activation_id, "activation-op-chain-root");
        assert_eq!(receipts[3].activation_id, "activation-op-chain-tip");
        assert_eq!(port.grant_graph_revision("root-chain"), Some(5));
        let expected_affected = vec![
            "grant-chain-leaf".to_owned(),
            "grant-chain-mid".to_owned(),
            "grant-chain-root".to_owned(),
            "grant-chain-tip".to_owned(),
        ];
        let committed = port
            .closure_receipt("op-chain-activate")
            .ok_or("activation closure receipt missing")?;
        assert_eq!(committed.operation_id, "op-chain-activate");
        assert_eq!(committed.declaration.target_grant_id, "grant-chain-root");
        assert_eq!(committed.declaration.grant_graph_revision, 5);
        assert_eq!(committed.declaration.affected_grants(), expected_affected);
        assert!(committed.declaration.preserved.is_empty());
        assert!(matches!(committed.state, GrantClosureState::Active));
        assert_eq!(
            port.closure_receipt_for_target("grant-chain-root"),
            Some(committed.clone())
        );
        // An activation closure is not a revocation: no fence is exposed.
        assert!(port.revocation_closure("op-chain-activate").is_none());

        // Exact replay returns the same member receipts without a second
        // commit.
        let replay = port.activate_grant_closure(&activation, &epoch)?;
        assert_eq!(replay, receipts);

        // A changed payload under one closure identity conflicts.
        let mut changed = activation.clone();
        changed.enumeration.members[1]
            .intent
            .receipt_obligations
            .push("obligation-2".to_owned());
        assert!(matches!(
            port.activate_grant_closure(&changed, &epoch),
            Err(KernelError::IdempotencyConflict)
        ));

        // An unrelated grant on another root stays usable outside the
        // closure.
        let unrelated = GrantActivationIntent {
            operation_id: "op-unrelated".to_owned(),
            grant_id: "grant-unrelated".to_owned(),
            parent_grant_id: None,
            authority_root_ref: "root-other".to_owned(),
            snapshot_id: "snap-1".to_owned(),
            grant_graph_revision: 1,
            holder_principal: "holder-9".to_owned(),
            session_id: "session-9".to_owned(),
            scope_id: "scope-9".to_owned(),
            binding: binding.clone(),
            allowed_effect: EffectClass::Read,
            proof_ceiling: ProofCeiling::ScopedVerification,
            issued_at_ms: 1_000,
            expires_at_ms: None,
            receipt_obligations: Vec::new(),
        };
        port.activate_grant(&unrelated, epoch.clone(), 1_000)?;
        assert!(!port.grant_revoked("grant-unrelated"));

        drop(port);
        drop(store);

        // Restart rehydrates the activation closure by re-presentation.
        let reopened = Arc::new(eliot_ors::RedbRecoveryStore::open(&path)?);
        let restarted = GrantActivationPort::with_durable_root_grant(
            hydration_source.clone(),
            reopened.clone(),
        );
        assert_eq!(restarted.grant_graph_revision("root-chain"), None);
        let recovered = restarted.recover_grant_closure_activation(&activation, &epoch, 1_000)?;
        assert_eq!(recovered, receipts);
        assert_eq!(restarted.grant_graph_revision("root-chain"), Some(5));
        assert_eq!(
            restarted.closure_receipt("op-chain-activate"),
            Some(committed.clone())
        );

        // A revision below the greatest observed for this root is stale.
        let stale = chain_revocation_intent(&binding, "op-chain-revoke-stale", 4);
        assert!(matches!(
            restarted.revoke_grant_closure(&stale, &epoch),
            Err(KernelError::InvalidField { .. })
        ));

        // The revocation enumeration advances the exact revision; the opaque
        // member records are unchanged, so the `Active` rows still agree.
        let revoke_enumeration = chain_enumeration(&epoch, &binding, 6, Vec::new())?;
        hydration_source.replace(revoke_enumeration);
        // The rich revocation shares the thin derived operation identity, so
        // the thin path and the rich path converge on one ledger record and
        // one closure receipt.
        let revoke_op = thin_operation_id("revoke-grant", "grant-chain-root", "snap-1", &epoch);
        let revocation = chain_revocation_intent(&binding, revoke_op.as_str(), 6);
        let fenced = restarted.revoke_grant_closure(&revocation, &epoch)?;
        assert_eq!(fenced.operation_id, revoke_op.as_str());
        assert_eq!(fenced.declaration.target_grant_id, "grant-chain-root");
        assert_eq!(fenced.declaration.grant_graph_revision, 6);
        assert_eq!(fenced.declaration.affected_grants(), expected_affected);
        assert!(fenced.declaration.preserved.is_empty());
        assert!(matches!(fenced.state, GrantClosureState::Revoked));
        for grant_id in &expected_affected {
            assert!(
                restarted.grant_revoked(grant_id),
                "{grant_id} must stay fenced"
            );
        }
        assert!(!restarted.grant_revoked("grant-unrelated"));
        assert_eq!(
            restarted.revocation_closure(revoke_op.as_str()),
            Some(expected_affected.clone())
        );
        assert_eq!(
            restarted.closure_receipt(revoke_op.as_str()),
            Some(fenced.clone())
        );
        assert_eq!(
            restarted.closure_receipt_for_target("grant-chain-root"),
            Some(fenced.clone())
        );
        assert!(matches!(
            restarted.disposition(revoke_op.as_str()),
            Some(IntentDisposition::Committed(_))
        ));
        for grant_id in &expected_affected {
            let subject = eliot_ors::OperationIdentity::new(grant_id)?;
            let projection = reopened
                .load_capability_grant(&subject)?
                .ok_or("fenced member projection missing")?;
            assert_eq!(projection.phase(), OperationalPhase::Fenced);
        }

        // Exact revocation replay returns the same receipt.
        let revoke_replay = restarted.revoke_grant_closure(&revocation, &epoch)?;
        assert_eq!(revoke_replay, fenced);

        drop(restarted);
        drop(reopened);

        // Restart rehydrates the committed revocation closure and keeps
        // rejecting stale descendant authority before any new admission.
        let after_restart_store = Arc::new(eliot_ors::RedbRecoveryStore::open(&path)?);
        let after_restart = GrantActivationPort::with_durable_root_grant(
            hydration_source.clone(),
            after_restart_store.clone(),
        );
        let rehydrated = after_restart.recover_grant_closure_revocation(&revocation, &epoch)?;
        assert_eq!(rehydrated, fenced);
        for grant_id in &expected_affected {
            assert!(
                after_restart.grant_revoked(grant_id),
                "{grant_id} must stay fenced after restart"
            );
        }
        assert_eq!(
            after_restart.revocation_closure(revoke_op.as_str()),
            Some(expected_affected.clone())
        );
        assert_eq!(
            after_restart.closure_receipt(revoke_op.as_str()),
            Some(fenced.clone())
        );
        let expected_revocation = eliot_runtime_contracts::AuthorityRevocationReceipt {
            revocation_id: format!("revocation-{revoke_op}"),
            snapshot_id: "snap-1".to_owned(),
            authority_epoch: epoch.clone(),
            state: AuthorityState::Revoked,
        };
        assert_eq!(
            after_restart.disposition(revoke_op.as_str()),
            Some(IntentDisposition::Committed(CommittedReceipt::Revocation(
                expected_revocation
            )))
        );
        assert_eq!(after_restart.grant_graph_revision("root-chain"), Some(6));

        // The activation closure cannot be recovered over `Fenced` rows.
        assert!(matches!(
            after_restart.recover_grant_closure_activation(&activation, &epoch, 1_000),
            Err(KernelError::RecoveryUnavailable(_))
        ));

        // The thin revocation path re-presents the same fence on the
        // reopened port and stays revoked.
        let thin_revoke = eliot_authority::GrantRevocationRequest {
            grant_id: eliot_authority::GrantId::new("grant-chain-root").map_err(|_| {
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
        };
        let thin_fenced = P07AuthorityPort::revoke_grant(&after_restart, &thin_revoke)
            .map_err(|error| format!("thin closure revoke failed: {error:?}"))?;
        assert!(matches!(thin_fenced.state, AuthorityState::Revoked));
        // The thin path converged on the same ledger record: the shared
        // operation identity replays the committed closure receipt.
        assert_eq!(
            after_restart.closure_receipt(revoke_op.as_str()),
            Some(fenced.clone())
        );
        assert_eq!(
            after_restart.revocation_closure(revoke_op.as_str()),
            Some(expected_affected.clone())
        );
        let thin_replay = P07AuthorityPort::revoke_grant(&after_restart, &thin_revoke)
            .map_err(|error| format!("thin closure replay failed: {error:?}"))?;
        assert_eq!(thin_replay, thin_fenced);

        drop(after_restart);
        drop(after_restart_store);
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn closure_enumeration_validation_rejects_before_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::Arc;

        let epoch = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 7)?;
        let binding = restart_test_binding(&epoch)?;
        let valid = chain_enumeration(&epoch, &binding, 5, Vec::new())?;
        let path = std::env::temp_dir().join(format!(
            "eliot-kernel-grant-closure-invalid-{}-{}.redb",
            std::process::id(),
            epoch.sequence
        ));
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(eliot_ors::RedbRecoveryStore::open(&path)?);
        let hydration_source = Arc::new(TestClosureHydration {
            enumeration: Mutex::new(valid.clone()),
        });
        let port =
            GrantActivationPort::with_durable_root_grant(hydration_source.clone(), store.clone());

        let attempt = |operation_id: &str, enumeration: GrantClosureEnumeration| {
            port.activate_grant_closure(
                &GrantClosureActivationIntent {
                    operation_id: operation_id.to_owned(),
                    enumeration,
                },
                &epoch,
            )
        };

        // Empty closure.
        let mut enumeration = valid.clone();
        enumeration.members.clear();
        assert!(matches!(
            attempt("op-invalid-empty", enumeration),
            Err(KernelError::InvalidField { .. })
        ));

        // Zero revision.
        let mut enumeration = valid.clone();
        enumeration.grant_graph_revision = 0;
        assert!(matches!(
            attempt("op-invalid-zero", enumeration),
            Err(KernelError::InvalidField { .. })
        ));

        // Two delegation roots.
        let mut enumeration = valid.clone();
        enumeration.members[1].intent.parent_grant_id = None;
        assert!(matches!(
            attempt("op-invalid-roots", enumeration),
            Err(KernelError::InvalidField { .. })
        ));

        // Misordered parent (child before its parent).
        let mut enumeration = valid.clone();
        enumeration.members.swap(0, 2);
        assert!(matches!(
            attempt("op-invalid-order", enumeration),
            Err(KernelError::InvalidField { .. })
        ));

        // Cross-root member.
        let mut enumeration = valid.clone();
        enumeration.members[2].intent.authority_root_ref = "root-other".to_owned();
        assert!(matches!(
            attempt("op-invalid-root", enumeration),
            Err(KernelError::FenceMismatch)
        ));

        // Duplicate member identity.
        let mut enumeration = valid.clone();
        enumeration.members[2] = enumeration.members[1].clone();
        assert!(matches!(
            attempt("op-invalid-duplicate", enumeration),
            Err(KernelError::InvalidField { .. })
        ));

        // Member revision drift from the enumeration revision.
        let mut enumeration = valid.clone();
        enumeration.members[3].intent.grant_graph_revision = 6;
        assert!(matches!(
            attempt("op-invalid-drift", enumeration),
            Err(KernelError::InvalidField { .. })
        ));

        // Tampered opaque record.
        let mut enumeration = valid.clone();
        let mut tampered = enumeration.members[0].durable_record.record().clone();
        tampered.subject_id = eliot_ors::OperationIdentity::new("grant-tampered")
            .map_err(KernelError::RecoveryState)?;
        enumeration.members[0].durable_record =
            CapabilityGrantActivation::new(tampered).map_err(KernelError::RecoveryState)?;
        assert!(matches!(
            attempt("op-invalid-record", enumeration),
            Err(KernelError::RecoveryUnavailable(_))
        ));

        // Survivor overlapping the fenced members.
        let mut enumeration = valid.clone();
        enumeration.preserved.push(preserved_survivor_fixture(
            "grant-chain-leaf",
            "grant-alt",
            "root-alt",
        ));
        assert!(matches!(
            attempt("op-invalid-survivor", enumeration),
            Err(KernelError::InvalidField { .. })
        ));

        // Nothing above mutated the ledger or the store.
        assert_eq!(port.grant_graph_revision("root-chain"), None);
        assert!(port.reconciling_operations().is_empty());
        for member in &valid.members {
            let subject = eliot_ors::OperationIdentity::new(&member.intent.grant_id)?;
            assert!(
                store.load_capability_grant(&subject)?.is_none(),
                "rejected enumeration must not commit ORS rows"
            );
        }

        drop(port);
        drop(store);
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn closure_revocation_preserves_declared_survivor() -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::Arc;

        let epoch = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 7)?;
        let binding = restart_test_binding(&epoch)?;
        let path = std::env::temp_dir().join(format!(
            "eliot-kernel-grant-closure-survivor-{}-{}.redb",
            std::process::id(),
            epoch.sequence
        ));
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(eliot_ors::RedbRecoveryStore::open(&path)?);

        // Four committed members: root, mid, leaf, and a side branch off mid.
        let mut full = chain_enumeration(&epoch, &binding, 5, Vec::new())?;
        let side = closure_member_fixture(
            &epoch,
            &binding,
            "op-chain-side",
            "grant-chain-side",
            Some("grant-chain-mid"),
            "root-chain",
            5,
        )?;
        full.members.insert(2, side);
        let hydration_source = Arc::new(TestClosureHydration {
            enumeration: Mutex::new(full.clone()),
        });
        let port =
            GrantActivationPort::with_durable_root_grant(hydration_source.clone(), store.clone());
        let activated = port.activate_grant_closure(
            &GrantClosureActivationIntent {
                operation_id: "op-side-activate".to_owned(),
                enumeration: full,
            },
            &epoch,
        )?;
        assert_eq!(activated.len(), 5);

        // Provision REAL covering authority for the declared survivor: a
        // live alt-root grant outside the affected set, committed durably
        // through the port (not a bare declaration). The survivor gate
        // proves this cover at revocation time; an unactivated cover
        // would (correctly) refuse.
        let alt_member = closure_member_fixture(
            &epoch,
            &binding,
            "op-alt-root",
            "grant-alt",
            None,
            "root-alt",
            5,
        )?;
        let alt_enumeration = GrantClosureEnumeration {
            authority_root_ref: "root-alt".to_owned(),
            grant_graph_revision: 5,
            members: vec![alt_member],
            preserved: Vec::new(),
        };
        hydration_source.replace(alt_enumeration.clone());
        let alt_activated = port.activate_grant_closure(
            &GrantClosureActivationIntent {
                operation_id: "op-alt-activate".to_owned(),
                enumeration: alt_enumeration,
            },
            &epoch,
        )?;
        assert_eq!(alt_activated.len(), 1);

        // Revocation fences the full chain and keeps the side branch usable
        // under its surviving alternate path.
        let mut fenced_enumeration = chain_enumeration(&epoch, &binding, 6, Vec::new())?;
        fenced_enumeration
            .preserved
            .push(preserved_survivor_fixture(
                "grant-chain-side",
                "grant-alt",
                "root-alt",
            ));
        hydration_source.replace(fenced_enumeration);
        let revocation = chain_revocation_intent(&binding, "op-side-revoke", 6);
        let receipt = port.revoke_grant_closure(&revocation, &epoch)?;
        assert_eq!(
            receipt.declaration.affected_grants(),
            vec![
                "grant-chain-leaf".to_owned(),
                "grant-chain-mid".to_owned(),
                "grant-chain-root".to_owned(),
                "grant-chain-tip".to_owned(),
            ]
        );
        assert_eq!(receipt.declaration.preserved.len(), 1);
        assert_eq!(
            receipt.declaration.preserved[0].grant_id,
            "grant-chain-side"
        );
        assert_eq!(
            receipt.declaration.preserved[0].covering_grant_id,
            "grant-alt"
        );
        assert_eq!(
            receipt.declaration.preserved[0].covering_root_ref,
            "root-alt"
        );
        assert!(!port.grant_revoked("grant-chain-side"));
        let side_subject = eliot_ors::OperationIdentity::new("grant-chain-side")?;
        assert_eq!(
            store
                .load_capability_grant(&side_subject)?
                .ok_or("survivor ORS row missing")?
                .phase(),
            OperationalPhase::Active
        );

        // An enumeration that drops a recorded descendant without declaring
        // it preserved is incomplete and cannot commit.
        let mut partial = chain_enumeration(&epoch, &binding, 7, Vec::new())?;
        partial.members.pop();
        partial.members.pop();
        hydration_source.replace(partial);
        let incomplete = chain_revocation_intent(&binding, "op-side-incomplete", 7);
        assert!(matches!(
            port.revoke_grant_closure(&incomplete, &epoch),
            Err(KernelError::InvalidField { .. })
        ));
        assert!(port.disposition("op-side-incomplete").is_none());

        drop(port);
        drop(store);
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn closure_revocation_refuses_stale_survivor_cover() -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::Arc;

        let epoch = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 7)?;
        let binding = restart_test_binding(&epoch)?;
        let path = std::env::temp_dir().join(format!(
            "eliot-kernel-grant-closure-stale-cover-{}-{}.redb",
            std::process::id(),
            epoch.sequence
        ));
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(eliot_ors::RedbRecoveryStore::open(&path)?);

        // Chain plus side branch plus a live alt-root cover, all committed.
        let mut full = chain_enumeration(&epoch, &binding, 5, Vec::new())?;
        let side = closure_member_fixture(
            &epoch,
            &binding,
            "op-chain-side",
            "grant-chain-side",
            Some("grant-chain-mid"),
            "root-chain",
            5,
        )?;
        full.members.insert(2, side);
        let hydration_source = Arc::new(TestClosureHydration {
            enumeration: Mutex::new(full.clone()),
        });
        let port =
            GrantActivationPort::with_durable_root_grant(hydration_source.clone(), store.clone());
        port.activate_grant_closure(
            &GrantClosureActivationIntent {
                operation_id: "op-stale-activate".to_owned(),
                enumeration: full,
            },
            &epoch,
        )?;
        let alt_member = closure_member_fixture(
            &epoch,
            &binding,
            "op-alt-root",
            "grant-alt",
            None,
            "root-alt",
            5,
        )?;
        let alt_enumeration = GrantClosureEnumeration {
            authority_root_ref: "root-alt".to_owned(),
            grant_graph_revision: 5,
            members: vec![alt_member],
            preserved: Vec::new(),
        };
        hydration_source.replace(alt_enumeration.clone());
        port.activate_grant_closure(
            &GrantClosureActivationIntent {
                operation_id: "op-alt-activate".to_owned(),
                enumeration: alt_enumeration,
            },
            &epoch,
        )?;

        // Fence the cover through its own closure: the surviving path it
        // anchored is gone, so any later declaration preserving through it
        // is stale evidence and must refuse.
        let alt_revoke_members = vec![closure_member_fixture(
            &epoch,
            &binding,
            "op-alt-root",
            "grant-alt",
            None,
            "root-alt",
            6,
        )?];
        hydration_source.replace(GrantClosureEnumeration {
            authority_root_ref: "root-alt".to_owned(),
            grant_graph_revision: 6,
            members: alt_revoke_members,
            preserved: Vec::new(),
        });
        let alt_revoke = GrantClosureRevocationIntent {
            operation_id: "op-alt-revoke".to_owned(),
            grant_id: "grant-alt".to_owned(),
            authority_root_ref: "root-alt".to_owned(),
            snapshot_id: "snap-1".to_owned(),
            grant_graph_revision: 6,
            binding: binding.clone(),
            unknown_outcome_operations: Vec::new(),
            receipt_obligations: Vec::new(),
        };
        port.revoke_grant_closure(&alt_revoke, &epoch)?;
        assert!(port.grant_revoked("grant-alt"));

        let mut fenced_enumeration = chain_enumeration(&epoch, &binding, 7, Vec::new())?;
        fenced_enumeration
            .preserved
            .push(preserved_survivor_fixture(
                "grant-chain-side",
                "grant-alt",
                "root-alt",
            ));
        hydration_source.replace(fenced_enumeration);
        let revocation = chain_revocation_intent(&binding, "op-stale-revoke", 7);
        assert!(matches!(
            port.revoke_grant_closure(&revocation, &epoch),
            Err(KernelError::InvalidField { .. })
        ));
        assert!(port.disposition("op-stale-revoke").is_none());

        drop(port);
        drop(store);
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn closure_revocation_proves_cover_from_durable_row() -> Result<(), Box<dyn std::error::Error>>
    {
        use std::sync::Arc;

        let epoch = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 7)?;
        let binding = restart_test_binding(&epoch)?;
        let path = std::env::temp_dir().join(format!(
            "eliot-kernel-grant-closure-durable-cover-{}-{}.redb",
            std::process::id(),
            epoch.sequence
        ));
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(eliot_ors::RedbRecoveryStore::open(&path)?);

        // Same committed state as the survivor fixture: chain plus side
        // plus alt-root cover, all with durable Active rows.
        let mut full = chain_enumeration(&epoch, &binding, 5, Vec::new())?;
        let side = closure_member_fixture(
            &epoch,
            &binding,
            "op-chain-side",
            "grant-chain-side",
            Some("grant-chain-mid"),
            "root-chain",
            5,
        )?;
        full.members.insert(2, side);
        let hydration_source = Arc::new(TestClosureHydration {
            enumeration: Mutex::new(full.clone()),
        });
        let port =
            GrantActivationPort::with_durable_root_grant(hydration_source.clone(), store.clone());
        port.activate_grant_closure(
            &GrantClosureActivationIntent {
                operation_id: "op-durable-activate".to_owned(),
                enumeration: full,
            },
            &epoch,
        )?;
        let alt_member = closure_member_fixture(
            &epoch,
            &binding,
            "op-alt-root",
            "grant-alt",
            None,
            "root-alt",
            5,
        )?;
        let alt_enumeration = GrantClosureEnumeration {
            authority_root_ref: "root-alt".to_owned(),
            grant_graph_revision: 5,
            members: vec![alt_member],
            preserved: Vec::new(),
        };
        hydration_source.replace(alt_enumeration.clone());
        port.activate_grant_closure(
            &GrantClosureActivationIntent {
                operation_id: "op-alt-activate".to_owned(),
                enumeration: alt_enumeration,
            },
            &epoch,
        )?;

        // Restart: an empty live ledger over the same durable store. The
        // survivor and its cover have no live records, so the gate must
        // prove the cover from its durable Active row bound to the
        // presented fence — never from a carried declaration.
        drop(port);
        let mut fenced_enumeration = chain_enumeration(&epoch, &binding, 6, Vec::new())?;
        fenced_enumeration
            .preserved
            .push(preserved_survivor_fixture(
                "grant-chain-side",
                "grant-alt",
                "root-alt",
            ));
        hydration_source.replace(fenced_enumeration);
        let reopened =
            GrantActivationPort::with_durable_root_grant(hydration_source.clone(), store.clone());
        let revocation = chain_revocation_intent(&binding, "op-durable-revoke", 6);
        let receipt = reopened.revoke_grant_closure(&revocation, &epoch)?;
        assert_eq!(receipt.declaration.preserved.len(), 1);
        assert_eq!(
            receipt.declaration.preserved[0].grant_id,
            "grant-chain-side"
        );
        assert_eq!(
            receipt.declaration.preserved[0].covering_grant_id,
            "grant-alt"
        );
        assert!(reopened.grant_revoked("grant-chain-root"));

        drop(reopened);
        drop(store);
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the repair-path proof keeps mismatch, resurrection, reconfirmation, and watermark in one restart sequence"
    )]
    fn closure_repair_paths_reject_and_reconfirm() -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::Arc;

        let epoch = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 7)?;
        let binding = restart_test_binding(&epoch)?;
        let path = std::env::temp_dir().join(format!(
            "eliot-kernel-grant-closure-repair-{}-{}.redb",
            std::process::id(),
            epoch.sequence
        ));
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(eliot_ors::RedbRecoveryStore::open(&path)?);
        let hydration_source = Arc::new(TestClosureHydration {
            enumeration: Mutex::new(chain_enumeration(&epoch, &binding, 5, Vec::new())?),
        });
        let port =
            GrantActivationPort::with_durable_root_grant(hydration_source.clone(), store.clone());
        let chain_root_label = eliot_ors::OpaqueLabel::new("root-chain")?;

        // A presented closure the owner never admitted cannot activate, and
        // commits nothing durably.
        let mut foreign = chain_enumeration(&epoch, &binding, 5, Vec::new())?;
        foreign.members[0].intent.snapshot_id = "snap-foreign".to_owned();
        assert!(matches!(
            port.activate_grant_closure(
                &GrantClosureActivationIntent {
                    operation_id: "op-repair-foreign".to_owned(),
                    enumeration: foreign,
                },
                &epoch,
            ),
            Err(KernelError::InvalidField { .. })
        ));
        assert!(port.disposition("op-repair-foreign").is_none());
        let chain_root = eliot_ors::OperationIdentity::new("grant-chain-root")?;
        assert!(store.load_capability_grant(&chain_root)?.is_none());
        assert!(
            store
                .load_grant_graph_revision(&chain_root_label)?
                .is_none()
        );

        // Owner-attested activation commits members, watermark, and row.
        let activation = GrantClosureActivationIntent {
            operation_id: "op-repair-activate".to_owned(),
            enumeration: chain_enumeration(&epoch, &binding, 5, Vec::new())?,
        };
        let receipts = port.activate_grant_closure(&activation, &epoch)?;
        assert_eq!(receipts.len(), 4);
        assert_eq!(store.load_grant_graph_revision(&chain_root_label)?, Some(5));

        // Revocation at the advanced revision fences every member.
        hydration_source.replace(chain_enumeration(&epoch, &binding, 6, Vec::new())?);
        let revocation = chain_revocation_intent(&binding, "op-repair-revoke-1", 6);
        let fenced = port.revoke_grant_closure(&revocation, &epoch)?;
        assert_eq!(fenced.declaration.affected_grants().len(), 4);
        let revoke_op_1 = eliot_ors::OperationIdentity::new("op-repair-revoke-1")?;
        let row_1 = store
            .load_grant_closure(&revoke_op_1)?
            .ok_or("revocation closure row missing")?;
        assert_eq!(row_1.commit().declaration.grant_graph_revision, 6);
        assert!(matches!(
            row_1.commit().state,
            eliot_ors::GrantClosureState::Revoked
        ));

        drop(port);
        drop(store);

        // After restart, re-presenting the same members under a fresh
        // activation identity refuses instead of resurrecting fenced rows.
        let reopened = Arc::new(eliot_ors::RedbRecoveryStore::open(&path)?);
        let restarted = GrantActivationPort::with_durable_root_grant(
            hydration_source.clone(),
            reopened.clone(),
        );
        let resurrection = GrantClosureActivationIntent {
            operation_id: "op-repair-resurrect".to_owned(),
            enumeration: chain_enumeration(&epoch, &binding, 6, Vec::new())?,
        };
        assert!(matches!(
            restarted.activate_grant_closure(&resurrection, &epoch),
            Err(KernelError::InvalidField { .. })
        ));
        assert!(restarted.disposition("op-repair-resurrect").is_none());
        // The durable rows are still fenced: nothing was resurrected and no
        // live authority was installed for the refused identity.
        for member in &resurrection.enumeration.members {
            let subject = eliot_ors::OperationIdentity::new(&member.intent.grant_id)?;
            let projection = reopened
                .load_capability_grant(&subject)?
                .ok_or("member row missing after refused resurrection")?;
            assert_eq!(projection.phase(), OperationalPhase::Fenced);
            assert!(!restarted.grant_revoked(&member.intent.grant_id));
        }

        // A fresh revocation identity reconfirms the fenced members instead
        // of forking a second fence: the member rows keep their original
        // revocation record identities while a new closure row commits.
        let reconfirm = chain_revocation_intent(&binding, "op-repair-revoke-2", 6);
        let reconfirmed = restarted.revoke_grant_closure(&reconfirm, &epoch)?;
        assert_eq!(
            reconfirmed.declaration.affected_grants(),
            fenced.declaration.affected_grants()
        );
        for grant_id in &reconfirmed.declaration.affected_grants() {
            let subject = eliot_ors::OperationIdentity::new(grant_id)?;
            let projection = reopened
                .load_capability_grant(&subject)?
                .ok_or("reconfirmed member row missing")?;
            assert_eq!(projection.phase(), OperationalPhase::Fenced);
            let expected_record = closure_member_revocation_id("op-repair-revoke-1", grant_id);
            assert_eq!(
                projection.record().record_id.as_str(),
                expected_record.as_str()
            );
        }
        let revoke_op_2 = eliot_ors::OperationIdentity::new("op-repair-revoke-2")?;
        assert!(
            reopened
                .load_grant_closure(&revoke_op_2)?
                .is_some_and(|row| row.commit().declaration.grant_graph_revision == 6)
        );

        drop(restarted);
        drop(reopened);

        // After a second restart the durable watermark still refuses a
        // superseded revision first presented as new, even though the fresh
        // process has no in-memory watermark yet.
        let stale_store = Arc::new(eliot_ors::RedbRecoveryStore::open(&path)?);
        let stale_port = GrantActivationPort::with_durable_root_grant(
            hydration_source.clone(),
            stale_store.clone(),
        );
        assert_eq!(stale_port.grant_graph_revision("root-chain"), None);
        let stale_member = closure_member_fixture(
            &epoch,
            &binding,
            "op-stale-act",
            "grant-stale",
            None,
            "root-chain",
            4,
        )?;
        let stale_enumeration = GrantClosureEnumeration {
            authority_root_ref: "root-chain".to_owned(),
            grant_graph_revision: 4,
            members: vec![stale_member],
            preserved: Vec::new(),
        };
        hydration_source.replace(stale_enumeration.clone());
        assert!(matches!(
            stale_port.activate_grant_closure(
                &GrantClosureActivationIntent {
                    operation_id: "op-repair-stale".to_owned(),
                    enumeration: stale_enumeration,
                },
                &epoch,
            ),
            Err(KernelError::InvalidField { .. })
        ));
        assert_eq!(
            stale_store.load_grant_graph_revision(&chain_root_label)?,
            Some(6)
        );
        assert!(
            stale_store
                .load_capability_grant(&eliot_ors::OperationIdentity::new("grant-stale")?)?
                .is_none()
        );

        drop(stale_port);
        drop(stale_store);
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the mid-chain proof keeps subtree enumeration, fence, and root-survival visible"
    )]
    fn closure_mid_chain_revoke_fences_subtree_only() -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::Arc;

        let epoch = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 7)?;
        let binding = restart_test_binding(&epoch)?;
        let path = std::env::temp_dir().join(format!(
            "eliot-kernel-grant-closure-midchain-{}-{}.redb",
            std::process::id(),
            epoch.sequence
        ));
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(eliot_ors::RedbRecoveryStore::open(&path)?);
        let hydration_source = Arc::new(TestClosureHydration {
            enumeration: Mutex::new(chain_enumeration(&epoch, &binding, 5, Vec::new())?),
        });
        let port =
            GrantActivationPort::with_durable_root_grant(hydration_source.clone(), store.clone());

        let activated = port.activate_grant_closure(
            &GrantClosureActivationIntent {
                operation_id: "op-mid-activate".to_owned(),
                enumeration: chain_enumeration(&epoch, &binding, 5, Vec::new())?,
            },
            &epoch,
        )?;
        assert_eq!(activated.len(), 4);

        // Subtree enumeration anchored at mid with the root as the external
        // delegating parent, at the advanced revision.
        let advanced = chain_enumeration(&epoch, &binding, 6, Vec::new())?;
        let subtree = GrantClosureEnumeration {
            authority_root_ref: "root-chain".to_owned(),
            grant_graph_revision: 6,
            members: advanced.members[1..].to_vec(),
            preserved: Vec::new(),
        };
        hydration_source.replace(subtree);
        let revocation = GrantClosureRevocationIntent {
            operation_id: "op-mid-revoke".to_owned(),
            grant_id: "grant-chain-mid".to_owned(),
            authority_root_ref: "root-chain".to_owned(),
            snapshot_id: "snap-1".to_owned(),
            grant_graph_revision: 6,
            binding: binding.clone(),
            unknown_outcome_operations: Vec::new(),
            receipt_obligations: Vec::new(),
        };
        let receipt = port.revoke_grant_closure(&revocation, &epoch)?;
        assert_eq!(receipt.declaration.target_grant_id, "grant-chain-mid");
        assert_eq!(
            receipt.declaration.affected_grants(),
            vec![
                "grant-chain-leaf".to_owned(),
                "grant-chain-mid".to_owned(),
                "grant-chain-tip".to_owned(),
            ]
        );
        assert!(port.grant_revoked("grant-chain-mid"));
        assert!(port.grant_revoked("grant-chain-leaf"));
        assert!(port.grant_revoked("grant-chain-tip"));
        // The delegating root survives the subtree fence.
        assert!(!port.grant_revoked("grant-chain-root"));
        assert_eq!(port.grant_graph_revision("root-chain"), Some(6));

        drop(port);
        drop(store);
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn closure_incremental_activation_delegates_onto_recorded_parent()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::Arc;

        let epoch = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 7)?;
        let binding = restart_test_binding(&epoch)?;
        let path = std::env::temp_dir().join(format!(
            "eliot-kernel-grant-closure-incremental-{}-{}.redb",
            std::process::id(),
            epoch.sequence
        ));
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(eliot_ors::RedbRecoveryStore::open(&path)?);
        let root_member = closure_member_fixture(
            &epoch,
            &binding,
            "op-inc-root-act",
            "grant-inc-root",
            None,
            "root-inc",
            5,
        )?;
        let root_enum = GrantClosureEnumeration {
            authority_root_ref: "root-inc".to_owned(),
            grant_graph_revision: 5,
            members: vec![root_member],
            preserved: Vec::new(),
        };
        let hydration_source = Arc::new(TestClosureHydration {
            enumeration: Mutex::new(root_enum.clone()),
        });
        let port =
            GrantActivationPort::with_durable_root_grant(hydration_source.clone(), store.clone());
        let root_receipts = port.activate_grant_closure(
            &GrantClosureActivationIntent {
                operation_id: "op-inc-activate-root".to_owned(),
                enumeration: root_enum,
            },
            &epoch,
        )?;
        assert_eq!(root_receipts.len(), 1);

        // Incremental delegation onto the recorded root at a newer revision.
        let mid = closure_member_fixture(
            &epoch,
            &binding,
            "op-inc-mid-act",
            "grant-inc-mid",
            Some("grant-inc-root"),
            "root-inc",
            6,
        )?;
        let leaf = closure_member_fixture(
            &epoch,
            &binding,
            "op-inc-leaf-act",
            "grant-inc-leaf",
            Some("grant-inc-mid"),
            "root-inc",
            6,
        )?;
        let child_enum = GrantClosureEnumeration {
            authority_root_ref: "root-inc".to_owned(),
            grant_graph_revision: 6,
            members: vec![mid, leaf],
            preserved: Vec::new(),
        };
        hydration_source.replace(child_enum.clone());
        let child_receipts = port.activate_grant_closure(
            &GrantClosureActivationIntent {
                operation_id: "op-inc-activate-children".to_owned(),
                enumeration: child_enum,
            },
            &epoch,
        )?;
        assert_eq!(child_receipts.len(), 2);
        assert_eq!(child_receipts[0].activation_id, "activation-op-inc-mid-act");
        assert_eq!(port.grant_graph_revision("root-inc"), Some(6));
        assert!(
            port.closure_receipt("op-inc-activate-children")
                .is_some_and(|receipt| { receipt.declaration.target_grant_id == "grant-inc-mid" })
        );

        // Delegation under an unknown external parent refuses.
        let ghost = closure_member_fixture(
            &epoch,
            &binding,
            "op-inc-ghost-act",
            "grant-inc-ghost",
            Some("grant-inc-missing"),
            "root-inc",
            7,
        )?;
        let ghost_enum = GrantClosureEnumeration {
            authority_root_ref: "root-inc".to_owned(),
            grant_graph_revision: 7,
            members: vec![ghost],
            preserved: Vec::new(),
        };
        hydration_source.replace(ghost_enum.clone());
        assert!(matches!(
            port.activate_grant_closure(
                &GrantClosureActivationIntent {
                    operation_id: "op-inc-activate-ghost".to_owned(),
                    enumeration: ghost_enum,
                },
                &epoch,
            ),
            Err(KernelError::InvalidField { .. })
        ));
        assert!(port.disposition("op-inc-activate-ghost").is_none());

        drop(port);
        drop(store);
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn closure_revocation_fences_introductions_durably() -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::Arc;

        let epoch = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 7)?;
        let binding = restart_test_binding(&epoch)?;
        let path = std::env::temp_dir().join(format!(
            "eliot-kernel-grant-closure-intro-{}-{}.redb",
            std::process::id(),
            epoch.sequence
        ));
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(eliot_ors::RedbRecoveryStore::open(&path)?);
        let root_member = closure_member_fixture(
            &epoch,
            &binding,
            "op-ci-root-act",
            "grant-ci-root",
            None,
            "root-ci",
            5,
        )?;
        let mid_member = closure_member_fixture(
            &epoch,
            &binding,
            "op-ci-mid-act",
            "grant-ci-mid",
            Some("grant-ci-root"),
            "root-ci",
            5,
        )?;
        let enumeration = GrantClosureEnumeration {
            authority_root_ref: "root-ci".to_owned(),
            grant_graph_revision: 5,
            members: vec![root_member, mid_member],
            preserved: Vec::new(),
        };
        let hydration_source = Arc::new(TestClosureHydration {
            enumeration: Mutex::new(enumeration.clone()),
        });
        let port =
            GrantActivationPort::with_durable_root_grant(hydration_source.clone(), store.clone());
        let activated = port.activate_grant_closure(
            &GrantClosureActivationIntent {
                operation_id: "op-ci-activate".to_owned(),
                enumeration,
            },
            &epoch,
        )?;
        assert_eq!(activated.len(), 2);

        let introduction = IntroductionActivationIntent {
            operation_id: "op-ci-intro".to_owned(),
            introduction_id: "intro-ci-1".to_owned(),
            snapshot_id: "snap-1".to_owned(),
            authority_root_ref: "root-ci".to_owned(),
            grant_graph_revision: 5,
            supporting_grant_ids: vec!["grant-ci-root".to_owned(), "grant-ci-mid".to_owned()],
            resource_handle: "handle-1".to_owned(),
            facet_manifest_ref: "facet-1".to_owned(),
            holder_principal: "holder-1".to_owned(),
            session_id: "session-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            binding: binding.clone(),
            allowed_effect: EffectClass::Read,
            proof_ceiling: ProofCeiling::ScopedVerification,
            issued_at_ms: 1_000,
            expires_at_ms: None,
            receipt_obligations: Vec::new(),
        };
        port.activate_introduction(&introduction, epoch.clone(), 1_000)?;
        assert!(!port.introduction_revoked("intro-ci-1"));

        // Revocation fences the dependent introduction and records it in the
        // durable closure row.
        let mut revoked_members = Vec::new();
        for (operation_id, grant_id, parent) in [
            ("op-ci-root-act", "grant-ci-root", None),
            ("op-ci-mid-act", "grant-ci-mid", Some("grant-ci-root")),
        ] {
            revoked_members.push(closure_member_fixture(
                &epoch,
                &binding,
                operation_id,
                grant_id,
                parent,
                "root-ci",
                6,
            )?);
        }
        let revoke_enum = GrantClosureEnumeration {
            authority_root_ref: "root-ci".to_owned(),
            grant_graph_revision: 6,
            members: revoked_members,
            preserved: Vec::new(),
        };
        hydration_source.replace(revoke_enum);
        let revocation = GrantClosureRevocationIntent {
            operation_id: "op-ci-revoke".to_owned(),
            grant_id: "grant-ci-root".to_owned(),
            authority_root_ref: "root-ci".to_owned(),
            snapshot_id: "snap-1".to_owned(),
            grant_graph_revision: 6,
            binding: binding.clone(),
            unknown_outcome_operations: Vec::new(),
            receipt_obligations: Vec::new(),
        };
        let receipt = port.revoke_grant_closure(&revocation, &epoch)?;
        assert_eq!(receipt.fenced_introductions, vec!["intro-ci-1".to_owned()]);
        assert_eq!(
            port.revocation_introductions("op-ci-revoke"),
            Some(vec!["intro-ci-1".to_owned()])
        );
        assert!(port.introduction_revoked("intro-ci-1"));
        let revoke_key = eliot_ors::OperationIdentity::new("op-ci-revoke")?;
        let stored_row = store
            .load_grant_closure(&revoke_key)?
            .ok_or("closure row missing for introduction evidence")?;
        assert_eq!(stored_row.commit().fenced_introductions.len(), 1);

        drop(port);
        drop(store);

        // Restart reinstalls the introduction fence from the closure row, so
        // the fenced introduction never reads as usable again.
        let reopened = Arc::new(eliot_ors::RedbRecoveryStore::open(&path)?);
        let restarted =
            GrantActivationPort::with_durable_root_grant(hydration_source.clone(), reopened);
        let rehydrated = restarted.recover_grant_closure_revocation(&revocation, &epoch)?;
        assert_eq!(
            rehydrated.fenced_introductions,
            vec!["intro-ci-1".to_owned()]
        );
        assert!(restarted.introduction_revoked("intro-ci-1"));
        assert_eq!(
            restarted.revocation_introductions("op-ci-revoke"),
            Some(vec!["intro-ci-1".to_owned()])
        );
        // Re-activating the fenced introduction identity refuses.
        let mut repeat = introduction.clone();
        repeat.operation_id = "op-ci-intro-again".to_owned();
        assert!(matches!(
            restarted.activate_introduction(&repeat, epoch.clone(), 1_000),
            Err(KernelError::InvalidField { .. })
        ));

        drop(restarted);
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn ledger_only_closure_revoke_fences_live_descendants() -> Result<(), Box<dyn std::error::Error>>
    {
        let epoch = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 7)?;
        let binding = restart_test_binding(&epoch)?;
        let port = GrantActivationPort::new();

        // Ledger-only lineage: root with two chained children.
        let root = GrantActivationIntent {
            operation_id: "op-local-root".to_owned(),
            grant_id: "grant-local-root".to_owned(),
            parent_grant_id: None,
            authority_root_ref: "root-local".to_owned(),
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
            receipt_obligations: Vec::new(),
        };
        port.activate_grant(&root, epoch.clone(), 1_000)?;
        let mut mid = root.clone();
        mid.operation_id = "op-local-mid".to_owned();
        mid.grant_id = "grant-local-mid".to_owned();
        mid.parent_grant_id = Some("grant-local-root".to_owned());
        port.activate_grant(&mid, epoch.clone(), 1_000)?;
        let mut leaf = mid.clone();
        leaf.operation_id = "op-local-leaf".to_owned();
        leaf.grant_id = "grant-local-leaf".to_owned();
        leaf.parent_grant_id = Some("grant-local-mid".to_owned());
        port.activate_grant(&leaf, epoch.clone(), 1_000)?;

        let revocation = GrantClosureRevocationIntent {
            operation_id: "op-local-revoke".to_owned(),
            grant_id: "grant-local-root".to_owned(),
            authority_root_ref: "root-local".to_owned(),
            snapshot_id: "snap-1".to_owned(),
            grant_graph_revision: 2,
            binding: binding.clone(),
            unknown_outcome_operations: Vec::new(),
            receipt_obligations: Vec::new(),
        };
        let receipt = port.revoke_grant_closure(&revocation, &epoch)?;
        assert_eq!(
            receipt.declaration.affected_grants(),
            vec![
                "grant-local-leaf".to_owned(),
                "grant-local-mid".to_owned(),
                "grant-local-root".to_owned(),
            ]
        );
        assert!(receipt.declaration.preserved.is_empty());
        assert!(matches!(receipt.state, GrantClosureState::Revoked));
        assert!(port.grant_revoked("grant-local-leaf"));
        assert_eq!(
            port.revocation_closure("op-local-revoke"),
            Some(receipt.declaration.affected_grants())
        );
        assert_eq!(
            port.closure_receipt("op-local-revoke"),
            Some(receipt.clone())
        );

        // Unknown ledger-only target records a reconciling intent.
        let mut unknown = revocation.clone();
        unknown.operation_id = "op-local-unknown".to_owned();
        unknown.grant_id = "grant-local-ghost".to_owned();
        assert!(matches!(
            port.revoke_grant_closure(&unknown, &epoch),
            Err(KernelError::InvalidField { .. })
        ));
        assert!(
            port.reconciling_operations()
                .contains(&"op-local-unknown".to_owned())
        );
        assert_eq!(
            port.revocation_closure("op-local-unknown"),
            Some(Vec::new())
        );
        Ok(())
    }
}
