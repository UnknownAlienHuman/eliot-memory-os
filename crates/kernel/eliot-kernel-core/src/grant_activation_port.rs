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
    CapabilityIntroductionActivation, GrantClosureCommit, GrantClosurePreserved, GrantClosureState,
    OpaqueLabel, OperationIdentity, OperationalPhase, OperationalRecordInput,
    OperationalRecoveryStore, StateFenceSnapshot,
};
use eliot_receipts::{AuthorityBinding, EffectClass, ProofCeiling};
use eliot_runtime_contracts::{
    AuthorityActivationReceipt, AuthorityRevocationReceipt, AuthorityState,
};
use serde::Serialize;

use crate::error::{KernelError, validate_id, validate_text};
use crate::introduction_lifecycle::{IntroductionHydration, introduction_fence_input};

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
    /// Checks every canonical field before the hydration enters the gate.
    ///
    /// The source owns semantic resolution, but the port owns this boundary
    /// check: no omitted/defaulted identity, lineage, binding, ceiling, time,
    /// or obligation field can reach ORS or live state.
    fn validate_complete(
        &self,
        request: &eliot_authority::GrantActivationRequest,
        operation_id: &str,
        active_epoch: &EpochId,
    ) -> Result<(), KernelError> {
        self.validate_fields(active_epoch)?;
        if self.intent.operation_id != operation_id
            || self.intent.grant_id != request.grant_id.as_str()
            || self.intent.snapshot_id != request.snapshot_id.as_str()
            || self.intent.binding != request.binding
        {
            return Err(KernelError::RecoveryUnavailable(
                "hydrated root-grant identity disagrees with the thin request".to_owned(),
            ));
        }
        if self.durable_record.record().record_id.as_str() != operation_id
            || self.durable_record.record().subject_id.as_str() != request.grant_id.as_str()
        {
            return Err(KernelError::RecoveryUnavailable(
                "hydrated opaque root-grant record has a different identity".to_owned(),
            ));
        }
        // Opaque↔intent seal: contour, shape/integrity reconstruction, and
        // epoch/fence agreement before the record becomes the trust anchor.
        verify_grant_seal(&self.durable_record, &self.intent, active_epoch)
    }

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

/// One descendant the Governor owner keeps usable under a surviving alternate
/// authority path while the rest of the closure is fenced.
///
/// The covering path is Governor semantic evidence recorded verbatim: the
/// Kernel never evaluates, widens, or re-derives it. It only checks identity
/// shape and disjointness from the fenced set.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantClosureSurvivor {
    /// Preserved descendant grant identity.
    pub grant_id: String,
    /// Covering grant identity on the surviving alternate path.
    pub covering_grant_id: String,
    /// Lineage domain of the surviving alternate path.
    pub covering_root_ref: String,
}

/// Durable receipt for one committed grant closure.
///
/// The receipt binds one operation identity to one exact revision, one fence
/// contour, and the complete affected set. It is recorded in the intent ledger
/// beside the single canonical revocation (or activation) receipt and is
/// rehydrated on restart by re-presentation through the owner enumeration, so
/// `closure_receipt`, `revocation_closure`, and `disposition` read back
/// restart-identical values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantClosureReceipt {
    /// Idempotency identity of the closure operation.
    pub operation_id: String,
    /// Lineage domain of the closure.
    pub authority_root_ref: String,
    /// Closure target: the revoked (or activated) delegation root.
    pub target_grant_id: String,
    /// Exact graph revision the closure committed at.
    pub grant_graph_revision: u64,
    /// Complete affected set: the target plus every fenced descendant, in
    /// sorted order.
    pub affected_grants: Vec<String>,
    /// Owner-declared alternate-path survivors, in sorted order. Empty for an
    /// activation closure.
    pub preserved_grants: Vec<GrantClosureSurvivor>,
    /// Introductions fenced live when the closure committed, in sorted
    /// order. They carry no supporting set here: the fence was verified
    /// against live supporters at commit time, and this list only reinstalls
    /// the fence after a restart so a fenced introduction can never read as
    /// usable again. Empty for an activation closure.
    pub fenced_introductions: Vec<String>,
    /// Committed closure state: `Active` for an activation closure,
    /// `Revoked` for a revocation closure.
    pub state: AuthorityState,
}

impl GrantClosureReceipt {
    /// Re-validates the recorded closure receipt shape.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] when any identity is blank, the
    /// revision is zero, the affected set is empty, unsorted, duplicated, or
    /// misses the target, a survivor overlaps the affected set, or the state
    /// is neither `Active` nor `Revoked`.
    pub fn validate(&self) -> Result<(), KernelError> {
        validate_id(&self.operation_id, "closure_receipt.operation_id")?;
        validate_id(&self.authority_root_ref, "closure_receipt.authority_root_ref")?;
        validate_id(&self.target_grant_id, "closure_receipt.target_grant_id")?;
        if self.grant_graph_revision == 0 {
            return Err(KernelError::InvalidField {
                field: "closure_receipt.grant_graph_revision",
                reason: "grant graph revision must be nonzero",
            });
        }
        if self.affected_grants.is_empty() {
            return Err(KernelError::InvalidField {
                field: "closure_receipt.affected_grants",
                reason: "a committed closure affects at least its target",
            });
        }
        let mut previous: Option<&str> = None;
        for grant_id in &self.affected_grants {
            validate_id(grant_id, "closure_receipt.affected_grant")?;
            if let Some(previous) = previous
                && previous >= grant_id.as_str()
            {
                return Err(KernelError::InvalidField {
                    field: "closure_receipt.affected_grants",
                    reason: "affected grants must be sorted and unique",
                });
            }
            previous = Some(grant_id.as_str());
        }
        if !self.affected_grants.contains(&self.target_grant_id) {
            return Err(KernelError::InvalidField {
                field: "closure_receipt.target_grant_id",
                reason: "the closure target must be in the affected set",
            });
        }
        let mut previous_survivor: Option<(&str, &str, &str)> = None;
        for survivor in &self.preserved_grants {
            validate_id(&survivor.grant_id, "closure_receipt.survivor_grant")?;
            validate_id(
                &survivor.covering_grant_id,
                "closure_receipt.survivor_covering_grant",
            )?;
            validate_id(
                &survivor.covering_root_ref,
                "closure_receipt.survivor_covering_root",
            )?;
            if self.affected_grants.contains(&survivor.grant_id) {
                return Err(KernelError::InvalidField {
                    field: "closure_receipt.preserved_grants",
                    reason: "a survivor must be disjoint from the affected set",
                });
            }
            let key = (
                survivor.grant_id.as_str(),
                survivor.covering_grant_id.as_str(),
                survivor.covering_root_ref.as_str(),
            );
            if let Some(previous) = previous_survivor
                && previous >= key
            {
                return Err(KernelError::InvalidField {
                    field: "closure_receipt.preserved_grants",
                    reason: "survivors must be sorted and unique",
                });
            }
            previous_survivor = Some(key);
        }
        let mut previous_introduction: Option<&str> = None;
        for introduction_id in &self.fenced_introductions {
            validate_id(introduction_id, "closure_receipt.fenced_introduction")?;
            if let Some(previous) = previous_introduction
                && previous >= introduction_id.as_str()
            {
                return Err(KernelError::InvalidField {
                    field: "closure_receipt.fenced_introductions",
                    reason: "fenced introductions must be sorted and unique",
                });
            }
            previous_introduction = Some(introduction_id.as_str());
        }
        if !matches!(
            self.state,
            AuthorityState::Active | AuthorityState::Revoked
        ) {
            return Err(KernelError::InvalidField {
                field: "closure_receipt.state",
                reason: "a closure receipt is Active or Revoked",
            });
        }
        Ok(())
    }
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
/// The intent carries no member list: the fence set is derived from the live
/// lineage plus the injected Governor enumeration, which must agree exactly.
/// Anything less than the complete declared closure refuses as incomplete.
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
    /// operation identity returns the same receipt; a changed payload under
    /// one identity, a duplicate introduction identity, or a `Fenced`
    /// durable row fails before any mutation — restore never reactivates a
    /// fenced introduction.
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
        match ledger.resolve(&request.operation_id, &digest) {
            IntentResolve::Conflict => return Err(KernelError::IdempotencyConflict),
            IntentResolve::Replay(disposition) => {
                return disposition.into_activation_receipt();
            }
            IntentResolve::New => {}
        }
        validate_introduction_activation(request, &ledger, active_epoch, now_ms)?;
        verify_introduction_seal(&hydration.durable_record, request, active_epoch)?;
        // Durable row gate: only an absent row may be committed. An `Active`
        // row must carry the exact presented input (exact replay installs
        // through the idempotent ORS transition); a `Fenced` row is fence
        // evidence and refuses with the explicit state-machine guard.
        let subject = OperationIdentity::new(&request.introduction_id)
            .map_err(KernelError::RecoveryState)?;
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
        let subject = OperationIdentity::new(&request.introduction_id)
            .map_err(KernelError::RecoveryState)?;
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
        let fence_record =
            introduction_fence_input(&activation_input, &request.operation_id)?;
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
    /// live state. A missing row, a `Fenced` row, or a disagreeing row stays
    /// fail-closed: absence of the durable introduction never restores
    /// introduction authority, and a fence is never resurrected.
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
        match ledger.resolve(&request.operation_id, &digest) {
            IntentResolve::Conflict => return Err(KernelError::IdempotencyConflict),
            IntentResolve::Replay(disposition) => {
                return disposition.into_activation_receipt();
            }
            IntentResolve::New => {}
        }
        // Restore agreement first: only an `Active` row carrying the exact
        // presented input may be reinstalled. A `Fenced` row refuses with
        // the explicit guard; recovery never resurrects revoked authority.
        let subject = OperationIdentity::new(&request.introduction_id)
            .map_err(KernelError::RecoveryState)?;
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
        validate_introduction_activation(request, &ledger, active_epoch, now_ms)?;
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

    /// Returns the durable closure receipt committed for one closure target
    /// grant, if any.
    ///
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
        validate_closure_activation_members(&request.enumeration, &ledger, Some(boundary), active_epoch)?;
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
        // The closure row makes the operation, revision, digest, and receipt
        // durable as one committed object: a crash before the ledger insert
        // replays here instead of losing the closure identity.
        ensure_closure_row(
            boundary,
            &closure_commit_for(
                &request.operation_id,
                &closure_anchor,
                &request.enumeration.authority_root_ref,
                request.enumeration.grant_graph_revision,
                &digest,
                &closure_affected_set(&request.enumeration),
                &[],
                &[],
                GrantClosureState::Active,
            )?,
        )?;

        let mut receipts = Vec::with_capacity(request.enumeration.members.len());
        for member in &request.enumeration.members {
            let receipt = runtime_activation_receipt(&member.intent, active_epoch)?;
            ledger.grants.insert(
                member.intent.grant_id.clone(),
                LiveGrantRecord {
                    parent_grant_id: member.intent.parent_grant_id.clone(),
                    authority_root_ref: member.intent.authority_root_ref.clone(),
                    binding: member.intent.binding.clone(),
                    allowed_effect: member.intent.allowed_effect,
                    proof_ceiling: member.intent.proof_ceiling,
                    expires_at_ms: member.intent.expires_at_ms,
                    status: LiveStatus::Active,
                },
            );
            receipts.push(receipt);
        }
        let anchor_grant_id = closure_anchor.clone();
        let affected = closure_affected_set(&request.enumeration);
        let closure_receipt = GrantClosureReceipt {
            operation_id: request.operation_id.clone(),
            authority_root_ref: request.enumeration.authority_root_ref.clone(),
            target_grant_id: anchor_grant_id.clone(),
            grant_graph_revision: request.enumeration.grant_graph_revision,
            affected_grants: affected,
            preserved_grants: Vec::new(),
            fenced_introductions: Vec::new(),
            state: AuthorityState::Active,
        };
        closure_receipt.validate()?;
        let first = receipts.first().cloned().ok_or_else(|| {
            KernelError::RecoveryUnavailable(
                "closure enumeration lost its receipts during activation".to_owned(),
            )
        })?;
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
                disposition: IntentDisposition::Committed(CommittedReceipt::Activation(
                    first,
                )),
                fenced: Vec::new(),
                closure_receipt: Some(closure_receipt),
                closure_member_receipts: receipts.clone(),
            },
        );
        ledger
            .closure_targets
            .insert(anchor_grant_id, request.operation_id.clone());
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
                boundary.hydration.enumerate_grant_closure(&request.grant_id)
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
        let anchor_grant_id = closure_anchor_grant(&request.enumeration)?;
        let owner_enumeration = boundary.hydration.enumerate_grant_closure(&anchor_grant_id)?;
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
        validate_closure_activation_members(&request.enumeration, &ledger, Some(boundary), active_epoch)?;
        // Member expiry is checked at the recovery observation time, exactly
        // like the single-root recovery path: a member expired at `now_ms`
        // cannot be reinstalled as live authority.
        for member in &request.enumeration.members {
            check_expiry(member.intent.issued_at_ms, member.intent.expires_at_ms, now_ms)?;
        }
        check_closure_watermark(
            boundary,
            &request.enumeration.authority_root_ref,
            request.enumeration.grant_graph_revision,
        )?;
        // A crash between the member commits and the closure commit completes
        // here: the row is committed (or replayed when already present) before
        // any live state is installed.
        ensure_closure_row(
            boundary,
            &closure_commit_for(
                &request.operation_id,
                &anchor_grant_id,
                &request.enumeration.authority_root_ref,
                request.enumeration.grant_graph_revision,
                &digest,
                &closure_affected_set(&request.enumeration),
                &[],
                &[],
                GrantClosureState::Active,
            )?,
        )?;

        let mut receipts = Vec::with_capacity(request.enumeration.members.len());
        for member in &request.enumeration.members {
            let receipt = runtime_activation_receipt(&member.intent, active_epoch)?;
            ledger.grants.insert(
                member.intent.grant_id.clone(),
                LiveGrantRecord {
                    parent_grant_id: member.intent.parent_grant_id.clone(),
                    authority_root_ref: member.intent.authority_root_ref.clone(),
                    binding: member.intent.binding.clone(),
                    allowed_effect: member.intent.allowed_effect,
                    proof_ceiling: member.intent.proof_ceiling,
                    expires_at_ms: member.intent.expires_at_ms,
                    status: LiveStatus::Active,
                },
            );
            receipts.push(receipt);
        }
        let affected = closure_affected_set(&request.enumeration);
        let closure_receipt = GrantClosureReceipt {
            operation_id: request.operation_id.clone(),
            authority_root_ref: request.enumeration.authority_root_ref.clone(),
            target_grant_id: anchor_grant_id.clone(),
            grant_graph_revision: request.enumeration.grant_graph_revision,
            affected_grants: affected,
            preserved_grants: Vec::new(),
            fenced_introductions: Vec::new(),
            state: AuthorityState::Active,
        };
        closure_receipt.validate()?;
        let first = receipts.first().cloned().ok_or_else(|| {
            KernelError::RecoveryUnavailable(
                "closure enumeration lost its receipts during recovery".to_owned(),
            )
        })?;
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
                disposition: IntentDisposition::Committed(CommittedReceipt::Activation(
                    first,
                )),
                fenced: Vec::new(),
                closure_receipt: Some(closure_receipt),
                closure_member_receipts: receipts.clone(),
            },
        );
        ledger
            .closure_targets
            .insert(anchor_grant_id, request.operation_id.clone());
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
        let owner_enumeration = boundary.hydration.enumerate_grant_closure(&request.grant_id)?;
        self.revoke_closure_core(request, active_epoch, Some(boundary), Some(&owner_enumeration))
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
        // Derive the fence set before the idempotency gate: the digest binds
        // the complete affected set, so exact replay re-derives the same
        // digest while any changed member is a typed conflict. These are
        // read-only derivations; no mutation happens above the gate.
        let derived = derive_closure_fence(
            &ledger,
            request,
            boundary,
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
                return record.closure_receipt.clone().ok_or(KernelError::IdempotencyConflict);
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

        // Durable linearization: one ORS `Active`-to-`Fenced`
        // compare-and-swap per affected member with an exact read-back. A
        // crash between members is recovered by exact re-presentation (an
        // already-`Fenced` member replays its receipt; a reconfirmed member
        // is skipped because its fence already covers the exact authority;
        // nothing is installed live until every read-back agrees).
        //
        // Live fencing runs before the closure-row commit so the row records
        // the exact fenced introduction set; a retry re-fences idempotently
        // and recommits the same row.
        let mut fenced_introductions: BTreeSet<String> = BTreeSet::new();
        if let Some(boundary) = boundary {
            check_closure_watermark(
                boundary,
                &request.authority_root_ref,
                request.grant_graph_revision,
            )?;
            for member in &derived.members {
                if member.reconfirmed {
                    continue;
                }
                let revocation_record =
                    closure_member_revocation(&member.activation_input, &request.operation_id)?;
                let durable_receipt = boundary
                    .store
                    .revoke_capability_grant(revocation_record.clone())
                    .map_err(|error| map_ors_recovery_error(&error))?;
                let subject = OperationIdentity::new(&member.grant_id)
                    .map_err(KernelError::RecoveryState)?;
                let projection = boundary
                    .store
                    .load_capability_grant(&subject)
                    .map_err(|error| map_ors_recovery_error(&error))?
                    .ok_or_else(|| {
                        KernelError::RecoveryUnavailable(
                            "closure member projection disappeared during revocation".to_owned(),
                        )
                    })?;
                if projection.phase() != OperationalPhase::Fenced
                    || projection.record() != revocation_record.record()
                    || projection.receipt() != durable_receipt.receipt()
                {
                    return Err(KernelError::RecoveryUnavailable(
                        "closure member revocation ORS receipt/read-back disagreed".to_owned(),
                    ));
                }
            }
            for introduction_id in fence_live_closure_members(&mut ledger, &derived.affected) {
                fenced_introductions.insert(introduction_id);
            }
            // A present row (crash between commit and install, or recovery
            // re-presentation) already recorded the fenced introduction set
            // when live supporters existed. Union it before committing so the
            // exact row replays instead of mismatching on evidence the fresh
            // live map can no longer derive.
            let operation_id = OperationIdentity::new(&request.operation_id)
                .map_err(KernelError::RecoveryState)?;
            if let Some(present) = boundary
                .store
                .load_grant_closure(&operation_id)
                .map_err(|error| map_ors_recovery_error(&error))?
            {
                for introduction_id in &present.commit().fenced_introductions {
                    fenced_introductions.insert(introduction_id.as_str().to_owned());
                }
            }
            // The closure row makes the operation, revision, digest, affected
            // set, survivors, fenced introductions, and receipt durable as
            // one committed object: a crash before the ledger insert replays
            // here instead of losing the closure identity. The union above
            // guarantees the candidate reproduces the stored row exactly, so
            // the reinstall below restores the same evidence on every path.
            let stored_commit = ensure_closure_row(
                boundary,
                &closure_commit_for(
                    &request.operation_id,
                    &request.grant_id,
                    &request.authority_root_ref,
                    request.grant_graph_revision,
                    &digest,
                    &derived.affected,
                    &derived.preserved,
                    &fenced_introductions.iter().cloned().collect::<Vec<_>>(),
                    GrantClosureState::Fenced,
                )?,
            )?;
            // Reinstall fenced-introduction evidence: after a restart the live
            // map is empty, so the union above (live fence plus stored row)
            // is the only record that these introductions were fenced and
            // must never read as usable again.
            for introduction_id in &stored_commit.fenced_introductions {
                fenced_introductions.insert(introduction_id.as_str().to_owned());
            }
        } else {
            // Ledger-only mode: no durable row exists, so only the live
            // fence is recorded.
            for introduction_id in fence_live_closure_members(&mut ledger, &derived.affected) {
                fenced_introductions.insert(introduction_id);
            }
        }
        for introduction_id in &fenced_introductions {
            ledger.introductions.entry(introduction_id.clone()).or_insert(
                LiveIntroductionRecord {
                    authority_root_ref: request.authority_root_ref.clone(),
                    supporting_grant_ids: BTreeSet::new(),
                    status: LiveStatus::Revoked,
                },
            );
        }
        let fenced_introductions: Vec<String> = fenced_introductions.into_iter().collect();
        let receipt = AuthorityRevocationReceipt {
            revocation_id: format!("revocation-{}", request.operation_id),
            snapshot_id: request.snapshot_id.clone(),
            authority_epoch: active_epoch.clone(),
            state: AuthorityState::Revoked,
        };
        receipt.validate()?;
        let closure_receipt = GrantClosureReceipt {
            operation_id: request.operation_id.clone(),
            authority_root_ref: request.authority_root_ref.clone(),
            target_grant_id: request.grant_id.clone(),
            grant_graph_revision: request.grant_graph_revision,
            affected_grants: derived.affected.clone(),
            preserved_grants: derived.preserved.clone(),
            fenced_introductions,
            state: AuthorityState::Revoked,
        };
        closure_receipt.validate()?;
        ledger.note_revision(
            &request.authority_root_ref,
            request.grant_graph_revision,
        );
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
        let digest =
            hydrated_root_grant_digest(&hydration).map_err(|error| map_thin_error(&error))?;
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
        check_root_activation_durability(boundary, &hydration)?;
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
            || receipt.target_grant_id != request.grant_id.as_str()
            || receipt.state != AuthorityState::Revoked
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
#[derive(Debug, Default)]
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

/// Returns the unique delegation anchor of one enumeration: the member
/// whose parent is `None` (a delegation root) or names a grant outside the
/// enumeration (a mid-chain subtree or an incremental delegation onto a
/// recorded parent). Structure validation requires exactly one.
fn closure_anchor_grant(enumeration: &GrantClosureEnumeration) -> Result<String, KernelError> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut anchor: Option<&str> = None;
    for member in &enumeration.members {
        let is_anchor = member.intent.parent_grant_id.as_deref().is_none_or(|parent| {
            !seen.contains(parent)
        });
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

/// Validates one Governor-enumerated closure structurally, before any
/// mutation and without consulting live state.
///
/// Every member must share the exact enumeration revision, root, and fence
/// contour; parents must appear earlier in parent-before-child order; opaque
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
    let mut previous_survivor: Option<(&str, &str, &str)> = None;
    for survivor in &enumeration.preserved {
        validate_id(&survivor.grant_id, "enumeration.survivor_grant")?;
        validate_id(
            &survivor.covering_grant_id,
            "enumeration.survivor_covering_grant",
        )?;
        validate_id(
            &survivor.covering_root_ref,
            "enumeration.survivor_covering_root",
        )?;
        let key = (
            survivor.grant_id.as_str(),
            survivor.covering_grant_id.as_str(),
            survivor.covering_root_ref.as_str(),
        );
        if let Some(previous) = previous_survivor
            && previous >= key
        {
            return Err(KernelError::InvalidField {
                field: "enumeration.preserved",
                reason: "survivors must be sorted and unique",
            });
        }
        previous_survivor = Some(key);
    }
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
            if !seen.contains(parent.as_str()) {
                anchor_count += 1;
            }
        } else {
            anchor_count += 1;
        }
        validate_id(&intent.authority_root_ref, "enumeration.member.authority_root_ref")?;
        validate_id(&intent.snapshot_id, "enumeration.member.snapshot_id")?;
        validate_id(&intent.holder_principal, "enumeration.member.holder_principal")?;
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
        check_ceiling(
            intent.allowed_effect,
            intent.proof_ceiling,
            &intent.binding,
        )?;
        check_expiry(
            intent.issued_at_ms,
            intent.expires_at_ms,
            member.observed_at_ms,
        )?;
        if let Some(contour) = contour {
            if contour.state_fence != intent.binding.state_fence
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
                parent_grant_id: intent.parent_grant_id.clone(),
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

/// One affected member with the exact opaque activation input its durable
/// fence is derived from.
struct ClosureFenceMember {
    grant_id: String,
    activation_input: OperationalRecordInput,
    /// A `Fenced` row already covers the same authority under a different
    /// closure operation: the fence is reconfirmed, never recommitted.
    reconfirmed: bool,
}

/// Read-only fence derivation for one closure revocation: the complete
/// affected set, the owner-declared survivors, and the per-member opaque
/// inputs. No mutation happens here; the caller commits after the idempotency
/// gate.
struct DerivedClosureFence {
    affected: Vec<String>,
    preserved: Vec<GrantClosureSurvivor>,
    members: Vec<ClosureFenceMember>,
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
/// Without the durable boundary the fence set is the recorded live
/// descendant closure and no survivor can be declared. An unrecorded target
/// reports `unknown_target` so the caller records a reconciling intent
/// instead of fabricating a fence.
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
    let Some(boundary) = boundary else {
        return derive_ledger_closure_fence(ledger, request);
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
    if let Some(external_parent) = anchor
        .intent
        .parent_grant_id
        .as_deref()
        .filter(|parent| {
            !enumeration
                .members
                .iter()
                .any(|member| member.intent.grant_id.as_str() == *parent)
        })
    {
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
    for survivor in &enumeration.preserved {
        if let Some(record) = ledger.grants.get(&survivor.grant_id)
            && record.status != LiveStatus::Active
        {
            return Err(KernelError::InvalidField {
                field: "enumeration.preserved",
                reason: "a declared survivor is not live authority",
            });
        }
    }
    let preserved_set: BTreeSet<&str> = enumeration
        .preserved
        .iter()
        .map(|survivor| survivor.grant_id.as_str())
        .collect();
    for descendant in descendant_closure(&ledger.grants, &request.authority_root_ref, &request.grant_id)
    {
        if !affected_set.contains(descendant.as_str())
            && !preserved_set.contains(descendant.as_str())
        {
            return Err(KernelError::InvalidField {
                field: "grant_id",
                reason: "incomplete durable enumeration; a recorded descendant is neither fenced nor preserved",
            });
        }
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
        let subject = OperationIdentity::new(&member.intent.grant_id)
            .map_err(KernelError::RecoveryState)?;
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
        let reconfirmed = match projection.phase() {
            OperationalPhase::Active => {
                if projection.record() != member.durable_record.record() {
                    return Err(KernelError::RecoveryUnavailable(
                        "closure member ORS row disagrees with its enumerated input".to_owned(),
                    ));
                }
                false
            }
            OperationalPhase::Fenced => {
                if projection.record() == revocation_record.record() {
                    false
                } else if activation_bytes_equal(
                    projection.record(),
                    member.durable_record.record(),
                ) {
                    // A previous closure already fenced the exact authority:
                    // reconfirm it under this operation instead of forking a
                    // second fence. A fence over different authority stays
                    // fail-closed.
                    true
                } else {
                    return Err(KernelError::RecoveryUnavailable(
                        "closure member fence evidence disagrees with the derived revocation"
                            .to_owned(),
                    ));
                }
            }
            _ => {
                return Err(KernelError::RecoveryUnavailable(
                    "closure member ORS row is not fenceable".to_owned(),
                ));
            }
        };
        members.push(ClosureFenceMember {
            grant_id: member.intent.grant_id.clone(),
            activation_input: member.durable_record.record().clone(),
            reconfirmed,
        });
    }
    Ok(DerivedClosureFence {
        affected,
        preserved: enumeration.preserved.clone(),
        members,
        unknown_target: false,
    })
}

/// Ledger-only fence derivation: the recorded live descendant closure, or an
/// unknown-target marker that the caller records as reconciling.
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
            unknown_target: true,
        });
    }
    if let Some(record) = ledger.grants.get(&request.grant_id)
        && record.authority_root_ref != request.authority_root_ref
    {
        return Err(KernelError::FenceMismatch);
    }
    Ok(DerivedClosureFence {
        affected: descendant_closure(&ledger.grants, &request.authority_root_ref, &request.grant_id),
        preserved: Vec::new(),
        members: Vec::new(),
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
    input.record_id =
        OperationIdentity::new(closure_member_revocation_id(operation_id, &grant_id))
            .map_err(KernelError::RecoveryState)?;
    CapabilityGrantRevocation::new(input).map_err(KernelError::RecoveryState)
}

/// Compares two opaque activation inputs field by field except the mutable
/// record identity: the same subject, epoch lineage, fence, payload bytes,
/// and times is the same fenced authority, even when a previous closure
/// operation fenced it first.
fn activation_bytes_equal(
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
    let subject =
        OperationIdentity::new(grant_id).map_err(KernelError::RecoveryState)?;
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
    let root =
        OpaqueLabel::new(authority_root_ref).map_err(KernelError::RecoveryState)?;
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

/// Builds the durable closure commit from validated request material and the
/// derived fence. Every identity is already validated port-side; ORS
/// revalidates shape on commit.
#[allow(
    clippy::too_many_arguments,
    reason = "the closure commit binds every validated closure coordinate explicitly"
)]
fn closure_commit_for(
    operation_id: &str,
    target_grant_id: &str,
    authority_root_ref: &str,
    grant_graph_revision: u64,
    digest: &str,
    affected: &[String],
    preserved: &[GrantClosureSurvivor],
    fenced_introductions: &[String],
    state: GrantClosureState,
) -> Result<GrantClosureCommit, KernelError> {
    let affected = affected
        .iter()
        .map(|grant_id| OperationIdentity::new(grant_id).map_err(KernelError::RecoveryState))
        .collect::<Result<Vec<_>, _>>()?;
    let preserved = preserved
        .iter()
        .map(|survivor| {
            Ok::<_, KernelError>(GrantClosurePreserved {
                grant_id: OperationIdentity::new(&survivor.grant_id)
                    .map_err(KernelError::RecoveryState)?,
                covering_grant_id: OperationIdentity::new(&survivor.covering_grant_id)
                    .map_err(KernelError::RecoveryState)?,
                covering_root: OpaqueLabel::new(&survivor.covering_root_ref)
                    .map_err(KernelError::RecoveryState)?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let fenced_introductions = fenced_introductions
        .iter()
        .map(|introduction_id| {
            OperationIdentity::new(introduction_id).map_err(KernelError::RecoveryState)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(GrantClosureCommit {
        operation_id: OperationIdentity::new(operation_id).map_err(KernelError::RecoveryState)?,
        target_id: OperationIdentity::new(target_grant_id).map_err(KernelError::RecoveryState)?,
        authority_root: OpaqueLabel::new(authority_root_ref).map_err(KernelError::RecoveryState)?,
        revision: grant_graph_revision,
        digest: digest.to_owned(),
        affected,
        preserved,
        fenced_introductions,
        state,
    })
}

/// Commits one closure row and verifies the exact read-back: the stored row
/// must reproduce the presented commit. A present row with the same commit
/// is an exact replay (crash between commit and install) and its stored
/// commit is returned; a present row with different content stays
/// fail-closed instead of overwriting.
fn ensure_closure_row(
    boundary: &DurableRootGrantBoundary,
    commit: &GrantClosureCommit,
) -> Result<GrantClosureCommit, KernelError> {
    if let Some(existing) = boundary
        .store
        .load_grant_closure(&commit.operation_id)
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
        .load_grant_closure(&commit.operation_id)
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
fn check_root_activation_durability(
    boundary: &DurableRootGrantBoundary,
    hydration: &RootGrantHydration,
) -> Result<(), eliot_authority::P07PortError> {
    check_closure_watermark(
        boundary,
        &hydration.intent.authority_root_ref,
        hydration.intent.grant_graph_revision,
    )
    .map_err(|error| map_thin_error(&error))?;
    match check_activation_row(
        boundary,
        &hydration.intent.grant_id,
        hydration.durable_record.record(),
    ) {
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
    let subject =
        OperationIdentity::new(parent_grant_id).map_err(KernelError::RecoveryState)?;
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

/// Fences every affected member in live state plus every dependent
/// introduction whose supporting path crosses the fence, and returns the
/// sorted fenced introduction identities for the durable closure row.
/// Members with no live record (restart-rehydrated fences) join the revoked
/// set so they can never be mistaken for live authority.
fn fence_live_closure_members(ledger: &mut PortLedger, affected: &[String]) -> Vec<String> {
    for grant_id in affected {
        if let Some(target) = ledger.grants.get_mut(grant_id) {
            target.status = LiveStatus::Revoked;
        } else {
            ledger.revoked_grants.insert(grant_id.clone());
        }
    }
    let fenced_set: BTreeSet<&str> = affected.iter().map(String::as_str).collect();
    let mut fenced_introductions = BTreeSet::new();
    for (introduction_id, introduction) in &mut ledger.introductions {
        if introduction.status == LiveStatus::Active
            && introduction
                .supporting_grant_ids
                .iter()
                .any(|id| fenced_set.contains(id.as_str()))
        {
            introduction.status = LiveStatus::Revoked;
            fenced_introductions.insert(introduction_id.clone());
        }
    }
    fenced_introductions.into_iter().collect()
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
    preserved: BTreeSet<(&'a str, &'a str, &'a str)>,
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
    preserved: BTreeSet<(&'a str, &'a str, &'a str)>,
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
        preserved: enumeration
            .preserved
            .iter()
            .map(|survivor| {
                (
                    survivor.grant_id.as_str(),
                    survivor.covering_grant_id.as_str(),
                    survivor.covering_root_ref.as_str(),
                )
            })
            .collect(),
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
        preserved: derived
            .preserved
            .iter()
            .map(|survivor| {
                (
                    survivor.grant_id.as_str(),
                    survivor.covering_grant_id.as_str(),
                    survivor.covering_root_ref.as_str(),
                )
            })
            .collect(),
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
            closure_receipt: None,
            closure_member_receipts: Vec::new(),
        },
    );
}

fn validate_root_hydration(
    hydration: &RootGrantHydration,
    request: &eliot_authority::GrantActivationRequest,
    operation_id: &str,
    active_epoch: &EpochId,
) -> Result<(), KernelError> {
    hydration.validate_complete(request, operation_id, active_epoch)
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
        self.activate_introduction_durable(
            &hydration,
            &active_epoch,
            hydration.observed_at_ms,
        )
        .map_err(|error| map_thin_error(&error))
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
        //
        // Thin-request durable corroboration (`#2100`): when the durable
        // boundary is bound, the live record alone is not enough to fence —
        // the durable row must corroborate fencable authority. A `Fenced`
        // durable row contradicts the live record, so the fence refuses
        // instead of double-fencing or fabricating recovery; the durable
        // recovery path owns the repair. An absent row is the legacy
        // live-only flow and proceeds unchanged; durable introduction
        // adoption moves those flows onto `revoke_introduction_durable`.
        if let Some(boundary) = self.durable_boundary() {
            let subject = OperationIdentity::new(request.introduction_id.as_str())
                .map_err(|_| P07PortError::InvalidBinding)?;
            let row = boundary
                .store
                .load_capability_introduction(&subject)
                .map_err(|_| P07PortError::Unavailable)?;
            if row.is_some_and(|projection| projection.phase() != OperationalPhase::Active) {
                return Err(P07PortError::Unavailable);
            }
        }
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
