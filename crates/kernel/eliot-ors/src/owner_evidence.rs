//! Production owner-backed [`CanonicalEvidenceProvider`] for the canonical
//! Store ordering heads.
//!
//! Issue #1925, package W, join (1). The production composition used to open
//! ORS with the internal rejecting default provider, so
//! `RedbRecoveryStore::stage_and_reserve` refused every correct seed at
//! `self.evidence.verify_ordering_heads(..)` before it could reserve a scope.
//! This module is the production replacement: the ordering-head proof it
//! authenticates comes from a REAL owner read taken by the caller through the
//! existing public store client surface, BEFORE the short synchronous ORS
//! write transaction.
//!
//! # Why the observation is armed, not read here
//!
//! [`CanonicalEvidenceProvider::verify_ordering_heads`] is synchronous and is
//! called from inside `stage_and_reserve`, which runs inside one short redb
//! write transaction. The canonical Store read is asynchronous
//! (`CanonicalStoreClient::ordering_heads`). Awaiting the owner from inside the
//! synchronous callback would hold the ORS write lock across a network wait,
//! which `A13.9` forbids ("no transaction, exclusive owner, or global lock may
//! be held during unbounded model, tool, or network wait").
//!
//! So the read is split in two, and the seam is deliberate:
//!
//! ```text
//! [RedbRecoveryStore::stage_and_reserve_after_owner_read]  (async, no ORS lock held)
//!   -> CanonicalStoreClient::ordering_heads(requested scopes)   <- the real owner read
//!   -> OwnerOrderingHeadEvidence::observe_committed_heads        <- validate + arm
//!   -> [stage_and_reserve]                                      (short sync transaction)
//!        -> verify_ordering_heads                                <- consume the arming
//! ```
//!
//! The armed observation is single-use: [`OwnerOrderingHeadEvidence`] stores it
//! behind a mutex and [`CanonicalEvidenceProvider::verify_ordering_heads`]
//! takes it. A second reservation, a replay that returns early, or any other
//! caller observes an unarmed provider and is refused. Evidence never outlives
//! the one transaction it authorizes.
//!
//! # What is verified, and what is deliberately not
//!
//! Verified against the owner read, per requested scope:
//!
//! * the owner publishes a row for the scope, or the scope is at genesis;
//! * the owner-observed committed sequence equals the sequence the request
//!   claims to extend (a stale or ahead claim is refused);
//! * the owner row's `StateFence` equals the caller's live generation fence,
//!   so a foreign or superseded owner observation can never arm the provider;
//! * the observed scope set is exactly the requested set, so a partially
//!   answered read cannot be read as complete evidence.
//!
//! NOT verified here, and not fabricated: the ordering **head digest**
//! (`ExpectedOrderingHead::head_sha256`). The canonical Store's public
//! ordering-head read publishes no head digest at all —
//! `eliot_store_api::OrderingHead`
//! (`crates/storage/eliot-store-api/src/lib.rs:4395`) carries only
//! `scope`/`sequence`/`state_fence`. The one read that does see a per-scope
//! link hash, `READ_ORDERING_CHAIN_TIPS_BY_SCOPES`
//! (`crates/storage/eliot-store-surreal-adapter/src/schema.rs:978`), selects
//! only `{ordering_scope, event_hash}` — no sequence, no previous hash, not an
//! ordering link — and is `pub(crate)`, read solely by the private
//! `read_ordering_chain_tips_inner`
//! (`crates/storage/eliot-store-surreal-adapter/src/apply.rs:2169`) whose one
//! caller is the in-transaction apply preflight at `apply.rs:1285`. It is not
//! reachable from any public client surface.
//!
//! The digest therefore keeps exactly the guarantee it already had and is not
//! weakened here: `ExpectedOrderingHead::validate` still requires a
//! well-formed lowercase SHA-256, and ORS's own durable scope head still
//! compares the WHOLE recorded `ExpectedOrderingHead`, digest included, against
//! the head persisted from a real canonical reconciliation
//! (`reserve_scope_sequences`, and again in `ensure_canonical_heads`). This
//! provider adds the independent owner-side check of scope and sequence; it
//! does not restate, recompute, or replace the digest check.
//!
//! # The other three trait methods
//!
//! `verify_reconciliation`, `verify_receipt`, and `verify_recovery_inbox`
//! refuse here exactly as they refuse under the production default they
//! replace. Binding this provider therefore changes the ordering-head
//! behaviour only; it neither widens nor narrows any receipt, reconciliation,
//! or recovery-inbox admission. Those three need their own owner-issued proof
//! source and are not this join.

use std::collections::BTreeMap;
use std::sync::Mutex;

use eliot_contracts::StateFence;
use eliot_store_api::{CanonicalStoreClient, OrderingScopeId};

use crate::{
    CanonicalEvidenceProvider, CanonicalReconciliation, OperationalRecoveryStore, OrsError,
    RecoveryInboxItem, RedbRecoveryStore, ReservationRequest, ScopeReservationRequest,
    WriterReservationToken,
};

/// What the canonical Store owner actually publishes for one Ordering Scope.
///
/// `None` is a real owner answer, not missing evidence: the Store has no
/// committed ordering head for that scope yet, which is the genesis prior. The
/// Store's own admission rule for that case is the single reference this
/// module follows — a scope with no row is admissible only when the caller
/// expects sequence `1`
/// (`crates/storage/eliot-store-surreal-adapter/src/apply.rs:2337`). Every
/// other absent scope is a refusal here.
type OwnerScopeHead = Option<u64>;

/// One coherent owner observation, armed for exactly one ORS reservation.
#[derive(Debug)]
struct ObservedCommittedHeads {
    heads: BTreeMap<String, OwnerScopeHead>,
}

/// Production canonical-evidence provider bound to the canonical Store owner.
///
/// One instance is created per ORS open by
/// [`RedbRecoveryStore::open_for_installation_with_owner_evidence`] and is both
/// the store's [`CanonicalEvidenceProvider`] and the handle the async caller
/// uses to arm it. The trait object and the typed handle are the same
/// allocation, so an armed observation can only be seen by the store that read
/// it.
#[derive(Debug, Default)]
pub struct OwnerOrderingHeadEvidence {
    armed: Mutex<Option<ObservedCommittedHeads>>,
}

impl OwnerOrderingHeadEvidence {
    /// Creates an unarmed provider. An unarmed provider refuses every
    /// ordering-head verification; there is no permissive default state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            armed: Mutex::new(None),
        }
    }

    /// Reads the committed ordering heads for `requested_scopes` from the
    /// canonical Store owner and arms this provider with the result.
    ///
    /// This is the async half of the split described in the module header. It
    /// is called BEFORE the short synchronous ORS write transaction and holds
    /// no ORS lock, no Kernel service lock, and no admission lease across the
    /// await.
    ///
    /// The read is refused — nothing is armed — when the owner is unreachable,
    /// answers with a duplicate or out-of-set scope, answers a scope that is
    /// neither present nor at genesis, or answers at any fence other than
    /// `live_fence`. A stale or foreign owner observation can therefore never
    /// become evidence.
    ///
    /// # Errors
    ///
    /// Returns the owner [`StoreError`](eliot_store_api::StoreError) mapped to
    /// [`OrsError::StoreContract`] when the read fails, or
    /// [`OrsError::CanonicalEvidence`] when the answer cannot serve as
    /// evidence for the requested scopes at the supplied fence.
    pub async fn observe_committed_heads<C>(
        &self,
        client: &C,
        requested_scopes: &[OrderingScopeId],
        live_fence: &StateFence,
    ) -> Result<(), OrsError>
    where
        C: CanonicalStoreClient + ?Sized,
    {
        if requested_scopes.is_empty() {
            return Err(OrsError::CanonicalEvidence(
                "canonical ordering-head evidence requires at least one requested scope".to_owned(),
            ));
        }
        // The independent expected set is fixed BEFORE the read, so a
        // duplicate request is refused without spending an owner call and so
        // the completeness comparison below has a fixed denominator.
        let mut expected: BTreeMap<&str, OwnerScopeHead> = BTreeMap::new();
        for scope in requested_scopes {
            if expected.insert(scope.as_str(), None).is_some() {
                return Err(OrsError::CanonicalEvidence(
                    "canonical ordering-head evidence was requested for a duplicate scope"
                        .to_owned(),
                ));
            }
        }

        let read = client.ordering_heads(requested_scopes.to_vec()).await?;
        for head in &read {
            head.validate()?;
            if head.state_fence != *live_fence {
                return Err(OrsError::CanonicalEvidence(format!(
                    "canonical Store ordering head for scope {} is not at the live generation fence",
                    head.scope
                )));
            }
            match expected.get_mut(head.scope.as_str()) {
                Some(slot) => {
                    if slot.is_some() {
                        return Err(OrsError::CanonicalEvidence(format!(
                            "canonical Store returned two ordering heads for scope {}",
                            head.scope
                        )));
                    }
                    *slot = Some(head.sequence);
                }
                None => {
                    return Err(OrsError::CanonicalEvidence(format!(
                        "canonical Store returned an ordering head for unrequested scope {}",
                        head.scope
                    )));
                }
            }
        }

        let heads = expected
            .into_iter()
            .map(|(scope, sequence)| (scope.to_owned(), sequence))
            .collect();
        self.arm(ObservedCommittedHeads { heads })
    }

    /// Installs one validated observation, replacing nothing: a provider that
    /// is already armed refuses, so two reservations can never share one owner
    /// read.
    fn arm(&self, observed: ObservedCommittedHeads) -> Result<(), OrsError> {
        let mut armed = self.armed.lock().map_err(|_| {
            OrsError::CanonicalEvidence("canonical ordering-head evidence lock poisoned".to_owned())
        })?;
        if armed.is_some() {
            return Err(OrsError::CanonicalEvidence(
                "canonical ordering-head evidence is already armed for another reservation"
                    .to_owned(),
            ));
        }
        *armed = Some(observed);
        Ok(())
    }

    /// Drops any armed observation. Called after every attempt so an early
    /// return that never reached the provider cannot leave evidence armed.
    fn disarm(&self) {
        if let Ok(mut armed) = self.armed.lock() {
            *armed = None;
        }
    }
}

impl CanonicalEvidenceProvider for OwnerOrderingHeadEvidence {
    /// Authenticates the requested ordering heads against the owner read armed
    /// for this transaction.
    ///
    /// Takes the arming: a second verification, or any verification that did
    /// not follow an owner read, is refused. Absent evidence refuses; a scope
    /// the owner did not answer refuses unless it is at genesis; a claimed
    /// sequence that differs from the owner-observed committed sequence refuses.
    fn verify_ordering_heads(
        &self,
        scopes: &[ScopeReservationRequest],
    ) -> Result<(), OrsError> {
        let observed = self
            .armed
            .lock()
            .map_err(|_| {
                OrsError::CanonicalEvidence(
                    "canonical ordering-head evidence lock poisoned".to_owned(),
                )
            })?
            .take()
            .ok_or_else(|| {
                OrsError::CanonicalEvidence(
                    "no live canonical Store ordering-head observation is registered".to_owned(),
                )
            })?;
        if scopes.is_empty() {
            return Err(OrsError::CanonicalEvidence(
                "canonical ordering-head evidence rejects an empty scope set".to_owned(),
            ));
        }
        if scopes.len() != observed.heads.len() {
            return Err(OrsError::CanonicalEvidence(
                "requested ordering scopes do not match the canonical Store observation set"
                    .to_owned(),
            ));
        }
        for scope in scopes {
            let committed = observed.heads.get(scope.scope.as_str()).ok_or_else(|| {
                OrsError::CanonicalEvidence(format!(
                    "canonical Store observation has no ordering head for scope {}",
                    scope.scope
                ))
            })?;
            let expected = scope.expected_head.sequence;
            let agrees = match committed {
                Some(observed_sequence) => *observed_sequence == expected,
                // The Store's own genesis rule for a scope with no committed
                // head: admissible only at sequence 1
                // (`crates/storage/eliot-store-surreal-adapter/src/apply.rs:2337`).
                None => expected == 1,
            };
            if !agrees {
                return Err(OrsError::CanonicalEvidence(format!(
                    "requested ordering head for scope {} is not the committed canonical Store head",
                    scope.scope
                )));
            }
        }
        Ok(())
    }

    /// Refuses: this provider carries ordering-head evidence only. Receipt
    /// admission keeps the fail-closed behaviour of the production default it
    /// replaces.
    fn verify_reconciliation(
        &self,
        _token: &WriterReservationToken,
        _reconciliation: &CanonicalReconciliation,
    ) -> Result<(), OrsError> {
        Err(OrsError::CanonicalEvidence(
            "canonical reconciliation proof source is not installed".to_owned(),
        ))
    }

    /// Refuses: see [`Self::verify_reconciliation`].
    fn verify_receipt(&self, _receipt: &eliot_receipts::ReceiptEnvelope) -> Result<(), OrsError> {
        Err(OrsError::CanonicalEvidence(
            "canonical receipt proof source is not installed".to_owned(),
        ))
    }

    /// Refuses: see [`Self::verify_reconciliation`].
    fn verify_recovery_inbox(&self, _item: &RecoveryInboxItem) -> Result<(), OrsError> {
        Err(OrsError::CanonicalEvidence(
            "recovery inbox signer proof source is not installed".to_owned(),
        ))
    }
}

impl RedbRecoveryStore {
    /// Reserves every declared Ordering Scope after a real owner read, or
    /// reserves none.
    ///
    /// This is the production reservation entry for a store opened with
    /// [`RedbRecoveryStore::open_for_installation_with_owner_evidence`]. It is
    /// the async half of the seam described in this module's header: the
    /// canonical Store read happens FIRST, with no ORS lock, no Kernel service
    /// lock, and no admission lease held across the await, and only then does
    /// the short synchronous
    /// [`OperationalRecoveryStore::stage_and_reserve`] transaction run and
    /// consume the armed observation.
    ///
    /// Any failure — an absent provider, a failed or incomplete owner read, a
    /// stale or foreign owner fence, a head mismatch, or any ORS refusal —
    /// reserves nothing and consumes no sequence. The armed observation is
    /// always cleared before returning, so a failure that never reached the
    /// provider cannot leave evidence armed for a later reservation.
    ///
    /// # Errors
    ///
    /// Returns the owner [`StoreError`](eliot_store_api::StoreError) mapped
    /// through [`OrsError`] when the owner read fails, and otherwise the exact
    /// [`OrsError`] the ORS reservation produced.
    pub async fn stage_and_reserve_after_owner_read<C>(
        &self,
        client: &C,
        request: ReservationRequest,
        live_fence: &StateFence,
    ) -> Result<WriterReservationToken, OrsError>
    where
        C: CanonicalStoreClient + ?Sized,
    {
        let evidence = self.owner_evidence.as_ref().ok_or_else(|| {
            OrsError::CanonicalEvidence(
                "this ORS was opened without an owner-backed ordering-head evidence provider"
                    .to_owned(),
            )
        })?;

        // The request's own scope set is the expected set for the owner read:
        // the read is asked for exactly what the reservation will consume, so
        // the provider can reject a partially answered read.
        let requested = request
            .scopes
            .iter()
            .map(|scope| OrderingScopeId::new(scope.scope.as_str()))
            .collect::<Result<Vec<_>, _>>()?;

        let observed = evidence.observe_committed_heads(client, &requested, live_fence).await;
        let reserved = match observed {
            Ok(()) => {
                <RedbRecoveryStore as OperationalRecoveryStore>::stage_and_reserve(self, request)
            }
            Err(error) => Err(error),
        };
        evidence.disarm();
        reserved
    }
}
