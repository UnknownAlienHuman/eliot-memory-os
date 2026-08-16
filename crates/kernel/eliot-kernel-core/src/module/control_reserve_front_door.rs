//! P-07 control reserve and front-door decision core.
//!
//! The front door is the single synchronous admission point for the Kernel. It
//! combines three owned properties: a bounded [`ControlReserve`] that data work
//! cannot consume, an idempotency ledger that deduplicates effects, and the
//! [`KernelAuthority`] that verifies non-forgeable receipts. It never performs
//! model inference, storage, or unbounded graph work.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use eliot_receipts::ProofCeiling;

use crate::RouteScope;
use crate::authority::{AuthorityGrant, AuthorityReceipt, KernelAuthority};
use crate::error::{KernelError, validate_id};

/// A bounded control reserve that data work can never starve.
///
/// The reserve is a fixed pool of control permits. Acquiring a permit is
/// non-blocking and atomic; releasing is automatic when the returned
/// [`ControlPermit`] drops. Saturation fails closed as
/// [`KernelError::ControlReserveExhausted`].
#[derive(Clone, Debug)]
pub struct ControlReserve {
    inner: Arc<ReserveInner>,
}

#[derive(Debug)]
struct ReserveInner {
    capacity: usize,
    in_flight: AtomicUsize,
}

/// A single held control permit. Releasing is automatic on drop.
#[derive(Debug)]
pub struct ControlPermit {
    inner: Arc<ReserveInner>,
}

impl ControlReserve {
    /// Creates a reserve with a non-zero capacity.
    ///
    /// # Errors
    ///
    /// Returns an error when the capacity is zero.
    pub fn new(capacity: usize) -> Result<Self, KernelError> {
        if capacity == 0 {
            return Err(KernelError::InvalidField {
                field: "control_reserve.capacity",
                reason: "must be greater than zero",
            });
        }
        Ok(Self {
            inner: Arc::new(ReserveInner {
                capacity,
                in_flight: AtomicUsize::new(0),
            }),
        })
    }

    /// Returns the configured capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }

    /// Returns the currently available control permits.
    #[must_use]
    pub fn available(&self) -> usize {
        self.inner
            .capacity
            .saturating_sub(self.inner.in_flight.load(Ordering::Acquire))
    }

    /// Attempts to acquire one control permit without blocking.
    #[must_use]
    pub fn try_acquire(&self) -> Option<ControlPermit> {
        let mut observed = self.inner.in_flight.load(Ordering::Acquire);
        loop {
            if observed >= self.inner.capacity {
                return None;
            }
            match self.inner.in_flight.compare_exchange_weak(
                observed,
                observed + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(ControlPermit {
                        inner: self.inner.clone(),
                    });
                }
                Err(current) => observed = current,
            }
        }
    }
}

impl Drop for ControlPermit {
    fn drop(&mut self) {
        self.inner.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The stable denial reason surfaced by the front door.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionDenialReason {
    /// The receipt failed its cryptographic binding.
    ForgedReceipt,
    /// The receipt belongs to a fenced epoch.
    StaleEpoch,
    /// The receipt targets a different route.
    RouteMismatch,
    /// The receipt has expired.
    Expired,
}

/// The result of one front-door admission decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityDecision {
    /// The receipt verified and the granted authority is returned.
    Granted(AuthorityGrant),
    /// The receipt could not authorize the request.
    Denied {
        /// Stable denial reason.
        reason: DecisionDenialReason,
    },
}

impl AuthorityDecision {
    /// Returns the granted authority, if any.
    #[must_use]
    pub fn granted(&self) -> Option<&AuthorityGrant> {
        match self {
            Self::Granted(grant) => Some(grant),
            Self::Denied { .. } => None,
        }
    }

    /// Returns `true` only for a granted decision.
    #[must_use]
    pub const fn is_granted(&self) -> bool {
        matches!(self, Self::Granted(_))
    }
}

/// The outcome of resolving an idempotency key before any effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdempotencyDisposition {
    /// The key has never been seen.
    New,
    /// The key was seen with the same digest; replay the prior decision.
    Replay(AuthorityDecision),
    /// The key was seen with a different digest.
    Conflict,
}

/// A bounded idempotency ledger that deduplicates effect admission.
///
/// The ledger is FIFO-bounded: when it reaches capacity, the oldest entry is
/// evicted, so a very old replay is re-evaluated rather than silently reused.
#[derive(Debug)]
pub struct IdempotencyLedger {
    capacity: usize,
    entries: BTreeMap<String, (String, AuthorityDecision)>,
    order: VecDeque<String>,
}

impl IdempotencyLedger {
    /// Creates a bounded ledger.
    ///
    /// # Errors
    ///
    /// Returns an error when the capacity is zero.
    pub fn new(capacity: usize) -> Result<Self, KernelError> {
        if capacity == 0 {
            return Err(KernelError::InvalidField {
                field: "idempotency_ledger.capacity",
                reason: "must be greater than zero",
            });
        }
        Ok(Self {
            capacity,
            entries: BTreeMap::new(),
            order: VecDeque::new(),
        })
    }

    /// Resolves an idempotency key against a request digest.
    #[must_use]
    pub fn resolve(&self, key: &str, digest: &str) -> IdempotencyDisposition {
        match self.entries.get(key) {
            Some((prior_digest, decision)) if prior_digest == digest => {
                IdempotencyDisposition::Replay(decision.clone())
            }
            Some(_) => IdempotencyDisposition::Conflict,
            None => IdempotencyDisposition::New,
        }
    }

    /// Records a decision under an idempotency key, evicting the oldest on overflow.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is blank or malformed.
    pub fn record(
        &mut self,
        key: &str,
        digest: &str,
        decision: AuthorityDecision,
    ) -> Result<(), KernelError> {
        validate_id(key, "idempotency_key")?;
        validate_id(digest, "request_digest")?;
        if !self.entries.contains_key(key) {
            self.order.push_back(key.to_owned());
        }
        self.entries
            .insert(key.to_owned(), (digest.to_owned(), decision));
        while self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        Ok(())
    }
}

/// The Kernel front door: the single synchronous admission decision core.
pub struct FrontDoor {
    authority: KernelAuthority,
    reserve: ControlReserve,
    ledger: Mutex<IdempotencyLedger>,
}

impl FrontDoor {
    /// Creates a front door from an authority holder and bounded parameters.
    ///
    /// # Errors
    ///
    /// Returns an error when `control_capacity` or `ledger_capacity` is zero.
    pub fn new(
        authority: KernelAuthority,
        control_capacity: usize,
        ledger_capacity: usize,
    ) -> Result<Self, KernelError> {
        Ok(Self {
            authority,
            reserve: ControlReserve::new(control_capacity)?,
            ledger: Mutex::new(IdempotencyLedger::new(ledger_capacity)?),
        })
    }

    /// Returns the current authority epoch.
    #[must_use]
    pub const fn epoch(&self) -> eliot_contracts::AuthorityEpoch {
        self.authority.current_epoch()
    }

    /// Returns the currently available control permits.
    #[must_use]
    pub fn available_control(&self) -> usize {
        self.reserve.available()
    }

    /// Admits one authority receipt through the control reserve and ledger.
    ///
    /// The control permit is released when the returned decision drops the
    /// held [`ControlPermit`], which happens at the end of this call; callers
    /// that need to keep control capacity held across a long effect should use
    /// [`Self::acquire_control`] explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::ControlReserveExhausted`] or
    /// [`KernelError::IdempotencyConflict`]. Receipt rejections are returned as
    /// [`AuthorityDecision::Denied`], never as an error.
    pub fn authorize(
        &self,
        receipt: &AuthorityReceipt,
        route: &RouteScope,
        now_ms: i64,
        idempotency_key: &str,
        request_digest: &str,
    ) -> Result<AuthorityDecision, KernelError> {
        let _permit = self
            .reserve
            .try_acquire()
            .ok_or(KernelError::ControlReserveExhausted)?;
        let mut ledger = self.lock_ledger();
        match ledger.resolve(idempotency_key, request_digest) {
            IdempotencyDisposition::Replay(decision) => return Ok(decision),
            IdempotencyDisposition::Conflict => return Err(KernelError::IdempotencyConflict),
            IdempotencyDisposition::New => {}
        }
        let decision = match self.authority.consume(receipt, route, now_ms) {
            Ok(grant) => AuthorityDecision::Granted(grant),
            Err(KernelError::ForgedReceipt) => AuthorityDecision::Denied {
                reason: DecisionDenialReason::ForgedReceipt,
            },
            Err(KernelError::StaleEpoch { .. }) => AuthorityDecision::Denied {
                reason: DecisionDenialReason::StaleEpoch,
            },
            Err(KernelError::RouteMismatch) => AuthorityDecision::Denied {
                reason: DecisionDenialReason::RouteMismatch,
            },
            Err(KernelError::Expired { .. }) => AuthorityDecision::Denied {
                reason: DecisionDenialReason::Expired,
            },
            Err(error) => return Err(error),
        };
        ledger.record(idempotency_key, request_digest, decision.clone())?;
        Ok(decision)
    }

    /// Acquires a control permit explicitly for a long-running control effect.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::ControlReserveExhausted`] when saturated.
    pub fn acquire_control(&self) -> Result<ControlPermit, KernelError> {
        self.reserve
            .try_acquire()
            .ok_or(KernelError::ControlReserveExhausted)
    }

    /// Raises the front-door epoch and fences all previously issued receipts.
    ///
    /// # Errors
    ///
    /// Returns an error when the epoch counter cannot advance.
    pub fn advance_epoch(&mut self) -> Result<eliot_contracts::AuthorityEpoch, KernelError> {
        self.authority.advance_epoch()
    }

    /// Fast-forwards the front-door fence to the durable recovery epoch.
    pub fn synchronize_epoch(
        &mut self,
        target: eliot_contracts::AuthorityEpoch,
    ) -> Result<eliot_contracts::AuthorityEpoch, KernelError> {
        self.authority.synchronize_epoch(target)
    }

    /// Returns whether a grant permits an effect without overclaiming proof.
    #[must_use]
    pub fn permits(
        grant: &AuthorityGrant,
        class: eliot_receipts::EffectClass,
        ceiling: ProofCeiling,
    ) -> bool {
        grant.permits(class, ceiling)
    }

    fn lock_ledger(&self) -> MutexGuard<'_, IdempotencyLedger> {
        self.ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ContractId, ResourceGeneration};
    use eliot_receipts::EffectClass;

    fn receipt(authority: &KernelAuthority) -> Result<AuthorityReceipt, KernelError> {
        authority.issue(crate::authority::AuthorityGrantRequest::new(
            ContractId::new("authority-1")?,
            "kernel",
            RouteScope::new("daemon")?,
            ResourceGeneration::genesis(),
            EffectClass::ReversibleMutation,
            ProofCeiling::ScopedVerification,
            100,
            Some(1_000),
        )?)
    }

    #[test]
    fn control_reserve_is_bounded_and_auto_releases() -> Result<(), KernelError> {
        let reserve = ControlReserve::new(2)?;
        let a = reserve.try_acquire().expect("first permit");
        let b = reserve.try_acquire().expect("second permit");
        assert!(reserve.try_acquire().is_none());
        drop(a);
        assert_eq!(reserve.available(), 1);
        assert!(reserve.try_acquire().is_some());
        drop(b);
        Ok(())
    }

    #[test]
    fn front_door_grants_valid_and_denies_tampered() -> Result<(), KernelError> {
        let authority = KernelAuthority::new(
            crate::authority::KernelAuthorityKey::from_bytes([3u8; 32]),
            AuthorityEpoch::genesis(),
        );
        let front_door = FrontDoor::new(authority.clone(), 2, 8)?;
        let route = RouteScope::new("daemon")?;
        let receipt = receipt(&authority)?;

        let decision = front_door.authorize(&receipt, &route, 500, "k-1", "d-1")?;
        assert!(decision.is_granted());

        let mut value = serde_json::to_value(&receipt).expect("receipt serializes");
        value["allowed_effect"] = serde_json::json!("EXTERNAL_EFFECT");
        let tampered: AuthorityReceipt =
            serde_json::from_value(value).expect("tampered receipt deserializes");
        let decision = front_door.authorize(&tampered, &route, 500, "k-2", "d-2")?;
        assert!(matches!(
            decision,
            AuthorityDecision::Denied {
                reason: DecisionDenialReason::ForgedReceipt
            }
        ));
        Ok(())
    }

    #[test]
    fn idempotent_replay_and_conflict_are_separate() -> Result<(), KernelError> {
        let authority = KernelAuthority::new(
            crate::authority::KernelAuthorityKey::from_bytes([3u8; 32]),
            AuthorityEpoch::genesis(),
        );
        let front_door = FrontDoor::new(authority.clone(), 2, 8)?;
        let route = RouteScope::new("daemon")?;
        let receipt = receipt(&authority)?;

        let first = front_door.authorize(&receipt, &route, 500, "k-1", "d-1")?;
        let replay = front_door.authorize(&receipt, &route, 500, "k-1", "d-1")?;
        assert_eq!(first, replay);

        assert!(matches!(
            front_door.authorize(&receipt, &route, 500, "k-1", "d-2"),
            Err(KernelError::IdempotencyConflict)
        ));
        Ok(())
    }

    #[test]
    fn control_reserve_exhaustion_fails_closed() -> Result<(), KernelError> {
        let authority = KernelAuthority::new(
            crate::authority::KernelAuthorityKey::from_bytes([3u8; 32]),
            AuthorityEpoch::genesis(),
        );
        let front_door = FrontDoor::new(authority.clone(), 1, 8)?;
        let route = RouteScope::new("daemon")?;
        let receipt = receipt(&authority)?;

        let held = front_door.acquire_control()?;
        assert!(matches!(
            front_door.authorize(&receipt, &route, 500, "k-1", "d-1"),
            Err(KernelError::ControlReserveExhausted)
        ));
        drop(held);
        assert!(
            front_door
                .authorize(&receipt, &route, 500, "k-1", "d-1")?
                .is_granted()
        );
        Ok(())
    }

    #[test]
    fn ledger_evicts_oldest_when_full() -> Result<(), KernelError> {
        let mut ledger = IdempotencyLedger::new(2)?;
        ledger.record(
            "a",
            "d",
            AuthorityDecision::Denied {
                reason: DecisionDenialReason::Expired,
            },
        )?;
        ledger.record(
            "b",
            "d",
            AuthorityDecision::Denied {
                reason: DecisionDenialReason::Expired,
            },
        )?;
        ledger.record(
            "c",
            "d",
            AuthorityDecision::Denied {
                reason: DecisionDenialReason::Expired,
            },
        )?;
        assert_eq!(ledger.resolve("a", "d"), IdempotencyDisposition::New);
        assert_eq!(
            ledger.resolve("c", "d"),
            IdempotencyDisposition::Replay(AuthorityDecision::Denied {
                reason: DecisionDenialReason::Expired,
            })
        );
        Ok(())
    }
}
