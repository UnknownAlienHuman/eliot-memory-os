//! Broker-local implementation-deviation registration ledger.
//!
//! Architecture anchors: I6.9 Recoverable implementation deviation and A0.6
//! Changing the Architecture (a Recoverable Deviation is temporary, scoped,
//! crosses no Hard Boundary, and carries an owner, reason, scope, review
//! condition, rollback, and outcome; permanent exceptions without an owner or
//! review are prohibited). Under ARCH-INTENT-01 every deviation the broker
//! operates under must be explicit, scoped, within already granted authority,
//! and assigned an owner, review, and outcome.
//!
//! The canonical deviation record stays Governor-owned
//! (`eliot_problem::ImplementationDeviation`): owner, evidence,
//! hard-boundary checks, benefit, risk, and rollback live there, and only
//! there. This ledger is the broker's local enforcement view: which deviation
//! ids this broker operates under, the review condition that keeps each one
//! alive, and whether it is still active or already expired. It owns no
//! canonical content and no durable canonical state; rows are process-memory
//! only and are rebuilt at composition from the registered records.
//!
//! Lifecycle rule enforced here:
//!
//! * a deviation is registered with its review condition before the broker
//!   may treat it as active (`register`, then `require_active`);
//! * when the review condition triggers, the row becomes expired with an
//!   explicit outcome reference (`expire_due_to_review`); it never silently
//!   remains active;
//! * re-registering an id never shadows the existing row, and terminal rows
//!   never leave `expired`.
//!
//! Stitch points for the remaining #1798 slices: the broker-deviation slice
//! calls `register` for the recorded deviation and `require_active` on every
//! path that relies on it; the operational-status slice enumerates rows with
//! `entries`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use thiserror::Error;

/// Typed refusal taxonomy for the broker's deviation registration ledger.
///
/// A refusal keeps its exact cause so an unregistered deviation is never
/// confused with an expired one: the first was never admitted here, the
/// second lapsed under its own review condition.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum DeviationRegistryError {
    /// The presented deviation id is empty, so there is nothing to register,
    /// admit, or expire.
    #[error("deviation id is not a non-empty value")]
    EmptyDeviationId,
    /// The presented review condition is empty. A deviation without a review
    /// condition would be a permanent exception, which A0.6 prohibits.
    #[error("deviation review condition is not a non-empty value")]
    EmptyReviewCondition,
    /// The presented outcome reference is empty. Leaving `active` requires
    /// recording why, so an empty outcome is refused.
    #[error("deviation outcome reference is not a non-empty value")]
    EmptyOutcomeRef,
    /// The deviation id is already registered. Registration is explicit and
    /// append-only per id; a second registration never shadows the first.
    #[error("deviation is already registered")]
    AlreadyRegistered,
    /// The deviation id is not registered in this ledger, so it cannot be
    /// treated as active and cannot be expired.
    #[error("deviation is not registered")]
    NotRegistered,
    /// The deviation id is registered but its review condition already moved
    /// it out of `active`. It is not treated as active again.
    #[error("deviation is no longer active")]
    NoLongerActive,
    /// The deviation row already left `active`. Terminal rows are retained
    /// for review and never transition again.
    #[error("deviation already left active")]
    AlreadyTerminal,
}

/// Broker-local lifecycle disposition of one registered deviation.
///
/// This mirrors only the broker-visible dispositions of the canonical
/// lifecycle: `active` (the broker may operate under it) and `expired` (its
/// review condition triggered). Promotion and rejection of the canonical
/// record stay Governor-owned and are observed here as expiry with the
/// recorded outcome, never as a silent return to `active`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviationRegistrationState {
    /// Registered with a live review condition; the broker may operate under it.
    Active,
    /// Its review condition triggered; the broker no longer operates under it.
    Expired,
}

/// One deviation id the broker operates under, with the review condition that
/// keeps it alive.
///
/// Fields stay private so the only way out of `active` is
/// [`ImplementationDeviationRegistry::expire_due_to_review`], which records
/// the outcome reference together with the transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviationRegistration {
    deviation_id: String,
    review_condition: String,
    state: DeviationRegistrationState,
    outcome_ref: Option<String>,
}

impl DeviationRegistration {
    /// Returns the canonical deviation id this row tracks.
    #[must_use]
    pub fn deviation_id(&self) -> &str {
        &self.deviation_id
    }

    /// Returns the review condition that keeps this row alive.
    #[must_use]
    pub fn review_condition(&self) -> &str {
        &self.review_condition
    }

    /// Returns the broker-local lifecycle disposition of this row.
    #[must_use]
    pub fn state(&self) -> DeviationRegistrationState {
        self.state
    }

    /// Returns the outcome reference recorded when the row left `active`, if any.
    #[must_use]
    pub fn outcome_ref(&self) -> Option<&str> {
        self.outcome_ref.as_deref()
    }
}

/// Broker-local lifecycle store and registration path for recoverable
/// implementation deviations.
///
/// The store is keyed by canonical deviation id and holds one row per id.
/// Rows are process-memory only: a broker restart rebuilds them from the
/// registered canonical records before any deviation-gated path runs.
#[derive(Clone, Debug, Default)]
pub struct ImplementationDeviationRegistry {
    rows: BTreeMap<String, DeviationRegistration>,
}

impl ImplementationDeviationRegistry {
    /// Creates an empty registration ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rows: BTreeMap::new(),
        }
    }

    /// Registers one deviation id with its review condition as active.
    ///
    /// Registration validates the presented originals: the id and the review
    /// condition must both be non-empty, and the id must not already be
    /// registered. A deviation that is not registered here can never be
    /// treated as active through [`Self::require_active`].
    pub fn register(
        &mut self,
        deviation_id: &str,
        review_condition: &str,
    ) -> Result<(), DeviationRegistryError> {
        if deviation_id.trim().is_empty() {
            return Err(DeviationRegistryError::EmptyDeviationId);
        }
        if review_condition.trim().is_empty() {
            return Err(DeviationRegistryError::EmptyReviewCondition);
        }
        if self.rows.contains_key(deviation_id) {
            return Err(DeviationRegistryError::AlreadyRegistered);
        }
        self.rows.insert(
            deviation_id.to_owned(),
            DeviationRegistration {
                deviation_id: deviation_id.to_owned(),
                review_condition: review_condition.to_owned(),
                state: DeviationRegistrationState::Active,
                outcome_ref: None,
            },
        );
        Ok(())
    }

    /// Admits the named deviation as one the broker may operate under.
    ///
    /// Only a registered, still-active id passes. An unknown id fails because
    /// future recoverable deviations must be registered before they are
    /// treated as active; an expired id fails because a triggered review
    /// condition never silently remains active.
    pub fn require_active(&self, deviation_id: &str) -> Result<(), DeviationRegistryError> {
        let row = self
            .rows
            .get(deviation_id)
            .ok_or(DeviationRegistryError::NotRegistered)?;
        if row.state != DeviationRegistrationState::Active {
            return Err(DeviationRegistryError::NoLongerActive);
        }
        Ok(())
    }

    /// Expires one active row when its review condition triggers.
    ///
    /// The departure reason is recorded in `outcome_ref`; the id, review
    /// condition, and terminal disposition are retained so a later reviewer
    /// can still read why the assumption lapsed. Only an active row expires;
    /// unknown ids and already-terminal rows are refused with a typed error.
    pub fn expire_due_to_review(
        &mut self,
        deviation_id: &str,
        outcome_ref: &str,
    ) -> Result<(), DeviationRegistryError> {
        if outcome_ref.trim().is_empty() {
            return Err(DeviationRegistryError::EmptyOutcomeRef);
        }
        let row = self
            .rows
            .get_mut(deviation_id)
            .ok_or(DeviationRegistryError::NotRegistered)?;
        if row.state != DeviationRegistrationState::Active {
            return Err(DeviationRegistryError::AlreadyTerminal);
        }
        row.state = DeviationRegistrationState::Expired;
        row.outcome_ref = Some(outcome_ref.to_owned());
        Ok(())
    }

    /// Returns the row for one deviation id, if it is registered.
    #[must_use]
    pub fn get(&self, deviation_id: &str) -> Option<&DeviationRegistration> {
        self.rows.get(deviation_id)
    }

    /// Enumerates every registered row in deviation-id order.
    ///
    /// This is the read path the operational-status slice projects
    /// active/expired deviations from; it never derives disposition from
    /// prose, code history, or the absence of a promotion.
    pub fn entries(&self) -> impl Iterator<Item = &DeviationRegistration> {
        self.rows.values()
    }
}
