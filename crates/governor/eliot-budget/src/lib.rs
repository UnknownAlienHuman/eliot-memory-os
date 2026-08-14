//! Pure G-17 budget, quota, and admission-reservation contracts.
//!
//! This crate owns no provider, clock, persistence, process, scheduler, or
//! automation authority. Callers supply immutable observations and the exact
//! canonical authority, operation, admission, and activation bindings.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_authority::AuthorityError;
use eliot_config::Applicability;
use eliot_evaluation_contracts::TrialStatus;
use eliot_receipts::{
    AuthorityBinding, OperationBinding, ReceiptDispositionKind, ReceiptEnvelope, ReceiptError,
    ReceiptIdentity, ReceiptKind,
};

/// An observed amount with absence and epistemic state kept distinct from zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservedAmount {
    /// The provider or tool reported the exact amount, including an exact zero.
    Known(u64),
    /// A non-authoritative estimate; never accepted as measured consumption.
    Estimated(u64),
    /// The source did not establish the value.
    Unknown,
    /// The source explicitly does not expose the value.
    NotExposed,
    /// This dimension does not apply to the observed operation.
    NotApplicable,
}

impl ObservedAmount {
    fn measured(self, field: &'static str) -> Result<Option<u64>, BudgetError> {
        match self {
            Self::Known(value) => Ok(Some(value)),
            Self::NotApplicable => Ok(None),
            Self::Estimated(_) | Self::Unknown | Self::NotExposed => {
                Err(BudgetError::UsageUnavailable(field))
            }
        }
    }
}

/// A quota observation, preserving unavailable state rather than treating it as zero.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuotaState {
    /// A measured remaining amount is available.
    Known { remaining: u64 },
    /// The source did not provide a value.
    Unknown,
    /// The source explicitly does not expose this quota.
    NotExposed,
    /// The observation is outside its declared freshness window.
    Stale,
    /// The source measured exhaustion.
    Exhausted,
}

/// One simultaneous quota window, such as credits, requests, or concurrency.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaWindow {
    pub window_id: String,
    pub state: QuotaState,
    /// Opaque identity of the provider/tool meter that produced this value.
    pub source_ref: String,
    /// Opaque confidence classification supplied by the observation owner.
    pub confidence_ref: String,
    /// Wall-clock observation time in Unix milliseconds; never causal order.
    pub observed_at_unix_ms: i64,
    /// Provider-declared reset time when the window has one.
    pub reset_at_unix_ms: Option<i64>,
}

/// Exact provider/tool route attribution for a reservation and its observations.
///
/// G-17 does not own route selection. A different attribution therefore needs a
/// newly admitted envelope rather than being accepted as an implicit fallback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderToolAttribution {
    pub provider_ref: String,
    pub tool_ref: String,
}

impl ProviderToolAttribution {
    fn validate(&self) -> Result<(), BudgetError> {
        text(&self.provider_ref, "provider_ref")?;
        text(&self.tool_ref, "tool_ref")
    }
}

/// Locator-only binding derived from an immutable C0-02 receipt envelope.
///
/// The locator preserves the receipt fields needed for exact comparison. It
/// does not prove durable canonical admission, provider authenticity, or an
/// active authority grant. Those claims remain with the owning service.
///
/// `PLAN_GAP`: the accepted G-17 bundle names receipt and authority references
/// but does not yet name a dedicated typed budget/cost grant contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptLocator {
    identity: ReceiptIdentity,
    receipt_kind: ReceiptKind,
    operation: OperationBinding,
    authority: AuthorityBinding,
    provider_tool: ProviderToolAttribution,
    disposition: ReceiptDispositionKind,
}

impl ReceiptLocator {
    /// Validates a receipt envelope and retains a locator-only comparison
    /// binding. `provider_tool` is caller-supplied attribution, not a grant.
    pub fn from_receipt(
        receipt: &ReceiptEnvelope,
        provider_tool: ProviderToolAttribution,
    ) -> Result<Self, BudgetError> {
        receipt.validate()?;
        provider_tool.validate()?;
        Ok(Self {
            identity: receipt.identity.clone(),
            receipt_kind: receipt.core.kind,
            operation: receipt.core.operation.clone(),
            authority: receipt.core.authority.clone(),
            provider_tool,
            disposition: receipt.core.disposition.kind(),
        })
    }

    /// Returns the immutable receipt identity.
    #[must_use]
    pub const fn identity(&self) -> &ReceiptIdentity {
        &self.identity
    }

    /// Returns the observed receipt disposition.
    #[must_use]
    pub const fn disposition(&self) -> ReceiptDispositionKind {
        self.disposition
    }

    /// Returns the receipt class preserved by this locator.
    #[must_use]
    pub const fn receipt_kind(&self) -> ReceiptKind {
        self.receipt_kind
    }

    /// Returns the exact operation preserved by this locator.
    #[must_use]
    pub const fn operation(&self) -> &OperationBinding {
        &self.operation
    }

    /// Returns the caller-supplied provider/tool attribution bound to this locator.
    #[must_use]
    pub const fn provider_tool(&self) -> &ProviderToolAttribution {
        &self.provider_tool
    }

    fn validate_for(
        &self,
        authority: &AuthorityBinding,
        provider_tool: &ProviderToolAttribution,
        expected_kind: ReceiptKind,
    ) -> Result<(), BudgetError> {
        if self.authority.state_fence != authority.state_fence {
            return Err(BudgetError::FenceMismatch);
        }
        if self.authority.authority_epoch != authority.authority_epoch {
            return Err(BudgetError::EpochMismatch);
        }
        if &self.authority != authority
            || &self.provider_tool != provider_tool
            || self.receipt_kind != expected_kind
        {
            return Err(BudgetError::ReceiptReferenceConflict);
        }
        Ok(())
    }

    fn validate_observation_for(
        &self,
        authority: &AuthorityBinding,
        provider_tool: &ProviderToolAttribution,
        operation: &OperationBinding,
    ) -> Result<(), BudgetError> {
        self.validate_for(authority, provider_tool, ReceiptKind::Operation)?;
        if &self.operation != operation {
            return Err(BudgetError::ReceiptReferenceConflict);
        }
        Ok(())
    }
}

/// The immutable limits and authority references for one budget scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BudgetEnvelope {
    pub envelope_id: String,
    pub policy_snapshot_id: String,
    pub applicability: Applicability,
    /// Locator-only reference to the Human-governed automation policy; it does
    /// not itself grant automation authority.
    pub automation_policy_ref: String,
    /// Locator-only reference to the System Owner/Requester cost authority; it
    /// does not itself prove an active cost grant.
    pub cost_authority_ref: String,
    /// The only exact route authorized by this immutable envelope.
    pub provider_tool: ProviderToolAttribution,
    pub max_cost_micros: Option<u64>,
    pub quota_windows: Vec<QuotaWindow>,
}

impl BudgetEnvelope {
    /// Validates the structural envelope without inventing missing measurements.
    pub fn validate(&self) -> Result<(), BudgetError> {
        text(&self.envelope_id, "envelope_id")?;
        text(&self.policy_snapshot_id, "policy_snapshot_id")?;
        text(&self.automation_policy_ref, "automation_policy_ref")?;
        text(&self.cost_authority_ref, "cost_authority_ref")?;
        self.provider_tool.validate()?;
        if self.applicability != Applicability::Applicable {
            return Err(BudgetError::PolicyNotApplicable);
        }
        if self.quota_windows.is_empty() {
            return Err(BudgetError::InvalidField("quota_windows"));
        }
        let mut ids = BTreeSet::new();
        for window in &self.quota_windows {
            text(&window.window_id, "quota.window_id")?;
            text(&window.source_ref, "quota.source_ref")?;
            text(&window.confidence_ref, "quota.confidence_ref")?;
            if window
                .reset_at_unix_ms
                .is_some_and(|reset| reset < window.observed_at_unix_ms)
            {
                return Err(BudgetError::InvalidQuotaWindowTime(
                    window.window_id.clone(),
                ));
            }
            if !ids.insert(&window.window_id) {
                return Err(BudgetError::DuplicateWindow(window.window_id.clone()));
            }
        }
        Ok(())
    }
}

/// Provider/tool-measured usage bound to one canonical operation and receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeasuredUsage {
    pub provider_tool: ProviderToolAttribution,
    pub operation: OperationBinding,
    pub provider_receipt_ref: ReceiptLocator,
    pub cost_micros: ObservedAmount,
    pub quota_units: ObservedAmount,
    pub status: TrialStatus,
}

/// A provider/tool-observed refund. A raw amount without this provenance cannot
/// change the ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefundObservation {
    pub observation_id: String,
    pub provider_tool: ProviderToolAttribution,
    pub operation: OperationBinding,
    pub provider_receipt_ref: ReceiptLocator,
    pub cost_micros: ObservedAmount,
    pub status: TrialStatus,
}

/// Reservation lifecycle. Unknown external outcomes are never terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationState {
    StagedInactive,
    Active,
    Reconciling,
    Released,
    Expired,
}

impl ReservationState {
    const fn holds_capacity(self) -> bool {
        matches!(
            self,
            Self::StagedInactive | Self::Active | Self::Reconciling
        )
    }
}

/// Post-transition capacity disposition after measured usage replaces the
/// current reservation while every other held reservation remains accounted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExhaustionDisposition {
    WithinEnvelope,
    CostExceeded,
    QuotaExceeded { window_ids: Vec<String> },
    CostAndQuotaExceeded { window_ids: Vec<String> },
}

/// Request to reserve budget for one exact canonical operation and route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationRequest {
    pub envelope_id: String,
    pub operation: OperationBinding,
    pub authority: AuthorityBinding,
    pub provider_tool: ProviderToolAttribution,
    pub estimated_cost_micros: Option<u64>,
    pub estimated_quota_units: Option<u64>,
}

/// Immutable view returned by every reservation transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationReceipt {
    pub reservation_id: String,
    pub envelope_id: String,
    pub idempotency_key: String,
    pub operation: OperationBinding,
    pub authority: AuthorityBinding,
    pub provider_tool: ProviderToolAttribution,
    pub state: ReservationState,
    pub disposition: ReceiptDispositionKind,
    pub exhaustion_disposition: ExhaustionDisposition,
    pub canonical_admission_receipt_ref: Option<ReceiptLocator>,
    pub activation_receipt_ref: Option<ReceiptLocator>,
    pub committed_usage: Option<MeasuredUsage>,
    pub refund_observations: Vec<RefundObservation>,
    pub estimated_cost_micros: Option<u64>,
    pub estimated_quota_units: Option<u64>,
}

impl ReservationReceipt {
    /// Returns the observed refunded cost, or `None` when no refund was observed.
    pub fn refunded_cost_micros(&self) -> Result<Option<u64>, BudgetError> {
        let mut total: Option<u64> = None;
        for observation in &self.refund_observations {
            let amount = observation
                .cost_micros
                .measured("refund.cost_micros")?
                .ok_or(BudgetError::UsageUnavailable("refund.cost_micros"))?;
            total = Some(match total {
                Some(existing) => existing
                    .checked_add(amount)
                    .ok_or(BudgetError::PoisonedState)?,
                None => amount,
            });
        }
        Ok(total)
    }
}

/// Fail-closed budget-core failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BudgetError {
    InvalidField(&'static str),
    InvalidQuotaWindowTime(String),
    DuplicateWindow(String),
    UnknownReservation(String),
    UnknownEnvelope(String),
    PolicyNotApplicable,
    MissingEstimate(&'static str),
    QuotaUnavailable(String),
    QuotaExhausted(String),
    CostExceeded,
    UnauthorizedFallback,
    InvalidLifecycleTransition,
    FenceMismatch,
    EpochMismatch,
    Authority(AuthorityError),
    Receipt(ReceiptError),
    IdempotencyConflict,
    UnknownOutcomeRequiresReconciliation,
    UsageUnavailable(&'static str),
    OutcomeNotTerminal,
    RefundExceedsCommitted,
    ReceiptReferenceConflict,
    PoisonedState,
}

impl From<AuthorityError> for BudgetError {
    fn from(error: AuthorityError) -> Self {
        Self::Authority(error)
    }
}

impl From<ReceiptError> for BudgetError {
    fn from(error: ReceiptError) -> Self {
        Self::Receipt(error)
    }
}

/// Pure mutable owner of reservations and measured budget state.
#[derive(Clone, Debug)]
pub struct BudgetLedger {
    envelope: BudgetEnvelope,
    authority: AuthorityBinding,
    reservations: BTreeMap<String, ReservationReceipt>,
    next_reservation: u64,
    reserved_cost_micros: u64,
    reserved_quota_units: u64,
    committed_cost_micros: u64,
    committed_quota_units: u64,
}

impl BudgetLedger {
    /// Creates a ledger bound to one immutable envelope and authority snapshot.
    pub fn new(envelope: BudgetEnvelope, authority: AuthorityBinding) -> Result<Self, BudgetError> {
        envelope.validate()?;
        authority
            .state_fence
            .validate()
            .map_err(|_| BudgetError::FenceMismatch)?;
        if authority.authority_epoch != authority.state_fence.authority_epoch {
            return Err(BudgetError::EpochMismatch);
        }
        Ok(Self {
            envelope,
            authority,
            reservations: BTreeMap::new(),
            next_reservation: 1,
            reserved_cost_micros: 0,
            reserved_quota_units: 0,
            committed_cost_micros: 0,
            committed_quota_units: 0,
        })
    }

    /// Returns the current checked capacity disposition across committed usage
    /// and every reservation that still holds capacity.
    pub fn exhaustion_disposition(&self) -> Result<ExhaustionDisposition, BudgetError> {
        self.classify_exhaustion(
            self.committed_cost_micros,
            self.reserved_cost_micros,
            self.committed_quota_units,
            self.reserved_quota_units,
        )
    }

    /// Stages an inactive reservation, or returns the exact prior receipt on an
    /// exact idempotent retry.
    pub fn reserve(
        &mut self,
        request: ReservationRequest,
    ) -> Result<ReservationReceipt, BudgetError> {
        self.validate_request(&request)?;
        if let Some(existing) = self.reservations.get(&request.operation.idempotency_key) {
            if same_request(existing, &request) {
                return Ok(existing.clone());
            }
            return Err(BudgetError::IdempotencyConflict);
        }
        self.check_capacity(request.estimated_cost_micros, request.estimated_quota_units)?;
        let receipt = ReservationReceipt {
            reservation_id: format!("{}-{}", self.envelope.envelope_id, self.next_reservation),
            envelope_id: request.envelope_id,
            idempotency_key: request.operation.idempotency_key.clone(),
            operation: request.operation,
            authority: request.authority,
            provider_tool: request.provider_tool,
            state: ReservationState::StagedInactive,
            disposition: ReceiptDispositionKind::Unknown,
            exhaustion_disposition: ExhaustionDisposition::WithinEnvelope,
            canonical_admission_receipt_ref: None,
            activation_receipt_ref: None,
            committed_usage: None,
            refund_observations: Vec::new(),
            estimated_cost_micros: request.estimated_cost_micros,
            estimated_quota_units: request.estimated_quota_units,
        };
        let next_reservation = self
            .next_reservation
            .checked_add(1)
            .ok_or(BudgetError::PoisonedState)?;
        let reserved_cost_micros =
            add_optional(self.reserved_cost_micros, receipt.estimated_cost_micros)?;
        let reserved_quota_units =
            add_optional(self.reserved_quota_units, receipt.estimated_quota_units)?;
        self.next_reservation = next_reservation;
        self.reserved_cost_micros = reserved_cost_micros;
        self.reserved_quota_units = reserved_quota_units;
        self.reservations
            .insert(receipt.idempotency_key.clone(), receipt.clone());
        Ok(receipt)
    }

    /// Activates a staged or reconciling reservation under exact admission and
    /// activation receipt locators. Their canonical persistence is validated by
    /// the owning service before this pure state transition.
    pub fn activate(
        &mut self,
        key: &str,
        authority: &AuthorityBinding,
        canonical_admission_receipt_ref: ReceiptLocator,
        activation_receipt_ref: ReceiptLocator,
    ) -> Result<ReservationReceipt, BudgetError> {
        if canonical_admission_receipt_ref == activation_receipt_ref {
            return Err(BudgetError::ReceiptReferenceConflict);
        }
        canonical_admission_receipt_ref.validate_for(
            authority,
            &self.envelope.provider_tool,
            ReceiptKind::Operation,
        )?;
        activation_receipt_ref.validate_for(
            authority,
            &self.envelope.provider_tool,
            ReceiptKind::Operation,
        )?;
        if canonical_admission_receipt_ref.disposition != ReceiptDispositionKind::Success
            || activation_receipt_ref.disposition != ReceiptDispositionKind::Success
        {
            return Err(BudgetError::ReceiptReferenceConflict);
        }
        self.transition(key, authority, |receipt| match receipt.state {
            ReservationState::StagedInactive | ReservationState::Reconciling => {
                if receipt
                    .canonical_admission_receipt_ref
                    .as_ref()
                    .is_some_and(|value| value != &canonical_admission_receipt_ref)
                    || receipt
                        .activation_receipt_ref
                        .as_ref()
                        .is_some_and(|value| value != &activation_receipt_ref)
                {
                    return Err(BudgetError::IdempotencyConflict);
                }
                receipt.canonical_admission_receipt_ref = Some(canonical_admission_receipt_ref);
                receipt.activation_receipt_ref = Some(activation_receipt_ref);
                receipt.state = ReservationState::Active;
                Ok(())
            }
            ReservationState::Active
                if receipt.canonical_admission_receipt_ref.as_ref()
                    == Some(&canonical_admission_receipt_ref)
                    && receipt.activation_receipt_ref.as_ref() == Some(&activation_receipt_ref) =>
            {
                Ok(())
            }
            ReservationState::Active => Err(BudgetError::IdempotencyConflict),
            ReservationState::Released | ReservationState::Expired => {
                Err(BudgetError::InvalidLifecycleTransition)
            }
        })
    }

    /// Commits terminal provider/tool usage and releases an active reservation.
    pub fn commit(
        &mut self,
        key: &str,
        authority: &AuthorityBinding,
        usage: &MeasuredUsage,
    ) -> Result<ReservationReceipt, BudgetError> {
        self.validate_usage(key, usage)?;
        if let Some(existing) = self.reservations.get(key)
            && existing.state == ReservationState::Released
        {
            validate_transition_authority(&self.authority, authority, existing)?;
            return if existing.committed_usage.as_ref() == Some(usage) {
                Ok(existing.clone())
            } else {
                Err(BudgetError::IdempotencyConflict)
            };
        }
        let disposition = disposition_for_status(usage.status)?;
        self.transition(key, authority, |receipt| match receipt.state {
            ReservationState::Active => {
                receipt.state = ReservationState::Released;
                receipt.disposition = disposition;
                receipt.committed_usage = Some(usage.clone());
                Ok(())
            }
            ReservationState::Released if receipt.committed_usage.as_ref() == Some(usage) => Ok(()),
            ReservationState::Released => Err(BudgetError::IdempotencyConflict),
            _ => Err(BudgetError::InvalidLifecycleTransition),
        })
    }

    /// Moves staged or active work into non-effecting reconciliation.
    pub fn begin_reconciliation(
        &mut self,
        key: &str,
        authority: &AuthorityBinding,
    ) -> Result<ReservationReceipt, BudgetError> {
        self.transition(key, authority, |receipt| match receipt.state {
            ReservationState::StagedInactive | ReservationState::Active => {
                receipt.state = ReservationState::Reconciling;
                receipt.disposition = ReceiptDispositionKind::Unknown;
                Ok(())
            }
            ReservationState::Reconciling => Ok(()),
            ReservationState::Released | ReservationState::Expired => {
                Err(BudgetError::InvalidLifecycleTransition)
            }
        })
    }

    /// Resolves reconciliation to a terminal measured provider/tool outcome.
    pub fn reconcile_usage(
        &mut self,
        key: &str,
        authority: &AuthorityBinding,
        usage: &MeasuredUsage,
    ) -> Result<ReservationReceipt, BudgetError> {
        self.validate_usage(key, usage)?;
        if let Some(existing) = self.reservations.get(key)
            && existing.state == ReservationState::Released
        {
            validate_transition_authority(&self.authority, authority, existing)?;
            return if existing.committed_usage.as_ref() == Some(usage) {
                Ok(existing.clone())
            } else {
                Err(BudgetError::IdempotencyConflict)
            };
        }
        let disposition = disposition_for_status(usage.status)?;
        self.transition(key, authority, |receipt| match receipt.state {
            ReservationState::Reconciling => {
                receipt.state = ReservationState::Released;
                receipt.disposition = disposition;
                receipt.committed_usage = Some(usage.clone());
                Ok(())
            }
            ReservationState::Released if receipt.committed_usage.as_ref() == Some(usage) => Ok(()),
            ReservationState::Released => Err(BudgetError::IdempotencyConflict),
            _ => Err(BudgetError::UnknownOutcomeRequiresReconciliation),
        })
    }

    /// Releases staged, active, or reconciling capacity only when the caller
    /// asserts that no provider execution occurred.
    pub fn release_without_execution(
        &mut self,
        key: &str,
        authority: &AuthorityBinding,
    ) -> Result<ReservationReceipt, BudgetError> {
        self.transition(key, authority, |receipt| match receipt.state {
            ReservationState::StagedInactive
            | ReservationState::Active
            | ReservationState::Reconciling => {
                receipt.state = ReservationState::Released;
                receipt.disposition = ReceiptDispositionKind::Cancelled;
                Ok(())
            }
            ReservationState::Released
                if receipt.committed_usage.is_none()
                    && receipt.disposition == ReceiptDispositionKind::Cancelled =>
            {
                Ok(())
            }
            ReservationState::Released | ReservationState::Expired => {
                Err(BudgetError::InvalidLifecycleTransition)
            }
        })
    }

    /// Expires only staged or reconciling capacity. Active attempt cleanup must
    /// first reconcile or release; it can never silently expire.
    pub fn expire(
        &mut self,
        key: &str,
        authority: &AuthorityBinding,
    ) -> Result<ReservationReceipt, BudgetError> {
        self.transition(key, authority, |receipt| match receipt.state {
            ReservationState::StagedInactive | ReservationState::Reconciling => {
                receipt.state = ReservationState::Expired;
                receipt.disposition = ReceiptDispositionKind::Cancelled;
                Ok(())
            }
            ReservationState::Expired => Ok(()),
            ReservationState::Active | ReservationState::Released => {
                Err(BudgetError::InvalidLifecycleTransition)
            }
        })
    }

    /// Applies an exact measured provider/tool refund observation idempotently.
    pub fn apply_refund(
        &mut self,
        key: &str,
        authority: &AuthorityBinding,
        observation: &RefundObservation,
    ) -> Result<ReservationReceipt, BudgetError> {
        self.validate_refund(key, observation)?;
        self.transition(key, authority, |receipt| {
            if receipt.state != ReservationState::Released {
                return Err(BudgetError::InvalidLifecycleTransition);
            }
            if let Some(existing) = receipt
                .refund_observations
                .iter()
                .find(|item| item.observation_id == observation.observation_id)
            {
                return if existing == observation {
                    Ok(())
                } else {
                    Err(BudgetError::IdempotencyConflict)
                };
            }
            if receipt
                .refund_observations
                .iter()
                .any(|item| item.provider_receipt_ref == observation.provider_receipt_ref)
            {
                return Err(BudgetError::ReceiptReferenceConflict);
            }
            let committed = receipt
                .committed_usage
                .as_ref()
                .ok_or(BudgetError::UsageUnavailable("committed_usage"))?
                .cost_micros
                .measured("usage.cost_micros")?
                .ok_or(BudgetError::UsageUnavailable("usage.cost_micros"))?;
            let refund = observation
                .cost_micros
                .measured("refund.cost_micros")?
                .ok_or(BudgetError::UsageUnavailable("refund.cost_micros"))?;
            let total = match receipt.refunded_cost_micros()? {
                Some(already) => already
                    .checked_add(refund)
                    .ok_or(BudgetError::PoisonedState)?,
                None => refund,
            };
            if total > committed {
                return Err(BudgetError::RefundExceedsCommitted);
            }
            receipt.refund_observations.push(observation.clone());
            Ok(())
        })
    }

    fn validate_request(&self, request: &ReservationRequest) -> Result<(), BudgetError> {
        text(&request.envelope_id, "envelope_id")?;
        request.provider_tool.validate()?;
        if request.envelope_id != self.envelope.envelope_id {
            return Err(BudgetError::UnknownEnvelope(request.envelope_id.clone()));
        }
        if request.provider_tool != self.envelope.provider_tool {
            return Err(BudgetError::UnauthorizedFallback);
        }
        if request.authority != self.authority {
            return Err(BudgetError::FenceMismatch);
        }
        validate_operation_authority(&request.operation, &request.authority)?;
        text(&request.operation.idempotency_key, "idempotency_key")?;
        Ok(())
    }

    fn validate_usage(&self, key: &str, usage: &MeasuredUsage) -> Result<(), BudgetError> {
        usage.provider_tool.validate()?;
        let receipt = self
            .reservations
            .get(key)
            .ok_or_else(|| BudgetError::UnknownReservation(key.to_owned()))?;
        if usage.provider_tool != receipt.provider_tool {
            return Err(BudgetError::UnauthorizedFallback);
        }
        if usage.operation != receipt.operation {
            return Err(BudgetError::FenceMismatch);
        }
        usage.provider_receipt_ref.validate_observation_for(
            &receipt.authority,
            &usage.provider_tool,
            &usage.operation,
        )?;
        if usage.provider_receipt_ref.disposition != disposition_for_status(usage.status)? {
            return Err(BudgetError::ReceiptReferenceConflict);
        }
        let _ = usage.cost_micros.measured("usage.cost_micros")?;
        let _ = usage.quota_units.measured("usage.quota_units")?;
        Ok(())
    }

    fn validate_refund(
        &self,
        key: &str,
        observation: &RefundObservation,
    ) -> Result<(), BudgetError> {
        text(&observation.observation_id, "refund.observation_id")?;
        observation.provider_tool.validate()?;
        let receipt = self
            .reservations
            .get(key)
            .ok_or_else(|| BudgetError::UnknownReservation(key.to_owned()))?;
        if observation.provider_tool != receipt.provider_tool {
            return Err(BudgetError::UnauthorizedFallback);
        }
        if observation.operation != receipt.operation {
            return Err(BudgetError::FenceMismatch);
        }
        observation.provider_receipt_ref.validate_observation_for(
            &receipt.authority,
            &observation.provider_tool,
            &observation.operation,
        )?;
        if observation.status != TrialStatus::Succeeded {
            return Err(BudgetError::OutcomeNotTerminal);
        }
        if observation.provider_receipt_ref.disposition != ReceiptDispositionKind::Success {
            return Err(BudgetError::ReceiptReferenceConflict);
        }
        let _ = observation
            .cost_micros
            .measured("refund.cost_micros")?
            .ok_or(BudgetError::UsageUnavailable("refund.cost_micros"))?;
        Ok(())
    }

    fn check_capacity(&self, cost: Option<u64>, quota: Option<u64>) -> Result<(), BudgetError> {
        if self.envelope.max_cost_micros.is_some() && cost.is_none() {
            return Err(BudgetError::MissingEstimate("estimated_cost_micros"));
        }
        if quota.is_none() {
            return Err(BudgetError::MissingEstimate("estimated_quota_units"));
        }
        if let (Some(cost), Some(limit)) = (cost, self.envelope.max_cost_micros) {
            let total = self
                .committed_cost_micros
                .checked_add(self.reserved_cost_micros)
                .and_then(|value| value.checked_add(cost))
                .ok_or(BudgetError::PoisonedState)?;
            if total > limit {
                return Err(BudgetError::CostExceeded);
            }
        }
        let quota = quota.ok_or(BudgetError::MissingEstimate("estimated_quota_units"))?;
        for window in &self.envelope.quota_windows {
            match &window.state {
                QuotaState::Known { remaining } => {
                    let used = self
                        .committed_quota_units
                        .checked_add(self.reserved_quota_units)
                        .and_then(|value| value.checked_add(quota))
                        .ok_or(BudgetError::PoisonedState)?;
                    if used > *remaining {
                        return Err(BudgetError::QuotaExhausted(window.window_id.clone()));
                    }
                }
                QuotaState::Exhausted => {
                    return Err(BudgetError::QuotaExhausted(window.window_id.clone()));
                }
                QuotaState::Unknown | QuotaState::NotExposed | QuotaState::Stale => {
                    return Err(BudgetError::QuotaUnavailable(window.window_id.clone()));
                }
            }
        }
        Ok(())
    }

    fn transition<F>(
        &mut self,
        key: &str,
        authority: &AuthorityBinding,
        change: F,
    ) -> Result<ReservationReceipt, BudgetError>
    where
        F: FnOnce(&mut ReservationReceipt) -> Result<(), BudgetError>,
    {
        let before = self
            .reservations
            .get(key)
            .cloned()
            .ok_or_else(|| BudgetError::UnknownReservation(key.to_owned()))?;
        validate_transition_authority(&self.authority, authority, &before)?;
        let mut receipt = before.clone();
        change(&mut receipt)?;

        let mut reserved_cost_micros = self.reserved_cost_micros;
        let mut reserved_quota_units = self.reserved_quota_units;
        let mut committed_cost_micros = self.committed_cost_micros;
        let mut committed_quota_units = self.committed_quota_units;

        if before.state.holds_capacity() && !receipt.state.holds_capacity() {
            reserved_cost_micros =
                subtract_optional(reserved_cost_micros, before.estimated_cost_micros)?;
            reserved_quota_units =
                subtract_optional(reserved_quota_units, before.estimated_quota_units)?;
        }
        if before.committed_usage.is_none()
            && let Some(usage) = &receipt.committed_usage
        {
            committed_cost_micros = add_optional(
                committed_cost_micros,
                usage.cost_micros.measured("usage.cost_micros")?,
            )?;
            committed_quota_units = add_optional(
                committed_quota_units,
                usage.quota_units.measured("usage.quota_units")?,
            )?;
        }
        if receipt.refund_observations.len() > before.refund_observations.len() {
            let refund = receipt
                .refund_observations
                .last()
                .ok_or(BudgetError::PoisonedState)?
                .cost_micros
                .measured("refund.cost_micros")?
                .ok_or(BudgetError::UsageUnavailable("refund.cost_micros"))?;
            committed_cost_micros = committed_cost_micros
                .checked_sub(refund)
                .ok_or(BudgetError::PoisonedState)?;
        }

        receipt.exhaustion_disposition = self.classify_exhaustion(
            committed_cost_micros,
            reserved_cost_micros,
            committed_quota_units,
            reserved_quota_units,
        )?;

        self.reserved_cost_micros = reserved_cost_micros;
        self.reserved_quota_units = reserved_quota_units;
        self.committed_cost_micros = committed_cost_micros;
        self.committed_quota_units = committed_quota_units;
        self.reservations.insert(key.to_owned(), receipt.clone());
        Ok(receipt)
    }

    fn classify_exhaustion(
        &self,
        committed_cost_micros: u64,
        reserved_cost_micros: u64,
        committed_quota_units: u64,
        reserved_quota_units: u64,
    ) -> Result<ExhaustionDisposition, BudgetError> {
        let total_cost_micros = committed_cost_micros
            .checked_add(reserved_cost_micros)
            .ok_or(BudgetError::PoisonedState)?;
        let total_quota_units = committed_quota_units
            .checked_add(reserved_quota_units)
            .ok_or(BudgetError::PoisonedState)?;
        let cost_exceeded = self
            .envelope
            .max_cost_micros
            .is_some_and(|limit| total_cost_micros > limit);
        let mut window_ids = Vec::new();
        for window in &self.envelope.quota_windows {
            let exhausted = match &window.state {
                QuotaState::Known { remaining } => total_quota_units > *remaining,
                QuotaState::Exhausted => true,
                QuotaState::Unknown | QuotaState::NotExposed | QuotaState::Stale => false,
            };
            if exhausted {
                window_ids.push(window.window_id.clone());
            }
        }
        Ok(match (cost_exceeded, window_ids.is_empty()) {
            (false, true) => ExhaustionDisposition::WithinEnvelope,
            (true, true) => ExhaustionDisposition::CostExceeded,
            (false, false) => ExhaustionDisposition::QuotaExceeded { window_ids },
            (true, false) => ExhaustionDisposition::CostAndQuotaExceeded { window_ids },
        })
    }
}

fn same_request(receipt: &ReservationReceipt, request: &ReservationRequest) -> bool {
    receipt.envelope_id == request.envelope_id
        && receipt.operation == request.operation
        && receipt.authority == request.authority
        && receipt.provider_tool == request.provider_tool
        && receipt.estimated_cost_micros == request.estimated_cost_micros
        && receipt.estimated_quota_units == request.estimated_quota_units
}

fn validate_operation_authority(
    operation: &OperationBinding,
    authority: &AuthorityBinding,
) -> Result<(), BudgetError> {
    operation
        .state_fence
        .validate()
        .map_err(|_| BudgetError::FenceMismatch)?;
    authority
        .state_fence
        .validate()
        .map_err(|_| BudgetError::FenceMismatch)?;
    if operation.state_fence != authority.state_fence {
        return Err(BudgetError::FenceMismatch);
    }
    if operation.state_fence.authority_epoch != authority.authority_epoch {
        return Err(BudgetError::EpochMismatch);
    }
    Ok(())
}

fn validate_transition_authority(
    ledger_authority: &AuthorityBinding,
    authority: &AuthorityBinding,
    receipt: &ReservationReceipt,
) -> Result<(), BudgetError> {
    if authority != ledger_authority || &receipt.authority != authority {
        return Err(BudgetError::FenceMismatch);
    }
    validate_operation_authority(&receipt.operation, authority)
}

fn disposition_for_status(status: TrialStatus) -> Result<ReceiptDispositionKind, BudgetError> {
    match status {
        TrialStatus::Succeeded => Ok(ReceiptDispositionKind::Success),
        TrialStatus::Partial => Ok(ReceiptDispositionKind::Partial),
        TrialStatus::Failed
        | TrialStatus::Excluded
        | TrialStatus::Censored
        | TrialStatus::Contaminated => Ok(ReceiptDispositionKind::Failure),
        TrialStatus::Planned | TrialStatus::Running | TrialStatus::Unknown => {
            Err(BudgetError::OutcomeNotTerminal)
        }
    }
}

fn add_optional(total: u64, value: Option<u64>) -> Result<u64, BudgetError> {
    match value {
        Some(value) => total.checked_add(value).ok_or(BudgetError::PoisonedState),
        None => Ok(total),
    }
}

fn subtract_optional(total: u64, value: Option<u64>) -> Result<u64, BudgetError> {
    match value {
        Some(value) => total.checked_sub(value).ok_or(BudgetError::PoisonedState),
        None => Ok(total),
    }
}

fn text(value: &str, field: &'static str) -> Result<(), BudgetError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(BudgetError::InvalidField(field))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use eliot_contracts::{
        AuthorityEpoch, ContractId, OperationId, ReceiptId, RequestId, ResourceGeneration,
        StateFence,
    };
    use eliot_receipts::{EffectClass, ProofCeiling};

    fn authority() -> AuthorityBinding {
        authority_at(AuthorityEpoch::genesis())
    }

    fn authority_at(epoch: AuthorityEpoch) -> AuthorityBinding {
        AuthorityBinding {
            authority_id: ContractId::new("authority:test").expect("valid id"),
            authority_owner: "G-01".to_owned(),
            authority_epoch: epoch,
            state_fence: StateFence::new(epoch, ResourceGeneration::genesis()),
            allowed_effect: EffectClass::ExternalEffect,
            proof_ceiling: ProofCeiling::ObservedExternalEffect,
        }
    }

    fn operation(key: &str, authority: &AuthorityBinding) -> OperationBinding {
        OperationBinding {
            operation_id: OperationId::new(format!("operation:{key}")).expect("valid id"),
            request_id: RequestId::new(format!("request:{key}")).expect("valid id"),
            idempotency_key: key.to_owned(),
            operation_kind: "budget-reservation".to_owned(),
            effect: EffectClass::ExternalEffect,
            state_fence: authority.state_fence.clone(),
        }
    }

    fn route() -> ProviderToolAttribution {
        ProviderToolAttribution {
            provider_ref: "provider:primary".to_owned(),
            tool_ref: "tool:model".to_owned(),
        }
    }

    fn fallback_route() -> ProviderToolAttribution {
        ProviderToolAttribution {
            provider_ref: "provider:fallback".to_owned(),
            tool_ref: "tool:model".to_owned(),
        }
    }

    fn receipt_ref(name: &str, authority: &AuthorityBinding) -> ReceiptLocator {
        receipt_ref_with_disposition_and_operation(
            name,
            authority,
            ReceiptDispositionKind::Success,
            operation(name, authority),
        )
    }

    fn receipt_ref_with_disposition(
        name: &str,
        authority: &AuthorityBinding,
        disposition: ReceiptDispositionKind,
    ) -> ReceiptLocator {
        receipt_ref_with_disposition_and_operation(
            name,
            authority,
            disposition,
            operation(name, authority),
        )
    }

    fn receipt_ref_with_disposition_and_operation(
        name: &str,
        authority: &AuthorityBinding,
        disposition: ReceiptDispositionKind,
        operation: OperationBinding,
    ) -> ReceiptLocator {
        ReceiptLocator {
            identity: ReceiptIdentity {
                receipt_id: ReceiptId::new(format!("receipt:{name}")).expect("valid id"),
                canonical_sha256: format!("{:064x}", name.len()),
            },
            receipt_kind: ReceiptKind::Operation,
            operation,
            authority: authority.clone(),
            provider_tool: route(),
            disposition,
        }
    }

    fn envelope(max_cost_micros: Option<u64>, quota_state: QuotaState) -> BudgetEnvelope {
        BudgetEnvelope {
            envelope_id: "budget:test".to_owned(),
            policy_snapshot_id: "policy:test".to_owned(),
            applicability: Applicability::Applicable,
            automation_policy_ref: "automation-policy:test".to_owned(),
            cost_authority_ref: "cost-authority:test".to_owned(),
            provider_tool: route(),
            max_cost_micros,
            quota_windows: vec![QuotaWindow {
                window_id: "credits".to_owned(),
                state: quota_state,
                source_ref: "provider-meter:test".to_owned(),
                confidence_ref: "provider-reported".to_owned(),
                observed_at_unix_ms: 1_000,
                reset_at_unix_ms: Some(2_000),
            }],
        }
    }

    fn request(
        key: &str,
        authority: &AuthorityBinding,
        cost: Option<u64>,
        quota: Option<u64>,
    ) -> ReservationRequest {
        ReservationRequest {
            envelope_id: "budget:test".to_owned(),
            operation: operation(key, authority),
            authority: authority.clone(),
            provider_tool: route(),
            estimated_cost_micros: cost,
            estimated_quota_units: quota,
        }
    }

    fn usage(key: &str, authority: &AuthorityBinding, status: TrialStatus) -> MeasuredUsage {
        let disposition = match status {
            TrialStatus::Succeeded => ReceiptDispositionKind::Success,
            TrialStatus::Partial => ReceiptDispositionKind::Partial,
            TrialStatus::Failed
            | TrialStatus::Excluded
            | TrialStatus::Censored
            | TrialStatus::Contaminated => ReceiptDispositionKind::Failure,
            TrialStatus::Planned | TrialStatus::Running | TrialStatus::Unknown => {
                ReceiptDispositionKind::Unknown
            }
        };
        let operation = operation(key, authority);
        MeasuredUsage {
            provider_tool: route(),
            operation: operation.clone(),
            provider_receipt_ref: receipt_ref_with_disposition_and_operation(
                &format!("usage-{key}-{status:?}"),
                authority,
                disposition,
                operation,
            ),
            cost_micros: ObservedAmount::Known(3),
            quota_units: ObservedAmount::Known(1),
            status,
        }
    }

    fn stage_and_activate(ledger: &mut BudgetLedger, key: &str, authority: &AuthorityBinding) {
        ledger
            .reserve(request(key, authority, Some(5), Some(1)))
            .expect("reserved");
        ledger
            .activate(
                key,
                authority,
                receipt_ref(&format!("admission-{key}"), authority),
                receipt_ref(&format!("activation-{key}"), authority),
            )
            .expect("active");
    }

    #[test]
    fn missing_estimate_is_not_equal_to_measured_zero() {
        let auth = authority();
        let mut ledger = BudgetLedger::new(
            envelope(None, QuotaState::Known { remaining: 10 }),
            auth.clone(),
        )
        .expect("valid ledger");
        let first = ledger
            .reserve(request("same", &auth, None, Some(1)))
            .expect("absence is preserved when no cost ceiling applies");
        assert_eq!(first.estimated_cost_micros, None);
        assert_eq!(
            ledger.reserve(request("same", &auth, Some(0), Some(1))),
            Err(BudgetError::IdempotencyConflict)
        );

        let mut bounded = BudgetLedger::new(
            envelope(Some(10), QuotaState::Known { remaining: 10 }),
            auth.clone(),
        )
        .expect("valid ledger");
        assert_eq!(
            bounded.reserve(request("missing-cost", &auth, None, Some(1))),
            Err(BudgetError::MissingEstimate("estimated_cost_micros"))
        );
        assert_eq!(
            bounded.reserve(request("missing-quota", &auth, Some(1), None)),
            Err(BudgetError::MissingEstimate("estimated_quota_units"))
        );
        assert_ne!(ObservedAmount::Unknown, ObservedAmount::Known(0));
    }

    #[test]
    fn stale_unknown_and_unexposed_quota_fail_closed() {
        for state in [
            QuotaState::Unknown,
            QuotaState::NotExposed,
            QuotaState::Stale,
            QuotaState::Exhausted,
        ] {
            let auth = authority();
            let mut ledger =
                BudgetLedger::new(envelope(None, state), auth.clone()).expect("valid ledger");
            assert!(matches!(
                ledger.reserve(request("key", &auth, None, Some(1))),
                Err(BudgetError::QuotaUnavailable(_) | BudgetError::QuotaExhausted(_))
            ));
        }
    }

    #[test]
    fn unauthorized_provider_fallback_is_rejected_everywhere() {
        let auth = authority();
        let mut ledger = BudgetLedger::new(
            envelope(Some(10), QuotaState::Known { remaining: 10 }),
            auth.clone(),
        )
        .expect("valid ledger");
        let mut fallback = request("fallback", &auth, Some(2), Some(1));
        fallback.provider_tool = fallback_route();
        assert_eq!(
            ledger.reserve(fallback),
            Err(BudgetError::UnauthorizedFallback)
        );

        stage_and_activate(&mut ledger, "primary", &auth);
        let mut fallback_usage = usage("primary", &auth, TrialStatus::Succeeded);
        fallback_usage.provider_tool = fallback_route();
        assert_eq!(
            ledger.commit("primary", &auth, &fallback_usage),
            Err(BudgetError::UnauthorizedFallback)
        );
    }

    #[test]
    fn automation_cost_and_provider_tool_authority_are_required() {
        let mut value = envelope(Some(10), QuotaState::Known { remaining: 10 });
        value.automation_policy_ref.clear();
        assert_eq!(
            value.validate(),
            Err(BudgetError::InvalidField("automation_policy_ref"))
        );

        let mut value = envelope(Some(10), QuotaState::Known { remaining: 10 });
        value.cost_authority_ref.clear();
        assert_eq!(
            value.validate(),
            Err(BudgetError::InvalidField("cost_authority_ref"))
        );

        let mut value = envelope(Some(10), QuotaState::Known { remaining: 10 });
        value.provider_tool.provider_ref.clear();
        assert_eq!(
            value.validate(),
            Err(BudgetError::InvalidField("provider_ref"))
        );

        let mut value = envelope(Some(10), QuotaState::Known { remaining: 10 });
        value.applicability = Applicability::Unknown;
        assert_eq!(value.validate(), Err(BudgetError::PolicyNotApplicable));

        let mut value = envelope(Some(10), QuotaState::Known { remaining: 10 });
        value.quota_windows[0].source_ref.clear();
        assert_eq!(
            value.validate(),
            Err(BudgetError::InvalidField("quota.source_ref"))
        );

        let mut value = envelope(Some(10), QuotaState::Known { remaining: 10 });
        value.quota_windows[0].confidence_ref.clear();
        assert_eq!(
            value.validate(),
            Err(BudgetError::InvalidField("quota.confidence_ref"))
        );

        let mut value = envelope(Some(10), QuotaState::Known { remaining: 10 });
        value.quota_windows[0].reset_at_unix_ms = Some(999);
        assert_eq!(
            value.validate(),
            Err(BudgetError::InvalidQuotaWindowTime("credits".to_owned()))
        );
    }

    #[test]
    fn normative_reconciling_transitions_and_active_expiry_are_enforced() {
        let auth = authority();
        let mut ledger = BudgetLedger::new(
            envelope(Some(100), QuotaState::Known { remaining: 100 }),
            auth.clone(),
        )
        .expect("valid ledger");

        stage_and_activate(&mut ledger, "reactivate", &auth);
        ledger
            .begin_reconciliation("reactivate", &auth)
            .expect("reconciling");
        assert_eq!(
            ledger
                .activate(
                    "reactivate",
                    &auth,
                    receipt_ref("admission-reactivate", &auth),
                    receipt_ref("activation-reactivate", &auth),
                )
                .expect("re-activated with exact refs")
                .state,
            ReservationState::Active
        );
        assert_eq!(
            ledger.expire("reactivate", &auth),
            Err(BudgetError::InvalidLifecycleTransition)
        );

        ledger
            .reserve(request("release", &auth, Some(2), Some(1)))
            .expect("reserved");
        ledger
            .begin_reconciliation("release", &auth)
            .expect("reconciling");
        assert_eq!(
            ledger
                .release_without_execution("release", &auth)
                .expect("released")
                .state,
            ReservationState::Released
        );

        ledger
            .reserve(request("expire", &auth, Some(2), Some(1)))
            .expect("reserved");
        ledger
            .begin_reconciliation("expire", &auth)
            .expect("reconciling");
        assert_eq!(
            ledger.expire("expire", &auth).expect("expired").state,
            ReservationState::Expired
        );
    }

    #[test]
    fn measured_outcome_status_controls_receipt_disposition() {
        for (status, expected) in [
            (TrialStatus::Succeeded, ReceiptDispositionKind::Success),
            (TrialStatus::Partial, ReceiptDispositionKind::Partial),
            (TrialStatus::Failed, ReceiptDispositionKind::Failure),
        ] {
            let auth = authority();
            let key = format!("status-{status:?}");
            let mut ledger = BudgetLedger::new(
                envelope(Some(10), QuotaState::Known { remaining: 10 }),
                auth.clone(),
            )
            .expect("valid ledger");
            stage_and_activate(&mut ledger, &key, &auth);
            let observed = usage(&key, &auth, status);
            let terminal = ledger
                .commit(&key, &auth, &observed)
                .expect("terminal observation");
            assert_eq!(terminal.disposition, expected);
            assert_eq!(
                ledger
                    .commit(&key, &auth, &observed)
                    .expect("exact terminal retry"),
                terminal
            );
        }

        let auth = authority();
        let mut ledger = BudgetLedger::new(
            envelope(Some(10), QuotaState::Known { remaining: 10 }),
            auth.clone(),
        )
        .expect("valid ledger");
        stage_and_activate(&mut ledger, "unknown", &auth);
        ledger
            .begin_reconciliation("unknown", &auth)
            .expect("reconciling");
        assert_eq!(
            ledger.reconcile_usage(
                "unknown",
                &auth,
                &usage("unknown", &auth, TrialStatus::Unknown)
            ),
            Err(BudgetError::OutcomeNotTerminal)
        );

        let auth = authority();
        let mut ledger = BudgetLedger::new(
            envelope(Some(10), QuotaState::Known { remaining: 10 }),
            auth.clone(),
        )
        .expect("valid ledger");
        stage_and_activate(&mut ledger, "mismatch", &auth);
        let mut mismatched = usage("mismatch", &auth, TrialStatus::Succeeded);
        mismatched.provider_receipt_ref = receipt_ref_with_disposition(
            "mismatched-provider-receipt",
            &auth,
            ReceiptDispositionKind::Failure,
        );
        assert_eq!(
            ledger.commit("mismatch", &auth, &mismatched),
            Err(BudgetError::ReceiptReferenceConflict)
        );
    }

    #[test]
    fn measured_overrun_is_recorded_and_accounts_all_held_reservations() {
        let auth = authority();
        let mut ledger = BudgetLedger::new(
            envelope(Some(10), QuotaState::Known { remaining: 10 }),
            auth.clone(),
        )
        .expect("valid ledger");
        stage_and_activate(&mut ledger, "overrun", &auth);
        ledger
            .reserve(request("held", &auth, Some(5), Some(5)))
            .expect("second reservation remains held");

        let mut observed = usage("overrun", &auth, TrialStatus::Failed);
        observed.cost_micros = ObservedAmount::Known(6);
        observed.quota_units = ObservedAmount::Known(6);
        let terminal = ledger
            .commit("overrun", &auth, &observed)
            .expect("observed outcome is recorded even after an overrun");
        assert_eq!(terminal.state, ReservationState::Released);
        assert_eq!(terminal.disposition, ReceiptDispositionKind::Failure);
        assert_eq!(terminal.committed_usage, Some(observed));
        assert_eq!(
            terminal.exhaustion_disposition,
            ExhaustionDisposition::CostAndQuotaExceeded {
                window_ids: vec!["credits".to_owned()]
            }
        );
        assert_eq!(
            ledger.exhaustion_disposition().expect("checked totals"),
            terminal.exhaustion_disposition
        );
        assert_eq!(
            ledger.reserve(request("blocked", &auth, Some(0), Some(0))),
            Err(BudgetError::CostExceeded)
        );

        let mut reconciling = BudgetLedger::new(
            envelope(Some(5), QuotaState::Known { remaining: 10 }),
            auth.clone(),
        )
        .expect("valid ledger");
        stage_and_activate(&mut reconciling, "reconcile-overrun", &auth);
        reconciling
            .begin_reconciliation("reconcile-overrun", &auth)
            .expect("reconciling");
        let mut observed = usage("reconcile-overrun", &auth, TrialStatus::Partial);
        observed.cost_micros = ObservedAmount::Known(6);
        let terminal = reconciling
            .reconcile_usage("reconcile-overrun", &auth, &observed)
            .expect("reconciled overrun remains truthful");
        assert_eq!(terminal.disposition, ReceiptDispositionKind::Partial);
        assert_eq!(
            terminal.exhaustion_disposition,
            ExhaustionDisposition::CostExceeded
        );
    }

    #[test]
    fn same_fence_unrelated_receipt_locators_are_rejected() {
        let auth = authority();
        let mut ledger = BudgetLedger::new(
            envelope(Some(20), QuotaState::Known { remaining: 20 }),
            auth.clone(),
        )
        .expect("valid ledger");
        stage_and_activate(&mut ledger, "bound", &auth);

        let mut unrelated = usage("bound", &auth, TrialStatus::Succeeded);
        unrelated.provider_receipt_ref.operation = operation("unrelated", &auth);
        assert_eq!(
            ledger.commit("bound", &auth, &unrelated),
            Err(BudgetError::ReceiptReferenceConflict)
        );

        let mut wrong_kind = usage("bound", &auth, TrialStatus::Succeeded);
        wrong_kind.provider_receipt_ref.receipt_kind = ReceiptKind::Verification;
        assert_eq!(
            ledger.commit("bound", &auth, &wrong_kind),
            Err(BudgetError::ReceiptReferenceConflict)
        );

        let mut wrong_route = usage("bound", &auth, TrialStatus::Succeeded);
        wrong_route.provider_receipt_ref.provider_tool = fallback_route();
        assert_eq!(
            ledger.commit("bound", &auth, &wrong_route),
            Err(BudgetError::ReceiptReferenceConflict)
        );

        let terminal_usage = usage("bound", &auth, TrialStatus::Succeeded);
        ledger
            .commit("bound", &auth, &terminal_usage)
            .expect("matching receipt locator commits");
        let mut refund = RefundObservation {
            observation_id: "refund-unrelated".to_owned(),
            provider_tool: route(),
            operation: operation("bound", &auth),
            provider_receipt_ref: receipt_ref_with_disposition_and_operation(
                "refund-unrelated-receipt",
                &auth,
                ReceiptDispositionKind::Success,
                operation("unrelated", &auth),
            ),
            cost_micros: ObservedAmount::Known(1),
            status: TrialStatus::Succeeded,
        };
        assert_eq!(
            ledger.apply_refund("bound", &auth, &refund),
            Err(BudgetError::ReceiptReferenceConflict)
        );
        refund.provider_receipt_ref.operation = operation("bound", &auth);
        refund.provider_receipt_ref.receipt_kind = ReceiptKind::Artifact;
        assert_eq!(
            ledger.apply_refund("bound", &auth, &refund),
            Err(BudgetError::ReceiptReferenceConflict)
        );
    }

    #[test]
    fn refunds_require_measured_provider_tool_provenance_and_are_idempotent() {
        let auth = authority();
        let mut ledger = BudgetLedger::new(
            envelope(Some(20), QuotaState::Known { remaining: 20 }),
            auth.clone(),
        )
        .expect("valid ledger");
        stage_and_activate(&mut ledger, "refund", &auth);
        ledger
            .commit(
                "refund",
                &auth,
                &MeasuredUsage {
                    cost_micros: ObservedAmount::Known(10),
                    ..usage("refund", &auth, TrialStatus::Failed)
                },
            )
            .expect("failed provider work may still incur measured cost");

        let observation = RefundObservation {
            observation_id: "refund-observation:1".to_owned(),
            provider_tool: route(),
            operation: operation("refund", &auth),
            provider_receipt_ref: receipt_ref_with_disposition_and_operation(
                "provider-refund-1",
                &auth,
                ReceiptDispositionKind::Success,
                operation("refund", &auth),
            ),
            cost_micros: ObservedAmount::Known(4),
            status: TrialStatus::Succeeded,
        };
        let first = ledger
            .apply_refund("refund", &auth, &observation)
            .expect("measured refund");
        assert_eq!(first.refunded_cost_micros().expect("valid total"), Some(4));
        assert_eq!(
            ledger
                .apply_refund("refund", &auth, &observation)
                .expect("exact retry"),
            first
        );

        let mut conflict = observation.clone();
        conflict.cost_micros = ObservedAmount::Known(5);
        assert_eq!(
            ledger.apply_refund("refund", &auth, &conflict),
            Err(BudgetError::IdempotencyConflict)
        );
        let mut unmeasured = observation.clone();
        unmeasured.observation_id = "refund-observation:2".to_owned();
        unmeasured.provider_receipt_ref = receipt_ref_with_disposition_and_operation(
            "provider-refund-2",
            &auth,
            ReceiptDispositionKind::Success,
            operation("refund", &auth),
        );
        unmeasured.cost_micros = ObservedAmount::Unknown;
        assert_eq!(
            ledger.apply_refund("refund", &auth, &unmeasured),
            Err(BudgetError::UsageUnavailable("refund.cost_micros"))
        );
        let mut fallback = observation.clone();
        fallback.observation_id = "refund-observation:3".to_owned();
        fallback.provider_receipt_ref = receipt_ref_with_disposition_and_operation(
            "provider-refund-3",
            &auth,
            ReceiptDispositionKind::Success,
            operation("refund", &auth),
        );
        fallback.provider_tool = fallback_route();
        assert_eq!(
            ledger.apply_refund("refund", &auth, &fallback),
            Err(BudgetError::UnauthorizedFallback)
        );
    }

    #[test]
    fn fence_epoch_activation_receipts_and_idempotency_are_exact() {
        let auth = authority();
        let mut ledger = BudgetLedger::new(
            envelope(Some(20), QuotaState::Known { remaining: 20 }),
            auth.clone(),
        )
        .expect("valid ledger");
        let stable_request = request("stable", &auth, Some(2), Some(1));
        let first = ledger.reserve(stable_request.clone()).expect("reserved");
        assert_eq!(ledger.reserve(stable_request).expect("exact retry"), first);

        let mut zero_conflict = request("stable", &auth, Some(0), Some(1));
        zero_conflict.operation = first.operation.clone();
        assert_eq!(
            ledger.reserve(zero_conflict),
            Err(BudgetError::IdempotencyConflict)
        );

        let admission = receipt_ref("admission-stable", &auth);
        let activation = receipt_ref("activation-stable", &auth);
        let wrong_epoch = AuthorityEpoch::new(2).expect("valid epoch");
        let wrong_authority = authority_at(wrong_epoch);
        assert_eq!(
            ledger.activate(
                "stable",
                &auth,
                receipt_ref("wrong-fence-admission", &wrong_authority),
                receipt_ref("wrong-fence-activation", &wrong_authority),
            ),
            Err(BudgetError::FenceMismatch)
        );
        let mut wrong_kind = receipt_ref("wrong-kind-admission", &auth);
        wrong_kind.receipt_kind = ReceiptKind::Coordination;
        assert_eq!(
            ledger.activate(
                "stable",
                &auth,
                wrong_kind,
                receipt_ref("wrong-kind-activation", &auth),
            ),
            Err(BudgetError::ReceiptReferenceConflict)
        );
        let mut wrong_route = receipt_ref("wrong-route-admission", &auth);
        wrong_route.provider_tool = fallback_route();
        assert_eq!(
            ledger.activate(
                "stable",
                &auth,
                wrong_route,
                receipt_ref("wrong-route-activation", &auth),
            ),
            Err(BudgetError::ReceiptReferenceConflict)
        );
        let active = ledger
            .activate("stable", &auth, admission.clone(), activation.clone())
            .expect("active");
        assert_eq!(
            active.canonical_admission_receipt_ref,
            Some(admission.clone())
        );
        assert_eq!(active.activation_receipt_ref, Some(activation.clone()));
        assert_eq!(
            ledger
                .activate("stable", &auth, admission, activation)
                .expect("exact activation retry"),
            active
        );
        assert_eq!(
            ledger.activate(
                "stable",
                &auth,
                receipt_ref("different-admission", &auth),
                receipt_ref("different-activation", &auth),
            ),
            Err(BudgetError::IdempotencyConflict)
        );

        assert_eq!(
            ledger.begin_reconciliation("stable", &wrong_authority),
            Err(BudgetError::FenceMismatch)
        );
    }

    #[test]
    fn estimated_or_unknown_usage_never_becomes_committed_zero() {
        let auth = authority();
        for observed in [
            ObservedAmount::Estimated(0),
            ObservedAmount::Unknown,
            ObservedAmount::NotExposed,
        ] {
            let key = format!("unmeasured-{observed:?}");
            let mut ledger = BudgetLedger::new(
                envelope(Some(10), QuotaState::Known { remaining: 10 }),
                auth.clone(),
            )
            .expect("valid ledger");
            stage_and_activate(&mut ledger, &key, &auth);
            let mut measured = usage(&key, &auth, TrialStatus::Succeeded);
            measured.cost_micros = observed;
            assert_eq!(
                ledger.commit(&key, &auth, &measured),
                Err(BudgetError::UsageUnavailable("usage.cost_micros"))
            );
        }
    }

    #[test]
    fn concurrent_same_identity_has_one_stable_reservation() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let auth = authority();
        let ledger = Arc::new(Mutex::new(
            BudgetLedger::new(
                envelope(Some(20), QuotaState::Known { remaining: 20 }),
                auth.clone(),
            )
            .expect("valid ledger"),
        ));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let ledger = Arc::clone(&ledger);
            let auth = auth.clone();
            workers.push(thread::spawn(move || {
                ledger
                    .lock()
                    .expect("unpoisoned ledger")
                    .reserve(request("concurrent", &auth, Some(2), Some(1)))
                    .expect("stable reservation")
                    .reservation_id
            }));
        }
        let ids: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker completed"))
            .collect();
        assert!(ids.iter().all(|id| id == &ids[0]));
    }
}
