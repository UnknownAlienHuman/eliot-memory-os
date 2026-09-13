//! Kernel-side Doctor recovery ledger vocabulary (Slice 2, issue #461).
//!
//! Durable, non-semantic Operational Recovery State for exactly one
//! Kernel-admitted Doctor repair operation. Every identity here is opaque to
//! ORS: problem, component, evidence, fence, resource, approval, and lease
//! values are preserved as exact bytes or digests for replay comparison and
//! are never interpreted. The Kernel admission gate owns recipe resolution,
//! fence, lease, and approval validation; ORS owns durable identity
//! continuity: an exact replay returns the same admission, while changed
//! request, recipe, or effect terms under one identity fail as an identity
//! conflict and never overwrite the durable binding.
//!
//! Budget, cooldown, and quarantine are enforced from these durable records,
//! never from process-local state: [`DoctorBudgetLedger`] carries the
//! admission counter, the last-admission timestamp, the consecutive-failure
//! count, and quarantine evidence, and [`DoctorBudgetLedger::evaluate`] is a
//! pure function over that durable input, so enforcement survives restarts.
//! Unknown effect outcomes stay reconciling: only
//! [`DoctorRecoveryLedger::record_doctor_effect_outcome`] may bind the exact
//! outcome afterwards, and blind retry is prohibited.
//!
//! Persistence of these records over redb lands with the store slice (Wave
//! E): [`DoctorRecoveryLedger`] is the durable contract the store
//! implements. This module contains no stubs: every constructor, validator,
//! transition table, and budget evaluation here is complete and executes.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{validate_digest, validate_text};
use crate::{EpochLineage, OpaqueLabel, OperationIdentity, OrsError};

/// Storage contract version for every Doctor recovery record in this module.
pub const DOCTOR_RECORD_CONTRACT_VERSION: u16 = 1;
/// Maximum changed-dimension entries admitted in one Doctor identity conflict.
pub const DOCTOR_CONFLICT_MAX_FIELDS: usize = 32;

/// Durable Doctor repair-attempt operation state.
///
/// `Unknown` may only move to `Reconciling`, and neither `Unknown` nor
/// `Reconciling` may return to `Requested`: an uncertain outcome is
/// reconciled under the original attempt, never blind-retried as new work.
/// `Terminal` is absorbing: once an attempt is terminal, restart rehydrates
/// the terminal outcome instead of downgrading it.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DoctorAttemptState {
    /// Attempt intent persisted before any admission.
    Requested,
    /// Kernel bound the admission receipt to this attempt.
    Admitted,
    /// Effect intent persisted before execution.
    EffectIntended,
    /// Exact effect outcome recorded by effect identity.
    ResultRecorded,
    /// Effect may have run; outcome is not yet known.
    Unknown,
    /// Unknown outcome is being reconciled by exact effect identity.
    Reconciling,
    /// Attempt was cancelled before execution.
    Cancelled,
    /// Attempt lapsed before admission.
    Expired,
    /// Attempt reached its absorbing close.
    Terminal,
}

impl DoctorAttemptState {
    /// Returns whether the state closes the attempt.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::ResultRecorded | Self::Cancelled | Self::Expired | Self::Terminal
        )
    }

    /// Validates one mechanical state advance without interpreting meaning.
    pub fn transition_to(self, next: Self) -> Result<Self, OrsError> {
        let legal = matches!(
            (self, next),
            (
                Self::Requested,
                Self::Admitted | Self::Cancelled | Self::Expired
            ) | (
                Self::Admitted,
                Self::EffectIntended | Self::Cancelled | Self::Expired | Self::Unknown
            ) | (
                Self::EffectIntended,
                Self::ResultRecorded | Self::Unknown | Self::Cancelled
            ) | (Self::Unknown, Self::Reconciling)
                | (Self::Reconciling, Self::ResultRecorded | Self::Unknown)
                | (
                    Self::ResultRecorded | Self::Cancelled | Self::Expired,
                    Self::Terminal
                )
        );
        legal.then_some(next).ok_or(OrsError::InvalidTransition)
    }
}

/// Durable Doctor repair-attempt intent and admission record.
///
/// Every identity is opaque to ORS: the recipe and manifest digests, the
/// registered operation reference, the problem and component references, the
/// diagnostic-evidence digest, the session principal, the fence echo, the
/// resource-envelope digest, and the approval digest are preserved as exact
/// bytes for replay comparison and are never interpreted. The approval
/// *value* is never stored: only its SHA-256 binds presence, so authority
/// material cannot leak through this record. The Kernel admission gate owns
/// recipe resolution, epoch and fence currency, lease bounds, and approval
/// presence; ORS owns durable identity continuity: an exact replay under the
/// same attempt digest returns the same admission digest, while changed
/// terms under one digest fail as [`DoctorLedgerError::AttemptIdentityConflict`]
/// and never overwrite the durable binding.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorAttemptRecord {
    /// Storage contract version.
    pub contract_version: u16,
    /// Immutable attempt identity digest; the durable key.
    pub attempt_digest: OperationIdentity,
    /// Opaque digest of the exact registered recipe revision.
    pub recipe_digest: String,
    /// Opaque digest of the exact admitted manifest revision.
    pub manifest_digest: String,
    /// Registered named-effect operation identity; opaque routing label.
    pub operation_id: OpaqueLabel,
    /// Opaque digest of the registered operation definition.
    pub operation_definition_digest: String,
    /// Opaque problem reference from the diagnostic brief.
    pub problem_ref: OpaqueLabel,
    /// Opaque component reference from the diagnostic brief.
    pub component_ref: OpaqueLabel,
    /// Opaque digest over the diagnostic-evidence handles.
    pub evidence_digest: String,
    /// Authenticated session principal bound at admission; opaque to ORS.
    pub principal_ref: OpaqueLabel,
    /// Opaque echo of the Kernel-supplied state-fence digest.
    pub fence_digest: String,
    /// Authority epoch at admission time.
    pub authority_epoch: u64,
    /// Target resource generation at admission time.
    pub generation: u64,
    /// Explicit epoch lineage fencing this attempt, when the Kernel
    /// supplied one. `None` preserves the echo path: the epoch and fence
    /// digests above still bind the attempt exactly.
    pub epoch_lineage: Option<EpochLineage>,
    /// Opaque digest of the target resource envelope.
    pub target_resource_digest: String,
    /// SHA-256 of the presented approval, or `None` when no approval was
    /// presented. Binds approval presence without storing authority material.
    pub approval_digest: Option<String>,
    /// Admitted budget units bound to this attempt.
    pub budget_units: u64,
    /// Attempt deadline in Unix nanoseconds.
    pub deadline_unix_nanos: u64,
    /// Recovery-lease expiry in Unix nanoseconds.
    pub lease_expires_unix_nanos: u64,
    /// Recipe cooldown in nanoseconds.
    pub cooldown_nanos: u64,
    /// Cancellation flag presented with the attempt.
    pub cancelled: bool,
    /// Canonical digest over every bound attempt field.
    pub binding_digest: String,
    /// Digest over the exact presenting wire-request bytes.
    pub request_digest: String,
    /// Durable attempt state.
    pub state: DoctorAttemptState,
    /// Canonical digest of the immutable admission. `None` while the intent
    /// is only requested; `Some` once Kernel admits the attempt. The
    /// admission digest never changes afterwards: exact replay returns this
    /// same digest.
    pub admission_digest: Option<String>,
    /// Admission time in Unix nanoseconds. `None` while requested.
    pub admitted_at_unix_nanos: Option<u64>,
    /// Monotonic ORS order assigned atomically when the attempt first
    /// reaches a terminal state. Zero while non-terminal.
    #[serde(default)]
    pub commit_order: u64,
}

impl DoctorAttemptRecord {
    /// Returns the durable key binding one attempt identity to one exact row.
    pub fn record_key(&self) -> String {
        self.attempt_digest.as_str().to_owned()
    }

    /// Returns whether two records carry the exact same admitted binding.
    ///
    /// State, admission evidence, and commit order are excluded: they are
    /// ORS-owned progression, not caller binding. Mirrors
    /// [`crate::HostRequestRecord::same_binding`].
    pub fn same_binding(&self, other: &Self) -> bool {
        self.attempt_digest == other.attempt_digest
            && self.recipe_digest == other.recipe_digest
            && self.manifest_digest == other.manifest_digest
            && self.operation_id == other.operation_id
            && self.operation_definition_digest == other.operation_definition_digest
            && self.problem_ref == other.problem_ref
            && self.component_ref == other.component_ref
            && self.evidence_digest == other.evidence_digest
            && self.principal_ref == other.principal_ref
            && self.fence_digest == other.fence_digest
            && self.authority_epoch == other.authority_epoch
            && self.generation == other.generation
            && self.epoch_lineage == other.epoch_lineage
            && self.target_resource_digest == other.target_resource_digest
            && self.approval_digest == other.approval_digest
            && self.budget_units == other.budget_units
            && self.deadline_unix_nanos == other.deadline_unix_nanos
            && self.lease_expires_unix_nanos == other.lease_expires_unix_nanos
            && self.cooldown_nanos == other.cooldown_nanos
            && self.cancelled == other.cancelled
            && self.binding_digest == other.binding_digest
            && self.request_digest == other.request_digest
    }

    /// Validates identity shape and state and admission coherence without
    /// interpreting semantic meaning.
    pub fn validate(&self) -> Result<(), OrsError> {
        self.validate_binding()?;
        self.validate_admission_coherence()
    }

    /// Validates identity shape and bound terms without interpreting meaning.
    fn validate_binding(&self) -> Result<(), OrsError> {
        if self.contract_version != DOCTOR_RECORD_CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        validate_text(self.attempt_digest.as_str(), "doctor_attempt_digest")?;
        for (value, field) in [
            (&self.recipe_digest, "doctor_attempt_recipe_digest"),
            (&self.manifest_digest, "doctor_attempt_manifest_digest"),
            (
                &self.operation_definition_digest,
                "doctor_attempt_operation_definition_digest",
            ),
            (&self.evidence_digest, "doctor_attempt_evidence_digest"),
            (&self.fence_digest, "doctor_attempt_fence_digest"),
            (
                &self.target_resource_digest,
                "doctor_attempt_target_resource_digest",
            ),
            (&self.binding_digest, "doctor_attempt_binding_digest"),
            (&self.request_digest, "doctor_attempt_request_digest"),
        ] {
            validate_digest(value, field)?;
        }
        for (value, field) in [
            (&self.operation_id, "doctor_attempt_operation_id"),
            (&self.problem_ref, "doctor_attempt_problem_ref"),
            (&self.component_ref, "doctor_attempt_component_ref"),
            (&self.principal_ref, "doctor_attempt_principal_ref"),
        ] {
            validate_text(value.as_str(), field)?;
        }
        if let Some(approval) = &self.approval_digest {
            validate_digest(approval, "doctor_attempt_approval_digest")?;
        }
        if let Some(lineage) = &self.epoch_lineage {
            lineage.validate()?;
            if lineage.current.epoch != self.authority_epoch {
                return Err(OrsError::EpochMismatch);
            }
        }
        if self.authority_epoch == 0 || self.generation == 0 {
            return Err(OrsError::InvalidField {
                field: "doctor_attempt_epoch",
                reason: "must be non-zero",
            });
        }
        if self.budget_units == 0 {
            return Err(OrsError::InvalidField {
                field: "doctor_attempt_budget_units",
                reason: "must be greater than zero",
            });
        }
        if self.deadline_unix_nanos == 0 || self.lease_expires_unix_nanos == 0 {
            return Err(OrsError::InvalidField {
                field: "doctor_attempt_deadline",
                reason: "deadline and lease expiry must be greater than zero",
            });
        }
        if self.cancelled
            && matches!(
                self.state,
                DoctorAttemptState::EffectIntended
                    | DoctorAttemptState::ResultRecorded
                    | DoctorAttemptState::Unknown
                    | DoctorAttemptState::Reconciling
            )
        {
            return Err(OrsError::InvalidField {
                field: "doctor_attempt_cancelled",
                reason: "a cancelled attempt never reaches effect execution states",
            });
        }
        Ok(())
    }

    /// Validates admission evidence and commit-order coherence.
    fn validate_admission_coherence(&self) -> Result<(), OrsError> {
        match (
            &self.state,
            &self.admission_digest,
            self.admitted_at_unix_nanos,
        ) {
            (DoctorAttemptState::Requested | DoctorAttemptState::Expired, None, None) => {}
            (DoctorAttemptState::Requested | DoctorAttemptState::Expired, _, _) => {
                return Err(OrsError::InvalidField {
                    field: "doctor_attempt_admission",
                    reason: "a requested or expired intent carries no admission",
                });
            }
            (_, Some(admission), Some(admitted_at)) => {
                validate_digest(admission, "doctor_attempt_admission_digest")?;
                if admitted_at == 0 {
                    return Err(OrsError::InvalidField {
                        field: "doctor_attempt_admitted_at",
                        reason: "admission time must be greater than zero",
                    });
                }
            }
            _ => {
                return Err(OrsError::InvalidField {
                    field: "doctor_attempt_admission",
                    reason: "an admitted attempt carries its immutable admission",
                });
            }
        }
        if self.state == DoctorAttemptState::Cancelled && !self.cancelled {
            return Err(OrsError::InvalidField {
                field: "doctor_attempt_cancelled",
                reason: "cancelled state requires the bound cancellation flag",
            });
        }
        if !self.state.is_terminal() && self.commit_order != 0 {
            return Err(OrsError::InvalidField {
                field: "doctor_attempt_commit_order",
                reason: "non-terminal states must not carry a commit order",
            });
        }
        Ok(())
    }
}

/// Durable Doctor effect-intent operation state.
///
/// `Unknown` may only move to `Reconciling`, and `Reported` is absorbing:
/// an exact outcome report replay returns the durable record unchanged,
/// while a different outcome under the same effect identity fails as
/// [`DoctorLedgerError::EffectIdentityConflict`]. There is no blind retry:
/// an uncertain effect is reconciled under its original identity.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DoctorEffectState {
    /// Effect intent persisted before execution.
    Intended,
    /// Exact outcome recorded by effect identity.
    Reported,
    /// Effect may have run; outcome is not yet known.
    Unknown,
    /// Unknown outcome is being reconciled by exact effect identity.
    Reconciling,
}

impl DoctorEffectState {
    /// Returns whether the state closes the effect.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Reported)
    }

    /// Validates one mechanical state advance without interpreting meaning.
    pub fn transition_to(self, next: Self) -> Result<Self, OrsError> {
        let legal = matches!(
            (self, next),
            (
                Self::Intended | Self::Reconciling,
                Self::Reported | Self::Unknown
            ) | (Self::Unknown, Self::Reconciling)
        );
        legal.then_some(next).ok_or(OrsError::InvalidTransition)
    }
}

/// Durable Doctor effect-intent record, persisted before execution.
///
/// The intent digest binds the exact authorized effect; the outcome digest
/// binds the exact observed outcome afterwards, both keyed by the immutable
/// effect identity. Adapter receipts are retained as opaque digests, never
/// interpreted. While the outcome is unknown the reconciliation key carries
/// the effect digest itself, so a later reconciliation must name the same
/// effect and can never blind-retry a fresh one.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorEffectRecord {
    /// Storage contract version.
    pub contract_version: u16,
    /// Immutable effect identity digest; the durable key.
    pub effect_digest: OperationIdentity,
    /// Attempt identity this effect was admitted under; opaque to ORS.
    pub attempt_digest: String,
    /// Registered named-effect operation identity; opaque routing label.
    pub operation_id: OpaqueLabel,
    /// Effect sequence distinguishing several effects of one attempt.
    pub effect_seq: u32,
    /// Digest over the exact authorized intent envelope.
    pub intent_digest: String,
    /// Durable effect state.
    pub state: DoctorEffectState,
    /// Digest of the exact outcome bound afterwards. `None` until reported.
    pub outcome_digest: Option<String>,
    /// Opaque digest of the executing adapter or process receipt, when one
    /// was returned. `None` while unreported or receiptless.
    pub adapter_receipt_digest: Option<String>,
    /// Reconciliation key while the outcome is unknown: always the effect
    /// digest itself. `None` once the outcome is reported.
    pub reconciliation_key: Option<String>,
    /// Monotonic ORS order assigned atomically when the effect first
    /// reaches its terminal state. Zero while non-terminal.
    #[serde(default)]
    pub commit_order: u64,
}

impl DoctorEffectRecord {
    /// Returns the durable key binding one effect identity to one exact row.
    pub fn record_key(&self) -> String {
        self.effect_digest.as_str().to_owned()
    }

    /// Returns whether two records carry the exact same authorized intent.
    ///
    /// State, outcome, receipt, reconciliation key, and commit order are
    /// excluded: they are ORS-owned progression, not caller binding.
    pub fn same_binding(&self, other: &Self) -> bool {
        self.effect_digest == other.effect_digest
            && self.attempt_digest == other.attempt_digest
            && self.operation_id == other.operation_id
            && self.effect_seq == other.effect_seq
            && self.intent_digest == other.intent_digest
    }

    /// Validates identity shape and state and outcome coherence.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != DOCTOR_RECORD_CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        validate_text(self.effect_digest.as_str(), "doctor_effect_digest")?;
        validate_digest(&self.attempt_digest, "doctor_effect_attempt_digest")?;
        validate_digest(&self.intent_digest, "doctor_effect_intent_digest")?;
        validate_text(self.operation_id.as_str(), "doctor_effect_operation_id")?;
        match (
            &self.state,
            &self.outcome_digest,
            &self.adapter_receipt_digest,
            &self.reconciliation_key,
        ) {
            (DoctorEffectState::Intended, None, None, None) => {}
            (DoctorEffectState::Intended, _, _, _) => {
                return Err(OrsError::InvalidField {
                    field: "doctor_effect_outcome",
                    reason: "an intended effect carries no outcome or reconciliation key",
                });
            }
            (DoctorEffectState::Reported, Some(outcome), receipt, None) => {
                validate_digest(outcome, "doctor_effect_outcome_digest")?;
                if let Some(receipt) = receipt {
                    validate_digest(receipt, "doctor_effect_adapter_receipt_digest")?;
                }
            }
            (DoctorEffectState::Reported, _, _, _) => {
                return Err(OrsError::InvalidField {
                    field: "doctor_effect_outcome",
                    reason: "a reported effect carries its exact outcome and no open key",
                });
            }
            (
                DoctorEffectState::Unknown | DoctorEffectState::Reconciling,
                None,
                None,
                Some(key),
            ) => {
                if key != self.effect_digest.as_str() {
                    return Err(OrsError::InvalidField {
                        field: "doctor_effect_reconciliation_key",
                        reason: "reconciliation must name the exact effect identity",
                    });
                }
            }
            (DoctorEffectState::Unknown | DoctorEffectState::Reconciling, _, _, _) => {
                return Err(OrsError::InvalidField {
                    field: "doctor_effect_reconciliation_key",
                    reason: "an unknown effect carries only its identity as reconciliation key",
                });
            }
        }
        if !self.state.is_terminal() && self.commit_order != 0 {
            return Err(OrsError::InvalidField {
                field: "doctor_effect_commit_order",
                reason: "non-terminal states must not carry a commit order",
            });
        }
        Ok(())
    }
}

/// Why a Doctor recovery scope was quarantined. Quarantine is terminal for
/// automatic retry under the quarantined scope; only a new admission outside
/// the quarantine (or an operator-cleared ledger) may proceed.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DoctorQuarantineCause {
    /// The recipe attempt budget is exhausted.
    BudgetExhausted,
    /// A new attempt arrived inside the recipe cooldown.
    CooldownActive,
    /// Consecutive failures reached the quarantine threshold.
    RepeatedFailure,
    /// An unknown outcome was never reconciled.
    UnknownOutcomeUnresolved,
}

/// Durable quarantine evidence bound to one Doctor budget scope.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorQuarantine {
    /// Why the scope was quarantined.
    pub cause: DoctorQuarantineCause,
    /// Quarantine time in Unix nanoseconds.
    pub quarantined_at_unix_nanos: u64,
    /// Quarantine expiry in Unix nanoseconds. `None` quarantines until an
    /// operator clears the ledger.
    pub quarantined_until_unix_nanos: Option<u64>,
}

impl DoctorQuarantine {
    /// Validates quarantine shape.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.quarantined_at_unix_nanos == 0 {
            return Err(OrsError::InvalidField {
                field: "doctor_quarantine_at",
                reason: "quarantine time must be greater than zero",
            });
        }
        if let Some(until) = self.quarantined_until_unix_nanos
            && until <= self.quarantined_at_unix_nanos
        {
            return Err(OrsError::InvalidField {
                field: "doctor_quarantine_until",
                reason: "quarantine expiry must be strictly later than quarantine time",
            });
        }
        Ok(())
    }

    /// Returns whether the quarantine still holds at `now_unix_nanos`.
    pub fn holds_at(&self, now_unix_nanos: u64) -> bool {
        self.quarantined_until_unix_nanos
            .is_none_or(|until| now_unix_nanos < until)
    }
}

/// Durable per-scope Doctor budget ledger.
///
/// The scope key opaquely binds one component to one exact recipe revision;
/// ORS never interprets either side. The admission counter, the
/// last-admission timestamp, and the consecutive-failure count are durable
/// fields of this record, so budget, cooldown, and quarantine enforcement
/// survive restarts without any process-local state.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorBudgetLedger {
    /// Storage contract version.
    pub contract_version: u16,
    /// Opaque scope key binding one component to one recipe revision.
    pub scope_key: OpaqueLabel,
    /// Total admissions ever bound to this scope, across restarts.
    pub total_admissions: u64,
    /// Consecutive failed outcomes bound to this scope.
    pub consecutive_failures: u32,
    /// Last admission time in Unix nanoseconds. `None` before the first
    /// admission.
    pub last_attempt_unix_nanos: Option<u64>,
    /// Active quarantine evidence, when the scope is quarantined.
    pub quarantine: Option<DoctorQuarantine>,
}

impl DoctorBudgetLedger {
    /// Returns a pristine ledger for a scope that has never admitted work.
    pub fn pristine(scope_key: OpaqueLabel) -> Self {
        Self {
            contract_version: DOCTOR_RECORD_CONTRACT_VERSION,
            scope_key,
            total_admissions: 0,
            consecutive_failures: 0,
            last_attempt_unix_nanos: None,
            quarantine: None,
        }
    }

    /// Returns the durable key binding one scope to one exact row.
    pub fn record_key(&self) -> String {
        self.scope_key.as_str().to_owned()
    }

    /// Validates ledger shape.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != DOCTOR_RECORD_CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        validate_text(self.scope_key.as_str(), "doctor_budget_scope_key")?;
        if self.total_admissions == 0
            && (self.last_attempt_unix_nanos.is_some()
                || self.consecutive_failures != 0
                || self.quarantine.is_some())
        {
            return Err(OrsError::InvalidField {
                field: "doctor_budget_ledger",
                reason: "a pristine ledger carries no history or quarantine",
            });
        }
        if let Some(last) = self.last_attempt_unix_nanos
            && last == 0
        {
            return Err(OrsError::InvalidField {
                field: "doctor_budget_last_attempt",
                reason: "admission time must be greater than zero",
            });
        }
        if let Some(quarantine) = &self.quarantine {
            quarantine.validate()?;
        }
        Ok(())
    }

    /// Evaluates budget, cooldown, and quarantine from durable state.
    ///
    /// Pure over durable input: the same ledger and clock always yield the
    /// same decision, so enforcement is identical before and after a
    /// restart. Quarantine dominates: an active quarantine refuses before
    /// budget is consulted. Budget exhaustion dominates cooldown: a scope
    /// that spent its recipe budget is exhausted even outside cooldown. A
    /// zero recipe budget refuses every admission. A backward clock never
    /// admits: when `now` precedes the last admission, the decision stays
    /// cooling until the durable timestamp.
    pub fn evaluate(
        &self,
        attempt_budget: u32,
        cooldown_nanos: u64,
        now_unix_nanos: u64,
    ) -> DoctorBudgetDecision {
        if let Some(quarantine) = &self.quarantine
            && quarantine.holds_at(now_unix_nanos)
        {
            return DoctorBudgetDecision::Quarantined {
                cause: quarantine.cause,
            };
        }
        let budget = u64::from(attempt_budget);
        if self.total_admissions >= budget {
            return DoctorBudgetDecision::BudgetExhausted {
                attempts_used: self.total_admissions,
                attempt_budget: budget,
            };
        }
        if let Some(last) = self.last_attempt_unix_nanos {
            let retry_after = last.saturating_add(cooldown_nanos);
            if now_unix_nanos < last || now_unix_nanos - last < cooldown_nanos {
                return DoctorBudgetDecision::CooldownActive {
                    retry_after_unix_nanos: retry_after,
                };
            }
        }
        DoctorBudgetDecision::Admitted {
            attempts_remaining: budget.saturating_sub(self.total_admissions),
        }
    }

    /// Notes one bound admission at `now_unix_nanos`.
    pub fn note_admission(&mut self, now_unix_nanos: u64) -> Result<(), OrsError> {
        if now_unix_nanos == 0 {
            return Err(OrsError::InvalidField {
                field: "doctor_budget_last_attempt",
                reason: "admission time must be greater than zero",
            });
        }
        self.total_admissions = self.total_admissions.saturating_add(1);
        self.last_attempt_unix_nanos = Some(now_unix_nanos);
        Ok(())
    }

    /// Notes one bound outcome: a failure extends the consecutive-failure
    /// run, any other outcome resets it.
    pub fn note_outcome(&mut self, failed: bool) {
        if failed {
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        } else {
            self.consecutive_failures = 0;
        }
    }

    /// Binds quarantine evidence to this scope.
    pub fn record_quarantine(
        &mut self,
        cause: DoctorQuarantineCause,
        now_unix_nanos: u64,
        quarantined_until_unix_nanos: Option<u64>,
    ) -> Result<(), OrsError> {
        let quarantine = DoctorQuarantine {
            cause,
            quarantined_at_unix_nanos: now_unix_nanos,
            quarantined_until_unix_nanos,
        };
        quarantine.validate()?;
        self.quarantine = Some(quarantine);
        Ok(())
    }
}

/// Pure budget, cooldown, and quarantine decision over durable ledger state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DoctorBudgetDecision {
    /// The scope may admit; carries the remaining recipe budget.
    Admitted {
        /// Recipe budget minus durable admissions.
        attempts_remaining: u64,
    },
    /// The recipe cooldown still holds; carries the earliest retry time.
    CooldownActive {
        /// Earliest Unix-nanosecond retry time.
        retry_after_unix_nanos: u64,
    },
    /// The durable admission count reached the recipe budget.
    BudgetExhausted {
        /// Durable admissions bound to this scope.
        attempts_used: u64,
        /// Recipe budget that was exhausted.
        attempt_budget: u64,
    },
    /// The scope is quarantined.
    Quarantined {
        /// Why the scope was quarantined.
        cause: DoctorQuarantineCause,
    },
}

/// Admission evidence bound when a requested attempt becomes admitted.
///
/// Carried only by the `Requested -> Admitted` and `Requested -> Cancelled`
/// advances (and accepted unchanged on an exact replay of an applied
/// advance); it is never overwritten once bound, so one attempt digest keeps
/// one admission digest.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorAttemptAdmission {
    /// Canonical digest of the immutable admission.
    pub admission_digest: String,
    /// Admission time in Unix nanoseconds.
    pub admitted_at_unix_nanos: u64,
}

impl DoctorAttemptAdmission {
    /// Validates admission-evidence shape.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_digest(&self.admission_digest, "doctor_attempt_admission_digest")?;
        if self.admitted_at_unix_nanos == 0 {
            return Err(OrsError::InvalidField {
                field: "doctor_attempt_admitted_at",
                reason: "admission time must be greater than zero",
            });
        }
        Ok(())
    }
}

/// Outcome evidence bound to one effect afterwards, by exact effect identity.
///
/// `unknown` reports that the effect may have run without a known outcome:
/// it carries no outcome or receipt digest and moves the effect to
/// `Unknown` with the effect digest as its reconciliation key. A known
/// outcome carries its exact digest and moves the effect to `Reported`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorEffectOutcomeReport {
    /// Digest of the exact observed outcome. `None` for unknown outcomes.
    pub outcome_digest: Option<String>,
    /// Opaque digest of the executing adapter receipt, when one exists.
    pub adapter_receipt_digest: Option<String>,
    /// Whether the outcome is unknown.
    pub unknown: bool,
}

impl DoctorEffectOutcomeReport {
    /// Validates outcome-report shape.
    pub fn validate(&self) -> Result<(), OrsError> {
        match (
            self.unknown,
            &self.outcome_digest,
            &self.adapter_receipt_digest,
        ) {
            (true, None, None) => Ok(()),
            (true, _, _) => Err(OrsError::InvalidField {
                field: "doctor_effect_outcome",
                reason: "an unknown outcome carries no outcome or receipt digest",
            }),
            (false, Some(outcome), receipt) => {
                validate_digest(outcome, "doctor_effect_outcome_digest")?;
                if let Some(receipt) = receipt {
                    validate_digest(receipt, "doctor_effect_adapter_receipt_digest")?;
                }
                Ok(())
            }
            (false, None, _) => Err(OrsError::InvalidField {
                field: "doctor_effect_outcome",
                reason: "a known outcome carries its exact digest",
            }),
        }
    }
}

/// Result of the atomic attempt-staging write.
///
/// `Stored` is a newly persisted intent; `Existing` is an exact replay
/// carrying the same admission digest. A changed binding under the same
/// attempt digest is not a variant here: staging fails with
/// [`DoctorLedgerError::AttemptIdentityConflict`] and never overwrites.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DoctorAttemptStageOutcome {
    /// A newly persisted attempt intent.
    Stored(DoctorAttemptRecord),
    /// An exact replay of a durably staged attempt.
    Existing(DoctorAttemptRecord),
}

impl DoctorAttemptStageOutcome {
    /// Returns the durable record regardless of how the write resolved.
    pub fn record(&self) -> &DoctorAttemptRecord {
        match self {
            Self::Stored(record) | Self::Existing(record) => record,
        }
    }
}

/// Result of the atomic effect-intent staging write.
///
/// `Stored` is a newly persisted intent; `Existing` is an exact replay of
/// the same authorized intent. A changed intent under the same effect
/// digest fails with [`DoctorLedgerError::EffectIdentityConflict`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DoctorEffectStageOutcome {
    /// A newly persisted effect intent.
    Stored(DoctorEffectRecord),
    /// An exact replay of a durably staged intent.
    Existing(DoctorEffectRecord),
}

impl DoctorEffectStageOutcome {
    /// Returns the durable record regardless of how the write resolved.
    pub fn record(&self) -> &DoctorEffectRecord {
        match self {
            Self::Stored(record) | Self::Existing(record) => record,
        }
    }
}

/// Typed Doctor ledger failures. None grants semantic or completion
/// authority.
#[derive(Debug, Error)]
pub enum DoctorLedgerError {
    /// Durable storage failed.
    #[error("durable doctor storage failed: {0}")]
    Storage(String),
    /// Durable encoding failed.
    #[error("durable doctor encoding failed: {0}")]
    Encoding(String),
    /// Changed attempt terms under one attempt digest: `IDENTITY_CONFLICT`.
    #[error("doctor attempt {attempt_digest} conflicts with durable ORS state: IDENTITY_CONFLICT")]
    AttemptIdentityConflict {
        /// Attempt digest both bindings were presented under.
        attempt_digest: String,
    },
    /// Changed effect terms under one effect digest: `IDENTITY_CONFLICT`.
    #[error("doctor effect {effect_digest} conflicts with durable ORS state: IDENTITY_CONFLICT")]
    EffectIdentityConflict {
        /// Effect digest both intents were presented under.
        effect_digest: String,
    },
}

/// Durable Doctor recovery ledger contract.
///
/// Implementations persist [`DoctorAttemptRecord`], [`DoctorEffectRecord`],
/// and [`DoctorBudgetLedger`] rows across restarts and enforce the
/// first-writer-wins rules documented on each method: an exact replay under
/// one identity returns the durable row unchanged, while changed terms
/// under one identity fail with an identity conflict and never overwrite.
/// The store slice implements this contract over redb; the Kernel admission
/// gate is generic over it, so no admission path can depend on
/// process-local state.
pub trait DoctorRecoveryLedger: Send + Sync {
    /// Stages one attempt intent before any admission.
    ///
    /// An exact replay under the same attempt digest returns
    /// [`DoctorAttemptStageOutcome::Existing`] with the same admission
    /// digest; a changed binding fails with
    /// [`DoctorLedgerError::AttemptIdentityConflict`] and never overwrites
    /// the durable row.
    fn stage_doctor_attempt(
        &self,
        record: &DoctorAttemptRecord,
    ) -> Result<DoctorAttemptStageOutcome, DoctorLedgerError>;

    /// Loads one attempt by exact attempt digest.
    fn load_doctor_attempt(
        &self,
        attempt_digest: &OperationIdentity,
    ) -> Result<Option<DoctorAttemptRecord>, DoctorLedgerError>;

    /// Advances one staged attempt to its next mechanical state.
    ///
    /// An exact repeat of an applied advance returns the durable record
    /// unchanged. An unknown attempt returns `Ok(None)`; this method never
    /// invents a record and never retries blindly. Admission evidence binds
    /// the admission digest on `Requested -> Admitted` and
    /// `Requested -> Cancelled`, is accepted unchanged on an exact replay
    /// of an applied advance, and can never overwrite a bound admission.
    fn advance_doctor_attempt(
        &self,
        attempt_digest: &OperationIdentity,
        target: DoctorAttemptState,
        admission: Option<&DoctorAttemptAdmission>,
    ) -> Result<Option<DoctorAttemptRecord>, DoctorLedgerError>;

    /// Stages one effect intent before execution.
    ///
    /// An exact replay under the same effect digest returns
    /// [`DoctorEffectStageOutcome::Existing`]; a changed intent fails with
    /// [`DoctorLedgerError::EffectIdentityConflict`] and never overwrites
    /// the durable row.
    fn stage_doctor_effect(
        &self,
        record: &DoctorEffectRecord,
    ) -> Result<DoctorEffectStageOutcome, DoctorLedgerError>;

    /// Loads one effect by exact effect digest.
    fn load_doctor_effect(
        &self,
        effect_digest: &OperationIdentity,
    ) -> Result<Option<DoctorEffectRecord>, DoctorLedgerError>;

    /// Binds the exact outcome or unknown state to one effect afterwards.
    ///
    /// A known report on `Intended` moves the effect to `Reported`; an
    /// unknown report on `Intended` moves it to `Unknown` with the effect
    /// digest as its reconciliation key; a known report on `Unknown` or
    /// `Reconciling` moves it to `Reported`. An exact repeat of an applied
    /// report returns the durable record unchanged; a different outcome
    /// under the same effect digest fails with
    /// [`DoctorLedgerError::EffectIdentityConflict`]. An unknown effect
    /// returns `Ok(None)`; this method never invents a record.
    fn record_doctor_effect_outcome(
        &self,
        effect_digest: &OperationIdentity,
        report: &DoctorEffectOutcomeReport,
    ) -> Result<Option<DoctorEffectRecord>, DoctorLedgerError>;

    /// Loads one budget ledger by exact scope key.
    fn load_doctor_budget(
        &self,
        scope_key: &OpaqueLabel,
    ) -> Result<Option<DoctorBudgetLedger>, DoctorLedgerError>;

    /// Persists one budget ledger row, replacing the prior row for its
    /// scope key. Ledgers are Kernel-derived from durable admissions and
    /// outcomes, never caller-supplied.
    fn store_doctor_budget(&self, ledger: &DoctorBudgetLedger) -> Result<(), DoctorLedgerError>;
}
