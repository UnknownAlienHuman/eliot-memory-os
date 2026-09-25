//! Kernel-owned UserAutomation contracts and deterministic admission.
//!
//! This module is the semantic owner of the first I11.12 automation boundary.
//! It describes immutable revision/configuration state and validates an
//! owner-issued preflight projection. It does not persist a revision, create a
//! scheduler, launch a process, call a provider, or issue a notification
//! receipt. Wake and execution values are typed projections of the existing
//! [`WakeIntent`] and Durable Job contracts; their owners remain responsible
//! for admission, persistence, execution and reconciliation.

use std::collections::BTreeSet;

pub use eliot_config::ConfigPolicySnapshot;
use eliot_contracts::{
    ContractIdentity, ContractVersion, OperationId, PolicyRevision, RequestMetadata, StateFence,
    canonical_json_bytes, contract_identity, sha256_hex,
};
use eliot_platform::PlatformHandle;
use eliot_protocol::{JobOperationKind, JobState};
use eliot_receipts::ReceiptEnvelope;
use eliot_runtime_contracts::{WakeIntent, WakeIntentState};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable contract name for the Kernel-owned UserAutomation domain.
pub const USER_AUTOMATION_CONTRACT_NAME: &str = "eliot.kernel.user-automation";
/// Current semantic contract revision.
pub const USER_AUTOMATION_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 1, 0);
/// Selector used by authenticated Kernel/Host preflight reads.
pub const USER_AUTOMATION_PREFLIGHT_SELECTOR: &str = "eliot.config.user_automation.v1";
/// Operation marker used by the preflight read route.
pub const USER_AUTOMATION_PREFLIGHT_OPERATION: &str = "GetUserAutomationPreflightProjection";
/// Effect ceiling for the authenticated preflight route.
pub const USER_AUTOMATION_PREFLIGHT_EFFECT_CEILING: &str = "READ";
/// Fixed scope for the UserAutomation projection query.
pub const USER_AUTOMATION_SCOPE: &str = "user-automation";
/// Revision required by the deterministic preflight contract.
pub const USER_AUTOMATION_PREFLIGHT_CONTRACT_REVISION: &str = "eliot.user-automation.preflight.v1";
const OCCURRENCE_IDENTITY_DOMAIN: &str = "ELIOT/I11.12/USER-AUTOMATION-OCCURRENCE/V1";
const FAILURE_FINGERPRINT_DOMAIN: &str = "ELIOT/I11.12/USER-AUTOMATION-FAILURE/V1";
const WAKE_REASON_PREFIX: &str = "user-automation";
const MAX_TEXT_BYTES: usize = 16 * 1024;
const MAX_REFERENCES: usize = 256;

/// Errors returned by the pure UserAutomation contract boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum UserAutomationError {
    /// A required field has an invalid shape.
    #[error("invalid UserAutomation field: {0}")]
    Invalid(&'static str),
    /// A bounded list or text field exceeded its contract limit.
    #[error("UserAutomation field exceeds its bound: {0}")]
    LimitExceeded(&'static str),
    /// The canonical configuration snapshot is incomplete or invalid.
    #[error("canonical configuration snapshot is invalid: {0}")]
    Config(String),
    /// The owner-issued source receipt is invalid.
    #[error("owner-issued source receipt is invalid: {0}")]
    Receipt(String),
    /// The owner-issued receipt does not bind to the authenticated request.
    #[error("owner-issued source receipt is not bound to the authenticated request")]
    ReceiptBinding,
    /// The invocation and immutable revision disagree.
    #[error("UserAutomation invocation does not match its immutable revision")]
    RevisionMismatch,
    /// The invocation trigger does not identify the projected occurrence.
    #[error("UserAutomation occurrence identity mismatch")]
    OccurrenceMismatch,
    /// An owner projection omitted the failure data needed for a blocked result.
    #[error("blocked_config requires an owner-issued failure projection")]
    FailureProjectionMissing,
    /// An owner projection supplied a different failure fingerprint.
    #[error("owner-issued failure fingerprint is not the deterministic class fingerprint")]
    FailureFingerprintMismatch,
    /// A supersession does not form one immutable revision lineage.
    #[error("UserAutomation revision supersession is invalid")]
    InvalidSupersession,
    /// Canonical serialization failed while deriving an identity.
    #[error("UserAutomation canonical serialization failed: {0}")]
    Serialization(String),
}

/// Execution mode admitted by an immutable revision.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserAutomationExecutionMode {
    /// Normal admitted task/model path; model access is still gated by the
    /// resulting preflight receipt and the existing route owners.
    Agent,
    /// Qualified process path with a capability profile that excludes model
    /// and provider access.
    DeterministicProcess,
}

/// Configuration state of an immutable UserAutomation revision.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserAutomationConfigurationState {
    /// Future occurrences may be admitted after successful preflight.
    Active,
    /// Future occurrences are deferred while admitted execution is preserved.
    Paused,
    /// The revision is retained but its configuration cannot be admitted.
    BlockedConfig,
    /// The revision is tombstoned; history and reconciliation remain visible.
    Retired,
}

/// One-shot versus recurring normalized schedule.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScheduleKind {
    /// Exactly one owner-normalized calendar occurrence.
    OneShot,
    /// A recurring owner-normalized calendar expression.
    Recurring,
}

/// Policy for an ambiguous local-time fold during DST conversion.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DstFoldPolicy {
    /// Choose the first offset in the fold.
    First,
    /// Choose the second offset in the fold.
    Second,
    /// Reject the ambiguous occurrence and block admission.
    Reject,
}

/// Policy for a nonexistent local time during a DST gap.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DstGapPolicy {
    /// Shift to the next valid instant using the owner-normalized rule.
    ShiftForward,
    /// Reject the nonexistent occurrence and block admission.
    Reject,
}

/// Immutable normalized schedule and bounded next-occurrence projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedSchedule {
    /// One-shot or recurring schedule kind.
    pub kind: ScheduleKind,
    /// Owner-normalized expression, never a caller reparse hint.
    pub expression: String,
    /// Owner-normalized calendar identifier.
    pub calendar: String,
    /// IANA or platform owner-normalized timezone identifier.
    pub timezone: String,
    /// Fold handling for ambiguous local times.
    pub dst_fold: DstFoldPolicy,
    /// Gap handling for nonexistent local times.
    pub dst_gap: DstGapPolicy,
    /// Inclusive owner-normalized start instant.
    pub start_at: String,
    /// Optional inclusive owner-normalized end instant.
    pub end_at: Option<String>,
    /// Bounded, sorted, owner-normalized next occurrence keys.
    pub next_occurrences: Vec<String>,
}

impl NormalizedSchedule {
    /// Validates schedule shape without interpreting calendar semantics.
    ///
    /// Shape validation deliberately does not read the calendar: the
    /// owner-normalized occurrence set is the trigger contract, and
    /// [`Self::validate_normalized_occurrences`] performs the deterministic
    /// calendar/timezone/DST interpretation over exactly that set.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.expression, "schedule.expression")?;
        text(&self.calendar, "schedule.calendar")?;
        text(&self.timezone, "schedule.timezone")?;
        text(&self.start_at, "schedule.start_at")?;
        if let Some(end_at) = &self.end_at {
            text(end_at, "schedule.end_at")?;
            if end_at < &self.start_at {
                return Err(UserAutomationError::Invalid("schedule.end_at"));
            }
        }
        if self.next_occurrences.is_empty() {
            return Err(UserAutomationError::Invalid("schedule.next_occurrences"));
        }
        list_text(&self.next_occurrences, "schedule.next_occurrences")?;
        if self
            .next_occurrences
            .windows(2)
            .any(|window| window[0] >= window[1])
        {
            return Err(UserAutomationError::Invalid(
                "schedule.next_occurrences.order",
            ));
        }
        if self.kind == ScheduleKind::OneShot && self.next_occurrences.len() != 1 {
            return Err(UserAutomationError::Invalid(
                "schedule.one_shot_occurrences",
            ));
        }
        Ok(())
    }

    /// Validates the declared timezone identifier without guessing one.
    ///
    /// Only the closed canonical forms are admitted: `UTC`, an `Etc/GMT`
    /// fixed-offset zone, or a canonical `Area/Location` IANA identifier. A
    /// blank, offset-suffixed, or otherwise shaped zone is refused instead of
    /// being resolved to a nearest match, because an ambiguous calendar
    /// phrase is never silently guessed.
    pub fn validate_timezone(&self) -> Result<(), UserAutomationError> {
        let zone = self.timezone.trim();
        if zone != self.timezone || zone.is_empty() {
            return Err(UserAutomationError::Invalid("schedule.timezone"));
        }
        let canonical = zone == "UTC"
            || zone
                .strip_prefix("Etc/GMT")
                .is_some_and(|offset| offset_is_canonical(offset))
            || (zone.split('/').count() == 2
                && zone.split('/').all(|segment| {
                    !segment.is_empty()
                        && segment
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                }));
        if !canonical {
            return Err(UserAutomationError::Invalid("schedule.timezone.canonical"));
        }
        Ok(())
    }

    /// Interprets the owner-normalized occurrence set deterministically.
    ///
    /// Each occurrence key is a canonical local wall clock
    /// (`YYYY-MM-DDTHH:MM:SS`) followed by the exact UTC offset selected by the
    /// declared timezone, so no time-zone database is required and no offset
    /// is inferred. The check enforces the property the declared
    /// [`DstFoldPolicy`]/[`DstGapPolicy`] must leave behind: the normalized set
    /// is unambiguous, that is, at most one member per local wall clock. A set
    /// that still carries an unresolved fold (or gap) member fails closed
    /// instead of being admitted.
    pub fn validate_normalized_occurrences(&self) -> Result<(), UserAutomationError> {
        self.validate()?;
        self.validate_timezone()?;
        let mut wall_clocks = BTreeSet::new();
        for occurrence_key in &self.next_occurrences {
            let wall_clock = occurrence_wall_clock(occurrence_key)?;
            if !wall_clocks.insert(wall_clock) {
                return Err(UserAutomationError::Invalid(
                    "schedule.next_occurrences.dst_ambiguity",
                ));
            }
        }
        Ok(())
    }

    /// Returns whether one calendar occurrence belongs to this revision's
    /// owner-normalized occurrence set.
    ///
    /// An occurrence outside the set is not resolved, shifted, or folded into a
    /// neighbour: the caller fails closed.
    pub fn contains_occurrence(&self, occurrence_key: &str) -> Result<bool, UserAutomationError> {
        occurrence_wall_clock(occurrence_key)?;
        Ok(self
            .next_occurrences
            .iter()
            .any(|key| key == occurrence_key))
    }

    /// Returns the deterministic successor of one normalized occurrence.
    ///
    /// `None` means the occurrence is the last retained member of this
    /// revision's projection; a caller never invents a later occurrence.
    pub fn next_occurrence_after(
        &self,
        occurrence_key: &str,
    ) -> Result<Option<String>, UserAutomationError> {
        occurrence_wall_clock(occurrence_key)?;
        Ok(self
            .next_occurrences
            .iter()
            .skip_while(|key| key.as_str() != occurrence_key)
            .nth(1)
            .cloned())
    }
}

/// Length of the canonical local wall clock prefix `YYYY-MM-DDTHH:MM:SS`.
const OCCURRENCE_WALL_CLOCK_BYTES: usize = 19;

/// Splits one canonical occurrence key into its local wall clock and exact
/// UTC offset, refusing any spelling that is not canonical.
fn occurrence_wall_clock(occurrence_key: &str) -> Result<&str, UserAutomationError> {
    let bytes = occurrence_key.as_bytes();
    if bytes.len() != OCCURRENCE_WALL_CLOCK_BYTES + 1
        && bytes.len() != OCCURRENCE_WALL_CLOCK_BYTES + 6
    {
        return Err(UserAutomationError::Invalid(
            "schedule.occurrence_key.shape",
        ));
    }
    if !bytes[..OCCURRENCE_WALL_CLOCK_BYTES]
        .iter()
        .enumerate()
        .all(|(index, byte)| match index {
            4 | 7 => *byte == b'-',
            10 => *byte == b'T',
            13 | 16 => *byte == b':',
            _ => byte.is_ascii_digit(),
        })
    {
        return Err(UserAutomationError::Invalid(
            "schedule.occurrence_key.wall_clock",
        ));
    }
    let offset = &occurrence_key[OCCURRENCE_WALL_CLOCK_BYTES..];
    if offset != "Z"
        && !(bytes.len() == OCCURRENCE_WALL_CLOCK_BYTES + 6
            && (offset.starts_with('+') || offset.starts_with('-'))
            && offset.as_bytes()[3] == b':'
            && offset[1..3].bytes().all(|byte| byte.is_ascii_digit())
            && offset[4..].bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(UserAutomationError::Invalid(
            "schedule.occurrence_key.offset",
        ));
    }
    Ok(&occurrence_key[..OCCURRENCE_WALL_CLOCK_BYTES])
}

/// Returns whether a canonical `Etc/GMT` offset suffix is well formed.
fn offset_is_canonical(offset: &str) -> bool {
    offset.is_empty()
        || offset
            .strip_prefix('+')
            .or_else(|| offset.strip_prefix('-'))
            .is_some_and(|hours| {
                hours.len() == 1
                    || (hours.len() == 2 && hours.bytes().all(|byte| byte.is_ascii_digit()))
            })
}

/// The exact UserAutomation WorkScope projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationWorkScope {
    /// Canonical scope identity.
    pub scope_id: String,
    /// Product identity bound to the scope.
    pub product_id: String,
    /// Owner-qualified workdir reference.
    pub workdir_ref: String,
}

impl AutomationWorkScope {
    /// Validates the scope projection.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.scope_id, "work_scope.scope_id")?;
        text(&self.product_id, "work_scope.product_id")?;
        text(&self.workdir_ref, "work_scope.workdir_ref")
    }
}

/// Qualified task or script binding.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AutomationTaskKind {
    /// Existing admitted task/model job path.
    AgentTask,
    /// Existing qualified deterministic process path.
    QualifiedScript,
}

/// Capability profile of the qualified task/script.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationCapabilityProfile {
    /// Whether the qualified executable may access a model provider.
    pub model_access: bool,
    /// Whether the qualified executable may access provider credentials/routes.
    pub provider_access: bool,
    /// Whether the qualified executable may create child automation operations.
    pub automation_scheduling: bool,
}

impl AutomationCapabilityProfile {
    /// Validates the capability profile as a shape-only value.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        Ok(())
    }
}

/// Owner-qualified task or script reference and capabilities.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationTaskBinding {
    /// Immutable qualified task/script identity.
    pub qualified_ref: String,
    /// Binding kind used for deterministic-mode checks.
    pub kind: AutomationTaskKind,
    /// Capability profile supplied by the qualified owner.
    pub capability_profile: AutomationCapabilityProfile,
}

impl AutomationTaskBinding {
    /// Validates the task binding.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.qualified_ref, "task.qualified_ref")?;
        self.capability_profile.validate()
    }
}

/// Provider/model/adapter identity observed or admitted by policy.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderFingerprint {
    /// Provider identity.
    pub provider: String,
    /// Model identity.
    pub model: String,
    /// Adapter/runtime identity.
    pub adapter: String,
    /// Owner-issued immutable fingerprint.
    pub fingerprint: String,
}

impl ProviderFingerprint {
    /// Validates the fingerprint identity.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.provider, "provider.provider")?;
        text(&self.model, "provider.model")?;
        text(&self.adapter, "provider.adapter")?;
        text(&self.fingerprint, "provider.fingerprint")
    }
}

/// Provider policy for agent or deterministic execution.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderFingerprintPolicy {
    /// Exact admitted provider/model/adapter set.
    Allowed {
        /// Allowed provider/model/adapter identities.
        fingerprints: Vec<ProviderFingerprint>,
    },
    /// No model/provider access is admitted by this revision.
    DeterministicOnly,
}

impl ProviderFingerprintPolicy {
    /// Validates the policy and rejects duplicate fingerprint identities.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        match self {
            Self::Allowed { fingerprints } => {
                if fingerprints.is_empty() {
                    return Err(UserAutomationError::Invalid("provider_policy.fingerprints"));
                }
                for fingerprint in fingerprints {
                    fingerprint.validate()?;
                }
                if fingerprints.windows(2).any(|window| window[0] == window[1]) {
                    return Err(UserAutomationError::Invalid(
                        "provider_policy.fingerprints.unique",
                    ));
                }
            }
            Self::DeterministicOnly => {}
        }
        Ok(())
    }

    fn admits(&self, observed: Option<&ProviderFingerprint>) -> bool {
        match self {
            Self::Allowed { fingerprints } => {
                observed.is_some_and(|value| fingerprints.contains(value))
            }
            Self::DeterministicOnly => observed.is_none(),
        }
    }
}

/// Route and cost ceiling supplied by the canonical human policy owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteCostPolicy {
    /// Named route policy reference.
    pub route_ref: String,
    /// Maximum admitted cost units.
    pub max_cost_units: u64,
    /// Maximum admitted duration in milliseconds.
    pub max_duration_ms: u64,
    /// Optional policy revision that approved the route ceiling.
    pub policy_revision: Option<PolicyRevision>,
}

impl RouteCostPolicy {
    /// Validates the route and finite resource ceilings.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.route_ref, "route_cost.route_ref")?;
        if self.max_cost_units == 0 {
            return Err(UserAutomationError::Invalid("route_cost.max_cost_units"));
        }
        if self.max_duration_ms == 0 {
            return Err(UserAutomationError::Invalid("route_cost.max_duration_ms"));
        }
        Ok(())
    }
}

/// Delivery target reference and allowed channels.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationDeliveryTarget {
    /// Canonical target identity.
    pub target_ref: String,
    /// Existing notification channels requested by the revision.
    pub channels: Vec<DeliveryChannel>,
    /// Owner-resolved recipient references.
    pub recipient_refs: Vec<String>,
}

impl AutomationDeliveryTarget {
    /// Validates the declared delivery target.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.target_ref, "delivery.target_ref")?;
        if self.channels.is_empty() {
            return Err(UserAutomationError::Invalid("delivery.channels"));
        }
        list_text(&self.recipient_refs, "delivery.recipient_refs")
    }
}

/// Bounded execution/resource policy.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationResourceCeiling {
    /// Maximum runtime in milliseconds.
    pub max_runtime_ms: u64,
    /// Maximum exact deterministic output bytes.
    pub max_output_bytes: u64,
    /// Maximum child depth admitted by this revision.
    pub max_child_count: u32,
}

impl AutomationResourceCeiling {
    /// Validates nonzero resource bounds.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        if self.max_runtime_ms == 0 {
            return Err(UserAutomationError::Invalid("resource.max_runtime_ms"));
        }
        if self.max_output_bytes == 0 {
            return Err(UserAutomationError::Invalid("resource.max_output_bytes"));
        }
        Ok(())
    }
}

/// Policy when one occurrence is already admitted or running.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OverlapPolicy {
    /// Reject the new occurrence before admission.
    ForbidOverlap,
    /// Keep one pending occurrence for the existing owner scheduler.
    QueueOne,
    /// Coalesce the latest wake into the existing owner projection.
    CoalesceLatest,
}

/// Policy controlling child automation scheduling.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecursionPolicy {
    /// Whether an admitted execution may request another automation operation.
    pub allow_child_automation: bool,
    /// Inclusive maximum child depth.
    pub max_child_depth: u16,
}

impl RecursionPolicy {
    /// Validates the bounded child policy.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        if !self.allow_child_automation && self.max_child_depth != 0 {
            return Err(UserAutomationError::Invalid("recursion.max_child_depth"));
        }
        Ok(())
    }
}

/// I14.1 work class selected by the canonical automation owner.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AutomationWorkClass {
    /// Kernel/control operations.
    Control,
    /// Human-interactive work.
    Interactive,
    /// Verification-only work.
    Verification,
    /// Canonical write work.
    CanonicalWrite,
    /// Ordinary background work.
    NormalBackground,
    /// Model-backed work.
    ModelJobs,
    /// Swarm coordination work.
    Swarm,
    /// Reporting work.
    Reporting,
    /// Maintenance work.
    Maintenance,
}

/// Immutable UserAutomation revision owned by Kernel semantics.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationRevision {
    /// Stable automation identity.
    pub automation_id: String,
    /// Immutable revision identity.
    pub revision: String,
    /// Immediately superseded revision, when this is an edit.
    pub supersedes: Option<String>,
    /// Owner principal reference.
    pub owner_principal: String,
    /// Exact UserAutomation WorkScope.
    pub work_scope: AutomationWorkScope,
    /// Original human request kept visible for inspection.
    pub natural_language_intent: String,
    /// Owner-normalized trigger contract.
    pub schedule: NormalizedSchedule,
    /// Agent or deterministic execution mode.
    pub mode: UserAutomationExecutionMode,
    /// Task/script binding and capability profile.
    pub task: AutomationTaskBinding,
    /// Exact trusted Skill package revision references.
    pub portable_skill_package_revision_refs: Vec<String>,
    /// Workdir binding repeated for explicit preflight inspection.
    pub workdir_ref: String,
    /// Route and cost ceiling.
    pub route_cost_policy: RouteCostPolicy,
    /// Provider/model/adapter admission policy.
    pub provider_policy: ProviderFingerprintPolicy,
    /// Delivery target.
    pub delivery_target: AutomationDeliveryTarget,
    /// Versioned deterministic preflight contract.
    pub preflight_contract_revision: String,
    /// Runtime/budget ceilings.
    pub resource_ceiling: AutomationResourceCeiling,
    /// Overlap behavior.
    pub overlap_policy: OverlapPolicy,
    /// Child scheduling behavior.
    pub recursion_policy: RecursionPolicy,
    /// Current configuration state.
    pub configuration_state: UserAutomationConfigurationState,
    /// I14.1 class for the existing Durable Job admission.
    pub work_class: AutomationWorkClass,
    /// Projection references into the existing Durable Job lifecycle.
    pub current_execution_refs: Vec<String>,
    /// Query reference into immutable execution/history records.
    pub execution_history_query_ref: String,
}

impl UserAutomationRevision {
    /// Validates the immutable revision and all nested owner projections.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.automation_id, "automation_id")?;
        text(&self.revision, "revision")?;
        if self.supersedes.as_deref() == Some(self.revision.as_str()) {
            return Err(UserAutomationError::InvalidSupersession);
        }
        text(&self.owner_principal, "owner_principal")?;
        self.work_scope.validate()?;
        text(&self.natural_language_intent, "natural_language_intent")?;
        self.schedule.validate_normalized_occurrences()?;
        self.task.validate()?;
        list_text(
            &self.portable_skill_package_revision_refs,
            "portable_skill_package_revision_refs",
        )?;
        text(&self.workdir_ref, "workdir_ref")?;
        if self.workdir_ref != self.work_scope.workdir_ref {
            return Err(UserAutomationError::Invalid("workdir_ref"));
        }
        self.route_cost_policy.validate()?;
        self.provider_policy.validate()?;
        self.delivery_target.validate()?;
        if self.preflight_contract_revision != USER_AUTOMATION_PREFLIGHT_CONTRACT_REVISION {
            return Err(UserAutomationError::Invalid("preflight_contract_revision"));
        }
        self.resource_ceiling.validate()?;
        self.recursion_policy.validate()?;
        list_text(&self.current_execution_refs, "current_execution_refs")?;
        if self
            .current_execution_refs
            .windows(2)
            .any(|window| window[0] == window[1])
        {
            return Err(UserAutomationError::Invalid(
                "current_execution_refs.unique",
            ));
        }
        text(
            &self.execution_history_query_ref,
            "execution_history_query_ref",
        )?;

        match self.mode {
            UserAutomationExecutionMode::Agent => {
                if self.task.kind != AutomationTaskKind::AgentTask
                    || !matches!(
                        self.provider_policy,
                        ProviderFingerprintPolicy::Allowed { .. }
                    )
                {
                    return Err(UserAutomationError::Invalid("agent_capability_profile"));
                }
            }
            UserAutomationExecutionMode::DeterministicProcess => {
                if self.task.kind != AutomationTaskKind::QualifiedScript
                    || self.task.capability_profile.model_access
                    || self.task.capability_profile.provider_access
                    || self.task.capability_profile.automation_scheduling
                    || !matches!(
                        self.provider_policy,
                        ProviderFingerprintPolicy::DeterministicOnly
                    )
                    || self.work_class == AutomationWorkClass::ModelJobs
                {
                    return Err(UserAutomationError::Invalid(
                        "deterministic_capability_profile",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Derives the immutable canonical digest used by query/read contracts.
    pub fn digest(&self) -> Result<String, UserAutomationError> {
        self.validate()?;
        canonical_digest(self)
    }

    /// Validates that `self` is a new revision immediately superseding `old`.
    pub fn validate_supersedes(
        &self,
        old: &UserAutomationRevision,
    ) -> Result<(), UserAutomationError> {
        self.validate()?;
        old.validate()?;
        if self.automation_id != old.automation_id
            || self.revision == old.revision
            || self.supersedes.as_deref() != Some(old.revision.as_str())
        {
            return Err(UserAutomationError::InvalidSupersession);
        }
        Ok(())
    }

    /// Compiles an inert existing-contract wake intent for one occurrence.
    pub fn compile_wake_intent(
        &self,
        occurrence_id: &str,
        state_fence: StateFence,
    ) -> Result<WakeIntent, UserAutomationError> {
        self.validate()?;
        text(occurrence_id, "occurrence_id")?;
        let wake = WakeIntent {
            wake_id: occurrence_id.to_owned(),
            reason: format!("{WAKE_REASON_PREFIX}:{occurrence_id}"),
            state_fence,
            state: WakeIntentState::Pending,
        };
        wake.validate()
            .map_err(|_| UserAutomationError::Invalid("wake_intent"))?;
        Ok(wake)
    }

    /// Returns the existing Durable Job operation used after admission.
    #[must_use]
    pub const fn durable_job_operation(&self) -> JobOperationKind {
        JobOperationKind::Submit
    }

    /// Compiles one owner-normalized calendar occurrence into the immutable
    /// scheduled trigger of this revision.
    ///
    /// The occurrence must be a member of this revision's normalized set. A
    /// calendar phrase the owner did not normalize is refused here rather than
    /// resolved, shifted, or folded into a neighbouring occurrence, so a
    /// duplicate wake or a restart of a different schedule revision can never
    /// invent a second identity for the same instant.
    pub fn scheduled_trigger(
        &self,
        occurrence_key: &str,
    ) -> Result<UserAutomationTrigger, UserAutomationError> {
        self.validate()?;
        if !self.schedule.contains_occurrence(occurrence_key)? {
            return Err(UserAutomationError::Invalid(
                "schedule.occurrence_key.unnormalized",
            ));
        }
        let trigger = UserAutomationTrigger::Scheduled {
            occurrence_key: occurrence_key.to_owned(),
        };
        trigger.validate()?;
        Ok(trigger)
    }

    /// Builds the revision-bound invocation for one calendar occurrence.
    ///
    /// `ScheduledWake` is the origin for the existing scheduler wake and
    /// `AutomationChild` for an already admitted child. Neither path mints a
    /// principal: the caller supplies the authenticated principal reference and
    /// the owner route revalidates it before any effect.
    pub fn scheduled_invocation(
        &self,
        occurrence_key: &str,
        authenticated_principal: &str,
        trigger_origin: UserAutomationTriggerOrigin,
        child_depth: u16,
    ) -> Result<UserAutomationInvocation, UserAutomationError> {
        text(authenticated_principal, "principal_ref")?;
        let trigger = self.scheduled_trigger(occurrence_key)?;
        let invocation = UserAutomationInvocation {
            automation_id: self.automation_id.clone(),
            automation_revision: self.revision.clone(),
            trigger,
            mode: self.mode,
            principal_ref: authenticated_principal.to_owned(),
            work_scope_ref: self.work_scope.scope_id.clone(),
            workdir_ref: self.workdir_ref.clone(),
            trigger_origin,
            child_depth,
            provenance: None,
        };
        invocation.occurrence_identity_projection()?;
        Ok(invocation)
    }

    /// Builds the explicit manual run-now trigger for one Human-issued nonce.
    ///
    /// A manual nonce never mutates the normalized schedule: the manual
    /// occurrence is a distinct trigger kind, so it receives a distinct stable
    /// identity from any calendar occurrence of the same revision.
    pub fn manual_trigger(
        &self,
        nonce: &str,
    ) -> Result<UserAutomationTrigger, UserAutomationError> {
        self.validate()?;
        text(nonce, "operation.nonce")?;
        let trigger = UserAutomationTrigger::Manual {
            nonce: nonce.to_owned(),
        };
        trigger.validate()?;
        Ok(trigger)
    }

    /// Returns the stable revision-bound occurrence identity for one trigger.
    pub fn occurrence_identity_for(
        &self,
        trigger: &UserAutomationTrigger,
    ) -> Result<String, UserAutomationError> {
        self.validate()?;
        UserAutomationInvocation::occurrence_identity_for(
            &self.automation_id,
            &self.revision,
            trigger,
        )
    }

    /// Compiles the bounded next-occurrence projection of this revision into
    /// immutable revision-bound occurrence identities.
    ///
    /// This is the deterministic schedule compiler surface shown to the Human
    /// before activation and reused by every later admission: the same revision
    /// always produces the same ordered identities, and a duplicate wake or
    /// restart resolves to the identity already present in this list.
    pub fn compile_occurrence_identities(
        &self,
    ) -> Result<Vec<AutomationOccurrenceIdentity>, UserAutomationError> {
        self.validate()?;
        self.schedule.validate_normalized_occurrences()?;
        let mut identities = Vec::with_capacity(self.schedule.next_occurrences.len());
        for occurrence_key in &self.schedule.next_occurrences {
            let trigger = self.scheduled_trigger(occurrence_key)?;
            identities.push(AutomationOccurrenceIdentity {
                automation_id: self.automation_id.clone(),
                revision: self.revision.clone(),
                trigger,
                occurrence_id: self.occurrence_identity_for(&trigger)?,
            });
        }
        Ok(identities)
    }

    /// Returns the deterministic successor occurrence of this revision.
    pub fn next_occurrence_after(
        &self,
        occurrence_key: &str,
    ) -> Result<Option<String>, UserAutomationError> {
        self.validate()?;
        self.schedule.next_occurrence_after(occurrence_key)
    }
}

/// Scheduled calendar occurrence or explicit manual nonce.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum UserAutomationTrigger {
    /// Owner-normalized calendar occurrence key.
    Scheduled {
        /// Exact owner-normalized calendar occurrence.
        occurrence_key: String,
    },
    /// Explicit Human-issued run-now nonce.
    Manual {
        /// Nonce that distinguishes this manual occurrence from the schedule.
        nonce: String,
    },
}

impl UserAutomationTrigger {
    fn validate(&self) -> Result<(), UserAutomationError> {
        match self {
            Self::Scheduled { occurrence_key } => text(occurrence_key, "trigger.occurrence_key"),
            Self::Manual { nonce } => text(nonce, "trigger.nonce"),
        }
    }
}

/// Origin of a UserAutomation invocation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserAutomationTriggerOrigin {
    /// Explicit Human operation.
    Human,
    /// Existing scheduler wake revalidated by Host/Kernel.
    ScheduledWake,
    /// Child request from an already admitted automation.
    AutomationChild,
}

/// Persisted evidence for the request that first admitted this invocation.
///
/// The Store writes this alongside a `RunNow` invocation. It retains the exact
/// task/session metadata, closed operator payload, and canonical write
/// identity that produced the invocation; a later daemon selector cannot
/// replace or manufacture these fields.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationInvocationProvenance {
    /// Authenticated Kernel request context that admitted the operator action.
    pub request_metadata: RequestMetadata,
    /// Closed operation payload that produced this invocation.
    pub source_operation: UserAutomationOperation,
    /// Canonical Store operation identity for the source action.
    pub operation_id: OperationId,
    /// Idempotency identity for the source action.
    pub idempotency_key: String,
    /// Canonical request digest verified by the Store write path.
    pub canonical_request_hash: String,
}

impl UserAutomationInvocationProvenance {
    fn validate_for(
        &self,
        invocation: &UserAutomationInvocation,
        expected_state_fence: &StateFence,
    ) -> Result<(), UserAutomationError> {
        self.request_metadata
            .validate()
            .map_err(|_| UserAutomationError::Invalid("invocation.provenance.request_metadata"))?;
        self.source_operation.validate()?;
        text(
            &self.idempotency_key,
            "invocation.provenance.idempotency_key",
        )?;
        if self.canonical_request_hash.len() != 64
            || !self
                .canonical_request_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(UserAutomationError::Invalid(
                "invocation.provenance.canonical_request_hash",
            ));
        }
        if self.request_metadata.state_fence != *expected_state_fence
            || self.request_metadata.session_id.is_none()
            || self.request_metadata.task_id.is_none()
        {
            return Err(UserAutomationError::ReceiptBinding);
        }

        match (&self.source_operation, &invocation.trigger) {
            (
                UserAutomationOperation::RunNow {
                    automation_id,
                    automation_revision,
                    nonce,
                },
                UserAutomationTrigger::Manual {
                    nonce: invocation_nonce,
                },
            ) if automation_id == &invocation.automation_id
                && automation_revision == &invocation.automation_revision
                && nonce == invocation_nonce
                && invocation.trigger_origin == UserAutomationTriggerOrigin::Human
                && invocation.child_depth == 0 =>
            {
                Ok(())
            }
            _ => Err(UserAutomationError::ReceiptBinding),
        }
    }
}

/// Authenticated invocation selector accepted by the Kernel owner route.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationInvocation {
    /// Stable automation identity.
    pub automation_id: String,
    /// Immutable revision identity.
    pub automation_revision: String,
    /// Scheduled occurrence or explicit manual nonce.
    pub trigger: UserAutomationTrigger,
    /// Mode supplied by the owner route and checked against the revision.
    pub mode: UserAutomationExecutionMode,
    /// Authenticated owner principal reference.
    pub principal_ref: String,
    /// Authenticated WorkScope reference.
    pub work_scope_ref: String,
    /// Authenticated workdir reference.
    pub workdir_ref: String,
    /// Origin of the invocation.
    pub trigger_origin: UserAutomationTriggerOrigin,
    /// Child depth carried by the admitted lineage.
    pub child_depth: u16,
    /// Original owner-admitted request and exact `RunNow` receipt identity.
    /// Older persisted invocations deserialize without provenance but are
    /// rejected by production admission until reconciled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<UserAutomationInvocationProvenance>,
}

impl UserAutomationInvocation {
    /// Validates the typed invocation without reading ambient identity.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.automation_id, "automation_id")?;
        text(&self.automation_revision, "automation_revision")?;
        self.trigger.validate()?;
        text(&self.principal_ref, "principal_ref")?;
        text(&self.work_scope_ref, "work_scope_ref")?;
        text(&self.workdir_ref, "workdir_ref")
    }

    /// Requires task/session and exact `RunNow` receipt provenance at the
    /// production owner-admission boundary.
    pub fn require_run_now_provenance(
        &self,
        expected_state_fence: &StateFence,
    ) -> Result<&UserAutomationInvocationProvenance, UserAutomationError> {
        let provenance = self
            .provenance
            .as_ref()
            .ok_or(UserAutomationError::ReceiptBinding)?;
        provenance.validate_for(self, expected_state_fence)?;
        Ok(provenance)
    }

    /// Returns the stable revision-bound occurrence identity.
    pub fn occurrence_identity(&self) -> Result<String, UserAutomationError> {
        self.validate()?;
        Self::occurrence_identity_for(
            &self.automation_id,
            &self.automation_revision,
            &self.trigger,
        )
    }

    /// Derives the stable occurrence identity from owner-selected immutable
    /// identity and trigger material without constructing an invocation.
    ///
    /// This is a selector operation only. It does not assign a principal,
    /// trigger origin, child depth, mode, or work scope; those fields must be
    /// recovered from the owner-issued persisted invocation before admission.
    pub fn occurrence_identity_for(
        automation_id: &str,
        automation_revision: &str,
        trigger: &UserAutomationTrigger,
    ) -> Result<String, UserAutomationError> {
        text(automation_id, "automation_id")?;
        text(automation_revision, "automation_revision")?;
        trigger.validate()?;
        let bytes = canonical_json_bytes(&(
            OCCURRENCE_IDENTITY_DOMAIN,
            automation_id,
            automation_revision,
            trigger,
        ))
        .map_err(|error| UserAutomationError::Serialization(error.to_string()))?;
        Ok(format!("user-automation-occurrence:{}", sha256_hex(&bytes)))
    }

    /// Returns a typed identity projection for callers that need the inputs.
    pub fn occurrence_identity_projection(
        &self,
    ) -> Result<AutomationOccurrenceIdentity, UserAutomationError> {
        Ok(AutomationOccurrenceIdentity {
            automation_id: self.automation_id.clone(),
            revision: self.automation_revision.clone(),
            trigger: self.trigger.clone(),
            occurrence_id: self.occurrence_identity()?,
        })
    }
}

/// Typed stable identity of one scheduled or manual occurrence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationOccurrenceIdentity {
    /// Automation identity.
    pub automation_id: String,
    /// Immutable revision identity.
    pub revision: String,
    /// Exact trigger material.
    pub trigger: UserAutomationTrigger,
    /// Derived stable identity.
    pub occurrence_id: String,
}

/// Execution projection backed by existing Durable Job history.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationExecutionReference {
    /// Stable occurrence identity.
    pub occurrence_id: String,
    /// Existing Durable Job record reference.
    pub durable_job_ref: String,
    /// Current projected Durable Job state.
    pub state: JobState,
}

impl AutomationExecutionReference {
    /// Validates one execution reference.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.occurrence_id, "execution.occurrence_id")?;
        text(&self.durable_job_ref, "execution.durable_job_ref")
    }
}

/// Existing reconciliation obligation for an uncertain effect.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationReconciliationReference {
    /// Occurrence whose effect remains uncertain.
    pub occurrence_id: String,
    /// Existing ORS/reconciliation operation reference.
    pub operation_ref: String,
}

impl AutomationReconciliationReference {
    /// Validates one reconciliation reference.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.occurrence_id, "reconciliation.occurrence_id")?;
        text(&self.operation_ref, "reconciliation.operation_ref")
    }
}

/// Separate execution/history projection for one immutable revision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationExecutionProjection {
    /// Currently admitted/running Durable Job references.
    pub current_execution_refs: Vec<AutomationExecutionReference>,
    /// Unknown or otherwise unresolved effects requiring reconciliation.
    pub unresolved_reconciliation_refs: Vec<AutomationReconciliationReference>,
    /// Query reference for immutable history.
    pub history_query_ref: String,
}

impl UserAutomationExecutionProjection {
    /// Validates projection shape and retains unknown outcomes as obligations.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        list_len(
            self.current_execution_refs.len(),
            "execution.current_execution_refs",
        )?;
        for execution in &self.current_execution_refs {
            execution.validate()?;
        }
        list_len(
            self.unresolved_reconciliation_refs.len(),
            "execution.unresolved_reconciliation_refs",
        )?;
        for reconciliation in &self.unresolved_reconciliation_refs {
            reconciliation.validate()?;
        }
        text(&self.history_query_ref, "execution.history_query_ref")
    }

    /// Returns whether any admitted execution is still active.
    #[must_use]
    pub fn has_active_execution(&self) -> bool {
        self.current_execution_refs
            .iter()
            .any(|reference| !reference.state.is_terminal())
    }

    /// Returns whether an effect must be reconciled before a new admission.
    #[must_use]
    pub fn requires_reconciliation(&self) -> bool {
        !self.unresolved_reconciliation_refs.is_empty()
            || self
                .current_execution_refs
                .iter()
                .any(|reference| reference.state == JobState::UnknownOutcome)
    }
}

/// A notification recipient projection supplied by the canonical owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationRecipient {
    /// Authenticated recipient principal reference.
    pub principal: PlatformHandle,
    /// Admitted recipient role.
    pub role: AutomationRecipientRole,
}

/// Recipient role projection used by the existing notification adapter.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AutomationRecipientRole {
    /// Requesting Human.
    Requester,
    /// Domain owner.
    DomainOwner,
    /// Architecture owner.
    ArchitectureOwner,
    /// System owner.
    SystemOwner,
    /// WorkScope owner.
    WorkScopeOwner,
    /// Approver.
    Approver,
    /// Recovery principal.
    RecoveryPrincipal,
    /// Explicitly authorized role.
    AuthorizedRole,
}

/// Notification content projected by the UserAutomation owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationFailureNotificationProjection {
    /// Canonical notification draft before revision/fingerprint identity bind.
    pub canonical: NotificationDraft,
    /// Human-facing subject.
    pub subject: String,
    /// Human-facing summary.
    pub summary: String,
    /// Owner-resolved recipients.
    pub recipients: Vec<AutomationRecipient>,
}

impl AutomationFailureNotificationProjection {
    /// Validates notification content without issuing delivery authority.
    pub fn validate(&self, state_fence: &StateFence) -> Result<(), UserAutomationError> {
        self.canonical
            .validate()
            .map_err(|_| UserAutomationError::Invalid("failure.notification.canonical"))?;
        text(&self.subject, "failure.notification.subject")?;
        text(&self.summary, "failure.notification.summary")?;
        if self.canonical.subject != self.subject || self.canonical.summary != self.summary {
            return Err(UserAutomationError::Invalid("failure.notification.summary"));
        }
        if self.canonical.state_fence != *state_fence || self.recipients.is_empty() {
            return Err(UserAutomationError::Invalid("failure.notification.binding"));
        }
        for recipient in &self.recipients {
            text(
                recipient.principal.as_str(),
                "failure.notification.recipient",
            )?;
        }
        Ok(())
    }
}

/// Canonical failure reason emitted by deterministic preflight.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum UserAutomationFailureReason {
    /// The canonical owner marked the revision blocked.
    CanonicalBlockedConfig {
        /// Owner-defined stable failure class.
        class: String,
    },
    /// Provider/model/adapter drift or absence failed closed.
    ProviderFingerprintMismatch,
    /// A deterministic capability attempted model/provider access.
    DeterministicModelAccess,
    /// Trusted Skill package revisions are not exact.
    SkillRevisionMismatch,
    /// Trusted Tool Definitions are not exact.
    ToolDefinitionMismatch,
    /// Delivery capability is unavailable.
    DeliveryUnavailable,
    /// Overlap policy forbids this occurrence.
    OverlapForbidden,
    /// Recursion policy rejects this child invocation.
    RecursionDenied,
    /// An admitted effect is unresolved.
    ReconciliationRequired,
}

impl UserAutomationFailureReason {
    fn validate(&self) -> Result<(), UserAutomationError> {
        if let Self::CanonicalBlockedConfig { class } = self {
            text(class, "failure.reason.class")?;
        }
        Ok(())
    }
}

/// Owner-issued failure fingerprint and notification content.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationFailureProjection {
    /// Deterministic failure-class fingerprint.
    pub failure_fingerprint: String,
    /// Typed reason used to derive the fingerprint.
    pub reason: UserAutomationFailureReason,
    /// Existing notification content passed to the surface adapter.
    pub notification: AutomationFailureNotificationProjection,
}

impl UserAutomationFailureProjection {
    /// Validates owner-issued failure identity and notification shape.
    pub fn validate(
        &self,
        revision: &UserAutomationRevision,
        state_fence: &StateFence,
    ) -> Result<(), UserAutomationError> {
        self.reason.validate()?;
        text(&self.failure_fingerprint, "failure.failure_fingerprint")?;
        let expected = revision.failure_fingerprint(&self.reason)?;
        if expected != self.failure_fingerprint {
            return Err(UserAutomationError::FailureFingerprintMismatch);
        }
        self.notification.validate(state_fence)
    }
}

impl UserAutomationRevision {
    /// Derives one stable class fingerprint from a typed preflight reason.
    pub fn failure_fingerprint(
        &self,
        reason: &UserAutomationFailureReason,
    ) -> Result<String, UserAutomationError> {
        self.validate()?;
        reason.validate()?;
        let bytes = canonical_json_bytes(&(FAILURE_FINGERPRINT_DOMAIN, reason))
            .map_err(|error| UserAutomationError::Serialization(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }
}

/// Deferred admission reason. No admitted execution is cancelled by this value.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserAutomationDeferReason {
    /// Configuration is paused.
    Paused,
    /// Revision is retired and history remains queryable.
    Retired,
    /// One occurrence is already active and queue-one owns the pending wake.
    QueueOne,
    /// The latest wake is coalesced by the existing scheduler projection.
    CoalescedLatest,
    /// The prior effect remains under I14.21 reconciliation.
    ReconciliationRequired,
}

/// Owner-issued preflight receipt bound to one occurrence and config snapshot.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationPreflightReceipt {
    /// Stable automation identity.
    pub automation_id: String,
    /// Immutable revision identity.
    pub automation_revision: String,
    /// Stable scheduled/manual occurrence identity.
    pub occurrence_id: String,
    /// Canonical configuration snapshot identity.
    pub config_snapshot_id: String,
    /// Existing B-owned complete config snapshot observed by this preflight.
    /// The daemon admission gate compares this exact snapshot against the
    /// live policy owner; the id alone is not sufficient.
    pub config_snapshot: ConfigPolicySnapshot,
    /// Configuration state observed by this preflight.
    pub configuration_state: UserAutomationConfigurationState,
    /// I14.1 class for the existing Durable Job path.
    pub work_class: AutomationWorkClass,
    /// Whether a subsequent admitted execution may access a model provider.
    pub model_access_allowed_after_admission: bool,
    /// Existing owner-issued source receipt.
    pub source_receipt: ReceiptEnvelope,
}

/// Deterministic preflight decision. No branch invokes a model or scheduler.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum UserAutomationPreflightDecision {
    /// The occurrence may join the existing Durable Job admission path.
    Admitted {
        /// Receipt for this exact occurrence.
        receipt: UserAutomationPreflightReceipt,
    },
    /// The occurrence remains unadmitted and waits for an existing owner.
    Deferred {
        /// Receipt for this exact occurrence.
        receipt: UserAutomationPreflightReceipt,
        /// Why admission is deferred.
        reason: UserAutomationDeferReason,
    },
    /// Configuration/fingerprint failure is surfaced once by the notification
    /// adapter; no model or task effect has been admitted.
    BlockedConfig {
        /// Receipt for the failed preflight.
        receipt: UserAutomationPreflightReceipt,
        /// Owner-issued failure content and deterministic class identity.
        failure: UserAutomationFailureProjection,
    },
}

/// Authenticated request context used by the pure preflight evaluator.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationPreflightContext {
    /// Full authenticated parent request metadata.
    pub request_metadata: RequestMetadata,
}

/// Owner-issued complete projection consumed by Kernel/Host and notify.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationPreflightProjection {
    /// Stable automation identity repeated for route binding.
    pub automation_id: String,
    /// Immutable revision identity repeated for route binding.
    pub automation_revision: String,
    /// Mode repeated for route binding.
    pub mode: UserAutomationExecutionMode,
    /// Stable occurrence identity.
    pub occurrence_id: String,
    /// Full immutable revision owned by this projection.
    pub revision: UserAutomationRevision,
    /// Live canonical configuration state from the current pointer.
    ///
    /// This may differ from the immutable revision's state after pause,
    /// resume, or retirement. Admission follows this owner readback; the
    /// revision retains the state captured when that immutable document was
    /// created.
    pub configuration_state: UserAutomationConfigurationState,
    /// Existing B-owned complete config snapshot.
    pub config_snapshot: ConfigPolicySnapshot,
    /// Existing owner-issued source verification receipt.
    pub source_receipt: ReceiptEnvelope,
    /// Existing Durable Job/history projection.
    pub execution: UserAutomationExecutionProjection,
    /// Provider identity observed by the owner route, if model access applies.
    pub observed_provider_fingerprint: Option<ProviderFingerprint>,
    /// Exact trusted Skill revisions observed by the owner route.
    pub trusted_skill_package_revision_refs: Vec<String>,
    /// Exact trusted Tool Definition revisions observed by the owner route.
    pub trusted_tool_definition_refs: Vec<String>,
    /// Whether the declared delivery target is currently capable.
    pub delivery_available: bool,
    /// Authenticated trigger origin.
    pub trigger_origin: UserAutomationTriggerOrigin,
    /// Authenticated child depth.
    pub child_depth: u16,
    /// Optional owner-issued blocked failure.
    pub failure: Option<UserAutomationFailureProjection>,
}

impl UserAutomationPreflightProjection {
    /// Runs deterministic preflight against the authenticated parent metadata.
    pub fn preflight(
        &self,
        invocation: &UserAutomationInvocation,
        context: &UserAutomationPreflightContext,
    ) -> Result<UserAutomationPreflightDecision, UserAutomationError> {
        invocation.validate()?;
        self.revision.validate()?;
        self.execution.validate()?;
        if self.execution.history_query_ref != self.revision.execution_history_query_ref {
            return Err(UserAutomationError::Invalid("execution.history_query_ref"));
        }
        let revision_refs = self
            .revision
            .current_execution_refs
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let execution_refs = self
            .execution
            .current_execution_refs
            .iter()
            .map(|reference| reference.durable_job_ref.as_str())
            .collect::<BTreeSet<_>>();
        if revision_refs != execution_refs {
            return Err(UserAutomationError::Invalid(
                "execution.current_execution_refs",
            ));
        }
        if self.automation_id != invocation.automation_id
            || self.automation_revision != invocation.automation_revision
            || self.mode != invocation.mode
            || self.revision.automation_id != self.automation_id
            || self.revision.revision != self.automation_revision
            || self.revision.mode != self.mode
            || self.trigger_origin != invocation.trigger_origin
            || self.child_depth != invocation.child_depth
        {
            return Err(UserAutomationError::RevisionMismatch);
        }
        if invocation.principal_ref != self.revision.owner_principal
            || invocation.work_scope_ref != self.revision.work_scope.scope_id
            || invocation.workdir_ref != self.revision.workdir_ref
        {
            return Err(UserAutomationError::RevisionMismatch);
        }
        if self.occurrence_id != invocation.occurrence_identity()? {
            return Err(UserAutomationError::OccurrenceMismatch);
        }
        self.config_snapshot
            .validate()
            .map_err(|error| UserAutomationError::Config(error.to_string()))?;
        if self.config_snapshot.state_fence != context.request_metadata.state_fence
            || self.config_snapshot.state_fence.policy_revision
                != Some(self.config_snapshot.revision)
        {
            return Err(UserAutomationError::Invalid("config_snapshot.state_fence"));
        }
        self.source_receipt
            .validate()
            .map_err(|error| UserAutomationError::Receipt(error.to_string()))?;
        if self.source_receipt.core.request.metadata != context.request_metadata
            || self.source_receipt.core.request.state_fence != context.request_metadata.state_fence
            || self.source_receipt.core.work_scope.state_fence
                != context.request_metadata.state_fence
            || self.source_receipt.core.work_scope.product_id != context.request_metadata.product_id
        {
            return Err(UserAutomationError::ReceiptBinding);
        }
        list_text(
            &self.trusted_skill_package_revision_refs,
            "trusted_skill_package_revision_refs",
        )?;
        list_text(
            &self.trusted_tool_definition_refs,
            "trusted_tool_definition_refs",
        )?;

        let receipt = self.receipt();
        match self.configuration_state {
            UserAutomationConfigurationState::Paused => {
                self.require_no_failure()?;
                return Ok(UserAutomationPreflightDecision::Deferred {
                    receipt,
                    reason: UserAutomationDeferReason::Paused,
                });
            }
            UserAutomationConfigurationState::Retired => {
                self.require_no_failure()?;
                return Ok(UserAutomationPreflightDecision::Deferred {
                    receipt,
                    reason: UserAutomationDeferReason::Retired,
                });
            }
            UserAutomationConfigurationState::BlockedConfig => {
                let failure = self
                    .failure
                    .as_ref()
                    .ok_or(UserAutomationError::FailureProjectionMissing)?;
                failure.validate(&self.revision, &context.request_metadata.state_fence)?;
                return Ok(UserAutomationPreflightDecision::BlockedConfig {
                    receipt,
                    failure: failure.clone(),
                });
            }
            UserAutomationConfigurationState::Active => {}
        }

        if self.execution.requires_reconciliation() {
            self.require_failure(UserAutomationFailureReason::ReconciliationRequired, context)?;
            return Ok(UserAutomationPreflightDecision::Deferred {
                receipt,
                reason: UserAutomationDeferReason::ReconciliationRequired,
            });
        }
        if !self
            .revision
            .provider_policy
            .admits(self.observed_provider_fingerprint.as_ref())
        {
            return self.blocked(
                UserAutomationFailureReason::ProviderFingerprintMismatch,
                receipt,
                context,
            );
        }
        if self.revision.mode == UserAutomationExecutionMode::DeterministicProcess
            && (self.observed_provider_fingerprint.is_some()
                || self.revision.task.capability_profile.model_access
                || self.revision.task.capability_profile.provider_access)
        {
            return self.blocked(
                UserAutomationFailureReason::DeterministicModelAccess,
                receipt,
                context,
            );
        }
        if self.trusted_skill_package_revision_refs
            != self.revision.portable_skill_package_revision_refs
        {
            return self.blocked(
                UserAutomationFailureReason::SkillRevisionMismatch,
                receipt,
                context,
            );
        }
        if self.trusted_tool_definition_refs.is_empty() {
            return self.blocked(
                UserAutomationFailureReason::ToolDefinitionMismatch,
                receipt,
                context,
            );
        }
        if !self.delivery_available {
            return self.blocked(
                UserAutomationFailureReason::DeliveryUnavailable,
                receipt,
                context,
            );
        }
        if invocation.trigger_origin == UserAutomationTriggerOrigin::AutomationChild
            && (!self.revision.recursion_policy.allow_child_automation
                || invocation.child_depth > self.revision.recursion_policy.max_child_depth
                || !self.revision.task.capability_profile.automation_scheduling)
        {
            return self.blocked(
                UserAutomationFailureReason::RecursionDenied,
                receipt,
                context,
            );
        }
        if self.execution.has_active_execution() {
            match self.revision.overlap_policy {
                OverlapPolicy::ForbidOverlap => {
                    return self.blocked(
                        UserAutomationFailureReason::OverlapForbidden,
                        receipt,
                        context,
                    );
                }
                OverlapPolicy::QueueOne => {
                    self.require_no_failure()?;
                    return Ok(UserAutomationPreflightDecision::Deferred {
                        receipt,
                        reason: UserAutomationDeferReason::QueueOne,
                    });
                }
                OverlapPolicy::CoalesceLatest => {
                    self.require_no_failure()?;
                    return Ok(UserAutomationPreflightDecision::Deferred {
                        receipt,
                        reason: UserAutomationDeferReason::CoalescedLatest,
                    });
                }
            }
        }
        self.require_no_failure()?;
        Ok(UserAutomationPreflightDecision::Admitted { receipt })
    }

    fn receipt(&self) -> UserAutomationPreflightReceipt {
        UserAutomationPreflightReceipt {
            automation_id: self.automation_id.clone(),
            automation_revision: self.automation_revision.clone(),
            occurrence_id: self.occurrence_id.clone(),
            config_snapshot_id: self.config_snapshot.snapshot_id.clone(),
            config_snapshot: self.config_snapshot.clone(),
            configuration_state: self.configuration_state,
            work_class: self.revision.work_class,
            model_access_allowed_after_admission: self.mode == UserAutomationExecutionMode::Agent,
            source_receipt: self.source_receipt.clone(),
        }
    }

    fn require_no_failure(&self) -> Result<(), UserAutomationError> {
        if self.failure.is_some() {
            return Err(UserAutomationError::Invalid(
                "unexpected_failure_projection",
            ));
        }
        Ok(())
    }

    fn require_failure(
        &self,
        reason: UserAutomationFailureReason,
        context: &UserAutomationPreflightContext,
    ) -> Result<(), UserAutomationError> {
        let failure = self
            .failure
            .as_ref()
            .ok_or(UserAutomationError::FailureProjectionMissing)?;
        if failure.reason != reason {
            return Err(UserAutomationError::FailureFingerprintMismatch);
        }
        failure.validate(&self.revision, &context.request_metadata.state_fence)
    }

    fn blocked(
        &self,
        reason: UserAutomationFailureReason,
        receipt: UserAutomationPreflightReceipt,
        context: &UserAutomationPreflightContext,
    ) -> Result<UserAutomationPreflightDecision, UserAutomationError> {
        self.require_failure(reason, context)?;
        let Some(failure) = self.failure.clone() else {
            return Err(UserAutomationError::FailureProjectionMissing);
        };
        Ok(UserAutomationPreflightDecision::BlockedConfig { receipt, failure })
    }
}

/// Query kinds served by the authenticated Kernel/Host owner route.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserAutomationQueryKind {
    /// List current configuration revisions.
    List,
    /// Read current configuration/status projection.
    Status,
    /// Read immutable Durable Job history projection.
    History,
    /// Read the last owner-issued failure projection.
    InspectLastFailure,
    /// Read one deterministic preflight projection.
    Preflight,
}

/// Typed authenticated query contract for Kernel/Host dispatch.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationQuery {
    /// Exact query kind.
    pub kind: UserAutomationQueryKind,
    /// Stable automation identity.
    pub automation_id: String,
    /// Optional immutable revision selector.
    pub automation_revision: Option<String>,
    /// Exact StateFence bound by Kernel/Host authentication.
    pub state_fence: StateFence,
}

impl UserAutomationQuery {
    /// Validates the closed query shape.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.automation_id, "query.automation_id")?;
        if let Some(revision) = &self.automation_revision {
            text(revision, "query.automation_revision")?;
        }
        self.state_fence
            .validate()
            .map_err(|_| UserAutomationError::Invalid("query.state_fence"))
    }
}

/// Closed Human/operator operation vocabulary for the UserAutomation surface.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum UserAutomationOperation {
    /// Create the first immutable revision.
    Create {
        /// Revision to persist through the existing canonical write path.
        revision: UserAutomationRevision,
    },
    /// List visible revisions.
    List {
        /// Whether retired tombstones are included in the read projection.
        include_retired: bool,
    },
    /// Read current status.
    Status {
        /// Stable automation identity.
        automation_id: String,
    },
    /// Read immutable execution/history records.
    History {
        /// Stable automation identity.
        automation_id: String,
    },
    /// Pause future admissions.
    Pause {
        /// Stable automation identity.
        automation_id: String,
        /// Exact revision being paused.
        automation_revision: String,
    },
    /// Resume future admissions using the same immutable revision.
    Resume {
        /// Stable automation identity.
        automation_id: String,
        /// Exact revision being resumed.
        automation_revision: String,
    },
    /// Edit by creating a new immutable superseding revision.
    Edit {
        /// Current revision that must be superseded.
        previous_revision: UserAutomationRevision,
        /// New immutable revision.
        revision: UserAutomationRevision,
    },
    /// Run once using an explicit nonce without mutating the schedule.
    RunNow {
        /// Stable automation identity.
        automation_id: String,
        /// Exact immutable revision to run.
        automation_revision: String,
        /// Explicit Human-issued manual nonce.
        nonce: String,
    },
    /// Retire/tombstone future work while preserving history.
    Remove {
        /// Stable automation identity.
        automation_id: String,
        /// Exact revision being retired.
        automation_revision: String,
    },
    /// Inspect the last owner-issued failure.
    InspectLastFailure {
        /// Stable automation identity.
        automation_id: String,
    },
}

impl UserAutomationOperation {
    /// Validates the closed operator operation and revision lineage.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        match self {
            Self::Create { revision } => revision.validate(),
            Self::List { .. } => Ok(()),
            Self::Status { automation_id }
            | Self::History { automation_id }
            | Self::InspectLastFailure { automation_id } => {
                text(automation_id, "operation.automation_id")
            }
            Self::Pause {
                automation_id,
                automation_revision,
            }
            | Self::Resume {
                automation_id,
                automation_revision,
            }
            | Self::Remove {
                automation_id,
                automation_revision,
            } => {
                text(automation_id, "operation.automation_id")?;
                text(automation_revision, "operation.automation_revision")
            }
            Self::Edit {
                previous_revision,
                revision,
            } => revision.validate_supersedes(previous_revision),
            Self::RunNow {
                automation_id,
                automation_revision,
                nonce,
            } => {
                text(automation_id, "operation.automation_id")?;
                text(automation_revision, "operation.automation_revision")?;
                text(nonce, "operation.nonce")
            }
        }
    }
}

/// Authenticated Human operator intent; the owner service persists it through
/// the existing canonical write/ORS path.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationOperatorIntent {
    /// Stable operation identity supplied by the authenticated surface.
    pub intent_id: String,
    /// Authenticated principal reference.
    pub principal_ref: String,
    /// Exact scope fence used for the operation.
    pub state_fence: StateFence,
    /// Closed operation payload.
    pub operation: UserAutomationOperation,
}

impl UserAutomationOperatorIntent {
    /// Validates the operation shape without issuing authority or writing.
    pub fn validate(&self) -> Result<(), UserAutomationError> {
        text(&self.intent_id, "intent_id")?;
        text(&self.principal_ref, "principal_ref")?;
        self.state_fence
            .validate()
            .map_err(|_| UserAutomationError::Invalid("intent.state_fence"))?;
        self.operation.validate()
    }
}

/// Stable contract identity for the UserAutomation wire boundary.
pub fn user_automation_contract_identity() -> Result<ContractIdentity, UserAutomationError> {
    contract_identity(
        USER_AUTOMATION_CONTRACT_NAME,
        USER_AUTOMATION_CONTRACT_VERSION,
        &serde_json::json!({
            "preflight_selector": USER_AUTOMATION_PREFLIGHT_SELECTOR,
            "preflight_operation": USER_AUTOMATION_PREFLIGHT_OPERATION,
            "wake_contract": "eliot.runtime.wake-intent",
            "durable_job_contract": "eliot.foundation.protocol.durable-job",
            "immutable_revisions": true,
            "unknown_outcome_reconciliation": true,
        }),
    )
    .map_err(|error| UserAutomationError::Serialization(error.to_string()))
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, UserAutomationError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| UserAutomationError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn text(value: &str, field: &'static str) -> Result<(), UserAutomationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(UserAutomationError::Invalid(field));
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(UserAutomationError::LimitExceeded(field));
    }
    Ok(())
}

fn list_text(values: &[String], field: &'static str) -> Result<(), UserAutomationError> {
    list_len(values.len(), field)?;
    for value in values {
        text(value, field)?;
    }
    Ok(())
}

fn list_len(length: usize, field: &'static str) -> Result<(), UserAutomationError> {
    if length > MAX_REFERENCES {
        Err(UserAutomationError::LimitExceeded(field))
    } else {
        Ok(())
    }
}

/// Existing Kernel notification state channel reused by UserAutomation.
pub use crate::module::notification_state::DeliveryChannel;
/// Existing canonical notification draft reused by the surface adapter.
pub use crate::module::notification_state::NotificationDraft;

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, SessionId, SourceId,
    };
    use eliot_security_contracts::PolicyFence;
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn fence() -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch");
        let mut fence = StateFence::new(epoch, eliot_contracts::ResourceGeneration::genesis());
        fence.policy_revision = Some(PolicyRevision::genesis());
        fence
    }

    fn revision(state: UserAutomationConfigurationState) -> UserAutomationRevision {
        UserAutomationRevision {
            automation_id: "automation-1".to_owned(),
            revision: "revision-7".to_owned(),
            supersedes: None,
            owner_principal: "human-1".to_owned(),
            work_scope: AutomationWorkScope {
                scope_id: "scope-1".to_owned(),
                product_id: "eliot-test".to_owned(),
                workdir_ref: "workdir-1".to_owned(),
            },
            natural_language_intent: "run the qualified deterministic check".to_owned(),
            schedule: NormalizedSchedule {
                kind: ScheduleKind::Recurring,
                expression: "at 12:00".to_owned(),
                calendar: "gregorian".to_owned(),
                timezone: "America/New_York".to_owned(),
                dst_fold: DstFoldPolicy::First,
                dst_gap: DstGapPolicy::ShiftForward,
                start_at: "2026-09-21T00:00:00Z".to_owned(),
                end_at: None,
                next_occurrences: vec!["2026-09-21T12:00:00-04:00".to_owned()],
            },
            mode: UserAutomationExecutionMode::DeterministicProcess,
            task: AutomationTaskBinding {
                qualified_ref: "script:checks/v1".to_owned(),
                kind: AutomationTaskKind::QualifiedScript,
                capability_profile: AutomationCapabilityProfile {
                    model_access: false,
                    provider_access: false,
                    automation_scheduling: false,
                },
            },
            portable_skill_package_revision_refs: vec!["skill-package@1".to_owned()],
            workdir_ref: "workdir-1".to_owned(),
            route_cost_policy: RouteCostPolicy {
                route_ref: "deterministic-local".to_owned(),
                max_cost_units: 1,
                max_duration_ms: 1_000,
                policy_revision: Some(PolicyRevision::genesis()),
            },
            provider_policy: ProviderFingerprintPolicy::DeterministicOnly,
            delivery_target: AutomationDeliveryTarget {
                target_ref: "human-1".to_owned(),
                channels: vec![DeliveryChannel::ControlBoard],
                recipient_refs: vec!["human-1".to_owned()],
            },
            preflight_contract_revision: USER_AUTOMATION_PREFLIGHT_CONTRACT_REVISION.to_owned(),
            resource_ceiling: AutomationResourceCeiling {
                max_runtime_ms: 1_000,
                max_output_bytes: 4_096,
                max_child_count: 0,
            },
            overlap_policy: OverlapPolicy::ForbidOverlap,
            recursion_policy: RecursionPolicy {
                allow_child_automation: false,
                max_child_depth: 0,
            },
            configuration_state: state,
            work_class: AutomationWorkClass::Maintenance,
            current_execution_refs: Vec::new(),
            execution_history_query_ref: "history:automation-1".to_owned(),
        }
    }

    fn request_metadata() -> RequestMetadata {
        RequestMetadata {
            request_id: RequestId::new("automation-request").expect("request id"),
            session_id: Some(SessionId::new("session-1").expect("session")),
            task_id: None,
            product_id: ProductId::new("eliot-test").expect("product"),
            source_id: SourceId::new("eliot-user-automation").expect("source"),
            state_fence: fence(),
            clock: ClockReading {
                valid_time_ms: Some(1),
                known_time_ms: Some(1),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
        }
    }

    fn source_receipt(metadata: &RequestMetadata) -> ReceiptEnvelope {
        let core: eliot_receipts::ReceiptCore = serde_json::from_value(serde_json::json!({
            "contract": eliot_receipts::contract_identity().expect("contract"),
            "kind":"VERIFICATION",
            "work_scope": {"scope_id":"scope-1","product_id":"eliot-test","resource_generation":metadata.state_fence.resource_generation,"state_fence":metadata.state_fence},
            "task": null,
            "session": {"session_id":metadata.session_id,"authority_epoch":metadata.state_fence.authority_epoch,"state_fence":metadata.state_fence},
            "causal": {"state_fence":metadata.state_fence,"transaction_sequence":1,"parent_receipt_id":null,"predecessor_receipt_ids":[]},
            "request": {"metadata":metadata,"state_fence":metadata.state_fence},
            "operation": {"operation_id":"operation-g08","request_id":metadata.request_id,"idempotency_key":"source-key","operation_kind":"g08_notification_projection","effect": "READ","state_fence":metadata.state_fence},
            "authority": {"authority_id":"authority-g08","authority_owner":"G-08","authority_epoch":metadata.state_fence.authority_epoch,"state_fence":metadata.state_fence,"allowed_effect":"READ","proof_ceiling":"SCOPED_VERIFICATION"},
            "artifacts": [], "verifier": null, "problem": null, "coordination": null,
            "disposition": {"kind":"SUCCESS","proof":"SCOPED_VERIFICATION"}
        }))
        .expect("receipt core fixture");
        ReceiptEnvelope::issue(core).expect("receipt fixture")
    }

    fn config_snapshot(metadata: &RequestMetadata) -> ConfigPolicySnapshot {
        let state_fence = metadata.state_fence.clone();
        ConfigPolicySnapshot {
            snapshot_id: "snapshot-1".to_owned(),
            machine_id: "machine-1".to_owned(),
            scope_id: USER_AUTOMATION_SCOPE.to_owned(),
            revision: PolicyRevision::genesis(),
            source_completeness: eliot_config::SourceCompleteness::Complete,
            settings: Vec::new(),
            policy_owner: eliot_config::HumanOwner {
                owner_ref: "human-1".to_owned(),
            },
            policy_fence: PolicyFence {
                policy_snapshot_id: "snapshot-1".to_owned(),
                state_fence: state_fence.clone(),
            },
            state_fence,
            parent_snapshot_id: None,
            rollback_of: None,
        }
    }

    fn notification(metadata: &RequestMetadata) -> AutomationFailureNotificationProjection {
        AutomationFailureNotificationProjection {
            canonical: NotificationDraft {
                notification_id: PlatformHandle::new("caller-id").expect("id"),
                severity: crate::NotificationSeverity::ActionRequired,
                subject: "Automation blocked".to_owned(),
                summary: "Configuration requires attention".to_owned(),
                evidence_handles: vec!["preflight-receipt".to_owned()],
                affected_scope: "automation-1".to_owned(),
                owner: "UserAutomation".to_owned(),
                required_action: "Review configuration".to_owned(),
                deadline_or_review: None,
                dedup_key: "caller-key".to_owned(),
                delivery_channels: vec![DeliveryChannel::ControlBoard],
                state_fence: metadata.state_fence.clone(),
            },
            subject: "Automation blocked".to_owned(),
            summary: "Configuration requires attention".to_owned(),
            recipients: vec![AutomationRecipient {
                principal: PlatformHandle::new("human-1").expect("principal"),
                role: AutomationRecipientRole::AuthorizedRole,
            }],
        }
    }

    #[test]
    fn canonical_automation_proof_covers_identity_revision_and_closed_preflight() {
        let metadata = request_metadata();
        let active = revision(UserAutomationConfigurationState::Active);
        active.validate().expect("valid revision");
        let mut edited = active.clone();
        edited.revision = "revision-8".to_owned();
        edited.supersedes = Some(active.revision.clone());
        edited
            .validate_supersedes(&active)
            .expect("valid supersession");

        let invocation = UserAutomationInvocation {
            automation_id: active.automation_id.clone(),
            automation_revision: active.revision.clone(),
            trigger: UserAutomationTrigger::Scheduled {
                occurrence_key: active.schedule.next_occurrences[0].clone(),
            },
            mode: active.mode,
            principal_ref: active.owner_principal.clone(),
            work_scope_ref: active.work_scope.scope_id.clone(),
            workdir_ref: active.workdir_ref.clone(),
            trigger_origin: UserAutomationTriggerOrigin::ScheduledWake,
            child_depth: 0,
            provenance: None,
        };
        let projection = UserAutomationPreflightProjection {
            automation_id: active.automation_id.clone(),
            automation_revision: active.revision.clone(),
            mode: active.mode,
            occurrence_id: invocation.occurrence_identity().expect("occurrence"),
            revision: active,
            configuration_state: UserAutomationConfigurationState::Active,
            config_snapshot: config_snapshot(&metadata),
            source_receipt: source_receipt(&metadata),
            execution: UserAutomationExecutionProjection {
                current_execution_refs: Vec::new(),
                unresolved_reconciliation_refs: Vec::new(),
                history_query_ref: "history:automation-1".to_owned(),
            },
            observed_provider_fingerprint: None,
            trusted_skill_package_revision_refs: vec!["skill-package@1".to_owned()],
            trusted_tool_definition_refs: vec!["tool-def@1".to_owned()],
            delivery_available: true,
            trigger_origin: UserAutomationTriggerOrigin::ScheduledWake,
            child_depth: 0,
            failure: None,
        };
        let decision = projection
            .preflight(
                &invocation,
                &UserAutomationPreflightContext {
                    request_metadata: metadata.clone(),
                },
            )
            .expect("deterministic preflight");
        let UserAutomationPreflightDecision::Admitted { receipt } = decision else {
            panic!("valid deterministic occurrence must be admitted");
        };
        assert!(!receipt.model_access_allowed_after_admission);
        assert!(matches!(
            projection
                .revision
                .compile_wake_intent(&receipt.occurrence_id, metadata.state_fence.clone(),),
            Ok(WakeIntent {
                state: WakeIntentState::Pending,
                ..
            })
        ));

        let mut blocked = projection;
        blocked.configuration_state = UserAutomationConfigurationState::BlockedConfig;
        blocked.revision.configuration_state = UserAutomationConfigurationState::BlockedConfig;
        let reason = UserAutomationFailureReason::CanonicalBlockedConfig {
            class: "provider-fingerprint".to_owned(),
        };
        let failure = UserAutomationFailureProjection {
            failure_fingerprint: blocked
                .revision
                .failure_fingerprint(&reason)
                .expect("fingerprint"),
            reason,
            notification: notification(&metadata),
        };
        blocked.failure = Some(failure);
        assert!(matches!(
            blocked.preflight(
                &invocation,
                &UserAutomationPreflightContext {
                    request_metadata: metadata,
                }
            ),
            Ok(UserAutomationPreflightDecision::BlockedConfig { .. })
        ));
    }

    #[test]
    fn manual_nonce_and_schedule_replay_have_distinct_stable_identities() {
        let base = revision(UserAutomationConfigurationState::Active);
        let common = |trigger| UserAutomationInvocation {
            automation_id: base.automation_id.clone(),
            automation_revision: base.revision.clone(),
            trigger,
            mode: base.mode,
            principal_ref: base.owner_principal.clone(),
            work_scope_ref: base.work_scope.scope_id.clone(),
            workdir_ref: base.workdir_ref.clone(),
            trigger_origin: UserAutomationTriggerOrigin::Human,
            child_depth: 0,
            provenance: None,
        };
        let scheduled = common(UserAutomationTrigger::Scheduled {
            occurrence_key: base.schedule.next_occurrences[0].clone(),
        });
        let replay = scheduled.clone();
        let manual = common(UserAutomationTrigger::Manual {
            nonce: "manual-1".to_owned(),
        });
        assert_eq!(
            scheduled.occurrence_identity(),
            replay.occurrence_identity()
        );
        assert_ne!(
            scheduled.occurrence_identity(),
            manual.occurrence_identity()
        );
    }
}
