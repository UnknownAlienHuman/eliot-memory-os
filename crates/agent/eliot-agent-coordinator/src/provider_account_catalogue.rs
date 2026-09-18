//! Observation-only provider/account catalogue for Swarm route filtering.
//!
//! This module owns one immutable, deterministic catalogue snapshot that binds
//! a provider/account pair to its independently observed readiness axes. It
//! performs no provider call, network I/O, admission, lease, reservation,
//! reroute, or finish decision. Every axis is validated and read on its own
//! evidence: a healthy billing axis never clears a saturated concurrency axis,
//! and stale, conflicted, or unknown evidence is preserved as such — it is
//! never coerced to ready.
//!
//! The stored observations reuse the existing owner types where they exist
//! ([`BillingEvidence`], [`QuotaObservation`], [`RouteHealthStatus`],
//! [`ModelAvailability`], [`RouteFingerprint`]); those types are never
//! redefined here. Their owner validators are private to `model_control`, so
//! this module reapplies the same field rules to the same public values
//! without minting a second definition. The four small axis types below
//! (rate-limit, concurrency, incident, auth) are new because the coordinator
//! has no existing owner for those dimensions (zero-hit at introduction).
//!
//! Credential material never appears here: rows carry an opaque
//! `credential_binding_ref` string only, never secret bytes, and diagnostics
//! carry row/binding identifiers rather than account or credential values.

use std::collections::BTreeSet;

use eliot_agent_api::RouteFingerprint;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model_control::{
    BillingEvidence, ModelAvailability, QuotaObservation, RouteHealthStatus,
    ZeroModelExecutionCounters,
};

/// Stable schema identity for the provider/account catalogue snapshot.
pub const PROVIDER_ACCOUNT_CATALOGUE_SCHEMA_VERSION: &str =
    "eliot.agent-provider-account-catalogue/v1";

const MAX_PROVIDER_ACCOUNT_ROWS: usize = 4096;
const MAX_INVALIDATION_REFS: usize = 256;

/// Fail-closed catalogue errors. Every production path returns these instead
/// of panicking; a malformed row or snapshot is rejected, never repaired.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderAccountCatalogueError {
    #[error("invalid provider-account catalogue field: {0}")]
    InvalidField(&'static str),
    #[error("unsupported provider-account catalogue schema: {0}")]
    UnsupportedSchema(&'static str),
    #[error("duplicate provider-account catalogue identity: {0}")]
    DuplicateIdentity(&'static str),
    #[error("provider-account snapshot identity conflict: same id with changed bytes")]
    IdentityConflict,
    #[error("canonical serialization failed: {0}")]
    Serialization(String),
}

fn validate_text(value: &str, field: &'static str) -> Result<(), ProviderAccountCatalogueError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ProviderAccountCatalogueError::InvalidField(field));
    }
    Ok(())
}

fn validate_window(
    observed_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    field: &'static str,
) -> Result<(), ProviderAccountCatalogueError> {
    if observed_at_unix_ms == 0 || expires_at_unix_ms < observed_at_unix_ms {
        return Err(ProviderAccountCatalogueError::InvalidField(field));
    }
    Ok(())
}

fn validate_unique_texts(
    values: &[String],
    field: &'static str,
) -> Result<(), ProviderAccountCatalogueError> {
    if values.len() > MAX_INVALIDATION_REFS {
        return Err(ProviderAccountCatalogueError::InvalidField(field));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_text(value, field)?;
        if !seen.insert(value) {
            return Err(ProviderAccountCatalogueError::DuplicateIdentity(field));
        }
    }
    Ok(())
}

fn validate_canonical_digest(
    value: &str,
    field: &'static str,
) -> Result<(), ProviderAccountCatalogueError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(ProviderAccountCatalogueError::InvalidField(field));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ProviderAccountCatalogueError::InvalidField(field));
    }
    Ok(())
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, ProviderAccountCatalogueError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ProviderAccountCatalogueError::Serialization(error.to_string()))?;
    Ok(format!("sha256:{}", eliot_receipts::sha256_hex(&bytes)))
}

/// Reapplies the catalogue owner's billing field rules to the reused stored
/// observation. The type itself stays owned by `model_control`.
fn validate_reused_billing(billing: &BillingEvidence) -> Result<(), ProviderAccountCatalogueError> {
    validate_text(&billing.source, "provider_account.billing.source")?;
    validate_text(&billing.receipt_ref, "provider_account.billing.receipt_ref")?;
    validate_window(
        billing.observed_at_unix_ms,
        billing.expires_at_unix_ms,
        "provider_account.billing.window",
    )
}

/// Reapplies the catalogue owner's quota field rules to the reused stored
/// observation. The type itself stays owned by `model_control`.
fn validate_reused_quota(quota: &QuotaObservation) -> Result<(), ProviderAccountCatalogueError> {
    validate_text(&quota.source, "provider_account.quota.source")?;
    validate_text(&quota.receipt_ref, "provider_account.quota.receipt_ref")?;
    validate_window(
        quota.observed_at_unix_ms,
        quota.expires_at_unix_ms,
        "provider_account.quota.window",
    )?;
    if quota
        .reset_at_unix_ms
        .is_some_and(|reset| reset < quota.observed_at_unix_ms)
    {
        return Err(ProviderAccountCatalogueError::InvalidField(
            "provider_account.quota.reset_at_unix_ms",
        ));
    }
    Ok(())
}

/// Observed rate-limit state for one provider/account pair.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RateLimitDisposition {
    Ready,
    Limited,
    Unknown,
}

/// Rate-limit window/backoff observation. A stale window reads as
/// [`RateLimitDisposition::Unknown`], never as ready.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitObservation {
    pub disposition: RateLimitDisposition,
    pub source: String,
    pub receipt_ref: String,
    pub observed_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub retry_after_unix_ms: Option<u64>,
    pub window_reset_unix_ms: Option<u64>,
}

impl RateLimitObservation {
    fn validate(&self) -> Result<(), ProviderAccountCatalogueError> {
        validate_text(&self.source, "provider_account.rate_limit.source")?;
        validate_text(&self.receipt_ref, "provider_account.rate_limit.receipt_ref")?;
        validate_window(
            self.observed_at_unix_ms,
            self.expires_at_unix_ms,
            "provider_account.rate_limit.window",
        )?;
        for (bound, field) in [
            (
                self.retry_after_unix_ms,
                "provider_account.rate_limit.retry_after_unix_ms",
            ),
            (
                self.window_reset_unix_ms,
                "provider_account.rate_limit.window_reset_unix_ms",
            ),
        ] {
            if bound.is_some_and(|value| value < self.observed_at_unix_ms) {
                return Err(ProviderAccountCatalogueError::InvalidField(field));
            }
        }
        Ok(())
    }

    pub(crate) const fn is_current(&self, now_unix_ms: u64) -> bool {
        now_unix_ms >= self.observed_at_unix_ms && now_unix_ms <= self.expires_at_unix_ms
    }

    pub(crate) const fn effective(&self, now_unix_ms: u64) -> RateLimitDisposition {
        if !self.is_current(now_unix_ms) {
            return RateLimitDisposition::Unknown;
        }
        self.disposition
    }
}

/// Observed concurrency state for one provider/account pair.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConcurrencyDisposition {
    Available,
    Saturated,
    Unknown,
}

/// Concurrency observation. A stale window reads as
/// [`ConcurrencyDisposition::Unknown`], never as available.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConcurrencyObservation {
    pub disposition: ConcurrencyDisposition,
    pub source: String,
    pub receipt_ref: String,
    pub observed_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub in_flight: Option<u64>,
    pub limit: Option<u64>,
}

impl ConcurrencyObservation {
    fn validate(&self) -> Result<(), ProviderAccountCatalogueError> {
        validate_text(&self.source, "provider_account.concurrency.source")?;
        validate_text(
            &self.receipt_ref,
            "provider_account.concurrency.receipt_ref",
        )?;
        validate_window(
            self.observed_at_unix_ms,
            self.expires_at_unix_ms,
            "provider_account.concurrency.window",
        )?;
        if self
            .in_flight
            .zip(self.limit)
            .is_some_and(|(in_flight, limit)| in_flight > limit)
        {
            return Err(ProviderAccountCatalogueError::InvalidField(
                "provider_account.concurrency.bound",
            ));
        }
        Ok(())
    }

    pub(crate) const fn is_current(&self, now_unix_ms: u64) -> bool {
        now_unix_ms >= self.observed_at_unix_ms && now_unix_ms <= self.expires_at_unix_ms
    }

    pub(crate) const fn effective(&self, now_unix_ms: u64) -> ConcurrencyDisposition {
        if !self.is_current(now_unix_ms) {
            return ConcurrencyDisposition::Unknown;
        }
        self.disposition
    }
}

/// Observed incident state for one provider/account pair.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IncidentDisposition {
    None,
    Degraded,
    Outage,
    Unknown,
}

/// Incident observation. The optional `incident_ref` is an opaque owner-issued
/// reference, never incident payload bytes. A stale window reads as
/// [`IncidentDisposition::Unknown`], never as no-incident.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentObservation {
    pub disposition: IncidentDisposition,
    pub source: String,
    pub receipt_ref: String,
    pub observed_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub incident_ref: Option<String>,
}

impl IncidentObservation {
    fn validate(&self) -> Result<(), ProviderAccountCatalogueError> {
        validate_text(&self.source, "provider_account.incident.source")?;
        validate_text(&self.receipt_ref, "provider_account.incident.receipt_ref")?;
        validate_window(
            self.observed_at_unix_ms,
            self.expires_at_unix_ms,
            "provider_account.incident.window",
        )?;
        match (&self.disposition, &self.incident_ref) {
            (IncidentDisposition::Degraded | IncidentDisposition::Outage, Some(reference)) => {
                validate_text(reference, "provider_account.incident.incident_ref")?;
                Ok(())
            }
            (IncidentDisposition::None | IncidentDisposition::Unknown, None) => Ok(()),
            (IncidentDisposition::Degraded | IncidentDisposition::Outage, None)
            | (IncidentDisposition::None | IncidentDisposition::Unknown, Some(_)) => {
                Err(ProviderAccountCatalogueError::InvalidField(
                    "provider_account.incident.incident_ref",
                ))
            }
        }
    }

    pub(crate) const fn is_current(&self, now_unix_ms: u64) -> bool {
        now_unix_ms >= self.observed_at_unix_ms && now_unix_ms <= self.expires_at_unix_ms
    }

    pub(crate) const fn effective(&self, now_unix_ms: u64) -> IncidentDisposition {
        if !self.is_current(now_unix_ms) {
            return IncidentDisposition::Unknown;
        }
        self.disposition
    }
}

/// Observed credential-binding state for one provider/account pair. The row
/// carries the binding reference only; this axis records whether that binding
/// is currently usable. `Conflicted` marks contradictory binding evidence and
/// is preserved even when every other axis is current.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthDisposition {
    Bound,
    Expired,
    Revoked,
    Unknown,
    Conflicted,
}

/// Auth observation. A stale window reads as [`AuthDisposition::Unknown`],
/// never as bound.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthObservation {
    pub disposition: AuthDisposition,
    pub source: String,
    pub receipt_ref: String,
    pub observed_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

impl AuthObservation {
    fn validate(&self) -> Result<(), ProviderAccountCatalogueError> {
        validate_text(&self.source, "provider_account.auth.source")?;
        validate_text(&self.receipt_ref, "provider_account.auth.receipt_ref")?;
        validate_window(
            self.observed_at_unix_ms,
            self.expires_at_unix_ms,
            "provider_account.auth.window",
        )
    }

    pub(crate) const fn is_current(&self, now_unix_ms: u64) -> bool {
        now_unix_ms >= self.observed_at_unix_ms && now_unix_ms <= self.expires_at_unix_ms
    }

    pub(crate) const fn effective(&self, now_unix_ms: u64) -> AuthDisposition {
        if !self.is_current(now_unix_ms) {
            return AuthDisposition::Unknown;
        }
        self.disposition
    }
}

/// Computed row readiness. This is a live view over the stored axes, not wire
/// evidence, so it is serialized for diagnostics but never deserialized as
/// proof. Precedence is fixed and documented: `Stale` outranks `Conflicted`
/// (expired evidence cannot sustain a contradiction claim), which outranks
/// `Unknown`, which outranks `NotReady`. Only every axis current-positive at
/// once yields `Ready`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "status")]
pub enum ProviderAccountReadiness {
    Ready,
    NotReady { reasons: Vec<String> },
    Stale { reasons: Vec<String> },
    Conflicted { reasons: Vec<String> },
    Unknown { reasons: Vec<String> },
}

impl ProviderAccountReadiness {
    /// Deterministic rank used as the final registry tie-break. Lower sorts
    /// first; only `Ready` rows can dispatch.
    #[must_use]
    pub const fn rank(&self) -> u8 {
        match self {
            Self::Ready => 0,
            Self::NotReady { .. } => 1,
            Self::Unknown { .. } => 2,
            Self::Stale { .. } => 3,
            Self::Conflicted { .. } => 4,
        }
    }

    #[must_use]
    pub const fn ready(&self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// One observed provider/account row. Every axis is validated by its own
/// validator; validation never infers one axis from another, so a passing
/// billing axis cannot mask a failing quota axis.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAccountRow {
    pub row_id: String,
    pub provider_id: String,
    /// Opaque account reference issued by the collector. Never secret bytes.
    pub account_ref: String,
    /// Opaque credential-binding reference issued by the collector. A string
    /// reference only — never token, cookie, or payload bytes.
    pub credential_binding_ref: String,
    pub adapter: String,
    pub artifact_generation: String,
    pub protocol_generation: String,
    /// Field-complete route identity, reused from the owning contract. A
    /// change to any behavior-bearing field is a different row binding.
    pub route: RouteFingerprint,
    pub route_revision: String,
    pub model_revision: String,
    pub billing: BillingEvidence,
    pub quota: QuotaObservation,
    pub route_health: RouteHealthStatus,
    pub availability: ModelAvailability,
    pub rate_limit: RateLimitObservation,
    pub concurrency: ConcurrencyObservation,
    pub incident: IncidentObservation,
    pub auth: AuthObservation,
    pub source: String,
    pub receipt_ref: String,
    pub observed_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    /// Owner-issued invalidation references. A non-empty set marks the row
    /// conflicted; invalidation never deletes or rewrites axis evidence.
    pub invalidation: Vec<String>,
}

impl ProviderAccountRow {
    pub fn validate(&self) -> Result<(), ProviderAccountCatalogueError> {
        for (value, field) in [
            (self.row_id.as_str(), "provider_account.row_id"),
            (self.provider_id.as_str(), "provider_account.provider_id"),
            (self.account_ref.as_str(), "provider_account.account_ref"),
            (
                self.credential_binding_ref.as_str(),
                "provider_account.credential_binding_ref",
            ),
            (self.adapter.as_str(), "provider_account.adapter"),
            (
                self.artifact_generation.as_str(),
                "provider_account.artifact_generation",
            ),
            (
                self.protocol_generation.as_str(),
                "provider_account.protocol_generation",
            ),
            (
                self.route_revision.as_str(),
                "provider_account.route_revision",
            ),
            (
                self.model_revision.as_str(),
                "provider_account.model_revision",
            ),
            (self.source.as_str(), "provider_account.source"),
            (self.receipt_ref.as_str(), "provider_account.receipt_ref"),
        ] {
            validate_text(value, field)?;
        }
        if self.provider_id != self.route.provider {
            return Err(ProviderAccountCatalogueError::InvalidField(
                "provider_account.route_binding",
            ));
        }
        self.route
            .validate()
            .map_err(|_| ProviderAccountCatalogueError::InvalidField("provider_account.route"))?;
        validate_window(
            self.observed_at_unix_ms,
            self.expires_at_unix_ms,
            "provider_account.window",
        )?;
        // Each axis validates on its own evidence only. No check below reads
        // another axis, so axes stay independent by construction.
        validate_reused_billing(&self.billing)?;
        validate_reused_quota(&self.quota)?;
        self.rate_limit.validate()?;
        self.concurrency.validate()?;
        self.incident.validate()?;
        self.auth.validate()?;
        validate_unique_texts(&self.invalidation, "provider_account.invalidation")?;
        Ok(())
    }

    #[must_use]
    pub const fn is_current(&self, now_unix_ms: u64) -> bool {
        now_unix_ms >= self.observed_at_unix_ms && now_unix_ms <= self.expires_at_unix_ms
    }

    fn stale_reasons(&self, now_unix_ms: u64) -> Vec<String> {
        let mut stale = Vec::new();
        if !self.is_current(now_unix_ms) {
            stale.push("provider_account:row_evidence_stale".to_owned());
        }
        if !self.billing.is_current(now_unix_ms) {
            stale.push("provider_account:billing_evidence_stale".to_owned());
        }
        if !self.quota.is_current(now_unix_ms) {
            stale.push("provider_account:quota_evidence_stale".to_owned());
        }
        if !self.rate_limit.is_current(now_unix_ms) {
            stale.push("provider_account:rate_limit_evidence_stale".to_owned());
        }
        if !self.concurrency.is_current(now_unix_ms) {
            stale.push("provider_account:concurrency_evidence_stale".to_owned());
        }
        if !self.incident.is_current(now_unix_ms) {
            stale.push("provider_account:incident_evidence_stale".to_owned());
        }
        if !self.auth.is_current(now_unix_ms) {
            stale.push("provider_account:auth_evidence_stale".to_owned());
        }
        stale
    }

    /// Computes row readiness without coercion: stale, conflicted, and unknown
    /// evidence each surface under their own status with per-axis reasons.
    #[must_use]
    pub fn readiness(&self, now_unix_ms: u64) -> ProviderAccountReadiness {
        let stale = self.stale_reasons(now_unix_ms);
        if !stale.is_empty() {
            return ProviderAccountReadiness::Stale { reasons: stale };
        }

        let mut conflicted = Vec::new();
        if self.auth.effective(now_unix_ms) == AuthDisposition::Conflicted {
            conflicted.push("provider_account:auth_conflicted".to_owned());
        }
        if !self.invalidation.is_empty() {
            conflicted.push("provider_account:row_invalidated".to_owned());
        }
        if !conflicted.is_empty() {
            return ProviderAccountReadiness::Conflicted {
                reasons: conflicted,
            };
        }

        let mut unknown = Vec::new();
        if matches!(
            self.billing.class,
            crate::model_control::BillingClass::Unknown
        ) {
            unknown.push("provider_account:billing_unknown".to_owned());
        }
        if matches!(
            self.quota.disposition,
            crate::model_control::QuotaDisposition::Unknown
                | crate::model_control::QuotaDisposition::NotExposed
        ) {
            unknown.push("provider_account:quota_unknown".to_owned());
        }
        if self.route_health == RouteHealthStatus::Unknown {
            unknown.push("provider_account:route_health_unknown".to_owned());
        }
        if self.availability == ModelAvailability::Unknown {
            unknown.push("provider_account:availability_unknown".to_owned());
        }
        if self.rate_limit.effective(now_unix_ms) == RateLimitDisposition::Unknown {
            unknown.push("provider_account:rate_limit_unknown".to_owned());
        }
        if self.concurrency.effective(now_unix_ms) == ConcurrencyDisposition::Unknown {
            unknown.push("provider_account:concurrency_unknown".to_owned());
        }
        if self.incident.effective(now_unix_ms) == IncidentDisposition::Unknown {
            unknown.push("provider_account:incident_unknown".to_owned());
        }
        if self.auth.effective(now_unix_ms) == AuthDisposition::Unknown {
            unknown.push("provider_account:auth_unknown".to_owned());
        }
        if !unknown.is_empty() {
            return ProviderAccountReadiness::Unknown { reasons: unknown };
        }

        let mut blocked = Vec::new();
        if self.quota.disposition == crate::model_control::QuotaDisposition::Exhausted {
            blocked.push("provider_account:quota_exhausted".to_owned());
        }
        if self.route_health != RouteHealthStatus::Healthy {
            blocked.push("provider_account:route_not_healthy".to_owned());
        }
        if self.availability != ModelAvailability::Available {
            blocked.push("provider_account:model_not_available".to_owned());
        }
        if self.rate_limit.effective(now_unix_ms) == RateLimitDisposition::Limited {
            blocked.push("provider_account:rate_limited".to_owned());
        }
        if self.concurrency.effective(now_unix_ms) == ConcurrencyDisposition::Saturated {
            blocked.push("provider_account:concurrency_saturated".to_owned());
        }
        if matches!(
            self.incident.effective(now_unix_ms),
            IncidentDisposition::Degraded | IncidentDisposition::Outage
        ) {
            blocked.push("provider_account:incident_active".to_owned());
        }
        if matches!(
            self.auth.effective(now_unix_ms),
            AuthDisposition::Expired | AuthDisposition::Revoked
        ) {
            blocked.push("provider_account:auth_not_bound".to_owned());
        }
        if blocked.is_empty() {
            ProviderAccountReadiness::Ready
        } else {
            ProviderAccountReadiness::NotReady { reasons: blocked }
        }
    }
}

/// Deterministic join key for one row: provider plus field-complete route.
fn row_join_key(
    row: &ProviderAccountRow,
) -> Result<(String, String), ProviderAccountCatalogueError> {
    let route_key = row
        .route
        .canonical_json()
        .map_err(|error| ProviderAccountCatalogueError::Serialization(error.to_string()))?;
    Ok((row.provider_id.clone(), route_key))
}

/// Immutable catalogue snapshot. Replaying exact canonical bytes returns the
/// same snapshot; reusing the snapshot id with changed bytes is a conflict.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAccountCatalogueSnapshot {
    pub schema_version: String,
    pub snapshot_id: String,
    pub account_scope: String,
    pub collector_identity: String,
    pub observed_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub rows: Vec<ProviderAccountRow>,
    pub invalidation: Vec<String>,
    pub canonical_digest: String,
}

impl ProviderAccountCatalogueSnapshot {
    pub fn validate(&self) -> Result<(), ProviderAccountCatalogueError> {
        if self.schema_version != PROVIDER_ACCOUNT_CATALOGUE_SCHEMA_VERSION {
            return Err(ProviderAccountCatalogueError::UnsupportedSchema(
                "provider_account_catalogue",
            ));
        }
        validate_text(&self.snapshot_id, "provider_account_catalogue.snapshot_id")?;
        validate_text(
            &self.account_scope,
            "provider_account_catalogue.account_scope",
        )?;
        validate_text(
            &self.collector_identity,
            "provider_account_catalogue.collector_identity",
        )?;
        validate_window(
            self.observed_at_unix_ms,
            self.expires_at_unix_ms,
            "provider_account_catalogue.window",
        )?;
        if self.rows.len() > MAX_PROVIDER_ACCOUNT_ROWS {
            return Err(ProviderAccountCatalogueError::InvalidField(
                "provider_account_catalogue.rows",
            ));
        }
        validate_unique_texts(
            &self.invalidation,
            "provider_account_catalogue.invalidation",
        )?;
        let mut row_ids = BTreeSet::new();
        let mut join_keys = BTreeSet::new();
        for row in &self.rows {
            row.validate()?;
            if !row_ids.insert(row.row_id.as_str()) {
                return Err(ProviderAccountCatalogueError::DuplicateIdentity(
                    "provider_account_catalogue.row_id",
                ));
            }
            if !join_keys.insert(row_join_key(row)?) {
                return Err(ProviderAccountCatalogueError::DuplicateIdentity(
                    "provider_account_catalogue.route",
                ));
            }
        }
        validate_canonical_digest(
            &self.canonical_digest,
            "provider_account_catalogue.canonical_digest",
        )?;
        if self.canonical_digest != snapshot_digest(self)? {
            return Err(ProviderAccountCatalogueError::InvalidField(
                "provider_account_catalogue.canonical_digest",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub const fn is_current(&self, now_unix_ms: u64) -> bool {
        now_unix_ms >= self.observed_at_unix_ms && now_unix_ms <= self.expires_at_unix_ms
    }

    /// Finds the single row bound to one provider/route pair. The snapshot
    /// rejects duplicate bindings at validation, so the join stays total.
    #[must_use]
    pub fn find_row(
        &self,
        provider_id: &str,
        route: &RouteFingerprint,
    ) -> Option<&ProviderAccountRow> {
        let route_key = route.canonical_json().ok()?;
        self.rows.iter().find(|row| {
            row.provider_id == provider_id
                && row
                    .route
                    .canonical_json()
                    .is_ok_and(|candidate| candidate == route_key)
        })
    }

    /// Exact-replay/conflict rule: identical canonical bytes replay, a reused
    /// snapshot id with changed bytes conflicts, and a different snapshot id
    /// is a new snapshot rather than a replay.
    pub fn replay_disposition(
        &self,
        previous: &Self,
    ) -> Result<ReplayDisposition, ProviderAccountCatalogueError> {
        self.validate()?;
        previous.validate()?;
        if self.snapshot_id != previous.snapshot_id {
            return Ok(ReplayDisposition::NewSnapshot);
        }
        if self.canonical_digest == previous.canonical_digest {
            Ok(ReplayDisposition::ExactReplay)
        } else {
            Err(ProviderAccountCatalogueError::IdentityConflict)
        }
    }
}

/// Outcome of [`ProviderAccountCatalogueSnapshot::replay_disposition`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReplayDisposition {
    ExactReplay,
    NewSnapshot,
}

fn snapshot_digest(
    snapshot: &ProviderAccountCatalogueSnapshot,
) -> Result<String, ProviderAccountCatalogueError> {
    let mut keyed = Vec::with_capacity(snapshot.rows.len());
    for row in &snapshot.rows {
        let route_key = row
            .route
            .canonical_json()
            .map_err(|error| ProviderAccountCatalogueError::Serialization(error.to_string()))?;
        keyed.push((
            row.provider_id.clone(),
            route_key,
            row.row_id.clone(),
            row.clone(),
        ));
    }
    keyed.sort_by(|left, right| (&left.0, &left.1, &left.2).cmp(&(&right.0, &right.1, &right.2)));
    let mut normalized = snapshot.clone();
    normalized.rows = keyed
        .into_iter()
        .map(|(_, _, _, row)| row)
        .collect::<Vec<_>>();
    normalized.canonical_digest.clear();
    canonical_digest(&normalized)
}

/// Builds a snapshot, computing its deterministic digest. Rows are stored in
/// the supplied order; the digest normalizes row order first.
pub fn build_snapshot(
    snapshot_id: impl Into<String>,
    account_scope: impl Into<String>,
    collector_identity: impl Into<String>,
    observed_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    rows: Vec<ProviderAccountRow>,
    invalidation: Vec<String>,
) -> Result<ProviderAccountCatalogueSnapshot, ProviderAccountCatalogueError> {
    let mut snapshot = ProviderAccountCatalogueSnapshot {
        schema_version: PROVIDER_ACCOUNT_CATALOGUE_SCHEMA_VERSION.to_owned(),
        snapshot_id: snapshot_id.into(),
        account_scope: account_scope.into(),
        collector_identity: collector_identity.into(),
        observed_at_unix_ms,
        expires_at_unix_ms,
        rows,
        invalidation,
        canonical_digest: String::new(),
    };
    // The digest binds the exact normalized bytes; structural validation
    // then proves the bound value instead of trusting a caller copy.
    snapshot.canonical_digest = snapshot_digest(&snapshot)?;
    snapshot.validate()?;
    Ok(snapshot)
}

/// Candidate-only operator commands over the catalogue. Validation only:
/// commands carry references and request identity, perform no provider call,
/// launch nothing, cancel nothing, and grant no dispatch authority. Execution
/// is always zero and `dispatch_authority` is always false.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum ProviderAccountCommand {
    RequestCatalogueRefresh {
        account_scope: String,
        reason: String,
    },
    UpdatePreference {
        account_scope: String,
        preference_policy_id: String,
        expected_revision: String,
    },
    RequestSwarmLaunch {
        task_id: String,
        plan_revision: String,
        account_scope: String,
    },
    CancelAttempt {
        attempt_ref: String,
        reason: String,
    },
    BoundedMonitor {
        watch_id: String,
        account_scope: String,
        bound_unix_ms: u64,
        reason: String,
    },
}

impl ProviderAccountCommand {
    pub fn validate(&self) -> Result<(), ProviderAccountCatalogueError> {
        match self {
            Self::RequestCatalogueRefresh {
                account_scope,
                reason,
            } => {
                validate_text(account_scope, "command.account_scope")?;
                validate_text(reason, "command.reason")
            }
            Self::UpdatePreference {
                account_scope,
                preference_policy_id,
                expected_revision,
            } => {
                validate_text(account_scope, "command.account_scope")?;
                validate_text(preference_policy_id, "command.preference_policy_id")?;
                validate_text(expected_revision, "command.expected_revision")
            }
            Self::RequestSwarmLaunch {
                task_id,
                plan_revision,
                account_scope,
            } => {
                validate_text(task_id, "command.task_id")?;
                validate_text(plan_revision, "command.plan_revision")?;
                validate_text(account_scope, "command.account_scope")
            }
            Self::CancelAttempt {
                attempt_ref,
                reason,
            } => {
                validate_text(attempt_ref, "command.attempt_ref")?;
                validate_text(reason, "command.reason")
            }
            Self::BoundedMonitor {
                watch_id,
                account_scope,
                bound_unix_ms,
                reason,
            } => {
                validate_text(watch_id, "command.watch_id")?;
                validate_text(account_scope, "command.account_scope")?;
                validate_text(reason, "command.reason")?;
                if *bound_unix_ms == 0 {
                    return Err(ProviderAccountCatalogueError::InvalidField(
                        "command.bound_unix_ms",
                    ));
                }
                Ok(())
            }
        }
    }

    /// Commands never execute: the counter receipt is always zero.
    #[must_use]
    pub const fn execution(&self) -> ZeroModelExecutionCounters {
        ZeroModelExecutionCounters::zero()
    }

    /// Commands never grant dispatch authority.
    #[must_use]
    pub const fn dispatch_authority(&self) -> bool {
        false
    }

    /// Commands are candidate requests only.
    #[must_use]
    pub const fn candidate_only(&self) -> bool {
        true
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::model_control::{
        BillingClass, ModelCatalogueEntry, ModelCatalogueSnapshot, ModelRole, QuotaDisposition,
    };
    use crate::model_registry::{ModelRegistrySnapshot, RouteRequirements, find_models};

    use eliot_agent_api::LowercaseSha256;
    use eliot_contracts::sha256_hex;

    const NOW: u64 = 10_000;

    fn route(provider: &str, model: &str, suffix: &str) -> RouteFingerprint {
        let digest = |seed: &str| {
            serde_json::from_value::<LowercaseSha256>(serde_json::json!(sha256_hex(
                format!("provider-account-fixture-{seed}-{suffix}").as_bytes()
            )))
            .expect("valid fixture digest")
        };
        RouteFingerprint {
            host_family: "opencode".to_owned(),
            adapter: "eliot-agent-opencode".to_owned(),
            protocol_transport: "http+sse".to_owned(),
            runtime_hash: digest("runtime"),
            adapter_hash: digest("adapter"),
            provider: provider.to_owned(),
            model: model.to_owned(),
            auth_billing: "account-scope-1".to_owned(),
            serializer_hash: digest("serializer"),
            tool_semantics_hash: digest("tools"),
            reasoning_mode: "high".to_owned(),
            continuation_behavior: "native-resume".to_owned(),
            feature_flags_hash: digest("features"),
        }
    }

    fn billing() -> BillingEvidence {
        BillingEvidence {
            class: BillingClass::Free,
            source: "provider-catalogue".to_owned(),
            receipt_ref: "billing-receipt-1".to_owned(),
            observed_at_unix_ms: NOW - 100,
            expires_at_unix_ms: NOW + 100,
        }
    }

    fn quota(disposition: QuotaDisposition) -> QuotaObservation {
        QuotaObservation {
            disposition,
            source: "provider-catalogue".to_owned(),
            receipt_ref: "quota-receipt-1".to_owned(),
            observed_at_unix_ms: NOW - 100,
            expires_at_unix_ms: NOW + 100,
            reset_at_unix_ms: Some(NOW + 1_000),
            remaining_microunits: Some(10),
        }
    }

    fn rate_limit(disposition: RateLimitDisposition) -> RateLimitObservation {
        RateLimitObservation {
            disposition,
            source: "provider-observer".to_owned(),
            receipt_ref: "rate-limit-receipt-1".to_owned(),
            observed_at_unix_ms: NOW - 100,
            expires_at_unix_ms: NOW + 100,
            retry_after_unix_ms: None,
            window_reset_unix_ms: Some(NOW + 500),
        }
    }

    fn concurrency(disposition: ConcurrencyDisposition) -> ConcurrencyObservation {
        ConcurrencyObservation {
            disposition,
            source: "provider-observer".to_owned(),
            receipt_ref: "concurrency-receipt-1".to_owned(),
            observed_at_unix_ms: NOW - 100,
            expires_at_unix_ms: NOW + 100,
            in_flight: Some(2),
            limit: Some(8),
        }
    }

    fn incident(disposition: IncidentDisposition) -> IncidentObservation {
        IncidentObservation {
            disposition,
            source: "provider-observer".to_owned(),
            receipt_ref: "incident-receipt-1".to_owned(),
            observed_at_unix_ms: NOW - 100,
            expires_at_unix_ms: NOW + 100,
            incident_ref: match disposition {
                IncidentDisposition::Degraded | IncidentDisposition::Outage => {
                    Some("incident-7".to_owned())
                }
                IncidentDisposition::None | IncidentDisposition::Unknown => None,
            },
        }
    }

    fn auth(disposition: AuthDisposition) -> AuthObservation {
        AuthObservation {
            disposition,
            source: "provider-observer".to_owned(),
            receipt_ref: "auth-receipt-1".to_owned(),
            observed_at_unix_ms: NOW - 100,
            expires_at_unix_ms: NOW + 100,
        }
    }

    fn row(row_id: &str, provider: &str, model: &str) -> ProviderAccountRow {
        ProviderAccountRow {
            row_id: row_id.to_owned(),
            provider_id: provider.to_owned(),
            account_ref: "account-scope-1".to_owned(),
            credential_binding_ref: "credential-binding-1".to_owned(),
            adapter: "eliot-agent-opencode".to_owned(),
            artifact_generation: "artifact-gen-3".to_owned(),
            protocol_generation: "protocol-gen-2".to_owned(),
            route: route(provider, model, row_id),
            route_revision: "route-rev-1".to_owned(),
            model_revision: "model-rev-1".to_owned(),
            billing: billing(),
            quota: quota(QuotaDisposition::Available),
            route_health: RouteHealthStatus::Healthy,
            availability: ModelAvailability::Available,
            rate_limit: rate_limit(RateLimitDisposition::Ready),
            concurrency: concurrency(ConcurrencyDisposition::Available),
            incident: incident(IncidentDisposition::None),
            auth: auth(AuthDisposition::Bound),
            source: "provider-collector".to_owned(),
            receipt_ref: format!("row-receipt-{row_id}"),
            observed_at_unix_ms: NOW - 100,
            expires_at_unix_ms: NOW + 100,
            invalidation: Vec::new(),
        }
    }

    fn snapshot(rows: Vec<ProviderAccountRow>) -> ProviderAccountCatalogueSnapshot {
        build_snapshot(
            "provider-accounts-1",
            "account-scope-1",
            "provider-collector-v1",
            NOW - 100,
            NOW + 100,
            rows,
            Vec::new(),
        )
        .expect("valid fixture snapshot")
    }

    #[test]
    fn row_validation_rejects_blank_and_control_refs() {
        let mut bad = row("row-1", "provider-a", "model-a");
        bad.account_ref = "   ".to_owned();
        assert_eq!(
            bad.validate(),
            Err(ProviderAccountCatalogueError::InvalidField(
                "provider_account.account_ref"
            ))
        );
        let mut bad = row("row-1", "provider-a", "model-a");
        bad.credential_binding_ref = "binding\x07ref".to_owned();
        assert_eq!(
            bad.validate(),
            Err(ProviderAccountCatalogueError::InvalidField(
                "provider_account.credential_binding_ref"
            ))
        );
        let mut bad = row("row-1", "provider-a", "model-a");
        bad.provider_id = "other-provider".to_owned();
        assert_eq!(
            bad.validate(),
            Err(ProviderAccountCatalogueError::InvalidField(
                "provider_account.route_binding"
            ))
        );
        // The healthy fixture validates: refs are opaque strings, never bytes.
        row("row-1", "provider-a", "model-a")
            .validate()
            .expect("healthy row validates");
    }

    #[test]
    fn axes_validate_independently_without_cross_coercion() {
        // Billing FREE must not clear an exhausted quota axis: validation
        // passes on each axis independently, while readiness stays blocked on
        // the quota reason only.
        let mut candidate = row("row-1", "provider-a", "model-a");
        candidate.quota = quota(QuotaDisposition::Exhausted);
        candidate.validate().expect("independent axes validate");
        match candidate.readiness(NOW) {
            ProviderAccountReadiness::NotReady { reasons } => {
                assert!(reasons.contains(&"provider_account:quota_exhausted".to_owned()));
                assert!(
                    !reasons.iter().any(|reason| reason.contains("billing")),
                    "billing must not appear in quota-driven reasons: {reasons:?}"
                );
            }
            other => panic!("exhausted quota must block readiness, got {other:?}"),
        }
        // A fully current row is the only ready shape.
        assert_eq!(
            row("row-2", "provider-a", "model-a").readiness(NOW),
            ProviderAccountReadiness::Ready
        );
    }

    #[test]
    fn stale_rows_are_preserved_never_ready() {
        let mut stale = row("row-1", "provider-a", "model-a");
        stale.observed_at_unix_ms = NOW - 500;
        stale.expires_at_unix_ms = NOW - 100;
        stale.billing.observed_at_unix_ms = NOW - 500;
        stale.billing.expires_at_unix_ms = NOW - 100;
        stale.quota.observed_at_unix_ms = NOW - 500;
        stale.quota.expires_at_unix_ms = NOW - 100;
        stale.rate_limit.observed_at_unix_ms = NOW - 500;
        stale.rate_limit.expires_at_unix_ms = NOW - 100;
        stale.concurrency.observed_at_unix_ms = NOW - 500;
        stale.concurrency.expires_at_unix_ms = NOW - 100;
        stale.incident.observed_at_unix_ms = NOW - 500;
        stale.incident.expires_at_unix_ms = NOW - 100;
        stale.auth.observed_at_unix_ms = NOW - 500;
        stale.auth.expires_at_unix_ms = NOW - 100;
        stale
            .validate()
            .expect("stale row still validates structurally");
        match stale.readiness(NOW) {
            ProviderAccountReadiness::Stale { reasons } => {
                assert!(reasons.contains(&"provider_account:row_evidence_stale".to_owned()));
                assert!(reasons.contains(&"provider_account:billing_evidence_stale".to_owned()));
            }
            other => panic!("stale evidence must surface as stale, got {other:?}"),
        }
        // A stale rate-limit window alone is enough to withhold readiness.
        let mut window_stale = row("row-1", "provider-a", "model-a");
        window_stale.rate_limit.expires_at_unix_ms = NOW - 1;
        match window_stale.readiness(NOW) {
            ProviderAccountReadiness::Stale { .. } => {}
            other => panic!("stale axis must surface as stale, got {other:?}"),
        }
    }

    #[test]
    fn conflicted_and_unknown_axes_are_preserved_never_ready() {
        let mut conflicted = row("row-1", "provider-a", "model-a");
        conflicted.auth = auth(AuthDisposition::Conflicted);
        match conflicted.readiness(NOW) {
            ProviderAccountReadiness::Conflicted { reasons } => {
                assert!(reasons.contains(&"provider_account:auth_conflicted".to_owned()));
            }
            other => panic!("conflicted auth must surface as conflicted, got {other:?}"),
        }
        let mut invalidated = row("row-1", "provider-a", "model-a");
        invalidated.invalidation = vec!["owner-invalidation-1".to_owned()];
        invalidated
            .validate()
            .expect("invalidated row still validates");
        assert!(matches!(
            invalidated.readiness(NOW),
            ProviderAccountReadiness::Conflicted { .. }
        ));
        for (unknown_row, expected) in [
            (
                {
                    let mut candidate = row("row-1", "provider-a", "model-a");
                    candidate.incident = incident(IncidentDisposition::Unknown);
                    candidate
                },
                "provider_account:incident_unknown",
            ),
            (
                {
                    let mut candidate = row("row-1", "provider-a", "model-a");
                    candidate.auth = auth(AuthDisposition::Unknown);
                    candidate
                },
                "provider_account:auth_unknown",
            ),
            (
                {
                    let mut candidate = row("row-1", "provider-a", "model-a");
                    candidate.concurrency = concurrency(ConcurrencyDisposition::Unknown);
                    candidate
                },
                "provider_account:concurrency_unknown",
            ),
        ] {
            unknown_row
                .validate()
                .expect("unknown axis still validates");
            match unknown_row.readiness(NOW) {
                ProviderAccountReadiness::Unknown { reasons } => {
                    assert!(reasons.contains(&expected.to_owned()), "missing {expected}");
                }
                other => panic!("unknown axis must surface as unknown, got {other:?}"),
            }
        }
    }

    #[test]
    fn snapshot_digest_is_deterministic_and_order_independent() {
        let first = snapshot(vec![
            row("row-1", "provider-a", "model-a"),
            row("row-2", "provider-b", "model-b"),
        ]);
        let reordered = build_snapshot(
            "provider-accounts-1",
            "account-scope-1",
            "provider-collector-v1",
            NOW - 100,
            NOW + 100,
            vec![
                row("row-2", "provider-b", "model-b"),
                row("row-1", "provider-a", "model-a"),
            ],
            Vec::new(),
        )
        .expect("reordered snapshot builds");
        assert_eq!(first.canonical_digest, reordered.canonical_digest);
        // Changed bytes under the same snapshot id are a conflict, not a replay.
        let mut changed_row = row("row-1", "provider-a", "model-a");
        changed_row.model_revision = "model-rev-2".to_owned();
        let changed = build_snapshot(
            "provider-accounts-1",
            "account-scope-1",
            "provider-collector-v1",
            NOW - 100,
            NOW + 100,
            vec![changed_row, row("row-2", "provider-b", "model-b")],
            Vec::new(),
        )
        .expect("changed snapshot builds");
        assert_ne!(first.canonical_digest, changed.canonical_digest);
        assert_eq!(
            changed.replay_disposition(&first),
            Err(ProviderAccountCatalogueError::IdentityConflict)
        );
    }

    #[test]
    fn exact_replay_passes_and_new_snapshot_is_not_a_replay() {
        let first = snapshot(vec![row("row-1", "provider-a", "model-a")]);
        let replay = build_snapshot(
            "provider-accounts-1",
            "account-scope-1",
            "provider-collector-v1",
            NOW - 100,
            NOW + 100,
            vec![row("row-1", "provider-a", "model-a")],
            Vec::new(),
        )
        .expect("replay snapshot builds");
        assert_eq!(
            replay.replay_disposition(&first),
            Ok(ReplayDisposition::ExactReplay)
        );
        let next = build_snapshot(
            "provider-accounts-2",
            "account-scope-1",
            "provider-collector-v1",
            NOW - 100,
            NOW + 100,
            vec![row("row-1", "provider-a", "model-a")],
            Vec::new(),
        )
        .expect("next snapshot builds");
        assert_eq!(
            next.replay_disposition(&first),
            Ok(ReplayDisposition::NewSnapshot)
        );
        // A tampered digest never validates: the snapshot is rejected, never repaired.
        let mut tampered = first.clone();
        tampered.canonical_digest = format!("sha256:{}", "f".repeat(64));
        assert!(tampered.validate().is_err());
    }

    fn catalogue_entry(entry_id: &str, provider: &str, model: &str) -> ModelCatalogueEntry {
        use std::collections::{BTreeMap, BTreeSet};

        use crate::model_control::{CapabilityObservation, CapabilityStatus, RouteAdmissionStatus};

        ModelCatalogueEntry {
            entry_id: entry_id.to_owned(),
            account_scope: "account-scope-1".to_owned(),
            host_family: "opencode".to_owned(),
            provider_id: provider.to_owned(),
            model_id: model.to_owned(),
            model_family: "family".to_owned(),
            route: route(provider, model, entry_id),
            route_admission: RouteAdmissionStatus::Admitted,
            route_health: RouteHealthStatus::Healthy,
            availability: ModelAvailability::Available,
            billing: BillingEvidence {
                class: BillingClass::Free,
                source: "provider-catalogue".to_owned(),
                receipt_ref: format!("billing-{entry_id}"),
                observed_at_unix_ms: NOW - 10,
                expires_at_unix_ms: NOW + 10,
            },
            quota: quota(QuotaDisposition::Available),
            context_window: 200_000,
            cost_class: 1,
            latency_class: 1,
            capabilities: BTreeMap::from([(
                "coding".to_owned(),
                CapabilityObservation {
                    status: CapabilityStatus::Supported,
                    evidence_class: "runtime_probe".to_owned(),
                    receipt_ref: format!("capability-{entry_id}"),
                },
            )]),
            role_eligibility: BTreeSet::from([ModelRole::Worker]),
            evidence_refs: vec![format!("evidence-{entry_id}")],
        }
    }

    #[test]
    fn registry_filter_on_new_axes_stays_candidate_only() {
        use eliot_agent_api::{ResourceGeneration, StateFence};
        use eliot_contracts::EpochLineageId;

        use crate::model_registry::{RankingDimension, RankingPolicy};

        use crate::model_registry::find_models_with_provider_accounts;

        let saturated_route = route("provider-a", "model-a", "ready");
        let mut saturated = row("ready", "provider-a", "model-a");
        saturated.route = saturated_route.clone();
        saturated.concurrency = ConcurrencyObservation {
            disposition: ConcurrencyDisposition::Saturated,
            ..concurrency(ConcurrencyDisposition::Saturated)
        };
        // Row and catalogue entry ids share the route suffix so both bind
        // the same field-complete route fingerprint.
        let accounts = snapshot(vec![saturated, row("steady", "provider-b", "model-b")]);

        let catalogue = ModelCatalogueSnapshot {
            schema_version: crate::model_control::MODEL_CATALOGUE_SCHEMA_VERSION.to_owned(),
            snapshot_id: "catalogue-1".to_owned(),
            account_scope: "account-scope-1".to_owned(),
            collector_identity: "collector-v1".to_owned(),
            observed_at_unix_ms: NOW - 10,
            expires_at_unix_ms: NOW + 10,
            entries: vec![
                {
                    let mut entry = catalogue_entry("ready", "provider-a", "model-a");
                    entry.route = saturated_route;
                    entry
                },
                catalogue_entry("steady", "provider-b", "model-b"),
            ],
        };
        let registry =
            ModelRegistrySnapshot::from_catalogue(&catalogue).expect("registry snapshot builds");
        let fence = StateFence::new(
            eliot_agent_api::EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                    .expect("valid test lineage"),
                std::num::NonZeroU64::new(1).expect("nonzero test sequence"),
            )
            .expect("valid test epoch"),
            ResourceGeneration::new(1).expect("generation"),
        );
        let requirements =
            RouteRequirements::new("task-1", "attempt-1", "scope-1", fence, "policy-1", NOW);
        let base = find_models(
            &registry,
            &requirements,
            RankingPolicy::new("r1", vec![RankingDimension::RouteIdentity]),
        )
        .expect("base search runs");
        let filtered = find_models_with_provider_accounts(
            &registry,
            &accounts,
            &requirements,
            RankingPolicy::new("r1", vec![RankingDimension::RouteIdentity]),
        )
        .expect("provider-aware search runs");
        // The saturated provider row filters its route out; filtering only
        // narrows and the receipt stays candidate-only with zero execution.
        assert!(base.eligible.len() >= filtered.eligible.len());
        assert!(
            filtered
                .eligible
                .iter()
                .all(|entry| entry.entry_id != "ready"),
            "saturated provider row must filter its route: {:?}",
            filtered
                .eligible
                .iter()
                .map(|entry| &entry.entry_id)
                .collect::<Vec<_>>()
        );
        assert!(
            filtered
                .eligible
                .iter()
                .any(|entry| entry.entry_id == "steady")
        );
        assert_eq!(filtered.execution, ZeroModelExecutionCounters::zero());
        assert_eq!(
            filtered.proof_ceiling,
            eliot_receipts::ProofCeiling::CandidateArtifact
        );
        assert!(
            filtered
                .explanations
                .iter()
                .find(|explanation| explanation.entry_id.as_deref() == Some("ready"))
                .is_some_and(|explanation| !explanation.eligible
                    && explanation
                        .checks
                        .iter()
                        .any(|check| check.dimension == "provider_concurrency")),
            "filtered route must keep its provider check evidence"
        );
    }

    #[test]
    fn commands_validate_and_stay_candidate_only() {
        let commands = [
            ProviderAccountCommand::RequestCatalogueRefresh {
                account_scope: "account-scope-1".to_owned(),
                reason: "operator-requested-refresh".to_owned(),
            },
            ProviderAccountCommand::UpdatePreference {
                account_scope: "account-scope-1".to_owned(),
                preference_policy_id: "preferences-1".to_owned(),
                expected_revision: "rev-9".to_owned(),
            },
            ProviderAccountCommand::RequestSwarmLaunch {
                task_id: "task-1".to_owned(),
                plan_revision: "plan-rev-1".to_owned(),
                account_scope: "account-scope-1".to_owned(),
            },
            ProviderAccountCommand::CancelAttempt {
                attempt_ref: "attempt-1".to_owned(),
                reason: "operator-cancel".to_owned(),
            },
            ProviderAccountCommand::BoundedMonitor {
                watch_id: "watch-1".to_owned(),
                account_scope: "account-scope-1".to_owned(),
                bound_unix_ms: NOW + 1_000,
                reason: "operator-watch".to_owned(),
            },
        ];
        for command in &commands {
            command.validate().expect("command validates");
            assert!(command.candidate_only());
            assert!(!command.dispatch_authority());
            assert_eq!(command.execution(), ZeroModelExecutionCounters::zero());
        }
        // Bounds and refs are load-bearing: an unbounded monitor and a blank
        // scope both fail closed instead of becoming open-ended commands.
        assert_eq!(
            ProviderAccountCommand::BoundedMonitor {
                watch_id: "watch-1".to_owned(),
                account_scope: "account-scope-1".to_owned(),
                bound_unix_ms: 0,
                reason: "operator-watch".to_owned(),
            }
            .validate(),
            Err(ProviderAccountCatalogueError::InvalidField(
                "command.bound_unix_ms"
            ))
        );
        assert_eq!(
            ProviderAccountCommand::RequestCatalogueRefresh {
                account_scope: "  ".to_owned(),
                reason: "operator-requested-refresh".to_owned(),
            }
            .validate(),
            Err(ProviderAccountCatalogueError::InvalidField(
                "command.account_scope"
            ))
        );
        // Round-trip keeps the candidate-only shape: no authority survives
        // serialization.
        let bytes = serde_json::to_vec(&commands[2]).expect("command serializes");
        let decoded: ProviderAccountCommand =
            serde_json::from_slice(&bytes).expect("command deserializes");
        assert_eq!(decoded, commands[2]);
        assert!(!decoded.dispatch_authority());
    }
}
