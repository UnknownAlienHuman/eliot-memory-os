//! Machine-readable telemetry field policies for the Kernel-daemon path.
//!
//! Every field or event family emitted outside immediate process debugging
//! carries a [`TelemetryFieldPolicy`] naming its purpose, minimum
//! scope/sampling, collection owner and truth limit, recipients, redaction and
//! disclosure closure, retention/erasure/export, downstream use, misuse risk,
//! and qualification/removal condition.
//!
//! Content and secrets never reach span labels or metric labels: they are
//! replaced with immutable redacted evidence handles by
//! [`scrub_labels_for_emit`] before emission. [`scrub_labels_for_emit`] is the
//! single emission boundary; it enforces each family's [`LabelDisposition`]
//! (Handle-only families emit handles only, Forbidden families emit nothing).
//! [`validate_labels_for_family`] enforces the same disposition on the
//! validation path used by operational events and metric samples.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::ObservabilityError;
use eliot_contracts::sha256_hex;

/// Maximum label value length, in Unicode scalar values.
///
/// Longer values are treated as content and must travel as an immutable
/// redacted evidence handle, never as a span or metric label.
pub const MAX_LABEL_VALUE_CHARS: usize = 256;

/// Prefix identifying an immutable redacted evidence handle.
pub const REDACTED_HANDLE_PREFIX: &str = "evh";

/// Telemetry field/event families on the running Kernel-daemon path.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TelemetryFieldFamily {
    QueryMetadata,
    Principal,
    Session,
    TaskId,
    TraceId,
    RouteFingerprint,
    Lease,
    IoHandle,
    OperationalLog,
    CrashReport,
    AuditReceipt,
    MetricSample,
}

impl TelemetryFieldFamily {
    /// Stable snake-case identity used in evidence handles.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QueryMetadata => "query_metadata",
            Self::Principal => "principal",
            Self::Session => "session",
            Self::TaskId => "task_id",
            Self::TraceId => "trace_id",
            Self::RouteFingerprint => "route_fingerprint",
            Self::Lease => "lease",
            Self::IoHandle => "io_handle",
            Self::OperationalLog => "operational_log",
            Self::CrashReport => "crash_report",
            Self::AuditReceipt => "audit_receipt",
            Self::MetricSample => "metric_sample",
        }
    }

    /// Every family governed on the running path.
    #[must_use]
    pub const fn all() -> [Self; 12] {
        [
            Self::QueryMetadata,
            Self::Principal,
            Self::Session,
            Self::TaskId,
            Self::TraceId,
            Self::RouteFingerprint,
            Self::Lease,
            Self::IoHandle,
            Self::OperationalLog,
            Self::CrashReport,
            Self::AuditReceipt,
            Self::MetricSample,
        ]
    }
}

/// Whether a family may appear in span/metric labels at all.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LabelDisposition {
    /// Low-cardinality opaque identifiers only; values still pass secret screening.
    Allowed,
    /// Never a label value; only a redacted evidence handle may be emitted.
    HandleOnly,
    /// Never emitted outside its owning store.
    Forbidden,
}

impl LabelDisposition {
    /// Returns the disposition governing one telemetry family.
    ///
    /// This matches the `label_disposition` recorded in
    /// [`field_policy_inventory`](crate::field_policy::field_policy_inventory);
    /// the inventory test below pins the two together.
    #[must_use]
    pub const fn for_family(family: TelemetryFieldFamily) -> Self {
        match family {
            TelemetryFieldFamily::TaskId
            | TelemetryFieldFamily::TraceId
            | TelemetryFieldFamily::RouteFingerprint
            | TelemetryFieldFamily::Lease
            | TelemetryFieldFamily::OperationalLog
            | TelemetryFieldFamily::MetricSample => Self::Allowed,
            TelemetryFieldFamily::QueryMetadata
            | TelemetryFieldFamily::Principal
            | TelemetryFieldFamily::Session
            | TelemetryFieldFamily::IoHandle
            | TelemetryFieldFamily::CrashReport => Self::HandleOnly,
            TelemetryFieldFamily::AuditReceipt => Self::Forbidden,
        }
    }
}

/// Returns the [`LabelDisposition`] governing one telemetry family.
#[must_use]
pub const fn disposition_for(family: TelemetryFieldFamily) -> LabelDisposition {
    LabelDisposition::for_family(family)
}

/// Minimum collection scope and sampling for one family.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeSampling {
    pub scope: String,
    pub sampling: String,
}

/// Retention, erasure and export rule for one family.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionPolicy {
    pub store: RetentionStore,
    pub retention_bound: String,
    pub erasure: String,
    pub export: String,
}

/// Durable home interpreting one family's retention rule.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetentionStore {
    RollingLog,
    MetricBuffer,
    AuditCanonical,
    BlobStore,
}

impl RetentionStore {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RollingLog => "rolling_log",
            Self::MetricBuffer => "metric_buffer",
            Self::AuditCanonical => "audit_canonical",
            Self::BlobStore => "blob_store",
        }
    }
}

/// One machine-readable telemetry field policy.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryFieldPolicy {
    pub family: TelemetryFieldFamily,
    pub purpose: String,
    pub scope_sampling: ScopeSampling,
    pub owner: String,
    pub truth_limit: String,
    pub recipients: Vec<String>,
    pub label_disposition: LabelDisposition,
    pub redaction: String,
    pub disclosure_closure: String,
    pub retention: RetentionPolicy,
    pub downstream_use: String,
    pub misuse_risk: String,
    pub qualification: String,
    pub removal_condition: String,
}

fn policy_text(value: &str, field: &'static str) -> Result<(), ObservabilityError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ObservabilityError::InvalidField {
            field,
            reason: "must be non-blank and contain no control characters",
        });
    }
    Ok(())
}

impl ScopeSampling {
    fn validate(&self) -> Result<(), ObservabilityError> {
        policy_text(&self.scope, "policy.scope")?;
        policy_text(&self.sampling, "policy.sampling")
    }
}

impl RetentionPolicy {
    /// Validates that retention, erasure and export are all explicitly defined.
    pub fn validate(&self) -> Result<(), ObservabilityError> {
        policy_text(&self.retention_bound, "policy.retention_bound")?;
        policy_text(&self.erasure, "policy.erasure")?;
        policy_text(&self.export, "policy.export")
    }
}

impl TelemetryFieldPolicy {
    /// Validates every required policy property.
    pub fn validate(&self) -> Result<(), ObservabilityError> {
        policy_text(&self.purpose, "policy.purpose")?;
        self.scope_sampling.validate()?;
        policy_text(&self.owner, "policy.owner")?;
        policy_text(&self.truth_limit, "policy.truth_limit")?;
        if self.recipients.is_empty() {
            return Err(ObservabilityError::Empty {
                field: "policy.recipients",
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        for recipient in &self.recipients {
            policy_text(recipient, "policy.recipient")?;
            if !seen.insert(recipient) {
                return Err(ObservabilityError::Duplicate {
                    field: "policy.recipients",
                });
            }
        }
        policy_text(&self.redaction, "policy.redaction")?;
        policy_text(&self.disclosure_closure, "policy.disclosure_closure")?;
        self.retention.validate()?;
        policy_text(&self.downstream_use, "policy.downstream_use")?;
        policy_text(&self.misuse_risk, "policy.misuse_risk")?;
        policy_text(&self.qualification, "policy.qualification")?;
        policy_text(&self.removal_condition, "policy.removal_condition")
    }
}

/// Returns `true` when a label value carries a recognisable secret.
#[must_use]
pub fn looks_like_secret(value: &str) -> bool {
    if value.starts_with("AKIA")
        || value.starts_with("sk-live-")
        || value.starts_with("sk-test-")
        || value.starts_with("ghp_")
        || value.starts_with("gho_")
        || value.starts_with("github_pat_")
        || value.starts_with("xoxb-")
        || value.starts_with("xoxp-")
        || value.starts_with("xoxa-")
        || value.starts_with("-----BEGIN")
    {
        return true;
    }
    let folded = value.to_ascii_lowercase();
    folded.contains("bearer ")
        || folded.contains("api_key")
        || folded.contains("apikey")
        || folded.contains("secret=")
        || folded.contains("secret:")
        || folded.contains("password=")
        || folded.contains("password:")
        || folded.contains("passwd=")
        || folded.contains("aws_secret")
}

/// Returns `true` when a label value must travel as an evidence handle.
#[must_use]
pub fn requires_evidence_handle(value: &str) -> bool {
    looks_like_secret(value) || value.chars().count() > MAX_LABEL_VALUE_CHARS
}

/// Why a value was replaced with an evidence handle.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RedactionReason {
    Secret,
    Content,
    ForbiddenKey,
    HandleOnly,
}

impl RedactionReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "redacted:secret",
            Self::Content => "redacted:content",
            Self::ForbiddenKey => "redacted:forbidden-key",
            Self::HandleOnly => "redacted:handle-only",
        }
    }

    /// Every recorded redaction status.
    #[must_use]
    pub const fn all_statuses() -> [&'static str; 4] {
        [
            Self::Secret.as_str(),
            Self::Content.as_str(),
            Self::ForbiddenKey.as_str(),
            Self::HandleOnly.as_str(),
        ]
    }
}

/// Immutable handle standing in for redacted content or a secret.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedHandle {
    pub handle: String,
    pub family: TelemetryFieldFamily,
    pub source_key: String,
    pub redaction_status: String,
}

/// Mints an immutable handle for one redacted value.
#[must_use]
pub fn mint_handle(
    family: TelemetryFieldFamily,
    source_key: &str,
    value: &str,
    reason: RedactionReason,
) -> RedactedHandle {
    let mut bytes = Vec::with_capacity(family.as_str().len() + value.len() + 1);
    bytes.extend_from_slice(family.as_str().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(value.as_bytes());
    RedactedHandle {
        handle: format!(
            "{REDACTED_HANDLE_PREFIX}:{}:{}",
            family.as_str(),
            sha256_hex(&bytes)
        ),
        family,
        source_key: source_key.to_owned(),
        redaction_status: reason.as_str().to_owned(),
    }
}

/// Label keys that may never carry a raw value, mirroring event/metric validation.
const FORBIDDEN_KEY_FRAGMENTS: &[&str] = &[
    "secret",
    "token",
    "password",
    "credential",
    "prompt",
    "content",
    "stdout",
    "stderr",
    "arguments",
    "args",
    "raw",
    "payload",
];

fn forbidden_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    FORBIDDEN_KEY_FRAGMENTS
        .iter()
        .any(|fragment| normalized.contains(fragment))
}

/// Returns `true` when `value` is a structurally valid evidence handle bound
/// to `family` (`evh:<family>:<64 lowercase hex>`).
#[must_use]
pub fn is_handle_value_for_family(value: &str, family: TelemetryFieldFamily) -> bool {
    let Some(suffix) = value.strip_prefix(REDACTED_HANDLE_PREFIX) else {
        return false;
    };
    let Some(suffix) = suffix.strip_prefix(':') else {
        return false;
    };
    let Some(hex) = suffix.strip_prefix(family.as_str()) else {
        return false;
    };
    let Some(hex) = hex.strip_prefix(':') else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn redaction_status_valid(status: &str) -> bool {
    RedactionReason::all_statuses().contains(&status)
}

fn label_text_ok(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

/// Labels safe for emission plus the recorded evidence handles.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScrubbedLabels {
    pub labels: BTreeMap<String, String>,
    pub handles: Vec<RedactedHandle>,
}

impl ScrubbedLabels {
    /// Returns `true` when the scrubbed output is safe to emit for `family`.
    ///
    /// This verifies every audit property: forbidden keys are gone from the
    /// emitted key set, no secret or content value survived, Handle-only
    /// families carry handles exclusively, Forbidden families emit nothing,
    /// every handle is a structurally valid `evh` identity bound to `family`
    /// and present among the emitted values, and every emitted key is safe.
    #[must_use]
    pub fn is_clean(&self, family: TelemetryFieldFamily) -> bool {
        match disposition_for(family) {
            LabelDisposition::Forbidden => self.labels.is_empty() && self.handles.is_empty(),
            LabelDisposition::HandleOnly => {
                if self.labels.len() != self.handles.len() || self.labels.len() > 16 {
                    return false;
                }
                for (key, value) in &self.labels {
                    if !label_text_ok(key)
                        || !label_text_ok(value)
                        || forbidden_key(key)
                        || requires_evidence_handle(value)
                        || !is_handle_value_for_family(value, family)
                    {
                        return false;
                    }
                }
                self.handles_valid(family)
            }
            LabelDisposition::Allowed => {
                if self.labels.len() > 16 {
                    return false;
                }
                for (key, value) in &self.labels {
                    if !label_text_ok(key)
                        || !label_text_ok(value)
                        || forbidden_key(key)
                        || requires_evidence_handle(value)
                    {
                        return false;
                    }
                }
                self.handles_valid(family)
            }
        }
    }

    /// Checks every recorded handle is bound to `family` and emitted.
    fn handles_valid(&self, family: TelemetryFieldFamily) -> bool {
        for handle in &self.handles {
            if handle.family != family
                || !label_text_ok(&handle.source_key)
                || !redaction_status_valid(&handle.redaction_status)
                || !is_handle_value_for_family(&handle.handle, family)
                || !self.labels.values().any(|value| value == &handle.handle)
            {
                return false;
            }
        }
        true
    }
}

/// Validates candidate labels for one family before emission.
///
/// This is the validation half of the emission boundary: it enforces the
/// family's [`LabelDisposition`] in addition to the shared secret, content and
/// forbidden-key screening. Handle-only families accept evidence handles bound
/// to that family exclusively; Forbidden families accept no labels at all.
pub fn validate_labels_for_family(
    family: TelemetryFieldFamily,
    labels: &BTreeMap<String, String>,
) -> Result<(), ObservabilityError> {
    if labels.len() > 16 {
        return Err(ObservabilityError::InvalidField {
            field: "labels",
            reason: "label cardinality exceeds the bounded limit",
        });
    }
    match disposition_for(family) {
        LabelDisposition::Forbidden => {
            if labels.is_empty() {
                return Ok(());
            }
            return Err(ObservabilityError::SensitiveLabel);
        }
        LabelDisposition::HandleOnly => {
            for (key, value) in labels {
                policy_text(key, "label.key")?;
                policy_text(value, "label.value")?;
                if forbidden_key(key)
                    || requires_evidence_handle(value)
                    || !is_handle_value_for_family(value, family)
                {
                    return Err(ObservabilityError::SensitiveLabel);
                }
            }
            return Ok(());
        }
        LabelDisposition::Allowed => {}
    }
    for (key, value) in labels {
        policy_text(key, "label.key")?;
        policy_text(value, "label.value")?;
        if forbidden_key(key) {
            return Err(ObservabilityError::SensitiveLabel);
        }
        if requires_evidence_handle(value) {
            return Err(ObservabilityError::SensitiveLabel);
        }
    }
    Ok(())
}

/// Replaces content and secrets with immutable handles before label emission.
///
/// This is the single emission boundary. It enforces each family's
/// [`LabelDisposition`]: Forbidden families emit nothing, Handle-only
/// families emit evidence handles exclusively (benign values included), and
/// Allowed families emit opaque identifiers subject to secret/content
/// screening. Forbidden keys are renamed to `redacted_evidence_<n>` so no
/// sensitive shape survives in the emitted key set; the original key is
/// recorded on the handle.
#[must_use]
pub fn scrub_labels_for_emit(
    family: TelemetryFieldFamily,
    candidate: &BTreeMap<String, String>,
) -> ScrubbedLabels {
    let mut scrubbed = ScrubbedLabels {
        labels: BTreeMap::new(),
        handles: Vec::new(),
    };
    if disposition_for(family) == LabelDisposition::Forbidden {
        return scrubbed;
    }
    let handle_only = disposition_for(family) == LabelDisposition::HandleOnly;
    let mut redacted_count = 0_usize;
    for (key, value) in candidate {
        if forbidden_key(key) {
            let handle = mint_handle(family, key, value, RedactionReason::ForbiddenKey);
            scrubbed.labels.insert(
                format!("redacted_evidence_{redacted_count}"),
                handle.handle.clone(),
            );
            redacted_count += 1;
            scrubbed.handles.push(handle);
        } else if handle_only {
            let handle = mint_handle(family, key, value, RedactionReason::HandleOnly);
            scrubbed.labels.insert(key.clone(), handle.handle.clone());
            scrubbed.handles.push(handle);
        } else if looks_like_secret(value) {
            let handle = mint_handle(family, key, value, RedactionReason::Secret);
            scrubbed.labels.insert(key.clone(), handle.handle.clone());
            scrubbed.handles.push(handle);
        } else if value.chars().count() > MAX_LABEL_VALUE_CHARS {
            let handle = mint_handle(family, key, value, RedactionReason::Content);
            scrubbed.labels.insert(key.clone(), handle.handle.clone());
            scrubbed.handles.push(handle);
        } else {
            scrubbed.labels.insert(key.clone(), value.clone());
        }
    }
    scrubbed
}

fn base_scope(scope: &str, sampling: &str) -> ScopeSampling {
    ScopeSampling {
        scope: scope.to_owned(),
        sampling: sampling.to_owned(),
    }
}

fn base_retention(
    store: RetentionStore,
    bound: &str,
    erasure: &str,
    export: &str,
) -> RetentionPolicy {
    RetentionPolicy {
        store,
        retention_bound: bound.to_owned(),
        erasure: erasure.to_owned(),
        export: export.to_owned(),
    }
}

fn query_metadata_policy() -> TelemetryFieldPolicy {
    TelemetryFieldPolicy {
        family: TelemetryFieldFamily::QueryMetadata,
        purpose: "Correlate one captured query with its execution lineage for process debugging."
            .to_owned(),
        scope_sampling: base_scope(
            "per captured query",
            "1:1 while retained in the rolling window",
        ),
        owner: "eliot-kernel query intake".to_owned(),
        truth_limit: "Metadata describes capture, not semantic success or user intent.".to_owned(),
        recipients: vec![
            "kernel operator log".to_owned(),
            "daemon diagnostics".to_owned(),
        ],
        label_disposition: LabelDisposition::HandleOnly,
        redaction:
            "Query text and arguments are replaced with an immutable evidence handle before labels."
                .to_owned(),
        disclosure_closure:
            "Handles disclose presence and identity only; raw text stays in BlobStore.".to_owned(),
        retention: base_retention(
            RetentionStore::RollingLog,
            "rolling 10_000 events per instance",
            "drop oldest on bound; purge on operator erasure request",
            "redacted handles only; raw text export requires explicit incident grant",
        ),
        downstream_use: "Trace correlation and diagnostic briefs.".to_owned(),
        misuse_risk: "Retaining raw query text would expose user content in logs.".to_owned(),
        qualification: "Admitted while query intake is the running capture path.".to_owned(),
        removal_condition: "Remove when query intake moves off the Kernel-daemon path.".to_owned(),
    }
}

fn principal_policy() -> TelemetryFieldPolicy {
    TelemetryFieldPolicy {
        family: TelemetryFieldFamily::Principal,
        purpose: "Attribute privileged actions to an opaque principal for audit correlation."
            .to_owned(),
        scope_sampling: base_scope(
            "per authenticated action",
            "1:1 for audit receipts; absent from metrics",
        ),
        owner: "session authority".to_owned(),
        truth_limit: "Reference is opaque; it proves neither identity strength nor authorization."
            .to_owned(),
        recipients: vec![
            "audit receipts".to_owned(),
            "kernel session guard".to_owned(),
        ],
        label_disposition: LabelDisposition::HandleOnly,
        redaction: "Principal material is replaced with an opaque reference before labels."
            .to_owned(),
        disclosure_closure: "Opaque references disclose no credential or claim material."
            .to_owned(),
        retention: base_retention(
            RetentionStore::RollingLog,
            "rolling 10_000 events per instance",
            "drop oldest on bound; purge on session close plus erasure request",
            "opaque references only; no principal export",
        ),
        downstream_use: "Audit correlation and session-guard decisions.".to_owned(),
        misuse_risk: "Label cardinality leak could fingerprint operators across sessions."
            .to_owned(),
        qualification: "Admitted while SID/session-bound launch is authoritative.".to_owned(),
        removal_condition: "Remove when session authority replaces the reference scheme."
            .to_owned(),
    }
}

fn session_policy() -> TelemetryFieldPolicy {
    TelemetryFieldPolicy {
        family: TelemetryFieldFamily::Session,
        purpose: "Bind operational events to one session for lifecycle debugging.".to_owned(),
        scope_sampling: base_scope("per session event", "1:1 for events; absent from metrics"),
        owner: "session authority".to_owned(),
        truth_limit: "Session reference marks association, not liveness or authorization."
            .to_owned(),
        recipients: vec![
            "kernel operator log".to_owned(),
            "daemon diagnostics".to_owned(),
        ],
        label_disposition: LabelDisposition::HandleOnly,
        redaction: "Session tokens are replaced with an opaque reference before labels.".to_owned(),
        disclosure_closure: "Opaque references disclose no session secret.".to_owned(),
        retention: base_retention(
            RetentionStore::RollingLog,
            "rolling 10_000 events per instance",
            "drop oldest on bound; purge on session close plus erasure request",
            "opaque references only; no session export",
        ),
        downstream_use: "Session lifecycle debugging and supervision.".to_owned(),
        misuse_risk: "Raw session tokens in labels would allow session hijack from telemetry."
            .to_owned(),
        qualification: "Admitted while SID/session-bound launch is authoritative.".to_owned(),
        removal_condition: "Remove when session authority replaces the reference scheme."
            .to_owned(),
    }
}

fn task_id_policy() -> TelemetryFieldPolicy {
    TelemetryFieldPolicy {
        family: TelemetryFieldFamily::TaskId,
        purpose: "Join task lifecycle events across kernel and daemon for one unit of work."
            .to_owned(),
        scope_sampling: base_scope("per task event", "1:1"),
        owner: "eliot-kernel task intake".to_owned(),
        truth_limit: "Task identity marks association, not progress or completion.".to_owned(),
        recipients: vec![
            "kernel operator log".to_owned(),
            "daemon diagnostics".to_owned(),
            "bounded metric labels".to_owned(),
        ],
        label_disposition: LabelDisposition::Allowed,
        redaction: "Opaque task identifiers only; secret screening still applies to values."
            .to_owned(),
        disclosure_closure: "Task identifiers disclose no content or principal.".to_owned(),
        retention: base_retention(
            RetentionStore::RollingLog,
            "rolling 10_000 events per instance",
            "drop oldest on bound; purge on task close plus window",
            "identifiers may export with redacted event extracts",
        ),
        downstream_use: "Task lifecycle joins and supervision dashboards.".to_owned(),
        misuse_risk: "High-cardinality task labels in metrics would exhaust the bounded buffer."
            .to_owned(),
        qualification: "Admitted while task intake is the running capture path.".to_owned(),
        removal_condition: "Remove when task identity moves off the Kernel-daemon path.".to_owned(),
    }
}

fn trace_id_policy() -> TelemetryFieldPolicy {
    TelemetryFieldPolicy {
        family: TelemetryFieldFamily::TraceId,
        purpose: "Propagate one trace across spans, metrics and gaps for causal debugging."
            .to_owned(),
        scope_sampling: base_scope("per trace event", "1:1"),
        owner: "eliot-observability trace context".to_owned(),
        truth_limit: "Trace identity marks correlation, not coverage; gaps are explicit."
            .to_owned(),
        recipients: vec![
            "kernel operator log".to_owned(),
            "daemon diagnostics".to_owned(),
            "bounded metric labels".to_owned(),
        ],
        label_disposition: LabelDisposition::Allowed,
        redaction: "Opaque trace identifiers only; secret screening still applies to values."
            .to_owned(),
        disclosure_closure: "Trace identifiers disclose no content or principal.".to_owned(),
        retention: base_retention(
            RetentionStore::RollingLog,
            "rolling 10_000 events per instance",
            "drop oldest on bound; purge with the owning event window",
            "identifiers may export with redacted event extracts",
        ),
        downstream_use: "Distributed causal debugging and gap accounting.".to_owned(),
        misuse_risk: "Unbounded trace label values would exhaust the bounded buffer.".to_owned(),
        qualification: "Admitted while TraceContext is the running lineage carrier.".to_owned(),
        removal_condition: "Remove when lineage moves to a successor context.".to_owned(),
    }
}

fn route_fingerprint_policy() -> TelemetryFieldPolicy {
    TelemetryFieldPolicy {
        family: TelemetryFieldFamily::RouteFingerprint,
        purpose: "Detect route mismatch and dispatch drift without logging route tables."
            .to_owned(),
        scope_sampling: base_scope(
            "per dispatch decision",
            "1:1 for mismatch; 1:100 sampled for match",
        ),
        owner: "kernel dispatch".to_owned(),
        truth_limit: "Fingerprint marks the chosen route, not its authorization or cost."
            .to_owned(),
        recipients: vec![
            "kernel operator log".to_owned(),
            "daemon diagnostics".to_owned(),
            "bounded metric labels".to_owned(),
        ],
        label_disposition: LabelDisposition::Allowed,
        redaction: "Fingerprints only; route arguments stay behind evidence handles.".to_owned(),
        disclosure_closure: "Fingerprints disclose no route arguments or topology.".to_owned(),
        retention: base_retention(
            RetentionStore::RollingLog,
            "rolling 10_000 events per instance",
            "drop oldest on bound; purge with the owning event window",
            "fingerprints may export with redacted event extracts",
        ),
        downstream_use: "Route-mismatch detection and dispatch dashboards.".to_owned(),
        misuse_risk: "Raw route arguments in labels would leak deployment topology.".to_owned(),
        qualification: "Admitted while kernel dispatch owns routing.".to_owned(),
        removal_condition: "Remove when dispatch moves off the Kernel-daemon path.".to_owned(),
    }
}

fn lease_policy() -> TelemetryFieldPolicy {
    TelemetryFieldPolicy {
        family: TelemetryFieldFamily::Lease,
        purpose: "Record lease transitions for occupancy and supervision accounting.".to_owned(),
        scope_sampling: base_scope("per lease transition", "1:1"),
        owner: "kernel lease authority".to_owned(),
        truth_limit: "Lease reference marks tenure, not resource ownership.".to_owned(),
        recipients: vec![
            "kernel operator log".to_owned(),
            "daemon diagnostics".to_owned(),
            "bounded metric labels".to_owned(),
        ],
        label_disposition: LabelDisposition::Allowed,
        redaction: "Lease references only; holder secrets never enter labels.".to_owned(),
        disclosure_closure: "Lease references disclose no holder material.".to_owned(),
        retention: base_retention(
            RetentionStore::RollingLog,
            "rolling 10_000 events per instance",
            "drop oldest on bound; purge on lease release plus window",
            "lease references may export with redacted event extracts",
        ),
        downstream_use: "Occupancy accounting and supervision.".to_owned(),
        misuse_risk: "Holder material in labels would leak capability references.".to_owned(),
        qualification: "Admitted while the kernel lease authority is authoritative.".to_owned(),
        removal_condition: "Remove when lease authority moves off the Kernel-daemon path."
            .to_owned(),
    }
}

fn io_handle_policy() -> TelemetryFieldPolicy {
    TelemetryFieldPolicy {
        family: TelemetryFieldFamily::IoHandle,
        purpose: "Preserve raw inputs/outputs immutably for replay without copying content into telemetry.".to_owned(),
        scope_sampling: base_scope("per IO capture", "1:1 handle emission; bytes stay in BlobStore"),
        owner: "instrument execution edge".to_owned(),
        truth_limit: "Handle proves preservation, not correctness or completeness of content.".to_owned(),
        recipients: vec!["blob store".to_owned(), "diagnostic briefs".to_owned()],
        label_disposition: LabelDisposition::HandleOnly,
        redaction: "Raw bytes never enter labels, metrics or rolling logs; handles only.".to_owned(),
        disclosure_closure: "Handles disclose byte counts and identity; content requires BlobStore grant.".to_owned(),
        retention: base_retention(
            RetentionStore::BlobStore,
            "bounded 1 GiB per instance; 7 day ceiling",
            "delete blobs past ceiling; erase on operator erasure request",
            "explicit per-blob grant with audit receipt; no bulk export",
        ),
        downstream_use: "Replay, truncation lineage and parser-warning analysis.".to_owned(),
        misuse_risk: "Raw output in telemetry would retain user content and secrets indefinitely.".to_owned(),
        qualification: "Admitted while instrument execution preserves raw output.".to_owned(),
        removal_condition: "Remove when raw-output preservation moves to a successor store.".to_owned(),
    }
}

fn operational_log_policy() -> TelemetryFieldPolicy {
    TelemetryFieldPolicy {
        family: TelemetryFieldFamily::OperationalLog,
        purpose: "Retain scrubbed operational events for rolling process debugging.".to_owned(),
        scope_sampling: base_scope(
            "per operational event",
            "1:1 for protected; sampled for diagnostic",
        ),
        owner: "eliot-observability buffer".to_owned(),
        truth_limit: "Logs are observations; they are not audit proof or verifier truth."
            .to_owned(),
        recipients: vec![
            "kernel operator log".to_owned(),
            "daemon diagnostics".to_owned(),
        ],
        label_disposition: LabelDisposition::Allowed,
        redaction: "Labels pass the emit gate; secrets and content become handles first."
            .to_owned(),
        disclosure_closure: "Scrubbed logs disclose handles and opaque identifiers only."
            .to_owned(),
        retention: base_retention(
            RetentionStore::RollingLog,
            "rolling 10_000 events per instance with explicit gap records",
            "drop oldest on bound; purge on operator erasure request",
            "scrubbed extracts only; raw re-export is forbidden",
        ),
        downstream_use: "Rolling debugging and diagnostic briefs.".to_owned(),
        misuse_risk: "Treating logs as audit proof would overstate their truth limit.".to_owned(),
        qualification: "Admitted while the bounded buffer is the rolling surface.".to_owned(),
        removal_condition: "Remove when rolling logs move to a successor surface.".to_owned(),
    }
}

fn crash_report_policy() -> TelemetryFieldPolicy {
    TelemetryFieldPolicy {
        family: TelemetryFieldFamily::CrashReport,
        purpose: "Preserve crash evidence for incident analysis with bounded retention.".to_owned(),
        scope_sampling: base_scope("per crash", "1:1; protected priority"),
        owner: "supervision edge".to_owned(),
        truth_limit: "Crash evidence marks failure observation, not root cause.".to_owned(),
        recipients: vec!["supervision".to_owned(), "incident review".to_owned()],
        label_disposition: LabelDisposition::HandleOnly,
        redaction: "Stacks and dumps become handles; labels carry crash class only.".to_owned(),
        disclosure_closure: "Crash class is public to supervision; dumps require incident grant."
            .to_owned(),
        retention: base_retention(
            RetentionStore::BlobStore,
            "bounded 256 MiB per instance; 30 day ceiling",
            "delete blobs past ceiling; erase on incident close plus request",
            "incident-scoped grant with audit receipt; no bulk export",
        ),
        downstream_use: "Incident analysis and restart accounting.".to_owned(),
        misuse_risk: "Dumps in labels or rolling logs would retain memory content.".to_owned(),
        qualification: "Admitted while supervision owns crash intake.".to_owned(),
        removal_condition: "Remove when crash intake moves to a successor edge.".to_owned(),
    }
}

fn audit_receipt_policy() -> TelemetryFieldPolicy {
    TelemetryFieldPolicy {
        family: TelemetryFieldFamily::AuditReceipt,
        purpose: "Retain canonical audit receipts with explicit purge for compliance proof."
            .to_owned(),
        scope_sampling: base_scope("per audited decision", "1:1; never sampled"),
        owner: "canonical audit owner".to_owned(),
        truth_limit: "Receipts prove the recorded decision, not external-world truth.".to_owned(),
        recipients: vec![
            "canonical audit store".to_owned(),
            "compliance review".to_owned(),
        ],
        label_disposition: LabelDisposition::Forbidden,
        redaction: "Receipts never enter labels or metrics; sealed canonical storage only."
            .to_owned(),
        disclosure_closure: "Receipt disclosure is a signed extract naming its scope.".to_owned(),
        retention: base_retention(
            RetentionStore::AuditCanonical,
            "canonical 400 day retention with sealed purge thereafter",
            "cryptographic purge past retention; erasure only by compliance order",
            "signed extracts only; no raw store export",
        ),
        downstream_use: "Compliance proof and dispute resolution.".to_owned(),
        misuse_risk: "Label or metric leakage of receipts would duplicate canonical truth."
            .to_owned(),
        qualification: "Admitted while canonical audit is the compliance surface.".to_owned(),
        removal_condition: "Remove only by compliance-surface migration with dual control."
            .to_owned(),
    }
}

fn metric_sample_policy() -> TelemetryFieldPolicy {
    TelemetryFieldPolicy {
        family: TelemetryFieldFamily::MetricSample,
        purpose: "Bound operational counters for dashboards without becoming proof.".to_owned(),
        scope_sampling: base_scope(
            "per metric sample",
            "bounded buffer; 1:60 downsample past 5_000 samples",
        ),
        owner: "eliot-observability buffer".to_owned(),
        truth_limit: "Samples are observations; they never become progress or semantic proof."
            .to_owned(),
        recipients: vec![
            "daemon dashboards".to_owned(),
            "kernel operator view".to_owned(),
        ],
        label_disposition: LabelDisposition::Allowed,
        redaction: "Labels pass the emit gate; secrets and content become handles first."
            .to_owned(),
        disclosure_closure: "Aggregates disclose counts only; no per-request content.".to_owned(),
        retention: base_retention(
            RetentionStore::MetricBuffer,
            "bounded 5_000 samples per instance with downsampling",
            "drop oldest on bound; explicit gap record on downsample",
            "aggregates may export; per-sample export is forbidden",
        ),
        downstream_use: "Dashboards and capacity signals.".to_owned(),
        misuse_risk: "Per-request metric labels would rebuild content from cardinality.".to_owned(),
        qualification: "Admitted while the bounded metric buffer is the metric surface.".to_owned(),
        removal_condition: "Remove when metrics move to a successor surface.".to_owned(),
    }
}

/// Full policy inventory for the running Kernel-daemon path.
#[must_use]
pub fn field_policy_inventory() -> Vec<TelemetryFieldPolicy> {
    vec![
        query_metadata_policy(),
        principal_policy(),
        session_policy(),
        task_id_policy(),
        trace_id_policy(),
        route_fingerprint_policy(),
        lease_policy(),
        io_handle_policy(),
        operational_log_policy(),
        crash_report_policy(),
        audit_receipt_policy(),
        metric_sample_policy(),
    ]
}

/// Returns the policy governing one family, when the family is on the path.
#[must_use]
pub fn policy_for(family: TelemetryFieldFamily) -> Option<TelemetryFieldPolicy> {
    field_policy_inventory()
        .into_iter()
        .find(|policy| policy.family == family)
}

/// Returns the retention/erasure/export rule for one family.
#[must_use]
pub fn retention_for(family: TelemetryFieldFamily) -> Option<RetentionPolicy> {
    policy_for(family).map(|policy| policy.retention)
}
