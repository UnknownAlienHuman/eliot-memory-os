//! Governor route evidence: requested route versus observed execution route
//! (issue #1958, I3.4 `I03-04-capability-and-route-registry.md`).
//!
//! `eliotd` is the semantic Governor application owner. This module is the
//! canonical Governor receipt view inside that owner: it records the
//! policy-selected requested route separately from the runtime-observed
//! route, forces an explicit `unknown` for unexposed provider/model/billing
//! facts, and keys routing evidence, capability lookup, and outcome-profile
//! lookup off the complete effective fingerprint rather than provider/model
//! labels alone.
//!
//! Identity ownership stays with [`RouteFingerprint`](eliot_agent_api::RouteFingerprint):
//! this module introduces no second fingerprint type. The observed
//! fingerprint is always built from [`RuntimeObservedFacts`] (runtime
//! handshake, transport metadata, or other evidence-bearing observations)
//! and never copied from the requested route. Divergence classification
//! reuses [`route_divergence_fields`](eliot_agent_api::route_divergence_fields).

use std::collections::BTreeMap;

use eliot_agent_api::{AttemptId, RouteFingerprint, route_divergence_fields};
use eliot_contracts::{LowercaseSha256, canonical_json_bytes, sha256_hex};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Explicit marker for a provider/model/billing fact the runtime did not
/// expose. It is never inferred from UI selection, configuration text, or
/// the requested route.
pub const UNKNOWN_ROUTE_FACT: &str = "unknown";

/// Maximum evidence references carried by one Governor route receipt.
pub const MAX_ROUTE_EVIDENCE_REFS: usize = 64;
/// Maximum length of one evidence reference, in Unicode scalar values.
pub const MAX_ROUTE_EVIDENCE_REF_CHARS: usize = 1024;

fn validate_text(value: &str, field: &'static str) -> Result<(), RouteReceiptError> {
    if value.trim().is_empty() {
        return Err(RouteReceiptError::BlankField(field));
    }
    if value.chars().any(char::is_control) {
        return Err(RouteReceiptError::ControlField(field));
    }
    Ok(())
}

fn validate_evidence_refs(refs: &[String]) -> Result<(), RouteReceiptError> {
    if refs.is_empty() {
        return Err(RouteReceiptError::EmptyEvidence);
    }
    if refs.len() > MAX_ROUTE_EVIDENCE_REFS {
        return Err(RouteReceiptError::OversizeEvidence);
    }
    for reference in refs {
        validate_text(reference, "evidence_ref")?;
        if reference.chars().count() > MAX_ROUTE_EVIDENCE_REF_CHARS {
            return Err(RouteReceiptError::OversizeEvidence);
        }
    }
    Ok(())
}

fn validate_optional_fact(
    value: Option<&String>,
    field: &'static str,
) -> Result<(), RouteReceiptError> {
    if let Some(text) = value {
        validate_text(text, field)?;
        // `unknown` is reserved for the unexposed case (`None`), matched
        // case-insensitively so no spelling variant can pose as observed
        // evidence. Evidence must carry an actual observed value; an
        // unexposed fact is reported as `None` by the caller.
        if text.eq_ignore_ascii_case(UNKNOWN_ROUTE_FACT) {
            return Err(RouteReceiptError::UnknownAsEvidence(field));
        }
    }
    Ok(())
}

fn typed_digest(hex: String) -> Result<LowercaseSha256, RouteReceiptError> {
    serde_json::from_value(serde_json::Value::String(hex)).map_err(|_| RouteReceiptError::Digest)
}

/// Typed Governor route-receipt failures. All arms fail closed without
/// parsing provider prose.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RouteReceiptError {
    /// A required text field is blank or whitespace-only.
    #[error("{0} must not be blank")]
    BlankField(&'static str),
    /// A text field carries a control character.
    #[error("{0} contains a control character")]
    ControlField(&'static str),
    /// No evidence reference was supplied for an observation.
    #[error("evidence_refs must contain at least one runtime evidence reference")]
    EmptyEvidence,
    /// Too many evidence references or an over-long reference.
    #[error("evidence_refs exceed the bounded receipt shape")]
    OversizeEvidence,
    /// The reserved `unknown` marker was supplied as if it were observed
    /// evidence. Unexposed facts must be `None`, not evidence.
    #[error("{0} must be None when unexposed; 'unknown' is not observed evidence")]
    UnknownAsEvidence(&'static str),
    /// An owned route fingerprint failed its own validation.
    #[error("route fingerprint is invalid: {0}")]
    InvalidRoute(&'static str),
    /// The attempt receipt does not bind the recorded requested route.
    #[error("attempt requested route does not match the actual receipt requested route")]
    RequestMismatch,
    /// Canonical digest computation or parsing failed.
    #[error("route digest failure")]
    Digest,
}

/// Runtime-observed route facts, sourced only from evidence-bearing
/// observations (runtime handshake, transport metadata, or equivalent).
///
/// `provider`, `model`, and `auth_billing` are `Some` exactly when the
/// runtime exposed an evidence-backed value; `None` means unexposed and
/// becomes the explicit [`UNKNOWN_ROUTE_FACT`] in the observed
/// fingerprint. Callers must never fill these from the requested route,
/// UI selection, or prompt text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeObservedFacts {
    pub host_family: String,
    pub adapter: String,
    pub protocol_transport: String,
    pub runtime_hash: LowercaseSha256,
    pub adapter_hash: LowercaseSha256,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub auth_billing: Option<String>,
    pub serializer_hash: LowercaseSha256,
    pub tool_semantics_hash: LowercaseSha256,
    pub reasoning_mode: String,
    pub continuation_behavior: String,
    pub feature_flags_hash: LowercaseSha256,
    /// Handshake digest / transport-metadata references backing this
    /// observation. At least one entry is required.
    pub evidence_refs: Vec<String>,
}

impl RuntimeObservedFacts {
    /// Validates the observed shape. Hash fields are proven by
    /// [`LowercaseSha256`] at the deserialization boundary; this validates
    /// the remaining text, the optional-fact rule, and the evidence bound.
    pub fn validate(&self) -> Result<(), RouteReceiptError> {
        for (field, value) in [
            ("host_family", &self.host_family),
            ("adapter", &self.adapter),
            ("protocol_transport", &self.protocol_transport),
            ("reasoning_mode", &self.reasoning_mode),
            ("continuation_behavior", &self.continuation_behavior),
        ] {
            validate_text(value, field)?;
        }
        validate_optional_fact(self.provider.as_ref(), "provider")?;
        validate_optional_fact(self.model.as_ref(), "model")?;
        validate_optional_fact(self.auth_billing.as_ref(), "auth_billing")?;
        validate_evidence_refs(&self.evidence_refs)?;
        Ok(())
    }
}

/// Canonical Governor receipt separating the policy-selected requested
/// route from the runtime-observed execution route (I3.4).
///
/// Disposition (issue #369): daemon-local Governor admission visibility
/// record, not a second provider-neutral physical-observation owner. The
/// provider-neutral owner is
/// `eliot_agent_api::PhysicalRouteObservationReceipt`; this receipt carries
/// no version, no digests, and no execution binding, and it is consumed only
/// inside this daemon crate (plus its caller-proof integration test). It
/// must not gain provider-neutral consumers or a cross-crate import path.
///
/// The requested route is the planning/configuration reference. The
/// observed route is built only from [`RuntimeObservedFacts`]; its
/// provider/model/billing fields are either evidence-backed values or the
/// explicit [`UNKNOWN_ROUTE_FACT`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActualRouteReceipt {
    /// Requested route selected by policy (planning/configuration).
    pub requested_route: RouteFingerprint,
    /// Route actually observed at runtime. Unexposed provider/model/billing
    /// facts read exactly `unknown`, never the requested value.
    pub observed_route: RouteFingerprint,
    /// Runtime evidence backing the observed route.
    pub evidence_refs: Vec<String>,
}

impl ActualRouteReceipt {
    /// Records one execution attempt's routing evidence: the requested
    /// route plus an observed route built exclusively from runtime
    /// evidence. Observed provider/model/billing default to `unknown`
    /// when the runtime did not expose them.
    pub fn observe(
        requested_route: RouteFingerprint,
        observed: &RuntimeObservedFacts,
    ) -> Result<Self, RouteReceiptError> {
        requested_route
            .validate()
            .map_err(|_| RouteReceiptError::InvalidRoute("requested_route"))?;
        observed.validate()?;
        let observed_route = RouteFingerprint {
            host_family: observed.host_family.clone(),
            adapter: observed.adapter.clone(),
            protocol_transport: observed.protocol_transport.clone(),
            runtime_hash: observed.runtime_hash.clone(),
            adapter_hash: observed.adapter_hash.clone(),
            provider: observed
                .provider
                .clone()
                .unwrap_or_else(|| UNKNOWN_ROUTE_FACT.to_owned()),
            model: observed
                .model
                .clone()
                .unwrap_or_else(|| UNKNOWN_ROUTE_FACT.to_owned()),
            auth_billing: observed
                .auth_billing
                .clone()
                .unwrap_or_else(|| UNKNOWN_ROUTE_FACT.to_owned()),
            serializer_hash: observed.serializer_hash.clone(),
            tool_semantics_hash: observed.tool_semantics_hash.clone(),
            reasoning_mode: observed.reasoning_mode.clone(),
            continuation_behavior: observed.continuation_behavior.clone(),
            feature_flags_hash: observed.feature_flags_hash.clone(),
        };
        observed_route
            .validate()
            .map_err(|_| RouteReceiptError::InvalidRoute("observed_route"))?;
        Ok(Self {
            requested_route,
            observed_route,
            evidence_refs: observed.evidence_refs.clone(),
        })
    }

    /// Validates both fingerprints and the evidence bound.
    pub fn validate(&self) -> Result<(), RouteReceiptError> {
        self.requested_route
            .validate()
            .map_err(|_| RouteReceiptError::InvalidRoute("requested_route"))?;
        self.observed_route
            .validate()
            .map_err(|_| RouteReceiptError::InvalidRoute("observed_route"))?;
        validate_evidence_refs(&self.evidence_refs)?;
        Ok(())
    }

    /// True when the runtime did not expose the provider fact.
    #[must_use]
    pub fn provider_unobserved(&self) -> bool {
        self.observed_route.provider == UNKNOWN_ROUTE_FACT
    }

    /// True when the runtime did not expose the model fact.
    #[must_use]
    pub fn model_unobserved(&self) -> bool {
        self.observed_route.model == UNKNOWN_ROUTE_FACT
    }

    /// True when the runtime did not expose the billing fact.
    #[must_use]
    pub fn billing_unobserved(&self) -> bool {
        self.observed_route.auth_billing == UNKNOWN_ROUTE_FACT
    }

    /// Deterministic field-level difference classification between the
    /// requested and observed fingerprints, in canonical field order.
    /// Empty means field-complete equality.
    #[must_use]
    pub fn diverged_fields(&self) -> Vec<String> {
        route_divergence_fields(&self.requested_route, &self.observed_route)
    }
}

/// Computes the effective route key: the canonical digest of the complete
/// fingerprint bytes.
///
/// Routing evidence, capability lookup, and outcome-profile lookup must all
/// key off this value rather than provider/model labels alone, so any
/// behavior-bearing change (serializer, tool-call ordering, reasoning,
/// continuation, feature flags, hashes) yields a different key.
pub fn effective_route_key(route: &RouteFingerprint) -> Result<LowercaseSha256, RouteReceiptError> {
    route
        .validate()
        .map_err(|_| RouteReceiptError::InvalidRoute("route"))?;
    let bytes = canonical_json_bytes(route).map_err(|_| RouteReceiptError::Digest)?;
    typed_digest(sha256_hex(&bytes))
}

/// Governor in-memory index of capability/outcome evidence keyed by the
/// complete effective fingerprint.
///
/// Two fingerprints that differ only by serializer or tool-call ordering
/// hash to different keys and therefore never share evidence entries.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RouteCapabilityIndex {
    entries: BTreeMap<String, LowercaseSha256>,
}

impl RouteCapabilityIndex {
    /// Creates an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Records capability/outcome evidence for the exact fingerprint.
    pub fn insert(
        &mut self,
        route: &RouteFingerprint,
        evidence: LowercaseSha256,
    ) -> Result<(), RouteReceiptError> {
        let key = effective_route_key(route)?;
        self.entries.insert(key.as_str().to_owned(), evidence);
        Ok(())
    }

    /// Looks up evidence for the exact fingerprint. Returns `None` when no
    /// evidence was recorded for this complete fingerprint, even if a
    /// provider/model-identical sibling exists under a different key.
    pub fn lookup(
        &self,
        route: &RouteFingerprint,
    ) -> Result<Option<&LowercaseSha256>, RouteReceiptError> {
        let key = effective_route_key(route)?;
        Ok(self.entries.get(key.as_str()))
    }

    /// Number of distinct effective fingerprints with recorded evidence.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no evidence is recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// One Governor execution attempt's routing record: the policy-selected
/// requested route plus the separated observed-route receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernorRouteAttempt {
    pub attempt_id: AttemptId,
    pub requested_route: RouteFingerprint,
    pub actual: ActualRouteReceipt,
}

impl GovernorRouteAttempt {
    /// Records an attempt. Fails closed when the receipt's requested route
    /// does not equal the policy-selected requested route.
    pub fn new(
        attempt_id: AttemptId,
        requested_route: RouteFingerprint,
        actual: ActualRouteReceipt,
    ) -> Result<Self, RouteReceiptError> {
        requested_route
            .validate()
            .map_err(|_| RouteReceiptError::InvalidRoute("requested_route"))?;
        actual.validate()?;
        if actual.requested_route != requested_route {
            return Err(RouteReceiptError::RequestMismatch);
        }
        Ok(Self {
            attempt_id,
            requested_route,
            actual,
        })
    }

    /// Validates the attempt linkage.
    pub fn validate(&self) -> Result<(), RouteReceiptError> {
        self.requested_route
            .validate()
            .map_err(|_| RouteReceiptError::InvalidRoute("requested_route"))?;
        self.actual.validate()?;
        if self.actual.requested_route != self.requested_route {
            return Err(RouteReceiptError::RequestMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(hex_char: char) -> Result<LowercaseSha256, serde_json::Error> {
        let hex: String = std::iter::repeat_n(hex_char, 64).collect();
        serde_json::from_value(serde_json::Value::String(hex))
    }

    fn requested_route() -> Result<RouteFingerprint, serde_json::Error> {
        Ok(RouteFingerprint {
            host_family: "opencode".to_owned(),
            adapter: "eliot-opencode-adapter".to_owned(),
            protocol_transport: "HTTP+SSE".to_owned(),
            runtime_hash: digest('a')?,
            adapter_hash: digest('b')?,
            provider: "configured-provider".to_owned(),
            model: "configured-model".to_owned(),
            auth_billing: "configured-billing".to_owned(),
            serializer_hash: digest('c')?,
            tool_semantics_hash: digest('d')?,
            reasoning_mode: "reasoning-visible".to_owned(),
            continuation_behavior: "native-resume".to_owned(),
            feature_flags_hash: digest('e')?,
        })
    }

    fn unexposed_facts() -> Result<RuntimeObservedFacts, serde_json::Error> {
        Ok(RuntimeObservedFacts {
            host_family: "opencode".to_owned(),
            adapter: "eliot-opencode-adapter".to_owned(),
            protocol_transport: "HTTP+SSE".to_owned(),
            runtime_hash: digest('a')?,
            adapter_hash: digest('b')?,
            provider: None,
            model: None,
            auth_billing: None,
            serializer_hash: digest('c')?,
            tool_semantics_hash: digest('d')?,
            reasoning_mode: "reasoning-visible".to_owned(),
            continuation_behavior: "native-resume".to_owned(),
            feature_flags_hash: digest('e')?,
            evidence_refs: vec!["handshake:session-1".to_owned()],
        })
    }

    #[test]
    fn requested_and_observed_are_recorded_separately_with_unknown_for_unexposed_facts()
    -> Result<(), Box<dyn std::error::Error>> {
        let requested = requested_route()?;
        let facts = unexposed_facts()?;
        let receipt = ActualRouteReceipt::observe(requested.clone(), &facts)?;
        receipt.validate()?;
        // Requested policy selection is preserved verbatim.
        assert_eq!(receipt.requested_route, requested);
        // Unexposed runtime facts are explicit `unknown`, never inferred
        // from the requested route.
        assert_eq!(receipt.observed_route.provider, UNKNOWN_ROUTE_FACT);
        assert_eq!(receipt.observed_route.model, UNKNOWN_ROUTE_FACT);
        assert_eq!(receipt.observed_route.auth_billing, UNKNOWN_ROUTE_FACT);
        assert!(receipt.provider_unobserved());
        assert!(receipt.model_unobserved());
        assert!(receipt.billing_unobserved());
        assert_ne!(
            receipt.observed_route.provider, requested.provider,
            "observed provider must not be inferred from the requested route"
        );

        let attempt = GovernorRouteAttempt::new(
            AttemptId::new("attempt-1")?,
            requested.clone(),
            receipt.clone(),
        )?;
        attempt.validate()?;
        assert_eq!(attempt.requested_route, requested);
        assert_eq!(attempt.actual, receipt);
        Ok(())
    }

    #[test]
    fn evidence_backed_observed_values_are_preserved_not_inferred()
    -> Result<(), Box<dyn std::error::Error>> {
        let requested = requested_route()?;
        let mut facts = unexposed_facts()?;
        facts.provider = Some("observed-provider".to_owned());
        facts.model = Some("observed-model".to_owned());
        facts.auth_billing = Some("observed-billing".to_owned());
        let receipt = ActualRouteReceipt::observe(requested, &facts)?;
        assert_eq!(receipt.observed_route.provider, "observed-provider");
        assert_eq!(receipt.observed_route.model, "observed-model");
        assert_eq!(receipt.observed_route.auth_billing, "observed-billing");
        assert!(!receipt.provider_unobserved());
        Ok(())
    }

    #[test]
    fn serializer_or_tool_ordering_change_yields_distinct_fingerprint_and_no_capability_reuse()
    -> Result<(), Box<dyn std::error::Error>> {
        let base = requested_route()?;
        let mut serializer_variant = base.clone();
        serializer_variant.serializer_hash = digest('f')?;
        let mut tool_variant = base.clone();
        tool_variant.tool_semantics_hash = digest('9')?;

        assert_ne!(
            effective_route_key(&base)?.as_str(),
            effective_route_key(&serializer_variant)?.as_str()
        );
        assert_ne!(
            effective_route_key(&base)?.as_str(),
            effective_route_key(&tool_variant)?.as_str()
        );
        assert!(!route_divergence_fields(&base, &serializer_variant).is_empty());
        assert!(
            route_divergence_fields(&base, &serializer_variant)
                .contains(&"serializer_hash".to_owned())
        );
        assert!(
            route_divergence_fields(&base, &tool_variant)
                .contains(&"tool_semantics_hash".to_owned())
        );

        let mut index = RouteCapabilityIndex::new();
        index.insert(&base, digest('1')?)?;
        assert_eq!(
            index.lookup(&base)?.map(LowercaseSha256::as_str),
            Some(digest('1')?.as_str())
        );
        assert_eq!(index.lookup(&serializer_variant)?, None);
        assert_eq!(index.lookup(&tool_variant)?, None);
        Ok(())
    }

    #[test]
    fn unknown_marker_is_reserved_case_insensitively() -> Result<(), Box<dyn std::error::Error>> {
        let requested = requested_route()?;
        // No spelling variant of the reserved marker may pose as observed
        // evidence; unexposed facts must be `None`.
        for spelling in ["unknown", "Unknown", "UNKNOWN", "uNkNoWn"] {
            let mut facts = unexposed_facts()?;
            facts.provider = Some(spelling.to_owned());
            let Err(error) = ActualRouteReceipt::observe(requested.clone(), &facts) else {
                return Err(format!("reserved marker {spelling:?} was admitted").into());
            };
            assert!(
                matches!(error, RouteReceiptError::UnknownAsEvidence("provider")),
                "unexpected refusal for {spelling:?}: {error:?}"
            );
        }
        Ok(())
    }
}
