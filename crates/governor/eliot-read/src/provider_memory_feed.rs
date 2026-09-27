//! Read-only import surface for provider-native memory.
//!
//! Provider results remain scoped source candidates. This module has no write
//! port and no representation for canonical policy or current position. A
//! caller proposing a durable-memory or policy change must use the ordinary
//! capture/reconciliation flow and its authority checks; this module cannot
//! perform or authorize that transition.

use std::{collections::BTreeSet, io, io::Write, num::NonZeroUsize};

use eliot_store_api::ScopeId;
use schemars::JsonSchema;
use serde::Serialize;
use thiserror::Error;

use crate::ProvenanceHandle;

/// Stable capability name for the optional provider-memory read adapter.
pub const MEMORY_PROVIDER_FEED_CAPABILITY: &str = "memory.provider_feed";

/// Exact closed capability identity returned by this module.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub enum ProviderMemoryFeedCapability {
    /// The optional provider-memory feed capability.
    #[serde(rename = "memory.provider_feed")]
    MemoryProviderFeed,
}

impl ProviderMemoryFeedCapability {
    /// Returns the stable capability name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        MEMORY_PROVIDER_FEED_CAPABILITY
    }
}

/// The only authority a provider-memory source candidate can carry.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub enum ProviderMemoryCandidateAuthority {
    /// Candidate input only; it is not canonical policy, current position, or
    /// durable memory and grants no promotion authority.
    #[serde(rename = "candidate_only")]
    CandidateOnly,
}

/// Validation failures while constructing or reading a provider feed.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderMemoryFeedError {
    /// A required profile or candidate text field was blank or malformed.
    #[error("invalid provider-memory text field: {field}")]
    InvalidText {
        /// Name of the rejected field.
        field: &'static str,
    },
    /// A profile fact claimed a basis that requires evidence but supplied no
    /// evidence handles.
    #[error("provider-memory profile fact {field} requires an evidence handle")]
    MissingFactEvidence {
        /// Name of the profile fact without evidence.
        field: &'static str,
    },
    /// One handle was repeated within a profile or candidate evidence list.
    #[error("duplicate provider-memory evidence handle in {field}")]
    DuplicateEvidenceHandle {
        /// Name of the handle collection with a duplicate.
        field: &'static str,
    },
    /// An adapter returned a candidate outside the requested exact user scope.
    #[error("provider-memory candidate {candidate_index} has a different user scope")]
    CandidateScopeMismatch {
        /// Zero-based index of the mismatched candidate in the adapter result.
        candidate_index: usize,
    },
    /// An adapter returned more candidates than the request allowed.
    #[error("provider-memory feed returned {observed} candidates above limit {limit}")]
    CandidateLimitExceeded {
        /// Requested candidate limit.
        limit: usize,
        /// Number of candidates returned.
        observed: usize,
    },
    /// An adapter returned an empty Available result instead of the explicit
    /// The explicit no-results outcome.
    #[error("empty provider-memory result must use the no_results outcome")]
    EmptyAvailableResult,
    /// The serialized capability result exceeded the caller's explicit bound.
    #[error("provider-memory feed response is above limit {limit} bytes")]
    ResponseLimitExceeded {
        /// Requested serialized response limit.
        limit: usize,
    },
    /// The typed result could not be serialized for response-bound checking.
    #[error("provider-memory feed response could not be serialized")]
    Serialization,
}

/// Non-empty profile text supplied by the provider adapter.
///
/// Values are descriptive declarations, not ELIOT policy. Unknown or
/// unavailable provider semantics must be stated explicitly by the caller.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ProviderMemoryProfileText(String);

impl ProviderMemoryProfileText {
    /// Creates a non-blank, control-character-free profile value.
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderMemoryFeedError> {
        let value = value.into();
        validate_profile_text(&value, "profile_text")?;
        Ok(Self(value))
    }

    /// Returns the exact declared text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Explicit basis for one provider-surface declaration.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMemoryFactBasis {
    /// The provider explicitly declared the accompanying fact.
    ProviderDeclared,
    /// An exact evidence handle supports the accompanying fact.
    EvidenceLinked,
    /// The fact is explicitly unknown to the adapter.
    Unknown,
    /// The provider surface explicitly reports the fact as unavailable.
    Unavailable,
}

/// A required, displayed provider-surface fact and its evidence lineage.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProviderMemorySurfaceFact {
    basis: ProviderMemoryFactBasis,
    statement: ProviderMemoryProfileText,
    evidence_handles: Vec<ProvenanceHandle>,
}

impl ProviderMemorySurfaceFact {
    /// Constructs one explicit surface fact.
    ///
    /// Provider-declared and evidence-linked facts require at least one exact
    /// evidence handle. Unknown and unavailable remain explicit states and
    /// require a non-blank statement explaining the displayed value.
    pub fn new(
        field: &'static str,
        basis: ProviderMemoryFactBasis,
        statement: ProviderMemoryProfileText,
        evidence_handles: Vec<ProvenanceHandle>,
    ) -> Result<Self, ProviderMemoryFeedError> {
        ensure_unique_handles(field, &evidence_handles)?;
        if matches!(
            basis,
            ProviderMemoryFactBasis::ProviderDeclared | ProviderMemoryFactBasis::EvidenceLinked
        ) && evidence_handles.is_empty()
        {
            return Err(ProviderMemoryFeedError::MissingFactEvidence { field });
        }
        Ok(Self {
            basis,
            statement,
            evidence_handles,
        })
    }

    /// Returns the basis for the displayed statement.
    #[must_use]
    pub const fn basis(&self) -> ProviderMemoryFactBasis {
        self.basis
    }

    /// Returns the exact statement shown for this profile fact.
    #[must_use]
    pub const fn statement(&self) -> &ProviderMemoryProfileText {
        &self.statement
    }

    /// Returns the exact evidence handles attached to the fact.
    #[must_use]
    pub fn evidence_handles(&self) -> &[ProvenanceHandle] {
        &self.evidence_handles
    }
}

/// Explicit poisoning-risk characterization for a provider-memory surface.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMemoryPoisoningRiskLevel {
    /// No assessment is available.
    Unassessed,
    /// The adapter does not know the risk level.
    Unknown,
    /// The evidence characterizes the risk as low.
    Low,
    /// The evidence characterizes the risk as elevated.
    Elevated,
    /// The evidence characterizes the risk as high.
    High,
}

/// Poisoning-risk label, explanation, and any supporting evidence handles.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProviderMemoryPoisoningRisk {
    level: ProviderMemoryPoisoningRiskLevel,
    characterization: ProviderMemoryProfileText,
    evidence_handles: Vec<ProvenanceHandle>,
}

impl ProviderMemoryPoisoningRisk {
    /// Creates an explicit poisoning-risk characterization.
    ///
    /// Assessed levels require supporting evidence. Unassessed and Unknown
    /// remain displayable candidate metadata and do not imply safety.
    pub fn new(
        level: ProviderMemoryPoisoningRiskLevel,
        characterization: ProviderMemoryProfileText,
        evidence_handles: Vec<ProvenanceHandle>,
    ) -> Result<Self, ProviderMemoryFeedError> {
        ensure_unique_handles("poisoning_risk", &evidence_handles)?;
        if matches!(
            level,
            ProviderMemoryPoisoningRiskLevel::Low
                | ProviderMemoryPoisoningRiskLevel::Elevated
                | ProviderMemoryPoisoningRiskLevel::High
        ) && evidence_handles.is_empty()
        {
            return Err(ProviderMemoryFeedError::MissingFactEvidence {
                field: "poisoning_risk",
            });
        }
        Ok(Self {
            level,
            characterization,
            evidence_handles,
        })
    }

    /// Returns the explicit risk level.
    #[must_use]
    pub const fn level(&self) -> ProviderMemoryPoisoningRiskLevel {
        self.level
    }

    /// Returns the exact risk characterization statement.
    #[must_use]
    pub const fn characterization(&self) -> &ProviderMemoryProfileText {
        &self.characterization
    }

    /// Returns the exact evidence handles attached to the assessment.
    #[must_use]
    pub fn evidence_handles(&self) -> &[ProvenanceHandle] {
        &self.evidence_handles
    }
}

/// Explicit fallback behavior for the actual model route.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMemoryFallbackRoute {
    /// The adapter declares that no fallback route is configured.
    NoFallback,
    /// The exact declared fallback model or route identity.
    Fallback(ProviderMemoryProfileText),
}

/// Actual model route and evidence required for each imported surface.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProviderMemoryModelRoute {
    actual_model: ProviderMemoryProfileText,
    fallback: ProviderMemoryFallbackRoute,
    evidence_handles: Vec<ProvenanceHandle>,
}

impl ProviderMemoryModelRoute {
    /// Creates a fully stated primary and fallback route.
    ///
    /// The actual model is mandatory. The fallback must be explicitly
    /// the explicit no-fallback variant or carry its exact declared route; route evidence cannot be
    /// omitted.
    pub fn new(
        actual_model: ProviderMemoryProfileText,
        fallback: ProviderMemoryFallbackRoute,
        evidence_handles: Vec<ProvenanceHandle>,
    ) -> Result<Self, ProviderMemoryFeedError> {
        ensure_unique_handles("model_route", &evidence_handles)?;
        if evidence_handles.is_empty() {
            return Err(ProviderMemoryFeedError::MissingFactEvidence {
                field: "model_route",
            });
        }
        Ok(Self {
            actual_model,
            fallback,
            evidence_handles,
        })
    }

    /// Returns the exact actual model route.
    #[must_use]
    pub const fn actual_model(&self) -> &ProviderMemoryProfileText {
        &self.actual_model
    }

    /// Returns the explicit fallback route declaration.
    #[must_use]
    pub const fn fallback(&self) -> &ProviderMemoryFallbackRoute {
        &self.fallback
    }

    /// Returns the exact route evidence handles.
    #[must_use]
    pub fn evidence_handles(&self) -> &[ProvenanceHandle] {
        &self.evidence_handles
    }
}

/// Required construction fields for a complete provider-memory surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderMemorySurfaceProfileInput {
    /// Exact provider name or identifier shown to the reader.
    pub provider: ProviderMemoryProfileText,
    /// Provider-native memory type shown to the reader.
    pub memory_type: ProviderMemoryProfileText,
    /// Explicit retention semantics, including an explicit unknown state.
    pub retention: ProviderMemorySurfaceFact,
    /// Explicit export semantics, including an explicit unknown state.
    pub export: ProviderMemorySurfaceFact,
    /// Explicit deletion semantics, including an explicit unknown state.
    pub deletion: ProviderMemorySurfaceFact,
    /// Provider scoping behavior and user controls for this surface.
    pub scope_and_user_controls: ProviderMemorySurfaceFact,
    /// Explicit source-assurance characterization.
    pub source_assurance: ProviderMemorySurfaceFact,
    /// Explicit poisoning-risk characterization.
    pub poisoning_risk: ProviderMemoryPoisoningRisk,
    /// Actual model and explicit fallback route.
    pub model_route: ProviderMemoryModelRoute,
}

/// Complete, validated facts needed to display an imported provider surface.
///
/// Every field is mandatory at construction. A fact may explicitly say
/// Unknown or Unavailable, but omission is not a valid profile. Candidate
/// imports always carry this whole profile.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProviderMemorySurfaceProfile {
    provider: ProviderMemoryProfileText,
    memory_type: ProviderMemoryProfileText,
    retention: ProviderMemorySurfaceFact,
    export: ProviderMemorySurfaceFact,
    deletion: ProviderMemorySurfaceFact,
    scope_and_user_controls: ProviderMemorySurfaceFact,
    source_assurance: ProviderMemorySurfaceFact,
    poisoning_risk: ProviderMemoryPoisoningRisk,
    model_route: ProviderMemoryModelRoute,
}

impl ProviderMemorySurfaceProfile {
    /// Constructs a profile with all provider, semantics, assurance, risk,
    /// scope, and route fields present.
    #[must_use]
    pub fn new(input: ProviderMemorySurfaceProfileInput) -> Self {
        Self {
            provider: input.provider,
            memory_type: input.memory_type,
            retention: input.retention,
            export: input.export,
            deletion: input.deletion,
            scope_and_user_controls: input.scope_and_user_controls,
            source_assurance: input.source_assurance,
            poisoning_risk: input.poisoning_risk,
            model_route: input.model_route,
        }
    }

    /// Returns the displayed provider identity.
    #[must_use]
    pub const fn provider(&self) -> &ProviderMemoryProfileText {
        &self.provider
    }

    /// Returns the displayed provider-native memory type.
    #[must_use]
    pub const fn memory_type(&self) -> &ProviderMemoryProfileText {
        &self.memory_type
    }

    /// Returns the explicit retention semantics.
    #[must_use]
    pub const fn retention(&self) -> &ProviderMemorySurfaceFact {
        &self.retention
    }

    /// Returns the explicit export semantics.
    #[must_use]
    pub const fn export(&self) -> &ProviderMemorySurfaceFact {
        &self.export
    }

    /// Returns the explicit deletion semantics.
    #[must_use]
    pub const fn deletion(&self) -> &ProviderMemorySurfaceFact {
        &self.deletion
    }

    /// Returns provider scoping behavior and user controls.
    #[must_use]
    pub const fn scope_and_user_controls(&self) -> &ProviderMemorySurfaceFact {
        &self.scope_and_user_controls
    }

    /// Returns the explicit source-assurance characterization.
    #[must_use]
    pub const fn source_assurance(&self) -> &ProviderMemorySurfaceFact {
        &self.source_assurance
    }

    /// Returns the explicit poisoning-risk characterization.
    #[must_use]
    pub const fn poisoning_risk(&self) -> &ProviderMemoryPoisoningRisk {
        &self.poisoning_risk
    }

    /// Returns the exact actual and fallback model route.
    #[must_use]
    pub const fn model_route(&self) -> &ProviderMemoryModelRoute {
        &self.model_route
    }
}

/// Exact untrusted text imported from one provider-memory item.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ProviderMemoryCandidateContent(String);

impl ProviderMemoryCandidateContent {
    /// Creates a non-blank candidate while preserving its exact text.
    ///
    /// Line breaks and tabs are retained. Other control characters are
    /// refused. Content remains untrusted provider input and is never
    /// interpreted as canonical state by this module.
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderMemoryFeedError> {
        let value = value.into();
        if value.trim().is_empty()
            || value
                .chars()
                .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        {
            return Err(ProviderMemoryFeedError::InvalidText {
                field: "candidate_content",
            });
        }
        Ok(Self(value))
    }

    /// Returns the exact untrusted provider text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One exact-scope imported provider item with provenance and full profile.
///
/// The only authority value is the candidate-only variant.
/// This type contains no canonical policy/current-position fields and has no
/// operation that can promote or persist the candidate.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProviderMemorySourceCandidate {
    user_scope: ScopeId,
    source_handle: ProvenanceHandle,
    evidence_handles: Vec<ProvenanceHandle>,
    content: ProviderMemoryCandidateContent,
    surface_profile: ProviderMemorySurfaceProfile,
    authority: ProviderMemoryCandidateAuthority,
}

impl ProviderMemorySourceCandidate {
    /// Creates one fully profiled candidate for the caller's exact user scope.
    pub fn new(
        user_scope: ScopeId,
        source_handle: ProvenanceHandle,
        evidence_handles: Vec<ProvenanceHandle>,
        content: ProviderMemoryCandidateContent,
        surface_profile: ProviderMemorySurfaceProfile,
    ) -> Result<Self, ProviderMemoryFeedError> {
        ensure_unique_handles("candidate", &evidence_handles)?;
        if evidence_handles.contains(&source_handle) {
            return Err(ProviderMemoryFeedError::DuplicateEvidenceHandle { field: "candidate" });
        }
        Ok(Self {
            user_scope,
            source_handle,
            evidence_handles,
            content,
            surface_profile,
            authority: ProviderMemoryCandidateAuthority::CandidateOnly,
        })
    }

    /// Returns the exact user scope supplied by the request.
    #[must_use]
    pub const fn user_scope(&self) -> &ScopeId {
        &self.user_scope
    }

    /// Returns the provider's exact source item handle.
    #[must_use]
    pub const fn source_handle(&self) -> &ProvenanceHandle {
        &self.source_handle
    }

    /// Returns supplemental exact provenance/evidence handles.
    #[must_use]
    pub fn evidence_handles(&self) -> &[ProvenanceHandle] {
        &self.evidence_handles
    }

    /// Returns the exact untrusted source content.
    #[must_use]
    pub const fn content(&self) -> &ProviderMemoryCandidateContent {
        &self.content
    }

    /// Returns the complete provider-memory surface profile.
    #[must_use]
    pub const fn surface_profile(&self) -> &ProviderMemorySurfaceProfile {
        &self.surface_profile
    }

    /// Returns the closed candidate-only authority marker.
    #[must_use]
    pub const fn authority(&self) -> ProviderMemoryCandidateAuthority {
        self.authority
    }
}

/// Exact scope and caller-declared response bounds for one feed read.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProviderMemoryReadRequest {
    user_scope: ScopeId,
    max_candidates: NonZeroUsize,
    max_response_bytes: NonZeroUsize,
}

impl ProviderMemoryReadRequest {
    /// Creates a bounded read request for one exact user scope.
    #[must_use]
    pub const fn new(
        user_scope: ScopeId,
        max_candidates: NonZeroUsize,
        max_response_bytes: NonZeroUsize,
    ) -> Self {
        Self {
            user_scope,
            max_candidates,
            max_response_bytes,
        }
    }

    /// Returns the exact requested user scope.
    #[must_use]
    pub const fn user_scope(&self) -> &ScopeId {
        &self.user_scope
    }

    /// Returns the maximum accepted candidate count.
    #[must_use]
    pub const fn max_candidates(&self) -> NonZeroUsize {
        self.max_candidates
    }

    /// Returns the maximum serialized response size.
    #[must_use]
    pub const fn max_response_bytes(&self) -> NonZeroUsize {
        self.max_response_bytes
    }
}

/// Why a provider feed could not produce a usable result.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMemoryFeedUnavailableReason {
    /// No provider-memory adapter is configured.
    AdapterNotConfigured,
    /// The adapter or provider surface is disabled.
    Disabled,
    /// The provider surface reports that it is unavailable.
    ProviderUnavailable,
    /// The adapter could not reach the provider transport.
    TransportFailure,
}

/// Why a feed could return only a degraded candidate set.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMemoryFeedDegradationReason {
    /// The adapter has evidence that its returned set is incomplete.
    PartialRead,
    /// The provider reports a bounded or reduced feed capability.
    CapabilityLimited,
}

/// Feed outcome that distinguishes items, true no-results, degradation, and
/// unavailability.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMemoryFeedOutcome {
    /// A complete, non-empty read of the requested scope.
    Available {
        /// Fully profiled candidates in the requested exact user scope.
        candidates: Vec<ProviderMemorySourceCandidate>,
    },
    /// The feed completed for the requested scope and returned no items.
    NoResults,
    /// The feed returned candidates but explicitly reports reduced coverage.
    Degraded {
        /// Cause of the degraded result.
        reason: ProviderMemoryFeedDegradationReason,
        /// Any candidates returned, each with a complete surface profile.
        candidates: Vec<ProviderMemorySourceCandidate>,
    },
    /// No candidate result is available for the requested scope.
    Unavailable {
        /// Exact reason the capability is unavailable.
        reason: ProviderMemoryFeedUnavailableReason,
    },
}

/// Failure reported by the read-only provider adapter port.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMemoryFeedPortFailure {
    /// The provider transport failed before a result could be read.
    TransportFailure,
    /// The adapter or provider surface is disabled.
    Disabled,
    /// The provider surface reports that it is unavailable.
    ProviderUnavailable,
}

/// Read-only boundary implemented by an optional provider-memory adapter.
#[allow(async_fn_in_trait)]
pub trait ProviderMemoryFeedPort: Send + Sync {
    /// Reads only the request's exact user scope and declared response bounds.
    ///
    /// A completed empty read returns the no-results outcome. Partial data
    /// returns a degraded outcome with full-profile candidates. Absence and
    /// transport failures remain distinct from a completed empty read.
    async fn read(
        &self,
        request: &ProviderMemoryReadRequest,
    ) -> Result<ProviderMemoryFeedOutcome, ProviderMemoryFeedPortFailure>;
}

/// Capability status and scoped result for one provider-memory read attempt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProviderMemoryFeedResult {
    capability: ProviderMemoryFeedCapability,
    user_scope: ScopeId,
    outcome: ProviderMemoryFeedOutcome,
}

impl ProviderMemoryFeedResult {
    /// Returns the exact capability identity.
    #[must_use]
    pub const fn capability(&self) -> ProviderMemoryFeedCapability {
        self.capability
    }

    /// Returns the scope the capability result is bound to.
    #[must_use]
    pub const fn user_scope(&self) -> &ScopeId {
        &self.user_scope
    }

    /// Returns the explicit available, no-results, degraded, or unavailable
    /// outcome.
    #[must_use]
    pub const fn outcome(&self) -> &ProviderMemoryFeedOutcome {
        &self.outcome
    }
}

/// Reads a provider feed when configured and returns explicit unavailability
/// when no adapter exists.
///
/// Candidate scope and response bounds are checked again after the adapter
/// returns. A missing adapter never invokes model recollection or a fallback
/// model; it returns Unavailable(AdapterNotConfigured).
pub async fn read_provider_memory_feed<P: ProviderMemoryFeedPort + ?Sized>(
    adapter: Option<&P>,
    request: &ProviderMemoryReadRequest,
) -> Result<ProviderMemoryFeedResult, ProviderMemoryFeedError> {
    let Some(adapter) = adapter else {
        return provider_memory_feed_unavailable(request);
    };
    let outcome = match adapter.read(request).await {
        Ok(outcome) => outcome,
        Err(ProviderMemoryFeedPortFailure::TransportFailure) => {
            ProviderMemoryFeedOutcome::Unavailable {
                reason: ProviderMemoryFeedUnavailableReason::TransportFailure,
            }
        }
        Err(ProviderMemoryFeedPortFailure::Disabled) => ProviderMemoryFeedOutcome::Unavailable {
            reason: ProviderMemoryFeedUnavailableReason::Disabled,
        },
        Err(ProviderMemoryFeedPortFailure::ProviderUnavailable) => {
            ProviderMemoryFeedOutcome::Unavailable {
                reason: ProviderMemoryFeedUnavailableReason::ProviderUnavailable,
            }
        }
    };
    validate_outcome(request, &outcome)?;
    let result = ProviderMemoryFeedResult {
        capability: ProviderMemoryFeedCapability::MemoryProviderFeed,
        user_scope: request.user_scope.clone(),
        outcome,
    };
    validate_serialized_bound(&result, request.max_response_bytes)?;
    Ok(result)
}

/// Returns the explicit unavailable capability result when no adapter exists.
///
/// This non-generic entry point is callable without naming a provider adapter
/// type. It reports that no adapter is configured and never substitutes model
/// recollection.
pub fn provider_memory_feed_unavailable(
    request: &ProviderMemoryReadRequest,
) -> Result<ProviderMemoryFeedResult, ProviderMemoryFeedError> {
    let result = ProviderMemoryFeedResult {
        capability: ProviderMemoryFeedCapability::MemoryProviderFeed,
        user_scope: request.user_scope.clone(),
        outcome: ProviderMemoryFeedOutcome::Unavailable {
            reason: ProviderMemoryFeedUnavailableReason::AdapterNotConfigured,
        },
    };
    validate_serialized_bound(&result, request.max_response_bytes)?;
    Ok(result)
}

fn validate_outcome(
    request: &ProviderMemoryReadRequest,
    outcome: &ProviderMemoryFeedOutcome,
) -> Result<(), ProviderMemoryFeedError> {
    let candidates = match outcome {
        ProviderMemoryFeedOutcome::Available { candidates } => {
            if candidates.is_empty() {
                return Err(ProviderMemoryFeedError::EmptyAvailableResult);
            }
            candidates.as_slice()
        }
        ProviderMemoryFeedOutcome::Degraded { candidates, .. } => candidates.as_slice(),
        ProviderMemoryFeedOutcome::NoResults | ProviderMemoryFeedOutcome::Unavailable { .. } => {
            return Ok(());
        }
    };
    if candidates.len() > request.max_candidates.get() {
        return Err(ProviderMemoryFeedError::CandidateLimitExceeded {
            limit: request.max_candidates.get(),
            observed: candidates.len(),
        });
    }
    for (candidate_index, candidate) in candidates.iter().enumerate() {
        if candidate.user_scope != request.user_scope {
            return Err(ProviderMemoryFeedError::CandidateScopeMismatch { candidate_index });
        }
    }
    Ok(())
}

fn validate_serialized_bound(
    result: &ProviderMemoryFeedResult,
    limit: NonZeroUsize,
) -> Result<(), ProviderMemoryFeedError> {
    let mut writer = BoundedJsonWriter::new(limit.get());
    match serde_json::to_writer(&mut writer, result) {
        Ok(()) => Ok(()),
        Err(_) if writer.exceeded => {
            Err(ProviderMemoryFeedError::ResponseLimitExceeded { limit: limit.get() })
        }
        Err(_) => Err(ProviderMemoryFeedError::Serialization),
    }
}

struct BoundedJsonWriter {
    limit: usize,
    written: usize,
    exceeded: bool,
}

impl BoundedJsonWriter {
    const fn new(limit: usize) -> Self {
        Self {
            limit,
            written: 0,
            exceeded: false,
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let Some(next) = self.written.checked_add(buffer.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("provider-memory response size overflow"));
        };
        if next > self.limit {
            self.exceeded = true;
            return Err(io::Error::other("provider-memory response limit exceeded"));
        }
        self.written = next;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn validate_profile_text(value: &str, field: &'static str) -> Result<(), ProviderMemoryFeedError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ProviderMemoryFeedError::InvalidText { field });
    }
    Ok(())
}

fn ensure_unique_handles(
    field: &'static str,
    handles: &[ProvenanceHandle],
) -> Result<(), ProviderMemoryFeedError> {
    let mut unique = BTreeSet::new();
    for handle in handles {
        if !unique.insert(handle) {
            return Err(ProviderMemoryFeedError::DuplicateEvidenceHandle { field });
        }
    }
    Ok(())
}
