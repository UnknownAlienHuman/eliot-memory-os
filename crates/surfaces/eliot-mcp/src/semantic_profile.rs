//! One versioned semantic owner for every exposed tool method (I7.24).
//!
//! Every introduced tool version joins to exactly one ELIOT-owned
//! [`ToolSemanticProfile`]. Routers and Stage classifiers consume the profile;
//! they never infer retry, read-only, or completion behavior from tool names,
//! descriptions, or shell substrings. A method identity with no registered
//! profile is absent from the Material surface and cannot be selected for
//! mutation. Generated MCP/WIT/EBP operational projections are validated
//! against the same profile, and a semantic-version change invalidates
//! dependent Skills, packets, competence evidence, and projections.

use std::collections::{BTreeMap, BTreeSet};

use eliot_receipts::ProofCeiling;
use eliot_receipts::tool_exposure::{ExposureIdentities, OwnerStageFact};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CoordinateInput, ObserveInput, QueryMode, SchemaError, ToolRequest, ToolSchema, VerifyIntent,
    canonical_tool_schemas,
};

/// Failure to register, resolve, or validate a semantic profile.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SemanticProfileError {
    /// A required text field is blank or carries control characters.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText {
        /// Stable field path.
        field: &'static str,
    },
    /// A bounded numeric field is zero.
    #[error("{field} must be greater than zero")]
    NotPositive {
        /// Stable field path.
        field: &'static str,
    },
    /// A second profile was registered for the same method identity/version.
    #[error("duplicate semantic profile for {name}@{version}")]
    DuplicateProfile {
        /// Canonical method name.
        name: String,
        /// Tool definition version.
        version: String,
    },
    /// No profile is registered for the requested method identity/version.
    #[error("missing semantic profile for {name}@{version}")]
    MissingProfile {
        /// Requested method name.
        name: String,
        /// Requested tool definition version.
        version: String,
    },
    /// An operational projection disagrees with the single semantic owner.
    #[error("projection disagreement at {field}: {reason}")]
    ProjectionDisagreement {
        /// Stable field path.
        field: &'static str,
        /// Public bounded reason.
        reason: &'static str,
    },
}

/// I7.24 operation class. Stable hot-surface vocabulary.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationClass {
    /// Read-only observation of owner state.
    Observe,
    /// Orientation without evidence claims.
    Navigate,
    /// Candidate proposal awaiting admission.
    Propose,
    /// Governed state transition.
    Mutate,
    /// Typed verification run.
    Verify,
    /// Durable execution-fabric progress.
    Progress,
    /// Candidate finish attempt, never a decision.
    CompleteCandidate,
}

/// Effect class owned by the profile, never inferred from a name.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectClass {
    /// No state transition; safe to expose narrowly.
    ReadOnly,
    /// Bounded owner-state transition.
    ScopedMutation,
    /// Externally visible effect.
    ExternalEffect,
}

/// Idempotency contract owned by the profile.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdempotencyClass {
    /// Repeated identical calls are safe without a key.
    Idempotent,
    /// Safe retry requires the exact idempotency key.
    IdempotentWithKey,
    /// Must not be retried blindly.
    NonIdempotent,
}

/// Reversibility / compensation contract owned by the profile.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReversibilityClass {
    /// Directly reversible.
    Reversible,
    /// Reversed only via the named compensation.
    Compensatable,
    /// Cannot be reversed; must be fenced before execution.
    Irreversible,
}

/// Repetition, polling, pagination, and terminal semantics.
#[allow(
    clippy::struct_excessive_bools,
    reason = "I7.24 fixes four independent repetition flags; an enum would obscure the wire contract"
)]
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepetitionSemantics {
    /// Whether blind retry is safe (derived from idempotency, not the name).
    pub retry_safe: bool,
    /// Whether bounded polling is admitted.
    pub polling_admitted: bool,
    /// Whether handle-cursor pagination is admitted.
    pub pagination_admitted: bool,
    /// Whether this method can terminally complete a task.
    pub terminal_completion: bool,
}

/// Timeout, resource, and privacy profile.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeoutResourcePrivacy {
    /// Owner timeout bound in milliseconds.
    pub timeout_ms: u64,
    /// Maximum structured resource bytes.
    pub max_resource_bytes: u64,
    /// Privacy class label owned by the profile.
    pub privacy_class: String,
}

/// Compatibility and invalidation set carried by the profile.
#[allow(
    clippy::struct_excessive_bools,
    reason = "I7.24 fixes four independent invalidation targets; an enum would obscure the wire contract"
)]
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvalidationSet {
    /// A profile/definition version change invalidates dependent Skills.
    pub skills: bool,
    /// A profile/definition version change invalidates dependent packets.
    pub packets: bool,
    /// A profile/definition version change invalidates competence evidence.
    pub competence_evidence: bool,
    /// A profile/definition version change invalidates generated projections.
    pub projections: bool,
}

impl InvalidationSet {
    /// Full invalidation carried by every canonical profile.
    #[must_use]
    pub const fn full() -> Self {
        Self {
            skills: true,
            packets: true,
            competence_evidence: true,
            projections: true,
        }
    }
}

/// Stable versioned method identity. Distinct from vendor display names.
#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolMethodIdentity {
    /// Canonical method name (e.g. `eliot.state`).
    pub canonical_name: String,
    /// Exact owning Tool Definition version.
    pub definition_version: String,
}

/// One ELIOT-owned semantic profile: the single operational owner for one
/// versioned method identity, per I7.24.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSemanticProfile {
    /// Versioned method identity this profile governs.
    pub method: ToolMethodIdentity,
    /// Exact semantic-profile version. A change invalidates dependents.
    pub profile_version: String,
    /// I7.24 operation class.
    pub operation_class: OperationClass,
    /// I7.24 effect class.
    pub effect_class: EffectClass,
    /// Authority requirements (never inferred from prose).
    pub authority_requirements: Vec<String>,
    /// Introduction requirements (capability evidence, handshake, scope).
    pub introduction_requirements: Vec<String>,
    /// Idempotency contract.
    pub idempotency_class: IdempotencyClass,
    /// Reversibility / compensation contract.
    pub reversibility_class: ReversibilityClass,
    /// Named compensation when [`ReversibilityClass::Compensatable`].
    pub compensation: Option<String>,
    /// Expected result semantics.
    pub expected_result: String,
    /// Repetition / polling / pagination / terminal semantics.
    pub repetition: RepetitionSemantics,
    /// Strongest evidence interpretation permitted.
    pub evidence_ceiling: ProofCeiling,
    /// Strongest completion interpretation permitted.
    pub completion_ceiling: ProofCeiling,
    /// Timeout / resource / privacy profile.
    pub timeout_resource_privacy: TimeoutResourcePrivacy,
    /// Compatibility and invalidation set.
    pub invalidation_set: InvalidationSet,
}

impl ToolSemanticProfile {
    /// Validates all I7.24 fields without consulting names or prose.
    pub fn validate(&self) -> Result<(), SemanticProfileError> {
        non_blank(&self.method.canonical_name, "method.canonical_name")?;
        non_blank(&self.method.definition_version, "method.definition_version")?;
        non_blank(&self.profile_version, "profile_version")?;
        non_blank_list(&self.authority_requirements, "authority_requirements")?;
        non_blank_list(&self.introduction_requirements, "introduction_requirements")?;
        non_blank(&self.expected_result, "expected_result")?;
        match self.reversibility_class {
            ReversibilityClass::Compensatable => {
                let compensation = self.compensation.as_deref().unwrap_or_default();
                non_blank(compensation, "compensation")?;
            }
            _ => {
                if let Some(compensation) = &self.compensation {
                    non_blank(compensation, "compensation")?;
                }
            }
        }
        if self.timeout_resource_privacy.timeout_ms == 0 {
            return Err(SemanticProfileError::NotPositive {
                field: "timeout_resource_privacy.timeout_ms",
            });
        }
        if self.timeout_resource_privacy.max_resource_bytes == 0 {
            return Err(SemanticProfileError::NotPositive {
                field: "timeout_resource_privacy.max_resource_bytes",
            });
        }
        non_blank(
            &self.timeout_resource_privacy.privacy_class,
            "timeout_resource_privacy.privacy_class",
        )?;
        Ok(())
    }

    /// Routing-relevant read-only bit, owned by the profile.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        matches!(self.effect_class, EffectClass::ReadOnly)
    }

    /// Routing-relevant retry bit, owned by the profile.
    #[must_use]
    pub const fn is_retry_safe(&self) -> bool {
        self.repetition.retry_safe
    }
}

/// Router-visible decision derived exclusively from the profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutingDecision {
    /// Whether the method is read-only.
    pub read_only: bool,
    /// Whether blind retry is safe.
    pub retry_safe: bool,
    /// Strongest completion interpretation permitted.
    pub completion_ceiling: ProofCeiling,
}

/// Derives the routing decision from the profile, never from a name.
#[must_use]
pub const fn routing_decision(profile: &ToolSemanticProfile) -> RoutingDecision {
    RoutingDecision {
        read_only: profile.is_read_only(),
        retry_safe: profile.is_retry_safe(),
        completion_ceiling: profile.completion_ceiling,
    }
}

/// Canonical registry: one versioned profile per method identity/version.
#[derive(Clone, Debug, Default)]
pub struct SemanticRegistry {
    profiles: BTreeMap<(String, String), ToolSemanticProfile>,
}

impl SemanticRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            profiles: BTreeMap::new(),
        }
    }

    /// Registers one profile; rejects a second owner for the same identity.
    pub fn register(&mut self, profile: ToolSemanticProfile) -> Result<(), SemanticProfileError> {
        profile.validate()?;
        let key = (
            profile.method.canonical_name.clone(),
            profile.method.definition_version.clone(),
        );
        if self.profiles.contains_key(&key) {
            return Err(SemanticProfileError::DuplicateProfile {
                name: key.0,
                version: key.1,
            });
        }
        self.profiles.insert(key, profile);
        Ok(())
    }

    /// Resolves exactly one profile by method identity and version.
    ///
    /// No fallback, no substring match, no description sniffing: a missing
    /// entry is [`SemanticProfileError::MissingProfile`].
    pub fn resolve(
        &self,
        canonical_name: &str,
        definition_version: &str,
    ) -> Result<&ToolSemanticProfile, SemanticProfileError> {
        self.profiles
            .get(&(canonical_name.to_owned(), definition_version.to_owned()))
            .ok_or_else(|| SemanticProfileError::MissingProfile {
                name: canonical_name.to_owned(),
                version: definition_version.to_owned(),
            })
    }

    /// Resolves through a provider-alias table to the stable method identity.
    ///
    /// A vendor rename changes only the alias entry; the resolved profile —
    /// and therefore retry/read-only/completion behavior — is unchanged.
    pub fn resolve_via_provider_alias(
        &self,
        aliases: &BTreeMap<String, String>,
        provider_name: &str,
        definition_version: &str,
    ) -> Result<&ToolSemanticProfile, SemanticProfileError> {
        let canonical =
            aliases
                .get(provider_name)
                .ok_or_else(|| SemanticProfileError::MissingProfile {
                    name: provider_name.to_owned(),
                    version: definition_version.to_owned(),
                })?;
        self.resolve(canonical, definition_version)
    }

    /// Material surface: only identities with a registered profile are
    /// exposed. Missing profiles are omitted (fail-closed for effectful
    /// methods; no narrow observable fallback is synthesized here).
    #[must_use]
    pub fn material_surface<'a>(
        &'a self,
        candidates: &'a [ToolMethodIdentity],
    ) -> Vec<&'a ToolSemanticProfile> {
        candidates
            .iter()
            .filter_map(|identity| {
                self.profiles.get(&(
                    identity.canonical_name.clone(),
                    identity.definition_version.clone(),
                ))
            })
            .collect()
    }

    /// Whether the method may be selected for mutation. A missing profile is
    /// never mutation-selectable; read-only profiles are never selectable for
    /// mutation either.
    #[must_use]
    pub fn mutation_selectable(&self, canonical_name: &str, definition_version: &str) -> bool {
        self.resolve(canonical_name, definition_version)
            .is_ok_and(|profile| !profile.is_read_only())
    }

    /// Number of registered profiles.
    #[must_use]
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// Canonical method names in stable order.
    #[must_use]
    pub fn canonical_names(&self) -> Vec<String> {
        let mut names = BTreeSet::new();
        for (name, _) in self.profiles.keys() {
            names.insert(name.clone());
        }
        names.into_iter().collect()
    }

    /// Registered profiles in stable registry (key) order.
    pub fn profiles(&self) -> impl Iterator<Item = &ToolSemanticProfile> {
        self.profiles.values()
    }
}

/// Returns true when a semantic-profile version change invalidates dependent
/// Skills, packets, competence evidence, and generated projections before
/// Material reuse.
#[must_use]
pub const fn profile_version_changed(old_version: &str, new_version: &str) -> bool {
    // Byte-wise comparison: any version edit is a semantic change until an
    // owner proves otherwise. Length check first keeps the comparison
    // constant-shape for the common equal case.
    if old_version.len() != new_version.len() {
        return true;
    }
    let old = old_version.as_bytes();
    let new = new_version.as_bytes();
    let mut index = 0;
    while index < old.len() {
        if old[index] != new[index] {
            return true;
        }
        index += 1;
    }
    false
}

/// Invalidation set owed when the profile version changes.
#[must_use]
pub const fn invalidation_on_profile_change(
    old_version: &str,
    new_version: &str,
) -> Option<InvalidationSet> {
    if profile_version_changed(old_version, new_version) {
        Some(InvalidationSet::full())
    } else {
        None
    }
}

/// One generated operational projection (MCP/WIT/EBP view) claiming behavior
/// for a method identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalProjection {
    /// Canonical method name the view claims to project.
    pub canonical_name: String,
    /// Claimed retry safety.
    pub claimed_retry_safe: bool,
    /// Claimed read-only behavior.
    pub claimed_read_only: bool,
    /// Claimed completion ceiling.
    pub claimed_completion_ceiling: ProofCeiling,
}

/// Validates that one generated MCP/WIT/EBP view agrees with the single
/// semantic owner. Any disagreement fails closed.
pub fn validate_operational_projection(
    profile: &ToolSemanticProfile,
    projection: &OperationalProjection,
) -> Result<(), SemanticProfileError> {
    if projection.canonical_name != profile.method.canonical_name {
        return Err(SemanticProfileError::ProjectionDisagreement {
            field: "projection.canonical_name",
            reason: "view does not name the profiled method identity",
        });
    }
    let decision = routing_decision(profile);
    if projection.claimed_retry_safe != decision.retry_safe {
        return Err(SemanticProfileError::ProjectionDisagreement {
            field: "projection.retry_safe",
            reason: "view retry bit disagrees with the semantic owner",
        });
    }
    if projection.claimed_read_only != decision.read_only {
        return Err(SemanticProfileError::ProjectionDisagreement {
            field: "projection.read_only",
            reason: "view effect bit disagrees with the semantic owner",
        });
    }
    if projection.claimed_completion_ceiling != decision.completion_ceiling {
        return Err(SemanticProfileError::ProjectionDisagreement {
            field: "projection.completion_ceiling",
            reason: "view completion ceiling disagrees with the semantic owner",
        });
    }
    Ok(())
}

/// Exact Tool Definition version governed by this registry revision.
pub const CANONICAL_DEFINITION_VERSION: &str = "1.2.0";

/// Builds the canonical registry owning the eight hot-surface methods.
pub fn canonical_registry() -> Result<SemanticRegistry, SemanticProfileError> {
    let mut registry = SemanticRegistry::new();
    for profile in canonical_profiles() {
        registry.register(profile)?;
    }
    Ok(registry)
}

/// Process-wide canonical registry: the single runtime semantic owner.
///
/// Built on demand from [`canonical_profiles`] (eight validated inserts —
/// negligible beside any kernel round-trip); every frozen lookup below
/// resolves through a freshly built instance of this one source, so all
/// callers share one owner per method identity with no cached fork.
fn canonical_shared() -> Result<SemanticRegistry, SemanticProfileError> {
    canonical_registry()
}

/// FROZEN v1 Skill `KnownTools` lookup (`1944-skill-handoff.md`).
///
/// Resolves exactly one versioned semantic owner by canonical method name,
/// binding the definition version to [`CANONICAL_DEFINITION_VERSION`].
/// A missing profile is [`SemanticProfileError::MissingProfile`]: the caller
/// must treat the method as absent, never synthesize semantics from prose.
pub fn known_tool_profile(
    canonical_name: &str,
) -> Result<ToolSemanticProfile, SemanticProfileError> {
    canonical_shared()?
        .resolve(canonical_name, CANONICAL_DEFINITION_VERSION)
        .cloned()
}

/// FROZEN v1 Skill `KnownTools` enumeration (`1944-skill-handoff.md`).
///
/// Every `KnownTool` is a profile owned by the canonical registry — the set is
/// never constructed from ad-hoc strings, so one versioned method identity
/// keeps one operational semantics owner. Order is stable registry (key)
/// order; consumers look up by name and must not rely on positions.
pub fn canonical_known_tools() -> Result<Vec<ToolSemanticProfile>, SemanticProfileError> {
    Ok(canonical_shared()?.profiles().cloned().collect())
}

/// One of the eight canonical hot MCP operations, with its closed typed
/// suboperation where the contract defines one.
///
/// This is derived from the request enum, never from caller-supplied method
/// text, descriptions, or payload strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalOperation {
    /// Current state and task-selection projection.
    State,
    /// Active Understanding View compilation or refresh.
    Packet,
    /// Typed observation capture.
    Observe(ObserveSuboperation),
    /// Intent-bearing owner-filtered query.
    Query(QueryMode),
    /// Action-frame request.
    Act,
    /// Typed verifier operation.
    Verify(VerifyIntent),
    /// Execution-fabric operation.
    Coordinate(CoordinateSuboperation),
    /// Typed finish candidate.
    Finish,
}

/// Closed observation suboperations from the canonical Observe contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObserveSuboperation {
    /// Cold raw observation candidate.
    Observation,
    /// Cold decision candidate.
    Decision,
    /// Cold failure candidate.
    Failure,
    /// Cold outcome candidate.
    Outcome,
    /// Task-relative memory influence acknowledgement.
    InfluenceAck,
}

/// Closed execution-fabric suboperations from the canonical Coordinate
/// contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinateSuboperation {
    /// Create a bounded work item or attempt.
    Delegate,
    /// Request an independent audit.
    Audit,
    /// Compare isolated candidates.
    Compare,
    /// Await an authorized job's status.
    Wait,
    /// Inspect an authorized job's status and lineage.
    Inspect,
    /// Cancel or reconcile a run or subtree.
    Cancel,
    /// Send durable mailbox or attention content.
    Send,
}

/// Contract classification of an operation's task and effect boundary.
///
/// Every variant still requires an authenticated application session. This
/// classification describes the owner's requirements; it neither
/// authenticates nor admits a request and never grants effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationAccessClass {
    /// Authenticated discovery/read-only work available before task selection.
    AuthenticatedDiscoveryReadOnly,
    /// Authenticated, policy-bounded cold capture with no task effect.
    SafeRawCapture,
    /// Work that is task-relative or effectful and needs exact task evidence.
    TaskRelativeEffectful,
}

/// Existing owner evidence the dispatch path must require for a classified
/// request. Every variant includes an authenticated application session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequiredBindingEvidence {
    /// Exact authenticated session and its owner-filtered read scope.
    AuthenticatedSession,
    /// Authenticated identity plus valid privacy and cold-staging policy.
    CaptureIdentityPrivacyAndStaging,
    /// Exact applicable task selection/binding evidence.
    ExactApplicableTask,
    /// Exact authorized job binding; a job handle alone is not authority.
    ExactAuthorizedJob,
}

/// Typed, declarative operation requirement consumed by dispatch.
///
/// `access_class` is not a grant or admission decision. In particular,
/// `SafeRawCapture` cannot promote, bind, or otherwise affect a task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationRequirement {
    /// Canonical operation and typed suboperation.
    pub operation: CanonicalOperation,
    /// Access/effect class fixed by the accepted operation contract.
    pub access_class: OperationAccessClass,
    /// Exact authenticated scope evidence required from existing owners.
    pub binding_evidence: RequiredBindingEvidence,
}

impl CanonicalOperation {
    /// Returns the contract-owned access class and binding evidence.
    #[must_use]
    pub const fn requirement(self) -> OperationRequirement {
        let (access_class, binding_evidence) = match self {
            Self::State | Self::Query(_) => (
                OperationAccessClass::AuthenticatedDiscoveryReadOnly,
                RequiredBindingEvidence::AuthenticatedSession,
            ),
            Self::Observe(
                ObserveSuboperation::Observation
                | ObserveSuboperation::Decision
                | ObserveSuboperation::Failure
                | ObserveSuboperation::Outcome,
            ) => (
                OperationAccessClass::SafeRawCapture,
                RequiredBindingEvidence::CaptureIdentityPrivacyAndStaging,
            ),
            Self::Coordinate(CoordinateSuboperation::Wait | CoordinateSuboperation::Inspect) => (
                OperationAccessClass::AuthenticatedDiscoveryReadOnly,
                RequiredBindingEvidence::ExactAuthorizedJob,
            ),
            Self::Packet
            | Self::Act
            | Self::Verify(_)
            | Self::Finish
            | Self::Observe(ObserveSuboperation::InfluenceAck)
            | Self::Coordinate(
                CoordinateSuboperation::Delegate
                | CoordinateSuboperation::Audit
                | CoordinateSuboperation::Compare
                | CoordinateSuboperation::Cancel
                | CoordinateSuboperation::Send,
            ) => (
                OperationAccessClass::TaskRelativeEffectful,
                RequiredBindingEvidence::ExactApplicableTask,
            ),
        };
        OperationRequirement {
            operation: self,
            access_class,
            binding_evidence,
        }
    }
}

/// A request outside the eight canonical hot MCP operations.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("request is not a canonical hot MCP operation")]
pub struct NonCanonicalHotRequest;

/// Classifies a typed request without granting authority or interpreting
/// caller-provided text.
///
/// State/task-selection and bootstrap discovery can therefore be routed
/// before task selection; cold Observe capture can be retained only after its
/// authenticated identity, privacy, and staging owners admit it. Packet is
/// always task-relative: no-task bootstrap is a separate route, and
/// `PacketInput` does not contain a bootstrap discriminator. Non-hot carriers
/// fail closed.
pub fn classify_tool_request(
    request: &ToolRequest,
) -> Result<OperationRequirement, NonCanonicalHotRequest> {
    let operation = match request {
        ToolRequest::State(_) => CanonicalOperation::State,
        ToolRequest::Packet(_) => CanonicalOperation::Packet,
        ToolRequest::Observe(ObserveInput::Observation(_)) => {
            CanonicalOperation::Observe(ObserveSuboperation::Observation)
        }
        ToolRequest::Observe(ObserveInput::Decision(_)) => {
            CanonicalOperation::Observe(ObserveSuboperation::Decision)
        }
        ToolRequest::Observe(ObserveInput::Failure(_)) => {
            CanonicalOperation::Observe(ObserveSuboperation::Failure)
        }
        ToolRequest::Observe(ObserveInput::Outcome(_)) => {
            CanonicalOperation::Observe(ObserveSuboperation::Outcome)
        }
        ToolRequest::Observe(ObserveInput::InfluenceAck(_)) => {
            CanonicalOperation::Observe(ObserveSuboperation::InfluenceAck)
        }
        ToolRequest::Query(input) => CanonicalOperation::Query(input.intent.mode),
        ToolRequest::Act(_) => CanonicalOperation::Act,
        ToolRequest::Verify(input) => CanonicalOperation::Verify(input.intent),
        ToolRequest::Coordinate(CoordinateInput::Delegate(_)) => {
            CanonicalOperation::Coordinate(CoordinateSuboperation::Delegate)
        }
        ToolRequest::Coordinate(CoordinateInput::Audit(_)) => {
            CanonicalOperation::Coordinate(CoordinateSuboperation::Audit)
        }
        ToolRequest::Coordinate(CoordinateInput::Compare(_)) => {
            CanonicalOperation::Coordinate(CoordinateSuboperation::Compare)
        }
        ToolRequest::Coordinate(CoordinateInput::Wait(_)) => {
            CanonicalOperation::Coordinate(CoordinateSuboperation::Wait)
        }
        ToolRequest::Coordinate(CoordinateInput::Inspect(_)) => {
            CanonicalOperation::Coordinate(CoordinateSuboperation::Inspect)
        }
        ToolRequest::Coordinate(CoordinateInput::Cancel(_)) => {
            CanonicalOperation::Coordinate(CoordinateSuboperation::Cancel)
        }
        ToolRequest::Coordinate(CoordinateInput::Send(_)) => {
            CanonicalOperation::Coordinate(CoordinateSuboperation::Send)
        }
        ToolRequest::Finish(_) => CanonicalOperation::Finish,
        ToolRequest::UserAutomation(_)
        | ToolRequest::SkillInject(_)
        | ToolRequest::SkillDisplay(_) => return Err(NonCanonicalHotRequest),
    };
    Ok(operation.requirement())
}

/// Resolves the single semantic owner for one real contract tool request.
///
/// Production join between the contract surface ([`ToolRequest`]) and the
/// semantic owner: the request's canonical name resolves to exactly one
/// versioned profile, or the request has no owner and must not be routed.
pub fn validate_tool_request_owner(
    request: &ToolRequest,
) -> Result<ToolSemanticProfile, SemanticProfileError> {
    known_tool_profile(request.canonical_name())
}

/// Publishes the Material MCP tool surface: the generated transport catalogue
/// joined against the single semantic owner.
///
/// Calls the real production schema generator ([`canonical_tool_schemas`])
/// and publishes only descriptors whose name resolves to exactly one
/// versioned profile. A generated descriptor without a registered profile is
/// omitted from the Material surface (fail-closed); narrowing to an
/// observable capability, where safe, is a bridge/Skill decision downstream.
pub fn published_mcp_tool_surface() -> Result<Vec<ToolSchema>, SchemaError> {
    let mut surface = Vec::new();
    for descriptor in canonical_tool_schemas()? {
        if let Ok(profile) = known_tool_profile(&descriptor.name) {
            if profile.method.definition_version != descriptor.definition_version {
                return Err(SchemaError::DefinitionVersionMismatch {
                    tool: descriptor.name,
                });
            }
            surface.push(descriptor);
        }
    }
    Ok(surface)
}

#[allow(
    clippy::too_many_lines,
    reason = "eight canonical profiles are declared once as literal data"
)]
fn canonical_profiles() -> Vec<ToolSemanticProfile> {
    vec![
        ToolSemanticProfile {
            method: ToolMethodIdentity {
                canonical_name: "eliot.state".to_owned(),
                definition_version: CANONICAL_DEFINITION_VERSION.to_owned(),
            },
            profile_version: "1.0.0".to_owned(),
            operation_class: OperationClass::Observe,
            effect_class: EffectClass::ReadOnly,
            authority_requirements: vec!["explicit-session-binding".to_owned()],
            introduction_requirements: vec!["handshake-capability-evidence".to_owned()],
            idempotency_class: IdempotencyClass::Idempotent,
            reversibility_class: ReversibilityClass::Reversible,
            compensation: None,
            expected_result: "current task/scope projection; never a finish verdict".to_owned(),
            repetition: RepetitionSemantics {
                retry_safe: true,
                polling_admitted: false,
                pagination_admitted: false,
                terminal_completion: false,
            },
            evidence_ceiling: ProofCeiling::ScopedVerification,
            completion_ceiling: ProofCeiling::ScopedVerification,
            timeout_resource_privacy: TimeoutResourcePrivacy {
                timeout_ms: 5_000,
                max_resource_bytes: 65_536,
                privacy_class: "INTERNAL".to_owned(),
            },
            invalidation_set: InvalidationSet::full(),
        },
        ToolSemanticProfile {
            method: ToolMethodIdentity {
                canonical_name: "eliot.packet".to_owned(),
                definition_version: CANONICAL_DEFINITION_VERSION.to_owned(),
            },
            profile_version: "1.0.0".to_owned(),
            operation_class: OperationClass::Progress,
            effect_class: EffectClass::ScopedMutation,
            authority_requirements: vec!["explicit-session-binding".to_owned()],
            introduction_requirements: vec!["sealed-packet-input".to_owned()],
            idempotency_class: IdempotencyClass::IdempotentWithKey,
            reversibility_class: ReversibilityClass::Reversible,
            compensation: None,
            expected_result: "compiled or refreshed understanding packet handle".to_owned(),
            repetition: RepetitionSemantics {
                retry_safe: false,
                polling_admitted: false,
                pagination_admitted: true,
                terminal_completion: false,
            },
            evidence_ceiling: ProofCeiling::CandidateArtifact,
            completion_ceiling: ProofCeiling::ScopedVerification,
            timeout_resource_privacy: TimeoutResourcePrivacy {
                timeout_ms: 30_000,
                max_resource_bytes: 262_144,
                privacy_class: "INTERNAL".to_owned(),
            },
            invalidation_set: InvalidationSet::full(),
        },
        ToolSemanticProfile {
            method: ToolMethodIdentity {
                canonical_name: "eliot.observe".to_owned(),
                definition_version: CANONICAL_DEFINITION_VERSION.to_owned(),
            },
            profile_version: "1.0.0".to_owned(),
            operation_class: OperationClass::Observe,
            effect_class: EffectClass::ScopedMutation,
            authority_requirements: vec!["explicit-session-binding".to_owned()],
            introduction_requirements: vec!["typed-observation-input".to_owned()],
            idempotency_class: IdempotencyClass::IdempotentWithKey,
            reversibility_class: ReversibilityClass::Reversible,
            compensation: None,
            expected_result: "captured typed observation receipt".to_owned(),
            repetition: RepetitionSemantics {
                retry_safe: false,
                polling_admitted: false,
                pagination_admitted: false,
                terminal_completion: false,
            },
            evidence_ceiling: ProofCeiling::CandidateArtifact,
            completion_ceiling: ProofCeiling::ScopedVerification,
            timeout_resource_privacy: TimeoutResourcePrivacy {
                timeout_ms: 5_000,
                max_resource_bytes: 65_536,
                privacy_class: "INTERNAL".to_owned(),
            },
            invalidation_set: InvalidationSet::full(),
        },
        ToolSemanticProfile {
            method: ToolMethodIdentity {
                canonical_name: "eliot.query".to_owned(),
                definition_version: CANONICAL_DEFINITION_VERSION.to_owned(),
            },
            profile_version: "1.0.0".to_owned(),
            operation_class: OperationClass::Navigate,
            effect_class: EffectClass::ReadOnly,
            authority_requirements: vec!["explicit-session-binding".to_owned()],
            introduction_requirements: vec!["explicit-query-intent".to_owned()],
            idempotency_class: IdempotencyClass::Idempotent,
            reversibility_class: ReversibilityClass::Reversible,
            compensation: None,
            expected_result: "orientation payload; navigation is never evidence".to_owned(),
            repetition: RepetitionSemantics {
                retry_safe: true,
                polling_admitted: false,
                pagination_admitted: true,
                terminal_completion: false,
            },
            evidence_ceiling: ProofCeiling::ScopedVerification,
            completion_ceiling: ProofCeiling::ScopedVerification,
            timeout_resource_privacy: TimeoutResourcePrivacy {
                timeout_ms: 15_000,
                max_resource_bytes: 131_072,
                privacy_class: "INTERNAL".to_owned(),
            },
            invalidation_set: InvalidationSet::full(),
        },
        ToolSemanticProfile {
            method: ToolMethodIdentity {
                canonical_name: "eliot.act".to_owned(),
                definition_version: CANONICAL_DEFINITION_VERSION.to_owned(),
            },
            profile_version: "1.0.0".to_owned(),
            operation_class: OperationClass::Propose,
            effect_class: EffectClass::ScopedMutation,
            authority_requirements: vec!["explicit-session-binding".to_owned()],
            introduction_requirements: vec!["action-frame-intent".to_owned()],
            idempotency_class: IdempotencyClass::IdempotentWithKey,
            reversibility_class: ReversibilityClass::Compensatable,
            compensation: Some("action-frame-rollback".to_owned()),
            expected_result: "governed action frame; never an executed effect".to_owned(),
            repetition: RepetitionSemantics {
                retry_safe: false,
                polling_admitted: false,
                pagination_admitted: false,
                terminal_completion: false,
            },
            evidence_ceiling: ProofCeiling::CandidateArtifact,
            completion_ceiling: ProofCeiling::ScopedVerification,
            timeout_resource_privacy: TimeoutResourcePrivacy {
                timeout_ms: 15_000,
                max_resource_bytes: 65_536,
                privacy_class: "INTERNAL".to_owned(),
            },
            invalidation_set: InvalidationSet::full(),
        },
        ToolSemanticProfile {
            method: ToolMethodIdentity {
                canonical_name: "eliot.verify".to_owned(),
                definition_version: CANONICAL_DEFINITION_VERSION.to_owned(),
            },
            profile_version: "1.0.0".to_owned(),
            operation_class: OperationClass::Verify,
            effect_class: EffectClass::ScopedMutation,
            authority_requirements: vec!["explicit-session-binding".to_owned()],
            introduction_requirements: vec!["admitted-verifier-intent".to_owned()],
            idempotency_class: IdempotencyClass::IdempotentWithKey,
            reversibility_class: ReversibilityClass::Reversible,
            compensation: None,
            expected_result: "typed verifier run handle; never a caller verdict".to_owned(),
            repetition: RepetitionSemantics {
                retry_safe: false,
                polling_admitted: true,
                pagination_admitted: false,
                terminal_completion: false,
            },
            evidence_ceiling: ProofCeiling::ScopedVerification,
            completion_ceiling: ProofCeiling::ScopedVerification,
            timeout_resource_privacy: TimeoutResourcePrivacy {
                timeout_ms: 60_000,
                max_resource_bytes: 131_072,
                privacy_class: "INTERNAL".to_owned(),
            },
            invalidation_set: InvalidationSet::full(),
        },
        ToolSemanticProfile {
            method: ToolMethodIdentity {
                canonical_name: "eliot.coordinate".to_owned(),
                definition_version: CANONICAL_DEFINITION_VERSION.to_owned(),
            },
            profile_version: "1.0.0".to_owned(),
            operation_class: OperationClass::Progress,
            effect_class: EffectClass::ExternalEffect,
            authority_requirements: vec!["explicit-session-binding".to_owned()],
            introduction_requirements: vec!["bounded-delegation-input".to_owned()],
            idempotency_class: IdempotencyClass::IdempotentWithKey,
            reversibility_class: ReversibilityClass::Compensatable,
            compensation: Some("coordinate-cancel-reconcile".to_owned()),
            expected_result: "durable job handle or bounded fabric projection".to_owned(),
            repetition: RepetitionSemantics {
                retry_safe: false,
                polling_admitted: true,
                pagination_admitted: false,
                terminal_completion: false,
            },
            evidence_ceiling: ProofCeiling::CandidateArtifact,
            completion_ceiling: ProofCeiling::ScopedVerification,
            timeout_resource_privacy: TimeoutResourcePrivacy {
                timeout_ms: 60_000,
                max_resource_bytes: 131_072,
                privacy_class: "INTERNAL".to_owned(),
            },
            invalidation_set: InvalidationSet::full(),
        },
        ToolSemanticProfile {
            method: ToolMethodIdentity {
                canonical_name: "eliot.finish".to_owned(),
                definition_version: CANONICAL_DEFINITION_VERSION.to_owned(),
            },
            profile_version: "1.0.0".to_owned(),
            operation_class: OperationClass::CompleteCandidate,
            effect_class: EffectClass::ScopedMutation,
            authority_requirements: vec!["explicit-session-binding".to_owned()],
            introduction_requirements: vec!["candidate-finish-draft".to_owned()],
            idempotency_class: IdempotencyClass::IdempotentWithKey,
            reversibility_class: ReversibilityClass::Irreversible,
            compensation: None,
            expected_result: "candidate finish attempt; the Governor derives the outcome"
                .to_owned(),
            repetition: RepetitionSemantics {
                retry_safe: false,
                polling_admitted: false,
                pagination_admitted: false,
                terminal_completion: true,
            },
            evidence_ceiling: ProofCeiling::CandidateArtifact,
            completion_ceiling: ProofCeiling::ScopedVerification,
            timeout_resource_privacy: TimeoutResourcePrivacy {
                timeout_ms: 15_000,
                max_resource_bytes: 65_536,
                privacy_class: "INTERNAL".to_owned(),
            },
            invalidation_set: InvalidationSet::full(),
        },
    ]
}

fn non_blank(value: &str, field: &'static str) -> Result<(), SemanticProfileError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(SemanticProfileError::InvalidText { field });
    }
    Ok(())
}

fn non_blank_list(values: &[String], field: &'static str) -> Result<(), SemanticProfileError> {
    if values.is_empty() {
        return Err(SemanticProfileError::InvalidText { field });
    }
    for value in values {
        non_blank(value, field)?;
    }
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(SemanticProfileError::InvalidText { field });
        }
    }
    Ok(())
}

// Definition-owner exposure-history staging (I7.24 R7).
//
// This section stages the registry-owned registration fact and the
// owner-joined turn/run/attempt/surface identities for one exposure-history
// entry. It stages only: revisions persist replay-safe through the existing
// observation/receipt/outbox path on the owning persistence seam, which lives
// outside this module. Nothing here mints identities, opens a second store,
// or builds a second profile registry — the [`SemanticRegistry`] remains the
// single operational semantics owner.

/// Owner evidence reference for one resolved semantic profile.
///
/// Binds the canonical method name to its live profile revision
/// (`canonical-name@profile-version`), the same shape the publish seam
/// records as registration evidence. A generated descriptor, README, or
/// handshake claim never substitutes for this owner binding.
#[must_use]
pub fn registration_source_ref(profile: &ToolSemanticProfile) -> String {
    format!(
        "{}@{}",
        profile.method.canonical_name, profile.profile_version
    )
}

/// Stages the definition-owner registration fact for one method identity.
///
/// A resolved profile stages supplied `true` bound to
/// [`registration_source_ref`]. An unregistered identity stages explicitly
/// unresolved unknown — never a silent `false` and never inferred from any
/// neighbouring stage. The definition owner records its own negative verdict
/// with its revision reference through the shared history contract; unknown
/// methods still fail closed at admission.
///
/// # Errors
///
/// Returns an error when the registry lookup fails for a reason other than a
/// missing profile, or when the resolved owner reference cannot be staged.
pub fn registration_stage_fact(
    registry: &SemanticRegistry,
    canonical_name: &str,
    definition_version: &str,
) -> Result<OwnerStageFact, SemanticProfileError> {
    match registry.resolve(canonical_name, definition_version) {
        Ok(profile) => OwnerStageFact::supplied(true, registration_source_ref(profile))
            .map_err(|_| SemanticProfileError::InvalidText {
                field: "history.registered",
            }),
        Err(SemanticProfileError::MissingProfile { .. }) => Ok(OwnerStageFact::unresolved()),
        Err(other) => Err(other),
    }
}

/// Packs the owner-joined turn/run/attempt/surface identities for one
/// exposure-history entry.
///
/// Each identity arrives from its owner; a seam that never mints an identity
/// passes `None` and the dimension stays explicitly unresolved rather than
/// invented. The surface binding is still required: entry validation fails
/// closed on a history fact about no surface.
#[must_use]
pub fn stage_exposure_identities(
    turn_ref: Option<String>,
    run_ref: Option<String>,
    attempt_ref: Option<String>,
    surface_ref: Option<String>,
) -> ExposureIdentities {
    ExposureIdentities {
        turn_ref,
        run_ref,
        attempt_ref,
        surface_ref,
    }
}
