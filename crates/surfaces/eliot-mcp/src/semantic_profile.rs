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
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
