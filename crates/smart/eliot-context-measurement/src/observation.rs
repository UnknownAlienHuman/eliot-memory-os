//! Immutable externally-supplied tokenizer observation taxonomy.
//!
//! An observation is validated against the exact envelope bytes/digest,
//! operation binding, route/provider/model/tokenizer identity, serializer
//! identity, count bounds, source and provider-rewrite evidence. Absent,
//! unavailable, unsupported, exact, stale/mismatched, transformed and
//! unknown outcomes stay distinct; unknown actual count is never zero and
//! never a proven error flag. This package never loads or invokes a
//! tokenizer or provider.

use eliot_context_contracts::{ContextBinding, ContextError};
use eliot_contracts::ArtifactId;

use crate::envelope::{SerializerIdentity, validate_digest, validate_identity_text};

/// Preserved observation outcome taxonomy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationStatus {
    /// No observation was supplied.
    Absent,
    /// The route tokenizer is known but never ran for this envelope.
    Unavailable,
    /// The named tokenizer is not a supported route tokenizer.
    Unsupported,
    /// The observation binds every expected identity exactly.
    Exact,
    /// The observation binds a different envelope, binding, route,
    /// tokenizer or serializer identity, or was explicitly superseded.
    Stale,
    /// The provider rewrote, truncated or normalized the measured bytes.
    Transformed,
    /// The observation outcome is explicitly unknown.
    Unknown,
}

impl ObservationStatus {
    /// Canonical wire spelling used by the deterministic receipt.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "ABSENT",
            Self::Unavailable => "UNAVAILABLE",
            Self::Unsupported => "UNSUPPORTED",
            Self::Exact => "EXACT",
            Self::Stale => "STALE",
            Self::Transformed => "TRANSFORMED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Route tokenizer identity an observation must bind.
#[derive(Clone, Debug)]
pub struct TokenizerIdentity {
    /// Required tokenizer identity.
    pub tokenizer_id: String,
    /// Required tokenizer revision.
    pub tokenizer_version: String,
    /// Required tokenizer digest (lowercase SHA-256 hex).
    pub tokenizer_hash: String,
    /// Required tokenizer configuration digest (lowercase SHA-256 hex).
    pub tokenizer_config_digest: String,
}

impl TokenizerIdentity {
    /// Validate identity texts and digest shapes.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_identity_text(&self.tokenizer_id, "route.tokenizer_id")?;
        validate_identity_text(&self.tokenizer_version, "route.tokenizer_version")?;
        validate_digest(&self.tokenizer_hash, "route.tokenizer_hash")?;
        validate_digest(
            &self.tokenizer_config_digest,
            "route.tokenizer_config_digest",
        )?;
        Ok(())
    }
}

/// Evidence source class for one observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationSource {
    /// The route tokenizer actually ran for this envelope.
    ProviderTokenizerRun,
    /// Replayed prior evidence bound to the same identities.
    ReplayedEvidence,
}

impl ObservationSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ProviderTokenizerRun => "PROVIDER_TOKENIZER_RUN",
            Self::ReplayedEvidence => "REPLAYED_EVIDENCE",
        }
    }
}

/// Provider rewrite/truncation/normalization evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderRewriteKind {
    /// The provider truncated the measured bytes.
    Truncation,
    /// The provider normalized the measured bytes.
    Normalization,
    /// The provider rewrote the measured bytes another way.
    Rewrite,
}

impl ProviderRewriteKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Truncation => "TRUNCATION",
            Self::Normalization => "NORMALIZATION",
            Self::Rewrite => "REWRITE",
        }
    }
}

/// Provider rewrite evidence carried with a transformed observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderRewrite {
    /// Rewrite class.
    pub kind: ProviderRewriteKind,
    /// Evidence digest (lowercase SHA-256 hex).
    pub evidence_digest: String,
}

impl ProviderRewrite {
    /// Validate the evidence digest shape.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_digest(&self.evidence_digest, "observation.rewrite_evidence")
    }
}

/// One exact externally-supplied observed token count with its bindings.
#[derive(Clone, Debug)]
pub struct ExactObservation {
    /// Stable observation identity; must not collide with any other role.
    pub observation_id: ArtifactId,
    /// Observed token count.
    pub tokens: u64,
    /// Route-admitted token bound; a count above it is impossible.
    pub token_bound: u64,
    /// Operation binding as observed.
    pub binding: ContextBinding,
    /// Envelope digest as observed.
    pub envelope_digest: String,
    /// Route identity as observed.
    pub route_id: String,
    /// Provider identity as observed.
    pub provider_id: String,
    /// Model identity as observed.
    pub model_id: String,
    /// Tokenizer identity as observed.
    pub tokenizer: TokenizerIdentity,
    /// Serializer identity as observed.
    pub serializer: SerializerIdentity,
    /// Evidence source class.
    pub source: ObservationSource,
    /// Provider rewrite evidence, when the provider transformed the bytes.
    pub rewrite: Option<ProviderRewrite>,
    /// Explicit superseding observation, when this one is stale.
    pub superseded_by: Option<ArtifactId>,
    /// Proof identity for this observation, when one exists.
    pub proof_id: Option<ArtifactId>,
}

impl ExactObservation {
    /// Identity roles carried by this observation for duplicate checks.
    pub(crate) fn identity_roles(&self) -> Vec<(&'static str, &ArtifactId)> {
        let mut roles = vec![("observation.observation_id", &self.observation_id)];
        if let Some(proof) = &self.proof_id {
            roles.push(("observation.proof_id", proof));
        }
        if let Some(superseded) = &self.superseded_by {
            roles.push(("observation.superseded_by", superseded));
        }
        roles
    }
}

/// Caller-supplied observation input in all preserved taxonomy arms.
#[derive(Clone, Debug)]
pub enum ObservationInput {
    /// No observation was supplied; stays absent, never zero.
    Absent,
    /// The route tokenizer is known but did not run; stays unavailable
    /// and is never fabricated.
    KnownTokenizerWithoutObservation { tokenizer: TokenizerIdentity },
    /// The named tokenizer is not supported; stays distinct from
    /// unavailable and unknown.
    UnsupportedTokenizer { tokenizer_id: String },
    /// One exact externally-supplied observation to validate.
    Exact(Box<ExactObservation>),
    /// The observation outcome is explicitly unknown.
    Unknown { reason: String },
}

/// Validated observation: status plus only the evidence that still binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedObservation {
    /// Preserved outcome status.
    pub status: ObservationStatus,
    /// Observed count, present only for [`ObservationStatus::Exact`].
    pub tokens: Option<u64>,
    /// Observation identity, when one was supplied.
    pub observation_id: Option<ArtifactId>,
    /// Provider rewrite evidence, present only when transformed.
    pub rewrite: Option<ProviderRewrite>,
    /// Evidence source class, when an exact observation was supplied.
    pub source: Option<ObservationSource>,
}

/// Identities an exact observation must bind to stay exact.
#[derive(Clone, Debug)]
pub struct ObservationExpectation<'a> {
    /// Expected operation binding.
    pub binding: &'a ContextBinding,
    /// Expected exact envelope digest.
    pub envelope_digest: &'a str,
    /// Expected route identity.
    pub route_id: &'a str,
    /// Expected provider identity.
    pub provider_id: &'a str,
    /// Expected model identity.
    pub model_id: &'a str,
    /// Expected tokenizer identity.
    pub tokenizer: &'a TokenizerIdentity,
    /// Expected serializer identity.
    pub serializer: &'a SerializerIdentity,
}

/// Validate one observation input against the expected identities.
///
/// Malformed inputs fail with typed errors. Well-formed evidence bound to
/// different bytes, bindings, routes, tokenizers or serializers is
/// preserved as stale; only exact evidence keeps its count.
pub fn validate_observation(
    input: &ObservationInput,
    expected: &ObservationExpectation<'_>,
) -> Result<ValidatedObservation, ContextError> {
    match input {
        ObservationInput::Absent => Ok(ValidatedObservation {
            status: ObservationStatus::Absent,
            tokens: None,
            observation_id: None,
            rewrite: None,
            source: None,
        }),
        ObservationInput::KnownTokenizerWithoutObservation { tokenizer } => {
            tokenizer.validate()?;
            Ok(ValidatedObservation {
                status: ObservationStatus::Unavailable,
                tokens: None,
                observation_id: None,
                rewrite: None,
                source: None,
            })
        }
        ObservationInput::UnsupportedTokenizer { tokenizer_id } => {
            validate_identity_text(tokenizer_id, "observation.tokenizer_id")?;
            Ok(ValidatedObservation {
                status: ObservationStatus::Unsupported,
                tokens: None,
                observation_id: None,
                rewrite: None,
                source: None,
            })
        }
        ObservationInput::Unknown { reason } => {
            if reason.len() > crate::MAX_IDENTITY_TEXT_BYTES {
                return Err(ContextError::Bounds {
                    field: "observation.reason",
                });
            }
            if reason.trim().is_empty() {
                return Err(ContextError::InvalidField("observation.reason"));
            }
            Ok(ValidatedObservation {
                status: ObservationStatus::Unknown,
                tokens: None,
                observation_id: None,
                rewrite: None,
                source: None,
            })
        }
        ObservationInput::Exact(observation) => validate_exact(observation, expected),
    }
}

/// Validate one exact observation: shape first, then binding comparison.
fn validate_exact(
    observation: &ExactObservation,
    expected: &ObservationExpectation<'_>,
) -> Result<ValidatedObservation, ContextError> {
    if observation.token_bound == 0 {
        return Err(ContextError::InvalidField("observation.token_bound"));
    }
    if observation.tokens > observation.token_bound {
        return Err(ContextError::Bounds {
            field: "observation.tokens",
        });
    }
    observation.binding.validate()?;
    observation.tokenizer.validate()?;
    observation.serializer.validate()?;
    validate_digest(&observation.envelope_digest, "observation.envelope_digest")?;
    validate_identity_text(&observation.route_id, "observation.route_id")?;
    validate_identity_text(&observation.provider_id, "observation.provider_id")?;
    validate_identity_text(&observation.model_id, "observation.model_id")?;
    if let Some(rewrite) = &observation.rewrite {
        rewrite.validate()?;
    }
    if let Some(superseded) = &observation.superseded_by
        && superseded == &observation.observation_id
    {
        return Err(ContextError::IdentityConflict);
    }
    let stale = || ValidatedObservation {
        status: ObservationStatus::Stale,
        tokens: None,
        observation_id: Some(observation.observation_id.clone()),
        rewrite: None,
        source: Some(observation.source),
    };
    if observation.binding != *expected.binding
        || observation.envelope_digest != expected.envelope_digest
        || observation.route_id != expected.route_id
        || observation.provider_id != expected.provider_id
        || observation.model_id != expected.model_id
        || observation.tokenizer.tokenizer_id != expected.tokenizer.tokenizer_id
        || observation.tokenizer.tokenizer_version != expected.tokenizer.tokenizer_version
        || observation.tokenizer.tokenizer_hash != expected.tokenizer.tokenizer_hash
        || observation.tokenizer.tokenizer_config_digest
            != expected.tokenizer.tokenizer_config_digest
        || observation.serializer.serializer_id != expected.serializer.serializer_id
        || observation.serializer.serializer_version != expected.serializer.serializer_version
        || observation.serializer.serializer_options_digest
            != expected.serializer.serializer_options_digest
        || observation.serializer.schema_revision != expected.serializer.schema_revision
    {
        return Ok(stale());
    }
    if observation.superseded_by.is_some() {
        return Ok(stale());
    }
    if let Some(rewrite) = &observation.rewrite {
        return Ok(ValidatedObservation {
            status: ObservationStatus::Transformed,
            tokens: None,
            observation_id: Some(observation.observation_id.clone()),
            rewrite: Some(rewrite.clone()),
            source: Some(observation.source),
        });
    }
    Ok(ValidatedObservation {
        status: ObservationStatus::Exact,
        tokens: Some(observation.tokens),
        observation_id: Some(observation.observation_id.clone()),
        rewrite: None,
        source: Some(observation.source),
    })
}
