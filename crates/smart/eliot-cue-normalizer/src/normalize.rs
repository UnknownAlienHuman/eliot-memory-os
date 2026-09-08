//! The one deterministic normalization implementation used by capture and fire.

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_cue_contracts::{
    CONTRACT_REVISION, CanonicalCueId, CanonicalCueIdentity, ComparisonForm, ComparisonKey,
    ComparisonKeyId, CueKind, Digest, MatchMode, NormalizationOutcome, NormalizationProfile,
    NormalizedCue, ObservedCue, TransformationStep,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    bounds::{self, MAX_KEYS, MAX_STEPS},
    error::NormalizationError,
    policy::{CasePolicy, NormalizationPolicy, NormalizationRule, SeparatorPolicy},
};

/// A normalization result plus the exact invocation binding and digest closure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NormalizationEnvelope {
    /// A-11 schema revision.
    pub schema_revision: String,
    /// The caller-supplied policy binding used by the operation.
    pub policy: PolicyBinding,
    /// Digest of the complete observation and policy binding.
    pub input_digest: Digest,
    /// Digest of the result and its invocation binding.
    pub result_digest: Digest,
    /// Existing A-10 result, retained without changing its vocabulary.
    pub normalized: NormalizedCue,
}

/// Policy identity retained alongside a normalized result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyBinding {
    /// External policy owner reference.
    pub owner_reference: String,
    /// Stable policy identity.
    pub policy_id: String,
    /// Policy revision.
    pub policy_revision: u32,
    /// Digest of the sealed policy parameters.
    pub policy_digest: Digest,
    /// Exact scope supplied with the policy.
    pub scope_id: eliot_cue_contracts::WorkScopeId,
    /// Exact fence supplied with the policy.
    pub state_fence: eliot_contracts::StateFence,
    /// Exact adapter profile.
    pub profile: NormalizationProfile,
}

impl NormalizationEnvelope {
    /// Validates nested A-10 data and both domain-separated digest bindings.
    pub fn validate(&self) -> Result<(), NormalizationError> {
        if self.schema_revision != crate::A11_CONTRACT_REVISION {
            return Err(NormalizationError::InvalidField {
                field: "envelope.schema_revision",
            });
        }
        bounds::preflight_binding(&self.policy)?;
        self.policy
            .profile
            .validate()
            .map_err(NormalizationError::Contract)?;
        self.normalized
            .validate()
            .map_err(NormalizationError::Contract)?;
        if self.normalized.profile != self.policy.profile
            || self.normalized.observed.context.scope_id != self.policy.scope_id
            || self.normalized.observed.context.state_fence != self.policy.state_fence
        {
            return Err(NormalizationError::InvalidField {
                field: "envelope.policy_binding",
            });
        }
        let expected_input = digest_for(
            &InputPreimage {
                domain: "eliot.a11.normalization.input.v1",
                observed: &self.normalized.observed,
                policy: &self.policy,
            },
            "envelope.input",
        )?;
        if expected_input != self.input_digest {
            return Err(NormalizationError::ResultInvalid);
        }
        let expected_result = digest_for(
            &ResultPreimage {
                domain: "eliot.a11.normalization.result.v1",
                schema_revision: &self.schema_revision,
                policy: &self.policy,
                input_digest: &self.input_digest,
                normalized: &self.normalized,
            },
            "envelope.result",
        )?;
        if expected_result != self.result_digest {
            return Err(NormalizationError::ResultInvalid);
        }
        bounds::output_bytes(self)?;
        Ok(())
    }
}

/// Executes the common normalization implementation.
pub(crate) fn run(
    observed: &ObservedCue,
    policy: &NormalizationPolicy,
    profile: &NormalizationProfile,
) -> Result<NormalizationEnvelope, NormalizationError> {
    bounds::preflight_inputs(observed, policy, profile)?;
    observed.validate().map_err(NormalizationError::Contract)?;
    policy.validate()?;
    if policy.profile != *profile {
        return Err(NormalizationError::ProfileMismatch);
    }
    if policy.scope_id != observed.context.scope_id {
        return Err(NormalizationError::InvalidField {
            field: "policy.scope_id",
        });
    }
    if policy.state_fence != observed.context.state_fence {
        return Err(NormalizationError::InvalidField {
            field: "policy.state_fence",
        });
    }
    let policy_binding = PolicyBinding {
        owner_reference: policy.owner_reference.clone(),
        policy_id: policy.policy_id.clone(),
        policy_revision: policy.policy_revision,
        policy_digest: policy.digest.clone(),
        scope_id: policy.scope_id.clone(),
        state_fence: policy.state_fence.clone(),
        profile: profile.clone(),
    };
    let input_digest = digest_for(
        &InputPreimage {
            domain: "eliot.a11.normalization.input.v1",
            observed,
            policy: &policy_binding,
        },
        "envelope.input",
    )?;
    let normalized = match policy.rule_for(observed.kind) {
        Some(rule) => match build_normalized(observed, policy, profile, rule) {
            Ok(value) => value,
            Err(NormalizationError::Unsupported) => {
                unsupported(observed, profile, "requested transformation is not proven")
            }
            Err(error) => return Err(error),
        },
        None => unsupported(observed, profile, "missing kind rule"),
    };
    normalized
        .validate()
        .map_err(NormalizationError::Contract)?;
    let result_digest = digest_for(
        &ResultPreimage {
            domain: "eliot.a11.normalization.result.v1",
            schema_revision: crate::A11_CONTRACT_REVISION,
            policy: &policy_binding,
            input_digest: &input_digest,
            normalized: &normalized,
        },
        "envelope.result",
    )?;
    let envelope = NormalizationEnvelope {
        schema_revision: crate::A11_CONTRACT_REVISION.to_owned(),
        policy: policy_binding,
        input_digest,
        result_digest,
        normalized,
    };
    bounds::output_bytes(&envelope)?;
    envelope.validate()?;
    Ok(envelope)
}

struct DerivedKey {
    value: String,
    form: ComparisonForm,
    mode: MatchMode,
    steps: Vec<TransformationStep>,
}

fn build_normalized(
    observed: &ObservedCue,
    policy: &NormalizationPolicy,
    profile: &NormalizationProfile,
    rule: &NormalizationRule,
) -> Result<NormalizedCue, NormalizationError> {
    let derived = derive_key(observed, rule)?;
    if derived.steps.len() > MAX_STEPS {
        return Err(NormalizationError::BoundExceeded {
            field: "transformation_evidence",
            limit: MAX_STEPS,
        });
    }
    let canonical_digest = digest_for(
        &CanonicalPreimage {
            domain: "eliot.a11.canonical-cue.v1",
            kind: observed.kind,
            value: &observed.original_value,
            scope_id: policy.scope_id.as_str(),
            policy_id: &policy.policy_id,
            policy_digest: &policy.digest,
            profile,
        },
        "canonical",
    )?;
    let canonical_id = CanonicalCueId::new(format!("canonical-{canonical_digest}"))
        .map_err(NormalizationError::Contract)?;
    let canonical = CanonicalCueIdentity::new(
        canonical_id,
        observed.kind,
        observed.original_value.clone(),
        canonical_digest,
    );
    let key_digest = digest_for(
        &KeyPreimage {
            domain: "eliot.a11.comparison-key.v1",
            kind: observed.kind,
            value: &derived.value,
            mode: derived.mode,
            form: derived.form,
            policy_id: &policy.policy_id,
            policy_digest: &policy.digest,
            profile,
        },
        "comparison_key",
    )?;
    let key_id =
        ComparisonKeyId::new(format!("key-{key_digest}")).map_err(NormalizationError::Contract)?;
    if MAX_KEYS == 0 {
        return Err(NormalizationError::BoundExceeded {
            field: "comparison_keys",
            limit: MAX_KEYS,
        });
    }
    let key = ComparisonKey::new(
        key_id,
        profile.clone(),
        derived.value,
        derived.mode,
        derived.form,
    );
    Ok(NormalizedCue::new(
        CONTRACT_REVISION.to_owned(),
        observed.clone(),
        profile.clone(),
        Some(canonical),
        vec![key],
        NormalizationOutcome::Lossless,
        derived.steps,
    ))
}

fn derive_key(
    observed: &ObservedCue,
    rule: &NormalizationRule,
) -> Result<DerivedKey, NormalizationError> {
    if matches!(observed.kind, CueKind::FilePath | CueKind::DirPath)
        && has_special_path_shape(&observed.original_value)
    {
        return Err(NormalizationError::Unsupported);
    }
    match rule {
        NormalizationRule::Preserve => Ok(DerivedKey {
            value: observed.original_value.clone(),
            form: ComparisonForm::Exact,
            mode: MatchMode::Exact,
            steps: Vec::new(),
        }),
        NormalizationRule::Path {
            case,
            separators,
            match_mode,
        } => {
            let separator_value = path_key(&observed.original_value, *separators)?;
            let mut steps = Vec::new();
            if separator_value != observed.original_value {
                steps.push(TransformationStep::new(
                    "path.separators".to_owned(),
                    separator_value.clone(),
                ));
            }
            let value = if *case == CasePolicy::AsciiInsensitive {
                if !separator_value.is_ascii() {
                    return Err(NormalizationError::Unsupported);
                }
                let folded = ascii_fold(&separator_value);
                if folded != separator_value {
                    steps.push(TransformationStep::new(
                        "path.case.ascii".to_owned(),
                        folded.clone(),
                    ));
                }
                folded
            } else {
                separator_value
            };
            Ok(DerivedKey {
                form: if steps.is_empty() {
                    ComparisonForm::Exact
                } else {
                    ComparisonForm::PathNormalized
                },
                value,
                mode: *match_mode,
                steps,
            })
        }
        NormalizationRule::Symbol { case } => {
            let value = if *case == CasePolicy::AsciiInsensitive {
                if !observed.original_value.is_ascii() {
                    return Err(NormalizationError::Unsupported);
                }
                ascii_fold(&observed.original_value)
            } else {
                observed.original_value.clone()
            };
            let steps = if value == observed.original_value {
                Vec::new()
            } else {
                vec![TransformationStep::new(
                    "symbol.case.ascii".to_owned(),
                    value.clone(),
                )]
            };
            Ok(DerivedKey {
                form: if steps.is_empty() {
                    ComparisonForm::Exact
                } else {
                    ComparisonForm::CaseInsensitive
                },
                value,
                mode: MatchMode::Exact,
                steps,
            })
        }
        NormalizationRule::Signature {
            algorithm_ref,
            prefix,
            hex_length,
        } => {
            validate_signature(&observed.original_value, algorithm_ref, prefix, *hex_length)?;
            Ok(DerivedKey {
                value: observed.original_value.clone(),
                form: ComparisonForm::Exact,
                mode: MatchMode::Signature,
                steps: Vec::new(),
            })
        }
    }
}

fn unsupported(
    observed: &ObservedCue,
    profile: &NormalizationProfile,
    reason: &'static str,
) -> NormalizedCue {
    NormalizedCue::new(
        CONTRACT_REVISION.to_owned(),
        observed.clone(),
        profile.clone(),
        None,
        Vec::new(),
        NormalizationOutcome::Unsupported {
            reason: reason.to_owned(),
        },
        Vec::new(),
    )
}

fn path_key(value: &str, separators: SeparatorPolicy) -> Result<String, NormalizationError> {
    if separators == SeparatorPolicy::Slash && has_special_path_shape(value) {
        return Err(NormalizationError::Unsupported);
    }
    Ok(match separators {
        SeparatorPolicy::Preserve => value.to_owned(),
        SeparatorPolicy::Slash => value.replace('\\', "/"),
    })
}

fn has_special_path_shape(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with('\\')
        || value.as_bytes().get(1) == Some(&b':')
        || value.contains(':')
        || value.contains("//")
        || value.contains("\\\\")
        || value.contains("/\\")
        || value.contains("\\/")
        || value.ends_with('/')
        || value.ends_with('\\')
        || value
            .split(['/', '\\'])
            .any(|part| part == "." || part == "..")
}

fn ascii_fold(value: &str) -> String {
    value
        .bytes()
        .map(|byte| char::from(byte.to_ascii_lowercase()))
        .collect()
}

fn validate_signature(
    value: &str,
    algorithm_ref: &str,
    prefix: &str,
    hex_length: usize,
) -> Result<(), NormalizationError> {
    if algorithm_ref.trim().is_empty()
        || algorithm_ref.chars().any(char::is_control)
        || !value.starts_with(prefix)
    {
        return Err(NormalizationError::InvalidSignature);
    }
    let suffix = &value[prefix.len()..];
    if suffix.len() != hex_length
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(NormalizationError::InvalidSignature);
    }
    Ok(())
}

fn digest_for<T: Serialize>(value: &T, field: &'static str) -> Result<Digest, NormalizationError> {
    let bytes =
        canonical_json_bytes(value).map_err(|_| NormalizationError::Canonicalization { field })?;
    if bytes.len() > bounds::MAX_OUTPUT_BYTES {
        return Err(NormalizationError::BoundExceeded {
            field,
            limit: bounds::MAX_OUTPUT_BYTES,
        });
    }
    Digest::new(sha256_hex(&bytes)).map_err(NormalizationError::Contract)
}

#[derive(Serialize)]
struct InputPreimage<'a> {
    domain: &'a str,
    observed: &'a ObservedCue,
    policy: &'a PolicyBinding,
}

#[derive(Serialize)]
struct ResultPreimage<'a> {
    domain: &'a str,
    schema_revision: &'a str,
    policy: &'a PolicyBinding,
    input_digest: &'a Digest,
    normalized: &'a NormalizedCue,
}

#[derive(Serialize)]
struct CanonicalPreimage<'a> {
    domain: &'a str,
    kind: CueKind,
    value: &'a str,
    scope_id: &'a str,
    policy_id: &'a str,
    policy_digest: &'a Digest,
    profile: &'a NormalizationProfile,
}

#[derive(Serialize)]
struct KeyPreimage<'a> {
    domain: &'a str,
    kind: CueKind,
    value: &'a str,
    mode: MatchMode,
    form: ComparisonForm,
    policy_id: &'a str,
    policy_digest: &'a Digest,
    profile: &'a NormalizationProfile,
}
