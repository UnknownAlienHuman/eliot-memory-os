//! Borrowed, checked preflight for the normalizer hot path.

use crate::{
    error::NormalizationError,
    policy::{
        MAX_ALGORITHM_REFERENCE_BYTES, MAX_OWNER_REFERENCE_BYTES, MAX_POLICY_ID_BYTES,
        MAX_POLICY_RULES, NormalizationPolicy,
    },
};
use eliot_cue_contracts::{NormalizationProfile, ObservedCue};

/// Maximum bytes scanned and retained by one normalization operation.
pub const MAX_INPUT_BYTES: usize = 64 * 1024;
/// Maximum generated transformation steps.
pub const MAX_STEPS: usize = 16;
/// Maximum generated comparison keys.
pub const MAX_KEYS: usize = 8;
/// Maximum serialized result envelope.
pub const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

pub(crate) fn preflight_inputs(
    observed: &ObservedCue,
    policy: &NormalizationPolicy,
    profile: &NormalizationProfile,
) -> Result<(), NormalizationError> {
    let mut total = 0usize;
    preflight_observed(observed, &mut total)?;
    preflight_profile(profile, &mut total)?;
    preflight_policy_into(policy, &mut total)?;
    Ok(())
}

pub(crate) fn preflight_observed(
    observed: &ObservedCue,
    total: &mut usize,
) -> Result<(), NormalizationError> {
    add_text(
        total,
        &observed.schema_revision,
        "observed.schema_revision",
        256,
    )?;
    add_text(
        total,
        &observed.original_value,
        "observed.original_value",
        8_192,
    )?;
    add_text(
        total,
        observed.observed_cue_id.as_str(),
        "observed.observed_cue_id",
        512,
    )?;
    add_text(total, observed.source.target.as_str(), "source.target", 512)?;
    add_text(total, observed.source.digest.as_str(), "source.digest", 64)?;
    add_provenance(total, &observed.source.provenance, "source.provenance")?;
    add_text(
        total,
        observed.context.task_id.as_str(),
        "context.task_id",
        512,
    )?;
    add_text(
        total,
        observed.context.scope_id.as_str(),
        "context.scope_id",
        512,
    )?;
    add_provenance(
        total,
        &observed.context.evidence.provenance,
        "context.evidence.provenance",
    )?;
    if let Some(binding) = &observed.context.evidence.verification {
        add_text(
            total,
            binding.contract_id.as_str(),
            "verification.contract_id",
            512,
        )?;
        add_text(total, binding.run_id.as_str(), "verification.run_id", 512)?;
        add_text(total, &binding.revision, "verification.revision", 8_192)?;
    }
    Ok(())
}

pub(crate) fn preflight_profile(
    profile: &NormalizationProfile,
    total: &mut usize,
) -> Result<(), NormalizationError> {
    add_text(
        total,
        &profile.profile_id,
        "profile.profile_id",
        MAX_POLICY_ID_BYTES,
    )?;
    add_text(total, profile.digest.as_str(), "profile.digest", 64)
}

fn preflight_policy_into(
    policy: &NormalizationPolicy,
    total: &mut usize,
) -> Result<(), NormalizationError> {
    preflight_profile(&policy.profile, total)?;
    add_text(
        total,
        &policy.schema_revision,
        "policy.schema_revision",
        256,
    )?;
    add_text(
        total,
        &policy.owner_reference,
        "policy.owner_reference",
        MAX_OWNER_REFERENCE_BYTES,
    )?;
    add_text(
        total,
        &policy.policy_id,
        "policy.policy_id",
        MAX_POLICY_ID_BYTES,
    )?;
    add_text(
        total,
        policy.scope_id.as_str(),
        "policy.scope_id",
        MAX_POLICY_ID_BYTES,
    )?;
    add_text(total, policy.digest.as_str(), "policy.digest", 64)?;
    if policy.rules.len() > MAX_POLICY_RULES {
        return Err(NormalizationError::BoundExceeded {
            field: "policy.rules",
            limit: MAX_POLICY_RULES,
        });
    }
    for entry in &policy.rules {
        if let crate::policy::NormalizationRule::Signature {
            algorithm_ref,
            prefix,
            ..
        } = &entry.rule
        {
            add_text(
                total,
                algorithm_ref,
                "policy.signature.algorithm_ref",
                MAX_ALGORITHM_REFERENCE_BYTES,
            )?;
            add_text(total, prefix, "policy.signature.prefix", 128)?;
        }
    }
    Ok(())
}

fn add_provenance(
    total: &mut usize,
    value: &eliot_evidence::Provenance,
    field: &'static str,
) -> Result<(), NormalizationError> {
    add_text(total, value.source_id.as_str(), "provenance.source_id", 512)?;
    add_text(total, &value.capture_route, field, 8_192)?;
    add_text(total, &value.scope, field, 8_192)?;
    if let Some(raw) = &value.raw_handle {
        add_text(total, raw, field, 8_192)?;
    }
    if let Some(revision) = &value.revision {
        add_text(total, revision, field, 8_192)?;
    }
    Ok(())
}

pub(crate) fn preflight_policy(policy: &NormalizationPolicy) -> Result<(), NormalizationError> {
    let mut total = 0usize;
    preflight_policy_into(policy, &mut total)
}

pub(crate) fn add_text(
    total: &mut usize,
    value: &str,
    field: &'static str,
    limit: usize,
) -> Result<(), NormalizationError> {
    if value.len() > limit {
        return Err(NormalizationError::BoundExceeded { field, limit });
    }
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(NormalizationError::InvalidField { field });
    }
    *total = total
        .checked_add(value.len())
        .ok_or(NormalizationError::BoundExceeded {
            field: "normalization.input_bytes",
            limit: MAX_INPUT_BYTES,
        })?;
    if *total > MAX_INPUT_BYTES {
        return Err(NormalizationError::BoundExceeded {
            field: "normalization.input_bytes",
            limit: MAX_INPUT_BYTES,
        });
    }
    Ok(())
}

pub(crate) fn preflight_binding_into(
    binding: &crate::normalize::PolicyBinding,
    total: &mut usize,
) -> Result<(), NormalizationError> {
    add_text(
        total,
        &binding.owner_reference,
        "envelope.policy.owner_reference",
        MAX_OWNER_REFERENCE_BYTES,
    )?;
    add_text(
        total,
        &binding.policy_id,
        "envelope.policy.policy_id",
        MAX_POLICY_ID_BYTES,
    )?;
    add_text(
        total,
        binding.scope_id.as_str(),
        "envelope.policy.scope_id",
        MAX_POLICY_ID_BYTES,
    )?;
    add_text(
        total,
        binding.policy_digest.as_str(),
        "envelope.policy.digest",
        64,
    )?;
    add_text(
        total,
        &binding.profile.profile_id,
        "envelope.policy.profile_id",
        MAX_POLICY_ID_BYTES,
    )?;
    add_text(
        total,
        binding.profile.digest.as_str(),
        "envelope.policy.profile_digest",
        64,
    )?;
    Ok(())
}
pub(crate) fn output_bytes<T: serde::Serialize>(value: &T) -> Result<usize, NormalizationError> {
    let bytes = eliot_contracts::canonical_json_bytes(value).map_err(|_| {
        NormalizationError::Canonicalization {
            field: "normalization.output",
        }
    })?;
    if bytes.len() > MAX_OUTPUT_BYTES {
        return Err(NormalizationError::BoundExceeded {
            field: "normalization.output_bytes",
            limit: MAX_OUTPUT_BYTES,
        });
    }
    Ok(bytes.len())
}
