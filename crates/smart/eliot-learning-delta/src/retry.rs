//! Canonical materially-equivalent retry detection.

use eliot_contracts::{ArtifactId, sha256_hex};
use std::{
    collections::BTreeSet,
    io::{self, Write},
};

use eliot_learning_contracts::{AgentAttemptId, ContractBinding};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    AttemptEvidence, DerivationContext, LearningDeltaError, SemanticOutcome, policy::RetryReason,
};

const MAX_FINGERPRINT_BYTES: usize = 4 * 1024 * 1024;
const MAX_FINGERPRINT_REFERENCES: usize = 256;
const MAX_FINGERPRINT_FIELD_BYTES: usize = 64 * 1024;

/// Prior-attempt lineage supplied by an immutable caller record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetryContext {
    /// Prior attempt identity, when this is a retry.
    pub prior_attempt: Option<AgentAttemptId>,
    /// Canonical fingerprint of the prior semantic strategy/operation.
    pub prior_fingerprint: Option<String>,
    /// Exact request/task/scope/fence binding of the prior attempt.
    pub prior_binding: Option<ContractBinding>,
    /// Exact target of the prior attempt.
    pub prior_target: Option<crate::TargetId>,
    /// Prior semantic outcome, required to prevent blind retry.
    pub prior_outcome: Option<SemanticOutcome>,
    /// Evidence proving the prior relationship.
    pub prior_evidence: Vec<ArtifactId>,
    /// Six prior raw material handles in discriminator/strategy/mechanism/probe/action-plan order.
    pub prior_material_evidence: Vec<ArtifactId>,
    /// Explicit controlled-retry reason, if allowed.
    pub reason: Option<RetryReason>,
    /// Exact environment identity included in the fingerprint.
    pub environment_fingerprint: String,
}

impl Default for RetryContext {
    fn default() -> Self {
        Self {
            prior_attempt: None,
            prior_fingerprint: None,
            prior_binding: None,
            prior_target: None,
            prior_outcome: None,
            prior_evidence: Vec::new(),
            prior_material_evidence: Vec::new(),
            reason: None,
            environment_fingerprint: "environment:unspecified".to_owned(),
        }
    }
}

/// Retry comparison result after exact fingerprinting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryAssessment {
    /// There is no compatible equivalent prior attempt.
    Distinct,
    /// The prior attempt is equivalent and has a permitted reason.
    EquivalentAllowed(RetryReason),
}

#[derive(Serialize)]
struct Fingerprint<'a> {
    target: &'a str,
    mechanism: &'a str,
    probe: &'a str,
    intended_content: &'a str,
    attempted_content: &'a str,
    environment: &'a str,
    intended_material: &'a [u8],
    attempted_material: &'a [u8],
    mechanism_material: &'a [u8],
    probe_material: &'a [u8],
    action_plan_material: &'a [u8],
    discriminator_material: &'a [u8],
}

/// Compute a deterministic fingerprint from load-bearing pre-observation fields.
///
/// The helper caps raw references at 256, individual binding fields at 64 KiB,
/// and each material plus the serialized fingerprint at 4 MiB.
pub fn canonical_retry_fingerprint(
    input: &AttemptEvidence,
    context: &DerivationContext<'_>,
) -> Result<String, LearningDeltaError> {
    validate_fingerprint_fields(input, input.retry.environment_fingerprint.as_str())?;
    if context.current.raw_evidence.len() > MAX_FINGERPRINT_REFERENCES {
        return Err(LearningDeltaError::Bound {
            field: "retry.raw_evidence",
        });
    }
    let materials = [
        (&input.discriminator_evidence, &input.discriminator_digest),
        (
            &input.intended_strategy_evidence,
            &input.intended_strategy_digest,
        ),
        (
            &input.attempted_strategy_evidence,
            &input.attempted_strategy_digest,
        ),
        (&input.mechanism_evidence, &input.mechanism_fingerprint),
        (&input.probe_evidence, &input.probe_fingerprint),
        (&input.action_plan_evidence, &input.action_plan_fingerprint),
    ];
    let mut material_bytes = Vec::with_capacity(materials.len());
    let mut seen = BTreeSet::new();
    for (artifact, digest) in materials {
        if !seen.insert(artifact.as_str()) {
            return Err(LearningDeltaError::EvidenceBinding {
                field: "retry.material",
            });
        }
        let mut candidates = context
            .current
            .raw_evidence
            .iter()
            .filter(|raw| raw.artifact_id == *artifact);
        let raw = candidates
            .next()
            .ok_or(LearningDeltaError::InsufficientEvidence {
                field: "retry.material",
            })?;
        if candidates.next().is_some() {
            return Err(LearningDeltaError::EvidenceBinding {
                field: "retry.material",
            });
        }
        if raw.invocation_id != input.pre_observation_invocation_id || raw.sha256 != *digest {
            return Err(LearningDeltaError::EvidenceBinding {
                field: "retry.material",
            });
        }
        if raw.bytes.len() > MAX_FINGERPRINT_BYTES
            || raw.artifact_id.as_str().len() > MAX_FINGERPRINT_FIELD_BYTES
            || raw.invocation_id.as_str().len() > MAX_FINGERPRINT_FIELD_BYTES
        {
            return Err(LearningDeltaError::Bound {
                field: "retry.material",
            });
        }
        raw.validate()
            .map_err(|_| LearningDeltaError::EvidenceBinding {
                field: "retry.material",
            })?;
        material_bytes.push(raw.bytes.as_slice());
    }
    fingerprint_from_parts(
        input.target.as_str(),
        input.retry.environment_fingerprint.as_str(),
        [
            input.discriminator_digest.as_str(),
            input.intended_strategy_digest.as_str(),
            input.attempted_strategy_digest.as_str(),
            input.mechanism_fingerprint.as_str(),
            input.probe_fingerprint.as_str(),
            input.action_plan_fingerprint.as_str(),
        ],
        &material_bytes,
    )
}

fn canonical_prior_retry_fingerprint(
    input: &AttemptEvidence,
    context: crate::EvaluationContext<'_>,
    material_ids: &[ArtifactId],
) -> Result<String, LearningDeltaError> {
    if material_ids.len() != 6 {
        return Err(LearningDeltaError::UnknownPriorEffect);
    }
    if material_ids.len() > MAX_FINGERPRINT_REFERENCES
        || context.raw_evidence.len() > MAX_FINGERPRINT_REFERENCES
    {
        return Err(LearningDeltaError::Bound {
            field: "retry.prior.raw_evidence",
        });
    }
    validate_fingerprint_fields(input, context.invocation.environment_fingerprint.as_str())
        .map_err(|_| LearningDeltaError::UnknownPriorEffect)?;
    let mut records = Vec::with_capacity(material_ids.len());
    let mut seen = BTreeSet::new();
    for artifact in material_ids {
        if !seen.insert(artifact.as_str()) {
            return Err(LearningDeltaError::UnknownPriorEffect);
        }
        let raw = context
            .raw_evidence
            .iter()
            .find(|raw| raw.artifact_id == *artifact)
            .ok_or(LearningDeltaError::UnknownPriorEffect)?;
        if raw.invocation_id != context.invocation.pre_observation_invocation_id {
            return Err(LearningDeltaError::UnknownPriorEffect);
        }
        if raw.bytes.len() > MAX_FINGERPRINT_BYTES
            || raw.artifact_id.as_str().len() > MAX_FINGERPRINT_FIELD_BYTES
            || raw.invocation_id.as_str().len() > MAX_FINGERPRINT_FIELD_BYTES
        {
            return Err(LearningDeltaError::Bound {
                field: "retry.material",
            });
        }
        raw.validate()
            .map_err(|_| LearningDeltaError::UnknownPriorEffect)?;
        records.push(raw);
    }
    let digests = [
        records[0].sha256.as_str(),
        records[1].sha256.as_str(),
        records[2].sha256.as_str(),
        records[3].sha256.as_str(),
        records[4].sha256.as_str(),
        records[5].sha256.as_str(),
    ];
    let bytes = [
        records[0].bytes.as_slice(),
        records[1].bytes.as_slice(),
        records[2].bytes.as_slice(),
        records[3].bytes.as_slice(),
        records[4].bytes.as_slice(),
        records[5].bytes.as_slice(),
    ];
    fingerprint_from_parts(
        input.target.as_str(),
        context.invocation.environment_fingerprint.as_str(),
        digests,
        &bytes,
    )
}

fn fingerprint_from_parts(
    target: &str,
    environment: &str,
    digests: [&str; 6],
    material_bytes: &[&[u8]],
) -> Result<String, LearningDeltaError> {
    if material_bytes.len() != 6
        || target.len() > MAX_FINGERPRINT_FIELD_BYTES
        || environment.len() > MAX_FINGERPRINT_FIELD_BYTES
        || digests
            .iter()
            .any(|digest| digest.len() > MAX_FINGERPRINT_FIELD_BYTES)
        || material_bytes
            .iter()
            .any(|bytes| bytes.len() > MAX_FINGERPRINT_BYTES)
    {
        return Err(LearningDeltaError::InvalidInput {
            field: "retry.fingerprint",
        });
    }
    let payload = Fingerprint {
        target,
        environment,
        mechanism: digests[3],
        probe: digests[4],
        intended_content: digests[1],
        attempted_content: digests[2],
        intended_material: material_bytes[1],
        attempted_material: material_bytes[2],
        mechanism_material: material_bytes[3],
        probe_material: material_bytes[4],
        action_plan_material: material_bytes[5],
        discriminator_material: material_bytes[0],
    };
    let mut output = BoundedBuffer::new(MAX_FINGERPRINT_BYTES);
    serde_json::to_writer(&mut output, &payload).map_err(|_| LearningDeltaError::Bound {
        field: "retry.fingerprint",
    })?;
    Ok(sha256_hex(output.as_slice()))
}

fn validate_fingerprint_fields(
    input: &AttemptEvidence,
    environment: &str,
) -> Result<(), LearningDeltaError> {
    if input.target.as_str().len() > MAX_FINGERPRINT_FIELD_BYTES
        || environment.len() > MAX_FINGERPRINT_FIELD_BYTES
        || input.pre_observation_invocation_id.as_str().len() > MAX_FINGERPRINT_FIELD_BYTES
        || input.target.as_str().trim().is_empty()
        || environment.trim().is_empty()
        || environment == "environment:unspecified"
    {
        return Err(LearningDeltaError::InvalidInput {
            field: "retry.fingerprint.binding",
        });
    }
    for (value, field) in [
        (&input.discriminator_digest, "discriminator"),
        (&input.intended_strategy_digest, "intended_strategy"),
        (&input.attempted_strategy_digest, "attempted_strategy"),
        (&input.mechanism_fingerprint, "mechanism"),
        (&input.probe_fingerprint, "probe"),
        (&input.action_plan_fingerprint, "action_plan"),
    ] {
        if value.len() > MAX_FINGERPRINT_FIELD_BYTES {
            return Err(LearningDeltaError::Bound { field });
        }
    }
    for (value, field) in [
        (&input.discriminator_evidence, "discriminator_evidence"),
        (
            &input.intended_strategy_evidence,
            "intended_strategy_evidence",
        ),
        (
            &input.attempted_strategy_evidence,
            "attempted_strategy_evidence",
        ),
        (&input.mechanism_evidence, "mechanism_evidence"),
        (&input.probe_evidence, "probe_evidence"),
        (&input.action_plan_evidence, "action_plan_evidence"),
    ] {
        if value.as_str().len() > MAX_FINGERPRINT_FIELD_BYTES {
            return Err(LearningDeltaError::Bound { field });
        }
    }
    Ok(())
}

struct BoundedBuffer {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedBuffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("fingerprint bound"))?;
        if next > self.limit {
            return Err(io::Error::other("fingerprint bound"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Compare the current canonical fingerprint with the prior one.
pub fn assess_retry(
    input: &AttemptEvidence,
    context: &DerivationContext<'_>,
) -> Result<RetryAssessment, LearningDeltaError> {
    let retry = &input.retry;
    let Some(prior_attempt) = &retry.prior_attempt else {
        if retry.prior_fingerprint.is_some()
            || retry.prior_binding.is_some()
            || retry.prior_target.is_some()
            || retry.prior_outcome.is_some()
            || !retry.prior_evidence.is_empty()
            || !retry.prior_material_evidence.is_empty()
            || retry.reason.is_some()
            || context.prior.is_some()
        {
            return Err(LearningDeltaError::InvalidInput {
                field: "retry.prior",
            });
        }
        return Ok(RetryAssessment::Distinct);
    };
    if prior_attempt.as_str().trim().is_empty() || retry.prior_evidence.is_empty() {
        return Err(LearningDeltaError::InvalidInput {
            field: "retry.evidence",
        });
    }
    let Some(prior_fingerprint) = retry.prior_fingerprint.as_deref() else {
        return Err(LearningDeltaError::InvalidInput {
            field: "retry.fingerprint",
        });
    };
    if prior_fingerprint.len() != 64
        || !prior_fingerprint
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(LearningDeltaError::InvalidInput {
            field: "retry.fingerprint",
        });
    }
    if prior_attempt == &input.attempt_id {
        return Err(LearningDeltaError::InvalidInput {
            field: "retry.prior_attempt",
        });
    }
    if retry.environment_fingerprint.trim().is_empty()
        || retry.environment_fingerprint == "environment:unspecified"
    {
        return Err(LearningDeltaError::InvalidInput {
            field: "retry.environment",
        });
    }
    let Some(prior_binding) = retry.prior_binding.as_ref() else {
        return Err(LearningDeltaError::UnknownPriorEffect);
    };
    if prior_binding.validate().is_err()
        || prior_binding.schema_version != input.binding.schema_version
        || prior_binding.policy_revision != input.binding.policy_revision
        || prior_binding.product_id != input.binding.product_id
        || prior_binding.task_id != input.binding.task_id
        || prior_binding.scope != input.binding.scope
        || prior_binding.state_fence != input.binding.state_fence
        || prior_binding.proof_ceiling != input.binding.proof_ceiling
        || retry.prior_target.as_ref() != Some(&input.target)
    {
        return Err(LearningDeltaError::UnknownPriorEffect);
    }
    let Some(prior_context) = context.prior else {
        return Err(LearningDeltaError::UnknownPriorEffect);
    };
    validate_prior_context(input, context, retry, prior_attempt, prior_context)?;
    let current = canonical_retry_fingerprint(input, context)?;
    let prior =
        canonical_prior_retry_fingerprint(input, prior_context, &retry.prior_material_evidence)?;
    if prior != prior_fingerprint {
        return Err(LearningDeltaError::UnknownPriorEffect);
    }
    if current != prior {
        return Ok(RetryAssessment::Distinct);
    }
    retry
        .reason
        .map(RetryAssessment::EquivalentAllowed)
        .ok_or(LearningDeltaError::EquivalentRetryRequiresReason)
}

fn validate_prior_context(
    input: &AttemptEvidence,
    context: &DerivationContext<'_>,
    retry: &RetryContext,
    prior_attempt: &AgentAttemptId,
    prior_context: crate::EvaluationContext<'_>,
) -> Result<(), LearningDeltaError> {
    prior_context
        .run
        .validate()
        .map_err(|_| LearningDeltaError::UnknownPriorEffect)?;
    validate_prior_run_quality(prior_context.run)?;
    validate_prior_identity(input, context, retry, prior_attempt, prior_context)?;
    validate_prior_raw_evidence(context, retry, prior_context)?;
    validate_prior_materials(retry, prior_context)?;
    let mapped = match prior_context.run.outcome {
        eliot_instrument_api::VerificationOutcome::Pass => prior_context.binding.pass_outcome,
        eliot_instrument_api::VerificationOutcome::Fail => prior_context.binding.fail_outcome,
        _ => return Err(LearningDeltaError::UnknownPriorEffect),
    };
    if retry.prior_outcome != Some(mapped)
        || !matches!(
            prior_context.run.execution,
            eliot_instrument_api::ExecutionStatus::Succeeded
        )
    {
        return Err(LearningDeltaError::UnknownPriorEffect);
    }
    Ok(())
}

fn validate_prior_identity(
    input: &AttemptEvidence,
    context: &DerivationContext<'_>,
    retry: &RetryContext,
    prior_attempt: &AgentAttemptId,
    prior_context: crate::EvaluationContext<'_>,
) -> Result<(), LearningDeltaError> {
    let invocation = prior_context.invocation;
    if invocation.attempt_id != *prior_attempt
        || invocation.target != input.target
        || invocation.task_id != input.binding.task_id
        || invocation.scope != input.binding.scope
        || invocation.state_fence != input.binding.state_fence
        || invocation.task_id
            != retry
                .prior_binding
                .as_ref()
                .map(|binding| binding.task_id.clone())
                .ok_or(LearningDeltaError::UnknownPriorEffect)?
        || invocation.invocation_id != prior_context.run.invocation_id
        || invocation
            .pre_observation_invocation_id
            .as_str()
            .trim()
            .is_empty()
        || invocation.pre_observation_invocation_id == invocation.invocation_id
        || invocation.environment_fingerprint.trim().is_empty()
        || invocation.environment_fingerprint == "environment:unspecified"
        || invocation.relation_receipt.as_str().trim().is_empty()
        || prior_context.run.run_id != prior_context.binding.run_id
        || prior_context.run.verifier != prior_context.binding.verifier
        || prior_context.run.invocation_id != prior_context.binding.invocation_id
        || prior_context.run.property != prior_context.binding.property
        || prior_context.run.scope != prior_context.binding.scope
        || prior_context.run.scope != invocation.scope.as_str()
        || prior_context.binding.scope != input.binding.scope.as_str()
        || prior_context.run.state_fence != invocation.state_fence
        || prior_context.binding.verifier != context.current.binding.verifier
        || prior_context.binding.property != context.current.binding.property
        || prior_context.binding.revision != context.current.binding.revision
        || prior_context.binding.pass_outcome != context.current.binding.pass_outcome
        || prior_context.binding.fail_outcome != context.current.binding.fail_outcome
    {
        return Err(LearningDeltaError::UnknownPriorEffect);
    }
    Ok(())
}

fn validate_prior_raw_evidence(
    context: &DerivationContext<'_>,
    retry: &RetryContext,
    prior_context: crate::EvaluationContext<'_>,
) -> Result<(), LearningDeltaError> {
    let run_ids: BTreeSet<&str> = prior_context
        .run
        .raw_evidence
        .iter()
        .map(eliot_contracts::ArtifactId::as_str)
        .collect();
    let raw_ids: BTreeSet<&str> = prior_context
        .raw_evidence
        .iter()
        .map(|raw| raw.artifact_id.as_str())
        .collect();
    if run_ids.is_empty()
        || run_ids.len() != prior_context.run.raw_evidence.len()
        || raw_ids.len() != prior_context.raw_evidence.len()
        || run_ids != raw_ids
        || retry
            .prior_evidence
            .iter()
            .map(eliot_contracts::ArtifactId::as_str)
            .collect::<BTreeSet<_>>()
            != run_ids
        || prior_context
            .run
            .evidence
            .iter()
            .any(|record| !run_ids.contains(record.raw_artifact_id.as_str()))
    {
        return Err(LearningDeltaError::UnknownPriorEffect);
    }
    for raw in prior_context.raw_evidence {
        raw.validate()
            .map_err(|_| LearningDeltaError::UnknownPriorEffect)?;
        if let Some(current) = context
            .current
            .raw_evidence
            .iter()
            .find(|candidate| candidate.artifact_id == raw.artifact_id)
            && current != raw
        {
            return Err(LearningDeltaError::UnknownPriorEffect);
        }
    }
    Ok(())
}

fn validate_prior_materials(
    retry: &RetryContext,
    prior_context: crate::EvaluationContext<'_>,
) -> Result<(), LearningDeltaError> {
    if retry.prior_material_evidence.len() != 6 {
        return Err(LearningDeltaError::UnknownPriorEffect);
    }
    for artifact in &retry.prior_material_evidence {
        let raw = prior_context
            .raw_evidence
            .iter()
            .find(|raw| raw.artifact_id == *artifact)
            .ok_or(LearningDeltaError::UnknownPriorEffect)?;
        if raw.invocation_id != prior_context.invocation.pre_observation_invocation_id {
            return Err(LearningDeltaError::UnknownPriorEffect);
        }
        raw.validate()
            .map_err(|_| LearningDeltaError::UnknownPriorEffect)?;
    }
    Ok(())
}

fn validate_prior_run_quality(
    run: &eliot_instrument_api::VerificationRun,
) -> Result<(), LearningDeltaError> {
    if !matches!(
        run.freshness,
        eliot_instrument_api::EvidenceFreshness::ExactCandidate
            | eliot_instrument_api::EvidenceFreshness::ExactCommit
            | eliot_instrument_api::EvidenceFreshness::ExactQuiescedWorktree
    ) || run.coverage != eliot_instrument_api::EvidenceCoverage::CompleteForScope
    {
        return Err(LearningDeltaError::UnknownPriorEffect);
    }
    Ok(())
}
