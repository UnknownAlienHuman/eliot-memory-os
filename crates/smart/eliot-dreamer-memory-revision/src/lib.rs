//! Advisory negative-memory extinction candidates (#223, order 79).
//!
//! [`propose`] consumes one owner-neutral [`FailureObservation`], its
//! [`MemoryRevisionEvidence`] refs, the admitted task/safety projections, and
//! the frozen self-query/accepted-source refs — all by value, all already
//! admitted or projected by their owners — and emits one
//! [`NegativeMemoryExtinctionCandidate`]. The candidate narrows only advisory
//! activation/influence fields and preserves every history field; without
//! adequate adjudication only reversible suppress/quarantine/archive is
//! proposed, and a recurring failure with the same causal hypothesis yields
//! Mechanism Review rather than another equivalent retry.
//!
//! There are no parallel observation, evidence, query, or projection types
//! here: failure/revision shapes stay with `eliot-observation-contracts`,
//! self-query/accepted-source shapes stay with `eliot-dreamer-contracts`,
//! and task/safety projections stay with `eliot-context-contracts`. This
//! crate performs no compilation, admission, briefing, or model work, owns
//! no reactive path, and promotes nothing: output is candidate-only for the
//! Governor transition path.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::{
    ArtifactId, ContractVersion, StateFence, canonical_json_bytes, sha256_hex,
};
use eliot_context_contracts::{ContextError, SafetyProjection, TaskProjection};
use eliot_dreamer_contracts::self_query::{
    AcceptedSourceProjection, SelfQueryContractError, SelfQueryInput,
};
use eliot_observation_contracts::{
    FailureObservation, FailureOmission, MemoryRevisionEvidence, ObservationError,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Freeze identity this consumer builds against.
///
/// See `crates/smart/cognitive-rev12-contract-schema-freeze.toml`.
pub const FREEZE_ID: &str = "cognitive-rev12-contract-schema-freeze-2026-09-22-r6";
/// Contract version carried by every candidate emitted here.
pub const CANDIDATE_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Maximum revision-evidence refs carried by one intake.
pub const MAX_REVISION_EVIDENCE: usize = 32;
/// Maximum closure members enumerated by one denominator.
pub const MAX_CLOSURE_MEMBERS: usize = 1024;
/// Maximum missing-evidence entries named by one candidate.
pub const MAX_MISSING_ENTRIES: usize = 256;
/// Maximum characters accepted for one identity echo.
pub const MAX_ID_CHARS: usize = 1024;

/// Revision failure: intake contract violations fail closed with a reason.
///
/// Evidence insufficiency is not an error: it yields an inconclusive or
/// unsupported candidate naming the exact missing evidence.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RevisionError {
    /// An owner input rejected its own shape.
    #[error("dreamer memory revision: observation contract: {0}")]
    Observation(#[from] ObservationError),
    /// A task/safety projection rejected its own shape.
    #[error("dreamer memory revision: context contract: {0}")]
    Context(#[from] ContextError),
    /// The self-query input or accepted-source projection rejected its shape.
    #[error("dreamer memory revision: self-query contract: {0}")]
    SelfQuery(#[from] SelfQueryContractError),
    /// A scope identity does not match its governing scope.
    #[error("dreamer memory revision: scope mismatch at {field}")]
    ScopeMismatch { field: &'static str },
    /// A fence is incompatible with its governing fence.
    #[error("dreamer memory revision: fence mismatch at {field}")]
    FenceMismatch { field: &'static str },
    /// A posed digest does not match the query it claims.
    #[error("dreamer memory revision: digest mismatch at {field}")]
    DigestMismatch { field: &'static str },
    /// A cited source triple is stale or uncited.
    #[error("dreamer memory revision: stale citation at {field}")]
    StaleCitation { field: &'static str },
    /// A bound on intake size is exceeded.
    #[error("dreamer memory revision: out of bounds: {field}")]
    Bounds { field: &'static str },
    /// The candidate is not canonically encodable.
    #[error("dreamer memory revision: candidate is not digestible")]
    NotDigestible,
}

/// Reversible advisory narrowing only.
///
/// Suppress, quarantine, and archive are the A14.4 reversible operators. No
/// purge field exists by design: irreversible extinction is never emitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryNarrowing {
    /// Propose suppressing advisory activation.
    pub suppress_activation: bool,
    /// Propose quarantine (reserved for Governor adjudication).
    pub quarantine: bool,
    /// Propose archive (reserved for Governor adjudication).
    pub archive: bool,
}

/// Candidate disposition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CandidateDisposition {
    /// Narrow advisory activation/influence after new evidence.
    AdvisoryNarrow,
    /// Recurrence with the same hypothesis: Governor Mechanism Review.
    MechanismReview,
}

/// Candidate terminal state. No state implies support, truth, or promotion.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CandidateState {
    Complete,
    Inconclusive,
    Unsupported,
}

/// Independently recheckable closure denominator.
///
/// `enumerated` is the sorted union of the observation journal refs and the
/// revision evidence refs at the named `fence`; `exclusions` carries the
/// closed-class omissions verbatim. Any third party holding the same refs at
/// the same fence recomputes the identical `recheck_digest`: that is the
/// recheck rule, not a second enumeration capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClosureDenominator {
    /// Named fence the closure was enumerated at.
    pub fence: StateFence,
    /// Sorted closure member handles.
    pub enumerated: Vec<ArtifactId>,
    /// Closed-class exclusions carried verbatim.
    pub exclusions: Vec<FailureOmission>,
    /// Frozen digest over the fence, members, and exclusions.
    pub recheck_digest: String,
    /// True when the closure is nonempty.
    pub complete: bool,
}

impl ClosureDenominator {
    /// Compute the frozen recheck digest.
    pub fn compute_digest(&self) -> Result<String, RevisionError> {
        if self.enumerated.len() > MAX_CLOSURE_MEMBERS {
            return Err(RevisionError::Bounds {
                field: "denominator.enumerated",
            });
        }
        canonical_json_bytes(&(&self.fence, &self.enumerated, &self.exclusions))
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| RevisionError::NotDigestible)
    }

    /// Validate exact closure membership and the omission-aware completeness
    /// posture. A nonempty exclusion set is an explicit incomplete read and
    /// can never be relabeled as a complete closure.
    pub fn validate(&self) -> Result<(), RevisionError> {
        self.fence
            .validate()
            .map_err(|_| RevisionError::FenceMismatch {
                field: "denominator.fence",
            })?;
        if self.enumerated.len() > MAX_CLOSURE_MEMBERS {
            return Err(RevisionError::Bounds {
                field: "denominator.enumerated",
            });
        }
        let mut previous: Option<&ArtifactId> = None;
        for member in &self.enumerated {
            check_candidate_id(member)?;
            if previous.is_some_and(|prior| prior >= member) {
                return Err(RevisionError::DigestMismatch {
                    field: "denominator.enumerated",
                });
            }
            previous = Some(member);
        }
        if self.exclusions.len() > MAX_CLOSURE_MEMBERS {
            return Err(RevisionError::Bounds {
                field: "denominator.exclusions",
            });
        }
        let members: BTreeSet<&str> = self
            .enumerated
            .iter()
            .map(ArtifactId::as_str)
            .collect();
        let mut named_exclusions = BTreeSet::new();
        for exclusion in &self.exclusions {
            exclusion
                .validate()
                .map_err(|_| RevisionError::DigestMismatch {
                    field: "denominator.exclusions",
                })?;
            if let Some(handle) = exclusion.handle.as_ref()
                && (!named_exclusions.insert(handle.as_str())
                    || members.contains(handle.as_str()))
            {
                return Err(RevisionError::DigestMismatch {
                    field: "denominator.exclusions",
                });
            }
        }
        if self.complete != (!self.enumerated.is_empty() && self.exclusions.is_empty()) {
            return Err(RevisionError::DigestMismatch {
                field: "denominator.complete",
            });
        }
        if self.recheck_digest != self.compute_digest()? {
            return Err(RevisionError::DigestMismatch {
                field: "denominator.recheck_digest",
            });
        }
        Ok(())
    }
}

/// One advisory negative-memory extinction candidate.
///
/// History fields are echoed verbatim from the observation; only
/// [`AdvisoryNarrowing`] narrows, and only reversibly. Every `Complete`
/// state carries the exact independently recheckable [`ClosureDenominator`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryExtinctionCandidate {
    /// Exact contract version; must equal [`CANDIDATE_CONTRACT_VERSION`].
    pub contract_version: ContractVersion,
    /// Stable candidate identity.
    pub candidate_id: ArtifactId,
    /// Observation handle this candidate bears on.
    pub observation_ref: ArtifactId,
    /// Failure fingerprint echoed verbatim.
    pub fingerprint: String,
    /// Posed self-query digest this candidate was assessed under.
    pub query_digest: String,
    /// Reversible advisory narrowing.
    pub narrowing: AdvisoryNarrowing,
    /// Candidate disposition.
    pub disposition: CandidateDisposition,
    /// Closure denominator with the recheck rule.
    pub denominator: ClosureDenominator,
    /// Terminal state.
    pub state: CandidateState,
    /// Exact missing evidence; empty when `Complete`.
    pub missing: Vec<String>,
    /// Frozen digest over the candidate shape, excluding this field.
    pub digest: String,
}

impl NegativeMemoryExtinctionCandidate {
    /// Compute the frozen digest over the candidate shape.
    pub fn compute_digest(&self) -> Result<String, RevisionError> {
        canonical_json_bytes(&(
            &self.contract_version,
            &self.candidate_id,
            &self.observation_ref,
            &self.fingerprint,
            &self.query_digest,
            &self.narrowing,
            &self.disposition,
            &self.denominator,
            &self.state,
            &self.missing,
        ))
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| RevisionError::NotDigestible)
    }

    /// Validate version, bounds, state/denominator coherence, and the digest.
    pub fn validate(&self) -> Result<(), RevisionError> {
        if self.contract_version != CANDIDATE_CONTRACT_VERSION {
            return Err(RevisionError::DigestMismatch {
                field: "candidate.contract_version",
            });
        }
        if self.missing.len() > MAX_MISSING_ENTRIES {
            return Err(RevisionError::Bounds {
                field: "candidate.missing",
            });
        }
        self.denominator.validate()?;
        match self.state {
            CandidateState::Complete => {
                if !self.missing.is_empty() || !self.denominator.complete {
                    return Err(RevisionError::DigestMismatch {
                        field: "candidate.complete_denominator",
                    });
                }
            }
            CandidateState::Inconclusive | CandidateState::Unsupported => {
                if self.missing.is_empty() {
                    return Err(RevisionError::DigestMismatch {
                        field: "candidate.missing",
                    });
                }
            }
        }
        if self.digest != self.compute_digest()? {
            return Err(RevisionError::DigestMismatch {
                field: "candidate.digest",
            });
        }
        Ok(())
    }
}

/// Complete validated intake for one extinction assessment.
pub struct RevisionIntake<'a> {
    /// Owner-neutral failure observation, by value.
    pub observation: &'a FailureObservation,
    /// Revision evidence refs bearing on the observation.
    pub evidence: &'a [MemoryRevisionEvidence],
    /// Admitted task projection (CC-004).
    pub task: &'a TaskProjection,
    /// Admitted safety projection (CC-004).
    pub safety: &'a SafetyProjection,
    /// Frozen self-query input (A-03 owner).
    pub query: &'a SelfQueryInput,
    /// Accepted-source projection the query cites against.
    pub sources: &'a AcceptedSourceProjection,
    /// Posed digest echo to recheck against the query.
    pub pose_digest: &'a str,
    /// Stable identity for the emitted candidate.
    pub candidate_id: &'a ArtifactId,
}

fn check_candidate_id(value: &ArtifactId) -> Result<(), RevisionError> {
    if value.as_str().trim().is_empty()
        || value.as_str().chars().any(char::is_control)
        || value.as_str().chars().count() > MAX_ID_CHARS
    {
        return Err(RevisionError::DigestMismatch {
            field: "intake.candidate_id",
        });
    }
    Ok(())
}

/// Propose one advisory extinction candidate over validated intake.
///
/// Intake contract violations (invalid shapes, scope/fence mismatch, stale
/// citations, digest drift) fail closed as [`RevisionError`]. Valid intake
/// with insufficient evidence yields `Ok` with state `Inconclusive` or
/// `Unsupported` and the exact missing evidence named.
pub fn propose(
    intake: &RevisionIntake<'_>,
) -> Result<NegativeMemoryExtinctionCandidate, RevisionError> {
    intake.observation.validate()?;
    if intake.evidence.len() > MAX_REVISION_EVIDENCE {
        return Err(RevisionError::Bounds {
            field: "intake.evidence",
        });
    }
    for evidence in intake.evidence {
        evidence.validate()?;
        if evidence.observation_ref != intake.observation.observation_id {
            return Err(RevisionError::ScopeMismatch {
                field: "intake.evidence.observation_ref",
            });
        }
    }
    intake.task.validate()?;
    intake.safety.validate()?;
    if intake.observation.scope.work_scope != intake.task.binding.scope_id
        || intake.observation.scope.work_scope != intake.safety.binding.scope_id
    {
        return Err(RevisionError::ScopeMismatch {
            field: "intake.observation.scope",
        });
    }
    let governing = &intake.task.binding.state_fence;
    if !intake
        .observation
        .state_fence
        .is_compatible_with(governing)
        || !intake.safety.binding.state_fence.is_compatible_with(governing)
    {
        return Err(RevisionError::FenceMismatch {
            field: "intake.projection_fence",
        });
    }
    for evidence in intake.evidence {
        if !evidence
            .state_fence
            .is_compatible_with(&intake.observation.state_fence)
        {
            return Err(RevisionError::FenceMismatch {
                field: "intake.evidence_fence",
            });
        }
        if evidence.scope.work_scope != intake.observation.scope.work_scope {
            return Err(RevisionError::ScopeMismatch {
                field: "intake.evidence.scope",
            });
        }
    }
    intake.query.validate()?;
    let query_digest = intake.query.input_digest()?;
    if intake.pose_digest != query_digest {
        return Err(RevisionError::DigestMismatch {
            field: "intake.pose_digest",
        });
    }
    intake.sources.validate()?;
    if let Some(source) = &intake.query.source {
        intake.sources.check_cited(
            &source.source_handle,
            &source.revision,
            &source.digest,
        )?;
    }
    for anchor in &intake.query.anchors {
        intake.sources.check_cited(
            &anchor.source_handle,
            &anchor.revision,
            &anchor.source_digest,
        )?;
    }
    if !intake.sources.fence.is_compatible_with(governing) {
        return Err(RevisionError::FenceMismatch {
            field: "intake.sources_fence",
        });
    }

    if intake
        .safety
        .negative_memory_triggers
        .iter()
        .any(|trigger| trigger == &intake.observation.trigger)
    {
        return finish(
            intake,
            query_digest,
            CandidateDisposition::AdvisoryNarrow,
            CandidateState::Unsupported,
            vec!["safety.negative_memory_triggers".to_owned()],
            AdvisoryNarrowing {
                suppress_activation: false,
                quarantine: false,
                archive: false,
            },
        );
    }
    if intake
        .evidence
        .iter()
        .any(|evidence| evidence.same_hypothesis_recurrence)
    {
        return finish(
            intake,
            query_digest,
            CandidateDisposition::MechanismReview,
            CandidateState::Inconclusive,
            vec!["mechanism-review-required".to_owned()],
            AdvisoryNarrowing {
                suppress_activation: false,
                quarantine: false,
                archive: false,
            },
        );
    }

    let mut missing = Vec::new();
    if !intake.observation.coverage_complete() {
        missing.push("observation.coverage".to_owned());
    }
    for (index, evidence) in intake.evidence.iter().enumerate() {
        if !evidence.coverage_complete() {
            missing.push(format!("revision.evidence[{index}].coverage"));
        }
    }
    if intake.evidence.is_empty() {
        missing.push("revision.evidence_refs".to_owned());
    }
    let complete = missing.is_empty();
    finish(
        intake,
        query_digest,
        CandidateDisposition::AdvisoryNarrow,
        if complete {
            CandidateState::Complete
        } else {
            CandidateState::Inconclusive
        },
        missing,
        AdvisoryNarrowing {
            suppress_activation: complete,
            quarantine: false,
            archive: false,
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn finish(
    intake: &RevisionIntake<'_>,
    query_digest: String,
    disposition: CandidateDisposition,
    state: CandidateState,
    missing: Vec<String>,
    narrowing: AdvisoryNarrowing,
) -> Result<NegativeMemoryExtinctionCandidate, RevisionError> {
    let mut members = BTreeSet::new();
    for handle in &intake.observation.journal_refs {
        members.insert(handle.clone());
    }
    for evidence in intake.evidence {
        for handle in &evidence.evidence_refs {
            members.insert(handle.clone());
        }
    }
    let enumerated: Vec<ArtifactId> = members.into_iter().collect();
    let mut exclusions = Vec::new();
    exclusions.extend(intake.observation.omissions.iter().cloned());
    for evidence in intake.evidence {
        exclusions.extend(evidence.omissions.iter().cloned());
    }
    let mut denominator = ClosureDenominator {
        fence: intake.task.binding.state_fence.clone(),
        enumerated,
        exclusions,
        recheck_digest: String::new(),
        complete: false,
    };
    denominator.complete = !denominator.enumerated.is_empty() && denominator.exclusions.is_empty();
    denominator.recheck_digest = denominator.compute_digest()?;
    check_candidate_id(intake.candidate_id)?;
    let mut candidate = NegativeMemoryExtinctionCandidate {
        contract_version: CANDIDATE_CONTRACT_VERSION,
        candidate_id: intake.candidate_id.clone(),
        observation_ref: intake.observation.observation_id.clone(),
        fingerprint: intake.observation.fingerprint.clone(),
        query_digest,
        narrowing,
        disposition,
        denominator,
        state,
        missing,
        digest: String::new(),
    };
    if candidate.state == CandidateState::Complete
        && (!candidate.denominator.complete || !candidate.missing.is_empty())
    {
        candidate.state = CandidateState::Inconclusive;
        if candidate.missing.is_empty() {
            candidate.missing.push("revision.enumerated_closure".to_owned());
        }
        candidate.narrowing.suppress_activation = false;
    }
    candidate.digest = candidate.compute_digest()?;
    candidate.validate()?;
    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};

    use super::*;

    fn fence() -> StateFence {
        StateFence::new(
            EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                    .expect("fixture lineage"),
                NonZeroU64::new(1).expect("fixture sequence"),
            )
            .expect("fixture epoch"),
            ResourceGeneration::genesis(),
        )
    }

    fn handle(value: &str) -> ArtifactId {
        ArtifactId::new(value).expect("fixture handle")
    }

    fn omission(value: Option<&str>) -> FailureOmission {
        FailureOmission {
            handle: value.map(handle),
            class: eliot_observation_contracts::FailureOmissionClass::JournalBlind,
            note: "fixture omission".to_owned(),
        }
    }

    #[test]
    fn closure_complete_requires_an_exact_nonempty_partition() {
        let mut denominator = ClosureDenominator {
            fence: fence(),
            enumerated: vec![handle("member-1")],
            exclusions: Vec::new(),
            recheck_digest: String::new(),
            complete: true,
        };
        denominator.recheck_digest = denominator
            .compute_digest()
            .expect("complete digest");
        denominator.validate().expect("complete closure");

        denominator.exclusions.push(omission(Some("member-2")));
        denominator.recheck_digest = denominator
            .compute_digest()
            .expect("incomplete digest");
        assert!(denominator.validate().is_err());
    }

    #[test]
    fn closure_rejects_duplicate_and_overlapping_named_exclusions() {
        let mut denominator = ClosureDenominator {
            fence: fence(),
            enumerated: vec![handle("member-1")],
            exclusions: vec![omission(Some("member-1")), omission(Some("member-1"))],
            recheck_digest: String::new(),
            complete: false,
        };
        denominator.recheck_digest = denominator
            .compute_digest()
            .expect("fixture digest");
        assert!(denominator.validate().is_err());
    }
}
