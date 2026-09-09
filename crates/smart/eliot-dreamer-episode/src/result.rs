//! Candidate result records for Episode reconstruction.

use eliot_contracts::StateFence;
use eliot_dreamer_contracts::{
    CandidateDisposition, CurationFamily, CurationKind, PreservationReport,
    TypedCurationHandlerResult, canonical_bytes, digest_hex,
};
use eliot_memory_curation_contracts::SourceSnapshot;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::input::{
    EpisodeOutcome, EpisodeParticipant, ExistingEpisodeSnapshot, GroundedEvent, MAX_EVENTS,
    MAX_LINKS, MAX_OUTCOMES, MAX_PARTICIPANTS, MAX_SERIALIZED_INPUT, MAX_TEXT,
    capped_serialized_len,
};
use eliot_dreamer_contracts::ContractViolation;
use eliot_epistemic_contracts::DenominatorKind;
use eliot_epistemic_contracts::{CoverageDenominator, CoverageReceipt};
use std::collections::BTreeSet;

/// Episode-specific status retained alongside the common disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum EpisodeStatus {
    Closed,
    Open,
    Partial,
    Conflicted,
    Duplicate,
    Bounded,
    Unknown,
    Stale,
    Cancelled,
    Error,
}

/// Relation between two events based only on explicit same-domain readings.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ChronologyRelation {
    Before,
    After,
    Concurrent,
    Incomparable,
    Unknown,
}

/// Explicit chronology edge; it carries no causal meaning.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChronologyLink {
    pub left_event_id: String,
    pub right_event_id: String,
    pub relation: ChronologyRelation,
    pub support: Vec<crate::input::EvidenceBinding>,
}

/// Episode boundary selected by the declared Episode policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EpisodeBoundary {
    pub start_event_id: String,
    pub end_event_id: Option<String>,
}

/// One explicit unresolved coverage interval or member gap.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EpisodeGap {
    pub member_id: Option<String>,
    pub reason: String,
}

/// Coverage projection preserving source disposition and event denominator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EpisodeCoverage {
    pub event_denominator_size: u64,
    pub observed_events: u64,
    pub gaps: Vec<EpisodeGap>,
    pub source_availability: eliot_memory_curation_contracts::SourceAvailability,
}

/// Overlap and conflict assessment between proposed and existing membership.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OverlapDisposition {
    None,
    ExactReplay,
    Conflict,
    Blocked,
}

/// Explicit overlap references retained in the candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OverlapAssessment {
    pub disposition: OverlapDisposition,
    pub event_ids: Vec<String>,
}

/// Reversible closure over the immutable input identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EpisodeRollback {
    pub source_fence: StateFence,
    pub episode_id: String,
    pub retained_event_ids: Vec<String>,
    pub retained_source_member_ids: Vec<String>,
    pub note: String,
}

/// Pure candidate-only Episode result. Raw/source values are copied as an
/// immutable closure; this record does not authorize a canonical mutation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EpisodeCandidate {
    pub candidate_id: String,
    pub request_id: String,
    pub receipt_id: String,
    pub job_id: String,
    pub task_id: String,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub policy_id: String,
    pub policy_digest: String,
    pub handler_id: String,
    pub handler_request_digest: String,
    pub admission_item_digest: String,
    pub admission_receipt_digest: String,
    pub screen_coverage_digest: String,
    pub whole_input_digest: String,
    pub kind: CurationKind,
    pub family: CurationFamily,
    pub episode: String,
    pub status: EpisodeStatus,
    pub disposition: CandidateDisposition,
    pub boundary: EpisodeBoundary,
    pub events: Vec<GroundedEvent>,
    pub participants: Vec<EpisodeParticipant>,
    pub outcomes: Vec<EpisodeOutcome>,
    pub chronology: Vec<ChronologyLink>,
    pub coverage: EpisodeCoverage,
    pub overlap: OverlapAssessment,
    pub rollback: EpisodeRollback,
    pub preservation: PreservationReport,
    pub source: SourceSnapshot,
    pub event_denominator: CoverageDenominator,
    pub event_receipt: CoverageReceipt,
    pub existing: ExistingEpisodeSnapshot,
    pub handler_result: TypedCurationHandlerResult,
    pub result_digest: String,
}

impl EpisodeCandidate {
    /// Validates bounded output shape and all retained input closures.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.validate_shape()?;
        self.validate_records()?;
        self.validate_rollback()?;
        self.validate_bindings()?;
        self.existing.validate()?;
        self.validate_integrity()
    }

    fn validate_shape(&self) -> Result<(), ContractViolation> {
        for (value, field) in [
            (&self.candidate_id, "candidate.id"),
            (&self.request_id, "candidate.request_id"),
            (&self.receipt_id, "candidate.receipt_id"),
            (&self.job_id, "candidate.job_id"),
            (&self.task_id, "candidate.task_id"),
            (&self.scope_id, "candidate.scope_id"),
            (&self.policy_id, "candidate.policy_id"),
            (&self.policy_digest, "candidate.policy_digest"),
            (&self.handler_id, "candidate.handler_id"),
            (
                &self.handler_request_digest,
                "candidate.handler_request_digest",
            ),
            (
                &self.admission_item_digest,
                "candidate.admission_item_digest",
            ),
            (
                &self.admission_receipt_digest,
                "candidate.admission_receipt_digest",
            ),
            (
                &self.screen_coverage_digest,
                "candidate.screen_coverage_digest",
            ),
            (&self.whole_input_digest, "candidate.whole_input_digest"),
            (&self.episode, "candidate.episode"),
        ] {
            eliot_dreamer_contracts::error::check_text(value, field, MAX_TEXT)?;
        }
        if self.kind != CurationKind::Episode || self.family != CurationFamily::Episode {
            return Err(ContractViolation::KindPayload(
                "Episode candidate kind/family drift".to_owned(),
            ));
        }
        if self.events.is_empty() || self.events.len() > MAX_EVENTS {
            return Err(ContractViolation::OutOfBounds {
                field: "candidate.events",
                min: 1,
                max: i64::try_from(MAX_EVENTS).unwrap_or(i64::MAX),
                got: i64::try_from(self.events.len()).unwrap_or(i64::MAX),
            });
        }
        if self.participants.len() > MAX_PARTICIPANTS {
            return Err(ContractViolation::OutOfBounds {
                field: "candidate.participants",
                min: 0,
                max: i64::try_from(MAX_PARTICIPANTS).unwrap_or(i64::MAX),
                got: i64::try_from(self.participants.len()).unwrap_or(i64::MAX),
            });
        }
        if self.outcomes.len() > MAX_OUTCOMES || self.chronology.len() > MAX_LINKS {
            return Err(ContractViolation::OutOfBounds {
                field: "candidate.records",
                min: 0,
                max: i64::try_from(MAX_LINKS).unwrap_or(i64::MAX),
                got: i64::try_from(self.outcomes.len().max(self.chronology.len()))
                    .unwrap_or(i64::MAX),
            });
        }
        Ok(())
    }

    fn validate_integrity(&self) -> Result<(), ContractViolation> {
        self.preservation.validate()?;
        if self.coverage.source_availability != self.source.availability {
            return Err(ContractViolation::BindingMismatch {
                field: "candidate.coverage.source_availability",
                reason: "coverage availability differs from retained source".to_owned(),
            });
        }
        if self.disposition == CandidateDisposition::Candidate {
            self.preservation.overall()?;
            self.validate_candidate_completeness()?;
        }
        self.handler_result.validate()?;
        if self.handler_result.request_id != self.request_id
            || self.handler_result.kind != self.kind
            || self.handler_result.family != self.family
            || self.handler_result.disposition != self.disposition
            || self.handler_result.handler_id != self.handler_id
            || self.handler_result.request_digest != self.handler_request_digest
            || self.handler_result.result_digest != self.result_digest
        {
            return Err(ContractViolation::BindingMismatch {
                field: "candidate.handler_result",
                reason: "handler result identity is not retained exactly".to_owned(),
            });
        }
        if self.result_digest != self.computed_digest()? {
            return Err(ContractViolation::BindingMismatch {
                field: "candidate.result_digest",
                reason: "candidate digest drift".to_owned(),
            });
        }
        if self.candidate_id != self.computed_identity()? {
            return Err(ContractViolation::BindingMismatch {
                field: "candidate.id",
                reason: "candidate identity does not cover retained bindings".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_candidate_completeness(&self) -> Result<(), ContractViolation> {
        let all_observed = self.event_receipt.members.iter().all(|outcome| {
            outcome.disposition == eliot_epistemic_contracts::MemberDisposition::Observed
        });
        if self.event_denominator.kind != DenominatorKind::CompleteScope
            || !self.event_receipt.is_terminal()
            || !self.event_receipt.omissions.is_empty()
            || !all_observed
            || self.events.len() as u64 != self.event_denominator.members.len() as u64
            || !self.coverage.gaps.is_empty()
            || self.source.availability
                != eliot_memory_curation_contracts::SourceAvailability::Available
            || self.chronology.iter().any(|link| {
                matches!(
                    link.relation,
                    ChronologyRelation::Unknown | ChronologyRelation::Incomparable
                )
            })
        {
            return Err(ContractViolation::BindingMismatch {
                field: "candidate.completeness",
                reason: "Candidate contradicts retained coverage or chronology".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_bindings(&self) -> Result<(), ContractViolation> {
        self.validate_coverage_bindings()?;
        self.validate_closure_bindings()
    }

    fn validate_coverage_bindings(&self) -> Result<(), ContractViolation> {
        self.source
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "candidate.source",
                reason: error.to_string(),
            })?;
        self.event_denominator
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "candidate.event_denominator",
                reason: error.to_string(),
            })?;
        self.event_receipt
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "candidate.event_receipt",
                reason: error.to_string(),
            })?;
        if self.event_receipt.denominator != self.event_denominator.digest
            || self.event_receipt.denominator_size != self.event_denominator.members.len() as u64
            || self.event_denominator.scope != self.scope_id
            || self.event_denominator.revision != self.source.identity.revision.to_string()
            || self.event_denominator.snapshot.snapshot_id
                != self.source.identity.snapshot_id.as_str()
            || self.event_denominator.snapshot.owner != self.source.identity.source_id
            || self.event_denominator.fence != self.state_fence
            || self.event_receipt.task_id.as_str() != self.task_id
            || self.event_receipt.scope != self.scope_id
            || self.event_receipt.fence != self.state_fence
            || self.event_receipt.policy != self.policy_id
            || self.event_denominator.query.as_ref() != Some(&self.event_receipt.query)
            || self.event_denominator.frontier.as_ref() != Some(&self.event_receipt.frontier)
            || self.coverage.event_denominator_size != self.event_denominator.members.len() as u64
            || self.coverage.observed_events != self.events.len() as u64
            || !eliot_dreamer_contracts::is_hex64_lower(&self.admission_item_digest)
            || !eliot_dreamer_contracts::is_hex64_lower(&self.admission_receipt_digest)
            || !eliot_dreamer_contracts::is_hex64_lower(&self.screen_coverage_digest)
            || !eliot_dreamer_contracts::is_hex64_lower(&self.whole_input_digest)
        {
            return Err(ContractViolation::BindingMismatch {
                field: "candidate.coverage_binding",
                reason: "retained admission or event coverage identity drift".to_owned(),
            });
        }
        let receipt_members: BTreeSet<_> = self
            .event_receipt
            .members
            .iter()
            .map(|outcome| outcome.member.clone())
            .chain(
                self.event_receipt
                    .omissions
                    .iter()
                    .map(|omission| omission.member.clone()),
            )
            .collect();
        if receipt_members != self.event_denominator.members
            || self.event_denominator.roles.len() != 1
            || !self.event_denominator.roles.contains("event")
            || self
                .event_receipt
                .members
                .iter()
                .any(|outcome| outcome.role != "event")
        {
            return Err(ContractViolation::BindingMismatch {
                field: "candidate.event_coverage_universe",
                reason: "retained receipt does not cover the typed event denominator".to_owned(),
            });
        }
        let observed_members: BTreeSet<_> = self
            .event_receipt
            .members
            .iter()
            .filter(|outcome| {
                outcome.disposition == eliot_epistemic_contracts::MemberDisposition::Observed
            })
            .map(|outcome| outcome.member.as_str().to_owned())
            .collect();
        let retained_members: BTreeSet<_> = self
            .events
            .iter()
            .map(|event| event.source_member_id.as_str().to_owned())
            .collect();
        if !retained_members.is_subset(&observed_members) {
            return Err(ContractViolation::BindingMismatch {
                field: "candidate.event_observed_members",
                reason: "retained events differ from observed receipt members".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_closure_bindings(&self) -> Result<(), ContractViolation> {
        if self.state_fence != self.source.identity.state_fence
            || self.state_fence != self.existing.state_fence
            || self.rollback.source_fence != self.state_fence
            || self.rollback.episode_id != self.episode
        {
            return Err(ContractViolation::BindingMismatch {
                field: "candidate.fence_closure",
                reason: "candidate closure does not retain one fence and episode".to_owned(),
            });
        }
        let event_ids: BTreeSet<_> = self
            .events
            .iter()
            .map(|event| event.core.event_id_and_time.event_id.clone())
            .collect();
        let rollback_event_ids: BTreeSet<_> =
            self.rollback.retained_event_ids.iter().cloned().collect();
        let source_ids: BTreeSet<_> = self
            .events
            .iter()
            .map(|event| event.source_member_id.as_str().to_owned())
            .collect();
        let rollback_source_ids: BTreeSet<_> = self
            .rollback
            .retained_source_member_ids
            .iter()
            .cloned()
            .collect();
        if event_ids != rollback_event_ids || source_ids != rollback_source_ids {
            return Err(ContractViolation::BindingMismatch {
                field: "candidate.rollback.closure",
                reason: "rollback IDs differ from retained event closure".to_owned(),
            });
        }
        if !event_ids.contains(&self.boundary.start_event_id)
            || self
                .boundary
                .end_event_id
                .as_ref()
                .is_some_and(|id| !event_ids.contains(id))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "candidate.boundary",
                reason: "boundary names an absent retained event".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_records(&self) -> Result<(), ContractViolation> {
        self.validate_event_records()?;
        self.validate_flattened_records()?;
        self.validate_chronology_records()?;
        for gap in &self.coverage.gaps {
            eliot_dreamer_contracts::error::check_text(
                &gap.reason,
                "candidate.coverage.gap",
                MAX_TEXT,
            )?;
        }
        Ok(())
    }

    fn validate_event_records(&self) -> Result<(), ContractViolation> {
        for event in &self.events {
            event.validate()?;
            let member = self
                .source
                .members
                .iter()
                .find(|member| member.member_id == event.source_member_id)
                .ok_or(ContractViolation::BindingMismatch {
                    field: "candidate.event_source",
                    reason: "retained event source member is absent".to_owned(),
                })?;
            if member.kind != eliot_memory_curation_contracts::SourceMemberKind::Observation
                || !self
                    .source
                    .partition
                    .immutable_references
                    .contains(&event.source_member_id)
                || member.revision != event.source_revision
                || member.content_digest != event.source_content_digest
                || event.core.affected_scope.work_scope.as_str() != self.scope_id
                || event.core.evidence_and_raw_handles.iter().any(|handle| {
                    !member
                        .evidence
                        .provenance
                        .iter()
                        .any(|value| value.as_str() == handle)
                        && !member
                            .evidence
                            .owner_status
                            .iter()
                            .any(|value| value.as_str() == handle)
                        && !member
                            .evidence
                            .protection
                            .iter()
                            .any(|value| value.as_str() == handle)
                        && !member
                            .evidence
                            .conflict
                            .iter()
                            .any(|value| value.as_str() == handle)
                        && !member
                            .evidence
                            .audit
                            .iter()
                            .any(|value| value.as_str() == handle)
                })
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "candidate.event_source",
                    reason: "retained event is outside the immutable observation closure"
                        .to_owned(),
                });
            }
            if event.participants.iter().any(|participant| {
                participant.binding.member_id != event.source_member_id
                    || participant.binding.member_revision != event.source_revision
                    || participant.binding.member_content_digest != event.source_content_digest
            }) || event.outcomes.iter().any(|outcome| {
                outcome.binding.member_id != event.source_member_id
                    || outcome.binding.member_revision != event.source_revision
                    || outcome.binding.member_content_digest != event.source_content_digest
            }) || event.temporal_binding.as_ref().is_some_and(|binding| {
                binding.member_id != event.source_member_id
                    || binding.member_revision != event.source_revision
                    || binding.member_content_digest != event.source_content_digest
            }) {
                return Err(ContractViolation::BindingMismatch {
                    field: "candidate.event_bindings",
                    reason: "nested event records are not bound to their source member".to_owned(),
                });
            }
        }
        for participant in &self.participants {
            participant.validate()?;
        }
        for outcome in &self.outcomes {
            outcome.validate()?;
        }
        Ok(())
    }

    fn validate_flattened_records(&self) -> Result<(), ContractViolation> {
        let expected_participants: Vec<_> = self
            .events
            .iter()
            .flat_map(|event| event.participants.iter())
            .collect();
        let retained_participants: Vec<_> = self.participants.iter().collect();
        if expected_participants != retained_participants {
            return Err(ContractViolation::BindingMismatch {
                field: "candidate.participants",
                reason: "flattened participants differ from retained events".to_owned(),
            });
        }
        let expected_outcomes: Vec<_> = self
            .events
            .iter()
            .flat_map(|event| event.outcomes.iter())
            .collect();
        let retained_outcomes: Vec<_> = self.outcomes.iter().collect();
        if expected_outcomes != retained_outcomes {
            return Err(ContractViolation::BindingMismatch {
                field: "candidate.outcomes",
                reason: "flattened outcomes differ from retained events".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_chronology_records(&self) -> Result<(), ContractViolation> {
        let event_ids: std::collections::BTreeSet<_> = self
            .events
            .iter()
            .map(|event| event.core.event_id_and_time.event_id.as_str())
            .collect();
        for link in &self.chronology {
            eliot_dreamer_contracts::error::check_text(
                &link.left_event_id,
                "candidate.chronology.before",
                MAX_TEXT,
            )?;
            eliot_dreamer_contracts::error::check_text(
                &link.right_event_id,
                "candidate.chronology.after",
                MAX_TEXT,
            )?;
            if !event_ids.contains(link.left_event_id.as_str())
                || !event_ids.contains(link.right_event_id.as_str())
                || link.left_event_id == link.right_event_id
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "candidate.chronology",
                    reason: "chronology edge names an absent event".to_owned(),
                });
            }
            let left = self
                .events
                .iter()
                .find(|event| event.core.event_id_and_time.event_id == link.left_event_id)
                .ok_or(ContractViolation::BindingMismatch {
                    field: "candidate.chronology",
                    reason: "chronology left endpoint is absent".to_owned(),
                })?;
            let right = self
                .events
                .iter()
                .find(|event| event.core.event_id_and_time.event_id == link.right_event_id)
                .ok_or(ContractViolation::BindingMismatch {
                    field: "candidate.chronology",
                    reason: "chronology right endpoint is absent".to_owned(),
                })?;
            match link.relation {
                ChronologyRelation::Before | ChronologyRelation::After => {
                    let expected: Vec<_> = [
                        left.temporal_binding.as_ref(),
                        right.temporal_binding.as_ref(),
                    ]
                    .into_iter()
                    .flatten()
                    .cloned()
                    .collect();
                    if expected.len() != 2 || link.support != expected {
                        return Err(ContractViolation::BindingMismatch {
                            field: "candidate.chronology.support",
                            reason: "ordered chronology lacks both endpoint bindings".to_owned(),
                        });
                    }
                }
                ChronologyRelation::Concurrent
                | ChronologyRelation::Incomparable
                | ChronologyRelation::Unknown
                    if !link.support.is_empty() =>
                {
                    return Err(ContractViolation::BindingMismatch {
                        field: "candidate.chronology.support",
                        reason: "nonordered chronology carries unsupported evidence".to_owned(),
                    });
                }
                _ => {}
            }
            for support in &link.support {
                support.validate()?;
            }
        }
        Ok(())
    }

    fn validate_rollback(&self) -> Result<(), ContractViolation> {
        self.rollback.source_fence.validate().map_err(|error| {
            ContractViolation::BindingMismatch {
                field: "candidate.rollback.fence",
                reason: error.to_string(),
            }
        })?;
        if self.rollback.retained_event_ids.is_empty()
            || self.rollback.retained_event_ids.len() != self.events.len()
        {
            return Err(ContractViolation::BindingMismatch {
                field: "candidate.rollback.events",
                reason: "rollback closure does not retain every event".to_owned(),
            });
        }
        Ok(())
    }

    /// Computes the result identity without recursively hashing the handler
    /// receipt, whose result digest points back to this preimage.
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        let preimage = CandidatePreimage {
            candidate_id: &self.candidate_id,
            request_id: &self.request_id,
            receipt_id: &self.receipt_id,
            job_id: &self.job_id,
            task_id: &self.task_id,
            scope_id: &self.scope_id,
            state_fence: &self.state_fence,
            policy_id: &self.policy_id,
            policy_digest: &self.policy_digest,
            handler_id: &self.handler_id,
            handler_request_digest: &self.handler_request_digest,
            admission_item_digest: &self.admission_item_digest,
            admission_receipt_digest: &self.admission_receipt_digest,
            screen_coverage_digest: &self.screen_coverage_digest,
            whole_input_digest: &self.whole_input_digest,
            kind: self.kind,
            family: self.family,
            episode: &self.episode,
            status: self.status,
            disposition: self.disposition,
            boundary: &self.boundary,
            events: &self.events,
            participants: &self.participants,
            outcomes: &self.outcomes,
            chronology: &self.chronology,
            coverage: &self.coverage,
            overlap: &self.overlap,
            rollback: &self.rollback,
            preservation: &self.preservation,
            source: &self.source,
            event_denominator: &self.event_denominator,
            event_receipt: &self.event_receipt,
            existing: &self.existing,
        };
        capped_serialized_len(&preimage, MAX_SERIALIZED_INPUT).map_err(|reason| {
            ContractViolation::Budget {
                dimension: "episode.result_bytes",
                reason,
            }
        })?;
        Ok(digest_hex(&canonical_bytes(&preimage)?))
    }

    pub(crate) fn computed_identity(&self) -> Result<String, ContractViolation> {
        let preimage = CandidateIdentityPreimage {
            request_id: &self.request_id,
            receipt_id: &self.receipt_id,
            job_id: &self.job_id,
            task_id: &self.task_id,
            scope_id: &self.scope_id,
            policy_id: &self.policy_id,
            policy_digest: &self.policy_digest,
            episode: &self.episode,
            events: &self.events,
            source: &self.source.identity,
            event_denominator: &self.event_denominator,
            event_receipt: &self.event_receipt,
            existing: &self.existing,
            whole_input_digest: &self.whole_input_digest,
        };
        capped_serialized_len(&preimage, MAX_SERIALIZED_INPUT).map_err(|reason| {
            ContractViolation::Budget {
                dimension: "episode.identity_bytes",
                reason,
            }
        })?;
        Ok(digest_hex(&canonical_bytes(&preimage)?))
    }
}

#[derive(Serialize)]
struct CandidatePreimage<'a> {
    candidate_id: &'a str,
    request_id: &'a str,
    receipt_id: &'a str,
    job_id: &'a str,
    task_id: &'a str,
    scope_id: &'a str,
    state_fence: &'a StateFence,
    policy_id: &'a str,
    policy_digest: &'a str,
    handler_id: &'a str,
    handler_request_digest: &'a str,
    admission_item_digest: &'a str,
    admission_receipt_digest: &'a str,
    screen_coverage_digest: &'a str,
    whole_input_digest: &'a str,
    kind: CurationKind,
    family: CurationFamily,
    episode: &'a str,
    status: EpisodeStatus,
    disposition: CandidateDisposition,
    boundary: &'a EpisodeBoundary,
    events: &'a [GroundedEvent],
    participants: &'a [EpisodeParticipant],
    outcomes: &'a [EpisodeOutcome],
    chronology: &'a [ChronologyLink],
    coverage: &'a EpisodeCoverage,
    overlap: &'a OverlapAssessment,
    rollback: &'a EpisodeRollback,
    preservation: &'a PreservationReport,
    source: &'a SourceSnapshot,
    event_denominator: &'a CoverageDenominator,
    event_receipt: &'a CoverageReceipt,
    existing: &'a ExistingEpisodeSnapshot,
}

#[derive(Serialize)]
struct CandidateIdentityPreimage<'a> {
    request_id: &'a str,
    receipt_id: &'a str,
    job_id: &'a str,
    task_id: &'a str,
    scope_id: &'a str,
    policy_id: &'a str,
    policy_digest: &'a str,
    episode: &'a str,
    events: &'a [GroundedEvent],
    source: &'a eliot_memory_curation_contracts::SourceIdentity,
    event_denominator: &'a CoverageDenominator,
    event_receipt: &'a CoverageReceipt,
    existing: &'a ExistingEpisodeSnapshot,
    whole_input_digest: &'a str,
}
