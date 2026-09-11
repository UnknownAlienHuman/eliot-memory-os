//! Structural input closure and exact source/evidence joins for Concept.

use eliot_contracts::{ArtifactId, StateFence};
use eliot_receipts::ProofCeiling;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};

use crate::curation::{CurationKind, CurationPayload};
use crate::draft::{CurationAcceptanceCtx, ValidatedCurationItem};
use crate::encoding::{canonical_bytes, digest_hex};
use crate::error::{ContractViolation, check_fence, check_text, check_vec_bound, is_hex64_lower};
use crate::job::DreamJobInput;
use crate::registry::TypedCurationHandlerRequest;
use crate::screen::{ScreenBinding, ScreenState};

use super::proposal::{
    ConceptCoverage, ConceptEvidence, ConceptNeighborhood, ConceptProposal, ConceptSourceRef,
    MAX_ITEMS, MAX_TEXT, SCHEMA_VERSION, concept_proposal_digest, normalized_preservation,
    normalized_proposal,
};

const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;

fn check_id(id: &ArtifactId, field: &'static str) -> Result<(), ContractViolation> {
    check_text(id.as_str(), field, MAX_TEXT)
}

fn check_digest(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    if is_hex64_lower(value) {
        Ok(())
    } else {
        Err(ContractViolation::Malformed {
            field,
            reason: "must be lowercase sha256".to_owned(),
        })
    }
}

fn check_ids(values: &[ArtifactId], field: &'static str) -> Result<(), ContractViolation> {
    check_vec_bound(values.len(), MAX_ITEMS, field)?;
    for (index, id) in values.iter().enumerate() {
        check_id(id, field)?;
        if values[..index].contains(id) {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "duplicate identity".to_owned(),
            });
        }
    }
    Ok(())
}

/// Finite source denominator; omitted members remain explicit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConceptSourceDenominator {
    pub expected_total: u32,
    pub processed: Vec<ArtifactId>,
    pub omitted: Vec<ArtifactId>,
    pub coverage: ConceptCoverage,
}

impl ConceptSourceDenominator {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        let expected =
            usize::try_from(self.expected_total).map_err(|_| ContractViolation::OutOfBounds {
                field: "concept.sources.expected_total",
                min: 0,
                max: 1024,
                got: i64::MAX,
            })?;
        check_vec_bound(expected, 1024, "concept.sources.expected_total")?;
        check_ids(&self.processed, "concept.sources.processed")?;
        check_ids(&self.omitted, "concept.sources.omitted")?;
        let actual = self.processed.len().checked_add(self.omitted.len()).ok_or(
            ContractViolation::OutOfBounds {
                field: "concept.sources.denominator",
                min: 0,
                max: 1024,
                got: i64::MAX,
            },
        )?;
        if actual != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.sources.denominator",
                reason: "processed plus omitted must equal expected_total".to_owned(),
            });
        }
        if self.processed.iter().any(|id| self.omitted.contains(id)) {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.sources.denominator",
                reason: "processed and omitted source partitions overlap".to_owned(),
            });
        }
        if matches!(self.coverage, ConceptCoverage::Complete) && !self.omitted.is_empty() {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.sources.coverage",
                reason: "complete denominator cannot omit members".to_owned(),
            });
        }
        Ok(())
    }
}

/// Exact admitted source set plus its finite denominator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConceptSourceSet {
    pub sources: Vec<ConceptSourceRef>,
    pub denominator: ConceptSourceDenominator,
}

impl ConceptSourceSet {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.denominator.validate()?;
        check_vec_bound(self.sources.len(), MAX_ITEMS, "concept.sources")?;
        let ids: Vec<_> = self
            .sources
            .iter()
            .map(|source| source.source_id.clone())
            .collect();
        check_ids(&ids, "concept.sources.ids")?;
        self.sources
            .iter()
            .try_for_each(ConceptSourceRef::validate)?;
        if ids != self.denominator.processed {
            let mut left = ids;
            let mut right = self.denominator.processed.clone();
            left.sort();
            right.sort();
            if left != right {
                return Err(ContractViolation::BindingMismatch {
                    field: "concept.sources.processed",
                    reason: "source set differs from processed denominator".to_owned(),
                });
            }
        }
        if self
            .denominator
            .omitted
            .iter()
            .any(|id| self.sources.iter().any(|source| &source.source_id == id))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.sources.omitted",
                reason: "omitted source is present".to_owned(),
            });
        }
        Ok(())
    }
}

/// Complete structural input presented to the future Concept handler.
///
/// The common A-03 item, receipt, screen and job are accepted through their
/// existing owner checks. The Concept proposal closure is then retained as a
/// candidate assertion and digest input; this module does not authenticate its
/// semantic truth or promote it into current state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConceptInput {
    pub schema_version: u32,
    pub operation_id: ArtifactId,
    pub request_id: String,
    pub idempotency_key: String,
    pub task_id: String,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub policy_digest: String,
    pub job: DreamJobInput,
    pub item: ValidatedCurationItem,
    pub request: TypedCurationHandlerRequest,
    pub sources: ConceptSourceSet,
    pub proposal: ConceptProposal,
    pub neighborhood: ConceptNeighborhood,
    pub screen: ScreenBinding,
    pub preservation: crate::relation::RelationPreservation,
}

impl ConceptInput {
    pub fn preflight(&self) -> Result<(), ContractViolation> {
        let mut writer = BoundedWriter {
            len: 0,
            max: MAX_INPUT_BYTES,
            exceeded: false,
        };
        match serde_json::to_writer(&mut writer, self) {
            Ok(()) => Ok(()),
            Err(_error) if writer.exceeded => Err(ContractViolation::OutOfBounds {
                field: "concept.input_bytes",
                min: 0,
                max: i64::try_from(MAX_INPUT_BYTES).unwrap_or(i64::MAX),
                got: i64::try_from(writer.len).unwrap_or(i64::MAX),
            }),
            Err(error) => Err(ContractViolation::Malformed {
                field: "concept.input",
                reason: error.to_string(),
            }),
        }
    }

    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.preflight()?;
        self.validate_header()?;
        self.sources.validate()?;
        self.proposal.validate()?;
        self.neighborhood.validate()?;
        self.validate_reference_closure()?;
        self.validate_screen_and_request()?;
        if self.proposal.preservation != self.preservation {
            return Err(ContractViolation::Preservation(
                "proposal and input must reuse one A-03 preservation report".to_owned(),
            ));
        }
        self.preservation.validate()
    }

    fn validate_header(&self) -> Result<(), ContractViolation> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ContractViolation::OutOfBounds {
                field: "concept.schema_version",
                min: 1,
                max: 1,
                got: self.schema_version.into(),
            });
        }
        check_id(&self.operation_id, "concept.operation_id")?;
        for (value, field) in [
            (&self.request_id, "concept.request_id"),
            (&self.idempotency_key, "concept.idempotency_key"),
            (&self.task_id, "concept.task_id"),
            (&self.scope_id, "concept.scope_id"),
        ] {
            check_text(value, field, MAX_TEXT)?;
        }
        check_digest(&self.policy_digest, "concept.policy_digest")?;
        check_fence(&self.state_fence)?;
        self.job.validate()?;
        if self.job.job_class != crate::job::JobClass::Curation
            || self.job.operation_id != self.operation_id.as_str()
            || self.job.idempotency_key != self.idempotency_key
            || self.job.task_id != self.task_id
            || self.job.scope_id != self.scope_id
            || self.job.state_fence != self.state_fence
            || self.item.requester != self.job.requester
            || self.item.job_digest != digest_hex(&canonical_bytes(&self.job)?)
        {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.job_identity",
                reason: "job and input identity or budget/privacy closure drift".to_owned(),
            });
        }
        self.item.validate()?;
        if self.item.kind_spelling != CurationKind::Concept.as_str()
            || self.item.payload.kind() != CurationKind::Concept
        {
            return Err(ContractViolation::KindPayload(
                "concept input requires the Concept curation item".to_owned(),
            ));
        }
        if self.item.task_id != self.task_id
            || self.item.scope_id != self.scope_id
            || self.item.state_fence != self.state_fence
        {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.item_identity",
                reason: "item task/scope/fence drift".to_owned(),
            });
        }
        if self.request.kind != CurationKind::Concept
            || self.request.family != crate::registry::CurationFamily::Concept
        {
            return Err(ContractViolation::KindPayload(
                "concept request requires Concept kind/family".to_owned(),
            ));
        }
        if self.request.job_id != self.item.receipt.job_id {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.request.job_id",
                reason: "request job identity differs from admitted item".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_reference_closure(&self) -> Result<(), ContractViolation> {
        let source_ids: Vec<_> = self
            .sources
            .sources
            .iter()
            .map(|source| source.source_id.clone())
            .collect();
        let evidence_ids: Vec<_> = self
            .proposal
            .evidence
            .iter()
            .map(ConceptEvidence::evidence_id)
            .cloned()
            .collect();
        let snapshot_ids: Vec<_> = self
            .neighborhood
            .concepts
            .iter()
            .map(|concept| concept.concept_id.clone())
            .collect();
        self.validate_source_phase(&source_ids)?;
        self.validate_evidence_case_phase(&source_ids, &evidence_ids)?;
        self.validate_neighborhood_dependency_phase(&source_ids, &evidence_ids, &snapshot_ids)?;
        self.validate_discriminator_phase(&evidence_ids, &snapshot_ids)
    }

    fn validate_source_phase(&self, source_ids: &[ArtifactId]) -> Result<(), ContractViolation> {
        for source in &self.sources.sources {
            if source.task_id.as_str() != self.task_id
                || source.scope_id.as_str() != self.scope_id
                || source.state_fence != self.state_fence
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "concept.source_identity",
                    reason: "source task/scope/fence differs from input".to_owned(),
                });
            }
        }
        if self
            .proposal
            .source_refs
            .iter()
            .any(|id| !source_ids.contains(id))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.proposal.source_refs",
                reason: "proposal source is not in admitted source set".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_evidence_case_phase(
        &self,
        source_ids: &[ArtifactId],
        evidence_ids: &[ArtifactId],
    ) -> Result<(), ContractViolation> {
        self.validate_payload_and_criteria(source_ids, evidence_ids)?;
        self.validate_cases_and_evidence(&self.proposal, source_ids, evidence_ids)
    }

    fn validate_payload_and_criteria(
        &self,
        source_ids: &[ArtifactId],
        evidence_ids: &[ArtifactId],
    ) -> Result<(), ContractViolation> {
        let CurationPayload::Concept(payload) = &self.item.payload else {
            return Err(ContractViolation::KindPayload(
                "concept input payload changed kind during closure validation".to_owned(),
            ));
        };
        if payload.concept != self.proposal.name || payload.definition != self.proposal.definition {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.payload",
                reason: "legacy payload fields differ from structured proposal".to_owned(),
            });
        }
        for handle in &payload.target_evidence.evidence_refs {
            if !evidence_ids.iter().any(|id| id.as_str() == handle) {
                return Err(ContractViolation::BindingMismatch {
                    field: "concept.payload.evidence_refs",
                    reason: "payload evidence is not named in proposal".to_owned(),
                });
            }
        }
        for criterion in &self.proposal.criteria {
            for id in criterion
                .evidence_refs
                .iter()
                .chain(&criterion.exception_refs)
            {
                if !evidence_ids.contains(id) {
                    return Err(ContractViolation::BindingMismatch {
                        field: "concept.criterion.evidence_refs",
                        reason: "criterion reference is not retained".to_owned(),
                    });
                }
            }
        }
        if self
            .proposal
            .applicability
            .source_refs
            .iter()
            .any(|id| !source_ids.contains(id))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.applicability.source_refs",
                reason: "applicability source is not retained".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_cases_and_evidence(
        &self,
        proposal: &ConceptProposal,
        source_ids: &[ArtifactId],
        evidence_ids: &[ArtifactId],
    ) -> Result<(), ContractViolation> {
        for case in &proposal.cases {
            if !source_ids.contains(&case.source_ref)
                || case
                    .evidence_refs
                    .iter()
                    .any(|id| !evidence_ids.contains(id))
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "concept.case.references",
                    reason: "case source/evidence is not retained".to_owned(),
                });
            }
        }
        for evidence in &proposal.evidence {
            if evidence
                .source_refs
                .iter()
                .any(|id| !source_ids.contains(id))
                || evidence
                    .named
                    .source_handles
                    .iter()
                    .any(|id| !source_ids.contains(id))
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "concept.evidence.source_refs",
                    reason: "evidence source handle is not retained".to_owned(),
                });
            }
            let envelope = &evidence.named.foundation_evidence_envelope;
            if envelope.state_fence != self.state_fence
                || envelope.provenance.scope != self.scope_id
                || !source_ids
                    .iter()
                    .any(|id| id.as_str() == envelope.provenance.source_id.as_str())
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "concept.evidence.envelope",
                    reason: "evidence envelope scope/fence/source differs from input".to_owned(),
                });
            }
            if let Some(raw_handle) = &envelope.provenance.raw_handle
                && !source_ids.iter().any(|id| id.as_str() == raw_handle)
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "concept.evidence.raw_handle",
                    reason: "raw evidence handle is not retained".to_owned(),
                });
            }
            if let Some(revision) = &envelope.provenance.revision {
                let Some(source) = source_ids
                    .iter()
                    .find(|id| id.as_str() == envelope.provenance.source_id.as_str())
                    .and_then(|id| {
                        self.sources
                            .sources
                            .iter()
                            .find(|source| &source.source_id == id)
                    })
                else {
                    return Err(ContractViolation::BindingMismatch {
                        field: "concept.evidence.revision",
                        reason: "evidence revision source is not retained".to_owned(),
                    });
                };
                if revision != &source.source_revision {
                    return Err(ContractViolation::BindingMismatch {
                        field: "concept.evidence.revision",
                        reason: "evidence revision differs from retained source".to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_neighborhood_dependency_phase(
        &self,
        source_ids: &[ArtifactId],
        evidence_ids: &[ArtifactId],
        snapshot_ids: &[ArtifactId],
    ) -> Result<(), ContractViolation> {
        self.validate_dependency_bindings(source_ids)?;
        self.validate_snapshot_bindings(source_ids, evidence_ids, snapshot_ids)?;
        self.validate_omitted_bindings(snapshot_ids)
    }

    fn validate_dependency_bindings(
        &self,
        source_ids: &[ArtifactId],
    ) -> Result<(), ContractViolation> {
        if self
            .proposal
            .dependencies
            .iter()
            .enumerate()
            .any(|(index, dependency)| {
                self.proposal.dependencies[..index]
                    .iter()
                    .any(|previous| previous.dependency_id == dependency.dependency_id)
            })
        {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.dependencies",
                reason: "duplicate dependency identity".to_owned(),
            });
        }
        for dependency in &self.proposal.dependencies {
            if dependency
                .source_refs
                .iter()
                .any(|id| !source_ids.contains(id))
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "concept.dependency.source_refs",
                    reason: "dependency source is not retained".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_snapshot_bindings(
        &self,
        source_ids: &[ArtifactId],
        evidence_ids: &[ArtifactId],
        snapshot_ids: &[ArtifactId],
    ) -> Result<(), ContractViolation> {
        if snapshot_ids
            .iter()
            .enumerate()
            .any(|(index, id)| snapshot_ids[..index].contains(id))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.neighborhood",
                reason: "duplicate snapshot identity".to_owned(),
            });
        }
        for snapshot in &self.neighborhood.concepts {
            let mut snapshot_sources = snapshot.proposal.source_refs.clone();
            let mut retained_sources = snapshot.source_refs.clone();
            snapshot_sources.sort();
            retained_sources.sort();
            let mut snapshot_evidence: Vec<_> = snapshot
                .proposal
                .evidence
                .iter()
                .map(ConceptEvidence::evidence_id)
                .cloned()
                .collect();
            let mut retained_evidence = snapshot.evidence_refs.clone();
            snapshot_evidence.sort();
            retained_evidence.sort();
            if snapshot.scope_id.as_str() != self.scope_id
                || snapshot.state_fence != self.state_fence
                || snapshot_sources != retained_sources
                || snapshot_evidence != retained_evidence
                || concept_proposal_digest(&snapshot.proposal)? != snapshot.content_digest
                || snapshot
                    .source_refs
                    .iter()
                    .any(|id| !source_ids.contains(id))
                || snapshot
                    .evidence_refs
                    .iter()
                    .any(|id| !evidence_ids.contains(id))
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "concept.snapshot.references",
                    reason: "snapshot scope/fence or closure is not retained".to_owned(),
                });
            }
            self.validate_snapshot_proposal_bindings(
                &snapshot.proposal,
                source_ids,
                evidence_ids,
                snapshot_ids,
            )?;
        }
        Ok(())
    }

    fn validate_snapshot_proposal_bindings(
        &self,
        proposal: &ConceptProposal,
        source_ids: &[ArtifactId],
        evidence_ids: &[ArtifactId],
        snapshot_ids: &[ArtifactId],
    ) -> Result<(), ContractViolation> {
        self.validate_cases_and_evidence(proposal, source_ids, evidence_ids)?;
        if proposal
            .source_refs
            .iter()
            .any(|id| !source_ids.contains(id))
            || proposal
                .applicability
                .source_refs
                .iter()
                .any(|id| !source_ids.contains(id))
            || proposal.evidence.iter().any(|evidence| {
                evidence
                    .source_refs
                    .iter()
                    .chain(&evidence.named.source_handles)
                    .any(|id| !source_ids.contains(id))
                    || self
                        .proposal
                        .evidence
                        .iter()
                        .find(|retained| retained.evidence_id() == evidence.evidence_id())
                        != Some(evidence)
            })
            || proposal.criteria.iter().any(|criterion| {
                criterion
                    .evidence_refs
                    .iter()
                    .chain(&criterion.exception_refs)
                    .any(|id| !evidence_ids.contains(id))
            })
            || proposal.cases.iter().any(|case| {
                !source_ids.contains(&case.source_ref)
                    || case
                        .evidence_refs
                        .iter()
                        .any(|id| !evidence_ids.contains(id))
            })
            || proposal.dependencies.iter().any(|dependency| {
                dependency
                    .source_refs
                    .iter()
                    .any(|id| !source_ids.contains(id))
            })
            || proposal
                .discriminator
                .evidence_refs
                .iter()
                .any(|id| !evidence_ids.contains(id))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.snapshot.proposal",
                reason: "snapshot proposal closure is not retained".to_owned(),
            });
        }
        self.validate_discriminator_bindings(proposal, evidence_ids, snapshot_ids)
    }

    fn validate_omitted_bindings(
        &self,
        snapshot_ids: &[ArtifactId],
    ) -> Result<(), ContractViolation> {
        if self
            .proposal
            .case_omitted_refs
            .iter()
            .any(|id| self.proposal.cases.iter().any(|case| &case.case_id == id))
            || self
                .neighborhood
                .omitted_refs
                .iter()
                .any(|id| snapshot_ids.contains(id))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.omitted_refs",
                reason: "omitted identity is already processed".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_discriminator_phase(
        &self,
        evidence_ids: &[ArtifactId],
        snapshot_ids: &[ArtifactId],
    ) -> Result<(), ContractViolation> {
        self.validate_discriminator_bindings(&self.proposal, evidence_ids, snapshot_ids)
    }

    fn validate_discriminator_bindings(
        &self,
        proposal: &ConceptProposal,
        evidence_ids: &[ArtifactId],
        snapshot_ids: &[ArtifactId],
    ) -> Result<(), ContractViolation> {
        let validate_discriminator = |discriminator: &super::proposal::ConceptDiscriminator| {
            discriminator.evidence_refs.iter().try_for_each(|id| {
                if evidence_ids.contains(id) {
                    Ok(())
                } else {
                    Err(ContractViolation::BindingMismatch {
                        field: "concept.discriminator.evidence_refs",
                        reason: "discriminator evidence is not retained".to_owned(),
                    })
                }
            })?;
            let verifier_id = &discriminator.verifier.verifier_id;
            let Some(source) = self
                .sources
                .sources
                .iter()
                .find(|source| &source.source_id == verifier_id)
            else {
                return Err(ContractViolation::BindingMismatch {
                    field: "concept.discriminator.verifier",
                    reason: "verifier must be a retained source definition".to_owned(),
                });
            };
            if source.source_revision != discriminator.verifier.revision
                || source.content_digest != discriminator.verifier.digest
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "concept.discriminator.verifier",
                    reason: "verifier revision/digest differs from retained source".to_owned(),
                });
            }
            if let Some(alternative) = &discriminator.alternative_id
                && !snapshot_ids.contains(alternative)
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "concept.discriminator.alternative_id",
                    reason: "rival alternative is not in the supplied neighborhood".to_owned(),
                });
            }
            Ok(())
        };
        validate_discriminator(&proposal.discriminator)?;
        for rival in &proposal.rivals {
            validate_discriminator(rival)?;
        }
        if proposal
            .rivals
            .iter()
            .filter_map(|rival| rival.alternative_id.as_ref())
            .any(|id| {
                proposal
                    .rivals
                    .iter()
                    .filter_map(|rival| rival.alternative_id.as_ref())
                    .filter(|other| *other == id)
                    .count()
                    > 1
            })
        {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.rivals",
                reason: "duplicate rival alternative identity".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_screen_and_request(&self) -> Result<(), ContractViolation> {
        self.request.validate()?;
        self.screen.validate()?;
        if self.screen.state != ScreenState::Eligible
            || self.screen.task_id != self.task_id
            || self.screen.scope_id != self.scope_id
            || self.screen.state_fence != self.state_fence
        {
            return Err(ContractViolation::ScreenIneligible(
                "concept requires an exact eligible screen binding".to_owned(),
            ));
        }
        if self.request.request_id != self.request_id
            || self.request.task_id != self.task_id
            || self.request.scope_id != self.scope_id
            || self.request.state_fence != self.state_fence
            || self.request.payload != self.item.payload
            || self.request.denominator != self.item.denominator
        {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.request_identity",
                reason: "request identity or payload drift".to_owned(),
            });
        }
        let binding =
            self.request
                .screen_binding
                .as_ref()
                .ok_or(ContractViolation::ScreenIneligible(
                    "missing request screen binding".to_owned(),
                ))?;
        if binding != &self.screen
            || self.request.source_snapshot != self.screen.source_snapshot
            || self.request.source_revision != self.screen.source_revision
            || self.request.profile != self.screen.profile
            || self.request.receipt_id != self.screen.receipt_id.as_str()
        {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.screen_identity",
                reason: "request and retained screen differ".to_owned(),
            });
        }
        if self.proposal.policy_digest != self.policy_digest
            || self.proposal.proof_ceiling != ProofCeiling::CandidateArtifact
        {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.policy",
                reason: "policy or proof ceiling drift".to_owned(),
            });
        }
        Ok(())
    }
}

struct BoundedWriter {
    len: usize,
    max: usize,
    exceeded: bool,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .len
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("serialized Concept input length overflow"))?;
        if next > self.max {
            self.len = self.max.checked_add(1).unwrap_or(self.max);
            self.exceeded = true;
            return Err(io::Error::other("serialized Concept input exceeds bound"));
        }
        self.len = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
/// Canonical digest of the full input closure.
///
/// Proposal criteria, cases, and dependencies retain supplied order; source,
/// evidence, omission, and neighborhood collections are normalized as sets.
pub fn concept_input_digest(input: &ConceptInput) -> Result<String, ContractViolation> {
    input.validate()?;
    let mut normalized = input.clone();
    normalized
        .sources
        .sources
        .sort_by(|a, b| a.source_id.cmp(&b.source_id));
    normalized.sources.denominator.processed.sort();
    normalized.sources.denominator.omitted.sort();
    normalized.proposal = normalized_proposal(&normalized.proposal);
    normalized.preservation = normalized_preservation(&normalized.preservation);
    normalized
        .proposal
        .dependencies
        .iter_mut()
        .for_each(|dependency| dependency.source_refs.sort());
    normalized.proposal.case_omitted_refs.sort();
    normalized.neighborhood.omitted_refs.sort();
    normalized
        .neighborhood
        .concepts
        .sort_by(|left, right| left.concept_id.cmp(&right.concept_id));
    normalized
        .neighborhood
        .concepts
        .iter_mut()
        .for_each(|concept| {
            *concept.proposal = normalized_proposal(&concept.proposal);
            concept.source_refs.sort();
            concept.evidence_refs.sort();
        });
    normalized.item.payload = normalized.item.payload.normalized_for_digest();
    normalized.request.payload = normalized.request.payload.normalized_for_digest();
    let bytes = canonical_bytes(&normalized)?;
    Ok(digest_hex(&bytes))
}

/// Canonical digest of the exact typed dispatch request carried by the input.
pub(crate) fn concept_request_digest(
    request: &TypedCurationHandlerRequest,
) -> Result<String, ContractViolation> {
    let mut normalized = request.clone();
    normalized.payload = normalized.payload.normalized_for_digest();
    Ok(digest_hex(&canonical_bytes(&normalized)?))
}

/// Structural validator alias for consumers.
pub fn validate_concept(input: &ConceptInput) -> Result<(), ContractViolation> {
    input.validate()
}

/// Acceptance seam: common A-03 acceptance first, Concept joins second.
///
/// Common receipt authentication remains the responsibility of A-03/A-05 and
/// the supplied acceptance context. Concept-specific fields are structurally
/// joined to the accepted source/evidence closure here, without becoming a
/// second receipt authority.
pub fn validate_concept_acceptance(
    input: &ConceptInput,
    ctx: &CurationAcceptanceCtx<'_>,
) -> Result<(), ContractViolation> {
    input.validate()?;
    if input.job != *ctx.job || input.request != *ctx.request {
        return Err(ContractViolation::BindingMismatch {
            field: "concept.acceptance_identity",
            reason: "input job/request differs from accepted context".to_owned(),
        });
    }
    input.item.accept(ctx)?;
    if input.screen != *ctx.screen {
        return Err(ContractViolation::BindingMismatch {
            field: "concept.screen",
            reason: "retained screen differs from accepted screen".to_owned(),
        });
    }
    for source in &input.sources.sources {
        if !ctx.bundle.materials.iter().any(|material| {
            material.handle == source.source_id.as_str() && material.digest == source.content_digest
        }) {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.source_material",
                reason: "source identity/digest absent from accepted bundle".to_owned(),
            });
        }
    }
    for omitted in &input.sources.denominator.omitted {
        if !ctx.bundle.omissions.iter().any(|omission| {
            omission.handle == omitted.as_str()
                && omission.task_id == input.task_id
                && omission.scope_id == input.scope_id
        }) {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.omitted_source",
                reason: "omitted source is absent from accepted bundle omissions".to_owned(),
            });
        }
    }
    Ok(())
}
