use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ContractError, CurationFinding, CurationScreenRequest, Digest, Eligibility, MemberDisposition,
    MemberId, ProtectionAssessment, ScreenCoverage, ScreenFrontier, SourceSnapshot,
    contract_digest, source_matches, validate_findings,
};

/// Explicit state of a complete or bounded screen result.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResultState {
    /// Every denominator member is terminal.
    Complete,
    /// Work stopped with an explicit frontier.
    Partial,
    /// Work is blocked by protection or source uncertainty.
    Blocked,
    /// State cannot be established.
    Unknown,
}

/// Distinct changed targets and immutable references retained by fan-in.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberSets {
    /// Members a later owner may consider for semantic change.
    pub changed_targets: BTreeSet<MemberId>,
    /// Members retained only as immutable evidence/reference.
    pub immutable_references: BTreeSet<MemberId>,
}
impl MemberSets {
    /// Validates that references cannot accidentally become changed targets.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self
            .changed_targets
            .iter()
            .any(|id| self.immutable_references.contains(id))
        {
            return Err(ContractError::Reconciliation {
                field: "member_sets.disjoint",
            });
        }
        Ok(())
    }
}

/// Read-only result handed to a later semantic curation owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurationScreenResult {
    /// Exact request identity and profile.
    pub request: CurationScreenRequest,
    /// Immutable source snapshot identity and denominator.
    pub source: SourceSnapshot,
    /// Structural findings.
    pub findings: Vec<CurationFinding>,
    /// Independent protection assessments.
    pub protection: Vec<ProtectionAssessment>,
    /// Neutral eligibility decisions.
    pub eligibility: Vec<Eligibility>,
    /// Every observed member has one disposition.
    pub coverage: ScreenCoverage,
    /// Distinct target/reference boundary for downstream fan-in.
    pub member_sets: MemberSets,
    /// Explicit result state.
    pub state: ResultState,
    /// Digest of the result payload excluding this field.
    pub result_digest: Digest,
}
impl CurationScreenResult {
    /// Computes the result digest while excluding the digest field itself.
    pub fn computed_digest(&self) -> Result<Digest, ContractError> {
        #[derive(Serialize)]
        struct Payload<'a> {
            request: &'a CurationScreenRequest,
            source: &'a SourceSnapshot,
            findings: &'a [CurationFinding],
            protection: &'a [ProtectionAssessment],
            eligibility: &'a [Eligibility],
            coverage: &'a ScreenCoverage,
            member_sets: &'a MemberSets,
            state: ResultState,
        }
        contract_digest(&Payload {
            request: &self.request,
            source: &self.source,
            findings: &self.findings,
            protection: &self.protection,
            eligibility: &self.eligibility,
            coverage: &self.coverage,
            member_sets: &self.member_sets,
            state: self.state,
        })
    }
    /// Validates all cross-record bindings and complete/partial semantics.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), ContractError> {
        self.request.validate_snapshot(&self.source)?;
        if self.result_digest != self.computed_digest()? {
            return Err(ContractError::Reconciliation {
                field: "result.digest",
            });
        }
        self.member_sets.validate()?;
        if self.member_sets.changed_targets != self.request.partition.changed_targets
            || self.member_sets.immutable_references != self.request.partition.immutable_references
        {
            return Err(ContractError::Reconciliation {
                field: "result.member_partition",
            });
        }
        self.coverage.validate_against_source(&self.source)?;
        if self.coverage.members.len() as u64 > self.request.profile.limits.max_items
            || self.coverage.usage.work_units > self.request.profile.limits.max_work_units
            || self.coverage.usage.input_bytes > self.request.profile.limits.max_bytes
            || self.coverage.usage.output_bytes > self.request.profile.limits.max_output_bytes
        {
            return Err(ContractError::Bound {
                field: "result.limits",
            });
        }
        let start =
            usize::try_from(self.coverage.start_position).map_err(|_| ContractError::Bound {
                field: "coverage.start_position",
            })?;
        if start > self.coverage.members.len() || start > self.source.members.len() {
            return Err(ContractError::Reconciliation {
                field: "coverage.start_position",
            });
        }
        if let Some(previous) = &self.request.cursor {
            previous.validate(&self.request)?;
            let previous_position =
                usize::try_from(previous.position).map_err(|_| ContractError::Bound {
                    field: "cursor.position",
                })?;
            if previous_position > self.source.members.len()
                || self.coverage.start_position != previous.position
            {
                return Err(ContractError::Reconciliation {
                    field: "coverage.start_position",
                });
            }
            let prefix: Vec<_> = self.source.members[..previous_position]
                .iter()
                .map(|member| member.member_id.clone())
                .collect();
            if contract_digest(&prefix)? != previous.processed_member_digest {
                return Err(ContractError::Reconciliation {
                    field: "cursor.processed_member_digest",
                });
            }
        } else if start != 0 {
            return Err(ContractError::Reconciliation {
                field: "coverage.start_position",
            });
        }
        let page_members: Vec<_> = self.coverage.members[start..]
            .iter()
            .map(|member| member.member_id.clone())
            .collect();
        if let Some(cursor) = &self.coverage.next_cursor {
            if cursor.position != self.coverage.end_position()? {
                return Err(ContractError::Reconciliation {
                    field: "cursor.coverage_position",
                });
            }
            if cursor.usage != self.coverage.usage {
                return Err(ContractError::Reconciliation {
                    field: "cursor.coverage_usage",
                });
            }
            cursor.validate_progress(
                &self.request,
                &self.source,
                self.request.cursor.as_ref(),
                &page_members,
            )?;
        } else if let Some(previous) = &self.request.cursor
            && (self.coverage.usage.processed_items < previous.usage.processed_items
                || self.coverage.usage.work_units < previous.usage.work_units
                || self.coverage.usage.input_bytes < previous.usage.input_bytes
                || self.coverage.usage.output_bytes < previous.usage.output_bytes)
        {
            return Err(ContractError::Reconciliation {
                field: "result.cumulative_usage",
            });
        }
        validate_findings(
            &self.findings,
            &self.source.identity,
            &self.request.profile.profile_id,
        )?;
        let source_ids = self.source.member_ids();
        for finding in &self.findings {
            if !source_ids.contains(&finding.member_id) {
                return Err(ContractError::BindingMismatch {
                    field: "finding.member",
                });
            }
            let rule = self
                .request
                .profile
                .rules
                .iter()
                .find(|rule| rule.rule_id == finding.rule_id)
                .ok_or(ContractError::BindingMismatch {
                    field: "finding.rule",
                })?;
            if rule.finding_class != finding.class {
                return Err(ContractError::BindingMismatch {
                    field: "finding.rule_class",
                });
            }
            if let Some(assessment) = self
                .protection
                .iter()
                .find(|assessment| assessment.member_id == finding.member_id)
                && !assessment.applicable_rule_ids.contains(&finding.rule_id)
            {
                return Err(ContractError::Reconciliation {
                    field: "finding.applicable_rule",
                });
            }
        }
        let coverage_ids = self.coverage.member_ids();
        let coverage_order: Vec<_> = self
            .coverage
            .members
            .iter()
            .map(|member| member.member_id.clone())
            .collect();
        let source_order: Vec<_> = self
            .source
            .members
            .iter()
            .map(|member| member.member_id.clone())
            .collect();
        if !coverage_ids.is_subset(&source_ids) {
            return Err(ContractError::Reconciliation {
                field: "coverage.source_members",
            });
        }
        for assessment in &self.protection {
            assessment.validate()?;
            source_matches(&self.source.identity, &assessment.source)?;
            if !source_ids.contains(&assessment.member_id) {
                return Err(ContractError::BindingMismatch {
                    field: "protection.member",
                });
            }
            let mut expected_required = BTreeSet::new();
            for rule_id in &assessment.applicable_rule_ids {
                let rule = self
                    .request
                    .profile
                    .rules
                    .iter()
                    .find(|rule| rule.rule_id == *rule_id)
                    .ok_or(ContractError::BindingMismatch {
                        field: "protection.applicable_rule",
                    })?;
                expected_required.extend(rule.required_protection.iter().copied());
            }
            if expected_required != assessment.required {
                return Err(ContractError::Reconciliation {
                    field: "protection.required",
                });
            }
        }
        for item in &self.eligibility {
            item.validate(&self.findings, &self.request.profile.profile_id)?;
            source_matches(&self.source.identity, &item.source)?;
            if !source_ids.contains(&item.member_id) {
                return Err(ContractError::BindingMismatch {
                    field: "eligibility.member",
                });
            }
            let assessment = self
                .protection
                .iter()
                .find(|candidate| candidate.member_id == item.member_id)
                .ok_or(ContractError::BindingMismatch {
                    field: "eligibility.protection_assessment",
                })?;
            if item.protection != assessment.decision {
                return Err(ContractError::Reconciliation {
                    field: "eligibility.protection",
                });
            }
            if item.status == crate::EligibilityStatus::EligibleForSemanticCuration
                && (assessment.decision != crate::ProtectionDecision::Unprotected
                    || assessment.applicable_rule_ids.is_empty())
            {
                return Err(ContractError::Reconciliation {
                    field: "eligibility.protected",
                });
            }
            if item.status == crate::EligibilityStatus::Protected
                && assessment.decision != crate::ProtectionDecision::Protected
            {
                return Err(ContractError::Reconciliation {
                    field: "eligibility.protected",
                });
            }
        }
        for member in &self.coverage.members {
            if self
                .member_sets
                .immutable_references
                .contains(&member.member_id)
                && member.disposition != MemberDisposition::PreservedReference
            {
                return Err(ContractError::Reconciliation {
                    field: "coverage.reference_disposition",
                });
            }
            if member.disposition == MemberDisposition::Eligible {
                let eligibility = self
                    .eligibility
                    .iter()
                    .find(|item| item.member_id == member.member_id)
                    .ok_or(ContractError::BindingMismatch {
                        field: "coverage.eligibility",
                    })?;
                if eligibility.status != crate::EligibilityStatus::EligibleForSemanticCuration
                    || eligibility.protection != crate::ProtectionDecision::Unprotected
                {
                    return Err(ContractError::Reconciliation {
                        field: "coverage.eligible",
                    });
                }
            } else if member.disposition == MemberDisposition::Protected {
                let assessment = self
                    .protection
                    .iter()
                    .find(|item| item.member_id == member.member_id)
                    .ok_or(ContractError::BindingMismatch {
                        field: "coverage.protection",
                    })?;
                if assessment.decision != crate::ProtectionDecision::Protected {
                    return Err(ContractError::Reconciliation {
                        field: "coverage.protected",
                    });
                }
            } else if member.eligible {
                return Err(ContractError::Reconciliation {
                    field: "coverage.eligible",
                });
            }
            if member.disposition == MemberDisposition::PreservedReference
                && !self
                    .member_sets
                    .immutable_references
                    .contains(&member.member_id)
            {
                return Err(ContractError::Reconciliation {
                    field: "coverage.reference",
                });
            }
            for finding_id in &member.finding_ids {
                let finding = self
                    .findings
                    .iter()
                    .find(|finding| finding.finding_id == *finding_id)
                    .ok_or(ContractError::BindingMismatch {
                        field: "coverage.finding",
                    })?;
                if finding.member_id != member.member_id {
                    return Err(ContractError::BindingMismatch {
                        field: "coverage.finding_member",
                    });
                }
            }
        }
        if self
            .protection
            .iter()
            .map(|item| &item.member_id)
            .collect::<BTreeSet<_>>()
            .len()
            != self.protection.len()
            || self
                .eligibility
                .iter()
                .map(|item| &item.member_id)
                .collect::<BTreeSet<_>>()
                .len()
                != self.eligibility.len()
        {
            return Err(ContractError::Duplicate {
                field: "result.member_records",
            });
        }
        if self.state == ResultState::Complete
            && (!self.source.denominator.is_complete()
                || self.coverage.frontier
                    != (ScreenFrontier {
                        complete: true,
                        remaining: Vec::new(),
                    })
                || coverage_order != source_order
                || self
                    .coverage
                    .members
                    .iter()
                    .any(|member| member.disposition == MemberDisposition::Unprocessed)
                || self.coverage.next_cursor.is_some())
        {
            return Err(ContractError::Reconciliation {
                field: "result.complete",
            });
        }
        if self.state == ResultState::Partial && self.coverage.frontier.complete {
            return Err(ContractError::Reconciliation {
                field: "result.partial_frontier",
            });
        }
        if !self.member_sets.changed_targets.is_subset(&source_ids)
            || !self.member_sets.immutable_references.is_subset(&source_ids)
        {
            return Err(ContractError::Reconciliation {
                field: "member_sets.source",
            });
        }
        Ok(())
    }
}
