//! Candidate assembly for the zero-effect relation handler.

use eliot_dreamer_contracts::{CurationKind, RelationCandidate, RelationInput, RelationRollback};
use eliot_receipts::ProofCeiling;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::policy::RelationPolicy;
use crate::selection::Selection;

const DIGEST_PLACEHOLDER: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const REOPEN_FRONTIER: &str = "reopen-on-endpoint-registry-evidence-digest-change";

#[derive(Serialize)]
struct ResultEnvelope<'a> {
    closure: &'a eliot_dreamer_contracts::RelationCandidateClosure,
    policy: &'a RelationPolicy,
    disposition: eliot_dreamer_contracts::RelationDisposition,
    unknown_evidence_refs: &'a [String],
    work_units: u64,
    stu_used: u64,
    expiry: Option<&'a String>,
    reopen_frontier: Option<&'a String>,
    degradation: Option<&'a String>,
    result_digest: &'static str,
}

pub(crate) struct ResultParts<'a> {
    pub closure: &'a eliot_dreamer_contracts::RelationCandidateClosure,
    pub policy: &'a RelationPolicy,
    pub disposition: eliot_dreamer_contracts::RelationDisposition,
    pub unknown_evidence_refs: &'a [String],
    pub work_units: u64,
    pub stu_used: u64,
    pub expiry: Option<&'a String>,
    pub reopen_frontier: Option<&'a String>,
    pub degradation: Option<&'a String>,
}

/// Bounded handler result retaining semantic policy and degradation trace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationResult {
    pub closure: eliot_dreamer_contracts::RelationCandidateClosure,
    pub policy: RelationPolicy,
    pub disposition: eliot_dreamer_contracts::RelationDisposition,
    pub unknown_evidence_refs: Vec<String>,
    pub work_units: u64,
    pub stu_used: u64,
    pub expiry: Option<String>,
    pub reopen_frontier: Option<String>,
    pub degradation: Option<String>,
    pub result_digest: String,
}

impl RelationResult {
    /// Validates the sealed closure and result digest.
    pub fn validate(&self) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
        self.preflight_output()?;
        self.validate_shape()?;
        let expected_work = crate::computed_work_bound(&self.closure.input, &self.policy)?;
        if self.work_units != expected_work {
            return Err(
                eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                    field: "relation.result.work",
                    reason: "reported work does not equal the checked semantic bound".to_owned(),
                },
            );
        }
        let expected = self.compute_digest()?;
        if self.result_digest != expected {
            return Err(
                eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                    field: "relation.result.digest",
                    reason: "result digest drift".to_owned(),
                },
            );
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
        self.policy.validate()?;
        self.closure.validate(&self.closure.input)?;
        if self.stu_used > self.policy.max_stu {
            return Err(eliot_dreamer_contracts::ContractViolation::Budget {
                dimension: "relation.result.stu",
                reason: "STU exceeds policy".to_owned(),
            });
        }
        if self.closure.candidate.policy_digest != self.policy.digest
            || self.closure.input.policy_digest != self.policy.digest
            || self.closure.candidate.disposition != self.disposition
        {
            return Err(
                eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                    field: "relation.result.policy",
                    reason: "result policy or disposition drift".to_owned(),
                },
            );
        }
        let retained: Vec<&str> = self
            .closure
            .input
            .evidence
            .iter()
            .chain(&self.closure.input.counterevidence)
            .map(eliot_dreamer_contracts::RelationEvidence::evidence_id)
            .collect();
        for (index, reference) in self.unknown_evidence_refs.iter().enumerate() {
            if self.unknown_evidence_refs[..index].contains(reference)
                || !retained.contains(&reference.as_str())
                || self.closure.candidate.evidence_refs.contains(reference)
                || self
                    .closure
                    .candidate
                    .counterevidence_refs
                    .contains(reference)
            {
                return Err(
                    eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                        field: "relation.result.unknown_evidence",
                        reason: "unknown evidence refs must be unique retained unqualified refs"
                            .to_owned(),
                    },
                );
            }
        }
        let expected_expiry = self.policy.deadline_ms.map(|value| value.to_string());
        if self.expiry != expected_expiry
            || self.reopen_frontier.as_deref() != Some(REOPEN_FRONTIER)
            || self.degradation.is_some()
                != (self.disposition != eliot_dreamer_contracts::RelationDisposition::Positive)
        {
            return Err(
                eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                    field: "relation.result.metadata",
                    reason: "result metadata does not match policy and disposition".to_owned(),
                },
            );
        }
        for (value, field) in [
            (&self.expiry, "relation.result.expiry"),
            (&self.reopen_frontier, "relation.result.reopen_frontier"),
            (&self.degradation, "relation.result.degradation"),
        ] {
            if let Some(value) = value {
                eliot_dreamer_contracts::error::check_text(value, field, 256)?;
            }
        }
        Ok(())
    }

    fn preflight_output(&self) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
        Self::preflight_components(&ResultParts {
            closure: &self.closure,
            policy: &self.policy,
            disposition: self.disposition,
            unknown_evidence_refs: &self.unknown_evidence_refs,
            work_units: self.work_units,
            stu_used: self.stu_used,
            expiry: self.expiry.as_ref(),
            reopen_frontier: self.reopen_frontier.as_ref(),
            degradation: self.degradation.as_ref(),
        })
    }

    pub(crate) fn preflight_components(
        parts: &ResultParts<'_>,
    ) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
        let retained = parts
            .closure
            .input
            .evidence
            .len()
            .checked_add(parts.closure.input.counterevidence.len())
            .ok_or(eliot_dreamer_contracts::ContractViolation::Budget {
                dimension: "relation.result.unknown_evidence",
                reason: "retained evidence count overflow".to_owned(),
            })?;
        if parts.unknown_evidence_refs.len() > retained {
            return Err(eliot_dreamer_contracts::ContractViolation::Budget {
                dimension: "relation.result.unknown_evidence",
                reason: "unknown evidence count exceeds retained input".to_owned(),
            });
        }
        for reference in parts.unknown_evidence_refs {
            eliot_dreamer_contracts::error::check_text(
                reference,
                "relation.result.unknown_evidence",
                256,
            )?;
        }
        if !serialized_within_envelope(
            &ResultEnvelope {
                closure: parts.closure,
                policy: parts.policy,
                disposition: parts.disposition,
                unknown_evidence_refs: parts.unknown_evidence_refs,
                work_units: parts.work_units,
                stu_used: parts.stu_used,
                expiry: parts.expiry,
                reopen_frontier: parts.reopen_frontier,
                degradation: parts.degradation,
                result_digest: DIGEST_PLACEHOLDER,
            },
            usize::try_from(parts.policy.max_output_bytes).unwrap_or(usize::MAX),
        )? {
            return Err(eliot_dreamer_contracts::ContractViolation::Budget {
                dimension: "relation.result.bytes",
                reason: "output exceeds policy".to_owned(),
            });
        }
        Ok(())
    }
    fn compute_digest(&self) -> Result<String, eliot_dreamer_contracts::ContractViolation> {
        let mut unknown = self.unknown_evidence_refs.clone();
        unknown.sort();
        let preimage = (
            &self.closure.result_digest,
            &self.policy.digest,
            self.disposition,
            &unknown,
            self.work_units,
            self.stu_used,
            &self.expiry,
            &self.reopen_frontier,
            &self.degradation,
        );
        let bytes = eliot_dreamer_contracts::canonical_bytes(&preimage)?;
        if bytes.len() > usize::try_from(self.policy.max_output_bytes).unwrap_or(usize::MAX) {
            return Err(eliot_dreamer_contracts::ContractViolation::Budget {
                dimension: "relation.result.bytes",
                reason: "output exceeds policy".to_owned(),
            });
        }
        Ok(eliot_dreamer_contracts::digest_hex(&bytes))
    }
    /// Seals a bounded result around an accepted A03 closure.
    pub fn seal(mut self) -> Result<Self, eliot_dreamer_contracts::ContractViolation> {
        self.preflight_output()?;
        self.validate_shape()?;
        let expected_work = crate::computed_work_bound(&self.closure.input, &self.policy)?;
        if self.work_units != expected_work {
            return Err(
                eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                    field: "relation.result.work",
                    reason: "reported work does not equal the checked semantic bound".to_owned(),
                },
            );
        }
        self.result_digest = self.compute_digest()?;
        self.validate()?;
        Ok(self)
    }
}

fn serialized_within_envelope(
    value: &ResultEnvelope<'_>,
    limit: usize,
) -> Result<bool, eliot_dreamer_contracts::ContractViolation> {
    serialized_within(value, limit)
}

fn serialized_within<T: Serialize>(
    value: &T,
    limit: usize,
) -> Result<bool, eliot_dreamer_contracts::ContractViolation> {
    struct Probe {
        used: usize,
        limit: usize,
        overflowed: bool,
    }
    impl std::io::Write for Probe {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let Some(next) = self.used.checked_add(bytes.len()) else {
                self.overflowed = true;
                return Err(std::io::Error::other("serialization length overflow"));
            };
            self.used = next;
            if self.used > self.limit {
                self.overflowed = true;
                return Err(std::io::Error::other("serialization bound exceeded"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut probe = Probe {
        used: 0,
        limit,
        overflowed: false,
    };
    match serde_json::to_writer(&mut probe, value) {
        Ok(()) => Ok(true),
        Err(_) if probe.overflowed => Ok(false),
        Err(_) => Err(eliot_dreamer_contracts::ContractViolation::Malformed {
            field: "relation.result.bytes",
            reason: "output serialization failed".to_owned(),
        }),
    }
}

/// Builds a candidate while retaining every supplied branch by reference.
pub fn assemble_candidate(
    input: &RelationInput,
    policy: &RelationPolicy,
    selection: &Selection,
    support: Vec<String>,
    counter: Vec<String>,
) -> Result<RelationCandidate, eliot_dreamer_contracts::ContractViolation> {
    let input_digest = eliot_dreamer_contracts::relation_input_digest(input)?;
    let raw_history_refs = raw_history_refs(input);
    let predecessor = selection.before.as_ref().map(|v| v.relation_id.clone());
    let mut rollback_refs = vec![selection.relation_id.clone()];
    if let Some(value) = &predecessor
        && value != &selection.relation_id
    {
        rollback_refs.push(value.clone());
    }
    Ok(RelationCandidate {
        candidate_id: RelationCandidate::expected_candidate_id(
            &input.operation_id,
            &input_digest,
            &policy.digest,
            input.family,
            input.direction,
            input.source.endpoint_id(),
            input.target.endpoint_id(),
        ),
        relation_id: selection.relation_id.clone(),
        operation_id: input.operation_id.clone(),
        input_digest,
        policy_digest: policy.digest.clone(),
        kind: CurationKind::Relation,
        family: input.family,
        direction: input.direction,
        source_id: input.source.endpoint_id().to_owned(),
        target_id: input.target.endpoint_id().to_owned(),
        source_material_digest: input.source.material_digest().to_owned(),
        target_material_digest: input.target.material_digest().to_owned(),
        registry_digest: input.registry.digest.clone(),
        temporal: input.temporal.clone(),
        evidence_refs: support,
        counterevidence_refs: counter,
        rival_refs: input
            .rivals
            .iter()
            .map(|v| v.alternative_id.clone())
            .collect(),
        no_relation_ref: input
            .no_relation_alternative
            .as_ref()
            .map(|v| v.alternative_id.clone()),
        before: selection.before.clone(),
        after: selection.after.clone(),
        preservation: input.preservation.clone(),
        rollback: RelationRollback {
            predecessor,
            rollback_refs,
            removal_or_restoration_refs: vec![selection.relation_id.clone()],
            invalidation_refs: Vec::new(),
            raw_history_refs,
            note: "candidate-only reversible relation; no canonical mutation".to_owned(),
        },
        disposition: selection.disposition,
        proof_ceiling: ProofCeiling::CandidateArtifact,
    })
}

fn raw_history_refs(input: &RelationInput) -> Vec<String> {
    let mut refs: Vec<String> = input
        .source
        .admitted
        .source_handles
        .iter()
        .map(|v| v.as_str().to_owned())
        .chain(
            input
                .target
                .admitted
                .source_handles
                .iter()
                .map(|v| v.as_str().to_owned()),
        )
        .collect();
    refs.extend(
        input
            .evidence
            .iter()
            .chain(&input.counterevidence)
            .flat_map(|evidence| {
                evidence
                    .named
                    .source_handles
                    .iter()
                    .map(|handle| handle.as_str().to_owned())
                    .chain(
                        evidence
                            .named
                            .foundation_evidence_envelope
                            .provenance
                            .raw_handle
                            .iter()
                            .cloned(),
                    )
            }),
    );
    refs.extend(
        input
            .neighborhood
            .relations
            .iter()
            .flat_map(|relation| relation.provenance_refs.iter().cloned()),
    );
    refs.sort();
    refs.dedup();
    refs
}
