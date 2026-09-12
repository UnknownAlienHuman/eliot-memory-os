use std::collections::{BTreeMap, BTreeSet};

use eliot_conformance_contracts::{
    ConformanceContractSet, EvidenceDomain, canonicalize_contract_set,
    validate_conformance_contract_set,
};
use eliot_dreamer_contracts::{SelfQueryInput, SelfQueryOutputProfile};
use serde::{Deserialize, Serialize};

use crate::{
    ImplementationBriefError,
    model::{
        ArchitectureAlignment, ImplementationEvidence, ImplementationSourceSnapshot,
        ImplementationSourceStatus, ProofStage,
    },
    validation::{
        MAX_ITEMS, MAX_TEXT_BYTES, MAX_WIRE_BYTES, bounded_canonical_size, canonical_digest,
        check_collection_len, check_digest, check_id, check_text, sorted_unique_strings,
    },
};

/// Declared Implementation mechanism assessed by the brief.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationMechanism {
    pub schema_version: u32,
    pub mechanism_id: String,
    pub owner: String,
    pub description: String,
    pub architecture_refs: Vec<String>,
    pub statement_refs: Vec<String>,
    pub dependency_refs: Vec<String>,
    pub obligation_refs: Vec<String>,
    pub contract_refs: Vec<String>,
    pub mechanism_digest: String,
}

#[derive(Serialize)]
struct MechanismDigestPreimage<'a> {
    schema_version: u32,
    mechanism_id: &'a str,
    owner: &'a str,
    description: &'a str,
    architecture_refs: &'a [String],
    statement_refs: &'a [String],
    dependency_refs: &'a [String],
    obligation_refs: &'a [String],
    contract_refs: &'a [String],
}

impl ImplementationMechanism {
    fn digest_preimage(&self) -> MechanismDigestPreimage<'_> {
        MechanismDigestPreimage {
            schema_version: self.schema_version,
            mechanism_id: &self.mechanism_id,
            owner: &self.owner,
            description: &self.description,
            architecture_refs: &self.architecture_refs,
            statement_refs: &self.statement_refs,
            dependency_refs: &self.dependency_refs,
            obligation_refs: &self.obligation_refs,
            contract_refs: &self.contract_refs,
        }
    }

    /// Canonicalizes set-like references and seals the mechanism.
    pub fn seal(&mut self) -> Result<(), ImplementationBriefError> {
        self.architecture_refs =
            sorted_unique_strings(&self.architecture_refs, "mechanism.architecture_refs")?;
        self.statement_refs =
            sorted_unique_strings(&self.statement_refs, "mechanism.statement_refs")?;
        self.dependency_refs =
            sorted_unique_strings(&self.dependency_refs, "mechanism.dependency_refs")?;
        self.obligation_refs =
            sorted_unique_strings(&self.obligation_refs, "mechanism.obligation_refs")?;
        self.contract_refs =
            sorted_unique_strings(&self.contract_refs, "mechanism.contract_refs")?;
        self.mechanism_digest =
            canonical_digest(&self.digest_preimage(), "mechanism.mechanism_digest")?;
        self.validate()
    }

    /// Validates one declared mechanism.
    pub fn validate(&self) -> Result<(), ImplementationBriefError> {
        if self.schema_version != super::IMPLEMENTATION_BRIEF_SCHEMA_VERSION {
            return Err(ImplementationBriefError::Invalid {
                field: "mechanism.schema_version",
                reason: "unsupported schema version",
            });
        }
        check_id(&self.mechanism_id, "mechanism.mechanism_id")?;
        check_id(&self.owner, "mechanism.owner")?;
        check_text(&self.description, "mechanism.description", MAX_TEXT_BYTES)?;
        for (field, values) in [
            ("mechanism.architecture_refs", &self.architecture_refs),
            ("mechanism.statement_refs", &self.statement_refs),
            ("mechanism.dependency_refs", &self.dependency_refs),
            ("mechanism.obligation_refs", &self.obligation_refs),
            ("mechanism.contract_refs", &self.contract_refs),
        ] {
            let canonical = sorted_unique_strings(values, field)?;
            if canonical != *values {
                return Err(ImplementationBriefError::Invalid {
                    field,
                    reason: "collection is not in canonical order",
                });
            }
        }
        if self.architecture_refs.is_empty() {
            return Err(ImplementationBriefError::Missing {
                field: "mechanism.architecture_refs",
            });
        }
        if self.statement_refs.is_empty() {
            return Err(ImplementationBriefError::Missing {
                field: "mechanism.statement_refs",
            });
        }
        check_digest(&self.mechanism_digest, "mechanism.mechanism_digest")?;
        if self.mechanism_digest
            != canonical_digest(&self.digest_preimage(), "mechanism.mechanism_digest")?
        {
            return Err(ImplementationBriefError::DigestMismatch {
                field: "mechanism.mechanism_digest",
            });
        }
        Ok(())
    }
}

/// One exact proof obligation for one mechanism.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationObligation {
    pub schema_version: u32,
    pub obligation_id: String,
    pub mechanism_id: String,
    pub owner: String,
    pub description: String,
    pub required_stages: Vec<ProofStage>,
    pub required_domains: Vec<EvidenceDomain>,
    pub architecture_refs: Vec<String>,
    pub statement_refs: Vec<String>,
    pub obligation_digest: String,
}

#[derive(Serialize)]
struct ObligationDigestPreimage<'a> {
    schema_version: u32,
    obligation_id: &'a str,
    mechanism_id: &'a str,
    owner: &'a str,
    description: &'a str,
    required_stages: &'a [ProofStage],
    required_domains: &'a [EvidenceDomain],
    architecture_refs: &'a [String],
    statement_refs: &'a [String],
}

impl ImplementationObligation {
    fn digest_preimage(&self) -> ObligationDigestPreimage<'_> {
        ObligationDigestPreimage {
            schema_version: self.schema_version,
            obligation_id: &self.obligation_id,
            mechanism_id: &self.mechanism_id,
            owner: &self.owner,
            description: &self.description,
            required_stages: &self.required_stages,
            required_domains: &self.required_domains,
            architecture_refs: &self.architecture_refs,
            statement_refs: &self.statement_refs,
        }
    }

    /// Canonicalizes stage/domain/reference sets and seals the obligation.
    pub fn seal(&mut self) -> Result<(), ImplementationBriefError> {
        self.required_stages.sort();
        self.required_stages.dedup();
        self.required_domains.sort();
        self.required_domains.dedup();
        self.architecture_refs =
            sorted_unique_strings(&self.architecture_refs, "obligation.architecture_refs")?;
        self.statement_refs =
            sorted_unique_strings(&self.statement_refs, "obligation.statement_refs")?;
        self.obligation_digest =
            canonical_digest(&self.digest_preimage(), "obligation.obligation_digest")?;
        self.validate()
    }

    /// Validates one proof obligation.
    pub fn validate(&self) -> Result<(), ImplementationBriefError> {
        if self.schema_version != super::IMPLEMENTATION_BRIEF_SCHEMA_VERSION {
            return Err(ImplementationBriefError::Invalid {
                field: "obligation.schema_version",
                reason: "unsupported schema version",
            });
        }
        check_id(&self.obligation_id, "obligation.obligation_id")?;
        check_id(&self.mechanism_id, "obligation.mechanism_id")?;
        check_id(&self.owner, "obligation.owner")?;
        check_text(&self.description, "obligation.description", MAX_TEXT_BYTES)?;
        check_collection_len(
            self.required_stages.len(),
            ProofStage::COUNT,
            "obligation.required_stages",
        )?;
        if self.required_stages.is_empty() {
            return Err(ImplementationBriefError::Missing {
                field: "obligation.required_stages",
            });
        }
        if !self.required_stages.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ImplementationBriefError::Invalid {
                field: "obligation.required_stages",
                reason: "collection is not in canonical order",
            });
        }
        if self.required_domains.is_empty() {
            return Err(ImplementationBriefError::Missing {
                field: "obligation.required_domains",
            });
        }
        if !self.required_domains.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ImplementationBriefError::Invalid {
                field: "obligation.required_domains",
                reason: "collection is not in canonical order",
            });
        }
        for (field, values) in [
            ("obligation.architecture_refs", &self.architecture_refs),
            ("obligation.statement_refs", &self.statement_refs),
        ] {
            let canonical = sorted_unique_strings(values, field)?;
            if canonical != *values {
                return Err(ImplementationBriefError::Invalid {
                    field,
                    reason: "collection is not in canonical order",
                });
            }
        }
        if self.architecture_refs.is_empty() || self.statement_refs.is_empty() {
            return Err(ImplementationBriefError::Missing {
                field: "obligation.source_refs",
            });
        }
        check_digest(&self.obligation_digest, "obligation.obligation_digest")?;
        if self.obligation_digest
            != canonical_digest(&self.digest_preimage(), "obligation.obligation_digest")?
        {
            return Err(ImplementationBriefError::DigestMismatch {
                field: "obligation.obligation_digest",
            });
        }
        Ok(())
    }
}

/// Complete expected denominator for the supplied self-query scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationDenominator {
    pub schema_version: u32,
    pub denominator_id: String,
    pub mechanism_ids: Vec<String>,
    pub obligation_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub complete: bool,
    pub denominator_digest: String,
}

#[derive(Serialize)]
struct DenominatorDigestPreimage<'a> {
    schema_version: u32,
    denominator_id: &'a str,
    mechanism_ids: &'a [String],
    obligation_ids: &'a [String],
    evidence_ids: &'a [String],
    complete: bool,
}

impl ImplementationDenominator {
    fn digest_preimage(&self) -> DenominatorDigestPreimage<'_> {
        DenominatorDigestPreimage {
            schema_version: self.schema_version,
            denominator_id: &self.denominator_id,
            mechanism_ids: &self.mechanism_ids,
            obligation_ids: &self.obligation_ids,
            evidence_ids: &self.evidence_ids,
            complete: self.complete,
        }
    }

    /// Canonicalizes all expected identities and seals the denominator.
    pub fn seal(&mut self) -> Result<(), ImplementationBriefError> {
        self.mechanism_ids =
            sorted_unique_strings(&self.mechanism_ids, "denominator.mechanism_ids")?;
        self.obligation_ids =
            sorted_unique_strings(&self.obligation_ids, "denominator.obligation_ids")?;
        self.evidence_ids =
            sorted_unique_strings(&self.evidence_ids, "denominator.evidence_ids")?;
        self.denominator_digest =
            canonical_digest(&self.digest_preimage(), "denominator.denominator_digest")?;
        self.validate()
    }

    /// Validates denominator identity and canonical ordering.
    pub fn validate(&self) -> Result<(), ImplementationBriefError> {
        if self.schema_version != super::IMPLEMENTATION_BRIEF_SCHEMA_VERSION {
            return Err(ImplementationBriefError::Invalid {
                field: "denominator.schema_version",
                reason: "unsupported schema version",
            });
        }
        check_id(&self.denominator_id, "denominator.denominator_id")?;
        for (field, values) in [
            ("denominator.mechanism_ids", &self.mechanism_ids),
            ("denominator.obligation_ids", &self.obligation_ids),
            ("denominator.evidence_ids", &self.evidence_ids),
        ] {
            let canonical = sorted_unique_strings(values, field)?;
            if canonical != *values {
                return Err(ImplementationBriefError::Invalid {
                    field,
                    reason: "collection is not in canonical order",
                });
            }
        }
        if self.complete
            && (self.mechanism_ids.is_empty()
                || self.obligation_ids.is_empty()
                || self.evidence_ids.is_empty())
        {
            return Err(ImplementationBriefError::Missing {
                field: "denominator.complete_members",
            });
        }
        check_digest(&self.denominator_digest, "denominator.denominator_digest")?;
        if self.denominator_digest
            != canonical_digest(&self.digest_preimage(), "denominator.denominator_digest")?
        {
            return Err(ImplementationBriefError::DigestMismatch {
                field: "denominator.denominator_digest",
            });
        }
        Ok(())
    }
}

/// Complete pure input closure for one ImplementationBrief projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationBriefInput {
    pub schema_version: u32,
    pub self_query: SelfQueryInput,
    pub implementation_source: Option<ImplementationSourceSnapshot>,
    pub mechanisms: Vec<ImplementationMechanism>,
    pub obligations: Vec<ImplementationObligation>,
    pub evidence: Vec<ImplementationEvidence>,
    pub conformance: ConformanceContractSet,
    pub denominator: ImplementationDenominator,
    pub invalidation_conditions: Vec<String>,
    pub input_digest: String,
}

#[derive(Serialize)]
struct InputDigestPreimage<'a> {
    schema_version: u32,
    self_query: &'a SelfQueryInput,
    implementation_source: &'a Option<ImplementationSourceSnapshot>,
    mechanisms: &'a [ImplementationMechanism],
    obligations: &'a [ImplementationObligation],
    evidence: &'a [ImplementationEvidence],
    conformance: &'a ConformanceContractSet,
    denominator: &'a ImplementationDenominator,
    invalidation_conditions: &'a [String],
}

impl ImplementationBriefInput {
    fn digest_preimage(&self) -> InputDigestPreimage<'_> {
        InputDigestPreimage {
            schema_version: self.schema_version,
            self_query: &self.self_query,
            implementation_source: &self.implementation_source,
            mechanisms: &self.mechanisms,
            obligations: &self.obligations,
            evidence: &self.evidence,
            conformance: &self.conformance,
            denominator: &self.denominator,
            invalidation_conditions: &self.invalidation_conditions,
        }
    }

    /// Canonicalizes every locally owned set/list and seals the input digest.
    pub fn seal(&mut self) -> Result<(), ImplementationBriefError> {
        if let Some(source) = &mut self.implementation_source {
            source.seal()?;
        }
        for mechanism in &mut self.mechanisms {
            mechanism.seal()?;
        }
        self.mechanisms
            .sort_by(|left, right| left.mechanism_id.cmp(&right.mechanism_id));
        for obligation in &mut self.obligations {
            obligation.seal()?;
        }
        self.obligations
            .sort_by(|left, right| left.obligation_id.cmp(&right.obligation_id));
        for evidence in &mut self.evidence {
            evidence.seal()?;
        }
        self.evidence
            .sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
        self.conformance = canonicalize_contract_set(self.conformance.clone())?;
        self.denominator.seal()?;
        self.invalidation_conditions = sorted_unique_strings(
            &self.invalidation_conditions,
            "input.invalidation_conditions",
        )?;
        self.input_digest = canonical_digest(&self.digest_preimage(), "input.input_digest")?;
        self.validate()
    }

    /// Validates exact A-03, Implementation, conformance and denominator joins.
    #[expect(
        clippy::too_many_lines,
        reason = "explicit join validation keeps all authority boundaries auditable"
    )]
    pub fn validate(&self) -> Result<(), ImplementationBriefError> {
        if self.schema_version != super::IMPLEMENTATION_BRIEF_SCHEMA_VERSION {
            return Err(ImplementationBriefError::Invalid {
                field: "input.schema_version",
                reason: "unsupported schema version",
            });
        }
        self.self_query.validate()?;
        if self.self_query.profile.output_profile != SelfQueryOutputProfile::ImplementationBrief {
            return Err(ImplementationBriefError::BindingMismatch {
                field: "input.self_query.profile.output_profile",
            });
        }
        validate_conformance_contract_set(&self.conformance)?;
        self.denominator.validate()?;
        check_collection_len(self.mechanisms.len(), MAX_ITEMS, "input.mechanisms")?;
        check_collection_len(self.obligations.len(), MAX_ITEMS, "input.obligations")?;
        check_collection_len(self.evidence.len(), MAX_ITEMS, "input.evidence")?;
        check_collection_len(
            self.invalidation_conditions.len(),
            MAX_ITEMS,
            "input.invalidation_conditions",
        )?;
        let invalidation = sorted_unique_strings(
            &self.invalidation_conditions,
            "input.invalidation_conditions",
        )?;
        if invalidation != self.invalidation_conditions {
            return Err(ImplementationBriefError::Invalid {
                field: "input.invalidation_conditions",
                reason: "collection is not in canonical order",
            });
        }

        if let Some(source) = &self.implementation_source {
            source.validate()?;
            let architecture = self
                .self_query
                .source
                .as_ref()
                .ok_or(ImplementationBriefError::Missing {
                    field: "input.self_query.source",
                })?;
            if source.revision != architecture.pair.implementation_revision
                || source.source_digest != architecture.pair.implementation_digest
            {
                return Err(ImplementationBriefError::BindingMismatch {
                    field: "input.implementation_source.normative_pair",
                });
            }
            if source.status == ImplementationSourceStatus::Accepted
                && (source.owner != architecture.pair.accepted_by.as_str()
                    || source.acceptance_receipt.as_deref()
                        != Some(architecture.pair.acceptance_receipt.as_str()))
            {
                return Err(ImplementationBriefError::BindingMismatch {
                    field: "input.implementation_source.acceptance",
                });
            }
        } else if !self.mechanisms.is_empty()
            || !self.obligations.is_empty()
            || !self.evidence.is_empty()
        {
            return Err(ImplementationBriefError::BindingMismatch {
                field: "input.implementation_source_absence",
            });
        }

        ensure_canonical_ids(
            self.mechanisms
                .iter()
                .map(|value| value.mechanism_id.as_str()),
            "input.mechanisms",
        )?;
        ensure_canonical_ids(
            self.obligations
                .iter()
                .map(|value| value.obligation_id.as_str()),
            "input.obligations",
        )?;
        ensure_canonical_ids(
            self.evidence
                .iter()
                .map(|value| value.evidence_id.as_str()),
            "input.evidence",
        )?;

        let mechanism_ids = self
            .mechanisms
            .iter()
            .map(|value| value.mechanism_id.as_str())
            .collect::<BTreeSet<_>>();
        let obligation_ids = self
            .obligations
            .iter()
            .map(|value| value.obligation_id.as_str())
            .collect::<BTreeSet<_>>();
        let evidence_ids = self
            .evidence
            .iter()
            .map(|value| value.evidence_id.as_str())
            .collect::<BTreeSet<_>>();
        let expected_mechanisms = self
            .denominator
            .mechanism_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let expected_obligations = self
            .denominator
            .obligation_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let expected_evidence = self
            .denominator
            .evidence_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if !mechanism_ids.is_subset(&expected_mechanisms)
            || !obligation_ids.is_subset(&expected_obligations)
            || !evidence_ids.is_subset(&expected_evidence)
        {
            return Err(ImplementationBriefError::BindingMismatch {
                field: "input.denominator_membership",
            });
        }
        if self.denominator.complete
            && (mechanism_ids != expected_mechanisms
                || obligation_ids != expected_obligations
                || evidence_ids != expected_evidence)
        {
            return Err(ImplementationBriefError::BindingMismatch {
                field: "input.complete_denominator",
            });
        }

        let statement_map = self
            .implementation_source
            .as_ref()
            .map(|source| {
                source
                    .statements
                    .iter()
                    .map(|statement| (statement.statement_id.as_str(), statement))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();

        for mechanism in &self.mechanisms {
            mechanism.validate()?;
            for statement_ref in &mechanism.statement_refs {
                if let Some(statement) = statement_map.get(statement_ref.as_str())
                    && statement.mechanism_id != mechanism.mechanism_id
                {
                    return Err(ImplementationBriefError::BindingMismatch {
                        field: "input.mechanism.statement_owner",
                    });
                }
            }
            for obligation_ref in &mechanism.obligation_refs {
                if !expected_obligations.contains(obligation_ref.as_str()) {
                    return Err(ImplementationBriefError::BindingMismatch {
                        field: "input.mechanism.obligation_ref",
                    });
                }
            }
            for dependency_ref in &mechanism.dependency_refs {
                if !expected_mechanisms.contains(dependency_ref.as_str()) {
                    return Err(ImplementationBriefError::BindingMismatch {
                        field: "input.mechanism.dependency_ref",
                    });
                }
                if dependency_ref == &mechanism.mechanism_id {
                    return Err(ImplementationBriefError::DependencyCycle {
                        field: "input.mechanism.dependency_ref",
                    });
                }
            }
        }
        detect_mechanism_cycles(&self.mechanisms)?;

        for obligation in &self.obligations {
            obligation.validate()?;
            if !expected_mechanisms.contains(obligation.mechanism_id.as_str()) {
                return Err(ImplementationBriefError::BindingMismatch {
                    field: "input.obligation.mechanism_id",
                });
            }
            if let Some(mechanism) = self
                .mechanisms
                .iter()
                .find(|value| value.mechanism_id == obligation.mechanism_id)
                && !mechanism.obligation_refs.contains(&obligation.obligation_id)
            {
                return Err(ImplementationBriefError::BindingMismatch {
                    field: "input.obligation.reverse_binding",
                });
            }
        }

        let support_rows = self
            .conformance
            .support_rows
            .iter()
            .map(|row| (row.support_claim_ref.as_str(), row))
            .collect::<BTreeMap<_, _>>();
        for evidence in &self.evidence {
            evidence.validate()?;
            if !expected_mechanisms.contains(evidence.mechanism_id.as_str())
                || !expected_obligations.contains(evidence.obligation_id.as_str())
            {
                return Err(ImplementationBriefError::BindingMismatch {
                    field: "input.evidence.denominator_binding",
                });
            }
            let row = support_rows
                .get(evidence.support_claim_ref.as_str())
                .ok_or(ImplementationBriefError::Missing {
                    field: "input.evidence.support_claim_ref",
                })?;
            if row.scope_ref != self.self_query.validated_candidate.job.scope_id
                || row.support_claim_ref != evidence.support_claim_ref
            {
                return Err(ImplementationBriefError::BindingMismatch {
                    field: "input.evidence.support_row",
                });
            }
        }

        if let Some(source) = &self.implementation_source {
            for statement in &source.statements {
                if !expected_mechanisms.contains(statement.mechanism_id.as_str()) {
                    return Err(ImplementationBriefError::BindingMismatch {
                        field: "input.statement.mechanism_id",
                    });
                }
                if statement.alignment == ArchitectureAlignment::Compatible
                    && statement.architecture_refs.is_empty()
                {
                    return Err(ImplementationBriefError::Missing {
                        field: "input.statement.architecture_refs",
                    });
                }
            }
        }

        let input_limit = usize::try_from(
            self.self_query
                .policy
                .max_input_bytes
                .min(MAX_WIRE_BYTES as u64),
        )
        .unwrap_or(MAX_WIRE_BYTES);
        bounded_canonical_size(self, input_limit, "input.wire")?;
        check_digest(&self.input_digest, "input.input_digest")?;
        if self.input_digest != canonical_digest(&self.digest_preimage(), "input.input_digest")? {
            return Err(ImplementationBriefError::DigestMismatch {
                field: "input.input_digest",
            });
        }
        Ok(())
    }
}

fn ensure_canonical_ids<'a>(
    values: impl Iterator<Item = &'a str>,
    field: &'static str,
) -> Result<(), ImplementationBriefError> {
    let values = values.collect::<Vec<_>>();
    let mut previous = None;
    for value in values {
        check_id(value, field)?;
        if previous.is_some_and(|left: &str| left >= value) {
            return Err(ImplementationBriefError::Invalid {
                field,
                reason: "collection is not in canonical order",
            });
        }
        previous = Some(value);
    }
    Ok(())
}

fn detect_mechanism_cycles(
    mechanisms: &[ImplementationMechanism],
) -> Result<(), ImplementationBriefError> {
    let dependencies = mechanisms
        .iter()
        .map(|mechanism| {
            (
                mechanism.mechanism_id.as_str(),
                mechanism
                    .dependency_refs
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for start in dependencies.keys() {
        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut stack = vec![(*start, false)];
        while let Some((current, leaving)) = stack.pop() {
            if leaving {
                visiting.remove(current);
                visited.insert(current);
                continue;
            }
            if visited.contains(current) {
                continue;
            }
            if !visiting.insert(current) {
                return Err(ImplementationBriefError::DependencyCycle {
                    field: "input.mechanism_dependencies",
                });
            }
            stack.push((current, true));
            if let Some(next) = dependencies.get(current) {
                for dependency in next.iter().rev() {
                    stack.push((*dependency, false));
                }
            }
        }
    }
    Ok(())
}
