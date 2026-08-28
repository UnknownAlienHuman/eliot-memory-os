//! Derived corpus report for semantic memory.
//!
//! Architecture anchor: `A14.4` (forgetting and memory ecology).
//! Implementation anchors: `I12.21` (memory ecology, residual experience, and
//! transfer) and `I16.1` (reports are projections, not canonical truth).
//!
//! `eliot-engine` aggregates this report from caller-supplied
//! [`super::CorpusProfileInput`]. This child computes only physical/logical
//! counts, maturity distributions, and coverage metrics; it cannot mutate the
//! corpus, grant trust, or replace canonical stores and verified episodes.

#![allow(clippy::cast_precision_loss)]

use std::collections::BTreeSet;

use eliot_types::{ExperienceCase, ExperienceMaturityState, MemoryCorpusProfile};

use super::CorpusProfileInput;

/// Report-only service that aggregates a derived corpus profile.
///
/// Derived corpus report only: computes coverage and distribution metrics from
/// caller-supplied [`CorpusProfileInput`]. It does not read canonical storage
/// directly, does not write, and does not confer authority.
#[derive(Clone, Copy, Debug, Default)]
pub struct CorpusProfileService;

impl CorpusProfileService {
    pub fn profile(input: &CorpusProfileInput) -> MemoryCorpusProfile {
        let mut profile = MemoryCorpusProfile {
            verified_episode_count: input.verified_episode_count,
            reconstructed_case_count: u64::try_from(input.cases.len()).unwrap_or(u64::MAX),
            contrastive_case_group_count: u64::try_from(input.patterns.len()).unwrap_or(u64::MAX),
            physical_case_record_count: input.physical_case_record_count,
            physical_pattern_record_count: input.physical_pattern_record_count,
            superseded_or_duplicate_case_record_count: input
                .physical_case_record_count
                .saturating_sub(u64::try_from(input.cases.len()).unwrap_or(u64::MAX)),
            superseded_or_duplicate_pattern_record_count: input
                .physical_pattern_record_count
                .saturating_sub(u64::try_from(input.patterns.len()).unwrap_or(u64::MAX)),
            transfer_validated_count: input
                .patterns
                .iter()
                .filter(|pattern| {
                    matches!(
                        pattern.maturity.state,
                        ExperienceMaturityState::TransferValidated
                            | ExperienceMaturityState::ProcedureCandidate
                            | ExperienceMaturityState::ActiveProcedure
                    )
                })
                .count()
                .try_into()
                .unwrap_or(u64::MAX),
            active_procedure_count: input.active_procedure_count,
            ..MemoryCorpusProfile::default()
        };
        if let Some(health) = &input.graph_health {
            let total = health.verified_claims + health.supported_claims + health.weak_claims;
            profile.weak_claim_fraction = fraction(health.weak_claims, total);
            profile
                .counts_by_epistemic_status
                .insert("verified".to_owned(), health.verified_claims);
            profile
                .counts_by_epistemic_status
                .insert("supported".to_owned(), health.supported_claims);
            profile
                .counts_by_epistemic_status
                .insert("weak".to_owned(), health.weak_claims);
            for count in &health.records_by_lifecycle_status {
                profile
                    .counts_by_lifecycle
                    .insert(count.name.clone(), count.count);
            }
            profile
                .counts_by_kind
                .insert("claim_card".to_owned(), total);
        }
        profile.counts_by_kind.insert(
            "experience_case".to_owned(),
            profile.reconstructed_case_count,
        );
        profile.counts_by_kind.insert(
            "experience_pattern".to_owned(),
            profile.contrastive_case_group_count,
        );
        for case in &input.cases {
            *profile
                .counts_by_maturity
                .entry(format!("{:?}", case.maturity.state).to_ascii_lowercase())
                .or_default() += 1;
            *profile
                .mechanism_family_distribution
                .entry(case.causal_model.mechanism.clone())
                .or_default() += 1;
        }
        for pattern in &input.patterns {
            *profile
                .counts_by_maturity
                .entry(format!("{:?}", pattern.maturity.state).to_ascii_lowercase())
                .or_default() += 1;
        }
        profile.exact_evidence_coverage = coverage(&input.cases, |case| {
            !case.authority.exact_source_refs.is_empty()
        });
        profile.applies_when_coverage = coverage(&input.cases, |case| {
            !case.transfer_boundary.applies_when.is_empty()
        });
        profile.does_not_apply_when_coverage = coverage(&input.cases, |case| {
            !case.transfer_boundary.does_not_apply_when.is_empty()
        });
        profile.counterexample_coverage = coverage(&input.cases, |case| {
            !case.transfer_boundary.counterexample_refs.is_empty()
        });
        profile.verifier_link_coverage = coverage(&input.cases, |case| {
            !case.intervention_and_outcome.verifier_refs.is_empty()
        });
        profile.cross_agent_source_diversity = input
            .cases
            .iter()
            .flat_map(|case| case.source_agent_sessions.iter().copied())
            .collect::<BTreeSet<_>>()
            .len()
            .try_into()
            .unwrap_or(u64::MAX);
        profile
    }
}

fn coverage(cases: &[ExperienceCase], predicate: impl Fn(&ExperienceCase) -> bool) -> f64 {
    if cases.is_empty() {
        0.0
    } else {
        cases.iter().filter(|case| predicate(case)).count() as f64 / cases.len() as f64
    }
}

fn fraction(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}
