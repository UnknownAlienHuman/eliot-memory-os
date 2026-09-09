//! Structured claim and precision shapes retained across grounding.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{ArtifactId, StateFence};
use eliot_epistemic_contracts::{
    CausalClaim, CoverageDenominator, CoverageReceipt, TemporalRecord,
};
use serde::{Deserialize, Serialize};

use crate::{error::ContractViolation, registry::TargetDenominator, screen::ScreenBinding};

const MAX_TEXT: usize = 16_384;

/// The eight precision distinctions in A-14b.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimKind {
    NumericQuantified,
    TemporalVersioned,
    Causal,
    AbsenceExhaustiveNegative,
    ComparativeSuperlative,
    QuoteAttribution,
    RecommendationNormativeInference,
    IdentityEntity,
}

/// Typed precision payload; no generic JSON or prose-only claim escape hatch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrecisionPayload {
    NumericQuantified {
        value: String,
        unit: String,
        denominator: Option<String>,
        interval: Option<String>,
        rounding: Option<String>,
        uncertainty: Option<String>,
    },
    TemporalVersioned {
        temporal: TemporalRecord,
        version: String,
        revision: String,
    },
    Causal {
        causal: Box<CausalClaim>,
    },
    AbsenceExhaustiveNegative {
        domain: String,
        denominator: Box<CoverageDenominator>,
        receipt: Option<Box<CoverageReceipt>>,
    },
    ComparativeSuperlative {
        measure: String,
        population: String,
        reference: String,
        relation: String,
        value: Option<String>,
    },
    QuoteAttribution {
        quoted_text: String,
        source: ArtifactId,
        span: String,
        attributed_to: String,
    },
    RecommendationNormativeInference {
        recommendation: String,
        fact_components: BTreeSet<String>,
        assumptions: BTreeSet<String>,
        inference_rule: String,
    },
    IdentityEntity {
        entity: String,
        entity_type: String,
        version: String,
        scope: String,
    },
}

impl PrecisionPayload {
    pub fn kind(&self) -> ClaimKind {
        match self {
            Self::NumericQuantified { .. } => ClaimKind::NumericQuantified,
            Self::TemporalVersioned { .. } => ClaimKind::TemporalVersioned,
            Self::Causal { .. } => ClaimKind::Causal,
            Self::AbsenceExhaustiveNegative { .. } => ClaimKind::AbsenceExhaustiveNegative,
            Self::ComparativeSuperlative { .. } => ClaimKind::ComparativeSuperlative,
            Self::QuoteAttribution { .. } => ClaimKind::QuoteAttribution,
            Self::RecommendationNormativeInference { .. } => {
                ClaimKind::RecommendationNormativeInference
            }
            Self::IdentityEntity { .. } => ClaimKind::IdentityEntity,
        }
    }

    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), ContractViolation> {
        match self {
            Self::NumericQuantified {
                value,
                unit,
                denominator,
                interval,
                rounding,
                uncertainty,
            } => {
                for value in [
                    value,
                    unit,
                    denominator.as_deref().unwrap_or(""),
                    interval.as_deref().unwrap_or(""),
                    rounding.as_deref().unwrap_or(""),
                    uncertainty.as_deref().unwrap_or(""),
                ] {
                    if !value.is_empty() {
                        text(value, "numeric_precision")?;
                    }
                }
            }
            Self::TemporalVersioned {
                temporal,
                version,
                revision,
            } => {
                temporal
                    .validate()
                    .map_err(|error| ContractViolation::BindingMismatch {
                        field: "temporal_precision",
                        reason: error.to_string(),
                    })?;
                text(version, "version")?;
                text(revision, "revision")?;
            }
            Self::Causal { causal } => {
                causal
                    .validate()
                    .map_err(|error| ContractViolation::BindingMismatch {
                        field: "causal_precision",
                        reason: error.to_string(),
                    })?;
            }
            Self::AbsenceExhaustiveNegative {
                domain,
                denominator,
                receipt,
            } => {
                text(domain, "absence_domain")?;
                denominator
                    .validate()
                    .map_err(|error| ContractViolation::BindingMismatch {
                        field: "absence_denominator",
                        reason: error.to_string(),
                    })?;
                if let Some(receipt) = receipt {
                    receipt
                        .validate()
                        .map_err(|error| ContractViolation::BindingMismatch {
                            field: "absence_receipt",
                            reason: error.to_string(),
                        })?;
                }
            }
            Self::ComparativeSuperlative {
                measure,
                population,
                reference,
                relation,
                value,
            } => {
                for value in [
                    measure,
                    population,
                    reference,
                    relation,
                    value.as_deref().unwrap_or(""),
                ] {
                    if !value.is_empty() {
                        text(value, "comparative_precision")?;
                    }
                }
            }
            Self::QuoteAttribution {
                quoted_text,
                span,
                attributed_to,
                source,
            } => {
                text(quoted_text, "quoted_text")?;
                text(span, "quote_span")?;
                text(attributed_to, "attributed_to")?;
                let _ = source;
            }
            Self::RecommendationNormativeInference {
                recommendation,
                fact_components,
                assumptions,
                inference_rule,
            } => {
                text(recommendation, "recommendation")?;
                text(inference_rule, "inference_rule")?;
                for value in fact_components.iter().chain(assumptions) {
                    text(value, "recommendation_component")?;
                }
            }
            Self::IdentityEntity {
                entity,
                entity_type,
                version,
                scope,
            } => {
                text(entity, "entity")?;
                text(entity_type, "entity_type")?;
                text(version, "entity_version")?;
                text(scope, "entity_scope")?;
            }
        }
        Ok(())
    }
}

/// Exact screen and target denominator identity retained with a claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScreenTargetBinding {
    pub screen: ScreenBinding,
    pub target_denominator: TargetDenominator,
    pub target_digest: String,
}

impl ScreenTargetBinding {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.screen.validate()?;
        self.target_denominator.validate()?;
        digest(&self.target_digest, "target_digest")
    }
}

/// One material claim with stable proposed support and counterevidence sets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterialClaim {
    pub claim_id: String,
    pub proposition_digest: String,
    pub kind: ClaimKind,
    pub payload: PrecisionPayload,
    pub subclaim_ids: BTreeSet<String>,
    pub proposed_support: BTreeSet<ArtifactId>,
    pub proposed_counterevidence: BTreeSet<ArtifactId>,
    pub component_digests: BTreeMap<String, String>,
    pub screen_target: Option<ScreenTargetBinding>,
    pub source_preimage_digest: String,
}

/// A source-bound, typed assertion retained on an authorized reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedEvidenceAssertion {
    pub assertion_id: String,
    pub claim_id: String,
    pub proposition_digest: String,
    pub component: String,
    pub precision: PrecisionPayload,
    pub source_span_digest: String,
}

impl TypedEvidenceAssertion {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        text(&self.assertion_id, "assertion.assertion_id")?;
        text(&self.claim_id, "assertion.claim_id")?;
        digest(&self.proposition_digest, "assertion.proposition_digest")?;
        text(&self.component, "assertion.component")?;
        digest(&self.source_span_digest, "assertion.source_span_digest")?;
        self.precision.validate()
    }
}

impl MaterialClaim {
    #[allow(clippy::too_many_lines)]
    pub fn preflight_bytes(&self) -> Result<usize, ContractViolation> {
        let mut bytes = 0usize;
        let add = |total: &mut usize, amount: usize| -> Result<(), ContractViolation> {
            *total = total.checked_add(amount).ok_or(ContractViolation::Budget {
                dimension: "grounding_handoff_bytes",
                reason: "claim preflight overflow".into(),
            })?;
            Ok(())
        };
        add(&mut bytes, self.claim_id.len())?;
        add(&mut bytes, self.proposition_digest.len())?;
        add(&mut bytes, self.source_preimage_digest.len())?;
        for value in &self.subclaim_ids {
            add(&mut bytes, value.len())?;
        }
        for value in self.component_digests.keys() {
            add(&mut bytes, value.len())?;
            add(&mut bytes, 64)?;
        }
        add(
            &mut bytes,
            self.proposed_support
                .len()
                .checked_mul(64)
                .ok_or(ContractViolation::Budget {
                    dimension: "grounding_edges",
                    reason: "support edge count overflow".into(),
                })?,
        )?;
        add(
            &mut bytes,
            self.proposed_counterevidence.len().checked_mul(64).ok_or(
                ContractViolation::Budget {
                    dimension: "grounding_edges",
                    reason: "counterevidence edge count overflow".into(),
                },
            )?,
        )?;
        match &self.payload {
            PrecisionPayload::NumericQuantified {
                value,
                unit,
                denominator,
                interval,
                rounding,
                uncertainty,
            } => {
                for value in [
                    value,
                    unit,
                    denominator.as_deref().unwrap_or(""),
                    interval.as_deref().unwrap_or(""),
                    rounding.as_deref().unwrap_or(""),
                    uncertainty.as_deref().unwrap_or(""),
                ] {
                    add(&mut bytes, value.len())?;
                }
            }
            PrecisionPayload::TemporalVersioned {
                version, revision, ..
            } => {
                add(&mut bytes, version.len())?;
                add(&mut bytes, revision.len())?;
                add(&mut bytes, 40)?;
            }
            PrecisionPayload::Causal { causal } => {
                add(&mut bytes, causal.mechanism.len())?;
                add(&mut bytes, causal.outcome.len())?;
                add(&mut bytes, causal.control.len())?;
                add(&mut bytes, causal.scope.len())?;
                add(&mut bytes, 640)?;
            }
            PrecisionPayload::AbsenceExhaustiveNegative { domain, .. } => {
                add(&mut bytes, domain.len())?;
                add(&mut bytes, 1024)?;
            }
            PrecisionPayload::ComparativeSuperlative {
                measure,
                population,
                reference,
                relation,
                value,
            } => {
                for value in [
                    measure,
                    population,
                    reference,
                    relation,
                    value.as_deref().unwrap_or(""),
                ] {
                    add(&mut bytes, value.len())?;
                }
            }
            PrecisionPayload::QuoteAttribution {
                quoted_text,
                span,
                attributed_to,
                ..
            } => {
                add(&mut bytes, quoted_text.len())?;
                add(&mut bytes, span.len())?;
                add(&mut bytes, attributed_to.len())?;
                add(&mut bytes, 64)?;
            }
            PrecisionPayload::RecommendationNormativeInference {
                recommendation,
                inference_rule,
                fact_components,
                assumptions,
            } => {
                add(&mut bytes, recommendation.len())?;
                add(&mut bytes, inference_rule.len())?;
                for value in fact_components.iter().chain(assumptions) {
                    add(&mut bytes, value.len())?;
                }
            }
            PrecisionPayload::IdentityEntity {
                entity,
                entity_type,
                version,
                scope,
            } => {
                add(&mut bytes, entity.len())?;
                add(&mut bytes, entity_type.len())?;
                add(&mut bytes, version.len())?;
                add(&mut bytes, scope.len())?;
            }
        }
        Ok(bytes)
    }
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        let mut preimage = self.clone();
        preimage.source_preimage_digest.clear();
        crate::grounding::encoding::digest(&preimage)
    }
    pub fn validate(&self) -> Result<(), ContractViolation> {
        text(&self.claim_id, "claim_id")?;
        digest(&self.proposition_digest, "proposition_digest")?;
        digest(&self.source_preimage_digest, "source_preimage_digest")?;
        if self.computed_digest()? != self.source_preimage_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "source_preimage_digest",
                reason: "claim preimage digest mismatch".into(),
            });
        }
        if self.payload.kind() != self.kind {
            return Err(ContractViolation::KindPayload(
                "claim kind does not match typed precision payload".into(),
            ));
        }
        self.payload.validate()?;
        for id in &self.subclaim_ids {
            text(id, "subclaim_ids")?;
        }
        for (component, digest) in &self.component_digests {
            text(component, "component_digests")?;
            super_digest(digest, "component_digests")?;
        }
        if let Some(binding) = &self.screen_target {
            binding.validate()?;
        }
        Ok(())
    }
}

/// Explicitly retained non-material residue; it cannot silently become a fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonMaterialClaim {
    pub claim_id: String,
    pub category: String,
    pub reason: String,
    pub source_preimage_digest: String,
}
impl NonMaterialClaim {
    pub fn preflight_bytes(&self) -> usize {
        self.claim_id.len()
            + self.category.len()
            + self.reason.len()
            + self.source_preimage_digest.len()
    }
    pub fn validate(&self) -> Result<(), ContractViolation> {
        text(&self.claim_id, "claim_id")?;
        text(&self.category, "category")?;
        text(&self.reason, "reason")?;
        digest(&self.source_preimage_digest, "source_preimage_digest")
    }
}

fn text(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    crate::error::check_text(value, field, MAX_TEXT)
}
fn digest(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    if crate::error::is_hex64_lower(value) {
        Ok(())
    } else {
        Err(ContractViolation::Malformed {
            field,
            reason: "expected lowercase SHA-256 digest".into(),
        })
    }
}
fn super_digest(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    digest(value, field)
}
#[allow(dead_code)]
fn _fence(_fence: &StateFence) {}
