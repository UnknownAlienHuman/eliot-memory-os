//! Structured claim and precision shapes retained across grounding.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{ArtifactId, StateFence, TaskId};
use eliot_epistemic_contracts::{
    AbsenceClaim, CausalClaim, CoverageDenominator, CoverageReceipt, PropositionId, SupportRecord,
    TemporalRecord,
};
use serde::{Deserialize, Serialize};

use crate::{error::ContractViolation, registry::TargetDenominator, screen::ScreenBinding};

const MAX_TEXT: usize = 16_384;
const MAX_SUPPORT_HANDLES: usize = 64;

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
        absence_proof: Option<Box<AbsenceClaim>>,
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
                text(value, "numeric_precision.value")?;
                text(unit, "numeric_precision.unit")?;
                for value in [denominator, interval, rounding, uncertainty]
                    .into_iter()
                    .flatten()
                {
                    text(value, "numeric_precision.optional")?;
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
                absence_proof,
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
                if let Some(proof) = absence_proof {
                    proof.validate_closed(denominator).map_err(|error| {
                        ContractViolation::BindingMismatch {
                            field: "absence_proof",
                            reason: error.to_string(),
                        }
                    })?;
                    if proof.denominator_digest != denominator.digest {
                        return Err(ContractViolation::BindingMismatch {
                            field: "absence_proof",
                            reason: "absence proof denominator differs from payload denominator"
                                .into(),
                        });
                    }
                }
            }
            Self::ComparativeSuperlative {
                measure,
                population,
                reference,
                relation,
                value,
            } => {
                for value in [measure, population, reference, relation] {
                    text(value, "comparative_precision")?;
                }
                if let Some(value) = value {
                    text(value, "comparative_precision.value")?;
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

    /// Validates the typed payload against the handoff proposition and context.
    pub fn validate_for_context(
        &self,
        proposition: &PropositionId,
        task_id: &TaskId,
        scope: &str,
        fence: &StateFence,
    ) -> Result<(), ContractViolation> {
        self.validate()?;
        match self {
            Self::Causal { causal } => {
                if causal.subject != *proposition {
                    return Err(ContractViolation::BindingMismatch {
                        field: "causal.subject",
                        reason: "causal subject differs from enclosing proposition".into(),
                    });
                }
                if causal.scope != scope || causal.fence != *fence {
                    return Err(ContractViolation::BindingMismatch {
                        field: "causal.context",
                        reason: "causal scope or fence differs from the enclosing context".into(),
                    });
                }
            }
            Self::AbsenceExhaustiveNegative {
                domain,
                denominator,
                receipt,
                absence_proof,
            } => {
                if denominator.scope != scope || denominator.fence != *fence {
                    return Err(ContractViolation::BindingMismatch {
                        field: "absence.denominator",
                        reason:
                            "absence denominator scope or fence differs from the enclosing context"
                                .into(),
                    });
                }
                if domain != &denominator.class {
                    return Err(ContractViolation::BindingMismatch {
                        field: "absence.domain",
                        reason: "absence domain differs from denominator class".into(),
                    });
                }
                if let Some(receipt) = receipt {
                    validate_receipt_context(receipt, denominator, task_id, scope, fence)?;
                }
                if let Some(proof) = absence_proof {
                    if proof.proposition != *proposition
                        || proof.domain != denominator.class
                        || proof.task_id != *task_id
                        || proof.scope != scope
                        || proof.receipt.fence != *fence
                    {
                        return Err(ContractViolation::BindingMismatch {
                            field: "absence_proof.context",
                            reason: "absence proof proposition, domain, task, scope, or fence differs from the enclosing context".into(),
                        });
                    }
                    validate_receipt_context(&proof.receipt, denominator, task_id, scope, fence)?;
                    if receipt.is_some_and(|receipt| receipt != &proof.receipt) {
                        return Err(ContractViolation::BindingMismatch {
                            field: "absence_receipt",
                            reason: "payload receipt and absence proof receipt differ".into(),
                        });
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn validate_receipt_context(
    receipt: &CoverageReceipt,
    denominator: &CoverageDenominator,
    task_id: &TaskId,
    scope: &str,
    fence: &StateFence,
) -> Result<(), ContractViolation> {
    if denominator.roles.len() != 1
        || receipt.denominator != denominator.digest
        || receipt.denominator_size != denominator.members.len() as u64
        || receipt.task_id != *task_id
        || receipt.scope != scope
        || receipt.fence != *fence
        || denominator.query.as_ref() != Some(&receipt.query)
        || denominator.frontier.as_ref() != Some(&receipt.frontier)
    {
        return Err(ContractViolation::BindingMismatch {
            field: "absence_receipt",
            reason: "receipt does not bind the exact single-role denominator and context".into(),
        });
    }
    let Some(role) = denominator.roles.iter().next() else {
        return Err(ContractViolation::MissingField("absence_receipt.role"));
    };
    let mut seen = BTreeSet::new();
    for member in &receipt.members {
        if member.role != *role
            || !denominator.members.contains(&member.member)
            || !seen.insert(member.member.clone())
        {
            return Err(ContractViolation::BindingMismatch {
                field: "absence_receipt",
                reason: "receipt contains a foreign or duplicate member".into(),
            });
        }
    }
    for omission in &receipt.omissions {
        if !denominator.members.contains(&omission.member) || !seen.insert(omission.member.clone())
        {
            return Err(ContractViolation::BindingMismatch {
                field: "absence_receipt",
                reason: "receipt omission contains a foreign or duplicate member".into(),
            });
        }
    }
    Ok(())
}

/// Content digest for a typed proposition payload. The canonical proposition
/// identity remains separate from this content binding.
pub fn proposition_content_digest(
    kind: &ClaimKind,
    payload: &PrecisionPayload,
) -> Result<String, ContractViolation> {
    #[derive(Serialize)]
    struct Preimage<'a> {
        schema_version: u32,
        kind: &'a ClaimKind,
        payload: &'a PrecisionPayload,
    }
    crate::grounding::encoding::digest(&Preimage {
        schema_version: super::GROUNDING_SCHEMA_VERSION,
        kind,
        payload,
    })
}

pub fn component_content_digest(
    proposition: &PropositionId,
    component: &str,
) -> Result<String, ContractViolation> {
    #[derive(Serialize)]
    struct Preimage<'a> {
        schema_version: u32,
        proposition: &'a PropositionId,
        component: &'a str,
    }
    crate::grounding::encoding::digest(&Preimage {
        schema_version: super::GROUNDING_SCHEMA_VERSION,
        proposition,
        component,
    })
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
        crate::grounding::encoding::preflight(self)?;
        self.screen.validate()?;
        self.target_denominator.validate()?;
        let mut screened = self.screen.screened_targets.clone();
        screened.sort();
        let mut members = self.target_denominator.members.clone();
        members.sort();
        if screened != members {
            return Err(ContractViolation::BindingMismatch {
                field: "target_denominator",
                reason: "screened target membership must equal the retained target denominator"
                    .into(),
            });
        }
        digest(&self.target_digest, "target_digest")?;
        let expected = crate::digest_hex(&crate::canonical_bytes(&(
            &self.target_denominator.mode,
            &self.target_denominator.members,
            self.target_denominator.expected_total,
        ))?);
        if expected != self.target_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "target_digest",
                reason: "target digest does not bind the retained member denominator".into(),
            });
        }
        Ok(())
    }

    pub fn validate_for_context(
        &self,
        task_id: &TaskId,
        scope: &str,
        fence: &StateFence,
    ) -> Result<(), ContractViolation> {
        self.validate()?;
        if self.screen.task_id != task_id.to_string()
            || self.screen.scope_id != scope
            || self.screen.state_fence != *fence
        {
            return Err(ContractViolation::BindingMismatch {
                field: "screen_target",
                reason: "screen target context differs from the enclosing handoff".into(),
            });
        }
        Ok(())
    }
}

/// One material claim with stable proposed support and counterevidence sets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterialClaim {
    pub claim_id: String,
    pub proposition: PropositionId,
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
    pub proposition: PropositionId,
    pub proposition_digest: String,
    pub component: String,
    pub precision: PrecisionPayload,
    pub source_span_digest: String,
    pub support: Option<Box<SupportRecord>>,
}

impl TypedEvidenceAssertion {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        text(&self.assertion_id, "assertion.assertion_id")?;
        if self.proposition.as_str().is_empty() {
            return Err(ContractViolation::MissingField("assertion.proposition"));
        }
        digest(&self.proposition_digest, "assertion.proposition_digest")?;
        text(&self.component, "assertion.component")?;
        digest(&self.source_span_digest, "assertion.source_span_digest")?;
        self.precision.validate()?;
        if self.proposition_digest
            != proposition_content_digest(&self.precision.kind(), &self.precision)?
        {
            return Err(ContractViolation::BindingMismatch {
                field: "assertion.proposition_digest",
                reason: "assertion content digest does not bind its typed payload".into(),
            });
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        handle: &ArtifactId,
        task_id: &eliot_contracts::TaskId,
        scope: &str,
        fence: &StateFence,
    ) -> Result<(), ContractViolation> {
        self.validate()?;
        self.precision
            .validate_for_context(&self.proposition, task_id, scope, fence)?;
        if let Some(support) = &self.support {
            support
                .validate_for(task_id, scope, fence)
                .map_err(|error| ContractViolation::BindingMismatch {
                    field: "assertion.support",
                    reason: error.to_string(),
                })?;
            if support.fence != *fence
                || support.task_id != *task_id
                || support.validity.scope != scope
                || support.proposition != self.proposition
                || !support.handles.contains(handle)
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "assertion.support",
                    reason: "support proposition or enclosing handle differs from assertion".into(),
                });
            }
        }
        Ok(())
    }
}

impl MaterialClaim {
    pub fn preflight_bytes(&self) -> Result<usize, ContractViolation> {
        crate::grounding::encoding::preflight(self)
    }
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema_version: u32,
            claim_id: &'a str,
            proposition: &'a PropositionId,
            proposition_digest: &'a str,
            kind: ClaimKind,
            payload: &'a PrecisionPayload,
            subclaim_ids: &'a BTreeSet<String>,
            proposed_support: &'a BTreeSet<ArtifactId>,
            proposed_counterevidence: &'a BTreeSet<ArtifactId>,
            component_digests: &'a BTreeMap<String, String>,
            screen_target: &'a Option<ScreenTargetBinding>,
        }
        crate::grounding::encoding::digest(&Preimage {
            schema_version: super::GROUNDING_SCHEMA_VERSION,
            claim_id: &self.claim_id,
            proposition: &self.proposition,
            proposition_digest: &self.proposition_digest,
            kind: self.kind,
            payload: &self.payload,
            subclaim_ids: &self.subclaim_ids,
            proposed_support: &self.proposed_support,
            proposed_counterevidence: &self.proposed_counterevidence,
            component_digests: &self.component_digests,
            screen_target: &self.screen_target,
        })
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
        if self.proposition_digest != proposition_content_digest(&self.kind, &self.payload)? {
            return Err(ContractViolation::BindingMismatch {
                field: "proposition_digest",
                reason: "claim content digest does not bind its typed payload".into(),
            });
        }
        if self.proposed_support.len() > MAX_SUPPORT_HANDLES
            || self.proposed_counterevidence.len() > MAX_SUPPORT_HANDLES
        {
            return Err(ContractViolation::Budget {
                dimension: "grounding_edges",
                reason: "support and counterevidence exceed the canonical 64-handle ceiling".into(),
            });
        }
        self.payload.validate()?;
        for id in &self.subclaim_ids {
            text(id, "subclaim_ids")?;
        }
        for (component, digest) in &self.component_digests {
            text(component, "component_digests")?;
            super_digest(digest, "component_digests")?;
            if *digest != component_content_digest(&self.proposition, component)? {
                return Err(ContractViolation::BindingMismatch {
                    field: "component_digests",
                    reason: "component digest does not bind its typed component identity".into(),
                });
            }
        }
        if let Some(binding) = &self.screen_target {
            binding.validate()?;
        }
        Ok(())
    }

    pub fn validate_for_context(
        &self,
        task_id: &TaskId,
        scope: &str,
        fence: &StateFence,
    ) -> Result<(), ContractViolation> {
        self.validate()?;
        self.payload
            .validate_for_context(&self.proposition, task_id, scope, fence)?;
        if let Some(binding) = &self.screen_target {
            binding.validate_for_context(task_id, scope, fence)?;
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
    pub fn preflight_bytes(&self) -> Result<usize, ContractViolation> {
        crate::grounding::encoding::preflight(self)
    }
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            claim_id: &'a str,
            category: &'a str,
            reason: &'a str,
        }
        crate::grounding::encoding::digest(&Preimage {
            claim_id: &self.claim_id,
            category: &self.category,
            reason: &self.reason,
        })
    }
    pub fn validate(&self) -> Result<(), ContractViolation> {
        text(&self.claim_id, "claim_id")?;
        text(&self.category, "category")?;
        text(&self.reason, "reason")?;
        digest(&self.source_preimage_digest, "source_preimage_digest")?;
        if self.computed_digest()? != self.source_preimage_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "source_preimage_digest",
                reason: "non-material residue preimage digest mismatch".into(),
            });
        }
        Ok(())
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
