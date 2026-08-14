//! Typed normative rule surfaces used by compiled ELIOT briefs.
//!
//! This crate is deliberately a contract-only boundary.  It validates the
//! identity and coverage of registered rules, bindings, reason codes and
//! directives; it does not evaluate rules, grant authority, or produce a
//! finish or release verdict.

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use eliot_agent_contracts::PublicReference;
use eliot_contracts::{ContractIdentity, Revision, StateFence};
use eliot_evidence::EvidenceEnvelope;
use eliot_instrument_api::VerificationRun;
use eliot_receipts::{ReceiptIdentity, TaskBinding, WorkScopeBinding};
use eliot_runtime_contracts::RecoveryDirective;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable contract name for this surface.
pub const CONTRACT_NAME: &str = "eliot.foundation.rules";
/// Wire revision of the rule surface.
pub const CONTRACT_VERSION: u16 = 1;

/// A validation failure in a rule or coverage contract.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RuleContractError {
    /// A required text field is empty or contains a control character.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    /// Two entries have the same exact identity.
    #[error("duplicate {kind} identity: {identity}")]
    Duplicate {
        kind: &'static str,
        identity: String,
    },
    /// A binding refers to a rule that is absent from the catalogue.
    #[error("missing rule binding target: {identity}")]
    MissingRule { identity: String },
    /// A binding points at a prior catalogue revision.
    #[error("stale rule binding: {identity} (expected revision {expected}, got {actual})")]
    StaleBinding {
        identity: String,
        expected: u64,
        actual: u64,
    },
    /// A binding points at an unregistered directive or reason code.
    #[error("missing {kind} registry entry: {identity}")]
    MissingRegistryEntry {
        kind: &'static str,
        identity: String,
    },
    /// A coverage manifest does not account for one catalogue rule exactly once.
    #[error("coverage manifest has no disposition for rule: {identity}")]
    MissingCoverage { identity: String },
    /// A rule is both included and excluded, or an exclusion has no reason.
    #[error("invalid coverage disposition for rule: {identity}")]
    InvalidCoverage { identity: String },
    /// A manifest declares a stale or conflicting rule.
    #[error("coverage manifest contains stale or conflicting rule: {identity}")]
    StaleOrConflictingRule { identity: String },
    /// The manifest was compiled against another normative pair/catalogue revision.
    #[error("catalogue revision mismatch: expected {expected}, got {actual}")]
    RevisionMismatch { expected: String, actual: String },
}

fn validate_text(value: &str, field: &'static str) -> Result<(), RuleContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(RuleContractError::InvalidText { field });
    }
    Ok(())
}

fn validate_list(values: &[String], field: &'static str) -> Result<(), RuleContractError> {
    for value in values {
        validate_text(value, field)?;
    }
    Ok(())
}

fn validate_unique(values: &[String], kind: &'static str) -> Result<(), RuleContractError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(RuleContractError::Duplicate {
                kind,
                identity: value.clone(),
            });
        }
    }
    Ok(())
}

/// Rule class declared by the normative catalogue.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuleClass {
    /// Fail-closed safety boundary.
    HardBoundary,
    /// Public contract obligation.
    Contract,
    /// Operational safety guardrail.
    Guardrail,
    /// Current default behavior.
    Default,
    /// Reversible bounded experiment.
    Experiment,
    /// Human-owned privacy, cost, risk, or model choice.
    Policy,
}

/// Exact identity of one catalogue rule revision.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleRef {
    /// Stable rule identifier.
    pub rule_id: String,
    /// Exact immutable revision of the rule.
    pub revision: Revision,
}

impl RuleRef {
    /// Constructs a rule reference with a non-zero revision.
    pub fn new(rule_id: impl Into<String>, revision: Revision) -> Result<Self, RuleContractError> {
        let rule_id = rule_id.into();
        validate_text(&rule_id, "rule_id")?;
        Ok(Self { rule_id, revision })
    }

    fn identity(&self) -> String {
        format!("{}@{}", self.rule_id, self.revision.value())
    }
}

/// One generated normative rule entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleCatalogueEntry {
    /// Exact rule identity and revision.
    pub rule_ref: RuleRef,
    /// Classification of the rule.
    pub class: RuleClass,
    /// Architecture anchor or Human policy root.
    pub architecture_anchor_or_policy_root: String,
    /// Owning Implementation section and capability.
    pub owning_implementation_section_and_capability: String,
    /// Scope in which the rule applies.
    pub scope_and_applicability: String,
    /// Public rationale and failure class.
    pub rationale_and_failure_class: String,
    /// Observable property or decision changed by enforcement.
    pub observable_property_or_decision_changed: String,
    /// Enforcement behavior or typed degraded behavior.
    pub enforcement_or_degraded_behavior: String,
    /// Challenge, deviation, or contract-change path.
    pub challenge_deviation_or_change_path: String,
    /// Invalidation, expiry, or supersession condition.
    pub invalidation_and_expiry: String,
}

impl RuleCatalogueEntry {
    /// Validates all identity and descriptive fields.
    pub fn validate(&self) -> Result<(), RuleContractError> {
        validate_text(&self.rule_ref.rule_id, "rule_id")?;
        let _ = self.rule_ref.revision;
        for (value, field) in [
            (
                &self.architecture_anchor_or_policy_root,
                "architecture_anchor_or_policy_root",
            ),
            (
                &self.owning_implementation_section_and_capability,
                "owning_implementation_section_and_capability",
            ),
            (&self.scope_and_applicability, "scope_and_applicability"),
            (
                &self.rationale_and_failure_class,
                "rationale_and_failure_class",
            ),
            (
                &self.observable_property_or_decision_changed,
                "observable_property_or_decision_changed",
            ),
            (
                &self.enforcement_or_degraded_behavior,
                "enforcement_or_degraded_behavior",
            ),
            (
                &self.challenge_deviation_or_change_path,
                "challenge_deviation_or_change_path",
            ),
            (&self.invalidation_and_expiry, "invalidation_and_expiry"),
        ] {
            validate_text(value, field)?;
        }
        Ok(())
    }
}

/// Immutable generated rule catalogue.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleCatalogue {
    /// Normative pair identity used to compile this catalogue.
    pub normative_pair_identity: ContractIdentity,
    /// Monotonic catalogue revision.
    pub catalogue_revision: Revision,
    /// Exact registered entries.
    pub entries: Vec<RuleCatalogueEntry>,
}

impl RuleCatalogue {
    /// Validates catalogue identity and rejects duplicate exact rule identities.
    pub fn validate(&self) -> Result<(), RuleContractError> {
        self.normative_pair_identity
            .validate()
            .map_err(|_| RuleContractError::InvalidText {
                field: "normative_pair_identity",
            })?;
        let _ = self.catalogue_revision;
        let mut seen = BTreeSet::new();
        for entry in &self.entries {
            entry.validate()?;
            let identity = entry.rule_ref.identity();
            if !seen.insert(identity.clone()) {
                return Err(RuleContractError::Duplicate {
                    kind: "rule",
                    identity,
                });
            }
        }
        Ok(())
    }

    fn entry(&self, rule_id: &str) -> Option<&RuleCatalogueEntry> {
        self.entries
            .iter()
            .find(|entry| entry.rule_ref.rule_id == rule_id)
    }
}

/// Registry entry for a rendered reason code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReasonCodeEntry {
    /// Stable machine-readable reason code.
    pub code: String,
    /// Human-readable explanation carried with the code.
    pub description: String,
}

/// Registry entry for an executable/rendered directive reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectiveEntry {
    /// Stable directive identity.
    pub directive_ref: PublicReference,
    /// Stable rule-relative directive text/handle.
    pub directive: String,
}

/// Exact reason and directive registry used by bindings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReasonDirectiveRegistry {
    /// Registered reason codes.
    pub reasons: Vec<ReasonCodeEntry>,
    /// Registered rendered directives.
    pub directives: Vec<DirectiveEntry>,
}

impl ReasonDirectiveRegistry {
    /// Validates registry text and rejects duplicate codes/references.
    pub fn validate(&self) -> Result<(), RuleContractError> {
        let reasons: Vec<_> = self
            .reasons
            .iter()
            .map(|entry| entry.code.clone())
            .collect();
        validate_list(&reasons, "reason_code")?;
        validate_unique(&reasons, "reason code")?;
        for entry in &self.directives {
            entry
                .directive_ref
                .validate()
                .map_err(|_| RuleContractError::InvalidText {
                    field: "directive_ref",
                })?;
        }
        let directives: Vec<_> = self
            .directives
            .iter()
            .map(|entry| entry.directive_ref.id.as_str().to_owned())
            .collect();
        validate_unique(&directives, "directive")?;
        for entry in &self.reasons {
            validate_text(&entry.description, "reason_description")?;
        }
        for entry in &self.directives {
            validate_text(&entry.directive, "directive")?;
        }
        Ok(())
    }

    fn has_reason(&self, code: &str) -> bool {
        self.reasons.iter().any(|entry| entry.code == code)
    }

    fn has_directive(&self, reference: &PublicReference) -> bool {
        self.directives
            .iter()
            .any(|entry| entry.directive_ref == *reference)
    }
}

/// A reason supplied when a rule is applied or explicitly not applicable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BindingReason {
    /// Registry reason code.
    pub code: String,
    /// Optional public detail; this is not hidden reasoning.
    pub detail: String,
}

/// A scope/fence-bound rendering of one exact rule revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleBinding {
    /// Exact rule reference from the catalogue.
    pub rule_ref: RuleRef,
    /// Work unit, task scope, and state-fence identity.
    pub work_unit_task_scope_and_state_fence: BindingScope,
    /// Registry directive rendered for this binding.
    pub rendered_instruction_or_directive_ref: PublicReference,
    /// Explicit applied/not-applicable reason.
    pub applied_or_not_applicable_reason: BindingReason,
    /// Authority and effect ceiling for this binding.
    pub authority_and_effect_ceiling: String,
    /// Delivery/acknowledgement receipt handle, if delivery occurred.
    pub delivery_and_acknowledgement_receipt: Option<ReceiptIdentity>,
}

/// Provider-owned scope and fence records grouped for one binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BindingScope {
    /// Stable `WorkScope` identity and its provider-owned fence.
    pub work_scope: WorkScopeBinding,
    /// Optional task identity and plan revision.
    pub task: Option<TaskBinding>,
    /// Fence captured for this exact binding.
    pub state_fence: StateFence,
}

impl RuleBinding {
    /// Validates local binding shape.
    pub fn validate(&self) -> Result<(), RuleContractError> {
        validate_text(&self.rule_ref.rule_id, "binding.rule_ref.rule_id")?;
        self.work_unit_task_scope_and_state_fence.validate()?;
        self.rendered_instruction_or_directive_ref
            .validate()
            .map_err(|_| RuleContractError::InvalidText {
                field: "rendered_instruction_or_directive_ref",
            })?;
        validate_text(
            &self.applied_or_not_applicable_reason.code,
            "binding_reason.code",
        )?;
        validate_text(
            &self.applied_or_not_applicable_reason.detail,
            "binding_reason.detail",
        )?;
        validate_text(
            &self.authority_and_effect_ceiling,
            "authority_and_effect_ceiling",
        )?;
        if let Some(receipt) = &self.delivery_and_acknowledgement_receipt {
            validate_text(
                receipt.receipt_id.as_str(),
                "delivery_and_acknowledgement_receipt",
            )?;
        }
        Ok(())
    }

    /// Validates the binding against one catalogue and registry.
    pub fn validate_against(
        &self,
        catalogue: &RuleCatalogue,
        registry: &ReasonDirectiveRegistry,
    ) -> Result<(), RuleContractError> {
        self.validate()?;
        let Some(entry) = catalogue.entry(&self.rule_ref.rule_id) else {
            return Err(RuleContractError::MissingRule {
                identity: self.rule_ref.identity(),
            });
        };
        if entry.rule_ref.revision != self.rule_ref.revision {
            return Err(RuleContractError::StaleBinding {
                identity: self.rule_ref.identity(),
                expected: entry.rule_ref.revision.value(),
                actual: self.rule_ref.revision.value(),
            });
        }
        if !registry.has_directive(&self.rendered_instruction_or_directive_ref) {
            return Err(RuleContractError::MissingRegistryEntry {
                kind: "directive",
                identity: self
                    .rendered_instruction_or_directive_ref
                    .id
                    .as_str()
                    .to_owned(),
            });
        }
        if !registry.has_reason(&self.applied_or_not_applicable_reason.code) {
            return Err(RuleContractError::MissingRegistryEntry {
                kind: "reason code",
                identity: self.applied_or_not_applicable_reason.code.clone(),
            });
        }
        Ok(())
    }
}

/// An explicit excluded rule disposition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExcludedRule {
    /// Exact rule identity excluded from this compiled brief.
    pub rule_ref: RuleRef,
    /// Registry reason code or public explanation for exclusion.
    pub reason: BindingReason,
}

/// Explicit normative coverage accompanying every compiled brief.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NormativeCoverageManifest {
    /// Normative pair and catalogue revision used for compilation.
    pub pair_and_catalogue_revision: PairAndCatalogueRevision,
    /// Rule scopes searched by the compiler.
    pub searched_rule_scopes: Vec<String>,
    /// Included exact rule bindings.
    pub included_rule_bindings: Vec<RuleBinding>,
    /// Explicitly excluded rules with reasons.
    pub excluded_with_reason: Vec<ExcludedRule>,
    /// Scopes deliberately not searched.
    pub not_searched_scopes: Vec<String>,
    /// Questions asked by the compiler that had no matching rule.
    pub searched_and_absent_questions: Vec<String>,
    /// Stale or conflicting rules discovered during compilation.
    pub stale_or_conflicting_rules: Vec<String>,
    /// Handles for bounded follow-up expansion.
    pub expansion_handles: Vec<PublicReference>,
}

/// Provider-owned normative identity paired with the catalogue revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PairAndCatalogueRevision {
    /// Frozen Architecture/Implementation pair identity.
    pub normative_pair_identity: ContractIdentity,
    /// Exact generated catalogue revision.
    pub catalogue_revision: Revision,
}

impl NormativeCoverageManifest {
    /// Validates coverage shape and exact one-disposition-per-rule semantics.
    pub fn validate_against(
        &self,
        catalogue: &RuleCatalogue,
        registry: &ReasonDirectiveRegistry,
    ) -> Result<(), RuleContractError> {
        catalogue.validate()?;
        registry.validate()?;
        let expected = PairAndCatalogueRevision {
            normative_pair_identity: catalogue.normative_pair_identity.clone(),
            catalogue_revision: catalogue.catalogue_revision,
        };
        if self.pair_and_catalogue_revision != expected {
            return Err(RuleContractError::RevisionMismatch {
                expected: format!(
                    "{}@{}",
                    expected.normative_pair_identity.name,
                    expected.catalogue_revision.value()
                ),
                actual: format!(
                    "{}@{}",
                    self.pair_and_catalogue_revision
                        .normative_pair_identity
                        .name,
                    self.pair_and_catalogue_revision.catalogue_revision.value()
                ),
            });
        }
        for (values, field) in [
            (&self.searched_rule_scopes, "searched_rule_scope"),
            (&self.not_searched_scopes, "not_searched_scope"),
            (
                &self.searched_and_absent_questions,
                "searched_and_absent_question",
            ),
            (
                &self.stale_or_conflicting_rules,
                "stale_or_conflicting_rule",
            ),
        ] {
            validate_list(values, field)?;
            validate_unique(values, field)?;
        }
        for reference in &self.expansion_handles {
            reference
                .validate()
                .map_err(|_| RuleContractError::InvalidText {
                    field: "expansion_handle",
                })?;
        }
        if let Some(identity) = self.stale_or_conflicting_rules.first() {
            return Err(RuleContractError::StaleOrConflictingRule {
                identity: identity.clone(),
            });
        }

        let mut dispositions = BTreeMap::new();
        for binding in &self.included_rule_bindings {
            binding.validate_against(catalogue, registry)?;
            let identity = binding.rule_ref.rule_id.clone();
            if dispositions.insert(identity.clone(), "included").is_some() {
                return Err(RuleContractError::Duplicate {
                    kind: "coverage disposition",
                    identity,
                });
            }
        }
        for excluded in &self.excluded_with_reason {
            excluded.reason.validate()?;
            let identity = excluded.rule_ref.rule_id.clone();
            let Some(entry) = catalogue.entry(&excluded.rule_ref.rule_id) else {
                return Err(RuleContractError::MissingRule { identity });
            };
            if entry.rule_ref.revision != excluded.rule_ref.revision {
                return Err(RuleContractError::StaleBinding {
                    identity: excluded.rule_ref.identity(),
                    expected: entry.rule_ref.revision.value(),
                    actual: excluded.rule_ref.revision.value(),
                });
            }
            if dispositions.insert(identity.clone(), "excluded").is_some() {
                return Err(RuleContractError::InvalidCoverage { identity });
            }
            if !registry.has_reason(&excluded.reason.code) {
                return Err(RuleContractError::MissingRegistryEntry {
                    kind: "reason code",
                    identity: excluded.reason.code.clone(),
                });
            }
        }
        for entry in &catalogue.entries {
            if !dispositions.contains_key(&entry.rule_ref.rule_id) {
                return Err(RuleContractError::MissingCoverage {
                    identity: entry.rule_ref.identity(),
                });
            }
        }
        Ok(())
    }
}

impl BindingReason {
    fn validate(&self) -> Result<(), RuleContractError> {
        validate_text(&self.code, "binding_reason.code")?;
        validate_text(&self.detail, "binding_reason.detail")
    }
}

impl BindingScope {
    fn validate(&self) -> Result<(), RuleContractError> {
        self.state_fence
            .validate()
            .map_err(|_| RuleContractError::InvalidText {
                field: "binding.state_fence",
            })?;
        self.work_scope
            .state_fence
            .validate()
            .map_err(|_| RuleContractError::InvalidText {
                field: "binding.work_scope.state_fence",
            })?;
        if self.work_scope.state_fence != self.state_fence {
            return Err(RuleContractError::InvalidText {
                field: "binding.work_scope.state_fence",
            });
        }
        if let Some(task) = &self.task {
            task.state_fence
                .validate()
                .map_err(|_| RuleContractError::InvalidText {
                    field: "binding.task.state_fence",
                })?;
            if task.state_fence != self.state_fence {
                return Err(RuleContractError::InvalidText {
                    field: "binding.task.state_fence",
                });
            }
        }
        Ok(())
    }
}

/// Validates provider-owned evidence without promoting it to normative authority.
pub fn validate_evidence(evidence: &EvidenceEnvelope) -> Result<(), RuleContractError> {
    evidence
        .validate()
        .map_err(|_| RuleContractError::InvalidText { field: "evidence" })
}

/// Validates an optional provider-owned verification observation for coverage.
pub fn validate_verification(run: &VerificationRun) -> Result<(), RuleContractError> {
    run.validate().map_err(|_| RuleContractError::InvalidText {
        field: "verification",
    })
}

/// Validates a runtime recovery directive used as a rendered directive payload.
pub fn validate_recovery_directive(directive: &RecoveryDirective) -> Result<(), RuleContractError> {
    directive
        .validate()
        .map_err(|_| RuleContractError::InvalidText {
            field: "recovery_directive",
        })
}

impl fmt::Display for RuleRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.identity())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ContractVersion, ProductId, ResourceGeneration};
    use eliot_receipts::WorkScopeId;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn fence() -> StateFence {
        StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
    }

    fn reference(id: &str) -> TestResult<PublicReference> {
        Ok(PublicReference {
            kind: "directive".to_owned(),
            id: eliot_agent_contracts::TargetId::new(id)?,
            revision: eliot_agent_contracts::RevisionId::new("rev-1")?,
            digest: None,
        })
    }

    fn catalogue() -> TestResult<RuleCatalogue> {
        Ok(RuleCatalogue {
            normative_pair_identity: eliot_contracts::contract_identity(
                "pair-1",
                ContractVersion::new(1, 0, 0),
                &"frozen-pair",
            )?,
            catalogue_revision: eliot_contracts::Revision::new(2)?,
            entries: vec![RuleCatalogueEntry {
                rule_ref: RuleRef {
                    rule_id: "RULE-1".to_owned(),
                    revision: Revision::new(3)?,
                },
                class: RuleClass::Contract,
                architecture_anchor_or_policy_root: "ARCH-1".to_owned(),
                owning_implementation_section_and_capability: "I0.1/rules".to_owned(),
                scope_and_applicability: "bootstrap".to_owned(),
                rationale_and_failure_class: "missing authority".to_owned(),
                observable_property_or_decision_changed: "admission".to_owned(),
                enforcement_or_degraded_behavior: "reject".to_owned(),
                challenge_deviation_or_change_path: "challenge".to_owned(),
                invalidation_and_expiry: "pair revision".to_owned(),
            }],
        })
    }

    fn registry() -> TestResult<ReasonDirectiveRegistry> {
        Ok(ReasonDirectiveRegistry {
            reasons: vec![ReasonCodeEntry {
                code: "APPLIED".to_owned(),
                description: "rule applies".to_owned(),
            }],
            directives: vec![DirectiveEntry {
                directive_ref: reference("DIR-1")?,
                directive: "reject missing authority".to_owned(),
            }],
        })
    }

    fn binding() -> TestResult<RuleBinding> {
        let state_fence = fence();
        Ok(RuleBinding {
            rule_ref: RuleRef {
                rule_id: "RULE-1".to_owned(),
                revision: Revision::new(3)?,
            },
            work_unit_task_scope_and_state_fence: BindingScope {
                work_scope: WorkScopeBinding {
                    scope_id: WorkScopeId::new("scope-1")?,
                    product_id: ProductId::new("product-1")?,
                    resource_generation: ResourceGeneration::genesis(),
                    state_fence: state_fence.clone(),
                },
                task: None,
                state_fence,
            },
            rendered_instruction_or_directive_ref: reference("DIR-1")?,
            applied_or_not_applicable_reason: BindingReason {
                code: "APPLIED".to_owned(),
                detail: "required in this scope".to_owned(),
            },
            authority_and_effect_ceiling: "no product authority".to_owned(),
            delivery_and_acknowledgement_receipt: None,
        })
    }

    #[test]
    fn valid_binding_and_manifest_round_trip() -> TestResult {
        let catalogue = catalogue()?;
        let registry = registry()?;
        let manifest = NormativeCoverageManifest {
            pair_and_catalogue_revision: PairAndCatalogueRevision {
                normative_pair_identity: catalogue.normative_pair_identity.clone(),
                catalogue_revision: catalogue.catalogue_revision,
            },
            searched_rule_scopes: vec!["bootstrap".to_owned()],
            included_rule_bindings: vec![binding()?],
            excluded_with_reason: Vec::new(),
            not_searched_scopes: vec!["product".to_owned()],
            searched_and_absent_questions: Vec::new(),
            stale_or_conflicting_rules: Vec::new(),
            expansion_handles: vec![reference("expand-1")?],
        };
        manifest.validate_against(&catalogue, &registry)?;
        let encoded = serde_json::to_string(&manifest)?;
        assert_eq!(
            serde_json::from_str::<NormativeCoverageManifest>(&encoded)?,
            manifest
        );
        assert!(!serde_json::to_vec(&schemars::schema_for!(NormativeCoverageManifest))?.is_empty());
        Ok(())
    }

    #[test]
    fn duplicate_catalogue_rules_are_rejected() -> TestResult {
        let mut value = catalogue()?;
        let duplicate = value.entries[0].clone();
        value.entries.push(duplicate);
        assert!(matches!(
            value.validate(),
            Err(RuleContractError::Duplicate { kind: "rule", .. })
        ));
        Ok(())
    }

    #[test]
    fn missing_and_stale_bindings_are_rejected() -> TestResult {
        let catalogue = catalogue()?;
        let registry = registry()?;
        let mut missing = binding()?;
        missing.rule_ref = RuleRef::new("RULE-MISSING", Revision::new(1)?)?;
        assert!(matches!(
            missing.validate_against(&catalogue, &registry),
            Err(RuleContractError::MissingRule { .. })
        ));
        let mut stale = binding()?;
        stale.rule_ref.revision = Revision::new(2)?;
        assert!(matches!(
            stale.validate_against(&catalogue, &registry),
            Err(RuleContractError::StaleBinding { .. })
        ));
        Ok(())
    }

    #[test]
    fn missing_coverage_and_duplicate_disposition_are_rejected() -> TestResult {
        let catalogue = catalogue()?;
        let registry = registry()?;
        let incomplete = NormativeCoverageManifest {
            pair_and_catalogue_revision: PairAndCatalogueRevision {
                normative_pair_identity: catalogue.normative_pair_identity.clone(),
                catalogue_revision: catalogue.catalogue_revision,
            },
            searched_rule_scopes: Vec::new(),
            included_rule_bindings: Vec::new(),
            excluded_with_reason: Vec::new(),
            not_searched_scopes: Vec::new(),
            searched_and_absent_questions: Vec::new(),
            stale_or_conflicting_rules: Vec::new(),
            expansion_handles: Vec::new(),
        };
        assert!(matches!(
            incomplete.validate_against(&catalogue, &registry),
            Err(RuleContractError::MissingCoverage { .. })
        ));
        let duplicate = NormativeCoverageManifest {
            pair_and_catalogue_revision: PairAndCatalogueRevision {
                normative_pair_identity: catalogue.normative_pair_identity.clone(),
                catalogue_revision: catalogue.catalogue_revision,
            },
            searched_rule_scopes: Vec::new(),
            included_rule_bindings: vec![binding()?, binding()?],
            excluded_with_reason: Vec::new(),
            not_searched_scopes: Vec::new(),
            searched_and_absent_questions: Vec::new(),
            stale_or_conflicting_rules: Vec::new(),
            expansion_handles: Vec::new(),
        };
        assert!(matches!(
            duplicate.validate_against(&catalogue, &registry),
            Err(RuleContractError::Duplicate {
                kind: "coverage disposition",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn unknown_registry_entries_and_conflicts_fail_closed() -> TestResult {
        let catalogue = catalogue()?;
        let mut unknown = binding()?;
        unknown.rendered_instruction_or_directive_ref = reference("DIR-MISSING")?;
        assert!(matches!(
            unknown.validate_against(&catalogue, &registry()?),
            Err(RuleContractError::MissingRegistryEntry {
                kind: "directive",
                ..
            })
        ));
        let manifest = NormativeCoverageManifest {
            pair_and_catalogue_revision: PairAndCatalogueRevision {
                normative_pair_identity: catalogue.normative_pair_identity.clone(),
                catalogue_revision: catalogue.catalogue_revision,
            },
            searched_rule_scopes: Vec::new(),
            included_rule_bindings: vec![binding()?],
            excluded_with_reason: Vec::new(),
            not_searched_scopes: Vec::new(),
            searched_and_absent_questions: Vec::new(),
            stale_or_conflicting_rules: vec!["RULE-1@2".to_owned()],
            expansion_handles: Vec::new(),
        };
        assert!(matches!(
            manifest.validate_against(&catalogue, &registry()?),
            Err(RuleContractError::StaleOrConflictingRule { .. })
        ));
        Ok(())
    }
}
