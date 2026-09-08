use eliot_memory_curation_contracts::{ContractError, FindingClass, RuleSpec};
use std::collections::BTreeSet;

/// Versioned local rule identifiers supported by this bounded screen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupportedRule {
    /// Finds a member without an owner provenance reference.
    ProvenanceGap,
    /// Retains an observed owner conflict reference as an ambiguity finding.
    ConflictAmbiguity,
}

/// The complete supported rule whitelist.
pub const SUPPORTED_RULES: &[&str] = &["provenance_gap_v1", "conflict_ambiguity_v1"];

/// Resolves and validates one A19c rule without interpreting arbitrary text.
pub fn resolve(rule: &RuleSpec) -> Result<SupportedRule, ContractError> {
    let supported = match rule.rule_id.as_str() {
        "provenance_gap_v1" if rule.finding_class == FindingClass::ProvenanceGap => {
            SupportedRule::ProvenanceGap
        }
        "conflict_ambiguity_v1" if rule.finding_class == FindingClass::ConflictAmbiguity => {
            SupportedRule::ConflictAmbiguity
        }
        _ => {
            return Err(ContractError::Unsupported {
                field: "profile.rule_id",
            });
        }
    };
    Ok(supported)
}

/// Validates the fixed rule/version/class contract for the supplied profile.
pub fn resolve_profile(
    rules: &[RuleSpec],
) -> Result<Vec<(RuleSpec, SupportedRule)>, ContractError> {
    if rules.len() > 64 {
        return Err(ContractError::Bound {
            field: "profile.rules",
        });
    }
    let mut resolved = Vec::with_capacity(rules.len());
    let mut classes = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut last_precedence = None;
    for rule in rules {
        let supported = resolve(rule)?;
        if rule.required_protection.is_empty() {
            return Err(ContractError::Unsupported {
                field: "profile.required_protection",
            });
        }
        if !ids.insert(rule.rule_id.clone()) {
            return Err(ContractError::Duplicate {
                field: "profile.rules",
            });
        }
        classes.insert(rule.finding_class);
        if last_precedence.is_some_and(|value| rule.precedence <= value) {
            return Err(ContractError::Reconciliation {
                field: "profile.precedence",
            });
        }
        last_precedence = Some(rule.precedence);
        resolved.push((rule.clone(), supported));
    }
    Ok(resolved)
}

/// Ensures the profile's requested finding set names exactly the supported
/// classes it declares, so an omitted false rule is never mistaken for an
/// evaluated rule.
pub fn validate_requested_findings(
    profile: &eliot_memory_curation_contracts::ScreenProfile,
) -> Result<(), ContractError> {
    let classes: BTreeSet<_> = profile
        .rules
        .iter()
        .map(|rule| rule.finding_class)
        .collect();
    if profile.requested_findings != classes {
        return Err(ContractError::Reconciliation {
            field: "profile.requested_findings",
        });
    }
    if profile.precedence
        != profile
            .rules
            .iter()
            .map(|rule| rule.rule_id.clone())
            .collect::<Vec<_>>()
    {
        return Err(ContractError::Reconciliation {
            field: "profile.precedence",
        });
    }
    Ok(())
}
