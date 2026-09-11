//! Deterministic relation disposition over the supplied bounded neighborhood.

use std::collections::BTreeSet;

use eliot_dreamer_contracts::{
    RelationDirection, RelationDisposition, RelationFamily, RelationInput, RelationSnapshot,
};
use eliot_evidence::{EpistemicStatus, LifecycleState};

use crate::policy::RelationPolicy;

/// Result of semantic selection; all source alternatives remain addressable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Selection {
    pub disposition: RelationDisposition,
    pub relation_id: String,
    pub before: Option<RelationSnapshot>,
    pub after: Option<RelationSnapshot>,
}

/// Checks a supplied transitive path without performing a graph traversal.
pub fn validate_path(
    input: &RelationInput,
    policy: &RelationPolicy,
) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
    if policy.transitive_path.is_empty() {
        return Ok(());
    }
    let Some(rule) = input
        .registry
        .rules
        .iter()
        .find(|r| r.family == input.family)
    else {
        return Err(eliot_dreamer_contracts::ContractViolation::Registry(
            "path has no registry rule".to_owned(),
        ));
    };
    if !rule.permits_transitive {
        return Err(eliot_dreamer_contracts::ContractViolation::ForbiddenCarry(
            "registry forbids transitive relation derivation".to_owned(),
        ));
    }
    let mut current = input.source.endpoint_id().to_owned();
    let mut seen = BTreeSet::new();
    for path in &policy.transitive_path {
        let path_id = &path.edge_id;
        if !seen.insert(path_id.as_str()) {
            return Err(eliot_dreamer_contracts::ContractViolation::Registry(
                "transitive path repeats a relation".to_owned(),
            ));
        }
        let Some(edge) = input
            .neighborhood
            .relations
            .iter()
            .find(|r| r.relation_id == *path_id)
        else {
            return Err(
                eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                    field: "relation.path",
                    reason: "path relation is not retained by neighborhood".to_owned(),
                },
            );
        };
        let Some(rule) = input
            .registry
            .rules
            .iter()
            .find(|rule| rule.family == edge.family)
        else {
            return Err(eliot_dreamer_contracts::ContractViolation::Registry(
                "path edge family is not registered".to_owned(),
            ));
        };
        if edge.relation_digest != path.relation_digest
            || edge.source_id != current
            || edge.direction != rule.direction
            || edge.family != input.family
            || edge.direction != input.direction
            || edge.scope_id != input.scope_id
            || edge.state_fence != input.state_fence
            || edge.registry_digest != input.registry.digest
            || !matches!(
                edge.status,
                EpistemicStatus::Supported | EpistemicStatus::Verified
            )
            || edge.lifecycle != LifecycleState::Active
            || edge.provenance_refs.is_empty()
            || edge.temporal != input.temporal
        {
            return Err(
                eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                    field: "relation.path",
                    reason: "path is disconnected or stale".to_owned(),
                },
            );
        }
        current.clone_from(&edge.target_id);
    }
    if current != input.target.endpoint_id() {
        return Err(
            eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                field: "relation.path",
                reason: "path does not terminate at target".to_owned(),
            },
        );
    }
    Ok(())
}

/// Checks that every policy-declared alternative is retained or explicitly omitted.
pub fn validate_alternative_coverage(
    input: &RelationInput,
    policy: &RelationPolicy,
) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
    let retained: Vec<&str> = input
        .rivals
        .iter()
        .map(|v| v.alternative_id.as_str())
        .chain(
            input
                .no_relation_alternative
                .iter()
                .map(|v| v.alternative_id.as_str()),
        )
        .collect();
    if policy.expected_alternative_refs.is_empty() {
        return Ok(());
    }
    for expected in &policy.expected_alternative_refs {
        if !retained.contains(&expected.as_str())
            && !policy.omitted_alternative_refs.contains(expected)
        {
            return Err(
                eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                    field: "relation.alternative_coverage",
                    reason: "declared alternative is neither retained nor explicitly omitted"
                        .to_owned(),
                },
            );
        }
    }
    for retained_id in &retained {
        if !policy
            .expected_alternative_refs
            .iter()
            .any(|expected| expected == retained_id)
        {
            return Err(
                eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                    field: "relation.alternative_coverage",
                    reason: "retained alternative is outside expected denominator".to_owned(),
                },
            );
        }
    }
    for omitted in &policy.omitted_alternative_refs {
        if retained.contains(&omitted.as_str()) {
            return Err(
                eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                    field: "relation.alternative_coverage",
                    reason: "alternative cannot be both retained and omitted".to_owned(),
                },
            );
        }
        if !policy.expected_alternative_refs.contains(omitted) {
            return Err(
                eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                    field: "relation.alternative_coverage",
                    reason: "omitted alternative is outside expected denominator".to_owned(),
                },
            );
        }
    }
    Ok(())
}

fn relation_id(
    input: &RelationInput,
) -> Result<String, eliot_dreamer_contracts::ContractViolation> {
    let identity = (
        input.scope_id.as_str(),
        input.family,
        input.direction,
        input.source.endpoint_id(),
        input.target.endpoint_id(),
    );
    Ok(format!(
        "relation:{}",
        eliot_dreamer_contracts::digest_hex(&eliot_dreamer_contracts::canonical_bytes(&identity)?)
    ))
}

fn proposed_matches(snapshot: &RelationSnapshot, input: &RelationInput) -> bool {
    snapshot.source_id == input.source.endpoint_id()
        && snapshot.target_id == input.target.endpoint_id()
        && snapshot.family == input.family
        && snapshot.direction == input.direction
        && snapshot.scope_id == input.scope_id
        && snapshot.registry_digest == input.registry.digest
        && snapshot.state_fence == input.state_fence
        && snapshot.temporal == input.temporal
        && matches!(
            snapshot.status,
            EpistemicStatus::Supported | EpistemicStatus::Verified
        )
        && snapshot.lifecycle == LifecycleState::Active
        && !snapshot.provenance_refs.is_empty()
}

fn snapshot_equal(left: &RelationSnapshot, right: &RelationSnapshot) -> bool {
    let mut left = left.clone();
    let mut right = right.clone();
    left.provenance_refs.sort();
    right.provenance_refs.sort();
    left == right
}

fn same_identity(snapshot: &RelationSnapshot, input: &RelationInput) -> bool {
    snapshot.source_id == input.source.endpoint_id()
        && snapshot.target_id == input.target.endpoint_id()
        && snapshot.family == input.family
        && snapshot.direction == input.direction
        && snapshot.scope_id == input.scope_id
}

fn reversal_selection(input: &RelationInput, id: &str) -> Option<Selection> {
    let rule = input
        .registry
        .rules
        .iter()
        .find(|rule| rule.family == input.family)?;
    let reversed = |family: RelationFamily, direction: RelationDirection| {
        input.neighborhood.relations.iter().find(|snapshot| {
            snapshot.source_id == input.target.endpoint_id()
                && snapshot.target_id == input.source.endpoint_id()
                && snapshot.family == family
                && snapshot.direction == direction
                && snapshot.scope_id == input.scope_id
                && snapshot.state_fence == input.state_fence
                && snapshot.registry_digest == input.registry.digest
                && snapshot.temporal == input.temporal
                && matches!(
                    snapshot.status,
                    EpistemicStatus::Supported | EpistemicStatus::Verified
                )
                && snapshot.lifecycle == LifecycleState::Active
                && !snapshot.provenance_refs.is_empty()
        })
    };
    if let Some(inverse) = rule.inverse_family
        && let Some(before) = reversed(inverse, input.direction)
    {
        return Some(Selection {
            disposition: RelationDisposition::Inverse,
            relation_id: id.to_owned(),
            before: Some(before.clone()),
            after: None,
        });
    }
    if rule.symmetric
        && let Some(before) = reversed(input.family, input.direction)
    {
        return Some(Selection {
            disposition: RelationDisposition::Ambiguous,
            relation_id: id.to_owned(),
            before: Some(before.clone()),
            after: None,
        });
    }
    None
}

/// Selects a typed disposition using only caller-supplied bounded records.
fn existing_selection(
    input: &RelationInput,
    policy: &RelationPolicy,
    id: &str,
) -> Result<Option<Selection>, eliot_dreamer_contracts::ContractViolation> {
    if let Some(proposed) = &policy.proposed_snapshot {
        if let Some(retained) = input
            .neighborhood
            .relations
            .iter()
            .find(|snapshot| snapshot.relation_id == proposed.relation_id)
        {
            return Ok(Some(Selection {
                disposition: if proposed_matches(proposed, input)
                    && snapshot_equal(proposed, retained)
                {
                    RelationDisposition::Duplicate
                } else {
                    RelationDisposition::Conflict
                },
                relation_id: retained.relation_id.clone(),
                before: Some(retained.clone()),
                after: None,
            }));
        }
        if proposed.relation_id != id || !proposed_matches(proposed, input) {
            return Err(
                eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                    field: "relation.proposed_snapshot",
                    reason: "new proposal must use the stable local identity and exact input tuple"
                        .to_owned(),
                },
            );
        }
        if let Some(retained) = input
            .neighborhood
            .relations
            .iter()
            .find(|snapshot| snapshot.relation_id == id)
        {
            return Ok(Some(Selection {
                disposition: if snapshot_equal(proposed, retained) {
                    RelationDisposition::Duplicate
                } else {
                    RelationDisposition::Conflict
                },
                relation_id: id.to_owned(),
                before: Some(retained.clone()),
                after: None,
            }));
        }
        if let Some(retained) = input
            .neighborhood
            .relations
            .iter()
            .find(|snapshot| same_identity(snapshot, input))
        {
            return Ok(Some(Selection {
                disposition: RelationDisposition::Ambiguous,
                relation_id: id.to_owned(),
                before: Some(retained.clone()),
                after: None,
            }));
        }
    } else if let Some(retained) = input
        .neighborhood
        .relations
        .iter()
        .find(|snapshot| snapshot.relation_id == id)
    {
        return Ok(Some(Selection {
            disposition: if proposed_matches(retained, input) {
                RelationDisposition::Ambiguous
            } else {
                RelationDisposition::Conflict
            },
            relation_id: id.to_owned(),
            before: Some(retained.clone()),
            after: None,
        }));
    } else if let Some(retained) = input
        .neighborhood
        .relations
        .iter()
        .find(|snapshot| same_identity(snapshot, input))
    {
        return Ok(Some(Selection {
            disposition: RelationDisposition::Ambiguous,
            relation_id: id.to_owned(),
            before: Some(retained.clone()),
            after: None,
        }));
    }
    Ok(None)
}

pub fn select(
    input: &RelationInput,
    policy: &RelationPolicy,
    support: &[String],
    counter: &[String],
    unknown: &[String],
    alternative_support: bool,
    unknown_alternative: bool,
) -> Result<Selection, eliot_dreamer_contracts::ContractViolation> {
    let id = relation_id(input)?;
    if let Some(existing) = existing_selection(input, policy, &id)? {
        return Ok(existing);
    }
    if let Some(reversal) = reversal_selection(input, &id) {
        return Ok(reversal);
    }
    if !counter.is_empty() && !support.is_empty() {
        return Ok(Selection {
            disposition: RelationDisposition::Conflict,
            relation_id: id,
            before: None,
            after: None,
        });
    }
    if !unknown.is_empty() || unknown_alternative {
        return Ok(Selection {
            disposition: RelationDisposition::Abstention,
            relation_id: id,
            before: None,
            after: None,
        });
    }
    if alternative_support {
        return Ok(Selection {
            disposition: if support.is_empty() {
                RelationDisposition::Ambiguous
            } else {
                RelationDisposition::Conflict
            },
            relation_id: id,
            before: None,
            after: None,
        });
    }
    if policy.expected_alternative_refs.is_empty() {
        return Ok(Selection {
            disposition: RelationDisposition::Abstention,
            relation_id: id,
            before: None,
            after: None,
        });
    }
    if support.is_empty() && !alternative_support && policy.transitive_path.is_empty() {
        return Ok(Selection {
            disposition: RelationDisposition::Unsupported,
            relation_id: id,
            before: None,
            after: None,
        });
    }
    let disposition = if policy.expected_alternative_refs.is_empty()
        || !input.neighborhood.omitted_refs.is_empty()
        || !policy.omitted_alternative_refs.is_empty()
    {
        RelationDisposition::Partial
    } else if input.neighborhood.complete {
        RelationDisposition::Positive
    } else {
        RelationDisposition::Partial
    };
    let after = policy
        .proposed_snapshot
        .as_ref()
        .filter(|snapshot| proposed_matches(snapshot, input))
        .filter(|_| {
            matches!(
                disposition,
                RelationDisposition::Positive | RelationDisposition::Partial
            )
        })
        .cloned();
    Ok(Selection {
        disposition,
        relation_id: id,
        before: None,
        after,
    })
}
