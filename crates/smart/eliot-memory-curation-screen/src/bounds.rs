use eliot_memory_curation_contracts::{
    ContractError, CurationScreenRequest, ProtectionEvidence, SourceIdentity, SourceMember,
    SourceSnapshot,
};
use serde::Serialize;

/// Maximum source members examined by one screen invocation.
pub const MAX_ITEMS: usize = 4096;
/// Maximum owner references retained by one invocation.
pub const MAX_REFERENCES: usize = 16_384;
/// Maximum estimated input bytes accepted before owner validation.
pub const MAX_INPUT_BYTES: u64 = 4 * 1024 * 1024;
/// Conservative local ceiling for materialized result allocation.
pub const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum structural work units accepted by one invocation.
pub const MAX_WORK_UNITS: u64 = 1_000_000;
const MAX_RULES: usize = 64;
const MAX_FIELD_BYTES: usize = 64 * 1024;

/// Cheap accounting returned by the preflight phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreflightSummary {
    /// Estimated bytes in the supplied identity and record leaves.
    pub input_bytes: u64,
    /// Number of retained evidence/reference handles.
    pub references: usize,
}

fn add(total: &mut u64, value: usize, field: &'static str) -> Result<(), ContractError> {
    *total = total
        .checked_add(u64::try_from(value).map_err(|_| ContractError::Bound { field })?)
        .ok_or(ContractError::Bound { field })?;
    if *total > MAX_INPUT_BYTES {
        return Err(ContractError::Bound { field });
    }
    Ok(())
}

fn text(total: &mut u64, value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.len() > MAX_FIELD_BYTES {
        return Err(ContractError::Bound { field });
    }
    add(total, value.len(), field)
}

fn identity(total: &mut u64, value: &SourceIdentity) -> Result<(), ContractError> {
    for text_value in [
        value.product_id.as_str(),
        value.source_id.as_str(),
        value.snapshot_id.as_str(),
        value.query.query_id.as_str(),
        value.query.query_digest.as_str(),
        value.digest.as_str(),
        value.scope.as_str(),
    ] {
        text(total, text_value, "screen.identity")?;
    }
    Ok(())
}

fn member(total: &mut u64, value: &SourceMember) -> Result<usize, ContractError> {
    text(total, value.member_id.as_str(), "source.member_id")?;
    text(
        total,
        value.content_digest.as_str(),
        "source.content_digest",
    )?;
    let mut references = 0usize;
    for set in [
        &value.evidence.provenance,
        &value.evidence.owner_status,
        &value.evidence.protection,
        &value.evidence.conflict,
        &value.evidence.audit,
    ] {
        references = references
            .checked_add(set.len())
            .ok_or(ContractError::Bound {
                field: "member.evidence",
            })?;
        for reference in set {
            text(total, reference.as_str(), "member.evidence")?;
        }
    }
    Ok(references)
}

fn evidence_record(total: &mut u64, value: &ProtectionEvidence) -> Result<usize, ContractError> {
    text(total, value.evidence_id.as_str(), "protection.evidence_id")?;
    text(total, value.member_id.as_str(), "protection.member_id")?;
    text(total, value.source_id.as_str(), "protection.source_id")?;
    text(total, value.snapshot_id.as_str(), "protection.snapshot_id")?;
    text(total, value.scope.as_str(), "protection.scope")?;
    text(total, value.digest.as_str(), "protection.digest")?;
    if let Some(invalidated) = &value.invalidated_by {
        text(total, invalidated.as_str(), "protection.invalidated_by")?;
    }
    Ok(value.references.len())
}

/// Performs cheap bounded accounting before any A19c validator can clone or
/// canonicalize nested input. It deliberately measures supplied data only.
fn validate_cardinalities(
    request: &CurationScreenRequest,
    source: &SourceSnapshot,
    evidence: &[ProtectionEvidence],
) -> Result<(), ContractError> {
    if source.members.len() > MAX_ITEMS
        || evidence.len() > MAX_ITEMS
        || source.denominator.declared_member_ids.len() > MAX_ITEMS
        || source.partition.changed_targets.len() > MAX_ITEMS
        || source.partition.immutable_references.len() > MAX_ITEMS
        || source.page.frontier.len() > MAX_ITEMS
        || request.denominator.declared_member_ids.len() > MAX_ITEMS
        || request.partition.changed_targets.len() > MAX_ITEMS
        || request.partition.immutable_references.len() > MAX_ITEMS
        || request.profile.precedence.len() > MAX_RULES
    {
        return Err(ContractError::Bound {
            field: "screen.items",
        });
    }
    if request.profile.rules.len() > MAX_RULES {
        return Err(ContractError::Bound {
            field: "profile.rules",
        });
    }
    Ok(())
}

fn count_references(
    source: &SourceSnapshot,
    evidence: &[ProtectionEvidence],
) -> Result<usize, ContractError> {
    let mut references = 0usize;
    for value in &source.members {
        for set in [
            &value.evidence.provenance,
            &value.evidence.owner_status,
            &value.evidence.protection,
            &value.evidence.conflict,
            &value.evidence.audit,
        ] {
            references = references
                .checked_add(set.len())
                .ok_or(ContractError::Bound {
                    field: "screen.references",
                })?;
        }
    }
    for value in evidence {
        references =
            references
                .checked_add(value.references.len())
                .ok_or(ContractError::Bound {
                    field: "screen.references",
                })?;
    }
    Ok(references)
}

fn account_request(total: &mut u64, request: &CurationScreenRequest) -> Result<(), ContractError> {
    identity(total, &request.source)?;
    for value in [
        request.binding.request_id.as_str(),
        request.binding.operation_id.as_str(),
        request.binding.attempt_id.as_str(),
        request.binding.scope.as_str(),
        request.profile.profile_id.as_str(),
    ] {
        text(total, value, "screen.input")?;
    }
    if let Some(task_id) = &request.binding.task_id {
        text(total, task_id.as_str(), "request.binding.task_id")?;
    }
    for rule in &request.profile.rules {
        if rule.required_protection.len() > 32 {
            return Err(ContractError::Bound {
                field: "profile.required_protection",
            });
        }
        text(total, rule.rule_id.as_str(), "profile.rule_id")?;
        add(total, rule.required_protection.len(), "profile.rules")?;
    }
    add(
        total,
        request.profile.precedence.len(),
        "profile.precedence",
    )?;
    for rule_id in &request.profile.precedence {
        text(total, rule_id.as_str(), "profile.precedence.rule_id")?;
    }
    Ok(())
}

fn account_source(
    total: &mut u64,
    source: &SourceSnapshot,
    evidence: &[ProtectionEvidence],
) -> Result<(), ContractError> {
    identity(total, &source.identity)?;
    for value in &source.members {
        let _ = member(total, value)?;
    }
    for value in evidence {
        let _ = evidence_record(total, value)?;
        for reference in &value.references {
            text(total, reference.as_str(), "protection.references")?;
        }
    }
    Ok(())
}

fn account_partitions(
    total: &mut u64,
    request: &CurationScreenRequest,
    source: &SourceSnapshot,
) -> Result<(), ContractError> {
    for member_id in &request.denominator.declared_member_ids {
        text(total, member_id.as_str(), "request.denominator.member_id")?;
    }
    for member_id in &request.partition.changed_targets {
        text(
            total,
            member_id.as_str(),
            "request.partition.changed_target",
        )?;
    }
    for member_id in &request.partition.immutable_references {
        text(
            total,
            member_id.as_str(),
            "request.partition.immutable_reference",
        )?;
    }
    for member_id in &source.partition.changed_targets {
        text(total, member_id.as_str(), "partition.changed_target")?;
    }
    for member_id in &source.partition.immutable_references {
        text(total, member_id.as_str(), "partition.immutable_reference")?;
    }
    add(
        total,
        source.denominator.declared_member_ids.len(),
        "denominator.members",
    )?;
    for member_id in &source.denominator.declared_member_ids {
        text(total, member_id.as_str(), "denominator.member_id")?;
    }
    add(total, source.page.frontier.len(), "source.frontier")?;
    for member_id in &source.page.frontier {
        text(total, member_id.as_str(), "source.frontier.member_id")?;
    }
    Ok(())
}

pub fn preflight(
    request: &CurationScreenRequest,
    source: &SourceSnapshot,
    evidence: &[ProtectionEvidence],
) -> Result<PreflightSummary, ContractError> {
    validate_cardinalities(request, source, evidence)?;
    let mut total = 0;
    account_request(&mut total, request)?;
    let references = count_references(source, evidence)?;
    if references > MAX_REFERENCES {
        return Err(ContractError::Bound {
            field: "screen.references",
        });
    }
    account_source(&mut total, source, evidence)?;
    account_partitions(&mut total, request, source)?;
    Ok(PreflightSummary {
        input_bytes: total,
        references,
    })
}

#[derive(Serialize)]
struct Input<'a> {
    request: &'a CurationScreenRequest,
    source: &'a SourceSnapshot,
    evidence: &'a [ProtectionEvidence],
}

/// Measures the exact canonical input envelope after cheap leaf checks and
/// before the owner validators clone or hash any nested record.
pub fn encoded_input_bytes(
    request: &CurationScreenRequest,
    source: &SourceSnapshot,
    evidence: &[ProtectionEvidence],
) -> Result<u64, ContractError> {
    let bytes = eliot_contracts::canonical_json_bytes(&Input {
        request,
        source,
        evidence,
    })
    .map_err(|error| ContractError::Canonicalization(error.to_string()))?;
    let length = u64::try_from(bytes.len()).map_err(|_| ContractError::Bound {
        field: "screen.input_bytes",
    })?;
    if length > MAX_INPUT_BYTES {
        return Err(ContractError::Bound {
            field: "screen.input_bytes",
        });
    }
    Ok(length)
}
