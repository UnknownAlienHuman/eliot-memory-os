//! Borrowed preflight for the A-12 hot path.
use crate::CueBindingError;
use crate::{BindingProfile, ExpectedReuseHint, MAX_BINDING_RULES, TouchedResourceProjection};
use eliot_cue_contracts::CueKind;
use eliot_observation::ObservationAdmissionReceipt;

pub const MAX_TEXT_BYTES: usize = 8_192;
pub const MAX_INPUT_ROWS: usize = 65_536;
pub const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

pub fn text(value: &str, field: &'static str) -> Result<(), CueBindingError> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(CueBindingError::Bound { field });
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), CueBindingError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(CueBindingError::Contract { field });
    }
    Ok(())
}

fn add(total: &mut usize, n: usize, field: &'static str) -> Result<(), CueBindingError> {
    *total = total
        .checked_add(n)
        .ok_or(CueBindingError::Bound { field })?;
    if *total > MAX_OUTPUT_BYTES {
        return Err(CueBindingError::Bound { field });
    }
    Ok(())
}

fn option_text(
    value: Option<&String>,
    field: &'static str,
    total: &mut usize,
) -> Result<(), CueBindingError> {
    if let Some(v) = value {
        text(v, field)?;
        add(total, v.len(), field)?;
    }
    Ok(())
}

pub fn profile(profile: &BindingProfile) -> Result<(), CueBindingError> {
    let mut total = 0;
    text(&profile.profile_id, "profile.profile_id")?;
    add(&mut total, profile.profile_id.len(), "profile")?;
    if profile.profile_revision == 0 {
        return Err(CueBindingError::Contract {
            field: "profile.profile_revision",
        });
    }
    profile
        .state_fence
        .validate()
        .map_err(|_| CueBindingError::Contract {
            field: "profile.state_fence",
        })?;
    text(profile.scope_id.as_str(), "profile.scope_id")?;
    digest(profile.profile_digest.as_str(), "profile.profile_digest")?;
    profile
        .expected_normalization_profile
        .validate()
        .map_err(|_| CueBindingError::Contract {
            field: "profile.expected_normalization_profile",
        })?;
    if profile.rules.is_empty() || profile.rules.len() > MAX_BINDING_RULES {
        return Err(CueBindingError::Bound {
            field: "profile.rules",
        });
    }
    for rule in &profile.rules {
        if rule.role != eliot_cue_contracts::BindingRole::Touched {
            return Err(CueBindingError::Contract {
                field: "profile.rule.role",
            });
        }
        text(&rule.rule_ref, "profile.rule_ref")?;
        add(&mut total, rule.rule_ref.len(), "profile.rules")?;
    }
    Ok(())
}

pub fn admission(receipt: &ObservationAdmissionReceipt) -> Result<(), CueBindingError> {
    let mut total = 0;
    for (value, field) in [
        (&receipt.operation_id, "admission.operation_id"),
        (&receipt.idempotency_key, "admission.idempotency_key"),
        (&receipt.record_id, "admission.record_id"),
        (&receipt.request_digest, "admission.request_digest"),
    ] {
        text(value, field)?;
        add(&mut total, value.len(), field)?;
    }
    receipt
        .state_fence
        .validate()
        .map_err(|_| CueBindingError::Contract {
            field: "admission.state_fence",
        })?;
    text(&receipt.record.record_id, "admission.record.record_id")?;
    add(
        &mut total,
        receipt.record.record_id.len(),
        "admission.record",
    )?;
    option_text(
        receipt.record.parent_record_id.as_ref(),
        "admission.parent_record_id",
        &mut total,
    )?;
    if let Some(event) = &receipt.record.event {
        admission_event(event, &mut total)?;
    }
    admission_optional(receipt, &mut total)
}

fn admission_event(
    event: &eliot_observation::ObservationEventCore,
    total: &mut usize,
) -> Result<(), CueBindingError> {
    text(&event.event_id_and_time.event_id, "admission.event_id")?;
    add(
        total,
        event.event_id_and_time.event_id.len(),
        "admission.event_id",
    )?;
    text(
        &event.producer_generation_and_trace.producer,
        "admission.producer",
    )?;
    text(
        &event.producer_generation_and_trace.generation,
        "admission.generation",
    )?;
    text(&event.observed_delta, "admission.observed_delta")?;
    add(total, event.observed_delta.len(), "admission.event")?;
    option_text(
        event.producer_generation_and_trace.trace_ref.as_ref(),
        "admission.trace_ref",
        total,
    )?;
    option_text(
        event.expected_baseline.as_ref(),
        "admission.expected_baseline",
        total,
    )?;
    text(
        &event.coverage_and_blind_intervals.denominator_source_ref,
        "admission.denominator",
    )?;
    add(
        total,
        event
            .coverage_and_blind_intervals
            .denominator_source_ref
            .len(),
        "admission.denominator",
    )?;
    for blind in &event.coverage_and_blind_intervals.blind_intervals {
        text(&blind.reason_ref, "admission.blind_reason")?;
        add(total, blind.reason_ref.len(), "admission.blind_reason")?;
    }
    for value in [
        &event.privacy_retention_and_disclosure.privacy_domain_ref,
        &event.privacy_retention_and_disclosure.retention_policy_ref,
        &event.privacy_retention_and_disclosure.disclosure_class,
    ] {
        text(value, "admission.privacy")?;
        add(total, value.len(), "admission.privacy")?;
    }
    for handle in &event.evidence_and_raw_handles {
        text(handle, "admission.evidence_handle")?;
        add(total, handle.len(), "admission.evidence")?;
    }
    text(
        event.affected_scope.work_scope.as_str(),
        "admission.work_scope",
    )?;
    option_text(
        event.affected_scope.task_ref.as_ref(),
        "admission.task_ref",
        total,
    )?;
    option_text(
        event.affected_scope.attempt_ref.as_ref(),
        "admission.attempt_ref",
        total,
    )?;
    Ok(())
}

fn admission_optional(
    receipt: &ObservationAdmissionReceipt,
    total: &mut usize,
) -> Result<(), CueBindingError> {
    if let Some(plan) = &receipt.plan {
        text(&plan.plan_id, "admission.plan_id")?;
        text(&plan.plan_revision, "admission.plan_revision")?;
        add(total, plan.plan_id.len(), "admission.plan")?;
        add(total, plan.plan_revision.len(), "admission.plan")?;
    }
    if let Some(selection) = &receipt.task_selection {
        for (value, field) in [
            (&selection.task_ref, "admission.selection.task"),
            (&selection.acceptance_digest, "admission.selection.digest"),
            (&selection.work_scope_ref, "admission.selection.scope"),
            (
                &selection.selection_source_ref,
                "admission.selection.source",
            ),
            (&selection.evidence_ref, "admission.selection.evidence"),
        ] {
            text(value, field)?;
            add(total, value.len(), field)?;
        }
        for value in &selection.contamination_flags {
            text(value, "admission.selection.flag")?;
            add(total, value.len(), "admission.selection.flag")?;
        }
    }
    if let Some(evidence) = &receipt.evidence {
        text(
            &evidence.provenance.capture_route,
            "admission.evidence.route",
        )?;
        text(&evidence.provenance.scope, "admission.evidence.scope")?;
        if let Some(value) = &evidence.provenance.raw_handle {
            text(value, "admission.evidence.raw")?;
            add(total, value.len(), "admission.evidence.raw")?;
        }
        if let Some(value) = &evidence.provenance.revision {
            text(value, "admission.evidence.revision")?;
            add(total, value.len(), "admission.evidence.revision")?;
        }
    }
    Ok(())
}

pub fn row(row: &TouchedResourceProjection, total: &mut usize) -> Result<(), CueBindingError> {
    text(row.target.as_str(), "touched.target")?;
    add(total, row.target.as_str().len(), "touched.target")?;
    let observation = &row.change.observation;
    text(&observation.change_id, "change.change_id")?;
    add(total, observation.change_id.len(), "change.change_id")?;
    for (value, field) in [
        (observation.origin_ref.as_ref(), "change.origin_ref"),
        (observation.session_ref.as_ref(), "change.session_ref"),
        (
            observation.action_lease_ref.as_ref(),
            "change.action_lease_ref",
        ),
        (observation.operation_ref.as_ref(), "change.operation_ref"),
        (
            observation.diff_or_artifact_ref.as_ref(),
            "change.diff_or_artifact_ref",
        ),
    ] {
        option_text(value, field, total)?;
    }
    row_snapshots(observation, total)?;
    for invalidation in &observation.invalidations {
        text(&invalidation.dependency, "change.invalidation.dependency")?;
        text(&invalidation.reason_ref, "change.invalidation.reason")?;
        add(total, invalidation.dependency.len(), "change.invalidations")?;
        add(total, invalidation.reason_ref.len(), "change.invalidations")?;
    }
    row_normalization(row, total)
}

fn row_snapshots(
    observation: &eliot_change_monitor::ChangeObservation,
    total: &mut usize,
) -> Result<(), CueBindingError> {
    for snapshot in [&observation.before, &observation.after]
        .into_iter()
        .flatten()
    {
        for (value, field) in [
            (&snapshot.resource_ref, "resource_ref"),
            (&snapshot.revision, "resource_revision"),
        ] {
            text(value, field)?;
            add(total, value.len(), field)?;
        }
        option_text(snapshot.path.as_ref(), "resource.path", total)?;
        option_text(snapshot.symbol.as_ref(), "resource.symbol", total)?;
        option_text(
            snapshot.content_digest.as_ref(),
            "resource.content_digest",
            total,
        )?;
        option_text(
            snapshot.structural_digest.as_ref(),
            "resource.structural_digest",
            total,
        )?;
    }
    Ok(())
}

fn row_normalization(
    row: &TouchedResourceProjection,
    total: &mut usize,
) -> Result<(), CueBindingError> {
    let normalized = &row.normalization.normalized;
    text(&normalized.observed.original_value, "cue.original_value")?;
    add(total, normalized.observed.original_value.len(), "cue")?;
    text(
        normalized.observed.observed_cue_id.as_str(),
        "cue.observed_cue_id",
    )?;
    for value in [
        row.normalization.normalized.observed.source.target.as_str(),
        row.normalization
            .normalized
            .observed
            .source
            .provenance
            .capture_route
            .as_str(),
        row.normalization
            .normalized
            .observed
            .source
            .provenance
            .scope
            .as_str(),
        row.normalization.policy.owner_reference.as_str(),
        row.normalization.policy.policy_id.as_str(),
        row.normalization.normalized.profile.profile_id.as_str(),
    ] {
        text(value, "normalization.binding")?;
        add(total, value.len(), "normalization.binding")?;
    }
    option_text(
        row.normalization
            .normalized
            .observed
            .source
            .provenance
            .raw_handle
            .as_ref(),
        "cue.raw_handle",
        total,
    )?;
    option_text(
        row.normalization
            .normalized
            .observed
            .source
            .provenance
            .revision
            .as_ref(),
        "cue.revision",
        total,
    )
}
pub fn hint(hint: Option<&ExpectedReuseHint>, total: &mut usize) -> Result<(), CueBindingError> {
    if let Some(h) = hint {
        text(h.target.as_str(), "hint.target")?;
        text(&h.evidence_ref, "hint.evidence_ref")?;
        add(total, h.evidence_ref.len(), "hint")?;
    }
    Ok(())
}

pub fn cue_kind_supported(kind: CueKind) -> bool {
    matches!(kind, CueKind::FilePath | CueKind::DirPath | CueKind::Symbol)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn text_bound_is_checked_before_owner_validation() {
        assert!(matches!(
            text(&"x".repeat(MAX_TEXT_BYTES + 1), "x"),
            Err(CueBindingError::Bound { .. })
        ));
    }
    #[test]
    fn only_resource_discriminators_are_positive_capabilities() {
        assert!(cue_kind_supported(CueKind::FilePath));
        assert!(cue_kind_supported(CueKind::DirPath));
        assert!(cue_kind_supported(CueKind::Symbol));
        assert!(!cue_kind_supported(CueKind::Concept));
    }
}
