use std::collections::BTreeSet;

use crate::model_control::{
    HumanModelPreferencePolicy, ModelQuery, ZeroModelExecutionCounters, project_attempt_health,
    query_model_catalogue,
};

use super::types::{
    MAX_ATTEMPTS, SWARM_CONTROLBOARD_PROJECTION_VERSION, SwarmAttemptProjection,
    SwarmAttemptSelectionBinding, SwarmAttemptTelemetryInput, SwarmCatalogueProjection,
    SwarmControlBoardProjection, SwarmControlBoardProjectionError,
    SwarmControlBoardProjectionInput, SwarmProjectionAuthorityCeiling, SwarmProjectionGap,
    SwarmProjectionProvider,
};

fn compile_catalogue(
    input: &SwarmControlBoardProjectionInput,
    query: &ModelQuery,
    now_unix_ms: u64,
    gaps: &mut BTreeSet<SwarmProjectionGap>,
) -> Result<Option<SwarmCatalogueProjection>, SwarmControlBoardProjectionError> {
    let Some(snapshot) = &input.catalogue else {
        gaps.insert(SwarmProjectionGap::ProviderUnavailable {
            provider: SwarmProjectionProvider::ModelCatalogue,
        });
        return Ok(None);
    };
    snapshot.validate()?;
    if snapshot.entries.is_empty() {
        gaps.insert(SwarmProjectionGap::CatalogueEmpty);
    }
    Ok(Some(SwarmCatalogueProjection {
        snapshot_id: snapshot.snapshot_id.clone(),
        account_scope: snapshot.account_scope.clone(),
        collector_identity: snapshot.collector_identity.clone(),
        observed_at_unix_ms: snapshot.observed_at_unix_ms,
        expires_at_unix_ms: snapshot.expires_at_unix_ms,
        current: snapshot.is_current(now_unix_ms),
        query: query_model_catalogue(snapshot, query, now_unix_ms)?,
    }))
}

fn compile_preferences(
    input: &SwarmControlBoardProjectionInput,
    catalogue_account_scope: Option<&str>,
    gaps: &mut BTreeSet<SwarmProjectionGap>,
) -> Result<Option<HumanModelPreferencePolicy>, SwarmControlBoardProjectionError> {
    let Some(policy) = &input.preferences else {
        gaps.insert(SwarmProjectionGap::ProviderUnavailable {
            provider: SwarmProjectionProvider::HumanPreferences,
        });
        return Ok(None);
    };
    policy.validate()?;
    if catalogue_account_scope.is_some_and(|scope| scope != policy.account_scope) {
        return Err(SwarmControlBoardProjectionError::InvalidField(
            "account_scope",
        ));
    }
    let mut normalized = policy.clone();
    normalized.roles.sort_by_key(|preference| preference.role);
    Ok(Some(normalized))
}

fn selection_binding(
    input: &SwarmControlBoardProjectionInput,
    preferences: Option<&HumanModelPreferencePolicy>,
    attempt: &SwarmAttemptTelemetryInput,
    now_unix_ms: u64,
) -> SwarmAttemptSelectionBinding {
    match (&input.catalogue, preferences) {
        (None, _) => SwarmAttemptSelectionBinding::CatalogueUnavailable,
        (Some(_), None) => SwarmAttemptSelectionBinding::PreferencesUnavailable,
        (Some(snapshot), Some(policy)) => {
            if attempt
                .selection
                .validate_against(snapshot, policy, now_unix_ms)
                .is_ok()
            {
                SwarmAttemptSelectionBinding::ExactCurrent
            } else {
                SwarmAttemptSelectionBinding::StaleOrMismatched
            }
        }
    }
}

fn compile_attempt(
    input: &SwarmControlBoardProjectionInput,
    preferences: Option<&HumanModelPreferencePolicy>,
    expected_account_scope: Option<&str>,
    attempt: &SwarmAttemptTelemetryInput,
    now_unix_ms: u64,
) -> Result<SwarmAttemptProjection, SwarmControlBoardProjectionError> {
    attempt.selection.validate()?;
    if expected_account_scope.is_some_and(|scope| scope != attempt.selection.account_scope) {
        return Err(SwarmControlBoardProjectionError::InvalidField(
            "attempt.account_scope",
        ));
    }
    Ok(SwarmAttemptProjection {
        selection_id: attempt.selection.selection_id.clone(),
        selection_digest: attempt.selection.selection_digest.clone(),
        account_scope: attempt.selection.account_scope.clone(),
        role: attempt.selection.role,
        catalogue_snapshot_id: attempt.selection.catalogue_snapshot_id.clone(),
        catalogue_digest: attempt.selection.catalogue_digest.clone(),
        preference_policy_id: attempt.selection.preference_policy_id.clone(),
        preference_revision: attempt.selection.preference_revision.clone(),
        preference_policy_digest: attempt.selection.preference_policy_digest.clone(),
        selected: attempt.selection.selected.clone(),
        selection_binding: selection_binding(input, preferences, attempt, now_unix_ms),
        health: project_attempt_health(&attempt.telemetry, now_unix_ms)?,
    })
}

fn compile_attempts(
    input: &SwarmControlBoardProjectionInput,
    preferences: Option<&HumanModelPreferencePolicy>,
    expected_account_scope: Option<&str>,
    now_unix_ms: u64,
    gaps: &mut BTreeSet<SwarmProjectionGap>,
) -> Result<Vec<SwarmAttemptProjection>, SwarmControlBoardProjectionError> {
    let Some(telemetry) = &input.attempt_telemetry else {
        gaps.insert(SwarmProjectionGap::ProviderUnavailable {
            provider: SwarmProjectionProvider::AttemptTelemetry,
        });
        return Ok(Vec::new());
    };
    if telemetry.len() > MAX_ATTEMPTS {
        return Err(SwarmControlBoardProjectionError::InvalidField(
            "attempt_telemetry",
        ));
    }
    let mut attempt_ids = BTreeSet::new();
    let mut selection_ids = BTreeSet::new();
    let mut projections = Vec::with_capacity(telemetry.len());
    for attempt in telemetry {
        if !attempt_ids.insert(attempt.telemetry.attempt_id.clone()) {
            return Err(SwarmControlBoardProjectionError::DuplicateIdentity(
                "attempt_id",
            ));
        }
        if !selection_ids.insert(attempt.selection.selection_id.as_str()) {
            return Err(SwarmControlBoardProjectionError::DuplicateIdentity(
                "selection_id",
            ));
        }
        projections.push(compile_attempt(
            input,
            preferences,
            expected_account_scope,
            attempt,
            now_unix_ms,
        )?);
    }
    projections.sort_by(|left, right| left.health.attempt_id.cmp(&right.health.attempt_id));
    Ok(projections)
}

/// Compiles a ControlBoard-consumable read model without calling any provider
/// or model.
///
/// `query.dispatchable_only` must be false because an operator view must retain
/// stale, exhausted, unavailable, and otherwise blocked rows together with the
/// reasons they cannot dispatch.
pub fn compile_swarm_controlboard_projection(
    input: &SwarmControlBoardProjectionInput,
    query: &ModelQuery,
    now_unix_ms: u64,
) -> Result<SwarmControlBoardProjection, SwarmControlBoardProjectionError> {
    if now_unix_ms == 0 {
        return Err(SwarmControlBoardProjectionError::InvalidField(
            "now_unix_ms",
        ));
    }
    if query.dispatchable_only {
        return Err(SwarmControlBoardProjectionError::InvalidField(
            "query.dispatchable_only",
        ));
    }

    let mut gaps = BTreeSet::new();
    let catalogue_account_scope = input
        .catalogue
        .as_ref()
        .map(|snapshot| snapshot.account_scope.as_str());
    let catalogue = compile_catalogue(input, query, now_unix_ms, &mut gaps)?;
    let preferences = compile_preferences(input, catalogue_account_scope, &mut gaps)?;
    let expected_account_scope = catalogue_account_scope
        .or_else(|| preferences.as_ref().map(|policy| policy.account_scope.as_str()));
    let attempts = compile_attempts(
        input,
        preferences.as_ref(),
        expected_account_scope,
        now_unix_ms,
        &mut gaps,
    )?;

    Ok(SwarmControlBoardProjection {
        schema_version: SWARM_CONTROLBOARD_PROJECTION_VERSION.to_owned(),
        observed_at_unix_ms: now_unix_ms,
        catalogue,
        preferences,
        attempts,
        gaps: gaps.into_iter().collect(),
        execution: ZeroModelExecutionCounters::zero(),
        authority_ceiling: SwarmProjectionAuthorityCeiling::UnfilteredReadModelOnly,
    })
}
