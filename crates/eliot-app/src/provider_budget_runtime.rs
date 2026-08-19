//! Durable provider-call authorization and calibration-budget transitions.
//!
//! This module contains the reusable execution boundary. Historical one-off
//! calibration closeout workflows do not belong in the product CLI.

use crate::calibration_runtime;
use anyhow::{Context, Result, bail};
use eliot_engine::{DelegationCalibrationCampaignService, ProviderReviewPreRegistrationService};
use eliot_types::{
    DelegationCalibrationCampaign, DelegationCalibrationCampaignState, DelegationCalibrationState,
    FrozenInputDigest, ProjectId, ProviderCallReservation, ProviderCallReservationState,
    ProviderReviewPreRegistration, TaskId,
};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::Command;
use time::OffsetDateTime;

const PROVIDER: &str = "antigravity";
const MATERIALITY_RULE: &str =
    "material behavior only; candidate-only; controller verifies independently";
const UTILITY_ATTRIBUTION_RULE_VERSION: &str = "l1c-preregistered-1";

/// Create the sealed preregistration that the provider reservation must consume.
///
/// The caller supplies only the governed campaign, task, question, and evidence
/// handles.  The frozen digests, canonical idempotency key, and one-shot token
/// hash are derived here from the campaign and current project state.  The raw
/// token never crosses this function boundary or enters durable state.
pub fn seal_or_reuse_preregistration(
    root: &Path,
    campaign_id: &str,
    project_id: ProjectId,
    task_id: TaskId,
    question: &str,
    evidence_refs: &[String],
    requested_idempotency_key: Option<&str>,
) -> Result<ProviderReviewPreRegistration> {
    with_provider_gate_lock(root, || {
        seal_or_reuse_preregistration_unlocked(
            root,
            campaign_id,
            project_id,
            task_id,
            question,
            evidence_refs,
            requested_idempotency_key,
        )
    })
}

#[allow(clippy::too_many_lines)]
fn seal_or_reuse_preregistration_unlocked(
    root: &Path,
    campaign_id: &str,
    project_id: ProjectId,
    task_id: TaskId,
    question: &str,
    evidence_refs: &[String],
    requested_idempotency_key: Option<&str>,
) -> Result<ProviderReviewPreRegistration> {
    if campaign_id.trim().is_empty() {
        bail!("provider execution campaign ID must not be empty");
    }
    if question.trim().is_empty() {
        bail!("provider review question must not be empty");
    }

    let mut state = calibration_runtime::load_state(root)?;
    let campaign = state
        .campaigns
        .iter()
        .find(|campaign| campaign.campaign_id == campaign_id)
        .cloned()
        .context("provider execution campaign does not exist")?;
    if campaign.project_id != project_id {
        bail!("provider execution campaign project scope mismatch");
    }
    if !campaign.selected_task_ids.contains(&task_id) {
        bail!("provider execution task is outside the campaign selection");
    }
    if campaign.provider_route != PROVIDER {
        bail!("provider execution campaign is not routed to antigravity");
    }
    let existing_preregistration = state
        .preregistrations
        .iter()
        .find(|item| item.campaign_id == campaign_id && item.real_task_id == task_id)
        .cloned();
    if DelegationCalibrationCampaignService::is_terminal(campaign.state)
        && existing_preregistration.is_none()
    {
        bail!("provider execution campaign is terminal");
    }
    if campaign.budget.max_provider_calls != 1 {
        bail!("provider execution campaign must reserve exactly one provider call");
    }
    if campaign.baseline_commit.trim().is_empty()
        || campaign.baseline_state_hash.trim().is_empty()
        || campaign.frozen_input_refs.is_empty()
    {
        bail!("provider execution campaign does not contain a frozen baseline");
    }

    let project_root = calibration_runtime::campaign_project_root(root, project_id, task_id)?;
    let mut frozen_input_refs = campaign.frozen_input_refs.clone();
    frozen_input_refs.sort();
    let frozen_input_digests = recompute_frozen_input_refs(&project_root, &frozen_input_refs)?;
    let frozen_input_hash = digest_set_hash(&frozen_input_digests)?;
    let canonical_idempotency_key = ProviderReviewPreRegistrationService::idempotency_key(
        campaign_id,
        task_id,
        PROVIDER,
        &campaign.baseline_commit,
        &frozen_input_hash,
    );
    if let Some(requested) = requested_idempotency_key {
        if requested.trim().is_empty() {
            bail!("provider execution idempotency key must not be empty");
        }
        if requested != canonical_idempotency_key {
            bail!("provider execution idempotency key does not match frozen campaign inputs");
        }
    }

    let preregistration_id = format!(
        "provider-preregistration:{}",
        blake3::hash(
            format!("{campaign_id}\n{task_id}\n{PROVIDER}\n{canonical_idempotency_key}").as_bytes(),
        )
        .to_hex()
    );
    let now = OffsetDateTime::now_utc();
    let mut candidate = ProviderReviewPreRegistration {
        preregistration_id,
        campaign_id: campaign_id.to_owned(),
        project_id: campaign.project_id,
        real_task_id: task_id,
        provider: PROVIDER.to_owned(),
        task_family: campaign.task_family,
        baseline_commit: campaign.baseline_commit.clone(),
        comparison_base_commit: campaign.baseline_commit.clone(),
        frozen_input_refs,
        frozen_input_digests,
        frozen_input_hash,
        review_questions: vec![question.trim().to_owned()],
        materiality_rule: MATERIALITY_RULE.to_owned(),
        independent_evidence_plan: if evidence_refs.is_empty() {
            vec!["controller_verifier_required".to_owned()]
        } else {
            evidence_refs.to_vec()
        },
        utility_attribution_rule_version: UTILITY_ATTRIBUTION_RULE_VERSION.to_owned(),
        max_provider_calls: 1,
        idempotency_key: canonical_idempotency_key,
        execution_token_hash: String::new(),
        historical_exclusions_hash: campaign.baseline_state_hash.clone(),
        forbidden_effects: vec!["live_tree_write".to_owned()],
        expected_terminal_states: vec!["closed".to_owned()],
        created_at: now,
        sealed_at: now,
        consumed_at: None,
        reservation_ref: None,
        invocation_ref: None,
        review_ref: None,
        supersedes_ref: None,
    };
    let execution_token = ProviderReviewPreRegistrationService::execution_token(&candidate);
    candidate.execution_token_hash = blake3::hash(execution_token.as_bytes())
        .to_hex()
        .to_string();
    ProviderReviewPreRegistrationService::validate_token(&candidate, &execution_token)
        .map_err(anyhow::Error::msg)?;

    if let Some(existing) = existing_preregistration {
        validate_preregistration_identity(&existing, &candidate)?;
        ProviderReviewPreRegistrationService::validate_sealed_replay(&existing, &candidate)
            .map_err(anyhow::Error::msg)?;
        validate_sealed_preregistration(root, &existing)?;
        return Ok(existing);
    }

    if let Some(stored_campaign) = state
        .campaigns
        .iter_mut()
        .find(|item| item.campaign_id == campaign_id)
    {
        if stored_campaign.state == DelegationCalibrationCampaignState::Draft {
            transition(
                stored_campaign,
                DelegationCalibrationCampaignState::Preregistered,
                Some(candidate.preregistration_id.clone()),
            )?;
            transition(
                stored_campaign,
                DelegationCalibrationCampaignState::Ready,
                Some(candidate.preregistration_id.clone()),
            )?;
        } else if stored_campaign.state == DelegationCalibrationCampaignState::Preregistered {
            transition(
                stored_campaign,
                DelegationCalibrationCampaignState::Ready,
                Some(candidate.preregistration_id.clone()),
            )?;
        }
    }
    state.preregistrations.push(candidate.clone());
    calibration_runtime::save(root, &state)?;
    Ok(candidate)
}

/// Revalidate the sealed record immediately before provider reservation.
///
/// This checks the immutable one-call/token invariants and recomputes all
/// frozen inputs from the current project root.  It deliberately returns no
/// execution token; the token is only derived and checked in-process when a
/// record is sealed.
pub fn validate_sealed_preregistration(
    root: &Path,
    preregistration: &ProviderReviewPreRegistration,
) -> Result<()> {
    if preregistration.provider != PROVIDER || preregistration.max_provider_calls != 1 {
        bail!("sealed provider preregistration provider or call budget is invalid");
    }
    let execution_token = ProviderReviewPreRegistrationService::execution_token(preregistration);
    ProviderReviewPreRegistrationService::validate_token(preregistration, &execution_token)
        .map_err(anyhow::Error::msg)?;
    let project_root = calibration_runtime::campaign_project_root(
        root,
        preregistration.project_id,
        preregistration.real_task_id,
    )?;
    let current_digests = recompute_frozen_inputs(&project_root, preregistration)?;
    if current_digests != preregistration.frozen_input_digests
        || digest_set_hash(&current_digests)? != preregistration.frozen_input_hash
    {
        bail!("frozen input hash changed after provider preregistration was sealed");
    }
    Ok(())
}

pub fn record_reservation(
    root: &Path,
    campaign_id: &str,
    preregistration_id: &str,
    reservation: &ProviderCallReservation,
) -> Result<()> {
    let mut state = calibration_runtime::load_state(root)?;
    transition(
        campaign_mut(&mut state, campaign_id)?,
        DelegationCalibrationCampaignState::Reserved,
        Some(reservation.reservation_id.clone()),
    )?;
    let preregistration = preregistration_mut(&mut state, preregistration_id)?;
    preregistration.consumed_at = Some(OffsetDateTime::now_utc());
    preregistration.reservation_ref = Some(reservation.reservation_id.clone());
    calibration_runtime::save(root, &state)
}

pub fn record_dispatching(root: &Path, campaign_id: &str, reservation_id: &str) -> Result<()> {
    let mut state = calibration_runtime::load_state(root)?;
    transition(
        campaign_mut(&mut state, campaign_id)?,
        DelegationCalibrationCampaignState::Dispatching,
        Some(reservation_id.to_owned()),
    )?;
    calibration_runtime::save(root, &state)
}

pub fn record_execution_terminal(
    root: &Path,
    campaign_id: &str,
    preregistration_id: &str,
    reservation: &ProviderCallReservation,
) -> Result<()> {
    let mut state = calibration_runtime::load_state(root)?;
    let next = match reservation.state {
        ProviderCallReservationState::Completed => {
            DelegationCalibrationCampaignState::ProviderExecuted
        }
        ProviderCallReservationState::ReleasedPreDispatch => {
            DelegationCalibrationCampaignState::ReleasedPreDispatch
        }
        ProviderCallReservationState::UnknownOutcome => {
            DelegationCalibrationCampaignState::UnknownOutcome
        }
        ProviderCallReservationState::Failed => DelegationCalibrationCampaignState::FailedProvider,
        _ => return Ok(()),
    };
    let campaign = campaign_mut(&mut state, campaign_id)?;
    if !DelegationCalibrationCampaignService::is_terminal(campaign.state) && campaign.state != next
    {
        transition(campaign, next, Some(reservation.reservation_id.clone()))?;
    }
    let preregistration = preregistration_mut(&mut state, preregistration_id)?;
    preregistration
        .invocation_ref
        .clone_from(&reservation.external_invocation_ref);
    preregistration
        .review_ref
        .clone_from(&reservation.review_ref);
    calibration_runtime::save(root, &state)
}

fn recompute_frozen_inputs(
    project_root: &Path,
    preregistration: &ProviderReviewPreRegistration,
) -> Result<Vec<FrozenInputDigest>> {
    let source_refs = preregistration
        .frozen_input_digests
        .iter()
        .map(|stored| stored.source_ref.clone())
        .collect::<Vec<_>>();
    recompute_frozen_input_refs(project_root, &source_refs)
}

fn recompute_frozen_input_refs(
    project_root: &Path,
    source_refs: &[String],
) -> Result<Vec<FrozenInputDigest>> {
    let mut digests = Vec::new();
    for source_ref in source_refs {
        let content = if let Some(spec) = source_ref.strip_prefix("git-diff:") {
            let (from, to) = spec
                .split_once("..")
                .context("invalid frozen git-diff source")?;
            git_bytes(project_root, &["diff", from, to, "--"])?
        } else if let Some(spec) = source_ref.strip_prefix("git-show:") {
            git_bytes(project_root, &["show", spec])?
        } else if let Some(path) = source_ref.strip_prefix("file:") {
            let path = PathBuf::from(path);
            std::fs::read(if path.is_absolute() {
                path
            } else {
                project_root.join(path)
            })?
        } else {
            bail!("unknown frozen input source {source_ref}");
        };
        digests.push(FrozenInputDigest {
            source_ref: source_ref.clone(),
            content_hash: blake3::hash(&content).to_hex().to_string(),
        });
    }
    digests.sort_by(|left, right| left.source_ref.cmp(&right.source_ref));
    Ok(digests)
}

fn validate_preregistration_identity(
    existing: &ProviderReviewPreRegistration,
    candidate: &ProviderReviewPreRegistration,
) -> Result<()> {
    let same_immutable_identity = existing.preregistration_id == candidate.preregistration_id
        && existing.campaign_id == candidate.campaign_id
        && existing.project_id == candidate.project_id
        && existing.real_task_id == candidate.real_task_id
        && existing.provider == candidate.provider
        && existing.task_family == candidate.task_family
        && existing.baseline_commit == candidate.baseline_commit
        && existing.comparison_base_commit == candidate.comparison_base_commit
        && existing.frozen_input_refs == candidate.frozen_input_refs
        && existing.frozen_input_digests == candidate.frozen_input_digests
        && existing.frozen_input_hash == candidate.frozen_input_hash
        && existing.execution_token_hash == candidate.execution_token_hash
        && existing.historical_exclusions_hash == candidate.historical_exclusions_hash
        && existing.forbidden_effects == candidate.forbidden_effects
        && existing.expected_terminal_states == candidate.expected_terminal_states;
    if !same_immutable_identity {
        bail!("sealed preregistration identity changed; create a new campaign attempt");
    }
    Ok(())
}

pub(crate) fn canonical_provider_idempotency_key(
    project_root: &Path,
    campaign_id: &str,
    task_id: TaskId,
    baseline_commit: &str,
    frozen_input_refs: &[String],
) -> Result<String> {
    let mut frozen_input_refs = frozen_input_refs.to_vec();
    frozen_input_refs.sort();
    let frozen_input_digests = recompute_frozen_input_refs(project_root, &frozen_input_refs)?;
    let frozen_input_hash = digest_set_hash(&frozen_input_digests)?;
    Ok(ProviderReviewPreRegistrationService::idempotency_key(
        campaign_id,
        task_id,
        PROVIDER,
        baseline_commit,
        &frozen_input_hash,
    ))
}

fn with_provider_gate_lock<T, F>(root: &Path, operation: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let runtime = root.join("runtime");
    std::fs::create_dir_all(&runtime)?;
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(runtime.join("provider-call-ledger.lock"))?;
    lock.lock()?;
    let result = operation();
    drop(lock);
    result
}

fn digest_set_hash(digests: &[FrozenInputDigest]) -> Result<String> {
    Ok(blake3::hash(&serde_json::to_vec(digests)?)
        .to_hex()
        .to_string())
}

fn campaign_mut<'a>(
    state: &'a mut DelegationCalibrationState,
    campaign_id: &str,
) -> Result<&'a mut DelegationCalibrationCampaign> {
    state
        .campaigns
        .iter_mut()
        .find(|item| item.campaign_id == campaign_id)
        .context("calibration campaign does not exist")
}

fn preregistration_mut<'a>(
    state: &'a mut DelegationCalibrationState,
    preregistration_id: &str,
) -> Result<&'a mut ProviderReviewPreRegistration> {
    state
        .preregistrations
        .iter_mut()
        .find(|item| item.preregistration_id == preregistration_id)
        .context("provider preregistration does not exist")
}

fn transition(
    campaign: &mut DelegationCalibrationCampaign,
    next: DelegationCalibrationCampaignState,
    evidence_ref: Option<String>,
) -> Result<()> {
    let changed = DelegationCalibrationCampaignService
        .transition(campaign, next)
        .map_err(anyhow::Error::msg)?;
    if changed && let Some(last) = campaign.transition_history.last_mut() {
        last.evidence_ref = evidence_ref;
    }
    Ok(())
}

fn git_bytes(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git").args(args).current_dir(root).output()?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_engine::{
        ProviderCallCampaignRequest, ProviderCallReservationDecision, ProviderCallReservationOwner,
        ProviderCallReservationRequest, WorkState, default_work_scope,
    };
    use eliot_types::{
        AgentId, AgentRole, AgentSessionId, DelegationCalibrationCampaignBudget,
        DelegationCalibrationCampaignCloseoutStatus, DelegationCalibrationTaskFamily,
        DelegationEvidenceFloorSnapshot, DelegationOrigin, DelegationProviderPreference,
        DelegationReviewKind, WorkItemId, WorkLease, WorkLeaseDecision, WorkLeaseDecisionKind,
        WorkLeaseDecisionReason, WorkLeaseId, WorkLeaseState,
    };
    use serde_json::json;

    struct Fixture {
        root: PathBuf,
        project_id: ProjectId,
        task_id: TaskId,
        campaign_id: String,
        input_path: PathBuf,
    }

    impl Fixture {
        fn new() -> Result<Self> {
            let project_root =
                std::env::temp_dir().join(format!("eliot-antigravity-prereg-{}", TaskId::new_v7()));
            let root = project_root.join(".eliot-governor");
            std::fs::create_dir_all(&project_root)?;
            let git_init = Command::new("git")
                .args(["init", "--quiet"])
                .current_dir(&project_root)
                .output()?;
            anyhow::ensure!(
                git_init.status.success(),
                "git init failed: {}",
                String::from_utf8_lossy(&git_init.stderr)
            );
            let input_path = project_root.join("frozen-input.txt");
            std::fs::write(&input_path, b"frozen evidence v1")?;
            let project_id = ProjectId::new_v7();
            let task_id = TaskId::new_v7();
            let now = OffsetDateTime::now_utc();
            let work_lease_id = WorkLeaseId::new_v7();
            let mut work_state = WorkState::default();
            work_state.leases.push(WorkLease {
                work_lease_id,
                work_item_id: WorkItemId::new_v7(),
                agent_session_id: AgentSessionId::new_v7(),
                agent_id: AgentId::new_v7(),
                project_id,
                task_id,
                role: AgentRole::Auditor,
                state: WorkLeaseState::Granted,
                epoch: 1,
                scope: default_work_scope(
                    project_root.display().to_string(),
                    vec![".".to_owned()],
                    Vec::new(),
                    Vec::new(),
                ),
                decision: WorkLeaseDecision {
                    kind: WorkLeaseDecisionKind::Granted,
                    reason: WorkLeaseDecisionReason::NoConflict,
                    message: "test audit lease".to_owned(),
                    work_lease_id: Some(work_lease_id),
                    conflicting_lease_ids: Vec::new(),
                    expires_at: Some(now + time::Duration::hours(1)),
                },
                conflict_refs: Vec::new(),
                granted_at: now,
                expires_at: now + time::Duration::hours(1),
                renewed_at: None,
                released_at: None,
                revoked_at: None,
                write_receipt: None,
            });
            crate::delegation_runtime::save_work_state(&root, &work_state)?;
            let campaign_id = format!("campaign:{task_id}");
            let campaign = DelegationCalibrationCampaign {
                campaign_id: campaign_id.clone(),
                project_id,
                schema_version: "1".to_owned(),
                created_at: OffsetDateTime::now_utc(),
                closed_at: None,
                baseline_commit: "baseline-commit".to_owned(),
                policy_snapshot_id: "policy:l0".to_owned(),
                provider_route: PROVIDER.to_owned(),
                task_family: DelegationCalibrationTaskFamily::ArchitectureDesign,
                selection_rule: "bounded test fixture".to_owned(),
                budget: DelegationCalibrationCampaignBudget {
                    max_provider_calls: 1,
                    max_cost_if_known: None,
                    max_wall_time_seconds: 60,
                },
                evidence_floor_snapshot: DelegationEvidenceFloorSnapshot::default(),
                selected_task_ids: vec![task_id],
                frozen_input_refs: vec!["file:frozen-input.txt".to_owned()],
                baseline_state_hash: "baseline-state".to_owned(),
                observed_provider_calls: 0,
                integrity_violations: Vec::new(),
                executed_review_ids: Vec::new(),
                independent_evidence_ids: Vec::new(),
                shadow_evaluation_ids: Vec::new(),
                state: DelegationCalibrationCampaignState::Ready,
                closeout_status: DelegationCalibrationCampaignCloseoutStatus::Open,
                transition_history: Vec::new(),
            };
            calibration_runtime::save(
                &root,
                &DelegationCalibrationState {
                    campaigns: vec![campaign],
                    ..DelegationCalibrationState::default()
                },
            )?;
            Ok(Self {
                root,
                project_id,
                task_id,
                campaign_id,
                input_path,
            })
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Some(project_root) = self.root.parent() {
                let _ = std::fs::remove_dir_all(project_root);
            }
        }
    }

    fn must_fail<T, E: std::fmt::Display>(result: Result<T, E>, message: &str) -> String {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn seal_is_idempotent_and_does_not_persist_raw_execution_token() -> Result<()> {
        let fixture = Fixture::new()?;
        let first = seal_or_reuse_preregistration(
            &fixture.root,
            &fixture.campaign_id,
            fixture.project_id,
            fixture.task_id,
            "bounded architecture question",
            &["cargo-nextest".to_owned()],
            None,
        )?;
        let second = seal_or_reuse_preregistration(
            &fixture.root,
            &fixture.campaign_id,
            fixture.project_id,
            fixture.task_id,
            "bounded architecture question",
            &["cargo-nextest".to_owned()],
            Some(&first.idempotency_key),
        )?;
        assert_eq!(first, second);
        let raw_token = ProviderReviewPreRegistrationService::execution_token(&first);
        let persisted = std::fs::read_to_string(
            fixture
                .root
                .join("reports/delegation-calibration-state/latest.json"),
        )?;
        assert!(!persisted.contains(&raw_token));
        assert_ne!(first.execution_token_hash, raw_token);
        assert_eq!(
            calibration_runtime::load_state(&fixture.root)?
                .preregistrations
                .len(),
            1
        );
        Ok(())
    }

    #[test]
    fn changed_question_or_frozen_input_cannot_replay_sealed_preregistration() -> Result<()> {
        let fixture = Fixture::new()?;
        let first = seal_or_reuse_preregistration(
            &fixture.root,
            &fixture.campaign_id,
            fixture.project_id,
            fixture.task_id,
            "original question",
            &[],
            None,
        )?;
        let question_error = must_fail(
            seal_or_reuse_preregistration(
                &fixture.root,
                &fixture.campaign_id,
                fixture.project_id,
                fixture.task_id,
                "amended question",
                &[],
                Some(&first.idempotency_key),
            ),
            "changed review question must not replay",
        );
        assert!(question_error.contains("semantic amendment"));

        std::fs::write(&fixture.input_path, b"frozen evidence v2")?;
        let input_error = must_fail(
            seal_or_reuse_preregistration(
                &fixture.root,
                &fixture.campaign_id,
                fixture.project_id,
                fixture.task_id,
                "original question",
                &[],
                None,
            ),
            "changed frozen input must not replay",
        );
        assert!(input_error.contains("sealed preregistration identity"));
        Ok(())
    }

    #[test]
    fn campaign_budget_is_exactly_one_call_and_wrong_key_is_rejected() -> Result<()> {
        let fixture = Fixture::new()?;
        let wrong_key = must_fail(
            seal_or_reuse_preregistration(
                &fixture.root,
                &fixture.campaign_id,
                fixture.project_id,
                fixture.task_id,
                "question",
                &[],
                Some("operator-supplied-not-canonical"),
            ),
            "caller cannot override frozen idempotency",
        );
        assert!(wrong_key.contains("idempotency key"));

        let mut state = calibration_runtime::load_state(&fixture.root)?;
        state.campaigns[0].budget.max_provider_calls = 2;
        calibration_runtime::save(&fixture.root, &state)?;
        let budget_error = must_fail(
            seal_or_reuse_preregistration(
                &fixture.root,
                &fixture.campaign_id,
                fixture.project_id,
                fixture.task_id,
                "question",
                &[],
                None,
            ),
            "campaign may not widen the one-call budget",
        );
        assert!(budget_error.contains("exactly one provider call"));
        Ok(())
    }

    #[test]
    fn provider_reservation_is_single_and_idempotent_without_provider_spawn() -> Result<()> {
        let fixture = Fixture::new()?;
        let preregistration = seal_or_reuse_preregistration(
            &fixture.root,
            &fixture.campaign_id,
            fixture.project_id,
            fixture.task_id,
            "question",
            &[],
            None,
        )?;
        let owner = ProviderCallReservationOwner::new(&fixture.root);
        owner.open_campaign(ProviderCallCampaignRequest {
            campaign_id: fixture.campaign_id.clone(),
            max_calls: 1,
            closed: false,
        })?;
        let request = ProviderCallReservationRequest {
            campaign_id: fixture.campaign_id.clone(),
            task_id: fixture.task_id,
            provider: PROVIDER.to_owned(),
            idempotency_key: preregistration.idempotency_key.clone(),
            gate_decision_ref: "gate:test".to_owned(),
        };
        let first = owner.reserve(request.clone())?;
        let first_reservation = match first {
            ProviderCallReservationDecision::Reserved(reservation) => reservation,
            other => panic!("expected first reservation, got {other:?}"),
        };
        let replay = owner.reserve(request)?;
        match replay {
            ProviderCallReservationDecision::IdempotentReplay(reservation) => {
                assert_eq!(reservation.reservation_id, first_reservation.reservation_id);
            }
            other => panic!("expected idempotent replay, got {other:?}"),
        }
        let ledger = owner.snapshot()?;
        assert_eq!(ledger.reservations.len(), 1);
        assert_eq!(ledger.budgets[0].max_calls, 1);
        assert_eq!(ledger.budgets[0].reserved_slots, 1);
        Ok(())
    }

    #[test]
    fn operator_intent_and_budget_slot_remain_required() {
        let mut input = crate::delegation_runtime::DelegationReviewInput {
            project_id: "project".to_owned(),
            task_id: "task".to_owned(),
            origin: DelegationOrigin::UserDirected,
            review_kind: DelegationReviewKind::ArchitectureAudit,
            question: "question".to_owned(),
            work_lease_id: "lease".to_owned(),
            evidence_refs: Vec::new(),
            preferred_provider: DelegationProviderPreference::Antigravity,
            wait: false,
            origin_chain: None,
            campaign_id: Some("campaign".to_owned()),
            idempotency_key: Some("idempotency".to_owned()),
            require_budget_slot: false,
            explicit_operator_intent: true,
        };
        assert!(!crate::delegation_runtime::real_provider_execution_flags(
            &input
        ));
        input.require_budget_slot = true;
        input.explicit_operator_intent = false;
        assert!(!crate::delegation_runtime::real_provider_execution_flags(
            &input
        ));
    }

    #[test]
    fn public_review_schema_rejects_raw_execution_token() {
        let input = json!({
            "project_id": "project",
            "task_id": "task",
            "origin": "user_directed",
            "review_kind": "architecture_audit",
            "question": "question",
            "work_lease_id": "lease",
            "campaign_id": "campaign",
            "idempotency_key": "idempotency",
            "require_budget_slot": true,
            "explicit_operator_intent": true,
            "execution_token": "raw-token-must-not-be-accepted"
        });
        let error = must_fail(
            serde_json::from_value::<crate::delegation_runtime::DelegationReviewInput>(input),
            "raw execution token is not a public input",
        );
        assert!(error.contains("unknown field"));
    }
}
