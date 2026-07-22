//! Durable provider-call authorization and calibration-budget transitions.
//!
//! This module contains the reusable execution boundary. Historical one-off
//! calibration closeout workflows do not belong in the product CLI.

use crate::calibration_runtime;
use anyhow::{Context, Result, bail};
use eliot_engine::{DelegationCalibrationCampaignService, ProviderReviewPreRegistrationService};
use eliot_types::{
    DelegationCalibrationCampaign, DelegationCalibrationCampaignState, DelegationCalibrationState,
    FrozenInputDigest, ProviderCallReservation, ProviderCallReservationState,
    ProviderReviewPreRegistration,
};
use std::path::{Path, PathBuf};
use std::process::Command;
use time::OffsetDateTime;

pub fn validate_execution_authorization(
    root: &Path,
    campaign_id: &str,
    preregistration_id: &str,
    token: &str,
) -> Result<ProviderReviewPreRegistration> {
    let state = calibration_runtime::load_state(root)?;
    let preregistration = state
        .preregistrations
        .iter()
        .find(|item| {
            item.preregistration_id == preregistration_id && item.campaign_id == campaign_id
        })
        .cloned()
        .context("sealed provider preregistration does not exist")?;
    ProviderReviewPreRegistrationService::validate_token(&preregistration, token)
        .map_err(anyhow::Error::msg)?;
    if preregistration.provider != "antigravity" {
        bail!("preregistration provider or call budget changed after sealing");
    }
    let project_root = root
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let current_digests = recompute_frozen_inputs(project_root, &preregistration)?;
    if current_digests != preregistration.frozen_input_digests
        || digest_set_hash(&current_digests)? != preregistration.frozen_input_hash
    {
        bail!("frozen input hash changed after provider preregistration was sealed");
    }
    Ok(preregistration)
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
    let mut digests = Vec::new();
    for stored in &preregistration.frozen_input_digests {
        let content = if let Some(spec) = stored.source_ref.strip_prefix("git-diff:") {
            let (from, to) = spec
                .split_once("..")
                .context("invalid frozen git-diff source")?;
            git_bytes(project_root, &["diff", from, to, "--"])?
        } else if let Some(spec) = stored.source_ref.strip_prefix("git-show:") {
            git_bytes(project_root, &["show", spec])?
        } else if let Some(path) = stored.source_ref.strip_prefix("file:") {
            let path = PathBuf::from(path);
            std::fs::read(if path.is_absolute() {
                path
            } else {
                project_root.join(path)
            })?
        } else {
            bail!("unknown frozen input source {}", stored.source_ref);
        };
        digests.push(FrozenInputDigest {
            source_ref: stored.source_ref.clone(),
            content_hash: blake3::hash(&content).to_hex().to_string(),
        });
    }
    digests.sort_by(|left, right| left.source_ref.cmp(&right.source_ref));
    Ok(digests)
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
