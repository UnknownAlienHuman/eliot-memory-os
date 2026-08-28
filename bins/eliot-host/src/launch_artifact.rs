//! Stable facade for the retained launch-artifact lease cell.

#[path = "launch_artifact_lease.rs"]
mod launch_artifact_lease;

pub(super) use self::launch_artifact_lease::{
    LaunchLease, approved_locator, approved_phase_b_destination_locator, open_launch_lease,
    verify_launch_digest,
};
