//! Stable facade for the retained launch-artifact lease cell.

#[path = "launch_artifact_lease.rs"]
mod launch_artifact_lease;

pub(super) use self::launch_artifact_lease::{
    LaunchLease, approved_locator, approved_locator_with_correlation,
    approved_phase_b_destination_locator, open_launch_lease, open_launch_lease_with_correlation,
    verify_launch_digest, verify_launch_digest_with_correlation,
};
