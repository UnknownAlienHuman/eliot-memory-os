// Frozen fixture for WORK_UNIT_CASE 748/1.
// Unauthorized direct std constructor outside the sole ProcessExecutor owner.
// Must keep triggering the oracle's direct-process-launch discovery
// (`_contains_direct_process_launch` == true) on the base oracle.
use std::process::Command;

pub fn launch_unauthorized() -> std::process::Child {
    Command::new("example-helper").spawn().expect("spawn unauthorized helper")
}
