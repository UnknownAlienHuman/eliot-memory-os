// Frozen fixture for WORK_UNIT_CASE 748/2.
// Accepted executor surface with no direct process construction.
// Must keep passing the oracle's direct-process-launch discovery
// (`_contains_direct_process_launch` == false) on the base oracle.
pub fn executor_name() -> &'static str {
    "eliot-process-executor"
}
