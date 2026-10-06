//! Overlay policy routing proof for issue #1864.
//!
//! A task-level surface rejected by overlay policy reaches the
//! Improvement path as an advisory draft for the Task Controller,
//! while the two local surfaces stay in the overlay path and blank
//! routing input is refused fail-closed.

use eliot_improvement::route_rejected_surface;

const TARGET_1864: &str = "target-1864";
const OVERLAY_1864: &str = "overlay-1864";
const DELTA_1864: &str = "delta-1864";
const TASK_1864: &str = "task-1864";

#[test]
fn task_level_surface_routes_to_improvement_draft_1864() {
    let draft = route_rejected_surface(
        "TaskLocalContext",
        TARGET_1864,
        OVERLAY_1864,
        DELTA_1864,
        TASK_1864,
    )
    .expect("task-level surface routes to an improvement draft");
    assert_eq!(draft.rejected_surface, "TaskLocalContext");
    assert_eq!(draft.rejected_target, TARGET_1864);
    assert_eq!(draft.source_overlay_id, OVERLAY_1864);
    assert_eq!(draft.source_delta_id, DELTA_1864);
    assert_eq!(draft.task_id, TASK_1864);
    assert!(draft.policy_summary.contains("Task Controller"));
}

#[test]
fn local_surfaces_stay_in_overlay_path_1864() {
    for surface in [
        "VerificationOrder",
        "VERIFICATION_ORDER",
        "SearchProbeStopping",
        "SEARCH_PROBE_STOPPING",
    ] {
        assert!(matches!(
            route_rejected_surface(surface, TARGET_1864, OVERLAY_1864, DELTA_1864, TASK_1864),
            Err("local_surface")
        ));
    }
}

#[test]
fn blank_routing_input_refused_1864() {
    assert!(matches!(
        route_rejected_surface("", TARGET_1864, OVERLAY_1864, DELTA_1864, TASK_1864),
        Err("empty_field")
    ));
}
