use eliot_engine::ActivationEngine;
use eliot_types::{
    ActivationEdgeKind, CoChangeEdge, ProjectId, SessionId, UlActivationGraphEdge,
    UlActivationGraphRows,
};

#[test]
fn u8_4_activation_arithmetic_is_fixed_point() -> Result<(), Box<dyn std::error::Error>> {
    let graph = UlActivationGraphRows {
        co_change: vec![co_change("a", "b", 0.8)],
        relations: vec![UlActivationGraphEdge {
            from_ref: "file:b".to_owned(),
            to_ref: "card:c".to_owned(),
            kind: ActivationEdgeKind::CardCovers,
        }],
    };
    let trace = ActivationEngine::compute(
        ProjectId::new_v7(),
        SessionId::new_v7(),
        None,
        &["file:a".to_owned()],
        &graph,
    )?;

    assert_eq!(
        trace
            .activated
            .iter()
            .find(|node| node.node_ref == "file:b")
            .map(|node| node.score_milli),
        Some(560)
    );
    assert!(trace.suppressed.iter().any(|node| {
        node.node_ref == "card:c" && node.score_milli == 252 && node.reason == "below_threshold"
    }));
    Ok(())
}

#[test]
fn u8_5_activation_fanout_is_capped_and_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let session_id = SessionId::new_v7();
    let graph = UlActivationGraphRows {
        co_change: Vec::new(),
        relations: (0..10_000)
            .map(|index| UlActivationGraphEdge {
                from_ref: "claim:hub".to_owned(),
                to_ref: format!("evidence:{index:05}"),
                kind: ActivationEdgeKind::Supports,
            })
            .collect(),
    };
    let first = ActivationEngine::compute(
        project_id,
        session_id,
        None,
        &["claim:hub".to_owned()],
        &graph,
    )?;
    let second = ActivationEngine::compute(
        project_id,
        session_id,
        None,
        &["claim:hub".to_owned()],
        &graph,
    )?;

    assert_eq!(first.activated.len(), 20);
    assert_eq!(first.suppressed.len(), 256);
    assert_eq!(serde_json::to_vec(&first)?, serde_json::to_vec(&second)?);
    Ok(())
}

fn co_change(path_a: &str, path_b: &str, confidence: f64) -> CoChangeEdge {
    CoChangeEdge {
        edge_id: format!("edge-{path_a}-{path_b}"),
        project_id: ProjectId::new_v7(),
        path_a: path_a.to_owned(),
        path_b: path_b.to_owned(),
        support: 8,
        confidence_ab: confidence,
        confidence_ba: confidence,
        last_cochange_at_unix: 0,
        static_edge_exists: None,
        mining_run_ref: "mining:test".to_owned(),
        cue_bindings: Vec::new(),
    }
}
