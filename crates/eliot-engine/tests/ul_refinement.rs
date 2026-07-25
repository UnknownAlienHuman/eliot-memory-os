use eliot_engine::{
    UlRefinementAnchor, UlRefinementTrigger, refine_capsule_prose, validate_refinement_candidate,
};
use eliot_types::{DependencyManifest, ProjectId, SubsystemCapsule, UlReasoningRoute};

#[test]
fn u10_8_refinement_validation_and_fallback() -> Result<(), Box<dyn std::error::Error>> {
    let capsule = capsule();
    let anchors = vec![
        UlRefinementAnchor {
            anchor_id: "purpose".to_owned(),
            text: "Own the governed writer boundary.".to_owned(),
        },
        UlRefinementAnchor {
            anchor_id: "path".to_owned(),
            text: "src/writer".to_owned(),
        },
    ];
    let valid = r#"{"purpose":"Own the governed writer boundary [a:purpose]","boundaries":"src/writer [a:path]"}"#;
    let candidate =
        validate_refinement_candidate(valid, &anchors).ok_or("valid candidate rejected")?;
    let refined = refine_capsule_prose(
        &capsule,
        UlRefinementTrigger::ExplicitMaintain,
        UlReasoningRoute::Claude,
        &anchors,
        Some(&candidate),
    )?;
    assert!(
        refined
            .capsule
            .body_md
            .starts_with("PURPOSE\nOwn the governed writer boundary [a:purpose]")
    );
    let old_suffix = capsule
        .body_md
        .split_once("KEY ENTRYPOINTS")
        .ok_or("old suffix missing")?
        .1;
    let new_suffix = refined
        .capsule
        .body_md
        .split_once("KEY ENTRYPOINTS")
        .ok_or("new suffix missing")?
        .1;
    assert_eq!(old_suffix, new_suffix);
    assert_eq!(
        refined.build.previous_build_id.as_deref(),
        Some(capsule.build_id.as_str())
    );

    let invalid_anchor =
        r#"{"purpose":"Unsupported claim [a:missing]","boundaries":"src/other [a:missing]"}"#;
    assert!(validate_refinement_candidate(invalid_anchor, &anchors).is_none());
    let over_budget = serde_json::json!({
        "purpose": format!("{} [a:purpose]", "operative ".repeat(200)),
        "boundaries": "src/writer [a:path]"
    })
    .to_string();
    assert!(validate_refinement_candidate(&over_budget, &anchors).is_none());

    let fallback = refine_capsule_prose(
        &capsule,
        UlRefinementTrigger::ExamFailure,
        UlReasoningRoute::Antigravity,
        &anchors,
        None,
    )?;
    assert!(fallback.used_fallback);
    assert_ne!(fallback.capsule.build_id, capsule.build_id);
    assert_eq!(
        fallback.build.previous_build_id.as_deref(),
        Some(capsule.build_id.as_str())
    );
    assert!(fallback.capsule.body_md.contains("PURPOSE\nOld purpose."));
    assert!(
        fallback
            .capsule
            .body_md
            .contains("BOUNDARIES\n- src/writer")
    );
    Ok(())
}

fn capsule() -> SubsystemCapsule {
    SubsystemCapsule {
        capsule_id: "capsule-writer".to_owned(),
        project_id: ProjectId::new_v7(),
        concept_id: "writer".to_owned(),
        body_md: "PURPOSE\nOld purpose.\n\nBOUNDARIES\n- src/writer\n\nKEY ENTRYPOINTS\n- file:src/writer/lib.rs\n\nINVARIANTS\n- invariant:single-writer\n\nDRAGONS\n- none\n\nKEY DECISIONS\n- none\n\nVERIFIERS\n- cargo test"
            .to_owned(),
        dependency_manifest: DependencyManifest::default(),
        build_id: "build-old".to_owned(),
        cue_bindings: Vec::new(),
        source_refs: vec!["file:src/writer/lib.rs".to_owned()],
    }
}
