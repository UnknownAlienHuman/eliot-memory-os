use eliot_engine::{dependency_refs, render_capsule_with_dirty};
use eliot_types::{
    DependencyManifest, FileDependency, ProjectId, PyramidTargetKind, SubsystemCapsule,
    UlArtifactDirtyState, UlDependencyKind, UlDependencyRef, UlDirtyReason,
};
use time::OffsetDateTime;

#[test]
fn u8_3_dependency_manifest_is_stable_and_dirty_state_renders_exact_keys() {
    let project_id = ProjectId::new_v7();
    let manifest = DependencyManifest {
        project_root: "C:/work/project".to_owned(),
        file_deps: vec![
            FileDependency {
                path: r"src\a.rs".to_owned(),
                blake3: "old".to_owned(),
            },
            FileDependency {
                path: "src/a.rs".to_owned(),
                blake3: "old".to_owned(),
            },
        ],
        claim_deps: vec!["claim:z".to_owned()],
        decision_deps: Vec::new(),
        edge_deps: Vec::new(),
        report_deps: Vec::new(),
    };
    let dependencies = dependency_refs(&manifest);
    assert_eq!(
        dependencies,
        vec![
            UlDependencyRef {
                kind: UlDependencyKind::File,
                key: "src/a.rs".to_owned(),
            },
            UlDependencyRef {
                kind: UlDependencyKind::Claim,
                key: "claim:z".to_owned(),
            },
        ]
    );
    let capsule = SubsystemCapsule {
        capsule_id: "capsule:test".to_owned(),
        project_id,
        concept_id: "concept:test".to_owned(),
        body_md: "PURPOSE\nbody".to_owned(),
        dependency_manifest: DependencyManifest::default(),
        build_id: "build:old".to_owned(),
        cue_bindings: Vec::new(),
        source_refs: Vec::new(),
    };
    let now = OffsetDateTime::now_utc();
    let dirty = UlArtifactDirtyState {
        project_id,
        target_kind: PyramidTargetKind::SubsystemCapsule,
        target_id: capsule.concept_id.clone(),
        build_id: capsule.build_id.clone(),
        dirty: true,
        reasons: vec![UlDirtyReason {
            dependency: dependencies[0].clone(),
            expected_fingerprint: Some("old".to_owned()),
            observed_fingerprint: Some("new".to_owned()),
            event_ref: "tool:test".to_owned(),
        }],
        first_dirty_at: now,
        updated_at: now,
    };
    let rendered = render_capsule_with_dirty(&capsule, std::path::Path::new("."), Some(&dirty));
    assert!(rendered.starts_with("[STALE: changed dependencies: src/a.rs]"));
}
