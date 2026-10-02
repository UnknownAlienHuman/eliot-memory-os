use eliot_engine::ul::ul_token_estimate;
use eliot_engine::{
    CapsuleEvidence, ConceptSeedResult, GitMiningArtifacts, OnboardingService, PyramidBuilder,
    capsule_freshness, render_capsule,
};
use eliot_types::{
    CapsuleFreshness, CoChangeEdge, ConceptKind, ConceptNode, CueBinding, CueMatchMode,
    CueStrength, HotspotScore, LegacyCueKindV1, ManifestPackage, MiningRun, ProjectId,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn t06_concept_assignment_is_total_and_unique() -> TestResult {
    let root = TempRoot::new("assignment")?;
    write(
        &root.path.join("Cargo.toml"),
        "[workspace]\nmembers=['crates/a','crates/b','crates/c']\n",
    )?;
    let mut manifests = Vec::new();
    for name in ["a", "b", "c"] {
        let boundary = format!("crates/{name}");
        write(
            &root.path.join(&boundary).join("Cargo.toml"),
            &format!("[package]\nname='{name}'\nversion='0.1.0'\n"),
        )?;
        for file in ["src/lib.rs", "src/model.rs", "src/config.rs"] {
            write(
                &root.path.join(&boundary).join(file),
                &format!("//! {name} owns its test subsystem.\npub fn marker() {{}}\n"),
            )?;
        }
        let source_files = [
            format!("{boundary}/Cargo.toml"),
            format!("{boundary}/src/config.rs"),
            format!("{boundary}/src/lib.rs"),
            format!("{boundary}/src/model.rs"),
        ]
        .to_vec();
        manifests.push(ManifestPackage {
            name: name.to_owned(),
            description: Some(format!("{name} package purpose.")),
            manifest_path: format!("{boundary}/Cargo.toml"),
            boundary_path: boundary,
            source_files,
        });
    }
    write(&root.path.join("shared/config.toml"), "mode='shared'\n")?;
    let project_id = ProjectId::new_v7();
    let mining = empty_mining(project_id);
    let seeded = OnboardingService::seed_concepts(&root.path, &mining, &manifests)?;
    let expected = 14;

    assert_eq!(seeded.assignments.len(), expected);
    assert!(seeded.assignments.contains_key("shared/config.toml"));
    assert_eq!(
        seeded
            .assignments
            .keys()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        expected
    );
    assert!(seeded.concepts.len() <= 20);
    assert_total_assignment(&seeded);
    Ok(())
}

#[test]
fn t06_capsule_has_fixed_sections_and_budget() -> TestResult {
    let root = TempRoot::new("capsule")?;
    write(
        &root.path.join("src/lib.rs"),
        "//! Owns deterministic capsule behavior.\npub fn entry() {}\n",
    )?;
    let project_id = ProjectId::new_v7();
    let concept = concept(project_id, "alpha", "src", "file:src/lib.rs#L1-L1");
    let builder = PyramidBuilder;
    let first = builder.build_capsule(&root.path, &concept, &CapsuleEvidence::default(), None)?;
    let second = builder.build_capsule(&root.path, &concept, &CapsuleEvidence::default(), None)?;
    let headers = [
        "PURPOSE",
        "BOUNDARIES",
        "KEY ENTRYPOINTS",
        "INVARIANTS",
        "DRAGONS",
        "KEY DECISIONS",
        "VERIFIERS",
    ];
    let positions = headers
        .iter()
        .map(|header| first.artifact.body_md.find(header).ok_or("header missing"))
        .collect::<Result<Vec<_>, _>>()?;

    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
    // #783: the limit is now counted in canonical source token units, so the
    // old `/4` number no longer describes the same envelope. The contract this
    // assertion protects is a BYTE envelope, not a unit count, and the retired
    // `ceil(bytes / 4) <= 500` admitted exactly `4 * 500 - 3 == 1997` bytes.
    // Restating that same envelope in canonical units gives
    // `ceil(1997 / 3) == 666`, and 666 admits `3 * 666 == 1998` bytes, so the
    // one-byte slack the old form also had is preserved rather than tightened
    // or invented. The literal was re-derived, not relaxed.
    const CAPSULE_BODY_MAX_UNITS: u32 = 666;
    // The re-derived literal is only correct if it admits the byte envelope
    // the retired `/4` form admitted, so that is measured rather than assumed:
    // 1_997 bytes is the retired maximum and must fit, 1_999 must not, and the
    // 1_998 the canonical form also admits is the one-byte slack the old form
    // carried. Nothing wider is admitted.
    let retired_max = ul_token_estimate(&"x".repeat(4 * 500 - 3))?;
    let retired_max_plus_one = ul_token_estimate(&"x".repeat(4 * 500 - 2))?;
    let first_units = ul_token_estimate(&first.artifact.body_md)?;
    assert!(first_units <= CAPSULE_BODY_MAX_UNITS);
    assert!(retired_max <= CAPSULE_BODY_MAX_UNITS);
    assert!(retired_max_plus_one > CAPSULE_BODY_MAX_UNITS);
    assert_eq!(first, second);
    assert_eq!(
        first.artifact.dependency_manifest.file_deps[0].path,
        "src/lib.rs"
    );
    Ok(())
}

#[test]
fn t06_charter_and_map_are_bounded() -> TestResult {
    let root = TempRoot::new("charter-map")?;
    write(
        &root.path.join("README.md"),
        "# Fixture\nA governed fixture workspace for pyramid tests.\n\n## Non-goals\n- network deployment\n",
    )?;
    write(&root.path.join("a/lib.rs"), "pub fn a() {}\n")?;
    write(&root.path.join("b/lib.rs"), "pub fn b() {}\n")?;
    let project_id = ProjectId::new_v7();
    let concepts = vec![
        concept(project_id, "alpha", "a", "file:a/lib.rs#L1-L1"),
        concept(project_id, "beta", "b", "file:b/lib.rs#L1-L1"),
    ];
    let edges = vec![CoChangeEdge {
        edge_id: "edge-ab".to_owned(),
        project_id,
        path_a: "a/lib.rs".to_owned(),
        path_b: "b/lib.rs".to_owned(),
        support: 4,
        confidence_ab: 0.8,
        confidence_ba: 0.75,
        last_cochange_at_unix: 1,
        static_edge_exists: Some(true),
        mining_run_ref: "run".to_owned(),
        cue_bindings: Vec::new(),
    }];
    let builder = PyramidBuilder;
    let map = builder.build_system_map(project_id, &root.path, &concepts, &edges, None)?;
    let charter = builder.build_charter(
        project_id,
        &root.path,
        &concepts,
        &["invariant:verified".to_owned()],
        None,
    )?;
    let map_again = builder.build_system_map(project_id, &root.path, &concepts, &edges, None)?;
    let charter_again = builder.build_charter(
        project_id,
        &root.path,
        &concepts,
        &["invariant:verified".to_owned()],
        None,
    )?;

    // #783: the same re-derivation applies to the map and charter limits. The
    // retired `ceil(bytes / 4) <= 600` admitted exactly `4 * 600 - 3 == 2397`
    // bytes and `ceil(bytes / 4) <= 200` admitted exactly `797` bytes; the
    // canonical forms are `ceil(2397 / 3) == 799` (admitting `2397` bytes, so
    // that envelope is exact) and `ceil(797 / 3) == 266` (admitting `798` bytes,
    // keeping the one-byte slack the old form also had). Neither is widened or
    // tightened beyond what `/4` already admitted.
    const MAP_BODY_MAX_UNITS: u32 = 799;
    const CHARTER_BODY_MAX_UNITS: u32 = 266;
    // Measured, not assumed, exactly as the capsule assertion above: 2_397 is
    // the retired map maximum and must fit while 2_398 must not, and 797 is
    // the retired charter maximum while 799 must not be admitted.
    let retired_map_max = ul_token_estimate(&"x".repeat(4 * 600 - 3))?;
    let retired_map_max_plus_one = ul_token_estimate(&"x".repeat(4 * 600 - 2))?;
    let retired_charter_max = ul_token_estimate(&"x".repeat(4 * 200 - 3))?;
    let retired_charter_max_plus_two = ul_token_estimate(&"x".repeat(4 * 200 - 1))?;
    let map_units = ul_token_estimate(&map.artifact.body_md)?;
    let charter_units = ul_token_estimate(&charter.artifact.body_md)?;
    assert!(map_units <= MAP_BODY_MAX_UNITS);
    assert!(charter_units <= CHARTER_BODY_MAX_UNITS);
    assert!(retired_map_max <= MAP_BODY_MAX_UNITS);
    assert!(retired_map_max_plus_one > MAP_BODY_MAX_UNITS);
    assert!(retired_charter_max <= CHARTER_BODY_MAX_UNITS);
    assert!(retired_charter_max_plus_two > CHARTER_BODY_MAX_UNITS);
    assert_eq!(map, map_again);
    assert_eq!(charter, charter_again);
    assert!(map.artifact.body_md.starts_with("SYSTEMS\n"));
    assert!(charter.artifact.body_md.starts_with("WHAT\n"));
    Ok(())
}

#[test]
fn t06_stale_capsule_is_visibly_stale() -> TestResult {
    let root = TempRoot::new("stale")?;
    write(&root.path.join("src/lib.rs"), "pub fn before() {}\n")?;
    let project_id = ProjectId::new_v7();
    let concept = concept(project_id, "stale", "src", "file:src/lib.rs#L1-L1");
    let capsule = PyramidBuilder
        .build_capsule(&root.path, &concept, &CapsuleEvidence::default(), None)?
        .artifact;
    let truth_before = capsule.clone();
    write(&root.path.join("src/lib.rs"), "pub fn after() {}\n")?;
    let rendered = render_capsule(&capsule, &root.path);

    assert_eq!(
        capsule_freshness(&capsule, &root.path),
        CapsuleFreshness::Stale {
            changed: vec!["src/lib.rs".to_owned()],
            missing: Vec::new(),
        }
    );
    assert!(rendered.starts_with(
        "[STALE: changed dependencies: src/lib.rs] — verify against code before relying.\n"
    ));
    assert_eq!(capsule, truth_before);
    Ok(())
}

fn empty_mining(project_id: ProjectId) -> GitMiningArtifacts {
    GitMiningArtifacts {
        run: MiningRun {
            run_id: "run".to_owned(),
            project_id,
            head_commit: "head".to_owned(),
            config_hash: "config".to_owned(),
            commits_scanned: 0,
            baskets_used: 0,
            edges_written: 0,
            classifier_version: "test".to_owned(),
            cue_bindings: Vec::new(),
        },
        edges: Vec::new(),
        hotspots: Vec::<HotspotScore>::new(),
    }
}

fn concept(project_id: ProjectId, name: &str, boundary: &str, source_ref: &str) -> ConceptNode {
    ConceptNode {
        concept_id: format!("concept-{name}"),
        project_id,
        name: name.to_owned(),
        kind: ConceptKind::Subsystem,
        purpose: format!("Owns {name} behavior."),
        boundary_paths: vec![boundary.to_owned()],
        invariant_refs: Vec::new(),
        hotspot_refs: Vec::new(),
        entrypoint_refs: vec![
            source_ref
                .split('#')
                .next()
                .unwrap_or(source_ref)
                .to_owned(),
        ],
        parent_concept_id: None,
        cue_bindings: vec![CueBinding {
            cue_kind: LegacyCueKindV1::Subsystem,
            cue_value: name.to_owned(),
            match_mode: CueMatchMode::Exact,
            strength: CueStrength::Primary,
            expected_reuse_note: Some(
                "when working in this subsystem or its boundary paths".to_owned(),
            ),
        }],
        source_refs: vec![source_ref.to_owned()],
    }
}

fn assert_total_assignment(seed: &ConceptSeedResult) {
    let concept_ids = seed
        .concepts
        .iter()
        .map(|concept| concept.concept_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        seed.assignments
            .values()
            .all(|concept_id| concept_ids.contains(concept_id.as_str()))
    );
}

fn write(path: &Path, body: &str) -> TestResult {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, body)?;
    Ok(())
}

struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new(name: &str) -> TestResult<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "eliot-ul-t06-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        if self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("eliot-ul-t06-"))
            && self.path.starts_with(std::env::temp_dir())
        {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
