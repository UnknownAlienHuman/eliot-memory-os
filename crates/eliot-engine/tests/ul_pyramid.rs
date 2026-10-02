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
    // assertion protects is a BYTE envelope, not a unit count. The retired gate
    // `ceil(bytes / 4) <= 500` admitted `b` exactly when `b <= 4 * 500 == 2_000`
    // bytes, NOT `b <= 1_997`: a 1_999-byte body gives `ceil(1_999 / 4) == 500
    // <= 500` and was admitted, as was 2_000. Restating `b <= 2_000` under the
    // canonical `ceil(b / 3)` needs `ceil(2_000 / 3) == 667`, and 667 admits
    // `3 * 667 == 2_001` bytes, so the retired 2_000-byte range is restored in
    // full and the envelope is one byte wider only because the `/4` ratio
    // could not express it. The literal is the minimal `ceil(4B / 3)`, so it is
    // re-derived, not relaxed.
    const CAPSULE_BODY_MAX_UNITS: u32 = 667;
    // The re-derived literal is only correct if it admits the byte envelope
    // the retired `/4` form admitted, so that is measured rather than assumed.
    // The discriminator is `4 * 500 - 1 == 1_999` bytes, the largest length
    // below the retired maximum: it estimates to `ceil(1_999 / 3) == 667`, so
    // it sits exactly on the boundary and could not have fit the pre-fix 666.
    // The retired maximum 2_000 and the first length the new constant rejects,
    // 2_002, bound the envelope from both sides.
    let retired_below_max = ul_token_estimate(&"x".repeat(4 * 500 - 1))?;
    let retired_max = ul_token_estimate(&"x".repeat(4 * 500))?;
    let first_units = ul_token_estimate(&first.artifact.body_md)?;
    assert!(first_units <= CAPSULE_BODY_MAX_UNITS);
    assert_eq!(
        retired_below_max, CAPSULE_BODY_MAX_UNITS,
        "4 * 500 - 1 bytes was admitted by the retired gate and must still fit"
    );
    assert!(retired_max <= CAPSULE_BODY_MAX_UNITS);
    assert!(
        ul_token_estimate(&"x".repeat(4 * 500 + 2))? > CAPSULE_BODY_MAX_UNITS,
        "the envelope must not be widened past the retired 2_000-byte maximum"
    );
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

    // #783: the same re-derivation applies to the map and charter limits, and
    // from the same true equivalence `ceil(b / 4) <= B  <=>  b <= 4B` rather
    // than `4B - 3`. The retired map gate `ceil(bytes / 4) <= 600` admitted
    // every `b <= 2_400` bytes and the retired charter gate
    // `ceil(bytes / 4) <= 200` admitted every `b <= 800` bytes. Restated
    // under the canonical `ceil(b / 3)` the minimal literals are
    // `ceil(2_400 / 3) == 800` and `ceil(800 / 3) == 267`. 800 admits
    // `3 * 800 == 2_400` bytes, exactly the retired map range, and 267 admits
    // `3 * 267 == 801` bytes, the retired charter range plus the one byte the
    // `/4` ratio could not express. Neither is widened or tightened beyond
    // what `/4` already admitted.
    const MAP_BODY_MAX_UNITS: u32 = 800;
    const CHARTER_BODY_MAX_UNITS: u32 = 267;
    // Measured, not assumed, exactly as the capsule assertion above. The
    // discriminators are `4 * 600 - 1 == 2_399` and `4 * 200 - 1 == 799`
    // bytes: the retired gates admitted both, and each estimates to exactly
    // its constant (800 and 267), so neither could have passed before the
    // fix. The retired maxima and the first rejected lengths bound the rest.
    let retired_map_below_max = ul_token_estimate(&"x".repeat(4 * 600 - 1))?;
    let retired_charter_below_max = ul_token_estimate(&"x".repeat(4 * 200 - 1))?;
    let map_units = ul_token_estimate(&map.artifact.body_md)?;
    let charter_units = ul_token_estimate(&charter.artifact.body_md)?;
    assert!(map_units <= MAP_BODY_MAX_UNITS);
    assert!(charter_units <= CHARTER_BODY_MAX_UNITS);
    assert_eq!(
        retired_map_below_max, MAP_BODY_MAX_UNITS,
        "4 * 600 - 1 bytes was admitted by the retired map gate and must still fit"
    );
    assert_eq!(
        retired_charter_below_max, CHARTER_BODY_MAX_UNITS,
        "4 * 200 - 1 bytes was admitted by the retired charter gate and must still fit"
    );
    assert!(ul_token_estimate(&"x".repeat(4 * 600))? <= MAP_BODY_MAX_UNITS);
    assert!(ul_token_estimate(&"x".repeat(4 * 200))? <= CHARTER_BODY_MAX_UNITS);
    assert!(
        ul_token_estimate(&"x".repeat(4 * 600 + 1))? > MAP_BODY_MAX_UNITS,
        "the map envelope must not be widened past the retired 2_400-byte maximum"
    );
    assert!(
        ul_token_estimate(&"x".repeat(4 * 200 + 2))? > CHARTER_BODY_MAX_UNITS,
        "the charter envelope must not be widened past the retired 800-byte maximum"
    );
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
