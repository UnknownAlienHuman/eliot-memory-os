use eliot_engine::ModuleCardService;
use eliot_types::{CoChangeEdge, HotspotScore, ProjectId, ul_token_estimate};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn t05_module_card_is_deterministic_and_bounded() -> TestResult {
    let project_id = ProjectId::new_v7();
    let root = temp_root()?;
    let path = "crates/demo/src/lib.rs";
    let source = root.join(path);
    fs::create_dir_all(source.parent().ok_or("source parent missing")?)?;
    fs::write(
        &source,
        "//! Deterministic demo storage boundary. Additional detail.\n\npub fn demo() {}\n",
    )?;
    let hotspot = HotspotScore {
        hotspot_id: "hotspot-demo".to_owned(),
        project_id,
        path: path.to_owned(),
        touches: 12,
        fix_touches: 6,
        churn_decayed: 9.5,
        bugfix_density: 0.5,
        failure_density: 1,
        score: 91,
        mining_run_ref: "run-demo".to_owned(),
        cue_bindings: Vec::new(),
    };
    let edge = CoChangeEdge {
        edge_id: "edge-demo".to_owned(),
        project_id,
        path_a: path.to_owned(),
        path_b: "crates/demo/src/peer.rs".to_owned(),
        support: 8,
        confidence_ab: 0.8,
        confidence_ba: 1.0,
        last_cochange_at_unix: 1_760_000_000,
        static_edge_exists: None,
        mining_run_ref: "run-demo".to_owned(),
        cue_bindings: Vec::new(),
    };
    let failures = BTreeMap::from([(path.to_owned(), vec!["failure:demo-regression".to_owned()])]);
    let first = ModuleCardService::build(
        project_id,
        &root,
        std::slice::from_ref(&hotspot),
        std::slice::from_ref(&edge),
        &failures,
        &BTreeMap::new(),
    )?;
    let second = ModuleCardService::build(
        project_id,
        &root,
        &[hotspot],
        &[edge],
        &failures,
        &BTreeMap::new(),
    )?;
    let first_card = first.first().ok_or("module card missing")?;

    assert_eq!(serde_json::to_vec(&first)?, serde_json::to_vec(&second)?);
    assert_eq!(first_card.body_md, second[0].body_md);
    assert!(ul_token_estimate(&first_card.body_md) <= 200);
    assert_eq!(first_card.verifier, "cargo test -p demo");
    let sections = [
        "PURPOSE:",
        "HOTSPOT:",
        "HIDDEN COUPLING:",
        "KNOWN FAILURES:",
        "VERIFY:",
    ];
    let positions = sections
        .iter()
        .map(|section| first_card.body_md.find(section).ok_or(*section))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(positions.windows(2).all(|window| window[0] < window[1]));
    assert!(
        first_card
            .source_refs
            .contains(&format!("file:{path}:module-doc"))
    );

    if root
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("eliot-ul-t05-cards-"))
        && root.starts_with(std::env::temp_dir())
    {
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

fn temp_root() -> TestResult<PathBuf> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root =
        std::env::temp_dir().join(format!("eliot-ul-t05-cards-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&root)?;
    Ok(root)
}
