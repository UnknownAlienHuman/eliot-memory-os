use eliot_engine::TouchedSetRegistry;
use eliot_types::{CueKind, SessionId};
use serde_json::json;

#[test]
fn t04_touched_set_extracts_expected_cues() {
    let registry = TouchedSetRegistry::new();
    let session_id = SessionId::new_v7();
    let observed = registry.observe_arguments(
        session_id,
        "eliot_test",
        &json!({
            "path": r".\Src\Net\Session.rs",
            "symbol": "Net.Session#connect",
            "command": ["cargo", "test", "--workspace"],
            "diagnostic": {
                "rule_id": "E0308",
                "message": "mismatched types at line 42",
                "file": "src/net/session.rs"
            }
        }),
    );

    assert!(
        observed
            .iter()
            .any(|cue| { cue.kind == CueKind::FilePath && cue.value == "src/net/session.rs" })
    );
    assert!(
        observed
            .iter()
            .any(|cue| { cue.kind == CueKind::Symbol && cue.value == "net::session::connect" })
    );
    assert!(
        observed
            .iter()
            .any(|cue| { cue.kind == CueKind::CommandPattern && cue.value == "cargo test" })
    );
    assert!(
        observed
            .iter()
            .any(|cue| { cue.kind == CueKind::ErrorSignature && cue.value.starts_with("sig:") })
    );

    for index in 0..140 {
        registry.observe_arguments(
            session_id,
            "eliot_test",
            &json!({"resource": format!("src/generated/{index}.rs")}),
        );
    }
    let recent = registry.recent_cues(session_id, 256);
    assert_eq!(recent.len(), 128);
    assert_eq!(recent[0].value, "src/generated/139.rs");
    assert!(!recent.iter().any(|cue| cue.value == "src/generated/0.rs"));
}
