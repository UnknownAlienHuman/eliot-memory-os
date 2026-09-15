//! Source-move and allowed-diff guards for the private process/session seam.
//! The behavioral cases execute the production modules as inline native tests.
#![allow(clippy::expect_used)]

use eliot_store_api::sha256_hex;
use serde_json::Value;
use std::path::Path;

fn descriptor() -> Value {
    serde_json::from_str(include_str!("data/provider_session_ownership.json"))
        .expect("ownership fixture")
}

fn source(path: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .expect("current source")
}

fn body_digest(text: &str, name: &str) -> String {
    let start = text.find(&format!("fn {name}")).expect("moved function");
    let text = &text[start..];
    let start = text.find('{').expect("function body");
    let end = text[start..].find("\n}").expect("top-level end") + start + 2;
    sha256_hex(
        text[start..end]
            .split_whitespace()
            .collect::<String>()
            .as_bytes(),
    )
}

// WORK_UNIT_CASE: 986/1
#[test]
fn old_to_new_ownership_map_preserves_checks_and_real_callers() {
    let descriptor = descriptor();
    let moves = descriptor["source_moves"].as_array().expect("source map");
    assert_eq!(moves.len(), 9);
    for item in moves {
        let current = source(item["to"].as_str().expect("destination"));
        assert_eq!(
            body_digest(&current, item["symbol"].as_str().expect("symbol")),
            item["old_body_sha256"].as_str().expect("old body digest"),
            "a moved security/process helper changed"
        );
    }
    let caller = source("src/apply.rs");
    assert!(caller.contains(
        "client::RpcTransport::connect(&adapter.config, &adapter.provider_process_lease)"
    ));
    let facade = source("src/client.rs");
    assert!(facade.contains("ProviderOwner::start(config, Arc::clone(process_lease))"));
    assert!(facade.contains("RpcSession::connect(&provider, deadline)"));
    assert!(facade.contains("self.provider.validate_liveness(config, process_lease)"));
    let owner = source("src/client/provider_owner.rs");
    let checkpoints = [
        "StoreDataRootLease::claim",
        "config.validate_data_root_lease",
        "provider_process_lease\n            .validate",
        "is_eliot_governor_running()",
        "reject_occupied_endpoint(config",
        "spawn_provider(config)",
        "let identity_before_listener = validate_child_process",
    ];
    let mut previous = 0;
    for checkpoint in checkpoints {
        let position = owner.find(checkpoint).expect("retained startup check");
        assert!(position > previous, "startup security sequencing changed");
        previous = position;
    }
    let session = source("src/client/session.rs");
    assert!(session.contains("require_unchanged_identity("));
    assert!(session.contains("owner.validate_owned().await?"));
    assert!(session.contains("authenticate_provider(&session, &owner.config)"));
}

// WORK_UNIT_CASE: 986/16
#[test]
fn source_guard_excludes_unowned_semantic_and_public_raw_api_changes() {
    let descriptor = descriptor();
    let session = source("src/client/session.rs");
    let production = session
        .split("#[cfg(all(test, windows))]")
        .next()
        .expect("production");
    for forbidden in [
        "Command::",
        ".spawn(",
        ".kill(",
        "kill_on_drop",
        "impl Drop",
        "pub fn ",
        "pub async fn ",
    ] {
        assert!(
            !production.contains(forbidden),
            "session gained process/public authority"
        );
    }
    assert!(production.contains("owner: Weak<ProviderOwner>"));
    for forbidden in ["crate::schema", "crate::plan", "crate::apply", "eliot_store_api", "eliot_protocol"] {
        assert!(!production.contains(forbidden), "session gained semantic or lifecycle dependencies");
    }
    assert!(
        production
            .split_whitespace()
            .collect::<String>()
            .contains("self.owner.upgrade().ok_or(AdapterError::ProviderUnavailable)?")
    );
    let lib = source("src/lib.rs");
    assert!(lib.contains("mod client;"));
    assert!(!lib.contains("pub mod client"));
    assert!(lib.contains("provider_process_lease: RetainedProcessPathLease,"));
    assert!(lib.contains("write_lock: tokio::sync::Mutex<()>"));
    assert_eq!(descriptor["denominator"], 16);
}
