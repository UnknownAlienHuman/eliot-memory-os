//! Bounded Rust test source fixture for ignored test inventory.

#[test]
#[ignore = "requires local authenticated SurrealDB store"]
fn test_sync_ignored() {
    assert!(true);
}

#[tokio::test]
#[ignore = "requires kernel and governor runtime host"]
async fn test_tokio_ignored() {
    assert!(true);
}

#[disabled_test = "requires local surrealdb and windows runtime pipe"]
fn test_disabled_ignored() {
    assert!(true);
}

#[test]
#[cfg_attr(windows, ignore = "requires windows runtime named pipe")]
fn test_cfg_attr_ignored() {
    assert!(true);
}

#[test]
#[ignore]
fn test_bare_ignored() {
    assert!(true);
}

#[test]
#[ignore = "flaky test without environment reason"]
fn test_unknown_reason_ignored() {
    assert!(true);
}

mod nested {
    #[test]
    #[ignore = "requires git repository worktree"]
    fn test_nested_ignored() {
        assert!(true);
    }
}

// Comments that must NOT be parsed as ignored tests:
// #[test]
// #[ignore = "commented out ignored test"]
// fn test_in_comment() {}

/*
#[test]
#[ignore = "block commented ignored test"]
fn test_in_block_comment() {}
*/

fn helper_function() {
    let _fake = "#[test]\n#[ignore = \"inside string\"]\nfn fake_test() {}";
}
