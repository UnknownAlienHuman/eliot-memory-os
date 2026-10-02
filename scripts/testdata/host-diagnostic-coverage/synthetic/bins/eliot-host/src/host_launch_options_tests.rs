//! Synthetic Host launch-option tests (issue #985 coverage-validator fixture).
//!
//! Frozen fixture input only: a `#[cfg(test)]` module with no production
//! caller, so its `test_only` exclusion stays evidence-backed.

use super::host_launch_options::reject_installation;

#[test]
fn rejected_installation_is_typed() {
    assert!(reject_installation("").is_err());
}
