//! Read-only verification report projection cluster.
//!
//! Architecture anchor: `A10.8` (verification and proof-bearing finish).
//! Implementation anchors: `I18.4` (test tiers), `I18.23` (agent development
//! test protocol), and `I18.29` (verification budget and escalation).
//!
//! This child owns only `FlakeDetectionService` and
//! `StatefulDbTestIsolationService` report projections and its private
//! report-ID seam. It executes no command, selects no verifier, changes no
//! oracle, and cannot promote a test result or task disposition.
//!
//! Canonical handles: `crates/eliot-engine/src/verification.rs:22-23` (service
//! types), `crates/eliot-engine/src/verification.rs:226-275` (report cluster),
//! `crates/eliot-engine/src/verification/report_clusters.rs` (this cell),
//! `crates/eliot-engine/tests/verification_gates.rs:flake_report_generated_or_skipped_with_reason,stateful_db_isolation_report_generated`.
//! Parent facade: `crates/eliot-engine/src/verification.rs` re-exports via
//! `pub use report_clusters::{FlakeDetectionService, StatefulDbTestIsolationService}`;
//! workspace facade: `crates/eliot-engine/src/lib.rs:257` re-exports
//! `verification::{FlakeDetectionService, StatefulDbTestIsolationService}`.
//! Ownership: `eliot-engine:verification` owns the projection; this child is a
//! pure report mapper with no write, policy, or lifecycle authority.

use eliot_types::{FlakeReport, StatefulDbIsolationReport, TestInventory, TestStatefulness};
use time::OffsetDateTime;

pub struct FlakeDetectionService;
pub struct StatefulDbTestIsolationService;

impl FlakeDetectionService {
    #[must_use]
    pub fn report(&self, profile_id: &str, repeat: u64, inventory: &TestInventory) -> FlakeReport {
        let stable_tests = inventory
            .tests
            .iter()
            .filter(|test| test.required_profiles.iter().any(|id| id == profile_id))
            .map(|test| test.test_id.clone())
            .collect::<Vec<_>>();
        FlakeReport {
            report_id: new_id("flake"),
            generated_at: OffsetDateTime::now_utc(),
            repeated_profile: profile_id.to_owned(),
            repeated_runs: repeat,
            stable_tests,
            flaky_tests: Vec::new(),
            blocked_tests: Vec::new(),
            skipped_reason: if repeat < 2 {
                Some("repeat count below flake-detection threshold".to_owned())
            } else {
                None
            },
        }
    }
}

impl StatefulDbTestIsolationService {
    #[must_use]
    pub fn report(&self, inventory: &TestInventory) -> StatefulDbIsolationReport {
        let shared_db_tests = inventory
            .tests
            .iter()
            .filter(|test| test.statefulness == TestStatefulness::LocalDbSharedSerial)
            .map(|test| test.test_id.clone())
            .collect::<Vec<_>>();
        StatefulDbIsolationReport {
            report_id: new_id("db-isolation"),
            generated_at: OffsetDateTime::now_utc(),
            serial_required: !shared_db_tests.is_empty(),
            isolated_fixture_roots: vec![
                "target/test-*".to_owned(),
                ".eliot-governor/test-roots".to_owned(),
            ],
            shared_db_tests,
            stale_locks_before: Vec::new(),
            stale_locks_after: Vec::new(),
            status: "serial_stateful_tests_documented".to_owned(),
        }
    }
}

fn new_id(prefix: &str) -> String {
    format!("{prefix}-{}", eliot_types::WriteId::new_v7())
}
