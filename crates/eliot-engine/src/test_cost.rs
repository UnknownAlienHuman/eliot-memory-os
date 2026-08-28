//! Read-only test-cost report projection.
//!
//! Architecture anchor: `A10.8` (verification and proof-bearing finish).
//! Implementation anchors: `I18.4` (test tiers), `I18.23` (agent development
//! test protocol), and `I18.29` (verification budget and escalation).
//!
//! This child owns only `TestCostService` aggregation and its private report-ID
//! seam. It executes no command, selects no verifier, changes no oracle, and
//! cannot promote a test result or task disposition.

use eliot_types::verification::VerificationRun;
use eliot_types::{
    TestCostReport, TestCountByCost, TestCountByIntent, TestCountByKind, TestInventory,
    TestMetadata,
};
use std::collections::BTreeMap;
use time::OffsetDateTime;

pub struct TestCostService;

impl TestCostService {
    #[must_use]
    pub fn report(
        &self,
        inventory: &TestInventory,
        last_run: Option<&VerificationRun>,
    ) -> TestCostReport {
        TestCostReport {
            report_id: new_id("test-cost"),
            generated_at: OffsetDateTime::now_utc(),
            total_tests: inventory.test_count,
            by_kind: Self::count_by_kind(&inventory.tests),
            by_intent: Self::count_by_intent(&inventory.tests),
            by_cost: Self::count_by_cost(&inventory.tests),
            slowest_commands: last_run
                .map(|run| {
                    let mut results = run.command_results.clone();
                    results.sort_by_key(|result| std::cmp::Reverse(result.duration_ms));
                    results.truncate(5);
                    results
                })
                .unwrap_or_default(),
            recommendations: vec![
                "use dev-fast for local edit feedback only".to_owned(),
                "use change-gate or full before DONE_VERIFIED".to_owned(),
                "keep stateful DB safety tests serial".to_owned(),
            ],
        }
    }

    fn count_by_kind(tests: &[TestMetadata]) -> Vec<TestCountByKind> {
        let mut counts = BTreeMap::new();
        for test in tests {
            *counts.entry(test.test_kind).or_insert(0) += 1;
        }
        counts
            .into_iter()
            .map(|(key, count)| TestCountByKind { key, count })
            .collect()
    }

    fn count_by_intent(tests: &[TestMetadata]) -> Vec<TestCountByIntent> {
        let mut counts = BTreeMap::new();
        for test in tests {
            *counts.entry(test.intent).or_insert(0) += 1;
        }
        counts
            .into_iter()
            .map(|(key, count)| TestCountByIntent { key, count })
            .collect()
    }

    fn count_by_cost(tests: &[TestMetadata]) -> Vec<TestCountByCost> {
        let mut counts = BTreeMap::new();
        for test in tests {
            *counts.entry(test.estimated_cost).or_insert(0) += 1;
        }
        counts
            .into_iter()
            .map(|(key, count)| TestCountByCost { key, count })
            .collect()
    }
}

fn new_id(prefix: &str) -> String {
    format!("{prefix}-{}", eliot_types::WriteId::new_v7())
}
