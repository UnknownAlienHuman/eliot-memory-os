//! Bounded operational metric-definition registry.
//!
//! Architecture anchors: `A13.10` (observability and Diagnostic Brief) and
//! `ARCH-OBS-01` (logs, metrics, audit, and reports remain distinct).
//! Implementation anchors: `I16.1` (four observability surfaces), `I16.5`
//! (metric groups), and `I16.9` (retention and telemetry cost).
//!
//! This child owns only builtin definition lookup and label-policy validation.
//! It records no samples, grants no authority, and cannot turn metrics into
//! durable audit evidence or canonical transition receipts.

use crate::EngineError;
use eliot_types::MetricDefinition;

pub struct MetricRegistryService;

impl MetricRegistryService {
    #[must_use]
    pub fn definitions(&self) -> Vec<MetricDefinition> {
        super::builtin_metric_definitions()
    }

    pub fn validate_definition(&self, definition: &MetricDefinition) -> Result<(), EngineError> {
        for label in &definition.labels {
            if label.secret_risk {
                return Err(super::rejected(
                    "metric-registry",
                    &format!("secret-risk metric label rejected: {}", label.name),
                ));
            }
            if label.high_cardinality {
                return Err(super::rejected(
                    "metric-registry",
                    &format!("high-cardinality metric label rejected: {}", label.name),
                ));
            }
        }
        Ok(())
    }

    pub fn find(&self, metric_id: &str) -> Result<MetricDefinition, EngineError> {
        self.definitions()
            .into_iter()
            .find(|definition| definition.metric_id == metric_id)
            .ok_or_else(|| {
                super::rejected("metric-registry", &format!("unknown metric: {metric_id}"))
            })
    }

    #[must_use]
    pub fn categories(&self) -> Vec<String> {
        self.definitions()
            .into_iter()
            .map(|definition| definition.component)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}
