//! Canonical meta-integrity aggregation cell — internal durable-audit aggregation model.
//!
//! Owns the passive `MetaIntegrityRecords` durable-audit aggregation extracted from
//! `crates/eliot-store/src/canonical_store/replay_view.rs` (`MetaIntegrityRecords`
//! with `metrics`, `isolation_rejections`, `policy_candidates`, `policy_executions`).
//! This is an internal durable-audit aggregation model, not canonical truth or write
//! authority: it aggregates derived `CanonicalRecord` projections for `meta_metric_evidence`,
//! `meta_isolation_rejection`, `experimental_policy_candidate` and `meta_policy_execution`
//! receipts. Derived audit aggregates are rebuildable report projections and must not confer
//! canonical write authority or lifecycle/topology ownership.
//!
//! Architecture A13.2 (Kernel and failure domains): minimal live Kernel preserves canonical
//! history, fencing, health and recovery entrypoint and does not depend on model/Dreamer/graph/
//! provider/UI; this cell owns no canonical state, authority, or write path.
//! Implementation I16.1 (Four surfaces): operational logs, metrics, durable audit, and reports —
//! reports are Human/agent projections generated from canonical state ("prose not truth"); this
//! cell is the I16.1 durable-audit/report surface handle for meta-integrity aggregates.
//! Reports/projections are not truth/authority; they are derived, rebuildable, and must not
//! confer canonical write authority.
//!
//! Mechanical extraction preserves exact fields, private/seam visibility (caller-visible via
//! `pub(super)`), imports and `serde` shape, and `CanonicalStore` facade via
//! `crate::canonical_store::replay_view`. No semantic redesign and no canonical
//! write-authority change. Excludes provider/handshake/migration/atomic-write,
//! capacity/L2/recall, and Dreamer/Luna/frozen/integrated scope.
//! Forbidden: durable-audit aggregation only — no `CanonicalStore` ownership, no migration,
//! `execute_value`/`decode` core, provider/handshake, `SeaWall`/`BlobStore` bridge, or
//! Dreamer/Luna/frozen write semantics — no new dependencies or broad re-exports.

use crate::CanonicalRecord;
use eliot_types::{
    CanonicalMetaMetricEvidence, ExperimentalMetaPolicyCandidate, MetaIsolationRejectionRecord,
    MetaPolicyExecutionReceipt,
};

pub(super) struct MetaIntegrityRecords {
    pub(super) metrics: Vec<CanonicalRecord<CanonicalMetaMetricEvidence>>,
    pub(super) isolation_rejections: Vec<CanonicalRecord<MetaIsolationRejectionRecord>>,
    pub(super) policy_candidates: Vec<CanonicalRecord<ExperimentalMetaPolicyCandidate>>,
    pub(super) policy_executions: Vec<CanonicalRecord<MetaPolicyExecutionReceipt>>,
}
