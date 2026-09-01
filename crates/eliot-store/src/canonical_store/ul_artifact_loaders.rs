//! Canonical UL artifact/dependency loader cell.
//!
//! Owns the read-only `CanonicalStore` loaders extracted from
//! `crates/eliot-store/src/canonical_store.rs` lines 3384-3549 contiguous
//! cluster: `load_ul_artifacts`, `load_ul_dirty_artifacts`,
//! `load_ul_reverse_dependents` with pooled paging/order/filters via
//! `NamedSurqlOp::LoadUlArtifacts` (`crates/eliot-store/src/surql/load_ul_artifacts.surql`),
//! `NamedSurqlOp::LoadUlArtifactDirty`
//! (`crates/eliot-store/src/surql/load_ul_artifact_dirty.surql`), and
//! `NamedSurqlOp::LoadUlReverseDependents`
//! (`crates/eliot-store/src/surql/load_ul_reverse_dependents.surql`). Preserves
//! exact SQL names, paging (`page_size` clamp `1..=UL_ARTIFACT_PAGE_SIZE`,
//! `start = records.len()`, `limit = page_size`, artifact safety bound
//! `MAX_CURRENT_UL_ARTIFACTS`; dirty `limit` clamp `1..=512`), filters
//! (`project_id`, `receipt_kinds` / `dependency_kinds`+`dependency_keys`),
//! order (`load_ul_reverse_dependents` sorts by `target_kind`→`target_id`→
//! `dependency`, deduped; `load_ul_artifacts` appends pages until `< page_size`),
//! and error behavior (decode errors, `MAX_CURRENT_UL_ARTIFACTS` bound, empty-
//! dependency early-return).
//!
//! Architecture: P.6 canonical Store — UL artifact/dependency read boundary;
//! parent `canonical_store` retains the store, receipt, and transport boundary.
//! Implementation: I2.23 — extracted loader module owns only its read-only
//! cell; parent remains sole write/receipt authority. Mechanical split from
//! `crates/eliot-store/src/canonical_store.rs` — behavior preserved, public
//! facade unchanged (`CanonicalStore::load_ul_*` via parent `impl`).
//! Ownership: `canonical_store` facade/caller retains API; child
//! `canonical_store::ul_artifact_loaders` is internal loader cell, no widened
//! visibility or new dependencies.
//! Forbidden: read-only UL loaders only — no `load_ul_activation_graph`, no
//! writes/resets/replaces (`replace_ul_reverse_dependencies`,
//! `reset_ul_reverse_dependency_project`, `mark_ul_artifact_dirty`,
//! `clear_ul_artifact_dirty`, `reset_ul_artifact_dirty_project`), no
//! task-class/metrics/readiness/experiment loaders, no integrated activation/
//! cognitive/observation/meta-integrity cells.

use std::collections::BTreeSet;

use serde::de::DeserializeOwned;
use serde_json::json;

use super::CanonicalStore;
use super::decode_value;
use crate::{CanonicalRecord, NamedSurqlOp, StoreError};
use eliot_types::ProjectId;

impl CanonicalStore {
    pub async fn load_ul_artifacts<T>(
        &self,
        project_id: ProjectId,
        receipt_kinds: &[&str],
        page_size: u16,
    ) -> Result<Vec<CanonicalRecord<T>>, StoreError>
    where
        T: DeserializeOwned,
    {
        let page_size = page_size.clamp(1, crate::UL_ARTIFACT_PAGE_SIZE);
        let mut records = Vec::new();
        loop {
            let value = self
                .execute_value(
                    NamedSurqlOp::LoadUlArtifacts,
                    json!({
                        "project_id": project_id,
                        "receipt_kinds": receipt_kinds,
                        "start": records.len(),
                        "limit": page_size,
                    }),
                )
                .await?;
            let page: Vec<CanonicalRecord<T>> = decode_value(NamedSurqlOp::LoadUlArtifacts, value)?;
            if records.len().saturating_add(page.len()) > crate::MAX_CURRENT_UL_ARTIFACTS {
                return Err(StoreError::Decode(format!(
                    "current UL projection exceeds the explicit {}-artifact safety bound",
                    crate::MAX_CURRENT_UL_ARTIFACTS
                )));
            }
            let complete = page.len() < usize::from(page_size);
            records.extend(page);
            if complete {
                return Ok(records);
            }
        }
    }

    pub async fn load_ul_reverse_dependents(
        &self,
        project_id: ProjectId,
        dependencies: &[eliot_types::UlDependencyRef],
    ) -> Result<Vec<eliot_types::UlReverseDependencyRow>, StoreError> {
        let expected = dependencies.iter().cloned().collect::<BTreeSet<_>>();
        if expected.is_empty() {
            return Ok(Vec::new());
        }
        let dependency_kinds = expected
            .iter()
            .map(|dependency| dependency.kind)
            .collect::<BTreeSet<_>>();
        let dependency_keys = expected
            .iter()
            .map(|dependency| dependency.key.clone())
            .collect::<BTreeSet<_>>();
        let value = self
            .execute_value(
                NamedSurqlOp::LoadUlReverseDependents,
                json!({
                    "project_id": project_id,
                    "dependency_kinds": dependency_kinds,
                    "dependency_keys": dependency_keys,
                }),
            )
            .await?;
        let mut rows: Vec<eliot_types::UlReverseDependencyRow> =
            decode_value(NamedSurqlOp::LoadUlReverseDependents, value)?;
        rows.retain(|row| expected.contains(&row.dependency));
        rows.sort_by(|left, right| {
            left.target_kind
                .cmp(&right.target_kind)
                .then_with(|| left.target_id.cmp(&right.target_id))
                .then_with(|| left.dependency.cmp(&right.dependency))
        });
        rows.dedup();
        Ok(rows)
    }

    pub async fn load_ul_dirty_artifacts(
        &self,
        project_id: ProjectId,
        limit: u16,
    ) -> Result<Vec<eliot_types::UlArtifactDirtyState>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::LoadUlArtifactDirty,
                json!({ "project_id": project_id, "limit": limit.clamp(1, 512) }),
            )
            .await?;
        decode_value(NamedSurqlOp::LoadUlArtifactDirty, value)
    }
}
