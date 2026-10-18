use super::{ActivationEngine, CueIndexService, TouchedSetRegistry, capsule_freshness};
use crate::{EngineError, WriterHandle};
use eliot_store::CanonicalStore;
use eliot_types::{
    ActivationTrace, CapsuleFreshness, ConceptNode, CueRecordSource, InjectionReceipt,
    LegacyCueKindV1, OBSERVABILITY_SCHEMA_VERSION, ObservabilityKind, ObservabilityWriteEnvelope,
    ObservabilityWriteReceipt, ObservabilityWriteStatus, ObservedCue, PendingInjectionItem,
    ProjectCharter, ProjectId, SessionId, SubsystemCapsule, SystemMap, TaskId, UlFiredBlock,
    UlFiredItem, UlInjectionMode, WriteId, ul_token_estimate,
};
use serde_json::{Value, json};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const MAX_ITEMS: usize = 3;
const MAX_TOTAL_UNITS: u32 = 400;
const MAX_PAYLOAD_UNITS: u32 = 300;
const MAX_LINE_BYTES: usize = 160;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingReceiptState {
    RetryablePreEnqueue,
    OutcomeUnknown,
    Conflict,
}

impl PendingReceiptState {
    const fn rank(self) -> u8 {
        match self {
            Self::RetryablePreEnqueue => 0,
            Self::OutcomeUnknown => 1,
            Self::Conflict => 2,
        }
    }
}

#[derive(Clone, Debug)]
struct PendingReceiptAttempt {
    item: PendingInjectionItem,
    rendered: UlFiredItem,
    receipt: InjectionReceipt,
    envelope: ObservabilityWriteEnvelope,
    state: PendingReceiptState,
}

impl PendingReceiptAttempt {
    fn matches_item(&self, item: &PendingInjectionItem) -> bool {
        self.item.item_ref == item.item_ref
            && self.item.source_fingerprint == item.source_fingerprint
    }
}

#[derive(Default)]
struct PendingBatch {
    items: Vec<PendingInjectionItem>,
    attempts: Vec<PendingReceiptAttempt>,
    overflow: usize,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ProjectSessionKey {
    project_id: ProjectId,
    session_id: SessionId,
}

enum ReceiptAttemptResult {
    Confirmed,
    RetryablePreEnqueue,
    OutcomeUnknown,
    Conflict,
}

pub struct InjectionPlanner {
    cue_index: Arc<CueIndexService>,
    store: CanonicalStore,
    writer: WriterHandle,
    activation: ActivationEngine,
    touched: Arc<TouchedSetRegistry>,
    pending: Mutex<HashMap<ProjectSessionKey, PendingBatch>>,
    hydrated: Mutex<HashSet<(ProjectId, SessionId)>>,
    project_root: PathBuf,
}

impl InjectionPlanner {
    #[must_use]
    pub fn new(
        cue_index: Arc<CueIndexService>,
        store: CanonicalStore,
        writer: WriterHandle,
        touched: Arc<TouchedSetRegistry>,
    ) -> Self {
        Self::with_project_root(
            cue_index,
            store,
            writer,
            touched,
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        )
    }

    #[must_use]
    pub fn with_project_root(
        cue_index: Arc<CueIndexService>,
        store: CanonicalStore,
        writer: WriterHandle,
        touched: Arc<TouchedSetRegistry>,
        project_root: PathBuf,
    ) -> Self {
        Self::with_project_root_and_activation_min_edges(
            cue_index,
            store,
            writer,
            touched,
            project_root,
            500,
        )
    }

    #[must_use]
    pub fn with_project_root_and_activation_min_edges(
        cue_index: Arc<CueIndexService>,
        store: CanonicalStore,
        writer: WriterHandle,
        touched: Arc<TouchedSetRegistry>,
        project_root: PathBuf,
        enable_min_edges: u32,
    ) -> Self {
        Self {
            cue_index,
            activation: ActivationEngine::new(store.clone(), writer.clone(), enable_min_edges),
            store,
            writer,
            touched,
            pending: Mutex::new(HashMap::new()),
            hydrated: Mutex::new(HashSet::new()),
            project_root,
        }
    }

    pub async fn plan_after_tool(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        observed_cues: &[ObservedCue],
    ) -> Result<Vec<PendingInjectionItem>, EngineError> {
        self.hydrate_delivery_state(project_id, session_id).await?;
        if observed_cues.is_empty() {
            return Ok(Vec::new());
        }
        let firing = self.cue_index.fire(project_id, observed_cues).await?;
        let sources = self
            .store
            .load_cue_records(project_id)
            .await?
            .into_iter()
            .map(|source| (source.record_ref.clone(), source))
            .collect::<HashMap<_, _>>();
        let mut planned = Vec::new();
        let mut seed_refs = Vec::new();
        for fired in firing.fired {
            let Some(source) = sources.get(&fired.record_ref) else {
                continue;
            };
            let invariant = fired.record_kind == "invariant";
            let include_payload = fired.negative_memory || invariant;
            let source_bytes = serde_json::to_vec(source)?;
            seed_refs.push(fired.record_ref.clone());
            seed_refs.extend(fired.fired_cues.iter().filter_map(canonical_cue_ref));
            planned.push(PendingInjectionItem {
                item_ref: fired.record_ref,
                record_kind: fired.record_kind,
                preview: source.preview_text.clone(),
                payload: include_payload.then(|| source.payload.clone()).flatten(),
                source_fingerprint: blake3::hash(&source_bytes).to_hex().to_string(),
                fired_cues: fired.fired_cues,
                negative_memory: fired.negative_memory,
                invariant,
                token_estimate: fired.token_estimate,
                activation_trace_ref: None,
                activation_score_milli: None,
            });
        }
        let trace = self
            .activation
            .activate(project_id, session_id, None, &seed_refs)
            .await?;
        if let Some(trace) = trace.as_ref() {
            planned.extend(activation_items(trace, &sources)?);
        }
        let mut deduped = HashMap::<String, PendingInjectionItem>::new();
        for item in planned {
            let exact = item.activation_trace_ref.is_none();
            if exact || !deduped.contains_key(&item.item_ref) {
                deduped.insert(item.item_ref.clone(), item);
            }
        }
        let mut planned = deduped.into_values().collect::<Vec<_>>();
        planned.sort_by(compare_pending);
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| planner_lock_error("pending"))?;
        let batch = pending
            .entry(ProjectSessionKey {
                project_id,
                session_id,
            })
            .or_default();
        for item in &planned {
            if batch.attempts.iter().any(|attempt| attempt.matches_item(item)) {
                continue;
            }
            batch.items.retain(|pending| {
                pending.item_ref != item.item_ref
                    || pending.source_fingerprint != item.source_fingerprint
            });
            batch.items.push(item.clone());
        }
        batch.overflow = batch.overflow.saturating_add(firing.overflow);
        Ok(planned)
    }

    #[allow(clippy::too_many_lines)]
    pub async fn attach(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        session_id: SessionId,
        response: &mut Value,
        effective_mode: Option<UlInjectionMode>,
    ) -> Result<Vec<InjectionReceipt>, EngineError> {
        let Some(effective_mode) = effective_mode else {
            return Ok(Vec::new());
        };
        self.hydrate_delivery_state(project_id, session_id).await?;
        let mut committed_receipts = self
            .attach_boot(project_id, task_id, session_id, response, effective_mode)
            .await?;

        let key = ProjectSessionKey {
            project_id,
            session_id,
        };
        let batch = self
            .pending
            .lock()
            .map_err(|_| planner_lock_error("pending"))?
            .remove(&key)
            .unwrap_or_default();
        let mut batch = retain_undelivered_items(&self.touched, project_id, session_id, batch);
        batch.items.sort_by(compare_pending);
        batch
            .attempts
            .sort_by(|left, right| compare_pending(&left.item, &right.item));

        let attempted_items = batch
            .attempts
            .iter()
            .map(|attempt| {
                (
                    attempt.item.item_ref.clone(),
                    attempt.item.source_fingerprint.clone(),
                )
            })
            .collect::<HashSet<_>>();
        batch.items.retain(|item| {
            !attempted_items.contains(&(item.item_ref.clone(), item.source_fingerprint.clone()))
        });

        let mut delivered = Vec::new();
        let mut unresolved = Vec::new();
        let mut selected_count = 0_usize;
        let mut total_units = 0_u32;
        let mut failed_count = 0_usize;
        let mut unknown_count = 0_usize;
        let mut conflict_count = 0_usize;

        for mut attempt in batch.attempts {
            if attempt.state == PendingReceiptState::Conflict {
                conflict_count = conflict_count.saturating_add(1);
                unresolved.push(attempt);
                continue;
            }
            if selected_count >= MAX_ITEMS
                || total_units.saturating_add(attempt.receipt.token_cost) > MAX_TOTAL_UNITS
            {
                unresolved.push(attempt);
                continue;
            }
            selected_count = selected_count.saturating_add(1);
            total_units = total_units.saturating_add(attempt.receipt.token_cost);
            let result = match attempt.state {
                PendingReceiptState::RetryablePreEnqueue => {
                    self.submit_receipt_attempt(&attempt).await
                }
                PendingReceiptState::OutcomeUnknown => {
                    self.reconcile_receipt_attempt(&attempt).await
                }
                PendingReceiptState::Conflict => ReceiptAttemptResult::Conflict,
            };
            match result {
                ReceiptAttemptResult::Confirmed => {
                    self.record_confirmed_attempt(
                        project_id,
                        session_id,
                        attempt,
                        &mut committed_receipts,
                        &mut delivered,
                    );
                }
                ReceiptAttemptResult::RetryablePreEnqueue => {
                    attempt.state = PendingReceiptState::RetryablePreEnqueue;
                    failed_count = failed_count.saturating_add(1);
                    unresolved.push(attempt);
                }
                ReceiptAttemptResult::OutcomeUnknown => {
                    attempt.state = PendingReceiptState::OutcomeUnknown;
                    unknown_count = unknown_count.saturating_add(1);
                    unresolved.push(attempt);
                }
                ReceiptAttemptResult::Conflict => {
                    attempt.state = PendingReceiptState::Conflict;
                    conflict_count = conflict_count.saturating_add(1);
                    unresolved.push(attempt);
                }
            }
        }

        for item in batch.items {
            let line = truncate_utf8(item.preview.trim(), MAX_LINE_BYTES);
            let mut payload = if effective_mode == UlInjectionMode::HandlesOnly {
                None
            } else {
                item.payload.clone()
            };
            let payload_units = payload
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?
                .map_or(0, |serialized| ul_token_estimate(&serialized));
            if payload_units > MAX_PAYLOAD_UNITS {
                payload = None;
            }
            let payload_units = if payload.is_some() { payload_units } else { 0 };
            let token_cost = ul_token_estimate(&line).saturating_add(payload_units);
            if selected_count >= MAX_ITEMS
                || total_units.saturating_add(token_cost) > MAX_TOTAL_UNITS
            {
                batch.overflow = batch.overflow.saturating_add(1);
                continue;
            }
            selected_count = selected_count.saturating_add(1);
            total_units = total_units.saturating_add(token_cost);

            let render_form = if payload.is_some() {
                "payload"
            } else {
                "handle"
            };
            let receipt = InjectionReceipt {
                injection_id: injection_write_id(
                    session_id,
                    task_id,
                    &item.item_ref,
                    &item.source_fingerprint,
                    "mcp_response_piggyback",
                )
                .to_string(),
                session_id,
                task_id,
                surface: "mcp_response_piggyback".to_owned(),
                item_ref: item.item_ref.clone(),
                render_form: render_form.to_owned(),
                fired_cues: item.fired_cues.clone(),
                token_cost,
                source_fingerprint: item.source_fingerprint.clone(),
                outcome: "delivered".to_owned(),
                policy_reason: (effective_mode == UlInjectionMode::HandlesOnly)
                    .then(|| "task_class_handles_only".to_owned()),
            };
            let rendered = UlFiredItem {
                item_ref: item.item_ref.clone(),
                kind: item.record_kind.clone(),
                line,
                uri: format!("eliot://memory/{}", item.item_ref),
                payload,
                activation_trace_ref: item.activation_trace_ref.clone(),
                activation_score_milli: item.activation_score_milli,
            };
            let mut attempt = PendingReceiptAttempt {
                envelope: observability_envelope(project_id, task_id, &receipt)?,
                item,
                rendered,
                receipt,
                state: PendingReceiptState::OutcomeUnknown,
            };
            match self.submit_receipt_attempt(&attempt).await {
                ReceiptAttemptResult::Confirmed => {
                    self.record_confirmed_attempt(
                        project_id,
                        session_id,
                        attempt,
                        &mut committed_receipts,
                        &mut delivered,
                    );
                }
                ReceiptAttemptResult::RetryablePreEnqueue => {
                    attempt.state = PendingReceiptState::RetryablePreEnqueue;
                    failed_count = failed_count.saturating_add(1);
                    unresolved.push(attempt);
                }
                ReceiptAttemptResult::OutcomeUnknown => {
                    attempt.state = PendingReceiptState::OutcomeUnknown;
                    unknown_count = unknown_count.saturating_add(1);
                    unresolved.push(attempt);
                }
                ReceiptAttemptResult::Conflict => {
                    attempt.state = PendingReceiptState::Conflict;
                    conflict_count = conflict_count.saturating_add(1);
                    unresolved.push(attempt);
                }
            }
        }

        self.merge_unresolved_attempts(key, unresolved)?;

        let delivered_count = delivered.len();
        if delivered_count > 0 {
            response_object_mut(response)?.insert(
                "ul_fired".to_owned(),
                serde_json::to_value(UlFiredBlock {
                    items: delivered,
                    overflow: batch.overflow,
                })?,
            );
        }

        let issue_count = failed_count
            .saturating_add(unknown_count)
            .saturating_add(conflict_count);
        if issue_count > 0 {
            let code = if delivered_count == 0 {
                "INJECTION_RECEIPT_FAILED"
            } else {
                "INJECTION_RECEIPT_PARTIAL"
            };
            response_object_mut(response)?.insert(
                "ul_warning".to_owned(),
                json!({
                    "code": code,
                    "failed": failed_count,
                    "unknown": unknown_count,
                    "conflict": conflict_count,
                }),
            );
        }

        Ok(committed_receipts)
    }

    fn record_confirmed_attempt(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        attempt: PendingReceiptAttempt,
        committed_receipts: &mut Vec<InjectionReceipt>,
        delivered: &mut Vec<UlFiredItem>,
    ) {
        self.touched.mark_delivered(
            project_id,
            session_id,
            &attempt.item.item_ref,
            &attempt.item.source_fingerprint,
        );
        committed_receipts.push(attempt.receipt);
        delivered.push(attempt.rendered);
    }

    fn merge_unresolved_attempts(
        &self,
        key: ProjectSessionKey,
        attempts: Vec<PendingReceiptAttempt>,
    ) -> Result<(), EngineError> {
        if attempts.is_empty() {
            return Ok(());
        }
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| planner_lock_error("pending"))?;
        let batch = pending.entry(key).or_default();
        for attempt in attempts {
            if let Some(existing) = batch
                .attempts
                .iter_mut()
                .find(|existing| existing.envelope.write_id == attempt.envelope.write_id)
            {
                if existing.envelope.input_hash == attempt.envelope.input_hash {
                    if attempt.state.rank() > existing.state.rank() {
                        *existing = attempt;
                    }
                } else {
                    existing.state = PendingReceiptState::Conflict;
                }
                continue;
            }
            batch.attempts.push(attempt);
        }
        Ok(())
    }

    async fn submit_receipt_attempt(
        &self,
        attempt: &PendingReceiptAttempt,
    ) -> ReceiptAttemptResult {
        match self
            .writer
            .submit_observability(attempt.envelope.clone())
            .await
        {
            Ok(receipt) => classify_receipt(attempt, &receipt),
            Err(EngineError::Backpressure) => ReceiptAttemptResult::RetryablePreEnqueue,
            Err(EngineError::ObservabilityConflict | EngineError::WriteRejected(_)) => {
                ReceiptAttemptResult::Conflict
            }
            Err(_) => self.reconcile_receipt_attempt(attempt).await,
        }
    }

    async fn reconcile_receipt_attempt(
        &self,
        attempt: &PendingReceiptAttempt,
    ) -> ReceiptAttemptResult {
        match self
            .store
            .observability_receipt(attempt.envelope.write_id)
            .await
        {
            Ok(Some(receipt)) => classify_receipt(attempt, &receipt),
            Ok(None) | Err(_) => ReceiptAttemptResult::OutcomeUnknown,
        }
    }

    async fn hydrate_delivery_state(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
    ) -> Result<(), EngineError> {
        let key = (project_id, session_id);
        if self
            .hydrated
            .lock()
            .map_err(|_| planner_lock_error("hydrated"))?
            .contains(&key)
        {
            return Ok(());
        }
        let receipts = self
            .store
            .load_injection_receipts(project_id, session_id)
            .await?;
        let mut boot_charter = false;
        let mut boot_map = false;
        for receipt in receipts {
            self.touched.restore_delivered(
                project_id,
                session_id,
                &receipt.item_ref,
                &receipt.source_fingerprint,
            );
            if receipt.item_ref == "ul_boot:not_onboarded" {
                self.touched.mark_boot_sent(project_id, session_id);
            }
            boot_charter |= receipt.item_ref.starts_with("charter:");
            boot_map |= receipt.item_ref.starts_with("system-map:");
        }
        if boot_charter && boot_map {
            self.touched.mark_boot_sent(project_id, session_id);
        }
        self.hydrated
            .lock()
            .map_err(|_| planner_lock_error("hydrated"))?
            .insert(key);
        Ok(())
    }

    async fn attach_boot(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        session_id: SessionId,
        response: &mut Value,
        effective_mode: UlInjectionMode,
    ) -> Result<Vec<InjectionReceipt>, EngineError> {
        if self.touched.boot_sent(project_id, session_id) {
            return Ok(Vec::new());
        }
        let revision = response
            .get("at_revision")
            .or_else(|| response.get("memory_revision"))
            .cloned()
            .unwrap_or(Value::Null);
        let charter = latest_artifact(
            self.store
                .load_ul_artifacts::<ProjectCharter>(project_id, &["project_charter"], 128)
                .await?,
        );
        let map = latest_artifact(
            self.store
                .load_ul_artifacts::<SystemMap>(project_id, &["system_map"], 128)
                .await?,
        );
        if let (Some(charter), Some(map)) = (charter, map) {
            return self
                .attach_ready_boot(
                    project_id,
                    task_id,
                    session_id,
                    response,
                    revision,
                    charter,
                    map,
                    effective_mode,
                )
                .await;
        }
        let boot = if effective_mode == UlInjectionMode::HandlesOnly {
            json!({
                "status": "not_onboarded",
                "revision": revision,
                "ref": "ul_boot:not_onboarded",
                "handle_only": true
            })
        } else {
            json!({
                "status": "not_onboarded",
                "revision": revision,
                "message": "project understanding artifacts are not built yet; cue firing is active"
            })
        };
        let serialized = serde_json::to_vec(&boot)?;
        let source_fingerprint = blake3::hash(&serialized).to_hex().to_string();
        let receipt = InjectionReceipt {
            injection_id: injection_write_id(
                session_id,
                task_id,
                "ul_boot:not_onboarded",
                &source_fingerprint,
                "mcp_auto_boot",
            )
            .to_string(),
            session_id,
            task_id,
            surface: "mcp_auto_boot".to_owned(),
            item_ref: "ul_boot:not_onboarded".to_owned(),
            render_form: if effective_mode == UlInjectionMode::HandlesOnly {
                "handle"
            } else {
                "payload"
            }
            .to_owned(),
            fired_cues: Vec::new(),
            token_cost: ul_token_estimate(&String::from_utf8_lossy(&serialized)),
            source_fingerprint,
            outcome: "delivered".to_owned(),
            policy_reason: (effective_mode == UlInjectionMode::HandlesOnly)
                .then(|| "task_class_handles_only".to_owned()),
        };
        self.commit_receipt(project_id, task_id, &receipt).await?;
        response_object_mut(response)?.insert("ul_boot".to_owned(), boot);
        self.touched.mark_boot_sent(project_id, session_id);
        Ok(vec![receipt])
    }

    #[allow(clippy::too_many_arguments)]
    async fn attach_ready_boot(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        session_id: SessionId,
        response: &mut Value,
        revision: Value,
        charter: ProjectCharter,
        map: SystemMap,
        effective_mode: UlInjectionMode,
    ) -> Result<Vec<InjectionReceipt>, EngineError> {
        let concepts = self
            .store
            .load_ul_artifacts::<ConceptNode>(project_id, &["concept_node"], 128)
            .await?
            .into_iter()
            .map(|record| record.receipt_body)
            .collect::<Vec<_>>();
        let capsules = self
            .store
            .load_ul_artifacts::<SubsystemCapsule>(project_id, &["subsystem_capsule"], 128)
            .await?
            .into_iter()
            .map(|record| record.receipt_body)
            .collect::<Vec<_>>();
        let coverage = boot_coverage(&concepts, &capsules, &self.project_root);
        let charter_ref = format!("charter:{}", charter.charter_id);
        let map_ref = format!("system-map:{}", map.map_id);
        let dirty = self.store.load_ul_dirty_artifacts(project_id, 512).await?;
        let charter_body = render_body_with_dirty(
            &charter.body_md,
            dirty.iter().find(|state| {
                state.target_kind == eliot_types::PyramidTargetKind::ProjectCharter
                    && state.target_id == project_id.to_string()
            }),
        );
        let map_body = render_body_with_dirty(
            &map.body_md,
            dirty.iter().find(|state| {
                state.target_kind == eliot_types::PyramidTargetKind::SystemMap
                    && state.target_id == project_id.to_string()
            }),
        );
        let content_units =
            ul_token_estimate(&charter_body).saturating_add(ul_token_estimate(&map_body));
        let over_budget = content_units > 1_200 || effective_mode == UlInjectionMode::HandlesOnly;
        let charter_delivery = if over_budget {
            json!({"ref": charter_ref})
        } else {
            json!({"ref": charter_ref, "body_md": charter_body})
        };
        let map_delivery = if over_budget {
            json!({"ref": map_ref})
        } else {
            json!({"ref": map_ref, "body_md": map_body})
        };
        let boot = if over_budget {
            json!({
                "status": "ready",
                "revision": revision,
                "charter": charter_delivery.clone(),
                "system_map": map_delivery.clone(),
                "coverage": coverage,
                "warning": "UL_BOOT_BUDGET_EXCEEDED: payload omitted; use artifact handles"
            })
        } else {
            json!({
                "status": "ready",
                "revision": revision,
                "charter": charter_delivery.clone(),
                "system_map": map_delivery.clone(),
                "coverage": coverage
            })
        };
        let render_form = if over_budget { "handle" } else { "payload" };
        let charter_receipt = boot_receipt(
            session_id,
            task_id,
            &charter_ref,
            &charter_delivery,
            render_form,
            effective_mode,
        )?;
        self.commit_receipt(project_id, task_id, &charter_receipt)
            .await?;
        let map_receipt = boot_receipt(
            session_id,
            task_id,
            &map_ref,
            &map_delivery,
            render_form,
            effective_mode,
        )?;
        self.commit_receipt(project_id, task_id, &map_receipt)
            .await?;
        response_object_mut(response)?.insert("ul_boot".to_owned(), boot);
        self.touched.mark_boot_sent(project_id, session_id);
        Ok(vec![charter_receipt, map_receipt])
    }

    async fn commit_receipt(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        receipt: &InjectionReceipt,
    ) -> Result<(), EngineError> {
        let envelope = observability_envelope(project_id, task_id, receipt)?;
        let result = self.writer.submit_observability(envelope).await?;
        if result.status == ObservabilityWriteStatus::Rejected {
            return Err(EngineError::ObservabilityConflict);
        }
        Ok(())
    }
}

fn observability_envelope(
    project_id: ProjectId,
    task_id: Option<TaskId>,
    receipt: &InjectionReceipt,
) -> Result<ObservabilityWriteEnvelope, EngineError> {
    let payload = serde_json::to_value(receipt)?;
    let payload_bytes = serde_json::to_vec(&payload)?;
    let write_id = WriteId::from_uuid(
        Uuid::parse_str(&receipt.injection_id)
            .map_err(|error| EngineError::WriteRejected(error.to_string()))?,
    );
    Ok(ObservabilityWriteEnvelope {
        schema_version: OBSERVABILITY_SCHEMA_VERSION.to_owned(),
        write_id,
        project_id,
        task_id,
        session_id: Some(receipt.session_id),
        kind: ObservabilityKind::InjectionReceipt,
        record_id: receipt.injection_id.clone(),
        payload,
        input_hash: blake3::hash(&payload_bytes).to_hex().to_string(),
        created_at: time::OffsetDateTime::now_utc(),
    })
}

fn classify_receipt(
    attempt: &PendingReceiptAttempt,
    receipt: &ObservabilityWriteReceipt,
) -> ReceiptAttemptResult {
    if receipt.write_id != attempt.envelope.write_id
        || receipt.record_id != attempt.envelope.record_id
        || receipt.project_id != attempt.envelope.project_id
        || receipt.task_id != attempt.envelope.task_id
        || receipt.kind != attempt.envelope.kind
        || receipt.input_hash != attempt.envelope.input_hash
    {
        return ReceiptAttemptResult::Conflict;
    }
    match receipt.status {
        ObservabilityWriteStatus::Committed | ObservabilityWriteStatus::IdempotentReplay => {
            ReceiptAttemptResult::Confirmed
        }
        ObservabilityWriteStatus::Rejected => ReceiptAttemptResult::Conflict,
    }
}

fn latest_artifact<T>(records: Vec<eliot_store::CanonicalRecord<T>>) -> Option<T> {
    records
        .into_iter()
        .max_by_key(|record| {
            (
                record
                    .memory_revision
                    .map_or(0, eliot_types::MemoryRevision::value),
                record
                    .project_sequence
                    .map_or(0, eliot_types::ProjectSequence::value),
            )
        })
        .map(|record| record.receipt_body)
}

fn boot_coverage(
    concepts: &[ConceptNode],
    capsules: &[SubsystemCapsule],
    project_root: &Path,
) -> String {
    let fresh = capsules
        .iter()
        .filter(|capsule| capsule_freshness(capsule, project_root) == CapsuleFreshness::Fresh)
        .count();
    let unassigned = concepts
        .iter()
        .filter(|concept| concept.name == "_unassigned")
        .map(|concept| concept.boundary_paths.len())
        .sum::<usize>();
    format!(
        "{} subsystems; {fresh} fresh capsules; {unassigned} unassigned source files",
        concepts.len()
    )
}

fn boot_receipt(
    session_id: SessionId,
    task_id: Option<TaskId>,
    item_ref: &str,
    delivery: &Value,
    render_form: &str,
    effective_mode: UlInjectionMode,
) -> Result<InjectionReceipt, EngineError> {
    let rendered_bytes = serde_json::to_vec(delivery)?;
    let source_fingerprint = blake3::hash(&rendered_bytes).to_hex().to_string();
    Ok(InjectionReceipt {
        injection_id: injection_write_id(
            session_id,
            task_id,
            item_ref,
            &source_fingerprint,
            "mcp_auto_boot",
        )
        .to_string(),
        session_id,
        task_id,
        surface: "mcp_auto_boot".to_owned(),
        item_ref: item_ref.to_owned(),
        render_form: render_form.to_owned(),
        fired_cues: Vec::new(),
        token_cost: ul_token_estimate(&String::from_utf8_lossy(&rendered_bytes)),
        source_fingerprint,
        outcome: "delivered".to_owned(),
        policy_reason: (effective_mode == UlInjectionMode::HandlesOnly)
            .then(|| "task_class_handles_only".to_owned()),
    })
}

fn injection_write_id(
    session_id: SessionId,
    task_id: Option<TaskId>,
    item_ref: &str,
    source_fingerprint: &str,
    surface: &str,
) -> WriteId {
    let key = format!(
        "injection|{session_id}|{}|{item_ref}|{source_fingerprint}|{surface}",
        task_id.map_or_else(|| "none".to_owned(), |task_id| task_id.to_string())
    );
    deterministic_write_id(&key)
}

#[must_use]
pub fn deterministic_write_id(key: &str) -> WriteId {
    let digest = blake3::hash(key.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    WriteId::from_uuid(Uuid::from_bytes(bytes))
}

fn retain_undelivered_items(
    touched: &TouchedSetRegistry,
    project_id: ProjectId,
    session_id: SessionId,
    mut batch: PendingBatch,
) -> PendingBatch {
    batch.items.retain(|item| {
        !touched.was_delivered(
            project_id,
            session_id,
            &item.item_ref,
            &item.source_fingerprint,
        )
    });
    batch.attempts.retain(|attempt| {
        !touched.was_delivered(
            project_id,
            session_id,
            &attempt.item.item_ref,
            &attempt.item.source_fingerprint,
        )
    });
    batch
}

fn compare_pending(left: &PendingInjectionItem, right: &PendingInjectionItem) -> Ordering {
    pending_rank(left)
        .cmp(&pending_rank(right))
        .then_with(|| {
            left.activation_trace_ref
                .is_some()
                .cmp(&right.activation_trace_ref.is_some())
        })
        .then_with(|| {
            right
                .activation_score_milli
                .cmp(&left.activation_score_milli)
        })
        .then_with(|| left.item_ref.cmp(&right.item_ref))
}

fn canonical_cue_ref(cue: &ObservedCue) -> Option<String> {
    match cue.kind {
        LegacyCueKindV1::FilePath => Some(format!("file:{}", cue.value)),
        LegacyCueKindV1::DirPath => Some(format!("dir:{}", cue.value)),
        LegacyCueKindV1::Symbol => Some(format!("symbol:{}", cue.value)),
        LegacyCueKindV1::Dependency => Some(format!("dependency:{}", cue.value)),
        LegacyCueKindV1::ApiSurface => Some(format!("api:{}", cue.value)),
        LegacyCueKindV1::Subsystem => Some(format!("subsystem:{}", cue.value)),
        LegacyCueKindV1::Concept => Some(format!("concept:{}", cue.value)),
        LegacyCueKindV1::CommandPattern
        | LegacyCueKindV1::ErrorSignature
        | LegacyCueKindV1::TaskClass => None,
    }
}

fn render_body_with_dirty(body: &str, dirty: Option<&eliot_types::UlArtifactDirtyState>) -> String {
    let mut keys = dirty
        .filter(|state| state.dirty)
        .into_iter()
        .flat_map(|state| state.reasons.iter())
        .map(|reason| reason.dependency.key.clone())
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    keys.truncate(3);
    if keys.is_empty() {
        body.to_owned()
    } else {
        format!(
            "[STALE: changed dependencies: {}] — verify against code before relying.\n{body}",
            keys.join(", ")
        )
    }
}

fn activation_items(
    trace: &ActivationTrace,
    sources: &HashMap<String, CueRecordSource>,
) -> Result<Vec<PendingInjectionItem>, EngineError> {
    let mut items = Vec::new();
    for activated in &trace.activated {
        let matching = activation_sources(&activated.node_ref, sources);
        for source in matching {
            let invariant = source.record_kind == "invariant";
            let include_payload = source.negative_memory || invariant;
            let source_bytes = serde_json::to_vec(source)?;
            items.push(PendingInjectionItem {
                item_ref: source.record_ref.clone(),
                record_kind: source.record_kind.clone(),
                preview: source.preview_text.clone(),
                payload: include_payload.then(|| source.payload.clone()).flatten(),
                source_fingerprint: blake3::hash(&source_bytes).to_hex().to_string(),
                fired_cues: Vec::new(),
                negative_memory: source.negative_memory,
                invariant,
                token_estimate: ul_token_estimate(&source.preview_text),
                activation_trace_ref: Some(format!("activation:{}", trace.trace_id)),
                activation_score_milli: Some(activated.score_milli),
            });
        }
    }
    Ok(items)
}

fn activation_sources<'a>(
    node_ref: &str,
    sources: &'a HashMap<String, CueRecordSource>,
) -> Vec<&'a CueRecordSource> {
    let mut matches = Vec::new();
    if let Some(source) = sources.get(node_ref) {
        matches.push(source);
    }
    if let Some(path) = node_ref.strip_prefix("file:") {
        matches.extend(sources.values().filter(|source| {
            source.cue_bindings.iter().any(|binding| {
                binding.cue_kind == LegacyCueKindV1::FilePath
                    && eliot_types::normalize_path(&binding.cue_value, None) == path
            })
        }));
    }
    matches.sort_by(|left, right| left.record_ref.cmp(&right.record_ref));
    matches.dedup_by(|left, right| left.record_ref == right.record_ref);
    matches
}

fn pending_rank(item: &PendingInjectionItem) -> u8 {
    if item.negative_memory {
        return 0;
    }
    if item.invariant {
        return 1;
    }
    match item.record_kind.as_str() {
        "decision" => 2,
        "module_card" => 3,
        "claim" => 4,
        "experience_case" => 5,
        "skill" => 6,
        "subsystem_capsule" => 7,
        _ => 8,
    }
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut boundary = max_bytes;
    while !value.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    value[..boundary].to_owned()
}

fn response_object_mut(
    response: &mut Value,
) -> Result<&mut serde_json::Map<String, Value>, EngineError> {
    response
        .as_object_mut()
        .ok_or_else(|| EngineError::WriteRejected("MCP response must be a JSON object".to_owned()))
}

fn planner_lock_error(lock: &str) -> EngineError {
    EngineError::ServiceNotReady {
        service: "injection_planner".to_owned(),
        reason: format!("{lock} lock poisoned"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_types::{CueBinding, CueMatchMode, CueStrength};

    #[test]
    fn u8_1_pending_batches_are_isolated_by_project_and_session() {
        let session_id = SessionId::new_v7();
        let project_a = ProjectId::new_v7();
        let project_b = ProjectId::new_v7();
        let mut pending = HashMap::<ProjectSessionKey, PendingBatch>::new();
        pending
            .entry(ProjectSessionKey {
                project_id: project_a,
                session_id,
            })
            .or_default()
            .overflow = 1;
        pending
            .entry(ProjectSessionKey {
                project_id: project_b,
                session_id,
            })
            .or_default()
            .overflow = 2;

        assert_eq!(
            pending
                .remove(&ProjectSessionKey {
                    project_id: project_b,
                    session_id,
                })
                .map(|batch| batch.overflow),
            Some(2)
        );
        assert_eq!(
            pending
                .remove(&ProjectSessionKey {
                    project_id: project_a,
                    session_id,
                })
                .map(|batch| batch.overflow),
            Some(1)
        );
    }

    #[test]
    fn u8_6_activated_file_maps_to_handle_only_partner() -> Result<(), EngineError> {
        let project_id = ProjectId::new_v7();
        let session_id = SessionId::new_v7();
        let trace = ActivationTrace {
            trace_id: Uuid::new_v4().to_string(),
            project_id,
            session_id,
            task_id: None,
            seed_refs: vec!["file:a.rs".to_owned()],
            enabled_edge_count: 501,
            depth_limit: 2,
            fanout_cap: 20,
            threshold_milli: 350,
            activated: vec![eliot_types::ActivationNode {
                node_ref: "file:b.rs".to_owned(),
                score_milli: 560,
                depth: 1,
                via: vec!["file:a.rs".to_owned(), "file:b.rs".to_owned()],
            }],
            suppressed: Vec::new(),
        };
        let source = CueRecordSource {
            record_ref: "card:b".to_owned(),
            record_kind: "module_card".to_owned(),
            preview_text: "partner card".to_owned(),
            payload: Some(json!({"must_not": "flow"})),
            cue_bindings: vec![CueBinding {
                cue_kind: LegacyCueKindV1::FilePath,
                cue_value: "b.rs".to_owned(),
                match_mode: CueMatchMode::Exact,
                strength: CueStrength::Primary,
                expected_reuse_note: Some("test".to_owned()),
            }],
            negative_memory: false,
            lifecycle: "active".to_owned(),
        };
        let sources = HashMap::from([(source.record_ref.clone(), source)]);
        let items = activation_items(&trace, &sources)?;

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].item_ref, "card:b");
        assert!(items[0].payload.is_none());
        assert_eq!(items[0].activation_score_milli, Some(560));
        assert_eq!(
            items[0].activation_trace_ref.as_deref(),
            Some(format!("activation:{}", trace.trace_id).as_str())
        );
        Ok(())
    }

    #[test]
    fn c7_03c_equal_source_fingerprint_is_suppressed_but_changed_source_is_deliverable() {
        let project_id = ProjectId::new_v7();
        let session_id = SessionId::new_v7();
        let touched = TouchedSetRegistry::new();
        touched.mark_delivered(project_id, session_id, "failure:revision", "revision-one");

        let filtered = retain_undelivered_items(
            &touched,
            project_id,
            session_id,
            PendingBatch {
                items: vec![
                    pending_item("failure:revision", "revision-one"),
                    pending_item("failure:revision", "revision-two"),
                ],
                attempts: Vec::new(),
                overflow: 0,
            },
        );

        assert_eq!(filtered.items.len(), 1);
        assert_eq!(filtered.items[0].source_fingerprint, "revision-two");
    }

    #[test]
    fn c7_03c_restored_delivery_suppression_preserves_existing_overflow() {
        let project_id = ProjectId::new_v7();
        let session_id = SessionId::new_v7();
        let touched = TouchedSetRegistry::new();
        touched.restore_delivered(project_id, session_id, "card:restored", "stable-card");

        let filtered = retain_undelivered_items(
            &touched,
            project_id,
            session_id,
            PendingBatch {
                items: vec![
                    pending_item("card:restored", "stable-card"),
                    pending_item("failure:fresh", "fresh-failure"),
                ],
                attempts: Vec::new(),
                overflow: 2,
            },
        );

        assert_eq!(filtered.overflow, 2);
        assert_eq!(filtered.items.len(), 1);
        assert_eq!(filtered.items[0].item_ref, "failure:fresh");
    }

    fn pending_item(item_ref: &str, source_fingerprint: &str) -> PendingInjectionItem {
        PendingInjectionItem {
            item_ref: item_ref.to_owned(),
            record_kind: "failure".to_owned(),
            preview: item_ref.to_owned(),
            payload: None,
            source_fingerprint: source_fingerprint.to_owned(),
            fired_cues: Vec::new(),
            negative_memory: true,
            invariant: false,
            token_estimate: 1,
            activation_trace_ref: None,
            activation_score_milli: None,
        }
    }
}
