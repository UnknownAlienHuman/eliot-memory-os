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
    KnownNoEffectRetryable,
    OutcomeUnknown,
    Conflict,
}

impl PendingReceiptState {
    const fn rank(self) -> u8 {
        match self {
            Self::KnownNoEffectRetryable => 0,
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
    KnownNoEffectRetryable,
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
                PendingReceiptState::KnownNoEffectRetryable => {
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
                ReceiptAttemptResult::KnownNoEffectRetryable => {
                    attempt.state = PendingReceiptState::KnownNoEffectRetryable;
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
                ReceiptAttemptResult::KnownNoEffectRetryable => {
                    attempt.state = PendingReceiptState::KnownNoEffectRetryable;
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
            Err(EngineError::Backpressure | EngineError::WriteRejected(_)) => {
                ReceiptAttemptResult::KnownNoEffectRetryable
            }
            Err(EngineError::ObservabilityConflict) => ReceiptAttemptResult::Conflict,
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
        let b