use super::{CueIndexService, TouchedSetRegistry};
use crate::{EngineError, WriterHandle};
use eliot_store::CanonicalStore;
use eliot_types::{
    InjectionReceipt, OBSERVABILITY_SCHEMA_VERSION, ObservabilityKind, ObservabilityWriteEnvelope,
    ObservabilityWriteStatus, ObservedCue, PendingInjectionItem, ProjectId, SessionId, TaskId,
    UlFiredBlock, UlFiredItem, WriteId, ul_token_estimate,
};
use serde_json::{Value, json};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const MAX_ITEMS: usize = 3;
const MAX_TOTAL_UNITS: u32 = 400;
const MAX_PAYLOAD_UNITS: u32 = 300;
const MAX_LINE_BYTES: usize = 160;

#[derive(Default)]
struct PendingBatch {
    items: Vec<PendingInjectionItem>,
    overflow: usize,
}

pub struct InjectionPlanner {
    cue_index: Arc<CueIndexService>,
    store: CanonicalStore,
    writer: WriterHandle,
    touched: Arc<TouchedSetRegistry>,
    pending: Mutex<HashMap<SessionId, PendingBatch>>,
    hydrated: Mutex<HashSet<(ProjectId, SessionId)>>,
}

impl InjectionPlanner {
    #[must_use]
    pub fn new(
        cue_index: Arc<CueIndexService>,
        store: CanonicalStore,
        writer: WriterHandle,
        touched: Arc<TouchedSetRegistry>,
    ) -> Self {
        Self {
            cue_index,
            store,
            writer,
            touched,
            pending: Mutex::new(HashMap::new()),
            hydrated: Mutex::new(HashSet::new()),
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
        for fired in firing.fired {
            let Some(source) = sources.get(&fired.record_ref) else {
                continue;
            };
            let invariant = fired.record_kind == "invariant";
            let include_payload = fired.negative_memory || invariant;
            let source_bytes = serde_json::to_vec(source)?;
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
            });
        }
        planned.sort_by(compare_pending);
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| planner_lock_error("pending"))?;
        let batch = pending.entry(session_id).or_default();
        for item in &planned {
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
        memory_free_control: bool,
    ) -> Result<(), EngineError> {
        if memory_free_control {
            return Ok(());
        }
        self.hydrate_delivery_state(project_id, session_id).await?;
        self.attach_boot(project_id, task_id, session_id, response)
            .await?;

        let mut batch = self
            .pending
            .lock()
            .map_err(|_| planner_lock_error("pending"))?
            .remove(&session_id)
            .unwrap_or_default();
        batch.items.sort_by(compare_pending);

        let mut selected = Vec::new();
        let mut total_units = 0_u32;
        for item in batch.items {
            if self
                .touched
                .was_delivered(session_id, &item.item_ref, &item.source_fingerprint)
            {
                continue;
            }
            let line = truncate_utf8(item.preview.trim(), MAX_LINE_BYTES);
            let mut payload = item.payload.clone();
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
            if selected.len() >= MAX_ITEMS
                || total_units.saturating_add(token_cost) > MAX_TOTAL_UNITS
            {
                batch.overflow = batch.overflow.saturating_add(1);
                continue;
            }
            total_units = total_units.saturating_add(token_cost);
            selected.push((item, line, payload, token_cost));
        }

        let candidate_count = selected.len();
        let mut delivered = Vec::new();
        for (item, line, payload, token_cost) in selected {
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
                fired_cues: item.fired_cues,
                token_cost,
                source_fingerprint: item.source_fingerprint.clone(),
                outcome: "delivered".to_owned(),
            };
            if self
                .commit_receipt(project_id, task_id, &receipt)
                .await
                .is_err()
            {
                continue;
            }
            self.touched
                .mark_delivered(session_id, &item.item_ref, &item.source_fingerprint);
            delivered.push(UlFiredItem {
                item_ref: item.item_ref.clone(),
                kind: item.record_kind,
                line,
                uri: format!("eliot://memory/{}", item.item_ref),
                payload,
            });
        }

        if !delivered.is_empty() {
            response_object_mut(response)?.insert(
                "ul_fired".to_owned(),
                serde_json::to_value(UlFiredBlock {
                    items: delivered,
                    overflow: batch.overflow,
                })?,
            );
        } else if candidate_count > 0 {
            response_object_mut(response)?.insert(
                "ul_warning".to_owned(),
                json!({"code": "INJECTION_RECEIPT_FAILED"}),
            );
        }
        Ok(())
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
        for receipt in receipts {
            self.touched.restore_delivered(
                session_id,
                &receipt.item_ref,
                &receipt.source_fingerprint,
            );
            if receipt.item_ref == "ul_boot:not_onboarded" {
                self.touched.mark_boot_sent(session_id);
            }
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
    ) -> Result<(), EngineError> {
        if self.touched.boot_sent(session_id) {
            return Ok(());
        }
        let revision = response
            .get("at_revision")
            .or_else(|| response.get("memory_revision"))
            .cloned()
            .unwrap_or(Value::Null);
        let boot = json!({
            "status": "not_onboarded",
            "revision": revision,
            "message": "project understanding artifacts are not built yet; cue firing is active"
        });
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
            render_form: "payload".to_owned(),
            fired_cues: Vec::new(),
            token_cost: ul_token_estimate(&String::from_utf8_lossy(&serialized)),
            source_fingerprint,
            outcome: "delivered".to_owned(),
        };
        self.commit_receipt(project_id, task_id, &receipt).await?;
        response_object_mut(response)?.insert("ul_boot".to_owned(), boot);
        self.touched.mark_boot_sent(session_id);
        Ok(())
    }

    async fn commit_receipt(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        receipt: &InjectionReceipt,
    ) -> Result<(), EngineError> {
        let payload = serde_json::to_value(receipt)?;
        let payload_bytes = serde_json::to_vec(&payload)?;
        let write_id = WriteId::from_uuid(
            Uuid::parse_str(&receipt.injection_id)
                .map_err(|error| EngineError::WriteRejected(error.to_string()))?,
        );
        let result = self
            .writer
            .submit_observability(ObservabilityWriteEnvelope {
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
            .await?;
        if result.status == ObservabilityWriteStatus::Rejected {
            return Err(EngineError::ObservabilityConflict);
        }
        Ok(())
    }
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

fn compare_pending(left: &PendingInjectionItem, right: &PendingInjectionItem) -> Ordering {
    pending_rank(left)
        .cmp(&pending_rank(right))
        .then_with(|| left.item_ref.cmp(&right.item_ref))
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
