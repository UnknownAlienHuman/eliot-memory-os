use crate::EngineError;
use eliot_store::CanonicalStore;
use eliot_types::{
    InjectionReceipt, MemoryInfluenceAckInput, ObservabilityKind, ProjectId, SessionId, TaskId,
    UlLedgerDelta, UlTaskLedger, UlUseReport,
};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

#[derive(Clone, Debug)]
pub struct UlToolMeasurement {
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub tool_name: String,
    pub arguments: Value,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub injection_receipts: Vec<InjectionReceipt>,
}

#[derive(Clone, Debug)]
struct DeliveredItem {
    task_id: Option<TaskId>,
    call_sequence: Option<u64>,
}

#[derive(Default)]
struct SessionLedger {
    call_sequence: u64,
    mutation_seen: bool,
    delivered: HashMap<String, DeliveredItem>,
    expanded: HashSet<String>,
    acknowledged: HashSet<String>,
}

pub struct UlLedgerService {
    store: CanonicalStore,
    sessions: Mutex<UlLedgerAccumulator>,
    hydrated: Mutex<HashSet<(ProjectId, SessionId)>>,
}

#[derive(Default)]
pub struct UlLedgerAccumulator {
    sessions: HashMap<(ProjectId, SessionId), SessionLedger>,
}

impl UlLedgerAccumulator {
    #[must_use]
    pub fn record(&mut self, measurement: &UlToolMeasurement) -> UlLedgerDelta {
        let key = (measurement.project_id, measurement.session_id);
        let session = self.sessions.entry(key).or_default();
        session.call_sequence = session.call_sequence.saturating_add(1);
        let sequence = session.call_sequence;
        let mutation = is_mutation_tool(&measurement.tool_name, &measurement.arguments);
        let count_exploration = !session.mutation_seen
            && !mutation
            && is_read_class_tool(&measurement.tool_name, &measurement.arguments);
        let mut delta = UlLedgerDelta {
            first_mutation_seen: mutation && !session.mutation_seen,
            ..UlLedgerDelta::default()
        };
        if count_exploration {
            delta.read_tool_input_bytes = measurement.input_bytes;
            delta.read_tool_output_bytes = measurement.output_bytes;
        }
        if mutation {
            session.mutation_seen = true;
        }
        if measurement.tool_name == "eliot_fetch_l2" {
            for handle in fetched_handles(&measurement.arguments) {
                let expands = session.delivered.get(&handle).is_some_and(|delivered| {
                    delivered.task_id == Some(measurement.task_id)
                        && delivered.call_sequence.is_some_and(|delivered_at| {
                            sequence > delivered_at && sequence.saturating_sub(delivered_at) <= 2
                        })
                });
                if expands && session.expanded.insert(handle) {
                    delta.expanded_injected_handles =
                        delta.expanded_injected_handles.saturating_add(1);
                }
            }
        }
        if measurement.tool_name == "eliot_memory_influence_trace"
            && let Some(handle) = acknowledged_handle(&measurement.arguments)
        {
            let delivered = session
                .delivered
                .get(&handle)
                .is_some_and(|item| item.task_id == Some(measurement.task_id));
            if delivered && session.acknowledged.insert(handle) {
                delta.acknowledged_items = delta.acknowledged_items.saturating_add(1);
            }
        }
        for receipt in &measurement.injection_receipts {
            delta.injected_tokens = delta
                .injected_tokens
                .saturating_add(u64::from(receipt.token_cost));
            session.delivered.insert(
                receipt.item_ref.clone(),
                DeliveredItem {
                    task_id: receipt.task_id,
                    call_sequence: Some(sequence),
                },
            );
        }
        delta
    }

    fn restore(&mut self, project_id: ProjectId, session_id: SessionId, receipt: InjectionReceipt) {
        self.sessions
            .entry((project_id, session_id))
            .or_default()
            .delivered
            .insert(
                receipt.item_ref,
                DeliveredItem {
                    task_id: receipt.task_id,
                    call_sequence: None,
                },
            );
    }
}

impl UlLedgerService {
    #[must_use]
    pub fn new(store: CanonicalStore) -> Self {
        Self {
            store,
            sessions: Mutex::new(UlLedgerAccumulator::default()),
            hydrated: Mutex::new(HashSet::new()),
        }
    }

    pub async fn record_call(
        &self,
        measurement: UlToolMeasurement,
    ) -> Result<UlTaskLedger, EngineError> {
        self.hydrate(
            measurement.project_id,
            measurement.session_id,
            &measurement.injection_receipts,
        )
        .await?;
        let delta = {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| ledger_lock_error("sessions"))?;
            sessions.record(&measurement)
        };
        self.store
            .upsert_ul_task_ledger(measurement.project_id, measurement.task_id, &delta)
            .await
            .map_err(Into::into)
    }

    pub async fn report(
        &self,
        project_id: ProjectId,
    ) -> Result<(UlUseReport, Vec<UlTaskLedger>, u32), EngineError> {
        let ledgers = self.store.load_ul_metrics(project_id).await?;
        let receipts = self
            .store
            .observability_records_by_kind::<InjectionReceipt>(
                project_id,
                None,
                ObservabilityKind::InjectionReceipt,
            )
            .await?;
        let receipt_count = u32::try_from(receipts.len()).unwrap_or(u32::MAX);
        Ok((
            Self::use_report(project_id, &ledgers, receipt_count),
            ledgers,
            receipt_count,
        ))
    }

    #[must_use]
    pub fn use_report(
        project_id: ProjectId,
        ledgers: &[UlTaskLedger],
        injected_items: u32,
    ) -> UlUseReport {
        let injected_tokens = ledgers.iter().map(|ledger| ledger.injected_tokens).sum();
        let exploration_bytes = ledgers
            .iter()
            .map(|ledger| {
                ledger
                    .read_tool_input_bytes
                    .saturating_add(ledger.read_tool_output_bytes)
            })
            .sum::<u64>();
        let acknowledged = ledgers.iter().fold(0_u32, |count, ledger| {
            count.saturating_add(ledger.acknowledged_items)
        });
        let expanded = ledgers.iter().fold(0_u32, |count, ledger| {
            count.saturating_add(ledger.expanded_injected_handles)
        });
        let denominator = f64::from(injected_items);
        UlUseReport {
            project_id,
            tasks: u32::try_from(ledgers.len()).unwrap_or(u32::MAX),
            injected_tokens,
            exploration_tokens: exploration_bytes.saturating_add(3) / 4,
            acknowledged_fraction: if injected_items == 0 {
                0.0
            } else {
                f64::from(acknowledged) / denominator
            },
            expanded_after_injection_fraction: if injected_items == 0 {
                0.0
            } else {
                f64::from(expanded) / denominator
            },
        }
    }

    async fn hydrate(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        current_receipts: &[InjectionReceipt],
    ) -> Result<(), EngineError> {
        let key = (project_id, session_id);
        {
            let hydrated = self
                .hydrated
                .lock()
                .map_err(|_| ledger_lock_error("hydrated"))?;
            if hydrated.contains(&key) {
                return Ok(());
            }
        }
        let current = current_receipts
            .iter()
            .map(|receipt| receipt.injection_id.as_str())
            .collect::<HashSet<_>>();
        let receipts = self
            .store
            .load_injection_receipts(project_id, session_id)
            .await?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| ledger_lock_error("sessions"))?;
        for receipt in receipts {
            if current.contains(receipt.injection_id.as_str()) {
                continue;
            }
            sessions.restore(project_id, session_id, receipt);
        }
        drop(sessions);
        self.hydrated
            .lock()
            .map_err(|_| ledger_lock_error("hydrated"))?
            .insert(key);
        Ok(())
    }
}

#[must_use]
pub fn is_read_class_tool(tool_name: &str, arguments: &Value) -> bool {
    match tool_name {
        "eliot_current_state"
        | "eliot_recall_l0"
        | "eliot_fetch_l2"
        | "eliot_codecortex_scan"
        | "eliot_codecortex_latest" => true,
        "eliot_compile_packet_l3" => arguments.get("material_frame").is_none_or(|frame| {
            frame
                .get("active_plan")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
        }),
        _ => false,
    }
}

#[must_use]
pub fn is_mutation_tool(tool_name: &str, arguments: &Value) -> bool {
    if matches!(
        tool_name,
        "eliot_agent_candidate_submit" | "eliot_task_observation_record"
    ) || tool_name.contains("patch")
        || tool_name.contains("action")
    {
        return true;
    }
    tool_name == "eliot_compile_packet_l3"
        && arguments.get("material_frame").is_some_and(|frame| {
            frame
                .get("active_plan")
                .and_then(Value::as_array)
                .is_some_and(|items| !items.is_empty())
                && frame
                    .get("expected_observable")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty())
        })
}

fn fetched_handles(arguments: &Value) -> Vec<String> {
    let mut handles = arguments
        .get("handles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if let Some(handle) = arguments.get("handle").and_then(Value::as_str) {
        handles.push(handle.to_owned());
    }
    handles.sort();
    handles.dedup();
    handles
}

fn acknowledged_handle(arguments: &Value) -> Option<String> {
    serde_json::from_value::<MemoryInfluenceAckInput>(arguments.clone())
        .ok()
        .map(|ack| ack.memory_handle)
}

fn ledger_lock_error(name: &str) -> EngineError {
    EngineError::ServiceNotReady {
        service: "ul_ledger".to_owned(),
        reason: format!("{name} lock poisoned"),
    }
}
