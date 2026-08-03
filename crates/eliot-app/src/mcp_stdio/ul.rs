use super::McpState;
use anyhow::{Context, Result};
use eliot_engine::{
    DeliveredFingerprint, InjectionPlan, InjectionSelectionPolicy, PacketUnderstandingRequest,
    PendingRestoreSource, RestoredSession, UnderstandingExecutionMode, deterministic_write_id,
    is_mutation_tool,
};
use eliot_types::{
    ActivationTrace, InjectionReceipt, OBSERVABILITY_SCHEMA_VERSION, ObservabilityKind,
    ObservabilityWriteEnvelope, ObservabilityWriteStatus, ObservedCue, PendingInjectionBatch,
    PendingInjectionItem, ProjectId, SessionId, TaskId, UlExperimentArm, UlFiredBlock, UlFiredItem,
    UlInjectionMode, UlTaskExperimentAssignment, WriteId, ul_token_estimate,
};
use serde_json::{Value, json};

pub(super) use eliot_engine::PyramidPacketEnrichment;

const SHIPPED_MAX_ITEMS: usize = 3;
const SHIPPED_MAX_TOTAL_UNITS: u32 = 400;
const SHIPPED_MAX_NEGATIVE_PAYLOADS: usize = 3;
const BOOT_PAYLOAD_BUDGET: u32 = 1_200;

impl McpState {
    pub(super) fn ledger_service(&self) -> &eliot_engine::UlLedgerService {
        &self.ul_ledger
    }

    pub(super) async fn ensure_understanding_session(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
    ) -> Result<()> {
        if self
            .understanding
            .session_snapshot(project_id, session_id)?
            .is_some()
        {
            return Ok(());
        }

        let pending = self
            .store
            .load_pending_injections(project_id, session_id)
            .await?;
        let receipts = self
            .store
            .load_injection_receipts(project_id, session_id)
            .await?;
        let delivered = receipts
            .iter()
            .map(|receipt| DeliveredFingerprint {
                item_ref: receipt.item_ref.clone(),
                source_fingerprint: receipt.source_fingerprint.clone(),
            })
            .collect();
        let boot_not_onboarded = receipts
            .iter()
            .any(|receipt| receipt.item_ref == "ul_boot:not_onboarded");
        let boot_charter = receipts
            .iter()
            .any(|receipt| receipt.item_ref.starts_with("charter:"));
        let boot_map = receipts
            .iter()
            .any(|receipt| receipt.item_ref.starts_with("system-map:"));
        self.understanding
            .restore_session_if_absent(RestoredSession {
                project_id,
                session_id,
                source: PendingRestoreSource::PendingInjectionAndReceipts,
                touched_cues: Vec::new(),
                pending,
                delivered,
                active_concepts: Vec::new(),
                packet_revision: None,
                execution_mode: UnderstandingExecutionMode::Production,
                boot_sent: boot_not_onboarded || (boot_charter && boot_map),
            })?;
        Ok(())
    }

    pub(super) async fn production_injection_mode(
        &self,
        assignment: &UlTaskExperimentAssignment,
    ) -> Result<Option<UlInjectionMode>> {
        let policy = self
            .store
            .load_ul_task_class_policy(assignment.project_id, &assignment.task_class.key())
            .await?;
        Ok(Some(policy.map_or(assignment.injection_mode, |policy| {
            policy.injection_mode
        })))
    }

    pub(super) async fn effective_injection_mode(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        task_id: Option<TaskId>,
        explicit_control: bool,
    ) -> Result<(Option<UlInjectionMode>, Option<UlTaskExperimentAssignment>)> {
        let assignment = if let Some(task_id) = task_id {
            self.ul_token_policy
                .load_assignment(project_id, task_id)
                .await?
        } else {
            None
        };
        let (mode, execution_mode) = if explicit_control {
            (None, UnderstandingExecutionMode::Control)
        } else if let Some(assignment) = assignment.as_ref() {
            if assignment.arm == UlExperimentArm::Control {
                (None, UnderstandingExecutionMode::Control)
            } else {
                (
                    self.ul_token_policy.effective_mode(assignment).await?,
                    UnderstandingExecutionMode::Treatment,
                )
            }
        } else {
            (
                Some(UlInjectionMode::Payload),
                UnderstandingExecutionMode::Production,
            )
        };
        self.understanding
            .set_execution_mode(project_id, session_id, execution_mode)?;
        Ok((mode, assignment))
    }

    pub(super) async fn observe_successful_tool(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        tool_name: &str,
        arguments: &Value,
        observed_cues: &[ObservedCue],
    ) -> Result<()> {
        if !is_mutation_tool(tool_name, arguments) {
            return Ok(());
        }
        let changed_paths = observed_cues
            .iter()
            .filter(|cue| cue.kind == eliot_types::CueKind::FilePath)
            .map(|cue| cue.value.clone())
            .collect::<Vec<_>>();
        self.projection
            .enqueue_dependency_dirty(
                project_id,
                &format!("tool:{tool_name}:{session_id}"),
                &changed_paths,
            )
            .await?;
        Ok(())
    }

    pub(super) async fn persist_activation_trace(
        &self,
        trace: Option<&ActivationTrace>,
    ) -> Result<()> {
        let Some(trace) = trace else {
            return Ok(());
        };
        let write_id = WriteId::from_uuid(
            uuid::Uuid::parse_str(&trace.trace_id)
                .context("activation trace must have a canonical write id")?,
        );
        self.commit_observability(
            write_id,
            trace.project_id,
            trace.task_id,
            Some(trace.session_id),
            ObservabilityKind::ActivationTrace,
            trace.trace_id.clone(),
            serde_json::to_value(trace)?,
        )
        .await
    }

    pub(super) async fn persist_pending_injection_candidate(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        session_id: SessionId,
        candidate: Vec<PendingInjectionItem>,
    ) -> Result<Vec<PendingInjectionItem>> {
        let batch = PendingInjectionBatch::new(
            project_id,
            task_id,
            session_id,
            candidate,
            time::OffsetDateTime::now_utc(),
        )?;
        self.writer
            .submit_pending_injection_batch(batch.clone())
            .await?;
        Ok(batch.items)
    }

    pub(super) async fn attach_understanding(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        session_id: SessionId,
        response: &mut Value,
        effective_mode: Option<UlInjectionMode>,
        plan: Option<&InjectionPlan>,
    ) -> Result<Vec<InjectionReceipt>> {
        let Some(effective_mode) = effective_mode else {
            return Ok(Vec::new());
        };
        // Project snapshots recover in the coordinator's background loop. An
        // absent snapshot means "not published yet", not "not onboarded".
        // Leave boot/session delivery state untouched and retry next call.
        if self
            .understanding
            .project_snapshot(project_id)?
            .is_none_or(|snapshot| !snapshot.is_fully_published())
        {
            return Ok(Vec::new());
        }
        response_object_mut(response)?;
        let mut committed = self
            .attach_understanding_boot(project_id, task_id, session_id, response, effective_mode)
            .await?;
        if self
            .understanding
            .project_snapshot(project_id)?
            .is_none_or(|snapshot| !snapshot.is_fully_published())
        {
            return Ok(committed);
        }
        let selection = self.understanding.select_pending_with_policy(
            project_id,
            session_id,
            effective_mode,
            InjectionSelectionPolicy {
                max_items: SHIPPED_MAX_ITEMS,
                max_token_units: SHIPPED_MAX_TOTAL_UNITS,
                max_negative_payloads: SHIPPED_MAX_NEGATIVE_PAYLOADS,
            },
        )?;
        let candidate_count = selection.items.len();
        let mut delivered_items = Vec::new();
        let mut delivered_fingerprints = Vec::new();
        for item in selection.items {
            let prepared = prepare_injection(item, session_id, task_id, effective_mode);
            if self
                .commit_injection_receipt(project_id, task_id, &prepared.receipt)
                .await
                .is_err()
            {
                continue;
            }
            delivered_fingerprints.push(prepared.fingerprint);
            committed.push(prepared.receipt);
            delivered_items.push(prepared.fired);
        }

        if !delivered_items.is_empty() {
            self.understanding.acknowledge_delivered(
                project_id,
                session_id,
                &delivered_fingerprints,
            )?;
            response_object_mut(response)?.insert(
                "ul_fired".to_owned(),
                serde_json::to_value(UlFiredBlock {
                    items: delivered_items,
                    overflow: selection
                        .overflow
                        .saturating_add(plan.map_or(0, |plan| plan.overflow)),
                })?,
            );
        } else if candidate_count > 0 {
            response_object_mut(response)?.insert(
                "ul_warning".to_owned(),
                json!({"code": "INJECTION_RECEIPT_FAILED"}),
            );
        }
        Ok(committed)
    }

    async fn attach_understanding_boot(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        session_id: SessionId,
        response: &mut Value,
        effective_mode: UlInjectionMode,
    ) -> Result<Vec<InjectionReceipt>> {
        if self.understanding.boot_sent(project_id, session_id)? {
            return Ok(Vec::new());
        }
        let revision = response
            .get("at_revision")
            .or_else(|| response.get("memory_revision"))
            .cloned()
            .unwrap_or(Value::Null);
        let snapshot = self.understanding.project_snapshot(project_id)?;
        let Some(snapshot) = snapshot else {
            return Ok(Vec::new());
        };
        if !snapshot.is_fully_published() {
            return Ok(Vec::new());
        }
        let (Some(charter), Some(system_map)) = (snapshot.charter(), snapshot.system_map()) else {
            return self
                .attach_not_onboarded_boot(
                    project_id,
                    task_id,
                    session_id,
                    response,
                    effective_mode,
                    revision,
                )
                .await;
        };
        let bodies_available = charter.body_md.is_some() && system_map.body_md.is_some();
        let content_units = charter
            .body_md
            .as_deref()
            .map_or(0, ul_token_estimate)
            .saturating_add(system_map.body_md.as_deref().map_or(0, ul_token_estimate));
        let handles_only = !bodies_available
            || content_units > BOOT_PAYLOAD_BUDGET
            || effective_mode == UlInjectionMode::HandlesOnly;
        let charter_delivery = if handles_only {
            json!({"ref": charter.handle})
        } else {
            json!({"ref": charter.handle, "body_md": charter.body_md})
        };
        let map_delivery = if handles_only {
            json!({"ref": system_map.handle})
        } else {
            json!({"ref": system_map.handle, "body_md": system_map.body_md})
        };
        let mut boot = json!({
            "status": "ready",
            "revision": revision,
            "charter": charter_delivery,
            "system_map": map_delivery,
            "coverage": snapshot.boot_coverage(),
        });
        if handles_only {
            boot["warning"] = Value::String(
                "UL_BOOT_BUDGET_EXCEEDED: payload omitted; use artifact handles".to_owned(),
            );
        }
        let render_form = if handles_only { "handle" } else { "payload" };
        let charter_receipt = boot_receipt(
            session_id,
            task_id,
            &charter.handle,
            boot.get("charter").context("boot charter delivery")?,
            render_form,
            effective_mode,
        )?;
        let map_receipt = boot_receipt(
            session_id,
            task_id,
            &system_map.handle,
            boot.get("system_map").context("boot system map delivery")?,
            render_form,
            effective_mode,
        )?;
        self.commit_injection_receipt(project_id, task_id, &charter_receipt)
            .await?;
        self.commit_injection_receipt(project_id, task_id, &map_receipt)
            .await?;
        self.understanding.mark_boot_sent(project_id, session_id)?;
        response_object_mut(response)?.insert("ul_boot".to_owned(), boot);
        Ok(vec![charter_receipt, map_receipt])
    }

    async fn attach_not_onboarded_boot(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        session_id: SessionId,
        response: &mut Value,
        effective_mode: UlInjectionMode,
        revision: Value,
    ) -> Result<Vec<InjectionReceipt>> {
        let boot = if effective_mode == UlInjectionMode::HandlesOnly {
            json!({
                "status": "not_onboarded",
                "revision": revision,
                "ref": "ul_boot:not_onboarded",
                "handle_only": true,
            })
        } else {
            json!({
                "status": "not_onboarded",
                "revision": revision,
                "message": "project understanding artifacts are not built yet; cue firing is active",
            })
        };
        let serialized = serde_json::to_vec(&boot)?;
        let fingerprint = blake3::hash(&serialized).to_hex().to_string();
        let receipt = InjectionReceipt {
            injection_id: injection_write_id(
                session_id,
                task_id,
                "ul_boot:not_onboarded",
                &fingerprint,
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
            source_fingerprint: fingerprint,
            outcome: "delivered".to_owned(),
            policy_reason: (effective_mode == UlInjectionMode::HandlesOnly)
                .then(|| "task_class_handles_only".to_owned()),
        };
        self.commit_injection_receipt(project_id, task_id, &receipt)
            .await?;
        self.understanding.mark_boot_sent(project_id, session_id)?;
        response_object_mut(response)?.insert("ul_boot".to_owned(), boot);
        Ok(vec![receipt])
    }

    async fn commit_injection_receipt(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        receipt: &InjectionReceipt,
    ) -> Result<()> {
        let write_id = WriteId::from_uuid(
            uuid::Uuid::parse_str(&receipt.injection_id)
                .context("injection receipt must have a canonical write id")?,
        );
        self.commit_observability(
            write_id,
            project_id,
            task_id,
            Some(receipt.session_id),
            ObservabilityKind::InjectionReceipt,
            receipt.injection_id.clone(),
            serde_json::to_value(receipt)?,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn commit_observability(
        &self,
        write_id: WriteId,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        session_id: Option<SessionId>,
        kind: ObservabilityKind,
        record_id: String,
        payload: Value,
    ) -> Result<()> {
        let input_hash = blake3::hash(&serde_json::to_vec(&payload)?)
            .to_hex()
            .to_string();
        let receipt = self
            .writer
            .submit_observability(ObservabilityWriteEnvelope {
                schema_version: OBSERVABILITY_SCHEMA_VERSION.to_owned(),
                write_id,
                project_id,
                task_id,
                session_id,
                kind,
                record_id,
                payload,
                input_hash,
                created_at: time::OffsetDateTime::now_utc(),
            })
            .await?;
        anyhow::ensure!(
            receipt.status != ObservabilityWriteStatus::Rejected,
            "observability write id conflicts with an existing payload"
        );
        Ok(())
    }

    pub(super) fn packet_enrichment(
        &self,
        project_id: ProjectId,
        task_id: &str,
        touched_paths: &[String],
        fallback_text: &str,
    ) -> Result<(eliot_types::MemoryRevision, PyramidPacketEnrichment)> {
        let snapshot = self
            .understanding
            .project_snapshot(project_id)?
            .with_context(|| format!("project snapshot {project_id} is not published"))?;
        anyhow::ensure!(
            snapshot.is_fully_published(),
            "project snapshot {project_id} has stale or unpublished projection families"
        );
        let revision = snapshot
            .revisions()
            .canonical
            .context("project snapshot has no canonical revision fence")?;
        let enrichment = snapshot.plan_packet_understanding(&PacketUnderstandingRequest {
            task_id: task_id.to_owned(),
            touched_paths: touched_paths.to_vec(),
            fallback_text: fallback_text.to_owned(),
        });
        Ok((revision, enrichment))
    }

    pub(super) fn record_packet_gate(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        task_id: Option<TaskId>,
        gate: Option<&Value>,
    ) -> Result<()> {
        // Startup outbox recovery may replay a gate before any request has
        // hydrated the session's durable delivery receipts. Do not create an
        // unhydrated hot session from that replay; normal in-session commits
        // update the already-restored snapshot here.
        if self
            .understanding
            .session_snapshot(project_id, session_id)?
            .is_some()
        {
            self.understanding
                .set_packet_gate(project_id, session_id, gate.cloned())?;
        }
        let directory = self.root.join("reports").join("ul-gates");
        std::fs::create_dir_all(&directory)?;
        let path = directory.join(format!("{session_id}.json"));
        if let Some(gate) = gate {
            serde_json::to_writer_pretty(
                std::fs::File::create(path)?,
                &json!({
                    "project_id": project_id,
                    "session_id": session_id,
                    "task_id": task_id,
                    "gate": gate,
                }),
            )?;
        } else if path.is_file() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}

struct PreparedInjection {
    receipt: InjectionReceipt,
    fingerprint: DeliveredFingerprint,
    fired: UlFiredItem,
}

fn prepare_injection(
    item: PendingInjectionItem,
    session_id: SessionId,
    task_id: Option<TaskId>,
    effective_mode: UlInjectionMode,
) -> PreparedInjection {
    let render_form = if item.payload.is_some() {
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
        token_cost: item.token_estimate,
        source_fingerprint: item.source_fingerprint.clone(),
        outcome: "delivered".to_owned(),
        policy_reason: (effective_mode == UlInjectionMode::HandlesOnly)
            .then(|| "task_class_handles_only".to_owned()),
    };
    PreparedInjection {
        fingerprint: DeliveredFingerprint {
            item_ref: item.item_ref.clone(),
            source_fingerprint: item.source_fingerprint.clone(),
        },
        fired: UlFiredItem {
            item_ref: item.item_ref.clone(),
            kind: item.record_kind,
            line: item.preview,
            uri: format!("eliot://memory/{}", item.item_ref),
            payload: item.payload,
            activation_trace_ref: item.activation_trace_ref,
            activation_score_milli: item.activation_score_milli,
        },
        receipt,
    }
}

fn boot_receipt(
    session_id: SessionId,
    task_id: Option<TaskId>,
    item_ref: &str,
    delivery: &Value,
    render_form: &str,
    effective_mode: UlInjectionMode,
) -> Result<InjectionReceipt> {
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
    deterministic_write_id(&format!(
        "injection|{session_id}|{}|{item_ref}|{source_fingerprint}|{surface}",
        task_id.map_or_else(|| "none".to_owned(), |task_id| task_id.to_string())
    ))
}

fn response_object_mut(response: &mut Value) -> Result<&mut serde_json::Map<String, Value>> {
    response
        .as_object_mut()
        .context("MCP tool response must be an object before understanding injection")
}

#[cfg(test)]
mod tests {
    use super::{SHIPPED_MAX_ITEMS, SHIPPED_MAX_TOTAL_UNITS};

    #[test]
    fn shipped_piggyback_selection_limits_remain_bounded() {
        assert_eq!(SHIPPED_MAX_ITEMS, 3);
        assert_eq!(SHIPPED_MAX_TOTAL_UNITS, 400);
    }
}
