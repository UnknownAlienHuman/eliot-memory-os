use crate::{EngineError, StopCoordinationGate, WorkState};
use eliot_agent_contracts::{AgentAttemptId, HandoffCaptureBoundary, HandoffCaptureLedger};
use eliot_types::{
    EliotHookEvent, HookDecision, HookDecisionReason, HookEventKind, HookProcessingStatus,
    HookSpoolRecord,
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

const MAX_STRING_LEN: usize = 512;
const MAX_ARRAY_ITEMS: usize = 16;
const MAX_OBJECT_KEYS: usize = 32;
const MAX_DEPTH: usize = 6;
const MAX_PENDING_SPOOL: usize = 256;

#[derive(Clone, Debug)]
pub struct HookProcessingResult {
    pub event: EliotHookEvent,
    pub decision: HookDecision,
}

pub struct EliotHookService {
    runtime_root: PathBuf,
    task_bound: bool,
    /// Capture ledger shared with whoever owns the checkpoint commit for this
    /// session (issue #1730).
    ///
    /// The pre-compaction hook is the only ELIOT-controlled boundary that
    /// destroys conversational state, so it is the boundary that must not allow
    /// destruction on a spool-size check alone. The ledger is shared rather than
    /// owned because the capture must be REGISTERED by the party that commits the
    /// checkpoint and READ by the hook that decides: a hook-local ledger could
    /// never see a capture made elsewhere, and would therefore refuse every
    /// compaction forever.
    capture_ledger: Arc<Mutex<HandoffCaptureLedger>>,
}

impl EliotHookService {
    /// A service that gates. Use this only when the session is attached to an
    /// ELIOT task; see [`EliotHookService::unbound`] for the alternative.
    pub fn new(runtime_root: impl Into<PathBuf>) -> Self {
        Self::with_capture_ledger(runtime_root, true, HandoffCaptureLedger::new())
    }

    /// A service that gates against a caller-owned capture ledger (issue #1730).
    ///
    /// The composition root that commits the pre-compaction checkpoint holds the
    /// same ledger, so the capture this hook requires is the one that was actually
    /// committed and read back, not one this process invented for itself.
    #[must_use]
    pub fn with_capture_ledger(
        runtime_root: impl Into<PathBuf>,
        task_bound: bool,
        capture_ledger: HandoffCaptureLedger,
    ) -> Self {
        Self {
            runtime_root: runtime_root.into(),
            task_bound,
            capture_ledger: Arc::new(Mutex::new(capture_ledger)),
        }
    }

    /// Returns the shared handle to this service's capture ledger.
    ///
    /// The checkpoint owner registers its capture through this handle, and the
    /// pre-compaction gate reads the registration through the same one, so the
    /// two cannot disagree about whether a durable capture exists.
    #[must_use]
    pub fn capture_ledger(&self) -> Arc<Mutex<HandoffCaptureLedger>> {
        Arc::clone(&self.capture_ledger)
    }

    /// The plugin is installed at user scope, so these hooks fire in every
    /// Claude session on the machine -- including projects that have nothing to
    /// do with ELIOT. A session with no attached task has no lease to check
    /// against and no completion to gate, so the enforcement points defer
    /// instead of blocking. Observation is unchanged: the event is still
    /// spooled, it just cannot deny anything.
    #[must_use]
    pub fn unbound(runtime_root: impl Into<PathBuf>) -> Self {
        Self::with_capture_ledger(runtime_root, false, HandoffCaptureLedger::new())
    }

    /// Builds the service for a session, gating only when `ELIOT_TASK_ID`
    /// attaches it to a task. This is the same binding signal the generic host
    /// event path uses, so the two cannot disagree about whether a session is
    /// ELIOT's to govern.
    #[must_use]
    pub fn for_session(runtime_root: impl Into<PathBuf>, task_attached: bool) -> Self {
        Self::with_capture_ledger(runtime_root, task_attached, HandoffCaptureLedger::new())
    }

    pub fn process(
        &self,
        kind: HookEventKind,
        payload: &Value,
    ) -> Result<HookProcessingResult, EngineError> {
        let raw = serde_json::to_vec(payload)?;
        let payload_hash = blake3::hash(&raw).to_hex().to_string();
        let event_id = payload_hash.chars().take(16).collect::<String>();
        let event = EliotHookEvent {
            kind,
            received_at: OffsetDateTime::now_utc(),
            event_id: event_id.clone(),
            payload_hash,
            payload_size_bytes: raw.len(),
            session_id: string_field(payload, &["session_id", "sessionId"]),
            cwd: string_field(payload, &["cwd", "working_directory", "workingDirectory"]),
            tool_name: tool_name(payload),
            prompt_excerpt: prompt_excerpt(payload),
            payload: sanitize_value(payload, 0),
        };

        let (allow, status, reasons) = self.evaluate(&event)?;
        let stdout = stdout_for_decision(&event, allow, &reasons);
        let mut decision = HookDecision {
            event_id,
            kind,
            processing_status: status,
            allow,
            reasons,
            spool_path: None,
            stdout,
        };
        let spool_path = self.spool(&event, &decision)?;
        decision.spool_path = Some(path_slash(&spool_path));

        Ok(HookProcessingResult { event, decision })
    }

    fn evaluate(
        &self,
        event: &EliotHookEvent,
    ) -> Result<(bool, HookProcessingStatus, Vec<HookDecisionReason>), EngineError> {
        // Every arm below that can block is reachable only for a bound
        // session. An unbound one falls through to the same spooled
        // observation the non-gating events get.
        if !self.task_bound
            && matches!(
                event.kind,
                HookEventKind::PreToolUse | HookEventKind::PermissionRequest | HookEventKind::Stop
            )
        {
            return Ok(allow_decision(
                "session_not_eliot_bound",
                "ELIOT defers: this session is not attached to an ELIOT task.",
            ));
        }
        match event.kind {
            HookEventKind::PreToolUse => self.evaluate_pre_tool_use(event),
            HookEventKind::PermissionRequest => Ok(evaluate_permission_request(event)),
            HookEventKind::PreCompact => self.evaluate_pre_compact(event),
            HookEventKind::Stop => self.evaluate_stop(event),
            HookEventKind::SessionStart
            | HookEventKind::UserPromptSubmit
            | HookEventKind::SubagentStart
            | HookEventKind::PostToolUse
            | HookEventKind::PostCompact
            | HookEventKind::SubagentStop => Ok(allow_decision(
                "event_spooled",
                "ELIOT lifecycle event spooled for governed memory discipline.",
            )),
        }
    }

    /// The pre-compaction gate: the ONLY ELIOT-controlled destructive boundary
    /// (issue #1730, `HandoffCaptureBoundary::HostPreCompactHook`).
    ///
    /// Compaction destroys conversational state. Before this hook existed as a
    /// capture site, the decision was made on spool size alone — a local resource
    /// bound — so a session with a small spool destroyed state whose handoff
    /// checkpoint had never been captured. The bound is still enforced; it is now
    /// the SECOND question rather than the only one.
    ///
    /// The FIRST question is the capture contract's own gate:
    /// [`HandoffCaptureLedger::admits_destructive_compaction`] answers `true` only
    /// for a registered `HostPreCompactHook` capture whose own durable readback
    /// names that capture identity. A boundary with no registered capture, a
    /// capture holding only a transport acknowledgement, and a capture whose
    /// commit response was lost all answer `false` here — which is the fail-closed
    /// direction for a destructive operation.
    ///
    /// The gate is asked PER SOURCE ATTEMPT, so it reads the ledger rather than
    /// assuming one session-wide answer. An unbound session has no ELIOT state to
    /// lose and is allowed before this point (the same rule the other enforcement
    /// events use); a bound session must have captured first.
    ///
    /// A poisoned ledger is NOT read as an absent capture and therefore NOT read
    /// as permission: it blocks with its own reason, because an unreadable gate on
    /// a destructive boundary is not evidence that the boundary is safe.
    fn evaluate_pre_compact(
        &self,
        event: &EliotHookEvent,
    ) -> Result<(bool, HookProcessingStatus, Vec<HookDecisionReason>), EngineError> {
        let pending = pending_spool_count(&self.runtime_root)?;
        if pending > MAX_PENDING_SPOOL {
            return Ok(block_decision(
                HookProcessingStatus::FailedClosed,
                "spool_backlog_too_large",
                "ELIOT blocks compaction because hook spool backlog exceeds the F0 bound.",
            ));
        }
        let captures_durable = self.pre_compact_capture_is_durable(event)?;
        if !captures_durable {
            return Ok(block_decision(
                HookProcessingStatus::FailedClosed,
                "handoff_capture_required",
                "ELIOT blocks compaction until this session's handoff checkpoint is captured \
                 and durably read back; the pre-compaction boundary destroys conversational \
                 state, so a missing or unproved capture is refused rather than allowed.",
            ));
        }
        Ok(allow_decision(
            "handoff_captured_and_spool_bounded",
            "ELIOT hook spool is within the F0 compaction bound and this session's handoff \
             checkpoint is captured with a durable readback.",
        ))
    }

    /// Whether the pre-compaction capture this event names is registered with a
    /// durable readback, or whether no capture is owed at all.
    ///
    /// `Ok(true)` covers two cases and they are deliberately different:
    ///
    /// * the event names a source attempt and the ledger holds that attempt's
    ///   capture with a durable readback; or
    /// * the event names no attempt, so there is no capture identity to check.
    ///   A hook payload with no attempt cannot have a registered capture either,
    ///   so refusing on that alone would block compaction for every session that
    ///   does not report one, which is the opposite of what this gate is for. The
    ///   caller decides what a session without an attempt means; this function
    ///   only refuses a NAMED capture that is missing or unproved.
    fn pre_compact_capture_is_durable(&self, event: &EliotHookEvent) -> Result<bool, EngineError> {
        let Some(attempt) = source_attempt_of(event) else {
            return Ok(true);
        };
        let ledger = self.capture_ledger.lock().map_err(|_| {
            EngineError::WriteRejected(
                "the handoff capture ledger is unreadable; a destructive boundary whose capture \
                 gate cannot be read is refused rather than allowed"
                    .to_owned(),
            )
        })?;
        Ok(ledger
            .admits_destructive_compaction(HandoffCaptureBoundary::HostPreCompactHook, &attempt))
    }

    fn evaluate_pre_tool_use(
        &self,
        event: &EliotHookEvent,
    ) -> Result<(bool, HookProcessingStatus, Vec<HookDecisionReason>), EngineError> {
        if packet_gate_blocks_mutation(&self.runtime_root, event)?
            && is_packet_gate_mutation_tool(event.tool_name.as_deref())
        {
            return Ok(block_decision(
                HookProcessingStatus::Blocked,
                "ul_packet_gate_requires_refresh",
                "ELIOT blocks mutation until a fresh packet satisfies the subsystem probe and invariant gate.",
            ));
        }
        Ok(evaluate_pre_tool_use(event))
    }

    fn evaluate_stop(
        &self,
        event: &EliotHookEvent,
    ) -> Result<(bool, HookProcessingStatus, Vec<HookDecisionReason>), EngineError> {
        let base = evaluate_stop(event);
        if !base.0 {
            return Ok(base);
        }
        let state_path = self
            .runtime_root
            .join("reports")
            .join("work")
            .join("state.json");
        if !state_path.is_file() {
            return Ok(base);
        }
        let state: WorkState = serde_json::from_reader(std::fs::File::open(state_path)?)?;
        let decision = StopCoordinationGate.evaluate(&state, None, None);
        if decision.allow {
            Ok(base)
        } else {
            Ok(block_decision(
                HookProcessingStatus::Blocked,
                "unresolved_collective_coordination",
                "ELIOT blocks stop while F3 control mailbox messages or blackboard blockers are unresolved.",
            ))
        }
    }

    fn spool(
        &self,
        event: &EliotHookEvent,
        decision: &HookDecision,
    ) -> Result<PathBuf, EngineError> {
        let pending = self.runtime_root.join("hook-spool").join("pending");
        std::fs::create_dir_all(&pending)?;
        std::fs::create_dir_all(self.runtime_root.join("hook-spool").join("committed"))?;
        std::fs::create_dir_all(self.runtime_root.join("hook-spool").join("failed"))?;
        let file_name = format!(
            "{}-{}.json",
            event.received_at.unix_timestamp_nanos(),
            event.event_id
        );
        let path = pending.join(file_name);
        let record = HookSpoolRecord {
            event: event.clone(),
            decision: decision.clone(),
            written_at: OffsetDateTime::now_utc(),
        };
        serde_json::to_writer_pretty(std::fs::File::create(&path)?, &record)?;
        Ok(path)
    }
}

/// The source attempt a hook event names, when it names one.
///
/// Read from the same admitted payload members the rest of this module reads, and
/// only when they agree: an `attempt_id` that disagrees with `attemptId` is
/// ambiguous and yields `None` rather than either value, because the capture
/// ledger is keyed by this identity and a wrong key answers about the wrong
/// attempt.
fn source_attempt_of(event: &EliotHookEvent) -> Option<AgentAttemptId> {
    let read = |key: &str| event.payload.get(key).and_then(Value::as_str);
    let primary = read("attempt_id").or_else(|| read("attemptId"))?;
    if let Some(secondary) = read("attemptId").or_else(|| read("attempt_id"))
        && secondary != primary
    {
        return None;
    }
    AgentAttemptId::new(primary).ok()
}

fn stdout_for_decision(
    event: &EliotHookEvent,
    allow: bool,
    reasons: &[HookDecisionReason],
) -> Value {
    let message = reasons
        .first()
        .map_or("ELIOT hook processed.", |reason| reason.detail.as_str());
    let hook_event_name = hook_event_name(event.kind);
    match event.kind {
        HookEventKind::PreToolUse if !allow => json!({
            "hookSpecificOutput": {
                "hookEventName": hook_event_name,
                "permissionDecision": "deny",
                "permissionDecisionReason": message
            }
        }),
        HookEventKind::PermissionRequest if !allow => json!({
            "hookSpecificOutput": {
                "hookEventName": hook_event_name,
                "decision": {
                    "behavior": "deny",
                    "message": message
                }
            }
        }),
        HookEventKind::PreCompact if !allow => json!({
            "continue": false,
            "stopReason": message
        }),
        HookEventKind::PreToolUse => json!({
            "hookSpecificOutput": {
                "hookEventName": hook_event_name,
                "additionalContext": message
            }
        }),
        HookEventKind::PermissionRequest => json!({
            "hookSpecificOutput": {
                "hookEventName": hook_event_name,
                "decision": {
                    "behavior": "allow"
                }
            }
        }),
        HookEventKind::SessionStart
        | HookEventKind::UserPromptSubmit
        | HookEventKind::SubagentStart => json!({
            "continue": true,
            "hookSpecificOutput": {
                "hookEventName": hook_event_name,
                "additionalContext": message
            }
        }),
        HookEventKind::Stop if !allow => json!({
            "decision": "block",
            "reason": message
        }),
        _ => json!({
            "continue": true,
            "systemMessage": message
        }),
    }
}

fn hook_event_name(kind: HookEventKind) -> &'static str {
    match kind {
        HookEventKind::SessionStart => "SessionStart",
        HookEventKind::UserPromptSubmit => "UserPromptSubmit",
        HookEventKind::SubagentStart => "SubagentStart",
        HookEventKind::PreToolUse => "PreToolUse",
        HookEventKind::PermissionRequest => "PermissionRequest",
        HookEventKind::PostToolUse => "PostToolUse",
        HookEventKind::PreCompact => "PreCompact",
        HookEventKind::PostCompact => "PostCompact",
        HookEventKind::SubagentStop => "SubagentStop",
        HookEventKind::Stop => "Stop",
    }
}

fn reason(code: &str, severity: &str, detail: &str) -> HookDecisionReason {
    HookDecisionReason {
        code: code.to_owned(),
        severity: severity.to_owned(),
        detail: detail.to_owned(),
    }
}

fn evaluate_pre_tool_use(
    event: &EliotHookEvent,
) -> (bool, HookProcessingStatus, Vec<HookDecisionReason>) {
    if is_unleased_write_tool(event.tool_name.as_deref()) {
        block_decision(
            HookProcessingStatus::Blocked,
            "unleased_patch_or_write",
            "ELIOT blocks patch/write tools unless an ActionLease and PatchRunner path are active.",
        )
    } else {
        allow_decision(
            "governed_read_allowed",
            "ELIOT allows governed read-only or non-mutating tool use.",
        )
    }
}

fn evaluate_permission_request(
    event: &EliotHookEvent,
) -> (bool, HookProcessingStatus, Vec<HookDecisionReason>) {
    if is_unleased_write_tool(event.tool_name.as_deref()) {
        block_decision(
            HookProcessingStatus::Blocked,
            "permission_denied_without_lease",
            "ELIOT denies escalation for write-capable tool use without an ActionLease.",
        )
    } else {
        allow_decision(
            "permission_observed",
            "ELIOT recorded the permission request.",
        )
    }
}

fn evaluate_stop(event: &EliotHookEvent) -> (bool, HookProcessingStatus, Vec<HookDecisionReason>) {
    if stop_claims_done_without_verification(&event.payload) {
        block_decision(
            HookProcessingStatus::Blocked,
            "done_without_done_verified",
            "ELIOT blocks final completion unless DONE_VERIFIED evidence is present.",
        )
    } else {
        allow_decision(
            "completion_gate_observed",
            "ELIOT stop hook observed verified or non-final completion state.",
        )
    }
}

fn allow_decision(
    code: &str,
    detail: &str,
) -> (bool, HookProcessingStatus, Vec<HookDecisionReason>) {
    (
        true,
        HookProcessingStatus::SpoolingPending,
        vec![reason(code, "info", detail)],
    )
}

fn block_decision(
    status: HookProcessingStatus,
    code: &str,
    detail: &str,
) -> (bool, HookProcessingStatus, Vec<HookDecisionReason>) {
    (false, status, vec![reason(code, "error", detail)])
}

fn pending_spool_count(root: &Path) -> Result<usize, EngineError> {
    let path = root.join("hook-spool").join("pending");
    if !path.is_dir() {
        return Ok(0);
    }
    Ok(std::fs::read_dir(path)?.filter_map(Result::ok).count())
}

fn stop_claims_done_without_verification(payload: &Value) -> bool {
    let text = value_text(payload).to_ascii_uppercase();
    (text.contains("DONE") || text.contains("COMPLETE")) && !text.contains("DONE_VERIFIED")
}

fn is_unleased_write_tool(tool_name: Option<&str>) -> bool {
    let Some(tool_name) = tool_name else {
        return false;
    };
    let lowered = tool_name.to_ascii_lowercase();
    if lowered.contains("eliot_patch_preflight") || lowered.contains("eliot_verifier_status") {
        return false;
    }
    [
        "apply_patch",
        "edit_file",
        "edit_lines",
        "bulk_edits",
        "patch_apply",
        "remove-item",
        "delete",
        "write",
        "move-item",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

fn is_packet_gate_mutation_tool(tool_name: Option<&str>) -> bool {
    let Some(tool_name) = tool_name else {
        return false;
    };
    matches!(
        tool_name.to_ascii_lowercase().as_str(),
        "bash" | "edit" | "write" | "notebookedit" | "notebook_edit"
    )
}

fn packet_gate_blocks_mutation(root: &Path, event: &EliotHookEvent) -> Result<bool, EngineError> {
    let Some(session_id) = event.session_id.as_deref() else {
        return Ok(false);
    };
    if !session_id
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Ok(false);
    }
    let path = root
        .join("reports")
        .join("ul-gates")
        .join(format!("{session_id}.json"));
    if !path.is_file() {
        return Ok(false);
    }
    let value: Value = serde_json::from_reader(std::fs::File::open(path)?)?;
    Ok(matches!(
        value.pointer("/gate/status").and_then(Value::as_str),
        Some("require_probe" | "require_packet_refresh")
    ))
}

fn sanitize_value(value: &Value, depth: usize) -> Value {
    if depth >= MAX_DEPTH {
        return json!("<truncated-depth>");
    }
    match value {
        Value::String(text) => Value::String(truncate(text, MAX_STRING_LEN)),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .take(MAX_ARRAY_ITEMS)
                .map(|item| sanitize_value(item, depth + 1))
                .collect(),
        ),
        Value::Object(map) => {
            let mut sanitized = serde_json::Map::new();
            for (key, value) in map.iter().take(MAX_OBJECT_KEYS) {
                if is_secret_key(key) {
                    sanitized.insert(key.clone(), Value::String("<redacted>".to_owned()));
                } else {
                    sanitized.insert(key.clone(), sanitize_value(value, depth + 1));
                }
            }
            Value::Object(sanitized)
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => value.clone(),
    }
}

fn is_secret_key(key: &str) -> bool {
    let lowered = key.to_ascii_lowercase();
    [
        "secret",
        "token",
        "password",
        "credential",
        "api_key",
        "apikey",
        "endpoint",
        "url",
        "dsn",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

fn string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(|text| truncate(text, MAX_STRING_LEN))
}

fn tool_name(value: &Value) -> Option<String> {
    string_field(
        value,
        &[
            "tool_name",
            "toolName",
            "name",
            "tool",
            "requested_tool",
            "requestedTool",
        ],
    )
}

fn prompt_excerpt(value: &Value) -> Option<String> {
    string_field(
        value,
        &["prompt", "user_prompt", "userPrompt", "message", "input"],
    )
}

fn value_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Array(items) => items.iter().map(value_text).collect::<Vec<_>>().join(" "),
        Value::Object(map) => map.values().map(value_text).collect::<Vec<_>>().join(" "),
        Value::Null => String::new(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
    }
}

fn truncate(text: &str, max_chars: usize) -> String {
    let mut output = text.chars().take(max_chars).collect::<String>();
    if text.chars().count() > max_chars {
        output.push_str("<truncated>");
    }
    output
}

fn path_slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
