use eliot_types::{
    CueKind, ObservedCue, SessionId, TaskId, command_pattern, error_signature, normalize_path,
    normalize_symbol,
};
use serde_json::Value;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

const MAX_TOUCHED_CUES: usize = 128;
const MAX_TOUCHED_STRING_BYTES: usize = 4096;

#[derive(Clone, Debug)]
pub struct TouchedCue {
    pub cue: ObservedCue,
    pub sequence: u64,
}

#[derive(Default)]
struct SessionTouchedSet {
    next_sequence: u64,
    cues: VecDeque<TouchedCue>,
    delivered: HashMap<String, String>,
    last_packet_id: Option<String>,
    last_packet_handles: HashSet<String>,
    last_task_id: Option<TaskId>,
    boot_sent: bool,
}

#[derive(Default)]
pub struct TouchedSetRegistry {
    sessions: Mutex<HashMap<SessionId, SessionTouchedSet>>,
}

impl TouchedSetRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe_arguments(
        &self,
        session_id: SessionId,
        tool_name: &str,
        arguments: &Value,
    ) -> Vec<ObservedCue> {
        self.observe(session_id, tool_name, arguments)
    }

    pub fn observe_result(
        &self,
        session_id: SessionId,
        tool_name: &str,
        result: &Value,
    ) -> Vec<ObservedCue> {
        let observed = self.observe(session_id, tool_name, result);
        if let Ok(mut sessions) = self.sessions.lock() {
            let session = sessions.entry(session_id).or_default();
            if let Some(packet_id) = result.get("packet_id").and_then(Value::as_str) {
                session.last_packet_id = Some(packet_id.to_owned());
            }
            if let Some(handles) = result.get("exact_handles").and_then(Value::as_array) {
                session.last_packet_handles = handles
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect();
            }
            if let Some(task_id) = result
                .get("task_id")
                .and_then(Value::as_str)
                .and_then(|task_id| task_id.parse().ok())
            {
                session.last_task_id = Some(task_id);
            }
        }
        observed
    }

    #[must_use]
    pub fn recent_cues(&self, session_id: SessionId, limit: usize) -> Vec<ObservedCue> {
        self.sessions
            .lock()
            .ok()
            .and_then(|sessions| {
                sessions.get(&session_id).map(|session| {
                    let mut cues = session.cues.iter().cloned().collect::<Vec<_>>();
                    cues.sort_by_key(|touched| std::cmp::Reverse(touched.sequence));
                    cues.into_iter()
                        .take(limit)
                        .map(|touched| touched.cue)
                        .collect()
                })
            })
            .unwrap_or_default()
    }

    pub fn mark_delivered(&self, session_id: SessionId, item_ref: &str, fingerprint: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions
                .entry(session_id)
                .or_default()
                .delivered
                .insert(item_ref.to_owned(), fingerprint.to_owned());
        }
    }

    #[must_use]
    pub fn was_delivered(&self, session_id: SessionId, item_ref: &str, fingerprint: &str) -> bool {
        self.sessions
            .lock()
            .ok()
            .and_then(|sessions| {
                sessions
                    .get(&session_id)
                    .and_then(|session| session.delivered.get(item_ref))
                    .map(|delivered| delivered == fingerprint)
            })
            .unwrap_or(false)
    }

    pub fn restore_delivered(&self, session_id: SessionId, item_ref: &str, fingerprint: &str) {
        self.mark_delivered(session_id, item_ref, fingerprint);
    }

    #[must_use]
    pub fn packet_context(&self, session_id: SessionId) -> (Option<String>, HashSet<String>) {
        self.sessions
            .lock()
            .ok()
            .and_then(|sessions| {
                sessions.get(&session_id).map(|session| {
                    (
                        session.last_packet_id.clone(),
                        session.last_packet_handles.clone(),
                    )
                })
            })
            .unwrap_or_default()
    }

    #[must_use]
    pub fn last_task_id(&self, session_id: SessionId) -> Option<TaskId> {
        self.sessions.lock().ok().and_then(|sessions| {
            sessions
                .get(&session_id)
                .and_then(|session| session.last_task_id)
        })
    }

    #[must_use]
    pub fn boot_sent(&self, session_id: SessionId) -> bool {
        self.sessions
            .lock()
            .ok()
            .and_then(|sessions| sessions.get(&session_id).map(|session| session.boot_sent))
            .unwrap_or(false)
    }

    pub fn mark_boot_sent(&self, session_id: SessionId) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.entry(session_id).or_default().boot_sent = true;
        }
    }

    fn observe(&self, session_id: SessionId, tool_name: &str, value: &Value) -> Vec<ObservedCue> {
        let mut observed = Vec::new();
        extract_cues(tool_name, None, value, &mut observed);
        observed.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.value.cmp(&right.value))
        });
        observed.dedup();
        let Ok(mut sessions) = self.sessions.lock() else {
            return Vec::new();
        };
        let session = sessions.entry(session_id).or_default();
        for cue in &observed {
            session.next_sequence = session.next_sequence.saturating_add(1);
            session.cues.retain(|touched| touched.cue != *cue);
            session.cues.push_back(TouchedCue {
                cue: cue.clone(),
                sequence: session.next_sequence,
            });
            while session.cues.len() > MAX_TOUCHED_CUES {
                session.cues.pop_front();
            }
        }
        observed
    }
}

fn extract_cues(
    tool_name: &str,
    key: Option<&str>,
    value: &Value,
    observed: &mut Vec<ObservedCue>,
) {
    match value {
        Value::Object(object) => {
            if let (Some(rule_id), Some(message)) = (
                object.get("rule_id").and_then(Value::as_str),
                object.get("message").and_then(Value::as_str),
            ) {
                let path = object
                    .get("path")
                    .or_else(|| object.get("file"))
                    .or_else(|| object.get("file_path"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                push_cue(
                    observed,
                    CueKind::ErrorSignature,
                    error_signature(tool_name, rule_id, message, path, None),
                );
            }
            for (field, child) in object {
                extract_cues(tool_name, Some(field), child, observed);
            }
        }
        Value::Array(values) => {
            if key.is_some_and(is_command_key) {
                let argv = values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>();
                push_cue(observed, CueKind::CommandPattern, command_pattern(&argv));
            }
            for child in values {
                extract_cues(tool_name, key, child, observed);
            }
        }
        Value::String(raw) if raw.len() <= MAX_TOUCHED_STRING_BYTES => {
            let field = key.unwrap_or_default();
            if is_path_key(field) && (field != "resource_ref" || looks_like_path(raw)) {
                push_cue(observed, CueKind::FilePath, normalize_path(raw, None));
            } else if is_symbol_key(field) {
                push_cue(observed, CueKind::Symbol, normalize_symbol(raw));
            } else if is_command_key(field) {
                let argv = raw
                    .split_whitespace()
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>();
                push_cue(observed, CueKind::CommandPattern, command_pattern(&argv));
            } else if is_signature_key(field) {
                let signature = if raw.starts_with("sig:") {
                    raw.to_owned()
                } else {
                    error_signature(tool_name, field, raw, "", None)
                };
                push_cue(observed, CueKind::ErrorSignature, signature);
            }
            if has_source_extension(raw) {
                push_cue(observed, CueKind::FilePath, normalize_path(raw, None));
            }
        }
        _ => {}
    }
}

fn push_cue(observed: &mut Vec<ObservedCue>, kind: CueKind, value: String) {
    if !value.is_empty() {
        observed.push(ObservedCue { kind, value });
    }
}

fn is_path_key(key: &str) -> bool {
    matches!(
        key,
        "path" | "file" | "file_path" | "worktree_ref" | "resource_ref"
    )
}

fn is_symbol_key(key: &str) -> bool {
    matches!(
        key,
        "symbol" | "owner" | "module" | "selected_owner_or_module"
    )
}

fn is_command_key(key: &str) -> bool {
    matches!(key, "command" | "verifier")
}

fn is_signature_key(key: &str) -> bool {
    matches!(key, "error_signature" | "fingerprint")
}

fn looks_like_path(raw: &str) -> bool {
    raw.contains(['/', '\\']) || has_source_extension(raw)
}

fn has_source_extension(raw: &str) -> bool {
    let lower = raw.trim().to_ascii_lowercase();
    [
        ".rs", ".toml", ".json", ".md", ".ps1", ".sh", ".yaml", ".yml",
    ]
    .iter()
    .any(|extension| lower.ends_with(extension))
}
