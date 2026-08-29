#!/usr/bin/env python3
"""One-shot exact patch for PR #139; removed after the workflow succeeds."""
from __future__ import annotations

from pathlib import Path


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one patch anchor, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    types = Path("crates/eliot-types/src/host.rs")
    replace_once(
        types,
        """pub struct HostEventEnvelope {
    pub host_id: AgentHostId,
    pub host_session_id: Option<String>,
    pub eliot_session_id: Option<AgentSessionId>,
""",
        """pub struct HostEventEnvelope {
    pub host_id: AgentHostId,
    pub host_session_id: Option<String>,
    #[serde(default, skip_serializing_if = \"Option::is_none\")]
    pub source_event_id: Option<String>,
    #[serde(default, skip_serializing_if = \"Option::is_none\")]
    pub source_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = \"Option::is_none\")]
    pub source_emitted_at: Option<String>,
    pub eliot_session_id: Option<AgentSessionId>,
""",
    )

    engine = Path("crates/eliot-engine/src/host.rs")
    replace_once(
        engine,
        """        let tool_or_command = string_field(&value, &[\"tool\", \"tool_name\", \"command\"]);
        let changed_path_refs = [\"changed_path\", \"file_path\", \"path\"]
""",
        """        let tool_or_command = string_field(&value, &[\"tool\", \"tool_name\", \"command\"]);
        let source_event_id = string_field(&value, &[\"event_id\", \"eventId\"]);
        let source_sequence = value.get(\"sequence\").and_then(Value::as_u64);
        let source_emitted_at = string_field(&value, &[\"emitted_at\", \"emittedAt\"]);
        let changed_path_refs = [\"changed_path\", \"file_path\", \"path\"]
""",
    )
    replace_once(
        engine,
        """            host_id,
            host_session_id: string_field(&value, &[\"host_session_id\", \"session_id\"]),
            eliot_session_id: None,
""",
        """            host_id,
            host_session_id: string_field(&value, &[\"host_session_id\", \"session_id\"]),
            source_event_id,
            source_sequence,
            source_emitted_at,
            eliot_session_id: None,
""",
    )
    replace_once(
        engine,
        """}

#[derive(Clone, Copy, Debug, Default)]
pub struct HostBrokerService;
""",
        """}

#[cfg(test)]
mod host_event_tests {
    use super::HostEventService;
    use eliot_types::AgentHostId;

    #[test]
    fn opencode_source_identity_survives_normalization() {
        let raw = br#\"{
            \\"event_id\\": \\"opencode:tool.execute.after:native-42\\",
            \\"sequence\\": 17,
            \\"emitted_at\\": \\"2026-08-29T18:40:00.123Z\\",
            \\"event_kind\\": \\"tool.execute.after\\",
            \\"host_session_id\\": \\"session-7\\"
        }\"#;
        let event = HostEventService
            .normalize(AgentHostId::OpenCode, \"tool.execute.after\", raw)
            .expect(\"OpenCode event must normalize\");

        assert_eq!(
            event.source_event_id.as_deref(),
            Some(\"opencode:tool.execute.after:native-42\")
        );
        assert_eq!(event.source_sequence, Some(17));
        assert_eq!(
            event.source_emitted_at.as_deref(),
            Some(\"2026-08-29T18:40:00.123Z\")
        );
        assert_eq!(event.host_session_id.as_deref(), Some(\"session-7\"));
    }

    #[test]
    fn legacy_host_event_without_source_identity_remains_compatible() {
        let event = HostEventService
            .normalize(
                AgentHostId::Claude,
                \"session.created\",
                br#\"{\\"event_kind\\":\\"session.created\\"}\"#,
            )
            .expect(\"legacy event must normalize\");

        assert!(event.source_event_id.is_none());
        assert!(event.source_sequence.is_none());
        assert!(event.source_emitted_at.is_none());
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HostBrokerService;
""",
    )


if __name__ == "__main__":
    main()
