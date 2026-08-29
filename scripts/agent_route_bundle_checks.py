"""Repository-level checks for agent runtime route bundles."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_route_contract import HOSTS, PROFILE, TOP, Finding, add, profile_errors

SCHEMA = "integrations/agent-runtimes/route-profile.schema.json"
README = "integrations/agent-runtimes/README.md"
PLUGIN = "integrations/opencode/plugins/eliot.js"
JUSTFILE = "Justfile"


def read_json(root: Path, relative: str, out: list[Finding]) -> dict[str, Any] | None:
    path = root / relative
    if not path.is_file():
        add(out, "file_missing", relative, "required JSON file is absent")
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        add(out, "json_invalid", relative, str(error))
        return None
    if not isinstance(value, dict):
        add(out, "json_root_invalid", relative, "root must be an object")
        return None
    return value


def plugin_errors(text: str) -> list[Finding]:
    out: list[Finding] = []
    markers = (
        "BRIDGE_ENV_KEYS", "bridgeEnvironment", "MAX_PASSIVE_QUEUE", "passiveQueue",
        "BRIDGE_TIMEOUT_MS", "waitForExit", "readBounded", "event_id", "sequence",
        "{ required: true }", "ELIOT ActionGate is unavailable",
        'enqueuePassive(client, "tool.execute.after"',
    )
    for marker in markers:
        if marker not in text:
            add(out, "opencode_plugin_marker_missing", PLUGIN, marker)
    if "env: process.env" in text:
        add(out, "opencode_full_env", PLUGIN, "whole host environment forwarded")
    if 'return { decision: "passive"' in text:
        add(out, "opencode_mutation_fail_open", PLUGIN, "missing bridge returns passive gate decision")
    return out


def verify(root: Path) -> list[Finding]:
    out: list[Finding] = []
    schema = read_json(root, SCHEMA, out)
    if schema:
        if schema.get("$id") != "https://eliot.local/schemas/agent-route-profile-v1.json":
            add(out, "schema_identity_invalid", SCHEMA, "unexpected $id")
        if TOP - set(schema.get("required", [])):
            add(out, "schema_required_gap", SCHEMA, "top-level required set is incomplete")
        enum = set(schema.get("properties", {}).get("host_family", {}).get("enum", []))
        if enum != set(HOSTS):
            add(out, "schema_host_set_invalid", SCHEMA, repr(sorted(enum)))
    for host in HOSTS:
        profile = read_json(root, PROFILE.format(host=host), out)
        if profile is not None:
            out.extend(profile_errors(profile, host, root))
    plugin_path = root / PLUGIN
    if not plugin_path.is_file():
        add(out, "opencode_plugin_missing", PLUGIN, "plugin is absent")
    else:
        out.extend(plugin_errors(plugin_path.read_text(encoding="utf-8")))
    support = {
        README: (
            "installing a plugin does not prove", "fixed_model_id", "durable mailbox",
            "concilium", "whole sibling transcripts",
        ),
        JUSTFILE: (
            "agent-route-bundles-self-test:", "agent-route-bundles:",
            "verify-agent-route-bundles.py",
        ),
    }
    for relative, markers in support.items():
        path = root / relative
        if not path.is_file():
            add(out, "support_file_missing", relative, "required support file is absent")
            continue
        text = path.read_text(encoding="utf-8")
        if relative == README:
            text = text.lower()
        for marker in markers:
            if marker not in text:
                add(out, "support_marker_missing", relative, marker)
    return sorted(out)
