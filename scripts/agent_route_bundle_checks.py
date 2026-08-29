"Repository-level checks for agent runtime route bundles."
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_route_contract import HOSTS, PROFILE, TOP, Finding, add, profile_errors

try:
    from jsonschema import Draft202012Validator, FormatChecker
    from jsonschema.exceptions import SchemaError
except ImportError:  # pragma: no cover - reported as a hard verifier failure below.
    Draft202012Validator = None
    FormatChecker = None
    SchemaError = Exception

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


def json_pointer(parts: Any) -> str:
    encoded = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "/" + "/".join(encoded) if encoded else "/"


def schema_validator(schema: dict[str, Any], out: list[Finding]):
    if Draft202012Validator is None or FormatChecker is None:
        add(
            out,
            "schema_validator_unavailable",
            SCHEMA,
            "install scripts/requirements-verification.txt before running route verification",
        )
        return None
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as error:
        add(out, "schema_definition_invalid", SCHEMA, error.message)
        return None
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_profile_schema(
    validator: Any,
    profile: dict[str, Any],
    relative: str,
    out: list[Finding],
) -> None:
    if validator is None:
        return
    errors = sorted(
        validator.iter_errors(profile),
        key=lambda error: (tuple(str(part) for part in error.absolute_path), error.message),
    )
    for error in errors:
        add(
            out,
            "profile_schema_invalid",
            f"{relative}#{json_pointer(error.absolute_path)}",
            error.message,
        )


def plugin_errors(text: str) -> list[Finding]:
    out: list[Finding] = []
    markers = (
        "BRIDGE_ENV_KEYS",
        "ELIOT_WORK_LEASE_ID",
        "bridgeEnvironment",
        "MAX_PASSIVE_QUEUE",
        "passiveQueue",
        "BRIDGE_TIMEOUT_MS",
        "waitForExit",
        "boundedDrain",
        "settleDrain",
        "event_id",
        "sequence",
        "emitted_at",
        "await child.stdin.write",
        "await child.stdin.end",
        "notePassiveOverflow",
        "{ required: true }",
        "ELIOT ActionGate is unavailable",
        'enqueuePassive(client, "tool.execute.after"',
    )
    for marker in markers:
        if marker not in text:
            add(out, "opencode_plugin_marker_missing", PLUGIN, marker)
    if "env: process.env" in text:
        add(out, "opencode_full_env", PLUGIN, "whole host environment forwarded")
    if 'return { decision: "passive"' in text:
        add(out, "opencode_mutation_fail_open", PLUGIN, "missing bridge returns passive gate decision")
    if "globalThis.crypto?.randomUUID" in text:
        add(out, "opencode_nondurable_event_identity", PLUGIN, "event identity is random on every retry")
    if "Promise.all([stdout, stderr])" in text:
        add(out, "opencode_unbounded_stream_wait", PLUGIN, "bridge drains can wait forever after timeout")
    return out



def verify(root: Path) -> list[Finding]:
    out: list[Finding] = []
    schema = read_json(root, SCHEMA, out)
    validator = None
    if schema:
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            add(out, "schema_dialect_invalid", SCHEMA, "expected Draft 2020-12")
        if schema.get("$id") != "https://eliot.local/schemas/agent-route-profile-v1.json":
            add(out, "schema_identity_invalid", SCHEMA, "unexpected $id")
        if TOP - set(schema.get("required", [])):
            add(out, "schema_required_gap", SCHEMA, "top-level required set is incomplete")
        enum = set(schema.get("properties", {}).get("host_family", {}).get("enum", []))
        if enum != set(HOSTS):
            add(out, "schema_host_set_invalid", SCHEMA, repr(sorted(enum)))
        validator = schema_validator(schema, out)
    for host in HOSTS:
        relative = PROFILE.format(host=host)
        profile = read_json(root, relative, out)
        if profile is not None:
            validate_profile_schema(validator, profile, relative, out)
            out.extend(profile_errors(profile, host, root))
    plugin_path = root / PLUGIN
    if not plugin_path.is_file():
        add(out, "opencode_plugin_missing", PLUGIN, "plugin is absent")
    else:
        out.extend(plugin_errors(plugin_path.read_text(encoding="utf-8")))
    support = {
        README: (
            "installing a plugin does not prove",
            "fixed_model_id",
            "durable mailbox",
            "concilium",
            "whole sibling transcripts",
        ),
        JUSTFILE: (
            "agent-route-bundles-self-test:",
            "agent-route-bundles:",
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
