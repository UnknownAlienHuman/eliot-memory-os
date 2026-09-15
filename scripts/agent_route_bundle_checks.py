"Repository-level checks for agent runtime route bundles."
from __future__ import annotations

import json
import re
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

DISPOSITIONS = (
    "live-admitted",
    "unavailable-target",
    "compatibility-with-expiry",
    "removal",
)
IDENTITY_BLOCK_KEYS = ("identity", "bundle_identity", "generation")
_HEX_DIGEST_RE = re.compile(r"^[0-9a-f]+$")
_HEX_DIGEST_LENGTHS = frozenset({32, 40, 48, 64, 96, 128})
_DIGEST_NAME_RE = re.compile(r"(?:^|_)(sha256|sha512|sha384|sha1|md5|digest|hash|blake3)$")


def _digest_like(name: str) -> bool:
    return _DIGEST_NAME_RE.search(str(name).lower().replace("-", "_")) is not None


def _identity_node_errors(name: str, value: Any, where: str, out: list[Finding]) -> None:
    """Validate a Part A disposition/identity field generically.

    Digest-shaped fields must be well-formed lowercase hex, disposition fields
    must name a known disposition, and version fields must be non-empty strings.
    Anything else passes through so the identity schema can grow without a
    checker change. Malformed identity is a hard violation.
    """
    normalized = str(name).lower().replace("-", "_")
    if normalized == "disposition":
        if isinstance(value, dict):
            # Specified Part A shape is a disposition BLOCK carrying the scalar
            # under its own "disposition" key plus digests/versions/metadata.
            # Recurse so the inner scalar, digest-likes, and versions validate
            # exactly like a scalar disposition site. Anything else passes
            # through; a block never grants admission by itself.
            for key, child in value.items():
                if not isinstance(key, str) or not key:
                    add(out, "route_identity_malformed", where, "identity mapping requires string keys")
                    continue
                _identity_node_errors(key, child, where, out)
            return
        if value not in DISPOSITIONS:
            add(out, "route_disposition_invalid", where, repr(value))
        return
    if normalized in {"schema_version", "identity_version", "version"}:
        if not isinstance(value, str) or not value.strip():
            add(out, "route_identity_malformed", where, f"{name}: version must be a non-empty string")
        return
    if _digest_like(name):
        if isinstance(value, list):
            if not value:
                add(out, "route_identity_malformed", where, f"{name}: digest list is empty")
            for index, child in enumerate(value):
                _identity_node_errors(name, child, f"{where}#{name}[{index}]", out)
            return
        if (
            not isinstance(value, str)
            or len(value) not in _HEX_DIGEST_LENGTHS
            or _HEX_DIGEST_RE.match(value) is None
        ):
            add(out, "route_identity_malformed", where, f"{name}: malformed digest (expected lowercase hex)")
        return
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or not key:
                add(out, "route_identity_malformed", where, "identity mapping requires string keys")
                continue
            _identity_node_errors(key, child, where, out)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _identity_node_errors(name, child, f"{where}#{name}[{index}]", out)


def _effective_disposition(profile: Any) -> Any:
    """Return the scalar disposition whether declared bare or as a block."""
    disposition = profile.get("disposition") if isinstance(profile, dict) else None
    if isinstance(disposition, dict):
        return disposition.get("disposition")
    return disposition


def identity_errors(profile: Any, host: str, root: Path | None = None) -> list[Finding]:
    """Validate declared disposition/identity without ever granting admission.

    A `live-admitted` disposition on a NOT_EXECUTED static profile is treated as
    a forged admission claim: static files cannot mint route readiness.
    """
    relative = PROFILE.format(host=host)
    out: list[Finding] = []
    if not isinstance(profile, dict):
        return out
    _identity_node_errors("profile", profile, relative, out)
    if _effective_disposition(profile) == "live-admitted" and profile.get("evidence_execution_status") == "NOT_EXECUTED":
        add(
            out,
            "route_disposition_overclaim",
            relative,
            "static bundle cannot admit an unexecuted route",
        )
    return out


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
        "maximumPassiveQueue",
        "ELIOT_OPENCODE_PASSIVE_QUEUE_LIMIT",
        "passiveDepth >= maximumPassiveQueue()",
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
            out.extend(identity_errors(profile, host, root))
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
