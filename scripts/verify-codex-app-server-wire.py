#!/usr/bin/env python3
"""Verify the bounded Codex App Server stable-wire diagnostic source."""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

MODULE = Path("crates/agent/eliot-agent-codex/src/app_server_stable_wire.rs")
BINARY = Path("crates/agent/eliot-agent-codex/src/bin/codex_app_server_preflight.rs")
CONTRACT = Path("integrations/codex/app-server-stable-wire.json")
PROFILE = Path("integrations/codex/route-profile.json")
JUSTFILE = Path("Justfile")


@dataclass(frozen=True, order=True)
class Finding:
    code: str
    path: str
    detail: str


def function_block(text: str, signature: str) -> str | None:
    start = text.find(signature)
    if start < 0:
        return None
    brace = text.find("{", start)
    if brace < 0:
        return None
    depth = 0
    for index in range(brace, len(text)):
        character = text[index]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return None


def add(findings: list[Finding], code: str, path: Path, detail: str) -> None:
    findings.append(Finding(code, path.as_posix(), detail))


def check_texts(texts: Mapping[Path, str]) -> list[Finding]:
    findings: list[Finding] = []
    module = texts.get(MODULE)
    binary = texts.get(BINARY)
    justfile = texts.get(JUSTFILE)
    profile_text = texts.get(PROFILE)

    if module is None:
        add(findings, "codex_wire_module_missing", MODULE, "stable wire module is absent")
    else:
        initialize = function_block(module, "pub fn initialize_request(")
        if initialize is None:
            add(findings, "codex_initialize_missing", MODULE, "initialize constructor is absent")
        else:
            for marker in ['"initialize"', '"clientInfo"']:
                if marker not in initialize:
                    add(findings, "codex_initialize_marker_missing", MODULE, marker)
            for forbidden in ["jsonrpc", "protocolVersion", "experimentalApi"]:
                if forbidden in initialize:
                    add(findings, "codex_initialize_forbidden_member", MODULE, forbidden)

        initialized = function_block(module, "pub fn initialized_notification()")
        if initialized is None or '"initialized"' not in initialized:
            add(findings, "codex_initialized_missing", MODULE, "initialized notification is absent")
        elif '"id"' in initialized:
            add(findings, "codex_initialized_has_id", MODULE, "initialized must be a notification")

        model_list = function_block(module, "pub fn model_list_request(")
        if model_list is None:
            add(findings, "codex_model_list_missing", MODULE, "model/list constructor is absent")
        else:
            for marker in ['"model/list"', '"cursor"', '"limit"', '"includeHidden"']:
                if marker not in model_list:
                    add(findings, "codex_model_list_marker_missing", MODULE, marker)
            if "jsonrpc" in model_list:
                add(findings, "codex_model_list_jsonrpc", MODULE, "model/list writes jsonrpc")

        for marker in [
            "JsonRpcHeaderPresent",
            "ResponseIdMismatch",
            "DuplicateModelId",
            "CursorLoop",
            "MaximumPagesExceeded",
            "MaximumModelsExceeded",
            "supported_reasoning_efforts",
            "default_reasoning_effort",
            "input_modalities",
            "is_default",
            'contains_key("nextCursor")',
            "server_error_does_not_expose_provider_message",
        ]:
            if marker not in module:
                add(findings, "codex_wire_guard_missing", MODULE, marker)
        for forbidden in ['"thread/start"', '"turn/start"', '"turn/interrupt"']:
            if forbidden in module:
                add(findings, "codex_preflight_exec_method", MODULE, forbidden)

    if binary is None:
        add(findings, "codex_preflight_binary_missing", BINARY, "diagnostic binary is absent")
    else:
        for marker in [
            "--emit-requests-only",
            "--validate-model-pages",
            "initialize_request",
            "initialized_notification",
        ]:
            if marker not in binary:
                add(findings, "codex_preflight_marker_missing", BINARY, marker)
        for forbidden in [
            "Command::new",
            "std::process::Command",
            "tokio::process",
            "thread/start",
            "turn/start",
        ]:
            if forbidden in binary:
                add(findings, "codex_preflight_spawns_provider", BINARY, forbidden)

    if justfile is None:
        add(findings, "justfile_missing", JUSTFILE, "Justfile is absent")
    else:
        for marker in [
            "codex-app-server-wire-self-test:",
            "codex-app-server-wire:",
            "verify-codex-app-server-wire.py",
        ]:
            if marker not in justfile:
                add(findings, "codex_just_target_missing", JUSTFILE, marker)

    if profile_text is None:
        add(findings, "codex_route_profile_missing", PROFILE, "route profile is absent")
    else:
        try:
            profile = json.loads(profile_text)
        except json.JSONDecodeError as error:
            add(findings, "codex_route_profile_invalid", PROFILE, str(error))
        else:
            if profile.get("implementation_support") != "PARTIAL":
                add(findings, "codex_route_profile_support", PROFILE, "expected PARTIAL")
            if profile.get("evidence_execution_status") != "NOT_EXECUTED":
                add(findings, "codex_route_profile_execution", PROFILE, "must remain NOT_EXECUTED")
            rendered = json.dumps(profile, sort_keys=True)
            for marker in [
                "initialize -> initialized -> model/list",
                "production adapter still uses the stale wire owner",
            ]:
                if marker not in rendered:
                    add(findings, "codex_route_profile_marker_missing", PROFILE, marker)

    contract_text = texts.get(CONTRACT)
    if contract_text is None:
        add(findings, "codex_contract_missing", CONTRACT, "stable wire contract is absent")
    else:
        try:
            contract = json.loads(contract_text)
        except json.JSONDecodeError as error:
            add(findings, "codex_contract_invalid", CONTRACT, str(error))
        else:
            if contract.get("schema_version") != "eliot.codex-app-server-stable-wire.v1":
                add(findings, "codex_contract_version", CONTRACT, "unexpected schema version")
            if contract.get("evidence_execution_status") != "NOT_EXECUTED":
                add(findings, "codex_contract_execution", CONTRACT, "must remain NOT_EXECUTED")
            if contract.get("executes_model") is not False:
                add(findings, "codex_contract_model_execution", CONTRACT, "executes_model must be false")
            if contract.get("production_route_admission") is not False:
                add(findings, "codex_contract_route_admission", CONTRACT, "production admission must be false")
            source = contract.get("upstream_schema_identity", {})
            if source.get("repository") != "openai/codex" or not source.get("commit_sha"):
                add(findings, "codex_contract_upstream_identity", CONTRACT, "pinned official source is required")

    return sorted(findings)


def load_texts(root: Path) -> dict[Path, str]:
    texts: dict[Path, str] = {}
    for relative in [MODULE, BINARY, CONTRACT, PROFILE, JUSTFILE]:
        path = root / relative
        if path.is_file():
            texts[relative] = path.read_text(encoding="utf-8")
    return texts


def self_test(root: Path) -> None:
    clean = load_texts(root)
    findings = check_texts(clean)
    if findings:
        raise AssertionError(f"clean fixture failed: {findings}")

    cases: list[tuple[str, Path, str, str, str]] = [
        (
            "initialize_protocol_version",
            MODULE,
            'client_info.insert("name"',
            'let protocolVersion = "stale";\n    client_info.insert("name"',
            "codex_initialize_forbidden_member",
        ),
        (
            "provider_spawn",
            BINARY,
            "fn emit_requests()",
            "fn emit_requests() /* Command::new */",
            "codex_preflight_spawns_provider",
        ),
        (
            "missing_next_cursor_guard",
            MODULE,
            'contains_key("nextCursor")',
            'contains_key("removedCursor")',
            "codex_wire_guard_missing",
        ),
    ]
    for name, path, old, new, expected in cases:
        mutated = dict(clean)
        if old not in mutated[path]:
            raise AssertionError(f"self-test marker missing for {name}")
        mutated[path] = mutated[path].replace(old, new, 1)
        codes = {finding.code for finding in check_texts(mutated)}
        if expected not in codes:
            raise AssertionError(f"{name}: expected {expected}, got {sorted(codes)}")
    print(f"CODEX_APP_SERVER_WIRE_SELF_TEST: PASS cases={len(cases)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    if args.self_test:
        self_test(root)
        return 0
    findings = check_texts(load_texts(root))
    if findings:
        for finding in findings:
            print(f"HARD_VIOLATION: {finding.code}: {finding.path}: {finding.detail}")
        return 1
    print("CODEX_APP_SERVER_WIRE_VERIFY: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
