#!/usr/bin/env python3
"""Verify deterministic, secret-free host bundle materialization."""
from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, Callable

from agent_host_bundle import (
    BundleError,
    INDEX_VERSION,
    MANIFEST_PATH,
    directory_digest,
    materialize_host_bundle,
)

HOSTS = ("codex", "opencode", "claude", "antigravity")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{path}: expected object")
    return value


def _assert_bundle(path: Path, host: str, receipt: dict[str, Any]) -> None:
    operator = path / "operator"
    host_root = path / "host"
    if not operator.is_dir() or not host_root.is_dir():
        raise AssertionError(f"{host}: host/operator split is missing")
    index = _read_json(operator / "skill-index.json")
    if index.get("schema_version") != INDEX_VERSION or index.get("host") != host:
        raise AssertionError(f"{host}: Skill index identity mismatch")
    if index.get("delivery") != "lazy":
        raise AssertionError(f"{host}: Skill index is not lazy")
    entries = index.get("entries")
    if not isinstance(entries, list) or not entries:
        raise AssertionError(f"{host}: Skill index is empty")
    for entry in entries:
        if not isinstance(entry, dict):
            raise AssertionError(f"{host}: malformed Skill index entry")
        if set(entry) != {
            "name",
            "trigger_description",
            "body_sha256",
            "relative_body",
            "references_loaded",
        }:
            raise AssertionError(f"{host}: Skill index leaked non-index payload")
        relative_body = entry["relative_body"]
        if not isinstance(relative_body, str) or not relative_body.startswith("host/"):
            raise AssertionError(f"{host}: invalid Skill body reference")
        body = path / relative_body
        if not body.is_file():
            raise AssertionError(f"{host}: staged Skill body is missing")
        if entry["references_loaded"] != "on_reference":
            raise AssertionError(f"{host}: Skill references are not lazy")
    route = _read_json(operator / "route-profile.json")
    if route.get("host_family") != host:
        raise AssertionError(f"{host}: operator route profile mismatch")
    plan = _read_json(operator / "install-plan.json")
    if plan.get("overwrite_existing") is not False:
        raise AssertionError(f"{host}: install plan permits overwrite")
    if plan.get("copy_credentials") is not False or plan.get("copy_runtime_state") is not False:
        raise AssertionError(f"{host}: install plan permits sensitive state copy")
    if plan.get("post_copy_route_admission_required") is not True:
        raise AssertionError(f"{host}: route admission is not required")
    if receipt.get("contains_credentials") is not False:
        raise AssertionError(f"{host}: receipt claims credentials")
    if receipt.get("contains_runtime_state") is not False:
        raise AssertionError(f"{host}: receipt claims runtime state")
    if receipt.get("provider_executions") != 0 or receipt.get("route_admitted") is not False:
        raise AssertionError(f"{host}: package proof overclaimed runtime behavior")
    for forbidden in (".env", "credentials.json", "secrets.json", "id_rsa", "id_ed25519"):
        if any(candidate.name.lower() == forbidden for candidate in path.rglob("*")):
            raise AssertionError(f"{host}: forbidden file entered bundle")


def verify_current_tree(root: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="eliot-host-bundles-") as temporary:
        scratch = Path(temporary)
        for host in HOSTS:
            first = scratch / f"{host}-a"
            second = scratch / f"{host}-b"
            receipt_a = materialize_host_bundle(root, host, first)
            receipt_b = materialize_host_bundle(root, host, second)
            _assert_bundle(first, host, receipt_a)
            _assert_bundle(second, host, receipt_b)
            if receipt_a != receipt_b:
                raise AssertionError(f"{host}: receipt is nondeterministic")
            if directory_digest(first) != directory_digest(second):
                raise AssertionError(f"{host}: bundle bytes are nondeterministic")


def _route_profile(host: str) -> dict[str, Any]:
    return {
        "schema_version": "eliot.agent-route-profile.v1",
        "profile_id": f"{host}.test",
        "host_family": host,
        "execution_routes": [
            {
                "role": "primary_candidate",
                "launch": {
                    "argv_construction": "typed_no_shell",
                    "shell": False,
                    "environment_policy": "allowlist",
                },
                "model_selection": {
                    "fixed_model_id": None,
                    "per_attempt_receipt": True,
                },
            }
        ],
        "skills": {
            "canonical_source": "integrations/agent-skills",
            "delivery": "lazy",
        },
        "mcp": {
            "raw_store_access": False,
            "tool_visibility": "task_relative_lazy",
        },
        "coordination": {
            "message_transport": "durable_mailbox",
            "meeting_form": "concilium_over_sealed_evidence",
        },
    }


def _synthetic_root() -> Path:
    root = Path(tempfile.mkdtemp(prefix="eliot-host-bundle-self-test-"))
    (root / "integrations/agent-runtimes").mkdir(parents=True)
    (root / "integrations/agent-skills/eliot-work/references").mkdir(parents=True)
    (root / "integrations/agent-skills/eliot-work/SKILL.md").write_text(
        "# Work\n\nUse this procedure for a bounded ELIOT work item.\n",
        encoding="utf-8",
    )
    (root / "integrations/agent-skills/eliot-work/references/contract.md").write_text(
        "Reference loaded only when requested.\n",
        encoding="utf-8",
    )
    (root / "integrations/agent-skills/skill-pack.manifest.json").write_text(
        json.dumps(
            {
                "skills": [
                    {
                        "name": "eliot-work",
                        "trigger_description": "Use for a bounded ELIOT work item.",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    hosts: dict[str, Any] = {}
    for host in HOSTS:
        route = root / f"integrations/{host}/route-profile.json"
        route.parent.mkdir(parents=True)
        route.write_text(json.dumps(_route_profile(host)), encoding="utf-8")
        payload = root / f"fixtures/{host}/plugin.json"
        payload.parent.mkdir(parents=True)
        payload.write_text(json.dumps({"name": f"eliot-{host}"}), encoding="utf-8")
        hosts[host] = {
            "route_profile": f"integrations/{host}/route-profile.json",
            "destination_hint": f"{host.upper()}_ROOT/eliot",
            "skill_destination": "skills",
            "payload": [
                {
                    "source": f"fixtures/{host}/plugin.json",
                    "destination": "plugin.json",
                    "kind": "file",
                }
            ],
        }
    manifest = {
        "schema_version": "eliot.agent-host-bundle-manifest.v1",
        "canonical_skill_root": "integrations/agent-skills",
        "canonical_skill_manifest": "integrations/agent-skills/skill-pack.manifest.json",
        "limits": {
            "max_file_bytes": 65536,
            "max_bundle_bytes": 1048576,
            "max_files": 64,
        },
        "hosts": hosts,
    }
    (root / MANIFEST_PATH).write_text(json.dumps(manifest), encoding="utf-8")
    return root


def _expect_failure(case: str, operation: Callable[[], object]) -> None:
    try:
        operation()
    except BundleError:
        return
    raise AssertionError(f"self-test case did not fail closed: {case}")


def self_test() -> None:
    root = _synthetic_root()
    try:
        with tempfile.TemporaryDirectory(prefix="eliot-host-bundle-self-output-") as temporary:
            scratch = Path(temporary)
            first = scratch / "first"
            second = scratch / "second"
            receipt_a = materialize_host_bundle(root, "codex", first)
            receipt_b = materialize_host_bundle(root, "codex", second)
            if receipt_a != receipt_b or directory_digest(first) != directory_digest(second):
                raise AssertionError("deterministic materialization failed")
            _assert_bundle(first, "codex", receipt_a)

            secret_payload = root / "fixtures/codex/plugin.json"
            original_payload = secret_payload.read_text(encoding="utf-8")
            secret_payload.write_text(json.dumps({"api_key": "sk-test-material-must-not-ship-123456789"}), encoding="utf-8")
            _expect_failure(
                "literal secret",
                lambda: materialize_host_bundle(root, "codex", scratch / "secret"),
            )
            secret_payload.write_text(original_payload, encoding="utf-8")

            route_path = root / "integrations/codex/route-profile.json"
            route = _read_json(route_path)
            route["execution_routes"][0]["model_selection"]["fixed_model_id"] = "hard-coded"
            route_path.write_text(json.dumps(route), encoding="utf-8")
            _expect_failure(
                "fixed model",
                lambda: materialize_host_bundle(root, "codex", scratch / "fixed-model"),
            )
            route_path.write_text(json.dumps(_route_profile("codex")), encoding="utf-8")

            manifest_path = root / MANIFEST_PATH
            manifest = _read_json(manifest_path)
            manifest["hosts"]["codex"]["payload"][0]["source"] = "../escape.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            _expect_failure(
                "path traversal",
                lambda: materialize_host_bundle(root, "codex", scratch / "escape"),
            )
            manifest = _read_json(manifest_path)
            manifest["hosts"]["codex"]["payload"][0]["source"] = "fixtures/codex/plugin.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            occupied = scratch / "occupied"
            occupied.mkdir()
            (occupied / "keep.txt").write_text("do not overwrite", encoding="utf-8")
            _expect_failure(
                "non-empty output",
                lambda: materialize_host_bundle(root, "codex", occupied),
            )
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    if arguments.self_test:
        self_test()
        print("AGENT_HOST_BUNDLES_SELF_TEST: PASS cases=5")
    else:
        verify_current_tree(arguments.root.resolve())
        print("AGENT_HOST_BUNDLES_VERIFY: PASS hosts=4")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
