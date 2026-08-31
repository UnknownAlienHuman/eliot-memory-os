#!/usr/bin/env python3
"""Verify the bounded core-daemon inventory projection.

This is a static routing/control-plane check. It validates the inventory's
identity, ownership references, proof requirements, and proof ceiling; it does
not establish runtime support or Product Proof.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


INVENTORY_RELATIVE = "workstreams/core-daemons/inventory.json"
EXPECTED_SCHEMA = "eliot.core-daemon-workstream.v4"
EXPECTED_NORMATIVE_PAIR = "sha256:105558fc8957e150fab407b4fc5818ec49dc784f23f246f42dc9d3ca5843196b"
EXPECTED_PRODUCT_STATUS = "NOT_ACCEPTED_UNVERIFIED"
EXPECTED_PROOF_CEILING = {
    "architecture_boundary_lint": "STATIC_SOURCE_BUILD_POLICY_ONLY",
    "nearest_path_guardrails": "ROUTING_CONTROL_PLANE_ONLY",
    "runtime_source_hygiene": "STATIC_SOURCE_QUALITY_SIGNALS_ONLY",
    "agent_bridge_protocol_policy": "STATIC_PROTOCOL_SOURCE_POLICY_ONLY",
    "package_build": "CURRENT_UNVERIFIED_UNLESS_EXECUTED_ON_EXACT_CANDIDATE",
    "edge": "NOT_EXECUTED",
    "windows_runtime": "NOT_EXECUTED",
    "store_runtime": "NOT_EXECUTED",
    "product_pulse": "NOT_EXECUTED",
    "support": "NOT_ACCEPTED",
}
KNOWN_OWNER_ISSUES = frozenset(
    {
        10,
        11,
        7,
        8,
        9,
        13,
        14,
        15,
        16,
        17,
        18,
        19,
        20,
        21,
        22,
        23,
        24,
        59,
        61,
        63,
        64,
        65,
        66,
        67,
        68,
        70,
        72,
        73,
        74,
        75,
        76,
        77,
        78,
        79,
        85,
        88,
        100,
        120,
        82,
        83,
        84,
    }
)
ALLOWED_RUNTIME_SUPPORT = frozenset({"CURRENT_UNVERIFIED", "NOT_EXECUTED", "BLOCKED"})
REQUIRED_UNIT_FIELDS = (
    "id",
    "process",
    "paths",
    "source_shape",
    "reusable_parts",
    "implementation_support",
    "runtime_support",
    "strategy",
    "main_nonconformant_boundary",
    "owner_issues",
    "next_causal_action",
    "proof_required",
)


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    detail: str


def _finding(code: str, path: str, detail: str) -> Finding:
    return Finding(code, path, detail)


def _string(value: Any, path: str, findings: list[Finding]) -> str:
    if not isinstance(value, str) or not value.strip():
        findings.append(_finding("inventory_shape", path, "expected a non-empty string"))
        return ""
    return value.strip()


def _nonempty_string_list(value: Any, path: str, findings: list[Finding]) -> list[str]:
    if not isinstance(value, list) or not value:
        findings.append(_finding("inventory_shape", path, "expected a non-empty string list"))
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(_string(item, f"{path}[{index}]", findings))
    return result


def _contains_excluded_capability(value: Any) -> bool:
    if isinstance(value, str):
        lowered = value.casefold()
        return "cognitive" in lowered or "dreamer" in lowered
    if isinstance(value, list):
        return any(_contains_excluded_capability(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_excluded_capability(item) for item in value.values())
    return False


def verify_payload(payload: Any) -> list[Finding]:
    """Return deterministic findings for one decoded inventory payload."""
    findings: list[Finding] = []
    if not isinstance(payload, dict):
        return [_finding("inventory_shape", "$", "inventory root must be an object")]

    if payload.get("schema") != EXPECTED_SCHEMA:
        findings.append(_finding("inventory_identity", "schema", f"expected {EXPECTED_SCHEMA}"))

    authority = payload.get("authority")
    if not isinstance(authority, dict):
        findings.append(_finding("inventory_shape", "authority", "expected an object"))
        authority = {}
    if authority.get("branch") != "main":
        findings.append(_finding("inventory_identity", "authority.branch", "inventory authority must be main"))
    if authority.get("normative_pair") != EXPECTED_NORMATIVE_PAIR:
        findings.append(
            _finding(
                "frozen_sha_mismatch",
                "authority.normative_pair",
                "inventory is not bound to the accepted normative-pair SHA",
            )
        )
    if authority.get("product_status") != EXPECTED_PRODUCT_STATUS:
        findings.append(
            _finding(
                "runtime_overclaim",
                "authority.product_status",
                f"expected {EXPECTED_PRODUCT_STATUS}; inventory cannot claim product support",
            )
        )
    source_rule = _string(authority.get("source_identity_rule"), "authority.source_identity_rule", findings)
    if "never freezes a source head" not in source_rule:
        findings.append(
            _finding(
                "frozen_sha_mismatch",
                "authority.source_identity_rule",
                "source identity rule must not freeze a source head",
            )
        )

    scope = payload.get("scope")
    if not isinstance(scope, dict):
        findings.append(_finding("inventory_shape", "scope", "expected an object"))
        scope = {}
    if scope.get("programme") != "core-daemons":
        findings.append(_finding("inventory_identity", "scope.programme", "inventory must belong to core-daemons"))
    if scope.get("integration_issue") != 11 or scope.get("registry_issue") != 13:
        findings.append(
            _finding(
                "unknown_owner",
                "scope",
                "core-daemon inventory must retain integration issue #11 and registry issue #13",
            )
        )
    excluded = scope.get("excluded_capabilities")
    if excluded != ["dreamer", "cognitive_micromodule_implementation"]:
        findings.append(
            _finding(
                "cognitive_leakage",
                "scope.excluded_capabilities",
                "core-daemon exclusions must retain Dreamer and cognitive micromodule implementation",
            )
        )
    if scope.get("work_rule") != "One issue, one causal change, one current-main branch, one PR, one mutable-path writer.":
        findings.append(_finding("inventory_identity", "scope.work_rule", "core-daemon work rule drifted"))

    if payload.get("proof_ceiling") != EXPECTED_PROOF_CEILING:
        findings.append(
            _finding(
                "proof_ceiling_drift",
                "proof_ceiling",
                "accepted core-daemon proof ceiling must remain unchanged",
            )
        )

    units = payload.get("units")
    if not isinstance(units, list) or not units:
        findings.append(_finding("inventory_shape", "units", "expected a non-empty list"))
        units = []

    seen_ids: set[str] = set()
    for index, unit in enumerate(units):
        path = f"units[{index}]"
        if not isinstance(unit, dict):
            findings.append(_finding("inventory_shape", path, "expected an object"))
            continue
        for field in REQUIRED_UNIT_FIELDS:
            if field not in unit:
                findings.append(_finding("inventory_shape", f"{path}.{field}", "required field is missing"))

        unit_id = _string(unit.get("id"), f"{path}.id", findings)
        if unit_id:
            if unit_id in seen_ids:
                findings.append(_finding("duplicate_id", f"{path}.id", f"unit id is repeated: {unit_id}"))
            seen_ids.add(unit_id)

        _string(unit.get("process"), f"{path}.process", findings)
        _nonempty_string_list(unit.get("paths"), f"{path}.paths", findings)
        _string(unit.get("source_shape"), f"{path}.source_shape", findings)
        _nonempty_string_list(unit.get("reusable_parts"), f"{path}.reusable_parts", findings)
        _string(unit.get("implementation_support"), f"{path}.implementation_support", findings)
        runtime_support = _string(unit.get("runtime_support"), f"{path}.runtime_support", findings)
        if runtime_support and runtime_support not in ALLOWED_RUNTIME_SUPPORT:
            findings.append(
                _finding(
                    "runtime_overclaim",
                    f"{path}.runtime_support",
                    f"runtime support value is outside the bounded non-claiming set: {runtime_support}",
                )
            )
        _string(unit.get("strategy"), f"{path}.strategy", findings)
        _string(unit.get("main_nonconformant_boundary"), f"{path}.main_nonconformant_boundary", findings)
        _string(unit.get("next_causal_action"), f"{path}.next_causal_action", findings)

        owner_issues = unit.get("owner_issues")
        if not isinstance(owner_issues, list) or not owner_issues:
            findings.append(_finding("unknown_owner", f"{path}.owner_issues", "at least one owner issue is required"))
        else:
            for owner_index, issue in enumerate(owner_issues):
                if not isinstance(issue, int) or issue not in KNOWN_OWNER_ISSUES:
                    findings.append(
                        _finding(
                            "unknown_owner",
                            f"{path}.owner_issues[{owner_index}]",
                            f"issue is not a current core-daemon owner: {issue!r}",
                        )
                    )

        proof_required = unit.get("proof_required")
        if not isinstance(proof_required, list) or not proof_required:
            findings.append(
                _finding(
                    "missing_proof",
                    f"{path}.proof_required",
                    "each inventory unit must name at least one required proof",
                )
            )
        else:
            for proof_index, proof in enumerate(proof_required):
                _string(proof, f"{path}.proof_required[{proof_index}]", findings)

        if _contains_excluded_capability(unit):
            findings.append(
                _finding(
                    "cognitive_leakage",
                    path,
                    "excluded cognitive/Dreamer capability leaked into a core-daemon unit",
                )
            )

    return sorted(findings, key=lambda item: (item.code, item.path, item.detail))


def load_inventory(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load core-daemon inventory: {error}") from error


def verify(root: Path) -> list[Finding]:
    path = root / INVENTORY_RELATIVE
    if not path.is_file():
        return [_finding("inventory_missing", INVENTORY_RELATIVE, "core-daemon inventory is missing")]
    try:
        return verify_payload(load_inventory(path))
    except ValueError as error:
        return [_finding("inventory_unreadable", INVENTORY_RELATIVE, str(error))]


def print_findings(findings: list[Finding]) -> None:
    for finding in findings:
        print(f"HARD_VIOLATION: {finding.code}: {finding.path}: {finding.detail}")


def _valid_fixture() -> dict[str, Any]:
    return {
        "schema": EXPECTED_SCHEMA,
        "authority": {
            "branch": "main",
            "normative_pair": EXPECTED_NORMATIVE_PAIR,
            "product_status": EXPECTED_PRODUCT_STATUS,
            "source_identity_rule": "Resolve exact current main at work start; this inventory never freezes a source head.",
        },
        "scope": {
            "programme": "core-daemons",
            "integration_issue": 11,
            "registry_issue": 13,
            "excluded_capabilities": ["dreamer", "cognitive_micromodule_implementation"],
            "work_rule": "One issue, one causal change, one current-main branch, one PR, one mutable-path writer.",
        },
        "proof_ceiling": copy.deepcopy(EXPECTED_PROOF_CEILING),
        "units": [
            {
                "id": "fixture",
                "process": "fixture.exe",
                "paths": ["bins/fixture"],
                "source_shape": "A bounded fixture unit exists.",
                "reusable_parts": ["fixture core"],
                "implementation_support": "CURRENT_PARTIAL",
                "runtime_support": "CURRENT_UNVERIFIED",
                "strategy": "KEEP_AND_HARDEN",
                "main_nonconformant_boundary": "Runtime proof remains unexecuted.",
                "owner_issues": [13],
                "next_causal_action": "Run the bounded proof.",
                "proof_required": ["fixture Module Proof"],
            }
        ],
    }


def _expect_only(payload: dict[str, Any], code: str) -> None:
    findings = verify_payload(payload)
    codes = {finding.code for finding in findings}
    if codes != {code}:
        raise AssertionError(f"expected only {code}, got {sorted(codes)}: {findings}")


def self_test() -> None:
    cases: list[tuple[str, str, Any]] = []

    duplicate = _valid_fixture()
    duplicate["units"].append(copy.deepcopy(duplicate["units"][0]))
    cases.append(("duplicate ID", "duplicate_id", duplicate))

    frozen = _valid_fixture()
    frozen["authority"]["normative_pair"] = "sha256:wrong"
    cases.append(("frozen SHA", "frozen_sha_mismatch", frozen))

    missing_proof = _valid_fixture()
    missing_proof["units"][0]["proof_required"] = []
    cases.append(("missing proof", "missing_proof", missing_proof))

    runtime_overclaim = _valid_fixture()
    runtime_overclaim["units"][0]["runtime_support"] = "CURRENT_VERIFIED"
    cases.append(("runtime overclaim", "runtime_overclaim", runtime_overclaim))

    unknown_owner = _valid_fixture()
    unknown_owner["units"][0]["owner_issues"] = [999]
    cases.append(("unknown owner", "unknown_owner", unknown_owner))

    cognitive_leakage = _valid_fixture()
    cognitive_leakage["units"][0]["paths"] = ["crates/smart/cognitive-field"]
    cases.append(("cognitive leakage", "cognitive_leakage", cognitive_leakage))

    clean = verify_payload(_valid_fixture())
    if clean:
        raise AssertionError(f"valid inventory fixture failed: {clean}")
    for case, code, payload in cases:
        _expect_only(payload, code)
        print(f"INVENTORY_FIXTURE: {case}: FAILS_AS={code}")
    print(f"CORE_DAEMON_INVENTORY_SELF_TEST: PASS cases={len(cases)}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        self_test()
        return 0

    findings = verify(args.root.resolve())
    if findings:
        print_findings(findings)
        return 1
    print(
        "CORE_DAEMON_INVENTORY_VERIFY: PASS "
        f"source={INVENTORY_RELATIVE} proof_ceiling=preserved"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
