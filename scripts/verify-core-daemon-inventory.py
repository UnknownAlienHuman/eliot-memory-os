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
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


INVENTORY_RELATIVE = "workstreams/core-daemons/inventory.json"
ACTIVE_RELATIVE = "workstreams/ACTIVE.toml"
EXPECTED_SCHEMA = "eliot.core-daemon-workstream.v4"
EXPECTED_NORMATIVE_PAIR = "sha256:105558fc8957e150fab407b4fc5818ec49dc784f23f246f42dc9d3ca5843196b"
EXPECTED_PRODUCT_STATUS = "NOT_ACCEPTED_UNVERIFIED"
EXPECTED_SOURCE_IDENTITY_RULE = (
    "Resolve exact current main at work start and record base/candidate SHAs in issue/PR evidence; "
    "this inventory never freezes a source head."
)
FORBIDDEN_FROZEN_IDENTITY_FIELDS = ("source_sha", "head_sha", "source_audit_base")
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
EXPECTED_ACTIVE_BRANCH_POLICY = {
    "new_branch_pattern": "^(work|fix|docs|chore|refactor|test)/[0-9]+-[a-z0-9]+(?:-[a-z0-9]+)*$",
    "standard_branch_requires_open_issue": True,
    "requires_current_main_ancestor": True,
    "one_issue_one_branch_one_pr": True,
    "nonstandard_branch_requires_explicit_exception": True,
    "merged_or_closed_branch_is_retired": True,
    "unlisted_branch_mutation_allowed": False,
}
EXPECTED_ACTIVE_CORE_DAEMON_FIELDS = {
    "id": "core-daemons",
    "status": "active",
    "branch_strategy": "fresh_per_issue_from_current_main",
    "issue_refs": [13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24],
    "integration_issue_refs": [11],
    "briefs": ["workstreams/core-daemons/AGENTS.md"],
    "inventories": ["workstreams/core-daemons/inventory.json"],
    "excluded_capabilities": ["dreamer"],
}
EXPECTED_ACTIVE_RETIRED_REFS = {
    "status": "non_mutable_aliases_of_main",
    "physical_delete_supported": False,
    "rule": "Visible legacy refs may remain because the connected GitHub surface cannot delete refs. They are forced to current main and are never valid work branches.",
    "branches": [
        "audit/core-daemon-conformance-20260828",
        "chore/28-repository-hygiene",
        "chore/32-finalize-branch-state",
        "chore/32-retire-stale-branches",
        "chore/32-sync-cognitive-authority",
        "chore/48-control-plane-cleanup",
        "claude/codex-swarm-audit-p576l9",
        "claude/eliot-search-architecture-45fdpe",
        "claude/loving-wozniak-tw3r2s",
        "cognitive-crates-prototypes-01",
        "cognitive-materialize-run",
        "cognitive-micromodules-wave-01",
        "docs/related-repositories",
    ],
}
EXPECTED_FACADES = [
    {
        "path": "crates/eliot-app",
        "status": "LEGACY_MIGRATION_REGRESSION_FACADE",
        "owner_issue": 18,
        "rule": "No new semantic/state/effect owner; every consumer is migrated, bounded as fixture, or deleted.",
    },
    {
        "path": "crates/eliot-engine",
        "status": "LEGACY_DOMAIN_DONOR_FACADE",
        "owner_issue": 18,
        "rule": "Extract only a proven current causal cell; never extend as a second Governor.",
    },
    {
        "path": "crates/eliot-store",
        "status": "LEGACY_STORE_FACADE",
        "owner_issue": 19,
        "rule": "Cannot bypass current store API/bridge or become a second storage owner.",
    },
    {
        "path": "crates/eliot-types",
        "status": "LEGACY_TYPE_FACADE",
        "owner_issue": 13,
        "rule": "Do not grow an unbounded common-type owner.",
    },
    {
        "path": "crates/eliot-windows-ipc",
        "status": "LEGACY_IPC_COMPATIBILITY_FACADE",
        "owner_issue": 15,
        "rule": "Current IPC/process ownership remains in declared Kernel/platform/surface contracts.",
    },
]
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


def _frozen_identity_findings(value: Any, path: str = "$") -> list[Finding]:
    findings: list[Finding] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key in FORBIDDEN_FROZEN_IDENTITY_FIELDS:
                findings.append(
                    _finding(
                        "frozen_sha_mismatch",
                        child_path,
                        "inventory must not freeze source or candidate identity",
                    )
                )
            findings.extend(_frozen_identity_findings(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(_frozen_identity_findings(child, f"{path}[{index}]"))
    return findings


def verify_active_registry(registry: Any) -> list[Finding]:
    """Return deterministic findings for the current ACTIVE registry contract."""
    findings: list[Finding] = []
    if not isinstance(registry, dict):
        return [_finding("active_registry_shape", "$", "ACTIVE registry root must be a TOML table")]

    if registry.get("schema") != "eliot.active-workstreams.v1":
        findings.append(_finding("active_registry_identity", "schema", "ACTIVE registry schema drifted"))
    if registry.get("authority_branch") != "main":
        findings.append(_finding("active_registry_identity", "authority_branch", "ACTIVE registry authority must be main"))

    branch_policy = registry.get("branch_policy")
    if branch_policy != EXPECTED_ACTIVE_BRANCH_POLICY:
        findings.append(
            _finding(
                "active_registry_identity",
                "branch_policy",
                "ACTIVE branch policy drifted",
            )
        )

    workstreams = registry.get("workstream")
    if not isinstance(workstreams, list):
        findings.append(_finding("active_registry_shape", "workstream", "ACTIVE workstream must be an array of tables"))
        workstreams = []
    core_daemon_matches = [
        item for item in workstreams if isinstance(item, dict) and item.get("id") == "core-daemons"
    ]
    if len(core_daemon_matches) != 1:
        detail = "core-daemons workstream is missing" if not core_daemon_matches else "core-daemons workstream is duplicated"
        findings.append(_finding("active_registry_identity", "workstream", detail))
    else:
        core_daemons = core_daemon_matches[0]
        for field, expected in EXPECTED_ACTIVE_CORE_DAEMON_FIELDS.items():
            if core_daemons.get(field) != expected:
                findings.append(
                    _finding(
                        "active_registry_identity",
                        f"workstream[id=core-daemons].{field}",
                        "current core-daemons registry binding drifted",
                    )
                )

    retired_refs = registry.get("retired_refs")
    if retired_refs != EXPECTED_ACTIVE_RETIRED_REFS:
        findings.append(
            _finding(
                "active_registry_identity",
                "retired_refs",
                "ACTIVE retired-reference registry drifted",
            )
        )

    return sorted(findings, key=lambda item: (item.code, item.path, item.detail))


def verify_payload(payload: Any, active_registry: Any | None = None) -> list[Finding]:
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
    findings.extend(_frozen_identity_findings(payload))
    source_rule = _string(authority.get("source_identity_rule"), "authority.source_identity_rule", findings)
    if source_rule != EXPECTED_SOURCE_IDENTITY_RULE:
        findings.append(
            _finding(
                "frozen_sha_mismatch",
                "authority.source_identity_rule",
                "source identity rule must preserve current-main resolution without frozen identity fields",
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

    if payload.get("retired_or_migration_facades") != EXPECTED_FACADES:
        findings.append(
            _finding(
                "facade_registry_mismatch",
                "retired_or_migration_facades",
                "retired and migration facade registry drifted",
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

    if active_registry is not None:
        findings.extend(verify_active_registry(active_registry))

    return sorted(findings, key=lambda item: (item.code, item.path, item.detail))


def load_inventory(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load core-daemon inventory: {error}") from error


def load_active_registry(path: Path) -> Any:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ValueError(f"cannot load ACTIVE registry: {error}") from error


def verify(root: Path) -> list[Finding]:
    inventory_path = root / INVENTORY_RELATIVE
    active_path = root / ACTIVE_RELATIVE
    findings: list[Finding] = []
    if not active_path.is_file():
        findings.append(_finding("active_registry_missing", ACTIVE_RELATIVE, "ACTIVE registry is missing"))
        active_registry = None
    else:
        try:
            active_registry = load_active_registry(active_path)
        except ValueError as error:
            findings.append(_finding("active_registry_unreadable", ACTIVE_RELATIVE, str(error)))
            active_registry = None

    if not inventory_path.is_file():
        findings.append(_finding("inventory_missing", INVENTORY_RELATIVE, "core-daemon inventory is missing"))
        return sorted(findings, key=lambda item: (item.code, item.path, item.detail))
    try:
        findings.extend(verify_payload(load_inventory(inventory_path), active_registry))
    except ValueError as error:
        findings.append(_finding("inventory_unreadable", INVENTORY_RELATIVE, str(error)))
    return sorted(findings, key=lambda item: (item.code, item.path, item.detail))


def print_findings(findings: list[Finding]) -> None:
    for finding in findings:
        print(f"HARD_VIOLATION: {finding.code}: {finding.path}: {finding.detail}")


def _valid_active_registry() -> dict[str, Any]:
    return {
        "schema": "eliot.active-workstreams.v1",
        "authority_branch": "main",
        "branch_policy": copy.deepcopy(EXPECTED_ACTIVE_BRANCH_POLICY),
        "workstream": [copy.deepcopy(EXPECTED_ACTIVE_CORE_DAEMON_FIELDS)],
        "retired_refs": copy.deepcopy(EXPECTED_ACTIVE_RETIRED_REFS),
    }


def _valid_fixture() -> dict[str, Any]:
    return {
        "schema": EXPECTED_SCHEMA,
        "authority": {
            "branch": "main",
            "normative_pair": EXPECTED_NORMATIVE_PAIR,
            "product_status": EXPECTED_PRODUCT_STATUS,
            "source_identity_rule": EXPECTED_SOURCE_IDENTITY_RULE,
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
        "retired_or_migration_facades": copy.deepcopy(EXPECTED_FACADES),
    }


def _expect_only(payload: dict[str, Any], code: str) -> None:
    findings = verify_payload(payload)
    codes = {finding.code for finding in findings}
    if codes != {code}:
        raise AssertionError(f"expected only {code}, got {sorted(codes)}: {findings}")


def _expect_active_only(registry: dict[str, Any], code: str) -> None:
    findings = verify_active_registry(registry)
    codes = {finding.code for finding in findings}
    if codes != {code}:
        raise AssertionError(f"expected only {code}, got {sorted(codes)}: {findings}")


def self_test() -> None:
    cases: list[tuple[str, str, Any]] = []

    duplicate = _valid_fixture()
    duplicate["units"].append(copy.deepcopy(duplicate["units"][0]))
    cases.append(("duplicate ID", "duplicate_id", duplicate))

    frozen_normative_pair = _valid_fixture()
    frozen_normative_pair["authority"]["normative_pair"] = "sha256:wrong"
    cases.append(("frozen normative-pair SHA", "frozen_sha_mismatch", frozen_normative_pair))

    for field in FORBIDDEN_FROZEN_IDENTITY_FIELDS:
        frozen_identity = _valid_fixture()
        frozen_identity["authority"][field] = "deadbeef"
        cases.append((f"forbidden {field}", "frozen_sha_mismatch", frozen_identity))

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

    facade_registry = _valid_fixture()
    facade_registry["retired_or_migration_facades"][0]["path"] = "crates/eliot-app-tampered"
    cases.append(("facade registry tamper", "facade_registry_mismatch", facade_registry))

    clean = verify_payload(_valid_fixture(), _valid_active_registry())
    if clean:
        raise AssertionError(f"valid inventory fixture failed: {clean}")
    for case, code, payload in cases:
        _expect_only(payload, code)
        print(f"INVENTORY_FIXTURE: {case}: FAILS_AS={code}")

    active_registry = _valid_active_registry()
    active_registry["retired_refs"]["branches"].append("tampered/branch")
    _expect_active_only(active_registry, "active_registry_identity")
    print("INVENTORY_FIXTURE: ACTIVE registry tamper: FAILS_AS=active_registry_identity")

    duplicate_active_registry = _valid_active_registry()
    duplicate_active_registry["workstream"].append(copy.deepcopy(duplicate_active_registry["workstream"][0]))
    _expect_active_only(duplicate_active_registry, "active_registry_identity")
    print("INVENTORY_FIXTURE: duplicate ACTIVE workstream: FAILS_AS=active_registry_identity")
    print(f"CORE_DAEMON_INVENTORY_SELF_TEST: PASS cases={len(cases) + 2}")


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
