#!/usr/bin/env python3
"""Verify static shape and safety properties of ELIOT agent route bundles.

PASS proves declarations and selected static guardrails only. It does not prove
current accounts, executable capability, host event coverage, or a working swarm.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

from agent_route_bundle_checks import (
    DISPOSITIONS,
    PLUGIN,
    SCHEMA,
    identity_errors,
    plugin_errors,
    read_json,
    schema_validator,
    validate_profile_schema,
    verify,
)
from agent_route_contract import HOSTS, PROFILE, Finding, profile_errors


def expect(findings: list[Finding], code: str) -> None:
    if not any(item[0] == code for item in findings):
        raise AssertionError(f"expected {code}: {findings}")


def schema_findings(validator, profile: dict, relative: str) -> list[Finding]:
    findings: list[Finding] = []
    validate_profile_schema(validator, profile, relative, findings)
    return findings


def self_test(root: Path) -> None:
    bootstrap_findings: list[Finding] = []
    schema = read_json(root, SCHEMA, bootstrap_findings)
    if schema is None or bootstrap_findings:
        raise AssertionError(f"schema bootstrap failed: {bootstrap_findings}")
    validator_findings: list[Finding] = []
    validator = schema_validator(schema, validator_findings)
    if validator is None or validator_findings:
        raise AssertionError(f"schema validator failed: {validator_findings}")

    profiles = {
        host: json.loads((root / PROFILE.format(host=host)).read_text(encoding="utf-8"))
        for host in HOSTS
    }
    for host, profile in profiles.items():
        errors = schema_findings(validator, profile, PROFILE.format(host=host))
        errors.extend(profile_errors(profile, host))
        if errors:
            raise AssertionError(f"clean {host} profile failed: {errors}")

    codex = copy.deepcopy(profiles["codex"])
    codex["execution_routes"][0]["model_selection"]["fixed_model_id"] = "hard-coded"
    expect(profile_errors(codex, "codex"), "route_fixed_model")

    antigravity = copy.deepcopy(profiles["antigravity"])
    antigravity["execution_routes"][0]["swarm"]["direct_group_chat"] = True
    expect(profile_errors(antigravity, "antigravity"), "route_swarm_contract_invalid")

    opencode = copy.deepcopy(profiles["opencode"])
    opencode["execution_routes"].append(copy.deepcopy(opencode["execution_routes"][0]))
    opencode["execution_routes"][1]["route_id"] = "opencode.duplicate"
    expect(profile_errors(opencode, "opencode"), "profile_route_set_invalid")

    invalid_support = copy.deepcopy(profiles["codex"])
    invalid_support["implementation_support"] = "PRODUCTION"
    expect(
        schema_findings(validator, invalid_support, PROFILE.format(host="codex")),
        "profile_schema_invalid",
    )

    bad_disposition = copy.deepcopy(profiles["codex"])
    bad_disposition["disposition"] = "admitted"
    expect(identity_errors(bad_disposition, "codex"), "route_disposition_invalid")

    bad_digest = copy.deepcopy(profiles["codex"])
    bad_digest["bundle_identity"] = {"route_profile_sha256": "forged"}
    expect(identity_errors(bad_digest, "codex"), "route_identity_malformed")

    forged_admission = copy.deepcopy(profiles["opencode"])
    forged_admission["disposition"] = "live-admitted"
    expect(identity_errors(forged_admission, "opencode"), "route_disposition_overclaim")

    clean_identity = copy.deepcopy(profiles["claude"])
    clean_identity["disposition"] = "unavailable-target"
    clean_identity["bundle_identity"] = {
        "route_profile_sha256": "0" * 64,
        "generator_version": "test",
    }
    if identity_errors(clean_identity, "claude"):
        raise AssertionError(f"clean identity failed: {identity_errors(clean_identity, 'claude')}")

    clean_block = {
        "route_id": "codex.app-server.stdio",
        "proof_ceiling": "DETERMINISTIC_PACKAGE_SHAPE_ONLY",
        "expiry_condition": "reprobe-before-admission",
        "per_attempt_receipt": True,
        "required_probes": ["smoke-probe"],
        "non_admittable_reasons": ["not-probed"],
        "route_profile_sha256": "0" * 64,
        "bundle_generation": "test-generation-1",
    }
    for scalar in DISPOSITIONS:
        if scalar == "live-admitted":
            continue
        blocked = copy.deepcopy(profiles["codex"])
        blocked["disposition"] = {**clean_block, "disposition": scalar}
        blocked_findings = identity_errors(blocked, "codex")
        if blocked_findings:
            raise AssertionError(f"blocked {scalar} disposition failed: {blocked_findings}")
        scalar_profile = copy.deepcopy(profiles["codex"])
        scalar_profile["disposition"] = scalar
        scalar_findings = identity_errors(scalar_profile, "codex")
        if scalar_findings:
            raise AssertionError(f"scalar {scalar} disposition failed: {scalar_findings}")

    live_blocked = copy.deepcopy(profiles["codex"])
    live_blocked["disposition"] = {**clean_block, "disposition": "live-admitted"}
    live_block_findings = identity_errors(live_blocked, "codex")
    expect(live_block_findings, "route_disposition_overclaim")
    if any(code == "route_disposition_invalid" for code, _, _ in live_block_findings):
        raise AssertionError(f"live-admitted block misflagged as invalid: {live_block_findings}")

    bad_block_scalar = copy.deepcopy(profiles["codex"])
    bad_block_scalar["disposition"] = {**clean_block, "disposition": "admitted"}
    expect(identity_errors(bad_block_scalar, "codex"), "route_disposition_invalid")

    bad_block_digest = copy.deepcopy(profiles["codex"])
    bad_block_digest["disposition"] = {**clean_block, "route_profile_sha256": "forged"}
    expect(identity_errors(bad_block_digest, "codex"), "route_identity_malformed")

    additional_property = copy.deepcopy(profiles["claude"])
    additional_property["undeclared"] = True
    expect(
        schema_findings(validator, additional_property, PROFILE.format(host="claude")),
        "profile_schema_invalid",
    )

    clean_plugin = (root / PLUGIN).read_text(encoding="utf-8")
    expect(plugin_errors(clean_plugin + "\nconst leaked = { env: process.env }\n"), "opencode_full_env")
    expect(plugin_errors(clean_plugin + '\nreturn { decision: "passive" }\n'), "opencode_mutation_fail_open")
    expect(
        plugin_errors(
            clean_plugin.replace(
                "passiveDepth >= maximumPassiveQueue()",
                "passiveDepth >= Number.POSITIVE_INFINITY",
            )
        ),
        "opencode_plugin_marker_missing",
    )
    expect(
        plugin_errors(
            clean_plugin.replace(
                "ELIOT_OPENCODE_PASSIVE_QUEUE_LIMIT",
                "REMOVED_PASSIVE_QUEUE_LIMIT",
            )
        ),
        "opencode_plugin_marker_missing",
    )
    expect(
        plugin_errors(clean_plugin.replace('"ELIOT_WORK_LEASE_ID",', "")),
        "opencode_plugin_marker_missing",
    )
    expect(
        plugin_errors(clean_plugin + "\nconst retryId = globalThis.crypto?.randomUUID()\n"),
        "opencode_nondurable_event_identity",
    )
    expect(
        plugin_errors(clean_plugin + "\nawait Promise.all([stdout, stderr])\n"),
        "opencode_unbounded_stream_wait",
    )
    print("AGENT_ROUTE_BUNDLES_SELF_TEST: PASS cases=26")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    if args.self_test:
        self_test(root)
        return 0
    findings = verify(root)
    if findings:
        for code, path, detail in findings:
            print(f"HARD_VIOLATION: {code}: {path}: {detail}")
        return 1
    print(f"AGENT_ROUTE_BUNDLES_VERIFY: PASS profiles={len(HOSTS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
