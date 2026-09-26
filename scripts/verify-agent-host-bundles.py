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
    DECLARED_IDENTITY_KEYS,
    INDEX_VERSION,
    IDENTITY_VERSION,
    MANIFEST_PATH,
    _blake3_hex,
    _canonical_skill_content_hash,
    _require_hex_digest,
    _safe_relative,
    _tree_digest,
    _verify_adapter_contract,
    _verify_file_payload,
    _verify_staged_bytes,
    _verify_tree_payload,
    canonical_json_bytes,
    compute_bundle_identity,
    directory_digest,
    load_manifest,
    load_skill_pack,
    materialize_host_bundle,
    sha256_bytes,
    verify_skill_pack_agreement,
)

HOSTS = ("codex", "opencode", "claude", "antigravity")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{path}: expected object")
    return value


def _load_expected_inputs(root: Path, host: str) -> dict[str, Any]:
    """Read the expected manifest set and input commitments independently.

    This never consults the materializer's returned list or receipt: manifests
    are parsed again from disk and every pinned byte string is re-hashed, so a
    self-consistent receipt over substituted inputs cannot pass the comparison
    in `_assert_bundle`.
    """
    manifest = load_manifest(root)
    host_config = manifest.get("hosts", {}).get(host)
    if not isinstance(host_config, dict):
        raise AssertionError(f"{host}: expected host entry is missing")
    skill_pack = load_skill_pack(
        root, str(manifest["canonical_skill_manifest"]), manifest["limits"]["max_file_bytes"]
    )
    verify_skill_pack_agreement(
        manifest, skill_pack, canonical_skill_manifest=str(manifest["canonical_skill_manifest"])
    )
    skill_root_relative = _safe_relative(str(manifest["canonical_skill_root"]), "canonical_skill_root")
    skill_root = root.joinpath(*skill_root_relative.parts)
    material: list[str] = []
    body_digests: dict[str, str] = {}
    for name in skill_pack["order"]:
        body = skill_root / name / "SKILL.md"
        if not body.is_file():
            raise AssertionError(f"{host}: expected Skill body is missing: {name!r}")
        body_text = body.read_text(encoding="utf-8")
        observed = _canonical_skill_content_hash(body_text)
        if observed != skill_pack["pins"][name]:
            raise AssertionError(f"{host}: expected Skill pin mismatch: {name!r}")
        material.append(f"{name}:{observed}\n")
        body_digests[name] = sha256_bytes(body.read_bytes())
    pack_hash = _blake3_hex("".join(material).encode("utf-8"))
    if pack_hash != manifest["skill_pack"]["pack_hash"]:
        raise AssertionError(f"{host}: expected Skill pack hash mismatch")
    route_pin = _require_hex_digest(
        host_config.get("route_profile_sha256"), f"{host}: expected route profile"
    )
    route_relative = _safe_relative(str(host_config.get("route_profile", "")), "route_profile")
    route_source = root.joinpath(*route_relative.parts).read_bytes()
    if sha256_bytes(route_source) != route_pin:
        raise AssertionError(f"{host}: expected route source pin mismatch")
    limits = manifest["limits"]

    def _checked(operation: Callable[[], object], what: str) -> None:
        try:
            operation()
        except BundleError as error:
            raise AssertionError(f"{host}: expected {what} mismatch: {error}") from error

    _checked(
        lambda: _verify_adapter_contract(root, host_config, host, limits),
        "adapter contract",
    )
    payload = host_config.get("payload", [])
    if not isinstance(payload, list) or not payload:
        raise AssertionError(f"{host}: expected payload mapping is empty")
    for mapping in payload:
        if not isinstance(mapping, dict) or mapping.get("kind") not in {"file", "tree"}:
            raise AssertionError(f"{host}: expected payload mapping is invalid")
        if mapping["kind"] == "file":
            _checked(
                lambda mapping=mapping: _verify_file_payload(root, mapping, host, limits),
                "payload file",
            )
        else:
            _checked(
                lambda mapping=mapping: _verify_tree_payload(root, mapping, host, limits),
                "payload tree",
            )
    return {
        "skill_order": skill_pack["order"],
        "skill_pack_hash": pack_hash,
        "body_digests": body_digests,
        "route_pin": route_pin,
        "host_config": host_config,
    }


def _assert_bundle(path: Path, host: str, receipt: dict[str, Any], expected: dict[str, Any]) -> None:
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
    if plan.get("bundle_sha256") != receipt.get("bundle_sha256"):
        raise AssertionError(f"{host}: install plan is pinned to a different bundle")
    if plan.get("bundle_identity") != receipt.get("bundle_identity"):
        raise AssertionError(f"{host}: install plan is pinned to a different bundle identity")
    if receipt.get("identity_version") != IDENTITY_VERSION:
        raise AssertionError(f"{host}: bundle identity version mismatch")
    for key in (
        "bundle_identity",
        "manifest_entry_sha256",
        "skill_manifest_sha256",
        "skill_pack_hash",
        "route_profile_sha256",
        "route_profile_source_sha256",
        "skill_index_sha256",
        "bundle_sha256",
    ):
        value = receipt.get(key)
        if not isinstance(value, str) or len(value) != 64 or any(
            char not in "0123456789abcdef" for char in value
        ):
            raise AssertionError(f"{host}: receipt identity field is malformed: {key}")
    if receipt.get("source_pins") != "verified":
        raise AssertionError(f"{host}: source-pin verification status is not verified")
    if receipt.get("origin_authentication") != "not_authenticated_hash_pins_only":
        raise AssertionError(f"{host}: receipt overclaims source origin authentication")
    # Independent expected-input check: staged membership and per-file bytes are
    # compared against the manifest commitments loaded in `_load_expected_inputs`,
    # never against the materializer's returned list. A self-consistent receipt
    # over substituted inputs cannot pass here.
    if receipt.get("skill_pack_order") != expected["skill_order"]:
        raise AssertionError(f"{host}: staged Skill order does not match the declared pack")
    if receipt.get("skill_pack_hash") != expected["skill_pack_hash"]:
        raise AssertionError(f"{host}: staged Skill pack hash does not match the declared pack")
    if receipt.get("route_profile_source_sha256") != expected["route_pin"]:
        raise AssertionError(f"{host}: staged route source pin does not match the declared pin")
    if [entry.get("name") for entry in entries] != expected["skill_order"]:
        raise AssertionError(f"{host}: staged Skill index order does not match the declared pack")
    host_config = expected["host_config"]
    skill_destination = str(host_config.get("skill_destination", ""))
    staged_skill_names = set()
    for entry in entries:
        staged_body = path / entry["relative_body"]
        expected_body_digest = expected["body_digests"].get(entry["name"])
        if expected_body_digest is None:
            raise AssertionError(f"{host}: staged Skill is not declared: {entry['name']!r}")
        if sha256_bytes(staged_body.read_bytes()) != expected_body_digest:
            raise AssertionError(f"{host}: staged Skill body drifted from its source pin: {entry['name']!r}")
        try:
            relative = Path(entry["relative_body"]).relative_to(f"host/{skill_destination}")
        except ValueError as error:
            raise AssertionError(f"{host}: staged Skill body escaped its destination") from error
        staged_skill_names.add(relative.parts[0])
    if staged_skill_names != set(expected["skill_order"]):
        raise AssertionError(f"{host}: staged Skill membership does not match the declared pack")
    payload = host_config.get("payload", [])
    declared_destinations: dict[str, str] = {}
    for mapping in payload:
        if not isinstance(mapping, dict):
            continue
        destination = str(mapping.get("destination", ""))
        if mapping.get("kind") == "file":
            declared_destinations[f"host/{destination}"] = mapping["sha256"]
        elif mapping.get("kind") == "tree":
            for item in mapping.get("tree_files", []):
                if isinstance(item, dict) and isinstance(item.get("path"), str):
                    declared_destinations[f"host/{destination}/{item['path']}"] = item["sha256"]
    for staged_key, expected_digest in declared_destinations.items():
        staged = path / staged_key
        if not staged.is_file():
            raise AssertionError(f"{host}: staged payload is missing: {staged_key}")
        if sha256_bytes(staged.read_bytes()) != expected_digest:
            raise AssertionError(f"{host}: staged payload drifted from its declared pin: {staged_key}")
    route_bytes = (operator / "route-profile.json").read_bytes()
    if sha256_bytes(route_bytes) != receipt["route_profile_sha256"]:
        raise AssertionError(f"{host}: declared route profile digest does not match staged bytes")
    index_bytes = (operator / "skill-index.json").read_bytes()
    if sha256_bytes(index_bytes) != receipt["skill_index_sha256"]:
        raise AssertionError(f"{host}: declared Skill index digest does not match staged bytes")
    files = receipt.get("files")
    if not isinstance(files, list) or not files:
        raise AssertionError(f"{host}: receipt file list is missing")
    if [entry.get("path") for entry in files] != sorted(entry.get("path") for entry in files):
        raise AssertionError(f"{host}: receipt file list is not deterministically ordered")
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "bytes"}:
            raise AssertionError(f"{host}: malformed receipt file entry")
        staged = path / entry["path"]
        if not staged.is_file():
            raise AssertionError(f"{host}: staged bundle file is missing: {entry['path']}")
        staged_bytes = staged.read_bytes()
        if len(staged_bytes) != entry["bytes"] or sha256_bytes(staged_bytes) != entry["sha256"]:
            raise AssertionError(f"{host}: staged bundle file drifted: {entry['path']}")
    for entry in files:
        staged_key = entry["path"]
        if staged_key.startswith("operator/"):
            continue
        if staged_key in declared_destinations:
            continue
        if staged_key.startswith(f"host/{skill_destination}/"):
            remainder = staged_key[len(f"host/{skill_destination}/"):]
            if "/" in remainder and remainder.split("/", 1)[0] in expected["skill_order"]:
                continue
        raise AssertionError(f"{host}: staged payload is not declared: {staged_key}")
    if sha256_bytes(canonical_json_bytes(files)) != receipt["bundle_sha256"]:
        raise AssertionError(f"{host}: bundle digest does not match file entries")
    expected_identity = compute_bundle_identity(
        manifest_entry_sha256=receipt["manifest_entry_sha256"],
        route_profile_sha256=receipt["route_profile_sha256"],
        route_profile_source_sha256=receipt["route_profile_source_sha256"],
        skill_manifest_sha256=receipt["skill_manifest_sha256"],
        skill_index_sha256=receipt["skill_index_sha256"],
        payload_entries=files,
    )
    if expected_identity != receipt["bundle_identity"]:
        raise AssertionError(f"{host}: bundle identity does not match recomputation")
    if receipt.get("declared_identity") not in {"absent", "verified"}:
        raise AssertionError(f"{host}: declared identity state is invalid")
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
            expected = _load_expected_inputs(root, host)
            first = scratch / f"{host}-a"
            second = scratch / f"{host}-b"
            receipt_a = materialize_host_bundle(root, host, first)
            receipt_b = materialize_host_bundle(root, host, second)
            _assert_bundle(first, host, receipt_a, expected)
            _assert_bundle(second, host, receipt_b, expected)
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
    # Fixed regression body: its BLAKE3 content pin and the pack hash below are
    # hardcoded so the self-test proves the adapter recipe on every run. Any
    # byte change here (including line endings) must fail the pack check.
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
                "schema_version": "eliot-agent-skill-pack-v1",
                "hash_algorithm": "blake3(name:content_blake3 joined with LF in manifest order)",
                "pack_hash": "085980d3da535214408d09de0fcb1925b8a68c444f9491385cbbcd77fcf41fcc",
                "skills": [
                    {
                        "name": "eliot-work",
                        "content_blake3": "df19ab6cdfcacc4644905930ad4984271e081c0dfbccced250d91c6d2f82c3c6",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    skill_manifest_sha = sha256_bytes(
        (root / "integrations/agent-skills/skill-pack.manifest.json").read_bytes()
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
            "route_profile_sha256": sha256_bytes(route.read_bytes()),
            "destination_hint": f"{host.upper()}_ROOT/eliot",
            "skill_destination": "skills",
            "payload": [
                {
                    "source": f"fixtures/{host}/plugin.json",
                    "destination": "plugin.json",
                    "kind": "file",
                    "mode": "verbatim_copy",
                    "sha256": sha256_bytes(payload.read_bytes()),
                }
            ],
        }
    manifest = {
        "schema_version": "eliot.agent-host-bundle-manifest.v1",
        "canonical_skill_root": "integrations/agent-skills",
        "canonical_skill_manifest": "integrations/agent-skills/skill-pack.manifest.json",
        "skill_pack": {
            "manifest": "integrations/agent-skills/skill-pack.manifest.json",
            "manifest_sha256": skill_manifest_sha,
            "pack_hash": "085980d3da535214408d09de0fcb1925b8a68c444f9491385cbbcd77fcf41fcc",
            "hash_algorithm": "blake3(name:content_blake3 joined with LF in manifest order)",
            "order": ["eliot-work"],
        },
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
            manifest_path = root / MANIFEST_PATH

            def expect() -> dict[str, Any]:
                return _load_expected_inputs(root, "codex")

            def repin_fixture_route() -> None:
                manifest = _read_json(manifest_path)
                route_bytes = (root / manifest["hosts"]["codex"]["route_profile"]).read_bytes()
                manifest["hosts"]["codex"]["route_profile_sha256"] = sha256_bytes(route_bytes)
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            first = scratch / "first"
            second = scratch / "second"
            receipt_a = materialize_host_bundle(root, "codex", first)
            receipt_b = materialize_host_bundle(root, "codex", second)
            if receipt_a != receipt_b or directory_digest(first) != directory_digest(second):
                raise AssertionError("deterministic materialization failed")
            _assert_bundle(first, "codex", receipt_a, expect())

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

            route = _read_json(route_path)
            route["disposition"] = {
                "disposition": "unavailable-target",
                "route_id": "codex.app-server.stdio",
                "proof_ceiling": "DETERMINISTIC_PACKAGE_SHAPE_ONLY",
                "expiry_condition": "reprobe-before-admission",
                "per_attempt_receipt": True,
                "required_probes": ["smoke-probe"],
                "non_admittable_reasons": ["not-probed"],
                "route_profile_sha256": "0" * 64,
                "bundle_generation": "test-generation-1",
            }
            route_path.write_text(json.dumps(route), encoding="utf-8")
            repin_fixture_route()
            blocked_receipt = materialize_host_bundle(root, "codex", scratch / "disposition-block")
            _assert_bundle(scratch / "disposition-block", "codex", blocked_receipt, expect())

            route = _read_json(route_path)
            route["disposition"] = {"disposition": "admitted"}
            route_path.write_text(json.dumps(route), encoding="utf-8")
            repin_fixture_route()
            _expect_failure(
                "blocked bad disposition",
                lambda: materialize_host_bundle(root, "codex", scratch / "blocked-bad-disposition"),
            )
            route_path.write_text(json.dumps(_route_profile("codex")), encoding="utf-8")
            repin_fixture_route()

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

            manifest_path = root / MANIFEST_PATH
            manifest = _read_json(manifest_path)
            codex_entry = manifest["hosts"]["codex"]
            route_doc = _read_json(root / "integrations/codex/route-profile.json")
            route_digest = sha256_bytes(canonical_json_bytes(route_doc) + b"\n")
            skill_manifest_bytes = (root / "integrations/agent-skills/skill-pack.manifest.json").read_bytes()
            entry_digest = sha256_bytes(
                canonical_json_bytes(
                    {key: value for key, value in codex_entry.items() if key not in DECLARED_IDENTITY_KEYS}
                )
            )
            codex_entry["identity"] = {
                "route_profile_sha256": route_digest,
                "skill_manifest_sha256": sha256_bytes(skill_manifest_bytes),
                "manifest_entry_sha256": entry_digest,
            }
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            declared_receipt = materialize_host_bundle(root, "codex", scratch / "declared")
            if declared_receipt.get("declared_identity") != "verified":
                raise AssertionError("declared identity was not verified")
            _assert_bundle(scratch / "declared", "codex", declared_receipt, expect())

            manifest = _read_json(manifest_path)
            manifest["hosts"]["codex"]["identity"]["bundle_identity"] = declared_receipt["bundle_identity"]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            repinned = materialize_host_bundle(root, "codex", scratch / "repinned")
            _assert_bundle(scratch / "repinned", "codex", repinned, expect())

            manifest = _read_json(manifest_path)
            manifest["hosts"]["codex"]["identity"]["route_profile_sha256"] = "0" * 64
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            _expect_failure(
                "forged route digest",
                lambda: materialize_host_bundle(root, "codex", scratch / "forged"),
            )
            manifest = _read_json(manifest_path)
            manifest["hosts"]["codex"]["identity"]["route_profile_sha256"] = "not-hex"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            _expect_failure(
                "malformed identity digest",
                lambda: materialize_host_bundle(root, "codex", scratch / "malformed"),
            )
            manifest = _read_json(manifest_path)
            del manifest["hosts"]["codex"]["identity"]
            manifest["hosts"]["codex"]["payload"][0]["source"] = "fixtures\\codex\\plugin.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            _expect_failure(
                "backslash traversal",
                lambda: materialize_host_bundle(root, "codex", scratch / "backslash"),
            )
            manifest = _read_json(manifest_path)
            manifest["hosts"]["codex"]["payload"][0]["source"] = "fixtures/codex/plugin.json"
            manifest["hosts"]["codex"]["payload"][0]["destination"] = "credentials.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            _expect_failure(
                "forbidden destination",
                lambda: materialize_host_bundle(root, "codex", scratch / "forbidden-dest"),
            )
            manifest = _read_json(manifest_path)
            manifest["hosts"]["codex"]["payload"][0]["destination"] = "plugin.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            # Declared-pack selection and pin cases (issue #2615). Each numbered
            # case below extends the historical 1-13 count.
            skills_root = root / "integrations/agent-skills"
            pack_path = skills_root / "skill-pack.manifest.json"
            original_pack = pack_path.read_bytes()
            body_path = skills_root / "eliot-work" / "SKILL.md"
            original_body = body_path.read_bytes()
            route_path = root / "integrations/codex/route-profile.json"

            def rewrite_pack(document: dict[str, Any]) -> None:
                pack_path.write_text(json.dumps(document), encoding="utf-8")
                repack = _read_json(manifest_path)
                repack["skill_pack"]["manifest_sha256"] = sha256_bytes(pack_path.read_bytes())
                manifest_path.write_text(json.dumps(repack), encoding="utf-8")

            def restore_pack() -> None:
                pack_path.write_bytes(original_pack)
                repack = _read_json(manifest_path)
                repack["skill_pack"]["manifest_sha256"] = sha256_bytes(original_pack)
                repack["skill_pack"]["order"] = ["eliot-work"]
                manifest_path.write_text(json.dumps(repack), encoding="utf-8")

            # Case 14: unlisted well-formed and empty directories never enter.
            shadow = skills_root / "unlisted-shadow"
            shadow.mkdir()
            (shadow / "SKILL.md").write_text("# Shadow\n\nUnlisted content.\n", encoding="utf-8")
            (skills_root / "empty-shadow").mkdir()
            shadowed = materialize_host_bundle(root, "codex", scratch / "unlisted-ignored")
            _assert_bundle(scratch / "unlisted-ignored", "codex", shadowed, expect())
            if shadowed.get("skill_pack_order") != ["eliot-work"]:
                raise AssertionError("unlisted directory entered the Skill index")
            if any("shadow" in item["path"] for item in shadowed["files"]):
                raise AssertionError("unlisted directory entered the payload")
            shutil.rmtree(shadow, ignore_errors=True)
            shutil.rmtree(skills_root / "empty-shadow", ignore_errors=True)

            # Case 15: a declared Skill without a directory rejects.
            (skills_root / "eliot-work").rename(skills_root / "eliot-work-hidden")
            _expect_failure(
                "missing declared Skill",
                lambda: materialize_host_bundle(root, "codex", scratch / "missing-skill"),
            )
            (skills_root / "eliot-work-hidden").rename(skills_root / "eliot-work")

            # Case 16: a duplicated declared Skill rejects.
            dup_pack = json.loads(original_pack.decode("utf-8"))
            dup_pack["skills"].append({"name": "eliot-work", "content_blake3": "0" * 64})
            rewrite_pack(dup_pack)
            _expect_failure(
                "duplicate declared Skill",
                lambda: materialize_host_bundle(root, "codex", scratch / "dup-skill"),
            )
            restore_pack()

            # Case 17: duplicate JSON keys in the Skill manifest reject.
            pack_path.write_text(
                '{"schema_version": "eliot-agent-skill-pack-v1",'
                ' "schema_version": "eliot-agent-skill-pack-v1",'
                ' "hash_algorithm": "x", "skills": []}',
                encoding="utf-8",
            )
            _expect_failure(
                "duplicate manifest key",
                lambda: materialize_host_bundle(root, "codex", scratch / "dup-key"),
            )
            restore_pack()

            # Case 18: changed normalized body content rejects.
            body_path.write_bytes(original_body + b"\nTampered input.\n")
            _expect_failure(
                "tampered Skill body",
                lambda: materialize_host_bundle(root, "codex", scratch / "tampered-body"),
            )
            body_path.write_bytes(original_body)

            # Case 19: an altered pack order rejects even when every body pin is right.
            second_dir = skills_root / "eliot-second"
            second_dir.mkdir()
            (second_dir / "SKILL.md").write_text(
                "# Second\n\nSecond procedure body for ordering checks.\n",
                encoding="utf-8",
            )
            two_pack = json.loads(original_pack.decode("utf-8"))
            two_pack["skills"].append(
                {
                    "name": "eliot-second",
                    "content_blake3": "6e7c00e13f6a3d9f95880317786b5c5a4906bf5c570815226189b16b7e8b8347",
                }
            )
            two_pack["skills"] = list(reversed(two_pack["skills"]))
            rewrite_pack(two_pack)
            both = _read_json(manifest_path)
            both["skill_pack"]["order"] = ["eliot-second", "eliot-work"]
            manifest_path.write_text(json.dumps(both), encoding="utf-8")
            _expect_failure(
                "altered pack order",
                lambda: materialize_host_bundle(root, "codex", scratch / "reordered-pack"),
            )
            restore_pack()
            shutil.rmtree(second_dir, ignore_errors=True)

            # Case 20: a route source pin mismatch rejects before validation.
            original_route = route_path.read_bytes()
            route_path.write_bytes(original_route + b" ")
            _expect_failure(
                "route source pin mismatch",
                lambda: materialize_host_bundle(root, "codex", scratch / "route-pin"),
            )
            route_path.write_bytes(original_route)

            # Cases 21-22: adapter pins fail closed in both directions.
            adapted = _read_json(manifest_path)
            adapted["hosts"]["codex"]["adapter_contract"] = "fixtures/codex/plugin.json"
            adapted["hosts"]["codex"]["adapter_contract_sha256"] = "0" * 64
            manifest_path.write_text(json.dumps(adapted), encoding="utf-8")
            _expect_failure(
                "adapter pin mismatch",
                lambda: materialize_host_bundle(root, "codex", scratch / "adapter-pin"),
            )
            adapted = _read_json(manifest_path)
            del adapted["hosts"]["codex"]["adapter_contract"]
            manifest_path.write_text(json.dumps(adapted), encoding="utf-8")
            _expect_failure(
                "adapter digest without contract",
                lambda: materialize_host_bundle(root, "codex", scratch / "adapter-digest-only"),
            )
            adapted = _read_json(manifest_path)
            del adapted["hosts"]["codex"]["adapter_contract_sha256"]
            manifest_path.write_text(json.dumps(adapted), encoding="utf-8")

            # Cases 23-25: tree payloads verify members, then reject extras and drift.
            tree_source = root / "fixtures/codex/treedir"
            tree_source.mkdir()
            (tree_source / "a.json").write_text(json.dumps({"a": 1}), encoding="utf-8")
            member_sha = sha256_bytes((tree_source / "a.json").read_bytes())
            member_bytes = (tree_source / "a.json").stat().st_size
            tree_digest = _tree_digest(
                [{"path": "a.json", "sha256": member_sha, "bytes": member_bytes}]
            )
            treed = _read_json(manifest_path)
            treed["hosts"]["codex"]["payload"].append(
                {
                    "source": "fixtures/codex/treedir",
                    "destination": "treedir",
                    "kind": "tree",
                    "mode": "verbatim_tree_copy",
                    "tree_digest_sha256": tree_digest,
                    "tree_file_count": 1,
                    "tree_files": [{"path": "a.json", "sha256": member_sha}],
                }
            )
            manifest_path.write_text(json.dumps(treed), encoding="utf-8")
            treed_receipt = materialize_host_bundle(root, "codex", scratch / "tree-baseline")
            _assert_bundle(scratch / "tree-baseline", "codex", treed_receipt, expect())
            (tree_source / "b.json").write_text(json.dumps({"b": 2}), encoding="utf-8")
            _expect_failure(
                "extra tree member",
                lambda: materialize_host_bundle(root, "codex", scratch / "tree-extra"),
            )
            (tree_source / "b.json").unlink()
            (tree_source / "a.json").write_text(json.dumps({"a": "changed"}), encoding="utf-8")
            _expect_failure(
                "changed tree member bytes",
                lambda: materialize_host_bundle(root, "codex", scratch / "tree-bytes"),
            )
            treed = _read_json(manifest_path)
            treed["hosts"]["codex"]["payload"] = treed["hosts"]["codex"]["payload"][:1]
            manifest_path.write_text(json.dumps(treed), encoding="utf-8")
            shutil.rmtree(tree_source, ignore_errors=True)

            # Case 26: changed file payload bytes reject.
            plugin_path = root / "fixtures/codex/plugin.json"
            saved_plugin = plugin_path.read_bytes()
            plugin_path.write_text(json.dumps({"name": "changed-input"}), encoding="utf-8")
            _expect_failure(
                "changed payload bytes",
                lambda: materialize_host_bundle(root, "codex", scratch / "payload-bytes"),
            )
            plugin_path.write_bytes(saved_plugin)

            # Case 27: CRLF bodies verify through normalization with raw bytes preserved.
            # Normalize first: on Windows the fixture files already rest with CRLF.
            crlf_body = original_body.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            body_path.write_bytes(crlf_body)
            crlf_receipt = materialize_host_bundle(root, "codex", scratch / "crlf-normalized")
            _assert_bundle(scratch / "crlf-normalized", "codex", crlf_receipt, expect())
            staged_body = scratch / "crlf-normalized" / "host" / "skills" / "eliot-work" / "SKILL.md"
            if staged_body.read_bytes() != crlf_body:
                raise AssertionError("CRLF source bytes were rewritten during staging")
            body_path.write_bytes(original_body)

            # Case 28: source and output route hashes live in separate domains.
            domain_receipt = materialize_host_bundle(root, "codex", scratch / "domains")
            _assert_bundle(scratch / "domains", "codex", domain_receipt, expect())
            source_pin = _read_json(manifest_path)["hosts"]["codex"]["route_profile_sha256"]
            if domain_receipt.get("route_profile_source_sha256") != source_pin:
                raise AssertionError("route source pin is not bound to the receipt")
            staged_route = (scratch / "domains" / "operator" / "route-profile.json").read_bytes()
            if sha256_bytes(staged_route) != domain_receipt["route_profile_sha256"]:
                raise AssertionError("route output hash is not bound to the staged bytes")
            if domain_receipt["route_profile_sha256"] == source_pin:
                raise AssertionError("route source and output domains are conflated")

            # Case 29: a self-consistent receipt over substituted inputs cannot pass.
            final = scratch / "final"
            final_receipt = materialize_host_bundle(root, "codex", final)
            _assert_bundle(final, "codex", final_receipt, expect())
            plugin_path.write_text(json.dumps({"name": "substituted-input"}), encoding="utf-8")
            try:
                _assert_bundle(final, "codex", final_receipt, _load_expected_inputs(root, "codex"))
            except AssertionError:
                pass
            else:
                raise AssertionError("substituted inputs passed the independent check")
            plugin_path.write_bytes(saved_plugin)

            # Case 30: staged bytes that change after validation are detected.
            (final / "host" / "plugin.json").write_text(
                json.dumps({"name": "mutated-after-staging"}), encoding="utf-8"
            )
            staged_entries = {item["path"]: item for item in final_receipt["files"]}
            _expect_failure(
                "staged mutation after validation",
                lambda: _verify_staged_bytes(final, staged_entries, "codex"),
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
        print("AGENT_HOST_BUNDLES_SELF_TEST: PASS cases=30")
    else:
        verify_current_tree(arguments.root.resolve())
        print("AGENT_HOST_BUNDLES_VERIFY: PASS hosts=4")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
