#!/usr/bin/env python3
"""Compile and validate non-authoritative ELIOT capability-cell evidence.

The compiler consumes only current repository evidence:

- `docs/normative-pair.toml` and the exact frozen document bytes;
- Cargo package manifests;
- package-local capability-cell manifests explicitly referenced from
  `[package.metadata.eliot].cell_manifest`;
- the core-daemon inventory only as a scope selector, never as an ownership
  or support authority.

It deliberately does not infer lifecycle, state, authority, proof, or support
from a crate name, binary name, directory, description, or source presence.
Generated output is evidence for validation/planning. Presence in the output
cannot create runtime authority or promote implementation support.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

REGISTRY_SCHEMA = "eliot.capability-cell-registry.v1"
CELL_MANIFEST_SCHEMA = "eliot.capability-cells.v1"
GENERATOR_VERSION = "1"
RECEIPT_SCHEMA = "eliot-normative-pair-v1"
PAIR_ALGORITHM = "sha256-domain-separated-v1"
PAIR_DOMAIN = b"eliot-normative-pair-v1\x00"

SKIP_DIRS = {".git", ".eliot", "target", "dist", "reports", "swarm"}

EXECUTION_CONTOURS = {
    "static_native",
    "native_process",
    "wasm_component",
    "development_only",
    "surface",
}
REPLACEMENT_CLASSES = {
    "component_generation",
    "process_generation",
    "daemon_generation",
    "host_generation",
    "offline_release",
    "rebuildable_projection",
}
SUPPORT_VALUES = {
    "CURRENT_VERIFIED",
    "CURRENT_UNVERIFIED",
    "PARTIAL",
    "BLOCKED",
    "TARGET",
    "EXPERIMENTAL",
    "DEFERRED",
    "DEGRADED",
    "STALE",
    "NOT_APPLICABLE",
}
EXECUTION_VALUES = {"NOT_EXECUTED", "SIMULATED", "EXECUTED", "UNKNOWN_OUTCOME"}


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    detail: str
    cell_id: str | None = None
    package: str | None = None


@dataclass(frozen=True)
class PackageRecord:
    name: str
    manifest_path: str
    package_root: str
    source_maintenance_owner: str
    cell_manifest_path: str
    cargo_manifest_sha256: str
    scope_units: tuple[str, ...]


@dataclass(frozen=True)
class ContractRecord:
    path: str
    owner: str
    sha256: str


@dataclass(frozen=True)
class StateOwnerRecord:
    state_id: str
    owner: str


@dataclass(frozen=True)
class CellRecord:
    cell_id: str
    package: str
    package_manifest: str
    causal_responsibility: str
    lifecycle_owner: str
    source_maintenance_owner: str
    runtime_owner: str
    runtime_bundle: str
    execution_contour: str
    replacement_class: str
    removal_boundary: str
    state: tuple[StateOwnerRecord, ...]
    stateless: bool
    allowed_effect_classes: tuple[str, ...]
    contracts: tuple[ContractRecord, ...]
    proof_entrypoint: str
    proof_ceiling: str
    edge_profiles: tuple[str, ...]
    product_pulse: str | None
    not_applicable_reason: str | None
    implementation_support: str
    evidence_execution_status: str
    providers: tuple[str, ...]
    consumers: tuple[str, ...]
    invalidation: tuple[str, ...]
    manifest_sha256: str
    scope_units: tuple[str, ...]


class RegistryError(RuntimeError):
    """Stable compiler/validator failure."""


def fail(message: str) -> None:
    raise RegistryError(f"CAPABILITY_CELL_REGISTRY_FAIL: {message}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def validate_digest(field: str, value: Any) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
        char not in "0123456789abcdef" for char in value
    ):
        fail(f"{field} must be exactly 64 lowercase hexadecimal characters")
    return value


def validate_nonempty(field: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or any(char in value for char in "\r\n\x00"):
        fail(f"{field} must be a non-empty single-line string")
    return value.strip()


def string_list(field: str, value: Any, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or (not allow_empty and not value):
        fail(f"{field} must be a {'possibly empty ' if allow_empty else 'non-empty '}list")
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(validate_nonempty(f"{field}[{index}]", item))
    if len(set(result)) != len(result):
        fail(f"{field} contains duplicate values")
    return tuple(sorted(result))


def read_toml(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot parse TOML {path}: {error}")


def load_normative_pair(root: Path) -> dict[str, str]:
    receipt_path = root / "docs/normative-pair.toml"
    receipt = read_toml(receipt_path)
    required = {
        "schema_version",
        "status",
        "repository_authority_branch",
        "pair_key_algorithm",
        "pair_key",
        "architecture_path",
        "architecture_sha256",
        "implementation_path",
        "implementation_sha256",
    }
    missing = sorted(required.difference(receipt))
    if missing:
        fail(f"normative-pair receipt is missing {', '.join(missing)}")
    if receipt["schema_version"] != RECEIPT_SCHEMA:
        fail("unsupported normative-pair schema")
    if receipt["status"] != "accepted" or receipt["repository_authority_branch"] != "main":
        fail("normative pair is not accepted on main")
    if receipt["pair_key_algorithm"] != PAIR_ALGORITHM:
        fail("unsupported normative-pair algorithm")

    architecture_hash = validate_digest("architecture_sha256", receipt["architecture_sha256"])
    implementation_hash = validate_digest(
        "implementation_sha256", receipt["implementation_sha256"]
    )
    for label, relative, expected in (
        ("Architecture", receipt["architecture_path"], architecture_hash),
        ("Implementation", receipt["implementation_path"], implementation_hash),
    ):
        path = resolve_repo_path(root, relative, f"{label} path")
        actual = sha256_bytes(path.read_bytes())
        if actual != expected:
            fail(f"{label} digest mismatch: receipt={expected} actual={actual}")

    pair_material = PAIR_DOMAIN + architecture_hash.encode() + b"\x00" + implementation_hash.encode() + b"\x00"
    expected_pair = "sha256:" + sha256_bytes(pair_material)
    if receipt["pair_key"] != expected_pair:
        fail(f"normative pair key mismatch: receipt={receipt['pair_key']} actual={expected_pair}")
    return {
        "pair_key": expected_pair,
        "architecture_sha256": architecture_hash,
        "implementation_sha256": implementation_hash,
    }


def resolve_repo_path(root: Path, value: Any, field: str) -> Path:
    relative = validate_nonempty(field, value).replace("\\", "/")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts:
        fail(f"{field} must remain inside the repository")
    path = (root / Path(*pure.parts)).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        fail(f"{field} escapes the repository")
    if not path.is_file():
        fail(f"{field} does not resolve to a file: {relative}")
    return path


def walk_manifests(root: Path) -> Iterable[Path]:
    for current, dirs, files in os.walk(root):
        dirs[:] = [directory for directory in dirs if directory not in SKIP_DIRS]
        if "Cargo.toml" in files:
            yield Path(current) / "Cargo.toml"


def relative(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def load_scope_units(root: Path) -> list[dict[str, Any]]:
    path = root / "workstreams/core-daemons/inventory.json"
    try:
        inventory = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot parse core-daemon scope inventory: {error}")
    units = inventory.get("units")
    if not isinstance(units, list):
        fail("core-daemon inventory has no units list")
    result: list[dict[str, Any]] = []
    for index, unit in enumerate(units):
        if not isinstance(unit, dict):
            fail(f"inventory unit {index} is not an object")
        unit_id = validate_nonempty(f"inventory.units[{index}].id", unit.get("id"))
        paths = string_list(f"inventory.units[{index}].paths", unit.get("paths"))
        result.append({"id": unit_id, "paths": paths})
    return result


def matching_units(package_root: str, units: list[dict[str, Any]]) -> tuple[str, ...]:
    package = PurePosixPath(package_root)
    matches: list[str] = []
    for unit in units:
        for unit_path in unit["paths"]:
            scope = PurePosixPath(unit_path.rstrip("/"))
            if package == scope or scope in package.parents or package in scope.parents:
                matches.append(unit["id"])
                break
    return tuple(sorted(set(matches)))


def load_packages(root: Path, units: list[dict[str, Any]]) -> tuple[list[PackageRecord], list[Finding]]:
    packages: list[PackageRecord] = []
    findings: list[Finding] = []
    names: dict[str, str] = {}
    for manifest_path in walk_manifests(root):
        data = read_toml(manifest_path)
        package = data.get("package")
        if not isinstance(package, dict):
            continue
        name = validate_nonempty(f"{relative(root, manifest_path)} package.name", package.get("name"))
        manifest_relative = relative(root, manifest_path)
        previous = names.get(name)
        if previous is not None:
            findings.append(
                Finding(
                    "duplicate_package_name",
                    manifest_relative,
                    f"package is also declared by {previous}",
                    package=name,
                )
            )
            continue
        names[name] = manifest_relative
        package_root = relative(root, manifest_path.parent)
        scope_units = matching_units(package_root, units)
        if not scope_units:
            continue

        metadata = package.get("metadata")
        eliot = metadata.get("eliot") if isinstance(metadata, dict) else None
        if not isinstance(eliot, dict):
            findings.append(
                Finding(
                    "missing_eliot_metadata",
                    manifest_relative,
                    "in-scope package has no [package.metadata.eliot] table",
                    package=name,
                )
            )
            continue
        source_owner = eliot.get("source_maintenance_owner")
        cell_manifest = eliot.get("cell_manifest")
        if not isinstance(source_owner, str) or not source_owner.strip():
            findings.append(
                Finding(
                    "missing_source_maintenance_owner",
                    manifest_relative,
                    "source maintenance ownership is not declared",
                    package=name,
                )
            )
            continue
        if not isinstance(cell_manifest, str) or not cell_manifest.strip():
            findings.append(
                Finding(
                    "missing_cell_manifest",
                    manifest_relative,
                    "in-scope package has no package-local cell_manifest reference",
                    package=name,
                )
            )
            continue
        try:
            cell_path = resolve_repo_path(
                root,
                str(PurePosixPath(package_root) / PurePosixPath(cell_manifest.replace("\\", "/"))),
                f"{name} cell_manifest",
            )
        except RegistryError as error:
            findings.append(
                Finding("invalid_cell_manifest_path", manifest_relative, str(error), package=name)
            )
            continue
        packages.append(
            PackageRecord(
                name=name,
                manifest_path=manifest_relative,
                package_root=package_root,
                source_maintenance_owner=source_owner.strip(),
                cell_manifest_path=relative(root, cell_path),
                cargo_manifest_sha256=sha256_bytes(manifest_path.read_bytes()),
                scope_units=scope_units,
            )
        )
    return sorted(packages, key=lambda package: package.name), findings


def parse_states(value: Any, *, cell_id: str) -> tuple[StateOwnerRecord, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        fail(f"cell {cell_id} owned_state must be a list of inline tables")
    records: list[StateOwnerRecord] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            fail(f"cell {cell_id} owned_state[{index}] must be a table")
        records.append(
            StateOwnerRecord(
                validate_nonempty(f"cell {cell_id} state_id", item.get("state_id")),
                validate_nonempty(f"cell {cell_id} state owner", item.get("owner")),
            )
        )
    if len({record.state_id for record in records}) != len(records):
        fail(f"cell {cell_id} repeats an owned state identity")
    return tuple(sorted(records, key=lambda record: record.state_id))


def load_cells(root: Path, package: PackageRecord) -> list[CellRecord]:
    path = root / package.cell_manifest_path
    data = read_toml(path)
    if data.get("schema") != CELL_MANIFEST_SCHEMA:
        fail(f"{package.cell_manifest_path} has unsupported cell-manifest schema")
    if data.get("package") != package.name:
        fail(f"{package.cell_manifest_path} package does not match {package.name}")
    raw_cells = data.get("cell")
    if not isinstance(raw_cells, list) or not raw_cells:
        fail(f"{package.cell_manifest_path} must contain at least one [[cell]]")
    manifest_hash = sha256_bytes(path.read_bytes())
    result: list[CellRecord] = []
    for index, raw in enumerate(raw_cells):
        if not isinstance(raw, dict):
            fail(f"{package.cell_manifest_path} cell[{index}] is not a table")
        cell_id = validate_nonempty("cell_id", raw.get("cell_id"))
        stateless = raw.get("stateless")
        if not isinstance(stateless, bool):
            fail(f"cell {cell_id} must declare boolean stateless")
        states = parse_states(raw.get("owned_state"), cell_id=cell_id)
        if stateless and states:
            fail(f"cell {cell_id} declares statelessness and owned state")
        if not stateless and not states:
            fail(f"stateful cell {cell_id} has no owned state")

        contour = validate_nonempty("execution_contour", raw.get("execution_contour"))
        replacement = validate_nonempty("replacement_class", raw.get("replacement_class"))
        support = validate_nonempty("implementation_support", raw.get("implementation_support"))
        execution = validate_nonempty(
            "evidence_execution_status", raw.get("evidence_execution_status")
        )
        if contour not in EXECUTION_CONTOURS:
            fail(f"cell {cell_id} uses unknown execution contour {contour}")
        if replacement not in REPLACEMENT_CLASSES:
            fail(f"cell {cell_id} uses unknown replacement class {replacement}")
        if support not in SUPPORT_VALUES:
            fail(f"cell {cell_id} uses unknown implementation support {support}")
        if execution not in EXECUTION_VALUES:
            fail(f"cell {cell_id} uses unknown evidence execution status {execution}")
        if support == "CURRENT_VERIFIED" and execution != "EXECUTED":
            fail(f"cell {cell_id} claims CURRENT_VERIFIED without EXECUTED evidence")

        contract_owner = validate_nonempty("contract_owner", raw.get("contract_owner"))
        contract_sources = string_list("contract_sources", raw.get("contract_sources"))
        contracts: list[ContractRecord] = []
        for contract_source in contract_sources:
            contract_path = resolve_repo_path(root, contract_source, f"cell {cell_id} contract")
            contracts.append(
                ContractRecord(relative(root, contract_path), contract_owner, sha256_bytes(contract_path.read_bytes()))
            )

        product_pulse = raw.get("product_pulse")
        not_applicable = raw.get("not_applicable_reason")
        if bool(product_pulse) == bool(not_applicable):
            fail(f"cell {cell_id} must declare exactly one product_pulse or not_applicable_reason")

        result.append(
            CellRecord(
                cell_id=cell_id,
                package=package.name,
                package_manifest=package.manifest_path,
                causal_responsibility=validate_nonempty(
                    "causal_responsibility", raw.get("causal_responsibility")
                ),
                lifecycle_owner=validate_nonempty("lifecycle_owner", raw.get("lifecycle_owner")),
                source_maintenance_owner=package.source_maintenance_owner,
                runtime_owner=validate_nonempty("runtime_owner", raw.get("runtime_owner")),
                runtime_bundle=validate_nonempty("runtime_bundle", raw.get("runtime_bundle")),
                execution_contour=contour,
                replacement_class=replacement,
                removal_boundary=validate_nonempty("removal_boundary", raw.get("removal_boundary")),
                state=states,
                stateless=stateless,
                allowed_effect_classes=string_list(
                    "allowed_effect_classes", raw.get("allowed_effect_classes"), allow_empty=True
                ),
                contracts=tuple(sorted(contracts, key=lambda contract: contract.path)),
                proof_entrypoint=validate_nonempty("proof_entrypoint", raw.get("proof_entrypoint")),
                proof_ceiling=validate_nonempty("proof_ceiling", raw.get("proof_ceiling")),
                edge_profiles=string_list("edge_profiles", raw.get("edge_profiles"), allow_empty=True),
                product_pulse=validate_nonempty("product_pulse", product_pulse)
                if product_pulse
                else None,
                not_applicable_reason=validate_nonempty(
                    "not_applicable_reason", not_applicable
                )
                if not_applicable
                else None,
                implementation_support=support,
                evidence_execution_status=execution,
                providers=string_list("providers", raw.get("providers"), allow_empty=True),
                consumers=string_list("consumers", raw.get("consumers"), allow_empty=True),
                invalidation=string_list("invalidation", raw.get("invalidation")),
                manifest_sha256=manifest_hash,
                scope_units=package.scope_units,
            )
        )
    return result


def source_sha(root: Path, explicit: str | None) -> str:
    candidate = explicit or os.environ.get("GITHUB_SHA")
    if candidate:
        return validate_digest("source_sha", candidate)
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        fail("source SHA is required when Git identity is unavailable")
    return validate_digest("source_sha", completed.stdout.strip())


def compile_registry(root: Path, *, exact_source_sha: str) -> tuple[dict[str, Any], list[Finding]]:
    pair = load_normative_pair(root)
    units = load_scope_units(root)
    packages, findings = load_packages(root, units)
    cells: list[CellRecord] = []
    for package in packages:
        try:
            cells.extend(load_cells(root, package))
        except RegistryError as error:
            findings.append(
                Finding(
                    "invalid_cell_manifest",
                    package.cell_manifest_path,
                    str(error),
                    package=package.name,
                )
            )

    cell_ids: dict[str, CellRecord] = {}
    state_owners: dict[str, tuple[str, str]] = {}
    contract_owners: dict[str, tuple[str, str]] = {}
    for cell in cells:
        previous = cell_ids.get(cell.cell_id)
        if previous is not None:
            findings.append(
                Finding(
                    "duplicate_cell_id",
                    cell.package_manifest,
                    f"cell also declared by package {previous.package}",
                    cell.cell_id,
                    cell.package,
                )
            )
        else:
            cell_ids[cell.cell_id] = cell
        for state in cell.state:
            previous_owner = state_owners.get(state.state_id)
            if previous_owner is not None:
                findings.append(
                    Finding(
                        "duplicate_state_owner",
                        cell.package_manifest,
                        f"state {state.state_id} already owned by {previous_owner[0]} in cell {previous_owner[1]}",
                        cell.cell_id,
                        cell.package,
                    )
                )
            else:
                state_owners[state.state_id] = (state.owner, cell.cell_id)
        for contract in cell.contracts:
            previous_contract = contract_owners.get(contract.path)
            if previous_contract is not None and previous_contract[0] != contract.owner:
                findings.append(
                    Finding(
                        "duplicate_contract_owner",
                        contract.path,
                        f"contract owner {contract.owner} conflicts with {previous_contract[0]} from cell {previous_contract[1]}",
                        cell.cell_id,
                        cell.package,
                    )
                )
            else:
                contract_owners[contract.path] = (contract.owner, cell.cell_id)

    registry = {
        "schema": REGISTRY_SCHEMA,
        "generator_version": GENERATOR_VERSION,
        "authority": "NON_AUTHORITATIVE_GENERATED_EVIDENCE",
        "normative_pair": pair,
        "source_sha": exact_source_sha,
        "scope_selector": "workstreams/core-daemons/inventory.json",
        "scope_rule": "inventory selects packages only; ownership/support come solely from package-local declared manifests and exact evidence",
        "packages": [asdict(package) for package in packages],
        "cells": [asdict(cell) for cell in sorted(cells, key=lambda item: item.cell_id)],
        "findings": [asdict(finding) for finding in sorted(findings, key=lambda item: (item.code, item.path, item.cell_id or ""))],
        "status": "COMPLETE" if not findings else "PARTIAL",
    }
    registry["registry_sha256"] = sha256_bytes(canonical_json_bytes(registry))
    return registry, findings


def write_output(path: Path | None, registry: dict[str, Any]) -> None:
    data = json.dumps(registry, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if path is None:
        sys.stdout.write(data)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8", newline="\n")


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="eliot-cell-registry-") as temporary:
        root = Path(temporary)
        (root / "docs/architecture").mkdir(parents=True)
        architecture = root / "docs/architecture/ELIOT_ARCHITECTURE.md"
        implementation = root / "docs/architecture/ELIOT_IMPLEMENTATION.md"
        architecture.write_text("architecture\n", encoding="utf-8")
        implementation.write_text("implementation\n", encoding="utf-8")
        ah = sha256_bytes(architecture.read_bytes())
        ih = sha256_bytes(implementation.read_bytes())
        pair = "sha256:" + sha256_bytes(PAIR_DOMAIN + ah.encode() + b"\x00" + ih.encode() + b"\x00")
        (root / "docs/normative-pair.toml").write_text(
            f'''schema_version = "{RECEIPT_SCHEMA}"
status = "accepted"
repository_authority_branch = "main"
pair_key_algorithm = "{PAIR_ALGORITHM}"
pair_key = "{pair}"
architecture_path = "docs/architecture/ELIOT_ARCHITECTURE.md"
architecture_sha256 = "{ah}"
implementation_path = "docs/architecture/ELIOT_IMPLEMENTATION.md"
implementation_sha256 = "{ih}"
''',
            encoding="utf-8",
        )
        (root / "workstreams/core-daemons").mkdir(parents=True)
        (root / "workstreams/core-daemons/inventory.json").write_text(
            json.dumps({"units": [{"id": "host", "paths": ["crates/host"]}]}),
            encoding="utf-8",
        )
        package_root = root / "crates/host"
        (package_root / "src").mkdir(parents=True)
        (package_root / "src/lib.rs").write_text("pub struct Contract;\n", encoding="utf-8")
        (package_root / "Cargo.toml").write_text(
            '''[package]
name = "eliot-host-test"
version = "0.1.0"
edition = "2024"

[package.metadata.eliot]
source_maintenance_owner = "source.host"
cell_manifest = "capability-cells.toml"
''',
            encoding="utf-8",
        )
        (package_root / "capability-cells.toml").write_text(
            '''schema = "eliot.capability-cells.v1"
package = "eliot-host-test"

[[cell]]
cell_id = "host.journal"
causal_responsibility = "Own one exact host journal transition."
lifecycle_owner = "runtime.host"
runtime_owner = "runtime.host"
runtime_bundle = "eliot-host"
execution_contour = "static_native"
replacement_class = "host_generation"
removal_boundary = "Host journal replacement requires migration proof."
stateless = false
owned_state = [{ state_id = "host_state_journal", owner = "runtime.host" }]
allowed_effect_classes = ["host_journal_write"]
contract_owner = "contract.host-journal"
contract_sources = ["crates/host/src/lib.rs"]
proof_entrypoint = "cargo test -p eliot-host-test"
proof_ceiling = "MODULE_ONLY"
edge_profiles = ["host-journal-write-readback"]
product_pulse = "D0_HOST_JOURNAL"
implementation_support = "CURRENT_UNVERIFIED"
evidence_execution_status = "NOT_EXECUTED"
providers = []
consumers = ["eliot-host"]
invalidation = ["source_sha", "normative_pair", "contract_digest"]
''',
            encoding="utf-8",
        )
        registry, findings = compile_registry(root, exact_source_sha="a" * 64)
        if findings or registry["status"] != "COMPLETE" or len(registry["cells"]) != 1:
            fail("self-test valid registry did not compile cleanly")

        text = (package_root / "capability-cells.toml").read_text(encoding="utf-8")
        (package_root / "capability-cells.toml").write_text(
            text.replace('proof_entrypoint = "cargo test -p eliot-host-test"\n', ""),
            encoding="utf-8",
        )
        _, broken = compile_registry(root, exact_source_sha="b" * 64)
        if not any(finding.code == "invalid_cell_manifest" for finding in broken):
            fail("self-test missing proof entrypoint was accepted")

        receipt_path = root / "docs/normative-pair.toml"
        receipt_path.write_text(
            receipt_path.read_text(encoding="utf-8").replace(pair, "sha256:" + "0" * 64),
            encoding="utf-8",
        )
        try:
            compile_registry(root, exact_source_sha="c" * 64)
        except RegistryError:
            pass
        else:
            fail("self-test stale normative pair was accepted")

    print("CAPABILITY_CELL_REGISTRY_SELF_TEST: PASS cases=3")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("generate", "validate", "self-test"))
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--source-sha")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--allow-partial", action="store_true")
    args = parser.parse_args()

    if args.command == "self-test":
        self_test()
        return 0

    root = args.repo.resolve()
    exact_source_sha = source_sha(root, args.source_sha)
    registry, findings = compile_registry(root, exact_source_sha=exact_source_sha)
    if args.command == "generate":
        write_output(args.output, registry)
    else:
        if args.output is None or not args.output.is_file():
            fail("validate requires an existing --output registry file")
        observed = json.loads(args.output.read_text(encoding="utf-8"))
        if observed != registry:
            fail("generated registry is stale or does not match current inputs")
        print(
            f"CAPABILITY_CELL_REGISTRY_VALIDATE: PASS cells={len(registry['cells'])} source={exact_source_sha}"
        )

    if findings and not args.allow_partial:
        codes = sorted({finding.code for finding in findings})
        fail(f"registry is PARTIAL with {len(findings)} finding(s): {', '.join(codes)}")
    if args.command == "generate":
        print(
            f"CAPABILITY_CELL_REGISTRY_GENERATE: {registry['status']} cells={len(registry['cells'])} findings={len(findings)}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RegistryError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
