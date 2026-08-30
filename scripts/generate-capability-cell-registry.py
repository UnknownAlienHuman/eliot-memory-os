#!/usr/bin/env python3
"""Compile non-authoritative ELIOT capability-cell evidence.

The compiler never infers lifecycle/state/contract/authority/support ownership
from a package, binary, directory, description, or source presence. A package
enters the registry only through explicit package metadata and a package-local
cell manifest bound to the accepted normative pair and exact source identity.
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
CELL_SCHEMA = "eliot.capability-cells.v1"
PAIR_SCHEMA = "eliot-normative-pair-v1"
PAIR_ALGORITHM = "sha256-domain-separated-v1"
PAIR_DOMAIN = b"eliot-normative-pair-v1\x00"
SKIP_DIRS = {".git", ".eliot", "target", "dist", "reports", "swarm"}

EXECUTION_CONTOURS = {
    "static_native", "native_process", "wasm_component",
    "development_only", "surface",
}
REPLACEMENT_CLASSES = {
    "component_generation", "process_generation", "daemon_generation",
    "host_generation", "offline_release", "rebuildable_projection",
}
SUPPORT_VALUES = {
    "CURRENT_VERIFIED", "CURRENT_UNVERIFIED", "PARTIAL", "BLOCKED",
    "TARGET", "EXPERIMENTAL", "DEFERRED", "DEGRADED", "STALE",
    "NOT_APPLICABLE",
}
EXECUTION_VALUES = {"NOT_EXECUTED", "SIMULATED", "EXECUTED", "UNKNOWN_OUTCOME"}


class RegistryError(RuntimeError):
    pass


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    detail: str
    package: str | None = None
    cell_id: str | None = None


@dataclass(frozen=True)
class StateOwner:
    state_id: str
    owner: str


@dataclass(frozen=True)
class ContractSource:
    path: str
    owner: str
    sha256: str


@dataclass(frozen=True)
class Cell:
    cell_id: str
    package: str
    package_manifest: str
    cell_manifest: str
    causal_responsibility: str
    source_maintenance_owner: str
    lifecycle_owner: str
    runtime_owner: str
    runtime_bundle: str
    execution_contour: str
    replacement_class: str
    removal_boundary: str
    stateless: bool
    owned_state: tuple[StateOwner, ...]
    allowed_effect_classes: tuple[str, ...]
    contracts: tuple[ContractSource, ...]
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


def fail(message: str) -> None:
    raise RegistryError(f"CAPABILITY_CELL_REGISTRY_FAIL: {message}")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("utf-8")


def nonempty(field: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or any(c in value for c in "\r\n\x00"):
        fail(f"{field} must be a non-empty single-line string")
    return value.strip()


def string_list(field: str, value: Any, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or (not allow_empty and not value):
        fail(f"{field} must be a {'possibly empty' if allow_empty else 'non-empty'} list")
    result = tuple(sorted(nonempty(f"{field}[{index}]", item)
                          for index, item in enumerate(value)))
    if len(set(result)) != len(result):
        fail(f"{field} contains duplicates")
    return result


def lower_hex(field: str, value: Any, lengths: set[int]) -> str:
    if not isinstance(value, str) or len(value) not in lengths or any(
        char not in "0123456789abcdef" for char in value
    ):
        allowed = "/".join(str(length) for length in sorted(lengths))
        fail(f"{field} must be {allowed} lowercase hexadecimal characters")
    return value


def document_digest(field: str, value: Any) -> str:
    return lower_hex(field, value, {64})


def source_identity(value: Any) -> str:
    # Current repositories use SHA-1 object IDs; Git can use SHA-256 object IDs.
    return lower_hex("source_sha", value, {40, 64})


def read_toml(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot parse TOML {path}: {error}")


def repo_path(root: Path, value: Any, field: str) -> Path:
    relative = PurePosixPath(nonempty(field, value).replace("\\", "/"))
    if relative.is_absolute() or ".." in relative.parts:
        fail(f"{field} must remain inside the repository")
    resolved = (root / Path(*relative.parts)).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        fail(f"{field} escapes the repository")
    if not resolved.is_file():
        fail(f"{field} does not resolve to a file: {relative}")
    return resolved


def relative(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def normative_pair(root: Path) -> dict[str, str]:
    receipt = read_toml(root / "docs/normative-pair.toml")
    if receipt.get("schema_version") != PAIR_SCHEMA:
        fail("unsupported normative-pair schema")
    if receipt.get("status") != "accepted" or receipt.get("repository_authority_branch") != "main":
        fail("normative pair is not accepted on main")
    if receipt.get("pair_key_algorithm") != PAIR_ALGORITHM:
        fail("unsupported normative-pair algorithm")

    architecture = document_digest("architecture_sha256", receipt.get("architecture_sha256"))
    implementation = document_digest("implementation_sha256", receipt.get("implementation_sha256"))
    for label, path_key, expected in (
        ("Architecture", "architecture_path", architecture),
        ("Implementation", "implementation_path", implementation),
    ):
        path = repo_path(root, receipt.get(path_key), path_key)
        actual = sha256(path.read_bytes())
        if actual != expected:
            fail(f"{label} digest mismatch: receipt={expected} actual={actual}")

    material = PAIR_DOMAIN + architecture.encode() + b"\x00" + implementation.encode() + b"\x00"
    pair_key = "sha256:" + sha256(material)
    if receipt.get("pair_key") != pair_key:
        fail(f"normative pair key mismatch: receipt={receipt.get('pair_key')} actual={pair_key}")
    return {
        "pair_key": pair_key,
        "architecture_sha256": architecture,
        "implementation_sha256": implementation,
    }


def scope_units(root: Path) -> list[tuple[str, tuple[str, ...]]]:
    path = root / "workstreams/core-daemons/inventory.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot parse scope inventory: {error}")
    units = payload.get("units")
    if not isinstance(units, list):
        fail("scope inventory has no units list")
    result: list[tuple[str, tuple[str, ...]]] = []
    for index, unit in enumerate(units):
        if not isinstance(unit, dict):
            fail(f"inventory unit {index} is not an object")
        result.append((
            nonempty(f"inventory unit {index} id", unit.get("id")),
            string_list(f"inventory unit {index} paths", unit.get("paths")),
        ))
    return result


def matching_units(package_root: str, units: list[tuple[str, tuple[str, ...]]]) -> tuple[str, ...]:
    package = PurePosixPath(package_root)
    matched: set[str] = set()
    for unit_id, paths in units:
        for value in paths:
            scope = PurePosixPath(value.rstrip("/"))
            if package == scope or scope in package.parents or package in scope.parents:
                matched.add(unit_id)
                break
    return tuple(sorted(matched))


def cargo_manifests(root: Path) -> Iterable[Path]:
    for current, dirs, files in os.walk(root):
        dirs[:] = [directory for directory in dirs if directory not in SKIP_DIRS]
        if "Cargo.toml" in files:
            yield Path(current) / "Cargo.toml"


def parse_states(cell_id: str, value: Any, stateless: bool) -> tuple[StateOwner, ...]:
    if value is None:
        states: tuple[StateOwner, ...] = ()
    else:
        if not isinstance(value, list):
            fail(f"cell {cell_id} owned_state must be a list")
        parsed: list[StateOwner] = []
        for index, item in enumerate(value):
            if not isinstance(item, dict):
                fail(f"cell {cell_id} owned_state[{index}] must be a table")
            parsed.append(StateOwner(
                nonempty(f"cell {cell_id} state_id", item.get("state_id")),
                nonempty(f"cell {cell_id} state owner", item.get("owner")),
            ))
        states = tuple(sorted(parsed, key=lambda state: state.state_id))
    if len({state.state_id for state in states}) != len(states):
        fail(f"cell {cell_id} repeats a state identity")
    if stateless == bool(states):
        fail(f"cell {cell_id} must declare either statelessness or owned state, not both/neither")
    return states


def parse_cell_manifest(
    root: Path,
    *,
    package_name: str,
    package_manifest: str,
    source_owner: str,
    manifest_path: Path,
    units: tuple[str, ...],
) -> list[Cell]:
    payload = read_toml(manifest_path)
    if payload.get("schema") != CELL_SCHEMA or payload.get("package") != package_name:
        fail(f"{relative(root, manifest_path)} has wrong schema or package")
    raw_cells = payload.get("cell")
    if not isinstance(raw_cells, list) or not raw_cells:
        fail(f"{relative(root, manifest_path)} must contain [[cell]] records")
    manifest_hash = sha256(manifest_path.read_bytes())
    result: list[Cell] = []
    for raw in raw_cells:
        if not isinstance(raw, dict):
            fail(f"{relative(root, manifest_path)} contains a non-table cell")
        cell_id = nonempty("cell_id", raw.get("cell_id"))
        stateless = raw.get("stateless")
        if not isinstance(stateless, bool):
            fail(f"cell {cell_id} must declare boolean stateless")
        states = parse_states(cell_id, raw.get("owned_state"), stateless)

        contour = nonempty(f"cell {cell_id} execution_contour", raw.get("execution_contour"))
        replacement = nonempty(f"cell {cell_id} replacement_class", raw.get("replacement_class"))
        support = nonempty(f"cell {cell_id} implementation_support", raw.get("implementation_support"))
        execution = nonempty(f"cell {cell_id} evidence_execution_status", raw.get("evidence_execution_status"))
        if contour not in EXECUTION_CONTOURS:
            fail(f"cell {cell_id} has unknown execution contour {contour}")
        if replacement not in REPLACEMENT_CLASSES:
            fail(f"cell {cell_id} has unknown replacement class {replacement}")
        if support not in SUPPORT_VALUES or execution not in EXECUTION_VALUES:
            fail(f"cell {cell_id} has unknown support/evidence status")
        if support == "CURRENT_VERIFIED" and execution != "EXECUTED":
            fail(f"cell {cell_id} claims CURRENT_VERIFIED without EXECUTED evidence")

        contract_owner = nonempty(f"cell {cell_id} contract_owner", raw.get("contract_owner"))
        contracts = tuple(sorted((
            ContractSource(
                relative(root, path),
                contract_owner,
                sha256(path.read_bytes()),
            )
            for path in (
                repo_path(root, item, f"cell {cell_id} contract")
                for item in string_list(f"cell {cell_id} contract_sources", raw.get("contract_sources"))
            )
        ), key=lambda contract: contract.path))

        pulse = raw.get("product_pulse")
        not_applicable = raw.get("not_applicable_reason")
        if bool(pulse) == bool(not_applicable):
            fail(f"cell {cell_id} must declare exactly one product_pulse or not_applicable_reason")

        result.append(Cell(
            cell_id=cell_id,
            package=package_name,
            package_manifest=package_manifest,
            cell_manifest=relative(root, manifest_path),
            causal_responsibility=nonempty(f"cell {cell_id} causal_responsibility", raw.get("causal_responsibility")),
            source_maintenance_owner=source_owner,
            lifecycle_owner=nonempty(f"cell {cell_id} lifecycle_owner", raw.get("lifecycle_owner")),
            runtime_owner=nonempty(f"cell {cell_id} runtime_owner", raw.get("runtime_owner")),
            runtime_bundle=nonempty(f"cell {cell_id} runtime_bundle", raw.get("runtime_bundle")),
            execution_contour=contour,
            replacement_class=replacement,
            removal_boundary=nonempty(f"cell {cell_id} removal_boundary", raw.get("removal_boundary")),
            stateless=stateless,
            owned_state=states,
            allowed_effect_classes=string_list(f"cell {cell_id} effects", raw.get("allowed_effect_classes"), allow_empty=True),
            contracts=contracts,
            proof_entrypoint=nonempty(f"cell {cell_id} proof_entrypoint", raw.get("proof_entrypoint")),
            proof_ceiling=nonempty(f"cell {cell_id} proof_ceiling", raw.get("proof_ceiling")),
            edge_profiles=string_list(f"cell {cell_id} edge_profiles", raw.get("edge_profiles"), allow_empty=True),
            product_pulse=nonempty(f"cell {cell_id} product_pulse", pulse) if pulse else None,
            not_applicable_reason=nonempty(f"cell {cell_id} not_applicable_reason", not_applicable) if not_applicable else None,
            implementation_support=support,
            evidence_execution_status=execution,
            providers=string_list(f"cell {cell_id} providers", raw.get("providers"), allow_empty=True),
            consumers=string_list(f"cell {cell_id} consumers", raw.get("consumers"), allow_empty=True),
            invalidation=string_list(f"cell {cell_id} invalidation", raw.get("invalidation")),
            manifest_sha256=manifest_hash,
            scope_units=units,
        ))
    return result


def compile_registry(root: Path, exact_source: str) -> tuple[dict[str, Any], list[Finding]]:
    pair = normative_pair(root)
    units = scope_units(root)
    findings: list[Finding] = []
    cells: list[Cell] = []
    package_names: dict[str, str] = {}

    for manifest in sorted(cargo_manifests(root)):
        payload = read_toml(manifest)
        package = payload.get("package")
        if not isinstance(package, dict):
            continue
        name = nonempty(f"{relative(root, manifest)} package.name", package.get("name"))
        package_manifest = relative(root, manifest)
        previous = package_names.get(name)
        if previous:
            findings.append(Finding("duplicate_package_name", package_manifest,
                                    f"also declared by {previous}", name))
            continue
        package_names[name] = package_manifest
        package_root = relative(root, manifest.parent)
        matched = matching_units(package_root, units)
        if not matched:
            continue

        metadata = package.get("metadata")
        eliot = metadata.get("eliot") if isinstance(metadata, dict) else None
        if not isinstance(eliot, dict):
            findings.append(Finding("missing_eliot_metadata", package_manifest,
                                    "in-scope package lacks [package.metadata.eliot]", name))
            continue
        source_owner = eliot.get("source_maintenance_owner")
        cell_manifest = eliot.get("cell_manifest")
        if not isinstance(source_owner, str) or not source_owner.strip():
            findings.append(Finding("missing_source_maintenance_owner", package_manifest,
                                    "source maintenance owner is not declared", name))
            continue
        if not isinstance(cell_manifest, str) or not cell_manifest.strip():
            findings.append(Finding("missing_cell_manifest", package_manifest,
                                    "package-local cell manifest is not declared", name))
            continue
        try:
            path = repo_path(
                root,
                str(PurePosixPath(package_root) / PurePosixPath(cell_manifest.replace("\\", "/"))),
                f"{name} cell_manifest",
            )
            cells.extend(parse_cell_manifest(
                root,
                package_name=name,
                package_manifest=package_manifest,
                source_owner=source_owner.strip(),
                manifest_path=path,
                units=matched,
            ))
        except RegistryError as error:
            findings.append(Finding("invalid_cell_manifest", package_manifest, str(error), name))

    cell_ids: dict[str, Cell] = {}
    state_owners: dict[str, tuple[str, str]] = {}
    contract_owners: dict[str, tuple[str, str]] = {}
    for cell in cells:
        if cell.cell_id in cell_ids:
            findings.append(Finding("duplicate_cell_id", cell.cell_manifest,
                                    f"also declared by {cell_ids[cell.cell_id].package}",
                                    cell.package, cell.cell_id))
        else:
            cell_ids[cell.cell_id] = cell
        for state in cell.owned_state:
            previous = state_owners.get(state.state_id)
            if previous:
                findings.append(Finding("duplicate_state_owner", cell.cell_manifest,
                                        f"{state.state_id} already owned by {previous[0]} in {previous[1]}",
                                        cell.package, cell.cell_id))
            else:
                state_owners[state.state_id] = (state.owner, cell.cell_id)
        for contract in cell.contracts:
            previous = contract_owners.get(contract.path)
            if previous and previous[0] != contract.owner:
                findings.append(Finding("duplicate_contract_owner", contract.path,
                                        f"{contract.owner} conflicts with {previous[0]} from {previous[1]}",
                                        cell.package, cell.cell_id))
            else:
                contract_owners[contract.path] = (contract.owner, cell.cell_id)

    registry: dict[str, Any] = {
        "schema": REGISTRY_SCHEMA,
        "authority": "NON_AUTHORITATIVE_GENERATED_EVIDENCE",
        "normative_pair": pair,
        "source_sha": source_identity(exact_source),
        "scope_selector": "workstreams/core-daemons/inventory.json",
        "scope_rule": "inventory selects package paths only; explicit package-local manifests own registry claims",
        "cells": [asdict(cell) for cell in sorted(cells, key=lambda item: item.cell_id)],
        "findings": [asdict(finding) for finding in sorted(
            findings, key=lambda item: (item.code, item.path, item.package or "", item.cell_id or "")
        )],
        "status": "COMPLETE" if not findings else "PARTIAL",
    }
    registry["registry_sha256"] = sha256(canonical_json(registry))
    return registry, findings


def current_source(root: Path, explicit: str | None) -> str:
    if explicit:
        return source_identity(explicit)
    if os.environ.get("GITHUB_SHA"):
        return source_identity(os.environ["GITHUB_SHA"])
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, check=True,
            capture_output=True, text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        fail("--source-sha is required when Git identity is unavailable")
    return source_identity(completed.stdout.strip())


def write_registry(path: Path | None, registry: dict[str, Any]) -> None:
    text = json.dumps(registry, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if path is None:
        sys.stdout.write(text)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")


def fixture(root: Path) -> tuple[Path, str]:
    (root / "docs/architecture").mkdir(parents=True)
    architecture = root / "docs/architecture/ELIOT_ARCHITECTURE.md"
    implementation = root / "docs/architecture/ELIOT_IMPLEMENTATION.md"
    architecture.write_text("architecture\n", encoding="utf-8")
    implementation.write_text("implementation\n", encoding="utf-8")
    ah, ih = sha256(architecture.read_bytes()), sha256(implementation.read_bytes())
    pair = "sha256:" + sha256(PAIR_DOMAIN + ah.encode() + b"\x00" + ih.encode() + b"\x00")
    (root / "docs/normative-pair.toml").write_text(
        f'''schema_version = "{PAIR_SCHEMA}"
status = "accepted"
repository_authority_branch = "main"
pair_key_algorithm = "{PAIR_ALGORITHM}"
pair_key = "{pair}"
architecture_path = "docs/architecture/ELIOT_ARCHITECTURE.md"
architecture_sha256 = "{ah}"
implementation_path = "docs/architecture/ELIOT_IMPLEMENTATION.md"
implementation_sha256 = "{ih}"
''', encoding="utf-8")
    (root / "workstreams/core-daemons").mkdir(parents=True)
    (root / "workstreams/core-daemons/inventory.json").write_text(
        json.dumps({"units": [{"id": "host", "paths": ["crates/host"]}]}),
        encoding="utf-8")
    package = root / "crates/host"
    (package / "src").mkdir(parents=True)
    (package / "src/lib.rs").write_text("pub struct Contract;\n", encoding="utf-8")
    (package / "Cargo.toml").write_text(
        '''[package]
name = "eliot-host-test"
version = "0.1.0"
edition = "2024"
[package.metadata.eliot]
source_maintenance_owner = "source.host"
cell_manifest = "capability-cells.toml"
''', encoding="utf-8")
    manifest = package / "capability-cells.toml"
    manifest.write_text(
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
removal_boundary = "Migration proof is required."
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
''', encoding="utf-8")
    return manifest, pair


def self_test() -> None:
    for value in ("a" * 40, "b" * 64):
        if source_identity(value) != value:
            fail("valid source identity changed")
    for value in ("a" * 39, "a" * 41, "a" * 63, "a" * 65, "A" * 40, "g" * 40):
        try:
            source_identity(value)
        except RegistryError:
            pass
        else:
            fail(f"invalid source identity was accepted: {value[:8]}... len={len(value)}")

    with tempfile.TemporaryDirectory(prefix="eliot-cell-registry-") as temporary:
        root = Path(temporary)
        manifest, pair = fixture(root)
        registry, findings = compile_registry(root, "c" * 40)
        if findings or registry["status"] != "COMPLETE" or len(registry["cells"]) != 1:
            fail("valid fixture did not compile cleanly")

        original = manifest.read_text(encoding="utf-8")
        manifest.write_text(original.replace('proof_entrypoint = "cargo test -p eliot-host-test"\n', ""), encoding="utf-8")
        _, broken = compile_registry(root, "d" * 64)
        if not any(finding.code == "invalid_cell_manifest" for finding in broken):
            fail("missing proof entrypoint was accepted")
        manifest.write_text(original, encoding="utf-8")

        receipt = root / "docs/normative-pair.toml"
        receipt.write_text(receipt.read_text(encoding="utf-8").replace(pair, "sha256:" + "0" * 64), encoding="utf-8")
        try:
            compile_registry(root, "e" * 40)
        except RegistryError:
            pass
        else:
            fail("stale normative pair was accepted")

    print("CAPABILITY_CELL_REGISTRY_SELF_TEST: PASS cases=11")


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
    exact_source = current_source(root, args.source_sha)
    registry, findings = compile_registry(root, exact_source)
    if findings and not args.allow_partial:
        codes = ", ".join(sorted({finding.code for finding in findings}))
        fail(f"registry is PARTIAL with {len(findings)} finding(s): {codes}")

    if args.command == "generate":
        write_registry(args.output, registry)
        print(f"CAPABILITY_CELL_REGISTRY_GENERATE: {registry['status']} cells={len(registry['cells'])} findings={len(findings)}", file=sys.stderr)
    else:
        if args.output is None or not args.output.is_file():
            fail("validate requires an existing --output file")
        try:
            observed = json.loads(args.output.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            fail(f"cannot parse existing registry: {error}")
        if observed != registry:
            fail("generated registry is stale or does not match current inputs")
        print(f"CAPABILITY_CELL_REGISTRY_VALIDATE: PASS cells={len(registry['cells'])} source={exact_source}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RegistryError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
