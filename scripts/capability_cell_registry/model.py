"""Shared types and validation primitives for capability-cell evidence."""

from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

REGISTRY_SCHEMA = "eliot.capability-cell-registry.v1"
CELL_SCHEMA = "eliot.capability-cells.v1"
SCOPE_SCHEMA = "eliot.capability-cell-registry-scope.v1"
PAIR_SCHEMA = "eliot-normative-pair-v1"
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


class RegistryError(RuntimeError):
    """Stable capability-cell compiler/validator failure."""


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
class ScopeSelection:
    contract_path: str
    contract_sha256: str
    inventory_path: str
    inventory_sha256: str
    explicit_package_roots: tuple[str, ...]
    selected_inventory_units: tuple[str, ...]
    unselected_inventory_units: tuple[str, ...]
    selected_paths: tuple[str, ...]
    coverage_status: str


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
    scope_selectors: tuple[str, ...]


def fail(message: str) -> None:
    raise RegistryError(f"CAPABILITY_CELL_REGISTRY_FAIL: {message}")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def nonempty(field: str, value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or any(char in value for char in "\r\n\x00")
    ):
        fail(f"{field} must be a non-empty single-line string")
    return value.strip()


def string_list(
    field: str,
    value: Any,
    *,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, list) or (not allow_empty and not value):
        qualifier = "possibly empty" if allow_empty else "non-empty"
        fail(f"{field} must be a {qualifier} list")
    result = tuple(
        sorted(nonempty(f"{field}[{index}]", item) for index, item in enumerate(value))
    )
    if len(set(result)) != len(result):
        fail(f"{field} contains duplicates")
    return result


def lower_hex(field: str, value: Any, lengths: set[int]) -> str:
    if (
        not isinstance(value, str)
        or len(value) not in lengths
        or any(char not in "0123456789abcdef" for char in value)
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


def resolved_repo_entry(
    root: Path,
    value: Any,
    field: str,
) -> tuple[PurePosixPath, Path]:
    relative_path = PurePosixPath(nonempty(field, value).replace("\\", "/"))
    if relative_path.is_absolute() or ".." in relative_path.parts:
        fail(f"{field} must remain inside the repository")
    resolved = (root / Path(*relative_path.parts)).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        fail(f"{field} escapes the repository")
    return relative_path, resolved


def repo_path(root: Path, value: Any, field: str) -> Path:
    relative_path, resolved = resolved_repo_entry(root, value, field)
    if not resolved.is_file():
        fail(f"{field} does not resolve to a file: {relative_path}")
    return resolved


def repo_directory(root: Path, value: Any, field: str) -> Path:
    relative_path, resolved = resolved_repo_entry(root, value, field)
    if not resolved.is_dir():
        fail(f"{field} does not resolve to a directory: {relative_path}")
    if not (resolved / "Cargo.toml").is_file():
        fail(f"{field} is not a Cargo package root: {relative_path}")
    return resolved


def relative(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()
