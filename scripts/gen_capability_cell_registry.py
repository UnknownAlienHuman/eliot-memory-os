#!/usr/bin/env python3
"""Generate the daemon projection and native-worker #13 capability-cell registry.

The canonical source of the daemon capability cells is
`bins/eliotd/Cargo.toml::[package.metadata.eliot]` (`functional_cell_refs` and
`functional_cell_state_owners`). The `[[declared_functional_cell]]` block of
`workstreams/core-daemons/capability-cell-registry.contract.toml` is GENERATED
from that manifest instead of hand-copied, so the contract can never silently
diverge from the declaration it claims to project (I2.23: a generated
`CapabilityCellRegistry` is compiled from `[package.metadata.eliot]`
`.functional_cell_refs`; prose never maintains a parallel list).

Usage:

    python scripts/gen_capability_cell_registry.py            # write the block
    python scripts/gen_capability_cell_registry.py --check    # gate: non-zero if stale

`--check` compares the committed block byte for byte against what the current
manifest would emit. A manifest cell/owner change therefore fails the gate
until the contract is regenerated and reviewed. A hand-edited generated row
cannot be kept, because the check compares bytes.

The worker record is generated from the worker package metadata, its adjacent
`capability-cell.contract.toml`, the worker bundle dependency, the current
normative pair, and the three I2.20 capsules. Its source identity hashes the
workspace manifest and full lockfile, those package/contract inputs, the
typed #13 contract, this generator, the capsules, and the source/test paths
selected by the context capsule. A change outside those inputs does not stale
the generated record; any `Cargo.lock` change does, because the typed source
identity binds the full lockfile digest. Kernel startup validates the
compiled record and does not scan or hash the checkout.

The worker record block is written into
`bins/eliot-kernel/src/composition_bootstrap.rs`. The existing daemon
projection remains in `workstreams/core-daemons/capability-cell-registry.contract.toml`.

Ownership truth flows one way, manifest -> contract. The per-cell evidence
pointers (`source_owner`, `source_evidence`, `state_evidence`,
`runtime_bundle`, `stateless`) are pinned per-cell annex data carried from the
existing rows keyed by cell id: they are pointers into the source, not a
parallel owner list, and the generator refuses to invent, drop, or reassign
one. A cell with an undeclared state owner, or a second owner for the same
mutable state, is a registry defect (I2.23), and the generator fails closed
instead of emitting it.

The generator fails closed. A missing manifest table, a refs/owners cell-set
mismatch, a duplicate cell, an owner symbol claimed by two cells, a manifest
cell with no pinned evidence row, and a pinned row for a cell the manifest no
longer declares are each a non-zero exit with a named reason, so the committed
block can never silently diverge from the manifest it claims to mirror.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

# ---------------------------------------------------------------------------
# Pinned inputs.
# ---------------------------------------------------------------------------

MANIFEST_RELATIVE = "bins/eliotd/Cargo.toml"
CONTRACT_RELATIVE = "workstreams/core-daemons/capability-cell-registry.contract.toml"
METADATA_POINTER = "bins/eliotd/Cargo.toml::package.metadata.eliot.functional_cell_refs"

BEGIN_MARKER = (
    "# BEGIN GENERATED declared_functional_cell "
    "(scripts/gen_capability_cell_registry.py from "
    "bins/eliotd/Cargo.toml [package.metadata.eliot]; do not hand-edit)"
)
END_MARKER = "# END GENERATED declared_functional_cell"

ANNEX_FIELDS = (
    "source_owner",
    "source_evidence",
    "state_evidence",
    "runtime_bundle",
    "stateless",
)

WORKER_MANIFEST_RELATIVE = "crates/modules/eliot-native-worker-core/Cargo.toml"
WORKER_CONTRACT_RELATIVE = (
    "crates/modules/eliot-native-worker-core/capability-cell.contract.toml"
)
WORKER_BUNDLE_MANIFEST_RELATIVE = "bins/eliot-native-worker/Cargo.toml"
WORKER_CAPSULE_ROOT = "docs/code-navigation/capsules/native-worker-core"
WORKER_CAPSULES = {
    "contract_kit": f"{WORKER_CAPSULE_ROOT}/contract_kit.json",
    "context_capsule": f"{WORKER_CAPSULE_ROOT}/context_capsule.json",
    "test_capsule": f"{WORKER_CAPSULE_ROOT}/test_capsule.json",
}
WORKER_REGISTRY_RELATIVE = "bins/eliot-kernel/src/composition_bootstrap.rs"
REGISTRY_SOURCE_RELATIVE = (
    "crates/foundation/eliot-contracts/src/capability_cell_registry.rs"
)
NORMATIVE_PAIR_RELATIVE = "docs/normative-pair.toml"
GENERATOR_VERSION = "1.0.0"
WORKER_REGISTRY_BEGIN = (
    "// BEGIN GENERATED native-worker capability-cell registry "
    "(scripts/gen_capability_cell_registry.py; do not hand-edit)"
)
WORKER_REGISTRY_END = "// END GENERATED native-worker capability-cell registry"
WORKER_CELL_ID_MARKER = "NATIVE_WORKER_CAPABILITY_CELL_ID"
WORKER_PACKAGE_MARKER = "NATIVE_WORKER_CAPABILITY_SOURCE_PACKAGE"
WORKER_REGISTRY_MARKER = "NATIVE_WORKER_CAPABILITY_CELL_REGISTRY_JSON"


def rust_raw_string(value: str) -> str:
    """Use the shortest raw delimiter that cannot occur in the JSON body."""
    hashes = "#"
    while f'"{hashes}' in value:
        hashes += "#"
    return f'r{hashes}"{value}"{hashes}'


class RegistryError(Exception):
    """Fail-closed named reason; the exit code distinguishes stale from broken."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason


def load_manifest_cells(manifest_path: Path) -> tuple[list[str], dict[str, dict[str, str]]]:
    """Return manifest cell order and the cell -> {state, owner} map."""
    try:
        payload = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise RegistryError("MANIFEST_UNREADABLE", str(error)) from error
    metadata = payload.get("package", {}).get("metadata", {}).get("eliot")
    if not isinstance(metadata, dict):
        raise RegistryError(
            "MANIFEST_METADATA_MISSING",
            f"{MANIFEST_RELATIVE} has no [package.metadata.eliot] table",
        )
    refs = metadata.get("functional_cell_refs")
    if not isinstance(refs, list) or not refs or not all(
        isinstance(cell, str) and cell.strip() for cell in refs
    ):
        raise RegistryError(
            "FUNCTIONAL_CELL_REFS_MISSING",
            "functional_cell_refs must be a non-empty string list",
        )
    owners = metadata.get("functional_cell_state_owners")
    if not isinstance(owners, list) or not owners:
        raise RegistryError(
            "STATE_OWNERS_MISSING",
            "functional_cell_state_owners must be a non-empty table list",
        )
    by_cell: dict[str, dict[str, str]] = {}
    seen_owners: dict[str, str] = {}
    for index, entry in enumerate(owners):
        if not isinstance(entry, dict):
            raise RegistryError(
                "STATE_OWNER_SHAPE",
                f"functional_cell_state_owners[{index}] is not a table",
            )
        cell = entry.get("cell")
        state = entry.get("state")
        owner = entry.get("owner")
        for field, value in (("cell", cell), ("state", state), ("owner", owner)):
            if not isinstance(value, str) or not value.strip():
                raise RegistryError(
                    "STATE_OWNER_SHAPE",
                    f"functional_cell_state_owners[{index}] has an empty {field}",
                )
        if cell in by_cell:
            raise RegistryError("DUPLICATE_CELL", f"cell is declared twice: {cell}")
        if owner in seen_owners:
            raise RegistryError(
                "DUPLICATE_STATE_OWNER",
                f"owner {owner} is claimed by {seen_owners[owner]} and {cell}; "
                "a second owner for mutable state is a registry defect",
            )
        seen_owners[owner] = cell
        by_cell[cell] = {"state": state, "owner": owner}
    if set(refs) != set(by_cell):
        missing = sorted(set(refs) - set(by_cell))
        extra = sorted(set(by_cell) - set(refs))
        raise RegistryError(
            "CELL_SET_MISMATCH",
            f"functional_cell_refs and functional_cell_state_owners disagree: "
            f"refs-without-owner={missing} owners-without-ref={extra}",
        )
    if len(set(refs)) != len(refs):
        raise RegistryError("DUPLICATE_CELL", "functional_cell_refs repeats a cell")
    return list(refs), by_cell


def load_evidence_annex(contract_text: str) -> dict[str, dict[str, object]]:
    """Return the pinned per-cell evidence columns keyed by cell id."""
    try:
        payload = tomllib.loads(contract_text)
    except tomllib.TOMLDecodeError as error:
        raise RegistryError("CONTRACT_UNREADABLE", str(error)) from error
    rows = payload.get("declared_functional_cell", [])
    if not isinstance(rows, list):
        raise RegistryError("CONTRACT_SHAPE", "declared_functional_cell is not an array")
    annex: dict[str, dict[str, object]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or not isinstance(row.get("cell"), str):
            raise RegistryError(
                "CONTRACT_SHAPE", f"declared_functional_cell[{index}] names no cell"
            )
        cell = row["cell"]
        if cell in annex:
            raise RegistryError("DUPLICATE_ANNEX_CELL", f"annex repeats cell: {cell}")
        pinned: dict[str, object] = {}
        for field in ANNEX_FIELDS:
            value = row.get(field)
            if field == "stateless":
                if not isinstance(value, bool):
                    raise RegistryError(
                        "EVIDENCE_PIN_SHAPE",
                        f"cell {cell} has a non-boolean stateless pin",
                    )
            elif not isinstance(value, str) or not value.strip():
                raise RegistryError(
                    "EVIDENCE_PIN_SHAPE", f"cell {cell} has an empty {field} pin"
                )
            pinned[field] = value
        annex[cell] = pinned
    return annex


def _quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_row(cell: str, owner: str, annex: dict[str, object]) -> str:
    lines = [
        "[[declared_functional_cell]]",
        f"cell = {_quote(cell)}",
        f"declared_by = {_quote(METADATA_POINTER)}",
        f"source_owner = {_quote(str(annex['source_owner']))}",
        f"mutable_state_owner = {_quote(owner)}",
        f"source_evidence = {_quote(str(annex['source_evidence']))}",
        f"state_evidence = {_quote(str(annex['state_evidence']))}",
        f"runtime_bundle = {_quote(str(annex['runtime_bundle']))}",
        f"stateless = {'true' if annex['stateless'] else 'false'}",
    ]
    return "\n".join(lines)


def render_block(
    cells: list[str],
    owners: dict[str, dict[str, str]],
    annex: dict[str, dict[str, object]],
) -> str:
    """Render the generated inner block, including its surrounding newlines."""
    missing = [cell for cell in cells if cell not in annex]
    if missing:
        raise RegistryError(
            "EVIDENCE_PIN_MISSING",
            f"manifest cells with no pinned evidence row: {missing}",
        )
    stale = sorted(set(annex) - set(cells))
    if stale:
        raise RegistryError(
            "STALE_EVIDENCE_PIN",
            f"pinned evidence rows for cells the manifest no longer declares: {stale}",
        )
    rows = [render_row(cell, owners[cell]["owner"], annex[cell]) for cell in cells]
    return "\n" + "\n\n".join(rows) + "\n"


def replace_block(contract_text: str, block: str) -> str:
    begin = contract_text.find(BEGIN_MARKER)
    end = contract_text.find(END_MARKER)
    if begin < 0 or end < 0 or end < begin:
        raise RegistryError(
            "GENERATED_BLOCK_MARKERS_MISSING",
            "the contract carries no generated declared_functional_cell block",
        )
    head = contract_text[: begin + len(BEGIN_MARKER)]
    tail = contract_text[end:]
    return head + block + tail


def read_bytes(root: Path, relative: str) -> bytes:
    try:
        return (root / relative).read_bytes()
    except OSError as error:
        raise RegistryError("SOURCE_UNREADABLE", f"{relative}: {error}") from error


def read_text(root: Path, relative: str) -> str:
    try:
        return read_bytes(root, relative).decode("utf-8")
    except UnicodeError as error:
        raise RegistryError("SOURCE_UNREADABLE", f"{relative}: {error}") from error


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def parse_toml(root: Path, relative: str) -> dict[str, object]:
    try:
        value = tomllib.loads(read_text(root, relative))
    except tomllib.TOMLDecodeError as error:
        raise RegistryError("TOML_INVALID", f"{relative}: {error}") from error
    if not isinstance(value, dict):
        raise RegistryError("TOML_SHAPE", f"{relative} is not a table")
    return value


def parse_capsule(root: Path, relative: str) -> dict[str, object]:
    try:
        value = json.loads(read_text(root, relative))
    except (json.JSONDecodeError, UnicodeError) as error:
        raise RegistryError("CAPSULE_INVALID", f"{relative}: {error}") from error
    if not isinstance(value, dict):
        raise RegistryError("CAPSULE_SHAPE", f"{relative} is not a JSON object")
    artifact_kind = value.get("artifact_kind")
    schema = value.get("schema_version")
    artifact_digest = value.get("artifact_digest")
    if not all(isinstance(item, str) and item for item in (artifact_kind, schema)):
        raise RegistryError("CAPSULE_IDENTITY_MISSING", relative)
    body = {
        key: item
        for key, item in value.items()
        if key not in {"artifact_digest", "contract_revision"}
    }
    actual = sha256_hex(
        canonical_json({"kind": artifact_kind, "schema": schema, "body": body})
    )
    if artifact_digest != actual:
        raise RegistryError(
            "CAPSULE_DIGEST_MISMATCH",
            f"{relative} declares {artifact_digest!r}, calculated {actual}",
        )
    return value


def _table(value: object, name: str, source: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RegistryError("SOURCE_SHAPE", f"{source} has no {name} table")
    return value


def _require_equal(actual: object, expected: object, field: str) -> None:
    if actual != expected:
        raise RegistryError(
            "SOURCE_DISAGREEMENT", f"{field}: expected {expected!r}, found {actual!r}"
        )


def _safe_relative_path(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RegistryError("SOURCE_PATH_MISSING", field)
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise RegistryError("SOURCE_PATH_INVALID", f"{field}: {value!r}")
    return path.as_posix()


def _worker_toolchain() -> str:
    try:
        result = subprocess.run(
            ["rustc", "-vV"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise RegistryError("TOOLCHAIN_UNAVAILABLE", str(error)) from error
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        raise RegistryError("TOOLCHAIN_IDENTITY_EMPTY", "rustc -vV returned no identity")
    return "; ".join(lines)


def _source_tree_digest(root: Path, capsule_payloads: dict[str, dict[str, object]]) -> str:
    """Bind package/cell evidence inputs, not unrelated Kernel composition code.

    A change outside this list does not stale the generated worker registry.
    The full workspace lockfile remains deliberate because the typed source
    identity names its SHA-256 as Cargo lock provenance; any lockfile change,
    including an unrelated dependency update, requires regeneration.
    """
    paths = {
        "Cargo.toml",
        "Cargo.lock",
        WORKER_MANIFEST_RELATIVE,
        WORKER_CONTRACT_RELATIVE,
        WORKER_BUNDLE_MANIFEST_RELATIVE,
        NORMATIVE_PAIR_RELATIVE,
        REGISTRY_SOURCE_RELATIVE,
        "scripts/gen_capability_cell_registry.py",
        "crates/foundation/eliot-contracts/src/facet_manifest.rs",
        "crates/modules/eliot-native-worker-core/build.rs",
        "crates/modules/eliot-native-worker-core/src/generated/native_worker_facets_v1.rs.in",
        "crates/modules/eliot-native-worker-core/src/generated/native_worker_facets_v1.rs",
        *WORKER_CAPSULES.values(),
    }
    context = capsule_payloads["context_capsule"]
    selected = _table(
        context.get("selected_source_and_tests"),
        "selected_source_and_tests",
        WORKER_CAPSULES["context_capsule"],
    )
    for collection in ("selected_source", "selected_tests"):
        entries = selected.get(collection, [])
        if not isinstance(entries, list):
            raise RegistryError("CAPSULE_SOURCE_SHAPE", collection)
        for entry in entries:
            item = _table(entry, "source entry", collection)
            paths.add(_safe_relative_path(item.get("path"), f"{collection}.path"))

    hashes: list[dict[str, str]] = []
    for relative in sorted(paths):
        contents = read_bytes(root, relative)
        # Git may check out text inputs with CRLF on Windows. Bind source
        # content rather than the local checkout's line-ending convention.
        hashes.append({"path": relative, "sha256": sha256_hex(contents.replace(b"\r\n", b"\n"))})
    return sha256_hex(canonical_json(hashes))


def load_worker_registry(root: Path) -> tuple[str, dict[str, object], str, str]:
    """Build the native-worker registry from package, contract, capsule, and source inputs."""
    source = parse_toml(root, WORKER_MANIFEST_RELATIVE)
    package = _table(source.get("package"), "package", WORKER_MANIFEST_RELATIVE)
    metadata = _table(
        _table(package.get("metadata"), "metadata", WORKER_MANIFEST_RELATIVE).get(
            "eliot"
        ),
        "package.metadata.eliot",
        WORKER_MANIFEST_RELATIVE,
    )
    contract = parse_toml(root, WORKER_CONTRACT_RELATIVE)
    bundle = parse_toml(root, WORKER_BUNDLE_MANIFEST_RELATIVE)
    bundle_package = _table(bundle.get("package"), "package", WORKER_BUNDLE_MANIFEST_RELATIVE)
    bundle_dependencies = _table(
        bundle.get("dependencies"), "dependencies", WORKER_BUNDLE_MANIFEST_RELATIVE
    )

    cell = contract.get("cell")
    source_package = contract.get("source_package")
    _require_equal(metadata.get("functional_cell"), cell, "package functional_cell")
    _require_equal(metadata.get("lifecycle_owner"), contract.get("lifecycle_owner"), "lifecycle_owner")
    _require_equal(metadata.get("source_layer"), contract.get("source_layer"), "source_layer")
    _require_equal(package.get("name"), source_package, "source package name")
    _require_equal(contract.get("source_manifest"), WORKER_MANIFEST_RELATIVE, "source manifest")
    _require_equal(contract.get("worker_bundle_manifest"), WORKER_BUNDLE_MANIFEST_RELATIVE, "worker bundle manifest")
    _require_equal(bundle_package.get("name"), contract.get("worker_bundle_package"), "worker bundle package")
    if "eliot-native-worker-core" not in bundle_dependencies:
        raise RegistryError(
            "WORKER_BUNDLE_DEPENDENCY_MISSING",
            f"{WORKER_BUNDLE_MANIFEST_RELATIVE} does not depend on {source_package}",
        )

    proof_entrypoint = metadata.get("proof_entrypoint")
    if not isinstance(proof_entrypoint, str) or not proof_entrypoint.strip():
        raise RegistryError("PROOF_ENTRYPOINT_MISSING", WORKER_MANIFEST_RELATIVE)
    _require_equal(
        contract.get("proof_entrypoint_source"),
        "package.metadata.eliot.proof_entrypoint",
        "proof entrypoint source",
    )
    _require_equal(
        contract.get("proof_ceiling"),
        "STATIC_FIELD_AND_MIGRATION_CONTRACT_ONLY",
        "conservative proof ceiling",
    )

    capsules = {
        name: parse_capsule(root, relative)
        for name, relative in WORKER_CAPSULES.items()
    }
    kit = capsules["contract_kit"]
    context = capsules["context_capsule"]
    test = capsules["test_capsule"]
    _require_equal(kit.get("artifact_kind"), "ModuleContractKit", "contract-kit kind")
    _require_equal(context.get("artifact_kind"), "CrateContextCapsule", "context-capsule kind")
    _require_equal(test.get("artifact_kind"), "ModuleTestCapsule", "test-capsule kind")
    for name, capsule in capsules.items():
        _require_equal(capsule.get("cell_id"), cell, f"{name} cell id")
    kit_identity = _table(kit.get("crate_or_cell_identity"), "crate_or_cell_identity", WORKER_CAPSULES["contract_kit"])
    _require_equal(kit_identity.get("functional_capability_cell"), cell, "contract-kit cell")
    _require_equal(kit_identity.get("source_package"), source_package, "contract-kit package")
    context_package = _table(context.get("primary_source_package"), "primary_source_package", WORKER_CAPSULES["context_capsule"])
    _require_equal(context_package.get("package"), source_package, "context-capsule package")
    test_proof = _table(test.get("independent_proof_entrypoint"), "independent_proof_entrypoint", WORKER_CAPSULES["test_capsule"])
    _require_equal(test_proof.get("package"), source_package, "test-capsule package")
    test_entrypoint = _table(test_proof.get("entrypoint"), "entrypoint", WORKER_CAPSULES["test_capsule"])
    _require_equal(test_entrypoint.get("value"), proof_entrypoint, "test-capsule proof entrypoint")
    _require_equal(context.get("bound_contract_digest"), kit.get("artifact_digest"), "context contract digest")
    _require_equal(test.get("bound_contract_digest"), kit.get("artifact_digest"), "test contract digest")
    test_ceiling = _table(test.get("proof_level_ceiling"), "proof_level_ceiling", WORKER_CAPSULES["test_capsule"])
    _require_equal(test_ceiling.get("state"), "UNDECLARED", "test-capsule proof ceiling status")

    pair = parse_toml(root, NORMATIVE_PAIR_RELATIVE)
    pair_key = pair.get("pair_key")
    if not isinstance(pair_key, str) or not pair_key.startswith("sha256:"):
        raise RegistryError("NORMATIVE_PAIR_KEY_MISSING", NORMATIVE_PAIR_RELATIVE)
    registry_source = read_text(root, REGISTRY_SOURCE_RELATIVE)
    constant_match = re.search(
        r'pub const EXPECTED_NORMATIVE_PAIR_KEY: &str\s*=\s*"([^"]+)";',
        registry_source,
    )
    if constant_match is None:
        raise RegistryError("EXPECTED_PAIR_CONSTANT_MISSING", REGISTRY_SOURCE_RELATIVE)
    _require_equal(constant_match.group(1), pair_key, "typed registry normative pair key")

    revision_text = contract.get("contract_revision")
    if not isinstance(revision_text, str) or not re.fullmatch(r"\d+\.\d+\.\d+", revision_text):
        raise RegistryError("CONTRACT_REVISION_INVALID", str(revision_text))
    revision = [int(component) for component in revision_text.split(".")]
    if any(component > 65535 for component in revision):
        raise RegistryError("CONTRACT_REVISION_INVALID", revision_text)

    manifest = _table(contract.get("manifest"), "manifest", WORKER_CONTRACT_RELATIVE)
    manifest_owner = manifest.get("owner")
    capsule_presence: dict[str, object] = {}
    for field in ("contract_kit", "context_capsule", "test_capsule"):
        expected_path = WORKER_CAPSULES[field]
        _require_equal(manifest.get(field), expected_path, f"manifest {field} path")
        capsule_presence[field] = {"present": True, "owner": manifest_owner}

    contract_digest = sha256_hex(canonical_json(contract))
    tree_digest = _source_tree_digest(root, capsules)
    lock_digest = sha256_hex(read_bytes(root, "Cargo.lock").replace(b"\r\n", b"\n"))
    toolchain = _worker_toolchain()
    state = contract.get("owned_state")
    state_owner = contract.get("state_owner")
    if not isinstance(state, str) or not state.strip() or not isinstance(state_owner, str):
        raise RegistryError("STATE_OWNERSHIP_MISSING", WORKER_CONTRACT_RELATIVE)

    record: dict[str, object] = {
        "cell": cell,
        "cell_revision": {"major": revision[0], "minor": revision[1], "patch": revision[2]},
        "lifecycle_owner": contract.get("lifecycle_owner"),
        "maintenance_owner": contract.get("maintenance_owner"),
        "semantic_owner": contract.get("semantic_owner"),
        "generation_owner": contract.get("generation_owner"),
        "stateless": contract.get("stateless"),
        "state_owners": [{"state": state, "owner": state_owner}],
        "contract_digest": contract_digest,
        "contract_digest_source": f"{WORKER_CONTRACT_RELATIVE}#contract-surface",
        "runtime_bundle": contract.get("runtime_bundle"),
        "execution_contour": contract.get("execution_contour"),
        "allowed_effect_classes": contract.get("allowed_effect_classes"),
        "replacement_class": contract.get("replacement_class"),
        "removal_boundary": contract.get("removal_boundary"),
        "proof_entrypoint": proof_entrypoint,
        "proof_ceiling": contract.get("proof_ceiling"),
        "affected_edges": [],
        "product_pulse": {
            "NOT_APPLICABLE": {"reason": contract.get("product_pulse_not_applicable_reason")}
        },
        "freshness": {
            "current_support": contract.get("current_support"),
            "invalidation": contract.get("invalidation"),
        },
        "source_crate": source_package,
        "manifest": capsule_presence,
    }
    registry: dict[str, object] = {
        "registry_version": 1,
        "pair_key": pair_key,
        "source_identity": {
            "tree_digest": tree_digest,
            "cargo_lock_digest": lock_digest,
            "toolchain": toolchain,
            "generator_version": GENERATOR_VERSION,
        },
        "generator_version": GENERATOR_VERSION,
        "cells": [record],
    }
    return (
        json.dumps(registry, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        record,
        str(cell),
        str(source_package),
    )


def replace_worker_registry_block(source: str, generated: str) -> str:
    begin = source.find(WORKER_REGISTRY_BEGIN)
    end = source.find(WORKER_REGISTRY_END)
    if begin < 0 or end < 0 or end < begin:
        raise RegistryError(
            "WORKER_REGISTRY_MARKERS_MISSING", WORKER_REGISTRY_RELATIVE
        )
    end += len(WORKER_REGISTRY_END)
    return source[:begin] + generated + source[end:]


def emit_worker_registry(root: Path) -> tuple[str, str]:
    source = read_text(root, WORKER_REGISTRY_RELATIVE)
    registry_json, _record, cell, package = load_worker_registry(root)
    newline = "\r\n" if "\r\n" in source else "\n"
    generated = newline.join(
        (
            WORKER_REGISTRY_BEGIN,
            f'const {WORKER_CELL_ID_MARKER}: &str = {json.dumps(cell)};',
            f'const {WORKER_PACKAGE_MARKER}: &str = {json.dumps(package)};',
            f'const {WORKER_REGISTRY_MARKER}: &str = {rust_raw_string(registry_json)};',
            WORKER_REGISTRY_END,
        )
    )
    return source, replace_worker_registry_block(source, generated)


def emit(root: Path) -> tuple[str, str]:
    """Return (committed_text, regenerated_text) for the contract file."""
    manifest_path = root / MANIFEST_RELATIVE
    contract_path = root / CONTRACT_RELATIVE
    try:
        committed = contract_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise RegistryError("CONTRACT_UNREADABLE", str(error)) from error
    cells, owners = load_manifest_cells(manifest_path)
    annex = load_evidence_annex(committed)
    return committed, replace_block(committed, render_block(cells, owners, annex))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate the capability-cell registry block from the eliotd manifest."
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--check", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    try:
        committed, regenerated = emit(root)
        bootstrap_committed, bootstrap_regenerated = emit_worker_registry(root)
    except RegistryError as error:
        print(f"CAPABILITY_CELL_REGISTRY_{error.reason}: {error}", file=sys.stderr)
        return 2
    if regenerated == committed and bootstrap_regenerated == bootstrap_committed:
        print(
            "CAPABILITY_CELL_REGISTRY_GENERATE: IN_SYNC "
            f"source={MANIFEST_RELATIVE} contract={CONTRACT_RELATIVE} "
            f"worker_registry={WORKER_REGISTRY_RELATIVE}"
        )
        return 0
    if args.check:
        print(
            "CAPABILITY_CELL_REGISTRY_STALE: regenerate with "
            "python scripts/gen_capability_cell_registry.py",
            file=sys.stderr,
        )
        return 1
    if regenerated != committed:
        (root / CONTRACT_RELATIVE).write_bytes(regenerated.encode("utf-8"))
    if bootstrap_regenerated != bootstrap_committed:
        (root / WORKER_REGISTRY_RELATIVE).write_bytes(
            bootstrap_regenerated.encode("utf-8")
        )
    print(
        "CAPABILITY_CELL_REGISTRY_GENERATE: WROTE "
        f"source={MANIFEST_RELATIVE} contract={CONTRACT_RELATIVE} "
        f"worker_registry={WORKER_REGISTRY_RELATIVE}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
