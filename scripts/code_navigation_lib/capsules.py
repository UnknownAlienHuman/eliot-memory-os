"""Mandatory I2.20 contract, context, and test capsule generation.

Generates, for every declared functional capability cell of the current
workspace, the mandatory triad `ModuleContractKit` + `CrateContextCapsule` +
`ModuleTestCapsule`, and enumerates every workspace capability - reachable,
unreachable, and currently excluded - in one deterministic projection.

The triad is generated only from existing machine-checked metadata:
`[package.metadata.eliot]`, `module.toml`, the Cargo path-dependency graph,
the documentation contract catalogue `docs/architecture/handle-index.json`,
the logical responsibility blocks, the runtime/process/tracked-debt records in
`config/architecture-boundaries.toml`, the `#1811` standalone dispositions,
and the source/test selection observed in the package itself. A field that
cannot be derived from those sources is emitted as an explicit `UNDECLARED`
semantic field naming the origin it would have to be declared in; it is never
defaulted from a crate name or copied from a sibling capability.

Every artifact carries stable identity, a contract revision, its own SHA-256
digest, and the digests of the metadata and selected source it was generated
from. `classify_capsule_set` never reports `ImplementationSupport` above
`CURRENT_UNVERIFIED` for a cell whose triad is absent, stale, or lacks an
executable proof entrypoint (I2.20, `ARCH-MOD-03`).
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from .blocks import load_blocks
from .cargo import (
    discover_manifests,
    expand_workspace_paths,
    iter_dependency_specs,
    package_metadata,
    resolve_dependency_path,
    resolve_dependency_spec,
)
from .common import (
    DEFAULT_BLOCKS,
    DEFAULT_HANDLE_INDEX,
    NavigationError,
    normalize_repo_path,
    path_matches,
    read_json,
    read_toml,
    sha256_file,
    walk_files,
)

SCHEMA = "eliot-capule-triad-v1"
GENERATOR = "scripts/code_navigation.py capsules"
GENERATOR_VERSION = "1.0.0"
CAPSULE_ROOT = "docs/code-navigation/capsules"
INDEX_PATH = f"{CAPSULE_ROOT}/index.json"
BOUNDARIES_PATH = "config/architecture-boundaries.toml"
DISPOSITIONS_PATH = "workstreams/security/standalone-crate-dispositions.toml"
CONTRACT_HANDLE = "I2.20"
CONTRACT_FRAGMENT = (
    "docs/architecture/"
    "I02-20-module-contract-kit-crate-context-capsule-and-module-test-capsule.md"
)
MODULE_MANIFEST = "module.toml"
STU_METHOD = "STU = ceil(UTF-8 bytes / 3) (I2.16)"

# I2.20 triad: projected key -> contract name.
ARTIFACT_KINDS = (
    ("contract_kit", "ModuleContractKit"),
    ("context_capsule", "CrateContextCapsule"),
    ("test_capsule", "ModuleTestCapsule"),
)

# I0.5 `ImplementationSupport` order, weakest first.
SUPPORT_LADDER = (
    "TARGET",
    "BLOCKED",
    "DEFERRED",
    "PARTIAL",
    "CURRENT_UNVERIFIED",
    "CURRENT_VERIFIED",
)
SUPPORT_CEILING_WITH_TRIAD = "CURRENT_UNVERIFIED"

CELL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
HANDLE_BODY_RE = re.compile(r"^[A-Z]?[0-9]+(?:\.[0-9]+)*$")
TEST_ATTRIBUTE_RE = re.compile(r"#\[\s*(?:tokio::|rstest::|test_case::)?test\b")
CFG_TEST_RE = re.compile(r"#\[\s*cfg\s*\(\s*test\s*\)\s*\]")
FAKE_PORT_RE = re.compile(r"\b(?:fake|mock|stub)\w*\b", re.IGNORECASE)
FAULT_CASE_RE = re.compile(
    r"\b(?:fault|restart|replay|recover|retry|reconnect|idempoten|roll_?back)\w*\b",
    re.IGNORECASE,
)
CORPUS_DIRS = ("data", "fixtures", "golden", "corpus", "snapshot", "snapshots")


# ---------------------------------------------------------------------------
# Deterministic serialization helpers
# ---------------------------------------------------------------------------


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def render(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def digest_of(kind: str, body: dict[str, Any]) -> str:
    """One plain SHA-256 over the namespaced canonical body.

    `artifact_digest` is excluded because it is the digest itself, and
    `contract_revision` is excluded because it is derived from that digest;
    including either would make recomputation unsatisfiable.
    """
    body = {
        key: value
        for key, value in body.items()
        if key not in {"artifact_digest", "contract_revision"}
    }
    return _sha256(_canonical({"kind": kind, "schema": SCHEMA, "body": body}))


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({_text(item) for item in value if _text(item)})


def _declared(value: Any, origin: str) -> dict[str, Any]:
    """One explicit non-derivable semantic field: declared, or explicitly not.

    A field absent from the machine-checked metadata is reported as
    `UNDECLARED` together with the origin it would have to be declared in. It
    is never defaulted, inferred, or borrowed from a sibling capability.
    """
    if value is None or (
        isinstance(value, (str, list, dict)) and len(value) == 0
    ):
        return {"state": "UNDECLARED", "origin": origin, "value": None}
    return {"state": "DECLARED", "origin": origin, "value": value}


def _weakest(*values: str) -> str:
    known = [value for value in values if value in SUPPORT_LADDER]
    if not known:
        return "TARGET"
    return min(known, key=SUPPORT_LADDER.index)


# ---------------------------------------------------------------------------
# Input discovery
# ---------------------------------------------------------------------------


def _workspace_tables(root: Path) -> tuple[list[str], list[str], list[str], dict[str, Any]]:
    payload = read_toml(root / "Cargo.toml")
    workspace = payload.get("workspace")
    if not isinstance(workspace, dict):
        raise NavigationError("root Cargo.toml has no [workspace] table")
    raw_members = workspace.get("members")
    if not isinstance(raw_members, list) or not raw_members:
        raise NavigationError("workspace.members must be a non-empty array")
    members = expand_workspace_paths(
        root, [str(item) for item in raw_members], "workspace.members"
    )
    raw_exclude = workspace.get("exclude", [])
    if not isinstance(raw_exclude, list):
        raise NavigationError("workspace.exclude must be an array")
    excludes = (
        expand_workspace_paths(root, [str(item) for item in raw_exclude], "workspace.exclude")
        if raw_exclude
        else []
    )
    raw_defaults = workspace.get("default-members", [])
    if not isinstance(raw_defaults, list):
        raise NavigationError("workspace.default-members must be an array")
    defaults = expand_workspace_paths(
        root, [str(item) for item in raw_defaults], "workspace.default-members"
    )
    dependencies = workspace.get("dependencies")
    return (
        members,
        excludes,
        defaults if raw_defaults else list(members),
        dependencies if isinstance(dependencies, dict) else {},
    )


def _dispositions(root: Path) -> dict[str, dict[str, str]]:
    """`#1811` standalone dispositions: development-tool/admission status."""
    path = root / DISPOSITIONS_PATH
    if not path.is_file():
        return {}
    rows: dict[str, dict[str, str]] = {}
    for row in read_toml(path).get("crate", []):
        if not isinstance(row, dict):
            continue
        package_path = _text(row.get("path"))
        if not package_path:
            continue
        rows[package_path] = {
            "disposition": _text(row.get("disposition")),
            "owner": _text(row.get("owner")),
            "workspace_admission": _text(row.get("workspace_admission")),
            "source": DISPOSITIONS_PATH,
        }
    return rows


def _standalone_packages(root: Path, known: set[str]) -> list[str]:
    """Packages carrying their own `[workspace]` table: the excluded scope."""
    found: list[str] = []
    for relative in discover_manifests(root):
        package_root = PurePosixPath(relative).parent.as_posix()
        if package_root in known:
            continue
        if any(
            part in {"target", "testdata", "fixtures"}
            for part in PurePosixPath(relative).parts
        ):
            continue
        path = root / relative
        try:
            text = path.read_text(encoding="utf-8")
            payload = read_toml(path)
        except (OSError, UnicodeDecodeError, NavigationError):
            continue
        if "[workspace]" not in text or not isinstance(payload.get("package"), dict):
            continue
        found.append(package_root)
    return sorted(found)


def _boundaries(root: Path) -> dict[str, Any]:
    """Runtime roots, process owners, and tracked debt (architecture boundaries)."""
    path = root / BOUNDARIES_PATH
    if not path.is_file():
        return {"runtime_roots": [], "process_owners": [], "tracked_debt": []}
    payload = read_toml(path)
    runtime_roots = sorted(
        (
            {
                "package": _text(row.get("package")),
                "issue": _text(row.get("issue")),
                "forbidden_exact": _strings(row.get("forbidden_exact")),
                "forbidden_prefix": _strings(row.get("forbidden_prefix")),
            }
            for row in payload.get("runtime_root", [])
            if isinstance(row, dict)
        ),
        key=lambda item: item["package"],
    )
    process_owners = sorted(
        (
            {"path": normalize_repo_path(_text(row["path"])), "issue": _text(row.get("issue"))}
            for row in payload.get("process_owner", [])
            if isinstance(row, dict) and _text(row.get("path"))
        ),
        key=lambda item: item["path"],
    )
    tracked_debt = sorted(
        (
            {
                "kind": _text(row.get("kind")),
                "path": normalize_repo_path(_text(row.get("path"))),
                "issue": _text(row.get("issue")),
                "class": _text(row.get("class")),
                "reason": _text(row.get("reason")),
                "remove_when": _text(row.get("remove_when")),
            }
            for row in payload.get("tracked_debt", [])
            if isinstance(row, dict) and _text(row.get("path"))
        ),
        key=lambda item: (item["kind"], item["path"]),
    )
    return {
        "runtime_roots": runtime_roots,
        "process_owners": process_owners,
        "tracked_debt": tracked_debt,
    }


def _contract_catalogue(root: Path) -> dict[str, Any]:
    path = root / DEFAULT_HANDLE_INDEX
    if not path.is_file():
        raise NavigationError(f"contract catalogue is missing: {DEFAULT_HANDLE_INDEX}")
    payload = read_json(path)
    if payload.get("schema_version") != "eliot-handle-index-v1":
        raise NavigationError("unsupported contract catalogue schema")
    handles = payload.get("handles")
    if not isinstance(handles, dict) or not handles:
        raise NavigationError("contract catalogue holds no handles")
    return handles


def _resolve_contract_ref(
    root: Path, ref: str, handles: dict[str, Any]
) -> tuple[dict[str, Any] | None, str]:
    """Resolve one declared `contract_refs` entry to an exact digest source."""
    body = ref.split(":", 1)[1] if ref.startswith("ELIOT_") else ref
    if HANDLE_BODY_RE.match(body):
        record = handles.get(body)
        if not isinstance(record, dict):
            return None, "handle_absent"
        fragment = _text(record.get("path"))
        if not fragment or not (root / fragment).is_file():
            return None, "fragment_absent"
        actual = sha256_file(root / fragment)
        if actual != _text(record.get("fragment_sha256")):
            return None, "fragment_stale"
        return {
            "ref": ref,
            "resolved_as": "documentation_handle",
            "handle": body,
            "path": fragment,
            "anchor": _text(record.get("anchor")),
            "sha256": actual,
        }, ""
    if "." in ref and not ref.startswith("http"):
        candidate = normalize_repo_path(ref)
        if (root / candidate).is_file():
            return {
                "ref": ref,
                "resolved_as": "repository_file",
                "path": candidate,
                "sha256": sha256_file(root / candidate),
            }, ""
    return None, "unresolvable"


def _resolve_refs(
    root: Path, record: dict[str, Any], handles: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """Return (resolved, unresolved, failures) for one package's contract refs."""
    resolved: list[dict[str, Any]] = []
    unresolved: list[str] = []
    failures: list[str] = []
    for ref in _strings(record["metadata"].get("contract_refs")):
        found, failure = _resolve_contract_ref(root, ref, handles)
        if found is None:
            unresolved.append(ref)
            if failure:
                failures.append(f"{ref} is {failure}")
        else:
            resolved.append(found)
    resolved.sort(key=lambda item: item["ref"])
    return resolved, sorted(unresolved), sorted(failures)


# ---------------------------------------------------------------------------
# Package, cell, and source/test inventory
# ---------------------------------------------------------------------------


def _package_inventory(root: Path) -> dict[str, Any]:
    members, excludes, defaults, workspace_dependencies = _workspace_tables(root)
    member_set, default_set, exclude_set = set(members), set(defaults), set(excludes)

    packages: dict[str, dict[str, Any]] = {}
    for manifest_relative in discover_manifests(root):
        payload = read_toml(root / manifest_relative)
        package = payload.get("package")
        if not isinstance(package, dict):
            continue
        name = _text(package.get("name"))
        if not name:
            raise NavigationError(f"package has no name: {manifest_relative}")
        package_root = PurePosixPath(manifest_relative).parent.as_posix()
        module_relative = f"{package_root}/{MODULE_MANIFEST}"
        module_path = root / module_relative
        packages[package_root] = {
            "package": name,
            "manifest_path": manifest_relative,
            "root_path": package_root,
            "description": _text(package.get("description")),
            "metadata": package_metadata(payload),
            "module": read_toml(module_path) if module_path.is_file() else {},
            "module_path": module_relative if module_path.is_file() else None,
            "workspace_member": package_root in member_set,
            "default_member": package_root in default_set,
            "declared_exclude": package_root in exclude_set,
            "dependencies": [],
            "consumers": [],
            "rust_files": [],
            "targets": [],
        }

    for member in members:
        if member not in packages:
            raise NavigationError(
                f"workspace member has no [package] manifest: {member}/Cargo.toml"
            )

    names: dict[str, list[str]] = {}
    for package_root, record in packages.items():
        names.setdefault(record["package"], []).append(package_root)
    unique_names = {name: roots[0] for name, roots in names.items() if len(roots) == 1}

    for package_root in sorted(packages):
        record = packages[package_root]
        payload = read_toml(root / record["manifest_path"])
        for kind, alias, spec in iter_dependency_specs(payload):
            package_name, raw_path, path_base = resolve_dependency_spec(
                alias, spec, workspace_dependencies
            )
            local_root: str | None = None
            if raw_path is not None:
                resolved = resolve_dependency_path(
                    root, package_root, raw_path, path_base, f"dependency {alias!r}.path"
                )
                if resolved in packages:
                    local_root = resolved
            else:
                candidate = unique_names.get(package_name)
                if candidate is not None and packages[candidate]["workspace_member"]:
                    local_root = candidate
            record["dependencies"].append(
                {
                    "alias": alias,
                    "package": package_name,
                    "kind": kind,
                    "local_package_root": local_root,
                }
            )
        record["dependencies"].sort(
            key=lambda item: (item["kind"], item["package"], item["alias"])
        )

    consumers: dict[str, set[str]] = {}
    for record in packages.values():
        for dependency in record["dependencies"]:
            target = dependency["local_package_root"]
            if target:
                consumers.setdefault(target, set()).add(record["root_path"])
    for package_root, record in packages.items():
        record["consumers"] = sorted(consumers.get(package_root, set()))

    by_depth = sorted(packages, key=lambda value: (-len(PurePosixPath(value).parts), value))
    for relative in walk_files(root):
        if not relative.endswith(".rs"):
            continue
        owner = next(
            (
                package_root
                for package_root in by_depth
                if relative == package_root
                or relative.startswith(package_root.rstrip("/") + "/")
            ),
            None,
        )
        if owner is not None:
            packages[owner]["rust_files"].append(relative)
    for record in packages.values():
        record["rust_files"].sort()

    reachable = _bins_reachable(packages)
    for record in packages.values():
        record["bins_reachable"] = record["root_path"] in reachable

    return {
        "packages": packages,
        "members": sorted(member_set),
        "excludes": sorted(exclude_set),
        "defaults": sorted(default_set),
        "reachable": sorted(reachable),
        "workspace_manifest_sha256": sha256_file(root / "Cargo.toml"),
    }


def _bins_reachable(packages: dict[str, dict[str, Any]]) -> set[str]:
    """Bins-reachable closure over the local path-dependency graph."""
    edges: dict[str, set[str]] = {}
    for package_root, record in packages.items():
        edges[package_root] = {
            dependency["local_package_root"]
            for dependency in record["dependencies"]
            if dependency["local_package_root"]
        }
    roots = {root for root in packages if root.startswith("bins/")}
    seen = set(roots)
    stack = sorted(roots)
    while stack:
        current = stack.pop()
        for nxt in sorted(edges[current]):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def _declared_cells(record: dict[str, Any]) -> list[str]:
    """Cell ids declared by `functional_cell_refs`, `functional_cell`, `module_id`."""
    metadata = record["metadata"]
    module = record["module"]
    declared: list[str] = []
    raw_refs = metadata.get("functional_cell_refs")
    if isinstance(raw_refs, list):
        declared.extend(_text(item) for item in raw_refs)
    single = _text(metadata.get("functional_cell")) or _text(module.get("module_id"))
    if single:
        declared.append(single)
    cells: list[str] = []
    for cell in declared:
        if not cell:
            continue
        if not CELL_ID_RE.match(cell):
            raise NavigationError(
                "functional capability cell id is not path-safe: "
                f"{record['root_path']}: {cell!r}"
            )
        if cell not in cells:
            cells.append(cell)
    return sorted(cells)


def _cell_declaration_projection(
    root: Path,
    packages: dict[str, dict[str, Any]],
    artifacts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Project exact cell/state-owner declarations without claiming proof.

    This is a narrow readback input for consumers that need declared ownership
    while the executable CapabilityCellRegistry is incomplete. It deliberately
    preserves missing proof as a typed diagnostic; a Cargo package or test
    profile name never becomes an executable proof entrypoint by inference.
    """
    pair_path = "docs/normative-pair.toml"
    pair = _text(read_toml(root / pair_path).get("pair_key"))
    if not pair.startswith("sha256:") or len(pair) != 71:
        raise NavigationError(f"accepted normative pair key is unavailable: {pair_path}")

    cells: list[dict[str, Any]] = []
    diagnostics: list[dict[str, str]] = []
    for package_root, record in sorted(packages.items()):
        declared = _declared_cells(record)
        if not declared:
            continue
        metadata = record["metadata"]
        raw_owners = metadata.get("functional_cell_state_owners")
        owner_rows = raw_owners if isinstance(raw_owners, list) else []
        owners_by_cell: dict[str, list[dict[str, Any]]] = {}
        for row in owner_rows:
            if not isinstance(row, dict):
                continue
            cell = _text(row.get("cell"))
            if cell:
                owners_by_cell.setdefault(cell, []).append(row)
                if cell not in declared:
                    diagnostics.append(
                        {
                            "kind": "OWNER_FOR_UNDECLARED_CELL",
                            "cell": cell,
                            "source": record["manifest_path"],
                        }
                    )

        manifest_path = record["manifest_path"]
        manifest_digest = sha256_file(root / manifest_path)
        for cell in declared:
            state_owners: list[dict[str, str]] = []
            for row in owners_by_cell.get(cell, []):
                state = _text(row.get("state"))
                owner = _text(row.get("owner"))
                if not state or not owner:
                    diagnostics.append(
                        {"kind": "MALFORMED_STATE_OWNER", "cell": cell, "source": manifest_path}
                    )
                    continue
                state_owners.append({"state": state, "owner": owner})
            state_owners.sort(key=lambda item: (item["state"], item["owner"]))
            if not state_owners:
                diagnostics.append(
                    {"kind": "MISSING_STATE_OWNER", "cell": cell, "source": manifest_path}
                )
            if len({row["state"] for row in state_owners}) != len(state_owners):
                diagnostics.append(
                    {"kind": "DUPLICATE_STATE_OWNER", "cell": cell, "source": manifest_path}
                )

            capsule = artifacts.get(cell, {}).get("test_capsule", {})
            proof = capsule.get("independent_proof_entrypoint", {})
            entrypoint = proof.get("entrypoint", {}) if isinstance(proof, dict) else {}
            entrypoint_value = entrypoint.get("value") if isinstance(entrypoint, dict) else None
            proof_declared = (
                isinstance(entrypoint_value, str)
                and bool(entrypoint_value.strip())
                and proof.get("executable") is True
            )
            capsule_path = f"{CAPSULE_ROOT}/{cell}/test_capsule.json"
            capsule_digest = _text(capsule.get("artifact_digest"))
            if proof_declared:
                proof_identity: dict[str, Any] = {
                    "state": "DECLARED",
                    "entrypoint": entrypoint_value,
                    "source": "[package.metadata.eliot].proof_entrypoint",
                    "capsule_path": capsule_path,
                    "capsule_digest": capsule_digest,
                }
            else:
                proof_identity = {
                    "state": "MISSING_PROOF",
                    "entrypoint": None,
                    "source": "[package.metadata.eliot].proof_entrypoint",
                    "capsule_path": capsule_path,
                    "capsule_digest": capsule_digest,
                }
                diagnostics.append(
                    {"kind": "MISSING_PROOF", "cell": cell, "source": capsule_path}
                )

            cells.append(
                {
                    "cell_id": cell,
                    "source_package": record["package"],
                    "source_manifest": manifest_path,
                    "source_manifest_sha256": manifest_digest,
                    "state_owners": state_owners,
                    "proof_identity": proof_identity,
                }
            )

    cells.sort(key=lambda item: item["cell_id"])
    diagnostics.sort(key=lambda item: (item["cell"], item["kind"], item["source"]))
    projection: dict[str, Any] = {
        "schema_version": "eliot.capability-cell-declaration-projection.v1",
        "authority": "DECLARED_SOURCE_ONLY_NOT_EXECUTABLE_REGISTRY",
        "normative_pair_ref": pair_path,
        "normative_pair_key": pair,
        "cells": cells,
        "diagnostics": diagnostics,
    }
    projection["projection_digest"] = _sha256(_canonical(projection))
    return projection


def _source_selection(
    root: Path, record: dict[str, Any], consumer_names: list[str]
) -> dict[str, Any]:
    """Derive production source, focused tests, and the STU estimate."""
    acceptance = record["module"].get("acceptance")
    forbidden = _strings(acceptance.get("forbidden_patterns")) if isinstance(acceptance, dict) else []
    production: list[dict[str, Any]] = []
    tests: list[dict[str, Any]] = []
    digests: list[tuple[str, str]] = []
    production_bytes = test_bytes = test_attributes = inline_cfg_tests = 0
    forbidden_hits: list[dict[str, str]] = []
    for relative in record["rust_files"]:
        path = root / relative
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise NavigationError(f"cannot read source file {relative}: {exc}") from exc
        digests.append((relative, _sha256(data)))
        parts = PurePosixPath(relative).parts
        is_test = "tests" in parts
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            is_test, text = True, ""
        attributes = len(TEST_ATTRIBUTE_RE.findall(text))
        has_cfg_test = bool(CFG_TEST_RE.search(text))
        entry: dict[str, Any] = {
            "path": relative,
            "bytes": len(data),
            "sha256": digests[-1][1],
        }
        if is_test:
            test_bytes += len(data)
            entry["test_attributes"] = attributes
            entry["inline_cfg_test"] = has_cfg_test
            entry["classes"] = sorted(
                {
                    "fake_port_contract" if FAKE_PORT_RE.search(text) else "",
                    "fault_restart_replay" if FAULT_CASE_RE.search(text) else "",
                    "parser_or_golden_corpus"
                    if any(part in CORPUS_DIRS for part in parts)
                    else "",
                    "edge_profile" if any(name in text for name in consumer_names) else "",
                }
                - {""}
            )
            tests.append(entry)
        else:
            production_bytes += len(data)
            entry["stu"] = -(-len(data) // 3)
            entry["inline_cfg_test"] = has_cfg_test
            production.append(entry)
            if has_cfg_test:
                inline_cfg_tests += 1
        test_attributes += attributes
        for pattern in forbidden:
            if pattern in text:
                forbidden_hits.append({"pattern": pattern, "path": relative})
    production.sort(key=lambda item: item["path"])
    tests.sort(key=lambda item: item["path"])
    forbidden_hits.sort(key=lambda item: (item["pattern"], item["path"]))
    digests.sort()
    return {
        "selected_source": production,
        "selected_tests": tests,
        "source_stu": -(-production_bytes // 3),
        "test_stu": -(-test_bytes // 3),
        "test_attribute_count": test_attributes,
        "inline_cfg_test_modules": inline_cfg_tests,
        "source_selection_digest": _sha256(_canonical(digests)),
        "selected_file_count": len(digests),
        "forbidden_pattern_hits": forbidden_hits,
    }


def _input_digests(
    root: Path,
    record: dict[str, Any],
    inventory: dict[str, Any],
    selection: dict[str, Any],
    excluded: dict[str, Any] | None,
) -> dict[str, Any]:
    digests: dict[str, Any] = {
        "workspace_manifest": {
            "path": "Cargo.toml",
            "sha256": inventory["workspace_manifest_sha256"],
        },
        "contract_catalogue": {
            "path": DEFAULT_HANDLE_INDEX,
            "sha256": sha256_file(root / DEFAULT_HANDLE_INDEX),
        },
        "architecture_boundaries": {
            "path": BOUNDARIES_PATH,
            "sha256": (
                sha256_file(root / BOUNDARIES_PATH)
                if (root / BOUNDARIES_PATH).is_file()
                else None
            ),
        },
        "logical_block_config": {
            "path": DEFAULT_BLOCKS,
            "sha256": sha256_file(root / DEFAULT_BLOCKS),
        },
        "package_manifest": {
            "path": record["manifest_path"],
            "sha256": sha256_file(root / record["manifest_path"]),
        },
        "module_manifest": (
            {
                "path": record["module_path"],
                "sha256": sha256_file(root / str(record["module_path"])),
            }
            if record["module_path"]
            else None
        ),
        "selected_source": {
            "path_count": selection["selected_file_count"],
            "sha256": selection["source_selection_digest"],
        },
    }
    if excluded is not None:
        digests["excluded_disposition"] = {
            "path": excluded["source"],
            "sha256": sha256_file(root / excluded["source"]),
        }
    return digests


def _logic_block_refs(
    package_root: str, manifest_path: str, blocks: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Governing logical responsibility blocks and documentation handles."""
    refs = [
        {
            "block": block["id"],
            "title": block["title"],
            "responsibility": block["responsibility"],
            "documentation_handles": sorted(block["documentation_handles"]),
        }
        for block in blocks
        if any(
            path_matches(package_root, pattern)
            or path_matches(manifest_path, pattern)
            for pattern in block["path_globs"]
        )
    ]
    return sorted(refs, key=lambda item: item["block"])


def _debt_for(boundaries: dict[str, Any], root_path: str) -> list[dict[str, Any]]:
    return sorted(
        (row for row in boundaries["tracked_debt"] if row["path"].startswith(root_path)),
        key=lambda item: (item["kind"], item["path"]),
    )


# ---------------------------------------------------------------------------
# The three generated artifacts
# ---------------------------------------------------------------------------


def _contract_kit(
    root: Path,
    cell: str,
    record: dict[str, Any],
    handles: dict[str, Any],
    boundaries: dict[str, Any],
    blocks: list[dict[str, Any]],
    excluded: dict[str, Any] | None,
    input_digests: dict[str, Any],
) -> dict[str, Any]:
    metadata = record["metadata"]
    module = record["module"]
    resolved, unresolved, failures = _resolve_refs(root, record, handles)
    acceptance = module.get("acceptance") if isinstance(module.get("acceptance"), dict) else {}
    purpose = (
        _text(module.get("primary_responsibility"))
        or _text(metadata.get("purpose"))
        or record["description"]
    )
    body: dict[str, Any] = {
        "schema_version": SCHEMA,
        "artifact_kind": "ModuleContractKit",
        "generator": GENERATOR,
        "generator_version": GENERATOR_VERSION,
        "governing_handle": CONTRACT_HANDLE,
        "governing_fragment": CONTRACT_FRAGMENT,
        "cell_id": cell,
        "crate_or_cell_identity": {
            "functional_capability_cell": cell,
            "source_package": record["package"],
            "source_manifest": record["manifest_path"],
            "source_root_path": record["root_path"],
            "module_manifest": record["module_path"],
            "workspace_member": record["workspace_member"],
            "bins_reachable": record["bins_reachable"],
            "excluded_scope": excluded,
        },
        "purpose_and_invariants": {
            "purpose": _declared(purpose, "module.toml|primary_responsibility or [package].description"),
            "causal_property": _declared(module.get("causal_property"), "module.toml|causal_property"),
            "invariants": _declared(module.get("invariants"), "module.toml|invariants"),
            "non_goals": _declared(module.get("non_goals"), "module.toml|non_goals"),
        },
        "public_types_and_schemas": {
            "public_targets": record["targets"],
            "declared_contract_refs": _strings(metadata.get("contract_refs")),
            "contract_catalogue": DEFAULT_HANDLE_INDEX,
            "governing_logic_blocks": _logic_block_refs(
                record["root_path"], record["manifest_path"], blocks
            ),
        },
        "owned_state_and_effects": {
            "lifecycle_owner": _declared(
                module.get("lifecycle_owner") or metadata.get("lifecycle_owner"),
                "module.toml|lifecycle_owner",
            ),
            "source_maintenance_owner": _declared(
                metadata.get("source_maintenance_owner"),
                "[package.metadata.eliot].source_maintenance_owner",
            ),
            "state_class": _declared(
                module.get("state_class") or module.get("delivery_depth"),
                "module.toml|state_class",
            ),
            "owned_mutable_state": _declared(
                module.get("owned_mutable_state"), "module.toml|owned_mutable_state"
            ),
            "allowed_effects": _declared(module.get("allowed_effects"), "module.toml|allowed_effects"),
            "allowed_effect_classes": _declared(
                metadata.get("allowed_effect_classes"),
                "[package.metadata.eliot].allowed_effect_classes",
            ),
            "failure_behavior": _declared(
                module.get("failure_behavior"), "module.toml|failure_behavior"
            ),
            "execution_contour": _declared(
                metadata.get("execution_contour"), "[package.metadata.eliot].execution_contour"
            ),
            "runtime_class": _declared(
                metadata.get("runtime_class"), "[package.metadata.eliot].runtime_class"
            ),
        },
        "dependency_ports": {
            "inputs": _declared(module.get("inputs"), "module.toml|inputs"),
            "outputs": _declared(module.get("outputs"), "module.toml|outputs"),
            "providers": _declared(module.get("providers"), "module.toml|providers"),
            "depends_on": _declared(module.get("depends_on"), "module.toml|depends_on"),
            "runtime_owner_and_bundle": {
                "runtime_layer": _declared(
                    module.get("runtime_layer") or metadata.get("runtime_layer"),
                    "module.toml|runtime_layer",
                ),
                "runtime_bundle": _declared(
                    module.get("runtime_bundle") or metadata.get("runtime_bundle"),
                    "module.toml|runtime_bundle",
                ),
                "runtime_root_rules": [
                    row for row in boundaries["runtime_roots"] if row["package"] == record["package"]
                ],
                "boundary_source": BOUNDARIES_PATH,
            },
        },
        "compatibility_rules": {
            "replacement_boundary": _declared(
                module.get("replacement_boundary"), "module.toml|replacement_boundary"
            ),
            "replacement_class": _declared(
                metadata.get("replacement_class"), "[package.metadata.eliot].replacement_class"
            ),
            "merge_rejoin_condition": _declared(
                module.get("merge_rejoin_condition"), "module.toml|merge_rejoin_condition"
            ),
            "split_trigger": _declared(
                module.get("split_trigger"), "module.toml|split_trigger"
            ),
            "iteration_lane": _declared(
                metadata.get("iteration_lane"), "[package.metadata.eliot].iteration_lane"
            ),
            "proof_latency_profile": _declared(
                metadata.get("independent_proof_profile"),
                "[package.metadata.eliot].independent_proof_profile",
            ),
        },
        "negative_cases": {
            "discriminator": _declared(module.get("discriminator"), "module.toml|discriminator"),
            "old_failure_or_missing_capability": _declared(
                module.get("old_failure_or_missing_capability"),
                "module.toml|old_failure_or_missing_capability",
            ),
            "forbidden_patterns": _declared(
                acceptance.get("forbidden_patterns"),
                "module.toml|acceptance.forbidden_patterns",
            ),
        },
        "known_unknowns": {
            "declared_known_unknowns": _declared(
                module.get("known_unknowns"), "module.toml|known_unknowns"
            ),
            "unresolved_contract_refs": unresolved,
            "contract_ref_failures": failures,
            "observation": (
                "A generated capsule is generation evidence from the named metadata, "
                "not executed product evidence (I0.5, I2.20)."
            ),
        },
        "oracle_origins": {
            "resolved_contract_refs": resolved,
            "contract_refs_source": record["manifest_path"],
            "donor_records": sorted(
                (
                    {
                        "path": _text(donor.get("path")),
                        "disposition": _text(donor.get("disposition")),
                    }
                    for donor in (module.get("donor") if isinstance(module.get("donor"), list) else [])
                    if isinstance(donor, dict)
                ),
                key=lambda item: (item["path"], item["disposition"]),
            ),
        },
        "source_provenance": {
            "input_digests": input_digests,
            "generator": GENERATOR,
            "generator_version": GENERATOR_VERSION,
        },
    }
    body["artifact_digest"] = digest_of("ModuleContractKit", body)
    body["contract_revision"] = {
        "derivation": "first 16 hex characters of the artifact digest",
        "value": body["artifact_digest"][:16],
    }
    return body


def _context_capsule(
    root: Path,
    cell: str,
    record: dict[str, Any],
    boundaries: dict[str, Any],
    blocks: list[dict[str, Any]],
    selection: dict[str, Any],
    input_digests: dict[str, Any],
    handles: dict[str, Any],
    contract_digest: str,
) -> dict[str, Any]:
    metadata = record["metadata"]
    module = record["module"]
    _, unresolved, _ = _resolve_refs(root, record, handles)
    one_hop_providers = sorted(
        {
            dependency["package"]
            for dependency in record["dependencies"]
            if dependency["kind"] in {"dependencies", "build-dependencies"}
        }
    )
    body: dict[str, Any] = {
        "schema_version": SCHEMA,
        "artifact_kind": "CrateContextCapsule",
        "generator": GENERATOR,
        "generator_version": GENERATOR_VERSION,
        "governing_handle": CONTRACT_HANDLE,
        "governing_fragment": CONTRACT_FRAGMENT,
        "cell_id": cell,
        "product_objective": _declared(
            module.get("product_objective") or metadata.get("purpose"),
            "module.toml|product_objective",
        ),
        "functional_capability_cell_refs": _declared_cells(record),
        "effective_micro_module_manifest_ref": f"{INDEX_PATH}#/cells/{cell}",
        "primary_source_package": {
            "package": record["package"],
            "root_path": record["root_path"],
            "manifest_path": record["manifest_path"],
            "module_manifest": record["module_path"],
            "description": record["description"],
        },
        "source_token_estimate": {
            "method": STU_METHOD,
            "source_stu": selection["source_stu"],
            "test_stu": selection["test_stu"],
            "selected_file_count": selection["selected_file_count"],
            "inline_cfg_test_modules": selection["inline_cfg_test_modules"],
            "qualification": "planning estimate only; not a qualified Context Envelope (I2.16)",
        },
        "selected_source_and_tests": {
            "selected_source": selection["selected_source"],
            "selected_tests": selection["selected_tests"],
            "source_selection_digest": selection["source_selection_digest"],
        },
        "one_hop_providers": one_hop_providers,
        "one_hop_consumers": list(record["consumers"]),
        "architecture_implementation_refs": _logic_block_refs(
            record["root_path"], record["manifest_path"], blocks
        ),
        "failure_fingerprints": _debt_for(boundaries, record["root_path"]),
        "edge_tests": sorted(
            entry["path"]
            for entry in selection["selected_tests"]
            if "edge_profile" in entry["classes"]
        ),
        "product_pulse": _declared(module.get("product_pulse"), "module.toml|product_pulse"),
        "omitted_material_and_handles": {
            "unresolved_contract_refs": unresolved,
            "omitted": (
                "Files outside the package source/test selection, exact route "
                "tokenizer measurement, executed edge and Product Pulse results, and "
                "every runtime, store, and live-state observation."
            ),
        },
        "effective_context_profile": {
            "estimate": "planning_estimate_only",
            "qualification": "UNVALIDATED (I2.16, I0.5)",
            "reference_capsule_handle": CONTRACT_HANDLE,
        },
        "bound_contract_digest": contract_digest,
        "source_provenance": {
            "input_digests": input_digests,
            "generator": GENERATOR,
            "generator_version": GENERATOR_VERSION,
        },
    }
    body["artifact_digest"] = digest_of("CrateContextCapsule", body)
    body["contract_revision"] = {
        "derivation": "first 16 hex characters of the artifact digest",
        "value": body["artifact_digest"][:16],
    }
    return body


def _test_capsule(
    cell: str,
    record: dict[str, Any],
    selection: dict[str, Any],
    boundaries: dict[str, Any],
    input_digests: dict[str, Any],
    contract_digest: str,
) -> dict[str, Any]:
    metadata = record["metadata"]
    module = record["module"]
    acceptance = module.get("acceptance") if isinstance(module.get("acceptance"), dict) else {}
    declared_entrypoint = _text(metadata.get("proof_entrypoint"))
    executable = bool(declared_entrypoint) and record["workspace_member"]
    tests_by_class: dict[str, list[str]] = {}
    for entry in selection["selected_tests"]:
        for name in entry["classes"]:
            tests_by_class.setdefault(name, []).append(entry["path"])
    body: dict[str, Any] = {
        "schema_version": SCHEMA,
        "artifact_kind": "ModuleTestCapsule",
        "generator": GENERATOR,
        "generator_version": GENERATOR_VERSION,
        "governing_handle": CONTRACT_HANDLE,
        "governing_fragment": CONTRACT_FRAGMENT,
        "cell_id": cell,
        "independent_proof_entrypoint": {
            "entrypoint": _declared(
                declared_entrypoint or None, "[package.metadata.eliot].proof_entrypoint"
            ),
            "package": record["package"],
            "executable": executable,
            "state": (
                "EXECUTABLE"
                if executable
                else (
                    "UNDECLARED"
                    if not declared_entrypoint
                    else "NOT_EXECUTABLE"
                )
            ),
            "runnable": (
                "the declared command is independently invocable for this package"
                if executable
                else "no executable proof entrypoint is declared for this cell"
            ),
        },
        "proof_level_ceiling": _declared(module.get("proof_ceiling"), "module.toml|proof_ceiling"),
        "shape_checks": {
            "deny_unknown_fields": _declared(
                acceptance.get("deny_unknown_fields"), "module.toml|acceptance.deny_unknown_fields"
            ),
            "forbid_unsafe": _declared(
                acceptance.get("forbid_unsafe"), "module.toml|acceptance.forbid_unsafe"
            ),
            "forbidden_patterns": _declared(
                acceptance.get("forbidden_patterns"), "module.toml|acceptance.forbidden_patterns"
            ),
            "forbidden_pattern_hits": selection["forbidden_pattern_hits"],
            "inline_cfg_test_modules": selection["inline_cfg_test_modules"],
        },
        "unit_property_model_tests": {
            "declared_proof_surface": _declared(module.get("proof_surface"), "module.toml|proof_surface"),
            "selected_tests": selection["selected_tests"],
            "test_attribute_count": selection["test_attribute_count"],
        },
        "parser_or_golden_corpus": sorted(tests_by_class.get("parser_or_golden_corpus", [])),
        "fake_port_contract_tests": sorted(tests_by_class.get("fake_port_contract", [])),
        "real_edge_profiles": {
            "one_hop_consumers": list(record["consumers"]),
            "declared_consumers": _declared(module.get("consumers"), "module.toml|consumers"),
            "edge_profile_tests": sorted(tests_by_class.get("edge_profile", [])),
        },
        "fault_restart_replay_cases": {
            "declared_failure_behavior": _declared(
                module.get("failure_behavior"), "module.toml|failure_behavior"
            ),
            "selected_cases": sorted(tests_by_class.get("fault_restart_replay", [])),
        },
        "resource_and_serial_groups": {
            "declared_serial_groups": _declared(
                None, "no resource or serial group registry is declared in the repository metadata"
            ),
            "boundary_tracked_test_debt": [
                {"path": row["path"], "issue": row["issue"], "reason": row["reason"]}
                for row in _debt_for(boundaries, record["root_path"])
                if row["class"] == "test"
            ],
        },
        "known_uncovered_behavior": {
            "declared_required_tests": _declared(
                acceptance.get("required_tests"), "module.toml|acceptance.required_tests"
            ),
            "declared_required_exports": _declared(
                acceptance.get("required_exports"), "module.toml|acceptance.required_exports"
            ),
            "observation": (
                "A zero counted test is not a pass; counted attributes are source "
                "metadata, not executed evidence (A14.8, I0.5)."
            ),
        },
        "expected_nonzero_test_count": {
            "method": "count of #[test]/#[tokio::test] attributes in the selected test slice",
            "test_attribute_count": selection["test_attribute_count"],
            "test_stu": selection["test_stu"],
            "nonzero": selection["test_attribute_count"] > 0,
        },
        "bound_contract_digest": contract_digest,
        "source_provenance": {
            "input_digests": input_digests,
            "generator": GENERATOR,
            "generator_version": GENERATOR_VERSION,
        },
    }
    body["artifact_digest"] = digest_of("ModuleTestCapsule", body)
    body["contract_revision"] = {
        "derivation": "first 16 hex characters of the artifact digest",
        "value": body["artifact_digest"][:16],
    }
    return body


# ---------------------------------------------------------------------------
# Registry, support classification, emission, and fail-closed validation
# ---------------------------------------------------------------------------


def _artifacts_block(
    cell: str, kit: dict[str, Any], context: dict[str, Any], capsule: dict[str, Any]
) -> dict[str, Any]:
    return {
        key: {
            "kind": kind,
            "path": f"{CAPSULE_ROOT}/{cell}/{key}.json",
            "artifact_digest": artifact["artifact_digest"],
            "contract_revision": artifact["contract_revision"]["value"],
        }
        for (key, kind), artifact in zip(
            ARTIFACT_KINDS, (kit, context, capsule), strict=True
        )
    }


def _undeclared_capability(
    record: dict[str, Any], reachability: str, excluded: dict[str, Any] | None
) -> dict[str, Any]:
    """A workspace package that declares no capability cell is still represented.

    The issue forbids silent omission: a package whose cell id is undeclared is
    carried with an explicit `UNDECLARED` cell identity, no triad artifacts,
    and `TARGET` support, rather than disappearing from the denominator.
    """
    support = classify_capsule_set(None, None, None, _adoption(record))
    return {
        "cell_id": None,
        "cell_id_state": "UNDECLARED",
        "cell_id_origin": (
            "[package.metadata.eliot].functional_cell_refs, "
            "[package.metadata.eliot].functional_cell, or module.toml|module_id"
        ),
        "crate": record["package"],
        "source_manifest": record["manifest_path"],
        "reachability": reachability,
        "workspace_admission": _adoption(record),
        "excluded_scope": excluded,
        "declared_in_module_manifest": bool(record["module_path"]),
        "implementation_support": "TARGET",
        "implementation_support_detail": support,
        "artifacts": None,
    }


def _adoption(record: dict[str, Any], force_nonmember: bool = False) -> dict[str, Any]:
    """Admission and development-tool status carried verbatim, never inferred."""
    metadata = record["metadata"]
    return {
        "workspace_member": False if force_nonmember else record["workspace_member"],
        "default_member": False if force_nonmember else record["default_member"],
        "declared_exclude": record["declared_exclude"],
        "module_status": _text(record["module"].get("status")) or None,
        "prototype": metadata.get("prototype"),
        "source_status": _text(metadata.get("source_status")) or None,
        "workspace_admission": _text(metadata.get("workspace_admission")) or None,
        "declared_implementation_support": _text(metadata.get("implementation_support")) or None,
        "declared_evidence_execution_status": (
            _text(metadata.get("evidence_execution_status")) or None
        ),
    }


def _build_cell(
    root: Path,
    cell: str,
    record: dict[str, Any],
    selection: dict[str, Any],
    handles: dict[str, Any],
    boundaries: dict[str, Any],
    blocks: list[dict[str, Any]],
    inventory: dict[str, Any],
    excluded: dict[str, Any] | None,
    reachability: str,
    force_nonmember: bool,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    input_digests = _input_digests(root, record, inventory, selection, excluded)
    kit = _contract_kit(
        root, cell, record, handles, boundaries, blocks, excluded, input_digests
    )
    context = _context_capsule(
        root,
        cell,
        record,
        boundaries,
        blocks,
        selection,
        input_digests,
        handles,
        kit["artifact_digest"],
    )
    capsule = _test_capsule(
        cell, record, selection, boundaries, input_digests, kit["artifact_digest"]
    )
    adoption = _adoption(record, force_nonmember)
    support = classify_capsule_set(kit, context, capsule, adoption)
    entry = {
        "cell_id": cell,
        "functional_capability_cell": cell,
        "crate": record["package"],
        "source_manifest": record["manifest_path"],
        "module_manifest": record["module_path"],
        "reachability": reachability,
        "workspace_admission": adoption,
        "excluded_scope": excluded,
        "declared_in_module_manifest": bool(record["module_path"]),
        "artifacts": _artifacts_block(cell, kit, context, capsule),
        "implementation_support": support,
    }
    return kit, context, capsule, entry


def build_capsules(root: Path) -> dict[str, Any]:
    """Build the deterministic projection and every artifact value, in memory."""
    root = root.resolve()
    if not (root / "Cargo.toml").is_file():
        raise NavigationError(f"not a repository root: {root}")
    inventory = _package_inventory(root)
    handles = _contract_catalogue(root)
    blocks = load_blocks(root)
    boundaries = _boundaries(root)
    dispositions = _dispositions(root)
    packages = inventory["packages"]
    member_set = set(inventory["members"])
    standalone = _standalone_packages(
        root, member_set | set(inventory["excludes"])
    )
    standalone_set = set(standalone)

    consumer_names = {
        root_path: sorted(
            {packages[consumer]["package"] for consumer in record["consumers"]}
        )
        for root_path, record in packages.items()
    }

    cells: list[dict[str, Any]] = []
    artifacts: dict[str, dict[str, Any]] = {}
    claimed: dict[str, str] = {}
    registry_defects: list[str] = []
    member_paths = sorted(packages)
    undeclared_cells: list[dict[str, Any]] = []

    for root_path in member_paths:
        record = packages[root_path]
        if root_path in standalone_set:
            # Carried by the excluded-scope pass below, never twice.
            continue
        selection = _source_selection(root, record, consumer_names[root_path])
        excluded = dispositions.get(root_path)
        if record["bins_reachable"]:
            reachability = "REACHABLE"
        elif excluded or record["declared_exclude"]:
            reachability = "EXCLUDED"
        else:
            reachability = "UNREACHABLE"
        for cell in _declared_cells(record):
            if cell in claimed:
                registry_defects.append(f"{cell}: claimed by {claimed[cell]} and {root_path}")
                continue
            claimed[cell] = root_path
            kit, context, capsule, entry = _build_cell(
                root, cell, record, selection, handles, boundaries, blocks,
                inventory, excluded, reachability, False,
            )
            artifacts[cell] = {
                "contract_kit": kit,
                "context_capsule": context,
                "test_capsule": capsule,
            }
            cells.append(entry)
        if not _declared_cells(record):
            undeclared_cells.append(_undeclared_capability(record, reachability, excluded))

    for root_path in standalone:
        record = packages[root_path]
        selection = _source_selection(root, record, consumer_names.get(root_path, []))
        excluded = dispositions.get(root_path)
        if excluded is None:
            registry_defects.append(
                f"{root_path}: excluded package has no {DISPOSITIONS_PATH} disposition row"
            )
            excluded = {
                "disposition": "UNKNOWN",
                "owner": "",
                "workspace_admission": "undeclared; fail-closed until dispositioned",
                "source": DISPOSITIONS_PATH,
            }
        declared = _declared_cells(record)
        if not declared:
            undeclared_cells.append(
                _undeclared_capability(record, "EXCLUDED", excluded)
            )
        for cell in declared:
            if cell in claimed:
                registry_defects.append(f"{cell}: claimed by {claimed[cell]} and {root_path}")
                continue
            claimed[cell] = root_path
            kit, context, capsule, entry = _build_cell(
                root, cell, record, selection, handles, boundaries, blocks,
                inventory, excluded, "EXCLUDED", True,
            )
            artifacts[cell] = {
                "contract_kit": kit,
                "context_capsule": context,
                "test_capsule": capsule,
            }
            cells.append(entry)

    cells.sort(key=lambda item: item["cell_id"])
    undeclared_cells.sort(key=lambda item: item["source_manifest"])
    registry_defects.sort()

    capabilities = [
        {
            "cell_id": cell["cell_id"],
            "crate": cell["crate"],
            "reachability": cell["reachability"],
            "workspace_admission": cell["workspace_admission"],
            "excluded_scope": cell["excluded_scope"],
            "declared_in_module_manifest": cell["declared_in_module_manifest"],
            "implementation_support": cell["implementation_support"]["implementation_support"],
            "artifacts": cell["artifacts"],
        }
        for cell in cells
    ] + undeclared_cells
    capabilities.sort(key=lambda item: (item["reachability"], item["cell_id"] or ""))

    support_tally: dict[str, int] = {}
    reachability_tally: dict[str, int] = {}
    for capability in capabilities:
        reachability_tally[capability["reachability"]] = (
            reachability_tally.get(capability["reachability"], 0) + 1
        )
        support_tally[capability["implementation_support"]] = (
            support_tally.get(capability["implementation_support"], 0) + 1
        )

    registry: dict[str, Any] = {
        "schema_version": SCHEMA,
        "generator": GENERATOR,
        "generator_version": GENERATOR_VERSION,
        "governing_handle": CONTRACT_HANDLE,
        "governing_fragment": CONTRACT_FRAGMENT,
        "capability_coverage": {
            "workspace_members": len(inventory["members"]),
            "workspace_exclude": list(inventory["excludes"]),
            "reachable_packages": len(inventory["reachable"]),
            "unreachable_member_packages": sum(
                1
                for root_path in member_paths
                if not packages[root_path]["bins_reachable"]
                and root_path not in standalone_set
            ),
            "excluded_standalone_packages": len(standalone),
            "excluded_standalone_paths": standalone,
            "declared_capability_cells": len(cells),
            "packages_with_declared_cells": len({cell["source_manifest"] for cell in cells}),
            "packages_with_undeclared_cell_id": len(undeclared_cells),
            "packages_with_undeclared_cell_id_paths": [
                item["source_manifest"] for item in undeclared_cells
            ],
            "reachability_tally": dict(sorted(reachability_tally.items())),
            "support_tally": dict(sorted(support_tally.items())),
            "coverage_note": (
                "Reachable, unreachable, and currently excluded workspace "
                "capabilities are all represented. An excluded capability may "
                "remain non-runtime; its #1811 development-tool and admission "
                "status is carried rather than silently omitted."
            ),
        },
        "support_ceiling_with_complete_triad": SUPPORT_CEILING_WITH_TRIAD,
        "triad_rule": (
            "A capability missing any element of the ModuleContractKit + "
            "CrateContextCapsule + ModuleTestCapsule triad cannot have "
            "ImplementationSupport above CURRENT_UNVERIFIED, regardless of code "
            "quality or test count (I2.20, ARCH-MOD-03)."
        ),
        "input_digests": {
            "workspace_manifest": {
                "path": "Cargo.toml",
                "sha256": inventory["workspace_manifest_sha256"],
            },
            "contract_catalogue": {
                "path": DEFAULT_HANDLE_INDEX,
                "sha256": sha256_file(root / DEFAULT_HANDLE_INDEX),
            },
            "architecture_boundaries": (
                {
                    "path": BOUNDARIES_PATH,
                    "sha256": sha256_file(root / BOUNDARIES_PATH),
                }
                if (root / BOUNDARIES_PATH).is_file()
                else None
            ),
            "logical_block_config": {
                "path": DEFAULT_BLOCKS,
                "sha256": sha256_file(root / DEFAULT_BLOCKS),
            },
            "excluded_dispositions": (
                {
                    "path": DISPOSITIONS_PATH,
                    "sha256": sha256_file(root / DISPOSITIONS_PATH),
                }
                if (root / DISPOSITIONS_PATH).is_file()
                else None
            ),
        },
        "registry_defects": registry_defects,
        "capabilities": capabilities,
        "cells": cells,
        "cell_declaration_projection": _cell_declaration_projection(
            root, packages, artifacts
        ),
    }
    registry["registry_digest"] = _sha256(_canonical(registry))
    return {"registry": registry, "artifacts": artifacts}


def classify_capsule_set(
    contract_kit: dict[str, Any] | None,
    context_capsule: dict[str, Any] | None,
    test_capsule: dict[str, Any] | None,
    declared_support: str | dict[str, Any] = "",
) -> dict[str, Any]:
    """Classify one cell's triad and bound its `ImplementationSupport` (I0.5).

    The triad is mandatory, not advisory: an absent, stale, or non-executable
    member caps the cell at `CURRENT_UNVERIFIED`. This generator produces
    generation evidence only, never executed evidence, so even a complete triad
    reports at most `CURRENT_UNVERIFIED` and never promotes a cell.
    """
    if isinstance(declared_support, dict):
        observed = _text(declared_support.get("declared_implementation_support"))
    else:
        observed = _text(declared_support)

    cell = ""
    for artifact in (contract_kit, context_capsule, test_capsule):
        if isinstance(artifact, dict):
            cell = _text(artifact.get("cell_id"))
            break

    supplied = {
        "contract_kit": contract_kit,
        "context_capsule": context_capsule,
        "test_capsule": test_capsule,
    }
    defects: list[dict[str, str]] = []
    present = {key: False for key, _ in ARTIFACT_KINDS}
    for key, kind in ARTIFACT_KINDS:
        artifact = supplied[key]
        if not isinstance(artifact, dict) or artifact.get("artifact_kind") != kind:
            defects.append({"code": "ARTIFACT_ABSENT", "artifact": key})
            continue
        present[key] = True
        if digest_of(kind, artifact) != _text(artifact.get("artifact_digest")):
            defects.append({"code": "ARTIFACT_STALE", "artifact": key})

    if isinstance(test_capsule, dict):
        entrypoint = test_capsule.get("independent_proof_entrypoint", {})
        state = _text(entrypoint.get("state"))
        if state == "UNDECLARED":
            defects.append(
                {"code": "PROOF_ENTRYPOINT_UNDECLARED", "artifact": "test_capsule"}
            )
        elif state != "EXECUTABLE":
            defects.append(
                {"code": "PROOF_ENTRYPOINT_NOT_EXECUTABLE", "artifact": "test_capsule"}
            )
        elif not test_capsule.get("expected_nonzero_test_count", {}).get("nonzero"):
            defects.append(
                {"code": "PROOF_ENTRYPOINT_ZERO_TESTS", "artifact": "test_capsule"}
            )
    if isinstance(contract_kit, dict) and not contract_kit.get(
        "oracle_origins", {}
    ).get("resolved_contract_refs"):
        defects.append(
            {"code": "CONTRACT_PROVENANCE_UNDECLARED", "artifact": "contract_kit"}
        )

    defects.sort(key=lambda item: (item["code"], item["artifact"]))
    complete = all(present.values()) and not defects
    support = _weakest(observed, SUPPORT_CEILING_WITH_TRIAD)
    return {
        "cell_id": cell,
        "triad_complete": complete,
        "present": present,
        "blocking_defects": defects,
        "blocking_codes": sorted({defect["code"] for defect in defects}),
        "implementation_support": support,
        "support_ceiling": SUPPORT_CEILING_WITH_TRIAD,
        "declared_support": observed or None,
        "evidence_execution_status": "NOT_EXECUTED",
        "note": (
            "Generated presence and digests are generation evidence only; they "
            "never set EXECUTED evidence and never promote support above "
            "CURRENT_UNVERIFIED (I0.5, I2.20)."
        ),
    }


# ---------------------------------------------------------------------------
# Emission and fail-closed validation
# ---------------------------------------------------------------------------


def _read_artifact(root: Path, cell: str, key: str) -> dict[str, Any] | None:
    path = root / CAPSULE_ROOT / cell / f"{key}.json"
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NavigationError(f"emitted capsule is unreadable: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise NavigationError(f"emitted capsule is not an object: {path}")
    return value


def emit_capsules(root: Path) -> dict[str, Any]:
    """Write the deterministic projection and every triad artifact."""
    root = root.resolve()
    built = build_capsules(root)
    registry = built["registry"]
    written = 0
    for cell_id, artifacts in sorted(built["artifacts"].items()):
        target = root / CAPSULE_ROOT / cell_id
        target.mkdir(parents=True, exist_ok=True)
        for key, _ in ARTIFACT_KINDS:
            path = target / f"{key}.json"
            payload = render(artifacts[key])
            if not path.is_file() or path.read_text(encoding="utf-8") != payload:
                path.write_text(payload, encoding="utf-8", newline="")
                written += 1
    index = root / INDEX_PATH
    index.parent.mkdir(parents=True, exist_ok=True)
    payload = render(registry)
    if not index.is_file() or index.read_text(encoding="utf-8") != payload:
        index.write_text(payload, encoding="utf-8", newline="")
        written += 1
    return {
        "index": INDEX_PATH,
        "cells": len(registry["cells"]),
        "artifacts": len(registry["cells"]) * len(ARTIFACT_KINDS),
        "files_written": written,
        "registry_digest": registry["registry_digest"],
        "registry_defects": registry["registry_defects"],
    }


def check_capsules(root: Path) -> list[str]:
    """Fail-closed absence/staleness validation of the emitted triad."""
    root = root.resolve()
    try:
        built = build_capsules(root)
    except NavigationError as exc:
        return [str(exc)]
    registry = built["registry"]
    failures: list[str] = []
    if registry["schema_version"] != SCHEMA:
        failures.append(f"schema mismatch: {registry['schema_version']!r}")
    failures.extend(registry["registry_defects"])
    for cell in registry["cells"]:
        on_disk: dict[str, Any] = {}
        for key, kind in ARTIFACT_KINDS:
            declared = cell["artifacts"][key]
            artifact = _read_artifact(root, cell["cell_id"], key)
            if artifact is None:
                failures.append(
                    f"{cell['cell_id']}: {kind} is absent ({declared['path']}); "
                    f"support cannot exceed {SUPPORT_CEILING_WITH_TRIAD}"
                )
                continue
            if artifact.get("artifact_kind") != kind:
                failures.append(f"{cell['cell_id']}: {kind} has the wrong artifact_kind")
                continue
            if _text(artifact.get("cell_id")) != cell["cell_id"]:
                failures.append(f"{cell['cell_id']}: {kind} identity is not bound to the cell")
            recomputed = digest_of(kind, artifact)
            if recomputed != _text(artifact.get("artifact_digest")):
                failures.append(f"{cell['cell_id']}: {kind} carries a stale self-digest")
            elif recomputed != declared["artifact_digest"]:
                failures.append(
                    f"{cell['cell_id']}: {kind} is stale against the current tree; "
                    f"regenerate with `python scripts/code_navigation.py capsules --emit`"
                )
            on_disk[key] = artifact
        support = classify_capsule_set(
            on_disk.get("contract_kit"),
            on_disk.get("context_capsule"),
            on_disk.get("test_capsule"),
            cell["workspace_admission"],
        )
        if SUPPORT_LADDER.index(support["implementation_support"]) > SUPPORT_LADDER.index(
            SUPPORT_CEILING_WITH_TRIAD
        ):
            failures.append(
                f"{cell['cell_id']}: support {support['implementation_support']} exceeds "
                f"the generated ceiling {SUPPORT_CEILING_WITH_TRIAD}"
            )
        if support["blocking_defects"] and support["triad_complete"]:
            failures.append(f"{cell['cell_id']}: triad reported complete with defects")
    return failures
