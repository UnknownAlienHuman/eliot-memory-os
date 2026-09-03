"""Fail-closed Cargo-package/front-door to canonical-documentation closure."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .blocks import load_docs_router
from .cargo import nearest_agents, package_metadata
from .common import (
    DEFAULT_HANDLE_INDEX,
    NavigationError,
    normalize_repo_path,
    read_json,
    read_toml,
    relative_to_root,
)
from .registry import build_registry

BLOCKS_PATH = "docs/code-navigation/logical-blocks.toml"
WORKSPACE_INDEX = "docs/code-navigation/PACKAGE_DOCS_INDEX.md"
PROTOTYPE_INDEX = "docs/code-navigation/PROTOTYPE_DOCS_INDEX.md"
HANDLE_TOKEN = re.compile(r"(?:[AI]\d+(?:\.\d+)*|APPENDIX-[A-Z])")

FAMILIES = (
    ("crates/", "crates/AGENTS.md"),
    ("bins/", "bins/AGENTS.md"),
    ("workspace/tools/", "workspace/tools/AGENTS.md"),
)


def _family(package_root: str) -> str:
    value = normalize_repo_path(package_root)
    for prefix, contract in FAMILIES:
        if value.startswith(prefix):
            return contract
    raise NavigationError(f"Cargo package has no documentation family: {value}")


def _selector(root: Path, raw: Any, field: str) -> list[str]:
    if not isinstance(raw, str) or not raw.strip():
        raise NavigationError(f"{field} contains an invalid selector")
    value = normalize_repo_path(raw)
    candidates = sorted(root.glob(value)) if any(c in value for c in "*?[") else [root / value]
    result = [
        relative_to_root(root, path)
        for path in candidates
        if path.is_dir() and not path.is_symlink() and (path / "Cargo.toml").is_file()
    ]
    if not result:
        raise NavigationError(f"{field} selector resolves to no Cargo package: {raw!r}")
    return result


def _unique(root: Path, values: Any, field: str) -> list[str]:
    if not isinstance(values, list) or not values:
        raise NavigationError(f"{field} must be a non-empty array")
    owners: dict[str, str] = {}
    for raw in values:
        for package_root in _selector(root, raw, field):
            previous = owners.get(package_root)
            if previous is not None:
                raise NavigationError(
                    f"{field} contains duplicate/overlapping selectors for {package_root}: "
                    f"{previous!r}, {raw!r}"
                )
            owners[package_root] = str(raw)
    return sorted(owners)


def _denominator(root: Path) -> tuple[list[str], list[str]]:
    workspace = read_toml(root / "Cargo.toml").get("workspace")
    if not isinstance(workspace, dict):
        raise NavigationError("root Cargo.toml has no [workspace] table")
    members = _unique(root, workspace.get("members"), "workspace.members")
    raw_excludes = workspace.get("exclude", [])
    if not isinstance(raw_excludes, list):
        raise NavigationError("workspace.exclude must be an array")
    excludes = set(_unique(root, raw_excludes, "workspace.exclude")) if raw_excludes else set()
    members = [item for item in members if item not in excludes]
    if not members:
        raise NavigationError("workspace member denominator is empty after excludes")
    raw_defaults = workspace.get("default-members")
    defaults = (
        _unique(root, raw_defaults, "workspace.default-members")
        if raw_defaults is not None
        else list(members)
    )
    outside = sorted(set(defaults) - set(members))
    if outside:
        raise NavigationError(
            "workspace.default-members contains nonmembers: " + ", ".join(outside)
        )
    return members, defaults


def _front_doors(package: dict[str, Any]) -> list[str]:
    root = normalize_repo_path(str(package.get("root_path", "")))
    manifest = normalize_repo_path(str(package.get("manifest_path", "")))
    targets = package.get("targets")
    if root in {"", "."} or manifest in {"", "."}:
        raise NavigationError("Cargo package has no root/manifest front door")
    if not isinstance(targets, list) or not targets:
        raise NavigationError(f"Cargo package has no target front door: {root}")
    values = [root, manifest]
    for target in targets:
        if not isinstance(target, dict):
            raise NavigationError(f"Cargo package target is invalid: {root}")
        relative = normalize_repo_path(str(target.get("path", "")))
        if relative in {"", "."}:
            raise NavigationError(f"Cargo package target path is empty: {root}")
        values.append(f"{root}/{relative}")
    return list(dict.fromkeys(values))


def _blocks(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for block in registry.get("logical_blocks", []):
        if not isinstance(block, dict):
            raise NavigationError("logical-block registry entry is not an object")
        block_id = str(block.get("id", "")).strip()
        handles = block.get("documentation_handles")
        files = block.get("matched_files")
        if not block_id or block_id in result:
            raise NavigationError(f"missing or duplicate logical-block id: {block_id!r}")
        if not isinstance(handles, list) or not handles:
            raise NavigationError(f"logical block has no governing handles: {block_id}")
        if not isinstance(files, list) or not files:
            raise NavigationError(f"logical block has no matched-file denominator: {block_id}")
        result[block_id] = block
    return result


def _declared_routes(root: Path) -> dict[str, set[str]]:
    raw_blocks = read_toml(root / BLOCKS_PATH).get("block")
    if not isinstance(raw_blocks, list) or not raw_blocks:
        raise NavigationError("logical block config has no [[block]] entries")
    result: dict[str, set[str]] = {}
    for index, raw in enumerate(raw_blocks):
        if not isinstance(raw, dict):
            raise NavigationError(f"logical block config entry is not a table: {index}")
        block_id = str(raw.get("id", "")).strip()
        route_ids = raw.get("documentation_route_ids")
        if not block_id or block_id in result:
            raise NavigationError(f"missing or duplicate logical block id in config: {block_id!r}")
        if not isinstance(route_ids, list) or not route_ids:
            raise NavigationError(f"logical block declares no documentation routes: {block_id}")
        normalized = {str(item).strip() for item in route_ids}
        if "" in normalized or len(normalized) != len(route_ids):
            raise NavigationError(
                f"logical block has empty/duplicate documentation routes: {block_id}"
            )
        result[block_id] = normalized
    return result


def _canonical(root: Path) -> dict[str, dict[str, Any]]:
    payload = read_json(root / DEFAULT_HANDLE_INDEX)
    handles = (
        payload.get("handles")
        if payload.get("schema_version") == "eliot-handle-index-v1"
        else None
    )
    if not isinstance(handles, dict) or not handles:
        raise NavigationError("canonical handle index is empty or unsupported")
    return handles


def _check_handles(
    root: Path,
    requested: Iterable[str],
    handles: dict[str, dict[str, Any]],
) -> None:
    for raw in requested:
        handle = str(raw).strip()
        record = handles.get(handle)
        if not isinstance(record, dict):
            raise NavigationError(f"governing handle is absent from canonical index: {handle}")
        path = normalize_repo_path(str(record.get("path", "")))
        anchor = str(record.get("anchor", "")).strip()
        digest = str(record.get("fragment_sha256", "")).strip()
        if path in {"", "."} or not anchor or len(digest) != 64:
            raise NavigationError(f"governing handle has an incomplete binding: {handle}")
        target = root / PurePosixPath(path)
        if not target.is_file() or target.is_symlink():
            raise NavigationError(
                f"governing handle fragment is missing/symlinked: {handle} -> {path}"
            )


def _index(root: Path, relative: str) -> str:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise NavigationError(f"package documentation index is missing/symlinked: {relative}")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise NavigationError(f"cannot read package documentation index {relative}: {exc}") from exc


def _unique_line(text: str, needle: str, field: str) -> str:
    lines = [line for line in text.splitlines() if needle in line]
    if len(lines) != 1:
        raise NavigationError(
            f"{field} must occur in exactly one table row: "
            f"needle={needle!r} count={len(lines)}"
        )
    return lines[0]


def _check_backlink(
    text: str,
    package: dict[str, Any],
    package_blocks: list[dict[str, Any]],
    known_block_ids: set[str],
    relative: str,
) -> None:
    package_root = normalize_repo_path(str(package.get("root_path", "")))
    manifest = normalize_repo_path(str(package.get("manifest_path", "")))
    package_link = f"[`{package_root}`](../../{manifest})"
    package_row = _unique_line(text, package_link, relative)
    expected_blocks = {str(block["id"]) for block in package_blocks}
    row_tokens = set(re.findall(r"`([^`]+)`", package_row))
    actual_blocks = row_tokens.intersection(known_block_ids)
    if actual_blocks != expected_blocks:
        raise NavigationError(
            f"{relative} package row has incorrect logical blocks: "
            f"{package_root} expected={sorted(expected_blocks)} "
            f"actual={sorted(actual_blocks)}"
        )

    for block in package_blocks:
        block_id = str(block["id"])
        block_row = _unique_line(text, f"| `{block_id}` |", relative)
        actual_handles = {
            token
            for token in re.findall(r"`([^`]+)`", block_row)
            if HANDLE_TOKEN.fullmatch(token)
        }
        expected_handles = {str(handle) for handle in block["documentation_handles"]}
        if actual_handles != expected_handles:
            raise NavigationError(
                f"{relative} block row has incorrect governing handles: "
                f"{block_id} expected={sorted(expected_handles)} "
                f"actual={sorted(actual_handles)}"
            )


def _route_evidence(
    root: Path,
    router: Any,
    config: Any,
    path: str,
    canonical: dict[str, dict[str, Any]],
) -> tuple[set[str], set[str]]:
    try:
        payload = router.route_payload(root, config, [path], "")
    except Exception as exc:  # noqa: BLE001
        raise NavigationError(
            f"cannot resolve path-only documentation route for {path}: {exc}"
        ) from exc
    routes = payload.get("matched_routes")
    required = payload.get("required")
    optional = payload.get("optional")
    if not isinstance(routes, list) or not routes or len(routes) != len(set(map(str, routes))):
        raise NavigationError(f"documentation route has no unique non-baseline routes: {path}")
    if not isinstance(required, list) or not required or not isinstance(optional, list):
        raise NavigationError(f"documentation route has invalid item sets: {path}")
    routed: set[str] = set()
    for item in [*required, *optional]:
        if not isinstance(item, dict) or item.get("kind") != "fragment":
            continue
        item_handles, anchors = item.get("handles"), item.get("anchors")
        if (
            not isinstance(item_handles, list)
            or not isinstance(anchors, list)
            or len(item_handles) != len(anchors)
        ):
            raise NavigationError(f"route fragment has invalid handle/anchor arrays: {path}")
        fragment = normalize_repo_path(str(item.get("path", "")))
        digest = str(item.get("sha256", ""))
        for handle, anchor in zip(item_handles, anchors, strict=True):
            handle = str(handle)
            expected = canonical.get(handle)
            if not isinstance(expected, dict):
                raise NavigationError(f"route returned unknown canonical handle {handle}: {path}")
            actual = (fragment, str(anchor), digest)
            wanted = (
                normalize_repo_path(str(expected.get("path", ""))),
                str(expected.get("anchor", "")),
                str(expected.get("fragment_sha256", "")),
            )
            if actual != wanted:
                raise NavigationError(
                    f"route binding differs from canonical handle index: {path} {handle}"
                )
            routed.add(handle)
    if not routed:
        raise NavigationError(f"documentation route resolves no canonical fragments: {path}")
    return {str(item) for item in routes}, routed


def _package_blocks(
    package: dict[str, Any],
    blocks: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    ids = package.get("logical_blocks")
    if not isinstance(ids, list) or not ids:
        raise NavigationError(
            f"Cargo package is outside every logical block: {package.get('root_path')}"
        )
    result: list[dict[str, Any]] = []
    for raw in ids:
        block = blocks.get(str(raw))
        if block is None:
            raise NavigationError(
                "Cargo package references unknown logical block: "
                f"{package.get('root_path')} {raw}"
            )
        result.append(block)
    return result


def check(root: Path) -> None:
    root = root.resolve()
    registry = build_registry(root)
    members, defaults = _denominator(root)
    manifest = registry.get("workspace_manifest", {})
    if manifest.get("members") != members or manifest.get("default_members") != defaults:
        raise NavigationError("workspace registry denominator differs from raw Cargo selectors")

    blocks = _blocks(registry)
    declared = _declared_routes(root)
    if set(declared) != set(blocks):
        raise NavigationError(
            "logical block route declarations differ from live registry: "
            f"missing={sorted(set(blocks)-set(declared)) or '-'} "
            f"extra={sorted(set(declared)-set(blocks)) or '-'}"
        )
    canonical = _canonical(root)
    router = load_docs_router(root)
    config = router.load_config(root)
    configured = {str(route.route_id) for route in config.routes}
    for block_id, route_ids in declared.items():
        unknown = sorted(route_ids - configured)
        if unknown:
            raise NavigationError(
                f"logical block declares unknown documentation routes: {block_id} {unknown}"
            )

    workspace_index = _index(root, WORKSPACE_INDEX)
    prototype_index = _index(root, PROTOTYPE_INDEX)
    block_paths = 0
    for block_id, block in blocks.items():
        _check_handles(root, block["documentation_handles"], canonical)
        for raw_path in block["matched_files"]:
            path = normalize_repo_path(str(raw_path))
            target = root / path
            if not target.is_file() or target.is_symlink():
                raise NavigationError(
                    f"logical-block matched path is missing/symlinked: {block_id} {path}"
                )
            try:
                actual = {
                    str(route.route_id)
                    for route in router.matched_routes(config, [path], "")
                }
            except Exception as exc:  # noqa: BLE001
                raise NavigationError(
                    f"cannot match path-only route: {block_id} {path}: {exc}"
                ) from exc
            missing = sorted(declared[block_id] - actual)
            if missing:
                raise NavigationError(
                    f"logical-block path omits declared routes: {block_id} "
                    f"{path} {missing}"
                )
            block_paths += 1

    route_cache: dict[str, tuple[set[str], set[str]]] = {}
    workspace_count = prototype_count = front_doors = package_checks = 0
    packages = registry.get("packages")
    if not isinstance(packages, list) or not packages:
        raise NavigationError("Cargo package registry is empty")
    for package in packages:
        if not isinstance(package, dict):
            raise NavigationError("Cargo package registry entry is not an object")
        package_root = normalize_repo_path(str(package.get("root_path", "")))
        package_blocks = _package_blocks(package, blocks)
        is_workspace = package.get("workspace_member") is True
        _check_backlink(
            workspace_index if is_workspace else prototype_index,
            package,
            package_blocks,
            set(blocks),
            WORKSPACE_INDEX if is_workspace else PROTOTYPE_INDEX,
        )
        if is_workspace:
            workspace_count += 1
        else:
            prototype_count += 1
            metadata = package_metadata(read_toml(root / str(package["manifest_path"])))
            if metadata.get("prototype") is not True:
                raise NavigationError(f"nonmember package is not prototype=true: {package_root}")
            admission = metadata.get("workspace_admission")
            if not isinstance(admission, str) or not admission.strip():
                raise NavigationError(
                    f"prototype package has no workspace_admission: {package_root}"
                )

        wanted_routes = set().union(*(declared[str(block["id"])] for block in package_blocks))
        wanted_handles = {
            str(handle)
            for block in package_blocks
            for handle in block["documentation_handles"]
        }
        contract = _family(package_root)
        for front_door in _front_doors(package):
            target = root / front_door
            if not target.exists() or target.is_symlink():
                raise NavigationError(
                    f"Cargo package front door is missing/symlinked: {front_door}"
                )
            if contract not in nearest_agents(root, front_door):
                raise NavigationError(
                    f"Cargo package front door does not inherit {contract}: {front_door}"
                )
            evidence = route_cache.get(front_door)
            if evidence is None:
                evidence = _route_evidence(root, router, config, front_door, canonical)
                route_cache[front_door] = evidence
            routes, handles = evidence
            missing_routes = sorted(wanted_routes - routes)
            missing_handles = sorted(wanted_handles - handles)
            if missing_routes or missing_handles:
                raise NavigationError(
                    "Cargo package front door has incomplete path-only documentation "
                    f"closure: {front_door} missing_routes={missing_routes or '-'} "
                    f"missing_handles={missing_handles or '-'}"
                )
            front_doors += 1
            package_checks += len(package_blocks)

    if workspace_count != len(members):
        raise NavigationError(
            "workspace package count differs from Cargo denominator: "
            f"{workspace_count} != {len(members)}"
        )
    print(
        "DOCUMENTATION_CLOSURE_CHECK: PASS "
        f"workspace_packages={workspace_count} prototypes={prototype_count} "
        f"front_doors={front_doors} package_routes={package_checks} block_paths={block_paths}"
    )


def self_test() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "crates/a").mkdir(parents=True)
        (root / "crates/a/Cargo.toml").write_text("[package]\nname='a'\n", encoding="utf-8")
        (root / "Cargo.toml").write_text(
            "[workspace]\nmembers=['crates/a', 'crates/*']\ndefault-members=['crates/a']\n",
            encoding="utf-8",
        )
        try:
            _denominator(root)
        except NavigationError as exc:
            if "duplicate/overlapping" not in str(exc):
                raise
        else:
            raise NavigationError("overlapping workspace selectors were accepted")
        (root / "Cargo.toml").write_text(
            "[workspace]\nmembers=['crates/a']\ndefault-members=['crates/a']\n",
            encoding="utf-8",
        )
        if _denominator(root) != (["crates/a"], ["crates/a"]):
            raise NavigationError("workspace denominator self-test differs")
        package = {
            "root_path": "crates/a",
            "manifest_path": "crates/a/Cargo.toml",
            "targets": [{"path": "src/lib.rs"}, {"path": "src/lib.rs"}],
        }
        if _front_doors(package) != ["crates/a", "crates/a/Cargo.toml", "crates/a/src/lib.rs"]:
            raise NavigationError("front-door deduplication self-test failed")
    print("DOCUMENTATION_CLOSURE_SELF_TEST: PASS cases=3")
