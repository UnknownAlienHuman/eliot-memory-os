"""Fail-closed workspace-package to documentation navigation closure."""

from __future__ import annotations

import re
import tempfile
import urllib.parse
from pathlib import Path, PurePosixPath
from typing import Any

from .cargo import nearest_agents
from .common import NavigationError, normalize_repo_path, relative_to_root
from .registry import build_registry

SCHEMA = "eliot-package-doc-index-v1"
MARKER = f"<!-- generated: {SCHEMA} -->"
INDEX_PATH = "docs/code-navigation/PACKAGE_DOCS_INDEX.md"
PROTOCOL_PATH = "docs/architecture/READING_PROTOCOL.md"
ROUTING_START = "<!-- eliot-doc-routing:start -->"
ROUTING_END = "<!-- eliot-doc-routing:end -->"
LINK_RE = re.compile(r"\[[^\]\r\n]+\]\((?P<destination>[^)\r\n]+)\)")
FAMILIES = (
    ("crates/", "crates/AGENTS.md"),
    ("bins/", "bins/AGENTS.md"),
    ("workspace/tools/", "workspace/tools/AGENTS.md"),
)


def family_contract(package_root: str) -> str:
    package_root = normalize_repo_path(package_root)
    for prefix, contract in FAMILIES:
        if package_root.startswith(prefix):
            return contract
    raise NavigationError(f"workspace package has no docs family: {package_root}")


def _destination(raw: str) -> str:
    value = raw.strip()
    if value.startswith("<"):
        end = value.find(">")
        if end < 0:
            raise NavigationError(f"malformed Markdown destination: {raw!r}")
        return value[1:end]
    return value.split(maxsplit=1)[0]


def _links(root: Path, source_relative: str, text: str) -> set[str]:
    source = root / PurePosixPath(normalize_repo_path(source_relative))
    result: set[str] = set()
    for match in LINK_RE.finditer(text):
        parsed = urllib.parse.urlsplit(_destination(match.group("destination")))
        if parsed.scheme or parsed.netloc:
            continue
        link_path = urllib.parse.unquote(parsed.path)
        if not link_path:
            target = source
        elif link_path.startswith("/"):
            target = root / PurePosixPath(link_path.lstrip("/"))
        else:
            target = source.parent / PurePosixPath(link_path)
        result.add(relative_to_root(root, target))
    return result


def _validate_contract(root: Path, relative: str) -> None:
    path = root / PurePosixPath(relative)
    if not path.is_file():
        raise NavigationError(f"workspace docs contract is missing: {relative}")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise NavigationError(f"cannot read workspace docs contract {relative}: {exc}") from exc
    if text.count(ROUTING_START) != 1 or text.count(ROUTING_END) != 1:
        raise NavigationError(f"invalid routing markers in {relative}")
    start = text.index(ROUTING_START)
    end = text.index(ROUTING_END)
    if start >= end or "python scripts/docs_read.py read" not in text[start:end]:
        raise NavigationError(f"verified reader is absent from routing block: {relative}")
    links = _links(root, relative, text)
    for required in (PROTOCOL_PATH, INDEX_PATH):
        if required not in links:
            raise NavigationError(f"{relative} does not link to {required}")
    if not (root / PROTOCOL_PATH).is_file():
        raise NavigationError(f"documentation reading protocol is missing: {PROTOCOL_PATH}")


def _packages(registry: dict[str, Any]) -> list[dict[str, Any]]:
    packages = [item for item in registry.get("packages", []) if item.get("workspace_member") is True]
    return sorted(packages, key=lambda item: str(item.get("root_path", "")))


def _blocks(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for block in registry.get("logical_blocks", []):
        block_id = str(block.get("id", "")).strip()
        if not block_id or block_id in result:
            raise NavigationError(f"missing or duplicate logical block id: {block_id!r}")
        result[block_id] = block
    return result


def _handles(package: dict[str, Any], blocks: dict[str, dict[str, Any]]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for raw_id in package.get("logical_blocks", []):
        block_id = str(raw_id)
        block = blocks.get(block_id)
        if block is None:
            raise NavigationError(
                f"package {package.get('root_path')} references unknown block {block_id}"
            )
        handles = block.get("documentation_handles")
        routes = block.get("documentation_route_ids")
        if not isinstance(handles, list) or not handles:
            raise NavigationError(f"logical block has no documentation handles: {block_id}")
        if not isinstance(routes, list) or not routes:
            raise NavigationError(f"logical block resolves no docs route: {block_id}")
        for raw_handle in handles:
            handle = str(raw_handle).strip()
            if not handle:
                raise NavigationError(f"logical block contains an empty handle: {block_id}")
            if handle not in seen:
                result.append(handle)
                seen.add(handle)
    return result


def validate(root: Path, registry: dict[str, Any]) -> None:
    root = root.resolve()
    packages = _packages(registry)
    manifest = registry.get("workspace_manifest", {})
    raw_members = manifest.get("members")
    if not isinstance(raw_members, list) or not raw_members:
        raise NavigationError("workspace registry has no Cargo member denominator")
    expected = sorted(normalize_repo_path(str(item)) for item in raw_members)
    actual = [normalize_repo_path(str(item.get("root_path", ""))) for item in packages]
    if len(actual) != len(set(actual)):
        raise NavigationError("workspace package registry contains duplicate roots")
    if actual != expected:
        missing = sorted(set(expected).difference(actual))
        extra = sorted(set(actual).difference(expected))
        raise NavigationError(f"workspace denominator mismatch: missing={missing or '-'} extra={extra or '-'}")

    raw_defaults = manifest.get("default_members", [])
    if not isinstance(raw_defaults, list):
        raise NavigationError("workspace default-member denominator is invalid")
    defaults = {normalize_repo_path(str(item)) for item in raw_defaults}
    blocks = _blocks(registry)
    checked_contracts: set[str] = set()

    for package, package_root in zip(packages, actual, strict=True):
        if package.get("default_member") is not (package_root in defaults):
            raise NavigationError(f"default-member state disagrees with Cargo.toml: {package_root}")
        manifest_path = normalize_repo_path(str(package.get("manifest_path", "")))
        if not (root / manifest_path).is_file():
            raise NavigationError(f"workspace package manifest is missing: {manifest_path}")
        targets = package.get("targets")
        if not isinstance(targets, list) or not targets:
            raise NavigationError(f"workspace package has no target front door: {package_root}")
        for target in targets:
            relative = normalize_repo_path(str(target.get("path", "")))
            if not (root / package_root / relative).is_file():
                raise NavigationError(f"workspace package target is missing: {package_root}/{relative}")
        logical_blocks = package.get("logical_blocks")
        if not isinstance(logical_blocks, list) or not logical_blocks or not _handles(package, blocks):
            raise NavigationError(f"workspace package resolves no governing docs: {package_root}")
        contract = family_contract(package_root)
        if contract not in nearest_agents(root, package_root):
            raise NavigationError(f"workspace package does not inherit {contract}: {package_root}")
        if contract not in checked_contracts:
            _validate_contract(root, contract)
            checked_contracts.add(contract)


def _md_link(label: str, destination: str) -> str:
    return f"[{label}]({destination})"


def render(registry: dict[str, Any]) -> str:
    packages = _packages(registry)
    blocks = _blocks(registry)
    default_count = sum(item.get("default_member") is True for item in packages)
    used_contracts = sorted({family_contract(str(item["root_path"])) for item in packages})
    lines = [
        MARKER,
        "# Workspace package ↔ documentation index",
        "",
        "This committed file is a deterministic navigation projection, not architectural",
        "or source authority. Its denominator comes only from the root",
        "[`Cargo.toml`](../../Cargo.toml). Package-to-document mappings come from",
        "[`logical-blocks.toml`](logical-blocks.toml), the canonical",
        "[`HANDLE_INDEX.md`](../architecture/HANDLE_INDEX.md), and inherited",
        "`AGENTS.md` contracts. Do not edit it by hand.",
        "",
        "```powershell",
        "python scripts/code_navigation.py sync-index --root .",
        "python scripts/code_navigation.py check --root .",
        "```",
        "",
        "## Coverage",
        "",
        f"- Workspace members: **{len(packages)}**.",
        f"- Default members: **{default_count}**.",
        f"- Logical responsibility blocks: **{len(blocks)}**.",
        f"- Inherited package-family contracts: **{len(used_contracts)}**.",
        "",
        "## Package-family contracts",
        "",
        "| Package path | Inherited contract |",
        "|---|---|",
    ]
    for prefix, contract in FAMILIES:
        if contract in used_contracts:
            lines.append(
                f"| `{prefix}**` | {_md_link(f'`{contract}`', f'../../{contract}')} |"
            )

    lines.extend(
        [
            "",
            "## Logical responsibility blocks",
            "",
            "| Block | Governing handles |",
            "|---|---|",
        ]
    )
    for block_id, block in blocks.items():
        handles = "<br>".join(
            _md_link(f"`{handle}`", "../architecture/HANDLE_INDEX.md")
            for handle in block["documentation_handles"]
        )
        lines.append(f"| `{block_id}` | {handles} |")

    lines.extend(
        [
            "",
            "## Workspace packages",
            "",
            "| Package manifest | Admission | Logical blocks |",
            "|---|---|---|",
        ]
    )
    for package in packages:
        root_path = str(package["root_path"])
        manifest_path = str(package["manifest_path"])
        admission = "default" if package.get("default_member") else "workspace"
        block_cell = "<br>".join(f"`{item}`" for item in package["logical_blocks"])
        package_link = _md_link(f"`{root_path}`", f"../../{manifest_path}")
        lines.append(f"| {package_link} | `{admission}` | {block_cell} |")

    lines.extend(
        [
            "",
            "## Proof boundary",
            "",
            "A clean index proves static workspace membership, inherited routing",
            "contracts, logical-block coverage, resolvable documentation handles, and",
            "byte-for-byte projection equality for the exact checkout. It does not prove",
            "compilation, runtime wiring, semantic ownership, service health, or Product",
            "acceptance.",
            "",
        ]
    )
    return "\n".join(lines)


def _check_index(root: Path, registry: dict[str, Any]) -> None:
    index = root / INDEX_PATH
    if not index.is_file():
        raise NavigationError(
            f"workspace package docs index is missing: {INDEX_PATH}; run "
            "`python scripts/code_navigation.py sync-index --root .`"
        )
    try:
        actual = index.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise NavigationError(f"cannot read workspace package docs index: {exc}") from exc
    if actual != render(registry):
        raise NavigationError(
            "workspace package docs index is stale or hand-edited; run "
            "`python scripts/code_navigation.py sync-index --root .`"
        )


def write_index(root: Path) -> None:
    root = root.resolve()
    registry = build_registry(root)
    validate(root, registry)
    index = root / INDEX_PATH
    index.parent.mkdir(parents=True, exist_ok=True)
    index.write_text(render(registry), encoding="utf-8", newline="")
    print(f"PACKAGE_DOC_INDEX_WRITE: PASS path={INDEX_PATH} workspace_members={len(_packages(registry))}")


def check(root: Path) -> None:
    root = root.resolve()
    registry = build_registry(root)
    validate(root, registry)
    _check_index(root, registry)
    print(
        "PACKAGE_DOC_INDEX_CHECK: PASS "
        f"workspace_members={len(_packages(registry))} "
        f"default_members={len(registry['workspace_manifest']['default_members'])} "
        f"logical_blocks={len(registry['logical_blocks'])}"
    )


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "crates/a/src").mkdir(parents=True)
        (root / "docs/architecture").mkdir(parents=True)
        (root / "docs/code-navigation").mkdir(parents=True)
        (root / "AGENTS.md").write_text("# root\n", encoding="utf-8")
        (root / "crates/a/Cargo.toml").write_text("[package]\nname='a'\n", encoding="utf-8")
        (root / "crates/a/src/lib.rs").write_text("pub fn value() {}\n", encoding="utf-8")
        (root / PROTOCOL_PATH).write_text("# protocol\n", encoding="utf-8")
        contract = (
            f"{ROUTING_START}\npython scripts/docs_read.py read\n"
            "[protocol](../docs/architecture/READING_PROTOCOL.md)\n"
            f"{ROUTING_END}\n[index](../docs/code-navigation/PACKAGE_DOCS_INDEX.md)\n"
        )
        (root / "crates/AGENTS.md").write_text(contract, encoding="utf-8")
        registry = {
            "workspace_manifest": {"members": ["crates/a"], "default_members": ["crates/a"]},
            "packages": [{
                "root_path": "crates/a",
                "manifest_path": "crates/a/Cargo.toml",
                "workspace_member": True,
                "default_member": True,
                "targets": [{"path": "src/lib.rs"}],
                "logical_blocks": ["test"],
            }],
            "logical_blocks": [{
                "id": "test",
                "documentation_handles": ["I2.8"],
                "documentation_route_ids": ["test-route"],
            }],
        }
        validate(root, registry)
        index = root / INDEX_PATH
        index.write_text(render(registry), encoding="utf-8", newline="")
        _check_index(root, registry)
        index.write_text("tampered\n", encoding="utf-8")
        try:
            _check_index(root, registry)
        except NavigationError:
            pass
        else:
            raise NavigationError("tampered package docs index was accepted")
        index.write_text(render(registry), encoding="utf-8", newline="")
        (root / "crates/AGENTS.md").write_text(
            contract.replace("[index](../docs/code-navigation/PACKAGE_DOCS_INDEX.md)\n", ""),
            encoding="utf-8",
        )
        try:
            validate(root, registry)
        except NavigationError:
            pass
        else:
            raise NavigationError("missing package-index backlink was accepted")
        (root / "crates/AGENTS.md").write_text(contract, encoding="utf-8")
        registry["packages"][0]["targets"] = []
        try:
            validate(root, registry)
        except NavigationError:
            pass
        else:
            raise NavigationError("workspace package without a target was accepted")
    print("PACKAGE_DOC_INDEX_SELF_TEST: PASS cases=4")
