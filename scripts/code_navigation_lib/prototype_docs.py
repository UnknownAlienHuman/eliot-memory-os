"""Fail-closed nonmember-prototype to documentation navigation closure."""

from __future__ import annotations

import re
import tempfile
import urllib.parse
from pathlib import Path, PurePosixPath
from typing import Any

from .cargo import nearest_agents, package_metadata
from .common import NavigationError, normalize_repo_path, read_toml, relative_to_root
from .package_docs import INDEX_PATH as WORKSPACE_INDEX_PATH
from .package_docs import PROTOCOL_PATH, family_contract
from .registry import build_registry

SCHEMA = "eliot-prototype-doc-index-v1"
MARKER = f"<!-- generated: {SCHEMA} -->"
INDEX_PATH = "docs/code-navigation/PROTOTYPE_DOCS_INDEX.md"
CONTRACT_PATH = "crates/AGENTS.md"
ROUTING_START = "<!-- eliot-doc-routing:start -->"
ROUTING_END = "<!-- eliot-doc-routing:end -->"
LINK_RE = re.compile(r"\[[^\]\r\n]+\]\((?P<destination>[^)\r\n]+)\)")


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


def _validate_contract(root: Path) -> None:
    path = root / CONTRACT_PATH
    if not path.is_file():
        raise NavigationError(f"prototype docs contract is missing: {CONTRACT_PATH}")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise NavigationError(f"cannot read prototype docs contract: {exc}") from exc
    if text.count(ROUTING_START) != 1 or text.count(ROUTING_END) != 1:
        raise NavigationError(f"invalid routing markers in {CONTRACT_PATH}")
    start = text.index(ROUTING_START)
    end = text.index(ROUTING_END)
    if start >= end or "python scripts/docs_read.py read" not in text[start:end]:
        raise NavigationError(
            f"verified reader is absent from routing block: {CONTRACT_PATH}"
        )
    links = _links(root, CONTRACT_PATH, text)
    for required in (PROTOCOL_PATH, WORKSPACE_INDEX_PATH, INDEX_PATH):
        if required not in links:
            raise NavigationError(f"{CONTRACT_PATH} does not link to {required}")


def _packages(registry: dict[str, Any]) -> list[dict[str, Any]]:
    packages = [
        item
        for item in registry.get("packages", [])
        if item.get("workspace_member") is not True
    ]
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
                f"prototype {package.get('root_path')} references unknown block {block_id}"
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


def _metadata(root: Path, package: dict[str, Any]) -> dict[str, Any]:
    manifest = normalize_repo_path(str(package.get("manifest_path", "")))
    if not manifest:
        raise NavigationError(f"prototype has no manifest path: {package.get('root_path')}")
    return package_metadata(read_toml(root / PurePosixPath(manifest)))


def validate(root: Path, registry: dict[str, Any]) -> None:
    root = root.resolve()
    packages = _packages(registry)
    roots = [normalize_repo_path(str(item.get("root_path", ""))) for item in packages]
    if len(roots) != len(set(roots)):
        raise NavigationError("nonmember Cargo package registry contains duplicate roots")
    blocks = _blocks(registry)
    _validate_contract(root)

    for package, package_root in zip(packages, roots, strict=True):
        if package.get("default_member") is True:
            raise NavigationError(
                f"nonmember package is marked as a default member: {package_root}"
            )
        if family_contract(package_root) != CONTRACT_PATH:
            raise NavigationError(
                f"nonmember package is outside the prototype docs family: {package_root}"
            )
        if CONTRACT_PATH not in nearest_agents(root, package_root):
            raise NavigationError(
                f"prototype package does not inherit {CONTRACT_PATH}: {package_root}"
            )
        manifest = normalize_repo_path(str(package.get("manifest_path", "")))
        if not (root / manifest).is_file():
            raise NavigationError(f"prototype manifest is missing: {manifest}")
        logical_blocks = package.get("logical_blocks")
        if not isinstance(logical_blocks, list) or not logical_blocks:
            raise NavigationError(
                f"prototype package is outside every logical block: {package_root}"
            )
        if not _handles(package, blocks):
            raise NavigationError(
                f"prototype package resolves no governing docs: {package_root}"
            )
        metadata = _metadata(root, package)
        if metadata.get("prototype") is not True:
            raise NavigationError(
                f"nonmember Cargo package is not classified as a prototype: {package_root}"
            )
        admission = metadata.get("workspace_admission")
        if not isinstance(admission, str) or not admission.strip():
            raise NavigationError(
                f"prototype package has no explicit workspace_admission: {package_root}"
            )


def _md_link(label: str, destination: str) -> str:
    return f"[{label}]({destination})"


def _block_handles(block: dict[str, Any]) -> str:
    return "<br>".join(
        _md_link(f"`{handle}`", "../architecture/HANDLE_INDEX.md")
        for handle in block["documentation_handles"]
    )


def render(root: Path, registry: dict[str, Any]) -> str:
    root = root.resolve()
    packages = _packages(registry)
    blocks = _blocks(registry)
    for package in packages:
        if _metadata(root, package).get("prototype") is not True:
            raise NavigationError(
                f"cannot render unclassified nonmember package: {package.get('root_path')}"
            )
    used_block_ids = {
        str(block_id)
        for package in packages
        for block_id in package.get("logical_blocks", [])
    }
    lines = [
        MARKER,
        "# Nonmember prototype package ↔ documentation index",
        "",
        "This committed file is a deterministic navigation projection for Cargo packages",
        "that exist in the repository but are not admitted by the root",
        "[`Cargo.toml`](../../Cargo.toml). Prototype presence is not workspace admission,",
        "implementation completion, runtime support, or Product acceptance. Package-to-",
        "documentation mappings come from [`logical-blocks.toml`](logical-blocks.toml),",
        "the canonical [`HANDLE_INDEX.md`](../architecture/HANDLE_INDEX.md), and the",
        "inherited [`crates/AGENTS.md`](../../crates/AGENTS.md) contract. Do not edit it",
        "by hand.",
        "",
        "```powershell",
        "python scripts/code_navigation.py sync-index --root .",
        "python scripts/code_navigation.py check --root .",
        "```",
        "",
        "## Coverage",
        "",
        f"- Nonmember Cargo packages: **{len(packages)}**.",
        f"- Explicitly classified prototypes: **{len(packages)}**.",
        f"- Governing logical blocks represented: **{len(used_block_ids)}**.",
        "",
        "## Governing logical blocks",
        "",
        "| Block | Governing handles |",
        "|---|---|",
    ]
    for block_id, block in blocks.items():
        if block_id in used_block_ids:
            lines.append(f"| `{block_id}` | {_block_handles(block)} |")

    lines.extend(
        [
            "",
            "## Nonmember prototype packages",
            "",
            "| Package manifest | Admission | Logical blocks |",
            "|---|---|---|",
        ]
    )
    for package in packages:
        root_path = str(package["root_path"])
        manifest_path = str(package["manifest_path"])
        block_cell = "<br>".join(f"`{item}`" for item in package["logical_blocks"])
        package_link = _md_link(f"`{root_path}`", f"../../{manifest_path}")
        lines.append(
            f"| {package_link} | `nonmember prototype` | {block_cell} |"
        )

    lines.extend(
        [
            "",
            "## Proof boundary",
            "",
            "A clean index proves manifest discovery, explicit prototype classification,",
            "inherited documentation routing, logical-block coverage, resolvable",
            "documentation handles, and byte-for-byte projection equality for the exact",
            "checkout. It does not prove source implementation, buildability, workspace",
            "admission, runtime wiring, semantic ownership, or Product acceptance.",
            "",
        ]
    )
    return "\n".join(lines)


def _check_index(root: Path, expected: str) -> None:
    index = root / INDEX_PATH
    if not index.is_file():
        raise NavigationError(
            f"prototype docs index is missing: {INDEX_PATH}; run "
            "`python scripts/code_navigation.py sync-index --root .`"
        )
    try:
        actual = index.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise NavigationError(f"cannot read prototype docs index: {exc}") from exc
    if actual != expected:
        raise NavigationError(
            "prototype docs index is stale or hand-edited; run "
            "`python scripts/code_navigation.py sync-index --root .`"
        )


def write_index(root: Path) -> None:
    root = root.resolve()
    registry = build_registry(root)
    validate(root, registry)
    index = root / INDEX_PATH
    index.parent.mkdir(parents=True, exist_ok=True)
    index.write_text(render(root, registry), encoding="utf-8", newline="")
    print(
        "PROTOTYPE_DOC_INDEX_WRITE: PASS "
        f"nonmember_prototypes={len(_packages(registry))}"
    )


def check(root: Path) -> None:
    root = root.resolve()
    registry = build_registry(root)
    validate(root, registry)
    _check_index(root, render(root, registry))
    print(
        "PROTOTYPE_DOC_INDEX_CHECK: PASS "
        f"nonmember_prototypes={len(_packages(registry))}"
    )


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "crates/p").mkdir(parents=True)
        (root / "docs/architecture").mkdir(parents=True)
        (root / "docs/code-navigation").mkdir(parents=True)
        (root / "AGENTS.md").write_text("# root\n", encoding="utf-8")
        (root / "crates/p/Cargo.toml").write_text(
            "[package]\nname='p'\n"
            "[package.metadata.eliot]\n"
            "prototype=true\n"
            "workspace_admission='pending proof'\n",
            encoding="utf-8",
        )
        (root / PROTOCOL_PATH).write_text("# protocol\n", encoding="utf-8")
        contract = (
            f"{ROUTING_START}\npython scripts/docs_read.py read\n"
            "[protocol](../docs/architecture/READING_PROTOCOL.md)\n"
            f"{ROUTING_END}\n"
            "[workspace](../docs/code-navigation/PACKAGE_DOCS_INDEX.md)\n"
            "[prototype](../docs/code-navigation/PROTOTYPE_DOCS_INDEX.md)\n"
        )
        (root / CONTRACT_PATH).write_text(contract, encoding="utf-8")
        registry = {
            "packages": [
                {
                    "root_path": "crates/p",
                    "manifest_path": "crates/p/Cargo.toml",
                    "workspace_member": False,
                    "default_member": False,
                    "logical_blocks": ["test"],
                }
            ],
            "logical_blocks": [
                {
                    "id": "test",
                    "documentation_handles": ["I2.8"],
                    "documentation_route_ids": ["test-route"],
                }
            ],
        }

        validate(root, registry)
        index = root / INDEX_PATH
        index.write_text(render(root, registry), encoding="utf-8", newline="")
        _check_index(root, render(root, registry))

        index.write_text("tampered\n", encoding="utf-8")
        try:
            _check_index(root, render(root, registry))
        except NavigationError:
            pass
        else:
            raise NavigationError("tampered prototype index was accepted")
        index.write_text(render(root, registry), encoding="utf-8", newline="")

        (root / CONTRACT_PATH).write_text(
            contract.replace(
                "[prototype](../docs/code-navigation/PROTOTYPE_DOCS_INDEX.md)\n",
                "",
            ),
            encoding="utf-8",
        )
        try:
            validate(root, registry)
        except NavigationError:
            pass
        else:
            raise NavigationError("missing prototype-index backlink was accepted")
        (root / CONTRACT_PATH).write_text(contract, encoding="utf-8")

        (root / "crates/p/Cargo.toml").write_text(
            "[package]\nname='p'\n"
            "[package.metadata.eliot]\n"
            "workspace_admission='pending proof'\n",
            encoding="utf-8",
        )
        try:
            validate(root, registry)
        except NavigationError:
            pass
        else:
            raise NavigationError("unclassified nonmember package was accepted")

        (root / "crates/p/Cargo.toml").write_text(
            "[package]\nname='p'\n"
            "[package.metadata.eliot]\n"
            "prototype=true\n"
            "workspace_admission='pending proof'\n",
            encoding="utf-8",
        )
        registry["packages"][0]["logical_blocks"] = []
        try:
            validate(root, registry)
        except NavigationError:
            pass
        else:
            raise NavigationError("unmapped prototype package was accepted")
    print("PROTOTYPE_DOC_INDEX_SELF_TEST: PASS cases=5")
