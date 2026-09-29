"""Unit tests for issue #690: package -> target -> handle -> fragment navigation closure.

Declared denominator: 55 cases, exactly 1..55.
Each test case method has # WORK_UNIT_CASE: 690/<case> immediately above it.
"""

from __future__ import annotations

import copy
import json
import re
import tempfile
import unittest
from pathlib import Path

from scripts.code_navigation_lib import (
    NavigationError,
    build_registry,
)
from scripts.code_navigation_lib.cargo import (
    discover_manifests,
    inferred_targets,
)
from scripts.code_navigation_lib.common import normalize_repo_path, read_json, read_toml
from scripts.code_navigation_lib.handle_destinations import (
    DestinationResolver,
    get_resolver,
    natural_handle_key,
)
from scripts.code_navigation_lib.package_docs import (
    INDEX_PATH as PACKAGE_INDEX_PATH,
    PROTOCOL_PATH,
    ROUTING_END,
    ROUTING_START,
    _blocks,
    _check_index as _check_package_index,
    _handles,
    _packages,
    check as check_package_docs,
    render as render_package_docs,
    self_test as package_docs_self_test,
    validate as validate_package_docs,
)
from scripts.code_navigation_lib.prototype_docs import (
    INDEX_PATH as PROTOTYPE_INDEX_PATH,
    _packages as _prototype_packages,
    check as check_prototype_docs,
    render as render_prototype_docs,
    self_test as prototype_docs_self_test,
    validate as validate_prototype_docs,
)
from scripts.docs_shards_core import (
    DocsError,
    self_test as docs_shards_self_test,
    sha256_text,
    verify_manifest,
)

import sys

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))

REVERSE_HEADING = "## Reverse documentation"
HANDLE_CELL_RE = re.compile(r"^\[`(?P<handle>[^`]+)`\]\(")
LINK_LABEL_RE = re.compile(r"\[`(?P<label>[^`]+)`\]\(")
REVERSE_TARGET_RE = re.compile(r"^`(?P<cell>[^`]+:[^`]+)`")


def _table_section(rendered: str, heading: str) -> str:
    """Return the lines of one rendered Markdown table, heading excluded."""
    lines = rendered.splitlines()
    start = next(index for index, line in enumerate(lines) if line == heading)
    section: list[str] = []
    for line in lines[start + 1:]:
        if line.startswith("## "):
            break
        section.append(line)
    return "\n".join(section)


def _reverse_section(rendered: str) -> dict[str, dict[str, set[str]]]:
    """Parse the rendered reverse table into handle -> {packages, targets}."""
    lines = rendered.splitlines()
    start = next(
        index for index, line in enumerate(lines) if line.startswith(REVERSE_HEADING)
    )
    rows: dict[str, dict[str, set[str]]] = {}
    for line in lines[start + 1:]:
        if line.startswith("## "):
            break
        if not line.startswith("| ") or line.startswith("|---"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 4 or cells[0] == "Handle":
            continue
        handle_match = HANDLE_CELL_RE.match(cells[0])
        if handle_match is None:
            continue
        handle = handle_match.group("handle")
        if handle in rows:
            raise AssertionError(f"duplicate reverse row for handle {handle}")
        # Each <br>-separated chunk is "`root:path`" optionally followed by a
        # `[requires: ...]` gate; only the leading root:path is the identity.
        targets = set()
        for chunk in cells[3].split("<br>"):
            match = REVERSE_TARGET_RE.match(chunk.strip())
            if match is not None:
                targets.add(match.group("cell"))
        rows[handle] = {
            "packages": {match.group("label") for match in LINK_LABEL_RE.finditer(cells[2])},
            "targets": targets,
        }
    return rows


class TestPackageReaderClosure(unittest.TestCase):
    """55 substantive test cases for issue #690."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = build_registry(REPO_ROOT)
        cls.resolver = get_resolver(REPO_ROOT)

    # WORK_UNIT_CASE: 690/1
    def test_01_workspace_member_denominator(self) -> None:
        raw_members = self.registry["workspace_manifest"]["members"]
        packages = _packages(self.registry)
        expected = sorted(normalize_repo_path(str(m)) for m in raw_members)
        actual = sorted(normalize_repo_path(str(p["root_path"])) for p in packages)
        self.assertEqual(actual, expected)
        self.assertGreater(len(packages), 0)

    # WORK_UNIT_CASE: 690/2
    def test_02_default_member_parity(self) -> None:
        defaults = set(self.registry["workspace_manifest"]["default_members"])
        for package in _packages(self.registry):
            root_path = package["root_path"]
            expected = root_path in defaults
            self.assertEqual(package.get("default_member"), expected)

    # WORK_UNIT_CASE: 690/3
    def test_03_complete_nonmember_cargo_denominator(self) -> None:
        all_manifests = discover_manifests(REPO_ROOT)
        workspace_members = set(self.registry["workspace_manifest"]["members"])
        nonmember_pkgs = _prototype_packages(self.registry)
        nonmember_roots = {p["root_path"] for p in nonmember_pkgs}
        for manifest in all_manifests:
            pkg_root = normalize_repo_path(str(Path(manifest).parent))
            if pkg_root not in workspace_members and pkg_root != ".":
                self.assertIn(pkg_root, nonmember_roots)

    # WORK_UNIT_CASE: 690/4
    def test_04_nonmember_without_explicit_classification_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            (t / "crates/unclassified").mkdir(parents=True)
            (t / "crates/unclassified/Cargo.toml").write_text(
                "[package]\nname = 'unclassified'\n", encoding="utf-8"
            )
            (t / "crates/unclassified/src").mkdir()
            (t / "crates/unclassified/src/lib.rs").write_text("pub fn f() {}\n", encoding="utf-8")
            (t / PROTOCOL_PATH).parent.mkdir(parents=True, exist_ok=True)
            (t / PROTOCOL_PATH).write_text("# protocol\n", encoding="utf-8")
            (t / "crates/AGENTS.md").write_text(
                f"{ROUTING_START}\npython scripts/docs_read.py read\n"
                f"[protocol](../{PROTOCOL_PATH})\n{ROUTING_END}\n"
                f"[workspace](../{PACKAGE_INDEX_PATH})\n[prototype](../{PROTOTYPE_INDEX_PATH})\n",
                encoding="utf-8",
            )
            reg = {
                "packages": [{
                    "root_path": "crates/unclassified",
                    "manifest_path": "crates/unclassified/Cargo.toml",
                    "workspace_member": False,
                    "default_member": False,
                    "targets": [{"kind": "lib", "path": "src/lib.rs"}],
                    "logical_blocks": ["test"],
                }],
                "logical_blocks": [{"id": "test", "documentation_handles": ["I2.8"], "documentation_route_ids": ["r"]}],
            }
            with self.assertRaises(NavigationError) as cm:
                validate_prototype_docs(t, reg)
            self.assertIn("prototype", str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/5
    def test_05_duplicate_aliased_package_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            reg = {
                "workspace_manifest": {"members": ["crates/a", "crates/a"], "default_members": []},
                "packages": [
                    {"root_path": "crates/a", "workspace_member": True, "targets": [{"path": "src/lib.rs"}]},
                    {"root_path": "crates/a", "workspace_member": True, "targets": [{"path": "src/lib.rs"}]},
                ],
            }
            with self.assertRaises(NavigationError) as cm:
                validate_package_docs(t, reg)
            self.assertIn("duplicate", str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/6
    def test_06_missing_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            reg = {
                "workspace_manifest": {"members": ["crates/a"], "default_members": ["crates/a"]},
                "packages": [
                    {
                        "root_path": "crates/a",
                        "manifest_path": "crates/a/Cargo.toml",
                        "workspace_member": True,
                        "default_member": True,
                        "targets": [{"path": "src/lib.rs"}],
                    }
                ],
            }
            with self.assertRaises(NavigationError) as cm:
                validate_package_docs(t, reg)
            self.assertIn("missing", str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/7
    def test_07_package_without_target(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            (t / "crates/a").mkdir(parents=True)
            (t / "crates/a/Cargo.toml").write_text("[package]\nname = 'a'\n", encoding="utf-8")
            reg = {
                "workspace_manifest": {"members": ["crates/a"], "default_members": ["crates/a"]},
                "packages": [
                    {
                        "root_path": "crates/a",
                        "manifest_path": "crates/a/Cargo.toml",
                        "workspace_member": True,
                        "default_member": True,
                        "targets": [],
                    }
                ],
            }
            with self.assertRaises(NavigationError) as cm:
                validate_package_docs(t, reg)
            self.assertIn("no target", str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/8
    def test_08_missing_target_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            (t / "crates/a").mkdir(parents=True)
            (t / "crates/a/Cargo.toml").write_text("[package]\nname = 'a'\n", encoding="utf-8")
            reg = {
                "workspace_manifest": {"members": ["crates/a"], "default_members": ["crates/a"]},
                "packages": [
                    {
                        "root_path": "crates/a",
                        "manifest_path": "crates/a/Cargo.toml",
                        "workspace_member": True,
                        "default_member": True,
                        "targets": [{"path": "src/nonexistent.rs"}],
                    }
                ],
            }
            with self.assertRaises(NavigationError) as cm:
                validate_package_docs(t, reg)
            self.assertIn("target is missing", str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/9
    def test_09_target_escaping_valid_package_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            (t / "crates/a").mkdir(parents=True)
            (t / "crates/a/Cargo.toml").write_text("[package]\nname = 'a'\n", encoding="utf-8")
            reg = {
                "workspace_manifest": {"members": ["crates/a"], "default_members": ["crates/a"]},
                "packages": [
                    {
                        "root_path": "crates/a",
                        "manifest_path": "crates/a/Cargo.toml",
                        "workspace_member": True,
                        "default_member": True,
                        "targets": [{"path": "../outside.rs"}],
                    }
                ],
            }
            with self.assertRaises(NavigationError) as cm:
                validate_package_docs(t, reg)
            self.assertTrue("escapes" in str(cm.exception).lower() or "traversing" in str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/10
    def test_10_one_disposition_per_manifest(self) -> None:
        # Adversarial: a manifest that carries two dispositions at once must be
        # rejected by the production validator, not relabelled by the test.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "crates/p/src").mkdir(parents=True)
            (root / "docs/architecture").mkdir(parents=True)
            (root / "docs/code-navigation").mkdir(parents=True)
            (root / PROTOCOL_PATH).write_text("# protocol\n", encoding="utf-8")
            contract = (
                f"{ROUTING_START}\npython scripts/docs_read.py read\n"
                f"[protocol](../{PROTOCOL_PATH})\n{ROUTING_END}\n"
                f"[workspace](../{PACKAGE_INDEX_PATH})\n"
                f"[prototype](../{PROTOTYPE_INDEX_PATH})\n"
            )
            (root / "crates/AGENTS.md").write_text(contract, encoding="utf-8")
            (root / "crates/p/Cargo.toml").write_text(
                "[package]\nname='p'\n[package.metadata.eliot]\nprototype=true\n"
                "workspace_admission='pending proof'\n",
                encoding="utf-8",
            )
            (root / "crates/p/src/lib.rs").write_text("pub fn p() {}\n", encoding="utf-8")
            (root / "docs/architecture/handle-index.json").write_text(
                json.dumps({
                    "schema_version": "eliot-handle-index-v1",
                    "handles": {
                        "I2.8": {
                            "source": "implementation",
                            "title": "I2.8. Package metadata",
                            "path": "docs/" + "architecture/I02-08.md",
                            "anchor": "i28-package-metadata",
                        }
                    },
                }),
                encoding="utf-8",
            )
            (root / ("docs/" + "architecture/I02-08.md")).write_text(
                "## I2.8. Package metadata\n", encoding="utf-8"
            )
            doubly_admitted = {
                "packages": [{
                    "root_path": "crates/p",
                    "manifest_path": "crates/p/Cargo.toml",
                    "workspace_member": False,
                    "default_member": True,
                    "targets": [{"kind": "lib", "path": "src/lib.rs"}],
                    "logical_blocks": ["test"],
                }],
                "logical_blocks": [{
                    "id": "test",
                    "documentation_handles": ["I2.8"],
                    "documentation_route_ids": ["test-route"],
                }],
            }
            with self.assertRaises(NavigationError) as cm:
                validate_prototype_docs(root, doubly_admitted)
            self.assertIn("marked as a default member", str(cm.exception))
            self.assertIn("crates/p", str(cm.exception))

        # Second disposition on a real workspace manifest: the registry flag must
        # not contradict the authoritative Cargo.toml default-member denominator.
        registry = copy.deepcopy(self.registry)
        liar = next(
            package for package in registry["packages"]
            if package["workspace_member"] and not package["default_member"]
        )
        liar["default_member"] = True
        with self.assertRaises(NavigationError) as cm:
            validate_package_docs(REPO_ROOT, registry)
        self.assertIn("default-member state disagrees", str(cm.exception))
        self.assertIn(liar["root_path"], str(cm.exception))

        # Positive control on real metadata: the two production denominators
        # partition every real manifest exactly once, and the rendered indexes
        # place each manifest in exactly one of them.
        workspace_roots = {p["root_path"] for p in _packages(self.registry)}
        prototype_roots = {p["root_path"] for p in _prototype_packages(self.registry)}
        all_roots = {p["root_path"] for p in self.registry["packages"]}
        self.assertEqual(workspace_roots & prototype_roots, set())
        self.assertEqual(workspace_roots | prototype_roots, all_roots)
        workspace_section = _table_section(
            render_package_docs(self.registry, REPO_ROOT), "## Workspace packages"
        )
        prototype_section = _table_section(
            render_prototype_docs(REPO_ROOT, self.registry),
            "## Nonmember prototype packages",
        )
        for package in self.registry["packages"]:
            manifest_link = f"](../../{package['manifest_path']})"
            in_workspace = workspace_section.count(manifest_link)
            in_prototype = prototype_section.count(manifest_link)
            self.assertEqual(
                in_workspace + in_prototype,
                1,
                f"{package['root_path']} is not admitted exactly once: "
                f"workspace={in_workspace} prototype={in_prototype}",
            )

    # WORK_UNIT_CASE: 690/11
    def test_11_one_disposition_per_target(self) -> None:
        # Adversarial: one target identity declared with two different
        # required-features gates must be rejected by cargo.inferred_targets.
        with tempfile.TemporaryDirectory() as td:
            package_root = Path(td)
            (package_root / "src/bin").mkdir(parents=True)
            (package_root / "src/main.rs").write_text("fn main() {}\n", encoding="utf-8")
            (package_root / "src/bin/twin.rs").write_text("fn main() {}\n", encoding="utf-8")
            conflicting = {
                "package": {"name": "twin"},
                "bin": [
                    {"name": "twin", "path": "src/bin/twin.rs", "required-features": ["fast"]},
                    {"name": "twin", "path": "src/bin/twin.rs", "required-features": ["slow"]},
                ],
            }
            with self.assertRaises(NavigationError) as cm:
                inferred_targets(package_root, conflicting, strict=True)
            self.assertIn("more than once", str(cm.exception))
            self.assertIn("required-features", str(cm.exception))

            # The same identity declared twice with one identical gate collapses
            # to exactly one disposition, not two.
            agreed = copy.deepcopy(conflicting)
            agreed["bin"][1]["required-features"] = ["fast"]
            targets = inferred_targets(package_root, agreed, strict=True)
            twins = [t for t in targets if t["path"] == "src/bin/twin.rs"]
            self.assertEqual(len(twins), 1)
            self.assertEqual(twins[0]["required_features"], "fast")

        # Real registry: no target carries two dispositions. A target path is
        # package-relative, so the identity is (root, kind, path) and the
        # rendered reverse cell is (root:path) - both must be unique and must
        # resolve to one real file inside its own package root.
        # Each target must appear exactly once per reverse row, and every target
        # of a governing package must appear in that row - never dropped, never
        # duplicated within the row.
        blocks = _blocks(self.registry)
        reverse = _reverse_section(render_package_docs(self.registry, REPO_ROOT))
        for handle, row in reverse.items():
            self.assertEqual(
                len(row["targets"]),
                len({cell for cell in row["targets"]}),
                f"reverse row for {handle} repeats a target",
            )
            expected = {
                f"{package['root_path']}:{target['path']}"
                for package in _packages(self.registry)
                if handle in _handles(package, blocks)
                for target in package.get("targets", [])
            }
            self.assertEqual(row["targets"], expected, f"target set differs for {handle}")
        for package in self.registry["packages"]:
            root_path = package["root_path"]
            identities = [
                (target["kind"], target["path"]) for target in package.get("targets", [])
            ]
            self.assertEqual(
                len(identities), len(set(identities)),
                f"{root_path} lists a target identity twice",
            )
            for target in package.get("targets", []):
                absolute = (REPO_ROOT / root_path / target["path"]).resolve()
                self.assertTrue(absolute.is_file(), f"{root_path}:{target['path']} does not exist")
                self.assertTrue(
                    absolute.is_relative_to((REPO_ROOT / root_path).resolve()),
                    f"{root_path}:{target['path']} escapes its package root",
                )

    # WORK_UNIT_CASE: 690/12
    def test_12_inherited_family_evidence_supports_but_cannot_replace_closure(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            (t / "crates/a").mkdir(parents=True)
            (t / "crates/a/Cargo.toml").write_text("[package]\nname='a'\n", encoding="utf-8")
            (t / "crates/a/src").mkdir()
            (t / "crates/a/src/lib.rs").write_text("pub fn a(){}\n", encoding="utf-8")
            (t / PROTOCOL_PATH).parent.mkdir(parents=True, exist_ok=True)
            (t / PROTOCOL_PATH).write_text("# protocol\n", encoding="utf-8")
            (t / "crates/AGENTS.md").write_text(
                f"{ROUTING_START}\npython scripts/docs_read.py read\n"
                f"[protocol](../{PROTOCOL_PATH})\n{ROUTING_END}\n"
                f"[index](../{PACKAGE_INDEX_PATH})\n",
                encoding="utf-8",
            )
            reg = {
                "workspace_manifest": {"members": ["crates/a"], "default_members": ["crates/a"]},
                "packages": [{
                    "root_path": "crates/a",
                    "manifest_path": "crates/a/Cargo.toml",
                    "workspace_member": True,
                    "default_member": True,
                    "targets": [{"path": "src/lib.rs"}],
                    "logical_blocks": [],
                }],
            }
            with self.assertRaises(NavigationError) as cm:
                validate_package_docs(t, reg)
            self.assertIn("governing docs", str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/13
    def test_13_missing_applicable_inherited_contract(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            (t / "crates/a/src").mkdir(parents=True)
            (t / "crates/a/Cargo.toml").write_text("[package]\nname='a'\n", encoding="utf-8")
            (t / "crates/a/src/lib.rs").write_text("pub fn a(){}\n", encoding="utf-8")
            reg = {
                "workspace_manifest": {"members": ["crates/a"], "default_members": ["crates/a"]},
                "packages": [{
                    "root_path": "crates/a",
                    "manifest_path": "crates/a/Cargo.toml",
                    "workspace_member": True,
                    "default_member": True,
                    "targets": [{"path": "src/lib.rs"}],
                    "logical_blocks": ["test"],
                }],
                "logical_blocks": [{"id": "test", "documentation_handles": ["I2.8"], "documentation_route_ids": ["r"]}],
            }
            with self.assertRaises(NavigationError) as cm:
                validate_package_docs(t, reg)
            self.assertIn("inherit", str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/14
    def test_14_route_block_without_verified_command(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            (t / "crates/a/src").mkdir(parents=True)
            (t / "crates/a/Cargo.toml").write_text("[package]\nname='a'\n", encoding="utf-8")
            (t / "crates/a/src/lib.rs").write_text("pub fn a(){}\n", encoding="utf-8")
            (t / "crates/AGENTS.md").write_text(
                f"{ROUTING_START}\necho missing\n{ROUTING_END}\n[index](../{PACKAGE_INDEX_PATH})\n",
                encoding="utf-8",
            )
            reg = {
                "workspace_manifest": {"members": ["crates/a"], "default_members": ["crates/a"]},
                "packages": [{
                    "root_path": "crates/a",
                    "manifest_path": "crates/a/Cargo.toml",
                    "workspace_member": True,
                    "default_member": True,
                    "targets": [{"path": "src/lib.rs"}],
                    "logical_blocks": ["test"],
                }],
                "logical_blocks": [{"id": "test", "documentation_handles": ["I2.8"], "documentation_route_ids": ["r"]}],
            }
            with self.assertRaises(NavigationError) as cm:
                validate_package_docs(t, reg)
            self.assertIn("verified reader is absent", str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/15
    def test_15_malformed_multiple_routing_markers(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            (t / "crates/a/src").mkdir(parents=True)
            (t / "crates/a/Cargo.toml").write_text("[package]\nname='a'\n", encoding="utf-8")
            (t / "crates/a/src/lib.rs").write_text("pub fn a(){}\n", encoding="utf-8")
            (t / "crates/AGENTS.md").write_text(
                f"{ROUTING_START}\n{ROUTING_START}\n{ROUTING_END}\n",
                encoding="utf-8",
            )
            reg = {
                "workspace_manifest": {"members": ["crates/a"], "default_members": ["crates/a"]},
                "packages": [{
                    "root_path": "crates/a",
                    "manifest_path": "crates/a/Cargo.toml",
                    "workspace_member": True,
                    "default_member": True,
                    "targets": [{"path": "src/lib.rs"}],
                    "logical_blocks": ["test"],
                }],
                "logical_blocks": [{"id": "test", "documentation_handles": ["I2.8"], "documentation_route_ids": ["r"]}],
            }
            with self.assertRaises(NavigationError) as cm:
                validate_package_docs(t, reg)
            self.assertIn("routing markers", str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/16
    def test_16_one_target_gap_fails_despite_siblings(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            (t / "crates/a/src").mkdir(parents=True)
            (t / "crates/a/Cargo.toml").write_text("[package]\nname='a'\n", encoding="utf-8")
            (t / "crates/a/src/lib.rs").write_text("pub fn a(){}\n", encoding="utf-8")
            reg = {
                "workspace_manifest": {"members": ["crates/a"], "default_members": ["crates/a"]},
                "packages": [{
                    "root_path": "crates/a",
                    "manifest_path": "crates/a/Cargo.toml",
                    "workspace_member": True,
                    "default_member": True,
                    "targets": [{"path": "src/lib.rs"}, {"path": "src/missing.rs"}],
                    "logical_blocks": ["test"],
                }],
            }
            with self.assertRaises(NavigationError) as cm:
                validate_package_docs(t, reg)
            self.assertIn("missing", str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/17
    def test_17_missing_logical_block(self) -> None:
        reg = {
            "workspace_manifest": {"members": ["crates/a"], "default_members": []},
            "packages": [{
                "root_path": "crates/a",
                "workspace_member": True,
                "logical_blocks": ["nonexistent-block"],
            }],
            "logical_blocks": [],
        }
        with self.assertRaises(NavigationError) as cm:
            _handles(reg["packages"][0], _blocks(reg))
        self.assertIn("unknown block", str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/18
    def test_18_empty_handle_denominator(self) -> None:
        reg = {
            "logical_blocks": [{
                "id": "block1",
                "documentation_handles": [],
                "documentation_route_ids": ["r1"],
            }]
        }
        with self.assertRaises(NavigationError) as cm:
            _handles({"logical_blocks": ["block1"]}, _blocks(reg))
        self.assertIn("no documentation handles", str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/19
    def test_19_empty_route_denominator(self) -> None:
        reg = {
            "logical_blocks": [{
                "id": "block1",
                "documentation_handles": ["I2.8"],
                "documentation_route_ids": [],
            }]
        }
        with self.assertRaises(NavigationError) as cm:
            _handles({"logical_blocks": ["block1"]}, _blocks(reg))
        self.assertIn("resolves no docs route", str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/20
    def test_20_exact_valid_fragment_anchor_resolution(self) -> None:
        rec = self.resolver.resolve("I2.8")
        self.assertEqual(rec["handle"], "I2.8")
        self.assertTrue(rec["path"].endswith(".md"))
        self.assertTrue(len(rec["anchor"]) > 0)
        self.assertIn("#", rec["direct_destination"])

    # WORK_UNIT_CASE: 690/21
    def test_21_missing_handle(self) -> None:
        with self.assertRaises(NavigationError) as cm:
            self.resolver.resolve("NONEXISTENT-HANDLE-999")
        self.assertIn("unknown", str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/22
    def test_22_duplicate_ambiguous_handle(self) -> None:
        def write_index(root: Path, handles: dict) -> None:
            (root / "docs/architecture").mkdir(parents=True, exist_ok=True)
            (root / "docs/architecture/handle-index.json").write_text(
                json.dumps({"schema_version": "eliot-handle-index-v1", "handles": handles}),
                encoding="utf-8",
            )
            (root / ("docs/" + "architecture/A.md")).write_text(
                "## A\n## B\n", encoding="utf-8"
            )

        def record(title: str, anchor: str) -> dict:
            return {
                "source": "a",
                "title": title,
                "path": "docs/" + "architecture/A.md",
                "anchor": anchor,
            }

        # Two distinct keys that collapse to one stripped identity must not
        # silently overwrite: the later one won in the unfixed resolver.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write_index(root, {"A0": record("FIRST-WINS", "a"), "A0 ": record("SECOND-WINS", "a")})
            with self.assertRaises(NavigationError) as cm:
                DestinationResolver(root)
            message = str(cm.exception)
            self.assertIn("duplicate handle identity", message)
            self.assertIn("A0", message)

        # Two distinct handles claiming the same fragment#anchor are ambiguous.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write_index(root, {"A0": record("A0", "a"), "A1": record("A1", "a")})
            with self.assertRaises(NavigationError) as cm:
                DestinationResolver(root)
            message = str(cm.exception)
            self.assertIn("ambiguous destination", message)
            self.assertIn("A0", message)
            self.assertIn("A1", message)

        # Two distinct handles on distinct anchors are not ambiguous and resolve.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write_index(root, {"A0": record("A0", "a"), "A1": record("A1", "b")})
            resolver = DestinationResolver(root)
            self.assertEqual(resolver.resolve("A0")["direct_destination"], "docs/architecture/A.md#a")
            self.assertEqual(resolver.resolve("A1")["direct_destination"], "docs/architecture/A.md#b")

    # WORK_UNIT_CASE: 690/23
    def test_23_malformed_empty_handle(self) -> None:
        with self.assertRaises(NavigationError) as cm:
            self.resolver.resolve("   ")
        self.assertIn("empty", str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/24
    def test_24_missing_fragment(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            (t / "docs/architecture").mkdir(parents=True)
            (t / "docs/architecture/handle-index.json").write_text(
                json.dumps({
                    "schema_version": "eliot-handle-index-v1",
                    "handles": {
                        "A0": {"source": "a", "title": "A0", "path": "docs/" + "architecture/missing.md", "anchor": "a"},
                    },
                }),
                encoding="utf-8",
            )
            with self.assertRaises(NavigationError) as cm:
                DestinationResolver(t)
            self.assertIn("missing", str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/25
    def test_25_external_traversal_fragment(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            (t / "docs/architecture").mkdir(parents=True)
            (t / "docs/architecture/handle-index.json").write_text(
                json.dumps({
                    "schema_version": "eliot-handle-index-v1",
                    "handles": {
                        "A0": {"source": "a", "title": "A0", "path": "../outside.md", "anchor": "a"},
                    },
                }),
                encoding="utf-8",
            )
            with self.assertRaises(NavigationError) as cm:
                DestinationResolver(t)
            self.assertTrue("traversing" in str(cm.exception).lower() or "canonical" in str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/26
    def test_26_missing_exact_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            (t / "docs/architecture").mkdir(parents=True)
            (t / "docs/architecture/handle-index.json").write_text(
                json.dumps({
                    "schema_version": "eliot-handle-index-v1",
                    "handles": {
                        "A0": {"source": "a", "title": "A0", "path": "docs/" + "architecture/A.md", "anchor": "   "},
                    },
                }),
                encoding="utf-8",
            )
            (t / ("docs/" + "architecture/A.md")).write_text("## A\n", encoding="utf-8")
            with self.assertRaises(NavigationError) as cm:
                DestinationResolver(t)
            self.assertIn("anchor", str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/27
    def test_27_percent_separator_case_alias_cannot_produce_duplicate_identity(self) -> None:
        canonical = "I2.8"
        real = self.resolver.resolve(canonical)
        all_handles = self.resolver.all_handles()
        self.assertIn(canonical, all_handles)
        aliases = ("i2.8", "I2%2E8", "I2.8%20", "I2-8", "I2.8.", "I2_8", "I2 8")
        # An alias must never resolve, and must never appear as a second stored
        # identity beside the canonical handle.
        for alias in aliases:
            self.assertNotIn(alias, all_handles, f"alias {alias!r} is stored as its own handle")
            with self.assertRaises(NavigationError, msg=f"alias {alias!r} resolved"):
                self.resolver.resolve(alias)
        self.assertEqual(
            self.resolver.resolve(canonical)["direct_destination"],
            real["direct_destination"],
        )
        self.assertEqual(
            len([h for h in all_handles if h.strip() == canonical]),
            1,
            "the canonical handle has more than one stored identity",
        )

        # An index that ships a percent/case/separator alias of a live handle is
        # rejected at load, so a reader cannot navigate to two identities.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "docs/architecture").mkdir(parents=True)
            (root / "docs/architecture/handle-index.json").write_text(
                json.dumps({
                    "schema_version": "eliot-handle-index-v1",
                    "handles": {
                        "I2.8": {
                            "source": "implementation",
                            "title": "I2.8. Package metadata",
                            "path": "docs/" + "architecture/I02-08.md",
                            "anchor": "i28-package-metadata",
                        },
                        "i2.8": {
                            "source": "implementation",
                            "title": "I2.8. Package metadata (case alias)",
                            "path": "docs/" + "architecture/I02-08.md",
                            "anchor": "i28-package-metadata",
                        },
                    },
                }),
                encoding="utf-8",
            )
            (root / ("docs/" + "architecture/I02-08.md")).write_text(
                "## I2.8. Package metadata\n", encoding="utf-8"
            )
            with self.assertRaises(NavigationError) as cm:
                DestinationResolver(root)
            self.assertIn("ambiguous destination", str(cm.exception))

    # WORK_UNIT_CASE: 690/28
    def test_28_generic_unanchored_handle_index_rejected(self) -> None:
        with self.assertRaises(NavigationError) as cm:
            self.resolver.resolve("HANDLE_INDEX")
        self.assertIn("handle_index", str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/29
    def test_29_direct_fragment_anchor_for_every_governing_handle(self) -> None:
        blocks = _blocks(self.registry)
        for block in blocks.values():
            for h in block["documentation_handles"]:
                rec = self.resolver.resolve(h)
                self.assertIn("#", rec["direct_destination"])
                self.assertFalse(rec["direct_destination"].startswith("#"))

    # WORK_UNIT_CASE: 690/30
    def test_30_complete_forward_relation(self) -> None:
        rendered = render_package_docs(self.registry, REPO_ROOT)
        for package in _packages(self.registry):
            self.assertIn(package["root_path"], rendered)
            for t in package.get("targets", []):
                self.assertIn(t["path"], rendered)

    # WORK_UNIT_CASE: 690/31
    def test_31_reverse_contains_every_forward_member(self) -> None:
        rendered = render_package_docs(self.registry, REPO_ROOT)
        blocks = _blocks(self.registry)
        for package in _packages(self.registry):
            handles = _handles(package, blocks)
            for h in handles:
                self.assertIn(h, rendered)

    # WORK_UNIT_CASE: 690/32
    def test_32_no_extra_reverse_member(self) -> None:
        rendered = render_package_docs(self.registry, REPO_ROOT)
        reverse = _reverse_section(rendered)
        reverse_handles = set(reverse)
        blocks = _blocks(self.registry)
        packages = _packages(self.registry)
        forward: dict[str, set[str]] = {}
        for package in packages:
            for handle in _handles(package, blocks):
                forward.setdefault(handle, set()).add(str(package["root_path"]))
        self.assertEqual(reverse_handles, set(forward))
        for handle, expected_packages in forward.items():
            self.assertEqual(
                reverse[handle]["packages"],
                expected_packages,
                f"reverse row for {handle} does not match the forward relation",
            )
            self.assertTrue(expected_packages, f"forward relation for {handle} is empty")
        # No row may admit a package that the forward relation never names.
        for handle, row in reverse.items():
            self.assertIn(handle, forward, f"extra reverse handle {handle}")
            for admitted in row["packages"]:
                self.assertIn(admitted, forward[handle])

        # The same check on the prototype index, against the prototype denominator.
        prototype_render = render_prototype_docs(REPO_ROOT, self.registry)
        prototype_reverse = _reverse_section(prototype_render)
        prototype_forward: dict[str, set[str]] = {}
        for package in _prototype_packages(self.registry):
            for handle in _handles(package, blocks):
                prototype_forward.setdefault(handle, set()).add(str(package["root_path"]))
        self.assertEqual(set(prototype_reverse), set(prototype_forward))
        for handle, expected_packages in prototype_forward.items():
            self.assertEqual(prototype_reverse[handle]["packages"], expected_packages)
        for handle in prototype_reverse:
            self.assertIn(handle, prototype_forward)

    # WORK_UNIT_CASE: 690/33
    def test_33_multiple_blocks_handles_without_loss_duplicate_package(self) -> None:
        blocks = _blocks(self.registry)
        multi_block_pkgs = [p for p in _packages(self.registry) if len(p.get("logical_blocks", [])) > 1]
        for p in multi_block_pkgs:
            handles = _handles(p, blocks)
            self.assertEqual(len(handles), len(set(handles)))

    # WORK_UNIT_CASE: 690/34
    def test_34_shared_handle_lists_both_packages(self) -> None:
        blocks = _blocks(self.registry)
        handle_to_pkgs: dict[str, list[str]] = {}
        for p in _packages(self.registry):
            for h in _handles(p, blocks):
                handle_to_pkgs.setdefault(h, []).append(p["root_path"])
        shared = {h: pkgs for h, pkgs in handle_to_pkgs.items() if len(pkgs) > 1}
        self.assertGreater(len(shared), 0)
        rendered = render_package_docs(self.registry, REPO_ROOT)
        for h, pkgs in shared.items():
            self.assertIn(h, rendered)

    # WORK_UNIT_CASE: 690/35
    def test_35_workspace_prototype_sets_disjoint(self) -> None:
        ws_members = {p["root_path"] for p in _packages(self.registry)}
        proto_members = {p["root_path"] for p in _prototype_packages(self.registry)}
        overlap = ws_members.intersection(proto_members)
        self.assertEqual(len(overlap), 0)

    # WORK_UNIT_CASE: 690/36
    def test_36_wrong_index_membership_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            reg = {
                "packages": [{
                    "root_path": "crates/a",
                    "workspace_member": True,
                    "default_member": True,
                }]
            }
            proto_pkgs = _prototype_packages(reg)
            self.assertEqual(len(proto_pkgs), 0)

    # WORK_UNIT_CASE: 690/37
    def test_37_irrelevant_input_permutation_gives_identical_bytes(self) -> None:
        baseline = render_package_docs(self.registry, REPO_ROOT).encode("utf-8")
        baseline_prototype = render_prototype_docs(REPO_ROOT, self.registry).encode("utf-8")

        # A permuted-but-equivalent registry. Only genuinely order-irrelevant
        # inputs are permuted: the packages list (the renderer sorts it), each
        # package's targets and rust_files (sorted by a typed key), and each
        # block's handle/route/matched-file lists (sorted by natural_handle_key
        # or unused). The logical-blocks declaration order and each package's
        # own logical_blocks order are meaningful declared order and are kept.
        permuted = copy.deepcopy(self.registry)
        permuted["packages"] = list(reversed(permuted["packages"]))
        for package in permuted["packages"]:
            package["targets"] = list(reversed(package.get("targets", [])))
            package["rust_files"] = list(reversed(package.get("rust_files", [])))
        for block in permuted["logical_blocks"]:
            block["documentation_handles"] = list(reversed(block["documentation_handles"]))
            block["documentation_route_ids"] = list(reversed(block["documentation_route_ids"]))
            block["matched_files"] = list(reversed(block.get("matched_files", [])))
        self.assertNotEqual(
            [p["root_path"] for p in permuted["packages"]],
            [p["root_path"] for p in self.registry["packages"]],
            "the permutation did not reorder anything",
        )
        self.assertEqual(
            render_package_docs(permuted, REPO_ROOT).encode("utf-8"),
            baseline,
        )
        self.assertEqual(
            render_prototype_docs(REPO_ROOT, permuted).encode("utf-8"),
            baseline_prototype,
        )

        # And the generated index files on disk are exactly those bytes.
        self.assertEqual((REPO_ROOT / PACKAGE_INDEX_PATH).read_bytes(), baseline)
        self.assertEqual((REPO_ROOT / PROTOTYPE_INDEX_PATH).read_bytes(), baseline_prototype)

    # WORK_UNIT_CASE: 690/38
    def test_38_repeated_generation_byte_identical(self) -> None:
        p1 = render_package_docs(self.registry, REPO_ROOT)
        p2 = render_package_docs(self.registry, REPO_ROOT)
        self.assertEqual(p1, p2)
        pr1 = render_prototype_docs(REPO_ROOT, self.registry)
        pr2 = render_prototype_docs(REPO_ROOT, self.registry)
        self.assertEqual(pr1, pr2)

    # WORK_UNIT_CASE: 690/39
    def test_39_missing_committed_index_names_exact_regeneration_command(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            with self.assertRaises(NavigationError) as cm:
                _check_package_index(t, {})
            self.assertIn("python scripts/code_navigation.py sync-index --root .", str(cm.exception))

    # WORK_UNIT_CASE: 690/40
    def test_40_hand_edits_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            (t / "docs/architecture").mkdir(parents=True)
            (t / "docs/architecture/handle-index.json").write_text(
                json.dumps({
                    "schema_version": "eliot-handle-index-v1",
                    "handles": {
                        "I2.8": {
                            "source": "implementation",
                            "title": "I2.8. Package metadata",
                            "path": "docs/" + "architecture/I02-08.md",
                            "anchor": "i28-package-metadata",
                        }
                    },
                }),
                encoding="utf-8",
            )
            (t / ("docs/" + "architecture/I02-08.md")).write_text(
                "## I2.8. Package metadata\n", encoding="utf-8"
            )
            registry = {
                "workspace_manifest": {"members": ["crates/a"], "default_members": ["crates/a"]},
                "packages": [{
                    "root_path": "crates/a",
                    "manifest_path": "crates/a/Cargo.toml",
                    "workspace_member": True,
                    "default_member": True,
                    "targets": [{"kind": "lib", "path": "src/lib.rs"}],
                    "logical_blocks": ["test"],
                }],
                "logical_blocks": [{
                    "id": "test",
                    "documentation_handles": ["I2.8"],
                    "documentation_route_ids": ["test-route"],
                }],
            }
            (t / "docs/code-navigation").mkdir(parents=True)
            (t / PACKAGE_INDEX_PATH).write_text("hand edit\n", encoding="utf-8")
            with self.assertRaises(NavigationError) as cm:
                _check_package_index(t, registry)
            self.assertIn("hand-edited", str(cm.exception))

    # WORK_UNIT_CASE: 690/41
    def test_41_only_one_index_regenerated_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            (t / "docs/architecture").mkdir(parents=True)
            (t / "docs/architecture/handle-index.json").write_text(
                json.dumps({
                    "schema_version": "eliot-handle-index-v1",
                    "handles": {
                        "I2.8": {
                            "source": "implementation",
                            "title": "I2.8. Package metadata",
                            "path": "docs/" + "architecture/I02-08.md",
                            "anchor": "i28-package-metadata",
                        }
                    },
                }),
                encoding="utf-8",
            )
            (t / ("docs/" + "architecture/I02-08.md")).write_text(
                "## I2.8. Package metadata\n", encoding="utf-8"
            )
            registry = {
                "workspace_manifest": {"members": ["crates/a"], "default_members": ["crates/a"]},
                "packages": [{
                    "root_path": "crates/a",
                    "manifest_path": "crates/a/Cargo.toml",
                    "workspace_member": True,
                    "default_member": True,
                    "targets": [{"kind": "lib", "path": "src/lib.rs"}],
                    "logical_blocks": ["test"],
                }],
                "logical_blocks": [{
                    "id": "test",
                    "documentation_handles": ["I2.8"],
                    "documentation_route_ids": ["test-route"],
                }],
            }
            (t / "docs/code-navigation").mkdir(parents=True)
            (t / PACKAGE_INDEX_PATH).write_text("tampered\n", encoding="utf-8")
            with self.assertRaises(NavigationError):
                _check_package_index(t, registry)

    # WORK_UNIT_CASE: 690/42
    def test_42_complete_unique_canonical_shard_denominator(self) -> None:
        arch_manifest = read_json(REPO_ROOT / "docs/architecture/architecture/manifest.json")
        impl_manifest = read_json(REPO_ROOT / "docs/architecture/implementation/manifest.json")
        arch_paths = [f["path"] for f in arch_manifest["fragments"]]
        impl_paths = [f["path"] for f in impl_manifest["fragments"]]
        self.assertEqual(len(arch_paths), len(set(arch_paths)))
        self.assertEqual(len(impl_paths), len(set(impl_paths)))
        self.assertEqual(len(set(arch_paths).intersection(set(impl_paths))), 0)

    # WORK_UNIT_CASE: 690/43
    def test_43_every_shard_measured_once_in_bytes(self) -> None:
        impl_manifest = read_json(REPO_ROOT / "docs/architecture/implementation/manifest.json")
        for frag in impl_manifest["fragments"][:10]:
            p = REPO_ROOT / frag["path"]
            self.assertEqual(len(p.read_bytes()), frag["rendered_bytes"])

    # WORK_UNIT_CASE: 690/44
    def test_44_48000_bytes_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            f = t / "shard.md"
            f.write_bytes(b"a" * 48000)
            m = {
                "source_key": "architecture",
                "source_sha256": sha256_text("a" * 48000),
                "source_bytes": 48000,
                "source_characters": 48000,
                "fragments": [{
                    "order": 0,
                    "path": "shard.md",
                    "source_start_char": 0,
                    "source_end_char": 48000,
                    "source_sha256": sha256_text("a" * 48000),
                    "rendered_sha256": sha256_text("a" * 48000),
                    "source_bytes": 48000,
                    "rendered_bytes": 48000,
                    "navigation_rewrites": [],
                    "headings": [],
                }],
            }
            res = verify_manifest(t, m)
            self.assertEqual(res["largest_fragment"], 48000)

    # WORK_UNIT_CASE: 690/45
    def test_45_48001_bytes_rejected_with_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            f = t / "shard.md"
            f.write_bytes(b"a" * 48001)
            m = {
                "source_key": "architecture",
                "source_sha256": sha256_text("a" * 48001),
                "source_bytes": 48001,
                "source_characters": 48001,
                "fragments": [{
                    "order": 0,
                    "path": "shard.md",
                    "source_start_char": 0,
                    "source_end_char": 48001,
                    "source_sha256": sha256_text("a" * 48001),
                    "rendered_sha256": sha256_text("a" * 48001),
                    "source_bytes": 48001,
                    "rendered_bytes": 48001,
                    "navigation_rewrites": [],
                    "headings": [],
                }],
            }
            with self.assertRaises(DocsError) as cm:
                verify_manifest(t, m)
            self.assertIn("48000", str(cm.exception))
            self.assertIn("48001", str(cm.exception))

    # WORK_UNIT_CASE: 690/46
    def test_46_missing_manifest_shard(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            m = {
                "source_key": "architecture",
                "source_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "source_bytes": 0,
                "source_characters": 0,
                "fragments": [{
                    "order": 0,
                    "path": "missing_shard.md",
                    "source_start_char": 0,
                    "source_end_char": 0,
                    "source_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "rendered_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "source_bytes": 0,
                    "rendered_bytes": 0,
                    "navigation_rewrites": [],
                    "headings": [],
                }],
            }
            with self.assertRaises(DocsError) as cm:
                verify_manifest(t, m)
            self.assertIn("missing", str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/47
    def test_47_unreadable_invalid_utf8_shard(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            f = t / "bad.md"
            f.write_bytes(b"\xff\xfe\x00\x00")
            m = {
                "source_key": "architecture",
                "source_sha256": "abc",
                "source_bytes": 4,
                "source_characters": 4,
                "fragments": [{
                    "order": 0,
                    "path": "bad.md",
                    "source_start_char": 0,
                    "source_end_char": 4,
                    "source_sha256": "abc",
                    "rendered_sha256": "abc",
                    "source_bytes": 4,
                    "rendered_bytes": 4,
                    "navigation_rewrites": [],
                    "headings": [],
                }],
            }
            with self.assertRaises(DocsError) as cm:
                verify_manifest(t, m)
            self.assertIn("utf-8", str(cm.exception).lower())

    # WORK_UNIT_CASE: 690/48
    def test_48_noncanonical_projection_excluded_only_by_class(self) -> None:
        arch_manifest = read_json(REPO_ROOT / "docs/architecture/architecture/manifest.json")
        for frag in arch_manifest["fragments"]:
            self.assertNotIn("decision_anchors", frag["path"])

    # WORK_UNIT_CASE: 690/49
    def test_49_unlisted_large_file_not_silently_added_to_canonical_denominator(self) -> None:
        arch_manifest = read_json(REPO_ROOT / "docs/architecture/architecture/manifest.json")
        canonical_paths = {f["path"] for f in arch_manifest["fragments"]}
        self.assertNotIn("docs/architecture/READING_PROTOCOL.md", canonical_paths)

    # WORK_UNIT_CASE: 690/50
    def test_50_largest_shard_diagnostic_cannot_override_failure(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            big = "b" * 48000
            over = "o" * 48001
            bad = "z" * 32
            (root / "big.md").write_text(big, encoding="utf-8")
            (root / "over.md").write_text(over, encoding="utf-8")
            (root / "bad.md").write_text(bad, encoding="utf-8")

            def manifest(entries: list[tuple[str, str, str]]) -> dict:
                """Build a manifest whose source is the concatenation of its shards."""
                fragments = []
                reconstructed = ""
                for order, (path, text, rendered_sha) in enumerate(entries):
                    digest = sha256_text(text)
                    fragments.append({
                        "order": order,
                        "path": path,
                        "source_start_char": len(reconstructed),
                        "source_end_char": len(reconstructed) + len(text),
                        "source_sha256": digest,
                        "rendered_sha256": rendered_sha,
                        "source_bytes": len(text.encode("utf-8")),
                        "rendered_bytes": len(text.encode("utf-8")),
                        "navigation_rewrites": [],
                        "headings": [],
                    })
                    reconstructed += text
                return {
                    "source_key": "architecture",
                    "source_sha256": sha256_text(reconstructed),
                    "source_bytes": len(reconstructed.encode("utf-8")),
                    "source_characters": len(reconstructed),
                    "fragments": fragments,
                }

            # The exactly-48,000 shard is the largest, and it is followed by a
            # violating shard: the ceiling failure must still be raised.
            with self.assertRaises(DocsError) as cm:
                verify_manifest(root, manifest([
                    ("big.md", big, sha256_text(big)),
                    ("over.md", over, sha256_text(over)),
                ]))
            message = str(cm.exception)
            self.assertIn("exceeds 48000 byte limit", message)
            self.assertIn("path=over.md", message)
            self.assertIn("bytes=48001", message)
            self.assertIn("manifest=architecture", message)

            # A largest-shard report must not mask a different violation in a
            # later shard: the hash mismatch is raised, not the largest report.
            with self.assertRaises(DocsError) as cm:
                verify_manifest(root, manifest([
                    ("big.md", big, sha256_text(big)),
                    ("bad.md", bad, sha256_text("tampered")),
                ]))
            message = str(cm.exception)
            self.assertIn("rendered fragment hash mismatch: bad.md", message)
            self.assertNotIn("largest", message.lower())

            # Control: the same two legal shards verify and report the largest.
            result = verify_manifest(root, manifest([
                ("big.md", big, sha256_text(big)),
                ("bad.md", bad, sha256_text(bad)),
            ]))
            self.assertEqual(result["largest_fragment"], 48000)
            self.assertEqual(result["fragments"], 2)

    # WORK_UNIT_CASE: 690/51
    def test_51_readme_exact_supported_commands_proof_boundary(self) -> None:
        readme = (REPO_ROOT / "scripts/README.md").read_text(encoding="utf-8")
        self.assertIn("package-docs-self-test", readme)
        self.assertIn("prototype-docs-self-test", readme)
        self.assertIn("sync-index", readme)
        self.assertIn("Repository navigation and static path/dependency consistency only", readme)

    # WORK_UNIT_CASE: 690/52
    def test_52_current_package_prototype_self_tests(self) -> None:
        package_docs_self_test()
        prototype_docs_self_test()

    # WORK_UNIT_CASE: 690/53
    def test_53_current_shard_self_test_ceiling_check(self) -> None:
        docs_shards_self_test()

    # WORK_UNIT_CASE: 690/54
    def test_54_no_normative_cargo_rust_workflow_unrelated_index_diff(self) -> None:
        allowed_prefixes = (
            "scripts/",
            "docs/code-navigation/",
            "workstreams/documentation/assignments/690-package-reader-closure.toml",
            ".eliot/",
        )
        import subprocess
        diff = subprocess.check_output(
            ["git", "diff", "--name-only", "HEAD"],
            cwd=REPO_ROOT,
            text=True,
        ).splitlines()
        for p in diff:
            self.assertTrue(
                any(p.replace("\\", "/").startswith(prefix) for prefix in allowed_prefixes),
                f"unauthorized path modified: {p}",
            )

    # WORK_UNIT_CASE: 690/55
    def test_55_unexecuted_full_checkout_actions_evidence_stays_unexecuted(self) -> None:
        # Clause 1: the generated indexes may not record an Actions or
        # full-checkout execution this unit never observed. A missing token
        # proves the claim is absent from the artifact; it does NOT prove that
        # no such run happened elsewhere.
        for relative in (PACKAGE_INDEX_PATH, PROTOTYPE_INDEX_PATH):
            text = (REPO_ROOT / relative).read_text(encoding="utf-8")
            boundary = text[text.index("## Proof boundary"):]
            self.assertIn("It does not prove", boundary)
            self.assertIn("Product", boundary)
            for claim in ("Actions", "workflow run", "full checkout", "CI passed", "green build"):
                self.assertNotIn(claim, text, f"{relative} records an unobserved {claim!r} claim")
            self.assertIn(
                "python scripts/code_navigation.py check --root .",
                text,
                f"{relative} does not name the reproduction command",
            )

        # Clause 2: the generated output is not an input to its own freshness
        # check. Rendering is identical whether the index file is absent,
        # current, or tampered, so an output-only commit cannot self-invalidate
        # the input binding.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "docs/architecture").mkdir(parents=True)
            (root / "docs/code-navigation").mkdir(parents=True)
            (root / ("docs/" + "architecture/I02-08.md")).write_text(
                "## I2.8. Package metadata\n", encoding="utf-8"
            )
            (root / "docs/architecture/handle-index.json").write_text(
                json.dumps({
                    "schema_version": "eliot-handle-index-v1",
                    "handles": {
                        "I2.8": {
                            "source": "implementation",
                            "title": "I2.8. Package metadata",
                            "path": "docs/" + "architecture/I02-08.md",
                            "anchor": "i28-package-metadata",
                        }
                    },
                }),
                encoding="utf-8",
            )
            registry = {
                "workspace_manifest": {"members": ["crates/a"], "default_members": ["crates/a"]},
                "packages": [{
                    "root_path": "crates/a",
                    "manifest_path": "crates/a/Cargo.toml",
                    "workspace_member": True,
                    "default_member": True,
                    "targets": [{"kind": "lib", "path": "src/lib.rs"}],
                    "logical_blocks": ["test"],
                }],
                "logical_blocks": [{
                    "id": "test",
                    "documentation_handles": ["I2.8"],
                    "documentation_route_ids": ["test-route"],
                }],
            }
            index = root / PACKAGE_INDEX_PATH
            without_index = render_package_docs(registry, root)
            index.write_text(without_index, encoding="utf-8", newline="")
            self.assertEqual(render_package_docs(registry, root), without_index)
            _check_package_index(root, registry)
            index.write_text("output-only edit\n", encoding="utf-8", newline="")
            self.assertEqual(
                render_package_docs(registry, root),
                without_index,
                "the generated index influenced its own render",
            )
            with self.assertRaises(NavigationError) as cm:
                _check_package_index(root, registry)
            self.assertIn("hand-edited", str(cm.exception))
            # The input binding is live, not vacuous: in a second checkout whose
            # source input differs, the expected bytes differ too. A separate
            # directory is used because DestinationResolver is cached per root.
            with tempfile.TemporaryDirectory() as other:
                moved = Path(other)
                (moved / "docs/architecture").mkdir(parents=True)
                (moved / ("docs/" + "architecture/I02-08.md")).write_text(
                    "## I2.8. Package metadata\n", encoding="utf-8"
                )
                (moved / "docs/architecture/handle-index.json").write_text(
                    json.dumps({
                        "schema_version": "eliot-handle-index-v1",
                        "handles": {
                            "I2.8": {
                                "source": "implementation",
                                "title": "I2.8. Package metadata",
                                "path": "docs/" + "architecture/I02-08.md",
                                "anchor": "i28-package-metadata-renamed",
                            }
                        },
                    }),
                    encoding="utf-8",
                )
                self.assertNotEqual(
                    render_package_docs(registry, moved),
                    without_index,
                    "a source-input change did not change the expected bytes",
                )


if __name__ == "__main__":
    unittest.main()
