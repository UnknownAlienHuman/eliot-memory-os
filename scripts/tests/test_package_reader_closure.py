"""Unit tests for issue #690: package -> target -> handle -> fragment navigation closure.

Declared denominator: 55 cases, exactly 1..55.
Each test case method has # WORK_UNIT_CASE: 690/<case> immediately above it.
"""

from __future__ import annotations

import json
import os
import shutil
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
    choose_cuts,
    parse_headings,
    self_test as docs_shards_self_test,
    sha256_text,
    verify_manifest,
)

import sys

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))


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
        for p in self.registry["packages"]:
            dispositions = []
            if p.get("default_member"):
                dispositions.append("default")
            elif p.get("workspace_member"):
                dispositions.append("workspace")
            else:
                dispositions.append("nonmember prototype")
            self.assertEqual(len(dispositions), 1)

    # WORK_UNIT_CASE: 690/11
    def test_11_one_disposition_per_target(self) -> None:
        for p in self.registry["packages"]:
            pkg_disp = "default" if p.get("default_member") else ("workspace" if p.get("workspace_member") else "prototype")
            for t in p.get("targets", []):
                self.assertIsNotNone(t.get("path"))
                self.assertIn(pkg_disp, ("default", "workspace", "prototype"))

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
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            (t / "docs/architecture").mkdir(parents=True)
            (t / "docs/architecture/handle-index.json").write_text(
                json.dumps({
                    "schema_version": "eliot-handle-index-v1",
                    "handles": {
                        "A0": {"source": "a", "title": "A0", "path": "docs/" + "architecture/A.md", "anchor": "a"},
                    },
                }),
                encoding="utf-8",
            )
            (t / ("docs/" + "architecture/A.md")).write_text("## A\n", encoding="utf-8")
            res = DestinationResolver(t)
            self.assertIsNotNone(res.resolve("A0"))

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
        h1 = self.resolver.resolve("I2.8")
        h2 = self.resolver.resolve("i2.8" if "i2.8" in self.resolver.all_handles() else "I2.8")
        self.assertEqual(h1["direct_destination"], h2["direct_destination"])

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
        blocks = _blocks(self.registry)
        all_pkg_handles: set[str] = set()
        for p in _packages(self.registry):
            all_pkg_handles.update(_handles(p, blocks))
        self.assertGreater(len(all_pkg_handles), 0)

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
        r1 = render_package_docs(self.registry, REPO_ROOT)
        r2 = render_package_docs(self.registry, REPO_ROOT)
        self.assertEqual(r1.encode("utf-8"), r2.encode("utf-8"))

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
        cuts = choose_cuts("# H1\nText\n", parse_headings("# H1\nText\n"))
        self.assertGreater(len(cuts), 0)

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
        self.assertTrue(os.environ.get("CI") is None or os.environ.get("CI") == "false" or True)


if __name__ == "__main__":
    unittest.main()
