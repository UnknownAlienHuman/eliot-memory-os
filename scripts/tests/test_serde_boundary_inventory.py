"""Deterministic serialized-boundary inventory tests (issue #929 [F-DENY-INV]).

Declared denominator: 24 cases, exactly 1..24. One substantive executable
Python test per case. Evidence is independently reviewed standalone
executed-pass output (unittest counts); no skip/empty/count-only substitute.

Base: b6632b7ea160f4a52d4cbea9873505b7b9ab19c1
Branch: work/929-serde-boundary-inventory
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "serde_boundary_inventory.py"
FIXTURE_DIR = ROOT / "scripts" / "testdata" / "serde-boundary-inventory"

_spec = importlib.util.spec_from_file_location("serde_boundary_inventory", SCRIPT)
assert _spec is not None and _spec.loader is not None
tool = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = tool
_spec.loader.exec_module(tool)

FROZEN_FIXTURES = [
    "derive_basic.rs",
    "derive_multiline.rs",
    "custom_remote.rs",
    "shapes.rs",
    "value_conversion.rs",
    "comments_strings.rs",
    "unsupported.rs",
    "test_scope.rs",
    "profile_bridge.json",
]

FIXTURE_RS = [n for n in FROZEN_FIXTURES if n.endswith(".rs")]

CARGO_TEMPLATE = """\
[workspace]
members = [{members}]
default-members = [{defaults}]
resolver = "3"

[workspace.package]
version = "0.1.0"
edition = "2024"
rust-version = "1.94"

[workspace.dependencies]
serde = {{ version = "1.0.228", features = ["derive"] }}
serde_json = {{ version = "1.0.150", features = ["float_roundtrip"] }}
"""


def _write_tree(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def _make_root(files: dict[str, str], members: list[str], defaults: list[str]) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="serde929-")).resolve()
    cargo = CARGO_TEMPLATE.format(
        members=", ".join('"%s"' % m for m in members),
        defaults=", ".join('"%s"' % d for d in defaults),
    )
    _write_tree(tmp, {"Cargo.toml": cargo, **files})
    return tmp


def _strict_derive(name: str, extra_attr: str = "") -> str:
    return (
        "use serde::Deserialize;\n"
        "#[derive(Debug, Deserialize)]\n"
        "#[serde(deny_unknown_fields)]\n" + extra_attr +
        "pub struct %s {\n    pub identity: String,\n    pub scope: String,\n}\n" % name
    )


def _fixture_rels() -> list[str]:
    return sorted("scripts/testdata/serde-boundary-inventory/%s" % n for n in FIXTURE_RS)


def _fixture_inventory() -> dict:
    return tool.build_inventory(ROOT, _fixture_rels())


def _by_file(inv: dict) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for row in inv["rows"]:
        grouped.setdefault(row["path"].rsplit("/", 1)[-1], []).append(row)
    return grouped


def _sync_and_load(tmp: Path) -> tuple[dict, str]:
    inventory, _payload = tool.sync_inventory(tmp)
    text = (tmp / tool.OWNED_TOML_REL).read_text(encoding="utf-8")
    return inventory, text


def _validate_text(tmp: Path, text: str) -> None:
    (tmp / tool.OWNED_TOML_REL).write_text(text, encoding="utf-8")
    doc = tool.load_artifact_toml(tmp)
    fresh = tool.build_inventory(tmp)
    tool.validate_against_artifact(tmp, fresh, doc)


class SerdeBoundaryInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        missing = [n for n in FROZEN_FIXTURES if not (FIXTURE_DIR / n).is_file()]
        assert not missing, "missing frozen fixtures: %r" % (missing,)

    # WORK_UNIT_CASE: 929/1
    def test_01_exact_release_roots_and_locked_target_feature_closure(self) -> None:
        meta = tool._load_workspace_meta(ROOT)
        self.assertTrue(meta["members"])
        self.assertTrue(meta["default_members"])
        self.assertTrue(set(meta["default_members"]) <= set(meta["members"]))
        self.assertEqual(meta["rust_version"], "1.94")
        self.assertIn("serde/derive", meta["serde_features"])
        self.assertIn("serde_json/float_roundtrip", meta["serde_features"])
        tmp = _make_root(
            {"bins/demo/src/main.rs": _strict_derive("Demo")},
            ["bins/demo"],
            ["bins/demo"],
        )
        inv = tool.build_inventory(tmp)
        denom = inv["denominator"]
        self.assertEqual(denom["release_roots"], ["bins/demo"])
        self.assertEqual(denom["packages"], ["bins/demo"])
        self.assertEqual(denom["targets"], [tool.FIXED_TARGET])
        self.assertIn("serde/derive", denom["features"])
        core = {k: denom[k] for k in ("release_roots", "packages", "targets", "features",
                                      "source_digest", "rule_digest", "owner_map_digest", "profile_digest")}
        recomputed = hashlib.sha256(
            json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        self.assertEqual(inv["header"]["denominator_digest"], recomputed)
        self.assertRegex(denom["source_digest"], r"\A[0-9a-f]{64}\Z")

    # WORK_UNIT_CASE: 929/2
    def test_02_ambiguous_release_authority_remains_incomplete(self) -> None:
        tmp = _make_root(
            {"orphan.rs": _strict_derive("Orphan")},
            [],
            [],
        )
        inv = tool.build_inventory(tmp, ["orphan.rs"])
        self.assertEqual(inv["header"]["denominator_status"], "INCOMPLETE")
        self.assertEqual(inv["header"]["coverage"], "INCOMPLETE")
        self.assertTrue(inv["header"]["ambiguous_reason"])
        inventory, _payload = tool.sync_inventory(tmp)
        self.assertEqual(inventory["header"]["denominator_status"], "INCOMPLETE")
        doc = tool.load_artifact_toml(tmp)
        fresh = tool.build_inventory(tmp)
        with self.assertRaises(tool.InventoryError) as ctx:
            tool.validate_against_artifact(tmp, fresh, doc)
        self.assertEqual(ctx.exception.code, "AMBIGUOUS_RELEASE")

    # WORK_UNIT_CASE: 929/3
    def test_03_build_reachability_differs_from_actual_boundary_evidence(self) -> None:
        tmp = _make_root(
            {
                "bins/demo/src/derive_only.rs": _strict_derive("DeriveOnly"),
                "bins/demo/src/callsite.rs": (
                    "pub fn read_it(text: &str) -> String {\n"
                    "    let v: serde_json::Value = serde_json::from_str(text).unwrap();\n"
                    "    v.to_string()\n}\n"
                ),
            },
            ["bins/demo"],
            ["bins/demo"],
        )
        inv = tool.build_inventory(tmp, ["bins/demo/src/derive_only.rs", "bins/demo/src/callsite.rs"])
        by_path = {r["path"]: r for r in inv["rows"] if r["kind"] != "decoder-callsite"}
        derive_row = next(r for r in inv["rows"] if r["type"] == "DeriveOnly")
        self.assertEqual(derive_row["build_class"], "workspace-member")
        self.assertEqual(derive_row["boundary_evidence"], "derive-only")
        call_rows = [r for r in inv["rows"] if r["kind"] == "decoder-callsite"]
        self.assertTrue(call_rows)
        for row in call_rows:
            self.assertEqual(row["boundary_evidence"], "actual-decoder-callsite")
        self.assertNotEqual(derive_row["boundary_evidence"], call_rows[0]["boundary_evidence"])
        self.assertEqual(derive_row["build_class"], call_rows[0]["build_class"])

    # WORK_UNIT_CASE: 929/4
    def test_04_multiline_derive_attribute_and_manual_implementation_discovery(self) -> None:
        grouped = _by_file(_fixture_inventory())
        rows = {r["type"]: r for r in grouped["derive_multiline.rs"]}
        self.assertEqual(set(rows), {"MultilineRecord", "ManualRecord", "ManualVisitor"})
        self.assertEqual(rows["MultilineRecord"]["kind"], "derive")
        self.assertTrue(rows["MultilineRecord"]["attributes"]["deny_unknown_fields"])
        self.assertLess(rows["MultilineRecord"]["span_start"], rows["MultilineRecord"]["span_end"])
        self.assertEqual(rows["ManualRecord"]["kind"], "manual-impl")
        self.assertEqual(rows["ManualVisitor"]["kind"], "visitor")
        self.assertTrue(rows["ManualRecord"]["evidence"].startswith("manual-deserialize-impl"))
        self.assertTrue(rows["ManualVisitor"]["evidence"].startswith("custom-visitor"))

    # WORK_UNIT_CASE: 929/5
    def test_05_custom_remote_with_and_deserialize_with_accounted(self) -> None:
        grouped = _by_file(_fixture_inventory())
        rows = {r["type"]: r for r in grouped["custom_remote.rs"]}
        self.assertEqual(set(rows), {"RemoteProxy", "WithHelper"})
        self.assertTrue(rows["RemoteProxy"]["attributes"]["remote"])
        self.assertIn("remote:", " ".join(rows["RemoteProxy"]["helpers"]))
        self.assertTrue(rows["WithHelper"]["attributes"]["with"])
        self.assertTrue(rows["WithHelper"]["attributes"]["deserialize_with"])
        self.assertTrue(rows["WithHelper"]["helpers"])
        self.assertFalse(rows["WithHelper"]["attributes"]["remote"])

    # WORK_UNIT_CASE: 929/6
    def test_06_tagged_untagged_flatten_alias_default_shapes_distinct(self) -> None:
        grouped = _by_file(_fixture_inventory())
        rows = {r["type"]: r for r in grouped["shapes.rs"]}
        self.assertEqual(set(rows), {"TaggedEnum", "UntaggedEnum", "InnerBlock", "FlattenHolder"})
        self.assertTrue(rows["TaggedEnum"]["attributes"]["tag"])
        self.assertFalse(rows["TaggedEnum"]["attributes"]["untagged"])
        self.assertTrue(rows["UntaggedEnum"]["attributes"]["untagged"])
        self.assertFalse(rows["UntaggedEnum"]["attributes"]["tag"])
        flat = rows["FlattenHolder"]["attributes"]
        self.assertTrue(flat["flatten"] and flat["alias"] and flat["default"])
        inner = rows["InnerBlock"]["attributes"]
        self.assertFalse(inner["flatten"] or inner["untagged"] or inner["alias"] or inner["default"])
        vectors = {
            tuple(sorted((k, str(v)) for k, v in r["attributes"].items() if k in ("tag", "untagged", "flatten", "alias", "default")))
            for r in rows.values()
        }
        self.assertEqual(len(vectors), 4)

    # WORK_UNIT_CASE: 929/7
    def test_07_generic_value_map_protected_conversion_found(self) -> None:
        grouped = _by_file(_fixture_inventory())
        rows = grouped["value_conversion.rs"]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["type"], "Protected")
        self.assertTrue(row["value_routing"])
        methods = {c["method"] for c in row["decoder_calls"]}
        self.assertEqual(methods, {"from_str", "from_value"})
        targets = {c["target"] for c in row["decoder_calls"]}
        self.assertEqual(targets, {"Protected"})
        self.assertEqual(len(row["decoder_calls"]), 3)
        call_lines = sorted(c["line"] for c in row["decoder_calls"])
        self.assertEqual(len(set(call_lines)), 3)

    # WORK_UNIT_CASE: 929/8
    def test_08_strings_comments_and_test_scope_not_production(self) -> None:
        grouped = _by_file(_fixture_inventory())
        noisy = grouped["comments_strings.rs"]
        self.assertEqual(len(noisy), 1)
        self.assertEqual(noisy[0]["type"], "RealAfterNoise")
        self.assertNotIn("Fake", " ".join(r["type"] for r in noisy))
        scoped = grouped["test_scope.rs"]
        self.assertEqual({r["type"] for r in scoped}, {"TestdataScopedDto", "TestOnlyDto"})
        for row in scoped:
            self.assertTrue(row["test_scope"])
            self.assertEqual(row["disposition"], "exact-internal")
            self.assertNotEqual(row["disposition"], "current-closed")

    # WORK_UNIT_CASE: 929/9
    def test_09_unsupported_syntax_macro_read_failure_never_empty_success(self) -> None:
        grouped = _by_file(_fixture_inventory())
        unsupported = grouped["unsupported.rs"]
        unknowns = [r for r in unsupported if r["disposition"] == "unknown"]
        self.assertGreaterEqual(len(unknowns), 1)
        self.assertGreaterEqual(len(unsupported), 2)
        self.assertTrue(all("unsupported-macro" in r["evidence"] for r in unknowns))
        inv = _fixture_inventory()
        self.assertGreater(inv["counts"]["unknown"], 0)
        self.assertEqual(inv["header"]["coverage"], "COMPLETE")
        tmp = _make_root(
            {"broken.rs": "/* unclosed block comment\nstruct Broken {\n"},
            ["bins/demo"],
            ["bins/demo"],
        )
        broken = tool.build_inventory(tmp, ["broken.rs"])
        self.assertEqual(len(broken["rows"]), 1)
        self.assertEqual(broken["rows"][0]["disposition"], "unknown")
        self.assertIn("malformed", broken["rows"][0]["evidence"])

    # WORK_UNIT_CASE: 929/10
    def test_10_one_row_disposition_per_candidate(self) -> None:
        inv = _fixture_inventory()
        ids = [r["id"] for r in inv["rows"]]
        self.assertEqual(len(ids), len(set(ids)))
        for row in inv["rows"]:
            self.assertIsInstance(row["disposition"], str)
            self.assertIn(row["disposition"], tool.DISPOSITIONS)
            self.assertRegex(str(row["digest"]), r"\A[0-9a-f]{64}\Z")
            self.assertRegex(str(row["span_digest"]), r"\A[0-9a-f]{64}\Z")
        self.assertEqual(inv["counts"]["candidate"], len(inv["rows"]))
        self.assertEqual(inv["counts"]["classified"], len(inv["rows"]))

    # WORK_UNIT_CASE: 929/11
    def test_11_duplicate_missing_extra_broad_exception_rejected(self) -> None:
        tmp = _make_root(
            {"bins/demo/src/only.rs": _strict_derive("Only")},
            ["bins/demo"],
            ["bins/demo"],
        )
        _inventory, text = _sync_and_load(tmp)
        blocks = text.split("[[candidates]]")
        self.assertGreaterEqual(len(blocks), 2)
        duplicated = text + "[[candidates]]" + blocks[1]
        with self.assertRaises(tool.InventoryError) as ctx:
            _validate_text(tmp, duplicated)
        self.assertEqual(ctx.exception.code, "DUPLICATE_ROW")
        removed = blocks[0] + "".join("[[candidates]]" + b for b in blocks[2:])
        with self.assertRaises(tool.InventoryError) as ctx:
            _validate_text(tmp, removed)
        self.assertEqual(ctx.exception.code, "EXTRA_ROWS")
        fabricated = text.replace(blocks[1].split("id = ")[1].split("\n")[0],
                                  '"bins/demo:bins/demo/src/only.rs:Fabricated:1"', 1)
        with self.assertRaises(tool.InventoryError) as ctx:
            _validate_text(tmp, fabricated)
        self.assertEqual(ctx.exception.code, "MISSING_ROWS")
        broad = text.replace(blocks[1].split("id = ")[1].split("\n")[0],
                             '"bins/demo:bins/demo/src/*.rs:Glob:1"', 1)
        with self.assertRaises(tool.InventoryError) as ctx:
            _validate_text(tmp, broad)
        self.assertEqual(ctx.exception.code, "BROAD_EXCEPTION")
        bad_disp_line = next(l for l in text.split("\n") if l.startswith("disposition = "))
        tampered = text.replace(bad_disp_line, 'disposition = "maybe"', 1)
        with self.assertRaises(tool.InventoryError) as ctx:
            _validate_text(tmp, tampered)
        self.assertEqual(ctx.exception.code, "UNKNOWN_DISPOSITION")

    # WORK_UNIT_CASE: 929/12
    def test_12_internal_exception_needs_exact_caller_evidence_and_invalidation(self) -> None:
        grouped = _by_file(_fixture_inventory())
        for row in grouped["test_scope.rs"]:
            self.assertEqual(row["disposition"], "exact-internal")
            self.assertTrue(row["callers"])
            self.assertTrue(row["invalidation"])
        tmp = _make_root(
            {"crates/foo/tests/dto.rs": _strict_derive("TestDto")},
            ["crates/foo"],
            ["crates/foo"],
        )
        _inventory, text = _sync_and_load(tmp)
        lines = text.split("\n")
        idx = next(i for i, l in enumerate(lines) if l.startswith("disposition = ") and '"exact-internal"' in l)
        caller_idx = next(i for i in range(idx, len(lines)) if lines[i].startswith("callers = "))
        lines[caller_idx] = "callers = []"
        with self.assertRaises(tool.InventoryError) as ctx:
            _validate_text(tmp, "\n".join(lines))
        self.assertEqual(ctx.exception.code, "INCOMPLETE_ROW")

    # WORK_UNIT_CASE: 929/13
    def test_13_specific_owner_row_retained_with_source_fixture_profile_evidence(self) -> None:
        self.assertTrue((ROOT / tool.MCP_SPECIFIC_OWNER_REL).is_file())
        tmp = _make_root(
            {"crates/eliot-types/src/mcp_contract.rs": _strict_derive("McpShape")},
            ["crates/eliot-types"],
            ["crates/eliot-types"],
        )
        inv = tool.build_inventory(tmp, ["crates/eliot-types/src/mcp_contract.rs"])
        self.assertEqual(len(inv["rows"]), 1)
        row = inv["rows"][0]
        self.assertEqual(row["disposition"], "specific-owner")
        self.assertEqual(row["owner"], "#692")
        self.assertEqual(row["repair_child"], "#933")
        self.assertTrue(row["file_digest"])
        expected = hashlib.sha256(
            (tmp / "crates/eliot-types/src/mcp_contract.rs").read_bytes()).hexdigest()
        self.assertEqual(row["file_digest"], expected)
        self.assertIn("not-applicable", row["limit_binding"])
        self.assertNotIn("999", row["limit_binding"])
        self.assertEqual(row["schema_class"], "current")

    # WORK_UNIT_CASE: 929/14
    def test_14_schema_profile_and_canonical_impact_kept_separate(self) -> None:
        tmp = _make_root(
            {
                "crates/eliot-store/src/canonical_record.rs": _strict_derive("WireRecord"),
                "bins/eliot-agent-bridge/src/main.rs": (
                    "use serde_json;\n"
                    "pub fn acquire(text: &str) -> String {\n"
                    '    let _r: Result<Request, _> = serde_json::from_str::<Request>(text);\n'
                    "    String::new()\n}\n"
                ),
                "bins/demo/src/strict.rs": _strict_derive("Strict"),
                "crates/eliot-types/src/ids.rs": _strict_derive("StrictIds"),
            },
            ["crates/eliot-store", "bins/eliot-agent-bridge", "bins/demo", "crates/eliot-types"],
            ["bins/demo"],
        )
        inv = tool.build_inventory(tmp, [
            "crates/eliot-store/src/canonical_record.rs",
            "bins/eliot-agent-bridge/src/main.rs",
            "bins/demo/src/strict.rs",
            "crates/eliot-types/src/ids.rs",
        ])
        by_id = {r["type"]: r for r in inv["rows"]}
        legacy_row = by_id["WireRecord"]
        self.assertEqual(legacy_row["schema_class"], "legacy")
        self.assertEqual(legacy_row["disposition"], "named-legacy")
        self.assertIn("not-applicable", legacy_row["limit_binding"])
        bridge_rows = [r for r in inv["rows"] if r["repair_child"] == "#977"]
        self.assertTrue(bridge_rows)
        for row in bridge_rows:
            self.assertTrue(row["limit_binding"].startswith("bridge-profile:"))
            self.assertEqual(row["schema_class"], "current")
        strict_row = by_id["StrictIds"]
        self.assertIn("not-applicable", strict_row["limit_binding"])
        self.assertIn("preserved", strict_row["canonical_impact"])
        self.assertNotEqual(legacy_row["limit_binding"], bridge_rows[0]["limit_binding"])
        self.assertNotEqual(legacy_row["schema_class"], bridge_rows[0]["schema_class"])

    # WORK_UNIT_CASE: 929/15
    def test_15_ready_for_repair_is_not_safe_and_blocked_never_blocks_inventory(self) -> None:
        tmp = _make_root(
            {
                "crates/eliot-types/src/memory.rs": (
                    "use serde::Deserialize;\n"
                    "#[derive(Debug, Deserialize)]\n"
                    "pub struct LooseMemory {\n    pub identity: String,\n}\n"
                ),
                "crates/surfaces/eliot-cli/src/edge.rs": (
                    "use serde::Deserialize;\n"
                    "#[derive(Debug, Deserialize)]\n"
                    "pub struct EdgeDto {\n    pub identity: String,\n}\n"
                ),
            },
            ["crates/eliot-types", "crates/surfaces/eliot-cli"],
            ["crates/eliot-types"],
        )
        inv = tool.build_inventory(tmp, [
            "crates/eliot-types/src/memory.rs",
            "crates/surfaces/eliot-cli/src/edge.rs",
        ])
        by_type = {r["type"]: r for r in inv["rows"]}
        loose = by_type["LooseMemory"]
        self.assertEqual(loose["disposition"], "needs-repair")
        self.assertEqual(loose["repair_readiness"], "READY_FOR_REPAIR")
        self.assertEqual(loose["safety"], "NOT_SAFE")
        edge = by_type["EdgeDto"]
        self.assertEqual(edge["repair_readiness"], "BLOCKED")
        self.assertIn("missing-owner", edge["blocked_reason"])
        self.assertEqual(edge["safety"], "NOT_SAFE")
        self.assertEqual(inv["header"]["coverage"], "COMPLETE")

    # WORK_UNIT_CASE: 929/16
    def test_16_ready_children_have_finite_allocations_and_bridge_preparation_precedes_parser(self) -> None:
        files: dict[str, str] = {}
        for child in tool.CHILDREN:
            rel = "%s/%s" % (child["base"], child["files"][0])
            if child["child"] == "#976":
                files[rel] = _strict_derive("LegacyWire")
            elif child["child"] == "#977":
                files[rel] = (
                    "pub fn acquire(text: &str) -> usize {\n"
                    '    let _r: Result<Request, _> = serde_json::from_str::<Request>(text);\n'
                    "    text.len()\n}\n"
                )
            elif rel == tool.MCP_SPECIFIC_OWNER_REL:
                files[rel] = _strict_derive("McpShape")
            else:
                files[rel] = _strict_derive("Strict%s" % child["family"].replace("-", ""))
        members = sorted({c["base"].split("/")[0] + "/" + c["base"].split("/")[1] for c in tool.CHILDREN})
        tmp = _make_root(files, members, [members[0]])
        inv = tool.build_inventory(tmp, sorted(files))
        allocs = {a["child"]: a for a in inv["allocations"]}
        self.assertEqual(set(allocs), {c["child"] for c in tool.CHILDREN})
        for child in tool.CHILDREN:
            alloc = allocs[child["child"]]
            for path in alloc["source_files"] + [t["path"] for t in alloc["test_files"]]:
                self.assertNotIn("*", path)
                self.assertRegex(path, r"\.(rs|json|toml)$")
            self.assertTrue(alloc["requirement_ids"])
            self.assertTrue(all(r.startswith("710/") for r in alloc["requirement_ids"]))
            self.assertTrue(set(tool.REQUIRED_CONTRACT_REFS) <= set(alloc["read_only_refs"]))
            self.assertLessEqual(alloc["stu_estimate"], alloc["stu_budget"])
            if child["child"] != "#977":
                self.assertEqual(alloc["readiness"], "READY_FOR_REPAIR")
        bridge = allocs["#977"]
        self.assertEqual(bridge["readiness"], "BLOCKED")
        self.assertTrue(bridge["preparation_before_parser"])
        self.assertIn("#977-preparation", bridge["prerequisites"])
        self.assertNotIn("#977", bridge["prerequisites"])
        self.assertNotIn("#977", bridge["write_after"])
        child_ids = set(allocs)
        self.assertNotIn("#977-preparation", child_ids)
        self.assertNotIn("#838", child_ids)

    # WORK_UNIT_CASE: 929/17
    def test_17_overlapping_writes_require_exact_serialization(self) -> None:
        overlapping = [
            {"child": "#930", "source_files": ["a/shared.rs"], "write_after": []},
            {"child": "#931", "source_files": ["a/shared.rs"], "write_after": []},
        ]
        with self.assertRaises(tool.InventoryError) as ctx:
            tool.check_write_serialization(overlapping)
        self.assertEqual(ctx.exception.code, "WRITE_COLLISION")
        serialized = [
            {"child": "#930", "source_files": ["a/shared.rs"], "write_after": []},
            {"child": "#931", "source_files": ["a/shared.rs"], "write_after": ["#930"]},
        ]
        tool.check_write_serialization(serialized)

    # WORK_UNIT_CASE: 929/18
    def test_18_read_only_shared_helper_is_not_a_write_collision(self) -> None:
        shared_reads = [
            {"child": "#930", "source_files": ["a/one.rs"],
             "read_only_refs": ["docs/architecture/I07-02-frame.md", "a/one.rs"],
             "write_after": []},
            {"child": "#931", "source_files": ["a/two.rs"],
             "read_only_refs": ["docs/architecture/I07-02-frame.md", "a/one.rs"],
             "write_after": []},
        ]
        tool.check_write_serialization(shared_reads)
        tmp = _make_root(
            {
                "crates/eliot-types/src/ids.rs": _strict_derive("IdsDto"),
                "crates/eliot-types/src/runtime.rs": _strict_derive("RuntimeDto"),
            },
            ["crates/eliot-types"],
            ["crates/eliot-types"],
        )
        inv = tool.build_inventory(tmp, [
            "crates/eliot-types/src/ids.rs",
            "crates/eliot-types/src/runtime.rs",
        ])
        tool.check_write_serialization(inv["allocations"])

    # WORK_UNIT_CASE: 929/19
    def test_19_unowned_remainder_or_lost_parent_blocks_family_readiness(self) -> None:
        tmp = _make_root(
            {
                "crates/eliot-types/src/ids.rs": _strict_derive("IdsDto"),
                "crates/surfaces/eliot-cli/src/edge.rs": (
                    "use serde::Deserialize;\n#[derive(Debug, Deserialize)]\n"
                    "pub struct EdgeDto {\n    pub identity: String,\n}\n"
                ),
            },
            ["crates/eliot-types", "crates/surfaces/eliot-cli"],
            ["crates/eliot-types"],
        )
        inv = tool.build_inventory(tmp, [
            "crates/eliot-types/src/ids.rs",
            "crates/surfaces/eliot-cli/src/edge.rs",
        ])
        self.assertGreater(inv["header"]["unassigned_count"], 0)
        self.assertEqual(inv["header"]["family_readiness"], "BLOCKED")
        self.assertIn("unowned-remainder", inv["header"]["family_blocked_reason"])

    # WORK_UNIT_CASE: 929/20
    def test_20_relevant_mutation_stales_evidence_output_only_commit_does_not(self) -> None:
        profile_src = (
            "pub struct RequestInputProfile { pub max_record_bytes: usize, pub max_buffered_bytes: usize, }\n"
            'pub const REQUEST_INPUT_PROFILE_ID: &str = "eliot.agent-bridge.request-input.v1";\n'
            "pub const REQUEST_INPUT_PROFILE: RequestInputProfile = RequestInputProfile {\n"
            "    max_record_bytes: 1024,\n    max_buffered_bytes: 2048,\n};\n"
        )
        tmp = _make_root(
            {
                "bins/demo/src/only.rs": _strict_derive("Only"),
                tool.BRIDGE_PROFILE_REL: profile_src,
            },
            ["bins/demo", "bins/eliot-agent-bridge"],
            ["bins/demo"],
        )
        _inventory, text_before = _sync_and_load(tmp)
        tool.check_cli(tmp)
        inventory2, text_after = _sync_and_load(tmp)
        self.assertEqual(text_before, text_after)
        tool.check_cli(tmp)
        self.assertEqual(inventory2["header"]["aggregate_digest"], _inventory["header"]["aggregate_digest"])
        (tmp / "bins/demo/src/only.rs").write_text(
            _strict_derive("Only") + "// trailing comment changes source bytes\n", encoding="utf-8")
        with self.assertRaises(tool.InventoryError) as ctx:
            tool.check_cli(tmp)
        self.assertEqual(ctx.exception.code, "STALE_INPUT")
        (tmp / "bins/demo/src/only.rs").write_text(_strict_derive("Only"), encoding="utf-8")
        tool.check_cli(tmp)
        (tmp / tool.BRIDGE_PROFILE_REL).write_text(
            profile_src.replace("max_record_bytes: 1024", "max_record_bytes: 2048"), encoding="utf-8")
        with self.assertRaises(tool.InventoryError) as ctx:
            tool.check_cli(tmp)
        self.assertEqual(ctx.exception.code, "STALE_INPUT")

    # WORK_UNIT_CASE: 929/21
    def test_21_shuffled_traversal_and_repeated_sync_byte_identical(self) -> None:
        tmp = _make_root(
            {
                "bins/demo/src/a.rs": _strict_derive("Alpha"),
                "bins/demo/src/b.rs": _strict_derive("Beta"),
            },
            ["bins/demo"],
            ["bins/demo"],
        )
        _inv, first = _sync_and_load(tmp)
        _inv2, second = _sync_and_load(tmp)
        self.assertEqual(first, second)
        forward = tool.build_inventory(tmp, ["bins/demo/src/a.rs", "bins/demo/src/b.rs"])
        backward = tool.build_inventory(tmp, ["bins/demo/src/b.rs", "bins/demo/src/a.rs"])
        self.assertEqual(
            [r["id"] for r in forward["rows"]], [r["id"] for r in backward["rows"]])
        self.assertEqual(tool._render_toml(forward), tool._render_toml(backward))

    # WORK_UNIT_CASE: 929/22
    def test_22_check_is_read_only_and_catches_hand_edits(self) -> None:
        tmp = _make_root(
            {"bins/demo/src/only.rs": _strict_derive("Only")},
            ["bins/demo"],
            ["bins/demo"],
        )
        _sync_and_load(tmp)

        def snapshot() -> dict[str, bytes]:
            state: dict[str, bytes] = {}
            for path in sorted(tmp.rglob("*")):
                if path.is_file() and not path.is_symlink():
                    state[path.relative_to(tmp).as_posix()] = path.read_bytes()
            return state

        before = snapshot()
        tool.check_cli(tmp)
        self.assertEqual(before, snapshot())
        text = (tmp / tool.OWNED_TOML_REL).read_text(encoding="utf-8")
        line = next(l for l in text.split("\n") if l.startswith("disposition = "))
        replacement = 'disposition = "needs-repair"' if "current-closed" in line else 'disposition = "current-closed"'
        (tmp / tool.OWNED_TOML_REL).write_text(
            text.replace(line, replacement, 1), encoding="utf-8")
        with self.assertRaises(tool.InventoryError) as ctx:
            tool.check_cli(tmp)
        self.assertEqual(ctx.exception.code, "HAND_EDIT_OR_DRIFT")

    # WORK_UNIT_CASE: 929/23
    def test_23_workset_includes_required_reading_and_oversized_remains_blocked(self) -> None:
        big_fields = "".join("    pub field_%04d: String,\n" % i for i in range(4000))
        big_src = (
            "use serde::Deserialize;\n#[derive(Debug, Deserialize)]\n"
            "#[serde(deny_unknown_fields)]\n"
            "pub struct HugeMemory {\n" + big_fields + "}\n"
        )
        tmp = _make_root(
            {"crates/eliot-types/src/memory.rs": big_src},
            ["crates/eliot-types"],
            ["crates/eliot-types"],
        )
        inv = tool.build_inventory(tmp, ["crates/eliot-types/src/memory.rs"])
        alloc = next(a for a in inv["allocations"] if a["child"] == "#937")
        self.assertTrue(set(tool.REQUIRED_CONTRACT_REFS) <= set(alloc["read_only_refs"]))
        self.assertGreater(alloc["stu_estimate"], alloc["stu_budget"])
        self.assertEqual(alloc["readiness"], "BLOCKED")
        self.assertIn("oversized", alloc["blocked_reason"])
        small = _make_root(
            {"crates/eliot-types/src/ids.rs": _strict_derive("IdsDto")},
            ["crates/eliot-types"],
            ["crates/eliot-types"],
        )
        small_inv = tool.build_inventory(small, ["crates/eliot-types/src/ids.rs"])
        small_alloc = next(a for a in small_inv["allocations"] if a["child"] == "#930")
        self.assertLessEqual(small_alloc["stu_estimate"], small_alloc["stu_budget"])

    # WORK_UNIT_CASE: 929/24
    def test_24_no_forbidden_mutation_and_baseline_rows_cannot_vanish(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(source.count("subprocess.run("), 1)
        self.assertNotIn("os.system(", source)
        self.assertNotIn("Popen(", source)
        self.assertNotIn("check_output(", source)
        for token in ('["cargo"', "['cargo'", '["gh"', "['gh'", '"curl"', '"wget"', '"ssh"'):
            self.assertNotIn(token, source)
        self.assertIn('("git", "ls-files")', source)
        tmp = _make_root(
            {
                "bins/demo/src/keep.rs": _strict_derive("Keep"),
                "bins/demo/src/drop.rs": _strict_derive("Drop"),
            },
            ["bins/demo"],
            ["bins/demo"],
        )
        _sync_and_load(tmp)
        before: dict[str, bytes] = {}
        for path in sorted(tmp.rglob("*")):
            if path.is_file() and not path.is_symlink():
                rel = path.relative_to(tmp).as_posix()
                if rel != tool.OWNED_TOML_REL:
                    before[rel] = path.read_bytes()
        tool.check_cli(tmp)
        tool.sync_inventory(tmp)
        after: dict[str, bytes] = {}
        for path in sorted(tmp.rglob("*")):
            if path.is_file() and not path.is_symlink():
                rel = path.relative_to(tmp).as_posix()
                if rel != tool.OWNED_TOML_REL:
                    after[rel] = path.read_bytes()
        self.assertEqual(before, after)
        (tmp / "bins/demo/src/drop.rs").unlink()
        with self.assertRaises(tool.InventoryError) as ctx:
            tool.check_cli(tmp)
        # Deleting a source file is a relevant input mutation: the check must
        # fail closed (stale inputs) rather than silently dropping the
        # baseline row from the denominator.
        self.assertEqual(ctx.exception.code, "STALE_INPUT")


if __name__ == "__main__":
    unittest.main()
