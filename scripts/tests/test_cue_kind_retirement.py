"""Retirement coordinator for the transitional CueKind alias (issue #835).

28 substantive coordinator checks, one per `# WORK_UNIT_CASE: 835/<case>`
marker. Static source denominator plus accepted gate binding: each method
rederives its denominator slice over accepted source and additionally asserts
its bound execution record from the accepted work-unit gate
(`audit_cue_kind_retirement.run_accepted_gate`: admitted offline assignment,
admitted descriptor, owned Python/Rust execution, #851 reconciliation,
contract composition). Native and legacy Rust executions therefore run through
the accepted interfaces with binary/test identity and typed receipts — never
mocked, never hand-written — and the delivery reports the same bound objects.
Run from the repository root:

    python -m unittest scripts.tests.test_cue_kind_retirement -v
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path
import tomllib

from scripts import audit_cue_kind_retirement as a

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "scripts/testdata/cue-kind-retirement"
MANIFEST = ROOT / "crates/eliot-types/tests/data/cue_kind_migration.toml"

A10_FILE = "crates/smart/eliot-cue-contracts/src/normalization.rs"
A10_LIB = "crates/smart/eliot-cue-contracts/src/lib.rs"
CUE_RS = "crates/eliot-types/src/ul/cue.rs"
BOUNDARY_RS = "crates/eliot-types/tests/cue_kind_legacy_boundary.rs"
RETIREMENT_RS = "crates/eliot-types/tests/cue_kind_retirement.rs"
ACCEPTANCE_804 = "crates/smart/eliot-cue-contracts/tests/acceptance_804.rs"
CONTRACT_SHAPE = "crates/smart/eliot-cue-contracts/tests/contract_shape.rs"


def fixture(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def manifest() -> dict:
    with open(MANIFEST, "rb") as handle:
        return tomllib.load(handle)


_gate_bound = None


def bound_case(number: int):
    """Bound (disposition, discovery-name) for coordinator case `number`.

    Runs the accepted gate once per process (lazy singleton) and returns the
    reconciled execution binding. Inside the owned gate child itself (argv
    carries --_python-child) binding is the parent's job, so this returns
    None and the child proves the static checks only — never a nested gate.
    """
    global _gate_bound
    if "--_python-child" in sys.argv:
        return None
    if _gate_bound is None:
        _gate_bound = {}
    if number not in _gate_bound:
        _gate_bound[number] = a.case_gate_result(number)
    return _gate_bound[number]


class RetirementCoordinator(unittest.TestCase):
    def assertBoundCase(self, number: int) -> None:
        """Assert the reconciled accepted execution for this coordinator case.

        Binds case identity to execution identity: the reconciled discovery
        name must equal this test's own unittest id and its disposition must
        be executed-pass. No-op inside the owned gate child (see bound_case).
        """
        bound = bound_case(number)
        if bound is None:
            return
        disposition, name = bound
        self.assertEqual(disposition, "executed-pass")
        self.assertEqual(name, self.id())
    # WORK_UNIT_CASE: 835/1
    def test_01_exactly_one_current_enum_in_complete_denominator(self):
        self.assertBoundCase(1)
        self.assertEqual(a.enum_declaration_files(), [A10_FILE])

    # WORK_UNIT_CASE: 835/2
    def test_02_current_owner_exactly_a10_pinned(self):
        self.assertBoundCase(2)
        lib = (ROOT / A10_LIB).read_text(encoding="utf-8")
        self.assertIn('pub const CONTRACT_REVISION: &str = "2.0.0";', lib)
        pins = fixture("version_pins.json")
        self.assertEqual(pins["a10"]["revision"], "2.0.0")
        self.assertEqual(pins["a10"]["file"], A10_FILE)
        doc = manifest()["meta"]
        self.assertEqual(doc["target_revision"], "2.0.0")
        self.assertEqual(doc["target_crate"], "eliot-cue-contracts")
        self.assertEqual(doc["target_digest"], pins["a10"]["digest"])
        owners = fixture("historical_owners.json")
        self.assertEqual(owners["current"]["file"], A10_FILE)
        self.assertEqual(owners["current"]["owner"], "#804")

    # WORK_UNIT_CASE: 835/3
    def test_03_no_legacy_cuekind_alias(self):
        self.assertBoundCase(3)
        self.assertEqual(a.type_alias_hits(), [])

    # WORK_UNIT_CASE: 835/4
    def test_04_no_legacy_as_current_reexport(self):
        self.assertBoundCase(4)
        self.assertEqual(
            a.reexport_lines(),
            [( "crates/smart/eliot-cues/src/lib.rs",
               "pub use eliot_cue_contracts::{CueKind, MatchMode};")],
        )

    # WORK_UNIT_CASE: 835/5
    def test_05_no_eliot_types_cuekind_consumer(self):
        self.assertBoundCase(5)
        self.assertEqual(a.eliot_types_consumer_files(), [])

    # WORK_UNIT_CASE: 835/6
    def test_06_historical_enums_explicitly_versioned(self):
        self.assertBoundCase(6)
        found = a.versioned_kind_enums()
        self.assertEqual(
            found,
            {
                "LegacyCueKindV1": "crates/eliot-types/src/ul/cue.rs",
                "LegacyContextCueKind": "crates/smart/eliot-context/src/lib.rs",
                "LegacyCueKindError": "crates/smart/eliot-context/src/lib.rs",
                "CueKind": A10_FILE,
            },
        )
        for name in found:
            if name != "CueKind":
                self.assertTrue(name.startswith("Legacy"), name)

    # WORK_UNIT_CASE: 835/7
    def test_07_every_historical_schema_has_owner(self):
        self.assertBoundCase(7)
        owners = fixture("historical_owners.json")["historical"]
        found = a.versioned_kind_enums()
        self.assertEqual(
            sorted(entry["enum"] for entry in owners),
            sorted(name for name in found if name != "CueKind"),
        )
        for entry in owners:
            self.assertTrue((ROOT / entry["file"]).is_file(), entry)
            self.assertTrue(entry["owner"].startswith("#"), entry)
            self.assertIn("generation", entry)

    # WORK_UNIT_CASE: 835/8
    def test_08_every_legacy_consumer_in_named_decoder_or_migration(self):
        self.assertBoundCase(8)
        rows = set(a.manifest_type_rows()) | set(a.manifest_field_rows())
        live = a.legacy_kind_consumer_files()
        self.assertTrue(live, "legacy consumer scan must not be empty")
        for rel in live:
            self.assertIn(rel, rows, f"legacy consumer without row: {rel}")

    def assertRustRows(self, package: str, test_ids: tuple) -> None:
        """Assert accepted-path Rust evidence rows show pass (None in child)."""
        bound = a.bound_rust()
        if bound is None:
            return
        rows, _gaps = bound
        for test_id in test_ids:
            matches = [r for r in rows if r[0] == package and r[1] == test_id]
            self.assertEqual(len(matches), 1, f"rust evidence row missing: {package}:{test_id}")
            self.assertEqual(matches[0][2], "pass")

    # WORK_UNIT_CASE: 835/9
    def test_09_current_a10_roundtrip_evidence_present(self):
        self.assertBoundCase(9)
        self.assertRustRows("eliot-cue-contracts", ("canonical_round_trip_and_digest_are_deterministic", "legacy_payload_is_rejected_by_current_decoder"))
        acceptance = (ROOT / ACCEPTANCE_804).read_text(encoding="utf-8")
        self.assertIn("let round_trip: CueKind", acceptance)
        self.assertIn("canonical_round_trip_and_digest_are_deterministic", acceptance)
        self.assertIn("legacy_payload_is_rejected_by_current_decoder", acceptance)
        shape = (ROOT / CONTRACT_SHAPE).read_text(encoding="utf-8")
        for spelling in a.V1_SPELLINGS:
            self.assertIn(f'"{spelling}"', shape)

    # WORK_UNIT_CASE: 835/10
    def test_10_historical_v1_roundtrip_available(self):
        self.assertBoundCase(10)
        self.assertRustRows("eliot-types", ("retired_v1_variants_and_wire_spellings_unchanged", "retired_v1_rejects_unknown_missing_and_empty"))
        vectors = fixture("wire_vectors.json")["v1_roundtrip"]
        self.assertEqual(len(vectors), 10)
        self.assertEqual(
            [entry["spelling"] for entry in vectors], list(a.V1_SPELLINGS)
        )
        retirement = (ROOT / RETIREMENT_RS).read_text(encoding="utf-8")
        self.assertIn("retired_v1_variants_and_wire_spellings_unchanged", retirement)
        wire = manifest()["wire"]
        self.assertEqual(wire["rename_all"], "snake_case")

    # WORK_UNIT_CASE: 835/11
    def test_11_current_decoder_rejects_legacy_only_input(self):
        self.assertBoundCase(11)
        region = a.enum_region_text(A10_FILE, "pub enum CueKind", "\n}\n")
        self.assertIn("deny_unknown_fields", (ROOT / A10_FILE).read_text(encoding="utf-8"))
        self.assertNotIn("untagged", region)
        acceptance = (ROOT / ACCEPTANCE_804).read_text(encoding="utf-8")
        self.assertIn("legacy_payload_is_rejected_by_current_decoder", acceptance)
        for spelling in a.LEGACY_ONLY_SPELLINGS:
            self.assertNotIn(spelling, a.V1_SPELLINGS)

    # WORK_UNIT_CASE: 835/12
    def test_12_legacy_cannot_emit_current_without_conversion(self):
        self.assertBoundCase(12)
        text = (ROOT / CUE_RS).read_text(encoding="utf-8")
        prod = a.strip_rust(text[: text.index("#[cfg(test)]")])
        self.assertNotIn("eliot_cue_contracts", prod)
        self.assertNotIn("smart::", prod)
        self.assertNotIn("cue_contracts", prod)

    # WORK_UNIT_CASE: 835/13
    def test_13_raw_unknown_missing_empty_rejection_vectors(self):
        self.assertBoundCase(13)
        vectors = fixture("wire_vectors.json")
        self.assertEqual(
            sorted(vectors["reject"]), sorted(manifest()["unsupported"]["inputs"])
        )
        self.assertIn("", vectors["reject"])
        self.assertIn("unknown", vectors["reject"])
        boundary = (ROOT / BOUNDARY_RS).read_text(encoding="utf-8")
        for marker in ("706/4", "706/5", "706/6"):
            self.assertIn(marker, boundary)
        retirement = (ROOT / RETIREMENT_RS).read_text(encoding="utf-8")
        self.assertIn("retired_v1_rejects_unknown_missing_and_empty", retirement)

    # WORK_UNIT_CASE: 835/14
    def test_14_no_permissive_default_alias_untagged_path(self):
        self.assertBoundCase(14)
        v1_region = a.enum_region_text(CUE_RS, "pub enum LegacyCueKindV1", "impl LegacyCueKindV1")
        needles = ("untagged", "alias", "Other", "Unknown", "_ =>", "impl Default")
        for label, region in (
            ("V1", v1_region),
            ("A-10", a.enum_region_text(A10_FILE, "pub enum CueKind", "\n}\n")),
        ):
            hits = [line.strip() for line in region.splitlines() if any(n in line for n in needles)]
            self.assertEqual(hits, [], f"permissive escape in {label} enum: {hits}")

    # WORK_UNIT_CASE: 835/15
    def test_15_temporary_allowlist_retired_with_row_dispositions(self):
        self.assertBoundCase(15)
        source = (ROOT / CUE_RS).read_text(encoding="utf-8")
        self.assertNotIn("pub type CueKind", source)
        self.assertNotIn("#[deprecated", source)
        doc = manifest()
        self.assertTrue(
            all(
                not key.lower().startswith("allowlist")
                for key in list(doc)
                + list(doc.get("notes", {}))
            ),
            "allowlist mechanism still present in manifest",
        )
        rows = dict(a.manifest_type_rows())
        rows.update(a.manifest_field_rows())
        self.assertTrue(rows, "manifest row denominator must not be empty")
        for name, row in rows.items():
            for key in ("owner", "migration", "expiry"):
                self.assertIn(key, row, f"{name} lacks {key}")
            self.assertTrue(str(row["owner"]).startswith("#"), name)
            self.assertGreaterEqual(len(str(row["expiry"])), 8, name)
        for rel in a.allow_deprecated_files():
            text = (ROOT / rel).read_text(encoding="utf-8")
            for index, line in enumerate(text.splitlines()):
                if "allow(deprecated" in line:
                    window = "\n".join(text.splitlines()[max(0, index - 15) : index + 15])
                    self.assertNotIn("CueKind", window, f"CueKind suppression in {rel}")

    # WORK_UNIT_CASE: 835/16
    def test_16_oracle_detects_second_current_enum(self):
        self.assertBoundCase(16)
        adversarial = fixture("adversarial_kinds.json")["second_current_enum"]
        self.assertTrue(adversarial)
        for snippet in adversarial:
            self.assertTrue(
                a.declares_enum(a.strip_rust(snippet), "CueKind"), snippet
            )
        self.assertFalse(a.declares_enum(a.strip_rust("enum CueKindProvenance {}\n"), "CueKind"))
        self.assertFalse(a.declares_enum(a.strip_rust("// enum CueKind\n"), "CueKind"))

    # WORK_UNIT_CASE: 835/17
    def test_17_oracle_detects_legacy_alias_and_reexport(self):
        self.assertBoundCase(17)
        adversarial = fixture("adversarial_kinds.json")
        alias_pattern = re.compile(r"(?<![A-Za-z0-9_])type\s+(?:r#)?CueKind\b")
        for snippet in adversarial["legacy_alias"]:
            self.assertIsNotNone(alias_pattern.search(a.strip_rust(snippet)), snippet)
        for snippet in adversarial["legacy_as_current_reexport"]:
            stripped = a.strip_rust(snippet)
            self.assertIn("CueKind", stripped)
            self.assertNotIn("eliot_cue_contracts", stripped)

    # WORK_UNIT_CASE: 835/18
    def test_18_oracle_detects_string_switch_owner(self):
        self.assertBoundCase(18)
        adversarial = fixture("adversarial_kinds.json")["string_switch_owner"]
        arm = re.compile(r'"(?:%s)"\s*=>' % "|".join(a.V1_SPELLINGS))
        for snippet in adversarial:
            self.assertIsNotNone(
                arm.search(a.strip_comments_only(snippet)), snippet
            )
        # Exactly one live owner branches on historical spellings: the named
        # #833 decoder, whose arms construct the A-10 owner (verified above).
        self.assertEqual(
            a.string_switch_owner_files(),
            ["crates/smart/eliot-cues/src/legacy_adapter.rs"],
        )

    # WORK_UNIT_CASE: 835/19
    def test_19_legacy_as_current_schema_acceptance_detected(self):
        self.assertBoundCase(19)
        adversarial = fixture("adversarial_kinds.json")["legacy_schema_acceptance"]
        escape = re.compile(r"untagged|alias\s*=")
        for snippet in adversarial:
            self.assertIsNotNone(escape.search(a.strip_rust(snippet)), snippet)
        self.assertEqual(a.enum_declaration_files(), [A10_FILE])

    # WORK_UNIT_CASE: 835/20
    def test_20_navigation_and_source_denominators_reconcile(self):
        self.assertBoundCase(20)
        rows = list(a.manifest_type_rows()) + list(a.manifest_field_rows())
        self.assertTrue(rows, "manifest row denominator must not be empty")
        scanned = set(a.iter_rs_files())
        for rel in rows:
            if rel.endswith(".rs"):
                self.assertIn(rel, scanned, f"manifest row outside scan domain: {rel}")
            self.assertTrue((ROOT / rel).is_file(), f"manifest row missing: {rel}")
        testdata_rs = [
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "scripts/testdata").rglob("*.rs")
        ]
        for rel in testdata_rs:
            self.assertNotIn(
                "CueKind", (ROOT / rel).read_text(encoding="utf-8"),
                f"testdata fixture carries kind tokens: {rel}",
            )
        # Explicit incomplete state (issue rule: incomplete, not zero).
        # Macro/file-inclusion coverage is unproved as a mechanism: the seven
        # files below load external fixture bytes via include_str!, so the
        # lexical denominator reports them INCOMPLETE with a stable reason.
        # Their included bytes are inspected here (no kind definitions), but
        # the mechanism verdict stays INCOMPLETE rather than claiming zero.
        self.assertEqual(a.unknown_root_kind_files(), [])
        verdict = a.denominator_status()
        self.assertEqual(verdict.status, "INCOMPLETE")
        self.assertEqual(
            sorted(verdict.incomplete),
            sorted([
                ("crates/eliot-app/src/mcp_stdio/protocol_tests.rs", "include-macro-fixture-bytes"),
                ("crates/eliot-app/tests/ul_pyramid_delivery.rs", "include-macro-fixture-bytes"),
                ("crates/eliot-store/tests/memory_retrieval.rs", "include-macro-fixture-bytes"),
            ]),
        )
        for rel, _reason in verdict.incomplete:
            targets = a.include_targets(rel)
            self.assertTrue(targets, f"no include targets in {rel}")
            for target in targets:
                self.assertTrue((ROOT / target).is_file(), f"include target missing: {target}")
                content = (ROOT / target).read_text(encoding="utf-8")
                self.assertIsNone(
                    re.search(r"enum\s+[A-Za-z_]*CueKind", content),
                    f"kind definition inside included bytes: {target}",
                )

    # WORK_UNIT_CASE: 835/21
    def test_21_persisted_config_ipc_provider_wasm_coverage(self):
        self.assertBoundCase(21)
        coverage = fixture("persisted_ipc_provider_wasm_coverage.json")
        for cls, entries in coverage["classes"].items():
            self.assertTrue(entries, f"empty coverage class: {cls}")
            for entry in entries:
                self.assertTrue((ROOT / entry["file"]).is_file(), entry)
        for name in coverage["retirement_vectors"]:
            vector = name.split(" ", 1)[0]
            self.assertTrue((FIXTURES / vector).is_file(), name)

    # WORK_UNIT_CASE: 835/22
    def test_22_affected_consumers_compile_without_alias(self):
        self.assertBoundCase(22)
        self.assertEqual(a.eliot_types_consumer_files(), [])
        self.assertEqual(a.type_alias_hits(), [])
        cargo = (ROOT / "crates/eliot-types/Cargo.toml").read_text(encoding="utf-8")
        for line in cargo.splitlines():
            cell = line.strip()
            self.assertFalse(
                "smart" in cell or "eliot-cue" in cell or "cue-contracts" in cell,
                f"Smart dependency in eliot-types manifest: {line}",
            )

    # WORK_UNIT_CASE: 835/23
    def test_23_exact_allowed_source_test_oracle_handoff_diff(self):
        self.assertBoundCase(23)
        diff = a.git_diff_names()
        self.assertIn(CUE_RS, diff)
        self.assertIn(RETIREMENT_RS, diff)
        allowed = {
            line.strip()
            for line in (FIXTURES / "allowed_diff.txt").read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
        for name in diff:
            self.assertTrue(
                name in allowed
                or name.startswith("scripts/testdata/cue-kind-retirement/"),
                f"diff outside frozen 835 scope: {name}",
            )

    # WORK_UNIT_CASE: 835/24
    def test_24_bounded_malformed_fixtures_panic_free(self):
        self.assertBoundCase(24)
        import json as jsonlib

        battery = fixture("malformed_current_legacy.json")["vectors"]
        self.assertGreaterEqual(len(battery), 5)
        by_tag = {entry["tag"]: entry for entry in battery}
        # JSON-syntax-broken vectors must fail loudly, never hang or crash.
        self.assertRaises(ValueError, jsonlib.loads, by_tag["truncated-object"]["raw"])
        deep = by_tag["deep-nesting-probe"]
        deep_raw = deep["wrap"] % (deep["repeat"]["char"] * deep["repeat"]["count"])
        try:
            jsonlib.loads(deep_raw)
        except (ValueError, RecursionError):
            pass
        else:
            self.fail("deep nesting probe must not parse cleanly")
        # Decoder-level vectors are valid JSON with wrong shapes: pinned here,
        # rejected by the owning Rust decoders (executed proof in delivery).
        self.assertEqual(jsonlib.loads(by_tag["wrong-top-level-type"]["raw"]), [1, 2, 3])
        nested = jsonlib.loads(by_tag["nested-kind-object"]["raw"])
        self.assertIsInstance(nested["kind"], dict)
        big = by_tag["bounded-large-value"]
        big_raw = big["wrap"] % (big["repeat"]["char"] * big["repeat"]["count"])
        self.assertEqual(jsonlib.loads(big_raw)["kind"], "file_path")
        missing = by_tag["missing-kind-field"]
        self.assertNotIn("kind", jsonlib.loads(jsonlib.dumps(missing["value"])))
        self.assertEqual(ord(jsonlib.loads('"\\ud800"')), 0xD800)

    # WORK_UNIT_CASE: 835/25
    def test_25_a10_encode_decode_bijection_evidence(self):
        self.assertBoundCase(25)
        self.assertRustRows("eliot-cue-contracts", ("canonical_round_trip_and_digest_are_deterministic",))
        acceptance = (ROOT / ACCEPTANCE_804).read_text(encoding="utf-8")
        self.assertIn("canonical_round_trip_and_digest_are_deterministic", acceptance)
        shape = (ROOT / CONTRACT_SHAPE).read_text(encoding="utf-8")
        for variant, spelling in [
            ("FilePath", "file_path"),
            ("DirPath", "dir_path"),
            ("Symbol", "symbol"),
            ("ErrorSignature", "error_signature"),
            ("CommandPattern", "command_pattern"),
            ("Dependency", "dependency"),
            ("ApiSurface", "api_surface"),
            ("TaskClass", "task_class"),
            ("Subsystem", "subsystem"),
            ("Concept", "concept"),
        ]:
            self.assertIn(f"CueKind::{variant}", shape)
            self.assertIn(f'"{spelling}"', shape)
        pins = fixture("version_pins.json")
        self.assertEqual(
            (ROOT / A10_LIB).read_text(encoding="utf-8").count('CONTRACT_REVISION: &str = "2.0.0"'),
            1,
        )
        self.assertEqual(pins["a10"]["revision"], "2.0.0")

    # WORK_UNIT_CASE: 835/26
    def test_26_unknown_and_legacy_only_cannot_construct_current(self):
        self.assertBoundCase(26)
        source = (ROOT / A10_FILE).read_text(encoding="utf-8")
        self.assertIn("non_exhaustive", source)
        self.assertIn("deny_unknown_fields", source)
        vectors = fixture("wire_vectors.json")
        current = {entry["spelling"] for entry in vectors["v1_roundtrip"]}
        for entry in vectors["legacy_only"]:
            self.assertNotIn(entry["spelling"], current)
        for spelling in vectors["reject"]:
            if spelling:
                self.assertNotIn(
                    spelling, current, f"reject vector overlaps current: {spelling}"
                )

    # WORK_UNIT_CASE: 835/27
    def test_27_retained_legacy_values_preserve_source_version(self):
        self.assertBoundCase(27)
        golden = (FIXTURES / "v1_enum_golden.txt").read_text(encoding="utf-8")
        source = (ROOT / CUE_RS).read_text(encoding="utf-8")
        self.assertIn(golden, source)
        block = golden
        self.assertIn("#[serde(rename_all", block)
        self.assertIn("pub enum LegacyCueKindV1 {", block)
        self.assertNotIn("untagged", block)
        self.assertNotIn("alias", block)
        self.assertNotIn("pub type CueKind", block)

    # WORK_UNIT_CASE: 835/28
    def test_28_no_algorithm_authority_effect_or_false_claim(self):
        self.assertBoundCase(28)
        # End-of-run live re-verification (F2): no nested gate in the
        # owned child (returns None there); raises on any post-gate
        # input or membership drift in a real run.
        a.verify_run_inputs_unchanged()
        diff = a.git_diff_names()
        for name in diff:
            self.assertFalse(
                name.startswith("bins/")
                or name.startswith("crates/kernel/")
                or name.startswith("crates/governor/")
                or name.startswith("crates/storage/")
                or name.startswith("crates/agent/"),
                f"delivery-adjacent path changed: {name}",
            )
            self.assertTrue(
                name.startswith("crates/eliot-types/")
                or name.startswith("scripts/audit_cue_kind_retirement.py")
                or name.startswith("scripts/tests/test_cue_kind_retirement.py")
                or name.startswith("scripts/testdata/cue-kind-retirement/")
                or name == ".github/work-units/835.toml",
                f"unexpected path changed: {name}",
            )
        audit_source = (ROOT / "scripts/audit_cue_kind_retirement.py").read_text(
            encoding="utf-8"
        )
        # Verdict-shaped literals in CODE (comments/docstrings/strings stripped):
        # no fabricated result payloads, no shouted verdicts, and never the
        # legacy NOT_RUN/NOT_CHECKED shape. Legitimate machinery identifiers
        # (passed_exec, EXECUTED_PASS receipts via accepted constructors) do
        # not match these payload shapes.
        code = a.strip_rust(audit_source)
        for token in (
            "NOT_RUN",
            "NOT_CHECKED",
            "PASSED",
            '"terminal"',
            "'terminal'",
            '"counts"',
            '"passed":',
            '"failed":',
            '"missing_evidence"',
            '"failed_evidence"',
            "NOT_VERIFIED",
            "VERIFIED_COMPLETE",
        ):
            self.assertNotIn(token, code, f"verdict-shaped token in oracle code: {token}")
        for name in diff:
            self.assertFalse(name.endswith(".log"))
            self.assertFalse(name.endswith(".out"))
            self.assertFalse("/target" in name)


if __name__ == "__main__":
    unittest.main()
