"""Executable metadata contract for issue #816.

The four cognitive TOMLs are read together.  The suite checks stable
assignment identity, the eleven I9.6 wire kinds, contract-only compile
relations, typed runtime value flow, write ownership, and donor dispositions.
It deliberately stops at the metadata proof ceiling: no assertion claims a
Smart runtime, Product Pulse, workspace admission, or Product acceptance.

The denominator is exactly 60 cases, each bound to one substantive unittest
by a ``WORK_UNIT_CASE: 816/<n>`` marker.
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import tomllib
import unittest
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOML_PATHS = {
    "wave": ROOT / "crates/smart/cognitive-wave-01.toml",
    "edges": ROOT / "crates/smart/cognitive-edge-map.toml",
    "decisions": ROOT / "crates/smart/cognitive-crate-decisions.toml",
    "donors": ROOT / "crates/smart/cognitive-donor-map.toml",
}
FIXTURE = ROOT / "scripts/testdata/cognitive-topology/invalid_topologies.json"
TASK_PATHS = {
    "crates/smart/cognitive-wave-01.toml",
    "crates/smart/cognitive-edge-map.toml",
    "crates/smart/cognitive-crate-decisions.toml",
    "crates/smart/cognitive-donor-map.toml",
    "scripts/tests/test_cognitive_topology_contract.py",
    "scripts/testdata/cognitive-topology/invalid_topologies.json",
    ".github/temporary/work-unit-816.md",
}

EXPECTED_ASSIGNMENTS = {
    "A-03": ("Dreamer", 3, 578, "eliot-dreamer-contracts"),
    "A-05": ("Dreamer", 5, 595, "eliot-dreamer-candidate-validation"),
    "A-06e": ("Epistemic", 6, 580, "eliot-epistemic-contracts"),
    "A-10": ("Cue", 10, 804, "eliot-cue-contracts"),
    "A-14a": ("Cue", 14, 600, "eliot-cue-activation"),
    "A-15": ("Context", 15, 584, "eliot-context-contracts"),
    "A-16a": ("Context", 16, 604, "eliot-context-candidates"),
    "A-17a": ("Context", 17, 608, "eliot-context-admission"),
    "A-18": ("Context", 18, 626, "eliot-context-assembly"),
    "A-19r": ("Context", 19, 612, "eliot-reactive-context-plan"),
    "A-19c": ("Curation", 19, 586, "eliot-memory-curation-contracts"),
    "A-20": ("Curation", 20, 588, "eliot-memory-curation-screen"),
    "A-21": ("Curation", 21, 653, "eliot-dreamer-classification"),
    "A-22": ("Curation", 22, 655, "eliot-dreamer-relation"),
    "A-23": ("Curation", 23, 657, "eliot-dreamer-episode"),
    "A-24": ("Curation", 24, 659, "eliot-dreamer-concept"),
    "A-25": ("Curation", 25, 661, "eliot-dreamer-procedure"),
    "A-26": ("Curation", 26, 663, "eliot-dreamer-failure"),
    "A-27": ("Curation", 27, 665, "eliot-dreamer-structure-repair"),
    "A-28": ("Curation", 28, 667, "eliot-dreamer-reconsolidation"),
    "A-29": ("Curation", 29, 669, "eliot-dreamer-accessibility"),
    "A-30": ("Curation", 30, 671, "eliot-dreamer-memory-repair"),
    "A-31": ("Curation", 31, 684, "eliot-dreamer-curation"),
}

WIRE_FAMILY = {
    "Classification": "Classification",
    "Relation": "Relation",
    "Episode": "Episode",
    "Concept": "Concept",
    "Procedure": "Procedure",
    "Failure": "Failure",
    "Merge": "StructureRepair",
    "Split": "StructureRepair",
    "Reconsolidation": "Reconsolidation",
    "Accessibility": "Accessibility",
    "Repair": "MemoryRepair",
}
CURATION_HANDLERS = {f"A-{number}" for number in range(21, 32)}
CONTEXT_STAGES = {"A-15", "A-16a", "A-17a", "A-18", "A-19r"}


def load_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def load_bundle() -> dict[str, dict]:
    return {name: load_toml(path) for name, path in TOML_PATHS.items()}


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def assignment_rows(bundle: dict[str, dict]) -> list[dict]:
    return bundle["wave"]["topology_assignment"]


def assignments_by_id(bundle: dict[str, dict]) -> dict[str, dict]:
    return {row["assignment_id"]: row for row in assignment_rows(bundle)}


def row_by(rows: list[dict], key: str, value: object) -> dict:
    for row in rows:
        if row.get(key) == value:
            return row
    raise AssertionError(f"missing {key}={value!r}")


def compile_pairs(bundle: dict[str, dict]) -> set[tuple[str, str]]:
    return {
        (row.get("from"), row.get("to"))
        for row in bundle["edges"].get("compile_edge", [])
    }


def has_cycle(edges: list[dict]) -> bool:
    graph: dict[str, set[str]] = defaultdict(set)
    nodes: set[str] = set()
    for row in edges:
        source, target = row.get("from"), row.get("to")
        if not isinstance(source, str) or not isinstance(target, str):
            continue
        if source not in EXPECTED_ASSIGNMENTS or target not in EXPECTED_ASSIGNMENTS:
            continue
        graph[source].add(target)
        nodes.update((source, target))

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        if any(visit(child) for child in graph[node]):
            return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(visit(node) for node in nodes)


def topology_errors(bundle: dict[str, dict]) -> list[str]:
    """Return semantic violations in a copied four-file metadata bundle."""

    errors: list[str] = []
    wave, edges, decisions, donors = (
        bundle["wave"],
        bundle["edges"],
        bundle["decisions"],
        bundle["donors"],
    )
    topology = wave.get("topology", {})
    if topology.get("issue") != 816:
        errors.append("wave topology issue mismatch")
    if topology.get("authority_base") != "9e3562df010fb0c0aa9bceebb7db2245cf181ca1":
        errors.append("wave authority base mismatch")
    if topology.get("metadata_only") is not True:
        errors.append("metadata-only ceiling missing")
    if topology.get("runtime_completion") is not False:
        errors.append("runtime completion claim present")
    if topology.get("product_acceptance") is not False:
        errors.append("Product acceptance claim present")
    if topology.get("existing_wave_assignment_rows") != len(wave.get("assignment", [])):
        errors.append("historical wave assignment denominator changed")
    if topology.get("existing_decision_rows") != len(decisions.get("decision", [])):
        errors.append("historical decision denominator changed")

    rows = assignment_rows(bundle)
    keys = [(row.get("assignment_id"), row.get("track")) for row in rows]
    if len(keys) != len(set(keys)):
        errors.append("assignment identity and track are not unique")
    actual_ids = {row.get("assignment_id") for row in rows}
    if actual_ids != set(EXPECTED_ASSIGNMENTS):
        errors.append("topology assignment set does not reconcile")
    for assignment_id, (track, order, issue, crate) in EXPECTED_ASSIGNMENTS.items():
        row = next((item for item in rows if item.get("assignment_id") == assignment_id), None)
        if row is None:
            errors.append(f"missing stable assignment {assignment_id}")
            continue
        if (row.get("track"), row.get("agent_order"), row.get("issue"), row.get("crate")) != (
            track,
            order,
            issue,
            crate,
        ):
            errors.append(f"assignment mapping mismatch for {assignment_id}")
        manifest = ROOT / row.get("manifest", "")
        if not manifest.is_file():
            errors.append(f"missing manifest for {assignment_id}")
            continue
        try:
            module = load_toml(manifest)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            errors.append(f"manifest parse failure for {assignment_id}: {exc}")
            continue
        if module.get("module_id") != row.get("module_id"):
            errors.append(f"module identity mismatch for {assignment_id}")
        if module.get("crate") != crate or module.get("agent_order") != order:
            errors.append(f"module order/crate mismatch for {assignment_id}")
        if issue not in row.get("issue_refs", []):
            errors.append(f"primary issue not retained for {assignment_id}")

    historical_orders = {
        row.get("crate"): row.get("order") for row in wave.get("assignment", [])
    }
    for row in rows:
        if row.get("crate") in historical_orders and row.get("agent_order") != historical_orders[row["crate"]]:
            errors.append(f"historical order changed for {row['assignment_id']}")

    wire_rows = decisions.get("wire_kind", [])
    expected_wire_kinds = set(WIRE_FAMILY)
    if len(wire_rows) != 11 or {row.get("kind") for row in wire_rows} != expected_wire_kinds:
        errors.append("wire-kind denominator is not exactly eleven")
    if len({row.get("family") for row in wire_rows}) != 10:
        errors.append("wire families are not exactly ten")
    if any(row.get("kind") == "StructureRepair" for row in wire_rows):
        errors.append("StructureRepair was incorrectly added as a wire kind")
    for row in wire_rows:
        kind = row.get("kind")
        if kind in WIRE_FAMILY and row.get("family") != WIRE_FAMILY[kind]:
            errors.append(f"wrong family for wire kind {kind}")
    if sum(row.get("kind") == "Merge" for row in wire_rows) != 1:
        errors.append("Merge wire kind missing or duplicated")
    if sum(row.get("kind") == "Split" for row in wire_rows) != 1:
        errors.append("Split wire kind missing or duplicated")

    excluded = decisions.get("excluded_job_class", [])
    if {row.get("assignment_id") for row in excluded} != {f"A-{n}" for n in range(39, 44)}:
        errors.append("A-39..A-43 job-class denominator changed")
    if any(row.get("wire_kind") or row.get("curation_kind") for row in excluded):
        errors.append("A-39..A-43 leaked into Curation wire kinds")

    policy = decisions.get("topology_policy", {})
    if policy.get("curation_dispatchable_terminal") != "Eligible":
        errors.append("dispatch terminal is not exact Eligible")
    if policy.get("screen_never_selects_kind") is not True:
        errors.append("screen kind-routing boundary missing")
    if policy.get("dispatch_requires_explicit_a03_kind") is not True:
        errors.append("explicit A-03 kind requirement missing")
    if policy.get("dispatch_requires_a05_validated_input") is not True:
        errors.append("A-05 validation requirement missing")
    if policy.get("dispatch_uses_contract_owned_registry_ports") is not True:
        errors.append("contract-owned registry-port boundary missing")
    if policy.get("dispatch_imports_concrete_handlers") is not False:
        errors.append("concrete handler import claim present")
    if policy.get("repeat_common_validation") is not False:
        errors.append("repeat validation claim present")
    rejection_states = {
        row.get("state") for row in decisions.get("dispatch_rejection_state", [])
        if row.get("dispatchable") is False
    }
    if rejection_states != {
        "Protected",
        "ProtectionUnknown",
        "Malformed",
        "Stale",
        "Unavailable",
        "Partial",
        "Truncated",
        "Unprocessed",
    }:
        errors.append("dispatch rejection state set is incomplete")

    ports = {row.get("id"): row for row in decisions.get("registry_port", [])}
    for port_id, owner, consumer in (
        ("A-03-validated-values", "A-03", "A-31"),
        ("A-19c-screen", "A-19c", "A-20"),
        ("A-20-terminal-evidence", "A-20", "A-31"),
        ("A-31-dispatch", "A-31", "Governor/runtime composition"),
    ):
        port = ports.get(port_id)
        if port is None or port.get("owner_assignment") != owner or consumer not in port.get("consumers", []):
            errors.append(f"registry port {port_id} is not owned/consumed correctly")
        elif port.get("algorithm_free") is not True:
            errors.append(f"registry port {port_id} exposes an algorithm")

    compile_edges = edges.get("compile_edge", [])
    if any(row.get("relation") != "contract_only" for row in compile_edges):
        errors.append("compile edge is not contract-only")
    required_compile = {
        ("A-16a", "A-15"),
        ("A-16a", "A-10"),
        ("A-16a", "A-06e"),
        ("A-17a", "A-15"),
        ("A-18", "A-15"),
        ("A-19r", "A-15"),
        ("A-19r", "A-10"),
        ("A-20", "A-19c"),
        ("A-31", "A-03"),
        ("A-31", "A-19c"),
    }
    if not required_compile <= compile_pairs(bundle):
        errors.append("required canonical compile edge is missing")
    forbidden_pairs = {
        (row.get("from"), row.get("to"))
        for row in edges.get("forbidden_topology_compile_edge", [])
    }
    if {("A-16a", "A-14a"), ("A-17a", "A-16a"), ("A-18", "A-17a"), ("A-31", "A-05"), ("A-31", "A-14b")} - forbidden_pairs:
        errors.append("required forbidden compile edge declaration is missing")
    if forbidden_pairs & compile_pairs(bundle):
        errors.append("forbidden compile edge was admitted")
    if has_cycle(compile_edges):
        errors.append("compile dependency graph contains a cycle")

    runtime = {row.get("id"): row for row in edges.get("runtime_edge", [])}
    required_runtime = {
        "context-projections-to-candidates",
        "candidates-to-admission",
        "admission-to-assembly",
        "assembly-to-reactive-plan",
        "reactive-plan-to-brctx",
        "brctx-to-host-transport",
        "screen-contract-to-screen",
        "screen-to-curation-dispatch",
        "validated-values-to-curation-dispatch",
        "a15-to-fstu-to-a18",
    }
    if set(runtime) != required_runtime:
        errors.append("runtime relation set is incomplete")
    if not runtime.get("admission-to-assembly", {}).get("selects_membership"):
        errors.append("A-17a membership ownership missing")
    if runtime.get("candidates-to-admission", {}).get("selects_membership"):
        errors.append("A-16a incorrectly selects final membership")
    if not runtime.get("assembly-to-reactive-plan", {}).get("preserves_membership"):
        errors.append("A-18 membership preservation missing")
    if runtime.get("reactive-plan-to-brctx", {}).get("writes"):
        errors.append("A-19r incorrectly owns physical writes")

    context_stages = {row.get("assignment_id"): row for row in decisions.get("context_stage", [])}
    if set(context_stages) != CONTEXT_STAGES:
        errors.append("Context stage ownership rows are incomplete")
    reactive = context_stages.get("A-19r", {})
    for field in ("refreshes_providers", "reruns_admission", "reassembles_view", "mutates_session", "delivers_bytes", "infers_use"):
        if reactive.get(field) is not False:
            errors.append(f"A-19r owns forbidden stage {field}")
    if context_stages.get("A-17a", {}).get("membership_decision") is not True:
        errors.append("A-17a is not the sole membership owner")
    if context_stages.get("A-16a", {}).get("membership_decision") is not False:
        errors.append("A-16a membership boundary missing")
    if context_stages.get("A-18", {}).get("membership_decision") is not False:
        errors.append("A-18 membership boundary missing")

    physical = {row.get("owner"): row for row in edges.get("physical_write_edge", [])}
    if physical.get("A-19r", {}).get("physical_write") is not False:
        errors.append("A-19r physical-write prohibition missing")
    if physical.get("B-RCTX", {}).get("physical_write") is not True:
        errors.append("B-RCTX write owner missing")
    proof_ids = {row.get("id") for row in edges.get("proof_edge", [])}
    if {"screen-eligibility-before-dispatch", "validated-draft-before-dispatch", "admitted-set-before-assembly"} - proof_ids:
        errors.append("proof-before-admission/dispatch edge missing")

    ownership = edges.get("ownership_edge", [])
    if not any(row.get("owner") == "A-15" and row.get("implementation_owner") == "F-STU" and row.get("consumer") == "A-18" for row in ownership):
        errors.append("A-15/F-STU/A-18 measurement ownership missing")
    if not any(row.get("owner") == "A-19r" and row.get("implementation_owner") == "B-RCTX" for row in ownership):
        errors.append("A-19r/B-RCTX ownership boundary missing")

    donor_rows = {row.get("path"): row for row in donors.get("topology_donor", [])}
    for path, disposition, owner in (
        ("crates/smart/eliot-context", "SPLIT_AND_RETAIN_AS_TEMPORARY_FACADE", "A-15/A-16a/A-17a/A-18"),
        ("crates/smart/eliot-understanding", "RETIRED_DUPLICATE_UNDERSTANDING_FACADE", "none"),
        ("crates/smart/eliot-cues", "SPLIT_AND_RETAIN_AS_TEMPORARY_FACADE", "A-10/A-11/A-12/A-13/A-14a; B-RCTX for delivery"),
        ("crates/smart/eliot-memory-curation", "PARTIAL_REUSE_THEN_RETIRE_FACADE", "A-19c/A-20/A-31"),
    ):
        row = donor_rows.get(path)
        if row is None or row.get("observed_disposition") != disposition or row.get("current_owner") != owner:
            errors.append(f"donor disposition missing for {path}")
        elif not row.get("uncertainty"):
            errors.append(f"donor uncertainty missing for {path}")

    return errors


def apply_mutation(bundle: dict[str, dict], mutation: dict) -> dict[str, dict]:
    mutated = copy.deepcopy(bundle)
    kind = mutation["kind"]
    if kind == "assignment_field":
        row = row_by(mutated["wave"]["topology_assignment"], "assignment_id", mutation["assignment_id"])
        row[mutation["field"]] = mutation["value"]
    elif kind == "wire_field":
        row = row_by(mutated["decisions"]["wire_kind"], "kind", mutation["wire_kind"])
        row[mutation["field"]] = mutation["value"]
    elif kind == "wire_append":
        mutated["decisions"]["wire_kind"].append(copy.deepcopy(mutation["row"]))
    elif kind == "remove_assignment":
        mutated["wave"]["topology_assignment"] = [
            row for row in mutated["wave"]["topology_assignment"]
            if row.get("assignment_id") != mutation["assignment_id"]
        ]
    elif kind == "compile_append":
        mutated["edges"]["compile_edge"].append(copy.deepcopy(mutation["row"]))
    elif kind == "policy_field":
        mutated["decisions"]["topology_policy"][mutation["field"]] = mutation["value"]
    elif kind == "runtime_field":
        row = row_by(mutated["edges"]["runtime_edge"], "id", mutation["runtime_id"])
        row[mutation["field"]] = mutation["value"]
    elif kind == "topology_field":
        mutated["wave"]["topology"][mutation["field"]] = mutation["value"]
    else:
        raise AssertionError(f"unknown fixture mutation {kind}")
    return mutated


class CognitiveTopologyContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bundle = load_bundle()
        cls.fixture = load_fixture()
        errors = topology_errors(cls.bundle)
        if errors:
            raise AssertionError("base topology is invalid: " + "; ".join(errors))

    # WORK_UNIT_CASE: 816/1
    def test_case_01_four_metadata_files_parse_as_toml(self):
        self.assertEqual(set(self.bundle), set(TOML_PATHS))
        self.assertTrue(all(isinstance(value, dict) for value in self.bundle.values()))

    # WORK_UNIT_CASE: 816/2
    def test_case_02_canonical_serialization_and_digest_are_deterministic(self):
        first = canonical_sha256(self.bundle)
        reordered = json.loads(json.dumps(self.bundle, sort_keys=True))
        self.assertEqual(first, canonical_sha256(reordered))
        self.assertEqual(64, len(first))

    # WORK_UNIT_CASE: 816/3
    def test_case_03_every_referenced_stable_assignment_exists_once(self):
        ids = set(assignments_by_id(self.bundle))
        for row in self.bundle["decisions"]["wire_kind"]:
            self.assertIn(row["assignment_id"], ids)
        for row in self.bundle["decisions"]["context_stage"]:
            self.assertIn(row["assignment_id"], ids)
        for row in self.bundle["decisions"]["registry_port"]:
            self.assertIn(row["owner_assignment"], ids)

    # WORK_UNIT_CASE: 816/4
    def test_case_04_identity_track_not_integer_order_defines_uniqueness(self):
        rows = assignment_rows(self.bundle)
        self.assertEqual(2, sum(row["agent_order"] == 19 for row in rows))
        self.assertEqual(2, len({(row["assignment_id"], row["track"]) for row in rows if row["agent_order"] == 19}))
        mutated = copy.deepcopy(self.bundle)
        row_by(mutated["wave"]["topology_assignment"], "assignment_id", "A-18")["agent_order"] = 19
        self.assertNotIn("assignment identity and track are not unique", topology_errors(mutated))

    # WORK_UNIT_CASE: 816/5
    def test_case_05_a19r_is_context_order_nineteen(self):
        row = assignments_by_id(self.bundle)["A-19r"]
        self.assertEqual(("Context", 19, 612), (row["track"], row["agent_order"], row["issue"]))

    # WORK_UNIT_CASE: 816/6
    def test_case_06_a19c_is_curation_order_nineteen(self):
        row = assignments_by_id(self.bundle)["A-19c"]
        self.assertEqual(("Curation", 19, 586), (row["track"], row["agent_order"], row["issue"]))

    # WORK_UNIT_CASE: 816/7
    def test_case_07_a20_through_a31_retain_stable_identity_order_and_issue(self):
        for number in range(20, 32):
            assignment_id = f"A-{number}"
            row = assignments_by_id(self.bundle)[assignment_id]
            expected = EXPECTED_ASSIGNMENTS[assignment_id]
            self.assertEqual(expected[:3], (row["track"], row["agent_order"], row["issue"]))

    # WORK_UNIT_CASE: 816/8
    def test_case_08_classification_maps_only_to_a21(self):
        row = row_by(self.bundle["decisions"]["wire_kind"], "kind", "Classification")
        self.assertEqual(("Classification", "A-21"), (row["family"], row["assignment_id"]))

    # WORK_UNIT_CASE: 816/9
    def test_case_09_relation_maps_only_to_a22(self):
        row = row_by(self.bundle["decisions"]["wire_kind"], "kind", "Relation")
        self.assertEqual(("Relation", "A-22"), (row["family"], row["assignment_id"]))

    # WORK_UNIT_CASE: 816/10
    def test_case_10_episode_maps_only_to_a23(self):
        row = row_by(self.bundle["decisions"]["wire_kind"], "kind", "Episode")
        self.assertEqual(("Episode", "A-23"), (row["family"], row["assignment_id"]))

    # WORK_UNIT_CASE: 816/11
    def test_case_11_concept_maps_only_to_a24(self):
        row = row_by(self.bundle["decisions"]["wire_kind"], "kind", "Concept")
        self.assertEqual(("Concept", "A-24"), (row["family"], row["assignment_id"]))

    # WORK_UNIT_CASE: 816/12
    def test_case_12_procedure_maps_only_to_a25(self):
        row = row_by(self.bundle["decisions"]["wire_kind"], "kind", "Procedure")
        self.assertEqual(("Procedure", "A-25"), (row["family"], row["assignment_id"]))

    # WORK_UNIT_CASE: 816/13
    def test_case_13_failure_maps_only_to_a26(self):
        row = row_by(self.bundle["decisions"]["wire_kind"], "kind", "Failure")
        self.assertEqual(("Failure", "A-26"), (row["family"], row["assignment_id"]))

    # WORK_UNIT_CASE: 816/14
    def test_case_14_merge_maps_only_to_a27_structure_repair(self):
        row = row_by(self.bundle["decisions"]["wire_kind"], "kind", "Merge")
        self.assertEqual(("StructureRepair", "A-27"), (row["family"], row["assignment_id"]))

    # WORK_UNIT_CASE: 816/15
    def test_case_15_split_maps_to_a27_and_remains_distinct_from_merge(self):
        merge = row_by(self.bundle["decisions"]["wire_kind"], "kind", "Merge")
        split = row_by(self.bundle["decisions"]["wire_kind"], "kind", "Split")
        self.assertEqual("A-27", split["assignment_id"])
        self.assertEqual("StructureRepair", split["family"])
        self.assertNotEqual(merge["wire_order"], split["wire_order"])

    # WORK_UNIT_CASE: 816/16
    def test_case_16_reconsolidation_maps_only_to_a28(self):
        row = row_by(self.bundle["decisions"]["wire_kind"], "kind", "Reconsolidation")
        self.assertEqual(("Reconsolidation", "A-28"), (row["family"], row["assignment_id"]))

    # WORK_UNIT_CASE: 816/17
    def test_case_17_accessibility_maps_only_to_a29(self):
        row = row_by(self.bundle["decisions"]["wire_kind"], "kind", "Accessibility")
        self.assertEqual(("Accessibility", "A-29"), (row["family"], row["assignment_id"]))

    # WORK_UNIT_CASE: 816/18
    def test_case_18_repair_maps_only_to_a30_memory_repair(self):
        row = row_by(self.bundle["decisions"]["wire_kind"], "kind", "Repair")
        self.assertEqual(("MemoryRepair", "A-30"), (row["family"], row["assignment_id"]))

    # WORK_UNIT_CASE: 816/19
    def test_case_19_wire_kind_denominator_is_eleven(self):
        rows = self.bundle["decisions"]["wire_kind"]
        self.assertEqual(11, len(rows))
        self.assertEqual(set(WIRE_FAMILY), {row["kind"] for row in rows})

    # WORK_UNIT_CASE: 816/20
    def test_case_20_wire_family_denominator_is_ten(self):
        families = {row["family"] for row in self.bundle["decisions"]["wire_kind"]}
        self.assertEqual(10, len(families))
        self.assertIn("StructureRepair", families)

    # WORK_UNIT_CASE: 816/21
    def test_case_21_structure_repair_is_not_a_wire_variant(self):
        self.assertNotIn("StructureRepair", {row["kind"] for row in self.bundle["decisions"]["wire_kind"]})
        self.assertNotIn("StructureRepair", {row["kind"] for row in self.bundle["decisions"]["wire_kind"]})

    # WORK_UNIT_CASE: 816/22
    def test_case_22_a39_through_a43_are_separate_job_classes(self):
        rows = self.bundle["decisions"]["excluded_job_class"]
        self.assertEqual({f"A-{n}" for n in range(39, 44)}, {row["assignment_id"] for row in rows})
        self.assertTrue(all(not row["wire_kind"] and not row["curation_kind"] for row in rows))

    # WORK_UNIT_CASE: 816/23
    def test_case_23_a19c_is_the_sole_schema_dependency_into_a20(self):
        matches = [row for row in self.bundle["edges"]["compile_edge"] if row.get("from") == "A-20"]
        self.assertEqual(1, len(matches))
        self.assertEqual("A-19c", matches[0]["to"])

    # WORK_UNIT_CASE: 816/24
    def test_case_24_a31_requires_a20_terminal_result(self):
        runtime = row_by(self.bundle["edges"]["runtime_edge"], "id", "screen-to-curation-dispatch")
        proof = row_by(self.bundle["edges"]["proof_edge"], "id", "screen-eligibility-before-dispatch")
        self.assertEqual(("A-20", "A-31"), (runtime["producer"], runtime["consumer"]))
        self.assertEqual(("A-20", "A-31"), (proof["from"], proof["to"]))

    # WORK_UNIT_CASE: 816/25
    def test_case_25_only_exact_terminal_eligible_dispatches(self):
        policy = self.bundle["decisions"]["topology_policy"]
        self.assertEqual("Eligible", policy["curation_dispatchable_terminal"])
        self.assertIn("exact terminal Eligible", self.bundle["edges"]["runtime_edge"][7]["contract"])

    # WORK_UNIT_CASE: 816/26
    def test_case_26_protected_unknown_invalid_stale_and_incomplete_states_do_not_dispatch(self):
        states = {row["state"] for row in self.bundle["decisions"]["dispatch_rejection_state"]}
        self.assertEqual({"Protected", "ProtectionUnknown", "Malformed", "Stale", "Unavailable", "Partial", "Truncated", "Unprocessed"}, states)
        self.assertTrue(all(row["dispatchable"] is False for row in self.bundle["decisions"]["dispatch_rejection_state"]))

    # WORK_UNIT_CASE: 816/27
    def test_case_27_screening_does_not_choose_handler_kind(self):
        self.assertTrue(self.bundle["decisions"]["topology_policy"]["screen_never_selects_kind"])
        self.assertNotIn("kind", row_by(self.bundle["edges"]["compile_edge"], "from", "A-20")["contract"])

    # WORK_UNIT_CASE: 816/28
    def test_case_28_a31_routes_only_after_eligibility_proof(self):
        proof = row_by(self.bundle["edges"]["proof_edge"], "id", "screen-eligibility-before-dispatch")
        self.assertEqual("proof_before_dispatch", proof["relation"])
        self.assertEqual("A-31", proof["to"])
        self.assertTrue(self.bundle["decisions"]["topology_policy"]["dispatch_requires_explicit_a03_kind"])

    # WORK_UNIT_CASE: 816/29
    def test_case_29_pre_handler_flow_is_a03_value_after_one_a05_gate(self):
        policy = self.bundle["decisions"]["topology_policy"]
        port = row_by(self.bundle["decisions"]["registry_port"], "id", "A-03-validated-values")
        self.assertTrue(policy["dispatch_requires_a05_validated_input"])
        self.assertEqual("A-03", port["owner_assignment"])
        self.assertFalse(policy["repeat_common_validation"])

    # WORK_UNIT_CASE: 816/30
    def test_case_30_a31_has_no_concrete_a05_or_a14b_import(self):
        pairs = compile_pairs(self.bundle)
        self.assertNotIn(("A-31", "A-05"), pairs)
        self.assertNotIn(("A-31", "A-14b"), pairs)
        forbidden = {(row["from"], row["to"]) for row in self.bundle["edges"]["forbidden_topology_compile_edge"]}
        self.assertIn(("A-31", "A-05"), forbidden)
        self.assertIn(("A-31", "A-14b"), forbidden)

    # WORK_UNIT_CASE: 816/31
    def test_case_31_a20_consumes_a19c_without_duplicate_screen_schema(self):
        port = row_by(self.bundle["decisions"]["registry_port"], "id", "A-19c-screen")
        edge = row_by(self.bundle["edges"]["compile_edge"], "from", "A-20")
        self.assertEqual("A-19c", port["owner_assignment"])
        self.assertEqual("A-19c", edge["to"])
        self.assertEqual(1, sum(row["to"] == "A-19c" and row["from"] == "A-20" for row in self.bundle["edges"]["compile_edge"]))

    # WORK_UNIT_CASE: 816/32
    def test_case_32_a31_uses_a03_and_a19c_contract_ports(self):
        ports = {row["id"]: row for row in self.bundle["decisions"]["registry_port"]}
        self.assertEqual("A-03", ports["A-03-validated-values"]["owner_assignment"])
        self.assertEqual("A-19c", ports["A-19c-screen"]["owner_assignment"])
        self.assertTrue(self.bundle["decisions"]["topology_policy"]["dispatch_uses_contract_owned_registry_ports"])

    # WORK_UNIT_CASE: 816/33
    def test_case_33_registry_covers_all_eleven_wire_dispatch_assignments(self):
        wire_ids = {row["assignment_id"] for row in self.bundle["decisions"]["wire_kind"]}
        self.assertEqual({f"A-{n}" for n in range(21, 31)}, wire_ids)
        port = row_by(self.bundle["decisions"]["registry_port"], "id", "A-03-validated-values")
        self.assertEqual(CURATION_HANDLERS, set(port["consumers"]))

    # WORK_UNIT_CASE: 816/34
    def test_case_34_legacy_curation_dtos_are_not_current_screen_owners(self):
        row = row_by(self.bundle["donors"]["topology_donor"], "path", "crates/smart/eliot-memory-curation")
        self.assertNotIn("eliot-memory-curation", row["current_owner"])
        self.assertEqual({"A-19c", "A-20", "A-31"}, set(row["targets"]))

    # WORK_UNIT_CASE: 816/35
    def test_case_35_context_identity_and_order_map_matches_current_manifests(self):
        for assignment_id in CONTEXT_STAGES | {"A-19c", "A-20"}:
            row = assignments_by_id(self.bundle)[assignment_id]
            module = load_toml(ROOT / row["manifest"])
            self.assertEqual((row["module_id"], row["agent_order"]), (module["module_id"], module["agent_order"]))

    # WORK_UNIT_CASE: 816/36
    def test_case_36_context_runtime_chain_is_typed_and_complete(self):
        runtime_ids = {row["id"] for row in self.bundle["edges"]["runtime_edge"]}
        self.assertTrue({"context-projections-to-candidates", "candidates-to-admission", "admission-to-assembly", "assembly-to-reactive-plan", "reactive-plan-to-brctx", "brctx-to-host-transport"} <= runtime_ids)

    # WORK_UNIT_CASE: 816/37
    def test_case_37_a16a_has_canonical_contract_only_compile_edges(self):
        pairs = compile_pairs(self.bundle)
        self.assertTrue({("A-16a", "A-15"), ("A-16a", "A-10"), ("A-16a", "A-06e")} <= pairs)
        self.assertTrue(all(row["relation"] == "contract_only" for row in self.bundle["edges"]["compile_edge"] if row["from"] == "A-16a"))

    # WORK_UNIT_CASE: 816/38
    def test_case_38_a16a_forbids_activation_and_legacy_epistemic_algorithms(self):
        forbidden = {(row["from"], row["to"]) for row in self.bundle["edges"]["forbidden_topology_compile_edge"]}
        self.assertIn(("A-16a", "A-14a"), forbidden)
        self.assertIn(("A-16a", "eliot-epistemic"), forbidden)

    # WORK_UNIT_CASE: 816/39
    def test_case_39_a16a_is_recorded_as_a17a_runtime_producer(self):
        row = row_by(self.bundle["edges"]["runtime_edge"], "id", "candidates-to-admission")
        self.assertEqual(("A-16a", "A-17a", "ContextCandidateSet"), (row["producer"], row["consumer"], row["contract"]))
        self.assertFalse(row["selects_membership"])

    # WORK_UNIT_CASE: 816/40
    def test_case_40_a17a_has_no_a16a_compile_dependency_and_is_sole_admitter(self):
        self.assertNotIn(("A-17a", "A-16a"), compile_pairs(self.bundle))
        owners = [row for row in self.bundle["decisions"]["context_stage"] if row.get("membership_decision")]
        self.assertEqual(["A-17a"], [row["assignment_id"] for row in owners])

    # WORK_UNIT_CASE: 816/41
    def test_case_41_candidates_and_assembly_do_not_choose_final_membership(self):
        stages = {row["assignment_id"]: row for row in self.bundle["decisions"]["context_stage"]}
        self.assertFalse(stages["A-16a"]["membership_decision"])
        self.assertFalse(stages["A-18"]["membership_decision"])
        self.assertTrue(stages["A-17a"]["membership_decision"])

    # WORK_UNIT_CASE: 816/42
    def test_case_42_assembly_requires_admitted_set_and_measurement(self):
        edge = row_by(self.bundle["edges"]["compile_edge"], "from", "A-18")
        proof = row_by(self.bundle["edges"]["proof_edge"], "id", "admitted-set-before-assembly")
        self.assertIn("AdmittedContextSet", edge["contract"])
        self.assertIn("SerializedContextMeasurement", edge["contract"])
        self.assertIn("AdmittedContextSet", proof["evidence"])

    # WORK_UNIT_CASE: 816/43
    def test_case_43_assembly_compiles_against_a15_not_admission_algorithm(self):
        self.assertIn(("A-18", "A-15"), compile_pairs(self.bundle))
        self.assertNotIn(("A-18", "A-17a"), compile_pairs(self.bundle))
        self.assertNotIn(("A-18", "F-STU-migration"), compile_pairs(self.bundle))

    # WORK_UNIT_CASE: 816/44
    def test_case_44_serialized_measurement_has_one_contract_owner_and_one_fstu_implementation(self):
        stages = [row for row in self.bundle["decisions"]["context_stage"] if row.get("measurement_owner")]
        ownership = [row for row in self.bundle["edges"]["ownership_edge"] if row.get("contract", "").startswith("serialized-context")]
        self.assertEqual(["A-15"], [row["assignment_id"] for row in stages])
        self.assertEqual(1, len(ownership))
        self.assertEqual("F-STU", ownership[0]["implementation_owner"])

    # WORK_UNIT_CASE: 816/45
    def test_case_45_a18_preserves_exact_admitted_membership(self):
        row = row_by(self.bundle["edges"]["runtime_edge"], "id", "assembly-to-reactive-plan")
        self.assertTrue(row["preserves_membership"])
        self.assertFalse(row["selects_membership"])
        self.assertIn("A-17a", self.bundle["decisions"]["topology_policy"]["view_membership_owner"])

    # WORK_UNIT_CASE: 816/46
    def test_case_46_reactive_plan_runtime_inputs_and_producer_are_complete(self):
        stage = row_by(self.bundle["decisions"]["context_stage"], "assignment_id", "A-19r")
        for token in ("ContextPlanningView", "ReactiveCueActivation", "SessionDeliverySnapshot", "CriticalAttentionProjection"):
            self.assertIn(token, stage["input_contract"])
        row = row_by(self.bundle["edges"]["runtime_edge"], "id", "reactive-plan-to-brctx")
        self.assertEqual(("A-19r", "B-RCTX"), (row["producer"], row["consumer"]))

    # WORK_UNIT_CASE: 816/47
    def test_case_47_reactive_plan_compile_edges_are_contract_only(self):
        rows = [row for row in self.bundle["edges"]["compile_edge"] if row["from"] == "A-19r"]
        self.assertEqual(3, len(rows))
        self.assertTrue(all(row["relation"] == "contract_only" for row in rows))

    # WORK_UNIT_CASE: 816/48
    def test_case_48_reactive_plan_has_no_concrete_producer_host_or_delivery_import(self):
        pairs = compile_pairs(self.bundle)
        self.assertFalse(any(source == "A-19r" and target in {"A-16a", "A-17a", "A-18", "Host", "B-RCTX", "eliot-cues"} for source, target in pairs))
        forbidden = {(row["from"], row["to"]) for row in self.bundle["edges"]["forbidden_topology_compile_edge"]}
        self.assertTrue({("A-19r", "A-16a"), ("A-19r", "A-17a"), ("A-19r", "A-18")} <= forbidden)

    # WORK_UNIT_CASE: 816/49
    def test_case_49_reactive_plan_does_not_refresh_readmit_reassemble_write_deliver_or_infer_use(self):
        stage = row_by(self.bundle["decisions"]["context_stage"], "assignment_id", "A-19r")
        fields = ("refreshes_providers", "reruns_admission", "reassembles_view", "mutates_session", "delivers_bytes", "infers_use")
        self.assertTrue(all(stage[field] is False for field in fields))
        self.assertFalse(row_by(self.bundle["edges"]["physical_write_edge"], "owner", "A-19r")["physical_write"])

    # WORK_UNIT_CASE: 816/50
    def test_case_50_attention_plan_enqueue_attempt_delivery_ack_visibility_and_use_stages_stay_separate(self):
        self.assertEqual("A-19r", row_by(self.bundle["edges"]["runtime_edge"], "id", "reactive-plan-to-brctx")["producer"])
        self.assertEqual("B-RCTX", row_by(self.bundle["edges"]["physical_write_edge"], "owner", "B-RCTX")["owner"])
        self.assertIn("Host queue/service/transport", row_by(self.bundle["edges"]["physical_write_edge"], "owner", "B-RCTX")["next_owner"])
        self.assertNotEqual("A-19r", self.bundle["decisions"]["topology_policy"]["reactive_plan_delivery_owner"])

    # WORK_UNIT_CASE: 816/51
    def test_case_51_context_understanding_and_cues_donor_dispositions_are_explicit(self):
        paths = {row["path"] for row in self.bundle["donors"]["topology_donor"]}
        self.assertTrue({"crates/smart/eliot-context", "crates/smart/eliot-understanding", "crates/smart/eliot-cues"} <= paths)
        self.assertTrue(all(row.get("observed_disposition") and row.get("uncertainty") for row in self.bundle["donors"]["topology_donor"]))

    # WORK_UNIT_CASE: 816/52
    def test_case_52_readiness_and_admission_relations_do_not_make_runtime_feedback_a_compile_cycle(self):
        self.assertFalse(has_cycle(self.bundle["edges"]["compile_edge"]))
        compile_ids = {row.get("id") for row in self.bundle["edges"].get("compile_edge", [])}
        runtime_ids = {row.get("id") for row in self.bundle["edges"]["runtime_edge"]}
        self.assertTrue(runtime_ids.isdisjoint(compile_ids))

    # WORK_UNIT_CASE: 816/53
    def test_case_53_compile_dependency_graph_is_acyclic(self):
        self.assertFalse(has_cycle(self.bundle["edges"]["compile_edge"]))
        self.assertNotIn(("A-15", "A-16a"), compile_pairs(self.bundle))

    # WORK_UNIT_CASE: 816/54
    def test_case_54_forbidden_compile_edges_are_absent_from_admitted_edges(self):
        admitted = compile_pairs(self.bundle)
        for row in self.bundle["edges"]["forbidden_topology_compile_edge"]:
            self.assertNotIn((row["from"], row["to"]), admitted)
        for mutation in self.fixture["mutations"]:
            mutated = apply_mutation(self.bundle, mutation)
            self.assertTrue(
                topology_errors(mutated),
                f"negative fixture unexpectedly passed: {mutation['id']} ({mutation['expected']})",
            )

    # WORK_UNIT_CASE: 816/55
    def test_case_55_every_curation_dispatch_row_traces_to_screen_eligibility(self):
        port = row_by(self.bundle["decisions"]["registry_port"], "id", "A-20-terminal-evidence")
        proof = row_by(self.bundle["edges"]["proof_edge"], "id", "screen-eligibility-before-dispatch")
        self.assertEqual(CURATION_HANDLERS, set(row_by(self.bundle["decisions"]["registry_port"], "id", "A-03-validated-values")["consumers"]))
        self.assertEqual("A-20", port["owner_assignment"])
        self.assertIn("Eligible", proof["evidence"])

    # WORK_UNIT_CASE: 816/56
    def test_case_56_a15_fstu_a18_measurement_ownership_is_explicit(self):
        row = next(row for row in self.bundle["edges"]["ownership_edge"] if row["owner"] == "A-15")
        self.assertEqual(("F-STU", "A-18"), (row["implementation_owner"], row["consumer"]))
        self.assertIn("measurement", row["contract"])

    # WORK_UNIT_CASE: 816/57
    def test_case_57_a19r_brctx_host_delivery_ownership_is_explicit(self):
        row = next(row for row in self.bundle["edges"]["ownership_edge"] if row["owner"] == "A-19r")
        self.assertEqual(("B-RCTX", "Host queue/service/transport"), (row["implementation_owner"], row["consumer"]))
        runtime = row_by(self.bundle["edges"]["runtime_edge"], "id", "brctx-to-host-transport")
        self.assertEqual(("B-RCTX", "Host queue/service/transport"), (runtime["producer"], runtime["consumer"]))

    # WORK_UNIT_CASE: 816/58
    def test_case_58_all_old_and_new_rows_reconcile_across_four_files(self):
        self.assertEqual(set(EXPECTED_ASSIGNMENTS), set(assignments_by_id(self.bundle)))
        self.assertEqual(set(WIRE_FAMILY), {row["kind"] for row in self.bundle["decisions"]["wire_kind"]})
        edge_refs = {row["from"] for row in self.bundle["edges"]["compile_edge"]} | {row["to"] for row in self.bundle["edges"]["compile_edge"]}
        self.assertTrue({"A-15", "A-16a", "A-17a", "A-18", "A-19r", "A-19c", "A-20", "A-31"} <= edge_refs)
        self.assertTrue(topology_errors(self.bundle) == [])

    # WORK_UNIT_CASE: 816/59
    def test_case_59_git_delta_is_limited_to_four_metadata_files_suite_fixture_and_marker(self):
        result = subprocess.run(["git", "diff", "--name-only", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True)
        tracked = {line.replace("\\", "/") for line in result.stdout.splitlines() if line}
        self.assertTrue(tracked <= TASK_PATHS)
        status = subprocess.run(["git", "status", "--short", "--untracked-files=all"], cwd=ROOT, capture_output=True, text=True, check=True)
        visible = {line[3:].replace("\\", "/") for line in status.stdout.splitlines() if len(line) >= 4 and line[0:2] in {"??", " M", "M ", "D ", " D"}}
        self.assertTrue(visible <= TASK_PATHS or all(path.startswith(".eliot/") for path in visible - TASK_PATHS))

    # WORK_UNIT_CASE: 816/60
    def test_case_60_metadata_ceiling_has_no_leaf_schema_cargo_algorithm_or_runtime_claim(self):
        topology = self.bundle["wave"]["topology"]
        self.assertEqual("TOPOLOGY_METADATA_AND_REGRESSION_GUARD", topology["proof_ceiling"])
        self.assertFalse(topology["runtime_completion"])
        self.assertFalse(topology["product_acceptance"])
        changed = subprocess.run(["git", "diff", "--name-only", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.splitlines()
        self.assertTrue(all(not path.startswith(("crates/smart/eliot-", "Cargo", "bins/")) for path in changed))


if __name__ == "__main__":
    unittest.main()
