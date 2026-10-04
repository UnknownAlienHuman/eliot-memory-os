"""Fail-closed excluded-disposition gate proof (issue #1811, slice 2 / go15).

Covers the REMAINDER from slice 1: every standalone/excluded package carries
a checked-in disposition verb (KEEP/WRAP/EXTRACT/REWORK/REPLACE/RETIRE/UNKNOWN)
plus a named owner, and any build/release consumption of an inventoried
package without provenance, lock, toolchain, license, and SBOM evidence is
rejected.

Slice 2 also proves the ONE admitted route around that refusal: a row that
declares the evidence-qualified state and binds every required evidence element
becomes an admitted separate package its consumer edges are allowed to reach,
while a row with an unbound element, or a non-production disposition verb
(UNKNOWN/REPLACE/RETIRE), stays refused however much evidence it presents.

Each gate case asserts the gate's OWN `EXCLUDED_DISPOSITIONS: FAIL rows=N
issues=K` summary, so a case proves it reached its intended branch instead of
merely finding a matching word somewhere in a multi-failure run.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "workstreams/security/standalone-crate-dispositions.toml"
GATE = ROOT / "scripts/verify-excluded-dispositions-1811.py"
DISCOVERY_OWNER = ROOT / "scripts/verify-standalone-crates.py"
ALLOWED = {"KEEP", "WRAP", "EXTRACT", "REWORK", "REPLACE", "RETIRE", "UNKNOWN"}

# The gate's own constants this proof asserts against. They are restated here,
# not imported from the gate, so a change to the gate that moves one of them
# fails this proof instead of silently moving the oracle with it.
EVIDENCE = "provenance, lock, toolchain, license, SBOM"
REQUIRED_EVIDENCE = (
    "source_identity",
    "independent_lock",
    "build_fingerprint",
    "license",
    "advisory",
    "sbom",
    "artifact_hash",
    "artifact_signature",
    "test_canary",
    "owner",
    "rollback",
    "trust_class",
    "cache_namespace",
    "admitted_use",
)
EVIDENCE_BOUND = "bound"
TRUST_CLASSES = ("T0", "T1", "T2")
EVIDENCE_ADMITTED_USES = ("production",)
DENY_MARKER = "deny-all"
EVIDENCE_ADMISSION = "evidence-qualified"
NON_PRODUCTION_DISPOSITIONS = {"UNKNOWN", "REPLACE", "RETIRE"}

# The one consumer edge this fixture tree can produce: the consumer's own
# manifest declaring a path dependency on the standalone package.
CONSUMER_SOURCE = "consumer/Cargo.toml"
CONSUMER_EDGE = (
    f"{CONSUMER_SOURCE} cargo-manifest [target-runtime] -> standalone-a "
    "(standalone-a -> standalone-a (path = ../standalone-a))"
)

SUMMARY = re.compile(r"^EXCLUDED_DISPOSITIONS: .*$", re.MULTILINE)
FAILURE_LINE = re.compile(r"^  - (.*)$", re.MULTILINE)
RECEIPT_PATH = re.compile(r"receipt=(\S+)")


def run_gate(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(GATE), "--root", str(root)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )


def summary_line(completed: subprocess.CompletedProcess) -> str:
    match = SUMMARY.search(completed.stdout)
    assert match is not None, completed.stdout + completed.stderr
    return match.group(0)


def failure_lines(completed: subprocess.CompletedProcess) -> list[str]:
    """The gate's refusal lines, which are also `receipt["failures"]`."""
    return FAILURE_LINE.findall(completed.stdout)


def read_receipt(completed: subprocess.CompletedProcess) -> dict:
    match = RECEIPT_PATH.search(completed.stdout)
    assert match is not None, completed.stdout + completed.stderr
    return json.loads(Path(match.group(1)).read_text(encoding="utf-8"))


def admitted_paths(receipt: dict) -> set[str]:
    """The gate's own `admitted_paths` derivation, recomputed from the receipt.

    `main` builds it from the per-row admission decisions; reading it back out
    of the receipt keeps the assertion on the gate's decision rather than on a
    test-local reimplementation of it.
    """
    return {
        decision["path"]
        for decision in receipt["admission"]["qualified"]
        if decision["decision"] == "admitted"
    }


def evidence_table(elements: tuple[str, ...]) -> str:
    """A `[crate.supply_chain_evidence]` table binding every named element."""
    lines = ["[crate.supply_chain_evidence]"]
    for element in elements:
        lines.append(f"[crate.supply_chain_evidence.{element}]")
        lines.append(f'state = "{EVIDENCE_BOUND}"')
        binding = {
            "trust_class": TRUST_CLASSES[0],
            "admitted_use": EVIDENCE_ADMITTED_USES[0],
        }.get(element, f"fixture::{element}")
        lines.append(f'binding = "{binding}"')
    return "\n".join(lines) + "\n"


def inventory_head(evidence_qualified_rows: int) -> str:
    """The declared denominators every fixture row set must be read against."""
    return (
        "standalone_package_count = 1\n"
        f'allowed_admission_states = ["{DENY_MARKER}", "{EVIDENCE_ADMISSION}"]\n'
        f'evidence_qualified_state = "{EVIDENCE_ADMISSION}"\n'
        f"evidence_qualified_package_count = {evidence_qualified_rows}\n"
    )


def crate_row(disposition: str, admission: str, evidence_reference: str) -> str:
    return (
        "[[crate]]\n"
        'path = "standalone-a"\n'
        'package = "standalone-a"\n'
        f'disposition = "{disposition}"\n'
        'owner = "fixture-owner"\n'
        f'supply_chain_admission = "{admission}"\n'
        f'evidence_reference = "{evidence_reference}"\n'
    )


def deny_all_inventory() -> str:
    return inventory_head(0) + crate_row("REWORK", DENY_MARKER, DENY_MARKER)


def qualified_inventory(
    disposition: str = "KEEP",
    elements: tuple[str, ...] = REQUIRED_EVIDENCE,
) -> str:
    return (
        inventory_head(1)
        + crate_row(disposition, EVIDENCE_ADMISSION, f"{EVIDENCE_ADMISSION}/standalone-a.json")
        + "\n"
        + evidence_table(elements)
    )


@contextmanager
def fixture_repo(inventory_body: str, consumer_depends: bool = True) -> Iterator[Path]:
    """A temp tree the gate can decide about with exactly one refusal subject.

    The tree carries everything the gate refuses without: the discovery owner it
    derives the denominator through, its OWN bytes (the generator version is the
    digest of `scripts/verify-excluded-dispositions-1811.py`, so a fixture
    without them cannot bind a generator at all), the inventory with its declared
    denominators, and one standalone package plus one consumer.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "workstreams/security").mkdir(parents=True)
        (root / INVENTORY.relative_to(ROOT)).write_text(inventory_body, encoding="utf-8")
        (root / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["consumer"]\nexclude = []\n', encoding="utf-8"
        )
        stand = root / "standalone-a"
        stand.mkdir()
        # The package's own `[workspace]` table is what makes it standalone:
        # the discovery owner selects exactly this shape.
        (stand / "Cargo.toml").write_text(
            '[package]\nname = "standalone-a"\nversion = "0.1.0"\nedition = "2021"\n\n[workspace]\n',
            encoding="utf-8",
        )
        consumer = root / "consumer"
        consumer.mkdir()
        manifest = '[package]\nname = "consumer"\nversion = "0.1.0"\nedition = "2021"\n'
        if consumer_depends:
            manifest += '\n[dependencies]\nstandalone-a = { path = "../standalone-a" }\n'
        (consumer / "Cargo.toml").write_text(manifest, encoding="utf-8")
        (root / "scripts").mkdir(parents=True, exist_ok=True)
        (root / "scripts/verify-standalone-crates.py").write_bytes(
            DISCOVERY_OWNER.read_bytes()
        )
        (root / "scripts/verify-excluded-dispositions-1811.py").write_bytes(GATE.read_bytes())
        yield root


class TestExcludedDispositionsGate1811(unittest.TestCase):
    def test_every_row_has_disposition_verb_and_named_owner(self) -> None:
        data = tomllib.loads(INVENTORY.read_text(encoding="utf-8"))
        rows = data.get("crate", [])
        self.assertEqual(len(rows), data.get("standalone_package_count"), "must cover the standalone denominator")
        for row in rows:
            with self.subTest(crate=row.get("path")):
                self.assertIn(str(row.get("disposition")), ALLOWED)
                self.assertTrue(str(row.get("owner", "")).strip())

    def test_gate_passes_on_current_tree(self) -> None:
        completed = run_gate(ROOT)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("EXCLUDED_DISPOSITIONS: PASS", completed.stdout)

    def test_gate_rejects_consumer_without_evidence(self) -> None:
        with fixture_repo(deny_all_inventory()) as root:
            completed = run_gate(root)
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            # issues=1 is the proof that this case's subject is the consumer edge
            # and not one of the fixture's other refusals (missing generator
            # bytes, undeclared denominators, undeclared admission state).
            self.assertEqual(
                summary_line(completed),
                "EXCLUDED_DISPOSITIONS: FAIL rows=1 issues=1",
                completed.stdout,
            )
            self.assertEqual(
                failure_lines(completed),
                [
                    "undeclared excluded-input consumption without "
                    f"{EVIDENCE} evidence: {CONSUMER_EDGE}"
                ],
                completed.stdout,
            )
            receipt = read_receipt(completed)
            # The deny marker is a decision, not a refusal: the row is denied,
            # so `admitted_paths` is empty and the edge it reaches is unevidenced.
            self.assertEqual(receipt["admission_policy"], DENY_MARKER)
            self.assertEqual(receipt["admission"]["admitted_packages"], [])
            self.assertEqual(receipt["admission"]["denied_packages"], ["standalone-a"])
            self.assertEqual(admitted_paths(receipt), set())
            edges = receipt["consumer_edges"]
            self.assertEqual(len(edges), 1)
            edge = edges[0]
            self.assertEqual(edge["kind"], "cargo-manifest")
            self.assertEqual(edge["role"], "target-runtime")
            self.assertEqual(edge["section"], "dependencies")
            self.assertEqual(edge["source"], CONSUMER_SOURCE)
            self.assertEqual(edge["package_path"], "standalone-a")
            self.assertNotIn(edge["package_path"], admitted_paths(receipt))

    def test_gate_admits_evidence_qualified_package(self) -> None:
        with fixture_repo(qualified_inventory()) as root:
            completed = run_gate(root)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(
                summary_line(completed),
                "EXCLUDED_DISPOSITIONS: PASS rows=1 consumers=1 locked=0 "
                "admitted_separate_packages=1 admission_policy=evidence-qualified",
                completed.stdout,
            )
            self.assertEqual(failure_lines(completed), [])
            receipt = read_receipt(completed)
            self.assertEqual(receipt["admission_policy"], EVIDENCE_ADMISSION)
            self.assertEqual(receipt["admission"]["admitted_packages"], ["standalone-a"])
            qualified = receipt["admission"]["qualified"]
            self.assertEqual(len(qualified), 1)
            self.assertEqual(qualified[0]["decision"], "admitted")
            self.assertEqual(qualified[0]["unbound_elements"], [])
            self.assertEqual(qualified[0]["evidence"]["trust_class"], TRUST_CLASSES[0])
            self.assertEqual(qualified[0]["evidence"]["admitted_use"], EVIDENCE_ADMITTED_USES[0])
            self.assertEqual(
                sorted(qualified[0]["evidence"]), sorted(REQUIRED_EVIDENCE)
            )
            # The edge case 3 refused is the edge this row admits: the
            # previously unevidenced consumer edge is now the admitted one, so
            # no unevidenced edge is left.
            edges = receipt["consumer_edges"]
            self.assertEqual(len(edges), 1)
            edge = edges[0]
            self.assertEqual(edge["kind"], "cargo-manifest")
            self.assertEqual(edge["role"], "target-runtime")
            self.assertEqual(edge["source"], CONSUMER_SOURCE)
            self.assertEqual(edge["package_path"], "standalone-a")
            self.assertIn(edge["package_path"], admitted_paths(receipt))
            self.assertEqual(
                [item for item in edges if item["package_path"] not in admitted_paths(receipt)],
                [],
            )

    def test_gate_rejects_unbound_evidence_element(self) -> None:
        omitted = "sbom"
        elements = tuple(element for element in REQUIRED_EVIDENCE if element != omitted)
        # The consumer declares NO dependency here on purpose: with an edge
        # present the gate reports the unbound element AND the unevidenced edge
        # (issues=2), which is exactly the confound this proof removes. The row
        # refuses before any consumer question is asked, so the isolated tree
        # still proves the fail-closed direction.
        with fixture_repo(qualified_inventory(elements=elements), consumer_depends=False) as root:
            completed = run_gate(root)
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(
                summary_line(completed),
                "EXCLUDED_DISPOSITIONS: FAIL rows=1 issues=1",
                completed.stdout,
            )
            self.assertEqual(
                failure_lines(completed),
                [f"standalone-a: evidence element {omitted!r} is missing or is not a table"],
                completed.stdout,
            )
            receipt = read_receipt(completed)
            self.assertEqual(receipt["failures"], failure_lines(completed))
            self.assertNotEqual(receipt["admission_policy"], EVIDENCE_ADMISSION)
            self.assertEqual(receipt["admission_policy"], DENY_MARKER)
            self.assertEqual(receipt["admission"]["admitted_packages"], [])
            self.assertEqual(admitted_paths(receipt), set())
            qualified = receipt["admission"]["qualified"]
            self.assertEqual(len(qualified), 1)
            self.assertEqual(qualified[0]["decision"], "denied")
            self.assertEqual(qualified[0]["unbound_elements"], [omitted])

    def test_gate_rejects_non_production_disposition_even_when_qualified(self) -> None:
        disposition = "RETIRE"
        self.assertIn(disposition, NON_PRODUCTION_DISPOSITIONS)
        with fixture_repo(qualified_inventory(disposition=disposition)) as root:
            completed = run_gate(root)
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            # Every element IS bound here, so the only row refusal is the
            # disposition verb; the second refusal is its consequence, the same
            # consumer edge the qualified row in case 4 is allowed to reach.
            self.assertEqual(
                summary_line(completed),
                "EXCLUDED_DISPOSITIONS: FAIL rows=1 issues=2",
                completed.stdout,
            )
            self.assertEqual(
                failure_lines(completed),
                [
                    f"standalone-a: disposition {disposition} is never admissible "
                    "as a production input",
                    "undeclared excluded-input consumption without "
                    f"{EVIDENCE} evidence: {CONSUMER_EDGE}",
                ],
                completed.stdout,
            )
            receipt = read_receipt(completed)
            self.assertEqual(receipt["failures"], failure_lines(completed))
            self.assertEqual(receipt["admission_policy"], DENY_MARKER)
            self.assertEqual(receipt["admission"]["admitted_packages"], [])
            self.assertEqual(admitted_paths(receipt), set())
            qualified = receipt["admission"]["qualified"]
            self.assertEqual(len(qualified), 1)
            self.assertEqual(qualified[0]["decision"], "denied")
            # The row was refused for its disposition, not for missing evidence.
            self.assertEqual(qualified[0]["unbound_elements"], [])
            self.assertEqual(
                qualified[0]["reasons"][0],
                f"standalone-a: disposition {disposition} is never admissible as a production input",
            )


if __name__ == "__main__":
    unittest.main()
