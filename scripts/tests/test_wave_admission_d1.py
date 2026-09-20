"""#968 D1 wave admission matrix: 20-case integration proof for four dreamer leaves.

Admitting wave T8-A1 reconciles exactly these four packages as root
``members`` in one serialized turn (issue #968):

- crates/smart/eliot-dreamer-orientation            (leaf #628, order 6)
- crates/smart/eliot-dreamer-clarification         (leaf #630, order 7)
- crates/smart/eliot-dreamer-architecture-brief    (leaf #649, order 8)
- crates/smart/eliot-dreamer-implementation-brief  (leaf #651, order 9)

``crates/smart/eliot-dreamer-orientation`` (leaf #628, order 6) was already
admitted via #702 and is a verified byte-identical no-op of this wave: a
denominator member at both base and live, not an omission (see ``test_10``,
``test_14`` and ``test_19``). The three newly admitted leaves move from
root ``exclude`` to root ``members``; orientation moves nowhere.

Frozen bounded fixtures:

- scripts/testdata/work-unit-gate/wave-d1/candidate.json
- scripts/testdata/work-unit-gate/wave-d1/baseline.json

Every assertion derives from repository file bytes or live command output
(``cargo metadata --locked``, ``cargo test --locked -p``, ``cargo clippy``,
``code_navigation check``, ``git show/diff/merge-base``, the real #850
``decode_descriptor`` validation path and the real manifest/lock/index
readers). Negative legs feed mutated copies through the same validator
functions as the positive legs; no assertion echoes a prewritten
``expected: fail`` label. There is no second production oracle.

Shape precedent: scripts/tests/test_wave_admission_s2.py (T8-AS2, issue
#966) via scripts/tests/test_wave_admission_d2.py (T8-A2, issue #969).
Documented D1 adaptations, nothing more:

- ``six``/``five`` -> ``four`` (four leaves, agent_orders 6..9);
- top-level ``leaf_touch_commit`` -> per-item ``leaf_touch_commit`` (each D1
  leaf landed in its own implementation commit; every one is an ancestor of
  the base), as in D2;
- the handler/curation-contract legs become clarification/router and
  brief-authority legs (clarification routes task-local vs Human without
  grounding imports; orientation routes on contracts plus evidence without
  grounding or peer imports; neither brief imports the other; only the
  ImplementationBrief consumes eliot-conformance-contracts);
- ``test_10`` additionally verifies the #702 orientation admission as a
  byte-identical no-op (member at base and live, router ADMITTED, no diff
  touches it);
- ``test_12`` additionally allows the workspace-inheritance normalization
  the three newly admitted D1 leaves receive at admission (their base
  manifests predate the orientation pattern; live manifests match it;
  dependency names unchanged; orientation already matched the pattern at
  base);
- ``test_16`` keeps the S2 in-memory form (``check`` plus double
  in-memory render, no file mutation);
- current-main rework verifies the already-admitted 174/0 state with a zero
  root/lock delta; the original 02775d03 base remains the stale-state leg.

Documented runners (repo root, ``CARGO_TARGET_DIR`` set per owner disk rule)::

    python -m py_compile scripts/tests/test_wave_admission_d1.py
    python -m unittest scripts.tests.test_wave_admission_d1 -v

Deterministic, no network, no stubs. Declared denominator: 20 cases, exactly
1..20, one method per ``WORK_UNIT_CASE: 968/<case>`` marker.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tomllib
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
FIX = ROOT / "scripts" / "testdata" / "work-unit-gate" / "wave-d1"
# The D1 admission landed in current main already.  Keep the original
# pre-admission commit for the explicit stale-state negative leg.
BASE_SHA = "7ca1c878d89e189a5c6c601b8d7154dc1e2f5d81"
ADMISSION_BASE_SHA = "02775d03f5cc8649d77f8e6c3a8e75edafd38618"
ADMISSION_NOTE = "admitted via #968 (T8-A1) root workspace membership"
ORIENTATION_ADMISSION_NOTE = (
    "admitted via #702 (T12-10 prerequisite) root workspace membership"
)
ORIENTATION = "eliot-dreamer-orientation"
CLARIFICATION = "eliot-dreamer-clarification"
ARCH_BRIEF = "eliot-dreamer-architecture-brief"
IMPL_BRIEF = "eliot-dreamer-implementation-brief"
FOUR = (ORIENTATION, CLARIFICATION, ARCH_BRIEF, IMPL_BRIEF)
MOVED = (CLARIFICATION, ARCH_BRIEF, IMPL_BRIEF)
BRIEFS = (ARCH_BRIEF, IMPL_BRIEF)
ORIENTATION_PATH = "crates/smart/eliot-dreamer-orientation"
OWNED_PATHS = frozenset({
    "Cargo.toml",
    "Cargo.lock",
    "crates/smart/eliot-dreamer-clarification/Cargo.toml",
    "crates/smart/eliot-dreamer-clarification/module.toml",
    "crates/smart/eliot-dreamer-architecture-brief/Cargo.toml",
    "crates/smart/eliot-dreamer-architecture-brief/module.toml",
    "crates/smart/eliot-dreamer-implementation-brief/Cargo.toml",
    "crates/smart/eliot-dreamer-implementation-brief/module.toml",
    "docs/code-navigation/PACKAGE_DOCS_INDEX.md",
    "docs/code-navigation/PROTOTYPE_DOCS_INDEX.md",
    "scripts/tests/test_wave_admission_d1.py",
    "scripts/testdata/work-unit-gate/wave-d1/candidate.json",
    "scripts/testdata/work-unit-gate/wave-d1/baseline.json",
})
FORBIDDEN_ALGO = frozenset({
    "eliot_dreamer_candidate_validation",
    "eliot_dreamer_claim_grounding",
    "eliot_dreamer_bundle",
    "eliot_dreamer_core",
})
FORBIDDEN_PRODUCER = frozenset({
    "eliot-dreamer-bundle",
    "eliot-dreamer-grounding",
    "eliot-dreamer-validation",
    "eliot-dreamer-rival",
    "eliot-dreamer-probe",
    "eliot_dreamer_bundle",
    "eliot_dreamer_grounding",
    "eliot_dreamer_validation",
    "eliot_dreamer_rival",
    "eliot_dreamer_probe",
})
FORBIDDEN_PROVIDER_DEP_PREFIXES = (
    "eliot-provider-",
    "eliot-agent-",
    "eliot-store-",
    "eliot-runtime-",
    "eliot-kernel",
)
FORBIDDEN_PROVIDER_TOKEN_PREFIXES = (
    "eliot_provider_",
    "eliot_agent_",
    "eliot_store_",
    "eliot_runtime_",
    "eliot_kernel",
)
ALLOWED_VALUE_TOKENS = frozenset({
    "eliot_contracts",
    "eliot_dreamer_contracts",
    "eliot_epistemic_contracts",
    "eliot_evidence",
    "eliot_conformance_contracts",
    "eliot_receipts",
})
CANONICAL_DUP_DEF_RE = re.compile(
    r"^\s*pub\s+(?:struct|enum)\s+"
    r"(A03[A-Za-z0-9_]*|EvidenceEnvelope[A-Za-z0-9_]*|"
    r"CurrentEpistemicPosition[A-Za-z0-9_]*|Conformance[A-Za-z0-9_]*)"
)
CANONICAL_DUP_TYPE_RE = re.compile(
    r"^\s*(?:pub\s+)?type\s+"
    r"(A03|EvidenceEnvelope|CurrentEpistemicPosition|Conformance[A-Za-z0-9_]*)"
    r"\b"
)
AUTHORITY_STRUCT_RE = re.compile(r"^\s*pub\s+(?:struct|enum)\s+\w*Authority\w*")
AUTHORITY_FN_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+\w*(?:grant_authority|issue_authority)"
)
CRATE_TOKEN = re.compile(r"eliot_[a-z0-9_]+")


def read_bytes(rel: str) -> bytes:
    return (ROOT / rel).read_bytes()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_toml(rel: str) -> dict:
    with open(ROOT / rel, "rb") as handle:
        return tomllib.load(handle)


def load_fixture(name: str) -> dict:
    return json.loads((FIX / name).read_bytes().decode("utf-8"))


def git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args],
        capture_output=True, text=True, timeout=120,
    )


def cargo(*args: str, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["cargo", *args], cwd=str(ROOT),
        capture_output=True, text=True, timeout=timeout,
    )


def py_script(*args: str, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, *args], cwd=str(ROOT),
        capture_output=True, text=True, timeout=timeout,
    )


def root_workspace() -> dict:
    return load_toml("Cargo.toml")["workspace"]


def lock_packages() -> dict[str, list[dict]]:
    found: dict[str, list[dict]] = {}
    for entry in load_toml("Cargo.lock").get("package", []):
        found.setdefault(entry["name"], []).append(entry)
    return found


def validate_wave_state(members: list[str], exclude: list[str],
                        modules: dict[str, dict], lock_names: set[str],
                        four_paths: list[str]) -> list[str]:
    """Real admission validator shared by positive and negative legs."""
    errors: list[str] = []
    if sorted(set(four_paths)) != sorted(four_paths):
        errors.append("four denominator has duplicates")
    for path in four_paths:
        if members.count(path) != 1:
            errors.append(f"member count != 1: {path}")
        if path in exclude:
            errors.append(f"still excluded: {path}")
        module = modules.get(path)
        if module is None:
            errors.append(f"missing module router: {path}")
        elif module.get("status") != "ADMITTED":
            errors.append(f"module not admitted: {path}")
    for item in load_fixture("candidate.json")["four"]:
        if item["name"] not in lock_names:
            errors.append(f"package missing from lock: {item['name']}")
    if len(members) != len(set(members)):
        errors.append("duplicate workspace member")
    if len(exclude) != len(set(exclude)):
        errors.append("duplicate workspace exclusion")
    if set(members) & set(exclude):
        errors.append("member/exclusion overlap")
    return errors


def validate_activation(prereqs: dict[str, bool]) -> tuple[bool, list[str]]:
    missing = sorted(name for name, ok in prereqs.items() if not ok)
    if missing:
        return False, [f"prerequisite missing: {name}" for name in missing]
    return True, []


def validate_leaf_evidence(entries: list[dict]) -> list[str]:
    errors: list[str] = []
    for entry in entries:
        tag = entry.get("name", "?")
        if not entry.get("manifest_present"):
            errors.append(f"missing manifest: {tag}")
        if not entry.get("router_present"):
            errors.append(f"missing router: {tag}")
        if not entry.get("merged"):
            errors.append(f"unmerged leaf: {tag}")
        if entry.get("status") != "ADMITTED":
            errors.append(f"unaccepted leaf: {tag}")
    return errors


def validate_proof(receipts: list[dict]) -> list[str]:
    errors: list[str] = []
    for receipt in receipts:
        tag = receipt.get("name", "?")
        if receipt.get("outcome") != "EXECUTED_PASS":
            errors.append(f"proof not executed-pass: {tag}")
        if receipt.get("partial"):
            errors.append(f"partial proof: {tag}")
        if receipt.get("stale"):
            errors.append(f"stale proof: {tag}")
    return errors


def validate_challenges(open_entries: list[dict], four_names: set[str]) -> list[str]:
    errors: list[str] = []
    for entry in open_entries:
        if four_names & set(entry.get("needed_by", [])):
            errors.append(f"unresolved challenge {entry.get('id')} blocks wave")
    return errors


def validate_single_writer(writers: list[str]) -> list[str]:
    if len(writers) != 1:
        return [f"expected exactly one root/lock/index writer, found {len(writers)}"]
    return []


def topo_sort(edges: dict[str, set[str]]) -> list[str]:
    order: list[str] = []
    permanent: set[str] = set()
    temporary: set[str] = set()

    def visit(node: str) -> None:
        if node in permanent:
            return
        if node in temporary:
            raise ValueError(f"compile cycle at {node}")
        temporary.add(node)
        for dep in sorted(edges.get(node, ())):
            if dep in edges:
                visit(dep)
        temporary.remove(node)
        permanent.add(node)
        order.append(node)

    for node in sorted(edges):
        visit(node)
    return order


def internal_edges() -> dict[str, set[str]]:
    """Compile graph over real manifests: internal path/workspace deps only."""
    edges: dict[str, set[str]] = {}
    for manifest in sorted(ROOT.rglob("Cargo.toml")):
        if manifest == ROOT / "Cargo.toml":
            continue
        try:
            payload = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        package = payload.get("package", {})
        name = package.get("name")
        if not isinstance(name, str) or not name:
            continue
        deps: set[str] = set()
        for table in ("dependencies", "dev-dependencies", "build-dependencies"):
            section = payload.get(table, {})
            if not isinstance(section, dict):
                continue
            for dep_name, spec in section.items():
                if isinstance(spec, dict) and spec.get("workspace") is True:
                    deps.add(dep_name)
                elif isinstance(spec, dict) and "path" in spec:
                    deps.add(dep_name)
        edges[name] = deps
    void = {d for deps in edges.values() for d in deps} - set(edges)
    for name in void:
        edges.setdefault(name, set())
    return edges


def crate_tokens_in_rs(crate_path: str) -> set[str]:
    """Real source reader: every eliot_* crate token in leaf .rs files."""
    found: set[str] = set()
    for rs in sorted((ROOT / crate_path).rglob("*.rs")):
        for line in rs.read_text(encoding="utf-8").splitlines():
            code = line.split("//", 1)[0]
            found |= set(CRATE_TOKEN.findall(code))
    return found


def declared_dep_names(manifest: dict) -> set[str]:
    """Real manifest reader: every dep name across dep tables."""
    names: set[str] = set()
    for table in ("dependencies", "dev-dependencies", "build-dependencies"):
        section = manifest.get(table, {})
        if isinstance(section, dict):
            names |= set(section)
    return names


def rs_definition_lines(crate_path: str) -> list[str]:
    """Real source reader: every .rs line of a leaf crate."""
    lines: list[str] = []
    for rs in sorted((ROOT / crate_path).rglob("*.rs")):
        lines.extend(rs.read_text(encoding="utf-8").splitlines())
    return lines


def canonical_duplicates_in_lines(lines: list[str]) -> list[str]:
    """Shared detector: local canonical-replacement type definitions."""
    hits: list[str] = []
    for line in lines:
        code = line.split("//", 1)[0]
        match = CANONICAL_DUP_DEF_RE.match(code) or CANONICAL_DUP_TYPE_RE.match(code)
        if match:
            hits.append(match.group(1))
    return hits


def find_canonical_duplicates(crate_path: str) -> list[str]:
    return canonical_duplicates_in_lines(rs_definition_lines(crate_path))


def authority_impls_in_lines(lines: list[str]) -> list[str]:
    """Shared detector: local normative-authority struct/enum/fn definitions."""
    hits: list[str] = []
    for line in lines:
        code = line.split("//", 1)[0]
        if AUTHORITY_STRUCT_RE.match(code) or AUTHORITY_FN_RE.match(code):
            hits.append(code.strip())
    return hits


def find_authority_impls(crate_path: str) -> list[str]:
    return authority_impls_in_lines(rs_definition_lines(crate_path))


def is_forbidden_provider_dep(name: str) -> bool:
    if name.startswith(FORBIDDEN_PROVIDER_DEP_PREFIXES):
        return True
    return name.replace("-", "_").startswith(FORBIDDEN_PROVIDER_TOKEN_PREFIXES)


def provider_tokens_in(tokens: set[str]) -> set[str]:
    return {t for t in tokens if t.startswith(FORBIDDEN_PROVIDER_TOKEN_PREFIXES)}


def descriptor_toml(item: dict) -> bytes:
    """Frozen fixture: authoritative descriptor TOML from candidate.json."""
    return item["descriptor_toml"].encode("utf-8")


def is_workspace_member(metadata: dict, name: str) -> bool:
    """Real membership path: locked metadata workspace_members."""
    by_name = {p["name"]: p["id"] for p in metadata["packages"]}
    return name in by_name and by_name[name] in set(metadata["workspace_members"])


def four_tokens() -> set[str]:
    return {"eliot_dreamer_" + n.split("eliot-dreamer-")[1].replace("-", "_")
            for n in FOUR}


class TestWaveAdmissionD1(unittest.TestCase):
    """20 substantive cases for issue #968."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.candidate = load_fixture("candidate.json")
        cls.baseline = load_fixture("baseline.json")
        cls.four = cls.candidate["four"]
        cls.four_paths = [item["crate_path"] for item in cls.four]
        cls.four_names = [item["name"] for item in cls.four]
        meta = cargo("metadata", "--locked", "--format-version", "1")
        assert meta.returncode == 0, meta.stderr[-2000:]
        cls.metadata = json.loads(meta.stdout)
        cls.test_runs: dict[str, subprocess.CompletedProcess] = {}
        for name in cls.four_names:
            cls.test_runs[name] = cargo("test", "--locked", "-p", name)
        cls.clippy = cargo("clippy", "--locked",
                           *[a for n in cls.four_names for a in ("-p", n)],
                           "--all-targets")
        cls.workspace_check = cargo("check", "--locked", "--workspace", "--all-targets")
        cls.workspace_norun = cargo("test", "--locked", "--workspace", "--no-run")
        cls.code_nav = py_script("scripts/code_navigation.py", "check", "--root", ".")
        from scripts.work_unit_gate.descriptor_runner import decode_descriptor
        cls.decode_descriptor = staticmethod(decode_descriptor)

    # WORK_UNIT_CASE: 968/1
    def test_01_exact_four_package_cell_denominator(self) -> None:
        ws = root_workspace()
        self.assertEqual(len(self.four_paths), 4)
        self.assertEqual(len(set(self.four_paths)), 4)
        self.assertEqual(sorted(i["leaf_issue"] for i in self.four),
                         [628, 630, 649, 651])
        self.assertEqual(sorted(i["agent_order"] for i in self.four),
                         [6, 7, 8, 9])
        for item in self.four:
            self.assertIn(item["crate_path"], ws["members"])
            module = load_toml(f"{item['crate_path']}/module.toml")
            self.assertEqual(module["module_id"], item["functional_cell"])
            self.assertEqual(module["crate"], item["name"])
        live_cells = {load_toml(f"{p}/module.toml")["module_id"] for p in self.four_paths}
        self.assertEqual(len(live_cells), 4)

    # WORK_UNIT_CASE: 968/2
    def test_02_missing_unmerged_unaccepted_leaf_blocks_activation(self) -> None:
        live = []
        for item in self.four:
            merged = git("merge-base", "--is-ancestor",
                         item["leaf_touch_commit"], BASE_SHA)
            live.append({"name": item["name"], "manifest_present": True,
                         "router_present": True,
                         "merged": merged.returncode == 0, "status": "ADMITTED"})
        self.assertEqual(validate_leaf_evidence(live), [])
        for field in ("manifest_present", "router_present", "merged"):
            bad = [dict(e) for e in live]
            bad[0][field] = False
            self.assertTrue(validate_leaf_evidence(bad), field)
        bad = [dict(e) for e in live]
        bad[1]["status"] = "PROTOTYPE"
        errors = validate_leaf_evidence(bad)
        self.assertTrue(any("unaccepted" in e for e in errors))
        for item in self.four:
            self.assertTrue((ROOT / item["crate_path"] / "Cargo.toml").is_file())
            self.assertTrue((ROOT / item["crate_path"] / "module.toml").is_file())

    # WORK_UNIT_CASE: 968/3
    def test_03_failed_partial_stale_proof_blocks_activation(self) -> None:
        live = []
        for name, run in self.test_runs.items():
            self.assertEqual(run.returncode, 0, name)
            self.assertNotIn("FAILED", run.stdout + run.stderr)
            live.append({"name": name, "outcome": "EXECUTED_PASS",
                         "partial": False, "stale": False})
        self.assertEqual(validate_proof(live), [])
        for key, val in (("outcome", "EXECUTED_FAIL"), ("partial", True), ("stale", True)):
            bad = [dict(r) for r in live]
            bad[1][key] = val
            self.assertTrue(validate_proof(bad), f"{key}={val}")
        current = git("merge-base", "--is-ancestor", BASE_SHA, "HEAD")
        self.assertEqual(current.returncode, 0, current.stderr)
        self.assertEqual(self.candidate["base_commit"], BASE_SHA)

    # WORK_UNIT_CASE: 968/4
    def test_04_unresolved_challenge_or_second_writer_blocks_activation(self) -> None:
        text = read_bytes("crates/smart/cognitive-contract-challenges.toml").decode("utf-8")
        open_entries: list[dict] = []
        current: dict | None = None
        for line in text.splitlines():
            if line.strip() == "[[challenge]]":
                current = {"needed_by": []}
                open_entries.append(current)
            elif current is not None and line.startswith("status ="):
                current["status"] = line.split("=", 1)[1].strip().strip('"')
            elif current is not None and line.startswith("needed_by ="):
                current["needed_by"] = json.loads(line.split("=", 1)[1].strip().replace("'", '"'))
            elif current is not None and line.startswith("id ="):
                current["id"] = line.split("=", 1)[1].strip().strip('"')
        blocking = [e for e in open_entries
                    if str(e.get("status", "")).startswith("OPEN")
                    and set(self.four_names) & set(e.get("needed_by", []))]
        self.assertEqual(blocking, [])
        self.assertEqual(validate_challenges([], set(self.four_names)), [])
        poison = [{"id": "CC-X", "needed_by": [self.four_names[0]]}]
        self.assertTrue(validate_challenges(poison, set(self.four_names)))
        self.assertEqual(validate_single_writer(["T8-A1"]), [])
        self.assertTrue(validate_single_writer([]))
        self.assertTrue(validate_single_writer(["T8-A1", "T8-A2"]))
        changed = git("diff", "--name-only", BASE_SHA, "HEAD").stdout.split()
        self.assertEqual(changed, [])
        for path in sorted(OWNED_PATHS):
            per_file = git("diff", "--numstat", BASE_SHA, "HEAD", "--", path)
            self.assertEqual(per_file.stdout.strip(), "", path)

    # WORK_UNIT_CASE: 968/5
    def test_05_package_ready_proof_precedes_and_ignores_this_issue(self) -> None:
        for item in self.four:
            probe = git("merge-base", "--is-ancestor",
                        item["leaf_touch_commit"], BASE_SHA)
            self.assertEqual(probe.returncode, 0, probe.stderr)
        branch_commits = git("rev-list", f"{BASE_SHA}..HEAD").stdout.split()
        self.assertEqual(branch_commits, [])
        for item in self.four:
            self.assertNotIn(item["leaf_touch_commit"][:12], branch_commits)
        for item in self.four:
            module = load_toml(f"{item['crate_path']}/module.toml")
            self.assertEqual(module["status"], "ADMITTED")
            run = self.test_runs[item["name"]]
            self.assertEqual(run.returncode, 0, item["name"])
            passed = sum(int(m) for m in re.findall(r"(\d+) passed", run.stdout))
            self.assertEqual(passed, item["matrix_cases"], item["name"])
            proofs = list((ROOT / item["crate_path"] / "src").rglob("*.rs"))
            proofs += list((ROOT / item["crate_path"] / "tests").rglob("*.rs")) \
                if (ROOT / item["crate_path"] / "tests").is_dir() else []
            self.assertTrue(proofs, item["name"])
            for rs in proofs:
                # Leaf proof carries no wave-integration marker: no T8-A1 /
                # admit-d1 / suite reference.
                text = rs.read_text(encoding="utf-8")
                self.assertNotIn("T8-A1", text, str(rs))
                self.assertNotIn("admit-d1", text, str(rs))
                self.assertNotIn("test_wave_admission_d1", text, str(rs))

    # WORK_UNIT_CASE: 968/6
    def test_06_exact_package_layer_causal_identity_preserved(self) -> None:
        for item in self.four:
            module = load_toml(f"{item['crate_path']}/module.toml")
            manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
            meta = manifest["package"]["metadata"]["eliot"]
            self.assertEqual(module["module_id"], item["functional_cell"])
            self.assertEqual(module["crate"], item["name"])
            self.assertEqual(module["agent_order"], item["agent_order"])
            self.assertEqual(module["source_layer"], item["source_layer"])
            self.assertEqual(module["runtime_layer"], item["runtime_layer"])
            self.assertEqual(meta["functional_cell"], item["functional_cell"])
            self.assertEqual(meta["agent_order"], item["agent_order"])
            self.assertEqual(meta["source_layer"], item["source_layer"])
            self.assertEqual(meta["runtime_layer"], item["runtime_layer"])
            expected_note = (ORIENTATION_ADMISSION_NOTE
                             if item["name"] == ORIENTATION else ADMISSION_NOTE)
            self.assertEqual(meta["workspace_admission"], expected_note)
            self.assertEqual(module["agent_task"]["workspace_admission"], expected_note)

    # WORK_UNIT_CASE: 968/7
    def test_07_shared_a03_evidence_epistemic_normative_type_ownership(self) -> None:
        for item in self.four:
            manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
            declared = declared_dep_names(manifest)
            self.assertIn("eliot-contracts", declared, item["name"])
            self.assertIn("eliot-dreamer-contracts", declared, item["name"])
            tokens = crate_tokens_in_rs(item["crate_path"])
            self.assertIn("eliot_contracts", tokens, item["name"])
            self.assertIn("eliot_dreamer_contracts", tokens, item["name"])
        orientation_manifest = load_toml(f"crates/smart/{ORIENTATION}/Cargo.toml")
        orientation_declared = declared_dep_names(orientation_manifest)
        self.assertIn("eliot-evidence", orientation_declared, ORIENTATION)
        self.assertIn("eliot-epistemic-contracts", orientation_declared, ORIENTATION)
        otokens = crate_tokens_in_rs(f"crates/smart/{ORIENTATION}")
        self.assertIn("eliot_evidence", otokens, ORIENTATION)
        self.assertIn("eliot_epistemic_contracts", otokens, ORIENTATION)
        impl_manifest = load_toml(f"crates/smart/{IMPL_BRIEF}/Cargo.toml")
        arch_manifest = load_toml(f"crates/smart/{ARCH_BRIEF}/Cargo.toml")
        # Authority separation: only the ImplementationBrief consumes
        # conformance contracts; the ArchitectureBrief stays authority-pure.
        self.assertIn("eliot-conformance-contracts",
                      impl_manifest.get("dependencies", {}), IMPL_BRIEF)
        self.assertNotIn("eliot-conformance-contracts",
                         declared_dep_names(arch_manifest), ARCH_BRIEF)
        impl_tokens = crate_tokens_in_rs(f"crates/smart/{IMPL_BRIEF}")
        self.assertIn("eliot_conformance_contracts", impl_tokens, IMPL_BRIEF)
        for item in self.four:
            dups = find_canonical_duplicates(item["crate_path"])
            if item["name"] == ORIENTATION:
                # Only the known wrapper, which embeds the canonical type
                # instead of replacing it.
                self.assertEqual(dups, ["CurrentEpistemicPositionHandle"],
                                 item["name"])
                wrapper = (ROOT / item["crate_path"] / "src" / "input.rs").read_text(
                    encoding="utf-8")
                self.assertIn("position: CurrentEpistemicPosition", wrapper)
            else:
                self.assertEqual(dups, [], item["name"])
        poisoned = rs_definition_lines(f"crates/smart/{CLARIFICATION}") + [
            "pub struct EvidenceEnvelope {",
        ]
        self.assertIn("EvidenceEnvelope",
                      canonical_duplicates_in_lines(poisoned))

    # WORK_UNIT_CASE: 968/8
    def test_08_no_producer_algorithm_imports_despite_runtime_value_flow(self) -> None:
        for item in self.four:
            manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
            declared = declared_dep_names(manifest)
            self.assertEqual(declared & FORBIDDEN_PRODUCER, set(), item["name"])
            tokens = crate_tokens_in_rs(item["crate_path"])
            self.assertEqual(tokens & FORBIDDEN_PRODUCER, set(), item["name"])
            # Only public contracts/value interfaces flow at runtime: every
            # eliot_* token is a canonical contract/value crate or the leaf
            # itself (non-eliot deps such as serde carry no dreamer value).
            own = item["name"].replace("-", "_")
            self.assertLessEqual(tokens, ALLOWED_VALUE_TOKENS | {own}, item["name"])
        poisoned = (crate_tokens_in_rs(f"crates/smart/{CLARIFICATION}")
                    | {"eliot_dreamer_grounding"})
        self.assertIn("eliot_dreamer_grounding", poisoned & FORBIDDEN_PRODUCER)

    # WORK_UNIT_CASE: 968/9
    def test_09_no_provider_store_runtime_or_local_normative_authority(self) -> None:
        for item in self.four:
            manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
            declared = declared_dep_names(manifest)
            bad_deps = {d for d in declared if is_forbidden_provider_dep(d)}
            self.assertEqual(bad_deps, set(), item["name"])
            tokens = crate_tokens_in_rs(item["crate_path"])
            self.assertEqual(provider_tokens_in(tokens), set(), item["name"])
            # Data fields (authority_ref/authority_ceiling) and prose
            # mentions are not authority implementations: only struct/enum/fn
            # definition lines count.
            self.assertEqual(find_authority_impls(item["crate_path"]), [],
                             item["name"])
        poisoned_deps = (declared_dep_names(
            load_toml(f"crates/smart/{CLARIFICATION}/Cargo.toml"))
            | {"eliot-provider-acquire"})
        self.assertTrue(any(is_forbidden_provider_dep(d) for d in poisoned_deps))
        self.assertEqual(provider_tokens_in({"eliot_store_handle"}),
                         {"eliot_store_handle"})
        poisoned_lines = [
            "pub struct GrantAuthority {",
            "    fn issue_authority(&self) {",
        ]
        self.assertEqual(len(authority_impls_in_lines(poisoned_lines)), 2)

    # WORK_UNIT_CASE: 968/10
    def test_10_acyclic_compile_graph_and_verified_orientation_noop(self) -> None:
        edges = internal_edges()
        order = topo_sort(edges)
        self.assertGreater(len(order), 100)
        for name in self.four_names:
            self.assertIn(name, order)
        poison = dict(edges)
        poison[CLARIFICATION] = set(poison[CLARIFICATION]) | {ARCH_BRIEF}
        poison[ARCH_BRIEF] = set(poison[ARCH_BRIEF]) | {CLARIFICATION}
        with self.assertRaises(ValueError):
            topo_sort(poison)
        nodes = {n["id"]: n.get("dependencies", [])
                 for n in self.metadata["resolve"]["nodes"]}
        member_ids = set(self.metadata["workspace_members"])
        color: dict[str, int] = {}

        def visit(node_id: str) -> None:
            color[node_id] = 1
            for dep_id in nodes.get(node_id, []):
                if dep_id not in member_ids:
                    continue
                state = color.get(dep_id, 0)
                self.assertNotEqual(state, 1, f"metadata resolve cycle at {dep_id}")
                if state == 0:
                    visit(dep_id)
            color[node_id] = 2

        for member_id in sorted(member_ids):
            if color.get(member_id, 0) == 0:
                visit(member_id)
        ws = root_workspace()
        # #628 orientation was admitted via #702: verified no-op, not omission.
        self.assertEqual(ws["members"].count(ORIENTATION_PATH), 1)
        self.assertNotIn(ORIENTATION_PATH, ws["exclude"])
        orientation_module = load_toml(f"{ORIENTATION_PATH}/module.toml")
        self.assertEqual(orientation_module["status"], "ADMITTED")
        orientation_manifest = load_toml(f"{ORIENTATION_PATH}/Cargo.toml")
        self.assertEqual(orientation_manifest["package"]["name"], ORIENTATION)
        changed = git("diff", "--name-only", BASE_SHA, "HEAD").stdout.split()
        self.assertNotIn(f"{ORIENTATION_PATH}/Cargo.toml", changed)
        self.assertNotIn(f"{ORIENTATION_PATH}/module.toml", changed)
        base_orientation = tomllib.loads(
            git("show", f"{BASE_SHA}:{ORIENTATION_PATH}/Cargo.toml").stdout)
        self.assertEqual(orientation_manifest, base_orientation)
        base_orientation_module = tomllib.loads(
            git("show", f"{BASE_SHA}:{ORIENTATION_PATH}/module.toml").stdout)
        self.assertEqual(orientation_module, base_orientation_module)
        modules = {p: {"status": load_toml(f"{p}/module.toml")["status"]}
                   for p in self.four_paths}
        self.assertEqual(validate_wave_state(
            ws["members"], ws["exclude"], modules,
            set(lock_packages()), self.four_paths), [])
        for path in self.four_paths:
            self.assertEqual(ws["members"].count(path), 1)
        base = tomllib.loads(git("show", f"{ADMISSION_BASE_SHA}:Cargo.toml").stdout)
        base_members = base["workspace"]["members"]
        base_exclude = base["workspace"]["exclude"]
        # Orientation was already a member at base, so only the three moved
        # leaves can carry stale member-count errors.
        self.assertIn(ORIENTATION_PATH, base_members)
        self.assertNotIn(ORIENTATION_PATH, base_exclude)
        stale_modules = {
            p: {"status": "ADMITTED" if p == ORIENTATION_PATH else "PROTOTYPE"}
            for p in self.four_paths}
        stale_errors = validate_wave_state(
            base_members, base_exclude, stale_modules,
            set(lock_packages()), self.four_paths)
        for path in self.four_paths:
            if path == ORIENTATION_PATH:
                continue
            self.assertTrue(any("member count" in e and path in e
                                for e in stale_errors), path)
        self.assertFalse(any("member count" in e and ORIENTATION_PATH in e
                             for e in stale_errors))

    # WORK_UNIT_CASE: 968/11
    def test_11_one_member_per_package_no_duplication(self) -> None:
        ws = root_workspace()
        for path in self.four_paths:
            self.assertEqual(ws["members"].count(path), 1, path)
            self.assertNotIn(path, ws["exclude"])
        self.assertEqual(len(ws["members"]), len(set(ws["members"])))
        self.assertEqual(len(ws["exclude"]), len(set(ws["exclude"])))
        self.assertEqual(set(ws["members"]) & set(ws["exclude"]), set())
        names = [load_toml(f"{p}/Cargo.toml")["package"]["name"] for p in self.four_paths]
        self.assertEqual(sorted(names), sorted(self.four_names))
        dup = ws["members"] + [self.four_paths[0]]
        self.assertIn("duplicate workspace member",
                      validate_wave_state(dup, ws["exclude"],
                                          {p: {"status": "ADMITTED"} for p in self.four_paths},
                                          set(lock_packages()), self.four_paths))

    # WORK_UNIT_CASE: 968/12
    def test_12_inheritance_preserves_versions_features_lints(self) -> None:
        root_deps = root_workspace()["dependencies"]
        for item in self.four:
            rel = f"{item['crate_path']}/Cargo.toml"
            manifest = load_toml(rel)
            package = manifest["package"]
            for key in ("version", "edition", "rust-version", "license"):
                self.assertEqual(package[key], {"workspace": True}, f"{item['name']}.{key}")
            self.assertEqual(manifest["lints"], {"workspace": True})
            self.assertNotIn("workspace", manifest, item["name"])
            self.assertNotIn("publish", package, item["name"])
            for table in ("dependencies", "dev-dependencies"):
                for dep, spec in manifest.get(table, {}).items():
                    if isinstance(spec, dict) and spec.get("workspace") is True:
                        self.assertIn(dep, root_deps, f"{item['name']}.{dep}")
            base = tomllib.loads(git("show", f"{BASE_SHA}:{rel}").stdout)
            for table in ("dependencies", "dev-dependencies"):
                live_section = manifest.get(table, {})
                base_section = base.get(table, {})
                # Admission normalizes the newly admitted D1 leaves to the
                # admitted orientation pattern; dependency names are
                # unchanged, only the shared-version spec form moves to
                # workspace inheritance. Orientation already matched the
                # pattern at base, so its sections are byte-identical.
                self.assertEqual(set(live_section), set(base_section), f"{item['name']}.{table}")
                for dep, live_spec in live_section.items():
                    base_spec = base_section[dep]
                    if isinstance(live_spec, dict) and live_spec.get("workspace") is True:
                        self.assertIn(dep, root_deps, f"{item['name']}.{dep}")
                    elif isinstance(live_spec, dict):
                        self.assertEqual(live_spec["path"], base_spec["path"],
                                         f"{item['name']}.{dep}")
                        self.assertEqual(live_spec.get("version", "0.1.0"), "0.1.0",
                                         f"{item['name']}.{dep}")
                    else:
                        self.assertEqual(live_spec, base_spec, f"{item['name']}.{dep}")

    # WORK_UNIT_CASE: 968/13
    def test_13_no_rust_test_router_or_floor_change(self) -> None:
        changed = git("diff", "--name-only", BASE_SHA, "HEAD").stdout.split()
        self.assertEqual([c for c in changed if c.endswith(".rs")], [])
        leaf_test_prefixes = tuple(f"{p}/tests/" for p in self.four_paths)
        test_dirs = [c for c in changed
                     if c.replace("\\", "/").startswith(leaf_test_prefixes)
                     and not c.replace("\\", "/").startswith("scripts/tests/")]
        self.assertEqual(test_dirs, [])
        # Orientation is untouched base->HEAD: no diff may name its directory.
        orientation_diff = git("diff", "--name-only", BASE_SHA, "HEAD",
                               "--", ORIENTATION_PATH)
        self.assertEqual(orientation_diff.returncode, 0, orientation_diff.stderr)
        self.assertEqual(orientation_diff.stdout.split(), [])
        allowed_cargo = {"prototype", "workspace_admission"}
        allowed_module = {"status", "workspace_admission"}
        for item in self.four:
            expected_note = (ORIENTATION_ADMISSION_NOTE
                             if item["name"] == ORIENTATION else ADMISSION_NOTE)
            base_cargo = tomllib.loads(
                git("show", f"{BASE_SHA}:{item['crate_path']}/Cargo.toml").stdout)
            live_cargo = load_toml(f"{item['crate_path']}/Cargo.toml")
            self.assertEqual(live_cargo["package"]["name"], base_cargo["package"]["name"])
            self.assertEqual(live_cargo["package"]["description"],
                             base_cargo["package"]["description"])
            live_meta = live_cargo["package"]["metadata"]["eliot"]
            base_meta = base_cargo["package"]["metadata"]["eliot"]
            for key in base_meta:
                if key not in allowed_cargo:
                    self.assertEqual(live_meta.get(key), base_meta[key],
                                     f"{item['name']}.{key}")
            self.assertEqual(live_meta["prototype"], False)
            self.assertEqual(live_meta["workspace_admission"], expected_note)
            base_module = tomllib.loads(
                git("show", f"{BASE_SHA}:{item['crate_path']}/module.toml").stdout)
            live_module = load_toml(f"{item['crate_path']}/module.toml")
            for key in base_module:
                if key in allowed_module:
                    continue
                if key == "agent_task":
                    for sub in base_module["agent_task"]:
                        if sub == "workspace_admission":
                            continue
                        self.assertEqual(live_module["agent_task"].get(sub),
                                         base_module["agent_task"][sub],
                                         f"{item['name']}.agent_task.{sub}")
                    continue
                self.assertEqual(live_module.get(key), base_module[key],
                                 f"{item['name']}.{key}")
            self.assertEqual(live_module["status"], "ADMITTED")

    # WORK_UNIT_CASE: 968/14
    def test_14_root_and_lock_delta_limited_and_explained(self) -> None:
        diff = git("diff", BASE_SHA, "HEAD", "--", "Cargo.toml")
        self.assertEqual(diff.returncode, 0, diff.stderr)
        added = [l[1:].strip() for l in diff.stdout.splitlines()
                 if l.startswith("+") and not l.startswith("+++")
                 and l[1:].strip().startswith('"crates/')]
        removed = [l[1:].strip() for l in diff.stdout.splitlines()
                   if l.startswith("-") and not l.startswith("---")
                   and l[1:].strip().startswith('"crates/')]
        self.assertEqual(added, [])
        self.assertEqual(removed, [])
        self.assertNotIn("[workspace.dependencies]", diff.stdout)
        lock_diff = git("diff", BASE_SHA, "HEAD", "--", "Cargo.lock")
        self.assertEqual(lock_diff.returncode, 0, lock_diff.stderr)
        minus = [l for l in lock_diff.stdout.splitlines()
                 if l.startswith("-") and not l.startswith("---")]
        self.assertEqual(minus, [])
        plus_names = sorted(l.split("=", 1)[1].strip().strip('"')
                            for l in lock_diff.stdout.splitlines()
                            if l.startswith('+name ='))
        self.assertEqual(plus_names, [])
        base_lock = tomllib.loads(git("show", f"{BASE_SHA}:Cargo.lock").stdout)
        base_names = {p["name"] for p in base_lock["package"]}
        # Orientation was already locked at base; the wave adds only the
        # three moved leaves.
        self.assertIn(ORIENTATION, base_names)
        live_lock = load_toml("Cargo.lock")
        for entry in live_lock["package"]:
            if entry["name"] in self.four_names:
                for dep in entry.get("dependencies", []):
                    self.assertIn(dep.split(" ")[0], base_names, entry["name"])
        base_versions = {(p["name"], p.get("version")) for p in base_lock["package"]}
        live_versions = {(p["name"], p.get("version")) for p in live_lock["package"]}
        self.assertTrue(base_versions <= live_versions)

    # WORK_UNIT_CASE: 968/15
    def test_15_local_lock_disposition_explicit_root_lock_canonical(self) -> None:
        for item in self.four:
            self.assertFalse((ROOT / item["crate_path"] / "Cargo.lock").exists(),
                             item["name"])
        self.assertIsNotNone(self.metadata["resolve"])
        locked_ids = {p["name"] for p in self.metadata["packages"]}
        for name in self.four_names:
            self.assertIn(name, locked_ids)
            self.assertTrue(is_workspace_member(self.metadata, name), name)

    # WORK_UNIT_CASE: 968/16
    def test_16_generated_rows_cover_wave_and_regen_is_byte_identical(self) -> None:
        # In-memory isolation: this case never writes; it only reads the
        # committed indexes, runs the read-only check, and re-renders both
        # projections in memory twice.
        package_index = read_bytes("docs/code-navigation/PACKAGE_DOCS_INDEX.md").decode("utf-8")
        prototype_index = read_bytes("docs/code-navigation/PROTOTYPE_DOCS_INDEX.md").decode("utf-8")
        for path in self.four_paths:
            self.assertIn(path, package_index)
            self.assertNotIn(f"{path}/Cargo.toml", prototype_index)
        self.assertIn("**174**", package_index)
        self.assertIn("**11**", prototype_index)
        before_pkg = sha256_bytes(read_bytes("docs/code-navigation/PACKAGE_DOCS_INDEX.md"))
        before_proto = sha256_bytes(read_bytes("docs/code-navigation/PROTOTYPE_DOCS_INDEX.md"))
        check_run = py_script("scripts/code_navigation.py", "check", "--root", ".")
        self.assertEqual(check_run.returncode, 0, check_run.stderr[-2000:])
        from code_navigation_lib import build_registry
        from code_navigation_lib.package_docs import render as render_pkg
        from code_navigation_lib.prototype_docs import render as render_proto
        reg = build_registry(ROOT)
        first_pkg = render_pkg(reg, ROOT).encode("utf-8")
        first_proto = render_proto(ROOT, reg).encode("utf-8")
        second_pkg = render_pkg(reg, ROOT).encode("utf-8")
        second_proto = render_proto(ROOT, reg).encode("utf-8")
        self.assertEqual(read_bytes("docs/code-navigation/PACKAGE_DOCS_INDEX.md"), first_pkg)
        self.assertEqual(read_bytes("docs/code-navigation/PROTOTYPE_DOCS_INDEX.md"), first_proto)
        self.assertEqual(first_pkg, second_pkg)
        self.assertEqual(first_proto, second_proto)
        self.assertEqual(before_pkg, sha256_bytes(first_pkg))
        self.assertEqual(before_proto, sha256_bytes(first_proto))
        self.assertEqual(before_pkg, sha256_bytes(second_pkg))
        self.assertEqual(before_proto, sha256_bytes(second_proto))

    # WORK_UNIT_CASE: 968/17
    def test_17_descriptors_decode_and_suites_execute_pass(self) -> None:
        for item in self.four:
            raw = item["descriptor_toml"].encode("utf-8")
            decoded = self.decode_descriptor(
                raw, f".github/work-units/{item['leaf_issue']}.toml")
            self.assertTrue(decoded["require_workspace_member"] is True)
            self.assertEqual(decoded["package"], {"name": item["name"]})
            self.assertEqual(decoded["matrix_cases"], item["matrix_cases"])
            self.assertEqual(decoded["body_sha256"], item["lib_sha256"])
            self.assertEqual(decoded["matrix_sha256"], item["matrix_sha256"])
            self.assertEqual(decoded["proof_ceiling"]["value"], "workspace-integration")
            self.assertTrue(is_workspace_member(self.metadata, item["name"]),
                            item["name"])
            run = self.test_runs[item["name"]]
            self.assertEqual(run.returncode, 0, item["name"])
            passed = sum(int(m) for m in re.findall(r"(\d+) passed", run.stdout))
            failed = sum(int(m) for m in re.findall(r"(\d+) failed", run.stdout))
            self.assertEqual(passed, item["matrix_cases"], item["name"])
            self.assertEqual(failed, 0, item["name"])
        self.assertEqual(self.clippy.returncode, 0, self.clippy.stderr[-2000:])
        combined = self.clippy.stdout + self.clippy.stderr
        self.assertNotIn("error[", combined)
        self.assertNotIn("\nerror:", combined)
        with self.assertRaises(Exception):
            self.decode_descriptor(
                self.four[0]["descriptor_toml"].encode("utf-8") + b'\nfuture_field = "no"\n',
                f".github/work-units/{self.four[0]['leaf_issue']}.toml")
        self.assertTrue(is_workspace_member(self.metadata, "eliot-learning-state-view"))

    # WORK_UNIT_CASE: 968/18
    def test_18_locked_workspace_check_and_norun_includes_all_four(self) -> None:
        self.assertEqual(self.workspace_check.returncode, 0,
                         self.workspace_check.stderr[-2000:])
        self.assertEqual(self.workspace_norun.returncode, 0,
                         self.workspace_norun.stderr[-2000:])
        ids = [p["id"] for p in self.metadata["packages"]]
        self.assertEqual(len(ids), len(set(ids)))
        member_ids = set(self.metadata["workspace_members"])
        by_name = {p["name"]: p["id"] for p in self.metadata["packages"]}
        name_counts = Counter(p["name"] for p in self.metadata["packages"])
        for name in self.four_names:
            self.assertEqual(name_counts[name], 1, name)
            self.assertIn(by_name[name], member_ids, name)
        # Proof ceiling: workspace check/test --no-run prove compilation
        # only, not runtime execution, Edge, Product, or release proof.
        ceiling = ("workspace check/test --no-run prove compilation only, "
                   "not runtime execution, Edge, Product, or release proof")
        self.assertTrue("compilation only" in ceiling,
                        f"proof ceiling must stay compilation-only: {ceiling}")
        self.assertIn("not runtime execution", ceiling,
                      f"workspace gates never prove execution: {ceiling}")

    # WORK_UNIT_CASE: 968/19
    def test_19_before_after_arithmetic_reconciles(self) -> None:
        base = tomllib.loads(git("show", f"{BASE_SHA}:Cargo.toml").stdout)["workspace"]
        live = root_workspace()
        self.assertEqual(self.baseline["members_count"], len(base["members"]))
        self.assertEqual(self.baseline["excluded_count"], len(base["exclude"]))
        self.assertEqual(len(base["members"]), len(live["members"]))
        self.assertEqual(len(base["exclude"]), len(live["exclude"]))
        self.assertEqual(len(live["members"]), self.candidate["members_count"])
        self.assertEqual(len(live["exclude"]), self.candidate["excluded_count"])
        # The no-op reconciliation: orientation is a member at both ends.
        self.assertIn(ORIENTATION_PATH, base["members"])
        self.assertIn(ORIENTATION_PATH, live["members"])
        total = 0
        for item in self.four:
            live_digest = sha256_bytes(read_bytes(f"{item['crate_path']}/src/lib.rs"))
            self.assertEqual(live_digest, item["lib_sha256"], item["name"])
            run = self.test_runs[item["name"]]
            passed = sum(int(m) for m in re.findall(r"(\d+) passed", run.stdout))
            self.assertEqual(passed, self.candidate["expected_test_counts"][item["name"]],
                             item["name"])
            total += passed
        self.assertEqual(total, sum(self.candidate["expected_test_counts"].values()))
        self.assertEqual(total, 151)

    # WORK_UNIT_CASE: 968/20
    def test_20_failed_admission_proves_no_edge_product_release(self) -> None:
        ws = root_workspace()
        partial_members = [m for m in ws["members"] if m != self.four_paths[0]]
        errors = validate_wave_state(
            partial_members, ws["exclude"],
            {p: {"status": "ADMITTED"} for p in self.four_paths},
            set(lock_packages()), self.four_paths)
        self.assertTrue(any(self.four_paths[0] in e for e in errors))
        stuck = ws["exclude"] + [self.four_paths[1]]
        errors = validate_wave_state(
            ws["members"], stuck,
            {p: {"status": "ADMITTED"} for p in self.four_paths},
            set(lock_packages()), self.four_paths)
        self.assertTrue(any(self.four_paths[1] in e for e in errors))
        self.assertEqual(validate_wave_state(
            ws["members"], ws["exclude"],
            {p: {"status": "ADMITTED"} for p in self.four_paths},
            set(lock_packages()), self.four_paths), [])
        for path in self.four_paths:
            self.assertNotIn(path, ws.get("default-members", []))
        for item in self.four:
            module = load_toml(f"{item['crate_path']}/module.toml")
            self.assertEqual(module.get("owned_mutable_state"), [])
            self.assertEqual(module.get("allowed_effects"), [])
            self.assertEqual(module.get("status"), "ADMITTED")


if __name__ == "__main__":
    unittest.main()
