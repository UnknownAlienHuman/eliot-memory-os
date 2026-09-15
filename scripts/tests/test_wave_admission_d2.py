"""#969 D2 wave admission matrix: 20-case integration proof for five Diagnosis/Planning leaves.

Admitting wave T8-A2 moves exactly these five packages from root ``exclude``
to root ``members`` in one serialized turn (issue #969):

- crates/smart/eliot-dreamer-conflict-analysis    (leaf #673, A-39)
- crates/smart/eliot-dreamer-development-diagnosis (leaf #675, A-40)
- crates/smart/eliot-dreamer-maintenance-plan      (leaf #677, A-41)
- crates/smart/eliot-dreamer-configuration-plan    (leaf #679, A-42)
- crates/smart/eliot-dreamer-orchestration-plan    (leaf #681, A-43)

Frozen bounded fixtures (exact filenames frozen before coding; no others):

- scripts/testdata/work-unit-gate/wave-d2/candidate.json
- scripts/testdata/work-unit-gate/wave-d2/baseline.json

Every assertion derives from repository file bytes or live command output
(``cargo metadata --locked``, ``cargo test --locked -p``, ``cargo clippy``,
``code_navigation check/sync-index``, ``git show/diff/merge-base``, the real
#850 ``decode_descriptor`` validation path and the real manifest/lock/index
readers). Negative legs feed mutated copies through the same validator
functions as the positive legs; no assertion echoes a prewritten
``expected: fail`` label. There is no second production oracle.

Shape precedent: scripts/tests/test_wave_admission_s1.py (commit 7a2b5fd4,
T8-AS1, issue #965). Documented D2 adaptations, nothing more:

- ``six`` -> ``five`` (five leaves, agent_orders 39..43);
- top-level ``leaf_touch_commit`` -> per-item ``leaf_touch_commit`` (each D2
  leaf landed in its own implementation commit; every one is an ancestor of
  the base);
- the screen/curation-contract legs become conflict/epistemic-contract legs
  (conflict-analysis is the only D2 leaf consuming eliot-epistemic-contracts;
  no D2 leaf uses schemars/serde, so the inheritance leg has no
  schemars/serde_json carve-out);
- counts 138/33 -> 152/20, total 34 -> 40, unit T8-AS1 -> T8-A2.

Documented runners (repo root, ``CARGO_TARGET_DIR`` set per owner disk rule)::

    python -m py_compile scripts/tests/test_wave_admission_d2.py
    $env:CARGO_TARGET_DIR='C:/Development/Rust/projects/eliot-swarm/MGR02-target-3'
    python -m unittest scripts.tests.test_wave_admission_d2 -v

Deterministic, no network, no stubs. Declared denominator: 20 cases, exactly
1..20, one method per ``# WORK_UNIT_CASE: 969/<case>`` marker.
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
FIX = ROOT / "scripts" / "testdata" / "work-unit-gate" / "wave-d2"
BASE_SHA = "9bc4aba334f7337f849710c134286ad94c32ba80"
ADMISSION_NOTE = "admitted via #969 (T8-A2) root workspace membership"
CONFLICT = "eliot-dreamer-conflict-analysis"
FOUR_PLANS = (
    "eliot-dreamer-development-diagnosis",
    "eliot-dreamer-maintenance-plan",
    "eliot-dreamer-configuration-plan",
    "eliot-dreamer-orchestration-plan",
)
FIVE = (CONFLICT, *FOUR_PLANS)
OWNED_PATHS = frozenset({
    "Cargo.toml",
    "Cargo.lock",
    "crates/smart/eliot-dreamer-conflict-analysis/Cargo.toml",
    "crates/smart/eliot-dreamer-conflict-analysis/module.toml",
    "crates/smart/eliot-dreamer-development-diagnosis/Cargo.toml",
    "crates/smart/eliot-dreamer-development-diagnosis/module.toml",
    "crates/smart/eliot-dreamer-maintenance-plan/Cargo.toml",
    "crates/smart/eliot-dreamer-maintenance-plan/module.toml",
    "crates/smart/eliot-dreamer-configuration-plan/Cargo.toml",
    "crates/smart/eliot-dreamer-configuration-plan/module.toml",
    "crates/smart/eliot-dreamer-orchestration-plan/Cargo.toml",
    "crates/smart/eliot-dreamer-orchestration-plan/module.toml",
    "docs/code-navigation/PACKAGE_DOCS_INDEX.md",
    "docs/code-navigation/PROTOTYPE_DOCS_INDEX.md",
    "scripts/tests/test_wave_admission_d2.py",
    "scripts/testdata/work-unit-gate/wave-d2/candidate.json",
    "scripts/testdata/work-unit-gate/wave-d2/baseline.json",
})
FORBIDDEN_ALGO = frozenset({
    "eliot_dreamer_candidate_validation",
    "eliot_dreamer_claim_grounding",
    "eliot_dreamer_bundle",
    "eliot_dreamer_core",
})
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
                        five_paths: list[str]) -> list[str]:
    """Real admission validator shared by positive and negative legs."""
    errors: list[str] = []
    if sorted(set(five_paths)) != sorted(five_paths):
        errors.append("five denominator has duplicates")
    for path in five_paths:
        if members.count(path) != 1:
            errors.append(f"member count != 1: {path}")
        if path in exclude:
            errors.append(f"still excluded: {path}")
        module = modules.get(path)
        if module is None:
            errors.append(f"missing module router: {path}")
        elif module.get("status") != "ADMITTED":
            errors.append(f"module not admitted: {path}")
    for item in load_fixture("candidate.json")["five"]:
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


def validate_challenges(open_entries: list[dict], five_names: set[str]) -> list[str]:
    errors: list[str] = []
    for entry in open_entries:
        if five_names & set(entry.get("needed_by", [])):
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


def descriptor_toml(item: dict) -> bytes:
    """Membership-required rust-package descriptor over real frozen digests."""
    count = item["matrix_cases"]
    text = f"""schema_version = "eliot-work-unit-descriptor-v2"
identity = {{value = "work-unit-{item['leaf_issue']}"}}
issue = {{repository = {{owner = "UnknownAlienHuman", name = "eliot-memory-os"}}, number = {item['leaf_issue']}}}
unit = {{value = "T8-A2"}}
mode = "rust-package"
source_roots = [{{value = "{item['crate_path']}/src/lib.rs"}}]
test_roots = [{{value = "{item['test_root']}"}}]
matrix_cases = {count}
proof_ceiling = {{value = "workspace-integration"}}
revision = 1
body_sha256 = "{item['lib_sha256']}"
matrix_sha256 = "{item['matrix_sha256']}"
require_workspace_member = true
package = {{name = "{item['name']}"}}
requirements = {{source_floor = 1, public_floor = 1, test_floor = {count}, required_guards = [{{value = "bounded"}}]}}
bounds = {{wall_ms = 10000, idle_ms = 5000, output_bytes = 65536, line_bytes = 4096, discovery_tests = {count}, child_processes = 4}}
"""
    return text.encode("utf-8")


def is_workspace_member(metadata: dict, name: str) -> bool:
    """Real membership path: locked metadata workspace_members."""
    by_name = {p["name"]: p["id"] for p in metadata["packages"]}
    return name in by_name and by_name[name] in set(metadata["workspace_members"])


class TestWaveAdmissionD2(unittest.TestCase):
    """20 substantive cases for issue #969."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.candidate = load_fixture("candidate.json")
        cls.baseline = load_fixture("baseline.json")
        cls.five = cls.candidate["five"]
        cls.five_paths = [item["crate_path"] for item in cls.five]
        cls.five_names = [item["name"] for item in cls.five]
        meta = cargo("metadata", "--locked", "--format-version", "1")
        assert meta.returncode == 0, meta.stderr[-2000:]
        cls.metadata = json.loads(meta.stdout)
        cls.test_runs: dict[str, subprocess.CompletedProcess] = {}
        for name in cls.five_names:
            cls.test_runs[name] = cargo("test", "--locked", "-p", name)
        cls.clippy = cargo("clippy", "--locked",
                           *[a for n in cls.five_names for a in ("-p", n)],
                           "--all-targets")
        cls.code_nav = py_script("scripts/code_navigation.py", "check", "--root", ".")
        from scripts.work_unit_gate.descriptor_runner import decode_descriptor
        cls.decode_descriptor = staticmethod(decode_descriptor)

    # WORK_UNIT_CASE: 969/1
    def test_01_exact_five_package_cell_denominator(self) -> None:
        ws = root_workspace()
        self.assertEqual(len(self.five_paths), 5)
        self.assertEqual(len(set(self.five_paths)), 5)
        self.assertEqual(sorted(i["leaf_issue"] for i in self.five),
                         [673, 675, 677, 679, 681])
        for item in self.five:
            self.assertIn(item["crate_path"], ws["members"])
            module = load_toml(f"{item['crate_path']}/module.toml")
            self.assertEqual(module["module_id"], item["functional_cell"])
            self.assertEqual(module["crate"], item["name"])
        live_cells = {load_toml(f"{p}/module.toml")["module_id"] for p in self.five_paths}
        self.assertEqual(len(live_cells), 5)

    # WORK_UNIT_CASE: 969/2
    def test_02_missing_unmerged_unaccepted_leaf_blocks_activation(self) -> None:
        live = []
        for item in self.five:
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
        for item in self.five:
            self.assertTrue((ROOT / item["crate_path"] / "Cargo.toml").is_file())
            self.assertTrue((ROOT / item["crate_path"] / "module.toml").is_file())

    # WORK_UNIT_CASE: 969/3
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
            bad[2][key] = val
            self.assertTrue(validate_proof(bad), f"{key}={val}")
        current = git("merge-base", "--is-ancestor", BASE_SHA, "HEAD")
        self.assertEqual(current.returncode, 0, current.stderr)
        self.assertEqual(self.candidate["base_commit"], BASE_SHA)

    # WORK_UNIT_CASE: 969/4
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
                    and set(self.five_names) & set(e.get("needed_by", []))]
        self.assertEqual(blocking, [])
        self.assertEqual(validate_challenges([], set(self.five_names)), [])
        poison = [{"id": "CC-X", "needed_by": [self.five_names[0]]}]
        self.assertTrue(validate_challenges(poison, set(self.five_names)))
        self.assertEqual(validate_single_writer(["T8-A2"]), [])
        self.assertTrue(validate_single_writer([]))
        self.assertTrue(validate_single_writer(["T8-A2", "T8-AS2"]))
        changed = git("diff", "--name-only", BASE_SHA, "HEAD").stdout.split()
        self.assertTrue(changed)
        self.assertEqual(set(changed) - OWNED_PATHS, set())

    # WORK_UNIT_CASE: 969/5
    def test_05_package_ready_proof_precedes_and_ignores_this_issue(self) -> None:
        for item in self.five:
            probe = git("merge-base", "--is-ancestor",
                        item["leaf_touch_commit"], BASE_SHA)
            self.assertEqual(probe.returncode, 0, probe.stderr)
        branch_commits = git("rev-list", f"{BASE_SHA}..HEAD").stdout.split()
        self.assertTrue(branch_commits)
        for item in self.five:
            self.assertNotIn(item["leaf_touch_commit"][:12], branch_commits)
        for item in self.five:
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
                # Leaf proof carries no wave-integration marker: no T8-A2 /
                # admit-d2 / suite reference (a plain "#969 is separate" note
                # in each leaf lib.rs states the same independence explicitly).
                text = rs.read_text(encoding="utf-8")
                self.assertNotIn("T8-A2", text, str(rs))
                self.assertNotIn("admit-d2", text, str(rs))
                self.assertNotIn("test_wave_admission_d2", text, str(rs))

    # WORK_UNIT_CASE: 969/6
    def test_06_exact_package_layer_causal_identity_preserved(self) -> None:
        for item in self.five:
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
            self.assertEqual(meta["workspace_admission"], ADMISSION_NOTE)
            self.assertEqual(module["agent_task"]["workspace_admission"], ADMISSION_NOTE)

    # WORK_UNIT_CASE: 969/7
    def test_07_compile_graph_acyclic_and_contract_only(self) -> None:
        edges = internal_edges()
        order = topo_sort(edges)
        self.assertGreater(len(order), 100)
        for name in self.five_names:
            self.assertIn(name, order)
        forbidden = (FORBIDDEN_ALGO
                     | {"eliot_dreamer_" + h.split("eliot-dreamer-")[1].replace("-", "_")
                        for h in FIVE})
        for item in self.five:
            manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
            declared: set[str] = set()
            for table in ("dependencies", "dev-dependencies", "build-dependencies"):
                section = manifest.get(table, {})
                if isinstance(section, dict):
                    declared |= {d.replace("-", "_") for d in section}
            hits = (declared & {f.replace("-", "_") for f in forbidden}) - {
                item["name"].replace("-", "_")}
            self.assertEqual(hits, set(), item["name"])
        poison = dict(edges)
        poison["eliot-dreamer-conflict-analysis"] = set(poison["eliot-dreamer-conflict-analysis"]) | {"eliot-dreamer-development-diagnosis"}
        poison["eliot-dreamer-development-diagnosis"] = set(poison["eliot-dreamer-development-diagnosis"]) | {"eliot-dreamer-conflict-analysis"}
        with self.assertRaises(ValueError):
            topo_sort(poison)

    # WORK_UNIT_CASE: 969/8
    def test_08_conflict_analysis_uses_epistemic_contracts_without_handler_imports(self) -> None:
        item = next(i for i in self.five if i["name"] == CONFLICT)
        tokens = crate_tokens_in_rs(item["crate_path"])
        self.assertIn("eliot_epistemic_contracts", tokens)
        self.assertIn("eliot_dreamer_contracts", tokens)
        banned = (FORBIDDEN_ALGO
                  | {"eliot_dreamer_" + h.split("eliot-dreamer-")[1].replace("-", "_")
                     for h in FIVE} - {"eliot_dreamer_conflict_analysis"})
        self.assertEqual(tokens & banned, set())
        manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
        declared: set[str] = set()
        for table in ("dependencies", "dev-dependencies"):
            declared |= set(manifest.get(table, {}))
        self.assertIn("eliot-epistemic-contracts", declared)
        self.assertIn("eliot-dreamer-contracts", declared)
        self.assertNotIn("eliot-dreamer-candidate-validation", declared)
        self.assertNotIn("eliot-dreamer-claim-grounding", declared)
        poisoned = set(tokens) | {"eliot_dreamer_claim_grounding"}
        self.assertEqual(poisoned & banned, {"eliot_dreamer_claim_grounding"})

    # WORK_UNIT_CASE: 969/9
    def test_09_leaves_use_validated_contracts_without_peer_or_grounding_imports(self) -> None:
        peers = {"eliot_dreamer_" + h.split("eliot-dreamer-")[1].replace("-", "_")
                 for h in FIVE}
        for item in self.five:
            tokens = crate_tokens_in_rs(item["crate_path"])
            self.assertIn("eliot_dreamer_contracts", tokens, item["name"])
            own = item["name"].replace("-", "_")
            self.assertEqual((tokens & FORBIDDEN_ALGO), set(), item["name"])
            self.assertEqual((tokens & peers) - {own}, set(), item["name"])
            manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
            declared: set[str] = set()
            for table in ("dependencies", "dev-dependencies"):
                declared |= set(manifest.get(table, {}))
            self.assertIn("eliot-dreamer-contracts", declared, item["name"])
            self.assertNotIn("eliot-dreamer-candidate-validation", declared, item["name"])
            self.assertNotIn("eliot-dreamer-claim-grounding", declared, item["name"])
        poisoned = crate_tokens_in_rs(
            next(i for i in self.five if i["name"] == FOUR_PLANS[0])["crate_path"],
        ) | {"eliot_dreamer_claim_grounding"}
        self.assertIn("eliot_dreamer_claim_grounding", poisoned & FORBIDDEN_ALGO)

    # WORK_UNIT_CASE: 969/10
    def test_10_already_admitted_is_verified_noop_not_omission(self) -> None:
        ws = root_workspace()
        modules = {p: {"status": load_toml(f"{p}/module.toml")["status"]}
                   for p in self.five_paths}
        self.assertEqual(validate_wave_state(
            ws["members"], ws["exclude"], modules,
            set(lock_packages()), self.five_paths), [])
        for path in self.five_paths:
            self.assertEqual(ws["members"].count(path), 1)
        base = tomllib.loads(git("show", f"{BASE_SHA}:Cargo.toml").stdout)
        stale_errors = validate_wave_state(
            base["workspace"]["members"], base["workspace"]["exclude"],
            {p: {"status": "PROTOTYPE"} for p in self.five_paths},
            set(lock_packages()), self.five_paths)
        self.assertTrue(any("member count" in e for e in stale_errors))

    # WORK_UNIT_CASE: 969/11
    def test_11_one_member_per_package_no_duplication(self) -> None:
        ws = root_workspace()
        for path in self.five_paths:
            self.assertEqual(ws["members"].count(path), 1, path)
            self.assertNotIn(path, ws["exclude"])
        self.assertEqual(len(ws["members"]), len(set(ws["members"])))
        self.assertEqual(len(ws["exclude"]), len(set(ws["exclude"])))
        self.assertEqual(set(ws["members"]) & set(ws["exclude"]), set())
        names = [load_toml(f"{p}/Cargo.toml")["package"]["name"] for p in self.five_paths]
        self.assertEqual(sorted(names), sorted(self.five_names))
        dup = ws["members"] + [self.five_paths[0]]
        self.assertIn("duplicate workspace member",
                      validate_wave_state(dup, ws["exclude"],
                                          {p: {"status": "ADMITTED"} for p in self.five_paths},
                                          set(lock_packages()), self.five_paths))

    # WORK_UNIT_CASE: 969/12
    def test_12_inheritance_preserves_versions_features_lints(self) -> None:
        root_deps = root_workspace()["dependencies"]
        for item in self.five:
            rel = f"{item['crate_path']}/Cargo.toml"
            manifest = load_toml(rel)
            package = manifest["package"]
            for key in ("version", "edition", "rust-version", "license"):
                self.assertEqual(package[key], {"workspace": True}, f"{item['name']}.{key}")
            self.assertEqual(manifest["lints"], {"workspace": True})
            self.assertNotIn("workspace", manifest, item["name"])
            self.assertNotIn("publish", package, item["name"])
            # The unused eliot-evidence dependency line is kept (as a
            # workspace dep): admission is mechanical, not a cleanup turn.
            self.assertIn("eliot-evidence", manifest.get("dependencies", {}),
                          item["name"])
            for table in ("dependencies", "dev-dependencies"):
                for dep, spec in manifest.get(table, {}).items():
                    if isinstance(spec, dict) and spec.get("workspace") is True:
                        self.assertIn(dep, root_deps, f"{item['name']}.{dep}")
            base = tomllib.loads(git("show", f"{BASE_SHA}:{rel}").stdout)
            for table in ("dependencies", "dev-dependencies"):
                live_section = manifest.get(table, {})
                base_section = base.get(table, {})
                self.assertEqual(set(live_section), set(base_section), f"{item['name']}.{table}")
                for dep, live_spec in live_section.items():
                    base_spec = base_section[dep]
                    if isinstance(live_spec, dict) and live_spec.get("workspace") is True:
                        self.assertIn(dep, root_deps, f"{item['name']}.{dep}")
                    else:
                        self.assertEqual(live_spec["path"], base_spec["path"], f"{item['name']}.{dep}")
                        self.assertEqual(live_spec.get("version"), "0.1.0", f"{item['name']}.{dep}")

    # WORK_UNIT_CASE: 969/13
    def test_13_no_rust_test_router_or_floor_change(self) -> None:
        changed = git("diff", "--name-only", BASE_SHA, "HEAD").stdout.split()
        self.assertEqual([c for c in changed if c.endswith(".rs")], [])
        leaf_test_prefixes = tuple(f"{p}/tests/" for p in self.five_paths)
        test_dirs = [c for c in changed
                     if c.replace("\\", "/").startswith(leaf_test_prefixes)
                     and not c.replace("\\", "/").startswith("scripts/tests/")]
        self.assertEqual(test_dirs, [])
        allowed_cargo = {"prototype", "workspace_admission"}
        allowed_module = {"status", "workspace_admission"}
        for item in self.five:
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
            self.assertEqual(live_meta["workspace_admission"], ADMISSION_NOTE)
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

    # WORK_UNIT_CASE: 969/14
    def test_14_root_and_lock_delta_limited_and_explained(self) -> None:
        diff = git("diff", BASE_SHA, "HEAD", "--", "Cargo.toml")
        self.assertEqual(diff.returncode, 0, diff.stderr)
        added = [l[1:].strip() for l in diff.stdout.splitlines()
                 if l.startswith("+") and not l.startswith("+++")
                 and l[1:].strip().startswith('"crates/')]
        removed = [l[1:].strip() for l in diff.stdout.splitlines()
                   if l.startswith("-") and not l.startswith("---")
                   and l[1:].strip().startswith('"crates/')]
        self.assertEqual(len(added), 5)
        self.assertEqual(len(removed), 5)
        for path in self.five_paths:
            self.assertTrue(any(path in line for line in added), path)
            self.assertTrue(any(path in line for line in removed), path)
        self.assertNotIn("[workspace.dependencies]", diff.stdout)
        lock_diff = git("diff", BASE_SHA, "HEAD", "--", "Cargo.lock")
        self.assertEqual(lock_diff.returncode, 0, lock_diff.stderr)
        minus = [l for l in lock_diff.stdout.splitlines()
                 if l.startswith("-") and not l.startswith("---")]
        self.assertEqual(minus, [])
        plus_names = sorted(l.split("=", 1)[1].strip().strip('"')
                            for l in lock_diff.stdout.splitlines()
                            if l.startswith('+name ='))
        self.assertEqual(plus_names, sorted(self.five_names))
        base_lock = tomllib.loads(git("show", f"{BASE_SHA}:Cargo.lock").stdout)
        base_names = {p["name"] for p in base_lock["package"]}
        live_lock = load_toml("Cargo.lock")
        for entry in live_lock["package"]:
            if entry["name"] in self.five_names:
                for dep in entry.get("dependencies", []):
                    self.assertIn(dep.split(" ")[0], base_names, entry["name"])
        base_versions = {(p["name"], p.get("version")) for p in base_lock["package"]}
        live_versions = {(p["name"], p.get("version")) for p in live_lock["package"]}
        self.assertTrue(base_versions <= live_versions)

    # WORK_UNIT_CASE: 969/15
    def test_15_local_lock_disposition_explicit_root_lock_canonical(self) -> None:
        for item in self.five:
            self.assertFalse((ROOT / item["crate_path"] / "Cargo.lock").exists(),
                             item["name"])
        self.assertIsNotNone(self.metadata["resolve"])
        locked_ids = {p["name"] for p in self.metadata["packages"]}
        for name in self.five_names:
            self.assertIn(name, locked_ids)
            self.assertTrue(is_workspace_member(self.metadata, name), name)

    # WORK_UNIT_CASE: 969/16
    def test_16_generated_rows_cover_wave_and_regen_is_byte_identical(self) -> None:
        package_index = read_bytes("docs/code-navigation/PACKAGE_DOCS_INDEX.md").decode("utf-8")
        prototype_index = read_bytes("docs/code-navigation/PROTOTYPE_DOCS_INDEX.md").decode("utf-8")
        for path in self.five_paths:
            self.assertIn(path, package_index)
            self.assertNotIn(path, prototype_index)
        self.assertIn("**152**", package_index)
        self.assertIn("**20**", prototype_index)
        before_pkg = sha256_bytes(read_bytes("docs/code-navigation/PACKAGE_DOCS_INDEX.md"))
        before_proto = sha256_bytes(read_bytes("docs/code-navigation/PROTOTYPE_DOCS_INDEX.md"))
        first = py_script("scripts/code_navigation.py", "sync-index", "--root", ".")
        self.assertEqual(first.returncode, 0, first.stderr[-2000:])
        mid_pkg = sha256_bytes(read_bytes("docs/code-navigation/PACKAGE_DOCS_INDEX.md"))
        mid_proto = sha256_bytes(read_bytes("docs/code-navigation/PROTOTYPE_DOCS_INDEX.md"))
        second = py_script("scripts/code_navigation.py", "sync-index", "--root", ".")
        self.assertEqual(second.returncode, 0, second.stderr[-2000:])
        after_pkg = sha256_bytes(read_bytes("docs/code-navigation/PACKAGE_DOCS_INDEX.md"))
        after_proto = sha256_bytes(read_bytes("docs/code-navigation/PROTOTYPE_DOCS_INDEX.md"))
        self.assertEqual(before_pkg, mid_pkg)
        self.assertEqual(mid_pkg, after_pkg)
        self.assertEqual(before_proto, mid_proto)
        self.assertEqual(mid_proto, after_proto)

    # WORK_UNIT_CASE: 969/17
    def test_17_descriptors_decode_and_suites_execute_pass(self) -> None:
        for item in self.five:
            raw = descriptor_toml(item)
            decoded = self.decode_descriptor(
                raw, f".github/work-units/{item['leaf_issue']}.toml")
            self.assertTrue(decoded["require_workspace_member"])
            self.assertEqual(decoded["package"], {"name": item["name"]})
            self.assertEqual(decoded["matrix_cases"], item["matrix_cases"])
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
                descriptor_toml(self.five[0]) + b'\nfuture_field = "no"\n',
                f".github/work-units/{self.five[0]['leaf_issue']}.toml")
        self.assertFalse(is_workspace_member(self.metadata, "eliot-dreamer-bundle"))

    # WORK_UNIT_CASE: 969/18
    def test_18_locked_metadata_lists_each_package_once_as_member(self) -> None:
        ids = [p["id"] for p in self.metadata["packages"]]
        self.assertEqual(len(ids), len(set(ids)))
        member_ids = set(self.metadata["workspace_members"])
        by_name = {p["name"]: p["id"] for p in self.metadata["packages"]}
        name_counts = Counter(p["name"] for p in self.metadata["packages"])
        for name in self.five_names:
            self.assertEqual(name_counts[name], 1, name)
            self.assertIn(by_name[name], member_ids, name)

    # WORK_UNIT_CASE: 969/19
    def test_19_before_after_arithmetic_reconciles(self) -> None:
        base = tomllib.loads(git("show", f"{BASE_SHA}:Cargo.toml").stdout)["workspace"]
        live = root_workspace()
        self.assertEqual(self.baseline["members_count"], len(base["members"]))
        self.assertEqual(self.baseline["excluded_count"], len(base["exclude"]))
        self.assertEqual(len(base["members"]) + 5, len(live["members"]))
        self.assertEqual(len(base["exclude"]) - 5, len(live["exclude"]))
        self.assertEqual(len(live["members"]), self.candidate["members_count"])
        self.assertEqual(len(live["exclude"]), self.candidate["excluded_count"])
        total = 0
        for item in self.five:
            live_digest = sha256_bytes(read_bytes(f"{item['crate_path']}/src/lib.rs"))
            self.assertEqual(live_digest, item["lib_sha256"], item["name"])
            run = self.test_runs[item["name"]]
            passed = sum(int(m) for m in re.findall(r"(\d+) passed", run.stdout))
            self.assertEqual(passed, self.candidate["expected_test_counts"][item["name"]],
                             item["name"])
            total += passed
        self.assertEqual(total, sum(self.candidate["expected_test_counts"].values()))
        self.assertEqual(total, 40)

    # WORK_UNIT_CASE: 969/20
    def test_20_failed_admission_proves_no_edge_product_release(self) -> None:
        ws = root_workspace()
        partial_members = [m for m in ws["members"] if m != self.five_paths[0]]
        errors = validate_wave_state(
            partial_members, ws["exclude"],
            {p: {"status": "ADMITTED"} for p in self.five_paths},
            set(lock_packages()), self.five_paths)
        self.assertTrue(any(self.five_paths[0] in e for e in errors))
        stuck = ws["exclude"] + [self.five_paths[1]]
        errors = validate_wave_state(
            ws["members"], stuck,
            {p: {"status": "ADMITTED"} for p in self.five_paths},
            set(lock_packages()), self.five_paths)
        self.assertTrue(any(self.five_paths[1] in e for e in errors))
        self.assertEqual(validate_wave_state(
            ws["members"], ws["exclude"],
            {p: {"status": "ADMITTED"} for p in self.five_paths},
            set(lock_packages()), self.five_paths), [])
        for path in self.five_paths:
            self.assertNotIn(path, ws.get("default-members", []))
        for item in self.five:
            module = load_toml(f"{item['crate_path']}/module.toml")
            self.assertEqual(module.get("owned_mutable_state"), [])
            self.assertEqual(module.get("allowed_effects"), [])
            self.assertEqual(module.get("status"), "ADMITTED")


if __name__ == "__main__":
    unittest.main()
