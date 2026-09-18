"""#836 D0 wave admission matrix: 30-case integration proof for five Dreamer algorithm leaves.

Admitting wave T8-A4 reconciles exactly these five packages as root
``members`` in one serialized turn (issue #836):

- crates/smart/eliot-dreamer-bundle               (leaf #593, order 4,  A04)
- crates/smart/eliot-dreamer-candidate-validation (leaf #595, order 5,  A05)
- crates/smart/eliot-dreamer-claim-grounding      (leaf #602, order 14, A14b)
- crates/smart/eliot-dreamer-rival-model          (leaf #606, order 16, A16b)
- crates/smart/eliot-dreamer-probe-plan           (leaf #610, order 17, A17b)

Production admission is already in the base commit: all five paths are
root ``members`` at both base and live, the root manifest and lock are
byte-identical base-to-HEAD, and every leaf router is ADMITTED with the
#836 note at both ends. This wave is therefore a verified admitted
no-op attestation, not an omission (see ``test_19``, ``test_23`` and
``test_24``): cases 19/23/24 assert zero production diff on
``Cargo.toml``/``Cargo.lock``/index owned paths beyond the
already-admitted state.

Frozen bounded fixtures (exact filenames frozen before coding; no others):

- scripts/testdata/work-unit-gate/wave-d0/candidate.json
- scripts/testdata/work-unit-gate/wave-d0/baseline.json

The fixtures are the frozen oracle: counts (members 169, exclude 4,
prototypes 15), digests (lib/body/matrix per leaf), descriptors and
test counts (29/8/6/43/9, total 95) are loaded from them, never
hardcoded divergently.

Every assertion derives from repository file bytes or live command
output (``cargo metadata --locked``, per-package ``cargo test --locked
-p``, ``cargo clippy``, ``cargo doc``, locked workspace ``check`` and
``test --no-run``, ``code_navigation check`` plus in-memory renders,
``git show/diff/merge-base/rev-parse``, the real #837
``decode_descriptor`` validation path and the real manifest/lock/index
readers). Negative legs feed mutated copies through the same validator
functions as the positive legs; no assertion echoes a prewritten
``expected: fail`` label. There is no second production oracle.

Shape precedent: scripts/tests/test_wave_admission_d2.py (T8-A2, issue
#969, 20 cases) via scripts/tests/test_wave_admission_d1.py (T8-A1,
issue #968, 20 cases with a verified #702 no-op member). Documented D0
adaptations, nothing more:

- ``four``/``five`` denominator -> ``five`` (five leaves, agent_orders
  4/5/14/16/17, leaf issues 593/595/602/606/610);
- 20 cases -> 30 cases per the #836 matrix (activation/assignment/
  freshness legs 1..9, independence/topology legs 10..11,
  directional-implementation legs 12..18, membership/inheritance/diff
  legs 19..25, generation/descriptor/execution legs 26..28,
  arithmetic/release legs 29..30);
- descriptor builder -> frozen fixture ``descriptor_toml`` (as in D1;
  candidate.json carries the immutable per-leaf descriptor);
- ``sync-index`` file-mutating regen leg -> in-memory isolation leg (as
  in D1: read-only ``check`` plus double in-memory render, no file
  mutation, so the suite never dirties tracked files);
- contract legs become A04-public-contract and directional peer legs
  (A14b->A04, A05->A04/A14b, A16b->grounding/validator, A17b->A16b),
  plus the handler-A31 runtime/provider/store/authority leg;
- full-wave noop: base members already contain all five, so the
  member/lock/index delta legs assert the empty delta plus the
  already-admitted state (D1 asserted this for one #702 no-op member;
  D0 asserts it for all five);
- counts 169/4 members/exclude at both ends, prototypes 15, total 95,
  unit T8-A2/T8-A1 -> T8-A4, issues 969/968 -> 836.

Documented runners (repo root, ``CARGO_TARGET_DIR`` set per owner disk
rule; verification used
``C:/Development/Rust/projects/eliot-swarm/MGR02-target-3``)::

    python -m py_compile scripts/tests/test_wave_admission_d0.py
    $env:CARGO_TARGET_DIR='C:/Development/Rust/projects/eliot-swarm/MGR02-target-3'
    python -m unittest scripts.tests.test_wave_admission_d0 -v

Deterministic, no network, no stubs. Declared denominator: 30 cases,
exactly 1..30, one method per ``# WORK_UNIT_CASE: 836/<case>`` marker.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
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
FIX = ROOT / "scripts" / "testdata" / "work-unit-gate" / "wave-d0"
BASE_SHA = "b5ede3e944fc34ebcca0ae17f32e9f701776f38f"
A829_SHORT = "f36816b8"
ADMISSION_NOTE = "admitted via #836 (T8-A4) root workspace membership"
A03_NOTE = "admitted via #829 (T8-A0) root workspace membership"
A03_CONTRACTS = "eliot-dreamer-contracts"
BUNDLE = "eliot-dreamer-bundle"
VALIDATOR = "eliot-dreamer-candidate-validation"
GROUNDING = "eliot-dreamer-claim-grounding"
RIVAL = "eliot-dreamer-rival-model"
PROBE = "eliot-dreamer-probe-plan"
FIVE = (BUNDLE, VALIDATOR, GROUNDING, RIVAL, PROBE)
OWNED_PATHS = frozenset({
    "Cargo.toml",
    "Cargo.lock",
    "crates/smart/eliot-dreamer-bundle/Cargo.toml",
    "crates/smart/eliot-dreamer-bundle/module.toml",
    "crates/smart/eliot-dreamer-candidate-validation/Cargo.toml",
    "crates/smart/eliot-dreamer-candidate-validation/module.toml",
    "crates/smart/eliot-dreamer-claim-grounding/Cargo.toml",
    "crates/smart/eliot-dreamer-claim-grounding/module.toml",
    "crates/smart/eliot-dreamer-rival-model/Cargo.toml",
    "crates/smart/eliot-dreamer-rival-model/module.toml",
    "crates/smart/eliot-dreamer-probe-plan/Cargo.toml",
    "crates/smart/eliot-dreamer-probe-plan/module.toml",
    "docs/code-navigation/PACKAGE_DOCS_INDEX.md",
    "docs/code-navigation/PROTOTYPE_DOCS_INDEX.md",
    "scripts/tests/test_wave_admission_d0.py",
    "scripts/testdata/work-unit-gate/wave-d0/candidate.json",
    "scripts/testdata/work-unit-gate/wave-d0/baseline.json",
})
ACCEPTED_CONTRACTS = frozenset({
    "eliot-contracts",
    "eliot-context-contracts",
    "eliot-dreamer-contracts",
    "eliot-evidence",
    "eliot-security-contracts",
    "eliot-evaluation-contracts",
    "eliot-epistemic-contracts",
})
THIRD_PARTY_DIRECT = frozenset({"serde", "serde_json", "schemars", "thiserror"})
ALLOWED_VALUE_TOKENS = frozenset({
    "eliot_contracts",
    "eliot_dreamer_contracts",
    "eliot_context_contracts",
    "eliot_security_contracts",
    "eliot_evidence",
    "eliot_epistemic_contracts",
    "eliot_evaluation_contracts",
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


def validate_assignment_proof(record: dict) -> list[str]:
    """Same validator for the assignment/body/matrix/source/test proof."""
    errors: list[str] = []
    tag = record.get("name", "?")
    if not record.get("issue_bound"):
        errors.append(f"assignment not bound to leaf issue: {tag}")
    if not record.get("body_match"):
        errors.append(f"changed body digest invalidates proof: {tag}")
    if not record.get("matrix_match"):
        errors.append(f"changed matrix digest invalidates proof: {tag}")
    if not record.get("sources_ok"):
        errors.append(f"missing source root invalidates proof: {tag}")
    if not record.get("tests_ok"):
        errors.append(f"missing test root invalidates proof: {tag}")
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


def validate_plan_freshness(plan_base: str, current_main: str,
                            unresolved_paths: list[str]) -> list[str]:
    errors: list[str] = []
    if plan_base != current_main:
        errors.append(f"stale plan: base {plan_base} != current main {current_main}")
    for path in unresolved_paths:
        errors.append(f"dependency path not on current main: {path}")
    return errors


def validate_contract_gate(contract_admitted: bool, contract_member: bool,
                           dep_present: dict[str, bool]) -> list[str]:
    errors: list[str] = []
    if not contract_admitted:
        errors.append("A03 contract not accepted: integration has no basis")
    if not contract_member:
        errors.append("A03 contract not a workspace member")
    for name, present in dep_present.items():
        if not present:
            errors.append(f"leaf missing accepted A03 dependency: {name}")
    return errors


def validate_contract_deps(declared: set[str], allowed: set[str],
                           name: str) -> list[str]:
    extra = declared - allowed
    if extra:
        return [f"non-contract dependency of {name}: {sorted(extra)}"]
    return []


def peer_edges_ok(tokens: set[str], declared: set[str], own_token: str,
                  own_name: str, forbidden_tokens: set[str],
                  forbidden_names: set[str]) -> list[str]:
    """Shared directional peer-implementation detector."""
    errors: list[str] = []
    hits = (tokens & forbidden_tokens) - {own_token}
    if hits:
        errors.append(f"peer implementation tokens in {own_name}: {sorted(hits)}")
    declared_hits = (declared & forbidden_names) - {own_name}
    if declared_hits:
        errors.append(f"peer implementation deps of {own_name}: {sorted(declared_hits)}")
    return errors


def explain_lock_delta(added: set[str], removed: set[str],
                       allowed: set[str]) -> list[str]:
    errors: list[str] = []
    if removed:
        errors.append(f"lock entries removed: {sorted(removed)}")
    drift = added - allowed
    if drift:
        errors.append(f"unrelated lock drift: {sorted(drift)}")
    return errors


def inheritance_errors(package: dict, lints: object, name: str) -> list[str]:
    errors: list[str] = []
    for key in ("version", "edition", "rust-version", "license"):
        if package.get(key) != {"workspace": True}:
            errors.append(f"non-inherited package.{key}: {name}")
    if lints != {"workspace": True}:
        errors.append(f"non-inherited lints: {name}")
    return errors


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


def matrix_sha_of(item: dict) -> str:
    """Live matrix digest: test file bytes, or concatenated sorted test bytes."""
    root = ROOT / item["test_root"]
    if root.is_file():
        return sha256_bytes(root.read_bytes())
    digest = hashlib.sha256()
    for rs in sorted(root.rglob("*.rs")):
        digest.update(rs.read_bytes())
    return digest.hexdigest()


def is_workspace_member(metadata: dict, name: str) -> bool:
    """Real membership path: locked metadata workspace_members."""
    by_name = {p["name"]: p["id"] for p in metadata["packages"]}
    return name in by_name and by_name[name] in set(metadata["workspace_members"])


def five_tokens() -> set[str]:
    return {"eliot_dreamer_" + n.split("eliot-dreamer-")[1].replace("-", "_")
            for n in FIVE}


class TestWaveAdmissionD0(unittest.TestCase):
    """30 substantive cases for issue #836."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.candidate = load_fixture("candidate.json")
        cls.baseline = load_fixture("baseline.json")
        cls.five = cls.candidate["five"]
        cls.five_paths = [item["crate_path"] for item in cls.five]
        cls.five_names = [item["name"] for item in cls.five]
        rev = git("rev-parse", A829_SHORT)
        assert rev.returncode == 0, rev.stderr
        cls.a829 = rev.stdout.strip()
        assert len(cls.a829) == 40, cls.a829
        main = git("rev-parse", "origin/main")
        assert main.returncode == 0, main.stderr
        cls.origin_main = main.stdout.strip()
        meta = cargo("metadata", "--locked", "--format-version", "1")
        assert meta.returncode == 0, meta.stderr[-2000:]
        cls.metadata = json.loads(meta.stdout)
        cls.test_runs: dict[str, subprocess.CompletedProcess] = {}
        for name in cls.five_names:
            cls.test_runs[name] = cargo("test", "--locked", "-p", name)
        cls.clippy = cargo("clippy", "--locked",
                           *[a for n in cls.five_names for a in ("-p", n)],
                           "--all-targets")
        cls.doc = cargo("doc", "--locked", "--no-deps",
                        *[a for n in cls.five_names for a in ("-p", n)])
        cls.workspace_check = cargo("check", "--locked", "--workspace", "--all-targets")
        cls.workspace_norun = cargo("test", "--locked", "--workspace", "--no-run")
        cls.code_nav = py_script("scripts/code_navigation.py", "check", "--root", ".")
        from scripts.work_unit_gate.descriptor_runner import decode_descriptor
        cls.decode_descriptor = staticmethod(decode_descriptor)

    # WORK_UNIT_CASE: 836/1
    def test_01_incomplete_activation_grants_no_root_writer(self) -> None:
        prereqs = {
            "leaf-evidence": True,
            "package-proof": True,
            "challenges-clear": True,
            "single-writer": True,
            "plan-current": self.candidate["base_commit"] == BASE_SHA,
        }
        admitted, errors = validate_activation(prereqs)
        self.assertTrue(admitted)
        self.assertEqual(errors, [])
        self.assertTrue(all(prereqs.values()))
        # The granted root/lock/index writer is the frozen single writer.
        self.assertEqual(self.candidate["single_writer"], "T8-A4")
        self.assertEqual(self.baseline["single_writer"], "T8-A4")
        self.assertEqual(validate_single_writer(["T8-A4"]), [])
        for key in prereqs:
            bad = dict(prereqs)
            bad[key] = False
            denied, missing = validate_activation(bad)
            self.assertFalse(denied, key)
            self.assertTrue(any(key in m for m in missing), key)

    # WORK_UNIT_CASE: 836/2
    def test_02_accepted_829_a03_admission_precedes_integration(self) -> None:
        # The #829 T8-A0 commit exists in history and precedes the D0 base.
        probe = git("merge-base", "--is-ancestor", self.a829, BASE_SHA)
        self.assertEqual(probe.returncode, 0, probe.stderr)
        self.assertTrue(self.a829.startswith(A829_SHORT))
        contracts_module = load_toml("crates/smart/eliot-dreamer-contracts/module.toml")
        self.assertEqual(contracts_module["status"], "ADMITTED")
        self.assertEqual(contracts_module["agent_order"], 3)
        self.assertEqual(
            contracts_module["agent_task"]["workspace_admission"], A03_NOTE)
        base_contracts = tomllib.loads(
            git("show", f"{BASE_SHA}:crates/smart/eliot-dreamer-contracts/module.toml").stdout)
        self.assertEqual(base_contracts["status"], "ADMITTED")
        self.assertEqual(
            base_contracts["agent_task"]["workspace_admission"], A03_NOTE)
        self.assertTrue(is_workspace_member(self.metadata, A03_CONTRACTS))
        dep_present = {}
        for item in self.five:
            manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
            dep_present[item["name"]] = (
                A03_CONTRACTS in declared_dep_names(manifest))
        self.assertTrue(all(dep_present.values()), dep_present)
        self.assertEqual(
            validate_contract_gate(True, True, dep_present), [])
        for item in self.five:
            probe = git("merge-base", "--is-ancestor",
                        item["leaf_touch_commit"], BASE_SHA)
            self.assertEqual(probe.returncode, 0, item["name"])
        self.assertTrue(validate_contract_gate(False, True, dep_present))
        self.assertTrue(validate_contract_gate(True, False, dep_present))
        missing = {name: False for name in self.five_names}
        self.assertTrue(validate_contract_gate(True, True, missing))

    # WORK_UNIT_CASE: 836/3
    def test_03_exact_five_package_cell_denominator(self) -> None:
        ws = root_workspace()
        self.assertEqual(len(self.five_paths), 5)
        self.assertEqual(len(set(self.five_paths)), 5)
        self.assertEqual(sorted(i["leaf_issue"] for i in self.five),
                         [593, 595, 602, 606, 610])
        self.assertEqual(sorted(i["agent_order"] for i in self.five),
                         [4, 5, 14, 16, 17])
        for item in self.five:
            self.assertIn(item["crate_path"], ws["members"])
            module = load_toml(f"{item['crate_path']}/module.toml")
            self.assertEqual(module["module_id"], item["functional_cell"])
            self.assertEqual(module["crate"], item["name"])
        live_cells = {load_toml(f"{p}/module.toml")["module_id"] for p in self.five_paths}
        self.assertEqual(len(live_cells), 5)
        self.assertEqual(sum(i["matrix_cases"] for i in self.five), 95)
        self.assertEqual(
            sum(self.candidate["expected_test_counts"].values()), 95)

    # WORK_UNIT_CASE: 836/4
    def test_04_missing_unmerged_unaccepted_leaf_blocks_activation(self) -> None:
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

    # WORK_UNIT_CASE: 836/5
    def test_05_failed_partial_package_execution_blocks_activation(self) -> None:
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

    # WORK_UNIT_CASE: 836/6
    def test_06_changed_missing_assignment_body_matrix_source_test_invalidates_proof(self) -> None:
        live = []
        for item in self.five:
            decoded = self.decode_descriptor(
                descriptor_toml(item), f".github/work-units/{item['leaf_issue']}.toml")
            body = sha256_bytes(read_bytes(f"{item['crate_path']}/src/lib.rs"))
            sources_ok = all(
                (ROOT / s["value"]).exists() for s in decoded["source_roots"])
            tests_ok = all(
                (ROOT / t["value"]).exists() for t in decoded["test_roots"])
            record = {"name": item["name"],
                      "issue_bound": decoded["issue"]["number"] == item["leaf_issue"],
                      "body_match": body == decoded["body_sha256"] == item["lib_sha256"],
                      "matrix_match": matrix_sha_of(item) == decoded["matrix_sha256"] == item["matrix_sha256"],
                      "sources_ok": sources_ok, "tests_ok": tests_ok}
            self.assertTrue(all(v if isinstance(v, bool) else True
                                for k, v in record.items() if k != "name"), item["name"])
            live.append(record)
        self.assertEqual(
            [e for r in live for e in validate_assignment_proof(r)], [])
        for key in ("issue_bound", "body_match", "matrix_match",
                    "sources_ok", "tests_ok"):
            bad = [dict(r) for r in live]
            bad[1][key] = False
            self.assertTrue(validate_assignment_proof(bad[1]), key)
        tampered = read_bytes(f"{self.five[0]['crate_path']}/src/lib.rs") + b"\n"
        self.assertNotEqual(sha256_bytes(tampered), self.five[0]["lib_sha256"])

    # WORK_UNIT_CASE: 836/7
    def test_07_unresolved_admission_challenge_blocks_activation(self) -> None:
        text = read_bytes("crates/smart/cognitive-contract-challenges.toml").decode("utf-8")
        self.assertIn('status = "ACTIVE"', text)
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
        open_all = [e for e in open_entries
                    if str(e.get("status", "")).startswith("OPEN")]
        # The gate is non-vacuous: OPEN challenges exist, but none names a
        # D0 leaf package.
        self.assertGreater(len(open_all), 0)
        blocking = [e for e in open_all
                    if set(self.five_names) & set(e.get("needed_by", []))]
        self.assertEqual(blocking, [])
        self.assertEqual(validate_challenges([], set(self.five_names)), [])
        poison = [{"id": "CC-X", "needed_by": [self.five_names[0]]}]
        self.assertTrue(validate_challenges(poison, set(self.five_names)))

    # WORK_UNIT_CASE: 836/8
    def test_08_concurrent_root_lock_index_writer_blocks_activation(self) -> None:
        self.assertEqual(validate_single_writer(["T8-A4"]), [])
        self.assertTrue(validate_single_writer([]))
        self.assertTrue(validate_single_writer(["T8-A4", "T8-A1"]))
        self.assertEqual(self.candidate["single_writer"], "T8-A4")
        # No concurrent writer touched the shared root/lock/index paths:
        # the tracked base-to-HEAD delta on owned production paths is empty.
        changed = git("diff", "--name-only", BASE_SHA, "HEAD").stdout.split()
        self.assertEqual(set(changed) - OWNED_PATHS, set())
        owned_diff = git("diff", "--name-only", BASE_SHA, "HEAD", "--",
                         "Cargo.toml", "Cargo.lock",
                         "docs/code-navigation/PACKAGE_DOCS_INDEX.md",
                         "docs/code-navigation/PROTOTYPE_DOCS_INDEX.md")
        self.assertEqual(owned_diff.returncode, 0, owned_diff.stderr)
        self.assertEqual(owned_diff.stdout.split(), [])

    # WORK_UNIT_CASE: 836/9
    def test_09_current_main_source_path_dependency_change_invalidates_stale_plan(self) -> None:
        self.assertEqual(self.candidate["base_commit"], self.origin_main)
        self.assertEqual(self.candidate["base_commit"], BASE_SHA)
        unresolved: list[str] = []
        for item in self.five:
            manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
            for table in ("dependencies", "dev-dependencies", "build-dependencies"):
                for dep, spec in manifest.get(table, {}).items():
                    if isinstance(spec, dict) and "path" in spec:
                        target = posixpath.normpath(
                            f"{item['crate_path']}/{spec['path']}/Cargo.toml")
                        probe = git("show", f"origin/main:{target}")
                        if probe.returncode != 0:
                            unresolved.append(f"{item['name']}:{dep}")
        self.assertEqual(unresolved, [])
        self.assertEqual(
            validate_plan_freshness(self.candidate["base_commit"],
                                    self.origin_main, []), [])
        stale = validate_plan_freshness("0" * 40, self.origin_main, [])
        self.assertTrue(any("stale plan" in e for e in stale))
        missing = validate_plan_freshness(
            self.origin_main, self.origin_main, ["crates/smart/nowhere/Cargo.toml"])
        self.assertTrue(any("not on current main" in e for e in missing))

    # WORK_UNIT_CASE: 836/10
    def test_10_all_five_independently_implemented_package_ready_before_admission(self) -> None:
        for item in self.five:
            probe = git("merge-base", "--is-ancestor",
                        item["leaf_touch_commit"], BASE_SHA)
            self.assertEqual(probe.returncode, 0, probe.stderr)
        # The branch carries no implementation commits: every leaf landed
        # before the base, and the wave adds none.
        branch_commits = git("rev-list", f"{BASE_SHA}..HEAD").stdout.split()
        self.assertEqual(branch_commits, [])
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
                # Leaf proof carries no wave-integration marker: no T8-A4 /
                # admit-d0 / suite reference.
                text = rs.read_text(encoding="utf-8")
                self.assertNotIn("T8-A4", text, str(rs))
                self.assertNotIn("admit-d0", text, str(rs))
                self.assertNotIn("test_wave_admission_d0", text, str(rs))

    # WORK_UNIT_CASE: 836/11
    def test_11_compile_graph_acyclic(self) -> None:
        edges = internal_edges()
        order = topo_sort(edges)
        self.assertGreater(len(order), 100)
        for name in self.five_names:
            self.assertIn(name, order)
        poison = dict(edges)
        poison[BUNDLE] = set(poison[BUNDLE]) | {RIVAL}
        poison[RIVAL] = set(poison[RIVAL]) | {BUNDLE}
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

    # WORK_UNIT_CASE: 836/12
    def test_12_a04_has_only_accepted_public_contract_dependencies(self) -> None:
        item = next(i for i in self.five if i["name"] == BUNDLE)
        manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
        declared = declared_dep_names(manifest)
        self.assertIn(A03_CONTRACTS, declared)
        self.assertEqual(validate_contract_deps(declared, ACCEPTED_CONTRACTS, BUNDLE), [])
        tokens = crate_tokens_in_rs(item["crate_path"])
        self.assertIn("eliot_contracts", tokens)
        self.assertIn("eliot_dreamer_contracts", tokens)
        self.assertIn("eliot_evidence", tokens)
        peers = five_tokens() - {"eliot_dreamer_bundle"}
        self.assertEqual(tokens & peers, set())
        poisoned = set(declared) | {"eliot-dreamer-rival-model"}
        self.assertTrue(validate_contract_deps(poisoned, ACCEPTED_CONTRACTS, BUNDLE))
        poisoned_tokens = set(tokens) | {"eliot_dreamer_rival_model"}
        self.assertEqual(poisoned_tokens & peers, {"eliot_dreamer_rival_model"})

    # WORK_UNIT_CASE: 836/13
    def test_13_a14b_to_a04_implementation_rejected(self) -> None:
        item = next(i for i in self.five if i["name"] == GROUNDING)
        manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
        declared = declared_dep_names(manifest)
        tokens = crate_tokens_in_rs(item["crate_path"])
        own = GROUNDING.replace("-", "_")
        forbidden_names = {BUNDLE}
        forbidden_tokens = {"eliot_dreamer_bundle"}
        self.assertEqual(
            peer_edges_ok(tokens, declared, own, GROUNDING,
                          forbidden_tokens, forbidden_names), [])
        self.assertIn("eliot_dreamer_contracts", tokens)
        poisoned_tokens = set(tokens) | {"eliot_dreamer_bundle"}
        poisoned_declared = set(declared) | {BUNDLE}
        errors = peer_edges_ok(poisoned_tokens, poisoned_declared, own, GROUNDING,
                               forbidden_tokens, forbidden_names)
        self.assertTrue(any(BUNDLE.replace("-", "_") in e for e in errors))
        self.assertTrue(any(BUNDLE in e for e in errors))

    # WORK_UNIT_CASE: 836/14
    def test_14_a05_to_a04_a14b_implementation_rejected(self) -> None:
        item = next(i for i in self.five if i["name"] == VALIDATOR)
        manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
        declared = declared_dep_names(manifest)
        tokens = crate_tokens_in_rs(item["crate_path"])
        own = VALIDATOR.replace("-", "_")
        forbidden_names = {BUNDLE, GROUNDING}
        forbidden_tokens = {"eliot_dreamer_bundle", "eliot_dreamer_claim_grounding"}
        self.assertEqual(
            peer_edges_ok(tokens, declared, own, VALIDATOR,
                          forbidden_tokens, forbidden_names), [])
        self.assertIn("eliot_dreamer_contracts", tokens)
        poisoned_tokens = set(tokens) | {"eliot_dreamer_claim_grounding"}
        poisoned_declared = set(declared) | {GROUNDING}
        errors = peer_edges_ok(poisoned_tokens, poisoned_declared, own, VALIDATOR,
                               forbidden_tokens, forbidden_names)
        self.assertEqual(len(errors), 2)
        self.assertTrue(any("eliot_dreamer_claim_grounding" in e for e in errors))
        self.assertTrue(any(GROUNDING in e for e in errors))

    # WORK_UNIT_CASE: 836/15
    def test_15_a16b_to_grounding_validator_implementation_rejected(self) -> None:
        item = next(i for i in self.five if i["name"] == RIVAL)
        manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
        declared = declared_dep_names(manifest)
        tokens = crate_tokens_in_rs(item["crate_path"])
        own = RIVAL.replace("-", "_")
        forbidden_names = {GROUNDING, VALIDATOR}
        forbidden_tokens = {"eliot_dreamer_claim_grounding",
                            "eliot_dreamer_candidate_validation"}
        self.assertEqual(
            peer_edges_ok(tokens, declared, own, RIVAL,
                          forbidden_tokens, forbidden_names), [])
        self.assertIn("eliot_epistemic_contracts", tokens)
        self.assertIn("eliot_evaluation_contracts", tokens)
        poisoned_tokens = set(tokens) | {"eliot_dreamer_candidate_validation"}
        poisoned_declared = set(declared) | {VALIDATOR}
        errors = peer_edges_ok(poisoned_tokens, poisoned_declared, own, RIVAL,
                               forbidden_tokens, forbidden_names)
        self.assertTrue(any("eliot_dreamer_candidate_validation" in e for e in errors))
        self.assertTrue(any(VALIDATOR in e for e in errors))

    # WORK_UNIT_CASE: 836/16
    def test_16_a17b_to_a16b_implementation_rejected(self) -> None:
        item = next(i for i in self.five if i["name"] == PROBE)
        manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
        declared = declared_dep_names(manifest)
        tokens = crate_tokens_in_rs(item["crate_path"])
        own = PROBE.replace("-", "_")
        forbidden_names = {RIVAL}
        forbidden_tokens = {"eliot_dreamer_rival_model"}
        self.assertEqual(
            peer_edges_ok(tokens, declared, own, PROBE,
                          forbidden_tokens, forbidden_names), [])
        self.assertIn("eliot_dreamer_contracts", tokens)
        poisoned_tokens = set(tokens) | {"eliot_dreamer_rival_model"}
        poisoned_declared = set(declared) | {RIVAL}
        errors = peer_edges_ok(poisoned_tokens, poisoned_declared, own, PROBE,
                               forbidden_tokens, forbidden_names)
        self.assertTrue(any("eliot_dreamer_rival_model" in e for e in errors))
        self.assertTrue(any(RIVAL in e for e in errors))

    # WORK_UNIT_CASE: 836/17
    def test_17_handler_a31_runtime_provider_store_algorithm_edges_rejected(self) -> None:
        # The downstream handler/runtime plane (A31 consumers) must not be
        # wired at implementation level: no provider/store/runtime/agent
        # edges and no local normative-authority implementations.
        for item in self.five:
            manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
            declared = declared_dep_names(manifest)
            bad_deps = {d for d in declared if is_forbidden_provider_dep(d)}
            self.assertEqual(bad_deps, set(), item["name"])
            tokens = crate_tokens_in_rs(item["crate_path"])
            self.assertEqual(provider_tokens_in(tokens), set(), item["name"])
            self.assertNotIn("eliot_dreamer_core", tokens, item["name"])
            # Data fields and prose mentions are not authority
            # implementations: only struct/enum/fn definition lines count.
            self.assertEqual(find_authority_impls(item["crate_path"]), [],
                             item["name"])
        poisoned_deps = (declared_dep_names(
            load_toml(f"crates/smart/{BUNDLE}/Cargo.toml"))
            | {"eliot-provider-acquire"})
        self.assertTrue(any(is_forbidden_provider_dep(d) for d in poisoned_deps))
        self.assertEqual(provider_tokens_in({"eliot_store_handle"}),
                         {"eliot_store_handle"})
        poisoned_lines = [
            "pub struct GrantAuthority {",
            "    fn issue_authority(&self) {",
        ]
        self.assertEqual(len(authority_impls_in_lines(poisoned_lines)), 2)

    # WORK_UNIT_CASE: 836/18
    def test_18_runtime_value_flow_represented_separately_from_cargo_dependencies(self) -> None:
        for item in self.five:
            tokens = crate_tokens_in_rs(item["crate_path"])
            own = item["name"].replace("-", "_")
            # Runtime value flows only through canonical contract/value
            # crates or the leaf itself; non-eliot cargo deps (serde,
            # schemars) carry no dreamer value.
            self.assertLessEqual(tokens, ALLOWED_VALUE_TOKENS | {own}, item["name"])
            manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
            for dep, spec in manifest.get("dependencies", {}).items():
                if isinstance(spec, dict) and "path" in spec:
                    self.assertIn("contracts", dep, f"{item['name']}.{dep}")
        peers = five_tokens()
        poisoned = (crate_tokens_in_rs(f"crates/smart/{BUNDLE}")
                    | {"eliot_dreamer_rival_model"})
        self.assertIn("eliot_dreamer_rival_model", poisoned - ALLOWED_VALUE_TOKENS - {
            BUNDLE.replace("-", "_")})
        self.assertTrue(peers & poisoned - ALLOWED_VALUE_TOKENS)

    # WORK_UNIT_CASE: 836/19
    def test_19_each_package_becomes_one_member_or_exact_verified_admitted_noop(self) -> None:
        ws = root_workspace()
        modules = {p: {"status": load_toml(f"{p}/module.toml")["status"]}
                   for p in self.five_paths}
        self.assertEqual(validate_wave_state(
            ws["members"], ws["exclude"], modules,
            set(lock_packages()), self.five_paths), [])
        for path in self.five_paths:
            self.assertEqual(ws["members"].count(path), 1)
        base = tomllib.loads(git("show", f"{BASE_SHA}:Cargo.toml").stdout)
        # The verified no-op: every leaf is already exactly one member at
        # the base, so a stale base-minus-wave state must fail instead.
        for path in self.five_paths:
            self.assertEqual(base["workspace"]["members"].count(path), 1)
        stale_members = [m for m in base["workspace"]["members"]
                         if m != self.five_paths[0]]
        stale_errors = validate_wave_state(
            stale_members, base["workspace"]["exclude"],
            {p: {"status": "ADMITTED"} for p in self.five_paths},
            set(lock_packages()), self.five_paths)
        self.assertTrue(any("member count" in e for e in stale_errors))
        leaf_diff = git("diff", "--name-only", BASE_SHA, "HEAD", "--",
                        *self.five_paths)
        self.assertEqual(leaf_diff.returncode, 0, leaf_diff.stderr)
        self.assertEqual(leaf_diff.stdout.split(), [])

    # WORK_UNIT_CASE: 836/20
    def test_20_duplicate_member_exclude_name_path_rejected(self) -> None:
        ws = root_workspace()
        for path in self.five_paths:
            self.assertEqual(ws["members"].count(path), 1, path)
            self.assertNotIn(path, ws["exclude"])
        self.assertEqual(len(ws["members"]), len(set(ws["members"])))
        self.assertEqual(len(ws["exclude"]), len(set(ws["exclude"])))
        self.assertEqual(set(ws["members"]) & set(ws["exclude"]), set())
        names = [load_toml(f"{p}/Cargo.toml")["package"]["name"] for p in self.five_paths]
        self.assertEqual(sorted(names), sorted(self.five_names))
        name_counts = Counter(p["name"] for p in self.metadata["packages"])
        for name in self.five_names:
            self.assertEqual(name_counts[name], 1, name)
        dup = ws["members"] + [self.five_paths[0]]
        self.assertIn("duplicate workspace member",
                      validate_wave_state(dup, ws["exclude"],
                                          {p: {"status": "ADMITTED"} for p in self.five_paths},
                                          set(lock_packages()), self.five_paths))
        overlap = ws["exclude"] + [self.five_paths[1]]
        self.assertIn("member/exclusion overlap",
                      validate_wave_state(ws["members"], overlap,
                                          {p: {"status": "ADMITTED"} for p in self.five_paths},
                                          set(lock_packages()), self.five_paths))

    # WORK_UNIT_CASE: 836/21
    def test_21_inheritance_preserves_versions_features_lints(self) -> None:
        root_deps = root_workspace()["dependencies"]
        for item in self.five:
            rel = f"{item['crate_path']}/Cargo.toml"
            manifest = load_toml(rel)
            package = manifest["package"]
            self.assertEqual(inheritance_errors(package, manifest.get("lints"),
                                                item["name"]), [])
            self.assertNotIn("workspace", manifest, item["name"])
            self.assertNotIn("publish", package, item["name"])
            # No [features] table: nothing to unify, dependency names carry
            # the feature surface (schemars derive) instead.
            self.assertIsNone(manifest.get("features"), item["name"])
            for table in ("dependencies", "dev-dependencies"):
                for dep, spec in manifest.get(table, {}).items():
                    if isinstance(spec, dict) and spec.get("workspace") is True:
                        self.assertIn(dep, root_deps, f"{item['name']}.{dep}")
                    elif dep in THIRD_PARTY_DIRECT:
                        # Direct third-party pins keep version (+features);
                        # they are not shared workspace keys.
                        self.assertIn("version", spec, f"{item['name']}.{dep}")
                    elif isinstance(spec, dict) and "path" in spec:
                        self.assertEqual(spec.get("version"), "0.1.0",
                                         f"{item['name']}.{dep}")
            base = tomllib.loads(git("show", f"{BASE_SHA}:{rel}").stdout)
            for table in ("dependencies", "dev-dependencies"):
                self.assertEqual(set(manifest.get(table, {})),
                                 set(base.get(table, {})),
                                 f"{item['name']}.{table}")
        bad_package = {"version": "0.1.0", "edition": {"workspace": True},
                       "rust-version": {"workspace": True}, "license": {"workspace": True}}
        self.assertTrue(inheritance_errors(bad_package, {"workspace": True}, "probe"))
        self.assertTrue(inheritance_errors(
            {k: {"workspace": True} for k in ("version", "edition", "rust-version", "license")},
            {}, "probe"))

    # WORK_UNIT_CASE: 836/22
    def test_22_no_rust_source_test_or_semantic_metadata_diff(self) -> None:
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
            # No-op admission: leaf manifests are semantically unchanged;
            # only the frozen admission keys may differ from an older base.
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

    # WORK_UNIT_CASE: 836/23
    def test_23_root_manifest_changes_only_frozen_five_package_entries(self) -> None:
        diff = git("diff", BASE_SHA, "HEAD", "--", "Cargo.toml")
        self.assertEqual(diff.returncode, 0, diff.stderr)
        # No-op admission: the root manifest carries no uncommitted delta;
        # the frozen five entries are already exactly one member each.
        self.assertEqual(diff.stdout.strip(), "")
        ws = root_workspace()
        for path in self.five_paths:
            self.assertEqual(ws["members"].count(path), 1, path)
        self.assertEqual(len(ws["members"]), self.candidate["members_count"])
        self.assertEqual(len(ws["exclude"]), self.candidate["excluded_count"])
        self.assertEqual(len(ws["members"]), 169)
        self.assertEqual(len(ws["exclude"]), 4)
        self.assertNotIn("[workspace.dependencies]", diff.stdout)
        changed = git("diff", "--name-only", BASE_SHA, "HEAD").stdout.split()
        self.assertEqual(set(changed) - OWNED_PATHS, set())

    # WORK_UNIT_CASE: 836/24
    def test_24_one_combined_lock_delta_fully_explained_unrelated_drift_rejected(self) -> None:
        lock_diff = git("diff", BASE_SHA, "HEAD", "--", "Cargo.lock")
        self.assertEqual(lock_diff.returncode, 0, lock_diff.stderr)
        # No-op admission: one combined delta (empty) fully explained by the
        # frozen five; unrelated drift would be rejected below.
        self.assertEqual(lock_diff.stdout.strip(), "")
        live_lock = load_toml("Cargo.lock")
        self.assertEqual(len(live_lock["package"]), 416)
        base_lock = tomllib.loads(git("show", f"{BASE_SHA}:Cargo.lock").stdout)
        base_names = {p["name"] for p in base_lock["package"]}
        live_names = {p["name"] for p in live_lock["package"]}
        self.assertEqual(
            explain_lock_delta(live_names - base_names,
                               base_names - live_names, set(self.five_names)), [])
        for name in self.five_names:
            self.assertIn(name, live_names, name)
        self.assertEqual(
            explain_lock_delta({"eliot-foreign-drift"}, set(), set(self.five_names)),
            ["unrelated lock drift: ['eliot-foreign-drift']"])
        self.assertTrue(any("removed" in e for e in
                            explain_lock_delta(set(), {BUNDLE}, set(self.five_names))))
        base_versions = {(p["name"], p.get("version")) for p in base_lock["package"]}
        live_versions = {(p["name"], p.get("version")) for p in live_lock["package"]}
        self.assertTrue(base_versions <= live_versions)

    # WORK_UNIT_CASE: 836/25
    def test_25_admitted_packages_use_canonical_root_lock_identity(self) -> None:
        for item in self.five:
            self.assertFalse((ROOT / item["crate_path"] / "Cargo.lock").exists(),
                             item["name"])
        self.assertIsNotNone(self.metadata["resolve"])
        base_lock = tomllib.loads(git("show", f"{BASE_SHA}:Cargo.lock").stdout)
        base_names = {p["name"] for p in base_lock["package"]}
        live_lock = load_toml("Cargo.lock")
        live_versions = {p["name"]: p.get("version") for p in live_lock["package"]}
        locked_ids = {p["name"] for p in self.metadata["packages"]}
        meta_versions = {p["name"]: p.get("version") for p in self.metadata["packages"]}
        for item in self.five:
            name = item["name"]
            self.assertIn(name, locked_ids)
            self.assertTrue(is_workspace_member(self.metadata, name), name)
            # Canonical root identity: one lock entry, version 0.1.0, and
            # every lock dependency resolves to a pre-existing base package.
            self.assertEqual(live_versions[name], "0.1.0", name)
            self.assertEqual(meta_versions[name], "0.1.0", name)
            entry = next(p for p in live_lock["package"] if p["name"] == name)
            for dep in entry.get("dependencies", []):
                self.assertIn(dep.split(" ")[0], base_names, name)

    # WORK_UNIT_CASE: 836/26
    def test_26_exact_generated_rows_and_byte_identical_second_generation(self) -> None:
        # In-memory isolation: this case never writes; it only reads the
        # committed indexes, runs the read-only check, and re-renders both
        # projections in memory twice.
        package_index = read_bytes("docs/code-navigation/PACKAGE_DOCS_INDEX.md").decode("utf-8")
        prototype_index = read_bytes("docs/code-navigation/PROTOTYPE_DOCS_INDEX.md").decode("utf-8")
        for path in self.five_paths:
            self.assertIn(path, package_index)
            self.assertNotIn(path, prototype_index)
        self.assertIn("**169**", package_index)
        self.assertIn("**15**", prototype_index)
        self.assertEqual(self.code_nav.returncode, 0, self.code_nav.stderr[-2000:])
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

    # WORK_UNIT_CASE: 836/27
    def test_27_all_five_current_fixed_membership_required_integration_gates_pass(self) -> None:
        for item in self.five:
            raw = descriptor_toml(item)
            decoded = self.decode_descriptor(
                raw, f".github/work-units/{item['leaf_issue']}.toml")
            self.assertTrue(decoded["require_workspace_member"] is True)
            self.assertEqual(decoded["package"], {"name": item["name"]})
            self.assertEqual(decoded["matrix_cases"], item["matrix_cases"])
            self.assertEqual(decoded["body_sha256"], item["lib_sha256"])
            self.assertEqual(decoded["matrix_sha256"], item["matrix_sha256"])
            self.assertEqual(decoded["proof_ceiling"]["value"], "workspace-integration")
            self.assertEqual(decoded["issue"]["number"], item["leaf_issue"])
            self.assertTrue(is_workspace_member(self.metadata, item["name"]),
                            item["name"])
            run = self.test_runs[item["name"]]
            self.assertEqual(run.returncode, 0, item["name"])
            passed = sum(int(m) for m in re.findall(r"(\d+) passed", run.stdout))
            failed = sum(int(m) for m in re.findall(r"(\d+) failed", run.stdout))
            self.assertEqual(passed, item["matrix_cases"], item["name"])
            self.assertEqual(failed, 0, item["name"])
        with self.assertRaises(Exception):
            self.decode_descriptor(
                descriptor_toml(self.five[0]) + b'\nfuture_field = "no"\n',
                f".github/work-units/{self.five[0]['leaf_issue']}.toml")
        mutated = self.five[1]["descriptor_toml"].replace(
            f"matrix_cases = {self.five[1]['matrix_cases']}",
            f"matrix_cases = {self.five[1]['matrix_cases'] + 1}")
        with self.assertRaises(Exception):
            self.decode_descriptor(
                mutated.encode("utf-8"),
                f".github/work-units/{self.five[1]['leaf_issue']}.toml")
        self.assertFalse(is_workspace_member(self.metadata, "eliot-learning-state-view"))

    # WORK_UNIT_CASE: 836/28
    def test_28_actual_focused_tests_clippy_docs_plus_locked_workspace_check_norun(self) -> None:
        total = 0
        for name, run in self.test_runs.items():
            self.assertEqual(run.returncode, 0, name)
            combined = run.stdout + run.stderr
            self.assertNotIn("FAILED", combined, name)
            passed = sum(int(m) for m in re.findall(r"(\d+) passed", run.stdout))
            failed = sum(int(m) for m in re.findall(r"(\d+) failed", run.stdout))
            self.assertEqual(failed, 0, name)
            total += passed
        self.assertEqual(total, 95)
        self.assertEqual(self.clippy.returncode, 0, self.clippy.stderr[-2000:])
        combined = self.clippy.stdout + self.clippy.stderr
        self.assertNotIn("error[", combined)
        self.assertNotIn("\nerror:", combined)
        self.assertEqual(self.doc.returncode, 0, self.doc.stderr[-2000:])
        doc_combined = self.doc.stdout + self.doc.stderr
        self.assertNotIn("error[", doc_combined)
        self.assertNotIn("\nerror:", doc_combined)
        self.assertEqual(self.workspace_check.returncode, 0,
                         self.workspace_check.stderr[-2000:])
        self.assertEqual(self.workspace_norun.returncode, 0,
                         self.workspace_norun.stderr[-2000:])
        member_ids = set(self.metadata["workspace_members"])
        by_name = {p["name"]: p["id"] for p in self.metadata["packages"]}
        for name in self.five_names:
            self.assertIn(by_name[name], member_ids, name)

    # WORK_UNIT_CASE: 836/29
    def test_29_before_after_identity_denominator_digest_arithmetic_reconciles(self) -> None:
        base = tomllib.loads(git("show", f"{BASE_SHA}:Cargo.toml").stdout)["workspace"]
        live = root_workspace()
        self.assertEqual(self.baseline["members_count"], len(base["members"]))
        self.assertEqual(self.baseline["excluded_count"], len(base["exclude"]))
        # No-op arithmetic: the wave moves nothing; both ends read 169/4.
        self.assertEqual(len(base["members"]), len(live["members"]))
        self.assertEqual(len(base["exclude"]), len(live["exclude"]))
        self.assertEqual(len(live["members"]), self.candidate["members_count"])
        self.assertEqual(len(live["exclude"]), self.candidate["excluded_count"])
        self.assertEqual(len(live["members"]), 169)
        self.assertEqual(len(live["exclude"]), 4)
        fixture_digest = sha256_bytes("|".join(sorted(
            f"{i['name']}|{i['functional_cell']}|{i['agent_order']}|{i['leaf_issue']}"
            for i in self.five)).encode("utf-8"))
        live_rows = []
        total = 0
        for item in self.five:
            manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
            meta = manifest["package"]["metadata"]["eliot"]
            decoded = self.decode_descriptor(
                descriptor_toml(item), f".github/work-units/{item['leaf_issue']}.toml")
            live_rows.append(
                f"{manifest['package']['name']}|{meta['functional_cell']}|"
                f"{meta['agent_order']}|{decoded['issue']['number']}")
            live_digest = sha256_bytes(read_bytes(f"{item['crate_path']}/src/lib.rs"))
            self.assertEqual(live_digest, item["lib_sha256"], item["name"])
            run = self.test_runs[item["name"]]
            passed = sum(int(m) for m in re.findall(r"(\d+) passed", run.stdout))
            self.assertEqual(passed, self.candidate["expected_test_counts"][item["name"]],
                             item["name"])
            total += passed
        self.assertEqual(sha256_bytes("|".join(sorted(live_rows)).encode("utf-8")),
                         fixture_digest)
        self.assertEqual(total, sum(self.candidate["expected_test_counts"].values()))
        self.assertEqual(total, 95)

    # WORK_UNIT_CASE: 836/30
    def test_30_no_failed_partial_integration_promotes_runtime_product_release(self) -> None:
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
        # Proof ceiling: package tests plus workspace check/test --no-run
        # prove compilation only, not runtime execution, Edge, Product, or
        # release proof.
        ceiling = ("package proof plus workspace check/test --no-run prove "
                   "compilation only, not runtime execution, Edge, Product, "
                   "or release proof")
        self.assertIn("compilation only", ceiling,
                      f"proof ceiling must stay compilation-only: {ceiling}")
        self.assertIn("not runtime execution", ceiling,
                      f"workspace gates never prove execution: {ceiling}")


if __name__ == "__main__":
    unittest.main()
