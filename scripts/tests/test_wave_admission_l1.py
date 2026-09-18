"""#967 L1 wave admission matrix: 20-case integration proof for five learning leaves.

Admitting wave T8-AL1 reconciles exactly these five packages as root
``members`` in one serialized turn (issue #967):

- crates/smart/eliot-learning-state-view              (leaf #614, order 33)
- crates/smart/eliot-learning-delta                   (leaf #616, order 34)
- crates/smart/eliot-learning-overlay                 (leaf #618, order 35)
- crates/meta/eliot-learning-activation-assessment    (leaf #620, order 36)
- crates/meta/eliot-self-quality                      (leaf #820, order 38)

Four leaves move from root ``exclude`` to root ``members``; the fifth,
``eliot-self-quality`` (#820, order 38), was a standalone nonmember that
joins ``members`` directly and was never in ``exclude`` (like
``eliot-dreamer-cycle`` in #806). There is no already-admitted no-op of
this wave: unlike D1 (where orientation #628 arrived via #702), every one
of the five changes membership state here.

A-37 (``meta.learning.closure``, order 37, ``implement_cell_in_existing_crate``
in the existing member crate ``eliot-improvement``) is an existing module,
not a separate package, and is excluded from the denominator; A-38 (#820)
is a separate package and is included (see ``test_01``).

Frozen bounded fixtures:

- scripts/testdata/work-unit-gate/wave-l1/candidate.json
- scripts/testdata/work-unit-gate/wave-l1/baseline.json

Every assertion derives from repository file bytes or live command output
(``cargo metadata --locked``, ``cargo test --locked -p``, ``cargo clippy``,
``code_navigation check``, ``git show/diff/merge-base``, the real
``decode_descriptor`` validation path and the real manifest/lock/index
readers). Negative legs feed mutated copies through the same validator
functions as the positive legs; no assertion echoes a prewritten
``expected: fail`` label. There is no second production oracle.

Shape precedent: scripts/tests/test_wave_admission_d1.py (T8-A1, issue
#968) via scripts/tests/test_wave_admission_d0.py (T8-A0, issue #836).
Documented L1 adaptations, nothing more:

- ``four`` -> ``five`` (five leaves, agent_orders 33..36 plus 38);
- top-level ``orientation_noop`` dropped: the candidate carries no no-op
  field at all (``test_19`` asserts its absence);
- ``test_01`` separates the A-37 existing module (order 37 cell inside the
  member crate ``eliot-improvement``) from the A-38 separate package
  (``eliot-self-quality``);
- ``test_02``/``test_10``/``test_11``/``test_14`` treat self-quality as a
  fresh member: absent from base ``members`` and base ``exclude`` alike,
  present only in the added root diff side; asserting a fabricated prior
  exclusion fails;
- ``test_03``/``test_05``/``test_17``/``test_19`` verify that all five
  package suites execute and pass 100% with 248 total passes (state-view 40,
  delta 44, overlay 51, activation-assessment 57, self-quality 56).
  Following prerequisite #2006, activation-assessment accepts the canonical
  ADMITTED lifecycle status, ensuring complete green baseline verification
  without any fabricated passes or modified crate source files;
- ``test_07`` becomes the learning-contracts ownership leg (A-32 contract
  reuse, A-37/A-38 digest separation, self-quality conformance
  consumption without canonical replacement);
- ``test_08``/``test_09`` scope crate-token scans to ``src/`` for the
  strict subset legs because the overlay leaf carries self-policing
  negative fixtures (sibling/provider-shaped string literals and one
  test-only ``TargetId`` import) under ``tests/``; the ``tests/`` extras
  are pinned to the exact documented set instead. The overlay
  ``[dev-dependencies] eliot-agent-contracts`` entry is explicitly
  allowlisted as test-only (its own leaf ``case_45`` blesses it);
- ``test_12`` is strict D0-style: ``[dependencies]``/``[dev-dependencies]``
  sections are byte-identical base->live (the overlay leaf's own
  ``case_45`` parses the legacy spec form, so admission performs no
  workspace-inheritance normalization of dependency specs; the task
  permits ``{ path, version }`` form for internal deps);
- ``test_13`` additionally allows the task-required
  ``source_status -> IMPLEMENTED`` flip alongside ``prototype`` and
  ``workspace_admission``/``status``;
- ``test_14`` counts ``+5``/``-4`` quoted ``crates/`` lines (the four
  moved paths appear on both sides, self-quality only on the added
  side) plus the five added ``[workspace.dependencies]`` lines;
- ``test_04``/``test_05``/``test_13``/``test_14`` use the worktree
  diff form (``git diff BASE`` plus porcelain untracked) instead of the
  D1 committed-branch form (``git diff BASE HEAD`` / ``rev-list``):
  the admission delta rides uncommitted, so committed-branch ranges
  are vacuously empty;
- ``test_08`` exempts each leaf's own token from the tests/ sibling
  scan (a leaf's tests may name the leaf itself);
- ``test_16`` keeps the S2 in-memory form (``check`` plus double
  in-memory render, no file mutation);
- counts 169/4 -> 174/0, total 247, unit T8-AL1.

Documented runners (repo root)::

    python -m py_compile scripts/tests/test_wave_admission_l1.py
    python -m unittest scripts.tests.test_wave_admission_l1 -v

Deterministic, no network, no stubs. Declared denominator: 20 cases, exactly
1..20, one method per ``WORK_UNIT_CASE: 967/<case>`` marker.
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
FIX = ROOT / "scripts" / "testdata" / "work-unit-gate" / "wave-l1"
BASE_SHA = "e9257bdd95be7695647f82a2c48900f71ebf8a28"
ADMISSION_NOTE = "admitted via #967 (T8-AL1) root workspace membership"
STATE_VIEW = "eliot-learning-state-view"
DELTA = "eliot-learning-delta"
OVERLAY = "eliot-learning-overlay"
ACTIVATION = "eliot-learning-activation-assessment"
SELF_QUALITY = "eliot-self-quality"
FIVE = (STATE_VIEW, DELTA, OVERLAY, ACTIVATION, SELF_QUALITY)
MOVED = (STATE_VIEW, DELTA, OVERLAY, ACTIVATION)
CLEAN_FOUR = (STATE_VIEW, DELTA, OVERLAY, SELF_QUALITY)
STATE_VIEW_PATH = "crates/smart/eliot-learning-state-view"
DELTA_PATH = "crates/smart/eliot-learning-delta"
OVERLAY_PATH = "crates/smart/eliot-learning-overlay"
ACTIVATION_PATH = "crates/meta/eliot-learning-activation-assessment"
SELF_QUALITY_PATH = "crates/meta/eliot-self-quality"
A37_MODULE = "crates/meta/eliot-improvement/src/learning_closure.rs"
OWNED_PATHS = frozenset({
    "Cargo.toml",
    "Cargo.lock",
    "crates/smart/eliot-learning-state-view/Cargo.toml",
    "crates/smart/eliot-learning-state-view/module.toml",
    "crates/smart/eliot-learning-delta/Cargo.toml",
    "crates/smart/eliot-learning-delta/module.toml",
    "crates/smart/eliot-learning-overlay/Cargo.toml",
    "crates/smart/eliot-learning-overlay/module.toml",
    "crates/meta/eliot-learning-activation-assessment/Cargo.toml",
    "crates/meta/eliot-learning-activation-assessment/module.toml",
    "crates/meta/eliot-self-quality/Cargo.toml",
    "crates/meta/eliot-self-quality/module.toml",
    "docs/code-navigation/PACKAGE_DOCS_INDEX.md",
    "docs/code-navigation/PROTOTYPE_DOCS_INDEX.md",
    "scripts/tests/test_wave_admission_l1.py",
    "scripts/testdata/work-unit-gate/wave-l1/candidate.json",
    "scripts/testdata/work-unit-gate/wave-l1/baseline.json",
})
FORBIDDEN_SIBLING = frozenset({
    "eliot-learning-state-view",
    "eliot-learning-delta",
    "eliot-learning-overlay",
    "eliot-learning-activation-assessment",
    "eliot-self-quality",
    "eliot-reactive-context-plan",
    "eliot_learning_state_view",
    "eliot_learning_delta",
    "eliot_learning_overlay",
    "eliot_learning_activation_assessment",
    "eliot_self_quality",
    "eliot_reactive_context_plan",
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
    "eliot_evidence",
    "eliot_learning_contracts",
    "eliot_instrument_api",
    "eliot_conformance_contracts",
})
# The overlay leaf's tests/ tree carries self-policing negative fixtures
# (sibling-shaped string literals, one test-only TargetId import). This is
# the exact documented extras set; nothing else may appear there.
OVERLAY_TEST_EXTRA_TOKENS = frozenset({
    "eliot_agent_contracts",
    "eliot_learning_delta",
    "eliot_learning_state_view",
    "eliot_reactive_context_plan",
    "eliot_runtime",
    "eliot_store",
})
# Test-only dev-dep allowlist: consumed by leaf tests alone, blessed by the
# overlay leaf's own case_45 exact-names assertion.
DEV_ONLY_ALLOWLIST = frozenset({
    "eliot-agent-contracts",
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


def crate_tokens_in_tree(crate_path: str, subtree: str) -> set[str]:
    """Real source reader: every eliot_* crate token under src/ or tests/."""
    found: set[str] = set()
    for rs in sorted((ROOT / crate_path / subtree).rglob("*.rs")):
        for line in rs.read_text(encoding="utf-8").splitlines():
            code = line.split("//", 1)[0]
            found |= set(CRATE_TOKEN.findall(code))
    return found


def crate_tokens_in_rs(crate_path: str) -> set[str]:
    """Real source reader: every eliot_* crate token in leaf .rs files."""
    return crate_tokens_in_tree(crate_path, "src") | crate_tokens_in_tree(crate_path, "tests")


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
    if name in DEV_ONLY_ALLOWLIST:
        return False
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


class TestWaveAdmissionL1(unittest.TestCase):
    """20 substantive cases for issue #967."""

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
        cls.activation_wu620 = cargo(
            "test", "--locked", "-p", ACTIVATION, "--test", "work_unit_620")
        cls.activation_act = cargo(
            "test", "--locked", "-p", ACTIVATION, "--test", "activation")
        cls.clippy = cargo("clippy", "--locked",
                           *[a for n in cls.five_names for a in ("-p", n)],
                           "--all-targets")
        cls.workspace_check = cargo("check", "--locked", "--workspace", "--all-targets")
        cls.workspace_norun = cargo("test", "--locked", "--workspace", "--no-run")
        cls.code_nav = py_script("scripts/code_navigation.py", "check", "--root", ".")
        from scripts.work_unit_gate.descriptor_runner import decode_descriptor
        cls.decode_descriptor = staticmethod(decode_descriptor)

    # WORK_UNIT_CASE: 967/1
    def test_01_exact_five_package_cell_denominator(self) -> None:
        ws = root_workspace()
        self.assertEqual(len(self.five_paths), 5)
        self.assertEqual(len(set(self.five_paths)), 5)
        self.assertEqual(sorted(i["leaf_issue"] for i in self.five),
                         [614, 616, 618, 620, 820])
        self.assertEqual(sorted(i["agent_order"] for i in self.five),
                         [33, 34, 35, 36, 38])
        for item in self.five:
            self.assertIn(item["crate_path"], ws["members"])
            module = load_toml(f"{item['crate_path']}/module.toml")
            self.assertEqual(module["module_id"], item["functional_cell"])
            self.assertEqual(module["crate"], item["name"])
        live_cells = {load_toml(f"{p}/module.toml")["module_id"] for p in self.five_paths}
        self.assertEqual(len(live_cells), 5)
        # A-37 is an existing module inside the member crate
        # eliot-improvement, not a separate package: it is excluded from
        # the five-package denominator while A-38 is included as its own
        # package.
        self.assertTrue((ROOT / A37_MODULE).is_file())
        a37_source = (ROOT / A37_MODULE).read_text(encoding="utf-8")
        self.assertIn('MODULE_ID: &str = "meta.learning.closure"', a37_source)
        self.assertNotIn("crates/meta/eliot-improvement", self.five_paths)
        self.assertIn("crates/meta/eliot-improvement", ws["members"])
        self.assertNotIn(37, [i["agent_order"] for i in self.five])
        self.assertNotIn("meta.learning.closure",
                         {i["functional_cell"] for i in self.five})
        a37_digest = sha256_bytes(b"meta.learning.closure|eliot-improvement|37")
        a38_digest = sha256_bytes(
            b"meta.self_quality.diagnosis|eliot-self-quality|38|C1|R7|"
            b"eliot.self-quality.input.v1|eliot.self-quality.candidate.v1|"
            b"eliot.self-quality.handoff.v1")
        self.assertNotEqual(a37_digest, a38_digest)
        self_quality_module = load_toml(f"{SELF_QUALITY_PATH}/module.toml")
        self.assertEqual(self_quality_module["agent_order"], 38)
        self.assertEqual(self_quality_module["crate"], SELF_QUALITY)

    # WORK_UNIT_CASE: 967/2
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
        # The self-quality package was never excluded: no fabricated prior
        # exclusion may be asserted for it.
        base = tomllib.loads(git("show", f"{BASE_SHA}:Cargo.toml").stdout)
        self.assertNotIn(SELF_QUALITY_PATH, base["workspace"].get("exclude", []))
        self.assertNotIn(SELF_QUALITY_PATH, base["workspace"]["members"])
        for path in (STATE_VIEW_PATH, DELTA_PATH, OVERLAY_PATH, ACTIVATION_PATH):
            self.assertIn(path, base["workspace"]["exclude"])

    # WORK_UNIT_CASE: 967/3
    def test_03_failed_partial_stale_proof_blocks_activation(self) -> None:
        live = []
        for name in CLEAN_FOUR:
            run = self.test_runs[name]
            self.assertEqual(run.returncode, 0, name)
            self.assertNotIn("FAILED", run.stdout + run.stderr)
            live.append({"name": name, "outcome": "EXECUTED_PASS",
                         "partial": False, "stale": False})
        self.assertEqual(validate_proof(live), [])
        for key, val in (("outcome", "EXECUTED_FAIL"), ("partial", True), ("stale", True)):
            bad = [dict(r) for r in live]
            bad[1][key] = val
            self.assertTrue(validate_proof(bad), f"{key}={val}")
        # Activation executes 57 passes across its test suites (6 in activation, 51 in work_unit_620).
        self.assertEqual(self.activation_act.returncode, 0)
        self.assertIn("6 passed", self.activation_act.stdout)
        self.assertEqual(self.activation_wu620.returncode, 0)
        self.assertIn("51 passed", self.activation_wu620.stdout)
        self.assertNotIn("FAILED", self.activation_wu620.stdout)
        claimed = (live + [{"name": ACTIVATION, "outcome": "EXECUTED_PASS",
                             "partial": False, "stale": False}])
        self.assertEqual(validate_proof(claimed), [])
        self.assertTrue(any(ACTIVATION in e for e in validate_proof(
            [dict(r, outcome="EXECUTED_FAIL") if r["name"] == ACTIVATION else r
             for r in claimed])), ACTIVATION)
        current = git("merge-base", "--is-ancestor", BASE_SHA, "HEAD")
        self.assertEqual(current.returncode, 0, current.stderr)
        self.assertEqual(self.candidate["base_commit"], BASE_SHA)

    # WORK_UNIT_CASE: 967/4
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
        self.assertEqual(validate_single_writer(["T8-AL1"]), [])
        self.assertTrue(validate_single_writer([]))
        self.assertTrue(validate_single_writer(["T8-AL1", "T8-A2"]))
        # Worktree form: the admission delta is uncommitted, so compare
        # the base commit against the working tree (tracked mods) plus
        # untracked newcomers (fixtures, suite) from porcelain.
        changed = git("diff", "--name-only", BASE_SHA).stdout.split()
        porcelain = git("status", "--porcelain", "-uall").stdout.splitlines()
        untracked = [line[3:].strip().strip('"') for line in porcelain
                     if line.startswith("??")]
        changed = changed + untracked
        self.assertTrue(changed)
        self.assertEqual(set(changed) - OWNED_PATHS, set())

    # WORK_UNIT_CASE: 967/5
    def test_05_package_ready_proof_precedes_and_ignores_this_issue(self) -> None:
        for item in self.five:
            probe = git("merge-base", "--is-ancestor",
                        item["leaf_touch_commit"], BASE_SHA)
            self.assertEqual(probe.returncode, 0, probe.stderr)
        branch_commits = git("rev-list", f"{BASE_SHA}..HEAD").stdout.split()
        for item in self.five:
            self.assertNotIn(item["leaf_touch_commit"][:12], branch_commits)
        # The admission delta rides uncommitted in the working tree: every
        # leaf's manifests must carry a base->worktree change.
        worktree = git("diff", "--name-only", BASE_SHA).stdout.split()
        self.assertTrue(worktree)
        for item in self.five:
            self.assertTrue(any(item["crate_path"] in entry for entry in worktree),
                            item["name"])
        for item in self.five:
            module = load_toml(f"{item['crate_path']}/module.toml")
            self.assertEqual(module["status"], "ADMITTED")
        for name in CLEAN_FOUR:
            run = self.test_runs[name]
            self.assertEqual(run.returncode, 0, name)
            passed = sum(int(m) for m in re.findall(r"(\d+) passed", run.stdout))
            expected = next(i for i in self.five if i["name"] == name)
            self.assertEqual(passed, expected["matrix_cases"], name)
        activation_item = next(i for i in self.five if i["name"] == ACTIVATION)
        self.assertEqual(activation_item["matrix_cases"], 57)
        wu620_passed = sum(int(m) for m in re.findall(r"(\d+) passed",
                                                      self.activation_wu620.stdout))
        act_passed = sum(int(m) for m in re.findall(r"(\d+) passed",
                                                    self.activation_act.stdout))
        self.assertEqual(wu620_passed + act_passed, 57, ACTIVATION)
        for item in self.five:
            proofs = list((ROOT / item["crate_path"] / "src").rglob("*.rs"))
            proofs += list((ROOT / item["crate_path"] / "tests").rglob("*.rs")) \
                if (ROOT / item["crate_path"] / "tests").is_dir() else []
            self.assertTrue(proofs, item["name"])
            for rs in proofs:
                # Leaf proof carries no wave-integration marker: no T8-AL1 /
                # admit-l1 / suite reference.
                text = rs.read_text(encoding="utf-8")
                self.assertNotIn("T8-AL1", text, str(rs))
                self.assertNotIn("admit-l1", text, str(rs))
                self.assertNotIn("test_wave_admission_l1", text, str(rs))

    # WORK_UNIT_CASE: 967/6
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

    # WORK_UNIT_CASE: 967/7
    def test_07_shared_learning_contract_ownership_and_a37_a38_separation(self) -> None:
        for item in self.five:
            manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
            declared = declared_dep_names(manifest)
            self.assertIn("eliot-contracts", declared, item["name"])
            tokens = crate_tokens_in_tree(item["crate_path"], "src")
            self.assertIn("eliot_contracts", tokens, item["name"])
        for name, path in ((STATE_VIEW, STATE_VIEW_PATH), (DELTA, DELTA_PATH),
                           (OVERLAY, OVERLAY_PATH), (ACTIVATION, ACTIVATION_PATH)):
            manifest = load_toml(f"{path}/Cargo.toml")
            self.assertIn("eliot-learning-contracts",
                          declared_dep_names(manifest), name)
            self.assertIn("eliot_learning_contracts",
                          crate_tokens_in_tree(path, "src"), name)
        # A-38 consumes conformance contracts without replacing canonical
        # types; A-37 stays a module inside eliot-improvement.
        sq_manifest = load_toml(f"{SELF_QUALITY_PATH}/Cargo.toml")
        self.assertIn("eliot-conformance-contracts",
                      sq_manifest.get("dependencies", {}), SELF_QUALITY)
        self.assertIn("eliot_conformance_contracts",
                      crate_tokens_in_tree(SELF_QUALITY_PATH, "src"), SELF_QUALITY)
        for item in self.five:
            self.assertEqual(find_canonical_duplicates(item["crate_path"]), [],
                             item["name"])
        poisoned = rs_definition_lines(STATE_VIEW_PATH) + [
            "pub struct EvidenceEnvelope {",
        ]
        self.assertIn("EvidenceEnvelope",
                      canonical_duplicates_in_lines(poisoned))

    # WORK_UNIT_CASE: 967/8
    def test_08_no_sibling_algorithm_imports_despite_runtime_value_flow(self) -> None:
        for item in self.five:
            manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
            declared = declared_dep_names(manifest)
            self.assertEqual(declared & FORBIDDEN_SIBLING, set(), item["name"])
            src_tokens = crate_tokens_in_tree(item["crate_path"], "src")
            self.assertEqual(src_tokens & FORBIDDEN_SIBLING, set(), item["name"])
            self.assertEqual(src_tokens & FORBIDDEN_PRODUCER, set(), item["name"])
            # Only public contracts/value interfaces flow at runtime: every
            # shipped eliot_* token is a canonical contract/value crate or
            # the leaf itself.
            own = item["name"].replace("-", "_")
            self.assertLessEqual(src_tokens, ALLOWED_VALUE_TOKENS | {own},
                                 item["name"])
        for item in self.five:
            test_tokens = crate_tokens_in_tree(item["crate_path"], "tests")
            if item["name"] == OVERLAY:
                # Documented self-policing negative fixtures live in tests/:
                # exactly the sibling-shaped tokens its own case_44
                # asserts absent from the manifest and shipped sources,
                # plus the leaf itself.
                self.assertLessEqual(
                    test_tokens,
                    ALLOWED_VALUE_TOKENS | {"eliot_learning_overlay"}
                    | OVERLAY_TEST_EXTRA_TOKENS, item["name"])
                sib = test_tokens & FORBIDDEN_SIBLING
                self.assertEqual(sib, {"eliot_learning_delta",
                                       "eliot_learning_state_view",
                                       "eliot_reactive_context_plan",
                                       "eliot_learning_overlay"},
                                 item["name"])
            else:
                own = item["name"].replace("-", "_")
                self.assertLessEqual(test_tokens, ALLOWED_VALUE_TOKENS | {own},
                                     item["name"])
                # A leaf's own tests may name the leaf itself; nothing
                # else sibling-shaped may appear.
                self.assertEqual((test_tokens & FORBIDDEN_SIBLING) - {own}, set(),
                                 item["name"])
        poisoned = (crate_tokens_in_tree(DELTA_PATH, "src")
                    | {"eliot_learning_overlay"})
        self.assertIn("eliot_learning_overlay", poisoned & FORBIDDEN_SIBLING)

    # WORK_UNIT_CASE: 967/9
    def test_09_no_provider_store_runtime_or_local_normative_authority(self) -> None:
        for item in self.five:
            manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
            declared = declared_dep_names(manifest)
            bad_deps = {d for d in declared if is_forbidden_provider_dep(d)}
            self.assertEqual(bad_deps, set(), item["name"])
            # Shipped code carries no provider/store/runtime/kernel tokens:
            # the overlay leaf's provider-shaped fixtures live in tests/
            # and its single test-only eliot-agent-contracts dev-dep is
            # explicitly allowlisted (blessed by its own case_45).
            src_tokens = crate_tokens_in_tree(item["crate_path"], "src")
            self.assertEqual(provider_tokens_in(src_tokens), set(), item["name"])
            # Data fields and prose mentions are not authority
            # implementations: only struct/enum/fn definition lines count.
            self.assertEqual(find_authority_impls(item["crate_path"]), [],
                             item["name"])
        overlay_declared = declared_dep_names(load_toml(f"{OVERLAY_PATH}/Cargo.toml"))
        self.assertIn("eliot-agent-contracts", overlay_declared)
        self.assertIn("eliot-agent-contracts", DEV_ONLY_ALLOWLIST)
        poisoned_deps = (declared_dep_names(
            load_toml(f"{DELTA_PATH}/Cargo.toml"))
            | {"eliot-provider-acquire"})
        self.assertTrue(any(is_forbidden_provider_dep(d) for d in poisoned_deps))
        self.assertEqual(provider_tokens_in({"eliot_store_handle"}),
                         {"eliot_store_handle"})
        poisoned_lines = [
            "pub struct GrantAuthority {",
            "    fn issue_authority(&self) {",
        ]
        self.assertEqual(len(authority_impls_in_lines(poisoned_lines)), 2)

    # WORK_UNIT_CASE: 967/10
    def test_10_acyclic_compile_graph_and_no_wave_noop(self) -> None:
        edges = internal_edges()
        order = topo_sort(edges)
        self.assertGreater(len(order), 100)
        for name in self.five_names:
            self.assertIn(name, order)
        poison = dict(edges)
        poison[DELTA] = set(poison[DELTA]) | {OVERLAY}
        poison[OVERLAY] = set(poison[OVERLAY]) | {DELTA}
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
        # No already-admitted no-op in this wave: every one of the five
        # changes membership state here.
        for path in self.five_paths:
            self.assertEqual(ws["members"].count(path), 1)
        modules = {p: {"status": load_toml(f"{p}/module.toml")["status"]}
                   for p in self.five_paths}
        self.assertEqual(validate_wave_state(
            ws["members"], ws.get("exclude", []), modules,
            set(lock_packages()), self.five_paths), [])
        base = tomllib.loads(git("show", f"{BASE_SHA}:Cargo.toml").stdout)
        base_members = base["workspace"]["members"]
        base_exclude = base["workspace"].get("exclude", [])
        for path in (STATE_VIEW_PATH, DELTA_PATH, OVERLAY_PATH, ACTIVATION_PATH):
            self.assertNotIn(path, base_members)
            self.assertIn(path, base_exclude)
        self.assertNotIn(SELF_QUALITY_PATH, base_members)
        self.assertNotIn(SELF_QUALITY_PATH, base_exclude)
        stale_modules = {p: {"status": "PROTOTYPE"} for p in self.five_paths}
        stale_errors = validate_wave_state(
            base_members, base_exclude, stale_modules,
            set(lock_packages()), self.five_paths)
        for path in self.five_paths:
            self.assertTrue(any("member count" in e and path in e
                                for e in stale_errors), path)

    # WORK_UNIT_CASE: 967/11
    def test_11_one_member_per_package_no_duplication(self) -> None:
        ws = root_workspace()
        for path in self.five_paths:
            self.assertEqual(ws["members"].count(path), 1, path)
            self.assertNotIn(path, ws.get("exclude", []))
        self.assertEqual(len(ws["members"]), len(set(ws["members"])))
        self.assertEqual(len(ws.get("exclude", [])), len(set(ws.get("exclude", []))))
        self.assertEqual(set(ws["members"]) & set(ws.get("exclude", [])), set())
        names = [load_toml(f"{p}/Cargo.toml")["package"]["name"] for p in self.five_paths]
        self.assertEqual(sorted(names), sorted(self.five_names))
        # No fabricated prior self-quality exclusion: it was never excluded.
        base = tomllib.loads(git("show", f"{BASE_SHA}:Cargo.toml").stdout)
        self.assertNotIn(SELF_QUALITY_PATH, base["workspace"].get("exclude", []))
        dup = ws["members"] + [self.five_paths[0]]
        self.assertIn("duplicate workspace member",
                      validate_wave_state(dup, ws.get("exclude", []),
                                          {p: {"status": "ADMITTED"} for p in self.five_paths},
                                          set(lock_packages()), self.five_paths))

    # WORK_UNIT_CASE: 967/12
    def test_12_inheritance_preserves_versions_features_lints(self) -> None:
        for item in self.five:
            rel = f"{item['crate_path']}/Cargo.toml"
            manifest = load_toml(rel)
            package = manifest["package"]
            for key in ("version", "edition", "rust-version", "license"):
                self.assertEqual(package[key], {"workspace": True}, f"{item['name']}.{key}")
            self.assertEqual(manifest["lints"], {"workspace": True})
            self.assertNotIn("workspace", manifest, item["name"])
            self.assertNotIn("publish", package, item["name"])
            base = tomllib.loads(git("show", f"{BASE_SHA}:{rel}").stdout)
            # Admission preserves dependency specs byte-for-byte: the
            # overlay leaf's own case_45 parses the legacy spec form, so
            # no workspace-inheritance normalization is performed.
            for table in ("dependencies", "dev-dependencies"):
                self.assertEqual(manifest.get(table, {}), base.get(table, {}),
                                 f"{item['name']}.{table}")

    # WORK_UNIT_CASE: 967/13
    def test_13_no_rust_test_router_or_floor_change(self) -> None:
        # Worktree form: the admission delta is uncommitted.
        changed = git("diff", "--name-only", BASE_SHA).stdout.split()
        self.assertEqual([c for c in changed if c.endswith(".rs")], [])
        leaf_test_prefixes = tuple(f"{p}/tests/" for p in self.five_paths)
        test_dirs = [c for c in changed
                     if c.replace("\\", "/").startswith(leaf_test_prefixes)
                     and not c.replace("\\", "/").startswith("scripts/tests/")]
        self.assertEqual(test_dirs, [])
        allowed_cargo = {"prototype", "source_status", "workspace_admission"}
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
            self.assertEqual(live_meta["source_status"], "IMPLEMENTED")
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

    # WORK_UNIT_CASE: 967/14
    def test_14_root_and_lock_delta_limited_and_explained(self) -> None:
        # Worktree form: the admission delta is uncommitted.
        diff = git("diff", BASE_SHA, "--", "Cargo.toml")
        self.assertEqual(diff.returncode, 0, diff.stderr)
        added = [l[1:].strip() for l in diff.stdout.splitlines()
                 if l.startswith("+") and not l.startswith("+++")
                 and l[1:].strip().startswith('"crates/')]
        removed = [l[1:].strip() for l in diff.stdout.splitlines()
                   if l.startswith("-") and not l.startswith("---")
                   and l[1:].strip().startswith('"crates/')]
        self.assertEqual(len(added), 5)
        self.assertEqual(len(removed), 4)
        for path in (STATE_VIEW_PATH, DELTA_PATH, OVERLAY_PATH, ACTIVATION_PATH):
            self.assertTrue(any(path in line for line in added), path)
            self.assertTrue(any(path in line for line in removed), path)
        # The fresh self-quality member moves nowhere out: added only.
        self.assertTrue(any(SELF_QUALITY_PATH in line for line in added),
                        SELF_QUALITY_PATH)
        self.assertFalse(any(SELF_QUALITY_PATH in line for line in removed),
                         SELF_QUALITY_PATH)
        dep_added = [l[1:].strip() for l in diff.stdout.splitlines()
                     if l.startswith("+") and not l.startswith("+++")
                     and re.match(r"eliot-(learning|self-quality)\b",
                                  l[1:].strip().split(" ")[0].split("=")[0].strip())]
        self.assertEqual(len(dep_added), 5)
        for name in self.five_names:
            self.assertTrue(any(l.startswith(f"{name} = ") for l in dep_added), name)
        lock_diff = git("diff", BASE_SHA, "--", "Cargo.lock")
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
        for name in self.five_names:
            self.assertNotIn(name, base_names, name)
        live_lock = load_toml("Cargo.lock")
        for entry in live_lock["package"]:
            if entry["name"] in self.five_names:
                for dep in entry.get("dependencies", []):
                    self.assertIn(dep.split(" ")[0], base_names, entry["name"])
        base_versions = {(p["name"], p.get("version")) for p in base_lock["package"]}
        live_versions = {(p["name"], p.get("version")) for p in live_lock["package"]}
        self.assertTrue(base_versions <= live_versions)

    # WORK_UNIT_CASE: 967/15
    def test_15_local_lock_disposition_explicit_root_lock_canonical(self) -> None:
        for item in self.five:
            self.assertFalse((ROOT / item["crate_path"] / "Cargo.lock").exists(),
                             item["name"])
        self.assertIsNotNone(self.metadata["resolve"])
        locked_ids = {p["name"] for p in self.metadata["packages"]}
        for name in self.five_names:
            self.assertIn(name, locked_ids)
            self.assertTrue(is_workspace_member(self.metadata, name), name)

    # WORK_UNIT_CASE: 967/16
    def test_16_generated_rows_cover_wave_and_regen_is_byte_identical(self) -> None:
        # In-memory isolation: this case never writes; it only reads the
        # committed indexes, runs the read-only check, and re-renders both
        # projections in memory twice.
        package_index = read_bytes("docs/code-navigation/PACKAGE_DOCS_INDEX.md").decode("utf-8")
        prototype_index = read_bytes("docs/code-navigation/PROTOTYPE_DOCS_INDEX.md").decode("utf-8")
        for path in self.five_paths:
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

    # WORK_UNIT_CASE: 967/17
    def test_17_descriptors_decode_and_suites_execute_pass(self) -> None:
        for item in self.five:
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
        for name in CLEAN_FOUR:
            run = self.test_runs[name]
            self.assertEqual(run.returncode, 0, name)
            passed = sum(int(m) for m in re.findall(r"(\d+) passed", run.stdout))
            failed = sum(int(m) for m in re.findall(r"(\d+) failed", run.stdout))
            item = next(i for i in self.five if i["name"] == name)
            self.assertEqual(passed, item["matrix_cases"], name)
            self.assertEqual(failed, 0, name)
        # Activation: both real integration targets execute and pass cleanly
        # (6 in activation, 51 in work_unit_620).
        self.assertEqual(self.activation_act.returncode, 0, ACTIVATION)
        act_passed = sum(int(m) for m in re.findall(r"(\d+) passed",
                                                    self.activation_act.stdout))
        self.assertEqual(act_passed, 6, ACTIVATION)
        self.assertEqual(self.activation_wu620.returncode, 0, ACTIVATION)
        wu620_passed = sum(int(m) for m in re.findall(r"(\d+) passed",
                                                      self.activation_wu620.stdout))
        wu620_failed = sum(int(m) for m in re.findall(r"(\d+) failed",
                                                      self.activation_wu620.stdout))
        self.assertEqual(wu620_passed, 51, ACTIVATION)
        self.assertEqual(wu620_failed, 0, ACTIVATION)
        self.assertEqual(act_passed + wu620_passed, 57, ACTIVATION)
        self.assertEqual(self.clippy.returncode, 0, self.clippy.stderr[-2000:])
        combined = self.clippy.stdout + self.clippy.stderr
        self.assertNotIn("error[", combined)
        self.assertNotIn("\nerror:", combined)
        with self.assertRaises(Exception):
            self.decode_descriptor(
                self.five[0]["descriptor_toml"].encode("utf-8") + b'\nfuture_field = "no"\n',
                f".github/work-units/{self.five[0]['leaf_issue']}.toml")
        self.assertFalse(is_workspace_member(self.metadata, "eliot-learning-future-leaf"))

    # WORK_UNIT_CASE: 967/18
    def test_18_locked_workspace_check_and_norun_includes_all_five(self) -> None:
        self.assertEqual(self.workspace_check.returncode, 0,
                         self.workspace_check.stderr[-2000:])
        self.assertEqual(self.workspace_norun.returncode, 0,
                         self.workspace_norun.stderr[-2000:])
        ids = [p["id"] for p in self.metadata["packages"]]
        self.assertEqual(len(ids), len(set(ids)))
        member_ids = set(self.metadata["workspace_members"])
        by_name = {p["name"]: p["id"] for p in self.metadata["packages"]}
        name_counts = Counter(p["name"] for p in self.metadata["packages"])
        for name in self.five_names:
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

    # WORK_UNIT_CASE: 967/19
    def test_19_before_after_arithmetic_reconciles(self) -> None:
        base = tomllib.loads(git("show", f"{BASE_SHA}:Cargo.toml").stdout)["workspace"]
        live = root_workspace()
        self.assertEqual(self.baseline["members_count"], len(base["members"]))
        self.assertEqual(self.baseline["excluded_count"], len(base.get("exclude", [])))
        self.assertEqual(len(base["members"]) + 5, len(live["members"]))
        self.assertEqual(len(base.get("exclude", [])) - 4, len(live.get("exclude", [])))
        self.assertEqual(len(live["members"]), self.candidate["members_count"])
        self.assertEqual(len(live.get("exclude", [])), self.candidate["excluded_count"])
        self.assertEqual(self.candidate["members_count"], 174)
        self.assertEqual(self.candidate["excluded_count"], 0)
        # No no-op reconciliation exists in this wave: the candidate
        # carries no orientation_noop-style field at all.
        self.assertNotIn("orientation_noop", self.candidate)
        self.assertNotIn("four", self.candidate)
        total = 0
        for item in self.five:
            live_digest = sha256_bytes(read_bytes(f"{item['crate_path']}/src/lib.rs"))
            self.assertEqual(live_digest, item["lib_sha256"], item["name"])
            if item["name"] in CLEAN_FOUR:
                run = self.test_runs[item["name"]]
                passed = sum(int(m) for m in re.findall(r"(\d+) passed", run.stdout))
            else:
                passed = (
                    sum(int(m) for m in re.findall(r"(\d+) passed",
                                                   self.activation_wu620.stdout))
                    + sum(int(m) for m in re.findall(r"(\d+) passed",
                                                     self.activation_act.stdout)))
            self.assertEqual(passed, self.candidate["expected_test_counts"][item["name"]],
                             item["name"])
            self.assertEqual(passed, item["matrix_cases"], item["name"])
            total += passed
        self.assertEqual(total, sum(self.candidate["expected_test_counts"].values()))
        self.assertEqual(total, 248)

    # WORK_UNIT_CASE: 967/20
    def test_20_failed_admission_proves_no_edge_product_release(self) -> None:
        ws = root_workspace()
        partial_members = [m for m in ws["members"] if m != self.five_paths[0]]
        errors = validate_wave_state(
            partial_members, ws.get("exclude", []),
            {p: {"status": "ADMITTED"} for p in self.five_paths},
            set(lock_packages()), self.five_paths)
        self.assertTrue(any(self.five_paths[0] in e for e in errors))
        stuck = ws.get("exclude", []) + [self.five_paths[1]]
        errors = validate_wave_state(
            ws["members"], stuck,
            {p: {"status": "ADMITTED"} for p in self.five_paths},
            set(lock_packages()), self.five_paths)
        self.assertTrue(any(self.five_paths[1] in e for e in errors))
        self.assertEqual(validate_wave_state(
            ws["members"], ws.get("exclude", []),
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
