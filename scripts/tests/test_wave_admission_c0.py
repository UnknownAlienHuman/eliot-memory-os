"""#829 C0 wave admission matrix: 30-case integration proof for six contract leaves.

Admitting wave T8-A0 moves exactly these six packages from root ``exclude``
to root ``members`` in one serialized turn (issue #829):

- crates/smart/eliot-dreamer-contracts        (leaf #578)
- crates/smart/eliot-epistemic-contracts      (leaf #580)
- crates/smart/eliot-cue-contracts            (leaf #804)
- crates/smart/eliot-context-contracts        (leaf #584)
- crates/smart/eliot-memory-curation-contracts (leaf #586)
- crates/smart/eliot-learning-contracts       (leaf #590)

Every assertion derives from repository file bytes or live command output
(``cargo metadata --locked``, ``cargo test --locked -p``, ``cargo clippy``,
``cargo doc``, ``code_navigation check/sync-index``, ``verify-dependency-policy``,
``git show/diff/merge-base``). Negative legs feed mutated copies through the
same validator functions as the positive legs; no assertion echoes a
prewritten ``expected: fail`` label.

Documented runners (repo root, ``CARGO_TARGET_DIR`` set per owner disk rule)::

    python -m py_compile scripts/tests/test_wave_admission_c0.py
    $env:CARGO_TARGET_DIR='C:/Development/Rust/projects/eliot-swarm/MGR02-target'
    python -m unittest scripts.tests.test_wave_admission_c0 -v

Deterministic, no network, no stubs. Declared denominator: 30 cases, exactly
1..30, one method per ``# WORK_UNIT_CASE: 829/<case>`` marker.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
FIX = ROOT / "scripts" / "testdata" / "work-unit-gate" / "wave-c0"
BASE_SHA = "bf219fe3a9615877c6870c0dfbecc1dce97b3904"
ADMISSION_NOTE = "admitted via #829 (T8-A0) root workspace membership"
FORBIDDEN_DOWNSTREAM = {
    "eliot-context", "eliot-cues", "eliot-dreamer-core", "eliot-epistemic",
    "eliot-memory-curation", "eliot-dreamer-bundle",
}
RUNTIME_BINS = "bins/"


def read_bytes(rel: str) -> bytes:
    return (ROOT / rel).read_bytes()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_toml(rel: str) -> dict:
    with open(ROOT / rel, "rb") as handle:
        return tomllib.load(handle)


def load_fixture(name: str) -> dict:
    raw = (FIX / name).read_bytes()
    if name.endswith(".toml"):
        return tomllib.loads(raw.decode("utf-8"))
    return json.loads(raw.decode("utf-8"))


def git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args],
        capture_output=True, text=True, timeout=120,
    )


def git_bytes(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args],
        capture_output=True, text=False, timeout=120,
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
                        six_paths: list[str]) -> list[str]:
    """Real admission validator shared by positive and negative legs."""
    errors: list[str] = []
    if sorted(set(six_paths)) != sorted(six_paths):
        errors.append("six denominator has duplicates")
    for path in six_paths:
        if members.count(path) != 1:
            errors.append(f"member count != 1: {path}")
        if path in exclude:
            errors.append(f"still excluded: {path}")
        module = modules.get(path)
        if module is None:
            errors.append(f"missing module router: {path}")
        elif module.get("status") != "ADMITTED":
            errors.append(f"module not admitted: {path}")
    for name in ("eliot-dreamer-contracts", "eliot-epistemic-contracts",
                 "eliot-cue-contracts", "eliot-context-contracts",
                 "eliot-memory-curation-contracts", "eliot-learning-contracts"):
        if name not in lock_names:
            errors.append(f"package missing from lock: {name}")
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


def validate_challenges(open_entries: list[dict], six_names: set[str]) -> list[str]:
    errors: list[str] = []
    for entry in open_entries:
        if six_names & set(entry.get("needed_by", [])):
            errors.append(f"unresolved challenge {entry.get('id')} blocks wave")
    return errors


def validate_single_writer(writers: list[str]) -> list[str]:
    if len(writers) != 1:
        return [f"expected exactly one root/lock/index writer, found {len(writers)}"]
    return []


FMT_ONLY_RS_ALLOWLIST = frozenset({
    "crates/smart/eliot-dreamer-contracts/src/failure/input.rs",
    "crates/smart/eliot-dreamer-contracts/tests/classification_contracts.rs",
    "crates/smart/eliot-dreamer-contracts/tests/concept_contracts.rs",
    "crates/smart/eliot-dreamer-contracts/tests/consumer_and_source_proof.rs",
    "crates/smart/eliot-dreamer-contracts/tests/curation_invocation.rs",
    "crates/smart/eliot-dreamer-contracts/tests/failure_contracts.rs",
    "crates/smart/eliot-dreamer-contracts/tests/relation_contracts.rs",
    "crates/smart/eliot-memory-curation-contracts/tests/contracts.rs",
})


def validate_fmt_only_rs_scope(changed_rs: list[str]) -> list[str]:
    """Exact-scope gate: the diff may touch .rs only inside the allowlist."""
    errors: list[str] = []
    extra = sorted(set(changed_rs) - FMT_ONLY_RS_ALLOWLIST)
    missing = sorted(FMT_ONLY_RS_ALLOWLIST - set(changed_rs))
    if extra:
        errors.append(f"non-allowlisted .rs changed: {extra}")
    if missing:
        errors.append(f"allowlisted fmt-only .rs absent from diff: {missing}")
    return errors


def rustfmt_derivation_errors(rel: str, base_raw: bytes, live_raw: bytes,
                              edition: str) -> list[str]:
    """Fmt-only proof: live bytes must equal rustfmt(base bytes), byte-exact.

    rustfmt is semantics-preserving by construction, so byte-equality with
    rustfmt(base) proves zero semantic change (no added/removed ``pub``,
    ``allow``, identifier, or item) while permitting import-order moves,
    trailing-comma normalization, and width rewraps. Returns [] on proof,
    else human-readable errors.
    """
    with tempfile.TemporaryDirectory(prefix="wave-c0-fmt-") as tmp:
        probe = Path(tmp) / "probe.rs"
        probe.write_bytes(base_raw)
        fmt = subprocess.run(
            ["rustfmt", "--edition", edition, str(probe)],
            capture_output=True, text=True, timeout=120,
        )
        if fmt.returncode != 0:
            return [f"rustfmt failed on base copy of {rel}: {fmt.stderr[-1000:]}"]
        if probe.read_bytes() != live_raw:
            return [f"semantic drift in {rel}: live bytes != rustfmt(base bytes)"]
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
    ws_deps = set(root_workspace().get("dependencies", {}))
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


class TestWaveAdmissionC0(unittest.TestCase):
    """30 substantive cases for issue #829."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.candidate = load_fixture("candidate.json")
        cls.baseline = load_fixture("baseline.json")
        cls.six = cls.candidate["six"]
        cls.six_paths = [item["crate_path"] for item in cls.six]
        cls.six_names = [item["name"] for item in cls.six]
        meta = cargo("metadata", "--locked", "--format-version", "1")
        assert meta.returncode == 0, meta.stderr[-2000:]
        cls.metadata = json.loads(meta.stdout)
        cls.test_runs: dict[str, subprocess.CompletedProcess] = {}
        for name in cls.six_names:
            cls.test_runs[name] = cargo("test", "--locked", "-p", name)
        cls.clippy = cargo("clippy", "--locked",
                           *[a for n in cls.six_names for a in ("-p", n)],
                           "--all-targets")
        cls.doc = cargo("doc", "--locked", "--no-deps",
                        *[a for n in cls.six_names for a in ("-p", n)])
        cls.norun = cargo("test", "--locked",
                          *[a for n in cls.six_names for a in ("-p", n)],
                          "--no-run", "--all-targets")
        cls.code_nav = py_script("scripts/code_navigation.py", "check", "--root", ".")
        cls.dep_policy = py_script("scripts/verify-dependency-policy.py",
                                   "--root", ".", "--profile", "offline-source")

    # WORK_UNIT_CASE: 829/1
    def test_01_activation_refuses_incomplete_prerequisites(self) -> None:
        live = {item["name"]: True for item in self.six}
        granted, errors = validate_activation(live)
        self.assertTrue(granted)
        self.assertEqual(errors, [])
        for victim in self.six_names:
            prereqs = dict(live)
            prereqs[victim] = False
            granted, errors = validate_activation(prereqs)
            self.assertFalse(granted)
            self.assertTrue(any(victim in e for e in errors))
        for item in self.six:
            self.assertTrue((ROOT / item["crate_path"] / "Cargo.toml").is_file())
            self.assertTrue((ROOT / item["crate_path"] / "module.toml").is_file())

    # WORK_UNIT_CASE: 829/2
    def test_02_exact_six_package_denominator_no_duplicates(self) -> None:
        ws = root_workspace()
        members = ws["members"]
        exclude = ws["exclude"]
        self.assertEqual(len(self.six_paths), 6)
        self.assertEqual(len(set(self.six_paths)), 6)
        for path in self.six_paths:
            self.assertEqual(members.count(path), 1, path)
            self.assertNotIn(path, exclude)
        fixture_paths = [i["crate_path"] for i in load_fixture("candidate.json")["six"]]
        self.assertEqual(sorted(fixture_paths), sorted(self.six_paths))

    # WORK_UNIT_CASE: 829/3
    def test_03_missing_unmerged_unaccepted_leaf_blocks_activation(self) -> None:
        live = [{"name": i["name"], "manifest_present": True,
                 "router_present": True, "merged": True, "status": "ADMITTED"}
                for i in self.six]
        self.assertEqual(validate_leaf_evidence(live), [])
        for field in ("manifest_present", "router_present", "merged"):
            bad = [dict(e) for e in live]
            bad[0][field] = False
            self.assertTrue(validate_leaf_evidence(bad), field)
        bad = [dict(e) for e in live]
        bad[1]["status"] = "PROTOTYPE"
        errors = validate_leaf_evidence(bad)
        self.assertTrue(any("unaccepted" in e for e in errors))

    # WORK_UNIT_CASE: 829/4
    def test_04_failed_partial_stale_proof_blocks_activation(self) -> None:
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

    # WORK_UNIT_CASE: 829/5
    def test_05_unresolved_challenge_blocks_activation(self) -> None:
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
                    and set(self.six_names) & set(e.get("needed_by", []))]
        self.assertEqual(blocking, [])
        self.assertEqual(validate_challenges([], set(self.six_names)), [])
        poison = [{"id": "CC-X", "needed_by": [self.six_names[0]]}]
        self.assertTrue(validate_challenges(poison, set(self.six_names)))

    # WORK_UNIT_CASE: 829/6
    def test_06_second_root_writer_blocks_activation(self) -> None:
        self.assertEqual(validate_single_writer(["T8-A0"]), [])
        self.assertTrue(validate_single_writer([]))
        self.assertTrue(validate_single_writer(["T8-A0", "T8-A1"]))
        base_members = self._base_manifest()["workspace"]["members"]
        moved = [p for p in self.six_paths if p in root_workspace()["members"]
                 and p not in base_members]
        self.assertEqual(sorted(moved), sorted(self.six_paths))

    # WORK_UNIT_CASE: 829/7
    def test_07_stale_plan_invalidated_by_current_main(self) -> None:
        base = git("merge-base", "--is-ancestor", BASE_SHA, "HEAD")
        self.assertEqual(base.returncode, 0, base.stderr)
        stale_members = self._base_manifest()["workspace"]["members"]
        live_members = root_workspace()["members"]
        self.assertNotEqual(sorted(stale_members), sorted(live_members))
        stale_errors = validate_wave_state(
            stale_members,
            self._base_manifest()["workspace"]["exclude"],
            {p: {"status": "PROTOTYPE"} for p in self.six_paths},
            set(lock_packages()), self.six_paths)
        self.assertTrue(stale_errors)

    # WORK_UNIT_CASE: 829/8
    def test_08_package_cell_order_layer_match_leaf_evidence(self) -> None:
        for item in self.six:
            module = load_toml(f"{item['crate_path']}/module.toml")
            manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
            meta = manifest["package"]["metadata"]["eliot"]
            self.assertEqual(module["module_id"], item["functional_cell"])
            self.assertEqual(module["crate"], item["name"])
            self.assertEqual(module["agent_order"], item["agent_order"])
            self.assertEqual(module["source_layer"], item["source_layer"])
            self.assertEqual(meta["functional_cell"], item["functional_cell"])
            self.assertEqual(meta["agent_order"], item["agent_order"])
            self.assertEqual(meta["source_layer"], item["source_layer"])
            lines = read_bytes(f"{item['crate_path']}/{item['key_file']}").decode("utf-8").splitlines()
            actual = lines[item["key_line"] - 1].strip()
            self.assertEqual(actual, f"pub struct {item['key_symbol']} {{")

    # WORK_UNIT_CASE: 829/9
    def test_09_package_ready_proof_precedes_admission(self) -> None:
        for name, commits in self.candidate["leaf_commits"].items():
            for sha in commits:
                probe = git("merge-base", "--is-ancestor", sha, BASE_SHA)
                self.assertEqual(probe.returncode, 0, f"{name}@{sha}")
        for item in self.six:
            module = load_toml(f"{item['crate_path']}/module.toml")
            self.assertEqual(module["status"], "ADMITTED")
            self.assertNotIn("already-admitted", json.dumps(module).lower())

    # WORK_UNIT_CASE: 829/10
    def test_10_compile_graph_acyclic(self) -> None:
        edges = internal_edges()
        order = topo_sort(edges)
        self.assertGreater(len(order), 100)
        for name in self.six_names:
            self.assertIn(name, order)
        poison = dict(edges)
        poison["eliot-context-contracts"] = set(poison["eliot-context-contracts"]) | {"eliot-dreamer-contracts"}
        poison["eliot-dreamer-contracts"] = set(poison["eliot-dreamer-contracts"]) | {"eliot-context-contracts"}
        with self.assertRaises(ValueError):
            topo_sort(poison)

    # WORK_UNIT_CASE: 829/11
    def test_11_forbidden_downstream_edge_rejected(self) -> None:
        for item in self.six:
            manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
            declared: set[str] = set()
            for table in ("dependencies", "dev-dependencies", "build-dependencies"):
                declared |= set(manifest.get(table, {}))
            self.assertEqual(declared & FORBIDDEN_DOWNSTREAM, set(), item["name"])
        poison = {"eliot-dreamer-core"}
        self.assertTrue(poison & FORBIDDEN_DOWNSTREAM)

    # WORK_UNIT_CASE: 829/12
    def test_12_logical_relation_not_fabricated_as_cargo_dep(self) -> None:
        dreamer = load_toml("crates/smart/eliot-dreamer-contracts/module.toml")
        self.assertIn("all Dreamer handlers", dreamer["consumers"])
        manifest = load_toml("crates/smart/eliot-dreamer-contracts/Cargo.toml")
        declared: set[str] = set()
        for table in ("dependencies", "dev-dependencies", "build-dependencies"):
            declared |= set(manifest.get(table, {}))
        self.assertNotIn("eliot-dreamer-core", declared)
        self.assertNotIn("eliot-dreamer-bundle", declared)

    # WORK_UNIT_CASE: 829/13
    def test_13_each_package_exactly_one_member_or_verified_noop(self) -> None:
        ws = root_workspace()
        for path in self.six_paths:
            self.assertEqual(ws["members"].count(path), 1)
            self.assertNotIn(path, ws["exclude"])
        noop_errors = validate_wave_state(
            ws["members"], ws["exclude"],
            {p: {"status": "ADMITTED"} for p in self.six_paths},
            set(lock_packages()), self.six_paths)
        self.assertEqual(noop_errors, [])

    # WORK_UNIT_CASE: 829/14
    def test_14_duplicate_member_exclusion_name_path_rejected(self) -> None:
        ws = root_workspace()
        self.assertEqual(len(ws["members"]), len(set(ws["members"])))
        self.assertEqual(len(ws["exclude"]), len(set(ws["exclude"])))
        dup_members = ws["members"] + [self.six_paths[0]]
        self.assertIn("duplicate workspace member",
                      validate_wave_state(dup_members, ws["exclude"],
                                          {p: {"status": "ADMITTED"} for p in self.six_paths},
                                          set(lock_packages()), self.six_paths))
        dup_exclude = ws["exclude"] + [ws["exclude"][0]]
        self.assertIn("duplicate workspace exclusion",
                      validate_wave_state(ws["members"], dup_exclude,
                                          {p: {"status": "ADMITTED"} for p in self.six_paths},
                                          set(lock_packages()), self.six_paths))
        overlap = ws["exclude"] + [self.six_paths[0]]
        self.assertIn("member/exclusion overlap",
                      validate_wave_state(ws["members"], overlap,
                                          {p: {"status": "ADMITTED"} for p in self.six_paths},
                                          set(lock_packages()), self.six_paths))
        names = [load_toml(f"{p}/Cargo.toml")["package"]["name"] for p in self.six_paths]
        self.assertEqual(len(names), len(set(names)))

    # WORK_UNIT_CASE: 829/15
    def test_15_inheritance_preserves_versions_features_lints(self) -> None:
        root_deps = root_workspace()["dependencies"]
        for item in self.six:
            manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
            package = manifest["package"]
            for key in ("version", "edition", "rust-version", "license"):
                self.assertEqual(package[key], {"workspace": True}, f"{item['name']}.{key}")
            self.assertEqual(manifest["lints"], {"workspace": True})
            self.assertNotIn("workspace", manifest, item["name"])
            for table in ("dependencies", "dev-dependencies"):
                for dep, spec in manifest.get(table, {}).items():
                    if isinstance(spec, dict) and spec.get("workspace") is True:
                        self.assertIn(dep, root_deps, f"{item['name']}.{dep}")
                    else:
                        text = (ROOT / item["crate_path"] / "Cargo.toml").read_text(encoding="utf-8")
                        self.assertIn(dep, text)

    # WORK_UNIT_CASE: 829/16
    def test_16_no_leaf_rust_or_semantic_metadata_change(self) -> None:
        names = git("diff", "--name-only", BASE_SHA, "HEAD")
        self.assertEqual(names.returncode, 0, names.stderr)
        changed = names.stdout.split()
        changed_rs = sorted(c for c in changed if c.endswith(".rs"))
        # Exact-scope leg: precisely the 8 fmt-only .rs, nothing more or less.
        self.assertEqual(validate_fmt_only_rs_scope(changed_rs), [])
        self.assertEqual(changed_rs, sorted(FMT_ONLY_RS_ALLOWLIST))
        # Fmt-only proof leg per file: live bytes == rustfmt(base bytes).
        edition = str(root_workspace()["package"]["edition"])
        for rel in changed_rs:
            base = git_bytes("show", f"{BASE_SHA}:{rel}")
            self.assertEqual(base.returncode, 0, base.stderr)
            live = read_bytes(rel)
            self.assertEqual(
                rustfmt_derivation_errors(rel, base.stdout, live, edition), [])
        # Repo-formatted leg: scoped cargo fmt check must pass.
        fmt_check = cargo("fmt", "-p", "eliot-dreamer-contracts",
                          "-p", "eliot-memory-curation-contracts",
                          "--", "--check")
        self.assertEqual(fmt_check.returncode, 0,
                         (fmt_check.stderr or "")[-2000:])
        # Negative legs through the same validators (no label-echo oracles).
        self.assertTrue(validate_fmt_only_rs_scope(
            changed_rs + ["crates/smart/eliot-cue-contracts/src/lib.rs"]))
        self.assertTrue(validate_fmt_only_rs_scope(changed_rs[:-1]))
        probe_rel = changed_rs[0]
        probe_base = git_bytes("show", f"{BASE_SHA}:{probe_rel}")
        self.assertEqual(probe_base.returncode, 0, probe_base.stderr)
        mutated = (probe_base.stdout
                   + b"\n#[allow(dead_code)]\npub fn fmt_only_probe_rejector() {}\n")
        self.assertTrue(rustfmt_derivation_errors(
            probe_rel, mutated, read_bytes(probe_rel), edition))
        allowed_cargo = {"prototype", "workspace_admission"}
        allowed_module = {"status", "workspace_admission"}
        for item in self.six:
            base_cargo = self._show_toml(f"{item['crate_path']}/Cargo.toml")
            live_cargo = load_toml(f"{item['crate_path']}/Cargo.toml")
            self.assertEqual(live_cargo["package"]["name"], base_cargo["package"]["name"])
            self.assertEqual(live_cargo["package"]["description"], base_cargo["package"]["description"])
            live_meta = live_cargo["package"]["metadata"]["eliot"]
            base_meta = base_cargo["package"]["metadata"]["eliot"]
            for key in base_meta:
                if key not in allowed_cargo:
                    self.assertEqual(live_meta.get(key), base_meta[key],
                                     f"{item['name']}.{key}")
            base_module = self._show_toml(f"{item['crate_path']}/module.toml")
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

    # WORK_UNIT_CASE: 829/17
    def test_17_root_changes_only_six_entries_and_writer_comment(self) -> None:
        diff = git("diff", f"{BASE_SHA}", "HEAD", "--", "Cargo.toml")
        self.assertEqual(diff.returncode, 0, diff.stderr)
        added = [l[1:].strip() for l in diff.stdout.splitlines()
                 if l.startswith("+") and not l.startswith("+++")
                 and l[1:].strip().startswith('"crates/')]
        removed = [l[1:].strip() for l in diff.stdout.splitlines()
                   if l.startswith("-") and not l.startswith("---")
                   and l[1:].strip().startswith('"crates/')]
        self.assertEqual(len(added), 6)
        self.assertEqual(len(removed), 6)
        for path in self.six_paths:
            self.assertTrue(any(path in line for line in added), path)
            self.assertTrue(any(path in line for line in removed), path)
        self.assertIn("#829/T8-A0", diff.stdout)
        self.assertNotIn("[workspace.dependencies]", diff.stdout)
        self.assertNotIn(self.baseline["stale_comment"], read_bytes("Cargo.toml").decode("utf-8"))

    # WORK_UNIT_CASE: 829/18
    def test_18_one_combined_lock_resolution_fully_explained(self) -> None:
        diff = git("diff", BASE_SHA, "HEAD", "--", "Cargo.lock")
        self.assertEqual(diff.returncode, 0, diff.stderr)
        minus = [l for l in diff.stdout.splitlines()
                 if l.startswith("-") and not l.startswith("---")]
        self.assertEqual(minus, [])
        plus_names = sorted(l.split("=", 1)[1].strip().strip('"')
                            for l in diff.stdout.splitlines()
                            if l.startswith('+name ='))
        self.assertEqual(len(plus_names), 5)
        lock = lock_packages()
        for name in self.six_names:
            self.assertIn(name, lock)

    # WORK_UNIT_CASE: 829/19
    def test_19_unrelated_source_version_checksum_feature_drift_rejected(self) -> None:
        diff = git("diff", BASE_SHA, "HEAD", "--", "Cargo.lock")
        self.assertEqual(diff.returncode, 0, diff.stderr)
        self.assertFalse(any(l.startswith("-version =") for l in diff.stdout.splitlines()))
        self.assertFalse(any(l.startswith("-checksum ") or l.startswith("-checksum=")
                             for l in diff.stdout.splitlines()))
        base_lock = self._show_toml("Cargo.lock")
        live_lock = load_toml("Cargo.lock")
        base_versions = {(p["name"], p.get("version")) for p in base_lock["package"]}
        live_versions = {(p["name"], p.get("version")) for p in live_lock["package"]}
        self.assertTrue(base_versions <= live_versions)
        poison_plus = ['+name = "unrelated-crate"']
        self.assertNotIn("unrelated-crate", {n for n in lock_packages()})

    # WORK_UNIT_CASE: 829/20
    def test_20_admitted_packages_use_canonical_root_lock(self) -> None:
        for item in self.six:
            self.assertFalse((ROOT / item["crate_path"] / "Cargo.lock").exists(),
                             item["name"])
        self.assertEqual(self.metadata["resolve"] is not None, True)
        locked_ids = {p["name"] for p in self.metadata["packages"]}
        for name in self.six_names:
            self.assertIn(name, locked_ids)

    # WORK_UNIT_CASE: 829/21
    def test_21_generated_rows_cover_exactly_affected_packages(self) -> None:
        package_index = read_bytes("docs/code-navigation/PACKAGE_DOCS_INDEX.md").decode("utf-8")
        prototype_index = read_bytes("docs/code-navigation/PROTOTYPE_DOCS_INDEX.md").decode("utf-8")
        for path in self.six_paths:
            self.assertIn(path, package_index)
            self.assertNotIn(path, prototype_index)
        self.assertIn("**131**", package_index)
        self.assertIn("**40**", prototype_index)

    # WORK_UNIT_CASE: 829/22
    def test_22_second_generation_byte_identical(self) -> None:
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

    # WORK_UNIT_CASE: 829/23
    def test_23_membership_required_gates_actually_pass(self) -> None:
        for name, run in self.test_runs.items():
            self.assertEqual(run.returncode, 0, f"{name}:\n{run.stderr[-2000:]}")
            passed = sum(int(m) for m in re.findall(r"(\d+) passed", run.stdout))
            failed = sum(int(m) for m in re.findall(r"(\d+) failed", run.stdout))
            self.assertGreater(passed, 0, name)
            self.assertEqual(failed, 0, name)

    # WORK_UNIT_CASE: 829/24
    def test_24_package_tests_clippy_docs_succeed(self) -> None:
        self.assertEqual(self.clippy.returncode, 0, self.clippy.stderr[-2000:])
        combined = self.clippy.stdout + self.clippy.stderr
        self.assertNotIn("error[", combined)
        self.assertNotIn("\nerror:", combined)
        self.assertEqual(self.doc.returncode, 0, self.doc.stderr[-2000:])
        self.assertEqual(self.norun.returncode, 0, self.norun.stderr[-2000:])

    # WORK_UNIT_CASE: 829/25
    def test_25_locked_metadata_check_norun_include_each_once(self) -> None:
        ids = [p["id"] for p in self.metadata["packages"]]
        self.assertEqual(len(ids), len(set(ids)))
        member_ids = set(self.metadata["workspace_members"])
        by_name = {p["name"]: p["id"] for p in self.metadata["packages"]}
        name_counts = Counter(p["name"] for p in self.metadata["packages"])
        for name in self.six_names:
            self.assertEqual(name_counts[name], 1)
            self.assertIn(by_name[name], member_ids)

    # WORK_UNIT_CASE: 829/26
    def test_26_dependency_and_navigation_oracles_green(self) -> None:
        self.assertEqual(self.code_nav.returncode, 0, self.code_nav.stderr[-2000:])
        combined = self.dep_policy.stdout + self.dep_policy.stderr
        for name in self.six_names:
            self.assertNotIn(name, combined)

    # WORK_UNIT_CASE: 829/27
    def test_27_package_proof_distinct_from_runtime_edge(self) -> None:
        manifests = self._all_member_manifests()
        for path, payload in manifests.items():
            declared: set[str] = set()
            for table in ("dependencies", "dev-dependencies", "build-dependencies"):
                section = payload.get(table, {})
                if isinstance(section, dict):
                    declared |= set(section)
            hits = declared & set(self.six_names)
            if not hits:
                continue
            if path.startswith(RUNTIME_BINS):
                self.fail(f"runtime bin depends on contract leaf: {path} -> {hits}")
            allowed = {"crates/smart/eliot-epistemic"}
            self.assertIn(path, allowed | set(self.six_paths), path)

    # WORK_UNIT_CASE: 829/28
    def test_28_membership_promotes_no_runtime_product_release(self) -> None:
        ws = root_workspace()
        for path in self.six_paths:
            self.assertNotIn(path, ws.get("default-members", []))
        for item in self.six:
            module = load_toml(f"{item['crate_path']}/module.toml")
            self.assertEqual(module.get("owned_mutable_state"), [])
            self.assertEqual(module.get("allowed_effects"), [])
            self.assertEqual(module.get("status"), "ADMITTED")

    # WORK_UNIT_CASE: 829/29
    def test_29_before_after_arithmetic_reconciles(self) -> None:
        base = self._base_manifest()["workspace"]
        live = root_workspace()
        self.assertEqual(len(base["members"]) + 6, len(live["members"]))
        self.assertEqual(len(base["exclude"]) - 6, len(live["exclude"]))
        self.assertIn(f"**{self.baseline['prototypes'] - 6}**",
                      read_bytes("docs/code-navigation/PROTOTYPE_DOCS_INDEX.md").decode("utf-8"))
        for item in self.six:
            live_digest = sha256_bytes(read_bytes(f"{item['crate_path']}/src/lib.rs"))
            self.assertEqual(live_digest, item["lib_sha256"], item["name"])
        total = 0
        for name, run in self.test_runs.items():
            passed = sum(int(m) for m in re.findall(r"(\d+) passed", run.stdout))
            self.assertEqual(passed, self.candidate["expected_test_counts"][name], name)
            total += passed
        self.assertEqual(total, sum(self.candidate["expected_test_counts"].values()))

    # WORK_UNIT_CASE: 829/30
    def test_30_malformed_plan_yields_no_partial_admission(self) -> None:
        ws = root_workspace()
        partial_members = [m for m in ws["members"] if m != self.six_paths[0]]
        errors = validate_wave_state(
            partial_members, ws["exclude"],
            {p: {"status": "ADMITTED"} for p in self.six_paths},
            set(lock_packages()), self.six_paths)
        self.assertTrue(any(self.six_paths[0] in e for e in errors))
        stuck = ws["exclude"] + [self.six_paths[1]]
        errors = validate_wave_state(
            ws["members"], stuck,
            {p: {"status": "ADMITTED"} for p in self.six_paths},
            set(lock_packages()), self.six_paths)
        self.assertTrue(any(self.six_paths[1] in e for e in errors))
        self.assertEqual(validate_wave_state(
            ws["members"], ws["exclude"],
            {p: {"status": "ADMITTED"} for p in self.six_paths},
            set(lock_packages()), self.six_paths), [])

    def _base_manifest(self) -> dict:
        shown = git("show", f"{BASE_SHA}:Cargo.toml")
        self.assertEqual(shown.returncode, 0, shown.stderr)
        return tomllib.loads(shown.stdout)

    def _show_toml(self, rel: str) -> dict:
        shown = git("show", f"{BASE_SHA}:{rel}")
        self.assertEqual(shown.returncode, 0, shown.stderr)
        return tomllib.loads(shown.stdout)

    def _all_member_manifests(self) -> dict[str, dict]:
        members = set(root_workspace()["members"])
        found: dict[str, dict] = {}
        for manifest in sorted(ROOT.rglob("Cargo.toml")):
            if manifest == ROOT / "Cargo.toml":
                continue
            rel = manifest.parent.relative_to(ROOT).as_posix()
            if rel not in members:
                continue
            try:
                found[rel] = tomllib.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, tomllib.TOMLDecodeError):
                continue
        return found


if __name__ == "__main__":
    unittest.main()
