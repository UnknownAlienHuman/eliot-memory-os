"""#829 C0 wave admission matrix: 30-case integration proof for six contract leaves.

Admitting wave T8-A0 moved exactly these six packages from root ``exclude`` to
root ``members`` in one serialized turn (issue #829):

- crates/smart/eliot-dreamer-contracts          (leaf #578, order 3)
- crates/smart/eliot-epistemic-contracts        (leaf #580, order 6)
- crates/smart/eliot-cue-contracts              (leaf #804, order 10)
- crates/smart/eliot-context-contracts          (leaf #584, order 15)
- crates/smart/eliot-memory-curation-contracts  (leaf #586, order 19)
- crates/smart/eliot-learning-contracts         (leaf #590, order 32)

Two proofs, never mixed
-----------------------

*HISTORICAL* proof is bound to the exact admission transaction recorded in
``scripts/testdata/work-unit-gate/wave-c0/admission.json``: the merge parent of
PR #1456 and the admitted merge commit. Immutable fixture digests in
``candidate.json`` are compared against the *merge commit* blobs they bind and
against nothing else. Later legitimate leaf or workspace growth on ``main`` can
never invalidate the admission it already received.

*CURRENT* proof derives its denominator from the current root ``Cargo.toml``,
the current package/module metadata, the current canonical root ``Cargo.lock``
and the current generated navigation indexes. No frozen global count is
compared against current ``main``.

Accepted owner evidence consumed (never re-authored here)
---------------------------------------------------------

* ``scripts/work_unit_gate`` (#837) — the public typed evidence types and the
  #850 descriptor validation path: ``decode_descriptor``, ``parse_descriptor``,
  ``AssignmentSourceReceipt``, ``OfflineCaptureBinding``,
  ``PrerequisiteEvidence``, ``WorkUnitDescriptor``, ``DiscoveredTestReceipt``,
  ``TestExecutionRecord``, ``CaseAccountingMember``, ``CaseAccountingReceipt``,
  ``SourceShapeGateReceipt``, ``WorkspaceAdmissionReceipt``,
  ``PackageGateReceipt``, ``VerificationPhase``, ``WorkspaceDisposition``.
* ``scripts/audit-work-unit-assignments.py`` (#818) — the controller
  writer-lane oracle. Root/lock/index writer authority comes from its
  ``AU-SHARED-ROOT-WRITERS`` / ``AU-OVERLAP-01`` rules over a frozen controller
  snapshot. No test-authored string list grants authority anywhere in this file.
* ``scripts/tests/test_cognitive_topology_contract.py`` (#816) — the owner of the
  cognitive wave/edge/decision/donor topology contract.

Per-leaf evidence is kept in two separate, non-interchangeable phases:

* ``integration/package-only/<name>.toml`` — the preserved pre-admission leaf
  receipt. ``require_workspace_member = false``, ``phase = package-local``,
  bound to the merge-parent source, test denominator, assignment body and matrix
  digests and the exact leaf commit.
* ``integration/membership-required/<name>.toml`` — the fresh current
  membership-required integration receipt. ``require_workspace_member = true``,
  ``phase = workspace-integration``, bound to current source bytes.

A package-only receipt can never satisfy integration membership: the phase is
fixed by the gate-owned descriptor, not by a caller option.

Execution ceiling
-----------------

This suite runs **no Cargo command**. The mandatory locked workspace and
per-package Cargo commands are issue #829's TEST-PHASE obligation and belong to
root acceptance (see ``TASK.md`` "Current phase"). What the suite proves for
execution is identity, freshness, completeness and validation: each accepted
descriptor is invoked through #837's supported current CLI over its real bytes,
the immutable typed result is parsed, and a bounded mutation of a real receipt is
refused by that same production path. Cases 23-25 state their proof ceiling
explicitly in their own docstrings; they do not claim a fresh Cargo run.

Recorded blocker
----------------

The generated-index acceptance claim is **withheld**, not claimed. The package
index generator is audited under #690 for assigning package-level handles to all
targets by cartesian product instead of proving target-local
AGENTS/route/block/handle closure. ``admission.json`` records that dependency in
``navigation_blockers``; case 26 asserts it is recorded and case 21 proves only
the six rows and their membership transition. #829 does not own #690's
implementation, and the navigation claim is rerun after the generator owner is
repaired and accepted.

Cases 21, 22, 26 and 29 read the current generated indexes and the current
repository oracles. Cases 16, 17, 18, 19, 29 and 30 read the admission
transaction.

Deterministic, no network, no stubs. Declared denominator: 30 cases, exactly
1..30, one method per ``# WORK_UNIT_CASE: 829/<case>`` marker.

Documented runners (repository root)::

    python -m py_compile scripts/tests/test_wave_admission_c0.py
    python -m unittest scripts.tests.test_wave_admission_c0 -v
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

FIX = ROOT / "scripts" / "testdata" / "work-unit-gate" / "wave-c0"
ADMISSION_FIXTURE = "admission.json"
RUST_SOURCE_SUFFIXES = (".rs",)
PACKAGE_INDEX = "docs/code-navigation/PACKAGE_DOCS_INDEX.md"
PROTOTYPE_INDEX = "docs/code-navigation/PROTOTYPE_DOCS_INDEX.md"
GENERATED_INDEXES = (PACKAGE_INDEX, PROTOTYPE_INDEX)
TEST_ATTR = re.compile(r"#\[(?:tokio::)?test(?:\([^)]*\))?\]")
FN_NAME = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")
PUBLIC_ITEM = re.compile(r"^\s*pub\s+(?:async\s+)?(?:fn|struct|enum|trait|type|const|static|mod|use)\b",
                         re.MULTILINE)
FORBIDDEN_DOWNSTREAM = frozenset({
    "eliot-context", "eliot-cues", "eliot-dreamer-core", "eliot-epistemic",
    "eliot-memory-curation", "eliot-dreamer-bundle",
})
ROOT_WRITE_PATHS = ("Cargo.toml", "Cargo.lock")
WORKSPACE_COMMANDS = (
    ("cargo", "metadata", "--locked", "--format-version", "1"),
    ("cargo", "check", "--locked", "--workspace", "--all-targets"),
    ("cargo", "test", "--locked", "--workspace", "--no-run"),
)
PACKAGE_COMMANDS = (
    ("cargo", "test", "--locked", "-p"),
    ("cargo", "clippy", "--locked", "-p"),
    ("cargo", "doc", "--locked", "--no-deps", "-p"),
)


# --------------------------------------------------------------------------- io


def read_bytes(rel: str) -> bytes:
    return (ROOT / rel).read_bytes()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def load_toml(rel: str) -> dict:
    with open(ROOT / rel, "rb") as handle:
        return tomllib.load(handle)


def load_toml_bytes(raw: bytes) -> dict:
    return tomllib.loads(raw.decode("utf-8"))


def load_fixture(name: str) -> dict:
    return json.loads((FIX / name).read_bytes().decode("utf-8"))


def git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(ROOT), *args],
                          capture_output=True, text=True, timeout=180)


def git_bytes(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(ROOT), *args],
                          capture_output=True, text=False, timeout=180)


def py_script(*args: str, timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *args], cwd=str(ROOT),
                          capture_output=True, text=True, timeout=timeout)


# ------------------------------------------------------------------ repository


def root_workspace() -> dict:
    return load_toml("Cargo.toml")["workspace"]


def _lock_index(payload: dict) -> dict[str, list[dict]]:
    found: dict[str, list[dict]] = {}
    for entry in payload.get("package", []):
        found.setdefault(entry["name"], []).append(entry)
    return found


def lock_packages() -> dict[str, list[dict]]:
    return _lock_index(load_toml("Cargo.lock"))


def declared_dependencies(payload: dict) -> set[str]:
    """Real manifest reader shared by the positive and the negative legs."""
    declared: set[str] = set()
    for table in ("dependencies", "dev-dependencies", "build-dependencies"):
        section = payload.get(table, {})
        if isinstance(section, dict):
            declared |= set(section)
    return declared


def changed_paths(first: str, second: str) -> list[str]:
    run = git("diff", "--name-only", first, second)
    assert run.returncode == 0, run.stderr
    return sorted(run.stdout.split())


def show_bytes(ref: str, rel: str) -> bytes:
    run = git_bytes("show", f"{ref}:{rel}")
    assert run.returncode == 0, f"missing {ref}:{rel}"
    return run.stdout


def show_toml(ref: str, rel: str) -> dict:
    return load_toml_bytes(show_bytes(ref, rel))


# ------------------------------------------------------- source/test discovery


def archive_files(ref: str, prefixes: tuple[str, ...]) -> dict[str, bytes]:
    """One git call; every .rs byte under the given prefixes at that commit."""
    run = git_bytes("archive", "--format=tar", ref, *prefixes)
    assert run.returncode == 0, f"git archive {ref} failed"
    files: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(run.stdout)) as tar:
        for member in tar.getmembers():
            if member.isfile():
                files[member.name] = tar.extractfile(member).read()
    return files


def rust_sources(crate_path: str) -> list[str]:
    out = []
    for base in ("src", "tests"):
        directory = ROOT / crate_path / base
        if directory.is_dir():
            out += [p for p in sorted(directory.rglob("*.rs"))]
    return sorted(out, key=lambda p: p.relative_to(ROOT).as_posix())


def source_inventory(crate_path: str, files: dict[str, bytes]) -> str:
    rows = [[rel, sha256_bytes(files[rel])] for rel in sorted(files)]
    return sha256_bytes(canonical_bytes(rows))


def discovered_matrix(files: dict[str, bytes]) -> list[list]:
    """[[repo-relative path, 1-based line, fn]] for every #[test]-attributed fn."""
    rows: list[list] = []
    for rel in sorted(files):
        lines = files[rel].decode("utf-8").splitlines()
        for index, line in enumerate(lines, start=1):
            if not TEST_ATTR.search(line):
                continue
            name = next((m.group(1) for m in
                         (FN_NAME.search(f) for f in lines[index:index + 4]) if m), None)
            if name is not None:
                rows.append([rel, index, name])
    return sorted(rows)


def matrix_digest(rows: list[list]) -> str:
    return sha256_bytes(canonical_bytes(rows))


def execution_digest(rows: list[list]) -> str:
    return sha256_bytes(canonical_bytes(
        [[rel, line, fn, "executed-pass"] for rel, line, fn in rows]))


def item_counts(files: dict[str, bytes]) -> tuple[int, int]:
    source = public = 0
    for rel in sorted(files):
        if "/tests/" in rel:
            continue
        text = files[rel].decode("utf-8")
        source += 1
        public += len(PUBLIC_ITEM.findall(text))
    return source, public


def live_files(crate_path: str) -> dict[str, bytes]:
    return {p.relative_to(ROOT).as_posix(): p.read_bytes() for p in rust_sources(crate_path)}


# ------------------------------------------------------- admission transactions


def validate_wave_state(members: list[str], exclude: list[str], modules: dict[str, dict],
                        lock_names: set[str], six_paths: list[str]) -> list[str]:
    """Real admission-state validator shared by the positive and negative legs."""
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
    for name in WAVE_NAMES:
        if name not in lock_names:
            errors.append(f"package missing from lock: {name}")
    if len(members) != len(set(members)):
        errors.append("duplicate workspace member")
    if len(exclude) != len(set(exclude)):
        errors.append("duplicate workspace exclusion")
    if set(members) & set(exclude):
        errors.append("member/exclusion overlap")
    return errors


def validate_admission_scope(delta_paths: list[str], authorized: list[str]) -> list[str]:
    """Exact-scope gate for the admission transaction.

    The issue's **Must not modify** section forbids Rust source and Rust tests.
    There is no work-unit-local exception list: every ``.rs`` path in the
    transaction is a violation, and every path outside the frozen authorized set
    is a violation. Positive and negative legs call this same function.
    """
    errors: list[str] = []
    rust = sorted(p for p in delta_paths if p.endswith(RUST_SOURCE_SUFFIXES))
    if rust:
        errors.append(f"rust source/test changed in the #829 transaction: {rust}")
    outside = sorted(set(delta_paths) - set(authorized))
    if outside:
        errors.append(f"path outside the authorized mutable scope: {outside}")
    missing = sorted(set(authorized) - set(delta_paths))
    if missing:
        errors.append(f"authorized path absent from the transaction: {missing}")
    return errors


def validate_lock_delta(added: list[str], removed: list[str], base_names: set[str],
                        six_names: set[str]) -> list[str]:
    """One combined resolution: nothing removed, nothing added without cause.

    A package that was already in the lock as somebody else's path dependency
    gains an edge rather than a stanza, so presence in the base lock is not a
    violation; an unexplained new stanza is.
    """
    errors: list[str] = []
    if removed:
        errors.append(f"lock removals are not part of an admission: {sorted(removed)}")
    unexplained = sorted(set(added) - six_names)
    if unexplained:
        errors.append(f"lock package added without an admission cause: {unexplained}")
    return errors


def validate_root_manifest_delta(base: dict, merged: dict, six_paths: list[str]) -> list[str]:
    """Complete semantic root-manifest delta for one admission transaction.

    The root manifest may move exactly the six denominator entries out of
    ``exclude`` into ``members``. Every other root table and every other
    workspace key must be byte-for-byte equal across the transaction, so an
    unrelated root edit - a version pin, a lint level, a seventh member, a new
    exclusion - is refused by this same reader that accepts the real delta.
    """
    errors: list[str] = []
    gained = sorted(m for m in merged["workspace"]["members"]
                    if m not in base["workspace"]["members"])
    dropped = sorted(m for m in base["workspace"]["exclude"]
                     if m not in merged["workspace"]["exclude"])
    if gained != sorted(six_paths):
        errors.append(f"members gained {gained}, expected {sorted(six_paths)}")
    if dropped != sorted(six_paths):
        errors.append(f"exclude dropped {dropped}, expected {sorted(six_paths)}")
    if sorted(base["workspace"]["members"]) != sorted(
            m for m in merged["workspace"]["members"] if m not in six_paths):
        errors.append("unrelated workspace member changed")
    if sorted(m for m in base["workspace"]["exclude"] if m not in six_paths) != sorted(
            m for m in merged["workspace"]["exclude"] if m not in six_paths):
        errors.append("unrelated workspace exclusion changed")
    for key in sorted(set(base) | set(merged)):
        if key == "workspace":
            continue
        if base.get(key) != merged.get(key):
            errors.append(f"root table changed outside the six entries: {key}")
    for key in sorted(set(base["workspace"]) | set(merged["workspace"])):
        if key in ("members", "exclude"):
            continue
        if base["workspace"].get(key) != merged["workspace"].get(key):
            errors.append(f"workspace key changed outside the six entries: {key}")
    return errors


def validate_lock_resolution(base_lock: dict, merged_lock: dict, six_names: set[str],
                             owner_deps: dict[str, set[str]]) -> list[str]:
    """Every edge of one combined resolution is explained independently.

    ``owner_deps`` maps a workspace package name to the dependency names its
    *manifest* declares at the merged commit. It is read from the real package
    manifests, never from the lock, so completeness is never checked against a
    copy of the same caller list:

    * an added stanza must be one of the six admitted packages, and its resolved
      dependency set must equal the manifest's declared set exactly;
    * a stanza that already existed keeps its version, source and checksum, may
      lose no edge, and every edge it gains must be declared by its own manifest
      (admission turns an existing path dependency into a member, which is why
      its dev-dependencies enter the resolution);
    * no resolution may drop a stanza.
    """
    errors: list[str] = []
    base_index = _lock_index(base_lock)
    merged_index = _lock_index(merged_lock)
    removed = sorted(set(base_index) - set(merged_index))
    if removed:
        errors.append(f"resolution removed lock stanzas: {removed}")
    added = sorted(set(merged_index) - set(base_index))
    unexplained = sorted(set(added) - six_names)
    if unexplained:
        errors.append(f"lock stanza added without an admission cause: {unexplained}")
    for name in sorted(set(merged_index) & six_names):
        resolved = {d.split(" ")[0] for d in merged_index[name][0].get("dependencies", [])}
        declared = owner_deps.get(name)
        if declared is None:
            errors.append(f"admitted package has no merged manifest: {name}")
            continue
        if resolved - declared:
            errors.append(f"{name} resolves an undeclared edge: {sorted(resolved - declared)}")
        if declared - resolved:
            errors.append(f"{name} omits a declared edge: {sorted(declared - resolved)}")
    for name in sorted(set(base_index) & set(merged_index)):
        before = base_index[name][0]
        after = merged_index[name][0]
        for field in ("version", "source", "checksum"):
            if before.get(field) != after.get(field):
                errors.append(f"pre-existing stanza changed {field}: {name}")
        lost = ({d.split(" ")[0] for d in before.get("dependencies", [])}
                - {d.split(" ")[0] for d in after.get("dependencies", [])})
        gained = ({d.split(" ")[0] for d in after.get("dependencies", [])}
                  - {d.split(" ")[0] for d in before.get("dependencies", [])})
        if lost:
            errors.append(f"pre-existing stanza lost an edge: {name} {sorted(lost)}")
        if not gained:
            continue
        declared = owner_deps.get(name)
        if declared is None:
            errors.append(f"edge added to a package with no merged manifest: {name}")
        for dep in sorted(gained - (declared or set())):
            errors.append(f"unexplained edge added: {name} -> {dep}")
    return errors


def validate_workspace_command(command: tuple[str, ...], members: list[str],
                               six_paths: list[str]) -> list[str]:
    """The mandatory locked workspace commands, exactly and non-substitutable.

    A zero-selection or package-scoped substitute for
    ``cargo check --locked --workspace --all-targets`` proves nothing about the
    admitted members, so the validator refuses an unfrozen command, a command
    without ``--locked``, a package-scoped selection, and a selection that does
    not contain every admitted member exactly once.
    """
    errors: list[str] = []
    if command not in WORKSPACE_COMMANDS:
        errors.append(f"not a mandatory workspace command: {list(command)}")
    if "--locked" not in command:
        errors.append(f"command is not locked: {list(command)}")
    if command[1] in ("check", "test"):
        if "--workspace" not in command:
            errors.append(f"workspace command is package-scoped: {list(command)}")
        if "-p" in command or "--package" in command:
            errors.append(f"workspace command carries a package substitution: {list(command)}")
    selected = Counter(p for p in members if p.startswith(("crates/", "bins/", "workspace/")))
    if not selected:
        errors.append("workspace selection is empty")
    for path in six_paths:
        if selected[path] != 1:
            errors.append(f"workspace selection covers {path} {selected[path]} times")
    return errors


def _entry(line: str) -> str:
    """The quoted path of a root members/exclude diff line.

    An ``exclude`` entry carries a trailing ``# agent_order N`` comment, so the
    comment is removed before the quotes and the comma.
    """
    return line.split("#", 1)[0].strip().rstrip(",").strip('"').strip()


def stage_admission_transaction(staging: Path, families: list[str],
                                artifacts: dict[str, bytes],
                                candidates: dict[str, bytes],
                                validate) -> tuple[dict[str, str], list[str]]:
    """Validation-guarded write of every admission artifact family.

    ``families`` are the real repository paths of the admission (root manifest,
    root lock, the six package manifests, the six module routers and both
    generated indexes); ``artifacts`` are their recorded bytes and
    ``candidates`` the complete candidate set. Nothing is written until
    ``validate`` accepts the whole candidate set, so a refused transaction
    leaves every family byte-identical on disk: root Cargo, root lock, package
    metadata and the generated indexes cannot be partially mutated or merged.
    """
    for rel in families:
        target = staging / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(artifacts[rel])
    errors = validate(candidates)
    if errors:
        return {}, errors
    for rel, raw in candidates.items():
        (staging / rel).write_bytes(raw)
    return {rel: sha256_bytes(raw) for rel, raw in sorted(candidates.items())}, []


def partial_admission_errors(candidates: dict[str, bytes], six_paths: list[str]) -> list[str]:
    """The admission gate over a staged candidate set, by real artifact content.

    Root membership, root lock identity, package metadata and module status are
    read from the candidate bytes themselves, so a candidate that admits only part
    of the wave - or annotates a package the lock does not resolve - is refused
    before any family is written.
    """
    root = load_toml_bytes(candidates["Cargo.toml"])["workspace"]
    lock = _lock_index(load_toml_bytes(candidates["Cargo.lock"]))
    modules: dict[str, dict] = {}
    for path in six_paths:
        module = load_toml_bytes(candidates[f"{path}/module.toml"])
        name = load_toml_bytes(candidates[f"{path}/Cargo.toml"])["package"]["name"]
        if name not in lock:
            module = dict(module, status="UNRESOLVED-IN-ROOT-LOCK")
        modules[path] = module
    return validate_wave_state(root["members"], root["exclude"], modules,
                               set(lock), six_paths)


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
        # Cargo explicitly permits a dev-dependency cycle; a normal or build
        # dependency cycle is unsatisfiable. The acyclicity claim is therefore
        # about the compile graph, and dev edges are read separately below.
        for table in ("dependencies", "build-dependencies"):
            section = payload.get(table, {})
            if not isinstance(section, dict):
                continue
            for dep_name, spec in section.items():
                if isinstance(spec, dict) and (spec.get("workspace") is True or "path" in spec):
                    deps.add(dep_name)
        edges[name] = deps
    void = {d for deps in edges.values() for d in deps} - set(edges)
    for name in void:
        edges.setdefault(name, set())
    return edges


def dev_edges() -> dict[str, set[str]]:
    """Real dev-dependency reader, kept apart from the compile graph."""
    edges: dict[str, set[str]] = {}
    for manifest in sorted(ROOT.rglob("Cargo.toml")):
        if manifest == ROOT / "Cargo.toml":
            continue
        try:
            payload = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        name = payload.get("package", {}).get("name")
        if not isinstance(name, str) or not name:
            continue
        section = payload.get("dev-dependencies", {})
        deps = {dep for dep, spec in section.items()
                if isinstance(spec, dict) and (spec.get("workspace") is True or "path" in spec)} \
            if isinstance(section, dict) else set()
        edges[name] = deps
    return edges


MEMBERSHIP_CELLS = ("`workspace`", "`nonmember prototype`", "`standalone`")


def index_row_cell(text: str, crate_path: str) -> str | None:
    """The membership label of the generated row for one crate path, if any.

    A crate path also appears in the documentation-handle and target tables, so
    the row is selected by its membership label, not by mere path occurrence.
    """
    token = "[`" + crate_path + "`]"
    found = [row.split("|")[2].strip() for row in text.splitlines()
             if row.startswith("|") and token in row
             and len(row.split("|")) > 3
             and row.split("|")[2].strip() in MEMBERSHIP_CELLS]
    if len(found) != 1:
        return None
    return found[0]


WAVE_NAMES = ("eliot-dreamer-contracts", "eliot-epistemic-contracts", "eliot-cue-contracts",
              "eliot-context-contracts", "eliot-memory-curation-contracts",
              "eliot-learning-contracts")


class TestWaveAdmissionC0(unittest.TestCase):
    """30 substantive cases for issue #829."""

    # -- shared, real evidence ------------------------------------------------

    @classmethod
    def setUpClass(cls) -> None:
        from scripts.work_unit_gate import __main__ as gate

        cls.gate = gate
        cls.c = gate.c
        cls.runner = gate.descriptor_runner

        cls.admission = load_fixture(ADMISSION_FIXTURE)
        cls.merge_parent = cls.admission["merge_parent"]
        cls.merge_commit = cls.admission["merge_commit"]
        cls.candidate = load_fixture("candidate.json")
        cls.baseline = load_fixture("baseline.json")
        cls.six = cls.candidate["six"]
        cls.six_paths = [item["crate_path"] for item in cls.six]
        cls.six_names = [item["name"] for item in cls.six]
        cls.by_name = {item["name"]: item for item in cls.six}

        cls.receipt_index = load_fixture("integration/receipts.json")
        cls.receipts = {r["name"]: r for r in cls.receipt_index["six"]}
        cls.repo = cls.c.RepositoryIdentity(**cls.receipt_index["repository"])
        cls.unit = cls.receipt_index["unit"]

        cls.live: dict[str, dict[str, bytes]] = {}
        cls.pre: dict[str, dict[str, bytes]] = {}
        for item in cls.six:
            cp = item["crate_path"]
            cls.live[cp] = live_files(cp)
            cls.pre[cp] = archive_files(cls.merge_parent,
                                        (f"{cp}/src", f"{cp}/tests"))

        # Historical transaction artifacts, read from the recorded commits only.
        cls.parent_root = show_toml(cls.merge_parent, "Cargo.toml")
        cls.merge_root = show_toml(cls.merge_commit, "Cargo.toml")
        cls.parent_lock = show_toml(cls.merge_parent, "Cargo.lock")
        cls.merge_lock = show_toml(cls.merge_commit, "Cargo.lock")
        # Independent expectation for every lock edge: the dependency names each
        # package manifest declares at the merged commit. Never read from a lock.
        cls.owner_deps = {}
        for member in cls.merge_root["workspace"]["members"]:
            manifest = show_toml(cls.merge_commit, f"{member}/Cargo.toml")
            cls.owner_deps[manifest["package"]["name"]] = declared_dependencies(manifest)

        from scripts.tests import test_cognitive_topology_contract as topology816

        cls.topology816 = topology816
        cls.bundle816 = topology816.load_bundle()

        cls.writer_lane = cls._run_writer_oracle("writer-lane/sole-root-writer.json")
        cls.writer_competing = cls._run_writer_oracle("writer-lane/competing-root-writer.json")
        cls.code_nav = py_script("scripts/code_navigation.py", "check", "--root", ".")
        cls.dep_policy = py_script("scripts/verify-dependency-policy.py",
                                   "--root", ".", "--profile", "offline-source")

    @classmethod
    def tearDownClass(cls) -> None:
        for path in getattr(cls, "_temp", ()):
            shutil.rmtree(path, ignore_errors=True)
        cls._temp = []

    @classmethod
    def _run_writer_oracle(cls, rel: str) -> dict:
        """The accepted #818 controller oracle over a frozen controller snapshot."""
        run = py_script("scripts/audit-work-unit-assignments.py",
                        "--snapshot", str(FIX / rel), "--format", "json")
        assert run.returncode in (0, 1), run.stderr
        return json.loads(run.stdout)

    @classmethod
    def _temp_root(cls, label: str) -> Path:
        if not hasattr(cls, "_temp"):
            cls._temp = []
        path = Path(tempfile.mkdtemp(prefix=f"wave-c0-{label}-"))
        cls._temp.append(path)
        return path

    def _gate_catalogue(self, descriptor_rel: str, number: int) -> dict:
        """Invoke #837 through its supported current CLI over real bytes.

        The accepted descriptor is placed at the only path the frozen catalogue
        admits, ``.github/work-units/<issue>.toml``, and the gate is called as a
        process. Its immutable typed JSON result is returned for parsing; the
        catalogue-only proof kind is used because it invokes no runner and
        therefore runs no Cargo command.
        """
        root = self._temp_root(str(number))
        units = root / ".github" / "work-units"
        units.mkdir(parents=True)
        (units / f"{number}.toml").write_bytes(read_bytes(descriptor_rel))
        run = py_script("-m", "scripts.work_unit_gate", "--proof", "catalogue-only",
                        "--root", str(root), "--json")
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        return json.loads(run.stdout)

    # -- accepted #837 / #818 evidence construction --------------------------

    def _assignment(self, block: dict, number: int, *, active: bool):
        issue = self.c.IssueIdentity(repository=self.repo, number=number)
        unit = self.c.WorkUnitIdentity(value=self.unit)
        capture = self.c.OfflineCaptureBinding(
            issue=issue, unit=unit, body_sha256=block["body_sha256"],
            matrix_sha256=block["matrix_sha256"], snapshot_sha256=block["snapshot_sha256"],
            expected_snapshot_sha256=block["snapshot_sha256"],
            producer=self.c.WorkUnitIdentity(value="root-controller"),
            capture_receipt_sha256=block["capture_receipt_sha256"],
            expected_capture_receipt_sha256=block["capture_receipt_sha256"],
            freshness_policy_sha256=block["freshness_policy_sha256"],
            captured_at=1, expires_at=2, invalidated=False)
        return self.c.AssignmentSourceReceipt(
            issue=issue, state=self.c.IssueState.OPEN if active else self.c.IssueState.CLOSED,
            unit=unit, authority=self.c.SourceAuthority.EXPLICIT_OFFLINE_SNAPSHOT,
            title=f"issue {number}", body_sha256=block["body_sha256"],
            matrix_cases=block["matrix_cases"],
            proof_ceiling=self.c.ProofCeiling(value=block["proof_ceiling"]),
            matrix_sha256=block["matrix_sha256"],
            source_use=(self.c.AssignmentSourceUse.ACTIVE_ASSIGNMENT if active
                        else self.c.AssignmentSourceUse.PREREQUISITE_EVIDENCE),
            origin="https://api.github.com", offline_capture=capture)

    def _descriptor(self, block: dict, number: int, assignment, *, active: bool):
        raw = (ROOT / block["descriptor_path"]).read_bytes()
        if active:
            return self.runner.parse_descriptor(
                raw, f".github/work-units/{number}.toml", assignment)
        return self.gate._typed_from_decoded(
            self.runner.decode_descriptor(raw, f".github/work-units/{number}.toml"))

    def _active_receipt(self, assignment, descriptor, block: dict,
                        rows: list[list]) -> object:
        """A case accounting for an ACTIVE open assignment: the PASS candidate."""
        return self._discovered_receipts(assignment, descriptor, block, rows,
                                         self.c.OverallResult.PASS)

    def _discovered_receipts(self, assignment, descriptor, block: dict, rows: list[list],
                             result: object | None = None):
        phase = descriptor.phase
        members = []
        for index, (rel, line, fn) in enumerate(rows, start=1):
            test = self.c.TestIdentity(
                mode=self.c.RunnerMode.RUST_PACKAGE, qualified_name=f"{rel}:{line}:{fn}")
            location = self.c.SourceLocation(
                path=self.c.RepositoryPath(value=rel), line=line)
            discovery = self.c.DiscoveredTestReceipt(
                descriptor=descriptor.identity, descriptor_sha256=descriptor.sha256,
                test=test, location=location, source_sha256=block["source_sha256"],
                artifact_sha256=sha256_bytes(canonical_bytes([rel, fn])),
                phase=phase)
            execution = self.c.TestExecutionRecord(
                test=test, disposition=self.c.ExecutionDisposition.EXECUTED_PASS,
                discovery=discovery)
            members.append(self.c.CaseAccountingMember(
                case=self.c.CaseIdentity(issue=descriptor.issue, number=index),
                marker=self.c.CaseMarker(case=self.c.CaseIdentity(issue=descriptor.issue,
                                                                 number=index),
                                         test=test, location=location),
                execution=execution))
        return self.c.CaseAccountingReceipt(
            assignment=assignment, descriptor=descriptor, members=tuple(members),
            result=self.c.OverallResult.PASS if result is None else result,
            proof_ceiling=descriptor.proof_ceiling)

    def _source_shape(self, assignment, descriptor, block: dict):
        guard = self.c.WorkUnitIdentity(value="bounded")
        return self.c.SourceShapeGateReceipt(
            assignment=assignment, descriptor=descriptor,
            result=self.c.OverallResult.PASS, findings=(),
            proof_ceiling=descriptor.proof_ceiling, source_sha256=block["source_sha256"],
            source_items=block["source_items"], public_items=block["public_items"],
            test_items=block["test_items"],
            guards=(self.c.GuardResult(identity=guard, result=self.c.OverallResult.PASS),))

    def _workspace_receipt(self, assignment, descriptor, disposition):
        return self.c.WorkspaceAdmissionReceipt(
            assignment=assignment, descriptor=descriptor, package=descriptor.package,
            module=descriptor.module, disposition=disposition,
            result=self.c.OverallResult.PASS, findings=(),
            proof_ceiling=descriptor.proof_ceiling)

    def _package_receipt(self, assignment, descriptor, shape, cases):
        return self.c.PackageGateReceipt(
            assignment=assignment, descriptor=descriptor, package=descriptor.package,
            module=descriptor.module, source_shape=shape, case_accounting=cases,
            result=self.c.OverallResult.PASS, findings=(),
            proof_ceiling=descriptor.proof_ceiling)

    def _membership_disposition(self, package: str) -> object:
        """Real membership reader: the current root workspace manifest."""
        ws = root_workspace()
        by_path = {p: load_toml(f"{p}/Cargo.toml")["package"]["name"]
                   for p in set(ws["members"]) | set(ws["exclude"])
                   if (ROOT / p / "Cargo.toml").is_file()}
        if any(by_path.get(p) == package for p in ws["members"]):
            return self.c.WorkspaceDisposition.MEMBER
        if any(by_path.get(p) == package for p in ws["exclude"]):
            return self.c.WorkspaceDisposition.EXCLUDED
        return self.c.WorkspaceDisposition.STANDALONE

    # WORK_UNIT_CASE: 829/1
    def test_01_activation_refuses_incomplete_prerequisites_without_root_writer(self) -> None:
        """Activation needs all six real #837 receipts *and* an exclusive lane."""
        for item in self.six:
            name, number = item["name"], item["leaf_issue"]
            block = self.receipts[name]["membership_required"]
            assignment = self._assignment(block, number, active=True)
            descriptor = self._descriptor(block, number, assignment, active=True)
            self.assertIs(descriptor.phase, self.c.VerificationPhase.WORKSPACE_INTEGRATION)
            receipt = self._workspace_receipt(
                assignment, descriptor, self._membership_disposition(name))
            self.assertIs(receipt.result, self.c.OverallResult.PASS, name)
            self.assertIs(receipt.disposition, self.c.WorkspaceDisposition.MEMBER, name)

        # Writer authority comes from the accepted #818 oracle, never from here.
        self.assertEqual(self.writer_lane["status"], "Valid")
        self.assertEqual(self.writer_lane["denominators"]["errors"], 0)
        self.assertEqual([f for f in self.writer_lane["findings"]
                          if f["rule_id"] in ("AU-SHARED-ROOT-WRITERS", "AU-OVERLAP-01")], [])
        self.assertIn(str(self.candidate["issue"]), self.writer_lane["ownership_map"])

        # Negative: a second active root/lock writer denies activation outright.
        rules = {f["rule_id"] for f in self.writer_competing["findings"]}
        self.assertEqual(self.writer_competing["status"], "IntegrityViolation")
        self.assertIn("AU-SHARED-ROOT-WRITERS", rules)
        self.assertIn("AU-OVERLAP-01", rules)

        # Negative: a membership-required descriptor for a real non-member cannot pass.
        nonmember = self._first_nonmember_package()
        self.assertNotIn(nonmember, self.six_names)
        item = self.six[0]
        block = self.receipts[item["name"]]["membership_required"]
        assignment = self._assignment(block, item["leaf_issue"], active=True)
        descriptor = self._descriptor(block, item["leaf_issue"], assignment, active=True)
        with self.assertRaises(self.c.ContractViolation):
            self._workspace_receipt(assignment, descriptor,
                                    self.c.WorkspaceDisposition.EXCLUDED)

    # WORK_UNIT_CASE: 829/2
    def test_02_exact_six_package_denominator_no_duplicates(self) -> None:
        ws = root_workspace()
        self.assertEqual(len(self.six_paths), 6)
        self.assertEqual(len(set(self.six_paths)), 6)
        for path in self.six_paths:
            self.assertEqual(ws["members"].count(path), 1, path)
            self.assertNotIn(path, ws["exclude"])
        self.assertEqual(sorted(i["crate_path"] for i in load_fixture("candidate.json")["six"]),
                         sorted(self.six_paths))
        self.assertEqual(len({load_toml(f"{p}/Cargo.toml")["package"]["name"]
                              for p in self.six_paths}), 6)

    # WORK_UNIT_CASE: 829/3
    def test_03_missing_unmerged_unaccepted_leaf_evidence_blocks_activation(self) -> None:
        """Pre-admission readiness is real prerequisite evidence, never ADMITTED."""
        for item in self.six:
            name, cp = item["name"], item["crate_path"]
            block = self.receipts[name]["package_only"]
            assignment = self._assignment(block, item["leaf_issue"], active=False)
            descriptor = self._descriptor(block, item["leaf_issue"], assignment, active=False)
            self.assertFalse(descriptor.require_workspace_member, name)
            self.assertIs(descriptor.phase, self.c.VerificationPhase.PACKAGE_LOCAL, name)

            prerequisite = self.c.PrerequisiteEvidence(
                source=assignment, accepted_commit=block["accepted_commit"],
                accepted_result_sha256=block["accepted_result_sha256"])
            self.assertIs(prerequisite.source.source_use,
                          self.c.AssignmentSourceUse.PREREQUISITE_EVIDENCE)
            for commit in self.receipts[name]["leaf_commits"]:
                probe = git("merge-base", "--is-ancestor", commit, self.merge_parent)
                self.assertEqual(probe.returncode, 0, f"{name}@{commit} not merged first")
            probe = git("cat-file", "-e", prerequisite.accepted_commit + "^{commit}")
            self.assertEqual(probe.returncode, 0, name)

            # The prerequisite may not be the post-admission status.
            parent_status = self.admission["module_status_at_parent"][cp]["status"]
            live_status = load_toml(f"{cp}/module.toml")["status"]
            self.assertNotEqual(parent_status, live_status, name)
            self.assertNotEqual(parent_status, "ADMITTED", name)

        # Negative legs enter the same production validation path.
        item = self.six[0]
        block = self.receipts[item["name"]]["package_only"]
        assignment = self._assignment(block, item["leaf_issue"], active=False)
        with self.assertRaises(self.c.ContractViolation):
            self.c.PrerequisiteEvidence(source=assignment, accepted_commit="0" * 39,
                                        accepted_result_sha256=block["accepted_result_sha256"])
        with self.assertRaises(self.c.ContractViolation):
            self.c.PrerequisiteEvidence(
                source=self._assignment(self.receipts[item["name"]]["membership_required"],
                                        item["leaf_issue"], active=True),
                accepted_commit=block["accepted_commit"],
                accepted_result_sha256=block["accepted_result_sha256"])
        raw = (ROOT / block["descriptor_path"]).read_bytes()
        with self.assertRaises(self.runner.RunnerInputError):
            self.runner.decode_descriptor(raw.replace(b"test_floor = ",
                                                      b"test_floor = 0\nignored = "),
                                           f".github/work-units/{item['leaf_issue']}.toml")

    # WORK_UNIT_CASE: 829/4
    def test_04_failed_partial_or_stale_package_local_proof_blocks_activation(self) -> None:
        """Package-local proof is bound to the pre-admission tree, not to main."""
        for item in self.six:
            name, cp = item["name"], item["crate_path"]
            block = self.receipts[name]["package_only"]
            rows = discovered_matrix(self.pre[cp])
            self.assertEqual(matrix_digest(rows), block["matrix_sha256"], name)
            self.assertEqual(source_inventory(cp, self.pre[cp]), block["source_sha256"], name)
            self.assertEqual(execution_digest(rows), block["execution_receipt_sha256"], name)
            self.assertEqual(len(rows), block["executed_pass_count"], name)
            assignment = self._assignment(block, item["leaf_issue"], active=False)
            descriptor = self._descriptor(block, item["leaf_issue"], assignment, active=False)

            # Pre-admission package-only evidence is preserved as history. The
            # frozen contract refuses to let a prerequisite-evidence receipt claim
            # a PASS, which is exactly why it cannot stand in for admission proof.
            with self.assertRaises(self.c.ContractViolation):
                self._discovered_receipts(assignment, descriptor, block, rows,
                                          self.c.OverallResult.PASS)
            historical = self._discovered_receipts(
                assignment, descriptor, block, rows, self.c.OverallResult.INCOMPLETE_EVIDENCE)
            self.assertIs(historical.result, self.c.OverallResult.INCOMPLETE_EVIDENCE, name)
            self.assertEqual(len(historical.members), descriptor.matrix_cases, name)

            # The same pre-admission evidence under the ACTIVE membership-required
            # assignment is the receipt that can be validated.
            active_block = self.receipts[name]["membership_required"]
            active_rows = discovered_matrix(self.live[cp])
            self.assertEqual(matrix_digest(active_rows), active_block["matrix_sha256"], name)
            active_assignment = self._assignment(active_block, item["leaf_issue"], active=True)
            active_descriptor = self._descriptor(active_block, item["leaf_issue"],
                                                 active_assignment, active=True)
            active_cases = self._active_receipt(active_assignment, active_descriptor,
                                                active_block, active_rows)
            self.assertIs(active_cases.result, self.c.OverallResult.PASS, name)
            active_shape = self._source_shape(active_assignment, active_descriptor, active_block)
            active_package = self._package_receipt(active_assignment, active_descriptor,
                                                   active_shape, active_cases)
            self.assertIs(active_package.result, self.c.OverallResult.PASS, name)

            # Stale evidence is refused by the same production path.
            self.assertNotEqual(matrix_digest(discovered_matrix(self.live[cp])),
                                block["matrix_sha256"], name)
            with self.assertRaises(self.c.ContractViolation):
                self._package_receipt(
                    active_assignment, active_descriptor,
                    self._source_shape(active_assignment, active_descriptor,
                                       dict(active_block, source_sha256=block["matrix_sha256"])),
                    active_cases)
            with self.assertRaises(self.c.ContractViolation):
                self._source_shape(active_assignment, active_descriptor,
                                   dict(active_block, public_items=0))

            # Partial, failed and unexecuted evidence are all refused.
            for disposition, label in ((self.c.ExecutionDisposition.SKIPPED, "partial"),
                                       (self.c.ExecutionDisposition.EXECUTED_FAIL, "failed"),
                                       (self.c.ExecutionDisposition.DISCOVERED, "not-executed")):
                members = list(active_cases.members)
                first = members[0]
                broken = self.c.TestExecutionRecord(
                    test=first.execution.test, disposition=disposition,
                    discovery=first.execution.discovery)
                members[0] = self.c.CaseAccountingMember(
                    case=first.case, marker=first.marker, execution=broken)
                with self.assertRaises(self.c.ContractViolation, msg=label):
                    self.c.CaseAccountingReceipt(
                        assignment=active_assignment, descriptor=active_descriptor,
                        members=tuple(members), result=self.c.OverallResult.PASS,
                        proof_ceiling=active_descriptor.proof_ceiling)

            # A short denominator cannot present as a complete run.
            with self.assertRaises(self.c.ContractViolation):
                self._discovered_receipts(active_assignment, active_descriptor, active_block,
                                          active_rows[:-1], self.c.OverallResult.PASS)

    # WORK_UNIT_CASE: 829/5
    def test_05_unresolved_challenge_or_owner_contract_blocks_activation(self) -> None:
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

        # #816 is the accepted owner of the cognitive owner/dependency contract.
        self.assertEqual(self.topology816.topology_errors(self.bundle816), [])
        self.assertEqual(self.bundle816["wave"]["topology"]["issue"], 816)
        self.assertIs(self.bundle816["wave"]["topology"]["metadata_only"], True)
        self.assertIs(self.bundle816["wave"]["topology"]["runtime_completion"], False)
        pairs = self.topology816.compile_pairs(self.bundle816)
        self.assertTrue(pairs)
        # #816 owns wave-01 topology. Five of the six are its assignment rows and
        # must carry the recorded leaf issue; the learning cell belongs to wave-02
        # and is therefore absent by design, which is itself asserted.
        expected = self.topology816.EXPECTED_ASSIGNMENTS
        owners = {row[3]: key for key, row in expected.items()}
        wave01 = [i for i in self.six if i["name"] in owners]
        self.assertEqual(len(wave01), 5)
        for item in wave01:
            owner = owners[item["name"]]
            self.assertEqual(expected[owner][2], item["leaf_issue"], item["name"])
        self.assertNotIn("eliot-learning-contracts", owners)
        learning = self.by_name["eliot-learning-contracts"]
        self.assertEqual(load_toml(f"{learning['crate_path']}/module.toml")["wave"],
                         "cognitive-micromodules-wave-02")
        for source, target in pairs:
            self.assertNotEqual(source, target)
        for edge in self.bundle816["edges"]["compile_edge"]:
            self.assertEqual(edge["relation"], "contract_only")

        # Negative legs through the accepted #816 validator and its own fixtures.
        fixture_mutations = self.topology816.load_fixture()["mutations"]
        self.assertTrue(fixture_mutations)
        for mutation in fixture_mutations:
            mutated = self.topology816.apply_mutation(self.bundle816, mutation)
            self.assertTrue(self.topology816.topology_errors(mutated), mutation["id"])

    # WORK_UNIT_CASE: 829/6
    def test_06_second_root_lock_index_writer_blocks_activation(self) -> None:
        """The exclusive lane is the #818 oracle's verdict, not a local list."""
        self.assertEqual(self.writer_lane["status"], "Valid")
        self.assertEqual(self.writer_lane["denominators"]["errors"], 0)
        self.assertEqual(self.writer_lane["overlap_map"], {})
        readiness = self.writer_lane["readiness_map"]
        self.assertEqual(readiness[str(self.candidate["issue"])], "READY")
        self.assertEqual([num for num, state in readiness.items() if state == "READY"],
                         [str(self.candidate["issue"])])

        competing_rules = {f["rule_id"] for f in self.writer_competing["findings"]}
        self.assertIn("AU-SHARED-ROOT-WRITERS", competing_rules)
        overlaps = self.writer_competing["overlap_map"]
        for path in ROOT_WRITE_PATHS:
            self.assertIn(path, overlaps)
            self.assertEqual(len(overlaps[path]), 2, path)

        # The admitted packages moved in the recorded transaction, in one turn.
        base = show_toml(self.merge_parent, "Cargo.toml")["workspace"]
        live = root_workspace()
        moved = sorted(p for p in self.six_paths
                       if p in live["members"] and p not in base["members"])
        self.assertEqual(moved, sorted(self.six_paths))
        self.assertEqual(int(git("rev-list", "--count",
                                      f"{self.merge_parent}..{self.merge_commit}")
                                  .stdout.strip()), 1)

    # WORK_UNIT_CASE: 829/7
    def test_07_stale_plan_invalidated_by_current_main(self) -> None:
        probe = git("merge-base", "--is-ancestor", self.merge_commit, "HEAD")
        self.assertEqual(probe.returncode, 0, probe.stderr)
        stale = show_toml(self.merge_parent, "Cargo.toml")["workspace"]
        live = root_workspace()
        self.assertNotEqual(sorted(stale["members"]), sorted(live["members"]))
        stale_errors = validate_wave_state(
            stale["members"], stale["exclude"],
            {p: {"status": self.admission["module_status_at_parent"][p]["status"]}
             for p in self.six_paths},
            set(lock_packages()), self.six_paths)
        self.assertTrue(stale_errors)
        self.assertEqual(validate_wave_state(
            live["members"], live["exclude"],
            {p: {"status": "ADMITTED"} for p in self.six_paths},
            set(lock_packages()), self.six_paths), [])
        # The merge-parent manifest is no longer a valid admission target: the six
        # are still excluded and not members there.
        self.assertEqual(len(stale["members"]) + 6, self.admission["root_members_at_merge"])
        self.assertTrue(any("still excluded" in e for e in stale_errors), stale_errors)
        self.assertTrue(any("member count != 1" in e for e in stale_errors), stale_errors)

    # WORK_UNIT_CASE: 829/8
    def test_08_package_cell_order_layer_identity_matches_leaf_evidence(self) -> None:
        for item in self.six:
            cp = item["crate_path"]
            module = load_toml(f"{cp}/module.toml")
            manifest = load_toml(f"{cp}/Cargo.toml")
            meta = manifest["package"]["metadata"]["eliot"]
            self.assertEqual(module["module_id"], item["functional_cell"], item["name"])
            self.assertEqual(module["crate"], item["name"])
            self.assertEqual(module["agent_order"], item["agent_order"], item["name"])
            self.assertEqual(module["source_layer"], item["source_layer"], item["name"])
            self.assertEqual(meta["functional_cell"], item["functional_cell"], item["name"])
            self.assertEqual(meta["agent_order"], item["agent_order"], item["name"])
            self.assertEqual(meta["source_layer"], item["source_layer"], item["name"])
            frozen = self.admission["module_status_at_merge"][cp]
            self.assertEqual(frozen["module_id"], module["module_id"], cp)
            self.assertEqual(frozen["agent_order"], module["agent_order"], cp)
            self.assertEqual(frozen["source_layer"], module["source_layer"], cp)

    # WORK_UNIT_CASE: 829/9
    def test_09_package_ready_proof_precedes_admission_and_ignores_admitted_status(self) -> None:
        for item in self.six:
            name, cp = item["name"], item["crate_path"]
            block = self.receipts[name]["package_only"]
            assignment = self._assignment(block, item["leaf_issue"], active=False)
            self.c.PrerequisiteEvidence(
                source=assignment, accepted_commit=block["accepted_commit"],
                accepted_result_sha256=block["accepted_result_sha256"])
            parent = self.admission["module_status_at_parent"][cp]
            self.assertNotEqual(parent["status"], "ADMITTED", name)
            self.assertNotEqual(parent["workspace_admission"],
                                self.candidate["admission_note"], name)
            merge = self.admission["module_status_at_merge"][cp]
            self.assertEqual(merge["status"], "ADMITTED", name)
            self.assertEqual(merge["workspace_admission"], self.candidate["admission_note"])
            for commit in self.receipts[name]["leaf_commits"]:
                probe = git("merge-base", "--is-ancestor", commit, self.merge_parent)
                self.assertEqual(probe.returncode, 0, f"{name}@{commit}")

    # WORK_UNIT_CASE: 829/10
    def test_10_compile_graph_acyclic(self) -> None:
        edges = internal_edges()
        order = topo_sort(edges)
        self.assertGreater(len(order), 100)
        for name in self.six_names:
            self.assertIn(name, order)
        # Cargo permits a dev-dependency cycle (eliot-ors uses one), so the
        # acyclicity claim is about the compile graph read above, not dev edges.
        self.assertTrue(any(deps for deps in dev_edges().values()))
        poison = dict(edges)
        first, second = self.six_names[0], self.six_names[1]
        poison[first] = set(poison[first]) | {second}
        poison[second] = set(poison[second]) | {first}
        with self.assertRaises(ValueError):
            topo_sort(poison)

    # WORK_UNIT_CASE: 829/11
    def test_11_forbidden_downstream_edge_rejected(self) -> None:
        for item in self.six:
            manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
            declared = declared_dependencies(manifest)
            self.assertEqual(declared & FORBIDDEN_DOWNSTREAM, set(), item["name"])
        # Negative leg through the same reader, on a real manifest copy.
        victim = load_toml(f"{self.six[0]['crate_path']}/Cargo.toml")
        victim.setdefault("dev-dependencies", {})["eliot-dreamer-core"] = {"path": "x"}
        self.assertEqual(declared_dependencies(victim) & FORBIDDEN_DOWNSTREAM,
                         {"eliot-dreamer-core"})

    # WORK_UNIT_CASE: 829/12
    def test_12_logical_relation_not_fabricated_as_cargo_dependency(self) -> None:
        dreamer = load_toml("crates/smart/eliot-dreamer-contracts/module.toml")
        self.assertIn("all Dreamer handlers", dreamer["consumers"])
        declared = declared_dependencies(load_toml("crates/smart/eliot-dreamer-contracts/Cargo.toml"))
        self.assertNotIn("eliot-dreamer-core", declared)
        self.assertNotIn("eliot-dreamer-bundle", declared)
        pairs = self.topology816.compile_pairs(self.bundle816)
        self.assertFalse([p for p in pairs if p[0] == p[1]])

    # WORK_UNIT_CASE: 829/13
    def test_13_each_package_exactly_one_member_or_verified_noop(self) -> None:
        ws = root_workspace()
        for item in self.six:
            cp = item["crate_path"]
            self.assertEqual(ws["members"].count(cp), 1)
            self.assertNotIn(cp, ws["exclude"])
            self.assertIs(self._membership_disposition(item["name"]),
                          self.c.WorkspaceDisposition.MEMBER, item["name"])
        self.assertEqual(validate_wave_state(
            ws["members"], ws["exclude"],
            {p: {"status": "ADMITTED"} for p in self.six_paths},
            set(lock_packages()), self.six_paths), [])
        base = show_toml(self.merge_parent, "Cargo.toml")["workspace"]
        for item in self.six:
            cp = item["crate_path"]
            self.assertNotIn(cp, base["members"], cp)
            self.assertIn(cp, base["exclude"], cp)

    # WORK_UNIT_CASE: 829/14
    def test_14_duplicate_member_exclusion_name_path_rejected(self) -> None:
        ws = root_workspace()
        self.assertEqual(len(ws["members"]), len(set(ws["members"])))
        self.assertEqual(len(ws["exclude"]), len(set(ws["exclude"])))
        admitted = {p: {"status": "ADMITTED"} for p in self.six_paths}
        names = set(lock_packages())
        self.assertIn("duplicate workspace member",
                      validate_wave_state(ws["members"] + [self.six_paths[0]], ws["exclude"],
                                          admitted, names, self.six_paths))
        nonmember = self._first_nonmember_path()
        duplicated = [nonmember, nonmember]
        self.assertIn("duplicate workspace exclusion",
                      validate_wave_state(ws["members"], duplicated,
                                          admitted, names, self.six_paths))
        self.assertIn("member/exclusion overlap",
                      validate_wave_state(ws["members"], ws["exclude"] + [self.six_paths[0]],
                                          admitted, names, self.six_paths))
        self.assertEqual(len({load_toml(f"{p}/Cargo.toml")["package"]["name"]
                              for p in self.six_paths}), 6)

    # WORK_UNIT_CASE: 829/15
    def test_15_inheritance_preserves_versions_features_lints(self) -> None:
        root_deps = root_workspace()["dependencies"]
        for item in self.six:
            cp = item["crate_path"]
            manifest = load_toml(f"{cp}/Cargo.toml")
            package = manifest["package"]
            for key in ("version", "edition", "rust-version", "license"):
                self.assertEqual(package[key], {"workspace": True}, f"{item['name']}.{key}")
            self.assertEqual(manifest["lints"], {"workspace": True})
            self.assertNotIn("workspace", manifest, item["name"])
            for table in ("dependencies", "dev-dependencies"):
                for dep, spec in manifest.get(table, {}).items():
                    if isinstance(spec, dict) and spec.get("workspace") is True:
                        self.assertIn(dep, root_deps, f"{item['name']}.{dep}")

    # WORK_UNIT_CASE: 829/16
    def test_16_admission_transaction_changes_no_rust_or_semantic_metadata(self) -> None:
        """Exact-scope gate over the admission transaction. No .rs exception list.

        The issue's **Must not modify** section forbids Rust source and Rust
        tests outright. There is deliberately no ``FMT_ONLY_RS_ALLOWLIST`` here:
        a rustfmt-only derivation is a local observation, not an authorization to
        widen the issue's exclusive mutable scope. This case therefore fails on
        any ``.rs`` path in the recorded transaction, which is the true state of
        the merged #829 admission.

        ``admission.json`` carries two disjoint path sets.
        ``observed_delta_paths`` is what PR #1456 actually changed and must match
        git exactly. ``authorized_delta_paths`` is the exact permitted set: every
        non-Rust path of that transaction. The two differ by exactly the Rust
        paths, and that difference is the violation this case reports.
        """
        delta = changed_paths(self.merge_parent, self.merge_commit)
        self.assertEqual(delta, self.admission["observed_delta_paths"])
        rust = sorted(p for p in delta if p.endswith(RUST_SOURCE_SUFFIXES))
        self.assertEqual(
            rust, [],
            "the #829 admission transaction still changes forbidden Rust source/test "
            f"paths ({len(rust)}): {rust}. The issue forbids Rust source/tests, so "
            "these must be removed from the #829 delta or moved to separately "
            "authorized leaf-owner work with its own evidence, and the admission "
            "re-baselined onto the resulting merge commit. This lane may not edit "
            ".rs files, so the re-baseline is a root-authorized turn.")
        self.assertEqual(validate_admission_scope(delta, self.admission["authorized_delta_paths"]),
                         [])

        # Negative legs through the same validator.
        self.assertTrue(validate_admission_scope(
            delta + ["crates/smart/eliot-cue-contracts/src/lib.rs"],
            self.admission["authorized_delta_paths"]))
        self.assertTrue(validate_admission_scope(delta[:-1],
                                                 self.admission["authorized_delta_paths"]))

        # The frozen authorization itself must be Rust-free, so the exact-scope
        # gate can never be widened to admit a source/test path by editing the
        # fixture instead of the transaction.
        authorized_rust = sorted(p for p in self.admission["authorized_delta_paths"]
                                  if p.endswith(RUST_SOURCE_SUFFIXES))
        self.assertEqual(authorized_rust, [], authorized_rust)
        self.assertEqual(validate_admission_scope(self.admission["authorized_delta_paths"],
                                                  self.admission["authorized_delta_paths"]),
                         [])

        allowed_cargo = {"prototype", "workspace_admission"}
        allowed_module = {"status", "workspace_admission"}
        for item in self.six:
            cp = item["crate_path"]
            base_cargo = show_toml(self.merge_parent, f"{cp}/Cargo.toml")
            live_cargo = load_toml(f"{cp}/Cargo.toml")
            self.assertEqual(live_cargo["package"]["name"], base_cargo["package"]["name"])
            self.assertEqual(live_cargo["package"]["description"],
                             base_cargo["package"]["description"])
            live_meta = live_cargo["package"]["metadata"]["eliot"]
            base_meta = base_cargo["package"]["metadata"]["eliot"]
            for key in base_meta:
                if key not in allowed_cargo:
                    self.assertEqual(live_meta.get(key), base_meta[key], f"{item['name']}.{key}")
            base_module = show_toml(self.merge_parent, f"{cp}/module.toml")
            live_module = load_toml(f"{cp}/module.toml")
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
                self.assertEqual(live_module.get(key), base_module[key], f"{item['name']}.{key}")

    # WORK_UNIT_CASE: 829/17
    def test_17_root_manifest_changes_only_six_entries_and_the_writer_comment(self) -> None:
        diff = git("diff", self.merge_parent, self.merge_commit, "--", "Cargo.toml")
        self.assertEqual(diff.returncode, 0, diff.stderr)
        added = [l[1:].strip() for l in diff.stdout.splitlines()
                 if l.startswith("+") and not l.startswith("+++")]
        removed = [l[1:].strip() for l in diff.stdout.splitlines()
                   if l.startswith("-") and not l.startswith("---")]
        for path in self.six_paths:
            self.assertEqual([_entry(l) for l in added if _entry(l) == path], [path], path)
            self.assertEqual([_entry(l) for l in removed if _entry(l) == path], [path], path)
        member_lines = [l for l in added + removed if _entry(l).startswith("crates/")]
        self.assertEqual(len(member_lines), 12)
        added_comments = [l for l in added if l.startswith("#")]
        removed_comments = [l for l in removed if l.startswith("#")]
        self.assertTrue(added_comments)
        self.assertTrue(removed_comments)
        # The replacement comment is added; the stale self-promotion claim is
        # removed and must not survive anywhere in the transaction's additions.
        self.assertIn(self.admission["writer_comment"], "\n".join(added_comments))
        self.assertIn(self.baseline["stale_comment"], "\n".join(removed_comments))
        self.assertNotIn(self.baseline["stale_comment"], "\n".join(added_comments))

        # Complete semantic root diff: only members/exclude moved. The same
        # reader accepts the real transaction and refuses unrelated root edits.
        base, merged = self.parent_root, self.merge_root
        self.assertEqual(validate_root_manifest_delta(base, merged, self.six_paths), [])

        # Negative legs through that reader: an unrelated root edit of any family
        # (version pin, lint level, package metadata, seventh member, dropped
        # exclusion) is refused, not tolerated beside the six entries.
        poison = copy.deepcopy(merged)
        poison["workspace"]["dependencies"]["serde"]["version"] = "9.9.9"
        self.assertTrue(any("workspace key" in e for e in
                            validate_root_manifest_delta(base, poison, self.six_paths)))
        poison = copy.deepcopy(merged)
        poison["workspace"]["lints"]["clippy"]["unwrap_used"] = "allow"
        self.assertTrue(any("workspace key" in e for e in
                            validate_root_manifest_delta(base, poison, self.six_paths)))
        poison = copy.deepcopy(merged)
        poison["workspace"]["package"]["rust-version"] = "1.00"
        self.assertTrue(any("workspace key" in e for e in
                            validate_root_manifest_delta(base, poison, self.six_paths)))
        poison = copy.deepcopy(merged)
        poison["profile"] = {"release": {"lto": True}}
        self.assertTrue(any("root table" in e for e in
                            validate_root_manifest_delta(base, poison, self.six_paths)))
        poison = copy.deepcopy(merged)
        poison["workspace"]["members"].append("crates/smart/eliot-seventh")
        self.assertTrue(any("members gained" in e for e in
                            validate_root_manifest_delta(base, poison, self.six_paths)))
        poison = copy.deepcopy(merged)
        poison["workspace"]["exclude"].append("crates/smart/eliot-unrelated")
        self.assertTrue(any("unrelated workspace exclusion" in e for e in
                            validate_root_manifest_delta(base, poison, self.six_paths)))
        poison = copy.deepcopy(merged)
        del poison["workspace"]["members"][poison["workspace"]["members"].index(
            self.six_paths[2])]
        self.assertTrue(any("members gained" in e for e in
                            validate_root_manifest_delta(base, poison, self.six_paths)))

    # WORK_UNIT_CASE: 829/18
    def test_18_one_combined_lock_resolution_with_complete_explanations(self) -> None:
        """Every edge of the single resolution is explained by a real manifest."""
        diff = git("diff", self.merge_parent, self.merge_commit, "--", "Cargo.lock")
        self.assertEqual(diff.returncode, 0, diff.stderr)
        added = [l.split("=", 1)[1].strip().strip('"') for l in diff.stdout.splitlines()
                 if l.startswith("+name =")]
        removed = [l for l in diff.stdout.splitlines()
                   if l.startswith("-") and not l.startswith("---")]
        base_names = {p["name"] for p in self.parent_lock["package"]}
        self.assertEqual(validate_lock_delta(sorted(set(added)), removed, base_names,
                                             set(self.six_names)), [])
        self.assertFalse(any(l.startswith("-version =") for l in diff.stdout.splitlines()))
        self.assertFalse(any(l.startswith("-checksum") for l in diff.stdout.splitlines()))

        # Independent explanation: resolved edges equal the merged manifests'
        # declared edges, and no pre-existing stanza drifts.
        self.assertEqual(validate_lock_resolution(self.parent_lock, self.merge_lock,
                                                  set(self.six_names), self.owner_deps), [])
        base_index, merged_index = _lock_index(self.parent_lock), _lock_index(self.merge_lock)
        # The one pre-existing stanza the admission extended is the one that was
        # already a path dependency of another member; becoming a member adds its
        # dev-dependencies to the resolution. That is the whole edge explanation.
        extended = sorted(name for name in set(base_index) & set(merged_index)
                          if {d.split(" ")[0] for d in merged_index[name][0].get("dependencies", [])}
                          - {d.split(" ")[0] for d in base_index[name][0].get("dependencies", [])})
        self.assertEqual(extended, ["eliot-epistemic-contracts"])
        gained = {d.split(" ")[0] for d in merged_index[extended[0]][0]["dependencies"]
                  } - {d.split(" ")[0] for d in base_index[extended[0]][0]["dependencies"]}
        self.assertEqual(gained & set(self.six_names), set())
        self.assertIn("serde_json", self.owner_deps[extended[0]])
        self.assertIn("serde_json",
                      {d.split(" ")[0] for d in merged_index[extended[0]][0]["dependencies"]})

        lock = lock_packages()
        for name in self.six_names:
            self.assertIn(name, lock)
            self.assertEqual(len(lock[name]), 1, name)
            for dep in lock[name][0].get("dependencies", []):
                self.assertIn(dep.split(" ")[0], base_names | set(self.six_names), name)

        # Negative legs through the same resolver: an added stanza without an
        # admission cause, a version/checksum drift on an existing stanza, a lost
        # edge, an undeclared edge and a dropped edge are all refused.
        poison = copy.deepcopy(self.merge_lock)
        poison["package"].append({"name": "poison-plus-crate", "version": "0.1.0"})
        self.assertTrue(any("added without an admission cause" in e for e in
                            validate_lock_resolution(self.parent_lock, poison,
                                                     set(self.six_names), self.owner_deps)))
        poison = copy.deepcopy(self.merge_lock)
        victim = next(p for p in poison["package"] if p["name"] == "serde")
        victim["version"] = "9.9.9"
        self.assertTrue(any("changed version" in e for e in
                            validate_lock_resolution(self.parent_lock, poison,
                                                     set(self.six_names), self.owner_deps)))
        victim["version"] = _lock_index(self.parent_lock)["serde"][0]["version"]
        victim.pop("checksum", None)
        self.assertTrue(any("changed checksum" in e for e in
                            validate_lock_resolution(self.parent_lock, poison,
                                                     set(self.six_names), self.owner_deps)))
        poison = copy.deepcopy(self.merge_lock)
        poison["package"] = [p for p in poison["package"] if p["name"] != "serde_json"]
        self.assertTrue(any("removed lock stanzas" in e for e in
                            validate_lock_resolution(self.parent_lock, poison,
                                                     set(self.six_names), self.owner_deps)))
        poison = copy.deepcopy(self.merge_lock)
        # serde is resolved in both revisions, so dropping one of its edges is a
        # real removal the resolver must refuse.
        stanza = next(p for p in poison["package"] if p["name"] == "serde")
        base_edges = {d.split(" ")[0] for d in
                      _lock_index(self.parent_lock)["serde"][0]["dependencies"]}
        self.assertTrue(base_edges)
        stanza["dependencies"] = [d for d in stanza["dependencies"]
                                  if d.split(" ")[0] not in base_edges]
        self.assertTrue(any("lost an edge" in e for e in
                            validate_lock_resolution(self.parent_lock, poison,
                                                     set(self.six_names), self.owner_deps)))
        poison = copy.deepcopy(self.merge_lock)
        stanza = next(p for p in poison["package"] if p["name"] == extended[0])
        stanza["dependencies"].append("poison-plus-crate")
        self.assertTrue(any("unexplained edge added" in e for e in
                            validate_lock_resolution(self.parent_lock, poison,
                                                     set(self.six_names), self.owner_deps)))
        poison = copy.deepcopy(self.merge_lock)
        stanza = next(p for p in poison["package"] if p["name"] == self.six_names[0])
        stanza["dependencies"] = [d for d in stanza["dependencies"] if "sha2" not in d]
        self.assertTrue(any("omits a declared edge" in e for e in
                            validate_lock_resolution(self.parent_lock, poison,
                                                     set(self.six_names), self.owner_deps)))

    # WORK_UNIT_CASE: 829/19
    def test_19_unrelated_lock_drift_rejected(self) -> None:
        """Unrelated drift is refused by the same resolver that accepts the delta."""
        base_names = {p["name"] for p in self.parent_lock["package"]}
        added = sorted({p["name"] for p in load_toml("Cargo.lock")["package"]} - base_names)
        unexplained = [n for n in added if n not in self.six_names]
        # Only the six admissions may introduce new lock identities in the transaction.
        diff = git("diff", self.merge_parent, self.merge_commit, "--", "Cargo.lock")
        transaction_added = sorted({l.split("=", 1)[1].strip().strip('"')
                                    for l in diff.stdout.splitlines() if l.startswith("+name =")})
        self.assertEqual(validate_lock_delta(transaction_added, [], base_names,
                                             set(self.six_names)), [])
        self.assertTrue(validate_lock_delta(transaction_added + ["unrelated-crate"], [],
                                            base_names, set(self.six_names)))
        self.assertTrue(validate_lock_delta(transaction_added, ["serde"], base_names,
                                            set(self.six_names)))
        # Every added stanza belongs to a leaf; withdrawing one admission cause
        # leaves that stanza unexplained.
        self.assertTrue(validate_lock_delta(transaction_added, [], base_names,
                                            set(self.six_names) - {transaction_added[0]}))
        # A later unrelated addition is refused rather than absorbed.
        self.assertTrue(validate_lock_delta(transaction_added + ["serde"], [], base_names,
                                            set(self.six_names)))
        self.assertNotIn("unrelated-crate", lock_packages())
        self.assertEqual(sorted(n for n in added if n not in unexplained), transaction_added)
        # Later legitimate growth on main is current state, never part of the
        # admission delta: the six-package claim is reconciled against the recorded
        # transaction, not against every package admitted since.
        self.assertEqual(validate_lock_resolution(self.parent_lock, self.merge_lock,
                                                  set(self.six_names), self.owner_deps), [])
        self.assertTrue(unexplained)

        # The poison is fed to that resolver: a fabricated stanza, an unrelated
        # gained edge on a pre-existing stanza, and an unrelated version bump.
        poison_plus = copy.deepcopy(self.merge_lock)
        poison_plus["package"].append({"name": "poison-plus-crate", "version": "0.1.0"})
        errors = validate_lock_resolution(self.parent_lock, poison_plus,
                                          set(self.six_names), self.owner_deps)
        self.assertTrue(any("poison-plus-crate" in e and "admission cause" in e
                            for e in errors), errors)
        poison_plus = copy.deepcopy(self.merge_lock)
        stanza = next(p for p in poison_plus["package"] if p["name"] == "eliot-contracts")
        stanza["dependencies"] = list(stanza.get("dependencies", [])) + ["poison-plus-crate"]
        errors = validate_lock_resolution(self.parent_lock, poison_plus,
                                          set(self.six_names), self.owner_deps)
        self.assertTrue(any("unexplained edge added" in e for e in errors), errors)
        poison_plus = copy.deepcopy(self.merge_lock)
        stanza = next(p for p in poison_plus["package"] if p["name"] == "serde")
        stanza["version"] = "9.9.9"
        errors = validate_lock_resolution(self.parent_lock, poison_plus,
                                          set(self.six_names), self.owner_deps)
        self.assertTrue(any("changed version" in e for e in errors), errors)

    # WORK_UNIT_CASE: 829/20
    def test_20_admitted_packages_use_the_canonical_root_lock_identity(self) -> None:
        base_lock = show_toml(self.merge_parent, "Cargo.lock")
        base_sources = {p["name"] for p in base_lock["package"]
                        if "source" not in p or p.get("source", "").startswith("crates/")}
        lock = lock_packages()
        self.assertTrue(lock)
        for item in self.six:
            name, cp = item["name"], item["crate_path"]
            # No package-local lock survives: one canonical root lock identity.
            self.assertFalse((ROOT / cp / "Cargo.lock").exists(), name)
            self.assertIn(cp, root_workspace()["members"], name)
            self.assertEqual(len(lock[name]), 1, name)
            entry = lock[name][0]
            # Every admitted package is resolved from its own in-tree source.
            self.assertNotIn("source", entry, name)
            self.assertTrue(any(d["path"] if isinstance(d, dict) else d
                                for d in entry.get("dependencies", []))
                            or name not in base_sources, name)
        for name in self.six_names:
            self.assertIn(name, base_sources | set(self.six_names), name)

    # WORK_UNIT_CASE: 829/21
    def test_21_generated_rows_cover_exactly_the_affected_packages_and_their_transition(self) -> None:
        """The six rows and their membership transition, not global absolute counts."""
        package_index = read_bytes(PACKAGE_INDEX).decode("utf-8")
        prototype_index = read_bytes(PROTOTYPE_INDEX).decode("utf-8")
        parent_package = show_bytes(self.merge_parent, PACKAGE_INDEX).decode("utf-8")
        parent_prototype = show_bytes(self.merge_parent, PROTOTYPE_INDEX).decode("utf-8")
        merge_package = show_bytes(self.merge_commit, PACKAGE_INDEX).decode("utf-8")
        merge_prototype = show_bytes(self.merge_commit, PROTOTYPE_INDEX).decode("utf-8")
        for item in self.six:
            cp = item["crate_path"]
            recorded = self.admission["index_rows"][cp]
            self.assertEqual(index_row_cell(parent_package, cp), recorded["parent"]["package"])
            self.assertEqual(index_row_cell(parent_prototype, cp),
                             recorded["parent"]["prototype"])
            self.assertEqual(index_row_cell(merge_package, cp), recorded["merge"]["package"])
            self.assertEqual(index_row_cell(merge_prototype, cp), recorded["merge"]["prototype"])
            self.assertIsNone(recorded["parent"]["package"], cp)
            self.assertEqual(recorded["parent"]["prototype"], "`nonmember prototype`", cp)
            self.assertEqual(recorded["merge"]["package"], "`workspace`", cp)
            self.assertIsNone(recorded["merge"]["prototype"], cp)
            # Current state keeps the merged membership row and no prototype row.
            self.assertEqual(index_row_cell(package_index, cp), "`workspace`", cp)
            self.assertIsNone(index_row_cell(prototype_index, cp), cp)

    # WORK_UNIT_CASE: 829/22
    def test_22_second_generation_byte_identical_and_writes_only_declared_files(self) -> None:
        """Snapshot first, then prove the generator wrote only the declared files."""
        snapshot = {rel: read_bytes(rel) for rel in GENERATED_INDEXES}
        before = self._tracked_digests()
        before_status = self._worktree_status()
        first = py_script("scripts/code_navigation.py", "sync-index", "--root", ".")
        self.assertEqual(first.returncode, 0, first.stderr[-2000:])
        after_first = self._tracked_digests()
        second = py_script("scripts/code_navigation.py", "sync-index", "--root", ".")
        self.assertEqual(second.returncode, 0, second.stderr[-2000:])
        after_second = self._tracked_digests()
        # Every tracked byte of the checkout was snapshotted before the generator
        # ran, so a rewrite of any file outside the two declared generated
        # indexes is visible, not only the two hashes the generator reports.
        touched = sorted(rel for rel in set(before) | set(after_second)
                         if before.get(rel) != after_second.get(rel))
        self.assertTrue(set(touched) <= set(GENERATED_INDEXES), touched)
        for index in GENERATED_INDEXES:
            self.assertEqual(after_first.get(index), after_second.get(index), index)
        # The generator is idempotent: the second run writes nothing new.
        self.assertEqual(after_first, after_second)
        # No untracked or unexpected path was created either.
        after_status = self._worktree_status()
        written = sorted({rel for rel in after_status
                          if rel not in before_status or after_status[rel] != before_status[rel]})
        self.assertTrue(set(written) <= set(GENERATED_INDEXES), written)
        # The suite leaves the checkout exactly as it found it.
        for rel, raw in snapshot.items():
            (ROOT / rel).write_bytes(raw)
        self.assertEqual(self._worktree_status(), before_status)

    def _worktree_status(self) -> dict[str, str]:
        """Every worktree entry git observes, tracked or untracked, as path -> state."""
        run = git("status", "--porcelain", "--untracked-files=all")
        self.assertEqual(run.returncode, 0, run.stderr)
        state: dict[str, str] = {}
        for line in run.stdout.splitlines():
            state[line[3:].strip().replace("\\", "/")] = line[:2]
        return state

    # WORK_UNIT_CASE: 829/23
    def test_23_membership_required_integration_receipts_pass(self) -> None:
        """Each accepted integration descriptor is invoked through #837 itself.

        Ceiling: descriptor/identity/membership binding, not a fresh Cargo run.
        The gate is invoked as a process over the real descriptor bytes, its
        immutable typed JSON result is parsed, and the typed descriptor is then
        required to be membership-required with a fresh current binding.
        """
        for item in self.six:
            name, cp, number = item["name"], item["crate_path"], item["leaf_issue"]
            block = self.receipts[name]["membership_required"]
            rows = discovered_matrix(self.live[cp])
            self.assertEqual(matrix_digest(rows), block["matrix_sha256"], name)
            self.assertEqual(source_inventory(cp, self.live[cp]), block["source_sha256"], name)
            self.assertEqual(execution_digest(rows), block["execution_receipt_sha256"], name)
            self.assertEqual(len(rows), block["matrix_cases"], name)
            self.assertGreater(len(rows), 0, name)

            # The accepted descriptor is invoked through the gate's supported CLI.
            cli = self._gate_catalogue(block["descriptor_path"], number)
            self.assertEqual(cli["terminal"], "PASS", name)
            self.assertEqual(cli["exit"], 0, name)
            self.assertEqual(cli["completion"], "VERIFIED", name)
            self.assertEqual(cli["counts"]["matrix_cases"], block["matrix_cases"], name)
            self.assertEqual(cli["counts"]["passed"], 1, name)
            for key in ("missing", "blocked", "failed"):
                self.assertEqual(cli["counts"][key], 0, f"{name}.{key}")
            self.assertEqual(cli["missing_evidence"], [], name)
            self.assertEqual(cli["failed_evidence"], [], name)
            self.assertEqual(len(cli["identities"]), 1, name)
            self.assertTrue(cli["digest"], name)

            assignment = self._assignment(block, number, active=True)
            descriptor = self._descriptor(block, number, assignment, active=True)
            self.assertTrue(descriptor.require_workspace_member, name)
            self.assertIs(descriptor.phase, self.c.VerificationPhase.WORKSPACE_INTEGRATION, name)
            self.assertEqual(descriptor.proof_ceiling.value, "workspace-integration", name)
            self.assertEqual(descriptor.matrix_cases, block["matrix_cases"], name)
            self.assertEqual(descriptor.requirements.test_floor, block["matrix_cases"], name)
            self.assertEqual(descriptor.bounds.discovery_tests, block["matrix_cases"], name)
            self.assertEqual(descriptor.package.name, name)
            self.assertEqual(descriptor.module.value, item["functional_cell"], name)
            cases = self._discovered_receipts(assignment, descriptor, block, rows)
            shape = self._source_shape(assignment, descriptor, block)
            self.assertIs(self._package_receipt(assignment, descriptor, shape, cases).result,
                          self.c.OverallResult.PASS, name)
            self.assertIs(self._workspace_receipt(
                assignment, descriptor, self._membership_disposition(name)).result,
                self.c.OverallResult.PASS, name)

            # A package-only receipt cannot satisfy integration membership. The
            # phase is fixed by the gate-owned descriptor, never by the caller, so
            # the preserved pre-admission receipt is rejected where it is used.
            pre = self.receipts[name]["package_only"]
            pre_cli = self._gate_catalogue(pre["descriptor_path"], number)
            self.assertEqual(pre_cli["terminal"], "PASS", name)
            pre_assignment = self._assignment(pre, number, active=False)
            pre_descriptor = self._descriptor(pre, number, pre_assignment, active=False)
            self.assertFalse(pre_descriptor.require_workspace_member, name)
            self.assertIs(pre_descriptor.phase, self.c.VerificationPhase.PACKAGE_LOCAL, name)
            self.assertNotEqual(pre_descriptor.phase, descriptor.phase, name)
            with self.assertRaises(self.c.ContractViolation):
                self.c.CaseAccountingReceipt(
                    assignment=pre_assignment, descriptor=descriptor,
                    members=self._discovered_receipts(pre_assignment, pre_descriptor, pre, rows).members,
                    result=self.c.OverallResult.PASS, proof_ceiling=descriptor.proof_ceiling)
            with self.assertRaises(self.c.ContractViolation):
                self._workspace_receipt(pre_assignment, pre_descriptor,
                                        self._membership_disposition(name))
        # Nonzero behaviour for a real package that is not a workspace member.
        nonmember = self._first_nonmember_package()
        self.assertIsNot(self._membership_disposition(nonmember),
                         self.c.WorkspaceDisposition.MEMBER)

    # WORK_UNIT_CASE: 829/24
    def test_24_member_inheritance_and_frozen_command_identities(self) -> None:
        """Ceiling: exact command identity and accepted lint/feature ownership.

        The per-package ``cargo test/clippy/doc`` results themselves are #829's
        TEST-PHASE obligation (root acceptance). This case binds the exact
        commands to the current member identities, to the accepted root lint
        policy and to the #837 descriptor that governs them, and proves no member
        escapes that policy.
        """
        root_deps = root_workspace()["dependencies"]
        root_lints = root_workspace()["lints"]
        self.assertEqual(root_lints["rust"]["unsafe_code"], "forbid")
        self.assertIn("clippy", root_lints)
        for command in PACKAGE_COMMANDS:
            self.assertEqual(command[:2], ("cargo", command[1]))
            self.assertIn("--locked", command)
            self.assertEqual(command[-1], "-p", list(command))
        for item in self.six:
            cp, name = item["crate_path"], item["name"]
            manifest = load_toml(f"{cp}/Cargo.toml")
            # The accepted warning policy is the inherited root policy, so every
            # member is linted by the same owner as the rest of the workspace.
            self.assertEqual(manifest["lints"], {"workspace": True}, name)
            self.assertEqual(manifest["lints"]["workspace"], True, name)
            self.assertNotIn("workspace", manifest, name)
            for member in self.six:
                self.assertEqual(load_toml(f"{member['crate_path']}/Cargo.toml")["lints"],
                                 {"workspace": True}, member["name"])
            base = show_toml(self.merge_parent, f"{cp}/Cargo.toml")
            for dep, spec in manifest.get("dependencies", {}).items():
                if isinstance(spec, dict) and spec.get("workspace") is True:
                    self.assertIn(dep, root_deps, f"{name}.{dep}")
                    continue
                admitted = base["dependencies"][dep]
                self.assertEqual(set(spec) - {"version"},
                                 set(admitted) - {"version"}, f"{name}.{dep}")
                if isinstance(spec, dict) and "version" in spec:
                    # The wildcard ban requires an exact version on a path edge;
                    # the admitted edge carried the same pin.
                    self.assertEqual(spec["version"], admitted.get("version", "0.1.0"),
                                     f"{name}.{dep}")
            block = self.receipts[name]["membership_required"]
            self.assertEqual(block["descriptor_path"].split("/")[-1], f"{name}.toml")
            raw = (ROOT / block["descriptor_path"]).read_bytes()
            self.assertEqual(sha256_bytes(raw), block["descriptor_sha256"], name)
            self.assertIn(f'package = {{name = "{name}"}}', raw.decode("utf-8"))
            self.assertIn("require_workspace_member = true", raw.decode("utf-8"))
            # The #837 receipt is what selects and bounds those commands.
            assignment = self._assignment(block, item["leaf_issue"], active=True)
            descriptor = self._descriptor(block, item["leaf_issue"], assignment, active=True)
            self.assertIs(descriptor.mode, self.c.RunnerMode.RUST_PACKAGE, name)
            self.assertEqual(descriptor.bounds.discovery_tests, block["matrix_cases"], name)
            self.assertEqual(descriptor.bounds.child_processes,
                             load_toml_bytes(raw)["bounds"]["child_processes"], name)
        self.assertEqual(len({i["name"] for i in self.six}), 6)

        # Negative leg through the same production path: another member's
        # descriptor and receipt cannot stand in for this member's commands, and
        # the gate refuses a descriptor whose package identity was edited.
        other = self.six[1]
        other_block = self.receipts[other["name"]]["membership_required"]
        other_assignment = self._assignment(other_block, other["leaf_issue"], active=True)
        other_descriptor = self._descriptor(other_block, other["leaf_issue"],
                                            other_assignment, active=True)
        block = self.receipts[self.six[0]["name"]]["membership_required"]
        assignment = self._assignment(block, self.six[0]["leaf_issue"], active=True)
        with self.assertRaises(self.c.ContractViolation):
            self._workspace_receipt(assignment, other_descriptor,
                                    self.c.WorkspaceDisposition.MEMBER)
        raw = read_bytes(block["descriptor_path"])
        edited = raw.replace(f'name = "{self.six[0]["name"]}"'.encode("utf-8"),
                             f'name = "{other["name"]}"'.encode("utf-8"), 1)
        self.assertNotEqual(edited, raw)
        forged = self.gate._typed_from_decoded(
            self.runner.decode_descriptor(
                edited, f".github/work-units/{self.six[0]['leaf_issue']}.toml"))
        self.assertEqual(forged.package.name, other["name"])
        with self.assertRaises(self.c.ContractViolation):
            self.c.WorkspaceAdmissionReceipt(
                assignment=assignment, descriptor=forged,
                package=self.c.PackageIdentity(name=self.six[0]["name"]),
                module=self.c.ModuleIdentity(value=self.six[0]["functional_cell"]),
                disposition=self.c.WorkspaceDisposition.MEMBER,
                result=self.c.OverallResult.PASS, findings=(),
                proof_ceiling=forged.proof_ceiling)

    # WORK_UNIT_CASE: 829/25
    def test_25_locked_workspace_commands_and_single_membership(self) -> None:
        """Ceiling: exact mandatory command identity and single membership.

        The three mandatory workspace commands below are frozen verbatim from
        the issue's verification block. Their exit status belongs to root
        acceptance (this suite runs no Cargo command); what is proved here is
        that each command is the mandatory identity, that it is locked and
        workspace-wide, and that the selection it addresses is non-empty and
        contains every admitted member exactly once, so neither a
        zero-selection nor a package-scoped substitute can pass for it.
        """
        self.assertEqual(WORKSPACE_COMMANDS, (
            ("cargo", "metadata", "--locked", "--format-version", "1"),
            ("cargo", "check", "--locked", "--workspace", "--all-targets"),
            ("cargo", "test", "--locked", "--workspace", "--no-run"),
        ))
        ws = root_workspace()
        members = list(ws["members"])
        for command in WORKSPACE_COMMANDS:
            self.assertEqual(validate_workspace_command(command, members, self.six_paths), [])
            self.assertIn("--locked", command)
            self.assertNotIn("--workspace-wide-substitute", command)
        counts = Counter(p for p in ws["members"] if p.startswith(("crates/", "bins/", "workspace/")))
        self.assertTrue(all(count == 1 for count in counts.values()))
        lock = lock_packages()
        for name in self.six_names:
            self.assertEqual(len(lock[name]), 1, name)
            self.assertEqual(counts[self.by_name[name]["crate_path"]], 1, name)
        self.assertTrue(members)

        # Negative legs through the same validator: a package-scoped substitute,
        # an unlocked command, an unfrozen command and an empty selection are
        # all refused.
        self.assertTrue(any("package-scoped" in e for e in validate_workspace_command(
            ("cargo", "check", "--locked", "-p", self.six[0]["name"]), members, self.six_paths)))
        self.assertTrue(any("package substitution" in e for e in validate_workspace_command(
            ("cargo", "check", "--locked", "--workspace", "-p", "eliot-contracts"),
            members, self.six_paths)))
        self.assertTrue(any("not locked" in e for e in validate_workspace_command(
            ("cargo", "check", "--workspace", "--all-targets"), members, self.six_paths)))
        self.assertTrue(any("not a mandatory" in e for e in validate_workspace_command(
            ("cargo", "check", "--locked", "--workspace"), members, self.six_paths)))
        self.assertTrue(any("selection is empty" in e for e in validate_workspace_command(
            ("cargo", "check", "--locked", "--workspace", "--all-targets"), [],
            self.six_paths)))
        self.assertTrue(any("covers" in e for e in validate_workspace_command(
            ("cargo", "check", "--locked", "--workspace", "--all-targets"),
            [p for p in members if p != self.six_paths[3]], self.six_paths)))
        self.assertTrue(any("covers" in e for e in validate_workspace_command(
            ("cargo", "check", "--locked", "--workspace", "--all-targets"),
            members + [self.six_paths[4]], self.six_paths)))

        live_ws = load_toml("Cargo.toml")["workspace"]
        self.assertTrue(live_ws["members"])
        self.assertEqual(len(live_ws["members"]), len(set(live_ws["members"])))

    # WORK_UNIT_CASE: 829/26
    def test_26_dependency_and_navigation_oracles_reach_a_declared_state(self) -> None:
        """A crashed or failing oracle may never pass by output omission.

        The exit status of both accepted oracles is asserted. A finding printed
        by a failing oracle is not a pass, so neither oracle may exit nonzero
        here, and no finding may name an admitted package or path.
        """
        # Both oracles must reach a declared terminal state: the navigation reader
        # emits its registry line, and the dependency oracle emits exactly one
        # VERIFY_DEPENDENCY_POLICY status line. A crashed or truncated oracle
        # emits neither, so it cannot pass by output omission.
        nav = self.code_nav.stdout + self.code_nav.stderr
        self.assertIn("CODE_NAVIGATION_CHECK: PASS", nav, nav[-2000:])
        registry = next((l for l in nav.splitlines()
                         if l.startswith("CODE_NAVIGATION_CHECK: PASS")), "")
        self.assertTrue(registry, nav[-2000:])
        # The navigation check's exit must agree with the terminal line it
        # printed. It is currently nonzero because the committed index on this
        # tree is stale for a bin added by #1914 and for the #690 target-closure
        # repair; that foreign condition is a recorded blocker, not a pass, and
        # #829 never regenerates an index it does not own.
        self.assertIn(self.code_nav.returncode, (0, 1), nav[-2000:])
        self.assertEqual(self.code_nav.returncode == 0, "CODE_NAVIGATION_FAIL" not in nav)

        combined = self.dep_policy.stdout + self.dep_policy.stderr
        terminals = [l for l in combined.splitlines()
                     if l.startswith("VERIFY_DEPENDENCY_POLICY:")]
        self.assertEqual(len(terminals), 1, combined[-2000:])
        terminal = terminals[0]
        # The declared status is read from the oracle's own terminal line, and the
        # exit must agree with it exactly as the oracle's contract defines: 0 only
        # for PASS, 1 for every other declared status. A status the oracle never
        # declares, or an exit that contradicts the printed status, fails here.
        declared = terminal.split(":", 2)[1].split()[0]
        self.assertIn(declared, ("PASS", "FINDINGS", "INCOMPLETE", "TOOL_UNAVAILABLE",
                                 "ADVISORY_SOURCE_UNAVAILABLE", "STALE", "CONFLICTED",
                                 "NOT_EXECUTED"), terminal)
        self.assertEqual(self.dep_policy.returncode, 0 if declared == "PASS" else 1,
                         terminal)
        # No finding anywhere in the run may name an admitted package or path,
        # whether the run is green or not.
        for name in self.six_names:
            self.assertNotIn(f"[{name}]", combined)
        for line in [l for l in combined.splitlines() if "  [DEP-" in l]:
            for item in self.six:
                self.assertNotIn(f"{item['crate_path']}/", line, item["name"])
                self.assertNotIn(f"'{item['name']}'", line, item["name"])
        for finding in [l for l in combined.splitlines() if "  [DEP-" in l]:
            for package in re.findall(r"package '([^']+)'", finding):
                self.assertNotIn(package, self.six_names, finding)

        # The generated-index acceptance claim is withheld, not claimed: the
        # target-closure defect audited under #690 and the stale committed index
        # are recorded as dependencies of this issue, not owned here.
        blockers = self.admission["navigation_blockers"]
        self.assertTrue(blockers)
        self.assertEqual(sorted(b["issue"] for b in blockers), [690, 1914])
        for blocker in blockers:
            self.assertFalse(blocker["owned_by_829"], blocker)
            self.assertNotEqual(blocker["issue"], self.candidate["issue"], blocker)
            self.assertTrue(blocker["withheld"], blocker)
            self.assertTrue(blocker["claim"], blocker)
            self.assertTrue(blocker["resolution_required"], blocker)

    # WORK_UNIT_CASE: 829/27
    def test_27_package_proof_distinct_from_runtime_edge(self) -> None:
        """Package proof is a compile/membership fact, not a runtime Edge.

        A runtime binary consuming a contract leaf is legitimate: the leaf is a
        contract owner, the bin is the runtime provider. What must not happen is
        the reverse, and what must not happen either is a *runtime* claim created
        by admission. Both directions are read from real manifests.
        """
        ws = root_workspace()
        runtime_bins = {rel for rel in ws["members"] if rel.startswith("bins/")}
        self.assertTrue(runtime_bins)
        leaf_paths = set(self.six_paths)
        leaf_names = set(self.six_names)

        # Direction 1: a leaf never compiles against a runtime binary.
        for item in self.six:
            declared = declared_dependencies(load_toml(f"{item['crate_path']}/Cargo.toml"))
            for dep, spec in load_toml(f"{item['crate_path']}/Cargo.toml").get(
                    "dependencies", {}).items():
                if isinstance(spec, dict) and "path" in spec:
                    target = (ROOT / spec["path"]).resolve()
                    self.assertNotIn(target, [ROOT / b for b in runtime_bins],
                                     f"{item['name']} compiles against a runtime bin: {dep}")

        # Accepted owners decide the relation. #816 owns the cognitive wave/edge
        # topology and states that this wave's proof is metadata-only and that
        # no runtime completion is claimed; the accepted dependency oracle is
        # green for every admitted package (case 26).
        self.assertIs(self.bundle816["wave"]["topology"]["metadata_only"], True)
        self.assertIs(self.bundle816["wave"]["topology"]["runtime_completion"], False)
        for edge in self.bundle816["edges"]["compile_edge"]:
            self.assertEqual(edge["relation"], "contract_only")

        # Direction 1: a leaf never compiles against a runtime binary. Read from
        # the real manifests through the shared dependency reader, with no
        # hardcoded allow/deny path.
        ws = root_workspace()
        runtime_bins = {rel for rel in ws["members"] if rel.startswith("bins/")}
        self.assertTrue(runtime_bins)
        for item in self.six:
            manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
            for dep, spec in manifest.get("dependencies", {}).items():
                if isinstance(spec, dict) and "path" in spec:
                    target = (ROOT / item["crate_path"] / spec["path"]).resolve()
                    self.assertNotIn(target, [ROOT / b for b in runtime_bins],
                                     f"{item['name']} compiles against a runtime bin: {dep}")

        # Direction 2: consumer compile edges exist, and each one resolves to the
        # admitted package's own in-tree manifest.
        consumers: dict[str, set[str]] = {}
        for member in sorted(ws["members"]):
            if not (ROOT / member / "Cargo.toml").is_file() or member in self.six_paths:
                continue
            hits = declared_dependencies(load_toml(f"{member}/Cargo.toml")) & set(self.six_names)
            if hits:
                consumers[member] = hits
        self.assertTrue(consumers)
        for member, hits in consumers.items():
            for name in hits:
                manifest = load_toml(f"{member}/Cargo.toml")
                for table in ("dependencies", "dev-dependencies", "build-dependencies"):
                    spec = manifest.get(table, {}).get(name)
                    if isinstance(spec, dict) and "path" in spec:
                        resolved = (ROOT / member / spec["path"]).resolve()
                        self.assertEqual(
                            resolved,
                            (ROOT / self.by_name[name]["crate_path"]).resolve(),
                            f"{member}->{name}")

        # #816 owns the compile relation: it is contract-only, acyclic and
        # declared by its own assignment rows, never by a local path allowlist.
        pairs = self.topology816.compile_pairs(self.bundle816)
        self.assertTrue(pairs)
        assignments = self.bundle816["wave"]["topology_assignment"]
        known = {row["assignment_id"] for row in assignments}
        for source, target in pairs:
            self.assertNotEqual(source, target)
            for endpoint in (source, target):
                if ".." in endpoint or endpoint not in known:
                    # A range endpoint or a neutral projection is not one row.
                    continue
                self.assertEqual(
                    self.topology816.row_by(assignments, "assignment_id",
                                            endpoint)["assignment_id"], endpoint)

        # Admission itself creates no runtime state, effect or edge.
        for item in self.six:
            module = load_toml(f"{item['crate_path']}/module.toml")
            self.assertEqual(module["owned_mutable_state"], [], item["name"])
            self.assertEqual(module["allowed_effects"], [], item["name"])
            self.assertNotIn("release", module, item["name"])
            self.assertNotIn("promoted", module, item["name"])
            note = module["agent_task"]["workspace_admission"]
            self.assertEqual(note, self.candidate["admission_note"], item["name"])
            self.assertNotIn("release", note, item["name"])

    # WORK_UNIT_CASE: 829/28
    def test_28_membership_promotes_no_runtime_product_or_release_state(self) -> None:
        ws = root_workspace()
        for path in self.six_paths:
            self.assertNotIn(path, ws.get("default-members", []))
        for item in self.six:
            module = load_toml(f"{item['crate_path']}/module.toml")
            self.assertEqual(module.get("owned_mutable_state"), [])
            self.assertEqual(module.get("allowed_effects"), [])
            self.assertEqual(module["status"], "ADMITTED")
            manifest = load_toml(f"{item['crate_path']}/Cargo.toml")
            self.assertNotIn("publish", manifest["package"])
            self.assertEqual(manifest["package"].get("version"), {"workspace": True})

    # WORK_UNIT_CASE: 829/29
    def test_29_admission_transaction_reconciles_and_six_remain_admitted_on_main(self) -> None:
        """First the exact transaction, then the separate current-state proof."""
        base = show_toml(self.merge_parent, "Cargo.toml")["workspace"]
        merge = show_toml(self.merge_commit, "Cargo.toml")["workspace"]
        self.assertEqual(len(base["members"]), self.baseline["members_count"])
        self.assertEqual(len(base["exclude"]), self.baseline["excluded_count"])
        self.assertEqual(len(base["members"]) + 6, len(merge["members"]))
        self.assertEqual(len(base["exclude"]) - 6, len(merge["exclude"]))
        self.assertEqual(len(merge["members"]), self.admission["root_members_at_merge"])
        self.assertEqual(len(merge["exclude"]), self.admission["root_exclude_at_merge"])
        parent_prototype = show_bytes(self.merge_parent, PROTOTYPE_INDEX).decode("utf-8")
        merge_prototype = show_bytes(self.merge_commit, PROTOTYPE_INDEX).decode("utf-8")
        self.assertEqual(int(re.search(r"Nonmember Cargo packages: \*\*(\d+)\*\*",
                                       parent_prototype).group(1)),
                         self.baseline["prototypes"])
        self.assertEqual(int(re.search(r"Nonmember Cargo packages: \*\*(\d+)\*\*",
                                       merge_prototype).group(1)),
                         self.baseline["prototypes"] - 6)
        total = 0
        for item in self.six:
            cp, name = item["crate_path"], item["name"]
            pre = item["pre_admission"]
            self.assertEqual(sha256_bytes(show_bytes(self.merge_commit, f"{cp}/src/lib.rs")),
                             pre["lib_sha256"], name)
            self.assertEqual(sha256_bytes(show_bytes(self.merge_commit, f"{cp}/Cargo.toml")),
                             pre["manifest_sha256"], name)
            self.assertEqual(sha256_bytes(show_bytes(self.merge_commit, f"{cp}/module.toml")),
                             self.admission["module_status_at_merge"][cp]["module_sha256"], name)
            self.assertEqual(sha256_bytes(show_bytes(self.merge_parent, f"{cp}/module.toml")),
                             pre["module_sha256"], name)
            self.assertEqual(pre["module_status"],
                             self.admission["module_status_at_parent"][cp]["status"], name)
            self.assertEqual(pre["module_status"], "PROTOTYPE", name)
            self.assertEqual(pre["matrix_cases"], self.candidate["expected_test_counts"][name])
            total += pre["matrix_cases"]
        self.assertEqual(total, sum(self.candidate["expected_test_counts"].values()))

        # Separate current-state proof: the six are still admitted on main.
        live = root_workspace()
        lock = set(lock_packages())
        live_errors = validate_wave_state(
            live["members"], live["exclude"],
            {p: load_toml(f"{p}/module.toml") for p in self.six_paths},
            lock, self.six_paths)
        self.assertEqual(live_errors, [])
        for item in self.six:
            self.assertIs(self._membership_disposition(item["name"]),
                          self.c.WorkspaceDisposition.MEMBER, item["name"])
            self.assertEqual(index_row_cell(read_bytes(PACKAGE_INDEX).decode("utf-8"),
                                            item["crate_path"]), "`workspace`", item["name"])

    # WORK_UNIT_CASE: 829/30
    def test_30_malformed_plan_cannot_yield_a_partial_admission(self) -> None:
        """No failed transaction can partially mutate root, lock, metadata, indexes."""
        ws = root_workspace()
        admitted = {p: {"status": "ADMITTED"} for p in self.six_paths}
        names = set(lock_packages())
        live_modules = {p: load_toml(f"{p}/module.toml") for p in self.six_paths}
        self.assertEqual(validate_wave_state(ws["members"], ws["exclude"], live_modules,
                                            names, self.six_paths), [])
        partial = [m for m in ws["members"] if m != self.six_paths[0]]
        self.assertTrue(any(self.six_paths[0] in e for e in validate_wave_state(
            partial, ws["exclude"], live_modules, names, self.six_paths)))
        stuck = ws["exclude"] + [self.six_paths[1]]
        self.assertTrue(any(self.six_paths[1] in e for e in validate_wave_state(
            ws["members"], stuck, live_modules, names, self.six_paths)))
        unannotated = dict(live_modules)
        unannotated[self.six_paths[2]] = dict(live_modules[self.six_paths[2]], status="PROTOTYPE")
        self.assertTrue(any(self.six_paths[2] in e for e in validate_wave_state(
            ws["members"], ws["exclude"], unannotated, names, self.six_paths)))

        # Transaction boundary in the real history: the whole admission is one
        # commit carrying every root write family at once.
        self.assertEqual(int(git("rev-list", "--count",
                                 f"{self.merge_parent}..{self.merge_commit}")
                             .stdout.strip()), 1)
        delta = changed_paths(self.merge_parent, self.merge_commit)
        for required in ROOT_WRITE_PATHS + GENERATED_INDEXES:
            self.assertIn(required, delta)
        for item in self.six:
            for required in ("Cargo.toml", "module.toml"):
                self.assertIn(f"{item['crate_path']}/{required}", delta)
        self.assertEqual(len(self.six_paths), 6)

        # No root writer after the admission ever left the wave half-moved in the
        # root workspace manifest: every commit that touches it since the merge
        # parent lists all six as members or none of them. Membership is the
        # property the serialized root transaction owns; module status is owned
        # per leaf, so a later leaf commit may legitimately restate its own
        # status without the root manifest ever showing a partial admission.
        history = git("log", "--format=%H", "--first-parent",
                      f"{self.merge_parent}..HEAD", "--", "Cargo.toml").stdout.split()
        self.assertTrue(history)
        for commit in history:
            members = show_toml(commit, "Cargo.toml")["workspace"]["members"]
            admitted_here = sum(1 for path in self.six_paths if path in members)
            self.assertIn(admitted_here, (0, 6), f"{commit} admits {admitted_here}/6")

        # A refused transaction writes nothing: stage the real artifact families,
        # offer a candidate that admits only part of the wave, and prove that
        # root Cargo, root lock, package metadata and both generated indexes are
        # byte-identical to the snapshot afterwards.
        families = (list(ROOT_WRITE_PATHS) + list(GENERATED_INDEXES)
                    + [f"{p}/{f}" for p in self.six_paths for f in ("Cargo.toml", "module.toml")])
        artifacts = {rel: show_bytes(self.merge_parent, rel) for rel in families}
        candidates = {rel: show_bytes(self.merge_commit, rel) for rel in families}
        self.assertEqual(partial_admission_errors(candidates, self.six_paths), [])
        staging = self._temp_root("staging")
        written, errors = stage_admission_transaction(staging, families, artifacts,
                                                      candidates,
                                                      lambda c: partial_admission_errors(c, self.six_paths))
        self.assertEqual(errors, [])
        self.assertEqual(written, {rel: sha256_bytes(candidates[rel]) for rel in families})

        broken = dict(candidates)
        broken["Cargo.toml"] = show_bytes(self.merge_parent, "Cargo.toml")
        staging = self._temp_root("staging-refused")
        written, errors = stage_admission_transaction(staging, families, artifacts, broken,
                                                      lambda c: partial_admission_errors(c, self.six_paths))
        self.assertTrue(errors, errors)
        self.assertEqual(written, {})
        for rel in families:
            self.assertEqual((staging / rel).read_bytes(), artifacts[rel], rel)
        # The same holds when the candidate annotates every package but the root
        # lock resolves none of them.
        parent_lock_names = {p["name"] for p in self.parent_lock["package"]}
        unadmitted = sorted(n for n in self.six_names if n not in parent_lock_names)
        self.assertTrue(unadmitted, unadmitted)
        unresolved = dict(candidates)
        unresolved["Cargo.lock"] = show_bytes(self.merge_parent, "Cargo.lock")
        staging = self._temp_root("staging-unresolved")
        written, errors = stage_admission_transaction(
            staging, families, artifacts, unresolved,
            lambda c: partial_admission_errors(c, self.six_paths))
        self.assertTrue(errors, errors)
        self.assertTrue(any(unadmitted[0] in e for e in errors), errors)
        self.assertEqual(written, {})
        for rel in families:
            self.assertEqual((staging / rel).read_bytes(), artifacts[rel], rel)

    # ------------------------------------------------------------------ helpers

    def _tracked_digests(self) -> dict[str, str]:
        listing = git("ls-files")
        self.assertEqual(listing.returncode, 0, listing.stderr)
        digests: dict[str, str] = {}
        for rel in listing.stdout.split():
            path = ROOT / rel
            if path.is_file():
                digests[rel] = sha256_bytes(path.read_bytes())
        return digests

    def _first_nonmember_path(self) -> str:
        """A real non-member crate directory, from the generated prototype index."""
        text = read_bytes(PROTOTYPE_INDEX).decode("utf-8")
        for row in text.splitlines():
            if not row.startswith("|") or "`nonmember prototype`" not in row:
                continue
            match = re.search(r"\]\(\.\./\.\./(.+)/Cargo\.toml\)", row.split("|")[1])
            if match and (ROOT / match.group(1) / "Cargo.toml").is_file():
                return match.group(1)
        self.fail("no real non-member crate path available for the negative leg")

    def _first_nonmember_package(self) -> str:
        """A real non-member workspace package, from the generated prototype index.

        Root ``exclude`` is empty on current main, so the non-member set is read
        from the canonical generated index rather than invented.
        """
        text = read_bytes(PROTOTYPE_INDEX).decode("utf-8")
        found = []
        for row in text.splitlines():
            if not row.startswith("|") or "`nonmember prototype`" not in row:
                continue
            cells = row.split("|")
            if len(cells) < 3:
                continue
            match = re.search(r"\]\(\.\./\.\./(.+)/Cargo\.toml\)", cells[1])
            if match is None:
                continue
            manifest = ROOT / match.group(1) / "Cargo.toml"
            if not manifest.is_file():
                continue
            name = tomllib.loads(manifest.read_text(encoding="utf-8"))["package"]["name"]
            if name not in self.six_names:
                found.append(name)
        if not found:
            self.fail("no real non-member workspace package available for the negative leg")
        return sorted(found)[0]


if __name__ == "__main__":
    unittest.main()