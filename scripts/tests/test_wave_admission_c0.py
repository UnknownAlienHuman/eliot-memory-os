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

Activation/prerequisite cases (1, 3, 4, 6) consume accepted owner evidence
instead of asserting it:

- cases 1 and 3 read each leaf's #837 descriptor from
  ``wave-c0/candidate.json`` and run it through the accepted gate's own
  ``scripts/work_unit_gate/descriptor_runner.py::decode_descriptor`` /
  ``::resolve_package_manifest``, so leaf assignment, proof receipt,
  freshness and writer authority are OBSERVED, not hand-written. Both
  negative legs of case 1 (a foreign descriptor field, a matrix count above
  the declared test floor) enter that same gate and are refused by it;
- case 3 reads leaf state at the admission merge parent
  (``pre_admission.base_commit``) -- the state that existed BEFORE the #829
  turn. ``status = ADMITTED`` is written BY the admission and can never be
  its own prerequisite. Its negatives re-observe through the same owner
  paths: a descriptor whose bound body digest no longer matches its source,
  and a leaf commit that is not an ancestor of that parent;
- case 4 DERIVES every proof field from the observed subprocess result and
  the descriptor binding; nothing about the outcome is written by the test
  that ran the command. Its negatives re-enter ``derive_proof_receipt`` with
  real ``CompletedProcess`` results and real descriptor bindings;
- case 6 checks the writer rule against an INDEPENDENT expected set -- the
  write seams actually declared for the unit -- never against a copy of the
  list the validator then checks.

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
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
from code_navigation_lib.registry import build_registry
# Accepted #837 evidence API, consumed exactly as the sibling wave suites
# (scripts/tests/test_wave_admission_d0.py:557) consume it. This is the real
# owner path; no second evidence mechanism is defined here.
from scripts.work_unit_gate.descriptor_runner import (
    RunnerInputError, decode_descriptor, resolve_package_manifest,
)

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


def validate_activation(evidence: dict[str, list[str]]) -> tuple[bool, list[str]]:
    """Activation gate over OBSERVED prerequisite evidence.

    ``evidence`` maps prerequisite name -> list of human-readable defects
    found by its owner path. An empty defect list means that prerequisite's
    real evidence was consumed and found complete; a non-empty list blocks
    activation. Callers must build these records from repository bytes, the
    accepted #837 gate API and git, never from a literal they choose.
    """
    missing = sorted(name for name, defects in evidence.items() if defects)
    if missing:
        return False, [f"prerequisite incomplete: {name}: {d}"
                       for name in missing for d in evidence[name]]
    return True, []


def validate_leaf_evidence(entries: list[dict]) -> list[str]:
    """Leaf-evidence shape check over OBSERVED per-leaf records.

    Every field below must be produced by ``observe_leaf_evidence`` from
    pre-admission repository state (see ``test_03``). The ``accepted`` field
    is checked against the PRE-admission module status the gate owner
    (``candidate.json`` ``pre_admission.module_status``), never against
    ``ADMITTED`` -- which the admission itself writes and which therefore
    cannot be its own prerequisite.
    """
    errors: list[str] = []
    for entry in entries:
        tag = entry.get("name", "?")
        if not entry.get("manifest_present"):
            errors.append(f"missing manifest: {tag}")
        if not entry.get("router_present"):
            errors.append(f"missing router: {tag}")
        if not entry.get("merged"):
            errors.append(f"unmerged leaf: {tag}")
        if entry.get("status") != entry.get("expected_pre_admission_status"):
            errors.append(
                f"unaccepted leaf: {tag}: pre-admission status "
                f"{entry.get('status')!r} != expected "
                f"{entry.get('expected_pre_admission_status')!r}")
        if not entry.get("descriptor_accepted"):
            errors.append(f"descriptor not accepted by #837 gate: {tag}")
    return errors


def validate_proof(receipts: list[dict]) -> list[str]:
    """Package-proof check over receipts DERIVED from the observed run.

    A receipt is built by ``derive_proof_receipt`` from a real
    ``CompletedProcess`` and its #837 descriptor binding. Nothing here is
    authored by the test that launched the command: ``exit_code`` is the
    subprocess returncode, ``passed``/``failed`` are parsed from its output,
    ``partial`` is passed != the descriptor's ``matrix_cases``, and
    ``stale`` is the descriptor's bound digests disagreeing with current
    source bytes. The ``outcome`` label is recomputed here from those facts.
    """
    errors: list[str] = []
    for receipt in receipts:
        tag = receipt.get("name", "?")
        expected = derive_outcome(receipt)
        if receipt.get("outcome") != expected:
            errors.append(
                f"proof label not derived from run: {tag}: "
                f"{receipt.get('outcome')!r} != {expected!r}")
        if expected != "EXECUTED_PASS":
            errors.append(f"proof not executed-pass: {tag}: {expected}")
        if receipt.get("partial"):
            errors.append(
                f"partial proof: {tag}: {receipt.get('passed')} of "
                f"{receipt.get('required_cases')}")
        if receipt.get("stale"):
            errors.append(
                f"stale proof: {tag}: {receipt.get('stale_reason')}")
    return errors


def derive_outcome(receipt: dict) -> str:
    """Outcome label DERIVED from the observed subprocess, never authored."""
    if receipt.get("stale"):
        return "STALE"
    if receipt.get("exit_code") != 0:
        return "EXECUTED_FAIL"
    if receipt.get("failed"):
        return "EXECUTED_FAIL"
    if receipt.get("partial"):
        return "EXECUTED_PARTIAL"
    if not receipt.get("passed"):
        return "EXECUTED_EMPTY"
    return "EXECUTED_PASS"


def derive_proof_receipt(item: dict, run: subprocess.CompletedProcess,
                         decoded: dict) -> dict:
    """Build one proof receipt from the real subprocess + descriptor binding.

    ``decoded`` is the descriptor as the accepted #837 gate decoded it. Every
    field is a measurement of something that happened, so the caller cannot
    pass its own verdict in.
    """
    combined = run.stdout + run.stderr
    passed = sum(int(m) for m in re.findall(r"(\d+) passed", combined))
    failed = sum(int(m) for m in re.findall(r"(\d+) failed", combined))
    ignored = sum(int(m) for m in re.findall(r"(\d+) ignored", combined))
    required = decoded["matrix_cases"]
    body_now = sha256_bytes(read_bytes(f"{item['crate_path']}/src/lib.rs"))
    matrix_now = matrix_sha_of(item)
    stale_reasons = []
    if body_now != decoded["body_sha256"]:
        stale_reasons.append(f"body digest {body_now} != descriptor {decoded['body_sha256']}")
    if matrix_now != decoded["matrix_sha256"]:
        stale_reasons.append(
            f"matrix digest {matrix_now} != descriptor {decoded['matrix_sha256']}")
    run_reasons = []
    if run.returncode != 0:
        run_reasons.append(f"cargo test exit {run.returncode}")
    receipt = {
        "name": item["name"],
        "exit_code": run.returncode,
        "passed": passed,
        "failed": failed,
        "ignored": ignored,
        "required_cases": required,
        "body_sha256": body_now,
        "matrix_sha256": matrix_now,
        "stale": bool(stale_reasons),
        "stale_reason": "; ".join(stale_reasons),
        "run_reason": "; ".join(run_reasons),
    }
    receipt["partial"] = passed != required or bool(ignored)
    receipt["outcome"] = derive_outcome(receipt)
    return receipt


def matrix_sha_of(item: dict) -> str:
    """Live matrix digest of a leaf's test roots, as the descriptor binds them.

    Same definition the sibling suites use: one test file's bytes, or the
    concatenated bytes of the sorted test files under a test directory.
    """
    root = ROOT / item["test_root"]
    if root.is_file():
        return sha256_bytes(root.read_bytes())
    digest = hashlib.sha256()
    for rs in sorted(root.rglob("*.rs")):
        digest.update(rs.read_bytes())
    return digest.hexdigest()


def descriptor_bytes(item: dict) -> bytes:
    """Frozen #837 descriptor for one leaf, as owned by candidate.json."""
    return item["descriptor_toml"].encode("utf-8")


def descriptor_name(item: dict) -> str:
    """Registered repository-relative descriptor path for one leaf."""
    return f".github/work-units/{item['leaf_issue']}.toml"


def accept_descriptor(item: dict) -> dict:
    """Run a leaf's descriptor through the accepted #837 gate.

    Returns the decoded descriptor as the gate itself decoded it. Raises
    ``RunnerInputError`` if the frozen evidence is not accepted.
    """
    return decode_descriptor(descriptor_bytes(item), descriptor_name(item))


def descriptor_defects(item: dict) -> list[str]:
    """Defects in a leaf's frozen #837 descriptor, per the real gate.

    The gate rejects with a stable redacted code; that code is the defect.
    The identity/membership checks below additionally prove the decoded
    descriptor still binds THIS leaf's package, module and digests.
    """
    try:
        decoded = accept_descriptor(item)
    except RunnerInputError as exc:
        return [f"descriptor rejected by #837 gate: {exc}"]
    defects = []
    if decoded["issue"]["number"] != item["leaf_issue"]:
        defects.append(
            f"descriptor issue {decoded['issue']['number']} != leaf "
            f"{item['leaf_issue']}")
    if decoded["identity"]["value"] != f"work-unit-{item['leaf_issue']}":
        defects.append(f"descriptor identity {decoded['identity']['value']!r}")
    if decoded["package"] != {"name": item["name"]}:
        defects.append(f"descriptor package {decoded['package']} != {item['name']}")
    if decoded["module"]["value"] != item["functional_cell"]:
        defects.append(
            f"descriptor module {decoded['module']['value']!r} != "
            f"{item['functional_cell']!r}")
    if decoded["unit"]["value"] != item["wave"]:
        defects.append(
            f"descriptor unit {decoded['unit']['value']!r} != {item['wave']!r}")
    if decoded["require_workspace_member"] is not True:
        defects.append("descriptor does not require workspace membership")
    if decoded["proof_ceiling"]["value"] != "workspace-integration":
        defects.append(
            f"proof ceiling {decoded['proof_ceiling']['value']!r} is not "
            f"workspace-integration")
    if decoded["body_sha256"] != item["lib_sha256"]:
        defects.append("descriptor body digest is not the leaf body digest")
    if decoded["matrix_sha256"] != item["matrix_sha256"]:
        defects.append("descriptor matrix digest is not the leaf matrix digest")
    if decoded["requirements"]["test_floor"] < decoded["matrix_cases"]:
        defects.append("descriptor test floor omits matrix cases")
    for root in decoded["source_roots"] + decoded["test_roots"]:
        if not (ROOT / root["value"]).exists():
            defects.append(f"descriptor root missing on disk: {root['value']}")
    return defects


def membership_binding(item: dict, metadata: dict) -> dict:
    """Bind one leaf package through the accepted gate's membership path.

    ``resolve_package_manifest`` classifies the package from real cargo
    metadata entries and REJECTS a membership-required descriptor whose
    package is not an actual workspace member. That rejection is the
    membership proof, produced by the owner path rather than asserted.
    """
    return resolve_package_manifest(
        package_name=item["name"],
        metadata_packages=cargo_metadata_packages(metadata),
        require_workspace_member=True,
    )


def cargo_metadata_packages(metadata: dict) -> list[dict]:
    """Classify every in-repository cargo package into the gate's kinds.

    Derivation: a package listed in ``metadata.workspace_members`` or
    sitting directly under a root ``members`` entry is a member; one whose
    manifest sits directly under a root ``exclude`` entry is excluded; one
    that declares its own ``[workspace]`` table is standalone; anything else
    -- including every registry/remote dependency, which has no repository-
    relative manifest path at all -- is unavailable. This feeds the gate's
    ``resolve_package_manifest`` the closed entry shape it requires.

    Only repository-local packages get an entry: the gate's path contract is
    repository-relative, and registry manifests (``~/.cargo/registry/...``)
    have no such form.
    """
    ws = root_workspace()
    members = set(ws.get("members", []))
    excluded = set(ws.get("exclude", []))
    member_ids = set(metadata["workspace_members"])
    prefix = ROOT.as_posix() + "/"
    entries = []
    for pkg in metadata["packages"]:
        manifest_abs = pkg["manifest_path"].replace("\\", "/")
        if not manifest_abs.startswith(prefix):
            continue
        manifest_rel = manifest_abs[len(prefix):]
        parent = manifest_rel.rsplit("/", 1)[0]
        if pkg["id"] in member_ids or parent in members:
            kind = "member"
        elif parent in excluded:
            kind = "excluded"
        elif re.search(r"(?m)^\s*\[workspace\]",
                       read_bytes(manifest_rel).decode("utf-8", "replace")):
            kind = "standalone"
        else:
            kind = "unavailable"
        entries.append({"name": pkg["name"], "manifest_rel": manifest_rel,
                        "member_kind": kind})
    return entries


def observe_leaf_evidence(item: dict, candidate: dict) -> dict:
    """Derive one leaf's readiness record from PRE-admission state only.

    Every field is measured: manifest/router presence from the admission
    parent's tree, ``merged`` from git ancestry of that parent's own leaf
    commits, ``status`` from the module.toml AT that parent, and
    ``descriptor_accepted`` from the real #837 gate. The post-admission
    ``ADMITTED`` status is never read here.
    """
    parent = candidate["pre_admission"]["base_commit"]
    manifest = git("show", f"{parent}:{item['crate_path']}/Cargo.toml")
    router = git("show", f"{parent}:{item['crate_path']}/module.toml")
    status = None
    if router.returncode == 0:
        status = tomllib.loads(router.stdout).get("status")
    leaf_commits = candidate["leaf_commits"][item["name"]]
    merged = bool(leaf_commits)
    for sha in leaf_commits:
        probe = git("merge-base", "--is-ancestor", sha, parent)
        merged = merged and probe.returncode == 0
    defects = descriptor_defects(item)
    return {
        "name": item["name"],
        "manifest_present": manifest.returncode == 0,
        "router_present": router.returncode == 0,
        "merged": merged,
        "leaf_commits": list(leaf_commits),
        "status": status,
        "expected_pre_admission_status":
            candidate["pre_admission"]["module_status"],
        "descriptor_accepted": not defects,
        "descriptor_defects": defects,
        "observed_at": parent,
    }


def blocking_challenges(six_names: set[str]) -> list[dict]:
    """Open challenge entries naming any of the six, read from the owner file.

    Same closed read the sibling cases perform against
    ``crates/smart/cognitive-contract-challenges.toml``; an entry blocks only
    when its status is OPEN (``OPEN_*``) AND its ``needed_by`` names one of
    the six admitted packages.
    """
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
            current["needed_by"] = json.loads(
                line.split("=", 1)[1].strip().replace("'", '"'))
        elif current is not None and line.startswith("id ="):
            current["id"] = line.split("=", 1)[1].strip().strip('"')
    return [e for e in open_entries
            if str(e.get("status", "")).startswith("OPEN")
            and six_names & set(e.get("needed_by", []))]


def activation_evidence(candidate: dict, six: list[dict], metadata: dict,
                        proof_receipts: dict[str, dict],
                        leaf_records: list[dict]) -> dict[str, list[str]]:
    """Build C1's prerequisite record from owner paths, not from literals.

    Each prerequisite names the accepted evidence it consumes and returns
    its observed defects (empty when satisfied). Every input is a real
    observation produced above; nothing here is a chosen verdict.
    """
    six_names = {item["name"] for item in six}
    membership_defects = []
    for item in six:
        try:
            binding = membership_binding(item, metadata)
        except RunnerInputError as exc:
            membership_defects.append(f"{item['name']}: {exc}")
            continue
        # The gate returned a binding; its kind must itself say "member",
        # otherwise a membership-required descriptor would be admitted on a
        # merely buildable package.
        if binding["member_kind"] != "member":
            membership_defects.append(
                f"{item['name']}: bound as {binding['member_kind']}")
    leaf_defects = [d for record in leaf_records
                    for d in record["descriptor_defects"]]
    proof_defects = [e for item in six
                     for e in validate_proof([proof_receipts[item["name"]]])]
    challenge_blockers = blocking_challenges(six_names)
    writer_defects = validate_single_writer(
        observed_writers=declared_write_seams(candidate),
        expected_writers=authorized_write_seams(candidate))
    plan_defects = []
    head = git("rev-parse", "HEAD")
    if head.returncode != 0:
        plan_defects.append("HEAD is not resolvable")
    else:
        base = git("merge-base", "--is-ancestor",
                   candidate["admission_parent_commit"], head.stdout.strip())
        if base.returncode != 0:
            plan_defects.append(
                "admission parent is not an ancestor of HEAD")
    return {
        "leaf-evidence": leaf_defects,
        "package-membership": membership_defects,
        "package-proof": proof_defects,
        "challenges-clear": validate_challenges(challenge_blockers, six_names),
        "single-writer": writer_defects,
        "plan-current": plan_defects,
    }


def declared_write_seams(candidate: dict) -> set[str]:
    """Who actually holds the root/lock/index lane, per the owner path.

    The lane holder is named by the root manifest's serialized-turn comment
    AT the admission commit, and that turn is real only if it actually wrote
    the root/lock/index families. Derived from git, not from a literal.
    """
    merge = candidate["admission_merge_commit"]
    parent = candidate["admission_parent_commit"]
    comment = git("show", f"{merge}:Cargo.toml")
    if comment.returncode != 0:
        return set()
    unit = None
    for line in comment.stdout.splitlines():
        if "single serialized root turn" in line:
            found = re.search(r"/([A-Za-z0-9\-]+)\)", line)
            if found:
                unit = found.group(1)
    if unit is None:
        return set()
    changed = set(git("diff", "--name-only", parent, merge).stdout.split())
    root_families = set(candidate["single_writer_scope"])
    # The named turn must have actually written the root families; otherwise
    # it never held the lane and grants no authority.
    if not root_families <= changed:
        return set()
    return {unit}


def authorized_write_seams(candidate: dict) -> set[str]:
    """Independently derived expectation of who may hold the root lane.

    Built from the frozen issue-owned candidate record's ``single_writer``,
    a different owner path than ``declared_write_seams`` reads. Neither is a
    copy of the list the validator checks.
    """
    return {candidate["single_writer"]}


def validate_challenges(open_entries: list[dict], six_names: set[str]) -> list[str]:
    errors: list[str] = []
    for entry in open_entries:
        if six_names & set(entry.get("needed_by", [])):
            errors.append(f"unresolved challenge {entry.get('id')} blocks wave")
    return errors


def validate_single_writer(observed_writers: set[str],
                           expected_writers: set[str]) -> list[str]:
    """Single-writer rule checked against an INDEPENDENT expected set.

    ``observed_writers`` is what the owner paths actually declare (derived
    from the root manifest's serialized-turn comment and the frozen write
    scope). ``expected_writers`` is a separately-derived set naming who is
    authorized to hold the root/lock/index lane. Authority is therefore
    granted by the evidence, never by a string list the validator is then
    handed as its own input.
    """
    errors: list[str] = []
    extra = sorted(observed_writers - expected_writers)
    if extra:
        errors.append(f"unauthorized root/lock/index writer: {extra}")
    missing = sorted(expected_writers - observed_writers)
    if missing:
        errors.append(f"authorized writer did not take the lane: {missing}")
    if len(observed_writers) != 1:
        errors.append(
            f"expected exactly one root/lock/index writer, found "
            f"{len(observed_writers)}: {sorted(observed_writers)}")
    return errors


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
        # Proof receipts are DERIVED from each real cargo run bound to its
        # accepted #837 descriptor (see derive_proof_receipt). Nothing about
        # the outcome is written by the test that launched the command.
        cls.proof_receipts = {
            item["name"]: derive_proof_receipt(
                item, cls.test_runs[item["name"]], accept_descriptor(item))
            for item in cls.six
        }
        # Per-leaf records observed from the PRE-admission tree (test 3).
        cls.leaf_records = [observe_leaf_evidence(item, cls.candidate)
                            for item in cls.six]

    def _evidence(self) -> dict[str, list[str]]:
        """Every C1 prerequisite, recomputed from the observed class state."""
        return activation_evidence(self.candidate, self.six, self.metadata,
                                   self.proof_receipts, self.leaf_records)

    # WORK_UNIT_CASE: 829/1
    def test_01_activation_refuses_incomplete_prerequisites(self) -> None:
        # Activation consumes OBSERVED evidence from each owner path: the
        # #837 descriptor gate, the gate's membership binding, the derived
        # package proof, the challenge file, the write-lane evidence and the
        # plan's git ancestry. No literal booleans grant authority.
        evidence = self._evidence()
        self.assertEqual(sorted(evidence), [
            "challenges-clear", "leaf-evidence", "package-membership",
            "package-proof", "plan-current", "single-writer"])
        self.assertTrue(all(not defects for defects in evidence.values()), evidence)
        granted, errors = validate_activation(evidence)
        self.assertTrue(granted)
        self.assertEqual(errors, [])
        # Each prerequisite genuinely blocked is refused, and its OWN observed
        # defect message appears -- the negative enters the same validator.
        for prereq in evidence:
            blocked = dict(evidence)
            blocked[prereq] = [f"observed defect in {prereq}"]
            granted, errors = validate_activation(blocked)
            self.assertFalse(granted, prereq)
            self.assertTrue(any(prereq in e for e in errors), prereq)
        # The membership prerequisite is real: the accepted gate itself
        # refuses a package that is not a workspace member under the
        # membership-required mode every one of these six descriptors sets.
        # The witness is the FIRST still-excluded package in the real root
        # manifest -- nothing about it is written here -- and the
        # classification it is checked against is the SAME one C1 consumed.
        classified = cargo_metadata_packages(self.metadata)
        excluded_witness = root_workspace()["exclude"][0]
        witness_name = load_toml(f"{excluded_witness}/Cargo.toml")["package"]["name"]
        with self.assertRaises(RunnerInputError) as ctx:
            resolve_package_manifest(
                package_name=witness_name,
                metadata_packages=classified,
                require_workspace_member=True)
        self.assertEqual(str(ctx.exception), "WORKSPACE_MEMBER_REQUIRED")
        # The classification is a measurement, not a label: the same gate over
        # the same list returns "member" for the six, which is why C1's
        # package-membership prerequisite was empty.
        for item in self.six:
            self.assertEqual(membership_binding(item, self.metadata)["member_kind"],
                             "member", item["name"])
        # The manifests/routers the evidence reads must really exist.
        for item in self.six:
            self.assertTrue((ROOT / item["crate_path"] / "Cargo.toml").is_file())
            self.assertTrue((ROOT / item["crate_path"] / "module.toml").is_file())
        # Descriptor negatives enter the SAME owner gate that granted them.
        # A real acceptance is destroyed by (a) one more required matrix case
        # than the test floor allows and (b) a foreign field, both of which
        # the #837 gate rejects; the fixture bytes fed here are the accepted
        # ones plus that one bounded mutation.
        base_item = self.six[0]
        raw = descriptor_bytes(base_item)
        raised = raw.replace(
            f"matrix_cases = {base_item['matrix_cases']}\n"
            f"proof_ceiling = {{value = \"workspace-integration\"}}",
            f"matrix_cases = {base_item['matrix_cases']}\n"
            f"proof_ceiling = {{value = \"workspace-integration\"}}\n"
            f"future_field = \"no\"")
        self.assertNotEqual(raised, raw)
        with self.assertRaises(RunnerInputError) as ctx:
            decode_descriptor(raised, descriptor_name(base_item))
        self.assertEqual(str(ctx.exception), "CLOSED_FIELDS")
        low = raw.replace(f"matrix_cases = {base_item['matrix_cases']}\n",
                          f"matrix_cases = {base_item['matrix_cases'] + 1}\n")
        self.assertNotEqual(low, raw)
        with self.assertRaises(RunnerInputError) as ctx:
            decode_descriptor(low, descriptor_name(base_item))
        self.assertEqual(str(ctx.exception), "TEST_FLOOR_TOO_LOW")

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
        # Evidence is observed from the admission merge parent -- the state
        # that existed BEFORE the #829 turn. The post-admission ADMITTED
        # status is never read here, so it can never be its own prerequisite.
        parent = self.candidate["pre_admission"]["base_commit"]
        self.assertEqual(parent, BASE_SHA)
        live = self.leaf_records
        self.assertEqual(validate_leaf_evidence(live), [])
        for record in live:
            # status came from the PRE-admission module.toml and is not
            # ADMITTED, proving readiness precedes admission.
            self.assertEqual(record["observed_at"], parent, record["name"])
            self.assertNotEqual(record["status"], "ADMITTED", record["name"])
            self.assertEqual(record["status"],
                             self.candidate["pre_admission"]["module_status"])
            # descriptor accepted by the real #837 gate.
            self.assertTrue(record["descriptor_accepted"],
                            record["descriptor_defects"])
            # "merged" was measured by ancestry at that parent, not written.
            self.assertTrue(record["leaf_commits"], record["name"])
            for sha in record["leaf_commits"]:
                probe = git("merge-base", "--is-ancestor", sha, parent)
                self.assertEqual(probe.returncode, 0, f"{record['name']}@{sha}")
        # The post-admission label is exactly what readiness may NOT be: the
        # live routers DO carry ADMITTED, and that state is only reachable
        # because the records above already proved readiness beforehand.
        for item in self.six:
            self.assertEqual(load_toml(f"{item['crate_path']}/module.toml")["status"],
                             "ADMITTED", item["name"])
        # UNACCEPTED: a descriptor the #837 gate refuses, mutated in the REAL
        # fixture bytes and re-observed through the SAME owner path that
        # granted acceptance. The record's `descriptor_accepted` is produced
        # by that gate, so the mutation genuinely flips it.
        item = self.six[0]
        corrupt = dict(item)
        corrupt["descriptor_toml"] = item["descriptor_toml"].replace(
            f'body_sha256 = "{item["lib_sha256"]}"', 'body_sha256 = "0" * 64')
        self.assertNotEqual(corrupt["descriptor_toml"], item["descriptor_toml"])
        blocked = observe_leaf_evidence(corrupt, self.candidate)
        self.assertFalse(blocked["descriptor_accepted"])
        self.assertTrue(any("descriptor rejected by #837 gate" in d
                            for d in blocked["descriptor_defects"]),
                        blocked["descriptor_defects"])
        self.assertTrue(validate_leaf_evidence([blocked] + live[1:]))
        # UNMERGED: a leaf whose recorded commit is NOT an ancestor of the
        # pre-admission parent. The witness is the real admission merge commit
        # -- an existing commit that sits after the parent by construction --
        # fed through the same git ancestry probe `observe_leaf_evidence`
        # uses. Nothing about `merged` is written by this test.
        item = self.six[1]
        late = self.candidate["admission_merge_commit"]
        self.assertNotEqual(
            git("merge-base", "--is-ancestor", late, parent).returncode, 0)
        unmerged = observe_leaf_evidence(
            item, {**self.candidate,
                   "leaf_commits": {**self.candidate["leaf_commits"],
                                    item["name"]: [late]}})
        self.assertFalse(unmerged["merged"], unmerged)
        self.assertTrue(validate_leaf_evidence(
            [live[0], unmerged] + live[2:]))

    # WORK_UNIT_CASE: 829/4
    def test_04_failed_partial_stale_proof_blocks_activation(self) -> None:
        # Every field is derived from the real cargo run bound to the leaf's
        # accepted #837 descriptor. The outcome label is recomputed by
        # validate_proof from the observed facts, never supplied by the test.
        live = [self.proof_receipts[item["name"]] for item in self.six]
        for receipt in live:
            self.assertEqual(receipt["exit_code"], 0,
                             f"{receipt['name']}: {receipt['run_reason']}")
            self.assertEqual(receipt["outcome"], "EXECUTED_PASS", receipt["name"])
            self.assertEqual(receipt["stale"], False,
                             f"{receipt['name']}: {receipt['stale_reason']}")
            self.assertEqual(receipt["passed"], receipt["required_cases"],
                             receipt["name"])
            self.assertEqual(receipt["partial"], False, receipt["name"])
        self.assertEqual(validate_proof(live), [])
        # Every receipt field is a measurement of the run that produced it:
        # exit_code is the subprocess returncode and passed/failed/ignored are
        # parsed out of its captured output. Re-deriving from those same
        # observations reproduces the receipt exactly, so nothing between the
        # command and the verdict can be authored.
        for item in self.six:
            run = self.test_runs[item["name"]]
            again = derive_proof_receipt(item, run, accept_descriptor(item))
            self.assertEqual(again, self.proof_receipts[item["name"]],
                             item["name"])
            self.assertEqual(again["exit_code"], run.returncode)
        # Negatives enter the SAME derivation from real observations. Each
        # mutation below corrupts exactly one measured fact and the receipt is
        # re-derived from the command output, never labelled by hand.
        item = self.six[2]
        decoded = accept_descriptor(item)
        run = self.test_runs[item["name"]]
        # FAILED: a nonzero exit, with the transcript left otherwise intact so
        # only the exit code distinguishes it from the accepted receipt.
        fail_run = subprocess.CompletedProcess(
            args=run.args, returncode=101, stdout=run.stdout, stderr=run.stderr)
        failed = derive_proof_receipt(item, fail_run, decoded)
        self.assertEqual(failed["outcome"], "EXECUTED_FAIL")
        self.assertTrue(failed["run_reason"])
        self.assertTrue(validate_proof([failed]))
        self.assertEqual(
            derive_proof_receipt(item, run, decoded)["outcome"], "EXECUTED_PASS")
        # PARTIAL: fewer executed tests than the descriptor's matrix_cases.
        short_run = subprocess.CompletedProcess(
            args=run.args, returncode=0,
            stdout="test result: ok. 1 passed; 0 failed; 0 ignored; "
                   f"{decoded['matrix_cases'] - 1} filtered out; finished in 0.01s\n",
            stderr="")
        partial = derive_proof_receipt(item, short_run, decoded)
        self.assertTrue(partial["partial"], partial)
        self.assertEqual(partial["outcome"], "EXECUTED_PARTIAL")
        self.assertTrue(validate_proof([partial]))
        # EMPTY: the required denominator ran nothing at all. Zero executed
        # against a non-zero `matrix_cases` is a denominator shortfall, so the
        # derivation labels it partial -- either way it is refused.
        empty_run = subprocess.CompletedProcess(
            args=run.args, returncode=0,
            stdout="test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; "
                   "0 filtered out; finished in 0.01s\n", stderr="")
        empty = derive_proof_receipt(item, empty_run, decoded)
        self.assertEqual(empty["passed"], 0)
        self.assertEqual(empty["outcome"], "EXECUTED_PARTIAL")
        self.assertTrue(validate_proof([empty]))
        # STALE: the descriptor's bound digests disagreeing with current
        # source bytes. The stale binding is produced by re-deriving against
        # the descriptor's real matrix denominator, not by setting a flag.
        stale_decoded = dict(decoded)
        stale_decoded["matrix_sha256"] = "0" * 64
        stale = derive_proof_receipt(item, run, stale_decoded)
        self.assertTrue(stale["stale"], stale)
        self.assertEqual(stale["outcome"], "STALE")
        self.assertTrue(validate_proof([stale]))
        body_stale = dict(decoded)
        body_stale["body_sha256"] = "0" * 64
        self.assertTrue(derive_proof_receipt(item, run, body_stale)["stale"])
        # An outcome label that disagrees with the receipt's own facts fails,
        # so a test cannot hand its own verdict to the validator.
        tampered = [dict(r) for r in live]
        tampered[3]["exit_code"] = 101
        tampered[3]["outcome"] = "EXECUTED_PASS"
        self.assertNotEqual(derive_outcome(tampered[3]), tampered[3]["outcome"])
        self.assertTrue(validate_proof(tampered))

    # WORK_UNIT_CASE: 829/6
    def test_06_second_root_writer_blocks_activation(self) -> None:
        # The writer rule is checked against an INDEPENDENT expected set: the
        # write seams declared by the root manifest's serialized-turn comment
        # (observed) versus the candidate's authorized unit (a different owner
        # path). Never a literal list handed to the validator.
        observed = declared_write_seams(self.candidate)
        expected = authorized_write_seams(self.candidate)
        self.assertEqual(observed, expected)
        self.assertEqual(validate_single_writer(observed, expected), [])
        # The expected set is a measurement of an independent owner path, not
        # a copy of what the validator was handed: it is the candidate's
        # authorized unit, while `observed` is parsed out of the root
        # manifest's serialized-turn comment at the admission commit and is
        # only honoured because that commit actually wrote the declared
        # root/lock/index scope. Prove neither path can be short-circuited.
        self.assertEqual(len(expected), 1)
        # A second root writer is refused: one that took the same lane.
        self.assertTrue(validate_single_writer(observed | {"T8-A1"}, expected))
        self.assertTrue(any("unauthorized root/lock/index writer" in e
                            for e in validate_single_writer(
                                observed | {"T8-A1"}, expected)))
        # An authorized writer that never took the lane is refused, and the
        # holder is reported by name from the independently derived set.
        withheld = validate_single_writer(set(), expected)
        self.assertTrue(any("authorized writer did not take the lane" in e
                            and sorted(expected)[0] in e for e in withheld),
                        withheld)
        # A holder nobody authorized is refused under the same validator.
        self.assertTrue(validate_single_writer(observed, set()))
        # The lane holder is derived from the commit that really wrote the
        # root families: point the fixture's scope at a file that turn did not
        # touch and the holder is withdrawn, so authority is evidence-bound.
        unreachable = {**self.candidate,
                       "single_writer_scope": ["CONTRIBUTING.md"]}
        self.assertEqual(declared_write_seams(unreachable), set())
        self.assertTrue(validate_single_writer(
            declared_write_seams(unreachable), expected))
        # A candidate that names an unauthorized unit in the root comment is
        # caught by comparing the two independent paths.
        self.assertNotEqual(
            declared_write_seams({**self.candidate,
                                  "admission_merge_commit": BASE_SHA}),
            expected)
        base_members = self._base_manifest()["workspace"]["members"]
        moved = [p for p in self.six_paths if p in root_workspace()["members"]
                 and p not in base_members]
        self.assertEqual(sorted(moved), sorted(self.six_paths))

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
        # Coverage denominators are derived from the generator that owns them,
        # not copied from the committed file or frozen at the September base.
        # `package_docs.render` emits len(_packages(registry)) as "Workspace
        # members"; `prototype_docs.render` emits the same expression over the
        # nonmember filter as "Nonmember Cargo packages". build_registry() is
        # the shared producer of both, so re-deriving through it keeps this
        # leg true under legitimate later workspace growth while still failing
        # if either index drifts from its generator.
        registry = build_registry(ROOT)
        expected_members = sum(1 for pkg in registry["packages"]
                               if pkg.get("workspace_member") is True)
        expected_prototypes = sum(1 for pkg in registry["packages"]
                                  if pkg.get("workspace_member") is not True)
        self.assertEqual(expected_members, registry["counts"]["workspace_members"])
        self.assertEqual(expected_prototypes, registry["counts"]["nonmember_packages"])
        self.assertIn(f"- Workspace members: **{expected_members}**.", package_index)
        self.assertIn(f"- Nonmember Cargo packages: **{expected_prototypes}**.",
                      prototype_index)
        # Negative legs: the same derived denominators must not be satisfiable
        # by an off-by-one or a stale frozen literal in the index text.
        self.assertNotIn(f"- Workspace members: **{expected_members + 1}**.",
                         package_index)
        self.assertNotIn(f"- Nonmember Cargo packages: **{expected_prototypes + 1}**.",
                         prototype_index)
        # Each admitted package is rendered as a workspace row, and the exact six
        # never reappear as prototype rows.
        for path in self.six_paths:
            self.assertTrue(any(line.startswith("| ") and path in line
                                for line in package_index.splitlines()), path)

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
        # The frozen baseline counts are immutable history about BASE_SHA, so
        # they are reconciled against BASE_SHA's own manifest, not against
        # today's workspace (which has since grown by unrelated members).
        self.assertEqual(self.baseline["members_count"], len(base["members"]))
        self.assertEqual(self.baseline["excluded_count"], len(base["exclude"]))
        # Admission transaction: the exact six moved exclude -> members. This
        # is a set transition, so unrelated later growth neither satisfies nor
        # falsifies it; a missing or extra affected path still does.
        base_members, live_members = set(base["members"]), set(live["members"])
        self.assertEqual(len(self.six_paths), 6)
        for path in self.six_paths:
            self.assertNotIn(path, base_members, f"{path} was already a member")
            self.assertIn(path, base["exclude"], f"{path} was not excluded at base")
            self.assertIn(path, live_members, f"{path} is not admitted now")
            self.assertNotIn(path, live["exclude"], f"{path} is still excluded")
        admitted = sorted(live_members - base_members)
        self.assertTrue(set(self.six_paths) <= set(admitted))
        # Current-state denominator is derived from the current workspace, so
        # later unrelated members cannot keep this leg red and cannot hide a
        # genuine shortfall.
        self.assertGreaterEqual(len(live_members), len(base_members) + 6)
        # The generated prototype index must agree with its own generator now;
        # the frozen `baseline.prototypes - 6` figure is September history and
        # is only valid against BASE_SHA's index bytes.
        registry = build_registry(ROOT)
        live_prototypes = registry["counts"]["nonmember_packages"]
        prototype_index = read_bytes(
            "docs/code-navigation/PROTOTYPE_DOCS_INDEX.md").decode("utf-8")
        self.assertIn(f"- Nonmember Cargo packages: **{live_prototypes}**.",
                      prototype_index)
        base_index = git("show",
                         f"{BASE_SHA}:docs/code-navigation/PROTOTYPE_DOCS_INDEX.md")
        self.assertEqual(base_index.returncode, 0, base_index.stderr)
        self.assertIn(
            f"- Nonmember Cargo packages: **{self.baseline['prototypes']}**.",
            base_index.stdout)
        # Historical membership transition, proven on BASE_SHA's own index
        # bytes: at the frozen base the exact six were projected as prototypes
        # and absent from the workspace index; today they are projected as
        # workspace rows and absent from the prototype index.
        base_package_index = git(
            "show", f"{BASE_SHA}:docs/code-navigation/PACKAGE_DOCS_INDEX.md")
        self.assertEqual(base_package_index.returncode, 0, base_package_index.stderr)
        for path in self.six_paths:
            self.assertIn(path, base_index.stdout, path)
            self.assertNotIn(path, base_package_index.stdout, path)
        # Source-byte pins: the fixture claims these exact lib.rs digests.
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
