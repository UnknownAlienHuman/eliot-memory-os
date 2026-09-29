"""Declared reproducible scanner/input preparation for dependency policy.

Issue #1229, external audit 5886153415: this module provides the exact
shared handoff the audit requires. It prepares what has an existing owner
and visibly reports the rest, so that #3004/#1225 can invoke one declared
entrypoint on a clean hosted runner before their applicable policy profile
instead of triaging cascaded findings afterwards.

Ordered plan (``PREPARATION_PLAN``):

1. ``scanner`` (source scope): verify the pinned cargo-deny identity from
   ``config/dependency-policy.toml [scanner]`` (PATH lookup, version,
   SHA-256, Windows PE identity, ``--version`` probe through a verified
   private copy). Never installs or fetches a tool: an absent scanner stays
   ``missing`` (``TOOL_UNAVAILABLE`` wording), never a silent pass.
2. ``surrealdb_provisioner`` (source scope): run the existing owner
   ``scripts/provision-surrealdb-release.py`` so project-local
   source/tag/OSV/candidate artifacts are materialized with digest pins.
   Never hand-authors locks or receipts.
3. ``standalone_resolver_inputs`` (source scope): declare every standalone
   workspace and its adjacent-lock readiness using the verifier's own
   manifest discovery. Binding stays with the verifier's actual resolver;
   no lock is generated or copied here.
4. ``installed_observation`` (installed scope, reported-only): classify the
   workstation ``observed_path`` binary without requiring or copying it.
5. ``advisory_expectation`` (declared): state the profile's advisory proof
   boundary (offline claims no current coverage).

Preparation establishes input readiness only. It creates no runtime,
advisory, release-acceptance or Product support claim.

Invoker contract::

    python scripts/prepare-dependency-policy-inputs.py --root . --profile offline-source --manifest-out .eliot/dependency-policy-preparation.json
    python scripts/verify-dependency-policy.py --root . --profile offline-source --receipt-out <caller-selected>

Run the profile only when preparation exits 0. Exit 1 means required
inputs are missing or provisioning failed; the manifest names them.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
_VERIFIER_PATH = _SCRIPT_DIR / "verify-dependency-policy.py"
_VERIFIER_SPEC = importlib.util.spec_from_file_location(
    "verify_dependency_policy_prep_owner", _VERIFIER_PATH
)
if _VERIFIER_SPEC is None or _VERIFIER_SPEC.loader is None:
    raise ImportError(f"Cannot load dependency-policy verifier owner {_VERIFIER_PATH}")
vdp = importlib.util.module_from_spec(_VERIFIER_SPEC)
sys.modules["verify_dependency_policy_prep_owner"] = vdp
_VERIFIER_SPEC.loader.exec_module(vdp)

PREPARATION_SCHEMA = "eliot.dependency-policy-preparation.v1"
AUDIT_REF = "5886153415"
DEFAULT_MANIFEST_RELATIVE = ".eliot/dependency-policy-preparation.json"
PROVISIONER_RELATIVE = "scripts/provision-surrealdb-release.py"
PROVISIONING_RECEIPT_RELATIVE = ".eliot/dependency-policy/surrealdb/provisioning-receipt.json"
POLICY_MANIFEST_RELATIVE = "config/dependency-policy.toml"

STATUS_READY = "ready"
STATUS_MISSING = "missing"
STATUS_MISMATCH = "mismatch"
STATUS_PROVISION_FAILED = "provision_failed"
STATUS_REPORTED = "reported"
STATUS_DECLARED = "declared"

SCOPE_SOURCE = "source"
SCOPE_INSTALLED = "installed"

PROFILES = ("offline-source", "current-advisories")

# Declared preparation order. ``required_profiles`` names the profiles for
# which the input must be ``ready``; an empty tuple means reported-only.
PREPARATION_PLAN: tuple[dict, ...] = (
    {
        "name": "scanner",
        "owner": "dependency-policy verifier pinned identity ([scanner])",
        "evidence_scope": SCOPE_SOURCE,
        "required_profiles": ("offline-source", "current-advisories"),
    },
    {
        "name": "surrealdb_provisioner",
        "owner": "scripts/provision-surrealdb-release.py",
        "evidence_scope": SCOPE_SOURCE,
        "required_profiles": ("offline-source", "current-advisories"),
    },
    {
        "name": "standalone_resolver_inputs",
        "owner": "verifier actual resolver (bind_nonmember_resolver_identity); preparation declares inputs only",
        "evidence_scope": SCOPE_SOURCE,
        "required_profiles": ("offline-source", "current-advisories"),
    },
    {
        "name": "installed_observation",
        "owner": "workstation installation (reported-only; never copied)",
        "evidence_scope": SCOPE_INSTALLED,
        "required_profiles": (),
    },
    {
        "name": "advisory_expectation",
        "owner": "profile contract declaration",
        "evidence_scope": SCOPE_SOURCE,
        "required_profiles": (),
    },
)

_PLAN_BY_NAME = {step["name"]: step for step in PREPARATION_PLAN}

_SEMVER = re.compile(r"\d+\.\d+\.\d+")
_HEX64 = re.compile(r"[0-9a-fA-F]{64}")
_HEX40 = re.compile(r"[0-9a-fA-F]{40}")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _record(name: str, status: str, detail: str, extra: dict | None = None) -> dict:
    step = _PLAN_BY_NAME[name]
    record = {
        "input": name,
        "owner": step["owner"],
        "evidence_scope": step["evidence_scope"],
        "status": status,
        "detail": detail,
    }
    if extra:
        record.update(extra)
    return record


def _read_policy_manifest(root: Path) -> tuple[dict, str | None]:
    path = root / POLICY_MANIFEST_RELATIVE
    try:
        return tomllib.loads(path.read_text(encoding="utf-8")), None
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return {}, f"cannot read {POLICY_MANIFEST_RELATIVE}: {exc}"


def check_scanner_input(root: Path, manifest_data: dict) -> dict:
    """Verify the pinned scanner identity; never installs or fetches a tool."""
    scanner = manifest_data.get("scanner", {})
    if not isinstance(scanner, dict):
        scanner = {}
    executable_name = str(scanner.get("executable", "cargo-deny") or "cargo-deny")
    expected_version = str(scanner.get("version", "") or "")
    expected_digest = str(scanner.get("sha256", "") or "").lower()
    for field, value in (
        ("tool", scanner.get("tool")),
        ("version", expected_version),
        ("executable", executable_name),
        ("sha256", expected_digest),
        ("advisory_owner", scanner.get("advisory_owner")),
    ):
        if value in (None, "", [], {}):
            return _record("scanner", STATUS_MISMATCH, f"[scanner] {field} is not declared")
    if scanner.get("tool") != "cargo-deny":
        return _record("scanner", STATUS_MISMATCH, "[scanner].tool must be cargo-deny")
    if not _SEMVER.fullmatch(expected_version):
        return _record("scanner", STATUS_MISMATCH, "[scanner].version must be an exact semantic version")
    if not _HEX64.fullmatch(expected_digest):
        return _record("scanner", STATUS_MISMATCH, "[scanner].sha256 must be a 64-character hexadecimal digest")

    exec_path = shutil.which(executable_name)
    if not exec_path:
        return _record(
            "scanner",
            STATUS_MISSING,
            f"scanner tool '{executable_name}' not found on PATH (TOOL_UNAVAILABLE): "
            f"provide pinned {scanner.get('tool')} {expected_version} before the policy profile; "
            "preparation never installs latest tools",
            {"configured_version": expected_version, "configured_sha256": expected_digest},
        )
    try:
        payload, _ = vdp._read_stable_file_bytes(Path(exec_path), "cargo-deny scanner")
        observed_digest = hashlib.sha256(payload).hexdigest().lower()
    except OSError as exc:
        return _record("scanner", STATUS_MISSING, f"cannot read scanner executable '{exec_path}': {exc}")
    if observed_digest != expected_digest:
        return _record(
            "scanner",
            STATUS_MISMATCH,
            f"scanner executable SHA-256 mismatch: configured {expected_digest}, observed {observed_digest}",
            {"executable": str(Path(exec_path).resolve()), "observed_sha256": observed_digest},
        )
    machine = vdp._pe_machine(payload)
    if machine != 0x8664:
        return _record("scanner", STATUS_MISMATCH, "scanner executable is not a Windows x86_64 PE artifact")
    try:
        probe = vdp._run_verified_executable(payload, ["--version"], root, "cargo-deny scanner")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _record("scanner", STATUS_MISSING, f"cannot execute scanner identity probe: {exc}")
    combined = "\n".join(part for part in (probe.stdout, probe.stderr) if part)
    observed_version = vdp._scanner_version(combined)
    if probe.returncode != 0 or not observed_version:
        return _record("scanner", STATUS_MISMATCH, "scanner identity probe did not report cargo-deny version")
    if observed_version != expected_version:
        return _record(
            "scanner",
            STATUS_MISMATCH,
            f"scanner version mismatch: configured {expected_version}, observed {observed_version}",
        )
    return _record(
        "scanner",
        STATUS_READY,
        f"pinned scanner {observed_version} identity verified",
        {
            "executable": str(Path(exec_path).resolve()),
            "observed_version": observed_version,
            "observed_sha256": observed_digest,
            "observed_size": len(payload),
        },
    )


def run_surrealdb_provisioner(root: Path) -> dict:
    """Run the existing SurrealDB provisioner; never hand-authors artifacts."""
    provisioner = root / PROVISIONER_RELATIVE
    if not provisioner.is_file():
        return _record(
            "surrealdb_provisioner", STATUS_PROVISION_FAILED, f"existing provisioner is absent: {PROVISIONER_RELATIVE}"
        )
    try:
        proc = subprocess.run(
            [sys.executable, str(provisioner), "--root", str(root)],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return _record("surrealdb_provisioner", STATUS_PROVISION_FAILED, "provisioner timed out after 600s")
    except OSError as exc:
        return _record("surrealdb_provisioner", STATUS_PROVISION_FAILED, f"cannot launch provisioner: {exc}")
    tail = "\n".join((proc.stdout or "").splitlines()[-5:] + (proc.stderr or "").splitlines()[-5:])
    if proc.returncode != 0:
        return _record(
            "surrealdb_provisioner",
            STATUS_PROVISION_FAILED,
            f"provisioner exited {proc.returncode}; inputs stay visibly missing, nothing fabricated",
            {"exit_code": proc.returncode, "output_tail": tail[-2000:]},
        )
    receipt_path = root / PROVISIONING_RECEIPT_RELATIVE
    receipt_digest = None
    if receipt_path.is_file() and not receipt_path.is_symlink():
        try:
            receipt_digest = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
        except OSError:
            receipt_digest = None
    return _record(
        "surrealdb_provisioner",
        STATUS_READY,
        "provisioner exited 0; project-local inputs materialized by their owner",
        {"exit_code": 0, "provisioning_receipt": PROVISIONING_RECEIPT_RELATIVE, "provisioning_receipt_sha256": receipt_digest},
    )


def collect_standalone_resolver_inputs(root: Path) -> dict:
    """Declare standalone workspace adjacent-lock readiness; generates nothing."""
    try:
        manifests = vdp._cargo_manifest_paths(root)
    except (OSError, ValueError) as exc:
        return _record("standalone_resolver_inputs", STATUS_MISMATCH, f"cannot enumerate manifests: {exc}")
    workspaces: list[dict] = []
    missing = 0
    for manifest_path in manifests:
        if manifest_path.resolve() == (root / "Cargo.toml").resolve():
            continue
        try:
            data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            workspaces.append(
                {
                    "manifest": manifest_path.relative_to(root).as_posix(),
                    "lock_status": STATUS_MISMATCH,
                    "detail": f"manifest cannot be parsed: {exc}",
                }
            )
            missing += 1
            continue
        if not isinstance(data.get("workspace"), dict):
            continue
        workspace_dir = manifest_path.parent
        lock_path = workspace_dir / "Cargo.lock"
        relative_manifest = manifest_path.relative_to(root).as_posix()
        if lock_path.is_file() and not lock_path.is_symlink():
            try:
                digest = hashlib.sha256(lock_path.read_bytes()).hexdigest()
            except OSError as exc:
                workspaces.append(
                    {
                        "manifest": relative_manifest,
                        "adjacent_lock": lock_path.relative_to(root).as_posix(),
                        "lock_status": STATUS_MISMATCH,
                        "detail": f"adjacent lock cannot be read: {exc}",
                    }
                )
                missing += 1
                continue
            workspaces.append(
                {
                    "manifest": relative_manifest,
                    "adjacent_lock": lock_path.relative_to(root).as_posix(),
                    "lock_status": STATUS_READY,
                    "lock_sha256": digest,
                }
            )
        else:
            missing += 1
            workspaces.append(
                {
                    "manifest": relative_manifest,
                    "adjacent_lock": lock_path.relative_to(root).as_posix(),
                    "lock_status": STATUS_MISSING,
                    "detail": "no adjacent checked-in Cargo.lock; the verifier's actual resolver "
                    "will keep this edge source_only_incomplete (preparation generates no lock)",
                }
            )
    status = STATUS_READY if missing == 0 else STATUS_MISSING
    detail = (
        f"{len(workspaces)} standalone workspaces, all adjacent locks present"
        if missing == 0
        else f"{len(workspaces)} standalone workspaces, {missing} without an adjacent lock; "
        "resolver joins for those edges stay source_only_incomplete"
    )
    return _record("standalone_resolver_inputs", status, detail, {"workspaces": workspaces})


def classify_installed_observation(root: Path, manifest_data: dict) -> dict:
    """Classify the workstation installed binary; reported-only, never copied.

    ``observed_path`` evidence belongs to the installed scope: it gates
    installed/runtime/release acceptance, never a source-only claim. This
    step only observes (presence plus hash) and never executes or copies
    workstation state.
    """
    _ = root
    externals = manifest_data.get("external_executables", {})
    surreal = externals.get("surrealdb", {}) if isinstance(externals, dict) else {}
    if not isinstance(surreal, dict):
        return _record("installed_observation", STATUS_REPORTED, "no surrealdb policy table; nothing installed to classify")
    observed_value = surreal.get("observed_path")
    pinned = str(surreal.get("sha256", "") or "").lower()
    if not isinstance(observed_value, str) or not Path(observed_value).is_absolute():
        return _record(
            "installed_observation",
            STATUS_REPORTED,
            "observed_path is not an absolute path; installed scope has no workstation observation",
            {"configured_path": observed_value},
        )
    observed_path = Path(observed_value)
    if not observed_path.is_file() or observed_path.is_symlink():
        return _record(
            "installed_observation",
            STATUS_REPORTED,
            f"installed observation unavailable: {observed_path} is not a regular file on this machine; "
            "source profiles proceed without it and installed acceptance stays separate",
            {"configured_path": str(observed_path)},
        )
    try:
        payload, _ = vdp._read_stable_file_bytes(observed_path, "observed surrealdb executable")
        observed_digest = hashlib.sha256(payload).hexdigest().lower()
    except OSError as exc:
        return _record(
            "installed_observation",
            STATUS_REPORTED,
            f"installed observation unreadable: {exc}",
            {"configured_path": str(observed_path)},
        )
    pin_match: bool | None = None
    if _HEX64.fullmatch(pinned):
        pin_match = observed_digest == pinned
    return _record(
        "installed_observation",
        STATUS_REPORTED,
        "installed observation classified (installed scope; reported without gating the source claim)",
        {
            "configured_path": str(observed_path),
            "observed_sha256": observed_digest,
            "observed_size": len(payload),
            "matches_pin": pin_match,
        },
    )


def declare_advisory_expectation(profile: str) -> dict:
    """State the profile's advisory proof boundary without fetching anything."""
    if profile == "current-advisories":
        return _record(
            "advisory_expectation",
            STATUS_DECLARED,
            "current-advisories binds the fresh advisory snapshot at profile execution "
            "through the pinned scanner; preparation fetches nothing itself",
            {"current_advisory_claim": True, "bound_at": "profile execution"},
        )
    return _record(
        "advisory_expectation",
        STATUS_DECLARED,
        "offline-source verifies cached/declared advisory bytes only and claims no current "
        "vulnerability coverage (proof ceiling OFFLINE_SOURCE_EVIDENCE_ONLY)",
        {"current_advisory_claim": False},
    )


def _git_source_sha(root: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    sha = proc.stdout.strip()
    return sha if proc.returncode == 0 and _HEX40.fullmatch(sha) else None


def build_preparation_manifest(
    root: Path,
    profile: str,
    step_records: list[dict],
    manifest_path_relative: str,
) -> dict:
    """Assemble the preparation manifest; missing inputs stay visibly missing."""
    _ = root
    by_name = {record["input"]: record for record in step_records}
    required = [step["name"] for step in PREPARATION_PLAN if profile in step["required_profiles"]]
    missing = [
        name for name in required if by_name.get(name, {}).get("status") != STATUS_READY
    ]
    return {
        "schema": PREPARATION_SCHEMA,
        "audit": AUDIT_REF,
        "profile": profile,
        "generated_at_utc": _utc_now(),
        "source_sha": _git_source_sha(root),
        "inputs": step_records,
        "required_inputs": required,
        "missing_inputs": missing,
        "ready": not missing,
        "invoker_contract": {
            "preparation": "python scripts/prepare-dependency-policy-inputs.py "
            f"--root . --profile {profile} --manifest-out {manifest_path_relative}",
            "profile_command": "python scripts/verify-dependency-policy.py "
            f"--root . --profile {profile} --receipt-out <caller-selected>",
            "gate": "run the profile command only when this manifest reports ready=true; "
            "otherwise report missing_inputs instead of running the profile",
        },
        "boundary_notes": [
            "scanner, resolver and provisioned inputs are source scope and gate source profiles.",
            "installed_observation is installed scope and reported-only: it gates "
            "installed/runtime/release acceptance, never a source-only claim.",
            "An unavailable installed observation or a missing adjacent lock is an explicit "
            "incomplete state, never PASS and never fabricated.",
        ],
        "proof_ceiling_note": "Preparation establishes input readiness only; it creates no runtime, "
        "advisory, release-acceptance or Product support claim.",
    }


def preparation_ready(manifest: dict) -> bool:
    """True only when every profile-required input is ready (production gate predicate)."""
    return bool(manifest.get("ready")) and not manifest.get("missing_inputs")


def run_self_tests() -> int:
    import tempfile

    print("Running prepare-dependency-policy-inputs self-tests...")
    failures = 0

    def check(label: str, condition: bool) -> None:
        nonlocal failures
        if not condition:
            print(f"SELF_TEST_FAILURE: {label}", file=sys.stderr)
            failures += 1

    # Case 1: absent scanner executable is missing, never fabricated.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest_data = {
            "scanner": {
                "tool": "cargo-deny",
                "version": "0.20.2",
                "executable": "nonexistent-scanner-tool-1229",
                "sha256": "f7292fab58c706638c999e64c4ba82e5128ae628130ba55e3266a768ee431fbf",
                "advisory_owner": "cargo-deny",
                "checks": ["advisories", "bans", "licenses", "sources"],
            }
        }
        record = check_scanner_input(root, manifest_data)
        check("absent scanner must be missing", record["status"] == STATUS_MISSING)
        check("absent scanner keeps source scope", record["evidence_scope"] == SCOPE_SOURCE)
        check("absent scanner names TOOL_UNAVAILABLE", "TOOL_UNAVAILABLE" in record["detail"])

    # Case 2: malformed scanner declaration is mismatch, not ready.
    with tempfile.TemporaryDirectory() as tmp:
        record = check_scanner_input(Path(tmp), {"scanner": {"tool": "cargo-deny"}})
        check("undeclared scanner fields must mismatch", record["status"] == STATUS_MISMATCH)

    # Case 3: plan scopes are declared; installed observation is reported-only.
    for step in PREPARATION_PLAN:
        check(f"plan step {step['name']} has owner", bool(step.get("owner")))
        check(
            f"plan step {step['name']} has a scope",
            step.get("evidence_scope") in (SCOPE_SOURCE, SCOPE_INSTALLED),
        )
    installed_step = _PLAN_BY_NAME["installed_observation"]
    check("installed observation is reported-only", installed_step["required_profiles"] == ())
    check("installed observation is installed scope", installed_step["evidence_scope"] == SCOPE_INSTALLED)

    # Case 4: standalone discovery reports a missing adjacent lock and writes nothing.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "Cargo.toml").write_text('[workspace]\nresolver = "3"\n', encoding="utf-8")
        standalone = root / "crates" / "demo-standalone"
        standalone.mkdir(parents=True)
        (standalone / "Cargo.toml").write_text(
            '[package]\nname = "demo-standalone"\nversion = "0.1.0"\nedition = "2021"\n[workspace]\n',
            encoding="utf-8",
        )
        before = sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))
        record = collect_standalone_resolver_inputs(root)
        after = sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))
        check("missing adjacent lock is missing", record["status"] == STATUS_MISSING)
        check("discovery names the standalone manifest", any(
            entry.get("manifest") == "crates/demo-standalone/Cargo.toml"
            for entry in record.get("workspaces", [])
        ))
        check("discovery generates no lock", before == after)
        check("discovery creates no Cargo.lock", not (standalone / "Cargo.lock").exists())

    # Case 5: installed observation outside the root is reported, never copied.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest_data = {
            "external_executables": {
                "surrealdb": {
                    "sha256": "13781bc97db9348498bd6b5e0090cf2770e9d296640be8adcf73956e8a568a1",
                    "observed_path": "C:/Tools/SurrealDB/surreal.exe",
                }
            }
        }
        before = sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))
        record = classify_installed_observation(root, manifest_data)
        after = sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))
        check("installed observation is reported-only", record["status"] == STATUS_REPORTED)
        check("installed observation keeps installed scope", record["evidence_scope"] == SCOPE_INSTALLED)
        check("classification copies no workstation state", before == after)

    # Case 6: manifest readiness logic names missing required inputs.
    ready_records = [
        _record("scanner", STATUS_READY, "ok"),
        _record("surrealdb_provisioner", STATUS_READY, "ok"),
        _record("standalone_resolver_inputs", STATUS_READY, "ok"),
        _record("installed_observation", STATUS_REPORTED, "reported"),
        _record("advisory_expectation", STATUS_DECLARED, "declared"),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        manifest = build_preparation_manifest(Path(tmp), "offline-source", ready_records, DEFAULT_MANIFEST_RELATIVE)
        check("complete inputs are ready", preparation_ready(manifest))
        check("complete inputs list no missing", manifest["missing_inputs"] == [])
        incomplete = [dict(record) for record in ready_records]
        incomplete[0] = _record("scanner", STATUS_MISSING, "absent")
        manifest = build_preparation_manifest(Path(tmp), "offline-source", incomplete, DEFAULT_MANIFEST_RELATIVE)
        check("absent scanner blocks readiness", not preparation_ready(manifest))
        check("absent scanner is named missing", manifest["missing_inputs"] == ["scanner"])
        check("manifest carries the invoker gate", "gate" in manifest["invoker_contract"])
        payload = json.dumps(manifest, indent=2)
        check("manifest is JSON round-trippable", json.loads(payload)["schema"] == PREPARATION_SCHEMA)

    # Case 7: advisory expectation differs by profile without fetching.
    offline = declare_advisory_expectation("offline-source")
    current = declare_advisory_expectation("current-advisories")
    check("offline claims no current coverage", offline["current_advisory_claim"] is False)
    check("current profile binds at execution", current["current_advisory_claim"] is True)

    if failures:
        return 1
    print("DEPENDENCY_POLICY_PREPARATION_SELF_TEST: PASS (7/7 cases verified)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare declared dependency-policy inputs before a policy profile.")
    parser.add_argument("--root", default=".", help="Repository root directory")
    parser.add_argument(
        "--profile",
        choices=list(PROFILES),
        default="offline-source",
        help="Policy profile the inputs are prepared for",
    )
    parser.add_argument(
        "--manifest-out",
        default=DEFAULT_MANIFEST_RELATIVE,
        help="Write the preparation manifest to this path (repository-relative or absolute)",
    )
    parser.add_argument("--self-test", action="store_true", help="Run internal self-tests")
    args = parser.parse_args()

    if args.self_test:
        return run_self_tests()

    root = Path(args.root).resolve()
    manifest_data, manifest_error = _read_policy_manifest(root)
    if manifest_error is not None:
        print(f"PREPARE_DEPENDENCY_POLICY_INPUTS: INCOMPLETE ({manifest_error})")
        return 1

    step_records = [
        check_scanner_input(root, manifest_data),
        run_surrealdb_provisioner(root),
        collect_standalone_resolver_inputs(root),
        classify_installed_observation(root, manifest_data),
        declare_advisory_expectation(args.profile),
    ]
    manifest_out = args.manifest_out
    manifest_relative = manifest_out.replace("\\", "/")
    manifest = build_preparation_manifest(root, args.profile, step_records, manifest_relative)
    out_path = Path(manifest_out)
    if not out_path.is_absolute():
        out_path = root / out_path
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"PREPARE_DEPENDENCY_POLICY_INPUTS: INCOMPLETE (cannot write manifest: {exc})")
        return 1

    for record in step_records:
        print(f"  [{record['status']}] {record['input']} ({record['evidence_scope']}): {record['detail']}")
    if preparation_ready(manifest):
        print(
            f"PREPARE_DEPENDENCY_POLICY_INPUTS: READY (profile={args.profile}, "
            f"required={len(manifest['required_inputs'])}, manifest={manifest_relative})"
        )
        return 0
    print(
        f"PREPARE_DEPENDENCY_POLICY_INPUTS: INCOMPLETE (profile={args.profile}, "
        f"missing={manifest['missing_inputs']}, manifest={manifest_relative})"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
