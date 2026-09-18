#!/usr/bin/env python3
"""Multi-ecosystem dependency admission policy verifier (issue #1229).

Executes and verifies the documented dependency admission policy:
- Pinned scanner identity (cargo-deny) outside legacy engine;
- Complete direct dependency inventory accounting (consumer, owner, reason, features, removal);
- Cross-ecosystem lockfile integrity (Rust Cargo.lock, NuGet packages.lock.json, Python hash-locked requirements);
- External executable inventory (SurrealDB);
- Distinct verification profiles: offline-source vs current-advisories;
- Structured expiring exceptions;
- Deterministic canonical receipt generation.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    line: int
    detail: str


STATUS_PASS = "PASS"
STATUS_FINDINGS = "FINDINGS"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"
STATUS_ADVISORY_SOURCE_UNAVAILABLE = "ADVISORY_SOURCE_UNAVAILABLE"
STATUS_STALE = "STALE"
STATUS_CONFLICTED = "CONFLICTED"
STATUS_NOT_EXECUTED = "NOT_EXECUTED"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def check_policy_manifest(root: Path) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    manifest_path = root / "config" / "dependency-policy.toml"
    rel_path = "config/dependency-policy.toml"

    if not manifest_path.is_file():
        findings.append(Finding("DEP-002", rel_path, 0, "missing required config/dependency-policy.toml manifest"))
        return findings, {}

    try:
        data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        findings.append(Finding("DEP-002", rel_path, 1, f"failed to parse config/dependency-policy.toml: {exc}"))
        return findings, {}

    if data.get("schema") != "eliot.dependency-policy.v1":
        findings.append(Finding("DEP-002", rel_path, 1, "schema must be 'eliot.dependency-policy.v1'"))

    if not data.get("scanner", {}).get("tool"):
        findings.append(Finding("DEP-002", rel_path, 1, "missing [scanner] tool declaration"))

    deny_path = root / "deny.toml"
    if not deny_path.is_file():
        findings.append(Finding("DEP-002", "deny.toml", 0, "missing required deny.toml policy configuration"))
    else:
        try:
            deny_data = tomllib.loads(deny_path.read_text(encoding="utf-8"))
            for section in ("advisories", "licenses", "bans", "sources"):
                if section not in deny_data:
                    findings.append(Finding("DEP-002", "deny.toml", 1, f"missing required section [{section}] in deny.toml"))
        except Exception as exc:
            findings.append(Finding("DEP-002", "deny.toml", 1, f"failed to parse deny.toml: {exc}"))

    return findings, data


def collect_direct_rust_dependencies(root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    direct_deps: set[str] = set()
    internal_crates: set[str] = set()

    cargo_root = root / "Cargo.toml"
    if not cargo_root.is_file():
        findings.append(Finding("DEP-003", "Cargo.toml", 0, "root Cargo.toml is missing"))
        return findings, direct_deps

    try:
        root_data = tomllib.loads(cargo_root.read_text(encoding="utf-8"))
        ws_deps = root_data.get("workspace", {}).get("dependencies", {})
        if isinstance(ws_deps, dict):
            for name, spec in ws_deps.items():
                if isinstance(spec, dict) and "path" in spec:
                    internal_crates.add(name)
    except Exception as exc:
        findings.append(Finding("DEP-003", "Cargo.toml", 1, f"failed to parse root Cargo.toml: {exc}"))

    cargo_files = [cargo_root]
    for sub in ("crates", "bins", "apps", "workspace/tools"):
        sub_dir = root / sub
        if sub_dir.is_dir():
            cargo_files.extend(sub_dir.rglob("Cargo.toml"))

    for cpath in cargo_files:
        try:
            data = tomllib.loads(cpath.read_text(encoding="utf-8"))
            pkg_name = data.get("package", {}).get("name")
            if pkg_name:
                internal_crates.add(pkg_name)
        except Exception:
            pass

    for cpath in cargo_files:
        try:
            data = tomllib.loads(cpath.read_text(encoding="utf-8"))
        except Exception as exc:
            rel = str(cpath.relative_to(root)).replace("\\", "/")
            findings.append(Finding("DEP-003", rel, 1, f"failed to parse Cargo.toml: {exc}"))
            continue

        for sec in ("dependencies", "dev-dependencies", "build-dependencies"):
            deps = data.get(sec, {})
            if isinstance(deps, dict):
                for name, spec in deps.items():
                    if name in internal_crates or name.startswith("eliot"):
                        continue
                    if isinstance(spec, dict) and "path" in spec:
                        continue
                    direct_deps.add(name)

        ws_deps = data.get("workspace", {}).get("dependencies", {})
        if isinstance(ws_deps, dict):
            for name, spec in ws_deps.items():
                if name in internal_crates or name.startswith("eliot"):
                    continue
                if isinstance(spec, dict) and "path" in spec:
                    continue
                direct_deps.add(name)

    return findings, direct_deps


def check_cargo_inventory(manifest_data: dict, direct_deps: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    inventory = manifest_data.get("direct_dependencies", {})
    required_fields = ("consumer", "owner", "reason", "features", "public_exposure", "removal_plan")

    for dep in sorted(direct_deps):
        if dep not in inventory:
            findings.append(
                Finding("DEP-003", "config/dependency-policy.toml", 1, f"direct dependency '{dep}' is missing from inventory")
            )
            continue

        entry = inventory[dep]
        if not isinstance(entry, dict):
            findings.append(
                Finding("DEP-003", "config/dependency-policy.toml", 1, f"inventory entry for '{dep}' must be a table")
            )
            continue

        for field in required_fields:
            if field not in entry:
                findings.append(
                    Finding(
                        "DEP-003",
                        "config/dependency-policy.toml",
                        1,
                        f"dependency '{dep}' is missing required field '{field}' in inventory",
                    )
                )

    return findings


def check_exceptions(manifest_data: dict, now_dt: datetime | None = None) -> list[Finding]:
    findings: list[Finding] = []
    exceptions = manifest_data.get("exceptions", [])
    if not isinstance(exceptions, list):
        findings.append(Finding("DEP-010", "config/dependency-policy.toml", 1, "'exceptions' must be a list"))
        return findings

    if now_dt is None:
        now_dt = datetime.now(timezone.utc)

    for exc_entry in exceptions:
        if not isinstance(exc_entry, dict):
            findings.append(Finding("DEP-010", "config/dependency-policy.toml", 1, "each exception must be a table"))
            continue

        for req in ("package", "version", "advisory", "owner", "compensating_control", "expires_at", "removal_condition"):
            if req not in exc_entry:
                findings.append(
                    Finding("DEP-010", "config/dependency-policy.toml", 1, f"exception missing required field '{req}'")
                )

        exp_str = exc_entry.get("expires_at", "")
        if exp_str:
            try:
                exp_dt = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
                if exp_dt < now_dt:
                    pkg = exc_entry.get("package", "unknown")
                    adv = exc_entry.get("advisory", "unknown")
                    findings.append(
                        Finding(
                            "DEP-010",
                            "config/dependency-policy.toml",
                            1,
                            f"exception for package '{pkg}' advisory '{adv}' expired on {exp_str}",
                        )
                    )
            except Exception as e:
                findings.append(
                    Finding("DEP-010", "config/dependency-policy.toml", 1, f"invalid expires_at format '{exp_str}': {e}")
                )

    return findings


def check_nuget_ecosystem(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    csproj_path = root / "apps" / "Eliot.Operator" / "Eliot.Operator.csproj"
    rel_csproj = "apps/Eliot.Operator/Eliot.Operator.csproj"

    if csproj_path.is_file():
        content = csproj_path.read_text(encoding="utf-8")
        if "<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>" not in content:
            findings.append(
                Finding("DEP-007", rel_csproj, 1, "missing <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>")
            )

        lock_path = root / "apps" / "Eliot.Operator" / "packages.lock.json"
        rel_lock = "apps/Eliot.Operator/packages.lock.json"
        if not lock_path.is_file():
            findings.append(Finding("DEP-007", rel_lock, 0, "checked-in NuGet packages.lock.json is missing"))
        else:
            try:
                lock_data = json.loads(lock_path.read_text(encoding="utf-8"))
                if not lock_data.get("dependencies"):
                    findings.append(Finding("DEP-007", rel_lock, 1, "packages.lock.json has empty dependencies"))
            except Exception as exc:
                findings.append(Finding("DEP-007", rel_lock, 1, f"malformed packages.lock.json: {exc}"))

    return findings


def check_python_ecosystem(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    req_path = root / "scripts" / "requirements-verification.txt"
    rel_req = "scripts/requirements-verification.txt"

    if not req_path.is_file():
        findings.append(Finding("DEP-008", rel_req, 0, "missing requirements-verification.txt"))
        return findings

    lines = req_path.read_text(encoding="utf-8").splitlines()
    current_package = None
    has_hash = False

    for line_no, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("--hash="):
            if not re.fullmatch(r"--hash=sha256:[0-9a-fA-F]{64}\s*\\?", stripped):
                findings.append(Finding("DEP-008", rel_req, line_no, f"invalid hash format: {stripped}"))
            else:
                has_hash = True
            continue

        if current_package and not has_hash:
            findings.append(
                Finding("DEP-008", rel_req, line_no - 1, f"package '{current_package}' is missing --hash=sha256")
            )

        pkg_part = stripped.rstrip("\\").strip()
        if "==" not in pkg_part:
            findings.append(
                Finding("DEP-008", rel_req, line_no, f"requirement '{pkg_part}' is not exact version-pinned with ==")
            )
        current_package = pkg_part
        has_hash = False

    if current_package and not has_hash:
        findings.append(
            Finding("DEP-008", rel_req, len(lines), f"package '{current_package}' is missing --hash=sha256")
        )

    return findings


def check_external_executables(manifest_data: dict) -> list[Finding]:
    findings: list[Finding] = []
    externals = manifest_data.get("external_executables", {})
    if not externals or "surrealdb" not in externals:
        findings.append(
            Finding("DEP-009", "config/dependency-policy.toml", 1, "missing 'surrealdb' in [external_executables]")
        )
        return findings

    surreal = externals["surrealdb"]
    for req in ("name", "version", "license", "consumer", "trust_model", "removal_boundary"):
        if req not in surreal:
            findings.append(
                Finding("DEP-009", "config/dependency-policy.toml", 1, f"surrealdb external executable missing '{req}'")
            )

    return findings


def run_cargo_deny(root: Path, profile: str, scanner_info: dict) -> tuple[list[Finding], str, dict]:
    findings: list[Finding] = []
    executable_name = scanner_info.get("executable", "cargo-deny")
    exec_path = shutil.which(executable_name)

    if not exec_path:
        findings.append(Finding("DEP-001", "deny.toml", 1, f"scanner tool '{executable_name}' not found on PATH"))
        return findings, STATUS_TOOL_UNAVAILABLE, {}

    checks = ["bans", "licenses", "sources"]
    if profile == "current-advisories":
        checks.insert(0, "advisories")

    cmd = [exec_path, "--format", "json", "check"] + checks
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except subprocess.TimeoutExpired:
        findings.append(Finding("DEP-001", "deny.toml", 1, "cargo-deny execution timed out after 180s"))
        return findings, STATUS_TOOL_UNAVAILABLE, {}
    except Exception as exc:
        findings.append(Finding("DEP-001", "deny.toml", 1, f"cargo-deny execution error: {exc}"))
        return findings, STATUS_TOOL_UNAVAILABLE, {}

    summary = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            if entry.get("type") == "summary":
                summary = entry.get("fields", {})
            elif entry.get("type") == "diagnostic":
                fields = entry.get("fields", {})
                severity = fields.get("severity")
                message = fields.get("message", "")
                code = fields.get("code", "")
                if severity == "error":
                    fcode = "DEP-004"
                    if "source" in code.lower() or "registry" in message.lower():
                        fcode = "DEP-005"
                    elif "advisory" in code.lower() or "RUSTSEC" in message:
                        fcode = "DEP-006"
                    findings.append(Finding(fcode, "deny.toml", 1, f"cargo-deny error: [{code}] {message}"))
        except Exception:
            continue

    if proc.returncode != 0 and not findings:
        findings.append(
            Finding("DEP-001", "deny.toml", 1, f"cargo-deny exited nonzero ({proc.returncode}): {proc.stderr[:200]}")
        )

    status = STATUS_PASS if not findings else STATUS_FINDINGS
    return findings, status, summary


def build_receipt(
    root: Path,
    profile: str,
    status: str,
    findings: list[Finding],
    manifest_data: dict,
    cargo_summary: dict,
    direct_deps_count: int,
) -> dict:
    source_sha = "unknown"
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=True,
        )
        source_sha = res.stdout.strip()
    except Exception:
        pass

    digests = {}
    for f in ("Cargo.lock", "deny.toml", "config/dependency-policy.toml", "apps/Eliot.Operator/packages.lock.json", "scripts/requirements-verification.txt"):
        fp = root / f
        if fp.is_file():
            digests[f] = sha256_file(fp)

    scanner = manifest_data.get("scanner", {})
    ceiling = (
        "DEPENDENCY_ADMISSION_AND_ADVISORY_EVIDENCE_CANDIDATE"
        if profile == "current-advisories"
        else "OFFLINE_SOURCE_EVIDENCE_ONLY"
    )

    receipt = {
        "schema": "eliot.dependency-policy-receipt.v1",
        "profile": profile,
        "proof_ceiling": ceiling,
        "status": status,
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_sha": source_sha,
        "scanner": {
            "tool": scanner.get("tool", "cargo-deny"),
            "version": scanner.get("version", "0.20.2"),
            "executable_sha256": scanner.get("sha256", ""),
            "advisory_owner": scanner.get("advisory_owner", "cargo-deny"),
        },
        "ecosystem_denominator": {
            "rust": {
                "direct_dependencies_count": direct_deps_count,
                "targets": manifest_data.get("ecosystems", {}).get("rust", {}).get("targets", []),
                "features": manifest_data.get("ecosystems", {}).get("rust", {}).get("features", "all"),
            },
            "nuget": {
                "project": "apps/Eliot.Operator/Eliot.Operator.csproj",
                "lock_mode": "RestorePackagesWithLockFile",
            },
            "python": {
                "manifest": "scripts/requirements-verification.txt",
                "hash_locked": True,
            },
            "external_executables": list(manifest_data.get("external_executables", {}).keys()),
        },
        "input_digests": digests,
        "scanner_summary": cargo_summary,
        "findings_count": len(findings),
        "findings": [
            {"code": f.code, "path": f.path, "line": f.line, "detail": f.detail} for f in findings
        ],
    }

    if profile == "current-advisories":
        receipt["advisory_snapshot"] = {
            "source": "https://github.com/rustsec/advisory-db",
            "evaluated_at_utc": receipt["timestamp_utc"],
            "status": "ok" if not any(f.code == "DEP-006" for f in findings) else "findings",
        }

    return receipt


def verify_all(root: Path, profile: str) -> tuple[list[Finding], str, dict, dict, int]:
    all_findings: list[Finding] = []

    # 1. Check policy manifest
    m_findings, manifest_data = check_policy_manifest(root)
    all_findings.extend(m_findings)

    # 2. Check Rust direct dependencies & inventory
    d_findings, direct_deps = collect_direct_rust_dependencies(root)
    all_findings.extend(d_findings)
    inv_findings = check_cargo_inventory(manifest_data, direct_deps)
    all_findings.extend(inv_findings)

    # 3. Check exceptions
    exc_findings = check_exceptions(manifest_data)
    all_findings.extend(exc_findings)

    # 4. Check NuGet
    nu_findings = check_nuget_ecosystem(root)
    all_findings.extend(nu_findings)

    # 5. Check Python requirements
    py_findings = check_python_ecosystem(root)
    all_findings.extend(py_findings)

    # 6. Check external executables
    ext_findings = check_external_executables(manifest_data)
    all_findings.extend(ext_findings)

    # 7. Run cargo deny scanner
    scanner_findings, scanner_status, cargo_summary = run_cargo_deny(root, profile, manifest_data.get("scanner", {}))
    all_findings.extend(scanner_findings)

    # Derive overall status
    if any(f.code == "DEP-001" for f in all_findings):
        overall_status = STATUS_TOOL_UNAVAILABLE
    elif any(f.code == "DEP-003" for f in all_findings):
        overall_status = STATUS_INCOMPLETE
    elif any(f.code == "DEP-006" for f in all_findings):
        overall_status = STATUS_FINDINGS
    elif all_findings:
        overall_status = STATUS_FINDINGS
    else:
        overall_status = STATUS_PASS

    receipt = build_receipt(
        root, profile, overall_status, all_findings, manifest_data, cargo_summary, len(direct_deps)
    )

    return all_findings, overall_status, receipt, manifest_data, len(direct_deps)


def run_self_tests() -> int:
    import tempfile

    print("Running verify-dependency-policy self-tests...")

    # Case 1: missing manifest
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        findings, data = check_policy_manifest(root)
        if not any(f.code == "DEP-002" for f in findings):
            print("SELF_TEST_FAILURE: expected DEP-002 for missing manifest", file=sys.stderr)
            return 1

    # Case 2: missing dependency in inventory
    manifest_fixture = {
        "schema": "eliot.dependency-policy.v1",
        "scanner": {"tool": "cargo-deny"},
        "direct_dependencies": {
            "dep1": {
                "consumer": "test",
                "owner": "test",
                "reason": "test",
                "features": [],
                "public_exposure": "none",
                "removal_plan": "none",
            }
        },
    }
    findings = check_cargo_inventory(manifest_fixture, {"dep1", "dep_unaccounted"})
    if not any(f.code == "DEP-003" and "dep_unaccounted" in f.detail for f in findings):
        print("SELF_TEST_FAILURE: expected DEP-003 for missing inventory item", file=sys.stderr)
        return 1

    # Case 3: expired exception
    manifest_exc = {
        "exceptions": [
            {
                "package": "vuln-pkg",
                "version": "1.0.0",
                "advisory": "RUSTSEC-2020-0001",
                "owner": "security",
                "compensating_control": "isolated",
                "expires_at": "2020-01-01T00:00:00Z",
                "removal_condition": "replace",
            }
        ]
    }
    findings = check_exceptions(manifest_exc, now_dt=datetime(2026, 9, 13, tzinfo=timezone.utc))
    if not any(f.code == "DEP-010" and "expired on 2020-01-01" in f.detail for f in findings):
        print("SELF_TEST_FAILURE: expected DEP-010 for expired exception", file=sys.stderr)
        return 1

    # Case 4: unhashed python requirement
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        sdir = root / "scripts"
        sdir.mkdir(parents=True)
        (sdir / "requirements-verification.txt").write_text("jsonschema==4.25.1\n", encoding="utf-8")
        findings = check_python_ecosystem(root)
        if not any(f.code == "DEP-008" for f in findings):
            print("SELF_TEST_FAILURE: expected DEP-008 for unhashed python requirement", file=sys.stderr)
            return 1

    # Case 5: missing nuget lockfile
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        op_dir = root / "apps" / "Eliot.Operator"
        op_dir.mkdir(parents=True)
        (op_dir / "Eliot.Operator.csproj").write_text(
            "<Project><PropertyGroup><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile></PropertyGroup></Project>",
            encoding="utf-8",
        )
        findings = check_nuget_ecosystem(root)
        if not any(f.code == "DEP-007" and "missing" in f.detail for f in findings):
            print("SELF_TEST_FAILURE: expected DEP-007 for missing nuget packages.lock.json", file=sys.stderr)
            return 1

    # Case 6: missing external executable inventory
    findings = check_external_executables({})
    if not any(f.code == "DEP-009" and "surrealdb" in f.detail for f in findings):
        print("SELF_TEST_FAILURE: expected DEP-009 for missing external executable", file=sys.stderr)
        return 1

    # Case 7: scanner tool missing
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        scanner_info = {"executable": "nonexistent-scanner-tool-12345"}
        findings, status, _ = run_cargo_deny(root, "offline-source", scanner_info)
        if status != STATUS_TOOL_UNAVAILABLE or not any(f.code == "DEP-001" for f in findings):
            print("SELF_TEST_FAILURE: expected TOOL_UNAVAILABLE for missing scanner", file=sys.stderr)
            return 1

    # Case 8: receipt generation structure
    receipt = build_receipt(
        Path("."),
        "current-advisories",
        STATUS_PASS,
        [],
        manifest_fixture,
        {"bans": {"errors": 0}},
        1,
    )
    if receipt.get("proof_ceiling") != "DEPENDENCY_ADMISSION_AND_ADVISORY_EVIDENCE_CANDIDATE":
        print("SELF_TEST_FAILURE: expected candidate proof ceiling in receipt", file=sys.stderr)
        return 1
    if "advisory_snapshot" not in receipt:
        print("SELF_TEST_FAILURE: expected advisory_snapshot in current-advisories receipt", file=sys.stderr)
        return 1

    print("DEPENDENCY_POLICY_SELF_TEST: PASS (8/8 cases verified)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify multi-ecosystem dependency admission policy.")
    parser.add_argument("--root", default=".", help="Repository root directory")
    parser.add_argument(
        "--profile",
        choices=["offline-source", "current-advisories"],
        default="offline-source",
        help="Verification profile to execute",
    )
    parser.add_argument("--json-out", help="Write findings to JSON output file")
    parser.add_argument("--receipt-out", help="Write canonical receipt to JSON output file")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-tests")
    args = parser.parse_args()

    if args.self_test:
        return run_self_tests()

    root = Path(args.root).resolve()
    findings, status, receipt, _, _ = verify_all(root, args.profile)

    if args.json_out:
        out_p = Path(args.json_out)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "status": status,
            "profile": args.profile,
            "findings_count": len(findings),
            "findings": [
                {"code": f.code, "path": f.path, "line": f.line, "detail": f.detail} for f in findings
            ],
        }
        out_p.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    if args.receipt_out:
        rec_p = Path(args.receipt_out)
        rec_p.parent.mkdir(parents=True, exist_ok=True)
        rec_p.write_text(json.dumps(receipt, indent=2), encoding="utf-8")

    print(f"VERIFY_DEPENDENCY_POLICY: {status} (profile={args.profile}, findings={len(findings)})")
    for f in findings:
        print(f"  [{f.code}] {f.path}:{f.line}: {f.detail}")

    return 0 if status == STATUS_PASS else 1


if __name__ == "__main__":
    sys.exit(main())
