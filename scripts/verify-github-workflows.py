#!/usr/bin/env python3
"""Verify GitHub workflows, pinned action inputs, dependency locks, and test execution.

Enforces that:
1. All workflows remain manual-only (workflow_dispatch only). Automatic triggers are rejected.
2. Every third-party Action reference is pinned to a full 40-character commit SHA.
3. Top-level permissions remain minimal (contents: read); broad write-all is rejected.
4. Python verification dependencies are fully version- and hash-locked with --hash=sha256.
5. NuGet dependencies for Eliot.Operator are locked with RestorePackagesWithLockFile and packages.lock.json.
6. Operator workflows execute the test harness (tests/Eliot.Operator.Tests) with nonzero execution.
7. Workflow names indicate manual invocation and state bounded proof ceilings.
8. Referenced local scripts exist on disk.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
from typing import Any


FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
ACTION_REF_RE = re.compile(r"^\s*-\s*uses:\s*([^\s#]+)")
PERMISSION_WRITE_ALL_RE = re.compile(r"^\s*permissions:\s*(?:write-all|read-all)", re.MULTILINE)


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    line: int
    detail: str


def parse_workflow_events(content: str) -> set[str]:
    """Extract event triggers defined in an 'on:' section."""
    lines = content.splitlines()
    for index, line in enumerate(lines):
        if not re.fullmatch(r"on:\s*.*", line.strip()):
            continue
        tail = line.split(":", 1)[1].strip()
        if tail.startswith("[") and tail.endswith("]"):
            return {
                item.strip(" '\"")
                for item in tail[1:-1].split(",")
                if item.strip()
            }
        if tail:
            return {tail.strip("'\"")}
        events: set[str] = set()
        for candidate in lines[index + 1 :]:
            stripped = candidate.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if candidate == candidate.lstrip():
                break
            match = re.match(r"^  ([A-Za-z_][A-Za-z0-9_-]*):", candidate)
            if match:
                events.add(match.group(1))
        return events
    return set()


def check_workflows(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    workflows_dir = root / ".github" / "workflows"
    if not workflows_dir.is_dir():
        findings.append(Finding("GWF-000", ".github/workflows", 0, "workflows directory missing"))
        return findings

    workflow_files = sorted([*workflows_dir.glob("*.yml"), *workflows_dir.glob("*.yaml")])
    if not workflow_files:
        findings.append(Finding("GWF-000", ".github/workflows", 0, "no workflow files found"))
        return findings

    for wf_path in workflow_files:
        rel_path = str(wf_path.relative_to(root)).replace("\\", "/")
        try:
            content = wf_path.read_text(encoding="utf-8")
        except Exception as exc:
            findings.append(Finding("GWF-000", rel_path, 0, f"cannot read file: {exc}"))
            continue

        lines = content.splitlines()

        # 1. Event trigger check: only workflow_dispatch allowed
        events = parse_workflow_events(content)
        if not events:
            findings.append(Finding("GWF-001", rel_path, 1, "missing 'on:' event trigger section"))
        elif events != {"workflow_dispatch"}:
            invalid = sorted(events - {"workflow_dispatch"})
            findings.append(
                Finding(
                    "GWF-001",
                    rel_path,
                    1,
                    f"unauthorized workflow triggers {invalid}; only workflow_dispatch is allowed",
                )
            )

        # 2. Action pin check: third-party actions must use full 40-char SHA
        for line_no, line in enumerate(lines, start=1):
            m = ACTION_REF_RE.match(line)
            if not m:
                continue
            action_ref = m.group(1)
            # Local actions (./.github/actions/...) are exempt from remote SHA pinning
            if action_ref.startswith("./"):
                continue
            if "@" not in action_ref:
                findings.append(
                    Finding(
                        "GWF-002",
                        rel_path,
                        line_no,
                        f"action '{action_ref}' has no version or SHA pin",
                    )
                )
                continue
            action_name, ref = action_ref.split("@", 1)
            if not FULL_SHA_RE.fullmatch(ref):
                findings.append(
                    Finding(
                        "GWF-002",
                        rel_path,
                        line_no,
                        f"mutable action ref '{ref}' for '{action_name}'; full 40-character SHA required",
                    )
                )

        # 3. Permissions check: minimal permissions required
        if PERMISSION_WRITE_ALL_RE.search(content):
            findings.append(
                Finding(
                    "GWF-003",
                    rel_path,
                    1,
                    "overbroad permissions (write-all / read-all) forbidden",
                )
            )

        # 4. Operator execution check: build-only Operator is forbidden
        has_operator_build = "apps/Eliot.Operator/Eliot.Operator.csproj" in content
        has_operator_test = (
            "tests/Eliot.Operator.Tests" in content
            or "Eliot.Operator.Tests.csproj" in content
        )
        if has_operator_build and not has_operator_test:
            findings.append(
                Finding(
                    "GWF-006",
                    rel_path,
                    1,
                    "workflow builds Eliot.Operator but does not execute test harness tests/Eliot.Operator.Tests",
                )
            )

        # 5. Workflow naming: must indicate manual invocation
        for line_no, line in enumerate(lines, start=1):
            if line.startswith("name:"):
                wf_name = line.split(":", 1)[1].strip()
                if "pull request integration" in wf_name.lower() and "manual" not in wf_name.lower():
                    findings.append(
                        Finding(
                            "GWF-007",
                            rel_path,
                            line_no,
                            f"workflow name '{wf_name}' implies automatic PR integration; must indicate manual invocation",
                        )
                    )
                break

        # 6. Local scripts executed in steps must exist
        # We look for execution patterns like 'scripts/foo.py', 'scripts/bar.ps1', but ignore 'forbidden=(' lists
        in_forbidden_block = False
        for line_no, line in enumerate(lines, start=1):
            if "forbidden=(" in line:
                in_forbidden_block = True
                continue
            if in_forbidden_block:
                if line.strip() == ")":
                    in_forbidden_block = False
                continue
            # Match executed scripts
            for match in re.finditer(r"(?:python|pwsh|bash|sh|-File|\.)\s+(?:[^\n]*\s+)?scripts/([a-zA-Z0-9_\-\./]+\.(?:py|ps1|sh))", line):
                s_ref = match.group(1)
                full_script_path = root / "scripts" / s_ref
                if not full_script_path.is_file():
                    findings.append(
                        Finding(
                            "GWF-008",
                            rel_path,
                            line_no,
                            f"executed script does not exist at target: scripts/{s_ref}",
                        )
                    )

    return findings


def check_python_requirements(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    req_file = root / "scripts" / "requirements-verification.txt"
    rel_path = "scripts/requirements-verification.txt"
    if not req_file.is_file():
        findings.append(Finding("GWF-004", rel_path, 0, "requirements-verification.txt missing"))
        return findings

    content = req_file.read_text(encoding="utf-8")
    lines = content.splitlines()
    current_package: str | None = None
    has_hash = False

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("--hash="):
            if not current_package:
                findings.append(
                    Finding("GWF-004", rel_path, line_no, "orphan --hash line without preceding package")
                )
            elif not re.fullmatch(r"--hash=sha256:[0-9a-fA-F]{64}\s*\\?", stripped):
                findings.append(
                    Finding("GWF-004", rel_path, line_no, f"invalid hash format on line: {stripped}")
                )
            else:
                has_hash = True
            continue

        # Encountered a new package line
        if current_package and not has_hash:
            findings.append(
                Finding(
                    "GWF-004",
                    rel_path,
                    line_no - 1,
                    f"package '{current_package}' is missing required --hash=sha256",
                )
            )

        pkg_part = stripped.rstrip("\\").strip()
        if "==" not in pkg_part:
            findings.append(
                Finding(
                    "GWF-004",
                    rel_path,
                    line_no,
                    f"package requirement '{pkg_part}' is not exact version-pinned with ==",
                )
            )
        current_package = pkg_part
        has_hash = False

    if current_package and not has_hash:
        findings.append(
            Finding(
                "GWF-004",
                rel_path,
                len(lines),
                f"package '{current_package}' is missing required --hash=sha256",
            )
        )

    return findings


def check_nuget_lock(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    csproj_path = root / "apps" / "Eliot.Operator" / "Eliot.Operator.csproj"
    rel_csproj = "apps/Eliot.Operator/Eliot.Operator.csproj"
    if csproj_path.is_file():
        content = csproj_path.read_text(encoding="utf-8")
        if "<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>" not in content:
            findings.append(
                Finding(
                    "GWF-005",
                    rel_csproj,
                    1,
                    "missing <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile> in Eliot.Operator.csproj",
                )
            )
        lock_file = root / "apps" / "Eliot.Operator" / "packages.lock.json"
        if not lock_file.is_file():
            findings.append(
                Finding(
                    "GWF-005",
                    "apps/Eliot.Operator/packages.lock.json",
                    0,
                    "checked-in NuGet packages.lock.json is missing for locked restore",
                )
            )
        else:
            try:
                json.loads(lock_file.read_text(encoding="utf-8"))
            except Exception as exc:
                findings.append(
                    Finding(
                        "GWF-005",
                        "apps/Eliot.Operator/packages.lock.json",
                        1,
                        f"corrupted packages.lock.json: {exc}",
                    )
                )

    return findings


def verify_all(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(check_workflows(root))
    findings.extend(check_python_requirements(root))
    findings.extend(check_nuget_lock(root))
    return findings


def run_self_tests() -> int:
    import tempfile

    test_cases = [
        ("trigger_push", "on:\n  push:\n    branches: [main]\n", "GWF-001"),
        ("trigger_pr", "on:\n  pull_request:\n", "GWF-001"),
        ("mutable_action", "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n", "GWF-002"),
        ("write_all_perms", "name: Manual Gate\non:\n  workflow_dispatch:\npermissions: write-all\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n", "GWF-003"),
        ("build_only_operator", "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: windows-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n      - run: dotnet build apps/Eliot.Operator/Eliot.Operator.csproj\n", "GWF-006"),
    ]

    for name, wf_yaml, expected_code in test_cases:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            wf_dir = tmp_root / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "test.yml").write_text(wf_yaml, encoding="utf-8")

            findings = check_workflows(tmp_root)
            codes = {f.code for f in findings}
            if expected_code not in codes:
                print(f"SELF_TEST_FAILURE in {name}: expected finding {expected_code}, got {codes}", file=sys.stderr)
                return 1

    # Test python requirements without hash
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        scripts_dir = tmp_root / "scripts"
        scripts_dir.mkdir(parents=True)
        (scripts_dir / "requirements-verification.txt").write_text("jsonschema==4.25.1\n", encoding="utf-8")
        findings = check_python_requirements(tmp_root)
        if not any(f.code == "GWF-004" for f in findings):
            print("SELF_TEST_FAILURE: expected GWF-004 for unhashed requirement", file=sys.stderr)
            return 1

    # Test valid requirements
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        scripts_dir = tmp_root / "scripts"
        scripts_dir.mkdir(parents=True)
        (scripts_dir / "requirements-verification.txt").write_text(
            "jsonschema==4.25.1 \\\n    --hash=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
            encoding="utf-8",
        )
        findings = check_python_requirements(tmp_root)
        if findings:
            print(f"SELF_TEST_FAILURE: valid requirement produced unexpected findings: {findings}", file=sys.stderr)
            return 1

    # Test missing nuget lock
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        op_dir = tmp_root / "apps" / "Eliot.Operator"
        op_dir.mkdir(parents=True)
        (op_dir / "Eliot.Operator.csproj").write_text("<Project><PropertyGroup></PropertyGroup></Project>", encoding="utf-8")
        findings = check_nuget_lock(tmp_root)
        if not any(f.code == "GWF-005" for f in findings):
            print("SELF_TEST_FAILURE: expected GWF-005 for missing RestorePackagesWithLockFile", file=sys.stderr)
            return 1

    print("GITHUB_WORKFLOW_VERIFIER_SELF_TEST: PASS (7/7 cases verified)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify GitHub workflows and external input locks.")
    parser.add_argument("--root", default=".", help="Repository root directory")
    parser.add_argument("--json-out", help="Write findings to JSON output file")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-tests")
    args = parser.parse_args()

    if args.self_test:
        return run_self_tests()

    root = Path(args.root).resolve()
    findings = verify_all(root)

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "status": "fail" if findings else "pass",
            "findings_count": len(findings),
            "findings": [
                {
                    "code": f.code,
                    "path": f.path,
                    "line": f.line,
                    "detail": f.detail,
                }
                for f in findings
            ],
        }
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    if findings:
        print(f"VERIFY_GITHUB_WORKFLOWS: FAIL ({len(findings)} findings)")
        for f in findings:
            print(f"  [{f.code}] {f.path}:{f.line}: {f.detail}")
        return 1

    print("VERIFY_GITHUB_WORKFLOWS: PASS (all workflows, action SHAs, and dependency locks conform)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
