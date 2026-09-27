#!/usr/bin/env python3
"""Verify GitHub workflows, pinned action inputs, dependency locks, and test execution.

Enforces that:
1. Triggers follow a closed per-workflow policy (accepted issue #3004): every
   workflow is workflow_dispatch-only except ci.yml, the sole automatic
   compile-only merge check (workflow_dispatch, main-scoped pull_request and
   push). pull_request_target, schedules, releases, merge queue and every
   other automatic trigger are rejected on every workflow.
2. Every third-party Action is verified by immutable identity (issue #1225 step
   2): the reference must be a reviewed full 40-character commit SHA owned by an
   approved action owner, the human-readable release stays comment-only metadata,
   mutable tags/branches/short SHAs/expressions are rejected, the same action may
   not carry two different pins across workflows, and every reference's
   owner/repository/SHA identity is derived from the files and published in the
   --json-out payload as the first step toward the run manifest.
3. Top-level permissions remain minimal (contents: read); broad write-all is rejected.
4. Python verification dependencies are fully version- and hash-locked with --hash=sha256.
5. NuGet dependencies for Eliot.Operator and the Eliot.Operator.Tests harness
   are locked with RestorePackagesWithLockFile and checked-in
   packages.lock.json files, so locked-mode restore fails on drift.
6. Operator coverage is classified by workflow/profile class (issue #3004):
   MergeCompile workflows restore/build both Operator projects through the
   shared profile with zero execution and no execution claim; every other
   workflow that builds Eliot.Operator executes tests/Eliot.Operator.Tests.
7. Workflow names indicate manual invocation and state bounded proof ceilings.
8. Referenced local scripts exist on disk.
9. Workflow pip installs consume only the hash-locked
   scripts/requirements-verification.txt with --require-hashes.
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
# Step-level `- uses:` and job-level reusable `uses:` (no dash). The capture
# stops at the first whitespace or `#`, so a trailing `# v4.2.2` release
# annotation is comment metadata and never becomes part of the ref.
ACTION_REF_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")
# Action identity shape: owner/repo[/path...]@ref. A `${{ ... }}` ref fails the
# full 40-hex ref test, and a reference without an owner segment fails the
# owner-shape test, so neither can silently reach the pin decision.
ACTION_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9._-]+)+$")
PERMISSION_WRITE_ALL_RE = re.compile(r"^\s*permissions:\s*(?:write-all|read-all)", re.MULTILINE)

# Closed approved action owner set (issue #1225 step 2, Wave D "unapproved
# owners"). Evidence-derived, not aspirational: `actions` is the only owner any
# workflow in this repository references. A third-party `uses:` whose owner
# segment is not listed here is rejected (GWF-002) even when it carries a
# syntactically valid full 40-hex SHA, so a well-formed pin cannot smuggle in an
# unreviewed publisher. Adding an owner is a reviewed change to this constant
# together with the workflow reference that introduces it; never a discovery
# result. There is deliberately no wildcard and no org-prefix matching.
APPROVED_ACTION_OWNERS = ("actions",)

# Closed per-workflow trigger policy (accepted issue #3004). Default: every
# repository workflow is manual-only. ci.yml is the sole exception: the
# automatic compile-only merge check.
DEFAULT_ALLOWED_EVENTS = {"workflow_dispatch"}
WORKFLOW_EVENT_EXCEPTIONS = {
    "ci.yml": {"workflow_dispatch", "pull_request", "push"},
}
# ci.yml exception scoping: automatic events are main-only, and PR activity
# must cover every open/update/reopen/ready transition (an absent types key
# keeps the GitHub default, which covers them).
CI_MAIN_BRANCHES = ["main"]
CI_REQUIRED_PR_TYPES = {"opened", "synchronize", "reopened", "ready_for_review"}
# Compile-only workflow/profile class marker (issue #3004 item 8).
COMPILE_ONLY_PROFILE_MARKER = "-Profile MergeCompile"


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


def event_scalar_list(content: str, event: str, key: str) -> list[str] | None:
    """Values under `key:` inside one top-level event block.

    Returns None when the event is absent, [] when the event is present
    without the key, otherwise the listed values (flow or block style).
    """
    lines = content.splitlines()
    values: list[str] | None = None
    in_list = False
    for line in lines:
        if values is None:
            if re.match(rf"^  {re.escape(event)}:\s*(#.*)?$", line):
                values = []
            continue
        if re.match(r"^  [A-Za-z_][A-Za-z0-9_-]*:\s*(#.*)?$", line):
            break
        if line.strip() and line == line.lstrip():
            break
        key_match = re.match(rf"^    {re.escape(key)}:\s*(.*)$", line)
        if key_match:
            tail = key_match.group(1).split("#", 1)[0].strip()
            if tail.startswith("["):
                return [
                    item.strip(" '\"")
                    for item in tail.strip("[]").split(",")
                    if item.strip()
                ]
            in_list = True
            continue
        if in_list:
            item_match = re.match(r"^      -\s*(\S+)", line)
            if item_match:
                values.append(item_match.group(1).strip("'\""))
            elif line.strip() and not line.startswith("      ") and not line.strip().startswith("#"):
                in_list = False
    return values


def check_workflows(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    workflows_dir = root / ".github" / "workflows"
    if not workflows_dir.is_dir():
        findings.append(Finding("GWF-000", ".github/workflows", 0, "workflows directory missing"))
        return findings

    workflow_files = iter_workflow_files(root)
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

        # 1. Event trigger check: closed per-workflow policy (issue #3004).
        # Default is workflow_dispatch-only; ci.yml is the sole automatic
        # exception with main-scoped pull_request/push.
        events = parse_workflow_events(content)
        allowed_events = WORKFLOW_EVENT_EXCEPTIONS.get(wf_path.name, DEFAULT_ALLOWED_EVENTS)
        if not events:
            findings.append(Finding("GWF-001", rel_path, 1, "missing 'on:' event trigger section"))
        elif events != allowed_events:
            invalid = sorted(events - allowed_events)
            findings.append(
                Finding(
                    "GWF-001",
                    rel_path,
                    1,
                    f"unauthorized workflow triggers {invalid} for {wf_path.name}; only {sorted(allowed_events)} allowed",
                )
            )
        if wf_path.name in WORKFLOW_EVENT_EXCEPTIONS:
            for scoped_event in ("pull_request", "push"):
                if scoped_event in events:
                    branches = event_scalar_list(content, scoped_event, "branches")
                    if branches != CI_MAIN_BRANCHES:
                        findings.append(
                            Finding(
                                "GWF-001",
                                rel_path,
                                1,
                                f"{wf_path.name} {scoped_event} must target branches {CI_MAIN_BRANCHES}",
                            )
                        )
            pr_types = event_scalar_list(content, "pull_request", "types")
            if pr_types is not None and pr_types:
                missing_types = sorted(CI_REQUIRED_PR_TYPES - set(pr_types))
                if missing_types:
                    findings.append(
                        Finding(
                            "GWF-001",
                            rel_path,
                            1,
                            f"{wf_path.name} pull_request types miss required activity {missing_types}",
                        )
                    )

        # 2. Action identity check (issue #1225 step 2): every third-party `uses:`
        # is a reviewed full 40-character commit SHA owned by an approved action
        # owner. The capture below is used for the owner decision, not only for
        # the error message, so a well-formed SHA from an unreviewed publisher
        # still fails. ACTION_REF_RE covers both step-level `- uses:` and
        # job-level reusable `uses:` (no dash), so a reusable workflow cannot
        # escape the pin rule.
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
            # Identity shape: a reference with no owner segment is not an
            # identity this verifier can attest, so it fails on its own code
            # rather than being attributed to the mutable-ref rule.
            if not ACTION_NAME_RE.fullmatch(action_name):
                findings.append(
                    Finding(
                        "GWF-010",
                        rel_path,
                        line_no,
                        f"action reference '{action_ref}' is not an owner/repository identity; "
                        f"expected owner/repo[/path]@<40-hex SHA> with owner in {list(APPROVED_ACTION_OWNERS)}",
                    )
                )
                continue
            if action_name.split("/")[0] not in APPROVED_ACTION_OWNERS:
                findings.append(
                    Finding(
                        "GWF-002",
                        rel_path,
                        line_no,
                        f"unapproved action owner '{action_name.split('/')[0]}' for '{action_name}'; "
                        f"approved owners are {list(APPROVED_ACTION_OWNERS)}",
                    )
                )
                continue
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

        # 4. Operator coverage check, classified by workflow/profile class
        # (issue #3004 item 8). Compile-only MergeCompile workflows restore
        # and build both Operator projects through the shared profile with
        # zero execution and no execution claim. Every other workflow that
        # builds Eliot.Operator must execute the harness (unchanged rule).
        has_operator_build = "apps/Eliot.Operator/Eliot.Operator.csproj" in content
        has_operator_test = (
            "tests/Eliot.Operator.Tests" in content
            or "Eliot.Operator.Tests.csproj" in content
        )
        # Closed compile-only class: ci.yml is the single workflow that may
        # invoke the MergeCompile profile. repository-policy.yml names the
        # profile only inside its own checker prose (not an invocation) and
        # is exempt; any other file carrying the marker is rejected.
        invokes_mergecompile = COMPILE_ONLY_PROFILE_MARKER in content
        is_compile_only = wf_path.name == "ci.yml" and invokes_mergecompile
        if invokes_mergecompile and wf_path.name not in ("ci.yml", "repository-policy.yml"):
            findings.append(
                Finding(
                    "GWF-006",
                    rel_path,
                    1,
                    f"only ci.yml may invoke {COMPILE_ONLY_PROFILE_MARKER}",
                )
            )
        if is_compile_only:
            if re.search(r"dotnet\s+(run|test|vstest)\b", content):
                findings.append(
                    Finding(
                        "GWF-006",
                        rel_path,
                        1,
                        "compile-only MergeCompile workflow must not execute dotnet run/test",
                    )
                )
            if "Operator tests: executed" in content:
                findings.append(
                    Finding(
                        "GWF-006",
                        rel_path,
                        1,
                        "compile-only MergeCompile workflow must not claim Operator test execution",
                    )
                )
            verify_ps1 = root / "scripts" / "verify.ps1"
            if verify_ps1.is_file():
                try:
                    verify_text = verify_ps1.read_text(encoding="utf-8")
                except Exception as exc:
                    findings.append(
                        Finding("GWF-006", rel_path, 1, f"cannot read scripts/verify.ps1: {exc}")
                    )
                    verify_text = ""
                for need in (
                    "dotnet restore",
                    "dotnet build",
                    "apps/Eliot.Operator/Eliot.Operator.csproj",
                    "tests/Eliot.Operator.Tests/Eliot.Operator.Tests.csproj",
                ):
                    if need not in verify_text:
                        findings.append(
                            Finding(
                                "GWF-006",
                                rel_path,
                                1,
                                f"MergeCompile profile lacks required Operator coverage: {need}",
                            )
                        )
                if re.search(r"dotnet\s+(run|test|vstest)\b", verify_text):
                    findings.append(
                        Finding(
                            "GWF-006",
                            rel_path,
                            1,
                            "verify.ps1 must not execute dotnet run/test in the compile-only class",
                        )
                    )
        elif has_operator_build and not has_operator_test:
            findings.append(
                Finding(
                    "GWF-006",
                    rel_path,
                    1,
                    "workflow builds Eliot.Operator but does not execute test harness tests/Eliot.Operator.Tests",
                )
            )

        # 5. Workflow naming: manual workflows must indicate manual
        # invocation; ci.yml (the automatic exception) must instead state
        # its compile-only ceiling.
        for line_no, line in enumerate(lines, start=1):
            if line.startswith("name:"):
                wf_name = line.split(":", 1)[1].strip()
                if wf_path.name == "ci.yml":
                    if "compile" not in wf_name.lower():
                        findings.append(
                            Finding(
                                "GWF-007",
                                rel_path,
                                line_no,
                                f"workflow name '{wf_name}' is the automatic ci.yml exception but does not state its compile-only ceiling",
                            )
                        )
                elif "pull request integration" in wf_name.lower() and "manual" not in wf_name.lower():
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


def iter_workflow_files(root: Path) -> list[Path]:
    """Every workflow file in the one closed directory, deterministically ordered."""
    workflows_dir = root / ".github" / "workflows"
    if not workflows_dir.is_dir():
        return []
    return sorted([*workflows_dir.glob("*.yml"), *workflows_dir.glob("*.yaml")])


def iter_action_references(root: Path):
    """Yield (rel_path, line_no, action_ref) for every third-party `uses:` ref.

    Derived from the files, never hand-written. Mirrors the ACTION_REF_RE handling
    in check_workflows, including the `./` local-action exemption, so the
    identity record and the enforcement decision can never disagree about which
    references are in scope.
    """
    for wf_path in iter_workflow_files(root):
        rel_path = str(wf_path.relative_to(root)).replace("\\", "/")
        try:
            lines = wf_path.read_text(encoding="utf-8").splitlines()
        except Exception:
            continue
        for line_no, line in enumerate(lines, start=1):
            match = ACTION_REF_RE.match(line)
            if not match:
                continue
            action_ref = match.group(1)
            if action_ref.startswith("./"):
                continue
            yield rel_path, line_no, action_ref


def collect_action_identities(root: Path) -> list[dict[str, str]]:
    """Derived owner/repository/SHA identity for every third-party `uses:` ref.

    This is the source of truth for the run manifest's action record: no workflow
    hand-types its action list. The returned list is sorted by
    (workflow, line, action, ref) so repeated runs over an unchanged tree produce
    a byte-identical payload, and it is bounded by the number of `uses:` lines in
    the repository. `ref` is empty when the reference carries no `@` pin, so an
    unpinned reference is still recorded rather than silently dropped.
    """
    records: list[dict[str, str]] = []
    for rel_path, line_no, action_ref in iter_action_references(root):
        if "@" in action_ref:
            action_name, ref = action_ref.split("@", 1)
        else:
            action_name, ref = action_ref, ""
        records.append(
            {
                "workflow": rel_path,
                "line": str(line_no),
                "action": action_name,
                "ref": ref,
            }
        )
    records.sort(key=lambda r: (r["workflow"], int(r["line"]), r["action"], r["ref"]))
    return records


def check_action_pin_divergence(root: Path) -> list[Finding]:
    """One action, one pin: reject the same action carried at two different SHAs.

    Without this, a future workflow can silently introduce a different (possibly
    compromised) commit for an action the repository already pins, and every
    per-file check still passes because each reference is individually
    well-formed. The first workflow in deterministic order is the reference
    observation and is never itself a finding; each divergent reference is.
    """
    findings: list[Finding] = []
    first_ref: dict[str, tuple[str, int, str]] = {}
    for rel_path, line_no, action_ref in iter_action_references(root):
        if "@" not in action_ref:
            continue
        action_name, ref = action_ref.split("@", 1)
        if not ACTION_NAME_RE.fullmatch(action_name):
            continue
        observed = first_ref.get(action_name)
        if observed is None:
            first_ref[action_name] = (rel_path, line_no, ref)
            continue
        if ref == observed[2]:
            continue
        findings.append(
            Finding(
                "GWF-011",
                rel_path,
                line_no,
                f"action '{action_name}' diverges from its repository pin: "
                f"{ref} here but {observed[2]} at {observed[0]}:{observed[1]}; "
                "one action carries one reviewed commit SHA across all workflows",
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


NUGET_LOCKED_PROJECTS = (
    ("apps/Eliot.Operator/Eliot.Operator.csproj", "apps/Eliot.Operator/packages.lock.json"),
    ("tests/Eliot.Operator.Tests/Eliot.Operator.Tests.csproj", "tests/Eliot.Operator.Tests/packages.lock.json"),
)


def check_nuget_lock(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for rel_csproj, rel_lock in NUGET_LOCKED_PROJECTS:
        csproj_path = root.joinpath(*rel_csproj.split("/"))
        if not csproj_path.is_file():
            continue
        content = csproj_path.read_text(encoding="utf-8")
        if "<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>" not in content:
            findings.append(
                Finding(
                    "GWF-005",
                    rel_csproj,
                    1,
                    f"missing <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile> in {rel_csproj}",
                )
            )
        lock_file = root.joinpath(*rel_lock.split("/"))
        if not lock_file.is_file():
            findings.append(
                Finding(
                    "GWF-005",
                    rel_lock,
                    0,
                    f"checked-in NuGet {rel_lock} is missing for locked restore",
                )
            )
        else:
            try:
                json.loads(lock_file.read_text(encoding="utf-8"))
            except Exception as exc:
                findings.append(
                    Finding(
                        "GWF-005",
                        rel_lock,
                        1,
                        f"corrupted {rel_lock}: {exc}",
                    )
                )

    return findings


def check_pip_install_lock(root: Path) -> list[Finding]:
    """Every workflow pip install must consume the hash-locked closure."""
    findings: list[Finding] = []
    workflows_dir = root / ".github" / "workflows"
    if not workflows_dir.is_dir():
        return findings
    for wf_path in sorted([*workflows_dir.glob("*.yml"), *workflows_dir.glob("*.yaml")]):
        rel_path = str(wf_path.relative_to(root)).replace("\\", "/")
        try:
            lines = wf_path.read_text(encoding="utf-8").splitlines()
        except Exception:
            continue
        for line_no, line in enumerate(lines, start=1):
            if "pip install" not in line:
                continue
            if "--require-hashes" not in line or "scripts/requirements-verification.txt" not in line:
                findings.append(
                    Finding(
                        "GWF-009",
                        rel_path,
                        line_no,
                        "pip install must use --require-hashes -r scripts/requirements-verification.txt",
                    )
                )
    return findings


def verify_all(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(check_workflows(root))
    findings.extend(check_action_pin_divergence(root))
    findings.extend(check_python_requirements(root))
    findings.extend(check_nuget_lock(root))
    findings.extend(check_pip_install_lock(root))
    return findings


def run_self_tests() -> int:
    import tempfile

    # (name, filename, workflow yaml, expected finding or None for clean[, extra files]).
    # Negative fixtures stay on test.yml (default dispatch-only policy); the
    # ci.yml exception and the compile-only Operator class get their own cases.
    ci_triggers = (
        "on:\n  workflow_dispatch:\n  pull_request:\n    branches: [main]\n"
        "    types: [opened, synchronize, reopened, ready_for_review]\n  push:\n    branches: [main]\n"
    )
    ci_prefix = "name: Automatic PR Merge Compile Gate\n" + ci_triggers + "permissions:\n  contents: read\n"
    # Action-identity fixtures (issue #1225 step 2). `gate_yaml` wraps a
    # `uses:` body in an otherwise conforming manual-dispatch workflow so a
    # rejection can only come from the action rule under test.
    gate_yaml = (
        "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n"
        "    runs-on: ubuntu-latest\n    steps:\n      {body}\n"
    )
    # A second 40-hex SHA, so divergence cases are distinguishable from the
    # reviewed actions/checkout pin by value and not only by position.
    other_sha = "a" * 40

    def step_uses(ref: str) -> str:
        return gate_yaml.format(body=f"- uses: {ref}")

    def job_uses(ref: str) -> str:
        # Job-level reusable workflow: `uses:` at job scope carries no dash.
        return (
            "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\n"
            "jobs:\n  t:\n    uses: " + ref + "\n"
        )

    test_cases = [
        ("trigger_push", "test.yml", "on:\n  push:\n    branches: [main]\n", "GWF-001"),
        ("trigger_pr", "test.yml", "on:\n  pull_request:\n", "GWF-001"),
        ("mutable_action", "test.yml", "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n", "GWF-002"),
        ("write_all_perms", "test.yml", "name: Manual Gate\non:\n  workflow_dispatch:\npermissions: write-all\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n", "GWF-003"),
        ("build_only_operator", "test.yml", "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: windows-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n      - run: dotnet build apps/Eliot.Operator/Eliot.Operator.csproj\n", "GWF-006"),
        ("ci_exception_accepted", "ci.yml", ci_prefix + "jobs:\n  check:\n    runs-on: windows-latest\n    steps:\n      # invokes -Profile MergeCompile through the shared profile owner\n      - run: echo merge-compile-check\n", None),
        ("ci_pr_target_rejected", "ci.yml", "name: Automatic PR Merge Compile Gate\non:\n  workflow_dispatch:\n  pull_request_target:\n    branches: [main]\n  push:\n    branches: [main]\npermissions:\n  contents: read\njobs:\n  check:\n    runs-on: windows-latest\n    steps:\n      - run: echo never\n", "GWF-001"),
        ("ci_unscoped_push_rejected", "ci.yml", "name: Automatic PR Merge Compile Gate\non:\n  workflow_dispatch:\n  pull_request:\n    branches: [main]\n  push:\npermissions:\n  contents: read\njobs:\n  check:\n    runs-on: windows-latest\n    steps:\n      - run: echo never\n", "GWF-001"),
        ("other_workflow_push_rejected", "policy.yml", "name: Manual Policy Gate\non:\n  workflow_dispatch:\n  push:\n    branches: [main]\npermissions:\n  contents: read\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo never\n", "GWF-001"),
        ("mergecompile_dotnet_run_rejected", "ci.yml", ci_prefix + "jobs:\n  check:\n    runs-on: windows-latest\n    steps:\n      - run: pwsh -NoProfile -File scripts/verify.ps1 -Profile MergeCompile\n      - run: dotnet test tests/Eliot.Operator.Tests/Eliot.Operator.Tests.csproj\n", "GWF-006"),
        ("mergecompile_claim_rejected", "ci.yml", ci_prefix + "jobs:\n  check:\n    runs-on: windows-latest\n    steps:\n      # invokes -Profile MergeCompile through the shared profile owner\n      - run: echo \"Operator tests: executed Eliot.Operator.Tests\"\n", "GWF-006"),
        ("mergecompile_clean_accepted", "ci.yml", ci_prefix + "jobs:\n  check:\n    runs-on: windows-latest\n    steps:\n      # invokes -Profile MergeCompile through the shared profile owner\n      - run: echo merge-compile-check\n", None, {"scripts/verify.ps1": "# stub profile owner\ndotnet restore apps/Eliot.Operator/Eliot.Operator.csproj --locked-mode\ndotnet restore tests/Eliot.Operator.Tests/Eliot.Operator.Tests.csproj --locked-mode\ndotnet build apps/Eliot.Operator/Eliot.Operator.csproj\ndotnet build tests/Eliot.Operator.Tests/Eliot.Operator.Tests.csproj\n"}),
        ("mergecompile_elsewhere_rejected", "extra.yml", "name: Manual Extra Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  check:\n    runs-on: windows-latest\n    steps:\n      - run: pwsh -NoProfile -File scripts/verify.ps1 -Profile MergeCompile\n", "GWF-006"),
        ("policy_checker_exempt", "repository-policy.yml", "name: Manual Repository Policy Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"asserts -Profile MergeCompile wiring\"\n", None),
        # --- Action identity (issue #1225 step 2) ---
        # An unapproved owner fails even with a syntactically perfect 40-hex
        # SHA: a valid pin is not on its own an approved identity.
        ("unapproved_owner_rejected", "test.yml", step_uses(f"evilcorp/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"), "GWF-002"),
        # Job-level reusable workflow `uses:` has no leading dash. This is the
        # blind spot the dash-optional ACTION_REF_RE closes: a mutable ref here
        # was previously not parsed at all.
        ("reusable_workflow_mutable_ref_rejected", "test.yml", job_uses("actions/reusable/.github/workflows/x.yml@v1"), "GWF-002"),
        ("reusable_workflow_expression_rejected", "test.yml", job_uses("actions/reusable/.github/workflows/x.yml@${{ inputs.ref }}"), "GWF-002"),
        ("reusable_workflow_pinned_accepted", "test.yml", job_uses("actions/reusable/.github/workflows/x.yml@11bd71901bbe5b1630ceea73d27597364c9af683"), None),
        ("expression_ref_rejected", "test.yml", step_uses("actions/checkout@${{ env.ACTION_SHA }}"), "GWF-002"),
        ("short_sha_rejected", "test.yml", step_uses("actions/checkout@11bd7190"), "GWF-002"),
        ("branch_ref_rejected", "test.yml", step_uses("actions/checkout@main"), "GWF-002"),
        ("wildcard_ref_rejected", "test.yml", step_uses("actions/checkout@*"), "GWF-002"),
        # No owner segment: the reference is not an owner/repository identity.
        ("malformed_action_name_rejected", "test.yml", step_uses(f"checkout@11bd71901bbe5b1630ceea73d27597364c9af683"), "GWF-010"),
        # The pre-existing no-`@` branch is reached first and is unchanged: a
        # reference with neither an owner segment nor a pin is reported as an
        # unpinned action, not reclassified as a malformed identity.
        ("unpinned_action_rejected", "test.yml", step_uses("checkout"), "GWF-002"),
        ("approved_owner_full_sha_accepted", "test.yml", step_uses("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2"), None),
        # Divergence is a repository-level rule: it needs two workflow files, so
        # it runs as a dedicated block below rather than in this single-file table.
    ]

    for case in test_cases:
        name, filename, wf_yaml, expected_code = case[:4]
        extra_files = case[4] if len(case) > 4 else {}
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            wf_dir = tmp_root / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / filename).write_text(wf_yaml, encoding="utf-8")
            for rel_extra, body_extra in extra_files.items():
                extra_path = tmp_root / rel_extra
                extra_path.parent.mkdir(parents=True, exist_ok=True)
                extra_path.write_text(body_extra, encoding="utf-8")

            findings = check_workflows(tmp_root)
            codes = {f.code for f in findings}
            if expected_code is None:
                if findings:
                    print(f"SELF_TEST_FAILURE in {name}: expected clean, got {findings}", file=sys.stderr)
                    return 1
            elif expected_code not in codes:
                print(f"SELF_TEST_FAILURE in {name}: expected finding {expected_code}, got {codes}", file=sys.stderr)
                return 1

    # Cross-workflow pin divergence (issue #1225 step 2): the same action at two
    # different SHAs is a finding, and one SHA everywhere is clean. Each pair of
    # workflows is individually well-formed, so only the repository-level check
    # can reject the divergent pair.
    divergence_cases = [
        ("divergent_pin_rejected", step_uses(f"actions/checkout@{other_sha}"), True),
        ("consistent_pin_accepted", step_uses("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"), False),
    ]
    for name, second_workflow, expect_finding in divergence_cases:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            wf_dir = tmp_root / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "a.yml").write_text(
                step_uses("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"),
                encoding="utf-8",
            )
            (wf_dir / "b.yml").write_text(second_workflow, encoding="utf-8")
            findings = check_action_pin_divergence(tmp_root)
            if expect_finding and not any(f.code == "GWF-011" for f in findings):
                print(
                    f"SELF_TEST_FAILURE in {name}: expected GWF-011 for divergent action pin, got {findings}",
                    file=sys.stderr,
                )
                return 1
            if not expect_finding and findings:
                print(
                    f"SELF_TEST_FAILURE in {name}: consistent pin produced unexpected findings: {findings}",
                    file=sys.stderr,
                )
                return 1

    # The identity record is derived from the files and deterministic: the same
    # tree yields the same sorted records, and every third-party ref is present
    # including the job-level (no dash) form.
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        wf_dir = tmp_root / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "b.yml").write_text(
            step_uses("actions/cache@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0"), encoding="utf-8"
        )
        (wf_dir / "a.yml").write_text(
            step_uses("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2")
            + job_uses(f"actions/reusable/.github/workflows/x.yml@{other_sha}"),
            encoding="utf-8",
        )
        identities = collect_action_identities(tmp_root)
        expected_identities = [
            {
                "workflow": ".github/workflows/a.yml",
                "line": "10",
                "action": "actions/checkout",
                "ref": "11bd71901bbe5b1630ceea73d27597364c9af683",
            },
            {
                "workflow": ".github/workflows/a.yml",
                "line": "18",
                "action": "actions/reusable/.github/workflows/x.yml",
                "ref": other_sha,
            },
            {
                "workflow": ".github/workflows/b.yml",
                "line": "10",
                "action": "actions/cache",
                "ref": "1bd1e32a3bdc45362d1e726936510720a7c30a57",
            },
        ]
        if identities != expected_identities:
            print(
                f"SELF_TEST_FAILURE in derived_action_identity: expected {expected_identities}, got {identities}",
                file=sys.stderr,
            )
            return 1
        if collect_action_identities(tmp_root) != identities:
            print(
                "SELF_TEST_FAILURE in derived_action_identity: record is not deterministic",
                file=sys.stderr,
            )
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

    # Test harness project without lock flag or lock file
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        harness_dir = tmp_root / "tests" / "Eliot.Operator.Tests"
        harness_dir.mkdir(parents=True)
        (harness_dir / "Eliot.Operator.Tests.csproj").write_text(
            "<Project><PropertyGroup></PropertyGroup></Project>", encoding="utf-8"
        )
        findings = check_nuget_lock(tmp_root)
        if not any(
            f.code == "GWF-005" and "Eliot.Operator.Tests" in f.path for f in findings
        ):
            print("SELF_TEST_FAILURE: expected GWF-005 for unlocked Operator harness", file=sys.stderr)
            return 1

    # Test locked harness project accepted
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        harness_dir = tmp_root / "tests" / "Eliot.Operator.Tests"
        harness_dir.mkdir(parents=True)
        (harness_dir / "Eliot.Operator.Tests.csproj").write_text(
            "<Project><PropertyGroup><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>"
            "</PropertyGroup></Project>",
            encoding="utf-8",
        )
        (harness_dir / "packages.lock.json").write_text(
            '{"version": 1, "dependencies": {"net10.0": {}}}', encoding="utf-8"
        )
        findings = check_nuget_lock(tmp_root)
        if findings:
            print(f"SELF_TEST_FAILURE: locked harness produced unexpected findings: {findings}", file=sys.stderr)
            return 1

    # Test pip install without hash lock rejected
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        wf_dir = tmp_root / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "test.yml").write_text(
            "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n"
            "    runs-on: windows-latest\n    steps:\n"
            "      - run: python -m pip install -r scripts/requirements.txt\n",
            encoding="utf-8",
        )
        findings = check_pip_install_lock(tmp_root)
        if not any(f.code == "GWF-009" for f in findings):
            print("SELF_TEST_FAILURE: expected GWF-009 for unhashed pip install", file=sys.stderr)
            return 1

    # Test hash-locked pip install accepted
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        wf_dir = tmp_root / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "test.yml").write_text(
            "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n"
            "    runs-on: windows-latest\n    steps:\n"
            "      - run: python -m pip install --require-hashes -r scripts/requirements-verification.txt\n",
            encoding="utf-8",
        )
        findings = check_pip_install_lock(tmp_root)
        if findings:
            print(f"SELF_TEST_FAILURE: hash-locked pip install produced unexpected findings: {findings}", file=sys.stderr)
            return 1

    # 25 single-file workflow cases + 2 cross-workflow divergence cases
    # + 1 derived-identity case + 7 rule-level cases below.
    case_count = len(test_cases) + len(divergence_cases) + 1 + 7
    print(f"GITHUB_WORKFLOW_VERIFIER_SELF_TEST: PASS ({case_count}/{case_count} cases verified)")
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
            # Derived action identity (issue #1225 step 2). Additive key: every
            # existing consumer reads `status`/`findings_count`/`findings`, which
            # keep their meaning and ordering unchanged. Sorted and bounded, so
            # an unchanged tree yields a byte-identical file.
            "actions": collect_action_identities(root),
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
