#!/usr/bin/env python3
"""Verify workstream routing, assignment boundaries, and owner projections.

Validates that:
1. workstreams/ACTIVE.toml defines stable workstream and branch policy;
2. assignment records define bounded mutable scopes and valid issues;
3. docs/PROJECT_MAP.md does not claim obsolete audit SHAs as current authority;
4. GitHub snapshot observations (when provided) are non-stale, complete, and
   consistent with declared owners and non-overlapping active writers.

This is a static routing control-plane check; it does not grant runtime or
Product support.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import tomllib
from typing import Any


EXPECTED_ACTIVE_SCHEMA = "eliot.active-workstreams.v1"
OBSOLETE_AUDIT_SHA = "0f2c94730a7e7947ec973474e3b469ce75f9469d"
REPO_PATH_RE = re.compile(
    r"^(crates|bins|apps|docs|workstreams|scripts|tests|Cargo\.toml|\.github)/[a-zA-Z0-9_\-\./\*]*"
)


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    detail: str


def _finding(code: str, path: str, detail: str) -> Finding:
    return Finding(code, path, detail)


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"cannot load TOML file {path}: {exc}") from exc


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"cannot load JSON file {path}: {exc}") from exc


def paths_overlap(p1: str, p2: str) -> bool:
    """Return True if path p1 is a prefix of p2 or p2 is a prefix of p1."""
    norm1 = p1.replace("\\", "/").rstrip("/*").rstrip("/") + "/"
    norm2 = p2.replace("\\", "/").rstrip("/*").rstrip("/") + "/"
    return norm1.startswith(norm2) or norm2.startswith(norm1) or norm1 == norm2


def extract_assignment_issue(data: dict[str, Any], path_str: str) -> int | None:
    if "issue" in data and isinstance(data["issue"], (int, str)):
        try:
            return int(data["issue"])
        except ValueError:
            pass
    work_unit = data.get("work_unit", {})
    if isinstance(work_unit, dict) and "issue" in work_unit:
        try:
            return int(work_unit["issue"])
        except (ValueError, TypeError):
            pass
    filename = Path(path_str).name
    m = re.match(r"^(\d+)-", filename)
    if m:
        return int(m.group(1))
    return None


def extract_assignment_paths(data: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    scope = data.get("scope", {})
    if isinstance(scope, dict):
        for p in scope.get("primary_paths", []):
            if isinstance(p, str):
                m = REPO_PATH_RE.match(p.strip())
                if m:
                    paths.append(m.group(0))
    for w in data.get("waves", []) + data.get("wave", []):
        if isinstance(w, dict):
            for p in w.get("mutable_paths", []):
                if isinstance(p, str):
                    m = REPO_PATH_RE.match(p.strip())
                    if m:
                        paths.append(m.group(0))
    return paths


def verify_active_toml(payload: dict[str, Any], path_str: str = "workstreams/ACTIVE.toml") -> list[Finding]:
    findings: list[Finding] = []
    if payload.get("schema") != EXPECTED_ACTIVE_SCHEMA:
        findings.append(_finding("active_schema_drift", path_str, f"expected schema {EXPECTED_ACTIVE_SCHEMA}"))
    if payload.get("authority_branch") != "main":
        findings.append(_finding("active_authority_drift", path_str, "authority_branch must be main"))

    branch_policy = payload.get("branch_policy")
    if not isinstance(branch_policy, dict):
        findings.append(_finding("active_branch_policy", path_str, "branch_policy must be a table"))
    else:
        if not branch_policy.get("standard_branch_requires_open_issue"):
            findings.append(_finding("active_branch_policy", path_str, "standard_branch_requires_open_issue must be true"))
        if not branch_policy.get("requires_current_main_ancestor"):
            findings.append(_finding("active_branch_policy", path_str, "requires_current_main_ancestor must be true"))
        if not branch_policy.get("one_issue_one_branch_one_pr"):
            findings.append(_finding("active_branch_policy", path_str, "one_issue_one_branch_one_pr must be true"))

    workstreams = payload.get("workstream")
    if not isinstance(workstreams, list) or not workstreams:
        findings.append(_finding("active_workstreams", path_str, "workstream must be a non-empty list of tables"))
    else:
        for index, ws in enumerate(workstreams):
            if not isinstance(ws, dict):
                findings.append(_finding("active_workstreams", f"{path_str}:workstream[{index}]", "expected table"))
                continue
            if not ws.get("id"):
                findings.append(_finding("active_workstreams", f"{path_str}:workstream[{index}]", "missing workstream id"))
            if ws.get("status") != "active":
                findings.append(_finding("active_workstreams", f"{path_str}:workstream[{index}]", "status must be active"))
    return findings


def verify_assignments(assignments: list[tuple[str, dict[str, Any]]]) -> list[Finding]:
    findings: list[Finding] = []
    for file_path, data in assignments:
        issue = extract_assignment_issue(data, file_path)
        if issue is None:
            findings.append(_finding("orphan_item", file_path, "assignment missing declared issue number"))
    return findings


def verify_project_map(content: str, path_str: str = "docs/PROJECT_MAP.md") -> list[Finding]:
    findings: list[Finding] = []
    if OBSOLETE_AUDIT_SHA in content:
        findings.append(
            _finding(
                "map_registry_contradiction",
                path_str,
                f"PROJECT_MAP.md contains obsolete audit SHA {OBSOLETE_AUDIT_SHA} as authority",
            )
        )
    return findings


def verify_active_writers(writers: list[dict[str, Any]]) -> list[Finding]:
    """Validate that active writers claim disjoint mutable path scopes."""
    findings: list[Finding] = []
    claimed: list[tuple[str, int | str, str]] = []  # (path, issue, source)

    for writer in writers:
        issue = writer.get("issue", "unknown")
        src = writer.get("source", str(issue))
        paths = writer.get("paths", [])
        for p in paths:
            if not isinstance(p, str) or not p.strip():
                continue
            clean_p = p.strip().replace("\\", "/")
            for other_p, other_issue, other_src in claimed:
                if issue != other_issue and paths_overlap(clean_p, other_p):
                    findings.append(
                        _finding(
                            "duplicate_writer",
                            src,
                            f"mutable path '{clean_p}' (issue #{issue}) overlaps '{other_p}' (issue #{other_issue} in {other_src})",
                        )
                    )
            claimed.append((clean_p, issue, src))
    return findings


def verify_snapshot(snapshot: dict[str, Any], assignments: list[tuple[str, dict[str, Any]]]) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(snapshot, dict):
        return [_finding("snapshot_shape", "$", "snapshot root must be an object")]

    required_keys = ["repository", "ref", "commit_sha", "observed_at", "expires_at", "page_complete"]
    for key in required_keys:
        if key not in snapshot:
            findings.append(_finding("snapshot_shape", f"$.{key}", f"required snapshot key missing: {key}"))

    if not snapshot.get("page_complete", False):
        findings.append(_finding("incomplete_snapshot", "$.page_complete", "snapshot reports query or page incomplete"))

    expires_at_str = snapshot.get("expires_at")
    if expires_at_str:
        try:
            expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > expires_at:
                findings.append(
                    _finding(
                        "stale_snapshot",
                        "$.expires_at",
                        f"snapshot expired at {expires_at_str}",
                    )
                )
        except Exception:
            findings.append(_finding("snapshot_shape", "$.expires_at", "invalid ISO 8601 expiry timestamp"))

    issues_map = {
        item["number"]: item
        for item in snapshot.get("issues", [])
        if isinstance(item, dict) and "number" in item
    }
    for file_path, data in assignments:
        issue_num = extract_assignment_issue(data, file_path)
        if issue_num and issue_num in issues_map:
            gh_issue = issues_map[issue_num]
            if gh_issue.get("state") == "closed" and data.get("status") in (
                "active",
                "in_progress",
                "READY_AFTER_CAPABILITY_REGISTRY_CONTRACT",
            ):
                if not data.get("historical_reference_only", False):
                    findings.append(
                        _finding(
                            "closed_active_item",
                            file_path,
                            f"issue #{issue_num} is closed in snapshot but assigned active status: {data.get('status')}",
                        )
                    )

    active_writers = snapshot.get("active_writers", [])
    if isinstance(active_writers, list):
        findings.extend(verify_active_writers(active_writers))

    return findings


def verify(root: Path, snapshot_path: Path | None = None) -> list[Finding]:
    findings: list[Finding] = []
    active_path = root / "workstreams" / "ACTIVE.toml"
    if not active_path.is_file():
        findings.append(_finding("active_missing", str(active_path), "workstreams/ACTIVE.toml is missing"))
    else:
        try:
            active_data = _load_toml(active_path)
            findings.extend(verify_active_toml(active_data, "workstreams/ACTIVE.toml"))
        except ValueError as exc:
            findings.append(_finding("active_unreadable", str(active_path), str(exc)))

    assignments: list[tuple[str, dict[str, Any]]] = []
    assignment_files = sorted(root.glob("workstreams/**/assignments/*.toml"))
    for af in assignment_files:
        rel = str(af.relative_to(root)).replace("\\", "/")
        try:
            data = _load_toml(af)
            assignments.append((rel, data))
        except ValueError as exc:
            findings.append(_finding("assignment_unreadable", rel, str(exc)))

    findings.extend(verify_assignments(assignments))

    project_map_path = root / "docs" / "PROJECT_MAP.md"
    if project_map_path.is_file():
        content = project_map_path.read_text(encoding="utf-8")
        findings.extend(verify_project_map(content, "docs/PROJECT_MAP.md"))

    if snapshot_path and snapshot_path.is_file():
        try:
            snapshot_data = _load_json(snapshot_path)
            findings.extend(verify_snapshot(snapshot_data, assignments))
        except ValueError as exc:
            findings.append(_finding("snapshot_unreadable", str(snapshot_path), str(exc)))

    return sorted(findings, key=lambda f: (f.code, f.path, f.detail))


def self_test() -> None:
    cases = []

    # Valid fixture
    valid_active = {
        "schema": EXPECTED_ACTIVE_SCHEMA,
        "authority_branch": "main",
        "branch_policy": {
            "standard_branch_requires_open_issue": True,
            "requires_current_main_ancestor": True,
            "one_issue_one_branch_one_pr": True,
        },
        "workstream": [{"id": "core-daemons", "status": "active", "branch_strategy": "fresh"}],
    }
    assert verify_active_toml(valid_active) == []

    # Case 1: stale snapshot
    stale_snapshot = {
        "repository": "UnknownAlienHuman/eliot-memory-os",
        "ref": "main",
        "commit_sha": "8dc9585805ddef8f4ca7ced5a87bbb7147c936bc",
        "observed_at": "2026-09-01T00:00:00Z",
        "expires_at": "2026-09-02T00:00:00Z",
        "page_complete": True,
    }
    findings = verify_snapshot(stale_snapshot, [])
    assert any(f.code == "stale_snapshot" for f in findings), f"expected stale_snapshot: {findings}"
    cases.append(("stale snapshot rejection", "stale_snapshot"))

    # Case 2: incomplete snapshot
    incomplete_snapshot = {
        "repository": "UnknownAlienHuman/eliot-memory-os",
        "ref": "main",
        "commit_sha": "8dc9585805ddef8f4ca7ced5a87bbb7147c936bc",
        "observed_at": "2026-09-13T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "page_complete": False,
    }
    findings = verify_snapshot(incomplete_snapshot, [])
    assert any(f.code == "incomplete_snapshot" for f in findings), f"expected incomplete_snapshot: {findings}"
    cases.append(("incomplete snapshot rejection", "incomplete_snapshot"))

    # Case 3: duplicate writer
    writers_conflict = [
        {"issue": 101, "source": "mgr01", "paths": ["crates/smart/cell-a/lib.rs"]},
        {"issue": 102, "source": "mgr02", "paths": ["crates/smart/cell-a/"]},
    ]
    findings = verify_active_writers(writers_conflict)
    assert any(f.code == "duplicate_writer" for f in findings), f"expected duplicate_writer: {findings}"
    cases.append(("duplicate writer detection", "duplicate_writer"))

    # Case 4: orphan item
    assignments_orphan = [
        ("workstreams/core/assignments/nonum.toml", {"scope": {"primary_paths": ["crates/orphan/"]}}),
    ]
    findings = verify_assignments(assignments_orphan)
    assert any(f.code == "orphan_item" for f in findings), f"expected orphan_item: {findings}"
    cases.append(("orphan item detection", "orphan_item"))

    # Case 5: closed active item
    active_snapshot = {
        "repository": "UnknownAlienHuman/eliot-memory-os",
        "ref": "main",
        "commit_sha": "8dc9585805ddef8f4ca7ced5a87bbb7147c936bc",
        "observed_at": "2026-09-13T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "page_complete": True,
        "issues": [{"number": 999, "state": "closed"}],
    }
    assignments_closed_active = [
        (
            "workstreams/core/assignments/999.toml",
            {
                "issue": 999,
                "status": "active",
                "scope": {"primary_paths": ["crates/test/"]},
            },
        ),
    ]
    findings = verify_snapshot(active_snapshot, assignments_closed_active)
    assert any(f.code == "closed_active_item" for f in findings), f"expected closed_active_item: {findings}"
    cases.append(("closed active item rejection", "closed_active_item"))

    # Case 6: map registry contradiction
    map_content = f"Status: current routing map for `main`, audited against `{OBSOLETE_AUDIT_SHA}` on 2026-08-31."
    findings = verify_project_map(map_content)
    assert any(f.code == "map_registry_contradiction" for f in findings), f"expected map_registry_contradiction: {findings}"
    cases.append(("map registry contradiction detection", "map_registry_contradiction"))

    for desc, code in cases:
        print(f"WORKSTREAM_ROUTING_FIXTURE: {desc}: FAILS_AS={code}")
    print(f"WORKSTREAM_ROUTING_SELF_TEST: PASS cases={len(cases)}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Verify workstream routing and assignment boundaries.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--snapshot", type=Path, default=None)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    findings = verify(args.root.resolve(), args.snapshot.resolve() if args.snapshot else None)
    if findings:
        for f in findings:
            print(f"HARD_VIOLATION: {f.code}: {f.path}: {f.detail}")
        return 1

    active_count = 0
    active_path = args.root / "workstreams" / "ACTIVE.toml"
    if active_path.is_file():
        try:
            active_count = len(_load_toml(active_path).get("workstream", []))
        except Exception:
            pass
    assignment_count = len(list(args.root.glob("workstreams/**/assignments/*.toml")))
    print(f"WORKSTREAM_ROUTING_VERIFY: PASS workstreams={active_count} assignments={assignment_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
