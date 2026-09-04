#!/usr/bin/env python3
"""Fail-closed acceptance gate for one ELIOT work unit."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

REPOSITORY = "UnknownAlienHuman/eliot-memory-os"
ISSUE_WEB = f"https://github.com/{REPOSITORY}/issues/"
ISSUE_API = f"https://api.github.com/repos/{REPOSITORY}/issues/"
MAX_ASSIGNMENT_BYTES = 2_000_000

PUB_ITEM = re.compile(
    r"^\s*pub(?:\s*\([^)]*\))?\s+"
    r"(?:async\s+|const\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+)*"
    r"(struct|enum|trait|fn|type|const|mod|union)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)",
    re.M,
)
TEST_FN = re.compile(
    r"#\[(?:tokio::)?test[^\]]*\]\s*"
    r"(?:#\[[^\]]*\]\s*)*(?:async\s+)?fn\s+([a-z_0-9]+)",
    re.M,
)
SERDE_DEFAULT_FIELD = re.compile(
    r"#\[serde\(default[^\]]*\)\]\s*(?:#\[[^\]]*\]\s*)*"
    r"(?:///[^\n]*\n\s*)*pub\s+([a-z_0-9]+)\s*:",
    re.M,
)
MATRIX_HEADING = re.compile(
    r"^##[ \t]+Required test matrix[ \t]*$", re.M | re.I
)
NEXT_H2 = re.compile(r"^##[ \t]+", re.M)
MATRIX_ITEM = re.compile(r"^([1-9][0-9]*)\.[ \t]+\S", re.M)
PROTECTED_FIELD_ROOTS = (
    "authority", "scope", "effect", "privacy", "ordering", "receipt",
    "grant", "permit", "revoc", "denominator", "fence", "proof",
)


class AssignmentSourceError(RuntimeError):
    pass


class Report:
    def __init__(self) -> None:
        self.ok: list[str] = []
        self.fail: list[str] = []

    def check(self, condition: bool, label: str, detail: str = "") -> None:
        target = self.ok if condition else self.fail
        target.append(label if condition or not detail else f"{label}: {detail}")


def crate_dir(root: Path, crate: str) -> Path:
    for manifest_path in root.rglob("Cargo.toml"):
        if "target" in manifest_path.parts:
            continue
        try:
            manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if manifest.get("package", {}).get("name") == crate:
            return manifest_path.parent
    print(f"error: crate {crate!r} not found under {root}", file=sys.stderr)
    raise SystemExit(2)


def read_sources(cdir: Path) -> tuple[str, str]:
    source: list[str] = []
    tests: list[str] = []
    for path in sorted(cdir.rglob("*.rs")):
        if "target" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        (tests if "tests" in path.parts else source).append(text)
    return "\n".join(source), "\n".join(tests)


def parse_assignment_matrix(body: str) -> tuple[int, str]:
    headings = list(MATRIX_HEADING.finditer(body))
    if len(headings) != 1:
        raise AssignmentSourceError(
            "expected exactly one level-two 'Required test matrix' heading; "
            f"found {len(headings)}"
        )
    remainder = body[headings[0].end():]
    next_heading = NEXT_H2.search(remainder)
    section = remainder[:next_heading.start()] if next_heading else remainder
    numbers = [int(match.group(1)) for match in MATRIX_ITEM.finditer(section)]
    if not numbers:
        raise AssignmentSourceError("matrix contains no numbered cases")
    expected = list(range(1, len(numbers) + 1))
    if numbers != expected:
        raise AssignmentSourceError(
            f"matrix numbering must be contiguous from 1; found {numbers}"
        )
    return len(numbers), hashlib.sha256(body.encode("utf-8")).hexdigest()


def fetch_assignment(issue_number: int) -> tuple[int, str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "eliot-work-unit-verifier",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(f"{ISSUE_API}{issue_number}", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read(MAX_ASSIGNMENT_BYTES + 1)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as error:
        raise AssignmentSourceError(
            f"cannot fetch authoritative issue #{issue_number}: {error}"
        ) from error
    if len(raw) > MAX_ASSIGNMENT_BYTES:
        raise AssignmentSourceError(
            f"issue #{issue_number} exceeds {MAX_ASSIGNMENT_BYTES} bytes"
        )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssignmentSourceError(
            f"issue #{issue_number} returned invalid JSON"
        ) from error
    body = payload.get("body")
    title = payload.get("title")
    if not isinstance(body, str):
        raise AssignmentSourceError(f"issue #{issue_number} has no textual body")
    if not isinstance(title, str) or not title.strip():
        raise AssignmentSourceError(f"issue #{issue_number} has no title")
    count, digest = parse_assignment_matrix(body)
    return count, digest, title


def normalized_unit(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--crate", required=True)
    parser.add_argument("--root", default=".")
    parser.add_argument("--no-cargo", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    cdir = crate_dir(root, args.crate)
    module_path = cdir / "module.toml"
    if not module_path.exists():
        print(f"error: {module_path} missing", file=sys.stderr)
        return 2
    module = tomllib.loads(module_path.read_text(encoding="utf-8"))
    acceptance = module.get("acceptance")
    if not isinstance(acceptance, dict):
        print(f"error: {module_path} has no [acceptance] table", file=sys.stderr)
        return 2

    source, tests = read_sources(cdir)
    all_text = f"{source}\n{tests}"
    report = Report()

    issue_raw = acceptance.get("source_issue")
    issue_number: int | None = None
    if isinstance(issue_raw, int) and issue_raw > 0:
        issue_number = issue_raw
    elif isinstance(issue_raw, str) and issue_raw.isdigit() and int(issue_raw) > 0:
        issue_number = int(issue_raw)
    unit = acceptance.get("source_unit")
    declared_cases = int(acceptance.get("test_matrix_cases", 0))
    min_tests = int(acceptance.get("min_tests", 0))
    required_tests = list(acceptance.get("required_tests", []))

    report.check(issue_number is not None, "valid source_issue", repr(issue_raw))
    report.check(
        isinstance(unit, str) and bool(unit.strip()),
        "non-blank source_unit",
        repr(unit),
    )
    report.check(declared_cases > 0, "positive test_matrix_cases", str(declared_cases))

    authoritative_cases = declared_cases
    if issue_number is not None:
        print(f"  unit  {unit or '?'}  assignment {ISSUE_WEB}{issue_number}")
        try:
            live_cases, issue_digest, issue_title = fetch_assignment(issue_number)
        except AssignmentSourceError as error:
            report.check(False, "authoritative assignment available", str(error))
        else:
            print(f"  assignment_body_sha256  {issue_digest}")
            authoritative_cases = live_cases
            if isinstance(unit, str) and unit.strip():
                report.check(
                    normalized_unit(unit) in normalized_unit(issue_title),
                    "source_unit matches issue title",
                    f"{unit!r} not in {issue_title!r}",
                )
            report.check(
                declared_cases == live_cases,
                "declared matrix matches authoritative issue",
                f"declared {declared_cases}, issue has {live_cases}",
            )

    report.check(
        min_tests >= authoritative_cases > 0,
        f"min_tests >= authoritative matrix ({authoritative_cases})",
        f"min_tests is {min_tests}",
    )
    report.check(
        len(required_tests) >= authoritative_cases > 0,
        f"named tests >= authoritative matrix ({authoritative_cases})",
        f"required_tests has {len(required_tests)} names",
    )
    duplicates = sorted(
        name for name in set(required_tests) if required_tests.count(name) > 1
    )
    report.check(not duplicates, "required test names unique", ", ".join(duplicates))
    invalid_names = sorted(
        name for name in required_tests
        if not isinstance(name, str) or not re.fullmatch(r"[a-z_][a-z_0-9]*", name)
    )
    report.check(
        not invalid_names,
        "required test names are Rust identifiers",
        ", ".join(map(str, invalid_names)),
    )

    source_lines = source.count("\n")
    source_floor = int(acceptance.get("min_source_lines", 1))
    report.check(
        source_lines >= source_floor,
        f"source floor >= {source_floor}",
        f"found {source_lines}",
    )

    public_items = {match.group(2) for match in PUB_ITEM.finditer(source)}
    for name in acceptance.get("required_exports", []):
        report.check(name in public_items, f"export `{name}`", "missing")
    min_public = int(acceptance.get("min_public_items", 0))
    if min_public:
        report.check(
            len(public_items) >= min_public,
            f"public items >= {min_public}",
            f"found {len(public_items)}",
        )

    found_tests = set(TEST_FN.findall(all_text))
    for name in required_tests:
        report.check(name in found_tests, f"test `{name}`", "missing")
    if min_tests:
        report.check(
            len(found_tests) >= min_tests,
            f"tests >= {min_tests}",
            f"found {len(found_tests)}",
        )

    if acceptance.get("require_deny_unknown_fields", False):
        derives = len(re.findall(r"#\[derive[^\]]*Deserialize", source))
        denies = len(re.findall(r"deny_unknown_fields", source))
        report.check(
            derives == 0 or denies >= 1,
            "deny_unknown_fields present",
            f"{derives} derives, {denies} deny",
        )
        offenders = [
            field for field in SERDE_DEFAULT_FIELD.findall(source)
            if any(root in field for root in PROTECTED_FIELD_ROOTS)
        ]
        report.check(
            not offenders,
            "no serde(default) on protected fields",
            ", ".join(sorted(set(offenders))),
        )
    if acceptance.get("forbid_unsafe", True):
        report.check(
            "forbid(unsafe_code)" in source,
            "crate declares forbid(unsafe_code)",
        )
    for pattern in acceptance.get("forbidden_patterns", []):
        hits = len(re.findall(pattern, all_text))
        report.check(hits == 0, f"forbidden /{pattern}/ absent", f"{hits} hits")
    for pattern in acceptance.get("required_patterns", []):
        hits = len(re.findall(pattern, all_text))
        report.check(hits > 0, f"required /{pattern}/ present", "0 hits")

    workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))[
        "workspace"
    ]
    relative = cdir.relative_to(root).as_posix()
    member = relative in set(workspace.get("members", []))
    excluded = relative in set(workspace.get("exclude", []))
    standalone = "[workspace]" in (cdir / "Cargo.toml").read_text(encoding="utf-8")
    report.check(
        member or excluded or standalone,
        "crate is buildable by cargo",
        relative,
    )
    manifest = tomllib.loads((cdir / "Cargo.toml").read_text(encoding="utf-8"))
    metadata = manifest.get("package", {}).get("metadata", {}).get("eliot", {})
    if metadata.get("source_status") == "IMPLEMENTED":
        report.check(member, "implemented crate is a workspace member", relative)

    if not args.no_cargo and (member or excluded or standalone):
        process = subprocess.run(
            [
                "cargo", "test", "--manifest-path", str(cdir / "Cargo.toml"),
                "--all-targets", "--", "--list",
            ],
            capture_output=True,
            text=True,
        )
        listed = len(re.findall(r": test$", process.stdout, re.M))
        first_error = (process.stderr or "").strip().splitlines()[:1]
        report.check(process.returncode == 0, "cargo test --list succeeds", str(first_error))
        report.check(
            listed >= max(1, min_tests),
            f"cargo lists >= {max(1, min_tests)} tests",
            f"listed {listed}",
        )

    print("=" * 72)
    print(f"work-unit gate :: {args.crate} :: module {module.get('module_id', '?')}")
    print("=" * 72)
    for label in report.ok:
        print(f"  PASS  {label}")
    for label in report.fail:
        print(f"  FAIL  {label}")
    print("-" * 72)
    print(f"  {len(report.ok)} passed, {len(report.fail)} failed")
    return 1 if report.fail else 0


if __name__ == "__main__":
    sys.exit(main())
