#!/usr/bin/env python3
"""Fail-closed acceptance gate for one ELIOT capability-cell work unit.

The authoritative test denominator is read from the GitHub issue named by the
crate's ``module.toml``. Package-local numbers are mirrors, never authority.
Each numbered issue case must be bound to one real Rust test with a marker of
this exact form immediately above its test attributes::

    // WORK_UNIT_CASE: 584/1
    #[test]
    fn loss_policy_vocabulary_is_exact() { ... }

The default mode proves a package-local leaf implementation. A leaf may be
complete while it remains independently buildable and waits for one serialized
workspace integration owner. ``--require-workspace-member`` proves the later
integrated state instead.
"""
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPOSITORY = "UnknownAlienHuman/eliot-memory-os"
ISSUE_WEB = f"https://github.com/{REPOSITORY}/issues/"
ISSUE_API = f"https://api.github.com/repos/{REPOSITORY}/issues/"
MAX_ASSIGNMENT_BYTES = 2_000_000
READY_FOR_INTEGRATION = "ready_for_wave_integration"
ADMITTED = "admitted"
IMPLEMENTED = "IMPLEMENTED"

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
MATRIX_HEADING = re.compile(r"^##[ \t]+Required test matrix[ \t]*$", re.M | re.I)
NEXT_H2 = re.compile(r"^##[ \t]+", re.M)
MATRIX_ITEM = re.compile(r"^([1-9][0-9]*)\.[ \t]+\S", re.M)
CASE_TEST = re.compile(
    r"^[ \t]*//[ \t]*WORK_UNIT_CASE:[ \t]*(\d+)[ \t]*/[ \t]*(\d+)[ \t]*$"
    r"(?P<attrs>(?:\n[ \t]*#\[[^\]\n]+\][ \t]*)+)"
    r"\n[ \t]*(?:async[ \t]+)?fn[ \t]+([a-z_][a-z_0-9]*)",
    re.M,
)
SHA256 = re.compile(r"[0-9a-f]{64}")
PROTECTED_FIELD_ROOTS = (
    "authority",
    "scope",
    "effect",
    "privacy",
    "ordering",
    "receipt",
    "grant",
    "permit",
    "revoc",
    "denominator",
    "fence",
    "proof",
)


class AssignmentSourceError(RuntimeError):
    """The external assignment cannot be used as an exact denominator."""


@dataclass(frozen=True)
class Assignment:
    number: int
    title: str
    state: str
    case_count: int
    body_sha256: str


class Report:
    def __init__(self) -> None:
        self.ok: list[str] = []
        self.fail: list[str] = []

    def check(self, condition: bool, label: str, detail: str = "") -> None:
        target = self.ok if condition else self.fail
        target.append(label if condition or not detail else f"{label}: {detail}")


def crate_dir(root: Path, crate: str) -> Path:
    """Find exactly one Cargo package with the requested package name."""
    matches: list[Path] = []
    for manifest_path in root.rglob("Cargo.toml"):
        if "target" in manifest_path.parts:
            continue
        try:
            manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError):
            continue
        if manifest.get("package", {}).get("name") == crate:
            matches.append(manifest_path.parent)
    if len(matches) != 1:
        print(
            f"error: expected exactly one crate named {crate!r}; "
            f"found {len(matches)}: {matches}",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return matches[0]


def is_test_source(path: Path) -> bool:
    """Classify conventional integration and module test files."""
    return (
        "tests" in path.parts
        or path.name == "tests.rs"
        or path.name.endswith("_tests.rs")
    )


def read_sources(cdir: Path) -> tuple[str, str]:
    """Return production-source text and test-source text in stable path order."""
    source: list[str] = []
    tests: list[str] = []
    for path in sorted(cdir.rglob("*.rs")):
        if "target" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="strict")
        (tests if is_test_source(path) else source).append(text)
    return "\n".join(source), "\n".join(tests)


def parse_assignment_matrix(body: str) -> tuple[int, str]:
    """Return the contiguous case count and exact body digest."""
    headings = list(MATRIX_HEADING.finditer(body))
    if len(headings) != 1:
        raise AssignmentSourceError(
            "expected exactly one level-two 'Required test matrix' heading; "
            f"found {len(headings)}"
        )
    remainder = body[headings[0].end() :]
    next_heading = NEXT_H2.search(remainder)
    section = remainder[: next_heading.start()] if next_heading else remainder
    numbers = [int(match.group(1)) for match in MATRIX_ITEM.finditer(section)]
    if not numbers:
        raise AssignmentSourceError("matrix contains no numbered cases")
    expected = list(range(1, len(numbers) + 1))
    if numbers != expected:
        raise AssignmentSourceError(
            f"matrix numbering must be contiguous from 1; found {numbers}"
        )
    return len(numbers), hashlib.sha256(body.encode("utf-8")).hexdigest()


def parse_case_tests(text: str) -> list[tuple[int, int, str]]:
    """Return ``(issue, case, test_name)`` bindings attached to actual tests."""
    bindings: list[tuple[int, int, str]] = []
    for match in CASE_TEST.finditer(text):
        attrs = match.group("attrs")
        if not re.search(r"#\[(?:tokio::)?test(?:[^\]]*)\]", attrs):
            continue
        bindings.append((int(match.group(1)), int(match.group(2)), match.group(4)))
    return bindings


def number_summary(values: list[int], limit: int = 30) -> str:
    ordered = sorted(set(values))
    shown = ordered[:limit]
    suffix = "..." if len(ordered) > limit else ""
    return ",".join(map(str, shown)) + suffix


def fetch_assignment(issue_number: int) -> Assignment:
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
        payload: Any = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssignmentSourceError(
            f"issue #{issue_number} returned invalid JSON"
        ) from error
    if not isinstance(payload, dict):
        raise AssignmentSourceError(f"issue #{issue_number} returned a non-object")
    if "pull_request" in payload:
        raise AssignmentSourceError(
            f"#{issue_number} is a pull request, not an authoritative issue"
        )
    body = payload.get("body")
    title = payload.get("title")
    state = payload.get("state")
    if not isinstance(body, str):
        raise AssignmentSourceError(f"issue #{issue_number} has no textual body")
    if not isinstance(title, str) or not title.strip():
        raise AssignmentSourceError(f"issue #{issue_number} has no title")
    if state not in {"open", "closed"}:
        raise AssignmentSourceError(f"issue #{issue_number} has invalid state {state!r}")
    count, digest = parse_assignment_matrix(body)
    return Assignment(issue_number, title, state, count, digest)


def normalized_unit(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def evaluate_workspace_lifecycle(
    *,
    source_status: object,
    prototype: object,
    module_status: object,
    workspace_admission: object,
    member: bool,
    excluded: bool,
    standalone: bool,
    require_workspace_member: bool,
) -> tuple[bool, str]:
    """Validate leaf-ready versus integrated workspace lifecycle states."""
    if source_status != IMPLEMENTED:
        return False, f"source_status must be {IMPLEMENTED!r}; found {source_status!r}"
    if prototype is not False:
        return False, f"prototype must be false; found {prototype!r}"
    if module_status != IMPLEMENTED:
        return False, f"module status must be {IMPLEMENTED!r}; found {module_status!r}"
    if member and excluded:
        return False, "crate cannot be both workspace member and excluded"

    if require_workspace_member:
        if not member:
            return False, "integration proof requires workspace membership"
        if excluded:
            return False, "integrated crate remains in workspace.exclude"
        if standalone:
            return False, "integrated crate still declares a standalone [workspace]"
        if workspace_admission != ADMITTED:
            return False, (
                f"integrated crate needs workspace_admission={ADMITTED!r}; "
                f"found {workspace_admission!r}"
            )
        return True, "integrated workspace state"

    integrated = (
        member
        and not excluded
        and not standalone
        and workspace_admission == ADMITTED
    )
    leaf_ready = (
        not member
        and (excluded or standalone)
        and workspace_admission == READY_FOR_INTEGRATION
    )
    if integrated:
        return True, "already integrated workspace state"
    if leaf_ready:
        return True, "package-local proof complete; waiting for integration owner"
    return False, (
        "expected either an admitted workspace member or an independently "
        f"buildable leaf with workspace_admission={READY_FOR_INTEGRATION!r}; "
        f"member={member}, excluded={excluded}, standalone={standalone}, "
        f"workspace_admission={workspace_admission!r}"
    )


def run_self_test() -> int:
    """Exercise parser, case binding and workspace-lifecycle regressions."""
    failures: list[str] = []

    def expect(condition: bool, name: str) -> None:
        if not condition:
            failures.append(name)

    body = "# Work\n\n## Required test matrix\n\n1. one\n2. two\n\n## Result\n"
    count, digest = parse_assignment_matrix(body)
    expect(count == 2, "matrix count")
    expect(SHA256.fullmatch(digest) is not None, "matrix digest")

    for malformed in (
        "## Required test matrix\n2. gap\n",
        "## Required test matrix\n1. one\n3. gap\n",
        "## Required test matrix\n1. one\n## Required test matrix\n1. two\n",
    ):
        try:
            parse_assignment_matrix(malformed)
        except AssignmentSourceError:
            pass
        else:
            failures.append("malformed matrix accepted")

    tests = (
        "// WORK_UNIT_CASE: 584/1\n#[test]\nfn one() {}\n"
        "// WORK_UNIT_CASE: 584/2\n#[tokio::test]\nasync fn two() {}\n"
        "// WORK_UNIT_CASE: 584/3\nfn not_a_test() {}\n"
    )
    expect(
        parse_case_tests(tests) == [(584, 1, "one"), (584, 2, "two")],
        "case binding parser",
    )

    common = dict(
        source_status=IMPLEMENTED,
        prototype=False,
        module_status=IMPLEMENTED,
    )
    ok, _ = evaluate_workspace_lifecycle(
        **common,
        workspace_admission=READY_FOR_INTEGRATION,
        member=False,
        excluded=True,
        standalone=True,
        require_workspace_member=False,
    )
    expect(ok, "leaf-ready state")
    ok, _ = evaluate_workspace_lifecycle(
        **common,
        workspace_admission=READY_FOR_INTEGRATION,
        member=False,
        excluded=True,
        standalone=True,
        require_workspace_member=True,
    )
    expect(not ok, "leaf-ready rejected by integration mode")
    ok, _ = evaluate_workspace_lifecycle(
        **common,
        workspace_admission=ADMITTED,
        member=True,
        excluded=False,
        standalone=False,
        require_workspace_member=True,
    )
    expect(ok, "integrated state")
    ok, _ = evaluate_workspace_lifecycle(
        **common,
        workspace_admission=ADMITTED,
        member=False,
        excluded=True,
        standalone=True,
        require_workspace_member=False,
    )
    expect(not ok, "false admitted standalone rejected")

    if failures:
        for failure in failures:
            print(f"FAIL self-test: {failure}")
        return 1
    print("PASS verify-work-unit self-test")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--crate")
    parser.add_argument("--root", default=".")
    parser.add_argument("--no-cargo", action="store_true")
    parser.add_argument(
        "--require-workspace-member",
        action="store_true",
        help="require the later integrated/admitted workspace state",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()
    if not args.crate:
        parser.error("--crate is required unless --self-test is used")

    root = Path(args.root).resolve()
    cdir = crate_dir(root, args.crate)
    module_path = cdir / "module.toml"
    if not module_path.exists():
        print(f"error: {module_path} missing", file=sys.stderr)
        return 2

    try:
        module = tomllib.loads(module_path.read_text(encoding="utf-8"))
        manifest = tomllib.loads((cdir / "Cargo.toml").read_text(encoding="utf-8"))
        workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))[
            "workspace"
        ]
    except (OSError, UnicodeError, KeyError, tomllib.TOMLDecodeError) as error:
        print(f"error: cannot load work-unit metadata: {error}", file=sys.stderr)
        return 2

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
    assignment: Assignment | None = None
    if issue_number is not None:
        print(f"  unit  {unit or '?'}  assignment {ISSUE_WEB}{issue_number}")
        try:
            assignment = fetch_assignment(issue_number)
        except AssignmentSourceError as error:
            report.check(False, "authoritative assignment available", str(error))
        else:
            print(f"  assignment_state        {assignment.state}")
            print(f"  assignment_body_sha256  {assignment.body_sha256}")
            authoritative_cases = assignment.case_count
            if isinstance(unit, str) and unit.strip():
                report.check(
                    normalized_unit(unit) in normalized_unit(assignment.title),
                    "source_unit matches issue title",
                    f"{unit!r} not in {assignment.title!r}",
                )
            report.check(
                declared_cases == assignment.case_count,
                "declared matrix matches authoritative issue",
                f"declared {declared_cases}, issue has {assignment.case_count}",
            )

    report.check(
        min_tests >= authoritative_cases > 0,
        f"min_tests >= authoritative matrix ({authoritative_cases})",
        f"min_tests is {min_tests}",
    )

    bindings = parse_case_tests(all_text)
    foreign = [
        (bound_issue, case, name)
        for bound_issue, case, name in bindings
        if issue_number is None or bound_issue != issue_number
    ]
    report.check(
        not foreign,
        "no foreign WORK_UNIT_CASE bindings",
        ", ".join(f"{bound_issue}/{case}:{name}" for bound_issue, case, name in foreign),
    )
    own_bindings = [
        (case, name)
        for bound_issue, case, name in bindings
        if bound_issue == issue_number
    ]
    bound_cases = [case for case, _ in own_bindings]
    duplicate_cases = sorted(
        case for case in set(bound_cases) if bound_cases.count(case) > 1
    )
    out_of_range = sorted(
        case for case in bound_cases if case < 1 or case > authoritative_cases
    )
    missing_cases = sorted(set(range(1, authoritative_cases + 1)) - set(bound_cases))
    report.check(
        not duplicate_cases,
        "each matrix case has at most one test binding",
        number_summary(duplicate_cases),
    )
    report.check(
        not out_of_range,
        "case bindings stay inside the authoritative denominator",
        number_summary(out_of_range),
    )
    report.check(
        not missing_cases and authoritative_cases > 0,
        f"every authoritative case 1..{authoritative_cases} has one test binding",
        f"missing {number_summary(missing_cases)}",
    )

    duplicate_names = sorted(
        name for name in set(required_tests) if required_tests.count(name) > 1
    )
    report.check(
        not duplicate_names,
        "required test names unique",
        ", ".join(duplicate_names),
    )
    invalid_names = sorted(
        name
        for name in required_tests
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
    for _, name in own_bindings:
        report.check(name in found_tests, f"case-bound test `{name}`", "missing")
    for name in required_tests:
        report.check(name in found_tests, f"anchor test `{name}`", "missing")
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
            field
            for field in SERDE_DEFAULT_FIELD.findall(source)
            if any(root_name in field for root_name in PROTECTED_FIELD_ROOTS)
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
        hits = len(re.findall(pattern, source))
        report.check(hits > 0, f"required /{pattern}/ present", "0 hits")

    relative = cdir.relative_to(root).as_posix()
    member = relative in set(workspace.get("members", []))
    excluded = relative in set(workspace.get("exclude", []))
    standalone = "[workspace]" in (cdir / "Cargo.toml").read_text(encoding="utf-8")
    report.check(
        member or excluded or standalone,
        "crate is independently buildable or integrated",
        relative,
    )

    package_metadata = manifest.get("package", {}).get("metadata", {}).get("eliot", {})
    source_status = package_metadata.get("source_status")
    prototype = package_metadata.get("prototype")
    workspace_admission = package_metadata.get("workspace_admission")
    lifecycle_ok, lifecycle_detail = evaluate_workspace_lifecycle(
        source_status=source_status,
        prototype=prototype,
        module_status=module.get("status"),
        workspace_admission=workspace_admission,
        member=member,
        excluded=excluded,
        standalone=standalone,
        require_workspace_member=args.require_workspace_member,
    )
    report.check(lifecycle_ok, "completion/workspace lifecycle is valid", lifecycle_detail)

    frozen_digest = acceptance.get("assignment_body_sha256")
    digest_well_formed = (
        isinstance(frozen_digest, str) and SHA256.fullmatch(frozen_digest) is not None
    )
    if source_status == IMPLEMENTED:
        report.check(
            digest_well_formed,
            "implemented unit freezes authoritative assignment digest",
            repr(frozen_digest),
        )
        if assignment is not None and digest_well_formed:
            report.check(
                frozen_digest == assignment.body_sha256,
                "frozen assignment digest matches live issue",
                f"frozen {frozen_digest}, live {assignment.body_sha256}",
            )

    if not args.no_cargo and (member or excluded or standalone):
        process = subprocess.run(
            [
                "cargo",
                "test",
                "--manifest-path",
                str(cdir / "Cargo.toml"),
                "--all-targets",
                "--",
                "--list",
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        listed = len(re.findall(r": test$", process.stdout, re.M))
        first_error = (process.stderr or "").strip().splitlines()[:1]
        report.check(
            process.returncode == 0,
            "cargo test --list succeeds",
            str(first_error),
        )
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
