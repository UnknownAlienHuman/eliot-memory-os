#!/usr/bin/env python3
"""Mechanical acceptance gate for one ELIOT work unit.

Reads `[acceptance]` from a crate's module.toml and proves the crate is
actually implemented. Unlike `cargo test`, this FAILS on an empty crate.

Usage:
    python scripts/verify-work-unit.py --crate <name> [--root .] [--no-cargo]

Exit codes:
    0  every acceptance rule satisfied
    1  one or more rules violated (each printed)
    2  usage / configuration error
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path

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

ISSUE_URL = "https://github.com/UnknownAlienHuman/eliot-memory-os/issues/"

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


class Report:
    def __init__(self) -> None:
        self.fail: list[str] = []
        self.ok: list[str] = []

    def check(self, condition: bool, label: str, detail: str = "") -> None:
        if condition:
            self.ok.append(label)
        else:
            self.fail.append(f"{label}{(': ' + detail) if detail else ''}")


def crate_dir(root: Path, crate: str) -> Path:
    for path in root.rglob("Cargo.toml"):
        if "target" in path.parts:
            continue
        try:
            manifest = tomllib.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if manifest.get("package", {}).get("name") == crate:
            return path.parent
    print(f"error: crate {crate!r} not found under {root}", file=sys.stderr)
    sys.exit(2)


def read_sources(cdir: Path) -> tuple[str, str]:
    """Return (src_text, test_text)."""
    src: list[str] = []
    tests: list[str] = []
    for path in sorted(cdir.rglob("*.rs")):
        if "target" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "tests" in path.parts:
            tests.append(text)
        else:
            src.append(text)
    return "\n".join(src), "\n".join(tests)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--crate", required=True)
    parser.add_argument("--root", default=".")
    parser.add_argument(
        "--no-cargo",
        action="store_true",
        help="skip cargo test --list",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    cdir = crate_dir(root, args.crate)
    mpath = cdir / "module.toml"
    if not mpath.exists():
        print(f"error: {mpath} missing; every work unit needs one", file=sys.stderr)
        return 2

    module = tomllib.loads(mpath.read_text(encoding="utf-8"))
    acc = module.get("acceptance")
    if not acc:
        print(
            f"error: {mpath} has no [acceptance] table; "
            "the unit has no machine-checkable gate",
            file=sys.stderr,
        )
        return 2

    src, tst = read_sources(cdir)
    all_text = src + "\n" + tst
    report = Report()

    # ---- 0. the gate must be at least as strong as its assignment -------
    # A numeric floor alone is insufficient: an agent can satisfy it with
    # unrelated trivial tests. Every numbered assignment case therefore needs
    # one unique, stable test name in `required_tests`, and every such test must
    # actually exist in source. Extra tests remain allowed.
    issue = acc.get("source_issue")
    unit = acc.get("source_unit")
    cases = int(acc.get("test_matrix_cases", 0))
    declared_min = int(acc.get("min_tests", 0))
    required_tests = list(acc.get("required_tests", []))

    if issue:
        print(f"  unit  {unit or '?'}  assignment {ISSUE_URL}{issue}")

    report.check(
        bool(issue),
        "acceptance names source issue",
        "source_issue is missing",
    )
    report.check(
        bool(unit),
        "acceptance names stable unit",
        "source_unit is missing",
    )
    report.check(
        cases > 0,
        "assignment matrix case count is positive",
        f"test_matrix_cases is {cases}",
    )

    if cases:
        report.check(
            declared_min >= cases,
            f"min_tests >= assignment matrix ({cases} cases)",
            f"min_tests is {declared_min}; the gate would pass work that skips "
            f"{cases - declared_min} cases the assignment requires",
        )
        report.check(
            len(required_tests) >= cases,
            f"named case tests >= assignment matrix ({cases} cases)",
            f"required_tests names {len(required_tests)} tests; "
            f"{cases - len(required_tests)} numbered cases have no machine binding",
        )

    duplicate_required = sorted(
        name for name in set(required_tests) if required_tests.count(name) > 1
    )
    report.check(
        not duplicate_required,
        "required test names are unique",
        ", ".join(duplicate_required),
    )

    invalid_required = sorted(
        name for name in required_tests if not re.fullmatch(r"[a-z_][a-z_0-9]*", name)
    )
    report.check(
        not invalid_required,
        "required test names are valid Rust identifiers",
        ", ".join(invalid_required),
    )

    # ---- 1. the crate is not empty -------------------------------------
    src_lines = src.count("\n")
    floor = int(acc.get("min_source_lines", 1))
    report.check(
        src_lines >= floor,
        f"source floor >= {floor} lines",
        f"found {src_lines}",
    )

    # ---- 2. required public exports exist -------------------------------
    found_items = {match.group(2) for match in PUB_ITEM.finditer(src)}
    for name in acc.get("required_exports", []):
        report.check(
            name in found_items,
            f"export `{name}`",
            "not declared pub in src/",
        )

    min_pub = int(acc.get("min_public_items", 0))
    if min_pub:
        report.check(
            len(found_items) >= min_pub,
            f"public items >= {min_pub}",
            f"found {len(found_items)}",
        )

    # ---- 3. every assignment-bound test exists --------------------------
    found_tests = set(TEST_FN.findall(all_text))
    for name in required_tests:
        report.check(
            name in found_tests,
            f"test `{name}`",
            "no #[test] fn with this name",
        )

    min_tests = int(acc.get("min_tests", 0))
    if min_tests:
        report.check(
            len(found_tests) >= min_tests,
            f"tests >= {min_tests}",
            f"found {len(found_tests)}",
        )

    # ---- 4. wire discipline ---------------------------------------------
    if acc.get("require_deny_unknown_fields", False):
        derives = len(re.findall(r"#\[derive[^\]]*Deserialize", src))
        denies = len(re.findall(r"deny_unknown_fields", src))
        report.check(
            derives == 0 or denies >= 1,
            "deny_unknown_fields present",
            f"{derives} Deserialize derives, {denies} deny",
        )
        offenders = [
            field
            for field in SERDE_DEFAULT_FIELD.findall(src)
            if any(root in field for root in PROTECTED_FIELD_ROOTS)
        ]
        report.check(
            not offenders,
            "no serde(default) on protected fields",
            ", ".join(sorted(set(offenders))),
        )

    if acc.get("forbid_unsafe", True):
        report.check(
            "forbid(unsafe_code)" in src,
            "crate declares forbid(unsafe_code)",
        )

    for pattern in acc.get("forbidden_patterns", []):
        hits = len(re.findall(pattern, all_text))
        report.check(
            hits == 0,
            f"forbidden pattern /{pattern}/ absent",
            f"{hits} occurrence(s)",
        )

    for pattern in acc.get("required_patterns", []):
        hits = len(re.findall(pattern, all_text))
        report.check(
            hits > 0,
            f"required pattern /{pattern}/ present",
            "0 occurrences",
        )

    # ---- 5. workspace membership ----------------------------------------
    workspace = tomllib.loads(
        (root / "Cargo.toml").read_text(encoding="utf-8")
    )["workspace"]
    rel = cdir.relative_to(root).as_posix()
    member = rel in set(workspace.get("members", []))
    excluded = rel in set(workspace.get("exclude", []))
    standalone = "[workspace]" in (cdir / "Cargo.toml").read_text(
        encoding="utf-8"
    )
    report.check(
        member or excluded or standalone,
        "crate is buildable by cargo",
        f"{rel} is in neither workspace.members nor workspace.exclude and has "
        "no own [workspace]; cargo will refuse with 'believes it is in a workspace'",
    )

    manifest = tomllib.loads((cdir / "Cargo.toml").read_text(encoding="utf-8"))
    declared = manifest.get("package", {}).get("metadata", {}).get("eliot", {})
    if declared.get("source_status") == "IMPLEMENTED":
        report.check(
            member,
            "implemented crate is a workspace member",
            f"{rel} is still in workspace.exclude; move it to workspace.members, "
            "drop the standalone [workspace] table, and switch dependency pins "
            "to `workspace = true`",
        )

    # ---- 6. tests actually run ------------------------------------------
    if not args.no_cargo and (member or excluded or standalone):
        proc = subprocess.run(
            [
                "cargo",
                "test",
                "--manifest-path",
                str(cdir / "Cargo.toml"),
                "--all-targets",
                "--",
                "--list",
            ],
            capture_output=True,
            text=True,
        )
        listed = len(re.findall(r": test$", proc.stdout, re.M))
        first_error = (proc.stderr or "").strip().splitlines()[:1]
        report.check(
            proc.returncode == 0,
            "cargo test --list succeeds",
            str(first_error),
        )
        report.check(
            listed >= max(1, min_tests),
            f"cargo lists >= {max(1, min_tests)} tests",
            f"listed {listed}",
        )

    # ---- report ----------------------------------------------------------
    width = 72
    print("=" * width)
    print(
        f"work-unit gate :: {args.crate} :: "
        f"module {module.get('module_id', '?')}"
    )
    print("=" * width)
    for label in report.ok:
        print(f"  PASS  {label}")
    for label in report.fail:
        print(f"  FAIL  {label}")
    print("-" * width)
    print(f"  {len(report.ok)} passed, {len(report.fail)} failed")
    return 1 if report.fail else 0


if __name__ == "__main__":
    sys.exit(main())
