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
TEST_FN = re.compile(r"#\[(?:tokio::)?test[^\]]*\]\s*(?:#\[[^\]]*\]\s*)*(?:async\s+)?fn\s+([a-z_0-9]+)", re.M)
SERDE_DEFAULT_FIELD = re.compile(
    r"#\[serde\(default[^\]]*\)\]\s*(?:#\[[^\]]*\]\s*)*(?:///[^\n]*\n\s*)*pub\s+([a-z_0-9]+)\s*:", re.M
)

PROTECTED_FIELD_ROOTS = (
    "authority", "scope", "effect", "privacy", "ordering", "receipt",
    "grant", "permit", "revoc", "denominator", "fence", "proof",
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
    for p in root.rglob("Cargo.toml"):
        if "target" in p.parts:
            continue
        try:
            d = tomllib.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if d.get("package", {}).get("name") == crate:
            return p.parent
    print(f"error: crate {crate!r} not found under {root}", file=sys.stderr)
    sys.exit(2)


def read_sources(cdir: Path) -> tuple[str, str]:
    """Return (src_text, test_text)."""
    src, tst = [], []
    for f in sorted(cdir.rglob("*.rs")):
        if "target" in f.parts:
            continue
        text = f.read_text(encoding="utf-8", errors="ignore")
        if "tests" in f.parts:
            tst.append(text)
        else:
            src.append(text)
    return "\n".join(src), "\n".join(tst)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--crate", required=True)
    ap.add_argument("--root", default=".")
    ap.add_argument("--no-cargo", action="store_true", help="skip cargo test --list")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    cdir = crate_dir(root, args.crate)
    mpath = cdir / "module.toml"
    if not mpath.exists():
        print(f"error: {mpath} missing; every work unit needs one", file=sys.stderr)
        return 2

    module = tomllib.loads(mpath.read_text(encoding="utf-8"))
    acc = module.get("acceptance")
    if not acc:
        print(f"error: {mpath} has no [acceptance] table; the unit has no machine-checkable gate", file=sys.stderr)
        return 2

    src, tst = read_sources(cdir)
    all_text = src + "\n" + tst
    r = Report()

    # ---- 1. the crate is not empty -------------------------------------
    src_lines = src.count("\n")
    floor = int(acc.get("min_source_lines", 1))
    r.check(src_lines >= floor, f"source floor >= {floor} lines", f"found {src_lines}")

    # ---- 2. required public exports exist -------------------------------
    found_items = {m.group(2) for m in PUB_ITEM.finditer(src)}
    for name in acc.get("required_exports", []):
        r.check(name in found_items, f"export `{name}`", "not declared pub in src/")

    min_pub = int(acc.get("min_public_items", 0))
    if min_pub:
        r.check(len(found_items) >= min_pub, f"public items >= {min_pub}", f"found {len(found_items)}")

    # ---- 3. required tests exist ----------------------------------------
    found_tests = set(TEST_FN.findall(all_text))
    for name in acc.get("required_tests", []):
        r.check(name in found_tests, f"test `{name}`", "no #[test] fn with this name")

    min_tests = int(acc.get("min_tests", 0))
    if min_tests:
        r.check(len(found_tests) >= min_tests, f"tests >= {min_tests}", f"found {len(found_tests)}")

    # ---- 4. wire discipline ---------------------------------------------
    if acc.get("require_deny_unknown_fields", False):
        derives = len(re.findall(r"#\[derive[^\]]*Deserialize", src))
        denies = len(re.findall(r"deny_unknown_fields", src))
        r.check(derives == 0 or denies >= 1, "deny_unknown_fields present", f"{derives} Deserialize derives, {denies} deny")
        offenders = [
            f for f in SERDE_DEFAULT_FIELD.findall(src)
            if any(k in f for k in PROTECTED_FIELD_ROOTS)
        ]
        r.check(not offenders, "no serde(default) on protected fields", ", ".join(sorted(set(offenders))))

    if acc.get("forbid_unsafe", True):
        r.check("forbid(unsafe_code)" in src, "crate declares forbid(unsafe_code)")

    for pat in acc.get("forbidden_patterns", []):
        hits = len(re.findall(pat, all_text))
        r.check(hits == 0, f"forbidden pattern /{pat}/ absent", f"{hits} occurrence(s)")

    for pat in acc.get("required_patterns", []):
        hits = len(re.findall(pat, all_text))
        r.check(hits > 0, f"required pattern /{pat}/ present", "0 occurrences")

    # ---- 5. workspace membership ----------------------------------------
    wsroot = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]
    rel = cdir.relative_to(root).as_posix()
    member = rel in set(wsroot.get("members", []))
    excluded = rel in set(wsroot.get("exclude", []))
    standalone = "[workspace]" in (cdir / "Cargo.toml").read_text(encoding="utf-8")
    r.check(
        member or excluded or standalone,
        "crate is buildable by cargo",
        f"{rel} is in neither workspace.members nor workspace.exclude and has no own [workspace]; "
        "cargo will refuse with 'believes it's in a workspace when it's not'",
    )

    # ---- 6. tests actually run ------------------------------------------
    if not args.no_cargo and (member or excluded or standalone):
        proc = subprocess.run(
            ["cargo", "test", "--manifest-path", str(cdir / "Cargo.toml"), "--all-targets", "--", "--list"],
            capture_output=True, text=True,
        )
        listed = len(re.findall(r": test$", proc.stdout, re.M))
        r.check(proc.returncode == 0, "cargo test --list succeeds", (proc.stderr or "").strip().splitlines()[:1])
        r.check(listed >= max(1, min_tests), f"cargo lists >= {max(1, min_tests)} tests", f"listed {listed}")

    # ---- report ----------------------------------------------------------
    width = 72
    print("=" * width)
    print(f"work-unit gate :: {args.crate} :: module {module.get('module_id', '?')}")
    print("=" * width)
    for label in r.ok:
        print(f"  PASS  {label}")
    for label in r.fail:
        print(f"  FAIL  {label}")
    print("-" * width)
    print(f"  {len(r.ok)} passed, {len(r.fail)} failed")
    return 1 if r.fail else 0


if __name__ == "__main__":
    sys.exit(main())
