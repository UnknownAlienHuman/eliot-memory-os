#!/usr/bin/env python3
"""Legacy source-shape diagnostics, NOT work-unit completion evidence.

The former checker counted declarations and `cargo test -- --list` output.
Neither proves test execution or assignment-case coverage. Until #837 composes
#849/#850/#851/#852, this compatibility entrypoint must fail closed for an
acceptance request, even when every source-shape hint matches. It runs no Cargo
command and cannot approve a work unit. Use the independently reviewed,
assignment-specific bootstrap checks; do not interpret these hints as proof.

Usage:
    python scripts/verify-work-unit.py --crate <name> [--root .] [--no-cargo]

Exit codes:
    0  help only; no work unit is accepted by this legacy entrypoint
    1  execution evidence incomplete, with source-shape findings when available
    2  usage / configuration error
"""

from __future__ import annotations

import argparse
import re
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
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--crate", required=True)
    ap.add_argument("--root", default=".")
    ap.add_argument("--no-cargo", action="store_true", help="legacy diagnostic flag; does not authorize skipping execution proof")
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

    # A successful build/list exit or --no-cargo supplies no execution proof.
    # Do not run the old unbounded discovery subprocess and then promote its
    # output to acceptance. The fixed runner and binding owners are #850/#851;
    # #837 replaces this compatibility path with their actual orchestration.

    # ---- report ----------------------------------------------------------
    width = 72
    print("=" * width)
    print(f"legacy work-unit diagnostics :: {args.crate} :: module {module.get('module_id', '?')}")
    print("=" * width)
    for label in r.ok:
        print(f"  MATCH  {label}")
    for label in r.fail:
        print(f"  FAIL  {label}")
    print("-" * width)
    print(f"  {len(r.ok)} source-shape hints matched, {len(r.fail)} findings")
    print("INCOMPLETE: proof=legacy-source-shape-only; execution=NOT_RUN; "
          "case-binding=NOT_CHECKED; completion=NOT_VERIFIED")
    print("The accepted runner/bindings/catalogue orchestration (#850/#851/#852/#837) "
          "is not integrated into this entrypoint. No work unit is accepted.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
