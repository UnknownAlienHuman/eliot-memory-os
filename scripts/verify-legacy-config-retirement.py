#!/usr/bin/env python3
"""Fail on legacy config reintroduction in current release/install/default paths (issue #1219).

Part B guard for item 1220 (legacy config retirement). Static source/packaging
evidence only: it proves the six deleted legacy files stay deleted and that no
current launch, install, release, or default path re-selects their filenames,
modes, roots, password-file fields, legacy Store source paths, or module
manifests. It is never runtime or Product Proof.

Deleted legacy family (Part A disposition = DELETE, no retained fixture):
- config/eliot.local.toml (mode dev-single-process, .eliot-governor roots,
  disabled IPC, config/modules manifest_dir; zero current-lane consumers;
  bins/eliot LocalAppData gate never reads these paths)
- config/eliot-governor.toml (EliotGovernor service, PATH-resolved surreal exe,
  fixed 127.0.0.1:18000, root user, password_file, .eliot-governor roots,
  crates/eliot-store surql/migrations paths)
- config/modules/builtin.{memory,mailbox,codecortex,verifier}.toml
  (pre-split in-process builtin manifests; current Module/Capability registry
  owns registration, never file presence)

Foreign decoder/fallback retirement (crates/eliot-app, crates/eliot-engine,
crates/eliot-types, crates/eliot-store, crates/governor, bins/eliot
LocalAppData gate, isolated temp-dir test fixtures) is HANDOFF H1-H5 for the
owning crates and is explicitly OUT of this verifier's scan families, so this
guard stays green while handoff owners do their work.

Scan families (current paths only):
- five canonical configs (must never cite legacy as current support)
- crates/kernel/eliot-installation (install/package manifests)
- crates/kernel/eliot-kernel-service, crates/kernel/eliot-host-service
  (current service topology)
- bins/eliotd, bins/eliot-host, bins/eliot-kernel (current bins)
- exact release/install scripts (no broad scripts/ sweep: other scripts own
  unrelated inventory/navigation concerns)
- docs/** narrowed to filename/mode/root citation tokens only (docs carry
  legitimate archaeology/policy prose for Store/password topics, which this
  verifier does not police)

Documented exclusions (not findings):
- scripts/code_navigation_lib/common.py SKIP_DIRS ".eliot-governor" entry:
  navigation hygiene list, not a launch/install/default path (file is outside
  every scan family; listed here so a future family widening does not
  misclassify it).
- config/architecture-boundaries.toml tracked-debt paths
  crates/eliot-store/src/canonical_store/fts_live_tests.rs and
  crates/eliot-store/src/surreal_server.rs: exact debt records, not current
  defaults; any other crates/eliot-store occurrence in canonical configs fails.
- docs/operations/SURREALDB_CREDENTIAL_AUTHORITY.md password_file prose:
  migration-only locator policy (ignored while the Windows provider is
  selected); docs are excluded from the password_file token family.
- Binary/crate name eliot-governor.exe / eliot-governor (lowercase, hyphen):
  current Governor packaging identity, never matched by the case-sensitive
  legacy service token EliotGovernor.
- Cargo manifest_dir variable: never matched by the literal token
  config/modules.
- URL https://eliot.local/... : never matched by the literal filename tokens
  eliot.local.toml / eliot-governor.toml.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


PROOF_CEILING = "STATIC_SOURCE_PACKAGING_EVIDENCE_ONLY"

LEGACY_FILES = (
    "config/eliot.local.toml",
    "config/eliot-governor.toml",
    "config/modules/builtin.memory.toml",
    "config/modules/builtin.mailbox.toml",
    "config/modules/builtin.codecortex.toml",
    "config/modules/builtin.verifier.toml",
)

LEGACY_MODULE_DIR = "config/modules"

CANONICAL_CONFIGS = (
    "config/architecture-boundaries.toml",
    "config/dependency-policy.toml",
    "config/doc-code-conformance.toml",
    "config/doc-traceability-retirement.toml",
    "config/normative-reference-conformance.toml",
)

INSTALL_ROOTS = ("crates/kernel/eliot-installation",)

SERVICE_ROOTS = (
    "crates/kernel/eliot-kernel-service",
    "crates/kernel/eliot-host-service",
)

BIN_ROOTS = (
    "bins/eliotd",
    "bins/eliot-host",
    "bins/eliot-kernel",
)

RELEASE_SCRIPTS = (
    "scripts/build-eliot-windows-x64-release.ps1",
    "scripts/finalize-eliot-windows-x64-release.ps1",
    "scripts/install-pipeline.ps1",
    "scripts/invoke-eliot-windows-x64-production.ps1",
    "scripts/reset-developer-install.ps1",
)

# Exact tracked-debt records that name legacy Store test sources. They are
# debt evidence, not current defaults; anything else matching the Store token
# inside canonical configs is a finding.
STORE_DEBT_ALLOWLIST = (
    "crates/eliot-store/src/canonical_store/fts_live_tests.rs",
    "crates/eliot-store/src/surreal_server.rs",
)

SKIP_DIRS = {
    ".git",
    ".eliot",
    ".codebase-memory",
    "target",
    "dist",
    "reports",
}

TEXT_SUFFIXES = {
    ".toml", ".rs", ".ps1", ".md", ".json", ".yaml", ".yml", ".txt",
    ".schema.json",
}


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    line: int
    detail: str


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _iter_family_files(root: Path, family: str) -> list[Path]:
    base = root / family
    if base.is_file():
        return [base]
    if not base.is_dir():
        return []
    out: list[Path] = []
    for current, dirs, files in __import__("os").walk(base):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            out.append(Path(current) / name)
    return sorted(out)


def _read_lines(path: Path) -> list[str] | None:
    if path.suffix not in TEXT_SUFFIXES and path.suffix != "":
        # PowerShell scripts without suffix edge: still read small files.
        try:
            if path.stat().st_size > 2_000_000:
                return None
        except OSError:
            return None
    try:
        if path.stat().st_size > 2_000_000:
            return None
        return path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return None


def check_legacy_files_absent(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for rel in LEGACY_FILES:
        if (root / rel).exists():
            findings.append(
                Finding(
                    "LCR-001",
                    rel,
                    0,
                    "legacy config file is present; Part A disposition is DELETE "
                    "(no current consumer; foreign decoder retirement is HANDOFF H1-H5)",
                )
            )
    module_dir = root / LEGACY_MODULE_DIR
    if module_dir.is_dir():
        stray = sorted(p for p in module_dir.glob("*.toml"))
        for path in stray:
            rel = _relative(root, path)
            if rel not in LEGACY_FILES:
                findings.append(
                    Finding(
                        "LCR-002",
                        rel,
                        0,
                        "stray module manifest under config/modules; in-process legacy "
                        "builtins cannot register a current module by file presence",
                    )
                )
    return findings


# (code, compiled pattern, families tag, detail)
TOKEN_CHECKS: tuple[tuple[str, "re.Pattern[str]", str, str], ...] = (
    (
        "LCR-010",
        re.compile(r"dev-single-process"),
        "all",
        "legacy runtime mode dev-single-process selected in a current path",
    ),
    (
        "LCR-011",
        re.compile(r"\.eliot-governor"),
        "all",
        "legacy root .eliot-governor selected in a current path",
    ),
    (
        "LCR-012",
        re.compile(r"EliotGovernor"),
        "current",
        "legacy service identity EliotGovernor cited in a current path",
    ),
    (
        "LCR-013",
        re.compile(r"crates/eliot-store"),
        "current",
        "legacy Store source path crates/eliot-store referenced in a current path",
    ),
    (
        "LCR-014",
        re.compile(r"eliot-governor\.toml|eliot\.local\.toml"),
        "all",
        "legacy config filename referenced in a current path",
    ),
    (
        "LCR-015",
        re.compile(r"config/modules"),
        "current",
        "legacy module manifest dir config/modules referenced in a current path",
    ),
    (
        "LCR-016",
        re.compile(r"password_file"),
        "current",
        "password-file field present in a current path; Store credentials must "
        "remain opaque references outside explicit one-shot migration handling",
    ),
    (
        "LCR-017",
        re.compile(r"builtin\.(memory|mailbox|codecortex|verifier)"),
        "current",
        "legacy in-process builtin manifest name referenced in a current path",
    ),
    (
        "LCR-018",
        re.compile(r"surreal_rpc_server"),
        "current",
        "legacy surreal_rpc_server db mode selected in a current path",
    ),
)


def _current_family_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for family in (*CANONICAL_CONFIGS, *INSTALL_ROOTS, *SERVICE_ROOTS, *BIN_ROOTS, *RELEASE_SCRIPTS):
        files.extend(_iter_family_files(root, family))
    # De-duplicate while keeping order.
    seen: set[str] = set()
    unique: list[Path] = []
    for path in files:
        key = path.resolve().as_posix().lower() if path.exists() else path.as_posix()
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def _docs_files(root: Path) -> list[Path]:
    return _iter_family_files(root, "docs")


def check_tokens(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    current_files = _current_family_files(root)
    docs_files = [p for p in _docs_files(root) if p.suffix in (".md", ".toml")]

    for code, pattern, families, detail in TOKEN_CHECKS:
        targets: list[Path] = []
        if families == "all":
            targets = [*current_files, *docs_files]
        else:
            targets = current_files
        for path in targets:
            lines = _read_lines(path)
            if lines is None:
                continue
            rel = _relative(root, path)
            for lineno, line in enumerate(lines, 1):
                if not pattern.search(line):
                    continue
                if code == "LCR-013" and rel == "config/architecture-boundaries.toml":
                    if any(allow in line for allow in STORE_DEBT_ALLOWLIST):
                        continue
                findings.append(Finding(code, rel, lineno, f"{detail}: {line.strip()[:160]}"))
    return findings


def verify(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(check_legacy_files_absent(root))
    findings.extend(check_tokens(root))
    return sorted(findings, key=lambda f: (f.code, f.path, f.line))


def run_self_tests() -> int:
    print("Running verify-legacy-config-retirement self-tests...")
    failures = 0

    def check(name: str, condition: bool) -> None:
        nonlocal failures
        if not condition:
            print(f"SELF_TEST_FAILURE: {name}", file=sys.stderr)
            failures += 1

    # Case 1: clean tree passes (no legacy files, no tokens in families).
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "config").mkdir(parents=True)
        (root / "config/architecture-boundaries.toml").write_text(
            'schema = "eliot.architecture-boundaries.v1"\n', encoding="utf-8"
        )
        (root / "docs").mkdir()
        (root / "docs/notes.md").write_text("# notes\n", encoding="utf-8")
        check("clean tree must pass", verify(root) == [])

    # Case 2: legacy file presence fails LCR-001.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "config").mkdir(parents=True)
        (root / "config/eliot.local.toml").write_text('[runtime]\nmode = "x"\n', encoding="utf-8")
        check(
            "legacy file must raise LCR-001",
            any(f.code == "LCR-001" for f in verify(root)),
        )

    # Case 3: stray module manifest fails LCR-002.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "config/modules").mkdir(parents=True)
        (root / "config/modules/custom.toml").write_text('name = "x"\n', encoding="utf-8")
        check(
            "stray manifest must raise LCR-002",
            any(f.code == "LCR-002" for f in verify(root)),
        )

    # Case 4: legacy mode/root in install family fails LCR-010/LCR-011.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        target = root / "crates/kernel/eliot-installation/src"
        target.mkdir(parents=True)
        (target / "plan.rs").write_text(
            '// mode dev-single-process root .eliot-governor\n', encoding="utf-8"
        )
        codes = {f.code for f in verify(root)}
        check("install mode token must raise LCR-010", "LCR-010" in codes)
        check("install root token must raise LCR-011", "LCR-011" in codes)

    # Case 5: password_file + module manifest + store path in current bin fails.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        target = root / "bins/eliotd/src"
        target.mkdir(parents=True)
        (target / "main.rs").write_text(
            '// password_file crates/eliot-store builtin.memory config/modules '
            'EliotGovernor surreal_rpc_server eliot-governor.toml\n',
            encoding="utf-8",
        )
        codes = {f.code for f in verify(root)}
        for expected in ("LCR-012", "LCR-013", "LCR-014", "LCR-015", "LCR-016", "LCR-017", "LCR-018"):
            check(f"bin token must raise {expected}", expected in codes)

    # Case 6: debt-allowlisted Store paths in boundary policy do not fail,
    # but a non-debt Store reference in canonical config does.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "config").mkdir(parents=True)
        (root / "config/architecture-boundaries.toml").write_text(
            '[[tracked_debt]]\npath = "crates/eliot-store/src/surreal_server.rs"\n',
            encoding="utf-8",
        )
        check(
            "debt-allowlisted store path must pass",
            [f for f in verify(root) if f.code == "LCR-013"] == [],
        )
        (root / "config/dependency-policy.toml").write_text(
            '# crates/eliot-store default\n', encoding="utf-8"
        )
        check(
            "non-debt store path in canonical config must raise LCR-013",
            any(f.code == "LCR-013" for f in verify(root)),
        )

    # Case 7: foreign-lane lookalikes never match (case-sensitive service
    # token, Cargo manifest_dir var, eliot.local URL).
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        target = root / "bins/eliot-host/src"
        target.mkdir(parents=True)
        (target / "main.rs").write_text(
            'let exe = "eliot-governor.exe";\n'
            'let dir = manifest_dir.join("x");\n',
            encoding="utf-8",
        )
        docs = root / "docs"
        docs.mkdir()
        (docs / "guide.md").write_text("see https://eliot.local/x\n", encoding="utf-8")
        check("foreign lookalikes must pass", verify(root) == [])

    if failures:
        return 1
    print("LEGACY_CONFIG_RETIREMENT_SELF_TEST: PASS (7/7 cases verified)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail if legacy config filenames/modes/roots/password-file "
        "fields/module manifests appear in current release/install/default paths."
    )
    parser.add_argument("--root", default=".", help="Repository root directory")
    parser.add_argument("--json-out", help="Write findings JSON to this file")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-tests")
    args = parser.parse_args()

    if args.self_test:
        return run_self_tests()

    root = Path(args.root).resolve()
    findings = verify(root)

    payload = {
        "schema": "eliot.legacy-config-retirement.v1",
        "proof_ceiling": PROOF_CEILING,
        "issue": 1219,
        "status": "PASS" if not findings else "FINDINGS",
        "findings_count": len(findings),
        "findings": [
            {"code": f.code, "path": f.path, "line": f.line, "detail": f.detail}
            for f in findings
        ],
    }
    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print(f"VERIFY_LEGACY_CONFIG_RETIREMENT: {payload['status']} (findings={len(findings)})")
    for finding in findings:
        print(f"  [{finding.code}] {finding.path}:{finding.line}: {finding.detail}")
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
