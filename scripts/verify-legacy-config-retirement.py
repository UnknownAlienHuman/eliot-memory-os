#!/usr/bin/env python3
"""Fail on legacy config reintroduction in current release/install/default paths (issue #1219).

Part B guard for item 1220 (legacy config retirement). Static source/packaging
evidence only: it proves the five deleted legacy files stay deleted, that the
single pending-retention file stays marker-gated and unextended, and that no
current launch, install, release, or default path re-selects their filenames,
modes, roots, password-file fields, legacy Store source paths, or module
manifests. It is never runtime or Product Proof.

Deleted legacy family (Part A disposition = DELETE, no retained fixture):
- config/eliot.local.toml (mode dev-single-process, .eliot-governor roots,
  disabled IPC, config/modules manifest_dir; zero current-lane consumers;
  bins/eliot LocalAppData gate never reads these paths)
- config/modules/builtin.{memory,mailbox,codecortex,verifier}.toml
  (pre-split in-process builtin manifests; current Module/Capability registry
  owns registration, never file presence)

Pending-retention fixture (Part A disposition = RETIREMENT-PENDING, NOT deleted):
- config/eliot-governor.toml is RETAINED with a RETIREMENT-PENDING comment
  header because crates/eliot-engine/src/safety.rs:1905-1909 probes this exact
  file for schema_version = "1" as a blocking schema_contract check, and
  crates/eliot-engine/tests/safety_and_backup.rs:509 expects degraded (not
  blocked) when surreal resolves. Deletion is blocked on foreign-lane H2
  engine-probe retirement. The file is non-production, must not be extended
  with new live keys, and is removed with H2. Verifier rule: absent = retired
  (pass); present WITH the pending-marker header and unextended = pass-with-
  pending (distinct text, exit 0); present WITHOUT the marker, missing the
  schema_version line, or extended with new live keys = finding (exit 1).

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
    "config/modules/builtin.memory.toml",
    "config/modules/builtin.mailbox.toml",
    "config/modules/builtin.codecortex.toml",
    "config/modules/builtin.verifier.toml",
)

# Pending-retention fixture: deletion blocked on foreign-lane H2 engine-probe
# retirement. Absent = fully retired (pass). Present with the pending-marker
# header and without new live keys = pass-with-pending (distinct text, exit 0).
# Present without the marker, missing the schema_version probe line, or
# extended with new live keys = finding (exit 1).
PENDING_FILE = "config/eliot-governor.toml"
PENDING_MARKER = "RETIREMENT-PENDING"
PENDING_PROBE_REF = "safety.rs:1905-1909"
PENDING_SCHEMA_LINE = 'schema_version = "1"'

# Live keys/sections pinned at the item-1220 retention snapshot (base
# 4706f67 plus comment-only RETIREMENT-PENDING header). Any new live key or
# section is an extension of a non-production pending fixture and fails.
PENDING_ALLOWED_KEYS = frozenset({
    "schema_version",
    "service_name",
    "instance_id",
    "mode",
    "exe",
    "bind",
    "endpoint",
    "storage",
    "ns",
    "db",
    "user",
    "credential_provider",
    "credential_id",
    "password_file",
    "log_level",
    "query_timeout_ms",
    "transaction_timeout_ms",
    "startup_timeout_ms",
    "restart_backoff_ms",
    "max_restart_backoff_ms",
    "deny_all",
    "allow_funcs",
    "allow_net",
    "allow_scripting",
    "allow_guests",
    "path",
    "root",
    "surql_dir",
    "migrations_dir",
    "minimum_real_tasks_total",
    "minimum_real_tasks_per_family",
    "minimum_executed_reviews_total",
    "minimum_executed_reviews_per_candidate_family",
    "minimum_complete_outcome_fraction",
    "minimum_shadow_tasks_total",
    "require_zero_authority_violations",
    "require_zero_live_tree_violations",
    "require_zero_recursive_executions",
})

PENDING_ALLOWED_SECTIONS = frozenset({
    "service",
    "db",
    "db.surreal",
    "db.surreal.capabilities",
    "control_wal",
    "blob_store",
    "store",
    "delegation_calibration",
})

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
            if rel not in LEGACY_FILES and rel != PENDING_FILE:
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


def check_pending_retirement(root: Path) -> tuple[list[Finding], bool]:
    """Gate the RETIREMENT-PENDING fixture (config/eliot-governor.toml).

    Returns (findings, is_pending_active). Absent = retired (no findings, not
    pending). Present with marker + probe line + no new live keys = valid
    pending (no findings, pending True). Present without marker, missing the
    schema line, unreadable, or extended = findings (exit 1).
    """
    path = root / PENDING_FILE
    if not path.exists():
        return ([], False)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return (
            [
                Finding(
                    "LCR-003",
                    PENDING_FILE,
                    0,
                    "pending-retention file is unreadable; RETIREMENT-PENDING "
                    "fixture must stay present with marker or be removed with H2",
                )
            ],
            False,
        )
    lines = text.splitlines()
    # Leading comment/blank header block (before the first live line).
    header_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped == "" or stripped.startswith("#"):
            header_lines.append(line)
        else:
            break
    header_text = "\n".join(header_lines)
    if PENDING_MARKER not in header_text:
        return (
            [
                Finding(
                    "LCR-003",
                    PENDING_FILE,
                    0,
                    "pending-retention file present WITHOUT the RETIREMENT-PENDING "
                    f"marker header (expected '{PENDING_MARKER}' + '{PENDING_PROBE_REF}' "
                    "in leading comments; remove with H2, do not run unmarked)",
                )
            ],
            False,
        )
    if PENDING_SCHEMA_LINE not in text:
        return (
            [
                Finding(
                    "LCR-003",
                    PENDING_FILE,
                    0,
                    "pending-retention file missing the engine-probe line "
                    f"{PENDING_SCHEMA_LINE}; the blocking schema_contract probe "
                    f"({PENDING_PROBE_REF}) greps it byte-intact",
                )
            ],
            False,
        )
    # Extension gate: every live (non-comment, non-blank) line must use a
    # pinned key/section. Anything new is a live extension of a
    # non-production fixture.
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped == "" or stripped.startswith("#"):
            continue
        # Strip trailing inline comments (TOML '#' starts a comment outside strings).
        code = line.split("#", 1)[0].strip()
        if not code:
            continue
        if code.startswith("[") and code.endswith("]"):
            section = code[1:-1].strip()
            if section not in PENDING_ALLOWED_SECTIONS:
                return (
                    [
                        Finding(
                            "LCR-003",
                            PENDING_FILE,
                            lineno,
                            f"pending-retention file extended with new section [{section}]; "
                            "non-production fixture is do-not-extend (remove with H2)",
                        )
                    ],
                    False,
                )
            continue
        if "=" in code:
            key = code.split("=", 1)[0].strip()
            if key not in PENDING_ALLOWED_KEYS:
                return (
                    [
                        Finding(
                            "LCR-003",
                            PENDING_FILE,
                            lineno,
                            f"pending-retention file extended with new live key '{key}'; "
                            "non-production fixture is do-not-extend (remove with H2)",
                        )
                    ],
                    False,
                )
            continue
        return (
            [
                Finding(
                    "LCR-003",
                    PENDING_FILE,
                    lineno,
                    "pending-retention file has an unrecognized live line; "
                    "non-production fixture is do-not-extend (remove with H2)",
                )
            ],
            False,
        )
    return ([], True)


def is_pending_retention_active(root: Path) -> bool:
    """True when the pending fixture is present, marked, and unextended."""
    findings, active = check_pending_retirement(root)
    return active and not findings


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
    pending_findings, _ = check_pending_retirement(root)
    findings.extend(pending_findings)
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
    # Re-scoped: config/eliot-governor.toml absent is fully retired (pass,
    # not pending); it must NOT raise LCR-001.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "config").mkdir(parents=True)
        (root / "config/architecture-boundaries.toml").write_text(
            'schema = "eliot.architecture-boundaries.v1"\n', encoding="utf-8"
        )
        (root / "docs").mkdir()
        (root / "docs/notes.md").write_text("# notes\n", encoding="utf-8")
        check("clean tree must pass", verify(root) == [])
        check("absent pending must not be pending", not is_pending_retention_active(root))
        check(
            "absent governor must not raise LCR-001",
            all(f.path != PENDING_FILE for f in verify(root)),
        )

    # Case 2: legacy file presence fails LCR-001 (re-scoped to the five
    # DELETE-disposition files; eliot-governor.toml is pending, not LCR-001).
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

    # Case 8: RETIREMENT-PENDING gate — positive (marked, unextended) passes
    # with pending active; negative (unmarked) and extension fail LCR-003.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "config").mkdir(parents=True)
        pending = root / PENDING_FILE
        # Positive: marker header + probe line + only pinned keys.
        pending.write_text(
            "# RETIREMENT-PENDING \u2014 deletion blocked on H2 engine-probe retirement "
            "(safety.rs:1905-1909); non-production; do-not-extend; remove with H2.\n"
            "# Retained only for the engine probe.\n"
            f"{PENDING_SCHEMA_LINE}\n"
            "\n[service]\nservice_name = \"EliotGovernor\"\n",
            encoding="utf-8",
        )
        check("pending marked file must pass", verify(root) == [])
        check(
            "pending marked file must be pending-active",
            is_pending_retention_active(root),
        )
        pending_findings, active = check_pending_retirement(root)
        check("pending positive must report active", active and pending_findings == [])
        # Negative: present WITHOUT the marker must fail.
        pending.write_text(
            f"{PENDING_SCHEMA_LINE}\n\n[service]\nservice_name = \"EliotGovernor\"\n",
            encoding="utf-8",
        )
        check(
            "pending unmarked file must raise LCR-003",
            any(f.code == "LCR-003" for f in verify(root)),
        )
        check(
            "pending unmarked file must not be pending-active",
            not is_pending_retention_active(root),
        )
        # Negative: marked but missing the probe line must fail.
        pending.write_text(
            "# RETIREMENT-PENDING \u2014 deletion blocked on H2 engine-probe retirement "
            "(safety.rs:1905-1909); non-production; do-not-extend; remove with H2.\n"
            "\n[service]\nservice_name = \"EliotGovernor\"\n",
            encoding="utf-8",
        )
        check(
            "pending file missing probe line must raise LCR-003",
            any(f.code == "LCR-003" for f in verify(root)),
        )
        # Negative: marked but extended with a new live key must fail.
        pending.write_text(
            "# RETIREMENT-PENDING \u2014 deletion blocked on H2 engine-probe retirement "
            "(safety.rs:1905-1909); non-production; do-not-extend; remove with H2.\n"
            f"{PENDING_SCHEMA_LINE}\nnew_live_key = true\n",
            encoding="utf-8",
        )
        check(
            "pending extended file must raise LCR-003",
            any(f.code == "LCR-003" for f in verify(root)),
        )

    if failures:
        return 1
    print("LEGACY_CONFIG_RETIREMENT_SELF_TEST: PASS (8/8 cases verified)")
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
    _, pending_active = check_pending_retirement(root)

    if findings:
        status = "FINDINGS"
    elif pending_active:
        status = "PASS_WITH_PENDING"
    else:
        status = "PASS"
    payload = {
        "schema": "eliot.legacy-config-retirement.v1",
        "proof_ceiling": PROOF_CEILING,
        "issue": 1219,
        "status": status,
        "findings_count": len(findings),
        "pending_retention": PENDING_FILE if pending_active else None,
        "findings": [
            {"code": f.code, "path": f.path, "line": f.line, "detail": f.detail}
            for f in findings
        ],
    }
    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    if status == "PASS_WITH_PENDING":
        print(
            f"VERIFY_LEGACY_CONFIG_RETIREMENT: PASS-WITH-PENDING "
            f"(findings=0 pending={PENDING_FILE})"
        )
    else:
        print(f"VERIFY_LEGACY_CONFIG_RETIREMENT: {payload['status']} (findings={len(findings)})")
    for finding in findings:
        print(f"  [{finding.code}] {finding.path}:{finding.line}: {finding.detail}")
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
