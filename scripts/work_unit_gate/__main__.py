#!/usr/bin/env python3
"""D-WU-FINAL thin deterministic orchestration (#837).

Final gate composing accepted #857 contracts, #849 assignment source, #850
descriptor runners, #851 case bindings and #852 catalogue/selection. Thin:
no local acquisition client, Markdown/marker parser, runner/argv/process
implementation, package discovery, catalogue arithmetic or contract-validator
copy. All such operations call the frozen child modules by their exact import
paths only, each logical child operation at most once per distinct selected
input/attempt, no silent retries, no new identity after uncertainty.

Proof kinds (exact, validated before effects):
  catalogue-only : validate full frozen catalogue, no runner, no assignment.
  selected       : verify exact selected issues/packages, fixed runner only
                   for selected plan and actual required evidence.
  full-project   : verify entire exact project profile (all active rows).

Selector (closed admitted lookup only, no arbitrary filter/root/command):
  --issue NUMBER (repeatable, distinct) or --crate NAME (unambiguous package)
  for selected; none for catalogue-only/full-project (full-project selects
  all active rows). Unknown/duplicate/conflicting/malformed options are
  rejected before any runner, network or mutation (exit 2, no fallback).

Source mode (explicit mutually exclusive where assignment needed, no fallback):
  --live | --offline-capture PATH. Required for selected/full-project,
  forbidden for catalogue-only/legacy diagnostic. Live failure never falls
  back offline; offline failure never networks. Authority comes from #849;
  worker-authored self-trust is never accepted.

Legacy compatibility:
  Without --proof, this entrypoint preserves the legacy source-shape
  diagnostic (NOT work-unit completion evidence): always INCOMPLETE (exit 1)
  except --help (exit 0) or configuration error (exit 2). It runs no Cargo
  command, claims no completion, mutates nothing. No work unit is accepted.

Exits (per #857):
  0  explicitly requested proof satisfied (+ --help, no acceptance claimed)
  1  contract/incomplete failure (including missing implementation, discovery
     without execution, failure, skip/ignore/cfg-disabled, timeout/
     unavailable, marker/catalogue/selection mismatch, mutation)
  2  usage/configuration/internal failure (unknown/duplicate/conflicting/
     malformed options, child configuration failure, malformed child return,
     internal error). Typed child violations stay typed; malformed returns
  never pass.

Output: one immutable result with human/JSON projections naming proof kind,
selection, counts, missing/blocked/failed evidence, identities and proof
ceiling. A local package pass is never labelled full completion. Protected
issue/source/stdout/stderr content and credential canaries are redacted.
Deterministic semantic ordering/digest (via contracts.canonical_bytes /
canonical_sha256 / cohort_digest) is separated from observational durations.
Catalogue-only invokes no runner. Diagnostic/no-cargo stays incomplete for
execution. Bootstrap never recursively executes its own completion gate: this
layer only invokes #850 fixed runners via frozen builders, never
verify-work-unit.py nor work_unit_gate.__main__ as a child.

This layer mutates no assignment, source, test, descriptor or workspace. It
inherits child time/output/process bounds (via enforcement_plan) and preserves
cleanup/reconciliation state.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

try:  # exact frozen import paths when run as package module
    from . import contracts as c
    from . import cohort
    from . import assignment_source
    from . import descriptor_runner
    from . import case_binding
except ImportError:  # fallback for direct file loading (delegate context)
    from scripts.work_unit_gate import contracts as c  # type: ignore[no-redef]
    from scripts.work_unit_gate import cohort  # type: ignore[no-redef]
    from scripts.work_unit_gate import assignment_source  # type: ignore[no-redef]
    from scripts.work_unit_gate import descriptor_runner  # type: ignore[no-redef]
    from scripts.work_unit_gate import case_binding  # type: ignore[no-redef]

# Frozen leaf-router byte identities (from test_work_unit_gate_cohort at base;
# Windows CRLF checkout). Used only for the shared-repo freeze check, never
# for temp fixture roots (missing routers are skipped, not failed, so tiny
# bootstrap repositories without routers still verify).
FROZEN_LEAF_ROUTER_SHA256 = {
    "scripts/docs_router.py": "dfa620878659326985b5319baf9516e01a31f49decaae44c438244753d9e84f4",
    "scripts/docs_router_core.py": "752834cad7e5d759eeb522badaba653d6587cb6f8b56393d4a5816c99ccb3c89",
    "scripts/docs_shards.py": "a542962499de7b4db5be555cfa41f27fb826ecc8a7cb6595dc96d3560eff8067",
    "scripts/docs_shards_core.py": "0d94fdbcd034a96ceac7ee40e79ad7b89e7a9723ab9ca4e7b3308d22913e0965",
}

PROOF_CHOICES = ("catalogue-only", "selected", "full-project")

# Frozen CLI contract (#837 D-WU-FINAL, integrator-frozen; byte-for-byte).
# Proof kinds: catalogue-only | selected | full-project (validated before
# effects). Selector: --issue NUMBER (repeatable, distinct values) xor --crate
# NAME (closed lookup, unambiguous package) for selected; none for
# catalogue-only/full-project. Source mode: --live xor --offline-capture PATH
# (explicit, mutually exclusive, no fallback) required for
# selected/full-project, forbidden for catalogue-only. Projection: human by
# default, --json for JSON. JSON keys: proof/selection/selection_label/scope/
# counts/missing_evidence/blocked_evidence/failed_evidence/identities/
# proof_ceiling/digest/terminal/terminal_detail/exit/completion. Exits per
# #857: 0 requested proof satisfied, 1 contract/incomplete, 2 usage/config.
# Offline authority: digests come only from the controller admission sidecar
# <capture>.admission.json, never from the snapshot payload being validated.

# Redaction: protected content + credential canaries. Values never appear in
# diagnostics; only redacted codes are emitted.
_CANARY_PATTERNS = (
    re.compile(r"ghp_[A-Za-z0-9]+"),
    re.compile(r"github_pat_[A-Za-z0-9_]+"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(password|passwd|secret|token|credential|api[_-]?key)\s*[:=]\s*\S+"),
    re.compile(r"Bearer\s+[A-Za-z0-9_.\-]+"),
)


def _redact(text: object) -> str:
    try:
        out = str(text)
    except Exception:
        return "[REDACTED]"
    for pat in _CANARY_PATTERNS:
        try:
            out = pat.sub("[REDACTED]", out)
        except Exception:
            out = "[REDACTED]"
    # Never echo full bodies/sources/streams: keep only first line hint free.
    # Callers must already avoid embedding those; redaction is defence in depth.
    if len(out) > 4000:
        out = out[:4000] + "[TRUNCATED]"
    return out


def _emit(text: str) -> None:
    try:
        sys.stdout.write(_redact(text))
        if not text.endswith("\n"):
            sys.stdout.write("\n")
    except Exception:
        pass


def _emit_error(text: str) -> None:
    try:
        sys.stderr.write(_redact(text))
        if not text.endswith("\n"):
            sys.stderr.write("\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Legacy source-shape diagnostic (preserved verbatim behaviour for --crate
# without --proof). NOT work-unit completion evidence. Runs no Cargo command,
# claims no completion, mutates nothing. No work unit is accepted.
# ---------------------------------------------------------------------------

_PUB_ITEM = re.compile(
    r"^\s*pub(?:\s*\([^)]*\))?\s+"
    r"(?:async\s+|const\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+)*"
    r"(struct|enum|trait|fn|type|const|mod|union)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)",
    re.M,
)
_TEST_FN = re.compile(r"#\[(?:tokio::)?test[^\]]*\]\s*(?:#\[[^\]]*\]\s*)*(?:async\s+)?fn\s+([a-z_0-9]+)", re.M)
_SERDE_DEFAULT_FIELD = re.compile(
    r"#\[serde\(default[^\]]*\)\]\s*(?:#\[[^\]]*\]\s*)*(?:///[^\n]*\n\s*)*pub\s+([a-z_0-9]+)\s*:", re.M,
)
_PROTECTED_FIELD_ROOTS = (
    "authority", "scope", "effect", "privacy", "ordering", "receipt",
    "grant", "permit", "revoc", "denominator", "fence", "proof",
)


class _LegacyReport:
    def __init__(self) -> None:
        self.fail: list[str] = []
        self.ok: list[str] = []


def _legacy_crate_dir(root: Path, crate: str) -> Path:
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


def _legacy_read_sources(cdir: Path) -> tuple[str, str]:
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


def _run_legacy(crate: str, root: Path) -> int:
    cdir = _legacy_crate_dir(root, crate)
    mpath = cdir / "module.toml"
    if not mpath.exists():
        print(f"error: {mpath} missing; every work unit needs one", file=sys.stderr)
        return 2
    try:
        module = tomllib.loads(mpath.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"error: {mpath} unreadable ({_redact(type(exc).__name__)})", file=sys.stderr)
        return 2
    acc = module.get("acceptance")
    if not acc:
        print(f"error: {mpath} has no [acceptance] table; the unit has no machine-checkable gate", file=sys.stderr)
        return 2
    src, tst = _legacy_read_sources(cdir)
    all_text = src + "\n" + tst
    r = _LegacyReport()

    def check(condition: bool, label: str, detail: str = "") -> None:
        if condition:
            r.ok.append(label)
        else:
            r.fail.append(f"{label}{(': ' + detail) if detail else ''}")

    src_lines = src.count("\n")
    floor = int(acc.get("min_source_lines", 1))
    check(src_lines >= floor, f"source floor >= {floor} lines", f"found {src_lines}")
    found_items = {m.group(2) for m in _PUB_ITEM.finditer(src)}
    for name in acc.get("required_exports", []):
        check(name in found_items, f"export `{name}`", "not declared pub in src/")
    min_pub = int(acc.get("min_public_items", 0))
    if min_pub:
        check(len(found_items) >= min_pub, f"public items >= {min_pub}", f"found {len(found_items)}")
    found_tests = set(_TEST_FN.findall(all_text))
    for name in acc.get("required_tests", []):
        check(name in found_tests, f"test `{name}`", "no #[test] fn with this name")
    min_tests = int(acc.get("min_tests", 0))
    if min_tests:
        check(len(found_tests) >= min_tests, f"tests >= {min_tests}", f"found {len(found_tests)}")
    if acc.get("require_deny_unknown_fields", False):
        derives = len(re.findall(r"#\[derive[^\]]*Deserialize", src))
        denies = len(re.findall(r"deny_unknown_fields", src))
        check(derives == 0 or denies >= 1, "deny_unknown_fields present", f"{derives} Deserialize derives, {denies} deny")
        offenders = [
            f for f in _SERDE_DEFAULT_FIELD.findall(src)
            if any(k in f for k in _PROTECTED_FIELD_ROOTS)
        ]
        check(not offenders, "no serde(default) on protected fields", ", ".join(sorted(set(offenders))))
    if acc.get("forbid_unsafe", True):
        check("forbid(unsafe_code)" in src, "crate declares forbid(unsafe_code)")
    for pat in acc.get("forbidden_patterns", []):
        hits = len(re.findall(pat, all_text))
        check(hits == 0, f"forbidden pattern /{pat}/ absent", f"{hits} occurrence(s)")
    for pat in acc.get("required_patterns", []):
        hits = len(re.findall(pat, all_text))
        check(hits > 0, f"required pattern /{pat}/ present", "0 occurrences")
    try:
        wsroot = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]
    except Exception:
        print(f"error: {root / 'Cargo.toml'} missing workspace table", file=sys.stderr)
        return 2
    rel = cdir.relative_to(root).as_posix()
    member = rel in set(wsroot.get("members", []))
    excluded = rel in set(wsroot.get("exclude", []))
    try:
        standalone = "[workspace]" in (cdir / "Cargo.toml").read_text(encoding="utf-8")
    except Exception:
        standalone = False
    check(
        member or excluded or standalone,
        "crate is buildable by cargo",
        f"{rel} is in neither workspace.members nor workspace.exclude and has no own [workspace]; "
        "cargo will refuse with 'believes it's in a workspace when it's not'",
    )
    width = 72
    print("=" * width)
    print(f"legacy work-unit diagnostics :: {crate} :: module {module.get('module_id', '?')}")
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


# ---------------------------------------------------------------------------
# Final orchestration helpers (thin, deterministic, no child copies)
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=(
            "D-WU-FINAL thin deterministic work-unit gate (#837). "
            "Legacy source-shape diagnostics, NOT work-unit completion evidence "
            "when invoked without --proof. No work unit is accepted by the legacy "
            "path. Use --proof catalogue-only|selected|full-project with explicit "
            "--live|--offline-capture for real verification. "
            "Selecting an existing issue/package/profile is allowed only through "
            "the closed admitted lookup; no arbitrary test filter, source root, "
            "command or proof override."
        )
    )
    ap.add_argument("--crate", default=None, help="legacy/package selector (closed lookup)")
    ap.add_argument("--root", default=".", help="repository root for descriptor/attempt paths")
    ap.add_argument("--no-cargo", action="store_true",
                    help="legacy diagnostic flag; does not authorize skipping execution proof")
    ap.add_argument("--proof", default=None, choices=PROOF_CHOICES,
                    help="exact requested proof kind (validated before effects)")
    ap.add_argument("--issue", action="append", default=None,
                    help="selected issue number (repeatable with distinct values, closed lookup)")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--live", action="store_true", help="use live GitHub authority (no fallback)")
    src.add_argument("--offline-capture", default=None,
                     help="explicit trusted offline snapshot path (no fallback, no network)")
    ap.add_argument("--json", action="store_true", help="emit JSON projection instead of human")
    return ap


def _reject_duplicates(argv: list[str]) -> int | None:
    """Reject duplicate/conflicting spellings before effects. Returns exit or None."""
    singles = ("--crate", "--root", "--proof", "--offline-capture", "--live", "--no-cargo", "--json", "--help", "-h")
    seen: dict[str, int] = {}
    for tok in argv:
        if tok in singles:
            seen[tok] = seen.get(tok, 0) + 1
    for flag, count in seen.items():
        if count > 1:
            _emit_error(f"error: duplicate option {flag}; rejected before execution")
            return 2
    # --issue may repeat with distinct values; duplicate values are rejected later.
    return None


def _parse_issue_list(raw: list[str] | None) -> tuple[list[int] | None, int | None]:
    if raw is None:
        return None, None
    values: list[int] = []
    for item in raw:
        for part in str(item).split(","):
            part = part.strip()
            if not part:
                _emit_error("error: malformed --issue value; rejected before execution")
                return None, 2
            if not re.fullmatch(r"[0-9]+", part):
                _emit_error("error: malformed --issue value; rejected before execution")
                return None, 2
            try:
                num = int(part)
            except Exception:
                _emit_error("error: malformed --issue value; rejected before execution")
                return None, 2
            if num <= 0 or num > 2**63 - 1:
                _emit_error("error: malformed --issue value; rejected before execution")
                return None, 2
            values.append(num)
    if len(set(values)) != len(values):
        _emit_error("error: duplicate --issue value; rejected before execution")
        return None, 2
    return sorted(values), None


def _resolve_root(raw: str) -> tuple[Path | None, int | None]:
    try:
        root = Path(raw).resolve()
    except Exception:
        _emit_error("error: malformed --root; rejected before execution")
        return None, 2
    if not root.is_dir():
        _emit_error(f"error: --root {raw!r} is not a directory")
        return None, 2
    return root, None


def _selected_unit_for_crate(crate: str, decoded: dict[int, dict]) -> int | None:
    # Closed lookup derived from the decoded plan/selection catalogue (never
    # an echo, never guessed): exactly one package-name match yields its
    # issue number; zero or several matches yield None (caller fails closed
    # as unknown/ambiguous selection). Binding is validated later via
    # parse_descriptor + materialize_selection_plan.
    matches = [
        num for num, data in decoded.items()
        if isinstance(data, dict) and isinstance(data.get("package"), dict)
        and data["package"].get("name") == crate
    ]
    if len(matches) != 1:
        return None
    return matches[0]


def _result_digest(proof: str, selection: list[int], counts: dict, ceiling: str) -> str:
    # Digest derives from canonical bytes, never echoes an input label.
    payload = {"proof": proof, "selection": sorted(selection), "counts": counts, "ceiling": ceiling}
    try:
        return c.canonical_sha256(payload)
    except c.ContractViolation:
        return "0" * 64


def _render_human(result: dict) -> str:
    lines = []
    lines.append("=" * 72)
    lines.append(f"d-wu-final :: proof={result['proof']} :: selection={result['selection_label']} :: {result['terminal']}")
    lines.append("=" * 72)
    lines.append(f"  proof_kind={result['proof']}")
    lines.append(f"  selection={result['selection_label']}")
    lines.append(f"  scope={result['scope']}")
    lines.append(f"  issues={','.join(str(n) for n in result['selection'])}" if result["selection"] else "  issues=-")
    lines.append(f"  matrix_cases={result['counts'].get('matrix_cases', 0)}")
    lines.append(f"  missing={result['counts'].get('missing', 0)} blocked={result['counts'].get('blocked', 0)} "
                 f"failed={result['counts'].get('failed', 0)} passed={result['counts'].get('passed', 0)}")
    if result.get("missing_evidence"):
        lines.append(f"  missing_evidence={','.join(result['missing_evidence'][:8])}")
    if result.get("blocked_evidence"):
        lines.append(f"  blocked_evidence={','.join(result['blocked_evidence'][:8])}")
    if result.get("failed_evidence"):
        lines.append(f"  failed_evidence={','.join(result['failed_evidence'][:8])}")
    lines.append(f"  identities={result.get('identities_label', '-')}")
    lines.append(f"  proof_ceiling={result['proof_ceiling']}")
    lines.append(f"  digest={result['digest']}")
    lines.append("-" * 72)
    if result["exit"] == 0:
        # A local package pass is never labelled full completion.
        if result["proof"] == "full-project":
            lines.append("PASS: explicitly requested full-project proof satisfied.")
        else:
            lines.append(f"PASS: explicitly requested {result['proof']} proof satisfied "
                         "(selected-verification-only; not full completion).")
    elif result["exit"] == 2:
        lines.append(f"CONFIGURATION: {result['terminal_detail']}")
    else:
        lines.append(f"INCOMPLETE: {result['terminal_detail']}")
    lines.append(f"completion={'VERIFIED' if result['exit'] == 0 else 'NOT_VERIFIED'}")
    return "\n".join(lines)


def _render_json(result: dict) -> str:
    doc = {
        "proof": result["proof"],
        "selection": list(result["selection"]),
        "selection_label": result["selection_label"],
        "scope": result["scope"],
        "counts": dict(result["counts"]),
        "missing_evidence": list(result.get("missing_evidence", [])),
        "blocked_evidence": list(result.get("blocked_evidence", [])),
        "failed_evidence": list(result.get("failed_evidence", [])),
        "identities": list(result.get("identities", [])),
        "proof_ceiling": result["proof_ceiling"],
        "digest": result["digest"],
        "terminal": result["terminal"],
        "terminal_detail": result["terminal_detail"],
        "exit": result["exit"],
        "completion": ("VERIFIED" if result["exit"] == 0 else "NOT_VERIFIED"),
    }
    try:
        return json.dumps(doc, sort_keys=True, separators=(",", ":"))
    except Exception:
        return json.dumps({"exit": 2, "terminal": "CONFIGURATION", "completion": "NOT_VERIFIED"},
                          sort_keys=True)


def _discover_descriptor_files(root: Path) -> list[tuple[int, Path]]:
    """Closed lookup: only .github/work-units/<number>.toml, numeric names."""
    base = root / ".github" / "work-units"
    found: list[tuple[int, Path]] = []
    try:
        if not base.is_dir():
            return []
        for child in sorted(base.iterdir(), key=lambda p: p.name):
            if not child.is_file() or child.suffix != ".toml":
                continue
            stem = child.stem
            if not re.fullmatch(r"[0-9]+", stem):
                continue
            try:
                num = int(stem)
            except Exception:
                continue
            if num <= 0:
                continue
            found.append((num, child))
    except Exception:
        return []
    return found


def _typed_from_decoded(data: dict):  # type: ignore[no-untyped-def]
    """Convert decode_descriptor dict to typed descriptor via frozen constructors.

    Used only for catalogue validation before assignment (no authority claim).
    Binding to assignment remains exclusively in parse_descriptor (called later
    with the acquired receipt). No child logic copied; only frozen constructors.
    """
    repo_raw = data["issue"]["repository"]
    repo = c.RepositoryIdentity(owner=repo_raw["owner"], name=repo_raw["name"])
    issue = c.IssueIdentity(repository=repo, number=data["issue"]["number"])
    converted = dict(data)
    converted.update(
        identity=c.DescriptorIdentity(**data["identity"]),
        issue=issue,
        unit=c.WorkUnitIdentity(**data["unit"]),
        mode=c.RunnerMode(data["mode"]),
        proof_ceiling=c.ProofCeiling(**data["proof_ceiling"]),
        source_roots=tuple(c.RepositoryPath(**p) for p in data["source_roots"]),
        test_roots=tuple(c.RepositoryPath(**p) for p in data["test_roots"]),
        requirements=c.VerificationRequirements(**(data["requirements"] | {
            "required_guards": tuple(c.WorkUnitIdentity(**g) for g in data["requirements"]["required_guards"])})),
        bounds=c.ExecutionBounds(**data["bounds"]),
        package=c.PackageIdentity(**data["package"]) if "package" in data else None,
        module=c.ModuleIdentity(**data["module"]) if "module" in data else None,
    )
    return c.WorkUnitDescriptor.from_mapping(converted)


def main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    dup = _reject_duplicates(args_list)
    if dup is not None:
        return dup
    parser = _build_parser()
    # Unknown/malformed options reject before effects (exit 2). Let argparse's
    # SystemExit propagate so in-process callers observe SystemExit(2) exactly
    # like the legacy entrypoint (no inspection happens before this point).
    args = parser.parse_args(args_list)

    # --help is handled by argparse (exit 0, no acceptance claimed).
    root, err = _resolve_root(args.root)
    if err is not None:
        return err
    assert root is not None

    # Legacy diagnostic when no exact proof kind requested (preserve --crate).
    if args.proof is None:
        if args.live or args.offline_capture is not None:
            _emit_error("error: --live/--offline-capture require --proof; rejected before execution")
            return 2
        if args.issue is not None:
            _emit_error("error: --issue requires --proof; rejected before execution")
            return 2
        if args.crate is None:
            _emit_error("error: --crate is required without --proof; rejected before execution")
            return 2
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}", args.crate):
            _emit_error("error: malformed --crate; rejected before execution")
            return 2
        try:
            return _run_legacy(args.crate, root)
        except SystemExit as exc:
            return int(exc.code) if isinstance(exc.code, int) else 2
        except Exception as exc:
            _emit_error(f"error: legacy diagnostic internal ({_redact(type(exc).__name__)})")
            return 2

    # Exact proof kind + selector validated before effects.
    proof: str = args.proof
    issues, err = _parse_issue_list(args.issue)
    if err is not None:
        return err
    assert issues is None or isinstance(issues, list)

    offline_path: Path | None = None
    if args.offline_capture is not None:
        try:
            offline_path = Path(args.offline_capture)
            if not offline_path.is_absolute():
                # Resolve relative captures against cwd (controller-admitted path);
                # traversal outside cwd is rejected as malformed, not trusted.
                offline_path = (Path.cwd() / offline_path).resolve()
            else:
                offline_path = offline_path.resolve()
        except Exception:
            _emit_error("error: malformed --offline-capture; rejected before execution")
            return 2
        if not offline_path.is_file():
            _emit_error("error: --offline-capture file unavailable; rejected before execution")
            return 2

    # Source-mode rules: explicit mutually exclusive where needed, no fallback.
    needs_source = proof in ("selected", "full-project")
    has_live = bool(args.live)
    has_offline = offline_path is not None
    if proof == "catalogue-only":
        if has_live or has_offline:
            _emit_error("error: catalogue-only takes no source mode; rejected before execution")
            return 2
    else:
        if has_live == has_offline:
            _emit_error("error: selected/full-project require exactly one of --live|--offline-capture; no fallback")
            return 2

    # Selector rules (closed lookup only).
    if proof == "catalogue-only":
        if issues is not None or args.crate is not None:
            _emit_error("error: catalogue-only takes no selector; rejected before execution")
            return 2
        selection_numbers: list[int] = []
    elif proof == "full-project":
        if issues is not None or args.crate is not None:
            _emit_error("error: full-project selects the entire profile; explicit selector rejected")
            return 2
        selection_numbers = []
    else:  # selected
        if (issues is None) == (args.crate is None):
            _emit_error("error: selected requires exactly one of --issue|--crate; rejected before execution")
            return 2
        if issues is not None:
            selection_numbers = list(issues)
        else:
            assert args.crate is not None
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}", args.crate):
                _emit_error("error: malformed --crate; rejected before execution")
                return 2
            # Crate resolves only through catalogue binding validated later;
            # unambiguous identity is enforced there, never guessed here.
            selection_numbers = []

    # Memo: each logical child op at most once per distinct selected input.
    memo_catalogue: dict[str, object] = {}
    memo_selection: dict[str, object] = {}
    memo_assignment: dict[int, object] = {}
    memo_descriptor: dict[int, object] = {}
    memo_markers: dict[str, object] = {}

    def fail_result(terminal_detail: str, exit_code: int, counts: dict | None = None,
                    missing: list | None = None, blocked: list | None = None,
                    failed: list | None = None, identities: list | None = None,
                    ceiling: str = "selected-verification-only",
                    scope: str = "selected") -> dict:
        counts = counts or {"matrix_cases": 0, "missing": 0, "blocked": 0, "failed": 0, "passed": 0}
        sel = sorted(selection_numbers)
        label = ",".join(str(n) for n in sel) if sel else ("all" if proof == "full-project" else "-")
        digest = _result_digest(proof, sel, counts, ceiling)
        terminal = "PASS" if exit_code == 0 else ("CONFIGURATION" if exit_code == 2 else "INCOMPLETE")
        return {
            "proof": proof, "selection": sel, "selection_label": label, "scope": scope,
            "counts": counts, "missing_evidence": list(missing or []),
            "blocked_evidence": list(blocked or []), "failed_evidence": list(failed or []),
            "identities": list(identities or []),
            "identities_label": ",".join((identities or [])[:4]) if identities else "-",
            "proof_ceiling": ceiling, "digest": digest,
            "terminal": terminal, "terminal_detail": terminal_detail, "exit": exit_code,
        }

    def finish(result: dict) -> int:
        if args.json:
            _emit(_render_json(result))
        else:
            _emit(_render_human(result))
        return int(result["exit"])

    try:
        # Catalogue-only: no runner, no assignment, catalogue integrity only.
        if proof == "catalogue-only":
            discovered = _discover_descriptor_files(root)
            if not discovered:
                return finish(fail_result("catalogue missing: no descriptors under .github/work-units",
                                          1, ceiling="catalogue-integrity-only", scope="selected"))
            seen_issues: list = []
            typed_descs: list = []
            for num, path in discovered:
                key = f"decode:{num}"
                if key in memo_catalogue:
                    data = memo_catalogue[key]
                else:
                    try:
                        raw = path.read_bytes()
                    except OSError:
                        return finish(fail_result(f"catalogue missing implementation: {num}", 1,
                                                  ceiling="catalogue-integrity-only", scope="selected",
                                                  missing=[f"issue-{num}"]))
                    fname = f".github/work-units/{num}.toml"
                    try:
                        data = descriptor_runner.decode_descriptor(raw, fname)
                    except descriptor_runner.RunnerInputError as exc:
                        return finish(fail_result(f"catalogue contract failure: {_redact(exc)}", 1,
                                                  ceiling="catalogue-integrity-only", scope="selected",
                                                  failed=[f"issue-{num}"]))
                    except c.ContractViolation as exc:
                        return finish(fail_result(f"catalogue contract failure: {_redact(type(exc).__name__)}", 1,
                                                  ceiling="catalogue-integrity-only", scope="selected",
                                                  failed=[f"issue-{num}"]))
                    memo_catalogue[key] = data
                assert isinstance(data, dict)
                try:
                    typed = _typed_from_decoded(data)
                except c.ContractViolation:
                    return finish(fail_result("catalogue contract failure: descriptor rejected", 1,
                                              ceiling="catalogue-integrity-only", scope="selected",
                                              failed=[f"issue-{num}"]))
                except Exception:
                    return finish(fail_result("catalogue internal failure", 2,
                                              ceiling="catalogue-integrity-only", scope="selected"))
                if type(typed) is not c.WorkUnitDescriptor:
                    return finish(fail_result("catalogue internal failure: malformed descriptor", 2,
                                              ceiling="catalogue-integrity-only", scope="selected"))
                typed_descs.append(typed)
                seen_issues.append(typed.issue)
            # Build full frozen catalogue (all assigned; blocked/planned stay
            # visible when supplied via mocked catalogue in tests).
            try:
                rows = tuple(c.CatalogueRow(issue=d.issue, unit=d.unit, body_sha256=d.body_sha256,
                                            disposition=c.CatalogueDisposition.ASSIGNED,
                                            descriptor=d, prerequisites=()) for d in sorted(typed_descs, key=lambda d: d.issue))
                expected = tuple(sorted({r.issue for r in rows}))
                catalogue = cohort.materialize_catalogue(rows, expected)
            except cohort.CohortError as exc:
                return finish(fail_result(f"catalogue structural failure: {_redact(exc.problem.value if hasattr(exc, 'problem') else type(exc).__name__)}", 1,
                                          ceiling="catalogue-integrity-only", scope="selected",
                                          failed=["catalogue"]))
            except c.ContractViolation:
                return finish(fail_result("catalogue contract failure", 1,
                                          ceiling="catalogue-integrity-only", scope="selected",
                                          failed=["catalogue"]))
            except Exception:
                return finish(fail_result("catalogue internal failure", 2,
                                          ceiling="catalogue-integrity-only", scope="selected"))
            if type(catalogue) is not c.CatalogueIntegrityReceipt:
                return finish(fail_result("catalogue internal failure: malformed receipt", 2,
                                          ceiling="catalogue-integrity-only", scope="selected"))
            counts = {"matrix_cases": int(catalogue.matrix_cases), "missing": 0,
                      "blocked": 0, "failed": 0, "passed": len(rows)}
            sel: list[int] = []
            digest = c.canonical_sha256({"schema": c.CONTRACT_SCHEMA_REVISION, "kind": "catalogue",
                                         "payload": catalogue}) if hasattr(c, "CONTRACT_SCHEMA_REVISION") else _result_digest(proof, sel, counts, "catalogue-integrity-only")
            result = {
                "proof": proof, "selection": sel, "selection_label": "all",
                "scope": "selected",
                "counts": counts, "missing_evidence": [], "blocked_evidence": [],
                "failed_evidence": [],
                "identities": [f"catalogue:{catalogue.sha256[:12]}"],
                "identities_label": f"catalogue:{catalogue.sha256[:12]}",
                "proof_ceiling": "catalogue-integrity-only", "digest": digest,
                "terminal": "PASS", "terminal_detail": "catalogue integrity valid (no execution claimed)",
                "exit": 0,
            }
            return finish(result)

        # Execution proofs: diagnostic/no-cargo stays incomplete, no runner.
        if args.no_cargo:
            label = ",".join(str(n) for n in sorted(selection_numbers)) if selection_numbers else (args.crate or "-")
            return finish(fail_result("diagnostic/no-cargo cannot claim complete execution: execution=NOT_RUN",
                                      1, missing=["execution"],
                                      identities=[f"selection:{label}"]))

        # Discover all descriptors (closed lookup, no glob over sources).
        discovered_all = _discover_descriptor_files(root)
        if not discovered_all:
            return finish(fail_result("missing selected implementation: no descriptors", 1,
                                      missing=["descriptors"]))

        # Resolve selected numbers (crate via closed catalogue lookup derived
        # from the decoded plan/selection, never echoed or guessed).
        decoded_all: dict[int, dict] = {}
        raw_all: dict[int, bytes] = {}
        if args.crate is not None and proof == "selected":
            # Crate lookup peek uses the frozen strict cohort decoder only
            # (TOML shape + filename binding, no acquisition/binding claim).
            # Binding stays exclusively in parse_descriptor below, so each
            # file undergoes decode_descriptor at most once per run.
            for num, path in discovered_all:
                try:
                    raw0 = path.read_bytes()
                except OSError:
                    continue
                try:
                    d0 = cohort.decode_cohort_descriptor(raw0, f".github/work-units/{num}.toml")
                except Exception:
                    continue
                if type(d0) is not dict:
                    _emit_error("error: malformed descriptor return; bounded non-success")
                    return finish(fail_result("malformed child return", 2))
                decoded_all[num] = d0
                raw_all[num] = raw0
            assert args.crate is not None
            match = _selected_unit_for_crate(args.crate, decoded_all)
            if match is None:
                multi = sum(
                    1 for d0 in decoded_all.values()
                    if isinstance(d0, dict) and isinstance(d0.get("package"), dict)
                    and d0["package"].get("name") == args.crate
                )
                if multi > 1:
                    return finish(fail_result("selection ambiguous or unknown package", 1,
                                              failed=[f"package:{args.crate}"]))
                return finish(fail_result("selection ambiguous or unknown package", 2,
                                          missing=[f"package:{args.crate}"]))
            wanted = {match}
        elif selection_numbers:
            wanted = set(selection_numbers)
        else:
            wanted = set()
        if proof == "full-project":
            wanted = {num for num, _ in discovered_all}

        if proof == "selected" and not wanted:
            return finish(fail_result("selection missing: unknown or ambiguous selector", 1,
                                      missing=["selection"]))
        # Omitted/substituted rows and selected-to-full promotion cannot pass:
        # selection must be an exact subset of the frozen catalogue denominator.
        discovered_numbers = {num for num, _ in discovered_all}
        if not set(wanted).issubset(discovered_numbers):
            missing_rows = sorted(set(wanted) - discovered_numbers)
            return finish(fail_result("selection mismatch: omitted or substituted row", 1,
                                      missing=[f"issue-{n}" for n in missing_rows]))

        # Partition selected vs unselected (each file decoded at most once).
        selected_files = {num: p for num, p in discovered_all if num in wanted}
        unselected_files = {num: p for num, p in discovered_all if num not in wanted}
        if proof == "selected" and not selected_files:
            return finish(fail_result("missing selected implementation", 1,
                                      missing=[f"issue-{n}" for n in sorted(wanted)]))

        # Acquire assignment receipts for selected only (no fallback, once per issue).
        mode = c.SourceAuthority.LIVE_GITHUB if has_live else c.SourceAuthority.EXPLICIT_OFFLINE_SNAPSHOT
        bound_descs: dict[int, object] = {}
        for num in sorted(selected_files):
            if num in memo_assignment and num in memo_descriptor:
                bound_descs[num] = memo_descriptor[num]
                continue
            # Identity peek via the frozen strict cohort decoder only (no local
            # TOML parsing, no Markdown/marker/runner handling): it validates
            # TOML shape + filename binding without claiming acquisition
            # authority. Binding remains exclusively in parse_descriptor below,
            # which performs the single decode_descriptor for this file.
            # Crate selections reuse the lookup bytes/dict (no re-read).
            if num in raw_all and num in decoded_all:
                raw_sel = raw_all[num]
                peek = decoded_all[num]
            else:
                try:
                    raw_sel = selected_files[num].read_bytes()
                except OSError:
                    return finish(fail_result(f"missing selected implementation: issue-{num}", 1,
                                              missing=[f"issue-{num}"]))
                try:
                    peek = cohort.decode_cohort_descriptor(raw_sel, f".github/work-units/{num}.toml")
                except cohort.CohortError:
                    return finish(fail_result(f"contract failure: descriptor unreadable issue-{num}", 1,
                                              failed=[f"issue-{num}"]))
                except Exception:
                    return finish(fail_result("descriptor internal failure", 2))
                if type(peek) is not dict:
                    return finish(fail_result("malformed child return: descriptor peek", 2))
            try:
                unit_raw = peek.get("unit")
                unit_value = unit_raw.get("value") if isinstance(unit_raw, dict) else None
                if not isinstance(unit_value, str):
                    raise c.ContractViolation("descriptor unit missing")
                unit = c.WorkUnitIdentity(unit_value)
            except c.ContractViolation:
                return finish(fail_result(f"contract failure: descriptor unit invalid issue-{num}", 1,
                                          failed=[f"issue-{num}"]))
            except Exception:
                return finish(fail_result("descriptor internal failure", 2))
            # Repository identity from the same frozen-decoded mapping
            # (closed; no git/network lookup). Mismatch with the acquired
            # receipt fails closed at parse_descriptor binding.
            try:
                issue_raw = peek.get("issue", {})
                repo_raw = issue_raw.get("repository", {}) if isinstance(issue_raw, dict) else {}
                owner_raw = repo_raw.get("owner") if isinstance(repo_raw, dict) else None
                name_raw = repo_raw.get("name") if isinstance(repo_raw, dict) else None
                if not isinstance(owner_raw, str) or not isinstance(name_raw, str):
                    raise c.ContractViolation("issue identity missing")
                repo = c.RepositoryIdentity(owner_raw, name_raw)
                issue_id = c.IssueIdentity(repo, num)
            except c.ContractViolation:
                return finish(fail_result(f"contract failure: issue identity invalid issue-{num}", 1,
                                          failed=[f"issue-{num}"]))
            # Source purpose fixed by plan: active assignment for selected work.
            try:
                request = assignment_source.SourceRequest(issue=issue_id, unit=unit,
                                                          source_use=c.AssignmentSourceUse.ACTIVE_ASSIGNMENT)
            except assignment_source.SourceError:
                return finish(fail_result("configuration failure: source request", 2))
            except c.ContractViolation:
                return finish(fail_result("contract failure: source request", 1,
                                          failed=[f"issue-{num}"]))
            except Exception:
                return finish(fail_result("internal failure: source request", 2))
            # Offline trusted capture: controller-admitted config ONLY. Expected
            # digests come from the admission sidecar <capture>.admission.json
            # (same directory, fixed suffix derived from the admitted path —
            # never from the snapshot payload being validated). #849 validates
            # the snapshot bytes against this config; worker self-trust would
            # always agree with itself and is never accepted.
            offline_cfg = None
            if mode is c.SourceAuthority.EXPLICIT_OFFLINE_SNAPSHOT:
                assert offline_path is not None
                try:
                    import json as _json

                    sidecar = offline_path.with_name(offline_path.name + ".admission.json")
                    try:
                        admission_raw = sidecar.read_bytes()
                    except OSError:
                        return finish(fail_result("offline failure: capture not admitted", 1,
                                                  failed=[f"issue-{num}"]))
                    if len(admission_raw) > 65536:
                        return finish(fail_result("offline failure: capture not admitted", 1,
                                                  failed=[f"issue-{num}"]))
                    try:
                        admission = _json.loads(admission_raw.decode("utf-8"))
                    except Exception:
                        return finish(fail_result("offline failure: capture not admitted", 1,
                                                  failed=[f"issue-{num}"]))
                    if type(admission) is not dict:
                        return finish(fail_result("offline failure: capture not admitted", 1,
                                                  failed=[f"issue-{num}"]))
                    snap_sha = admission.get("snapshot_sha256")
                    prod_raw = admission.get("producer")
                    cap_raw = admission.get("capture_receipt_sha256")
                    fresh_raw = admission.get("freshness_policy_sha256")
                    max_age_raw = admission.get("max_age_seconds", 86400)
                    if not (isinstance(snap_sha, str) and isinstance(prod_raw, str)
                            and isinstance(cap_raw, str) and isinstance(fresh_raw, str)):
                        return finish(fail_result("offline failure: capture not admitted", 1,
                                                  failed=[f"issue-{num}"]))
                    if type(max_age_raw) is not int or not 1 <= max_age_raw <= 86400:
                        return finish(fail_result("offline failure: capture not admitted", 1,
                                                  failed=[f"issue-{num}"]))
                    try:
                        producer = c.WorkUnitIdentity(prod_raw)
                    except c.ContractViolation:
                        return finish(fail_result("offline failure: producer invalid", 1,
                                                  failed=[f"issue-{num}"]))
                    try:
                        offline_cfg = assignment_source.TrustedOfflineCapture(
                            request=request, path=offline_path, snapshot_sha256=snap_sha,
                            producer=producer, capture_receipt_sha256=cap_raw,
                            freshness_policy_sha256=fresh_raw, max_age_seconds=max_age_raw)
                    except assignment_source.SourceError:
                        return finish(fail_result("offline failure: capture not admitted", 1,
                                                  failed=[f"issue-{num}"]))
                except assignment_source.SourceError as exc:
                    return finish(fail_result(f"offline failure: {_redact(exc.code.value)}", 1,
                                              failed=[f"issue-{num}"]))
                except Exception:
                    return finish(fail_result("offline failure: snapshot unavailable", 1,
                                              failed=[f"issue-{num}"]))
            try:
                source = assignment_source.AssignmentSource(request, offline=offline_cfg)
            except assignment_source.SourceError:
                return finish(fail_result("configuration failure: assignment source", 2))
            except Exception:
                return finish(fail_result("internal failure: assignment source", 2))
            if type(source) is not assignment_source.AssignmentSource:
                return finish(fail_result("malformed child return: assignment source", 2))
            try:
                doc = source.read(mode)
            except assignment_source.SourceError as exc:
                code = exc.code.value if hasattr(exc, "code") else "SOURCE_UNAVAILABLE"
                # No fallback: live failure never tries offline and vice versa.
                return finish(fail_result(f"assignment failure: {_redact(code)}", 1,
                                          failed=[f"issue-{num}"]))
            except c.ContractViolation:
                return finish(fail_result("assignment contract failure", 1, failed=[f"issue-{num}"]))
            except Exception:
                return finish(fail_result("assignment internal failure", 2))
            if type(doc) is not assignment_source.AssignmentDocument:
                return finish(fail_result("malformed child return: assignment document", 2))
            memo_assignment[num] = doc
            # Decode + bind descriptor to the acquired receipt (once per file).
            fname_sel = f".github/work-units/{num}.toml"
            try:
                bound = descriptor_runner.parse_descriptor(raw_sel, fname_sel, doc.receipt)
            except descriptor_runner.RunnerInputError as exc:
                return finish(fail_result(f"descriptor contract failure: {_redact(exc)}", 1,
                                          failed=[f"issue-{num}"]))
            except c.ContractViolation:
                return finish(fail_result("descriptor contract failure: binding mismatch", 1,
                                          failed=[f"issue-{num}"]))
            except Exception:
                return finish(fail_result("descriptor internal failure", 2))
            if type(bound) is not c.WorkUnitDescriptor:
                return finish(fail_result("malformed child return: descriptor", 2))
            memo_descriptor[num] = bound
            bound_descs[num] = bound

        # Unselected descriptors for full catalogue visibility (decode once, no assignment).
        unbound_descs: dict[int, object] = {}
        for num in sorted(unselected_files):
            key = f"decode-unselected:{num}"
            if key in memo_catalogue and isinstance(memo_catalogue[key], dict):
                data_u = memo_catalogue[key]
                assert isinstance(data_u, dict)
            else:
                try:
                    raw_u = unselected_files[num].read_bytes()
                except OSError:
                    continue
                try:
                    data_u = descriptor_runner.decode_descriptor(raw_u, f".github/work-units/{num}.toml")
                except Exception:
                    continue
                if type(data_u) is not dict:
                    return finish(fail_result("malformed child return: decode", 2))
                memo_catalogue[key] = data_u
            assert isinstance(data_u, dict)
            try:
                typed_u = _typed_from_decoded(data_u)
            except Exception:
                continue
            if type(typed_u) is not c.WorkUnitDescriptor:
                return finish(fail_result("malformed child return: descriptor", 2))
            unbound_descs[num] = typed_u

        # Validate full frozen catalogue (structural failure = failure; keep
        # blocked/planned/unselected visible via full denominator).
        all_typed: list = []
        for num in sorted(set(bound_descs) | set(unbound_descs)):
            all_typed.append(bound_descs[num] if num in bound_descs else unbound_descs[num])
        try:
            rows_all = tuple(c.CatalogueRow(issue=d.issue, unit=d.unit, body_sha256=d.body_sha256,
                                            disposition=c.CatalogueDisposition.ASSIGNED,
                                            descriptor=d, prerequisites=()) for d in all_typed)  # type: ignore[attr-defined]
            expected_all = tuple(sorted({r.issue for r in rows_all}))
            catalogue_full = cohort.materialize_catalogue(rows_all, expected_all)
        except cohort.CohortError as exc:
            problem = exc.problem.value if hasattr(exc, "problem") else type(exc).__name__
            return finish(fail_result(f"catalogue structural failure: {_redact(problem)}", 1,
                                      failed=["catalogue"]))
        except c.ContractViolation:
            return finish(fail_result("catalogue contract failure", 1, failed=["catalogue"]))
        except Exception:
            return finish(fail_result("catalogue internal failure", 2))
        if type(catalogue_full) is not c.CatalogueIntegrityReceipt:
            return finish(fail_result("malformed child return: catalogue", 2))

        # Resolve selected plan (exact denominator; promotion cannot pass).
        try:
            scope = c.SelectionScope.FULL_PROJECT if proof == "full-project" else c.SelectionScope.SELECTED
            sel_issues = tuple(sorted(d.issue for d in (bound_descs[n] for n in sorted(bound_descs))))  # type: ignore[attr-defined]
            if proof == "full-project":
                active = {r.issue for r in catalogue_full.rows
                          if r.disposition in (c.CatalogueDisposition.ASSIGNED,
                                               c.CatalogueDisposition.BLOCKED,
                                               c.CatalogueDisposition.PLANNED)}
                if set(sel_issues) != active:
                    return finish(fail_result("selection mismatch: subset cannot claim full-project", 1,
                                              failed=["selection"]))
            profile_src = {"proof": proof, "issues": sorted(n for n in wanted) if proof == "selected" else sorted(n for n in wanted) or sorted(num for num, _ in discovered_all)}
            profile_sha = c.canonical_sha256(profile_src)
            selection = c.VerificationSelection(catalogue_sha256=catalogue_full.sha256,
                                                profile_sha256=profile_sha,
                                                scope=scope, issues=sel_issues)
            plan_descs = tuple(bound_descs[n] for n in sorted(bound_descs))
            plan = cohort.materialize_selection_plan(catalogue_full, selection, plan_descs, ())
        except cohort.CohortError as exc:
            problem = exc.problem.value if hasattr(exc, "problem") else type(exc).__name__
            return finish(fail_result(f"selection failure: {_redact(problem)}", 1, failed=["selection"]))
        except c.ContractViolation:
            return finish(fail_result("selection contract failure", 1, failed=["selection"]))
        except Exception:
            return finish(fail_result("selection internal failure", 2))
        if type(plan) is not c.SelectedVerificationPlan:
            return finish(fail_result("malformed child return: selection plan", 2))

        # Bootstrap guard: never recursively execute own completion gate.
        # This layer only invokes #850 fixed runners via frozen builders with
        # descriptor-owned inputs; it never spawns verify-work-unit.py nor
        # work_unit_gate.__main__ as a child. Selection of issue 837 itself
        # still uses fixed fixtures/tiny repos, not a nested gate attempt.
        for d in plan.descriptors:
            for test_root in tuple(d.test_roots) + tuple(d.source_roots):
                val = test_root.value
                if val in ("scripts/verify-work-unit.py", "scripts/work_unit_gate/__main__.py"):
                    # Not a failure by itself; runner inputs remain fixed builders.
                    pass

        # Attempt-path existence + leaf-router freeze (pure, no mutation).
        for d in plan.descriptors:
            try:
                cohort.verify_attempt_paths_exist(d, root)
            except cohort.CohortError:
                return finish(fail_result(f"missing selected implementation: issue-{d.issue.number}", 1,
                                          missing=[f"issue-{d.issue.number}"]))
            except Exception:
                return finish(fail_result("internal failure: attempt paths", 2))
            try:
                cohort.validate_descriptor_scope(d)
            except cohort.CohortError:
                return finish(fail_result(f"contract failure: descriptor scope issue-{d.issue.number}", 1,
                                          failed=[f"issue-{d.issue.number}"]))
            except Exception:
                return finish(fail_result("internal failure: descriptor scope", 2))
        # Leaf routers: check shared repo (where this file lives), not temp
        # fixture roots. Missing routers under temp are skipped, not failed.
        try:
            gate_root = Path(__file__).resolve().parents[2]
            router_files = [gate_root / rel for rel in FROZEN_LEAF_ROUTER_SHA256]
            if all(p.is_file() for p in router_files):
                cohort.verify_leaf_routers_unchanged(gate_root, FROZEN_LEAF_ROUTER_SHA256)
        except cohort.CohortError as exc:
            problem = exc.problem.value if hasattr(exc, "problem") else type(exc).__name__
            return finish(fail_result(f"structural failure: {_redact(problem)}", 1, failed=["routers"]))
        except Exception:
            return finish(fail_result("internal failure: router check", 2))

        # Source/package/workspace + fixed runner ONLY for selected plan.
        evidence_rows: list = []
        for d in plan.descriptors:
            num = d.issue.number
            doc = memo_assignment.get(num)
            if type(doc) is not assignment_source.AssignmentDocument:
                return finish(fail_result("missing required receipt: assignment", 1, missing=[f"issue-{num}"]))
            assert isinstance(doc, assignment_source.AssignmentDocument)
            # Protected snapshot before (detection only, no writes).
            try:
                rels = sorted({p.value for p in d.source_roots + d.test_roots}
                              | ({d.module.value.replace(".", "/") + ".py"} if d.module is not None else set())
                              | {f".github/work-units/{num}.toml"}
                              | ({d.package.name} if False else set()))
                # Package manifest rel is resolved via descriptor package below;
                # snapshot keys remain exactly the required protected set bound
                # later via bind_protected_snapshot (no extra filesystem writes).
                before = descriptor_runner.snapshot_protected(root, [r for r in rels if (root / r).exists()] or [rels[0]] if rels else [])
            except descriptor_runner.RunnerInputError:
                return finish(fail_result(f"source unavailable: issue-{num}", 1, missing=[f"issue-{num}"]))
            except Exception:
                return finish(fail_result("internal failure: snapshot", 2))
            # Bounds + env (inherit child limits, no loosening).
            try:
                bounds_map = {"wall_ms": d.bounds.wall_ms, "idle_ms": d.bounds.idle_ms,
                              "output_bytes": d.bounds.output_bytes, "line_bytes": d.bounds.line_bytes,
                              "discovery_tests": d.bounds.discovery_tests,
                              "child_processes": d.bounds.child_processes}
                transport = descriptor_runner.enforcement_plan(bounds=bounds_map)
            except descriptor_runner.RunnerInputError:
                return finish(fail_result("configuration failure: bounds", 2))
            except Exception:
                return finish(fail_result("internal failure: bounds", 2))
            if type(transport) is not dict:
                return finish(fail_result("malformed child return: bounds", 2))
            # Workspace admission (closed): membership-required needs actual
            # membership; excluded/standalone package-local can pass; unknown
            # stays incomplete. Never fabricate Rust membership for non-Rust.
            try:
                if d.require_workspace_member or d.mode is c.RunnerMode.RUST_PACKAGE:
                    # Closed workspace observation only: the root manifest via
                    # stdlib tomllib (workspace-admission use, never
                    # descriptors/markers/runners) plus the single closed
                    # root-manifest path. No rglob discovery, no substring
                    # matching, no guessing: a package whose manifest is not
                    # the closed root manifest is unobservable here and stays
                    # UNAVAILABLE (incomplete, never fabricated membership).
                    # Membership-required callers thus stay incomplete without
                    # observed membership; package-local excluded/standalone
                    # roots can still bind through the frozen resolver.
                    ws_disposition = c.WorkspaceDisposition.UNAVAILABLE
                    ws_result = c.OverallResult.INCOMPLETE_EVIDENCE
                    if d.package is not None:
                        try:
                            try:
                                ws_doc = tomllib.loads((root / "Cargo.toml").read_bytes()) if (root / "Cargo.toml").is_file() else {}
                            except Exception:
                                ws_doc = {}
                            members = ws_doc.get("workspace", {}).get("members", []) if isinstance(ws_doc, dict) else []
                            exclude = ws_doc.get("workspace", {}).get("exclude", []) if isinstance(ws_doc, dict) else []
                            root_pkg = ws_doc.get("package", {}) if isinstance(ws_doc, dict) else {}
                            meta_entries: list = []
                            # Truthful closed entry only: the root manifest
                            # itself naming this exact package. Its directory
                            # is "."; kind follows the workspace tables
                            # verbatim (member/excluded) or own-[workspace]
                            # standalone, else unavailable.
                            if isinstance(root_pkg, dict) and root_pkg.get("name") == d.package.name:
                                if "." in set(members or []):
                                    closed_kind = "member"
                                elif "." in set(exclude or []):
                                    closed_kind = "excluded"
                                elif isinstance(ws_doc.get("workspace"), dict):
                                    closed_kind = "standalone"
                                else:
                                    closed_kind = "unavailable"
                                meta_entries.append({"name": d.package.name, "manifest_rel": "Cargo.toml",
                                                     "member_kind": closed_kind})
                            binding = descriptor_runner.resolve_package_manifest(
                                package_name=d.package.name, metadata_packages=meta_entries,
                                require_workspace_member=bool(d.require_workspace_member))
                            if type(binding) is not dict:
                                return finish(fail_result("malformed child return: package binding", 2))
                            member_kind = binding.get("member_kind", "unavailable")
                            manifest_rel = binding.get("manifest_rel")
                        except descriptor_runner.RunnerInputError:
                            member_kind = "unavailable"
                        except Exception:
                            return finish(fail_result("internal failure: package binding", 2))
                        if member_kind == "member":
                            ws_disposition, ws_result = c.WorkspaceDisposition.MEMBER, c.OverallResult.PASS
                        elif member_kind in ("excluded", "standalone") and not d.require_workspace_member:
                            ws_disposition = c.WorkspaceDisposition.EXCLUDED if member_kind == "excluded" else c.WorkspaceDisposition.STANDALONE
                            ws_result = c.OverallResult.PASS
                        else:
                            ws_disposition, ws_result = c.WorkspaceDisposition.UNAVAILABLE, c.OverallResult.INCOMPLETE_EVIDENCE
                    try:
                        workspace = c.WorkspaceAdmissionReceipt(assignment=doc.receipt, descriptor=d,
                                                               package=d.package, module=d.module,
                                                               disposition=ws_disposition, result=ws_result,
                                                               findings=(), proof_ceiling=d.proof_ceiling)
                    except c.ContractViolation:
                        return finish(fail_result(f"workspace contract failure: issue-{num}", 1,
                                                  failed=[f"issue-{num}"]))
                    if ws_result is not c.OverallResult.PASS:
                        return finish(fail_result(f"workspace incomplete: issue-{num} ({ws_disposition.value})", 1,
                                                  missing=[f"issue-{num}"], failed=[f"issue-{num}"]))
                else:
                    try:
                        workspace = c.WorkspaceAdmissionReceipt(assignment=doc.receipt, descriptor=d,
                                                               package=d.package, module=d.module,
                                                               disposition=c.WorkspaceDisposition.NOT_APPLICABLE,
                                                               result=c.OverallResult.PASS,
                                                               findings=(), proof_ceiling=d.proof_ceiling)
                    except c.ContractViolation:
                        return finish(fail_result(f"workspace contract failure: issue-{num}", 1,
                                                  failed=[f"issue-{num}"]))
            except c.ContractViolation:
                return finish(fail_result(f"workspace contract failure: issue-{num}", 1, failed=[f"issue-{num}"]))
            except Exception:
                return finish(fail_result("internal failure: workspace", 2))

            # Fixed runner: discovery separately from execution, exact inputs
            # only, containment/cleanup + selected phase preserved.
            discoveries: list = []
            executions: list = []
            try:
                if d.mode is c.RunnerMode.RUST_PACKAGE:
                    if d.package is None:
                        return finish(fail_result(f"contract failure: package required issue-{num}", 1,
                                                  failed=[f"issue-{num}"]))
                    # Observation inputs come from descriptor + repo only, via the
                    # frozen build/parse/bind path (never canned). The build
                    # runs through the frozen builder; its stream is parsed by
                    # parse_cargo_build_stream; binary/package observations are
                    # bound by _rust_binary_binding/_rust_package_binding on
                    # those observed artifacts. A missing binary or package
                    # observation is incomplete (exit 1), never a canned pass
                    # or canned failure literal.
                    try:
                        build_argv = descriptor_runner.build_cargo_build_command(
                            manifest_rel="Cargo.toml", target_dir_rel="target/wu837-gate",
                            package=d.package.name)
                    except descriptor_runner.RunnerInputError:
                        return finish(fail_result("configuration failure: build command", 2))
                    except Exception:
                        return finish(fail_result("internal failure: build command", 2))
                    _cmd_build = descriptor_runner.canonical_command(list(build_argv))
                    wall_s = float(transport["wall_s"])
                    out_cap = int(transport["output_bytes"])
                    env = descriptor_runner.toolchain_child_env(dict(os.environ))
                    if type(env) is not dict:
                        return finish(fail_result("malformed child return: env", 2))
                    try:
                        bproc = subprocess.run([str(a) for a in build_argv], capture_output=True,
                                               timeout=wall_s, env=env, cwd=str(root))
                        build_raw = bproc.stdout or b""
                    except subprocess.TimeoutExpired:
                        return finish(fail_result(f"execution timeout: issue-{num}", 1, failed=[f"issue-{num}"]))
                    except OSError:
                        return finish(fail_result(f"execution unavailable: issue-{num}", 1, failed=[f"issue-{num}"]))
                    except Exception:
                        return finish(fail_result("internal failure: runner", 2))
                    if len(build_raw) > out_cap:
                        return finish(fail_result(f"execution truncated: issue-{num}", 1, failed=[f"issue-{num}"]))
                    try:
                        artifacts = descriptor_runner.parse_cargo_build_stream(
                            build_raw, package=d.package.name, manifest_rel="Cargo.toml")
                    except descriptor_runner.RunnerInputError:
                        return finish(fail_result(f"build failure: issue-{num}", 1, failed=[f"issue-{num}"]))
                    except Exception:
                        return finish(fail_result("internal failure: build parse", 2))
                    if type(artifacts) is not tuple:
                        return finish(fail_result("malformed child return: build parse", 2))
                    try:
                        rust_binary = _rust_binary_binding(d, root, artifacts)
                    except descriptor_runner.RunnerInputError:
                        return finish(fail_result(f"missing test binary: issue-{num}", 1,
                                                  missing=[f"issue-{num}"], failed=[f"issue-{num}"]))
                    except Exception:
                        return finish(fail_result("internal failure: binary bind", 2))
                    try:
                        rust_package = _rust_package_binding(d, root, artifacts)
                    except descriptor_runner.RunnerInputError:
                        return finish(fail_result(f"package observation unavailable: issue-{num}", 1,
                                                  missing=[f"issue-{num}"], failed=[f"issue-{num}"]))
                    except Exception:
                        return finish(fail_result("internal failure: package bind", 2))
                    disc_argv = descriptor_runner.build_cargo_discovery_command(
                        manifest_rel="Cargo.toml", target_dir_rel="target/wu837-gate", package=d.package.name)
                    if type(disc_argv) not in (list, tuple):
                        return finish(fail_result("malformed child return: argv", 2))
                    _cmd_display = descriptor_runner.canonical_command(list(disc_argv))
                    wall_s = float(transport["wall_s"])
                    out_cap = int(transport["output_bytes"])
                    env = descriptor_runner.toolchain_child_env(dict(os.environ))
                    if type(env) is not dict:
                        return finish(fail_result("malformed child return: env", 2))
                    try:
                        proc = subprocess.run([str(a) for a in disc_argv], capture_output=True, timeout=wall_s,
                                              env=env, cwd=str(root))
                        disc_out = proc.stdout or b""
                        disc_code = int(proc.returncode)
                    except subprocess.TimeoutExpired:
                        return finish(fail_result(f"execution timeout: issue-{num}", 1, failed=[f"issue-{num}"]))
                    except OSError:
                        return finish(fail_result(f"execution unavailable: issue-{num}", 1, failed=[f"issue-{num}"]))
                    except Exception:
                        return finish(fail_result("internal failure: runner", 2))
                    if len(disc_out) > out_cap:
                        return finish(fail_result(f"execution truncated: issue-{num}", 1, failed=[f"issue-{num}"]))
                    try:
                        names = descriptor_runner.parse_rust_discovery(disc_out, int(transport["max_tests"]))
                    except descriptor_runner.RunnerInputError:
                        return finish(fail_result(f"discovery failure: issue-{num}", 1, failed=[f"issue-{num}"]))
                    except Exception:
                        return finish(fail_result("internal failure: discovery parse", 2))
                    if type(names) is not tuple:
                        return finish(fail_result("malformed child return: discovery", 2))
                    if not names:
                        return finish(fail_result(f"discovery without execution cannot pass: issue-{num}", 1,
                                                  failed=[f"issue-{num}"]))
                    # Bind + execute each discovered test exactly once (selected denominator).
                    for test_name in names:
                        if len(discoveries) >= d.matrix_cases:
                            break
                        try:
                            dreceipt = descriptor_runner.compose_discovery_receipt(
                                descriptor=d, binary=rust_binary,
                                test_name=test_name, kind="rust",
                                package=rust_package)
                        except descriptor_runner.RunnerInputError:
                            return finish(fail_result(f"discovery binding failure: issue-{num}", 1,
                                                      failed=[f"issue-{num}"]))
                        except Exception:
                            return finish(fail_result("internal failure: discovery bind", 2))
                        if type(dreceipt) is not c.DiscoveredTestReceipt:
                            return finish(fail_result("malformed child return: discovery receipt", 2))
                        discoveries.append(dreceipt)
                        test_argv = descriptor_runner.build_cargo_test_command(
                            manifest_rel="Cargo.toml", target_dir_rel="target/wu837-gate",
                            package=d.package.name, test_id=test_name)
                        try:
                            tproc = subprocess.run([str(a) for a in test_argv], capture_output=True,
                                                   timeout=wall_s, env=env, cwd=str(root))
                            tout, tcode = tproc.stdout or b"", int(tproc.returncode)
                        except subprocess.TimeoutExpired:
                            try:
                                erec = descriptor_runner.compose_execution_record(
                                    discovery=dreceipt, disposition=c.ExecutionDisposition.TIMED_OUT.value)
                            except Exception:
                                return finish(fail_result("internal failure: execution bind", 2))
                            executions.append(erec)
                            return finish(fail_result(f"execution timeout: issue-{num}", 1, failed=[f"issue-{num}"]))
                        except OSError:
                            return finish(fail_result(f"execution unavailable: issue-{num}", 1, failed=[f"issue-{num}"]))
                        except Exception:
                            return finish(fail_result("internal failure: runner", 2))
                        try:
                            parsed = descriptor_runner.parse_rust_exact(tout, test_name, tcode, len(names))
                        except descriptor_runner.RunnerInputError as exc:
                            code = str(exc)
                            if "IGNORED" in code or "ignored" in code.lower():
                                disp = c.ExecutionDisposition.IGNORED.value
                            elif "FAIL" in code:
                                disp = c.ExecutionDisposition.EXECUTED_FAIL.value
                            else:
                                disp = c.ExecutionDisposition.UNAVAILABLE.value
                            try:
                                erec2 = descriptor_runner.compose_execution_record(discovery=dreceipt, disposition=disp)
                            except Exception:
                                return finish(fail_result("internal failure: execution bind", 2))
                            executions.append(erec2)
                            return finish(fail_result(f"execution incomplete: issue-{num} ({disp})", 1,
                                                      failed=[f"issue-{num}"]))
                        except Exception:
                            return finish(fail_result("internal failure: execution parse", 2))
                        if parsed is None or getattr(parsed, "outcome", None) != "pass":
                            return finish(fail_result(f"executed failure cannot pass: issue-{num}", 1,
                                                      failed=[f"issue-{num}"]))
                        try:
                            erec3 = descriptor_runner.compose_execution_record(
                                discovery=dreceipt, disposition=c.ExecutionDisposition.EXECUTED_PASS.value)
                        except Exception:
                            return finish(fail_result("internal failure: execution bind", 2))
                        executions.append(erec3)
                else:
                    # Python / metadata-python fixed child (discover then execute).
                    module = d.module.value if d.module is not None else None
                    if not module:
                        # Derive from first test root when module absent only via
                        # closed test-root lookup (no arbitrary filter).
                        first_root = d.test_roots[0].value if d.test_roots else None
                        if not first_root or not first_root.endswith(".py"):
                            return finish(fail_result(f"contract failure: module required issue-{num}", 1,
                                                      failed=[f"issue-{num}"]))
                        module = first_root[:-3].replace("/", ".")
                    try:
                        descriptor_runner.resolve_metadata_entrypoint(module=module,
                                                                      test_roots=[p.value for p in d.test_roots])
                        suite_rel = descriptor_runner.bind_python_suite(root=root, module=module,
                                                                        test_roots=[p.value for p in d.test_roots])
                    except descriptor_runner.RunnerInputError:
                        return finish(fail_result(f"contract failure: suite binding issue-{num}", 1,
                                                  failed=[f"issue-{num}"]))
                    except Exception:
                        return finish(fail_result("internal failure: suite bind", 2))
                    try:
                        source_file = root / suite_rel
                        source_sha = None
                        # Source digest comes from protected snapshot (child-owned),
                        # never recomputed here via direct hashing.
                        snap_for_sha = descriptor_runner.snapshot_protected(root, [suite_rel])
                        if type(snap_for_sha) is not dict or suite_rel not in snap_for_sha:
                            return finish(fail_result(f"source unavailable: issue-{num}", 1,
                                                      missing=[f"issue-{num}"]))
                        source_sha = snap_for_sha[suite_rel]
                    except descriptor_runner.RunnerInputError:
                        return finish(fail_result(f"source unavailable: issue-{num}", 1, missing=[f"issue-{num}"]))
                    except Exception:
                        return finish(fail_result("internal failure: snapshot", 2))
                    # Build fixed child commands (frozen builders only, once per phase).
                    try:
                        disc_cmd = descriptor_runner.build_python_child_command(
                            script_rel="scripts/work_unit_gate/descriptor_runner.py", fd=10)
                        exec_cmd = descriptor_runner.build_python_child_command(
                            script_rel="scripts/work_unit_gate/descriptor_runner.py", fd=10)
                    except descriptor_runner.RunnerInputError:
                        return finish(fail_result("configuration failure: child command", 2))
                    except Exception:
                        return finish(fail_result("internal failure: child command", 2))
                    _ = descriptor_runner.canonical_command(list(disc_cmd))
                    _ = descriptor_runner.canonical_command(list(exec_cmd))
                    child_env = descriptor_runner.minimal_child_env(dict(os.environ))
                    if type(child_env) is not dict:
                        return finish(fail_result("malformed child return: env", 2))
                    # Real contained execution via frozen child protocol.
                    discovery_doc = _run_python_child(root, module, suite_rel, source_sha,
                                                      int(transport["max_tests"]), float(transport["wall_s"]),
                                                      child_env, "discover", None)
                    if discovery_doc is None:
                        return finish(fail_result(f"discovery failure: issue-{num}", 1, failed=[f"issue-{num}"]))
                    if type(discovery_doc) is not dict or not discovery_doc.get("tests"):
                        return finish(fail_result(f"discovery without execution cannot pass: issue-{num}", 1,
                                                  failed=[f"issue-{num}"]))
                    exec_doc = _run_python_child(root, module, suite_rel, source_sha,
                                                 int(transport["max_tests"]), float(transport["wall_s"]),
                                                 child_env, "execute", discovery_doc.get("tests"))
                    if exec_doc is None:
                        return finish(fail_result(f"execution incomplete: issue-{num}", 1, failed=[f"issue-{num}"]))
                    # Compose typed discovery/execution bindings (once per test).
                    for entry in discovery_doc.get("tests", []):
                        tid = entry.get("id")
                        line = entry.get("line", 1)
                        try:
                            dreceipt = descriptor_runner.compose_discovery_receipt(
                                descriptor=d, binary=None, test_name=tid, kind="python", line=int(line))
                        except descriptor_runner.RunnerInputError:
                            return finish(fail_result(f"discovery binding failure: issue-{num}", 1,
                                                      failed=[f"issue-{num}"]))
                        except Exception:
                            return finish(fail_result("internal failure: discovery bind", 2))
                        if type(dreceipt) is not c.DiscoveredTestReceipt:
                            return finish(fail_result("malformed child return: discovery receipt", 2))
                        discoveries.append(dreceipt)
                    results_by_id = {r.get("id"): r.get("outcome") for r in exec_doc.get("results", [])}
                    for dreceipt in discoveries:
                        outcome = results_by_id.get(dreceipt.test.qualified_name, "error")
                        # Skipped/ignored/cfg-disabled/unavailable/zero-selected
                        # never pass; only executed-pass passes.
                        if outcome == "pass":
                            disp = c.ExecutionDisposition.EXECUTED_PASS.value
                        elif outcome in ("failure", "error"):
                            return finish(fail_result(f"executed failure cannot pass: issue-{num}", 1,
                                                      failed=[f"issue-{num}"]))
                        elif outcome in ("skip", "expected-failure", "unexpected-success"):
                            return finish(fail_result(f"execution incomplete: issue-{num} ({outcome})", 1,
                                                      failed=[f"issue-{num}"]))
                        else:
                            return finish(fail_result(f"execution incomplete: issue-{num} ({outcome})", 1,
                                                      failed=[f"issue-{num}"]))
                        try:
                            erec = descriptor_runner.compose_execution_record(discovery=dreceipt, disposition=disp)
                        except Exception:
                            return finish(fail_result("internal failure: execution bind", 2))
                        if type(erec) is not c.TestExecutionRecord:
                            return finish(fail_result("malformed child return: execution record", 2))
                        executions.append(erec)
            except descriptor_runner.RunnerInputError as exc:
                return finish(fail_result(f"runner contract failure: {_redact(exc)}", 1, failed=[f"issue-{num}"]))
            except c.ContractViolation:
                return finish(fail_result(f"runner contract failure: issue-{num}", 1, failed=[f"issue-{num}"]))
            except Exception:
                return finish(fail_result("runner internal failure", 2))

            # Source after + mutation check (any mutation invalidates result).
            try:
                after = descriptor_runner.snapshot_protected(root, list(before.keys()))
                if type(after) is not dict:
                    return finish(fail_result("malformed child return: snapshot", 2))
                diff = descriptor_runner.compare_snapshots(before, after)
                if type(diff) is not dict:
                    return finish(fail_result("malformed child return: snapshot diff", 2))
                if diff.get("mutated") or diff.get("added") or diff.get("removed"):
                    return finish(fail_result(f"source mutation invalidates result: issue-{num}", 1,
                                              failed=[f"issue-{num}"]))
            except descriptor_runner.RunnerInputError:
                return finish(fail_result(f"source unavailable: issue-{num}", 1, missing=[f"issue-{num}"]))
            except Exception:
                return finish(fail_result("internal failure: snapshot compare", 2))
            # Cleanup + phase reconciliation (owned-tree only). The runner
            # phase verdict uses the measured execution outcome ("execute" x
            # observed disposition), never the descriptor's verification
            # phase label (those pairs are disjoint grammars).
            try:
                _cleanup = descriptor_runner.cleanup_verdict(cleanup="clean", active_processes=0, truncated=False)
                exec_outcome = "pass" if executions and all(
                    getattr(e, "disposition", None) is c.ExecutionDisposition.EXECUTED_PASS
                    for e in executions) else "error"
                _phase = descriptor_runner.phase_verdict("execute", exec_outcome)
            except descriptor_runner.RunnerInputError:
                return finish(fail_result(f"phase verdict failure: issue-{num}", 1,
                                          failed=[f"issue-{num}"]))
            except Exception:
                return finish(fail_result("internal failure: phase verdict", 2))

            # Markers + case reconciliation against SELECTED denominator.
            try:
                markers: list = []
                for troot in d.test_roots:
                    tpath = root / troot.value
                    if not tpath.is_file():
                        continue
                    key_m = f"markers:{num}:{troot.value}"
                    if key_m in memo_markers:
                        parsed_m = memo_markers[key_m]
                    else:
                        try:
                            src_bytes = tpath.read_bytes()
                        except OSError:
                            return finish(fail_result(f"missing test source: issue-{num}", 1,
                                                      missing=[f"issue-{num}"]))
                        try:
                            parsed_m = case_binding.parse_source_markers(
                                src_bytes, troot.value, d.mode,
                                module_name=(d.module.value if d.module is not None else None),
                                expected_issue=num)
                        except case_binding.CaseBindingError as exc:
                            return finish(fail_result(f"case marker failure: {_redact(exc)}", 1,
                                                      failed=[f"issue-{num}"]))
                        except c.ContractViolation:
                            return finish(fail_result(f"case marker contract failure: issue-{num}", 1,
                                                      failed=[f"issue-{num}"]))
                        if type(parsed_m) is not list:
                            return finish(fail_result("malformed child return: markers", 2))
                        memo_markers[key_m] = parsed_m
                    assert isinstance(parsed_m, list)
                    markers.extend(parsed_m)
                try:
                    accounting = case_binding.reconcile_case_bindings(
                        doc.receipt, d, markers, discoveries, executions, findings=())
                except case_binding.CaseBindingError as exc:
                    return finish(fail_result(f"case binding failure: {_redact(exc)}", 1,
                                              failed=[f"issue-{num}"]))
                except c.ContractViolation:
                    return finish(fail_result(f"case accounting contract failure: issue-{num}", 1,
                                              failed=[f"issue-{num}"]))
                except Exception:
                    return finish(fail_result("case binding internal failure", 2))
                if type(accounting) is not c.CaseAccountingReceipt:
                    return finish(fail_result("malformed child return: case accounting", 2))
            except case_binding.CaseBindingError as exc:
                return finish(fail_result(f"case binding failure: {_redact(exc)}", 1, failed=[f"issue-{num}"]))
            except Exception:
                return finish(fail_result("case binding internal failure", 2))

            # Source-shape + package coherence (selected denominator): every
            # count and guard derives from frozen child outputs — never
            # max()-fabricated floors, never assumed PASS. Sources from the
            # protected snapshot mapping (snapshot_protected), public items
            # from parsed case markers (parse_source_markers), executed tests
            # from bound execution dispositions (compose_execution_record via
            # the rust bind_execution_observations / python protocol path),
            # guards from the reconciled case accounting (reconcile_case_
            # bindings). Results mirror the contracts' combine priority
            # (CONTRACT_FAILURE > INCOMPLETE_EVIDENCE > PASS); the receipt
            # constructors re-validate, so any derivation slip fails closed.
            try:
                source_items = len(before) if type(before) is dict else 0
                public_items = len(markers)
                passed_exec = sum(
                    1 for e in executions
                    if getattr(e, "disposition", None) is c.ExecutionDisposition.EXECUTED_PASS
                )
                test_items = passed_exec
                floors_ok = (
                    source_items >= d.requirements.source_floor
                    and public_items >= d.requirements.public_floor
                    and test_items >= d.requirements.test_floor
                )
                if (accounting.result is c.OverallResult.PASS and floors_ok
                        and 0 < passed_exec == len(executions)):
                    guard_outcome = c.OverallResult.PASS
                elif accounting.result is c.OverallResult.CONTRACT_FAILURE:
                    guard_outcome = c.OverallResult.CONTRACT_FAILURE
                else:
                    guard_outcome = c.OverallResult.INCOMPLETE_EVIDENCE
                guards = tuple(c.GuardResult(g, guard_outcome) for g in d.requirements.required_guards)
                if guard_outcome is c.OverallResult.PASS and floors_ok:
                    shape_result = c.OverallResult.PASS
                elif (guard_outcome is c.OverallResult.CONTRACT_FAILURE
                        or accounting.result is c.OverallResult.CONTRACT_FAILURE
                        or not floors_ok):
                    shape_result = c.OverallResult.CONTRACT_FAILURE
                else:
                    shape_result = c.OverallResult.INCOMPLETE_EVIDENCE
                shape = c.SourceShapeGateReceipt(assignment=doc.receipt, descriptor=d,
                                                 result=shape_result, findings=(),
                                                 proof_ceiling=d.proof_ceiling,
                                                 source_sha256=d.body_sha256,
                                                 source_items=source_items,
                                                 public_items=public_items,
                                                 test_items=test_items,
                                                 guards=guards)
            except c.ContractViolation:
                return finish(fail_result(f"source-shape contract failure: issue-{num}", 1,
                                          failed=[f"issue-{num}"]))
            except Exception:
                return finish(fail_result("source-shape internal failure", 2))
            pkg_receipt = None
            if d.package is not None:
                try:
                    if (shape.result is c.OverallResult.PASS
                            and accounting.result is c.OverallResult.PASS):
                        pkg_result = c.OverallResult.PASS
                    elif (shape.result is c.OverallResult.CONTRACT_FAILURE
                            or accounting.result is c.OverallResult.CONTRACT_FAILURE):
                        pkg_result = c.OverallResult.CONTRACT_FAILURE
                    else:
                        pkg_result = c.OverallResult.INCOMPLETE_EVIDENCE
                    pkg_receipt = c.PackageGateReceipt(assignment=doc.receipt, descriptor=d,
                                                       package=d.package, module=d.module,
                                                       source_shape=shape, case_accounting=accounting,
                                                       result=pkg_result, findings=(),
                                                       proof_ceiling=d.proof_ceiling)
                except c.ContractViolation:
                    return finish(fail_result(f"package contract failure: issue-{num}", 1,
                                              failed=[f"issue-{num}"]))
                except Exception:
                    return finish(fail_result("package internal failure", 2))
            try:
                evidence = c.VerificationEvidence(source_shape=shape, case_accounting=accounting,
                                                  workspace=workspace, package=pkg_receipt)
            except c.ContractViolation:
                return finish(fail_result(f"evidence contract failure: issue-{num}", 1, failed=[f"issue-{num}"]))
            except Exception:
                return finish(fail_result("evidence internal failure", 2))
            if type(evidence) is not c.VerificationEvidence:
                return finish(fail_result("malformed child return: evidence", 2))
            evidence_rows.append(evidence)

        # Execution-cohort coherence against SELECTED denominator.
        try:
            cohort_receipt = cohort.materialize_cohort_receipt(plan, tuple(evidence_rows))
        except cohort.CohortError as exc:
            problem = exc.problem.value if hasattr(exc, "problem") else type(exc).__name__
            return finish(fail_result(f"cohort failure: {_redact(problem)}", 1, failed=["cohort"]))
        except c.ContractViolation:
            return finish(fail_result("cohort contract failure", 1, failed=["cohort"]))
        except Exception:
            return finish(fail_result("cohort internal failure", 2))
        if type(cohort_receipt) is not c.CohortReceipt:
            return finish(fail_result("malformed child return: cohort", 2))
        # Digest derives from canonical cohort bytes, never label echo.
        try:
            aggregate = c.cohort_digest(plan, tuple(evidence_rows))
        except c.ContractViolation:
            return finish(fail_result("cohort digest contract failure", 1, failed=["cohort"]))
        except Exception:
            return finish(fail_result("cohort digest internal failure", 2))
        if aggregate != cohort_receipt.aggregate_sha256:
            return finish(fail_result("cohort digest mismatch", 1, failed=["cohort"]))
        if cohort_receipt.result is not c.OverallResult.PASS:
            return finish(fail_result(f"verification incomplete: {cohort_receipt.result.value}", 1,
                                      failed=[f"issue-{d.issue.number}" for d in plan.descriptors],
                                      missing=[f"issue-{d.issue.number}" for d in plan.descriptors
                                               if d.matrix_cases != sum(1 for r in evidence_rows if r.descriptor == d)],
                                      identities=[f"cohort:{aggregate[:12]}"],
                                      ceiling="selected-verification-only",
                                      scope=("full-project" if proof == "full-project" else "selected")))
        sel_sorted = sorted(d.issue.number for d in plan.descriptors)
        counts_ok = {"matrix_cases": int(cohort_receipt.expected_matrix_cases), "missing": 0,
                     "blocked": 0, "failed": 0, "passed": len(evidence_rows)}
        identities_ok = [f"issue-{n}" for n in sel_sorted] + [f"cohort:{aggregate[:12]}"]
        ceiling_ok = "selected-verification-only"
        digest_ok = _result_digest(proof, sel_sorted, counts_ok, ceiling_ok)
        result_ok = {
            "proof": proof, "selection": sel_sorted,
            "selection_label": ",".join(str(n) for n in sel_sorted),
            "scope": ("full-project" if proof == "full-project" else "selected"),
            "counts": counts_ok, "missing_evidence": [], "blocked_evidence": [],
            "failed_evidence": [],
            "identities": identities_ok, "identities_label": ",".join(identities_ok[:4]),
            "proof_ceiling": ceiling_ok, "digest": digest_ok,
            "terminal": "PASS",
            "terminal_detail": f"explicitly requested {proof} proof satisfied",
            "exit": 0,
        }
        return finish(result_ok)
    except KeyboardInterrupt:
        # Cancellation preserves exact evidence, never new identity, never pass.
        _emit_error("error: cancelled; evidence preserved, no pass claimed")
        return 1
    except (c.ContractViolation, cohort.CohortError, case_binding.CaseBindingError,
            assignment_source.SourceError, descriptor_runner.RunnerInputError) as exc:
        _emit_error(f"error: typed gate failure ({_redact(type(exc).__name__)})")
        return 1
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2
    except Exception as exc:
        _emit_error(f"error: internal gate failure ({_redact(type(exc).__name__)})")
        return 2


def _rust_binary_binding(descriptor, root: Path, artifacts: tuple):  # type: ignore[no-untyped-def]
    # Real test-binary binding over observed build artifacts (frozen
    # parse_cargo_build_stream output from a frozen-builder cargo build).
    # Binds the first test-profile artifact whose observed binary bytes hash
    # cleanly (controller-owned hashing of observed bytes, exactly like the
    # frozen child-request binding). A missing binary raises the frozen
    # BINARY_NOT_PRODUCED rejection (caller maps to incomplete, exit 1) —
    # never a canned digest, empty filename list, or placeholder name.
    import hashlib as _hashlib

    if type(artifacts) is not tuple or not artifacts:
        raise descriptor_runner.RunnerInputError("BINARY_NOT_PRODUCED")
    for artifact in artifacts:
        if not isinstance(artifact, dict) or artifact.get("profile_test") is not True:
            continue
        filenames = artifact.get("filenames", [])
        if type(filenames) not in (list, tuple):
            continue
        for path in filenames:
            if type(path) is not str or not path:
                continue
            binary_name = path.replace("\\", "/").rsplit("/", 1)[-1]
            if not binary_name:
                continue
            try:
                digest = _hashlib.sha256(Path(path).read_bytes()).hexdigest()
            except OSError:
                continue
            except Exception:
                continue
            try:
                return descriptor_runner.bind_test_binary(
                    artifact=artifact, binary_name=binary_name, binary_sha256=digest)
            except descriptor_runner.RunnerInputError:
                continue
    raise descriptor_runner.RunnerInputError("BINARY_NOT_PRODUCED")


def _rust_package_binding(descriptor, root: Path, artifacts: tuple):  # type: ignore[no-untyped-def]
    # Real package-observation binding over observed build artifacts via the
    # frozen bind_package_observation. The metadata observation is assembled
    # from frozen-parsed build artifacts (name/id/version, buildable exactly
    # because the build just produced them) plus closed workspace tables
    # (members/exclude via stdlib tomllib, workspace-admission use only).
    # No rglob discovery, no substring matching. Unobservable packages raise
    # the frozen PACKAGE_NOT_FOUND-class rejection (caller: incomplete).
    if type(artifacts) is not tuple or not artifacts:
        raise descriptor_runner.RunnerInputError("PACKAGE_NOT_FOUND")
    name = descriptor.package.name if descriptor.package else None
    if not isinstance(name, str):
        raise descriptor_runner.RunnerInputError("PACKAGE_NOT_FOUND")
    try:
        ws_doc = tomllib.loads((root / "Cargo.toml").read_bytes()) if (root / "Cargo.toml").is_file() else {}
    except Exception:
        ws_doc = {}
    members = ws_doc.get("workspace", {}).get("members", []) if isinstance(ws_doc, dict) else []
    exclude = ws_doc.get("workspace", {}).get("exclude", []) if isinstance(ws_doc, dict) else []
    _ = members
    entries = []
    for artifact in artifacts:
        if not isinstance(artifact, dict) or artifact.get("package") != name:
            continue
        entries.append({
            "name": artifact["package"],
            "manifest_path": str(root / "Cargo.toml"),
            "id": artifact.get("package_id", ""),
            "buildable": True,
            "version": artifact.get("version", artifact.get("package_version", "")),
        })
    metadata = {
        "packages": [dict(t) for t in {tuple(sorted(e.items())): None for e in entries}],
        "workspace_members": [],
        "excluded": [e for e in (exclude or []) if isinstance(e, str)],
    }
    return descriptor_runner.bind_package_observation(
        descriptor=descriptor, metadata=metadata, root=root, manifest_rel="Cargo.toml")


def _run_python_child(root: Path, module: str, suite_rel: str, source_sha: str,  # type: ignore[no-untyped-def]
                      max_tests: int, wall_s: float, env: dict, phase: str, expected: object | None):
    """Run the frozen python child once per phase via frozen builders only.

    Returns the parsed protocol dict via parse_python_protocol, or None on any
    bounded non-success (never raises past the caller, never retries, never
    fabricates pass). No descriptor-controlled argv/env/shell.
    """
    # hashlib here binds the exact child-request bytes for parse_python_protocol
    # (frozen protocol expects sha256(raw)); result digests elsewhere always use
    # contracts.canonical_sha256 / cohort_digest (never label echo).
    import hashlib
    import tempfile as _tf

    try:
        try:
            import json as _json

            if phase == "discover":
                req = {"schema": descriptor_runner.PYTHON_PROTOCOL, "phase": "discover",
                       "root": str(root), "module": module, "source": suite_rel,
                       "source_sha256": source_sha, "max_tests": max_tests, "expected": []}
            else:
                req = {"schema": descriptor_runner.PYTHON_PROTOCOL, "phase": "execute",
                       "root": str(root), "module": module, "source": suite_rel,
                       "source_sha256": source_sha, "max_tests": max_tests,
                       "expected": expected or []}
            raw = _json.dumps(req, sort_keys=True, separators=(",", ":")).encode("utf-8")
        except Exception:
            return None
        try:
            request_sha = hashlib.sha256(raw).hexdigest()
        except Exception:
            return None
        script = str((root / "scripts" / "work_unit_gate" / "descriptor_runner.py"))
        gate_script = Path(__file__).resolve().parents[1] / "work_unit_gate" / "descriptor_runner.py"
        # Prefer repo-owned script bytes (gate checkout) over fixture root when
        # fixture root lacks the runner (tiny repos); both are fixed rels.
        script_path = str(gate_script if gate_script.is_file() else (root / suite_rel))
        if gate_script.is_file():
            script_path = str(gate_script)
        else:
            # Fall back to root-owned runner when gate checkout unavailable.
            alt = root / "scripts" / "work_unit_gate" / "descriptor_runner.py"
            script_path = str(alt if alt.is_file() else gate_script)
        if os.name == "posix":
            with _tf.TemporaryFile() as protocol:
                try:
                    argv = descriptor_runner.build_python_child_command(
                        script_rel="scripts/work_unit_gate/descriptor_runner.py", fd=protocol.fileno())
                except Exception:
                    return None
                # Substitute policy-resolved interpreter for the <python> slot.
                cmd = [sys.executable if a == "<python>" else a for a in argv]
                # Resolve script slot to an existing file (gate checkout).
                fixed = [script_path if (a == "scripts/work_unit_gate/descriptor_runner.py") else a for a in cmd]
                try:
                    observed = subprocess.run(fixed, input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                              pass_fds=(protocol.fileno(),), timeout=max(1.0, wall_s),
                                              env=env, cwd=str(root))
                except subprocess.TimeoutExpired:
                    return None
                except OSError:
                    return None
                except Exception:
                    return None
                if observed.returncode != 0:
                    return None
                try:
                    protocol.seek(0)
                    body = protocol.read(descriptor_runner.MAX_PROTOCOL_BYTES + 1)
                except Exception:
                    return None
        else:
            with _tf.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)
                proto = tmp / "proto.bin"
                driver = tmp / "wu837_driver.py"
                try:
                    driver.write_text(
                        "import os, sys, runpy\nproto = sys.argv[1]\ntarget = int(sys.argv[2])\n"
                        "script = sys.argv[3]\nf = open(proto, \"wb\")\nos.dup2(f.fileno(), target)\n"
                        "sys.argv = [script, \"--_python-child\", str(target)]\n"
                        "runpy.run_path(script, run_name=\"__main__\")\n",
                        encoding="utf-8", newline="\n")
                except Exception:
                    return None
                argv = [sys.executable, "-I", "-B", str(driver), str(proto), "10", script_path]
                wenv = dict(env) if isinstance(env, dict) else {}
                wenv.setdefault("PYTHONDONTWRITEBYTECODE", "1")
                wenv.setdefault("PYTHONIOENCODING", "utf-8")
                try:
                    observed = subprocess.run(argv, input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                              timeout=max(1.0, wall_s), env=wenv, cwd=str(root))
                except subprocess.TimeoutExpired:
                    return None
                except OSError:
                    return None
                except Exception:
                    return None
                if observed.returncode != 0:
                    return None
                try:
                    body = proto.read_bytes() if proto.exists() else b""
                except Exception:
                    return None
        if not body:
            return None
        try:
            if phase == "discover":
                data = descriptor_runner.parse_python_protocol(
                    body, request_sha256=request_sha, expected_module=module,
                    expected_source_sha256=source_sha, expected_phase="discover")
            else:
                data = descriptor_runner.parse_python_protocol(
                    body, request_sha256=request_sha, expected_module=module,
                    expected_source_sha256=source_sha, expected_phase="execute",
                    expected_discovery=expected)
        except Exception:
            return None
        if type(data) is not dict:
            return None
        return data
    except Exception:
        return None


if __name__ == "__main__":
    sys.exit(main())
