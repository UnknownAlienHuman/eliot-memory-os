#!/usr/bin/env python3
"""Deterministic serialized-boundary inventory and finite repair allocations (issue #929).

Freeze the F-DENY serialized-boundary denominator for #710: scan tracked Rust
source for serde boundary candidates, classify each into exactly one closed
disposition, bind acquisition profiles without inventing limits, and allocate
finite repair ownership. This unit builds the inventory and initial artifact;
it fixes no production decoder.

Closed dispositions (exactly one per candidate row):
  current-closed | named-legacy | exact-internal | specific-owner |
  needs-repair | unknown

Repair readiness, inventory coverage and safety are independent: a known
unsafe decoder with a complete accepted allocation is READY_FOR_REPAIR but
never safe; missing owner/contract/profile blocks dispatch without blocking
inventory completion. Unknown/unsupported rows are explicit evidence, never
empty success.

Proof ceiling: SOURCE_INVENTORY_AND_OWNERSHIP_ONLY. Findings remain blocking
for #710; this artifact never certifies decoder safety, runtime closure,
product or release acceptance.

Usage:
  python scripts/serde_boundary_inventory.py sync --root .
  python scripts/serde_boundary_inventory.py check --root .
  python scripts/serde_boundary_inventory.py --self-test

Only filesystem mutation: ``sync`` atomically writes the single owned TOML.
``check`` and ``--self-test`` are read-only (no network, no GitHub, no cargo,
no production edits). Allowed subprocesses: ``git ls-files`` and
``git rev-parse`` only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

SCHEMA = "eliot.serde-boundary-inventory.v1"
TOOL_VERSION = "0.1.0"
RULE_REVISION = "929.1"
ISSUE = 929
OWNED_TOML_REL = (
    "crates/foundation/eliot-contracts/tests/data/shipped_serde_boundaries.toml"
)
PROOF_CEILING = "SOURCE_INVENTORY_AND_OWNERSHIP_ONLY"
FIXED_TARGET = "x86_64-pc-windows-msvc"
STU_BUDGET = 100_000

DISPOSITIONS = (
    "current-closed",
    "named-legacy",
    "exact-internal",
    "specific-owner",
    "needs-repair",
    "unknown",
)
KNOWN_DISPOSITIONS = frozenset(DISPOSITIONS)

PROTECTED_FIELDS = frozenset(
    {
        "identity",
        "scope",
        "authority",
        "provenance",
        "privacy",
        "retry",
        "receipt",
        "finish",
        "completeness",
    }
)
BYPASS_SHAPES = frozenset({"flatten", "untagged", "alias", "manual-visitor"})

DENOMINATOR_CASES = tuple(range(1, 25))

# Directly required contract fragments (read-only references, never mutated).
REQUIRED_CONTRACT_REFS = (
    "docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md",
    "docs/architecture/I05-16-common-durable-fields.md",
    "docs/architecture/I05-22-schema-and-migration-rules.md",
    "docs/architecture/I07-02-frame.md",
    "docs/architecture/I07-20-agent-facing-error-contract.md",
    "docs/architecture/I15-06-instructiondata-separation.md",
    "docs/architecture/I18-27-oracle-ownership-and-test-change-governance.md",
)

# Finite owner/repair allocation table (path-anchored rules, not canned rows).
# Each entry owns exact source files; rows are computed by scanning.
CHILDREN: tuple[dict, ...] = (
    {
        "child": "#930",
        "family": "T01",
        "files": ["lib.rs", "ids.rs", "error.rs", "records.rs", "task_execution.rs"],
        "base": "crates/eliot-types/src",
        "tests": ["crates/eliot-types/tests/serde_t01_core.rs"],
        "requirements": ["710/%02d" % n for n in range(1, 21)],
        "prerequisites": [],
        "write_after": [],
    },
    {
        "child": "#931",
        "family": "T02",
        "files": ["runtime.rs", "runtime_supervision.rs", "service.rs", "health.rs", "observability.rs"],
        "base": "crates/eliot-types/src",
        "tests": ["crates/eliot-types/tests/serde_t02_runtime.rs"],
        "requirements": ["710/%02d" % n for n in range(1, 21)],
        "prerequisites": [],
        "write_after": [],
    },
    {
        "child": "#932",
        "family": "T03",
        "files": ["host.rs", "config.rs", "secret_boundary.rs"],
        "base": "crates/eliot-types/src",
        "tests": ["crates/eliot-types/tests/serde_t03_host.rs"],
        "requirements": ["710/%02d" % n for n in range(1, 21)],
        "prerequisites": [],
        "write_after": [],
    },
    {
        "child": "#933",
        "family": "T04",
        "files": ["adapter.rs", "external_agent.rs", "provider_invocation.rs", "mcp_contract.rs"],
        "base": "crates/eliot-types/src",
        "tests": ["crates/eliot-types/tests/serde_t04_agent.rs"],
        "requirements": ["710/%02d" % n for n in range(1, 21)],
        "prerequisites": ["#692"],
        "write_after": [],
    },
    {
        "child": "#934",
        "family": "T05",
        "files": ["antigravity.rs", "antigravity_persistent.rs"],
        "base": "crates/eliot-types/src",
        "tests": ["crates/eliot-types/tests/serde_t05_antigravity.rs"],
        "requirements": ["710/%02d" % n for n in range(1, 21)],
        "prerequisites": [],
        "write_after": [],
    },
    {
        "child": "#935",
        "family": "T06",
        "files": ["cognition.rs", "cognitive_field.rs", "cognitive_run.rs", "project_understanding.rs"],
        "base": "crates/eliot-types/src",
        "tests": ["crates/eliot-types/tests/serde_t06_cognition.rs"],
        "requirements": ["710/%02d" % n for n in range(1, 21)],
        "prerequisites": [],
        "write_after": [],
    },
    {
        "child": "#936",
        "family": "T07",
        "files": ["delegation.rs", "delegation_calibration.rs", "external_review.rs", "verification.rs"],
        "base": "crates/eliot-types/src",
        "tests": ["crates/eliot-types/tests/serde_t07_delegation.rs"],
        "requirements": ["710/%02d" % n for n in range(1, 21)],
        "prerequisites": [],
        "write_after": [],
    },
    {
        "child": "#937",
        "family": "T08",
        "files": ["memory.rs"],
        "base": "crates/eliot-types/src",
        "tests": ["crates/eliot-types/tests/serde_t08_memory.rs"],
        "requirements": ["710/%02d" % n for n in range(1, 21)],
        "prerequisites": [],
        "write_after": [],
    },
    {
        "child": "#938",
        "family": "T09",
        "files": ["semantic_memory.rs", "distillation.rs", "replay.rs", "safety.rs"],
        "base": "crates/eliot-types/src",
        "tests": ["crates/eliot-types/tests/serde_t09_semantic.rs"],
        "requirements": ["710/%02d" % n for n in range(1, 21)],
        "prerequisites": [],
        "write_after": [],
    },
    {
        "child": "#939",
        "family": "T10",
        "files": ["skill.rs", "lifecycle.rs", "eval.rs", "metrics.rs"],
        "base": "crates/eliot-types/src",
        "tests": ["crates/eliot-types/tests/serde_t10_skill.rs"],
        "requirements": ["710/%02d" % n for n in range(1, 21)],
        "prerequisites": [],
        "write_after": [],
    },
    {
        "child": "#940",
        "family": "T11",
        "files": ["cue.rs", "normalize.rs", "activation.rs", "artifact.rs", "measurement.rs"],
        "base": "crates/eliot-types/src/ul",
        "tests": ["crates/eliot-types/tests/serde_t11_ul_cue.rs"],
        "requirements": ["710/%02d" % n for n in range(1, 21)],
        "prerequisites": ["#706"],
        "write_after": [],
    },
    {
        "child": "#941",
        "family": "T12",
        "files": ["behavior.rs", "concept.rs", "cross_agent.rs", "dependency.rs", "exam.rs", "guard.rs", "injection.rs", "onboarding.rs", "prediction.rs", "mod.rs"],
        "base": "crates/eliot-types/src/ul",
        "tests": ["crates/eliot-types/tests/serde_t12_ul_rest.rs"],
        "requirements": ["710/%02d" % n for n in range(1, 21)],
        "prerequisites": [],
        "write_after": [],
    },
    {
        "child": "#976",
        "family": "F-DENY-LS-RECORD",
        "files": ["canonical_record.rs"],
        "base": "crates/eliot-store/src",
        "tests": ["crates/eliot-store/tests/serde_legacy_record.rs"],
        "requirements": ["710/06", "710/11", "710/12", "710/13", "710/16"],
        "prerequisites": [],
        "write_after": [],
    },
    {
        "child": "#977",
        "family": "F-DENY-BRIDGE-INPUT",
        "files": ["main.rs", "request_input.rs"],
        "base": "bins/eliot-agent-bridge/src",
        "tests": ["bins/eliot-agent-bridge/tests/data/request_input_cases.json"],
        "requirements": ["710/%02d" % n for n in range(1, 21)],
        "prerequisites": ["#977-preparation"],
        "write_after": ["#838", "#77"],
    },
)

BRIDGE_PROFILE_REL = "bins/eliot-agent-bridge/src/request_input.rs"
BRIDGE_PROFILE_ID = "eliot.agent-bridge.request-input.v1"
LEGACY_RECORD_REL = "crates/eliot-store/src/canonical_record.rs"
MCP_SPECIFIC_OWNER_REL = "crates/eliot-types/src/mcp_contract.rs"

ALLOWED_COMMANDS = (
    ("git", "ls-files"),
    ("git", "rev-parse"),
    ("git", "status"),
)


class InventoryError(RuntimeError):
    """Stable fail-closed error carrying a machine-readable reason code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _toml_str(value: str) -> str:
    out = value.replace("\\", "\\\\").replace('"', '\\"')
    out = out.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return '"%s"' % out


def _run_git(root: Path, argv: list[str]) -> bytes:
    prefix = tuple(argv[:2])
    if prefix not in ALLOWED_COMMANDS:
        raise InventoryError("COMMAND_NOT_ALLOWED", "command is not fixed/allowed: %r" % (argv,))
    env_keys = ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "TEMP", "TMP",
                "RUSTUP_HOME", "CARGO_HOME", "CARGO_TERM_COLOR", "RUST_BACKTRACE")
    env = {k: v for k, v in os.environ.items() if k in env_keys and v}
    env.setdefault("CARGO_TERM_COLOR", "never")
    try:
        completed = subprocess.run(
            list(argv), cwd=str(root), env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InventoryError("COMMAND_FAILED", "git could not run: %s" % exc) from exc
    if completed.returncode != 0:
        raise InventoryError(
            "COMMAND_FAILED",
            "command exited %d: %r" % (completed.returncode, argv),
        )
    return completed.stdout


def _tracked_rust_files(root: Path) -> list[str]:
    """Enumerate tracked *.rs files; fall back to a sorted walk for bare dirs."""
    try:
        raw = _run_git(root, ["git", "ls-files", "-z"])
        rels = [p for p in raw.decode("utf-8", errors="strict").split("\0") if p.endswith(".rs")]
        # Validate entries stay inside the root (no absolute/parent escapes).
        clean: list[str] = []
        for rel in rels:
            if rel.startswith("/") or ".." in rel.split("/"):
                continue
            if (root / rel).is_file():
                clean.append(rel)
        if clean:
            return sorted(clean)
    except InventoryError:
        pass
    found: list[str] = []
    for path in sorted(root.rglob("*.rs")):
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        parts = rel.split("/")
        if any(part in (".git", "target") for part in parts):
            continue
        found.append(rel)
    return sorted(found)


def _mask_rust(source: str) -> str:
    """Blank strings/comments with spaces, preserving newlines and spans.

    Raises InventoryError MALFORMED_RUST_SOURCE on unclosed block comments,
    string/char literals or raw strings instead of silently mis-scanning.
    """
    out: list[str] = []
    i = 0
    n = len(source)
    line_comment = False
    block_depth = 0
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if line_comment:
            if ch == "\n":
                line_comment = False
                out.append("\n")
            else:
                out.append(" ")
            i += 1
            continue
        if block_depth > 0:
            if ch == "/" and nxt == "*":
                block_depth += 1
                out.extend([" ", " "])
                i += 2
            elif ch == "*" and nxt == "/":
                block_depth -= 1
                out.extend([" ", " "])
                i += 2
            elif ch == "\n":
                out.append("\n")
                i += 1
            else:
                out.append(" ")
                i += 1
            continue
        if ch == "/" and nxt == "/":
            line_comment = True
            out.extend([" ", " "])
            i += 2
            continue
        if ch == "/" and nxt == "*":
            block_depth = 1
            out.extend([" ", " "])
            i += 2
            continue
        if ch == "b" and nxt == '"' :
            j = i + 2
            closed = False
            out.extend([" ", " "])
            i += 2
            while i < n:
                c = source[i]
                if c == "\\":
                    out.extend([" ", " "])
                    i += 2
                    continue
                if c == '"':
                    out.append(" ")
                    i += 1
                    closed = True
                    break
                if c == "\n":
                    break
                out.append(" ")
                i += 1
            if not closed:
                raise InventoryError("MALFORMED_RUST_SOURCE", "unclosed byte-string literal")
            continue
        if ch == "b" and nxt == "'":
            m = re.match(r"b'(?:\\.|[^'\\])'", source[i:])
            if not m:
                raise InventoryError("MALFORMED_RUST_SOURCE", "unclosed byte-char literal")
            out.extend([" "] * len(m.group(0)))
            i += len(m.group(0))
            continue
        if ch == '"':
            out.append(" ")
            i += 1
            closed = False
            while i < n:
                c = source[i]
                if c == "\\":
                    out.extend([" ", " "])
                    i += 2
                    continue
                if c == '"':
                    out.append(" ")
                    i += 1
                    closed = True
                    break
                if c == "\n":
                    break
                out.append(" " if c != "\n" else "\n")
                i += 1
            if not closed:
                raise InventoryError("MALFORMED_RUST_SOURCE", "unclosed string literal")
            continue
        if ch == "'":
            m = re.match(r"'(?:\\.|[^'\\\n])'", source[i:])
            if m:
                # Genuine char literal: blank it.
                out.extend([" "] * len(m.group(0)))
                i += len(m.group(0))
            else:
                # Lifetime tick (e.g. <'de>) or stray quote: keep it so the
                # surrounding code stays visible to discovery.
                out.append(ch)
                i += 1
            continue
        if ch == "r":
            m = re.match(r'r(#*)"', source[i:])
            if m:
                hashes = m.group(1)
                closer = '"' + hashes
                start = i + len(m.group(0))
                end = source.find(closer, start)
                if end < 0:
                    raise InventoryError("MALFORMED_RUST_SOURCE", "unclosed raw string literal")
                segment = source[i:end + len(closer)]
                out.extend("\n" if c == "\n" else " " for c in segment)
                i = end + len(closer)
                continue
            m2 = re.match(r'br(#*)"', source[i:])
            if m2:
                hashes = m2.group(1)
                closer = '"' + hashes
                start = i + len(m2.group(0))
                end = source.find(closer, start)
                if end < 0:
                    raise InventoryError("MALFORMED_RUST_SOURCE", "unclosed raw byte string")
                segment = source[i:end + len(closer)]
                out.extend("\n" if c == "\n" else " " for c in segment)
                i = end + len(closer)
                continue
            out.append(ch)
            i += 1
            continue
        out.append(ch)
        i += 1
    if block_depth > 0:
        raise InventoryError("MALFORMED_RUST_SOURCE", "unclosed block comment")
    return "".join(out)


_DERIVE_OPEN_RE = re.compile(r"#\s*\[\s*derive\s*\(")
_STRUCT_RE = re.compile(r"\b(?:pub(?:\s*\([^)]*\))?\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)\b")
_ENUM_RE = re.compile(r"\b(?:pub(?:\s*\([^)]*\))?\s+)?enum\s+([A-Za-z_][A-Za-z0-9_]*)\b")
_MANUAL_IMPL_RE = re.compile(
    r"impl\s*(?:<[^;{}]*>)?\s*Deserialize\s*(?:<[^;{}]*>)?\s*for\s+([A-Za-z_][A-Za-z0-9_]*(?:::\s*[A-Za-z_][A-Za-z0-9_]*)*)"
)
_VISITOR_IMPL_RE = re.compile(
    r"impl\s*(?:<[^;{}]*>)?\s*Visitor\s*(?:<[^;{}]*>)?\s*for\s+([A-Za-z_][A-Za-z0-9_]*)"
)
_DECODER_CALL_RE = re.compile(
    r"serde_json\s*::\s*from_(str|value|slice|reader)\s*(?:::\s*<\s*([^;(){}<>]+?)\s*>)?\s*\("
)
_VALUE_USE_RE = re.compile(r"\b(?:Value|Map)\b")
_MACRO_UNSUPPORTED_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:serde|deser|Deser)[A-Za-z0-9_]*)\s*!\s*(\(|\[|\{)")
_MAKE_MACRO_CALL_RE = re.compile(r"\b(make_deser|make_serde|serde_derive_magic)\s*!\s*(\(|\[|\{)")
_FN_RE = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^;{}]*>)?\s*\(")
_MOD_RE = re.compile(r"\bmod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")


def _line_of(offset: int, line_starts: list[int]) -> int:
    import bisect

    return bisect.bisect_right(line_starts, offset)


def _enclosing_item(masked: str, offset: int) -> tuple[str, str]:
    """Return (function, module) enclosing a byte offset (nearest backwards)."""
    head = masked[:offset]
    func = ""
    for m in _FN_RE.finditer(head):
        func = m.group(1)
    mod = ""
    for m in _MOD_RE.finditer(head):
        mod = m.group(1)
    return func, mod


def _preceding_attr_block(
    masked_lines: list[str], raw_lines: list[str], line_starts: list[int], offset: int
) -> tuple[str, int]:
    """Collect the attribute block directly above an offset (multiline-aware).

    The walk uses masked lines for structure; the returned text is sliced
    from the raw lines so quoted values (``tag = "kind"``) survive: masking
    blanks string contents. Returns ``(attr_text, start_lineno_1based)``;
    ``("", 0)`` when no attribute block is present. Attribute blocks may
    span lines and stack; the walk stops at code.
    """
    lineno = _line_of(offset, line_starts)
    picked: list[int] = []
    idx = lineno - 2  # zero-based line just above
    while idx >= 0:
        stripped = masked_lines[idx].strip()
        if stripped == "":
            idx -= 1
            continue
        is_attr_start = stripped.startswith("#[")
        open_brackets = sum(masked_lines[k].count("[") - masked_lines[k].count("]") for k in picked)
        open_parens = sum(masked_lines[k].count("(") - masked_lines[k].count(")") for k in picked)
        continues = (
            is_attr_start
            or open_brackets > 0
            or open_parens > 0
            or stripped in (")]", ")]", "]", ")", "},", "},")
            or stripped.endswith(",")
            or stripped.endswith("(")
            or re.match(r"^[A-Za-z_:][A-Za-z0-9_:]*(\s*::\s*[A-Za-z_][A-Za-z0-9_]*)*$", stripped) is not None
            or re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", stripped) is not None
            or stripped.startswith('"')
        )
        if not continues:
            break
        picked.append(idx)
        idx -= 1
    picked.reverse()
    # Keep only genuine attribute lines (from the first #[ onward).
    start = 0
    for k, lineno0 in enumerate(picked):
        if masked_lines[lineno0].strip().startswith("#["):
            start = k
            break
    else:
        return "", 0
    kept = picked[start:]
    return "\n".join(raw_lines[k] for k in kept), kept[0] + 1


def _extend_to_close_brace(masked: str, end_off: int) -> int:
    """Extend an item end offset to its balanced closing brace when present.

    Struct/enum/impl bodies matter for review worksets, so the candidate
    span covers the whole item rather than its header line. Masked text has
    no strings/comments, so braces are structural.
    """
    tail = masked[end_off:]
    open_at = tail.find("{")
    if open_at < 0:
        return end_off
    # Refuse to cross a top-level item boundary: only extend when the brace
    # belongs to this item (no intervening ';' at depth zero).
    depth = 0
    i = end_off
    n = len(masked)
    while i < n:
        ch = masked[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        elif ch == ";" and depth == 0:
            return end_off
        i += 1
    return end_off


def _serde_flags(attr_text: str) -> dict[str, bool | str]:
    low = attr_text.lower()
    flags: dict[str, bool | str] = {
        "deny_unknown_fields": "deny_unknown_fields" in low,
        "tag": "",
        "untagged": "untagged" in low,
        "flatten": "flatten" in low,
        "alias": "alias" in low,
        "default": "default" in low,
        "remote": "",
        "with": "",
        "deserialize_with": "deserialize_with" in low,
    }
    m = re.search(r'tag\s*=\s*"([^"]+)"', attr_text)
    if m:
        flags["tag"] = m.group(1)
    m = re.search(r'remote\s*=\s*"([^"]+)"', attr_text)
    if m:
        flags["remote"] = m.group(1)
    m = re.search(r'with\s*=\s*"([^"]+)"', attr_text)
    if m:
        flags["with"] = m.group(1)
    return flags


def _is_test_scope(rel: str, masked: str, offset: int, func: str, mod: str) -> bool:
    if "/tests/" in rel or "/testdata/" in rel or "/testing/" in rel:
        return True
    base = rel.rsplit("/", 1)[-1]
    if base.startswith("test_") or base.endswith("_test.rs") or base.endswith("_tests.rs"):
        return True
    if mod == "tests":
        return True
    # Span-level cfg(test): candidate below a cfg(test) marker in the same file.
    head = masked[:offset]
    if '#[cfg(test)]' in head.replace(" ", "") or '#[cfg( test )]' in head:
        # Only treat as test scope when inside the tests module region.
        cfg_pos = head.replace(" ", "").rfind("#[cfg(test)]")
        mod_pos = head.rfind("mod tests")
        if mod_pos >= 0 and mod_pos > cfg_pos - 500:
            return True
    if func.startswith("test_"):
        return True
    return False


def _scan_text(
    rel: str,
    text: str,
    package: str,
    file_digest: str,
    build_class: str,
    release_class: str,
) -> list[dict]:
    try:
        masked = _mask_rust(text)
    except InventoryError as exc:
        span_digest = _sha256_text(rel + ":unreadable-span")
        return [
            {
                "id": "%s:%s:<unparsed>:1" % (package, rel),
                "package": package,
                "path": rel,
                "type": "<unparsed>",
                "function": "",
                "kind": "unreadable-source",
                "span_start": 1,
                "span_end": 1,
                "span_digest": span_digest,
                "digest": _sha256_text(rel + span_digest + exc.code),
                "attributes": {},
                "helpers": [],
                "decoder_calls": [],
                "value_routing": False,
                "test_scope": _is_test_scope(rel, "", 0, "", ""),
                "build_class": build_class,
                "release_class": release_class,
                "evidence": "malformed-rust-source: %s" % exc.detail,
                "protected_hint": False,
            }
        ]
    masked_lines = masked.split("\n")
    raw_lines = text.split("\n")
    lines = masked_lines
    line_starts: list[int] = []
    pos = 0
    for line in lines:
        line_starts.append(pos)
        pos += len(line) + 1

    candidates: list[dict] = []

    def push_candidate(
        type_name: str,
        kind: str,
        start_off: int,
        end_off: int,
        attr_text: str,
        attr_start_line: int,
        func: str,
        evidence: str,
    ) -> None:
        end_off = _extend_to_close_brace(masked, end_off)
        start_line = _line_of(start_off, line_starts)
        if attr_start_line:
            start_line = min(start_line, attr_start_line)
        end_line = max(start_line, _line_of(end_off, line_starts))
        span_text = "\n".join(lines[start_line - 1 : end_line])
        span_digest = _sha256_text(rel + "\n" + span_text)
        flags = _serde_flags(attr_text)
        # Field-level helpers (with/deserialize_with/remote) and shapes
        # (flatten/alias/default) live inside the item body: merge every
        # inner #[serde(...)] from the raw span so masked string contents
        # cannot hide them. Booleans OR together; first value wins.
        raw_span = "\n".join(raw_lines[start_line - 1 : end_line])
        for inner in re.findall(r"#\[serde\((.*?)\)\]", raw_span, re.DOTALL):
            inner_flags = _serde_flags("#[serde(%s)]" % inner)
            for key, value in inner_flags.items():
                if isinstance(value, bool):
                    if value:
                        flags[key] = True
                elif value and not flags.get(key):
                    flags[key] = value
        helpers: list[str] = []
        if flags.get("with"):
            helpers.append(str(flags["with"]))
        if flags.get("deserialize_with"):
            helpers.append("deserialize_with")
        if flags.get("remote"):
            helpers.append("remote:%s" % flags["remote"])
        test_scope = _is_test_scope(rel, masked, start_off, func, _enclosing_item(masked, start_off)[1])
        protected_hint = any(
            field in span_text
            for field in ("identity", "authority", "scope", "principal", "fence", "receipt")
        )
        candidates.append(
            {
                "id": "%s:%s:%s:%d" % (package, rel, type_name, start_line),
                "package": package,
                "path": rel,
                "type": type_name,
                "function": func,
                "kind": kind,
                "span_start": start_line,
                "span_end": end_line,
                "span_digest": span_digest,
                "digest": _sha256_text(":".join((package, rel, type_name, str(start_line), span_digest))),
                "attributes": {
                    "deny_unknown_fields": bool(flags["deny_unknown_fields"]),
                    "tag": str(flags["tag"]),
                    "untagged": bool(flags["untagged"]),
                    "flatten": bool(flags["flatten"]),
                    "alias": bool(flags["alias"]),
                    "default": bool(flags["default"]),
                    "remote": str(flags["remote"]),
                    "with": str(flags["with"]),
                    "deserialize_with": bool(flags["deserialize_with"]),
                },
                "helpers": sorted(set(helpers)),
                "decoder_calls": [],
                "value_routing": bool(_VALUE_USE_RE.search(span_text)),
                "test_scope": test_scope,
                "build_class": build_class,
                "release_class": release_class,
                "evidence": evidence,
                "protected_hint": protected_hint,
            }
        )

    # Derive-declared structs/enums (multiline-aware via preceding attrs).
    for pattern in (_STRUCT_RE, _ENUM_RE):
        for m in pattern.finditer(masked):
            attrs, attr_start = _preceding_attr_block(masked_lines, raw_lines, line_starts, m.start())
            if "deserialize" not in attrs.lower():
                continue
            func, _mod = _enclosing_item(masked, m.start())
            push_candidate(m.group(1), "derive", m.start(), m.end(), attrs, attr_start, func, "derive-deserialize")
    # Manual Deserialize impls.
    for m in _MANUAL_IMPL_RE.finditer(masked):
        target = m.group(1).split("::")[-1].strip()
        attrs, attr_start = _preceding_attr_block(masked_lines, raw_lines, line_starts, m.start())
        func, _mod = _enclosing_item(masked, m.start())
        # Avoid double-counting a derive row for the same type+line.
        push_candidate(target, "manual-impl", m.start(), m.end(), attrs, attr_start, func, "manual-deserialize-impl")
    # Custom visitors.
    for m in _VISITOR_IMPL_RE.finditer(masked):
        attrs, attr_start = _preceding_attr_block(masked_lines, raw_lines, line_starts, m.start())
        func, _mod = _enclosing_item(masked, m.start())
        push_candidate(m.group(1), "visitor", m.start(), m.end(), attrs, attr_start, func, "custom-visitor")

    # Decoder call sites: attach to a local type row when the target matches,
    # otherwise accumulate as standalone acquisition candidates keyed by
    # (target, function, test_scope) so repeated test calls do not explode.
    standalone: dict[tuple[str, str, bool], dict] = {}
    local_types = {c["type"] for c in candidates}
    for m in _DECODER_CALL_RE.finditer(masked):
        method = m.group(1)
        target = (m.group(2) or "").strip()
        if not target:
            target = "Value" if method == "value" else "<inferred>"
        target = target.split("::")[-1].split("<")[0].strip() or target
        func, mod = _enclosing_item(masked, m.start())
        start_line = _line_of(m.start(), line_starts)
        test_scope = _is_test_scope(rel, masked, m.start(), func, mod)
        call = {
            "method": "from_%s" % method,
            "target": target,
            "function": func,
            "line": start_line,
            "test_scope": test_scope,
        }
        attached = False
        for row in candidates:
            if row["type"] == target and row["kind"] in ("derive", "manual-impl"):
                row["decoder_calls"].append(call)
                if method == "value" or target == "Value":
                    row["value_routing"] = True
                attached = True
        if attached:
            continue
        key = (target, func, test_scope)
        entry = standalone.get(key)
        if entry is None:
            span_digest = _sha256_text("%s:%s:%s" % (rel, target, func))
            entry = {
                "id": "%s:%s:%s@%s:%d" % (package, rel, target, func or "<root>", start_line),
                "package": package,
                "path": rel,
                "type": target,
                "function": func,
                "kind": "decoder-callsite",
                "span_start": start_line,
                "span_end": start_line,
                "span_digest": span_digest,
                "digest": _sha256_text(":".join((package, rel, target, func, span_digest))),
                "attributes": {
                    "deny_unknown_fields": False,
                    "tag": "",
                    "untagged": False,
                    "flatten": False,
                    "alias": False,
                    "default": False,
                    "remote": "",
                    "with": "",
                    "deserialize_with": False,
                },
                "helpers": [],
                "decoder_calls": [],
                "value_routing": target == "Value" or method == "value",
                "test_scope": test_scope,
                "build_class": build_class,
                "release_class": release_class,
                "evidence": "actual-decoder-callsite",
                "protected_hint": target not in ("Value", "<inferred>"),
            }
            standalone[key] = entry
            candidates.append(entry)
        entry["decoder_calls"].append(call)

    # Unsupported/descriptive macros stay explicit unknown rows (one per site;
    # overlapping patterns are deduped so one site yields exactly one row).
    seen_macro_sites: set[tuple[str, int]] = set()
    for pattern in (_MACRO_UNSUPPORTED_RE, _MAKE_MACRO_CALL_RE):
        for m in pattern.finditer(masked):
            name = m.group(1)
            func, _mod = _enclosing_item(masked, m.start())
            start_line = _line_of(m.start(), line_starts)
            if (name, start_line) in seen_macro_sites:
                continue
            seen_macro_sites.add((name, start_line))
            span_digest = _sha256_text("%s:unsupported:%s:%d" % (rel, name, start_line))
            candidates.append(
                {
                    "id": "%s:%s:<macro-%s>:%d" % (package, rel, name, start_line),
                    "package": package,
                    "path": rel,
                    "type": "<macro-%s>" % name,
                    "function": func,
                    "kind": "unsupported-macro",
                    "span_start": start_line,
                    "span_end": start_line,
                    "span_digest": span_digest,
                    "digest": _sha256_text(":".join((package, rel, name, str(start_line), span_digest))),
                    "attributes": {
                        "deny_unknown_fields": False,
                        "tag": "",
                        "untagged": False,
                        "flatten": False,
                        "alias": False,
                        "default": False,
                        "remote": "",
                        "with": "",
                        "deserialize_with": False,
                    },
                    "helpers": [name],
                    "decoder_calls": [],
                    "value_routing": False,
                    "test_scope": _is_test_scope(rel, masked, m.start(), func, _mod if "_mod" in dir() else ""),
                    "build_class": build_class,
                    "release_class": release_class,
                    "evidence": "unsupported-macro: regex discovery cannot resolve generated Deserialize",
                    "protected_hint": False,
                }
            )
    # File digest binds every row for staleness checks.
    for row in candidates:
        row["file_digest"] = file_digest
    # Deterministic order regardless of traversal.
    candidates.sort(key=lambda r: r["id"])
    return candidates


def _load_workspace_meta(root: Path) -> dict:
    cargo_path = root / "Cargo.toml"
    if not cargo_path.is_file():
        return {"members": [], "default_members": [], "rust_version": "", "serde_features": []}
    try:
        data = tomllib.loads(cargo_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {"members": [], "default_members": [], "rust_version": "", "serde_features": []}
    workspace = data.get("workspace", {})
    members = list(workspace.get("members", []) or [])
    default_members = list(workspace.get("default-members", []) or [])
    package = workspace.get("package", {}) or {}
    rust_version = str(package.get("rust-version", "") or "")
    deps = workspace.get("dependencies", {}) or {}
    serde_features: list[str] = []
    for dep_name in ("serde", "serde_json"):
        dep = deps.get(dep_name)
        if isinstance(dep, dict):
            for feat in dep.get("features", []) or []:
                serde_features.append("%s/%s" % (dep_name, feat))
    return {
        "members": sorted(members),
        "default_members": sorted(default_members),
        "rust_version": rust_version,
        "serde_features": sorted(set(serde_features)),
    }


def _package_for_path(root: Path, rel: str, cache: dict[str, str]) -> str:
    if rel in cache:
        return cache[rel]
    parts = rel.split("/")[:-1]
    for depth in range(len(parts), -1, -1):
        candidate = root.joinpath(*parts[:depth], "Cargo.toml") if depth else root / "Cargo.toml"
        if candidate.is_file():
            try:
                data = tomllib.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, tomllib.TOMLDecodeError):
                continue
            name = (data.get("package", {}) or {}).get("name", "")
            if name:
                cache[rel] = str(name)
                return cache[rel]
    cache[rel] = "unknown-package"
    return cache[rel]


def _release_package_dirs(root: Path, meta: dict) -> set[str]:
    """BFS path-dependency closure from default-members (no cargo execution)."""
    members: set[str] = set(meta.get("members", []))
    seeds = [m for m in meta.get("default_members", []) if m in members]
    if not seeds:
        return set()
    dir_to_member: dict[str, str] = {m: m for m in members}
    visited: set[str] = set()
    stack = list(seeds)
    while stack:
        member = stack.pop()
        if member in visited:
            continue
        visited.add(member)
        manifest = root / member / "Cargo.toml"
        if not manifest.is_file():
            continue
        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        for section in ("dependencies", "build-dependencies"):
            deps = (data.get(section, {}) or {})
            for _name, spec in deps.items():
                if isinstance(spec, dict) and isinstance(spec.get("path"), str):
                    dep_dir = (Path(member) / spec["path"]).as_posix()
                    # Normalize ./ and ../ segments lexically.
                    norm = os.path.normpath(dep_dir).replace("\\", "/")
                    if norm in dir_to_member and norm not in visited:
                        stack.append(norm)
    return visited


def _owner_map_digest() -> str:
    payload = json.dumps(
        [
            {
                "child": c["child"],
                "base": c["base"],
                "files": sorted(c["files"]),
                "tests": sorted(c["tests"]),
                "requirements": sorted(c["requirements"]),
                "prerequisites": sorted(c["prerequisites"]),
            }
            for c in CHILDREN
        ],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _rule_digest() -> str:
    payload = json.dumps(
        {
            "rule_revision": RULE_REVISION,
            "dispositions": list(DISPOSITIONS),
            "protected_fields": sorted(PROTECTED_FIELDS),
            "bypass_shapes": sorted(BYPASS_SHAPES),
            "target": FIXED_TARGET,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _profile_evidence(root: Path) -> dict:
    """Parse (never invent) the accepted Bridge input-profile limits."""
    path = root / BRIDGE_PROFILE_REL
    if not path.is_file():
        return {
            "profile_id": BRIDGE_PROFILE_ID,
            "status": "missing",
            "source": BRIDGE_PROFILE_REL,
            "source_digest": "",
            "limits": [],
            "digest": _sha256_text("missing:" + BRIDGE_PROFILE_ID),
            "evidence": "missing-profile: no accepted Bridge input profile; affected parser dispatch is blocked",
        }
    try:
        text = path.read_text(encoding="utf-8")
        source_digest = _sha256_text(text)
    except OSError:
        return {
            "profile_id": BRIDGE_PROFILE_ID,
            "status": "unreadable",
            "source": BRIDGE_PROFILE_REL,
            "source_digest": "",
            "limits": [],
            "digest": _sha256_text("unreadable:" + BRIDGE_PROFILE_ID),
            "evidence": "unreadable-profile: cannot establish accepted limits",
        }
    if "REQUEST_INPUT_PROFILE" not in text:
        return {
            "profile_id": BRIDGE_PROFILE_ID,
            "status": "unrecognized",
            "source": BRIDGE_PROFILE_REL,
            "source_digest": source_digest,
            "limits": [],
            "digest": _sha256_text("unrecognized:" + source_digest),
            "evidence": "unrecognized-profile: expected REQUEST_INPUT_PROFILE block not found",
        }
    profile_id = BRIDGE_PROFILE_ID
    m = re.search(r'REQUEST_INPUT_PROFILE_ID\s*:\s*&str\s*=\s*"([^"]+)"', text)
    if m:
        profile_id = m.group(1)
    block = re.search(
        r"REQUEST_INPUT_PROFILE\s*:\s*RequestInputProfile\s*=\s*RequestInputProfile\s*\{(.*?)\};",
        text,
        re.DOTALL,
    )
    limits: list[dict] = []
    if block:
        for name, raw in re.findall(r"(\bmax_[a-z_]+|idle_timeout_ms|lifetime_timeout_ms)\s*:\s*([0-9][0-9_]*)", block.group(1)):
            value = int(raw.replace("_", ""))
            if name.endswith("_bytes"):
                unit, encoding, stage = "bytes", "encoded-or-retained-bytes", "acquisition"
            elif name.endswith("_items") or name.endswith("_values"):
                unit, encoding, stage = "items", "decoded-container", "decode"
            elif name.endswith("_depth"):
                unit, encoding, stage = "levels", "decoded-tree", "decode"
            elif name.endswith("_ms"):
                unit, encoding, stage = "milliseconds", "wall-clock-declared-not-enforced", "lifetime"
            else:
                unit, encoding, stage = "count", "process-lifetime", "lifetime"
            limits.append(
                {
                    "name": name,
                    "value": value,
                    "unit": unit,
                    "encoding": encoding,
                    "stage": stage,
                    "source": "bridge-local-decision",
                }
            )
    limits.sort(key=lambda l: l["name"])
    digest = _sha256_text(
        json.dumps(
            {"profile_id": profile_id, "source_digest": source_digest, "limits": limits},
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return {
        "profile_id": profile_id,
        "status": "parsed" if limits else "unrecognized",
        "source": BRIDGE_PROFILE_REL,
        "source_digest": source_digest,
        "limits": limits,
        "digest": digest,
        "evidence": "parsed-from-%s; I7.2 frame defaults not reused as request limits" % BRIDGE_PROFILE_REL,
    }


def _legacy_evidence(root: Path) -> dict:
    path = root / LEGACY_RECORD_REL
    if not path.is_file():
        return {"status": "missing", "source": LEGACY_RECORD_REL, "source_digest": "",
                "digest": _sha256_text("missing:legacy"),
                "evidence": "missing-legacy-source"}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {"status": "unreadable", "source": LEGACY_RECORD_REL, "source_digest": "",
                "digest": _sha256_text("unreadable:legacy"),
                "evidence": "unreadable-legacy-source"}
    digest = _sha256_text(text)
    return {
        "status": "parsed",
        "source": LEGACY_RECORD_REL,
        "source_digest": digest,
        "digest": _sha256_text("legacy:" + digest),
        "dual_form": ("receipt_body_json_b64" in text and "receipt_body" in text),
        "base64_legacy": ("STANDARD_NO_PAD" in text or "base64" in text.lower()),
        "evidence": "dual-form-precedence: receipt_body_json_b64 preferred, legacy receipt_body fallback",
    }


def _child_for_rel(rel: str) -> str:
    for child in CHILDREN:
        base = child["base"].rstrip("/")
        if rel == base or rel.startswith(base + "/"):
            leaf = rel.rsplit("/", 1)[-1]
            if leaf in child["files"]:
                return child["child"]
    return ""


def _classify(row: dict, profile: dict, legacy: dict) -> dict:
    """Assign exactly one disposition plus ownership/readiness (first match wins)."""
    rel: str = row["path"]
    kind: str = row["kind"]
    attrs: dict = row["attributes"]
    test_scope: bool = row["test_scope"]

    if kind in ("unreadable-source", "unsupported-macro"):
        return {
            "disposition": "unknown",
            "owner": "unknown",
            "repair_child": "",
            "repair_readiness": "BLOCKED",
            "blocked_reason": "missing-contract: unsupported syntax or unreadable source",
            "safety": "NOT_SAFE",
            "callers": [],
            "invalidation": "invalidate on resolved syntax with exact caller evidence",
            "limit_binding": "not-applicable: unknown candidate has no limit table",
            "canonical_impact": "unknown: cannot assess canonical identity before parsing",
            "schema_class": "unknown",
        }
    if test_scope:
        return {
            "disposition": "exact-internal",
            "owner": "test-harness",
            "repair_child": "",
            "repair_readiness": "NO_REPAIR_REQUIRED",
            "blocked_reason": "",
            "safety": "PENDING_EXECUTED_PROOF",
            "callers": [rel],
            "invalidation": "invalidate on any new production ingress caller",
            "limit_binding": "not-applicable: test scope performs no shipped acquisition",
            "canonical_impact": "none: test scope carries no canonical identity",
            "schema_class": "test-only",
        }
    if rel == MCP_SPECIFIC_OWNER_REL:
        return {
            "disposition": "specific-owner",
            "owner": "#692",
            "repair_child": "#933",
            "repair_readiness": "READY_FOR_REPAIR",
            "blocked_reason": "",
            "safety": "PENDING_EXECUTED_PROOF",
            "callers": [rel],
            "invalidation": "invalidate on new MCP forwarding caller or contract change",
            "limit_binding": "not-applicable: non-acquisition row; limits require an explained disposition, never invented values",
            "canonical_impact": "versioned: MCP shapes preserve wire identity per owner contract",
            "schema_class": "current",
        }
    if rel == LEGACY_RECORD_REL:
        return {
            "disposition": "named-legacy",
            "owner": "#976",
            "repair_child": "#976",
            "repair_readiness": "READY_FOR_REPAIR",
            "blocked_reason": "",
            "safety": "PENDING_EXECUTED_PROOF",
            "callers": [rel],
            "invalidation": "invalidate on legacy form, precedence or owner change",
            "limit_binding": "not-applicable: store projection row; acquisition limits live with the ingress owner",
            "canonical_impact": "preserved: dual-form precedence keeps canonical bytes; drift must be versioned",
            "schema_class": "legacy",
        }
    if rel.startswith("bins/eliot-agent-bridge/src/") and row["type"] in ("Request", "request_input", "ReadOutcome", "RequestInputProfile"):
        readiness = "BLOCKED" if profile.get("status") != "parsed" else "BLOCKED"
        reason = "missing-profile: accepted Bridge profile pending" if profile.get("status") != "parsed" else "pending-profile-acceptance: parsed limits await independent review before parser dispatch"
        return {
            "disposition": "needs-repair",
            "owner": "#977",
            "repair_child": "#977",
            "repair_readiness": readiness,
            "blocked_reason": reason,
            "safety": "NOT_SAFE",
            "callers": ["bins/eliot-agent-bridge/src/main.rs"],
            "invalidation": "invalidate on profile, limit, framing or operation-set change",
            "limit_binding": "bridge-profile:%s" % profile.get("profile_id", BRIDGE_PROFILE_ID),
            "canonical_impact": "bounded-ingress: rejection precedes dispatch; no canonical bytes admitted before validation",
            "schema_class": "current",
        }
    if rel.startswith("bins/eliot-agent-bridge/src/") and kind == "decoder-callsite":
        readiness = "BLOCKED"
        reason = "pending-profile-acceptance: Bridge acquisition needs the accepted input profile before parser dispatch"
        return {
            "disposition": "needs-repair",
            "owner": "#977",
            "repair_child": "#977",
            "repair_readiness": readiness,
            "blocked_reason": reason,
            "safety": "NOT_SAFE",
            "callers": ["bins/eliot-agent-bridge/src/main.rs"],
            "invalidation": "invalidate on profile, limit, framing or operation-set change",
            "limit_binding": "bridge-profile:%s" % profile.get("profile_id", BRIDGE_PROFILE_ID),
            "canonical_impact": "bounded-ingress: rejection precedes dispatch; no canonical bytes admitted before validation",
            "schema_class": "current",
        }
    if kind == "visitor":
        child = _child_for_rel(rel) or "UNASSIGNED"
        blocked = child == "UNASSIGNED"
        return {
            "disposition": "needs-repair",
            "owner": child,
            "repair_child": child,
            "repair_readiness": "BLOCKED" if blocked else "READY_FOR_REPAIR",
            "blocked_reason": "missing-owner: no bounded repair child for this path" if blocked else "",
            "safety": "NOT_SAFE",
            "callers": [c.get("target", "") + ":" + str(c.get("line", "")) for c in row["decoder_calls"]] or [rel],
            "invalidation": "invalidate on visitor, caller or schema change",
            "limit_binding": "not-applicable: non-acquisition row; manual visitor needs bypass-blocked proof, not invented limits",
            "canonical_impact": "unknown: manual visitor may reshape canonical identity; owner must prove preservation",
            "schema_class": "current",
        }
    bypass = [s for s in ("flatten", "untagged", "alias") if attrs.get(s)] + (
        ["manual-visitor"] if kind == "manual-impl" and "visit_map" in (row.get("evidence", "") + str(attrs)) else []
    )
    # Manual impls always route through custom code: treat as bypass-class.
    if kind == "manual-impl":
        bypass = sorted(set(bypass + ["manual-visitor"]))
    if bypass or row.get("value_routing"):
        child = _child_for_rel(rel) or "UNASSIGNED"
        blocked = child == "UNASSIGNED"
        # Value/map routing into protected types is permissive until proven.
        return {
            "disposition": "needs-repair",
            "owner": child,
            "repair_child": child,
            "repair_readiness": "BLOCKED" if blocked else "READY_FOR_REPAIR",
            "blocked_reason": "missing-owner: no bounded repair child for this path" if blocked else "",
            "safety": "NOT_SAFE",
            "callers": [rel],
            "invalidation": "invalidate on shape, helper, caller or schema change",
            "limit_binding": "not-applicable: non-acquisition row; bypass/value routes need blocked-shape proof, not invented limits",
            "canonical_impact": "unknown: bypass/value routing may erase lexical evidence; owner must prove canonical preservation",
            "schema_class": "current",
        }
    if not attrs.get("deny_unknown_fields"):
        child = _child_for_rel(rel) or "UNASSIGNED"
        blocked = child == "UNASSIGNED"
        return {
            "disposition": "needs-repair",
            "owner": child,
            "repair_child": child,
            "repair_readiness": "BLOCKED" if blocked else "READY_FOR_REPAIR",
            "blocked_reason": "missing-owner: no bounded repair child for this path" if blocked else "",
            "safety": "NOT_SAFE",
            "callers": [rel],
            "invalidation": "invalidate on attribute, caller or schema change",
            "limit_binding": "not-applicable: non-acquisition row; permissive shape needs closure proof, not invented limits",
            "canonical_impact": "unknown: permissive shape may admit non-canonical bytes",
            "schema_class": "current",
        }
    child = _child_for_rel(rel)
    if child:
        return {
            "disposition": "current-closed",
            "owner": child,
            "repair_child": child,
            "repair_readiness": "NO_REPAIR_REQUIRED",
            "blocked_reason": "",
            "safety": "PENDING_EXECUTED_PROOF",
            "callers": [rel],
            "invalidation": "invalidate on attribute, caller, schema or owner change",
            "limit_binding": "not-applicable: non-acquisition row with strict shape; no invented limits",
            "canonical_impact": "preserved: deny_unknown_fields with no bypass shapes; drift must be versioned",
            "schema_class": "current",
        }
    return {
        "disposition": "needs-repair",
        "owner": "UNASSIGNED",
        "repair_child": "UNASSIGNED",
        "repair_readiness": "BLOCKED",
        "blocked_reason": "missing-owner: no bounded repair child for this path",
        "safety": "NOT_SAFE",
        "callers": [rel],
        "invalidation": "invalidate on ownership assignment or caller change",
        "limit_binding": "not-applicable: ownerless row cannot carry invented limits",
        "canonical_impact": "unknown: unowned boundary cannot claim canonical preservation",
        "schema_class": "current",
    }


def build_inventory(root: Path, scan_rels: list[str] | None = None) -> dict:
    """Scan, classify and allocate. Pure compute; no filesystem writes."""
    root = root.resolve()
    meta = _load_workspace_meta(root)
    members = meta["members"]
    default_members = meta["default_members"]
    ambiguous = False
    ambiguous_reason = ""
    if not members:
        ambiguous = True
        ambiguous_reason = "missing-workspace-members: root Cargo.toml lists no workspace members"
    elif not default_members:
        ambiguous = True
        ambiguous_reason = "missing-default-members: no exact release roots declared"
    elif any(m not in members for m in default_members):
        ambiguous = True
        ambiguous_reason = "default-members-outside-workspace: release roots must be workspace members"
    release_dirs = _release_package_dirs(root, meta)
    targets = [FIXED_TARGET]
    features = meta["serde_features"] or ["serde/derive", "serde_json/float_roundtrip"]

    try:
        base_sha = _run_git(root, ["git", "rev-parse", "HEAD"]).decode("utf-8", errors="replace").strip()
    except InventoryError:
        base_sha = "unknown-base"

    if scan_rels is None:
        scan_rels = _tracked_rust_files(root)
    else:
        scan_rels = sorted(scan_rels)
    if len(scan_rels) > 20000:
        raise InventoryError("UNIVERSE_TOO_LARGE", "refusing hidden truncation: %d files" % len(scan_rels))

    profile = _profile_evidence(root)
    legacy = _legacy_evidence(root)

    package_cache: dict[str, str] = {}
    candidates: list[dict] = []
    for rel in scan_rels:
        path = root / rel
        package = _package_for_path(root, rel, package_cache)
        in_release = any(
            rel == d or rel.startswith(d.rstrip("/") + "/") for d in release_dirs
        ) if release_dirs else False
        in_member = any(
            rel == m or rel.startswith(m.rstrip("/") + "/") for m in members
        ) if members else False
        build_class = "workspace-member" if in_member else "disconnected"
        if not release_dirs:
            release_class = "unknown-release"
        else:
            release_class = "release-reachable" if in_release else "non-release"
        try:
            raw = path.read_bytes()
            if len(raw) > 8 * 1024 * 1024:
                raise InventoryError("SOURCE_FILE_TOO_LARGE", rel)
            text = raw.decode("utf-8")
            file_digest = _sha256_bytes(raw)
        except (OSError, UnicodeDecodeError) as exc:
            span_digest = _sha256_text(rel + ":read-failure")
            candidates.append(
                {
                    "id": "%s:%s:<unreadable>:1" % (package, rel),
                    "package": package,
                    "path": rel,
                    "type": "<unreadable>",
                    "function": "",
                    "kind": "unreadable-source",
                    "span_start": 1,
                    "span_end": 1,
                    "span_digest": span_digest,
                    "digest": _sha256_text(rel + span_digest),
                    "file_digest": "",
                    "attributes": {},
                    "helpers": [],
                    "decoder_calls": [],
                    "value_routing": False,
                    "test_scope": False,
                    "build_class": build_class,
                    "release_class": release_class,
                    "evidence": "read-failure: %s" % exc,
                    "protected_hint": False,
                }
            )
            continue
        for row in _scan_text(rel, text, package, file_digest, build_class, release_class):
            candidates.append(row)

    # Bind classification/allocation per row (no canned rows: all computed).
    rows: list[dict] = []
    for cand in candidates:
        verdict = _classify(cand, profile, legacy)
        admission = "ship" if (
            cand["release_class"] == "release-reachable" and not cand["test_scope"]
            and verdict["disposition"] != "unknown"
        ) else "admission-risk"
        boundary_evidence = (
            "actual-decoder-callsite"
            if cand["decoder_calls"] or cand["kind"] == "decoder-callsite"
            else ("derive-only" if cand["kind"] in ("derive", "manual-impl", "visitor") else cand["kind"])
        )
        is_acquisition = verdict["limit_binding"].startswith("bridge-profile:")
        if is_acquisition:
            limit_detail = {
                "profile_id": profile.get("profile_id", BRIDGE_PROFILE_ID),
                "profile_source": profile.get("source", BRIDGE_PROFILE_REL),
                "profile_source_digest": profile.get("source_digest", ""),
                "profile_digest": profile.get("digest", ""),
                "limits": profile.get("limits", []),
                "status": profile.get("status", "missing"),
            }
        else:
            limit_detail = {
                "disposition": "not-applicable",
                "reason": verdict["limit_binding"],
            }
        row = {
            "id": cand["id"],
            "candidate_id": cand["id"],
            "package": cand["package"],
            "path": cand["path"],
            "type": cand["type"],
            "function": cand["function"],
            "kind": cand["kind"],
            "span_start": cand["span_start"],
            "span_end": cand["span_end"],
            "span_digest": cand["span_digest"],
            "digest": cand["digest"],
            "file_digest": cand.get("file_digest", ""),
            "owner": verdict["owner"],
            "schema_owner": verdict["owner"],
            "repair_owner": verdict["repair_child"],
            "repair_child": verdict["repair_child"],
            "repair_readiness": verdict["repair_readiness"],
            "blocked_reason": verdict["blocked_reason"],
            "safety": verdict["safety"],
            "disposition": verdict["disposition"],
            "build_class": cand["build_class"],
            "release_class": cand["release_class"],
            "admission": admission,
            "boundary_evidence": boundary_evidence,
            "attributes": cand["attributes"],
            "helpers": cand["helpers"],
            "decoder_calls": cand["decoder_calls"],
            "value_routing": cand["value_routing"],
            "test_scope": cand["test_scope"],
            "callers": verdict["callers"],
            "invalidation": verdict["invalidation"],
            "limit_binding": verdict["limit_binding"],
            "limit_detail": limit_detail,
            "canonical_impact": verdict["canonical_impact"],
            "schema_class": verdict["schema_class"],
            "evidence": cand["evidence"],
            "fixtures": [],
        }
        rows.append(row)
    rows.sort(key=lambda r: r["id"])

    # Source digest covers exact scanned bytes (artifact excluded by construction).
    source_entries: list[str] = []
    for rel in scan_rels:
        try:
            digest = _sha256_bytes((root / rel).read_bytes())
        except OSError:
            digest = "unreadable"
        source_entries.append(rel + ":" + digest)
    source_digest = _sha256_text("\n".join(sorted(source_entries)))
    rule_digest = _rule_digest()
    owner_map_digest = _owner_map_digest()
    profile_digest = str(profile.get("digest", ""))
    denominator_core = {
        "release_roots": sorted(default_members),
        "packages": sorted(members),
        "targets": sorted(targets),
        "features": sorted(features),
        "source_digest": source_digest,
        "rule_digest": rule_digest,
        "owner_map_digest": owner_map_digest,
        "profile_digest": profile_digest,
    }
    denominator_digest = _sha256_text(
        json.dumps(denominator_core, sort_keys=True, separators=(",", ":"))
    )

    # Finite per-child allocations aggregated from exact rows.
    reading_bytes = 0
    for ref in REQUIRED_CONTRACT_REFS:
        try:
            reading_bytes += (root / ref).stat().st_size
        except OSError:
            pass
    per_child_reading = reading_bytes // max(1, len(CHILDREN))
    allocations: list[dict] = []
    # Exact span bytes per file (merged line ranges, no double-count).
    file_line_bytes: dict[str, list[int]] = {}

    def span_bytes_for(rel: str, start: int, end: int) -> int:
        sizes = file_line_bytes.get(rel)
        if sizes is None:
            try:
                raw_lines = (root / rel).read_bytes().split(b"\n")
            except OSError:
                return 0
            sizes = [len(line) + 1 for line in raw_lines]
            file_line_bytes[rel] = sizes
        total = 0
        for lineno in range(start, end + 1):
            if 1 <= lineno <= len(sizes):
                total += sizes[lineno - 1]
        return total

    for child in CHILDREN:
        child_rows = [r for r in rows if r["repair_child"] == child["child"]]
        source_files = sorted({r["path"] for r in child_rows})
        type_names = sorted({r["type"] for r in child_rows})
        # Merge overlapping span ranges per file so shared lines count once.
        ranges_by_file: dict[str, list[list[int]]] = {}
        for r in child_rows:
            ranges_by_file.setdefault(r["path"], []).append([r["span_start"], r["span_end"]])
        source_bytes = 0
        for rel, ranges in ranges_by_file.items():
            ranges.sort()
            cur_start, cur_end = ranges[0]
            for start, end in ranges[1:]:
                if start <= cur_end + 1:
                    cur_end = max(cur_end, end)
                else:
                    source_bytes += span_bytes_for(rel, cur_start, cur_end)
                    cur_start, cur_end = start, end
            source_bytes += span_bytes_for(rel, cur_start, cur_end)
        test_bytes = 0
        test_states: list[dict] = []
        for t in sorted(child["tests"]):
            exists = (root / t).is_file()
            size = 0
            if exists:
                try:
                    size = (root / t).stat().st_size
                except OSError:
                    size = 0
            test_bytes += size
            test_states.append({"path": t, "exists": exists, "bytes": size})
        caller_files = sorted({c for r in child_rows for c in r["callers"] if c})
        read_refs = sorted(set(REQUIRED_CONTRACT_REFS) | set(caller_files))
        stu = source_bytes + test_bytes + per_child_reading
        if child["child"] == "#977" and profile.get("status") != "parsed":
            readiness = "BLOCKED"
            blocked = "missing-profile: accepted Bridge input profile not parsed"
        elif child["child"] == "#977":
            readiness = "BLOCKED"
            blocked = "pending-profile-acceptance: preparation precedes parser proof without a cycle; dispatch waits for accepted profile"
        elif stu > STU_BUDGET:
            readiness = "BLOCKED"
            blocked = "oversized-allocation: %d STU exceeds %d budget; split while preserving requirement IDs" % (stu, STU_BUDGET)
        elif not child_rows:
            readiness = "BLOCKED"
            blocked = "empty-scope: no scanned rows bound to this child on current source"
        else:
            readiness = "READY_FOR_REPAIR"
            blocked = ""
        allocations.append(
            {
                "child": child["child"],
                "family": child["family"],
                "source_files": source_files,
                "types": type_names,
                "row_count": len(child_rows),
                "source_bytes": source_bytes,
                "test_files": test_states,
                "test_bytes": test_bytes,
                "read_only_refs": read_refs,
                "requirement_ids": sorted(child["requirements"]),
                "prerequisites": sorted(child["prerequisites"]),
                "write_after": sorted(child["write_after"]),
                "preparation_before_parser": child["child"] == "#977",
                "stu_estimate": stu,
                "stu_budget": STU_BUDGET,
                "readiness": readiness,
                "blocked_reason": blocked,
            }
        )
    allocations.sort(key=lambda a: a["child"])

    unassigned = [r for r in rows if r["repair_child"] in ("", "UNASSIGNED")]
    unknown = [r for r in rows if r["disposition"] == "unknown"]
    ready_children = [a for a in allocations if a["readiness"] == "READY_FOR_REPAIR"]
    blocked_children = [a for a in allocations if a["readiness"] == "BLOCKED"]
    family_readiness = "READY" if (not unassigned and not unknown and not blocked_children) else "BLOCKED"
    family_blocked_reason = ""
    if unassigned:
        family_blocked_reason = "unowned-remainder: %d rows lack a bounded owner; a vague umbrella is not executable ownership" % len(unassigned)
    elif unknown:
        family_blocked_reason = "unknown-evidence: %d rows need explicit resolution" % len(unknown)
    elif blocked_children:
        family_blocked_reason = "blocked-children: %s" % ",".join(a["child"] for a in blocked_children)

    aggregate = _sha256_text(
        json.dumps(
            {
                "denominator_digest": denominator_digest,
                "rows": [
                    {"id": r["id"], "disposition": r["disposition"], "owner": r["owner"], "digest": r["digest"]}
                    for r in rows
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    header = {
        "schema": SCHEMA,
        "tool_version": TOOL_VERSION,
        "rule_revision": RULE_REVISION,
        "proof_ceiling": PROOF_CEILING,
        "issue": ISSUE,
        "base_sha": base_sha,
        "denominator_status": "INCOMPLETE" if ambiguous else "COMPLETE",
        "ambiguous_reason": ambiguous_reason,
        "coverage": "COMPLETE" if not ambiguous else "INCOMPLETE",
        "family_readiness": family_readiness,
        "family_blocked_reason": family_blocked_reason,
        "safety": "FINDINGS_REMAIN_BLOCKING",
        "candidate_count": len(rows),
        "classified_count": len(rows),
        "unknown_count": len(unknown),
        "unassigned_count": len(unassigned),
        "ready_children": len(ready_children),
        "blocked_children": len(blocked_children),
        "denominator_digest": denominator_digest,
        "aggregate_digest": aggregate,
    }
    return {
        "header": header,
        "denominator": denominator_core,
        "denominator_meta": {
            "release_roots": sorted(default_members),
            "packages": sorted(members),
            "targets": sorted(targets),
            "features": sorted(features),
            "rust_version": meta.get("rust_version", ""),
        },
        "counts": {
            "candidate": len(rows),
            "classified": len(rows),
            "unknown": len(unknown),
            "unassigned": len(unassigned),
        },
        "profile": profile,
        "legacy": legacy,
        "rows": rows,
        "allocations": allocations,
    }


def _escape_toml_str(value: str) -> str:
    return _toml_str(value)


def _render_toml(inventory: dict) -> bytes:
    header = inventory["header"]
    denom = inventory["denominator"]
    meta = inventory["denominator_meta"]
    counts = inventory["counts"]
    profile = inventory["profile"]
    legacy = inventory["legacy"]
    lines: list[str] = []
    lines.append("# Closed serialized-boundary inventory (issue #929).")
    lines.append("# Generated by scripts/serde_boundary_inventory.py sync; do not hand-edit.")
    lines.append("# Proof ceiling: %s." % PROOF_CEILING)
    lines.append("")
    lines.append("schema = %s" % _escape_toml_str(str(header["schema"])))
    lines.append("tool_version = %s" % _escape_toml_str(str(header["tool_version"])))
    lines.append("rule_revision = %s" % _escape_toml_str(str(header["rule_revision"])))
    lines.append("proof_ceiling = %s" % _escape_toml_str(str(header["proof_ceiling"])))
    lines.append("issue = %d" % int(header["issue"]))
    lines.append("base_sha = %s" % _escape_toml_str(str(header["base_sha"])))
    lines.append("denominator_status = %s" % _escape_toml_str(str(header["denominator_status"])))
    lines.append("ambiguous_reason = %s" % _escape_toml_str(str(header.get("ambiguous_reason", ""))))
    lines.append("coverage = %s" % _escape_toml_str(str(header["coverage"])))
    lines.append("family_readiness = %s" % _escape_toml_str(str(header["family_readiness"])))
    lines.append("family_blocked_reason = %s" % _escape_toml_str(str(header.get("family_blocked_reason", ""))))
    lines.append("safety = %s" % _escape_toml_str(str(header["safety"])))
    lines.append("candidate_count = %d" % int(header["candidate_count"]))
    lines.append("classified_count = %d" % int(header["classified_count"]))
    lines.append("unknown_count = %d" % int(header["unknown_count"]))
    lines.append("unassigned_count = %d" % int(header["unassigned_count"]))
    lines.append("ready_children = %d" % int(header["ready_children"]))
    lines.append("blocked_children = %d" % int(header["blocked_children"]))
    lines.append("denominator_digest = %s" % _escape_toml_str(str(header["denominator_digest"])))
    lines.append("aggregate_digest = %s" % _escape_toml_str(str(header["aggregate_digest"])))
    lines.append("")
    lines.append("[denominator]")
    for key in ("release_roots", "packages", "targets", "features"):
        vals = denom.get(key, [])
        lines.append("%s = [%s]" % (key, ", ".join(_escape_toml_str(v) for v in vals)))
    for key in ("source_digest", "rule_digest", "owner_map_digest", "profile_digest"):
        lines.append("%s = %s" % (key, _escape_toml_str(str(denom.get(key, "")))))
    lines.append("rust_version = %s" % _escape_toml_str(str(meta.get("rust_version", ""))))
    lines.append("")
    lines.append("[counts]")
    for key in ("candidate", "classified", "unknown", "unassigned"):
        lines.append("%s = %d" % (key, int(counts.get(key, 0))))
    lines.append("")
    lines.append("[profile]")
    lines.append("profile_id = %s" % _escape_toml_str(str(profile.get("profile_id", ""))))
    lines.append("status = %s" % _escape_toml_str(str(profile.get("status", ""))))
    lines.append("source = %s" % _escape_toml_str(str(profile.get("source", ""))))
    lines.append("source_digest = %s" % _escape_toml_str(str(profile.get("source_digest", ""))))
    lines.append("digest = %s" % _escape_toml_str(str(profile.get("digest", ""))))
    lines.append("evidence = %s" % _escape_toml_str(str(profile.get("evidence", ""))))
    for limit in profile.get("limits", []):
        lines.append("")
        lines.append("[[profile.limits]]")
        lines.append("name = %s" % _escape_toml_str(str(limit["name"])))
        lines.append("value = %d" % int(limit["value"]))
        lines.append("unit = %s" % _escape_toml_str(str(limit["unit"])))
        lines.append("encoding = %s" % _escape_toml_str(str(limit["encoding"])))
        lines.append("stage = %s" % _escape_toml_str(str(limit["stage"])))
        lines.append("source = %s" % _escape_toml_str(str(limit["source"])))
    lines.append("")
    lines.append("[legacy]")
    lines.append("status = %s" % _escape_toml_str(str(legacy.get("status", ""))))
    lines.append("source = %s" % _escape_toml_str(str(legacy.get("source", ""))))
    lines.append("source_digest = %s" % _escape_toml_str(str(legacy.get("source_digest", ""))))
    lines.append("digest = %s" % _escape_toml_str(str(legacy.get("digest", ""))))
    lines.append("evidence = %s" % _escape_toml_str(str(legacy.get("evidence", ""))))
    for alloc in inventory["allocations"]:
        lines.append("")
        lines.append("[[allocations]]")
        lines.append("child = %s" % _escape_toml_str(str(alloc["child"])))
        lines.append("family = %s" % _escape_toml_str(str(alloc["family"])))
        lines.append("row_count = %d" % int(alloc["row_count"]))
        lines.append("source_bytes = %d" % int(alloc["source_bytes"]))
        lines.append("test_bytes = %d" % int(alloc["test_bytes"]))
        lines.append("stu_estimate = %d" % int(alloc["stu_estimate"]))
        lines.append("stu_budget = %d" % int(alloc["stu_budget"]))
        lines.append("readiness = %s" % _escape_toml_str(str(alloc["readiness"])))
        lines.append("blocked_reason = %s" % _escape_toml_str(str(alloc.get("blocked_reason", ""))))
        lines.append("source_files = [%s]" % ", ".join(_escape_toml_str(v) for v in alloc["source_files"]))
        lines.append("types = [%s]" % ", ".join(_escape_toml_str(v) for v in alloc["types"]))
        lines.append("test_files = [%s]" % ", ".join(
            _escape_toml_str("%s:%s" % (t["path"], "exists" if t["exists"] else "planned")) for t in alloc["test_files"]
        ))
        lines.append("read_only_refs = [%s]" % ", ".join(_escape_toml_str(v) for v in alloc["read_only_refs"]))
        lines.append("requirement_ids = [%s]" % ", ".join(_escape_toml_str(v) for v in alloc["requirement_ids"]))
        lines.append("prerequisites = [%s]" % ", ".join(_escape_toml_str(v) for v in alloc["prerequisites"]))
        lines.append("write_after = [%s]" % ", ".join(_escape_toml_str(v) for v in alloc["write_after"]))
        lines.append("preparation_before_parser = %s" % ("true" if alloc["preparation_before_parser"] else "false"))
    for row in inventory["rows"]:
        lines.append("")
        lines.append("[[candidates]]")
        lines.append("id = %s" % _escape_toml_str(str(row["id"])))
        lines.append("package = %s" % _escape_toml_str(str(row["package"])))
        lines.append("path = %s" % _escape_toml_str(str(row["path"])))
        lines.append("type = %s" % _escape_toml_str(str(row["type"])))
        lines.append("function = %s" % _escape_toml_str(str(row["function"])))
        lines.append("kind = %s" % _escape_toml_str(str(row["kind"])))
        lines.append("span_start = %d" % int(row["span_start"]))
        lines.append("span_end = %d" % int(row["span_end"]))
        lines.append("span_digest = %s" % _escape_toml_str(str(row["span_digest"])))
        lines.append("digest = %s" % _escape_toml_str(str(row["digest"])))
        lines.append("file_digest = %s" % _escape_toml_str(str(row.get("file_digest", ""))))
        lines.append("owner = %s" % _escape_toml_str(str(row["owner"])))
        lines.append("repair_child = %s" % _escape_toml_str(str(row["repair_child"])))
        lines.append("repair_readiness = %s" % _escape_toml_str(str(row["repair_readiness"])))
        lines.append("blocked_reason = %s" % _escape_toml_str(str(row.get("blocked_reason", ""))))
        lines.append("safety = %s" % _escape_toml_str(str(row["safety"])))
        lines.append("disposition = %s" % _escape_toml_str(str(row["disposition"])))
        lines.append("build_class = %s" % _escape_toml_str(str(row["build_class"])))
        lines.append("release_class = %s" % _escape_toml_str(str(row["release_class"])))
        lines.append("admission = %s" % _escape_toml_str(str(row["admission"])))
        lines.append("boundary_evidence = %s" % _escape_toml_str(str(row["boundary_evidence"])))
        lines.append("schema_class = %s" % _escape_toml_str(str(row["schema_class"])))
        lines.append("canonical_impact = %s" % _escape_toml_str(str(row["canonical_impact"])))
        lines.append("limit_binding = %s" % _escape_toml_str(str(row["limit_binding"])))
        lines.append("invalidation = %s" % _escape_toml_str(str(row["invalidation"])))
        lines.append("evidence = %s" % _escape_toml_str(str(row["evidence"])))
        attrs = row["attributes"]
        lines.append("deny_unknown_fields = %s" % ("true" if attrs.get("deny_unknown_fields") else "false"))
        lines.append("tag = %s" % _escape_toml_str(str(attrs.get("tag", ""))))
        lines.append("untagged = %s" % ("true" if attrs.get("untagged") else "false"))
        lines.append("flatten = %s" % ("true" if attrs.get("flatten") else "false"))
        lines.append("has_alias = %s" % ("true" if attrs.get("alias") else "false"))
        lines.append("has_default = %s" % ("true" if attrs.get("default") else "false"))
        lines.append("remote = %s" % _escape_toml_str(str(attrs.get("remote", ""))))
        lines.append("with_helper = %s" % _escape_toml_str(str(attrs.get("with", ""))))
        lines.append("deserialize_with = %s" % ("true" if attrs.get("deserialize_with") else "false"))
        lines.append("value_routing = %s" % ("true" if row["value_routing"] else "false"))
        lines.append("helpers = [%s]" % ", ".join(_escape_toml_str(v) for v in row["helpers"]))
        lines.append("callers = [%s]" % ", ".join(_escape_toml_str(v) for v in row["callers"]))
        lines.append("fixtures = [%s]" % ", ".join(_escape_toml_str(v) for v in row["fixtures"]))
        lines.append("decoder_calls = %s" % _escape_toml_str(json.dumps(row["decoder_calls"], sort_keys=True, separators=(",", ":"))))
    lines.append("")
    return ("\n".join(lines)).encode("utf-8")


def artifact_path(root: Path) -> Path:
    return root / OWNED_TOML_REL


def sync_inventory(root: Path) -> tuple[dict, bytes]:
    root = root.resolve()
    inventory = build_inventory(root)
    payload = _render_toml(inventory)
    target = artifact_path(root)
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="wb", dir=str(target.parent), prefix=".shipped_serde_boundaries-", suffix=".tmp", delete=False
    ) as handle:
        handle.write(payload)
        tmp_name = handle.name
    os.replace(tmp_name, target)
    return inventory, payload


def load_artifact_toml(root: Path) -> dict:
    target = artifact_path(root)
    if not target.is_file():
        raise InventoryError("ARTIFACT_MISSING", "missing artifact: %s:1" % OWNED_TOML_REL)
    try:
        return tomllib.loads(target.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise InventoryError("ARTIFACT_MALFORMED", "malformed artifact %s:1: %s" % (OWNED_TOML_REL, exc)) from exc


def check_write_serialization(allocations: list[dict]) -> None:
    """Overlapping mutable writes require an exact serialization edge.

    Shared *read-only* references are never collisions. A source file claimed
    as mutable scope by two children passes only when at least one of the
    sharing children names another sharing child in ``write_after``.
    """
    owners: dict[str, list[str]] = {}
    for alloc in allocations:
        child = str(alloc.get("child", "?"))
        for src in alloc.get("source_files", []) or []:
            owners.setdefault(str(src), []).append(child)
    for src, children in sorted(owners.items()):
        if len(children) < 2:
            continue
        sharing = set(children)
        ordered = any(
            other in sharing
            for alloc in allocations
            if str(alloc.get("child")) in sharing
            for other in (alloc.get("write_after", []) or [])
        )
        if not ordered:
            raise InventoryError(
                "WRITE_COLLISION",
                "overlapping mutable writes to %s by %s without an exact write_after edge"
                % (src, sorted(sharing)),
            )


def _stored_rows(doc: dict) -> list[dict]:
    rows = doc.get("candidates", [])
    if not isinstance(rows, list):
        raise InventoryError("ARTIFACT_MALFORMED", "malformed artifact: [[candidates]] is not a list")
    return rows


def validate_against_artifact(root: Path, fresh: dict, doc: dict) -> list[dict]:
    """Compare fresh compute against the stored artifact; raise on any drift."""
    if doc.get("schema") != SCHEMA:
        raise InventoryError("STALE_RULE", "artifact schema %r != %r" % (doc.get("schema"), SCHEMA))
    if doc.get("rule_revision") != RULE_REVISION:
        raise InventoryError("STALE_RULE", "artifact rule %r != %r" % (doc.get("rule_revision"), RULE_REVISION))
    for key in ("source_digest", "rule_digest", "owner_map_digest", "profile_digest"):
        stored = (doc.get("denominator", {}) or {}).get(key, "")
        current = fresh["denominator"].get(key, "")
        if stored != current:
            raise InventoryError(
                "STALE_INPUT",
                "stale %s: stored %.16s != current %.16s; relevant input change invalidates evidence" % (key, stored, current),
            )
    if doc.get("denominator_digest") != fresh["header"]["denominator_digest"]:
        raise InventoryError("STALE_INPUT", "stale denominator_digest; release/source/rule/owner/profile change invalidates evidence")
    stored_rows = _stored_rows(doc)
    seen: set[str] = set()
    for row in stored_rows:
        rid = row.get("id", "")
        if not rid:
            raise InventoryError("INCOMPLETE_ROW", "stored row without id")
        if rid in seen:
            raise InventoryError("DUPLICATE_ROW", "duplicate stored row %s" % rid)
        seen.add(rid)
        if "*" in rid or "?" in rid or "[" in rid:
            raise InventoryError("BROAD_EXCEPTION", "broad exception pattern stored as row: %s" % rid)
        if row.get("disposition", "") not in KNOWN_DISPOSITIONS:
            raise InventoryError("UNKNOWN_DISPOSITION", "stored row %s has unknown disposition %r" % (rid, row.get("disposition")))
        if row.get("disposition") == "exact-internal" and not row.get("callers"):
            raise InventoryError("INCOMPLETE_ROW", "internal row %s lacks exact caller evidence" % rid)
    fresh_by_id = {r["id"]: r for r in fresh["rows"]}
    stored_ids = set(seen)
    fresh_ids = set(fresh_by_id)
    if stored_ids - fresh_ids:
        missing = sorted(stored_ids - fresh_ids)[:5]
        raise InventoryError("MISSING_ROWS", "baseline rows vanished in reconciliation: %s" % missing)
    if fresh_ids - stored_ids:
        extra = sorted(fresh_ids - stored_ids)[:5]
        raise InventoryError("EXTRA_ROWS", "unaccounted candidates missing from artifact: %s" % extra)
    for rid in sorted(stored_ids):
        stored = next(r for r in stored_rows if r.get("id") == rid)
        current = fresh_by_id[rid]
        if stored.get("digest", "") != current["digest"] or stored.get("disposition", "") != current["disposition"]:
            raise InventoryError(
                "HAND_EDIT_OR_DRIFT",
                "row %s differs (stored digest %.12s disposition %s vs current %.12s %s); hand edits are rejected" % (
                    rid, stored.get("digest", ""), stored.get("disposition", ""),
                    current["digest"], current["disposition"],
                ),
            )
    if doc.get("aggregate_digest") != fresh["header"]["aggregate_digest"]:
        raise InventoryError("HAND_EDIT_OR_DRIFT", "aggregate digest mismatch; artifact was hand-edited or inputs drifted")
    if fresh["header"]["denominator_status"] == "INCOMPLETE":
        raise InventoryError("AMBIGUOUS_RELEASE", fresh["header"].get("ambiguous_reason", "ambiguous release authority"))
    stored_allocs = doc.get("allocations", []) or []
    for alloc in stored_allocs:
        for key in ("source_files", "test_files", "read_only_refs"):
            for entry in (alloc.get(key, []) or []):
                text = entry if isinstance(entry, str) else entry.get("path", "")
                if any(mark in text for mark in ("*", "?", "[")):
                    raise InventoryError(
                        "BROAD_EXCEPTION",
                        "allocation %s lists a glob instead of exact files: %s" % (alloc.get("child"), text),
                    )
    check_write_serialization(stored_allocs)
    return [
        {"candidate_id": r["id"], "id": r["id"], "disposition": r["disposition"],
         "owner": r["owner"], "digest": r["digest"]}
        for r in fresh["rows"]
    ]


# ---------------------------------------------------------------------------
# Public #929 generator/rules API consumed by the #710 closure oracle.
# ---------------------------------------------------------------------------


def load_artifact(root: Path | str) -> dict:
    """Load stored rows through the artifact (oracle entry point)."""
    root_path = Path(root).resolve()
    doc = load_artifact_toml(root_path)
    rows = _stored_rows(doc)
    return {
        "rows": [
            {"candidate_id": r.get("id", ""), "id": r.get("id", ""),
             "disposition": r.get("disposition", ""), "owner": r.get("owner", ""),
             "digest": r.get("digest", "")}
            for r in rows
        ],
        "header": {k: doc.get(k) for k in ("schema", "aggregate_digest", "denominator_digest", "candidate_count")},
        "digest": str(doc.get("aggregate_digest", "")),
    }


def iter_candidate_rows(root: Path | str) -> list[dict]:
    """Rescan current source and return fresh rows (oracle entry point)."""
    root_path = Path(root).resolve()
    fresh = build_inventory(root_path)
    return [
        {"candidate_id": r["id"], "id": r["id"], "disposition": r["disposition"],
         "owner": r["owner"], "digest": r["digest"]}
        for r in fresh["rows"]
    ]


def check(root: Path | str) -> dict:
    """Read-only validation returning rows (oracle entry point).

    Raises InventoryError on malformed/stale/missing/extra/duplicate or
    incomplete accounting; never writes.
    """
    root_path = Path(root).resolve()
    doc = load_artifact_toml(root_path)
    fresh = build_inventory(root_path)
    rows = validate_against_artifact(root_path, fresh, doc)
    return {"rows": rows, "digest": fresh["header"]["aggregate_digest"], "header": fresh["header"]}


def check_cli(root: Path) -> dict:
    doc = load_artifact_toml(root)
    fresh = build_inventory(root)
    rows = validate_against_artifact(root, fresh, doc)
    return {"passed": True, "rows": rows, "header": fresh["header"]}


# ---------------------------------------------------------------------------
# Focused self-test (proves the tool runs; the 24-case matrix lives in tests).
# ---------------------------------------------------------------------------


def run_self_test() -> dict:
    here = Path(__file__).resolve()
    repo = here.parents[1]
    fixture_dir = repo / "scripts" / "testdata" / "serde-boundary-inventory"
    required = ["derive_basic.rs", "comments_strings.rs", "unsupported.rs", "profile_bridge.json"]
    for name in required:
        if not (fixture_dir / name).is_file():
            raise AssertionError("self-test fixture missing: %s" % name)
    masked = _mask_rust('let s = "x"; // #[derive(Deserialize)]\nstruct A;')
    if "Deserialize" in masked and "derive" in masked:
        raise AssertionError("self-test mask is inert")
    try:
        _mask_rust('/* unclosed')
    except InventoryError as exc:
        if exc.code != "MALFORMED_RUST_SOURCE":
            raise
    else:
        raise AssertionError("self-test mask accepts unclosed input")
    first = build_inventory(repo, [p.as_posix() for p in
                                   sorted((fixture_dir).rglob("*.rs")) if p.is_file()])
    second = build_inventory(repo, [p.as_posix() for p in
                                    sorted((fixture_dir).rglob("*.rs"), reverse=True) if p.is_file()])
    if not first["rows"]:
        raise AssertionError("self-test fixture scan is empty")
    if [r["id"] for r in first["rows"]] != [r["id"] for r in second["rows"]]:
        raise AssertionError("self-test traversal order leaks into rows")
    if _render_toml(first) != _render_toml(second):
        raise AssertionError("self-test rendering is not deterministic")
    by_path: dict[str, list[dict]] = {}
    for row in first["rows"]:
        by_path.setdefault(row["path"].rsplit("/", 1)[-1], []).append(row)
    basic = by_path.get("derive_basic.rs", [])
    if len(basic) != 1 or basic[0]["type"] != "BasicRecord":
        raise AssertionError("self-test basic fixture mismatch: %r" % [r["type"] for r in basic])
    noisy = by_path.get("comments_strings.rs", [])
    if len(noisy) != 1 or noisy[0]["type"] != "RealAfterNoise":
        raise AssertionError("self-test comment/string mask failed: %r" % [r["type"] for r in noisy])
    unsupported = by_path.get("unsupported.rs", [])
    if not any(r["disposition"] == "unknown" for r in unsupported):
        raise AssertionError("self-test unsupported macro is not explicit unknown")
    if _sha256_text("a") == _sha256_text("b"):
        raise AssertionError("self-test digest is inert")
    print(
        "SERDE_BOUNDARY_INVENTORY_SELF_TEST: PASS "
        "(fixture rows %d; digest %s)"
        % (len(first["rows"]), first["header"]["aggregate_digest"][:16])
    )
    return {"passed": True, "rows": len(first["rows"]), "digest": first["header"]["aggregate_digest"]}


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="F-DENY serde-boundary inventory (#929).")
    parser.add_argument("--self-test", action="store_true", help="Run the focused self-test.")
    sub = parser.add_subparsers(dest="command")
    for name in ("sync", "check"):
        cmd = sub.add_parser(name, help="%s the owned inventory artifact." % name)
        cmd.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    return parser.parse_args(sys.argv[1:] if argv is None else argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        run_self_test()
        return 0
    if args.command == "sync":
        root = args.root.resolve()
        inventory, _payload = sync_inventory(root)
        print(
            "SERDE_BOUNDARY_INVENTORY: SYNC rows=%d unknown=%d unassigned=%d family=%s digest=%s"
            % (
                inventory["header"]["candidate_count"],
                inventory["header"]["unknown_count"],
                inventory["header"]["unassigned_count"],
                inventory["header"]["family_readiness"],
                inventory["header"]["aggregate_digest"][:16],
            )
        )
        return 0
    if args.command == "check":
        root = args.root.resolve()
        try:
            result = check_cli(root)
        except InventoryError as exc:
            print("SERDE_BOUNDARY_INVENTORY: FAIL [%s] %s" % (exc.code, exc.detail), file=sys.stderr)
            return 1
        header = result["header"]
        print(
            "SERDE_BOUNDARY_INVENTORY: PASS rows=%d unknown=%d unassigned=%d family=%s digest=%s"
            % (
                header["candidate_count"],
                header["unknown_count"],
                header["unassigned_count"],
                header["family_readiness"],
                header["aggregate_digest"][:16],
            )
        )
        return 0
    print("SERDE_BOUNDARY_INVENTORY: expected sync, check, or --self-test", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
