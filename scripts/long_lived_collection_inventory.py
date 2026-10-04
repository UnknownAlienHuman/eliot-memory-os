#!/usr/bin/env python3
"""Deterministic source-bound inventory of mutable collections in long-lived owners.

Issue: https://github.com/UnknownAlienHuman/eliot-memory-os/issues/885

The inventory is static-source evidence, not authority. It never builds or runs
repository code, never mutates Rust/Cargo sources, never touches the network or
ambient clock, never spawns subprocesses, and never repairs, bounds, clears, or
repolicies any collection. ``sync`` atomically writes exactly one owned TOML
artifact; ``check`` is read-only.

Proof ceiling: STATIC_SOURCE_CLASSIFICATION_ONLY. A complete honest inventory
with findings stays explicitly findings-bearing; it must never be read as a
product bounded/leak-free claim. Unresolved rows remain launch/release blockers
until the coordinator links each to a concrete bounded implementation issue.
The scanner proposes rows and successor scopes only; it creates no GitHub tasks.

Closed classification vocabulary (exactly one per candidate row):
  request-local/stack-bounded | immutable DTO | test-only |
  long-lived hard-bounded | versioned-policy-bounded | lifecycle-removal |
  TTL/lease with scheduled bounded cleanup | external compaction |
  append-only durable segmented retention | unbounded long-lived candidate |
  ownership/lifetime unknown | unrelated false positive

The vocabulary is closed and stable, but RULE_REVISION 885.2 can no longer
produce `long-lived hard-bounded`, `versioned-policy-bounded`,
`lifecycle-removal` or `immutable DTO`: no discovery-only signal establishes a
bound, so those four are reserved vocabulary values. `unrelated false
positive` is the fail-closed default; the three scanned candidate kinds
(static/field/local) are each claimed by an earlier rule, so it is a defensive
default rather than a reachable outcome.

Classification rules (RULE_REVISION 885.2, first match wins, evidence kept):
  1. test-only signals (tests/ path, test file name, cfg(test)) -> test-only
  2. function-local `let` binding (grown or not) -> request-local
  3. TTL/lease/expiry signal + receiver-attributed scheduled retention (never a
     whole-collection `clear()`) -> TTL/lease
  4. append/segment/rotation signal + receiver-attributed production
     retention/eviction -> append-only retention
  5. receiver-attributed production compaction/eviction callsite outside the
     declaring file -> external compaction
  6. preallocation (`with_capacity`), policy-like names, and mere
     removal-method presence are DISCOVERY EVIDENCE ONLY: none of them, alone
     or combined with a name signal, may yield `hard`/`configured` bound status
     or a `none-required` repair. `Vec::with_capacity(n)` PREALLOCATES and is
     not a maximum length; an unscheduled `cleanup` that only calls `clear()`
     proves no scheduling and no cardinality limit.
  7. any long-lived growth not already claimed by rules 3-5 -> unbounded
     long-lived candidate, counted in unresolved_count
  8. collection-typed field/static with no receiver-attributed growth ->
     ownership/lifetime unknown, counted in unresolved_count
  9. otherwise -> unrelated false positive (with evidence, never silent)

Evidence attribution: growth, removal, and preallocation evidence is credited
only to `ident.method(` where `ident` is the actual receiver (a bare identifier
or `self.ident`). A field reached through an unresolved expression
(`other.items.clear()`), a coincidental same-line method call, a cross-owner
signal, and test-only or cfg-gated removal never establish a bound: the detail
is retained in the row evidence and the row stays explicitly unresolved.
Unresolved rows stay counted in `unresolved_count`, keep `safety_disposition =
FINDINGS_REMAIN_BLOCKING`, and hand off through `repair_owner/repair_issue =
UNRESOLVED`; scan coverage completeness is independent of findings and may be
COMPLETE while findings remain blocking.

Test-only removal proves no production bound; cfg-gated removal has unknown
production reachability and stays unknown (matrix-14/15). Unbounded/unknown
rows carry their cardinality driver plus explicit untrusted-key-influence
status (matrix-19). Absent scan inputs are excluded with source evidence and
explicit incomplete coverage (matrix-25).

Usage:
  python scripts/long_lived_collection_inventory.py sync --root .
  python scripts/long_lived_collection_inventory.py check --root .
  python scripts/long_lived_collection_inventory.py --self-test
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import tomllib
from pathlib import Path

SCHEMA = "eliot.long-lived-collection-inventory.v1"
RULE_REVISION = "885.2"
TOOL_VERSION = "0.1.0"
OWNED_TOML = Path(".github/work-units/long-lived-collection-inventory.toml")
PROOF_CEILING = "STATIC_SOURCE_CLASSIFICATION_ONLY"

DEFAULT_SCAN = (
    "crates/governor/eliot-problem/src/lib.rs",
    "crates/governor/eliot-skill/src/lib.rs",
    "crates/governor/eliot-canonical/src/lib.rs",
    "crates/agent/eliot-agent-coordinator/src/model_control.rs",
)

CLASSIFICATIONS = (
    "request-local/stack-bounded",
    "immutable DTO",
    "test-only",
    "long-lived hard-bounded",
    "versioned-policy-bounded",
    "lifecycle-removal",
    "TTL/lease with scheduled bounded cleanup",
    "external compaction",
    "append-only durable segmented retention",
    "unbounded long-lived candidate",
    "ownership/lifetime unknown",
    "unrelated false positive",
)

UNRESOLVED_CLASSIFICATIONS = frozenset(
    {
        "unbounded long-lived candidate",
        "ownership/lifetime unknown",
    }
)

BOUND_STATUSES = ("hard", "configured", "empirical", "none", "unknown")


class InventoryError(RuntimeError):
    """Stable fail-closed error carrying a machine-readable reason code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


COLLECTION_CORE = (
    "Vec",
    "HashMap",
    "HashSet",
    "BTreeMap",
    "BTreeSet",
    "VecDeque",
    "BinaryHeap",
    "IndexMap",
    "IndexSet",
    "Slab",
)

_COLLECTION_ALTERNATION = "|".join(COLLECTION_CORE)
_TYPE_RE = re.compile(r"\b(?:" + _COLLECTION_ALTERNATION + r")\s*(?:<|:)")
_STRUCT_RE = re.compile(r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^;{}]*>)?\s*\{")
_FIELD_NAME_RE = re.compile(
    r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*"
)
_LET_RE = re.compile(
    r"\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([^;=]+)="
)
_STATIC_RE = re.compile(
    r"^\s*(?:pub\s+)?static\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([^;=]+)=",
    re.MULTILINE,
)
_FN_RE = re.compile(r"\bfn\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:<[^;{}]*>)?\s*\(")
_IMPL_DROP_RE = re.compile(r"\bimpl\s+Drop\s+for\s+([A-Za-z_][A-Za-z0-9_]*)")
_DERIVE_SERDE_RE = re.compile(r"#\s*\[\s*derive\s*\([^]]*(?:Serialize|Deserialize)")
_TEST_ATTR_RE = re.compile(r"#\s*\[\s*(?:cfg\s*\(\s*test\s*\)|test)\s*\]")
_CFG_RE = re.compile(r"#\s*\[\s*cfg\s*\(")

GROWTH_METHODS = (
    "push",
    "push_back",
    "push_front",
    "insert",
    "extend",
    "entry",
    "or_insert",
    "append",
    "enqueue",
    "intern",
    "register",
)
REMOVAL_METHODS = (
    "remove",
    "pop",
    "pop_back",
    "pop_front",
    "retain",
    "clear",
    "drain",
    "evict",
    "expire",
    "compact",
    "rotate",
    "truncate",
)
# Removal methods that drop or discard entries one by one (or drop a suffix)
# instead of discarding the whole collection. `clear`/`drain` return a value
# and leave the collection empty; treating their mere presence as boundedness
# is exactly the audit-5885377544 defect, so a cleanup that only clears a
# collection establishes no cardinality limit.
RETAINING_REMOVAL_METHODS = tuple(
    method for method in REMOVAL_METHODS if method not in ("clear", "drain")
)

_CHAR_RE = re.compile(
    r"^(?:b)?'(?:\\x[0-9a-fA-F]{2}|\\u\{[0-9a-fA-F_]{1,6}\}|\\[\\'\"0nrt]|[^\\'\n\r])'"
)
_LIFETIME_RE = re.compile(r"^'[a-zA-Z_][a-zA-Z0-9_]*")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _mask_rust(text: str) -> str:
    """Replace comments and literal bodies with spaces, preserving line layout."""
    chars = list(text)
    length = len(chars)
    index = 0

    def blank(start: int, end: int) -> None:
        for pos in range(start, end):
            if chars[pos] not in "\r\n":
                chars[pos] = " "

    while index < length:
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            if end < 0:
                end = length
            blank(index, end)
            index = end
            continue
        if text.startswith("/*", index):
            depth = 1
            cursor = index + 2
            while cursor < length and depth:
                if text.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif text.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            if depth:
                raise InventoryError("MALFORMED_RUST_SOURCE", "unterminated block comment")
            blank(index, cursor)
            index = cursor
            continue
        raw_match = re.match(r"(?:b|c)?r(#{0,255})\"", text[index:])
        if raw_match:
            hashes = raw_match.group(1)
            body_start = index + raw_match.end()
            terminator = '"' + hashes
            end = text.find(terminator, body_start)
            if end < 0:
                raise InventoryError("MALFORMED_RUST_SOURCE", "unterminated raw string")
            end += len(terminator)
            blank(index, end)
            index = end
            continue
        if text.startswith("'", index) or text.startswith("b'", index):
            char_match = _CHAR_RE.match(text[index:])
            if char_match:
                blank(index, index + char_match.end())
                index += char_match.end()
                continue
            lifetime_match = _LIFETIME_RE.match(text[index:])
            if lifetime_match:
                index += lifetime_match.end()
                continue
        prefix = (
            1
            if text[index : index + 1] in {"b", "c"} and text[index + 1 : index + 2] == '"'
            else 0
        )
        quote_pos = index + prefix
        if quote_pos < length and text[quote_pos] == '"':
            cursor = quote_pos + 1
            escaped = False
            while cursor < length:
                current = text[cursor]
                cursor += 1
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == '"':
                    break
            else:
                raise InventoryError("MALFORMED_RUST_SOURCE", "unterminated string literal")
            blank(index, cursor)
            index = cursor
            continue
        index += 1
    return "".join(chars)


def _root(path: Path) -> Path:
    try:
        return path.resolve(strict=True)
    except OSError as exc:
        raise InventoryError("REPOSITORY_UNAVAILABLE", f"root is unavailable: {path}") from exc


def _inside(root: Path, path: Path) -> Path:
    try:
        resolved = path.resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise InventoryError("PATH_ESCAPE", f"path is outside scan root: {path}") from exc
    return resolved


def _read_source(root: Path, path: Path) -> bytes:
    resolved = _inside(root, path)
    if resolved.is_symlink() or not resolved.is_file():
        raise InventoryError(
            "SOURCE_NOT_REGULAR_FILE", f"expected a regular non-symlink file: {path}"
        )
    try:
        return resolved.read_bytes()
    except OSError as exc:
        raise InventoryError("SOURCE_UNREADABLE", f"cannot read source: {path}") from exc


def _package_of(root: Path, path: Path) -> str:
    """Nearest Cargo package name above the file, else the scan-relative parent."""
    current = _inside(root, path).parent
    while True:
        manifest = current / "Cargo.toml"
        if manifest.is_file() and not manifest.is_symlink():
            try:
                text = manifest.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                break
            match = re.search(r'^\s*name\s*=\s*"([^"]+)"', text, re.MULTILINE)
            if match:
                return match.group(1)
            break
        if current == root:
            break
        parent = current.parent
        try:
            parent.relative_to(root)
        except ValueError:
            break
        current = parent
    try:
        relative_parent = _inside(root, path).parent.relative_to(root).as_posix()
    except InventoryError:
        return "unknown"
    return relative_parent if relative_parent not in ("", ".") else "unknown"


def _split_field_type(rest: str) -> str | None:
    """Depth-aware field-type split: stops at a top-level ',' ';' or '='."""
    depth = 0
    for pos, char in enumerate(rest):
        if char in "<([":
            depth += 1
        elif char in ">)]":
            depth = depth - 1 if depth else 0
        elif char in ",;=" and depth == 0:
            return rest[:pos].strip()
    tail = rest.strip()
    return tail or None


def _attr_regions(masked: str, attr_re: re.Pattern[str]) -> list[tuple[int, int]]:
    """Line ranges owned by attribute-gated items (brace-matched).

    A bare declaration (semicolon before any brace) owns no inline region:
    its code lives in another file. Items outside these regions must never
    inherit the attribute's label from a distant gated module in the same
    file.
    """
    regions: list[tuple[int, int]] = []
    for attr in attr_re.finditer(masked):
        rest = masked[attr.end() :]
        brace = rest.find("{")
        semi = rest.find(";")
        if brace < 0 or (0 <= semi < brace):
            continue
        depth = 0
        cursor = attr.end() + brace
        end = -1
        while cursor < len(masked):
            if masked[cursor] == "{":
                depth += 1
            elif masked[cursor] == "}":
                depth -= 1
                if depth == 0:
                    end = cursor
                    break
            cursor += 1
        if end < 0:
            continue
        regions.append(
            (
                masked.count("\n", 0, attr.start()) + 1,
                masked.count("\n", 0, end) + 1,
            )
        )
    return regions


def _test_regions(masked: str) -> list[tuple[int, int]]:
    """Line ranges owned by #[cfg(test)]/#[test] items (brace-matched).

    A bare `mod tests;` declaration (semicolon before any brace) owns no
    inline region: its code lives in another file. Production items outside
    these regions must never inherit a test-only label from a distant test
    module in the same file.
    """
    return _attr_regions(masked, _TEST_ATTR_RE)


def _cfg_regions(masked: str) -> list[tuple[int, int]]:
    """Line ranges owned by #[cfg(...)]-gated items (brace-matched).

    cfg-gated code may be compiled out of the scanned target/feature set, so
    removal observed only there has unknown production reachability: it stays
    inventoried but proves no bound and the row stays unknown (matrix-15).
    Overlap with test regions resolves to test-only in row evidence.
    """
    return _attr_regions(masked, _CFG_RE)


def _region_lines(regions: list[tuple[int, int]]) -> frozenset[int]:
    """Expand inclusive (start, end) line regions into a line set."""
    lines: set[int] = set()
    for start, end in regions:
        lines.update(range(start, end + 1))
    return frozenset(lines)


def _toml_string(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return '"' + "".join(
        ch if 0x20 <= ord(ch) != 0x7F else f"\\u{ord(ch):04X}" for ch in escaped
    ) + '"'


def _toml_str_list(values: list[str]) -> str:
    return "[" + ", ".join(_toml_string(item) for item in values) + "]"


def _receiver_re(ident: str, methods: tuple[str, ...]) -> re.Pattern[str]:
    """Build the `ident.method(` receiver regex for the given methods.

    Longer names are tried first so `pop_back` never matches as `pop`. `ident`
    must be the call receiver: an optional explicit `self.` prefix is allowed
    (so `self.items.push(` and `self . items . clear()` match), the character
    before the whole match may not be an identifier character or `.`, and the
    identifier must be immediately followed by `.` and one of the methods. That
    admits `items.push(...)` and `self.items.push(...)` while refusing
    `other.items.push(...)`, `cache.items.clear()` and `xitems.clear()`,
    because the engine can only start the match at `self` or at a bare
    identifier, never mid-path.
    """
    ordered = sorted(methods, key=len, reverse=True)
    return re.compile(
        r"(?<![A-Za-z0-9_.])"
        r"(?:self\s*\.\s*)?"
        + re.escape(ident)
        + r"\s*\.\s*("
        + "|".join(re.escape(method) for method in ordered)
        + r")\s*(?:::|<|\()"
    )


def _unique_in_order(found: list[str]) -> list[str]:
    """Preserve first-seen order, drop exact duplicates."""
    seen: set[str] = set()
    ordered: list[str] = []
    for item in found:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def _callsites_for(
    masked_lines: list[str], ident: str, methods: tuple[str, ...], rel: str
) -> list[str]:
    """Associate `ident.method(` callsites where `ident` is the call receiver.

    A callsite counts only when the identifier is the direct receiver of the
    method call (``ident.method(``, allowing whitespace and `Vec::method(` /
    `Vec<method>(` generic paths), not when the identifier and a
    growth/removal method merely share a line. Same-line coincidence,
    other-owner receivers (`other.items.clear()`), and unattributed file-wide
    signals are not attributed here; downstream classification keeps such rows
    explicitly unresolved while retaining the observed details in row evidence
    and owner-level removal inventory.
    """
    call_re = _receiver_re(ident, methods)
    found: list[str] = []
    for lineno, line in enumerate(masked_lines, start=1):
        # Same-line coincidence without an ident.receiver match is ignored here.
        for match in call_re.finditer(line):
            found.append(f"{rel}:{lineno}:{match.group(1)}")
    return _unique_in_order(found)


def _field_preallocations(
    masked_lines: list[str], field_name: str, struct_name: str, rel: str
) -> list[str]:
    """Attribute `Vec::with_capacity(n)` to the field/owner it initializes.

    Preallocation is recorded as *owner-level* discovery evidence: the call is
    credited when the field identifier and `with_capacity` share a line
    (optionally through an `=` initializer or a `Struct { field: .. }` literal)
    and no other owner/field identifier appears as the nearest preceding
    receiver. That keeps `Vec::with_capacity(4)` inside an unrelated struct out
    of this row while never claiming the number is a maximum length, because
    attribution can establish initialization, not boundedness.
    """
    call_re = re.compile(
        r"\b(?:" + re.escape("Vec") + r"|" + re.escape(field_name) + r")"
        r"\s*(?:::|<|\.)with_capacity\s*\(\s*(\d+)\s*\)"
    )
    ident_re = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z_][A-Za-z0-9_]*(?![A-Za-z0-9_])")
    struct_token = str(struct_name)
    tokens = set(ident_re.findall(field_name + " " + struct_token))
    found: list[str] = []
    for lineno, line in enumerate(masked_lines, start=1):
        for match in call_re.finditer(line):
            prefix = line[: match.start()]
            receivers = ident_re.findall(prefix)
            nearest = receivers[-1] if receivers else ""
            # `Vec::with_capacity(4)` inside `impl Holder {` belongs to the
            # enclosing owner; `Other::new(..)` names a different owner.
            owner_ok = not nearest or nearest in tokens or (
                nearest.startswith("impl") and struct_token in tokens
            )
            if owner_ok:
                found.append(f"{rel}:{lineno}:with_capacity({match.group(1)})")
    return _unique_in_order(found)


def _preallocation_note(preallocations: list[str]) -> str:
    """Discovery-only disclosure for observed preallocation."""
    if not preallocations:
        return ""
    return (
        f"; observed preallocation {preallocations} attributed to this field/owner"
        " slice is discovery evidence only: with_capacity(n) preallocates and is"
        " not a maximum length"
    )


def _partition_removal(
    masked_lines: list[str],
    ident: str,
    rel: str,
    test_lines: frozenset[int],
    cfg_lines: frozenset[int],
) -> tuple[list[str], list[str], list[str]]:
    """Split removal callsites into production / test-only / cfg-unknown.

    Line membership decides the bucket, so no callsite string is re-parsed.
    Every callsite stays inventoried in the row, but only production
    callsites may prove a bound: test-only removal proves no production
    bound (matrix-14) and cfg-gated removal has unknown production
    reachability (matrix-15). Test membership wins on overlap.
    """
    numbered = list(enumerate(masked_lines, start=1))
    prod_lines = [line if number not in test_lines and number not in cfg_lines else "" for number, line in numbered]
    test_only_lines = [line if number in test_lines else "" for number, line in numbered]
    cfg_only_lines = [
        line if number in cfg_lines and number not in test_lines else ""
        for number, line in numbered
    ]
    return (
        _callsites_for(prod_lines, ident, REMOVAL_METHODS, rel),
        _callsites_for(test_only_lines, ident, REMOVAL_METHODS, rel),
        _callsites_for(cfg_only_lines, ident, REMOVAL_METHODS, rel),
    )


def _excluded_removal_note(test_only: list[str], cfg_unknown: list[str]) -> str:
    """Disclosure for inventoried removal that proves no production bound."""
    parts: list[str] = []
    if test_only:
        parts.append(f"test-only removal {test_only} proves no production bound")
    if cfg_unknown:
        parts.append(
            f"cfg-gated removal {cfg_unknown} has unknown production reachability"
            " and stays unknown"
        )
    return ("; " + "; ".join(parts)) if parts else ""


def _scan_file(root: Path, rel: str) -> tuple[dict[str, object], list[dict[str, object]]]:
    """Scan one Rust file; return (file_record, candidate_dicts)."""
    raw = _read_source(root, root / rel)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InventoryError("INVALID_RUST_ENCODING", f"source is not UTF-8: {rel}") from exc
    try:
        masked = _mask_rust(text)
    except InventoryError as exc:
        raise InventoryError(exc.code, f"{rel}: {exc.detail}") from exc
    lines = text.splitlines()
    masked_lines = masked.splitlines()
    file_sha = _sha256(raw)
    package = _package_of(root, root / rel)

    lowered_path = rel.lower()
    # Fixtures under scripts/testdata are controlled scan inputs, not product
    # test code; only genuine test signals classify test-only. Path signals
    # apply file-wide; attribute signals apply only inside the item region so
    # production structs never inherit test-only from a distant test module.
    path_test_signal = "/tests/" in rel or lowered_path.endswith("_test.rs") or lowered_path.endswith(
        "_tests.rs"
    )
    regions = _test_regions(masked)
    test_lines = _region_lines(regions)
    cfg_lines = _region_lines(_cfg_regions(masked))
    serde_signal = bool(_DERIVE_SERDE_RE.search(text))

    candidates: list[dict[str, object]] = []

    def note_candidate(
        kind: str,
        struct_name: str,
        field_name: str,
        field_type: str,
        span_start: int,
        span_end: int,
        owner: str,
        lifetime: str,
    ) -> None:
        growth = _callsites_for(masked_lines, field_name, GROWTH_METHODS, rel)
        removal = _callsites_for(masked_lines, field_name, REMOVAL_METHODS, rel)
        production_removal, test_only_removal, cfg_unknown_removal = _partition_removal(
            masked_lines, field_name, rel, test_lines, cfg_lines
        )
        span_text = "\n".join(lines[span_start - 1 : span_end])
        own_test = path_test_signal or any(
            start <= span_start <= end for start, end in regions
        )
        candidates.append(
            {
                "kind": kind,
                "package": package,
                "path": rel,
                "struct_name": struct_name,
                "field_name": field_name,
                "field_type": " ".join(field_type.split()),
                "span_start": span_start,
                "span_end": span_end,
                "source_sha256": file_sha,
                "span_digest": _sha256(span_text.encode("utf-8")),
                "owner": owner,
                "lifetime": lifetime,
                "growth_callsites": growth,
                "removal_callsites": removal,
                "preallocations": _field_preallocations(
                    masked_lines, field_name, struct_name, rel
                ),
                "production_removal": production_removal,
                "removal_test_only": test_only_removal,
                "removal_cfg_unknown": cfg_unknown_removal,
                "test_lines": test_lines,
                "cfg_lines": cfg_lines,
                "test_signal": own_test,
                "serde_signal": serde_signal,
                "masked_lines": masked_lines,
                "plain_lines": lines,
            }
        )

    for match in _STATIC_RE.finditer(masked):
        name, typ = match.group(1), match.group(2)
        if not _TYPE_RE.search(typ):
            continue
        lineno = masked.count("\n", 0, match.start()) + 1
        note_candidate(
            "static",
            "",
            name,
            typ,
            lineno,
            lineno,
            f"static {name}",
            "process-global static",
        )

    for match in _STRUCT_RE.finditer(masked):
        struct_name = match.group(1)
        body_start = match.end()
        depth = 1
        cursor = body_start
        while cursor < len(masked) and depth:
            if masked[cursor] == "{":
                depth += 1
            elif masked[cursor] == "}":
                depth -= 1
            cursor += 1
        if depth:
            raise InventoryError("MALFORMED_RUST_SOURCE", f"{rel}: unterminated struct body")
        body = masked[body_start : cursor - 1]
        for lineno_offset, body_line in enumerate(body.split("\n")):
            name_match = _FIELD_NAME_RE.match(body_line)
            if not name_match:
                continue
            name = name_match.group(1)
            typ = _split_field_type(body_line[name_match.end() :])
            if typ is None or not _TYPE_RE.search(typ):
                continue
            lineno = masked.count("\n", 0, body_start) + 1 + lineno_offset
            note_candidate(
                "field",
                struct_name,
                name,
                typ,
                lineno,
                lineno,
                f"struct {struct_name}",
                "owner-struct lifetime",
            )

    if _FN_RE.search(masked):
        for match in _LET_RE.finditer(masked):
            name, typ = match.group(1), match.group(2)
            if not _TYPE_RE.search(typ):
                continue
            lineno = masked.count("\n", 0, match.start()) + 1
            note_candidate(
                "local",
                "",
                name,
                typ,
                lineno,
                lineno,
                "enclosing function frame",
                "function-frame local",
            )

    file_record: dict[str, object] = {
        "path": rel,
        "sha256": file_sha,
        "bytes": len(raw),
        "package": package,
    }
    return file_record, candidates


def _scheduled_retention_evidence(masked_lines: list[str], ident: str) -> str | None:
    """Find a scheduling marker on a receiver-attributed per-entry retention call.

    Scheduled lifecycle boundedness is only claimed when the scheduling marker
    (interval/schedule/cron/cleanup/compact/retain/reap/sweep) and the per-entry
    retention call are the *same* line and `ident` is that call's receiver. This
    replaces the pre-885.2 helper that paired any marker with any removal call
    on a line, which let `fn cleanup(&mut self) { self.items.clear(); }` read as
    a scheduled bounded-cleanup owner: no marker beside the receiver call proves
    neither scheduling nor a cardinality limit (audit 5885377544).
    """
    sched_re = re.compile(r"\b(interval|schedule|cron|cleanup|compact|retain|reap|sweep)\b")
    retain_re = _receiver_re(ident, RETAINING_REMOVAL_METHODS)
    for lineno, line in enumerate(masked_lines, start=1):
        match = retain_re.search(line)
        if match is not None and sched_re.search(line):
            return f"line {lineno}: {line.strip()[:160]} ({match.group(1)})"
    return None


def _unbounded_lifetime_detail(item: dict[str, object]) -> str:
    """Lifetime detail for a row proven unbounded from static source."""
    if item["kind"] == "static":
        return "process-global; restart amplification unknown from this slice"
    return (
        "persisted/restart-amplified (serde derive signal in slice)"
        if item["serde_signal"]
        else "in-memory-only unless cross-slice persistence exists"
    )


def _classify(item: dict[str, object]) -> tuple[str, str, str, str, str, str]:
    """Return (classification, bound, bound_status, persistence, repair, evidence)."""
    field_type = str(item["field_type"])
    field_name = str(item["field_name"])
    masked_lines = item["masked_lines"]  # type: ignore[assignment]
    assert isinstance(masked_lines, list)
    growth = item["growth_callsites"]
    removal = item["removal_callsites"]
    preallocations = item["preallocations"]
    production = item["production_removal"]
    test_only_removal = item["removal_test_only"]
    cfg_unknown_removal = item["removal_cfg_unknown"]
    assert isinstance(growth, list) and isinstance(removal, list)
    assert isinstance(preallocations, list)
    assert isinstance(production, list)
    assert isinstance(test_only_removal, list) and isinstance(cfg_unknown_removal, list)
    test_lines = item["test_lines"]
    assert isinstance(test_lines, frozenset)
    cfg_lines = item["cfg_lines"]
    assert isinstance(cfg_lines, frozenset)
    excluded_lines = test_lines | cfg_lines
    prod_lines = [
        line if number not in excluded_lines else ""
        for number, line in enumerate(masked_lines, start=1)
    ]
    excluded_note = _excluded_removal_note(
        [str(call) for call in test_only_removal],
        [str(call) for call in cfg_unknown_removal],
    )
    driver = _cardinality_key(field_type)

    lowered = (field_type + " " + field_name).lower()
    ttl_signal = bool(re.search(r"\b(ttl|lease|expir|deadline)\b", lowered))
    append_signal = bool(re.search(r"\b(append|segment|journal|log_entries|events)\b", lowered))
    policy_signal = bool(
        re.search(r"\b(policy|policies|config|quota|budget|versioned)\b", lowered)
    )
    prealloc_note = _preallocation_note([str(call) for call in preallocations])
    # Bounded classifications below are gated on receiver-attributed evidence:
    # production removal is required, and the two lifecycle rules additionally
    # require a scheduling marker on a per-entry retention call owned by this
    # exact receiver. Preallocation, policy-like names and mere removal-method
    # presence stay discovery evidence and never upgrade a bound status or a
    # repair to none-required (audit 5885377544).
    scheduled_retention = _scheduled_retention_evidence(prod_lines, field_name)
    retention_production = [
        str(call) for call in production if str(call).rsplit(":", 1)[-1] in RETAINING_REMOVAL_METHODS
    ]
    cross_file_compaction = [
        str(call)
        for call in production
        if "(cross-file)" in str(call)
        and str(call).rsplit(":", 1)[-1].split(" ")[0] in RETAINING_REMOVAL_METHODS
    ]
    cross_file = [str(call) for call in production if "(cross-file)" in str(call)]
    detail = _unbounded_lifetime_detail(item)

    if bool(item["test_signal"]):
        return (
            "test-only",
            "none-observed",
            "none",
            "in-memory-only (no persistence signal in slice)",
            "none-required",
            "test signal (tests/ path, test file name, or cfg(test)/#[test]) in scanned slice",
        )

    if item["kind"] == "local" and growth and not removal:
        return (
            "request-local/stack-bounded",
            "none-observed",
            "none",
            "in-memory-only (function frame; no persistence signal in slice)",
            "none-required",
            f"function-local binding with growth {growth} and no static/owner escape in slice",
        )

    if item["kind"] == "local":
        return (
            "request-local/stack-bounded",
            "none-observed",
            "none",
            "in-memory-only (function frame; no persistence signal in slice)",
            "none-required",
            "function-local binding with no growth observed; frame-bounded regardless",
        )

    if (
        ttl_signal
        and scheduled_retention
        and retention_production
        and item["kind"] in ("field", "static")
    ):
        return (
            "TTL/lease with scheduled bounded cleanup",
            "scheduled retention: " + scheduled_retention,
            "configured",
            "in-memory-only unless persistence signal present",
            "none-required",
            f"ttl/lease signal with a receiver-attributed scheduled retention owner"
            f" ({scheduled_retention}) and receiver-attributed production removal"
            f" {retention_production}; whole-collection clear/drain is not retention"
            + excluded_note
            + prealloc_note,
        )

    if append_signal and retention_production and item["kind"] in ("field", "static"):
        return (
            "append-only durable segmented retention",
            "retention/rotation evidence in slice",
            "configured",
            "durable segments; restart replays retained segments",
            "none-required",
            f"append/segment signal with receiver-attributed production retention"
            f" callsites {retention_production}; whole-collection clear/drain is not"
            f" retention" + excluded_note + prealloc_note,
        )

    if growth and cross_file_compaction:
        return (
            "external compaction",
            "compaction owned outside declaring file",
            "configured",
            "owner-slice dependent",
            "none-required",
            f"receiver-attributed production compaction/eviction callsites outside the"
            f" declaring file on a growing collection: {cross_file_compaction}"
            f" (all cross-file removal: {cross_file})" + excluded_note + prealloc_note,
        )

    # Rule 6 (audit 5885377544): policy-like names, preallocation and bare
    # removal-method presence are DISCOVERY EVIDENCE ONLY. None of them, alone
    # or combined, yields a configured/hard bound or a none-required repair, so
    # there is deliberately no versioned-policy-bounded and no
    # long-lived hard-bounded branch here. Every candidate kind reaches one of
    # the branches below, which all resolve to unresolved or a frame-bound
    # local.
    discovery: list[str] = []
    if policy_signal:
        discovery.append(
            "policy-like name signal without an enforced limit: discovery evidence"
            " only, not a configured bound"
        )
    if preallocations:
        discovery.append(
            f"observed preallocation {[str(call) for call in preallocations]}"
            " preallocates and is not a maximum length: discovery evidence only"
        )
    if production:
        discovery.append(
            f"observed receiver-attributed production removal {production} establishes"
            " no guard/eviction/cleanup obligation on every growth path: discovery"
            " evidence only"
        )
    if cross_file:
        discovery.append(
            f"cross-file removal {cross_file} is whole-collection or otherwise"
            " non-retention: discovery evidence only"
        )
    discovery_note = ("; " + "; ".join(discovery)) if discovery else ""

    if growth:
        return (
            "unbounded long-lived candidate",
            "none-observed",
            "none",
            detail,
            "UNRESOLVED",
            f"{item['kind']} growth {growth} with no proven guard/eviction/cleanup"
            " obligation on every growth path in the scanned slice; static source"
            " cannot prove boundedness" + excluded_note + discovery_note
            + f"; cardinality driver '{driver}'; untrusted key influence unknown from static source",
        )

    if item["kind"] in ("field", "static"):
        return (
            "ownership/lifetime unknown",
            "none-observed",
            "unknown",
            "unknown from this slice",
            "UNRESOLVED",
            "collection-typed owner with no receiver-attributed growth callsite in the"
            " scanned slice; cross-impl/cross-module growth possible; static"
            " uncertainty stays explicit" + excluded_note + discovery_note
            + f"; cardinality driver '{driver}'; untrusted key influence unknown from static source",
        )

    return (
        "unrelated false positive",
        "none-observed",
        "none",
        "not-applicable",
        "none-required",
        "collection-type token without long-lived storage binding in scanned slice",
    )


def _cardinality_key(field_type: str) -> str:
    match = re.search(r"HashMap\s*<\s*([^,>]+)", field_type)
    if match:
        return match.group(1).strip()[:128]
    match = re.search(r"(?:BTreeMap|IndexMap)\s*<\s*([^,>]+)", field_type)
    if match:
        return match.group(1).strip()[:128]
    if re.search(r"\bVec", field_type):
        return "positional index"
    if re.search(r"\bHashSet\b|\bBTreeSet\b|\bIndexSet\b", field_type):
        return "element identity"
    return "unknown"


def _concurrency(field_type: str) -> str:
    for wrapper in ("Mutex", "RwLock", "Arc", "OnceLock", "OnceCell"):
        if re.search(r"\b" + wrapper + r"\b", field_type):
            return wrapper
    return "none-observed"


def _cross_file_removal(
    candidates: list[dict[str, object]],
) -> None:
    """Conservatively associate removal callsites from other scanned files.

    A cross-file callsite binds to a field/static only when one masked line
    mentions the owner name (struct or static ident), and `field.receiver` is
    the actual receiver of the removal method call on that same line. The
    receiver requirement matters: `owner.field` and `other.field.clear()` on one
    line establish no receiver relationship and are no longer associated.
    Function-local bindings never associate across files. The rule favors
    precision over recall; unassociated cross-module activity stays explicit in
    row evidence via the unknown classifications and successor scopes. Cross-file
    hits bucket by the owning file's test/cfg line sets: only production hits may
    prove a bound.
    """
    by_path: dict[str, list[str]] = {}
    test_by_path: dict[str, frozenset[int]] = {}
    cfg_by_path: dict[str, frozenset[int]] = {}
    for item in candidates:
        path = str(item["path"])
        if path not in by_path:
            masked = item["masked_lines"]
            assert isinstance(masked, list)
            by_path[path] = [str(line) for line in masked]
            test_value = item["test_lines"]
            assert isinstance(test_value, frozenset)
            test_by_path[path] = test_value
            cfg_value = item["cfg_lines"]
            assert isinstance(cfg_value, frozenset)
            cfg_by_path[path] = cfg_value
    for item in candidates:
        if item["kind"] == "local":
            continue
        owner_token = str(item["struct_name"]) if item["kind"] == "field" else str(
            item["field_name"]
        )
        field_token = str(item["field_name"])
        if not owner_token or not field_token:
            continue
        owner_re = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(owner_token) + r"(?![A-Za-z0-9_])")
        field_re = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(field_token) + r"(?![A-Za-z0-9_])")
        cross_re = _receiver_re(field_token, REMOVAL_METHODS)
        hits = item["removal_callsites"]
        assert isinstance(hits, list)
        prod = item["production_removal"]
        assert isinstance(prod, list)
        test_only = item["removal_test_only"]
        assert isinstance(test_only, list)
        cfg_only = item["removal_cfg_unknown"]
        assert isinstance(cfg_only, list)
        for other, other_lines in sorted(by_path.items()):
            if other == str(item["path"]):
                continue
            for lineno, line in enumerate(other_lines, start=1):
                if not owner_re.search(line) or not field_re.search(line):
                    continue
                for match in cross_re.finditer(line):
                    method = match.group(1)
                    hit = f"{other}:{lineno}:{method} (cross-file)"
                    if hit not in hits:
                        hits.append(hit)
                    if lineno in test_by_path[other]:
                        bucket = test_only
                    elif lineno in cfg_by_path[other]:
                        bucket = cfg_only
                    else:
                        bucket = prod
                    if hit not in bucket:
                        bucket.append(hit)


def _build_rows(
    file_records: list[dict[str, object]], candidates: list[dict[str, object]]
) -> list[dict[str, object]]:
    ordered = sorted(
        candidates,
        key=lambda item: (str(item["path"]), str(item["struct_name"]), str(item["field_name"])),
    )
    seen: set[str] = set()
    rows: list[dict[str, object]] = []
    for position, item in enumerate(ordered, start=1):
        identity = (
            f"{item['package']}|{item['path']}|{item['struct_name']}|"
            f"{item['field_name']}|{item['field_type']}|{item['span_start']}"
        )
        identity_digest = _sha256(identity.encode("utf-8"))
        if identity_digest in seen:
            raise InventoryError(
                "DUPLICATE_ROW_IDENTITY", f"duplicate/overlapping row identity: {identity}"
            )
        seen.add(identity_digest)
        classification, bound, bound_status, persistence, repair, evidence = _classify(item)
        assert classification in CLASSIFICATIONS, classification
        assert bound_status in BOUND_STATUSES, bound_status
        growth = [str(x) for x in item["growth_callsites"]]  # type: ignore[union-attr]
        removal = [str(x) for x in item["removal_callsites"]]  # type: ignore[union-attr]
        package = str(item["package"])
        unresolved = classification in UNRESOLVED_CLASSIFICATIONS
        if unresolved:
            # Every uncertain row keeps the blocking unresolved-owner handoff,
            # stays counted in unresolved_count and keeps FINDINGS_REMAIN_BLOCKING
            # set. Coverage completeness is tracked independently.
            repair_owner = "UNRESOLVED"
            repair_issue = "UNRESOLVED"
            assert bound_status in ("none", "unknown"), (
                "unresolved row must not claim a proven bound status: "
                f"{repair_issue}/{bound_status}"
            )
            assert repair == "UNRESOLVED", (
                f"unresolved row must not claim a closed repair: {repair!r}"
            )
            driver = _cardinality_key(str(item["field_type"]))
            successor = (
                f"bounded successor scope: give {item['struct_name'] or item['owner']}."
                f"{item['field_name']} an explicit bound plus a removal/eviction owner "
                f"with scheduled or lifecycle cleanup; run experiments before policy choice; "
                f"experiments must establish untrusted key influence on cardinality driver "
                f"'{driver}' before policy choice"
            )
        else:
            repair_owner = "none-required" if repair == "none-required" else package
            repair_issue = "none-required"
            successor = "none-required"
        drop_impl = any(
            _IMPL_DROP_RE.search(line or "") for line in item["plain_lines"]  # type: ignore[union-attr]
        )
        row: dict[str, object] = {
            "id": f"c{position:04d}",
            "package": package,
            "path": str(item["path"]),
            "struct_name": str(item["struct_name"]),
            "field_name": str(item["field_name"]),
            "field_type": str(item["field_type"]),
            "span_start": int(item["span_start"]),  # type: ignore[arg-type]
            "span_end": int(item["span_end"]),  # type: ignore[arg-type]
            "source_sha256": str(item["source_sha256"]),
            "span_digest": str(item["span_digest"]),
            "owner": str(item["owner"]),
            "lifetime": str(item["lifetime"]),
            "creation_site": f"{item['path']}:{item['span_start']}",
            "destruction_site": (
                "Drop impl present in slice" if drop_impl else "none-observed-in-slice"
            ),
            "persistence": persistence,
            "growth_callsites": sorted(growth),
            "removal_callsites": sorted(removal),
            "bound": bound,
            "bound_status": bound_status,
            "cardinality_key": _cardinality_key(str(item["field_type"])),
            "concurrency": _concurrency(str(item["field_type"])),
            "at_capacity_behavior": "unknown",
            "over_capacity_behavior": "unknown",
            "classification": classification,
            "evidence": evidence,
            "repair_owner": repair_owner,
            "repair_issue": repair_issue,
            "invalidation": (
                "row invalid when the source span digest or file sha changes; rerun sync"
            ),
            "successor_scope": successor,
        }
        row["row_digest"] = _sha256(
            json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        )
        rows.append(row)
    return rows


def _collect_inputs(root: Path, scans: list[str]) -> list[str]:
    collected: list[str] = []
    for scan in scans:
        candidate = root / scan
        resolved = _inside(root, candidate)
        if resolved.is_symlink():
            raise InventoryError("SOURCE_NOT_REGULAR_FILE", f"scan input is a symlink: {scan}")
        if resolved.is_file():
            if resolved.suffix != ".rs":
                raise InventoryError("UNSUPPORTED_SCAN_INPUT", f"not a Rust file: {scan}")
            collected.append(resolved.relative_to(root).as_posix())
        elif resolved.is_dir():
            found = sorted(
                path.relative_to(root).as_posix()
                for path in resolved.rglob("*.rs")
                if path.is_file() and not path.is_symlink()
            )
            collected.extend(found)
        else:
            raise InventoryError("SCAN_INPUT_MISSING", f"scan input is absent: {scan}")
    unique = sorted(set(collected))
    if not unique:
        raise InventoryError("EMPTY_SCAN", "scan selected no Rust files; refusing empty coverage")
    return unique


def build_inventory(
    root: Path, scans: list[str] | None, generation_command: str
) -> dict[str, object]:
    root = _root(root)
    scan_inputs = list(scans) if scans else list(DEFAULT_SCAN)
    files: list[str] = []
    exclusions: list[str] = []
    first_gap: InventoryError | None = None
    for scan in scan_inputs:
        try:
            files.extend(_collect_inputs(root, [scan]))
        except InventoryError as exc:
            if exc.code not in ("SCAN_INPUT_MISSING", "EMPTY_SCAN"):
                raise
            if first_gap is None:
                first_gap = exc
            if exc.code == "SCAN_INPUT_MISSING":
                exclusions.append(f"{scan}: absent at this revision; excluded with source evidence")
            else:
                exclusions.append(
                    f"{scan}: present but selects no Rust files; excluded with source evidence"
                )
    files = sorted(set(files))
    if not files:
        assert first_gap is not None
        raise first_gap
    file_records: list[dict[str, object]] = []
    candidates: list[dict[str, object]] = []
    for rel in files:
        record, found = _scan_file(root, rel)
        file_records.append(record)
        candidates.extend(found)

    source_pairs = sorted(f"{record['path']}:{record['sha256']}" for record in file_records)
    source_sha = _sha256("\n".join(source_pairs).encode("utf-8"))
    _cross_file_removal(candidates)
    rows = _build_rows(file_records, candidates)
    unresolved = sum(
        1 for row in rows if str(row["classification"]) in UNRESOLVED_CLASSIFICATIONS
    )
    coverage: dict[str, object] = {
        "disposition": "COMPLETE" if not exclusions else "INCOMPLETE",
        "reason": (
            "every selected file scanned; every candidate carries exactly one row"
            if not exclusions
            else "selected inputs missing: " + "; ".join(exclusions)
        ),
    }
    safety = (
        "FINDINGS_REMAIN_BLOCKING"
        if unresolved
        else "NO_UNRESOLVED_GROWTH"
    )
    header: dict[str, object] = {
        "schema": SCHEMA,
        "rule_revision": RULE_REVISION,
        "tool_version": TOOL_VERSION,
        "source_sha": source_sha,
        "scan_roots": sorted(scan_inputs),
        "scan_denominator_files": len(file_records),
        "scan_denominator_bytes": sum(int(record["bytes"]) for record in file_records),  # type: ignore[arg-type]
        "candidate_count": len(candidates),
        "classified_count": len(rows),
        "unresolved_count": unresolved,
        "generation_command": generation_command,
        "coverage_disposition": coverage["disposition"],
        "coverage_reason": coverage["reason"],
        "safety_disposition": safety,
        "proof_ceiling": PROOF_CEILING,
        "exclusions": sorted(exclusions),
        "classifications": list(CLASSIFICATIONS),
    }
    inventory: dict[str, object] = {"header": header, "rows": rows}
    inventory["inventory_digest"] = _sha256(
        json.dumps(inventory, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    )
    return inventory


def _emit_toml(inventory: dict[str, object]) -> bytes:
    header = inventory["header"]
    assert isinstance(header, dict)
    rows = inventory["rows"]
    assert isinstance(rows, list)
    digest = inventory["inventory_digest"]
    assert isinstance(digest, str)
    out: list[str] = []
    # Top-level digest first: TOML places later keys under [header]/[[rows]].
    out.append(f"inventory_digest = {_toml_string(digest)}")
    out.append("")
    out.append("[header]")
    for key in (
        "schema",
        "rule_revision",
        "tool_version",
        "source_sha",
        "scan_denominator_files",
        "scan_denominator_bytes",
        "candidate_count",
        "classified_count",
        "unresolved_count",
        "generation_command",
        "coverage_disposition",
        "coverage_reason",
        "safety_disposition",
        "proof_ceiling",
    ):
        value = header[key]
        if isinstance(value, int):
            out.append(f"{key} = {value}")
        else:
            out.append(f"{key} = {_toml_string(str(value))}")
    out.append(f"scan_roots = {_toml_str_list([str(x) for x in header['scan_roots']])}")  # type: ignore[union-attr]
    out.append(f"exclusions = {_toml_str_list([str(x) for x in header['exclusions']])}")  # type: ignore[union-attr]
    out.append(f"classifications = {_toml_str_list([str(x) for x in header['classifications']])}")  # type: ignore[union-attr]
    row_keys = (
        "id",
        "package",
        "path",
        "struct_name",
        "field_name",
        "field_type",
        "span_start",
        "span_end",
        "source_sha256",
        "span_digest",
        "row_digest",
        "owner",
        "lifetime",
        "creation_site",
        "destruction_site",
        "persistence",
        "bound",
        "bound_status",
        "cardinality_key",
        "concurrency",
        "at_capacity_behavior",
        "over_capacity_behavior",
        "classification",
        "evidence",
        "repair_owner",
        "repair_issue",
        "invalidation",
        "successor_scope",
    )
    for row in rows:
        assert isinstance(row, dict)
        out.append("")
        out.append("[[rows]]")
        for key in row_keys:
            value = row[key]
            if isinstance(value, int):
                out.append(f"{key} = {value}")
            else:
                out.append(f"{key} = {_toml_string(str(value))}")
        out.append(f"growth_callsites = {_toml_str_list([str(x) for x in row['growth_callsites']])}")  # type: ignore[union-attr]
        out.append(f"removal_callsites = {_toml_str_list([str(x) for x in row['removal_callsites']])}")  # type: ignore[union-attr]
    return ("\n".join(out) + "\n").encode("utf-8")


def _parse_toml(raw: bytes, *, source: str) -> dict[str, object]:
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise InventoryError("MALFORMED_INVENTORY", f"owned TOML is malformed: {source}") from exc
    if not isinstance(value, dict):
        raise InventoryError("MALFORMED_INVENTORY", f"owned TOML must hold a table: {source}")
    return value


def _validate_artifact(artifact: dict[str, object]) -> tuple[dict[str, object], list[dict[str, object]]]:
    if set(artifact.keys()) != {"header", "rows", "inventory_digest"}:
        raise InventoryError("MALFORMED_INVENTORY", "owned TOML must hold header/rows/digest only")
    header = artifact["header"]
    rows = artifact["rows"]
    digest = artifact["inventory_digest"]
    if not isinstance(header, dict) or not isinstance(rows, list) or not isinstance(digest, str):
        raise InventoryError("MALFORMED_INVENTORY", "owned TOML field types are wrong")
    for key in (
        "schema",
        "rule_revision",
        "source_sha",
        "scan_roots",
        "scan_denominator_files",
        "candidate_count",
        "classified_count",
        "unresolved_count",
        "coverage_disposition",
        "safety_disposition",
        "proof_ceiling",
    ):
        if key not in header:
            raise InventoryError("MALFORMED_INVENTORY", f"header is missing {key}")
    if header["schema"] != SCHEMA:
        raise InventoryError("SCHEMA_MISMATCH", f"schema is not {SCHEMA}")
    if header["rule_revision"] != RULE_REVISION:
        raise InventoryError("RULE_MISMATCH", f"rule revision is not {RULE_REVISION}")
    if header["coverage_disposition"] not in ("COMPLETE", "INCOMPLETE"):
        raise InventoryError("MALFORMED_INVENTORY", "coverage disposition is not closed")
    if header["safety_disposition"] not in ("NO_UNRESOLVED_GROWTH", "FINDINGS_REMAIN_BLOCKING"):
        raise InventoryError("MALFORMED_INVENTORY", "safety disposition is not closed")
    seen: set[str] = set()
    typed_rows: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise InventoryError("MALFORMED_INVENTORY", "row must be a table")
        for key in ("path", "struct_name", "field_name", "field_type", "classification"):
            if key not in row:
                raise InventoryError("MALFORMED_INVENTORY", f"row is missing {key}")
        classification = row["classification"]
        if classification not in CLASSIFICATIONS:
            raise InventoryError(
                "CLASSIFICATION_NOT_CLOSED",
                f"row classification is not in the closed set: {classification!r}",
            )
        identity = (
            f"{row.get('package')}|{row.get('path')}|{row.get('struct_name')}|"
            f"{row.get('field_name')}|{row.get('field_type')}|{row.get('span_start')}"
        )
        identity_digest = _sha256(identity.encode("utf-8"))
        if identity_digest in seen:
            raise InventoryError("DUPLICATE_ROW_IDENTITY", "owned TOML holds duplicated rows")
        seen.add(identity_digest)
        typed_rows.append(row)
    if len(typed_rows) != int(header["classified_count"]):
        raise InventoryError("COUNT_MISMATCH", "classified_count disagrees with row count")
    unresolved = sum(
        1 for row in typed_rows if str(row["classification"]) in UNRESOLVED_CLASSIFICATIONS
    )
    if unresolved != int(header["unresolved_count"]):
        raise InventoryError("COUNT_MISMATCH", "unresolved_count disagrees with row content")
    recomputed = _sha256(
        json.dumps(
            {"header": header, "rows": typed_rows},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    if recomputed != digest:
        raise InventoryError("DIGEST_MISMATCH", "inventory digest disagrees with content")
    return header, typed_rows


def cmd_sync(root: Path, scans: list[str] | None, generation_command: str) -> int:
    inventory = build_inventory(root, scans, generation_command)
    payload = _emit_toml(inventory)
    target = root / OWNED_TOML
    parent = target.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise InventoryError("OUTPUT_UNAVAILABLE", f"cannot create owned parent: {exc}") from exc
    fd, tmp_name = tempfile.mkstemp(dir=str(parent), prefix=".inventory-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
        os.replace(tmp_name, target)
    except OSError as exc:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise InventoryError("OUTPUT_UNAVAILABLE", f"atomic write failed: {exc}") from exc
    header = inventory["header"]
    assert isinstance(header, dict)
    print(
        json.dumps(
            {
                "status": "ok",
                "output": OWNED_TOML.as_posix(),
                "files": header["scan_denominator_files"],
                "candidates": header["candidate_count"],
                "unresolved": header["unresolved_count"],
                "safety_disposition": header["safety_disposition"],
                "inventory_digest": inventory["inventory_digest"],
            },
            sort_keys=True,
        )
    )
    return 0


def cmd_check(root: Path) -> int:
    target = root / OWNED_TOML
    if not target.is_file() or target.is_symlink():
        print(
            json.dumps(
                {
                    "status": "stale",
                    "code": "ARTIFACT_MISSING",
                    "detail": "owned inventory TOML is absent; run sync",
                },
                sort_keys=True,
            )
        )
        return 1
    try:
        stored_raw = target.read_bytes()
    except OSError as exc:
        raise InventoryError("ARTIFACT_UNREADABLE", f"cannot read owned TOML: {exc}") from exc
    artifact = _parse_toml(stored_raw, source=OWNED_TOML.as_posix())
    try:
        header, _ = _validate_artifact(artifact)
    except InventoryError as exc:
        print(
            json.dumps({"status": "error", "code": exc.code, "detail": exc.detail}, sort_keys=True)
        )
        return 2
    scans = [str(x) for x in header["scan_roots"]]  # type: ignore[union-attr]
    fresh = build_inventory(root, scans, str(header.get("generation_command", "")))
    fresh_raw = _emit_toml(fresh)
    if fresh_raw != stored_raw:
        print(
            json.dumps(
                {
                    "status": "stale",
                    "code": "STALE_ARTIFACT",
                    "detail": "sources, rules, or artifact changed; run sync",
                    "safety_disposition": header.get("safety_disposition"),
                },
                sort_keys=True,
            )
        )
        return 1
    print(
        json.dumps(
            {
                "status": "ok",
                "coverage_disposition": header.get("coverage_disposition"),
                "safety_disposition": header.get("safety_disposition"),
                "candidates": header.get("candidate_count"),
                "unresolved": header.get("unresolved_count"),
                "inventory_digest": artifact.get("inventory_digest"),
                "note": "a findings-bearing inventory stays findings-bearing, never a safety pass",
            },
            sort_keys=True,
        )
    )
    return 0


def run_self_tests() -> int:
    sample = """
    // line comment with push(
    /* block Vec<String> */
    struct Registry {
        inner: Mutex<HashMap<String, Vec<u8>>>,
    }
    impl Registry {
        fn add(&self, k: String, v: Vec<u8>) { self.inner.insert(k, v); }
    }
    fn local() {
        let mut buf: Vec<u8> = Vec::new();
        buf.push(1);
        let s = "push(";
        let raw = r#"Vec<String>"#;
    }
    """
    masked = _mask_rust(sample)
    assert "// line comment" not in masked
    assert "block Vec" not in masked
    assert '"push("' not in masked
    assert 'Vec<String>"#' not in masked
    assert "struct Registry" in masked
    assert "self.inner.insert" in masked
    assert "buf.push" in masked
    for bad in ("/* unclosed", 'let s = "unclosed;', 'let r = r#"unclosed;'):
        try:
            _mask_rust(bad)
        except InventoryError as exc:
            assert exc.code == "MALFORMED_RUST_SOURCE", exc.code
        else:
            raise AssertionError(f"expected fail-closed masking: {bad!r}")

    first = _sha256(json.dumps({"b": 2, "a": [1]}.copy(), sort_keys=True).encode())
    second = _sha256(json.dumps({"a": [1], "b": 2}, sort_keys=True).encode())
    assert first == second, "digests must be key-order independent"
    assert len(CLASSIFICATIONS) == 12, "closed classification set must hold 12 values"
    assert len(set(CLASSIFICATIONS)) == 12, "classifications must be unique"

    with tempfile.TemporaryDirectory() as td:
        troot = Path(td).resolve()
        scan = troot / "scan"
        scan.mkdir()
        (scan / "demo.rs").write_text(
            "struct Holder {\n    items: Vec<String>,\n}\n"
            "impl Holder {\n    fn add(&mut self, v: String) { self.items.push(v); }\n}\n",
            encoding="utf-8",
        )
        first_build = build_inventory(troot, ["scan"], "self-test")
        second_build = build_inventory(troot, ["scan"], "self-test")
        assert _emit_toml(first_build) == _emit_toml(second_build), "build must be deterministic"
        assert int(first_build["header"]["candidate_count"]) >= 1  # type: ignore[union-attr]
        round_tripped = _parse_toml(_emit_toml(first_build), source="self-test")
        _validate_artifact(round_tripped)

    print("PASS: long_lived_collection_inventory self-tests completed successfully")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", choices=("sync", "check"))
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--scan", action="append", default=None)
    parser.add_argument("--self-test", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.self_test:
        if args.command is not None:
            print("error: --self-test takes no command", file=sys.stderr)
            return 2
        try:
            return run_self_tests()
        except (InventoryError, AssertionError) as exc:
            print(f"SELF_TEST_FAILED: {exc}", file=sys.stderr)
            return 1
    if args.command == "sync":
        generation = (
            "python scripts/long_lived_collection_inventory.py sync"
            f" --root {args.root.as_posix()}"
            + ("" if not args.scan else "".join(f" --scan {item}" for item in args.scan))
        )
        try:
            return cmd_sync(args.root, args.scan, generation)
        except InventoryError as exc:
            print(
                json.dumps({"status": "error", "code": exc.code, "detail": exc.detail}, sort_keys=True),
                file=sys.stderr,
            )
            return 2
    if args.command == "check":
        if args.scan:
            print("error: check derives scan roots from the owned artifact", file=sys.stderr)
            return 2
        try:
            return cmd_check(args.root)
        except InventoryError as exc:
            print(
                json.dumps({"status": "error", "code": exc.code, "detail": exc.detail}, sort_keys=True),
                file=sys.stderr,
            )
            return 2
    print("error: expected sync, check, or --self-test", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
