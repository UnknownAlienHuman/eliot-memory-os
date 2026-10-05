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

Rules 885.3 are deliberately bounded. Balanced Rust items establish lexical
module/impl/function ownership; direct fields, lock chains and non-reassigned
local aliases retain receiver evidence. Unsupported receiver/escape shapes stay
unresolved. A narrow finite guard is recognized only for private Vec fields,
empty construction and every single-item push path; other limits and cleanup,
TTL, compaction, serde and policy names remain observations, never clearance.
Serde is a serialization capability, not evidence of actual durable storage.
Build reachability is a symbolic Cargo dependency closure, never runtime proof.
Missing inputs, malformed source and incomplete coverage cannot pass check.

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

SCHEMA = "eliot.long-lived-collection-inventory.v2"
RULE_REVISION = "885.3"
TOOL_VERSION = "0.2.0"
OWNED_TOML = Path(".github/work-units/long-lived-collection-inventory.toml")
PROOF_CEILING = "STATIC_SOURCE_CLASSIFICATION_ONLY"

DEFAULT_SCAN = (
    "crates/governor/eliot-problem/src/lib.rs",
    "crates/governor/eliot-skill/src/lib.rs",
    "crates/governor/eliot-canonical/src/lib.rs",
    "crates/agent/eliot-agent-coordinator/src/model_control.rs",
)
DEFAULT_DISCOVERY_SCAN = tuple(sorted({str(Path(path).parent.as_posix()) for path in DEFAULT_SCAN}))

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
    if path.is_symlink():
        raise InventoryError("SOURCE_NOT_REGULAR_FILE", f"source is a symlink: {path}")
    resolved = _inside(root, path)
    if not resolved.is_file():
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


def _balanced(masked: str, rel: str) -> dict[int, int]:
    """Validate delimiters; this is a bounded item reader, not a Rust compiler."""
    stack: list[tuple[str, int]] = []
    pairs: dict[int, int] = {}
    for pos, char in enumerate(masked):
        if char in "({[":
            stack.append((char, pos))
        elif char in ")} ]".replace(" ", ""):
            if not stack or "({[".index(stack[-1][0]) != ")}]".index(char):
                raise InventoryError("MALFORMED_RUST_SOURCE", f"{rel}: unmatched {char}")
            _, opening = stack.pop()
            pairs[opening] = pos
    if stack:
        raise InventoryError("MALFORMED_RUST_SOURCE", f"{rel}: unclosed delimiter")
    return pairs


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _regions(masked: str, pairs: dict[int, int], pattern: str) -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    for match in re.finditer(pattern, masked):
        opening = masked.find("{", match.start(), match.end())
        if opening in pairs:
            found.append({"start": match.start(), "body": opening,
                          "end": pairs[opening], "name": match.group(1)})
    return found


def _module_at(context: dict[str, object], pos: int) -> str:
    modules = context["modules"]
    names = [str(context.get("base_module", ""))]
    names += [str(m["name"]) for m in modules
              if int(m["body"]) < pos < int(m["end"])]
    return "::".join(name for name in names if name)


def _qualify(module: str, name: str) -> str:
    return f"{module}::{name}" if module else name


def _context(masked: str, rel: str) -> dict[str, object]:
    pairs = _balanced(masked, rel)
    modules = _regions(masked, pairs, r"\bmod\s+(\w+)\s*\{")
    context: dict[str, object] = {"masked": masked, "pairs": pairs,
                                 "modules": modules, "path": rel}
    source_parts = rel.replace("\\", "/").split("/src/", 1)
    source_module = source_parts[-1] if len(source_parts) == 2 else ""
    parts = source_module.removesuffix(".rs").split("/")
    if parts and parts[-1] in ("lib", "main", "mod"):
        parts.pop()
    context["base_module"] = "::".join(part for part in parts if part)
    imports = {}
    for imported in re.finditer(r"\buse\s+(crate::[\w:]+)(?:\s+as\s+(\w+))?\s*;", masked):
        name = imported.group(2) or imported.group(1).split("::")[-1]
        imports[(_module_at(context, imported.start()), name)] = imported.group(1).removeprefix("crate::")
    impls = []
    for match in re.finditer(r"\bimpl\b([^;{}]*)\{", masked):
        opening = match.end() - 1
        signature = match.group(1).strip()
        # Remove leading generic arguments using depth, rather than '<.*>'.
        if signature.startswith("<"):
            depth = 0
            for index, char in enumerate(signature):
                depth += (char == "<") - (char == ">")
                if depth == 0:
                    signature = signature[index + 1:].strip()
                    break
        signature = signature.split(" where ", 1)[0]
        owner = signature.rsplit(" for ", 1)[-1].strip()
        owner = re.sub(r"<.*", "", owner).strip()
        module = _module_at(context, match.start())
        qualified = imports.get((module, owner), _qualify(module, owner))
        if owner.startswith("crate::"):
            qualified = owner.removeprefix("crate::")
        impls.append({"start": match.start(), "body": opening,
                      "end": pairs[opening], "name": owner,
                      "qualified": qualified,
                      "drop": bool(re.search(r"\bDrop\s+for\b", signature))})
    context["impls"] = impls
    functions = []
    for match in _FN_RE.finditer(masked):
        paren = match.end() - 1
        end_params = pairs[paren]
        tail = masked[end_params + 1:]
        body_offset = tail.find("{")
        semi_offset = tail.find(";")
        if body_offset < 0 or 0 <= semi_offset < body_offset:
            continue
        opening = end_params + 1 + body_offset
        owner_impl = next((i for i in reversed(impls)
                           if int(i["body"]) < match.start() < int(i["end"])), None)
        functions.append({"start": match.start(), "body": opening,
                          "end": pairs[opening],
                          "name": re.search(r"\bfn\s+(\w+)", match.group()).group(1),
                          "params": masked[paren + 1:end_params],
                          "owner": owner_impl["qualified"] if owner_impl else "",
                          "module": _module_at(context, match.start())})
    context["functions"] = functions
    return context


def _function_at(context: dict[str, object], pos: int) -> dict[str, object] | None:
    return next((f for f in reversed(context["functions"])
                 if int(f["body"]) < pos < int(f["end"])), None)


def _gated_at(context: dict[str, object], pos: int, attr_re: re.Pattern[str]) -> bool:
    masked = str(context["masked"])
    for attr in attr_re.finditer(masked):
        brace = masked.find("{", attr.end())
        semi = masked.find(";", attr.end())
        if brace >= 0 and not (0 <= semi < brace):
            if attr.start() <= pos <= context["pairs"][brace]:
                return True
    return False


def _aliases(masked: str, context: dict[str, object]) -> dict[str, str]:
    aliases = {_qualify(_module_at(context, m.start()), m.group(1)): m.group(2).strip()
               for m in re.finditer(r"\btype\s+(\w+)(?:\s*<[^;=]*>)?\s*=\s*([^;]+);", masked)}
    for statement in re.finditer(r"\buse\s+([^;]+);", masked):
        for imported in re.finditer(r"([\w:]+)\s+as\s+(\w+)", statement.group(1)):
            target, name = imported.groups()
            if target.split("::")[-1] in COLLECTION_CORE:
                target = target.split("::")[-1]
            elif target.startswith("crate::"):
                target = target.removeprefix("crate::")
            else:
                target = "UNKNOWN_IMPORTED_TYPE " + target
            aliases[_qualify(_module_at(context, statement.start()), name)] = target
    return aliases


def _resolve_type(typ: str, aliases: dict[str, str], module: str = "") -> tuple[str, bool]:
    resolved = typ
    seen = set()
    for _ in range(16):
        selected = None
        for qualified in sorted(aliases, key=len, reverse=True):
            alias_module, _, bare = qualified.rpartition("::")
            spelling = qualified if "::" in qualified and qualified in resolved else bare
            if spelling == bare and alias_module != module:
                continue
            pattern = r"(?<![\w:])" + re.escape(spelling) + r"(?![\w:])"
            if re.search(pattern, resolved):
                selected = qualified, pattern
                break
        if selected is None:
            return resolved, bool(_TYPE_RE.search(resolved))
        token, pattern = selected
        if token in seen:
            return resolved, False
        seen.add(token)
        resolved = re.sub(pattern, aliases[token], resolved)
    return resolved, False


def _scan_file(root: Path, rel: str, external_aliases: dict[str, str] | None = None) -> tuple[dict[str, object], list[dict[str, object]]]:
    raw = _read_source(root, root / rel)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InventoryError("SOURCE_ENCODING", f"{rel}: source is not UTF-8") from exc
    masked = _mask_rust(text)
    context = _context(masked, rel)
    context["plain"] = text
    package = _package_of(root, root / rel)
    aliases = dict(external_aliases or {})
    aliases.update(_aliases(masked, context))
    test_regions = _test_regions(masked)
    test_lines = _region_lines(test_regions)
    cfg_lines = _region_lines(_cfg_regions(masked))
    path_test = bool(re.search(r"(^|/)(tests|testdata)/|(^|/)test_", rel))
    candidates: list[dict[str, object]] = []

    def add(kind: str, owner: str, name: str, typ: str, start: int, end: int,
            public: bool = False, attrs: str = "") -> None:
        typ = typ.strip()
        resolved, supported = _resolve_type(typ, aliases, _module_at(context, start))
        if not supported and not _TYPE_RE.search(resolved):
            if resolved in ("String", "str", "bool", "usize", "u8", "u16", "u32", "u64", "i32", "i64"):
                return
            # A cyclic/ambiguous alias with collection evidence must remain a candidate.
            if "UNKNOWN_IMPORTED_TYPE" not in resolved and not any(re.search(r"\b" + re.escape(alias.split("::")[-1]) + r"\b", typ)
                       and _TYPE_RE.search(value) for alias, value in aliases.items()):
                return
        module = _module_at(context, start)
        qualified = _qualify(module, owner) if owner else ""
        func = _function_at(context, start)
        scope = f"{func['owner']}::{func['name']}@{func['start']}" if func else ""
        line = _line(masked, start)
        candidates.append({
            "kind": kind, "package": package, "path": rel,
            "struct_name": qualified if kind == "field" else scope if kind == "local" else module,
            "field_name": name, "field_type": " ".join(typ.split()),
            "resolved_type": resolved, "span_start": line, "span_end": _line(masked, end),
            "source_sha256": _sha256(raw), "span_digest": _sha256(text[start:end].encode()),
            "owner": f"struct {qualified}" if kind == "field" else f"static {name}" if kind == "static" else scope,
            "lifetime": "owner lifetime UNKNOWN" if kind == "field" else "process-global static" if kind == "static" else "function frame; escape analysis required",
            "position": start, "end_position": end, "qualified": qualified,
            "public": public, "context": context, "function": func,
            "test_signal": path_test or _gated_at(context, start, _TEST_ATTR_RE),
            "test_lines": test_lines, "cfg_lines": cfg_lines,
            "serde_signal": bool(_DERIVE_SERDE_RE.search(attrs)),
            "deserialize_signal": bool(re.search(r"\bDeserialize\b", attrs)),
            "owner_attributes": attrs,
            "growth_callsites": [], "removal_callsites": [], "preallocations": [],
            "production_removal": [], "removal_test_only": [], "removal_cfg_unknown": [],
            "unresolved_evidence": [], "creation_callsites": [], "growth_details": [],
            "masked_lines": masked.splitlines(), "plain_lines": text.splitlines(),
        })

    structs = _regions(masked, context["pairs"], r"\bstruct\s+(\w+)[^;{}]*\{")
    for region in structs:
        start, opening, closing = int(region["start"]), int(region["body"]), int(region["end"])
        # Only immediately preceding attributes belong to this declaration.
        prefix = masked[:start]
        attrs_match = re.search(r"((?:#\s*\[[^\]]*\]\s*)*)(?:pub(?:\([^)]*\))?\s+)?$", prefix)
        attrs = attrs_match.group(1) if attrs_match else ""
        cursor = opening + 1
        field_start = cursor
        angle = 0
        while cursor <= closing:
            char = masked[cursor] if cursor < closing else ","
            if char in "([{" and cursor in context["pairs"]:
                cursor = context["pairs"][cursor] + 1
                continue
            angle += (char == "<") - (char == ">")
            if char == "," and angle == 0:
                field = masked[field_start:cursor]
                match = re.match(r"\s*(?:#\s*\[[^\]]*\]\s*)*(pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*(.+)", field, re.S)
                if match:
                    pos = field_start + match.start(2)
                    add("field", str(region["name"]), match.group(2), match.group(3),
                        pos, cursor, bool(match.group(1)), attrs)
                elif _TYPE_RE.search(field):
                    raise InventoryError("UNSUPPORTED_RUST_SYNTAX", f"{rel}: collection field could not be read")
                field_start = cursor + 1
            cursor += 1
        if angle != 0:
            raise InventoryError("MALFORMED_RUST_SOURCE", f"{rel}: unbalanced field type arguments")
    for match in re.finditer(r"\bstatic\s+(?:mut\s+)?(\w+)\s*:\s*([^;=]+)=", masked):
        add("static", "", match.group(1), match.group(2), match.start(), match.end())
    for match in _LET_RE.finditer(masked):
        if _function_at(context, match.start()):
            add("local", "", match.group(1), match.group(2), match.start(), match.end())
    for match in re.finditer(r"\blet\s+(?:mut\s+)?(\w+)\s*=\s*((?:[\w:]+::)?(?:"
                            + _COLLECTION_ALTERNATION + r")(?:\s*::<[^;=]*>)?\s*::\s*(?:new|with_capacity)\s*\(|vec\s*!\s*\[)", masked):
        if _function_at(context, match.start()):
            typ = "Vec<UNKNOWN>" if re.search(r"vec\s*!", match.group(2)) else re.search(r"\b(" + _COLLECTION_ALTERNATION + r")\b", match.group(2)).group(1) + "<UNKNOWN>"
            add("local", "", match.group(1), typ, match.start(), match.end())
    # Tuple fields have stable numeric identities; unsupported numeric receiver
    # analysis leaves them unresolved rather than silently omitting the owner.
    for match in re.finditer(r"\bstruct\s+(\w+)(?:\s*<[^;{}]*>)?\s*\(", masked):
        opening = match.end() - 1
        closing = context["pairs"][opening]
        cursor, field_start, angle, number = opening + 1, opening + 1, 0, 0
        while cursor <= closing:
            char = masked[cursor] if cursor < closing else ","
            if char in "([{" and cursor in context["pairs"]:
                cursor = context["pairs"][cursor] + 1
                continue
            angle += (char == "<") - (char == ">")
            if char == "," and angle == 0:
                typ = re.sub(r"^\s*pub(?:\([^)]*\))?\s+", "", masked[field_start:cursor]).strip()
                if typ:
                    add("field", match.group(1), str(number), typ, field_start, cursor)
                    number += 1
                field_start = cursor + 1
            cursor += 1
    return {"path": rel, "sha256": _sha256(raw), "bytes": len(raw),
            "package": package, "_context": context}, candidates


_LOCK_CHAIN = r"(?:\s*\.\s*(?:lock|read|write|unwrap|expect|borrow_mut|get_mut|as_mut)\s*\([^()]*\))*"


def _associate_sites(records: list[dict[str, object]], candidates: list[dict[str, object]]) -> None:
    """Credit only a resolved receiver in a specific lexical owner/function.

    Parameters and cross-file destructuring are retained as unresolved observations;
    their mere presence cannot discharge a production cleanup obligation.
    """
    for item in candidates:
        name = str(item["field_name"])
        for record in records:
            ctx = record["_context"]
            masked = str(ctx["masked"])
            rel = str(record["path"])
            if item["kind"] == "local" and rel != item["path"]:
                continue
            for func in ctx["functions"]:
                begin, end = int(func["body"]) + 1, int(func["end"])
                body = masked[begin:end]
                same_owner = (record["package"] == item["package"] and
                              func["owner"] == item["qualified"])
                if item["kind"] == "field":
                    if not same_owner:
                        # Preserve typed/destructured cross-module activity without invented linkage.
                        owner = str(item["qualified"]).split("::")[-1]
                        if owner and re.search(r"\b" + re.escape(owner) + r"\b", str(func["params"]) + body):
                            if re.search(r"\b" + re.escape(name) + r"\b", body):
                                item["unresolved_evidence"].append(f"{rel}:{_line(masked, begin)}: possible typed/destructured {owner}.{name}; receiver/obligation UNKNOWN")
                        continue
                    receiver = r"(?<![\w.])self\s*\.\s*" + re.escape(name)
                elif item["kind"] == "static":
                    if record["package"] != item["package"] or func["module"] != item["struct_name"]:
                        continue
                    if re.search(r"\blet\s+(?:mut\s+)?" + re.escape(name) + r"\b", body) or re.search(r"\b" + re.escape(name) + r"\s*:", str(func["params"])):
                        continue
                    receiver = r"(?<![\w.])" + re.escape(name)
                else:
                    own_func = item["function"]
                    if own_func is None or func["start"] != own_func["start"]:
                        continue
                    receiver = r"(?<![\w.])" + re.escape(name)
                receivers = [(receiver, "direct")]
                if item["kind"] in ("field", "static"):
                    for alias in re.finditer(r"\blet\s+(?:mut\s+)?(\w+)\s*=\s*(?:&\s*(?:mut\s+)?)?(" + receiver + _LOCK_CHAIN + r")\s*;", body):
                        alias_name = alias.group(1)
                        tail = body[alias.end():]
                        if re.search(r"\b" + re.escape(alias_name) + r"\s*=|\blet\s+(?:mut\s+)?" + re.escape(alias_name) + r"\b", tail):
                            item["unresolved_evidence"].append(f"{rel}:{_line(masked, begin + alias.start())}: reassigned/shadowed receiver alias {alias_name}")
                        else:
                            receivers.append((r"(?<![\w.])" + re.escape(alias_name), f"alias {alias_name}"))
                            for use in re.finditer(r"(?<![\w.])" + re.escape(alias_name) + r"\b", tail):
                                if not re.match(r"\s*\.\s*(?:" + "|".join(GROWTH_METHODS + REMOVAL_METHODS + ("len", "is_empty")) + r")\s*\(", tail[use.end():]):
                                    item["unresolved_evidence"].append(f"{rel}:{_line(masked, begin + alias.start())}: alias {alias_name} passed/escaped; helper growth/cleanup UNKNOWN")
                for prefix, provenance in receivers:
                    pattern = prefix + _LOCK_CHAIN + r"\s*\.\s*(" + "|".join(GROWTH_METHODS + REMOVAL_METHODS) + r")\s*(?:::<[^;{}]*>)?\s*\("
                    for call in re.finditer(pattern, body):
                        pos = begin + call.start()
                        line = _line(masked, pos)
                        method = call.group(1)
                        site = f"{rel}:{line}:{method}"
                        if rel != item["path"]:
                            site += " (cross-file)"
                        if provenance != "direct":
                            site += f" ({provenance})"
                        if method in GROWTH_METHODS:
                            item["growth_callsites"].append(site)
                            item["growth_details"].append({"context": ctx, "function": func,
                                "pos": pos, "method": method, "receiver": prefix,
                                "provenance": provenance})
                        else:
                            item["removal_callsites"].append(site)
                            test = _gated_at(ctx, pos, _TEST_ATTR_RE)
                            cfg = _gated_at(ctx, pos, _CFG_RE)
                            bucket = "removal_test_only" if test else "removal_cfg_unknown" if cfg else "production_removal"
                            item[bucket].append(site)
                # A lexical method body does not establish that its cleanup is ever invoked.
                if re.search(receiver + r"\b", body) and not same_owner and item["kind"] == "field":
                    item["unresolved_evidence"].append(f"{rel}:{_line(masked, begin)}: owner relationship UNKNOWN")
                if item["kind"] == "local":
                    after_declaration = masked[int(item["end_position"]):end]
                    for reference in re.finditer(r"(?<![\w.])" + re.escape(name) + r"\b", after_declaration):
                        allowed = "|".join(GROWTH_METHODS + REMOVAL_METHODS + ("len", "is_empty"))
                        if not re.match(r"\s*\.\s*(?:" + allowed + r")\s*\(", after_declaration[reference.end():]):
                            item["unresolved_evidence"].append("local binding has unsupported use/escape or shadowing")
                    # Any return/storage/pass-by-value/ref escape is conservatively unresolved.
                    if re.search(r"\breturn\s+(?:&\s*)?" + re.escape(name) + r"\b|\b(?:self|[A-Z]\w*)\b[^;]*[:=]\s*" + re.escape(name) + r"\b", body):
                        item["unresolved_evidence"].append("local binding may escape function frame")
                    if re.search(r"\blet\s+(?:mut\s+)?\w+\s*=\s*(?:&\s*(?:mut\s+)?)?" + re.escape(name) + r"\b", body):
                        item["unresolved_evidence"].append("local binding alias/transfer; escape UNKNOWN")
                    if re.search(r"\bmove\b[^;]*\b" + re.escape(name) + r"\b|\{\s*" + re.escape(name) + r"\s*[,}]", body):
                        item["unresolved_evidence"].append("local binding captured/stored; escape UNKNOWN")
                    after = body[body.find(";", max(0, int(item["position"]) - begin)) + 1:].strip()
                    if re.search(r"(?:\(|,)\s*&?(?:mut\s+)?" + re.escape(name) + r"\s*[,)]|\b" + re.escape(name) + r"\s*$", after):
                        item["unresolved_evidence"].append("local binding passed/returned; escape UNKNOWN")
            if item["kind"] == "field":
                for impl in ctx["impls"]:
                    if record["package"] != item["package"] or impl["qualified"] != item["qualified"]:
                        continue
                    region = masked[int(impl["body"]) + 1:int(impl["end"])]
                    for func in ctx["functions"]:
                        if func["owner"] != item["qualified"]:
                            continue
                        body_start = int(func["body"]) + 1
                        body = masked[body_start:int(func["end"])]
                        for creation in re.finditer(r"\b(?:Self|" + re.escape(str(item["qualified"]).split("::")[-1]) + r")\s*\{", body):
                            opening = body_start + creation.end() - 1
                            content = masked[opening + 1:ctx["pairs"][opening]]
                            value_match = re.search(r"\b" + re.escape(name) + r"\s*:\s*([^,}]+)", content)
                            value = value_match.group(1).strip() if value_match else "UNKNOWN shorthand/update/constructor"
                            site = f"{rel}:{_line(masked, opening)}: {name}: {value}"
                            item["creation_callsites"].append(site)
                            if "with_capacity" in value:
                                item["preallocations"].append(site)
        for key in ("growth_callsites", "removal_callsites", "production_removal",
                    "removal_test_only", "removal_cfg_unknown", "preallocations",
                    "unresolved_evidence", "creation_callsites"):
            item[key] = sorted(set(item[key]))


def _hard_guard(item: dict[str, object]) -> tuple[str, str] | None:
    """Recognize one small syntactic proof, refusing all broader Rust control flow.

    Private plain Vec, only empty constructions, only single-item push growth,
    literal/associated finite constant, and a top-level early-return guard with
    no intervening statements. Aliases, public fields, cfg and other uses refuse.
    """
    if item["kind"] != "field" or item["public"] or item["unresolved_evidence"] or item["deserialize_signal"] or item["owner_attributes"]:
        return None
    if item["context"]["modules"] or re.search(
        r"\b(?:unsafe|include|macro_rules)\b|\bmod\s+\w+\s*;",
        str(item["context"]["masked"]),
    ):
        return None
    if not re.fullmatch(r"(?:std::vec::)?Vec\s*<[^<>]+>", str(item["resolved_type"])):
        return None
    if not item["creation_callsites"] or any(not re.search(r":\s*(?:Vec|std::vec::Vec)::new\(\)\s*$", site)
                                              for site in item["creation_callsites"]):
        return None
    growth = item["growth_details"]
    if not growth:
        return None
    limits = []
    for detail in growth:
        ctx, func = detail["context"], detail["function"]
        masked = str(ctx["masked"])
        pos = int(detail["pos"])
        prefix = masked[int(func["body"]) + 1:pos]
        if detail["method"] != "push" or detail["provenance"] != "direct":
            return None
        if _gated_at(ctx, pos, _CFG_RE):
            return None
        field = re.escape(str(item["field_name"]))
        match = re.fullmatch(r"\s*if\s+self\s*\.\s*" + field + r"\s*\.\s*len\s*\(\s*\)\s*>=\s*([A-Za-z_][\w:]*|[0-9][0-9_]*)\s*\{\s*return(?:\s+[^;{}]+)?\s*;\s*\}\s*", prefix)
        if not match:
            return None
        expression = match.group(1)
        if re.fullmatch(r"[0-9][0-9_]*", expression):
            value = int(expression.replace("_", ""))
        else:
            # Associated const is resolved only in this exact impl; global names
            # and policy fields are not guessed, nor is usize::MAX a safe cap.
            if not expression.startswith("Self::"):
                return None
            const_name = re.escape(expression[6:])
            owner_impls = [i for i in ctx["impls"] if i["qualified"] == item["qualified"]]
            declarations = []
            for impl in owner_impls:
                declarations += re.findall(r"\bconst\s+" + const_name + r"\s*:\s*usize\s*=\s*([0-9][0-9_]*)\s*;", masked[int(impl["body"]):int(impl["end"])])
            if len(declarations) != 1:
                return None
            value = int(declarations[0].replace("_", ""))
        if not 0 < value < 2**32:
            return None
        # Entire body must be this guard plus a single push statement.
        body = masked[int(func["body"]) + 1:int(func["end"])]
        if not re.fullmatch(re.escape(prefix) + r"self\s*\.\s*" + field + r"\s*\.\s*push\s*\([^();{}]*\)\s*;\s*", body):
            return None
        limits.append(value)
    if len(set(limits)) != 1:
        return None
    # Any unsupported mutation or escaped field reference prevents a positive
    # bound; a method outside the inventory slice remains explicit proof ceiling.
    name = re.escape(str(item["field_name"]))
    ctx = item["context"]
    # A selected module can mutate/construct private fields through a type alias
    # or free function. Refuse any unowned access/literal instead of guessing its
    # type. This intentionally sacrifices positives for unrelated same-name uses.
    for reference in re.finditer(r"\b" + name + r"\b", str(ctx["masked"])):
        if int(item["position"]) <= reference.start() < int(item["end_position"]):
            continue
        function = _function_at(ctx, reference.start())
        if function is None or function["owner"] != item["qualified"]:
            return None
    for func in ctx["functions"]:
        if func["owner"] != item["qualified"]:
            continue
        body = str(ctx["masked"])[int(func["body"]) + 1:int(func["end"])]
        if re.search(r"\bself\b(?!\s*\.\s*" + name + r"\b)", body):
            return None
        refs = list(re.finditer(r"\bself\s*\.\s*" + name + r"\b", body))
        for ref in refs:
            if not re.match(r"\s*\.\s*(?:len|push)\s*\(", body[ref.end():]):
                return None
    return str(limits[0]), "top-level early return; no mutation at or over capacity"


def _classify(item: dict[str, object]) -> tuple[str, str, str, str, str, str]:
    growth = item["growth_callsites"]
    persistence = ("serialization capability on exact owner; durable storage and restart amplification UNKNOWN"
                   if item["serde_signal"] else "no persistence observed; cross-slice persistence UNKNOWN")
    observations = []
    if item["deserialize_signal"]:
        observations.append("Deserialize capability can bypass constructor/growth guards; imported length UNKNOWN")
    for key in ("preallocations", "production_removal", "removal_test_only", "removal_cfg_unknown", "unresolved_evidence"):
        if item[key]:
            observations.append(f"{key}={item[key]}")
    note = "; ".join(observations)
    if item["test_signal"]:
        return "test-only", "none-observed", "none", persistence, "none-required", "test-only owner; " + note
    if item["kind"] == "local" and not item["unresolved_evidence"]:
        return "request-local/stack-bounded", "function frame", "none", persistence, "none-required", "local non-escaping binding in selected function; " + note
    hard = _hard_guard(item)
    if hard:
        return "long-lived hard-bounded", hard[0], "hard", persistence, "none-required", hard[1] + "; private Vec empty construction; every observed push guarded; STATIC selected-slice proof only"
    classification = "unbounded long-lived candidate" if growth and not item["unresolved_evidence"] else "ownership/lifetime unknown"
    return classification, "none-observed", "none" if classification.startswith("unbounded") else "unknown", persistence, "UNRESOLVED", (
        "No established guard/cleanup obligation on every growth path. Names, preallocation, serialization, optional removal/retention/rotation and cross-file cleanup are discovery only. " + note)


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


def _cargo_metadata(root: Path, packages: list[str]) -> tuple[list[str], list[str]]:
    """Static build lower bound plus target/feature-aware symbolic potential.

    Only unconditional nonoptional dependency paths establish shipped-build.
    Conditional paths remain UNKNOWN; dev-only potential paths are nonrelease.
    All predicates/features are recorded, never executable call-path proof.
    """
    manifests: dict[str, dict[str, object]] = {}
    inputs: list[str] = []

    def read(path: Path) -> dict[str, object]:
        path = _inside(root, path)
        raw = _read_source(root, path)
        try:
            value = tomllib.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise InventoryError("MALFORMED_CARGO_METADATA", str(path.relative_to(root))) from exc
        inputs.append(f"{path.relative_to(root).as_posix()}:{_sha256(raw)}")
        manifests[path.relative_to(root).as_posix()] = value
        return value

    root_manifest = root / "Cargo.toml"
    if not root_manifest.is_file():
        return [], [json.dumps({"package": package, "classification": "UNKNOWN",
                               "reason": "no Cargo manifest in scan root", "runtime_proof": False}, sort_keys=True)
                    for package in packages]
    root_data = read(root_manifest)
    for identity in ("Cargo.lock", "rust-toolchain.toml"):
        path = root / identity
        if path.is_file():
            inputs.append(f"{identity}:{_sha256(_read_source(root, path))}")
    workspace = root_data.get("workspace", {})
    members = workspace.get("members", [])
    excluded = workspace.get("exclude", [])
    selected_manifests = set()
    for pattern in members:
        for member in root.glob(str(pattern)):
            member = _inside(root, member)
            if any(member.match(str(pattern)) for pattern in excluded):
                continue
            path = member / "Cargo.toml"
            if not path.is_file():
                raise InventoryError("CARGO_MEMBER_MISSING", str(path.relative_to(root)))
            selected_manifests.add(path)
    if "package" in root_data:
        selected_manifests.add(root_manifest)
    for path in sorted(selected_manifests):
        if path != root_manifest:
            read(path)
    nodes = {str(data["package"]["name"]): (rel, data)
             for rel, data in manifests.items() if isinstance(data.get("package"), dict)}
    defaults = workspace.get("default-members", members)
    seeds = set()
    for name, (rel, _) in nodes.items():
        directory = str(Path(rel).parent.as_posix())
        if rel == "Cargo.toml" and "package" in root_data:
            seeds.add(name)
        if any(Path(directory).match(str(pattern)) for pattern in defaults):
            seeds.add(name)
    workspace_deps = workspace.get("dependencies", {})
    edges = []
    for name, (rel, data) in sorted(nodes.items()):
        tables = [("all-declared-targets", data)]
        tables += [(str(target), table) for target, table in data.get("target", {}).items()]
        for target, table in tables:
            for kind in ("dependencies", "build-dependencies", "dev-dependencies"):
                for alias, spec in sorted(table.get(kind, {}).items()):
                    declared = dict(spec) if isinstance(spec, dict) else {"version": spec}
                    effective = dict(workspace_deps.get(alias, {})) if declared.get("workspace") and isinstance(workspace_deps.get(alias), dict) else dict(declared)
                    effective.update({key: value for key, value in declared.items() if key != "workspace"})
                    dependency = str(effective.get("package", alias))
                    edges.append({"from": name, "to": dependency, "alias": alias, "kind": kind,
                                  "target_predicate": target, "optional": bool(effective.get("optional", False)),
                                  "features": sorted(effective.get("features", [])),
                                  "default_features": bool(effective.get("default-features", True))})
    # A guaranteed unconditional/default-feature lower bound is separate from
    # target/optional-feature potential reachability. Unsupported activation
    # remains UNKNOWN rather than being mislabeled a shipped dependency.
    shipped = set(seeds)
    possible_shipped = set(seeds)
    all_reached = set(seeds)
    for _ in range(len(nodes) + 1):
        next_shipped = shipped | {str(edge["to"]) for edge in edges
                                  if edge["from"] in shipped and edge["kind"] != "dev-dependencies"
                                  and not edge["optional"] and edge["target_predicate"] == "all-declared-targets"
                                  and edge["to"] in nodes}
        next_possible = possible_shipped | {str(edge["to"]) for edge in edges
                          if edge["from"] in possible_shipped and edge["kind"] != "dev-dependencies" and edge["to"] in nodes}
        next_all = all_reached | {str(edge["to"]) for edge in edges
                                 if edge["from"] in all_reached and edge["to"] in nodes}
        if shipped == next_shipped and possible_shipped == next_possible and all_reached == next_all:
            break
        shipped, possible_shipped, all_reached = next_shipped, next_possible, next_all
    results = []
    for package in packages:
        if package not in nodes:
            classification = "UNKNOWN"
        elif package in shipped:
            classification = "shipped-build"
        elif package in possible_shipped:
            classification = "UNKNOWN"
        elif package in all_reached:
            classification = "nonrelease-only"
        else:
            classification = "disconnected"
        results.append(json.dumps({"package": package, "classification": classification,
            "profile": "workspace default-members; unconditional dependencies lower bound; declared target/optional-feature activation UNKNOWN",
            "feature_activation": "default feature declarations retained; conditional forwarding/unification UNKNOWN",
            "target_activation": "all predicates retained symbolically; no host/target cfg inferred",
            "roots": sorted(seeds), "manifest": nodes[package][0] if package in nodes else "UNKNOWN",
            "features": nodes[package][1].get("features", {}) if package in nodes else {},
            "build_targets": nodes[package][1].get("bin", []) if package in nodes else [],
            "dependency_edges": [e for e in edges if e["from"] == package or e["to"] == package],
            "runtime_proof": False, "admission": "unresolved findings block admission even if disconnected"}, sort_keys=True, separators=(",", ":")))
    return sorted(set(inputs)), results


def _cross_file_removal(candidates: list[dict[str, object]]) -> None:
    # Compatibility entry point. Association now requires records (including
    # cleanup-only files); build_inventory calls _associate_sites instead.
    return None


def _build_rows(
    file_records: list[dict[str, object]], candidates: list[dict[str, object]]
) -> list[dict[str, object]]:
    ordered = sorted(
        candidates,
        key=lambda item: (str(item["path"]), str(item["struct_name"]), str(item["field_name"])),
    )
    seen: set[str] = set()
    spans: dict[tuple[str, str, str, str], list[tuple[int, int]]] = {}
    rows: list[dict[str, object]] = []
    for item in ordered:
        key = tuple(str(item[name]) for name in ("package", "path", "struct_name", "field_name"))
        start, end = int(item["span_start"]), int(item["span_end"])
        if any(start <= old_end and old_start <= end for old_start, old_end in spans.get(key, [])):
            raise InventoryError("DUPLICATE_ROW_IDENTITY", "duplicate/overlapping source identity")
        spans.setdefault(key, []).append((start, end))
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
            item["unresolved_evidence"] = sorted(set(item["unresolved_evidence"] + [
                "blocking unresolved growth/ownership: no proven bound and canonical repair issue UNKNOWN"
            ]))
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
        drops = []
        for impl in item["context"]["impls"]:
            if impl["drop"] and impl["qualified"] == item["qualified"]:
                drops.append(f"{item['path']}:{_line(item['context']['masked'], impl['start'])}: exact owner Drop (cleanup effect UNKNOWN)")
        bound_slice = str(item["field_name"]) + " " + str(item["field_type"])
        for detail in item["growth_details"]:
            function = detail["function"]
            bound_slice += " " + str(detail["context"]["masked"])[int(function["body"]):int(function["end"])]
        for function in item["context"]["functions"]:
            if function["owner"] != item["qualified"]:
                continue
            body = str(item["context"]["masked"])[int(function["body"]):int(function["end"])]
            if re.search(r"\bself\s*\.\s*" + re.escape(str(item["field_name"])) + r"\b", body):
                bound_slice += " " + body
        row: dict[str, object] = {
            "id": "c-" + identity_digest[:24],
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
            "creation_site": "; ".join(item["creation_callsites"]) or "UNKNOWN; declaration is not construction",
            "destruction_site": "; ".join(drops) or "UNKNOWN; no exact-owner destructor observed",
            "persistence": persistence,
            "growth_callsites": sorted(growth),
            "removal_callsites": sorted(removal),
            "bound": bound,
            "bound_status": bound_status,
            "cardinality_key": _cardinality_key(str(item["resolved_type"])),
            "cardinality_domain": "UNKNOWN; key type does not bound input domain",
            "cardinality_driver": "distinct keys/elements or repeated append operations",
            "untrusted_key_influence": "UNKNOWN; trace caller/input boundary before policy choice",
            "item_size": "UNKNOWN; allocation and nested payload size require measurement",
            "persistence_amplification": "UNKNOWN; serialization capability observed" if item["serde_signal"] else "UNKNOWN; no durable/restart path established",
            "lock_owner": str(item["owner"]) + "." + str(item["field_name"]) if _concurrency(str(item["resolved_type"])) != "none-observed" else "none-observed",
            "build_classification": str(item.get("build_classification", "UNKNOWN")),
            "risk_security": "UNKNOWN; untrusted key/payload admission requires caller review" if unresolved else "UNKNOWN; static inventory is not security proof",
            "risk_correctness": "UNKNOWN; exhaustion and eviction semantics require owner review",
            "risk_memory": "POTENTIAL unbounded allocation; measure cardinality and item size" if unresolved else "UNKNOWN; static bound does not prove memory budget",
            "risk_disk": "UNKNOWN; durable amplification not established",
            "risk_operational": "UNKNOWN; control lane/degradation behavior requires qualification",
            "affected_boundary": package + "::" + str(item["owner"]) + "." + str(item["field_name"]),
            "experiments_before_policy": "measure admitted key domain, nested item bytes, restart/durable amplification and exhaustion/degradation at the owning boundary" if unresolved else "UNKNOWN; qualify any product resource claim separately",
            "observed_bound_references": sorted(set(re.findall(r"\b(?:policy|quota|budget|capacity|limit|resource_ledger|empirical|versioned)\w*\b", bound_slice, re.I))),
            "unresolved_evidence": list(item["unresolved_evidence"]),
            "concurrency": _concurrency(str(item["resolved_type"])),
            "at_capacity_behavior": "early return before push" if bound_status == "hard" else "UNKNOWN",
            "over_capacity_behavior": "early return before push; no observed mutation" if bound_status == "hard" else "UNKNOWN",
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
    scan_inputs = sorted(set(list(scans) if scans else list(DEFAULT_SCAN + DEFAULT_DISCOVERY_SCAN)))
    if scans and len(scans) != len(set(scans)):
        raise InventoryError("DUPLICATE_SCAN_ROOT", "scan roots must be unique")
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
    external_aliases = {}
    for rel in files:
        try:
            masked = _mask_rust(_read_source(root, root / rel).decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise InventoryError("SOURCE_ENCODING", f"{rel}: source is not UTF-8") from exc
        external_aliases.update(_aliases(masked, _context(masked, rel)))
    for rel in files:
        record, found = _scan_file(root, rel, external_aliases)
        file_records.append(record)
        candidates.extend(found)

    packages = sorted(set(str(record["package"]) for record in file_records))
    cargo_inputs, dependency_classifications = _cargo_metadata(root, packages)
    build_classes = {value["package"]: value["classification"] for value in
                     (json.loads(entry) for entry in dependency_classifications)}
    for candidate in candidates:
        candidate["build_classification"] = build_classes.get(candidate["package"], "UNKNOWN")
    source_pairs = sorted(f"{record['path']}:{record['sha256']}" for record in file_records)
    source_sha = _sha256("\n".join(sorted(source_pairs + cargo_inputs)).encode("utf-8"))
    _associate_sites(file_records, candidates)
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
        "scan_roots": scan_inputs,
        "scan_packages": packages,
        "scan_denominator_packages": len(packages),
        "cargo_inputs": cargo_inputs,
        "dependency_classifications": dependency_classifications,
        "build_targets": ["all-declared-targets-symbolic"],
        "build_features": ["default-features-lower-bound; conditional-activation-UNKNOWN"],
        "dependency_proof_ceiling": "PACKAGE_BUILD_REACHABILITY_ONLY; symbolic potential, not host selection or executable call path",
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
    def value(item: object) -> str:
        if type(item) is int:
            return str(item)
        if isinstance(item, str):
            return _toml_string(item)
        if isinstance(item, list) and all(isinstance(part, str) for part in item):
            return _toml_str_list(item)
        raise InventoryError("MALFORMED_INVENTORY", "unsupported serialized type")
    out = [f"inventory_digest = {value(inventory['inventory_digest'])}", "", "[header]"]
    for key, item in sorted(inventory["header"].items()):
        out.append(f"{key} = {value(item)}")
    if not inventory["rows"]:
        # Empty rows still need an explicit top-level array, before [header].
        out.insert(1, "rows = []")
    for row in inventory["rows"]:
        out += ["", "[[rows]]"]
        for key, item in sorted(row.items()):
            out.append(f"{key} = {value(item)}")
    return ("\n".join(out) + "\n").encode("utf-8")


def _parse_toml(raw: bytes, *, source: str) -> dict[str, object]:
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise InventoryError("MALFORMED_INVENTORY", f"owned TOML is malformed: {source}") from exc
    if not isinstance(value, dict):
        raise InventoryError("MALFORMED_INVENTORY", f"owned TOML must hold a table: {source}")
    return value


HEADER_LIST_KEYS = frozenset("scan_roots scan_packages cargo_inputs dependency_classifications build_targets build_features exclusions classifications".split())
HEADER_INT_KEYS = frozenset("scan_denominator_packages scan_denominator_files scan_denominator_bytes candidate_count classified_count unresolved_count".split())
HEADER_STR_KEYS = frozenset("schema rule_revision tool_version source_sha generation_command coverage_disposition coverage_reason safety_disposition proof_ceiling dependency_proof_ceiling".split())
ROW_LIST_KEYS = frozenset("growth_callsites removal_callsites observed_bound_references unresolved_evidence".split())
ROW_INT_KEYS = frozenset("span_start span_end".split())
ROW_STR_KEYS = frozenset("id package path struct_name field_name field_type source_sha256 span_digest row_digest owner lifetime creation_site destruction_site persistence bound bound_status cardinality_key cardinality_domain cardinality_driver untrusted_key_influence item_size persistence_amplification lock_owner build_classification risk_security risk_correctness risk_memory risk_disk risk_operational affected_boundary experiments_before_policy concurrency at_capacity_behavior over_capacity_behavior classification evidence repair_owner repair_issue invalidation successor_scope".split())


def _digest(value: object) -> str:
    return _sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                              separators=(",", ":")).encode("utf-8"))


def _closed_table(table: object, strings: frozenset[str], integers: frozenset[str],
                  lists: frozenset[str], label: str) -> None:
    if not isinstance(table, dict) or set(table) != strings | integers | lists:
        raise InventoryError("MALFORMED_INVENTORY", f"{label}: missing/extra schema fields")
    for key in strings:
        if not isinstance(table[key], str):
            raise InventoryError("MALFORMED_INVENTORY", f"{label}.{key} must be string")
    for key in integers:
        if type(table[key]) is not int or table[key] < 0:
            raise InventoryError("MALFORMED_INVENTORY", f"{label}.{key} must be nonnegative integer")
    for key in lists:
        if not isinstance(table[key], list) or not all(isinstance(item, str) for item in table[key]):
            raise InventoryError("MALFORMED_INVENTORY", f"{label}.{key} must be string array")


def _validate_artifact(artifact: dict[str, object]) -> tuple[dict[str, object], list[dict[str, object]]]:
    if set(artifact) != {"header", "rows", "inventory_digest"}:
        raise InventoryError("MALFORMED_INVENTORY", "owned TOML must hold header/rows/digest only")
    header, rows = artifact["header"], artifact["rows"]
    _closed_table(header, HEADER_STR_KEYS, HEADER_INT_KEYS, HEADER_LIST_KEYS, "header")
    if not isinstance(rows, list) or not isinstance(artifact["inventory_digest"], str):
        raise InventoryError("MALFORMED_INVENTORY", "rows/digest types are wrong")
    if header["schema"] != SCHEMA:
        raise InventoryError("SCHEMA_MISMATCH", f"schema is not {SCHEMA}")
    if header["rule_revision"] != RULE_REVISION or header["tool_version"] != TOOL_VERSION:
        raise InventoryError("RULE_MISMATCH", "rule/tool revision changed")
    if header["proof_ceiling"] != PROOF_CEILING or header["classifications"] != list(CLASSIFICATIONS):
        raise InventoryError("MALFORMED_INVENTORY", "proof ceiling/vocabulary changed")
    if header["coverage_disposition"] not in ("COMPLETE", "INCOMPLETE"):
        raise InventoryError("MALFORMED_INVENTORY", "coverage disposition is not closed")
    if (header["coverage_disposition"] == "COMPLETE") != (not header["exclusions"]):
        raise InventoryError("MALFORMED_INVENTORY", "coverage/exclusions mismatch")
    for key in HEADER_LIST_KEYS - {"classifications"}:
        if header[key] != sorted(set(header[key])):
            raise InventoryError("MALFORMED_INVENTORY", f"{key} must be sorted and unique")
    if not header["scan_roots"] or not header["scan_denominator_files"]:
        raise InventoryError("MALFORMED_INVENTORY", "empty source denominator")
    if len(header["scan_packages"]) != header["scan_denominator_packages"]:
        raise InventoryError("COUNT_MISMATCH", "package denominator mismatch")
    seen_ids = set()
    identities: dict[tuple[str, str, str, str], list[tuple[int, int]]] = {}
    for row in rows:
        _closed_table(row, ROW_STR_KEYS, ROW_INT_KEYS, ROW_LIST_KEYS, "row")
        if row["classification"] not in CLASSIFICATIONS or row["bound_status"] not in BOUND_STATUSES:
            raise InventoryError("CLASSIFICATION_NOT_CLOSED", "row class/bound status is not closed")
        if row["build_classification"] not in ("shipped-build", "nonrelease-only", "disconnected", "UNKNOWN"):
            raise InventoryError("CLASSIFICATION_NOT_CLOSED", "build classification is not closed")
        if row["id"] in seen_ids:
            raise InventoryError("DUPLICATE_ROW_IDENTITY", "duplicate row id")
        seen_ids.add(row["id"])
        identity = row["package"], row["path"], row["struct_name"], row["field_name"]
        start, end = row["span_start"], row["span_end"]
        if start < 1 or end < start:
            raise InventoryError("MALFORMED_INVENTORY", "invalid source span")
        if any(start <= prior_end and prior_start <= end for prior_start, prior_end in identities.get(identity, [])):
            raise InventoryError("DUPLICATE_ROW_IDENTITY", "duplicate/overlapping source identity")
        identities.setdefault(identity, []).append((start, end))
        if row["package"] not in header["scan_packages"]:
            raise InventoryError("MALFORMED_INVENTORY", "row package outside denominator")
        for key in ("source_sha256", "span_digest", "row_digest"):
            if not re.fullmatch(r"[0-9a-f]{64}", row[key]):
                raise InventoryError("MALFORMED_INVENTORY", f"invalid {key}")
        if _digest({key: value for key, value in row.items() if key != "row_digest"}) != row["row_digest"]:
            raise InventoryError("DIGEST_MISMATCH", "row digest disagrees with content")
        unresolved = row["classification"] in UNRESOLVED_CLASSIFICATIONS
        if unresolved and (row["repair_owner"] != "UNRESOLVED" or row["repair_issue"] != "UNRESOLVED" or row["bound_status"] not in ("none", "unknown")):
            raise InventoryError("MALFORMED_INVENTORY", "unresolved finding cannot clear repair/bound")
    if len(rows) != header["classified_count"] or len(rows) != header["candidate_count"]:
        raise InventoryError("COUNT_MISMATCH", "candidate/classified counts disagree with rows")
    unresolved = sum(row["classification"] in UNRESOLVED_CLASSIFICATIONS for row in rows)
    if unresolved != header["unresolved_count"]:
        raise InventoryError("COUNT_MISMATCH", "unresolved_count disagrees with rows")
    safety = "FINDINGS_REMAIN_BLOCKING" if unresolved else "NO_UNRESOLVED_GROWTH"
    if header["safety_disposition"] != safety:
        raise InventoryError("MALFORMED_INVENTORY", "safety disposition disagrees with findings")
    if not re.fullmatch(r"[0-9a-f]{64}", header["source_sha"]):
        raise InventoryError("MALFORMED_INVENTORY", "invalid source digest")
    if _digest({"header": header, "rows": rows}) != artifact["inventory_digest"]:
        raise InventoryError("DIGEST_MISMATCH", "inventory digest disagrees with content")
    return header, rows


def cmd_sync(root: Path, scans: list[str] | None, generation_command: str) -> int:
    inventory = build_inventory(root, scans, generation_command)
    payload = _emit_toml(inventory)
    root = _root(root)
    target = _inside(root, root / OWNED_TOML)
    for path in (root / OWNED_TOML, *(root / OWNED_TOML).parents):
        if path == root:
            break
        if path.is_symlink():
            raise InventoryError("OUTPUT_UNAVAILABLE", "owned output path contains symlink")
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
    return 0 if header["coverage_disposition"] == "COMPLETE" else 2


def cmd_check(root: Path) -> int:
    root = _root(root)
    target = root / OWNED_TOML
    _inside(root, target)
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
    if header["coverage_disposition"] != "COMPLETE":
        print(json.dumps({"status": "error", "code": "INCOMPLETE_SCAN",
                          "detail": header["coverage_reason"]}, sort_keys=True))
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
