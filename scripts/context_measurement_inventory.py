#!/usr/bin/env python3
"""Deterministic source-bound inventory of serialized-context measurement cases.

Issue: https://github.com/UnknownAlienHuman/eliot-memory-os/issues/866

The inventory is static-source evidence, not authority. It never builds or
runs repository code, never mutates Rust/Cargo sources, never touches the
network or ambient clock, never spawns subprocesses, and never measures,
admits, delivers, or repairs any context payload. ``sync`` atomically writes
exactly one owned TOML artifact; ``check`` is read-only.

Proof ceiling: STATIC_SOURCE_CLASSIFICATION_ONLY. A complete honest
inventory with findings stays explicitly findings-bearing; it must never be
read as a product measured/fit/safe claim. Unresolved rows remain
launch/release blockers until the coordinator links each to a concrete
bounded implementation issue. The scanner proposes rows and successor
scopes only; it creates no GitHub tasks.

Consumer handoffs (residuals, not this issue):
  #783 owns assembly consumption of the exact measurement callback;
  #878 owns the SerializedContextMeasurement contract shape;
  #880 owns capacity/error/observation analysis;
  #704 owns the sole measurement leaf operation.
Issue #785 is explicitly never allocated: it belongs to a different
domain and must not appear in any owner allocation. Consumer work stays
in those issues; this unit only freezes the shared denominator.

Discovery/classification API reuse:
  ``discover_context_measurements`` and ``classify_context_measurement``
  are the single stable entry points. Issue #787 reuses these two
  functions directly (import, never copy) so denominator drift in one
  place invalidates both consumers.

Closed classifications (exactly one per candidate row, 10 total):
  exact-utf8-envelope | normative-stu-estimate |
  serializer-identity-bound | route-identity-bound |
  estimator-policy-unvalidated | capacity-fit-analysis |
  exact-observation | stale-or-absent-observation |
  transformed-observation | test-only

Classification rules (RULE_REVISION 866.1, first match wins, evidence kept):
  1. signal is "#[test]" or "cfg(test)" -> test-only
  2. signal contains "stu_for_bytes" or signal is "StuEstimate" -> normative-stu-estimate
  3. signal in (measure_serialized_context, measure_exact_utf8,
     rendered_utf8_bytes, envelope_digest, declared_len, content_digest,
     payload_utf8, max_serialized_bytes, final_bytes, utf8_bytes,
     ExactUtf8) -> exact-utf8-envelope
  4. signal in (serializer_id, serializer_options_digest, schema_version,
     SerializerIdentity) -> serializer-identity-bound
  5. signal in (route_id, model_id, provider_id, tokenizer_hash,
     tokenizer_config_digest) -> route-identity-bound
  6. signal contains "estimator" or signal is "candidate_digests" -> estimator-policy-unvalidated
  7. signal in (fixed_overhead, output_reserve, review_reserve,
     route_capacity, headroom, proves_fit, receipt_digest, false_safe,
     false_reject) -> capacity-fit-analysis
  8. signal in (ProviderTokenizerRun, observed_tokens,
     TokenizerObservation) -> exact-observation
  9. signal in (Transformed, rewrite, Truncation, Normalization, Rewrite)
     -> transformed-observation
  10. signal in (Stale, Absent, Unavailable, Unsupported, Unknown)
     -> stale-or-absent-observation
  11. otherwise -> fail-closed InventoryError (never silent, never empty success)

Denominator (31 frozen cases, never #785):
  #704 owns 9 leaf cases (exact bytes, STU, envelope, estimator, receipt);
  #783 owns 8 assembly cases (final bytes, envelope verify, identities,
    fit, reserves, ExactUtf8);
  #878 owns 6 contract cases (serializer shape, STU/tokenizer types,
    utf8 helper);
  #880 owns 8 capacity/observation cases (reserves, headroom, exact
    observation, transformed, stale/absent, test-only).
Any denominator source, rule, or owner-map edit changes source_sha,
rule_digest, or owner_digest and therefore fails ``check`` until ``sync``.

Usage:
  python scripts/context_measurement_inventory.py sync --root .
  python scripts/context_measurement_inventory.py check --root .
  python scripts/context_measurement_inventory.py --self-test
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

SCHEMA = "eliot.context-measurement-inventory.v1"
RULE_REVISION = "866.1"
TOOL_VERSION = "0.1.0"
OWNED_TOML = Path(".github/work-units/context-measurement-inventory.toml")
PROOF_CEILING = "STATIC_SOURCE_CLASSIFICATION_ONLY"

CLASSIFICATIONS = (
    "exact-utf8-envelope",
    "normative-stu-estimate",
    "serializer-identity-bound",
    "route-identity-bound",
    "estimator-policy-unvalidated",
    "capacity-fit-analysis",
    "exact-observation",
    "stale-or-absent-observation",
    "transformed-observation",
    "test-only",
)

# Frozen 31-case denominator: (case_ref, owner, source_path, signal).
# Owners are exactly #704, #783, #878, #880. Issue #785 never appears.
# Signals are literal substrings that must be present in the masked source
# at this revision; discovery fails closed when a signal is absent.
DENOMINATOR_CASES: tuple[tuple[str, str, str, str], ...] = (
    ("704/1", "#704", "crates/smart/eliot-context-measurement/src/stu.rs", "stu_for_bytes"),
    ("704/2", "#704", "crates/smart/eliot-context-measurement/src/lib.rs", "measure_serialized_context"),
    ("704/3", "#704", "crates/smart/eliot-context-measurement/src/lib.rs", "measure_exact_utf8"),
    ("704/4", "#704", "crates/smart/eliot-context-measurement/src/envelope.rs", "declared_len"),
    ("704/5", "#704", "crates/smart/eliot-context-measurement/src/envelope.rs", "content_digest"),
    ("704/6", "#704", "crates/smart/eliot-context-measurement/src/lib.rs", "rendered_utf8_bytes"),
    ("704/7", "#704", "crates/smart/eliot-context-measurement/src/lib.rs", "estimator_id"),
    ("704/8", "#704", "crates/smart/eliot-context-measurement/src/lib.rs", "candidate_digests"),
    ("704/9", "#704", "crates/smart/eliot-context-measurement/src/receipt.rs", "receipt_digest"),
    ("783/1", "#783", "crates/smart/eliot-context-assembly/src/measurement.rs", "final_bytes"),
    ("783/2", "#783", "crates/smart/eliot-context-assembly/src/measurement.rs", "envelope_digest"),
    ("783/3", "#783", "crates/smart/eliot-context-assembly/src/measurement.rs", "serializer_id"),
    ("783/4", "#783", "crates/smart/eliot-context-assembly/src/measurement.rs", "route_id"),
    ("783/5", "#783", "crates/smart/eliot-context-assembly/src/measurement.rs", "model_id"),
    ("783/6", "#783", "crates/smart/eliot-context-assembly/src/measurement.rs", "proves_fit"),
    ("783/7", "#783", "crates/smart/eliot-context-assembly/src/measurement.rs", "fixed_overhead"),
    ("783/8", "#783", "crates/smart/eliot-context-assembly/src/measurement.rs", "ExactUtf8"),
    ("878/1", "#878", "crates/smart/eliot-context-contracts/src/measurement.rs", "serializer_id"),
    ("878/2", "#878", "crates/smart/eliot-context-contracts/src/measurement.rs", "serializer_options_digest"),
    ("878/3", "#878", "crates/smart/eliot-context-contracts/src/measurement.rs", "schema_version"),
    ("878/4", "#878", "crates/smart/eliot-context-contracts/src/measurement.rs", "StuEstimate"),
    ("878/5", "#878", "crates/smart/eliot-context-contracts/src/measurement.rs", "TokenizerObservation"),
    ("878/6", "#878", "crates/smart/eliot-context-contracts/src/measurement.rs", "utf8_bytes"),
    ("880/1", "#880", "crates/smart/eliot-context-measurement/src/capacity.rs", "fixed_overhead"),
    ("880/2", "#880", "crates/smart/eliot-context-measurement/src/capacity.rs", "headroom"),
    ("880/3", "#880", "crates/smart/eliot-context-measurement/src/capacity.rs", "observed_tokens"),
    ("880/4", "#880", "crates/smart/eliot-context-measurement/src/observation.rs", "ProviderTokenizerRun"),
    ("880/5", "#880", "crates/smart/eliot-context-measurement/src/observation.rs", "Transformed"),
    ("880/6", "#880", "crates/smart/eliot-context-measurement/src/observation.rs", "Stale"),
    ("880/7", "#880", "crates/smart/eliot-context-measurement/src/observation.rs", "Absent"),
    ("880/8", "#880", "crates/smart/eliot-context-measurement/tests/measurement.rs", "#[test]"),
)

EXPECTED_DENOMINATOR_COUNT = 31

# Per-consumer allocation counts (frozen; sum is 31; #785 never allocated).
OWNER_ALLOCATIONS = (
    ("#704", 9),
    ("#783", 8),
    ("#878", 6),
    ("#880", 8),
)

FORBIDDEN_OWNER = "#785"

# Closed versioned header keys (exact set; any drift fails validation).
HEADER_KEYS = frozenset(
    {
        "schema",
        "rule_revision",
        "tool_version",
        "source_sha",
        "rule_digest",
        "owner_digest",
        "scan_roots",
        "scan_denominator_files",
        "scan_denominator_bytes",
        "candidate_count",
        "classified_count",
        "generation_command",
        "coverage_disposition",
        "coverage_reason",
        "proof_ceiling",
        "exclusions",
        "classifications",
        "owner_allocations",
    }
)

REQUIRED_ROW_KEYS = frozenset(
    {
        "id",
        "case_ref",
        "owner",
        "path",
        "signal",
        "span_start",
        "span_end",
        "source_sha256",
        "span_digest",
        "row_digest",
        "classification",
        "evidence",
        "successor_scope",
        "invalidation",
    }
)


class InventoryError(RuntimeError):
    """Stable fail-closed error carrying a machine-readable reason code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


_CHAR_RE = re.compile(
    r"^(?:b)?'(?:\\x[0-9a-fA-F]{2}|\\u\{[0-9a-fA-F_]{1,6}\}|\\[\\'\"0nrt]|[^\\'\n\r])'"
)
_LIFETIME_RE = re.compile(r"^'[a-zA-Z_][a-zA-Z0-9_]*")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _mask_rust(text: str) -> str:
    """Replace comments and literal bodies with spaces, preserving layout."""
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


def _read_source(root: Path, rel: str) -> bytes:
    resolved = _inside(root, root / rel)
    if resolved.is_symlink() or not resolved.is_file():
        raise InventoryError(
            "SOURCE_NOT_REGULAR_FILE", f"expected a regular non-symlink file: {rel}"
        )
    try:
        return resolved.read_bytes()
    except OSError as exc:
        raise InventoryError("SOURCE_UNREADABLE", f"cannot read source: {rel}") from exc


def _package_of(root: Path, rel: str) -> str:
    """Nearest Cargo package name above the file, else the parent dir."""
    current = _inside(root, root / rel).parent
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
        relative_parent = _inside(root, root / rel).parent.relative_to(root).as_posix()
    except InventoryError:
        return "unknown"
    return relative_parent if relative_parent not in ("", ".") else "unknown"


def _rule_digest() -> str:
    """Digest of the closed rule set (revision + classifications + order)."""
    payload = {
        "rule_revision": RULE_REVISION,
        "classifications": list(CLASSIFICATIONS),
        "forbidden_owner": FORBIDDEN_OWNER,
    }
    return _sha256(_canonical_bytes(payload))


def _owner_digest(cases: tuple[tuple[str, str, str, str], ...]) -> str:
    """Digest of the frozen owner allocation map (sorted, order-free)."""
    grouped: dict[str, list[str]] = {}
    for case_ref, owner, _path, _signal in cases:
        grouped.setdefault(owner, []).append(case_ref)
    canonical = [
        {"owner": owner, "cases": sorted(refs)} for owner, refs in sorted(grouped.items())
    ]
    return _sha256(_canonical_bytes(canonical))


def classify_context_measurement(signal: str, path: str = "") -> tuple[str, str]:
    """Classify one denominator signal into exactly one closed class.

    This is the stable classification API reused by issue #787 (import
    this function, never copy its rules). First match wins; unknown
    signals fail closed with CLASSIFICATION_OPEN instead of inventing a
    class. ``path`` is accepted for future scope evidence and is never
    used to widen a closed class.
    """
    _ = path
    if signal in ("#[test]", "cfg(test)"):
        return (
            "test-only",
            "test marker (#[test]/cfg(test)) in scanned slice; no shipped measurement",
        )
    if "stu_for_bytes" in signal or signal == "StuEstimate":
        return (
            "normative-stu-estimate",
            f"normative STU signal {signal!r}: ceil(bytes/3) estimate, never proves fit",
        )
    if signal in (
        "measure_serialized_context",
        "measure_exact_utf8",
        "rendered_utf8_bytes",
        "envelope_digest",
        "declared_len",
        "content_digest",
        "payload_utf8",
        "max_serialized_bytes",
        "final_bytes",
        "utf8_bytes",
        "ExactUtf8",
    ):
        return (
            "exact-utf8-envelope",
            f"exact envelope signal {signal!r}: final UTF-8 bytes and digest binding",
        )
    if signal in (
        "serializer_id",
        "serializer_options_digest",
        "schema_version",
        "SerializerIdentity",
    ):
        return (
            "serializer-identity-bound",
            f"serializer identity signal {signal!r}: serializer/schema binding",
        )
    if signal in (
        "route_id",
        "model_id",
        "provider_id",
        "tokenizer_hash",
        "tokenizer_config_digest",
    ):
        return (
            "route-identity-bound",
            f"route identity signal {signal!r}: route/provider/model/tokenizer binding",
        )
    if "estimator" in signal or signal == "candidate_digests":
        return (
            "estimator-policy-unvalidated",
            f"estimator signal {signal!r}: UNVALIDATED planning evidence, candidates cited only",
        )
    if signal in (
        "fixed_overhead",
        "output_reserve",
        "review_reserve",
        "route_capacity",
        "headroom",
        "proves_fit",
        "receipt_digest",
        "false_safe",
        "false_reject",
    ):
        return (
            "capacity-fit-analysis",
            f"capacity signal {signal!r}: reserves/fit/headroom/error/receipt binding",
        )
    if signal in ("ProviderTokenizerRun", "observed_tokens", "TokenizerObservation"):
        return (
            "exact-observation",
            f"exact observation signal {signal!r}: actually-run route tokenizer count",
        )
    if signal in ("Transformed", "rewrite", "Truncation", "Normalization", "Rewrite"):
        return (
            "transformed-observation",
            f"transformed signal {signal!r}: provider rewrite evidence, no count comparison",
        )
    if signal in ("Stale", "Absent", "Unavailable", "Unsupported", "Unknown"):
        return (
            "stale-or-absent-observation",
            f"non-exact signal {signal!r}: absent/unavailable/stale/unsupported/unknown, never zero",
        )
    raise InventoryError(
        "CLASSIFICATION_OPEN", f"signal is outside the closed 10-class set: {signal!r}"
    )


def discover_context_measurements(
    root: Path, cases: tuple[tuple[str, str, str, str], ...] | None = None
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Discover one candidate per denominator case (stable API for #787).

    Returns (file_records, candidates). Candidates are sorted by case_ref
    so shuffled input traversal yields identical digests. Each candidate
    carries the source sha, span line, span digest, owner, signal, and
    classified label with evidence. Missing signals, duplicate identities,
    or forbidden owners fail closed.
    """
    root = _root(root)
    selected = tuple(cases) if cases is not None else DENOMINATOR_CASES
    if not selected:
        raise InventoryError("EMPTY_SCAN", "denominator selected no cases; refusing empty coverage")
    # Sort by case_ref for traversal-order independence.
    ordered_cases = sorted(selected, key=lambda item: item[0])
    seen_refs: set[str] = set()
    for case_ref, owner, _path, _signal in ordered_cases:
        if case_ref in seen_refs:
            raise InventoryError("DUPLICATE_ROW_IDENTITY", f"duplicate case_ref: {case_ref}")
        seen_refs.add(case_ref)
        if owner == FORBIDDEN_OWNER:
            raise InventoryError(
                "FORBIDDEN_OWNER", f"owner {FORBIDDEN_OWNER} is never allocated: {case_ref}"
            )
        if owner not in ("#704", "#783", "#878", "#880"):
            raise InventoryError(
                "OWNER_NOT_CLOSED", f"owner is outside the closed consumer set: {owner}"
            )
    # Collect distinct source files in sorted order.
    distinct_rels = sorted({path for _ref, _owner, path, _sig in ordered_cases})
    file_records: list[dict[str, object]] = []
    file_cache: dict[str, dict[str, object]] = {}
    for rel in distinct_rels:
        raw = _read_source(root, rel)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InventoryError("INVALID_RUST_ENCODING", f"source is not UTF-8: {rel}") from exc
        try:
            masked = _mask_rust(text)
        except InventoryError as exc:
            raise InventoryError(exc.code, f"{rel}: {exc.detail}") from exc
        record: dict[str, object] = {
            "path": rel,
            "sha256": _sha256(raw),
            "bytes": len(raw),
            "package": _package_of(root, rel),
            "masked": masked,
            "lines": text.splitlines(),
        }
        file_records.append({k: v for k, v in record.items() if k != "masked" and k != "lines"})
        file_cache[rel] = record
    candidates: list[dict[str, object]] = []
    for case_ref, owner, rel, signal in ordered_cases:
        record = file_cache[rel]
        masked = str(record["masked"])
        lines = list(record["lines"])  # type: ignore[union-attr]
        assert isinstance(masked, str)
        if signal not in masked:
            raise InventoryError(
                "SIGNAL_ABSENT",
                f"denominator signal {signal!r} absent from masked source: {rel} ({case_ref})",
            )
        masked_lines = masked.splitlines()
        span_start = 0
        for lineno, line in enumerate(masked_lines, start=1):
            if signal in line:
                span_start = lineno
                break
        if span_start == 0:
            raise InventoryError(
                "SIGNAL_ABSENT", f"signal has no span line: {signal!r} in {rel}"
            )
        span_end = span_start
        span_text = lines[span_start - 1] if 0 < span_start <= len(lines) else rel
        classification, evidence = classify_context_measurement(signal, rel)
        assert classification in CLASSIFICATIONS, classification
        candidates.append(
            {
                "case_ref": case_ref,
                "owner": owner,
                "path": rel,
                "signal": signal,
                "span_start": span_start,
                "span_end": span_end,
                "source_sha256": str(record["sha256"]),
                "span_digest": _sha256(f"{rel}\n{span_text}".encode("utf-8")),
                "classification": classification,
                "evidence": evidence,
                "package": str(record["package"]),
            }
        )
    # Deterministic candidate order regardless of traversal.
    candidates.sort(key=lambda item: str(item["case_ref"]))
    file_records.sort(key=lambda item: str(item["path"]))
    return file_records, candidates


def _successor_scope(owner: str, case_ref: str, classification: str) -> str:
    if classification == "test-only":
        return "none-required"
    return (
        f"bounded successor scope: consumer {owner} owns case {case_ref} "
        f"({classification}); prove fit/error/receipt in the owning issue"
    )


def _build_rows(
    candidates: list[dict[str, object]],
) -> list[dict[str, object]]:
    ordered = sorted(candidates, key=lambda item: str(item["case_ref"]))
    seen: set[str] = set()
    rows: list[dict[str, object]] = []
    for position, item in enumerate(ordered, start=1):
        identity = (
            f"{item['owner']}|{item['case_ref']}|{item['path']}|{item['signal']}|"
            f"{item['span_start']}"
        )
        identity_digest = _sha256(identity.encode("utf-8"))
        if identity_digest in seen:
            raise InventoryError(
                "DUPLICATE_ROW_IDENTITY", f"duplicate/overlapping row identity: {identity}"
            )
        seen.add(identity_digest)
        classification = str(item["classification"])
        assert classification in CLASSIFICATIONS, classification
        owner = str(item["owner"])
        case_ref = str(item["case_ref"])
        row: dict[str, object] = {
            "id": f"c{position:04d}",
            "case_ref": case_ref,
            "owner": owner,
            "path": str(item["path"]),
            "signal": str(item["signal"]),
            "span_start": int(item["span_start"]),  # type: ignore[arg-type]
            "span_end": int(item["span_end"]),  # type: ignore[arg-type]
            "source_sha256": str(item["source_sha256"]),
            "span_digest": str(item["span_digest"]),
            "classification": classification,
            "evidence": str(item["evidence"]),
            "successor_scope": _successor_scope(owner, case_ref, classification),
            "invalidation": (
                "row invalid when the source span digest, file sha, rule "
                "revision, or owner map changes; rerun sync"
            ),
        }
        row["row_digest"] = _sha256(_canonical_bytes(row))
        rows.append(row)
    return rows


def build_inventory(
    root: Path,
    cases: tuple[tuple[str, str, str, str], ...] | list[tuple[str, str, str, str]] | None,
    generation_command: str,
) -> dict[str, object]:
    """Build the deterministic inventory (sorted, clock-free, fail-closed)."""
    root = _root(root)
    frozen: tuple[tuple[str, str, str, str], ...] | None = None
    if cases is not None:
        frozen = tuple(tuple(item) for item in cases)  # type: ignore[arg-type]
    file_records, candidates = discover_context_measurements(root, frozen)
    if not candidates:
        raise InventoryError("EMPTY_SCAN", "scan yielded no candidates; refusing empty success")
    active_cases = frozen if frozen is not None else DENOMINATOR_CASES
    # Frozen 31-case gate for the default denominator only. Custom fixture
    # denominators (tests/self-test) pass explicit cases and share the same
    # consistency rules without the 31 total, so reduced inputs stay
    # deterministic without empty success.
    if frozen is None:
        if len(active_cases) != EXPECTED_DENOMINATOR_COUNT:
            raise InventoryError(
                "COUNT_MISMATCH",
                f"default denominator holds {len(active_cases)}, expected {EXPECTED_DENOMINATOR_COUNT}",
            )
        if len(candidates) != EXPECTED_DENOMINATOR_COUNT:
            raise InventoryError(
                "COUNT_MISMATCH",
                f"default scan yielded {len(candidates)}, expected {EXPECTED_DENOMINATOR_COUNT}",
            )
    # Source sha over sorted path:sha pairs (no clock, no status).
    source_pairs = sorted(f"{record['path']}:{record['sha256']}" for record in file_records)
    source_sha = _sha256("\n".join(source_pairs).encode("utf-8"))
    rule_digest = _rule_digest()
    owner_digest = _owner_digest(tuple(active_cases))
    rows = _build_rows(candidates)
    # Owner allocation counts in sorted owner order.
    counts: dict[str, int] = {}
    for _ref, owner, _path, _sig in active_cases:
        counts[owner] = counts.get(owner, 0) + 1
    owner_allocations = sorted(f"{owner}:{count}" for owner, count in counts.items())
    scan_roots = sorted({path for _ref, _owner, path, _sig in active_cases})
    coverage: dict[str, object] = {
        "disposition": "COMPLETE",
        "reason": "every denominator case discovered exactly once with a closed class",
    }
    header: dict[str, object] = {
        "schema": SCHEMA,
        "rule_revision": RULE_REVISION,
        "tool_version": TOOL_VERSION,
        "source_sha": source_sha,
        "rule_digest": rule_digest,
        "owner_digest": owner_digest,
        "scan_roots": scan_roots,
        "scan_denominator_files": len(file_records),
        "scan_denominator_bytes": sum(int(record["bytes"]) for record in file_records),  # type: ignore[arg-type]
        "candidate_count": len(candidates),
        "classified_count": len(rows),
        "generation_command": generation_command,
        "coverage_disposition": coverage["disposition"],
        "coverage_reason": coverage["reason"],
        "proof_ceiling": PROOF_CEILING,
        "exclusions": [],
        "classifications": list(CLASSIFICATIONS),
        "owner_allocations": owner_allocations,
    }
    if set(header.keys()) != HEADER_KEYS:
        raise InventoryError("HEADER_NOT_CLOSED", "header keys drifted from the closed set")
    inventory: dict[str, object] = {"header": header, "rows": rows}
    inventory["inventory_digest"] = _sha256(_canonical_bytes(inventory))
    return inventory


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


def _emit_toml(inventory: dict[str, object]) -> bytes:
    header = inventory["header"]
    assert isinstance(header, dict)
    rows = inventory["rows"]
    assert isinstance(rows, list)
    digest = inventory["inventory_digest"]
    assert isinstance(digest, str)
    out: list[str] = []
    out.append(f"inventory_digest = {_toml_string(digest)}")
    out.append("")
    out.append("[header]")
    for key in (
        "schema",
        "rule_revision",
        "tool_version",
        "source_sha",
        "rule_digest",
        "owner_digest",
        "scan_denominator_files",
        "scan_denominator_bytes",
        "candidate_count",
        "classified_count",
        "generation_command",
        "coverage_disposition",
        "coverage_reason",
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
    out.append(f"owner_allocations = {_toml_str_list([str(x) for x in header['owner_allocations']])}")  # type: ignore[union-attr]
    row_keys = (
        "id",
        "case_ref",
        "owner",
        "path",
        "signal",
        "span_start",
        "span_end",
        "source_sha256",
        "span_digest",
        "row_digest",
        "classification",
        "evidence",
        "successor_scope",
        "invalidation",
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
    if set(header.keys()) != HEADER_KEYS:
        raise InventoryError("HEADER_NOT_CLOSED", "header keys are not the closed versioned set")
    for key in (
        "schema",
        "rule_revision",
        "source_sha",
        "rule_digest",
        "owner_digest",
        "scan_roots",
        "scan_denominator_files",
        "candidate_count",
        "classified_count",
        "coverage_disposition",
        "proof_ceiling",
        "classifications",
        "owner_allocations",
    ):
        if key not in header:
            raise InventoryError("MALFORMED_INVENTORY", f"header is missing {key}")
    if header["schema"] != SCHEMA:
        raise InventoryError("SCHEMA_MISMATCH", f"schema is not {SCHEMA}")
    if header["rule_revision"] != RULE_REVISION:
        raise InventoryError("RULE_MISMATCH", f"rule revision is not {RULE_REVISION}")
    if header["rule_digest"] != _rule_digest():
        raise InventoryError("RULE_MISMATCH", "rule digest disagrees with closed rules")
    if list(header["classifications"]) != list(CLASSIFICATIONS):  # type: ignore[union-attr]
        raise InventoryError("CLASSIFICATION_NOT_CLOSED", "classifications drifted from the closed 10")
    if len(set(str(x) for x in header["classifications"])) != 10:  # type: ignore[union-attr]
        raise InventoryError("CLASSIFICATION_NOT_CLOSED", "classifications must hold 10 unique values")
    if header["coverage_disposition"] not in ("COMPLETE", "INCOMPLETE"):
        raise InventoryError("MALFORMED_INVENTORY", "coverage disposition is not closed")
    # Denominator guards: closed owners, never #785, allocations sum to
    # candidate/classified/row counts, never empty. The frozen 31-case
    # total is enforced by build_inventory for the default denominator;
    # custom fixture denominators (tests/self-test) share the same
    # consistency rules with their own non-empty totals so shuffled or
    # reduced inputs stay deterministic without empty success.
    allocations = [str(x) for x in header["owner_allocations"]]  # type: ignore[union-attr]
    total = 0
    seen_owners: set[str] = set()
    for entry in allocations:
        if ":" not in entry:
            raise InventoryError("MALFORMED_INVENTORY", f"owner allocation is malformed: {entry}")
        owner, count_text = entry.split(":", 1)
        if owner == FORBIDDEN_OWNER:
            raise InventoryError("FORBIDDEN_OWNER", f"owner {FORBIDDEN_OWNER} is never allocated")
        if owner not in ("#704", "#783", "#878", "#880"):
            raise InventoryError("OWNER_NOT_CLOSED", f"owner is outside the closed set: {owner}")
        if owner in seen_owners:
            raise InventoryError("MALFORMED_INVENTORY", f"duplicate owner allocation: {owner}")
        seen_owners.add(owner)
        try:
            count = int(count_text)
        except ValueError as exc:
            raise InventoryError("MALFORMED_INVENTORY", f"owner count is not an integer: {entry}") from exc
        total += count
    candidate_count = int(header["candidate_count"])
    classified_count = int(header["classified_count"])
    if total != candidate_count:
        raise InventoryError(
            "COUNT_MISMATCH",
            f"owner allocations sum to {total}, candidate_count is {candidate_count}",
        )
    if classified_count != len(rows):
        raise InventoryError("COUNT_MISMATCH", "classified_count disagrees with row count")
    if candidate_count != classified_count:
        raise InventoryError("COUNT_MISMATCH", "candidate/classified counts disagree")
    if not rows:
        raise InventoryError("EMPTY_SCAN", "empty inventory never succeeds")
    seen: set[str] = set()
    typed_rows: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise InventoryError("MALFORMED_INVENTORY", "row must be a table")
        if set(row.keys()) != REQUIRED_ROW_KEYS:
            raise InventoryError("MALFORMED_INVENTORY", "row keys are not the closed set")
        for key in ("case_ref", "owner", "path", "signal", "classification"):
            if key not in row:
                raise InventoryError("MALFORMED_INVENTORY", f"row is missing {key}")
        classification = row["classification"]
        if classification not in CLASSIFICATIONS:
            raise InventoryError(
                "CLASSIFICATION_NOT_CLOSED",
                f"row classification is not in the closed set: {classification!r}",
            )
        if row["owner"] == FORBIDDEN_OWNER:
            raise InventoryError("FORBIDDEN_OWNER", "row owner is never allocated")
        identity = (
            f"{row.get('owner')}|{row.get('case_ref')}|{row.get('path')}|"
            f"{row.get('signal')}|{row.get('span_start')}"
        )
        identity_digest = _sha256(identity.encode("utf-8"))
        if identity_digest in seen:
            raise InventoryError("DUPLICATE_ROW_IDENTITY", "owned TOML holds duplicated rows")
        seen.add(identity_digest)
        typed_rows.append(row)
    recomputed = _sha256(_canonical_bytes({"header": header, "rows": typed_rows}))
    if recomputed != digest:
        raise InventoryError("DIGEST_MISMATCH", "inventory digest disagrees with content")
    return header, typed_rows


def cmd_sync(root: Path, generation_command: str) -> int:
    inventory = build_inventory(root, None, generation_command)
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
    fresh = build_inventory(root, None, str(header.get("generation_command", "")))
    fresh_raw = _emit_toml(fresh)
    if fresh_raw != stored_raw:
        print(
            json.dumps(
                {
                    "status": "stale",
                    "code": "STALE_ARTIFACT",
                    "detail": "sources, rules, or artifact changed; run sync",
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
                "candidates": header.get("candidate_count"),
                "inventory_digest": artifact.get("inventory_digest"),
                "note": "a findings-bearing inventory stays findings-bearing, never a safety pass",
            },
            sort_keys=True,
        )
    )
    return 0


def run_self_tests() -> int:
    sample = """
    // line comment with stu_for_bytes(
    /* block rendered_utf8_bytes */
    struct Envelope {
        rendered_utf8_bytes: u64,
    }
    fn local() {
        let mut buf: Vec<u8> = Vec::new();
        buf.push(1);
        let s = "rendered_utf8_bytes(";
        let raw = r#"stu_for_bytes"#;
    }
    """
    masked = _mask_rust(sample)
    assert "// line comment" not in masked
    assert "block rendered" not in masked
    assert '"rendered_utf8_bytes(' not in masked
    assert 'stu_for_bytes"#' not in masked
    assert "struct Envelope" in masked
    assert "buf.push" in masked
    for bad in ("/* unclosed", 'let s = "unclosed;', 'let r = r#"unclosed;'):
        try:
            _mask_rust(bad)
        except InventoryError as exc:
            assert exc.code == "MALFORMED_RUST_SOURCE", exc.code
        else:
            raise AssertionError(f"expected fail-closed masking: {bad!r}")

    first = _sha256(_canonical_bytes({"b": 2, "a": [1]}))
    second = _sha256(_canonical_bytes({"a": [1], "b": 2}))
    assert first == second, "digests must be key-order independent"
    assert len(CLASSIFICATIONS) == 10, "closed classification set must hold 10 values"
    assert len(set(CLASSIFICATIONS)) == 10, "classifications must be unique"
    assert len(DENOMINATOR_CASES) == EXPECTED_DENOMINATOR_COUNT, "denominator must hold 31 cases"
    assert sum(count for _owner, count in OWNER_ALLOCATIONS) == EXPECTED_DENOMINATOR_COUNT
    assert all(owner != FORBIDDEN_OWNER for owner, _count in OWNER_ALLOCATIONS)
    assert all(owner != FORBIDDEN_OWNER for _ref, owner, _path, _sig in DENOMINATOR_CASES)
    # Closed owner set check.
    assert {owner for _ref, owner, _path, _sig in DENOMINATOR_CASES} == {
        "#704",
        "#783",
        "#878",
        "#880",
    }
    # Every rule arm resolves to a closed class; unknown fails closed.
    for _ref, _owner, _path, signal in DENOMINATOR_CASES:
        label, evidence = classify_context_measurement(signal)
        assert label in CLASSIFICATIONS, signal
        assert evidence, signal
    try:
        classify_context_measurement("definitely-not-a-measurement-signal-xyz")
    except InventoryError as exc:
        assert exc.code == "CLASSIFICATION_OPEN", exc.code
    else:
        raise AssertionError("expected fail-closed classification for unknown signal")
    assert _rule_digest() == _rule_digest(), "rule digest must be deterministic"
    assert _owner_digest(DENOMINATOR_CASES) == _owner_digest(tuple(reversed(DENOMINATOR_CASES)))

    with tempfile.TemporaryDirectory() as td:
        troot = Path(td).resolve()
        scan = troot / "scan"
        scan.mkdir()
        (scan / "demo.rs").write_text(
            "pub struct Envelope {\n    pub rendered_utf8_bytes: u64,\n}\n",
            encoding="utf-8",
        )
        demo_cases = (("704/9", "#704", "scan/demo.rs", "rendered_utf8_bytes"),)
        first_build = build_inventory(troot, demo_cases, "self-test")
        second_build = build_inventory(troot, demo_cases, "self-test")
        assert _emit_toml(first_build) == _emit_toml(second_build), "build must be deterministic"
        assert int(first_build["header"]["candidate_count"]) == 1  # type: ignore[union-attr]
        round_tripped = _parse_toml(_emit_toml(first_build), source="self-test")
        _validate_artifact(round_tripped)

    print("PASS: context_measurement_inventory self-tests completed successfully")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", choices=("sync", "check"))
    parser.add_argument("--root", type=Path, default=Path("."))
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
            "python scripts/context_measurement_inventory.py sync"
            f" --root {args.root.as_posix()}"
        )
        try:
            return cmd_sync(args.root, generation)
        except InventoryError as exc:
            print(
                json.dumps({"status": "error", "code": exc.code, "detail": exc.detail}, sort_keys=True),
                file=sys.stderr,
            )
            return 2
    if args.command == "check":
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
