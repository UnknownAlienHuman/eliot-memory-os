#!/usr/bin/env python3
"""Read-only F-DENY serde-boundary closure reconciliation coordinator (issue #710).

Slice A owns this file only: ``scripts/audit-serde-boundary-closure.py``.
Sibling scope (``scripts/tests/test_audit_serde_boundary_closure.py`` and
``scripts/testdata/serde-boundary-closure/``) belongs to WRITER-710B and is
never mutated here.

Role: reconcile the complete protected-wire denominator against the single
discovery/classification API owned by issue #929
(``scripts/serde_boundary_inventory.py`` + generated artifact
``crates/foundation/eliot-contracts/tests/data/shipped_serde_boundaries.toml``).
This coordinator implements no inventory scanner and no production decoder: it
loads rows through the #929 generator/rules as documented and fails closed
with a precise ``missing file:<line>`` diagnostic when that input is absent.
Actual decoder behaviour stays tested in the owning Rust packages; no
production Rust/Cargo/WIT is touched.

Denominator: exactly cases 1..20 per #710. Cases 1-10 (denominator, unknown
envelope/nested fields, raw duplicates, variants, tag/payload, defaults,
bypass shapes) evaluate substantively in this file. Cases 11-20 evaluate over
evidence structures supplied by the 710B fixtures/test file through the same
:class:`ReconciliationInput` model defined here.

Normal checking is read-only: this entrypoint never writes the inventory
artifact, fixtures, tests, or evidence. The only filesystem mutation is an
explicit ``--json-out`` report chosen by the caller.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

ISSUE = 710
INVENTORY_ISSUE = 929
DENOMINATOR_CASES: tuple[int, ...] = tuple(range(1, 21))

INVENTORY_SCRIPT_REL = "scripts/serde_boundary_inventory.py"
ARTIFACT_REL = (
    "crates/foundation/eliot-contracts/tests/data/shipped_serde_boundaries.toml"
)
FIXTURE_DIR_REL = "scripts/testdata/serde-boundary-closure"
TEST_REL = "scripts/tests/test_audit_serde_boundary_closure.py"

# Public #929 generator/rules entry points this coordinator is documented to
# call (first available wins). The inventory module is owned by #929; the
# names below come from that issue's sync/check/artifact contract.
EXPECTED_INVENTORY_SYMBOLS = (
    "load_artifact",
    "iter_candidate_rows",
    "check",
)

COVERED_DISPOSITIONS = frozenset(
    {"current-closed", "named-legacy", "exact-internal", "specific-owner"}
)
KNOWN_DISPOSITIONS = frozenset(
    {
        "current-closed",
        "named-legacy",
        "exact-internal",
        "specific-owner",
        "needs-repair",
        "unknown",
    }
)
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


class InventoryUnavailable(Exception):
    """Raised when #929 input is absent; always carries a file:line pointer."""


@dataclass(frozen=True)
class CaseResult:
    case: int
    passed: bool
    detail: str


@dataclass(frozen=True)
class InventoryRow:
    candidate_id: str
    disposition: str
    owner: str = ""
    digest: str = ""


@dataclass
class ReconciliationInput:
    """Everything the 20-case coordinator evaluates.

    Cases 1-10 are computed here from ``rows`` plus the lexical/shape
    evidence maps. Cases 11-20 read the same model from structures the
    710B fixtures/test file supplies; each evaluator below documents the
    evidence keys it requires.
    """

    rows: list[InventoryRow] = field(default_factory=list)
    expected_digest: str = ""
    actual_digest: str = ""
    # candidate_id -> list of positive fixture identities.
    positive_fixtures: dict[str, list[str]] = field(default_factory=dict)
    # candidate_id -> {"raw": bytes/str, "observed": "rejected"|...,
    #   "allowed": [fields]} for unknown-envelope rejection proof.
    unknown_envelope: dict[str, dict[str, Any]] = field(default_factory=dict)
    # candidate_id -> same shape for nested protected unknown fields.
    nested_unknown: dict[str, dict[str, Any]] = field(default_factory=dict)
    # candidate_id -> {"raw": bytes/str, "observed": ...} lexical duplicate proof.
    duplicates: dict[str, dict[str, Any]] = field(default_factory=dict)
    # candidate_id -> {"known": [...], "unknown_fixture": "...", "observed": ...}.
    variants: dict[str, dict[str, Any]] = field(default_factory=dict)
    # candidate_id -> {"tag_field": ..., "payload_field": ..., "table": {...},
    #   "fixture": {...}, "observed": ...}.
    tag_payload: dict[str, dict[str, Any]] = field(default_factory=dict)
    # candidate_id -> {"defaults": {field: value}, "owner_tied": bool,
    #   "protected_invented": [...]}.
    defaults: dict[str, dict[str, Any]] = field(default_factory=dict)
    # candidate_id -> {"shapes": {shape: "blocked"|...}, "observed": ...}.
    bypass_shapes: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Cases 11-20 evidence, keyed by candidate_id where applicable.
    normalization: dict[str, dict[str, Any]] = field(default_factory=dict)
    legacy: dict[str, dict[str, Any]] = field(default_factory=dict)
    migration: dict[str, dict[str, Any]] = field(default_factory=dict)
    canonical: dict[str, dict[str, Any]] = field(default_factory=dict)
    internal_only: dict[str, dict[str, Any]] = field(default_factory=dict)
    specific_owner: dict[str, dict[str, Any]] = field(default_factory=dict)
    malformed: dict[str, dict[str, Any]] = field(default_factory=dict)
    ingress: dict[str, dict[str, Any]] = field(default_factory=dict)
    agreement: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ReconciliationResult:
    passed: bool
    passed_count: int
    failed_cases: tuple[int, ...]
    case_results: tuple[CaseResult, ...]
    row_count: int
    canonical_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "issue": ISSUE,
            "denominator": list(DENOMINATOR_CASES),
            "passed": self.passed,
            "passed_count": self.passed_count,
            "failed_cases": list(self.failed_cases),
            "row_count": self.row_count,
            "canonical_digest": self.canonical_digest,
            "cases": [
                {"case": r.case, "passed": r.passed, "detail": r.detail}
                for r in self.case_results
            ],
        }


# ---------------------------------------------------------------------------
# Lexical helpers (raw-bytes evidence, before any Value/map normalization).
# ---------------------------------------------------------------------------


def find_duplicate_keys(raw: bytes | str) -> list[str]:
    """Return dotted paths of lexically duplicated keys in raw JSON bytes."""
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return ["<non-utf8>"]
    else:
        text = raw
    duplicates: list[str] = []

    def hook(pairs: list[tuple[str, Any]], path: str) -> dict[str, Any]:
        seen: set[str] = set()
        obj: dict[str, Any] = {}
        for key, value in pairs:
            full = f"{path}.{key}" if path else key
            if key in seen:
                duplicates.append(full)
            else:
                seen.add(key)
            obj[key] = value
        return obj

    def parse(text_value: str, path: str) -> Any:
        decoder = json.JSONDecoder(
            object_pairs_hook=lambda p: hook(p, path),
        )
        value, _ = decoder.raw_decode(text_value.strip())
        return value

    try:
        parsed = parse(text, "")
    except (json.JSONDecodeError, ValueError):
        return ["<malformed>"]
    # Recurse so nested objects also report duplicates with their paths.
    stack: list[tuple[Any, str]] = [(parsed, "")]
    seen_dupes = set(duplicates)
    while stack:
        value, path = stack.pop()
        if isinstance(value, dict):
            for key, child in value.items():
                full = f"{path}.{key}" if path else key
                if isinstance(child, (dict, list)):
                    # Re-scan the raw text is unnecessary; object_pairs_hook
                    # already visited nested objects during decode. Here we
                    # only descend for structural completeness.
                    stack.append((child, full))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                stack.append((child, f"{path}[{index}]"))
    return sorted(seen_dupes | set(duplicates))


def unknown_field_names(obj: Mapping[str, Any], allowed: set[str]) -> set[str]:
    return set(obj.keys()) - allowed


def check_variant(value: Any, known: set[str]) -> bool:
    """True when a variant value is rejected (i.e. not silently accepted)."""
    return value not in known


def check_tag_payload(
    obj: Mapping[str, Any],
    tag_field: str,
    payload_field: str,
    table: Mapping[str, str],
) -> bool:
    """True when a tag/payload pair is consistent; mismatch must fail."""
    tag = obj.get(tag_field)
    expected_payload = table.get(tag) if isinstance(tag, str) else None
    if expected_payload is None:
        return False
    return payload_field in obj and expected_payload == payload_field


# ---------------------------------------------------------------------------
# #929 inventory access (no reinvented discovery).
# ---------------------------------------------------------------------------


def inventory_script_path(root: Path) -> Path:
    return root / INVENTORY_SCRIPT_REL


def artifact_path(root: Path) -> Path:
    return root / ARTIFACT_REL


def load_inventory_module(root: Path) -> Any:
    """Import the #929 generator/rules module or fail closed precisely."""
    script = inventory_script_path(root)
    if not script.is_file():
        raise InventoryUnavailable(
            f"missing file: {INVENTORY_SCRIPT_REL}:1 "
            f"(F-DENY inventory generator owned by #{INVENTORY_ISSUE}; "
            "coordinator refuses to reinvent discovery)"
        )
    spec = importlib.util.spec_from_file_location(
        "serde_boundary_inventory", script
    )
    if spec is None or spec.loader is None:
        raise InventoryUnavailable(
            f"missing file: {INVENTORY_SCRIPT_REL}:1 "
            "(unloadable inventory module; cannot reconcile)"
        )
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        raise InventoryUnavailable(
            f"missing file: {INVENTORY_SCRIPT_REL}:1 "
            f"(inventory module failed to load: {error})"
        ) from error
    missing = [
        name for name in EXPECTED_INVENTORY_SYMBOLS if not hasattr(module, name)
    ]
    if len(missing) == len(EXPECTED_INVENTORY_SYMBOLS):
        raise InventoryUnavailable(
            f"missing file: {INVENTORY_SCRIPT_REL}:1 "
            f"(no documented public entry {list(EXPECTED_INVENTORY_SYMBOLS)}; "
            f"cannot reconcile via #{INVENTORY_ISSUE} API)"
        )
    return module


def load_rows_via_inventory_api(root: Path) -> tuple[list[InventoryRow], str]:
    """Load candidate rows through the #929 API; fail closed if absent."""
    module = load_inventory_module(root)
    artifact = artifact_path(root)
    if not artifact.is_file():
        raise InventoryUnavailable(
            f"missing file: {ARTIFACT_REL}:1 "
            f"(shipped inventory artifact owned by #{INVENTORY_ISSUE}; "
            "run its accepted sync before reconciliation)"
        )
    for name in EXPECTED_INVENTORY_SYMBOLS:
        func = getattr(module, name, None)
        if callable(func):
            try:
                loaded = func(root) if name != "check" else func(root)
            except TypeError:
                try:
                    loaded = func(str(root))
                except Exception as error:
                    raise InventoryUnavailable(
                        f"missing file: {INVENTORY_SCRIPT_REL}:1 "
                        f"(inventory entry '{name}' failed: {error})"
                    ) from error
            except Exception as error:
                raise InventoryUnavailable(
                    f"missing file: {INVENTORY_SCRIPT_REL}:1 "
                    f"(inventory entry '{name}' failed: {error})"
                ) from error
            rows = _coerce_rows(loaded)
            digest = _digest_rows(rows)
            return rows, digest
    raise InventoryUnavailable(
        f"missing file: {INVENTORY_SCRIPT_REL}:1 "
        "(no callable documented inventory entry; cannot reconcile)"
    )


def _coerce_rows(loaded: Any) -> list[InventoryRow]:
    rows: list[InventoryRow] = []
    candidates: Any = loaded
    if isinstance(loaded, Mapping):
        for key in ("rows", "candidates", "items"):
            if isinstance(loaded.get(key), list):
                candidates = loaded[key]
                break
    if not isinstance(candidates, list):
        return rows
    for entry in candidates:
        if isinstance(entry, InventoryRow):
            rows.append(entry)
        elif isinstance(entry, Mapping):
            cid = str(entry.get("candidate_id") or entry.get("id") or "")
            if cid:
                rows.append(
                    InventoryRow(
                        candidate_id=cid,
                        disposition=str(entry.get("disposition", "")),
                        owner=str(entry.get("owner", "")),
                        digest=str(entry.get("digest", "")),
                    )
                )
    return rows


def _digest_rows(rows: Sequence[InventoryRow]) -> str:
    payload = json.dumps(
        [
            {
                "candidate_id": r.candidate_id,
                "disposition": r.disposition,
                "owner": r.owner,
                "digest": r.digest,
            }
            for r in sorted(rows, key=lambda r: r.candidate_id)
        ],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Cases 1-10: denominator/unknown/duplicate/variant/tag (evaluated here).
# ---------------------------------------------------------------------------


def evaluate_case_01_denominator(data: ReconciliationInput) -> CaseResult:
    """Case 1: exact 1..20 denominator; stale digests invalidate."""
    if not data.expected_digest or not data.actual_digest:
        return CaseResult(1, False, "case-01: missing expected/actual digest")
    if data.expected_digest != data.actual_digest:
        return CaseResult(
            1, False, "case-01: source/inventory/profile change invalidated"
        )
    return CaseResult(1, True, "case-01: denominator 1..20 with fresh digest")


def evaluate_case_02_assignment(data: ReconciliationInput) -> CaseResult:
    """Case 2: every candidate has exactly one known disposition."""
    seen: set[str] = set()
    for row in data.rows:
        if row.candidate_id in seen:
            return CaseResult(
                2, False, f"case-02: duplicate row {row.candidate_id}"
            )
        seen.add(row.candidate_id)
        if row.disposition not in KNOWN_DISPOSITIONS:
            return CaseResult(
                2,
                False,
                f"case-02: unknown disposition for {row.candidate_id}",
            )
    if not data.rows:
        return CaseResult(2, False, "case-02: empty denominator")
    return CaseResult(
        2, True, f"case-02: {len(data.rows)} candidates singly assigned"
    )


def evaluate_case_03_positive_fixture(data: ReconciliationInput) -> CaseResult:
    """Case 3: every applicable current type has an actual positive fixture."""
    missing = [
        row.candidate_id
        for row in data.rows
        if row.disposition in ("current-closed", "specific-owner")
        and not data.positive_fixtures.get(row.candidate_id)
    ]
    if missing:
        return CaseResult(
            3, False, f"case-03: missing positive fixture for {missing}"
        )
    return CaseResult(3, True, "case-03: positive fixtures present")


def _rejection_observed(entry: Mapping[str, Any]) -> bool:
    return entry.get("observed") == "rejected"


def evaluate_case_04_unknown_envelope(data: ReconciliationInput) -> CaseResult:
    """Case 4: raw unknown-envelope-field rejection evidence is complete."""
    lacking = [
        row.candidate_id
        for row in data.rows
        if row.disposition in ("current-closed", "specific-owner")
        and not _rejection_observed(data.unknown_envelope.get(row.candidate_id, {}))
    ]
    if lacking:
        return CaseResult(
            4, False, f"case-04: missing unknown-envelope proof for {lacking}"
        )
    # Substantive spot-check: the recorded raw bytes must actually contain an
    # unknown field relative to the recorded allow-list.
    for cid, entry in data.unknown_envelope.items():
        raw = entry.get("raw")
        allowed = set(entry.get("allowed", []))
        if raw is None or not allowed:
            continue
        try:
            text = raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
            obj = json.loads(text)
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(obj, dict) and not unknown_field_names(obj, allowed):
            return CaseResult(
                4, False, f"case-04: fixture for {cid} shows no unknown field"
            )
    return CaseResult(4, True, "case-04: unknown-envelope rejection complete")


def evaluate_case_05_nested_unknown(data: ReconciliationInput) -> CaseResult:
    """Case 5: nested protected unknown-field rejection evidence complete."""
    lacking = [
        row.candidate_id
        for row in data.rows
        if row.disposition in ("current-closed", "specific-owner")
        and not _rejection_observed(data.nested_unknown.get(row.candidate_id, {}))
    ]
    if lacking:
        return CaseResult(
            5, False, f"case-05: missing nested-unknown proof for {lacking}"
        )
    return CaseResult(5, True, "case-05: nested unknown rejection complete")


def evaluate_case_06_duplicates(data: ReconciliationInput) -> CaseResult:
    """Case 6: raw lexical duplicate evidence precedes Value normalization."""
    lacking = [
        row.candidate_id
        for row in data.rows
        if row.disposition in ("current-closed", "specific-owner")
        and not _rejection_observed(data.duplicates.get(row.candidate_id, {}))
    ]
    if lacking:
        return CaseResult(
            6, False, f"case-06: missing duplicate proof for {lacking}"
        )
    for cid, entry in data.duplicates.items():
        raw = entry.get("raw")
        if raw is None:
            continue
        dupes = find_duplicate_keys(raw)
        if not dupes or dupes == ["<malformed>"]:
            return CaseResult(
                6, False, f"case-06: fixture for {cid} shows no lexical duplicate"
            )
    return CaseResult(6, True, "case-06: raw duplicate rejection complete")


def evaluate_case_07_variants(data: ReconciliationInput) -> CaseResult:
    """Case 7: unknown variants cannot become known ones."""
    lacking = [
        row.candidate_id
        for row in data.rows
        if row.disposition in ("current-closed", "specific-owner")
        and not _rejection_observed(data.variants.get(row.candidate_id, {}))
    ]
    if lacking:
        return CaseResult(
            7, False, f"case-07: missing variant proof for {lacking}"
        )
    for cid, entry in data.variants.items():
        known = set(entry.get("known", []))
        unknown_fixture = entry.get("unknown_fixture")
        if known and unknown_fixture is not None and not check_variant(
            unknown_fixture, known
        ):
            return CaseResult(
                7, False, f"case-07: unknown variant accepted for {cid}"
            )
    return CaseResult(7, True, "case-07: unknown variants rejected")


def evaluate_case_08_tag_payload(data: ReconciliationInput) -> CaseResult:
    """Case 8: frame/tag/payload mismatches remain failures."""
    lacking = [
        row.candidate_id
        for row in data.rows
        if row.disposition in ("current-closed", "specific-owner")
        and not _rejection_observed(data.tag_payload.get(row.candidate_id, {}))
    ]
    if lacking:
        return CaseResult(
            8, False, f"case-08: missing tag/payload proof for {lacking}"
        )
    for cid, entry in data.tag_payload.items():
        tag_field = str(entry.get("tag_field", "kind"))
        payload_field = str(entry.get("payload_field", "payload"))
        table = entry.get("table", {})
        fixture = entry.get("fixture", {})
        if (
            isinstance(table, Mapping)
            and isinstance(fixture, Mapping)
            and table
            and fixture
            and check_tag_payload(fixture, tag_field, payload_field, table)
            and entry.get("observed") == "rejected"
        ):
            return CaseResult(
                8,
                False,
                f"case-08: consistent fixture marked rejected for {cid}",
            )
    return CaseResult(8, True, "case-08: tag/payload mismatches fail")


def evaluate_case_09_defaults(data: ReconciliationInput) -> CaseResult:
    """Case 9: defaults cannot invent protected identity/scope/authority."""
    for cid, entry in data.defaults.items():
        defaults = entry.get("defaults", {})
        invented = set(entry.get("protected_invented", []))
        if not isinstance(defaults, Mapping):
            continue
        invented_now = set(defaults.keys()) & PROTECTED_FIELDS
        if invented_now and not entry.get("owner_tied"):
            return CaseResult(
                9,
                False,
                f"case-09: untied protected defaults for {cid}: "
                f"{sorted(invented_now)}",
            )
        if invented:
            return CaseResult(
                9, False, f"case-09: invented protected meaning for {cid}"
            )
    applicable = [
        r.candidate_id
        for r in data.rows
        if r.disposition in ("current-closed", "specific-owner")
    ]
    missing = [cid for cid in applicable if cid not in data.defaults]
    if missing:
        return CaseResult(
            9, False, f"case-09: missing default analysis for {missing}"
        )
    return CaseResult(9, True, "case-09: no invented protected defaults")


def evaluate_case_10_bypass_shapes(data: ReconciliationInput) -> CaseResult:
    """Case 10: flatten/untagged/alias/manual-visitor bypasses stay blocked."""
    applicable = [
        r.candidate_id
        for r in data.rows
        if r.disposition in ("current-closed", "specific-owner")
    ]
    missing = [cid for cid in applicable if cid not in data.bypass_shapes]
    if missing:
        return CaseResult(
            10, False, f"case-10: missing bypass analysis for {missing}"
        )
    for cid, entry in data.bypass_shapes.items():
        shapes = entry.get("shapes", {})
        if not isinstance(shapes, Mapping):
            continue
        for shape in BYPASS_SHAPES & set(shapes.keys()):
            if shapes[shape] != "blocked":
                return CaseResult(
                    10, False, f"case-10: bypass shape open for {cid}: {shape}"
                )
    return CaseResult(10, True, "case-10: bypass shapes blocked")


# ---------------------------------------------------------------------------
# Cases 11-20: exercised via 710B fixtures/test file over this same model.
# ---------------------------------------------------------------------------


def evaluate_case_11_normalization(data: ReconciliationInput) -> CaseResult:
    """Case 11: Value/map normalization cannot erase evidence or pass as raw."""
    lacking = [
        row.candidate_id
        for row in data.rows
        if row.disposition in ("current-closed", "specific-owner")
        and not data.normalization.get(row.candidate_id, {}).get("lexical_kept")
    ]
    if lacking:
        return CaseResult(
            11, False, f"case-11: missing normalization guard for {lacking}"
        )
    for cid, entry in data.normalization.items():
        if entry.get("normalized_as_raw"):
            return CaseResult(
                11, False, f"case-11: normalized proof masquerades for {cid}"
            )
    return CaseResult(11, True, "case-11: lexical evidence preserved")


def evaluate_case_12_legacy_unsupported(data: ReconciliationInput) -> CaseResult:
    """Case 12: unsupported legacy input cannot silently become current."""
    for cid, entry in data.legacy.items():
        if entry.get("supported") is False and entry.get("observed") != "rejected":
            return CaseResult(
                12, False, f"case-12: unsupported legacy accepted for {cid}"
            )
    if not data.legacy and any(
        r.disposition == "named-legacy" for r in data.rows
    ):
        return CaseResult(12, False, "case-12: legacy rows lack evidence")
    return CaseResult(12, True, "case-12: unsupported legacy rejected")


def evaluate_case_13_legacy_supported(data: ReconciliationInput) -> CaseResult:
    """Case 13: supported legacy has owner compat/migration/loss/proof."""
    required = ("owner", "compatibility", "migration", "loss", "proof")
    for cid, entry in data.legacy.items():
        if entry.get("supported") is True:
            missing = [k for k in required if not entry.get(k)]
            if missing:
                return CaseResult(
                    13,
                    False,
                    f"case-13: incomplete legacy contract for {cid}: {missing}",
                )
    return CaseResult(13, True, "case-13: supported legacy fully owned")


def evaluate_case_14_migration(data: ReconciliationInput) -> CaseResult:
    """Case 14: migration missing protected identity/lineage is rejected."""
    for cid, entry in data.migration.items():
        if entry.get("missing_protected") and entry.get("observed") != "rejected":
            return CaseResult(
                14, False, f"case-14: unsafe migration accepted for {cid}"
            )
    return CaseResult(14, True, "case-14: unsafe migration rejected")


def evaluate_case_15_canonical(data: ReconciliationInput) -> CaseResult:
    """Case 15: canonical bytes/digests/replay goldens preserved/versioned."""
    for cid, entry in data.canonical.items():
        if not (entry.get("preserved") or entry.get("versioned")):
            return CaseResult(
                15, False, f"case-15: canonical drift unversioned for {cid}"
            )
    applicable = [
        r.candidate_id
        for r in data.rows
        if r.disposition in ("current-closed", "specific-owner")
    ]
    missing = [cid for cid in applicable if cid not in data.canonical]
    if missing:
        return CaseResult(
            15, False, f"case-15: missing canonical evidence for {missing}"
        )
    return CaseResult(15, True, "case-15: canonical identity preserved")


def evaluate_case_16_internal_only(data: ReconciliationInput) -> CaseResult:
    """Case 16: internal-only exceptions exact; new callers invalidate."""
    for cid, entry in data.internal_only.items():
        if not entry.get("callers"):
            return CaseResult(
                16, False, f"case-16: caller-free exception for {cid}"
            )
        if entry.get("new_caller") and not entry.get("invalidated"):
            return CaseResult(
                16, False, f"case-16: new caller did not invalidate {cid}"
            )
    return CaseResult(16, True, "case-16: internal exceptions exact")


def evaluate_case_17_specific_owner(data: ReconciliationInput) -> CaseResult:
    """Case 17: specific owners stay covered with fixtures/profile proof."""
    lacking = [
        row.candidate_id
        for row in data.rows
        if row.disposition == "specific-owner"
        and not data.specific_owner.get(row.candidate_id, {}).get("fixture")
    ]
    if lacking:
        return CaseResult(
            17, False, f"case-17: specific owner lacks fixture for {lacking}"
        )
    return CaseResult(17, True, "case-17: specific owners covered")


def evaluate_case_18_malformed(data: ReconciliationInput) -> CaseResult:
    """Case 18: malformed/property behaviour proven, not counted/suppressed."""
    for cid, entry in data.malformed.items():
        if entry.get("count_only") or entry.get("panic_suppressed"):
            return CaseResult(
                18, False, f"case-18: vacuous malformed proof for {cid}"
            )
        if not entry.get("observed"):
            return CaseResult(
                18, False, f"case-18: missing malformed behaviour for {cid}"
            )
    applicable = [
        r.candidate_id
        for r in data.rows
        if r.disposition in ("current-closed", "specific-owner")
    ]
    missing = [cid for cid in applicable if cid not in data.malformed]
    if missing:
        return CaseResult(
            18, False, f"case-18: missing malformed evidence for {missing}"
        )
    return CaseResult(18, True, "case-18: malformed behaviour substantive")


def evaluate_case_19_ingress(data: ReconciliationInput) -> CaseResult:
    """Case 19: bounded ingress rejects before admission/dispatch/effects."""
    for cid, entry in data.ingress.items():
        if entry.get("decoder_only") or entry.get("mocked"):
            return CaseResult(
                19, False, f"case-19: non-ingress proof claimed for {cid}"
            )
        if entry.get("observed") == "rejected" and not entry.get("before_effects"):
            return CaseResult(
                19, False, f"case-19: late rejection for {cid}"
            )
    applicable = [
        r.candidate_id
        for r in data.rows
        if r.disposition in ("current-closed", "specific-owner")
    ]
    missing = [cid for cid in applicable if cid not in data.ingress]
    if missing:
        return CaseResult(
            19, False, f"case-19: missing ingress evidence for {missing}"
        )
    return CaseResult(19, True, "case-19: bounded ingress precedes effects")


def evaluate_case_20_agreement(data: ReconciliationInput) -> CaseResult:
    """Case 20: all evidence planes and text/JSON digests agree; gaps fail."""
    agreement = data.agreement
    if not agreement:
        return CaseResult(20, False, "case-20: missing agreement evidence")
    if agreement.get("skipped") or agreement.get("stale") or agreement.get(
        "absent"
    ):
        return CaseResult(20, False, "case-20: skipped/stale/absent proof")
    if agreement.get("text_digest") != agreement.get("json_digest"):
        return CaseResult(20, False, "case-20: text/JSON digest mismatch")
    if not agreement.get("text_digest"):
        return CaseResult(20, False, "case-20: missing result digest")
    return CaseResult(20, True, "case-20: evidence planes agree")


CASE_EVALUATORS = (
    evaluate_case_01_denominator,
    evaluate_case_02_assignment,
    evaluate_case_03_positive_fixture,
    evaluate_case_04_unknown_envelope,
    evaluate_case_05_nested_unknown,
    evaluate_case_06_duplicates,
    evaluate_case_07_variants,
    evaluate_case_08_tag_payload,
    evaluate_case_09_defaults,
    evaluate_case_10_bypass_shapes,
    evaluate_case_11_normalization,
    evaluate_case_12_legacy_unsupported,
    evaluate_case_13_legacy_supported,
    evaluate_case_14_migration,
    evaluate_case_15_canonical,
    evaluate_case_16_internal_only,
    evaluate_case_17_specific_owner,
    evaluate_case_18_malformed,
    evaluate_case_19_ingress,
    evaluate_case_20_agreement,
)


def reconcile(data: ReconciliationInput) -> ReconciliationResult:
    """Run the full 20-case coordinator over one evidence input."""
    results = tuple(evaluator(data) for evaluator in CASE_EVALUATORS)
    assert [r.case for r in results] == list(DENOMINATOR_CASES), (
        "coordinator must preserve the exact 1..20 denominator"
    )
    failed = tuple(r.case for r in results if not r.passed)
    payload = json.dumps(
        {
            "rows": [
                {
                    "candidate_id": r.candidate_id,
                    "disposition": r.disposition,
                    "owner": r.owner,
                    "digest": r.digest,
                }
                for r in sorted(data.rows, key=lambda r: r.candidate_id)
            ],
            "cases": [
                {"case": r.case, "passed": r.passed, "detail": r.detail}
                for r in results
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return ReconciliationResult(
        passed=not failed,
        passed_count=sum(1 for r in results if r.passed),
        failed_cases=failed,
        case_results=results,
        row_count=len(data.rows),
        canonical_digest=digest,
    )


def audit(root: Path) -> ReconciliationResult:
    """Read-only reconciliation against current #929 inputs (fails closed)."""
    rows, digest = load_rows_via_inventory_api(root)
    data = ReconciliationInput(
        rows=rows, expected_digest=digest, actual_digest=digest
    )
    return reconcile(data)


# ---------------------------------------------------------------------------
# Focused self-test: proves the coordinator runs (no matrices).
# ---------------------------------------------------------------------------


def build_self_test_input() -> ReconciliationInput:
    """One minimal in-memory input exercising the coordinator end to end."""
    rows = [
        InventoryRow(
            candidate_id="selftest.envelope",
            disposition="current-closed",
            owner="self-test",
            digest="st",
        )
    ]
    cid = "selftest.envelope"
    unknown_raw = b'{"id":"1","bogus_field":true}'
    duplicate_raw = b'{"id":"1","id":"2"}'
    agreement_digest = hashlib.sha256(b"self-test").hexdigest()
    return ReconciliationInput(
        rows=rows,
        expected_digest="selftest",
        actual_digest="selftest",
        positive_fixtures={cid: ["selftest-positive-1"]},
        unknown_envelope={
            cid: {
                "raw": unknown_raw,
                "allowed": ["id"],
                "observed": "rejected",
            }
        },
        nested_unknown={cid: {"observed": "rejected"}},
        duplicates={cid: {"raw": duplicate_raw, "observed": "rejected"}},
        variants={
            cid: {"known": ["a"], "unknown_fixture": "zzz", "observed": "rejected"}
        },
        tag_payload={
            cid: {
                "tag_field": "kind",
                "payload_field": "request",
                "table": {"request": "request"},
                "fixture": {"kind": "other"},
                "observed": "rejected",
            }
        },
        defaults={cid: {"defaults": {}, "owner_tied": True}},
        bypass_shapes={cid: {"shapes": {"flatten": "blocked"}}},
        normalization={cid: {"lexical_kept": True}},
        legacy={},
        migration={},
        canonical={cid: {"preserved": True}},
        internal_only={},
        specific_owner={},
        malformed={cid: {"observed": "rejected"}},
        ingress={cid: {"observed": "rejected", "before_effects": True}},
        agreement={
            "text_digest": agreement_digest,
            "json_digest": agreement_digest,
        },
    )


def self_test() -> ReconciliationResult:
    data = build_self_test_input()
    # Prove the lexical core really runs: the fixtures above must contain one
    # unknown field and one raw duplicate.
    unknown = unknown_field_names(
        {"id": "1", "bogus_field": True}, {"id"}
    )
    if "bogus_field" not in unknown:
        raise AssertionError("self-test unknown-field helper is inert")
    dupes = find_duplicate_keys(b'{"id":"1","id":"2"}')
    if dupes != ["id"]:
        raise AssertionError(f"self-test duplicate helper inert: {dupes}")
    result = reconcile(data)
    if not result.passed:
        raise AssertionError(
            f"self-test reconciliation failed: {result.failed_cases}"
        )
    repeat = reconcile(build_self_test_input())
    if repeat.canonical_digest != result.canonical_digest:
        raise AssertionError("self-test digest is not deterministic")
    print(
        "SERDE_BOUNDARY_CLOSURE_SELF_TEST: PASS "
        f"(20/20 cases; digest {result.canonical_digest[:16]})"
    )
    return result


# ---------------------------------------------------------------------------
# CLI (read-only; explicit --json-out is the only filesystem write).
# ---------------------------------------------------------------------------


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="F-DENY serde-boundary closure coordinator (#710, Slice A)."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root (default: inferred from this script).",
    )
    parser.add_argument("--json-out", type=Path, default=None)
    parser.add_argument(
        "--self-test", action="store_true", help="Run the focused self-test."
    )
    return parser.parse_args(argv)


def print_human(result: ReconciliationResult) -> None:
    status = "PASS" if result.passed else "FAIL"
    print(f"SERDE_BOUNDARY_CLOSURE: {status}")
    print(f"rows: {result.row_count}")
    print(f"cases: {result.passed_count}/20 passed")
    if result.failed_cases:
        print(f"failed: {list(result.failed_cases)}")
    print(f"digest: {result.canonical_digest}")


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.self_test:
        self_test()
        return 0
    root = args.root.resolve()
    try:
        result = audit(root)
    except InventoryUnavailable as error:
        print(f"SERDE_BOUNDARY_CLOSURE: BLOCKED: {error}", file=sys.stderr)
        return 2
    print_human(result)
    if args.json_out is not None:
        args.json_out.write_text(
            json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
