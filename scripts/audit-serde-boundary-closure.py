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
requires the existing source-validating ``check(root)`` exactly once and
fails closed with a precise cause before evaluating any closure case when
that checked input is absent or stale. Unchecked stored rows and unvalidated
rescans are never a fallback. Actual decoder behaviour stays tested in the
owning Rust packages; no production Rust/Cargo/WIT is touched.

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

# The single #929 generator/rules entry point this coordinator calls. The
# inventory module is owned by #929; unchecked stored loaders
# (``load_artifact``) and unvalidated rescans (``iter_candidate_rows``) are
# never a fallback for the source-validating check.
REQUIRED_INVENTORY_SYMBOL = "check"

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

# ---------------------------------------------------------------------------
# The closed #929 ``check(root)`` result contract admitted at this boundary.
#
# #929 owns these values. They are restated here as the exact admission shape
# this coordinator requires, so a result that is merely *well typed* but is not
# a real #929 checked identity is refused as malformed API output instead of
# being carried into the 20 closure cases. Nothing here is derived from the
# returned value; nothing here widens what #929 can legitimately return.
# ---------------------------------------------------------------------------

# ``header["proof_ceiling"]`` must EQUAL this, not merely be a string.
ACCEPTED_PROOF_CEILING = "SOURCE_INVENTORY_AND_OWNERSHIP_ONLY"
# ``header["base_sha"]`` is ``git rev-parse HEAD``: a 40-hex object id, or this
# literal when #929 cannot resolve one. Any other shape is not a base identity.
ACCEPTED_UNKNOWN_BASE_SHA = "unknown-base"
# Identity of the inventory schema this coordinator is written against.
ACCEPTED_SCHEMA_PREFIX = "eliot.serde-boundary-inventory."
# Closed header vocabularies.
ACCEPTED_COVERAGE_STATES = frozenset({"COMPLETE", "INCOMPLETE"})
ACCEPTED_FAMILY_READINESS = frozenset({"READY", "BLOCKED"})

# Explicit required-key sets for the three levels of the returned result. A
# load-bearing field that is absent is refused; it is never read as an empty
# checked identity. Unknown *additional* fields are tolerated and ignored (they
# are inert evidence for this coordinator), but nothing load-bearing is
# defaulted.
CHECKED_RESULT_REQUIRED_KEYS = frozenset({"rows", "digest", "header"})
CHECKED_HEADER_REQUIRED_KEYS = frozenset(
    {
        "schema",
        "tool_version",
        "rule_revision",
        "proof_ceiling",
        "issue",
        "base_sha",
        "base_sha_source",
        "provenance_authority",
        "canonical_excludes",
        "denominator_status",
        "ambiguous_reason",
        "coverage",
        "family_readiness",
        "family_blocked_reason",
        "safety",
        "candidate_count",
        "classified_count",
        "unknown_count",
        "unassigned_count",
        "ready_children",
        "blocked_children",
        "denominator_digest",
        "aggregate_digest",
    }
)
CHECKED_ROW_REQUIRED_KEYS = frozenset(
    {"candidate_id", "id", "disposition", "owner", "digest"}
)

_SHA256_HEX_DIGITS = frozenset("0123456789abcdef")
_GIT_OBJECT_ID_LENGTH = 40
_SHA256_DIGEST_LENGTH = 64


class InventoryUnavailable(Exception):
    """Raised when no checked #929 inventory is available; precise cause.

    Causes: ``missing file:`` (a genuinely absent input file),
    ``stale inventory [CODE]:`` (the surfaced #929 InventoryError
    code/detail), ``inventory module failure:`` (import failure),
    ``inventory api failure:`` (missing ``check`` or an unexpected
    exception), ``inventory contract failure:`` (a malformed ``check``
    result that neither validates nor silently drops).
    """


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


@dataclass(frozen=True)
class CheckedInventory:
    """One successful ``check(root)`` binding carried into reconciliation.

    Freshness against current source was decided inside #929's
    ``validate_against_artifact`` (fresh source/rule/profile/owner-map
    identities and rows compared with the stored artifact). This object
    only carries that checked result — the exact rows, the aggregate and
    denominator identities, the informational base, and the proof
    ceiling — into the 20 cases and the text/JSON output. It never
    recomputes source identity and never relabels a copied digest pair
    as an independent source comparison.
    """

    rows: tuple[InventoryRow, ...]
    aggregate_digest: str
    denominator_digest: str
    base_sha: str
    proof_ceiling: str
    candidate_count: int


@dataclass
class ReconciliationInput:
    """Everything the 20-case coordinator evaluates.

    Cases 1-10 are computed here from ``rows`` plus the lexical/shape
    evidence maps. Cases 11-20 read the same model from structures the
    710B fixtures/test file supplies; each evaluator below documents the
    evidence keys it requires.
    """

    rows: list[InventoryRow] = field(default_factory=list)
    # Successful check(root) binding the evaluated rows were taken from.
    # None means freshness was never established: case 1 fails closed.
    inventory: CheckedInventory | None = None
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
    # Digest of this closure result (rows + case verdicts). This is the
    # closure-result identity only; inventory freshness identity travels
    # separately in the checked_inventory block below.
    canonical_digest: str
    inventory_aggregate_digest: str = ""
    inventory_denominator_digest: str = ""
    inventory_base_sha: str = ""
    inventory_proof_ceiling: str = ""
    inventory_candidate_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "issue": ISSUE,
            "denominator": list(DENOMINATOR_CASES),
            "passed": self.passed,
            "passed_count": self.passed_count,
            "failed_cases": list(self.failed_cases),
            "row_count": self.row_count,
            "canonical_digest": self.canonical_digest,
            "checked_inventory": {
                "aggregate_digest": self.inventory_aggregate_digest,
                "denominator_digest": self.inventory_denominator_digest,
                "base_sha": self.inventory_base_sha,
                "proof_ceiling": self.inventory_proof_ceiling,
                "candidate_count": self.inventory_candidate_count,
            },
            "cases": [
                {"case": r.case, "passed": r.passed, "detail": r.detail}
                for r in self.case_results
            ],
        }


def blocked_report(cause: str) -> dict[str, Any]:
    """Freshness-failure report carrying the same cause as the text output.

    No closure case was evaluated, so there is no row count, no
    closure-result digest, and no case verdict to present as current.
    """
    return {
        "issue": ISSUE,
        "denominator": list(DENOMINATOR_CASES),
        "passed": False,
        "blocked_cause": cause,
        "row_count": 0,
        "canonical_digest": "",
        "cases": [],
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


def load_inventory_module(root: Path) -> Any:
    """Import the #929 module and require its callable ``check`` entry."""
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
            f"inventory module failure: {INVENTORY_SCRIPT_REL}:1 "
            "(unloadable inventory module; cannot reconcile)"
        )
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        raise InventoryUnavailable(
            f"inventory module failure: {INVENTORY_SCRIPT_REL}:1 "
            f"(inventory module failed to load: {error})"
        ) from error
    if not callable(getattr(module, REQUIRED_INVENTORY_SYMBOL, None)):
        raise InventoryUnavailable(
            f"inventory api failure: {INVENTORY_SCRIPT_REL}:1 "
            f"(no callable '{REQUIRED_INVENTORY_SYMBOL}(root)'; "
            "unchecked loaders are not a fallback)"
        )
    return module


def _is_inventory_error(error: Exception) -> bool:
    """Match #929's stable InventoryError contract (code + detail)."""
    return (
        type(error).__name__ == "InventoryError"
        and isinstance(getattr(error, "code", None), str)
        and isinstance(getattr(error, "detail", None), str)
    )


def load_checked_inventory(root: Path) -> CheckedInventory:
    """Invoke #929 ``check(root)`` exactly once; refuse anything unchecked.

    No first-available loader probing, no signature probing, no sync: an
    absent API, an import failure, or any check exception stops
    current-source closure evaluation before the 20 cases run. A missing
    or malformed artifact is reported by ``check`` itself through its
    typed InventoryError, not by a coordinator pre-check.
    """
    module = load_inventory_module(root)
    check = getattr(module, REQUIRED_INVENTORY_SYMBOL)
    try:
        result = check(root)
    except Exception as error:
        if _is_inventory_error(error):
            raise InventoryUnavailable(
                f"stale inventory [{error.code}]: {error.detail}"
            ) from error
        raise InventoryUnavailable(
            f"inventory api failure: {INVENTORY_SCRIPT_REL}:1 "
            f"('{REQUIRED_INVENTORY_SYMBOL}(root)' raised "
            f"{type(error).__name__}: {error})"
        ) from error
    return _validate_checked_result(result)


def _contract_failure(detail: str) -> InventoryUnavailable:
    """Every admission failure keeps the one inventory/API contract category."""
    return InventoryUnavailable(f"inventory contract failure: {detail}")


def _is_sha256_digest(value: Any) -> bool:
    """True only for a lowercase 64-hex SHA-256 identity.

    ``str`` is checked exactly, so a bool, int or bytes value is not a digest.
    """
    return (
        isinstance(value, str)
        and len(value) == _SHA256_DIGEST_LENGTH
        and all(char in _SHA256_HEX_DIGITS for char in value)
    )


def _is_git_object_id(value: Any) -> bool:
    """True only for a lowercase 40-hex git object id."""
    return (
        isinstance(value, str)
        and len(value) == _GIT_OBJECT_ID_LENGTH
        and all(char in _SHA256_HEX_DIGITS for char in value)
    )


def _is_checked_base_sha(value: Any) -> bool:
    """The base identity form #929 promises for a checked source snapshot.

    ``git rev-parse HEAD`` yields a 40-hex object id; when #929 cannot resolve
    one it records the literal ``unknown-base``. A blank string is neither.
    """
    if value == ACCEPTED_UNKNOWN_BASE_SHA:
        return True
    return _is_git_object_id(value)


def _is_exact_int(value: Any) -> bool:
    """A real integer count. ``bool`` is a subclass of ``int`` in Python."""
    return type(value) is int


def _non_blank_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _require_keys(
    mapping: Mapping[str, Any], required: frozenset[str], level: str
) -> None:
    missing = sorted(required - set(mapping.keys()))
    if missing:
        raise _contract_failure(f"check(root) {level} is missing {missing}")


def _validate_checked_result(result: Any) -> CheckedInventory:
    """Validate ``check(root)``'s exact identity contract without rescanning.

    Trusting Python value types is insufficient here: a Boolean is an ``int``,
    any non-empty string is a plausible ``str``, and two conflicting row
    identities can collapse to whichever one happens to be truthy. This
    adapter therefore admits a result only when it carries the real #929
    identity material:

    - lowercase 64-hex aggregate, denominator and per-row digests, with the
      result digest equal to the header aggregate;
    - a ``base_sha`` in the form #929 promises, and a ``proof_ceiling`` that
      *equals* the accepted #929 ceiling;
    - both row identity fields present, non-blank, and equal, with no
      duplicate identity across rows;
    - dispositions inside #929's closed vocabulary — legitimate ``unknown``
      and ``needs-repair`` rows are preserved as findings, while a foreign
      disposition is malformed API output, not a closure-case result;
    - non-blank owner and a real row digest, never silently normalised;
    - real integer (non-boolean) counts that agree with the returned rows.

    Any failure is an ``inventory contract failure`` raised before
    ``evaluate_cases`` runs, so no closure case is ever presented as current
    over an identity that was never admitted.
    """
    if not isinstance(result, Mapping):
        raise _contract_failure(
            f"check(root) returned {type(result).__name__}, expected a mapping "
            "with rows/digest/header"
        )
    _require_keys(result, CHECKED_RESULT_REQUIRED_KEYS, "result")
    rows_raw = result["rows"]
    if not isinstance(rows_raw, list):
        raise _contract_failure("check(root) result rows is not a list")
    digest = result["digest"]
    header = result["header"]
    if not isinstance(header, Mapping):
        raise _contract_failure("check(root) result header is not a mapping")
    _require_keys(header, CHECKED_HEADER_REQUIRED_KEYS, "header")

    # --- top-level and header identity material ----------------------------
    if not _is_sha256_digest(digest):
        raise _contract_failure(
            f"check(root) result digest {digest!r} is not a lowercase 64-hex "
            "SHA-256 aggregate identity"
        )
    header_aggregate = header["aggregate_digest"]
    if not _is_sha256_digest(header_aggregate):
        raise _contract_failure(
            "header aggregate_digest "
            f"{header_aggregate!r} is not a lowercase 64-hex SHA-256 identity"
        )
    if header_aggregate != digest:
        raise _contract_failure(
            "result digest does not match header aggregate_digest"
        )
    denominator = header["denominator_digest"]
    if not _is_sha256_digest(denominator):
        raise _contract_failure(
            "header denominator_digest "
            f"{denominator!r} is not a lowercase 64-hex SHA-256 identity"
        )
    proof_ceiling = header["proof_ceiling"]
    if proof_ceiling != ACCEPTED_PROOF_CEILING:
        raise _contract_failure(
            f"header proof_ceiling {proof_ceiling!r} != accepted #{INVENTORY_ISSUE} "
            f"ceiling {ACCEPTED_PROOF_CEILING!r}"
        )
    base_sha = header["base_sha"]
    if not _is_checked_base_sha(base_sha):
        raise _contract_failure(
            f"header base_sha {base_sha!r} is not a #{INVENTORY_ISSUE} checked "
            "source identity (40-hex object id or "
            f"{ACCEPTED_UNKNOWN_BASE_SHA!r})"
        )
    schema = header["schema"]
    if not _non_blank_str(schema) or not schema.startswith(
        ACCEPTED_SCHEMA_PREFIX
    ):
        raise _contract_failure(
            f"header schema {schema!r} is not the #{INVENTORY_ISSUE} inventory "
            f"schema ({ACCEPTED_SCHEMA_PREFIX}*)"
        )
    issue = header["issue"]
    if not _is_exact_int(issue) or issue != INVENTORY_ISSUE:
        raise _contract_failure(
            f"header issue {issue!r} != owning issue {INVENTORY_ISSUE}"
        )
    for key in (
        "tool_version",
        "rule_revision",
        "safety",
        "base_sha_source",
        "provenance_authority",
    ):
        if not _non_blank_str(header[key]):
            raise _contract_failure(f"header {key} is blank or not a string")
    excludes = header["canonical_excludes"]
    if (
        not isinstance(excludes, list)
        or not excludes
        or not all(_non_blank_str(item) for item in excludes)
    ):
        raise _contract_failure(
            "header canonical_excludes is not a non-empty list of strings"
        )
    for key, vocabulary in (
        ("denominator_status", ACCEPTED_COVERAGE_STATES),
        ("coverage", ACCEPTED_COVERAGE_STATES),
        ("family_readiness", ACCEPTED_FAMILY_READINESS),
    ):
        if header[key] not in vocabulary:
            raise _contract_failure(
                f"header {key} {header[key]!r} is outside the closed vocabulary "
                f"{sorted(vocabulary)}"
            )
    for key in ("ambiguous_reason", "family_blocked_reason"):
        if not isinstance(header[key], str):
            raise _contract_failure(f"header {key} is not a string")

    # --- row identity material --------------------------------------------
    rows: list[InventoryRow] = []
    seen: set[str] = set()
    for entry in rows_raw:
        if not isinstance(entry, Mapping):
            raise _contract_failure(
                f"row is {type(entry).__name__}, expected a mapping"
            )
        _require_keys(entry, CHECKED_ROW_REQUIRED_KEYS, "row")
        candidate_id = entry["candidate_id"]
        row_id = entry["id"]
        if not _non_blank_str(candidate_id):
            raise _contract_failure(
                f"row candidate_id {candidate_id!r} is blank or not a string"
            )
        if not _non_blank_str(row_id):
            raise _contract_failure(
                f"row id {row_id!r} is blank or not a string"
            )
        if candidate_id != row_id:
            raise _contract_failure(
                f"row claims two identities: candidate_id {candidate_id!r} != "
                f"id {row_id!r}"
            )
        cid = candidate_id
        if cid in seen:
            raise _contract_failure(f"duplicate row identity {cid}")
        seen.add(cid)
        disposition = entry["disposition"]
        if disposition not in KNOWN_DISPOSITIONS:
            raise _contract_failure(
                f"row {cid} disposition {disposition!r} is outside the closed "
                f"#{INVENTORY_ISSUE} vocabulary {sorted(KNOWN_DISPOSITIONS)}"
            )
        owner = entry["owner"]
        if not _non_blank_str(owner):
            raise _contract_failure(
                f"row {cid} owner {owner!r} is blank or not a string"
            )
        row_digest = entry["digest"]
        if not _is_sha256_digest(row_digest):
            raise _contract_failure(
                f"row {cid} digest {row_digest!r} is not a lowercase 64-hex "
                "SHA-256 identity"
            )
        rows.append(
            InventoryRow(
                candidate_id=cid,
                disposition=disposition,
                owner=owner,
                digest=row_digest,
            )
        )

    # --- returned count relationships --------------------------------------
    counts: dict[str, int] = {}
    for key in (
        "candidate_count",
        "classified_count",
        "unknown_count",
        "unassigned_count",
        "ready_children",
        "blocked_children",
    ):
        value = header[key]
        if not _is_exact_int(value) or value < 0:
            raise _contract_failure(
                f"header {key} {value!r} is not a real non-negative integer "
                "count"
            )
        counts[key] = value
    if counts["candidate_count"] != len(rows):
        raise _contract_failure(
            "header candidate_count "
            f"{counts['candidate_count']!r} != returned rows {len(rows)}"
        )
    if counts["classified_count"] != len(rows):
        raise _contract_failure(
            "header classified_count "
            f"{counts['classified_count']!r} != returned rows {len(rows)}"
        )
    unknown_rows = sum(1 for row in rows if row.disposition == "unknown")
    if counts["unknown_count"] != unknown_rows:
        raise _contract_failure(
            f"header unknown_count {counts['unknown_count']!r} != "
            f"{unknown_rows} returned unknown row(s)"
        )
    if counts["unassigned_count"] > counts["candidate_count"]:
        raise _contract_failure(
            f"header unassigned_count {counts['unassigned_count']!r} exceeds "
            f"candidate_count {counts['candidate_count']!r}"
        )
    return CheckedInventory(
        rows=tuple(rows),
        aggregate_digest=digest,
        denominator_digest=denominator,
        base_sha=base_sha,
        proof_ceiling=proof_ceiling,
        candidate_count=counts["candidate_count"],
    )


# ---------------------------------------------------------------------------
# Cases 1-10: denominator/unknown/duplicate/variant/tag (evaluated here).
# ---------------------------------------------------------------------------


def evaluate_case_01_denominator(data: ReconciliationInput) -> CaseResult:
    """Case 1: closure evaluates only over a checked inventory binding.

    Freshness against current source was decided inside #929 ``check``
    (``validate_against_artifact``); this case asserts that the binding
    is present and internally consistent instead of comparing a copied
    digest pair as if it were an independent source comparison.
    """
    binding = data.inventory
    if binding is None:
        return CaseResult(
            1, False, "case-01: no checked inventory binding; freshness "
            "unevaluated"
        )
    if not binding.aggregate_digest or not binding.denominator_digest:
        return CaseResult(
            1,
            False,
            "case-01: checked binding lacks aggregate/denominator identity",
        )
    if binding.candidate_count != len(data.rows):
        return CaseResult(
            1,
            False,
            "case-01: binding count does not match evaluated rows",
        )
    return CaseResult(
        1,
        True,
        f"case-01: denominator 1..20 over checked inventory "
        f"{binding.aggregate_digest[:16]} ({binding.candidate_count} rows)",
    )


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
    binding = data.inventory
    return ReconciliationResult(
        passed=not failed,
        passed_count=sum(1 for r in results if r.passed),
        failed_cases=failed,
        case_results=results,
        row_count=len(data.rows),
        canonical_digest=digest,
        inventory_aggregate_digest=binding.aggregate_digest
        if binding is not None
        else "",
        inventory_denominator_digest=binding.denominator_digest
        if binding is not None
        else "",
        inventory_base_sha=binding.base_sha if binding is not None else "",
        inventory_proof_ceiling=binding.proof_ceiling
        if binding is not None
        else "",
        inventory_candidate_count=binding.candidate_count
        if binding is not None
        else 0,
    )


def audit(root: Path) -> ReconciliationResult:
    """Read-only reconciliation against checked #929 input (fails closed)."""
    binding = load_checked_inventory(root)
    data = ReconciliationInput(rows=list(binding.rows), inventory=binding)
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
    binding = CheckedInventory(
        rows=tuple(rows),
        aggregate_digest="selftest-aggregate",
        denominator_digest="selftest-denominator",
        base_sha="selftest-base",
        proof_ceiling="SOURCE_INVENTORY_AND_OWNERSHIP_ONLY",
        candidate_count=len(rows),
    )
    return ReconciliationInput(
        rows=rows,
        inventory=binding,
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


# ---------------------------------------------------------------------------
# Fake-API regressions for the checked identity contract (#2701 audit).
#
# Every shape below is one #929 ``check(root)`` result the adapter MUST refuse.
# A refused result is refused, never coerced into "no problems found": the
# admission phase raises before ``evaluate_cases`` runs.
# ---------------------------------------------------------------------------

_FAKE_AGGREGATE = "a" * _SHA256_DIGEST_LENGTH
_FAKE_DENOMINATOR = "b" * _SHA256_DIGEST_LENGTH
_FAKE_ROW_DIGEST = "c" * _SHA256_DIGEST_LENGTH
_FAKE_BASE_SHA = "0" * _GIT_OBJECT_ID_LENGTH
_FAKE_CANDIDATE_ID = "fake-package:crates/fake.rs:FakeType:1"


def _fake_check_result() -> dict[str, Any]:
    """One faithful #929 ``check(root)`` result with a single repair row."""
    return {
        "rows": [
            {
                "candidate_id": _FAKE_CANDIDATE_ID,
                "id": _FAKE_CANDIDATE_ID,
                "disposition": "needs-repair",
                "owner": "#929",
                "digest": _FAKE_ROW_DIGEST,
            }
        ],
        "digest": _FAKE_AGGREGATE,
        "header": {
            "schema": "eliot.serde-boundary-inventory.v1",
            "tool_version": "0.4.0",
            "rule_revision": "929.4",
            "proof_ceiling": ACCEPTED_PROOF_CEILING,
            "issue": INVENTORY_ISSUE,
            "base_sha": _FAKE_BASE_SHA,
            "base_sha_source": "git-rev-parse-HEAD",
            "provenance_authority": (
                "informational-observational-outside-proof-ceiling"
            ),
            "canonical_excludes": ["base_sha", "base_sha_source"],
            "denominator_status": "COMPLETE",
            "ambiguous_reason": "",
            "coverage": "COMPLETE",
            "family_readiness": "BLOCKED",
            "family_blocked_reason": "unknown-evidence",
            "safety": "FINDINGS_REMAIN_BLOCKING",
            "candidate_count": 1,
            "classified_count": 1,
            "unknown_count": 0,
            "unassigned_count": 0,
            "ready_children": 0,
            "blocked_children": 1,
            "denominator_digest": _FAKE_DENOMINATOR,
            "aggregate_digest": _FAKE_AGGREGATE,
        },
    }


# The exact counterexample from the #2701 external audit (comment 5908785311):
# conflicting row identities, non-digest identities, an absent base identity, a
# foreign proof ceiling, a Boolean accepted as an integer count, counts that
# contradict the row set, and an empty owner presented as owner evidence.
AUDIT_COUNTEREXAMPLE_2701: dict[str, Any] = {
    "rows": [
        {
            "candidate_id": "candidate-A",
            "id": "candidate-B",
            "disposition": "unknown",
            "owner": "",
            "digest": "",
        }
    ],
    "digest": "x",
    "header": {
        "aggregate_digest": "x",
        "denominator_digest": "y",
        "candidate_count": True,
        "base_sha": "",
        "proof_ceiling": "NOT_THE_929_CEILING",
        "classified_count": 999,
        "unknown_count": 0,
    },
}


def _broken(
    *,
    header: dict[str, Any] | None = None,
    drop_header: tuple[str, ...] = (),
    row: dict[str, Any] | None = None,
    drop_row: tuple[str, ...] = (),
    extra_rows: list[dict[str, Any]] | None = None,
    digest: str | None = None,
) -> dict[str, Any]:
    """A faithful #929 result with exactly the named defect(s) applied.

    Every regression below is built from a complete, otherwise-valid result so
    that the refusal is attributable to that one defect and not to some earlier
    field also being wrong.
    """
    result = _fake_check_result()
    if extra_rows is not None:
        result["rows"] = result["rows"] + extra_rows
    if row is not None:
        result["rows"][0] = {**result["rows"][0], **row}
    if drop_row:
        result["rows"][0] = {
            key: value
            for key, value in result["rows"][0].items()
            if key not in drop_row
        }
    if header is not None:
        result["header"] = {**result["header"], **header}
    if drop_header:
        result["header"] = {
            key: value
            for key, value in result["header"].items()
            if key not in drop_header
        }
    if digest is not None:
        result["digest"] = digest
        result["header"]["aggregate_digest"] = digest
    return result


_FAKE_SECOND_ROW = {
    "candidate_id": "fake-package:crates/fake.rs:OtherType:2",
    "id": "fake-package:crates/fake.rs:OtherType:2",
    "disposition": "current-closed",
    "owner": "#929",
    "digest": "d" * _SHA256_DIGEST_LENGTH,
}


def _refusal_regressions() -> list[tuple[str, Any]]:
    """(label, fake check result) pairs that must all be refused."""
    return [
        # The audit's own counterexample, verbatim.
        ("audit-2701-counterexample", AUDIT_COUNTEREXAMPLE_2701),
        # Row identity: both fields required, non-blank, equal, unique.
        (
            "conflicting candidate_id/id",
            _broken(row={"id": "fake-package:crates/fake.rs:OtherType:2"}),
        ),
        ("missing row id field", _broken(drop_row=("id",))),
        (
            "missing row candidate_id field",
            _broken(drop_row=("candidate_id",)),
        ),
        (
            "blank row identity material",
            _broken(row={"candidate_id": "   ", "id": "   "}),
        ),
        (
            "duplicate row identity",
            _broken(
                extra_rows=[
                    {
                        **_FAKE_SECOND_ROW,
                        "candidate_id": _FAKE_CANDIDATE_ID,
                        "id": _FAKE_CANDIDATE_ID,
                    }
                ],
                header={"candidate_count": 2, "classified_count": 2},
            ),
        ),
        # Digest identities: lowercase 64-hex only.
        ("non-digest row digest", _broken(row={"digest": ""})),
        ("non-digest row digest (short hex)", _broken(row={"digest": "abcd"})),
        (
            "non-digest aggregate identity",
            _broken(digest="x"),
        ),
        (
            "non-digest denominator identity",
            _broken(header={"denominator_digest": "y"}),
        ),
        # Base identity and proof ceiling.
        ("blank base identity", _broken(header={"base_sha": ""})),
        (
            "non-object-id base identity",
            _broken(header={"base_sha": "not-a-commit"}),
        ),
        (
            "foreign proof ceiling",
            _broken(header={"proof_ceiling": "NOT_THE_929_CEILING"}),
        ),
        # Disposition: closed #929 vocabulary at this boundary.
        ("foreign disposition", _broken(row={"disposition": "covered"})),
        # Owner: exact, non-ambiguous, never blank.
        ("blank row owner", _broken(row={"owner": ""})),
        ("missing row owner", _broken(drop_row=("owner",))),
        ("missing row digest", _broken(drop_row=("digest",))),
        # Counts: real integers whose returned relationships hold.
        ("boolean candidate_count", _broken(header={"candidate_count": True})),
        (
            "boolean classified_count",
            _broken(header={"classified_count": False}),
        ),
        (
            "inconsistent candidate_count",
            _broken(header={"candidate_count": 999}),
        ),
        (
            "inconsistent classified_count",
            _broken(header={"classified_count": 999}),
        ),
        (
            "inconsistent unknown_count",
            _broken(header={"unknown_count": 3}),
        ),
        (
            "unassigned_count exceeds candidate_count",
            _broken(header={"unassigned_count": 2}),
        ),
        # A load-bearing field that is absent is not an empty identity.
        (
            "load-bearing header field absent",
            _broken(drop_header=("denominator_digest",)),
        ),
        (
            "load-bearing base identity absent",
            _broken(drop_header=("base_sha",)),
        ),
    ]


def self_test_checked_identity_contract() -> None:
    """Prove the checked identity contract admits only real #929 results."""
    admitted = _validate_checked_result(_fake_check_result())
    if admitted.aggregate_digest != _FAKE_AGGREGATE:
        raise AssertionError("faithful fake result lost its aggregate identity")
    if admitted.candidate_count != 1 or len(admitted.rows) != 1:
        raise AssertionError("faithful fake result lost its row accounting")
    if admitted.rows[0].disposition != "needs-repair":
        raise AssertionError("a valid needs-repair row must survive admission")

    # A legitimate `unknown` row is a finding, not a contract failure: it is
    # preserved as returned and counted in the returned header.
    unknown_result = json.loads(json.dumps(_fake_check_result()))
    unknown_result["rows"][0]["disposition"] = "unknown"
    unknown_result["header"]["unknown_count"] = 1
    unknown_admitted = _validate_checked_result(unknown_result)
    if unknown_admitted.rows[0].disposition != "unknown":
        raise AssertionError("a valid unknown row must be preserved as a finding")

    for label, fake in _refusal_regressions():
        try:
            _validate_checked_result(fake)
        except InventoryUnavailable as error:
            cause = str(error)
            if not cause.startswith("inventory contract failure: "):
                raise AssertionError(
                    f"self-test {label!r} left the inventory contract "
                    f"category: {cause}"
                ) from error
            continue
        raise AssertionError(
            f"self-test {label!r} was admitted as a checked #929 identity"
        )
    print(
        "SERDE_BOUNDARY_CLOSURE_SELF_TEST: checked-identity contract "
        f"({len(_refusal_regressions())} malformed shapes refused)"
    )


def self_test() -> ReconciliationResult:
    self_test_checked_identity_contract()
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
    if result.inventory_aggregate_digest:
        print(
            f"inventory: aggregate={result.inventory_aggregate_digest[:16]} "
            f"denominator={result.inventory_denominator_digest[:16]} "
            f"base={result.inventory_base_sha} "
            f"ceiling={result.inventory_proof_ceiling}"
        )
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
        cause = str(error)
        print(f"SERDE_BOUNDARY_CLOSURE: BLOCKED: {cause}", file=sys.stderr)
        if args.json_out is not None:
            args.json_out.write_text(
                json.dumps(blocked_report(cause), indent=2, sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
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
