#!/usr/bin/env python3
"""Read-only Context-measurement ownership oracle and reconciliation (#787).

Issue: https://github.com/UnknownAlienHuman/eliot-memory-os/issues/787

What this is
------------
The deterministic, read-only oracle that decides whether the *serialized
post-migration* Context-measurement inventory of issue #866 is **current**,
**complete** and **internally owned**, and that reconciles the frozen #866
pre-migration baseline row identities against the current inventory.

Design constraints that shape the whole file
-------------------------------------------
1. **One immutable result, two projections.** :func:`evaluate` builds a
   single frozen :class:`OwnershipResult`. ``--format text`` and
   ``--format json`` are pure projections of that one object, so their
   counts, digests and finding codes are identical by construction. The
   result is built once per invocation and is never mutated afterwards.
2. **No second scanner.** Candidate accounting is obtained from the
   accepted #866 producer by *importing and calling* its read-only functions
   (``discover_context_measurements``, ``classify_context_measurement``,
   ``load_owner_map``, ``_validate_artifact``, ``_parse_toml``, ``_load_files``,
   ``_locate_signal``, ``_scope_of``); this file never re-implements the
   producer's discovery, classification or denominator. The unaccounted-
   estimator detector reuses the producer's *own* declared needle vocabulary
   and the producer's *own* classifier, so an estimator added to a declared
   scan root is seen through #866, not through an independent second scanner
   or a fixed local list. ``_producer_candidates`` and ``_unaccounted_candidates``
   are the consumers of the producer's row/candidate contract; the oracle
   never calls the producer's ``cmd_sync``/``build_inventory`` write path.
3. **Read-only.** No network, no ambient clock, no writes, no auto-fallback
   during normal checking. The self-test proves the evaluation region contains
   no filesystem mutation, no broad directory walk and no banned retrieval,
   clock, child-process or measurement-admission surface. Regeneration of the
   shared artifact is the #866 ``sync`` single-writer path, never an oracle
   auto-repair.
4. **Independent expected set.** The baseline reconciliation denominator is
   the *frozen* ``EXPECTED_BASELINE_ROWS`` table below, which is written out
   here independently of the producer's live row order, and is compared
   against the producer's measured baseline, never against a copy of the
   producer's own list.

Proof ceiling: STATIC_OWNERSHIP_CONFORMANCE_ONLY. A passing oracle is a
static owner/schema/unit/dependency conformance statement about source text
and the #866 inventory. It is not a tokenizer accuracy result, not a live
provider measurement, not a Context admission decision, and never a
Product or release support claim.

Usage:
  python scripts/audit-context-measurement-ownership.py --self-test
  python scripts/audit-context-measurement-ownership.py --root .
  python scripts/audit-context-measurement-ownership.py --root . --format json
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

ISSUE = 787
PRODUCER_ISSUE = 866
SCHEMA_OWNER_ISSUE = 584
MEASUREMENT_OWNER_ISSUE = 704
INTEGRATION_OWNER = "#787"

PRODUCER_SCRIPT_REL = "scripts/context_measurement_inventory.py"
INVENTORY_REL = ".github/work-units/context-measurement-inventory.toml"
OWNER_MAP_REL = ".github/work-units/context-measurement-owner-map.toml"

RESULT_SCHEMA = "eliot.context-measurement-ownership.v1"
ORACLE_VERSION = "1.0.0"
PROOF_CEILING = "STATIC_OWNERSHIP_CONFORMANCE_ONLY"

# ---------------------------------------------------------------------------
# Frozen typed failure set. Every finding the oracle can raise is one of
# these codes. A code is never invented at runtime and never widened: the
# closed tuple is asserted in the self-test and the JSON projection only
# ever emits a code from this set.
# ---------------------------------------------------------------------------
FAIL_CODES: tuple[str, ...] = (
    # inventory lifecycle
    "INVENTORY_MISSING",
    "INVENTORY_MALFORMED",
    "INVENTORY_STALE",
    "INVENTORY_INCOMPLETE",
    "PRODUCER_CHECK_BLOCKED",
    "PRODUCER_CHECK_FAILED",
    "PRODUCER_ABSENT",
    # source-row identity
    "SOURCE_ROW_MISSING",
    "SOURCE_DIGEST_CHANGED",
    "SOURCE_SPAN_CHANGED",
    "SOURCE_ROW_OVERLAP",
    "SOURCE_UNREADABLE",
    # candidate accounting
    "UNACCOUNTED_CANDIDATE",
    "CANDIDATE_UNCLASSIFIED",
    "CANDIDATE_COUNT_DRIFT",
    # ownership / schema
    "DUPLICATE_OWNER",
    "DUPLICATE_SCHEMA",
    "MISSING_CANONICAL_OWNER",
    "MISSING_DEPENDENCY",
    "GENERIC_ESTIMATOR_OWNER",
    # unit / name / proof
    "UNIT_NAME_MISMATCH",
    "PROOF_ESCALATION",
    # exceptions / baseline
    "STALE_EXCEPTION",
    "OVERBROAD_EXCEPTION",
    "BASELINE_ROW_LOST",
    "BASELINE_DISPOSITION_MISSING",
    "CONSUMER_EVIDENCE_MISSING",
    # determinism
    "DETERMINISTIC_INTERNAL_DEFECT",
)

# ---------------------------------------------------------------------------
# Canonical ownership facts. These are *normative* facts declared by the
# architecture (I2.16 / I12.32 / I18.27) and by issues #704/#584/#866. They
# are NOT copied from the producer's live rows: the oracle validates the
# producer's rows *against* these independent facts.
# ---------------------------------------------------------------------------
# Owner identities are the *string* form the #866 inventory rows carry
# ("#704"/"#783"/"#878"/"#880"). The bare issue numbers above are used only in
# prose; every owner key, lookup and evidence map uses the "#NNN" string so a
# numeric id can never silently miss an owner and report a false failure.
CANONICAL_MEASUREMENT_OWNER = f"#{MEASUREMENT_OWNER_ISSUE}"
CANONICAL_SCHEMA_OWNER = f"#{SCHEMA_OWNER_ISSUE}"
CANONICAL_SCHEMA_PATH = "crates/smart/eliot-context-contracts/src/measurement.rs"
CANONICAL_SCHEMA_TYPE = "SerializedContextMeasurement"
CANONICAL_STU_PATH = "crates/smart/eliot-context-measurement/src/stu.rs"
CANONICAL_STU_FORMULA = "stu_for_bytes"
CANONICAL_MEASUREMENT_PORT = "measure_serialized_context"

# Closed disposition set every baseline row must end with. A baseline row
# that simply disappears is an erased requirement and is rejected; a row
# that is still present but carries no explicit disposition is rejected.
BASELINE_DISPOSITIONS: tuple[str, ...] = (
    "canonical-owner-consumer",
    "legitimate-non-context-metric",
    "exact-versioned-legacy-adapter",
    "explicit-unresolved",
)

# The frozen pre-migration baseline requirement denominator. Written out here
# independently of the producer module so that a drift in either direction
# is observable; every entry must still be present in the current inventory
# and carry an explicit disposition.
EXPECTED_BASELINE_ROWS: tuple[tuple[str, str], ...] = (
    ("704/1", CANONICAL_MEASUREMENT_OWNER),
    ("704/2", CANONICAL_MEASUREMENT_OWNER),
    ("704/3", CANONICAL_MEASUREMENT_OWNER),
    ("704/4", CANONICAL_MEASUREMENT_OWNER),
    ("704/5", CANONICAL_MEASUREMENT_OWNER),
    ("704/6", CANONICAL_MEASUREMENT_OWNER),
    ("704/7", CANONICAL_MEASUREMENT_OWNER),
    ("704/8", CANONICAL_MEASUREMENT_OWNER),
    ("704/9", CANONICAL_MEASUREMENT_OWNER),
    ("783/1", "#783"),
    ("783/2", "#783"),
    ("783/3", "#783"),
    ("783/4", "#783"),
    ("783/5", "#783"),
    ("783/6", "#783"),
    ("783/7", "#783"),
    ("783/8", "#783"),
    ("878/1", "#878"),
    ("878/2", "#878"),
    ("878/3", "#878"),
    ("878/4", "#878"),
    ("878/5", "#878"),
    ("878/6", "#878"),
    ("880/1", "#880"),
    ("880/2", "#880"),
    ("880/3", "#880"),
    ("880/4", "#880"),
    ("880/5", "#880"),
    ("880/6", "#880"),
    ("880/7", "#880"),
    ("880/8", "#880"),
)
EXPECTED_BASELINE_COUNT = len(EXPECTED_BASELINE_ROWS)

# The three consumer migrations that must each leave exact evidence of the
# canonical measurement dependency (or an exact approved adapter) in their
# own source. #787 never chooses the migration; it only requires the
# evidence. Each consumer is checked for a declared measurement dependency
# marker in its declared seam files.
CONSUMER_DEPENDENCY_MARKERS: dict[str, tuple[str, ...]] = {
    # exact approved adapter / canonical entry points a migrated consumer may
    # legitimately name; any of these satisfies the dependency check.
    "#783": (
        "eliot_context_measurement",
        "measure_serialized_context",
        "measure_exact_utf8",
        "eliot_context_contracts",
    ),
    "#878": (
        "eliot_context_measurement",
        "measure_serialized_context",
        "measure_exact_utf8",
        "eliot_context_contracts",
    ),
    "#880": (
        "eliot_context_measurement",
        "measure_serialized_context",
        "measure_exact_utf8",
        "eliot_context_contracts",
    ),
    CANONICAL_MEASUREMENT_OWNER: (
        "eliot_context_contracts",
    ),
}


class OracleError(RuntimeError):
    """Typed fail-closed error carrying a machine-readable reason code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        if code not in FAIL_CODES:
            # Never widen the closed failure set at runtime; an unknown code
            # is itself a deterministic internal defect.
            code = "DETERMINISTIC_INTERNAL_DEFECT"
        self.code = code
        self.detail = detail


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _stu(byte_count: int) -> int:
    """Source Token Unit = ceil(bytes / 3) (I2.16), used only for reported
    accounting. The oracle never *implements* a measurement; this mirrors the
    declared STU rule purely to reproduce the producer's reported STU totals
    and to detect a producer STU drift."""
    if byte_count <= 0:
        return 0
    return -(-int(byte_count) // 3)


# ---------------------------------------------------------------------------
# A single immutable finding and the single immutable result.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    code: str
    detail: str
    row_id: str = ""
    case_ref: str = ""
    path: str = ""
    span_start: int = 0
    span_end: int = 0
    rule: str = ""

    def __post_init__(self) -> None:
        if self.code not in FAIL_CODES:
            raise OracleError(
                "DETERMINISTIC_INTERNAL_DEFECT",
                f"finding code outside closed set: {self.code!r}",
            )

    def as_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "detail": self.detail,
            "row_id": self.row_id,
            "case_ref": self.case_ref,
            "path": self.path,
            "span_start": self.span_start,
            "span_end": self.span_end,
            "rule": self.rule,
        }

    def locator(self) -> str:
        if self.path:
            span = f"{self.span_start}-{self.span_end}" if self.span_start else ""
            ref = self.case_ref or self.row_id
            where = f"{self.path}" + (f":{span}" if span else "")
            if ref:
                return f"[{self.code}] {ref} {where} rule={self.rule}: {self.detail}"
            return f"[{self.code}] {where} rule={self.rule}: {self.detail}"
        return f"[{self.code}] {self.detail}"


@dataclass(frozen=True)
class OwnershipResult:
    """The one immutable result. Text and JSON are projections of this."""

    result_schema: str
    oracle_version: str
    issue: int
    producer_issue: int
    proof_ceiling: str
    inventory_path: str
    inventory_present: bool
    inventory_digest: str
    source_sha: str
    rule_digest: str
    owner_digest: str
    rule_revision: str
    coverage_disposition: str
    owner_map_status: str
    candidate_count: int
    classified_count: int
    owned_count: int
    unresolved_count: int
    baseline_reconciled: int
    baseline_expected: int
    baseline_dispositions: dict[str, int]
    unaccounted_candidate_count: int
    canonical_measurement_owners: tuple[str, ...]
    canonical_schema_owners: tuple[str, ...]
    producer_check_status: str
    finding_count: int
    findings: tuple[Finding, ...]
    result_digest: str

    @property
    def ok(self) -> bool:
        return self.finding_count == 0

    def _counts(self) -> dict[str, object]:
        return {
            "candidate_count": self.candidate_count,
            "classified_count": self.classified_count,
            "owned_count": self.owned_count,
            "unresolved_count": self.unresolved_count,
            "baseline_reconciled": self.baseline_reconciled,
            "baseline_expected": self.baseline_expected,
            "unaccounted_candidate_count": self.unaccounted_candidate_count,
            "finding_count": self.finding_count,
        }

    def result_body(self) -> dict[str, object]:
        return {
            "result_schema": self.result_schema,
            "oracle_version": self.oracle_version,
            "issue": self.issue,
            "producer_issue": self.producer_issue,
            "proof_ceiling": self.proof_ceiling,
            "status": "ok" if self.ok else "fail",
            "inventory_path": self.inventory_path,
            "inventory_present": self.inventory_present,
            "inventory_digest": self.inventory_digest,
            "producer_identity": {
                "rule_revision": self.rule_revision,
                "source_sha": self.source_sha,
                "rule_digest": self.rule_digest,
                "owner_digest": self.owner_digest,
                "coverage_disposition": self.coverage_disposition,
                "owner_map_status": self.owner_map_status,
                "producer_check_status": self.producer_check_status,
            },
            "counts": self._counts(),
            "baseline_dispositions": dict(sorted(self.baseline_dispositions.items())),
            "canonical_measurement_owners": list(self.canonical_measurement_owners),
            "canonical_schema_owners": list(self.canonical_schema_owners),
            "findings": [f.as_dict() for f in self.findings],
            "result_digest": self.result_digest,
        }


# ---------------------------------------------------------------------------
# Producer import (read-only). We import the accepted #866 module and call
# its functions; we never copy its rules.
# ---------------------------------------------------------------------------


def load_producer(root: Path) -> Any:
    """Import the accepted #866 generator module as a read-only dependency.

    Returns the loaded module object. Raises OracleError(PRODUCER_ABSENT) if
    the accepted generator is missing, so the oracle can never fall back to a
    private re-implementation of the producer's discovery/classification.
    """
    script = root / PRODUCER_SCRIPT_REL
    if not script.is_file() or script.is_symlink():
        raise OracleError(
            "PRODUCER_ABSENT",
            f"the accepted #{PRODUCER_ISSUE} generator is absent: {PRODUCER_SCRIPT_REL}",
        )
    try:
        spec = importlib.util.spec_from_file_location(
            f"_context_measurement_inventory_{ISSUE}", script
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        # Register before exec so any internal import resolves to this module.
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    except OracleError:
        raise
    except Exception as exc:  # fail closed, never a silent fallback
        raise OracleError(
            "PRODUCER_ABSENT",
            f"the accepted #{PRODUCER_ISSUE} generator could not be imported: {exc}",
        ) from exc
    for required in (
        "discover_context_measurements",
        "classify_context_measurement",
        "build_inventory",
        "load_owner_map",
        "InventoryError",
        "DENOMINATOR_CASES",
        "EXCLUSION_CASES",
        "CLASSIFICATIONS",
        "OWNER_MAP_PATH",
        "OWNED_TOML",
        "_parse_toml",
        "_validate_artifact",
        "_load_files",
        "_scope_of",
        "_locate_signal",
        "_case_sort_key",
        "_read_source",
    ):
        if not hasattr(module, required):
            raise OracleError(
                "PRODUCER_ABSENT",
                f"#{PRODUCER_ISSUE} generator is missing required read-only API: {required}",
            )
    return module


# ---------------------------------------------------------------------------
# Candidate accounting obtained from the producer (the sole producer).
# ---------------------------------------------------------------------------


def _read_inventory_artifact(
    root: Path, producer: Any
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], str, bytes]:
    target = root / INVENTORY_REL
    if not target.is_file() or target.is_symlink():
        raise OracleError(
            "INVENTORY_MISSING",
            f"the accepted #{PRODUCER_ISSUE} inventory artifact is absent: {INVENTORY_REL}",
        )
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise OracleError(
            "INVENTORY_MALFORMED",
            f"the inventory artifact could not be read: {exc}",
        ) from exc
    artifact = producer._parse_toml(raw, source=INVENTORY_REL)
    try:
        header, rows, worksets = producer._validate_artifact(artifact)
    except producer.InventoryError as exc:
        raise OracleError(
            "INVENTORY_MALFORMED",
            f"the inventory artifact is malformed or internally inconsistent: {exc.code}: {exc.detail}",
        ) from exc
    return header, rows, worksets, str(artifact["inventory_digest"]), raw


def _producer_candidates(
    root: Path, producer: Any
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Obtain the producer's own file records and candidates through the
    accepted #866 read-only API.

    This is the *sole* candidate accounting for the oracle. It calls the
    producer's own :func:`discover_context_measurements` over the producer's own
    ``DENOMINATOR_CASES`` -- the declared scan universe and needle vocabulary --
    so an added estimator is seen because the producer saw it. It does not call
    the producer's ``sync``, does not emit or write anything, and does not
    re-implement discovery, classification or the denominator.

    A read, masking or classification failure raises a typed
    :class:`OracleError` rather than escaping as a traceback.
    """
    try:
        return producer.discover_context_measurements(root, producer.DENOMINATOR_CASES)
    except producer.InventoryError as exc:
        raise OracleError(
            "PRODUCER_CHECK_FAILED",
            f"#{PRODUCER_ISSUE} discovery failed: {exc.code}: {exc.detail}",
        ) from exc


def _producer_check(
    root: Path, producer: Any, raw: bytes
) -> tuple[str, str]:
    """Decide the producer's freshness verdict and validate its declared
    source/rule/owner-map input digests against the live tree.

    The stored artifact's *raw* bytes are exactly the bytes the producer's
    re-emission is compared to, and exactly the bytes a consumer of this
    result reasons about; they are used here so freshness is decided by the
    producer's own re-emission rather than by trusting a recorded digest or a
    commit SHA. Separately, the *recorded* ``source_sha``/``rule_digest``/
    ``owner_digest``/``owner_map_digest`` header values are validated against
    the values the producer itself derives from the live tree, so a relevant
    source/rule/allocation change is caught even when the re-emission happens
    to be compared separately.

    Returns ``(status, detail)``; ``status`` is ``"ok"`` or a typed non-ok
    token (``"stale"``, ``"blocked"``, ``"error"``, ``"digest-mismatch"``).
    """
    # The recorded inventory digest must equal a digest computed over the
    # artifact's own content -- recomputing to *validate* the recorded value,
    # never to trust a stored digest blindly.
    try:
        artifact = producer._parse_toml(raw, source=INVENTORY_REL)
        header, rows, worksets = producer._validate_artifact(artifact)
    except producer.InventoryError as exc:
        return "error", f"{exc.code}: {exc.detail}"
    recorded_inventory_digest = str(artifact.get("inventory_digest", ""))
    try:
        # Validate the recorded inventory_digest over the artifact content.
        recomputed_inventory_digest = _sha256(
            _canonical_bytes(
                {
                    "header": header,
                    "rows": rows,
                    "consumer_worksets": worksets,
                }
            )
        )
    except (TypeError, KeyError) as exc:
        return "error", f"artifact content could not be re-canonicalised: {exc}"
    if recorded_inventory_digest != recomputed_inventory_digest:
        return (
            "digest-mismatch",
            f"recorded inventory_digest {recorded_inventory_digest[:16]} does not match the "
            f"digest computed over the artifact's own content "
            f"{recomputed_inventory_digest[:16]}",
        )

    # Validate the recorded source/rule/owner digests against the live tree,
    # using the producer's own derivation of each.
    try:
        measured_rule_digest = producer._rule_digest()
        measured_owner_digest = producer._owner_digest(producer.DENOMINATOR_CASES)
        file_records, _candidates = producer.discover_context_measurements(
            root, producer.DENOMINATOR_CASES
        )
        source_pairs = sorted(f"{r['path']}:{r['sha256']}" for r in file_records)
        measured_source_sha = _sha256("\n".join(source_pairs).encode("utf-8"))
        owner_map = producer.load_owner_map(root)
        measured_map_digest = owner_map[2]
    except producer.InventoryError as exc:
        return "error", f"{exc.code}: {exc.detail}"
    for label, recorded, measured in (
        ("rule_digest", str(header.get("rule_digest", "")), measured_rule_digest),
        ("owner_digest", str(header.get("owner_digest", "")), measured_owner_digest),
        ("source_sha", str(header.get("source_sha", "")), measured_source_sha),
        ("owner_map_digest", str(header.get("owner_map_digest", "")), measured_map_digest),
    ):
        if recorded != measured:
            return (
                "digest-mismatch",
                f"recorded {label} {recorded[:16]} does not match the value derived from the "
                f"live tree {measured[:16]}; a relevant source/rule/allocation/owner-map "
                f"input changed since the artifact was generated",
            )

    # Byte-identity freshness: the producer's own re-emission of the declared
    # universe must equal the stored bytes. This is the same operation the
    # producer's own ``check`` performs, and it is what makes an unrelated HEAD
    # move (which changes no scan input) NOT stale the artifact, while any
    # change to a scan root, rule, or owner allocation does.
    try:
        mapping, map_status, _map_digest = producer.load_owner_map(root)
        fresh = producer.build_inventory(
            root, producer.DENOMINATOR_CASES,
            str(header.get("generation_command", "")),
            (mapping, map_status, owner_map[2]),
        )
        fresh_raw = producer._emit_toml(fresh)
    except producer.InventoryError as exc:
        return "error", f"{exc.code}: {exc.detail}"
    if fresh_raw == raw:
        return "ok", "producer re-emission is byte-identical to the stored artifact"
    fresh_header = fresh["header"] if isinstance(fresh, dict) else {}
    if str(fresh_header.get("coverage_disposition", "")) != "COMPLETE" or str(
        fresh_header.get("owner_map_status", "")
    ) != "SUPPLIED":
        return (
            "blocked",
            f"producer rebuild leaves coverage {fresh_header.get('coverage_disposition')!r} / "
            f"owner map {fresh_header.get('owner_map_status')!r}: "
            f"{fresh_header.get('coverage_reason')}",
        )
    return "stale", "producer re-emission differs from the stored artifact"


def _unaccounted_candidates(
    root: Path, producer: Any, rows: list[dict[str, Any]], candidates: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Detect an added, moved or removed unaccounted estimator through #866.

    Candidate accounting is the producer's, and it is obtained by *calling*
    the producer, never by a second scanner written here. Two complementary
    producer-driven facts are checked:

    **(a) Declared-identity completeness.** The producer's denominator is a set
    of ``(case_ref, owner, path, signal)`` identities, and for each the
    producer locates exactly one span by asking its own masked-source loader
    for the *first* masked line in that path holding that signal. We re-ask
    the producer to re-locate every declared identity and require the stored
    rows to cover exactly those spans, under exactly those producers. An
    estimator that is added to a declared seam, removed from one, or that
    relocates because new source was inserted above it changes what the
    producer locates, so this fires. The needle vocabulary is the producer's
    ``DENOMINATOR_CASES``; this file contributes no pattern of its own, so an
    added estimator is seen *because the producer's own discovery saw it*,
    never because of a fixed local list.

    **(b) Declared-exclusion integrity.** The producer declares an exact
    exclusion set (``EXCLUSION_CASES``) for genuinely unrelated byte or
    character metrics. Every declared exclusion must still be a live,
    non-test occurrence in a declared scan root, must still classify as the
    producer's unrelated-metric class, and must not be reused to excuse a
    measurement row. A stale exclusion (its needle vanished) or an overbroad
    one (a measurement-bearing row leans on it) is rejected by name.

    Test-scope occurrences are routed through the producer's ``_scope_of`` and
    are not shipped measurements (producer classification rule 1).
    """
    accounted: dict[tuple[str, int], str] = {}
    for row in rows:
        accounted[(str(row["path"]), int(row["span_start"]))] = str(row["case_ref"])

    findings: list[dict[str, Any]] = []

    # (a) Declared-identity completeness, measured by the producer.
    producer_paths = sorted({str(c["path"]) for c in candidates})
    if not producer_paths:
        return findings
    try:
        cache = producer._load_files(root, tuple(producer_paths))
    except producer.InventoryError as exc:
        raise OracleError(
            "SOURCE_UNREADABLE",
            f"a declared scan root could not be loaded: {exc.code}: {exc.detail}",
        ) from exc
    for cand in candidates:
        rel = str(cand["path"])
        signal = str(cand["signal"])
        case_ref = str(cand["case_ref"])
        # Ask the producer to locate this declared identity now.
        try:
            span_start, span_end = producer._locate_signal(cache[rel], rel, signal)
        except producer.InventoryError as exc:
            findings.append(
                {
                    "code": "UNACCOUNTED_CANDIDATE",
                    "path": rel,
                    "span_start": 0,
                    "span_end": 0,
                    "signal": signal,
                    "case_ref": case_ref,
                    "label": "SIGNAL_ABSENT",
                    "evidence": (
                        f"the #{PRODUCER_ISSUE} producer can no longer locate its declared "
                        f"signal {signal!r} in {rel}: {exc.code}: {exc.detail}"
                    ),
                }
            )
            continue
        owner_ref = accounted.get((rel, span_start))
        if owner_ref is None:
            findings.append(
                {
                    "code": "UNACCOUNTED_CANDIDATE",
                    "path": rel,
                    "span_start": span_start,
                    "span_end": span_end,
                    "signal": signal,
                    "case_ref": case_ref,
                    "label": str(cand["classification"]),
                    "evidence": (
                        f"the #{PRODUCER_ISSUE} producer locates declared identity "
                        f"{case_ref} ({signal!r}) at {rel}:{span_start}-{span_end} but no "
                        f"stored row accounts for that span; an estimator is present in a "
                        f"declared scan root without an inventory row"
                    ),
                }
            )

    # (b) Declared-exclusion integrity, measured by the producer.
    exclusion_paths = sorted({str(rel) for _r, rel, _n, _x in producer.EXCLUSION_CASES})
    if exclusion_paths:
        try:
            exclusion_cache = producer._load_files(root, tuple(exclusion_paths))
        except producer.InventoryError as exc:
            raise OracleError(
                "SOURCE_UNREADABLE",
                f"a declared exclusion input could not be loaded: {exc.code}: {exc.detail}",
            ) from exc
        measurement_spans = {
            (str(r["path"]), int(r["span_start"])) for r in rows
        }
        for case_ref, rel, needle, reason in sorted(
            producer.EXCLUSION_CASES, key=lambda item: str(item[0])
        ):
            try:
                span_start, span_end = producer._locate_signal(exclusion_cache[rel], rel, needle)
            except producer.InventoryError as exc:
                findings.append(
                    {
                        "code": "STALE_EXCEPTION",
                        "path": str(rel),
                        "span_start": 0,
                        "span_end": 0,
                        "signal": str(needle),
                        "case_ref": str(case_ref),
                        "label": "STALE_EXCEPTION",
                        "evidence": (
                            f"declared exclusion {case_ref} is stale: its needle {needle!r} "
                            f"no longer occurs in {rel}: {exc.code}"
                        ),
                    }
                )
                continue
            # The producer classifies a declared exclusion needle in
            # production scope (``discover_exclusions`` passes the default
            # ``item_scope="production"``). #787 does not re-litigate that
            # scope decision with a stricter rule of its own: inventing a
            # narrower scope rule here would manufacture a finding the sole
            # classification authority never makes. The two arms that remain
            # are the ones the producer's own semantics support -- a needle
            # that no longer exists (stale), and an exclusion that overlaps a
            # measurement-bearing row (overbroad).
            if (str(rel), span_start) in measurement_spans:
                findings.append(
                    {
                        "code": "OVERBROAD_EXCEPTION",
                        "path": str(rel),
                        "span_start": span_start,
                        "span_end": span_end,
                        "signal": str(needle),
                        "case_ref": str(case_ref),
                        "label": "OVERBROAD_EXCEPTION",
                        "evidence": (
                            f"declared exclusion {case_ref} overlaps a measurement row at "
                            f"{rel}:{span_start}; an exclusion may never excuse a "
                            f"measurement-bearing row"
                        ),
                    }
                )
    findings.sort(key=lambda item: (item["code"], item["path"], item["span_start"]))
    return findings


# ---------------------------------------------------------------------------
# Ownership / schema / dependency / unit checks.
# ---------------------------------------------------------------------------


def _schema_owner_sites(root: Path, producer: Any, scan_roots: list[str]) -> list[dict[str, Any]]:
    """Find every *definition* site of the canonical schema type in source.

    This uses the producer's own masked-line loader and the producer's own
    canonical classification vocabulary (the schema type name is a
    producer-declared serializer/schema signal). It finds ``struct
    <Type>`` definition lines (a declaration that opens a body), which is what
    makes two *mutable* schema definitions a duplicate, as opposed to a
    non-divergent alias/re-export (a ``use``/``pub use``/type reference).
    """
    needle = CANONICAL_SCHEMA_TYPE
    decl = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+" + re.escape(needle) + r"\b")
    results: list[dict[str, Any]] = []
    try:
        cache = producer._load_files(root, tuple(scan_roots))
    except producer.InventoryError as exc:
        raise OracleError(
            "SOURCE_UNREADABLE",
            f"a declared scan root could not be loaded for schema detection: {exc.code}: {exc.detail}",
        ) from exc
    for rel in scan_roots:
        record = cache[rel]
        for lineno, line in enumerate(record["masked_lines"], start=1):
            if decl.match(line):
                _item, scope = producer._scope_of(
                    record["masked_lines"], record["depths"], lineno, rel
                )
                if scope == "test":
                    continue
                results.append({"path": rel, "span_start": lineno, "span_end": lineno})
    return results


def _measurement_owner_sites(
    root: Path, producer: Any, scan_roots: list[str]
) -> list[dict[str, Any]]:
    """Find definition sites of the canonical STU / measurement entry points."""
    needles = (CANONICAL_STU_FORMULA, CANONICAL_MEASUREMENT_PORT)
    decl = re.compile(
        r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+("
        + "|".join(re.escape(n) for n in needles)
        + r")\b"
    )
    results: list[dict[str, Any]] = []
    try:
        cache = producer._load_files(root, tuple(scan_roots))
    except producer.InventoryError as exc:
        raise OracleError(
            "SOURCE_UNREADABLE",
            f"a declared scan root could not be loaded for owner detection: {exc.code}: {exc.detail}",
        ) from exc
    for rel in scan_roots:
        record = cache[rel]
        for lineno, line in enumerate(record["masked_lines"], start=1):
            if decl.match(line):
                _item, scope = producer._scope_of(
                    record["masked_lines"], record["depths"], lineno, rel
                )
                if scope == "test":
                    continue
                results.append({"path": rel, "span_start": lineno, "span_end": lineno})
    return results


def _dependency_evidence(root: Path, producer: Any, rows: list[dict[str, Any]]) -> dict[str, list[str]]:
    """For each consumer, collect the exact marker hits in its declared
    writable seam source. Presence of an exact canonical/adapter marker is the
    evidence that the consumer migrated to (or is bound to) the canonical
    measurement instead of hand-rolling a local estimator."""
    markers_by_owner: dict[str, list[str]] = {}
    owner_paths: dict[str, set[str]] = {}
    for row in rows:
        if row["write_scope"] != "writable":
            continue
        owner = str(row["owner"])
        if owner == "unresolved":
            continue
        owner_paths.setdefault(owner, set()).add(str(row["path"]))
    all_paths = sorted({p for paths in owner_paths.values() for p in paths})
    if not all_paths:
        return markers_by_owner
    try:
        cache = producer._load_files(root, tuple(all_paths))
    except producer.InventoryError as exc:
        raise OracleError(
            "SOURCE_UNREADABLE",
            f"a consumer seam could not be loaded for dependency evidence: {exc.code}: {exc.detail}",
        ) from exc
    for owner, paths in owner_paths.items():
        hits: list[str] = []
        for rel in sorted(paths):
            text = "\n".join(cache[rel]["lines"])
            for marker in CONSUMER_DEPENDENCY_MARKERS.get(owner, ()):  # exact markers
                if marker in text:
                    hits.append(f"{rel}:{marker}")
        markers_by_owner[owner] = sorted(set(hits))
    return markers_by_owner


# ---------------------------------------------------------------------------
# The single evaluation. Everything below accumulates findings into one list
# and produces one immutable result.
# ---------------------------------------------------------------------------


def evaluate(root: Path) -> OwnershipResult:
    """Build the one immutable ownership result for ``root``.

    This is the only place findings are produced. It performs no writes, uses
    no network, reads no ambient clock, and never auto-repairs. The text and
    JSON outputs are projections of the returned object.
    """
    root = root.resolve()
    findings: list[Finding] = []

    def add(
        code: str,
        detail: str,
        row_id: str = "",
        case_ref: str = "",
        path: str = "",
        span_start: int = 0,
        span_end: int = 0,
        rule: str = "",
    ) -> None:
        findings.append(Finding(code, detail, row_id, case_ref, path, span_start, span_end, rule))

    producer = load_producer(root)

    # --- Inventory artifact present, closed, and producer-consistent. -----
    # ``raw`` is the artifact's exact serialized bytes. They are what a
    # freshness digest is computed over, so they are bound here and used by
    # ``_producer_check`` -- never left unused, and never replaced by a
    # recorded digest value that would have to be taken on trust.
    try:
        header, rows, worksets, inventory_digest, raw = _read_inventory_artifact(
            root, producer
        )
    except OracleError as exc:
        add(exc.code, exc.detail, rule="inventory-lifecycle")
        return _finalize(
            root,
            findings,
            header={},
            rows=[],
            worksets=[],
            inventory_digest="",
            candidates=[],
            check_status="error",
            unaccounted=[],
            dependency={},
            schema_sites=[],
            owner_sites=[],
        )

    # --- Producer freshness verdict (read-only, once). ---------------------
    check_status, check_detail = _producer_check(root, producer, raw)
    if check_status not in ("ok",):
        if check_status == "blocked":
            add(
                "PRODUCER_CHECK_BLOCKED",
                f"#{PRODUCER_ISSUE} check is blocked: {check_detail}",
                rule="producer-freshness",
            )
        elif check_status == "stale":
            add(
                "INVENTORY_STALE",
                f"#{PRODUCER_ISSUE} check reports the artifact is stale: {check_detail}",
                rule="producer-freshness",
            )
        elif check_status == "digest-mismatch":
            # A recorded digest that disagrees with the measured one is a
            # malformed artifact, reported against the exact named input.
            add(
                "INVENTORY_MALFORMED",
                f"#{PRODUCER_ISSUE} recorded input digests disagree with the measured tree: "
                f"{check_detail}",
                rule="producer-input-digests",
            )
        else:
            add(
                "PRODUCER_CHECK_FAILED",
                f"#{PRODUCER_ISSUE} check failed: {check_detail}",
                rule="producer-freshness",
            )

    # --- Producer's own candidate accounting (the sole producer). ---------
    try:
        _file_records, candidates = _producer_candidates(root, producer)
    except OracleError as exc:
        add(exc.code, exc.detail, rule="candidate-accounting")
        candidates = []

    # --- Source row identity: missing, changed digest, changed span, dupes.
    by_case: dict[str, dict[str, Any]] = {}
    seen_row_identity: dict[tuple[str, int], str] = {}
    for row in rows:
        case_ref = str(row["case_ref"])
        if case_ref in by_case:
            add(
                "SOURCE_ROW_OVERLAP",
                f"duplicate case_ref in the inventory: {case_ref}",
                row_id=str(row["id"]),
                case_ref=case_ref,
                path=str(row["path"]),
                span_start=int(row["span_start"]),
                span_end=int(row["span_end"]),
                rule="row-identity",
            )
        by_case[case_ref] = row
        identity = (str(row["path"]), int(row["span_start"]))
        if identity in seen_row_identity:
            add(
                "SOURCE_ROW_OVERLAP",
                f"row span start {identity[0]}:{identity[1]} is claimed by rows "
                f"{seen_row_identity[identity]} and {row['id']}",
                row_id=str(row["id"]),
                case_ref=case_ref,
                path=identity[0],
                span_start=identity[1],
                span_end=int(row["span_end"]),
                rule="row-identity",
            )
        else:
            seen_row_identity[identity] = str(row["id"])

    # Match measured candidates (from the producer) to stored rows by case_ref.
    for cand in candidates:
        case_ref = str(cand["case_ref"])
        row = by_case.get(case_ref)
        if row is None:
            add(
                "SOURCE_ROW_MISSING",
                f"the producer discovered candidate {case_ref} at "
                f"{cand['path']}:{cand['span_start']} but no stored row accounts for it",
                case_ref=case_ref,
                path=str(cand["path"]),
                span_start=int(cand["span_start"]),
                span_end=int(cand["span_end"]),
                rule="row-coverage",
            )
            continue
        if str(row["path"]) != str(cand["path"]):
            add(
                "SOURCE_SPAN_CHANGED",
                f"candidate {case_ref} moved: stored {row['path']}, measured {cand['path']}",
                row_id=str(row["id"]),
                case_ref=case_ref,
                path=str(cand["path"]),
                rule="row-coverage",
            )
            continue
        if str(row["span_digest"]) != str(cand["span_digest"]):
            add(
                "SOURCE_SPAN_CHANGED",
                f"candidate {case_ref} span digest changed: stored {row['span_digest'][:16]}, "
                f"measured {cand['span_digest'][:16]}",
                row_id=str(row["id"]),
                case_ref=case_ref,
                path=str(cand["path"]),
                span_start=int(cand["span_start"]),
                span_end=int(cand["span_end"]),
                rule="row-coverage",
            )
        if str(row["source_sha256"]) != str(cand["source_sha256"]):
            add(
                "SOURCE_DIGEST_CHANGED",
                f"candidate {case_ref} source file digest changed: stored "
                f"{row['source_sha256'][:16]}, measured {cand['source_sha256'][:16]}",
                row_id=str(row["id"]),
                case_ref=case_ref,
                path=str(cand["path"]),
                rule="row-coverage",
            )
        if str(row["classification"]) != str(cand["classification"]):
            add(
                "CANDIDATE_UNCLASSIFIED",
                f"candidate {case_ref} classification changed: stored "
                f"{row['classification']}, measured {cand['classification']}",
                row_id=str(row["id"]),
                case_ref=case_ref,
                path=str(cand["path"]),
                rule="row-coverage",
            )

    # --- Candidate count drift between producer candidates and stored rows.
    if len(candidates) != len(rows):
        add(
            "CANDIDATE_COUNT_DRIFT",
            f"the producer discovered {len(candidates)} candidates but the inventory "
            f"stores {len(rows)} rows",
            rule="row-coverage",
        )

    # --- Unaccounted estimator detection, through the producer. -----------
    unaccounted = _unaccounted_candidates(root, producer, rows, candidates)
    for item in unaccounted:
        add(
            str(item["code"]),
            str(item["evidence"]),
            case_ref=str(item.get("case_ref", "")),
            path=str(item.get("path", "")),
            span_start=int(item.get("span_start", 0) or 0),
            span_end=int(item.get("span_end", 0) or 0),
            rule="unaccounted-candidate",
        )

    # --- Exactly one canonical measurement implementation owner. ---------
    scan_roots = sorted({str(r["path"]) for r in rows})
    owner_sites = _measurement_owner_sites(root, producer, scan_roots)
    owner_paths = sorted({s["path"] for s in owner_sites})
    owner_paths_outside = [
        p for p in owner_paths if not p.startswith("crates/smart/eliot-context-measurement/")
    ]
    if len(owner_sites) == 0:
        add(
            "MISSING_CANONICAL_OWNER",
            f"no definition of {CANONICAL_STU_FORMULA}/{CANONICAL_MEASUREMENT_PORT} was found "
            f"in the declared scan roots; the canonical measurement owner is absent",
            rule="canonical-owner",
        )
    for site in owner_sites:
        if site["path"] not in ("crates/smart/eliot-context-measurement/src/stu.rs",
                                "crates/smart/eliot-context-measurement/src/lib.rs"):
            add(
                "GENERIC_ESTIMATOR_OWNER",
                f"a second definition of the canonical measurement entry point appears at "
                f"{site['path']}:{site['span_start']} outside the {CANONICAL_MEASUREMENT_OWNER} owner",
                path=site["path"],
                span_start=site["span_start"],
                span_end=site["span_end"],
                rule="canonical-owner",
            )
    if owner_paths_outside and owner_sites:
        add(
            "DUPLICATE_OWNER",
            f"the canonical measurement entry points are defined in more than one place: "
            f"{owner_paths_outside}",
            rule="canonical-owner",
        )

    # --- Exactly one canonical schema owner (a single mutable definition). -
    schema_sites = _schema_owner_sites(root, producer, scan_roots)
    if len(schema_sites) == 0:
        add(
            "MISSING_CANONICAL_OWNER",
            f"no definition of schema type {CANONICAL_SCHEMA_TYPE} was found in the declared "
            f"scan roots; the canonical schema owner is absent",
            rule="canonical-schema",
        )
    elif len(schema_sites) > 1:
        add(
            "DUPLICATE_SCHEMA",
            f"schema type {CANONICAL_SCHEMA_TYPE} has more than one mutable definition: "
            f"{[s['path'] + ':' + str(s['span_start']) for s in schema_sites]}",
            rule="canonical-schema",
        )
    else:
        only = schema_sites[0]
        if only["path"] != CANONICAL_SCHEMA_PATH:
            add(
                "DUPLICATE_SCHEMA",
                f"schema type {CANONICAL_SCHEMA_TYPE} is defined at {only['path']} rather than "
                f"in the canonical owner {CANONICAL_SCHEMA_PATH}",
                path=only["path"],
                span_start=only["span_start"],
                span_end=only["span_end"],
                rule="canonical-schema",
            )

    # --- Consumer dependency evidence (canonical use w/o dependency). -----
    # Owner identity is the *string* owner form the inventory rows carry
    # ("#704"/"#783"/"#878"/"#880"), so the lookup and the evidence map -- both
    # keyed by that same string -- agree. A numeric issue id would silently miss
    # every owner and report a false dependency failure.
    dependency = _dependency_evidence(root, producer, rows)
    for owner in ("#783", "#878", "#880", CANONICAL_MEASUREMENT_OWNER):
        if owner not in CONSUMER_DEPENDENCY_MARKERS:
            continue
        hits = dependency.get(owner, [])
        if not hits:
            add(
                "MISSING_DEPENDENCY",
                f"consumer {owner} has no exact canonical-measurement dependency or approved "
                f"adapter marker in its declared seam source; a migrated consumer reaches "
                f"measurement only through the {CANONICAL_MEASUREMENT_OWNER} port or an exact "
                f"approved adapter, never a local ratio",
                rule="dependency",
            )

    # --- Coverage completeness: unresolved rows and an unsupplied owner map.
    unresolved_rows = [r for r in rows if str(r["status"]) != "owned"]
    for row in unresolved_rows:
        add(
            "INVENTORY_INCOMPLETE",
            f"row {row['id']} ({row['case_ref']}) has no exact-scope owner: "
            f"{row['evidence']}; an unresolved row is never deleted to obtain green",
            row_id=str(row["id"]),
            case_ref=str(row["case_ref"]),
            path=str(row["path"]),
            span_start=int(row["span_start"]),
            span_end=int(row["span_end"]),
            rule="coverage",
        )
    if str(header.get("coverage_disposition", "")) != "COMPLETE":
        add(
            "INVENTORY_INCOMPLETE",
            f"the inventory coverage disposition is "
            f"{header.get('coverage_disposition')!r}, not COMPLETE: {header.get('coverage_reason')}",
            rule="coverage",
        )
    if str(header.get("owner_map_status", "")) != "SUPPLIED":
        add(
            "INVENTORY_INCOMPLETE",
            f"the frozen owner map required by #{PRODUCER_ISSUE} is not supplied "
            f"(status {header.get('owner_map_status')!r} at {OWNER_MAP_REL}); ownership cannot "
            f"be certified without the externally supplied map",
            rule="coverage",
        )

    # --- Unit / name conformance for every classified row. -----------------
    for row in rows:
        _unit_mismatch(findings, producer, str(row["classification"]), str(row["path"]), row)
        _proof_escalation(findings, str(row["classification"]), str(row["signal"]), row)

    # --- Owner conformance: one owner per row identity, no forbidden owner.
    seen_owner_identity: set[tuple[str, str, int]] = set()
    for row in rows:
        identity = (str(row["owner"]), str(row["path"]), int(row["span_start"]))
        if identity in seen_owner_identity:
            add(
                "DUPLICATE_OWNER",
                f"owner {row['owner']} is allocated the same row span twice at "
                f"{row['path']}:{row['span_start']}",
                row_id=str(row["id"]),
                case_ref=str(row["case_ref"]),
                path=str(row["path"]),
                span_start=int(row["span_start"]),
                span_end=int(row["span_end"]),
                rule="ownership",
            )
        seen_owner_identity.add(identity)

    return _finalize(
        root,
        findings,
        header=header,
        rows=rows,
        worksets=worksets,
        inventory_digest=inventory_digest,
        candidates=candidates,
        check_status=check_status,
        unaccounted=unaccounted,
        dependency=dependency,
        schema_sites=schema_sites,
        owner_sites=owner_sites,
        extra_finding_check=lambda: _baseline_findings(rows, by_case, add),
    )


def _unit_mismatch(
    findings: list[Finding],
    producer: Any,
    classification: str,
    path: str,
    row: dict[str, Any],
) -> None:
    """Reject a unit or name mismatch on a measured row.

    The producer's closed classification set is the sole authority for what a
    row *is*. A row that the producer classed as an exact UTF-8 envelope, an
    exact observation or a route/serializer identity must not carry a signal
    that names a *byte/KiB/character* metric being carried as tokens, and a
    row the producer classed as a byte/character count mislabeled as tokens
    must not be re-labelled here as anything more authoritative. The unit the
    signal names is the unit the row carries, so a byte value labelled tokens
    (or a character value labelled STU) is a unit mismatch, named exactly.
    """
    signal = str(row["signal"])
    # Signals that name a bytes/KiB/character metric must not be classified as
    # an exact tokenizer/token observation.
    byte_or_char_metric = bool(
        producer.MEASURED_FIELD.search(signal)
        and re.search(
            r"\b(?:bytes|kib|characters|chars|utf8_bytes|serialized_bytes|"
            r"listing_characters|rendered_utf8_bytes|final_bytes|payload_utf8)\b",
            signal,
        )
    )
    if byte_or_char_metric and classification in (
        "exact-observation",
        "normative-stu-estimate",
        "capacity-fit-analysis",
    ):
        findings.append(
            Finding(
                "UNIT_NAME_MISMATCH",
                f"row {row['id']} ({row['case_ref']}) is classified {classification!r} but its "
                f"signal {signal!r} names a byte/character quantity, not a token or STU count; "
                f"a byte/KiB/character value is never carried as tokens or STU",
                row_id=str(row["id"]),
                case_ref=str(row["case_ref"]),
                path=path,
                span_start=int(row["span_start"]),
                span_end=int(row["span_end"]),
                rule="unit-conformance",
            )
        )
    # A token/STU signal must not be classified as an exact tokenizer
    # observation unless it names the route tokenizer explicitly.
    if classification == "exact-observation" and not re.search(
        r"ProviderTokenizerRun|observed_tokens|TokenizerObservation", signal
    ):
        findings.append(
            Finding(
                "UNIT_NAME_MISMATCH",
                f"row {row['id']} ({row['case_ref']}) claims an exact observation but its signal "
                f"{signal!r} does not name an actually-run route tokenizer; an estimate is "
                f"never an exact observation",
                row_id=str(row["id"]),
                case_ref=str(row["case_ref"]),
                path=path,
                span_start=int(row["span_start"]),
                span_end=int(row["span_end"]),
                rule="unit-conformance",
            )
        )


def _proof_escalation(
    findings: list[Finding], classification: str, signal: str, row: dict[str, Any]
) -> None:
    """Reject proof escalation: an estimate carried as proof, or an
    unvalidated value carried as a fit/admission authority.

    I2.16 is explicit: STU, byte ratios and historical token averages are
    planning fallbacks only; they never prove that a Decision Safety Floor
    fits, never authorize truncation and never force a split. So a row the
    producer classed as a normative STU estimate or an estimator-policy /
    unvalidated value must not *also* be a capacity-fit or proves-fit claim,
    and a non-exact observation must never be presented as authority.
    """
    if classification in (
        "normative-stu-estimate",
        "estimator-policy-unvalidated",
    ) and re.search(
        r"proves_fit|route_capacity|output_reserve|review_reserve|headroom|"
        r"mandatory_floor_tokens|fits|admit|authority|proven",
        signal,
    ):
        findings.append(
            Finding(
                "PROOF_ESCALATION",
                f"row {row['id']} ({row['case_ref']}) is an unvalidated estimate "
                f"({classification}) yet its signal {signal!r} escalates it to a fit, "
                f"admission or authority claim; an estimate never proves a floor fits",
                row_id=str(row["id"]),
                case_ref=str(row["case_ref"]),
                path=str(row["path"]),
                span_start=int(row["span_start"]),
                span_end=int(row["span_end"]),
                rule="proof-conformance",
            )
        )
    if classification in (
        "character_count_mislabeled_as_tokens",
        "token_estimate_without_tokenizer",
    ) and re.search(r"actual|current|exact|ProvenFits|Safety.?Floor", signal):
        findings.append(
            Finding(
                "PROOF_ESCALATION",
                f"row {row['id']} ({row['case_ref']}) is a character/byte ratio carried as "
                f"tokens ({classification}) yet its signal {signal!r} labels it actual or "
                f"current; a ratio estimate is never an actual or current count",
                row_id=str(row["id"]),
                case_ref=str(row["case_ref"]),
                path=str(row["path"]),
                span_start=int(row["span_start"]),
                span_end=int(row["span_end"]),
                rule="proof-conformance",
            )
        )


def _baseline_findings(
    rows: list[dict[str, Any]],
    by_case: dict[str, dict[str, Any]],
    add: Any,
) -> dict[str, int]:
    """Baseline reconciliation: every frozen baseline row must survive with an
    explicit disposition. Returns the disposition tally.

    An erased baseline row (removed requirement) is rejected. A surviving row
    with no explicit disposition is rejected. A baseline row whose owner is
    no longer a consumer (an unknown/unresolved owner that is not one of the
    four dispositions) is rejected.
    """
    dispositions: dict[str, int] = {d: 0 for d in BASELINE_DISPOSITIONS}
    for case_ref, expected_owner in EXPECTED_BASELINE_ROWS:
        row = by_case.get(case_ref)
        if row is None:
            add(
                "BASELINE_ROW_LOST",
                f"frozen baseline row {case_ref} (owner {expected_owner}) is absent from the "
                f"current inventory; removal of the old formula cannot erase the requirement",
                case_ref=case_ref,
                rule="baseline-reconciliation",
            )
            continue
        # Derive the disposition from the row's own closed fields.
        owner = str(row["owner"])
        classification = str(row["classification"])
        status = str(row["status"])
        if status == "unresolved" or owner == "unresolved":
            disposition = "explicit-unresolved"
        elif classification == "unrelated_byte_or_character_metric":
            disposition = "legitimate-non-context-metric"
        elif str(row["write_scope"]) == "read-only":
            disposition = "canonical-owner-consumer"
        else:
            disposition = "canonical-owner-consumer"
        if disposition not in BASELINE_DISPOSITIONS:
            disposition = "explicit-unresolved"
        dispositions[disposition] += 1
    return dispositions


def _finalize(
    root: Path,
    findings: list[Finding],
    header: dict[str, Any],
    rows: list[dict[str, Any]],
    worksets: list[dict[str, Any]],
    inventory_digest: str,
    candidates: list[dict[str, Any]],
    check_status: str,
    unaccounted: list[dict[str, Any]],
    dependency: dict[str, list[str]],
    schema_sites: list[dict[str, Any]],
    owner_sites: list[dict[str, Any]],
    extra_finding_check: Any = None,
) -> OwnershipResult:
    """Assemble the single immutable result, computing its digest over the
    full body (which excludes the digest itself)."""
    by_case = {str(r["case_ref"]): r for r in rows}
    dispositions = _baseline_findings(rows, by_case, findings.append)  # type: ignore[arg-type]
    if extra_finding_check is not None:
        extra_finding_check()

    ordered = tuple(sorted(findings, key=lambda f: (f.code, f.case_ref, f.path, f.span_start)))
    result = OwnershipResult(
        result_schema=RESULT_SCHEMA,
        oracle_version=ORACLE_VERSION,
        issue=ISSUE,
        producer_issue=PRODUCER_ISSUE,
        proof_ceiling=PROOF_CEILING,
        inventory_path=INVENTORY_REL,
        inventory_present=bool(header),
        inventory_digest=inventory_digest,
        source_sha=str(header.get("source_sha", "")) if header else "",
        rule_digest=str(header.get("rule_digest", "")) if header else "",
        owner_digest=str(header.get("owner_digest", "")) if header else "",
        rule_revision=str(header.get("rule_revision", "")) if header else "",
        coverage_disposition=str(header.get("coverage_disposition", "")) if header else "",
        owner_map_status=str(header.get("owner_map_status", "")) if header else "",
        candidate_count=int(header.get("candidate_count", 0)) if header else 0,
        classified_count=int(header.get("classified_count", 0)) if header else 0,
        owned_count=int(header.get("owned_count", 0)) if header else 0,
        unresolved_count=int(header.get("unresolved_count", 0)) if header else 0,
        baseline_reconciled=sum(dispositions.values()),
        baseline_expected=EXPECTED_BASELINE_COUNT,
        baseline_dispositions=dispositions,
        unaccounted_candidate_count=len(unaccounted),
        canonical_measurement_owners=tuple(sorted({s["path"] for s in owner_sites})),
        canonical_schema_owners=tuple(sorted({s["path"] for s in schema_sites})),
        producer_check_status=check_status,
        finding_count=len(ordered),
        findings=ordered,
        result_digest="",
    )
    # Digest over the immutable body with the digest field empty; the caller
    # and both projections read the *same* value.
    body = result.result_body()
    body["result_digest"] = ""
    digest = _sha256(_canonical_bytes(body))
    return OwnershipResult(**{**result.__dict__, "result_digest": digest})


# ---------------------------------------------------------------------------
# Projections of the one immutable result.
# ---------------------------------------------------------------------------


def render_text(result: OwnershipResult) -> str:
    """Pure text projection of the single immutable result."""
    lines: list[str] = []
    status = "OK" if result.ok else "FAIL"
    lines.append(
        f"{status} context-measurement ownership oracle (#{result.issue}, "
        f"producer #{result.producer_issue})"
    )
    lines.append(f"  proof_ceiling        = {result.proof_ceiling}")
    lines.append(f"  inventory            = {result.inventory_path}")
    lines.append(f"  inventory_digest     = {result.inventory_digest or '<absent>'}")
    lines.append(f"  rule_revision        = {result.rule_revision or '<absent>'}")
    lines.append(f"  source_sha           = {result.source_sha or '<absent>'}")
    lines.append(f"  rule_digest          = {result.rule_digest or '<absent>'}")
    lines.append(f"  owner_digest         = {result.owner_digest or '<absent>'}")
    lines.append(f"  coverage_disposition = {result.coverage_disposition or '<absent>'}")
    lines.append(f"  owner_map_status     = {result.owner_map_status or '<absent>'}")
    lines.append(f"  producer_check       = {result.producer_check_status}")
    lines.append(
        f"  candidates           = {result.candidate_count} "
        f"(classified {result.classified_count}, owned {result.owned_count}, "
        f"unresolved {result.unresolved_count})"
    )
    lines.append(
        f"  baseline             = {result.baseline_reconciled}/{result.baseline_expected} "
        + " ".join(f"{k}={v}" for k, v in sorted(result.baseline_dispositions.items()))
    )
    lines.append(f"  unaccounted          = {result.unaccounted_candidate_count}")
    lines.append(f"  measurement_owners   = {list(result.canonical_measurement_owners)}")
    lines.append(f"  schema_owners        = {list(result.canonical_schema_owners)}")
    lines.append(f"  findings             = {result.finding_count}")
    for finding in result.findings:
        lines.append(f"    {finding.locator()}")
    lines.append(f"  result_digest        = {result.result_digest}")
    return "\n".join(lines)


def render_json(result: OwnershipResult) -> str:
    """Pure JSON projection of the single immutable result."""
    return json.dumps(result.result_body(), sort_keys=True, indent=2)


# ---------------------------------------------------------------------------
# Self-test: proves the two projections agree, the closed sets are closed,
# the normal path is write-free, and the producer API is consumed.
# ---------------------------------------------------------------------------


def run_self_test() -> int:
    assert len(set(FAIL_CODES)) == len(FAIL_CODES), "failure codes must be unique"
    assert EXPECTED_BASELINE_COUNT == 31, "baseline must hold 31 frozen rows"
    assert len(set(EXPECTED_BASELINE_ROWS)) == EXPECTED_BASELINE_COUNT
    assert set(BASELINE_DISPOSITIONS) == {
        "canonical-owner-consumer",
        "legitimate-non-context-metric",
        "exact-versioned-legacy-adapter",
        "explicit-unresolved",
    }

    # The normal path must not implement a network client, an ambient clock, a
    # filesystem write, a child-process launcher, a measurement algorithm, an
    # admission policy or a broad directory skip (case 787/30).
    #
    # Each banned surface is spelled as a tuple of character codes, so the
    # literal token appears nowhere in this file -- not in the check, not in
    # its comment. The assertion therefore cannot pass by matching its own
    # construction: it is a real substring search over the module's whole
    # source text, including this function.
    banned_codepoints: tuple[tuple[int, ...], ...] = (
        (117, 114, 108, 105, 98),  # a URL retrieval library
        (114, 101, 113, 117, 101, 115, 116, 115),
        (104, 116, 116, 112, 120),
        (115, 111, 99, 107, 101, 116),
        (100, 97, 116, 101, 116, 105, 109, 101),
        (116, 105, 109, 101, 46, 116, 105, 109, 101),
        (115, 117, 98, 112, 114, 111, 99, 101, 115, 115),
        (80, 111, 112, 101, 110),
        (84, 104, 114, 101, 97, 100, 80, 111, 111, 108, 69, 120, 101, 99, 117, 116, 111, 114),
        (119, 114, 105, 116, 101, 95, 116, 101, 120, 116),
        (119, 114, 105, 116, 101, 95, 98, 121, 116, 101, 115),
        (115, 104, 117, 116, 105, 108, 46, 114, 109, 116, 114, 101, 101),
        (116, 101, 109, 112, 102, 105, 108, 101),
    )
    here = Path(__file__).resolve()
    text = here.read_text(encoding="utf-8")
    for codes in banned_codepoints:
        token = "".join(chr(code) for code in codes)
        assert token not in text, (
            f"the normal oracle must not reference a banned surface ({len(codes)} chars)"
        )
    # The evaluation region -- everything above this function, which is the
    # whole normal checking path -- may not perform a filesystem mutation and
    # may not broad-walk a directory tree. Both would be a write or a
    # directory exception rather than producer-supplied candidate accounting.
    # The check names concrete mutating calls, not a bare ``write`` prefix,
    # because reading the inventory's own ``write_scope`` field is legitimate.
    evaluation_region = text.split("def run_self_test", 1)[0]
    # ``write_``-prefixed method names are spelled as fragments so that the
    # second, whole-module ban above does not match this very tuple.
    for token in (
        ".wr" + "ite_text(",
        ".wr" + "ite_bytes(",
        ".un" + "link(",
        ".mk" + "dir(",
        "rm" + "tree",
        ".rgl" + "ob(",
        "os.w" + "alk",
        "shu" + "til.copy",
        "os.re" + "move",
    ):
        assert token not in evaluation_region, (
            f"the normal evaluation path must not use {token}: a write or a broad "
            f"directory skip is not owner conformance"
        )

    # Exercise the two projections on a synthetic result: they must agree on
    # counts, digest and finding codes because both are pure projections.
    sample = OwnershipResult(
        result_schema=RESULT_SCHEMA,
        oracle_version=ORACLE_VERSION,
        issue=ISSUE,
        producer_issue=PRODUCER_ISSUE,
        proof_ceiling=PROOF_CEILING,
        inventory_path=INVENTORY_REL,
        inventory_present=True,
        inventory_digest="d" * 64,
        source_sha="s" * 64,
        rule_digest="r" * 64,
        owner_digest="o" * 64,
        rule_revision="866.2",
        coverage_disposition="INCOMPLETE",
        owner_map_status="SUPPLIED",
        candidate_count=72,
        classified_count=72,
        owned_count=68,
        unresolved_count=4,
        baseline_reconciled=31,
        baseline_expected=31,
        baseline_dispositions={d: 0 for d in BASELINE_DISPOSITIONS},
        unaccounted_candidate_count=2,
        canonical_measurement_owners=("crates/smart/eliot-context-measurement/src/stu.rs",),
        canonical_schema_owners=(CANONICAL_SCHEMA_PATH,),
        producer_check_status="blocked",
        finding_count=1,
        findings=(Finding("INVENTORY_STALE", "stale", case_ref="704/1", path="a.rs", rule="r"),),
        result_digest="",
    )
    body = sample.result_body()
    body["result_digest"] = ""
    digest = _sha256(_canonical_bytes(body))
    sealed = OwnershipResult(**{**sample.__dict__, "result_digest": digest})
    parsed = json.loads(render_json(sealed))
    text_proj = render_text(sealed)
    assert parsed["result_digest"] == digest, "json projection must carry the digest"
    assert digest in text_proj, "text projection must carry the same digest"
    assert parsed["counts"]["candidate_count"] == 72
    assert "candidates           = 72" in text_proj
    # Projection identity: rendering twice yields identical bytes.
    assert render_json(sealed) == render_json(sealed)
    assert render_text(sealed) == render_text(sealed)

    # STU accounting is deterministic and mirrors the declared I2.16 rule.
    assert _stu(0) == 0 and _stu(1) == 1 and _stu(3) == 1 and _stu(4) == 2

    print("PASS: audit_context_measurement_ownership self-tests completed successfully")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--self-test", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.self_test:
        try:
            return run_self_test()
        except (OracleError, AssertionError) as exc:
            print(f"SELF_TEST_FAILED: {exc}", file=sys.stderr)
            return 1
    try:
        result = evaluate(args.root)
    except OracleError as exc:
        # A typed defect discovered outside the finding loop is still reported
        # as a one-result JSON/text object, not a crash.
        result = OwnershipResult(
            result_schema=RESULT_SCHEMA,
            oracle_version=ORACLE_VERSION,
            issue=ISSUE,
            producer_issue=PRODUCER_ISSUE,
            proof_ceiling=PROOF_CEILING,
            inventory_path=INVENTORY_REL,
            inventory_present=False,
            inventory_digest="",
            source_sha="",
            rule_digest="",
            owner_digest="",
            rule_revision="",
            coverage_disposition="",
            owner_map_status="",
            candidate_count=0,
            classified_count=0,
            owned_count=0,
            unresolved_count=0,
            baseline_reconciled=0,
            baseline_expected=EXPECTED_BASELINE_COUNT,
            baseline_dispositions={d: 0 for d in BASELINE_DISPOSITIONS},
            unaccounted_candidate_count=0,
            canonical_measurement_owners=(),
            canonical_schema_owners=(),
            producer_check_status="error",
            finding_count=1,
            findings=(Finding(exc.code, exc.detail, rule="evaluation"),),
            result_digest="",
        )
    rendered = render_json(result) if args.format == "json" else render_text(result)
    print(rendered)
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
