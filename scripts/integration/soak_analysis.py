"""Deterministic bounded offline analyzer of #942 soak resource records.

Issue #943 (D-SOAK-ANALYZE): evaluates finite Windows resource series without
ever turning a flat graph, two similar endpoints, or missing counters into a
leak-free claim. This is analysis code, not a live test and not a
profile-qualification experiment.

Public contract (new local APIs owned by this module)::

    validate_analysis_profile(...)
    validate_run_evidence(...)
    analyze_samples(records, sampling_plan, analysis_profile, run_evidence)

``analyze_samples`` is total: content problems become explicit axis failures
in the returned :class:`AnalysisResult`, never exceptions and never dropped
rows. Only the standard library plus the #942 owner module is used. This
module performs no sampling, no process or network access, no filesystem
mutation, no threshold auto-tuning, no remediation, and no fitted statistics
(no slopes, no p-values, no post-hoc windows or baselines).

Method (algorithm revision ``fixed-window-v1``): per exact
process-generation/phase/counter series, half-open slot windows aligned to
the phase start, exact first/last/min/max/sum/count per window, adjacent
window changes under the profile's predeclared rule, absolute peaks retained
independently, and quiescent recovery compared against the profile's declared
baseline window plus tolerance. All comparisons are exact integer/rational
comparisons over a checked finite domain.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # Normal package import: python -m unittest from the repository root.
    from scripts.integration import soak_samples as _soak
except ImportError:  # Direct file load of this module next to its owner.
    import soak_samples as _soak  # type: ignore[no-redef]

__all__ = [
    "ANALYSIS_SCHEMA_FAMILY",
    "ANALYSIS_SCHEMA_VERSION",
    "ANALYSIS_SCHEMA_ID",
    "PROFILE_SCHEMA_ID",
    "RUN_EVIDENCE_SCHEMA_ID",
    "ALGORITHM_REVISION",
    "FINITE_MAX",
    "Disposition",
    "AxisName",
    "AxisStatus",
    "AnalysisError",
    "ProfileRejected",
    "EvidenceRejected",
    "Applicability",
    "Qualification",
    "ProfileCounter",
    "ProfileExpected",
    "ProfileCoverage",
    "GrowthRule",
    "RecoveryRule",
    "AnalysisLimits",
    "AnalysisProfile",
    "EvidenceProducer",
    "PreRunCommitment",
    "EvidencePhase",
    "OperationOutcome",
    "RestartEntry",
    "Cancellation",
    "CrashEntry",
    "CleanupEvidence",
    "RunEvidence",
    "AxisResult",
    "AnalysisResult",
    "validate_analysis_profile",
    "validate_run_evidence",
    "analyze_samples",
    "encode_analysis_semantic",
    "profile_content_digest",
]

ANALYSIS_SCHEMA_FAMILY = "eliot.soak_analysis"
ANALYSIS_SCHEMA_VERSION = 1
ANALYSIS_SCHEMA_ID = "eliot.soak_analysis/v1"
PROFILE_SCHEMA_ID = "eliot.soak_analysis_profile/v1"
RUN_EVIDENCE_SCHEMA_ID = "eliot.soak_run_evidence/v1"
ALGORITHM_REVISION = "fixed-window-v1"

# Checked finite numeric domain. Every integer consumed or derived here must
# lie within [0, FINITE_MAX]; floats, bools-as-ints, and out-of-domain values
# are explicit failures, never coerced. Intermediate exact products use
# Python big integers and are re-checked before use, so no silent overflow,
# NaN, Infinity, or empty denominator can pass.
FINITE_MAX = 2**62

_REASON_TRUNCATION_MARK = "reasons_truncated"

_MAX_REF_LEN = 256
_MAX_DETAIL_LEN = 512
_MAX_PHASE_ROLES = 256
_MAX_COUNTERS = 8
_MAX_ABS_BOUND_KEYS = 8
_MAX_EVIDENCE_PHASES = 256
_MAX_OPERATIONS = 4096
_MAX_RESTARTS = 1024
_MAX_CRASHES = 1024


class Disposition(str, Enum):
    """Closed summary dispositions in presentation-precedence order."""

    WORKLOAD_FAILURE = "WorkloadFailure"
    RESOURCE_VIOLATION = "ResourceViolation"
    INCOMPLETE_EVIDENCE = "IncompleteEvidence"
    INCONCLUSIVE_PROFILE = "InconclusiveProfile"
    OBSERVED_WITHIN_QUALIFIED_ENVELOPE = "ObservedWithinQualifiedEnvelope"


class AxisName(str, Enum):
    INPUT_INTEGRITY_COVERAGE = "input_integrity_coverage"
    PROFILE_QUALIFICATION = "profile_qualification"
    RESOURCE = "resource"
    WORKLOAD = "workload"
    CLEANUP = "cleanup"


class AxisStatus(str, Enum):
    SATISFIED = "satisfied"
    VIOLATED = "violated"
    UNKNOWN = "unknown"
    NOT_EVALUATED = "not_evaluated"


class AnalysisError(Exception):
    """Base error for analyzer contract violations."""


class ProfileRejected(AnalysisError):
    """An analysis profile failed closed shape validation."""


class EvidenceRejected(AnalysisError):
    """Run evidence failed closed shape validation."""


class _BudgetExceeded(Exception):
    """Internal signal: a profile analysis limit was reached."""


# ---------------------------------------------------------------------------
# Analysis profile types (thresholds owned by #700/#885 successors)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Applicability:
    sample_schema: str
    source_ref: str
    workload_ref: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_schema": self.sample_schema,
            "source_ref": self.source_ref,
            "workload_ref": self.workload_ref,
        }


@dataclass(frozen=True)
class Qualification:
    status: str  # "qualified" | "exploratory"
    qualification_ref: str
    issuer_ref: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "qualification_ref": self.qualification_ref,
            "issuer_ref": self.issuer_ref,
        }


@dataclass(frozen=True)
class ProfileCounter:
    name: str
    unit: str

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "unit": self.unit}


@dataclass(frozen=True)
class ProfileExpected:
    cadence_ms: int
    expected_slots: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cadence_ms": self.cadence_ms,
            "expected_slots": self.expected_slots,
        }


@dataclass(frozen=True)
class ProfileCoverage:
    min_coverage_num: int
    min_coverage_den: int
    max_gap_slots: int
    require_terminal: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "min_coverage_num": self.min_coverage_num,
            "min_coverage_den": self.min_coverage_den,
            "max_gap_slots": self.max_gap_slots,
            "require_terminal": self.require_terminal,
        }


@dataclass(frozen=True)
class GrowthRule:
    statistic: str  # first | last | min | max | mean_floor
    consecutive_windows: int
    allowed_delta: int
    applies_to_roles: Tuple[str, ...]
    counters: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "statistic": self.statistic,
            "consecutive_windows": self.consecutive_windows,
            "allowed_delta": self.allowed_delta,
            "applies_to_roles": list(self.applies_to_roles),
            "counters": list(self.counters),
        }


@dataclass(frozen=True)
class RecoveryRule:
    baseline_role: str
    baseline_selector: str  # first_window | last_window | min_window
    quiescent_role: str
    quiescent_selector: str  # first_window | last_window | min_window | max_window
    statistic: str
    tolerance: int
    counters: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "baseline_role": self.baseline_role,
            "baseline_selector": self.baseline_selector,
            "quiescent_role": self.quiescent_role,
            "quiescent_selector": self.quiescent_selector,
            "statistic": self.statistic,
            "tolerance": self.tolerance,
            "counters": list(self.counters),
        }


@dataclass(frozen=True)
class AnalysisLimits:
    max_records: int
    max_streams: int
    max_windows_total: int
    max_work_units: int
    max_total_bytes: int
    max_record_bytes: int
    max_reasons: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_records": self.max_records,
            "max_streams": self.max_streams,
            "max_windows_total": self.max_windows_total,
            "max_work_units": self.max_work_units,
            "max_total_bytes": self.max_total_bytes,
            "max_record_bytes": self.max_record_bytes,
            "max_reasons": self.max_reasons,
        }


@dataclass(frozen=True)
class AnalysisProfile:
    schema: str
    profile_ref: str
    revision: int
    applicability: Applicability
    qualification: Qualification
    counters: Tuple[ProfileCounter, ...]
    expected: ProfileExpected
    phase_roles: Tuple[Tuple[str, str], ...]  # sorted (phase_id, role) pairs
    window_slots: int
    coverage: ProfileCoverage
    absolute_bounds: Tuple[Tuple[str, int], ...]  # sorted (name, bound) pairs
    growth: GrowthRule
    recovery: RecoveryRule
    algorithm_revision: str
    limits: AnalysisLimits

    def role_of(self, phase_id: str) -> Optional[str]:
        for pid, role in self.phase_roles:
            if pid == phase_id:
                return role
        return None

    def bound_of(self, counter: str) -> Optional[int]:
        for name, bound in self.absolute_bounds:
            if name == counter:
                return bound
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "profile_ref": self.profile_ref,
            "revision": self.revision,
            "applicability": self.applicability.to_dict(),
            "qualification": self.qualification.to_dict(),
            "counters": [c.to_dict() for c in self.counters],
            "expected": self.expected.to_dict(),
            "phase_roles": [
                {"phase_id": pid, "role": role} for pid, role in self.phase_roles
            ],
            "window_slots": self.window_slots,
            "coverage": self.coverage.to_dict(),
            "absolute_bounds": [
                {"name": name, "max_value": bound}
                for name, bound in self.absolute_bounds
            ],
            "growth": self.growth.to_dict(),
            "recovery": self.recovery.to_dict(),
            "algorithm_revision": self.algorithm_revision,
            "limits": self.limits.to_dict(),
        }


def profile_content_digest(profile: AnalysisProfile) -> str:
    """Canonical digest of the complete normalized profile content.

    The pre-run commitment binds this digest: reusing the same profile_ref
    and revision with altered thresholds, rules, or limits after the run
    changes the digest and is rejected as post-run substitution.
    """
    encoded = json.dumps(
        profile.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


_PROFILE_KEYS = (
    "schema",
    "profile_ref",
    "revision",
    "applicability",
    "qualification",
    "counters",
    "expected",
    "phase_roles",
    "window_slots",
    "coverage",
    "absolute_bounds",
    "growth",
    "recovery",
    "algorithm_revision",
    "limits",
)
_APPLICABILITY_KEYS = ("sample_schema", "source_ref", "workload_ref")
_QUALIFICATION_KEYS = ("status", "qualification_ref", "issuer_ref")
_PROFILE_COUNTER_KEYS = ("name", "unit")
_EXPECTED_KEYS = ("cadence_ms", "expected_slots")
_PHASE_ROLE_KEYS = ("phase_id", "role")
_COVERAGE_KEYS = (
    "min_coverage_num",
    "min_coverage_den",
    "max_gap_slots",
    "require_terminal",
)
_BOUND_KEYS = ("name", "max_value")
_GROWTH_KEYS = (
    "statistic",
    "consecutive_windows",
    "allowed_delta",
    "applies_to_roles",
    "counters",
)
_RECOVERY_KEYS = (
    "baseline_role",
    "baseline_selector",
    "quiescent_role",
    "quiescent_selector",
    "statistic",
    "tolerance",
    "counters",
)
_LIMIT_KEYS = (
    "max_records",
    "max_streams",
    "max_windows_total",
    "max_work_units",
    "max_total_bytes",
    "max_record_bytes",
    "max_reasons",
)

_PHASE_ROLES = ("warmup", "stationary", "quiescent", "excluded")
_WINDOW_STATISTICS = ("first", "last", "min", "max", "mean_floor")
_BASELINE_SELECTORS = ("first_window", "last_window", "min_window")
_QUIESCENT_SELECTORS = ("first_window", "last_window", "min_window", "max_window")
_QUALIFICATION_STATUSES = ("qualified", "exploratory")


def _profile_fail(message: str) -> ProfileRejected:
    return ProfileRejected(message)


def _require_closed_keys(
    data: Mapping[str, Any], allowed: Sequence[str], what: str
) -> None:
    extra = [k for k in data.keys() if k not in allowed]
    if extra:
        raise _profile_fail(f"{what}: extra fields rejected: {sorted(extra)!r}")
    missing = [k for k in allowed if k not in data]
    if missing:
        raise _profile_fail(f"{what}: missing fields: {sorted(missing)!r}")


def _profile_ref(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise _profile_fail(f"{name}: must be a non-empty string")
    if len(value) > _MAX_REF_LEN:
        raise _profile_fail(f"{name}: exceeds {_MAX_REF_LEN} chars")
    if any(ch < " " for ch in value):
        raise _profile_fail(f"{name}: control characters rejected")
    return value


def _profile_optional_ref(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise _profile_fail(f"{name}: must be a string")
    if len(value) > _MAX_REF_LEN:
        raise _profile_fail(f"{name}: exceeds {_MAX_REF_LEN} chars")
    if any(ch < " " for ch in value):
        raise _profile_fail(f"{name}: control characters rejected")
    return value


def _profile_int(
    value: Any, name: str, *, minimum: int = 0, maximum: int = FINITE_MAX
) -> int:
    # Bool is an int subclass in Python; a bool here is a type error, and a
    # float here is a non-finite-domain risk. Both are rejected, never coerced.
    if isinstance(value, bool) or not isinstance(value, int):
        raise _profile_fail(f"{name}: must be an integer, never bool/float")
    if isinstance(value, float):  # pragma: no cover - guarded above
        raise _profile_fail(f"{name}: non-finite float rejected")
    if not (minimum <= value <= maximum):
        raise _profile_fail(f"{name}: must be within [{minimum}, {maximum}]")
    return value


def _profile_float_reject(value: Any, name: str) -> None:
    if isinstance(value, float):
        raise _profile_fail(f"{name}: float rejected (finite integer domain)")


def _validate_applicability(data: Any) -> Applicability:
    if not isinstance(data, Mapping):
        raise _profile_fail("applicability: must be an object")
    _require_closed_keys(data, _APPLICABILITY_KEYS, "applicability")
    return Applicability(
        sample_schema=_profile_ref(data["sample_schema"], "applicability.sample_schema"),
        source_ref=_profile_ref(data["source_ref"], "applicability.source_ref"),
        workload_ref=_profile_ref(data["workload_ref"], "applicability.workload_ref"),
    )


def _validate_qualification(data: Any) -> Qualification:
    if not isinstance(data, Mapping):
        raise _profile_fail("qualification: must be an object")
    _require_closed_keys(data, _QUALIFICATION_KEYS, "qualification")
    status = data["status"]
    if status not in _QUALIFICATION_STATUSES:
        raise _profile_fail(f"qualification.status: unknown {status!r}")
    qualification_ref = _profile_optional_ref(
        data["qualification_ref"], "qualification.qualification_ref"
    )
    issuer_ref = _profile_optional_ref(data["issuer_ref"], "qualification.issuer_ref")
    if status == "qualified":
        # A bare caller assertion carries no owner evidence: a qualified claim
        # without both owner-issued references is a shape error here, and the
        # pre-run commitment binding is re-checked again at analysis time.
        if not qualification_ref or not issuer_ref:
            raise _profile_fail(
                "qualification: qualified status requires non-empty "
                "qualification_ref and issuer_ref"
            )
    else:
        if qualification_ref or issuer_ref:
            raise _profile_fail(
                "qualification: exploratory status must not carry "
                "qualification_ref/issuer_ref"
            )
    return Qualification(
        status=status,
        qualification_ref=qualification_ref,
        issuer_ref=issuer_ref,
    )


def _validate_profile_counters(data: Any) -> Tuple[ProfileCounter, ...]:
    if not isinstance(data, Sequence) or isinstance(data, (str, bytes)):
        raise _profile_fail("counters: must be an array")
    if not data or len(data) > _MAX_COUNTERS:
        raise _profile_fail(
            f"counters: must hold 1..{_MAX_COUNTERS} entries"
        )
    out: List[ProfileCounter] = []
    for index, entry in enumerate(data):
        where = f"counters[{index}]"
        if not isinstance(entry, Mapping):
            raise _profile_fail(f"{where}: must be an object")
        _require_closed_keys(entry, _PROFILE_COUNTER_KEYS, where)
        name = entry["name"]
        unit = entry["unit"]
        if name not in _soak.COUNTER_UNITS:
            raise _profile_fail(f"{where}: unknown counter {name!r}")
        if unit != _soak.COUNTER_UNITS[name]:
            raise _profile_fail(
                f"{where}: unit {unit!r} invalid for {name!r}; "
                f"must be {_soak.COUNTER_UNITS[name]!r}"
            )
        out.append(ProfileCounter(name=name, unit=unit))
    names = [c.name for c in out]
    if len(set(names)) != len(names):
        raise _profile_fail("counters: duplicate names rejected")
    required = {c.value for c in _soak.REQUIRED_COUNTERS}
    if not required.issubset(set(names)):
        raise _profile_fail(
            f"counters: required counters missing: "
            f"{sorted(required - set(names))!r}"
        )
    return tuple(out)


def _validate_profile_expected(data: Any) -> ProfileExpected:
    if not isinstance(data, Mapping):
        raise _profile_fail("expected: must be an object")
    _require_closed_keys(data, _EXPECTED_KEYS, "expected")
    return ProfileExpected(
        cadence_ms=_profile_int(data["cadence_ms"], "expected.cadence_ms", minimum=1),
        expected_slots=_profile_int(
            data["expected_slots"], "expected.expected_slots", minimum=1
        ),
    )


def _validate_phase_roles(data: Any) -> Tuple[Tuple[str, str], ...]:
    if not isinstance(data, Sequence) or isinstance(data, (str, bytes)):
        raise _profile_fail("phase_roles: must be an array")
    if not data or len(data) > _MAX_PHASE_ROLES:
        raise _profile_fail(
            f"phase_roles: must hold 1..{_MAX_PHASE_ROLES} entries"
        )
    pairs: List[Tuple[str, str]] = []
    for index, entry in enumerate(data):
        where = f"phase_roles[{index}]"
        if not isinstance(entry, Mapping):
            raise _profile_fail(f"{where}: must be an object")
        _require_closed_keys(entry, _PHASE_ROLE_KEYS, where)
        phase_id = _profile_ref(entry["phase_id"], f"{where}.phase_id")
        role = entry["role"]
        if role not in _PHASE_ROLES:
            raise _profile_fail(f"{where}: unknown role {role!r}")
        pairs.append((phase_id, role))
    ids = [p for p, _ in pairs]
    if len(set(ids)) != len(ids):
        raise _profile_fail("phase_roles: duplicate phase_id rejected")
    return tuple(sorted(pairs))


def _validate_profile_coverage(data: Any) -> ProfileCoverage:
    if not isinstance(data, Mapping):
        raise _profile_fail("coverage: must be an object")
    _require_closed_keys(data, _COVERAGE_KEYS, "coverage")
    num = _profile_int(data["min_coverage_num"], "coverage.min_coverage_num")
    den = _profile_int(
        data["min_coverage_den"], "coverage.min_coverage_den", minimum=1
    )
    if num > den:
        raise _profile_fail("coverage: min_coverage_num must not exceed den")
    require_terminal = data["require_terminal"]
    if not isinstance(require_terminal, bool):
        raise _profile_fail("coverage.require_terminal: must be a boolean")
    return ProfileCoverage(
        min_coverage_num=num,
        min_coverage_den=den,
        max_gap_slots=_profile_int(
            data["max_gap_slots"], "coverage.max_gap_slots"
        ),
        require_terminal=require_terminal,
    )


def _validate_absolute_bounds(
    data: Any, counter_names: Sequence[str]
) -> Tuple[Tuple[str, int], ...]:
    if not isinstance(data, Sequence) or isinstance(data, (str, bytes)):
        raise _profile_fail("absolute_bounds: must be an array")
    if not data or len(data) > _MAX_ABS_BOUND_KEYS:
        raise _profile_fail(
            f"absolute_bounds: must hold 1..{_MAX_ABS_BOUND_KEYS} entries"
        )
    pairs: List[Tuple[str, int]] = []
    for index, entry in enumerate(data):
        where = f"absolute_bounds[{index}]"
        if not isinstance(entry, Mapping):
            raise _profile_fail(f"{where}: must be an object")
        _require_closed_keys(entry, _BOUND_KEYS, where)
        name = entry["name"]
        if name not in counter_names:
            raise _profile_fail(
                f"{where}: {name!r} is not a profile counter"
            )
        bound = _profile_int(entry["max_value"], f"{where}.max_value")
        pairs.append((name, bound))
    names = [n for n, _ in pairs]
    if len(set(names)) != len(names):
        raise _profile_fail("absolute_bounds: duplicate names rejected")
    required = {c.value for c in _soak.REQUIRED_COUNTERS}
    if not required.issubset(set(names)):
        raise _profile_fail(
            "absolute_bounds: bounds for all required counters are mandatory: "
            f"{sorted(required - set(names))!r}"
        )
    return tuple(sorted(pairs))


def _validate_counter_subset(
    data: Any, where: str, counter_names: Sequence[str]
) -> Tuple[str, ...]:
    if not isinstance(data, Sequence) or isinstance(data, (str, bytes)):
        raise _profile_fail(f"{where}: must be an array")
    chosen = tuple(data)
    for name in chosen:
        if name not in counter_names:
            raise _profile_fail(f"{where}: {name!r} is not a profile counter")
    if len(set(chosen)) != len(chosen):
        raise _profile_fail(f"{where}: duplicates rejected")
    return chosen


def _validate_growth(data: Any, counter_names: Sequence[str]) -> GrowthRule:
    if not isinstance(data, Mapping):
        raise _profile_fail("growth: must be an object")
    _require_closed_keys(data, _GROWTH_KEYS, "growth")
    statistic = data["statistic"]
    if statistic not in _WINDOW_STATISTICS:
        raise _profile_fail(f"growth.statistic: unknown {statistic!r}")
    roles = data["applies_to_roles"]
    if not isinstance(roles, Sequence) or isinstance(roles, (str, bytes)):
        raise _profile_fail("growth.applies_to_roles: must be an array")
    roles_t = tuple(roles)
    for role in roles_t:
        if role not in ("stationary", "quiescent"):
            raise _profile_fail(
                f"growth.applies_to_roles: role {role!r} rejected "
                "(growth is judged on stationary/quiescent only)"
            )
    if len(set(roles_t)) != len(roles_t):
        raise _profile_fail("growth.applies_to_roles: duplicates rejected")
    return GrowthRule(
        statistic=statistic,
        consecutive_windows=_profile_int(
            data["consecutive_windows"], "growth.consecutive_windows", minimum=1
        ),
        allowed_delta=_profile_int(data["allowed_delta"], "growth.allowed_delta"),
        applies_to_roles=roles_t,
        counters=_validate_counter_subset(
            data["counters"], "growth.counters", counter_names
        ),
    )


def _validate_recovery(data: Any, counter_names: Sequence[str]) -> RecoveryRule:
    if not isinstance(data, Mapping):
        raise _profile_fail("recovery: must be an object")
    _require_closed_keys(data, _RECOVERY_KEYS, "recovery")
    baseline_role = data["baseline_role"]
    if baseline_role not in ("warmup", "stationary"):
        raise _profile_fail(
            f"recovery.baseline_role: {baseline_role!r} rejected "
            "(baseline is warmup/stationary only)"
        )
    baseline_selector = data["baseline_selector"]
    if baseline_selector not in _BASELINE_SELECTORS:
        raise _profile_fail(
            f"recovery.baseline_selector: unknown {baseline_selector!r}"
        )
    quiescent_role = data["quiescent_role"]
    if quiescent_role != "quiescent":
        raise _profile_fail(
            f"recovery.quiescent_role: {quiescent_role!r} rejected "
            "(must be quiescent)"
        )
    quiescent_selector = data["quiescent_selector"]
    if quiescent_selector not in _QUIESCENT_SELECTORS:
        raise _profile_fail(
            f"recovery.quiescent_selector: unknown {quiescent_selector!r}"
        )
    statistic = data["statistic"]
    if statistic not in _WINDOW_STATISTICS:
        raise _profile_fail(f"recovery.statistic: unknown {statistic!r}")
    return RecoveryRule(
        baseline_role=baseline_role,
        baseline_selector=baseline_selector,
        quiescent_role=quiescent_role,
        quiescent_selector=quiescent_selector,
        statistic=statistic,
        tolerance=_profile_int(data["tolerance"], "recovery.tolerance"),
        counters=_validate_counter_subset(
            data["counters"], "recovery.counters", counter_names
        ),
    )


def _validate_analysis_limits(data: Any) -> AnalysisLimits:
    if not isinstance(data, Mapping):
        raise _profile_fail("limits: must be an object")
    _require_closed_keys(data, _LIMIT_KEYS, "limits")
    return AnalysisLimits(
        max_records=_profile_int(data["max_records"], "limits.max_records", minimum=1),
        max_streams=_profile_int(data["max_streams"], "limits.max_streams", minimum=1),
        max_windows_total=_profile_int(
            data["max_windows_total"], "limits.max_windows_total", minimum=1
        ),
        max_work_units=_profile_int(
            data["max_work_units"], "limits.max_work_units", minimum=1
        ),
        max_total_bytes=_profile_int(
            data["max_total_bytes"], "limits.max_total_bytes", minimum=1024
        ),
        max_record_bytes=_profile_int(
            data["max_record_bytes"],
            "limits.max_record_bytes",
            minimum=256,
            maximum=16 * 1024 * 1024,
        ),
        max_reasons=_profile_int(
            data["max_reasons"], "limits.max_reasons", minimum=1
        ),
    )


def validate_analysis_profile(data: Any) -> AnalysisProfile:
    """Validate an analysis-profile mapping into a closed :class:`AnalysisProfile`.

    Shape validation only: a returned profile may still be exploratory,
    inapplicable, or unsupported, which :func:`analyze_samples` reports as an
    executable result instead of acceptance. Raises :class:`ProfileRejected`.
    """
    if isinstance(data, AnalysisProfile):
        return validate_analysis_profile(data.to_dict())
    if not isinstance(data, Mapping):
        raise _profile_fail("profile: must be an object")
    _require_closed_keys(data, _PROFILE_KEYS, "profile")
    if data["schema"] != PROFILE_SCHEMA_ID:
        raise _profile_fail(f"profile.schema: must be {PROFILE_SCHEMA_ID!r}")
    counters = _validate_profile_counters(data["counters"])
    counter_names = [c.name for c in counters]
    algorithm_revision = _profile_ref(
        data["algorithm_revision"], "profile.algorithm_revision"
    )
    return AnalysisProfile(
        schema=PROFILE_SCHEMA_ID,
        profile_ref=_profile_ref(data["profile_ref"], "profile.profile_ref"),
        revision=_profile_int(data["revision"], "profile.revision", minimum=1),
        applicability=_validate_applicability(data["applicability"]),
        qualification=_validate_qualification(data["qualification"]),
        counters=counters,
        expected=_validate_profile_expected(data["expected"]),
        phase_roles=_validate_phase_roles(data["phase_roles"]),
        window_slots=_profile_int(
            data["window_slots"], "profile.window_slots", minimum=1
        ),
        coverage=_validate_profile_coverage(data["coverage"]),
        absolute_bounds=_validate_absolute_bounds(
            data["absolute_bounds"], counter_names
        ),
        growth=_validate_growth(data["growth"], counter_names),
        recovery=_validate_recovery(data["recovery"], counter_names),
        algorithm_revision=algorithm_revision,
        limits=_validate_analysis_limits(data["limits"]),
    )


# ---------------------------------------------------------------------------
# Run evidence types (#944 owns production/provenance; this module checks shape
# locally and treats producer/issuer references as opaque provenance markers)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceProducer:
    producer_ref: str  # "" when unattested; never minted locally
    evidence_ref: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "producer_ref": self.producer_ref,
            "evidence_ref": self.evidence_ref,
        }


@dataclass(frozen=True)
class PreRunCommitment:
    plan_id: str
    profile_ref: str
    profile_revision: int
    qualification_ref: str  # "" only for exploratory profiles
    source_ref: str
    artifact_ref: str
    committed_before_workload: bool
    plan_digest: str = ""  # must equal the sampled plan's canonical digest
    profile_digest: str = ""  # must equal profile_content_digest(profile)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "profile_ref": self.profile_ref,
            "profile_revision": self.profile_revision,
            "qualification_ref": self.qualification_ref,
            "source_ref": self.source_ref,
            "artifact_ref": self.artifact_ref,
            "committed_before_workload": self.committed_before_workload,
            "plan_digest": self.plan_digest,
            "profile_digest": self.profile_digest,
        }


@dataclass(frozen=True)
class EvidencePhase:
    phase_id: str
    first_slot: int
    last_slot: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase_id": self.phase_id,
            "first_slot": self.first_slot,
            "last_slot": self.last_slot,
        }


@dataclass(frozen=True)
class OperationOutcome:
    op_ref: str
    phase_id: str
    required: bool
    expected: str  # success | failed | crashed | cancelled | unknown
    observed: str
    producer_attested: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "op_ref": self.op_ref,
            "phase_id": self.phase_id,
            "required": self.required,
            "expected": self.expected,
            "observed": self.observed,
            "producer_attested": self.producer_attested,
        }


@dataclass(frozen=True)
class RestartEntry:
    owner_ref: str
    component: str
    pid: int
    old_generation: str
    new_generation: str
    slot: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "owner_ref": self.owner_ref,
            "component": self.component,
            "pid": self.pid,
            "old_generation": self.old_generation,
            "new_generation": self.new_generation,
            "slot": self.slot,
        }


@dataclass(frozen=True)
class Cancellation:
    cancelled: bool
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {"cancelled": self.cancelled, "detail": self.detail}


@dataclass(frozen=True)
class CrashEntry:
    crash_ref: str
    detail: str
    slot: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "crash_ref": self.crash_ref,
            "detail": self.detail,
            "slot": self.slot,
        }


@dataclass(frozen=True)
class CleanupEvidence:
    disposition: str  # verified_clean | failed | unknown | quarantined
    issuer_ref: str  # "" when no owner issued the disposition
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "disposition": self.disposition,
            "issuer_ref": self.issuer_ref,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class RunEvidence:
    schema: str
    producer: EvidenceProducer
    commitment: PreRunCommitment
    phases: Tuple[EvidencePhase, ...]
    operations: Tuple[OperationOutcome, ...]
    restarts: Tuple[RestartEntry, ...]
    cancellation: Cancellation
    crashes: Tuple[CrashEntry, ...]
    cleanup: CleanupEvidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "producer": self.producer.to_dict(),
            "commitment": self.commitment.to_dict(),
            "phases": [p.to_dict() for p in self.phases],
            "operations": [o.to_dict() for o in self.operations],
            "restarts": [r.to_dict() for r in self.restarts],
            "cancellation": self.cancellation.to_dict(),
            "crashes": [c.to_dict() for c in self.crashes],
            "cleanup": self.cleanup.to_dict(),
        }


_EVIDENCE_KEYS = (
    "schema",
    "producer",
    "commitment",
    "phases",
    "operations",
    "restarts",
    "cancellation",
    "crashes",
    "cleanup",
)
_PRODUCER_KEYS = ("producer_ref", "evidence_ref")
_COMMITMENT_KEYS = (
    "plan_id",
    "profile_ref",
    "profile_revision",
    "qualification_ref",
    "source_ref",
    "artifact_ref",
    "committed_before_workload",
    "plan_digest",
    "profile_digest",
)
_EVIDENCE_PHASE_KEYS = ("phase_id", "first_slot", "last_slot")
_OPERATION_KEYS = (
    "op_ref",
    "phase_id",
    "required",
    "expected",
    "observed",
    "producer_attested",
)
_RESTART_KEYS = (
    "owner_ref",
    "component",
    "pid",
    "old_generation",
    "new_generation",
    "slot",
)
_CANCELLATION_KEYS = ("cancelled", "detail")
_CRASH_KEYS = ("crash_ref", "detail", "slot")
_CLEANUP_KEYS = ("disposition", "issuer_ref", "detail")

_OPERATION_OUTCOMES = ("success", "failed", "crashed", "cancelled", "unknown")
_CLEANUP_DISPOSITIONS = ("verified_clean", "failed", "unknown", "quarantined")


def _evidence_fail(message: str) -> EvidenceRejected:
    return EvidenceRejected(message)


def _evidence_closed_keys(
    data: Mapping[str, Any], allowed: Sequence[str], what: str
) -> None:
    extra = [k for k in data.keys() if k not in allowed]
    if extra:
        raise _evidence_fail(f"{what}: extra fields rejected: {sorted(extra)!r}")
    missing = [k for k in allowed if k not in data]
    if missing:
        raise _evidence_fail(f"{what}: missing fields: {sorted(missing)!r}")


def _evidence_ref(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise _evidence_fail(f"{name}: must be a non-empty string")
    if len(value) > _MAX_REF_LEN:
        raise _evidence_fail(f"{name}: exceeds {_MAX_REF_LEN} chars")
    if any(ch < " " for ch in value):
        raise _evidence_fail(f"{name}: control characters rejected")
    return value


def _evidence_optional_ref(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise _evidence_fail(f"{name}: must be a string")
    if len(value) > _MAX_REF_LEN:
        raise _evidence_fail(f"{name}: exceeds {_MAX_REF_LEN} chars")
    if any(ch < " " for ch in value):
        raise _evidence_fail(f"{name}: control characters rejected")
    return value


def _evidence_detail(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise _evidence_fail(f"{name}: must be a string")
    if len(value) > _MAX_DETAIL_LEN:
        raise _evidence_fail(f"{name}: exceeds {_MAX_DETAIL_LEN} chars")
    if any(ch < " " and ch not in ("\t",) for ch in value):
        raise _evidence_fail(f"{name}: control characters rejected")
    return value


def _evidence_int(
    value: Any, name: str, *, minimum: int = 0, maximum: int = FINITE_MAX
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _evidence_fail(f"{name}: must be an integer, never bool/float")
    if not (minimum <= value <= maximum):
        raise _evidence_fail(f"{name}: must be within [{minimum}, {maximum}]")
    return value


def _evidence_digest(value: Any, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise _evidence_fail(f"{name}: must be a lowercase SHA-256 digest")
    return value


def _evidence_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise _evidence_fail(f"{name}: must be a boolean")
    return value


def validate_run_evidence(data: Any) -> RunEvidence:
    """Validate run-evidence shape into a closed :class:`RunEvidence`.

    Local shape validation only. Producer validation and provenance stay with
    the #944 owner: empty ``producer_ref``/``issuer_ref`` markers are
    shape-valid but unauthenticated, and :func:`analyze_samples` treats
    unattested failure/cleanup claims as unknown evidence rather than as
    proven facts. Raises :class:`EvidenceRejected`.
    """
    if isinstance(data, RunEvidence):
        return validate_run_evidence(data.to_dict())
    if not isinstance(data, Mapping):
        raise _evidence_fail("run_evidence: must be an object")
    _evidence_closed_keys(data, _EVIDENCE_KEYS, "run_evidence")
    if data["schema"] != RUN_EVIDENCE_SCHEMA_ID:
        raise _evidence_fail(
            f"run_evidence.schema: must be {RUN_EVIDENCE_SCHEMA_ID!r}"
        )
    producer_raw = data["producer"]
    if not isinstance(producer_raw, Mapping):
        raise _evidence_fail("producer: must be an object")
    _evidence_closed_keys(producer_raw, _PRODUCER_KEYS, "producer")
    producer = EvidenceProducer(
        producer_ref=_evidence_optional_ref(
            producer_raw["producer_ref"], "producer.producer_ref"
        ),
        evidence_ref=_evidence_optional_ref(
            producer_raw["evidence_ref"], "producer.evidence_ref"
        ),
    )
    commitment_raw = data["commitment"]
    if not isinstance(commitment_raw, Mapping):
        raise _evidence_fail("commitment: must be an object")
    _evidence_closed_keys(commitment_raw, _COMMITMENT_KEYS, "commitment")
    commitment = PreRunCommitment(
        plan_id=_evidence_ref(commitment_raw["plan_id"], "commitment.plan_id"),
        profile_ref=_evidence_ref(
            commitment_raw["profile_ref"], "commitment.profile_ref"
        ),
        profile_revision=_evidence_int(
            commitment_raw["profile_revision"],
            "commitment.profile_revision",
            minimum=1,
        ),
        qualification_ref=_evidence_optional_ref(
            commitment_raw["qualification_ref"],
            "commitment.qualification_ref",
        ),
        source_ref=_evidence_ref(
            commitment_raw["source_ref"], "commitment.source_ref"
        ),
        artifact_ref=_evidence_ref(
            commitment_raw["artifact_ref"], "commitment.artifact_ref"
        ),
        committed_before_workload=_evidence_bool(
            commitment_raw["committed_before_workload"],
            "commitment.committed_before_workload",
        ),
        plan_digest=_evidence_digest(
            commitment_raw["plan_digest"], "commitment.plan_digest"
        ),
        profile_digest=_evidence_digest(
            commitment_raw["profile_digest"], "commitment.profile_digest"
        ),
    )
    phases_raw = data["phases"]
    if not isinstance(phases_raw, Sequence) or isinstance(phases_raw, (str, bytes)):
        raise _evidence_fail("phases: must be an array")
    if not phases_raw or len(phases_raw) > _MAX_EVIDENCE_PHASES:
        raise _evidence_fail(
            f"phases: must hold 1..{_MAX_EVIDENCE_PHASES} entries"
        )
    phases: List[EvidencePhase] = []
    for index, entry in enumerate(phases_raw):
        where = f"phases[{index}]"
        if not isinstance(entry, Mapping):
            raise _evidence_fail(f"{where}: must be an object")
        _evidence_closed_keys(entry, _EVIDENCE_PHASE_KEYS, where)
        first = _evidence_int(entry["first_slot"], f"{where}.first_slot")
        last = _evidence_int(entry["last_slot"], f"{where}.last_slot")
        if first > last:
            raise _evidence_fail(f"{where}: first_slot exceeds last_slot")
        phases.append(
            EvidencePhase(
                phase_id=_evidence_ref(entry["phase_id"], f"{where}.phase_id"),
                first_slot=first,
                last_slot=last,
            )
        )
    phase_ids = [p.phase_id for p in phases]
    if len(set(phase_ids)) != len(phase_ids):
        raise _evidence_fail(
            "phases: duplicate phase_id rejected (substitution rejected)"
        )
    operations_raw = data["operations"]
    if not isinstance(operations_raw, Sequence) or isinstance(
        operations_raw, (str, bytes)
    ):
        raise _evidence_fail("operations: must be an array")
    if len(operations_raw) > _MAX_OPERATIONS:
        raise _evidence_fail(
            f"operations: exceeds {_MAX_OPERATIONS} entries"
        )
    operations: List[OperationOutcome] = []
    for index, entry in enumerate(operations_raw):
        where = f"operations[{index}]"
        if not isinstance(entry, Mapping):
            raise _evidence_fail(f"{where}: must be an object")
        _evidence_closed_keys(entry, _OPERATION_KEYS, where)
        expected = entry["expected"]
        observed = entry["observed"]
        if expected not in _OPERATION_OUTCOMES:
            raise _evidence_fail(f"{where}: unknown expected {expected!r}")
        if observed not in _OPERATION_OUTCOMES:
            raise _evidence_fail(f"{where}: unknown observed {observed!r}")
        operations.append(
            OperationOutcome(
                op_ref=_evidence_ref(entry["op_ref"], f"{where}.op_ref"),
                phase_id=_evidence_ref(entry["phase_id"], f"{where}.phase_id"),
                required=_evidence_bool(entry["required"], f"{where}.required"),
                expected=expected,
                observed=observed,
                producer_attested=_evidence_bool(
                    entry["producer_attested"], f"{where}.producer_attested"
                ),
            )
        )
    op_refs = [o.op_ref for o in operations]
    if len(set(op_refs)) != len(op_refs):
        raise _evidence_fail(
            "operations: duplicate op_ref rejected (outcome double-count rejected)"
        )
    restarts_raw = data["restarts"]
    if not isinstance(restarts_raw, Sequence) or isinstance(
        restarts_raw, (str, bytes)
    ):
        raise _evidence_fail("restarts: must be an array")
    if len(restarts_raw) > _MAX_RESTARTS:
        raise _evidence_fail(f"restarts: exceeds {_MAX_RESTARTS} entries")
    restarts: List[RestartEntry] = []
    for index, entry in enumerate(restarts_raw):
        where = f"restarts[{index}]"
        if not isinstance(entry, Mapping):
            raise _evidence_fail(f"{where}: must be an object")
        _evidence_closed_keys(entry, _RESTART_KEYS, where)
        restarts.append(
            RestartEntry(
                owner_ref=_evidence_ref(entry["owner_ref"], f"{where}.owner_ref"),
                component=_evidence_ref(entry["component"], f"{where}.component"),
                pid=_evidence_int(entry["pid"], f"{where}.pid", minimum=1),
                old_generation=_evidence_ref(
                    entry["old_generation"], f"{where}.old_generation"
                ),
                new_generation=_evidence_ref(
                    entry["new_generation"], f"{where}.new_generation"
                ),
                slot=_evidence_int(entry["slot"], f"{where}.slot"),
            )
        )
    seen_restarts = set()
    for entry in restarts:
        if entry.old_generation == entry.new_generation:
            raise _evidence_fail(
                "restarts: old_generation == new_generation rejected"
            )
        link = (
            entry.owner_ref,
            entry.component,
            entry.pid,
            entry.old_generation,
            entry.new_generation,
            entry.slot,
        )
        if link in seen_restarts:
            raise _evidence_fail(
                "restarts: duplicate restart entry rejected"
            )
        seen_restarts.add(link)
    cancellation_raw = data["cancellation"]
    if not isinstance(cancellation_raw, Mapping):
        raise _evidence_fail("cancellation: must be an object")
    _evidence_closed_keys(cancellation_raw, _CANCELLATION_KEYS, "cancellation")
    cancellation = Cancellation(
        cancelled=_evidence_bool(
            cancellation_raw["cancelled"], "cancellation.cancelled"
        ),
        detail=_evidence_detail(
            cancellation_raw["detail"], "cancellation.detail"
        ),
    )
    crashes_raw = data["crashes"]
    if not isinstance(crashes_raw, Sequence) or isinstance(crashes_raw, (str, bytes)):
        raise _evidence_fail("crashes: must be an array")
    if len(crashes_raw) > _MAX_CRASHES:
        raise _evidence_fail(f"crashes: exceeds {_MAX_CRASHES} entries")
    crashes: List[CrashEntry] = []
    for index, entry in enumerate(crashes_raw):
        where = f"crashes[{index}]"
        if not isinstance(entry, Mapping):
            raise _evidence_fail(f"{where}: must be an object")
        _evidence_closed_keys(entry, _CRASH_KEYS, where)
        crashes.append(
            CrashEntry(
                crash_ref=_evidence_ref(entry["crash_ref"], f"{where}.crash_ref"),
                detail=_evidence_detail(entry["detail"], f"{where}.detail"),
                slot=_evidence_int(entry["slot"], f"{where}.slot"),
            )
        )
    cleanup_raw = data["cleanup"]
    if not isinstance(cleanup_raw, Mapping):
        raise _evidence_fail("cleanup: must be an object")
    _evidence_closed_keys(cleanup_raw, _CLEANUP_KEYS, "cleanup")
    disposition = cleanup_raw["disposition"]
    if disposition not in _CLEANUP_DISPOSITIONS:
        raise _evidence_fail(f"cleanup: unknown disposition {disposition!r}")
    cleanup = CleanupEvidence(
        disposition=disposition,
        issuer_ref=_evidence_optional_ref(
            cleanup_raw["issuer_ref"], "cleanup.issuer_ref"
        ),
        detail=_evidence_detail(cleanup_raw["detail"], "cleanup.detail"),
    )
    return RunEvidence(
        schema=RUN_EVIDENCE_SCHEMA_ID,
        producer=producer,
        commitment=commitment,
        phases=tuple(phases),
        operations=tuple(operations),
        restarts=tuple(restarts),
        cancellation=cancellation,
        crashes=tuple(crashes),
        cleanup=cleanup,
    )


# ---------------------------------------------------------------------------
# Analysis result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AxisResult:
    name: str
    status: str  # satisfied | violated | unknown | not_evaluated
    reasons: Tuple[str, ...]  # sorted, deduplicated, bounded

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class AnalysisResult:
    """Complete analyzer output. Exactly one summary disposition plus every
    independent failed/unknown axis; all qualifying violations and uncertainty
    reasons are retained regardless of precedence."""

    schema: str
    algorithm_revision: str
    disposition: str
    axes: Tuple[AxisResult, ...]
    measurements: Dict[str, Any] = field(default_factory=dict)
    windows: Dict[str, Any] = field(default_factory=dict)
    violations: Tuple[Dict[str, Any], ...] = ()
    coverage: Dict[str, Any] = field(default_factory=dict)
    semantic_digest: str = ""
    transport_digest: str = ""
    records_accepted: int = 0
    records_rejected: int = 0
    work_units_consumed: int = 0
    limits_exceeded: bool = False
    plan_id: str = ""
    run_ref: str = ""
    profile_ref: str = ""
    profile_revision: int = 0

    def axis(self, name: str) -> Optional[AxisResult]:
        for axis in self.axes:
            if axis.name == name:
                return axis
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "algorithm_revision": self.algorithm_revision,
            "disposition": self.disposition,
            "axes": [a.to_dict() for a in self.axes],
            "measurements": self.measurements,
            "windows": self.windows,
            "violations": list(self.violations),
            "coverage": self.coverage,
            "semantic_digest": self.semantic_digest,
            "transport_digest": self.transport_digest,
            "records_accepted": self.records_accepted,
            "records_rejected": self.records_rejected,
            "work_units_consumed": self.work_units_consumed,
            "limits_exceeded": self.limits_exceeded,
            "plan_id": self.plan_id,
            "run_ref": self.run_ref,
            "profile_ref": self.profile_ref,
            "profile_revision": self.profile_revision,
        }


def encode_analysis_semantic(result: AnalysisResult) -> bytes:
    """Deterministic semantic encoding of a result for the versioned digest.

    The semantic digest covers domain content only: transport provenance
    (``transport_digest``) is excluded so that equivalent interleavings of
    independent valid streams yield identical semantic digests while raw
    arrival order stays visible as separate provenance.
    """
    body = result.to_dict()
    body.pop("transport_digest", None)
    body.pop("semantic_digest", None)
    return (
        json.dumps(body, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True).encode("utf-8")
        + b"\n"
    )


def _semantic_digest_of(result: AnalysisResult) -> str:
    digest = hashlib.sha256(encode_analysis_semantic(result)).hexdigest()
    return f"{ANALYSIS_SCHEMA_ID}:sha256:{digest}"


# ---------------------------------------------------------------------------
# Analysis engine internals
# ---------------------------------------------------------------------------


class _Budget:
    """Incremental work/byte accounting against profile limits."""

    def __init__(self, limits: AnalysisLimits) -> None:
        self._limits = limits
        self.work_units = 0
        self.total_bytes = 0
        self.windows = 0

    def spend_work(self, units: int, what: str) -> None:
        if units < 0:  # pragma: no cover - defensive
            raise _BudgetExceeded(f"negative work for {what}")
        self.work_units += units
        if self.work_units > self._limits.max_work_units:
            raise _BudgetExceeded(
                f"analysis work budget exceeded at {what}: "
                f"{self.work_units} > {self._limits.max_work_units}"
            )

    def spend_bytes(self, count: int, what: str) -> None:
        self.total_bytes += count
        if self.total_bytes > self._limits.max_total_bytes:
            raise _BudgetExceeded(
                f"analysis byte budget exceeded at {what}: "
                f"{self.total_bytes} > {self._limits.max_total_bytes}"
            )

    def spend_window(self, what: str) -> None:
        self.windows += 1
        if self.windows > self._limits.max_windows_total:
            raise _BudgetExceeded(
                f"analysis window budget exceeded at {what}: "
                f"{self.windows} > {self._limits.max_windows_total}"
            )


class _Reasons:
    """Unbounded collection during evaluation; bounded at axis build time."""

    def __init__(self) -> None:
        self._items: List[str] = []

    def add(self, reason: str) -> None:
        text = reason if len(reason) <= 256 else reason[:253] + "..."
        self._items.append(text)

    def extend(self, reasons: Sequence[str]) -> None:
        for reason in reasons:
            self.add(reason)

    def build(self, max_reasons: int) -> Tuple[str, ...]:
        ordered = sorted(set(self._items))
        if len(ordered) <= max_reasons:
            return tuple(ordered)
        kept = ordered[: max_reasons - 1] if max_reasons > 1 else []
        withheld = len(ordered) - len(kept)
        return tuple(kept + [f"{_REASON_TRUNCATION_MARK}:withheld={withheld}"])

    def __len__(self) -> int:
        return len(self._items)


def _stream_id_of(stream: Mapping[str, Any]) -> str:
    """Identity key of one stream: the full binding digest, never 4 fields."""
    return str(stream["binding_digest"])


def _stream_display(stream: Mapping[str, Any]) -> str:
    """Human display of a stream: four fields, never an identity key."""
    return "|".join(
        (
            str(stream["owner_ref"]),
            str(stream["component"]),
            str(stream["pid"]),
            str(stream["generation"]),
        )
    )


_TERMINAL_LIFECYCLE_CODES = frozenset(
    {
        _soak.LifecycleCode.PROCESS_EXIT,
        _soak.LifecycleCode.PROCESS_REPLACEMENT,
        _soak.LifecycleCode.UNKNOWN_OWNERSHIP,
        _soak.LifecycleCode.IDENTITY_UNAVAILABLE,
        _soak.LifecycleCode.LIFECYCLE_UPDATE_REJECTED,
    }
)


def _checked_int(value: Any, name: str) -> int:
    """Re-check one consumed integer against the finite domain."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise _soak.RecordRejected(f"{name}: must be an integer, never bool/float")
    if isinstance(value, float):  # pragma: no cover - guarded above
        raise _soak.RecordRejected(f"{name}: non-finite float rejected")
    if not 0 <= value <= FINITE_MAX:
        raise _soak.RecordRejected(
            f"{name}: outside finite domain [0, {FINITE_MAX}]"
        )
    return value


def _select_window(
    selector: str, stats: Sequence[Tuple[int, int]]
) -> Optional[Tuple[int, int]]:
    """Select (window_index, value) from non-empty window stats in order."""
    if not stats:
        return None
    if selector == "first_window":
        return stats[0]
    if selector == "last_window":
        return stats[-1]
    if selector == "min_window":
        return min(stats, key=lambda item: (item[1], item[0]))
    if selector == "max_window":
        best = max(stats, key=lambda item: (item[1], -item[0]))
        return best
    raise AssertionError(f"unknown window selector {selector!r}")  # pragma: no cover


_FALLBACK_LIMITS = AnalysisLimits(
    max_records=100000,
    max_streams=4096,
    max_windows_total=1000000,
    max_work_units=10000000,
    max_total_bytes=256 * 1024 * 1024,
    max_record_bytes=65536,
    max_reasons=64,
)


def _canonical_record_bytes(record: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(dict(record), sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True).encode("utf-8")
        + b"\n"
    )


def analyze_samples(
    records: Any,
    sampling_plan: Any,
    analysis_profile: Any,
    run_evidence: Any,
) -> AnalysisResult:
    """Analyze finite #942 sample records against a frozen profile and run evidence.

    Total function: every content problem becomes an explicit axis failure in
    the returned result. The only summary dispositions are the closed five,
    in presentation precedence WorkloadFailure > ResourceViolation >
    IncompleteEvidence > InconclusiveProfile >
    ObservedWithinQualifiedEnvelope; precedence never suppresses a retained
    violation or uncertainty reason.
    """
    input_r = _Reasons()
    profile_r = _Reasons()
    resource_r = _Reasons()
    resource_unknown = _Reasons()
    workload_r = _Reasons()
    cleanup_r = _Reasons()
    violations: List[Dict[str, Any]] = []

    plan = None
    try:
        plan = _soak.validate_sampling_plan(sampling_plan)
    except _soak.SamplingError as exc:
        input_r.add(f"plan_rejected:{exc}")
    except (TypeError, ValueError) as exc:
        input_r.add(f"plan_unusable:{exc}")

    profile = None
    try:
        profile = validate_analysis_profile(analysis_profile)
    except ProfileRejected as exc:
        input_r.add(f"profile_rejected:{exc}")
        profile_r.add(f"profile_rejected:{exc}")
    except (TypeError, ValueError) as exc:
        input_r.add(f"profile_unusable:{exc}")
        profile_r.add(f"profile_unusable:{exc}")

    evidence = None
    try:
        evidence = validate_run_evidence(run_evidence)
    except EvidenceRejected as exc:
        input_r.add(f"run_evidence_rejected:{exc}")
    except (TypeError, ValueError) as exc:
        input_r.add(f"run_evidence_unusable:{exc}")

    limits = profile.limits if profile is not None else _FALLBACK_LIMITS
    budget = _Budget(limits)
    limits_exceeded = False

    plan_digests: Dict[str, Any] = {}
    plan_four_field: Dict[str, str] = {}
    seen_four_field: Dict[str, str] = {}
    replacement_start: Dict[str, int] = {}
    replacement_note: Dict[str, str] = {}

    def _replacement_linkage(
        stream: Mapping[str, Any], slot: int
    ) -> Optional[str]:
        """Admit a replacement generation stream only with owner approval.

        A digest unknown to the plan is admitted only when run evidence links
        it to a restart entry (same owner/component/pid, new generation), the
        plan permits replace_generation, the record slot is at or after the
        restart slot, and the old generation is plan-bound or already
        observed. Anything else stays a foreign binding rejection.
        """
        if evidence is None or plan is None:
            return None
        if "replace_generation" not in plan.permitted_lifecycle_updates:
            return None
        owner = str(stream["owner_ref"])
        component = str(stream["component"])
        pid = int(stream["pid"])
        generation = str(stream["generation"])
        for restart in evidence.restarts:
            if (
                restart.owner_ref != owner
                or restart.component != component
                or restart.pid != pid
                or restart.new_generation != generation
                or slot < restart.slot
            ):
                continue
            old_key = "|".join(
                (owner, component, str(pid), restart.old_generation)
            )
            if old_key in plan_four_field or old_key in seen_four_field:
                return (
                    f"replace_generation {restart.old_generation}->"
                    f"{restart.new_generation} at slot {restart.slot}"
                )
        return None

    def _check_plan_binding(normalized: Mapping[str, Any]) -> None:
        """Enforce plan digest, binding membership, slot/phase/workload.

        Raises RecordRejected like the #942 owner validator so rejections
        stay counted input failures, never dropped rows.
        """
        if plan is None:
            return
        stream = normalized["stream"]
        digest = str(stream["binding_digest"])
        if str(normalized["plan_digest"]) != plan.plan_digest:
            raise _soak.RecordRejected(
                "record: canonical plan digest mismatch"
            )
        if digest in plan_digests:
            expected = plan_digests[digest]
            for field in ("owner_ref", "component", "pid", "generation"):
                if str(stream[field]) != str(getattr(expected, field)):
                    raise _soak.RecordRejected(
                        "record: stream identity differs from plan binding"
                    )
        else:
            linkage = _replacement_linkage(stream, int(normalized["slot"]))
            if linkage is None:
                raise _soak.RecordRejected(
                    "record: stream is not plan-bound and has no "
                    "owner-approved replacement linkage "
                    "(foreign binding rejected)"
                )
            replacement_note[digest] = linkage
            for restart in evidence.restarts:
                if (
                    restart.new_generation == str(stream["generation"])
                    and restart.owner_ref == str(stream["owner_ref"])
                    and restart.component == str(stream["component"])
                    and restart.pid == int(stream["pid"])
                ):
                    if digest not in replacement_start:
                        replacement_start[digest] = int(restart.slot)
                    else:
                        replacement_start[digest] = min(
                            replacement_start[digest], int(restart.slot)
                        )
        kind = normalized["kind"]
        slot = int(normalized["slot"])
        if kind == _soak.RecordKind.TERMINAL:
            if slot != plan.expected_slots:
                raise _soak.RecordRejected(
                    "record: terminal slot outside plan range"
                )
            probe = plan.expected_slots - 1
        else:
            if slot >= plan.expected_slots:
                raise _soak.RecordRejected("record: slot outside plan range")
            probe = slot
        phase = next(
            (
                candidate
                for candidate in plan.phases
                if candidate.first_slot <= probe <= candidate.last_slot
            ),
            None,
        )
        if (
            phase is None
            or str(normalized["phase_id"]) != phase.phase_id
            or str(normalized["workload_ref"]) != phase.workload_ref
        ):
            raise _soak.RecordRejected(
                "record: slot/phase/workload binding mismatch"
            )
    if plan is not None:
        for binding in plan.bindings:
            plan_digests[binding.binding_digest] = binding
            plan_four_field[binding.stream_key()] = binding.binding_digest

    # -- Step 1: three-way plan/profile/commitment bindings -------------------
    if plan is not None and profile is not None and evidence is not None:
        commitment = evidence.commitment
        if plan.profile_ref != profile.profile_ref:
            input_r.add(
                "integrity:plan.profile_ref != profile.profile_ref "
                "(post-run substitution rejected)"
            )
        if commitment.profile_ref != profile.profile_ref:
            input_r.add(
                "integrity:commitment.profile_ref != profile.profile_ref "
                "(post-run substitution rejected)"
            )
        if commitment.profile_revision != profile.revision:
            input_r.add(
                "integrity:commitment.profile_revision != profile.revision "
                "(post-run substitution rejected)"
            )
        if commitment.plan_digest != plan.plan_digest:
            input_r.add(
                "integrity:commitment.plan_digest != plan.plan_digest "
                "(post-run substitution rejected)"
            )
        if commitment.profile_digest != profile_content_digest(profile):
            input_r.add(
                "integrity:commitment.profile_digest != profile content digest "
                "(post-run substitution rejected)"
            )
        if commitment.plan_id != plan.plan_id:
            input_r.add("integrity:commitment.plan_id != plan.plan_id")
        if commitment.source_ref != plan.source_ref:
            input_r.add("integrity:commitment.source_ref != plan.source_ref")
        if commitment.artifact_ref != plan.artifact_ref:
            input_r.add("integrity:commitment.artifact_ref != plan.artifact_ref")
        if not commitment.committed_before_workload:
            input_r.add(
                "integrity:commitment not made before the workload "
                "(post-hoc commitment rejected)"
            )
        plan_phase_map = {
            p.phase_id: (p.first_slot, p.last_slot) for p in plan.phases
        }
        evidence_phase_map = {
            p.phase_id: (p.first_slot, p.last_slot) for p in evidence.phases
        }
        plan_phase_ids = [p.phase_id for p in plan.phases]
        if len(set(plan_phase_ids)) != len(plan_phase_ids):
            input_r.add(
                "integrity:plan phases carry duplicate phase_id "
                "(substitution rejected)"
            )
        for operation in evidence.operations:
            if operation.phase_id not in plan_phase_map:
                input_r.add(
                    f"integrity:operation {operation.op_ref} phase "
                    f"{operation.phase_id} not in plan (foreign-phase rejected)"
                )
        if evidence_phase_map != plan_phase_map:
            input_r.add(
                "integrity:run_evidence phases differ from plan phases "
                "(unapproved phase change rejected)"
            )
        # Profile applicability (unknown -> InconclusiveProfile, never a
        # violation of an invented limit).
        app = profile.applicability
        if app.sample_schema != _soak.SCHEMA_ID:
            profile_r.add(
                f"applicability:sample_schema {app.sample_schema!r} != "
                f"{_soak.SCHEMA_ID!r}"
            )
        if app.source_ref != plan.source_ref:
            profile_r.add("applicability:source_ref mismatch with plan")
        if app.workload_ref != plan.workload_ref:
            profile_r.add("applicability:workload_ref mismatch with plan")
        if profile.expected.cadence_ms != plan.cadence_ms:
            profile_r.add("applicability:cadence_ms mismatch with plan")
        if profile.expected.expected_slots != plan.expected_slots:
            profile_r.add("applicability:expected_slots mismatch with plan")
        profile_phase_ids = {pid for pid, _ in profile.phase_roles}
        for phase_id in plan_phase_map:
            if phase_id not in profile_phase_ids:
                input_r.add(
                    f"unbound:plan phase {phase_id!r} has no profile role"
                )
        for phase_id in sorted(profile_phase_ids):
            if phase_id not in plan_phase_map:
                profile_r.add(
                    f"applicability:profile role for unknown phase {phase_id!r}"
                )
        if profile.algorithm_revision != ALGORITHM_REVISION:
            profile_r.add(
                f"unsupported:algorithm_revision "
                f"{profile.qualification.status}:{profile.algorithm_revision!r}"
            )
            # W7: an unsupported algorithm leaves resources unevaluated.
            resource_unknown.add(
                f"not_evaluated:unsupported algorithm_revision "
                f"{profile.algorithm_revision!r}"
            )
    elif plan is not None and profile is not None:
        profile_r.add("qualification:run_evidence missing, binding unchecked")
    elif profile is not None and evidence is not None:
        profile_r.add("qualification:plan missing, applicability unchecked")

    # Qualification binding: only a qualified profile whose owner-issued
    # reference is named by the pre-run commitment can justify acceptance. A
    # caller self-assertion or self-computed digest never qualifies.
    if profile is not None and evidence is not None:
        qual = profile.qualification
        if qual.status != "qualified":
            profile_r.add(
                f"qualification:profile is {qual.status}, not qualified "
                "(measurements only)"
            )
        elif evidence.commitment.qualification_ref != qual.qualification_ref:
            profile_r.add(
                "qualification:commitment does not name the profile "
                "qualification_ref"
            )
    elif profile is not None and profile.qualification.status != "qualified":
        profile_r.add(
            f"qualification:profile is {profile.qualification.status}, "
            "not qualified (measurements only)"
        )

    # -- Steps 1-2: bounded incremental ingest, per-stream order -------------
    accepted: List[Dict[str, Any]] = []
    rejected_count = 0
    curtailed = False
    transport_hash = hashlib.sha256()
    # Order/conflict/terminal semantics come from the #942 owner validator
    # without its plan membership gate; membership stays analyzer-side in
    # _check_plan_binding so owner-approved replacement generations are
    # admittable instead of foreign-rejected.
    validator = _soak.StreamValidator(None)
    raw_provenance = 0
    synthesized_provenance = 0
    seen_streams: Dict[str, bool] = {}

    def _note_rejected(index: int, message: str) -> None:
        nonlocal rejected_count
        rejected_count += 1
        input_r.add(f"record[{index}]:{message}")

    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        input_r.add("records: must be a sequence of mappings/bytes")
        curtailed = True
    else:
        for index, raw in enumerate(records):
            try:
                budget.spend_work(1, f"record[{index}]")
                if index >= limits.max_records:
                    raise _BudgetExceeded(
                        f"record limit exceeded: {index + 1} > "
                        f"{limits.max_records}"
                    )
                if isinstance(raw, (bytes, bytearray)):
                    body = bytes(raw)
                    if len(body) > limits.max_record_bytes:
                        raise _soak.RecordRejected(
                            "record: transport body exceeds "
                            "profile limits.max_record_bytes"
                        )
                    budget.spend_bytes(len(body), f"record[{index}]")
                    normalized = _soak.decode_record(
                        body,
                        max_bytes=limits.max_record_bytes,
                        plan=None,
                    )
                    _check_plan_binding(normalized)
                    normalized = validator.observe(normalized)
                    wire = _soak.encode_transport(normalized)
                    # AUD6: transport provenance is the raw arrival bytes, never a
                    # re-encoding of the accepted subset (the encode above is
                    # superseded here for bytes inputs).
                    wire = body
                    raw_provenance += 1
                elif isinstance(raw, Mapping):
                    wire = _canonical_record_bytes(raw)
                    if len(wire) > limits.max_record_bytes:
                        raise _soak.RecordRejected(
                            "record: body exceeds profile limits.max_record_bytes"
                        )
                    budget.spend_bytes(len(wire), f"record[{index}]")
                    preview = _soak.validate_record(raw, plan=None)
                    _check_plan_binding(preview)
                    normalized = validator.observe(preview)
                    synthesized_provenance += 1
                    wire = _soak.encode_transport(normalized)
                else:
                    raise _soak.RecordRejected(
                        f"record: unsupported encoding "
                        f"{type(raw).__name__!r} (mapping/bytes only)"
                    )
                key = _stream_id_of(normalized["stream"])
                seen_four_field[_stream_display(normalized["stream"])] = key
                if key not in seen_streams:
                    seen_streams[key] = True
                    if len(seen_streams) > limits.max_streams:
                        raise _BudgetExceeded(
                            f"stream limit exceeded: {len(seen_streams)} > "
                            f"{limits.max_streams}"
                        )
                # Membership was enforced pre-observe in _check_plan_binding, so
                # only plan-bound or owner-approved replacement streams arrive.
                if (
                    plan is not None
                    and key not in plan_digests
                    and key not in replacement_note
                ):
                    raise _soak.RecordRejected(
                        f"record: stream {key} is not plan-bound "
                        "(foreign binding rejected)"
                    )
                _checked_int(normalized["seq"], "record.seq")
                _checked_int(normalized["slot"], "record.slot")
                _checked_int(normalized["elapsed_ms"], "record.elapsed_ms")
                if normalized["kind"] == _soak.RecordKind.SAMPLE:
                    for counter in normalized["counters"]:
                        if counter["status"] == _soak.CounterStatus.OK:
                            _checked_int(
                                counter["value"],
                                f"counter {counter['name']}",
                            )
                accepted.append(normalized)
                transport_hash.update(wire)
            except _BudgetExceeded as exc:
                limits_exceeded = True
                curtailed = True
                input_r.add(f"limit_exceeded:{exc}")
                break
            except _soak.SamplingError as exc:
                _note_rejected(index, str(exc))
            except (TypeError, ValueError) as exc:
                _note_rejected(index, f"unusable:{exc}")
    if rejected_count:
        input_r.add(f"records_rejected:count={rejected_count}")

    transport_digest = (
        f"{_soak.SCHEMA_ID}.transport:sha256:{transport_hash.hexdigest()}"
        f":accepted={len(accepted)}:rejected={rejected_count}"
    )

    # -- Step 2: separate series per process-generation/phase/counter --------
    # Per-stream arrival order was validated above; series are grouped, never
    # re-sorted, so a broken stream can never be sorted into validity.
    by_stream: Dict[str, List[Dict[str, Any]]] = {}
    for record in accepted:
        by_stream.setdefault(_stream_id_of(record["stream"]), []).append(record)

    required_names = [c.value for c in _soak.REQUIRED_COUNTERS]
    profile_counters: Tuple[str, ...] = tuple(required_names)
    if profile is not None:
        profile_counters = tuple(c.name for c in profile.counters)

    expected_slots = plan.expected_slots if plan is not None else 0
    phase_of_slot: Dict[int, str] = {}
    if plan is not None:
        for phase in plan.phases:
            for slot in range(phase.first_slot, phase.last_slot + 1):
                phase_of_slot[slot] = phase.phase_id

    # -- Step 3: measurements + coverage -------------------------------------
    measurements_streams: Dict[str, Any] = {}
    coverage_streams: Dict[str, Any] = {}
    sample_records: List[Dict[str, Any]] = [
        r for r in accepted if r["kind"] == _soak.RecordKind.SAMPLE
    ]

    # Restart linkage (AUD7): every restart entry must name a real old
    # generation and an observed successor; otherwise the lifecycle claim is
    # incomplete evidence, never a silent denominator change.
    observed_four_field: Dict[str, str] = {}
    for _digest, _recs in by_stream.items():
        observed_four_field[_stream_display(_recs[0]["stream"])] = _digest
    if evidence is not None:
        for restart in evidence.restarts:
            old_key = "|".join(
                (
                    restart.owner_ref,
                    restart.component,
                    str(restart.pid),
                    restart.old_generation,
                )
            )
            new_key = "|".join(
                (
                    restart.owner_ref,
                    restart.component,
                    str(restart.pid),
                    restart.new_generation,
                )
            )
            if old_key not in plan_four_field and old_key not in observed_four_field:
                input_r.add(
                    f"restart:old generation {old_key} neither plan-bound nor "
                    "observed (linkage rejected)"
                )
            if new_key not in observed_four_field:
                input_r.add(
                    f"restart:successor {new_key} unobserved "
                    "(replacement without evidence)"
                )
    stream_ids: List[str] = sorted(by_stream.keys())
    active_samples: List[Dict[str, Any]] = []
    active_spans: Dict[str, Tuple[int, int]] = {}
    if plan is not None:
        stream_ids = sorted(set(plan_digests) | set(by_stream.keys()))

    for stream_id in stream_ids:
        stream_records = by_stream.get(stream_id, [])
        samples = [r for r in stream_records if r["kind"] == _soak.RecordKind.SAMPLE]
        missed_records = [
            r for r in stream_records
            if r["kind"] == _soak.RecordKind.MISSED_SLOT
        ]
        terminals = [
            r for r in stream_records if r["kind"] == _soak.RecordKind.TERMINAL
        ]
        boundaries = [
            {
                "slot": int(r["slot"]),
                "kind": str(r["kind"]),
                "code": str(r["event"]["code"]),
            }
            for r in stream_records
            if r["kind"] in (
                _soak.RecordKind.LIFECYCLE, _soak.RecordKind.TERMINAL,
            )
        ]
        boundaries.sort(key=lambda b: (b["slot"], b["kind"], b["code"]))
        # Active interval (AUD4): a generation answers only for its admitted
        # span. Replacements open at the restart slot; every stream closes at
        # its first terminal-closure record (TERMINAL or a typed lifecycle
        # disposition from _TERMINAL_LIFECYCLE_CODES).
        active_start = replacement_start.get(stream_id, 0)
        closure_slot: Optional[int] = None
        closure_code: Optional[str] = None
        for boundary_record in stream_records:
            if boundary_record["kind"] == _soak.RecordKind.TERMINAL:
                closure_slot = (
                    plan.expected_slots - 1
                    if plan is not None
                    else int(boundary_record["slot"])
                )
                closure_code = str(boundary_record["event"]["code"])
                break
            if (
                boundary_record["kind"] == _soak.RecordKind.LIFECYCLE
                and boundary_record["event"]["code"]
                in _TERMINAL_LIFECYCLE_CODES
            ):
                # The closure slot carries the lifecycle record, never a
                # sample: the generation answers through the slot before.
                closure_slot = int(boundary_record["slot"]) - 1
                closure_code = str(boundary_record["event"]["code"])
                break
        if plan is not None:
            active_end = (
                closure_slot if closure_slot is not None else expected_slots - 1
            )
        else:
            observed_slots = [int(r["slot"]) for r in stream_records]
            active_end = max(observed_slots) if observed_slots else -1
        active_len = active_end - active_start + 1
        if plan is not None and active_len <= 0:
            input_r.add(
                f"coverage:{stream_id} empty active interval "
                f"[{active_start}, {active_end}] (linkage rejected)"
            )
            active_len = 0
        in_active = [
            r
            for r in samples
            if active_len > 0
            and active_start <= int(r["slot"]) <= active_end
        ]
        active_sample_slots = {int(r["slot"]) for r in in_active}
        if len(in_active) != len(samples):
            input_r.add(
                f"coverage:{stream_id} {len(samples) - len(in_active)} "
                "sample(s) outside the active interval "
                "(spliced generation rejected)"
            )
        active_samples.extend(in_active)
        active_spans[stream_id] = (active_start, active_end)

        present = len(active_sample_slots)
        known = 0
        unknown_slots = 0
        unknown_by_counter: Dict[str, Dict[str, int]] = {}
        per_counter_points: Dict[str, List[Tuple[int, int]]] = {
            name: [] for name in profile_counters
        }
        per_counter_unknown: Dict[str, int] = {
            name: 0 for name in profile_counters
        }
        for record in in_active:
            slot = int(record["slot"])
            all_ok = True
            seen_here = set()
            for counter in record["counters"]:
                name = str(counter["name"])
                seen_here.add(name)
                if name not in per_counter_points:
                    continue
                if counter["status"] == _soak.CounterStatus.OK:
                    per_counter_points[name].append((slot, int(counter["value"])))
                else:
                    all_ok = False
                    per_counter_unknown[name] += 1
                    reason = str(counter.get("reason", "unknown"))
                    bucket = unknown_by_counter.setdefault(name, {})
                    bucket[reason] = bucket.get(reason, 0) + 1
            for name in per_counter_points:
                if name not in seen_here:
                    all_ok = False
            if all_ok:
                known += 1
            else:
                unknown_slots += 1
        # The issue goal: missing counters never become a leak-free claim.
        # Unknown readings stay unknown on the resource axis (A8), so no
        # acceptance can silently rest on unread counters.
        for counter_name, unknown_count in per_counter_unknown.items():
            if unknown_count:
                resource_unknown.add(
                    f"unknown:{stream_id}:{counter_name} "
                    f"readings_unknown={unknown_count}"
                )
        missed = active_len - present if plan is not None else 0
        if missed < 0:
            missed = 0

        max_gap = 0
        if plan is not None:
            run = 0
            for slot in range(active_start, active_end + 1):
                if slot in active_sample_slots:
                    run = 0
                else:
                    run += 1
                    if run > max_gap:
                        max_gap = run

        terminal_code: Optional[str] = None
        if terminals:
            terminal_code = str(terminals[-1]["event"]["code"])

        if plan is not None and profile is not None and not curtailed:
            cov = profile.coverage
            # Exact rational comparison: present/active >= num/den.
            if present * cov.min_coverage_den < active_len * cov.min_coverage_num:
                input_r.add(
                    f"coverage:{stream_id} present {present}/active {active_len} "
                    "below "
                    f"{cov.min_coverage_num}/{cov.min_coverage_den}"
                )
            if max_gap > cov.max_gap_slots:
                input_r.add(
                    f"coverage:{stream_id} gap {max_gap} exceeds "
                    f"max_gap_slots {cov.max_gap_slots}"
                )
            if (
                cov.require_terminal
                and terminal_code is None
                and closure_code is None
            ):
                input_r.add(
                    f"coverage:{stream_id} missing terminal record (truncated)"
                )
            if not stream_records:
                input_r.add(f"coverage:{stream_id} no records (missing stream)")
        elif plan is None:
            input_r.add(f"coverage:{stream_id} plan missing, coverage unchecked")
        if curtailed and limits_exceeded:
            input_r.add(f"coverage:{stream_id} ingest curtailed by limits")

        elapsed_values = [int(r["elapsed_ms"]) for r in stream_records]
        counter_measurements: Dict[str, Any] = {}
        for name in profile_counters:
            points = per_counter_points.get(name, [])
            peak = None
            end = None
            if points:
                peak_slot, peak_value = max(
                    points, key=lambda p: (p[1], -p[0])
                )
                peak = {"slot": peak_slot, "sampled_peak": peak_value}
                end_slot, end_value = max(points, key=lambda p: (p[0], p[1]))
                end = {"slot": end_slot, "value": end_value}
            quiescent_point = None
            if profile is not None and points:
                quiescent_slots = [
                    (slot, value)
                    for slot, value in points
                    if profile.role_of(phase_of_slot.get(slot, "")) == "quiescent"
                ]
                if quiescent_slots:
                    q_slot, q_value = max(
                        quiescent_slots, key=lambda p: (p[0], p[1])
                    )
                    quiescent_point = {"slot": q_slot, "value": q_value}
            unit = str(_soak.COUNTER_UNITS.get(name, ""))
            counter_measurements[name] = {
                "unit": unit,
                "readings_ok": len(points),
                "readings_unknown": per_counter_unknown.get(name, 0),
                "sampled_peak": peak,
                "end": end,
                "quiescent": quiescent_point,
                "unknown_by_reason": unknown_by_counter.get(name, {}),
            }
        measurements_streams[stream_id] = {
            "elapsed_first_ms": min(elapsed_values) if elapsed_values else None,
            "elapsed_last_ms": max(elapsed_values) if elapsed_values else None,
            "elapsed_ms": (
                max(elapsed_values) - min(elapsed_values)
                if elapsed_values
                else None
            ),
            "records": len(stream_records),
            "samples": len(samples),
            "missed_slot_records": len(missed_records),
            "terminal": terminal_code,
            "boundaries": boundaries,
            "counters": counter_measurements,
        }
        coverage_streams[stream_id] = {
            "active_start_slot": active_start,
            "active_end_slot": active_end,
            "active_slots": active_len,
            "closure_code": closure_code,
            "replacement": replacement_note.get(stream_id),
            "expected_slots": expected_slots,
            "present_slots": present,
            "known_slots": known,
            "unknown_slots": unknown_slots,
            "missed_slots": missed,
            "missed_slot_records": len(missed_records),
            "max_gap_slots": max_gap,
            "terminal": terminal_code,
        }

    # Windows, bounds, and the working-set sum below consume only in-active
    # samples: out-of-interval rows are rejected evidence, never measurements.
    sample_records = list(active_samples)
    non_unique_ws: Dict[str, Any] = {
        "label": "non-unique-shared-pages",
        "total_working_set_bytes": 0,
        "contributing_readings": 0,
        "unknown_readings": 0,
        "not_system_rss": True,
        "not_private_rss": True,
    }
    if sample_records:
        try:
            budget.spend_work(len(sample_records), "working_set_sum")
            non_unique_ws = _soak.non_unique_working_set_sum(sample_records)
        except (_soak.SamplingError, _BudgetExceeded) as exc:
            resource_unknown.add(f"working_set_sum_unavailable:{exc}")

    operation_counts: Dict[str, Any] = {
        "total": 0,
        "required": 0,
        "by_observed": {},
        "by_expected": {},
    }
    if evidence is not None:
        by_observed: Dict[str, int] = {}
        by_expected: Dict[str, int] = {}
        required = 0
        for operation in evidence.operations:
            by_observed[operation.observed] = (
                by_observed.get(operation.observed, 0) + 1
            )
            by_expected[operation.expected] = (
                by_expected.get(operation.expected, 0) + 1
            )
            if operation.required:
                required += 1
        operation_counts = {
            "total": len(evidence.operations),
            "required": required,
            "by_observed": by_observed,
            "by_expected": by_expected,
        }

    measurements = {
        "streams": measurements_streams,
        "non_unique_working_set": non_unique_ws,
        "operations": operation_counts,
        "restarts": len(evidence.restarts) if evidence is not None else 0,
        "crashes": len(evidence.crashes) if evidence is not None else 0,
    }

    # -- Step 4: fixed half-open windows, frozen method ----------------------
    windows_out: Dict[str, Any] = {}
    # (stream, phase_id, counter) -> ordered non-empty window stats + all windows
    window_index: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    algorithm_supported = (
        profile is not None and profile.algorithm_revision == ALGORITHM_REVISION
    )
    rules_evaluated = False

    slot_present: set = set()
    slot_value: Dict[Tuple[str, int, str], int] = {}
    if plan is not None and profile is not None and algorithm_supported:
        for record in sample_records:
            key = _stream_id_of(record["stream"])
            slot = int(record["slot"])
            slot_present.add((key, slot))
            for counter in record["counters"]:
                name = str(counter["name"])
                if counter["status"] == _soak.CounterStatus.OK:
                    slot_value[(key, slot, name)] = int(counter["value"])
        try:
            if plan is not None and profile is not None and algorithm_supported:
                width = profile.window_slots
                for stream_id in stream_ids:
                    stream_windows: Dict[str, Any] = {}
                    for phase in plan.phases:
                        role = profile.role_of(phase.phase_id)
                        if role is None or role == "excluded":
                            continue
                        span = phase.last_slot - phase.first_slot + 1
                        count = (span + width - 1) // width
                        phase_windows: Dict[str, Any] = {}
                        for name in profile_counters:
                            budget.spend_work(1, f"windows:{stream_id}")
                            entries: List[Dict[str, Any]] = []
                            for window in range(count):
                                start = phase.first_slot + window * width
                                stop = min(start + width, phase.last_slot + 1)
                                # Windows outside the generation's active
                                # interval are not its evidence: a truncated
                                # generation leaves no empty-window verdicts.
                                live = active_spans.get(stream_id)
                                if live is not None and (
                                    start > live[1] or stop - 1 < live[0]
                                ):
                                    continue
                                budget.spend_window(
                                    f"{stream_id}:{phase.phase_id}:{name}"
                                )
                                budget.spend_work(1, f"window:{window}")
                                values: List[int] = []
                                unknown_count = 0
                                missed_count = 0
                                present_count = 0
                                for slot in range(start, stop):
                                    hit = slot_value.get((stream_id, slot, name))
                                    if hit is not None:
                                        values.append(hit)
                                        present_count += 1
                                    elif (stream_id, slot) in slot_present:
                                        unknown_count += 1
                                    else:
                                        missed_count += 1
                                total = stop - start
                                if values:
                                    total_sum = 0
                                    for value in values:
                                        total_sum += value
                                        if total_sum > FINITE_MAX * 1024:
                                            raise _BudgetExceeded(
                                                "window sum exceeds checked "
                                                "intermediate bound"
                                            )
                                    entry = {
                                        "index": window,
                                        "first_slot": start,
                                        "last_slot_exclusive": stop,
                                        "count": len(values),
                                        "sum": total_sum,
                                        "min": min(values),
                                        "max": max(values),
                                        "first": values[0],
                                        "last": values[-1],
                                        "unknown_count": unknown_count,
                                        "missed_count": missed_count,
                                        "present_slots": present_count,
                                        "total_slots": total,
                                        "empty": False,
                                    }
                                else:
                                    entry = {
                                        "index": window,
                                        "first_slot": start,
                                        "last_slot_exclusive": stop,
                                        "count": 0,
                                        "sum": 0,
                                        "min": None,
                                        "max": None,
                                        "first": None,
                                        "last": None,
                                        "unknown_count": unknown_count,
                                        "missed_count": missed_count,
                                        "present_slots": 0,
                                        "total_slots": total,
                                        "empty": True,
                                    }
                                    resource_unknown.add(
                                        f"window:{stream_id}:{phase.phase_id}:"
                                        f"{name}#{window} empty "
                                        "(no ok readings)"
                                    )
                                entries.append(entry)
                            phase_windows[name] = {
                                "role": role,
                                "window_slots": width,
                                "windows": entries,
                            }
                            window_index[(stream_id, phase.phase_id, name)] = {
                                "role": role,
                                "entries": entries,
                            }
                        stream_windows[phase.phase_id] = phase_windows
                    windows_out[stream_id] = stream_windows
        except _BudgetExceeded as exc:
            limits_exceeded = True
            curtailed = True
            input_r.add(f"limit_exceeded:{exc}")
    elif profile is not None and not algorithm_supported:
        # W7: skipped windows are unevaluated, never satisfied.
        resource_unknown.add(
            "not_evaluated:windows skipped for unsupported algorithm_revision"
        )

    def _entry_stat(statistic: str, entry: Dict[str, Any]) -> Optional[int]:
        if entry["empty"]:
            return None
        if statistic == "first":
            return int(entry["first"])
        if statistic == "last":
            return int(entry["last"])
        if statistic == "min":
            return int(entry["min"])
        if statistic == "max":
            return int(entry["max"])
        count = int(entry["count"])
        if count <= 0:  # pragma: no cover - empty guarded above
            return None
        return int(entry["sum"]) // count

    # -- Absolute bounds (every ok reading, every role but excluded) ---------
    if plan is not None and profile is not None and algorithm_supported:
        rules_evaluated = True
        role_cache = {p.phase_id: profile.role_of(p.phase_id) for p in plan.phases}
        for record in sample_records:
            stream_id = _stream_id_of(record["stream"])
            slot = int(record["slot"])
            try:
                budget.spend_work(1, f"bounds:{stream_id}:{slot}")
            except _BudgetExceeded as exc:
                limits_exceeded = True
                curtailed = True
                input_r.add(f"limit_exceeded:{exc}")
                break
            if role_cache.get(str(record["phase_id"])) == "excluded":
                continue
            for counter in record["counters"]:
                name = str(counter["name"])
                if counter["status"] != _soak.CounterStatus.OK:
                    continue
                bound = profile.bound_of(name)
                # W7: a counter without a bound is unevaluated, never satisfied.
                if bound is None:
                    resource_unknown.add(
                        f"not_evaluated:no absolute bound for {name}"
                    )
                    continue
                value = int(counter["value"])
                # Exact boundary passes; one over fails (case 14).
                if value > bound:
                    violations.append(
                        {
                            "rule": "absolute_bound",
                            "stream": stream_id,
                            "counter": name,
                            "slot": slot,
                            "value": value,
                            "bound": bound,
                        }
                    )
    elif profile is not None and algorithm_supported:
        resource_unknown.add("bounds:plan missing, bounds unchecked")

    # -- Growth rule (predeclared roles/counters/statistic only) -------------
    if (
        plan is not None
        and profile is not None
        and algorithm_supported
        and profile.growth.counters
        and profile.growth.applies_to_roles
    ):
        applicable_phases = [
            p for p in plan.phases
            if profile.role_of(p.phase_id) in profile.growth.applies_to_roles
        ]
        if not applicable_phases:
            profile_r.add(
                "applicability:no plan phase carries a growth role "
                f"{list(profile.growth.applies_to_roles)!r}"
            )
        for stream_id in stream_ids:
            for phase in applicable_phases:
                for name in profile.growth.counters:
                    node = window_index.get((stream_id, phase.phase_id, name))
                    if node is None:
                        continue
                    entries = node["entries"]
                    stat = profile.growth.statistic
                    run = 0
                    run_start = 0
                    deltas: List[int] = []
                    try:
                        for left, right in zip(entries, entries[1:]):
                            budget.spend_work(1, "growth:compare")
                            first_v = _entry_stat(stat, left)
                            second_v = _entry_stat(stat, right)
                            if first_v is None or second_v is None:
                                if run:
                                    run = 0
                                    deltas = []
                                resource_unknown.add(
                                    f"growth:{stream_id}:{phase.phase_id}:"
                                    f"{name} windows {left['index']}->"
                                    f"{right['index']} incomparable "
                                    "(empty window)"
                                )
                                continue
                            delta = second_v - first_v
                            if delta > profile.growth.allowed_delta:
                                if not run:
                                    run_start = int(left["index"])
                                    deltas = []
                                run += 1
                                deltas.append(delta)
                                if run >= profile.growth.consecutive_windows:
                                    violations.append(
                                        {
                                            "rule": "growth",
                                            "stream": stream_id,
                                            "phase": phase.phase_id,
                                            "counter": name,
                                            "statistic": stat,
                                            "run_start_window": run_start,
                                            "run_length": run,
                                            "allowed_delta": (
                                                profile.growth.allowed_delta
                                            ),
                                            "deltas": list(deltas),
                                        }
                                    )
                                    run = 0
                                    deltas = []
                            else:
                                run = 0
                                deltas = []
                    except _BudgetExceeded as exc:
                        limits_exceeded = True
                        curtailed = True
                        input_r.add(f"limit_exceeded:{exc}")
                        break
    elif profile is not None and algorithm_supported:
        # W7: an unevaluated rule is unknown evidence, never satisfaction.
        resource_unknown.add("not_evaluated:growth rule has no counters/roles")

    # -- Quiescent recovery (declared baseline window + tolerance) -----------
    if (
        plan is not None
        and profile is not None
        and algorithm_supported
        and profile.recovery.counters
    ):
        rec = profile.recovery
        baseline_phases = [
            p for p in plan.phases if profile.role_of(p.phase_id) == rec.baseline_role
        ]
        quiescent_phases = [
            p for p in plan.phases
            if profile.role_of(p.phase_id) == rec.quiescent_role
        ]
        if not baseline_phases or not quiescent_phases:
            profile_r.add(
                "applicability:recovery needs baseline "
                f"{rec.baseline_role!r} and quiescent phases in plan"
            )
        for stream_id in stream_ids:
            for name in rec.counters:
                # A generation that never lived through both the baseline
                # and the quiescent span cannot falsify recovery: no verdict,
                # no unknown — its successor is judged on its own interval.
                span = active_spans.get(stream_id)
                if span is not None and (
                    not any(
                        p.first_slot <= span[1] and span[0] <= p.last_slot
                        for p in baseline_phases
                    )
                    or not any(
                        p.first_slot <= span[1] and span[0] <= p.last_slot
                        for p in quiescent_phases
                    )
                ):
                    continue
                baseline_stats: List[Tuple[int, int]] = []
                for phase in baseline_phases:
                    node = window_index.get((stream_id, phase.phase_id, name))
                    if node is None:
                        continue
                    for entry in node["entries"]:
                        value = _entry_stat(rec.statistic, entry)
                        if value is not None:
                            baseline_stats.append(
                                (int(entry["index"]), value)
                            )
                quiescent_stats: List[Tuple[int, int]] = []
                for phase in quiescent_phases:
                    node = window_index.get((stream_id, phase.phase_id, name))
                    if node is None:
                        continue
                    for entry in node["entries"]:
                        value = _entry_stat(rec.statistic, entry)
                        if value is not None:
                            quiescent_stats.append(
                                (int(entry["index"]), value)
                            )
                try:
                    budget.spend_work(1, "recovery:compare")
                except _BudgetExceeded as exc:
                    limits_exceeded = True
                    curtailed = True
                    input_r.add(f"limit_exceeded:{exc}")
                    break
                baseline = _select_window(rec.baseline_selector, baseline_stats)
                observed = _select_window(
                    rec.quiescent_selector, quiescent_stats
                )
                if baseline is None or observed is None:
                    resource_unknown.add(
                        f"recovery:{stream_id}:{name} baseline or quiescent "
                        "window unavailable (empty)"
                    )
                    continue
                _, baseline_value = baseline
                _, observed_value = observed
                # Exact comparison against tolerance; a restart, trim, flat
                # slope, or stable endpoints never clears this rule.
                if observed_value > baseline_value + rec.tolerance:
                    violations.append(
                        {
                            "rule": "recovery",
                            "stream": stream_id,
                            "counter": name,
                            "statistic": rec.statistic,
                            "baseline": baseline_value,
                            "observed": observed_value,
                            "tolerance": rec.tolerance,
                        }
                    )
    elif profile is not None and algorithm_supported:
        # W7: an unevaluated rule is unknown evidence, never satisfaction.
        resource_unknown.add("not_evaluated:recovery rule has no counters")

    # -- Step 6: workload semantics ------------------------------------------
    workload_violated = False
    workload_unknown = False
    if evidence is None:
        workload_unknown = True
        workload_r.add("workload:run_evidence missing")
    else:
        producer_ok = bool(evidence.producer.producer_ref)
        if not evidence.operations:
            # AUD3: with no declared operations there is no required-work
            # denominator; an empty list never proves required work complete.
            workload_unknown = True
            workload_r.add(
                "workload:no operations declared "
                "(required-work denominator missing)"
            )
        committed = evidence.commitment.committed_before_workload
        for operation in evidence.operations:
            if not operation.required:
                continue
            if operation.observed in ("failed", "crashed"):
                if operation.producer_attested and producer_ok and committed:
                    workload_violated = True
                    workload_r.add(
                        f"workload:required {operation.op_ref} "
                        f"observed {operation.observed} (authenticated)"
                    )
                else:
                    workload_unknown = True
                    workload_r.add(
                        f"workload:required {operation.op_ref} "
                        f"observed {operation.observed} (unattested)"
                    )
            elif operation.observed in ("cancelled", "unknown"):
                workload_unknown = True
                workload_r.add(
                    f"workload:required {operation.op_ref} "
                    f"observed {operation.observed} (incomplete)"
                )
            elif operation.observed != operation.expected:
                workload_unknown = True
                workload_r.add(
                    f"workload:required {operation.op_ref} observed "
                    f"{operation.observed} != expected {operation.expected}"
                )
        for crash in evidence.crashes:
            if producer_ok and committed:
                workload_violated = True
                workload_r.add(
                    f"workload:crash {crash.crash_ref} (authenticated)"
                )
            else:
                workload_unknown = True
                workload_r.add(
                    f"workload:crash {crash.crash_ref} (unattested)"
                )
        if evidence.cancellation.cancelled and not workload_violated:
            workload_unknown = True
            workload_r.add("workload:run cancelled (required work incomplete)")

    # -- Step 6: cleanup ------------------------------------------------------
    cleanup_violated = False
    cleanup_unknown = False
    if evidence is None:
        cleanup_unknown = True
        cleanup_r.add("cleanup:run_evidence missing")
    else:
        cleanup = evidence.cleanup
        producer_ok = bool(evidence.producer.producer_ref)
        issuer_ok = bool(cleanup.issuer_ref)
        if cleanup.disposition == "verified_clean":
            if issuer_ok and producer_ok:
                pass
            else:
                cleanup_unknown = True
                cleanup_r.add(
                    "cleanup:verified_clean without owner issuer/producer"
                )
        elif cleanup.disposition == "failed":
            if issuer_ok and producer_ok:
                cleanup_violated = True
                cleanup_r.add("cleanup:confirmed failed cleanup (owner-issued)")
            else:
                cleanup_unknown = True
                cleanup_r.add("cleanup:failed claim without owner issuer")
        else:
            cleanup_unknown = True
            cleanup_r.add(f"cleanup:disposition {cleanup.disposition} (unknown)")

    # -- Axes, disposition (presentation precedence only), digest -------------
    if curtailed and limits_exceeded:
        resource_unknown.add("evaluation curtailed by analysis limits")

    max_reasons = limits.max_reasons
    if len(input_r):
        input_status = AxisStatus.VIOLATED.value
    else:
        input_status = AxisStatus.SATISFIED.value
    if len(profile_r):
        profile_status = AxisStatus.UNKNOWN.value
    else:
        profile_status = AxisStatus.SATISFIED.value
    if violations:
        resource_status = AxisStatus.VIOLATED.value
    elif len(resource_unknown):
        resource_status = AxisStatus.UNKNOWN.value
    elif not rules_evaluated or not algorithm_supported:
        resource_status = AxisStatus.NOT_EVALUATED.value
    else:
        resource_status = AxisStatus.SATISFIED.value
    if workload_violated:
        workload_status = AxisStatus.VIOLATED.value
    elif workload_unknown:
        workload_status = AxisStatus.UNKNOWN.value
    else:
        workload_status = AxisStatus.SATISFIED.value
    if cleanup_violated:
        cleanup_status = AxisStatus.VIOLATED.value
    elif cleanup_unknown:
        cleanup_status = AxisStatus.UNKNOWN.value
    else:
        cleanup_status = AxisStatus.SATISFIED.value

    resource_all = _Reasons()
    resource_all.extend(list(resource_r.build(10**9)))
    resource_all.extend(list(resource_unknown.build(10**9)))

    axes = (
        AxisResult(
            name=AxisName.INPUT_INTEGRITY_COVERAGE.value,
            status=input_status,
            reasons=input_r.build(max_reasons),
        ),
        AxisResult(
            name=AxisName.PROFILE_QUALIFICATION.value,
            status=profile_status,
            reasons=profile_r.build(max_reasons),
        ),
        AxisResult(
            name=AxisName.RESOURCE.value,
            status=resource_status,
            reasons=resource_all.build(max_reasons),
        ),
        AxisResult(
            name=AxisName.WORKLOAD.value,
            status=workload_status,
            reasons=workload_r.build(max_reasons),
        ),
        AxisResult(
            name=AxisName.CLEANUP.value,
            status=cleanup_status,
            reasons=cleanup_r.build(max_reasons),
        ),
    )

    if workload_status == AxisStatus.VIOLATED.value or (
        cleanup_status == AxisStatus.VIOLATED.value
    ):
        disposition = Disposition.WORKLOAD_FAILURE.value
    elif resource_status == AxisStatus.VIOLATED.value:
        disposition = Disposition.RESOURCE_VIOLATION.value
    elif (
        input_status != AxisStatus.SATISFIED.value
        or workload_status == AxisStatus.UNKNOWN.value
        or cleanup_status == AxisStatus.UNKNOWN.value
        or resource_status == AxisStatus.UNKNOWN.value
    ):
        disposition = Disposition.INCOMPLETE_EVIDENCE.value
    elif (
        profile_status != AxisStatus.SATISFIED.value
        or resource_status == AxisStatus.NOT_EVALUATED.value
    ):
        disposition = Disposition.INCONCLUSIVE_PROFILE.value
    else:
        disposition = Disposition.OBSERVED_WITHIN_QUALIFIED_ENVELOPE.value

    ordered_violations = tuple(
        sorted(violations, key=lambda v: json.dumps(v, sort_keys=True))
    )
    coverage = {
        "streams": coverage_streams,
        "expected_slots": expected_slots,
        "streams_expected": len(stream_ids),
        "streams_observed": len(by_stream),
        # AUD6: raw arrival bytes vs caller-synthesized mappings behind the
        # transport digest (valid-prefix sink receipts stay #944-owned).
        "provenance": {
            "raw_bytes_records": raw_provenance,
            "synthesized_records": synthesized_provenance,
        },
    }
    result = AnalysisResult(
        schema=ANALYSIS_SCHEMA_ID,
        algorithm_revision=(
            profile.algorithm_revision if profile is not None
            else ALGORITHM_REVISION
        ),
        disposition=disposition,
        axes=axes,
        measurements=measurements,
        windows=windows_out,
        violations=ordered_violations,
        coverage=coverage,
        semantic_digest="",
        transport_digest=transport_digest,
        records_accepted=len(accepted),
        records_rejected=rejected_count,
        work_units_consumed=budget.work_units,
        limits_exceeded=limits_exceeded,
        plan_id=plan.plan_id if plan is not None else "",
        run_ref=plan.run_ref if plan is not None else "",
        profile_ref=profile.profile_ref if profile is not None else "",
        profile_revision=profile.revision if profile is not None else 0,
    )
    digest = _semantic_digest_of(result)
    return AnalysisResult(
        schema=result.schema,
        algorithm_revision=result.algorithm_revision,
        disposition=result.disposition,
        axes=result.axes,
        measurements=result.measurements,
        windows=result.windows,
        violations=result.violations,
        coverage=result.coverage,
        semantic_digest=digest,
        transport_digest=result.transport_digest,
        records_accepted=result.records_accepted,
        records_rejected=result.records_rejected,
        work_units_consumed=result.work_units_consumed,
        limits_exceeded=result.limits_exceeded,
        plan_id=result.plan_id,
        run_ref=result.run_ref,
        profile_ref=result.profile_ref,
        profile_revision=result.profile_revision,
    )
