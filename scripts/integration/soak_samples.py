"""Identity-bound Windows resource sampler (issue #942, D-SOAK-COLLECT).

Read-only collector used by #943 (analysis) and #944 (run): it measures a
finite, explicitly owned process set and streams versioned sample records.
It never launches or stops product processes and never decides whether
growth is acceptable. Unknown counters and missing samples stay explicit.

Integration seam (see issue body): ``Invoke-RuntimeStart`` returns PID /
nonce / containment but no handle-bound creation-time/image identity. This
module therefore never invents identity fields and never accepts the first
process found at a PID as the owned process. Process identity
(creation identity, approved image identity, owner-issued generation) must
arrive through the injected owner handoff supplied by #944. When the handoff
is unavailable the sampler emits an identity-unavailable lifecycle record
naming the #907/#911 handoff and produces no samples for that target.

Public contract (new local APIs owned by this module; #943 imports the
validators/types, #944 supplies owner/clock/sink adapters)::

    validate_sampling_plan(...)
    validate_sample_record(...)
    collect_samples(plan, process_source, clock, sink, cancellation)

Windows HANDLE integers are process-local: the live adapter consumes a valid
same-process/duplicated handle supplied in-process by the owner adapter, or
reopens the PID with minimum query rights, and always compares readback
against the already trusted owner identity. A numeric HANDLE is never
deserialized from the plan or the wire as a capability.

Only the standard library is used. Windows DLLs load solely inside the live
Windows query path, so validation/fixture imports stay usable elsewhere.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from enum import Enum
from functools import cached_property
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "SCHEMA_FAMILY",
    "SCHEMA_VERSION",
    "SCHEMA_ID",
    "CounterName",
    "CounterUnit",
    "CounterStatus",
    "RecordKind",
    "LifecycleCode",
    "Completeness",
    "HandleCleanupStatus",
    "HardDeadlineStatus",
    "Reason",
    "REASON_DISPOSITION",
    "SamplingError",
    "PlanRejected",
    "RecordRejected",
    "StreamRejected",
    "IdentityUnavailable",
    "IdentityMismatch",
    "AdapterUnavailable",
    "SinkError",
    "CounterReading",
    "ProcessBinding",
    "AdmittedProcessBinding",
    "PhaseBinding",
    "CollectionLimits",
    "SamplingPlan",
    "QueryContext",
    "QueryOutcome",
    "SampleCounters",
    "ProcessExit",
    "ProcessReplacement",
    "QueryFailure",
    "UnknownOwnership",
    "PreparedTarget",
    "ProcessSource",
    "SampleClock",
    "RecordSink",
    "StreamValidator",
    "SamplerFootprint",
    "StreamSummary",
    "SamplingResult",
    "REQUIRED_COUNTERS",
    "OPTIONAL_COUNTERS",
    "COUNTER_UNITS",
    "CLOSED_REASONS",
    "HANDOFF_IDENTITY_UNAVAILABLE",
    "validate_sampling_plan",
    "validate_sample_record",
    "validate_record",
    "decode_record",
    "encode_semantic",
    "encode_transport",
    "encode_result",
    "non_unique_working_set_sum",
    "collect_samples",
    "WindowsQueryAdapter",
    "create_windows_source",
]


SCHEMA_FAMILY = "eliot.soak_samples"
SCHEMA_VERSION = 2
SCHEMA_ID = "eliot.soak_samples/v2"

HANDOFF_IDENTITY_UNAVAILABLE = (
    "process identity unavailable: #944 must supply the validated "
    "owner observation/retained-handle handoff via the #907/#911 seam; "
    "PID alone never identifies the owned process"
)

_RECEIPT_MINT_TOKEN = object()


def _canonical_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class CounterName(str, Enum):
    WORKING_SET_BYTES = "working_set_bytes"
    PRIVATE_COMMIT_BYTES = "private_commit_bytes"
    HANDLE_COUNT = "handle_count"
    CPU_TIME_MS = "cpu_time_ms"
    THREAD_COUNT = "thread_count"


class CounterUnit(str, Enum):
    BYTES = "bytes"
    COUNT = "count"
    MILLISECONDS = "milliseconds"


class CounterStatus(str, Enum):
    OK = "ok"
    UNKNOWN = "unknown"


class RecordKind(str, Enum):
    SAMPLE = "sample"
    MISSED_SLOT = "missed_slot"
    LIFECYCLE = "lifecycle"
    TERMINAL = "terminal"


class LifecycleCode(str, Enum):
    SLOT_MISSED = "slot_missed"
    PROCESS_EXIT = "process_exit"
    PROCESS_REPLACEMENT = "process_replacement"
    QUERY_FAILURE = "query_failure"
    CANCELLATION = "cancellation"
    OUTPUT_TRUNCATION = "output_truncation"
    UNKNOWN_OWNERSHIP = "unknown_ownership"
    IDENTITY_UNAVAILABLE = "identity_unavailable"
    LIFECYCLE_UPDATE_REJECTED = "lifecycle_update_rejected"
    RUN_COMPLETE = "run_complete"


class Completeness(str, Enum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"


class HandleCleanupStatus(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    NONE_OWNED = "none_owned"


class HardDeadlineStatus(str, Enum):
    NOT_REQUESTED = "not_requested"
    ENFORCED = "enforced"
    UNSUPPORTED = "unsupported"


class Reason(str, Enum):
    """Closed reason registry for unknown counters and lifecycle events.

    Each reason maps to a stable I7.20 disposition; bridges switch on the
    disposition and preserve the exact reason verbatim.
    """

    IDENTITY_UNAVAILABLE = "identity_unavailable"
    FOREIGN_BINDING = "foreign_binding"
    CREATION_MISMATCH = "creation_mismatch"
    IMAGE_MISMATCH = "image_mismatch"
    GENERATION_UNKNOWN = "generation_unknown"
    ACCESS_DENIED = "access_denied"
    QUERY_FAILED = "query_failed"
    PROCESS_EXITED = "process_exited"
    PROCESS_REPLACED = "process_replaced"
    SLOT_MISSED = "slot_missed"
    CANCELLED = "cancelled"
    SINK_TRUNCATED = "sink_truncated"
    SINK_FAILED = "sink_failed"
    LIMIT_EXCEEDED = "limit_exceeded"
    HARD_DEADLINE_UNSUPPORTED = "hard_deadline_unsupported"
    LIFECYCLE_NOT_PERMITTED = "lifecycle_not_permitted"
    BUDGET_EXHAUSTED = "budget_exhausted"
    UNKNOWN_OWNERSHIP = "unknown_ownership"
    ADAPTER_UNAVAILABLE = "adapter_unavailable"


REASON_DISPOSITION: Dict[str, str] = {
    Reason.IDENTITY_UNAVAILABLE: "NEEDS_EVIDENCE",
    Reason.FOREIGN_BINDING: "DENIED",
    Reason.CREATION_MISMATCH: "STALE_OR_CONFLICT",
    Reason.IMAGE_MISMATCH: "STALE_OR_CONFLICT",
    Reason.GENERATION_UNKNOWN: "NEEDS_EVIDENCE",
    Reason.ACCESS_DENIED: "DENIED",
    Reason.QUERY_FAILED: "FAILED",
    Reason.PROCESS_EXITED: "STALE_OR_CONFLICT",
    Reason.PROCESS_REPLACED: "STALE_OR_CONFLICT",
    Reason.SLOT_MISSED: "NEEDS_EVIDENCE",
    Reason.CANCELLED: "FAILED",
    Reason.SINK_TRUNCATED: "FAILED",
    Reason.SINK_FAILED: "FAILED",
    Reason.LIMIT_EXCEEDED: "UNAVAILABLE_OR_CAPACITY",
    Reason.HARD_DEADLINE_UNSUPPORTED: "UNAVAILABLE_OR_CAPACITY",
    Reason.LIFECYCLE_NOT_PERMITTED: "DENIED",
    Reason.BUDGET_EXHAUSTED: "UNAVAILABLE_OR_CAPACITY",
    Reason.UNKNOWN_OWNERSHIP: "NEEDS_EVIDENCE",
    Reason.ADAPTER_UNAVAILABLE: "UNAVAILABLE_OR_CAPACITY",
}

CLOSED_REASONS = frozenset(r.value for r in Reason)

REQUIRED_COUNTERS = (
    CounterName.WORKING_SET_BYTES,
    CounterName.PRIVATE_COMMIT_BYTES,
    CounterName.HANDLE_COUNT,
)
OPTIONAL_COUNTERS = (CounterName.CPU_TIME_MS, CounterName.THREAD_COUNT)
COUNTER_UNITS: Dict[str, str] = {
    CounterName.WORKING_SET_BYTES: CounterUnit.BYTES,
    CounterName.PRIVATE_COMMIT_BYTES: CounterUnit.BYTES,
    CounterName.HANDLE_COUNT: CounterUnit.COUNT,
    CounterName.CPU_TIME_MS: CounterUnit.MILLISECONDS,
    CounterName.THREAD_COUNT: CounterUnit.COUNT,
}

_PERMITTED_LIFECYCLE_UPDATES = frozenset({"add_child", "replace_generation"})

_MAX_REF_LEN = 256
_MAX_IMAGE_ID_LEN = 1024
_MAX_REASON_DETAIL_LEN = 512
_MAX_JSON_DEPTH = 12
_MAX_JSON_KEYS = 512
_MAX_API_ERROR = 0xFFFFFFFF
_MAX_DWORD = 0xFFFFFFFF
_MAX_PROCESS_COUNT = 4096


class SamplingError(Exception):
    """Base error for sampler contract violations."""


class PlanRejected(SamplingError):
    """A sampling plan failed closed validation."""


class RecordRejected(SamplingError):
    """A single record failed closed validation."""


class StreamRejected(SamplingError):
    """A record stream failed sequence/conflict validation."""


class IdentityUnavailable(SamplingError):
    """No validated owner handoff exists for the target.

    Carries the handoff reference (#907/#911 seam) so callers name the
    missing integration instead of guessing identity from a PID.
    """

    def __init__(self, handoff: str = HANDOFF_IDENTITY_UNAVAILABLE) -> None:
        super().__init__(handoff)
        self.handoff = handoff


class IdentityMismatch(SamplingError):
    """Live readback disagreed with the trusted owner identity."""

    def __init__(self, reason: str = Reason.UNKNOWN_OWNERSHIP) -> None:
        self.reason = reason if reason in CLOSED_REASONS else Reason.UNKNOWN_OWNERSHIP
        super().__init__(self.reason)


class AdapterUnavailable(SamplingError):
    """The selected query adapter cannot run on this platform/path."""


class SinkError(SamplingError):
    """The record sink rejected or truncated a write."""

    def __init__(self, message: str, *, partial: bool = False) -> None:
        super().__init__(message)
        self.partial = partial


@dataclass(frozen=True)
class CounterReading:
    name: str
    value: Optional[int]
    unit: str
    status: str
    reason: Optional[str] = None
    api_error: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "name": self.name,
            "value": self.value,
            "unit": self.unit,
            "status": self.status,
        }
        if self.reason is not None:
            out["reason"] = self.reason
        if self.api_error is not None:
            out["api_error"] = self.api_error
        return out


@dataclass(frozen=True)
class ProcessBinding:
    """One owned process: owner-issued identity, never PID-discovered."""

    owner_ref: str
    component: str
    pid: int
    creation_identity: str
    image_identity: str
    generation: str

    def stream_key(self) -> str:
        """Return the four-field grouping key consumed by #943."""
        return "|".join(
            (self.owner_ref, self.component, str(self.pid), self.generation)
        )

    @cached_property
    def binding_digest(self) -> str:
        """Collision-resistant digest of the complete six-field identity."""
        return _canonical_digest(self.to_dict())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "owner_ref": self.owner_ref,
            "component": self.component,
            "pid": self.pid,
            "creation_identity": self.creation_identity,
            "image_identity": self.image_identity,
            "generation": self.generation,
        }


@dataclass(frozen=True, init=False)
class AdmittedProcessBinding:
    """In-process, source-issued authority to prepare one expected binding.

    The value is deliberately not deserializable. Its issuer identity is
    checked by the source before preparation or handle attachment; the digest
    alone is evidence of identity equality, never authority.
    """

    binding: ProcessBinding
    binding_digest: str
    _issuer: object = field(repr=False, compare=False)

    def __init__(
        self,
        binding: ProcessBinding,
        issuer: object,
        token: object,
    ) -> None:
        if token is not _RECEIPT_MINT_TOKEN:
            raise TypeError("admitted process bindings are owner-issued only")
        if not isinstance(binding, ProcessBinding):
            raise TypeError("admitted process binding requires ProcessBinding")
        object.__setattr__(self, "binding", binding)
        object.__setattr__(self, "binding_digest", binding.binding_digest)
        object.__setattr__(self, "_issuer", issuer)


@dataclass(frozen=True)
class PhaseBinding:
    phase_id: str
    workload_ref: str
    first_slot: int
    last_slot: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase_id": self.phase_id,
            "workload_ref": self.workload_ref,
            "first_slot": self.first_slot,
            "last_slot": self.last_slot,
        }


@dataclass(frozen=True)
class CollectionLimits:
    max_processes: int = 64
    max_samples_total: int = 100000
    max_total_bytes: int = 256 * 1024 * 1024
    max_record_bytes: int = 65536
    max_elapsed_ms: int = 4 * 3600 * 1000
    slot_lateness_ms: int = 5000
    terminal_reserve_records: int = 8
    max_lifecycle_updates: int = 16

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_processes": self.max_processes,
            "max_samples_total": self.max_samples_total,
            "max_total_bytes": self.max_total_bytes,
            "max_record_bytes": self.max_record_bytes,
            "max_elapsed_ms": self.max_elapsed_ms,
            "slot_lateness_ms": self.slot_lateness_ms,
            "terminal_reserve_records": self.terminal_reserve_records,
            "max_lifecycle_updates": self.max_lifecycle_updates,
        }


@dataclass(frozen=True)
class SamplingPlan:
    schema: str
    plan_id: str
    run_ref: str
    source_ref: str
    artifact_ref: str
    workload_ref: str
    profile_ref: str
    phases: Tuple[PhaseBinding, ...]
    cadence_ms: int
    expected_slots: int
    bindings: Tuple[ProcessBinding, ...]
    permitted_lifecycle_updates: Tuple[str, ...]
    optional_counters: Tuple[str, ...]
    limits: CollectionLimits
    hard_deadline_required: bool = False

    @cached_property
    def plan_digest(self) -> str:
        """Canonical digest of the complete normalized plan content."""
        return _canonical_digest(self.to_dict())

    @cached_property
    def _binding_index(self) -> Dict[str, ProcessBinding]:
        return {binding.binding_digest: binding for binding in self.bindings}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "run_ref": self.run_ref,
            "source_ref": self.source_ref,
            "artifact_ref": self.artifact_ref,
            "workload_ref": self.workload_ref,
            "profile_ref": self.profile_ref,
            "phases": [p.to_dict() for p in self.phases],
            "cadence_ms": self.cadence_ms,
            "expected_slots": self.expected_slots,
            "bindings": [b.to_dict() for b in self.bindings],
            "permitted_lifecycle_updates": list(self.permitted_lifecycle_updates),
            "optional_counters": list(self.optional_counters),
            "limits": self.limits.to_dict(),
            "hard_deadline_required": self.hard_deadline_required,
        }


def _require_keys(
    data: Mapping[str, Any], allowed: Sequence[str], what: str
) -> None:
    extra = [k for k in data.keys() if k not in allowed]
    if extra:
        raise PlanRejected(f"{what}: extra fields rejected: {sorted(extra)!r}")
    missing = [k for k in allowed if k not in data]
    if missing:
        raise PlanRejected(f"{what}: missing fields: {sorted(missing)!r}")


def _require_ref(value: Any, name: str, *, max_len: int = _MAX_REF_LEN) -> str:
    if not isinstance(value, str) or not value:
        raise PlanRejected(f"{name}: must be a non-empty string")
    if len(value) > max_len:
        raise PlanRejected(f"{name}: exceeds {max_len} chars")
    if any(ch < " " for ch in value):
        raise PlanRejected(f"{name}: control characters rejected")
    return value


def _require_int(
    value: Any, name: str, *, minimum: int = 0, maximum: int = 2**62
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PlanRejected(f"{name}: must be an integer")
    if not (minimum <= value <= maximum):
        raise PlanRejected(
            f"{name}: must be within [{minimum}, {maximum}]"
        )
    return value


_PLAN_KEYS = (
    "schema",
    "plan_id",
    "run_ref",
    "source_ref",
    "artifact_ref",
    "workload_ref",
    "profile_ref",
    "phases",
    "cadence_ms",
    "expected_slots",
    "bindings",
    "permitted_lifecycle_updates",
    "optional_counters",
    "limits",
    "hard_deadline_required",
)
_BINDING_KEYS = (
    "owner_ref",
    "component",
    "pid",
    "creation_identity",
    "image_identity",
    "generation",
)
_PHASE_KEYS = ("phase_id", "workload_ref", "first_slot", "last_slot")
_LIMIT_KEYS = (
    "max_processes",
    "max_samples_total",
    "max_total_bytes",
    "max_record_bytes",
    "max_elapsed_ms",
    "slot_lateness_ms",
    "terminal_reserve_records",
    "max_lifecycle_updates",
)


def _validate_binding(data: Any, index: int) -> ProcessBinding:
    if not isinstance(data, Mapping):
        raise PlanRejected(f"bindings[{index}]: must be an object")
    _require_keys(data, _BINDING_KEYS, f"bindings[{index}]")
    pid = _require_int(
        data["pid"], f"bindings[{index}].pid", minimum=1, maximum=_MAX_DWORD
    )
    return ProcessBinding(
        owner_ref=_require_ref(data["owner_ref"], f"bindings[{index}].owner_ref"),
        component=_require_ref(data["component"], f"bindings[{index}].component"),
        pid=pid,
        creation_identity=_require_ref(
            data["creation_identity"],
            f"bindings[{index}].creation_identity",
        ),
        image_identity=_require_ref(
            data["image_identity"],
            f"bindings[{index}].image_identity",
            max_len=_MAX_IMAGE_ID_LEN,
        ),
        generation=_require_ref(
            data["generation"], f"bindings[{index}].generation"
        ),
    )


def _validate_phase(data: Any, index: int, expected_slots: int) -> PhaseBinding:
    if not isinstance(data, Mapping):
        raise PlanRejected(f"phases[{index}]: must be an object")
    _require_keys(data, _PHASE_KEYS, f"phases[{index}]")
    first = _require_int(data["first_slot"], f"phases[{index}].first_slot")
    last = _require_int(data["last_slot"], f"phases[{index}].last_slot")
    if first > last or last >= expected_slots:
        raise PlanRejected(
            f"phases[{index}]: slot range [{first}, {last}] outside "
            f"[0, {expected_slots})"
        )
    return PhaseBinding(
        phase_id=_require_ref(data["phase_id"], f"phases[{index}].phase_id"),
        workload_ref=_require_ref(
            data["workload_ref"], f"phases[{index}].workload_ref"
        ),
        first_slot=first,
        last_slot=last,
    )


def _validate_limits(data: Any) -> CollectionLimits:
    if not isinstance(data, Mapping):
        raise PlanRejected("limits: must be an object")
    _require_keys(data, _LIMIT_KEYS, "limits")
    return CollectionLimits(
        max_processes=_require_int(
            data["max_processes"],
            "limits.max_processes",
            minimum=1,
            maximum=_MAX_PROCESS_COUNT,
        ),
        max_samples_total=_require_int(data["max_samples_total"], "limits.max_samples_total", minimum=1),
        max_total_bytes=_require_int(data["max_total_bytes"], "limits.max_total_bytes", minimum=1024),
        max_record_bytes=_require_int(data["max_record_bytes"], "limits.max_record_bytes", minimum=256, maximum=16 * 1024 * 1024),
        max_elapsed_ms=_require_int(data["max_elapsed_ms"], "limits.max_elapsed_ms", minimum=1),
        slot_lateness_ms=_require_int(data["slot_lateness_ms"], "limits.slot_lateness_ms", minimum=0),
        terminal_reserve_records=_require_int(data["terminal_reserve_records"], "limits.terminal_reserve_records", minimum=1, maximum=64),
        max_lifecycle_updates=_require_int(data["max_lifecycle_updates"], "limits.max_lifecycle_updates", minimum=0, maximum=1024),
    )


def validate_sampling_plan(data: Any) -> SamplingPlan:
    """Validate a sampling plan mapping into a closed :class:`SamplingPlan`.

    Rejects extra fields, empty process sets, duplicate stream identities,
    uncovered slots, invalid cadence/counts, undeclared optional counters,
    and unknown lifecycle updates. Raises :class:`PlanRejected`.
    """
    if isinstance(data, SamplingPlan):
        return validate_sampling_plan(data.to_dict())
    if not isinstance(data, Mapping):
        raise PlanRejected("plan: must be an object")
    _require_keys(data, _PLAN_KEYS, "plan")
    if data["schema"] != SCHEMA_ID:
        raise PlanRejected(f"plan.schema: must be {SCHEMA_ID!r}")
    expected_slots = _require_int(
        data["expected_slots"], "plan.expected_slots", minimum=1, maximum=10**7
    )
    cadence_ms = _require_int(
        data["cadence_ms"], "plan.cadence_ms", minimum=1, maximum=3600 * 1000
    )
    raw_bindings = data["bindings"]
    if not isinstance(raw_bindings, Sequence) or isinstance(raw_bindings, (str, bytes)):
        raise PlanRejected("plan.bindings: must be a non-empty array")
    if not raw_bindings:
        raise PlanRejected("plan.bindings: process set must be finite and non-empty")
    bindings = tuple(_validate_binding(b, i) for i, b in enumerate(raw_bindings))
    keys = [b.stream_key() for b in bindings]
    if len(set(keys)) != len(keys):
        raise PlanRejected("plan.bindings: duplicate process identities rejected")
    raw_phases = data["phases"]
    if not isinstance(raw_phases, Sequence) or isinstance(raw_phases, (str, bytes)):
        raise PlanRejected("plan.phases: must be a non-empty array")
    if not raw_phases:
        raise PlanRejected("plan.phases: at least one phase is required")
    phases = tuple(
        _validate_phase(p, i, expected_slots) for i, p in enumerate(raw_phases)
    )
    covered = [False] * expected_slots
    for phase in phases:
        for slot in range(phase.first_slot, phase.last_slot + 1):
            if covered[slot]:
                raise PlanRejected("plan.phases: overlapping phase ranges rejected")
            covered[slot] = True
    if not all(covered):
        missing = [str(i) for i, c in enumerate(covered) if not c]
        raise PlanRejected(
            f"plan.phases: uncovered slots rejected: {','.join(missing)}"
        )
    raw_updates = data["permitted_lifecycle_updates"]
    if not isinstance(raw_updates, Sequence) or isinstance(raw_updates, (str, bytes)):
        raise PlanRejected("plan.permitted_lifecycle_updates: must be an array")
    updates = tuple(raw_updates)
    for update in updates:
        if update not in _PERMITTED_LIFECYCLE_UPDATES:
            raise PlanRejected(
                f"plan.permitted_lifecycle_updates: unknown update {update!r}"
            )
    if len(set(updates)) != len(updates):
        raise PlanRejected("plan.permitted_lifecycle_updates: duplicates rejected")
    raw_optional = data["optional_counters"]
    if not isinstance(raw_optional, Sequence) or isinstance(raw_optional, (str, bytes)):
        raise PlanRejected("plan.optional_counters: must be an array")
    optional = tuple(raw_optional)
    allowed_optional = {c.value for c in OPTIONAL_COUNTERS}
    for name in optional:
        if name not in allowed_optional:
            raise PlanRejected(f"plan.optional_counters: unknown counter {name!r}")
    if len(set(optional)) != len(optional):
        raise PlanRejected("plan.optional_counters: duplicates rejected")
    hard_deadline = data["hard_deadline_required"]
    if not isinstance(hard_deadline, bool):
        raise PlanRejected("plan.hard_deadline_required: must be a boolean")
    limits = _validate_limits(data["limits"])
    if len(bindings) > limits.max_processes:
        raise PlanRejected("plan.bindings: exceeds limits.max_processes")
    terminal_reserve_bytes = (
        limits.terminal_reserve_records * limits.max_record_bytes
    )
    if terminal_reserve_bytes >= limits.max_total_bytes:
        raise PlanRejected(
            "plan.limits: terminal byte reserve must leave capacity "
            "for nonterminal records"
        )
    return SamplingPlan(
        schema=SCHEMA_ID,
        plan_id=_require_ref(data["plan_id"], "plan.plan_id"),
        run_ref=_require_ref(data["run_ref"], "plan.run_ref"),
        source_ref=_require_ref(data["source_ref"], "plan.source_ref"),
        artifact_ref=_require_ref(data["artifact_ref"], "plan.artifact_ref"),
        workload_ref=_require_ref(data["workload_ref"], "plan.workload_ref"),
        profile_ref=_require_ref(data["profile_ref"], "plan.profile_ref"),
        phases=phases,
        cadence_ms=cadence_ms,
        expected_slots=expected_slots,
        bindings=bindings,
        permitted_lifecycle_updates=updates,
        optional_counters=optional,
        limits=limits,
        hard_deadline_required=hard_deadline,
    )


_RECORD_HEADER_KEYS = (
    "schema",
    "kind",
    "run_ref",
    "plan_id",
    "plan_digest",
    "source_ref",
    "artifact_ref",
    "stream",
    "seq",
    "slot",
    "elapsed_ms",
    "phase_id",
    "workload_ref",
)
_STREAM_KEYS = (
    "owner_ref",
    "component",
    "pid",
    "generation",
    "binding_digest",
)
_COUNTER_KEYS = ("name", "value", "unit", "status", "reason", "api_error")
_EVENT_KEYS = ("code", "detail", "handoff", "api_error", "exit_code")


def _record_fail(message: str) -> RecordRejected:
    return RecordRejected(message)


def _check_ref(value: Any, name: str, *, max_len: int = _MAX_REF_LEN) -> str:
    if not isinstance(value, str) or not value:
        raise _record_fail(f"{name}: must be a non-empty string")
    if len(value) > max_len:
        raise _record_fail(f"{name}: exceeds {max_len} chars")
    if any(ch < " " for ch in value):
        raise _record_fail(f"{name}: control characters rejected")
    return value


def _check_int(value: Any, name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _record_fail(f"{name}: must be an integer")
    if value < minimum:
        raise _record_fail(f"{name}: must be >= {minimum}")
    return value


def _check_digest(value: Any, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise _record_fail(f"{name}: must be a lowercase SHA-256 digest")
    return value


def _validate_stream_key(data: Any) -> Dict[str, Any]:
    if not isinstance(data, Mapping):
        raise _record_fail("stream: must be an object")
    extra = [k for k in data.keys() if k not in _STREAM_KEYS]
    if extra:
        raise _record_fail(f"stream: extra fields rejected: {sorted(extra)!r}")
    for key in _STREAM_KEYS:
        if key not in data:
            raise _record_fail(f"stream: missing field {key!r}")
    _check_ref(data["owner_ref"], "stream.owner_ref")
    _check_ref(data["component"], "stream.component")
    pid = _check_int(data["pid"], "stream.pid", minimum=1)
    if pid > _MAX_DWORD:
        raise _record_fail("stream.pid: exceeds the Win32 DWORD range")
    _check_ref(data["generation"], "stream.generation")
    _check_digest(data["binding_digest"], "stream.binding_digest")
    return dict(data)


def _validate_counter(
    data: Any, index: int, allowed_names: Sequence[str]
) -> CounterReading:
    where = f"counters[{index}]"
    if not isinstance(data, Mapping):
        raise _record_fail(f"{where}: must be an object")
    extra = [k for k in data.keys() if k not in _COUNTER_KEYS]
    if extra:
        raise _record_fail(f"{where}: extra fields rejected: {sorted(extra)!r}")
    for key in ("name", "value", "unit", "status"):
        if key not in data:
            raise _record_fail(f"{where}: missing field {key!r}")
    name = data["name"]
    if name not in allowed_names:
        raise _record_fail(f"{where}: counter {name!r} not declared by plan")
    unit = data["unit"]
    if unit != COUNTER_UNITS[name]:
        raise _record_fail(
            f"{where}: unit {unit!r} invalid for {name!r}; "
            f"must be {COUNTER_UNITS[name]!r}"
        )
    status = data["status"]
    if status not in (CounterStatus.OK, CounterStatus.UNKNOWN):
        raise _record_fail(f"{where}: unknown status {status!r}")
    value = data["value"]
    reason = data.get("reason")
    api_error = data.get("api_error")
    if status == CounterStatus.OK:
        if isinstance(value, bool) or not isinstance(value, int):
            raise _record_fail(f"{where}: ok value must be an integer")
        if value < 0:
            raise _record_fail(f"{where}: negative value rejected")
        if reason is not None:
            raise _record_fail(f"{where}: ok reading must not carry a reason")
    else:
        if value is not None:
            raise _record_fail(
                f"{where}: unknown reading must be null, never a number"
            )
        if not isinstance(reason, str) or reason not in CLOSED_REASONS:
            raise _record_fail(
                f"{where}: unknown reading needs a closed reason"
            )
    if api_error is not None:
        if isinstance(api_error, bool) or not isinstance(api_error, int):
            raise _record_fail(f"{where}: api_error must be an integer")
        if not 0 <= api_error <= _MAX_API_ERROR:
            raise _record_fail(f"{where}: api_error out of range")
    return CounterReading(
        name=name,
        value=value,
        unit=unit,
        status=status,
        reason=reason,
        api_error=api_error,
    )


def _validate_event(data: Any) -> Dict[str, Any]:
    if not isinstance(data, Mapping):
        raise _record_fail("event: must be an object")
    extra = [k for k in data.keys() if k not in _EVENT_KEYS]
    if extra:
        raise _record_fail(f"event: extra fields rejected: {sorted(extra)!r}")
    if "code" not in data:
        raise _record_fail("event: missing field 'code'")
    code = data["code"]
    if code not in {c.value for c in LifecycleCode}:
        raise _record_fail(f"event: unknown code {code!r}")
    out: Dict[str, Any] = {"code": code}
    if "detail" in data:
        detail = data["detail"]
        if not isinstance(detail, str) or detail not in CLOSED_REASONS:
            raise _record_fail("event.detail: must be a closed reason")
        out["detail"] = detail
    if "handoff" in data:
        handoff = data["handoff"]
        if handoff != HANDOFF_IDENTITY_UNAVAILABLE:
            raise _record_fail("event.handoff: unknown handoff reference")
        out["handoff"] = handoff
    for key in ("api_error", "exit_code"):
        if key in data:
            value = data[key]
            if isinstance(value, bool) or not isinstance(value, int):
                raise _record_fail(f"event.{key}: must be an integer")
            if not 0 <= value <= _MAX_API_ERROR:
                raise _record_fail(f"event.{key}: out of range")
            out[key] = value
    return out


def validate_record(
    data: Any, *, plan: Optional[SamplingPlan] = None
) -> Dict[str, Any]:
    """Validate one transport record mapping; return its normalized dict.

    Closed per-kind key sets; unknown kinds, extra fields, invalid units,
    negative values, and inconsistent kind/body combinations are rejected.
    Raises :class:`RecordRejected`.
    """
    if not isinstance(data, Mapping):
        raise _record_fail("record: must be an object")
    if data.get("schema") != SCHEMA_ID:
        raise _record_fail(f"record.schema: must be {SCHEMA_ID!r}")
    kind = data.get("kind")
    if kind == RecordKind.SAMPLE:
        allowed = _RECORD_HEADER_KEYS + ("counters", "wall_ms")
        required_body = ("counters",)
    elif kind in (RecordKind.MISSED_SLOT, RecordKind.LIFECYCLE, RecordKind.TERMINAL):
        allowed = _RECORD_HEADER_KEYS + ("event", "wall_ms")
        required_body = ("event",)
    else:
        raise _record_fail(f"record.kind: unknown kind {kind!r}")
    extra = [k for k in data.keys() if k not in allowed]
    if extra:
        raise _record_fail(f"record: extra fields rejected: {sorted(extra)!r}")
    for key in _RECORD_HEADER_KEYS:
        if key not in data:
            raise _record_fail(f"record: missing field {key!r}")
    for key in required_body:
        if key not in data:
            raise _record_fail(f"record: {kind} requires field {key!r}")
    if kind == RecordKind.SAMPLE and "event" in data:
        raise _record_fail("record: sample must not carry an event")
    if kind != RecordKind.SAMPLE and "counters" in data:
        raise _record_fail(f"record: {kind} must not carry counters")
    stream = _validate_stream_key(data["stream"])
    _check_ref(data["run_ref"], "record.run_ref")
    _check_ref(data["plan_id"], "record.plan_id")
    _check_digest(data["plan_digest"], "record.plan_digest")
    _check_ref(data["source_ref"], "record.source_ref")
    _check_ref(data["artifact_ref"], "record.artifact_ref")
    _check_int(data["seq"], "record.seq")
    _check_int(data["slot"], "record.slot")
    _check_int(data["elapsed_ms"], "record.elapsed_ms")
    _check_ref(data["phase_id"], "record.phase_id")
    _check_ref(data["workload_ref"], "record.workload_ref")
    if "wall_ms" in data:
        _check_int(data["wall_ms"], "record.wall_ms")
    if plan is not None:
        if data["plan_id"] != plan.plan_id or data["run_ref"] != plan.run_ref:
            raise _record_fail("record: plan/run binding mismatch")
        if data["plan_digest"] != plan.plan_digest:
            raise _record_fail("record: canonical plan digest mismatch")
        if data["source_ref"] != plan.source_ref:
            raise _record_fail("record: source binding mismatch")
        if data["artifact_ref"] != plan.artifact_ref:
            raise _record_fail("record: artifact binding mismatch")
        if (
            (kind == RecordKind.TERMINAL and data["slot"] != plan.expected_slots)
            or (kind != RecordKind.TERMINAL and data["slot"] >= plan.expected_slots)
        ):
            raise _record_fail("record: slot outside plan range")
        expected_binding = plan._binding_index.get(stream["binding_digest"])
        if expected_binding is None:
            raise _record_fail("record: stream is not a plan-bound process")
        expected_stream = {
            "owner_ref": expected_binding.owner_ref,
            "component": expected_binding.component,
            "pid": expected_binding.pid,
            "generation": expected_binding.generation,
            "binding_digest": expected_binding.binding_digest,
        }
        if stream != expected_stream:
            raise _record_fail("record: stream identity differs from plan binding")
        if kind == RecordKind.TERMINAL:
            phase = next(
                (
                    candidate
                    for candidate in plan.phases
                    if candidate.first_slot
                    <= plan.expected_slots - 1
                    <= candidate.last_slot
                ),
                None,
            )
        else:
            phase = next(
                (
                    candidate
                    for candidate in plan.phases
                    if candidate.first_slot <= data["slot"] <= candidate.last_slot
                ),
                None,
            )
        if (
            phase is None
            or data["phase_id"] != phase.phase_id
            or data["workload_ref"] != phase.workload_ref
        ):
            raise _record_fail("record: slot/phase/workload binding mismatch")
    if kind == RecordKind.SAMPLE:
        raw_counters = data["counters"]
        if not isinstance(raw_counters, Sequence) or isinstance(
            raw_counters, (str, bytes)
        ):
            raise _record_fail("record.counters: must be an array")
        allowed_names = [c.value for c in REQUIRED_COUNTERS]
        if plan is not None:
            allowed_names = allowed_names + list(plan.optional_counters)
        else:
            allowed_names = allowed_names + [c.value for c in OPTIONAL_COUNTERS]
        readings = [
            _validate_counter(c, i, allowed_names)
            for i, c in enumerate(raw_counters)
        ]
        names = [r.name for r in readings]
        if len(set(names)) != len(names):
            raise _record_fail("record.counters: duplicate counters rejected")
        for required in REQUIRED_COUNTERS:
            if required.value not in names:
                raise _record_fail(
                    f"record.counters: required counter {required.value!r} missing"
                )
        for name in names:
            if name not in allowed_names:
                raise _record_fail(
                    f"record.counters: {name!r} replaces no required metric"
                )
    else:
        event = _validate_event(data["event"])
        if kind == RecordKind.MISSED_SLOT:
            allowed_codes = {LifecycleCode.SLOT_MISSED}
        elif kind == RecordKind.LIFECYCLE:
            allowed_codes = {
                LifecycleCode.PROCESS_EXIT,
                LifecycleCode.PROCESS_REPLACEMENT,
                LifecycleCode.QUERY_FAILURE,
                LifecycleCode.UNKNOWN_OWNERSHIP,
                LifecycleCode.IDENTITY_UNAVAILABLE,
                LifecycleCode.LIFECYCLE_UPDATE_REJECTED,
            }
        else:
            allowed_codes = {
                LifecycleCode.CANCELLATION,
                LifecycleCode.OUTPUT_TRUNCATION,
                LifecycleCode.RUN_COMPLETE,
            }
        if event["code"] not in allowed_codes:
            raise _record_fail(f"record: {kind} has an inconsistent event code")
        if kind in (RecordKind.MISSED_SLOT, RecordKind.LIFECYCLE):
            if "detail" not in event:
                raise _record_fail(f"record: {kind} requires a closed reason")
        if "api_error" in event and event["code"] != LifecycleCode.QUERY_FAILURE:
            raise _record_fail("record: api_error requires query_failure")
        if "exit_code" in event and event["code"] != LifecycleCode.PROCESS_EXIT:
            raise _record_fail("record: exit_code requires process_exit")
        if "handoff" in event and event["code"] != LifecycleCode.IDENTITY_UNAVAILABLE:
            raise _record_fail("record: handoff requires identity_unavailable")
    return dict(data)


def validate_sample_record(
    data: Any, *, plan: Optional[SamplingPlan] = None
) -> Dict[str, Any]:
    """Validate one sample record mapping; return its normalized dict.

    Non-sample kinds are rejected here; use :func:`validate_record` for the
    full lifecycle/missed-slot/terminal dispatch. Raises
    :class:`RecordRejected`.
    """
    normalized = validate_record(data, plan=plan)
    if normalized["kind"] != RecordKind.SAMPLE:
        raise _record_fail(
            f"sample record: kind {normalized['kind']!r} is not a sample"
        )
    return normalized


def _check_json_bounds(obj: Any, depth: int, budget: List[int]) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise RecordRejected("record: JSON nesting exceeds bound")
    if isinstance(obj, Mapping):
        budget[0] -= len(obj)
        if budget[0] < 0:
            raise RecordRejected("record: JSON key budget exceeded")
        for value in obj.values():
            _check_json_bounds(value, depth + 1, budget)
    elif isinstance(obj, (list, tuple)):
        budget[0] -= len(obj)
        if budget[0] < 0:
            raise RecordRejected("record: JSON item budget exceeded")
        for value in obj:
            _check_json_bounds(value, depth + 1, budget)


def decode_record(
    data: bytes, *, max_bytes: int, plan: Optional[SamplingPlan] = None
) -> Dict[str, Any]:
    """Boundedly decode one transport record; length is checked first.

    Raises :class:`RecordRejected` before and after JSON parsing so hostile
    inputs cannot force unbounded allocation.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise RecordRejected("record: transport body must be bytes")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        raise RecordRejected("record: max_bytes must be a non-negative integer")
    if len(data) > max_bytes:
        raise RecordRejected("record: transport body exceeds max_record_bytes")
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RecordRejected("record: transport body is not UTF-8") from exc

    def reject_duplicate_keys(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise RecordRejected("record: duplicate JSON key rejected")
            result[key] = value
        return result

    def reject_nonfinite(_value: str) -> Any:
        raise RecordRejected("record: non-finite JSON number rejected")

    try:
        obj = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except RecordRejected:
        raise
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise RecordRejected("record: invalid or unbounded JSON") from exc
    try:
        _check_json_bounds(obj, 0, [_MAX_JSON_KEYS])
    except RecursionError as exc:
        raise RecordRejected("record: JSON nesting exceeds bound") from exc
    return validate_record(obj, plan=plan)


def encode_semantic(record: Mapping[str, Any]) -> bytes:
    """Deterministic semantic encoding: canonical JSON without diagnostics.

    ``wall_ms`` is diagnostic only and excluded, so the semantic digest is
    stable across transports of the same domain content.
    """
    body = {k: v for k, v in record.items() if k != "wall_ms"}
    return (
        json.dumps(body, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True).encode("utf-8")
        + b"\n"
    )


def encode_transport(record: Mapping[str, Any]) -> bytes:
    """Deterministic transport encoding: canonical JSON incl. diagnostics."""
    return (
        json.dumps(dict(record), sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True).encode("utf-8")
        + b"\n"
    )


class StreamValidator:
    """Per-stream sequence/slot/conflict enforcement for #943 and the loop.

    Sequences and slots must strictly increase per stream; a repeated slot
    with differing semantic content is a conflict, an identical repeat is a
    duplicate. Both are rejected, never merged.
    """

    def __init__(self, plan: Optional[SamplingPlan] = None) -> None:
        self._plan = plan
        self._last_seq: Dict[str, int] = {}
        self._last_slot: Dict[str, int] = {}
        self._last_slot_digest: Dict[str, str] = {}
        self._terminated: Dict[str, str] = {}
        self._committed_run_ref: Optional[str] = None
        self._committed_plan_id: Optional[str] = None
        self._committed_plan_digest: Optional[str] = None

    @staticmethod
    def _key_of(stream: Mapping[str, Any]) -> str:
        return str(stream["binding_digest"])

    def _preview(
        self, data: Any
    ) -> Tuple[Dict[str, Any], str, int, int, str]:
        normalized = validate_record(data, plan=self._plan)
        if self._plan is None and self._committed_plan_id is not None:
            if (
                normalized["run_ref"] != self._committed_run_ref
                or
                normalized["plan_id"] != self._committed_plan_id
                or normalized["plan_digest"] != self._committed_plan_digest
            ):
                raise StreamRejected(
                    "stream validator: committed plan identity changed"
                )
        key = self._key_of(normalized["stream"])
        if key not in self._last_seq and len(self._last_seq) >= _MAX_PROCESS_COUNT:
            raise StreamRejected("stream validator: fixed stream bound exceeded")
        if key in self._terminated:
            raise StreamRejected(
                f"stream {key}: record after terminal "
                f"{self._terminated[key]} rejected"
            )
        seq = int(normalized["seq"])
        slot = int(normalized["slot"])
        if key in self._last_seq and seq <= self._last_seq[key]:
            raise StreamRejected(
                f"stream {key}: seq {seq} not strictly increasing "
                f"(last {self._last_seq[key]})"
            )
        if key in self._last_slot and slot < self._last_slot[key]:
            raise StreamRejected(
                f"stream {key}: reordered slot {slot} "
                f"(last {self._last_slot[key]})"
            )
        digest = hashlib.sha256(encode_semantic(normalized)).hexdigest()
        if key in self._last_slot and slot == self._last_slot[key]:
            if self._last_slot_digest[key] != digest:
                raise StreamRejected(
                    f"stream {key}: conflicting content for slot {slot}"
                )
            raise StreamRejected(
                f"stream {key}: duplicate record for slot {slot}"
            )
        return normalized, key, seq, slot, digest

    def _commit(
        self,
        normalized: Mapping[str, Any],
        key: str,
        seq: int,
        slot: int,
        digest: str,
    ) -> None:
        if self._plan is None and self._committed_plan_id is None:
            self._committed_run_ref = str(normalized["run_ref"])
            self._committed_plan_id = str(normalized["plan_id"])
            self._committed_plan_digest = str(normalized["plan_digest"])
        self._last_seq[key] = seq
        self._last_slot[key] = slot
        self._last_slot_digest[key] = digest
        if normalized["kind"] == RecordKind.TERMINAL or (
            normalized["kind"] == RecordKind.LIFECYCLE
            and normalized["event"]["code"]
            in {
                LifecycleCode.PROCESS_EXIT,
                LifecycleCode.PROCESS_REPLACEMENT,
                LifecycleCode.UNKNOWN_OWNERSHIP,
                LifecycleCode.IDENTITY_UNAVAILABLE,
                LifecycleCode.LIFECYCLE_UPDATE_REJECTED,
            }
        ):
            self._terminated[key] = str(normalized["event"]["code"])

    def observe(self, data: Any) -> Dict[str, Any]:
        normalized, key, seq, slot, digest = self._preview(data)
        self._commit(normalized, key, seq, slot, digest)
        return normalized


@dataclass(frozen=True)
class QueryContext:
    slot: int
    elapsed_ms: int
    phase_id: str
    workload_ref: str


@dataclass(frozen=True)
class SampleCounters:
    """One successful query: required counters plus declared optionals."""

    readings: Tuple[CounterReading, ...]


@dataclass(frozen=True)
class ProcessExit:
    exit_code: Optional[int] = None


@dataclass(frozen=True)
class ProcessReplacement:
    observed_creation: str = ""
    observed_image: str = ""


@dataclass(frozen=True)
class QueryFailure:
    reason: str
    api_error: Optional[int] = None
    detail: str = ""


@dataclass(frozen=True)
class UnknownOwnership:
    detail: str = ""


QueryOutcome = (
    SampleCounters,
    ProcessExit,
    ProcessReplacement,
    QueryFailure,
    UnknownOwnership,
)


@dataclass
class PreparedTarget:
    """An owner-bound query target held by the process source.

    ``owned_handle`` marks a query handle opened by this sampler run; only
    such handles are closed during cleanup. Owner-retained handles are never
    closed here.
    """

    binding: ProcessBinding
    owned_handle: bool = False
    note: str = ""


class ProcessSource:
    """Injected owner/query adapter protocol (supplied by #944).

    Implementations bind owner-approved identities, query counters, admit
    owner-approved lifecycle updates, and release sampler-owned handles.
    """

    capabilities: Tuple[str, ...] = ()

    def admit_binding(
        self, expected: ProcessBinding
    ) -> AdmittedProcessBinding:
        """Ask this source's owner boundary to admit one expected binding."""
        raise IdentityUnavailable()

    def _mint_admitted_binding(
        self,
        expected: ProcessBinding,
        owner_observation: Any,
    ) -> AdmittedProcessBinding:
        """Mint only after a source-specific owner observation is obtained.

        Synthetic sources call this with an independently stored fixture-owner
        observation. The plan binding itself is never an observation.
        """
        if not isinstance(expected, ProcessBinding) or not isinstance(
            owner_observation, ProcessBinding
        ):
            raise IdentityUnavailable()
        try:
            validated = _validate_binding(expected.to_dict(), 0)
        except (PlanRejected, TypeError, ValueError):
            raise IdentityUnavailable() from None
        if owner_observation != expected or validated != expected:
            raise IdentityUnavailable()
        return AdmittedProcessBinding(
            expected, self, _RECEIPT_MINT_TOKEN
        )

    def _require_admitted_binding(
        self,
        receipt: Any,
        expected: Optional[ProcessBinding] = None,
    ) -> ProcessBinding:
        if (
            not isinstance(receipt, AdmittedProcessBinding)
            or receipt._issuer is not self
            or receipt.binding_digest != receipt.binding.binding_digest
            or (expected is not None and receipt.binding != expected)
        ):
            raise IdentityUnavailable()
        try:
            if _validate_binding(receipt.binding.to_dict(), 0) != receipt.binding:
                raise IdentityUnavailable()
        except (PlanRejected, TypeError, ValueError):
            raise IdentityUnavailable() from None
        return receipt.binding

    def prepare(self, receipt: AdmittedProcessBinding) -> PreparedTarget:
        raise NotImplementedError

    def query(self, target: PreparedTarget, context: QueryContext) -> Any:
        raise NotImplementedError

    def pending_bindings(self) -> Tuple[ProcessBinding, ...]:
        return ()

    def sampler_footprint(self) -> "SamplerFootprint":
        raise NotImplementedError

    def release(self, target: PreparedTarget) -> None:
        raise NotImplementedError


class SampleClock:
    """Injected monotonic schedule clock (supplied by #944)."""

    def monotonic_ms(self) -> int:
        raise NotImplementedError

    def wall_ms(self) -> int:
        raise NotImplementedError

    def wait_until(self, deadline_ms: int, cancelled: Callable[[], bool]) -> bool:
        """Wait for the monotonic deadline; False when cancelled first."""
        raise NotImplementedError


class RecordSink:
    """Injected streaming record sink (supplied by #944)."""

    def write(self, data: bytes) -> int:
        """Accept one complete record or report an uncertain/short write.

        An exact byte count acknowledges the complete record. Any short,
        oversized, invalid, or exceptional result freezes the in-band stream.
        """
        raise NotImplementedError

    @property
    def bytes_accepted(self) -> int:
        raise NotImplementedError


@dataclass(frozen=True)
class SamplerFootprint:
    working_set_bytes: Optional[int] = None
    private_commit_bytes: Optional[int] = None
    handle_count: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "working_set_bytes": self.working_set_bytes,
            "private_commit_bytes": self.private_commit_bytes,
            "handle_count": self.handle_count,
        }


@dataclass(frozen=True)
class StreamSummary:
    stream_key: str
    emitted: int
    missed: int
    query_failed: int
    terminal_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stream_key": self.stream_key,
            "emitted": self.emitted,
            "missed": self.missed,
            "query_failed": self.query_failed,
            "terminal_code": self.terminal_code,
        }


@dataclass(frozen=True)
class SamplingResult:
    """Run outcome: counts, digests, completeness, cleanup. No verdict."""

    schema: str
    plan_id: str
    plan_digest: str
    run_ref: str
    expected_samples: int
    accepted_samples: int
    accepted_gap_slots: int
    accepted_gaps_by_reason: Mapping[str, int]
    accepted_lifecycle_records: int
    accepted_terminals: int
    missing_obligations: int
    failed_writes: int
    emitted_records: int
    missed_slots: int
    query_failed: int
    valid_prefix_records: int
    transport_digest: str
    semantic_digest: str
    completeness: str
    completeness_reasons: Tuple[str, ...]
    handle_cleanup: str
    handle_cleanup_detail: Optional[str]
    hard_deadline: str
    sampler_footprint: SamplerFootprint
    streams: Tuple[StreamSummary, ...]
    sink_error: Optional[str] = None
    diagnostics: Tuple[str, ...] = field(default=(), repr=False, compare=False)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "plan_digest": self.plan_digest,
            "run_ref": self.run_ref,
            "expected_samples": self.expected_samples,
            "accepted_samples": self.accepted_samples,
            "accepted_gap_slots": self.accepted_gap_slots,
            "accepted_gaps_by_reason": dict(self.accepted_gaps_by_reason),
            "accepted_lifecycle_records": self.accepted_lifecycle_records,
            "accepted_terminals": self.accepted_terminals,
            "missing_obligations": self.missing_obligations,
            "failed_writes": self.failed_writes,
            "emitted_records": self.emitted_records,
            "missed_slots": self.missed_slots,
            "query_failed": self.query_failed,
            "valid_prefix_records": self.valid_prefix_records,
            "transport_digest": self.transport_digest,
            "semantic_digest": self.semantic_digest,
            "completeness": self.completeness,
            "completeness_reasons": list(self.completeness_reasons),
            "handle_cleanup": self.handle_cleanup,
            "hard_deadline": self.hard_deadline,
            "sampler_footprint": self.sampler_footprint.to_dict(),
            "streams": [s.to_dict() for s in self.streams],
        }
        if self.handle_cleanup_detail is not None:
            out["handle_cleanup_detail"] = self.handle_cleanup_detail
        if self.sink_error is not None:
            out["sink_error"] = self.sink_error
        return out


def encode_result(result: SamplingResult) -> bytes:
    """Deterministic versioned encoding of the run summary for #943."""
    return (
        json.dumps(result.to_dict(), sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True).encode("utf-8")
        + b"\n"
    )


def non_unique_working_set_sum(samples: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Sum working-set bytes across samples, explicitly labeled non-unique.

    Per-process working sets may share physical pages, so the total is never
    system or private RSS. Only ``ok`` working-set readings contribute;
    unknown readings are counted separately and never treated as zero.
    """
    total = 0
    contributing = 0
    unknown = 0
    for sample in samples:
        normalized = validate_sample_record(sample)
        for counter in normalized["counters"]:
            if counter["name"] != CounterName.WORKING_SET_BYTES:
                continue
            if counter["status"] == CounterStatus.OK:
                total += int(counter["value"])
                contributing += 1
            else:
                unknown += 1
    return {
        "label": "non-unique-shared-pages",
        "total_working_set_bytes": total,
        "contributing_readings": contributing,
        "unknown_readings": unknown,
        "not_system_rss": True,
        "not_private_rss": True,
    }


def _as_cancel_flag(cancellation: Any) -> Callable[[], bool]:
    if cancellation is None:
        return lambda: False
    if callable(cancellation):
        return cancellation  # type: ignore[return-value]
    probe = getattr(cancellation, "is_cancelled", None)
    if callable(probe):
        return probe
    raise SamplingError("cancellation: must be None, a callable, or is_cancelled()")


@dataclass
class _StreamState:
    binding: ProcessBinding
    receipt: Optional[AdmittedProcessBinding] = None
    target: Optional[PreparedTarget] = None
    sampler_owned_target: bool = False
    prepared: bool = False
    seq: int = 0
    emitted: int = 0
    missed: int = 0
    query_failed: int = 0
    dead: bool = False
    terminal_code: Optional[str] = None
    admit_slot: int = 0


class _Collector:
    """Deterministic injected sampling loop behind :func:`collect_samples`."""

    def __init__(
        self,
        plan: SamplingPlan,
        process_source: ProcessSource,
        clock: SampleClock,
        sink: RecordSink,
        cancelled: Callable[[], bool],
    ) -> None:
        self._plan = plan
        self._source = process_source
        self._clock = clock
        self._sink = sink
        self._cancelled = cancelled
        self._streams: Dict[str, _StreamState] = {}
        self._order: List[str] = []
        self._validator = StreamValidator(plan)
        self._transport = hashlib.sha256()
        self._semantic = hashlib.sha256()
        self._valid_prefix = 0
        self._emitted_records = 0
        self._samples = 0
        self._query_attempts = 0
        self._missed = 0
        self._query_failed = 0
        self._expected = len(plan.bindings) * plan.expected_slots
        self._accepted_gap_slots = 0
        self._accepted_gaps_by_reason: Dict[str, int] = {
            reason: 0 for reason in sorted(CLOSED_REASONS)
        }
        self._accepted_lifecycle_records = 0
        self._accepted_terminals = 0
        self._failed_writes = 0
        self._terminal_failures = 0
        self._terminal_attempts = 0
        self._soft_deadline_exceeded = False
        self._reasons: List[str] = []
        self._sink_error: Optional[str] = None
        self._sink_dead = False
        self._output_truncated = False
        self._confirmed_bytes = 0
        self._terminal_reserve_bytes = (
            plan.limits.terminal_reserve_records * plan.limits.max_record_bytes
        )
        self._ordinary_byte_limit = (
            plan.limits.max_total_bytes - self._terminal_reserve_bytes
        )
        self._diagnostic_counts: Dict[Tuple[str, str], int] = {}
        self._updates_used = 0
        self._t0_ms = 0
        self._cleanup_done = False
        self._cleanup_result: Tuple[str, Optional[str]] = (
            HandleCleanupStatus.NONE_OWNED,
            None,
        )
        for binding in plan.bindings:
            self._admit(binding, 0)

    # -- stream bookkeeping ------------------------------------------------

    def _admit(self, binding: ProcessBinding, slot: int) -> None:
        key = binding.stream_key()
        self._streams[key] = _StreamState(binding=binding, admit_slot=slot)
        self._order.append(key)

    def _diagnose(self, stage: str, error: Optional[BaseException] = None) -> None:
        stages = {
            "owner_admission",
            "prepare",
            "query",
            "sink",
            "footprint",
            "cleanup",
            "terminal",
        }
        if stage not in stages:
            stage = "query"
        if error is None:
            kind = "redacted"
        elif isinstance(error, SinkError):
            kind = "sink_error"
        elif isinstance(error, OSError):
            kind = "os_error"
        elif isinstance(error, ValueError):
            kind = "value_error"
        elif isinstance(error, SamplingError):
            kind = "sampling_error"
        else:
            kind = "other"
        key = (stage, kind)
        self._diagnostic_counts[key] = self._diagnostic_counts.get(key, 0) + 1

    def _diagnostic_summary(self) -> Tuple[str, ...]:
        return tuple(
            f"{stage}:{kind}:{count}"
            for (stage, kind), count in sorted(self._diagnostic_counts.items())
        )

    def _phase_for(self, slot: int) -> PhaseBinding:
        for phase in self._plan.phases:
            if phase.first_slot <= slot <= phase.last_slot:
                return phase
        raise SamplingError(f"slot {slot}: no phase covers it")

    # -- record construction -----------------------------------------------

    def _base(
        self, state: _StreamState, kind: str, slot: int, elapsed_ms: int
    ) -> Dict[str, Any]:
        plan = self._plan
        phase_slot = plan.expected_slots - 1 if slot == plan.expected_slots else slot
        phase = self._phase_for(phase_slot)
        record: Dict[str, Any] = {
            "schema": SCHEMA_ID,
            "kind": kind,
            "run_ref": plan.run_ref,
            "plan_id": plan.plan_id,
            "plan_digest": plan.plan_digest,
            "source_ref": plan.source_ref,
            "artifact_ref": plan.artifact_ref,
            "stream": {
                "owner_ref": state.binding.owner_ref,
                "component": state.binding.component,
                "pid": state.binding.pid,
                "generation": state.binding.generation,
                "binding_digest": state.binding.binding_digest,
            },
            "seq": state.seq,
            "slot": slot,
            "elapsed_ms": elapsed_ms,
            "phase_id": phase.phase_id,
            "workload_ref": phase.workload_ref,
            "wall_ms": self._clock.wall_ms(),
        }
        return record

    def _sample_record(
        self,
        state: _StreamState,
        slot: int,
        elapsed_ms: int,
        outcome: SampleCounters,
    ) -> Dict[str, Any]:
        allowed = [c.value for c in REQUIRED_COUNTERS]
        allowed += list(self._plan.optional_counters)
        names = [r.name for r in outcome.readings]
        if len(set(names)) != len(names):
            raise SamplingError("adapter: duplicate counters in one query")
        for required in REQUIRED_COUNTERS:
            if required.value not in names:
                raise SamplingError(
                    f"adapter: required counter {required.value!r} missing"
                )
        for name in names:
            if name not in allowed:
                raise SamplingError(
                    f"adapter: counter {name!r} not declared by plan"
                )
        record = self._base(state, RecordKind.SAMPLE, slot, elapsed_ms)
        record["counters"] = [r.to_dict() for r in outcome.readings]
        return record

    def _gap_record(
        self,
        state: _StreamState,
        slot: int,
        elapsed_ms: int,
        code: str,
        detail: str = "",
    ) -> Dict[str, Any]:
        record = self._base(state, RecordKind.MISSED_SLOT, slot, elapsed_ms)
        event: Dict[str, Any] = {"code": code}
        if detail:
            event["detail"] = detail
        record["event"] = event
        return record

    def _lifecycle_record(
        self,
        state: _StreamState,
        slot: int,
        elapsed_ms: int,
        code: str,
        detail: str = "",
        handoff: str = "",
        api_error: Optional[int] = None,
        exit_code: Optional[int] = None,
    ) -> Dict[str, Any]:
        record = self._base(state, RecordKind.LIFECYCLE, slot, elapsed_ms)
        event: Dict[str, Any] = {"code": code}
        if detail:
            event["detail"] = detail
        if handoff:
            event["handoff"] = handoff
        if api_error is not None:
            event["api_error"] = api_error
        if exit_code is not None:
            event["exit_code"] = exit_code
        record["event"] = event
        return record

    def _terminal_record(
        self, state: _StreamState, elapsed_ms: int, code: str, detail: str = ""
    ) -> Dict[str, Any]:
        record = self._base(
            state, RecordKind.TERMINAL, self._plan.expected_slots, elapsed_ms
        )
        event: Dict[str, Any] = {"code": code}
        if detail:
            event["detail"] = detail
        record["event"] = event
        return record

    # -- streaming emit ------------------------------------------------------

    def _refuse_before_write(self, reason: str) -> None:
        self._output_truncated = True
        self._sink_error = reason
        self._note(reason)

    def _state_for_record(self, record: Mapping[str, Any]) -> _StreamState:
        stream = record["stream"]
        key = "|".join(
            (
                stream["owner_ref"],
                stream["component"],
                str(stream["pid"]),
                stream["generation"],
            )
        )
        state = self._streams.get(key)
        if state is None or state.binding.binding_digest != stream["binding_digest"]:
            raise StreamRejected("collector: accepted record has no fixed stream")
        return state

    def _accept_record(
        self, normalized: Mapping[str, Any], state: _StreamState
    ) -> None:
        kind = normalized["kind"]
        if kind == RecordKind.SAMPLE:
            self._samples += 1
            state.emitted += 1
            return
        if kind == RecordKind.TERMINAL:
            self._accepted_terminals += 1
            return
        if kind == RecordKind.MISSED_SLOT:
            self._missed += 1
            state.missed += 1
        else:
            self._accepted_lifecycle_records += 1
            state.emitted += 1
            code = normalized["event"]["code"]
            if code in (LifecycleCode.QUERY_FAILURE, LifecycleCode.UNKNOWN_OWNERSHIP):
                self._query_failed += 1
                state.query_failed += 1
        reason = normalized["event"]["detail"]
        self._accepted_gap_slots += 1
        self._accepted_gaps_by_reason[reason] += 1

    def _emit(self, record: Dict[str, Any]) -> bool:
        """Commit one complete record only after the sink acknowledges it."""
        if self._sink_dead:
            return False
        if self._output_truncated and record.get("kind") != RecordKind.TERMINAL:
            return False
        normalized, key, seq, slot, digest = self._validator._preview(record)
        state = self._state_for_record(normalized)
        if seq != state.seq:
            raise StreamRejected("collector: record sequence is not the next slot")
        transport = encode_transport(normalized)
        if len(transport) > self._plan.limits.max_record_bytes:
            if normalized["kind"] == RecordKind.TERMINAL:
                self._terminal_failures += 1
                self._diagnose("terminal")
                self._refuse_before_write(Reason.SINK_TRUNCATED)
            else:
                self._refuse_before_write(Reason.SINK_TRUNCATED)
            return False

        terminal = normalized["kind"] == RecordKind.TERMINAL
        if terminal:
            if self._terminal_attempts >= self._plan.limits.terminal_reserve_records:
                self._terminal_failures += 1
                self._diagnose("terminal")
                self._refuse_before_write(Reason.SINK_TRUNCATED)
                return False
            byte_limit = self._plan.limits.max_total_bytes
        else:
            byte_limit = self._ordinary_byte_limit
        if self._confirmed_bytes + len(transport) > byte_limit:
            if terminal:
                self._terminal_failures += 1
                self._diagnose("terminal")
            self._refuse_before_write(Reason.SINK_TRUNCATED)
            return False

        if terminal:
            self._terminal_attempts += 1
        try:
            accepted = self._sink.write(transport)
        except Exception as exc:  # noqa: BLE001 - preserve prefix, redact detail
            self._failed_writes += 1
            self._sink_dead = True
            self._sink_error = Reason.SINK_FAILED
            self._note(Reason.SINK_FAILED)
            self._diagnose("sink", exc)
            return False
        if type(accepted) is not int or accepted != len(transport):
            self._failed_writes += 1
            self._sink_dead = True
            self._sink_error = Reason.SINK_FAILED
            self._note(Reason.SINK_FAILED)
            self._diagnose("sink", ValueError())
            return False

        self._validator._commit(normalized, key, seq, slot, digest)
        state.seq += 1
        self._confirmed_bytes += len(transport)
        self._transport.update(transport)
        self._semantic.update(encode_semantic(normalized))
        self._valid_prefix += 1
        self._emitted_records += 1
        self._accept_record(normalized, state)
        return True

    def _kill_stream(self, state: _StreamState, code: str) -> None:
        state.dead = True
        state.terminal_code = code

    # -- per-slot work ---------------------------------------------------------

    def _ensure_prepared(
        self, key: str, state: _StreamState, slot: int, elapsed_ms: int
    ) -> bool:
        if state.prepared and state.target is not None:
            if (
                state.receipt is None
                or state.target.binding != state.receipt.binding
            ):
                self._emit(
                    self._lifecycle_record(
                        state,
                        slot,
                        elapsed_ms,
                        LifecycleCode.UNKNOWN_OWNERSHIP,
                        detail=Reason.UNKNOWN_OWNERSHIP,
                    )
                )
                self._kill_stream(state, LifecycleCode.UNKNOWN_OWNERSHIP)
                self._note(Reason.UNKNOWN_OWNERSHIP)
                return False
            return True
        try:
            receipt = self._source.admit_binding(state.binding)
            ProcessSource._require_admitted_binding(
                self._source, receipt, state.binding
            )
            state.receipt = receipt
        except IdentityUnavailable as exc:
            self._diagnose("owner_admission", exc)
            self._emit(
                self._lifecycle_record(
                    state,
                    slot,
                    elapsed_ms,
                    LifecycleCode.IDENTITY_UNAVAILABLE,
                    detail=Reason.IDENTITY_UNAVAILABLE,
                    handoff=HANDOFF_IDENTITY_UNAVAILABLE,
                )
            )
            self._kill_stream(state, LifecycleCode.IDENTITY_UNAVAILABLE)
            self._note(Reason.IDENTITY_UNAVAILABLE)
            return False
        except Exception as exc:  # noqa: BLE001 - authority failure is closed
            self._diagnose("owner_admission", exc)
            self._emit(
                self._lifecycle_record(
                    state,
                    slot,
                    elapsed_ms,
                    LifecycleCode.IDENTITY_UNAVAILABLE,
                    detail=Reason.IDENTITY_UNAVAILABLE,
                    handoff=HANDOFF_IDENTITY_UNAVAILABLE,
                )
            )
            self._kill_stream(state, LifecycleCode.IDENTITY_UNAVAILABLE)
            self._note(Reason.IDENTITY_UNAVAILABLE)
            return False
        try:
            state.target = self._source.prepare(state.receipt)
        except IdentityUnavailable as exc:
            self._diagnose("prepare", exc)
            self._emit(
                self._lifecycle_record(
                    state,
                    slot,
                    elapsed_ms,
                    LifecycleCode.IDENTITY_UNAVAILABLE,
                    detail=Reason.IDENTITY_UNAVAILABLE,
                    handoff=HANDOFF_IDENTITY_UNAVAILABLE,
                )
            )
            self._kill_stream(state, LifecycleCode.IDENTITY_UNAVAILABLE)
            self._note(Reason.IDENTITY_UNAVAILABLE)
            return False
        except IdentityMismatch as exc:
            self._diagnose("prepare", exc)
            if exc.reason in (Reason.CREATION_MISMATCH, Reason.IMAGE_MISMATCH):
                self._handle_outcome(
                    key, state, slot, elapsed_ms, ProcessReplacement()
                )
            else:
                self._emit(
                    self._lifecycle_record(
                        state,
                        slot,
                        elapsed_ms,
                        LifecycleCode.UNKNOWN_OWNERSHIP,
                        detail=Reason.UNKNOWN_OWNERSHIP,
                    )
                )
                self._kill_stream(state, LifecycleCode.UNKNOWN_OWNERSHIP)
                self._note(Reason.UNKNOWN_OWNERSHIP)
            return False
        except SamplingError as exc:
            self._diagnose("prepare", exc)
            self._emit(
                self._lifecycle_record(
                    state,
                    slot,
                    elapsed_ms,
                    LifecycleCode.QUERY_FAILURE,
                    detail=Reason.ADAPTER_UNAVAILABLE,
                )
            )
            self._kill_stream(state, LifecycleCode.QUERY_FAILURE)
            self._note(Reason.ADAPTER_UNAVAILABLE)
            return False
        except Exception as exc:  # noqa: BLE001 - cleanup finally, propagate bugs
            self._diagnose("prepare", exc)
            raise
        if isinstance(state.target, PreparedTarget):
            state.sampler_owned_target = state.target.owned_handle is True
        if (
            not isinstance(state.target, PreparedTarget)
            or state.receipt is None
            or state.target.binding != state.receipt.binding
        ):
            self._emit(
                self._lifecycle_record(
                    state,
                    slot,
                    elapsed_ms,
                    LifecycleCode.UNKNOWN_OWNERSHIP,
                    detail=Reason.UNKNOWN_OWNERSHIP,
                )
            )
            self._kill_stream(state, LifecycleCode.UNKNOWN_OWNERSHIP)
            self._note(Reason.UNKNOWN_OWNERSHIP)
            return False
        state.prepared = True
        return True

    def _note(self, reason: str) -> None:
        if reason not in CLOSED_REASONS:
            reason = Reason.QUERY_FAILED
        if reason not in self._reasons:
            self._reasons.append(reason)

    def _handle_outcome(
        self,
        key: str,
        state: _StreamState,
        slot: int,
        elapsed_ms: int,
        outcome: Any,
    ) -> None:
        if isinstance(outcome, SampleCounters):
            self._emit(self._sample_record(state, slot, elapsed_ms, outcome))
        elif isinstance(outcome, ProcessExit):
            exit_code = outcome.exit_code
            if (
                isinstance(exit_code, bool)
                or not isinstance(exit_code, int)
                or not 0 <= exit_code <= _MAX_DWORD
            ):
                exit_code = None
            accepted = self._emit(
                self._lifecycle_record(
                    state,
                    slot,
                    elapsed_ms,
                    LifecycleCode.PROCESS_EXIT,
                    detail=Reason.PROCESS_EXITED,
                    exit_code=exit_code,
                )
            )
            self._kill_stream(state, LifecycleCode.PROCESS_EXIT)
            self._note(Reason.PROCESS_EXITED)
        elif isinstance(outcome, ProcessReplacement):
            permitted = (
                "replace_generation" in self._plan.permitted_lifecycle_updates
            )
            budgeted = self._updates_used < self._plan.limits.max_lifecycle_updates
            if permitted and budgeted:
                accepted = self._emit(
                    self._lifecycle_record(
                        state,
                        slot,
                        elapsed_ms,
                        LifecycleCode.PROCESS_REPLACEMENT,
                        detail=Reason.PROCESS_REPLACED,
                    )
                )
                self._kill_stream(state, LifecycleCode.PROCESS_REPLACEMENT)
                self._note(Reason.PROCESS_REPLACED)
                if accepted:
                    self._updates_used += 1
            else:
                why = (
                    Reason.BUDGET_EXHAUSTED if permitted
                    else Reason.LIFECYCLE_NOT_PERMITTED
                )
                self._emit(
                    self._lifecycle_record(
                        state,
                        slot,
                        elapsed_ms,
                        LifecycleCode.LIFECYCLE_UPDATE_REJECTED,
                        detail=why,
                    )
                )
                self._kill_stream(
                    state, LifecycleCode.LIFECYCLE_UPDATE_REJECTED
                )
                self._note(why)
        elif isinstance(outcome, QueryFailure):
            detail = (
                outcome.reason
                if isinstance(outcome.reason, str)
                and outcome.reason in CLOSED_REASONS
                else Reason.QUERY_FAILED
            )
            api_error = outcome.api_error
            if (
                isinstance(api_error, bool)
                or not isinstance(api_error, int)
                or not 0 <= api_error <= _MAX_DWORD
            ):
                api_error = None
            self._emit(
                self._lifecycle_record(
                    state,
                    slot,
                    elapsed_ms,
                    LifecycleCode.QUERY_FAILURE,
                    detail=detail,
                    api_error=api_error,
                )
            )
            self._note(Reason.QUERY_FAILED)
        elif isinstance(outcome, UnknownOwnership):
            self._emit(
                self._lifecycle_record(
                    state,
                    slot,
                    elapsed_ms,
                    LifecycleCode.UNKNOWN_OWNERSHIP,
                    detail=Reason.UNKNOWN_OWNERSHIP,
                )
            )
            self._kill_stream(state, LifecycleCode.UNKNOWN_OWNERSHIP)
            self._note(Reason.UNKNOWN_OWNERSHIP)
        else:
            raise SamplingError(
                f"adapter: unknown query outcome {type(outcome).__name__}"
            )

    def _sample_stream(
        self, key: str, state: _StreamState, slot: int, elapsed_ms: int
    ) -> None:
        if not self._ensure_prepared(key, state, slot, elapsed_ms):
            return
        assert state.target is not None
        phase = self._phase_for(slot)
        context = QueryContext(
            slot=slot,
            elapsed_ms=elapsed_ms,
            phase_id=phase.phase_id,
            workload_ref=phase.workload_ref,
        )
        try:
            if (
                state.receipt is None
                or state.target.binding != state.receipt.binding
            ):
                self._handle_outcome(
                    key,
                    state,
                    slot,
                    elapsed_ms,
                    UnknownOwnership(detail=Reason.UNKNOWN_OWNERSHIP),
                )
                return
            if (
                self._clock.monotonic_ms() - self._t0_ms
                > self._plan.limits.max_elapsed_ms
            ):
                self._note(Reason.LIMIT_EXCEEDED)
                raise _LimitStop()
            if self._query_attempts >= self._plan.limits.max_samples_total:
                self._note(Reason.LIMIT_EXCEEDED)
                raise _LimitStop()
            self._query_attempts += 1
            outcome = self._source.query(state.target, context)
            if (
                self._clock.monotonic_ms() - self._t0_ms
                > self._plan.limits.max_elapsed_ms
            ):
                self._soft_deadline_exceeded = True
                self._note(Reason.LIMIT_EXCEEDED)
        except _LimitStop:
            raise
        except IdentityMismatch as exc:
            self._diagnose("query", exc)
            outcome = UnknownOwnership(detail=Reason.UNKNOWN_OWNERSHIP)
        except Exception as exc:  # noqa: BLE001 - cleanup finally, propagate bugs
            self._diagnose("query", exc)
            raise
        self._handle_outcome(key, state, slot, elapsed_ms, outcome)

    def _poll_lifecycle(self, slot: int) -> None:
        try:
            pending = self._source.pending_bindings()
        except Exception as exc:  # noqa: BLE001 - no dynamic admission
            self._diagnose("owner_admission", exc)
            self._note(Reason.QUERY_FAILED)
            return
        try:
            has_pending = bool(pending)
        except Exception as exc:  # noqa: BLE001
            self._diagnose("owner_admission", exc)
            self._note(Reason.QUERY_FAILED)
            return
        if has_pending:
            self._note(Reason.FOREIGN_BINDING)

    # -- main loop ---------------------------------------------------------------

    def run(self) -> SamplingResult:
        plan = self._plan
        hard_deadline = HardDeadlineStatus.NOT_REQUESTED
        if plan.hard_deadline_required:
            if "hard_deadline" in self._source.capabilities:
                hard_deadline = HardDeadlineStatus.ENFORCED
            else:
                hard_deadline = HardDeadlineStatus.UNSUPPORTED
                self._note(Reason.HARD_DEADLINE_UNSUPPORTED)
        t0 = self._clock.monotonic_ms()
        self._t0_ms = t0
        stopped_early = False
        try:
            for slot in range(plan.expected_slots):
                if self._cancelled():
                    self._cancel_active()
                    stopped_early = True
                    break
                elapsed = self._clock.monotonic_ms() - t0
                if elapsed < 0:
                    elapsed = 0
                if elapsed > plan.limits.max_elapsed_ms:
                    self._note(Reason.LIMIT_EXCEEDED)
                    stopped_early = True
                    break
                deadline = t0 + slot * plan.cadence_ms
                if not self._clock.wait_until(deadline, self._cancelled):
                    self._cancel_active()
                    stopped_early = True
                    break
                now = self._clock.monotonic_ms()
                elapsed = max(0, now - t0)
                if elapsed > plan.limits.max_elapsed_ms:
                    self._note(Reason.LIMIT_EXCEEDED)
                    stopped_early = True
                    break
                self._poll_lifecycle(slot)
                if now > deadline + plan.limits.slot_lateness_ms:
                    for key in self._order:
                        state = self._streams[key]
                        if state.dead or state.admit_slot > slot:
                            continue
                        self._emit(
                            self._gap_record(
                                state, slot, elapsed,
                                LifecycleCode.SLOT_MISSED,
                                detail=Reason.SLOT_MISSED,
                            )
                        )
                        if self._sink_dead or self._output_truncated:
                            break
                    self._note(Reason.SLOT_MISSED)
                else:
                    for key in self._order:
                        state = self._streams[key]
                        if state.dead or state.admit_slot > slot:
                            continue
                        self._sample_stream(key, state, slot, elapsed)
                        if (
                            self._sink_dead
                            or self._output_truncated
                            or self._soft_deadline_exceeded
                        ):
                            break
                elapsed_after_work = self._clock.monotonic_ms() - t0
                if elapsed_after_work > plan.limits.max_elapsed_ms:
                    self._soft_deadline_exceeded = True
                    self._note(Reason.LIMIT_EXCEEDED)
                if (
                    self._sink_dead
                    or self._output_truncated
                    or self._soft_deadline_exceeded
                ):
                    stopped_early = True
                    break
        except _LimitStop:
            stopped_early = True
        if self._sink_dead:
            pass
        elif self._output_truncated:
            self._truncate_terminals()
        elif stopped_early and self._cancelled():
            pass
        elif not stopped_early:
            self._complete_terminals()
        return self._finish(hard_deadline, stopped_early)

    def _elapsed_now(self) -> int:
        return max(0, self._clock.monotonic_ms() - self._t0_ms)

    def _cancel_active(self) -> None:
        elapsed = self._elapsed_now()
        for key in self._order:
            state = self._streams[key]
            if state.dead:
                continue
            accepted = self._emit(
                self._terminal_record(
                    state, elapsed, LifecycleCode.CANCELLATION,
                    detail=Reason.CANCELLED,
                )
            )
            if accepted:
                self._kill_stream(state, LifecycleCode.CANCELLATION)
            elif self._sink_dead or self._output_truncated:
                break
        self._note(Reason.CANCELLED)

    def _truncate_terminals(self) -> None:
        elapsed = self._elapsed_now()
        for key in self._order:
            state = self._streams[key]
            if state.dead:
                continue
            accepted = self._emit(
                self._terminal_record(
                    state,
                    elapsed,
                    LifecycleCode.OUTPUT_TRUNCATION,
                    detail=Reason.SINK_TRUNCATED,
                )
            )
            if accepted:
                self._kill_stream(state, LifecycleCode.OUTPUT_TRUNCATION)
            if self._sink_dead or not accepted:
                break
        self._note(Reason.SINK_TRUNCATED)

    def _complete_terminals(self) -> None:
        elapsed = self._elapsed_now()
        for key in self._order:
            state = self._streams[key]
            if state.dead:
                continue
            accepted = self._emit(
                self._terminal_record(
                    state, elapsed, LifecycleCode.RUN_COMPLETE
                )
            )
            if accepted:
                self._kill_stream(state, LifecycleCode.RUN_COMPLETE)
            else:
                break

    def _finish(
        self, hard_deadline: str, stopped_early: bool
    ) -> SamplingResult:
        try:
            raw_footprint = self._source.sampler_footprint()
        except Exception as exc:  # noqa: BLE001 - diagnostics are redacted
            self._diagnose("footprint", exc)
            raw_footprint = None
        footprint_values: Dict[str, Optional[int]] = {}
        footprint_valid = isinstance(raw_footprint, SamplerFootprint)
        if not footprint_valid:
            self._diagnose("footprint", ValueError())
        for name in (
            "working_set_bytes",
            "private_commit_bytes",
            "handle_count",
        ):
            value: Any = None
            if footprint_valid:
                try:
                    value = getattr(raw_footprint, name)
                except Exception as exc:  # noqa: BLE001
                    self._diagnose("footprint", exc)
                    value = None
            if value is not None and (
                type(value) is not int or value < 0
            ):
                self._diagnose("footprint", ValueError())
                value = None
            footprint_values[name] = value
        footprint = SamplerFootprint(**footprint_values)
        cleanup, cleanup_detail = self._cleanup()
        complete = (
            not stopped_early
            and not self._sink_dead
            and not self._output_truncated
            and self._missed == 0
            and self._query_failed == 0
            and self._samples + self._accepted_gap_slots == self._expected
            and self._accepted_terminals == len(self._streams)
            and not self._reasons
        )
        missing = self._expected - self._samples - self._accepted_gap_slots
        if missing < 0 or sum(self._accepted_gaps_by_reason.values()) != self._accepted_gap_slots:
            raise SamplingError("collector: obligation arithmetic failed")
        return SamplingResult(
            schema=SCHEMA_ID,
            plan_id=self._plan.plan_id,
            plan_digest=self._plan.plan_digest,
            run_ref=self._plan.run_ref,
            expected_samples=self._expected,
            accepted_samples=self._samples,
            accepted_gap_slots=self._accepted_gap_slots,
            accepted_gaps_by_reason=dict(self._accepted_gaps_by_reason),
            accepted_lifecycle_records=self._accepted_lifecycle_records,
            accepted_terminals=self._accepted_terminals,
            missing_obligations=missing,
            failed_writes=self._failed_writes,
            emitted_records=self._emitted_records,
            missed_slots=self._missed,
            query_failed=self._query_failed,
            valid_prefix_records=self._valid_prefix,
            transport_digest=self._transport.hexdigest(),
            semantic_digest=self._semantic.hexdigest(),
            completeness=(
                Completeness.COMPLETE if complete else Completeness.INCOMPLETE
            ),
            completeness_reasons=tuple(self._reasons),
            handle_cleanup=cleanup,
            handle_cleanup_detail=cleanup_detail,
            hard_deadline=hard_deadline,
            sampler_footprint=footprint,
            streams=tuple(
                StreamSummary(
                    stream_key=key,
                    emitted=self._streams[key].emitted,
                    missed=self._streams[key].missed,
                    query_failed=self._streams[key].query_failed,
                    terminal_code=self._streams[key].terminal_code,
                )
                for key in self._order
            ),
            sink_error=self._sink_error,
            diagnostics=self._diagnostic_summary(),
        )

    def _cleanup(self) -> Tuple[str, Optional[str]]:
        if self._cleanup_done:
            return self._cleanup_result
        self._cleanup_done = True
        owned = [
            s.target
            for s in self._streams.values()
            if s.target is not None and s.sampler_owned_target
        ]
        if not owned:
            self._cleanup_result = (
                HandleCleanupStatus.NONE_OWNED,
                None,
            )
            return self._cleanup_result
        failures = 0
        for target in owned:
            try:
                self._source.release(target)
            except Exception as exc:  # noqa: BLE001 - cleanup must not raise
                failures += 1
                self._diagnose("cleanup", exc)
        if failures:
            self._cleanup_result = (
                HandleCleanupStatus.PARTIAL,
                Reason.QUERY_FAILED,
            )
        else:
            self._cleanup_result = (
                HandleCleanupStatus.OK,
                None,
            )
        return self._cleanup_result


class _LimitStop(Exception):
    pass


def collect_samples(
    plan: Any,
    process_source: ProcessSource,
    clock: SampleClock,
    sink: RecordSink,
    cancellation: Any = None,
) -> SamplingResult:
    """Run the injected sampling loop and stream versioned records.

    ``plan`` is validated closed; every declared slot binds to a sample or
    an explicit gap record per active stream, and stopping early never
    lowers the expected denominator. The monotonic schedule comes from
    ``clock``; lateness yields missed slots, never backdated catch-up.
    Cancellation stops querying and releases sampler-owned handles only; it
    never terminates a sampled process. Only adapter-declared query bounds
    are honored — an unmet hard deadline is reported, never falsely
    claimed. Unexpected adapter bugs propagate after owned-handle cleanup;
    the sink prefix written so far stays valid.
    """
    validated = validate_sampling_plan(plan)
    cancelled = _as_cancel_flag(cancellation)
    collector = _Collector(validated, process_source, clock, sink, cancelled)
    try:
        return collector.run()
    finally:
        collector._cleanup()


# ---------------------------------------------------------------------------
# Windows live query adapter (ctypes FFI; loads DLLs only when constructed)
# ---------------------------------------------------------------------------

_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_SYNCHRONIZE = 0x00100000
_PROCESS_READ_ONLY_RIGHTS = (
    _PROCESS_QUERY_LIMITED_INFORMATION | _SYNCHRONIZE
)
_ERROR_ACCESS_DENIED = 5
_WAIT_OBJECT_0 = 0x00000000
_WAIT_TIMEOUT = 0x00000102
_WAIT_FAILED = 0xFFFFFFFF
_TH32CS_SNAPTHREAD = 0x00000004
_MAX_IMAGE_CHARS = 32768


def _load_windows_apis() -> Any:
    """Load kernel32/psapi with exact signatures (Windows live path only)."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)

    class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
            ("PrivateUsage", ctypes.c_size_t),
        ]

    class FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD),
                    ("dwHighDateTime", wintypes.DWORD)]

    class THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    kernel32.OpenProcess.argtypes = (
        wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetProcessHandleCount.argtypes = (
        wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    kernel32.GetProcessHandleCount.restype = wintypes.BOOL
    kernel32.GetProcessTimes.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME))
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.GetProcessId.argtypes = (wintypes.HANDLE,)
    kernel32.GetProcessId.restype = wintypes.DWORD
    kernel32.QueryFullProcessImageNameW.argtypes = (
        wintypes.HANDLE, wintypes.DWORD,
        wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD))
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.GetExitCodeProcess.argtypes = (
        wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = (
        wintypes.HANDLE, wintypes.DWORD)
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetCurrentProcess.argtypes = ()
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CreateToolhelp32Snapshot.argtypes = (
        wintypes.DWORD, wintypes.DWORD)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Thread32First.argtypes = (
        wintypes.HANDLE, ctypes.POINTER(THREADENTRY32))
    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = (
        wintypes.HANDLE, ctypes.POINTER(THREADENTRY32))
    kernel32.Thread32Next.restype = wintypes.BOOL
    psapi.GetProcessMemoryInfo.argtypes = (
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD)
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

    apis = {
        "ctypes": ctypes,
        "wintypes": wintypes,
        "kernel32": kernel32,
        "psapi": psapi,
        "PMCEX": PROCESS_MEMORY_COUNTERS_EX,
        "FILETIME": FILETIME,
        "THREADENTRY32": THREADENTRY32,
    }
    return apis


def _filetime_to_int(creation: Any) -> int:
    return (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)


@dataclass
class _WindowsTarget(PreparedTarget):
    receipt: Optional[AdmittedProcessBinding] = None
    handle: Optional[int] = None
    open_error: Optional[int] = None

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "receipt" and "receipt" in self.__dict__:
            raise AttributeError("Windows target receipt is immutable")
        object.__setattr__(self, name, value)


class WindowsQueryAdapter(ProcessSource):
    """Live Windows query engine behind an owner-supplied process source.

    Opens each admitted PID with only the query-limited and synchronization
    rights required by the read-only APIs and zero-time retained-handle wait.
    It verifies the exact PID, creation time, image and issuer-bound receipt
    before and after every counter read. A PID alone never authorizes access.

    Counter mapping (per MSDN): ``WorkingSetSize`` is current working-set
    bytes; ``PrivateUsage`` is private committed bytes, not private resident
    bytes; handle count comes from ``GetProcessHandleCount``. Optional
    ``cpu_time_ms`` derives from ``GetProcessTimes`` kernel+user time and
    ``thread_count`` from a thread snapshot; both only when the plan
    declares them. Any failed counter is unknown with its API error, never
    zero. No ``hard_deadline`` capability is claimed: a deadline check after
    a blocking native call cannot preempt it, so the sampler reports that
    explicitly.
    """

    capabilities: Tuple[str, ...] = (
        "identity_readback",
        "opt_cpu_time_ms",
        "opt_thread_count",
    )

    def __init__(
        self,
        optional_counters: Sequence[str] = (),
        owner_handoff: Optional[Callable[[ProcessBinding], Any]] = None,
    ) -> None:
        if sys.platform != "win32":
            raise AdapterUnavailable(
                f"{Reason.ADAPTER_UNAVAILABLE}: live Windows query path "
                f"requires win32 (running on {sys.platform}); validation, "
                "encoding, and injected-fixture sampling remain usable"
            )
        self._apis = _load_windows_apis()
        allowed = {c.value for c in OPTIONAL_COUNTERS}
        for name in optional_counters:
            if name not in allowed:
                raise AdapterUnavailable(
                    f"optional counter {name!r} is not supported"
                )
        self._optional = tuple(optional_counters)
        self._owner_handoff = owner_handoff
        self._owned_handle_by_target: Dict[int, int] = {}

    # -- ProcessSource protocol ----------------------------------------------

    def admit_binding(
        self, expected: ProcessBinding
    ) -> AdmittedProcessBinding:
        if self._owner_handoff is None:
            raise IdentityUnavailable()
        if not isinstance(expected, ProcessBinding):
            raise IdentityUnavailable()
        try:
            expected = _validate_binding(expected.to_dict(), 0)
        except (PlanRejected, TypeError, ValueError):
            raise IdentityUnavailable() from None
        try:
            observation = self._owner_handoff(expected)
        except Exception as exc:  # noqa: BLE001 - do not infer identity
            raise IdentityUnavailable() from exc
        return self._mint_admitted_binding(expected, observation)

    def prepare(self, receipt: AdmittedProcessBinding) -> PreparedTarget:
        binding = self._require_admitted_binding(receipt)
        target = _WindowsTarget(
            binding=binding, receipt=receipt, owned_handle=False
        )
        self._reopen(target)
        return target

    def attach_verified_handle(
        self, receipt: AdmittedProcessBinding, handle: int
    ) -> PreparedTarget:
        """Consume a same-process/duplicated handle supplied in-process.

        Precondition: the caller (the #944 owner adapter) guarantees the
        integer is a valid handle in this process. It is still verified
        against the trusted owner identity before use, and it is never
        closed here: ownership stays with the supplier.
        """
        binding = self._require_admitted_binding(receipt)
        if isinstance(handle, bool) or not isinstance(handle, int) or handle <= 0:
            raise IdentityUnavailable()
        target = _WindowsTarget(
            binding=binding,
            receipt=receipt,
            owned_handle=False,
            handle=int(handle),
        )
        self._verify(target)
        return target

    def query(self, target: PreparedTarget, context: QueryContext) -> Any:
        if not isinstance(target, _WindowsTarget):
            return UnknownOwnership(detail=Reason.UNKNOWN_OWNERSHIP)
        try:
            self._require_target_receipt(target)
        except IdentityUnavailable:
            return UnknownOwnership(detail=Reason.UNKNOWN_OWNERSHIP)
        if target.handle is None:
            self._reopen(target)
        if target.handle is None:
            return UnknownOwnership(detail=Reason.UNKNOWN_OWNERSHIP)
        try:
            self._verify(target)
        except IdentityMismatch as exc:
            return self._identity_outcome(exc)
        except Exception:
            return UnknownOwnership(detail=Reason.UNKNOWN_OWNERSHIP)
        before = self._terminal_state(target)
        if before is not None:
            return before
        try:
            counters = self._read_counters(target)
            self._verify(target)
        except IdentityMismatch as exc:
            return self._identity_outcome(exc)
        except Exception:
            return UnknownOwnership(detail=Reason.UNKNOWN_OWNERSHIP)
        after = self._terminal_state(target)
        if after is not None:
            return after
        return counters

    def sampler_footprint(self) -> SamplerFootprint:
        apis = self._apis
        current = apis["kernel32"].GetCurrentProcess()
        working = self._memory_value(current, "WorkingSetSize")
        private = self._memory_value(current, "PrivateUsage")
        handles = self._handle_count_value(current)
        return SamplerFootprint(
            working_set_bytes=working,
            private_commit_bytes=private,
            handle_count=handles,
        )

    def release(self, target: PreparedTarget) -> None:
        if not isinstance(target, _WindowsTarget):
            return
        owned_handles = getattr(self, "_owned_handle_by_target", {})
        handle = owned_handles.pop(id(target), None)
        if handle is None:
            return
        apis = self._apis
        target.handle = None
        target.owned_handle = False
        if not apis["kernel32"].CloseHandle(handle):
            raise AdapterUnavailable(Reason.QUERY_FAILED)

    # -- internals ---------------------------------------------------------------

    def _reopen(self, target: _WindowsTarget) -> None:
        binding = self._require_target_receipt(target)
        owned_handles = getattr(self, "_owned_handle_by_target", None)
        if owned_handles is None:
            owned_handles = {}
            self._owned_handle_by_target = owned_handles
        existing = owned_handles.get(id(target))
        if existing is not None:
            target.handle = existing
            target.owned_handle = True
            return
        apis = self._apis
        handle = apis["kernel32"].OpenProcess(
            _PROCESS_READ_ONLY_RIGHTS, False, binding.pid
        )
        if not handle:
            target.handle = None
            target.open_error = apis["ctypes"].get_last_error()
            return
        handle_value = int(handle)
        target.handle = handle_value
        target.owned_handle = True
        owned_handles[id(target)] = handle_value
        target.open_error = None

    def _require_target_receipt(
        self, target: _WindowsTarget
    ) -> ProcessBinding:
        receipt = target.receipt
        if receipt is None or target.binding != receipt.binding:
            raise IdentityUnavailable()
        return self._require_admitted_binding(receipt, target.binding)

    def _actual_pid(self, target: _WindowsTarget) -> int:
        if target.handle is None:
            raise IdentityMismatch(Reason.UNKNOWN_OWNERSHIP)
        pid = int(self._apis["kernel32"].GetProcessId(target.handle))
        if pid == 0:
            raise IdentityMismatch(Reason.UNKNOWN_OWNERSHIP)
        return pid

    def _readback_identity(self, target: _WindowsTarget) -> Tuple[str, str]:
        apis = self._apis
        ctypes = apis["ctypes"]
        kernel32 = apis["kernel32"]
        creation = apis["FILETIME"]()
        exit_t = apis["FILETIME"]()
        kernel_t = apis["FILETIME"]()
        user_t = apis["FILETIME"]()
        if not kernel32.GetProcessTimes(
            target.handle, creation, exit_t, kernel_t, user_t
        ):
            raise SamplingError(
                f"{Reason.QUERY_FAILED}:GetProcessTimes:"
                f"{ctypes.get_last_error()}"
            )
        size = apis["wintypes"].DWORD(_MAX_IMAGE_CHARS)
        buf = ctypes.create_unicode_buffer(_MAX_IMAGE_CHARS)
        if not kernel32.QueryFullProcessImageNameW(
            target.handle, 0, buf, ctypes.byref(size)
        ):
            raise SamplingError(
                f"{Reason.QUERY_FAILED}:QueryFullProcessImageNameW:"
                f"{ctypes.get_last_error()}"
            )
        return format(_filetime_to_int(creation), "016x"), buf.value

    def _verify(self, target: _WindowsTarget) -> None:
        binding = self._require_target_receipt(target)
        actual_pid = self._actual_pid(target)
        if actual_pid != binding.pid:
            raise IdentityMismatch(Reason.UNKNOWN_OWNERSHIP)
        creation, image = self._readback_identity(target)
        if creation != binding.creation_identity:
            raise IdentityMismatch(Reason.CREATION_MISMATCH)
        if image != binding.image_identity:
            raise IdentityMismatch(Reason.IMAGE_MISMATCH)

    def _identity_outcome(self, mismatch: IdentityMismatch) -> Any:
        if mismatch.reason in (Reason.CREATION_MISMATCH, Reason.IMAGE_MISMATCH):
            return ProcessReplacement()
        return UnknownOwnership(detail=Reason.UNKNOWN_OWNERSHIP)

    def _terminal_state(self, target: _WindowsTarget) -> Optional[Any]:
        try:
            self._require_target_receipt(target)
        except IdentityUnavailable:
            return UnknownOwnership(detail=Reason.UNKNOWN_OWNERSHIP)
        if target.handle is None:
            return UnknownOwnership(detail=Reason.UNKNOWN_OWNERSHIP)
        try:
            status = int(
                self._apis["kernel32"].WaitForSingleObject(target.handle, 0)
            )
        except Exception:
            return UnknownOwnership(detail=Reason.UNKNOWN_OWNERSHIP)
        if status == _WAIT_TIMEOUT:
            return None
        if status == _WAIT_OBJECT_0:
            code = self._apis["wintypes"].DWORD()
            try:
                ok = self._apis["kernel32"].GetExitCodeProcess(
                    target.handle, self._apis["ctypes"].byref(code)
                )
            except Exception:
                return UnknownOwnership(detail=Reason.UNKNOWN_OWNERSHIP)
            if not ok:
                return UnknownOwnership(detail=Reason.UNKNOWN_OWNERSHIP)
            return ProcessExit(exit_code=int(code.value))
        if status == _WAIT_FAILED:
            return UnknownOwnership(detail=Reason.UNKNOWN_OWNERSHIP)
        return UnknownOwnership(detail=Reason.UNKNOWN_OWNERSHIP)

    def _classify_absence(self, target: _WindowsTarget) -> Any:
        try:
            self._verify(target)
        except IdentityMismatch as exc:
            return self._identity_outcome(exc)
        except Exception:
            return UnknownOwnership(detail=Reason.UNKNOWN_OWNERSHIP)
        return UnknownOwnership(detail=Reason.UNKNOWN_OWNERSHIP)

    def _unknown_reading(self, name: str, api_error: Optional[int]) -> CounterReading:
        reason = Reason.ACCESS_DENIED if api_error == _ERROR_ACCESS_DENIED else Reason.QUERY_FAILED
        return CounterReading(
            name=name,
            value=None,
            unit=COUNTER_UNITS[name],
            status=CounterStatus.UNKNOWN,
            reason=reason,
            api_error=api_error,
        )

    def _unknown_all(self, api_error: Optional[int]) -> SampleCounters:
        return SampleCounters(
            readings=tuple(
                self._unknown_reading(name.value, api_error)
                for name in REQUIRED_COUNTERS
            )
        )

    def _memory_value(self, handle: int, field_name: str) -> Optional[int]:
        apis = self._apis
        counters = apis["PMCEX"]()
        counters.cb = apis["ctypes"].sizeof(counters)
        if not apis["psapi"].GetProcessMemoryInfo(
            handle, apis["ctypes"].byref(counters), counters.cb
        ):
            return None
        return int(getattr(counters, field_name))

    def _handle_count_value(self, handle: int) -> Optional[int]:
        apis = self._apis
        count = apis["wintypes"].DWORD()
        if not apis["kernel32"].GetProcessHandleCount(
            handle, apis["ctypes"].byref(count)
        ):
            return None
        return int(count.value)

    def _cpu_time_ms(self, handle: int) -> Optional[int]:
        apis = self._apis
        creation = apis["FILETIME"]()
        exit_t = apis["FILETIME"]()
        kernel_t = apis["FILETIME"]()
        user_t = apis["FILETIME"]()
        if not apis["kernel32"].GetProcessTimes(
            handle, creation, exit_t, kernel_t, user_t
        ):
            return None
        total_100ns = _filetime_to_int(kernel_t) + _filetime_to_int(user_t)
        return total_100ns // 10000

    def _thread_count(self, pid: int) -> Optional[int]:
        apis = self._apis
        ctypes = apis["ctypes"]
        snapshot = apis["kernel32"].CreateToolhelp32Snapshot(
            _TH32CS_SNAPTHREAD, 0
        )
        if int(snapshot) == -1:
            return None
        try:
            entry = apis["THREADENTRY32"]()
            entry.dwSize = ctypes.sizeof(entry)
            if not apis["kernel32"].Thread32First(snapshot, ctypes.byref(entry)):
                return None
            count = 0
            while True:
                if int(entry.th32OwnerProcessID) == pid:
                    count += 1
                if not apis["kernel32"].Thread32Next(
                    snapshot, ctypes.byref(entry)
                ):
                    break
            return count
        finally:
            apis["kernel32"].CloseHandle(snapshot)

    def _read_counters(self, target: _WindowsTarget) -> SampleCounters:
        apis = self._apis
        assert target.handle is not None
        readings: List[CounterReading] = []
        working = self._memory_value(target.handle, "WorkingSetSize")
        private = self._memory_value(target.handle, "PrivateUsage")
        memory_error: Optional[int] = None
        if working is None or private is None:
            memory_error = apis["ctypes"].get_last_error()
        if working is None:
            readings.append(self._unknown_reading(
                CounterName.WORKING_SET_BYTES, memory_error))
        else:
            readings.append(CounterReading(
                CounterName.WORKING_SET_BYTES, working,
                CounterUnit.BYTES, CounterStatus.OK))
        if private is None:
            readings.append(self._unknown_reading(
                CounterName.PRIVATE_COMMIT_BYTES, memory_error))
        else:
            readings.append(CounterReading(
                CounterName.PRIVATE_COMMIT_BYTES, private,
                CounterUnit.BYTES, CounterStatus.OK))
        handles = self._handle_count_value(target.handle)
        if handles is None:
            readings.append(self._unknown_reading(
                CounterName.HANDLE_COUNT, apis["ctypes"].get_last_error()))
        else:
            readings.append(CounterReading(
                CounterName.HANDLE_COUNT, handles,
                CounterUnit.COUNT, CounterStatus.OK))
        if CounterName.CPU_TIME_MS in self._optional:
            cpu = self._cpu_time_ms(target.handle)
            if cpu is None:
                readings.append(self._unknown_reading(
                    CounterName.CPU_TIME_MS, apis["ctypes"].get_last_error()))
            else:
                readings.append(CounterReading(
                    CounterName.CPU_TIME_MS, cpu,
                    CounterUnit.MILLISECONDS, CounterStatus.OK))
        if CounterName.THREAD_COUNT in self._optional:
            binding = self._require_target_receipt(target)
            threads = self._thread_count(binding.pid)
            if threads is None:
                readings.append(self._unknown_reading(
                    CounterName.THREAD_COUNT, apis["ctypes"].get_last_error()))
            else:
                readings.append(CounterReading(
                    CounterName.THREAD_COUNT, threads,
                    CounterUnit.COUNT, CounterStatus.OK))
        return SampleCounters(readings=tuple(readings))


def create_windows_source(
    optional_counters: Sequence[str] = (),
    owner_handoff: Optional[Callable[[ProcessBinding], Any]] = None,
) -> WindowsQueryAdapter:
    """Construct the live Windows query adapter (win32 only).

    Raises :class:`AdapterUnavailable` on other platforms; validation,
    encoding, and injected-fixture sampling never touch this path.
    """
    return WindowsQueryAdapter(
        optional_counters=optional_counters, owner_handoff=owner_handoff
    )
