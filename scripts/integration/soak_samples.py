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
from dataclasses import dataclass
from enum import Enum
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
SCHEMA_VERSION = 1
SCHEMA_ID = "eliot.soak_samples/v1"

HANDOFF_IDENTITY_UNAVAILABLE = (
    "process identity unavailable: #944 must supply the validated "
    "owner observation/retained-handle handoff via the #907/#911 seam; "
    "PID alone never identifies the owned process"
)


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
        return "|".join(
            (self.owner_ref, self.component, str(self.pid), self.generation)
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "owner_ref": self.owner_ref,
            "component": self.component,
            "pid": self.pid,
            "creation_identity": self.creation_identity,
            "image_identity": self.image_identity,
            "generation": self.generation,
        }


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
    pid = _require_int(data["pid"], f"bindings[{index}].pid", minimum=1)
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
        max_processes=_require_int(data["max_processes"], "limits.max_processes", minimum=1, maximum=4096),
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
    "source_ref",
    "artifact_ref",
    "stream",
    "seq",
    "slot",
    "elapsed_ms",
    "phase_id",
    "workload_ref",
)
_STREAM_KEYS = ("owner_ref", "component", "pid", "generation")
_COUNTER_KEYS = ("name", "value", "unit", "status", "reason", "api_error")
_EVENT_KEYS = ("code", "detail", "handoff")


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
    _check_int(data["pid"], "stream.pid", minimum=1)
    _check_ref(data["generation"], "stream.generation")
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
        if not isinstance(detail, str) or not detail:
            raise _record_fail("event.detail: must be a non-empty string")
        if len(detail) > _MAX_REASON_DETAIL_LEN:
            raise _record_fail("event.detail: exceeds bound")
        out["detail"] = detail
    if "handoff" in data:
        handoff = data["handoff"]
        if not isinstance(handoff, str) or not handoff:
            raise _record_fail("event.handoff: must be a non-empty string")
        if len(handoff) > _MAX_REASON_DETAIL_LEN:
            raise _record_fail("event.handoff: exceeds bound")
        out["handoff"] = handoff
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
    _validate_stream_key(data["stream"])
    _check_ref(data["run_ref"], "record.run_ref")
    _check_ref(data["plan_id"], "record.plan_id")
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
        if data["source_ref"] != plan.source_ref:
            raise _record_fail("record: source binding mismatch")
        if data["artifact_ref"] != plan.artifact_ref:
            raise _record_fail("record: artifact binding mismatch")
        if data["slot"] > plan.expected_slots or (
            data["slot"] == plan.expected_slots
            and kind != RecordKind.TERMINAL
        ):
            raise _record_fail("record: slot outside plan range")
        phase_ids = {p.phase_id for p in plan.phases}
        if data["phase_id"] not in phase_ids:
            raise _record_fail("record: unknown phase binding")
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
        _validate_event(data["event"])
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
    if len(data) > max_bytes:
        raise RecordRejected("record: transport body exceeds max_record_bytes")
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RecordRejected(f"record: transport body is not UTF-8: {exc}") from exc
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RecordRejected(f"record: invalid JSON: {exc}") from exc
    _check_json_bounds(obj, 0, [_MAX_JSON_KEYS])
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
        self._slot_digest: Dict[Tuple[str, int], str] = {}
        self._terminated: Dict[str, str] = {}

    @staticmethod
    def _key_of(stream: Mapping[str, Any]) -> str:
        return "|".join(
            (
                str(stream["owner_ref"]),
                str(stream["component"]),
                str(stream["pid"]),
                str(stream["generation"]),
            )
        )

    def observe(self, data: Any) -> Dict[str, Any]:
        normalized = validate_record(data, plan=self._plan)
        key = self._key_of(normalized["stream"])
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
        slot_id = (key, slot)
        if slot_id in self._slot_digest:
            if self._slot_digest[slot_id] != digest:
                raise StreamRejected(
                    f"stream {key}: conflicting content for slot {slot}"
                )
            raise StreamRejected(
                f"stream {key}: duplicate record for slot {slot}"
            )
        self._slot_digest[slot_id] = digest
        self._last_seq[key] = seq
        self._last_slot[key] = slot
        if normalized["kind"] == RecordKind.TERMINAL:
            self._terminated[key] = str(normalized["event"]["code"])
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

    def prepare(self, binding: ProcessBinding) -> PreparedTarget:
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
        """Write one record; return bytes accepted (short ⇒ truncation)."""
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
    run_ref: str
    expected_samples: int
    emitted_records: int
    missed_slots: int
    query_failed: int
    valid_prefix_records: int
    transport_digest: str
    semantic_digest: str
    completeness: str
    completeness_reasons: Tuple[str, ...]
    handle_cleanup: str
    handle_cleanup_detail: str
    hard_deadline: str
    sampler_footprint: SamplerFootprint
    streams: Tuple[StreamSummary, ...]
    sink_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "run_ref": self.run_ref,
            "expected_samples": self.expected_samples,
            "emitted_records": self.emitted_records,
            "missed_slots": self.missed_slots,
            "query_failed": self.query_failed,
            "valid_prefix_records": self.valid_prefix_records,
            "transport_digest": self.transport_digest,
            "semantic_digest": self.semantic_digest,
            "completeness": self.completeness,
            "completeness_reasons": list(self.completeness_reasons),
            "handle_cleanup": self.handle_cleanup,
            "handle_cleanup_detail": self.handle_cleanup_detail,
            "hard_deadline": self.hard_deadline,
            "sampler_footprint": self.sampler_footprint.to_dict(),
            "streams": [s.to_dict() for s in self.streams],
        }
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
    target: Optional[PreparedTarget] = None
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
        self._missed = 0
        self._query_failed = 0
        self._expected = 0
        self._reasons: List[str] = []
        self._sink_error: Optional[str] = None
        self._sink_dead = False
        self._updates_used = 0
        self._t0_ms = 0
        self._cleanup_done = False
        self._cleanup_result: Tuple[str, str] = (
            HandleCleanupStatus.NONE_OWNED,
            "cleanup not run",
        )
        for binding in plan.bindings:
            self._admit(binding, 0)

    # -- stream bookkeeping ------------------------------------------------

    def _admit(self, binding: ProcessBinding, slot: int) -> None:
        key = binding.stream_key()
        self._streams[key] = _StreamState(binding=binding, admit_slot=slot)
        self._order.append(key)
        self._expected += max(0, self._plan.expected_slots - slot)

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
        phase = self._phase_for(min(slot, plan.expected_slots - 1))
        record: Dict[str, Any] = {
            "schema": SCHEMA_ID,
            "kind": kind,
            "run_ref": plan.run_ref,
            "plan_id": plan.plan_id,
            "source_ref": plan.source_ref,
            "artifact_ref": plan.artifact_ref,
            "stream": {
                "owner_ref": state.binding.owner_ref,
                "component": state.binding.component,
                "pid": state.binding.pid,
                "generation": state.binding.generation,
            },
            "seq": state.seq,
            "slot": slot,
            "elapsed_ms": elapsed_ms,
            "phase_id": phase.phase_id,
            "workload_ref": phase.workload_ref,
            "wall_ms": self._clock.wall_ms(),
        }
        state.seq += 1
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
            event["detail"] = detail[:_MAX_REASON_DETAIL_LEN]
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
    ) -> Dict[str, Any]:
        record = self._base(state, RecordKind.LIFECYCLE, slot, elapsed_ms)
        event: Dict[str, Any] = {"code": code}
        if detail:
            event["detail"] = detail[:_MAX_REASON_DETAIL_LEN]
        if handoff:
            event["handoff"] = handoff[:_MAX_REASON_DETAIL_LEN]
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
            event["detail"] = detail[:_MAX_REASON_DETAIL_LEN]
        record["event"] = event
        return record

    # -- streaming emit ------------------------------------------------------

    def _emit(self, record: Dict[str, Any]) -> bool:
        """Validate, encode, and stream one record. False ⇒ sink failed."""
        normalized = self._validator.observe(record)
        transport = encode_transport(normalized)
        if len(transport) > self._plan.limits.max_record_bytes:
            self._sink_error = (
                f"sink_error=record_exceeds_max_record_bytes "
                f"slot={normalized['slot']} bytes={len(transport)}"
            )
            self._sink_dead = True
            return False
        if (
            self._sink.bytes_accepted + len(transport)
            > self._plan.limits.max_total_bytes
        ):
            self._sink_error = (
                "sink_error=max_total_bytes_exceeded "
                f"accepted={self._sink.bytes_accepted}"
            )
            self._sink_dead = True
            return False
        try:
            accepted = self._sink.write(transport)
        except (SinkError, OSError, ValueError) as exc:
            self._sink_error = f"sink_error=write_failed {exc}"[:_MAX_REF_LEN]
            self._sink_dead = True
            return False
        if accepted != len(transport):
            self._sink_error = (
                f"sink_error=short_write accepted={accepted} "
                f"expected={len(transport)}"
            )
            self._sink_dead = True
            return False
        self._transport.update(transport)
        self._semantic.update(encode_semantic(normalized))
        self._valid_prefix += 1
        self._emitted_records += 1
        return True

    def _kill_stream(self, state: _StreamState, code: str) -> None:
        state.dead = True
        state.terminal_code = code

    # -- per-slot work ---------------------------------------------------------

    def _ensure_prepared(
        self, key: str, state: _StreamState, slot: int, elapsed_ms: int
    ) -> bool:
        if state.prepared and state.target is not None:
            return True
        try:
            state.target = self._source.prepare(state.binding)
        except IdentityUnavailable as exc:
            self._emit(
                self._lifecycle_record(
                    state,
                    slot,
                    elapsed_ms,
                    LifecycleCode.IDENTITY_UNAVAILABLE,
                    detail=Reason.IDENTITY_UNAVAILABLE,
                    handoff=exc.handoff,
                )
            )
            self._kill_stream(state, LifecycleCode.IDENTITY_UNAVAILABLE)
            self._note(Reason.IDENTITY_UNAVAILABLE)
            return False
        except SamplingError as exc:
            self._emit(
                self._lifecycle_record(
                    state,
                    slot,
                    elapsed_ms,
                    LifecycleCode.QUERY_FAILURE,
                    detail=f"{Reason.ADAPTER_UNAVAILABLE}:{exc}"[
                        :_MAX_REASON_DETAIL_LEN
                    ],
                )
            )
            self._kill_stream(state, LifecycleCode.QUERY_FAILURE)
            self._note(Reason.ADAPTER_UNAVAILABLE)
            return False
        state.prepared = True
        return True

    def _note(self, reason: str) -> None:
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
            if self._samples >= self._plan.limits.max_samples_total:
                self._note(Reason.LIMIT_EXCEEDED)
                raise _LimitStop()
            self._emit(self._sample_record(state, slot, elapsed_ms, outcome))
            state.emitted += 1
            self._samples += 1
        elif isinstance(outcome, ProcessExit):
            detail = Reason.PROCESS_EXITED
            if outcome.exit_code is not None:
                detail += f":exit_code={outcome.exit_code}"
            self._emit(
                self._lifecycle_record(
                    state, slot, elapsed_ms, LifecycleCode.PROCESS_EXIT,
                    detail=detail,
                )
            )
            state.emitted += 1
            self._kill_stream(state, LifecycleCode.PROCESS_EXIT)
            self._note(Reason.PROCESS_EXITED)
        elif isinstance(outcome, ProcessReplacement):
            permitted = (
                "replace_generation" in self._plan.permitted_lifecycle_updates
            )
            budgeted = self._updates_used < self._plan.limits.max_lifecycle_updates
            if permitted and budgeted:
                self._updates_used += 1
                self._emit(
                    self._lifecycle_record(
                        state,
                        slot,
                        elapsed_ms,
                        LifecycleCode.PROCESS_REPLACEMENT,
                        detail=Reason.PROCESS_REPLACED,
                    )
                )
                state.emitted += 1
                self._kill_stream(state, LifecycleCode.PROCESS_REPLACEMENT)
                self._note(Reason.PROCESS_REPLACED)
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
                state.emitted += 1
                self._kill_stream(
                    state, LifecycleCode.LIFECYCLE_UPDATE_REJECTED
                )
                self._note(why)
        elif isinstance(outcome, QueryFailure):
            detail = outcome.reason
            if outcome.api_error is not None:
                detail += f":api_error={outcome.api_error}"
            if outcome.detail:
                detail += f":{outcome.detail}"
            self._emit(
                self._lifecycle_record(
                    state,
                    slot,
                    elapsed_ms,
                    LifecycleCode.QUERY_FAILURE,
                    detail=detail,
                )
            )
            state.emitted += 1
            state.query_failed += 1
            self._query_failed += 1
            self._note(Reason.QUERY_FAILED)
        elif isinstance(outcome, UnknownOwnership):
            self._emit(
                self._lifecycle_record(
                    state,
                    slot,
                    elapsed_ms,
                    LifecycleCode.UNKNOWN_OWNERSHIP,
                    detail=outcome.detail or Reason.UNKNOWN_OWNERSHIP,
                )
            )
            state.emitted += 1
            state.query_failed += 1
            self._query_failed += 1
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
            outcome = self._source.query(state.target, context)
        except IdentityMismatch as exc:
            outcome = UnknownOwnership(detail=f"identity_readback:{exc}"[
                :_MAX_REASON_DETAIL_LEN
            ])
        self._handle_outcome(key, state, slot, elapsed_ms, outcome)

    def _poll_lifecycle(self, slot: int) -> None:
        try:
            pending = self._source.pending_bindings()
        except SamplingError:
            self._note(Reason.QUERY_FAILED)
            return
        for binding in pending:
            if not isinstance(binding, ProcessBinding):
                self._note(Reason.FOREIGN_BINDING)
                continue
            key = binding.stream_key()
            if key in self._streams:
                self._note(Reason.FOREIGN_BINDING)
                continue
            same_process = [
                s
                for s in self._streams.values()
                if s.binding.owner_ref == binding.owner_ref
                and s.binding.component == binding.component
                and s.binding.pid == binding.pid
            ]
            continues_replacement = any(
                s.terminal_code == LifecycleCode.PROCESS_REPLACEMENT
                for s in same_process
            )
            need = (
                "replace_generation" if continues_replacement else "add_child"
            )
            if need not in self._plan.permitted_lifecycle_updates:
                self._note(Reason.LIFECYCLE_NOT_PERMITTED)
                continue
            if len(self._streams) >= self._plan.limits.max_processes:
                self._note(Reason.BUDGET_EXHAUSTED)
                continue
            if self._updates_used >= self._plan.limits.max_lifecycle_updates:
                self._note(Reason.BUDGET_EXHAUSTED)
                continue
            self._updates_used += 1
            self._admit(binding, slot)

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
                        state.missed += 1
                        self._missed += 1
                    self._note(Reason.SLOT_MISSED)
                else:
                    for key in self._order:
                        state = self._streams[key]
                        if state.dead or state.admit_slot > slot:
                            continue
                        self._sample_stream(key, state, slot, elapsed)
                        if self._sink_dead:
                            break
                if self._sink_dead:
                    stopped_early = True
                    break
        except _LimitStop:
            stopped_early = True
        if self._sink_dead:
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
            self._emit(
                self._terminal_record(
                    state, elapsed, LifecycleCode.CANCELLATION,
                    detail=Reason.CANCELLED,
                )
            )
            self._kill_stream(state, LifecycleCode.CANCELLATION)
        self._note(Reason.CANCELLED)

    def _truncate_terminals(self) -> None:
        reserve = self._plan.limits.terminal_reserve_records
        used = 0
        elapsed = self._elapsed_now()
        for key in self._order:
            if used >= reserve:
                break
            state = self._streams[key]
            if state.dead:
                continue
            record = self._terminal_record(
                state, elapsed, LifecycleCode.OUTPUT_TRUNCATION,
                detail=Reason.SINK_TRUNCATED,
            )
            try:
                normalized = self._validator.observe(record)
            except StreamRejected:
                continue
            try:
                blob = encode_transport(normalized)
                if self._sink.write(blob) == len(blob):
                    self._transport.update(blob)
                    self._semantic.update(encode_semantic(normalized))
                    self._valid_prefix += 1
                    self._emitted_records += 1
            except (SinkError, OSError, ValueError):
                continue
            used += 1
            self._kill_stream(state, LifecycleCode.OUTPUT_TRUNCATION)
        self._note(Reason.SINK_TRUNCATED)

    def _complete_terminals(self) -> None:
        elapsed = self._elapsed_now()
        for key in self._order:
            state = self._streams[key]
            if state.dead:
                continue
            self._emit(
                self._terminal_record(
                    state, elapsed, LifecycleCode.RUN_COMPLETE
                )
            )
            self._kill_stream(state, LifecycleCode.RUN_COMPLETE)

    def _finish(
        self, hard_deadline: str, stopped_early: bool
    ) -> SamplingResult:
        try:
            footprint = self._source.sampler_footprint()
        except Exception:
            footprint = SamplerFootprint()
        if not isinstance(footprint, SamplerFootprint):
            footprint = SamplerFootprint()
        cleanup, cleanup_detail = self._cleanup()
        complete = (
            not stopped_early
            and not self._sink_dead
            and self._missed == 0
            and self._query_failed == 0
            and self._samples == self._expected
            and not self._reasons
        )
        return SamplingResult(
            schema=SCHEMA_ID,
            plan_id=self._plan.plan_id,
            run_ref=self._plan.run_ref,
            expected_samples=self._expected,
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
        )

    def _cleanup(self) -> Tuple[str, str]:
        if self._cleanup_done:
            return self._cleanup_result
        self._cleanup_done = True
        owned = [
            s.target
            for s in self._streams.values()
            if s.target is not None and s.target.owned_handle
        ]
        if not owned:
            self._cleanup_result = (
                HandleCleanupStatus.NONE_OWNED,
                "no sampler-owned handles",
            )
            return self._cleanup_result
        failures: List[str] = []
        for target in owned:
            try:
                self._source.release(target)
            except Exception as exc:  # noqa: BLE001 - cleanup must not raise
                failures.append(f"{target.binding.stream_key()}:{exc}")
        if failures:
            detail = ";".join(failures)[:_MAX_REASON_DETAIL_LEN]
            self._cleanup_result = (HandleCleanupStatus.PARTIAL, detail)
        else:
            self._cleanup_result = (
                HandleCleanupStatus.OK,
                f"released {len(owned)} sampler-owned",
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
_ERROR_ACCESS_DENIED = 5
_STILL_ACTIVE = 259
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
    kernel32.QueryFullProcessImageNameW.argtypes = (
        wintypes.HANDLE, wintypes.DWORD,
        wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD))
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.GetExitCodeProcess.argtypes = (
        wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
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
    handle: Optional[int] = None
    open_error: Optional[int] = None


class WindowsQueryAdapter(ProcessSource):
    """Live Windows query engine behind an owner-supplied process source.

    Opens each bound PID with ``PROCESS_QUERY_LIMITED_INFORMATION`` only —
    never ALL_ACCESS, elevation, or memory-reading privileges — and verifies
    creation-time/image readback against the trusted owner binding before
    every query. A PID alone never identifies the owned process: without the
    owner-issued creation/image/generation identity there is nothing to
    verify against, and callers must surface identity-unavailable instead.

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

    def __init__(self, optional_counters: Sequence[str] = ()) -> None:
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

    # -- ProcessSource protocol ----------------------------------------------

    def prepare(self, binding: ProcessBinding) -> PreparedTarget:
        target = _WindowsTarget(binding=binding, owned_handle=True)
        self._reopen(target)
        return target

    def attach_verified_handle(
        self, binding: ProcessBinding, handle: int
    ) -> PreparedTarget:
        """Consume a same-process/duplicated handle supplied in-process.

        Precondition: the caller (the #944 owner adapter) guarantees the
        integer is a valid handle in this process. It is still verified
        against the trusted owner identity before use, and it is never
        closed here: ownership stays with the supplier.
        """
        target = _WindowsTarget(
            binding=binding, owned_handle=False, handle=int(handle)
        )
        self._verify(target)
        return target

    def query(self, target: PreparedTarget, context: QueryContext) -> Any:
        assert isinstance(target, _WindowsTarget)
        if target.handle is None:
            self._reopen(target)
        if target.handle is None:
            return self._unknown_all(target.open_error)
        try:
            self._verify(target)
        except IdentityMismatch:
            return self._classify_absence(target)
        return self._read_counters(target)

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
        assert isinstance(target, _WindowsTarget)
        if not target.owned_handle or target.handle is None:
            return
        apis = self._apis
        handle = target.handle
        target.handle = None
        if not apis["kernel32"].CloseHandle(handle):
            raise AdapterUnavailable(
                f"CloseHandle failed: {apis['ctypes'].get_last_error()}"
            )

    # -- internals ---------------------------------------------------------------

    def _reopen(self, target: _WindowsTarget) -> None:
        apis = self._apis
        handle = apis["kernel32"].OpenProcess(
            _PROCESS_QUERY_LIMITED_INFORMATION, False, target.binding.pid
        )
        if not handle:
            target.handle = None
            target.open_error = apis["ctypes"].get_last_error()
            return
        target.handle = int(handle)
        target.open_error = None

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
        creation, image = self._readback_identity(target)
        if creation != target.binding.creation_identity:
            raise IdentityMismatch(Reason.CREATION_MISMATCH)
        if image != target.binding.image_identity:
            raise IdentityMismatch(Reason.IMAGE_MISMATCH)

    def _classify_absence(self, target: _WindowsTarget) -> Any:
        apis = self._apis
        code = apis["wintypes"].DWORD()
        if apis["kernel32"].GetExitCodeProcess(target.handle, apis["ctypes"].byref(code)):
            if int(code.value) != _STILL_ACTIVE:
                return ProcessExit(exit_code=int(code.value))
        try:
            creation, image = self._readback_identity(target)
        except SamplingError:
            return UnknownOwnership(detail=Reason.QUERY_FAILED)
        return ProcessReplacement(
            observed_creation=creation[:_MAX_REF_LEN],
            observed_image=image[:_MAX_IMAGE_ID_LEN],
        )

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
            threads = self._thread_count(target.binding.pid)
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
) -> WindowsQueryAdapter:
    """Construct the live Windows query adapter (win32 only).

    Raises :class:`AdapterUnavailable` on other platforms; validation,
    encoding, and injected-fixture sampling never touch this path.
    """
    return WindowsQueryAdapter(optional_counters=optional_counters)
