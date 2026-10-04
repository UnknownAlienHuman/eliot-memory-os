"""Independent synthetic oracles for the bounded soak sampler schema v2."""

from __future__ import annotations

import copy
import ctypes
import hashlib
import json
import unittest
from ctypes import wintypes
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence
from unittest import mock

from scripts.integration import soak_samples as soak


_FIXTURE_DIR = (
    Path(__file__).resolve().parents[1]
    / "testdata"
    / "integration"
    / "soak-samples"
)
_PLAN_DIGEST = "cdb30adb30733352ea1dd9c25a74f82001b051e6510898d7ae9ad9920cdeaa10"
_BINDING_DIGEST = "5131f1b39627e8b84d65a32c015e8be0c98e3acceee830d2c612b67c0b12c2a8"
_IDENTITY_FIELDS = (
    "owner_ref",
    "component",
    "pid",
    "creation_identity",
    "image_identity",
    "generation",
)
_OWNER_OBSERVATION = {
    "owner_ref": "synthetic-owner-942",
    "component": "synthetic-component",
    "pid": 942,
    "creation_identity": "0000000000000942",
    "image_identity": "synthetic-approved-image-942",
    "generation": "synthetic-generation-1",
}
_REPLACEMENT_OWNER_OBSERVATION = {
    **_OWNER_OBSERVATION,
    "pid": 943,
    "creation_identity": "0000000000000943",
    "generation": "synthetic-generation-2",
}


def _read_fixture(name: str) -> dict[str, Any]:
    path = _FIXTURE_DIR / name
    return json.loads(path.read_text(encoding="utf-8"))


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _complete_identity(binding: Mapping[str, Any]) -> dict[str, Any]:
    return {name: binding[name] for name in _IDENTITY_FIELDS}


def _foreign_identity(
    binding: Mapping[str, Any], field: str
) -> dict[str, Any]:
    identity = _complete_identity(binding)
    if field == "pid":
        identity[field] += 1
    elif field == "creation_identity":
        identity[field] = "0000000000000943"
    elif field == "image_identity":
        identity[field] = "synthetic-approved-image-943"
    else:
        identity[field] = f"{identity[field]}-foreign"
    return identity


def _sample_record(
    plan: Any,
    slot: int,
    cases: Mapping[str, Any],
    *,
    counters: Optional[Sequence[Mapping[str, Any]]] = None,
    wall_ms: Optional[int] = None,
) -> dict[str, Any]:
    binding = plan.bindings[0]
    phase = next(
        phase
        for phase in plan.phases
        if phase.first_slot <= slot < plan.expected_slots
        and slot <= phase.last_slot
    )
    identity = binding.to_dict()
    row = {
        "schema": soak.SCHEMA_ID,
        "kind": soak.RecordKind.SAMPLE.value,
        "run_ref": plan.run_ref,
        "plan_id": plan.plan_id,
        "plan_digest": _sha256_json(plan.to_dict()),
        "source_ref": plan.source_ref,
        "artifact_ref": plan.artifact_ref,
        "stream": {
            "owner_ref": binding.owner_ref,
            "component": binding.component,
            "pid": binding.pid,
            "generation": binding.generation,
            "binding_digest": _sha256_json(_complete_identity(identity)),
        },
        "seq": slot,
        "slot": slot,
        "elapsed_ms": slot * plan.cadence_ms,
        "phase_id": phase.phase_id,
        "workload_ref": phase.workload_ref,
        "wall_ms": (
            cases["clock"]["wall_time_ms"][slot]
            if wall_ms is None
            else wall_ms
        ),
        "counters": copy.deepcopy(
            list(cases["counters_ok"] if counters is None else counters)
        ),
    }
    return row


def _terminal_record(plan: Any, cases: Mapping[str, Any]) -> dict[str, Any]:
    last_slot = plan.expected_slots - 1
    record = _sample_record(plan, last_slot, cases)
    record["kind"] = soak.RecordKind.TERMINAL.value
    record["slot"] = plan.expected_slots
    record.pop("counters")
    record["event"] = {"code": soak.LifecycleCode.RUN_COMPLETE.value}
    return record


def _record_from_payload(payload: bytes) -> dict[str, Any]:
    return json.loads(payload.decode("utf-8"))


def _accepted_records(sink: "_RecordingSink") -> list[dict[str, Any]]:
    return [_record_from_payload(payload) for payload in sink.full_ack_payloads]


def _semantic_digest(records: Sequence[Mapping[str, Any]]) -> str:
    digest = hashlib.sha256()
    for record in records:
        semantic = {key: value for key, value in record.items() if key != "wall_ms"}
        digest.update(_canonical_json(semantic))
        digest.update(b"\n")
    return digest.hexdigest()


def _counter_outcome(readings: Sequence[Mapping[str, Any]]) -> Any:
    return soak.SampleCounters(
        readings=tuple(soak.CounterReading(**copy.deepcopy(reading)) for reading in readings)
    )


class _ScriptedClock(soak.SampleClock):
    """Fixture clock: monotonic progress is independent of wall time."""

    def __init__(
        self,
        cases: Mapping[str, Any],
        *,
        late_slot: Optional[int] = None,
        lateness_ms: int = 0,
        wall_offset_ms: int = 0,
    ) -> None:
        self._clock = cases["clock"]
        self._late_slot = late_slot
        self._lateness_ms = lateness_ms
        self._wall_offset_ms = wall_offset_ms
        self._slot = 0
        self._waits = 0
        self._now = self._clock["monotonic_ms"][0]

    def monotonic_ms(self) -> int:
        return self._now

    def wall_ms(self) -> int:
        index = min(self._slot, len(self._clock["wall_time_ms"]) - 1)
        return self._clock["wall_time_ms"][index] + self._wall_offset_ms

    def wait_until(self, deadline_ms: int, cancelled: Any) -> bool:
        del deadline_ms
        index = min(self._waits, len(self._clock["monotonic_ms"]) - 1)
        self._waits += 1
        self._slot = index
        self._now = self._clock["monotonic_ms"][index]
        if index == self._late_slot:
            self._now += self._lateness_ms
        return not cancelled()


class _RecordingSink(soak.RecordSink):
    def __init__(
        self,
        *,
        partial_second_write: Optional[int] = None,
        invalid_ack: Optional[str] = None,
        underreport_bytes: bool = False,
    ) -> None:
        self.data = bytearray()
        self.attempts: list[bytes] = []
        self.acks: list[Any] = []
        self.partial_second_write = partial_second_write
        self.invalid_ack = invalid_ack
        self.underreport_bytes = underreport_bytes

    @property
    def bytes_accepted(self) -> int:
        return 0 if self.underreport_bytes else len(self.data)

    @property
    def full_ack_payloads(self) -> list[bytes]:
        return [
            payload
            for payload, ack in zip(self.attempts, self.acks)
            if type(ack) is int and ack == len(payload)
        ]

    def write(self, data: bytes) -> int:
        payload = bytes(data)
        self.attempts.append(payload)
        index = len(self.attempts)
        if self.partial_second_write is not None and index == 2:
            accepted = self.partial_second_write
            self.data.extend(payload[:accepted])
            self.acks.append(accepted)
            return accepted
        if self.invalid_ack == "float_full":
            self.data.extend(payload)
            ack: Any = float(len(payload))
        elif self.invalid_ack == "bool":
            self.data.extend(payload[:1])
            ack = True
        elif self.invalid_ack == "negative":
            ack = -1
        elif self.invalid_ack == "overshoot":
            self.data.extend(payload)
            ack = len(payload) + 1
        else:
            self.data.extend(payload)
            ack = len(payload)
        self.acks.append(ack)
        return ack


class _SyntheticProcessSource(soak.ProcessSource):
    """Independent synthetic owner observation; carries no live authority."""

    def __init__(
        self,
        plan_data: Mapping[str, Any],
        cases: Mapping[str, Any],
        outcomes: Optional[Mapping[int, Any]] = None,
        *,
        owner_observations: Optional[Sequence[Mapping[str, Any]]] = None,
        owned_handle: bool = True,
        capabilities: Sequence[str] = (),
        cancel_after_first_query: Any = None,
    ) -> None:
        self._plan_data = copy.deepcopy(plan_data)
        self._owner_observations = {}
        observations = (
            (_OWNER_OBSERVATION,)
            if owner_observations is None
            else owner_observations
        )
        for raw_binding in observations:
            binding = soak.ProcessBinding(**copy.deepcopy(raw_binding))
            self._owner_observations[binding.stream_key()] = binding
        self._cases = cases
        self._outcomes = dict(outcomes or {})
        self._owned_handle = owned_handle
        self.capabilities = tuple(capabilities)
        self.cancel_after_first_query = cancel_after_first_query
        self.queried_slots: list[int] = []
        self.prepared: list[Any] = []
        self.released: list[Any] = []
        self.termination_attempts = 0

    def admit_binding(self, expected: Any) -> Any:
        observation = self._owner_observations.get(expected.stream_key())
        if observation is None:
            raise soak.IdentityUnavailable()
        return self._mint_admitted_binding(expected, observation)

    def prepare(self, receipt: Any) -> Any:
        self._require_admitted_binding(receipt)
        target = soak.PreparedTarget(
            binding=receipt.binding,
            owned_handle=self._owned_handle,
        )
        self.prepared.append(target)
        return target

    def query(self, target: Any, context: Any) -> Any:
        del target
        self.queried_slots.append(context.slot)
        if self.cancel_after_first_query is not None and len(self.queried_slots) == 1:
            self.cancel_after_first_query.cancelled = True
        if context.slot in self._outcomes:
            return self._outcomes[context.slot]
        return _counter_outcome(self._cases["counters_ok"])

    def sampler_footprint(self) -> Any:
        return soak.SamplerFootprint()

    def release(self, target: Any) -> None:
        self.released.append(target)

    def terminate(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        self.termination_attempts += 1
        raise AssertionError("the sampler must never terminate sampled processes")


class _CancelFlag:
    def __init__(self) -> None:
        self.cancelled = False

    def __call__(self) -> bool:
        return self.cancelled


class SoakSamplesOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plan_data = _read_fixture("sampling_plan.json")
        cls.cases = _read_fixture("sampling_cases.json")

    def _plan(self, plan_data: Optional[Mapping[str, Any]] = None) -> Any:
        return soak.validate_sampling_plan(
            copy.deepcopy(self.plan_data if plan_data is None else plan_data)
        )

    def _source(
        self,
        plan_data: Optional[Mapping[str, Any]] = None,
        outcomes: Optional[Mapping[int, Any]] = None,
        *,
        owner_observations: Optional[Sequence[Mapping[str, Any]]] = None,
        owned_handle: bool = True,
        capabilities: Sequence[str] = (),
        cancel_after_first_query: Any = None,
    ) -> _SyntheticProcessSource:
        return _SyntheticProcessSource(
            self.plan_data if plan_data is None else plan_data,
            self.cases,
            outcomes,
            owner_observations=owner_observations,
            owned_handle=owned_handle,
            capabilities=capabilities,
            cancel_after_first_query=cancel_after_first_query,
        )

    def _windows_adapter(self, *, owner_handoff: Any = None) -> tuple[Any, Any]:
        kernel32 = mock.Mock()
        kernel32.OpenProcess = mock.Mock(return_value=942)
        kernel32.CloseHandle = mock.Mock(return_value=True)
        kernel32.GetProcessId = mock.Mock(return_value=942)
        psapi = mock.Mock()
        apis = {
            "kernel32": kernel32,
            "psapi": psapi,
            "ctypes": ctypes,
            "wintypes": wintypes,
        }
        with mock.patch.object(soak.sys, "platform", "win32"):
            with mock.patch.object(soak, "_load_windows_apis", return_value=apis):
                adapter = soak.WindowsQueryAdapter(owner_handoff=owner_handoff)
        return adapter, kernel32

    def _run(
        self,
        *,
        plan_data: Optional[Mapping[str, Any]] = None,
        outcomes: Optional[Mapping[int, Any]] = None,
        clock: Optional[_ScriptedClock] = None,
        sink: Optional[_RecordingSink] = None,
        source: Optional[_SyntheticProcessSource] = None,
        owner_observations: Optional[Sequence[Mapping[str, Any]]] = None,
        cancellation: Any = None,
        owned_handle: bool = True,
        capabilities: Sequence[str] = (),
    ) -> tuple[Any, _SyntheticProcessSource, _ScriptedClock, _RecordingSink, Any]:
        raw_plan = self.plan_data if plan_data is None else plan_data
        plan = self._plan(raw_plan)
        source = source or self._source(
            raw_plan,
            outcomes,
            owner_observations=owner_observations,
            owned_handle=owned_handle,
            capabilities=capabilities,
        )
        clock = clock or _ScriptedClock(self.cases)
        sink = sink or _RecordingSink()
        result = soak.collect_samples(plan, source, clock, sink, cancellation)
        return plan, source, clock, sink, result

    def _assert_foreign_identity_rejected(
        self, record: Mapping[str, Any], plan: Any, field: str
    ) -> None:
        forged = copy.deepcopy(record)
        identity = _foreign_identity(self.plan_data["bindings"][0], field)
        forged["stream"].update(
            {
                "owner_ref": identity["owner_ref"],
                "component": identity["component"],
                "pid": identity["pid"],
                "generation": identity["generation"],
                "binding_digest": _sha256_json(identity),
            }
        )
        with self.assertRaises(soak.RecordRejected):
            soak.validate_sample_record(forged, plan=plan)

    def _run_with_bad_ack(self, ack_kind: str) -> None:
        sink = _RecordingSink(invalid_ack=ack_kind)
        plan, _, _, _, result = self._run(sink=sink)
        self.assertEqual(len(sink.attempts), 1)
        self.assertEqual(result.valid_prefix_records, 0)
        self.assertEqual(result.accepted_samples, 0)
        self.assertEqual(result.failed_writes, 1)
        self.assertNotEqual(result.completeness, soak.Completeness.COMPLETE)
        self.assertEqual(
            result.transport_digest,
            hashlib.sha256(b"").hexdigest(),
        )
        self.assertEqual(result.expected_samples, plan.expected_slots)

    # WORK_UNIT_CASE: 942/1
    def test_case_01_closed_plan_has_finite_owned_bindings(self) -> None:
        plan = self._plan()
        self.assertEqual(plan.schema, "eliot.soak_samples/v2")
        self.assertEqual(plan.expected_slots, 6)
        self.assertEqual(plan.cadence_ms, 100)
        self.assertEqual(len(plan.bindings), 1)
        self.assertEqual(len(plan.bindings), len(self.plan_data["bindings"]))
        self.assertEqual(plan.bindings[0].to_dict(), self.plan_data["bindings"][0])

        extra_field = copy.deepcopy(self.plan_data)
        extra_field["unreviewed_input"] = "synthetic"
        with self.assertRaises(soak.PlanRejected):
            soak.validate_sampling_plan(extra_field)

        empty_process_set = copy.deepcopy(self.plan_data)
        empty_process_set["bindings"] = []
        with self.assertRaises(soak.PlanRejected):
            soak.validate_sampling_plan(empty_process_set)

    # WORK_UNIT_CASE: 942/2
    def test_case_02_foreign_reused_or_plan_rebound_identity_is_rejected(self) -> None:
        plan = self._plan()
        binding_preimage = _complete_identity(self.plan_data["bindings"][0])
        self.assertEqual(_complete_identity(_OWNER_OBSERVATION), binding_preimage)
        self.assertEqual(_sha256_json(binding_preimage), _BINDING_DIGEST)
        self.assertEqual(plan.bindings[0].binding_digest, _BINDING_DIGEST)
        self.assertEqual(_sha256_json(plan.to_dict()), _PLAN_DIGEST)
        self.assertEqual(plan.plan_digest, _PLAN_DIGEST)

        record = _sample_record(plan, 0, self.cases)
        self.assertEqual(record["stream"]["binding_digest"], _BINDING_DIGEST)
        self.assertEqual(record["plan_digest"], _PLAN_DIGEST)
        self.assertEqual(
            soak.validate_sample_record(record, plan=plan),
            record,
        )
        self._assert_foreign_identity_rejected(record, plan, "pid")
        self._assert_foreign_identity_rejected(record, plan, "creation_identity")
        self._assert_foreign_identity_rejected(record, plan, "image_identity")
        self._assert_foreign_identity_rejected(record, plan, "generation")
        self._assert_foreign_identity_rejected(record, plan, "owner_ref")
        self._assert_foreign_identity_rejected(record, plan, "component")

        altered_plan_data = copy.deepcopy(self.plan_data)
        altered_plan_data["cadence_ms"] += 1
        altered_plan = self._plan(altered_plan_data)
        self.assertEqual(altered_plan.plan_id, plan.plan_id)
        self.assertNotEqual(altered_plan.plan_digest, plan.plan_digest)
        with self.assertRaises(soak.RecordRejected):
            soak.validate_sample_record(record, plan=altered_plan)

        original = plan.bindings[0]
        for field in _IDENTITY_FIELDS:
            foreign_observation = _foreign_identity(
                self.plan_data["bindings"][0], field
            )
            source = self._source()
            source._owner_observations[original.stream_key()] = soak.ProcessBinding(
                **foreign_observation
            )
            with self.subTest(owner_observation_field=field):
                with self.assertRaises(soak.IdentityUnavailable):
                    source.admit_binding(original)

        duplicate_legacy_stream = copy.deepcopy(self.plan_data)
        duplicate_binding = copy.deepcopy(duplicate_legacy_stream["bindings"][0])
        duplicate_binding["creation_identity"] = "0000000000000000"
        duplicate_legacy_stream["bindings"].append(duplicate_binding)
        with self.assertRaises(soak.PlanRejected):
            self._plan(duplicate_legacy_stream)

        adapter_without_owner, kernel32 = self._windows_adapter()
        with self.assertRaises(soak.IdentityUnavailable):
            adapter_without_owner.admit_binding(original)
        with self.assertRaises(soak.IdentityUnavailable):
            adapter_without_owner.prepare(original)
        with self.assertRaises(soak.IdentityUnavailable):
            adapter_without_owner.attach_verified_handle(original, 942)
        kernel32.OpenProcess.assert_not_called()
        kernel32.GetProcessId.assert_not_called()

        for field in _IDENTITY_FIELDS:
            foreign_observation = _foreign_identity(
                self.plan_data["bindings"][0], field
            )
            adapter, kernel32 = self._windows_adapter(
                owner_handoff=lambda expected, observation=foreign_observation: soak.ProcessBinding(
                    **observation
                )
            )
            with self.subTest(adapter_observation_field=field):
                with self.assertRaises(soak.IdentityUnavailable):
                    adapter.admit_binding(original)
            kernel32.OpenProcess.assert_not_called()
            kernel32.GetProcessId.assert_not_called()

        class _MissingAdmissionSource(_SyntheticProcessSource):
            def admit_binding(self, expected: Any) -> Any:
                return soak.ProcessSource.admit_binding(self, expected)

        missing_source = _MissingAdmissionSource(self.plan_data, self.cases)
        _, _, _, missing_sink, _ = self._run(source=missing_source)
        identity_unavailable = [
            row
            for row in _accepted_records(missing_sink)
            if row["kind"] == soak.RecordKind.LIFECYCLE.value
            and row["event"]["code"] == soak.LifecycleCode.IDENTITY_UNAVAILABLE.value
        ]
        self.assertEqual(len(identity_unavailable), 1)
        self.assertEqual(missing_source.prepared, [])
        self.assertEqual(missing_source.queried_slots, [])

    # WORK_UNIT_CASE: 942/3
    def test_case_03_counter_names_and_units_remain_distinct(self) -> None:
        plan = self._plan()
        record = _sample_record(plan, 0, self.cases)
        normalized = soak.validate_sample_record(record, plan=plan)
        counters = {row["name"]: row for row in normalized["counters"]}
        self.assertEqual(
            counters["working_set_bytes"]["value"],
            4096,
        )
        self.assertEqual(counters["working_set_bytes"]["unit"], "bytes")
        self.assertEqual(counters["private_commit_bytes"]["value"], 8192)
        self.assertEqual(counters["private_commit_bytes"]["unit"], "bytes")
        self.assertEqual(counters["handle_count"]["value"], 3)
        self.assertEqual(counters["handle_count"]["unit"], "count")

        mislabeled_handle_count = copy.deepcopy(record)
        for counter in mislabeled_handle_count["counters"]:
            if counter["name"] == "handle_count":
                counter["unit"] = "bytes"
        with self.assertRaises(soak.RecordRejected):
            soak.validate_sample_record(mislabeled_handle_count, plan=plan)

    # WORK_UNIT_CASE: 942/4
    def test_case_04_denied_counter_is_unknown_with_closed_reason(self) -> None:
        plan = self._plan()
        readings = [
            self.cases["counter_unknown"],
            self.cases["counters_ok"][1],
            self.cases["counters_ok"][2],
        ]
        record = _sample_record(plan, 0, self.cases, counters=readings)
        normalized = soak.validate_sample_record(record, plan=plan)
        unknown = normalized["counters"][0]
        self.assertIsNone(unknown["value"])
        self.assertEqual(unknown["status"], soak.CounterStatus.UNKNOWN.value)
        self.assertEqual(unknown["reason"], soak.Reason.ACCESS_DENIED.value)
        self.assertEqual(unknown["api_error"], 5)

        fabricated_zero = copy.deepcopy(record)
        fabricated_zero["counters"][0]["value"] = 0
        with self.assertRaises(soak.RecordRejected):
            soak.validate_sample_record(fabricated_zero, plan=plan)

        unregistered_reason = copy.deepcopy(record)
        unregistered_reason["counters"][0]["reason"] = "raw_adapter_detail"
        with self.assertRaises(soak.RecordRejected):
            soak.validate_sample_record(unregistered_reason, plan=plan)

    # WORK_UNIT_CASE: 942/5
    def test_case_05_exit_replacement_new_plan_and_retained_259_handle(self) -> None:
        exit_slot = self.cases["missed_exit"]["exit_slot"]
        exit_code = self.cases["missed_exit"]["exit_code"]
        outcomes = {exit_slot: soak.ProcessExit(exit_code=exit_code)}
        plan, source, _, sink, result = self._run(outcomes=outcomes)
        records = _accepted_records(sink)
        samples = [r for r in records if r["kind"] == soak.RecordKind.SAMPLE.value]
        exits = [
            r
            for r in records
            if r["kind"] == soak.RecordKind.LIFECYCLE.value
            and r["event"]["code"] == soak.LifecycleCode.PROCESS_EXIT.value
        ]
        self.assertEqual(source.queried_slots, [0, 1, 2, exit_slot])
        self.assertEqual([row["slot"] for row in samples], [0, 1, 2])
        self.assertEqual([row["slot"] for row in exits], [exit_slot])
        self.assertEqual(exits[0]["event"]["exit_code"], exit_code)
        self.assertEqual(
            exits[0]["event"]["detail"], soak.Reason.PROCESS_EXITED.value
        )
        self.assertEqual(result.accepted_samples, 3)
        self.assertEqual(result.accepted_lifecycle_records, 1)
        self.assertEqual(result.accepted_terminals, 0)
        self.assertEqual(result.missing_obligations, 2)

        replacement_outcomes = {
            exit_slot: soak.ProcessReplacement(
                observed_creation="0000000000000943",
                observed_image="synthetic-approved-image-942",
            )
        }
        _, replacement_source, _, replacement_sink, replacement_result = self._run(
            outcomes=replacement_outcomes
        )
        replacement_records = _accepted_records(replacement_sink)
        rejected_replacement = [
            r
            for r in replacement_records
            if r["kind"] == soak.RecordKind.LIFECYCLE.value
            and r["event"]["code"]
            == soak.LifecycleCode.LIFECYCLE_UPDATE_REJECTED.value
        ]
        self.assertEqual(replacement_source.queried_slots, [0, 1, 2, exit_slot])
        self.assertEqual(len(rejected_replacement), 1)
        self.assertEqual(replacement_result.accepted_samples, 3)

        replacement_plan_data = copy.deepcopy(self.plan_data)
        replacement_plan_data["plan_id"] = "synthetic-plan-942-replacement"
        replacement_plan_data["bindings"][0].update(
            {
                "pid": 943,
                "creation_identity": "0000000000000943",
                "generation": "synthetic-generation-2",
            }
        )
        replacement_binding = soak.ProcessBinding(
            **replacement_plan_data["bindings"][0]
        )
        old_plan_source = self._source()
        with self.assertRaises(soak.IdentityUnavailable):
            old_plan_source.admit_binding(replacement_binding)
        new_plan, new_source, _, new_sink, new_result = self._run(
            plan_data=replacement_plan_data,
            owner_observations=[_REPLACEMENT_OWNER_OBSERVATION],
        )
        new_samples = [
            r
            for r in _accepted_records(new_sink)
            if r["kind"] == soak.RecordKind.SAMPLE.value
        ]
        self.assertEqual(new_plan.plan_id, "synthetic-plan-942-replacement")
        self.assertNotEqual(new_plan.plan_digest, plan.plan_digest)
        self.assertEqual(new_source.queried_slots, [0, 1, 2, 3, 4, 5])
        self.assertEqual(new_samples[0]["stream"]["pid"], 943)
        self.assertEqual(
            new_samples[0]["stream"]["generation"], "synthetic-generation-2"
        )
        self.assertEqual(new_result.accepted_samples, 6)

        binding = plan.bindings[0]
        owner_observation = soak.ProcessBinding(**_OWNER_OBSERVATION)
        adapter, kernel32 = self._windows_adapter(
            owner_handoff=lambda expected: owner_observation
        )
        receipt = adapter.admit_binding(binding)
        kernel32.GetProcessId.return_value = binding.pid
        kernel32.WaitForSingleObject.return_value = soak._WAIT_OBJECT_0

        def get_exit_code(handle: int, output: Any) -> int:
            self.assertEqual(handle, fake_handle)
            output._obj.value = 259
            return 1

        kernel32.GetExitCodeProcess.side_effect = get_exit_code
        fake_handle = 942
        foreign_receipt = self._source().admit_binding(binding)
        with self.assertRaises(soak.IdentityUnavailable):
            adapter.attach_verified_handle(foreign_receipt, fake_handle)
        kernel32.GetProcessId.assert_not_called()
        with mock.patch.object(
            adapter,
            "_readback_identity",
            return_value=(binding.creation_identity, binding.image_identity),
        ):
            retained = adapter.attach_verified_handle(receipt, fake_handle)
            with mock.patch.object(adapter, "_read_counters") as read_counters:
                kernel32.WaitForSingleObject.side_effect = [
                    soak._WAIT_TIMEOUT,
                    soak._WAIT_OBJECT_0,
                ]
                read_counters.return_value = _counter_outcome(self.cases["counters_ok"])
                outcome = adapter.query(
                    retained,
                    soak.QueryContext(
                        slot=0,
                        elapsed_ms=0,
                        phase_id=plan.phases[0].phase_id,
                        workload_ref=plan.phases[0].workload_ref,
                    ),
                )
        self.assertIsInstance(outcome, soak.ProcessExit)
        self.assertEqual(outcome.exit_code, 259)
        read_counters.assert_called_once()
        self.assertEqual(
            kernel32.WaitForSingleObject.call_args_list,
            [mock.call(fake_handle, 0), mock.call(fake_handle, 0)],
        )
        kernel32.GetExitCodeProcess.assert_called_once()
        kernel32.OpenProcess.assert_not_called()
        self.assertNotIsInstance(outcome, soak.SampleCounters)

        failed_adapter, failed_kernel32 = self._windows_adapter(
            owner_handoff=lambda expected: owner_observation
        )
        failed_receipt = failed_adapter.admit_binding(binding)
        failed_kernel32.GetProcessId.return_value = binding.pid
        failed_kernel32.WaitForSingleObject.return_value = soak._WAIT_FAILED
        with mock.patch.object(
            failed_adapter,
            "_readback_identity",
            return_value=(binding.creation_identity, binding.image_identity),
        ):
            failed_target = failed_adapter.attach_verified_handle(
                failed_receipt, fake_handle
            )
            with mock.patch.object(
                failed_adapter, "_read_counters"
            ) as read_counters:
                unknown_owner = failed_adapter.query(
                    failed_target,
                    soak.QueryContext(
                        slot=0,
                        elapsed_ms=0,
                        phase_id=plan.phases[0].phase_id,
                        workload_ref=plan.phases[0].workload_ref,
                    ),
                )
        self.assertIsInstance(unknown_owner, soak.UnknownOwnership)
        read_counters.assert_not_called()

    # WORK_UNIT_CASE: 942/6
    def test_case_06_monotonic_slots_ignore_backward_wall_clock(self) -> None:
        _, _, clock, sink, result = self._run()
        samples = [
            row
            for row in _accepted_records(sink)
            if row["kind"] == soak.RecordKind.SAMPLE.value
        ]
        self.assertEqual(clock._clock["wall_time_ms"], [600, 500, 400, 300, 200, 100])
        self.assertEqual([row["slot"] for row in samples], [0, 1, 2, 3, 4, 5])
        self.assertEqual(
            [row["elapsed_ms"] for row in samples],
            [0, 100, 200, 300, 400, 500],
        )
        self.assertEqual(result.accepted_samples, 6)
        self.assertEqual(result.completeness, soak.Completeness.COMPLETE)

    # WORK_UNIT_CASE: 942/7
    def test_case_07_gap_exit_and_missing_obligations_reconcile(self) -> None:
        expected = self.cases["missed_exit"]["expected"]
        outcomes = {
            self.cases["missed_exit"]["exit_slot"]: soak.ProcessExit(
                exit_code=self.cases["missed_exit"]["exit_code"]
            )
        }
        clock = _ScriptedClock(
            self.cases,
            late_slot=self.cases["missed_exit"]["missed_slot"],
            lateness_ms=self.cases["missed_exit"]["lateness_ms"],
        )
        plan, source, _, sink, result = self._run(outcomes=outcomes, clock=clock)
        records = _accepted_records(sink)
        sample_slots = [
            row["slot"]
            for row in records
            if row["kind"] == soak.RecordKind.SAMPLE.value
        ]
        explicit_gap_slots = [
            row["slot"]
            for row in records
            if row["kind"] == soak.RecordKind.MISSED_SLOT.value
        ]
        exit_lifecycle_slots = [
            row["slot"]
            for row in records
            if row["kind"] == soak.RecordKind.LIFECYCLE.value
            and row["event"]["code"] == soak.LifecycleCode.PROCESS_EXIT.value
        ]
        self.assertEqual(sample_slots, expected["accepted_sample_slots"])
        self.assertEqual(explicit_gap_slots, expected["accepted_gap_slots"])
        self.assertEqual(exit_lifecycle_slots, expected["accepted_exit_lifecycle_slots"])
        self.assertEqual(source.queried_slots, [0, 1, 3])
        self.assertEqual(result.expected_samples, expected["expected_slots"])
        self.assertEqual(result.accepted_samples, 2)
        self.assertEqual(result.accepted_gap_slots, 2)
        self.assertEqual(
            set(result.accepted_gaps_by_reason),
            {reason.value for reason in soak.Reason},
        )
        self.assertEqual(
            result.accepted_gaps_by_reason[soak.Reason.SLOT_MISSED.value],
            1,
        )
        self.assertEqual(
            result.accepted_gaps_by_reason[soak.Reason.PROCESS_EXITED.value],
            1,
        )
        self.assertTrue(
            all(
                count == 0
                for reason, count in result.accepted_gaps_by_reason.items()
                if reason
                not in {
                    soak.Reason.SLOT_MISSED.value,
                    soak.Reason.PROCESS_EXITED.value,
                }
            )
        )
        self.assertEqual(
            sum(result.accepted_gaps_by_reason.values()),
            result.accepted_gap_slots,
        )
        self.assertEqual(result.accepted_lifecycle_records, 1)
        self.assertEqual(result.missing_obligations, len(expected["missing_obligation_slots"]))
        self.assertEqual(
            result.expected_samples,
            result.accepted_samples
            + result.accepted_gap_slots
            + result.missing_obligations,
        )
        self.assertEqual(plan.expected_slots, 6)
        self.assertEqual(result.completeness, soak.Completeness.INCOMPLETE)

    # WORK_UNIT_CASE: 942/8
    def test_case_08_duplicate_reordered_conflicting_and_rebound_streams_fail(self) -> None:
        plan = self._plan()
        first = _sample_record(plan, 0, self.cases)
        second = _sample_record(plan, 1, self.cases)

        positive = soak.StreamValidator(plan)
        self.assertEqual(positive.observe(first), first)
        self.assertEqual(positive.observe(second), second)

        duplicate = soak.StreamValidator(plan)
        duplicate.observe(first)
        with self.assertRaises(soak.StreamRejected):
            duplicate.observe(copy.deepcopy(first))

        reordered = soak.StreamValidator(plan)
        later = _sample_record(plan, 2, self.cases)
        reordered.observe(later)
        reordered_earlier = _sample_record(plan, 1, self.cases)
        with self.assertRaises(soak.StreamRejected):
            reordered.observe(reordered_earlier)

        conflicting = soak.StreamValidator(plan)
        conflicting.observe(first)
        changed_same_slot = copy.deepcopy(first)
        changed_same_slot["counters"][0]["value"] += 1
        with self.assertRaises(soak.StreamRejected):
            conflicting.observe(changed_same_slot)

        planless = soak.StreamValidator(None)
        planless.observe(first)
        altered_plan_data = copy.deepcopy(self.plan_data)
        altered_plan_data["cadence_ms"] += 1
        altered_plan = self._plan(altered_plan_data)
        same_id_different_digest = _sample_record(altered_plan, 1, self.cases)
        self.assertEqual(same_id_different_digest["plan_id"], first["plan_id"])
        self.assertNotEqual(
            same_id_different_digest["plan_digest"], first["plan_digest"]
        )
        with self.assertRaises(soak.StreamRejected):
            planless.observe(same_id_different_digest)

    # WORK_UNIT_CASE: 942/9
    def test_case_09_exact_phase_workload_plan_and_terminal_slot_binding(self) -> None:
        plan = self._plan()
        valid = _sample_record(plan, 2, self.cases)
        self.assertEqual(soak.validate_sample_record(valid, plan=plan), valid)

        wrong_phase = copy.deepcopy(valid)
        wrong_phase["phase_id"] = "synthetic-phase-b"
        wrong_phase["workload_ref"] = "synthetic-workload-b"
        with self.assertRaises(soak.RecordRejected):
            soak.validate_sample_record(wrong_phase, plan=plan)

        wrong_workload = copy.deepcopy(valid)
        wrong_workload["workload_ref"] = plan.workload_ref
        with self.assertRaises(soak.RecordRejected):
            soak.validate_sample_record(wrong_workload, plan=plan)

        wrong_source = copy.deepcopy(valid)
        wrong_source["source_ref"] = "synthetic-other-source"
        with self.assertRaises(soak.RecordRejected):
            soak.validate_sample_record(wrong_source, plan=plan)

        wrong_artifact = copy.deepcopy(valid)
        wrong_artifact["artifact_ref"] = "synthetic-other-artifact"
        with self.assertRaises(soak.RecordRejected):
            soak.validate_sample_record(wrong_artifact, plan=plan)

        unsorted_data = copy.deepcopy(self.plan_data)
        unsorted_data["phases"] = list(reversed(unsorted_data["phases"]))
        unsorted_plan = self._plan(unsorted_data)
        _, _, _, sink, result = self._run(plan_data=unsorted_data)
        records = _accepted_records(sink)
        terminal = next(
            row for row in records if row["kind"] == soak.RecordKind.TERMINAL.value
        )
        self.assertEqual(terminal["slot"], unsorted_plan.expected_slots)
        self.assertEqual(
            terminal["plan_digest"], _sha256_json(unsorted_plan.to_dict())
        )
        self.assertEqual(terminal["phase_id"], "synthetic-phase-b")
        self.assertEqual(terminal["workload_ref"], "synthetic-workload-b")
        self.assertEqual(result.completeness, soak.Completeness.COMPLETE)
        for row in records:
            soak.validate_record(row, plan=unsorted_plan)

    # WORK_UNIT_CASE: 942/10
    def test_case_10_process_point_byte_and_query_time_bounds_are_honest(self) -> None:
        too_many_processes = copy.deepcopy(self.plan_data)
        too_many_processes["limits"]["max_processes"] = 0
        with self.assertRaises(soak.PlanRejected):
            self._plan(too_many_processes)

        too_many_points = copy.deepcopy(self.plan_data)
        too_many_points["limits"]["max_samples_total"] = 5
        point_plan, point_source, _, point_sink, point_result = self._run(
            plan_data=too_many_points
        )
        point_denominator = len(point_plan.bindings) * point_plan.expected_slots
        self.assertEqual(point_denominator, 6)
        self.assertEqual(point_source.queried_slots, [0, 1, 2, 3, 4])
        self.assertEqual(point_result.accepted_samples, 5)
        self.assertEqual(point_result.expected_samples, point_denominator)
        self.assertEqual(point_result.missing_obligations, 1)
        self.assertIn("limit_exceeded", point_result.completeness_reasons)
        self.assertEqual(
            point_result.expected_samples,
            point_result.accepted_samples
            + point_result.accepted_gap_slots
            + point_result.missing_obligations,
        )
        self.assertNotEqual(point_result.completeness, soak.Completeness.COMPLETE)
        self.assertFalse(
            any(
                row.get("event", {}).get("code")
                == soak.LifecycleCode.RUN_COMPLETE.value
                for row in _accepted_records(point_sink)
            )
        )

        byte_reserve_does_not_fit = copy.deepcopy(self.plan_data)
        byte_reserve_does_not_fit["limits"]["max_total_bytes"] = 8191
        with self.assertRaises(soak.PlanRejected):
            self._plan(byte_reserve_does_not_fit)

        elapsed_limited = copy.deepcopy(self.plan_data)
        elapsed_limited["limits"]["max_elapsed_ms"] = 399
        limited_plan, _, _, _, limited_result = self._run(plan_data=elapsed_limited)
        limited_denominator = len(limited_plan.bindings) * limited_plan.expected_slots
        self.assertLess(limited_result.accepted_samples, limited_denominator)
        self.assertEqual(limited_result.expected_samples, limited_denominator)
        self.assertGreater(limited_result.missing_obligations, 0)
        self.assertEqual(
            limited_result.expected_samples,
            limited_result.accepted_samples
            + limited_result.accepted_gap_slots
            + limited_result.missing_obligations,
        )

        wait_bound = copy.deepcopy(self.plan_data)
        wait_bound["limits"]["max_elapsed_ms"] = 50
        wait_plan, wait_source, wait_clock, wait_sink, wait_result = self._run(
            plan_data=wait_bound
        )
        self.assertEqual(wait_plan.cadence_ms, 100)
        self.assertEqual(wait_clock._waits, 2)
        self.assertEqual(wait_source.queried_slots, [0])
        self.assertEqual(wait_result.expected_samples, 6)
        self.assertEqual(wait_result.accepted_samples, 1)
        self.assertEqual(wait_result.accepted_gap_slots, 0)
        self.assertEqual(wait_result.missing_obligations, 5)
        self.assertIn("limit_exceeded", wait_result.completeness_reasons)

        overrun_clock = _ScriptedClock(self.cases)

        class _BlockingQuerySource(_SyntheticProcessSource):
            def __init__(self, plan_data: Mapping[str, Any], cases: Mapping[str, Any]):
                super().__init__(plan_data, cases)
                self.query_elapsed_ms: list[int] = []

            def query(self, target: Any, context: Any) -> Any:
                self.query_elapsed_ms.append(context.elapsed_ms)
                outcome = super().query(target, context)
                overrun_clock._now = 51
                return outcome

        overrun_source = _BlockingQuerySource(self.plan_data, self.cases)
        overrun_result_plan, _, _, overrun_sink, overrun_result = self._run(
            plan_data=wait_bound,
            source=overrun_source,
            clock=overrun_clock,
        )
        self.assertEqual(overrun_result_plan.expected_slots, 6)
        self.assertEqual(overrun_source.queried_slots, [0])
        self.assertEqual(overrun_source.query_elapsed_ms, [0])
        self.assertEqual(overrun_result.accepted_samples, 1)
        self.assertIn("limit_exceeded", overrun_result.completeness_reasons)
        self.assertNotEqual(overrun_result.completeness, soak.Completeness.COMPLETE)

        for bounded_sink in (wait_sink, overrun_sink):
            bounded_records = _accepted_records(bounded_sink)
            self.assertFalse(
                any(
                    row.get("event", {}).get("code")
                    == soak.LifecycleCode.RUN_COMPLETE.value
                    for row in bounded_records
                )
            )

        hard_deadline = copy.deepcopy(self.plan_data)
        hard_deadline["hard_deadline_required"] = True
        _, _, _, _, deadline_result = self._run(plan_data=hard_deadline)
        self.assertEqual(
            deadline_result.hard_deadline,
            soak.HardDeadlineStatus.UNSUPPORTED,
        )

    # WORK_UNIT_CASE: 942/11
    def test_case_11_bounded_streaming_and_digest_domains_are_independent(self) -> None:
        plan, _, _, sink, result = self._run()
        records = _accepted_records(sink)
        self.assertEqual(len(sink.attempts), result.valid_prefix_records)
        self.assertEqual(result.valid_prefix_records, result.emitted_records)
        self.assertLessEqual(len(sink.data), plan.limits.max_total_bytes)
        self.assertLessEqual(
            max(map(len, sink.attempts)),
            plan.limits.max_record_bytes,
        )
        self.assertEqual(
            result.transport_digest,
            hashlib.sha256(bytes(sink.data)).hexdigest(),
        )
        self.assertEqual(result.semantic_digest, _semantic_digest(records))

        shifted_clock = _ScriptedClock(self.cases, wall_offset_ms=1)
        _, _, _, shifted_sink, shifted_result = self._run(clock=shifted_clock)
        self.assertEqual(
            shifted_result.semantic_digest,
            result.semantic_digest,
        )
        self.assertNotEqual(
            shifted_result.transport_digest,
            result.transport_digest,
        )

    # WORK_UNIT_CASE: 942/12
    def test_case_12_partial_or_invalid_ack_freezes_confirmed_prefix(self) -> None:
        partial = self.cases["partial_write"]["acceptedBytes"]
        sink = _RecordingSink(partial_second_write=partial)
        _, _, _, _, result = self._run(sink=sink)
        self.assertEqual(len(sink.attempts), 2)
        self.assertEqual(
            len(sink.attempts) - 2,
            self.cases["partial_write"]["following_write_attempts"],
        )
        self.assertEqual(sink.acks[1], partial)
        self.assertEqual(
            bytes(sink.data),
            sink.attempts[0] + sink.attempts[1][:partial],
        )
        self.assertEqual(result.valid_prefix_records, 1)
        self.assertEqual(result.accepted_samples, 1)
        self.assertEqual(result.failed_writes, 1)
        self.assertEqual(result.accepted_terminals, 0)
        self.assertFalse(self.cases["partial_write"]["expected_in_band_terminal"])
        self.assertNotEqual(result.completeness, soak.Completeness.COMPLETE)
        self.assertEqual(
            result.transport_digest,
            hashlib.sha256(sink.attempts[0]).hexdigest(),
        )
        first_record = _record_from_payload(sink.attempts[0])
        self.assertEqual(result.semantic_digest, _semantic_digest([first_record]))

        self._run_with_bad_ack("float_full")
        self._run_with_bad_ack("bool")
        self._run_with_bad_ack("negative")
        self._run_with_bad_ack("overshoot")

        plan = self._plan()
        first_record = _sample_record(plan, 0, self.cases)
        first_record_size = len(soak.encode_transport(first_record))
        underreported_plan_data = copy.deepcopy(self.plan_data)
        reserve_bytes = (
            underreported_plan_data["limits"]["terminal_reserve_records"]
            * underreported_plan_data["limits"]["max_record_bytes"]
        )
        underreported_plan_data["limits"]["max_total_bytes"] = (
            reserve_bytes + first_record_size + 1
        )
        underreported_sink = _RecordingSink(underreport_bytes=True)
        limited_plan, _, _, _, underreported_result = self._run(
            plan_data=underreported_plan_data,
            sink=underreported_sink,
        )
        self.assertEqual(underreported_sink.bytes_accepted, 0)
        self.assertEqual(len(underreported_sink.attempts), 2)
        self.assertLessEqual(
            len(underreported_sink.data),
            limited_plan.limits.max_total_bytes,
        )
        self.assertEqual(underreported_result.accepted_samples, 1)
        self.assertEqual(underreported_result.failed_writes, 0)
        self.assertEqual(underreported_result.accepted_terminals, 1)
        underreported_records = _accepted_records(underreported_sink)
        self.assertEqual(
            sum(
                row["kind"] == soak.RecordKind.SAMPLE.value
                for row in underreported_records
            ),
            1,
        )
        self.assertEqual(
            sum(
                row["kind"] == soak.RecordKind.TERMINAL.value
                for row in underreported_records
            ),
            1,
        )
        self.assertEqual(
            underreported_result.transport_digest,
            hashlib.sha256(bytes(underreported_sink.data)).hexdigest(),
        )
        self.assertNotEqual(
            underreported_result.completeness,
            soak.Completeness.COMPLETE,
        )

    # WORK_UNIT_CASE: 942/13
    def test_case_13_working_set_sum_is_non_unique_and_unknown_is_counted(self) -> None:
        plan = self._plan()
        known_first = _sample_record(plan, 0, self.cases)
        known_second = _sample_record(plan, 1, self.cases)
        unknown_readings = [
            self.cases["counter_unknown"],
            self.cases["counters_ok"][1],
            self.cases["counters_ok"][2],
        ]
        unknown = _sample_record(
            plan,
            2,
            self.cases,
            counters=unknown_readings,
        )
        summary = soak.non_unique_working_set_sum(
            [known_first, known_second, unknown]
        )
        self.assertEqual(summary["label"], "non-unique-shared-pages")
        self.assertEqual(summary["total_working_set_bytes"], 8192)
        self.assertEqual(summary["contributing_readings"], 2)
        self.assertEqual(summary["unknown_readings"], 1)
        self.assertTrue(summary["not_system_rss"])
        self.assertTrue(summary["not_private_rss"])

        fabricated_unknown_zero = copy.deepcopy(unknown)
        fabricated_unknown_zero["counters"][0]["value"] = 0
        with self.assertRaises(soak.RecordRejected):
            soak.non_unique_working_set_sum(
                [known_first, known_second, fabricated_unknown_zero]
            )

    # WORK_UNIT_CASE: 942/14
    def test_case_14_cancellation_releases_only_sampler_owned_handles(self) -> None:
        owned_cancel = _CancelFlag()
        owned_source = self._source(cancel_after_first_query=owned_cancel)
        _, _, _, _, owned_result = self._run(
            source=owned_source,
            cancellation=owned_cancel,
        )
        self.assertEqual(owned_source.queried_slots, [0])
        self.assertEqual(len(owned_source.released), 1)
        self.assertTrue(owned_source.released[0].owned_handle)
        self.assertEqual(owned_source.termination_attempts, 0)
        self.assertEqual(owned_result.handle_cleanup, soak.HandleCleanupStatus.OK)

        retained_cancel = _CancelFlag()
        retained_source = self._source(
            owned_handle=False,
            cancel_after_first_query=retained_cancel,
        )
        _, _, _, _, retained_result = self._run(
            source=retained_source,
            cancellation=retained_cancel,
        )
        self.assertEqual(retained_source.queried_slots, [0])
        self.assertEqual(retained_source.released, [])
        self.assertEqual(retained_source.termination_attempts, 0)
        self.assertEqual(
            retained_result.handle_cleanup,
            soak.HandleCleanupStatus.NONE_OWNED,
        )

        class _InvalidOwnedTargetSource(_SyntheticProcessSource):
            def prepare(self, receipt: Any) -> Any:
                self._require_admitted_binding(receipt)
                wrong_binding = copy.deepcopy(self._plan_data["bindings"][0])
                wrong_binding.update(
                    {
                        "pid": 943,
                        "creation_identity": "0000000000000943",
                        "generation": "synthetic-generation-2",
                    }
                )
                target = soak.PreparedTarget(
                    binding=soak.ProcessBinding(**wrong_binding),
                    owned_handle=True,
                )
                self.prepared.append(target)
                return target

            def release(self, target: Any) -> None:
                self.released.append(target)
                raise RuntimeError("synthetic close failure detail")

        invalid_source = _InvalidOwnedTargetSource(self.plan_data, self.cases)
        _, _, _, _, invalid_result = self._run(source=invalid_source)
        self.assertEqual(invalid_source.queried_slots, [])
        self.assertEqual(len(invalid_source.prepared), 1)
        self.assertEqual(invalid_source.released, invalid_source.prepared)
        self.assertEqual(
            invalid_result.handle_cleanup,
            soak.HandleCleanupStatus.PARTIAL,
        )
        self.assertEqual(invalid_result.handle_cleanup_detail, "query_failed")
        self.assertNotEqual(
            invalid_result.handle_cleanup,
            soak.HandleCleanupStatus.NONE_OWNED,
        )
        self.assertNotIn(
            "synthetic close failure detail",
            json.dumps(invalid_result.to_dict(), sort_keys=True),
        )
        self.assertEqual(invalid_source.termination_attempts, 0)

        binding = self._plan().bindings[0]
        owner_observation = soak.ProcessBinding(**_OWNER_OBSERVATION)
        adapter, kernel32 = self._windows_adapter(
            owner_handoff=lambda expected: owner_observation
        )
        receipt = adapter.admit_binding(binding)
        kernel32.OpenProcess.return_value = 942
        with mock.patch.object(
            adapter,
            "_readback_identity",
            return_value=(binding.creation_identity, binding.image_identity),
        ):
            sampler_target = adapter.prepare(receipt)
            self.assertEqual(adapter._owned_handle_by_target[id(sampler_target)], 942)
            sampler_target.handle = 943
            sampler_target.owned_handle = False
            adapter.release(sampler_target)

            supplier_target = adapter.attach_verified_handle(receipt, 943)
            self.assertNotIn(id(supplier_target), adapter._owned_handle_by_target)
            supplier_target.handle = 943
            supplier_target.owned_handle = True
            adapter.release(supplier_target)

        kernel32.CloseHandle.assert_called_once_with(942)
        self.assertNotIn(id(sampler_target), adapter._owned_handle_by_target)
        self.assertNotIn(id(supplier_target), adapter._owned_handle_by_target)

        class _RaisingSource(_SyntheticProcessSource):
            def query(self, target: Any, context: Any) -> Any:
                del target, context
                raise RuntimeError("synthetic query failure")

        raising_source = _RaisingSource(self.plan_data, self.cases)
        with self.assertRaisesRegex(RuntimeError, "synthetic query failure"):
            self._run(source=raising_source)
        self.assertEqual(len(raising_source.released), 1)
        self.assertTrue(raising_source.released[0].owned_handle)
        self.assertEqual(raising_source.termination_attempts, 0)

    # WORK_UNIT_CASE: 942/15
    def test_case_15_portable_output_excludes_synthetic_sensitive_canary(self) -> None:
        canary = self.cases["privacy_canary"]["diagnostic_test_input"]
        failure = soak.QueryFailure(
            reason=soak.Reason.ACCESS_DENIED.value,
            api_error=5,
            detail=canary,
        )

        class _CanaryFootprintSource(_SyntheticProcessSource):
            def sampler_footprint(self) -> Any:
                return soak.SamplerFootprint(
                    working_set_bytes=canary,
                    private_commit_bytes=canary,
                    handle_count=canary,
                )

        canary_source = _CanaryFootprintSource(
            self.plan_data,
            self.cases,
            outcomes={0: failure},
        )
        _, _, _, sink, result = self._run(source=canary_source)
        self.assertEqual(
            result.to_dict()["sampler_footprint"],
            {
                "working_set_bytes": None,
                "private_commit_bytes": None,
                "handle_count": None,
            },
        )
        portable = bytes(sink.data) + json.dumps(
            result.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        self.assertNotIn("diagnostics", result.to_dict())
        self.assertEqual(
            self.cases["privacy_canary"]["expected_portable_occurrences"],
            [],
        )
        self.assertEqual(portable.count(canary.encode("utf-8")), 0)
        records = _accepted_records(sink)
        failed = next(
            row
            for row in records
            if row["kind"] == soak.RecordKind.LIFECYCLE.value
            and row["event"]["code"] == soak.LifecycleCode.QUERY_FAILURE.value
        )
        self.assertEqual(failed["event"]["api_error"], 5)
        self.assertEqual(failed["event"]["detail"], soak.Reason.ACCESS_DENIED.value)

        injected_detail = _sample_record(plan := self._plan(), 0, self.cases)
        injected_detail["kind"] = soak.RecordKind.LIFECYCLE.value
        injected_detail.pop("counters")
        injected_detail["event"] = {
            "code": soak.LifecycleCode.QUERY_FAILURE.value,
            "detail": canary,
            "api_error": 5,
        }
        with self.assertRaises(soak.RecordRejected):
            soak.validate_record(injected_detail, plan=plan)

    # WORK_UNIT_CASE: 942/16
    def test_case_16_windows_isolated_child_smoke_is_deferred_without_fake_pass(
        self,
    ) -> None:
        """The live isolated-child proof waits for the #907/#911 owner handoff."""
        self.skipTest(
            "DEFER: supported-Windows isolated-child smoke belongs to the #907/#911 to #944 handoff"
        )


if __name__ == "__main__":
    unittest.main()
