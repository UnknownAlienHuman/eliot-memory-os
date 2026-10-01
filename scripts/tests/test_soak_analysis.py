"""Tests for the #943 soak analyzer: no string/boolean authentication.

Scope of this module: the blocking defect that arbitrary non-empty strings and
caller-supplied booleans authenticated the complete acceptance path, and the
self-contained half of the evidence-closure defect (duplicate evidence phase
IDs). The numeric core assertions here are regression guards: they pin the
deterministic fixed-window measurements, coverage and violations that must not
move while the acceptance path is repaired.

These tests do NOT claim the 16 numbered ``# WORK_UNIT_CASE: 943/<n>``
acceptance cases; those remain later acceptance per the issue.
"""

from __future__ import annotations

import unittest
from typing import Any, Dict, List

from scripts.integration import soak_analysis as sa
from scripts.integration import soak_samples as _soak

STREAM_KEY = "owner-a|comp-a|4242|g1"

_PHASES = (
    {"phase_id": "warmup", "workload_ref": "wl-warm", "first_slot": 0, "last_slot": 3},
    {
        "phase_id": "stationary",
        "workload_ref": "wl-stationary",
        "first_slot": 4,
        "last_slot": 7,
    },
    {
        "phase_id": "quiescent",
        "workload_ref": "wl-quiescent",
        "first_slot": 8,
        "last_slot": 11,
    },
)
_EXPECTED_SLOTS = 12
_RUN_REF = "run-943"
_PLAN_ID = "plan-943"
_SOURCE_REF = "src-943"
_ARTIFACT_REF = "art-943"
_WORKLOAD_REF = "wl-943"
_PROFILE_REF = "prof-943"

_FLAT = {
    "working_set_bytes": 1_000_000,
    "private_commit_bytes": 2_000_000,
    "handle_count": 120,
}

_BOUNDED_COUNTERS = (
    {"name": "working_set_bytes", "unit": "bytes"},
    {"name": "private_commit_bytes", "unit": "bytes"},
    {"name": "handle_count", "unit": "count"},
)

_UNITS = {
    "working_set_bytes": "bytes",
    "private_commit_bytes": "bytes",
    "handle_count": "count",
}


def make_plan() -> Dict[str, Any]:
    """A #942 sampling plan covering every slot with three typed phases."""
    return {
        "schema": _soak.SCHEMA_ID,
        "plan_id": _PLAN_ID,
        "run_ref": _RUN_REF,
        "source_ref": _SOURCE_REF,
        "artifact_ref": _ARTIFACT_REF,
        "workload_ref": _WORKLOAD_REF,
        "profile_ref": _PROFILE_REF,
        "phases": [dict(p) for p in _PHASES],
        "cadence_ms": 1000,
        "expected_slots": _EXPECTED_SLOTS,
        "bindings": [
            {
                "owner_ref": "owner-a",
                "component": "comp-a",
                "pid": 4242,
                "creation_identity": "ct-1",
                "image_identity": "img-1",
                "generation": "g1",
            }
        ],
        "permitted_lifecycle_updates": [],
        "optional_counters": [],
        "limits": {
            "max_processes": 4,
            "max_samples_total": 1000,
            "max_total_bytes": 1048576,
            "max_record_bytes": 65536,
            "max_elapsed_ms": 600000,
            "slot_lateness_ms": 5000,
            "terminal_reserve_records": 8,
            "max_lifecycle_updates": 4,
        },
        "hard_deadline_required": False,
    }


def make_profile(status: str = "qualified") -> Dict[str, Any]:
    """A shape-valid analysis profile with predeclared windows and rules."""
    if status == "qualified":
        qualification = {
            "status": "qualified",
            "qualification_ref": "q",
            "issuer_ref": "anything",
        }
    else:
        qualification = {
            "status": "exploratory",
            "qualification_ref": "",
            "issuer_ref": "",
        }
    return {
        "schema": sa.PROFILE_SCHEMA_ID,
        "profile_ref": _PROFILE_REF,
        "revision": 1,
        "applicability": {
            "sample_schema": _soak.SCHEMA_ID,
            "source_ref": _SOURCE_REF,
            "workload_ref": _WORKLOAD_REF,
        },
        "qualification": qualification,
        "counters": [dict(c) for c in _BOUNDED_COUNTERS],
        "expected": {"cadence_ms": 1000, "expected_slots": _EXPECTED_SLOTS},
        "phase_roles": [
            {"phase_id": "warmup", "role": "warmup"},
            {"phase_id": "stationary", "role": "stationary"},
            {"phase_id": "quiescent", "role": "quiescent"},
        ],
        "window_slots": 2,
        "coverage": {
            "min_coverage_num": 1,
            "min_coverage_den": 1,
            "max_gap_slots": 0,
            "require_terminal": True,
        },
        "absolute_bounds": [
            {"name": "working_set_bytes", "max_value": 10_000_000},
            {"name": "private_commit_bytes", "max_value": 10_000_000},
            {"name": "handle_count", "max_value": 1000},
        ],
        "growth": {
            "statistic": "last",
            "consecutive_windows": 2,
            "allowed_delta": 0,
            "applies_to_roles": ["stationary"],
            "counters": ["working_set_bytes", "private_commit_bytes", "handle_count"],
        },
        "recovery": {
            "baseline_role": "stationary",
            "baseline_selector": "first_window",
            "quiescent_role": "quiescent",
            "quiescent_selector": "max_window",
            "statistic": "max",
            "tolerance": 0,
            "counters": ["working_set_bytes", "private_commit_bytes", "handle_count"],
        },
        "algorithm_revision": sa.ALGORITHM_REVISION,
        "limits": {
            "max_records": 1000,
            "max_streams": 8,
            "max_windows_total": 100000,
            "max_work_units": 1000000,
            "max_total_bytes": 1048576,
            "max_record_bytes": 65536,
            "max_reasons": 64,
        },
    }


def _phase_for(slot: int) -> Dict[str, Any]:
    for phase in _PHASES:
        if phase["first_slot"] <= slot <= phase["last_slot"]:
            return phase
    return _PHASES[-1]


def _header(kind: str, seq: int, slot: int) -> Dict[str, Any]:
    phase = _phase_for(min(slot, _EXPECTED_SLOTS - 1))
    return {
        "schema": _soak.SCHEMA_ID,
        "kind": kind,
        "run_ref": _RUN_REF,
        "plan_id": _PLAN_ID,
        "source_ref": _SOURCE_REF,
        "artifact_ref": _ARTIFACT_REF,
        "stream": {
            "owner_ref": "owner-a",
            "component": "comp-a",
            "pid": 4242,
            "generation": "g1",
        },
        "seq": seq,
        "slot": slot,
        "elapsed_ms": slot * 1000,
        "phase_id": phase["phase_id"],
        "workload_ref": phase["workload_ref"],
        "wall_ms": 1_700_000_000_000 + slot * 1000,
    }


def make_records(flat: bool = True) -> List[Dict[str, Any]]:
    """A complete, plan-bound series: one sample per slot plus a terminal."""
    records: List[Dict[str, Any]] = []
    for slot in range(_EXPECTED_SLOTS):
        values = dict(_FLAT) if flat else {
            "working_set_bytes": _FLAT["working_set_bytes"] + 100 * slot,
            "private_commit_bytes": _FLAT["private_commit_bytes"] + 100 * slot,
            "handle_count": _FLAT["handle_count"] + slot,
        }
        record = _header("sample", slot, slot)
        record["counters"] = [
            {"name": name, "value": value, "unit": _UNITS[name], "status": "ok"}
            for name, value in sorted(values.items())
        ]
        records.append(record)
    terminal = _header("terminal", _EXPECTED_SLOTS, _EXPECTED_SLOTS)
    terminal["event"] = {"code": "run_complete"}
    records.append(terminal)
    return records


def make_evidence() -> Dict[str, Any]:
    """Run evidence exactly as the audit's five-step forgery supplies it."""
    return {
        "schema": sa.RUN_EVIDENCE_SCHEMA_ID,
        "producer": {"producer_ref": "anything", "evidence_ref": "ev-anything"},
        "commitment": {
            "plan_id": _PLAN_ID,
            "profile_ref": _PROFILE_REF,
            "profile_revision": 1,
            "qualification_ref": "q",
            "source_ref": _SOURCE_REF,
            "artifact_ref": _ARTIFACT_REF,
            "committed_before_workload": True,
        },
        "phases": [
            {"phase_id": p["phase_id"], "first_slot": p["first_slot"],
             "last_slot": p["last_slot"]}
            for p in _PHASES
        ],
        "operations": [],
        "restarts": [],
        "cancellation": {"cancelled": False, "detail": ""},
        "crashes": [],
        "cleanup": {
            "disposition": "verified_clean",
            "issuer_ref": "anything",
            "detail": "anything",
        },
    }


def _axis(result: sa.AnalysisResult, name: str) -> sa.AxisResult:
    axis = result.axis(name)
    assert axis is not None, f"missing axis {name}"
    return axis


class SoakAnalysisNoStringAuthentication(unittest.TestCase):
    """The acceptance path must not be authenticated by strings or booleans."""

    def test_forgery_is_refused_and_never_reaches_qualified_envelope(self) -> None:
        result = sa.analyze_samples(
            make_records(flat=True), make_plan(), make_profile(), make_evidence()
        )
        self.assertNotEqual(
            result.disposition,
            sa.Disposition.OBSERVED_WITHIN_QUALIFIED_ENVELOPE.value,
            "caller strings and booleans must not authenticate acceptance",
        )
        profile_axis = _axis(result, sa.AxisName.PROFILE_QUALIFICATION.value)
        self.assertNotEqual(
            profile_axis.status,
            sa.AxisStatus.SATISFIED.value,
            "an unauthenticated qualification claim cannot satisfy the axis",
        )
        joined = " | ".join(profile_axis.reasons)
        self.assertIn("owner-issued", joined)
        self.assertIn("qualification", joined)
        for axis_name in (
            sa.AxisName.WORKLOAD.value,
            sa.AxisName.CLEANUP.value,
        ):
            axis = _axis(result, axis_name)
            self.assertNotEqual(
                axis.status,
                sa.AxisStatus.SATISFIED.value,
                f"{axis_name} cannot be satisfied by caller-authored fields",
            )
            self.assertIn("owner-issued", " | ".join(axis.reasons))

    def test_qualified_profile_claim_never_authenticates_itself(self) -> None:
        # Even with every optional string made maximally plausible, the
        # profile axis still refuses: there is no owner receipt to verify.
        profile = make_profile()
        profile["qualification"] = {
            "status": "qualified",
            "qualification_ref": "q" * 8,
            "issuer_ref": "owner-that-does-not-exist",
        }
        evidence = make_evidence()
        evidence["commitment"]["qualification_ref"] = "q" * 8
        result = sa.analyze_samples(
            make_records(flat=True), make_plan(), profile, evidence
        )
        self.assertNotEqual(
            result.disposition,
            sa.Disposition.OBSERVED_WITHIN_QUALIFIED_ENVELOPE.value,
        )
        profile_axis = _axis(result, sa.AxisName.PROFILE_QUALIFICATION.value)
        self.assertEqual(profile_axis.status, sa.AxisStatus.UNKNOWN.value)
        self.assertTrue(
            any("owner-issued" in reason for reason in profile_axis.reasons)
        )

    def test_cleanup_disposition_is_never_owner_issued_without_a_receipt(self) -> None:
        for disposition in ("verified_clean", "failed"):
            with self.subTest(disposition=disposition):
                evidence = make_evidence()
                evidence["cleanup"]["disposition"] = disposition
                result = sa.analyze_samples(
                    make_records(flat=True),
                    make_plan(),
                    make_profile(),
                    evidence,
                )
                axis = _axis(result, sa.AxisName.CLEANUP.value)
                self.assertNotEqual(
                    axis.status,
                    sa.AxisStatus.SATISFIED.value,
                    "cleanup must not be satisfied by issuer_ref string presence",
                )
                self.assertIn("owner-issued", " | ".join(axis.reasons))

    def test_claimed_required_failure_is_retained_but_not_promoted(self) -> None:
        # A caller-authored failure row must stay visible as uncertainty; it
        # can never be reported as an authenticated workload failure.
        evidence = make_evidence()
        evidence["operations"] = [
            {
                "op_ref": "op-1",
                "phase_id": "stationary",
                "required": True,
                "expected": "success",
                "observed": "failed",
                "producer_attested": True,
            }
        ]
        result = sa.analyze_samples(
            make_records(flat=True), make_plan(), make_profile(), evidence
        )
        workload = _axis(result, sa.AxisName.WORKLOAD.value)
        self.assertEqual(workload.status, sa.AxisStatus.UNKNOWN.value)
        joined = " | ".join(workload.reasons)
        self.assertIn("op-1", joined)
        self.assertIn("failed", joined)
        self.assertNotEqual(
            result.disposition, sa.Disposition.WORKLOAD_FAILURE.value
        )

    def test_exploratory_profile_still_measures_but_never_accepts(self) -> None:
        result = sa.analyze_samples(
            make_records(flat=True),
            make_plan(),
            make_profile(status="exploratory"),
            make_evidence(),
        )
        self.assertNotEqual(
            result.disposition,
            sa.Disposition.OBSERVED_WITHIN_QUALIFIED_ENVELOPE.value,
        )
        self.assertTrue(result.measurements["streams"])
        self.assertEqual(result.violations, ())


class SoakAnalysisEvidenceClosure(unittest.TestCase):
    """Duplicate evidence phase IDs and foreign phases are rejected."""

    def test_duplicate_evidence_phase_ids_are_rejected(self) -> None:
        evidence = make_evidence()
        evidence["phases"].append(
            {"phase_id": "stationary", "first_slot": 4, "last_slot": 7}
        )
        with self.assertRaises(sa.EvidenceRejected) as ctx:
            sa.validate_run_evidence(evidence)
        self.assertIn("duplicate", str(ctx.exception).lower())

    def test_duplicate_evidence_phase_ids_are_not_silently_overwritten(self) -> None:
        # The pre-change module overwrote the duplicate in evidence_phase_map
        # and reported no rejection at all.
        evidence = make_evidence()
        evidence["phases"] = [
            {"phase_id": "stationary", "first_slot": 0, "last_slot": 3},
            {"phase_id": "stationary", "first_slot": 4, "last_slot": 7},
            {"phase_id": "quiescent", "first_slot": 8, "last_slot": 11},
        ]
        with self.assertRaises(sa.EvidenceRejected):
            sa.validate_run_evidence(evidence)
        result = sa.analyze_samples(
            make_records(flat=True), make_plan(), make_profile(), evidence
        )
        self.assertNotEqual(
            result.disposition,
            sa.Disposition.OBSERVED_WITHIN_QUALIFIED_ENVELOPE.value,
        )

    def test_operation_in_an_undeclared_phase_is_rejected(self) -> None:
        evidence = make_evidence()
        evidence["operations"] = [
            {
                "op_ref": "op-1",
                "phase_id": "phase-not-declared",
                "required": True,
                "expected": "success",
                "observed": "success",
                "producer_attested": True,
            }
        ]
        with self.assertRaises(sa.EvidenceRejected) as ctx:
            sa.validate_run_evidence(evidence)
        self.assertIn("phase", str(ctx.exception))

    def test_record_phase_contradicting_the_plan_slot_is_rejected(self) -> None:
        records = make_records(flat=True)
        records[5]["phase_id"] = "quiescent"
        result = sa.analyze_samples(
            records, make_plan(), make_profile(), make_evidence()
        )
        input_axis = _axis(result, sa.AxisName.INPUT_INTEGRITY_COVERAGE.value)
        self.assertEqual(input_axis.status, sa.AxisStatus.VIOLATED.value)
        self.assertTrue(
            any("phase" in reason for reason in input_axis.reasons),
            f"reasons did not name the phase contradiction: {input_axis.reasons}",
        )
        self.assertEqual(result.records_rejected, 1)

    def test_record_workload_ref_contradicting_the_plan_phase_is_rejected(
        self,
    ) -> None:
        records = make_records(flat=True)
        records[5]["workload_ref"] = "wl-wrong"
        result = sa.analyze_samples(
            records, make_plan(), make_profile(), make_evidence()
        )
        input_axis = _axis(result, sa.AxisName.INPUT_INTEGRITY_COVERAGE.value)
        self.assertEqual(input_axis.status, sa.AxisStatus.VIOLATED.value)
        self.assertEqual(result.records_rejected, 1)


class SoakAnalysisNumericCorePreserved(unittest.TestCase):
    """The deterministic numeric core must be unchanged by the repair."""

    def test_flat_complete_series_produces_the_pinned_numeric_result(self) -> None:
        result = sa.analyze_samples(
            make_records(flat=True), make_plan(), make_profile(), make_evidence()
        )
        # Input integrity for a well-formed run stays satisfied.
        self.assertEqual(
            _axis(result, sa.AxisName.INPUT_INTEGRITY_COVERAGE.value).status,
            sa.AxisStatus.SATISFIED.value,
        )
        # Resource axis still evaluates and still finds no violation.
        self.assertEqual(
            _axis(result, sa.AxisName.RESOURCE.value).status,
            sa.AxisStatus.SATISFIED.value,
        )
        self.assertEqual(result.violations, ())
        # Fixed half-open windows, exact per-window statistics.
        windows = result.windows[STREAM_KEY]["stationary"]["handle_count"]["windows"]
        self.assertEqual([w["index"] for w in windows], [0, 1])
        self.assertEqual([w["first_slot"] for w in windows], [4, 6])
        self.assertEqual([w["last_slot_exclusive"] for w in windows], [6, 8])
        for window in windows:
            self.assertEqual(window["count"], 2)
            self.assertEqual(window["min"], 120)
            self.assertEqual(window["max"], 120)
            self.assertEqual(window["first"], 120)
            self.assertEqual(window["last"], 120)
            self.assertEqual(window["sum"], 240)
            self.assertFalse(window["empty"])
        # Separate resource axes: working set and private commit stay distinct.
        # A tied maximum resolves to its earliest slot, deterministically.
        counters = result.measurements["streams"][STREAM_KEY]["counters"]
        self.assertEqual(
            counters["working_set_bytes"]["sampled_peak"],
            {"slot": 0, "sampled_peak": 1_000_000},
        )
        self.assertEqual(
            counters["private_commit_bytes"]["sampled_peak"],
            {"slot": 0, "sampled_peak": 2_000_000},
        )
        self.assertEqual(
            counters["handle_count"]["sampled_peak"],
            {"slot": 0, "sampled_peak": 120},
        )
        # Units are kept per counter and never collapsed. The analyzer
        # renders the #942 CounterUnit enum member, so the pinned value is the
        # enum's str() form (see the DEFECT-NOTE in the lane report about this
        # cosmetic rendering; behaviour is pinned here, not changed).
        self.assertEqual(
            counters["working_set_bytes"]["unit"],
            str(_soak.CounterUnit.BYTES),
        )
        self.assertEqual(
            counters["handle_count"]["unit"], str(_soak.CounterUnit.COUNT)
        )
        # Sampled peaks stay labelled sampled, never a guaranteed maximum.
        self.assertNotIn("peak", counters["handle_count"])
        self.assertIn("sampled_peak", counters["handle_count"])
        # Exact rational coverage arithmetic against the full denominator.
        coverage = result.coverage["streams"][STREAM_KEY]
        self.assertEqual(coverage["expected_slots"], _EXPECTED_SLOTS)
        self.assertEqual(coverage["present_slots"], _EXPECTED_SLOTS)
        self.assertEqual(coverage["known_slots"], _EXPECTED_SLOTS)
        self.assertEqual(coverage["unknown_slots"], 0)
        self.assertEqual(coverage["missed_slots"], 0)
        self.assertEqual(coverage["max_gap_slots"], 0)
        self.assertEqual(coverage["terminal"], "run_complete")
        self.assertEqual(result.records_accepted, _EXPECTED_SLOTS + 1)
        self.assertEqual(result.records_rejected, 0)

    def test_aggregate_working_set_sum_is_still_labelled_non_unique(self) -> None:
        result = sa.analyze_samples(
            make_records(flat=True), make_plan(), make_profile(), make_evidence()
        )
        aggregate = result.measurements["non_unique_working_set"]
        self.assertEqual(aggregate["label"], "non-unique-shared-pages")
        self.assertEqual(aggregate["total_working_set_bytes"], 12_000_000)
        self.assertEqual(aggregate["contributing_readings"], _EXPECTED_SLOTS)
        self.assertTrue(aggregate["not_system_rss"])
        self.assertTrue(aggregate["not_private_rss"])

    def test_quiescent_recovery_failure_is_still_detected(self) -> None:
        # The rising series fails quiescent recovery against the declared
        # baseline window and tolerance.
        result = sa.analyze_samples(
            make_records(flat=False), make_plan(), make_profile(), make_evidence()
        )
        rules = {violation["rule"] for violation in result.violations}
        self.assertIn("recovery", rules)
        self.assertEqual(
            _axis(result, sa.AxisName.RESOURCE.value).status,
            sa.AxisStatus.VIOLATED.value,
        )
        self.assertEqual(
            result.disposition, sa.Disposition.RESOURCE_VIOLATION.value
        )

    def test_predeclared_growth_rule_is_evaluated_with_its_own_settings(
        self,
    ) -> None:
        profile = make_profile()
        profile["growth"]["consecutive_windows"] = 1
        result = sa.analyze_samples(
            make_records(flat=False), make_plan(), profile, make_evidence()
        )
        growth = [
            violation
            for violation in result.violations
            if violation["rule"] == "growth"
        ]
        self.assertTrue(growth)
        self.assertEqual(growth[0]["phase"], "stationary")
        self.assertEqual(growth[0]["statistic"], "last")
        self.assertEqual(growth[0]["run_length"], 1)
        self.assertEqual(growth[0]["allowed_delta"], 0)

    def test_exact_boundary_passes_and_one_over_fails(self) -> None:
        records = make_records(flat=True)
        for record in records:
            if record["kind"] != "sample":
                continue
            for counter in record["counters"]:
                if counter["name"] == "handle_count":
                    counter["value"] = 1000
        at_bound = sa.analyze_samples(
            records, make_plan(), make_profile(), make_evidence()
        )
        self.assertEqual(at_bound.violations, ())

        over = [dict(r) for r in records]
        for record in over:
            if record["kind"] != "sample":
                continue
            record["counters"] = [
                dict(c)
                for c in record["counters"]
            ]
            for counter in record["counters"]:
                if counter["name"] == "handle_count":
                    counter["value"] = 1001
        one_over = sa.analyze_samples(
            over, make_plan(), make_profile(), make_evidence()
        )
        bound_violations = [
            v for v in one_over.violations if v["rule"] == "absolute_bound"
        ]
        self.assertTrue(bound_violations)
        self.assertEqual(bound_violations[0]["counter"], "handle_count")
        self.assertEqual(bound_violations[0]["value"], 1001)
        self.assertEqual(bound_violations[0]["bound"], 1000)

    def test_equivalent_interleavings_of_independent_streams_agree(self) -> None:
        first = sa.analyze_samples(
            make_records(flat=True), make_plan(), make_profile(), make_evidence()
        )
        second = sa.analyze_samples(
            make_records(flat=True), make_plan(), make_profile(), make_evidence()
        )
        self.assertEqual(first.semantic_digest, second.semantic_digest)

    def test_unknown_counters_stay_unknown_and_are_never_zero(self) -> None:
        records = make_records(flat=True)
        for record in records:
            if record["kind"] != "sample":
                continue
            for counter in record["counters"]:
                if counter["name"] == "handle_count":
                    counter["value"] = None
                    counter["status"] = "unknown"
                    counter["reason"] = "access_denied"
        result = sa.analyze_samples(
            records, make_plan(), make_profile(), make_evidence()
        )
        counters = result.measurements["streams"][STREAM_KEY]["counters"]
        self.assertEqual(counters["handle_count"]["readings_ok"], 0)
        self.assertEqual(counters["handle_count"]["readings_unknown"], _EXPECTED_SLOTS)
        self.assertIsNone(counters["handle_count"]["sampled_peak"])
        self.assertEqual(
            counters["handle_count"]["unknown_by_reason"],
            {"access_denied": _EXPECTED_SLOTS},
        )

    def test_bounded_limits_are_still_enforced_without_remediation(self) -> None:
        profile = make_profile()
        profile["limits"]["max_records"] = 4
        result = sa.analyze_samples(
            make_records(flat=True), make_plan(), profile, make_evidence()
        )
        self.assertTrue(result.limits_exceeded)
        self.assertEqual(result.records_accepted, 4)
        self.assertNotEqual(
            result.disposition,
            sa.Disposition.OBSERVED_WITHIN_QUALIFIED_ENVELOPE.value,
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()