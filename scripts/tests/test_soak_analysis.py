"""Acceptance oracles for the bounded soak analyzer (issue #943).

Each method carries one substantive `# WORK_UNIT_CASE: 943/<case>` marker
from the issue body table. Series are synthetic and finite, built in-code
against the #942 v2 owner schema; no fixture files, no sampling, no network,
no filesystem mutation.
"""

from __future__ import annotations

import unittest
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from scripts.integration import soak_analysis as analysis
from scripts.integration import soak_samples as soak


PLAN_LIMITS = {
    "max_processes": 8,
    "max_samples_total": 100000,
    "max_total_bytes": 256 * 1024 * 1024,
    "max_record_bytes": 65536,
    "max_elapsed_ms": 4 * 3600 * 1000,
    "slot_lateness_ms": 5000,
    "terminal_reserve_records": 8,
    "max_lifecycle_updates": 16,
}

ANALYSIS_LIMITS = {
    "max_records": 100000,
    "max_streams": 64,
    "max_windows_total": 1000000,
    "max_work_units": 10000000,
    "max_total_bytes": 256 * 1024 * 1024,
    "max_record_bytes": 65536,
    "max_reasons": 64,
}


def make_binding(owner="o1", comp="c1", pid=100, creation="boot-1",
                 image="img-1", gen="g0"):
    return {
        "owner_ref": owner, "component": comp, "pid": pid,
        "creation_identity": creation, "image_identity": image,
        "generation": gen,
    }


def binding_digest_of(bound):
    return soak.ProcessBinding(
        owner_ref=bound["owner_ref"], component=bound["component"],
        pid=bound["pid"], creation_identity=bound["creation_identity"],
        image_identity=bound["image_identity"],
        generation=bound["generation"]).binding_digest


def make_plan(spans=(("warmup", 0, 2), ("stationary", 3, 8),
                      ("quiescent", 9, 11)),
              binds=None, permitted=(), profile_ref="prof-1"):
    nslots = max(b for _, _, b in spans) + 1
    if binds is None:
        binds = [make_binding()]
    return {
        "schema": soak.SCHEMA_ID, "plan_id": "plan-1", "run_ref": "run-1",
        "source_ref": "src-1", "artifact_ref": "art-1",
        "workload_ref": "wl-1", "profile_ref": profile_ref,
        "phases": [{"phase_id": p, "workload_ref": "wl-1",
                    "first_slot": a, "last_slot": b} for p, a, b in spans],
        "cadence_ms": 100, "expected_slots": nslots,
        "bindings": binds,
        "permitted_lifecycle_updates": list(permitted),
        "optional_counters": [],
        "limits": dict(PLAN_LIMITS),
        "hard_deadline_required": False,
    }


def make_profile(spans, nslots, qualification="qualified", revision=1,
                 growth_counters=("private_commit_bytes",),
                 recovery_counters=("working_set_bytes",),
                 bound_ws=10 ** 9, bound_pc=10 ** 9, bound_h=10 ** 9,
                 coverage=(9, 10, 2, True), window_slots=3):
    qualified = qualification == "qualified"
    return {
        "schema": analysis.PROFILE_SCHEMA_ID, "profile_ref": "prof-1",
        "revision": revision,
        "applicability": {"sample_schema": soak.SCHEMA_ID,
                          "source_ref": "src-1", "workload_ref": "wl-1"},
        "qualification": {
            "status": qualification,
            "qualification_ref": "q-1" if qualified else "",
            "issuer_ref": "issuer-1" if qualified else ""},
        "counters": [{"name": "working_set_bytes", "unit": "bytes"},
                     {"name": "private_commit_bytes", "unit": "bytes"},
                     {"name": "handle_count", "unit": "count"}],
        "expected": {"cadence_ms": 100, "expected_slots": nslots},
        "phase_roles": [{"phase_id": p, "role": p} for p, _, _ in spans],
        "window_slots": window_slots,
        "coverage": {"min_coverage_num": coverage[0],
                     "min_coverage_den": coverage[1],
                     "max_gap_slots": coverage[2],
                     "require_terminal": coverage[3]},
        "absolute_bounds": [
            {"name": "working_set_bytes", "max_value": bound_ws},
            {"name": "private_commit_bytes", "max_value": bound_pc},
            {"name": "handle_count", "max_value": bound_h}],
        "growth": {"statistic": "last", "consecutive_windows": 2,
                   "allowed_delta": 0, "applies_to_roles": ["stationary"],
                   "counters": list(growth_counters)},
        "recovery": {"baseline_role": "stationary",
                     "baseline_selector": "last_window",
                     "quiescent_role": "quiescent",
                     "quiescent_selector": "last_window",
                     "statistic": "last", "tolerance": 100,
                     "counters": list(recovery_counters)},
        "algorithm_revision": "fixed-window-v1",
        "limits": dict(ANALYSIS_LIMITS),
    }


def make_evidence(plan, profile, ops="default", restarts=(),
                  cancelled=False, cleanup=("verified_clean", "issuer-1")):
    if ops == "default":
        ops = [{"op_ref": "op-1", "phase_id": "stationary", "required": True,
                "expected": "success", "observed": "success",
                "producer_attested": True}]
    return {
        "schema": analysis.RUN_EVIDENCE_SCHEMA_ID,
        "producer": {"producer_ref": "prod-1", "evidence_ref": "ev-1"},
        "commitment": {
            "plan_id": "plan-1", "profile_ref": "prof-1",
            "profile_revision": profile["revision"],
            "qualification_ref": "q-1",
            "source_ref": "src-1", "artifact_ref": "art-1",
            "committed_before_workload": True,
            "plan_digest": plan.plan_digest,
            "profile_digest": analysis.profile_content_digest(
                analysis.validate_analysis_profile(profile))},
        "phases": [{"phase_id": p.phase_id, "first_slot": p.first_slot,
                    "last_slot": p.last_slot} for p in plan.phases],
        "operations": list(ops),
        "restarts": list(restarts),
        "cancellation": {"cancelled": cancelled, "detail": "none"},
        "crashes": [],
        "cleanup": {"disposition": cleanup[0], "issuer_ref": cleanup[1],
                    "detail": "ok"},
    }


def phase_at(spans, slot):
    for phase_id, first, last in spans:
        if first <= slot <= last:
            return phase_id
    raise AssertionError(f"slot {slot} outside spans")


def stream_of(bound, digest):
    return {"owner_ref": bound["owner_ref"], "component": bound["component"],
            "pid": bound["pid"], "generation": bound["generation"],
            "binding_digest": digest}


def sample_record(spans, bound, digest, plan_digest, slot, ws, pc, h):
    return {
        "schema": soak.SCHEMA_ID, "kind": "sample", "run_ref": "run-1",
        "plan_id": "plan-1", "plan_digest": plan_digest,
        "source_ref": "src-1", "artifact_ref": "art-1",
        "stream": stream_of(bound, digest),
        "seq": 0, "slot": slot, "elapsed_ms": slot * 100,
        "phase_id": phase_at(spans, slot), "workload_ref": "wl-1",
        "counters": [
            {"name": "working_set_bytes", "value": ws, "unit": "bytes",
             "status": "ok"},
            {"name": "private_commit_bytes", "value": pc, "unit": "bytes",
             "status": "ok"},
            {"name": "handle_count", "value": h, "unit": "count",
             "status": "ok"},
        ],
    }


def terminal_record(spans, bound, digest, plan_digest, slot, last_phase=None):
    return {
        "schema": soak.SCHEMA_ID, "kind": "terminal", "run_ref": "run-1",
        "plan_id": "plan-1", "plan_digest": plan_digest,
        "source_ref": "src-1", "artifact_ref": "art-1",
        "stream": stream_of(bound, digest),
        "seq": 0, "slot": slot, "elapsed_ms": slot * 100,
        "phase_id": last_phase or spans[-1][0], "workload_ref": "wl-1",
        "event": {"code": "run_complete"},
    }


def lifecycle_record(spans, bound, digest, plan_digest, slot, code, detail):
    return {
        "schema": soak.SCHEMA_ID, "kind": "lifecycle", "run_ref": "run-1",
        "plan_id": "plan-1", "plan_digest": plan_digest,
        "source_ref": "src-1", "artifact_ref": "art-1",
        "stream": stream_of(bound, digest),
        "seq": 0, "slot": slot, "elapsed_ms": slot * 100,
        "phase_id": phase_at(spans, slot), "workload_ref": "wl-1",
        "event": {"code": code, "detail": detail},
    }


def missed_record(spans, bound, digest, plan_digest, slot):
    return {
        "schema": soak.SCHEMA_ID, "kind": "missed_slot", "run_ref": "run-1",
        "plan_id": "plan-1", "plan_digest": plan_digest,
        "source_ref": "src-1", "artifact_ref": "art-1",
        "stream": stream_of(bound, digest),
        "seq": 0, "slot": slot, "elapsed_ms": slot * 100,
        "phase_id": phase_at(spans, slot), "workload_ref": "wl-1",
        "event": {"code": "slot_missed", "detail": "slot_missed"},
    }


def number(records):
    """Assign per-stream sequence numbers in arrival order (a valid transport
    must carry strictly increasing seq per stream; callers interleave)."""
    counters: Dict[str, int] = {}
    for record in records:
        key = str(record["stream"]["binding_digest"])
        counters[key] = counters.get(key, 0) + 1
        record["seq"] = counters[key]
    return records


def analyze(records, plan_dict_obj, profile, evidence):
    return analysis.analyze_samples(
        number(records), plan_dict_obj, profile, evidence)


def world(spans=(("warmup", 0, 2), ("stationary", 3, 8),
                 ("quiescent", 9, 11)), **profile_kw):
    plan_d = make_plan(spans=spans)
    plan = soak.validate_sampling_plan(plan_d)
    nslots = max(b for _, _, b in spans) + 1
    profile = make_profile(spans, nslots, **profile_kw)
    evidence = make_evidence(plan, profile)
    bound = make_binding()
    digest = binding_digest_of(bound)
    return plan_d, plan, profile, evidence, bound, digest


class SoakAnalysisCases(unittest.TestCase):
    # WORK_UNIT_CASE: 943/1
    def test_qualified_complete_plateau_gets_only_bounded_claim(self):
        spans = (("warmup", 0, 2), ("stationary", 3, 8),
                 ("quiescent", 9, 11))
        plan_d, plan, profile, evidence, bound, digest = world(spans=spans)
        records = [sample_record(spans, bound, digest, plan.plan_digest, s,
                                 1000, 2000, 50) for s in range(12)]
        records.append(terminal_record(spans, bound, digest,
                                       plan.plan_digest, 12))
        result = analyze(records, plan_d, profile, evidence)
        self.assertEqual(result.disposition,
                         "ObservedWithinQualifiedEnvelope")
        self.assertEqual(list(result.violations), [])
        for axis in result.axes:
            self.assertEqual(axis.status, "satisfied", axis)
        # The claim names the observed run only: no leak-free language.
        self.assertNotIn("leak", (result.disposition + str(result.axes)).lower()
                         .replace("leak-free", ""))
        self.assertTrue(result.semantic_digest.startswith(
            "eliot.soak_analysis/v1:sha256:"))
        self.assertIn("accepted=13", result.transport_digest)

    # WORK_UNIT_CASE: 943/2
    def test_sustained_private_commit_growth_breaches_fixed_rule(self):
        spans = (("warmup", 0, 2), ("stationary", 3, 11),
                 ("quiescent", 12, 13))
        plan_d, plan, profile, evidence, bound, digest = world(spans=spans)
        values = [2000, 2000, 2000] + [2000 + 100 * (s - 2) for s in range(3, 12)]
        values += [2900, 2900]
        records = [sample_record(spans, bound, digest, plan.plan_digest, s,
                                 1000, values[s], 50) for s in range(14)]
        records.append(terminal_record(spans, bound, digest,
                                       plan.plan_digest, 14))
        result = analyze(records, plan_d, profile, evidence)
        self.assertEqual(result.disposition, "ResourceViolation")
        growth = [v for v in result.violations if v["rule"] == "growth"]
        self.assertTrue(growth, result.violations)
        self.assertEqual(growth[0]["counter"], "private_commit_bytes")
        self.assertEqual(growth[0]["phase"], "stationary")

    # WORK_UNIT_CASE: 943/3
    def test_handle_growth_is_independent_from_stable_memory(self):
        spans = (("warmup", 0, 2), ("stationary", 3, 11),
                 ("quiescent", 12, 13))
        plan_d, plan, profile, evidence, bound, digest = world(
            spans=spans, growth_counters=("handle_count",))
        handles = [50, 50, 50] + [50 + 10 * (s - 2) for s in range(3, 12)]
        handles += [140, 140]
        records = [sample_record(spans, bound, digest, plan.plan_digest, s,
                                 1000, 2000, handles[s]) for s in range(14)]
        records.append(terminal_record(spans, bound, digest,
                                       plan.plan_digest, 14))
        result = analyze(records, plan_d, profile, evidence)
        self.assertEqual(result.disposition, "ResourceViolation")
        growth = [v for v in result.violations if v["rule"] == "growth"]
        self.assertTrue(growth)
        self.assertTrue(all(v["counter"] == "handle_count" for v in growth))
        self.assertFalse([v for v in result.violations
                          if v["counter"] in ("working_set_bytes",
                                              "private_commit_bytes")])

    # WORK_UNIT_CASE: 943/4
    def test_warmup_growth_differs_from_stationary_growth(self):
        spans = (("warmup", 0, 2), ("stationary", 3, 11),
                 ("quiescent", 12, 13))
        # Warm-up-only rise: the predeclared rule judges stationary only.
        plan_d, plan, profile, evidence, bound, digest = world(spans=spans)
        values = [2000, 2300, 2600] + [2600] * 11
        records = [sample_record(spans, bound, digest, plan.plan_digest, s,
                                 1000, values[s], 50) for s in range(14)]
        records.append(terminal_record(spans, bound, digest,
                                       plan.plan_digest, 14))
        result = analyze(records, plan_d, profile, evidence)
        self.assertEqual(result.disposition, "ObservedWithinQualifiedEnvelope")
        self.assertFalse([v for v in result.violations
                          if v["rule"] == "growth"])
        # Continuing stationary rise: the same fixed rule fires.
        values = [2000] * 3 + [2000 + 100 * (s - 2) for s in range(3, 12)]
        values += [2900, 2900]
        records = [sample_record(spans, bound, digest, plan.plan_digest, s,
                                 1000, values[s], 50) for s in range(14)]
        records.append(terminal_record(spans, bound, digest,
                                       plan.plan_digest, 14))
        result = analyze(records, plan_d, profile, evidence)
        self.assertEqual(result.disposition, "ResourceViolation")
        self.assertTrue([v for v in result.violations
                         if v["rule"] == "growth"
                         and v["phase"] == "stationary"])

    # WORK_UNIT_CASE: 943/5
    def test_quiescent_recovery_failure_stays_visible(self):
        spans = (("warmup", 0, 2), ("stationary", 3, 8),
                 ("quiescent", 9, 11))
        plan_d, plan, profile, evidence, bound, digest = world(spans=spans)
        values = [1000] * 9 + [5000, 5000, 5000]
        records = [sample_record(spans, bound, digest, plan.plan_digest, s,
                                 values[s], 2000, 50) for s in range(12)]
        records.append(terminal_record(spans, bound, digest,
                                       plan.plan_digest, 12))
        result = analyze(records, plan_d, profile, evidence)
        self.assertEqual(result.disposition, "ResourceViolation")
        recovery = [v for v in result.violations if v["rule"] == "recovery"]
        self.assertTrue(recovery, result.violations)
        self.assertEqual(recovery[0]["counter"], "working_set_bytes")

    # WORK_UNIT_CASE: 943/6
    def test_restart_generation_gets_own_interval_never_spliced(self):
        spans = (("warmup", 0, 2), ("stationary", 3, 8),
                 ("quiescent", 9, 11))
        plan_d = make_plan(spans=spans, binds=[make_binding(gen="g0")],
                           permitted=["replace_generation"])
        plan = soak.validate_sampling_plan(plan_d)
        profile = make_profile(spans, 12)
        old, new = make_binding(gen="g0"), make_binding(gen="g1")
        d_old, d_new = binding_digest_of(old), binding_digest_of(new)
        evidence = make_evidence(plan, profile, restarts=(
            {"owner_ref": "o1", "component": "c1", "pid": 100,
             "old_generation": "g0", "new_generation": "g1", "slot": 6},))
        records = [sample_record(spans, old, d_old, plan.plan_digest, s,
                                 1000, 2000, 50) for s in range(6)]
        records.append(lifecycle_record(spans, old, d_old, plan.plan_digest,
                                        6, "process_replacement",
                                        "process_replaced"))
        records += [sample_record(spans, new, d_new, plan.plan_digest, s,
                                  1000, 2000, 50) for s in range(6, 12)]
        records.append(terminal_record(spans, new, d_new, plan.plan_digest,
                                       12))
        result = analyze(records, plan_d, profile, evidence)
        self.assertEqual(result.disposition, "ObservedWithinQualifiedEnvelope",
                         [a for a in result.axes])
        cov = result.coverage["streams"]
        self.assertEqual((cov[d_old]["active_start_slot"],
                          cov[d_old]["active_end_slot"]), (0, 5))
        self.assertEqual((cov[d_new]["active_start_slot"],
                          cov[d_new]["active_end_slot"]), (6, 11))
        self.assertEqual(cov[d_old]["closure_code"], "process_replacement")
        self.assertEqual(cov[d_new]["closure_code"], "run_complete")
        self.assertIn("replace_generation g0->g1 at slot 6",
                      cov[d_new]["replacement"])
        self.assertFalse([r for r in
                          result.axis("input_integrity_coverage").reasons
                          if "outside the active interval" in r])

    # WORK_UNIT_CASE: 943/7
    def test_missing_reordered_duplicate_truncated_fail_coverage(self):
        spans = (("warmup", 0, 2), ("stationary", 3, 8),
                 ("quiescent", 9, 11))
        plan_d, plan, profile, evidence, bound, digest = world(spans=spans)

        def full():
            recs = [sample_record(spans, bound, digest, plan.plan_digest, s,
                                  1000, 2000, 50) for s in range(12)]
            recs.append(terminal_record(spans, bound, digest,
                                        plan.plan_digest, 12))
            return recs

        # Missing slots break the coverage ratio.
        sparse = [r for r in full() if r["slot"] % 2 == 0
                  or r["kind"] == "terminal"]
        result = analyze(sparse, plan_d, profile, evidence)
        self.assertEqual(result.disposition, "IncompleteEvidence")
        # Reordered arrival within one stream is rejected, never re-sorted.
        recs = full()
        recs[4], recs[5] = recs[5], recs[4]
        result = analyze(recs, plan_d, profile, evidence)
        self.assertEqual(result.disposition, "IncompleteEvidence")
        self.assertGreater(result.records_rejected, 0)
        # An identical duplicate is rejected, never merged.
        recs = full() + [dict(full()[3])]
        result = analyze(recs, plan_d, profile, evidence)
        self.assertEqual(result.disposition, "IncompleteEvidence")
        self.assertGreater(result.records_rejected, 0)
        # A truncated run (no terminal) fails require_terminal.
        recs = [r for r in full() if r["kind"] != "terminal"]
        result = analyze(recs, plan_d, profile, evidence)
        self.assertEqual(result.disposition, "IncompleteEvidence")
        self.assertTrue([r for r in
                         result.axis("input_integrity_coverage").reasons
                         if "missing terminal record" in r])

    # WORK_UNIT_CASE: 943/8
    def test_access_denied_counter_remains_unknown(self):
        spans = (("warmup", 0, 2), ("stationary", 3, 8),
                 ("quiescent", 9, 11))
        plan_d, plan, profile, evidence, bound, digest = world(spans=spans)
        records = []
        for s in range(12):
            rec = sample_record(spans, bound, digest, plan.plan_digest, s,
                                1000, 2000, 50)
            rec["counters"][2] = {"name": "handle_count", "value": None,
                                  "unit": "count", "status": "unknown",
                                  "reason": "access_denied"}
            records.append(rec)
        records.append(terminal_record(spans, bound, digest,
                                       plan.plan_digest, 12))
        result = analyze(records, plan_d, profile, evidence)
        streams = result.measurements["streams"]
        only = next(iter(streams.values()))
        self.assertEqual(
            only["counters"]["handle_count"]["unknown_by_reason"],
            {"access_denied": 12})
        self.assertEqual(only["counters"]["handle_count"]["readings_ok"], 0)
        # Unknown is reported as unknown, never as a zero reading or a pass.
        self.assertFalse([v for v in result.violations
                          if v["counter"] == "handle_count"])
        self.assertNotEqual(result.disposition,
                            "ObservedWithinQualifiedEnvelope")

    # WORK_UNIT_CASE: 943/9
    def test_units_preserved_and_working_set_sum_is_non_unique(self):
        spans = (("warmup", 0, 2), ("stationary", 3, 8),
                 ("quiescent", 9, 11))
        plan_d, plan, profile, evidence, bound, digest = world(spans=spans)
        # A wrong unit is rejected input, not a re-labeled reading.
        recs = [sample_record(spans, bound, digest, plan.plan_digest, s,
                              1000, 2000, 50) for s in range(12)]
        recs[5]["counters"][0]["unit"] = "count"
        recs.append(terminal_record(spans, bound, digest,
                                    plan.plan_digest, 12))
        result = analyze(recs, plan_d, profile, evidence)
        self.assertEqual(result.disposition, "IncompleteEvidence")
        self.assertGreater(result.records_rejected, 0)
        # The aggregate working set is labeled non-unique, never system RSS.
        recs = [sample_record(spans, bound, digest, plan.plan_digest, s,
                              1000, 2000, 50) for s in range(12)]
        recs.append(terminal_record(spans, bound, digest,
                                    plan.plan_digest, 12))
        result = analyze(recs, plan_d, profile, evidence)
        total = result.measurements["non_unique_working_set"]
        self.assertEqual(total["label"], "non-unique-shared-pages")
        self.assertTrue(total["not_system_rss"])
        self.assertTrue(total["not_private_rss"])
        self.assertEqual(total["total_working_set_bytes"], 12 * 1000)

    # WORK_UNIT_CASE: 943/10
    def test_absent_unqualified_wrong_profile_cannot_accept(self):
        spans = (("warmup", 0, 2), ("stationary", 3, 8),
                 ("quiescent", 9, 11))
        plan_d, plan, profile, evidence, bound, digest = world(spans=spans)
        records = [sample_record(spans, bound, digest, plan.plan_digest, s,
                                 1000, 2000, 50) for s in range(12)]
        records.append(terminal_record(spans, bound, digest,
                                       plan.plan_digest, 12))
        # Absent profile: integrity failure, never accepted.
        result = analyze(records, plan_d, None, evidence)
        self.assertEqual(result.disposition, "IncompleteEvidence")
        # Exploratory profile: measurements only, never accepted.
        exploratory = make_profile(spans, 12, qualification="exploratory")
        result = analyze(records, plan_d, exploratory,
                         make_evidence(plan, exploratory))
        self.assertEqual(result.disposition, "InconclusiveProfile")
        # Wrong applicability: cannot justify acceptance.
        other = make_profile(spans, 12)
        other["applicability"] = dict(other["applicability"],
                                      workload_ref="wl-other")
        result = analyze(records, plan_d, other, make_evidence(plan, other))
        self.assertEqual(result.disposition, "InconclusiveProfile")

    # WORK_UNIT_CASE: 943/11
    def test_post_run_profile_substitution_is_rejected(self):
        spans = (("warmup", 0, 2), ("stationary", 3, 8),
                 ("quiescent", 9, 11))
        plan_d, plan, profile, evidence, bound, digest = world(spans=spans)
        records = [sample_record(spans, bound, digest, plan.plan_digest, s,
                                 1000, 2000, 50) for s in range(12)]
        records.append(terminal_record(spans, bound, digest,
                                       plan.plan_digest, 12))
        # Same refs, loosened bound after the run: the content digest moves.
        profile["absolute_bounds"] = [dict(x) for x in
                                      profile["absolute_bounds"]]
        profile["absolute_bounds"][1] = {"name": "private_commit_bytes",
                                         "max_value": 10 ** 9 + 1}
        result = analyze(records, plan_d, profile, evidence)
        self.assertEqual(result.disposition, "IncompleteEvidence")
        self.assertTrue([r for r in
                         result.axis("input_integrity_coverage").reasons
                         if "commitment.profile_digest" in r])
        # Same refs, bumped revision after the run: rejected as well.
        plan_d2, plan2, profile2, _, _, _ = world(spans=spans)
        evidence2 = make_evidence(plan2, profile2)
        profile2["revision"] = 2
        result = analyze(records, plan_d2, profile2, evidence2)
        self.assertEqual(result.disposition, "IncompleteEvidence")
        self.assertTrue([r for r in
                         result.axis("input_integrity_coverage").reasons
                         if "commitment.profile_revision" in r])

    # WORK_UNIT_CASE: 943/12
    def test_equal_endpoints_do_not_hide_an_observed_peak(self):
        spans = (("warmup", 0, 2), ("stationary", 3, 8),
                 ("quiescent", 9, 11))
        plan_d, plan, profile, evidence, bound, digest = world(
            spans=spans, bound_pc=2100)
        values = [2000] * 6 + [5000] + [2000] * 5
        records = [sample_record(spans, bound, digest, plan.plan_digest, s,
                                 1000, values[s], 50) for s in range(12)]
        records.append(terminal_record(spans, bound, digest,
                                       plan.plan_digest, 12))
        result = analyze(records, plan_d, profile, evidence)
        self.assertEqual(result.disposition, "ResourceViolation")
        bounds = [v for v in result.violations
                  if v["rule"] == "absolute_bound"]
        self.assertTrue(bounds, result.violations)
        self.assertEqual(bounds[0]["value"], 5000)
        self.assertEqual(bounds[0]["bound"], 2100)

    # WORK_UNIT_CASE: 943/13
    def test_workload_crash_cleanup_failures_prevent_acceptance(self):
        spans = (("warmup", 0, 2), ("stationary", 3, 8),
                 ("quiescent", 9, 11))
        plan_d, plan, profile, evidence, bound, digest = world(spans=spans)
        records = [sample_record(spans, bound, digest, plan.plan_digest, s,
                                 1000, 2000, 50) for s in range(12)]
        records.append(terminal_record(spans, bound, digest,
                                       plan.plan_digest, 12))
        # An authenticated required workload failure dominates the summary.
        failed = [dict(o) for o in evidence["operations"]]
        failed[0] = dict(failed[0], observed="failed")
        result = analyze(records, plan_d, profile,
                         dict(evidence, operations=failed))
        self.assertEqual(result.disposition, "WorkloadFailure")
        # A crash is a proven workload failure even with green resources.
        crashed = dict(evidence, crashes=[{"crash_ref": "c-1",
                                           "detail": "none", "slot": 7}])
        result = analyze(records, plan_d, profile, crashed)
        self.assertEqual(result.disposition, "WorkloadFailure")
        # Unknown cleanup blocks acceptance without claiming failure.
        unknown = dict(evidence, cleanup={"disposition": "unknown",
                                          "issuer_ref": "", "detail": "none"})
        result = analyze(records, plan_d, profile, unknown)
        self.assertEqual(result.disposition, "IncompleteEvidence")

    # WORK_UNIT_CASE: 943/14
    def test_boundary_arithmetic_rejects_invalid_and_nonfinite(self):
        spans = (("warmup", 0, 2), ("stationary", 3, 8),
                 ("quiescent", 9, 11))
        plan_d, plan, profile, evidence, bound, digest = world(
            spans=spans, bound_pc=2000)
        # An exact-boundary value passes.
        records = [sample_record(spans, bound, digest, plan.plan_digest, s,
                                 1000, 2000, 50) for s in range(12)]
        records.append(terminal_record(spans, bound, digest,
                                       plan.plan_digest, 12))
        result = analyze(records, plan_d, profile, evidence)
        self.assertEqual(result.disposition, "ObservedWithinQualifiedEnvelope")
        # One over the bound fails.
        records = [sample_record(spans, bound, digest, plan.plan_digest, s,
                                 1000, 2000, 50) for s in range(12)]
        records[7]["counters"][1]["value"] = 2001
        records.append(terminal_record(spans, bound, digest,
                                       plan.plan_digest, 12))
        result = analyze(records, plan_d, profile, evidence)
        self.assertEqual(result.disposition, "ResourceViolation")
        self.assertTrue([v for v in result.violations
                         if v["rule"] == "absolute_bound"
                         and v["value"] == 2001])
        # A non-finite value is rejected input, never a measurement.
        records = [sample_record(spans, bound, digest, plan.plan_digest, s,
                                 1000, 2000, 50) for s in range(12)]
        records[7]["counters"][1]["value"] = float("nan")
        records.append(terminal_record(spans, bound, digest,
                                       plan.plan_digest, 12))
        result = analyze(records, plan_d, profile, evidence)
        self.assertEqual(result.disposition, "IncompleteEvidence")
        self.assertGreater(result.records_rejected, 0)

    # WORK_UNIT_CASE: 943/15
    def test_equivalent_interleavings_share_semantic_digest(self):
        spans = (("warmup", 0, 2), ("stationary", 3, 8),
                 ("quiescent", 9, 11))
        binds = [make_binding(pid=100, gen="g0"),
                 make_binding(pid=200, gen="g0")]
        plan_d = make_plan(spans=spans, binds=binds)
        plan = soak.validate_sampling_plan(plan_d)
        profile = make_profile(spans, 12)
        evidence = make_evidence(plan, profile)
        digests = [binding_digest_of(b) for b in binds]

        def stream_records(bound, digest):
            recs = [sample_record(spans, bound, digest, plan.plan_digest, s,
                                  1000 + s, 2000, 50) for s in range(12)]
            recs.append(terminal_record(spans, bound, digest,
                                        plan.plan_digest, 12))
            return recs

        left = stream_records(binds[0], digests[0])
        right = stream_records(binds[1], digests[1])
        round_robin = [r for pair in zip(left, right) for r in pair]
        grouped = list(left) + list(right)
        first = analyze(round_robin, plan_d, profile, evidence)
        second = analyze(grouped, plan_d, profile, evidence)
        self.assertEqual(first.disposition, "ObservedWithinQualifiedEnvelope")
        self.assertEqual(second.disposition, "ObservedWithinQualifiedEnvelope")
        self.assertEqual(first.semantic_digest, second.semantic_digest)
        # Disorder inside one stream is rejected, never accepted.
        broken = list(left) + list(right)
        broken[2], broken[5] = broken[5], broken[2]
        result = analyze(broken, plan_d, profile, evidence)
        self.assertEqual(result.disposition, "IncompleteEvidence")
        self.assertGreater(result.records_rejected, 0)

    # WORK_UNIT_CASE: 943/16
    def test_large_finite_input_respects_bounds_without_side_effects(self):
        spans = (("warmup", 0, 99), ("stationary", 100, 899),
                 ("quiescent", 900, 999))
        binds = [make_binding(pid=100 + i, gen="g0") for i in range(3)]
        plan_d = make_plan(spans=spans, binds=binds)
        plan = soak.validate_sampling_plan(plan_d)
        profile = make_profile(spans, 1000, window_slots=100)
        evidence = make_evidence(plan, profile)
        records = []
        for bound in binds:
            digest = binding_digest_of(bound)
            for s in range(1000):
                records.append(sample_record(spans, bound, digest,
                                             plan.plan_digest, s,
                                             1000, 2000, 50))
            records.append(terminal_record(spans, bound, digest,
                                           plan.plan_digest, 1000))
        before = set((plan_d["plan_id"],))  # no fixture writes expected
        result = analyze(records, plan_d, profile, evidence)
        self.assertEqual(before, set((plan_d["plan_id"],)))
        self.assertEqual(result.disposition, "ObservedWithinQualifiedEnvelope")
        self.assertEqual(result.records_accepted, 3003)
        self.assertFalse(result.limits_exceeded)
        self.assertLessEqual(result.work_units_consumed,
                             profile["limits"]["max_work_units"])
        self.assertEqual(result.coverage["provenance"]["synthesized_records"],
                         3003)

    # WORK_UNIT_CASE: 943/W7
    def test_unevaluated_rules_block_acceptance(self):
        spans = (("warmup", 0, 2), ("stationary", 3, 8),
                 ("quiescent", 9, 11))
        plan_d, plan, profile, evidence, bound, digest = world(spans=spans)
        profile["growth"] = dict(profile["growth"], counters=[])
        profile["recovery"] = dict(profile["recovery"], counters=[])
        evidence = make_evidence(plan, profile)
        records = [sample_record(spans, bound, digest, plan.plan_digest, s,
                                 1000, 2000, 50) for s in range(12)]
        records.append(terminal_record(spans, bound, digest,
                                       plan.plan_digest, 12))
        result = analyze(records, plan_d, profile, evidence)
        self.assertEqual(result.axis("resource").status, "unknown")
        self.assertTrue([r for r in result.axis("resource").reasons
                         if r.startswith("not_evaluated:")])
        self.assertNotEqual(result.disposition,
                            "ObservedWithinQualifiedEnvelope")


if __name__ == "__main__":
    unittest.main()
