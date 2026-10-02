"""Deterministic coordinator tests for serialized trust-boundary closure (#710, Slice B).

Declared denominator: 20 cases, exactly 1..20.
Slice B owns tests plus frozen synthetic fixtures only; the 20 fixture cases
below never import the checker, so they stay independent of its code.
Issue #2701 adds the fake-API admission regressions at the end of this file
(``CheckedInventoryAdmissionTests``): that class loads the coordinator by path
because #2701's required completion 8 puts the smallest API-failure
regressions here. Frozen fixtures live under scripts/testdata/serde-boundary-closure/.

Base: dfa3547e62544e4df311a61a8ff3c61b629f89f7
Branch: work/710-serde-closure-tests
"""

from __future__ import annotations

import ast
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
COORDINATOR_SCRIPT = REPO_ROOT / "scripts" / "audit-serde-boundary-closure.py"
INVENTORY_SCRIPT = REPO_ROOT / "scripts" / "serde_boundary_inventory.py"
FIXTURE_DIR = REPO_ROOT / "scripts" / "testdata" / "serde-boundary-closure"

_coordinator_spec = importlib.util.spec_from_file_location(
    "audit_serde_boundary_closure", COORDINATOR_SCRIPT
)
assert _coordinator_spec is not None and _coordinator_spec.loader is not None
coordinator = importlib.util.module_from_spec(_coordinator_spec)
sys.modules[_coordinator_spec.name] = coordinator
_coordinator_spec.loader.exec_module(coordinator)

FROZEN_FIXTURES = [
    "case-01-denominator.json",
    "case-02-disposition-map.json",
    "case-03-positive-envelope.json",
    "case-04-unknown-envelope-field.json",
    "case-05-nested-unknown-field.json",
    "case-06-duplicate-keys.raw.json",
    "case-07-unknown-variant.json",
    "case-08-tag-payload-mismatch.json",
    "case-09-defaulted-identity.json",
    "case-10-flatten-bypass.json",
    "case-11-normalization-loss.json",
    "case-12-unsupported-legacy.json",
    "case-13-supported-legacy-dualform.json",
    "case-14-unsafe-migration.json",
    "case-15-canonical-golden.json",
    "case-16-internal-only.json",
    "case-17-specific-owner.json",
    "case-18-malformed.json",
    "case-19-bounded-ingress.json",
    "case-20-evidence-digest.json",
]

ALLOWED_TOP_FIELDS = frozenset(
    {
        "protocol_version",
        "message_type",
        "schema_version",
        "authority",
        "scope",
        "identity",
        "payload",
        "trace_context",
    }
)
REQUIRED_PROTECTED_FIELDS = frozenset({"authority", "scope", "identity"})
ALLOWED_PAYLOAD_FIELDS = frozenset({"kind", "request_id", "state_fence"})
KNOWN_VARIANTS = frozenset(
    {"request", "response", "event", "cancel", "heartbeat", "control"}
)
SUPPORTED_SCHEMA_VERSIONS = frozenset({"v1"})
SUPPORTED_LEGACY_VERSIONS = frozenset({"v0-legacy"})
ALLOWED_DISPOSITIONS = frozenset({"covered", "no-applicable-row"})


def canonical_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_fixture(name: str) -> dict:
    path = FIXTURE_DIR / name
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def find_duplicate_keys(raw_text: str) -> list:
    duplicates: list = []

    def hook(pairs):
        seen: set = set()
        for key, _value in pairs:
            if key in seen:
                duplicates.append(key)
            seen.add(key)
        return dict(pairs)

    json.loads(raw_text, object_pairs_hook=hook)
    return duplicates


def has_unknown_top(envelope: dict) -> bool:
    return any(key not in ALLOWED_TOP_FIELDS for key in envelope)


def unknown_top_fields(envelope: dict) -> set:
    return {key for key in envelope if key not in ALLOWED_TOP_FIELDS}


def has_unknown_nested(payload: dict) -> bool:
    return any(key not in ALLOWED_PAYLOAD_FIELDS for key in payload)


def validate_disposition_map(candidates, allowed) -> tuple:
    seen: set = set()
    for row in candidates:
        row_id = row.get("id")
        disp = row.get("disposition")
        if not row_id or not disp:
            return False, "missing-id-or-disposition"
        if row_id in seen:
            return False, "duplicate-id:%s" % row_id
        seen.add(row_id)
        if disp not in allowed:
            return False, "unknown-disposition:%s" % disp
    return True, "ok"


def object_depth(obj, level: int = 0) -> int:
    if isinstance(obj, dict):
        if not obj:
            return level + 1
        return max(object_depth(v, level + 1) for v in obj.values())
    if isinstance(obj, list):
        if not obj:
            return level + 1
        return max(object_depth(v, level + 1) for v in obj)
    return level + 1


class SerdeBoundaryClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        missing = [n for n in FROZEN_FIXTURES if not (FIXTURE_DIR / n).is_file()]
        assert not missing, "missing frozen fixtures: %r" % (missing,)

    # WORK_UNIT_CASE: 710/1
    def test_01_denominator_invalidation(self) -> None:
        fix = load_fixture("case-01-denominator.json")
        core = {
            "release": fix["release"],
            "packages": fix["packages"],
            "targets": fix["targets"],
            "features": fix["features"],
            "source_digest": fix["source_digest"],
            "inventory_digest": fix["inventory_digest"],
            "profile_digest": fix["profile_digest"],
        }
        recomputed = sha256_hex(canonical_bytes(core))
        self.assertEqual(fix["denominator_digest"], recomputed)
        tampered = dict(core)
        tampered["source_digest"] = "0" * 64
        self.assertNotEqual(sha256_hex(canonical_bytes(tampered)), fix["denominator_digest"])
        tampered_profile = dict(core)
        tampered_profile["profile_digest"] = "f" * 64
        self.assertNotEqual(
            sha256_hex(canonical_bytes(tampered_profile)), fix["denominator_digest"]
        )
        self.assertTrue(fix["packages"])
        self.assertTrue(fix["targets"])
        self.assertTrue(fix["features"])

    # WORK_UNIT_CASE: 710/2
    def test_02_single_disposition_per_candidate(self) -> None:
        fix = load_fixture("case-02-disposition-map.json")
        ok, reason = validate_disposition_map(
            fix["candidates"], set(fix["allowed_dispositions"])
        )
        self.assertTrue(ok, reason)
        self.assertEqual(set(fix["allowed_dispositions"]), set(ALLOWED_DISPOSITIONS))
        dup = list(fix["candidates"]) + [dict(fix["candidates"][0])]
        ok_dup, _ = validate_disposition_map(dup, set(fix["allowed_dispositions"]))
        self.assertFalse(ok_dup)
        missing_disp = [{"id": "row-9"}]
        ok_missing, _ = validate_disposition_map(missing_disp, set(fix["allowed_dispositions"]))
        self.assertFalse(ok_missing)
        unknown_disp = [{"id": "row-9", "disposition": "maybe"}]
        ok_unknown, _ = validate_disposition_map(unknown_disp, set(fix["allowed_dispositions"]))
        self.assertFalse(ok_unknown)
        extra = list(fix["candidates"]) + [{"id": "row-extra", "disposition": "bogus"}]
        ok_extra, _ = validate_disposition_map(extra, set(fix["allowed_dispositions"]))
        self.assertFalse(ok_extra)

    # WORK_UNIT_CASE: 710/3
    def test_03_positive_envelope_accepted(self) -> None:
        fix = load_fixture("case-03-positive-envelope.json")
        env = fix["raw_envelope"]
        self.assertEqual(fix["expected"], "accept")
        self.assertFalse(has_unknown_top(env))
        self.assertTrue(REQUIRED_PROTECTED_FIELDS.issubset(env.keys()))
        self.assertIn(env["message_type"], KNOWN_VARIANTS)
        self.assertIn(env["schema_version"], SUPPORTED_SCHEMA_VERSIONS)
        self.assertFalse(has_unknown_nested(env["payload"]))
        self.assertEqual(env["message_type"], env["payload"]["kind"])
        self.assertNotEqual(find_duplicate_keys(json.dumps(env)), ["x-missing"])

    # WORK_UNIT_CASE: 710/4
    def test_04_unknown_envelope_field_rejected(self) -> None:
        fix = load_fixture("case-04-unknown-envelope-field.json")
        env = fix["raw_envelope"]
        self.assertEqual(fix["expected"], "reject")
        self.assertTrue(has_unknown_top(env))
        self.assertIn(fix["unknown_field"], unknown_top_fields(env))
        self.assertNotIn(fix["unknown_field"], ALLOWED_TOP_FIELDS)
        positive = load_fixture("case-03-positive-envelope.json")["raw_envelope"]
        self.assertFalse(has_unknown_top(positive))

    # WORK_UNIT_CASE: 710/5
    def test_05_nested_unknown_field_rejected(self) -> None:
        fix = load_fixture("case-05-nested-unknown-field.json")
        env = fix["raw_envelope"]
        self.assertEqual(fix["expected"], "reject")
        self.assertFalse(has_unknown_top(env))
        self.assertTrue(has_unknown_nested(env["payload"]))
        self.assertIn(fix["unknown_nested_field"], set(env["payload"].keys()))
        self.assertNotIn(fix["unknown_nested_field"], ALLOWED_PAYLOAD_FIELDS)

    # WORK_UNIT_CASE: 710/6
    def test_06_duplicate_keys_rejected(self) -> None:
        fix = load_fixture("case-06-duplicate-keys.raw.json")
        dups = find_duplicate_keys(fix["raw_text"])
        self.assertEqual(fix["expected"], "reject")
        self.assertIn(fix["duplicate_key"], dups)
        for key in ("message_type", "identity", "authority"):
            raw = (
                '{"protocol_version": "v1", "message_type": "request", '
                '"schema_version": "v1", "authority": "kernel", '
                '"scope": "task:123", "identity": "principal:alice", '
                '"payload": {"kind": "request"}}'
            )
            raw_dup = raw.replace('"%s":' % key, '"%s": "evil", "%s":' % (key, key), 1)
            self.assertIn(key, find_duplicate_keys(raw_dup))
        self.assertEqual(find_duplicate_keys('{"a": 1, "b": 2}'), [])

    # WORK_UNIT_CASE: 710/7
    def test_07_unknown_variant_rejected(self) -> None:
        fix = load_fixture("case-07-unknown-variant.json")
        self.assertEqual(fix["expected"], "reject")
        self.assertNotIn(fix["message_type"], KNOWN_VARIANTS)
        self.assertNotIn(fix["raw_envelope"]["message_type"], KNOWN_VARIANTS)
        self.assertEqual(set(fix["known_variants"]), set(KNOWN_VARIANTS))
        for known in ("request", "response", "event"):
            self.assertIn(known, KNOWN_VARIANTS)

    # WORK_UNIT_CASE: 710/8
    def test_08_tag_payload_mismatch_rejected(self) -> None:
        fix = load_fixture("case-08-tag-payload-mismatch.json")
        env = fix["raw_envelope"]
        self.assertEqual(fix["expected"], "reject")
        self.assertEqual(fix["tag"], env["message_type"])
        self.assertEqual(fix["payload_kind"], env["payload"]["kind"])
        self.assertNotEqual(env["message_type"], env["payload"]["kind"])
        positive = load_fixture("case-03-positive-envelope.json")["raw_envelope"]
        self.assertEqual(positive["message_type"], positive["payload"]["kind"])

    # WORK_UNIT_CASE: 710/9
    def test_09_defaults_cannot_invent_identity(self) -> None:
        fix = load_fixture("case-09-defaulted-identity.json")
        env = fix["raw_envelope"]
        self.assertEqual(fix["expected"], "reject")
        for field in fix["missing_fields"]:
            self.assertNotIn(field, env)
        self.assertFalse(REQUIRED_PROTECTED_FIELDS.issubset(env.keys()))
        validated = dict(env)
        for field in REQUIRED_PROTECTED_FIELDS:
            self.assertNotIn(field, validated.setdefault(field, validated.get(field, "__absent__")) if field in validated else "__absent__")
        self.assertNotIn("identity", env)

    # WORK_UNIT_CASE: 710/10
    def test_10_flatten_bypass_blocked(self) -> None:
        fix = load_fixture("case-10-flatten-bypass.json")
        env = fix["raw_envelope"]
        self.assertEqual(fix["expected"], "reject")
        self.assertEqual(fix["bypass_kind"], "flatten")
        self.assertNotIn("payload", env)
        self.assertNotIn("identity", env)
        self.assertIn("ident", env)
        self.assertTrue(has_unknown_top(env))

    # WORK_UNIT_CASE: 710/11
    def test_11_normalization_cannot_erase_evidence(self) -> None:
        fix = load_fixture("case-11-normalization-loss.json")
        dups = find_duplicate_keys(fix["raw_text"])
        self.assertTrue(dups)
        normalized = fix["normalized_envelope"]
        self.assertFalse(has_unknown_top(normalized))
        self.assertEqual(find_duplicate_keys(json.dumps(normalized)), [])
        self.assertIn("reject-raw", fix["expected"])
        parsed_once = json.loads(fix["raw_text"])
        self.assertEqual(parsed_once, normalized)

    # WORK_UNIT_CASE: 710/12
    def test_12_unsupported_legacy_rejected(self) -> None:
        fix = load_fixture("case-12-unsupported-legacy.json")
        self.assertEqual(fix["expected"], "reject")
        self.assertNotIn(fix["schema_version"], SUPPORTED_SCHEMA_VERSIONS)
        self.assertNotIn(fix["schema_version"], SUPPORTED_LEGACY_VERSIONS)
        self.assertEqual(fix["raw_envelope"]["schema_version"], fix["schema_version"])

    # WORK_UNIT_CASE: 710/13
    def test_13_supported_legacy_dualform_accepted(self) -> None:
        fix = load_fixture("case-13-supported-legacy-dualform.json")
        self.assertEqual(fix["expected"], "accept-with-migration-proof")
        self.assertEqual(fix["owner"], "#976")
        self.assertEqual(fix["precedence"], "form-a-then-b-dual")
        self.assertTrue(fix["migration_proof"])
        self.assertTrue(fix["loss"])
        form_a = fix["legacy_form_a"]
        form_b = fix["legacy_form_b"]
        self.assertIn(form_a["envelope_version"], SUPPORTED_LEGACY_VERSIONS)
        self.assertIn(form_b["envelope_version"], SUPPORTED_LEGACY_VERSIONS)
        decoded = json.loads(base64.b64decode(form_a["body_base64"]).decode("utf-8"))
        self.assertEqual(decoded, form_a["body_legacy"])
        self.assertEqual(decoded, form_b["body"])

    # WORK_UNIT_CASE: 710/14
    def test_14_unsafe_migration_rejected(self) -> None:
        fix = load_fixture("case-14-unsafe-migration.json")
        env = fix["migrated_envelope"]
        self.assertEqual(fix["expected"], "reject")
        for field in fix["missing"]:
            self.assertNotIn(field, env)
            self.assertNotIn(field, json.dumps(env))

    # WORK_UNIT_CASE: 710/15
    def test_15_canonical_golden_preserved(self) -> None:
        fix = load_fixture("case-15-canonical-golden.json")
        raw = fix["canonical_bytes"].encode("utf-8")
        self.assertEqual(sha256_hex(raw), fix["digest"])
        parsed = json.loads(fix["canonical_bytes"])
        self.assertEqual(sha256_hex(canonical_bytes(parsed)), fix["digest"])
        versioned = dict(parsed)
        versioned["schema_version"] = "v2"
        self.assertNotEqual(sha256_hex(canonical_bytes(versioned)), fix["digest"])
        self.assertEqual(fix["schema_version"], "v1")

    # WORK_UNIT_CASE: 710/16
    def test_16_internal_only_exact_and_invalidated(self) -> None:
        fix = load_fixture("case-16-internal-only.json")
        exc = fix["exception"]
        self.assertEqual(fix["expected"], "invalidate-on-new-caller")
        self.assertEqual(exc["callers"], ["crates/eliot-engine/src/context.rs"])
        self.assertNotIn(fix["new_caller"], exc["callers"])
        extended = list(exc["callers"]) + [fix["new_caller"]]
        self.assertNotEqual(extended, exc["callers"])

    # WORK_UNIT_CASE: 710/17
    def test_17_specific_owner_covered_with_profile(self) -> None:
        fix = load_fixture("case-17-specific-owner.json")
        self.assertEqual(fix["expected"], "accept-with-profile")
        self.assertEqual(fix["owner"], "#977")
        profile = fix["profile"]
        self.assertGreater(profile["max_bytes"], 0)
        self.assertGreater(profile["max_members"], 0)
        self.assertGreater(profile["max_depth"], 0)
        env = fix["fixture"]
        self.assertFalse(has_unknown_top(env))
        self.assertTrue(REQUIRED_PROTECTED_FIELDS.issubset(env.keys()))
        size = len(canonical_bytes(env))
        self.assertLessEqual(size, profile["max_bytes"])
        self.assertLessEqual(len(env), profile["max_members"])
        self.assertLessEqual(object_depth(env), profile["max_depth"])

    # WORK_UNIT_CASE: 710/18
    def test_18_malformed_typed_rejection_no_panic(self) -> None:
        fix = load_fixture("case-18-malformed.json")
        self.assertEqual(fix["expected"], "reject-typed-error-no-panic")
        for key in ("raw_text_malformed", "raw_text_truncated"):
            with self.assertRaises(json.JSONDecodeError):
                json.loads(fix[key])

    # WORK_UNIT_CASE: 710/19
    def test_19_bounded_ingress_rejects_before_dispatch(self) -> None:
        fix = load_fixture("case-19-bounded-ingress.json")
        limits = fix["limits"]
        env = fix["raw_envelope"]
        size = len(canonical_bytes(env))
        self.assertGreater(size, limits["max_bytes"])
        self.assertGreater(fix["raw_size"], limits["max_bytes"])
        self.assertEqual(fix["expected"], "reject-before-dispatch")
        self.assertFalse(fix["dispatched"])
        self.assertEqual(fix["effects"], [])

    # WORK_UNIT_CASE: 710/20
    def test_20_evidence_digest_agreement(self) -> None:
        fix = load_fixture("case-20-evidence-digest.json")
        text_digest = sha256_hex(fix["text_output"].encode("utf-8"))
        json_digest = sha256_hex(canonical_bytes(fix["json_output"]))
        self.assertEqual(text_digest, fix["text_digest"])
        self.assertEqual(json_digest, fix["json_digest"])
        agreement = sha256_hex((text_digest + json_digest).encode("utf-8"))
        self.assertEqual(agreement, fix["agreement_digest"])
        self.assertEqual(fix["skipped"], [])
        self.assertEqual(fix["stale"], [])
        tampered = dict(fix["json_output"])
        tampered["coverage"] = "0/20"
        self.assertNotEqual(sha256_hex(canonical_bytes(tampered)), fix["json_digest"])


# ---------------------------------------------------------------------------
# #2701: fake-API admission regressions for the #929 checked-result boundary.
#
# ``producer_shaped_result`` is constructed from #929's own key names, not
# from a run: ``check(root)`` returns rows/digest/header,
# ``validate_against_artifact`` projects exactly candidate_id/id/disposition/
# owner/digest per row, and ``build_inventory`` names every header key. It
# therefore proves the admission boundary admits genuine producer output
# without a tree scan, and that the accepted key sets cannot silently drift
# narrower than the producer's own shape.
# ---------------------------------------------------------------------------

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
BASE_SHA = "d" * 40


def producer_shaped_result() -> dict:
    """A ``check(root)`` result with exactly #929's producer key names."""
    rows = [
        {
            "candidate_id": "cand.current",
            "id": "cand.current",
            "disposition": "current-closed",
            "owner": "#930",
            "digest": SHA_A,
        },
        {
            "candidate_id": "cand.repair",
            "id": "cand.repair",
            "disposition": "needs-repair",
            "owner": "#977",
            "digest": SHA_B,
        },
        {
            "candidate_id": "cand.unknown",
            "id": "cand.unknown",
            "disposition": "unknown",
            "owner": "unknown",
            "digest": SHA_C,
        },
    ]
    header = {
        "schema": "eliot.serde-boundary-inventory.v1",
        "tool_version": "0.5.0",
        "rule_revision": "929.5",
        "proof_ceiling": "SOURCE_INVENTORY_AND_OWNERSHIP_ONLY",
        "issue": 929,
        "base_sha": BASE_SHA,
        "base_sha_source": "git-rev-parse-HEAD",
        "provenance_authority": (
            "informational-observational-outside-proof-ceiling"
        ),
        "canonical_excludes": ["base_sha", "base_sha_source"],
        "denominator_status": "COMPLETE",
        "ambiguous_reason": "",
        "coverage": "COMPLETE",
        "family_readiness": "BLOCKED",
        "family_blocked_reason": "unknown-evidence: 1 rows need explicit resolution",
        "safety": "FINDINGS_REMAIN_BLOCKING",
        "candidate_count": len(rows),
        "classified_count": len(rows),
        "unknown_count": 1,
        # Only the unknown row has an empty #929 repair_child.
        "unassigned_count": 1,
        "ready_children": 1,
        "blocked_children": 1,
        "denominator_digest": SHA_B,
        "aggregate_digest": SHA_A,
    }
    return {"rows": rows, "digest": header["aggregate_digest"], "header": header}


def mutate(path: list, value) -> dict:
    """Return a fresh producer-shaped result with one nested value replaced."""
    result = producer_shaped_result()
    cursor = result
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    return result


def producer_source_key_names() -> tuple:
    """Read #929's own key names out of its source, without running it.

    ``build_inventory``'s header literal, ``validate_against_artifact``'s row
    projection and ``check``'s return value are the producer's real contract.
    Reading them here keeps the admission proof anchored to the producer
    instead of to this test's transcription of it.
    """
    tree = ast.parse(INVENTORY_SCRIPT.read_text(encoding="utf-8"))
    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
    }
    header_assign = next(
        node
        for node in ast.walk(functions["build_inventory"])
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "header"
            for target in node.targets
        )
        and isinstance(node.value, ast.Dict)
    )
    row_projection = next(
        node
        for node in ast.walk(functions["validate_against_artifact"])
        if isinstance(node, ast.Return)
        and isinstance(node.value, ast.ListComp)
        and isinstance(node.value.elt, ast.Dict)
    )
    result_shape = next(
        node
        for node in ast.walk(functions["check"])
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict)
    )
    return (
        {key.value for key in header_assign.value.keys},
        {key.value for key in row_projection.value.elt.keys},
        {key.value for key in result_shape.value.keys},
    )


class CheckedInventoryAdmissionTests(unittest.TestCase):
    """The admission boundary admits #929 output and refuses malformed output."""

    def assert_refused(self, result) -> str:
        with self.assertRaises(coordinator.InventoryUnavailable) as caught:
            coordinator._validate_checked_result(result)
        cause = str(caught.exception)
        self.assertTrue(
            cause.startswith("inventory contract failure:"), cause
        )
        return cause

    # WORK_UNIT_CASE: 2701/1
    def test_01_genuine_producer_shape_admitted(self) -> None:
        admitted = coordinator._validate_checked_result(producer_shaped_result())
        self.assertEqual(
            [row.candidate_id for row in admitted.rows],
            ["cand.current", "cand.repair", "cand.unknown"],
        )
        # Legitimate findings survive admission as findings.
        self.assertEqual(
            sorted({row.disposition for row in admitted.rows}),
            ["current-closed", "needs-repair", "unknown"],
        )
        self.assertEqual(admitted.aggregate_digest, SHA_A)
        self.assertEqual(admitted.denominator_digest, SHA_B)
        self.assertEqual(admitted.base_sha, BASE_SHA)
        self.assertEqual(admitted.candidate_count, 3)
        # The accepted key sets must never be narrower than #929's own shape:
        # a contract that refuses the real producer output breaks the tool.
        genuine = producer_shaped_result()
        self.assertEqual(
            set(coordinator.CHECKED_RESULT_REQUIRED_KEYS), set(genuine)
        )
        self.assertEqual(
            set(coordinator.CHECKED_ROW_REQUIRED_KEYS), set(genuine["rows"][0])
        )
        self.assertEqual(
            set(coordinator.CHECKED_HEADER_REQUIRED_KEYS), set(genuine["header"])
        )
        # Extra future keys are tolerated, not refused.
        extended = producer_shaped_result()
        extended["header"]["future_field"] = 1
        extended["rows"][0]["future_row_field"] = "x"
        self.assertEqual(len(coordinator._validate_checked_result(extended).rows), 3)
        # #929's own explicit unknown-base fallback stays admitted.
        fallback = mutate(["header", "base_sha"], coordinator.INVENTORY_UNKNOWN_BASE)
        self.assertEqual(
            coordinator._validate_checked_result(fallback).base_sha,
            coordinator.INVENTORY_UNKNOWN_BASE,
        )

    # WORK_UNIT_CASE: 2701/2
    def test_02_conflicting_row_identity_refused(self) -> None:
        cause = self.assert_refused(
            mutate(["rows", 0, "candidate_id"], "candidate-A")
        )
        self.assertIn("conflicting identities", cause)
        missing = producer_shaped_result()
        del missing["rows"][0]["id"]
        self.assert_refused(missing)
        blank = mutate(["rows", 0, "id"], "   ")
        self.assert_refused(blank)
        duplicate = producer_shaped_result()
        duplicate["rows"].append(dict(duplicate["rows"][0]))
        self.assertIn("duplicate row", self.assert_refused(duplicate))

    # WORK_UNIT_CASE: 2701/3
    def test_03_non_digest_identity_material_refused(self) -> None:
        self.assert_refused(mutate(["digest"], "x"))
        self.assert_refused(mutate(["header", "aggregate_digest"], "x"))
        self.assert_refused(mutate(["header", "denominator_digest"], "y"))
        self.assert_refused(mutate(["header", "base_sha"], ""))
        self.assert_refused(mutate(["rows", 0, "digest"], ""))
        self.assert_refused(mutate(["rows", 0, "owner"], ""))
        # Uppercase hex is not the lowercase identity #929 emits.
        self.assert_refused(mutate(["rows", 0, "digest"], "A" * 64))
        # A truncated or over-long digest is refused as well.
        self.assert_refused(mutate(["rows", 0, "digest"], SHA_A[:63]))
        self.assert_refused(mutate(["rows", 0, "digest"], SHA_A + "a"))
        # Base identity that is not the commit form is refused.
        self.assert_refused(mutate(["header", "base_sha"], "not-a-commit"))

    # WORK_UNIT_CASE: 2701/4
    def test_04_foreign_ceiling_and_disposition_refused(self) -> None:
        cause = self.assert_refused(
            mutate(["header", "proof_ceiling"], "NOT_THE_929_CEILING")
        )
        self.assertIn("proof_ceiling", cause)
        cause = self.assert_refused(mutate(["rows", 0, "disposition"], "almost-closed"))
        self.assertIn("disposition", cause)
        self.assert_refused(mutate(["rows", 1, "disposition"], ["needs-repair"]))
        # Vocabulary-only accounting checks: not forced to the optimistic value.
        self.assert_refused(mutate(["header", "denominator_status"], "MAYBE"))
        self.assert_refused(mutate(["header", "coverage"], "PARTIAL"))
        self.assert_refused(mutate(["header", "family_readiness"], "MOSTLY"))
        for vocabulary in (
            {"denominator_status": "INCOMPLETE", "coverage": "INCOMPLETE"},
            {"family_readiness": "READY"},
        ):
            tolerant = producer_shaped_result()
            tolerant["header"].update(vocabulary)
            admitted = coordinator._validate_checked_result(tolerant)
            self.assertEqual(len(admitted.rows), 3)

    # WORK_UNIT_CASE: 2701/5
    def test_05_boolean_and_inconsistent_counts_refused(self) -> None:
        # Python bool is an int subclass; only a real integer count is admitted.
        self.assert_refused(mutate(["header", "candidate_count"], True))
        self.assert_refused(mutate(["header", "classified_count"], True))
        self.assert_refused(mutate(["header", "unknown_count"], True))
        self.assert_refused(mutate(["header", "unassigned_count"], True))
        self.assert_refused(mutate(["header", "unknown_count"], 0))
        self.assert_refused(mutate(["header", "candidate_count"], 999))
        self.assert_refused(mutate(["header", "classified_count"], 2))
        self.assert_refused(mutate(["header", "unknown_count"], "1"))
        self.assert_refused(mutate(["header", "unassigned_count"], -1))
        self.assert_refused(mutate(["header", "unassigned_count"], 4))
        # Documented bound only: unassigned_count inside it is admitted.
        bounded = mutate(["header", "unassigned_count"], 3)
        self.assertEqual(
            coordinator._validate_checked_result(bounded).candidate_count, 3
        )
        missing = producer_shaped_result()
        del missing["header"]["unknown_count"]
        self.assert_refused(missing)

    # WORK_UNIT_CASE: 2701/6
    def test_06_required_key_sets_refused(self) -> None:
        for key in sorted(coordinator.CHECKED_HEADER_REQUIRED_KEYS):
            missing = producer_shaped_result()
            del missing["header"][key]
            self.assert_refused(missing)
        for key in sorted(coordinator.CHECKED_ROW_REQUIRED_KEYS):
            missing = producer_shaped_result()
            del missing["rows"][0][key]
            self.assert_refused(missing)
        for key in sorted(coordinator.CHECKED_RESULT_REQUIRED_KEYS):
            missing = producer_shaped_result()
            del missing[key]
            self.assert_refused(missing)
        self.assert_refused({"rows": [], "digest": SHA_A, "header": "nope"})
        self.assert_refused({"rows": {}, "digest": SHA_A, "header": {}})
        self.assert_refused(["rows"])

    # WORK_UNIT_CASE: 2701/7
    def test_07_unverified_count_relationship_is_self_describing(self) -> None:
        admitted = coordinator._validate_checked_result(producer_shaped_result())
        self.assertEqual(len(admitted.unverified_count_relationships), 1)
        report = admitted.unverified_count_relationships[0]
        self.assertEqual(report.relationship, coordinator.UNASSIGNED_COUNT_RELATIONSHIP)
        self.assertIn("repair_child", report.relationship)
        self.assertIn(
            "0 <= unassigned_count(1) <= candidate_count(3)", report.checked_part
        )
        self.assertFalse(report.to_dict()["verified"])
        result = coordinator.reconcile(
            coordinator.ReconciliationInput(
                rows=list(admitted.rows), inventory=admitted
            )
        )
        payload = result.to_dict()["checked_inventory"]
        self.assertEqual(
            payload["verified_count_relationships"],
            list(coordinator.VERIFIED_COUNT_RELATIONSHIPS),
        )
        self.assertEqual(len(payload["unverified_count_relationships"]), 1)
        self.assertFalse(payload["unverified_count_relationships"][0]["verified"])
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            coordinator.print_human(result)
        text = buffer.getvalue()
        self.assertIn("inventory counts verified:", text)
        self.assertIn("inventory NOT verified:", text)
        self.assertIn("unassigned_count ==", text)
        self.assertIn("repair_child", text)

    # WORK_UNIT_CASE: 2701/8
    def test_08_blocked_output_agrees_on_no_current_closure_cases(self) -> None:
        with tempfile.TemporaryDirectory(prefix="closure2701-") as tmp:
            root = Path(tmp)
            report_path = root / "blocked.json"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = coordinator.main(
                    ["--root", str(root), "--json-out", str(report_path)]
                )
            cause = stderr.getvalue()
            self.assertEqual(code, 2)
            self.assertIn("SERDE_BOUNDARY_CLOSURE: BLOCKED:", cause)
            # Text and JSON must not disagree about the same result.
            self.assertIn("no current closure cases", cause)
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["cases"], [])
            self.assertFalse(payload["passed"])
            self.assertIn("missing file:", payload["blocked_cause"])
            self.assertIn(payload["blocked_cause"], cause)

    # WORK_UNIT_CASE: 2701/9
    def test_09_accepted_contract_matches_producer_source_key_names(self) -> None:
        """The admission contract cannot outgrow or drift from #929's own shape."""
        header_keys, row_keys, result_keys = producer_source_key_names()
        # No over-narrowing: every accepted key really is a producer key.
        self.assertEqual(coordinator.CHECKED_HEADER_REQUIRED_KEYS, header_keys)
        self.assertEqual(coordinator.CHECKED_ROW_REQUIRED_KEYS, row_keys)
        self.assertEqual(coordinator.CHECKED_RESULT_REQUIRED_KEYS, result_keys)
        # #929's ceiling and disposition vocabulary are read from its source.
        source = INVENTORY_SCRIPT.read_text(encoding="utf-8")
        self.assertIn(
            'PROOF_CEILING = "%s"' % coordinator.INVENTORY_PROOF_CEILING, source
        )
        for disposition in coordinator.INVENTORY_DISPOSITIONS:
            self.assertIn('"%s"' % disposition, source)
        # The producer's row projection really is five keys: repair_child never
        # crosses this boundary, which is why unassigned_count stays explicitly
        # reported as unverified instead of silently compared.
        self.assertNotIn("repair_child", row_keys)


if __name__ == "__main__":
    unittest.main()
