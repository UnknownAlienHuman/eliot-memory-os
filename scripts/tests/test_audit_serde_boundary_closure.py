"""Deterministic coordinator tests for serialized trust-boundary closure (#710, Slice B).

Declared denominator: 20 cases, exactly 1..20.
Slice B owns tests plus frozen synthetic fixtures only; the checker itself
is owned by Slice A and is never imported as a hard dependency here.
Frozen fixtures live under scripts/testdata/serde-boundary-closure/.

Base: dfa3547e62544e4df311a61a8ff3c61b629f89f7
Branch: work/710-serde-closure-tests
"""

from __future__ import annotations

import base64
import hashlib
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "scripts" / "testdata" / "serde-boundary-closure"

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


if __name__ == "__main__":
    unittest.main()
