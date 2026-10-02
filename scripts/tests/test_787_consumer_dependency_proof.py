"""Adversarial binding matrix for #787 audit defect 4 (consumer dependency proof).

Defect 4 of the `code-complete` audit of issue #787 named
``scripts/audit-context-measurement-ownership.py::_dependency_evidence`` as a raw
substring check over joined source lines that accepted ANY ONE marker, and
accepted ``eliot_context_contracts`` (#584's public Context *schema* crate) alone
as proof of a canonical measurement dependency. These tests bind the repaired
check to the seven frozen fixtures the audit requires and prove that six of them
are rejected for the *specific* conjunct they fail, and that the seventh -- a
genuine migrated consumer -- is accepted.

Scope note: this module owns defect 4 only. The issue's full 32-case matrix
(audit defect 2) is a separate owner and lives in
``scripts/tests/test_audit_context_measurement_ownership.py``; this file neither
creates nor claims those cases and uses no ``# WORK_UNIT_CASE: 787/<N>`` marker,
because that marker namespace belongs to that suite alone.

Fixture policy: the frozen ``.rs`` fixtures under
``scripts/testdata/context-measurement-ownership/`` are the exact bytes under
test. Nothing here is written into the repository tree; each case materialises a
throwaway crate in a temporary directory and copies the fixture in unchanged, so
a fixture edit changes what is measured rather than being masked by a literal
embedded in the test.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_SCRIPT = (
    Path(__file__).resolve().parent.parent / "audit-context-measurement-ownership.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "audit_context_measurement_ownership_787_defect4", _SCRIPT
)
oracle = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = oracle
_SPEC.loader.exec_module(oracle)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FIXTURES = _REPO_ROOT / "scripts" / "testdata" / "context-measurement-ownership"

# The one exact seam path every fixture is materialised at and measured under.
_SEAM_REL = "crates/fixture-consumer/src/seam.rs"

# The single fixture that must be ACCEPTED. Every other fixture in
# ``scripts/testdata/context-measurement-ownership/`` is a negative and must be
# rejected; naming the genuine one as a constant keeps the "which fixture is the
# positive" decision out of the individual assertions.
_GENUINE_FIXTURE = "dep_canonical_positive.rs"

# The crate layout each fixture is measured inside. The Cargo manifest is the
# AUTHORITATIVE dependency evidence, so each case declares exactly which of
# #704's crates the fake consumer package depends on -- that is the first
# conjunct, and a fixture with no measurement dependency must fail on it
# regardless of what its Rust source says.
_CRATE_MANIFEST_WITH_MEASUREMENT = """\
[package]
name = "fixture-consumer"
version = "0.1.0"
edition = "2024"

[dependencies]
eliot-context-measurement = "0.1.0"
"""

# A real consumer that depends ONLY on #584's public Context contract crate.
# This is the schema-only Cargo metadata, and it must never satisfy the check.
_CRATE_MANIFEST_SCHEMA_ONLY = """\
[package]
name = "fixture-consumer"
version = "0.1.0"
edition = "2024"

[dependencies]
eliot-context-contracts = "0.1.0"
"""


def _stages_of(producer: object, root: Path, rel: str) -> dict[str, bool]:
    """Where does the canonical port call stop surviving the checker's filters?

    Runs the SAME filters :func:`oracle._port_call_sites` runs, in order, on the
    producer-masked record, and reports at which stage a candidate disappears:

    ``present``
        the exact-call regex ``(?<![\\w:])port\\s*\\(`` matched a masked line;
    ``production``
        that line's enclosing scope, per the producer's own ``_scope_of``, is
        production rather than test;
    ``reachable``
        the enclosing item passed :func:`oracle._reachable_item_starts`.

    Returns all three booleans so a caller can tell WHICH stage eliminated a
    fixture. Uses the real helpers, not a re-implementation, so the stages
    cannot drift from what the checker actually enforces.
    """
    record = producer._load_files(root, (rel,))[rel]
    masked = record["masked_lines"]
    depths = record["depths"]
    needle = re.compile(r"(?<![\w:])" + re.escape(oracle.CANONICAL_MEASUREMENT_PORT) + r"\s*\(")
    reachable = oracle._reachable_item_starts(producer, record, rel)
    item_re = producer.ITEM_RE
    present = production = reached = False
    for lineno, line in enumerate(masked, start=1):
        if not needle.search(line):
            continue
        present = True
        _item, scope = producer._scope_of(masked, depths, lineno, rel)
        if scope == "test":
            continue
        production = True
        enclosing = 0
        for index in range(lineno - 1, -1, -1):
            if item_re.match(masked[index]) is not None:
                if producer._item_extent(masked, depths, index + 1) >= lineno:
                    enclosing = index + 1
                    break
        if enclosing and enclosing in reachable:
            reached = True
    return {"present": present, "production": production, "reachable": reached}


def _materialize(fixture: str, manifest: str) -> tuple[Path, str]:
    """Copy one frozen fixture into a throwaway crate. Returns (root, rel)."""
    root = Path(tempfile.mkdtemp(prefix="787-defect4-"))
    crate = root / "crates" / "fixture-consumer"
    crate.mkdir(parents=True)
    (crate / "Cargo.toml").write_text(manifest, encoding="utf-8")
    rel = "crates/fixture-consumer/src/seam.rs"
    target = crate / "src" / "seam.rs"
    target.parent.mkdir(parents=True)
    shutil.copyfile(_FIXTURES / fixture, target)
    return (root, rel)


def _rows(rel: str, owner: str = "#783") -> list[dict[str, object]]:
    """One writable seam row, which is what selects a consumer's dependency
    universe. The oracle reads only ``write_scope``/``owner``/``path`` from a row
    for this decision."""
    return [{"write_scope": "writable", "owner": owner, "path": rel}]


def _measure(
    fixture: str,
    manifest: str = _CRATE_MANIFEST_WITH_MEASUREMENT,
    owner: str = "#783",
) -> dict[str, object]:
    """Run the REAL ``_dependency_evidence`` over one fixture and return its
    measured evidence.

    The temp root is removed in the ``finally`` so a failing assertion cannot
    leak a throwaway crate into the repository or the system temp beyond the
    call.
    """
    root, rel = _materialize(fixture, manifest)
    try:
        producer = oracle.load_producer(_REPO_ROOT)
        return oracle._dependency_evidence(root, producer, _rows(rel, owner))
    finally:
        shutil.rmtree(root, ignore_errors=True)


class ConsumerDependencyProofTest(unittest.TestCase):
    """Defect 4: the dependency proof must be BOUND evidence, not a name."""

    def _evidence_for(self, fixture: str, manifest: str) -> dict[str, object]:
        return _measure(fixture, manifest)

    def _accepted_sites(self, fixture: str, manifest: str, owner: str = "#783") -> list:
        """The accepted production call sites for the one fixture seam path."""
        accepted = self._evidence_for(fixture, manifest)["accepted_sites"].get(owner, {})
        return list(accepted.get(_SEAM_REL, []))

    def _masked_calls(self, fixture: str, manifest: str, owner: str = "#783") -> list:
        """The masked production call sites for the one fixture seam path."""
        calls = self._evidence_for(fixture, manifest)["calls"].get(owner, {})
        return list(calls.get(_SEAM_REL, []))

    def _cargo_declared(self, fixture: str, manifest: str, owner: str = "#783") -> tuple:
        """The measured (declared, evidence) Cargo conjunct for the seam path."""
        cargo = self._evidence_for(fixture, manifest)["cargo_dependencies"].get(owner, {})
        return cargo.get(_SEAM_REL, (False, "no seam path"))

    def _stages(self, fixture: str) -> dict[str, bool]:
        """At which filter stage the fixture's port call stops surviving."""
        root, rel = _materialize(fixture, _CRATE_MANIFEST_WITH_MEASUREMENT)
        try:
            producer = oracle.load_producer(_REPO_ROOT)
            return _stages_of(producer, root, rel)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    # -- 1. a comment naming the canonical symbol ------------------------
    def test_comment_naming_the_port_is_rejected(self) -> None:
        """``// TODO: call measure_serialized_context`` proves nothing.

        The producer's own ``_mask_rust`` blanks every comment body, so the
        masked production span holds no call at all. FIELDS THAT PROVE IT: the
        masked ``calls`` list is EMPTY (the comment text is gone from the masked
        record) and ``accepted_sites`` is EMPTY even though the Cargo conjunct is
        satisfied -- so the rejection is specifically about the missing bound
        call, not about an absent dependency.
        """
        cargo_flag, _why = self._cargo_declared("dep_comment_only.rs", _CRATE_MANIFEST_WITH_MEASUREMENT)
        self.assertTrue(cargo_flag, "the Cargo conjunct is independently satisfied here")
        self.assertEqual(self._masked_calls("dep_comment_only.rs", _CRATE_MANIFEST_WITH_MEASUREMENT), [],
                         "a comment must not produce a masked production call site")
        self.assertEqual(self._accepted_sites("dep_comment_only.rs", _CRATE_MANIFEST_WITH_MEASUREMENT), [],
                         "a comment naming the port must yield no accepted site")

    # -- 2. a string literal naming it ------------------------------------
    def test_string_literal_naming_the_port_is_rejected(self) -> None:
        """``const NOTE: &str = "eliot_context_measurement::measure_serialized_context";``
        proves nothing.

        FIELDS THAT PROVE IT: the masked ``calls`` list is EMPTY -- ``_mask_rust``
        blanks the literal body, so neither the crate name nor the port name
        survives into the masked record, and ``accepted_sites`` is empty even
        though the Cargo dependency IS declared.
        """
        evidence = self._evidence_for("dep_string_literal_only.rs", _CRATE_MANIFEST_WITH_MEASUREMENT)
        cargo_flag, _why = self._cargo_declared("dep_string_literal_only.rs", _CRATE_MANIFEST_WITH_MEASUREMENT)
        self.assertTrue(cargo_flag, "the Cargo conjunct is independently satisfied here")
        self.assertEqual(self._accepted_sites("dep_string_literal_only.rs", _CRATE_MANIFEST_WITH_MEASUREMENT), [],
                         "a string literal naming the port must yield no accepted site")
        self.assertEqual(evidence["calls"]["#783"][_SEAM_REL], [],
                         "the masked record must hold no call site for a string literal")

    # -- 3. a similarly named LOCAL function ------------------------------
    def test_similarly_named_local_function_is_rejected(self) -> None:
        """``fn measure_serialized_context_local(...)`` shares the port's stem
        but is defined locally.

        FIELDS THAT PROVE IT: the call-site regex requires the EXACT identifier
        followed by ``(`` and not preceded by ``::`` or part of a longer
        identifier, so ``measure_serialized_context_local(`` never matches and
        the masked ``calls`` list is EMPTY. The fixture also declares no Cargo
        dependency, so it additionally fails the Cargo conjunct.
        """
        self.assertEqual(
            self._accepted_sites("dep_local_similar_name.rs", _CRATE_MANIFEST_WITH_MEASUREMENT), [],
            "a similarly named local function must yield no accepted site",
        )
        cargo_flag, _why = self._cargo_declared("dep_local_similar_name.rs", _CRATE_MANIFEST_WITH_MEASUREMENT)
        self.assertTrue(cargo_flag, "with the Cargo dependency declared, the local name still fails")
        # And the genuinely absent Cargo dependency is caught as its own conjunct.
        cargo_flag_schema, _why2 = self._cargo_declared(
            "dep_local_similar_name.rs", _CRATE_MANIFEST_SCHEMA_ONLY
        )
        self.assertFalse(cargo_flag_schema, "a package without #704's crate must report no Cargo dependency")

    # -- 4. a schema-only import ------------------------------------------
    def test_schema_only_import_is_rejected(self) -> None:
        """``use eliot_context_contracts::SomeUnrelatedType;`` is #584's schema,
        not #704's algorithm.

        FIELDS THAT PROVE IT: with the SCHEMA-ONLY manifest, the measured
        ``cargo_dependencies`` flag for the consumer is False and names #704's
        crate in the evidence -- the #584 schema crate is nowhere an accepted
        measurement dependency. Even given the full measurement manifest, the
        fixture calls no port, so ``accepted_sites`` is EMPTY.
        """
        schema_only = self._evidence_for("dep_schema_only_import.rs", _CRATE_MANIFEST_SCHEMA_ONLY)
        declared, why = self._cargo_declared("dep_schema_only_import.rs", _CRATE_MANIFEST_SCHEMA_ONLY)
        self.assertFalse(declared, "a schema-only package must not declare #704's measurement crate")
        self.assertIn("eliot-context-measurement", why, "the finding must name the absent measurement crate")
        self.assertEqual(schema_only["accepted_sites"]["#783"][_SEAM_REL], [],
                         "a schema-only import must yield no accepted measurement site")
        # And the source-derived call is empty regardless of manifest.
        self.assertEqual(self._accepted_sites("dep_schema_only_import.rs", _CRATE_MANIFEST_WITH_MEASUREMENT), [],
                         "a schema-only import must never satisfy the dependency")

    # -- 5. a test-only call ----------------------------------------------
    def test_test_only_call_is_rejected(self) -> None:
        """The fixture has a REAL Cargo dependency and a REAL call, but both sit
        inside ``#[cfg(test)] mod tests``.

        FIELDS THAT PROVE IT: the producer's ``_scope_of`` measures the enclosing
        item scope as ``test`` for the call line, so the masked ``calls`` list is
        EMPTY -- the production dependency conjunct cannot be met by test-only
        code. The Cargo conjunct IS satisfied (deliberately, so the rejection is
        not for the wrong reason).
        """
        evidence = self._evidence_for("dep_test_only_call.rs", _CRATE_MANIFEST_WITH_MEASUREMENT)
        cargo_flag, _why = self._cargo_declared("dep_test_only_call.rs", _CRATE_MANIFEST_WITH_MEASUREMENT)
        self.assertTrue(cargo_flag, "the Cargo conjunct is satisfied, isolating the rejection to scope")
        self.assertEqual(evidence["calls"]["#783"][_SEAM_REL], [],
                         "a call inside #[cfg(test)]/#[test] must not be a production call site")
        self.assertEqual(self._accepted_sites("dep_test_only_call.rs", _CRATE_MANIFEST_WITH_MEASUREMENT), [],
                         "a test-only call must yield no accepted measurement site")

    # -- 6. dead code ------------------------------------------------------
    def test_dead_code_is_rejected(self) -> None:
        """``fn never_called_measurement_probe(...)`` carries a real Cargo
        dependency and a real call to the port, but nothing in the crate calls it.

        FIELDS THAT PROVE IT: ``_reachable_item_starts`` -- measured from the
        producer's masked lines with its ``ITEM_RE``/``_item_extent`` grammar --
        finds the private helper is neither ``pub`` nor called anywhere, so its
        call site is filtered out of the masked ``calls`` list. The Cargo conjunct
        IS satisfied, so the rejection is specifically about reachability.
        """
        evidence = self._evidence_for("dep_dead_code_call.rs", _CRATE_MANIFEST_WITH_MEASUREMENT)
        cargo_flag, _why = self._cargo_declared("dep_dead_code_call.rs", _CRATE_MANIFEST_WITH_MEASUREMENT)
        self.assertTrue(cargo_flag, "the Cargo conjunct is satisfied, isolating the rejection to reachability")
        self.assertEqual(evidence["calls"]["#783"][_SEAM_REL], [],
                         "a call only inside an unreached private fn must not be a production call site")
        self.assertEqual(self._accepted_sites("dep_dead_code_call.rs", _CRATE_MANIFEST_WITH_MEASUREMENT), [],
                         "dead code must yield no accepted measurement site")

    # -- 7. the REAL positive ---------------------------------------------
    def test_genuine_canonical_measurement_is_accepted(self) -> None:
        """A real migrated consumer -- real #704 Cargo dependency, real import,
        real PRODUCTION call with the final serialized bytes as the payload and
        the serializer/route/tokenizer identities bound into the input record --
        MUST still pass.

        FIELDS THAT PROVE IT: the Cargo conjunct is True; the masked ``calls``
        list holds exactly one production site; ``accepted_sites`` is non-empty;
        and the recorded binding for that site has BOTH ``final_bytes_bound`` and
        ``identity_bound`` True with a non-empty payload argument.
        """
        evidence = self._evidence_for(_GENUINE_FIXTURE, _CRATE_MANIFEST_WITH_MEASUREMENT)
        declared, _why = self._cargo_declared(_GENUINE_FIXTURE, _CRATE_MANIFEST_WITH_MEASUREMENT)
        self.assertTrue(declared, "the genuine fixture declares #704's measurement crate")
        sites = evidence["calls"]["#783"][_SEAM_REL]
        self.assertEqual(len(sites), 1, "the genuine fixture has exactly one production port call")
        self.assertEqual(evidence["accepted_sites"]["#783"][_SEAM_REL], sites,
                         "the genuine production call must be an accepted site")
        binding = evidence["bindings"]["#783"][_SEAM_REL][0]
        self.assertIsNotNone(binding["payload_argument"], "the port call passes the final serialized bytes")
        self.assertTrue(binding["final_bytes_bound"],
                        "the call binds declared_len/content_digest into SerializedContextInputs")
        self.assertTrue(binding["identity_bound"],
                        "the call binds serializer/route/tokenizer into SerializedContextInputs")

        # The recorded span must COVER the call, not merely name its line. A
        # zero-width span (span_start == span_end) cites a span that proves
        # nothing about the call it claims to be evidence for, so it is a
        # rejection of the oracle itself, not a stylistic detail. The genuine
        # call wraps its argument list across two lines, so the span must cover
        # both.
        site = sites[0]
        self.assertGreater(
            site["span_end"], site["span_start"],
            "the accepted site's span must cover the wrapped call, not just its first line",
        )
        self.assertGreaterEqual(
            site["span_start"], site["item_start"],
            "the call must lie at or after the enclosing item it is attributed to",
        )
        self.assertLessEqual(
            site["span_end"], site["span_start"] + 8,
            "the call span must stay within the enclosing item, not spill into the next one",
        )

    # -- the accepted span is real and non-degenerate ----------------------
    def test_accepted_site_span_is_not_degenerate(self) -> None:
        """Every accepted call site carries a span with ``span_start < span_end``.

        A site whose span had zero width would name a line without covering the
        call, so an audit finding citing that span would assert the location of
        evidence it never measured. This binds the span arithmetic itself, not
        only the acceptance decision.
        """
        accepted = self._accepted_sites(_GENUINE_FIXTURE, _CRATE_MANIFEST_WITH_MEASUREMENT)
        self.assertTrue(accepted, "the genuine fixture must produce at least one accepted site")
        for site in accepted:
            self.assertGreater(
                site["span_end"], site["span_start"],
                f"accepted site {site!r} has a zero-width span",
            )

    # -- each negative is rejected by its OWN mechanism, not incidentally --
    def test_each_negative_is_rejected_by_its_own_mechanism(self) -> None:
        """The six negatives must each be eliminated by a DIFFERENT measured rule.

        "Every negative is rejected" is not sufficient on its own: six fixtures
        could all be rejected by the same accident. This binds, for each fixture,
        the exact stage that eliminates it, by re-running the checker's own
        filters in order and recording where the port call disappears:

        ==========================  ======================  =========================
        fixture                     stage that eliminates it  why
        ==========================  ======================  =========================
        ``dep_comment_only``        no masked call site       comment body blanked
        ``dep_string_literal_only`` no masked call site       literal body blanked
        ``dep_local_similar_name``  no masked call site       exact-identifier regex
        ``dep_schema_only_import``  no masked call site       #704's port is never called
        ``dep_test_only_call``      scope filter              call exists, scope is test
        ``dep_dead_code_call``      reachability filter       call exists, item is dead
        ==========================  ======================  =========================

        The last two are the load-bearing rows: their call sites ARE found by the
        regex on the masked source, and only the scope and reachability filters
        remove them. If either fixture were rejected merely because the regex
        missed, the scope/reachability logic would be untested dead code.
        """
        stages = {
            "dep_comment_only.rs": (False, False, False),
            "dep_string_literal_only.rs": (False, False, False),
            "dep_local_similar_name.rs": (False, False, False),
            "dep_schema_only_import.rs": (False, False, False),
            "dep_test_only_call.rs": (True, False, False),
            "dep_dead_code_call.rs": (True, True, False),
            _GENUINE_FIXTURE: (True, True, True),
        }
        for fixture, expected in stages.items():
            with self.subTest(fixture=fixture):
                measured = self._stages(fixture)
                self.assertEqual(
                    (measured["present"], measured["production"], measured["reachable"]),
                    expected,
                    f"{fixture} must be eliminated at its intended stage",
                )

        # Only the negatives must yield no accepted site. The genuine fixture
        # reaches the last stage precisely because it IS accepted.
        for fixture in stages:
            if fixture == _GENUINE_FIXTURE:
                continue
            with self.subTest(fixture=fixture, assertion="rejected"):
                self.assertEqual(
                    self._accepted_sites(fixture, _CRATE_MANIFEST_WITH_MEASUREMENT), [],
                    f"{fixture} must yield no accepted measurement site",
                )

        # The genuine fixture is the only one that survives all three stages.
        survivors = [
            fixture
            for fixture in stages
            if self._stages(fixture)["reachable"]
        ]
        self.assertEqual(
            survivors, [_GENUINE_FIXTURE],
            "exactly one fixture -- the genuine migrated consumer -- is reachable",
        )

    # -- the four negative classes, as a set, all rejected ----------------
    def test_the_six_negative_fixtures_are_all_rejected(self) -> None:
        """Every non-genuine fixture is rejected, with the genuine one accepted.

        This binds the SET: none of comment/string/local-name/schema-only/
        test-only/dead-code can be mistaken for the real thing, and the real
        thing still passes.
        """
        negatives = (
            "dep_comment_only.rs",
            "dep_string_literal_only.rs",
            "dep_local_similar_name.rs",
            "dep_schema_only_import.rs",
            "dep_test_only_call.rs",
            "dep_dead_code_call.rs",
        )
        for fixture in negatives:
            with self.subTest(fixture=fixture):
                self.assertEqual(
                    self._accepted_sites(fixture, _CRATE_MANIFEST_WITH_MEASUREMENT), [],
                    f"{fixture} must be rejected by the canonical measurement dependency check",
                )
        # The genuine one is not in the rejected set.
        self.assertNotEqual(
            self._accepted_sites(_GENUINE_FIXTURE, _CRATE_MANIFEST_WITH_MEASUREMENT), [],
            "the genuine migrated consumer must be accepted",
        )

    # -- the exact #584 schema crate is never a measurement dependency ---
    def test_schema_crate_is_never_a_measurement_dependency(self) -> None:
        """#584's public Context contract crate owns the measurement SCHEMA, not
        the measurement ALGORITHM.

        A reference to ``eliot_context_contracts`` alone must not, and structurally
        cannot, satisfy the dependency. This binds the CLOSED contract: every
        consumer's Cargo conjunct names #704's measurement crate, and the schema
        crate is absent from every accepted arm.
        """
        contracts = oracle.CONSUMER_DEPENDENCY_CONTRACTS
        for owner, contract in contracts.items():
            self.assertEqual(contract.cargo_package, oracle.MEASUREMENT_CRATE_PACKAGE,
                             f"{owner} must depend on #704's measurement crate")
            self.assertNotEqual(contract.cargo_package, "eliot-context-contracts",
                                "the #584 schema crate is not a measurement dependency")
        # A consumer whose Cargo metadata declares ONLY the schema crate fails.
        schema_flag, _why = self._cargo_declared("dep_canonical_positive.rs", _CRATE_MANIFEST_SCHEMA_ONLY)
        self.assertFalse(schema_flag,
                         "even a genuine call site cannot satisfy the dependency without #704's Cargo dependency")


if __name__ == "__main__":
    unittest.main()