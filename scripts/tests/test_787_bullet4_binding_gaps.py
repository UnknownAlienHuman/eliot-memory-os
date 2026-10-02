"""Adversarial binding matrix for #787 audit section 4, bullet 4 (bullet 4 gaps).

Audit section 4 of the ``code-complete`` audit of issue #787, required repair
bullet 4, states:

    Bind the call/evidence to final serialized bytes and, for actual-token
    claims, provider/model/tokenizer ID/version/hash and content digest.

A verification pass over the repaired `_dependency_evidence` established that the
six named forgeries of section 4 bullet 5 are all rejected, but that this bullet
4 has three residual gaps. Each is reproduced here against the REAL production
function, and each fix is bound by a frozen fixture.

* **Gap 1** -- `payload_argument` was computed by `_call_payload_argument` and
  surfaced by `_binding_gaps`, but acceptance tested only ``final_bytes_bound and
  identity_bound``. A site was therefore accepted with ``payload_argument: null``.
  `_call_payload_argument` also computed over ``masked_line.splitlines()`` -- the
  call's FIRST LINE only -- so it returned ``None`` for any wrapped call.
* **Gap 2** -- ``&[]`` passed as ``payload_argument`` with ``declared_len: 0``:
  an empty byte slice, i.e. no serialized bytes at all.
* **Gap 3** -- ``PORT_IDENTITY_BINDING_FIELDS`` was only ("serializer", "route",
  "tokenizer"), matched as bare substrings, so ``serializer: 1, route: 1,
  tokenizer: 1`` with a literal ``"sha256:00"`` content digest passed.

SEMANTICS THIS SUITE IS WRITTEN AGAINST (the committed, reviewed behaviour).
Read from ``scripts/audit-context-measurement-ownership.py``, not assumed:

* ``_binding_gaps`` is PER BINDING and is a fixed ``if/elif`` chain. A complete
  binding yields ``[]`` for that binding, so a one-site file yields ``[[]]`` --
  "one binding, no missing conjunct". It names the FIRST missing requirement,
  not every defect at once, so its length is not a defect count.
* ``_identity_placeholders`` is measured on the PRODUCER-MASKED span and returns
  FIELD NAMES. A string-literal value is blanked by ``_mask_rust`` and so
  survives as an EMPTY value; there is no closed list of placeholder digest
  strings, because such a list would be the invented registry the issue forbids.
* A call that passes no payload also passes no second argument, so
  ``carries_record`` is False and the record conjuncts are False as a measured
  fact -- not as a penalty. See ``test_gap1_bare_call_is_rejected_for_the_missing_payload``.

Scope note: this module owns audit section 4, bullet 4 only. The six named
forgeries of bullet 5 are owned by
``scripts/tests/test_787_consumer_dependency_proof.py`` (defect 4), the #866
candidate enumeration by ``scripts/tests/test_787_candidate_enumeration_c7.py``
(defect 3), and the issue's 32-case matrix by
``scripts/tests/test_audit_context_measurement_ownership.py`` (defect 2). This file
uses no ``# WORK_UNIT_CASE: 787/<N>`` marker, because that namespace belongs to
the matrix suite alone.

Fixture policy: the frozen ``.rs`` fixtures under
``scripts/testdata/context-measurement-ownership/`` are the exact bytes under
test. Nothing here is written into the repository tree; each case materialises a
throwaway crate in a temporary directory and copies the fixture in unchanged, so
a fixture edit changes what is measured rather than being masked by a literal
embedded in the test.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_SCRIPT = (
    Path(__file__).resolve().parent.parent / "audit-context-measurement-ownership.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "audit_context_measurement_ownership_787_bullet4", _SCRIPT
)
oracle = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = oracle
_SPEC.loader.exec_module(oracle)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FIXTURES = _REPO_ROOT / "scripts" / "testdata" / "context-measurement-ownership"

# The one exact seam path every fixture is materialised at and measured under.
_SEAM_REL = "crates/fixture-consumer/src/seam.rs"

# The consumer owner each fixture is measured under. Only #783 is exercised:
# the binding conjuncts are owner-independent, and exercising all three owners
# would multiply the same measurement without adding a distinct conjunct.
_OWNER = "#783"

# The Cargo manifest each fixture is measured inside. The Cargo manifest is the
# AUTHORITATIVE dependency evidence, and every fixture here satisfies it, so a
# rejection is never for the missing-dependency reason -- it is always for the
# bullet-4 binding conjunct the fixture is written to isolate.
_CRATE_MANIFEST = """\
[package]
name = "fixture-consumer"
version = "0.1.0"
edition = "2024"

[dependencies]
eliot-context-measurement = "0.1.0"
"""


def _materialize(fixture: str, manifest: str = _CRATE_MANIFEST) -> tuple[Path, str]:
    """Copy one frozen fixture into a throwaway crate. Returns (root, rel)."""
    root = Path(tempfile.mkdtemp(prefix="787-bullet4-"))
    crate = root / "crates" / "fixture-consumer"
    crate.mkdir(parents=True)
    (crate / "Cargo.toml").write_text(manifest, encoding="utf-8")
    rel = _SEAM_REL
    target = crate / "src" / "seam.rs"
    target.parent.mkdir(parents=True)
    shutil.copyfile(_FIXTURES / fixture, target)
    return (root, rel)


def _rows(rel: str, owner: str = _OWNER) -> list[dict[str, object]]:
    """One writable seam row, which is what selects a consumer's dependency
    universe. The oracle reads only ``write_scope``/``owner``/``path`` from a row
    for this decision."""
    return [{"write_scope": "writable", "owner": owner, "path": rel}]


class _Measured:
    """The measured evidence for one fixture, plus the bindings it recorded."""

    __slots__ = ("bindings", "accepted", "calls", "cargo", "declared", "why")

    def __init__(self, evidence: dict[str, object]) -> None:
        self.calls = list(evidence["calls"][_OWNER][_SEAM_REL])
        self.accepted = list(evidence["accepted_sites"][_OWNER][_SEAM_REL])
        self.bindings = list(evidence["bindings"][_OWNER][_SEAM_REL])
        self.declared, self.why = evidence["cargo_dependencies"][_OWNER][_SEAM_REL]

    def gaps(self) -> list[list[str]]:
        """One gap list per measured binding, in site order.

        :func:`oracle._binding_gaps` is PER BINDING: a file with one call site
        yields ``[[]]`` -- a list containing one empty list -- when that binding
        is complete, and the inner list is empty because the binding has no
        missing conjunct. A single ``[]`` would mean "no binding at all", which
        ``first()``/``assert_one_binding`` already rules out. ``no_gaps()`` is
        the readable "every binding is complete" assertion.
        """
        return [oracle._binding_gaps(entry) for entry in self.bindings]

    def no_gaps(self) -> bool:
        """True when every measured binding is complete (``gaps() == [[], ...]``)."""
        return all(not gaps for gaps in self.gaps())

    def first_gaps(self) -> list[str]:
        """The named missing conjuncts of the single binding this fixture has."""
        self.assert_one_binding()
        return oracle._binding_gaps(self.bindings[0])

    def first(self) -> dict[str, object]:
        self.assert_one_binding()
        return self.bindings[0]

    def assert_one_binding(self) -> None:
        if len(self.bindings) != 1:
            raise AssertionError(
                f"expected exactly one measured binding, got {self.bindings!r}"
            )


def _measure(fixture: str, manifest: str = _CRATE_MANIFEST) -> _Measured:
    """Run the REAL ``_dependency_evidence`` over one fixture.

    The temp root is removed in the ``finally`` so a failing assertion cannot
    leak a throwaway crate into the repository or the system temp beyond the
    call.
    """
    root, rel = _materialize(fixture, manifest)
    try:
        producer = oracle.load_producer(_REPO_ROOT)
        return _Measured(oracle._dependency_evidence(root, producer, _rows(rel)))
    finally:
        shutil.rmtree(root, ignore_errors=True)


class Bullet4BindingTest(unittest.TestCase):
    """Bullet 4: bind to final serialized bytes and to a named identity."""

    def setUp(self) -> None:
        # Every fixture in this suite must satisfy the Cargo conjunct, or a
        # rejection could be for the wrong reason. Asserted per-case below and
        # pinned here as the suite's invariant.
        self.assertIn(
            "eliot-context-measurement",
            oracle.MEASUREMENT_CRATE_PACKAGE,
            "the accepted measurement dependency is #704's algorithm crate",
        )

    # -- GAP 1: payload_argument is computed but not gated -----------------
    def test_gap1_bare_call_is_rejected_for_the_missing_payload(self) -> None:
        """A site accepted with ``payload_argument: null`` is the reported gap.

        BEFORE: ``_dependency_evidence`` accepted a site on ``final_bytes_bound
        and identity_bound`` alone, so a call that passed NO payload argument at
        all was an accepted site while ``_binding_gaps`` simultaneously reported
        ``"a final serialized byte payload argument"``.

        FIELDS THAT PROVE IT: the fixture's call site IS found (``calls`` is
        non-empty), the Cargo conjunct is True, and the port is genuinely called
        BARE -- no first argument at all. The real ``_binding_gaps`` names the
        missing payload, and ``accepted_sites`` is empty.

        WHY THE RECORD CONJECTS ARE ALSO FALSE HERE (and that is correct, not a
        weakening). A call that passes NO payload also passes NO second argument,
        so the call binds no ``SerializedContextInputs`` at all and the production
        code proves nothing about the record sitting beside it: ``carries_record``
        in :func:`oracle._port_call_bindings` is False, which is exactly what the
        committed predicate says -- "the record the CALL passes is the record
        whose fields are measured". ``_binding_gaps`` reports that as its own
        named conjunct, so the rejection is still precise and the finding still
        names what is missing. The gap this test binds is narrower and is the one
        the issue names: ``payload_argument is None`` must NOT be an accepted
        site.
        """
        measured = _measure("reject_missing_payload_argument.rs")
        self.assertTrue(measured.declared, "the Cargo conjunct is satisfied, isolating the rejection")
        self.assertTrue(measured.calls, "the production call must be DETECTED, or this would pass for the wrong reason")
        binding = measured.first()
        self.assertIsNone(binding["payload_argument"], "the port is called bare: no payload argument")
        self.assertFalse(binding["payload_non_empty"], "no payload argument binds no bytes")
        # The call passes no ``SerializedContextInputs`` either, so the record
        # conjuncts are False as a measured fact, not as a penalty.
        self.assertIsNone(
            binding["inputs_argument"],
            "a bare call passes no input record, so nothing can bind the envelope",
        )
        self.assertFalse(binding["final_bytes_bound"])
        self.assertFalse(binding["content_digest_bound"])
        self.assertFalse(binding["identity_bound"])
        self.assertFalse(binding["identity_detail_bound"])
        self.assertFalse(binding["identity_non_placeholder"])
        # The missing payload IS the first named conjunct, and the uncarried
        # record is named too -- so the rejection is never silent.
        gaps = measured.first_gaps()
        self.assertEqual(
            gaps[0],
            "a final serialized byte payload argument",
            "the missing payload argument must be named first",
        )
        self.assertTrue(
            any("identity binding" in gap for gap in gaps[1:]),
            f"the uncarried record must also be named: {gaps!r}",
        )
        self.assertEqual(
            measured.accepted, [],
            "a call that binds no payload argument is not an accepted site",
        )

    def test_gap1_wrapped_call_payload_is_measured_not_lost(self) -> None:
        """``_call_payload_argument`` must read the WHOLE call, not line 1.

        BEFORE: it computed over ``masked_line.splitlines()`` -- the call's FIRST
        LINE -- so a wrapped argument list produced no payload argument at all.

        FIELDS THAT PROVE IT: the genuine fixture's payload sits on a CONTINUATION
        line of a fully wrapped call. The REAL ``_call_payload_argument`` returns
        ``&request.payload`` -- the measured value, not a fixture literal -- and
        the site is ACCEPTED, so the repair is a false-negative fix and not a
        tightening that rejects the genuine shape.
        """
        wrapped = [
            "    let measured = measure_serialized_context(",
            "        &request.payload,",
            "        &inputs,",
            "    )",
        ]
        self.assertEqual(
            oracle._call_payload_argument(wrapped, len(wrapped), 1),
            "&request.payload",
            "the payload on a continuation line is the first top-level argument",
        )
        measured = _measure("accept_wrapped_call_payload.rs")
        self.assertTrue(measured.declared)
        self.assertEqual(len(measured.calls), 1, f"expected one production call: {measured.calls!r}")
        binding = measured.first()
        self.assertEqual(
            binding["payload_argument"],
            "&request.payload",
            "the wrapped call's payload must be measured, not lost to line-1 reading",
        )
        self.assertTrue(measured.no_gaps(), f"the wrapped genuine shape must have no gap: {measured.gaps()!r}")
        self.assertEqual(
            measured.accepted, measured.calls,
            "a wrapped genuine call must still be an accepted site",
        )

    def test_gap1_inlined_struct_literal_does_not_mis_anchor_the_payload(self) -> None:
        """An inline ``&SerializedContextInputs { .. }`` must not steal argument 1.

        The writer's report names the mis-anchor: an inlined struct literal's
        own brace/paren nesting can shift where the argument splitter thinks
        argument 1 ends. This binds BOTH shapes through the real splitter: the
        literal opened on the CALL LINE, and the literal opened on the NEXT line.

        FIELDS THAT PROVE IT: ``_call_payload_argument`` returns exactly the first
        argument for both, and neither shape changes the argument count or reads
        the record as the payload.
        """
        on_call_line = [
            "    let measured = measure_serialized_context(payload, &SerializedContextInputs {",
            "        declared_len: payload.len() as u64,",
            "        content_digest: digest,",
            "    })",
        ]
        self.assertEqual(
            oracle._call_payload_argument(on_call_line, len(on_call_line), 1),
            "payload",
            "the struct literal's commas must not be read as argument-1 terminators",
        )
        next_line = [
            "    let measured = measure_serialized_context(payload,",
            "        &SerializedContextInputs {",
            "            declared_len: payload.len() as u64,",
            "            content_digest: digest,",
            "        },",
            "    )",
        ]
        self.assertEqual(
            oracle._call_payload_argument(next_line, len(next_line), 1),
            "payload",
            "a record opened on the next line must not become the payload",
        )
        # The record is still measured as the SECOND argument in both shapes, so
        # the two readers agree about where each argument ends.
        for lines in (on_call_line, next_line):
            with self.subTest(first_line=lines[0]):
                self.assertIsNotNone(
                    oracle._call_inputs_argument(lines, len(lines), 1),
                    "the inline record must still be read as the port's second argument",
                )

    def test_gap1_bare_call_still_yields_no_payload_argument(self) -> None:
        """The multiline read must not manufacture a payload for a bare call.

        A widened reader that always returns a non-empty string would make
        ``payload_argument is None`` unfalsifiable and silently re-open Gap 1.
        """
        bare = ["    measure_serialized_context()"]
        self.assertIsNone(
            oracle._call_payload_argument(bare, len(bare), 1),
            "a call with no argument binds no payload",
        )
        trailing_comma = ["    measure_serialized_context("]
        self.assertIsNone(
            oracle._call_payload_argument(trailing_comma, len(trailing_comma), 1),
            "an unterminated argument list binds no payload",
        )

    # -- GAP 2: an empty payload is not "final serialized bytes" -----------
    def test_gap2_empty_payload_slice_is_rejected(self) -> None:
        """``&[]`` with ``declared_len: 0`` is no serialized bytes at all.

        FIELDS THAT PROVE IT: the measured ``payload_argument`` is literally
        ``"&[]"``, the real ``_is_empty_payload_literal`` says it denotes zero
        bytes, the real ``_envelope_length_is_zero`` says the record's
        ``declared_len: 0`` is a literal-zero envelope length (so
        ``content_digest_bound`` is False as a measured fact), and every identity
        conjunct passes -- so the rejection is specifically about the final
        serialized bytes.

        WHY EXACTLY ONE GAP IS NAMED. :func:`oracle._binding_gaps` is a fixed
        ``if/elif`` chain by design, so a fixture failing the payload conjunct
        reports that conjunct and stops: the gap list is a deterministic,
        ordered "first missing requirement", not a set of every defect at once.
        The literal-zero ``declared_len`` is therefore still MEASURED (asserted
        directly below via ``content_digest_bound`` is False) even though the
        named gap list is the single payload entry. Nothing is hidden: the
        binding record carries both facts.
        """
        self.assertTrue(
            oracle._is_empty_payload_literal("&[]"),
            "an empty slice literal denotes no serialized bytes",
        )
        measured = _measure("reject_empty_payload_slice.rs")
        binding = measured.first()
        self.assertEqual(binding["payload_argument"], "&[]", "the measured payload is the empty slice")
        self.assertFalse(binding["payload_non_empty"], "an empty slice binds no final serialized bytes")
        self.assertFalse(
            binding["content_digest_bound"],
            "a literal-zero declared length is not a bound envelope length",
        )
        self.assertTrue(binding["identity_bound"])
        self.assertTrue(binding["identity_detail_bound"])
        self.assertTrue(binding["identity_non_placeholder"])
        gaps = measured.first_gaps()
        self.assertIn(
            "empty byte/string literal", gaps[0],
            f"the empty payload must be named as its own conjunct: {gaps!r}",
        )
        self.assertEqual(
            len(gaps), 1,
            f"the elif chain names the first missing conjunct only: {gaps!r}",
        )
        self.assertEqual(measured.accepted, [], "an empty payload must yield no accepted site")

    def test_gap2_zero_declared_length_alone_is_rejected(self) -> None:
        """The declared-length arm in isolation, with everything else genuine.

        This is the half of Gap 2 a ``&[]`` payload does not isolate: a REAL,
        non-empty payload whose record declares ``declared_len: 0``. Only the
        declared-length conjunct fails, so a finding names exactly that.

        WHY A LEGITIMATELY-EMPTY PAYLOAD CANNOT OCCUR HERE. The admitted cases
        are C23 ("exact authorized tokenizer adapter accepted") and C26 ("current
        final-serialized measurement with exact tokenizer identity accepted").
        Both are about a measurement OF a serialized Context envelope: C26 names
        the exact tokenizer identity of that envelope's content. An empty
        envelope has no serialized bytes to digest, no tokens to count and no
        tokenizer observation to attribute, so it is not the subject either case
        admits. The zero rule is therefore not a narrowing of a legitimate shape
        -- it removes a shape that could never have carried the proof anyway.
        """
        self.assertTrue(
            oracle._envelope_length_is_zero("declared_len: 0,"),
            "a literal-zero declared length is detectable",
        )
        self.assertFalse(
            oracle._envelope_length_is_zero("declared_len: request.payload.len() as u64,"),
            "a real envelope length is never a literal zero",
        )
        measured = _measure("reject_zero_declared_length.rs")
        binding = measured.first()
        self.assertEqual(binding["payload_argument"], "&request.payload")
        self.assertTrue(binding["payload_non_empty"], "the payload IS a real non-empty payload here")
        self.assertTrue(binding["final_bytes_bound"], "the declared_len/content_digest NAMES are present")
        self.assertTrue(binding["identity_bound"])
        self.assertTrue(binding["identity_detail_bound"])
        self.assertTrue(binding["identity_non_placeholder"])
        self.assertEqual(
            measured.first_gaps(),
            [
                "a non-placeholder content_digest value "
                "(not a constant, a blanked string literal or an empty value)"
            ],
            "ONLY the literal-zero declared length may fail here, so the rejection is precise",
        )
        self.assertEqual(measured.accepted, [], "a zero declared length must yield no accepted site")

    def test_gap2_empty_literal_predicate_does_not_over_reach(self) -> None:
        """Only LITERAL empties are rejected; ordinary expressions are not.

        The constraint is that the fix must not widen a rule so broadly that
        ordinary code starts being reported. An expression whose RUNTIME value
        might be empty cannot be established empty from a static span, so
        ``Vec::new()``, ``self.payload()`` and an empty static must NOT match --
        only the literal empty forms do.
        """
        for literal in ("&[]", "[]", "&[]u8", 'b""', '&""'):
            with self.subTest(literal=literal):
                self.assertTrue(
                    oracle._is_empty_payload_literal(literal),
                    f"{literal!r} is a literal empty byte/string value",
                )
        for expression in (
            "Vec::new()",
            "self.payload()",
            "&self.buffer[..]",
            "&request.payload",
            "payload",
            "EMPTY_SLICE",
        ):
            with self.subTest(expression=expression):
                self.assertFalse(
                    oracle._is_empty_payload_literal(expression),
                    f"{expression!r} is an expression; its emptiness is a runtime fact "
                    f"a static span cannot establish, so it must not be reported",
                )

    # -- GAP 3: the identity conjunct must be present AND non-placeholder --
    def test_gap3_hardcoded_integer_identity_is_rejected(self) -> None:
        """``serializer: 1, route: 1, tokenizer: 1`` is not an identity.

        BEFORE: ``PORT_IDENTITY_BINDING_FIELDS`` was only ("serializer", "route",
        "tokenizer"), matched as bare substrings of the enclosing item's masked
        span, so this site was ACCEPTED with no ID, no version, no hash, no
        provider, no model and a literal ``"sha256:00"`` content digest.

        FIELDS THAT PROVE IT: the OLD conjunct still passes (``identity_bound``
        is True -- the three names ARE present), the payload conjunct and the
        final-bytes conjunct pass, and the ONLY failing conjuncts are the
        ID/version/hash conjunct and the placeholder conjunct. That is what makes
        this a test of the NEW predicate rather than of the old one.
        """
        measured = _measure("reject_hardcoded_identity_fields.rs")
        binding = measured.first()
        # The pre-repair conjunct is deliberately still satisfied...
        self.assertTrue(
            binding["identity_bound"],
            "the old name-only conjunct still passes here; only the new one rejects",
        )
        self.assertTrue(binding["payload_non_empty"], "the payload is a real non-empty payload")
        self.assertTrue(binding["final_bytes_bound"])
        # ...and the new conjuncts are what reject it.
        self.assertFalse(
            binding["identity_detail_bound"],
            "no provider_id/model_id/tokenizer_id/tokenizer_version/tokenizer_hash is present",
        )
        self.assertFalse(
            binding["identity_non_placeholder"],
            "hardcoded integers and a literal 'sha256:00' are placeholders",
        )
        self.assertFalse(
            binding["content_digest_bound"],
            "a literal 'sha256:00' content digest is a placeholder, not a digest",
        )
        gaps = measured.first_gaps()
        # Both the placeholder digest AND the absent ID/version/hash conjunct are
        # named -- ``_binding_gaps`` puts the final-bytes arm before the identity
        # arm, so the digest conjunct is gaps[0] and the ID/version/hash conjunct
        # is gaps[1]. Asserting both by content (not by index) keeps the test
        # bound to the semantics rather than to the report ordering.
        self.assertTrue(
            any("ID/version/hash" in gap for gap in gaps),
            f"the missing ID/version/hash must be named: {gaps!r}",
        )
        self.assertTrue(
            any("non-placeholder content_digest" in gap for gap in gaps),
            f"the placeholder 'sha256:00' digest must be named: {gaps!r}",
        )
        self.assertIn(
            "content_digest",
            binding["placeholder_bindings"],
            "the literal 'sha256:00' digest is reported as a placeholder by FIELD NAME",
        )
        self.assertEqual(
            measured.accepted, [],
            "hardcoded integer identities must yield no accepted site",
        )

    def test_gap3_placeholder_predicate_rejects_only_placeholders(self) -> None:
        """The placeholder predicate must be narrow, or ordinary code is reported.

        It rejects a blanked string-literal digest, a bare hardcoded integer used
        as an identity value, and an empty value -- and nothing else. A genuine
        ``request.provider_id.clone()`` and a genuine per-request digest are NOT
        placeholders.

        THE MEASUREMENT SURFACE IS THE PRODUCER-MASKED SPAN, AND THAT IS THE POINT.
        :func:`oracle._identity_placeholders` is documented to be measured on the
        span the producer's ``_mask_rust`` has already blanked, and the real
        binding path only ever hands it such a span. That is what lets it name a
        CONSTANT without needing a closed registry of approved digests: a string
        literal's body is blanked, so it survives as an EMPTY value, which is
        unambiguous -- whereas an UNMASKED ``content_digest: "sha256:00"`` is just
        a string and tells the predicate nothing about its provenance. So the
        literal placeholder is asserted here THROUGH the producer's own masker,
        and the raw form is asserted NOT to be a placeholder, pinning that the
        predicate cannot be satisfied by naming a digest text.
        """
        # #866's OWN masker, so the mask under test is the production one and not
        # a hand-rolled imitation of it.
        producer = oracle.load_producer(_REPO_ROOT)
        # The literal placeholder digest, as the real measurement surface sees it.
        self.assertIn(
            oracle.PORT_CONTENT_DIGEST_FIELD,
            oracle._identity_placeholders(producer._mask_rust('content_digest: "sha256:00",')),
            "a string-literal digest masks to an empty value and is a placeholder",
        )
        # ...and the UNMASKED text alone is NOT accepted as a placeholder, so a
        # site cannot satisfy the conjunct by naming a digest literal in raw text.
        self.assertEqual(
            oracle._identity_placeholders('content_digest: "sha256:00",'),
            set(),
            "an unmasked span cannot establish that a quoted value is a constant",
        )
        # A hardcoded integer identity value is a placeholder, by field name.
        self.assertEqual(
            oracle._identity_placeholders(producer._mask_rust("serializer_id: 1,")),
            {"serializer_id"},
            "a hardcoded integer identity value is a placeholder",
        )
        self.assertEqual(
            oracle._identity_placeholders(producer._mask_rust("route_id: 0u64,")),
            {"route_id"},
            "a suffixed integer constant is a placeholder too",
        )
        # The OLD name-only fields ("serializer"/"route"/"tokenizer") are NOT in
        # the placeholder vocabulary at all: the repaired conjunct is over the
        # ID/version/hash field names, so `serializer: 1` alone cannot satisfy it.
        self.assertEqual(
            oracle._identity_placeholders(producer._mask_rust("serializer: 1,\nroute: 1,\ntokenizer: 1,")),
            set(),
            "the old name-only fields are not part of the placeholder vocabulary",
        )
        for genuine in (
            "provider_id: request.provider_id.clone(),",
            "model_id: self.model_id.clone(),",
            "tokenizer_hash: tokenizer_hash.clone(),",
            "content_digest: request.content_digest.clone(),",
            "serializer_version: config.serializer_version.clone(),",
        ):
            with self.subTest(genuine=genuine):
                self.assertEqual(
                    oracle._identity_placeholders(genuine), set(),
                    f"{genuine!r} is a real per-request identity value, not a placeholder",
                )

    def test_gap3_identity_conjunct_requires_the_named_groups(self) -> None:
        """The identity conjunct is the issue's OWN list of required facts.

        Binds the closed vocabulary directly: every group the issue names --
        serializer, route (provider + model) and tokenizer -- and the exact
        ID/version/hash fields each must carry. The vocabulary is checked rather
        than hard-coded, so a future widening of
        :data:`PORT_IDENTITY_REQUIRED_FIELDS` cannot silently drop provider,
        model or the tokenizer hash.
        """
        required = dict(oracle.PORT_IDENTITY_REQUIRED_FIELDS)
        self.assertEqual(
            set(required), {"serializer", "route", "tokenizer"},
            "the identity conjunct is the issue's three named identity groups",
        )
        self.assertIn("provider_id", required["route"], "the provider must be named, not inferred")
        self.assertIn("model_id", required["route"], "the model must be named, not inferred")
        self.assertIn("tokenizer_id", required["tokenizer"])
        self.assertIn("tokenizer_version", required["tokenizer"])
        self.assertIn("tokenizer_hash", required["tokenizer"])
        self.assertIn("serializer_id", required["serializer"])
        self.assertIn("serializer_version", required["serializer"])
        producer = oracle.load_producer(_REPO_ROOT)
        # The content digest is its own conjunct: its NAME is in the final-bytes
        # vocabulary, and whether its VALUE is a placeholder is a PREDICATE over
        # the masked span, not a membership test against a list of literal digest
        # strings. That is deliberate -- a closed list of placeholder digests
        # would be an invented registry, and any digest outside it would pass.
        # So what is bound here is the field, and the placeholder VALUE is proven
        # separately in test_gap3_placeholder_predicate_rejects_only_placeholders.
        self.assertIn(oracle.PORT_CONTENT_DIGEST_FIELD, oracle.PORT_FINAL_BYTES_BINDING_FIELDS)
        self.assertNotIn(
            oracle.PORT_CONTENT_DIGEST_FIELD,
            tuple(name for _group, names in oracle.PORT_IDENTITY_REQUIRED_FIELDS for name in names),
            "the content digest is its own conjunct, not one of the identity fields",
        )
        # The identity conjunct enumerates exactly the issue's named facts and
        # nothing else: every one of them is reported by NAME when it is a
        # placeholder, which is why the predicate returns field names.
        self.assertEqual(
            oracle._identity_placeholders(producer._mask_rust("content_digest:            ,")),
            {oracle.PORT_CONTENT_DIGEST_FIELD},
            "a blanked digest is reported by its FIELD NAME, which is what a finding cites",
        )

    def test_gap3_no_approved_adapter_registry_was_invented(self) -> None:
        """The registry stays the honest empty; only the PREDIDATE was fixed.

        Closing Gap 3 required a provider/model/tokenizer that is actually NAMED,
        and the tempting shortcut was to populate
        :data:`APPROVED_MEASUREMENT_ADAPTERS` with an invented adapter record.
        This binds that it was NOT done: the registry is still empty, so no
        consumer can be proven through the adapter arm, and the fix is entirely in
        the measured predicate.
        """
        self.assertEqual(
            oracle.APPROVED_MEASUREMENT_ADAPTERS, {},
            "no approved measurement adapter may be invented here; the registry is "
            "reachable only through a field added to #866's ROW_KEYS by its owner",
        )
        self.assertIsNone(
            oracle._adapter_record(_OWNER),
            "an empty registry yields no adapter record, so the adapter arm stays closed",
        )

    # -- the genuine fixtures of the owning suites still pass --------------
    def test_the_genuine_fixtures_of_both_suites_are_still_accepted(self) -> None:
        """Both accepted fixtures -- and nothing else -- must remain accepted.

        This is the regression guard for the whole repair: bullet 4's conjuncts
        are now STRICTLY STRONGER, so the proof that they were not over-tightened
        is that the two genuine migrated-consumer fixtures
        (``dep_canonical_positive.rs`` and ``accept_authorized_tokenizer_adapter.rs``,
        which cases 23 and 26 assert on) still measure no gap at all.
        """
        for fixture in ("dep_canonical_positive.rs", "accept_authorized_tokenizer_adapter.rs"):
            with self.subTest(fixture=fixture):
                measured = _measure(fixture)
                self.assertTrue(measured.declared)
                self.assertEqual(measured.accepted, measured.calls, f"{fixture} must stay accepted")
                self.assertTrue(
                    measured.no_gaps(), f"{fixture} must have no binding gap: {measured.gaps()!r}",
                )

    def test_every_bullet4_negative_fixture_is_rejected_by_its_own_conjunct(self) -> None:
        """Each negative is rejected, and each by a DIFFERENT measured conjunct.

        "Every negative is rejected" is not sufficient on its own: five fixtures
        could all be rejected by the same accident. This binds, for each fixture,
        the conjunct that eliminates it, so the five repairs stay independent.

        ==============================  =====================================
        fixture                         the conjunct that rejects it
        ==============================  =====================================
        ``reject_missing_payload_       no payload argument at all
        argument``                      (``payload_argument`` is None)
        ``reject_empty_payload_slice``   the payload is a literal ``&[]``
        ``reject_zero_declared_length`` the declared length is a literal ``0``
        ``reject_hardcoded_identity_    no provider/model/tokenizer
        fields``                        ID/version/hash is named
        ==============================  =====================================

        The ``reject_hardcoded_identity_fields`` arm does NOT require
        ``content_digest_bound``: that fixture's content digest is the literal
        ``"sha256:00"``, so the placeholder conjunct is a SECOND independent
        defect it carries. Its distinguishing conjunct -- the one the other
        three fixtures do not fail -- is ``identity_detail_bound``.

        Likewise ``reject_empty_payload_slice`` carries BOTH a literal-zero
        declared length and a literal ``&[]``, so it fails two conjuncts; the
        per-fixture sets asserted below are what prove the four negatives fail
        DISTINCT conjunct sets rather than all resting on one accident.
        """
        expectations = {
            "reject_missing_payload_argument.rs": lambda b: b["payload_argument"] is None,
            "reject_empty_payload_slice.rs": lambda b: (
                b["payload_argument"] is not None and not b["payload_non_empty"]
            ),
            "reject_zero_declared_length.rs": lambda b: (
                b["payload_argument"] is not None
                and b["payload_non_empty"]
                and not b["content_digest_bound"]
            ),
            "reject_hardcoded_identity_fields.rs": lambda b: (
                b["payload_argument"] is not None
                and b["payload_non_empty"]
                and b["final_bytes_bound"]
                and b["identity_bound"]
                and not b["identity_detail_bound"]
                and not b["identity_non_placeholder"]
            ),
        }
        for fixture, conjunct_holds in expectations.items():
            with self.subTest(fixture=fixture):
                measured = _measure(fixture)
                binding = measured.first()
                self.assertTrue(
                    conjunct_holds(binding),
                    f"{fixture} must reach the conjunct it is written to isolate; got {binding!r}",
                )
                self.assertEqual(
                    measured.accepted, [],
                    f"{fixture} must yield no accepted site",
                )
                self.assertTrue(
                    measured.first_gaps(),
                    f"{fixture} must name at least one missing conjunct",
                )
        # The four negatives fail DIFFERENT conjuncts: this is what proves the repairs
        # stay independent rather than all resting on one accident. Each entry is
        # the exact set of conjuncts that is FALSE for that fixture's single
        # binding, measured from the real predicate output.
        failed = {
            fixture: {
                name
                for name, satisfied in (
                    ("payload_argument", binding["payload_argument"] is not None),
                    ("payload_non_empty", bool(binding["payload_non_empty"])),
                    ("content_digest_bound", bool(binding["content_digest_bound"])),
                    ("identity_detail_bound", bool(binding["identity_detail_bound"])),
                    ("identity_non_placeholder", bool(binding["identity_non_placeholder"])),
                )
                if not satisfied
            }
            for fixture in expectations
            for binding in [_measure(fixture).first()]
        }
        self.assertEqual(
            failed["reject_missing_payload_argument.rs"],
            {
                "payload_argument", "payload_non_empty", "content_digest_bound",
                "identity_detail_bound", "identity_non_placeholder",
            },
            "a bare call passes no record at all, so every record conjunct fails too",
        )
        self.assertEqual(
            failed["reject_empty_payload_slice.rs"],
            {"payload_non_empty", "content_digest_bound"},
            "the empty-payload fixture fails the empty payload AND the literal-zero "
            "declared length; its identity conjuncts pass",
        )
        self.assertEqual(
            failed["reject_zero_declared_length.rs"],
            {"content_digest_bound"},
            "the zero-length fixture fails ONLY the zero declared length",
        )
        self.assertEqual(
            failed["reject_hardcoded_identity_fields.rs"],
            {"content_digest_bound", "identity_detail_bound", "identity_non_placeholder"},
            "the hardcoded-identity record fails the digest AND both identity conjuncts",
        )
        # No two fixtures fail the same set, so the four repairs are independent.
        distinct = {frozenset(value) for value in failed.values()}
        self.assertEqual(
            len(distinct), len(failed),
            "each negative must fail a DISTINCT conjunct set, or the repairs are not independent",
        )

    # -- the closed vocabulary the fix relies on --------------------------
    def test_the_binding_vocabulary_is_closed_and_non_empty(self) -> None:
        """The new conjuncts are declared data, not runtime invention.

        Every name the repair added is a module-level constant or a function of
        the masked span. Nothing is derived from a fixture literal, and no
        approved registry was added, so the vocabulary cannot be widened at
        runtime.
        """
        self.assertEqual(
            oracle.PORT_INPUT_RECORD, "SerializedContextInputs",
            "the bound record is #704's own input record",
        )
        self.assertEqual(
            oracle.PORT_FINAL_BYTES_BINDING_FIELDS, ("declared_len", "content_digest"),
            "the final-bytes conjunct names the envelope length and digest",
        )
        self.assertEqual(
            set(oracle.PORT_IDENTITY_BINDING_FIELDS), {"serializer", "route", "tokenizer"},
            "the three named identity groups are unchanged",
        )
        self.assertTrue(
            oracle.PORT_IDENTITY_REQUIRED_FIELDS,
            "the ID/version/hash conjunct must be a non-empty closed table",
        )
        self.assertTrue(
            oracle.PORT_EMPTY_PAYLOAD_LITERALS,
            "the literal empty payload forms must be a non-empty closed tuple",
        )
        self.assertTrue(
            oracle.PORT_ZERO_LENGTH_SPELLINGS,
            "the literal zero declared-length spellings must be a non-empty closed tuple",
        )
        # The placeholder set is a PREDICATE over the masked span, never a closed
        # list of literal placeholder digests. A named list would be the invented
        # registry the issue forbids: every digest outside it would pass. So what
        # is closed here is the FIELD vocabulary the predicate reports over, and
        # the predicate itself returns those field names.
        self.assertFalse(
            hasattr(oracle, "PORT_CONTENT_DIGEST_PLACEHOLDERS"),
            "there is no closed list of placeholder digest strings; a placeholder is "
            "decided by _identity_placeholders over the masked span",
        )
        producer = oracle.load_producer(_REPO_ROOT)
        self.assertEqual(
            oracle._identity_placeholders(producer._mask_rust("content_digest: ,")),
            {oracle.PORT_CONTENT_DIGEST_FIELD},
            "an EMPTY value is a placeholder too, decided by the predicate not a list",
        )


if __name__ == "__main__":
    unittest.main()