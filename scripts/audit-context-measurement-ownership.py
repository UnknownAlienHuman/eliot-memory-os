#!/usr/bin/env python3
"""Read-only Context-measurement ownership oracle and reconciliation (#787).

Issue: https://github.com/UnknownAlienHuman/eliot-memory-os/issues/787

What this is
------------
The deterministic, read-only oracle that decides whether the *serialized
post-migration* Context-measurement inventory of issue #866 is **current**,
**complete** and **internally owned**, and that reconciles the frozen #866
pre-migration baseline row identities against the current inventory.

Design constraints that shape the whole file
-------------------------------------------
1. **One immutable result, two projections.** :func:`evaluate` builds a
   single frozen :class:`OwnershipResult`. ``--format text`` and
   ``--format json`` are pure projections of that one object, so their
   counts, digests and finding codes are identical by construction. The
   result is built once per invocation and is never mutated afterwards.
2. **No second scanner.** Candidate accounting is obtained from the
   accepted #866 producer by *importing and calling* its read-only functions
   (``discover_context_measurements``, ``classify_context_measurement``,
   ``load_owner_map``, ``_validate_artifact``, ``_parse_toml``, ``_load_files``,
   ``_locate_signal``, ``_scope_of``); this file never re-implements the
   producer's discovery, classification or denominator. The unaccounted-
   estimator detector reuses the producer's *own* declared needle vocabulary
   and the producer's *own* classifier, so an estimator added to a declared
   scan root is seen through #866, not through an independent second scanner
   or a fixed local list. ``_producer_candidates`` and ``_unaccounted_candidates``
   are the consumers of the producer's row/candidate contract; the oracle
   never calls the producer's ``cmd_sync``/``build_inventory`` write path.
3. **Read-only.** No network, no ambient clock, no writes, no auto-fallback
   during normal checking. The self-test proves the evaluation region contains
   no filesystem mutation, no broad directory walk and no banned retrieval,
   clock, child-process or measurement-admission surface. Regeneration of the
   shared artifact is the #866 ``sync`` single-writer path, never an oracle
   auto-repair.
4. **Independent expected set.** The baseline reconciliation denominator is
   the *frozen* ``EXPECTED_BASELINE_ROWS`` table below, which is written out
   here independently of the producer's live row order, and is compared
   against the producer's measured baseline, never against a copy of the
   producer's own list.

Proof ceiling: STATIC_OWNERSHIP_CONFORMANCE_ONLY. A passing oracle is a
static owner/schema/unit/dependency conformance statement about source text
and the #866 inventory. It is not a tokenizer accuracy result, not a live
provider measurement, not a Context admission decision, and never a
Product or release support claim.

Usage:
  python scripts/audit-context-measurement-ownership.py --self-test
  python scripts/audit-context-measurement-ownership.py --root .
  python scripts/audit-context-measurement-ownership.py --root . --format json
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

ISSUE = 787
PRODUCER_ISSUE = 866
SCHEMA_OWNER_ISSUE = 584
MEASUREMENT_OWNER_ISSUE = 704
INTEGRATION_OWNER = "#787"

PRODUCER_SCRIPT_REL = "scripts/context_measurement_inventory.py"
INVENTORY_REL = ".github/work-units/context-measurement-inventory.toml"
OWNER_MAP_REL = ".github/work-units/context-measurement-owner-map.toml"

RESULT_SCHEMA = "eliot.context-measurement-ownership.v1"
ORACLE_VERSION = "1.0.0"
PROOF_CEILING = "STATIC_OWNERSHIP_CONFORMANCE_ONLY"

# ---------------------------------------------------------------------------
# Frozen typed failure set. Every finding the oracle can raise is one of
# these codes. A code is never invented at runtime and never widened: the
# closed tuple is asserted in the self-test and the JSON projection only
# ever emits a code from this set.
# ---------------------------------------------------------------------------
FAIL_CODES: tuple[str, ...] = (
    # inventory lifecycle
    "INVENTORY_MISSING",
    "INVENTORY_MALFORMED",
    "INVENTORY_STALE",
    "INVENTORY_INCOMPLETE",
    "PRODUCER_CHECK_BLOCKED",
    "PRODUCER_CHECK_FAILED",
    "PRODUCER_ABSENT",
    # source-row identity
    "SOURCE_ROW_MISSING",
    "SOURCE_DIGEST_CHANGED",
    "SOURCE_SPAN_CHANGED",
    "SOURCE_ROW_OVERLAP",
    "SOURCE_UNREADABLE",
    # candidate accounting
    "UNACCOUNTED_CANDIDATE",
    "CANDIDATE_UNCLASSIFIED",
    "CANDIDATE_COUNT_DRIFT",
    # ownership / schema
    "DUPLICATE_OWNER",
    "DUPLICATE_SCHEMA",
    "MISSING_CANONICAL_OWNER",
    "MISSING_DEPENDENCY",
    "GENERIC_ESTIMATOR_OWNER",
    # unit / name / proof
    "UNIT_NAME_MISMATCH",
    "PROOF_ESCALATION",
    # exceptions / baseline
    "STALE_EXCEPTION",
    "OVERBROAD_EXCEPTION",
    "BASELINE_ROW_LOST",
    "BASELINE_DISPOSITION_MISSING",
    "CONSUMER_EVIDENCE_MISSING",
    # determinism
    "DETERMINISTIC_INTERNAL_DEFECT",
)

# ---------------------------------------------------------------------------
# Canonical ownership facts. These are *normative* facts declared by the
# architecture (I2.16 / I12.32 / I18.27) and by issues #704/#584/#866. They
# are NOT copied from the producer's live rows: the oracle validates the
# producer's rows *against* these independent facts.
# ---------------------------------------------------------------------------
# Owner identities are the *string* form the #866 inventory rows carry
# ("#704"/"#783"/"#878"/"#880"). The bare issue numbers above are used only in
# prose; every owner key, lookup and evidence map uses the "#NNN" string so a
# numeric id can never silently miss an owner and report a false failure.
CANONICAL_MEASUREMENT_OWNER = f"#{MEASUREMENT_OWNER_ISSUE}"
CANONICAL_SCHEMA_OWNER = f"#{SCHEMA_OWNER_ISSUE}"
CANONICAL_SCHEMA_PATH = "crates/smart/eliot-context-contracts/src/measurement.rs"
CANONICAL_SCHEMA_TYPE = "SerializedContextMeasurement"
CANONICAL_STU_PATH = "crates/smart/eliot-context-measurement/src/stu.rs"
CANONICAL_STU_FORMULA = "stu_for_bytes"
CANONICAL_MEASUREMENT_PORT = "measure_serialized_context"

# The Cargo PACKAGE name of #704's algorithm crate. Cargo dependency facts are
# named in the manifest's own kebab-case spelling; the Rust crate identifier is
# the underscore spelling of the same name. Both come from this one constant so
# the manifest lookup and the source lookup can never drift apart.
MEASUREMENT_CRATE_PACKAGE = "eliot-context-measurement"
MEASUREMENT_CRATE_RUST = "eliot_context_measurement"

# The exact #704 input record the canonical port takes. The fields listed here
# are the closed set whose presence in a production call's span is what binds the
# call to the final serialized bytes and to the route/tokenizer identity. They
# are #704's own ``SerializedContextInputs`` field names
# (``crates/smart/eliot-context-measurement/src/lib.rs:277-308``), read here as
# the acceptance vocabulary and not as a re-implementation of the record.
PORT_INPUT_RECORD = "SerializedContextInputs"
PORT_FINAL_BYTES_BINDING_FIELDS: tuple[str, ...] = ("declared_len", "content_digest")
PORT_IDENTITY_BINDING_FIELDS: tuple[str, ...] = (
    "serializer",
    "route",
    "tokenizer",
)

# ---------------------------------------------------------------------------
# Audit section 4, bullet 4 requires the identity conjunct to be "provider/
# model/tokenizer ID/version/hash and content digest". #704's own record carries
# those facts as the FIELDS of the three identity sub-records, so the identity
# conjunct is a conjunction over those field names -- read as the acceptance
# vocabulary, not re-implemented as a new record type.
#
# The names are matched on the SAME producer-masked enclosing-item span as
# :data:`PORT_IDENTITY_BINDING_FIELDS`, so a binding named only in a comment or
# a string literal cannot satisfy them, and every identity fact is required to
# be PRESENT AND NON-PLACEHOLDER (see :func:`_identity_placeholders`): the
# sub-record field names alone, paired with hardcoded integers or a literal
# ``sha256:00``, are not an identity.
#
# The grouping is (identity group, required field names within that group):
# ``serializer`` carries the serializer id/version/options digest, ``route``
# carries the route id plus the provider id and model id, and ``tokenizer``
# carries the tokenizer id/version/hash/config digest. Every entry is a
# ``#704`` ``SerializedContextInputs`` field name
# (``crates/smart/eliot-context-measurement/src/lib.rs:277-308``).
PORT_IDENTITY_REQUIRED_FIELDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("serializer", ("serializer_id", "serializer_version", "serializer_options_digest")),
    ("route", ("route_id", "provider_id", "model_id")),
    ("tokenizer", ("tokenizer_id", "tokenizer_version", "tokenizer_hash")),
)

# The content digest of the final serialized bytes is its OWN conjunct: the
# ``content_digest`` NAME is already in
# :data:`PORT_FINAL_BYTES_BINDING_FIELDS`, but a NAME is not a digest.
PORT_CONTENT_DIGEST_FIELD = "content_digest"

# The classifications whose OWN evidence says the retired formula is still live
# at that span. Read from #866's closed ``CLASSIFICATIONS``
# (``context_measurement_inventory.py:213-231``) rather than restated: a row
# carrying one of these IS the pre-migration defect, so an owner-level
# canonical-reach proof elsewhere cannot reconcile it.
_LIVE_LEGACY_CLASSIFICATIONS: frozenset[str] = frozenset(
    {
        "token_estimate_without_tokenizer",
        "character_count_mislabeled_as_tokens",
        "estimator-policy-unvalidated",
    }
)

# A length written as a literal zero -- ``declared_len: 0`` -- declares no
# serialized bytes, so it cannot satisfy the final-bytes conjunct (see
# :func:`_envelope_length_is_zero`). The tuple is the set of zero spellings a
# masked span may carry for that literal.
PORT_ZERO_LENGTH_SPELLINGS: tuple[str, ...] = (
    "declared_len: 0",
    "declared_len:0",
    "declared_len: 0u64",
    "declared_len:0u64",
    "declared_len: 0usize",
    "declared_len:0usize",
)

# An EMPTY byte slice / empty string / empty array literal carries no serialized
# bytes at all. ``&[]``/``b""``/``&""``/``Vec::new()``-shaped *expressions* are
# deliberately NOT in this set: an expression's emptiness is a runtime fact the
# static span cannot establish, and rejecting every ``Vec::new()`` would report
# ordinary code. Only the LITERAL empty forms are matched, because those are
# unambiguously "no bytes" in the source itself.
PORT_EMPTY_PAYLOAD_LITERALS: tuple[str, ...] = ("&[]", "&[]u8", "b\"\"", "&\"\"")
# The same empty literals with the reference/bracket markers normalised away, so
# the predicate compares the DENOTATION rather than every spelling of it.
PORT_EMPTY_PAYLOAD_DENOTATIONS: tuple[str, ...] = ("[]", "[]u8", "\"\"")


def _is_empty_payload_literal(payload: str) -> bool:
    """Is the measured payload argument a LITERAL empty byte/string value?

    ``&[]``, ``[]``, ``&[]u8``, ``b""`` and ``&""`` all denote the same zero
    bytes, so the reference, bracket and byte-string markers are normalised away
    before the comparison instead of every spelling being listed twice.

    Only LITERAL empties match. An EXPRESSION whose runtime value might be empty
    (``Vec::new()``, ``self.payload()``, ``&[][..]``) is deliberately NOT matched:
    emptiness of an expression is a runtime fact a static span cannot establish,
    and treating every such expression as empty would report ordinary code.
    """
    if payload in PORT_EMPTY_PAYLOAD_LITERALS:
        return True
    denotation = payload.strip()
    while denotation[:1] in {"&", "("}:
        denotation = denotation[1:].strip()
    while denotation[-1:] in {")"}:
        denotation = denotation[:-1].strip()
    return denotation in PORT_EMPTY_PAYLOAD_DENOTATIONS


def _strip_comment_body(text: str) -> str:
    """Blank any trailing ``//`` comment on a single masked line.

    The producer's ``_mask_rust`` already blanks whole-line comments, but a
    TRAILING comment after a real binding survives masking. This keeps a
    placeholder written only in a trailing comment from satisfying a conjunct.
    The helper is deliberately conservative: a ``//`` that sits inside a string
    literal is left alone, because the masked span's quotes are the only
    evidence of where a literal ends and the line ends.
    """
    index = 0
    while True:
        position = text.find("//", index)
        if position < 0:
            return text
        quote_count = text[:position].count('"') % 2
        if quote_count:
            index = position + 2
            continue
        return text[:position]


def _field_value(span: str, field: str) -> str | None:
    """The masked value expression a ``field:`` binding carries, or None.

    Measured on the PRODUCER-MASKED span. ``_mask_rust`` blanks every string
    LITERAL BODY, so the masked form of each case is unambiguous:

    =======================================  =========================
    source                                   masked value
    =======================================  =========================
    ``provider_id: request.provider_id``     ``request.provider_id``
    ``serializer: 1,``                       ``1``          (literal)
    ``content_digest: "sha256:00",``         ``""``         (blanked)
    ``declared_len: 0,``                     ``0``          (literal)
    =======================================  =========================

    So a literal value is detectable as literal (it survives masking as a bare
    token) and a string-literal value is detectable as EMPTY (its body was
    blanked), while a real per-request value survives as a real expression.
    That is the whole measurement: the audit asks for an identity that is
    *actually named*, and a name carried by a constant or a string literal is
    not a named identity. Returns ``None`` when the field does not occur at all.
    """
    pattern = re.compile(
        r"\b" + re.escape(field) + r"\s*:\s*(?P<value>[^,}\n]*)", re.MULTILINE
    )
    for match in pattern.finditer(span):
        value = _strip_comment_body(match.group("value")).strip()
        if value:
            return value
        # A blanked string-literal body is an EMPTY value, not an absent field:
        # the field IS bound, and its value is a literal.
        return ""
    return None


def _identity_placeholders(span: str) -> set[str]:
    """The identity/digest bindings a masked span carries only as PLACEHOLDERS.

    A placeholder is a binding whose value is a CONSTANT rather than a named
    identity: a bare integer literal (``serializer: 1``), a string LITERAL whose
    body the producer's ``_mask_rust`` blanked (``content_digest: "sha256:00"``
    masks to an empty value), or an empty value. Each returns the field NAME, so
    a finding names exactly which identity is a placeholder.

    Why the masked span is the right measurement surface: a placeholder can only
    be written as a constant, and a constant survives masking as a bare token
    (integer) or as an empty value (blanked string literal). A genuine identity
    arrives from the request and survives as a real expression, which is what
    separates the two without any closed registry of approved identities --
    :data:`APPROVED_MEASUREMENT_ADAPTERS` is an honest empty and this predicate
    does not invent one. The predicate is therefore exactly "present and
    non-placeholder", which is what the audit asks for and the most the recorded
    facts can establish.
    """
    placeholders: set[str] = set()
    for field in tuple(
        name
        for _group, names in PORT_IDENTITY_REQUIRED_FIELDS
        for name in names
    ) + (PORT_CONTENT_DIGEST_FIELD,):
        value = _field_value(span, field)
        if value is None:
            # The field is absent; presence is a separate conjunct, not a
            # placeholder, so it is reported by identity_detail_bound instead.
            continue
        if not value:
            # Blanked string literal: the value is a constant, not a name.
            placeholders.add(field)
            continue
        if re.fullmatch(r"[-+]?[0-9][0-9_]*(?:[iu](?:8|16|32|64|128|size))?", value):
            # A bare integer constant standing in for an ID/version/hash.
            placeholders.add(field)
    return placeholders


def _envelope_length_is_zero(span: str) -> bool:
    """Does the span declare the envelope length as a literal zero?

    ``declared_len: 0`` is the shape a fabricated record writes: it says the
    final serialized Context is zero bytes long while still presenting the
    record as a bound observation. A real envelope's length is
    ``<something>.len()`` or arrives from the request, never a constant 0, so a
    zero literal here cannot be a legitimate measurement of a non-empty Context.
    """
    stripped = _strip_comment_body(span)
    return any(spelling in stripped for spelling in PORT_ZERO_LENGTH_SPELLINGS)

# The closed approved legacy-adapter record. An adapter may satisfy the
# dependency without calling #704's port directly only when it is listed here
# with an exact identity, an exact version, an exact expiry and the canonical
# port it implements. Every field is required; a record missing one of them is
# rejected, never treated as satisfied.
@dataclass(frozen=True)
class ApprovedAdapter:
    identity: str
    version: str
    expires: str
    implements_port: str

    def closed(self) -> bool:
        """An adapter record is closed only with all four exact fields."""
        return all(
            bool(part) for part in (self.identity, self.version, self.expires, self.implements_port)
        )


# The closed per-consumer dependency contract. Every field is measured, never
# assumed: ``cargo_package`` is looked up in the consumer's own manifest, and
# ``port_symbol`` is looked up as a production CALL. See the comment above
# :data:`CONSUMER_DEPENDENCY_CONTRACTS` for the five conjuncts a consumer must
# satisfy.
@dataclass(frozen=True)
class ConsumerDependencyContract:
    owner: str
    cargo_package: str
    port_symbol: str
    role: str = "consumer"


# Closed disposition set every baseline row must end with. A baseline row
# that simply disappears is an erased requirement and is rejected; a row
# that is still present but carries no explicit disposition is rejected.
# The set stays closed at four and is NOT widened by the evidence-bearing
# derivation below. Three values are reachable: two from the row's own closed
# recorded fields, one only when the row's owner has a *measured* canonical
# consumer dependency. ``exact-versioned-legacy-adapter`` stays declared but
# underived, and the comment immediately below says exactly why.
BASELINE_DISPOSITIONS: tuple[str, ...] = (
    "canonical-owner-consumer",
    "legitimate-non-context-metric",
    "exact-versioned-legacy-adapter",
    "explicit-unresolved",
)

# The closed ``dependency_proofs`` kinds that constitute PROVEN canonical
# reach for an owner. A row may be called ``canonical-owner-consumer`` only
# when its owner holds one of these. They are exactly the outcomes the
# dependency check in :func:`evaluate` reaches -- a real, bound production call
# to #704's port; a CLOSED approved legacy adapter record; or, for #704 itself,
# the single proved definition site of the canonical port. Nothing else, and in
# particular never the mere absence of a finding.
CANONICAL_REACH_KINDS: tuple[str, ...] = (
    "canonical-port-call",
    "canonical-port-owner",
    "approved-adapter",
)

# The classifications that describe a site which is STILL THE OLD LOCAL FORMULA
# rather than a canonical consumer: an unvalidated byte/character ratio carried
# as tokens, a characters-labelled-as-tokens ratio, or a bare measurement field
# fed by a unit conversion with no estimator policy of its own.
#
# These are the #866 producer's OWN closed classes (``CLASSIFICATIONS``,
# ``context_measurement_inventory.py:226-229``), read here as the acceptance
# vocabulary and not as a second classification scheme. They are the row-schema
# evidence that a formula was never migrated: whatever the row's owner, a site
# the producer still classes as a local ratio is not a canonical consumer, so it
# is never reconciled as one.
LEGACY_FORMULA_CLASSIFICATIONS: tuple[str, ...] = (
    "token_estimate_without_tokenizer",
    "character_count_mislabeled_as_tokens",
    "bare_measurement_field_or_conversion",
)

# An *exact* versioned legacy adapter is, per the issue, an approved adapter
# that implements/uses #704's port and binds provider/model/tokenizer
# ID/version/hash to the final serialized bytes, and that is *closed*: retired
# by an explicit recorded boundary, not merely unreadable or unwritable.
#
# No row field in #866's closed ``ROW_KEYS``
# (``context_measurement_inventory.py:533-559``) records a legacy-adapter
# marker, a version bound, or an expiry date. The two fields a tempting
# shortcut would reach for are the WRONG vocabulary and are deliberately not
# used here:
#
#   * ``write_scope`` is *mutation permission*, not closure. #866 assigns
#     ``read-only`` to a baseline row whose declared owner is one of the three
#     live consumers #783/#878/#880 reading the #704 algorithm crate
#     (``_write_scope_of`` ``:1597-1602``, and its own module docstring
#     ``:43-45`` "Read-only sharing is not shared mutable scope"). The owner
#     map says the same: it "records ownership of a candidate, not write
#     permission" (``context-measurement-owner-map.toml:24-25``). So a
#     ``read-only`` row is an ACTIVE consumer seam, the opposite of retired.
#   * ``dispatch_blocked`` is defined as ``status != "owned"`` (``:1649``) and
#     re-validated against ``status`` on the read path (``:2445-2446``), so for
#     any row that is not already ``explicit-unresolved`` it is invariably
#     ``False`` and could only restate the check the first arm already made.
#
# Deriving the disposition from either field would let a live, in-migration
# consumer be reported as a closed legacy adapter: a label that does not
# describe its subject, which is the defect class this reconciliation exists to
# repair. So the disposition stays declared-but-unreachable, and the truthful
# ``_derive_baseline_disposition`` reports every such row as
# ``explicit-unresolved`` -- a row that cannot prove it is a closed, exact,
# versioned adapter is not one. Emitting it needs a closed field added to
# #866's ``ROW_KEYS`` by its owner, not a second scheme here. That blocker is
# filed as a ContractChallenge against #866; #787 must not attempt it.

# The frozen pre-migration baseline requirement denominator. Written out here
# independently of the producer module so that a drift in either direction
# is observable; every entry must still be present in the current inventory
# and carry an explicit disposition.
EXPECTED_BASELINE_ROWS: tuple[tuple[str, str], ...] = (
    ("704/1", CANONICAL_MEASUREMENT_OWNER),
    ("704/2", CANONICAL_MEASUREMENT_OWNER),
    ("704/3", CANONICAL_MEASUREMENT_OWNER),
    ("704/4", CANONICAL_MEASUREMENT_OWNER),
    ("704/5", CANONICAL_MEASUREMENT_OWNER),
    ("704/6", CANONICAL_MEASUREMENT_OWNER),
    ("704/7", CANONICAL_MEASUREMENT_OWNER),
    ("704/8", CANONICAL_MEASUREMENT_OWNER),
    ("704/9", CANONICAL_MEASUREMENT_OWNER),
    ("783/1", "#783"),
    ("783/2", "#783"),
    ("783/3", "#783"),
    ("783/4", "#783"),
    ("783/5", "#783"),
    ("783/6", "#783"),
    ("783/7", "#783"),
    ("783/8", "#783"),
    ("878/1", "#878"),
    ("878/2", "#878"),
    ("878/3", "#878"),
    ("878/4", "#878"),
    ("878/5", "#878"),
    ("878/6", "#878"),
    ("880/1", "#880"),
    ("880/2", "#880"),
    ("880/3", "#880"),
    ("880/4", "#880"),
    ("880/5", "#880"),
    ("880/6", "#880"),
    ("880/7", "#880"),
    ("880/8", "#880"),
)
EXPECTED_BASELINE_COUNT = len(EXPECTED_BASELINE_ROWS)

# The three consumer migrations that must each leave exact evidence of the
# canonical measurement dependency in their own source. #787 never chooses the
# migration; it only requires the evidence.
#
# A dependency is *bound* evidence, not the existence or the shape of a name.
# Every field below is compared against the measured content of this operation
# -- the consumer's own Cargo metadata, its own masked production spans and its
# own call site -- so a name that merely occurs somewhere in the file proves
# nothing. The evidence is the conjunction of all five facts below; a consumer
# that satisfies any subset has no dependency proof.
#
# 1. ``cargo_dependency`` -- the consumer's OWN Cargo manifest declares
#    ``eliot-context-measurement`` under a normal/build/dev ``[dependencies]``
#    table (directly or through ``.workspace = true`` / ``{ workspace = true }``).
#    A renamed dependency still declares the real package via
#    ``package = "eliot-context-measurement"``. Read from the manifest
#    hierarchy, never from a Rust-source substring.
# 2. ``port_call`` -- a production (non-test) masked line in the consumer's
#    declared writable seam calls #704's canonical port ``measure_serialized_context``
#    as a *call*, i.e. the identifier is followed by ``(`` and is not part of a
#    path (``crate::name``/``module::name``) or of a longer identifier.
# 3. ``final_serialized_bytes`` -- the same production call passes a NON-EMPTY
#    payload argument, and the surrounding production span binds the envelope
#    length and content digest into the ``SerializedContextInputs`` record the
#    port takes (``declared_len`` and ``content_digest``), with a declared
#    length that is not a literal zero and a digest that is not a literal
#    placeholder. An ``&[]`` payload -- no serialized bytes at all -- is not a
#    bound measurement. A legitimately-empty payload cannot occur in an admitted
#    case: the admitted cases are C23/C26, "exact authorized tokenizer adapter
#    accepted" and "current final-serialized measurement with exact tokenizer
#    identity accepted", and both name a measurement OF a serialized Context
#    envelope; an empty envelope has no tokens to count, no tokenizer
#    observation to bind, and no digest of final serialized bytes to record, so
#    it is not the subject either case admits.
# 4. ``identity_binding`` -- the same production span binds the serializer,
#    route, provider, model and tokenizer identities (``serializer``/
#    ``SerializerIdentity``, ``route``/``RouteIdentity``, ``tokenizer``/
#    ``TokenizerIdentity``) into that record, WITH each identity's ID/version/
#    hash field present and carrying a non-placeholder value. A hardcoded
#    integer, an empty value or a literal ``"sha256:00"`` is not an identity:
#    the field NAME alone is not the identity the issue names.
# 5. ``adapter_record`` -- when a consumer does not call #704's port directly,
#    the only other accepted evidence is a CLOSED approved adapter record: an
#    exact adapter identity with an exact version and an exact expiry, declared
#    in :data:`APPROVED_MEASUREMENT_ADAPTERS` below. No such record exists on
#    current main, so that arm is currently unreachable by design (defect 5 of
#    the audit owns making case 25 reachable upstream, not this file); it is
#    still evaluated so an adapter record can never be forged by naming a type.
#
# The closed accepted set is one entry per closed consumer owner. An owner
# absent from :data:`CONSUMER_DEPENDENCY_CONTRACTS` has NO accepted dependency
# and can never satisfy the check, and no owner key is ever added at runtime.
#
# ``eliot_context_contracts`` (#584, the public Context contract/schema crate)
# is deliberately NOT an accepted measurement dependency. It owns the measurement
# SCHEMA; depending on it names a type, not an algorithm. A schema-only import
# with no call to #704's port is exactly the forging the audit names, so it is
# excluded here and the check has no arm that would accept it.
CONSUMER_DEPENDENCY_CONTRACTS: dict[str, "ConsumerDependencyContract"] = {
    owner: ConsumerDependencyContract(
        owner=owner,
        cargo_package=MEASUREMENT_CRATE_PACKAGE,
        port_symbol=CANONICAL_MEASUREMENT_PORT,
    )
    for owner in ("#783", "#878", "#880")
}
# #704 is the canonical measurement OWNER, not a consumer of it. Its requirement
# is that it DEFINE :data:`CANONICAL_MEASUREMENT_PORT` exactly once, which the
# ``canonical-owner`` arm of :func:`evaluate` already measures through
# :func:`_measurement_owner_sites` and reports as ``MISSING_CANONICAL_OWNER`` /
# ``GENERIC_ESTIMATOR_OWNER`` / ``DUPLICATE_OWNER``. Requiring #704 to declare a
# Cargo dependency on the crate it *is* would be a false failure against the
# algorithm owner, so its role is ``"owner"`` and it is evaluated by that
# definition-site proof. It is present in the closed table rather than absent so
# #704 still has a declared, closed role and can never be an owner with no
# declared reach.
CONSUMER_DEPENDENCY_CONTRACTS[CANONICAL_MEASUREMENT_OWNER] = ConsumerDependencyContract(
    owner=CANONICAL_MEASUREMENT_OWNER,
    cargo_package=MEASUREMENT_CRATE_PACKAGE,
    port_symbol=CANONICAL_MEASUREMENT_PORT,
    role="owner",
)

# The CLOSED approved legacy-adapter set: exact identity, exact version, exact
# expiry, and the canonical port each adapter must implement. This is the only
# way a consumer may satisfy the dependency WITHOUT calling #704's port in
# production, and an entry that names no canonical port, no exact version or no
# exact expiry is rejected by :func:`_adapter_record` rather than treated as
# satisfied. The set is empty on current main because no approved adapter record
# exists in any owned data file; that is an honest empty, not a widened accept.
APPROVED_MEASUREMENT_ADAPTERS: dict[str, tuple["ApprovedAdapter", ...]] = {}


class OracleError(RuntimeError):
    """Typed fail-closed error carrying a machine-readable reason code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        if code not in FAIL_CODES:
            # Never widen the closed failure set at runtime; an unknown code
            # is itself a deterministic internal defect.
            code = "DETERMINISTIC_INTERNAL_DEFECT"
        self.code = code
        self.detail = detail


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _stu(byte_count: int) -> int:
    """Source Token Unit = ceil(bytes / 3) (I2.16), used only for reported
    accounting. The oracle never *implements* a measurement; this mirrors the
    declared STU rule purely to reproduce the producer's reported STU totals
    and to detect a producer STU drift."""
    if byte_count <= 0:
        return 0
    return -(-int(byte_count) // 3)


# ---------------------------------------------------------------------------
# A single immutable finding and the single immutable result.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    code: str
    detail: str
    row_id: str = ""
    case_ref: str = ""
    path: str = ""
    span_start: int = 0
    span_end: int = 0
    rule: str = ""

    def __post_init__(self) -> None:
        if self.code not in FAIL_CODES:
            raise OracleError(
                "DETERMINISTIC_INTERNAL_DEFECT",
                f"finding code outside closed set: {self.code!r}",
            )

    def as_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "detail": self.detail,
            "row_id": self.row_id,
            "case_ref": self.case_ref,
            "path": self.path,
            "span_start": self.span_start,
            "span_end": self.span_end,
            "rule": self.rule,
        }

    def locator(self) -> str:
        if self.path:
            span = f"{self.span_start}-{self.span_end}" if self.span_start else ""
            ref = self.case_ref or self.row_id
            where = f"{self.path}" + (f":{span}" if span else "")
            if ref:
                return f"[{self.code}] {ref} {where} rule={self.rule}: {self.detail}"
            return f"[{self.code}] {where} rule={self.rule}: {self.detail}"
        return f"[{self.code}] {self.detail}"


@dataclass(frozen=True)
class OwnershipResult:
    """The one immutable result. Text and JSON are projections of this."""

    result_schema: str
    oracle_version: str
    issue: int
    producer_issue: int
    proof_ceiling: str
    inventory_path: str
    inventory_present: bool
    inventory_digest: str
    source_sha: str
    rule_digest: str
    owner_digest: str
    rule_revision: str
    coverage_disposition: str
    owner_map_status: str
    candidate_count: int
    classified_count: int
    owned_count: int
    unresolved_count: int
    baseline_reconciled: int
    baseline_expected: int
    baseline_dispositions: dict[str, int]
    unaccounted_candidate_count: int
    canonical_measurement_owners: tuple[str, ...]
    canonical_schema_owners: tuple[str, ...]
    dependency_proofs: dict[str, dict[str, Any]]
    producer_check_status: str
    finding_count: int
    findings: tuple[Finding, ...]
    result_digest: str

    @property
    def ok(self) -> bool:
        return self.finding_count == 0

    def _counts(self) -> dict[str, object]:
        return {
            "candidate_count": self.candidate_count,
            "classified_count": self.classified_count,
            "owned_count": self.owned_count,
            "unresolved_count": self.unresolved_count,
            "baseline_reconciled": self.baseline_reconciled,
            "baseline_expected": self.baseline_expected,
            "unaccounted_candidate_count": self.unaccounted_candidate_count,
            "finding_count": self.finding_count,
        }

    def result_body(self) -> dict[str, object]:
        return {
            "result_schema": self.result_schema,
            "oracle_version": self.oracle_version,
            "issue": self.issue,
            "producer_issue": self.producer_issue,
            "proof_ceiling": self.proof_ceiling,
            "status": "ok" if self.ok else "fail",
            "inventory_path": self.inventory_path,
            "inventory_present": self.inventory_present,
            "inventory_digest": self.inventory_digest,
            "producer_identity": {
                "rule_revision": self.rule_revision,
                "source_sha": self.source_sha,
                "rule_digest": self.rule_digest,
                "owner_digest": self.owner_digest,
                "coverage_disposition": self.coverage_disposition,
                "owner_map_status": self.owner_map_status,
                "producer_check_status": self.producer_check_status,
            },
            "counts": self._counts(),
            "baseline_dispositions": dict(sorted(self.baseline_dispositions.items())),
            "canonical_measurement_owners": list(self.canonical_measurement_owners),
            "canonical_schema_owners": list(self.canonical_schema_owners),
            "dependency_proofs": {
                owner: dict(sorted(proof.items()))
                for owner, proof in sorted(self.dependency_proofs.items())
            },
            "findings": [f.as_dict() for f in self.findings],
            "result_digest": self.result_digest,
        }


# ---------------------------------------------------------------------------
# Producer import (read-only). We import the accepted #866 module and call
# its functions; we never copy its rules.
# ---------------------------------------------------------------------------


def load_producer(root: Path) -> Any:
    """Import the accepted #866 generator module as a read-only dependency.

    Returns the loaded module object. Raises OracleError(PRODUCER_ABSENT) if
    the accepted generator is missing, so the oracle can never fall back to a
    private re-implementation of the producer's discovery/classification.
    """
    script = root / PRODUCER_SCRIPT_REL
    if not script.is_file() or script.is_symlink():
        raise OracleError(
            "PRODUCER_ABSENT",
            f"the accepted #{PRODUCER_ISSUE} generator is absent: {PRODUCER_SCRIPT_REL}",
        )
    try:
        spec = importlib.util.spec_from_file_location(
            f"_context_measurement_inventory_{ISSUE}", script
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        # Register before exec so any internal import resolves to this module.
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    except OracleError:
        raise
    except Exception as exc:  # fail closed, never a silent fallback
        raise OracleError(
            "PRODUCER_ABSENT",
            f"the accepted #{PRODUCER_ISSUE} generator could not be imported: {exc}",
        ) from exc
    for required in (
        "discover_context_measurements",
        "enumerate_measurement_candidates",
        "classify_context_measurement",
        "build_inventory",
        "load_owner_map",
        "InventoryError",
        "DENOMINATOR_CASES",
        "EXCLUSION_CASES",
        "CLASSIFICATIONS",
        "OWNER_MAP_PATH",
        "OWNED_TOML",
        "_parse_toml",
        "_package_of",
        "_validate_artifact",
        "_load_files",
        "_scope_of",
        "_locate_signal",
        "_case_sort_key",
        "_read_source",
        "_measure_test_paths",
        # The closed structural constants the artifact-read path validates
        # against. They are the producer's, not a local copy: a widened or
        # narrowed producer grammar must make the oracle fail closed as
        # PRODUCER_ABSENT, never be silently re-typed here.
        "TOP_LEVEL_KEYS",
        "HEADER_KEYS",
        "ROW_KEYS",
        "SCHEMA",
        "RULE_REVISION",
        "_sha256",
        "_canonical_bytes",
    ):
        if not hasattr(module, required):
            raise OracleError(
                "PRODUCER_ABSENT",
                f"#{PRODUCER_ISSUE} generator is missing required read-only API: {required}",
            )
    return module


# ---------------------------------------------------------------------------
# Candidate accounting obtained from the producer (the sole producer).
# ---------------------------------------------------------------------------


def _read_inventory_artifact(
    root: Path, producer: Any
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], str, bytes, str]:
    """Read the stored artifact and separate *readability* from *freshness*.

    Returns ``(header, rows, worksets, splits, inventory_digest, raw,
    aggregate_fault)``.

    Two independent things are decided here and they must not be conflated:

    *Readability* -- the artifact parses, holds the producer's closed top-level
    key set, and each row carries the producer's closed row keys and a
    ``row_digest`` that re-derives over its own content. Without that, no row can
    be named in a finding and the reconciliation is meaningless, so an
    unreadable artifact is a typed ``INVENTORY_MALFORMED`` abort.

    *Freshness* -- whether the artifact's recorded aggregates still describe the
    live tree (measured test-path bytes, measured span digests, the recorded
    inventory digest, the recorded source/rule/owner/map digests). Drift here is
    STALENESS, not malformation: the artifact is well-formed and simply no
    longer current. It is carried to the caller as ``aggregate_fault`` so the
    rest of the evaluation still runs and still reports every other finding.
    Collapsing the two is what previously let a single stale test-file size
    abort the whole reconciliation with one finding and hide the baseline,
    ownership and unit findings behind it.

    The structural key/schema/row-digest rules below are read straight off the
    producer's own closed constants (``TOP_LEVEL_KEYS``, ``ROW_KEYS``,
    ``SCHEMA``, ``RULE_REVISION``, ``CLASSIFICATIONS``) and are re-checked by
    the producer's own ``_validate_artifact`` in :func:`_producer_check`; this
    file adds no row grammar of its own, it only refuses to *read* a row the
    producer would not accept as well-formed.
    """
    target = root / INVENTORY_REL
    if not target.is_file() or target.is_symlink():
        raise OracleError(
            "INVENTORY_MISSING",
            f"the accepted #{PRODUCER_ISSUE} inventory artifact is absent: {INVENTORY_REL}",
        )
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise OracleError(
            "INVENTORY_MALFORMED",
            f"the inventory artifact could not be read: {exc}",
        ) from exc
    try:
        artifact = producer._parse_toml(raw, source=INVENTORY_REL)
    except producer.InventoryError as exc:
        raise OracleError(
            "INVENTORY_MALFORMED",
            f"the inventory artifact could not be parsed: {exc.code}: {exc.detail}",
        ) from exc

    if set(artifact.keys()) != producer.TOP_LEVEL_KEYS:
        raise OracleError(
            "INVENTORY_MALFORMED",
            f"the inventory artifact top-level keys {sorted(artifact.keys())} are not the "
            f"producer's closed set {sorted(producer.TOP_LEVEL_KEYS)}",
        )
    header = artifact.get("header")
    rows = artifact.get("rows")
    worksets = artifact.get("consumer_worksets")
    splits = artifact.get("proposed_splits")
    if not isinstance(header, dict) or not isinstance(rows, list):
        raise OracleError(
            "INVENTORY_MALFORMED",
            f"the inventory artifact header/rows are not a table and a list in {INVENTORY_REL}",
        )
    if not isinstance(worksets, list) or not isinstance(splits, list):
        raise OracleError(
            "INVENTORY_MALFORMED",
            f"consumer_worksets and proposed_splits must both be lists in {INVENTORY_REL}",
        )
    if set(header.keys()) != producer.HEADER_KEYS:
        raise OracleError(
            "INVENTORY_MALFORMED",
            f"the inventory artifact header keys are not the producer's closed set",
        )
    if header.get("schema") != producer.SCHEMA or header.get("rule_revision") != producer.RULE_REVISION:
        raise OracleError(
            "INVENTORY_MALFORMED",
            f"the inventory artifact declares schema {header.get('schema')!r} / rule revision "
            f"{header.get('rule_revision')!r}, not the producer's "
            f"{producer.SCHEMA!r} / {producer.RULE_REVISION!r}",
        )
    # Each row must be a closed-key table whose own row_digest re-derives over
    # its content. This is the producer's own per-row rule
    # (``_validate_artifact`` DIGEST_MISMATCH arm); a row that fails it cannot be
    # named in a finding, so it is a readability failure, not a drift.
    for row in rows:
        if not isinstance(row, dict) or set(row.keys()) != producer.ROW_KEYS:
            raise OracleError(
                "INVENTORY_MALFORMED",
                f"an inventory row is not a table with the producer's closed row keys",
            )
        recorded = row.get("row_digest")
        recomputed = producer._sha256(
            producer._canonical_bytes({k: v for k, v in row.items() if k != "row_digest"})
        )
        if not isinstance(recorded, str) or recorded != recomputed:
            raise OracleError(
                "INVENTORY_MALFORMED",
                f"inventory row {row.get('id')} carries a row_digest that does not re-derive "
                f"over its own content",
            )
    if not isinstance(artifact.get("inventory_digest"), str):
        raise OracleError(
            "INVENTORY_MALFORMED",
            f"the inventory artifact declares no string inventory_digest: {INVENTORY_REL}",
        )
    if not rows:
        raise OracleError(
            "INVENTORY_INCOMPLETE",
            f"the inventory artifact carries no rows; an empty inventory never succeeds",
        )

    # The producer's own full validation -- measured test-path bytes, span
    # digests, aggregate arithmetic, the closed workset/split tables and the
    # recorded inventory digest -- still runs, but through
    # :func:`_producer_check`, which reports its verdict as a freshness finding.
    # Its result is deliberately not used to gate row reading here.
    return header, rows, worksets, splits, str(artifact["inventory_digest"]), raw, ""


def _declared_universe(rows: list[dict[str, Any]]) -> tuple[tuple[str, str, str, str], ...]:
    """The scan universe the *stored artifact itself* declares.

    Each inventory row carries the exact ``(case_ref, owner, path, signal)``
    identity #866 measured. Reconstructing that tuple set is how the oracle
    asks the producer to re-discover the very same universe -- it is the
    artifact's own declaration, never a list hard-coded here, so a row the
    producer added and a row the producer dropped both change the question the
    producer is asked and both are visible as drift.
    """
    return tuple(
        (str(r["case_ref"]), str(r["owner"]), str(r["path"]), str(r["signal"])) for r in rows
    )


def _producer_candidates(
    root: Path, producer: Any, declared: tuple[tuple[str, str, str, str], ...]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Obtain the producer's own file records and candidates through the
    accepted #866 read-only API.

    This is the *sole* candidate accounting for the oracle. Every location,
    classification, span and digest below is produced by the #866 producer's own
    functions over the artifact's own universe and needle vocabulary, never by a
    second scanner written here, and the producer's ``sync`` is never called.

    The one structural choice this function makes is *isolation*: the producer's
    :func:`discover_context_measurements` fails closed on the FIRST declared
    identity it cannot measure, so a single signal that a consumer migration
    legitimately removed (the estimator site is gone; that is the point of the
    migration) would abort the whole call and hide every other candidate -- and
    with them every row-coverage, span-digest, classification and
    unaccounted-candidate check. That single signal is itself a finding, but it
    must not be able to suppress the reconciliation of the other 71 rows.

    So the producer's discovery is driven **one declared identity at a time**.
    Each call is still the producer's own discovery for that identity and can
    still only return that identity's producer-measured record or raise that
    identity's producer-typed error; the batch simply collects the outcomes
    instead of collapsing on the first one. A case that cannot be measured is
    returned in the ``absent`` list with the producer's own error code and is
    reported by the caller as a named finding. ``file_records`` is the union of
    the per-case file records, so a path only an unmeasurable case declared still
    contributes its digest and the recorded ``source_sha`` stays re-derivable.

    Returns ``(file_records, candidates, absent)``.
    """
    ordered = sorted(declared, key=lambda item: producer._case_sort_key(str(item[0])))
    files: dict[str, dict[str, Any]] = {}
    candidates: list[dict[str, Any]] = []
    absent: list[dict[str, Any]] = []
    for case_ref, owner, rel, signal in ordered:
        # Each call is the producer's own discovery for exactly one declared
        # identity, reusing the producer's own loader, locator, scope and
        # classifier. Passing a one-case tuple keeps the producer's own
        # fail-closed, closed-owner-set, closed-classification checks in force.
        try:
            case_files, case_candidates = producer.discover_context_measurements(
                root, ((case_ref, owner, rel, signal),)
            )
        except producer.InventoryError as exc:
            absent.append(
                {
                    "case_ref": str(case_ref),
                    "owner": str(owner),
                    "path": str(rel),
                    "signal": str(signal),
                    "code": exc.code,
                    "detail": exc.detail,
                }
            )
            continue
        for record in case_files:
            files.setdefault(str(record["path"]), record)
        candidates.extend(case_candidates)
    # The file records carry the exact producer-measured sha256 per scan root
    # the run actually loaded. They are reported so the evaluation can name a
    # declared root that was never measured; a root missing here is one where no
    # declared identity in it could be loaded, which the caller reports as
    # SOURCE_UNREADABLE.
    file_records = [files[rel] for rel in sorted(files)]
    # Candidates are returned in the producer's own case order so downstream
    # comparisons and digests never depend on dictionary iteration order.
    candidates.sort(key=lambda item: producer._case_sort_key(str(item["case_ref"])))
    absent.sort(key=lambda item: (str(item["path"]), str(item["case_ref"])))
    return file_records, candidates, absent


def _producer_check(
    root: Path, producer: Any, raw: bytes, declared: tuple[tuple[str, str, str, str], ...]
) -> tuple[str, str]:
    """Decide the producer's freshness verdict and validate its declared
    source/rule/owner-map input digests against the live tree.

    The stored artifact's *raw* bytes are exactly the bytes the producer's
    re-emission is compared to, and exactly the bytes a digest is computed
    over; they are used here so freshness is decided by the producer's own
    re-emission rather than by trusting a recorded digest or a commit SHA.
    Separately, the *recorded* ``source_sha``/``rule_digest``/``owner_digest``/
    ``owner_map_digest`` header values are validated against the values the
    producer itself derives from the live tree, so a relevant source/rule/
    allocation/owner-map change is caught and named.


    Returns ``(status, detail)``; ``status`` is ``"ok"`` or a typed non-ok
    token (``"stale"``, ``"blocked"``, ``"error"``, ``"digest-mismatch"``).

    The producer's own full validation is reused as the *freshness* authority,
    not as a gate on reading rows. When it rejects the stored artifact because a
    measured input moved (a test-path size, a span digest, an aggregate sum), the
    verdict is ``"stale"``: the artifact is well-formed and no longer current.
    Only a verdict that means the bytes cannot be *interpreted* at all stays an
    ``"error"``. This is what lets one stale input be reported as exactly that
    while the reconciliation continues.
    """
    # The recorded inventory digest must equal a digest computed over the
    # artifact's own content -- recomputing to *validate* the recorded value,
    # never to trust a stored digest blindly.
    try:
        artifact = producer._parse_toml(raw, source=INVENTORY_REL)
    except producer.InventoryError as exc:
        return "error", f"{exc.code}: {exc.detail}"
    recorded_inventory_digest = str(artifact.get("inventory_digest", ""))
    try:
        # Validate the recorded inventory_digest over the artifact content.
        #
        # The canonicalisation MUST span the producer's own closed top-level
        # key set -- header, rows, consumer_worksets AND proposed_splits --
        # because that is exactly the mapping ``build_inventory`` digests
        # (scripts/context_measurement_inventory.py: ``inventory["inventory_digest"]
        # = _sha256(_canonical_bytes(inventory))``) and exactly the mapping its
        # own ``_validate_artifact`` re-derives when it rejects
        # ``DIGEST_MISMATCH``. Omitting ``proposed_splits`` here would hash a
        # strict subset of the content, so the oracle would compare the
        # producer's full-content digest against a narrower digest and report
        # a mismatch on a perfectly valid artifact -- rejecting on a digest it
        # itself normalised wrongly, and leaving the producer's actual split
        # accounting unverified. Including it reproduces the producer's own
        # normalisation; it does not relax the comparison, because the digest
        # still has to be re-derived from the artifact content rather than
        # trusted.
        recomputed_inventory_digest = _sha256(
            _canonical_bytes(
                {
                    "header": artifact["header"],
                    "rows": artifact["rows"],
                    "consumer_worksets": artifact["consumer_worksets"],
                    "proposed_splits": artifact["proposed_splits"],
                }
            )
        )
    except (TypeError, KeyError) as exc:
        return "error", f"artifact content could not be re-canonicalised: {exc}"
    if recorded_inventory_digest != recomputed_inventory_digest:
        return (
            "digest-mismatch",
            f"recorded inventory_digest {recorded_inventory_digest[:16]} does not match the "
            f"digest computed over the artifact's own content "
            f"{recomputed_inventory_digest[:16]}",
        )

    # The producer's own aggregate/workset/split validation, run exactly as its
    # `check` runs it (measure the declared test paths, then validate). This is
    # the freshness authority: it re-derives every recorded measurement against
    # the live tree. A rejection here is staleness, not malformation -- the
    # structural grammar was already decided (and passed) in
    # :func:`_read_inventory_artifact`.
    try:
        _wsets = artifact.get("consumer_worksets")
        if not isinstance(_wsets, list):
            return "error", "consumer_worksets must be a list in the inventory artifact"
        _header, _rows, _worksets, _splits = producer._validate_artifact(
            artifact, producer._measure_test_paths(root, _wsets)
        )
    except producer.InventoryError as exc:
        return (
            "stale",
            f"the #{PRODUCER_ISSUE} producer's recorded aggregates no longer describe the live "
            f"tree: {exc.code}: {exc.detail}",
        )

    # Validate the recorded source/rule/owner digests against the live tree,
    # using the producer's own derivation of each over the artifact's OWN
    # declared universe. A recorded value is validated, never trusted.
    #
    # The source digest is re-derived from the producer's own file loader over
    # the declared scan roots. That is deliberately NOT routed through
    # ``discover_context_measurements``: discovery locates each *signal*, so a
    # signal that a consumer migration legitimately removed would abort the whole
    # call and hide the digest verdict. File digests do not depend on any
    # individual signal still being present, and the vanished signal is reported
    # separately, by name, as its own finding class.
    header = artifact["header"]
    try:
        measured_rule_digest = producer._rule_digest()
        measured_owner_digest = producer._owner_digest(declared)
        scan_roots = tuple(sorted({str(path) for _ref, _owner, path, _sig in declared}))
        file_cache = producer._load_files(root, scan_roots)
        source_pairs = sorted(
            f"{rel}:{str(file_cache[rel]['sha256'])}" for rel in scan_roots
        )
        measured_source_sha = _sha256("\n".join(source_pairs).encode("utf-8"))
        owner_map = producer.load_owner_map(root)
        measured_map_digest = owner_map[2]
    except producer.InventoryError as exc:
        return "error", f"{exc.code}: {exc.detail}"
    for label, recorded, measured in (
        ("rule_digest", str(header.get("rule_digest", "")), measured_rule_digest),
        ("owner_digest", str(header.get("owner_digest", "")), measured_owner_digest),
        ("source_sha", str(header.get("source_sha", "")), measured_source_sha),
        ("owner_map_digest", str(header.get("owner_map_digest", "")), measured_map_digest),
    ):
        if recorded != measured:
            return (
                "stale",
                f"recorded {label} {recorded[:16]} does not match the value derived from the "
                f"live tree {measured[:16]}; a relevant source/rule/allocation/owner-map "
                f"input changed since the artifact was generated",
            )

    # Byte-identity freshness: the producer's own re-emission of the declared
    # universe must equal the stored bytes. This is the same operation the
    # producer's own ``check`` performs, and it is what makes an unrelated HEAD
    # move (which changes no scan input) NOT stale the artifact, while any
    # change to a scan root, rule, or owner allocation does.
    #
    # A rebuild that cannot complete because a declared signal no longer exists
    # is staleness with a named cause, not an unreadable error: the artifact
    # describes a source state the tree has since left behind.
    try:
        mapping, map_status, map_digest = producer.load_owner_map(root)
        fresh = producer.build_inventory(
            root, declared,
            str(header.get("generation_command", "")),
            (mapping, map_status, map_digest),
        )
        fresh_raw = producer._emit_toml(fresh)
    except producer.InventoryError as exc:
        return (
            "stale",
            f"the #{PRODUCER_ISSUE} producer can no longer re-emit the stored artifact from "
            f"the live tree: {exc.code}: {exc.detail}",
        )
    if fresh_raw == raw:
        return "ok", "producer re-emission is byte-identical to the stored artifact"
    fresh_header = fresh["header"] if isinstance(fresh, dict) else {}
    if str(fresh_header.get("coverage_disposition", "")) != "COMPLETE" or str(
        fresh_header.get("owner_map_status", "")
    ) != "SUPPLIED":
        return (
            "blocked",
            f"producer rebuild leaves coverage {fresh_header.get('coverage_disposition')!r} / "
            f"owner map {fresh_header.get('owner_map_status')!r}: "
            f"{fresh_header.get('coverage_reason')}",
        )
    return "stale", "producer re-emission differs from the stored artifact"


def _enumerated_unaccounted(
    root: Path,
    producer: Any,
    rows: list[dict[str, Any]],
    scan_roots: list[str],
) -> list[dict[str, Any]]:
    """Independently enumerate the producer's scan roots and diff vs the rows.

    This is the C7 repair. The declared-identity check above asks the producer
    to re-locate the signals the *stored rows already declare*, so it can only
    ever re-find what the artifact already accounts for: an estimator added to a
    declared scan root with no stored row is invisible to it. That is the
    "C7 is impossible" defect -- the universe was seeded from the very thing it
    was supposed to check.

    Here the universe is NOT seeded from stored rows. The producer's own
    :func:`enumerate_measurement_candidates` walks each declared scan root and
    returns every site the accepted rules already match, before any owner
    allocation, so a newly written estimator is seen *because the producer's own
    grammar sees it* and not because of any list written here.

    Accounting is then a set difference over exact ``(path, span_start)`` spans:
    an enumerated site with no stored row at that span is an
    ``UNACCOUNTED_CANDIDATE`` finding naming its path, span and the producer rule
    that matched it. A declared-exclusion site is the producer's own answer for
    that location and is not re-reported.

    Only the forward direction is claimed. The producer's trigger arms
    (``ESTIMATOR_HELPER_RE``/``ESTIMATOR_CALL_RE``/``CHAR_RATIO``/``BYTE_RATIO``)
    match estimators *by lexical shape*; most declared denominator rows anchor on
    a plain identifier such as ``declared_len`` or ``serialized_bytes`` that no
    trigger arm matches, so "row present but not enumerated" is not a defect and
    asserting it here would invent a second, stricter denominator. Row-to-source
    truth is settled by the declared-identity arm above, which re-locates every
    declared signal through the producer's own locator.

    The finding carries ``rule`` so the audit can name WHICH accepted rule
    fired, and ``case_ref`` is empty for a site no row declares -- an undeclared
    estimator has no case identity, and inventing one would be inventing the
    very accounting this check exists to force.
    """
    if not scan_roots:
        return []
    try:
        enumerated = producer.enumerate_measurement_candidates(root, tuple(scan_roots))
    except producer.InventoryError as exc:
        raise OracleError(
            "SOURCE_UNREADABLE",
            f"a declared scan root could not be enumerated by the "
            f"#{PRODUCER_ISSUE} producer: {exc.code}: {exc.detail}",
        ) from exc

    # A stored row is accounted at its span START: that is the anchor both the
    # producer's locator and its row schema agree on.
    accounted: dict[tuple[str, int], str] = {}
    for row in rows:
        accounted[(str(row["path"]), int(row["span_start"]))] = str(row["case_ref"])

    findings: list[dict[str, Any]] = []
    for cand in enumerated:
        rel = str(cand["path"])
        span_start = int(cand["span_start"])
        label = str(cand["classification"])
        if label == "declared-exclusion":
            # The producer already declared this exact unrelated metric with its
            # own reason. Re-reporting it would be a second, weaker answer to a
            # question the sole producer has already answered.
            continue
        if label == "test-only":
            # The producer's own rule 1 classes a test-scope site as carrying
            # no shipped measurement. #787 audits SHIPPED measurement ownership,
            # so it does not re-litigate that scope decision with a stricter rule
            # of its own -- doing so would manufacture findings the sole
            # classification authority never makes, and would report every
            # #[cfg(test)] assertion that touches the estimator vocabulary.
            continue
        if (rel, span_start) in accounted:
            # A stored row already sits at this exact span. The declared-identity
            # arm above checks whether that row still matches live source, so the
            # same site is never reported twice for one defect.
            continue
        code = "CANDIDATE_UNCLASSIFIED" if label == "unclassified" else "UNACCOUNTED_CANDIDATE"
        findings.append(
            {
                "code": code,
                "path": rel,
                "span_start": span_start,
                "span_end": int(cand["span_end"]),
                "signal": str(cand["signal"]),
                "case_ref": "",
                "rule": str(cand["rule"]),
                "label": label,
                "item": str(cand["item"]),
                "item_scope": str(cand["item_scope"]),
                "evidence": (
                    f"the #{PRODUCER_ISSUE} producer independently enumerates a measurement "
                    f"candidate at {rel}:{span_start}-{cand['span_end']} (rule "
                    f"{cand['rule']}, class {label}, {cand['item_scope']} scope, inside "
                    f"`{cand['item']}`) but no stored inventory row accounts for that span; "
                    f"an estimator added to a declared scan root must carry its own row: "
                    f"{cand['evidence']}"
                ),
            }
        )
    findings.sort(key=lambda item: (item["code"], item["path"], item["span_start"]))
    return findings


def _unaccounted_candidates(
    root: Path,
    producer: Any,
    rows: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    header: dict[str, Any],
) -> list[dict[str, Any]]:
    """Detect an added, moved or removed unaccounted estimator through #866.

    Candidate accounting is the producer's, and it is obtained by *calling*
    the producer, never by a second scanner written here. Two complementary
    producer-driven facts are checked:

    **(a) Declared-identity completeness.** The producer's denominator is a set
    of ``(case_ref, owner, path, signal)`` identities, and for each the
    producer locates exactly one span by asking its own masked-source loader
    for the *first* masked line in that path holding that signal. We re-ask
    the producer to re-locate every declared identity and require the stored
    rows to cover exactly those spans, under exactly those producers. An
    estimator that is added to a declared seam, removed from one, or that
    relocates because new source was inserted above it changes what the
    producer locates, so this fires. The needle vocabulary is the producer's
    ``DENOMINATOR_CASES``; this file contributes no pattern of its own, so an
    added estimator is seen *because the producer's own discovery saw it*,
    never because of a fixed local list.

    **(b) Declared-exclusion integrity.** The producer declares an exact
    exclusion set (``EXCLUSION_CASES``) for genuinely unrelated byte or
    character metrics. Every declared exclusion must still be a live,
    non-test occurrence in a declared scan root, must still classify as the
    producer's unrelated-metric class, and must not be reused to excuse a
    measurement row. A stale exclusion (its needle vanished) or an overbroad
    one (a measurement-bearing row leans on it) is rejected by name.

    Test-scope occurrences are routed through the producer's ``_scope_of`` and
    are not shipped measurements (producer classification rule 1).
    """
    accounted: dict[tuple[str, int], str] = {}
    for row in rows:
        accounted[(str(row["path"]), int(row["span_start"]))] = str(row["case_ref"])

    findings: list[dict[str, Any]] = []

    # (a) Declared-identity completeness, measured by the producer.
    producer_paths = sorted({str(c["path"]) for c in candidates})
    if not producer_paths:
        return findings
    try:
        cache = producer._load_files(root, tuple(producer_paths))
    except producer.InventoryError as exc:
        raise OracleError(
            "SOURCE_UNREADABLE",
            f"a declared scan root could not be loaded: {exc.code}: {exc.detail}",
        ) from exc
    for cand in candidates:
        rel = str(cand["path"])
        signal = str(cand["signal"])
        case_ref = str(cand["case_ref"])
        # Ask the producer to locate this declared identity now.
        try:
            span_start, span_end = producer._locate_signal(cache[rel], rel, signal)
        except producer.InventoryError as exc:
            findings.append(
                {
                    "code": "UNACCOUNTED_CANDIDATE",
                    "path": rel,
                    "span_start": 0,
                    "span_end": 0,
                    "signal": signal,
                    "case_ref": case_ref,
                    "label": "SIGNAL_ABSENT",
                    "evidence": (
                        f"the #{PRODUCER_ISSUE} producer can no longer locate its declared "
                        f"signal {signal!r} in {rel}: {exc.code}: {exc.detail}"
                    ),
                }
            )
            continue
        owner_ref = accounted.get((rel, span_start))
        if owner_ref is None:
            findings.append(
                {
                    "code": "UNACCOUNTED_CANDIDATE",
                    "path": rel,
                    "span_start": span_start,
                    "span_end": span_end,
                    "signal": signal,
                    "case_ref": case_ref,
                    "label": str(cand["classification"]),
                    "evidence": (
                        f"the #{PRODUCER_ISSUE} producer locates declared identity "
                        f"{case_ref} ({signal!r}) at {rel}:{span_start}-{span_end} but no "
                        f"stored row accounts for that span; an estimator is present in a "
                        f"declared scan root without an inventory row"
                    ),
                }
            )

    # (b) Declared-exclusion integrity, measured by the producer.
    #
    # The exclusion set under audit is the one *this artifact declares* (its
    # own ``exclusions`` header), not the producer's process-wide default: a
    # bounded declared universe legitimately records none. Each recorded
    # evidence string names ``case_ref|path:span|digest|reason|class``; the
    # needle is recovered from the producer's own declared exclusion table, so
    # the oracle still contributes no needle vocabulary of its own. A
    # declaration that names an exclusion the producer does not declare is
    # itself an overbroad/invented exception.
    recorded_exclusions = header.get("exclusions") or []
    declared_exclusions: list[tuple[str, str, str, str]] = []
    if recorded_exclusions:
        by_ref = {str(case[0]): case for case in producer.EXCLUSION_CASES}
        for entry in recorded_exclusions:
            parts = str(entry).split("|")
            if len(parts) < 3 or not parts[0]:
                findings.append(
                    {
                        "code": "OVERBROAD_EXCEPTION",
                        "path": "",
                        "span_start": 0,
                        "span_end": 0,
                        "signal": "",
                        "case_ref": parts[0] if parts else "",
                        "label": "UNDECLARED_EXCLUSION_EVIDENCE",
                        "evidence": (
                            f"the artifact records malformed exclusion evidence {entry!r}; an "
                            f"exception must name its exact case, span and digest"
                        ),
                    }
                )
                continue
            case_ref = parts[0]
            if case_ref not in by_ref:
                findings.append(
                    {
                        "code": "OVERBROAD_EXCEPTION",
                        "path": parts[1].split(":", 1)[0] if ":" in parts[1] else parts[1],
                        "span_start": 0,
                        "span_end": 0,
                        "signal": "",
                        "case_ref": case_ref,
                        "label": "UNDECLARED_EXCLUSION",
                        "evidence": (
                            f"the artifact claims exclusion {case_ref} but the "
                            f"#{PRODUCER_ISSUE} producer declares no such exclusion; an "
                            f"exception is never invented by the artifact"
                        ),
                    }
                )
                continue
            _c, rel, needle, _reason = by_ref[case_ref]
            # The producer's OWN declared reason is carried, never one written
            # here: an exception's justification belongs to the producer that
            # declares the exception, and an oracle that supplied its own would
            # be inventing the very thing it is meant to audit.
            declared_exclusions.append((case_ref, str(rel), str(needle), str(_reason)))
    exclusion_paths = sorted({rel for _c, rel, _n, _r in declared_exclusions})
    if exclusion_paths:
        try:
            exclusion_cache = producer._load_files(root, tuple(exclusion_paths))
        except producer.InventoryError as exc:
            raise OracleError(
                "SOURCE_UNREADABLE",
                f"a declared exclusion input could not be loaded: {exc.code}: {exc.detail}",
            ) from exc
        measurement_spans = {
            (str(r["path"]), int(r["span_start"])) for r in rows
        }
        for case_ref, rel, needle, reason in sorted(
            producer.EXCLUSION_CASES, key=lambda item: str(item[0])
        ):
            try:
                span_start, span_end = producer._locate_signal(exclusion_cache[rel], rel, needle)
            except producer.InventoryError as exc:
                findings.append(
                    {
                        "code": "STALE_EXCEPTION",
                        "path": str(rel),
                        "span_start": 0,
                        "span_end": 0,
                        "signal": str(needle),
                        "case_ref": str(case_ref),
                        "label": "STALE_EXCEPTION",
                        "evidence": (
                            f"declared exclusion {case_ref} is stale: its needle {needle!r} "
                            f"no longer occurs in {rel}: {exc.code}"
                        ),
                    }
                )
                continue
            # The producer classifies a declared exclusion needle in
            # production scope (``discover_exclusions`` passes the default
            # ``item_scope="production"``). #787 does not re-litigate that
            # scope decision with a stricter rule of its own: inventing a
            # narrower scope rule here would manufacture a finding the sole
            # classification authority never makes. The two arms that remain
            # are the ones the producer's own semantics support -- a needle
            # that no longer exists (stale), and an exclusion that overlaps a
            # measurement-bearing row (overbroad).
            if (str(rel), span_start) in measurement_spans:
                findings.append(
                    {
                        "code": "OVERBROAD_EXCEPTION",
                        "path": str(rel),
                        "span_start": span_start,
                        "span_end": span_end,
                        "signal": str(needle),
                        "case_ref": str(case_ref),
                        "label": "OVERBROAD_EXCEPTION",
                        "evidence": (
                            f"declared exclusion {case_ref} overlaps a measurement row at "
                            f"{rel}:{span_start}; an exclusion may never excuse a "
                            f"measurement-bearing row"
                        ),
                    }
                )
    findings.sort(key=lambda item: (item["code"], item["path"], item["span_start"]))
    return findings


# ---------------------------------------------------------------------------
# Ownership / schema / dependency / unit checks.
# ---------------------------------------------------------------------------


def _schema_owner_sites(root: Path, producer: Any, scan_roots: list[str]) -> list[dict[str, Any]]:
    """Find every *definition* site of the canonical schema type in source.

    This uses the producer's own masked-line loader and the producer's own
    canonical classification vocabulary (the schema type name is a
    producer-declared serializer/schema signal). It finds ``struct
    <Type>`` definition lines (a declaration that opens a body), which is what
    makes two *mutable* schema definitions a duplicate, as opposed to a
    non-divergent alias/re-export (a ``use``/``pub use``/type reference).
    """
    needle = CANONICAL_SCHEMA_TYPE
    decl = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+" + re.escape(needle) + r"\b")
    results: list[dict[str, Any]] = []
    try:
        cache = producer._load_files(root, tuple(scan_roots))
    except producer.InventoryError as exc:
        raise OracleError(
            "SOURCE_UNREADABLE",
            f"a declared scan root could not be loaded for schema detection: {exc.code}: {exc.detail}",
        ) from exc
    for rel in scan_roots:
        record = cache[rel]
        for lineno, line in enumerate(record["masked_lines"], start=1):
            if decl.match(line):
                _item, scope = producer._scope_of(
                    record["masked_lines"], record["depths"], lineno, rel
                )
                if scope == "test":
                    continue
                results.append({"path": rel, "span_start": lineno, "span_end": lineno})
    return results


def _measurement_owner_sites(
    root: Path, producer: Any, scan_roots: list[str]
) -> list[dict[str, Any]]:
    """Find definition sites of the canonical STU / measurement entry points."""
    needles = (CANONICAL_STU_FORMULA, CANONICAL_MEASUREMENT_PORT)
    decl = re.compile(
        r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+("
        + "|".join(re.escape(n) for n in needles)
        + r")\b"
    )
    results: list[dict[str, Any]] = []
    try:
        cache = producer._load_files(root, tuple(scan_roots))
    except producer.InventoryError as exc:
        raise OracleError(
            "SOURCE_UNREADABLE",
            f"a declared scan root could not be loaded for owner detection: {exc.code}: {exc.detail}",
        ) from exc
    for rel in scan_roots:
        record = cache[rel]
        for lineno, line in enumerate(record["masked_lines"], start=1):
            if decl.match(line):
                _item, scope = producer._scope_of(
                    record["masked_lines"], record["depths"], lineno, rel
                )
                if scope == "test":
                    continue
                results.append({"path": rel, "span_start": lineno, "span_end": lineno})
    return results


# ---------------------------------------------------------------------------
# Authoritative Cargo dependency facts.
#
# WHY THIS READER EXISTS HERE AND NOT ELSEWHERE. The audit requires the exact
# Cargo dependency to be verified "from authoritative Cargo metadata, not a
# Rust-source substring". The repository's other Cargo-metadata readers
# (``scripts/verify-dependency-policy.py``, ``scripts/crate_reachability_inventory.py``,
# ``scripts/migration_inventory_1860.py``, ``scripts/integration/ignored_test_inventory.py``)
# all shell out to a Cargo resolver and parse its JSON. This oracle may not: its
# own closed self-test bans the child-process surface module-wide (case 787/30,
# "no network/write/measurement/admission/broad-skip implementation", which the
# #866 producer's module docstring extends to "never spawns a child process"),
# and the normal checking path is declared read-only, clock-free and network-free.
# Reusing a resolver-spawning reader would import exactly the surface this
# oracle's contract forbids.
#
# So the metadata is read with the producer's OWN read-only readers, reused
# rather than restated: ``_parse_toml`` (``context_measurement_inventory.py``
# ``:2062-2069``) parses the committed ``Cargo.toml`` and ``_package_of``
# (``:779-805``) resolves the owning package by the same upward walk the
# producer uses for every inventory row. Both are required read-only API in
# :func:`load_producer`, so a producer that lost either fails closed as
# ``PRODUCER_ABSENT`` instead of this oracle silently growing a second Cargo
# grammar. What remains here is the *dependency-table* reader -- "does this
# package declare this package as a dependency, and where" -- which reads only
# declared ``[dependencies]`` tables, never Rust source.
# ---------------------------------------------------------------------------

# Cargo dependency tables. ``target.<cfg>.dependencies`` is flattened in: a
# Windows-only dependency is a real dependency of a Windows consumer, and an
# audit that ignored it would let a platform-gated measurement edge through
# unproved.
CARGO_DEPENDENCY_TABLES: tuple[str, ...] = (
    "dependencies",
    "dev-dependencies",
    "build-dependencies",
)


def _read_cargo_manifest(producer: Any, root: Path, path: Path) -> dict[str, Any]:
    """Parse one committed ``Cargo.toml`` with the PRODUCER's own TOML reader.

    The decode/parse/table-check is the accepted #866 ``_parse_toml``
    (``context_measurement_inventory.py:2062-2069``), reused as-is and translated
    into this oracle's typed failure code. A second TOML grammar here would be a
    second scheme for reading committed metadata: a manifest this oracle and the
    producer could disagree about is exactly the disagreement a dependency proof
    must not have.
    """
    resolved = path.resolve(strict=False)
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise OracleError(
            "SOURCE_UNREADABLE",
            f"Cargo manifest could not be read: {resolved.as_posix()}",
        ) from exc
    try:
        return producer._parse_toml(raw, source=resolved.as_posix())
    except producer.InventoryError as exc:
        raise OracleError(
            "INVENTORY_MALFORMED",
            f"Cargo manifest is malformed: {resolved.as_posix()}: {exc.detail}",
        ) from exc


def _cargo_package_manifest(producer: Any, root: Path, rel: str) -> tuple[str, Path]:
    """The nearest ``Cargo.toml`` at or above ``rel``, and its package name.

    The upward walk is the accepted #866 ``_package_of``
    (``context_measurement_inventory.py:779-805``) -- the same walk the producer
    uses to attribute every inventory row to its Cargo package -- reused rather
    than restated. Only the manifest's PATH is resolved here, because
    ``_package_of`` returns the package NAME; the path is the same
    ``<dir>/Cargo.toml`` the producer's walk stopped at. That manifest -- not a
    Rust-source substring -- is the consumer's authoritative Cargo metadata.
    """
    package = producer._package_of(root, rel)
    current = (root / rel).parent
    while True:
        manifest = current / "Cargo.toml"
        if manifest.is_file() and not manifest.is_symlink():
            document = _read_cargo_manifest(producer, root, manifest)
            declared = document.get("package")
            if isinstance(declared, dict) and isinstance(declared.get("name"), str):
                if str(declared["name"]) == package:
                    return (package, manifest)
        if current == root:
            break
        parent = current.parent
        try:
            parent.relative_to(root)
        except ValueError:
            break
        current = parent
    raise OracleError(
        "SOURCE_UNREADABLE",
        f"no Cargo package manifest declares the crate owning {rel}; a consumer seam "
        f"outside every Cargo package has no authoritative dependency metadata",
    )


def _cargo_dependency_declarations(
    producer: Any, root: Path, manifest: Path
) -> dict[str, list[tuple[str, str]]]:
    """Every dependency declaration of one package, keyed by real package name.

    Returns ``{declared_package_name: [(table, alias), ...]}``. The KEY is always
    the real package name, so a renamed dependency is recorded under the package
    it actually pulls. ``table`` is the declared table's path, e.g.
    ``target.'cfg(windows)'.dependencies``, so a finding can name exactly where
    the dependency was declared.
    """
    document = _read_cargo_manifest(producer, root, manifest)
    declared: dict[str, list[tuple[str, str]]] = {}

    def collect(table: Any, label: str) -> None:
        if not isinstance(table, dict):
            return
        for alias, value in table.items():
            if isinstance(value, str):
                # ``foo = "1.0"`` style: the alias IS the package name.
                package, _req = alias, value
            elif isinstance(value, dict):
                renamed = value.get("package")
                package = renamed if isinstance(renamed, str) else alias
            else:
                continue
            if isinstance(package, str) and package:
                declared.setdefault(package, []).append((label, alias))

    for name in CARGO_DEPENDENCY_TABLES:
        collect(document.get(name), name)
    targets = document.get("target")
    if isinstance(targets, dict):
        for triple, target_table in targets.items():
            if not isinstance(triple, str) or not isinstance(target_table, dict):
                continue
            for name in CARGO_DEPENDENCY_TABLES:
                collect(target_table.get(name), f"target.'{triple}'.{name}")
    return declared


def _cargo_dependency_facts(
    producer: Any, root: Path, rels: Sequence[str], package: str
) -> tuple[bool, str]:
    """Does the package owning ``rels[0]`` declare ``package`` as a dependency?

    Returns ``(declared, evidence)``. ``evidence`` names the exact declaring
    table so a finding cites the manifest line the decision came from, not a
    paraphrase.
    """
    _manifest_name, manifest = _cargo_package_manifest(producer, root, rels[0])
    deltas = _cargo_dependency_declarations(producer, root, manifest)
    sites = deltas.get(package, [])
    if not sites:
        return (
            False,
            f"{manifest.relative_to(root.resolve()).as_posix()} declares no dependency on "
            f"{package!r} in any {', '.join(CARGO_DEPENDENCY_TABLES)} table",
        )
    table, alias = sorted(sites)[0]
    return (True, f"{manifest.relative_to(root.resolve()).as_posix()} [{table}] declares {alias!r}")


def _port_call_sites(
    producer: Any, record: dict[str, Any], rel: str, port_symbol: str
) -> list[dict[str, Any]]:
    """Production call sites of ``port_symbol`` in one producer-masked record.

    A site qualifies only when ALL of these hold, and each is load-bearing:

    * the identifier occurs in a MASKED line, so a comment or a string literal
      body is already blanked out by the producer's ``_mask_rust`` and can never
      produce a site;
    * it is followed by ``(`` -- a CALL, not an import, a type mention or a
      re-export;
    * it is not preceded by ``::`` and not part of a longer identifier, so
      ``crate::measure_serialized_context``, ``mod::measure_serialized_context``
      and ``measure_serialized_context_local`` are all rejected;
    * the enclosing item scope measured by the producer's own ``_scope_of`` is
      production, so a call inside ``#[cfg(test)]``/``#[test]``/``mod tests``
      never produces a site;
    * the ENCLOSING ITEM is REACHED by production code. A private ``fn`` no
      production item calls is dead code: naming the port inside it binds
      nothing. Reachability is measured on the item's own declaration line by
      :func:`_reachable_item_starts`, not on the call line.

    Returns one record per accepted site with its exact line and enclosing item.
    ``span_start``/``span_end`` cover the CALL itself -- from the call line to
    the line where its parenthesis nesting closes -- so a cited span always
    covers the call it names and is never a zero-width line.
    """
    masked_lines = record["masked_lines"]
    depths = record["depths"]
    reachable = _reachable_item_starts(producer, record, rel)
    item_re = producer.ITEM_RE
    sites: list[dict[str, Any]] = []
    needle = re.compile(
        r"(?<![\w:])" + re.escape(port_symbol) + r"\s*\(",
    )
    for lineno, line in enumerate(masked_lines, start=1):
        if not needle.search(line):
            continue
        item, scope = producer._scope_of(masked_lines, depths, lineno, rel)
        if scope == "test":
            continue
        # The enclosing item's declaration line, measured with the producer's own
        # item grammar: the last item declaration at or above the call whose
        # extent reaches the call line.
        enclosing = 0
        for index in range(lineno - 1, -1, -1):
            if item_re.match(masked_lines[index]) is not None:
                if producer._item_extent(masked_lines, depths, index + 1) >= lineno:
                    enclosing = index + 1
                    break
        if enclosing == 0 or enclosing not in reachable:
            continue
        # The site records the CALL's own extent, measured from the call line to
        # the line where the call's parenthesis nesting closes -- the same
        # top-level-argument splitter :func:`_call_arguments` walks. A site whose
        # span were a single zero-width line (``span_start == span_end``) would
        # name the call without covering any of it, so a finding could cite a
        # span that proves nothing about the call. ``span_end`` is therefore at
        # least ``span_start + 1`` whenever a call actually opens there, and it
        # covers the whole call including a wrapped argument list.
        call_end = _call_extent(masked_lines, lineno)
        sites.append(
            {
                "path": rel,
                "span_start": lineno,
                "span_end": max(lineno + 1, call_end),
                "item": item,
                "item_start": enclosing,
            }
        )
    return sites


def _reachable_item_starts(producer: Any, record: dict[str, Any], rel: str) -> set[int]:
    """1-based line numbers of items production code can actually reach.

    Measured from the producer's own masked lines, with the producer's own
    ``ITEM_RE`` grammar and its own ``_item_extent``:

    * a ``pub`` item -- or a ``pub(...)``-anything item -- is reachable by
      definition, because it is nameable from outside its module;
    * any item whose own name is CALLED or PATHED somewhere outside its own
      extent is reachable;
    * ``main`` is reachable.

    Anything else -- an unannotated private helper nothing calls -- is dead and
    is excluded. This is deliberately conservative in the accepting direction
    only for the two unambiguous classes: a public item and a called item. A
    private helper called only by another dead helper stays dead, which is the
    correct answer for "never called" and never hides a real production call,
    because a real production call is itself a call site from a reachable item.
    """
    masked_lines = record["masked_lines"]
    depths = record["depths"]
    item_re = producer.ITEM_RE
    declarations: list[tuple[int, str, bool]] = []
    for index, line in enumerate(masked_lines):
        match = item_re.match(line)
        if match is None:
            continue
        declarations.append(
            (index + 1, str(match.group("name")), bool(re.match(r"\s*pub(\s|\()", line)))
        )
    # A name is CALLED only where it occurs OUTSIDE its own declaration line.
    # Counting the declaration itself would make every function its own caller
    # and would turn the dead-code class into an unreachable one.
    declaration_lines = {start for start, _name, _pub in declarations}
    called: set[str] = set()
    for name in {name for _start, name, _pub in declarations}:
        pattern = re.compile(r"(?<![\w:])" + re.escape(name) + r"(?![\w])")
        if any(
            pattern.search(line)
            for lineno, line in enumerate(masked_lines, start=1)
            if lineno not in declaration_lines
        ):
            called.add(name)
    reachable: set[int] = set()
    for start, name, is_public in declarations:
        if is_public or name in called or name == "main":
            reachable.add(start)
    del rel  # the reachability decision is per-file, not per-owner
    return reachable


def _port_call_bindings(
    producer: Any, record: dict[str, Any], rel: str, site: dict[str, Any]
) -> dict[str, object]:
    """What the production call at ``site`` binds, measured over its item span.

    The bindings are read from the PRODUCER-MASKED lines of the enclosing item
    (located with the producer's own ``_item_extent``), so a binding named only
    in a comment or a string literal cannot satisfy them.

    ``payload_argument`` is the span-level fact that the call passes a payload:
    the port's first parameter is the final serialized bytes, and the call site
    must supply an argument in that position.

    The three ADDITIONAL conjuncts measure what the payload and the record
    actually carry, not merely that their field NAMES occur:

    ``payload_non_empty``
        the payload argument is not a literal empty byte/string slice, so an
        ``&[]`` -- no serialized bytes at all -- cannot satisfy the binding;
    ``content_digest_bound`` / ``identity_detail_bound`` / ``identity_non_placeholder``
        the recorded digest is a real digest and every provider/model/tokenizer
        ID/version/hash is present and non-placeholder. See
        :data:`PORT_IDENTITY_REQUIRED_FIELDS` and :func:`_identity_placeholders`.
    """
    masked_lines = record["masked_lines"]
    depths = record["depths"]
    lineno = int(site["span_start"])
    # The enclosing item's own span, measured from its declaration line with the
    # producer's ``_item_extent`` -- NOT from the call line, because a
    # ``SerializedContextInputs`` literal is normally built BEFORE the call that
    # consumes it, and a binding that only looked below the call would miss every
    # real call site.
    item_start = int(site.get("item_start") or lineno)
    span_end = producer._item_extent(masked_lines, depths, item_start)
    span = "\n".join(masked_lines[item_start - 1 : span_end])
    # The record is a struct literal whose fields legitimately span many lines,
    # so the binding is searched over the whole enclosing item's MASKED span --
    # never over one line, and never over a raw line. A field named only in a
    # comment or a string literal is blanked out by the producer's ``_mask_rust``
    # before this search runs, so it cannot satisfy a binding.
    #
    # The SECOND argument of the call is the ``&SerializedContextInputs`` the
    # port takes, and THAT is the binding: the record whose fields are measured
    # is the record the call passes. The measured argument text is extracted
    # from the masked call's own extent, so a record built but never passed
    # cannot carry the proof, and a record passed but never built cannot either.
    inputs_argument = _call_inputs_argument(masked_lines, span_end, lineno)
    carries_record = (
        inputs_argument is not None
        and _binds_that_argument(inputs_argument, span)
    )
    # The payload argument is the text between the call's opening parenthesis and
    # the first top-level comma, measured over the WHOLE wrapped call so a
    # payload on a continuation line is seen (see :func:`_call_payload_argument`).
    payload = _call_payload_argument(masked_lines, span_end, lineno)
    # The placeholder scan runs over the span with TRAILING comments stripped, so
    # a placeholder written only beside a real binding cannot satisfy it either.
    placeholders = _identity_placeholders(span) if carries_record else {
        *(name for _group, names in PORT_IDENTITY_REQUIRED_FIELDS for name in names),
        PORT_CONTENT_DIGEST_FIELD,
    }
    content_digest_bound = (
        carries_record
        and PORT_CONTENT_DIGEST_FIELD in span
        and not _envelope_length_is_zero(span)
        and PORT_CONTENT_DIGEST_FIELD not in placeholders
    )
    identity_detail_bound = carries_record and all(
        name in span
        for _group, names in PORT_IDENTITY_REQUIRED_FIELDS
        for name in names
    )
    identity_non_placeholder = identity_detail_bound and not placeholders
    return {
        "payload_argument": payload,
        "inputs_argument": inputs_argument,
        "payload_non_empty": payload is not None
        and not _is_empty_payload_literal(payload),
        "final_bytes_bound": carries_record
        and all(field in span for field in PORT_FINAL_BYTES_BINDING_FIELDS),
        "content_digest_bound": content_digest_bound,
        "identity_bound": carries_record
        and all(field in span for field in PORT_IDENTITY_BINDING_FIELDS),
        "identity_detail_bound": identity_detail_bound,
        "identity_non_placeholder": identity_non_placeholder,
        "placeholder_bindings": sorted(placeholders),
    }


def _call_inputs_argument(
    masked_lines: list[str], span_end: int, lineno: int
) -> str | None:
    """The masked call's SECOND argument, or None when the span has no second one.

    #704's port signature is ``measure_serialized_context(payload: &[u8],
    inputs: &SerializedContextInputs)`` (``crates/smart/eliot-context-measurement/
    src/lib.rs:460-463``), so the bound record is the second argument. It may wrap
    across lines, so the argument text is measured from the call line down to the
    point where the call's parenthesis nesting closes.

    The call's arguments are SPLIT on the top-level commas -- the commas at the
    call's own nesting depth, ignoring commas inside a nested ``(...)``/``{...}``/
    ``[...]`` expression such as a nested call or struct literal -- and the
    SECOND argument is returned. Returning the first (which is what a naive
    "text before the first comma" read gives) would hand back the payload and
    could never observe the record; returning a whole-argument string for arg 2
    keeps the check bound to what the call actually passes.
    """
    arguments = _call_arguments(masked_lines, span_end, lineno)
    if len(arguments) < 2:
        return None
    return arguments[1].strip() or None


def _call_extent(masked_lines: list[str], lineno: int) -> int:
    """The 1-based line where the call opening on ``lineno`` closes.

    Returns ``lineno`` itself when the call's parenthesis nesting never closes
    within the file (a genuinely unterminated call), so the caller always gets a
    span that at least covers the call line rather than a zero-width span.
    """
    depth = 0
    opened = False
    for index in range(lineno - 1, len(masked_lines)):
        for char in masked_lines[index]:
            if char in "([":
                depth += 1
                opened = True
            elif char in ")]":
                depth -= 1
                if opened and depth == 0:
                    return index + 1
    return lineno


def _call_arguments(masked_lines: list[str], span_end: int, lineno: int) -> list[str]:
    """The masked call's top-level arguments, in order, up to ``span_end``.

    Scanning starts at the FIRST opening parenthesis at or after the canonical
    port identifier on ``lineno`` and runs to the line where that parenthesis's
    nesting closes. Anchoring on the port call rather than on the start of the
    line matters: in ``wrap(x).measure_serialized_context(p, i)`` the leading
    ``wrap(`` closes before the port's own ``(``, so scanning from the line start
    would read ``wrap``'s arguments and measure the wrong call. A comma only
    separates arguments at the call's own depth (``depth == 1``); a comma nested
    inside a call/struct/bracket expression is carried in the argument text. A
    trailing comma does not produce a final empty argument.
    """
    depth = 0
    opened = False
    current: list[str] = []
    arguments: list[str] = []
    index = lineno - 1
    while index < min(span_end, len(masked_lines)):
        line = masked_lines[index]
        for position, char in enumerate(line):
            if not opened:
                # Locate the port's own call parenthesis. The anchor is the same
                # exact-identifier condition :func:`_port_call_sites` uses to
                # accept a site, so the splitter and the site finder can never
                # disagree about which parenthesis is the call's.
                if char == "(" and _port_call_opens_at(line, position):
                    opened = True
                    depth = 1
                continue
            if char in "([":
                depth += 1
            elif char in ")]":
                depth -= 1
                if depth == 0:
                    arguments.append("".join(current))
                    return [arg for arg in arguments if arg.strip()]
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            if depth >= 1:
                if char == "," and depth == 1:
                    arguments.append("".join(current))
                    current = []
                else:
                    current.append(char)
        index += 1
    if opened:
        arguments.append("".join(current))
    return [arg for arg in arguments if arg.strip()]


def _port_call_opens_at(line: str, position: int) -> bool:
    """Does the ``(`` at ``position`` belong to the canonical port's own call?

    True when the exact port identifier ends immediately before this
    parenthesis, allowing intervening whitespace, and the identifier is neither
    preceded by ``::`` nor part of a longer name -- the same condition
    :func:`_port_call_sites` uses to accept a site, so the argument splitter and
    the site finder can never disagree about which parenthesis is the call's.
    """
    prefix = line[:position]
    match = re.search(
        r"(?<![\w:])" + re.escape(CANONICAL_MEASUREMENT_PORT) + r"\s*$", prefix
    )
    return match is not None


def _binds_that_argument(inputs_argument: str, span: str) -> bool:
    """Is the call's second argument actually bound to a ``SerializedContextInputs``?

    The argument is bound when EITHER

    * it names :data:`PORT_INPUT_RECORD` directly -- an inline
      ``&SerializedContextInputs { .. }`` literal at the call site; or
    * it is a reference into a local binding whose own right-hand side is a
      ``SerializedContextInputs`` literal -- the ordinary shape of a real
      migrated consumer, which builds the record first and passes ``&inputs``.

    The second form is what makes the proof BOUND rather than nominal: the
    variable the call passes is followed to the record it was assigned from, in
    the same masked enclosing-item span, so a call that passes an unrelated
    ``&something_else``, or passes nothing, or passes a hand-rolled struct of
    the same field names, satisfies neither arm. The span is producer-masked, so
    a ``let x = SerializedContextInputs`` appearing only in a comment or a string
    literal has been blanked out and cannot supply the binding.
    """
    normalized = inputs_argument.strip()
    if re.search(r"\b" + re.escape(PORT_INPUT_RECORD) + r"\b", normalized):
        return True
    # ``&inputs`` / ``inputs`` / ``self.inputs`` -- take the trailing path
    # segment, which is the local binding's name.
    identifier = re.split(r"[.&\s]", normalized.lstrip("&"))[-1]
    if not identifier or not identifier.isidentifier():
        return False
    # The local must be assigned a ``SerializedContextInputs`` literal in the
    # same masked span. Match ``let <mut>? <name> ... = SerializedContextInputs``
    # and require the record type on the right-hand side of that binding.
    binding = re.compile(
        r"\blet\s+(?:mut\s+)?" + re.escape(identifier) + r"\b[^=;]*=\s*"
        + re.escape(PORT_INPUT_RECORD) + r"\b"
    )
    return bool(binding.search(span))


def _call_payload_argument(
    masked_lines: list[str], span_end: int, lineno: int
) -> str | None:
    """The masked call's first argument, or None when the port passes no payload.

    The canonical port's first parameter is ``payload: &[u8]`` -- the final
    serialized bytes (``crates/smart/eliot-context-measurement/src/lib.rs:460-463``).
    A call with no argument, or one whose first argument is empty, binds no bytes
    and is not evidence of a bound measurement.

    WHAT A CORRECT ARGUMENT LOOKS LIKE. It is the first top-level argument of the
    port's OWN parenthesis, measured with the SAME splitter as
    :func:`_call_inputs_argument` (:func:`_call_arguments`), so the payload and
    the input record can never be split by two different comma rules and
    disagree about where one argument ends and the next begins. A well-formed
    payload is therefore any non-empty first argument -- an identifier, a field
    path (``&request.payload``), a slice expression (``&payload[a..b]``), a call
    (``&req.render()``) -- because the port's parameter type already fixes what a
    correct payload must BE, and re-deciding that from the text would be a second
    grammar this oracle does not own.

    WHY THE WHOLE CALL, NOT LINE 1. The argument list of a real call is
    routinely wrapped: ``measure_serialized_context(\\n    &request.payload,\\n
    &inputs,\\n)``. Reading only ``masked_line`` -- the CALL'S FIRST LINE --
    sees the opening ``(`` and no comma before the line ends, so the splitter
    reports no argument at all and the real payload is recorded as absent. That
    is a false negative on the genuine fixture shape, so this function takes the
    masked LINES of the call's own extent and the line the call opens on, exactly
    like :func:`_call_inputs_argument`.

    WHY AN INLINED STRUCT LITERAL DOES NOT MIS-ANCHOR. The splitter anchors on
    the port's own ``(`` (:func:`_port_call_opens_at`) and treats ``(``, ``[``,
    ``{`` as depth-increasing and their partners as depth-decreasing, so the
    ``&SerializedContextInputs { .. }`` passed as the SECOND argument -- with its
    own braces, parens and commas -- is carried in argument 2's text and can
    never be read as argument 1 or terminate the scan early. Argument 1 is
    therefore always the text before the first top-level comma, whatever that
    comma is nested in.
    """
    arguments = _call_arguments(masked_lines, span_end, lineno)
    if not arguments:
        return None
    payload = arguments[0].strip()
    return payload or None


def _binding_gaps(entry: Mapping[str, Any]) -> list[str]:
    """Name the measured bindings a production port call does NOT make.

    Returns the missing conjuncts in a fixed order so a finding is deterministic
    and a fixture can be rejected for exactly one named reason rather than for
    whatever happened to be checked first. An empty list means the call is fully
    bound and may carry the proof.
    """
    gaps: list[str] = []
    if entry.get("payload_argument") is None:
        gaps.append("a final serialized byte payload argument")
    elif not entry.get("payload_non_empty"):
        gaps.append(
            "a payload argument that is not an empty byte/string literal "
            f"({'/'.join(PORT_EMPTY_PAYLOAD_LITERALS)})"
        )
    elif not entry.get("final_bytes_bound"):
        gaps.append(
            f"the envelope length/digest binding "
            f"({'/'.join(PORT_FINAL_BYTES_BINDING_FIELDS)}) into {PORT_INPUT_RECORD}"
        )
    elif not entry.get("content_digest_bound"):
        gaps.append(
            f"a non-placeholder {PORT_CONTENT_DIGEST_FIELD} value "
            f"(not a constant, a blanked string literal or an empty value)"
        )
    if not entry.get("identity_bound"):
        gaps.append(
            f"the serializer/route/tokenizer identity binding "
            f"({'/'.join(PORT_IDENTITY_BINDING_FIELDS)}) into {PORT_INPUT_RECORD}"
        )
    elif not entry.get("identity_detail_bound"):
        required = "/".join(
            name for _group, names in PORT_IDENTITY_REQUIRED_FIELDS for name in names
        )
        gaps.append(
            f"the provider/model/tokenizer ID/version/hash binding "
            f"({required}) into {PORT_INPUT_RECORD}"
        )
    elif not entry.get("identity_non_placeholder"):
        gaps.append(
            "a non-placeholder value for every identity binding "
            "(a hardcoded integer, an empty value and a literal "
            "'sha256:00' are not an identity)"
        )
    return gaps


def _adapter_record(owner: str) -> dict[str, object] | None:
    """The closed approved-adapter evidence for ``owner``, if any.

    An adapter record counts only when it is CLOSED: an exact identity, an exact
    version, an exact expiry and the canonical port it implements. A record
    missing any of those is not evidence, so no adapter can be approved by naming
    a type or by omitting its boundary.
    """
    records = APPROVED_MEASUREMENT_ADAPTERS.get(owner, ())
    closed = [record for record in records if record.closed()]
    if len(closed) != len(records):
        raise OracleError(
            "DETERMINISTIC_INTERNAL_DEFECT",
            f"an approved measurement adapter for {owner} is not a closed record "
            f"(identity/version/expiry/port are all required)",
        )
    if not closed:
        return None
    return {
        "identity": closed[0].identity,
        "version": closed[0].version,
        "expires": closed[0].expires,
        "implements_port": closed[0].implements_port,
    }


def _dependency_evidence(root: Path, producer: Any, rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Measure each consumer's canonical measurement dependency.

    Every field of the returned evidence is a measured fact about this
    operation, not the presence or the shape of a name:

    ``cargo_dependencies``
        per ``path`` -> ``(declared, evidence)`` from that package's own
        ``Cargo.toml`` dependency tables;
    ``calls``
        per ``path`` -> the production call sites of #704's canonical port, with
        the item and line each was measured at;
    ``bindings``
        per ``path`` -> per call site, the measured final-serialized-bytes and
        identity bindings;
    ``accepted_sites``
        per ``path`` -> only the call sites that bind BOTH the payload argument
        and the envelope identities, i.e. the sites that may carry the proof.

    A consumer is proven only if its Cargo metadata declares #704's crate AND at
    least one accepted site exists. A comment, a string literal, a similarly
    named local function, a schema-only import, a test-only call and dead code
    each fail a specific conjunct and are named by the conjunct they fail.
    """
    owner_paths: dict[str, set[str]] = {}
    for row in rows:
        if row["write_scope"] != "writable":
            continue
        owner = str(row["owner"])
        if owner == "unresolved":
            continue
        owner_paths.setdefault(owner, set()).add(str(row["path"]))
    all_paths = sorted({path for paths in owner_paths.values() for path in paths})
    if not all_paths:
        return {"cargo_dependencies": {}, "calls": {}, "bindings": {}, "accepted_sites": {}}
    try:
        cache = producer._load_files(root, tuple(all_paths))
    except producer.InventoryError as exc:
        raise OracleError(
            "SOURCE_UNREADABLE",
            f"a consumer seam could not be loaded for dependency evidence: {exc.code}: {exc.detail}",
        ) from exc

    cargo_dependencies: dict[str, dict[str, Any]] = {}
    calls: dict[str, dict[str, list[dict[str, Any]]]] = {}
    bindings: dict[str, dict[str, list[dict[str, Any]]]] = {}
    accepted_sites: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for owner, paths in owner_paths.items():
        contract = CONSUMER_DEPENDENCY_CONTRACTS.get(owner)
        ordered = sorted(paths)
        owner_cargo: dict[str, Any] = {}
        owner_calls: dict[str, list[dict[str, Any]]] = {}
        owner_bindings: dict[str, list[dict[str, Any]]] = {}
        owner_accepted: dict[str, list[dict[str, Any]]] = {}
        for rel in ordered:
            if contract is None or contract.role == "owner":
                # No closed contract, or the owner of the algorithm crate: the
                # owner's reach is proved by its single definition site (the
                # ``canonical-owner`` arm), never by a self-dependency.
                reason = (
                    f"owner {owner} has no closed dependency contract"
                    if contract is None
                    else f"owner {owner} owns the canonical port; its reach is proved by its "
                    f"definition site, not by a Cargo dependency on itself"
                )
                owner_cargo[rel] = (False, reason)
                continue
            declared, cargo_evidence = _cargo_dependency_facts(
                producer, root, (rel,), contract.cargo_package
            )
            owner_cargo[rel] = (declared, cargo_evidence)
            sites = _port_call_sites(producer, cache[rel], rel, contract.port_symbol)
            owner_calls[rel] = sites
            measured = [
                {"site": site, **_port_call_bindings(producer, cache[rel], rel, site)}
                for site in sites
            ]
            owner_bindings[rel] = measured
            # An accepted site is a call that satisfies EVERY conjunct the issue
            # names for bullet 4 -- it passes a real, non-empty final serialized
            # byte payload, and the record it passes binds the envelope
            # length/digest and a present, non-placeholder provider/model/
            # tokenizer ID/version/hash. A site that fails any of them is NOT
            # accepted, and the conjunct it fails is named by
            # :func:`_binding_gaps` on the finding path.
            owner_accepted[rel] = [
                entry["site"]
                for entry in measured
                if not _binding_gaps(entry)
            ]
        cargo_dependencies[owner] = owner_cargo
        calls[owner] = owner_calls
        bindings[owner] = owner_bindings
        accepted_sites[owner] = owner_accepted
    return {
        "cargo_dependencies": cargo_dependencies,
        "calls": calls,
        "bindings": bindings,
        "accepted_sites": accepted_sites,
    }


# ---------------------------------------------------------------------------
# The single evaluation. Everything below accumulates findings into one list
# and produces one immutable result.
# ---------------------------------------------------------------------------


def evaluate(root: Path) -> OwnershipResult:
    """Build the one immutable ownership result for ``root``.

    This is the only place findings are produced. It performs no writes, uses
    no network, reads no ambient clock, and never auto-repairs. The text and
    JSON outputs are projections of the returned object.
    """
    root = root.resolve()
    findings: list[Finding] = []

    def add(
        code: str,
        detail: str,
        row_id: str = "",
        case_ref: str = "",
        path: str = "",
        span_start: int = 0,
        span_end: int = 0,
        rule: str = "",
    ) -> None:
        _record(findings, code, detail, row_id, case_ref, path, span_start, span_end, rule)

    producer = load_producer(root)

    # --- Inventory artifact present, closed, and producer-consistent. -----
    # ``raw`` is the artifact's exact serialized bytes. They are what a
    # freshness digest is computed over, so they are bound here and used by
    # ``_producer_check`` -- never left unused, and never replaced by a
    # recorded digest value that would have to be taken on trust.
    try:
        header, rows, worksets, splits, inventory_digest, raw, _fault = (
            _read_inventory_artifact(root, producer)
        )
    except OracleError as exc:
        add(exc.code, exc.detail, rule="inventory-lifecycle")
        return _finalize(
            root,
            findings,
            header={},
            rows=[],
            worksets=[],
            inventory_digest="",
            candidates=[],
            check_status="error",
            unaccounted=[],
            dependency={},
            schema_sites=[],
            owner_sites=[],
            dependency_proofs={},
            # No rows were read, so no baseline row was reconciled. The tally is
            # an honest all-zero: the artifact is malformed, not a tree whose
            # baseline happens to be empty.
            baseline_dispositions={d: 0 for d in BASELINE_DISPOSITIONS},
        )

    # The scan universe is the artifact's own declared case set: #866's own
    # row identities, never a list fixed here.
    declared = _declared_universe(rows)

    # --- Producer freshness verdict (read-only, once). ---------------------
    check_status, check_detail = _producer_check(root, producer, raw, declared)
    if check_status not in ("ok",):
        if check_status == "blocked":
            add(
                "PRODUCER_CHECK_BLOCKED",
                f"#{PRODUCER_ISSUE} check is blocked: {check_detail}",
                rule="producer-freshness",
            )
        elif check_status == "stale":
            add(
                "INVENTORY_STALE",
                f"#{PRODUCER_ISSUE} check reports the artifact is stale: {check_detail}",
                rule="producer-freshness",
            )
        elif check_status == "digest-mismatch":
            # A recorded digest that disagrees with the measured CONTENT digest
            # is a malformed artifact: the bytes no longer hash to the digest the
            # artifact itself declares. Reported against the exact named input.
            add(
                "INVENTORY_MALFORMED",
                f"#{PRODUCER_ISSUE} recorded content digest disagrees with the measured tree: "
                f"{check_detail}",
                rule="producer-input-digests",
            )
        else:
            add(
                "PRODUCER_CHECK_FAILED",
                f"#{PRODUCER_ISSUE} check failed: {check_detail}",
                rule="producer-freshness",
            )

    # --- Producer's own candidate accounting (the sole producer). ---------
    #
    # Measured one declared identity at a time (see :func:`_producer_candidates`)
    # so that a declared identity the producer can no longer locate is reported
    # as itself -- a named finding -- instead of aborting the whole accounting
    # and hiding the remaining rows' reconciliation.
    file_records, candidates, absent = _producer_candidates(root, producer, declared)
    for item in absent:
        add(
            "SOURCE_ROW_MISSING",
            f"the #{PRODUCER_ISSUE} producer can no longer measure declared identity "
            f"{item['case_ref']} (owner {item['owner']}): its signal {item['signal']!r} no "
            f"longer occurs in {item['path']} ({item['code']}: {item['detail']}); the stored "
            f"row no longer corresponds to live source",
            case_ref=str(item["case_ref"]),
            path=str(item["path"]),
            rule="row-coverage",
        )

    # --- Source row identity: missing, changed digest, changed span, dupes.
    by_case: dict[str, dict[str, Any]] = {}
    seen_row_identity: dict[tuple[str, int], str] = {}
    for row in rows:
        case_ref = str(row["case_ref"])
        if case_ref in by_case:
            add(
                "SOURCE_ROW_OVERLAP",
                f"duplicate case_ref in the inventory: {case_ref}",
                row_id=str(row["id"]),
                case_ref=case_ref,
                path=str(row["path"]),
                span_start=int(row["span_start"]),
                span_end=int(row["span_end"]),
                rule="row-identity",
            )
        by_case[case_ref] = row
        identity = (str(row["path"]), int(row["span_start"]))
        if identity in seen_row_identity:
            add(
                "SOURCE_ROW_OVERLAP",
                f"row span start {identity[0]}:{identity[1]} is claimed by rows "
                f"{seen_row_identity[identity]} and {row['id']}",
                row_id=str(row["id"]),
                case_ref=case_ref,
                path=identity[0],
                span_start=identity[1],
                span_end=int(row["span_end"]),
                rule="row-identity",
            )
        else:
            seen_row_identity[identity] = str(row["id"])

    # Match measured candidates (from the producer) to stored rows by case_ref.
    for cand in candidates:
        case_ref = str(cand["case_ref"])
        row = by_case.get(case_ref)
        if row is None:
            add(
                "SOURCE_ROW_MISSING",
                f"the producer discovered candidate {case_ref} at "
                f"{cand['path']}:{cand['span_start']} but no stored row accounts for it",
                case_ref=case_ref,
                path=str(cand["path"]),
                span_start=int(cand["span_start"]),
                span_end=int(cand["span_end"]),
                rule="row-coverage",
            )
            continue
        if str(row["path"]) != str(cand["path"]):
            add(
                "SOURCE_SPAN_CHANGED",
                f"candidate {case_ref} moved: stored {row['path']}, measured {cand['path']}",
                row_id=str(row["id"]),
                case_ref=case_ref,
                path=str(cand["path"]),
                rule="row-coverage",
            )
            continue
        if str(row["span_digest"]) != str(cand["span_digest"]):
            add(
                "SOURCE_SPAN_CHANGED",
                f"candidate {case_ref} span digest changed: stored {row['span_digest'][:16]}, "
                f"measured {cand['span_digest'][:16]}",
                row_id=str(row["id"]),
                case_ref=case_ref,
                path=str(cand["path"]),
                span_start=int(cand["span_start"]),
                span_end=int(cand["span_end"]),
                rule="row-coverage",
            )
        if str(row["source_sha256"]) != str(cand["source_sha256"]):
            add(
                "SOURCE_DIGEST_CHANGED",
                f"candidate {case_ref} source file digest changed: stored "
                f"{row['source_sha256'][:16]}, measured {cand['source_sha256'][:16]}",
                row_id=str(row["id"]),
                case_ref=case_ref,
                path=str(cand["path"]),
                rule="row-coverage",
            )
        if str(row["classification"]) != str(cand["classification"]):
            add(
                "CANDIDATE_UNCLASSIFIED",
                f"candidate {case_ref} classification changed: stored "
                f"{row['classification']}, measured {cand['classification']}",
                row_id=str(row["id"]),
                case_ref=case_ref,
                path=str(cand["path"]),
                rule="row-coverage",
            )

    # --- Candidate count drift between producer candidates and stored rows.
    #
    # Every declared identity was *asked*; each produced either a measured
    # candidate or a named absence. The denominator of that accounting is
    # therefore ``candidates + absent`` -- the number the producer was actually
    # asked about -- compared against the stored row count. An absent identity
    # already carries its own ``SOURCE_ROW_MISSING`` finding above, so this
    # comparison is not double counting: it answers a different question, namely
    # whether the stored artifact accounts for every identity the oracle put to
    # the producer.
    measured_total = len(candidates) + len(absent)
    if measured_total != len(rows):
        add(
            "CANDIDATE_COUNT_DRIFT",
            f"the producer was asked about {measured_total} declared identities "
            f"({len(candidates)} measured, {len(absent)} unmeasurable) but the inventory "
            f"stores {len(rows)} rows",
            rule="row-coverage",
        )

    # --- Declared scan-root readability, from the producer's own loader verdicts.
    #
    # A declared root is reported unreadable ONLY when the producer's own loader
    # rejected an identity declared in that root for a reason that is not the
    # signal having migrated away. A root whose identities all report
    # ``SIGNAL_ABSENT`` is a readable file whose measurement sites were migrated
    # out of it -- that is a row-coverage fact, already reported once per
    # identity above, and calling it a read failure would report a readable file
    # as unreadable.
    #
    # ``SIGNAL_ABSENT`` (the declared signal no longer occurs) and
    # ``CLASSIFICATION_OPEN`` (the signal no longer falls in the closed class
    # set) are therefore not read failures; every other producer error code
    # raised while loading or masking a declared root -- ``SCAN_INPUT_MISSING``,
    # ``MALFORMED_RUST_SOURCE``, ``PACKAGE_UNDECLARED`` -- is.
    unreadable_identities = [
        item for item in absent if str(item["code"]) not in ("SIGNAL_ABSENT", "CLASSIFICATION_OPEN")
    ]
    for rel in sorted({str(item["path"]) for item in unreadable_identities}):
        failing = sorted(
            str(item["case_ref"]) for item in unreadable_identities if str(item["path"]) == rel
        )
        codes = sorted({str(item["code"]) for item in unreadable_identities if str(item["path"]) == rel})
        add(
            "SOURCE_UNREADABLE",
            f"declared scan root {rel} could not be loaded or masked by the "
            f"#{PRODUCER_ISSUE} producer for identity(ies) {failing} ({', '.join(codes)}); "
            f"the artifact declares rows in a root the producer cannot read",
            path=rel,
            rule="row-coverage",
        )

    # --- Every stored row's recorded source digest, validated against the
    # producer-measured digest of its OWN file record.
    #
    # A row's ``source_sha256`` is a recorded claim about one specific file. It
    # is validated here against the sha256 the producer's loader measured for
    # that path in THIS run -- never recomputed from any sibling field of the
    # same row (``row_digest`` covers the row's own content and says nothing
    # about the file it points at) and never against the header's aggregate
    # ``source_sha``, which is a digest *of* those digests and would let every
    # row in a changed file be excused by one aggregate. This is the per-row
    # half of A1's "matching exact source digests" clause, and it is independent
    # of the candidate-by-candidate comparison above: it needs no signal to still
    # be present, so it also covers rows whose measurement site was migrated.
    measured_file_sha = {str(rec["path"]): str(rec["sha256"]) for rec in file_records}
    for row in rows:
        rel = str(row["path"])
        measured_sha = measured_file_sha.get(rel)
        if measured_sha is None:
            # No measurable identity in this root; whether the root itself is
            # readable is decided above. Recorded against the header's own
            # source digest claim instead, which is checked in _producer_check.
            continue
        if str(row["source_sha256"]) != measured_sha:
            add(
                "SOURCE_DIGEST_CHANGED",
                f"row {row['id']} ({row['case_ref']}) records source digest "
                f"{str(row['source_sha256'])[:16]} for {rel} but the live file measures "
                f"{measured_sha[:16]}; the stored row was measured against different source",
                row_id=str(row["id"]),
                case_ref=str(row["case_ref"]),
                path=rel,
                rule="row-digest",
            )

    # --- Unaccounted estimator detection, through the producer. -----------
    unaccounted = _unaccounted_candidates(root, producer, rows, candidates, header)
    for item in unaccounted:
        add(
            str(item["code"]),
            str(item["evidence"]),
            case_ref=str(item.get("case_ref", "")),
            path=str(item.get("path", "")),
            span_start=int(item.get("span_start", 0) or 0),
            span_end=int(item.get("span_end", 0) or 0),
            rule="unaccounted-candidate",
        )

    # --- Independent enumeration of the producer's scan roots (C7). -------
    #
    # The universe is derived from the LIVE SOURCE by the producer's own
    # enumeration, never from the stored rows, so an estimator that was added
    # to a declared scan root with no denominator row is now detectable. This
    # is the arm that makes C7 possible; the arm above re-locates only what the
    # artifact already declares and could never see it.
    scan_roots = sorted({str(r["path"]) for r in rows})
    enumerated_unaccounted = _enumerated_unaccounted(root, producer, rows, scan_roots)
    for item in enumerated_unaccounted:
        # The finding names the PRODUCER rule that fired (BYTE_RATIO,
        # ESTIMATOR_HELPER_RE, ...), because the audit must be able to say
        # which accepted rule observed the site, not merely that something did.
        add(
            str(item["code"]),
            str(item["evidence"]),
            case_ref=str(item.get("case_ref", "")),
            path=str(item.get("path", "")),
            span_start=int(item.get("span_start", 0) or 0),
            span_end=int(item.get("span_end", 0) or 0),
            rule=str(item.get("rule", "")) or "unaccounted-candidate",
        )

    # --- Exactly one canonical measurement implementation owner. ---------
    owner_sites = _measurement_owner_sites(root, producer, scan_roots)
    owner_paths = sorted({s["path"] for s in owner_sites})
    owner_paths_outside = [
        p for p in owner_paths if not p.startswith("crates/smart/eliot-context-measurement/")
    ]
    if len(owner_sites) == 0:
        add(
            "MISSING_CANONICAL_OWNER",
            f"no definition of {CANONICAL_STU_FORMULA}/{CANONICAL_MEASUREMENT_PORT} was found "
            f"in the declared scan roots; the canonical measurement owner is absent",
            rule="canonical-owner",
        )
    for site in owner_sites:
        if site["path"] not in ("crates/smart/eliot-context-measurement/src/stu.rs",
                                "crates/smart/eliot-context-measurement/src/lib.rs"):
            add(
                "GENERIC_ESTIMATOR_OWNER",
                f"a second definition of the canonical measurement entry point appears at "
                f"{site['path']}:{site['span_start']} outside the {CANONICAL_MEASUREMENT_OWNER} owner",
                path=site["path"],
                span_start=site["span_start"],
                span_end=site["span_end"],
                rule="canonical-owner",
            )
    if owner_paths_outside and owner_sites:
        add(
            "DUPLICATE_OWNER",
            f"the canonical measurement entry points are defined in more than one place: "
            f"{owner_paths_outside}",
            rule="canonical-owner",
        )

    # --- Exactly one canonical schema owner (a single mutable definition). -
    schema_sites = _schema_owner_sites(root, producer, scan_roots)
    if len(schema_sites) == 0:
        add(
            "MISSING_CANONICAL_OWNER",
            f"no definition of schema type {CANONICAL_SCHEMA_TYPE} was found in the declared "
            f"scan roots; the canonical schema owner is absent",
            rule="canonical-schema",
        )
    elif len(schema_sites) > 1:
        add(
            "DUPLICATE_SCHEMA",
            f"schema type {CANONICAL_SCHEMA_TYPE} has more than one mutable definition: "
            f"{[s['path'] + ':' + str(s['span_start']) for s in schema_sites]}",
            rule="canonical-schema",
        )
    else:
        only = schema_sites[0]
        if only["path"] != CANONICAL_SCHEMA_PATH:
            add(
                "DUPLICATE_SCHEMA",
                f"schema type {CANONICAL_SCHEMA_TYPE} is defined at {only['path']} rather than "
                f"in the canonical owner {CANONICAL_SCHEMA_PATH}",
                path=only["path"],
                span_start=only["span_start"],
                span_end=only["span_end"],
                rule="canonical-schema",
            )

    # --- Consumer dependency proof (canonical use w/o bound dependency). ---
    # Owner identity is the *string* owner form the inventory rows carry
    # ("#704"/"#783"/"#878"/"#880"), so the lookup and the evidence map -- both
    # keyed by that same string -- agree. A numeric issue id would silently miss
    # every owner and report a false dependency failure.
    #
    # The iteration set is EXACTLY ``CONSUMER_DEPENDENCY_CONTRACTS``'s own keys,
    # in its own (sorted) order. It is not a hard-coded restatement of the
    # consumer list and not a superset of it: a closed owner that owns writable
    # seam rows but has no closed contract is a finding in its own right,
    # reported below, rather than being quietly skipped here.
    #
    # A dependency is PROVEN only by the measured conjunction of its Cargo
    # metadata declaration and at least one accepted production call site. Each
    # missing conjunct is reported with the exact field that failed, so a
    # comment, a string literal, a similarly named local function, a schema-only
    # import, a test-only call and dead code each name themselves.
    dependency = _dependency_evidence(root, producer, rows)
    proven: dict[str, dict[str, Any]] = {}
    # The owner of record's reach is proved at its DECLARED scope, not at its
    # definition site. That scope is the owner's own ``source_paths`` in the
    # externally supplied frozen owner map -- the same closed, exact allocation
    # #866 resolves every row owner against
    # (``context_measurement_inventory.py::load_owner_map``,
    # ``_owner_confirmed`` at ``:1264-1287``). The map's own header states the
    # rule that makes it a scope rather than a hint: "every row is one exact file
    # path; no prefix, glob, directory or 'anything under' scope is permitted,
    # and the loader rejects ``*`` and any trailing ``/``"
    # (``.github/work-units/context-measurement-owner-map.toml:17-18``), and the
    # loader enforces it (``context_measurement_inventory.py:1245-1250``).
    #
    # It is loaded here, once, through the producer's own accepted loader -- the
    # same call ``_producer_check`` already makes twice for its own
    # ``owner_map_digest`` validation. It is NOT re-read per row: the result is
    # read once here and the resulting path set is bound into the single owner
    # proof record, so ``_reach_scope`` never touches the filesystem. Nothing is
    # invented: these are the owner's own declared paths, verbatim.
    try:
        owner_map_mapping, owner_map_state, _owner_map_digest = producer.load_owner_map(root)
    except producer.InventoryError as exc:
        raise OracleError(
            "OWNER_MAP_UNREADABLE",
            f"the frozen owner map required by #{PRODUCER_ISSUE} could not be read for the "
            f"canonical owner's declared scope: {exc.code}: {exc.detail}",
        ) from exc
    for owner in sorted(CONSUMER_DEPENDENCY_CONTRACTS):
        contract = CONSUMER_DEPENDENCY_CONTRACTS[owner]
        if contract.role == "owner":
            # #704 owns the algorithm crate. Its reach is measured by the
            # single-definition-site proof above (``canonical-owner``), so the
            # dependency conjuncts do not apply to it and a self-dependency is
            # never demanded.
            #
            # The DECLARED SCOPE travels in the proof because that is where the
            # proof actually lives: the owner of record has no closed dependency
            # contract and no self-dependency, so its canonical reach is proved
            # by the exact file paths the accepted owner map allocates to it, and
            # a declared path is a path. Collapsing that to a bare owner key is
            # what once let a #704 row at any path read as canonical; keeping the
            # measured paths makes the same closed allocation askable per row.
            #
            # The scope is the DECLARED allocation, not the set of definition
            # sites. The two are different facts about different things: a
            # definition site says where the port is written, while the owner map
            # says where #704's measurement implementation is owned at all. #704
            # owns four exact files -- ``envelope.rs``, ``lib.rs``, ``receipt.rs``
            # and ``stu.rs`` -- but DEFINES the port in only two of them, and its
            # own non-definition spans in the other two are the owner's, declared
            # by the accepted map this audit is required to reconcile against
            # ("reconcile new candidates through #866's existing rules and
            # accepted owner map"). Case 22 says the canonical STU formula is
            # accepted "only in its owner"; *its owner* is the declared
            # ``source_paths`` entry, so that is the path the reach proof is
            # asked at.
            #
            # Both measured facts travel in the record -- ``source_paths`` is the
            # scope :func:`_reach_scope` reads, ``definition_paths`` the
            # definition-site fact this run measured -- so the proof stays
            # auditable rather than restating one of them.
            _declared_scope = (
                [
                    str(p)
                    for p in (owner_map_mapping or {}).get(owner, {}).get("source_paths", [])
                ]
                if owner_map_state == "SUPPLIED"
                else []
            )
            proven[owner] = {
                "kind": "canonical-port-owner",
                "port_symbol": contract.port_symbol,
                "definition_proved_by": "canonical-owner",
                "definition_paths": sorted({str(site["path"]) for site in owner_sites}),
                "scope_proved_by": "frozen-owner-map",
                "source_paths": sorted(_declared_scope),
            }
            continue
        owner_cargo = dependency["cargo_dependencies"].get(owner, {})
        owner_accepted = dependency["accepted_sites"].get(owner, {})
        owner_bindings = dependency["bindings"].get(owner, {})
        declared_any = any(bool(flag) for flag, _why in owner_cargo.values())
        accepted_any = [site for sites in owner_accepted.values() for site in sites]
        if not declared_any:
            undeclared = sorted(rel for rel, (flag, _why) in owner_cargo.items() if not flag)
            for rel in undeclared:
                _why = dict(owner_cargo)[rel][1]
                add(
                    "MISSING_DEPENDENCY",
                    f"consumer {owner} declares no Cargo dependency on "
                    f"{contract.cargo_package!r} for {rel}: {_why}; the exact dependency must "
                    f"come from authoritative Cargo metadata, not from a Rust-source name",
                    path=rel,
                    rule="dependency-cargo",
                )
            if not undeclared:
                add(
                    "MISSING_DEPENDENCY",
                    f"consumer {owner} owns no writable seam path, so its Cargo metadata "
                    f"cannot declare {contract.cargo_package!r} at all",
                    rule="dependency-cargo",
                )
            continue
        if not accepted_any:
            # The dependency IS declared in Cargo metadata. The only other way
            # to be accepted is a CLOSED approved adapter record: an exact
            # identity, an exact version, an exact expiry and the canonical port
            # it implements. A record that is absent, or present but not closed,
            # is not evidence and is named as such.
            adapter = _adapter_record(owner)
            if adapter is not None:
                # ``cargo_dependency`` is the measured per-path scope this proof is
                # claimed at: the paths whose authoritative Cargo metadata declared
                # the adapter's package, out of exactly the paths the dependency
                # check measured for this owner. A closed adapter record names one
                # implementation of #704's port for one owner, so it has to be
                # read against a path rather than inherited by one.
                proven[owner] = {
                    "kind": "approved-adapter",
                    "identity": adapter["identity"],
                    "version": adapter["version"],
                    "expires": adapter["expires"],
                    "implements_port": adapter["implements_port"],
                    "cargo_dependency": sorted(
                        rel for rel, (flag, _why) in owner_cargo.items() if flag
                    ),
                }
                continue
            # The dependency IS declared. What is missing is a bound production
            # call; the finding names which measured field was absent, and names
            # every candidate site that was rejected and why, so "dead code",
            # "test-only" and "unbound final bytes" are distinguishable.
            for rel in sorted(owner_bindings):
                for entry in owner_bindings[rel]:
                    site = entry["site"]
                    missing = _binding_gaps(entry)
                    if not missing:
                        continue
                    add(
                        "MISSING_DEPENDENCY",
                        f"consumer {owner} calls {contract.port_symbol} at "
                        f"{rel}:{site['span_start']} inside `{site['item']}` but the call does "
                        f"not bind {', '.join(missing)}; a measurement proof is bound to the "
                        f"final serialized bytes and the route/tokenizer identity, not to the "
                        f"existence of a call",
                        path=rel,
                        span_start=int(site["span_start"]),
                        span_end=int(site["span_end"]),
                        rule="dependency-binding",
                    )
            if not any(owner_bindings.values()):
                add(
                    "MISSING_DEPENDENCY",
                    f"consumer {owner} declares {contract.cargo_package!r} but has no production "
                    f"call to {contract.port_symbol!r} in its declared writable seam and no "
                    f"closed approved adapter record; a comment, a string literal, a similarly "
                    f"named local function, a schema-only import, a test-only call and dead code "
                    f"are all not a measurement dependency",
                    rule="dependency-call",
                )
            continue
        # Proven by a real, bound production call. The accepted sites travel in
        # the immutable result so the proof is auditable rather than an unstated
        # pass; see :data:`OwnershipResult.dependency_proofs`.
        proven[owner] = {
            "kind": "canonical-port-call",
            "cargo_dependency": sorted(
                rel for rel, (flag, _why) in owner_cargo.items() if flag
            ),
            "port_symbol": contract.port_symbol,
            "call_sites": [
                f"{site['path']}:{site['span_start']}" for site in accepted_any
            ],
        }

    # --- Every closed owner that owns writable seam rows must HAVE a closed
    # dependency contract, or its dependency check above could never have run.
    #
    # A consumer present in the inventory's own rows but absent from
    # ``CONSUMER_DEPENDENCY_CONTRACTS`` has no declared accepted dependency at
    # all. It is reported, never skipped: an owner with no closed contract is an
    # owner whose measurement reach is unconstrained.
    seam_owners = {
        str(row["owner"])
        for row in rows
        if row["write_scope"] == "writable" and str(row["owner"]) != "unresolved"
    }
    for owner in sorted(seam_owners - set(CONSUMER_DEPENDENCY_CONTRACTS)):
        add(
            "MISSING_DEPENDENCY",
            f"consumer {owner} owns writable seam rows but has no entry in the exact closed "
            f"dependency contract set, so no Cargo dependency and no call in its source could "
            f"satisfy or fail the canonical-measurement dependency check",
            rule="dependency",
        )

    # --- Coverage completeness: unresolved rows and an unsupplied owner map.
    unresolved_rows = [r for r in rows if str(r["status"]) != "owned"]
    for row in unresolved_rows:
        add(
            "INVENTORY_INCOMPLETE",
            f"row {row['id']} ({row['case_ref']}) has no exact-scope owner: "
            f"{row['evidence']}; an unresolved row is never deleted to obtain green",
            row_id=str(row["id"]),
            case_ref=str(row["case_ref"]),
            path=str(row["path"]),
            span_start=int(row["span_start"]),
            span_end=int(row["span_end"]),
            rule="coverage",
        )
    if str(header.get("coverage_disposition", "")) != "COMPLETE":
        add(
            "INVENTORY_INCOMPLETE",
            f"the inventory coverage disposition is "
            f"{header.get('coverage_disposition')!r}, not COMPLETE: {header.get('coverage_reason')}",
            rule="coverage",
        )
    if str(header.get("owner_map_status", "")) != "SUPPLIED":
        add(
            "INVENTORY_INCOMPLETE",
            f"the frozen owner map required by #{PRODUCER_ISSUE} is not supplied "
            f"(status {header.get('owner_map_status')!r} at {OWNER_MAP_REL}); ownership cannot "
            f"be certified without the externally supplied map",
            rule="coverage",
        )

    # --- Unit / name conformance for every classified row. -----------------
    for row in rows:
        _unit_mismatch(findings, producer, str(row["classification"]), str(row["path"]), row)
        _proof_escalation(findings, str(row["classification"]), str(row["signal"]), row)

    # --- Owner conformance: one owner per row identity, no forbidden owner.
    seen_owner_identity: set[tuple[str, str, int]] = set()
    for row in rows:
        identity = (str(row["owner"]), str(row["path"]), int(row["span_start"]))
        if identity in seen_owner_identity:
            add(
                "DUPLICATE_OWNER",
                f"owner {row['owner']} is allocated the same row span twice at "
                f"{row['path']}:{row['span_start']}",
                row_id=str(row["id"]),
                case_ref=str(row["case_ref"]),
                path=str(row["path"]),
                span_start=int(row["span_start"]),
                span_end=int(row["span_end"]),
                rule="ownership",
            )
        seen_owner_identity.add(identity)

    # One reconciliation pass, producing both the findings and the tally that
    # is reported from them. It runs here, once, and its tally is carried into
    # ``_finalize`` instead of being recomputed there.
    #
    # ``proven`` -- the consumer dependency proofs measured above, from this run's
    # live source -- is passed in so the disposition derivation consumes
    # before/after consumer EVIDENCE. Without it the derivation could only read
    # ``owner``/``status``/``classification`` off the row, which is precisely the
    # "owned means migrated" shortcut audit defect 5 names.
    return _finalize(
        root,
        findings,
        header=header,
        rows=rows,
        worksets=worksets,
        inventory_digest=inventory_digest,
        candidates=candidates,
        check_status=check_status,
        unaccounted=unaccounted + enumerated_unaccounted,
        dependency=dependency,
        schema_sites=schema_sites,
        owner_sites=owner_sites,
        dependency_proofs=proven,
        baseline_dispositions=_baseline_findings(rows, by_case, add, proven),
    )


def _unit_mismatch(
    findings: list[Finding],
    producer: Any,
    classification: str,
    path: str,
    row: dict[str, Any],
) -> None:
    """Reject a unit or name mismatch on a measured row.

    The producer's closed classification set is the sole authority for what a
    row *is*. A row that the producer classed as an exact UTF-8 envelope, an
    exact observation or a route/serializer identity must not carry a signal
    that names a *byte/KiB/character* metric being carried as tokens, and a
    row the producer classed as a byte/character count mislabeled as tokens
    must not be re-labelled here as anything more authoritative. The unit the
    signal names is the unit the row carries, so a byte value labelled tokens
    (or a character value labelled STU) is a unit mismatch, named exactly.
    """
    signal = str(row["signal"])
    # Signals that name a bytes/KiB/character metric must not be classified as
    # an exact tokenizer/token observation.
    byte_or_char_metric = bool(
        producer.MEASURED_FIELD.search(signal)
        and re.search(
            r"\b(?:bytes|kib|characters|chars|utf8_bytes|serialized_bytes|"
            r"listing_characters|rendered_utf8_bytes|final_bytes|payload_utf8)\b",
            signal,
        )
    )
    if byte_or_char_metric and classification in (
        "exact-observation",
        "normative-stu-estimate",
        "capacity-fit-analysis",
    ):
        findings.append(
            Finding(
                "UNIT_NAME_MISMATCH",
                f"row {row['id']} ({row['case_ref']}) is classified {classification!r} but its "
                f"signal {signal!r} names a byte/character quantity, not a token or STU count; "
                f"a byte/KiB/character value is never carried as tokens or STU",
                row_id=str(row["id"]),
                case_ref=str(row["case_ref"]),
                path=path,
                span_start=int(row["span_start"]),
                span_end=int(row["span_end"]),
                rule="unit-conformance",
            )
        )
    # A token/STU signal must not be classified as an exact tokenizer
    # observation unless it names the route tokenizer explicitly.
    if classification == "exact-observation" and not re.search(
        r"ProviderTokenizerRun|observed_tokens|TokenizerObservation", signal
    ):
        findings.append(
            Finding(
                "UNIT_NAME_MISMATCH",
                f"row {row['id']} ({row['case_ref']}) claims an exact observation but its signal "
                f"{signal!r} does not name an actually-run route tokenizer; an estimate is "
                f"never an exact observation",
                row_id=str(row["id"]),
                case_ref=str(row["case_ref"]),
                path=path,
                span_start=int(row["span_start"]),
                span_end=int(row["span_end"]),
                rule="unit-conformance",
            )
        )


def _proof_escalation(
    findings: list[Finding], classification: str, signal: str, row: dict[str, Any]
) -> None:
    """Reject proof escalation: an estimate carried as proof, or an
    unvalidated value carried as a fit/admission authority.

    I2.16 is explicit: STU, byte ratios and historical token averages are
    planning fallbacks only; they never prove that a Decision Safety Floor
    fits, never authorize truncation and never force a split. So a row the
    producer classed as a normative STU estimate or an estimator-policy /
    unvalidated value must not *also* be a capacity-fit or proves-fit claim,
    and a non-exact observation must never be presented as authority.
    """
    if classification in (
        "normative-stu-estimate",
        "estimator-policy-unvalidated",
    ) and re.search(
        r"proves_fit|route_capacity|output_reserve|review_reserve|headroom|"
        r"mandatory_floor_tokens|fits|admit|authority|proven",
        signal,
    ):
        findings.append(
            Finding(
                "PROOF_ESCALATION",
                f"row {row['id']} ({row['case_ref']}) is an unvalidated estimate "
                f"({classification}) yet its signal {signal!r} escalates it to a fit, "
                f"admission or authority claim; an estimate never proves a floor fits",
                row_id=str(row["id"]),
                case_ref=str(row["case_ref"]),
                path=str(row["path"]),
                span_start=int(row["span_start"]),
                span_end=int(row["span_end"]),
                rule="proof-conformance",
            )
        )
    if classification in (
        "character_count_mislabeled_as_tokens",
        "token_estimate_without_tokenizer",
    ) and re.search(r"actual|current|exact|ProvenFits|Safety.?Floor", signal):
        findings.append(
            Finding(
                "PROOF_ESCALATION",
                f"row {row['id']} ({row['case_ref']}) is a character/byte ratio carried as "
                f"tokens ({classification}) yet its signal {signal!r} labels it actual or "
                f"current; a ratio estimate is never an actual or current count",
                row_id=str(row["id"]),
                case_ref=str(row["case_ref"]),
                path=str(row["path"]),
                span_start=int(row["span_start"]),
                span_end=int(row["span_end"]),
                rule="proof-conformance",
            )
        )


def _canonical_reach_proven(
    owner: str,
    path: str,
    dependency_proofs: Mapping[str, Mapping[str, Any]] | None,
) -> tuple[bool, str]:
    """Is this owner's canonical measurement reach PROVEN **at this path**?

    Returns ``(proven, reason)``. ``reason`` names the measured conjunct that
    decided it, so a row that falls to ``explicit-unresolved`` can say *why*
    rather than merely that it fell through.

    The answer is read from :data:`OwnershipResult.dependency_proofs`, i.e. from
    :func:`_dependency_evidence`'s measurement of the consumer's OWN Cargo
    metadata and its OWN masked production call site -- never from the row's
    ``owner``/``status`` pair. An owner that is absent from the proof map, or
    that carries no proof of one of the :data:`CANONICAL_REACH_KINDS`, has NOT
    demonstrated a canonical migration.

    The mere absence of a ``MISSING_DEPENDENCY`` finding is deliberately NOT
    accepted as proof: a consumer whose rows are all ``read-only`` has no
    writable seam for the dependency check to have run over, so it produces no
    finding and no proof either. Absence of a complaint is not evidence.

    PATH-SCOPED, NOT OWNER-SCOPED. The audit's concern is per ROW: the evidence
    must be about *this site*, not about *this owner somewhere*. So the lookup is
    answered against the row's OWN ``path``, out of the per-path scope each proof
    record carries (see :func:`_reach_scope`). A ``canonical-port-call`` proof is
    proved only at a path it actually called the port at; an
    ``approved-adapter`` proof is proved only at a path the adapter's measured
    Cargo metadata actually declared it at; a ``canonical-port-owner`` proof is
    proved only at a path the accepted owner map actually DECLARES the owner at
    (its exact ``source_paths``). Every one of those is a fact this run already
    measured at a named path, so scoping the lookup widens no rule and invents
    no field. Before this was path-scoped, a row at one path inherited another
    path's proof from the same owner -- a row whose own site carried no
    measurement evidence at all was reported as a canonical consumer.
    """
    if not dependency_proofs:
        return (False, "no consumer dependency proof was measured for this run")
    proof = dependency_proofs.get(owner)
    if proof is None:
        return (
            False,
            f"owner {owner} has no entry in the measured consumer dependency proofs",
        )
    kind = str(proof.get("kind", ""))
    if kind not in CANONICAL_REACH_KINDS:
        return (False, f"owner {owner} has no proven canonical reach (measured kind {kind!r})")
    measured_at = _reach_scope(proof)
    if path in measured_at:
        return (
            True,
            f"owner {owner} holds a measured {kind} proof at this row's own path {path}",
        )
    return (
        False,
        f"owner {owner} holds a {kind} proof measured only at {sorted(measured_at)}, which "
        f"does not include this row's own path {path}; a proof about the owner somewhere "
        f"else is not evidence about this site",
    )


def _reach_scope(proof: Mapping[str, Any]) -> set[str]:
    """The paths at which one ``dependency_proofs`` record is actually proven.

    Every proof kind names its own proven paths, measured this run, and the
    reader below is the single place that maps a kind onto that vocabulary. A
    record that names no proven path proves nothing at any path.

    ``canonical-port-call``
        the paths of the accepted, bound production call sites this run measured.
    ``approved-adapter``
        the paths whose authoritative Cargo metadata declared the adapter's
        package, restricted to the paths it was measured for. A closed adapter
        record is itself owner-scoped by construction -- it names one
        implementation of #704's port for one owner -- and this is where that is
        made a per-path claim instead of an inherited one.
    ``canonical-port-owner``
        the owner's DECLARED ``source_paths`` in the externally supplied frozen
        owner map, as measured by :func:`producer.load_owner_map` and bound into
        the proof record by ``evaluate``. The owner of record has no closed
        dependency contract and no self-dependency, so its reach is proved by the
        exact file paths the accepted owner map allocates to it. That map is a
        closed, exact, per-owner scope by its own declared rule
        (``context-measurement-owner-map.toml:17-18``: "every row is one exact
        file path; no prefix, glob, directory or 'anything under' scope is
        permitted"), which is what makes the declared paths -- and not the
        definition sites -- the paths this proof is asked at. The owner's other
        measured fact, its ``definition_paths``, still travels in the record and
        is still what the single-definition-site finding is derived from; this
        reader simply reads the scope, so #704's own non-definition spans inside
        its declared files are proved at the paths the map declares them.
    """
    kind = str(proof.get("kind", ""))
    if kind == "canonical-port-call":
        return {
            str(str(site).rsplit(":", 1)[0])
            for site in proof.get("call_sites", [])
            if isinstance(site, str) and ":" in site
        }
    if kind == "canonical-port-owner":
        return {str(p) for p in proof.get("source_paths", [])}
    if kind == "approved-adapter":
        return {str(p) for p in proof.get("cargo_dependency", [])}
    return set()


def _derive_baseline_disposition(
    row: Mapping[str, Any],
    dependency_proofs: Mapping[str, Mapping[str, Any]] | None = None,
) -> str:
    """Derive one baseline row's disposition from MEASURED evidence.

    Audit defect 5, second half. The previous residual arm returned the literal
    ``canonical-owner-consumer`` for every row that was neither ``unresolved`` nor
    ``unrelated_byte_or_character_metric``, reading only ``owner``,
    ``classification`` and ``status``. That made the label a restatement of "this
    row is still owned" and nothing more, so an old still-active formula was
    counted as reconciled merely because its old row remained owned -- exactly the
    defect the audit names: "do not treat 'owned' as proof of canonical migration".

    The derivation is now evidence-bearing in two independent, measured directions:

    * the row's OWN closed fields, re-read from #866's frozen ``ROW_KEYS``; and
    * the canonical dependency proof measured this run from live source by
      :func:`_dependency_evidence`, asked about the row's OWN ``path`` -- so the
      evidence is about *this site*, not about *this owner somewhere*.

    No new row field is used and none is invented: every input below is one of
    the 22 keys #866 already freezes at
    ``context_measurement_inventory.py:533-559``.

    The arms are mutually exclusive by construction -- each is a first-match on a
    distinct predicate, and no two predicates can hold for the same row:

    ``explicit-unresolved`` (first arm)
        The producer itself could not attribute the row: its ``status`` is not
        ``owned`` or its ``owner`` is the literal ``unresolved``. Both are values
        #866 writes (``context_measurement_inventory.py:1648``, ``:1264-1290``)
        and both are validated as a closed pair on the producer's read path
        (``:2443-2449``). No other disposition may be claimed for a row nobody
        owns.
    ``legitimate-non-context-metric`` (second arm)
        A real value comparison against the producer's own closed classification
        for a true byte/KiB/line/UI-character metric that is never carried as a
        token or STU count. Such a row carries its own exact exclusion evidence
        in its ``evidence`` field (``context_measurement_inventory.py:1178-1182``),
        so no consumer migration is owed for it.
    ``canonical-owner-consumer`` (third arm)
        REQUIRES BOTH: the row is a live *production* measurement site, AND its
        owner holds a measured canonical-reach proof **at this row's own path**.
        Both halves are evidence: ``item_scope`` is the producer's own ``_scope_of``
        verdict on the enclosing item, so a ``test-only`` row is not a consumer;
        and the reach proof is measured from the consumer's Cargo metadata and its
        masked production call site, not read off the row. A live legacy formula
        whose owner has no proven dependency falls past this arm to
        ``explicit-unresolved`` -- it is never counted as a migrated consumer, and
        neither is a site whose owner is proved only somewhere else.
    ``explicit-unresolved`` (fourth arm)
        Everything else, i.e. the row cannot demonstrate a canonical migration:
        a live site the producer still classes as an unvalidated local ratio (the
        old formula), or a production site whose owner's dependency is unproven.
        This is the audit's "keep rows unresolved until that evidence exists".

    ``exact-versioned-legacy-adapter`` stays declared in
    :data:`BASELINE_DISPOSITIONS` but deliberately NOT derived here, and that is
    the honest outcome rather than a missing rule. No field in #866's closed
    ``ROW_KEYS`` records a legacy-adapter marker, a version bound or an expiry;
    reaching for ``write_scope`` (mutation permission by tier, ``:1597-1602``)
    or ``dispatch_blocked`` (``status != "owned"``, ``:1649``) would restate a
    different fact under this name. That blocker is filed as a ContractChallenge
    against #866; emitting it needs a closed field added there by its owner.
    """
    owner = str(row["owner"])
    classification = str(row["classification"])
    status = str(row["status"])

    # Arm 1 -- nobody owns it, so nothing else may be claimed for it.
    if status == "unresolved" or owner == "unresolved":
        return "explicit-unresolved"

    # Arm 2 -- a declared, exact-excluded non-Context metric. Its own
    # ``evidence`` records the exclusion reason, so no migration is owed.
    if classification == "unrelated_byte_or_character_metric":
        return "legitimate-non-context-metric"

    # Arm 2b -- the row's OWN frozen classification is itself the evidence that
    # the OLD formula is still live at this span. An unvalidated local estimator
    # is the pre-migration defect #787 exists to reconcile, so no owner-level
    # canonical-reach proof can make this row a reconciled consumer: the row
    # describes a site that still computes the retired ratio itself. Classifying
    # it as canonical would assert a migration that the row's own
    # ``classification`` contradicts.
    if classification in _LIVE_LEGACY_CLASSIFICATIONS:
        return "explicit-unresolved"

    # Arm 3 -- canonical consumer, but ONLY on proven evidence AT THIS SITE. A
    # test-only site is not a consumer, an unproven owner is not a migrated one,
    # and an owner's proven reach at some OTHER path is not a proof about this
    # row's own path.
    if str(row.get("item_scope", "production")) != "test":
        # ``path`` is one of #866's frozen ``ROW_KEYS``, so every row reaching
        # here carries it and it is read directly rather than defaulted: a row
        # that did not name its own site could not be judged as a site at all,
        # and defaulting one in would put a proof on a path nobody measured.
        proven, _reason = _canonical_reach_proven(owner, str(row["path"]), dependency_proofs)
        if proven:
            return "canonical-owner-consumer"

    # Arm 4 -- the migration was never demonstrated. The row stays unresolved;
    # an owned old formula is not a reconciled canonical consumer.
    return "explicit-unresolved"


def _baseline_findings(
    rows: list[dict[str, Any]],
    by_case: dict[str, dict[str, Any]],
    add: Any,
    dependency_proofs: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, int]:
    """Baseline reconciliation: every frozen baseline row must survive with an
    explicit disposition. Returns the disposition tally.

    An erased baseline row (removed requirement) is rejected. Every surviving
    row's disposition comes from :func:`_derive_baseline_disposition`, which
    derives three of the four closed values in :data:`BASELINE_DISPOSITIONS` --
    ``canonical-owner-consumer`` (only on a measured canonical-reach proof),
    ``legitimate-non-context-metric`` and ``explicit-unresolved`` -- and never
    returns anything else. ``exact-versioned-legacy-adapter`` stays declared but
    underived by design; see :func:`_derive_baseline_disposition` for why no
    recorded row fact can establish it.

    A row that falls to ``explicit-unresolved`` *because* its owner has no proven
    canonical dependency also carries a ``CONSUMER_EVIDENCE_MISSING`` finding, so
    the reconciliation never quietly shrinks the canonical bucket: the row is
    counted once, as unresolved, and the missing conjunct is named per row.
    """
    # --- The denominator must itself be complete before it can reconcile
    # anything.
    #
    # ``EXPECTED_BASELINE_ROWS`` is the frozen pre-migration denominator,
    # written out independently of the producer module. Iterating it reconciles
    # 31 rows -- but only if it really holds 31 distinct rows with 31 distinct
    # case identities. A silently truncated or de-duplicated table would shrink
    # the denominator and make every surviving-row check pass over fewer
    # requirements than exist, which is exactly "erasing a requirement to get
    # green". So the table's own cardinality and uniqueness are checked here, and
    # the reconciled count is compared against that cardinality at the end.
    if len(EXPECTED_BASELINE_ROWS) != EXPECTED_BASELINE_COUNT:
        raise OracleError(
            "DETERMINISTIC_INTERNAL_DEFECT",
            f"the frozen baseline denominator holds {len(EXPECTED_BASELINE_ROWS)} rows but "
            f"EXPECTED_BASELINE_COUNT declares {EXPECTED_BASELINE_COUNT}",
        )
    frozen_refs = [str(case_ref) for case_ref, _owner in EXPECTED_BASELINE_ROWS]
    if len(set(frozen_refs)) != len(frozen_refs):
        duplicates = sorted({ref for ref in frozen_refs if frozen_refs.count(ref) > 1})
        raise OracleError(
            "DETERMINISTIC_INTERNAL_DEFECT",
            f"the frozen baseline denominator repeats case identity(ies) {duplicates}",
        )

    dispositions: dict[str, int] = {d: 0 for d in BASELINE_DISPOSITIONS}
    lost = 0
    for case_ref, expected_owner in EXPECTED_BASELINE_ROWS:
        row = by_case.get(case_ref)
        if row is None:
            add(
                "BASELINE_ROW_LOST",
                f"frozen baseline row {case_ref} (owner {expected_owner}) is absent from the "
                f"current inventory; removal of the old formula cannot erase the requirement",
                case_ref=case_ref,
                rule="baseline-reconciliation",
            )
            lost += 1
            continue
        # The frozen row's expected owner is the oracle's own recorded fact about
        # the pre-migration allocation. The current row must still carry it: a
        # baseline requirement that was silently re-allocated to a different owner
        # has not been reconciled, it has been transferred without evidence, and
        # the frozen owner is what makes the check independent of the very row
        # field being judged.
        actual_owner = str(row["owner"])
        if actual_owner != expected_owner:
            add(
                "BASELINE_DISPOSITION_MISSING",
                f"frozen baseline row {case_ref} is owned by {actual_owner} but its recorded "
                f"pre-migration owner is {expected_owner}; a baseline requirement is never "
                f"re-allocated to obtain green",
                row_id=str(row["id"]),
                case_ref=case_ref,
                path=str(row["path"]),
                span_start=int(row["span_start"]),
                span_end=int(row["span_end"]),
                rule="baseline-reconciliation",
            )
        # Derive the disposition from the row's own closed fields plus the
        # owner-level canonical dependency proof measured this run. The derivation
        # is total over the four closed values, so the membership guard below is a
        # structural invariant of the closed set rather than a check that no
        # recorded row could ever fail; it is kept so that widening the tuple
        # above fails loudly here instead of raising a KeyError on the tally.
        disposition = _derive_baseline_disposition(row, dependency_proofs)
        if disposition not in BASELINE_DISPOSITIONS:
            raise OracleError(
                "DETERMINISTIC_INTERNAL_DEFECT",
                f"baseline row {case_ref} derived a disposition outside the closed set: "
                f"{disposition!r}",
            )
        # A row that could not demonstrate a canonical migration must say so out
        # loud. Without this the reconciliation would still be arithmetically
        # complete (the row is counted, once, as unresolved) while a reader of
        # the tally alone could not tell WHY the canonical bucket shrank. The
        # finding is emitted only for the arm-4 case -- a row the producer
        # attributed but whose consumer evidence is absent -- and never for an
        # arm-1 row, which is already reported as INVENTORY_INCOMPLETE.
        if disposition == "explicit-unresolved" and actual_owner == expected_owner:
            _proven, reach_reason = _canonical_reach_proven(
                actual_owner, str(row["path"]), dependency_proofs
            )
            if not _proven:
                add(
                    "CONSUMER_EVIDENCE_MISSING",
                    f"frozen baseline row {case_ref} (owner {actual_owner}, classification "
                    f"{row['classification']}, item scope {row.get('item_scope', 'production')!r}) "
                    f"cannot be reported as a canonical owner consumer: {reach_reason}. An owned "
                    f"row is not proof of a canonical migration; the before/after consumer "
                    f"evidence this disposition requires is absent from both the frozen row "
                    f"schema and the measured dependency proofs, so the requirement stays "
                    f"unresolved until that evidence exists",
                    row_id=str(row["id"]),
                    case_ref=case_ref,
                    path=str(row["path"]),
                    span_start=int(row["span_start"]),
                    span_end=int(row["span_end"]),
                    rule="baseline-consumer-evidence",
                )
        dispositions[disposition] += 1

    # --- The reconciliation must cover the whole declared denominator.
    #
    # ``reconciled + lost == EXPECTED_BASELINE_COUNT`` is the denominator
    # arithmetic in its exact form: every frozen row is either reconciled with an
    # explicit disposition, or reported lost, and nothing else may contribute to
    # the tally. A shortfall would mean a frozen row was silently skipped rather
    # than reconciled; an excess would mean the tally counts something outside the
    # frozen requirement set. ``lost`` is counted here from the same loop that
    # emitted the ``BASELINE_ROW_LOST`` findings, so the two cannot disagree.
    reconciled = sum(dispositions.values())
    if reconciled + lost != EXPECTED_BASELINE_COUNT:
        raise OracleError(
            "DETERMINISTIC_INTERNAL_DEFECT",
            f"baseline reconciliation covers {reconciled} + {lost} rows but the frozen "
            f"denominator holds {EXPECTED_BASELINE_COUNT}",
        )
    return dispositions


def _record(
    findings: list[Finding],
    code: str,
    detail: str,
    row_id: str = "",
    case_ref: str = "",
    path: str = "",
    span_start: int = 0,
    span_end: int = 0,
    rule: str = "",
) -> None:
    """Append one typed finding. The single writer used by every finding site,
    so the ``add`` closure in :func:`evaluate` and the reconciliation in
    :func:`_finalize` share one construction path."""
    findings.append(Finding(code, detail, row_id, case_ref, path, span_start, span_end, rule))


def _finalize(
    root: Path,
    findings: list[Finding],
    header: dict[str, Any],
    rows: list[dict[str, Any]],
    worksets: list[dict[str, Any]],
    inventory_digest: str,
    candidates: list[dict[str, Any]],
    check_status: str,
    unaccounted: list[dict[str, Any]],
    dependency: dict[str, Any],
    schema_sites: list[dict[str, Any]],
    owner_sites: list[dict[str, Any]],
    baseline_dispositions: dict[str, int],
    dependency_proofs: dict[str, dict[str, Any]] | None = None,
) -> OwnershipResult:
    """Assemble the single immutable result, computing its digest over the
    full body (which excludes the digest itself)."""
    by_case = {str(r["case_ref"]): r for r in rows}

    def add(
        code: str,
        detail: str,
        row_id: str = "",
        case_ref: str = "",
        path: str = "",
        span_start: int = 0,
        span_end: int = 0,
        rule: str = "",
    ) -> None:
        _record(findings, code, detail, row_id, case_ref, path, span_start, span_end, rule)

    # The baseline reconciliation ran EXACTLY ONCE, in ``evaluate``, which
    # passes its tally in as ``baseline_dispositions``. Those findings are
    # already in ``findings``.
    #
    # It used to run twice: once directly here and once again through
    # ``extra_finding_check``. Both calls shared this one ``add`` closure and
    # this one ``findings`` list, so every erased requirement was recorded
    # TWICE -- thirty lost baseline rows produced sixty BASELINE_ROW_LOST
    # findings. That inflated ``finding_count`` and ``result_digest`` with a
    # duplicate that described no second defect, and it made the reported count
    # of erased requirements depend on an implementation detail rather than on
    # the tree. One pass, one tally, exactly one finding per erased
    # requirement. No closed set, no rule and no threshold is touched: the
    # findings this code emits are the same findings, counted once, and the
    # tally is reported from the pass that emitted them.
    # The tally must cover exactly the closed disposition set: a key outside
    # it, or one missing, is a widened or eroded closed set and must fail
    # loudly here rather than being silently dropped from the projection.
    if set(baseline_dispositions) != set(BASELINE_DISPOSITIONS):
        raise OracleError(
            "DETERMINISTIC_INTERNAL_DEFECT",
            "the baseline disposition tally keys "
            f"{sorted(baseline_dispositions)} instead of the closed set "
            f"{sorted(BASELINE_DISPOSITIONS)}",
        )
    dispositions = {d: int(baseline_dispositions[d]) for d in BASELINE_DISPOSITIONS}

    ordered = tuple(sorted(findings, key=lambda f: (f.code, f.case_ref, f.path, f.span_start)))
    result = OwnershipResult(
        result_schema=RESULT_SCHEMA,
        oracle_version=ORACLE_VERSION,
        issue=ISSUE,
        producer_issue=PRODUCER_ISSUE,
        proof_ceiling=PROOF_CEILING,
        inventory_path=INVENTORY_REL,
        inventory_present=bool(header),
        inventory_digest=inventory_digest,
        source_sha=str(header.get("source_sha", "")) if header else "",
        rule_digest=str(header.get("rule_digest", "")) if header else "",
        owner_digest=str(header.get("owner_digest", "")) if header else "",
        rule_revision=str(header.get("rule_revision", "")) if header else "",
        coverage_disposition=str(header.get("coverage_disposition", "")) if header else "",
        owner_map_status=str(header.get("owner_map_status", "")) if header else "",
        candidate_count=int(header.get("candidate_count", 0)) if header else 0,
        classified_count=int(header.get("classified_count", 0)) if header else 0,
        owned_count=int(header.get("owned_count", 0)) if header else 0,
        unresolved_count=int(header.get("unresolved_count", 0)) if header else 0,
        baseline_reconciled=sum(dispositions.values()),
        baseline_expected=EXPECTED_BASELINE_COUNT,
        baseline_dispositions=dispositions,
        unaccounted_candidate_count=len(unaccounted),
        canonical_measurement_owners=tuple(sorted({s["path"] for s in owner_sites})),
        canonical_schema_owners=tuple(sorted({s["path"] for s in schema_sites})),
        dependency_proofs={
            owner: dict(sorted(proof.items()))
            for owner, proof in sorted((dependency_proofs or {}).items())
        },
        producer_check_status=check_status,
        finding_count=len(ordered),
        findings=ordered,
        result_digest="",
    )
    # Digest over the immutable body with the digest field empty; the caller
    # and both projections read the *same* value.
    body = result.result_body()
    body["result_digest"] = ""
    digest = _sha256(_canonical_bytes(body))
    return OwnershipResult(**{**result.__dict__, "result_digest": digest})


# ---------------------------------------------------------------------------
# Projections of the one immutable result.
# ---------------------------------------------------------------------------


def render_text(result: OwnershipResult) -> str:
    """Pure text projection of the single immutable result."""
    lines: list[str] = []
    status = "OK" if result.ok else "FAIL"
    lines.append(
        f"{status} context-measurement ownership oracle (#{result.issue}, "
        f"producer #{result.producer_issue})"
    )
    lines.append(f"  proof_ceiling        = {result.proof_ceiling}")
    lines.append(f"  inventory            = {result.inventory_path}")
    lines.append(f"  inventory_digest     = {result.inventory_digest or '<absent>'}")
    lines.append(f"  rule_revision        = {result.rule_revision or '<absent>'}")
    lines.append(f"  source_sha           = {result.source_sha or '<absent>'}")
    lines.append(f"  rule_digest          = {result.rule_digest or '<absent>'}")
    lines.append(f"  owner_digest         = {result.owner_digest or '<absent>'}")
    lines.append(f"  coverage_disposition = {result.coverage_disposition or '<absent>'}")
    lines.append(f"  owner_map_status     = {result.owner_map_status or '<absent>'}")
    lines.append(f"  producer_check       = {result.producer_check_status}")
    lines.append(
        f"  candidates           = {result.candidate_count} "
        f"(classified {result.classified_count}, owned {result.owned_count}, "
        f"unresolved {result.unresolved_count})"
    )
    lines.append(
        f"  baseline             = {result.baseline_reconciled}/{result.baseline_expected} "
        + " ".join(f"{k}={v}" for k, v in sorted(result.baseline_dispositions.items()))
    )
    lines.append(f"  unaccounted          = {result.unaccounted_candidate_count}")
    lines.append(f"  measurement_owners   = {list(result.canonical_measurement_owners)}")
    lines.append(f"  schema_owners        = {list(result.canonical_schema_owners)}")
    for owner in sorted(result.dependency_proofs):
        proof = result.dependency_proofs[owner]
        kind = str(proof.get("kind"))
        if kind == "approved-adapter":
            lines.append(
                f"  dependency[{owner}]   = approved-adapter "
                f"{proof.get('identity')}@{proof.get('version')} "
                f"expires={proof.get('expires')} port={proof.get('implements_port')}"
            )
        elif kind == "canonical-port-owner":
            lines.append(
                f"  dependency[{owner}]   = canonical-port-owner "
                f"{proof.get('port_symbol')} proved by {proof.get('definition_proved_by')} "
                f"defined at {sorted(proof.get('definition_paths', []))}, "
                f"declared scope {sorted(_reach_scope(proof))}"
            )
        else:
            lines.append(
                f"  dependency[{owner}]   = {kind} "
                f"{proof.get('port_symbol')} at {sorted(_reach_scope(proof))} "
                f"(call sites {proof.get('call_sites')})"
            )
    lines.append(f"  findings             = {result.finding_count}")
    for finding in result.findings:
        lines.append(f"    {finding.locator()}")
    lines.append(f"  result_digest        = {result.result_digest}")
    return "\n".join(lines)


def render_json(result: OwnershipResult) -> str:
    """Pure JSON projection of the single immutable result."""
    return json.dumps(result.result_body(), sort_keys=True, indent=2)


# ---------------------------------------------------------------------------
# Self-test: proves the two projections agree, the closed sets are closed,
# the normal path is write-free, and the producer API is consumed.
# ---------------------------------------------------------------------------


def run_self_test() -> int:
    assert len(set(FAIL_CODES)) == len(FAIL_CODES), "failure codes must be unique"
    assert EXPECTED_BASELINE_COUNT == 31, "baseline must hold 31 frozen rows"
    assert len(set(EXPECTED_BASELINE_ROWS)) == EXPECTED_BASELINE_COUNT
    assert set(BASELINE_DISPOSITIONS) == {
        "canonical-owner-consumer",
        "legitimate-non-context-metric",
        "exact-versioned-legacy-adapter",
        "explicit-unresolved",
    }

    # The normal path must not implement a network client, an ambient clock, a
    # filesystem write, a child-process launcher, a measurement algorithm, an
    # admission policy or a broad directory skip (case 787/30).
    #
    # Each banned surface is spelled as a tuple of character codes, so the
    # literal token appears nowhere in this file -- not in the check, not in
    # its comment. The assertion therefore cannot pass by matching its own
    # construction: it is a real substring search over the module's whole
    # source text, including this function.
    banned_codepoints: tuple[tuple[int, ...], ...] = (
        (117, 114, 108, 105, 98),  # a URL retrieval library
        (114, 101, 113, 117, 101, 115, 116, 115),
        (104, 116, 116, 112, 120),
        (115, 111, 99, 107, 101, 116),
        (100, 97, 116, 101, 116, 105, 109, 101),
        (116, 105, 109, 101, 46, 116, 105, 109, 101),
        (115, 117, 98, 112, 114, 111, 99, 101, 115, 115),
        (80, 111, 112, 101, 110),
        (84, 104, 114, 101, 97, 100, 80, 111, 111, 108, 69, 120, 101, 99, 117, 116, 111, 114),
        (119, 114, 105, 116, 101, 95, 116, 101, 120, 116),
        (119, 114, 105, 116, 101, 95, 98, 121, 116, 101, 115),
        (115, 104, 117, 116, 105, 108, 46, 114, 109, 116, 114, 101, 101),
        (116, 101, 109, 112, 102, 105, 108, 101),
    )
    here = Path(__file__).resolve()
    text = here.read_text(encoding="utf-8")
    for codes in banned_codepoints:
        token = "".join(chr(code) for code in codes)
        assert token not in text, (
            f"the normal oracle must not reference a banned surface ({len(codes)} chars)"
        )
    # The evaluation region -- everything above this function, which is the
    # whole normal checking path -- may not perform a filesystem mutation and
    # may not broad-walk a directory tree. Both would be a write or a
    # directory exception rather than producer-supplied candidate accounting.
    # The check names concrete mutating calls, not a bare ``write`` prefix,
    # because reading the inventory's own ``write_scope`` field is legitimate.
    evaluation_region = text.split("def run_self_test", 1)[0]
    # ``write_``-prefixed method names are spelled as fragments so that the
    # second, whole-module ban above does not match this very tuple.
    for token in (
        ".wr" + "ite_text(",
        ".wr" + "ite_bytes(",
        ".un" + "link(",
        ".mk" + "dir(",
        "rm" + "tree",
        ".rgl" + "ob(",
        "os.w" + "alk",
        "shu" + "til.copy",
        "os.re" + "move",
    ):
        assert token not in evaluation_region, (
            f"the normal evaluation path must not use {token}: a write or a broad "
            f"directory skip is not owner conformance"
        )

    # Exercise the two projections on a synthetic result: they must agree on
    # counts, digest and finding codes because both are pure projections.
    sample = OwnershipResult(
        result_schema=RESULT_SCHEMA,
        oracle_version=ORACLE_VERSION,
        issue=ISSUE,
        producer_issue=PRODUCER_ISSUE,
        proof_ceiling=PROOF_CEILING,
        inventory_path=INVENTORY_REL,
        inventory_present=True,
        inventory_digest="d" * 64,
        source_sha="s" * 64,
        rule_digest="r" * 64,
        owner_digest="o" * 64,
        rule_revision="866.2",
        coverage_disposition="INCOMPLETE",
        owner_map_status="SUPPLIED",
        candidate_count=72,
        classified_count=72,
        owned_count=68,
        unresolved_count=4,
        baseline_reconciled=31,
        baseline_expected=31,
        baseline_dispositions={d: 0 for d in BASELINE_DISPOSITIONS},
        unaccounted_candidate_count=2,
        canonical_measurement_owners=("crates/smart/eliot-context-measurement/src/stu.rs",),
        canonical_schema_owners=(CANONICAL_SCHEMA_PATH,),
        dependency_proofs={
            "#783": {
                "kind": "canonical-port-call",
                "cargo_dependency": ["crates/eliot-app/src/mcp_stdio.rs"],
                "port_symbol": CANONICAL_MEASUREMENT_PORT,
                "call_sites": ["crates/eliot-app/src/mcp_stdio.rs:10"],
            }
        },
        producer_check_status="blocked",
        finding_count=1,
        findings=(Finding("INVENTORY_STALE", "stale", case_ref="704/1", path="a.rs", rule="r"),),
        result_digest="",
    )
    body = sample.result_body()
    body["result_digest"] = ""
    digest = _sha256(_canonical_bytes(body))
    sealed = OwnershipResult(**{**sample.__dict__, "result_digest": digest})
    parsed = json.loads(render_json(sealed))
    text_proj = render_text(sealed)
    assert parsed["result_digest"] == digest, "json projection must carry the digest"
    assert digest in text_proj, "text projection must carry the same digest"
    assert parsed["counts"]["candidate_count"] == 72
    assert "candidates           = 72" in text_proj
    # Projection identity: rendering twice yields identical bytes.
    assert render_json(sealed) == render_json(sealed)
    assert render_text(sealed) == render_text(sealed)

# STU accounting is deterministic and mirrors the declared I2.16 rule.
    assert _stu(0) == 0 and _stu(1) == 1 and _stu(3) == 1 and _stu(4) == 2

    # --- Dependency-proof invariants (defect 4). --------------------------
    #
    # #584's schema crate is NEVER a measurement dependency: a consumer that
    # only imports ``eliot_context_contracts`` names a type, not an algorithm.
    # This is the closed structural fact the audit names, asserted here so a
    # later edit that re-admits the schema crate fails loudly instead of
    # restoring the forgeable marker disjunction.
    assert MEASUREMENT_CRATE_PACKAGE == "eliot-context-measurement"
    assert MEASUREMENT_CRATE_RUST == MEASUREMENT_CRATE_PACKAGE.replace("-", "_")
    assert set(CONSUMER_DEPENDENCY_CONTRACTS) == {"#783", "#878", "#880", CANONICAL_MEASUREMENT_OWNER}
    for _owner, _contract in CONSUMER_DEPENDENCY_CONTRACTS.items():
        assert _contract.cargo_package == MEASUREMENT_CRATE_PACKAGE, (
            "every consumer contract must name #704's own measurement crate in its Cargo "
            "metadata; the #584 schema crate is not a measurement dependency"
        )
        assert _contract.port_symbol == CANONICAL_MEASUREMENT_PORT
        assert _contract.role in ("consumer", "owner")
    # Exactly one owner-role contract, and it is the canonical measurement owner:
    # the algorithm owner is proved by its definition site, never by depending on
    # the crate it is.
    assert CONSUMER_DEPENDENCY_CONTRACTS[CANONICAL_MEASUREMENT_OWNER].role == "owner"
    assert all(
        _contract.role == "consumer"
        for _owner, _contract in CONSUMER_DEPENDENCY_CONTRACTS.items()
        if _owner != CANONICAL_MEASUREMENT_OWNER
    ), "only the canonical measurement owner may hold the owner role"
    # Every approved adapter record is closed, and an empty approved set is an
    # honest empty rather than a widened accept.
    for _owner, _records in APPROVED_MEASUREMENT_ADAPTERS.items():
        assert all(record.closed() for record in _records), (
            "an approved measurement adapter record must carry an exact identity, version, "
            "expiry and canonical port"
        )
    # Every approved adapter must implement the canonical port; an adapter that
    # implements something else is not measurement evidence.
    for _records in APPROVED_MEASUREMENT_ADAPTERS.values():
        for _record in _records:
            assert _record.implements_port == CANONICAL_MEASUREMENT_PORT

    # The binding vocabulary is closed and non-empty on both sides.
    assert PORT_INPUT_RECORD == "SerializedContextInputs"
    assert PORT_FINAL_BYTES_BINDING_FIELDS == ("declared_len", "content_digest")
    assert set(PORT_IDENTITY_BINDING_FIELDS) == {"serializer", "route", "tokenizer"}
    # The identity conjunct names provider/model/tokenizer ID/version/hash, and
    # the content digest is its own conjunct.
    _identity_groups = {group for group, _names in PORT_IDENTITY_REQUIRED_FIELDS}
    assert _identity_groups == {"serializer", "route", "tokenizer"}
    assert ("route", ("route_id", "provider_id", "model_id")) in PORT_IDENTITY_REQUIRED_FIELDS
    assert ("tokenizer", ("tokenizer_id", "tokenizer_version", "tokenizer_hash")) in (
        PORT_IDENTITY_REQUIRED_FIELDS
    )

    # The binding-gap report is deterministic and names only missing conjuncts.
    _full = {
        "payload_argument": "&request.payload",
        "payload_non_empty": True,
        "final_bytes_bound": True,
        "content_digest_bound": True,
        "identity_bound": True,
        "identity_detail_bound": True,
        "identity_non_placeholder": True,
    }
    assert _binding_gaps(_full) == [], "a fully bound call has no gap to report"
    assert _binding_gaps({**_full, "final_bytes_bound": False}) == [
        f"the envelope length/digest binding ({'/'.join(PORT_FINAL_BYTES_BINDING_FIELDS)}) "
        f"into {PORT_INPUT_RECORD}"
    ]
    assert _binding_gaps({**_full, "identity_bound": False}) == [
        f"the serializer/route/tokenizer identity binding "
        f"({'/'.join(PORT_IDENTITY_BINDING_FIELDS)}) into {PORT_INPUT_RECORD}"
    ]
    assert _binding_gaps({**_full, "payload_argument": None}) == [
        "a final serialized byte payload argument"
    ]

    # Audit section 4, bullet 4: an empty payload, a literal-zero declared length
    # and a placeholder digest/identity are each NAMED as their own conjunct, so
    # none of them can pass as "final serialized bytes" or "identity" silently.
    _empty = _binding_gaps({**_full, "payload_non_empty": False})
    assert len(_empty) == 1 and "empty byte/string literal" in _empty[0], _empty
    _digest = _binding_gaps({**_full, "content_digest_bound": False})
    assert len(_digest) == 1 and "non-placeholder" in _digest[0], _digest
    _detail = _binding_gaps({**_full, "identity_detail_bound": False})
    assert len(_detail) == 1 and "ID/version/hash" in _detail[0], _detail
    _placeholder = _binding_gaps({**_full, "identity_non_placeholder": False})
    assert len(_placeholder) == 1 and "sha256:00" in _placeholder[0], _placeholder

    # The placeholder and zero-length predicates reject exactly the fabricated
    # shapes and nothing broader. The predicate reports the FIELD NAME that is
    # only a placeholder, so a blanked string literal is named by its field.
    assert PORT_CONTENT_DIGEST_FIELD in _identity_placeholders(
        "content_digest:            ,"
    )
    assert "serializer_id" in _identity_placeholders("serializer_id: 1,\nroute_id: 1,")
    assert not _identity_placeholders("serializer_id: request.serializer_id.clone(),")
    assert not _identity_placeholders("provider_id: request.provider_id.clone(),")
    assert _envelope_length_is_zero("declared_len: 0,")
    assert not _envelope_length_is_zero("declared_len: request.payload.len() as u64,")
    assert not _envelope_length_is_zero("declared_len: 1024,")

    # The payload argument is read over the WHOLE call, so a wrapped argument
    # list is measured rather than only its first line.
    _wrapped = [
        "    let measured = measure_serialized_context(",
        "        &request.payload,",
        "        &inputs,",
        "    )",
    ]
    assert _call_payload_argument(_wrapped, len(_wrapped), 1) == "&request.payload"
    # An inlined struct literal in the second position cannot mis-anchor the
    # payload read: its braces/parens/commas are carried in argument 2.
    _inline = [
        "    let measured = measure_serialized_context(payload, &SerializedContextInputs {",
        "        declared_len: payload.len() as u64,",
        "    })",
    ]
    assert _call_payload_argument(_inline, len(_inline), 1) == "payload"
    # A bare call still binds no payload.
    _bare = ["    measure_serialized_context()"]
    assert _call_payload_argument(_bare, len(_bare), 1) is None

    # --- Evidence-bearing baseline disposition (audit defect 5). ----------
    #
    # THE REGRESSION THIS BINDS. The residual arm used to return the literal
    # "canonical-owner-consumer" for every row that was neither unresolved nor an
    # excluded metric, reading only owner/classification/status. So an old
    # still-active formula was counted as reconciled purely because its old row
    # was still owned. Each assert below runs the PRODUCTION derivation over a
    # row built only from #866's frozen ROW_KEYS -- no new field is invented.
    _proven_call = {
        "#783": {
            "kind": "canonical-port-call",
            "port_symbol": CANONICAL_MEASUREMENT_PORT,
            "call_sites": ["crates/smart/eliot-context-assembly/src/measurement.rs:23"],
        }
    }
    # The paths every row below is judged at. The reach proof is measured at
    # ``_reach_path``; a row at any other path of the same owner must NOT inherit
    # it, because the audit's concern is the site, not the owner.
    _reach_path = "crates/smart/eliot-context-assembly/src/measurement.rs"
    _other_path = "crates/eliot-engine/src/skill_curator.rs"
    # (1) The defect itself: owned, attributed, but the row's OWN evidence says
    # the site is still an unvalidated local byte ratio -- the old formula.
    _live_legacy = {
        "owner": "#783",
        "status": "owned",
        "classification": "token_estimate_without_tokenizer",
        "write_scope": "read-only",
        "item_scope": "production",
        "path": _reach_path,
    }
    assert _derive_baseline_disposition(_live_legacy, _proven_call) == "explicit-unresolved", (
        "an owned row whose own evidence says the site is still an unvalidated local ratio "
        "must NOT be reported as a canonical owner consumer, even when its owner holds a "
        "proven dependency elsewhere"
    )
    # (2) The SAME row after a real migration: canonical classification + proof.
    _genuine = dict(_live_legacy, classification="exact-utf8-envelope")
    assert _derive_baseline_disposition(_genuine, _proven_call) == "canonical-owner-consumer", (
        "a migrated row whose owner holds a MEASURED canonical dependency AT THIS PATH is "
        "still canonical"
    )
    # (3) Genuine classification but NO proven dependency: the evidence is absent.
    assert _derive_baseline_disposition(_genuine, {}) == "explicit-unresolved", (
        "an owned row with no measured consumer dependency proof must not assert a migration"
    )
    assert _derive_baseline_disposition(
        _genuine, {"#783": {"kind": "missing"}}
    ) == "explicit-unresolved", "an owner whose measured kind is not a canonical reach kind proves nothing"
    # An owner absent from the map entirely (its rows were all read-only, so the
    # dependency check never ran over it) is NOT proven. Absence of a complaint
    # is not evidence.
    assert _derive_baseline_disposition(_genuine, {"#878": _proven_call["#783"]}) == (
        "explicit-unresolved"
    ), "another owner's proof must never satisfy this row's owner"
    # (4) A test-only site is not a consumer even with a proven owner.
    assert _derive_baseline_disposition(
        dict(_genuine, item_scope="test"), _proven_call
    ) == "explicit-unresolved", "a test-only row is not a consumer seam"
    # (5) PATH-SCOPED, not owner-scoped: the very same row, same owner, same
    # classification and status, moved to a DIFFERENT path of that owner. The
    # owner's proof was measured at ``_reach_path`` only, so this row's own site
    # carries no evidence and must stay unresolved.
    _off_path = dict(_genuine, path=_other_path)
    assert _derive_baseline_disposition(_off_path, _proven_call) == "explicit-unresolved", (
        "a proof about the owner at one path is not a proof about this row's own path"
    )
    assert _derive_baseline_disposition(_genuine, _proven_call) == "canonical-owner-consumer", (
        "the same owner at the proven path is still canonical -- scoping must not invert it"
    )
    # The owner of record is proved at its DECLARED SCOPE -- the exact
    # ``source_paths`` the accepted frozen owner map allocates to it -- not at
    # its definition sites. Those are two different measured facts and this
    # binds the difference, because #704 DECLARES four exact files while it
    # DEFINES the port in only two of them: a row at ``receipt.rs`` or
    # ``envelope.rs`` is inside the owner's declared scope with no definition
    # site of its own, and a row at a path the map does not declare to #704 is
    # outside the owner's scope entirely.
    _owner_proof = {
        "#704": {
            "kind": "canonical-port-owner",
            "port_symbol": CANONICAL_MEASUREMENT_PORT,
            "definition_proved_by": "canonical-owner",
            "scope_proved_by": "frozen-owner-map",
            # #704's four DECLARED files, verbatim from the accepted owner map.
            "source_paths": [
                "crates/smart/eliot-context-measurement/src/envelope.rs",
                "crates/smart/eliot-context-measurement/src/lib.rs",
                "crates/smart/eliot-context-measurement/src/receipt.rs",
                "crates/smart/eliot-context-measurement/src/stu.rs",
            ],
            # The port is DEFINED in only two of those four. The definition-site
            # fact still travels in the record and is still measured; it is just
            # not the scope the reach is asked at.
            "definition_paths": [
                "crates/smart/eliot-context-measurement/src/lib.rs",
                "crates/smart/eliot-context-measurement/src/stu.rs",
            ],
        }
    }
    _owner_row = dict(_genuine, owner="#704")
    # A declared, non-definition file IS the owner's own scope.
    assert _derive_baseline_disposition(
        dict(_owner_row, path="crates/smart/eliot-context-measurement/src/stu.rs"),
        _owner_proof,
    ) == "canonical-owner-consumer", "the owner's row at a declared path is canonical"
    assert _derive_baseline_disposition(
        dict(_owner_row, path="crates/smart/eliot-context-measurement/src/receipt.rs"),
        _owner_proof,
    ) == "canonical-owner-consumer", (
        "an owner-of-record row at a DECLARED path with no definition site of its own is "
        "inside the owner's scope: the accepted owner map allocates that exact file to "
        "#704, and 'only in its owner' means its declared source_paths entry"
    )
    # A path the accepted map does NOT declare to #704 is outside the scope,
    # however close it is to the owner's crate.
    assert _derive_baseline_disposition(
        dict(_owner_row, path="crates/eliot-engine/src/skill_curator.rs"),
        _owner_proof,
    ) == "explicit-unresolved", (
        "an owner-of-record row at a path the owner map does not declare to #704 is not "
        "proved by the owner's declared scope elsewhere"
    )
    # A record that names no declared scope proves nothing at any path -- the
    # per-kind reader is total, and a canonical-port-owner record with an empty
    # ``source_paths`` is exactly the over-broad proof this reader exists to stop.
    assert _derive_baseline_disposition(
        _owner_row,
        {"#704": {"kind": "canonical-port-owner", "definition_paths": [
            "crates/smart/eliot-context-measurement/src/stu.rs",
        ]}},
    ) == "explicit-unresolved", (
        "a canonical-port-owner record that names no declared source_paths proves nothing "
        "at any path; the definition-site list alone is not the reach scope"
    )
    # (6) The declared-but-underived disposition is still never returned, by any
    # of the reachable shapes.
    _shapes = (
        (_live_legacy, _proven_call),
        (_genuine, _proven_call),
        (_genuine, {}),
        (_off_path, _proven_call),
        (dict(_genuine, item_scope="test"), _proven_call),
        (dict(_genuine, status="unresolved"), _proven_call),
        (dict(_genuine, classification="unrelated_byte_or_character_metric"), _proven_call),
    )
    for _row, _proofs in _shapes:
        assert _derive_baseline_disposition(_row, _proofs) in BASELINE_DISPOSITIONS
        assert _derive_baseline_disposition(_row, _proofs) != "exact-versioned-legacy-adapter", (
            "exact-versioned-legacy-adapter stays declared but unreachable (ContractChallenge "
            "against #866); no admissible row may derive it"
        )
    # (7) Mutual exclusivity: no row receives two dispositions. The function
    # returns exactly one string, so exclusivity is asserted structurally -- the
    # three distinct shapes give three DISTINCT values, and the two shapes that
    # share a value share it because they fail the SAME predicate.
    assert len(
        {
            _derive_baseline_disposition(_genuine, _proven_call),
            _derive_baseline_disposition(_live_legacy, _proven_call),
            _derive_baseline_disposition(
                dict(_genuine, classification="unrelated_byte_or_character_metric"),
                _proven_call,
            ),
        }
    ) == 3, "the three distinguishable shapes must yield three distinct dispositions"
    # The reach vocabulary is closed and matches the kinds evaluate can produce.
    assert set(CANONICAL_REACH_KINDS) == {
        "canonical-port-call",
        "canonical-port-owner",
        "approved-adapter",
    }
    assert not set(LEGACY_FORMULA_CLASSIFICATIONS) & set(CANONICAL_REACH_KINDS)
    # _canonical_reach_proven reports the deciding conjunct, never a bare bool,
    # and never proves a row outside the path its proof was measured at.
    _ok, _why = _canonical_reach_proven("#783", _reach_path, _proven_call)
    assert _ok is True and "canonical-port-call" in _why
    _ok_off, why_off = _canonical_reach_proven("#783", _other_path, _proven_call)
    assert _ok_off is False and _other_path in why_off and _reach_path in why_off, (
        "the unproven path's reason must name both the path asked about and the path the "
        "proof was actually measured at"
    )
    _ok2, why2 = _canonical_reach_proven("#783", _reach_path, {})
    assert _ok2 is False and why2
    # A proof record that names no proven path proves nothing anywhere.
    assert _canonical_reach_proven("#783", _reach_path, {"#783": {"kind": "canonical-port-call"}})[
        0
    ] is False, "a proof carrying no measured path is not a proof at any path"

    print("PASS: audit_context_measurement_ownership self-tests completed successfully")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--self-test", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.self_test:
        try:
            return run_self_test()
        except (OracleError, AssertionError) as exc:
            print(f"SELF_TEST_FAILED: {exc}", file=sys.stderr)
            return 1
    try:
        result = evaluate(args.root)
    except OracleError as exc:
        # A typed defect discovered outside the finding loop is still reported
        # as a one-result JSON/text object, not a crash.
        result = OwnershipResult(
            result_schema=RESULT_SCHEMA,
            oracle_version=ORACLE_VERSION,
            issue=ISSUE,
            producer_issue=PRODUCER_ISSUE,
            proof_ceiling=PROOF_CEILING,
            inventory_path=INVENTORY_REL,
            inventory_present=False,
            inventory_digest="",
            source_sha="",
            rule_digest="",
            owner_digest="",
            rule_revision="",
            coverage_disposition="",
            owner_map_status="",
            candidate_count=0,
            classified_count=0,
            owned_count=0,
            unresolved_count=0,
            baseline_reconciled=0,
            baseline_expected=EXPECTED_BASELINE_COUNT,
            baseline_dispositions={d: 0 for d in BASELINE_DISPOSITIONS},
            unaccounted_candidate_count=0,
            canonical_measurement_owners=(),
            canonical_schema_owners=(),
            dependency_proofs={},
            producer_check_status="error",
            finding_count=1,
            findings=(Finding(exc.code, exc.detail, rule="evaluation"),),
            result_digest="",
        )
    rendered = render_json(result) if args.format == "json" else render_text(result)
    print(rendered)
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
