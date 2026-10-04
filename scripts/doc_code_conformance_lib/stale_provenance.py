"""Repository-wide scanner for stale documentation provenance (DCC-018).

Issue #1147 (`[docs/source] Remove stale codebase-memory and legacy-document
provenance from production comments`) declares that a known-file retirement
ledger is not an enforcement boundary.  ``DCC-014`` only visits the hand-listed
``[[surface]]`` entries of ``config/doc-traceability-retirement.toml``, so a
production file that is not in that ledger is never inspected.  This module
replaces that bounded denominator with a single scan over the repository's own
declared production/current-documentation roots
(``retired_references.scan_roots`` in ``config/doc-code-conformance.toml``).
The ledger keeps its job -- it declares *required replacement tokens* for the
surfaces it already names -- but it no longer defines what is checked.

WHAT IS FORBIDDEN
-----------------
Stale *documentation provenance and authority prose*: comments, doc strings and
operational documentation that present a retired predecessor identity, a frozen
snapshot identity, a historical git coordinate, or a legacy index/attestation
tool as the current source or document authority.

WHAT IS NOT FORBIDDEN
---------------------
The *existence* of a legacy integration name in product code.  ``codebase_memory``
is a live MCP integration id, a serde enum variant and a serialized token; the
prohibition targets provenance prose, not identifiers.

THE CLASSIFICATION MECHANISM (the part that must not be hand-waved)
---------------------------------------------------------------------
A banned spelling alone cannot separate the two, so every candidate is first
classified by *usage context* and only then judged.  Two orthogonal tests:

1. LEXICAL CONTEXT (closed, per family).  A bare identifier is a product
   string.  A candidate inside a narrative clause is a provenance claim.  For
   example ``codebase_memory_mcp`` in a tuple of integration ids is a product
   identifier, while ``verified via codebase_memory against <id>`` is an
   attestation naming a legacy index as the thing that verified the claim.
   Every family in :data:`FAMILIES` declares its own context pattern; none of
   them matches on a bare token.

2. EVIDENCE SUBSTRATE.  A claim is forbidden authority when the same match
   window ties it to a legacy substrate, and specifically NOT when the
   substrate is an exact (case-sensitive) source-code spelling:

   * ``codebase-memory`` (hyphenated) == the on-disk skip-directory name
     ``.codebase-memory``.  It is a real path.  It is never evidence.
   * ``codebase_memory`` / ``CodebaseMemory`` (underscore / PascalCase) ==
     the integration id and the serde token.  It is never evidence either,
     which is what spares ``codebase_memory_mcp`` and
     ``CodeEvidenceSource::CodebaseMemory``.
   * ``codebase memory`` (spaced, mixed case, case-insensitive) == prose.  It
     is evidence, because only prose can write that.

   So the same lexical family yields opposite verdicts for
   ``CodebaseMemory,`` (spared) and ``verified via codebase_memory against
   <id>`` (forbidden) on identical substrings, and the discriminator is
   derived from the match, not from a file list.

For the attestation-narrative families the substrate is an explicit
antecedent requirement: ``verified against base``, ``verified from``,
``source of truth`` and their equivalents are extremely common in ordinary
product prose in this repository (verified: 268 in-scope occurrences), and all
of them are legitimate -- "the host receipt stays the source of truth", "the
recorded digest is verified against the live root".  Banning the phrases would
be wrong and would break live code.  They are forbidden only when the sentence
either names a legacy index substrate or pins a git coordinate as the current
authority, both of which are separately detectable.  That is why this module
requires the substrate rather than assuming the phrase is enough.

Both findings report the exact repository path, the line, the matched text, the
family id, and the canonical replacement guidance.
"""

from __future__ import annotations

import fnmatch
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

import doc_code_conformance_core as core

FINDING_ID = "DCC-018"
SECTION = "stale_provenance"
# Bumped whenever a family is added, a context pattern is widened, or the
# classification rules change. Findings embed it so a stored artifact can be
# compared against the detector that produced it.
POLICY_VERSION = "eliot-stale-provenance-v1"

# The repository's own notion of a production/current-documentation surface.
# `docs` is deliberately absent: the documentation books record predecessor
# identities intentionally.
DEFAULT_SCAN_SECTION = "retired_references"


class ProvenanceError(RuntimeError):
    """Raised for malformed configuration; callers turn this into exit code 2."""

    def __init__(self, message: str, path: str | Path = SECTION) -> None:
        super().__init__(message)
        self.path = Path(path).as_posix()


# --------------------------------------------------------------------------
# Family catalogue
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Family:
    """One closed, versioned stale-provenance pattern family.

    ``context`` is the provenance narrative the stale spelling may only appear
    in.  It is matched against the full physical line, so a family can never
    fire on a bare identifier.  ``substrate`` names the legacy spelling that
    makes the surrounding sentence a legacy claim.
    """

    family_id: str
    summary: str
    guidance: str
    context: re.Pattern[str]
    substrate: re.Pattern[str] | None = None
    neutral: re.Pattern[str] | None = None
    emit_substrate: bool = False


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# A legacy substrate spelling in prose. `codebase memory` is the only spelling
# that can only occur in a sentence; the hyphenated and underscored forms are
# real paths/identifiers and are therefore never treated as evidence on their
# own (see the module docstring). The em-dash/elision forms produced by older
# tooling are included so a typo cannot open a bypass.
LEGACY_INDEX_SUBSTRATE = _rx(
    r"codebase[\s\u00a0_\-]*memor(?:y|ies)"
    r"|code[\s\-_]*base[\s\-_]*memor(?:y|ies)"
    r"|code[\s\-_]*base[\s\-_]*memori(?:z|s|ed|ing)"
)
LEGACY_DOC_SUBSTRATE = _rx(
    r"eliot-(?:architecture|implementation|memory)-docs-[A-Za-z0-9][A-Za-z0-9._-]*"
    r"|eliot-memory-os-[A-Za-z0-9][A-Za-z0-9._-]*-live"
    r"|ELIOT_(?:ARCHITECTURE|IMPLEMENTATION)\.(?!md)"
)

# Attribution/verification verbs. Only these may introduce an authority claim.
ATTESTATION_VERB = _rx(
    r"(?:verif(?:y|ied|ies|ying|ication)"
    r"|confirm(?:ed|s|ation)?"
    r"|attest(?:ed|s|ation)?"
    r"|proven|proves|proved"
    r"|establish(?:ed|es)?"
    r"|derived|derived from"
    r"|taken\s+from|taken\s+from"
    r"|cross[-\s]checked"
    r"|grounded"
    r"|reconciled)"
)

FAMILIES: dict[str, Family] = {}


def _register(family: Family) -> Family:
    FAMILIES[family.family_id] = family
    return family


# --- F1: legacy index/graph attestation used as authority -----------------
_register(
    Family(
        family_id="legacy-index-attestation",
        summary="legacy codebase-memory index cited as the attestation substrate",
        guidance=(
            "codebase-memory is not a verification oracle. Cite exact source plus the "
            "owning verifier instead."
        ),
        context=_rx(
            r"\b(?:verif(?:y|ied|ies|ying|ication)|confirm(?:ed|s|ation)?"
            r"|attest(?:ed|s|ation)?|proven|proves|proved"
            r"|establish(?:ed|es)?|grounded|reconciled|cross[-\s]checked)"
            r"\s+(?:directly\s+|independently\s+|externally\s+)?"
            r"(?:against|via|from|by|with|through|using|under|in|on)"
        ),
        substrate=LEGACY_INDEX_SUBSTRATE,
        emit_substrate=True,
    )
)

# --- F2: snapshot / routing identity presented as document authority ------
_register(
    Family(
        family_id="snapshot-document-id",
        summary="frozen architecture/implementation snapshot identity presented as document authority",
        guidance=(
            "the snapshot id is a retired predecessor identity. Cite the canonical "
            "shard path and its handle, e.g. docs/architecture/A02-03-modular-architecture.md:A2.3"
        ),
        context=_rx(
            r"\b(?:source\s+of\s+truth|authority|authoritative|normative\s+source"
            r"|canonical\s+(?:document|source|reference)"
            r"|definitive|governing\s+(?:document|source|spec)"
            r"|verified\s+(?:against|from|via|by)"
            r"|cited\s+(?:from|in)\s+the\s+snapshot)"
        ),
        substrate=LEGACY_DOC_SUBSTRATE,
        emit_substrate=True,
    )
)

# --- F3: historical SHA/branch pin presented as current authority ---------
_register(
    Family(
        family_id="historical-authority-pin",
        summary="historical commit/branch coordinate presented as current source or document authority",
        guidance=(
            "a commit coordinate is a provenance record, not a read path. Cite the "
            "canonical shard path and handle, and record the commit in the issue "
            "or run receipt instead."
        ),
        context=_rx(
            r"(?:\bsource\s+of\s+truth\b|\bcanonical\s+(?:base|parent|sha|commit|pin)"
            r"|\bcurrent\s+authority\b|\bauthoritative\s+(?:source|commit|pin)"
            r"|\bpinned\s+(?:to|at)\b|\bverified\s+(?:against|from|via|by)\b"
            r"|\bcited\s+(?:at|from|to)\b|\bbased\s+on\s+commit\b"
            r"|\bline\s+spans?\s+refer\s+to\b)"
        ),
        substrate=_rx(r"\b[A-Za-z][A-Za-z0-9]*(?:[._/-][A-Za-z0-9_-]+)*@[0-9a-f]{7,40}\b"),
        emit_substrate=True,
    )
)

# --- F4: dotted ELIOT_* compatibility handle -----------------------------
# `ELIOT_ARCHITECTURE.md` is allowed (DCC-003 already owns the .md token and its
# path-qualified spelling). Anything else behind the dot is a compatibility-map
# handle whose resolution is a snapshot lookup, not a handle-index entry.
_register(
    Family(
        family_id="dotted-legacy-handle",
        summary="unresolved dotted ELIOT_ARCHITECTURE/ELIOT_IMPLEMENTATION compatibility handle",
        guidance=(
            "the dotted ELIOT_* form resolves through a snapshot lookup and is not in "
            "the handle index. Cite docs/architecture/<shard>.md:<A|I handle> instead."
        ),
        context=_rx(r"ELIOT_(?:ARCHITECTURE|IMPLEMENTATION)\.(?!md)"),
    )
)


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Config:
    policy_version: str
    scan_roots: tuple[str, ...]
    extensions: frozenset[str]
    ignore_globs: tuple[str, ...]
    enabled_families: frozenset[str]
    exceptions: tuple[tuple[str, str, str], ...]


def _strings(value: Any, field: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if value is None and allow_empty:
        return ()
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ProvenanceError(f"{field} must be an array of non-empty strings")
    normalized = tuple(item.strip().replace("\\", "/") for item in value)
    if not allow_empty and not normalized:
        raise ProvenanceError(f"{field} must not be empty")
    if len(normalized) != len(set(normalized)):
        raise ProvenanceError(f"{field} contains duplicates")
    return normalized


def load_config(cfg: dict[str, Any]) -> Config:
    """Build a Config from the already-parsed conformance document.

    The scan denominator is reused from ``retired_references.scan_roots`` so this
    detector can never drift from the repository's own definition of a
    production surface.  Only families and exceptions are new.
    """

    base = cfg.get(DEFAULT_SCAN_SECTION)
    if not isinstance(base, dict):
        raise ProvenanceError(
            f"{DEFAULT_SCAN_SECTION} section is required: it defines the scan denominator"
        )
    raw = cfg.get(SECTION)
    if not isinstance(raw, dict):
        raise ProvenanceError(f"[{SECTION}] section is missing")

    policy_version = str(raw.get("policy_version", "")).strip()
    if policy_version != POLICY_VERSION:
        raise ProvenanceError(
            f"unsupported stale_provenance policy_version: {policy_version!r} "
            f"(expected {POLICY_VERSION!r})"
        )

    enabled = _strings(
        raw.get("families", sorted(FAMILIES)),
        "stale_provenance.families",
    )
    unknown = sorted(set(enabled) - set(FAMILIES))
    if unknown:
        raise ProvenanceError(
            "stale_provenance.families names unknown family ids: " + ", ".join(unknown)
        )

    raw_exceptions = raw.get("exception", [])
    if not isinstance(raw_exceptions, list):
        raise ProvenanceError("stale_provenance.exception must be an array")
    exceptions: list[tuple[str, str, str]] = []
    for index, item in enumerate(raw_exceptions):
        if not isinstance(item, dict):
            raise ProvenanceError(f"stale_provenance.exception[{index}] must be a table")
        # Unknown keys are rejected so an exception cannot be silently widened
        # by adding a field this detector does not honour.
        extra = sorted(set(item) - {"path", "pattern", "reason"})
        if extra:
            raise ProvenanceError(
                f"stale_provenance.exception[{index}] has unknown keys: {', '.join(extra)}"
            )
        try:
            path = core.norm(str(item.get("path", "")))
        except core.AuditError as exc:
            raise ProvenanceError(f"stale_provenance.exception[{index}]: {exc}") from exc
        pattern = str(item.get("pattern", "")).strip()
        reason = str(item.get("reason", "")).strip()
        if not pattern:
            raise ProvenanceError(
                f"stale_provenance.exception[{index}] ({path}) needs a pattern"
            )
        if not reason:
            raise ProvenanceError(
                f"stale_provenance.exception[{index}] ({path}) needs a reason"
            )
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ProvenanceError(
                f"stale_provenance.exception[{index}] ({path}) has an invalid "
                f"pattern {pattern!r}: {exc}"
            ) from exc
        exceptions.append((path, pattern, reason))
    if len({(path, pattern) for path, pattern, _ in exceptions}) != len(exceptions):
        raise ProvenanceError("stale_provenance.exception has duplicate path/pattern pairs")

    return Config(
        policy_version=policy_version,
        scan_roots=_strings(base.get("scan_roots"), "retired_references.scan_roots"),
        extensions=frozenset(
            item.casefold()
            for item in _strings(base.get("extensions"), "retired_references.extensions")
        ),
        ignore_globs=_strings(
            base.get("ignore_globs", []),
            "retired_references.ignore_globs",
            allow_empty=True,
        ),
        enabled_families=frozenset(enabled),
        exceptions=tuple(exceptions),
    )


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------


def _context_of(value: str, offset: int) -> tuple[int, str]:
    """Return the absolute start of the physical line holding ``offset`` and its text.

    Classification is per physical line rather than per file: a provenance claim
    is a sentence, and a claim never straddles a newline in these surfaces.
    """

    start = value.rfind("\n", 0, offset) + 1
    end = value.find("\n", offset)
    if end < 0:
        end = len(value)
    return start, value[start:end]


def _scan_line(
    value: str,
    relative: str,
    start: int,
    line: str,
    families: Sequence[Family],
    exceptions: dict[str, tuple[tuple[str, str], ...]],
) -> list[core.Finding]:
    findings: list[core.Finding] = []
    number = value.count("\n", 0, start) + 1
    for family in families:
        for match in family.context.finditer(line):
            context_end = match.end()
            # The substrate must appear in the same claim. Prefer the text to the
            # right of the verb (`verified against <id>`); fall back to the whole
            # line so `... codebase_memory; verified by <sha>` still qualifies.
            tail = line[context_end:]
            head = line[: match.start()]
            substrate_match = None
            if family.substrate is not None:
                substrate_match = (
                    family.substrate.search(tail)
                    or family.substrate.search(head)
                    or family.substrate.search(line)
                )
                if substrate_match is None:
                    continue
                if family.neutral is not None and family.neutral.search(line):
                    continue
            if any(
                path == relative and re.search(pattern, line)
                for path, pattern in exceptions.get(family.family_id, ())
            ):
                continue
            matched = match.group(0)
            detail = ""
            if family.emit_substrate and substrate_match is not None:
                detail = f" substrate={substrate_match.group(0)!r}"
            findings.append(
                core.Finding(
                    FINDING_ID,
                    relative,
                    number,
                    f"stale documentation provenance ({family.family_id}): {matched!r};"
                    f" replace with current authority -- {family.guidance}{detail}",
                )
            )
    return findings


def _exception_map(
    config: Config,
    families: Sequence[Family],
) -> dict[str, tuple[tuple[str, str], ...]]:
    mapped: dict[str, tuple[tuple[str, str], ...]] = {}
    for path, pattern, _ in config.exceptions:
        for family in families:
            mapped.setdefault(family.family_id, ())
            mapped[family.family_id] += ((path, pattern),)
    return mapped


def audit(
    root: Path,
    cfg: dict[str, Any],
) -> tuple[list[core.Finding], dict[str, int]]:
    config = load_config(cfg)
    families = [FAMILIES[family_id] for family_id in sorted(config.enabled_families)]
    exceptions = _exception_map(config, families)

    findings: list[core.Finding] = []
    scanned = 0
    candidates = 0
    # Reuse the front door's fail-closed root expansion so a missing configured
    # root can never silently shrink the denominator.
    for path in core.selected_files(root, config.scan_roots):
        relative = core.rel(root, path)
        if path.suffix.lower() not in config.extensions:
            continue
        if any(fnmatch.fnmatchcase(relative, pat) for pat in config.ignore_globs):
            continue
        try:
            value = core.text(path)
        except core.AuditError as exc:
            findings.append(core.Finding(FINDING_ID, relative, 0, str(exc)))
            continue
        scanned += 1
        for family in families:
            for match in family.context.finditer(value):
                candidates += 1
                start, line = _context_of(value, match.start())
                findings.extend(
                    _scan_line(value, relative, start, line, families, exceptions)
                )
    return sorted(set(findings)), {
        "stale_provenance_files": scanned,
        "stale_provenance_candidates": candidates,
        "stale_provenance_families": len(families),
    }
    CONFIG_EXCEPTIONS = {}
    for path, pattern, _ in config.exceptions:
        for family_id in CONFIG_FAMILIES:
            CONFIG_EXCEPTIONS.setdefault(family_id, ())
            CONFIG_EXCEPTIONS[family_id] += ((path, pattern),)

    findings: list[core.Finding] = []
    scanned = 0
    candidates = 0
    # Reuse the front door's fail-closed root expansion so a missing configured
    # root can never silently shrink the denominator.
    for path in core.selected_files(root, config.scan_roots):
        relative = core.rel(root, path)
        if path.suffix.lower() not in config.extensions:
            continue
        if any(fnmatch.fnmatchcase(relative, pat) for pat in config.ignore_globs):
            continue
        try:
            value = core.text(path)
        except core.AuditError as exc:
            findings.append(core.Finding(FINDING_ID, relative, 0, str(exc)))
            continue
        scanned += 1
        for family_id in sorted(CONFIG_FAMILIES):
            family = CONFIG_FAMILIES[family_id]
            for match in family.context.finditer(value):
                candidates += 1
                start, line = _context_of(value, match.start())
                findings.extend(_scan_line(value, relative, start, line))
    return sorted(set(findings)), {
        "stale_provenance_files": scanned,
        "stale_provenance_candidates": candidates,
        "stale_provenance_families": len(CONFIG_FAMILIES),
    }


def _fixture_config(base: dict[str, Any]) -> dict[str, Any]:
    config = {
        key: value for key, value in base.items() if key in {DEFAULT_SCAN_SECTION}
    }
    section = dict(config[DEFAULT_SCAN_SECTION])
    section["scan_roots"] = ["crates"]
    section["extensions"] = [".rs", ".yml", ".toml", ".py"]
    config[DEFAULT_SCAN_SECTION] = section
    config[SECTION] = {
        "policy_version": POLICY_VERSION,
        "families": sorted(FAMILIES),
        "exception": [],
    }
    return config


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------


def _write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8", newline="")


def self_test() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        _write(root / "crates/tool/src/lib.rs", "pub fn marker() {}\n")
        _write(
            root / "crates/tool/Cargo.toml",
            '[package]\nname = "tool"\nversion = "0.1.0"\n',
        )
        cfg = _fixture_config({"retired_references": {}})

        clean, metrics = audit(root, cfg)
        if clean:
            raise ProvenanceError(f"clean stale-provenance fixture failed: {clean}")

        def findings_for(relative: str) -> list[core.Finding]:
            return [
                item
                for item in audit(root, cfg)[0]
                if item.path == relative
            ]

        # ---- Case 1: an UNLISTED production source with each stale family.
        # `crates/tool/src/unlisted.rs` appears in no ledger of any kind.
        unlisted = root / "crates/tool/src/unlisted.rs"
        cases: list[tuple[str, str]] = [
            (
                "F1",
                "//! verified via codebase memory against eliot-architecture-docs-x\n",
            ),
            (
                "F2",
                "//! source of truth: eliot-architecture-docs-9f2b\n",
            ),
            (
                "F3",
                "//! source of truth: main@0123456789abcdef0123456789abcdef01234567\n",
            ),
            (
                "F4",
                "//! unresolved handle ELIOT_ARCHITECTURE.A2.3 in this header\n",
            ),
        ]
        for _label, body in cases:
            _write(unlisted, body)
            produced = findings_for("crates/tool/src/unlisted.rs")
            if not produced:
                raise ProvenanceError(f"unlisted production fixture {body!r} did not fail")
            if produced[0].line != 1:
                raise ProvenanceError(
                    f"unlisted production fixture {body!r} reported line "
                    f"{produced[0].line}, expected 1"
                )
            if FINDING_ID not in {item.finding_id for item in produced}:
                raise ProvenanceError("stale provenance did not report DCC-018")
        _write(unlisted, "pub fn marker() {}\n")

        # ---- Case 2: variable ids, not one frozen literal.
        for snapshot in ("eliot-architecture-docs-deadbeef", "eliot-architecture-docs-00c0ffee1234"):
            body = f"//! source of truth: {snapshot}\n"
            _write(unlisted, body)
            produced = findings_for("crates/tool/src/unlisted.rs")
            if not any(snapshot in item.message for item in produced):
                raise ProvenanceError(f"variable snapshot id {snapshot!r} did not fail")
        _write(unlisted, "pub fn marker() {}\n")

        # ---- Case 3: historical SHA/branch authority narrative.
        branch_body = (
            "//! source of truth: main@0123456789abcdef0123456789abcdef01234567\n"
        )
        _write(unlisted, branch_body)
        produced = findings_for("crates/tool/src/unlisted.rs")
        if not produced or "main@0123456789abcdef" not in produced[0].message:
            raise ProvenanceError(
                f"historical branch authority narrative did not fail: {produced}"
            )
        # The same narrative in a fixture exception is permitted, bounded.
        cfg[SECTION]["exception"] = [
            {
                "path": "crates/tool/src/unlisted.rs",
                "pattern": r"main@[0-9a-f]{40}",
                "reason": "detector fixture: the negative narrative under test",
            }
        ]
        if findings_for("crates/tool/src/unlisted.rs"):
            raise ProvenanceError("bounded fixture exception was not honoured")
        # The exception is per pattern: a different pin in the same file fails.
        _write(
            unlisted,
            "//! source of truth: main@0123456789abcdef0123456789abcdef01234567\n"
            "//! source of truth: release@fedcba9876543210fedcba9876543210fedcba98\n",
        )
        if not findings_for("crates/tool/src/unlisted.rs"):
            raise ProvenanceError("fixture exception was not pattern-scoped")
        cfg[SECTION]["exception"] = []
        _write(unlisted, "pub fn marker() {}\n")

        # ---- Case 6: legitimate product identifiers must survive.
        # This is the positive half of the classification requirement.
        for body in (
            '//! ("codebase_memory_mcp", IntegrationCategory::McpServer),\n',
            "    CodeEvidenceSource::CodebaseMemory,\n",
            "    CodebaseMemory,\n",
            '    "adapter": "CodeBase Memory MCP",\n',
            '[mcp_servers.codebase_memory]\ncommand = "C:/fixture/codebase-memory-mcp.exe"\n',
            "# skip .codebase-memory/ before globbing\n",
        ):
            _write(unlisted, body)
            produced = findings_for("crates/tool/src/unlisted.rs")
            if produced:
                raise ProvenanceError(
                    f"legitimate product identifier was rejected {body!r}: {produced}"
                )
        # ...and the same spelling inside an attestation clause IS rejected.
        _write(unlisted, "//! verified via codebase_memory against eliot-architecture-docs-deadbeef\n")
        if not findings_for("crates/tool/src/unlisted.rs"):
            raise ProvenanceError(
                "codebase_memory attestation prose was accepted; the context "
                "classification is not discriminating"
            )
        _write(unlisted, "pub fn marker() {}\n")

        # ---- Case 4: unresolved dotted legacy handle vs the .md token.
        _write(unlisted, "//! resolved against ELIOT_ARCHITECTURE.md:A2.3\n")
        if findings_for("crates/tool/src/unlisted.rs"):
            raise ProvenanceError("ELIOT_ARCHITECTURE.md:A2.3 is not dotted and must pass")
        for dotted in (
            "//! handle ELIOT_ARCHITECTURE.A2.3\n",
            "//! handle ELIOT_IMPLEMENTATION.I1.8\n",
        ):
            _write(unlisted, dotted)
            if not findings_for("crates/tool/src/unlisted.rs"):
                raise ProvenanceError(f"dotted legacy handle {dotted!r} was accepted")
        _write(unlisted, "pub fn marker() {}\n")

        # ---- Phrase families must not fire without a legacy substrate.
        # These are ordinary product sentences that exist in this repository.
        for body in (
            "/// the host receipt stays the source of truth for this projection\n",
            "/// the recorded digest is verified against the live root\n",
            "/// verified by recomputation against the installed document\n",
        ):
            _write(unlisted, body)
            produced = findings_for("crates/tool/src/unlisted.rs")
            if produced:
                raise ProvenanceError(
                    f"attestation phrase without a legacy substrate was rejected "
                    f"{body!r}: {produced}"
                )

        # ---- Malformed configuration fails closed (exit 2 path).
        for broken in (
            {SECTION: {"policy_version": "wrong"}},
            {SECTION: {"policy_version": POLICY_VERSION, "families": ["no-such-family"]}},
            {
                SECTION: {
                    "policy_version": POLICY_VERSION,
                    "exception": [{"path": "crates/x.rs", "reason": "no pattern"}],
                }
            },
            {
                SECTION: {
                    "policy_version": POLICY_VERSION,
                    "exception": [
                        {
                            "path": "crates/x.rs",
                            "pattern": "([",
                            "reason": "invalid regex",
                        }
                    ],
                }
            },
        ):
            bad = _fixture_config({"retired_references": {}})
            bad[SECTION].update(broken[SECTION])
            try:
                audit(root, bad)
            except ProvenanceError:
                pass
            else:
                raise ProvenanceError(f"malformed config did not fail closed: {broken}")

    print("STALE_DOCUMENTATION_PROVENANCE_SELF_TEST: PASS cases=14")