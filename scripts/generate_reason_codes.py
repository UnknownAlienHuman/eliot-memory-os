#!/usr/bin/env python3
"""Emit the I7.20 reason-code registry from its canonical catalogue source.

The canonical source is the I7.20 agent-facing error contract
(`docs/architecture/I07-20-agent-facing-error-contract.md`): it owns the
closed ``AgentResponseDisposition`` vocabulary and the grouped additive
reason-code set. This generator projects both into the executable runtime
registry ``crates/foundation/eliot-protocol/src/reason_codes.rs`` and the
human-readable ``docs/generated/reason-codes.md``. The Rust file is never
edited by hand: every row derives from a parsed owner source, and the file
header binds the exact catalogue/transport digests plus this generator
revision, so a catalogue change fails ``--check`` until the projection is
regenerated and reviewed.

The seven bridge-alias pairs are the explicit #204 product mapping pinned
here (legacy transport name to canonical catalogue reason). Each pin is
validated on every run: the legacy name must resolve through the exact
``AgentBridgeActivationDenialCode::as_str`` transport vocabulary owned by
``crates/foundation/eliot-protocol/src/lib.rs`` (read-only input; full
coverage, no more and no less), and the canonical target must be a member
of the parsed I7.20 set. The seven bridge-denial projection rows extend the
same pins with the closed I7.20 disposition and the typed directive wire
value, so the catalogue projection owns a disposition callable instead of
leaving Bridge/Kernel on hand-maintained matches: each disposition must be a
member of the parsed catalogue disposition vocabulary and each directive
must resolve through the exact ``AgentActivationDirectiveKind::as_str``
vocabulary owned by the same transport file. Bridge/Kernel consumption of
the emitted tables is a separate consumer slice; this generator only ships
the projection.

Usage:

    python scripts/generate_reason_codes.py            # write both artefacts
    python scripts/generate_reason_codes.py --check    # gate: non-zero if stale

``--check`` re-derives both artefacts byte for byte from the current owner
sources, including the recorded source digests. A hand-edited registry row
cannot be kept, because the check compares bytes.

The generator fails closed. A disposition vocabulary, reason group, alias
pin, or transport declaration it cannot read exactly is a non-zero exit
with a named reason, so the projection can never silently diverge from the
catalogue it claims to project.
"""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
I720_CATALOGUE = ROOT / "docs/architecture/I07-20-agent-facing-error-contract.md"
PROTOCOL_LIB = ROOT / "crates/foundation/eliot-protocol/src/lib.rs"
RS_ARTIFACT = ROOT / "crates/foundation/eliot-protocol/src/reason_codes.rs"
MD_ARTIFACT = ROOT / "docs/generated/reason-codes.md"

#: Generator logic revision. Bump when this file's parsing or rendering
#: rules change so a regenerated artefact records what produced it.
GENERATOR_REVISION = 2

#: Explicit #204 product mapping: (transport const name, canonical reason).
#: The legacy wire spelling is read from the owner transport declaration,
#: never re-typed here; the canonical target is validated against the
#: parsed I7.20 set on every run.
BRIDGE_ALIASES: tuple[tuple[str, str], ...] = (
    ("AGENT_BRIDGE_TASK_SELECTION_REQUIRED", "TASK_SELECTION_REQUIRED"),
    ("AGENT_BRIDGE_SCOPE_SELECTION_REQUIRED", "TASK_SCOPE_INCOMPATIBLE"),
    ("AGENT_BRIDGE_SCOPE_AMBIGUOUS", "AMBIGUOUS_RESULT"),
    ("AGENT_BRIDGE_NOT_READY", "DEFERRED_CAPACITY"),
    ("AGENT_BRIDGE_STALE_FENCE", "STALE_STATE_FENCE"),
    ("AGENT_BRIDGE_FAILED_INTERNAL", "RUNTIME_FAILED"),
    ("AGENT_BRIDGE_SEMANTIC_RESOLUTION_UNAVAILABLE", "UNKNOWN_OUTCOME"),
)

#: Explicit #204 product mapping: (transport const name, closed I7.20
#: disposition, directive variant name). The disposition must be a member of
#: the parsed catalogue disposition vocabulary; the directive variant must
#: resolve through the exact ``AgentActivationDirectiveKind::as_str``
#: vocabulary owned by the transport file. The Kernel-owned no-result row
#: (``SEMANTIC_RESOLUTION_UNAVAILABLE``) keeps the retry directive, never
#: the failure capsule, so it stays distinct from ``FAILED_INTERNAL`` by
#: (reason, directive) even where the closed disposition is shared.
BRIDGE_DENIAL_PROJECTION: tuple[tuple[str, str, str], ...] = (
    ("AGENT_BRIDGE_TASK_SELECTION_REQUIRED", "INVALID_REQUEST", "CandidateRecoveryNoAutoSelection"),
    ("AGENT_BRIDGE_SCOPE_SELECTION_REQUIRED", "INVALID_REQUEST", "CandidateRecoveryNoAutoSelection"),
    ("AGENT_BRIDGE_SCOPE_AMBIGUOUS", "STALE_OR_CONFLICT", "CandidateRecoveryNoAutoSelection"),
    ("AGENT_BRIDGE_NOT_READY", "UNAVAILABLE_OR_CAPACITY", "RetryRequiresNewTicket"),
    ("AGENT_BRIDGE_STALE_FENCE", "STALE_OR_CONFLICT", "StaleFenceFailClosed"),
    ("AGENT_BRIDGE_FAILED_INTERNAL", "FAILED", "FailureCapsule"),
    ("AGENT_BRIDGE_SEMANTIC_RESOLUTION_UNAVAILABLE", "FAILED", "RetryRequiresNewTicket"),
)

NORMATIVE_GROUP = re.compile(r"^([a-z]+(?:/[a-z]+)?)\s*—\s*(.*)$")
CANONICAL_CODE = re.compile(r"\b[A-Z][A-Z0-9_]*\b")
DISPOSITION_CODE = re.compile(r"^[A-Z][A-Z0-9_]*$")
TRANSPORT_CONST = re.compile(r'^pub const (AGENT_BRIDGE_[A-Z0-9_]+): &str = "([^"]*)";$')
TRANSPORT_ARM = re.compile(r"^\s*Self::([A-Za-z0-9_]+) => (AGENT_BRIDGE_[A-Z0-9_]+),\s*$")
DIRECTIVE_ARM = re.compile(r'^\s*Self::([A-Za-z0-9_]+) => "([a-z0-9-]+)",\s*$')


class Refused(Exception):
    """The owner source does not say exactly what the projection must say."""


def normalized_bytes(path: Path) -> bytes:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise Refused(f"{path.relative_to(ROOT)} is missing: {error.strerror}") from error
    return raw.replace(b"\r\n", b"\n")


def source_digest(path: Path) -> str:
    return hashlib.sha256(normalized_bytes(path)).hexdigest()


def source_lines(path: Path) -> list[str]:
    try:
        text = normalized_bytes(path).decode("utf-8")
    except UnicodeDecodeError as error:
        raise Refused(f"{path.relative_to(ROOT)} is not valid UTF-8: {error}") from error
    return text.split("\n")


def catalogue_text_block(source: str, marker: str) -> str:
    _, found, after = source.partition(marker)
    if not found:
        raise Refused("I7.20 is missing its canonical agent-surface reason-code block")
    opening = after.find("```text")
    closing = after.find("```", opening + len("```text"))
    if opening < 0 or closing < 0:
        raise Refused("I7.20 canonical reason-code block is malformed")
    return after[opening + len("```text") : closing]


def parse_dispositions(source: str) -> list[str]:
    """Read the closed AgentResponseDisposition vocabulary from the catalogue."""
    marker = "AgentResponseDisposition (small closed control enum):"
    _, found, after = source.partition(marker)
    if not found:
        raise Refused("I7.20 is missing its closed disposition vocabulary block")
    values: list[str] = []
    for raw_line in after.splitlines()[1:]:
        line = raw_line.strip()
        if not line:
            continue
        for chunk in line.replace("|", " ").split():
            token = chunk.rstrip(";").rstrip(",")
            if not token:
                continue
            if DISPOSITION_CODE.match(token) is None:
                raise Refused(f"I7.20 disposition vocabulary has an unrecognized token {token!r}")
            values.append(token)
        if line.endswith(";"):
            break
    else:
        raise Refused("I7.20 disposition vocabulary block is unterminated")
    if not values:
        raise Refused("I7.20 disposition vocabulary block is empty")
    if len(set(values)) != len(values):
        raise Refused("I7.20 disposition vocabulary contains a duplicate value")
    return values


def parse_reason_groups(source: str) -> list[tuple[str, str]]:
    """Read the grouped canonical reason-code set from the catalogue."""
    block = catalogue_text_block(
        source, "Agent surfaces group reasons without changing their exact identity:"
    )
    expected: list[tuple[str, str]] = []
    group: str | None = None
    for raw_line in block.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = NORMATIVE_GROUP.match(line)
        if match:
            group, codes_text = match.groups()
        elif group is not None:
            codes_text = line
        else:
            raise Refused("I7.20 canonical reason-code block has an unrecognized line")
        codes = CANONICAL_CODE.findall(codes_text)
        if not codes:
            raise Refused("I7.20 canonical reason-code group is empty")
        expected.extend((group, code) for code in codes)
        if line.endswith(";") or line.endswith("."):
            group = None
    if group is not None or not expected:
        raise Refused("I7.20 canonical reason-code block is incomplete")
    return expected


def parse_transport_wires(lines: list[str]) -> dict[str, str]:
    """Resolve every as_str transport wire name from its owner declaration."""
    consts: dict[str, str] = {}
    for line in lines:
        match = TRANSPORT_CONST.match(line)
        if match is not None:
            name, wire = match.groups()
            if name in consts:
                raise Refused(f"transport constant {name!r} is declared more than once")
            consts[name] = wire
    start = next(
        (
            index
            for index, line in enumerate(lines)
            if "impl AgentBridgeActivationDenialCode" in line
        ),
        None,
    )
    if start is None:
        raise Refused("AgentBridgeActivationDenialCode owner block is absent")
    depth = 0
    opened = False
    wires: dict[str, str] = {}
    for line in lines[start:]:
        depth += line.count("{") - line.count("}")
        opened |= "{" in line
        match = TRANSPORT_ARM.match(line)
        if match is not None:
            variant, const = match.groups()
            if const not in consts:
                raise Refused(f"transport vocabulary {const!r} has no owner declaration")
            if variant in wires:
                raise Refused(f"transport vocabulary variant {variant!r} is mapped twice")
            wires[variant] = consts[const]
        if opened and depth == 0:
            break
    if not wires:
        raise Refused("AgentBridgeActivationDenialCode transport vocabulary is empty")
    return wires


def parse_directives(lines: list[str]) -> dict[str, str]:
    """Resolve every directive wire value from its owner declaration."""
    start = next(
        (
            index
            for index, line in enumerate(lines)
            if "impl AgentActivationDirectiveKind" in line
        ),
        None,
    )
    if start is None:
        raise Refused("AgentActivationDirectiveKind owner block is absent")
    depth = 0
    opened = False
    wires: dict[str, str] = {}
    for line in lines[start:]:
        depth += line.count("{") - line.count("}")
        opened |= "{" in line
        match = DIRECTIVE_ARM.match(line)
        if match is not None:
            variant, wire = match.groups()
            if variant in wires:
                raise Refused(f"directive vocabulary variant {variant!r} is mapped twice")
            wires[variant] = wire
        if opened and depth == 0:
            break
    if not wires:
        raise Refused("AgentActivationDirectiveKind vocabulary is empty")
    return wires


def resolve_aliases(
    catalogue: list[tuple[str, str]], transport_wires: dict[str, str]
) -> list[tuple[str, str]]:
    """Validate the pinned alias mapping against both owner sources."""
    catalogue_codes = {code for _, code in catalogue}
    const_wires: dict[str, str] = {}
    for line in source_lines(PROTOCOL_LIB):
        match = TRANSPORT_CONST.match(line)
        if match is not None:
            const_wires[match.group(1)] = match.group(2)
    seen_legacy: set[str] = set()
    resolved: list[tuple[str, str]] = []
    for const, canonical in BRIDGE_ALIASES:
        if const not in const_wires:
            raise Refused(f"bridge alias legacy {const!r} has no transport declaration")
        if canonical not in catalogue_codes:
            raise Refused(f"bridge alias target {canonical!r} is absent from the I7.20 set")
        if const_wires[const] in seen_legacy:
            raise Refused(f"bridge alias legacy wire {const_wires[const]!r} is pinned twice")
        seen_legacy.add(const_wires[const])
        resolved.append((const_wires[const], canonical))
    if seen_legacy != set(transport_wires.values()):
        raise Refused("bridge alias pins do not cover the exact transport vocabulary")
    return resolved


def resolve_denial_projection(
    aliases: list[tuple[str, str]],
    dispositions: list[str],
    transport_wires: dict[str, str],
    directives: dict[str, str],
) -> list[tuple[str, str, str, str]]:
    """Validate the pinned denial projection against every owner source."""
    const_wires: dict[str, str] = {}
    for line in source_lines(PROTOCOL_LIB):
        match = TRANSPORT_CONST.match(line)
        if match is not None:
            const_wires[match.group(1)] = match.group(2)
    canonical_by_legacy = dict(aliases)
    seen_legacy: set[str] = set()
    rows: list[tuple[str, str, str, str]] = []
    for const, disposition, directive_variant in BRIDGE_DENIAL_PROJECTION:
        if const not in const_wires:
            raise Refused(f"denial projection legacy {const!r} has no transport declaration")
        if disposition not in dispositions:
            raise Refused(
                f"denial projection disposition {disposition!r} is absent from the I7.20 set"
            )
        if directive_variant not in directives:
            raise Refused(
                f"denial projection directive {directive_variant!r} is absent from the owner vocabulary"
            )
        legacy = const_wires[const]
        if legacy in seen_legacy:
            raise Refused(f"denial projection legacy wire {legacy!r} is pinned twice")
        if legacy not in canonical_by_legacy:
            raise Refused(f"denial projection legacy wire {legacy!r} has no bridge alias pin")
        seen_legacy.add(legacy)
        rows.append((legacy, canonical_by_legacy[legacy], disposition, directives[directive_variant]))
    if seen_legacy != set(transport_wires.values()):
        raise Refused("denial projection pins do not cover the exact transport vocabulary")
    canonicals = [canonical for _, canonical, _, _ in rows]
    if len(canonicals) != len(set(canonicals)):
        raise Refused("denial projection canonical targets are not unique")
    return rows


def render_rs(
    catalogue: list[tuple[str, str]],
    aliases: list[tuple[str, str]],
    projection: list[tuple[str, str, str, str]],
    catalogue_digest: str,
    transport_digest: str,
    dispositions: list[str],
) -> str:
    disposition_list = "|".join(dispositions)
    disposition_digest = hashlib.sha256("|".join(dispositions).encode("utf-8")).hexdigest()
    lines = [
        "// Generated by `python scripts/generate_reason_codes.py` -- do not edit by hand.",
        f"// Canonical source: docs/architecture/I07-20-agent-facing-error-contract.md (sha256:{catalogue_digest}).",
        f"// Transport source: crates/foundation/eliot-protocol/src/lib.rs (sha256:{transport_digest}).",
        f"// I7.20 disposition vocabulary ({disposition_list}) sha256:{disposition_digest}.",
        f"// Generator revision: {GENERATOR_REVISION}.",
        "//! Canonical open I7.20 reason-code registry used by transport mapping and its",
        "//! generated human-readable projection.",
        "",
        "/// One canonical reason code and its stable I7.20 agent-facing group.",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
        "pub struct AgentReasonCode {",
        "    /// Stable catalogue group.",
        "    pub group: &'static str,",
        "    /// Exact additive reason-code token.",
        "    pub code: &'static str,",
        "}",
        "",
        "/// Current canonical I7.20 reason-code set, grouped as in the contract.",
        "///",
        "/// Emitted from the I7.20 catalogue by `python scripts/generate_reason_codes.py`;",
        "/// `docs/generated/reason-codes.md` is the human-readable projection of the same set.",
        "pub const AGENT_REASON_CODES: &[AgentReasonCode] = &[",
    ]
    for group, code in catalogue:
        lines.extend(
            [
                "    AgentReasonCode {",
                f'        group: "{group}",',
                f'        code: "{code}",',
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
            "",
            "/// Kernel↔bridge legacy transport names and their canonical I7.20 aliases.",
            "pub const BRIDGE_REASON_CODE_ALIASES: &[(&str, &str)] = &[",
        ]
    )
    for legacy, canonical in aliases:
        lines.append(f'    ("{legacy}", "{canonical}"),')
    lines.extend(
        [
            "];",
            "",
            "/// Projects a known legacy transport name through the designated bridge alias table.",
            "#[must_use]",
            "pub fn bridge_reason_code_alias(legacy_code: &str) -> Option<&'static str> {",
            "    BRIDGE_REASON_CODE_ALIASES",
            "        .iter()",
            "        .find_map(|(legacy, canonical)| (*legacy == legacy_code).then_some(*canonical))",
            "}",
            "",
            "/// Looks up one known registry code while leaving open-code decoding to the wire types.",
            "#[must_use]",
            "pub fn agent_reason_code(code: &str) -> Option<&'static AgentReasonCode> {",
            "    AGENT_REASON_CODES.iter().find(|entry| entry.code == code)",
            "}",
            "",
            "/// One generated bridge denial projection row: a legacy transport",
            "/// wire plus its exact I7.20 catalogue projection (canonical",
            "/// reason, closed disposition, typed directive wire value).",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub struct BridgeDenialProjection {",
            "    /// Legacy Kernel↔bridge transport wire name.",
            "    pub legacy: &'static str,",
            "    /// Exact canonical I7.20 catalogue reason code.",
            "    pub canonical: &'static str,",
            "    /// Closed I7.20 disposition vocabulary member.",
            "    pub disposition: &'static str,",
            "    /// Typed directive wire value (`AgentActivationDirectiveKind::as_str`).",
            "    pub directive: &'static str,",
            "}",
            "",
            "/// Bridge denial projection for every legacy transport wire,",
            "/// generated from the I7.20 catalogue disposition vocabulary plus",
            "/// the explicit #204 product pins. The Kernel-owned no-result row",
            "/// keeps the retry directive, never the failure capsule.",
            "pub const BRIDGE_DENIAL_PROJECTION: &[BridgeDenialProjection] = &[",
        ]
    )
    for legacy, canonical, disposition, directive in projection:
        lines.extend(
            [
                "    BridgeDenialProjection {",
                f'        legacy: "{legacy}",',
                f'        canonical: "{canonical}",',
                f'        disposition: "{disposition}",',
                f'        directive: "{directive}",',
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
            "",
            "/// Projects a legacy transport wire through the generated denial table.",
            "#[must_use]",
            "pub fn bridge_denial_projection(",
            "    legacy_code: &str,",
            ") -> Option<&'static BridgeDenialProjection> {",
            "    BRIDGE_DENIAL_PROJECTION",
            "        .iter()",
            "        .find(|entry| entry.legacy == legacy_code)",
            "}",
            "",
            "/// Projects a canonical catalogue reason to its bridge denial row.",
            "#[must_use]",
            "pub fn canonical_denial_projection(",
            "    canonical_code: &str,",
            ") -> Option<&'static BridgeDenialProjection> {",
            "    BRIDGE_DENIAL_PROJECTION",
            "        .iter()",
            "        .find(|entry| entry.canonical == canonical_code)",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def render_md(
    catalogue: list[tuple[str, str]],
    aliases: list[tuple[str, str]],
    projection: list[tuple[str, str, str, str]],
    dispositions: list[str],
) -> str:
    groups: dict[str, list[str]] = {}
    for group, code in catalogue:
        groups.setdefault(group, []).append(code)
    lines = [
        "# Agent-facing reason-code registry",
        "",
        "Generated by `python scripts/generate_reason_codes.py` from the",
        "canonical I7.20 catalogue",
        "(`docs/architecture/I07-20-agent-facing-error-contract.md`). Unknown",
        "additive reason-code strings remain valid and are relayed verbatim",
        "under their stable disposition.",
        "",
        "`CURRENT_DOCUMENTATION_PROJECTION`  ",
        "`DOCUMENTATION_ONLY`  ",
        "`ImplementationSupport = TARGET`  ",
        "`EvidenceExecutionStatus = NOT_EXECUTED`",
        "",
        "## Agent-facing dispositions (closed control enum)",
        "",
        "Bridges switch on the stable disposition and MAY specialise known",
        "reason codes; they may not require an exhaustive compile-time match",
        "over the entire additive reason registry.",
        "",
        ", ".join(f"`{disposition}`" for disposition in dispositions),
        "",
        "## Canonical reason codes",
        "",
    ]
    for group, group_codes in groups.items():
        lines.extend([f"### {group}", "", ", ".join(f"`{code}`" for code in group_codes), ""])
    lines.extend(
        [
            "## Bridge-only migration aliases",
            "",
            "This transport column is interpreted only at the bridge compatibility boundary.",
            "An identity mapping retains the same canonical spelling and does not create a second registry entry.",
            "The disposition and directive columns are the generated #204 denial",
            "projection: the closed I7.20 disposition plus the typed directive",
            "wire value for each legacy transport name. The Kernel-owned",
            "no-result row keeps the retry directive, never the failure capsule.",
            "",
            "| Legacy transport name | Canonical reason code | Disposition | Directive |",
            "| --- | --- | --- | --- |",
        ]
    )
    projection_by_legacy = {legacy: (disposition, directive) for legacy, _, disposition, directive in projection}
    for legacy, canonical in aliases:
        disposition, directive = projection_by_legacy[legacy]
        lines.append(f"| `{legacy}` | `{canonical}` | `{disposition}` | `{directive}` |")
    lines.extend([""])
    return "\n".join(lines)


def render_all() -> tuple[str, str]:
    catalogue_source = normalized_bytes(I720_CATALOGUE).decode("utf-8")
    dispositions = parse_dispositions(catalogue_source)
    catalogue = parse_reason_groups(catalogue_source)
    codes = [code for _, code in catalogue]
    if len(codes) != len(set(codes)):
        raise Refused("I7.20 canonical reason-code set contains a duplicate code")
    protocol_lines = source_lines(PROTOCOL_LIB)
    transport_wires = parse_transport_wires(protocol_lines)
    directives = parse_directives(protocol_lines)
    aliases = resolve_aliases(catalogue, transport_wires)
    projection = resolve_denial_projection(aliases, dispositions, transport_wires, directives)
    expected_rs = render_rs(
        catalogue,
        aliases,
        projection,
        source_digest(I720_CATALOGUE),
        source_digest(PROTOCOL_LIB),
        dispositions,
    )
    return expected_rs, render_md(catalogue, aliases, projection, dispositions)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if a checked-in projection differs from the owner sources",
    )
    args = parser.parse_args()
    try:
        expected_rs, expected_md = render_all()
    except (OSError, Refused) as error:
        parser.error(str(error))
    if args.check:
        stale = [
            str(path.relative_to(ROOT))
            for path, expected in ((RS_ARTIFACT, expected_rs), (MD_ARTIFACT, expected_md))
            if not path.is_file() or path.read_text(encoding="utf-8") != expected
        ]
        if stale:
            parser.error(f"stale generated projection: {', '.join(stale)}; regenerate it")
        return 0
    RS_ARTIFACT.write_text(expected_rs, encoding="utf-8", newline="\n")
    MD_ARTIFACT.write_text(expected_md, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
