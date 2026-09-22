#!/usr/bin/env python3
"""Final cross-package CueKind retirement oracle library (issue #835).

Static source denominator only: it rederives the current type/alias/import/
reexport/string-selector/source/wire/caller denominator over accepted source,
including release and future-admission code. It never executes callers,
never writes verdict files, and never substitutes file SHA-256 for the
scanner BLAKE3 fingerprints owned by the Rust oracles (those stay authoritative
through the executed `eliot-types`/`eliot-cue-contracts` proof reported in the
delivery). Digest binding here uses SHA-256 file digests as identity only.

Scan discipline (mirrors the Rust oracles, no third design):
- Rust files are lexically stripped (comments, strings, chars, lifetimes and
  raw strings become spaces, newlines kept) before any token test, so fixture
  strings, doc prose and comments can never count as definitions or uses.
- `declares_enum` uses whole-word boundaries on both sides of the `enum`
  keyword and the name, all Rust whitespace between them, `r#`-prefixed names
  count, `r#enum` never counts, and unparseable enum-adjacent syntax fails
  closed as a hit.
- Deliberately adversarial fixture strings live only under
  `scripts/testdata/cue-kind-retirement/` (JSON, never `.rs`), so the `.rs`
  scans below cannot see them. Unknown macros/syntax/coverage is reported as
  incomplete, never as zero.

Accepted interfaces reused (no invented process runner): unittest discovery,
`pathlib` anchoring (`ROOT` from file location), TOML via stdlib `tomllib`,
read-only `git diff --name-only` / `git status --porcelain` plumbing for the
exact-diff cases. No network, no cargo invocation, no writes.
"""

from __future__ import annotations

import json
import re
import subprocess
from hashlib import sha256
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "scripts/testdata/cue-kind-retirement"
MANIFEST = ROOT / "crates/eliot-types/tests/data/cue_kind_migration.toml"

TOKEN = r"(?<![A-Za-z0-9_])CueKind(?![A-Za-z0-9_])"
LEGACY_TOKEN = r"(?<![A-Za-z0-9_])(LegacyCueKindV1|LegacyContextCueKind|LegacyCueKindError)(?![A-Za-z0-9_])"
V1_SPELLINGS = (
    "file_path",
    "dir_path",
    "symbol",
    "error_signature",
    "command_pattern",
    "dependency",
    "api_surface",
    "task_class",
    "subsystem",
    "concept",
)
LEGACY_ONLY_SPELLINGS = ("path", "error", "command", "service", "problem")


def read_text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def file_sha256(relative: str) -> str:
    return sha256((ROOT / relative).read_bytes()).hexdigest()


SCAN_ROOTS = ("crates", "bins", "apps", "workers", "workspace")


def iter_rs_files() -> list[str]:
    out: list[str] = []
    for root in SCAN_ROOTS:
        candidate = ROOT / root
        if not candidate.is_dir():
            continue
        for path in sorted(candidate.rglob("*.rs")):
            out.append(path.relative_to(ROOT).as_posix())
    return out


def candidate_files(needle: str) -> list[str]:
    """Raw-substring prefilter (C speed); only these are stripped/scanned."""
    out: list[str] = []
    for rel in iter_rs_files():
        text = read_text(rel)
        if needle in text:
            out.append(rel)
    return out


def strip_rust(text: str) -> str:
    out: list[str] = []
    data = text.encode("utf-8")
    index = 0
    size = len(data)
    while index < size:
        rest = data[index:]
        if rest.startswith(b"//"):
            while index < size and data[index] != 0x0A:
                out.append(" ")
                index += 1
        elif rest.startswith(b"/*"):
            depth = 0
            while index < size:
                if data[index] == 0x0A:
                    out.append("\n")
                    index += 1
                elif data[index:].startswith(b"/*"):
                    depth += 1
                    out.append("  ")
                    index += 2
                elif data[index:].startswith(b"*/"):
                    depth -= 1
                    out.append("  ")
                    index += 2
                    if depth == 0:
                        break
                else:
                    out.append(" ")
                    index += 1
        elif rest.startswith(b'"'):
            out.append(" ")
            index += 1
            while index < size:
                cell = data[index]
                if cell == 0x22:
                    out.append(" ")
                    index += 1
                    break
                if cell == 0x5C:
                    out.append(" ")
                    index += 1
                    if index < size:
                        out.append("\n" if data[index] == 0x0A else " ")
                        index += 1
                elif cell == 0x0A:
                    out.append("\n")
                    index += 1
                else:
                    out.append(" ")
                    index += 1
        elif _raw_prefix_len(rest) is not None:
            hashes = _raw_prefix_len(rest)
            index += 1 + hashes
            closer = b'"' + b"#" * hashes
            while index < size and not data[index:].startswith(closer):
                out.append("\n" if data[index] == 0x0A else " ")
                index += 1
            out.append(" " * (len(closer)))
            index += len(closer)
        elif rest.startswith(b"'"):
            index = _consume_char_or_lifetime(data, index, out)
        else:
            out.append(chr(data[index]))
            index += 1
    return "".join(out)


def _raw_prefix_len(rest: bytes) -> int | None:
    if not rest.startswith(b"r"):
        return None
    hashes = 0
    while 1 + hashes < len(rest) and rest[1 + hashes] == 0x23:
        hashes += 1
    if 1 + hashes < len(rest) and rest[1 + hashes] == 0x22:
        return hashes
    return None


def _consume_char_or_lifetime(data: bytes, index: int, out: list[str]) -> int:
    size = len(data)
    out.append(" ")
    index += 1
    if index < size and data[index] == 0x5C:
        out.append(" ")
        index += 2
        if index < size and data[index] == 0x27:
            out.append(" ")
            index += 1
        return index
    while index < size and data[index] != 0x0A and data[index] != 0x27:
        if data[index] == 0x5C:
            out.append(" ")
            index += 2
        else:
            out.append(" " if data[index] != 0x3B else " ")
            index += 1
    if index < size and data[index] == 0x27:
        nxt = index + 1
        if nxt >= size or not (chr(data[nxt]).isalnum() or data[nxt] == 0x5F):
            out.append(" ")
            return nxt
    return index


def _is_ident(cell: str) -> bool:
    return cell.isalnum() or cell == "_"


def declares_enum(stripped: str, name: str) -> bool:
    data = stripped.encode("utf-8")
    index = 0
    while index + 4 <= len(data):
        if data[index : index + 4] == b"enum":
            prev_ok = index == 0 or not (
                chr(data[index - 1]).isalnum() or data[index - 1] == 0x5F
            )
            raw_enum = (
                index >= 2 and data[index - 2] == ord("r") and data[index - 1] == ord("#")
            )
            if prev_ok and not raw_enum:
                cursor = index + 4
                if cursor < len(data) and (
                    chr(data[cursor]).isalnum() or data[cursor] == 0x5F
                ):
                    index += 1
                    continue
                while cursor < len(data) and chr(data[cursor]).isspace():
                    cursor += 1
                if data[cursor : cursor + 2] == b"r#":
                    cursor += 2
                rest = data[cursor:].decode("utf-8", "replace")
                if rest.startswith(name):
                    after = cursor + len(name)
                    if after >= len(data) or not (
                        chr(data[after]).isalnum() or data[after] == 0x5F
                    ):
                        return True
                    index = after
                    continue
                if cursor >= len(data):
                    return True
                cell = chr(data[cursor])
                if not (cell.isalpha() or cell == "_"):
                    return True
        index += 1
    return False


def enum_declaration_files(name: str = "CueKind") -> list[str]:
    hits: list[str] = []
    for rel in candidate_files(name):
        if declares_enum(strip_rust(read_text(rel)), name):
            hits.append(rel)
    return hits


def versioned_kind_enums() -> dict[str, str]:
    """Every `enum *CueKind*` declaration site, name -> file (stripped code)."""
    found: dict[str, str] = {}
    pattern = re.compile(
        r"\benum\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*CueKind[A-Za-z0-9_]*|CueKind)\b"
    )
    for rel in candidate_files("CueKind"):
        for match in pattern.finditer(strip_rust(read_text(rel))):
            found.setdefault(match.group(1), rel)
    return found


def type_alias_hits() -> list[str]:
    """Files whose stripped code defines `type CueKind` (any right-hand side)."""
    pattern = re.compile(r"(?<![A-Za-z0-9_])type\s+(?:r#)?CueKind\b")
    return [rel for rel in candidate_files("CueKind") if pattern.search(strip_rust(read_text(rel)))]


def reexport_lines() -> list[tuple[str, str]]:
    """Stripped `pub use` lines naming bare `CueKind` (never `Legacy*`)."""
    out: list[tuple[str, str]] = []
    for rel in candidate_files("CueKind"):
        for line in strip_rust(read_text(rel)).splitlines():
            cell = line.strip()
            if cell.startswith("pub use") and re.search(TOKEN, cell):
                out.append((rel, cell))
    return out


def eliot_types_consumer_files() -> list[str]:
    """Files where a bare `CueKind` use resolves to `eliot_types` (not A-10)."""
    out: list[str] = []
    definition = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:enum|type)\s+(?:r#)?CueKind\b")
    use_pattern = re.compile(r"\beliot_types\s*::[^{};]*\bCueKind\b")
    for rel in candidate_files("CueKind"):
        stripped = strip_rust(read_text(rel))
        if not re.search(TOKEN, stripped):
            continue
        body = "\n".join(
            line for line in stripped.splitlines() if not definition.match(line)
        )
        if not re.search(TOKEN, body):
            continue
        in_types = rel.startswith("crates/eliot-types/")
        linked = bool(use_pattern.search(body))
        if not linked and in_types:
            for line in body.splitlines():
                cell = line.strip()
                if re.search(TOKEN, cell) and (
                    cell.startswith("use crate::") or cell.startswith("use super::")
                ):
                    linked = True
                    break
        if linked:
            out.append(rel)
    return out


def legacy_kind_consumer_files() -> list[str]:
    """Files naming an explicit legacy kind (`Legacy*`) in stripped code."""
    pattern = re.compile(LEGACY_TOKEN)
    return [rel for rel in candidate_files("Legacy") if pattern.search(strip_rust(read_text(rel)))]


def allow_deprecated_files() -> list[str]:
    return [
        rel
        for rel in candidate_files("allow(deprecated")
        if "allow(deprecated" in strip_rust(read_text(rel))
    ]


def permissive_lines(relative: str) -> list[str]:
    needles = ("untagged", "alias", "Other", "Unknown", "_ =>", "impl Default")
    return [
        line.strip()
        for line in strip_rust(read_text(relative)).splitlines()
        if any(needle in line for needle in needles)
    ]


def enum_region_text(relative: str, declaration: str, end_marker: str) -> str:
    """Stripped code from an enum declaration to its end marker.

    Mirrors the Rust oracle's region scoping (case 706/30): only the enum
    body counts for permissive-escape detection, never attributes above it
    or unrelated code below it.
    """
    stripped = strip_rust(read_text(relative))
    start = stripped.index(declaration)
    region = stripped[start:]
    end = region.index(end_marker)
    return region[:end]


def string_switch_owner_files() -> list[str]:
    """Non-test files matching on V1 spelling string literals as ownership logic.

    String literals are the evidence here, so this scan strips comments only
    (the full code stripper would erase them). The named legacy decoders that
    legitimately branch on historical spellings are returned, not hidden.
    """
    arm = re.compile(r'"(?:%s)"\s*=>' % "|".join(V1_SPELLINGS))
    out: list[str] = []
    for rel in candidate_files("match"):
        if "/tests/" in rel or "/testdata/" in rel or rel.endswith("_test.rs"):
            continue
        if arm.search(strip_comments_only(read_text(rel))):
            out.append(rel)
    return out


def manifest() -> dict:
    with (ROOT / MANIFEST.relative_to(ROOT)).open("rb") as handle:
        return tomllib.load(handle)


def manifest_type_rows() -> dict[str, dict]:
    return dict(manifest().get("type_row", {}))


def manifest_field_rows() -> dict[str, dict]:
    return dict(manifest().get("field_row", {}))


def strip_comments_only(text: str) -> str:
    """Remove line/block comments but keep string literals visible.

    Used only for string-content detection (spelling match arms), where the
    full code stripper would erase the evidence. Test/fixture prose never
    reaches this scanner with standing: callers restrict it to non-test
    source plus explicit adversarial fixtures.
    """
    out: list[str] = []
    data = text.encode("utf-8")
    index = 0
    size = len(data)
    in_string = False
    while index < size:
        rest = data[index:]
        if in_string:
            if rest.startswith(b"\\") and index + 1 < size:
                out.append(chr(data[index]))
                out.append(chr(data[index + 1]))
                index += 2
            elif rest.startswith(b'"'):
                in_string = False
                out.append('"')
                index += 1
            else:
                out.append(chr(data[index]))
                index += 1
        elif rest.startswith(b"//"):
            while index < size and data[index] != 0x0A:
                out.append(" ")
                index += 1
        elif rest.startswith(b"/*"):
            depth = 0
            while index < size:
                if data[index] == 0x0A:
                    out.append("\n")
                    index += 1
                elif data[index:].startswith(b"/*"):
                    depth += 1
                    out.append("  ")
                    index += 2
                elif data[index:].startswith(b"*/"):
                    depth = max(0, depth - 1)
                    out.append("  ")
                    index += 2
                    if depth == 0:
                        break
                else:
                    out.append(" ")
                    index += 1
        elif rest.startswith(b'"'):
            in_string = True
            out.append('"')
            index += 1
        else:
            out.append(chr(data[index]))
            index += 1
    return "".join(out)


def manifest_row_paths(prefix: str) -> list[str]:
    doc = manifest()
    return sorted(
        name[len(prefix) :].strip('"')
        for name in doc
        if name.startswith(prefix)
    )


def matched_lines(text: str, needle: str) -> list[str]:
    return [line for line in text.splitlines() if needle in line]


def git_diff_names() -> list[str]:
    diff = subprocess.run(
        ["git", "diff", "--name-only", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    names = {line.strip() for line in diff if line.strip()}
    for line in status:
        if line.startswith("??"):
            names.add(line[2:].strip())
    return sorted(names)


def load_fixture(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def main() -> int:
    findings: list[str] = []
    if enum_declaration_files() != [
        "crates/smart/eliot-cue-contracts/src/normalization.rs"
    ]:
        findings.append(f"current-enum-denominator: {enum_declaration_files()}")
    if type_alias_hits():
        findings.append(f"legacy-alias-present: {type_alias_hits()}")
    if eliot_types_consumer_files():
        findings.append(f"eliot-types-consumers: {eliot_types_consumer_files()}")
    for finding in findings:
        print(finding)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
