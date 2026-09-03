#!/usr/bin/env python3
"""One-shot issue #530 Rust-comment traceability cleanup.

The helper derives its Rust denominator from ``git ls-files``. It changes only
comment spans, hardens the plain-comment handle validator, removes satisfied
exact legacy allowances, emits a receipt, and is deleted before publication.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tomllib
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from doc_code_conformance_lib.rust_comments import code_projection, comment_spans  # noqa: E402

ARCH_PATH = "docs/architecture/ELIOT_ARCHITECTURE.md"
IMPL_PATH = "docs/architecture/ELIOT_IMPLEMENTATION.md"
ANCHOR_PATH = "docs/architecture/A16-01-decision-anchors.md"
AUTH_PATH = "docs/ARCHITECTURE_CONTRACT.md"
CONFIG = ROOT / "config/doc-code-conformance.toml"
VALIDATOR = ROOT / "scripts/doc_code_conformance_lib/normative_references.py"
REPORT = ROOT / ".eliot/issue-530-traceability.json"
LEGACY_DOC_PROJECT = "eliot-architecture-docs-fa941135"

INVALID_I22 = re.compile(r"(?<![A-Za-z0-9])I2\.2(?![0-9])")
LEGACY_GRAPH = re.compile(r"(?<![A-Za-z0-9_.-])eliot-memory-os-[0-9a-f]{7,}(?:-[a-z0-9-]+)?")
OLD_DOC_DIGEST = re.compile(
    r"(?<![A-F0-9])(?:"
    r"58E71A2BDB10925C63D85A708ED768AEE8617BED0FB52EB044478EC20AB439D8"
    r"|C216FB7F6FDBC62D108C748BE6F61CA7EF9E5D24E5BB13AF2677C31A58460C0B"
    r")(?![A-F0-9])"
)
NORMATIVE_LINE = re.compile(
    r"(?P<path>(?:docs/(?:normative|architecture)/)?ELIOT_(?:ARCHITECTURE|IMPLEMENTATION)\.md)"
    r"(?::|,\s*lines?\s+|,\s*line\s+)~?\d+(?:\s*[-–]\s*\d+)?"
)
SOURCE_COORD = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:crates|bins)/[A-Za-z0-9_./-]+\.rs:"
    r"\d+(?:\s*[-–]\s*\d+)?"
)
COMPOUND_ARCH = re.compile(
    re.escape(LEGACY_DOC_PROJECT)
    + r"\.ELIOT_ARCHITECTURE\."
    + r"(?P<handle>A\d+(?:\.\d+)*|APPENDIX-[A-Z])"
    + r"(?:\.-[^`\s,;)\]]+)?"
)
COMPOUND_IMPL = re.compile(
    re.escape(LEGACY_DOC_PROJECT)
    + r"\.ELIOT_IMPLEMENTATION\."
    + r"(?P<handle>I\d+(?:\.\d+)*|APPENDIX-[A-Z])"
    + r"(?:\.-[^`\s,;)\]]+)?"
)
EMPTY_CODE_SPAN = re.compile(r"`\s*`")
DUP_I223 = re.compile(
    r"(?P<one>`?I2\.23`?)(?:\s*(?:,|/|;|\band\b|\bor\b)\s*`?I2\.23`?)+"
)
VERSION_DRAFT = re.compile(r"(?<![A-Za-z0-9])0\.29-draft(?![A-Za-z0-9])")
LINES_RANGE = re.compile(r"\blines?\s+~?\d+(?:\s*[-–]\s*\d+)?")
HEX_SHORT_PIN = re.compile(r"(?<![0-9a-f])2ecd3da(?![0-9a-f])")
ALLOW_BLOCK = re.compile(r"(?ms)^\[\[retired_references\.allow\]\]\r?\n.*?(?=^\[\[|\Z)")
LEADING_DOCS = re.compile(r"\A(?://!.*(?:\r?\n|\Z))+")

TARGET_HEADERS = {
    "crates/kernel/eliot-platform-windows/src/directory_publication.rs": f"""//! Handle-bound create-new directory publication for the Windows platform contour.
//!
//! Current documentation authority:
//! - `{ARCH_PATH}`: `A2.3`, `A12.1`, `A13.1`, `A13.6`, and `A13.9`.
//! - `{ANCHOR_PATH}`: `ARCH-MOD-02`, `ARCH-SEC-01`, `ARCH-RES-01`, and `ARCH-ORD-01`.
//! - `{IMPL_PATH}`: `I2.15`, `I2.23`, `I3.15`, and `I5.23`.
//! - precedence: `{AUTH_PATH}`.
//!
//! This module owns one independently understandable physical publication
//! capability: retained no-follow parent handles, create-new staging, identity
//! fences, handle-relative no-replace rename, and typed post-commit
//! reconciliation. It owns no installer, package-policy, process, secret,
//! canonical-state, or semantic-transition authority.
""",
    "crates/kernel/eliot-platform-windows/src/kernel_front_door_server.rs": f"""//! Kernel front-door server proof and authentication.
//!
//! Current documentation authority:
//! - `{ARCH_PATH}`: `A12.2` and `A12.3`.
//! - `{ANCHOR_PATH}`: `ARCH-AUTH-01`, `ARCH-SEC-01`, and `ARCH-SEC-02`.
//! - `{IMPL_PATH}`: `I2.23`, `I7.5`, and `I7.14`.
//! - precedence: `{AUTH_PATH}`.
//!
//! This module owns only OS-observed front-door proof and fail-closed
//! authentication mechanics. Listener creation, generic ACL construction,
//! expectation policy, process admission, handshake/session orchestration,
//! semantic results, Store authority, and Governor authority remain elsewhere.
""",
    "crates/kernel/eliot-platform-windows/src/named_pipe_peer_auth.rs": f"""//! Named-pipe client admission through live impersonation and OS-observed identity.
//!
//! Current documentation authority:
//! - `{ARCH_PATH}`: `A2.3`, `A12.2`, and `A12.3`.
//! - `{ANCHOR_PATH}`: `ARCH-AUTH-01`, `ARCH-SEC-01`, and `ARCH-SEC-02`.
//! - `{IMPL_PATH}`: `I2.23`, `I7.5`, `I7.14`, and `I15.2`.
//! - precedence: `{AUTH_PATH}`.
//!
//! This module owns live named-pipe peer authentication evidence only. It does
//! not own listener creation, wire sessions, semantic authority, canonical
//! writes, service lifecycle, or caller policy.
""",
    "crates/kernel/eliot-platform-windows/src/secret_store.rs": f"""//! Windows secret-storage closure.
//!
//! Current documentation authority:
//! - `{ARCH_PATH}`: `A2.3`, `A12.3`, and `A13.1`.
//! - `{ANCHOR_PATH}`: `ARCH-AUTH-01`, `ARCH-SEC-02`, and `ARCH-RES-01`.
//! - `{IMPL_PATH}`: `I2.23` and `I15.4`.
//! - precedence: `{AUTH_PATH}`.
//!
//! This module owns physical Windows secret persistence through Credential
//! Manager and DPAPI. Secret bytes remain opaque OS primitives; this module has
//! no semantic authority, provider ownership, path ownership, capability
//! minting, ambient retry/default authority, or canonical transition ownership.
""",
    "crates/kernel/eliot-platform-windows/src/tests.rs": f"""//! Test-oracle-only module for `eliot-platform-windows`.
//!
//! Current documentation authority:
//! - `{ARCH_PATH}`: `A2.3` and `A12.2`.
//! - `{IMPL_PATH}`: `I2.23`.
//! - precedence: `{AUTH_PATH}`.
//!
//! The test topology mirrors current production modules in `lib.rs` and sibling
//! modules. This file owns tests only; it has no production, semantic, or
//! authority ownership. No wildcard imports or new lint allowances are
//! introduced.
""",
}


class CleanupError(RuntimeError):
    pass


def git(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=ROOT, text=True, capture_output=True, check=False
    )
    if completed.returncode:
        raise CleanupError(
            f"git {' '.join(args)} failed ({completed.returncode}):\n"
            f"{completed.stdout}{completed.stderr}"
        )
    return completed.stdout


def tracked_rust_files() -> list[Path]:
    return [ROOT / item for item in git("ls-files", "--", "*.rs").splitlines() if item]


def read_allow_entries() -> dict[str, set[str]]:
    with CONFIG.open("rb") as stream:
        payload = tomllib.load(stream)
    retired = payload.get("retired_references")
    if not isinstance(retired, dict):
        return {}
    entries = retired.get("allow", [])
    if not isinstance(entries, list):
        raise CleanupError("retired_references.allow must be an array")
    result: dict[str, set[str]] = defaultdict(set)
    for entry in entries:
        if not isinstance(entry, dict):
            raise CleanupError("retired reference allowance must be a table")
        relative = str(entry.get("path", "")).replace("\\", "/")
        token = str(entry.get("token", ""))
        if relative and token:
            result[relative].add(token)
    return dict(result)


def normalize_paths(value: str) -> str:
    value = value.replace("docs/normative/ELIOT_ARCHITECTURE.md", ARCH_PATH)
    value = value.replace("docs/normative/ELIOT_IMPLEMENTATION.md", IMPL_PATH)
    value = COMPOUND_ARCH.sub(lambda m: f"{ARCH_PATH}:{m.group('handle')}", value)
    value = COMPOUND_IMPL.sub(lambda m: f"{IMPL_PATH}:{m.group('handle')}", value)
    value = re.sub(r"(?<![A-Za-z0-9_./-])ELIOT_ARCHITECTURE\.md", ARCH_PATH, value)
    value = re.sub(r"(?<![A-Za-z0-9_./-])ELIOT_IMPLEMENTATION\.md", IMPL_PATH, value)
    value = re.sub(
        rf"({re.escape(ARCH_PATH)}|{re.escape(IMPL_PATH)})\s*§\s*([AI]\d+(?:\.\d+)*)",
        r"\1:\2",
        value,
    )
    return value


def replacement_for_allowance(token: str) -> str:
    if token == LEGACY_DOC_PROJECT:
        return "current sharded normative documentation"
    if "ELIOT_ARCHITECTURE.md" in token:
        return ARCH_PATH
    if "ELIOT_IMPLEMENTATION.md" in token:
        return IMPL_PATH
    return ""


def clean_comment(value: str, allowed_tokens: set[str]) -> str:
    original = value
    value = normalize_paths(value)
    for token in sorted(allowed_tokens, key=len, reverse=True):
        if token in value:
            value = value.replace(token, replacement_for_allowance(token))
    value = OLD_DOC_DIGEST.sub("", value)
    value = LEGACY_GRAPH.sub("", value)
    value = HEX_SHORT_PIN.sub("", value)
    value = VERSION_DRAFT.sub("", value)
    value = NORMATIVE_LINE.sub(lambda m: normalize_paths(m.group("path")), value)
    value = SOURCE_COORD.sub("", value)
    value = LINES_RANGE.sub("", value)
    value = INVALID_I22.sub("I2.23", value)
    value = DUP_I223.sub(lambda m: m.group("one"), value)
    value = value.replace(LEGACY_DOC_PROJECT, "current sharded normative documentation")
    value = EMPTY_CODE_SPAN.sub("", value)
    value = re.sub(r",\s*,+", ", ", value)
    value = re.sub(r";\s*;+", "; ", value)
    value = re.sub(r"\(\s*[,;]\s*", "(", value)
    value = re.sub(r"\s+([,;:)])", r"\1", value)
    value = re.sub(r"([(:])\s*,\s*", r"\1 ", value)
    value = re.sub(r",\s*(?:and|or)\s*,", ", ", value)
    value = re.sub(r"[ \t]{3,}", "  ", value)
    if LEGACY_DOC_PROJECT in original and ARCH_PATH not in value and IMPL_PATH not in value:
        value = value.rstrip() + f" ({AUTH_PATH})"
    return value


def replace_target_header(relative: str, text: str) -> str:
    header = TARGET_HEADERS.get(relative)
    if header is None:
        return text
    match = LEADING_DOCS.match(text)
    if match is None:
        raise CleanupError(f"missing leading module docs: {relative}")
    return header.rstrip() + "\n\n" + text[match.end():].lstrip("\r\n")


def transform_rust(path: Path, allowed_tokens: set[str]) -> tuple[str, dict[str, Any]]:
    relative = path.relative_to(ROOT).as_posix()
    before = path.read_text(encoding="utf-8")
    projection = code_projection(before)
    pieces: list[str] = []
    cursor = 0
    changed_comments = 0
    for span in comment_spans(before):
        pieces.append(before[cursor:span.body_start])
        body = before[span.body_start:span.body_end]
        cleaned = clean_comment(body, allowed_tokens)
        changed_comments += int(cleaned != body)
        pieces.append(cleaned)
        cursor = span.body_end
    pieces.append(before[cursor:])
    after = replace_target_header(relative, "".join(pieces))
    if code_projection(after) != projection:
        raise CleanupError(f"non-comment Rust projection changed: {relative}")
    return after, {
        "path": relative,
        "changed_comments": changed_comments,
        "before_sha256": hashlib.sha256(before.encode()).hexdigest(),
        "after_sha256": hashlib.sha256(after.encode()).hexdigest(),
        "code_projection_sha256": hashlib.sha256(projection.encode()).hexdigest(),
    }


def patch_validator() -> None:
    value = VALIDATOR.read_text(encoding="utf-8")
    original = value
    import_line = "from docs_shards_lib import decision_anchors\n"
    import_added = import_line + "from doc_code_conformance_lib.rust_comments import iter_rust_comments\n"
    if "import iter_rust_comments" not in value:
        if import_line not in value:
            raise CleanupError("validator import insertion point changed")
        value = value.replace(import_line, import_added, 1)

    needle = (
        "        for match in DECISION_ANCHOR.finditer(value):\n"
        "            decision_candidates += 1\n"
    )
    block = (
        '        if path.suffix.casefold() == ".rs":\n'
        "            for comment, comment_offset in iter_rust_comments(value):\n"
        "                for selector, local_offset in selectors_in_span(comment):\n"
        "                    absolute = comment_offset + local_offset\n"
        "                    key = (absolute, selector)\n"
        "                    if key in seen_numeric:\n"
        "                        continue\n"
        "                    seen_numeric.add(key)\n"
        "                    numeric_candidates += 1\n"
        "                    problem = validate_selector(selector, handles)\n"
        "                    if problem:\n"
        "                        findings.append(\n"
        "                            core.Finding(\n"
        "                                DCC_NUMERIC, relative, _line(value, absolute), problem\n"
        "                            )\n"
        "                        )\n\n"
        "        for match in DECISION_ANCHOR.finditer(value):\n"
        "            decision_candidates += 1\n"
    )
    if "for comment, comment_offset in iter_rust_comments(value):" not in value:
        if needle not in value:
            raise CleanupError("validator scan insertion point changed")
        value = value.replace(needle, block, 1)

    clean_old = (
        '"//! `I2.23` `I1.1..I1.8` `I2.*` `B.2` `P.3` `ARCH-AUTH-01`\\n",'
    )
    clean_new = (
        '"//! `I2.23` `I1.1..I1.8` `I2.*` `B.2` `P.3` `ARCH-AUTH-01`; plain I2.23\\n",'
    )
    if clean_old in value:
        value = value.replace(clean_old, clean_new, 1)
    if 'metrics["numeric_reference_candidates"] != 3' in value:
        value = value.replace(
            'metrics["numeric_reference_candidates"] != 3',
            'metrics["numeric_reference_candidates"] != 4',
            1,
        )

    fixture = (
        '        sample.write_text("//! `I2.2`\\n", encoding="utf-8", newline="")\n'
        "        if DCC_NUMERIC not in _ids(reference_findings(root)[0]):\n"
        '            raise ReferenceAuditError("unknown exact numeric handle was accepted")\n\n'
    )
    extended = fixture + (
        '        sample.write_text("//! plain I2.2\\n", encoding="utf-8", newline="")\n'
        "        if DCC_NUMERIC not in _ids(reference_findings(root)[0]):\n"
        '            raise ReferenceAuditError("plain Rust-comment numeric handle was accepted")\n\n'
        "        sample.write_text(\n"
        "            'const VALUE: &str = \"I2.2\"; // plain I2.23\\n',\n"
        '            encoding="utf-8",\n'
        '            newline="",\n'
        "        )\n"
        "        if reference_findings(root)[0]:\n"
        "            raise ReferenceAuditError(\n"
        '                "Rust string content was misclassified as a normative reference"\n'
        "            )\n\n"
    )
    if "plain Rust-comment numeric handle was accepted" not in value:
        if fixture not in value:
            raise CleanupError("validator fixture insertion point changed")
        value = value.replace(fixture, extended, 1)
    value = value.replace(
        "NORMATIVE_REFERENCE_CONFORMANCE_SELF_TEST: PASS cases=8",
        "NORMATIVE_REFERENCE_CONFORMANCE_SELF_TEST: PASS cases=10",
    )
    if value == original:
        raise CleanupError("validator patch produced no change")
    compile(value, str(VALIDATOR), "exec")
    VALIDATOR.write_text(value, encoding="utf-8", newline="")


def remove_satisfied_allowances(sources: dict[str, str]) -> list[dict[str, str]]:
    value = CONFIG.read_text(encoding="utf-8")
    removed: list[dict[str, str]] = []

    def replacement(match: re.Match[str]) -> str:
        block = match.group(0)
        parsed = tomllib.loads(block)
        entries = parsed.get("retired_references", {}).get("allow", [])
        if len(entries) != 1 or not isinstance(entries[0], dict):
            raise CleanupError("allowance block did not decode to one entry")
        entry = entries[0]
        relative = str(entry.get("path", "")).replace("\\", "/")
        token = str(entry.get("token", ""))
        if relative.endswith(".rs") and relative in sources and token and token not in sources[relative]:
            removed.append({"path": relative, "token": token})
            return ""
        return block

    updated = ALLOW_BLOCK.sub(replacement, value)
    if removed:
        updated = re.sub(r"\n{3,}", "\n\n", updated).rstrip() + "\n"
        CONFIG.write_text(updated, encoding="utf-8", newline="")
    return removed


def residuals(paths: list[Path]) -> dict[str, list[str]]:
    patterns = {
        "I2.2": INVALID_I22,
        "legacy_project": re.compile(re.escape(LEGACY_DOC_PROJECT)),
        "legacy_graph": LEGACY_GRAPH,
        "old_digest": OLD_DOC_DIGEST,
        "docs_normative": re.compile(r"docs/normative/"),
        "normative_line": NORMATIVE_LINE,
        "source_coordinate": SOURCE_COORD,
        "short_pin": HEX_SHORT_PIN,
    }
    result: dict[str, list[str]] = {}
    for path in paths:
        text = path.read_text(encoding="utf-8")
        comments = "\n".join(
            text[span.body_start:span.body_end] for span in comment_spans(text)
        )
        hits = [name for name, pattern in patterns.items() if pattern.search(comments)]
        if hits:
            result[path.relative_to(ROOT).as_posix()] = hits
    return result


def main() -> int:
    allowances = read_allow_entries()
    reports: list[dict[str, Any]] = []
    sources: dict[str, str] = {}
    paths = tracked_rust_files()
    for path in paths:
        relative = path.relative_to(ROOT).as_posix()
        before = path.read_text(encoding="utf-8")
        after, report = transform_rust(path, allowances.get(relative, set()))
        if after != before:
            path.write_text(after, encoding="utf-8", newline="")
        sources[relative] = after
        reports.append(report)

    patch_validator()
    removed = remove_satisfied_allowances(sources)
    remaining = residuals(paths)
    if remaining:
        raise CleanupError(
            "obsolete Rust comment traceability remains:\n"
            + json.dumps(remaining, ensure_ascii=False, indent=2)
        )
    changed = [r for r in reports if r["before_sha256"] != r["after_sha256"]]
    if not changed:
        raise CleanupError("no Rust source comments changed")
    if not removed:
        raise CleanupError("no satisfied retired-reference allowances were removed")

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        json.dumps(
            {
                "schema_version": "eliot-issue-530-traceability-v2",
                "rust_files_scanned": len(paths),
                "rust_files_changed": len(changed),
                "removed_allowances": removed,
                "changed_rust": changed,
                "residuals": remaining,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
        newline="",
    )
    print(
        "TRACEABILITY_CLEANUP: PASS "
        f"scanned={len(paths)} changed={len(changed)} allowances_removed={len(removed)}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CleanupError as exc:
        print(f"TRACEABILITY_CLEANUP: FAIL {exc}", file=sys.stderr)
        raise SystemExit(1)
