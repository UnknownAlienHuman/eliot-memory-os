#!/usr/bin/env python3
"""One-shot issue #530 source-comment and validator cleanup.

This file is removed before the final candidate commit is created.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from collections import defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from doc_code_conformance_lib.rust_comments import (  # noqa: E402
    code_projection,
    comment_spans,
)

LEGACY_DOC_PROJECT = "eliot-architecture-docs-fa941135"
ARCH_PATH = "docs/architecture/ELIOT_ARCHITECTURE.md"
IMPL_PATH = "docs/architecture/ELIOT_IMPLEMENTATION.md"
AUTH_PATH = "docs/ARCHITECTURE_CONTRACT.md"
INVALID_I22 = re.compile(r"(?<![A-Za-z0-9])I2\.2(?![0-9])")
LEGACY_GRAPH = re.compile(
    r"(?<![A-Za-z0-9_.-])eliot-memory-os-[0-9a-f]{7,}(?:-[a-z0-9-]+)?"
)
NORMATIVE_LINE = re.compile(
    r"(?P<path>(?:docs/(?:normative|architecture)/)?"
    r"ELIOT_(?:ARCHITECTURE|IMPLEMENTATION)\.md)"
    r"(?::|,\s*lines?\s+|,\s*line\s+)"
    r"~?\d+(?:\s*[-–]\s*\d+)?"
)
SOURCE_COORD = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:crates|bins)/[A-Za-z0-9_./-]+\.rs:"
    r"\d+(?:\s*[-–]\s*\d+)?"
)
OLD_DOC_DIGEST = re.compile(
    r"(?<![A-F0-9])(?:"
    r"58E71A2BDB10925C63D85A708ED768AEE8617BED0FB52EB044478EC20AB439D8"
    r"|C216FB7F6FDBC62D108C748BE6F61CA7EF9E5D24E5BB13AF2677C31A58460C0B"
    r")(?![A-F0-9])"
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
    r"(?P<one>`?I2\.23`?)"
    r"(?:\s*(?:,|/|;|\band\b|\bor\b)\s*`?I2\.23`?)+"
)
VERSION_DRAFT = re.compile(r"(?<![A-Za-z0-9])0\.29-draft(?![A-Za-z0-9])")
LINES_RANGE = re.compile(r"\blines?\s+~?\d+(?:\s*[-–]\s*\d+)?")
HEX_SHORT_PIN = re.compile(r"(?<![0-9a-f])(?:2ecd3da)(?![0-9a-f])")
PATHS_CONFIG = Path("config/doc-code-conformance.toml")
VALIDATOR = Path("scripts/doc_code_conformance_lib/normative_references.py")
REPORT = Path(".eliot/normative-traceability-cleanup.json")


class CleanupError(RuntimeError):
    pass


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        list(args),
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if check and completed.returncode != 0:
        raise CleanupError(
            f"command failed ({completed.returncode}): {' '.join(args)}\n"
            f"{completed.stdout}"
        )
    return completed


def tracked_rust_files() -> list[Path]:
    raw = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.rs"],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout
    return [
        REPO_ROOT / item.decode("utf-8")
        for item in raw.split(b"\0")
        if item
    ]


def read_allow_entries() -> dict[str, set[str]]:
    path = REPO_ROOT / PATHS_CONFIG
    with path.open("rb") as stream:
        payload = tomllib.load(stream)
    retired = payload.get("retired_references")
    if not isinstance(retired, dict):
        return {}
    entries = retired.get("allow", [])
    if not isinstance(entries, list):
        raise CleanupError("retired_references.allow must be an array")
    by_path: dict[str, set[str]] = defaultdict(set)
    for entry in entries:
        if not isinstance(entry, dict):
            raise CleanupError("retired reference allowance must be a table")
        source = str(entry.get("path", "")).replace("\\", "/")
        token = str(entry.get("token", ""))
        if source and token:
            by_path[source].add(token)
    return dict(by_path)


def normalize_current_paths(value: str) -> str:
    value = value.replace(
        "docs/normative/ELIOT_ARCHITECTURE.md",
        ARCH_PATH,
    )
    value = value.replace(
        "docs/normative/ELIOT_IMPLEMENTATION.md",
        IMPL_PATH,
    )
    value = COMPOUND_ARCH.sub(
        lambda match: f"{ARCH_PATH}:{match.group('handle')}",
        value,
    )
    value = COMPOUND_IMPL.sub(
        lambda match: f"{IMPL_PATH}:{match.group('handle')}",
        value,
    )
    value = re.sub(
        r"(?<![A-Za-z0-9_./-])ELIOT_ARCHITECTURE\.md",
        ARCH_PATH,
        value,
    )
    value = re.sub(
        r"(?<![A-Za-z0-9_./-])ELIOT_IMPLEMENTATION\.md",
        IMPL_PATH,
        value,
    )
    value = re.sub(
        rf"({re.escape(ARCH_PATH)}|{re.escape(IMPL_PATH)})\s*§\s*"
        r"([AI]\d+(?:\.\d+)*)",
        r"\1:\2",
        value,
    )
    return value


def replacement_for_allowed_token(token: str) -> str:
    if token == LEGACY_DOC_PROJECT:
        return "current sharded normative documentation"
    if token == "docs/normative/ELIOT_ARCHITECTURE.md":
        return ARCH_PATH
    if token == "docs/normative/ELIOT_IMPLEMENTATION.md":
        return IMPL_PATH
    if token.startswith("ELIOT_ARCHITECTURE.md:"):
        return ARCH_PATH
    if token.startswith("ELIOT_IMPLEMENTATION.md:"):
        return IMPL_PATH
    if token.startswith("docs/architecture/ELIOT_ARCHITECTURE.md:"):
        return ARCH_PATH
    if token.startswith("docs/architecture/ELIOT_IMPLEMENTATION.md:"):
        return IMPL_PATH
    return ""


def clean_comment(value: str, allowed_tokens: set[str]) -> str:
    original = value
    value = normalize_current_paths(value)

    for token in sorted(allowed_tokens, key=len, reverse=True):
        if token in value:
            value = value.replace(token, replacement_for_allowed_token(token))

    value = OLD_DOC_DIGEST.sub("", value)
    value = LEGACY_GRAPH.sub("", value)
    value = HEX_SHORT_PIN.sub("", value)
    value = VERSION_DRAFT.sub("", value)
    value = NORMATIVE_LINE.sub(
        lambda match: normalize_current_paths(match.group("path")),
        value,
    )
    value = SOURCE_COORD.sub("", value)
    value = LINES_RANGE.sub("", value)

    # I2.23 is the accepted capability-family topology/crate-extraction section.
    value = INVALID_I22.sub("I2.23", value)
    value = DUP_I223.sub(lambda match: match.group("one"), value)

    value = value.replace(
        LEGACY_DOC_PROJECT,
        "current sharded normative documentation",
    )
    value = EMPTY_CODE_SPAN.sub("", value)

    # Repair punctuation left by removing stale evidence pins.
    value = re.sub(r",\s*,+", ", ", value)
    value = re.sub(r";\s*;+", "; ", value)
    value = re.sub(r"\(\s*[,;]\s*", "(", value)
    value = re.sub(r"\s+([,;:)])", r"\1", value)
    value = re.sub(r"([(:])\s*,\s*", r"\1 ", value)
    value = re.sub(r",\s*(?:and|or)\s*,", ", ", value)
    value = re.sub(r"[ \t]{3,}", "  ", value)

    if (
        LEGACY_DOC_PROJECT in original
        and ARCH_PATH not in value
        and IMPL_PATH not in value
    ):
        value = value.rstrip() + f" ({AUTH_PATH})"

    return value


def transform_rust(path: Path, tokens: set[str]) -> tuple[str, dict[str, Any]]:
    original = path.read_text(encoding="utf-8")
    before_projection = code_projection(original)
    spans = comment_spans(original)
    parts: list[str] = []
    cursor = 0
    changed_comments = 0
    for span in spans:
        parts.append(original[cursor : span.body_start])
        body = original[span.body_start : span.body_end]
        cleaned = clean_comment(body, tokens)
        if cleaned != body:
            changed_comments += 1
        parts.append(cleaned)
        cursor = span.body_end
    parts.append(original[cursor:])
    updated = "".join(parts)
    after_projection = code_projection(updated)
    if before_projection != after_projection:
        raise CleanupError(
            f"non-comment Rust projection changed: {path.relative_to(REPO_ROOT)}"
        )
    return updated, {
        "path": path.relative_to(REPO_ROOT).as_posix(),
        "changed_comments": changed_comments,
        "before_i2_2": len(INVALID_I22.findall(original)),
        "after_i2_2": len(INVALID_I22.findall(updated)),
        "before_legacy_project": original.count(LEGACY_DOC_PROJECT),
        "after_legacy_project": updated.count(LEGACY_DOC_PROJECT),
        "before_sha256": hashlib.sha256(original.encode()).hexdigest(),
        "after_sha256": hashlib.sha256(updated.encode()).hexdigest(),
        "code_projection_sha256": hashlib.sha256(
            before_projection.encode()
        ).hexdigest(),
    }


def patch_validator() -> None:
    path = REPO_ROOT / VALIDATOR
    value = path.read_text(encoding="utf-8")
    original = value

    import_needle = "from docs_shards_lib import decision_anchors\n"
    import_replacement = (
        import_needle
        + "from doc_code_conformance_lib.rust_comments import iter_rust_comments\n"
    )
    if "from doc_code_conformance_lib.rust_comments import iter_rust_comments" not in value:
        if import_needle not in value:
            raise CleanupError("validator import insertion point changed")
        value = value.replace(import_needle, import_replacement, 1)

    scan_needle = (
        "        for match in DECISION_ANCHOR.finditer(value):\n"
        "            decision_candidates += 1\n"
    )
    scan_block = (
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
        "                                DCC_NUMERIC,\n"
        "                                relative,\n"
        "                                _line(value, absolute),\n"
        "                                problem,\n"
        "                            )\n"
        "                        )\n"
        "\n"
        "        for match in DECISION_ANCHOR.finditer(value):\n"
        "            decision_candidates += 1\n"
    )
    if "for comment, comment_offset in iter_rust_comments(value):" not in value:
        if scan_needle not in value:
            raise CleanupError("validator scan insertion point changed")
        value = value.replace(scan_needle, scan_block, 1)

    clean_sample_old = (
        '"//! `I2.23` `I1.1..I1.8` `I2.*` `B.2` `P.3` '
        '`ARCH-AUTH-01`\\n",'
    )
    clean_sample_new = (
        '"//! `I2.23` `I1.1..I1.8` `I2.*` `B.2` `P.3` '
        '`ARCH-AUTH-01`; plain I2.23\\n",'
    )
    if clean_sample_old in value:
        value = value.replace(clean_sample_old, clean_sample_new, 1)
    elif "plain I2.23" not in value:
        raise CleanupError("validator clean fixture changed")

    if 'metrics["numeric_reference_candidates"] != 3' in value:
        value = value.replace(
            'metrics["numeric_reference_candidates"] != 3',
            'metrics["numeric_reference_candidates"] != 4',
            1,
        )

    plain_fixture_needle = (
        '        sample.write_text("//! `I2.2`\\n", encoding="utf-8", newline="")\n'
        "        if DCC_NUMERIC not in _ids(reference_findings(root)[0]):\n"
        '            raise ReferenceAuditError("unknown exact numeric handle was accepted")\n'
        "\n"
    )
    plain_fixture_replacement = plain_fixture_needle + (
        '        sample.write_text("//! plain I2.2\\n", encoding="utf-8", newline="")\n'
        "        if DCC_NUMERIC not in _ids(reference_findings(root)[0]):\n"
        '            raise ReferenceAuditError("plain Rust-comment numeric handle was accepted")\n'
        "\n"
        "        sample.write_text(\n"
        "            'const VALUE: &str = \"I2.2\"; // plain I2.23\\n',\n"
        '            encoding="utf-8",\n'
        '            newline="",\n'
        "        )\n"
        "        if reference_findings(root)[0]:\n"
        "            raise ReferenceAuditError(\n"
        '                "Rust string content was misclassified as a normative reference"\n'
        "            )\n"
        "\n"
    )
    if "plain Rust-comment numeric handle was accepted" not in value:
        if plain_fixture_needle not in value:
            raise CleanupError("validator invalid fixture insertion point changed")
        value = value.replace(
            plain_fixture_needle,
            plain_fixture_replacement,
            1,
        )

    value = value.replace(
        "NORMATIVE_REFERENCE_CONFORMANCE_SELF_TEST: PASS cases=8",
        "NORMATIVE_REFERENCE_CONFORMANCE_SELF_TEST: PASS cases=10",
    )

    if value == original:
        raise CleanupError("validator patch produced no change")
    compile(value, str(path), "exec")
    path.write_text(value, encoding="utf-8", newline="")


def remove_satisfied_allowances(source_by_path: dict[str, str]) -> list[dict[str, str]]:
    path = REPO_ROOT / PATHS_CONFIG
    value = path.read_text(encoding="utf-8")
    pattern = re.compile(
        r"(?ms)^\[\[retired_references\.allow\]\]\r?\n"
        r".*?(?=^\[\[|\Z)"
    )
    removed: list[dict[str, str]] = []

    def replacement(match: re.Match[str]) -> str:
        block = match.group(0)
        try:
            parsed = tomllib.loads(block)
        except tomllib.TOMLDecodeError as exc:
            raise CleanupError(f"cannot parse allowance block: {exc}") from exc
        retired = parsed.get("retired_references", {})
        entries = retired.get("allow", []) if isinstance(retired, dict) else []
        if len(entries) != 1 or not isinstance(entries[0], dict):
            raise CleanupError("allowance block did not decode to one entry")
        entry = entries[0]
        source = str(entry.get("path", "")).replace("\\", "/")
        token = str(entry.get("token", ""))
        if not source.endswith(".rs") or source not in source_by_path:
            return block
        if token and token not in source_by_path[source]:
            removed.append({"path": source, "token": token})
            return ""
        return block

    updated = pattern.sub(replacement, value)
    if removed:
        updated = re.sub(r"\n{3,}", "\n\n", updated).rstrip() + "\n"
        path.write_text(updated, encoding="utf-8", newline="")
    return removed


def count_comment_matches(path: Path) -> dict[str, int]:
    value = path.read_text(encoding="utf-8")
    comment_text = "\n".join(
        value[span.body_start : span.body_end]
        for span in comment_spans(value)
    )
    return {
        "i2_2": len(INVALID_I22.findall(comment_text)),
        "legacy_project": comment_text.count(LEGACY_DOC_PROJECT),
        "legacy_graph": len(LEGACY_GRAPH.findall(comment_text)),
        "old_doc_digest": len(OLD_DOC_DIGEST.findall(comment_text)),
        "normative_line": len(NORMATIVE_LINE.findall(comment_text)),
        "docs_normative": comment_text.count("docs/normative/"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    args = parser.parse_args()
    root = args.root.resolve()
    if root != REPO_ROOT.resolve():
        raise CleanupError(f"unexpected root: {root}")

    allowances = read_allow_entries()
    reports: list[dict[str, Any]] = []
    updated_sources: dict[str, str] = {}
    for path in tracked_rust_files():
        relative = path.relative_to(REPO_ROOT).as_posix()
        before = path.read_text(encoding="utf-8")
        updated, report = transform_rust(path, allowances.get(relative, set()))
        reports.append(report)
        if updated != before:
            path.write_text(updated, encoding="utf-8", newline="")
        updated_sources[relative] = updated

    patch_validator()
    removed = remove_satisfied_allowances(updated_sources)

    residuals: dict[str, dict[str, int]] = {}
    for path in tracked_rust_files():
        counts = count_comment_matches(path)
        if any(counts.values()):
            residuals[path.relative_to(REPO_ROOT).as_posix()] = counts
    if residuals:
        raise CleanupError(
            "obsolete Rust comment traceability remains:\n"
            + json.dumps(residuals, ensure_ascii=False, indent=2)
        )

    modified = [
        report
        for report in reports
        if report["before_sha256"] != report["after_sha256"]
    ]
    if not modified:
        raise CleanupError("no Rust source comments changed")
    if not removed:
        raise CleanupError("no satisfied retired-reference allowances were removed")

    report_path = REPO_ROOT / REPORT
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(
            {
                "schema_version": "eliot-normative-traceability-cleanup-v1",
                "rust_files_scanned": len(reports),
                "rust_files_changed": len(modified),
                "comment_changes": sum(
                    item["changed_comments"] for item in modified
                ),
                "removed_allowances": removed,
                "modified_rust": modified,
                "residuals": residuals,
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
        f"scanned={len(reports)} changed={len(modified)} "
        f"allowances_removed={len(removed)}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CleanupError as exc:
        print(f"TRACEABILITY_CLEANUP: FAIL {exc}", file=sys.stderr)
        raise SystemExit(1)
