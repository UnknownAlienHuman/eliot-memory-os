"""Validate operational normative references against generated canonical indexes."""

from __future__ import annotations

import fnmatch
import json
import os
import re
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence

import doc_code_conformance_core as core
from doc_code_conformance_lib.rust_comments import iter_rust_comments
from docs_shards_lib import decision_anchors

SCHEMA = "eliot-normative-reference-conformance-v1"
CONFIG_PATH = Path("config/normative-reference-conformance.toml")
NUMERIC_SCHEMA = "eliot-handle-index-v1"
DECISION_SCHEMA = "eliot-decision-anchor-index-v1"
DCC_NUMERIC = "DCC-015"
DCC_DECISION = "DCC-016"
DCC_INDEX = "DCC-017"

CODE_SPAN = re.compile(r"`([^`\r\n]+)`")
PATH_HANDLE = re.compile(
    r"(?:ELIOT_(?:ARCHITECTURE|IMPLEMENTATION)\.md|"
    r"docs/architecture/[A-Za-z0-9_.\-/]+\.md)"
    r"[:#]((?:[AI]\d+(?:\.\d+)*|APPENDIX-[A-Z]))\b"
)
DECISION_ANCHOR = re.compile(
    r"(?<![A-Z0-9-])ARCH-[A-Z0-9]+(?:-[A-Z0-9]+)+(?![A-Z0-9-])"
)
EXACT_HANDLE = re.compile(r"(?:[AI]\d+(?:\.\d+)*|APPENDIX-[A-Z])")
RANGE_HANDLE = re.compile(
    r"((?:[AI]\d+(?:\.\d+)*|APPENDIX-[A-Z]))\.\."
    r"((?:[AI]\d+(?:\.\d+)*|APPENDIX-[A-Z]))"
)
WILDCARD_HANDLE = re.compile(r"([AI]\d+(?:\.\d+)*)\.\*")
SELECTOR_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:"
    r"(?:[AI]\d+(?:\.\d+)*|APPENDIX-[A-Z])\.\."
    r"(?:[AI]\d+(?:\.\d+)*|APPENDIX-[A-Z])"
    r"|[AI]\d+(?:\.\d+)*\.\*"
    r"|[AI]\d+(?:\.\d+)*"
    r"|APPENDIX-[A-Z]"
    r")(?![A-Za-z0-9_.-])"
)


class ReferenceAuditError(RuntimeError):
    def __init__(self, message: str, path: str | Path = CONFIG_PATH) -> None:
        super().__init__(message)
        self.path = Path(path).as_posix()


@dataclass(frozen=True)
class Config:
    numeric_index: str
    decision_anchor_index: str
    decision_anchor_source: str
    scan_roots: tuple[str, ...]
    extensions: frozenset[str]
    ignore_globs: tuple[str, ...]


def _norm(value: str) -> str:
    value = re.sub(r"/+", "/", value.strip().replace("\\", "/"))
    while value.startswith("./"):
        value = value[2:]
    if value in {"", "."}:
        return "."
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or re.match(r"^[A-Za-z]:", value):
        raise ReferenceAuditError(f"path must be repository-relative: {value!r}")
    return path.as_posix()


def _string_array(
    value: Any,
    field: str,
    *,
    allow_empty: bool = False,
    paths: bool = True,
) -> tuple[str, ...]:
    if value is None and allow_empty:
        return ()
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ReferenceAuditError(f"{field} must be an array of non-empty strings")
    normalized = tuple(
        _norm(item) if paths else item.strip().replace("\\", "/")
        for item in value
    )
    if not allow_empty and not normalized:
        raise ReferenceAuditError(f"{field} must not be empty")
    if len(normalized) != len(set(normalized)):
        raise ReferenceAuditError(f"{field} contains duplicates")
    return normalized


def load_config(root: Path, relative: Path = CONFIG_PATH) -> Config:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise ReferenceAuditError(
            "normative-reference config is missing or symlinked",
            relative,
        )
    try:
        with path.open("rb") as stream:
            value = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ReferenceAuditError(
            f"cannot read normative-reference config: {exc}",
            relative,
        ) from exc
    if value.get("schema_version") != SCHEMA:
        raise ReferenceAuditError(
            "unsupported normative-reference config schema",
            relative,
        )
    extensions = _string_array(
        value.get("extensions"),
        "extensions",
        paths=False,
    )
    if not all(item.startswith(".") for item in extensions):
        raise ReferenceAuditError("extensions must start with a dot", relative)
    return Config(
        numeric_index=_norm(str(value.get("numeric_index", ""))),
        decision_anchor_index=_norm(str(value.get("decision_anchor_index", ""))),
        decision_anchor_source=_norm(str(value.get("decision_anchor_source", ""))),
        scan_roots=_string_array(value.get("scan_roots"), "scan_roots"),
        extensions=frozenset(item.casefold() for item in extensions),
        ignore_globs=_string_array(
            value.get("ignore_globs", []),
            "ignore_globs",
            allow_empty=True,
            paths=False,
        ),
    )


def _read_json_object(
    root: Path,
    relative: str,
    schema: str,
    field: str,
) -> dict[str, Any]:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise ReferenceAuditError(f"{field} is missing or symlinked", relative)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReferenceAuditError(f"cannot read {field}: {exc}", relative) from exc
    if not isinstance(value, dict):
        raise ReferenceAuditError(f"{field} root must be an object", relative)
    if value.get("schema_version") != schema:
        raise ReferenceAuditError(f"unsupported {field} schema", relative)
    return value


def load_indexes(
    root: Path,
    config: Config,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    numeric = _read_json_object(
        root,
        config.numeric_index,
        NUMERIC_SCHEMA,
        "numeric handle index",
    )
    handles = numeric.get("handles")
    if not isinstance(handles, dict) or not handles:
        raise ReferenceAuditError(
            "numeric handle index has no handles",
            config.numeric_index,
        )
    if not all(
        isinstance(key, str)
        and EXACT_HANDLE.fullmatch(key)
        and isinstance(record, dict)
        for key, record in handles.items()
    ):
        raise ReferenceAuditError(
            "numeric handle index contains malformed entries",
            config.numeric_index,
        )

    decision = _read_json_object(
        root,
        config.decision_anchor_index,
        DECISION_SCHEMA,
        "Decision Anchor index",
    )
    anchors = decision.get("anchors")
    if not isinstance(anchors, dict) or not anchors:
        raise ReferenceAuditError(
            "Decision Anchor index has no anchors",
            config.decision_anchor_index,
        )
    if not all(
        isinstance(key, str)
        and DECISION_ANCHOR.fullmatch(key)
        and isinstance(record, dict)
        for key, record in anchors.items()
    ):
        raise ReferenceAuditError(
            "Decision Anchor index contains malformed entries",
            config.decision_anchor_index,
        )
    if config.decision_anchor_source != decision_anchors.SOURCE_PATH.as_posix():
        raise ReferenceAuditError(
            "configured Decision Anchor source differs from canonical A16.1",
            CONFIG_PATH,
        )
    try:
        expected_decision = decision_anchors.build_payload(root)
    except decision_anchors.DecisionAnchorError as exc:
        raise ReferenceAuditError(
            f"cannot rebuild Decision Anchor index: {exc}",
            config.decision_anchor_source,
        ) from exc
    if decision != expected_decision:
        raise ReferenceAuditError(
            "Decision Anchor index differs from canonical A16.1 projection",
            config.decision_anchor_index,
        )
    return handles, anchors


def _handle_key(handle: str) -> tuple[Any, ...]:
    appendix = re.fullmatch(r"APPENDIX-([A-Z])", handle)
    if appendix:
        return (2, ord(appendix.group(1)))
    match = re.fullmatch(r"([AI])(\d+(?:\.\d+)*)", handle)
    if not match:
        return (9, handle)
    return (
        0 if match.group(1) == "A" else 1,
        *(int(piece) for piece in match.group(2).split(".")),
    )


def validate_selector(
    selector: str,
    handles: dict[str, dict[str, Any]],
) -> str | None:
    if EXACT_HANDLE.fullmatch(selector):
        return None if selector in handles else f"unknown numeric handle: {selector}"
    wildcard = WILDCARD_HANDLE.fullmatch(selector)
    if wildcard:
        prefix = wildcard.group(1)
        if any(handle.startswith(prefix + ".") for handle in handles):
            return None
        return f"wildcard selector resolves to no indexed member: {selector}"
    range_match = RANGE_HANDLE.fullmatch(selector)
    if range_match:
        start, end = range_match.groups()
        missing = [candidate for candidate in (start, end) if candidate not in handles]
        if missing:
            return "range selector has unknown endpoint(s): " + ", ".join(missing)
        if start.startswith("APPENDIX-") or end.startswith("APPENDIX-"):
            return f"appendix ranges are unsupported: {selector}"
        if start[0] != end[0]:
            return f"cross-book range is prohibited: {selector}"
        if _handle_key(start) > _handle_key(end):
            return f"reversed handle range: {selector}"
        return None
    return f"unsupported numeric selector: {selector}"


def selectors_in_span(value: str) -> list[tuple[str, int]]:
    return [
        (match.group(0), match.start())
        for match in SELECTOR_CANDIDATE.finditer(value)
    ]


def _ignored(relative: str, globs: Sequence[str]) -> bool:
    return any(fnmatch.fnmatchcase(relative, pattern) for pattern in globs)


def selected_files(root: Path, config: Config) -> list[Path]:
    selected: dict[str, tuple[Path, str]] = {}
    for relative in config.scan_roots:
        path = root / relative
        if not path.exists() or path.is_symlink():
            raise ReferenceAuditError(
                "configured normative-reference scan root is missing or symlinked",
                relative,
            )
        candidates: Iterable[Path]
        if path.is_file():
            candidates = (path,)
        elif path.is_dir():
            candidates = path.rglob("*")
        else:
            raise ReferenceAuditError(
                "configured normative-reference scan root is neither file nor directory",
                relative,
            )
        for candidate in candidates:
            try:
                is_symlink = candidate.is_symlink()
            except OSError as exc:
                raise ReferenceAuditError(
                    f"cannot inspect configured surface: {exc}",
                    candidate.relative_to(root),
                ) from exc
            if is_symlink:
                raise ReferenceAuditError(
                    "symlinked configured normative-reference surface is prohibited",
                    candidate.relative_to(root),
                )
            if not candidate.is_file():
                continue
            if candidate.suffix.casefold() not in config.extensions:
                continue
            normalized = candidate.relative_to(root).as_posix()
            if _ignored(normalized, config.ignore_globs):
                continue
            previous = selected.get(normalized)
            if previous is not None and previous[1] != relative:
                raise ReferenceAuditError(
                    "configured normative-reference scan roots overlap on "
                    f"{normalized}: {previous[1]} and {relative}",
                    normalized,
                )
            selected[normalized] = (candidate, relative)
    return [selected[key][0] for key in sorted(selected)]


def _line(value: str, offset: int) -> int:
    return value.count("\n", 0, offset) + 1


def _numeric_finding(
    relative: str,
    value: str,
    selector: str,
    offset: int,
    handles: dict[str, dict[str, Any]],
) -> core.Finding | None:
    problem = validate_selector(selector, handles)
    if problem is None:
        return None
    return core.Finding(DCC_NUMERIC, relative, _line(value, offset), problem)


def reference_findings(
    root: Path,
    config_relative: Path = CONFIG_PATH,
) -> tuple[list[core.Finding], dict[str, int]]:
    try:
        config = load_config(root, config_relative)
        handles, anchors = load_indexes(root, config)
        surfaces = selected_files(root, config)
    except ReferenceAuditError as exc:
        return [core.Finding(DCC_INDEX, exc.path, 0, str(exc))], {
            "normative_reference_files": 0,
            "numeric_reference_candidates": 0,
            "decision_anchor_candidates": 0,
        }

    findings: list[core.Finding] = []
    numeric_candidates = 0
    decision_candidates = 0
    for path in surfaces:
        relative = path.relative_to(root).as_posix()
        try:
            value = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            findings.append(
                core.Finding(
                    DCC_INDEX,
                    relative,
                    0,
                    f"cannot read configured surface: {exc}",
                )
            )
            continue

        seen_numeric: set[tuple[int, str]] = set()

        def inspect_selector(selector: str, absolute: int) -> None:
            nonlocal numeric_candidates
            key = (absolute, selector)
            if key in seen_numeric:
                return
            seen_numeric.add(key)
            numeric_candidates += 1
            finding = _numeric_finding(
                relative,
                value,
                selector,
                absolute,
                handles,
            )
            if finding is not None:
                findings.append(finding)

        for span in CODE_SPAN.finditer(value):
            for selector, local_offset in selectors_in_span(span.group(1)):
                inspect_selector(selector, span.start(1) + local_offset)

        for match in PATH_HANDLE.finditer(value):
            inspect_selector(match.group(1), match.start(1))

        decision_regions: Iterable[tuple[str, int]]
        if path.suffix.casefold() == ".rs":
            rust_comments = tuple(iter_rust_comments(value))
            for comment, comment_offset in rust_comments:
                for selector, local_offset in selectors_in_span(comment):
                    inspect_selector(selector, comment_offset + local_offset)
            decision_regions = rust_comments
        else:
            decision_regions = ((value, 0),)

        for region, region_offset in decision_regions:
            for match in DECISION_ANCHOR.finditer(region):
                decision_candidates += 1
                anchor = match.group(0)
                if anchor not in anchors:
                    findings.append(
                        core.Finding(
                            DCC_DECISION,
                            relative,
                            _line(value, region_offset + match.start()),
                            f"unknown Decision Anchor: {anchor}",
                        )
                    )

    return sorted(set(findings)), {
        "normative_reference_files": len(surfaces),
        "numeric_reference_candidates": numeric_candidates,
        "decision_anchor_candidates": decision_candidates,
    }


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2) + "\n",
        encoding="utf-8",
        newline="",
    )


def _fixture(root: Path) -> None:
    (root / "config").mkdir(parents=True)
    (root / "src").mkdir()
    architecture_manifest = root / "docs/architecture/architecture/manifest.json"
    architecture_manifest.parent.mkdir(parents=True)
    architecture_manifest.write_text("{}\n", encoding="utf-8", newline="")
    pair = root / decision_anchors.PAIR_PATH
    pair.parent.mkdir(parents=True, exist_ok=True)
    pair.write_text(
        "\n".join(
            [
                f'schema_version = "{decision_anchors.PAIR_SCHEMA}"',
                'status = "accepted"',
                'pair_key = "sha256:' + "1" * 64 + '"',
                'architecture_sha256 = "' + "a" * 64 + '"',
                'architecture_path = "docs/architecture/architecture/manifest.json"',
                "",
            ]
        ),
        encoding="utf-8",
        newline="",
    )
    source = root / decision_anchors.SOURCE_PATH
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        "\n".join(
            [
                decision_anchors.SECTION_HEADING,
                "",
                "Navigation only.",
                "",
                "| ID | Class | Decision |",
                "|---|---|---|",
                "| `ARCH-AUTH-01` | Invariant | Authority is explicit |",
                "",
            ]
        ),
        encoding="utf-8",
        newline="",
    )
    source_data = source.read_bytes()
    handles: dict[str, dict[str, Any]] = {
        "A16.1": {
            "source": "architecture",
            "path": decision_anchors.SOURCE_PATH.as_posix(),
            "anchor": decision_anchors.SOURCE_ANCHOR,
            "source_anchor": decision_anchors.SOURCE_ANCHOR,
            "source_line": 100,
            "fragment_sha256": decision_anchors._sha256(source_data),
            "fragment_bytes": len(source_data),
        }
    }
    for handle in ("I1.1", "I1.8", "I2", "I2.1", "I2.23"):
        handles[handle] = {}
    _write_json(
        root / decision_anchors.HANDLE_INDEX_PATH,
        {
            "schema_version": NUMERIC_SCHEMA,
            "handles": handles,
            "headings": [],
        },
    )
    decision_anchors.write_generated(root)
    (root / CONFIG_PATH).write_text(
        "\n".join(
            [
                f'schema_version = "{SCHEMA}"',
                'numeric_index = "docs/architecture/handle-index.json"',
                'decision_anchor_index = "docs/architecture/decision-anchor-index.json"',
                'decision_anchor_source = "docs/architecture/A16-01-decision-anchors.md"',
                'scan_roots = ["src"]',
                'extensions = [".rs"]',
                "ignore_globs = []",
                "",
            ]
        ),
        encoding="utf-8",
        newline="",
    )


def _ids(findings: Sequence[core.Finding]) -> set[str]:
    return {finding.finding_id for finding in findings}


def _write_config(root: Path, scan_roots: Sequence[str]) -> None:
    (root / CONFIG_PATH).write_text(
        "\n".join(
            [
                f'schema_version = "{SCHEMA}"',
                'numeric_index = "docs/architecture/handle-index.json"',
                'decision_anchor_index = "docs/architecture/decision-anchor-index.json"',
                'decision_anchor_source = "docs/architecture/A16-01-decision-anchors.md"',
                "scan_roots = ["
                + ", ".join(json.dumps(item) for item in scan_roots)
                + "]",
                'extensions = [".rs"]',
                "ignore_globs = []",
                "",
            ]
        ),
        encoding="utf-8",
        newline="",
    )


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        _fixture(root)
        sample = root / "src/sample.rs"
        sample.write_text(
            "//! `I2.23` `I1.1..I1.8` `I2.*` `B.2` `P.3` "
            "`ARCH-AUTH-01`; plain I2.23\n",
            encoding="utf-8",
            newline="",
        )
        findings, metrics = reference_findings(root)
        if findings:
            raise ReferenceAuditError(
                f"clean normative-reference fixture failed: {findings}"
            )
        if metrics["numeric_reference_candidates"] != 4:
            raise ReferenceAuditError("numeric selector fixture count changed")

        sample.write_text("//! `I2.2`\n", encoding="utf-8", newline="")
        if DCC_NUMERIC not in _ids(reference_findings(root)[0]):
            raise ReferenceAuditError("unknown exact numeric handle was accepted")

        sample.write_text("//! plain I2.2\n", encoding="utf-8", newline="")
        if DCC_NUMERIC not in _ids(reference_findings(root)[0]):
            raise ReferenceAuditError(
                "plain Rust-comment numeric handle was accepted"
            )

        sample.write_text(
            'const VALUE: &str = "I2.2"; // plain I2.23\n',
            encoding="utf-8",
            newline="",
        )
        if reference_findings(root)[0]:
            raise ReferenceAuditError(
                "Rust string content was misclassified as a normative reference"
            )

        sample.write_text("//! `I1.1..I1.9`\n", encoding="utf-8", newline="")
        if DCC_NUMERIC not in _ids(reference_findings(root)[0]):
            raise ReferenceAuditError("missing range endpoint was accepted")

        sample.write_text("//! `I3.*`\n", encoding="utf-8", newline="")
        if DCC_NUMERIC not in _ids(reference_findings(root)[0]):
            raise ReferenceAuditError("empty wildcard selector was accepted")

        sample.write_text("//! `ARCH-FAKE-99`\n", encoding="utf-8", newline="")
        if DCC_DECISION not in _ids(reference_findings(root)[0]):
            raise ReferenceAuditError("unknown Decision Anchor was accepted")

        numeric_path = root / "docs/architecture/handle-index.json"
        clean_numeric = numeric_path.read_text(encoding="utf-8")
        numeric_path.write_text(
            '{"schema_version":"wrong","handles":{}}\n',
            encoding="utf-8",
        )
        if DCC_INDEX not in _ids(reference_findings(root)[0]):
            raise ReferenceAuditError(
                "wrong numeric-index schema did not fail closed"
            )
        numeric_path.write_text(clean_numeric, encoding="utf-8", newline="")

        decision_path = root / decision_anchors.JSON_PATH
        clean_decision = decision_path.read_text(encoding="utf-8")
        value = json.loads(clean_decision)
        value["anchors"]["ARCH-AUTH-01"]["decision"] = "Drifted"
        _write_json(decision_path, value)
        if DCC_INDEX not in _ids(reference_findings(root)[0]):
            raise ReferenceAuditError(
                "Decision Anchor table/index drift was accepted"
            )
        decision_path.write_text(clean_decision, encoding="utf-8", newline="")

        _write_config(root, ("src", "src/sample.rs"))
        if DCC_INDEX not in _ids(reference_findings(root)[0]):
            raise ReferenceAuditError("overlapping scan roots were accepted")
        _write_config(root, ("src",))

        if hasattr(os, "symlink"):
            target = root / "src/target.txt"
            surface = root / "src/symlink.rs"
            target.write_text("target\n", encoding="utf-8")
            try:
                surface.symlink_to(target.name)
            except OSError:
                pass
            else:
                if DCC_INDEX not in _ids(reference_findings(root)[0]):
                    raise ReferenceAuditError(
                        "symlinked configured surface was accepted"
                    )

    print("NORMATIVE_REFERENCE_CONFORMANCE_SELF_TEST: PASS cases=10")
