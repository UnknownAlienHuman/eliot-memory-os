"""Generated Decision Anchor projection for the sharded normative books."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
import tomllib
from collections import OrderedDict
from pathlib import Path
from typing import Any, Mapping

SCHEMA = "eliot-decision-anchor-index-v1"
PAIR_SCHEMA = "eliot-normative-pair-v2-sharded"
HANDLE_SCHEMA = "eliot-handle-index-v1"
SOURCE_PATH = Path("docs/architecture/A16-01-decision-anchors.md")
HANDLE_INDEX_PATH = Path("docs/architecture/handle-index.json")
PAIR_PATH = Path("docs/normative-pair.toml")
ARCHITECTURE_MANIFEST_PATH = Path("docs/architecture/architecture/manifest.json")
JSON_PATH = Path("docs/architecture/decision-anchor-index.json")
MARKDOWN_PATH = Path("docs/architecture/DECISION_ANCHOR_INDEX.md")
SECTION_HANDLE = "A16.1"
SECTION_HEADING = "## A16.1. Decision Anchors"
SOURCE_ANCHOR = "a161-decision-anchors"
ROW = re.compile(
    r"^\|\s*`(ARCH-[A-Z0-9]+(?:-[A-Z0-9]+)+)`\s*\|\s*"
    r"(Invariant|Contract)\s*\|\s*(.*?)\s*\|\s*$"
)


class DecisionAnchorError(RuntimeError):
    pass


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecisionAnchorError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise DecisionAnchorError(f"JSON root must be an object: {path}")
    return value


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            value = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise DecisionAnchorError(f"cannot read TOML {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise DecisionAnchorError(f"TOML root must be a table: {path}")
    return value


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()  # noqa: S324 - Git object identity


def parse_table(text: str) -> "OrderedDict[str, dict[str, Any]]":
    lines = text.splitlines()
    headings = [index for index, line in enumerate(lines) if line == SECTION_HEADING]
    if headings != [0]:
        raise DecisionAnchorError(
            f"{SECTION_HEADING!r} must occur exactly once as the first line"
        )
    if len(lines) < 7 or lines[4].strip() != "| ID | Class | Decision |":
        raise DecisionAnchorError("A16.1 Decision Anchor table header is missing")
    if not re.fullmatch(r"\|[-|\s]+\|", lines[5].strip()):
        raise DecisionAnchorError("A16.1 Decision Anchor separator is malformed")

    anchors: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
    table_started = False
    table_ended = False
    for index, line in enumerate(lines[6:], start=7):
        stripped = line.strip()
        if not stripped:
            if table_started:
                table_ended = True
            continue
        if table_ended:
            raise DecisionAnchorError(
                f"unexpected nonblank content after Decision Anchor table at line {index}"
            )
        if not stripped.startswith("|"):
            raise DecisionAnchorError(
                f"unexpected content in Decision Anchor section at line {index}"
            )
        match = ROW.fullmatch(line)
        if not match:
            raise DecisionAnchorError(
                f"malformed Decision Anchor row at line {index}: {line!r}"
            )
        table_started = True
        anchor_id, anchor_class, decision = match.groups()
        decision = decision.strip()
        if anchor_id in anchors:
            raise DecisionAnchorError(f"duplicate Decision Anchor: {anchor_id}")
        if not decision:
            raise DecisionAnchorError(f"blank Decision Anchor decision: {anchor_id}")
        anchors[anchor_id] = {
            "class": anchor_class,
            "decision": decision,
            "fragment_line": index,
        }
    if not anchors:
        raise DecisionAnchorError("A16.1 Decision Anchor table is empty")
    return anchors


def _section_record(
    handle_index: Mapping[str, Any],
    source_data: bytes,
) -> dict[str, Any]:
    if handle_index.get("schema_version") != HANDLE_SCHEMA:
        raise DecisionAnchorError("unsupported handle-index schema")
    handles = handle_index.get("handles")
    if not isinstance(handles, dict) or not handles:
        raise DecisionAnchorError("handle-index has no handles")
    record = handles.get(SECTION_HANDLE)
    if not isinstance(record, dict):
        raise DecisionAnchorError(f"handle-index has no {SECTION_HANDLE} record")
    required = {
        "source": "architecture",
        "path": SOURCE_PATH.as_posix(),
        "anchor": SOURCE_ANCHOR,
        "source_anchor": SOURCE_ANCHOR,
    }
    for field, expected in required.items():
        if record.get(field) != expected:
            raise DecisionAnchorError(
                f"{SECTION_HANDLE}.{field} differs: "
                f"expected {expected!r}, found {record.get(field)!r}"
            )
    if record.get("fragment_sha256") != _sha256(source_data):
        raise DecisionAnchorError(
            f"{SECTION_HANDLE} fragment hash differs from canonical source"
        )
    if record.get("fragment_bytes") != len(source_data):
        raise DecisionAnchorError(
            f"{SECTION_HANDLE} fragment byte count differs from canonical source"
        )
    source_line = record.get("source_line")
    if not isinstance(source_line, int) or source_line <= 0:
        raise DecisionAnchorError(f"{SECTION_HANDLE}.source_line is invalid")
    return record


def build_payload(root: Path) -> dict[str, Any]:
    root = root.resolve()
    pair = _read_toml(root / PAIR_PATH)
    if pair.get("schema_version") != PAIR_SCHEMA or pair.get("status") != "accepted":
        raise DecisionAnchorError("normative pair is not accepted sharded authority")
    pair_key = str(pair.get("pair_key", ""))
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", pair_key):
        raise DecisionAnchorError("normative pair key is invalid")
    architecture_source_sha256 = str(pair.get("architecture_sha256", ""))
    if not re.fullmatch(r"[0-9a-f]{64}", architecture_source_sha256):
        raise DecisionAnchorError("architecture source digest is invalid")
    if pair.get("architecture_path") != ARCHITECTURE_MANIFEST_PATH.as_posix():
        raise DecisionAnchorError("normative pair does not identify Architecture manifest")

    source_path = root / SOURCE_PATH
    try:
        source_data = source_path.read_bytes()
        source_text = source_data.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DecisionAnchorError(f"cannot read canonical A16.1 source: {exc}") from exc

    handle_index = _read_json(root / HANDLE_INDEX_PATH)
    section = _section_record(handle_index, source_data)
    anchors = parse_table(source_text)
    source_start_line = int(section["source_line"])
    projected: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
    for anchor_id, record in anchors.items():
        projected[anchor_id] = {
            "class": record["class"],
            "decision": record["decision"],
            "fragment_line": record["fragment_line"],
            "source_line": source_start_line + int(record["fragment_line"]) - 1,
        }

    manifest_data = (root / ARCHITECTURE_MANIFEST_PATH).read_bytes()
    return {
        "schema_version": SCHEMA,
        "normative_pair_key": pair_key,
        "architecture_source_sha256": architecture_source_sha256,
        "architecture_manifest_path": ARCHITECTURE_MANIFEST_PATH.as_posix(),
        "architecture_manifest_git_blob_sha1": _git_blob_sha1(manifest_data),
        "source": {
            "path": SOURCE_PATH.as_posix(),
            "section_handle": SECTION_HANDLE,
            "anchor": SOURCE_ANCHOR,
            "sha256": _sha256(source_data),
            "git_blob_sha1": _git_blob_sha1(source_data),
            "bytes": len(source_data),
        },
        "anchors": projected,
    }


def render_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def render_markdown(payload: Mapping[str, Any]) -> str:
    source = payload["source"]
    lines = [
        "<!-- generated: eliot-decision-anchor-index-v1 -->",
        "# Canonical Decision Anchor index",
        "",
        "This generated projection exposes the `ARCH-*` identifiers defined by the",
        "canonical A16.1 table. It is navigation and validation data, not a third",
        "normative source.",
        "",
        f"- Normative pair: `{payload['normative_pair_key']}`",
        "- Canonical table: "
        "[`A16-01-decision-anchors.md`]"
        "(A16-01-decision-anchors.md#a161-decision-anchors)",
        f"- Canonical table SHA-256: `{source['sha256']}`",
        f"- Architecture source SHA-256: `{payload['architecture_source_sha256']}`",
        "",
        "| Decision Anchor | Class | Decision | Canonical source line |",
        "|---|---|---|---:|",
    ]
    anchors = payload.get("anchors")
    if not isinstance(anchors, dict):
        raise DecisionAnchorError("payload anchors must be an object")
    for anchor_id, record in anchors.items():
        if not isinstance(record, dict):
            raise DecisionAnchorError(f"payload anchor is not an object: {anchor_id}")
        decision = str(record["decision"]).replace("|", r"\|")
        lines.append(
            f"| [`{anchor_id}`]"
            "(A16-01-decision-anchors.md#a161-decision-anchors) | "
            f"{record['class']} | {decision} | {record['source_line']} |"
        )
    return "\n".join(lines) + "\n"


def generated_surfaces(root: Path) -> tuple[str, str]:
    payload = build_payload(root)
    return render_json(payload), render_markdown(payload)


def write_generated(root: Path) -> None:
    root = root.resolve()
    json_text, markdown_text = generated_surfaces(root)
    json_path = root / JSON_PATH
    markdown_path = root / MARKDOWN_PATH
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json_text, encoding="utf-8", newline="")
    markdown_path.write_text(markdown_text, encoding="utf-8", newline="")


def verify_generated(root: Path) -> None:
    root = root.resolve()
    expected_json, expected_markdown = generated_surfaces(root)
    for relative, expected in (
        (JSON_PATH, expected_json),
        (MARKDOWN_PATH, expected_markdown),
    ):
        path = root / relative
        try:
            actual = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise DecisionAnchorError(
                f"cannot read generated Decision Anchor surface {relative}: {exc}"
            ) from exc
        if actual != expected:
            raise DecisionAnchorError(
                f"stale generated Decision Anchor surface: {relative}"
            )


def self_test() -> None:
    valid = "\n".join(
        [
            SECTION_HEADING,
            "",
            "Navigation only.",
            "",
            "| ID | Class | Decision |",
            "|---|---|---|",
            "| `ARCH-AUTH-01` | Invariant | Authority is explicit |",
            "| `ARCH-DEV-01` | Contract | Build a working spine |",
            "",
        ]
    )
    parsed = parse_table(valid)
    if list(parsed) != ["ARCH-AUTH-01", "ARCH-DEV-01"]:
        raise DecisionAnchorError("Decision Anchor parse order self-test failed")
    if parsed["ARCH-AUTH-01"]["fragment_line"] != 7:
        raise DecisionAnchorError("Decision Anchor source-line self-test failed")

    duplicate = (
        valid.rstrip("\n")
        + "\n| `ARCH-AUTH-01` | Contract | Duplicate |\n"
    )
    try:
        parse_table(duplicate)
    except DecisionAnchorError as exc:
        if "duplicate" not in str(exc):
            raise
    else:
        raise DecisionAnchorError("duplicate Decision Anchor self-test failed")

    malformed = valid.replace("Invariant", "Default", 1)
    try:
        parse_table(malformed)
    except DecisionAnchorError as exc:
        if "malformed" not in str(exc):
            raise
    else:
        raise DecisionAnchorError("unknown Decision Anchor class self-test failed")

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        path = root / "surface"
        path.write_text("value\n", encoding="utf-8", newline="")
        data = path.read_bytes()
        if _git_blob_sha1(data) != hashlib.sha1(
            f"blob {len(data)}\0".encode("ascii") + data
        ).hexdigest():
            raise DecisionAnchorError("Git blob identity self-test failed")
