"""Fail closed while retiring obsolete source-header traceability markers."""

from __future__ import annotations

import re
import tempfile
import tomllib
from pathlib import Path
from typing import Any, Sequence

import doc_code_conformance_core as core

SCHEMA = "eliot-doc-traceability-retirement-v1"
DEFAULT_CONFIG = Path("config/doc-traceability-retirement.toml")
FINDING_ID = "DCC-014"


class TraceabilityError(RuntimeError):
    pass


def _strings(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise TraceabilityError(f"{field} must be a non-empty string array")
    return [item.strip() for item in value]


def findings(
    root: Path,
    config_relative: Path = DEFAULT_CONFIG,
) -> tuple[list[core.Finding], dict[str, int]]:
    config_path = root / config_relative
    if not config_path.is_file() or config_path.is_symlink():
        return [
            core.Finding(
                FINDING_ID,
                config_relative.as_posix(),
                0,
                "traceability retirement config is missing or symlinked",
            )
        ], {"traceability_retirement_surfaces": 0}

    try:
        with config_path.open("rb") as stream:
            payload = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise TraceabilityError(f"cannot read traceability retirement config: {exc}") from exc
    if payload.get("schema_version") != SCHEMA:
        raise TraceabilityError(
            f"unsupported traceability retirement schema: "
            f"{payload.get('schema_version')!r}"
        )
    raw_surfaces = payload.get("surface")
    if not isinstance(raw_surfaces, list) or not raw_surfaces:
        raise TraceabilityError(
            "traceability retirement config requires at least one [[surface]]"
        )

    result: list[core.Finding] = []
    seen_paths: set[str] = set()
    for index, raw in enumerate(raw_surfaces):
        if not isinstance(raw, dict):
            raise TraceabilityError(f"traceability surface[{index}] must be a table")
        try:
            relative = core.norm(str(raw.get("path", "")))
        except core.AuditError as exc:
            raise TraceabilityError(str(exc)) from exc
        reason = str(raw.get("reason", "")).strip()
        if not reason:
            raise TraceabilityError(f"traceability surface {relative!r} has no reason")
        if relative in seen_paths:
            raise TraceabilityError(f"duplicate traceability surface: {relative}")
        seen_paths.add(relative)

        forbidden_patterns = _strings(
            raw.get("forbidden_patterns"),
            f"traceability surface {relative}.forbidden_patterns",
        )
        required_tokens = _strings(
            raw.get("required_tokens"),
            f"traceability surface {relative}.required_tokens",
        )

        source = root / relative
        if not source.is_file():
            result.append(
                core.Finding(FINDING_ID, relative, 0, "traceability source is missing")
            )
            continue
        if source.is_symlink():
            result.append(
                core.Finding(
                    FINDING_ID,
                    relative,
                    0,
                    "traceability source must not be a symlink",
                )
            )
            continue

        try:
            value = source.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            result.append(
                core.Finding(
                    FINDING_ID,
                    relative,
                    0,
                    f"cannot read traceability source: {exc}",
                )
            )
            continue

        for raw_pattern in forbidden_patterns:
            try:
                pattern = re.compile(raw_pattern)
            except re.error as exc:
                raise TraceabilityError(
                    f"invalid traceability regex for {relative}: "
                    f"{raw_pattern!r}: {exc}"
                ) from exc
            for match in pattern.finditer(value):
                result.append(
                    core.Finding(
                        FINDING_ID,
                        relative,
                        core.line_no(value, match.start()),
                        f"retired traceability marker remains: {match.group(0)}",
                    )
                )

        for token in required_tokens:
            if token not in value:
                result.append(
                    core.Finding(
                        FINDING_ID,
                        relative,
                        1,
                        f"current traceability token is absent: {token}",
                    )
                )

    return sorted(set(result)), {
        "traceability_retirement_surfaces": len(raw_surfaces),
    }


def _ids(values: Sequence[core.Finding]) -> set[str]:
    return {value.finding_id for value in values}


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "config").mkdir()
        (root / "src").mkdir()
        config = root / DEFAULT_CONFIG
        source = root / "src/example.rs"
        config.write_text(
            (
                f'schema_version = "{SCHEMA}"\n\n'
                '[[surface]]\n'
                'path = "src/example.rs"\n'
                'reason = "fixture"\n'
                "forbidden_patterns = [\"legacy-project\", "
                "'(?<![A-Za-z0-9])I2\\.2(?![0-9])']\n"
                'required_tokens = ["docs/architecture/ELIOT_ARCHITECTURE.md", '
                '"docs/ARCHITECTURE_CONTRACT.md"]\n'
            ),
            encoding="utf-8",
            newline="",
        )
        clean = (
            "//! docs/architecture/ELIOT_ARCHITECTURE.md A2.3 I2.23\n"
            "//! docs/ARCHITECTURE_CONTRACT.md\n"
            "pub fn value() {}\n"
        )
        source.write_text(clean, encoding="utf-8", newline="")
        clean_findings, metrics = findings(root)
        if clean_findings or metrics["traceability_retirement_surfaces"] != 1:
            raise TraceabilityError(f"clean traceability fixture failed: {clean_findings}")

        source.write_text(
            clean.replace("A2.3", "legacy-project A2.3"),
            encoding="utf-8",
            newline="",
        )
        if FINDING_ID not in _ids(findings(root)[0]):
            raise TraceabilityError("legacy-project fixture did not fail")

        source.write_text(
            clean.replace("I2.23", "I2.2"),
            encoding="utf-8",
            newline="",
        )
        if FINDING_ID not in _ids(findings(root)[0]):
            raise TraceabilityError("exact invalid-handle fixture did not fail")

        source.write_text(
            clean.replace("docs/ARCHITECTURE_CONTRACT.md", ""),
            encoding="utf-8",
            newline="",
        )
        if FINDING_ID not in _ids(findings(root)[0]):
            raise TraceabilityError("missing current token did not fail")

        config.write_text(
            config.read_text(encoding="utf-8")
            + "\n[[surface]]\n"
            + 'path = "src/example.rs"\n'
            + 'reason = "duplicate"\n'
            + 'forbidden_patterns = ["legacy"]\n'
            + 'required_tokens = ["current"]\n',
            encoding="utf-8",
            newline="",
        )
        try:
            findings(root)
        except TraceabilityError:
            pass
        else:
            raise TraceabilityError(
                "duplicate traceability surface did not fail closed"
            )

    print("DOC_TRACEABILITY_RETIREMENT_SELF_TEST: PASS cases=5")
