#!/usr/bin/env python3
"""Front door for repository documentation/source conformance.

The complete DCC-001..007 checks remain in ``doc_code_conformance_core``. This
front door preserves fail-closed configured-root handling and adds pipeline
integrity checks DCC-010..013 for the documentation generator/router and
DCC-014 for bounded retirement of pre-sharding source traceability.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any, Iterable, Sequence

import doc_code_conformance_core as _core
from doc_code_conformance_core import *  # noqa: F403

_base_audit = _core.audit
_base_self_test = _core.self_test
_base_selected_files = _core.selected_files


def selected_files(root: Path, roots: Sequence[str]) -> Iterable[Path]:
    """Expand configured roots and fail instead of silently skipping a gap."""

    missing: list[str] = []
    for raw in roots:
        relative = norm(raw)  # noqa: F405
        if not (root / relative).exists():
            missing.append(relative)
    if missing:
        raise AuditError(  # noqa: F405
            "configured roots are missing: " + ", ".join(sorted(set(missing)))
        )
    return _base_selected_files(root, roots)


# The base checkers resolve this name from their defining module at execution.
_core.selected_files = selected_files


TRACEABILITY_SCHEMA = "eliot-doc-traceability-retirement-v1"
TRACEABILITY_DEFAULT_CONFIG = "config/doc-traceability-retirement.toml"
TRACEABILITY_FINDING_ID = "DCC-014"


def traceability_retirement_findings(
    root: Path,
    config_relative: str = TRACEABILITY_DEFAULT_CONFIG,
) -> tuple[list[Finding], dict[str, int]]:
    """Validate exact source headers selected for legacy-marker retirement."""

    config_relative = norm(config_relative)
    config_path = root / config_relative
    if not config_path.is_file():
        return (
            [
                Finding(
                    TRACEABILITY_FINDING_ID,
                    config_relative,
                    0,
                    "traceability retirement config is missing",
                )
            ],
            {"traceability_retirement_surfaces": 0},
        )

    payload = toml(config_path)
    if payload.get("schema_version") != TRACEABILITY_SCHEMA:
        raise AuditError(
            f"unsupported traceability retirement schema: {payload.get('schema_version')!r}"
        )
    raw_surfaces = payload.get("surface")
    if not isinstance(raw_surfaces, list) or not raw_surfaces:
        raise AuditError("traceability retirement config requires at least one [[surface]]")

    findings: list[Finding] = []
    seen_paths: set[str] = set()
    for index, raw in enumerate(raw_surfaces):
        if not isinstance(raw, dict):
            raise AuditError(f"traceability surface[{index}] must be a table")
        relative = norm(str(raw.get("path", "")))
        reason = str(raw.get("reason", "")).strip()
        if not reason:
            raise AuditError(f"traceability surface {relative!r} has no reason")
        if relative in seen_paths:
            raise AuditError(f"duplicate traceability surface: {relative}")
        seen_paths.add(relative)

        forbidden_patterns = strings(
            raw.get("forbidden_patterns"),
            f"traceability surface {relative}.forbidden_patterns",
        )
        required_tokens = strings(
            raw.get("required_tokens"),
            f"traceability surface {relative}.required_tokens",
        )
        if not forbidden_patterns or not required_tokens:
            raise AuditError(
                f"traceability surface {relative} requires forbidden_patterns and required_tokens"
            )

        source = root / relative
        if not source.is_file():
            findings.append(
                Finding(
                    TRACEABILITY_FINDING_ID,
                    relative,
                    0,
                    "traceability source is missing",
                )
            )
            continue
        if source.is_symlink():
            findings.append(
                Finding(
                    TRACEABILITY_FINDING_ID,
                    relative,
                    0,
                    "traceability source must not be a symlink",
                )
            )
            continue

        value = text(source)
        for raw_pattern in forbidden_patterns:
            try:
                pattern = re.compile(raw_pattern)
            except re.error as exc:
                raise AuditError(
                    f"invalid traceability regex for {relative}: {raw_pattern!r}: {exc}"
                ) from exc
            for match in pattern.finditer(value):
                findings.append(
                    Finding(
                        TRACEABILITY_FINDING_ID,
                        relative,
                        line_no(value, match.start()),
                        f"retired traceability marker remains: {match.group(0)}",
                    )
                )

        for token in required_tokens:
            if token not in value:
                findings.append(
                    Finding(
                        TRACEABILITY_FINDING_ID,
                        relative,
                        1,
                        f"current traceability token is absent: {token}",
                    )
                )

    return sorted(set(findings)), {
        "traceability_retirement_surfaces": len(raw_surfaces),
    }


def documentation_pipeline_findings(
    root: Path,
    cfg: dict[str, Any],
) -> tuple[list[Finding], dict[str, int]]:  # noqa: F405
    section = cfg["documentation_pipeline"]
    findings: list[Finding] = []  # noqa: F405

    shards_relative = norm(str(section["shards_front_door"]))  # noqa: F405
    shards_path = root / shards_relative
    if not shards_path.is_file():
        findings.extend(
            [
                Finding(  # noqa: F405
                    "DCC-010",
                    shards_relative,
                    0,
                    "documentation shard front door is missing",
                ),
                Finding(  # noqa: F405
                    "DCC-012",
                    shards_relative,
                    0,
                    "documentation shard front door is missing",
                ),
            ]
        )
        shards_value = ""
    else:
        shards_value = text(shards_path)  # noqa: F405

    for part in strings(  # noqa: F405
        section["required_link_skip_parts"],
        "documentation_pipeline.required_link_skip_parts",
    ):
        if part not in shards_value:
            findings.append(
                Finding(  # noqa: F405
                    "DCC-010",
                    shards_relative,
                    1,
                    "Markdown link verification does not exclude "
                    f"generated/local directory: {part}",
                )
            )

    case_marker = str(section["exact_case_marker"])
    if case_marker not in shards_value:
        findings.append(
            Finding(  # noqa: F405
                "DCC-012",
                shards_relative,
                1,
                "Markdown link verification has no cross-platform "
                f"exact-case marker: {case_marker}",
            )
        )

    router_relative = norm(str(section["router_front_door"]))  # noqa: F405
    router_path = root / router_relative
    if not router_path.is_file():
        findings.extend(
            [
                Finding(  # noqa: F405
                    "DCC-011",
                    router_relative,
                    0,
                    "documentation router front door is missing",
                ),
                Finding(  # noqa: F405
                    "DCC-013",
                    router_relative,
                    0,
                    "documentation router front door is missing",
                ),
            ]
        )
        router_value = ""
    else:
        router_value = text(router_path)  # noqa: F405

    diff_filter = re.search(r"--diff-filter=([A-Z]+)", router_value)
    if not diff_filter or "D" not in diff_filter.group(1):
        findings.append(
            Finding(  # noqa: F405
                "DCC-011",
                router_relative,
                line_no(router_value, diff_filter.start()) if diff_filter else 1,  # noqa: F405
                "--changed-from routing excludes deleted paths; "
                "diff filter must include D",
            )
        )

    drive_marker = str(section["drive_path_rejection_marker"])
    if drive_marker not in router_value:
        findings.append(
            Finding(  # noqa: F405
                "DCC-013",
                router_relative,
                1,
                "Windows drive-qualified paths are not rejected by "
                "the router front door",
            )
        )

    return findings, {
        "documentation_pipeline_files": int(shards_path.is_file())
        + int(router_path.is_file()),
    }


def audit(
    root: Path,
    cfg: dict[str, Any],
) -> tuple[list[Finding], dict[str, int]]:  # noqa: F405
    findings, metrics = _base_audit(root, cfg)
    pipeline_findings, pipeline_metrics = documentation_pipeline_findings(root, cfg)
    findings.extend(pipeline_findings)
    metrics.update(pipeline_metrics)
    traceability_findings, traceability_metrics = (
        traceability_retirement_findings(root)
    )
    findings.extend(traceability_findings)
    metrics.update(traceability_metrics)
    return sorted(set(findings)), metrics


def _pipeline_fixture(root: Path) -> dict[str, Any]:
    scripts = root / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "docs_shards.py").write_text(
        "\n".join(
            [
                '".eliot"',
                '".eliot-docs"',
                '".codebase-memory"',
                '"target"',
                '"dist"',
                '"node_modules"',
                '"obj"',
                '"__pycache__"',
                'DOC_LINK_EXACT_CASE_V1 = "eliot-doc-link-exact-case-v1"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (scripts / "docs_router.py").write_text(
        '--diff-filter=ACMRTUXBD\n'
        'DRIVE_QUALIFIED_PATH_REJECTED = '
        '"eliot-doc-router-drive-qualified-path-v1"\n',
        encoding="utf-8",
    )
    return {
        "documentation_pipeline": {
            "shards_front_door": "scripts/docs_shards.py",
            "router_front_door": "scripts/docs_router.py",
            "required_link_skip_parts": [
                ".eliot",
                ".eliot-docs",
                ".codebase-memory",
                "target",
                "dist",
                "node_modules",
                "obj",
                "__pycache__",
            ],
            "exact_case_marker": "DOC_LINK_EXACT_CASE_V1",
            "drive_path_rejection_marker": "DRIVE_QUALIFIED_PATH_REJECTED",
        }
    }


def _expect_pipeline_finding(
    root: Path,
    cfg: dict[str, Any],
    finding_id: str,
) -> None:
    ids = {
        finding.finding_id
        for finding in documentation_pipeline_findings(root, cfg)[0]
    }
    if finding_id not in ids:
        raise AuditError(  # noqa: F405
            f"pipeline self-test expected {finding_id}, got {sorted(ids)}"
        )


def traceability_retirement_self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "config").mkdir()
        (root / "src").mkdir()
        config = root / TRACEABILITY_DEFAULT_CONFIG
        source = root / "src/example.rs"
        config.write_text(
            (
                'schema_version = "eliot-doc-traceability-retirement-v1"\n\n'
                '[[surface]]\n'
                'path = "src/example.rs"\n'
                'reason = "fixture"\n'
                "forbidden_patterns = [\"legacy-project\", '(?<![A-Za-z0-9])I2\\.2(?![0-9])']\n"
                'required_tokens = ["docs/architecture/ELIOT_ARCHITECTURE.md", '
                '"docs/ARCHITECTURE_CONTRACT.md"]\n'
            ),
            encoding="utf-8",
        )
        clean = (
            "//! docs/architecture/ELIOT_ARCHITECTURE.md A2.3 I2.23\n"
            "//! docs/ARCHITECTURE_CONTRACT.md\n"
            "pub fn value() {}\n"
        )
        source.write_text(clean, encoding="utf-8")
        findings, metrics = traceability_retirement_findings(root)
        if findings or metrics["traceability_retirement_surfaces"] != 1:
            raise AuditError(f"clean traceability fixture failed: {findings}")

        source.write_text(clean.replace("A2.3", "legacy-project A2.3"), encoding="utf-8")
        ids = {finding.finding_id for finding in traceability_retirement_findings(root)[0]}
        if TRACEABILITY_FINDING_ID not in ids:
            raise AuditError("legacy project fixture did not fail")

        source.write_text(clean.replace("I2.23", "I2.2"), encoding="utf-8")
        ids = {finding.finding_id for finding in traceability_retirement_findings(root)[0]}
        if TRACEABILITY_FINDING_ID not in ids:
            raise AuditError("exact invalid handle fixture did not fail")

        source.write_text(clean.replace("docs/ARCHITECTURE_CONTRACT.md", ""), encoding="utf-8")
        ids = {finding.finding_id for finding in traceability_retirement_findings(root)[0]}
        if TRACEABILITY_FINDING_ID not in ids:
            raise AuditError("missing current traceability token did not fail")

        config.write_text(
            config.read_text(encoding="utf-8")
            + "\n[[surface]]\npath = \"src/example.rs\"\nreason = \"duplicate\"\n"
            + "forbidden_patterns = [\"legacy\"]\nrequired_tokens = [\"current\"]\n",
            encoding="utf-8",
        )
        try:
            traceability_retirement_findings(root)
        except AuditError:
            pass
        else:
            raise AuditError("duplicate traceability surface did not fail closed")

    print("DOC_TRACEABILITY_RETIREMENT_SELF_TEST: PASS cases=5")


def self_test() -> None:
    _core.audit = _base_audit
    try:
        _base_self_test()
    finally:
        _core.audit = audit

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        try:
            list(selected_files(root, ["missing-root"]))
        except AuditError:  # noqa: F405
            pass
        else:
            raise AuditError("missing configured root did not fail closed")  # noqa: F405

        cfg = _pipeline_fixture(root)
        findings, _ = documentation_pipeline_findings(root, cfg)
        if findings:
            raise AuditError(  # noqa: F405
                f"clean pipeline fixture failed: {findings}"
            )

        shards = root / "scripts/docs_shards.py"
        clean_shards = shards.read_text(encoding="utf-8")
        shards.write_text(
            clean_shards.replace('".eliot-docs"\n', ""),
            encoding="utf-8",
        )
        _expect_pipeline_finding(root, cfg, "DCC-010")
        shards.write_text(clean_shards, encoding="utf-8")

        shards.write_text(
            clean_shards.replace(
                'DOC_LINK_EXACT_CASE_V1 = '
                '"eliot-doc-link-exact-case-v1"\n',
                "",
            ),
            encoding="utf-8",
        )
        _expect_pipeline_finding(root, cfg, "DCC-012")
        shards.write_text(clean_shards, encoding="utf-8")

        router = root / "scripts/docs_router.py"
        clean_router = router.read_text(encoding="utf-8")
        router.write_text(
            clean_router.replace("--diff-filter=ACMRTUXBD", "--diff-filter=ACMRTUXB"),
            encoding="utf-8",
        )
        _expect_pipeline_finding(root, cfg, "DCC-011")
        router.write_text(clean_router, encoding="utf-8")

        router.write_text(
            clean_router.replace(
                'DRIVE_QUALIFIED_PATH_REJECTED = '
                '"eliot-doc-router-drive-qualified-path-v1"\n',
                "",
            ),
            encoding="utf-8",
        )
        _expect_pipeline_finding(root, cfg, "DCC-013")

    traceability_retirement_self_test()
    print("DOC_CODE_CONFORMANCE_PIPELINE_SELF_TEST: PASS cases=6")


_core.audit = audit
_core.self_test = self_test
main = _core.main


if __name__ == "__main__":
    raise SystemExit(main())
