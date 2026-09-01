#!/usr/bin/env python3
"""Front door for repository documentation/source conformance.

The complete DCC-001..007 checks remain in ``doc_code_conformance_core``. This
front door preserves fail-closed configured-root handling, adds documentation
pipeline checks DCC-010..013, and validates canonical numeric handles and
Decision Anchors through DCC-015..017.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any, Iterable, Sequence

import doc_code_conformance_core as _core
from doc_code_conformance_core import *  # noqa: F403
from doc_code_conformance_lib import normative_references

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
    normative_findings, normative_metrics = normative_references.reference_findings(root)
    findings.extend(pipeline_findings)
    findings.extend(normative_findings)
    metrics.update(pipeline_metrics)
    metrics.update(normative_metrics)
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

    try:
        normative_references.self_test()
    except normative_references.ReferenceAuditError as exc:
        raise AuditError(  # noqa: F405
            f"normative-reference conformance self-test failed: {exc}"
        ) from exc

    print("DOC_CODE_CONFORMANCE_PIPELINE_SELF_TEST: PASS cases=14")


_core.audit = audit
_core.self_test = self_test
main = _core.main


if __name__ == "__main__":
    raise SystemExit(main())
