"""Deterministic capability-cell registry compiler."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from .discovery import discover_cells
from .model import REGISTRY_SCHEMA, Finding, canonical_json, sha256, source_identity
from .ownership import ownership_findings
from .scope import load_scope, normative_pair


def compile_registry(
    root: Path,
    exact_source: str,
) -> tuple[dict[str, Any], list[Finding]]:
    pair = normative_pair(root)
    scope = load_scope(root)
    cells, findings = discover_cells(root, scope)
    findings.extend(ownership_findings(cells))

    registry: dict[str, Any] = {
        "schema": REGISTRY_SCHEMA,
        "authority": "NON_AUTHORITATIVE_GENERATED_EVIDENCE",
        "normative_pair": pair,
        "source_sha": source_identity(exact_source),
        "scope": asdict(scope),
        "scope_rule": (
            "the scope contract selects package roots and optional inventory units only; "
            "all ownership/support claims still require explicit package-local manifests"
        ),
        "cells": [asdict(cell) for cell in sorted(cells, key=lambda item: item.cell_id)],
        "findings": [
            asdict(finding)
            for finding in sorted(
                findings,
                key=lambda item: (
                    item.code,
                    item.path,
                    item.package or "",
                    item.cell_id or "",
                ),
            )
        ],
        "status": "COMPLETE" if not findings else "PARTIAL",
    }
    registry["registry_sha256"] = sha256(canonical_json(registry))
    return registry, findings
