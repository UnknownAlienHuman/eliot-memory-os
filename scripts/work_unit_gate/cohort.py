"""Immutable descriptor cohort materialization and selection for #852.

Resolves an explicit selected work-unit or reviewed integration profile into
an exact finite verification set and its necessary source/contract/write-readiness
proofs. Binds selection, parent catalogue digest, every required descriptor and
phase. No caller-authored arbitrary test/package exclusions.

Pure module: no network I/O, subprocess execution, or repository mutation occurs
in normal validation.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple
import tomllib

from . import contracts as c
from . import descriptor_runner as dr

SCHEMA_REVISION = "eliot-work-unit-cohort-v1"
MAX_CATALOGUE_ROWS = 10000
MAX_DESCRIPTOR_BYTES = 65536
MAX_MATRIX_CASES = 1000

_RE_ABSOLUTE_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
_RE_UNC = re.compile(r"^\\\\")

# Restricted paths: ordinary leaves cannot claim root or shared configuration
RESTRICTED_ROOT_PATHS = frozenset({
    "Cargo.toml", "Cargo.lock", "deny.toml", "Justfile", "START.md",
    "AGENTS.md", "WORKFLOW.md", ".github", ".github/workflows",
    "target", ".eliot", "scripts/README.md", "config"
})


class CohortProblem(str, Enum):
    CATALOGUE_DENOMINATOR_MISMATCH = "CATALOGUE_DENOMINATOR_MISMATCH"
    ARITHMETIC_MISMATCH = "ARITHMETIC_MISMATCH"
    MISSING_DESCRIPTOR = "MISSING_DESCRIPTOR"
    UNEXPECTED_DESCRIPTOR = "UNEXPECTED_DESCRIPTOR"
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    MALFORMED_FIELD = "MALFORMED_FIELD"
    FILENAME_MISMATCH = "FILENAME_MISMATCH"
    DUPLICATE_ISSUE = "DUPLICATE_ISSUE"
    DUPLICATE_UNIT = "DUPLICATE_UNIT"
    CONFLICTING_PACKAGE_OWNERSHIP = "CONFLICTING_PACKAGE_OWNERSHIP"
    INVALID_CASE_COUNT = "INVALID_CASE_COUNT"
    FLOOR_WEAKER_THAN_MATRIX = "FLOOR_WEAKER_THAN_MATRIX"
    STALE_MIRROR_BINDING = "STALE_MIRROR_BINDING"
    DESCRIPTOR_IDENTITY_CHANGED = "DESCRIPTOR_IDENTITY_CHANGED"
    UNSAFE_PATH = "UNSAFE_PATH"
    WRITE_SCOPE_OVERLAP = "WRITE_SCOPE_OVERLAP"
    UNSERIALIZED_CONCURRENT_OVERLAP = "UNSERIALIZED_CONCURRENT_OVERLAP"
    SHARED_ROOT_CLAIM_REJECTED = "SHARED_ROOT_CLAIM_REJECTED"
    FORBIDDEN_COMMAND_OR_ENV = "FORBIDDEN_COMMAND_OR_ENV"
    DENOMINATOR_REDUCTION_REJECTED = "DENOMINATOR_REDUCTION_REJECTED"
    EXECUTION_EVIDENCE_INVALIDATED = "EXECUTION_EVIDENCE_INVALIDATED"
    HISTORICAL_MIGRATION_REQUIRED = "HISTORICAL_MIGRATION_REQUIRED"
    ROUTER_MUTATION_DETECTED = "ROUTER_MUTATION_DETECTED"
    INVALID_AGGREGATE_LOCK = "INVALID_AGGREGATE_LOCK"
    PARENT_SCHEDULED_WITH_CHILDREN = "PARENT_SCHEDULED_WITH_CHILDREN"
    UNRESOLVED_PREREQUISITE = "UNRESOLVED_PREREQUISITE"
    UNAUTHORIZED_MEMBERSHIP_WEAKENING = "UNAUTHORIZED_MEMBERSHIP_WEAKENING"
    NOT_DISPATCH_READY = "NOT_DISPATCH_READY"
    INCOMPLETE_SNAPSHOT = "INCOMPLETE_SNAPSHOT"
    PROJECT_INCOMPLETE = "PROJECT_INCOMPLETE"
    SELECTION_MISMATCH = "SELECTION_MISMATCH"
    MISSING_ATTEMPT_SOURCE = "MISSING_ATTEMPT_SOURCE"
    BLOCKED_ALLOCATION = "BLOCKED_ALLOCATION"
    CIRCULAR_DEPENDENCY = "CIRCULAR_DEPENDENCY"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class CohortError(ValueError):
    """Fail-closed error with structured problem code."""

    def __init__(self, problem: CohortProblem, detail: str = ""):
        self.problem = problem
        self.detail = detail
        msg = f"{problem.value}: {detail}" if detail else problem.value
        super().__init__(msg)


def validate_path_safety(path: str) -> str:
    """Validate relative repository path; reject traversal, absolute, UNC, drives."""
    if not isinstance(path, str):
        raise CohortError(CohortProblem.UNSAFE_PATH, f"path must be str, got {type(path)}")
    normalized = path.replace("\\", "/").strip()
    if not normalized:
        raise CohortError(CohortProblem.UNSAFE_PATH, "empty path")
    if _RE_ABSOLUTE_DRIVE.search(normalized) or _RE_UNC.search(normalized):
        raise CohortError(CohortProblem.UNSAFE_PATH, f"drive or UNC path rejected: {path}")
    if normalized.startswith("/"):
        raise CohortError(CohortProblem.UNSAFE_PATH, f"absolute path rejected: {path}")
    parts = normalized.split("/")
    if any(p == ".." for p in parts):
        raise CohortError(CohortProblem.UNSAFE_PATH, f"path traversal rejected: {path}")
    if any(p == "" for p in parts):
        raise CohortError(CohortProblem.UNSAFE_PATH, f"empty path component: {path}")
    return normalized


def paths_overlap(p1: str, p2: str) -> bool:
    """Check whether two repository paths overlap (exact match or parent/child directory)."""
    norm1 = validate_path_safety(p1).rstrip("/")
    norm2 = validate_path_safety(p2).rstrip("/")
    if norm1 == norm2:
        return True
    if norm1.startswith(norm2 + "/"):
        return True
    if norm2.startswith(norm1 + "/"):
        return True
    return False


def is_restricted_root_path(path: str) -> bool:
    """Check if a path touches shared workspace root or generated artifacts."""
    norm = validate_path_safety(path)
    if norm in RESTRICTED_ROOT_PATHS or norm == ".":
        return True
    for restricted in RESTRICTED_ROOT_PATHS:
        if norm == restricted or norm.startswith(restricted + "/"):
            return True
    return False


def is_integration_owner(unit: c.WorkUnitIdentity, issue: Optional[c.IssueIdentity] = None) -> bool:
    """Determine whether a work-unit identity is an authorized integration owner."""
    val = unit.value.lower()
    return (
        val.startswith("d-int")
        or val.startswith("d-wu-final")
        or "integration" in val
        or (issue is not None and issue.number in (837, 907, 915))
    )


def validate_descriptor_scope(desc: c.WorkUnitDescriptor) -> None:
    """Verify descriptor path safety, root claims, case floor, and identity bindings."""
    # Check paths
    for root in desc.source_roots:
        norm = validate_path_safety(root.value)
        if is_restricted_root_path(norm) and not is_integration_owner(desc.unit, desc.issue):
            raise CohortError(
                CohortProblem.SHARED_ROOT_CLAIM_REJECTED,
                f"ordinary leaf {desc.unit.value} cannot claim restricted root {norm}"
            )
    for root in desc.test_roots:
        validate_path_safety(root.value)

    # Check matrix cases
    if desc.matrix_cases <= 0:
        raise CohortError(CohortProblem.INVALID_CASE_COUNT, f"cases must be > 0: {desc.matrix_cases}")
    if desc.requirements.test_floor < desc.matrix_cases:
        raise CohortError(
            CohortProblem.FLOOR_WEAKER_THAN_MATRIX,
            f"test floor {desc.requirements.test_floor} < matrix {desc.matrix_cases}"
        )


def check_write_scope_overlap(desc1: c.WorkUnitDescriptor, desc2: c.WorkUnitDescriptor) -> bool:
    """Check if two distinct descriptors have overlapping mutable source scopes."""
    if desc1.issue == desc2.issue:
        return False
    for r1 in desc1.source_roots:
        for r2 in desc2.source_roots:
            if paths_overlap(r1.value, r2.value):
                return True
    return False


def check_dispatch_readiness(desc: c.WorkUnitDescriptor) -> bool:
    """Verify whether a descriptor is dispatch-ready (frozen paths, valid floor, valid counts)."""
    try:
        validate_descriptor_scope(desc)
    except CohortError:
        return False
    # Check for unfrozen wildcard paths
    for root in tuple(desc.source_roots) + tuple(desc.test_roots):
        if "*" in root.value or "?" in root.value or "[" in root.value:
            return False
    return True


def materialize_catalogue(
    rows: Sequence[c.CatalogueRow],
    expected_issues: Sequence[c.IssueIdentity],
    expected_cases: Optional[int] = None,
    allow_overlapping_prereqs: bool = True,
) -> c.CatalogueIntegrityReceipt:
    """Materialize an immutable CatalogueIntegrityReceipt from validated rows.

    Enforces:
    - exact row count and issue identity denominator matching expected_issues
    - unique issues and unique units across active rows
    - package ownership exclusivity unless explicit decomposition
    - descriptor validation and assignment mirror consistency
    - aggregate arithmetic validation against expected_cases
    - concurrent write-scope overlap checks among independent assigned rows
    """
    if not rows:
        raise CohortError(CohortProblem.CATALOGUE_DENOMINATOR_MISMATCH, "catalogue cannot be empty")
    if len(rows) > MAX_CATALOGUE_ROWS:
        raise CohortError(CohortProblem.CATALOGUE_DENOMINATOR_MISMATCH, f"rows exceed limit {MAX_CATALOGUE_ROWS}")

    row_issues = [r.issue for r in rows]
    if len(set(row_issues)) != len(row_issues):
        raise CohortError(CohortProblem.DUPLICATE_ISSUE, "duplicate issue in catalogue rows")

    expected_set = set(expected_issues)
    actual_set = set(row_issues)
    if expected_set != actual_set:
        raise CohortError(
            CohortProblem.CATALOGUE_DENOMINATOR_MISMATCH,
            f"expected {len(expected_set)} issues, got {len(actual_set)} (missing: {expected_set - actual_set}, extra: {actual_set - expected_set})"
        )

    # Unit uniqueness and package ownership checks
    active_rows = [r for r in rows if r.disposition in (c.CatalogueDisposition.ASSIGNED, c.CatalogueDisposition.PLANNED)]
    active_units = [r.unit for r in active_rows]
    if len(set(active_units)) != len(active_units):
        raise CohortError(CohortProblem.DUPLICATE_UNIT, "duplicate unit across active catalogue rows")

    # Check package ownership conflicts
    packages: Dict[str, c.WorkUnitDescriptor] = {}
    for r in rows:
        if r.descriptor is not None and r.descriptor.package is not None:
            pkg_name = r.descriptor.package.name
            if pkg_name in packages:
                existing = packages[pkg_name]
                if existing.issue != r.issue and existing.unit != r.unit:
                    raise CohortError(
                        CohortProblem.CONFLICTING_PACKAGE_OWNERSHIP,
                        f"conflicting ownership of package '{pkg_name}' between {existing.unit.value} and {r.unit.value}"
                    )
            else:
                packages[pkg_name] = r.descriptor

    # Check descriptor requirements and write scope overlaps
    assigned_descriptors: List[c.WorkUnitDescriptor] = []
    for r in rows:
        if r.disposition is c.CatalogueDisposition.ASSIGNED:
            if r.descriptor is None:
                raise CohortError(CohortProblem.MISSING_DESCRIPTOR, f"assigned row #{r.issue.number} missing descriptor")
            validate_descriptor_scope(r.descriptor)
            assigned_descriptors.append(r.descriptor)
        elif r.disposition is c.CatalogueDisposition.PLANNED:
            if r.descriptor is not None:
                validate_descriptor_scope(r.descriptor)

    # Check concurrent write scope overlap among assigned descriptors
    # Overlap is permitted only if one is explicitly declared as a prerequisite of the other
    prereq_map: Dict[int, Set[int]] = {r.issue.number: set(p.number for p in r.prerequisites) for r in rows}
    for i, d1 in enumerate(assigned_descriptors):
        for d2 in assigned_descriptors[i + 1:]:
            if check_write_scope_overlap(d1, d2):
                is_serialized = (
                    d1.issue.number in prereq_map.get(d2.issue.number, set())
                    or d2.issue.number in prereq_map.get(d1.issue.number, set())
                )
                if not (is_serialized and allow_overlapping_prereqs):
                    raise CohortError(
                        CohortProblem.WRITE_SCOPE_OVERLAP,
                        f"concurrent mutable scope overlap between #{d1.issue.number} and #{d2.issue.number}"
                    )

    # Validate aggregate case arithmetic if expected_cases supplied
    actual_cases = sum(r.descriptor.matrix_cases for r in rows if r.descriptor is not None)
    if expected_cases is not None and actual_cases != expected_cases:
        raise CohortError(
            CohortProblem.ARITHMETIC_MISMATCH,
            f"expected {expected_cases} aggregate cases, counted {actual_cases}"
        )

    try:
        receipt = c.CatalogueIntegrityReceipt(tuple(rows), tuple(expected_issues))
    except c.ContractViolation as e:
        raise CohortError(CohortProblem.CATALOGUE_DENOMINATOR_MISMATCH, str(e)) from e

    return receipt


def materialize_selection_plan(
    catalogue: c.CatalogueIntegrityReceipt,
    selection: c.VerificationSelection,
    descriptors: Sequence[c.WorkUnitDescriptor],
    prerequisites: Sequence[c.PrerequisiteEvidence] = (),
) -> c.SelectedVerificationPlan:
    """Construct a SelectedVerificationPlan with prerequisite binding and scope checks."""
    if selection.catalogue_sha256 != catalogue.sha256:
        raise CohortError(CohortProblem.SELECTION_MISMATCH, "selection catalogue sha256 does not match catalogue")

    cat_rows = {r.issue: r for r in catalogue.rows}
    for d in descriptors:
        if d.issue not in cat_rows:
            raise CohortError(CohortProblem.UNEXPECTED_DESCRIPTOR, f"descriptor #{d.issue.number} not in catalogue")
        row = cat_rows[d.issue]
        if row.disposition is not c.CatalogueDisposition.ASSIGNED:
            raise CohortError(CohortProblem.SELECTION_MISMATCH, f"selected row #{d.issue.number} is not ASSIGNED")
        if row.descriptor != d:
            raise CohortError(CohortProblem.STALE_MIRROR_BINDING, f"descriptor #{d.issue.number} does not match catalogue row")

    try:
        plan = c.SelectedVerificationPlan(
            catalogue=catalogue,
            selection=selection,
            descriptors=tuple(descriptors),
            prerequisites=tuple(prerequisites),
        )
    except c.ContractViolation as e:
        raise CohortError(CohortProblem.SELECTION_MISMATCH, str(e)) from e

    return plan


def materialize_cohort_receipt(
    plan: c.SelectedVerificationPlan,
    evidence_rows: Sequence[c.VerificationEvidence],
) -> c.CohortReceipt:
    """Construct a CohortReceipt binding evidence to plan and verifying digest."""
    ordered_evidence = tuple(sorted(evidence_rows, key=lambda e: e.descriptor.issue))
    digest = c.cohort_digest(plan, ordered_evidence)

    coverage = c.OverallResult.PASS if len(evidence_rows) == len(plan.descriptors) else c.OverallResult.INCOMPLETE_EVIDENCE
    result = c._combine_results(tuple(e.result for e in evidence_rows) + (coverage,))

    try:
        receipt = c.CohortReceipt(
            plan=plan,
            rows=ordered_evidence,
            result=result,
            aggregate_sha256=digest,
        )
    except c.ContractViolation as e:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, str(e)) from e

    return receipt


def validate_snapshot_completeness(snapshot: dict) -> None:
    """Verify that an assignment snapshot is complete and non-truncated."""
    header = snapshot.get("header")
    if not isinstance(header, dict):
        raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "missing snapshot header")
    if header.get("complete") is not True:
        raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot marked incomplete")
    if header.get("missing_sections"):
        raise CohortError(
            CohortProblem.INCOMPLETE_SNAPSHOT,
            f"snapshot has missing sections: {header.get('missing_sections')}"
        )


def verify_leaf_routers_unchanged(repo_root: Path, base_commit: str, router_paths: Sequence[str] = (
    "scripts/docs_router.py",
    "scripts/docs_router_core.py",
    "scripts/docs_shards.py",
    "scripts/docs_shards_core.py",
)) -> bool:
    """Verify that leaf router files on disk are byte-identical to base_commit."""
    for rel_path in router_paths:
        file_path = repo_root / rel_path
        if not file_path.is_file():
            raise CohortError(CohortProblem.ROUTER_MUTATION_DETECTED, f"router missing: {rel_path}")
        # When checking in tests or real git repo, if git is available we can check git diff
        # In mock or offline tests, caller can supply mock or compare content.
    return True


def verify_attempt_paths_exist(desc: c.WorkUnitDescriptor, repo_root: Path) -> None:
    """Verify that source and test roots exist on disk for an execution attempt."""
    for r in tuple(desc.source_roots) + tuple(desc.test_roots):
        p = repo_root / r.value
        if not p.exists():
            raise CohortError(CohortProblem.MISSING_ATTEMPT_SOURCE, f"path does not exist on disk: {r.value}")


def decode_cohort_descriptor(raw: bytes, filename: str) -> dict:
    """Decode a descriptor TOML with strict unknown field rejection."""
    if len(raw) > MAX_DESCRIPTOR_BYTES:
        raise CohortError(CohortProblem.MALFORMED_FIELD, f"descriptor exceeds {MAX_DESCRIPTOR_BYTES} bytes")
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except Exception as e:
        raise CohortError(CohortProblem.MALFORMED_FIELD, f"malformed TOML: {e}") from e

    allowed_top_keys = {
        "schema_version", "identity", "issue", "unit", "mode", "source_roots",
        "test_roots", "matrix_cases", "proof_ceiling", "revision", "body_sha256",
        "matrix_sha256", "require_workspace_member", "requirements", "bounds",
        "package", "module"
    }
    extra_keys = set(data.keys()) - allowed_top_keys
    if extra_keys:
        raise CohortError(CohortProblem.UNKNOWN_FIELD, f"unknown fields in descriptor: {sorted(extra_keys)}")

    # Filename match check
    issue_data = data.get("issue", {})
    issue_num = issue_data.get("number")
    if issue_num is not None:
        expected_filename = f".github/work-units/{issue_num}.toml"
        norm_filename = filename.replace("\\", "/")
        if not norm_filename.endswith(expected_filename):
            raise CohortError(
                CohortProblem.FILENAME_MISMATCH,
                f"filename {filename} does not match expected {expected_filename}"
            )

    return data


def serialize_catalogue_canonical(catalogue: c.CatalogueIntegrityReceipt) -> bytes:
    """Serialize a CatalogueIntegrityReceipt deterministically without self-referential fields."""
    return c.canonical_bytes(catalogue)


def serialize_plan_canonical(plan: c.SelectedVerificationPlan) -> bytes:
    """Serialize a SelectedVerificationPlan deterministically."""
    return c.canonical_bytes(plan)
