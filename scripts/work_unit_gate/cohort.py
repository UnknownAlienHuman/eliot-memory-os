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
import tomllib
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from . import contracts as c
from . import descriptor_runner as dr

SCHEMA_REVISION = "eliot-work-unit-cohort-v1"
MAX_CATALOGUE_ROWS = 10000
MAX_DESCRIPTOR_BYTES = 65536
MAX_MATRIX_CASES = 1000

_RE_ABSOLUTE_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
_RE_UNC = re.compile(r"^\\\\")
_RE_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
_RE_NUMERIC_STEM = re.compile(r"[0-9]+")
_RE_GIT_SHA = re.compile(r"[0-9a-f]{40}")

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
        elif r.disposition is c.CatalogueDisposition.SUPERSEDED and r.descriptor is not None:
            # A superseded historical row is a terminal record: #843 accepts no
            # implementation evidence ("Superseded source donor only") and #859
            # is closed unmerged ("not merged or accepted verification"). A
            # descriptor attached to one smuggles the historical candidate in
            # as current acceptance authority instead of migrating its data
            # into gate-owned descriptors, so migration is still required.
            raise CohortError(
                CohortProblem.HISTORICAL_MIGRATION_REQUIRED,
                f"superseded historical row #{r.issue.number} carries an executable descriptor; "
                "a historical candidate is not current acceptance authority",
            )

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


def discover_numeric_descriptor_files(work_units_dir: Path | str) -> Tuple[Tuple[int, str], ...]:
    """Discover the exact numeric descriptor class under .github/work-units.

    Closed rule, single owner (#852): only regular files named <number>.toml
    whose stem is all digits decoding to a positive issue number are members.
    Named inventory artifacts and any other spelling are never members.
    Returns (issue_number, filename) pairs sorted by filename.

    A missing or unreadable directory yields the empty class; discovery alone
    claims no integrity. The verdict always comes from comparing this class
    (and the recomputed aggregate digest) against the committed lock in
    verify_cohort_lock, which fails closed on any mismatch.
    """
    try:
        base = work_units_dir if isinstance(work_units_dir, Path) else Path(work_units_dir)
        if not base.is_dir():
            return ()
        found: List[Tuple[int, str]] = []
        for child in sorted(base.iterdir(), key=lambda p: p.name):
            if not child.is_file() or child.suffix != ".toml":
                continue
            stem = child.stem
            if _RE_NUMERIC_STEM.fullmatch(stem) is None:
                continue
            try:
                num = int(stem)
            except Exception:
                continue
            if num <= 0:
                continue
            found.append((num, child.name))
        return tuple(found)
    except Exception:
        return ()


# Closed lock shape (.github/work-unit-cohort.toml). Unknown tables or keys
# are rejected: the lock is the immutable aggregate commitment, not an
# extensible document.
_LOCK_TOP_LEVEL_KEYS = frozenset({"schema_version", "repository", "row", "aggregate", "provenance"})
_LOCK_REPOSITORY_KEYS = frozenset({"owner", "name"})
_LOCK_ROW_KEYS = frozenset({"issue", "unit", "body_sha256", "disposition", "prerequisites"})
_LOCK_AGGREGATE_KEYS = frozenset({
    "issues", "numeric_descriptors", "matrix_cases", "assigned", "blocked",
    "planned", "nonexecutable", "superseded", "accepted_historical", "sha256",
})
_LOCK_PROVENANCE_KEYS = frozenset({
    "base_commit", "acquired_at", "acquisition", "note",
    "acquired_at_historical", "acquisition_historical",
})
_LOCK_DISPOSITIONS = frozenset({
    "assigned", "planned", "blocked", "nonexecutable", "superseded", "accepted-historical",
})


@dataclass(frozen=True)
class CohortLockRow:
    issue: int
    unit: str
    body_sha256: str
    disposition: str
    prerequisites: Tuple[int, ...]


@dataclass(frozen=True)
class CohortLockAggregate:
    issues: Tuple[int, ...]
    numeric_descriptors: Tuple[int, ...]
    matrix_cases: int
    assigned: int
    blocked: int
    planned: int
    nonexecutable: int
    superseded: int
    accepted_historical: int
    sha256: str


@dataclass(frozen=True)
class CohortLock:
    schema_version: str
    repository_owner: str
    repository_name: str
    rows: Tuple[CohortLockRow, ...]
    aggregate: CohortLockAggregate


def _lock_int(value: object, field: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, f"lock field {field} is not a valid integer")
    return value


def _lock_text(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, f"lock field {field} is not valid text")
    return value


def _lock_digest(value: object, field: str) -> str:
    if type(value) is not str or _RE_HEX_SHA256.fullmatch(value) is None:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, f"lock field {field} is not a sha256 hex digest")
    return value


def read_cohort_lock(lock_path: Path | str) -> CohortLock:
    """Read and closed-validate the committed aggregate lock TOML.

    Rejects unknown tables/keys, mistyped fields, non-canonical row order,
    and malformed digests with INVALID_AGGREGATE_LOCK. Digest comparison
    against recomputed bytes happens in verify_cohort_lock.
    """
    path = lock_path if isinstance(lock_path, Path) else Path(lock_path)
    try:
        raw = path.read_bytes()
    except OSError:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock unreadable") from None
    if not raw or len(raw) > MAX_DESCRIPTOR_BYTES:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock size out of bounds")
    try:
        doc = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError):
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock is not valid TOML") from None
    if type(doc) is not dict or set(doc) - _LOCK_TOP_LEVEL_KEYS:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock has unknown tables")
    for required in ("schema_version", "repository", "row", "aggregate", "provenance"):
        if required not in doc:
            raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, f"cohort lock missing {required}")
    schema_version = _lock_text(doc["schema_version"], "schema_version")

    repository = doc["repository"]
    if type(repository) is not dict or set(repository) - _LOCK_REPOSITORY_KEYS:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock repository is not closed")
    try:
        repo = c.RepositoryIdentity(
            _lock_text(repository["owner"], "repository.owner"),
            _lock_text(repository["name"], "repository.name"),
        )
    except (KeyError, c.ContractViolation):
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock repository identity invalid") from None

    raw_rows = doc["row"]
    if type(raw_rows) is not list or not raw_rows:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock has no rows")
    rows: List[CohortLockRow] = []
    for entry in raw_rows:
        if type(entry) is not dict or set(entry) - _LOCK_ROW_KEYS or set(entry) != _LOCK_ROW_KEYS:
            raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock row is not closed")
        prereqs = entry["prerequisites"]
        if type(prereqs) is not list:
            raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock prerequisites not a list")
        try:
            c.WorkUnitIdentity(_lock_text(entry["unit"], "row.unit"))
        except c.ContractViolation:
            raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock row unit invalid") from None
        disposition = _lock_text(entry["disposition"], "row.disposition")
        if disposition not in _LOCK_DISPOSITIONS:
            raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock row disposition unknown")
        rows.append(CohortLockRow(
            issue=_lock_int(entry["issue"], "row.issue", minimum=1),
            unit=entry["unit"],
            body_sha256=_lock_digest(entry["body_sha256"], "row.body_sha256"),
            disposition=disposition,
            prerequisites=tuple(_lock_int(n, "row.prerequisites", minimum=1) for n in prereqs),
        ))
    row_issues = [r.issue for r in rows]
    if any(b <= a for a, b in zip(row_issues, row_issues[1:])):
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock rows are not canonical sorted")

    aggregate = doc["aggregate"]
    if type(aggregate) is not dict or set(aggregate) != _LOCK_AGGREGATE_KEYS:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock aggregate is not closed")
    issues = aggregate["issues"]
    numeric = aggregate["numeric_descriptors"]
    if type(issues) is not list or type(numeric) is not list:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock aggregate lists mistyped")
    issues_t = tuple(_lock_int(n, "aggregate.issues", minimum=1) for n in issues)
    numeric_t = tuple(_lock_int(n, "aggregate.numeric_descriptors", minimum=1) for n in numeric)
    if any(b <= a for a, b in zip(numeric_t, numeric_t[1:])):
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock numeric class not canonical sorted")
    if issues_t != tuple(row_issues):
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock aggregate issues mismatch rows")

    provenance = doc["provenance"]
    if type(provenance) is not dict or set(provenance) - _LOCK_PROVENANCE_KEYS:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock provenance is not closed")
    for required in ("base_commit", "acquired_at", "acquisition", "note"):
        if required not in provenance:
            raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, f"cohort lock provenance missing {required}")
    base_commit = _lock_text(provenance["base_commit"], "provenance.base_commit")
    if _RE_GIT_SHA.fullmatch(base_commit) is None:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock base commit is not a git SHA")
    for key in ("acquired_at", "acquisition", "note", "acquired_at_historical", "acquisition_historical"):
        if key in provenance:
            _lock_text(provenance[key], f"provenance.{key}")

    return CohortLock(
        schema_version=schema_version,
        repository_owner=repo.owner,
        repository_name=repo.name,
        rows=tuple(rows),
        aggregate=CohortLockAggregate(
            issues=issues_t,
            numeric_descriptors=numeric_t,
            matrix_cases=_lock_int(aggregate["matrix_cases"], "aggregate.matrix_cases"),
            assigned=_lock_int(aggregate["assigned"], "aggregate.assigned"),
            blocked=_lock_int(aggregate["blocked"], "aggregate.blocked"),
            planned=_lock_int(aggregate["planned"], "aggregate.planned"),
            nonexecutable=_lock_int(aggregate["nonexecutable"], "aggregate.nonexecutable"),
            superseded=_lock_int(aggregate["superseded"], "aggregate.superseded"),
            accepted_historical=_lock_int(aggregate["accepted_historical"], "aggregate.accepted_historical"),
            sha256=_lock_digest(aggregate["sha256"], "aggregate.sha256"),
        ),
    )


def verify_cohort_lock(
    lock_path: Path | str,
    work_units_dir: Path | str,
    assigned_descriptors: Optional[Mapping[int, c.WorkUnitDescriptor]] = None,
) -> c.CatalogueIntegrityReceipt:
    """Verify the committed aggregate lock against freshly discovered state.

    Re-discovers the exact numeric descriptor class from the work-units
    directory, rebuilds every catalogue row (assigned rows bound to the
    caller-supplied typed descriptors), re-materializes the catalogue, and
    compares the recomputed aggregate sha256 against the lock's [aggregate]
    sha256. Any mismatch fails closed with INVALID_AGGREGATE_LOCK (or the
    precise structural problem); the lock is never trusted on its own bytes.
    """
    lock = read_cohort_lock(lock_path)
    if lock.schema_version != SCHEMA_REVISION:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock schema revision mismatch")
    discovered = sorted(num for num, _ in discover_numeric_descriptor_files(work_units_dir))
    if discovered != list(lock.aggregate.numeric_descriptors):
        raise CohortError(
            CohortProblem.INVALID_AGGREGATE_LOCK,
            "discovered numeric descriptor class does not match the lock",
        )
    supplied = dict(assigned_descriptors) if assigned_descriptors else {}
    try:
        repo = c.RepositoryIdentity(lock.repository_owner, lock.repository_name)
        rows: List[c.CatalogueRow] = []
        for entry in lock.rows:
            issue = c.IssueIdentity(repo, entry.issue)
            unit = c.WorkUnitIdentity(entry.unit)
            disposition = c.CatalogueDisposition(entry.disposition)
            prereqs = tuple(c.IssueIdentity(repo, n) for n in entry.prerequisites)
            descriptor = supplied.get(entry.issue)
            if descriptor is not None and type(descriptor) is not c.WorkUnitDescriptor:
                raise CohortError(CohortProblem.INTERNAL_ERROR, "supplied assigned descriptor mistyped")
            rows.append(c.CatalogueRow(
                issue=issue,
                unit=unit,
                body_sha256=entry.body_sha256,
                disposition=disposition,
                descriptor=descriptor,
                prerequisites=prereqs,
            ))
        expected = tuple(c.IssueIdentity(repo, n) for n in lock.aggregate.issues)
    except CohortError:
        raise
    except c.ContractViolation as exc:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, str(exc)) from exc
    receipt = materialize_catalogue(rows, expected, expected_cases=lock.aggregate.matrix_cases)

    counted = {"assigned": 0, "blocked": 0, "planned": 0, "nonexecutable": 0,
               "superseded": 0, "accepted-historical": 0}
    for row in rows:
        counted[row.disposition.value] += 1
    claimed = {"assigned": lock.aggregate.assigned, "blocked": lock.aggregate.blocked,
               "planned": lock.aggregate.planned, "nonexecutable": lock.aggregate.nonexecutable,
               "superseded": lock.aggregate.superseded,
               "accepted-historical": lock.aggregate.accepted_historical}
    if counted != claimed:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock disposition arithmetic mismatch")
    if receipt.sha256 != lock.aggregate.sha256:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock aggregate digest mismatch")
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


def is_real_repository_root(candidate: Path) -> bool:
    """True when `candidate` is a real repository checkout, not a temp fixture root.

    Pure (no network I/O, subprocess execution, or repository mutation):
    resolves `candidate` and reports whether it carries the `.git` identity
    entry (a directory in a main checkout, a gitdir-pointer file in a linked
    worktree). Temp fixture roots created for tests never carry one. The
    marker is deliberately independent of leaf-router presence: a missing
    router on a real tree is a mutation and must fail, never evidence that
    the tree is "not real" so the check may be skipped.
    """
    return (Path(candidate).resolve() / ".git").exists()


def verify_leaf_routers_unchanged(
    repo_root: Path,
    frozen_router_sha256: Dict[str, str],
    router_paths: Sequence[str] = (
        "scripts/docs_router.py",
        "scripts/docs_router_core.py",
        "scripts/docs_shards.py",
        "scripts/docs_shards_core.py",
    ),
) -> bool:
    """Verify that leaf router files on disk are byte-identical to frozen base identities.

    Pure (no network I/O, subprocess execution, or repository mutation): hashes
    the exact on-disk bytes of each listed router (binary mode, sha256) and
    compares against the caller-supplied frozen mapping of rel-path ->
    64-hex-char sha256 recorded from the immutable base snapshot/receipt.
    Raises CohortError(ROUTER_MUTATION_DETECTED) on any mismatch: mutated
    bytes, CRLF-only change, missing file, missing frozen identity for a
    listed router, or malformed expected digest. Returns True only when every
    listed router matches.
    """
    try:
        get_digest = frozen_router_sha256.get
    except AttributeError:
        raise CohortError(
            CohortProblem.ROUTER_MUTATION_DETECTED,
            "frozen router identities must be a rel-path -> sha256 mapping",
        ) from None
    root = Path(repo_root)
    for rel_path in router_paths:
        expected = get_digest(rel_path)
        if expected is None:
            raise CohortError(
                CohortProblem.ROUTER_MUTATION_DETECTED,
                f"missing frozen identity for router: {rel_path}",
            )
        if not isinstance(expected, str) or _RE_HEX_SHA256.fullmatch(expected) is None:
            raise CohortError(
                CohortProblem.ROUTER_MUTATION_DETECTED,
                f"malformed frozen digest for router: {rel_path}",
            )
        file_path = root / rel_path
        if not file_path.is_file():
            raise CohortError(CohortProblem.ROUTER_MUTATION_DETECTED, f"router missing: {rel_path}")
        try:
            actual = hashlib.sha256(file_path.read_bytes()).hexdigest()
        except OSError as e:
            raise CohortError(
                CohortProblem.ROUTER_MUTATION_DETECTED, f"router unreadable: {rel_path} ({e})"
            ) from e
        if actual != expected:
            raise CohortError(
                CohortProblem.ROUTER_MUTATION_DETECTED,
                f"router bytes differ from frozen identity: {rel_path}",
            )
    return True


def verify_attempt_paths_exist(desc: c.WorkUnitDescriptor, repo_root: Path) -> None:
    """Verify that source and test roots exist on disk for an execution attempt."""
    for r in tuple(desc.source_roots) + tuple(desc.test_roots):
        p = repo_root / r.value
        if not p.exists():
            raise CohortError(CohortProblem.MISSING_ATTEMPT_SOURCE, f"path does not exist on disk: {r.value}")


# Stable redacted #850 rejection codes mapped to cohort problems. Any other
# code stays a generic malformed-field failure; the code itself is the detail.
_COHORT_RUNNER_PROBLEMS = {
    "CLOSED_FIELDS": CohortProblem.UNKNOWN_FIELD,
    "DESCRIPTOR_FILENAME_MISMATCH": CohortProblem.FILENAME_MISMATCH,
}


def decode_cohort_descriptor(raw: bytes, filename: str) -> dict:
    """Decode a descriptor TOML through the accepted #850 validator.

    Delegates closed-shape validation to descriptor_runner.decode_descriptor
    so cohort decoding can never drift from the descriptor contract owner.
    Translates its stable redacted codes to CohortProblem values.
    """
    try:
        return dr.decode_descriptor(raw, filename)
    except dr.RunnerInputError as exc:
        code = str(exc)
        problem = _COHORT_RUNNER_PROBLEMS.get(code, CohortProblem.MALFORMED_FIELD)
        raise CohortError(problem, code) from None


def serialize_catalogue_canonical(catalogue: c.CatalogueIntegrityReceipt) -> bytes:
    """Serialize a CatalogueIntegrityReceipt deterministically without self-referential fields."""
    return c.canonical_bytes(catalogue)


def serialize_plan_canonical(plan: c.SelectedVerificationPlan) -> bytes:
    """Serialize a SelectedVerificationPlan deterministically."""
    return c.canonical_bytes(plan)
