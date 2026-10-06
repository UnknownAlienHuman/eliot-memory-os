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


class OwnerRole(str, Enum):
    """Typed work-unit owner role.

    Authority comes only from the accepted catalogue/snapshot classification
    carried by an IntegrationOwnerProfile. Unit-name spelling is identity,
    never authority.
    """
    LEAF = "leaf"
    INTEGRATION_OWNER = "integration-owner"


@dataclass(frozen=True)
class IntegrationOwnerEntry:
    """One exact accepted integration-owner binding: issue plus unit."""

    issue: c.IssueIdentity
    unit: c.WorkUnitIdentity


@dataclass(frozen=True)
class IntegrationOwnerProfile:
    """Explicit typed integration-owner authority bound by the accepted catalogue/snapshot.

    Built by the snapshot/catalogue owner from accepted classification rows.
    Only a listed (issue, unit) pair holds the INTEGRATION_OWNER role; every
    other identity is LEAF. Name prefixes, substrings and bare issue numbers
    never confer authority.
    """

    owners: Tuple[IntegrationOwnerEntry, ...] = ()

    def __post_init__(self) -> None:
        entries = self.owners
        if type(entries) is not tuple:
            raise CohortError(CohortProblem.MALFORMED_FIELD, "integration owners must be a tuple")
        for entry in entries:
            if type(entry) is not IntegrationOwnerEntry:
                raise CohortError(CohortProblem.INTERNAL_ERROR, "integration owner entry mistyped")
        pairs = tuple((entry.issue, entry.unit) for entry in entries)
        if len(set(pairs)) != len(pairs):
            raise CohortError(CohortProblem.DUPLICATE_UNIT, "duplicate integration owner entry")
        object.__setattr__(self, "owners", tuple(sorted(entries, key=lambda e: (e.issue, e.unit))))

    def role_of(self, unit: c.WorkUnitIdentity, issue: Optional[c.IssueIdentity] = None) -> OwnerRole:
        """Return the typed role for an identity under this profile."""
        if type(unit) is not c.WorkUnitIdentity:
            raise CohortError(CohortProblem.INTERNAL_ERROR, "owner lookup unit mistyped")
        if issue is not None and type(issue) is not c.IssueIdentity:
            raise CohortError(CohortProblem.INTERNAL_ERROR, "owner lookup issue mistyped")
        for entry in self.owners:
            if entry.unit == unit and (issue is None or entry.issue == issue):
                return OwnerRole.INTEGRATION_OWNER
        return OwnerRole.LEAF


def is_integration_owner(
    unit: c.WorkUnitIdentity,
    issue: Optional[c.IssueIdentity] = None,
    *,
    profile: Optional[IntegrationOwnerProfile] = None,
) -> bool:
    """Determine whether a work-unit identity is an authorized integration owner.

    Typed authority only: True exactly when the (unit, issue) pair is a member
    of the supplied accepted profile. Without a profile there is no authority
    (False); spelling heuristics and magic issue numbers never apply.
    """
    if type(unit) is not c.WorkUnitIdentity:
        raise CohortError(CohortProblem.INTERNAL_ERROR, "integration owner unit mistyped")
    if profile is None:
        return False
    if type(profile) is not IntegrationOwnerProfile:
        raise CohortError(CohortProblem.INTERNAL_ERROR, "integration owner profile mistyped")
    return profile.role_of(unit, issue) is OwnerRole.INTEGRATION_OWNER


def derive_integration_owners(
    relations: Sequence[c.AssignmentRelation],
    units: Mapping[c.IssueIdentity, c.WorkUnitIdentity],
) -> IntegrationOwnerProfile:
    """Project admitted integrated-by relations onto the owner profile.

    Authority comes only from caller-admitted AssignmentRelation values with
    the closed integrated-by role: the relation target holding the admitted
    unit for its issue is the integration owner. Relations with any other
    role confer nothing; a target with no admitted unit is skipped (never
    fabricated); contradictory admitted units for one target fail closed.
    Unit-name spelling and bare issue numbers never confer authority.
    An empty input yields the empty profile, which authorizes nothing.
    Pure: no network, subprocess or mutation.
    """
    try:
        rel_list = list(relations)
    except Exception:
        raise CohortError(CohortProblem.INTERNAL_ERROR, "owner relations unreadable") from None
    try:
        unit_map = dict(units)
    except Exception:
        raise CohortError(CohortProblem.INTERNAL_ERROR, "owner units unreadable") from None
    seen: Dict[c.IssueIdentity, c.WorkUnitIdentity] = {}
    for rel in rel_list:
        if type(rel) is not c.AssignmentRelation:
            raise CohortError(CohortProblem.INTERNAL_ERROR, "owner relation mistyped")
        if rel.role is not c.RelationRole.INTEGRATED_BY:
            continue
        unit = unit_map.get(rel.target_issue)
        if unit is None:
            continue
        if type(unit) is not c.WorkUnitIdentity:
            raise CohortError(CohortProblem.INTERNAL_ERROR, "owner unit mistyped")
        prev = seen.get(rel.target_issue)
        if prev is None:
            seen[rel.target_issue] = unit
        elif prev != unit:
            raise CohortError(
                CohortProblem.DUPLICATE_UNIT,
                f"contradictory admitted owner identity for #{rel.target_issue.number}",
            )
    return IntegrationOwnerProfile(
        owners=tuple(IntegrationOwnerEntry(issue, unit) for issue, unit in seen.items())
    )


def validate_descriptor_scope(
    desc: c.WorkUnitDescriptor,
    *,
    integration_owners: Optional[IntegrationOwnerProfile] = None,
) -> None:
    """Verify descriptor path safety, root claims, case floor, and identity bindings.

    Restricted-root claims are allowed only for the exact typed integration
    owner bound by the supplied accepted profile.
    """
    # Check paths
    for root in desc.source_roots:
        norm = validate_path_safety(root.value)
        if is_restricted_root_path(norm) and not is_integration_owner(desc.unit, desc.issue, profile=integration_owners):
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


class PackageSharingKind(str, Enum):
    """Explicit typed package-sharing mode.

    DISJOINT: finite disjoint ownership with no overlapping mutable scopes.
    SERIALIZED: overlapping scopes ordered by a typed prerequisite edge with
    exactly one integration owner on the edge.
    """

    DISJOINT = "disjoint"
    SERIALIZED = "serialized"


@dataclass(frozen=True)
class PackageSharingEdge:
    """One explicit typed package-sharing declaration between finite parties.

    Covers the exact sharing parties for one package; order labels alone never
    suffice, and validation always re-checks scopes and order together.
    """

    package: c.PackageIdentity
    issues: Tuple[c.IssueIdentity, ...]
    kind: PackageSharingKind

    def __post_init__(self) -> None:
        if type(self.package) is not c.PackageIdentity:
            raise CohortError(CohortProblem.MALFORMED_FIELD, "package sharing package mistyped")
        if type(self.kind) is not PackageSharingKind:
            raise CohortError(CohortProblem.MALFORMED_FIELD, "package sharing kind mistyped")
        issues = self.issues
        if type(issues) is not tuple or len(issues) < 2:
            raise CohortError(CohortProblem.MALFORMED_FIELD, "package sharing needs at least two issues")
        for ident in issues:
            if type(ident) is not c.IssueIdentity:
                raise CohortError(CohortProblem.MALFORMED_FIELD, "package sharing issue mistyped")
        if len(set(issues)) != len(issues):
            raise CohortError(CohortProblem.DUPLICATE_ISSUE, "duplicate issue in package sharing edge")
        if len({ident.repository for ident in issues}) != 1:
            raise CohortError(CohortProblem.MALFORMED_FIELD, "package sharing crosses repositories")
        object.__setattr__(self, "issues", tuple(sorted(issues)))


def _require_package_sharing(
    package_name: str,
    first: c.WorkUnitDescriptor,
    second: c.WorkUnitDescriptor,
    sharing: Tuple[PackageSharingEdge, ...],
    prereq_map: Dict[int, Set[int]],
    integration_owners: Optional[IntegrationOwnerProfile],
) -> None:
    """Allow one same-package pair only through a validated explicit edge.

    DISJOINT requires no overlapping mutable (source) scopes. SERIALIZED
    requires a typed prerequisite edge in one direction plus exactly one
    typed integration owner on the pair. Test roots are read scopes and may
    stay shared. Without a covering validated edge the pair stays a conflict.
    """
    pair = {first.issue, second.issue}
    for edge in sharing:
        if edge.package.name != package_name or not pair.issubset(set(edge.issues)):
            continue
        if edge.kind is PackageSharingKind.DISJOINT:
            if not check_write_scope_overlap(first, second):
                return
        elif edge.kind is PackageSharingKind.SERIALIZED:
            is_serialized = (
                first.issue.number in prereq_map.get(second.issue.number, set())
                or second.issue.number in prereq_map.get(first.issue.number, set())
            )
            if not is_serialized:
                continue
            owner_count = sum(
                1 for desc in (first, second)
                if integration_owners is not None
                and is_integration_owner(desc.unit, desc.issue, profile=integration_owners)
            )
            if owner_count == 1:
                return
    raise CohortError(
        CohortProblem.CONFLICTING_PACKAGE_OWNERSHIP,
        f"conflicting ownership of package '{package_name}' between {first.unit.value} and {second.unit.value}"
    )


def derive_package_sharing(
    descriptors: Sequence[c.WorkUnitDescriptor],
    prerequisites: Mapping[int, Set[int]],
    integration_owners: Optional[IntegrationOwnerProfile] = None,
) -> Tuple[PackageSharingEdge, ...]:
    """Derive explicit per-pair sharing edges from accepted rows and scopes.

    Finite parties only: descriptors sharing one package name are paired in
    canonical order. A pair with no overlapping mutable (source) scopes yields
    a DISJOINT edge. An overlapping pair yields a SERIALIZED edge only with a
    one-direction typed prerequisite edge plus exactly one admitted
    integration owner on the pair (the same rule _require_package_sharing
    enforces). Any other pair yields no edge, so the conflict stands.
    Deterministic order; pure: no network, subprocess or mutation.
    """
    try:
        desc_list = list(descriptors)
    except Exception:
        raise CohortError(CohortProblem.INTERNAL_ERROR, "sharing descriptors unreadable") from None
    try:
        prereq_map = {k: set(v) for k, v in dict(prerequisites).items()}
    except Exception:
        raise CohortError(CohortProblem.INTERNAL_ERROR, "sharing prerequisites unreadable") from None
    if integration_owners is not None and type(integration_owners) is not IntegrationOwnerProfile:
        raise CohortError(CohortProblem.MALFORMED_FIELD, "integration owners profile mistyped")
    by_package: Dict[str, List[c.WorkUnitDescriptor]] = {}
    for desc in desc_list:
        if type(desc) is not c.WorkUnitDescriptor:
            raise CohortError(CohortProblem.INTERNAL_ERROR, "sharing descriptor mistyped")
        if desc.package is None:
            continue
        by_package.setdefault(desc.package.name, []).append(desc)
    edges: List[PackageSharingEdge] = []
    for package_name in sorted(by_package):
        holders = sorted(by_package[package_name], key=lambda d: d.issue)
        for pos, first in enumerate(holders):
            for second in holders[pos + 1:]:
                if (first.issue, first.unit) == (second.issue, second.unit):
                    continue
                kind = None
                if not check_write_scope_overlap(first, second):
                    kind = PackageSharingKind.DISJOINT
                else:
                    serialized = (
                        first.issue.number in prereq_map.get(second.issue.number, set())
                        or second.issue.number in prereq_map.get(first.issue.number, set())
                    )
                    owner_count = sum(
                        1 for desc in (first, second)
                        if integration_owners is not None
                        and is_integration_owner(desc.unit, desc.issue, profile=integration_owners)
                    )
                    if serialized and owner_count == 1:
                        kind = PackageSharingKind.SERIALIZED
                if kind is not None:
                    edges.append(PackageSharingEdge(
                        package=c.PackageIdentity(package_name),
                        issues=(first.issue, second.issue),
                        kind=kind,
                    ))
    return tuple(edges)


def materialize_catalogue(
    rows: Sequence[c.CatalogueRow],
    expected_issues: Sequence[c.IssueIdentity],
    expected_cases: Optional[int] = None,
    allow_overlapping_prereqs: bool = True,
    *,
    integration_owners: Optional[IntegrationOwnerProfile] = None,
    package_sharing: Sequence[PackageSharingEdge] = (),
) -> c.CatalogueIntegrityReceipt:
    """Materialize an immutable CatalogueIntegrityReceipt from validated rows.

    Enforces:
    - exact row count and issue identity denominator matching expected_issues
    - unique issues and unique units across active rows
    - package ownership exclusivity unless a validated explicit PackageSharingEdge
      (finite disjoint ownership or a typed serialization edge with one
      integration owner from the supplied accepted profile)
    - restricted-root claims only for the exact typed integration owner
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

    # Prerequisite edges resolve inside the denominator: a row depending on
    # an issue outside the rows being materialized is orphaned and stays
    # blocking instead of validating.
    known_issues = set(row_issues)
    for r in rows:
        if any(p not in known_issues for p in r.prerequisites):
            raise CohortError(
                CohortProblem.UNRESOLVED_PREREQUISITE,
                f"row #{r.issue.number} requires a prerequisite outside the denominator",
            )

    if integration_owners is not None and type(integration_owners) is not IntegrationOwnerProfile:
        raise CohortError(CohortProblem.MALFORMED_FIELD, "integration owners profile mistyped")
    if type(package_sharing) is tuple:
        sharing: Tuple[PackageSharingEdge, ...] = package_sharing
    else:
        try:
            sharing = tuple(package_sharing)
        except Exception:
            raise CohortError(CohortProblem.MALFORMED_FIELD, "package sharing declaration unreadable") from None
    for edge in sharing:
        if type(edge) is not PackageSharingEdge:
            raise CohortError(CohortProblem.MALFORMED_FIELD, "package sharing edge mistyped")

    # Prerequisite order map, shared by the package-sharing check (typed
    # serialization edges) and the concurrent write-scope check below.
    prereq_map: Dict[int, Set[int]] = {r.issue.number: set(p.number for p in r.prerequisites) for r in rows}

    # Check package ownership conflicts. A pair sharing one package is valid
    # only through a covering validated explicit edge; otherwise it conflicts.
    holders_by_package: Dict[str, List[c.WorkUnitDescriptor]] = {}
    for r in rows:
        if r.descriptor is not None and r.descriptor.package is not None:
            holders_by_package.setdefault(r.descriptor.package.name, []).append(r.descriptor)
    for package_name, holders in holders_by_package.items():
        for i, first in enumerate(holders):
            for second in holders[i + 1:]:
                if (first.issue, first.unit) == (second.issue, second.unit):
                    continue
                _require_package_sharing(package_name, first, second, sharing, prereq_map, integration_owners)

    # Check descriptor requirements and write scope overlaps
    assigned_descriptors: List[c.WorkUnitDescriptor] = []
    for r in rows:
        if r.disposition is c.CatalogueDisposition.ASSIGNED:
            if r.descriptor is None:
                raise CohortError(CohortProblem.MISSING_DESCRIPTOR, f"assigned row #{r.issue.number} missing descriptor")
            validate_descriptor_scope(r.descriptor, integration_owners=integration_owners)
            assigned_descriptors.append(r.descriptor)
        elif r.disposition is c.CatalogueDisposition.PLANNED:
            if r.descriptor is not None:
                validate_descriptor_scope(r.descriptor, integration_owners=integration_owners)
        elif r.disposition is c.CatalogueDisposition.BLOCKED and r.descriptor is not None:
            # A blocked allocation is unresolved work, not an exemption from the
            # scope rules: a blocked row carrying a descriptor that claims a
            # restricted/shared root belongs to its named integrator, not to
            # every leaf, so it is validated exactly like a planned row.
            # Descriptor-less blocked rows pass through (case 852/36).
            validate_descriptor_scope(r.descriptor, integration_owners=integration_owners)
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
    if selection.scope is c.SelectionScope.FULL_PROJECT:
        active = {r.issue for r in catalogue.rows if r.disposition in
                  (c.CatalogueDisposition.ASSIGNED, c.CatalogueDisposition.BLOCKED,
                   c.CatalogueDisposition.PLANNED)}
        if {d.issue for d in descriptors} != active:
            raise CohortError(
                CohortProblem.DENOMINATOR_REDUCTION_REJECTED,
                "full-project selection is not the exact active catalogue denominator",
            )
    selected_issues = {d.issue for d in descriptors}
    for d in descriptors:
        if d.issue not in cat_rows:
            raise CohortError(CohortProblem.UNEXPECTED_DESCRIPTOR, f"descriptor #{d.issue.number} not in catalogue")
        row = cat_rows[d.issue]
        if row.disposition is not c.CatalogueDisposition.ASSIGNED:
            if row.disposition is c.CatalogueDisposition.BLOCKED:
                raise CohortError(
                    CohortProblem.BLOCKED_ALLOCATION,
                    f"selected row #{d.issue.number} is an unresolved blocked allocation",
                )
            if any(d.issue in cat_rows[other].prerequisites for other in selected_issues if other in cat_rows):
                raise CohortError(
                    CohortProblem.PARENT_SCHEDULED_WITH_CHILDREN,
                    f"replaced parent row #{d.issue.number} scheduled alongside its children",
                )
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
    """Construct a CohortReceipt binding evidence to plan and verifying digest.

    Evidence for an edited (or substituted) descriptor is stale: a source
    edit changes the descriptor identity, so evidence bound to the old
    descriptor no longer proves the planned one. The catalogue identity is
    unaffected by this rejection.
    """
    planned = {d.issue: d for d in plan.descriptors}
    for ev in evidence_rows:
        if planned.get(ev.descriptor.issue) != ev.descriptor:
            raise CohortError(
                CohortProblem.EXECUTION_EVIDENCE_INVALIDATED,
                f"stale execution evidence for #{ev.descriptor.issue.number}: "
                "evidence descriptor does not match the planned descriptor",
            )
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


# Closed named-inventory class under .github/work-units: artifacts that are
# never parsed as numeric executable descriptors. Any other non-numeric TOML
# artifact is unexpected and fails closed.
ALLOWED_NAMED_INVENTORY = frozenset({
    "context-measurement-inventory.toml",
    "context-measurement-owner-map.toml",
    "long-lived-collection-inventory.toml",
})


class DescriptorDiscoveryStatus(str, Enum):
    """Typed discovery outcome. Only OBSERVED (even when empty) may validate
    against a lock; MISSING and UNREADABLE are distinct non-evidence."""

    OBSERVED = "observed"
    MISSING = "missing"
    UNREADABLE = "unreadable"


@dataclass(frozen=True)
class DescriptorDiscovery:
    """Single closed discovery rule result for the work-units directory."""

    status: DescriptorDiscoveryStatus
    files: Tuple[Tuple[int, str], ...] = ()


def discover_work_units(work_units_dir: Path | str) -> DescriptorDiscovery:
    """Discover the work-units directory under one closed rule.

    Returns OBSERVED with the exact numeric descriptor class (sorted
    (issue_number, filename) pairs, possibly empty for an observed-empty
    directory), or MISSING/UNREADABLE when the directory cannot be listed.
    Rejects unknown extra TOML artifacts, noncanonical numeric names and
    duplicate numeric identities; named inventory artifacts in
    ALLOWED_NAMED_INVENTORY are accepted as non-members. Pure (no network,
    subprocess or mutation); unreadable entries fail closed as UNREADABLE.
    """
    base = work_units_dir if isinstance(work_units_dir, Path) else Path(work_units_dir)
    try:
        if not os.path.lexists(base):
            return DescriptorDiscovery(DescriptorDiscoveryStatus.MISSING)
    except (OSError, ValueError):
        raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "work-units discovery unavailable") from None
    try:
        children = sorted(base.iterdir(), key=lambda p: p.name)
    except OSError:
        try:
            if not os.path.lexists(base):
                return DescriptorDiscovery(DescriptorDiscoveryStatus.MISSING)
        except (OSError, ValueError):
            pass
        return DescriptorDiscovery(DescriptorDiscoveryStatus.UNREADABLE)
    found: List[Tuple[int, str]] = []
    seen: Set[int] = set()
    for child in children:
        try:
            if not child.is_file() or child.suffix != ".toml":
                continue
        except OSError:
            return DescriptorDiscovery(DescriptorDiscoveryStatus.UNREADABLE)
        name = child.name
        if name in ALLOWED_NAMED_INVENTORY:
            continue
        stem = child.stem
        if _RE_NUMERIC_STEM.fullmatch(stem) is None:
            raise CohortError(
                CohortProblem.UNEXPECTED_DESCRIPTOR,
                f"unknown work-units artifact: {child.name}",
            )
        try:
            num = int(stem)
        except Exception:
            raise CohortError(
                CohortProblem.FILENAME_MISMATCH,
                f"noncanonical numeric descriptor name: {child.name}",
            ) from None
        if num <= 0 or str(num) != stem:
            raise CohortError(
                CohortProblem.FILENAME_MISMATCH,
                f"noncanonical numeric descriptor name: {child.name}",
            )
        if num in seen:
            raise CohortError(
                CohortProblem.DUPLICATE_ISSUE,
                f"duplicate numeric descriptor identity: {num}",
            )
        seen.add(num)
        found.append((num, child.name))
    return DescriptorDiscovery(DescriptorDiscoveryStatus.OBSERVED, tuple(found))


def discover_numeric_descriptor_files(work_units_dir: Path | str) -> Tuple[Tuple[int, str], ...]:
    """Discover the exact numeric descriptor class under .github/work-units.

    Closed rule, single owner (#852): only regular files named <number>.toml
    whose stem is the canonical decimal of a positive issue number are members.
    Named inventory artifacts and any other spelling are never members.
    Returns (issue_number, filename) pairs sorted by filename.

    Only an OBSERVED directory (even when empty) yields a class. A missing or
    unreadable directory raises INCOMPLETE_SNAPSHOT: an observed-empty
    directory, a missing directory and an unreadable directory are not the
    same evidence, and none of the latter two may validate as an empty class.
    The verdict always comes from comparing this class (and the recomputed
    aggregate digest) against the committed lock in verify_cohort_lock, which
    fails closed on any mismatch.
    """
    discovery = discover_work_units(work_units_dir)
    if discovery.status is DescriptorDiscoveryStatus.OBSERVED:
        return discovery.files
    if discovery.status is DescriptorDiscoveryStatus.MISSING:
        raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "work-units directory is missing")
    raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "work-units directory is unreadable")


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
    # Retained authoritative snapshot identity: exact base/source revision,
    # acquisition receipt and coverage/movement context. Provenance stays
    # outside the hashed aggregate payload (canonical serialization unchanged),
    # but verification binds it via verify_lock_currency instead of discarding it.
    base_commit: str
    acquired_at: str
    acquisition: str
    note: str
    acquired_at_historical: Optional[str] = None
    acquisition_historical: Optional[str] = None


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
    acquired_at = _lock_text(provenance["acquired_at"], "provenance.acquired_at")
    acquisition = _lock_text(provenance["acquisition"], "provenance.acquisition")
    note = _lock_text(provenance["note"], "provenance.note")
    acquired_at_historical = provenance.get("acquired_at_historical")
    if acquired_at_historical is not None:
        acquired_at_historical = _lock_text(acquired_at_historical, "provenance.acquired_at_historical")
    acquisition_historical = provenance.get("acquisition_historical")
    if acquisition_historical is not None:
        acquisition_historical = _lock_text(acquisition_historical, "provenance.acquisition_historical")
    for key in ("acquired_at", "acquisition", "note", "acquired_at_historical", "acquisition_historical"):
        if key in provenance:
            _lock_text(provenance[key], f"provenance.{key}")

    return CohortLock(
        schema_version=schema_version,
        repository_owner=repo.owner,
        repository_name=repo.name,
        rows=tuple(rows),
        base_commit=base_commit,
        acquired_at=acquired_at,
        acquisition=acquisition,
        note=note,
        acquired_at_historical=acquired_at_historical,
        acquisition_historical=acquisition_historical,
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


def verify_lock_currency(
    lock: CohortLock,
    *,
    expected_base_commit: Optional[str] = None,
    expected_repository: Optional[c.RepositoryIdentity] = None,
) -> bool:
    """Verify the retained authoritative snapshot identity of a cohort lock.

    Compares the lock's exact base/source revision and repository against the
    caller-supplied current values. A stale base or a moved source is
    invalidation (INVALID_AGGREGATE_LOCK), never a valid self-consistent
    catalogue: issue bodies, matrices, dispositions, predecessors and accepted
    replacements may have moved while the lock stayed internally consistent.
    Only supplied expectations are checked; unsupplied dimensions are not
    assumed. Pure: no network, subprocess or mutation.
    """
    if type(lock) is not CohortLock:
        raise CohortError(CohortProblem.INTERNAL_ERROR, "cohort lock mistyped")
    if expected_base_commit is not None:
        if type(expected_base_commit) is not str or _RE_GIT_SHA.fullmatch(expected_base_commit) is None:
            raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "expected base commit is not a git SHA")
        if lock.base_commit != expected_base_commit:
            raise CohortError(
                CohortProblem.INVALID_AGGREGATE_LOCK,
                f"stale lock base {lock.base_commit} is not current {expected_base_commit}",
            )
    if expected_repository is not None:
        if type(expected_repository) is not c.RepositoryIdentity:
            raise CohortError(CohortProblem.INTERNAL_ERROR, "expected repository mistyped")
        if lock.repository_owner != expected_repository.owner or lock.repository_name != expected_repository.name:
            raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock repository moved")
    return True


def verify_assignment_binding(
    lock: CohortLock,
    assigned_descriptors: Optional[Mapping[int, c.WorkUnitDescriptor]] = None,
    assignment_receipts: Optional[Mapping[int, c.AssignmentSourceReceipt]] = None,
) -> bool:
    """Rebind every lock row to its live or explicitly admitted offline receipt.

    Compares the retained row identity (issue, unit, body digest) against the
    caller-supplied AssignmentSourceReceipt for that issue, and additionally
    the matrix digest/count through the bound typed descriptor when one is
    supplied. Any row meaning change fails with STALE_MIRROR_BINDING. An
    assigned row with no receipt, when receipts were admitted for this
    verification, is incomplete (INCOMPLETE_SNAPSHOT), not valid. Rows without
    a supplied receipt are left to lock-internal verification; absence of an
    admitted receipt set never fabricates one. Pure: no network, subprocess
    or mutation.
    """
    if type(lock) is not CohortLock:
        raise CohortError(CohortProblem.INTERNAL_ERROR, "cohort lock mistyped")
    supplied = dict(assigned_descriptors) if assigned_descriptors else {}
    receipts = dict(assignment_receipts) if assignment_receipts else {}
    for entry in lock.rows:
        descriptor = supplied.get(entry.issue)
        if descriptor is not None and type(descriptor) is not c.WorkUnitDescriptor:
            raise CohortError(CohortProblem.INTERNAL_ERROR, "supplied assigned descriptor mistyped")
        receipt = receipts.get(entry.issue)
        if receipt is not None and type(receipt) is not c.AssignmentSourceReceipt:
            raise CohortError(CohortProblem.INTERNAL_ERROR, "supplied assignment receipt mistyped")
        if receipt is None:
            if entry.disposition == c.CatalogueDisposition.ASSIGNED.value and receipts:
                raise CohortError(
                    CohortProblem.INCOMPLETE_SNAPSHOT,
                    f"assigned row #{entry.issue} has no assignment receipt",
                )
            continue
        if (receipt.issue.number != entry.issue or receipt.unit.value != entry.unit
                or receipt.body_sha256 != entry.body_sha256):
            raise CohortError(
                CohortProblem.STALE_MIRROR_BINDING,
                f"lock row #{entry.issue} moved against its assignment receipt",
            )
        if descriptor is not None and (
            descriptor.matrix_sha256 != receipt.matrix_sha256
            or descriptor.matrix_cases != receipt.matrix_cases
        ):
            raise CohortError(
                CohortProblem.STALE_MIRROR_BINDING,
                f"lock row #{entry.issue} matrix moved against its assignment receipt",
            )
    return True


def locked_catalogue_rows(
    lock_path: Path | str,
    discovered: Optional[Mapping[int, c.WorkUnitDescriptor]] = None,
) -> Dict[int, c.CatalogueRow]:
    """Project the committed lock onto catalogue rows, preserving its edges.

    Pure projection over the closed lock schema `read_cohort_lock` already owns
    (no second parser, no second discovery rule). Every locked row is returned
    with the disposition, body digest, unit and `prerequisites` the lock
    actually declares, bound to the caller's freshly decoded descriptor when
    one exists for that issue.

    A missing lock declares nothing and projects to the empty mapping: a root
    that ships no lock has declared no row, no disposition and no prerequisite
    edge, and the caller keeps its own discovered denominator unchanged. An
    existing lock that is malformed, unreadable or digest-invalid instead
    propagates INVALID_AGGREGATE_LOCK; it never becomes `{}`. Present-but-
    unusable paths (directory, broken link, special file) are invalid, not
    missing. Prerequisite edges are never dropped here; a row that declares a
    prerequisite keeps it so the selected plan can demand the matching
    accepted evidence.
    """
    path = lock_path if isinstance(lock_path, Path) else Path(lock_path)
    try:
        if not path.is_file():
            if os.path.lexists(path):
                raise CohortError(
                    CohortProblem.INVALID_AGGREGATE_LOCK,
                    "cohort lock path is present but not a regular file",
                )
            return {}
    except CohortError:
        raise
    except (OSError, ValueError):
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock stat failed") from None
    lock = read_cohort_lock(path)
    supplied = dict(discovered) if discovered else {}
    rows: Dict[int, c.CatalogueRow] = {}
    try:
        repo = c.RepositoryIdentity(lock.repository_owner, lock.repository_name)
        for entry in lock.rows:
            descriptor = supplied.get(entry.issue)
            if descriptor is not None and type(descriptor) is not c.WorkUnitDescriptor:
                raise CohortError(CohortProblem.INTERNAL_ERROR, "supplied assigned descriptor mistyped")
            rows[entry.issue] = c.CatalogueRow(
                issue=c.IssueIdentity(repo, entry.issue),
                unit=c.WorkUnitIdentity(entry.unit),
                body_sha256=entry.body_sha256,
                disposition=c.CatalogueDisposition(entry.disposition),
                descriptor=descriptor,
                prerequisites=tuple(c.IssueIdentity(repo, n) for n in entry.prerequisites),
            )
    except CohortError:
        raise
    except c.ContractViolation as exc:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, str(exc)) from exc
    try:
        expected = tuple(c.IssueIdentity(repo, n) for n in lock.aggregate.issues)
        receipt = c.CatalogueIntegrityReceipt(tuple(rows.values()), expected)
    except c.ContractViolation as exc:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, str(exc)) from exc
    if receipt.sha256 != lock.aggregate.sha256:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock aggregate digest mismatch")
    return rows


def verify_cohort_lock(
    lock_path: Path | str,
    work_units_dir: Path | str,
    assigned_descriptors: Optional[Mapping[int, c.WorkUnitDescriptor]] = None,
    *,
    expected_base_commit: Optional[str] = None,
    expected_repository: Optional[c.RepositoryIdentity] = None,
    assignment_receipts: Optional[Mapping[int, c.AssignmentSourceReceipt]] = None,
    integration_owners: Optional[IntegrationOwnerProfile] = None,
    package_sharing: Sequence[PackageSharingEdge] = (),
) -> c.CatalogueIntegrityReceipt:
    """Verify the committed aggregate lock against freshly discovered state.

    Re-discovers the exact numeric descriptor class from the work-units
    directory (missing/unreadable fails closed with INCOMPLETE_SNAPSHOT, never
    validates as empty), rebinds every catalogue row to the caller-supplied
    typed descriptors and assignment receipts, re-materializes the catalogue,
    and compares the recomputed aggregate sha256 against the lock's
    [aggregate] sha256. When a current base commit or repository is supplied,
    the retained lock provenance must match it: a stale base or moved source
    is invalidation, even when the lock is internally self-consistent. Any
    mismatch fails closed with INVALID_AGGREGATE_LOCK (or the precise
    structural problem); the lock is never trusted on its own bytes.
    A supplied integration-owner profile and package-sharing declaration are
    threaded into re-materialization; omitted, restricted roots and same-
    package pairs fail closed exactly as in materialize_catalogue.
    """
    lock = read_cohort_lock(lock_path)
    if lock.schema_version != SCHEMA_REVISION:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "cohort lock schema revision mismatch")
    if expected_base_commit is not None or expected_repository is not None:
        verify_lock_currency(
            lock,
            expected_base_commit=expected_base_commit,
            expected_repository=expected_repository,
        )
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
    if assignment_receipts is not None:
        verify_assignment_binding(lock, supplied, assignment_receipts)
    receipt = materialize_catalogue(
        rows, expected, expected_cases=lock.aggregate.matrix_cases,
        integration_owners=integration_owners, package_sharing=package_sharing)

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
    """Verify that an assignment snapshot is complete and non-truncated.

    Beyond the header completeness flag and missing sections, a snapshot that
    claims completeness must bind the repository identity, the exact
    base/source revision, and an acquisition receipt, and must carry
    coverage/pagination evidence with no reported movement or inconsistency.
    Declared counts must match their observed object lists. Unresolved
    coverage is incomplete, not zero findings. Pure: no network, subprocess
    or mutation.
    """
    if type(snapshot) is not dict:
        raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot is not a mapping")
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
    repository = header.get("repository")
    if type(repository) is not str or not repository:
        raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot lacks repository identity")
    base_revision = header.get("base_revision", header.get("base_commit"))
    if type(base_revision) is not str or _RE_GIT_SHA.fullmatch(base_revision) is None:
        raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot lacks exact base revision")
    if not header.get("acquisition") and not header.get("acquired_at"):
        raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot lacks acquisition receipt")
    if header.get("moved") is True or header.get("inconsistent") is True:
        raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot reports movement or inconsistency")
    pagination = header.get("pagination")
    if pagination is not None:
        if type(pagination) is not dict or pagination.get("complete") is not True:
            raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot pagination incomplete")
    for count_key, items_key in (("issue_count", "issues"), ("object_count", "objects")):
        count = header.get(count_key)
        items = header.get(items_key)
        if count is None and items is None:
            continue
        if type(count) is not int or count < 0 or type(items) is not list or len(items) != count:
            raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot coverage and count mismatch")


def _toml_escape(text: str) -> str:
    """Escape free text for a TOML basic string (deterministic)."""
    out = []
    for char in text:
        code = ord(char)
        if char == "\\":
            out.append("\\\\")
        elif char == '"':
            out.append('\\"')
        elif char == "\n":
            out.append("\\n")
        elif char == "\r":
            out.append("\\r")
        elif char == "\t":
            out.append("\\t")
        elif code < 0x20 or code == 0x7F:
            raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot text carries a control character")
        else:
            out.append(char)
    return "".join(out)


_SNAPSHOT_ROW_KEYS = frozenset({"issue", "unit", "body_sha256", "disposition", "prerequisites"})


def generate_cohort_lock(
    snapshot: dict,
    descriptors: Mapping[int, c.WorkUnitDescriptor],
) -> bytes:
    """Render a deterministic closed cohort lock from a validated snapshot.

    Owner-side generation outside read-only validation (issue body: the owner
    may explicitly generate its authorized descriptors outside read-only
    validation): the controller-supplied snapshot carries the accepted
    header (repository, exact base revision, acquisition receipt, coverage)
    plus the classified row table, and the caller supplies the currently
    observed typed descriptors bound by issue. Steps: validate_snapshot_
    completeness first (truncated/tag-filtered/moved snapshots never
    generate); closed-shape row checks against _LOCK_ROW_KEYS; assigned rows
    without an observed descriptor are incomplete, never fabricated;
    aggregate arithmetic recomputed from the built receipt with the exact
    digest function verify_cohort_lock compares against; provenance bound to
    the snapshot header (never a hand-edited base). Blocked/planned/
    superseded rows pass through with their dispositions preserved.
    Same inputs give byte-identical outputs. Pure: no network, subprocess,
    repository mutation or writes; the caller persists the bytes.
    """
    validate_snapshot_completeness(snapshot)
    header = snapshot["header"]
    assert isinstance(header, dict)
    repository = header["repository"]
    if type(repository) is not str or repository.count("/") != 1:
        raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot repository is not owner/name")
    owner_name, repo_name = repository.split("/")
    try:
        repo = c.RepositoryIdentity(owner_name, repo_name)
    except c.ContractViolation:
        raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot repository identity invalid") from None
    base_revision = header["base_revision"] if "base_revision" in header else header.get("base_commit")
    if type(base_revision) is not str or _RE_GIT_SHA.fullmatch(base_revision) is None:
        raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot lacks exact base revision")
    acquisition = header.get("acquisition")
    acquired_at = header.get("acquired_at")
    if type(acquisition) is not str or not acquisition:
        raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot lacks acquisition receipt")
    if type(acquired_at) is not str or not acquired_at:
        raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot lacks acquisition time")
    note = header.get("note")
    if note is None:
        note = (f"Generated outside read-only validation from the controller snapshot acquired "
                f"{acquired_at} via {acquisition} at base {base_revision}.")
    if type(note) is not str or not note:
        raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot note invalid")
    raw_rows = snapshot.get("rows")
    if type(raw_rows) is not list or not raw_rows:
        raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot carries no classified rows")
    if len(raw_rows) > MAX_CATALOGUE_ROWS:
        raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot row count exceeds the catalogue limit")
    numeric = snapshot.get("numeric_descriptors", [])
    if type(numeric) is not list or any(type(n) is not int or n < 1 for n in numeric):
        raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot numeric class invalid")
    numeric_t = tuple(sorted(numeric))
    if any(b <= a for a, b in zip(numeric_t, numeric_t[1:])):
        raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot numeric class not canonical sorted")
    try:
        supplied = dict(descriptors)
    except Exception:
        raise CohortError(CohortProblem.INTERNAL_ERROR, "generation descriptors unreadable") from None
    entries = []
    for entry in raw_rows:
        if type(entry) is not dict or set(entry) != _SNAPSHOT_ROW_KEYS:
            raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot row is not closed")
        number = entry["issue"]
        if type(number) is not int or number < 1:
            raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot row issue invalid")
        unit_raw = entry["unit"]
        body_raw = entry["body_sha256"]
        disp_raw = entry["disposition"]
        prereqs_raw = entry["prerequisites"]
        if type(prereqs_raw) is not list or any(type(n) is not int or n < 1 for n in prereqs_raw):
            raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot row prerequisites invalid")
        if type(disp_raw) is not str or disp_raw not in _LOCK_DISPOSITIONS:
            raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot row disposition unknown")
        if type(body_raw) is not str or _RE_HEX_SHA256.fullmatch(body_raw) is None:
            raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot row body digest invalid")
        try:
            unit = c.WorkUnitIdentity(unit_raw)
            disposition = c.CatalogueDisposition(disp_raw)
            prereqs = tuple(c.IssueIdentity(repo, n) for n in prereqs_raw)
        except c.ContractViolation:
            raise CohortError(CohortProblem.INCOMPLETE_SNAPSHOT, "snapshot row identity invalid") from None
        body = body_raw
        descriptor = supplied.get(number)
        if descriptor is not None and type(descriptor) is not c.WorkUnitDescriptor:
            raise CohortError(CohortProblem.INTERNAL_ERROR, "generation descriptor mistyped")
        if disposition is c.CatalogueDisposition.ASSIGNED and descriptor is None:
            raise CohortError(
                CohortProblem.INCOMPLETE_SNAPSHOT,
                f"assigned row #{number} has no observed descriptor",
            )
        try:
            entries.append(c.CatalogueRow(
                issue=c.IssueIdentity(repo, number),
                unit=unit,
                body_sha256=body,
                disposition=disposition,
                descriptor=descriptor,
                prerequisites=prereqs,
            ))
        except c.ContractViolation as exc:
            raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, str(exc)) from exc
    numbers = [r.issue.number for r in entries]
    if len(set(numbers)) != len(numbers):
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, "snapshot rows carry a duplicate issue")
    ordered = sorted(entries, key=lambda r: r.issue.number)
    expected = tuple(r.issue for r in ordered)
    try:
        receipt = c.CatalogueIntegrityReceipt(tuple(ordered), expected)
    except c.ContractViolation as exc:
        raise CohortError(CohortProblem.INVALID_AGGREGATE_LOCK, str(exc)) from exc
    counted = {"assigned": 0, "blocked": 0, "planned": 0, "nonexecutable": 0,
               "superseded": 0, "accepted-historical": 0}
    for row in ordered:
        counted[row.disposition.value] += 1
    lines = [
        "# Immutable gate-owned assignment catalogue lock (#852).",
        "# Generated outside read-only validation; see the #852 REPORT for",
        "# acquisition bindings, classifications and evidence. Do not hand-edit.",
        f'schema_version = "{SCHEMA_REVISION}"',
        "",
        "[repository]",
        f'owner = "{_toml_escape(repo.owner)}"',
        f'name = "{_toml_escape(repo.name)}"',
        "",
    ]
    for row in ordered:
        lines += [
            "[[row]]",
            f"issue = {row.issue.number}",
            f'unit = "{_toml_escape(row.unit.value)}"',
            f'body_sha256 = "{row.body_sha256}"',
            f'disposition = "{row.disposition.value}"',
            "prerequisites = [" + ", ".join(str(p.number) for p in row.prerequisites) + "]",
            "",
        ]
    lines += [
        "[aggregate]",
        "issues = [" + ", ".join(str(r.issue.number) for r in ordered) + "]",
        "numeric_descriptors = [" + ", ".join(str(n) for n in numeric_t) + "]",
        f"matrix_cases = {receipt.matrix_cases}",
        f"assigned = {counted['assigned']}",
        f"blocked = {counted['blocked']}",
        f"planned = {counted['planned']}",
        f"nonexecutable = {counted['nonexecutable']}",
        f"superseded = {counted['superseded']}",
        f"accepted_historical = {counted['accepted-historical']}",
        f'sha256 = "{receipt.sha256}"',
        "",
        "[provenance]",
        f'base_commit = "{base_revision}"',
        f'acquired_at = "{_toml_escape(acquired_at)}"',
        f'acquisition = "{_toml_escape(acquisition)}"',
        f'note = "{_toml_escape(note)}"',
        "",
    ]
    return ("\n".join(lines)).encode("utf-8")


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
    """Verify that source and test roots exist on disk for an execution attempt.

    Existence is not enough: a symlink, junction or reparse point smuggling
    an outside tree under an innocent root value is a physical alias escape,
    so every existing path must resolve inside the repository root. Pure read
    (no network, subprocess or mutation).
    """
    try:
        root_real = os.path.normcase(os.path.realpath(repo_root))
    except (OSError, ValueError):
        raise CohortError(CohortProblem.UNSAFE_PATH, "attempt root is not resolvable") from None
    for r in tuple(desc.source_roots) + tuple(desc.test_roots):
        p = repo_root / r.value
        if not p.exists():
            raise CohortError(CohortProblem.MISSING_ATTEMPT_SOURCE, f"path does not exist on disk: {r.value}")
        try:
            resolved = os.path.normcase(os.path.realpath(p))
        except (OSError, ValueError):
            raise CohortError(CohortProblem.UNSAFE_PATH, f"attempt path is not resolvable: {r.value}") from None
        if resolved != root_real and not resolved.startswith(root_real + os.sep):
            raise CohortError(CohortProblem.UNSAFE_PATH, f"attempt path escapes the repository root: {r.value}")


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
