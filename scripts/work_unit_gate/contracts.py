"""Phase-aware immutable contracts for the work-unit verification gate.

v4 deliberately rejects legacy receipts missing assignment, source or phase
bindings. The preserved v2 module is historical, never silently upgraded.
All validation here is intrinsic: constructing a value cannot establish source
acquisition authority, current workspace state, execution, or accepted merge.
"""
from __future__ import annotations

import dataclasses
import hashlib
import re
from dataclasses import dataclass
from enum import Enum

from . import _contracts_v2 as _base
from ._contracts_v2 import *  # noqa: F401,F403

CONTRACT_SCHEMA_REVISION = "eliot-work-unit-contracts-v4"
WORK_UNIT_DESCRIPTOR_SCHEMA = "eliot-work-unit-descriptor-v2"
LegacyWorkUnitDescriptorV1 = _base.WorkUnitDescriptor
LegacyAssignmentSourceReceiptV2 = _base.AssignmentSourceReceipt
LegacyCohortRowV2 = _base.CohortRow


def canonical_bytes(value: object) -> bytes:
    """Preserve canonicalization rules, contain malformed extension behavior."""
    try:
        return _base.canonical_bytes(value)
    except Exception:
        # Legacy canonicalization can include a hostile Mapping exception in
        # its message. Preserve rejection, never echo that untrusted message.
        raise ContractViolation("canonical value rejected") from None


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _digest(value: object, field: str) -> str:
    _base._exact_type(value, str, field)
    return _base._sha256(value, field)


def _count(value: object, field: str, maximum: int, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ContractViolation(f"{field} is outside its integer bounds")
    return value


def _text(value: object, field: str, limit: int = MAX_TOKEN_BYTES) -> str:
    _base._exact_type(value, str, field)
    try:
        return _base._bounded_text(value, field, limit)
    except (UnicodeError, RecursionError):
        raise ContractViolation(f"{field} is not bounded UTF-8 text") from None


def _tuple(values: object, kind: type, field: str, maximum: int = MAX_COHORT_ROWS,
           *, nonempty: bool = False) -> tuple:
    return _base._tuple_of_exact(values, kind, field, maximum=maximum, nonempty=nonempty)


def _unique(values: tuple, field: str) -> None:
    if len(set(values)) != len(values):
        raise ContractViolation(f"duplicate {field}")


def _combine_results(results: tuple[OverallResult, ...]) -> OverallResult:
    if not results:
        raise ContractViolation("result evidence cannot be empty")
    for result in results:
        _base._exact_type(result, OverallResult, "result evidence")
    for result in (OverallResult.CONFIGURATION_FAILURE, OverallResult.CONTRACT_FAILURE,
                   OverallResult.INCOMPLETE_EVIDENCE):
        if result in results:
            return result
    return OverallResult.PASS


def _finding_result(findings: tuple[Finding, ...]) -> OverallResult:
    results = []
    for item in findings:
        if item.severity is not FindingSeverity.ERROR:
            continue
        if item.finding_class in (FindingClass.CONFIGURATION_DEFECT, FindingClass.INTERNAL_DEFECT):
            results.append(OverallResult.CONFIGURATION_FAILURE)
        elif item.finding_class in (FindingClass.SOURCE_UNAVAILABLE, FindingClass.INCOMPLETE_EVIDENCE):
            results.append(OverallResult.INCOMPLETE_EVIDENCE)
        else:
            results.append(OverallResult.CONTRACT_FAILURE)
    return _combine_results(tuple(results) or (OverallResult.PASS,))


class _ClosedEnum(str, Enum):
    @classmethod
    def _missing_(cls, value: object) -> None:
        # Do not call an untrusted value's repr or echo secrets into diagnostics.
        raise ContractViolation(f"unsupported {cls.__name__} value")


class AssignmentSourceUse(_ClosedEnum):
    ACTIVE_ASSIGNMENT = "active-assignment"
    PREREQUISITE_EVIDENCE = "prerequisite-evidence"


class VerificationPhase(_ClosedEnum):
    PACKAGE_LOCAL = "package-local"
    WORKSPACE_INTEGRATION = "workspace-integration"


class WorkspaceDisposition(_ClosedEnum):
    MEMBER = "member"
    EXCLUDED = "excluded"
    STANDALONE = "standalone"
    UNAVAILABLE = "unavailable"
    CONFIGURATION_DEFECT = "configuration-defect"
    NOT_APPLICABLE = "not-applicable"


@dataclass(frozen=True)
class VerificationRequirements:
    source_floor: int
    public_floor: int
    test_floor: int
    required_guards: tuple[WorkUnitIdentity, ...]

    def __post_init__(self) -> None:
        for name in ("source_floor", "public_floor", "test_floor"):
            _count(getattr(self, name), name, MAX_CANONICAL_ITEMS)
        guards = _tuple(self.required_guards, WorkUnitIdentity, "required_guards", 64)
        _unique(guards, "required guard")
        object.__setattr__(self, "required_guards", tuple(sorted(guards)))


@dataclass(frozen=True)
class ExecutionBounds:
    wall_ms: int
    idle_ms: int
    output_bytes: int
    line_bytes: int
    discovery_tests: int
    child_processes: int

    def __post_init__(self) -> None:
        limits = (("wall_ms", 86_400_000), ("idle_ms", 86_400_000),
                  ("output_bytes", 67_108_864), ("line_bytes", 1_048_576),
                  ("discovery_tests", MAX_MATRIX_CASES), ("child_processes", 64))
        for name, limit in limits:
            _count(getattr(self, name), name, limit, minimum=1)
        if self.idle_ms > self.wall_ms or self.line_bytes > self.output_bytes:
            raise ContractViolation("execution bounds are inconsistent")


@dataclass(frozen=True)
class WorkUnitDescriptor:
    schema_version: str
    identity: DescriptorIdentity
    issue: IssueIdentity
    unit: WorkUnitIdentity
    mode: RunnerMode
    source_roots: tuple[RepositoryPath, ...]
    test_roots: tuple[RepositoryPath, ...]
    matrix_cases: int
    proof_ceiling: ProofCeiling
    revision: int
    body_sha256: str
    matrix_sha256: str
    require_workspace_member: bool
    requirements: VerificationRequirements
    bounds: ExecutionBounds
    package: PackageIdentity | None = None
    module: ModuleIdentity | None = None

    def __post_init__(self) -> None:
        if type(self.schema_version) is not str or self.schema_version != WORK_UNIT_DESCRIPTOR_SCHEMA:
            raise ContractViolation("unsupported descriptor schema; explicit migration required")
        # Reuse the proven v1 identity/path checks with an explicit historical
        # constructor, never a changed global schema or a subclass type bypass.
        old = _base.WorkUnitDescriptor(
            _base.WORK_UNIT_DESCRIPTOR_SCHEMA, self.identity, self.issue, self.unit,
            self.mode, self.source_roots, self.test_roots, self.matrix_cases,
            self.proof_ceiling, self.package, self.module)
        for name in ("source_roots", "test_roots", "matrix_cases"):
            object.__setattr__(self, name, getattr(old, name))
        for path in self.source_roots + self.test_roots:
            if any(char in path.value for char in "*?[]"):
                raise ContractViolation("descriptor roots cannot grant wildcard authority")
        _count(self.revision, "revision", MAX_CANONICAL_INTEGER_ABS, minimum=1)
        _digest(self.body_sha256, "body_sha256")
        _digest(self.matrix_sha256, "matrix_sha256")
        _base._exact_type(self.require_workspace_member, bool, "require_workspace_member")
        _base._exact_type(self.requirements, VerificationRequirements, "requirements")
        _base._exact_type(self.bounds, ExecutionBounds, "bounds")
        if (self.mode is RunnerMode.RUST_PACKAGE or self.require_workspace_member) and self.package is None:
            raise ContractViolation("this descriptor requires an exact package")
        if self.requirements.test_floor < self.matrix_cases or self.bounds.discovery_tests < self.matrix_cases:
            raise ContractViolation("test floor or discovery bound cannot omit matrix cases")

    @classmethod
    def from_mapping(cls, value: object) -> WorkUnitDescriptor:
        # Mapping construction consumes already typed values; TOML/JSON decoding
        # belongs to #850. Missing v2 fields are never supplied by defaults.
        try:
            if type(value) is not dict:
                raise ContractViolation("descriptor input must be an exact dictionary")
            fields = {field.name: field for field in dataclasses.fields(cls)}
            if len(value) > len(fields):
                raise ContractViolation("descriptor contains unknown fields")
            copied = {}
            for key, item in value.items():
                if type(key) is not str or key not in fields:
                    raise ContractViolation("descriptor contains unknown or non-string fields")
                if key in copied:
                    raise ContractViolation("duplicate descriptor field")
                copied[key] = item
            required = {name for name, field in fields.items() if field.default is dataclasses.MISSING}
            if not required.issubset(copied):
                raise ContractViolation("descriptor is missing required fields")
            return cls(**copied)
        except ContractViolation:
            raise
        except Exception:
            raise ContractViolation("descriptor mapping access failed") from None

    @property
    def phase(self) -> VerificationPhase:
        return (VerificationPhase.WORKSPACE_INTEGRATION if self.require_workspace_member
                else VerificationPhase.PACKAGE_LOCAL)

    @property
    def sha256(self) -> str:
        return canonical_sha256(self)


@dataclass(frozen=True)
class OfflineCaptureBinding:
    """Intrinsic expected/observed capture binding, not authority verification.

    #849 must acquire the expected values independently and validate the actual
    controller authority and policy clock. Equal caller-provided hashes alone
    never establish trust, freshness or accepted merge.
    """
    issue: IssueIdentity
    unit: WorkUnitIdentity
    body_sha256: str
    matrix_sha256: str
    snapshot_sha256: str
    expected_snapshot_sha256: str
    producer: WorkUnitIdentity
    capture_receipt_sha256: str
    expected_capture_receipt_sha256: str
    freshness_policy_sha256: str
    captured_at: int
    expires_at: int
    invalidated: bool

    def __post_init__(self) -> None:
        _base._exact_type(self.issue, IssueIdentity, "issue")
        _base._exact_type(self.unit, WorkUnitIdentity, "unit")
        _base._exact_type(self.producer, WorkUnitIdentity, "producer")
        for name in ("body_sha256", "matrix_sha256", "snapshot_sha256", "expected_snapshot_sha256", "capture_receipt_sha256",
                     "expected_capture_receipt_sha256", "freshness_policy_sha256"):
            _digest(getattr(self, name), name)
        for name in ("captured_at", "expires_at"):
            _count(getattr(self, name), name, (1 << 63) - 1)
        _base._exact_type(self.invalidated, bool, "invalidated")
        if self.invalidated or self.expires_at <= self.captured_at:
            raise ContractViolation("offline capture is invalidated or has invalid expiry")
        if self.snapshot_sha256 != self.expected_snapshot_sha256:
            raise ContractViolation("offline expected snapshot mismatch")
        if self.capture_receipt_sha256 != self.expected_capture_receipt_sha256:
            raise ContractViolation("offline expected capture receipt mismatch")


@dataclass(frozen=True)
class AssignmentSourceReceipt:
    issue: IssueIdentity
    state: IssueState
    unit: WorkUnitIdentity
    authority: SourceAuthority
    title: str
    body_sha256: str
    matrix_cases: int
    proof_ceiling: ProofCeiling
    matrix_sha256: str
    source_use: AssignmentSourceUse
    origin: str
    live_etag: str | None = None
    offline_capture: OfflineCaptureBinding | None = None

    def __post_init__(self) -> None:
        for name, kind in (("issue", IssueIdentity), ("state", IssueState),
                           ("unit", WorkUnitIdentity), ("authority", SourceAuthority),
                           ("proof_ceiling", ProofCeiling), ("source_use", AssignmentSourceUse)):
            _base._exact_type(getattr(self, name), kind, name)
        _text(self.title, "title", MAX_TITLE_BYTES)
        _digest(self.body_sha256, "body_sha256")
        _digest(self.matrix_sha256, "matrix_sha256")
        _count(self.matrix_cases, "matrix_cases", MAX_MATRIX_CASES, minimum=1)
        if type(self.origin) is not str or self.origin != "https://api.github.com":
            raise ContractViolation("assignment origin is not the fixed GitHub API")
        if self.source_use is AssignmentSourceUse.ACTIVE_ASSIGNMENT and self.state is not IssueState.OPEN:
            raise ContractViolation("active assignment requires open nonsuperseded ownership")
        if self.authority is SourceAuthority.LIVE_GITHUB:
            if self.offline_capture is not None:
                raise ContractViolation("live source cannot carry offline capture")
            if self.live_etag is not None:
                _text(self.live_etag, "live_etag")
        else:
            if self.live_etag is not None:
                raise ContractViolation("offline source cannot carry live ETag")
            _base._exact_type(self.offline_capture, OfflineCaptureBinding, "offline_capture")
            for name in ("issue", "unit", "body_sha256", "matrix_sha256"):
                if getattr(self.offline_capture, name) != getattr(self, name):
                    raise ContractViolation("offline capture assignment identity mismatch")


def _binding(assignment: AssignmentSourceReceipt, descriptor: WorkUnitDescriptor) -> None:
    _base._exact_type(assignment, AssignmentSourceReceipt, "assignment")
    _base._exact_type(descriptor, WorkUnitDescriptor, "descriptor")
    for field in ("issue", "unit", "matrix_cases", "body_sha256", "matrix_sha256"):
        if getattr(assignment, field) != getattr(descriptor, field):
            raise ContractViolation(f"assignment {field} does not match descriptor")


def _active(assignment: AssignmentSourceReceipt) -> OverallResult:
    return (OverallResult.PASS if assignment.source_use is AssignmentSourceUse.ACTIVE_ASSIGNMENT
            and assignment.state is IssueState.OPEN else OverallResult.INCOMPLETE_EVIDENCE)


@dataclass(frozen=True)
class DiscoveredTestReceipt:
    descriptor: DescriptorIdentity
    descriptor_sha256: str
    test: TestIdentity
    location: SourceLocation
    source_sha256: str
    artifact_sha256: str
    phase: VerificationPhase

    def __post_init__(self) -> None:
        for name, kind in (("descriptor", DescriptorIdentity), ("test", TestIdentity),
                           ("location", SourceLocation), ("phase", VerificationPhase)):
            _base._exact_type(getattr(self, name), kind, name)
        for name in ("descriptor_sha256", "source_sha256", "artifact_sha256"):
            _digest(getattr(self, name), name)


@dataclass(frozen=True)
class TestExecutionRecord:
    test: TestIdentity
    disposition: ExecutionDisposition
    discovery: DiscoveredTestReceipt
    detail: str | None = None

    def __post_init__(self) -> None:
        _base._exact_type(self.test, TestIdentity, "test")
        _base._exact_type(self.disposition, ExecutionDisposition, "disposition")
        _base._exact_type(self.discovery, DiscoveredTestReceipt, "discovery")
        if self.test != self.discovery.test:
            raise ContractViolation("execution test does not match discovery test")
        if self.detail is not None:
            _text(self.detail, "execution detail", MAX_DIAGNOSTIC_BYTES)


TestExecutionReceipt = TestExecutionRecord


@dataclass(frozen=True)
class CaseAccountingMember:
    case: CaseIdentity
    marker: CaseMarker
    execution: TestExecutionRecord

    def __post_init__(self) -> None:
        for name, kind in (("case", CaseIdentity), ("marker", CaseMarker), ("execution", TestExecutionRecord)):
            _base._exact_type(getattr(self, name), kind, name)
        if self.case != self.marker.case or self.marker.test != self.execution.test:
            raise ContractViolation("case marker does not match execution")
        if self.marker.location != self.execution.discovery.location:
            raise ContractViolation("discovery location does not match marker location")


@dataclass(frozen=True)
class CaseAccountingReceipt:
    assignment: AssignmentSourceReceipt
    descriptor: WorkUnitDescriptor
    members: tuple[CaseAccountingMember, ...]
    result: OverallResult
    proof_ceiling: ProofCeiling
    findings: tuple[Finding, ...] = ()

    def __post_init__(self) -> None:
        _binding(self.assignment, self.descriptor)
        _proof(self.proof_ceiling, self.descriptor)
        members = _tuple(self.members, CaseAccountingMember, "members", MAX_MATRIX_CASES)
        ordered = tuple(sorted(members, key=lambda item: item.case.number))
        object.__setattr__(self, "members", ordered)
        findings = _base._normalize_findings(self.findings)
        object.__setattr__(self, "findings", findings)
        _unique(tuple(item.case for item in ordered), "case-accounting member")
        _unique(tuple(item.execution.test for item in ordered), "test covering multiple cases")
        for item in ordered:
            item.case.require_within(self.descriptor.matrix_cases)
            found = item.execution.discovery
            if (item.case.issue != self.descriptor.issue or found.descriptor != self.descriptor.identity
                    or found.descriptor_sha256 != self.descriptor.sha256
                    or found.test.mode is not self.descriptor.mode or found.phase is not self.descriptor.phase):
                raise ContractViolation("case/discovery descriptor identity, mode or phase mismatch")
            path = found.location.path.value
            if not any(path == root.value or path.startswith(root.value + "/")
                       for root in self.descriptor.test_roots):
                raise ContractViolation("discovered test is outside registered test roots")
        dispositions = tuple(item.execution.disposition for item in ordered)
        if ExecutionDisposition.EXECUTED_FAIL in dispositions:
            execution = OverallResult.CONTRACT_FAILURE
        elif (tuple(item.case.number for item in ordered) == tuple(range(1, self.descriptor.matrix_cases + 1))
              and all(item is ExecutionDisposition.EXECUTED_PASS for item in dispositions)):
            execution = OverallResult.PASS
        else:
            execution = OverallResult.INCOMPLETE_EVIDENCE
        expected = _combine_results((execution, _active(self.assignment), _finding_result(findings)))
        _base._require_result(self.result, expected, "case-accounting")


def _proof(value: ProofCeiling, descriptor: WorkUnitDescriptor) -> None:
    _base._exact_type(value, ProofCeiling, "proof_ceiling")
    if value != descriptor.proof_ceiling:
        raise ContractViolation("proof ceiling does not match descriptor")


@dataclass(frozen=True)
class GuardResult:
    identity: WorkUnitIdentity
    result: OverallResult

    def __post_init__(self) -> None:
        _base._exact_type(self.identity, WorkUnitIdentity, "guard identity")
        _base._exact_type(self.result, OverallResult, "guard result")


@dataclass(frozen=True)
class SourceShapeGateReceipt:
    assignment: AssignmentSourceReceipt
    descriptor: WorkUnitDescriptor
    result: OverallResult
    findings: tuple[Finding, ...]
    proof_ceiling: ProofCeiling
    source_sha256: str
    source_items: int
    public_items: int
    test_items: int
    guards: tuple[GuardResult, ...]

    def __post_init__(self) -> None:
        _binding(self.assignment, self.descriptor)
        _proof(self.proof_ceiling, self.descriptor)
        _digest(self.source_sha256, "source_sha256")
        findings = _base._normalize_findings(self.findings)
        object.__setattr__(self, "findings", findings)
        guards = _tuple(self.guards, GuardResult, "guards", 64)
        _unique(tuple(item.identity for item in guards), "guard observation")
        object.__setattr__(self, "guards", tuple(sorted(guards, key=lambda item: item.identity)))
        actual = tuple(sorted(item.identity for item in guards))
        required = self.descriptor.requirements.required_guards
        if not set(actual).issubset(required):
            raise ContractViolation("unregistered source guard")
        floor_results = []
        for observation, floor in (("source_items", "source_floor"), ("public_items", "public_floor"),
                                   ("test_items", "test_floor")):
            count = _count(getattr(self, observation), observation, MAX_CANONICAL_ITEMS)
            floor_results.append(OverallResult.PASS if count >= getattr(self.descriptor.requirements, floor)
                                 else OverallResult.CONTRACT_FAILURE)
        coverage = OverallResult.PASS if actual == required else OverallResult.INCOMPLETE_EVIDENCE
        expected = _combine_results(tuple(floor_results) + tuple(item.result for item in guards)
                                    + (coverage, _active(self.assignment), _finding_result(findings)))
        _base._require_result(self.result, expected, "source-shape")


@dataclass(frozen=True)
class PackageGateReceipt:
    assignment: AssignmentSourceReceipt
    descriptor: WorkUnitDescriptor
    package: PackageIdentity
    module: ModuleIdentity | None
    source_shape: SourceShapeGateReceipt
    case_accounting: CaseAccountingReceipt
    result: OverallResult
    findings: tuple[Finding, ...]
    proof_ceiling: ProofCeiling

    def __post_init__(self) -> None:
        _binding(self.assignment, self.descriptor)
        _proof(self.proof_ceiling, self.descriptor)
        _base._exact_type(self.package, PackageIdentity, "package")
        if self.module is not None:
            _base._exact_type(self.module, ModuleIdentity, "module")
        if self.package != self.descriptor.package or self.module != self.descriptor.module:
            raise ContractViolation("package/module does not match descriptor")
        _children(self.assignment, self.descriptor, self.source_shape, self.case_accounting)
        findings = _base._normalize_findings(self.findings)
        object.__setattr__(self, "findings", findings)
        expected = _combine_results((self.source_shape.result, self.case_accounting.result, _finding_result(findings)))
        _base._require_result(self.result, expected, "package")


def _children(assignment: AssignmentSourceReceipt, descriptor: WorkUnitDescriptor,
              source: SourceShapeGateReceipt, cases: CaseAccountingReceipt) -> None:
    _base._exact_type(source, SourceShapeGateReceipt, "source_shape")
    _base._exact_type(cases, CaseAccountingReceipt, "case_accounting")
    for child in (source, cases):
        if child.assignment != assignment or child.descriptor != descriptor:
            raise ContractViolation("child assignment/descriptor mismatch")
    if any(member.execution.discovery.source_sha256 != source.source_sha256 for member in cases.members):
        raise ContractViolation("case execution source does not match inspected source")


@dataclass(frozen=True)
class WorkspaceAdmissionReceipt:
    assignment: AssignmentSourceReceipt
    descriptor: WorkUnitDescriptor
    package: PackageIdentity | None
    module: ModuleIdentity | None
    disposition: WorkspaceDisposition
    result: OverallResult
    findings: tuple[Finding, ...]
    proof_ceiling: ProofCeiling

    def __post_init__(self) -> None:
        _binding(self.assignment, self.descriptor)
        _proof(self.proof_ceiling, self.descriptor)
        _base._exact_type(self.disposition, WorkspaceDisposition, "disposition")
        if self.package is not None:
            _base._exact_type(self.package, PackageIdentity, "package")
        if self.module is not None:
            _base._exact_type(self.module, ModuleIdentity, "module")
        if self.package != self.descriptor.package or self.module != self.descriptor.module:
            raise ContractViolation("workspace package/module mismatch")
        findings = _base._normalize_findings(self.findings)
        object.__setattr__(self, "findings", findings)
        if self.disposition is WorkspaceDisposition.NOT_APPLICABLE:
            if self.descriptor.mode is RunnerMode.RUST_PACKAGE or self.descriptor.require_workspace_member:
                raise ContractViolation("workspace not-applicable contradicts descriptor")
            observed = OverallResult.PASS
        elif self.disposition is WorkspaceDisposition.CONFIGURATION_DEFECT:
            observed = OverallResult.CONFIGURATION_FAILURE
        elif self.disposition is WorkspaceDisposition.UNAVAILABLE:
            observed = OverallResult.INCOMPLETE_EVIDENCE
        elif self.disposition is WorkspaceDisposition.MEMBER or not self.descriptor.require_workspace_member:
            observed = OverallResult.PASS
        else:
            observed = OverallResult.INCOMPLETE_EVIDENCE
        _base._require_result(self.result, _combine_results((observed, _active(self.assignment),
                                                           _finding_result(findings))), "workspace")


@dataclass(frozen=True)
class ComponentGateReceipt:
    """Generic summary; not an authoritative source/workspace/execution result."""
    component: str
    result: OverallResult
    findings: tuple[Finding, ...]
    proof_ceiling: ProofCeiling

    def __post_init__(self) -> None:
        _base._token(self.component, "component")
        _base._exact_type(self.proof_ceiling, ProofCeiling, "proof_ceiling")
        findings = _base._normalize_findings(self.findings)
        object.__setattr__(self, "findings", findings)
        _base._require_result(self.result, _finding_result(findings), "component-summary")


class CatalogueDisposition(_ClosedEnum):
    ASSIGNED = "assigned"
    PLANNED = "planned"
    BLOCKED = "blocked"
    NONEXECUTABLE = "nonexecutable"
    SUPERSEDED = "superseded"
    ACCEPTED_HISTORICAL = "accepted-historical"


class CatalogueResult(_ClosedEnum):
    INTEGRITY_VALID = "integrity-valid"


class SelectionScope(_ClosedEnum):
    SELECTED = "selected"
    FULL_PROJECT = "full-project"


@dataclass(frozen=True)
class CatalogueRow:
    issue: IssueIdentity
    unit: WorkUnitIdentity
    body_sha256: str
    disposition: CatalogueDisposition
    descriptor: WorkUnitDescriptor | None
    prerequisites: tuple[IssueIdentity, ...] = ()

    def __post_init__(self) -> None:
        _base._exact_type(self.issue, IssueIdentity, "issue")
        _base._exact_type(self.unit, WorkUnitIdentity, "unit")
        _base._exact_type(self.disposition, CatalogueDisposition, "disposition")
        _digest(self.body_sha256, "body_sha256")
        deps = _tuple(self.prerequisites, IssueIdentity, "prerequisites", 256)
        _unique(deps, "prerequisite")
        if self.issue in deps or any(dep.repository != self.issue.repository for dep in deps):
            raise ContractViolation("self or foreign-repository prerequisite")
        object.__setattr__(self, "prerequisites", tuple(sorted(deps)))
        if self.descriptor is not None:
            _base._exact_type(self.descriptor, WorkUnitDescriptor, "descriptor")
            if (self.descriptor.issue != self.issue or self.descriptor.unit != self.unit
                    or self.descriptor.body_sha256 != self.body_sha256):
                raise ContractViolation("catalogue descriptor binding mismatch")
        elif self.disposition is CatalogueDisposition.ASSIGNED:
            raise ContractViolation("assigned catalogue row requires a descriptor")


@dataclass(frozen=True)
class CatalogueIntegrityReceipt:
    """Well-formed complete accounting; neither ready nor executed work."""
    rows: tuple[CatalogueRow, ...]
    expected_issues: tuple[IssueIdentity, ...]

    def __post_init__(self) -> None:
        rows = _tuple(self.rows, CatalogueRow, "catalogue rows", nonempty=True)
        expected = _tuple(self.expected_issues, IssueIdentity, "expected issues", nonempty=True)
        _unique(tuple(row.issue for row in rows), "catalogue issue")
        _unique(tuple(row.unit for row in rows), "catalogue unit")
        descriptors = tuple(row.descriptor.identity for row in rows if row.descriptor is not None)
        _unique(descriptors, "catalogue descriptor")
        _unique(expected, "expected issue")
        if set(expected) != {row.issue for row in rows}:
            raise ContractViolation("catalogue issue denominator mismatch")
        if len({identity.repository for identity in expected}) != 1:
            raise ContractViolation("catalogue contains multiple repositories")
        known = set(expected)
        if any(not set(row.prerequisites).issubset(known) for row in rows):
            raise ContractViolation("catalogue prerequisite is missing")
        object.__setattr__(self, "rows", tuple(sorted(rows, key=lambda row: row.issue)))
        object.__setattr__(self, "expected_issues", tuple(sorted(expected)))

    @property
    def result(self) -> CatalogueResult:
        return CatalogueResult.INTEGRITY_VALID

    @property
    def proof_ceiling(self) -> ProofCeiling:
        return ProofCeiling("catalogue-integrity-only")

    @property
    def matrix_cases(self) -> int:
        return sum(row.descriptor.matrix_cases for row in self.rows if row.descriptor is not None)

    @property
    def sha256(self) -> str:
        return canonical_sha256({"schema": CONTRACT_SCHEMA_REVISION, "kind": "catalogue", "payload": self})


@dataclass(frozen=True)
class VerificationSelection:
    """Producer-issued requested denominator, not a CLI permission override."""
    catalogue_sha256: str
    profile_sha256: str
    scope: SelectionScope
    issues: tuple[IssueIdentity, ...]

    def __post_init__(self) -> None:
        _digest(self.catalogue_sha256, "catalogue_sha256")
        _digest(self.profile_sha256, "profile_sha256")
        _base._exact_type(self.scope, SelectionScope, "scope")
        issues = _tuple(self.issues, IssueIdentity, "selected issues", nonempty=True)
        _unique(issues, "selected issue")
        object.__setattr__(self, "issues", tuple(sorted(issues)))


@dataclass(frozen=True)
class PrerequisiteEvidence:
    """Reference to separately accepted proof; a source read is insufficient."""
    source: AssignmentSourceReceipt
    accepted_commit: str
    accepted_result_sha256: str

    def __post_init__(self) -> None:
        _base._exact_type(self.source, AssignmentSourceReceipt, "source")
        if self.source.source_use is not AssignmentSourceUse.PREREQUISITE_EVIDENCE:
            raise ContractViolation("prerequisite evidence requires its distinct source use")
        if type(self.accepted_commit) is not str or not re.fullmatch(r"[0-9a-f]{40}", self.accepted_commit):
            raise ContractViolation("accepted commit must be an exact observed Git object ID")
        _digest(self.accepted_result_sha256, "accepted_result_sha256")


@dataclass(frozen=True)
class SelectedVerificationPlan:
    catalogue: CatalogueIntegrityReceipt
    selection: VerificationSelection
    descriptors: tuple[WorkUnitDescriptor, ...]
    prerequisites: tuple[PrerequisiteEvidence, ...]

    def __post_init__(self) -> None:
        _base._exact_type(self.catalogue, CatalogueIntegrityReceipt, "catalogue")
        _base._exact_type(self.selection, VerificationSelection, "selection")
        if self.selection.catalogue_sha256 != self.catalogue.sha256:
            raise ContractViolation("selection catalogue identity mismatch")
        descriptors = _tuple(self.descriptors, WorkUnitDescriptor, "selected descriptors", nonempty=True)
        _unique(tuple(item.issue for item in descriptors), "selected descriptor issue")
        if set(self.selection.issues) != {item.issue for item in descriptors}:
            raise ContractViolation("selected descriptor denominator mismatch")
        rows = {row.issue: row for row in self.catalogue.rows}
        active = {row.issue for row in rows.values() if row.disposition in
                  (CatalogueDisposition.ASSIGNED, CatalogueDisposition.BLOCKED, CatalogueDisposition.PLANNED)}
        if self.selection.scope is SelectionScope.FULL_PROJECT and set(self.selection.issues) != active:
            raise ContractViolation("subset cannot claim full-project selection")
        required = set()
        for desc in descriptors:
            row = rows.get(desc.issue)
            if row is None or row.descriptor != desc or row.disposition is not CatalogueDisposition.ASSIGNED:
                raise ContractViolation("selected row is not an assigned matching descriptor")
            required.update(row.prerequisites)
        evidence = _tuple(self.prerequisites, PrerequisiteEvidence, "prerequisite evidence")
        _unique(tuple(item.source.issue for item in evidence), "prerequisite evidence")
        if {item.source.issue for item in evidence} != required:
            raise ContractViolation("selected prerequisite denominator mismatch")
        for item in evidence:
            row = rows[item.source.issue]
            if (row.disposition is not CatalogueDisposition.ACCEPTED_HISTORICAL
                    or item.source.body_sha256 != row.body_sha256 or item.source.unit != row.unit):
                raise ContractViolation("prerequisite is not matching accepted historical evidence")
            if row.descriptor is not None:
                _binding(item.source, row.descriptor)
        object.__setattr__(self, "descriptors", tuple(sorted(descriptors, key=lambda desc: desc.issue)))
        object.__setattr__(self, "prerequisites", tuple(sorted(evidence, key=lambda item: item.source.issue)))

    @property
    def matrix_cases(self) -> int:
        return sum(desc.matrix_cases for desc in self.descriptors)

    @property
    def sha256(self) -> str:
        # No self-digest field or future integration commit is hashed here.
        return canonical_sha256({"schema": CONTRACT_SCHEMA_REVISION, "kind": "selection", "payload": self})


@dataclass(frozen=True)
class VerificationEvidence:
    source_shape: SourceShapeGateReceipt
    case_accounting: CaseAccountingReceipt
    workspace: WorkspaceAdmissionReceipt
    package: PackageGateReceipt | None

    def __post_init__(self) -> None:
        _base._exact_type(self.source_shape, SourceShapeGateReceipt, "source_shape")
        _base._exact_type(self.workspace, WorkspaceAdmissionReceipt, "workspace")
        assignment, descriptor = self.source_shape.assignment, self.source_shape.descriptor
        _children(assignment, descriptor, self.source_shape, self.case_accounting)
        if self.workspace.assignment != assignment or self.workspace.descriptor != descriptor:
            raise ContractViolation("workspace evidence binding mismatch")
        if descriptor.package is None:
            if self.package is not None:
                raise ContractViolation("nonpackage descriptor cannot carry package evidence")
        else:
            _base._exact_type(self.package, PackageGateReceipt, "package")
            if (self.package.source_shape != self.source_shape or self.package.case_accounting != self.case_accounting
                    or self.package.assignment != assignment or self.package.descriptor != descriptor):
                raise ContractViolation("package evidence binding mismatch")

    @property
    def descriptor(self) -> WorkUnitDescriptor:
        return self.source_shape.descriptor

    @property
    def result(self) -> OverallResult:
        results = (self.source_shape.result, self.case_accounting.result, self.workspace.result)
        if self.package is not None:
            results += (self.package.result,)
        return _combine_results(results)


def cohort_digest(plan: SelectedVerificationPlan, rows: tuple[VerificationEvidence, ...]) -> str:
    _base._exact_type(plan, SelectedVerificationPlan, "plan")
    rows = _tuple(rows, VerificationEvidence, "execution rows")
    return canonical_sha256({"schema": CONTRACT_SCHEMA_REVISION, "kind": "execution-cohort",
                             "plan_sha256": plan.sha256,
                             "rows": tuple(sorted(rows, key=lambda row: row.descriptor.issue))})


@dataclass(frozen=True)
class CohortReceipt:
    plan: SelectedVerificationPlan
    rows: tuple[VerificationEvidence, ...]
    result: OverallResult
    aggregate_sha256: str

    def __post_init__(self) -> None:
        _base._exact_type(self.plan, SelectedVerificationPlan, "plan")
        rows = _tuple(self.rows, VerificationEvidence, "execution rows")
        _unique(tuple(row.descriptor.issue for row in rows), "cohort issue")
        expected = {desc.issue: desc for desc in self.plan.descriptors}
        for row in rows:
            if expected.get(row.descriptor.issue) != row.descriptor:
                raise ContractViolation("foreign or substituted execution descriptor")
        ordered = tuple(sorted(rows, key=lambda row: row.descriptor.issue))
        object.__setattr__(self, "rows", ordered)
        coverage = OverallResult.PASS if len(rows) == len(expected) else OverallResult.INCOMPLETE_EVIDENCE
        actual = _combine_results(tuple(row.result for row in rows) + (coverage,))
        _base._require_result(self.result, actual, "execution-cohort")
        _digest(self.aggregate_sha256, "aggregate_sha256")
        if self.aggregate_sha256 != cohort_digest(self.plan, ordered):
            raise ContractViolation("cohort aggregate digest mismatch")

    @property
    def matrix_cases(self) -> int:
        return sum(row.descriptor.matrix_cases for row in self.rows)

    @property
    def expected_matrix_cases(self) -> int:
        return self.plan.matrix_cases

    @property
    def proof_ceiling(self) -> ProofCeiling:
        return ProofCeiling("selected-verification-only")


# One current row owner; the old summary is available only by its explicit
# versioned name and cannot enter a current cohort.
CohortRow = VerificationEvidence
__all__ = tuple(_base.__all__) + (
    "AssignmentSourceUse", "VerificationPhase", "VerificationRequirements", "ExecutionBounds",
    "OfflineCaptureBinding", "GuardResult", "CatalogueDisposition", "CatalogueResult", "CatalogueRow",
    "CatalogueIntegrityReceipt", "SelectionScope", "VerificationSelection", "PrerequisiteEvidence",
    "SelectedVerificationPlan", "VerificationEvidence", "LegacyWorkUnitDescriptorV1",
    "LegacyAssignmentSourceReceiptV2", "LegacyCohortRowV2",
)
