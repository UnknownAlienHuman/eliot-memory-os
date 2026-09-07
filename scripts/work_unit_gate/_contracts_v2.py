"""Closed, immutable value contracts for the ELIOT work-unit gate.

This module deliberately contains no filesystem access, repository scan,
network client, subprocess runner, ambient clock, environment access, mutable
global state, or mutation API.  It is the neutral vocabulary shared by the
separately owned assignment-source, descriptor-runner, case-binding, cohort,
and final integration components.
"""
from __future__ import annotations
import dataclasses
import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Any, Mapping
WORK_UNIT_DESCRIPTOR_SCHEMA = 'eliot-work-unit-descriptor-v1'
RELATION_ROLE_WIRE_REVISION = 'hyphenated-v1'
CONTRACT_SCHEMA_REVISION = 'eliot-work-unit-contracts-v2'
MAX_TOKEN_BYTES = 128
MAX_TITLE_BYTES = 512
MAX_DIAGNOSTIC_BYTES = 1024
MAX_DIAGNOSTIC_FIELDS = 32
MAX_MATRIX_CASES = 100000
MAX_COHORT_ROWS = 10000
MAX_DESCRIPTOR_ROOTS = 256
MAX_CANONICAL_DEPTH = 64
MAX_CANONICAL_ITEMS = 100000
MAX_CANONICAL_TEXT_BYTES = 1048576
MAX_CANONICAL_BYTES = 8388608
MAX_CANONICAL_INTEGER_ABS = (1 << 127) - 1
_TOKEN = re.compile('^[A-Za-z0-9][A-Za-z0-9._:/+-]*$')
_GITHUB_SLUG = re.compile('^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$')
_SHA256 = re.compile('^[0-9a-f]{64}$')
_REMEDIATION_CODE = re.compile('^[A-Z][A-Z0-9_]{2,63}$')
_TEST_ID = re.compile('^[A-Za-z_][A-Za-z0-9_.:<>/-]{0,511}$')

class ContractViolation(ValueError):
    """A supplied value cannot represent a valid current gate contract."""

class _ClosedStringEnum(str, Enum):

    @classmethod
    def _missing_(cls, value: object) -> None:
        raise ContractViolation(f'unsupported {cls.__name__} value: {value!r}')

class SourceAuthority(_ClosedStringEnum):
    LIVE_GITHUB = 'live-github'
    EXPLICIT_OFFLINE_SNAPSHOT = 'explicit-offline-snapshot'

class IssueState(_ClosedStringEnum):
    OPEN = 'open'
    CLOSED = 'closed'
    SUPERSEDED = 'superseded'

class RelationRole(_ClosedStringEnum):
    IMPLEMENTS = 'implements'
    VERIFIED_BY = 'verified-by'
    INTEGRATED_BY = 'integrated-by'
    BLOCKED_BY = 'blocked-by'
    SUPERSEDES = 'supersedes'

class RunnerMode(_ClosedStringEnum):
    RUST_PACKAGE = 'rust-package'
    PYTHON_UNITTEST = 'python-unittest'
    METADATA_PYTHON = 'metadata-python'

class ExecutionDisposition(_ClosedStringEnum):
    DISCOVERED = 'discovered'
    EXECUTED_PASS = 'executed-pass'
    EXECUTED_FAIL = 'executed-fail'
    SKIPPED = 'skipped'
    IGNORED = 'ignored'
    CFG_DISABLED = 'cfg-disabled'
    TIMED_OUT = 'timed-out'
    UNAVAILABLE = 'unavailable'

class OverallResult(_ClosedStringEnum):
    PASS = 'pass'
    CONTRACT_FAILURE = 'contract-failure'
    CONFIGURATION_FAILURE = 'configuration-failure'
    INCOMPLETE_EVIDENCE = 'incomplete-evidence'

class FindingSeverity(_ClosedStringEnum):
    ERROR = 'error'
    WARNING = 'warning'
    OBSERVATION = 'observation'

class FindingClass(_ClosedStringEnum):
    INVALID_IDENTITY = 'invalid-identity'
    INVALID_DENOMINATOR = 'invalid-denominator'
    SOURCE_UNAVAILABLE = 'source-unavailable'
    DISCOVERY_MISMATCH = 'discovery-mismatch'
    EXECUTION_MISMATCH = 'execution-mismatch'
    CONTRACT_DEFECT = 'contract-defect'
    CONFIGURATION_DEFECT = 'configuration-defect'
    INCOMPLETE_EVIDENCE = 'incomplete-evidence'
    INTERNAL_DEFECT = 'internal-defect'

class WorkspaceDisposition(_ClosedStringEnum):
    MEMBER = 'member'
    EXCLUDED = 'excluded'
    STANDALONE = 'standalone'
    UNAVAILABLE = 'unavailable'
    CONFIGURATION_DEFECT = 'configuration-defect'

def _utf8_len(value: str) -> int:
    return len(value.encode('utf-8'))

def _bounded_text(value: object, field: str, limit: int) -> str:
    if not isinstance(value, str):
        raise ContractViolation(f'{field} must be text')
    if not value.strip():
        raise ContractViolation(f'{field} must be non-blank')
    if _utf8_len(value) > limit:
        raise ContractViolation(f'{field} exceeds {limit} UTF-8 bytes')
    if any((ord(char) < 32 and char not in '\t\n\r' for char in value)):
        raise ContractViolation(f'{field} contains a control character')
    return value

def _token(value: object, field: str, *, pattern: re.Pattern[str]=_TOKEN) -> str:
    text = _bounded_text(value, field, MAX_TOKEN_BYTES)
    if pattern.fullmatch(text) is None:
        raise ContractViolation(f'{field} has invalid token syntax')
    return text

def _positive(value: object, field: str, *, maximum: int | None=None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ContractViolation(f'{field} must be a positive integer')
    if maximum is not None and value > maximum:
        raise ContractViolation(f'{field} exceeds {maximum}')
    return value

def _sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ContractViolation(f'{field} must be lowercase SHA-256 hex')
    return value

def _exact_type(value: object, expected: type[Any], field: str) -> None:
    if type(value) is not expected:
        raise ContractViolation(f'{field} must be exactly {expected.__name__}')

def _tuple_of_exact(values: object, expected: type[Any], field: str, *, maximum: int, nonempty: bool=False) -> tuple[Any, ...]:
    if type(values) is not tuple:
        raise ContractViolation(f'{field} must be a tuple')
    if nonempty and (not values):
        raise ContractViolation(f'{field} cannot be empty')
    if len(values) > maximum:
        raise ContractViolation(f'{field} exceeds {maximum} members')
    for value in values:
        _exact_type(value, expected, field)
    return values

@dataclass(frozen=True, order=True)
class RepositoryIdentity:
    owner: str
    name: str

    def __post_init__(self) -> None:
        object.__setattr__(self, 'owner', _token(self.owner, 'owner', pattern=_GITHUB_SLUG))
        object.__setattr__(self, 'name', _token(self.name, 'name', pattern=_GITHUB_SLUG))

    @property
    def full_name(self) -> str:
        return f'{self.owner}/{self.name}'

@dataclass(frozen=True, order=True)
class IssueIdentity:
    repository: RepositoryIdentity
    number: int

    def __post_init__(self) -> None:
        _exact_type(self.repository, RepositoryIdentity, 'repository')
        object.__setattr__(self, 'number', _positive(self.number, 'issue number'))

@dataclass(frozen=True, order=True)
class PullRequestIdentity:
    repository: RepositoryIdentity
    number: int

    def __post_init__(self) -> None:
        _exact_type(self.repository, RepositoryIdentity, 'repository')
        object.__setattr__(self, 'number', _positive(self.number, 'pull request number'))

@dataclass(frozen=True, order=True)
class PackageIdentity:
    name: str

    def __post_init__(self) -> None:
        object.__setattr__(self, 'name', _token(self.name, 'package name'))

@dataclass(frozen=True, order=True)
class ModuleIdentity:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, 'value', _token(self.value, 'module identity'))

@dataclass(frozen=True, order=True)
class WorkUnitIdentity:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, 'value', _token(self.value, 'work-unit identity'))

@dataclass(frozen=True, order=True)
class DescriptorIdentity:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, 'value', _token(self.value, 'descriptor identity'))

@dataclass(frozen=True, order=True)
class ProofCeiling:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, 'value', _token(self.value, 'proof ceiling'))

@dataclass(frozen=True)
class AssignmentRelation:
    source_issue: IssueIdentity
    role: RelationRole
    target_issue: IssueIdentity

    def __post_init__(self) -> None:
        _exact_type(self.source_issue, IssueIdentity, 'source_issue')
        _exact_type(self.target_issue, IssueIdentity, 'target_issue')
        _exact_type(self.role, RelationRole, 'role')

@dataclass(frozen=True, order=True)
class CaseIdentity:
    issue: IssueIdentity
    number: int

    def __post_init__(self) -> None:
        _exact_type(self.issue, IssueIdentity, 'issue')
        object.__setattr__(self, 'number', _positive(self.number, 'case number', maximum=MAX_MATRIX_CASES))

    def require_within(self, denominator: int) -> None:
        checked = _positive(denominator, 'matrix denominator', maximum=MAX_MATRIX_CASES)
        if self.number > checked:
            raise ContractViolation(f'case {self.number} exceeds matrix denominator {checked}')

@dataclass(frozen=True, order=True)
class RepositoryPath:
    value: str

    def __post_init__(self) -> None:
        value = _bounded_text(self.value, 'repository path', 1024)
        if any((ord(char) < 32 for char in value)):
            raise ContractViolation('repository path contains a control character')
        if '\\' in value:
            raise ContractViolation('repository path must use forward slashes')
        if value.startswith('/') or value.startswith('//'):
            raise ContractViolation('repository path must be relative')
        if value.endswith('/'):
            raise ContractViolation('repository path cannot end with a separator')
        if '//' in value:
            raise ContractViolation('repository path contains a repeated separator')
        raw_parts = value.split('/')
        if not raw_parts or any((part in {'', '.', '..'} for part in raw_parts)):
            raise ContractViolation('repository path contains an invalid segment')
        if ':' in raw_parts[0]:
            raise ContractViolation('repository path cannot contain a drive prefix')
        path = PurePosixPath(value)
        if path.is_absolute() or path.as_posix() != value:
            raise ContractViolation('repository path is not canonical')
        object.__setattr__(self, 'value', value)

@dataclass(frozen=True, order=True)
class SourceLocation:
    path: RepositoryPath
    line: int
    column: int = 1

    def __post_init__(self) -> None:
        _exact_type(self.path, RepositoryPath, 'path')
        object.__setattr__(self, 'line', _positive(self.line, 'line'))
        object.__setattr__(self, 'column', _positive(self.column, 'column'))

@dataclass(frozen=True)
class TestIdentity:
    mode: RunnerMode
    qualified_name: str

    def __post_init__(self) -> None:
        _exact_type(self.mode, RunnerMode, 'mode')
        name = _bounded_text(self.qualified_name, 'qualified test identity', 512)
        if _TEST_ID.fullmatch(name) is None:
            raise ContractViolation('qualified test identity has invalid syntax')
        object.__setattr__(self, 'qualified_name', name)

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
    package: PackageIdentity | None = None
    module: ModuleIdentity | None = None

    def __post_init__(self) -> None:
        schema = _token(self.schema_version, 'descriptor schema version')
        if schema != WORK_UNIT_DESCRIPTOR_SCHEMA:
            raise ContractViolation(f'unsupported descriptor schema {schema!r}')
        _exact_type(self.identity, DescriptorIdentity, 'identity')
        _exact_type(self.issue, IssueIdentity, 'issue')
        _exact_type(self.unit, WorkUnitIdentity, 'unit')
        _exact_type(self.mode, RunnerMode, 'mode')
        _exact_type(self.proof_ceiling, ProofCeiling, 'proof_ceiling')
        if self.package is not None:
            _exact_type(self.package, PackageIdentity, 'package')
        if self.module is not None:
            _exact_type(self.module, ModuleIdentity, 'module')
        source_roots = _tuple_of_exact(self.source_roots, RepositoryPath, 'source_roots', maximum=MAX_DESCRIPTOR_ROOTS, nonempty=True)
        test_roots = _tuple_of_exact(self.test_roots, RepositoryPath, 'test_roots', maximum=MAX_DESCRIPTOR_ROOTS, nonempty=True)
        if len(set(source_roots)) != len(source_roots):
            raise ContractViolation('duplicate source root')
        if len(set(test_roots)) != len(test_roots):
            raise ContractViolation('duplicate test root')
        object.__setattr__(self, 'source_roots', tuple(sorted(source_roots)))
        object.__setattr__(self, 'test_roots', tuple(sorted(test_roots)))
        object.__setattr__(self, 'matrix_cases', _positive(self.matrix_cases, 'matrix_cases', maximum=MAX_MATRIX_CASES))

    @classmethod
    def from_mapping(cls, value: object) -> 'WorkUnitDescriptor':
        if not isinstance(value, Mapping):
            raise ContractViolation('descriptor input must be a mapping')
        allowed = {field.name for field in dataclasses.fields(cls)}
        unknown = [key for key in value if type(key) is not str or key not in allowed]
        unknown.sort(key=lambda key: (type(key).__name__, repr(key)))
        if unknown:
            raise ContractViolation('descriptor contains unknown or non-string fields: ' + ', '.join(map(str, unknown)))
        missing = sorted((field.name for field in dataclasses.fields(cls) if field.default is dataclasses.MISSING and field.default_factory is dataclasses.MISSING and (field.name not in value)))
        if missing:
            raise ContractViolation('descriptor is missing required fields: ' + ', '.join(missing))
        try:
            return cls(**dict(value))
        except ContractViolation:
            raise
        except (TypeError, ValueError) as error:
            raise ContractViolation(f'invalid descriptor input: {error}') from error

    @property
    def sha256(self) -> str:
        return canonical_sha256(self)

@dataclass(frozen=True)
class CaseMarker:
    case: CaseIdentity
    test: TestIdentity
    location: SourceLocation

    def __post_init__(self) -> None:
        _exact_type(self.case, CaseIdentity, 'case')
        _exact_type(self.test, TestIdentity, 'test')
        _exact_type(self.location, SourceLocation, 'location')

@dataclass(frozen=True)
class DiscoveredTestReceipt:
    descriptor: DescriptorIdentity
    descriptor_sha256: str
    test: TestIdentity
    location: SourceLocation

    def __post_init__(self) -> None:
        _exact_type(self.descriptor, DescriptorIdentity, 'descriptor')
        object.__setattr__(self, 'descriptor_sha256', _sha256(self.descriptor_sha256, 'descriptor_sha256'))
        _exact_type(self.test, TestIdentity, 'test')
        _exact_type(self.location, SourceLocation, 'location')

@dataclass(frozen=True)
class TestExecutionRecord:
    """Execution result, optionally bound to an exact discovery receipt.

    The first three fields preserve the #853 constructor shape.  Current
    case-accounting receipts require ``discovery`` and reject unbound legacy
    records rather than interpreting them as stronger evidence.
    """
    test: TestIdentity
    disposition: ExecutionDisposition
    detail: str | None = None
    discovery: DiscoveredTestReceipt | None = None

    def __post_init__(self) -> None:
        _exact_type(self.test, TestIdentity, 'test')
        _exact_type(self.disposition, ExecutionDisposition, 'disposition')
        if self.detail is not None:
            object.__setattr__(self, 'detail', _bounded_text(self.detail, 'execution detail', MAX_DIAGNOSTIC_BYTES))
        if self.discovery is not None:
            _exact_type(self.discovery, DiscoveredTestReceipt, 'discovery')
            if self.discovery.test != self.test:
                raise ContractViolation('execution test does not match discovery test')
TestExecutionReceipt = TestExecutionRecord

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
    live_etag: str | None = None
    snapshot_sha256: str | None = None

    def __post_init__(self) -> None:
        _exact_type(self.issue, IssueIdentity, 'issue')
        _exact_type(self.state, IssueState, 'state')
        _exact_type(self.unit, WorkUnitIdentity, 'unit')
        _exact_type(self.authority, SourceAuthority, 'authority')
        _exact_type(self.proof_ceiling, ProofCeiling, 'proof_ceiling')
        object.__setattr__(self, 'title', _bounded_text(self.title, 'title', MAX_TITLE_BYTES))
        object.__setattr__(self, 'body_sha256', _sha256(self.body_sha256, 'body_sha256'))
        object.__setattr__(self, 'matrix_cases', _positive(self.matrix_cases, 'matrix_cases', maximum=MAX_MATRIX_CASES))
        if self.live_etag is not None:
            object.__setattr__(self, 'live_etag', _bounded_text(self.live_etag, 'live_etag', MAX_TOKEN_BYTES))
        if self.snapshot_sha256 is not None:
            object.__setattr__(self, 'snapshot_sha256', _sha256(self.snapshot_sha256, 'snapshot_sha256'))
        if self.authority is SourceAuthority.LIVE_GITHUB:
            if self.snapshot_sha256 is not None:
                raise ContractViolation('live source cannot carry an offline snapshot digest')
        elif self.authority is SourceAuthority.EXPLICIT_OFFLINE_SNAPSHOT:
            if self.snapshot_sha256 is None:
                raise ContractViolation('offline source requires snapshot_sha256')
            if self.live_etag is not None:
                raise ContractViolation('offline source cannot carry a live ETag')

@dataclass(frozen=True)
class CaseAccountingMember:
    case: CaseIdentity
    marker: CaseMarker
    execution: TestExecutionRecord

    def __post_init__(self) -> None:
        _exact_type(self.case, CaseIdentity, 'case')
        _exact_type(self.marker, CaseMarker, 'marker')
        _exact_type(self.execution, TestExecutionRecord, 'execution')
        if self.marker.case != self.case:
            raise ContractViolation('marker case does not match member case')
        if self.marker.test != self.execution.test:
            raise ContractViolation('marker test does not match execution test')
        discovery = self.execution.discovery
        if discovery is None:
            raise ContractViolation('case accounting requires an exact discovery receipt')
        if discovery.test != self.marker.test:
            raise ContractViolation('discovery test does not match marker test')
        if discovery.location != self.marker.location:
            raise ContractViolation('discovery location does not match marker location')

@dataclass(frozen=True)
class RemediationCode:
    value: str

    def __post_init__(self) -> None:
        value = _bounded_text(self.value, 'remediation code', 64)
        if _REMEDIATION_CODE.fullmatch(value) is None:
            raise ContractViolation('remediation code must use stable uppercase syntax')
        object.__setattr__(self, 'value', value)

@dataclass(frozen=True)
class Finding:
    severity: FindingSeverity
    finding_class: FindingClass
    owner: WorkUnitIdentity
    remediation: RemediationCode
    message: str

    def __post_init__(self) -> None:
        _exact_type(self.severity, FindingSeverity, 'severity')
        _exact_type(self.finding_class, FindingClass, 'finding_class')
        _exact_type(self.owner, WorkUnitIdentity, 'owner')
        _exact_type(self.remediation, RemediationCode, 'remediation')
        object.__setattr__(self, 'message', _bounded_text(self.message, 'finding message', MAX_DIAGNOSTIC_BYTES))

def _finding_sort_key(finding: Finding) -> tuple[str, str, str, str, str]:
    return (finding.severity.value, finding.finding_class.value, finding.owner.value, finding.remediation.value, finding.message)

def _normalize_findings(values: object) -> tuple[Finding, ...]:
    findings = _tuple_of_exact(values, Finding, 'findings', maximum=MAX_DIAGNOSTIC_FIELDS)
    return tuple(sorted(findings, key=_finding_sort_key))

def _result_from_findings(findings: tuple[Finding, ...]) -> OverallResult:
    errors = [item for item in findings if item.severity is FindingSeverity.ERROR]
    if any((item.finding_class in {FindingClass.CONFIGURATION_DEFECT, FindingClass.INTERNAL_DEFECT} for item in errors)):
        return OverallResult.CONFIGURATION_FAILURE
    if any((item.finding_class in {FindingClass.SOURCE_UNAVAILABLE, FindingClass.INCOMPLETE_EVIDENCE} for item in errors)):
        return OverallResult.INCOMPLETE_EVIDENCE
    if errors:
        return OverallResult.CONTRACT_FAILURE
    return OverallResult.PASS

def _require_result(actual: OverallResult, expected: OverallResult, owner: str) -> None:
    _exact_type(actual, OverallResult, 'result')
    if actual is not expected:
        raise ContractViolation(f'{owner} result {actual.value!r} contradicts evidence; expected {expected.value!r}')

@dataclass(frozen=True)
class CaseAccountingReceipt:
    assignment: AssignmentSourceReceipt
    descriptor: WorkUnitDescriptor
    members: tuple[CaseAccountingMember, ...]
    result: OverallResult
    proof_ceiling: ProofCeiling
    findings: tuple[Finding, ...] = ()

    def __post_init__(self) -> None:
        _exact_type(self.assignment, AssignmentSourceReceipt, 'assignment')
        _exact_type(self.descriptor, WorkUnitDescriptor, 'descriptor')
        _exact_type(self.result, OverallResult, 'result')
        _exact_type(self.proof_ceiling, ProofCeiling, 'proof_ceiling')
        if self.assignment.issue != self.descriptor.issue:
            raise ContractViolation('assignment issue does not match descriptor')
        if self.assignment.unit != self.descriptor.unit:
            raise ContractViolation('assignment unit does not match descriptor')
        if self.assignment.matrix_cases != self.descriptor.matrix_cases:
            raise ContractViolation('assignment matrix denominator does not match descriptor')
        if self.proof_ceiling != self.descriptor.proof_ceiling:
            raise ContractViolation('case-accounting proof ceiling does not match descriptor')
        members = _tuple_of_exact(self.members, CaseAccountingMember, 'members', maximum=MAX_MATRIX_CASES)
        ordered = tuple(sorted(members, key=lambda item: item.case.number))
        object.__setattr__(self, 'members', ordered)
        findings = _normalize_findings(self.findings)
        object.__setattr__(self, 'findings', findings)
        numbers: list[int] = []
        tests: list[TestIdentity] = []
        for member in ordered:
            if member.case.issue != self.assignment.issue:
                raise ContractViolation('member issue does not match assignment issue')
            member.case.require_within(self.assignment.matrix_cases)
            discovery = member.execution.discovery
            if discovery is None:
                raise ContractViolation('case member lost its required discovery receipt')
            if discovery.descriptor != self.descriptor.identity:
                raise ContractViolation('member discovery descriptor identity does not match')
            if discovery.descriptor_sha256 != self.descriptor.sha256:
                raise ContractViolation('member discovery descriptor digest does not match')
            numbers.append(member.case.number)
            tests.append(member.execution.test)
        if len(numbers) != len(set(numbers)):
            raise ContractViolation('duplicate case-accounting member')
        if len(tests) != len(set(tests)):
            raise ContractViolation('one test identity cannot cover multiple cases')
        configuration_errors = any((item.severity is FindingSeverity.ERROR and item.finding_class in {FindingClass.CONFIGURATION_DEFECT, FindingClass.INTERNAL_DEFECT} for item in findings))
        other_contract_errors = any((item.severity is FindingSeverity.ERROR and item.finding_class not in {FindingClass.CONFIGURATION_DEFECT, FindingClass.INTERNAL_DEFECT, FindingClass.SOURCE_UNAVAILABLE, FindingClass.INCOMPLETE_EVIDENCE} for item in findings))
        expected_numbers = list(range(1, self.assignment.matrix_cases + 1))
        complete = numbers == expected_numbers
        dispositions = [member.execution.disposition for member in ordered]
        if configuration_errors:
            expected_result = OverallResult.CONFIGURATION_FAILURE
        elif ExecutionDisposition.EXECUTED_FAIL in dispositions or other_contract_errors:
            expected_result = OverallResult.CONTRACT_FAILURE
        elif self.assignment.state is IssueState.OPEN and complete and dispositions and all((disposition is ExecutionDisposition.EXECUTED_PASS for disposition in dispositions)):
            expected_result = OverallResult.PASS
        else:
            expected_result = OverallResult.INCOMPLETE_EVIDENCE
        _require_result(self.result, expected_result, 'case-accounting')

@dataclass(frozen=True)
class SourceShapeGateReceipt:
    assignment: AssignmentSourceReceipt
    descriptor: WorkUnitDescriptor
    result: OverallResult
    findings: tuple[Finding, ...]
    proof_ceiling: ProofCeiling

    def __post_init__(self) -> None:
        _exact_type(self.assignment, AssignmentSourceReceipt, 'assignment')
        _exact_type(self.descriptor, WorkUnitDescriptor, 'descriptor')
        _exact_type(self.result, OverallResult, 'result')
        _exact_type(self.proof_ceiling, ProofCeiling, 'proof_ceiling')
        if self.assignment.issue != self.descriptor.issue:
            raise ContractViolation('source-shape issue does not match descriptor')
        if self.assignment.unit != self.descriptor.unit:
            raise ContractViolation('source-shape unit does not match descriptor')
        if self.proof_ceiling != self.descriptor.proof_ceiling:
            raise ContractViolation('source-shape proof ceiling does not match')
        findings = _normalize_findings(self.findings)
        object.__setattr__(self, 'findings', findings)
        expected = _result_from_findings(findings)
        if self.assignment.state is not IssueState.OPEN and expected is OverallResult.PASS:
            expected = OverallResult.INCOMPLETE_EVIDENCE
        _require_result(self.result, expected, 'source-shape')

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
        _exact_type(self.assignment, AssignmentSourceReceipt, 'assignment')
        _exact_type(self.descriptor, WorkUnitDescriptor, 'descriptor')
        _exact_type(self.package, PackageIdentity, 'package')
        if self.module is not None:
            _exact_type(self.module, ModuleIdentity, 'module')
        _exact_type(self.source_shape, SourceShapeGateReceipt, 'source_shape')
        _exact_type(self.case_accounting, CaseAccountingReceipt, 'case_accounting')
        _exact_type(self.result, OverallResult, 'result')
        _exact_type(self.proof_ceiling, ProofCeiling, 'proof_ceiling')
        if self.descriptor.package != self.package:
            raise ContractViolation('package does not match descriptor package')
        if self.descriptor.module != self.module:
            raise ContractViolation('module does not match descriptor module')
        if self.source_shape.assignment != self.assignment:
            raise ContractViolation('source-shape assignment does not match package')
        if self.case_accounting.assignment != self.assignment:
            raise ContractViolation('case assignment does not match package')
        if self.source_shape.descriptor != self.descriptor:
            raise ContractViolation('source-shape descriptor does not match package')
        if self.case_accounting.descriptor != self.descriptor:
            raise ContractViolation('case descriptor does not match package')
        if self.proof_ceiling != self.descriptor.proof_ceiling:
            raise ContractViolation('package proof ceiling does not match descriptor')
        findings = _normalize_findings(self.findings)
        object.__setattr__(self, 'findings', findings)
        own = _result_from_findings(findings)
        child_results = {own, self.source_shape.result, self.case_accounting.result}
        if OverallResult.CONFIGURATION_FAILURE in child_results:
            expected = OverallResult.CONFIGURATION_FAILURE
        elif OverallResult.CONTRACT_FAILURE in child_results:
            expected = OverallResult.CONTRACT_FAILURE
        elif OverallResult.INCOMPLETE_EVIDENCE in child_results:
            expected = OverallResult.INCOMPLETE_EVIDENCE
        else:
            expected = OverallResult.PASS
        _require_result(self.result, expected, 'package')

@dataclass(frozen=True)
class WorkspaceAdmissionReceipt:
    assignment: AssignmentSourceReceipt
    descriptor: WorkUnitDescriptor
    package: PackageIdentity
    module: ModuleIdentity | None
    disposition: WorkspaceDisposition
    result: OverallResult
    findings: tuple[Finding, ...]
    proof_ceiling: ProofCeiling

    def __post_init__(self) -> None:
        _exact_type(self.assignment, AssignmentSourceReceipt, 'assignment')
        _exact_type(self.descriptor, WorkUnitDescriptor, 'descriptor')
        _exact_type(self.package, PackageIdentity, 'package')
        if self.module is not None:
            _exact_type(self.module, ModuleIdentity, 'module')
        _exact_type(self.disposition, WorkspaceDisposition, 'disposition')
        _exact_type(self.result, OverallResult, 'result')
        _exact_type(self.proof_ceiling, ProofCeiling, 'proof_ceiling')
        if self.assignment.issue != self.descriptor.issue:
            raise ContractViolation('workspace issue does not match descriptor')
        if self.assignment.unit != self.descriptor.unit:
            raise ContractViolation('workspace unit does not match descriptor')
        if self.descriptor.package != self.package:
            raise ContractViolation('workspace package does not match descriptor')
        if self.descriptor.module != self.module:
            raise ContractViolation('workspace module does not match descriptor')
        if self.proof_ceiling != self.descriptor.proof_ceiling:
            raise ContractViolation('workspace proof ceiling does not match descriptor')
        findings = _normalize_findings(self.findings)
        object.__setattr__(self, 'findings', findings)
        own = _result_from_findings(findings)
        if self.disposition is WorkspaceDisposition.CONFIGURATION_DEFECT:
            expected = OverallResult.CONFIGURATION_FAILURE
        elif own in {OverallResult.CONFIGURATION_FAILURE, OverallResult.CONTRACT_FAILURE}:
            expected = own
        elif self.disposition is WorkspaceDisposition.MEMBER:
            expected = OverallResult.PASS
        else:
            expected = OverallResult.INCOMPLETE_EVIDENCE
        _require_result(self.result, expected, 'workspace-admission')

@dataclass(frozen=True)
class ComponentGateReceipt:
    """A bounded generic summary; not a package/workspace evidence substitute."""
    component: str
    result: OverallResult
    findings: tuple[Finding, ...]
    proof_ceiling: ProofCeiling

    def __post_init__(self) -> None:
        object.__setattr__(self, 'component', _token(self.component, 'component'))
        _exact_type(self.result, OverallResult, 'result')
        _exact_type(self.proof_ceiling, ProofCeiling, 'proof_ceiling')
        findings = _normalize_findings(self.findings)
        object.__setattr__(self, 'findings', findings)
        expected = _result_from_findings(findings)
        _require_result(self.result, expected, 'component-summary')

@dataclass(frozen=True)
class CohortRow:
    issue: IssueIdentity
    unit: WorkUnitIdentity
    mode: RunnerMode
    matrix_cases: int
    descriptor_sha256: str
    descriptor: DescriptorIdentity | None = None
    result: OverallResult = OverallResult.INCOMPLETE_EVIDENCE

    def __post_init__(self) -> None:
        _exact_type(self.issue, IssueIdentity, 'issue')
        _exact_type(self.unit, WorkUnitIdentity, 'unit')
        _exact_type(self.mode, RunnerMode, 'mode')
        object.__setattr__(self, 'matrix_cases', _positive(self.matrix_cases, 'matrix_cases', maximum=MAX_MATRIX_CASES))
        object.__setattr__(self, 'descriptor_sha256', _sha256(self.descriptor_sha256, 'descriptor_sha256'))
        if self.descriptor is not None:
            _exact_type(self.descriptor, DescriptorIdentity, 'descriptor')
        _exact_type(self.result, OverallResult, 'result')
        if self.result is OverallResult.PASS and self.descriptor is None:
            raise ContractViolation('passing cohort row requires descriptor identity')

def _cohort_row_key(row: CohortRow) -> tuple[str, str, int, str, str]:
    return (row.issue.repository.full_name, row.unit.value, row.issue.number, row.descriptor_sha256, row.mode.value)

def cohort_digest(rows: tuple[CohortRow, ...], expected_rows: int, expected_matrix_cases: int, expected_descriptor_sha256s: tuple[str, ...], proof_ceiling: ProofCeiling) -> str:
    _exact_type(proof_ceiling, ProofCeiling, 'proof_ceiling')
    checked_rows = _tuple_of_exact(rows, CohortRow, 'rows', maximum=MAX_COHORT_ROWS, nonempty=True)
    expected_rows = _positive(expected_rows, 'expected_rows', maximum=MAX_COHORT_ROWS)
    expected_matrix_cases = _positive(expected_matrix_cases, 'expected_matrix_cases', maximum=MAX_MATRIX_CASES * MAX_COHORT_ROWS)
    if type(expected_descriptor_sha256s) is not tuple:
        raise ContractViolation('expected descriptor denominator must be a tuple')
    digests = tuple(sorted((_sha256(value, 'expected descriptor digest') for value in expected_descriptor_sha256s)))
    if len(digests) != len(set(digests)):
        raise ContractViolation('duplicate expected descriptor digest')
    payload = {'schema_revision': CONTRACT_SCHEMA_REVISION, 'rows': tuple(sorted(checked_rows, key=_cohort_row_key)), 'expected_rows': expected_rows, 'expected_matrix_cases': expected_matrix_cases, 'expected_descriptor_sha256s': digests, 'proof_ceiling': proof_ceiling}
    return canonical_sha256(payload)

@dataclass(frozen=True)
class CohortReceipt:
    rows: tuple[CohortRow, ...]
    result: OverallResult
    proof_ceiling: ProofCeiling
    expected_rows: int | None = None
    expected_matrix_cases: int | None = None
    aggregate_sha256: str | None = None
    expected_descriptor_sha256s: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _exact_type(self.result, OverallResult, 'result')
        _exact_type(self.proof_ceiling, ProofCeiling, 'proof_ceiling')
        rows = _tuple_of_exact(self.rows, CohortRow, 'rows', maximum=MAX_COHORT_ROWS, nonempty=True)
        ordered = tuple(sorted(rows, key=_cohort_row_key))
        object.__setattr__(self, 'rows', ordered)
        if len({row.issue for row in ordered}) != len(ordered):
            raise ContractViolation('duplicate cohort issue identity')
        if len({row.unit for row in ordered}) != len(ordered):
            raise ContractViolation('duplicate cohort work-unit identity')
        if len({row.descriptor_sha256 for row in ordered}) != len(ordered):
            raise ContractViolation('duplicate cohort descriptor digest')
        if type(self.expected_descriptor_sha256s) is not tuple:
            raise ContractViolation('expected descriptor denominator must be a tuple')
        denominator = tuple(sorted((_sha256(value, 'expected descriptor digest') for value in self.expected_descriptor_sha256s)))
        if len(denominator) != len(set(denominator)):
            raise ContractViolation('duplicate expected descriptor digest')
        object.__setattr__(self, 'expected_descriptor_sha256s', denominator)
        if self.expected_rows is not None:
            object.__setattr__(self, 'expected_rows', _positive(self.expected_rows, 'expected_rows', maximum=MAX_COHORT_ROWS))
        if self.expected_matrix_cases is not None:
            object.__setattr__(self, 'expected_matrix_cases', _positive(self.expected_matrix_cases, 'expected_matrix_cases', maximum=MAX_MATRIX_CASES * MAX_COHORT_ROWS))
        if self.aggregate_sha256 is not None:
            object.__setattr__(self, 'aggregate_sha256', _sha256(self.aggregate_sha256, 'aggregate_sha256'))
        actual_descriptor_digests = tuple(sorted((row.descriptor_sha256 for row in ordered)))
        if self.expected_rows is not None and self.expected_rows != len(ordered):
            raise ContractViolation('cohort row denominator mismatch')
        if self.expected_matrix_cases is not None and self.expected_matrix_cases != self.matrix_cases:
            raise ContractViolation('cohort matrix arithmetic mismatch')
        if denominator and actual_descriptor_digests != denominator:
            raise ContractViolation('cohort descriptor denominator mismatch')
        if self.aggregate_sha256 is not None:
            if self.expected_rows is None or self.expected_matrix_cases is None or (not denominator):
                raise ContractViolation('cohort digest requires exact denominator and arithmetic')
            calculated = cohort_digest(ordered, self.expected_rows, self.expected_matrix_cases, denominator, self.proof_ceiling)
            if self.aggregate_sha256 != calculated:
                raise ContractViolation('cohort aggregate digest mismatch')
        if self.result is OverallResult.PASS:
            if self.expected_rows is None or self.expected_matrix_cases is None or self.aggregate_sha256 is None or (not denominator):
                raise ContractViolation('passing cohort requires exact denominator, arithmetic, and digest')
            if any((row.result is not OverallResult.PASS for row in ordered)):
                raise ContractViolation('passing cohort requires every row to pass')
            if any((row.descriptor is None for row in ordered)):
                raise ContractViolation('passing cohort requires every descriptor identity')

    @property
    def matrix_cases(self) -> int:
        return sum((row.matrix_cases for row in self.rows))

@dataclass(frozen=True)
class BoundedDiagnostic:
    summary: str
    fields: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, 'summary', _bounded_text(self.summary, 'diagnostic summary', MAX_DIAGNOSTIC_BYTES))
        if type(self.fields) is not tuple:
            raise ContractViolation('diagnostic fields must be a tuple')
        if len(self.fields) > MAX_DIAGNOSTIC_FIELDS:
            raise ContractViolation('too many diagnostic fields')
        normalized: list[tuple[str, str]] = []
        for index, entry in enumerate(self.fields):
            if type(entry) is not tuple or len(entry) != 2:
                raise ContractViolation(f'diagnostic field {index} must be a two-item tuple')
            key, value = entry
            normalized.append((_token(key, 'diagnostic field key'), _bounded_text(value, 'diagnostic field value', MAX_DIAGNOSTIC_BYTES)))
        if len({key for key, _ in normalized}) != len(normalized):
            raise ContractViolation('duplicate diagnostic field')
        object.__setattr__(self, 'fields', tuple(sorted(normalized)))

def _canonical_value(value: Any, *, depth: int=0, stack: set[int] | None=None) -> Any:
    if depth > MAX_CANONICAL_DEPTH:
        raise ContractViolation('canonical value exceeds maximum depth')
    if stack is None:
        stack = set()
    track = dataclasses.is_dataclass(value) and (not isinstance(value, type))
    track = track or isinstance(value, (Mapping, set, frozenset, tuple, list))
    identity = id(value)
    if track:
        if identity in stack:
            raise ContractViolation('canonical value contains a cycle')
        stack.add(identity)
    try:
        if dataclasses.is_dataclass(value) and (not isinstance(value, type)):
            fields = dataclasses.fields(value)
            if len(fields) > MAX_CANONICAL_ITEMS:
                raise ContractViolation('canonical dataclass has too many fields')
            return {field.name: _canonical_value(getattr(value, field.name), depth=depth + 1, stack=stack) for field in fields}
        if isinstance(value, Enum):
            return _canonical_value(value.value, depth=depth + 1, stack=stack)
        if isinstance(value, Mapping):
            if len(value) > MAX_CANONICAL_ITEMS:
                raise ContractViolation('canonical mapping has too many items')
            normalized: dict[str, Any] = {}
            for key, item in value.items():
                if type(key) is not str:
                    raise ContractViolation('canonical mapping keys must be exact strings')
                if _utf8_len(key) > MAX_CANONICAL_TEXT_BYTES:
                    raise ContractViolation('canonical mapping key exceeds byte bound')
                if any((ord(char) < 32 for char in key)):
                    raise ContractViolation('canonical mapping key contains a control character')
                if key in normalized:
                    raise ContractViolation('duplicate canonical mapping key')
                normalized[key] = _canonical_value(item, depth=depth + 1, stack=stack)
            return {key: normalized[key] for key in sorted(normalized)}
        if isinstance(value, (set, frozenset)):
            if len(value) > MAX_CANONICAL_ITEMS:
                raise ContractViolation('canonical set has too many items')
            normalized = [_canonical_value(item, depth=depth + 1, stack=stack) for item in value]
            keyed = [(json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(',', ':')), item) for item in normalized]
            if len({key for key, _ in keyed}) != len(keyed):
                raise ContractViolation('distinct set members collapse to one canonical identity')
            return [item for _, item in sorted(keyed, key=lambda pair: pair[0])]
        if isinstance(value, (tuple, list)):
            if len(value) > MAX_CANONICAL_ITEMS:
                raise ContractViolation('canonical sequence has too many items')
            return [_canonical_value(item, depth=depth + 1, stack=stack) for item in value]
        if isinstance(value, str):
            if _utf8_len(value) > MAX_CANONICAL_TEXT_BYTES:
                raise ContractViolation('canonical text exceeds byte bound')
            return value
        if type(value) is int:
            if abs(value) > MAX_CANONICAL_INTEGER_ABS:
                raise ContractViolation('canonical integer exceeds bound')
            return value
        if value is None or type(value) is bool:
            return value
        raise ContractViolation(f'unsupported canonical value type: {type(value).__name__}')
    finally:
        if track:
            stack.remove(identity)

def canonical_bytes(value: Any) -> bytes:
    """Return bounded deterministic UTF-8 JSON bytes for a contract value."""
    try:
        encoded = json.dumps(_canonical_value(value), ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
    except ContractViolation:
        raise
    except (TypeError, ValueError, RecursionError) as error:
        raise ContractViolation(f'cannot canonicalize value: {error}') from error
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise ContractViolation('canonical bytes exceed output bound')
    return encoded

def canonical_sha256(value: Any) -> str:
    """Return SHA-256 of :func:`canonical_bytes`."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
__all__ = ['AssignmentRelation', 'AssignmentSourceReceipt', 'BoundedDiagnostic', 'CONTRACT_SCHEMA_REVISION', 'CaseAccountingMember', 'CaseAccountingReceipt', 'CaseIdentity', 'CaseMarker', 'CohortReceipt', 'CohortRow', 'ComponentGateReceipt', 'ContractViolation', 'DescriptorIdentity', 'DiscoveredTestReceipt', 'ExecutionDisposition', 'Finding', 'FindingClass', 'FindingSeverity', 'IssueIdentity', 'IssueState', 'MAX_CANONICAL_BYTES', 'MAX_CANONICAL_DEPTH', 'MAX_CANONICAL_INTEGER_ABS', 'MAX_CANONICAL_ITEMS', 'MAX_CANONICAL_TEXT_BYTES', 'MAX_COHORT_ROWS', 'MAX_DESCRIPTOR_ROOTS', 'MAX_DIAGNOSTIC_BYTES', 'MAX_DIAGNOSTIC_FIELDS', 'MAX_MATRIX_CASES', 'MAX_TITLE_BYTES', 'MAX_TOKEN_BYTES', 'ModuleIdentity', 'OverallResult', 'PackageGateReceipt', 'PackageIdentity', 'ProofCeiling', 'PullRequestIdentity', 'RELATION_ROLE_WIRE_REVISION', 'RelationRole', 'RemediationCode', 'RepositoryIdentity', 'RepositoryPath', 'RunnerMode', 'SourceAuthority', 'SourceLocation', 'SourceShapeGateReceipt', 'TestExecutionReceipt', 'TestExecutionRecord', 'TestIdentity', 'WORK_UNIT_DESCRIPTOR_SCHEMA', 'WorkUnitDescriptor', 'WorkUnitIdentity', 'WorkspaceAdmissionReceipt', 'WorkspaceDisposition', 'canonical_bytes', 'canonical_sha256', 'cohort_digest']