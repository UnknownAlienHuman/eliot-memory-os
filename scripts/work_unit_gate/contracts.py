"""Closed, immutable value contracts for the ELIOT work-unit gate.

This module deliberately contains no filesystem, network, subprocess, clock,
environment, or repository mutation logic. It is the neutral vocabulary used
by separately owned assignment-source, runner, case-binding, cohort, and CLI
components.
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

MAX_TOKEN_BYTES = 128
MAX_TITLE_BYTES = 512
MAX_DIAGNOSTIC_BYTES = 1_024
MAX_DIAGNOSTIC_FIELDS = 32
MAX_MATRIX_CASES = 100_000
MAX_COHORT_ROWS = 10_000

_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]*$")
_GITHUB_SLUG = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REMEDIATION_CODE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
_TEST_ID = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:<>/-]{0,511}$")


class ContractViolation(ValueError):
    """A supplied value cannot represent a valid current gate contract."""


class SourceAuthority(str, Enum):
    LIVE_GITHUB = "live-github"
    EXPLICIT_OFFLINE_SNAPSHOT = "explicit-offline-snapshot"


class IssueState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    SUPERSEDED = "superseded"


class RelationRole(str, Enum):
    IMPLEMENTS = "implements"
    VERIFIED_BY = "verified-by"
    INTEGRATED_BY = "integrated-by"
    BLOCKED_BY = "blocked-by"
    SUPERSEDES = "supersedes"


class RunnerMode(str, Enum):
    RUST_PACKAGE = "rust-package"
    PYTHON_UNITTEST = "python-unittest"
    METADATA_PYTHON = "metadata-python"


class ExecutionDisposition(str, Enum):
    DISCOVERED = "discovered"
    EXECUTED_PASS = "executed-pass"
    EXECUTED_FAIL = "executed-fail"
    SKIPPED = "skipped"
    IGNORED = "ignored"
    CFG_DISABLED = "cfg-disabled"
    TIMED_OUT = "timed-out"
    UNAVAILABLE = "unavailable"


class OverallResult(str, Enum):
    PASS = "pass"
    CONTRACT_FAILURE = "contract-failure"
    CONFIGURATION_FAILURE = "configuration-failure"
    INCOMPLETE_EVIDENCE = "incomplete-evidence"


class FindingSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    OBSERVATION = "observation"


class FindingClass(str, Enum):
    INVALID_IDENTITY = "invalid-identity"
    INVALID_DENOMINATOR = "invalid-denominator"
    SOURCE_UNAVAILABLE = "source-unavailable"
    DISCOVERY_MISMATCH = "discovery-mismatch"
    EXECUTION_MISMATCH = "execution-mismatch"
    CONFIGURATION_DEFECT = "configuration-defect"
    INCOMPLETE_EVIDENCE = "incomplete-evidence"
    INTERNAL_DEFECT = "internal-defect"


def _utf8_len(value: str) -> int:
    return len(value.encode("utf-8"))


def _bounded_text(value: str, field: str, limit: int) -> str:
    if not isinstance(value, str):
        raise ContractViolation(f"{field} must be text")
    if not value.strip():
        raise ContractViolation(f"{field} must be non-blank")
    if _utf8_len(value) > limit:
        raise ContractViolation(f"{field} exceeds {limit} UTF-8 bytes")
    if any(ord(char) < 32 and char not in "\t\n\r" for char in value):
        raise ContractViolation(f"{field} contains a control character")
    return value


def _token(value: str, field: str, *, pattern: re.Pattern[str] = _TOKEN) -> str:
    value = _bounded_text(value, field, MAX_TOKEN_BYTES)
    if pattern.fullmatch(value) is None:
        raise ContractViolation(f"{field} has invalid token syntax")
    return value


def _positive(value: int, field: str, *, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ContractViolation(f"{field} must be a positive integer")
    if maximum is not None and value > maximum:
        raise ContractViolation(f"{field} exceeds {maximum}")
    return value


def _sha256(value: str, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ContractViolation(f"{field} must be lowercase SHA-256 hex")
    return value


def _exact_type(value: object, expected: type[Any], field: str) -> None:
    if type(value) is not expected:
        raise ContractViolation(f"{field} must be exactly {expected.__name__}")


@dataclass(frozen=True, order=True)
class RepositoryIdentity:
    owner: str
    name: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "owner", _token(self.owner, "owner", pattern=_GITHUB_SLUG))
        object.__setattr__(self, "name", _token(self.name, "name", pattern=_GITHUB_SLUG))

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"


@dataclass(frozen=True, order=True)
class IssueIdentity:
    repository: RepositoryIdentity
    number: int

    def __post_init__(self) -> None:
        _exact_type(self.repository, RepositoryIdentity, "repository")
        object.__setattr__(self, "number", _positive(self.number, "issue number"))


@dataclass(frozen=True, order=True)
class PullRequestIdentity:
    repository: RepositoryIdentity
    number: int

    def __post_init__(self) -> None:
        _exact_type(self.repository, RepositoryIdentity, "repository")
        object.__setattr__(self, "number", _positive(self.number, "pull request number"))


@dataclass(frozen=True, order=True)
class PackageIdentity:
    name: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _token(self.name, "package name"))


@dataclass(frozen=True, order=True)
class ModuleIdentity:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _token(self.value, "module identity"))


@dataclass(frozen=True, order=True)
class WorkUnitIdentity:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _token(self.value, "work-unit identity"))


@dataclass(frozen=True, order=True)
class ProofCeiling:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _token(self.value, "proof ceiling"))


@dataclass(frozen=True, order=True)
class AssignmentRelation:
    source_issue: IssueIdentity
    role: RelationRole
    target_issue: IssueIdentity

    def __post_init__(self) -> None:
        _exact_type(self.source_issue, IssueIdentity, "source_issue")
        _exact_type(self.target_issue, IssueIdentity, "target_issue")
        _exact_type(self.role, RelationRole, "role")


@dataclass(frozen=True, order=True)
class CaseIdentity:
    issue: IssueIdentity
    number: int

    def __post_init__(self) -> None:
        _exact_type(self.issue, IssueIdentity, "issue")
        object.__setattr__(self, "number", _positive(self.number, "case number", maximum=MAX_MATRIX_CASES))

    def require_within(self, denominator: int) -> None:
        denominator = _positive(denominator, "matrix denominator", maximum=MAX_MATRIX_CASES)
        if self.number > denominator:
            raise ContractViolation(f"case {self.number} exceeds matrix denominator {denominator}")


@dataclass(frozen=True, order=True)
class RepositoryPath:
    value: str

    def __post_init__(self) -> None:
        value = _bounded_text(self.value, "repository path", 1_024)
        if "\\" in value:
            raise ContractViolation("repository path must use forward slashes")
        path = PurePosixPath(value)
        if path.is_absolute() or value.startswith("//"):
            raise ContractViolation("repository path must be relative")
        if not path.parts or any(part in {"", ".", ".."} for part in path.parts):
            raise ContractViolation("repository path contains an invalid segment")
        if ":" in path.parts[0]:
            raise ContractViolation("repository path cannot contain a drive prefix")
        object.__setattr__(self, "value", path.as_posix())


@dataclass(frozen=True, order=True)
class SourceLocation:
    path: RepositoryPath
    line: int
    column: int = 1

    def __post_init__(self) -> None:
        _exact_type(self.path, RepositoryPath, "path")
        object.__setattr__(self, "line", _positive(self.line, "line"))
        object.__setattr__(self, "column", _positive(self.column, "column"))


@dataclass(frozen=True, order=True)
class TestIdentity:
    mode: RunnerMode
    qualified_name: str

    def __post_init__(self) -> None:
        _exact_type(self.mode, RunnerMode, "mode")
        name = _bounded_text(self.qualified_name, "qualified test identity", 512)
        if _TEST_ID.fullmatch(name) is None:
            raise ContractViolation("qualified test identity has invalid syntax")
        object.__setattr__(self, "qualified_name", name)


@dataclass(frozen=True, order=True)
class CaseMarker:
    case: CaseIdentity
    test: TestIdentity
    location: SourceLocation

    def __post_init__(self) -> None:
        _exact_type(self.case, CaseIdentity, "case")
        _exact_type(self.test, TestIdentity, "test")
        _exact_type(self.location, SourceLocation, "location")


@dataclass(frozen=True, order=True)
class TestExecutionRecord:
    test: TestIdentity
    disposition: ExecutionDisposition
    detail: str | None = None

    def __post_init__(self) -> None:
        _exact_type(self.test, TestIdentity, "test")
        _exact_type(self.disposition, ExecutionDisposition, "disposition")
        if self.detail is not None:
            object.__setattr__(self, "detail", _bounded_text(self.detail, "execution detail", MAX_DIAGNOSTIC_BYTES))


@dataclass(frozen=True, order=True)
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
        _exact_type(self.issue, IssueIdentity, "issue")
        _exact_type(self.state, IssueState, "state")
        _exact_type(self.unit, WorkUnitIdentity, "unit")
        _exact_type(self.authority, SourceAuthority, "authority")
        _exact_type(self.proof_ceiling, ProofCeiling, "proof_ceiling")
        object.__setattr__(self, "title", _bounded_text(self.title, "title", MAX_TITLE_BYTES))
        object.__setattr__(self, "body_sha256", _sha256(self.body_sha256, "body_sha256"))
        object.__setattr__(self, "matrix_cases", _positive(self.matrix_cases, "matrix_cases", maximum=MAX_MATRIX_CASES))
        if self.live_etag is not None:
            object.__setattr__(self, "live_etag", _bounded_text(self.live_etag, "live_etag", MAX_TOKEN_BYTES))
        if self.snapshot_sha256 is not None:
            object.__setattr__(self, "snapshot_sha256", _sha256(self.snapshot_sha256, "snapshot_sha256"))
        if self.authority is SourceAuthority.LIVE_GITHUB:
            if self.snapshot_sha256 is not None:
                raise ContractViolation("live source cannot carry an offline snapshot digest")
        elif self.authority is SourceAuthority.EXPLICIT_OFFLINE_SNAPSHOT:
            if self.snapshot_sha256 is None:
                raise ContractViolation("offline source requires snapshot_sha256")
            if self.live_etag is not None:
                raise ContractViolation("offline source cannot carry a live ETag")


@dataclass(frozen=True, order=True)
class CaseAccountingMember:
    case: CaseIdentity
    marker: CaseMarker
    execution: TestExecutionRecord

    def __post_init__(self) -> None:
        _exact_type(self.case, CaseIdentity, "case")
        _exact_type(self.marker, CaseMarker, "marker")
        _exact_type(self.execution, TestExecutionRecord, "execution")
        if self.marker.case != self.case:
            raise ContractViolation("marker case does not match member case")
        if self.marker.test != self.execution.test:
            raise ContractViolation("marker test does not match execution test")


@dataclass(frozen=True)
class CaseAccountingReceipt:
    assignment: AssignmentSourceReceipt
    members: tuple[CaseAccountingMember, ...]
    result: OverallResult
    proof_ceiling: ProofCeiling

    def __post_init__(self) -> None:
        _exact_type(self.assignment, AssignmentSourceReceipt, "assignment")
        _exact_type(self.result, OverallResult, "result")
        _exact_type(self.proof_ceiling, ProofCeiling, "proof_ceiling")
        if len(self.members) > MAX_MATRIX_CASES:
            raise ContractViolation("case-accounting member count exceeds policy")
        for member in self.members:
            _exact_type(member, CaseAccountingMember, "member")
            if member.case.issue != self.assignment.issue:
                raise ContractViolation("member issue does not match assignment issue")
            member.case.require_within(self.assignment.matrix_cases)
        ordered = tuple(sorted(self.members, key=lambda item: item.case.number))
        object.__setattr__(self, "members", ordered)
        numbers = [item.case.number for item in ordered]
        tests = [item.execution.test for item in ordered]
        if len(numbers) != len(set(numbers)):
            raise ContractViolation("duplicate case-accounting member")
        if len(tests) != len(set(tests)):
            raise ContractViolation("one test identity cannot cover multiple cases")
        if self.result is OverallResult.PASS:
            expected = list(range(1, self.assignment.matrix_cases + 1))
            if numbers != expected:
                raise ContractViolation("pass requires complete exact case denominator")
            if any(item.execution.disposition is not ExecutionDisposition.EXECUTED_PASS for item in ordered):
                raise ContractViolation("pass requires every case test to execute successfully")


@dataclass(frozen=True, order=True)
class RemediationCode:
    value: str

    def __post_init__(self) -> None:
        value = _bounded_text(self.value, "remediation code", 64)
        if _REMEDIATION_CODE.fullmatch(value) is None:
            raise ContractViolation("remediation code must be stable uppercase syntax")
        object.__setattr__(self, "value", value)


@dataclass(frozen=True, order=True)
class Finding:
    severity: FindingSeverity
    finding_class: FindingClass
    owner: WorkUnitIdentity
    remediation: RemediationCode
    message: str

    def __post_init__(self) -> None:
        _exact_type(self.severity, FindingSeverity, "severity")
        _exact_type(self.finding_class, FindingClass, "finding_class")
        _exact_type(self.owner, WorkUnitIdentity, "owner")
        _exact_type(self.remediation, RemediationCode, "remediation")
        object.__setattr__(self, "message", _bounded_text(self.message, "finding message", MAX_DIAGNOSTIC_BYTES))


@dataclass(frozen=True)
class ComponentGateReceipt:
    component: str
    result: OverallResult
    findings: tuple[Finding, ...]
    proof_ceiling: ProofCeiling

    def __post_init__(self) -> None:
        object.__setattr__(self, "component", _token(self.component, "component"))
        _exact_type(self.result, OverallResult, "result")
        _exact_type(self.proof_ceiling, ProofCeiling, "proof_ceiling")
        if len(self.findings) > MAX_DIAGNOSTIC_FIELDS:
            raise ContractViolation("too many component findings")
        for finding in self.findings:
            _exact_type(finding, Finding, "finding")
        object.__setattr__(self, "findings", tuple(sorted(self.findings)))
        if self.result is OverallResult.PASS and any(finding.severity is FindingSeverity.ERROR for finding in self.findings):
            raise ContractViolation("passing component receipt cannot contain errors")


@dataclass(frozen=True, order=True)
class CohortRow:
    issue: IssueIdentity
    unit: WorkUnitIdentity
    mode: RunnerMode
    matrix_cases: int
    descriptor_sha256: str

    def __post_init__(self) -> None:
        _exact_type(self.issue, IssueIdentity, "issue")
        _exact_type(self.unit, WorkUnitIdentity, "unit")
        _exact_type(self.mode, RunnerMode, "mode")
        object.__setattr__(self, "matrix_cases", _positive(self.matrix_cases, "matrix_cases", maximum=MAX_MATRIX_CASES))
        object.__setattr__(self, "descriptor_sha256", _sha256(self.descriptor_sha256, "descriptor_sha256"))


@dataclass(frozen=True)
class CohortReceipt:
    rows: tuple[CohortRow, ...]
    result: OverallResult
    proof_ceiling: ProofCeiling

    def __post_init__(self) -> None:
        _exact_type(self.result, OverallResult, "result")
        _exact_type(self.proof_ceiling, ProofCeiling, "proof_ceiling")
        if not self.rows:
            raise ContractViolation("cohort denominator cannot be empty")
        if len(self.rows) > MAX_COHORT_ROWS:
            raise ContractViolation("cohort row count exceeds policy")
        for row in self.rows:
            _exact_type(row, CohortRow, "row")
        ordered = tuple(sorted(self.rows, key=lambda row: (row.issue.number, row.unit.value)))
        object.__setattr__(self, "rows", ordered)
        if len({row.issue for row in ordered}) != len(ordered):
            raise ContractViolation("duplicate cohort issue identity")
        if len({row.unit for row in ordered}) != len(ordered):
            raise ContractViolation("duplicate cohort work-unit identity")

    @property
    def matrix_cases(self) -> int:
        return sum(row.matrix_cases for row in self.rows)


@dataclass(frozen=True)
class BoundedDiagnostic:
    summary: str
    fields: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "summary", _bounded_text(self.summary, "diagnostic summary", MAX_DIAGNOSTIC_BYTES))
        if len(self.fields) > MAX_DIAGNOSTIC_FIELDS:
            raise ContractViolation("too many diagnostic fields")
        normalized: list[tuple[str, str]] = []
        for key, value in self.fields:
            normalized.append((_token(key, "diagnostic field key"), _bounded_text(value, "diagnostic field value", MAX_DIAGNOSTIC_BYTES)))
        if len({key for key, _ in normalized}) != len(normalized):
            raise ContractViolation("duplicate diagnostic field")
        object.__setattr__(self, "fields", tuple(sorted(normalized)))


def _canonical_value(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {field.name: _canonical_value(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _canonical_value(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (set, frozenset)):
        normalized = [_canonical_value(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    if isinstance(value, (tuple, list)):
        return [_canonical_value(item) for item in value]
    if value is None or isinstance(value, (str, int, bool)):
        return value
    raise ContractViolation(f"unsupported canonical value type: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes for a contract value."""

    return json.dumps(
        _canonical_value(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    """Return the SHA-256 of :func:`canonical_bytes`."""

    return hashlib.sha256(canonical_bytes(value)).hexdigest()


__all__ = [
    "AssignmentRelation",
    "AssignmentSourceReceipt",
    "BoundedDiagnostic",
    "CaseAccountingMember",
    "CaseAccountingReceipt",
    "CaseIdentity",
    "CaseMarker",
    "CohortReceipt",
    "CohortRow",
    "ComponentGateReceipt",
    "ContractViolation",
    "ExecutionDisposition",
    "Finding",
    "FindingClass",
    "FindingSeverity",
    "IssueIdentity",
    "IssueState",
    "MAX_COHORT_ROWS",
    "MAX_DIAGNOSTIC_BYTES",
    "MAX_DIAGNOSTIC_FIELDS",
    "MAX_MATRIX_CASES",
    "MAX_TITLE_BYTES",
    "MAX_TOKEN_BYTES",
    "ModuleIdentity",
    "OverallResult",
    "PackageIdentity",
    "ProofCeiling",
    "PullRequestIdentity",
    "RelationRole",
    "RemediationCode",
    "RepositoryIdentity",
    "RepositoryPath",
    "RunnerMode",
    "SourceAuthority",
    "SourceLocation",
    "TestExecutionRecord",
    "TestIdentity",
    "WorkUnitIdentity",
    "canonical_bytes",
    "canonical_sha256",
]
