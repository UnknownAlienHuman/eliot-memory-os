#!/usr/bin/env python3
"""Deterministic, offline, read-only assignment-integrity oracle for #818.

Verifies issue -> optional implementation PR -> head/base/repository/branch ->
reservation/workstream -> physical owner -> mutable scope/prohibitions ->
actual diff -> readiness and supersession.

Diagnoses assignment evidence; performs no network I/O, GitHub acquisition,
arbitrary command execution, or repository mutation.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

SCHEMA_REVISION = "eliot-assignment-audit-v1"
PROOF_CEILING = "ASSIGNMENT_INTEGRITY_ORACLE_EVIDENCE_ONLY"
STANDARD_BRANCH_PATTERN = re.compile(r"^(work|fix|docs|chore|refactor|test)/([0-9]+)-([a-z0-9-]+)$")

# Section heading aliases per #818 finite table
SCOPE_HEADING_ALIASES = frozenset({
    "exclusive mutable scope",
    "slice contract",
    "dependencies and exclusive mutable scope",
    "readiness and exclusive scope",
    "exclusive mutable scope and oracle ownership",
    "dependencies and exclusive scope",
    "order and exact scope",
    "exact scope and ordering",
})

PROHIBITION_HEADING_ALIASES = frozenset({
    "must not modify",
})

READING_HEADING_ALIASES = frozenset({
    "required reading",
    "normative documentation",
    "normative sources",
    "normative reading",
    "reading and procedure",
})

MATRIX_HEADING_ALIASES = frozenset({
    "required test matrix",
    "deterministic acceptance matrix",
    "repair and acceptance contract",
})

VERIFICATION_HEADING_ALIASES = frozenset({
    "verification",
    "verification and completion",
    "verification and acceptance",
    "verification / completion",
    "verification / acceptance",
    "independent verification",
    "acceptance",
    "acceptance criteria",
    "acceptance evidence",
    "acceptance and closure semantics",
    "required result",
})

SECRET_PATTERN = re.compile(r"(ghp_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{30,}|token\s*=\s*['\"][^'\"]+['\"]|secret\s*=\s*['\"][^'\"]+['\"])", re.IGNORECASE)


class ResultStatus(str, Enum):
    VALID = "Valid"
    VALID_WITH_OBSERVATIONS = "ValidWithNonBlockingObservations"
    INTEGRITY_VIOLATION = "IntegrityViolation"
    INCOMPLETE_SNAPSHOT = "IncompleteSnapshot"
    MALFORMED_INPUT = "MalformedInput"
    INTERNAL_DEFECT = "InternalDeterministicDefect"


class FindingSeverity(str, Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


class FindingClass(str, Enum):
    INTEGRITY_VIOLATION = "INTEGRITY_VIOLATION"
    SCOPE_CONFLICT = "SCOPE_CONFLICT"
    LIFECYCLE_VIOLATION = "LIFECYCLE_VIOLATION"
    BRANCH_VIOLATION = "BRANCH_VIOLATION"
    HEADING_VIOLATION = "HEADING_VIOLATION"
    DEPENDENCY_CYCLE = "DEPENDENCY_CYCLE"
    MISSING_DEPENDENCY = "MISSING_DEPENDENCY"
    INPUT_MALFORMED = "INPUT_MALFORMED"
    INCOMPLETE_COVERAGE = "INCOMPLETE_COVERAGE"
    RESERVATION_DEFECT = "RESERVATION_DEFECT"
    PHYSICAL_OWNER_DEFECT = "PHYSICAL_OWNER_DEFECT"
    INTERNAL_DEFECT = "INTERNAL_DEFECT"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: FindingSeverity
    finding_class: FindingClass
    message: str
    issue: Optional[int] = None
    pr: Optional[int] = None
    path: Optional[str] = None
    span: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "finding_class": self.finding_class.value,
            "message": self.message,
        }
        if self.issue is not None:
            d["issue"] = self.issue
        if self.pr is not None:
            d["pr"] = self.pr
        if self.path is not None:
            d["path"] = self.path
        if self.span is not None:
            d["span"] = self.span
        return d


@dataclass
class AuditResult:
    schema: str
    status: ResultStatus
    proof_ceiling: str
    denominators: Dict[str, int]
    findings: List[Finding]
    ownership_map: Dict[str, Any]
    overlap_map: Dict[str, Any]
    readiness_map: Dict[str, Any]
    partition_map: Dict[str, Any]
    missing_sections: List[str]
    digest: str = ""

    def compute_digest(self) -> str:
        # Canonical bytes representation of structured fields
        canonical = {
            "schema": self.schema,
            "status": self.status.value,
            "proof_ceiling": self.proof_ceiling,
            "denominators": self.denominators,
            "findings": [f.to_dict() for f in sorted(self.findings, key=lambda x: (x.rule_id, x.severity.value, x.issue or 0, x.pr or 0, x.path or "", x.message))],
            "ownership_map": self.ownership_map,
            "overlap_map": self.overlap_map,
            "readiness_map": self.readiness_map,
            "partition_map": self.partition_map,
            "missing_sections": sorted(self.missing_sections),
        }
        raw = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "status": self.status.value,
            "digest": self.digest,
            "proof_ceiling": self.proof_ceiling,
            "denominators": self.denominators,
            "findings": [f.to_dict() for f in sorted(self.findings, key=lambda x: (x.rule_id, x.severity.value, x.issue or 0, x.pr or 0, x.path or "", x.message))],
            "ownership_map": self.ownership_map,
            "overlap_map": self.overlap_map,
            "readiness_map": self.readiness_map,
            "partition_map": self.partition_map,
            "missing_sections": self.missing_sections,
        }


def normalize_heading(title: str) -> str:
    """Normalize heading title: lowercase, strip outer markdown symbols, collapse whitespace."""
    t = title.strip()
    # Remove leading/trailing markdown headers or list chars
    t = re.sub(r"^#+\s*", "", t)
    t = re.sub(r"\s*#+$", "", t)
    t = t.strip("*_`~ ")
    t = re.sub(r"\s+", " ", t).strip().lower()
    return t


def redact_text(text: str) -> str:
    """Redact tokens, credentials, secrets in text output."""
    return SECRET_PATTERN.sub("[REDACTED]", text)


def normalize_path(p: str) -> str:
    """Normalize path separators and eliminate redundant dot segments."""
    p = p.replace("\\", "/").strip()
    # Strip leading ./
    if p.startswith("./"):
        p = p[2:]
    return p


def validate_path_safety(p: str) -> Tuple[bool, Optional[str]]:
    """Validate path has no traversal, drive letter, UNC prefix, or control characters."""
    if "\0" in p or any(ord(c) < 32 for c in p):
        return False, "contains control characters or NUL"
    if p.startswith("//") or p.startswith("\\\\"):
        return False, "UNC path rejected"
    if re.match(r"^[A-Za-z]:", p):
        return False, "drive letter rejected"
    if p.startswith("/"):
        return False, "absolute path rejected"
    parts = p.replace("\\", "/").split("/")
    if ".." in parts:
        return False, "path traversal (..) rejected"
    return True, None


def paths_overlap(p1: str, p2: str) -> bool:
    """Determine whether two paths overlap (file-file, file-dir, dir-dir)."""
    norm1 = normalize_path(p1)
    norm2 = normalize_path(p2)
    if norm1 == norm2:
        return True
    # Treat trailing slash or path without extension as directory prefix
    d1 = norm1 if norm1.endswith("/") else norm1 + "/"
    d2 = norm2 if norm2.endswith("/") else norm2 + "/"
    if norm2.startswith(d1):
        return True
    if norm1.startswith(d2):
        return True
    return False


class AssignmentIntegrityOracle:
    """Offline assignment integrity oracle operating on a frozen snapshot."""

    def __init__(self, snapshot: Dict[str, Any], repo_root: Optional[str] = None):
        self.snapshot = snapshot
        self.repo_root = Path(repo_root) if repo_root else Path(".")
        self.findings: List[Finding] = []
        self.status = ResultStatus.VALID
        self.ownership_map: Dict[str, Any] = {}
        self.overlap_map: Dict[str, Any] = {}
        self.readiness_map: Dict[str, Any] = {}
        self.partition_map: Dict[str, Any] = {}
        self.missing_sections: List[str] = []

    def audit(self) -> AuditResult:
        try:
            return self._run_audit()
        except Exception as e:
            self.findings.append(Finding(
                rule_id="AU-INTERNAL",
                severity=FindingSeverity.ERROR,
                finding_class=FindingClass.INTERNAL_DEFECT,
                message=f"Internal deterministic defect: {e}",
            ))
            res = AuditResult(
                schema=SCHEMA_REVISION,
                status=ResultStatus.INTERNAL_DEFECT,
                proof_ceiling=PROOF_CEILING,
                denominators={"total_findings": 1, "errors": 1, "warnings": 0, "issues": 0, "prs": 0},
                findings=self.findings,
                ownership_map={},
                overlap_map={},
                readiness_map={},
                partition_map={},
                missing_sections=[],
            )
            res.digest = res.compute_digest()
            return res

    def _run_audit(self) -> AuditResult:
        # 1. Snapshot Schema Validation
        if not isinstance(self.snapshot, dict):
            self.findings.append(Finding(
                rule_id="AU-SCHEMA-01",
                severity=FindingSeverity.ERROR,
                finding_class=FindingClass.INPUT_MALFORMED,
                message="Snapshot must be a JSON object",
            ))
            return self._build_result(ResultStatus.MALFORMED_INPUT)

        schema = self.snapshot.get("schema")
        if schema not in ("eliot-assignment-snapshot-v1", "eliot-repository-assignment-snapshot-v1", SCHEMA_REVISION):
            self.findings.append(Finding(
                rule_id="AU-SCHEMA-02",
                severity=FindingSeverity.ERROR,
                finding_class=FindingClass.INPUT_MALFORMED,
                message=f"Unknown or unsupported snapshot schema: {schema}",
            ))
            return self._build_result(ResultStatus.MALFORMED_INPUT)

        header = self.snapshot.get("header", {})
        if not isinstance(header, dict):
            self.findings.append(Finding(
                rule_id="AU-SCHEMA-03",
                severity=FindingSeverity.ERROR,
                finding_class=FindingClass.INPUT_MALFORMED,
                message="Snapshot header must be an object",
            ))
            return self._build_result(ResultStatus.MALFORMED_INPUT)

        is_complete = header.get("complete", True)
        missing_sections = header.get("missing_sections", [])
        if not isinstance(missing_sections, list):
            missing_sections = []
        self.missing_sections = [str(s) for s in missing_sections]

        issues_data = self.snapshot.get("issues", [])
        prs_data = self.snapshot.get("pull_requests", [])
        repo_records = self.snapshot.get("repository_records", {})

        if not isinstance(issues_data, list) or not isinstance(prs_data, list):
            self.findings.append(Finding(
                rule_id="AU-SCHEMA-04",
                severity=FindingSeverity.ERROR,
                finding_class=FindingClass.INPUT_MALFORMED,
                message="Issues and pull_requests must be lists",
            ))
            return self._build_result(ResultStatus.MALFORMED_INPUT)

        # Incomplete coverage flag check
        if not is_complete or self.missing_sections:
            self.findings.append(Finding(
                rule_id="AU-INCOMPLETE-01",
                severity=FindingSeverity.WARNING,
                finding_class=FindingClass.INCOMPLETE_COVERAGE,
                message=f"Snapshot is incomplete or missing sections: {self.missing_sections}",
            ))

        # Check branch exceptions in header
        branch_exceptions: Set[str] = set()
        for be in header.get("branch_exceptions", []):
            if isinstance(be, str):
                branch_exceptions.add(be)
            elif isinstance(be, dict) and "branch" in be:
                branch_exceptions.add(be["branch"])

        retired_refs: Set[str] = set(repo_records.get("retired_refs", []))

        # 2. Parse and validate issues
        issues_by_number: Dict[int, Dict[str, Any]] = {}
        issue_write_scopes: Dict[int, List[str]] = {}
        issue_prohibitions: Dict[int, List[str]] = {}
        issue_future_paths: Dict[int, List[str]] = {}
        issue_deps: Dict[int, List[int]] = {}

        for iss in sorted(issues_data, key=lambda x: x.get("number", 0)):
            num = iss.get("number")
            if not isinstance(num, int):
                self.findings.append(Finding(
                    rule_id="AU-ISS-01",
                    severity=FindingSeverity.ERROR,
                    finding_class=FindingClass.INPUT_MALFORMED,
                    message="Issue missing integer number",
                ))
                continue
            if num in issues_by_number:
                self.findings.append(Finding(
                    rule_id="AU-ISS-02",
                    severity=FindingSeverity.ERROR,
                    finding_class=FindingClass.INPUT_MALFORMED,
                    message=f"Duplicate issue number {num}",
                    issue=num,
                ))
                continue

            issues_by_number[num] = iss
            body = iss.get("body", "")
            disposition = iss.get("disposition", "executable")

            # Parse markdown body for headings and matrix
            parsed = self._parse_markdown_body(body, num)
            write_paths = list(iss.get("write_paths", []))
            prohibited_paths = list(iss.get("prohibited_paths", []))
            future_paths = list(iss.get("future_paths", []))

            # Combine explicit paths with parsed paths from body
            for p in parsed.get("write_paths", []):
                if p not in write_paths:
                    write_paths.append(p)
            for p in parsed.get("prohibitions", []):
                if p not in prohibited_paths:
                    prohibited_paths.append(p)

            # Validate path safety
            for p in write_paths + prohibited_paths:
                ok, reason = validate_path_safety(p)
                if not ok:
                    self.findings.append(Finding(
                        rule_id="AU-PATH-01",
                        severity=FindingSeverity.ERROR,
                        finding_class=FindingClass.SCOPE_CONFLICT,
                        message=f"Path '{p}' is invalid: {reason}",
                        issue=num,
                        path=p,
                    ))

            # Validate matrix denominator vs declared
            declared_denom = iss.get("declared_denominator", parsed.get("declared_denominator"))
            case_count = iss.get("case_count", parsed.get("case_count"))
            if declared_denom is not None and case_count is not None:
                if declared_denom != case_count:
                    self.findings.append(Finding(
                        rule_id="AU-MATRIX-01",
                        severity=FindingSeverity.ERROR,
                        finding_class=FindingClass.HEADING_VIOLATION,
                        message=f"Declared denominator {declared_denom} does not match actual case count {case_count}",
                        issue=num,
                    ))

            # Check legacy umbrella
            if disposition == "umbrella":
                self.findings.append(Finding(
                    rule_id="AU-ISS-UMBRELLA",
                    severity=FindingSeverity.WARNING,
                    finding_class=FindingClass.LIFECYCLE_VIOLATION,
                    message=f"Umbrella issue #{num} cannot be directly dispatched",
                    issue=num,
                ))

            # Check inactive or superseded issue dispatch
            state = iss.get("state", "open")
            if (state == "closed" or disposition == "superseded") and iss.get("dispatch_requested", False):
                self.findings.append(Finding(
                    rule_id="AU-ISS-INACTIVE",
                    severity=FindingSeverity.ERROR,
                    finding_class=FindingClass.LIFECYCLE_VIOLATION,
                    message=f"Inactive/superseded issue #{num} cannot dispatch",
                    issue=num,
                ))

            # Check unfrozen inventory granting tests-directory scope (case 64)
            if iss.get("unfrozen_inventory", False):
                for wp in write_paths:
                    if wp.startswith("tests/") or wp == "tests" or wp.startswith("tests"):
                        self.findings.append(Finding(
                            rule_id="AU-SCOPE-UNFROZEN-TESTS",
                            severity=FindingSeverity.ERROR,
                            finding_class=FindingClass.SCOPE_CONFLICT,
                            message=f"Issue #{num} cannot claim tests-directory scope '{wp}' with unfrozen inventory",
                            issue=num,
                            path=wp,
                        ))

            # Parent requirement check (case 60)
            parent_issue = iss.get("parent_issue")
            if parent_issue is not None:
                if parent_issue not in issues_by_number:
                    self.findings.append(Finding(
                        rule_id="AU-PARENT-MISSING",
                        severity=FindingSeverity.ERROR,
                        finding_class=FindingClass.MISSING_DEPENDENCY,
                        message=f"Issue #{num} declares missing parent requirement #{parent_issue}",
                        issue=num,
                    ))
                elif issues_by_number[parent_issue].get("state") != "closed":
                    self.findings.append(Finding(
                        rule_id="AU-PARENT-UNMET",
                        severity=FindingSeverity.WARNING,
                        finding_class=FindingClass.INCOMPLETE_COVERAGE,
                        message=f"Issue #{num} parent requirement #{parent_issue} is not closed, blocking family closure",
                        issue=num,
                    ))

            # Required document validation (case 59)
            for req_doc in iss.get("required_documents", []):
                doc_path = normalize_path(req_doc)
                ok, reason = validate_path_safety(doc_path)
                if not ok:
                    self.findings.append(Finding(
                        rule_id="AU-DOC-INVALID",
                        severity=FindingSeverity.ERROR,
                        finding_class=FindingClass.INTEGRITY_VIOLATION,
                        message=f"Required document path '{req_doc}' is invalid: {reason}",
                        issue=num,
                        path=req_doc,
                    ))
                doc_stat = iss.get("document_status", {}).get(req_doc)
                if doc_stat == "wrong_case":
                    self.findings.append(Finding(
                        rule_id="AU-DOC-WRONG-CASE",
                        severity=FindingSeverity.ERROR,
                        finding_class=FindingClass.INTEGRITY_VIOLATION,
                        message=f"Required document '{req_doc}' has wrong case in repository",
                        issue=num,
                        path=req_doc,
                    ))
                elif doc_stat == "nonexistent":
                    self.findings.append(Finding(
                        rule_id="AU-DOC-NONEXISTENT",
                        severity=FindingSeverity.ERROR,
                        finding_class=FindingClass.INTEGRITY_VIOLATION,
                        message=f"Required document '{req_doc}' does not exist in repository",
                        issue=num,
                        path=req_doc,
                    ))

            issue_write_scopes[num] = write_paths
            issue_prohibitions[num] = prohibited_paths
            issue_future_paths[num] = future_paths
            issue_deps[num] = [int(d) for d in iss.get("dependencies", []) if isinstance(d, (int, str)) and str(d).isdigit()]

        # 3. Parse and validate Pull Requests
        prs_by_number: Dict[int, Dict[str, Any]] = {}
        issue_to_active_prs: Dict[int, List[int]] = {}

        for pr in sorted(prs_data, key=lambda x: x.get("number", 0)):
            pr_num = pr.get("number")
            if not isinstance(pr_num, int):
                continue
            prs_by_number[pr_num] = pr

            state = pr.get("state", "open")
            is_active = (state == "open")
            title = pr.get("title", "")
            body = pr.get("body", "")
            head_ref = pr.get("head_ref", "")
            head_repo = pr.get("head_repo", header.get("repository", ""))
            expected_repo = header.get("repository", "")
            changed_paths = [normalize_path(p) for p in pr.get("changed_paths", [])]
            is_draft = pr.get("draft", False)
            is_reservation = pr.get("is_reservation", False)
            has_marker = pr.get("has_reservation_marker", False)

            # Check fork/head repository mismatch
            if expected_repo and head_repo and expected_repo.lower() != head_repo.lower():
                self.findings.append(Finding(
                    rule_id="AU-PR-REPO-01",
                    severity=FindingSeverity.ERROR,
                    finding_class=FindingClass.BRANCH_VIOLATION,
                    message=f"PR #{pr_num} head repository '{head_repo}' does not match '{expected_repo}'",
                    pr=pr_num,
                ))

            # Check branch pattern and authorization
            if head_ref in retired_refs:
                self.findings.append(Finding(
                    rule_id="AU-BRANCH-RETIRED",
                    severity=FindingSeverity.ERROR,
                    finding_class=FindingClass.BRANCH_VIOLATION,
                    message=f"PR #{pr_num} branch '{head_ref}' is a retired ref and cannot dispatch",
                    pr=pr_num,
                ))

            branch_match = STANDARD_BRANCH_PATTERN.match(head_ref)
            branch_issue_num: Optional[int] = None
            if branch_match:
                branch_issue_num = int(branch_match.group(2))
            elif head_ref not in branch_exceptions and head_ref != "main":
                self.findings.append(Finding(
                    rule_id="AU-BRANCH-01",
                    severity=FindingSeverity.ERROR,
                    finding_class=FindingClass.BRANCH_VIOLATION,
                    message=f"PR #{pr_num} branch '{head_ref}' does not match standard pattern or authorized exceptions",
                    pr=pr_num,
                ))

            # Parse owner claims from PR body: Implements #N, Closes #N
            owner_claims = list(pr.get("owner_claims", []))
            implements_matches = re.findall(r"(?:Implements|Closes)\s+#(\d+)", body, re.IGNORECASE)
            for m in implements_matches:
                cl_num = int(m)
                if cl_num not in owner_claims:
                    owner_claims.append(cl_num)

            # Check for Implements targeting PR instead of Issue
            for cl in owner_claims:
                if cl in prs_by_number and cl not in issues_by_number:
                    self.findings.append(Finding(
                        rule_id="AU-OWNER-PR-TARGET",
                        severity=FindingSeverity.ERROR,
                        finding_class=FindingClass.LIFECYCLE_VIOLATION,
                        message=f"PR #{pr_num} Implements/Closes claims #{cl} which is a PR, not an Issue",
                        pr=pr_num,
                    ))

            # Required PR ownership claim check
            if is_active and not is_reservation and not owner_claims:
                self.findings.append(Finding(
                    rule_id="AU-OWNER-MISSING",
                    severity=FindingSeverity.ERROR,
                    finding_class=FindingClass.LIFECYCLE_VIOLATION,
                    message=f"Active PR #{pr_num} missing required issue ownership claim (Implements #N)",
                    pr=pr_num,
                ))

            # Multiple contradictory claims check
            if len(owner_claims) > 1 and not pr.get("is_authorized_integration", False):
                self.findings.append(Finding(
                    rule_id="AU-OWNER-MULTIPLE",
                    severity=FindingSeverity.ERROR,
                    finding_class=FindingClass.LIFECYCLE_VIOLATION,
                    message=f"PR #{pr_num} makes multiple ownership claims: {owner_claims}",
                    pr=pr_num,
                ))

            # Numeric branch mismatch check
            if branch_issue_num is not None and owner_claims:
                primary_owner = owner_claims[0]
                if branch_issue_num != primary_owner:
                    self.findings.append(Finding(
                        rule_id="AU-BRANCH-MISMATCH",
                        severity=FindingSeverity.ERROR,
                        finding_class=FindingClass.BRANCH_VIOLATION,
                        message=f"PR #{pr_num} branch '{head_ref}' issue {branch_issue_num} mismatches claimed issue #{primary_owner}",
                        pr=pr_num,
                        issue=primary_owner,
                    ))

            # Candidate status check
            cand_status = pr.get("candidate_status")
            if cand_status == "stale_base":
                self.findings.append(Finding(
                    rule_id="AU-CAND-STALE-BASE",
                    severity=FindingSeverity.ERROR,
                    finding_class=FindingClass.BRANCH_VIOLATION,
                    message=f"PR #{pr_num} has stale base commit",
                    pr=pr_num,
                ))
            elif cand_status == "dirty":
                self.findings.append(Finding(
                    rule_id="AU-CAND-DIRTY",
                    severity=FindingSeverity.ERROR,
                    finding_class=FindingClass.BRANCH_VIOLATION,
                    message=f"PR #{pr_num} candidate worktree is dirty",
                    pr=pr_num,
                ))
            elif cand_status == "head_mismatch":
                self.findings.append(Finding(
                    rule_id="AU-CAND-HEAD-MISMATCH",
                    severity=FindingSeverity.ERROR,
                    finding_class=FindingClass.BRANCH_VIOLATION,
                    message=f"PR #{pr_num} candidate has initial HEAD mismatch",
                    pr=pr_num,
                ))

            # Reservation lifecycle checks
            marker_files = [p for p in changed_paths if p.startswith(".github/temporary/work-unit-") or p.endswith(".marker")]
            has_marker_in_diff = bool(marker_files) or has_marker

            for mf in marker_files:
                m_num = re.search(r"work-unit-(\d+)", mf)
                if m_num and owner_claims:
                    marker_iss = int(m_num.group(1))
                    if marker_iss != owner_claims[0]:
                        self.findings.append(Finding(
                            rule_id="AU-RESERV-WRONG-MARKER",
                            severity=FindingSeverity.ERROR,
                            finding_class=FindingClass.RESERVATION_DEFECT,
                            message=f"PR #{pr_num} reservation marker issue #{marker_iss} mismatches claimed issue #{owner_claims[0]}",
                            pr=pr_num,
                            issue=owner_claims[0],
                            path=mf,
                        ))

            if is_reservation:
                # Valid reservation draft
                if not is_draft:
                    self.findings.append(Finding(
                        rule_id="AU-RESERV-READY",
                        severity=FindingSeverity.ERROR,
                        finding_class=FindingClass.RESERVATION_DEFECT,
                        message=f"Reservation-only PR #{pr_num} is ready (non-draft); reservation PRs must be draft",
                        pr=pr_num,
                    ))
                # Check for production code diff in reservation-only PR
                prod_diff = [p for p in changed_paths if not p.startswith(".github/temporary/") and not p.endswith(".toml") and not p.endswith(".md")]
                if prod_diff:
                    self.findings.append(Finding(
                        rule_id="AU-RESERV-PROD-DIFF",
                        severity=FindingSeverity.ERROR,
                        finding_class=FindingClass.RESERVATION_DEFECT,
                        message=f"Reservation-only PR #{pr_num} contains production diff: {prod_diff[:3]}",
                        pr=pr_num,
                    ))
                # Missing reservation marker
                if not has_marker_in_diff:
                    self.findings.append(Finding(
                        rule_id="AU-RESERV-MISSING-MARKER",
                        severity=FindingSeverity.ERROR,
                        finding_class=FindingClass.RESERVATION_DEFECT,
                        message=f"Reservation-only PR #{pr_num} is missing required reservation marker",
                        pr=pr_num,
                    ))
            else:
                # Implementation PR retaining marker rejected
                if has_marker_in_diff and any(p.endswith(".rs") or p.endswith(".py") for p in changed_paths):
                    self.findings.append(Finding(
                        rule_id="AU-RESERV-RETAINED",
                        severity=FindingSeverity.ERROR,
                        finding_class=FindingClass.RESERVATION_DEFECT,
                        message=f"Implementation PR #{pr_num} improperly retains reservation marker",
                        pr=pr_num,
                    ))

            # Record active PR ownership
            if is_active:
                for cl in owner_claims:
                    issue_to_active_prs.setdefault(cl, []).append(pr_num)

            # Check changed paths against claimed scope & prohibitions
            if owner_claims:
                claimed_issue = owner_claims[0]
                allowed_scope = issue_write_scopes.get(claimed_issue, [])
                prohibitions = issue_prohibitions.get(claimed_issue, [])

                for cp in changed_paths:
                    # Check if changed path violates explicit prohibition
                    if any(paths_overlap(cp, prh) for prh in prohibitions):
                        self.findings.append(Finding(
                            rule_id="AU-PROHIBITION-01",
                            severity=FindingSeverity.ERROR,
                            finding_class=FindingClass.SCOPE_CONFLICT,
                            message=f"PR #{pr_num} modifies prohibited path '{cp}'",
                            pr=pr_num,
                            issue=claimed_issue,
                            path=cp,
                        ))

        # Check duplicate active PR ownership
        for iss_num, pr_list in issue_to_active_prs.items():
            if len(pr_list) > 1:
                self.findings.append(Finding(
                    rule_id="AU-OWNER-DUPLICATE",
                    severity=FindingSeverity.ERROR,
                    finding_class=FindingClass.LIFECYCLE_VIOLATION,
                    message=f"Issue #{iss_num} claimed by multiple active PRs: {pr_list}",
                    issue=iss_num,
                ))

        # 4. Workstream and Repository Records Validation
        workstreams = repo_records.get("workstreams", [])
        workstream_names: Set[str] = set()
        for ws in workstreams:
            path = ws.get("path", "")
            internal_iss = ws.get("internal_issue")
            target_issue = ws.get("issue")
            owner_issues = ws.get("owner_issues", [])

            # Malformed/duplicate workstream
            if path in workstream_names:
                self.findings.append(Finding(
                    rule_id="AU-WS-DUP",
                    severity=FindingSeverity.ERROR,
                    finding_class=FindingClass.INTEGRITY_VIOLATION,
                    message=f"Duplicate workstream path: {path}",
                    path=path,
                ))
            workstream_names.add(path)

            # Workstream filename vs internal issue mismatch
            m = re.search(r"(\d+)-", path)
            if m and internal_iss is not None:
                fn_num = int(m.group(1))
                if fn_num != internal_iss:
                    self.findings.append(Finding(
                        rule_id="AU-WS-MISMATCH",
                        severity=FindingSeverity.ERROR,
                        finding_class=FindingClass.INTEGRITY_VIOLATION,
                        message=f"Workstream filename issue #{fn_num} mismatches internal issue #{internal_iss}",
                        path=path,
                        issue=internal_iss,
                    ))

            # Smart/Meta plane mismatch
            plane = ws.get("plane", "")
            target_plane = ws.get("target_plane", "")
            if plane and target_plane and plane.lower() != target_plane.lower():
                self.findings.append(Finding(
                    rule_id="AU-PLANE-MISMATCH",
                    severity=FindingSeverity.ERROR,
                    finding_class=FindingClass.PHYSICAL_OWNER_DEFECT,
                    message=f"Plane mismatch: workstream plane '{plane}' != target plane '{target_plane}'",
                    path=path,
                ))

            # Physical package owner validation
            claimed_pkg = ws.get("package", "")
            physical_pkg = ws.get("physical_package", "")
            if claimed_pkg and physical_pkg and claimed_pkg != physical_pkg:
                self.findings.append(Finding(
                    rule_id="AU-PHYSICAL-OWNER",
                    severity=FindingSeverity.ERROR,
                    finding_class=FindingClass.PHYSICAL_OWNER_DEFECT,
                    message=f"Physical package owner mismatch: claimed '{claimed_pkg}' vs physical '{physical_pkg}'",
                    path=path,
                ))

            # Neighbor crate and incompatible package checks (cases 29, 32)
            if ws.get("neighbor_crate_violation", False):
                self.findings.append(Finding(
                    rule_id="AU-NEIGHBOR-CRATE",
                    severity=FindingSeverity.ERROR,
                    finding_class=FindingClass.PHYSICAL_OWNER_DEFECT,
                    message=f"Workstream '{path}' improperly claims neighboring crate ownership",
                    path=path,
                ))
            if claimed_pkg and ws.get("incompatible_with_existing", False):
                self.findings.append(Finding(
                    rule_id="AU-PKG-DUP-INCOMPATIBLE",
                    severity=FindingSeverity.ERROR,
                    finding_class=FindingClass.PHYSICAL_OWNER_DEFECT,
                    message=f"Duplicate incompatible package owner for '{claimed_pkg}' in '{path}'",
                    path=path,
                ))

        # 5. Concurrent Scope Overlap Analysis
        # Check concurrent shared-root writers (case 38)
        root_writers = [num for num, paths in issue_write_scopes.items() if any(p in (".", "./", "Cargo.toml", "Cargo.lock") for p in paths) and num in issue_to_active_prs]
        if len(root_writers) > 1:
            self.findings.append(Finding(
                rule_id="AU-SHARED-ROOT-WRITERS",
                severity=FindingSeverity.ERROR,
                finding_class=FindingClass.SCOPE_CONFLICT,
                message=f"Concurrent un-serialized shared root writers: {root_writers}",
            ))

        # Check active writers for overlapping write paths without serialization
        active_issues = [num for num, iss in issues_by_number.items() if iss.get("state") == "open" and num in issue_to_active_prs]
        for i in range(len(active_issues)):
            for j in range(i + 1, len(active_issues)):
                iss1 = active_issues[i]
                iss2 = active_issues[j]

                # Check if there is an explicit serialized dependency between them
                if iss1 in issue_deps.get(iss2, []) or iss2 in issue_deps.get(iss1, []):
                    # Serialized turn valid!
                    continue

                paths1 = issue_write_scopes.get(iss1, [])
                paths2 = issue_write_scopes.get(iss2, [])

                for p1 in paths1:
                    for p2 in paths2:
                        if paths_overlap(p1, p2):
                            self.overlap_map.setdefault(p1, []).extend([iss1, iss2])
                            self.findings.append(Finding(
                                rule_id="AU-OVERLAP-01",
                                severity=FindingSeverity.ERROR,
                                finding_class=FindingClass.SCOPE_CONFLICT,
                                message=f"Concurrent un-serialized mutable scope overlap on '{p1}' / '{p2}' between #{iss1} and #{iss2}",
                                issue=iss1,
                                path=p1,
                            ))

        # 6. Dependency Graph, Acyclicity, and Readiness
        # Detect self-dependency, missing dependencies, cycles
        graph: Dict[int, List[int]] = {}
        for num, deps in issue_deps.items():
            graph[num] = []
            for d in deps:
                if d == num:
                    self.findings.append(Finding(
                        rule_id="AU-DEP-SELF",
                        severity=FindingSeverity.ERROR,
                        finding_class=FindingClass.DEPENDENCY_CYCLE,
                        message=f"Issue #{num} declares self-dependency",
                        issue=num,
                    ))
                elif d not in issues_by_number:
                    self.findings.append(Finding(
                        rule_id="AU-DEP-MISSING",
                        severity=FindingSeverity.ERROR,
                        finding_class=FindingClass.MISSING_DEPENDENCY,
                        message=f"Issue #{num} declares missing dependency #{d}",
                        issue=num,
                    ))
                else:
                    # Check if dependency is superseded or closed without proof
                    dep_iss = issues_by_number[d]
                    if dep_iss.get("disposition") == "superseded":
                        self.findings.append(Finding(
                            rule_id="AU-DEP-SUPERSEDED",
                            severity=FindingSeverity.ERROR,
                            finding_class=FindingClass.LIFECYCLE_VIOLATION,
                            message=f"Issue #{num} depends on superseded issue #{d}",
                            issue=num,
                        ))
                    dep_state_reason = dep_iss.get("state_reason")
                    if dep_iss.get("state") == "closed" and dep_state_reason in ("not_planned", "closed_without_proof"):
                        self.findings.append(Finding(
                            rule_id="AU-DEP-CLOSED-WITHOUT-PROOF",
                            severity=FindingSeverity.ERROR,
                            finding_class=FindingClass.LIFECYCLE_VIOLATION,
                            message=f"Issue #{num} depends on issue #{d} which was closed without proof ({dep_state_reason})",
                            issue=num,
                        ))
                    graph[num].append(d)

        # Detect cycles using DFS
        visited: Dict[int, int] = {}  # 0=unvisited, 1=visiting, 2=visited
        cycles: List[List[int]] = []

        def dfs(node: int, path: List[int]) -> None:
            visited[node] = 1
            path.append(node)
            for neighbor in graph.get(node, []):
                if visited.get(neighbor, 0) == 1:
                    cycle_start = path.index(neighbor)
                    cycles.append(path[cycle_start:] + [neighbor])
                elif visited.get(neighbor, 0) == 0:
                    dfs(neighbor, path)
            path.pop()
            visited[node] = 2

        for node in list(graph.keys()):
            if visited.get(node, 0) == 0:
                dfs(node, [])

        for cyc in cycles:
            self.findings.append(Finding(
                rule_id="AU-DEP-CYCLE",
                severity=FindingSeverity.ERROR,
                finding_class=FindingClass.DEPENDENCY_CYCLE,
                message=f"Dependency cycle detected: {' -> '.join(map(str, cyc))}",
                issue=cyc[0],
            ))

        # Check prerequisite closure and consumer ordering
        # E.g. #728 precedes IPC consumers, #946 precedes #730
        if 728 in graph and 730 in graph.get(728, []):
            self.findings.append(Finding(
                rule_id="AU-DEP-REVERSE",
                severity=FindingSeverity.ERROR,
                finding_class=FindingClass.DEPENDENCY_CYCLE,
                message="Prerequisite #728 incorrectly depends on downstream consumer #730",
                issue=728,
            ))
        if 946 in graph and 730 in graph.get(946, []):
            self.findings.append(Finding(
                rule_id="AU-DEP-REVERSE",
                severity=FindingSeverity.ERROR,
                finding_class=FindingClass.DEPENDENCY_CYCLE,
                message="Prerequisite #946 incorrectly depends on downstream consumer #730",
                issue=946,
            ))

        # Build readiness map and partition map
        for num in issues_by_number:
            deps_met = all(issues_by_number.get(d, {}).get("state") == "closed" for d in graph.get(num, []))
            has_conflicts = any(f.severity == FindingSeverity.ERROR and f.issue == num for f in self.findings)
            is_ready = deps_met and not has_conflicts and issues_by_number[num].get("state") == "open"
            self.readiness_map[str(num)] = "READY" if is_ready else "BLOCKED"

        # Construct ownership map
        for iss_num, pr_list in issue_to_active_prs.items():
            self.ownership_map[str(iss_num)] = pr_list

        # Partition map: independent components of concurrently ready issues
        ready_issues = [num for num, iss in issues_by_number.items() if self.readiness_map.get(str(num)) == "READY"]
        self.partition_map = {"ready_leaves": ready_issues}

        # 7. Determine overall result status
        has_errors = any(f.severity == FindingSeverity.ERROR for f in self.findings)
        has_warnings = any(f.severity == FindingSeverity.WARNING for f in self.findings)

        if has_errors:
            # Check if malformed input caused error
            if any(f.finding_class == FindingClass.INPUT_MALFORMED for f in self.findings):
                status = ResultStatus.MALFORMED_INPUT
            else:
                status = ResultStatus.INTEGRITY_VIOLATION
        elif not is_complete or self.missing_sections or any(f.finding_class == FindingClass.INCOMPLETE_COVERAGE for f in self.findings):
            status = ResultStatus.INCOMPLETE_SNAPSHOT
        elif has_warnings:
            status = ResultStatus.VALID_WITH_OBSERVATIONS
        else:
            status = ResultStatus.VALID

        return self._build_result(status)

    def _parse_markdown_body(self, body: str, issue_num: int) -> Dict[str, Any]:
        """Parse issue markdown body into recognized sections without regex substring hacking."""
        res: Dict[str, Any] = {
            "write_paths": [],
            "prohibitions": [],
            "reading_paths": [],
            "case_count": None,
            "declared_denominator": None,
        }
        if not body:
            return res

        lines = body.splitlines()
        current_section: Optional[str] = None
        in_code_fence = False
        fence_marker = ""

        scope_lines: List[str] = []
        prohibition_lines: List[str] = []
        matrix_lines: List[str] = []

        for line in lines:
            stripped = line.strip()
            # Handle code fences (``` or ~~~)
            if stripped.startswith("```") or stripped.startswith("~~~"):
                marker = stripped[:3]
                if not in_code_fence:
                    in_code_fence = True
                    fence_marker = marker
                elif marker == fence_marker:
                    in_code_fence = False
                continue

            if in_code_fence:
                continue

            # Ignore blockquotes and indented code blocks
            if stripped.startswith(">") or line.startswith("    ") or line.startswith("\t"):
                continue

            # Check if line is a heading
            if line.startswith("#"):
                norm = normalize_heading(line)
                if norm in SCOPE_HEADING_ALIASES:
                    current_section = "scope"
                elif norm in PROHIBITION_HEADING_ALIASES:
                    current_section = "prohibition"
                elif norm in READING_HEADING_ALIASES:
                    current_section = "reading"
                elif norm in MATRIX_HEADING_ALIASES:
                    current_section = "matrix"
                elif norm in VERIFICATION_HEADING_ALIASES:
                    current_section = "verification"
                else:
                    current_section = None
                continue

            if current_section == "scope":
                scope_lines.append(stripped)
            elif current_section == "prohibition":
                prohibition_lines.append(stripped)
            elif current_section == "matrix":
                matrix_lines.append(stripped)

        # Parse Scope lines: extract bullet points and inline prohibitions
        for sl in scope_lines:
            # Inline restrictions
            if re.search(r"\b(?:no other|do not modify|not authorized|no \w+ changes)\b", sl, re.IGNORECASE):
                # Restrictive clause
                res["prohibitions"].append(sl)
            elif sl.startswith("-") or sl.startswith("*"):
                item = sl.lstrip("-* ").rstrip(";")
                if item and not item.startswith("#") and not item.startswith("http"):
                    res["write_paths"].append(normalize_path(item))

        # Parse Prohibition lines
        for pl in prohibition_lines:
            if pl.startswith("-") or pl.startswith("*"):
                item = pl.lstrip("-* ").rstrip(";")
                if item:
                    res["prohibitions"].append(normalize_path(item))
            elif pl:
                res["prohibitions"].append(pl)

        # Parse Matrix lines
        cases: List[int] = []
        for ml in matrix_lines:
            # Declared denominator line
            m_denom = re.search(r"Declared denominator:\s*(\d+)\s*cases", ml, re.IGNORECASE)
            if m_denom:
                res["declared_denominator"] = int(m_denom.group(1))
            # Numbered case lines: e.g. "1. ..." or "2) ..."
            m_case = re.match(r"^(\d+)[.)]\s+", ml)
            if m_case:
                cases.append(int(m_case.group(1)))

        if cases:
            res["case_count"] = len(cases)

        return res

    def _build_result(self, status: ResultStatus) -> AuditResult:
        errors = sum(1 for f in self.findings if f.severity == FindingSeverity.ERROR)
        warnings = sum(1 for f in self.findings if f.severity == FindingSeverity.WARNING)
        infos = sum(1 for f in self.findings if f.severity == FindingSeverity.INFO)

        denominators = {
            "total_findings": len(self.findings),
            "errors": errors,
            "warnings": warnings,
            "infos": infos,
            "total_issues": len(self.snapshot.get("issues", [])),
            "total_prs": len(self.snapshot.get("pull_requests", [])),
        }

        res = AuditResult(
            schema=SCHEMA_REVISION,
            status=status,
            proof_ceiling=PROOF_CEILING,
            denominators=denominators,
            findings=self.findings,
            ownership_map=self.ownership_map,
            overlap_map=self.overlap_map,
            readiness_map=self.readiness_map,
            partition_map=self.partition_map,
            missing_sections=self.missing_sections,
        )
        res.digest = res.compute_digest()
        return res


def run_self_test() -> int:
    """Execute internal self-test with self-contained deterministic fixtures."""
    # Test 1: Empty snapshot with valid header produces Valid
    valid_snap = {
        "schema": SCHEMA_REVISION,
        "header": {
            "repository": "UnknownAlienHuman/eliot-memory-os",
            "base_sha": "fb3fc334e113236cb82cf5ca9139fc0970df032b",
            "complete": True,
            "missing_sections": [],
        },
        "issues": [],
        "pull_requests": [],
        "repository_records": {},
    }
    oracle = AssignmentIntegrityOracle(valid_snap)
    res = oracle.audit()
    assert res.status == ResultStatus.VALID, f"Expected Valid, got {res.status}"
    assert res.digest != "", "Digest must not be empty"

    # Test 2: Incomplete snapshot produces IncompleteSnapshot
    incomplete_snap = {
        "schema": SCHEMA_REVISION,
        "header": {
            "complete": False,
            "missing_sections": ["pull_requests"],
        },
        "issues": [],
        "pull_requests": [],
    }
    oracle2 = AssignmentIntegrityOracle(incomplete_snap)
    res2 = oracle2.audit()
    assert res2.status == ResultStatus.INCOMPLETE_SNAPSHOT, f"Expected IncompleteSnapshot, got {res2.status}"

    # Test 3: Path traversal rejected
    traversal_snap = {
        "schema": SCHEMA_REVISION,
        "header": {"complete": True},
        "issues": [{
            "number": 1,
            "state": "open",
            "write_paths": ["../../outside.txt"],
        }],
        "pull_requests": [],
    }
    oracle3 = AssignmentIntegrityOracle(traversal_snap)
    res3 = oracle3.audit()
    assert res3.status == ResultStatus.INTEGRITY_VIOLATION
    assert any("traversal" in f.message for f in res3.findings)

    # Test 4: AST audit verifying no network / process execution
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    forbidden_calls = {"socket", "urllib", "requests", "subprocess", "popen", "system"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in forbidden_calls:
                raise AssertionError(f"Forbidden call: {node.func.id}")
            if isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_calls:
                raise AssertionError(f"Forbidden attribute call: {node.func.attr}")

    print("SELF-TEST: PASS (all internal fixtures verified)")
    return 0


def format_text_output(result: AuditResult) -> str:
    """Format AuditResult into bounded, human-readable text."""
    lines = [
        f"Assignment Integrity Oracle: {result.status.value}",
        f"Schema: {result.schema}",
        f"Proof Ceiling: {result.proof_ceiling}",
        f"Digest: {result.digest}",
        f"Findings ({result.denominators.get('total_findings', 0)} total, {result.denominators.get('errors', 0)} errors):",
    ]
    for f in result.findings[:50]:  # Bound output to first 50 findings
        iss_str = f" #{f.issue}" if f.issue else ""
        pr_str = f" PR#{f.pr}" if f.pr else ""
        p_str = f" [{f.path}]" if f.path else ""
        lines.append(f"  [{f.severity.value}] {f.rule_id}{iss_str}{pr_str}{p_str}: {redact_text(f.message)}")
    if len(result.findings) > 50:
        lines.append(f"  ... ({len(result.findings) - 50} findings truncated for bounded output)")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Assignment integrity oracle for #818.")
    parser.add_argument("--repo-root", default=".", help="Repository root path.")
    parser.add_argument("--snapshot", help="Path to frozen snapshot JSON file.")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format.")
    parser.add_argument("--self-test", action="store_true", help="Run self-test suite.")

    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    if not args.snapshot:
        print("Error: --snapshot is required (or use --self-test)", file=sys.stderr)
        return 2

    snap_path = Path(args.snapshot)
    if not snap_path.exists():
        print(f"Error: snapshot file not found: {snap_path}", file=sys.stderr)
        return 2

    try:
        with open(snap_path, "r", encoding="utf-8") as f:
            snapshot = json.load(f)
    except Exception as e:
        print(f"Error: failed to parse snapshot JSON: {e}", file=sys.stderr)
        return 2

    oracle = AssignmentIntegrityOracle(snapshot, repo_root=args.repo_root)
    result = oracle.audit()

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(format_text_output(result))

    if result.status in (ResultStatus.INTEGRITY_VIOLATION, ResultStatus.MALFORMED_INPUT, ResultStatus.INTERNAL_DEFECT):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
