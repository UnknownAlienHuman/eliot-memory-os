#!/usr/bin/env python3
"""Verify the #789 declared case denominator, its source bindings, and fixture integrity.

Static source/contract evidence only. It runs no Cargo command, executes no test,
and cannot promote any case to executed: per I0.5 a `NOT_EXECUTED` case stays
`NOT_EXECUTED` no matter what this reports.

Why the expected set is independent
-----------------------------------
The expected 42-case set is parsed out of DOCUMENTED_CASE_MATRIX below - the issue
#789 body section "Required test matrix" - by the accepted gate parser
`scripts/work_unit_gate/assignment_source.py::parse_matrix`. The observed side is
parsed out of the repository tree by the accepted registry parser
`scripts/work_unit_gate/case_binding.py::parse_rust_markers`. Two independent
derivations, so a disagreement can fail. Neither side is copied from the other, and
the expected side is never derived from the impl/caller list the implementation
produces.

`FIXTURE_EXPECTED_SET` additionally re-checks the fixture's own recorded
`case_denominator.expected_set` against the same documented list, so editing the
fixture cannot make a row green on its own authority. Three further anchors keep
the expected set from being narrowed by editing the evidence next to it:

  * `ALLOCATION` reads the git-tracked work-unit allocation
    `workstreams/security/assignments/789-windows-ipc-unsafe-hardening.toml`, which
    states "Exactly 42 substantive cases" independently of both the fixture and the
    transcription. A self-consistent 41-case world fails here.
  * `FIXTURE_FAMILY_COUNT_NOT_RECONCILED` recounts every family's frozen site ids
    against the fixture's own inventory rows instead of trusting the row's
    `declared_site_count_matches_freeze` boolean, and requires the families to
    partition the inventory exactly.
  * `FIXTURE_RECORDED_DIGEST_UNVERIFIED` recomputes the fixture's recorded
    `matrix_sha256` with the accepted canonical digest over the documented titles,
    so a recorded authority that no longer reproduces is reported, not trusted.

The fixture is DATA consumed by a test; measurement output is never written into it
(see AUD-TESTDATA-REVERT).

Usage:
    python scripts/verify-789-case-denominator.py --root .
    python scripts/verify-789-case-denominator.py --root . --format json

Exit codes:
    0  every check passed
    1  at least one typed problem (the denominator or its bindings are incomplete)
    2  usage / configuration / internal failure
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

REPO_MARKER = "scripts/verify-789-case-denominator.py"
FIXTURE_REL = "crates/eliot-windows-ipc/tests/data/unsafe_family_cases.json"
TEST_FILE_REL = "crates/eliot-windows-ipc/tests/unsafe_family_boundaries.rs"
# Tracked, git-authenticated allocation for this work unit. It is a file in the
# repository, not a value this program or the fixture can move, so it is the one
# anchor the denominator cannot be shrunk past by editing a single file.
ASSIGNMENT_REL = "workstreams/security/assignments/789-windows-ipc-unsafe-hardening.toml"
DECLARED_DENOMINATOR = 42

# The issue #789 body section "Required test matrix", transcribed once. This is the
# documented case list; it is the only place a case title enters this program, and
# the accepted parse_matrix validates its own structure (one H2 heading, the
# "Declared denominator: 42 cases, exactly 1..42." declaration equal to the
# numbered-row count, rows 1..42 with no gap, duplicate, non-ASCII digit or empty
# text). Editing this text changes the expected set; it never changes the observed
# set, which is read from the tree.
DOCUMENTED_CASE_MATRIX = """## Required test matrix

**Declared denominator: 42 cases, exactly 1..42.** One substantive executable Rust test per `// WORK_UNIT_CASE: 789/<case>` immediately above attributes. Every applicable site/family must also have an exact fixture binding; 42 tests do not replace that independent denominator.

1. complete site/family denominator reconciles with #754, including target/features and source-set changes;
2. each site has one ADR disposition and wrapper owner;
3. each retained site has adjacent operation-specific SAFETY evidence;
4. generic/detached/copied SAFETY prose rejected;
5. null/invalid pointer cannot enter unsafe use;
6. alignment/layout mismatch;
7. length/capacity/integer overflow and truncation;
8. uninitialized output remains inaccessible;
9. valid/invalid/embedded-NUL/terminator UTF-16 boundaries;
10. invalid handle sentinel;
11. transfer and duplication ownership;
12. every early return preserves no-leak/no-double-close/no-use-after-close;
13. concurrent close/use race;
14. prepared but unsubmitted cleanup;
15. synchronous overlapped completion;
16. pending completion;
17. unknown submission outcome;
18. cancel before submission;
19. cancel request while pending;
20. CancelIoEx success/failure alone cannot release storage;
21. late completion after cancel request;
22. timeout/disconnect with unknown completion;
23. exact reconciliation before reuse/retry;
24. exact replay versus changed same-operation payload;
25. partial read/write and remainder accounting;
26. zero-byte/EOF/broken-pipe distinctions;
27. message/frame boundary preservation;
28. callback after owner destruction prevented;
29. thread affinity and concurrent access;
30. every unsafe Send/Sync implementation has an enforceable witness;
31. unauthorized/ambiguous peer cannot authenticate;
32. ACL/session/principal mismatch stays typed;
33. error/panic cleanup preserves ownership;
34. deterministic fault/crash hooks use barriers, not timing assumptions;
35. bounded randomized submit/cancel/complete/close sequences;
36. buffers/OVERLAPPED remain resident until terminal kernel-ownership proof;
37. owned handles close once or remain explicitly owned/unresolved;
38. partial I/O never becomes complete semantic success;
39. unknown possible submission/completion has no blind retry;
40. no new raw API family/process owner/authority or unrelated semantic expansion;
41. package checks cover default and test-support target sets and supported Windows fixtures;
42. no broad lint/unsafe allow, weakened oracle or omitted required family.

Preserve minimal property/fault regressions. Exact evidence-backed inapplicability differs from ignored execution; a required Windows case unavailable on another platform remains unverified. Fake/raw-call seams prove model behavior, not every OS lifetime guarantee; attach actual supported-Windows wrapper/cancellation/cleanup evidence for the applicable families.
"""

REPOSITORY = "UnknownAlienHuman/eliot-memory-os"
ISSUE_NUMBER = 789


class DenominatorProblem(str, Enum):
    """Typed, fail-closed problem codes. Each names what is not proven."""

    DENOMINATOR_COUNT_MISMATCH = "DENOMINATOR_COUNT_MISMATCH"
    DENOMINATOR_NOT_CONTIGUOUS = "DENOMINATOR_NOT_CONTIGUOUS"
    ALLOCATION_COUNT_MISMATCH = "ALLOCATION_COUNT_MISMATCH"
    ALLOCATION_UNREADABLE = "ALLOCATION_UNREADABLE"
    FIXTURE_UNREADABLE = "FIXTURE_UNREADABLE"
    FIXTURE_EXPECTED_SET_DRIFT = "FIXTURE_EXPECTED_SET_DRIFT"
    FIXTURE_CASE_ROWS_INCOMPLETE = "FIXTURE_CASE_ROWS_INCOMPLETE"
    FIXTURE_BINDING_STATE_UNSOUND = "FIXTURE_BINDING_STATE_UNSOUND"
    FIXTURE_FAMILY_EVIDENCE_INCOMPLETE = "FIXTURE_FAMILY_EVIDENCE_INCOMPLETE"
    FIXTURE_FAMILY_COUNT_NOT_RECONCILED = "FIXTURE_FAMILY_COUNT_NOT_RECONCILED"
    FIXTURE_FAMILY_SITE_PARTITION_BROKEN = "FIXTURE_FAMILY_SITE_PARTITION_BROKEN"
    FIXTURE_MUTATED_AGAINST_HEAD = "FIXTURE_MUTATED_AGAINST_HEAD"
    FIXTURE_RECORDED_DIGEST_UNVERIFIED = "FIXTURE_RECORDED_DIGEST_UNVERIFIED"
    MARKER_SOURCE_UNREADABLE = "MARKER_SOURCE_UNREADABLE"
    MARKER_ACCEPTANCE_FAILED = "MARKER_ACCEPTANCE_FAILED"
    NO_SOURCE_BINDING = "NO_SOURCE_BINDING"
    BINDING_IDENTITY_MISIDENTIFIED = "BINDING_IDENTITY_MISIDENTIFIED"
    TEST_FILE_UNREADABLE = "TEST_FILE_UNREADABLE"
    GATE_IMPORT_FAILED = "GATE_IMPORT_FAILED"


@dataclass(frozen=True)
class Finding:
    problem: DenominatorProblem
    detail: str

    def __str__(self) -> str:
        return f"{self.problem.value}: {self.detail}"


def _git(root: Path, *args: str) -> tuple[int, str, str]:
    done = subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    return done.returncode, done.stdout.strip(), done.stderr.strip()


def _load_gate(root: Path):
    """Import the ACCEPTED gate parsers. No second scheme is reimplemented here."""
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    try:
        from scripts.work_unit_gate import assignment_source, case_binding, contracts
    except Exception as exc:  # fail closed: an unavailable gate is not a pass
        raise RuntimeError(f"accepted gate parsers unavailable: {type(exc).__name__}: {exc}") from exc
    return assignment_source, case_binding, contracts


def _declared_matrix(assignment_source, contracts, findings: list[Finding]):
    """Expected set: the documented case list, parsed by the accepted parser."""
    issue = contracts.IssueIdentity(contracts.RepositoryIdentity(*REPOSITORY.split("/")), ISSUE_NUMBER)
    try:
        matrix = assignment_source.parse_matrix(DOCUMENTED_CASE_MATRIX, issue)
    except Exception as exc:
        findings.append(Finding(DenominatorProblem.DENOMINATOR_COUNT_MISMATCH,
                                f"the documented case list was rejected by the accepted parser: {exc}"))
        return None
    numbers = [case.identity.number for case in matrix.cases]
    if len(numbers) != DECLARED_DENOMINATOR:
        findings.append(Finding(
            DenominatorProblem.DENOMINATOR_COUNT_MISMATCH,
            f"documented list parsed to {len(numbers)} cases, declared denominator is {DECLARED_DENOMINATOR}"))
    if numbers != list(range(1, DECLARED_DENOMINATOR + 1)):
        findings.append(Finding(
            DenominatorProblem.DENOMINATOR_NOT_CONTIGUOUS,
            f"documented case numbers are not exactly 1..{DECLARED_DENOMINATOR}: {numbers}"))
    return {case.identity.number: case.text.rstrip("\n") for case in matrix.cases}


def _check_allocation_count(root: Path, findings: list[Finding]) -> None:
    """The tracked allocation must still say 42, independently of any artifact.

    The fixture and the transcription are both editable by the same hand, so a
    self-consistent 41-case world would satisfy every other check. The assignment
    toml is a git-tracked file owned by the controller: moving this number takes a
    commit to a different file, not an edit next to the evidence.
    """
    path = root / ASSIGNMENT_REL
    if not path.is_file():
        findings.append(Finding(DenominatorProblem.ALLOCATION_UNREADABLE,
                                f"{ASSIGNMENT_REL} is missing, so the 42-case allocation cannot be confirmed"))
        return
    text = path.read_text(encoding="utf-8")
    declared = set()
    for pattern in (r"Exactly\s+([0-9]{1,6})\s+substantive\s+cases",
                    r"WORK_UNIT_CASE:\s*([0-9]{1,6})\s*\.\.\s*([0-9]{1,6})"):
        for match in re.finditer(pattern, text, re.IGNORECASE):
            for group in match.groups():
                if group:
                    declared.add(int(group))
    if not declared:
        findings.append(Finding(DenominatorProblem.ALLOCATION_UNREADABLE,
                                f"{ASSIGNMENT_REL} states no case count; the allocation cannot confirm 42"))
        return
    if declared != {DECLARED_DENOMINATOR}:
        findings.append(Finding(
            DenominatorProblem.ALLOCATION_COUNT_MISMATCH,
            f"{ASSIGNMENT_REL} declares case numbers {sorted(declared)}, "
            f"but this issue's declared denominator is {DECLARED_DENOMINATOR}"))


def _check_fixture_against_documented(root: Path, expected: dict[int, str], findings: list[Finding]) -> dict | None:
    """The fixture's recorded expected set must equal the documented list.

    This is what stops the denominator from being self-certified: the recorded
    titles are checked against the documented list, not against the tree.
    """
    path = root / FIXTURE_REL
    if not path.is_file():
        findings.append(Finding(DenominatorProblem.FIXTURE_UNREADABLE, f"{FIXTURE_REL} is missing"))
        return None
    try:
        fixture = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        findings.append(Finding(DenominatorProblem.FIXTURE_UNREADABLE, f"{FIXTURE_REL}: {type(exc).__name__}: {exc}"))
        return None

    recorded = fixture.get("case_denominator", {})
    recorded_set = {row.get("case"): (row.get("title") or "").rstrip("\n")
                    for row in recorded.get("expected_set", [])}
    if recorded_set != expected:
        missing = sorted(set(expected) - set(recorded_set))
        extra = sorted(set(recorded_set) - set(expected))
        drifted = sorted(n for n in set(expected) & set(recorded_set) if expected[n] != recorded_set[n])
        findings.append(Finding(
            DenominatorProblem.FIXTURE_EXPECTED_SET_DRIFT,
            f"fixture case_denominator.expected_set disagrees with the documented case list: "
            f"missing={missing} unexpected={extra} title_drift={drifted}"))
    if recorded.get("expected_cases") != DECLARED_DENOMINATOR:
        findings.append(Finding(
            DenominatorProblem.DENOMINATOR_COUNT_MISMATCH,
            f"fixture records expected_cases={recorded.get('expected_cases')}, "
            f"documented denominator is {DECLARED_DENOMINATOR}"))
    return fixture


def _check_recorded_digest_reproduces(fixture: dict, expected: dict[int, str],
                                      assignment_source, findings: list[Finding]) -> str | None:
    """The fixture claims its expected set is 'authenticated by matrix_sha256'.

    That claim is only worth something if the digest actually recomputes. It is
    recomputed here over the very titles this program parsed, with the accepted
    canonical digest. A recorded value that no longer reproduces is an
    unverifiable authority claim, and is reported rather than trusted.
    """
    recorded = fixture.get("case_denominator", {})
    recorded_digest = recorded.get("matrix_sha256")
    if not recorded_digest:
        return None
    computed = assignment_source._canonical_digest({  # noqa: SLF001 - the accepted digest, reused
        "schema": assignment_source.MATRIX_SCHEMA,
        "cases": tuple((n, expected[n] + "\n") for n in sorted(expected)),
    })
    if computed != recorded_digest:
        findings.append(Finding(
            DenominatorProblem.FIXTURE_RECORDED_DIGEST_UNVERIFIED,
            f"fixture records matrix_sha256={recorded_digest} as the authentication of its expected set, "
            f"but the accepted canonical digest over the {len(expected)} documented titles is {computed}; "
            "the recorded authority is not reproducible, so it is reported, not relied on"))
    return computed


def _check_fixture_itself_unchanged(root: Path, findings: list[Finding]) -> None:
    """Proof of AUD-TESTDATA-REVERT by producer, not by hand-editing.

    The fixture is test data. A measurement block written into it is the recorded
    failure mode. This compares the working-tree bytes against the committed blob
    so the revert is re-provable on demand instead of asserted once.
    """
    path = root / FIXTURE_REL
    if not path.is_file():
        findings.append(Finding(DenominatorProblem.FIXTURE_UNREADABLE, f"{FIXTURE_REL} is missing"))
        return
    try:
        working = hashlib.sha1(b"blob " + str(len(path.read_bytes())).encode() + b"\0" + path.read_bytes()).hexdigest()
    except OSError as exc:
        findings.append(Finding(DenominatorProblem.FIXTURE_UNREADABLE,
                                f"{FIXTURE_REL} is unreadable: {type(exc).__name__}: {exc}"))
        return
    code, blob, err = _git(root, "rev-parse", f"HEAD:{FIXTURE_REL}")
    if code != 0 or not blob:
        findings.append(Finding(DenominatorProblem.FIXTURE_UNREADABLE,
                                f"cannot read committed blob for {FIXTURE_REL}: {err or code}"))
        return
    if working != blob:
        findings.append(Finding(
            DenominatorProblem.FIXTURE_MUTATED_AGAINST_HEAD,
            f"{FIXTURE_REL} differs from its committed blob (working={working} head={blob}); "
            "test data must not carry measurement blocks"))


def _check_case_rows(fixture: dict, expected: dict[int, str], findings: list[Finding]) -> None:
    """Every case 1..42 has exactly one fixture row, bound to the documented title."""
    rows = fixture.get("cases", [])
    numbers = [row.get("case") for row in rows]
    if sorted(numbers) != sorted(expected):
        findings.append(Finding(
            DenominatorProblem.FIXTURE_CASE_ROWS_INCOMPLETE,
            f"fixture cases[] covers {len(numbers)} rows, expected exactly 1..{DECLARED_DENOMINATOR}"))
        return
    for row in rows:
        number = row["case"]
        if (row.get("title") or "").rstrip("\n") != expected[number]:
            findings.append(Finding(
                DenominatorProblem.FIXTURE_EXPECTED_SET_DRIFT,
                f"case {number} row title differs from the documented case list"))
        # A row may not claim the registry accepts its marker unless the registry does.
        if row.get("marker_accepted_by_registry") and row.get("binding_state") != "registry-marker-present":
            findings.append(Finding(
                DenominatorProblem.FIXTURE_BINDING_STATE_UNSOUND,
                f"case {number} claims a registry-accepted marker but is recorded as {row.get('binding_state')!r}"))


def _check_family_evidence(fixture: dict, expected: dict[int, str], findings: list[Finding]) -> None:
    """Per-family evidence must cover every documented case exactly once overall.

    A family row's own `declared_site_count_matches_freeze` boolean is a
    self-declaration and is NOT trusted. Each family's site ids are recounted from
    the inventory rows the fixture itself carries and from the family recorded on
    each inventory row, so a family cannot claim a count the inventory does not
    support, and the families must together partition the inventory exactly.
    """
    families = fixture.get("family_evidence", [])
    if not families:
        findings.append(Finding(DenominatorProblem.FIXTURE_FAMILY_EVIDENCE_INCOMPLETE,
                                "fixture carries no family_evidence rows"))
        return
    seen: dict[int, list[str]] = {}
    for row in families:
        name = row.get("family", "<unnamed>")
        for number in row.get("cases", []):
            if number not in expected:
                findings.append(Finding(
                    DenominatorProblem.FIXTURE_FAMILY_EVIDENCE_INCOMPLETE,
                    f"family {name} claims case {number}, which is not a documented case"))
                continue
            seen.setdefault(number, []).append(name)
    unevidenced = sorted(n for n in expected if n not in seen)
    if unevidenced:
        findings.append(Finding(
            DenominatorProblem.FIXTURE_FAMILY_EVIDENCE_INCOMPLETE,
            f"no per-family evidence for documented cases {unevidenced}"))

    inventory = fixture.get("inventory") or fixture.get("sites") or []
    if not inventory:
        findings.append(Finding(
            DenominatorProblem.FIXTURE_FAMILY_SITE_PARTITION_BROKEN,
            "fixture carries no inventory rows, so family site counts cannot be reconciled"))
        return
    by_id = {row.get("n"): row for row in inventory}
    counted: dict[str, int] = {}
    for row in inventory:
        counted[row.get("family", "<unnamed>")] = counted.get(row.get("family", "<unnamed>"), 0) + 1

    claimed: list[str] = []
    for row in families:
        name = row.get("family", "<unnamed>")
        ids = list(row.get("frozen_site_ids") or [])
        claimed.extend(ids)
        actual = counted.get(name, 0)
        if row.get("frozen_sites") != actual or len(ids) != actual:
            findings.append(Finding(
                DenominatorProblem.FIXTURE_FAMILY_COUNT_NOT_RECONCILED,
                f"family {name} declares frozen_sites={row.get('frozen_sites')} over {len(ids)} frozen_site_ids, "
                f"but its inventory rows number {actual}; a self-declared count is not evidence"))
        foreign = sorted(i for i in ids if i in by_id and by_id[i].get("family") != name)
        if foreign:
            findings.append(Finding(
                DenominatorProblem.FIXTURE_FAMILY_COUNT_NOT_RECONCILED,
                f"family {name} claims inventory rows belonging to another family: {foreign[:6]}"))
        if not row.get("declared_site_count_matches_freeze"):
            # Recorded, not re-litigated: the row states its own count does not
            # reconcile, and the recount above is why that is now visible.
            findings.append(Finding(
                DenominatorProblem.FIXTURE_FAMILY_COUNT_NOT_RECONCILED,
                f"family {name} self-declares declared_site_count_matches_freeze=false; its recount above "
                f"is the evidence, so the flag is reported rather than believed"))
        # "Full per-family evidence" means per SITE, not per family count. The
        # issue requires an exact raw API contract and a real production caller
        # for every retained site, so both are recounted from the inventory rows.
        missing_signature = [i for i in ids if i in by_id and not by_id[i].get("raw_signature")]
        if missing_signature:
            findings.append(Finding(
                DenominatorProblem.FIXTURE_FAMILY_EVIDENCE_INCOMPLETE,
                f"family {name}: {len(missing_signature)} of {actual} sites freeze no exact raw API "
                f"signature: {sorted(missing_signature)[:8]}"))
        callerless = [i for i in ids if i in by_id and not [
            c for c in (by_id[i].get("callers") or []) if c.get("state") != "test-only-annotated"]]
        if callerless:
            findings.append(Finding(
                DenominatorProblem.FIXTURE_FAMILY_EVIDENCE_INCOMPLETE,
                f"family {name}: {len(callerless)} of {actual} sites have no production caller "
                f"(only test-only-annotated ones): {sorted(callerless)[:8]}"))
    duplicates = sorted({i for i in claimed if claimed.count(i) > 1})
    if duplicates or sorted(claimed) != sorted(by_id):
        findings.append(Finding(
            DenominatorProblem.FIXTURE_FAMILY_SITE_PARTITION_BROKEN,
            f"family frozen_site_ids do not partition the inventory: {len(claimed)} claimed over "
            f"{len(by_id)} inventory rows, duplicates={duplicates[:6]}, "
            f"unclaimed={sorted(set(by_id) - set(claimed))[:6]}"))


def _observed_markers(root: Path, case_binding, findings: list[Finding]):
    """Observed side: the accepted registry marker parser over the real test file."""
    path = root / TEST_FILE_REL
    if not path.is_file():
        findings.append(Finding(DenominatorProblem.TEST_FILE_UNREADABLE, f"{TEST_FILE_REL} is missing"))
        return {}
    try:
        markers = case_binding.parse_rust_markers(path.read_text(encoding="utf-8"), TEST_FILE_REL)
    except Exception as exc:
        findings.append(Finding(DenominatorProblem.MARKER_ACCEPTANCE_FAILED,
                                f"accepted marker parser rejected {TEST_FILE_REL}: {exc}"))
        return {}
    return {marker.case_number: marker for marker in markers}


def _check_bindings(fixture: dict, expected: dict[int, str], markers: dict, findings: list[Finding]) -> None:
    """Reconcile documented cases against registry-accepted source markers.

    A case with no accepted marker is NOT written off as skipped: the issue states a
    required Windows case that is unexecuted remains unverified, so absence is
    reported as a typed problem rather than rounded away.
    """
    rows = {row["case"]: row for row in fixture.get("cases", []) if isinstance(row.get("case"), int)}
    misidentified: list[int] = []
    for number in sorted(expected):
        marker = markers.get(number)
        row = rows.get(number, {})
        if marker is None:
            findings.append(Finding(
                DenominatorProblem.NO_SOURCE_BINDING,
                f"documented case {number} has no registry-accepted WORK_UNIT_CASE marker; "
                f"the registry's anchored regex accepts only a bare '// WORK_UNIT_CASE: 789/{number}'"))
            continue
        if marker.adequacy_problem is not None:
            findings.append(Finding(
                DenominatorProblem.MARKER_ACCEPTANCE_FAILED,
                f"case {number} marker {marker.qualified_name}: {marker.adequacy_problem.value} "
                f"{marker.adequacy_detail or ''}".strip()))
        # The identity claim: the marker's test must be the test the fixture records.
        recorded_test = row.get("source_test")
        if recorded_test is not None and recorded_test != marker.test_name:
            findings.append(Finding(
                DenominatorProblem.BINDING_IDENTITY_MISIDENTIFIED,
                f"case {number}: fixture records source_test={recorded_test!r} but the registry "
                f"marker binds {marker.test_name!r}"))
        if row.get("title_mismatch"):
            misidentified.append(number)
    if misidentified:
        findings.append(Finding(
            DenominatorProblem.BINDING_IDENTITY_MISIDENTIFIED,
            f"{len(misidentified)} of {DECLARED_DENOMINATOR} case identities are mis-identified: the "
            f"registry-accepted markers bind a superseded credential enumeration, not the "
            f"documented cases {misidentified}"))


def _declared_only_markers(root: Path, findings: list[Finding]) -> int:
    """Count declaration-only marker lines the accepted parser rejects.

    Measured, not asserted. These are the cases the file claims to cover but that
    the registry cannot see; they are the difference between the declared
    denominator and the realised one.
    """
    path = root / TEST_FILE_REL
    if not path.is_file():
        return 0
    accepted = re.compile(r"^\s*//\s*WORK_UNIT_CASE:\s*(\d+)/(\d+)\s*$")
    count = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if "WORK_UNIT_CASE" in line and not accepted.match(line) and re.search(r"WORK_UNIT_CASE:\s*\d+/\d+", line):
            count += 1
    return count


def verify(root: Path) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    try:
        assignment_source, case_binding, contracts = _load_gate(root)
    except RuntimeError as exc:
        return [Finding(DenominatorProblem.GATE_IMPORT_FAILED, str(exc))], {}

    expected = _declared_matrix(assignment_source, contracts, findings)
    if expected is None:
        return findings, {}
    _check_allocation_count(root, findings)
    fixture = _check_fixture_against_documented(root, expected, findings)
    _check_fixture_itself_unchanged(root, findings)
    if fixture is not None:
        _check_case_rows(fixture, expected, findings)
        _check_family_evidence(fixture, expected, findings)
        _check_recorded_digest_reproduces(fixture, expected, assignment_source, findings)
    markers = _observed_markers(root, case_binding, findings)
    if fixture is not None:
        _check_bindings(fixture, expected, markers, findings)

    declared_only = _declared_only_markers(root, findings)
    measured = {
        "expected_cases": len(expected),
        "expected_first": min(expected),
        "expected_last": max(expected),
        "expected_source": "documented issue #789 'Required test matrix' via "
                           "scripts/work_unit_gate/assignment_source.py::parse_matrix",
        "observed_source": "scripts/work_unit_gate/case_binding.py::parse_rust_markers over "
                           + TEST_FILE_REL,
        "registry_accepted_markers": len(markers),
        "registry_accepted_cases": sorted(markers),
        "declaration_only_markers_rejected_by_registry": declared_only,
        "cases_without_registry_binding": sorted(n for n in expected if n not in markers),
        "executed_pass_cases": 0,
        "executed_pass_note": "this program executes no test and reads no execution receipt; "
                              "per I0.5 a NOT_EXECUTED case cannot be promoted by a source report",
        "fixture": FIXTURE_REL,
        "fixture_matches_head": not any(
            f.problem is DenominatorProblem.FIXTURE_MUTATED_AGAINST_HEAD for f in findings),
    }
    return findings, measured


def _render_text(findings: list[Finding], measured: dict) -> str:
    lines = ["CASE_DENOMINATOR_CHECK: " + ("PASS" if not findings else f"FAIL problems={len(findings)}")]
    for key in ("expected_cases", "expected_first", "expected_last", "registry_accepted_markers",
                "declaration_only_markers_rejected_by_registry", "executed_pass_cases",
                "fixture_matches_head"):
        if key in measured:
            lines.append(f"  {key}={measured[key]}")
    missing = measured.get("cases_without_registry_binding", [])
    lines.append(f"  cases_without_registry_binding={len(missing)}"
                 + (f" ({missing[0]}..{missing[-1]})" if missing else ""))
    for finding in findings[:40]:
        lines.append(f"  [{finding.problem.value}] {finding.detail}")
    if len(findings) > 40:
        lines.append(f"  ... ({len(findings) - 40} more findings)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=".", help="Repository root path.")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--self-test", action="store_true",
                        help="Verify this program's own invariants without the repository.")
    args = parser.parse_args(argv)

    if args.self_test:
        # Configuration invariants only. This proves the program's own constants,
        # not any repository evidence; it is a lint, never a denominator proof.
        if ISSUE_NUMBER != 789 or DECLARED_DENOMINATOR != 42:
            print("SELF_TEST: FAIL", file=sys.stderr)
            return 2
        print("SELF_TEST: PASS (configuration invariants only; no repository evidence)")
        return 0

    root = Path(args.root).resolve()
    if not (root / FIXTURE_REL).is_file() or not (root / REPO_MARKER).is_file():
        print(f"error: run from the repository root (missing {REPO_MARKER} or {FIXTURE_REL})", file=sys.stderr)
        return 2
    try:
        findings, measured = verify(root)
    except Exception as exc:  # bounded, non-success
        print(f"error: internal ({type(exc).__name__}: {exc})", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps({"ok": not findings,
                          "measured": measured,
                          "problems": [{"problem": f.problem.value, "detail": f.detail} for f in findings]},
                         indent=2, sort_keys=True))
    else:
        print(_render_text(findings, measured))
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
