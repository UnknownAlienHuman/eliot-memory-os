"""Bounded assignment acquisition for #849; no test or repository mutation.

The caller/controller supplies SourceRequest and (for offline use) a trusted
capture expectation through a separate configuration channel. Nothing in an
issue, snapshot or worker descriptor can create that expectation. Receipts use
contracts v4; parsed spans are source data, not another authority schema.

Markdown grammar v1: one unquoted/unfenced H2 `Required test matrix`, column-zero
ordered cases 1..N, H3 groups, and an explicit numeric denominator. Fenced,
indented, quoted and nested examples do not add cases. Unsupported HTML blocks
and unterminated fences fail closed. Hashes preserve UTF-8, CRLF and whitespace.

The network port sends a full GET (no conditional cache/304 support). A single
in-flight call per adapter bounds DNS/HTTP/file waits at the caller boundary.
A timed-out I/O thread may still be alive; it retains the slot and no late result
is accepted. This is not a sandbox or a claim that a timeout cancelled the OS.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import math
import os
import re
import ssl
import stat
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable

from . import contracts as c

API_ORIGIN = "https://api.github.com"
API_VERSION = "2026-03-10"
MATRIX_SCHEMA = "eliot-assignment-matrix-v1"
SNAPSHOT_SCHEMA = "eliot-assignment-snapshot-v1"
_TOKEN_ENV = frozenset({"GITHUB_TOKEN", "GH_TOKEN"})


class SourceProblem(str, Enum):
    CONFIGURATION = "SOURCE_CONFIGURATION"
    AUTH = "SOURCE_AUTHENTICATION"
    FORBIDDEN = "SOURCE_FORBIDDEN"
    RATE_LIMIT = "SOURCE_RATE_LIMIT"
    NOT_FOUND = "SOURCE_NOT_FOUND"
    UNAVAILABLE = "SOURCE_UNAVAILABLE"
    BUSY = "SOURCE_BUSY"
    TIMEOUT = "SOURCE_TIMEOUT"
    CANCELLED = "SOURCE_CANCELLED"
    REDIRECT = "SOURCE_REDIRECT"
    NOT_MODIFIED = "SOURCE_304_WITHOUT_AUTHORITY"
    ORIGIN = "SOURCE_ORIGIN_MISMATCH"
    MEDIA = "SOURCE_MEDIA_INVALID"
    ENCODING = "SOURCE_ENCODING_INVALID"
    JSON = "SOURCE_JSON_INVALID"
    SCHEMA = "SOURCE_SCHEMA_INVALID"
    RESPONSE_LIMIT = "SOURCE_RESPONSE_LIMIT"
    BODY_LIMIT = "SOURCE_BODY_LIMIT"
    STRUCTURE_LIMIT = "SOURCE_STRUCTURE_LIMIT"
    IDENTITY = "SOURCE_IDENTITY_MISMATCH"
    PR_OBJECT = "SOURCE_IS_PULL_REQUEST"
    CLOSED = "SOURCE_OWNER_CLOSED"
    SUPERSEDED = "SOURCE_OWNER_SUPERSEDED"
    MATRIX_MISSING = "MATRIX_MISSING"
    MATRIX_MULTIPLE = "MATRIX_MULTIPLE"
    MATRIX_HEADING = "MATRIX_HEADING_LEVEL"
    MATRIX_EMPTY = "MATRIX_EMPTY"
    MATRIX_NUMBERING = "MATRIX_NUMBERING_INVALID"
    MATRIX_DENOMINATOR = "MATRIX_DENOMINATOR_INVALID"
    MARKDOWN = "MATRIX_MARKDOWN_UNSUPPORTED"
    UNTRUSTED_CAPTURE = "CAPTURE_NOT_ADMITTED"
    CAPTURE_DIGEST = "CAPTURE_DIGEST_MISMATCH"
    CAPTURE_STALE = "CAPTURE_STALE_OR_INCOMPLETE"
    FILE = "CAPTURE_FILE_UNAVAILABLE"
    INTERNAL = "SOURCE_INTERNAL_FAILURE"


class SourceError(ValueError):
    """Only a fixed reason and cleanup flag escape; never raw exception text."""
    def __init__(self, code: SourceProblem, *, cleanup_pending: bool = False):
        if type(code) is not SourceProblem or type(cleanup_pending) is not bool:
            code, cleanup_pending = SourceProblem.INTERNAL, False
        self.code = code
        self.cleanup_pending = cleanup_pending
        super().__init__(code.value)


def _require(condition: bool, code: SourceProblem) -> None:
    if not condition:
        raise SourceError(code)


def _integer(value: object, low: int, high: int, code=SourceProblem.SCHEMA) -> int:
    _require(type(value) is int and low <= value <= high, code)
    return value


def _text(value: object, limit: int, code=SourceProblem.SCHEMA) -> str:
    _require(type(value) is str and len(value) <= limit, code)
    try:
        _require(len(value.encode("utf-8")) <= limit, code)
    except UnicodeError:
        raise SourceError(SourceProblem.ENCODING) from None
    return value


def _sha(value: object) -> str:
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
             SourceProblem.SCHEMA)
    return value


def _canonical_digest(value: object) -> str:
    try:
        return c.canonical_sha256(value)
    except c.ContractViolation:
        raise SourceError(SourceProblem.SCHEMA) from None


def _revision(value: object) -> str:
    value = _text(value, 32)
    _require(re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value) is not None,
             SourceProblem.SCHEMA)
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise SourceError(SourceProblem.SCHEMA) from None
    return value


@dataclass(frozen=True)
class SourceLimits:
    response_bytes: int = 1_048_576
    body_bytes: int = 262_144
    line_bytes: int = 16_384
    case_bytes: int = 65_536
    json_depth: int = 32
    json_items: int = 50_000
    lines: int = 20_000
    cases: int = 4_096
    connect_ms: int = 5_000
    read_ms: int = 5_000
    total_ms: int = 20_000

    def __post_init__(self) -> None:
        maxima = (4_194_304, 1_048_576, 65_536, 262_144, 64, 100_000,
                  100_000, c.MAX_MATRIX_CASES, 60_000, 60_000, 120_000)
        for name, maximum in zip(self.__dataclass_fields__, maxima):
            _integer(getattr(self, name), 1, maximum, SourceProblem.CONFIGURATION)
        _require(self.body_bytes <= self.response_bytes and self.line_bytes <= self.body_bytes
                 and self.case_bytes <= self.body_bytes
                 and max(self.connect_ms, self.read_ms) <= self.total_ms, SourceProblem.CONFIGURATION)


@dataclass(frozen=True)
class SourceRequest:
    issue: c.IssueIdentity
    unit: c.WorkUnitIdentity
    source_use: c.AssignmentSourceUse
    relation: c.AssignmentRelation | None = None

    def __post_init__(self) -> None:
        _require(type(self.issue) is c.IssueIdentity and type(self.unit) is c.WorkUnitIdentity
                 and type(self.source_use) is c.AssignmentSourceUse, SourceProblem.CONFIGURATION)
        _integer(self.issue.number, 1, 2**63 - 1, SourceProblem.CONFIGURATION)
        _require(re.fullmatch(r"[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*", self.unit.value) is not None,
                 SourceProblem.CONFIGURATION)
        if self.relation is not None:
            _require(type(self.relation) is c.AssignmentRelation, SourceProblem.CONFIGURATION)
            _require(self.issue in (self.relation.source_issue, self.relation.target_issue)
                     and self.relation.source_issue.repository == self.issue.repository
                     and self.relation.target_issue.repository == self.issue.repository, SourceProblem.CONFIGURATION)

    @property
    def endpoint(self) -> str:
        return f"{API_ORIGIN}/repos/{self.issue.repository.full_name}/issues/{self.issue.number}"


@dataclass(frozen=True)
class MatrixCase:
    identity: c.CaseIdentity
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int
    text: str = field(repr=False)


@dataclass(frozen=True)
class ParsedMatrix:
    cases: tuple[MatrixCase, ...]
    body_sha256: str
    matrix_sha256: str


@dataclass(frozen=True)
class AssignmentDocument:
    receipt: c.AssignmentSourceReceipt = field(repr=False)
    matrix: ParsedMatrix = field(repr=False)
    body: str = field(repr=False)
    relation: c.AssignmentRelation | None
    source_updated_at: str
    captured_etag: str | None = field(repr=False)


@dataclass(frozen=True)
class TrustedOfflineCapture:
    """Controller configuration, NEVER constructed from the snapshot itself.

    The controller must protect this configuration and its admitted absolute
    path from the worker. A matching digest alone does not prove an accepted
    merge, and this module provides no signing or worker self-enrolment API.
    """
    request: SourceRequest
    path: Path = field(repr=False)
    snapshot_sha256: str
    producer: c.WorkUnitIdentity
    capture_receipt_sha256: str
    freshness_policy_sha256: str
    max_age_seconds: int

    def __post_init__(self) -> None:
        _require(type(self.request) is SourceRequest and isinstance(self.path, Path)
                 and self.path.is_absolute() and ".." not in self.path.parts
                 and type(self.producer) is c.WorkUnitIdentity, SourceProblem.CONFIGURATION)
        for value in (self.snapshot_sha256, self.capture_receipt_sha256, self.freshness_policy_sha256):
            _sha(value)
        _integer(self.max_age_seconds, 1, 86_400, SourceProblem.CONFIGURATION)


@dataclass(frozen=True)
class HTTPResult:
    """Bounded transport observation; not an assignment-authority receipt."""
    status: int
    url: str
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    body: bytes = field(repr=False)


def _visible_lines(body: str, limits: SourceLimits) -> tuple[list[str], list[bool], list[int]]:
    _text(body, limits.body_bytes, SourceProblem.BODY_LIMIT)
    _require(not re.search(r"\r(?!\n)", body), SourceProblem.MARKDOWN)
    # Only LF is Markdown line structure; Unicode separators remain content.
    lines = body.split("\n")
    lines = [line + "\n" for line in lines[:-1]] + ([lines[-1]] if lines[-1] else [])
    _require(len(lines) <= limits.lines, SourceProblem.STRUCTURE_LIMIT)
    visible, offsets, offset = [], [], 0
    fence: tuple[str, int] | None = None
    for raw in lines:
        encoded = raw.encode("utf-8")
        _require(len(encoded) <= limits.line_bytes, SourceProblem.STRUCTURE_LIMIT)
        offsets.append(offset)
        offset += len(encoded)
        text = raw.rstrip("\r\n")
        if fence:
            if re.fullmatch(r" {0,3}" + re.escape(fence[0]) + "{" + str(fence[1]) + r",}[ \t]*", text):
                fence = None
            visible.append(False)
            continue
        if text.startswith("    ") or text.startswith("\t") or re.match(r" {0,3}>", text):
            visible.append(False)
            continue
        opening = re.match(r" {0,3}(`{3,}|~{3,})(.*)$", text)
        if opening:
            marker, info = opening.groups()
            _require(marker[0] != "`" or "`" not in info, SourceProblem.MARKDOWN)
            fence = (marker[0], len(marker))
            visible.append(False)
            continue
        _require(not re.match(r" {0,3}<(?:!--|/?[A-Za-z][A-Za-z0-9]*\b)", text), SourceProblem.MARKDOWN)
        visible.append(True)
    _require(fence is None, SourceProblem.MARKDOWN)
    offsets.append(offset)
    return lines, visible, offsets


def parse_matrix(body: str, issue: c.IssueIdentity, limits: SourceLimits = SourceLimits()) -> ParsedMatrix:
    """Parse exact case spans; this alone establishes no source authority."""
    _require(type(issue) is c.IssueIdentity and type(limits) is SourceLimits, SourceProblem.CONFIGURATION)
    lines, visible, offsets = _visible_lines(body, limits)
    headings = []
    for index, raw in enumerate(lines):
        if not visible[index]:
            continue
        heading = re.fullmatch(r"(#{1,6})[ \t]+Required test matrix[ \t]*(?:[ \t]+#+)?", raw.rstrip("\r\n"))
        if heading:
            _require(len(heading[1]) == 2, SourceProblem.MATRIX_HEADING)
            headings.append(index)
    _require(len(headings) > 0, SourceProblem.MATRIX_MISSING)
    _require(len(headings) == 1, SourceProblem.MATRIX_MULTIPLE)
    start, end = headings[0] + 1, len(lines)
    for index in range(start, len(lines)):
        if visible[index] and re.match(r"#{1,2}[ \t]+", lines[index]):
            end = index
            break
    starts, stops, declarations = [], [], []
    current: int | None = None
    for index in range(start, end):
        if not visible[index]:
            continue
        text = lines[index].rstrip("\r\n")
        plain = text.replace("**", "").replace("__", "").replace("`", "").strip()
        declaration_seen = False
        for expression in (r"^Declared denominator:\s*([0-9]{1,6})\s+cases?\b",
                           r"^When all ([0-9]{1,6}) cases are green\b"):
            matched = re.search(expression, plain, re.IGNORECASE)
            if matched:
                declaration_seen = True
                declarations.append(int(matched[1]))
                exact = re.search(r"\bexactly\s+(?:cases\s+)?1\.\.([0-9]{1,6})\b", plain, re.IGNORECASE)
                if exact:
                    declarations.append(int(exact[1]))
        if plain.lower().startswith(("declared denominator:", "when all ")):
            _require(declaration_seen, SourceProblem.MATRIX_DENOMINATOR)
        if text and text[0].isdecimal() and not text[0].isascii():
            raise SourceError(SourceProblem.MATRIX_NUMBERING)
        if re.match(r"#{3,6}[ \t]+", text):
            if current is not None:
                stops.append(index)
                current = None
            continue
        numbered = re.fullmatch(r"([0-9]{1,6})[.)][ \t]+(.*)", text)
        if numbered:
            number = int(numbered[1])
            _require(numbered[1] == str(number) and number == len(starts) + 1,
                     SourceProblem.MATRIX_NUMBERING)
            _require(numbered[2].strip() != "", SourceProblem.MATRIX_EMPTY)
            _require(number <= limits.cases, SourceProblem.STRUCTURE_LIMIT)
            if current is not None:
                stops.append(index)
            starts.append((number, index))
            current = index
        elif re.match(r"^[0-9]+(?:[.)]|[ \t:])", text):
            raise SourceError(SourceProblem.MATRIX_NUMBERING)
    if current is not None:
        stops.append(end)
    _require(bool(starts), SourceProblem.MATRIX_EMPTY)
    _require(bool(declarations) and all(number == len(starts) for number in declarations),
             SourceProblem.MATRIX_DENOMINATOR)
    _require(len(starts) == len(stops), SourceProblem.INTERNAL)
    cases = []
    for (number, first), last in zip(starts, stops):
        raw = "".join(lines[first:last])
        _text(raw, limits.case_bytes, SourceProblem.STRUCTURE_LIMIT)
        cases.append(MatrixCase(c.CaseIdentity(issue, number), first + 1, last,
                                offsets[first], offsets[last], raw))
    return ParsedMatrix(tuple(cases), hashlib.sha256(body.encode("utf-8")).hexdigest(),
                        _canonical_digest({"schema": MATRIX_SCHEMA, "cases": tuple(
                            (item.identity.number, item.text) for item in cases)}))


def _json_bytes(raw: bytes, limits: SourceLimits) -> dict:
    _require(type(raw) is bytes and len(raw) <= limits.response_bytes, SourceProblem.RESPONSE_LIMIT)
    depth, items, quoted, escaped = 0, 0, False, False
    for char in raw:
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
        elif char == 34:
            quoted = True
        elif char in (123, 91):
            depth += 1
            items += 1
            _require(depth <= limits.json_depth, SourceProblem.STRUCTURE_LIMIT)
        elif char in (125, 93):
            depth -= 1
        elif char in (44, 58):
            items += 1
        _require(items <= limits.json_items, SourceProblem.STRUCTURE_LIMIT)
    def pairs(entries):
        output = {}
        for key, value in entries:
            _require(key not in output, SourceProblem.JSON)
            output[key] = value
        return output
    def reject_constant(_value):
        raise SourceError(SourceProblem.JSON)
    def integer(value):
        _require(len(value) <= 40, SourceProblem.STRUCTURE_LIMIT)
        return int(value)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_int=integer, parse_constant=reject_constant)
    except UnicodeError:
        raise SourceError(SourceProblem.ENCODING) from None
    except (ValueError, RecursionError) as error:
        if isinstance(error, SourceError):
            raise
        raise SourceError(SourceProblem.JSON) from None
    _require(type(value) is dict, SourceProblem.SCHEMA)
    pending = [value]
    while pending:
        item = pending.pop()
        if type(item) is str:
            _text(item, limits.response_bytes)
        elif type(item) is dict:
            pending.extend(item.keys())
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
        elif type(item) is float:
            _require(math.isfinite(item), SourceProblem.JSON)
    return value


def _relation_value(relation: c.AssignmentRelation | None) -> dict | None:
    if relation is None:
        return None
    return {"source": relation.source_issue.number, "role": relation.role.value,
            "target": relation.target_issue.number}


def _headers(headers: tuple[tuple[str, str], ...]) -> dict[str, str]:
    _require(type(headers) is tuple and len(headers) <= 100, SourceProblem.SCHEMA)
    result, size = {}, 0
    for entry in headers:
        _require(type(entry) is tuple and len(entry) == 2, SourceProblem.SCHEMA)
        key, value = entry
        _text(key, 256)
        _text(value, 65_536)
        size += len(key.encode("utf-8")) + len(value.encode("utf-8"))
        _require(size <= 65_536, SourceProblem.STRUCTURE_LIMIT)
        key = key.lower()
        _require(key not in result, SourceProblem.SCHEMA)
        result[key] = value
    return result


def _etag(value: object) -> str | None:
    if value is None:
        return None
    value = _text(value, c.MAX_TOKEN_BYTES)
    _require(re.fullmatch(r'(?:W/)?"[\x21\x23-\x7e]*"', value) is not None, SourceProblem.SCHEMA)
    return value


def _issue_document(payload: dict, request: SourceRequest, limits: SourceLimits,
                    authority: c.SourceAuthority, *, capture: c.OfflineCaptureBinding | None = None,
                    etag: str | None = None) -> AssignmentDocument:
    _require("pull_request" not in payload, SourceProblem.PR_OBJECT)
    _require(payload.get("url") == request.endpoint
             and payload.get("repository_url") == f"{API_ORIGIN}/repos/{request.issue.repository.full_name}"
             and payload.get("html_url") == f"https://github.com/{request.issue.repository.full_name}/issues/{request.issue.number}",
             SourceProblem.ORIGIN)
    _require(_integer(payload.get("number"), 1, 2**63 - 1) == request.issue.number, SourceProblem.IDENTITY)
    title = _text(payload.get("title"), c.MAX_TITLE_BYTES)
    body = _text(payload.get("body"), limits.body_bytes, SourceProblem.BODY_LIMIT)
    states = ("open", "closed", "superseded") if authority is c.SourceAuthority.EXPLICIT_OFFLINE_SNAPSHOT else ("open", "closed")
    _require(type(payload.get("state")) is str and payload["state"] in states, SourceProblem.SCHEMA)
    state = c.IssueState(payload["state"])
    labels = payload.get("labels")
    _require(type(labels) is list and len(labels) <= 100, SourceProblem.SCHEMA)
    label_names = []
    for label in labels:
        _require(type(label) is dict, SourceProblem.SCHEMA)
        label_names.append(_text(label.get("name"), 256).lower())
    lines, visible, _ = _visible_lines(body, limits)
    superseded = (any(label in ("superseded", "status:superseded") for label in label_names)
                  or title.lower().startswith("[superseded]")
                  or re.match(r"^\[[^\]]+\] (?:\[SUPERSEDED\]|SUPERSEDED\b)", title, re.IGNORECASE)
                  or any(active and re.match(r"^(?:Disposition:\s*)?Superseded by #[0-9]+\b", line, re.IGNORECASE)
                         for line, active in zip(lines, visible)))
    if superseded:
        state = c.IssueState.SUPERSEDED
    if request.source_use is c.AssignmentSourceUse.ACTIVE_ASSIGNMENT:
        _require(state is not c.IssueState.SUPERSEDED, SourceProblem.SUPERSEDED)
        _require(state is c.IssueState.OPEN, SourceProblem.CLOSED)
    match = re.fullmatch(r"\[([A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*)\] [^\r\n]+", title)
    _require(match is not None and match[1] == request.unit.value, SourceProblem.IDENTITY)
    revision = _revision(payload.get("updated_at"))
    matrix = parse_matrix(body, request.issue, limits)
    proof = "assignment-source-only" if request.source_use is c.AssignmentSourceUse.ACTIVE_ASSIGNMENT else "historical-assignment-source-only"
    try:
        receipt = c.AssignmentSourceReceipt(request.issue, state, request.unit, authority,
            title, matrix.body_sha256, len(matrix.cases), c.ProofCeiling(proof), matrix.matrix_sha256,
            request.source_use, API_ORIGIN, etag if authority is c.SourceAuthority.LIVE_GITHUB else None, capture)
    except c.ContractViolation:
        raise SourceError(SourceProblem.IDENTITY) from None
    return AssignmentDocument(receipt, matrix, body, request.relation, revision, etag)


def _live_document(response: HTTPResult, request: SourceRequest, limits: SourceLimits) -> AssignmentDocument:
    _require(type(response) is HTTPResult and type(response.status) is int, SourceProblem.SCHEMA)
    _require(response.url == request.endpoint, SourceProblem.ORIGIN)
    headers = _headers(response.headers)
    if response.status == 304:
        raise SourceError(SourceProblem.NOT_MODIFIED)
    if 300 <= response.status < 400:
        raise SourceError(SourceProblem.REDIRECT)
    if response.status == 429 or (response.status == 403 and
            (headers.get("x-ratelimit-remaining") == "0" or "retry-after" in headers)):
        raise SourceError(SourceProblem.RATE_LIMIT)
    if response.status == 401:
        raise SourceError(SourceProblem.AUTH)
    if response.status == 403:
        raise SourceError(SourceProblem.FORBIDDEN)
    if response.status in (404, 410):
        raise SourceError(SourceProblem.NOT_FOUND)
    _require(response.status == 200, SourceProblem.UNAVAILABLE)
    media = headers.get("content-type", "").lower().split(";")
    _require(media[0].strip() in ("application/json", "application/vnd.github+json", "application/vnd.github.raw+json")
             and all(part.strip() in ("charset=utf-8", 'charset="utf-8"') for part in media[1:]), SourceProblem.MEDIA)
    _require(headers.get("content-encoding", "identity").lower() == "identity", SourceProblem.MEDIA)
    return _issue_document(_json_bytes(response.body, limits), request, limits,
                           c.SourceAuthority.LIVE_GITHUB, etag=_etag(headers.get("etag")))


def _https_get(request: SourceRequest, limits: SourceLimits, token: str | None) -> HTTPResult:
    """Fixed-host GET. The outer single-flight guard bounds DNS/header waits."""
    deadline = time.monotonic() + limits.total_ms / 1000
    connection = http.client.HTTPSConnection("api.github.com", timeout=limits.connect_ms / 1000,
                                             context=ssl.create_default_context())
    headers = {"Accept": "application/vnd.github.raw+json", "Accept-Encoding": "identity",
               "User-Agent": "eliot-work-unit-source/1", "X-GitHub-Api-Version": API_VERSION}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    try:
        connection.connect()
        _require(connection.sock is not None, SourceProblem.UNAVAILABLE)
        connection.sock.settimeout(min(limits.read_ms / 1000, max(.001, deadline - time.monotonic())))
        connection.request("GET", request.endpoint[len(API_ORIGIN):], headers=headers)
        response = connection.getresponse()
        response_headers = tuple(response.getheaders())
        checked = _headers(response_headers)
        output = bytearray()
        if response.status == 200:
            length = checked.get("content-length")
            if length is not None:
                _require(re.fullmatch(r"[0-9]{1,12}", length) is not None, SourceProblem.SCHEMA)
                _require(int(length) <= limits.response_bytes, SourceProblem.RESPONSE_LIMIT)
            while True:
                remaining = deadline - time.monotonic()
                _require(remaining > 0, SourceProblem.TIMEOUT)
                if connection.sock is not None:
                    connection.sock.settimeout(min(limits.read_ms / 1000, remaining))
                chunk = response.read1(min(8192, limits.response_bytes + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                _require(len(output) <= limits.response_bytes, SourceProblem.RESPONSE_LIMIT)
            if length is not None:
                _require(len(output) == int(length), SourceProblem.JSON)
        return HTTPResult(response.status, request.endpoint, response_headers, bytes(output))
    except TimeoutError:
        raise SourceError(SourceProblem.TIMEOUT) from None
    except (OSError, http.client.HTTPException):
        raise SourceError(SourceProblem.UNAVAILABLE) from None
    finally:
        connection.close()


def _read_capture(path: Path, limit: int) -> bytes:
    """No-follow regular-file read; a digest still binds the actual bytes read."""
    directory = None
    try:
        if os.name == "posix":
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            directory = os.open(path.anchor, flags)
            for segment in path.parts[1:-1]:
                child = os.open(segment, flags, dir_fd=directory)
                os.close(directory)
                directory = child
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        else:
            # Windows controller admission must also protect ancestor directory
            # mutation; reject observed reparse points and compare opened identity.
            for item in (*reversed(path.parents), path):
                observed = item.lstat()
                _require(not stat.S_ISLNK(observed.st_mode)
                         and not getattr(observed, "st_file_attributes", 0) & 0x400, SourceProblem.FILE)
            observed = path.lstat()
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        with os.fdopen(fd, "rb") as stream:
            actual = os.fstat(stream.fileno())
            _require(stat.S_ISREG(actual.st_mode), SourceProblem.FILE)
            if os.name != "posix":
                _require((actual.st_dev, actual.st_ino) == (observed.st_dev, observed.st_ino), SourceProblem.FILE)
            raw = stream.read(limit + 1)
        _require(len(raw) <= limit, SourceProblem.RESPONSE_LIMIT)
        return raw
    except (OSError, ValueError) as error:
        if isinstance(error, SourceError):
            raise
        raise SourceError(SourceProblem.FILE) from None
    finally:
        if directory is not None:
            os.close(directory)


_CAPTURE_FIELDS = frozenset({"repository", "number", "title", "body", "unit", "state", "source_use",
    "relation", "body_sha256", "matrix_sha256", "origin", "updated_at", "etag", "producer",
    "capture_receipt_sha256", "freshness_policy_sha256", "captured_at", "expires_at", "invalidated",
    "complete", "source_mode", "base_commit", "labels"})


def _offline_document(raw: bytes, admitted: TrustedOfflineCapture, limits: SourceLimits,
                      now: int) -> AssignmentDocument:
    snapshot = _json_bytes(raw, limits)
    _require(set(snapshot) == {"schema", "snapshot_sha256", "payload"}
             and snapshot["schema"] == SNAPSHOT_SCHEMA and type(snapshot["payload"]) is dict, SourceProblem.SCHEMA)
    payload = snapshot["payload"]
    _require(set(payload) == _CAPTURE_FIELDS, SourceProblem.SCHEMA)
    digest = _canonical_digest({"schema": SNAPSHOT_SCHEMA, "payload": payload})
    _require(_sha(snapshot["snapshot_sha256"]) == digest == admitted.snapshot_sha256, SourceProblem.CAPTURE_DIGEST)
    request = admitted.request
    relation = payload["relation"]
    if relation is not None:
        _require(type(relation) is dict and set(relation) == {"source", "role", "target"}, SourceProblem.SCHEMA)
        _integer(relation["source"], 1, 2**63 - 1)
        _integer(relation["target"], 1, 2**63 - 1)
        _require(type(relation["role"]) is str, SourceProblem.SCHEMA)
    _require(payload["repository"] == request.issue.repository.full_name
             and payload["number"] == request.issue.number and payload["unit"] == request.unit.value
             and payload["source_use"] == request.source_use.value
             and payload["relation"] == _relation_value(request.relation), SourceProblem.IDENTITY)
    _require(payload["origin"] == API_ORIGIN and payload["source_mode"] == c.SourceAuthority.LIVE_GITHUB.value,
             SourceProblem.ORIGIN)
    _require(payload["producer"] == admitted.producer.value
             and _sha(payload["capture_receipt_sha256"]) == admitted.capture_receipt_sha256
             and _sha(payload["freshness_policy_sha256"]) == admitted.freshness_policy_sha256, SourceProblem.UNTRUSTED_CAPTURE)
    _require(type(payload["complete"]) is bool and payload["complete"]
             and type(payload["invalidated"]) is bool and not payload["invalidated"], SourceProblem.CAPTURE_STALE)
    captured = _integer(payload["captured_at"], 0, 2**63 - 1)
    expires = _integer(payload["expires_at"], 0, 2**63 - 1)
    _integer(now, 0, 2**63 - 1, SourceProblem.CONFIGURATION)
    _require(captured <= now < expires and now - captured <= admitted.max_age_seconds
             and expires - captured <= admitted.max_age_seconds, SourceProblem.CAPTURE_STALE)
    base = payload["base_commit"]
    _require(base is None or (type(base) is str and re.fullmatch(r"[0-9a-f]{40}", base) is not None), SourceProblem.SCHEMA)
    matrix = parse_matrix(payload["body"], request.issue, limits)
    _require(_sha(payload["body_sha256"]) == matrix.body_sha256
             and _sha(payload["matrix_sha256"]) == matrix.matrix_sha256, SourceProblem.CAPTURE_DIGEST)
    capture = c.OfflineCaptureBinding(request.issue, request.unit, matrix.body_sha256, matrix.matrix_sha256,
        digest, admitted.snapshot_sha256, admitted.producer, admitted.capture_receipt_sha256,
        admitted.capture_receipt_sha256, admitted.freshness_policy_sha256, captured, expires, False)
    # Reuse the same issue validation, but keep archived ETag separate from live authority.
    issue_payload = {key: payload[key] for key in ("number", "title", "body", "state", "labels", "updated_at")}
    issue_payload.update(url=request.endpoint, repository_url=f"{API_ORIGIN}/repos/{request.issue.repository.full_name}",
                         html_url=f"https://github.com/{request.issue.repository.full_name}/issues/{request.issue.number}")
    return _issue_document(issue_payload, request, limits, c.SourceAuthority.EXPLICIT_OFFLINE_SNAPSHOT,
                           capture=capture, etag=_etag(payload["etag"]))


class AssignmentSource:
    """One configured assignment, no caller URL, fallback, cache or write API.

    `_transport` and `_reader` are trusted dependency/test seams, not inputs read
    from a worker file. They do not authenticate arbitrary code inside Python.
    Reuse this instance: after timeout its one in-flight slot remains occupied
    until the real read returns. No late success or implicit retry is delivered.
    """
    def __init__(self, request: SourceRequest, *, limits: SourceLimits = SourceLimits(),
                 offline: TrustedOfflineCapture | None = None, token_env: str | None = None,
                 clock: Callable[[], int] = lambda: int(time.time()),
                 _transport: Callable = _https_get, _reader: Callable = _read_capture):
        _require(type(request) is SourceRequest and type(limits) is SourceLimits, SourceProblem.CONFIGURATION)
        _require(token_env is None or type(token_env) is str and token_env in _TOKEN_ENV, SourceProblem.CONFIGURATION)
        _require(callable(clock) and callable(_transport) and callable(_reader), SourceProblem.CONFIGURATION)
        if offline is not None:
            _require(type(offline) is TrustedOfflineCapture and offline.request == request, SourceProblem.UNTRUSTED_CAPTURE)
        self._request, self._limits, self._offline = request, limits, offline
        self._token_env, self._clock = token_env, clock
        self._transport, self._reader = _transport, _reader
        self._slot = threading.Lock()

    def read(self, mode: c.SourceAuthority) -> AssignmentDocument:
        _require(type(mode) is c.SourceAuthority, SourceProblem.CONFIGURATION)
        _require(mode is not c.SourceAuthority.EXPLICIT_OFFLINE_SNAPSHOT or self._offline is not None,
                 SourceProblem.UNTRUSTED_CAPTURE)
        _require(self._slot.acquire(blocking=False), SourceProblem.BUSY)
        done, outcome = threading.Event(), []
        deadline = time.monotonic() + self._limits.total_ms / 1000
        def work():
            try:
                if mode is c.SourceAuthority.LIVE_GITHUB:
                    token = None
                    if self._token_env is not None:
                        token = os.environ.get(self._token_env)
                        _require(type(token) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,512}", token) is not None,
                                 SourceProblem.AUTH)
                    response = self._transport(self._request, self._limits, token)
                    result = _live_document(response, self._request, self._limits)
                else:
                    assert self._offline is not None
                    raw = self._reader(self._offline.path, self._limits.response_bytes)
                    result = _offline_document(raw, self._offline, self._limits, self._clock())
                    capture = result.receipt.offline_capture
                    assert capture is not None
                    now = _integer(self._clock(), 0, 2**63 - 1, SourceProblem.CONFIGURATION)
                    _require(capture.captured_at <= now < capture.expires_at
                             and now - capture.captured_at <= self._offline.max_age_seconds,
                             SourceProblem.CAPTURE_STALE)
                _require(time.monotonic() <= deadline, SourceProblem.TIMEOUT)
                outcome.append(result)
            except SourceError as error:
                outcome.append(error)
            except TimeoutError:
                outcome.append(SourceError(SourceProblem.TIMEOUT))
            except OSError:
                outcome.append(SourceError(SourceProblem.UNAVAILABLE))
            except Exception:
                outcome.append(SourceError(SourceProblem.INTERNAL))
            finally:
                self._slot.release()
                done.set()
        try:
            threading.Thread(target=work, name="eliot-assignment-read", daemon=True).start()
        except RuntimeError:
            self._slot.release()
            raise SourceError(SourceProblem.UNAVAILABLE) from None
        try:
            finished = done.wait(max(0, deadline - time.monotonic()))
        except KeyboardInterrupt:
            raise SourceError(SourceProblem.CANCELLED, cleanup_pending=not done.is_set()) from None
        if not finished:
            raise SourceError(SourceProblem.TIMEOUT, cleanup_pending=True)
        _require(len(outcome) == 1, SourceProblem.INTERNAL)
        if isinstance(outcome[0], SourceError):
            raise outcome[0] from None
        return outcome[0]
