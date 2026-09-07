"""Closed parsing and fixed Python child protocol for work-unit runner #850.

This is an incremental runner component, NOT the complete acceptance gate.
The controller must supply an admitted process-tree execution port, source
snapshot and toolchain evidence. This module neither spawns a process nor
claims containment. A parsed child record is not a trusted execution receipt.
The v4 shared contracts remain the descriptor owner; only parse_descriptor
constructs that public type. No legacy promotion or descriptor command field.

Fixed argv constructors below build command vectors only; they never start a
child. The controller owns interpreter/toolchain resolution, working
directories, owned process-tree containment, timeouts and cleanup. Environment
filtering passes names only, never secret values. This module is not a sandbox
against hostile test code.

Adapter role: this module consumes controller-owned observations (admitted
descriptors, captured cargo/python transcripts, metadata, snapshots,
environments) and emits authoritative typed bindings; execution and
containment stay controller-owned.
"""
from __future__ import annotations

import hashlib
import importlib
import importlib.machinery
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import stat
import sys
import tomllib
import unittest
from dataclasses import dataclass

DESCRIPTOR_SCHEMA = "eliot-work-unit-descriptor-v2"
PYTHON_PROTOCOL = "eliot-python-child-v1"
MAX_DESCRIPTOR_BYTES = 65536
MAX_PROTOCOL_BYTES = 1048576
MAX_LINE_BYTES = 65536
MAX_TESTS = 100000
MAX_ROOTS = 256
MAX_SOURCE_BYTES = 8388608
MODES = frozenset(("rust-package", "python-unittest", "metadata-python"))
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}\Z")
_PY_MODULE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z")
_RUST_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*\Z")
_STATUSES = frozenset(("pass", "failure", "error", "skip", "expected-failure", "unexpected-success"))
_SAFE_COMMAND_ARG = re.compile(r"[A-Za-z0-9_./:=-]+\Z")
# Package-mode cargo invocations must never carry one of these. Constructors
# are structurally incapable of emitting them; assert_no_workspace_wide
# rechecks every argv at runtime.
WORKSPACE_WIDE_FLAGS = frozenset(("--workspace", "--all"))
# Caller-supplied cargo metadata classification. Strings are preserved verbatim
# in the returned binding; this module never edits membership.
MEMBER_KINDS = frozenset(("member", "excluded", "standalone", "unavailable"))
# Minimal nonsecret child environment. Exact names only, no prefix wildcards:
# build-scoped CARGO_*/RUST_* passthrough stays controller-owned policy, never
# an implicit passthrough here. Entries naming a blocked marker are dropped
# even when explicitly allowed.
ALLOWED_ENV_NAMES = frozenset((
    "PATH", "SYSTEMROOT", "TEMP", "TMP",
    "PYTHONDONTWRITEBYTECODE", "PYTHONIOENCODING",
))
BLOCKED_ENV_MARKERS = frozenset(("TOKEN", "SECRET", "CREDENTIAL", "PASSWORD", "KEY"))
# Bounded child-environment byte caps (UTF-8 byte lengths, not characters).
ENV_VALUE_CAP = 4096
ENV_TOTAL_CAP = 65536
# Proven cargo/rustc toolchain names. Sufficiency was proven with one scratch
# zero-dep build+test under toolchain_child_env in %TEMP% (direct rustc
# 1.97.1, RUSTC_WRAPPER forced empty); see toolchain_child_env. The fixed set
# below plus the build-scoped CARGO_*/RUST_* prefix rule is the whole policy.
TOOLCHAIN_ENV_NAMES = frozenset((
    "PATH", "SYSTEMROOT", "SYSTEMDRIVE", "PROGRAMDATA", "TEMP", "TMP",
    "PATHEXT", "OS", "USERPROFILE", "COMSPEC", "WINDIR", "LOCALAPPDATA",
))
# Suffixes that mark a metadata value as a generator/mutation/network spelling
# rather than a dotted registered-suite identity.
_METADATA_FORBIDDEN_SUFFIXES = (".py", ".pyw", ".pyc", ".pyd", ".ps1", ".psm1",
                                ".psd1", ".sh", ".exe", ".bat", ".dll", ".so", ".dylib",
                                ".js", ".com", ".cmd", ".vbs")
# Phase x outcome verdicts. Only a complete discovery and an exact terminal
# pass record are green. Skip and expected-failure are valid observations but
# cannot satisfy a selected identity, so they stay non-green here.
PHASE_TRUTH_TABLE = {
    ("discover", "complete"): "green",
    ("discover", "empty"): "non-green",
    ("discover", "malformed"): "non-green",
    ("execute", "pass"): "green",
    ("execute", "failure"): "non-green",
    ("execute", "error"): "non-green",
    ("execute", "skip"): "non-green",
    ("execute", "expected-failure"): "non-green",
    ("execute", "unexpected-success"): "non-green",
    ("execute", "missing"): "non-green",
    ("execute", "timeout"): "non-green",
}


class RunnerInputError(ValueError):
    """Stable redacted parser error. It carries no candidate source or output."""


def _reject(code: str):
    raise RunnerInputError(code)


def _keys(value, required, optional=()):
    if type(value) is not dict or any(type(k) is not str for k in value):
        _reject("OBJECT_REQUIRED")
    if not set(required).issubset(value) or set(value) - set(required) - set(optional):
        _reject("CLOSED_FIELDS")
    return value


def _integer(value, maximum, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        _reject("INTEGER_BOUND")
    return value


def _text(value, maximum=1024):
    if type(value) is not str:
        _reject("TEXT_REQUIRED")
    try:
        length = len(value.encode("utf-8"))
    except UnicodeError:
        _reject("UTF8_REQUIRED")
    if not value or length > maximum or any(ord(c) < 32 for c in value):
        _reject("TEXT_BOUND")
    return value


def _identity(value, field="value"):
    _keys(value, (field,))
    text = _text(value[field], 128)
    if not _IDENT.fullmatch(text):
        _reject("IDENTITY_SYNTAX")
    return value


def _sha(value):
    if type(value) is not str or not _HEX.fullmatch(value):
        _reject("SHA256_REQUIRED")
    return value


def _bounded_json(raw: bytes, maximum=MAX_PROTOCOL_BYTES):
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        _reject("INPUT_BYTE_BOUND")
    # Check nesting before JSON allocation. Strings and escape sequences do not
    # count as structure. A bounded decoder later rejects malformed structure.
    depth = 0
    in_string = escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                in_string = False
        elif byte == 34:
            in_string = True
        elif byte in (91, 123):
            depth += 1
            if depth > 32:
                _reject("JSON_DEPTH_BOUND")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                _reject("MALFORMED_JSON")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _reject("DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    def constant(_):
        _reject("NONFINITE_JSON")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except RunnerInputError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        _reject("MALFORMED_JSON")


def _relative_path(value):
    value = _text(value)
    parts = value.split("/")
    if (value.startswith("/") or "\\" in value or any(p in ("", ".", "..") for p in parts)
            or any(c in value for c in ":*?[]")
            or any(p.endswith((" ", ".")) for p in parts)):
        _reject("NONCANONICAL_PATH")
    # Literal percent text is never URL-decoded.
    return value


def _safe_path(root: Path, relative: str):
    """Resolve a repository-relative path with link/reparse checks.

    Detection, not prevention: lstat checks and the later open/read are
    separate steps, so a concurrently executing admitted test could swap an
    entry between check and use (TOCTOU). Callers must treat this as they
    treat snapshot comparison -- invalidation evidence, not a barrier -- and
    never run unadmitted source under it.
    """
    relative = _relative_path(relative)
    try:
        root = root.resolve(strict=True)
        current = root
        for part in relative.split("/"):
            current = current / part
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                _reject("LINK_OR_REPARSE_PATH")
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                _reject("NONREGULAR_PATH")
        current.resolve(strict=True).relative_to(root)
        return current
    except RunnerInputError:
        raise
    except (OSError, ValueError):
        _reject("PATH_UNAVAILABLE")


def decode_descriptor(raw: bytes, filename: str):
    """Validate the closed primitive representation before constructing v4.

    filename is the registered repository-relative numeric descriptor path.
    This function does not establish acquisition authority or path existence.
    """
    if type(raw) is not bytes or not raw or len(raw) > MAX_DESCRIPTOR_BYTES:
        _reject("DESCRIPTOR_BYTE_BOUND")
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError):
        _reject("MALFORMED_TOML")
    required = ("schema_version", "identity", "issue", "unit", "mode", "source_roots",
                "test_roots", "matrix_cases", "proof_ceiling", "revision", "body_sha256",
                "matrix_sha256", "require_workspace_member", "requirements", "bounds")
    _keys(data, required, ("package", "module"))
    if data["schema_version"] != DESCRIPTOR_SCHEMA or type(data["mode"]) is not str or data["mode"] not in MODES:
        _reject("UNSUPPORTED_SCHEMA_OR_MODE")
    for key in ("identity", "unit", "proof_ceiling"):
        _identity(data[key])
    if "package" in data:
        _identity(data["package"], "name")
    if "module" in data:
        _identity(data["module"])
    _keys(data["issue"], ("repository", "number"))
    _keys(data["issue"]["repository"], ("owner", "name"))
    for text in data["issue"]["repository"].values():
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", _text(text, 100)):
            _reject("REPOSITORY_SYNTAX")
    number = _integer(data["issue"]["number"], 2**63-1, 1)
    if filename != f".github/work-units/{number}.toml":
        _reject("DESCRIPTOR_FILENAME_MISMATCH")
    if data["identity"]["value"] != f"work-unit-{number}":
        _reject("DESCRIPTOR_IDENTITY_MISMATCH")
    _integer(data["revision"], 2**63-1, 1)
    count = _integer(data["matrix_cases"], MAX_TESTS, 1)
    _sha(data["body_sha256"])
    _sha(data["matrix_sha256"])
    if type(data["require_workspace_member"]) is not bool:
        _reject("MEMBERSHIP_BOOL_REQUIRED")
    if (data["mode"] == "rust-package" or data["require_workspace_member"]) and "package" not in data:
        _reject("PACKAGE_REQUIRED")
    for key in ("source_roots", "test_roots"):
        values = data[key]
        if type(values) is not list or not 1 <= len(values) <= MAX_ROOTS:
            _reject("ROOT_DENOMINATOR")
        paths = [_relative_path(v.get("value")) if type(v) is dict and set(v) == {"value"}
                 else _reject("ROOT_SHAPE") for v in values]
        if len(set(paths)) != len(paths) or any(len(p.split("/")) < 2 for p in paths):
            _reject("DUPLICATE_OR_BROAD_ROOT")
    required_floors = ("source_floor", "public_floor", "test_floor", "required_guards")
    floors = _keys(data["requirements"], required_floors)
    for key in required_floors[:3]:
        _integer(floors[key], MAX_TESTS)
    if floors["test_floor"] < count:
        _reject("TEST_FLOOR_TOO_LOW")
    guards = floors["required_guards"]
    if type(guards) is not list or len(guards) > 64:
        _reject("GUARD_BOUND")
    names = [_identity(g)["value"] for g in guards]
    if len(names) != len(set(names)):
        _reject("DUPLICATE_GUARD")
    bounds = _keys(data["bounds"], ("wall_ms", "idle_ms", "output_bytes", "line_bytes", "discovery_tests", "child_processes"))
    maxima = (86400000, 86400000, 67108864, 1048576, MAX_TESTS, 64)
    for key, limit in zip(("wall_ms", "idle_ms", "output_bytes", "line_bytes", "discovery_tests", "child_processes"), maxima):
        _integer(bounds[key], limit, 1)
    if bounds["idle_ms"] > bounds["wall_ms"] or bounds["line_bytes"] > bounds["output_bytes"] or bounds["discovery_tests"] < count:
        _reject("INCONSISTENT_BOUNDS")
    return data


def parse_descriptor(raw: bytes, filename: str, assignment):
    """Return the actual #857 descriptor, bound to a supplied #849 receipt.

    Live/offline acquisition authority must already have been verified by #849.
    The pure primitive parser above cannot supply it.
    """
    from . import contracts as c
    data = decode_descriptor(raw, filename)
    if type(assignment) is not c.AssignmentSourceReceipt:
        _reject("ASSIGNMENT_RECEIPT_REQUIRED")
    if assignment.source_use is not c.AssignmentSourceUse.ACTIVE_ASSIGNMENT or assignment.state is not c.IssueState.OPEN:
        _reject("INACTIVE_ASSIGNMENT")
    issue = data["issue"]
    repo = c.RepositoryIdentity(**issue["repository"])
    converted = dict(data)
    converted.update(
        identity=c.DescriptorIdentity(**data["identity"]),
        issue=c.IssueIdentity(repo, issue["number"]), unit=c.WorkUnitIdentity(**data["unit"]),
        mode=c.RunnerMode(data["mode"]), proof_ceiling=c.ProofCeiling(**data["proof_ceiling"]),
        source_roots=tuple(c.RepositoryPath(**p) for p in data["source_roots"]),
        test_roots=tuple(c.RepositoryPath(**p) for p in data["test_roots"]),
        requirements=c.VerificationRequirements(**(data["requirements"] | {
            "required_guards": tuple(c.WorkUnitIdentity(**g) for g in data["requirements"]["required_guards"])})),
        bounds=c.ExecutionBounds(**data["bounds"]),
        package=c.PackageIdentity(**data["package"]) if "package" in data else None,
        module=c.ModuleIdentity(**data["module"]) if "module" in data else None)
    try:
        descriptor = c.WorkUnitDescriptor.from_mapping(converted)
    except c.ContractViolation:
        _reject("SHARED_DESCRIPTOR_REJECTED")
    for key in ("issue", "unit", "matrix_cases", "body_sha256", "matrix_sha256"):
        if getattr(descriptor, key) != getattr(assignment, key):
            _reject("STALE_ASSIGNMENT_BINDING")
    return descriptor


def parse_rust_discovery(raw: bytes, maximum: int):
    """Parse only terse libtest discovery lines. Never an execution pass."""
    _integer(maximum, MAX_TESTS, 1)
    if type(raw) is not bytes or len(raw) > MAX_PROTOCOL_BYTES:
        _reject("OUTPUT_BYTE_BOUND")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        _reject("OUTPUT_UTF8")
    names = []
    for line in text.splitlines():
        if len(line) > 1024:
            _reject("DISCOVERY_LINE_BOUND")
        if not line.endswith(": test") or not _RUST_NAME.fullmatch(line[:-6]):
            _reject("UNSUPPORTED_DISCOVERY_GRAMMAR")
        names.append(line[:-6])
        if len(names) > maximum:
            _reject("DISCOVERY_BOUND")
    if not names or len(set(names)) != len(names):
        _reject("EMPTY_OR_DUPLICATE_DISCOVERY")
    return tuple(sorted(names))


@dataclass(frozen=True)
class ParsedRustResult:
    """Intrinsic observation, NOT a shared test execution receipt."""
    identity: str
    outcome: str
    filtered: int


def parse_rust_exact(raw: bytes, selected: str, returncode: int, discovered_count: int):
    """Accept a strict single-test pretty libtest success transcript.

    Untrusted stdout is not generally a status channel. Only this complete
    anchored grammar can describe success, and its code/count/name must match.
    Caller additionally binds binary bytes, owned execution and captured stream.
    No supported Rust toolchain is certified by these grammar checks alone.
    The selected identity is length-capped before matching so an untrusted
    megabyte-scale name cannot drive pathological matching cost in the parent.
    """
    if type(selected) is not str or len(selected) > 256 or not _RUST_NAME.fullmatch(selected):
        _reject("RUST_IDENTITY_SYNTAX")
    _integer(discovered_count, MAX_TESTS, 1)
    if type(returncode) is not int:
        _reject("EXIT_CODE_REQUIRED")
    if type(raw) is not bytes or len(raw) > MAX_PROTOCOL_BYTES:
        _reject("OUTPUT_BYTE_BOUND")
    try:
        text = raw.decode("utf-8").replace("\r\n", "\n")
    except UnicodeError:
        _reject("OUTPUT_UTF8")
    name = re.escape(selected)
    grammar = (r"\nrunning 1 test\ntest " + name + r" \.\.\. ok\n\n"
               r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; "
               + str(discovered_count - 1) + r" filtered out; finished in [0-9]+\.[0-9]+s\n\n")
    if returncode == 0 and re.fullmatch(grammar, text):
        return ParsedRustResult(selected, "pass", discovered_count - 1)
    if " ... ignored" in text:
        _reject("IGNORED_NOT_EXECUTED")
    if returncode != 0:
        _reject("TEST_OR_HARNESS_FAILED")
    _reject("UNTRUSTED_OR_INCOMPLETE_RESULT")


def parse_python_protocol(raw: bytes, *, request_sha256: str, expected_module: str,
                          expected_source_sha256: str, expected_phase: str, expected_discovery=None):
    """Decode the dedicated runner-owned channel, not stdout/stderr.

    The external process owner must bind the bytes to its exact child and
    request. A caller-provided JSON document alone is not trusted provenance.
    """
    data = _keys(_bounded_json(raw), ("schema", "request_sha256", "phase", "tests", "results", "source_sha256"))
    if data["schema"] != PYTHON_PROTOCOL or data["request_sha256"] != _sha(request_sha256):
        _reject("PROTOCOL_REQUEST_MISMATCH")
    if data["source_sha256"] != _sha(expected_source_sha256):
        _reject("PROTOCOL_SOURCE_MISMATCH")
    if type(expected_module) is not str or not _PY_MODULE.fullmatch(expected_module):
        _reject("PROTOCOL_MODULE_REQUIRED")
    if (expected_phase not in ("discover", "execute") or data["phase"] != expected_phase):
        _reject("PROTOCOL_PHASE")
    tests, results = data["tests"], data["results"]
    if type(tests) is not list or not 1 <= len(tests) <= MAX_TESTS or type(results) is not list:
        _reject("PROTOCOL_DENOMINATOR")
    identities = []
    for test in tests:
        _keys(test, ("id", "line"))
        identity = _text(test["id"], 512)
        if not identity.startswith(expected_module + ".") or not _PY_MODULE.fullmatch(identity):
            _reject("FOREIGN_TEST_IDENTITY")
        _integer(test["line"], 2**31 - 1, 1)
        identities.append(test["id"])
    if identities != sorted(set(identities)):
        _reject("DUPLICATE_OR_UNSORTED_TESTS")
    if expected_discovery is not None and tests != expected_discovery:
        _reject("DISCOVERY_EXECUTION_MISMATCH")
    if data["phase"] == "discover":
        if results:
            _reject("DISCOVERY_IS_NOT_EXECUTION")
    else:
        if type(expected_discovery) is not list or not expected_discovery:
            _reject("EXPECTED_DISCOVERY_REQUIRED")
        if len(results) != len(tests):
            _reject("MISSING_EXECUTION")
        for test, result in zip(tests, results):
            _keys(result, ("id", "outcome"))
            if (result["id"] != test["id"] or type(result["outcome"]) is not str
                    or result["outcome"] not in _STATUSES):
                _reject("FOREIGN_OR_INVALID_RESULT")
    return data


def compose_discovery_receipt(*, descriptor, binary, test_name, kind, line=1):
    """Emit an authoritative typed discovery binding from controller observations.

    The adapter consumes the admitted descriptor, an observed binary binding
    (or None) and the selected test identity, and emits the shared typed
    receipt bound to descriptor.identity and descriptor.sha256. The test name
    grammar follows kind ("rust" or "python"), which must match the descriptor
    mode (rust with rust-package, python with python-unittest/metadata-python);
    the location is the binary manifest_rel when a binary is bound, else the
    first descriptor test root. The receipt carries the descriptor source
    digest and the descriptor phase. With no binary the artifact digest falls
    back to the descriptor matrix digest; a bound binary must carry its own
    valid digest and, when the descriptor names a package, the same package.
    Execution and containment stay controller-owned.
    """
    from . import contracts as c
    if type(descriptor) is not c.WorkUnitDescriptor:
        _reject("DESCRIPTOR_TYPE_REQUIRED")
    if type(kind) is not str or kind not in ("rust", "python"):
        _reject("DISCOVERY_KIND_REQUIRED")
    if kind == "rust":
        if descriptor.mode is not c.RunnerMode.RUST_PACKAGE:
            _reject("KIND_MODE_MISMATCH")
        if type(test_name) is not str or len(test_name) > 256 or not _RUST_NAME.fullmatch(test_name):
            _reject("RUST_IDENTITY_SYNTAX")
    else:
        if (descriptor.mode is not c.RunnerMode.PYTHON_UNITTEST
                and descriptor.mode is not c.RunnerMode.METADATA_PYTHON):
            _reject("KIND_MODE_MISMATCH")
        if type(test_name) is not str or len(test_name) > 512 or not _PY_MODULE.fullmatch(test_name):
            _reject("PYTHON_MODULE_SYNTAX")
    _integer(line, 2**31 - 1, 1)
    if binary is None:
        rel = descriptor.test_roots[0].value
        artifact_digest = descriptor.matrix_sha256
    else:
        if type(binary) is not dict or "manifest_rel" not in binary:
            _reject("BINARY_BINDING_REQUIRED")
        if descriptor.package is not None and binary.get("package") != descriptor.package.name:
            _reject("PACKAGE_BINARY_MISMATCH")
        rel = _relative_path(binary["manifest_rel"])
        candidate = binary.get("binary_sha256")
        if type(candidate) is not str or not _HEX.fullmatch(candidate):
            _reject("BINARY_DIGEST_REQUIRED")
        artifact_digest = candidate
    try:
        identity = c.TestIdentity(mode=descriptor.mode, qualified_name=test_name)
        location = c.SourceLocation(c.RepositoryPath(rel), line)
        return c.DiscoveredTestReceipt(
            descriptor=descriptor.identity,
            descriptor_sha256=descriptor.sha256,
            test=identity,
            location=location,
            source_sha256=descriptor.body_sha256,
            artifact_sha256=artifact_digest,
            phase=descriptor.phase)
    except c.ContractViolation:
        _reject("DISCOVERY_RECEIPT_REJECTED")


def compose_execution_record(*, discovery, disposition, detail=None):
    """Emit an authoritative typed execution binding for a discovered test.

    The disposition is decoded through the shared ExecutionDisposition enum;
    unknown values fail closed. Detail carries stable codes only, never
    values; it is shape-checked and preserved verbatim.
    """
    from . import contracts as c
    if type(discovery) is not c.DiscoveredTestReceipt:
        _reject("DISCOVERY_RECEIPT_REQUIRED")
    try:
        confirmed = c.ExecutionDisposition(disposition)
    except (c.ContractViolation, TypeError):
        _reject("UNKNOWN_DISPOSITION")
    if detail is not None:
        _text(detail, 1024)
    try:
        return c.TestExecutionRecord(test=discovery.test, disposition=confirmed,
                                      discovery=discovery, detail=detail)
    except c.ContractViolation:
        _reject("EXECUTION_RECORD_REJECTED")


def assert_no_workspace_wide(argv):
    """Structural guard: reject any workspace-wide selection flag.

    Returns the argv as a tuple when clean. Package-mode constructors call
    this at runtime; they are additionally incapable of emitting such flags
    by construction.
    """
    if type(argv) not in (list, tuple):
        _reject("COMMAND_SHAPE")
    for item in argv:
        if type(item) is not str:
            _reject("COMMAND_TEXT_REQUIRED")
        if item in WORKSPACE_WIDE_FLAGS:
            _reject("WORKSPACE_WIDE_FORBIDDEN")
    return tuple(argv)


def build_cargo_discovery_command(*, manifest_rel: str, target_dir_rel: str, package: str):
    """Fixed package-mode discovery argv. Verified on cargo 1.97.1:

    cargo test --manifest-path <m> --target-dir <t> -p <pkg> -- --list --format terse
    emits `<name>: test` lines accepted by parse_rust_discovery.
    """
    manifest = _relative_path(manifest_rel)
    target = _relative_path(target_dir_rel)
    name = _text(package, 128)
    return assert_no_workspace_wide(
        ("cargo", "test", "--manifest-path", manifest, "--target-dir", target,
         "-p", name, "--", "--list", "--format", "terse"))


def build_cargo_test_command(*, manifest_rel: str, target_dir_rel: str, package: str, test_id: str):
    """Fixed single-test argv. Verified on cargo 1.97.1:

    cargo test --manifest-path <m> --target-dir <t> -p <pkg> -- --exact <id>
    runs exactly one test; its pretty transcript matches parse_rust_exact.
    An ignored identity prints `... ignored` and a filtered-out identity
    prints `running 0 tests`, both rejected by the exact-result grammar.
    """
    manifest = _relative_path(manifest_rel)
    target = _relative_path(target_dir_rel)
    name = _text(package, 128)
    if type(test_id) is not str or len(test_id) > 256 or not _RUST_NAME.fullmatch(test_id):
        _reject("RUST_IDENTITY_SYNTAX")
    return assert_no_workspace_wide(
        ("cargo", "test", "--manifest-path", manifest, "--target-dir", target,
         "-p", name, "--", "--exact", test_id))


def build_cargo_build_command(*, manifest_rel: str, target_dir_rel: str, package: str):
    """Fixed package-mode build argv. Verified on cargo 1.97.1:

    cargo build --manifest-path <m> --target-dir <t> -p <pkg>
    --message-format json-render-diagnostics
    emits structured JSON lines (`compiler-artifact`, `build-finished`).
    """
    manifest = _relative_path(manifest_rel)
    target = _relative_path(target_dir_rel)
    name = _text(package, 128)
    return assert_no_workspace_wide(
        ("cargo", "build", "--manifest-path", manifest, "--target-dir", target,
         "-p", name, "--message-format", "json-render-diagnostics"))


def _parse_build_artifact(data: dict, package: str, manifest_rel: str):
    package_id = data.get("package_id")
    if type(package_id) is not str:
        _reject("PACKAGE_ID_MISMATCH")
    fragments = package_id.split("#")
    if len(fragments) != 2 or not fragments[1].startswith(f"{package}@"):
        _reject("PACKAGE_ID_MISMATCH")
    target = data.get("target")
    if type(target) is not dict:
        _reject("TARGET_SHAPE")
    target_name = target.get("name")
    if type(target_name) is not str or not target_name or len(target_name.encode("utf-8")) > 128:
        _reject("TARGET_SHAPE")
    kind = target.get("kind")
    if type(kind) is str:
        kinds = [kind]
    elif type(kind) is list and kind and all(type(item) is str for item in kind):
        kinds = list(kind)
    else:
        _reject("TARGET_SHAPE")
    for item in kinds:
        if not item or len(item.encode("utf-8")) > 128:
            _reject("TARGET_SHAPE")
    if len(kinds) != 1:
        _reject("TARGET_SHAPE")
    profile = data.get("profile")
    if type(profile) is not dict or type(profile.get("test")) is not bool:
        _reject("PROFILE_SHAPE")
    filenames = data.get("filenames")
    if type(filenames) is not list or not filenames:
        _reject("FILENAMES_REQUIRED")
    clean = [_text(path, 1024) for path in filenames]
    fresh = data.get("fresh")
    if type(fresh) is not bool:
        _reject("FRESH_BOOL_REQUIRED")
    return {"package": package, "manifest_rel": manifest_rel, "target_name": target_name,
            "target_kind": kinds[0], "profile_test": profile["test"],
            "filenames": tuple(clean), "fresh": fresh}


def parse_cargo_build_stream(raw: bytes, *, package: str, manifest_rel: str):
    """Parse pinned `cargo build --message-format=json-render-diagnostics` stdout.

    The controller owns cargo resolution, the working directory, the owned
    process tree, timeouts and capture; this function only decodes captured
    stdout bytes (MAX_PROTOCOL_BYTES, UTF-8, per-line _bounded_json). Every
    nonempty line must carry a reason of exactly compiler-artifact or
    build-finished; any other reason fails closed. Each compiler-artifact must
    belong to the selected package (package_id splits on "#" into exactly two
    parts whose tail starts with `<package>@`) and
    carry a well-formed target, profile, filenames and fresh flag. The stream
    must terminate in exactly one successful build-finished event, otherwise
    BUILD_NOT_SUCCESSFUL. Returns one binding per compiler-artifact.
    """
    name = _text(package, 128)
    manifest = _relative_path(manifest_rel)
    if type(raw) is not bytes or len(raw) > MAX_PROTOCOL_BYTES:
        _reject("OUTPUT_BYTE_BOUND")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        _reject("OUTPUT_UTF8")
    artifacts = []
    finished = 0
    last_reason = None
    last_success = False
    for line in text.splitlines():
        if not line:
            continue
        data = _bounded_json(line.encode("utf-8"))
        if type(data) is not dict or type(data.get("reason")) is not str:
            _reject("UNSUPPORTED_BUILD_EVENT")
        reason = data["reason"]
        last_reason = reason
        if reason == "compiler-artifact":
            artifacts.append(_parse_build_artifact(data, name, manifest))
        elif reason == "build-finished":
            finished += 1
            success = data.get("success")
            if type(success) is not bool:
                _reject("BUILD_NOT_SUCCESSFUL")
            last_success = success
        else:
            _reject("UNSUPPORTED_BUILD_EVENT")
    if finished != 1 or last_reason != "build-finished" or last_success is not True:
        _reject("BUILD_NOT_SUCCESSFUL")
    return tuple(artifacts)


def resolve_package_manifest(*, package_name: str, metadata_packages: list,
                             require_workspace_member: bool = False):
    """Bind one exact package against caller-supplied cargo metadata.

    Pure classification: no cargo invocation, no membership edits. Each entry
    must hold exactly {name, manifest_rel, member_kind}; member_kind stays one
    of member/excluded/standalone/unavailable and is preserved verbatim in the
    returned binding. Exactly one name match is required. Package-only callers
    pass through buildable excluded/standalone entries; unavailable entries
    and unknown names fail, and membership-required callers fail on non-member.
    """
    name = _text(package_name, 128)
    if type(require_workspace_member) is not bool:
        _reject("MEMBERSHIP_BOOL_REQUIRED")
    if type(metadata_packages) is not list:
        _reject("METADATA_SHAPE")
    matches = []
    for entry in metadata_packages:
        item = _keys(entry, ("name", "manifest_rel", "member_kind"))
        entry_name = _text(item["name"], 128)
        manifest = _relative_path(item["manifest_rel"])
        kind = item["member_kind"]
        if type(kind) is not str or kind not in MEMBER_KINDS:
            _reject("UNKNOWN_MEMBER_KIND")
        if entry_name == name:
            matches.append({"name": entry_name, "manifest_rel": manifest, "member_kind": kind})
    if not matches:
        _reject("PACKAGE_NOT_FOUND")
    if len(matches) > 1:
        _reject("DUPLICATE_PACKAGE_IDENTITY")
    binding = matches[0]
    if binding["member_kind"] == "unavailable":
        _reject("PACKAGE_UNAVAILABLE")
    if require_workspace_member and binding["member_kind"] != "member":
        _reject("WORKSPACE_MEMBER_REQUIRED")
    return binding


def bind_test_binary(*, artifact, binary_name, binary_sha256, target=None, cfgs=()):
    """Bind one observed test binary to a parsed build artifact.

    Pure basename match against the artifact filenames (both separators are
    honored); the controller owns binary-byte acquisition, hashing and owned
    execution. cfgs are opaque short codes validated for shape only.
    """
    if type(artifact) is not dict:
        _reject("ARTIFACT_SHAPE")
    for key in ("package", "manifest_rel", "filenames"):
        if key not in artifact:
            _reject("ARTIFACT_SHAPE")
    package = _text(artifact["package"], 128)
    manifest = _relative_path(artifact["manifest_rel"])
    filenames = artifact["filenames"]
    if type(filenames) not in (list, tuple) or not filenames:
        _reject("ARTIFACT_SHAPE")
    for path in filenames:
        _text(path, 1024)
    name = _text(binary_name, 1024)
    if "/" in name or "\\" in name:
        _reject("BINARY_NAME_SHAPE")
    if not any(path.replace("\\", "/").rsplit("/", 1)[-1] == name for path in filenames):
        _reject("BINARY_NOT_PRODUCED")
    digest = _sha(binary_sha256)
    if target is not None:
        _text(target, 128)
        if artifact.get("target_name") != target:
            _reject("TARGET_MISMATCH")
    if type(cfgs) not in (list, tuple):
        _reject("CFGS_SHAPE")
    codes = tuple(_text(item, 128) for item in cfgs)
    profile = artifact.get("profile_test", False)
    if type(profile) is not bool:
        _reject("PROFILE_SHAPE")
    return {"package": package, "manifest_rel": manifest, "binary_name": name,
            "binary_sha256": digest, "target": target, "cfgs": codes,
            "profile_test": profile}


def bind_package_observation(*, descriptor, metadata):
    """Classify one observed cargo-metadata package against the descriptor.

    The controller owns cargo invocation and metadata acquisition; this
    function only decodes the closed observation shape {"packages": [{name,
    manifest_path, id, buildable}], "workspace_members": [id], "excluded":
    [name]} and binds the single entry whose name equals the descriptor
    package name. Membership is derived verbatim from workspace_members,
    excluded and buildable, never edited here.
    """
    from . import contracts as c
    if type(descriptor) is not c.WorkUnitDescriptor:
        _reject("DESCRIPTOR_TYPE_REQUIRED")
    if descriptor.package is None:
        _reject("PACKAGE_REQUIRED")
    _keys(metadata, ("packages", "workspace_members", "excluded"))
    packages = metadata["packages"]
    members = metadata["workspace_members"]
    excluded = metadata["excluded"]
    if type(packages) is not list or type(members) is not list or type(excluded) is not list:
        _reject("METADATA_SHAPE")
    for value in members:
        _text(value, 1024)
    for value in excluded:
        _text(value, 128)
    wanted = descriptor.package.name
    matches = []
    for entry in packages:
        item = _keys(entry, ("name", "manifest_path", "id", "buildable"))
        entry_name = _text(item["name"], 128)
        manifest_path = _text(item["manifest_path"], 1024)
        if not manifest_path.endswith("/Cargo.toml"):
            _reject("MANIFEST_PATH_SHAPE")
        entry_id = _text(item["id"], 1024)
        if type(item["buildable"]) is not bool:
            _reject("BUILDABLE_BOOL_REQUIRED")
        if entry_name == wanted:
            matches.append({"name": entry_name, "manifest_path": manifest_path,
                            "id": entry_id, "buildable": item["buildable"]})
    if not matches:
        _reject("PACKAGE_NOT_FOUND")
    if len(matches) > 1:
        _reject("DUPLICATE_PACKAGE_IDENTITY")
    found = matches[0]
    member_ids = set(members)
    if found["id"] in member_ids:
        kind = "member"
    elif found["name"] in set(excluded):
        kind = "excluded"
    elif found["buildable"]:
        kind = "standalone"
    else:
        kind = "unavailable"
    if kind == "unavailable":
        _reject("PACKAGE_UNAVAILABLE")
    if descriptor.require_workspace_member and kind != "member":
        _reject("WORKSPACE_MEMBER_REQUIRED")
    return {"name": found["name"], "manifest_path": found["manifest_path"],
            "member_kind": kind}


def build_python_child_command(*, script_rel: str, fd: int):
    """Fixed Python child argv. The `<python>` slot is a placeholder: the
    controller substitutes its policy-resolved interpreter (the equivalent of
    its own sys.executable) so this module never resolves host paths and stays
    deterministic across hosts. fd names the pre-opened protocol channel and
    must leave 0/1/2 alone. No descriptor-controlled parts, no shell.
    """
    script = _relative_path(script_rel)
    if type(fd) is not int or not 3 <= fd <= 1048575:
        _reject("CHILD_FD_BOUND")
    return ("<python>", "-I", "-B", script, "--_python-child", str(fd))


def minimal_child_env(env: dict):
    """Filter a controller-supplied environment down to allowed nonsecret names.

    Keeps only entries whose name is exactly in fixed ALLOWED_ENV_NAMES and
    carries no blocked marker (TOKEN/SECRET/CREDENTIAL/PASSWORD/KEY,
    case-insensitive), even when allowed. Per-value UTF-8 bytes are capped at
    4096 and the kept total at 65536; over-cap values fail closed. Returns a
    filtered copy; values never appear in diagnostics, only codes are raised.
    """
    if type(env) is not dict:
        _reject("ENV_OBJECT_REQUIRED")
    filtered = {}
    total = 0
    for key, value in env.items():
        if type(key) is not str or type(value) is not str:
            _reject("ENV_TEXT_REQUIRED")
        if key not in ALLOWED_ENV_NAMES:
            continue
        upper = key.upper()
        if any(marker in upper for marker in BLOCKED_ENV_MARKERS):
            continue
        size = len(value.encode("utf-8"))
        if size > ENV_VALUE_CAP:
            _reject("ENV_VALUE_BOUND")
        total += size
        if total > ENV_TOTAL_CAP:
            _reject("ENV_TOTAL_BOUND")
        filtered[key] = value
    return filtered


def toolchain_child_env(env: dict):
    """Filter a controller-supplied environment down to the proven toolchain set.

    Keeps only fixed TOOLCHAIN_ENV_NAMES plus the build-scoped CARGO_*/RUST_*
    prefix rule; blocked secret markers still drop, and the same byte caps as
    minimal_child_env apply. Always emits RUSTC_WRAPPER="" AFTER filtering so
    no ambient wrapper value can leak in: pinned policy is no wrapper, direct
    rustc 1.97.1; ambient sccache config must not interpose. Returns a filtered
    copy; values never appear in diagnostics, only codes are raised.
    """
    if type(env) is not dict:
        _reject("ENV_OBJECT_REQUIRED")
    filtered = {}
    total = 0
    for key, value in env.items():
        if type(key) is not str or type(value) is not str:
            _reject("ENV_TEXT_REQUIRED")
        if key == "RUSTC_WRAPPER":
            continue
        upper = key.upper()
        if not (key in TOOLCHAIN_ENV_NAMES or upper.startswith("CARGO_")
                or upper.startswith("RUST_")):
            continue
        if any(marker in upper for marker in BLOCKED_ENV_MARKERS):
            continue
        size = len(value.encode("utf-8"))
        if size > ENV_VALUE_CAP:
            _reject("ENV_VALUE_BOUND")
        total += size
        if total > ENV_TOTAL_CAP:
            _reject("ENV_TOTAL_BOUND")
        filtered[key] = value
    filtered["RUSTC_WRAPPER"] = ""
    return filtered


def resolve_metadata_entrypoint(*, module: str, test_roots):
    """Resolve one fixed registered Python suite identity.

    Registered suites are dotted module identities only. Generator, mutation
    and network spellings (anything carrying :, /, backslash, !, @,
    whitespace, or a script/binary suffix) are rejected as NOT_A_REGISTERED_SUITE.
    A well-formed module whose file is outside every supplied test root is
    rejected as FOREIGN_TEST_IDENTITY. Library imports used by test code are
    unaffected; only the entrypoint identity is checked.
    """
    if type(module) is not str or not module:
        _reject("NOT_A_REGISTERED_SUITE")
    lowered = module.lower()
    if (any(mark in module for mark in (":", "/", "\\", "!", "@"))
            or any(char.isspace() for char in module)
            or any(lowered.endswith(suffix) for suffix in _METADATA_FORBIDDEN_SUFFIXES)
            or not _PY_MODULE.fullmatch(module)):
        _reject("NOT_A_REGISTERED_SUITE")
    if type(test_roots) not in (list, tuple):
        _reject("ROOT_DENOMINATOR")
    roots = [_relative_path(root) for root in test_roots]
    candidate = module.replace(".", "/") + ".py"
    if not any(candidate == root or candidate.startswith(root + "/") for root in roots):
        _reject("FOREIGN_TEST_IDENTITY")
    return module


def bind_python_suite(*, root: Path, module: str, test_roots):
    """Bind one registered Python suite to its repository-relative source file.

    Lexical registration checks come from resolve_metadata_entrypoint;
    physical authority comes from _safe_path. The resolved entry must be an
    existing file whose repository-relative form equals the module-derived
    candidate, otherwise FOREIGN_TEST_SOURCE. Returns the candidate rel.
    """
    if not isinstance(root, Path):
        _reject("SNAPSHOT_ROOT_REQUIRED")
    resolve_metadata_entrypoint(module=module, test_roots=test_roots)
    candidate = module.replace(".", "/") + ".py"
    resolved = _safe_path(root, candidate)
    try:
        rel = resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        _reject("FOREIGN_TEST_SOURCE")
    if rel != candidate or not resolved.is_file():
        _reject("FOREIGN_TEST_SOURCE")
    return candidate


def snapshot_protected(root: Path, rels: list):
    """Record sha256 digests of protected inputs. Detection only.

    Reads through _safe_path and _file_digest, so unowned or missing paths are
    rejected. Never writes, never resets; the controller compares the returned
    mapping with compare_snapshots and preserves the diff on mismatch.
    """
    if not isinstance(root, Path):
        _reject("SNAPSHOT_ROOT_REQUIRED")
    if type(rels) not in (list, tuple):
        _reject("SNAPSHOT_SHAPE")
    snapshot = {}
    for rel in rels:
        key = _relative_path(rel)
        snapshot[key] = _file_digest(_safe_path(root, key))
    return snapshot


def compare_snapshots(before: dict, after: dict):
    """Diff two protected-input snapshots. Empty lists mean clean.

    Pure mapping comparison; no filesystem access, no writes, no auto-reset.
    """
    if type(before) is not dict or type(after) is not dict:
        _reject("SNAPSHOT_SHAPE")
    for snapshot in (before, after):
        for key, value in snapshot.items():
            if type(key) is not str or type(value) is not str:
                _reject("SNAPSHOT_SHAPE")
    keys_before = set(before)
    keys_after = set(after)
    return {
        "mutated": sorted(key for key in keys_before & keys_after if before[key] != after[key]),
        "added": sorted(keys_after - keys_before),
        "removed": sorted(keys_before - keys_after),
    }


def bind_protected_snapshot(*, descriptor, assignment, snapshot: dict):
    """Bind a controller-observed protected-input snapshot to the descriptor.

    The adapter consumes the controller's observed digest mapping and emits an
    authoritative binding; no filesystem access, no writes, no reset. The
    assignment must be an ACTIVE_ASSIGNMENT+OPEN receipt bound to the same
    issue/unit/matrix/body as the descriptor. Required keys are the sorted
    source+test root values plus the module file when the descriptor carries
    one; the digest is sha256 over the canonical JSON of the sorted items.
    """
    from . import contracts as c
    if type(descriptor) is not c.WorkUnitDescriptor:
        _reject("DESCRIPTOR_TYPE_REQUIRED")
    if type(assignment) is not c.AssignmentSourceReceipt:
        _reject("ASSIGNMENT_RECEIPT_REQUIRED")
    if assignment.source_use is not c.AssignmentSourceUse.ACTIVE_ASSIGNMENT or assignment.state is not c.IssueState.OPEN:
        _reject("INACTIVE_ASSIGNMENT")
    for key in ("issue", "unit", "matrix_cases", "body_sha256", "matrix_sha256"):
        if getattr(descriptor, key) != getattr(assignment, key):
            _reject("STALE_ASSIGNMENT_BINDING")
    required = sorted({path.value for path in descriptor.source_roots + descriptor.test_roots}
                      | ({descriptor.module.value.replace(".", "/") + ".py"}
                         if descriptor.module is not None else set()))
    if not required:
        _reject("EMPTY_SNAPSHOT")
    if type(snapshot) is not dict:
        _reject("SNAPSHOT_SHAPE")
    if any(key not in snapshot for key in required):
        _reject("MISSING_SNAPSHOT_KEY")
    if any(key not in required for key in snapshot):
        _reject("FOREIGN_SNAPSHOT_KEY")
    for value in snapshot.values():
        if type(value) is not str or not _HEX.fullmatch(value):
            _reject("SNAPSHOT_DIGEST_SYNTAX")
    canonical = json.dumps({key: snapshot[key] for key in required},
                           sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"digest": hashlib.sha256(canonical).hexdigest(), "keys": required}


def canonical_command(argv):
    """Deterministic rendering of a constructed argv.

    Space-joined; an argument passes through verbatim only when it matches
    [A-Za-z0-9_./:=-]+, otherwise it is wrapped in double quotes with
    backslash and double-quote characters escaped. Wall durations and other
    observations never enter this rendering, so equal semantic inputs give
    identical strings. The argv is count- and byte-bounded so an untrusted
    caller cannot force unbounded allocation in the parent.
    """
    if type(argv) not in (list, tuple) or not argv:
        _reject("EMPTY_COMMAND")
    if len(argv) > 4096:
        _reject("COMMAND_BOUND")
    parts = []
    total = 0
    for item in argv:
        if type(item) is not str or not item:
            _reject("COMMAND_TEXT_REQUIRED")
        total += len(item.encode("utf-8")) + 3
        if total > MAX_PROTOCOL_BYTES:
            _reject("COMMAND_BOUND")
        if _SAFE_COMMAND_ARG.fullmatch(item):
            parts.append(item)
        else:
            parts.append('"' + item.replace("\\", "\\\\").replace('"', '\\"') + '"')
    return " ".join(parts)


def phase_verdict(phase: str, outcome: str):
    """Look up the phase x outcome verdict: "green" or "non-green".

    Unknown pairs fail closed. See PHASE_TRUTH_TABLE.
    """
    try:
        return PHASE_TRUTH_TABLE[(phase, outcome)]
    except (KeyError, TypeError):
        _reject("UNKNOWN_PHASE_OUTCOME")


def cleanup_verdict(*, cleanup: str, active_processes: int, truncated: bool):
    """Reconcile one owned-tree cleanup observation to green or non-green.

    Covers cleanup reconciliation only: green requires a clean or
    timeout-reaped tree with zero active processes and no truncation. Wall and
    idle causes and the timeout cause itself are separate observations owned
    elsewhere; every other cleanup string or shape stays non-green, so an
    unknown cleanup can never read as green.
    """
    if (type(cleanup) is not str or type(active_processes) is not int
            or type(truncated) is not bool or active_processes < 0):
        _reject("CLEANUP_SHAPE")
    if cleanup in ("clean", "timeout-reaped") and active_processes == 0 and truncated is False:
        return "green"
    return "non-green"


def enforcement_plan(*, bounds: dict):
    """Normalize descriptor execution bounds to owned-transport parameters.

    Consumes a closed ExecutionBounds-shaped mapping and emits transport
    parameters {wall_s, idle_s, output_bytes, line_bytes, max_tests,
    max_processes}. Transports take THESE values, never looser substitutes:
    callers must not widen, default, or reinterpret any dimension; tighter
    test-provisioning subsets stay within the emitted ceiling.
    """
    data = _keys(bounds, ("wall_ms", "idle_ms", "output_bytes", "line_bytes",
                          "discovery_tests", "child_processes"))
    wall = _integer(data["wall_ms"], 86400000, 1)
    idle = _integer(data["idle_ms"], 86400000, 1)
    output = _integer(data["output_bytes"], 67108864, 1)
    line = _integer(data["line_bytes"], 1048576, 1)
    tests = _integer(data["discovery_tests"], MAX_TESTS, 1)
    procs = _integer(data["child_processes"], 64, 1)
    if idle > wall or line > output:
        _reject("INCONSISTENT_BOUNDS")
    return {"wall_s": wall / 1000, "idle_s": idle / 1000, "output_bytes": output,
            "line_bytes": line, "max_tests": tests, "max_processes": procs}


def _file_digest(path):
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_SOURCE_BYTES + 1)
    except OSError:
        _reject("SOURCE_UNAVAILABLE")
    if len(raw) > MAX_SOURCE_BYTES:
        _reject("SOURCE_BYTE_BOUND")
    return hashlib.sha256(raw).hexdigest()


def _python_child(raw: bytes, channel):
    """Fixed child entry. Only an owned process adapter may invoke in production.

    Candidate code is imported and executed here, never by the parent parser.
    This is not a security sandbox against arbitrary malicious test code.
    """
    req = _keys(_bounded_json(raw, MAX_DESCRIPTOR_BYTES),
                ("schema", "phase", "root", "module", "source", "source_sha256", "max_tests", "expected"))
    if req["schema"] != PYTHON_PROTOCOL or req["phase"] not in ("discover", "execute"):
        _reject("CHILD_REQUEST_SCHEMA")
    module = _text(req["module"], 256)
    if not _PY_MODULE.fullmatch(module):
        _reject("PYTHON_MODULE_SYNTAX")
    expected = req["expected"]
    if type(expected) is not list or (req["phase"] == "discover" and expected):
        _reject("CHILD_EXPECTED_SHAPE")
    maximum = _integer(req["max_tests"], MAX_TESTS, 1)
    root = Path(_text(req["root"], 4096))
    source = _safe_path(root, req["source"])
    if req["source"] != module.replace(".", "/") + ".py":
        _reject("MODULE_SOURCE_MISMATCH")
    before = _file_digest(source)
    if before != _sha(req["source_sha256"]):
        _reject("SOURCE_IDENTITY_MISMATCH")
    sys.path.insert(0, str(root.resolve()))
    importlib.invalidate_caches()
    # -B prevents writing .pyc files, not loading them. Every repository-owned
    # Python import must compile current source bytes, never timestamp/size-only
    # cache validation. Otherwise a same-size edited failing test can run stale
    # passing bytecode while its new source hash is reported as executed.
    loaded_sources = {}
    class FreshSourceLoader(importlib.machinery.SourceFileLoader):
        def get_code(self, fullname):
            path = Path(self.path)
            relative = path.relative_to(root.resolve()).as_posix()
            checked = _safe_path(root, relative)
            with checked.open("rb") as stream:
                content = stream.read(MAX_SOURCE_BYTES + 1)
            if len(content) > MAX_SOURCE_BYTES:
                _reject("SOURCE_BYTE_BOUND")
            digest = hashlib.sha256(content).hexdigest()
            if checked == source and digest != before:
                _reject("SOURCE_IDENTITY_MISMATCH")
            previous = loaded_sources.get(checked)
            if previous is not None and previous != digest:
                _reject("IMPORTED_SOURCE_MUTATED")
            loaded_sources[checked] = digest
            return self.source_to_code(content, str(checked))

    class FreshRepositoryFinder:
        @staticmethod
        def find_spec(fullname, path=None, target=None):
            spec = importlib.machinery.PathFinder.find_spec(fullname, path, target)
            if spec is None or not spec.origin:
                return None
            origin = Path(spec.origin)
            try:
                relative = origin.relative_to(root.resolve()).as_posix()
            except ValueError:
                return None  # Normal installed/standard-library import policy.
            if origin.suffix == ".py":
                checked = _safe_path(root, relative)
                spec.loader = FreshSourceLoader(fullname, str(checked))
                return spec
            if origin.suffix == ".pyc":
                _reject("SOURCELESS_REPOSITORY_MODULE")
            _reject("NATIVE_REPOSITORY_MODULE")

    if module in sys.modules:
        _reject("TEST_MODULE_ALREADY_LOADED")
    sys.meta_path.insert(0, FreshRepositoryFinder)
    loaded = importlib.import_module(module)
    if Path(loaded.__file__).resolve() != source.resolve():
        _reject("FOREIGN_MODULE_SOURCE")
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(loaded)
    if loader.errors:
        _reject("DISCOVERY_ERROR")
    tests = []
    def flatten(value, depth=0):
        if depth > 32:
            _reject("SUITE_DEPTH_BOUND")
        if type(value) is unittest.TestSuite:
            for child in value:
                flatten(child, depth + 1)
        elif isinstance(value, unittest.TestCase):
            if len(tests) >= maximum:
                _reject("DISCOVERY_BOUND")
            if type(value).__module__ != module or type(value).run is not unittest.TestCase.run:
                _reject("FOREIGN_OR_CUSTOM_TEST")
            method = getattr(value, value._testMethodName)
            if Path(inspect.getsourcefile(inspect.unwrap(method))).resolve() != source.resolve():
                _reject("FOREIGN_TEST_SOURCE")
            identity = value.id()
            if identity != f"{module}.{type(value).__qualname__}.{value._testMethodName}":
                _reject("CUSTOM_TEST_IDENTITY")
            tests.append((identity, inspect.unwrap(method).__code__.co_firstlineno, value))
        else:
            _reject("UNSUPPORTED_SUITE")
    flatten(suite)
    tests.sort(key=lambda item: item[0])
    if not tests or len({t[0] for t in tests}) != len(tests):
        _reject("EMPTY_OR_DUPLICATE_DISCOVERY")
    discovered = [{"id": identity, "line": line} for identity, line, _ in tests]
    if req["phase"] == "execute" and expected != discovered:
        _reject("DISCOVERY_EXECUTION_MISMATCH")
    results = {}
    allowed_ids = {item[0] for item in tests}
    if req["phase"] == "execute":
        class Result(unittest.TestResult):
            def record(self, test, outcome):
                identity = test.id()
                if identity not in allowed_ids or identity in results:
                    _reject("FOREIGN_OR_DUPLICATE_TERMINAL")
                results[identity] = outcome
            def addSuccess(self, test): self.record(test, "pass")
            def addFailure(self, test, err): self.record(test, "failure")
            def addError(self, test, err): self.record(test, "error")
            def addSkip(self, test, reason): self.record(test, "skip")
            def addExpectedFailure(self, test, err): self.record(test, "expected-failure")
            def addUnexpectedSuccess(self, test): self.record(test, "unexpected-success")
            def addSubTest(self, test, subtest, err):
                # Accumulate subtest failure without manufacturing a second
                # terminal record. Unknown/mixed complex protocols fail closed.
                if err is not None:
                    _reject("SUBTEST_FAILURE_NOT_SUPPORTED")
        result = Result()
        unittest.TestSuite([value for _, _, value in tests]).run(result)
        if set(results) != allowed_ids:
            _reject("MISSING_EXECUTION")
    if _file_digest(source) != before:
        _reject("SOURCE_MUTATED")
    for loaded_path, loaded_digest in loaded_sources.items():
        if _file_digest(loaded_path) != loaded_digest:
            _reject("IMPORTED_SOURCE_MUTATED")
    payload = {"schema": PYTHON_PROTOCOL, "request_sha256": hashlib.sha256(raw).hexdigest(),
               "phase": req["phase"], "tests": discovered,
               "results": [{"id": identity, "outcome": results[identity]} for identity, _, _ in tests] if results else [],
               "source_sha256": before}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_PROTOCOL_BYTES:
        _reject("PROTOCOL_BYTE_BOUND")
    channel.write(encoded)
    channel.flush()


def _child_main():
    # A descriptor cannot select this command, channel, working directory or
    # executable. The future parent adapter derives them under its own policy.
    if len(sys.argv) != 3 or sys.argv[1] != "--_python-child":
        return 2
    try:
        fd = int(sys.argv[2])
        if fd < 3:
            return 2
        raw = sys.stdin.buffer.read(MAX_DESCRIPTOR_BYTES + 1)
        with os.fdopen(fd, "wb", closefd=False) as channel:
            _python_child(raw, channel)
        return 0
    except BaseException:
        # Do not print a traceback containing raw test source, credentials or
        # exception text; the owning process adapter records the nonzero exit.
        return 2


if __name__ == "__main__":
    raise SystemExit(_child_main())
