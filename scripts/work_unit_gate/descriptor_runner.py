"""Closed parsing and fixed Python child protocol for work-unit runner #850.

This is an incremental runner component, NOT the complete acceptance gate.
The controller must supply an admitted process-tree execution port, source
snapshot and toolchain evidence. This module neither spawns a process nor
claims containment. A parsed child record is not a trusted execution receipt.
The v4 shared contracts remain the descriptor owner; only parse_descriptor
constructs that public type. No legacy promotion or descriptor command field.
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
    """
    if type(selected) is not str or not _RUST_NAME.fullmatch(selected):
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
            return None

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
