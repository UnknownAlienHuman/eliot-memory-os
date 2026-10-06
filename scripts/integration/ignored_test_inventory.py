#!/usr/bin/env python3
"""Derive a bounded source/compiled inventory of ignored Rust tests.

Issue #905 owns the complete 28-case acceptance contract.  This module is the
real implementation entrypoint, not a reservation marker.  It performs no test
execution and provisions no Store, Runtime, Git, credential, or network state.
It builds the locked test graph, asks each produced libtest binary to list only
ignored tests, scans admitted Rust source with a small bounded lexer, reconciles
the two denominators, and writes canonical JSON to an explicit `.eliot` path.
"""

from __future__ import annotations

import argparse
import dataclasses
import enum
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path
from typing import Any, Final

SCHEMA: Final = "eliot.integration.ignored-test-inventory.v1"
# TOOL_VERSION binds the emitted artifact identity: any change to the header,
# row schema, requirement classes, or classification rules bumps it, so two
# different tool states never certify indistinguishable artifacts (issue #905 W3).
TOOL_VERSION: Final = "0.8.0"
OUTPUT_ROOT: Final = ".eliot"
_TARGET_ROOT_PARTS: Final = (".eliot", "integration", "ignored-test-inventory", "target")
_CARGO_METADATA_ARGV: Final = ("cargo", "metadata", "--locked", "--format-version", "1")
_CARGO_BUILD_ARGV: Final = ("cargo", "test", "--workspace", "--all-targets", "--locked", "--no-run", "--message-format=json")
_LIBTEST_LIST_ARGS: Final = ("--list", "--ignored", "--format", "terse")
_CARGO_MESSAGE_REASONS: Final = frozenset({"compiler-artifact", "compiler-message", "build-script-executed", "build-finished"})
_PROFILE_FIELDS: Final = frozenset({"opt_level", "debuginfo", "debug_assertions", "overflow_checks", "test"})


class InventoryError(RuntimeError):
    """Stable public failure with a machine-readable reason code."""

    def __init__(self, code: str, detail: str, owner: str = "build-test-graph-owner") -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.owner = owner


@dataclasses.dataclass(frozen=True)
class Bounds:
    max_source_files: int = 20_000
    max_source_bytes: int = 512 * 1024 * 1024
    max_file_bytes: int = 4 * 1024 * 1024
    max_attribute_bytes: int = 64 * 1024
    max_source_tests: int = 100_000
    max_test_binaries: int = 10_000
    max_compiled_tests: int = 100_000
    max_command_output_bytes: int = 256 * 1024 * 1024
    command_timeout_seconds: int = 3_600


BOUNDS: Final = Bounds()


class RowState(str, enum.Enum):
    CLASSIFIED = "CLASSIFIED"
    UNCLASSIFIED = "UNCLASSIFIED"
    SOURCE_ONLY = "SOURCE_ONLY"
    COMPILED_ONLY = "COMPILED_ONLY"
    DUPLICATE = "DUPLICATE"
    COMPILED_GRAPH_UNAVAILABLE = "COMPILED_GRAPH_UNAVAILABLE"


class Requirement(str, enum.Enum):
    STORE = "STORE"
    RUNTIME = "RUNTIME"
    GIT = "GIT"
    NETWORK = "NETWORK"
    EXTERNAL_CREDENTIALED_MANUAL_ONLY = "EXTERNAL_CREDENTIALED_MANUAL_ONLY"
    UNKNOWN = "UNKNOWN"


DEFAULT_REMEDIATION_OWNERS: Final = {
    RowState.CLASSIFIED: "declared-environment-owner",
    RowState.UNCLASSIFIED: "test-declaration-owner",
    RowState.SOURCE_ONLY: "test-target-owner",
    RowState.COMPILED_ONLY: "build-test-graph-owner",
    RowState.DUPLICATE: "test-source-owner",
    RowState.COMPILED_GRAPH_UNAVAILABLE: "build-test-graph-owner",
}


@dataclasses.dataclass(frozen=True)
class Token:
    kind: str
    value: str
    start: int
    end: int
    line: int


@dataclasses.dataclass(frozen=True)
class SourceTest:
    package_id: str
    package_name: str
    target_name: str
    target_kind: str
    test_name: str
    source_path: str
    line: int
    attribute_text: str
    attribute_digest: str
    reason: str | None
    cfg_evidence: tuple[str, ...]
    requirements: tuple[str, ...]
    source_digest: str
    # Declared isolation/serialization/reset/timeout tokens (issue #905 row
    # contract). Last with a default so existing constructions stay valid.
    isolation: tuple[str, ...] = ()
    # Exact offsets into the scanned source text (issue #905 W3): the test
    # fn name token and first-attribute start to last-attribute end.
    fn_span: tuple[int, int] | None = None
    attribute_span: tuple[int, int] | None = None

    def identity(self) -> tuple[str, str, str, str]:
        return (self.package_id, self.target_kind, self.target_name, self.test_name)


@dataclasses.dataclass(frozen=True)
class CompiledTest:
    package_id: str
    package_name: str
    target_name: str
    target_kind: str
    executable: str
    executable_digest: str
    test_name: str

    def identity(self) -> tuple[str, str, str, str]:
        return (self.package_id, self.target_kind, self.target_name, self.test_name)


@dataclasses.dataclass(frozen=True)
class InventoryRow:
    state: str
    package_id: str
    package_name: str
    target_name: str
    target_kind: str
    test_name: str
    source_path: str | None
    source_line: int | None
    source_digest: str | None
    attribute_text: str | None
    attribute_digest: str | None
    ignore_reason: str | None
    cfg_evidence: tuple[str, ...]
    requirements: tuple[str, ...]
    executable: str | None
    executable_digest: str | None
    remediation_owner: str
    row_digest: str
    # Declared isolation/serialization/reset/timeout tokens, digest-covered via
    # the _row payload (issue #905 row contract). Default keeps the field additive.
    isolation: tuple[str, ...] = ()
    # Exact offsets into the scanned source text (issue #905 W3): the test
    # fn name token and first-attribute start to last-attribute end.
    fn_span: tuple[int, int] | None = None
    attribute_span: tuple[int, int] | None = None


@dataclasses.dataclass(frozen=True)
class PackageTarget:
    package_id: str
    package_name: str
    manifest_dir: Path
    target_name: str
    target_kind: str
    src_path: Path
    test_enabled: bool = True
    doctest_enabled: bool = False
    bench_enabled: bool | None = None
    required_features: tuple[str, ...] = ()
    required_features_satisfied: bool | None = True
    features: tuple[str, ...] = ()
    edition: str | None = None
    available_features: tuple[str, ...] = ()
    test_profile_active: bool | None = None


@dataclasses.dataclass(frozen=True)
class Artifact:
    package_id: str
    target_name: str
    target_kind: str
    executable: Path
    profile: dict[str, Any] = dataclasses.field(default_factory=dict)
    features: tuple[str, ...] = ()
    filenames: tuple[Path, ...] = ()
    file_identity: dict[str, int] = dataclasses.field(default_factory=dict)
    executable_sha256: str = ""
    # Internal admission binding only; deliberately excluded from public rows,
    # artifact records, and their digests.
    target_root: Path | None = None


@dataclasses.dataclass(frozen=True)
class CommandResult:
    stdout: bytes
    stderr: bytes


@dataclasses.dataclass(frozen=True)
class _WindowsHandleDetails:
    attributes: int
    native_identity: tuple[int, int, int]
    final_path: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _repo_path(root: Path, path: Path) -> Path:
    try:
        resolved_root = root.resolve(strict=True)
        candidate = path if path.is_absolute() else root / path
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise InventoryError("PATH_ESCAPE", _redact_detail(f"path is outside repository root: {path}")) from exc
    return resolved


def _relative(root: Path, path: Path) -> str:
    return _repo_path(root, path).relative_to(root.resolve(strict=True)).as_posix()


def _safe_output(root: Path, output: Path, overwrite: bool = False) -> Path:
    root = root.resolve(strict=True)
    candidate = output if output.is_absolute() else root / output
    try:
        resolved_candidate = candidate.resolve(strict=False)
        relative = resolved_candidate.relative_to(root)
    except (OSError, ValueError) as exc:
        raise InventoryError("UNSAFE_OUTPUT", _redact_detail(f"output parent is outside repository root: {output}")) from exc
    if not relative.parts or relative.parts[0] != OUTPUT_ROOT:
        raise InventoryError("UNSAFE_OUTPUT", "output must be below the repository .eliot directory")
    if candidate.exists() and not overwrite:
        raise InventoryError("OUTPUT_EXISTS", _redact_detail(f"refusing to overwrite {candidate}"))
    return candidate


def _bounded_read(path: Path) -> bytes:
    size = path.stat().st_size
    if size > BOUNDS.max_file_bytes:
        raise InventoryError("SOURCE_FILE_TOO_LARGE", _redact_detail(f"{path} exceeds {BOUNDS.max_file_bytes} bytes"))
    return path.read_bytes()


def _snapshot_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if not isinstance(argv, (tuple, list)):
        raise InventoryError("COMMAND_NOT_ALLOWED", "command arguments must be a fixed sequence")
    return tuple(argv)


def _validate_command(
    argv: Sequence[str], root: Path | None = None, *, admitted_executable: Path | None = None
) -> None:
    command = _snapshot_argv(argv)
    if not command or any(not isinstance(item, str) or not item or "\x00" in item for item in command):
        raise InventoryError("COMMAND_NOT_ALLOWED", "empty command is not allowed")
    if command in {
        _CARGO_METADATA_ARGV,
        _CARGO_BUILD_ARGV,
        ("git", "rev-parse", "HEAD"),
        ("git", "status", "--porcelain=v1", "--untracked-files=all"),
        ("rustc", "--version", "--verbose"),
    }:
        return
    if len(command) == 1 + len(_LIBTEST_LIST_ARGS) and command[1:] == _LIBTEST_LIST_ARGS:
        candidate = Path(command[0])
        try:
            if root is None or admitted_executable is None:
                raise InventoryError("COMMAND_NOT_ALLOWED", "listing requires the exact admitted executable")
            target_root = _admitted_target_root(root)
            resolved = candidate.resolve(strict=True)
            expected = admitted_executable.resolve(strict=True)
            resolved.relative_to(target_root)
            _reject_reparse_components(target_root, resolved, include_leaf=True)
            if candidate.is_absolute() and resolved.is_file() and resolved == expected == candidate:
                return
        except (InventoryError, OSError, ValueError):
            pass
    raise InventoryError("COMMAND_NOT_ALLOWED", "command is not fixed/allowed")


def _reject_reparse_components(root: Path, path: Path, *, include_leaf: bool = True) -> None:
    """Reject symlink/junction components before trusting an admitted path."""
    import stat

    root = root.resolve(strict=True)
    candidate = path if path.is_absolute() else root / path
    try:
        candidate = Path(os.path.abspath(candidate))
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise InventoryError("PATH_ESCAPE", "admitted path is outside its root") from exc
    current = root
    parts = relative.parts if include_leaf else relative.parts[:-1]
    for part in parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise InventoryError("PATH_ESCAPE", "reparse path component is not admitted")


def _admitted_target_root(root: Path) -> Path:
    """Return the fixed inventory-owned Cargo target directory."""
    try:
        resolved_root = root.resolve(strict=True)
        target = resolved_root.joinpath(*_TARGET_ROOT_PARTS)
        target.resolve(strict=False).relative_to(resolved_root)
        _reject_reparse_components(resolved_root, target, include_leaf=True)
    except (OSError, ValueError) as exc:
        raise InventoryError("PATH_ESCAPE", "fixed Cargo target root escapes or is unreadable") from exc
    return target


def _create_job_object() -> int:
    """Create a Windows Job Object whose close action owns the process tree."""
    import ctypes
    from ctypes import wintypes

    class BasicLimit(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class ExtendedLimit(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", BasicLimit), ("IoInfo", IoCounters), ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.CreateJobObjectW(None, None)
    if not handle:
        raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
    limits = ExtendedLimit()
    limits.BasicLimitInformation.LimitFlags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not kernel.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
        error = ctypes.get_last_error()
        kernel.CloseHandle(handle)
        raise OSError(error, "SetInformationJobObject failed")
    return int(handle)


def _assign_job_object(job: int, process_handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    if not kernel.AssignProcessToJobObject(job, process_handle):
        raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject failed")


def _windows_api_path(path: str | Path) -> str:
    """Return an absolute extended-length path for a Windows file API call."""
    import ntpath

    value = os.fspath(path)
    if not isinstance(value, str) or not ntpath.isabs(value):
        raise OSError("Windows path is not absolute")
    value = ntpath.normpath(value)
    if value.startswith("\\\\?\\") or value.startswith("\\\\.\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _normalize_windows_path(path: str | Path) -> str:
    """Normalize DOS/extended final paths for case-insensitive comparison."""
    import ntpath

    value = os.fspath(path).replace("/", "\\")
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return ntpath.normcase(ntpath.normpath(value))


def _open_windows_path_handle(path: str | Path, *, directory: bool) -> int:
    """Open one path component without following its reparse point."""
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    kernel.CreateFileW.restype = wintypes.HANDLE
    desired_access = 0x00000080 if directory else 0x80000000  # FILE_READ_ATTRIBUTES / GENERIC_READ
    share_mode = 0x00000001  # FILE_SHARE_READ; deny write and delete while held
    flags = 0x00200000  # FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= 0x02000000  # FILE_FLAG_BACKUP_SEMANTICS
    handle = kernel.CreateFileW(
        _windows_api_path(path), desired_access, share_mode, None, 3, flags, None
    )
    invalid = ctypes.c_void_p(-1).value
    if handle is None or int(handle) == invalid:
        raise OSError(ctypes.get_last_error(), "CreateFileW could not hold admitted path component")
    return int(handle)


def _close_windows_handle(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    if not kernel.CloseHandle(wintypes.HANDLE(handle)):
        raise OSError(ctypes.get_last_error(), "CloseHandle for launch lease failed")


def _windows_handle_details(handle: int) -> _WindowsHandleDetails:
    import ctypes
    from ctypes import wintypes

    class FileTime(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", FileTime),
            ("ftLastAccessTime", FileTime),
            ("ftLastWriteTime", FileTime),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileInformationByHandle.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(ByHandleFileInformation),
    )
    kernel.GetFileInformationByHandle.restype = wintypes.BOOL
    value = ByHandleFileInformation()
    if not kernel.GetFileInformationByHandle(wintypes.HANDLE(handle), ctypes.byref(value)):
        raise OSError(ctypes.get_last_error(), "GetFileInformationByHandle failed")
    kernel.GetFinalPathNameByHandleW.argtypes = (
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    capacity = 32768
    while capacity <= 131072:
        buffer = ctypes.create_unicode_buffer(capacity)
        length = kernel.GetFinalPathNameByHandleW(
            wintypes.HANDLE(handle), buffer, capacity, 0  # normalized DOS volume path
        )
        if length == 0:
            raise OSError(ctypes.get_last_error(), "GetFinalPathNameByHandleW failed")
        if length < capacity:
            return _WindowsHandleDetails(
                attributes=int(value.dwFileAttributes),
                native_identity=(
                    int(value.dwVolumeSerialNumber),
                    int(value.nFileIndexHigh),
                    int(value.nFileIndexLow),
                ),
                final_path=buffer.value,
            )
        capacity = int(length) + 1
    raise OSError("GetFinalPathNameByHandleW path exceeds the supported bound")


def _windows_handle_python_identity(handle: int) -> dict[str, int]:
    """Read Python's admitted stat identity from a duplicate of the same handle."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.argtypes = ()
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.DuplicateHandle.argtypes = (
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    )
    kernel.DuplicateHandle.restype = wintypes.BOOL
    current = kernel.GetCurrentProcess()
    duplicate = wintypes.HANDLE()
    if not kernel.DuplicateHandle(
        current,
        wintypes.HANDLE(handle),
        current,
        ctypes.byref(duplicate),
        0,
        False,
        0x00000002,  # DUPLICATE_SAME_ACCESS
    ):
        raise OSError(ctypes.get_last_error(), "DuplicateHandle for admitted identity failed")
    duplicate_value = int(duplicate.value)
    fd: int | None = None
    try:
        fd = msvcrt.open_osfhandle(duplicate_value, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        duplicate_value = 0  # ownership transferred to the CRT descriptor
        info = os.fstat(fd)
        return {
            "device": int(info.st_dev),
            "inode": int(info.st_ino),
            "size": int(info.st_size),
            "mtime_ns": int(info.st_mtime_ns),
        }
    finally:
        if fd is not None:
            os.close(fd)
        elif duplicate_value:
            _close_windows_handle(duplicate_value)


def _windows_handle_sha256(handle: int, deadline: float | None) -> str:
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.SetFilePointerEx.argtypes = (
        wintypes.HANDLE,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.DWORD,
    )
    kernel.SetFilePointerEx.restype = wintypes.BOOL
    position = ctypes.c_longlong()
    if not kernel.SetFilePointerEx(wintypes.HANDLE(handle), 0, ctypes.byref(position), 0):
        raise OSError(ctypes.get_last_error(), "SetFilePointerEx for admitted image failed")
    kernel.ReadFile.argtypes = (
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    )
    kernel.ReadFile.restype = wintypes.BOOL
    digest = hashlib.sha256()
    buffer = ctypes.create_string_buffer(1024 * 1024)
    while True:
        _remaining(deadline)
        count = wintypes.DWORD()
        if not kernel.ReadFile(
            wintypes.HANDLE(handle), buffer, len(buffer), ctypes.byref(count), None
        ):
            raise OSError(ctypes.get_last_error(), "ReadFile for admitted image failed")
        if count.value == 0:
            return digest.hexdigest()
        digest.update(buffer.raw[: count.value])


def _query_suspended_image_path(process_handle: int) -> str:
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.QueryFullProcessImageNameW.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    )
    kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
    buffer = ctypes.create_unicode_buffer(32768)
    size = wintypes.DWORD(len(buffer))
    if not kernel.QueryFullProcessImageNameW(
        wintypes.HANDLE(process_handle), 0, buffer, ctypes.byref(size)
    ):
        raise OSError(ctypes.get_last_error(), "QueryFullProcessImageNameW failed")
    if not buffer.value:
        raise OSError("QueryFullProcessImageNameW returned an empty image path")
    return buffer.value


def _snapshot_launch_artifact(artifact: Artifact) -> tuple[Artifact, tuple[tuple[str, int], ...], str]:
    """Freeze the private admission receipt before entering native APIs."""
    if not isinstance(artifact, Artifact) or artifact.target_root is None:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "native listing lacks its admitted artifact receipt")
    if not all(isinstance(value, str) and value for value in (artifact.package_id, artifact.target_name, artifact.target_kind)):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "admitted artifact target identity is invalid")
    if not isinstance(artifact.profile, dict) or set(artifact.profile) != _PROFILE_FIELDS or artifact.profile.get("test") is not True:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "admitted artifact profile is invalid")
    if not isinstance(artifact.file_identity, dict) or set(artifact.file_identity) != {"device", "inode", "size", "mtime_ns"}:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "admitted artifact file identity is incomplete")
    if any(
        not isinstance(value, int) or isinstance(value, bool)
        for value in artifact.file_identity.values()
    ):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "admitted artifact file identity is invalid")
    digest = artifact.executable_sha256
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "admitted artifact digest is invalid")
    snapshot = dataclasses.replace(
        artifact,
        executable=Path(artifact.executable),
        profile=dict(artifact.profile),
        features=tuple(artifact.features),
        filenames=tuple(artifact.filenames),
        file_identity=dict(artifact.file_identity),
        target_root=Path(artifact.target_root),
    )
    identity = tuple(sorted((key, int(value)) for key, value in snapshot.file_identity.items()))
    return snapshot, identity, digest


def _open_artifact_launch_lease(
    root: Path,
    artifact: Artifact,
    expected_identity: tuple[tuple[str, int], ...],
    expected_sha256: str,
    deadline: float | None,
) -> tuple[int, ...]:
    """Hold every lexical component and the admitted image against replacement."""
    handles: list[int] = []
    try:
        if artifact.target_root is None:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "admitted artifact has no target-root binding")
        root_path = Path(os.path.abspath(root))
        target_path = Path(os.path.abspath(artifact.target_root))
        image_path = Path(os.path.abspath(artifact.executable))
        expected_target = Path(os.path.abspath(root_path.joinpath(*_TARGET_ROOT_PARTS)))
        if _normalize_windows_path(target_path) != _normalize_windows_path(expected_target):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "admitted artifact target root differs from its original root binding")
        try:
            target_path.relative_to(root_path)
            image_path.relative_to(target_path)
        except ValueError as exc:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "admitted artifact image is outside its target root") from exc
        if not image_path.is_absolute() or not root_path.is_absolute() or not target_path.is_absolute():
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "admitted launch path is not absolute")
        parts = image_path.parts
        if not parts or not image_path.anchor:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "admitted image path has no volume root")
        chain: list[Path] = [Path(image_path.anchor)]
        current = chain[0]
        for component in parts[1:]:
            current = current / component
            chain.append(current)
        if len(chain) < 2:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "admitted image path has no file component")
        for index, component_path in enumerate(chain):
            _remaining(deadline)
            is_directory = index < len(chain) - 1
            handle = _open_windows_path_handle(component_path, directory=is_directory)
            handles.append(handle)
            details = _windows_handle_details(handle)
            is_reparse = bool(details.attributes & 0x00000400)  # FILE_ATTRIBUTE_REPARSE_POINT
            is_directory_actual = bool(details.attributes & 0x00000010)  # FILE_ATTRIBUTE_DIRECTORY
            if is_reparse or is_directory_actual != is_directory:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "admitted launch path contains a reparse or type-mismatched component")
            if _normalize_windows_path(details.final_path) != _normalize_windows_path(component_path):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "held launch component final path differs from its lexical path")
        image_handle = handles[-1]
        if tuple(sorted(_windows_handle_python_identity(image_handle).items())) != expected_identity:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "held image identity differs from the admitted Cargo artifact")
        if _windows_handle_sha256(image_handle, deadline) != expected_sha256:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "held image digest differs from the admitted Cargo artifact")
        return tuple(handles)
    except BaseException as exc:
        close_errors: list[BaseException] = []
        for handle in reversed(handles):
            try:
                _close_windows_handle(handle)
            except BaseException as close_exc:
                close_errors.append(close_exc)
        if close_errors:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "partial launch lease cleanup could not be confirmed") from exc
        raise


def _verify_suspended_artifact_image(
    process_handle: int,
    artifact: Artifact,
    held_handles: tuple[int, ...],
    expected_identity: tuple[tuple[str, int], ...],
    expected_sha256: str,
    deadline: float | None,
) -> None:
    """Bind the still-suspended child image to the already-held artifact."""
    if not held_handles:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "suspended image check has no retained launch lease")
    _remaining(deadline)
    queried_path = _query_suspended_image_path(process_handle)
    expected_path = Path(os.path.abspath(artifact.executable))
    if _normalize_windows_path(queried_path) != _normalize_windows_path(expected_path):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "suspended process image path differs from the admitted executable")
    actual_handle = _open_windows_path_handle(queried_path, directory=False)
    try:
        actual = _windows_handle_details(actual_handle)
        admitted = _windows_handle_details(held_handles[-1])
        if actual.attributes & (0x00000400 | 0x00000010):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "suspended process image is a reparse point or directory")
        if _normalize_windows_path(actual.final_path) != _normalize_windows_path(admitted.final_path):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "suspended process image final path differs from the admitted image")
        if actual.native_identity != admitted.native_identity:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "suspended process image identity differs from the admitted image")
        if tuple(sorted(_windows_handle_python_identity(actual_handle).items())) != expected_identity:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "suspended process image stat identity differs from the admitted Cargo artifact")
        if tuple(sorted(_windows_handle_python_identity(held_handles[-1]).items())) != expected_identity:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "held image identity changed after process creation")
        if _windows_handle_sha256(held_handles[-1], deadline) != expected_sha256:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "held image digest changed after process creation")
    finally:
        _close_windows_handle(actual_handle)


def _resume_suspended_process(pid: int) -> None:
    """Resume the suspended process using its owning thread handles."""
    import ctypes
    from ctypes import wintypes

    class ThreadEntry(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ThreadID", wintypes.DWORD), ("th32OwnerProcessID", wintypes.DWORD), ("tpBasePri", ctypes.c_long), ("tpDeltaPri", ctypes.c_long), ("dwFlags", wintypes.DWORD)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.Thread32First.argtypes = (wintypes.HANDLE, ctypes.POINTER(ThreadEntry))
    kernel.Thread32First.restype = wintypes.BOOL
    kernel.Thread32Next.argtypes = (wintypes.HANDLE, ctypes.POINTER(ThreadEntry))
    kernel.Thread32Next.restype = wintypes.BOOL
    kernel.OpenThread.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenThread.restype = wintypes.HANDLE
    kernel.ResumeThread.argtypes = (wintypes.HANDLE,)
    kernel.ResumeThread.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    snapshot = kernel.CreateToolhelp32Snapshot(0x00000004, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot failed")
    process_threads: list[int] = []
    entry = ThreadEntry()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        more = kernel.Thread32First(snapshot, ctypes.byref(entry))
        while more:
            if entry.th32OwnerProcessID == pid:
                process_threads.append(int(entry.th32ThreadID))
            entry.dwSize = ctypes.sizeof(entry)
            more = kernel.Thread32Next(snapshot, ctypes.byref(entry))
    finally:
        kernel.CloseHandle(snapshot)
    if len(process_threads) != 1:
        raise OSError("suspended process does not have exactly one creation thread")
    thread = kernel.OpenThread(0x0002, False, process_threads[0])  # THREAD_SUSPEND_RESUME
    if not thread:
        raise OSError(ctypes.get_last_error(), "OpenThread failed")
    try:
        previous_suspend_count = int(kernel.ResumeThread(thread))
        if previous_suspend_count == 0xFFFFFFFF:
            raise OSError(ctypes.get_last_error(), "ResumeThread failed")
        if previous_suspend_count != 1:
            raise OSError("suspended process creation thread had an unexpected suspend count")
    finally:
        kernel.CloseHandle(thread)


def _query_job_active_processes(job: int) -> int:
    import ctypes
    from ctypes import wintypes

    class Accounting(ctypes.Structure):
        _fields_ = [("TotalUserTime", ctypes.c_longlong), ("TotalKernelTime", ctypes.c_longlong), ("ThisPeriodTotalUserTime", ctypes.c_longlong), ("ThisPeriodTotalKernelTime", ctypes.c_longlong), ("TotalPageFaultCount", wintypes.DWORD), ("TotalProcesses", wintypes.DWORD), ("ActiveProcesses", wintypes.DWORD), ("TotalTerminatedProcesses", wintypes.DWORD)]

    value = Accounting()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.QueryInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD))
    kernel.QueryInformationJobObject.restype = wintypes.BOOL
    if not kernel.QueryInformationJobObject(job, 1, ctypes.byref(value), ctypes.sizeof(value), None):
        raise OSError(ctypes.get_last_error(), "QueryInformationJobObject failed")
    return int(value.ActiveProcesses)


def _terminate_job_object(job: int, exit_code: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel.TerminateJobObject.restype = wintypes.BOOL
    if not kernel.TerminateJobObject(job, exit_code):
        raise OSError(ctypes.get_last_error(), "TerminateJobObject failed")


def _close_job_object(job: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    if not kernel.CloseHandle(job):
        raise OSError(ctypes.get_last_error(), "CloseHandle failed")


def _cancel_synchronous_thread_io(thread_id: int) -> None:
    """Interrupt a blocked synchronous pipe reader during bounded cleanup."""
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenThread.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenThread.restype = wintypes.HANDLE
    kernel.CancelSynchronousIo.argtypes = (wintypes.HANDLE,)
    kernel.CancelSynchronousIo.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.OpenThread(0x0001, False, thread_id)  # THREAD_TERMINATE
    if not handle:
        raise OSError(ctypes.get_last_error(), "OpenThread for pipe cancellation failed")
    try:
        if not kernel.CancelSynchronousIo(handle):
            error = ctypes.get_last_error()
            # ERROR_NOT_FOUND means no I/O was pending when cancellation ran.
            if error != 1168:
                raise OSError(error, "CancelSynchronousIo failed")
    finally:
        kernel.CloseHandle(handle)


def _remaining(deadline: float | None) -> float:
    if deadline is None:
        return float(BOUNDS.command_timeout_seconds)
    value = deadline - time.monotonic()
    if value <= 0:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "inventory command deadline expired")
    return value


def _fixed_command_env(target_root: str) -> dict[str, str]:
    """Fail-closed environment for owned cargo/process execution (issue #905 W1).

    Only toolchain-locating variables pass through: PATH-like lookup roots,
    cargo/rustup homes, the admitted target dir, and the Windows MSVC locator
    pair SystemDrive/ProgramData (rustc needs one of them to find link.exe;
    without it every workspace link fails under the scrubbed environment).
    Absent variables drop out via the falsy filter, so non-Windows runs are
    unaffected. The values locate the toolchain only; they add no build input.
    """
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "USERPROFILE": os.environ.get("USERPROFILE", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "SystemDrive": os.environ.get("SystemDrive", ""),
        "ProgramData": os.environ.get("ProgramData", ""),
        "WINDIR": os.environ.get("WINDIR", ""),
        "TEMP": os.environ.get("TEMP", os.environ.get("TMP", "")),
        "TMP": os.environ.get("TMP", os.environ.get("TEMP", "")),
        "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", ""),
        "CARGO_HOME": os.environ.get("CARGO_HOME", ""),
        "CARGO_TARGET_DIR": target_root,
        "CARGO_TERM_COLOR": "never",
        "RUST_BACKTRACE": "0",
    }
    return {key: value for key, value in env.items() if value}


def _run_fixed(
    root: Path,
    argv: Sequence[str],
    timeout: float | None = None,
    *,
    deadline: float | None = None,
    admitted_executable: Path | None = None,
    admitted_target_root: Path | None = None,
    admitted_artifact: Artifact | None = None,
) -> CommandResult:
    command = _snapshot_argv(argv)
    launch_artifact: Artifact | None = None
    expected_identity: tuple[tuple[str, int], ...] = ()
    expected_sha256 = ""
    listing_command = len(command) == 1 + len(_LIBTEST_LIST_ARGS) and command[1:] == _LIBTEST_LIST_ARGS
    if admitted_artifact is not None:
        launch_artifact, expected_identity, expected_sha256 = _snapshot_launch_artifact(admitted_artifact)
        if not listing_command or Path(admitted_executable or "") != launch_artifact.executable:
            raise InventoryError("COMMAND_NOT_ALLOWED", "artifact receipt is only valid for its exact libtest listing command")
        if admitted_target_root is not None and _normalize_windows_path(admitted_target_root) != _normalize_windows_path(launch_artifact.target_root):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "listing target root differs from the admitted artifact binding")
        admitted_executable = launch_artifact.executable
        admitted_target_root = launch_artifact.target_root
    elif listing_command:
        raise InventoryError("COMMAND_NOT_ALLOWED", "native listing requires the original admitted artifact receipt")
    _validate_command(command, root, admitted_executable=admitted_executable)
    if os.name != "nt":
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "owned Windows Job process-tree execution is unavailable on this platform")
    if admitted_target_root is not None:
        target_root = Path(os.path.abspath(admitted_target_root))
    else:
        target_root = _admitted_target_root(root)
    env = _fixed_command_env(str(target_root))
    budget = timeout if timeout is not None else float(BOUNDS.command_timeout_seconds)
    if budget <= 0:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "fixed command has no remaining deadline budget")
    stop_at = min(deadline if deadline is not None else float("inf"), time.monotonic() + budget)
    cleanup_reserve = min(budget / 100.0, BOUNDS.command_timeout_seconds / 100.0)
    run_until = stop_at - cleanup_reserve
    proc: subprocess.Popen[bytes] | None = None
    job: int | None = None
    assigned = False
    cleanup_confirmed = False
    launch_handles: tuple[int, ...] = ()
    output_lock = __import__("threading").Lock()
    overflow = __import__("threading").Event()
    chunks: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
    stderr_diagnostic_tail = bytearray()
    total = 0
    pump_errors: list[BaseException] = []
    threads: list[Any] = []

    def pump(name: str, pipe: Any) -> None:
        nonlocal total
        try:
            while True:
                chunk = pipe.read(64 * 1024)
                if not chunk:
                    return
                with output_lock:
                    total += len(chunk)
                    if name == "stderr":
                        stderr_diagnostic_tail.extend(chunk[-_STDERR_PRE_WINDOW:])
                        if len(stderr_diagnostic_tail) > _STDERR_PRE_WINDOW:
                            del stderr_diagnostic_tail[:-_STDERR_PRE_WINDOW]
                    if total > BOUNDS.max_command_output_bytes:
                        overflow.set()
                    else:
                        chunks[name].append(chunk)
        except BaseException as exc:
            pump_errors.append(exc)

    def shared_failure_detail(prefix: str) -> str:
        with output_lock:
            stderr_tail = bytes(stderr_diagnostic_tail)
        bounded_prefix = _redact_detail(prefix)[-_STDERR_PRE_WINDOW:]
        stderr_text = stderr_tail.decode("utf-8", errors="replace")
        detail = f"{bounded_prefix}: {stderr_text}" if stderr_text else bounded_prefix
        return _redact_detail(detail)[-_STDERR_TAIL_CHARS:]

    def settle_output_pumps() -> None:
        for thread in threads:
            thread.join(timeout=max(0.0, stop_at - time.monotonic()))

    def terminate_owned() -> bool:
        nonlocal cleanup_confirmed
        if cleanup_confirmed:
            return True
        clean = True
        if job is not None and assigned:
            try:
                _terminate_job_object(job, 1)
            except Exception:
                clean = False
        elif proc is not None and proc.poll() is None:
            # Still suspended and not assigned: this exact child has run no code.
            try:
                proc.kill()
            except Exception:
                clean = False
        if proc is not None:
            try:
                proc.wait(timeout=max(0.0, min(2.0, stop_at - time.monotonic())))
            except Exception:
                clean = False
        if job is not None and assigned:
            try:
                until = stop_at
                while _query_job_active_processes(job) and time.monotonic() < until:
                    time.sleep(0.01)
                if _query_job_active_processes(job) != 0:
                    clean = False
            except Exception:
                clean = False
        cleanup_confirmed = clean
        return clean

    try:
        if time.monotonic() >= run_until:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "inventory command deadline expired")
        if launch_artifact is not None:
            launch_handles = _open_artifact_launch_lease(
                root,
                launch_artifact,
                expected_identity,
                expected_sha256,
                run_until,
            )
        if time.monotonic() >= run_until:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "launch lease acquisition exceeded the inventory deadline")
        proc = subprocess.Popen(
            list(command), cwd=root, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
            bufsize=0,
            creationflags=getattr(subprocess, "CREATE_SUSPENDED", 0x00000004),
            executable=None if launch_artifact is None else str(launch_artifact.executable),
        )
        job = _create_job_object()
        _assign_job_object(job, int(proc._handle))
        assigned = True
        if time.monotonic() >= run_until:
            clean = terminate_owned()
            if not clean:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "process-tree cleanup after setup deadline is uncertain")
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "fixed command setup exceeded the inventory deadline")
        if launch_artifact is not None:
            assert proc is not None
            _verify_suspended_artifact_image(
                int(proc._handle),
                launch_artifact,
                launch_handles,
                expected_identity,
                expected_sha256,
                run_until,
            )
        if time.monotonic() >= run_until:
            clean = terminate_owned()
            if not clean:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "process-tree cleanup after image validation deadline is uncertain")
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "suspended image validation exceeded the inventory deadline")
        _resume_suspended_process(proc.pid)
        if time.monotonic() >= run_until:
            clean = terminate_owned()
            if not clean:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "process-tree cleanup after launch deadline is uncertain")
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "fixed command launch exceeded the inventory deadline")
        for name, pipe in (("stdout", proc.stdout), ("stderr", proc.stderr)):
            thread = __import__("threading").Thread(target=pump, args=(name, pipe), daemon=True)
            thread.start()
            threads.append(thread)
        while proc.poll() is None:
            if overflow.is_set():
                clean = terminate_owned()
                if not clean:
                    raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "process-tree cleanup after output limit is uncertain")
                raise InventoryError("COMMAND_OUTPUT_TOO_LARGE", f"fixed command output exceeds {BOUNDS.max_command_output_bytes} bytes")
            if time.monotonic() >= run_until:
                clean = terminate_owned()
                if not clean:
                    raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "process-tree cleanup after deadline is uncertain")
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "fixed command exceeded the inventory deadline")
            time.sleep(min(0.02, max(0.001, run_until - time.monotonic())))
        if time.monotonic() >= run_until:
            clean = terminate_owned()
            if not clean:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "process-tree cleanup after completion deadline is uncertain")
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "fixed command exceeded the inventory deadline")
        if job is None or _query_job_active_processes(job) != 0:
            clean = terminate_owned()
            if not clean:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "child process cleanup is uncertain")
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "command exited while owned child processes remained")
        for thread in threads:
            thread.join(timeout=max(0.0, run_until - time.monotonic()))
        if any(thread.is_alive() for thread in threads):
            clean = terminate_owned()
            if not clean:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "process output drain cleanup is uncertain")
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "fixed command output drain exceeded the inventory deadline")
        if pump_errors:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "fixed command output stream could not be drained")
        if overflow.is_set():
            raise InventoryError("COMMAND_OUTPUT_TOO_LARGE", f"fixed command output exceeds {BOUNDS.max_command_output_bytes} bytes")
        stdout = b"".join(chunks["stdout"])
        stderr = b"".join(chunks["stderr"])
        if proc.returncode != 0:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", f"fixed command exited {proc.returncode}")
        return CommandResult(stdout, stderr)
    except InventoryError as exc:
        if proc is not None and (proc.poll() is None or (job is not None and assigned)):
            clean = terminate_owned()
            if not clean:
                settle_output_pumps()
                raise InventoryError(
                    "COMPILED_GRAPH_UNAVAILABLE",
                    shared_failure_detail("owned process-tree cleanup is uncertain"),
                    exc.owner,
                ) from exc
        settle_output_pumps()
        raise InventoryError(exc.code, shared_failure_detail(exc.detail), exc.owner) from exc
    except Exception as exc:
        if proc is not None and (proc.poll() is None or (job is not None and assigned)):
            clean = terminate_owned()
            if not clean:
                settle_output_pumps()
                raise InventoryError(
                    "COMPILED_GRAPH_UNAVAILABLE",
                    shared_failure_detail("owned process-tree cleanup is uncertain"),
                ) from exc
        settle_output_pumps()
        command_name = Path(command[0]).name or "fixed-command"
        raise InventoryError(
            "COMPILED_GRAPH_UNAVAILABLE",
            shared_failure_detail(f"fixed command failed: {command_name}: {exc}"),
        ) from exc
    except BaseException as exc:
        if proc is not None and (proc.poll() is None or (job is not None and assigned)):
            clean = terminate_owned()
            if not clean:
                settle_output_pumps()
                raise InventoryError(
                    "COMPILED_GRAPH_UNAVAILABLE",
                    shared_failure_detail("owned process-tree cleanup after cancellation is uncertain"),
                ) from exc
        settle_output_pumps()
        raise
    finally:
        live_readers = [thread for thread in threads if thread.is_alive()]
        for thread in live_readers:
            native_id = thread.native_id
            if native_id is not None:
                try:
                    _cancel_synchronous_thread_io(native_id)
                except Exception:
                    pass
        for thread in live_readers:
            thread.join(timeout=max(0.0, stop_at - time.monotonic()))
        readers_finished = not any(thread.is_alive() for thread in threads)
        if proc is not None and readers_finished:
            for pipe in (proc.stdout, proc.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:
                        pass
        job_close_error: Exception | None = None
        if job is not None:
            try:
                _close_job_object(job)
            except Exception as exc:
                job_close_error = exc
        lease_close_errors: list[BaseException] = []
        for handle in reversed(launch_handles):
            try:
                _close_windows_handle(handle)
            except BaseException as exc:
                lease_close_errors.append(exc)
        if not readers_finished:
            error = InventoryError(
                "COMPILED_GRAPH_UNAVAILABLE",
                shared_failure_detail("pipe-reader cleanup could not be confirmed"),
            )
            if job_close_error is not None:
                raise error from job_close_error
            if lease_close_errors:
                raise error from lease_close_errors[0]
            raise error
        if job_close_error is not None:
            raise InventoryError(
                "COMPILED_GRAPH_UNAVAILABLE",
                shared_failure_detail("owned Job Object closure could not be confirmed"),
            ) from job_close_error
        if lease_close_errors:
            raise InventoryError(
                "COMPILED_GRAPH_UNAVAILABLE",
                shared_failure_detail("admitted executable lease closure could not be confirmed"),
            ) from lease_close_errors[0]


def _runner_accepts_timeout(runner: Any) -> bool:
    import inspect

    try:
        signature = inspect.signature(runner)
    except (TypeError, ValueError):
        return False
    return "timeout" in signature.parameters or any(parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in signature.parameters.values())


def _normalize_command_result(value: Any) -> CommandResult:
    if not hasattr(value, "stdout") or not hasattr(value, "stderr"):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "injected command transport returned an invalid result shape")
    stdout, stderr = value.stdout, value.stderr
    if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "injected command transport output must be bytes")
    if len(stdout) + len(stderr) > BOUNDS.max_command_output_bytes:
        raise InventoryError("COMMAND_OUTPUT_TOO_LARGE", f"injected command output exceeds {BOUNDS.max_command_output_bytes} bytes")
    return CommandResult(stdout, stderr)


# Redaction for fixed-command failure details (issue #905: "Redact
# secrets/user paths/payloads from diagnostics"). Secrets and high-risk
# literals are redacted before persistence (I4.3.1); secrets and personal
# data never cross the boundary raw (I15.12); credentials and user profiles
# are denied by default (I18.32). "Payloads" maps to credential payloads
# (opaque tokens, key blocks) plus the bounded tail itself: diagnostics stay
# bounded (I16.7). Exit code, command identity, owner, and the tail structure
# stay intact because redaction must not destroy required integrity metadata
# (I18.45).
_REDACT_SECRET_ASSIGNMENT: Final = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret"
    r"|access[_-]?key|auth[_-]?token|oauth[_-]?token)([ \t]*[:=][ \t]*)\S+"
)
_REDACT_BEARER_TOKEN: Final = re.compile(r"\b[Bb]earer[ \t]+[A-Za-z0-9\-._~+/=]+")
_REDACT_PRIVATE_KEY: Final = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_REDACT_OPAQUE_CREDENTIAL: Final = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]+)\b"
)
# The doubled-backslash alternative covers repr/JSON-escaped paths (e.g. the
# `{argv!r}` echo in COMMAND_NOT_ALLOWED or escaped cargo stderr tails).
_REDACT_USER_HOME: Final = re.compile(
    r"(?i)(?:[A-Za-z]:\\\\Users\\\\[^\\\\/:*?\"<>|\s]+|[A-Za-z]:\\Users\\[^\\/:*?\"<>|\s]+"
    r"|/home/[^/\s]+|/Users/[^/\s]+)"
)
_REDACTED_SECRET: Final = "<redacted-secret>"
_REDACTED_USER_PATH: Final = "<redacted-user-path>"
_STDERR_PRE_WINDOW: Final = 8192
_STDERR_TAIL_CHARS: Final = 4096


def _redact_detail(text: str) -> str:
    """Redact secrets, user paths, and credential payloads from an error detail."""
    redacted = _REDACT_PRIVATE_KEY.sub(_REDACTED_SECRET, text)
    redacted = _REDACT_SECRET_ASSIGNMENT.sub(r"\1\2" + _REDACTED_SECRET, redacted)
    redacted = _REDACT_BEARER_TOKEN.sub("Bearer " + _REDACTED_SECRET, redacted)
    redacted = _REDACT_OPAQUE_CREDENTIAL.sub(_REDACTED_SECRET, redacted)
    return _REDACT_USER_HOME.sub(_REDACTED_USER_PATH, redacted)


def _run_cmd(
    runner: Any,
    root: Path,
    argv: Sequence[str],
    timeout: float | None = None,
    *,
    deadline: float | None = None,
    admitted_executable: Path | None = None,
    admitted_target_root: Path | None = None,
    admitted_artifact: Artifact | None = None,
) -> CommandResult:
    command = _snapshot_argv(argv)
    _validate_command(command, root, admitted_executable=admitted_executable)
    budget = min(timeout if timeout is not None else float(BOUNDS.command_timeout_seconds), _remaining(deadline))
    if runner is not None:
        if _runner_accepts_timeout(runner):
            value = runner(root, command, timeout=budget)
        else:
            value = runner(root, command)
        if deadline is not None and time.monotonic() >= deadline:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "injected command exceeded the inventory deadline")
        return _normalize_command_result(value)
    launch_artifact = admitted_artifact
    if admitted_artifact is not None:
        launch_artifact, _, _ = _snapshot_launch_artifact(admitted_artifact)
    return _run_fixed(
        root,
        command,
        timeout=budget,
        deadline=deadline,
        admitted_executable=admitted_executable,
        admitted_target_root=admitted_target_root,
        admitted_artifact=launch_artifact,
    )


def _cargo_metadata(root: Path, runner: Any = None, *, deadline: float | None = None) -> dict[str, Any]:
    result = _run_cmd(runner, root, _CARGO_METADATA_ARGV, deadline=deadline)
    try:
        value = _closed_json_object(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo metadata returned malformed JSON") from exc
    if not isinstance(value, dict) or not isinstance(value.get("version"), int) or isinstance(value.get("version"), bool) or value["version"] != 1:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo metadata shape is invalid")
    target_directory = value.get("target_directory")
    workspace_root = value.get("workspace_root")
    packages = value.get("packages")
    members = value.get("workspace_members")
    defaults = value.get("workspace_default_members")
    resolve = value.get("resolve")
    if not all(isinstance(item, str) for item in (target_directory, workspace_root)) or not isinstance(packages, list):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo metadata identity fields are invalid")
    if not isinstance(members, list) or not all(isinstance(item, str) for item in members):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo metadata workspace members are invalid")
    if not isinstance(defaults, list) or not all(isinstance(item, str) for item in defaults):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo metadata default members are invalid")
    if not isinstance(resolve, dict) or "root" not in resolve or not isinstance(resolve.get("nodes"), list):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo metadata dependency resolution is incomplete")
    if "metadata" not in value or not (resolve["root"] is None or isinstance(resolve["root"], str)):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo metadata root or workspace metadata is malformed")
    root_path = root.resolve(strict=True)
    admitted_target = _admitted_target_root(root)
    try:
        if Path(workspace_root).resolve(strict=True) != root_path:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo metadata workspace root differs from the admitted repository root")
        if Path(target_directory).resolve(strict=False) != admitted_target.resolve(strict=False):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo metadata target directory differs from the fixed admitted target root")
        _reject_reparse_components(root_path, admitted_target, include_leaf=True)
    except (OSError, ValueError) as exc:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo metadata returned an invalid root path") from exc
    ids: set[str] = set()
    for package in packages:
        if not isinstance(package, dict):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo package metadata is invalid")
        package_id, name, version, manifest, targets, features, dependencies = (
            package.get("id"), package.get("name"), package.get("version"), package.get("manifest_path"),
            package.get("targets"), package.get("features"), package.get("dependencies"),
        )
        if not isinstance(package_id, str) or package_id in ids or not isinstance(name, str) or not isinstance(version, str):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo package identity is invalid or duplicated")
        if "source" not in package or (package["source"] is not None and not isinstance(package["source"], str)):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo package source identity is malformed")
        if not isinstance(manifest, str) or not isinstance(targets, list) or not isinstance(features, dict) or not isinstance(dependencies, list):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo package graph fields are incomplete")
        ids.add(package_id)
        if not Path(manifest).is_absolute():
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo package manifest path is not absolute")
        for feature, members_for_feature in features.items():
            if not isinstance(feature, str) or not isinstance(members_for_feature, list) or not all(isinstance(item, str) for item in members_for_feature):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo feature metadata is invalid")
        for target in targets:
            if not isinstance(target, dict):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo target metadata is invalid")
            if not all(isinstance(target.get(key), str) for key in ("name", "src_path", "edition")):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo target identity fields are invalid")
            if not all(isinstance(target.get(key), list) and target[key] and all(isinstance(item, str) for item in target[key]) for key in ("kind", "crate_types")):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo target kinds are invalid")
            if not all(isinstance(target.get(key), bool) for key in ("doc", "doctest", "test")):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo target test flags are invalid")
            if "bench" in target and not isinstance(target["bench"], bool):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo target bench flag is invalid")
            required = target.get("required-features", [])
            if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo target required features are invalid")
    if not set(members).issubset(ids) or not set(defaults).issubset(set(members)):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo workspace membership is inconsistent with package metadata")
    resolved_ids: set[str] = set()
    for node in resolve["nodes"]:
        node_id = node.get("id") if isinstance(node, dict) else None
        if not isinstance(node, dict) or not isinstance(node_id, str) or node_id not in ids:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo resolved package node is invalid")
        if node_id in resolved_ids:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo resolved package node is duplicated")
        resolved_ids.add(node_id)
        if not isinstance(node.get("features"), list) or not all(isinstance(item, str) for item in node["features"]):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo resolved features are invalid")
        if not isinstance(node.get("deps"), list) or not isinstance(node.get("dependencies"), list):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo dependency edges are invalid")
    if not set(members).issubset(resolved_ids):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo workspace package resolution is incomplete")
    if resolve["root"] is not None and resolve["root"] not in ids:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo workspace root package is absent from metadata")
    for node in resolve["nodes"]:
        for dependency_id in node["dependencies"]:
            if not isinstance(dependency_id, str) or dependency_id not in ids:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo resolved dependency package is absent from metadata")
        edge_packages: set[str] = set()
        for edge in node["deps"]:
            if not isinstance(edge, dict) or set(edge) != {"name", "pkg", "dep_kinds"}:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo resolved dependency edge schema is invalid")
            if not isinstance(edge["name"], str) or not isinstance(edge["pkg"], str) or edge["pkg"] not in ids:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo resolved dependency edge identity is invalid")
            if not isinstance(edge["dep_kinds"], list):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo resolved dependency kinds are invalid")
            edge_packages.add(edge["pkg"])
            for dep_kind in edge["dep_kinds"]:
                if not isinstance(dep_kind, dict) or set(dep_kind) != {"kind", "target"}:
                    raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo resolved dependency kind schema is invalid")
                if dep_kind["kind"] is not None and not isinstance(dep_kind["kind"], str):
                    raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo resolved dependency kind is invalid")
                if dep_kind["target"] is not None and not isinstance(dep_kind["target"], str):
                    raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo resolved dependency target is invalid")
        if edge_packages != set(node["dependencies"]):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo resolved dependency edges do not match dependency IDs")
    for package in packages:
        for dependency in package["dependencies"]:
            if not isinstance(dependency, dict):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo dependency metadata is invalid")
            required_dependency = {"name", "source", "req", "kind", "rename", "optional", "uses_default_features", "features", "target", "registry"}
            if not required_dependency.issubset(dependency):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo dependency metadata is incomplete")
            if not all(isinstance(dependency[key], str) for key in ("name", "req")):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo dependency identity is invalid")
            if dependency["source"] is not None and not isinstance(dependency["source"], str):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo dependency source is invalid")
            if dependency["kind"] is not None and not isinstance(dependency["kind"], str):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo dependency kind is invalid")
            if dependency["rename"] is not None and not isinstance(dependency["rename"], str):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo dependency rename is invalid")
            if not isinstance(dependency["optional"], bool) or not isinstance(dependency["uses_default_features"], bool):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo dependency flags are invalid")
            if not isinstance(dependency["features"], list) or not all(isinstance(item, str) for item in dependency["features"]):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo dependency features are invalid")
            if dependency["target"] is not None and not isinstance(dependency["target"], str):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo dependency target is invalid")
            if dependency["registry"] is not None and not isinstance(dependency["registry"], str):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo dependency registry is invalid")
    return value


def _targets(root: Path, metadata: dict[str, Any]) -> list[PackageTarget]:
    workspace = set(metadata.get("workspace_members", []))
    active_features: dict[str, tuple[str, ...]] = {}
    resolve = metadata.get("resolve")
    if isinstance(resolve, dict) and isinstance(resolve.get("nodes"), list):
        for node in resolve["nodes"]:
            if isinstance(node, dict) and isinstance(node.get("id"), str) and isinstance(node.get("features"), list) and all(isinstance(item, str) for item in node["features"]):
                active_features[node["id"]] = tuple(sorted(set(node["features"])))
    result: list[PackageTarget] = []
    for package in metadata["packages"]:
        package_id = package.get("id")
        if package_id not in workspace:
            continue
        name = package.get("name")
        manifest = package.get("manifest_path")
        targets = package.get("targets")
        if not isinstance(package_id, str) or not isinstance(name, str) or not isinstance(manifest, str) or not isinstance(targets, list):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo package metadata is incomplete")
        manifest_path = _repo_path(root, Path(manifest))
        for target in targets:
            kinds = target.get("kind")
            src_path = target.get("src_path")
            target_name = target.get("name")
            required_features = target.get("required-features", [])
            features = active_features.get(package_id)
            if not isinstance(kinds, list) or not kinds or not all(isinstance(item, str) for item in kinds) or not isinstance(src_path, str) or not isinstance(target_name, str):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo target metadata is incomplete")
            if not all(isinstance(target.get(key), bool) for key in ("test", "doctest")) or not isinstance(target.get("edition"), str):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo target flags are incomplete")
            if "bench" in target and not isinstance(target["bench"], bool):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo target bench flag is invalid")
            if not isinstance(required_features, list) or not all(isinstance(item, str) for item in required_features):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo target required features are invalid")
            satisfied = None if features is None else set(required_features).issubset(features)
            target_kind = "+".join(sorted(str(item) for item in kinds))
            result.append(
                PackageTarget(
                    package_id=package_id,
                    package_name=name,
                    manifest_dir=manifest_path.parent,
                    target_name=target_name,
                    target_kind=target_kind,
                    src_path=_declared_repo_path(root, Path(src_path)),
                    test_enabled=target["test"],
                    doctest_enabled=target["doctest"],
                    bench_enabled=target.get("bench"),
                    required_features=tuple(sorted(set(required_features))),
                    required_features_satisfied=satisfied,
                    features=features or (),
                    edition=target["edition"],
                    available_features=tuple(sorted(package["features"])),
                )
            )
    return sorted(result, key=lambda item: (item.package_id, item.target_kind, item.target_name))


def _target_disposition(target: PackageTarget) -> str:
    if set(target.target_kind.split("+")) & _TEST_ARTIFACT_EXEMPT_KINDS:
        return "exempt"
    if not target.test_enabled or target.required_features_satisfied is False:
        return "test_disabled"
    return "test_enabled"


def _target_denominator(root: Path, targets: Sequence[PackageTarget]) -> list[dict[str, Any]]:
    records = [
        {
            "package_id": item.package_id,
            "package_name": item.package_name,
            "target_name": item.target_name,
            "target_kind": item.target_kind,
            "src_path": _declared_repo_path(root, item.src_path).relative_to(root.resolve(strict=True)).as_posix(),
            "test_enabled": item.test_enabled,
            "doctest_enabled": item.doctest_enabled,
            "bench_enabled": item.bench_enabled,
            "required_features": item.required_features,
            "required_features_satisfied": item.required_features_satisfied,
            "features": item.features,
            "available_features": item.available_features,
            "edition": item.edition,
            "test_disposition": _target_disposition(item),
        }
        for item in targets
    ]
    return sorted(records, key=lambda item: (item["package_id"], item["target_kind"], item["target_name"]))


def _metadata_package_identity(root: Path, package: dict[str, Any]) -> str:
    def normalized_path(path_text: str) -> str:
        path = Path(path_text).resolve(strict=False)
        try:
            return "$ROOT/" + path.relative_to(root.resolve(strict=True)).as_posix()
        except ValueError:
            return "$EXTERNAL/" + path.as_posix()

    source = package.get("source")
    if source is None:
        source_identity = "path:" + normalized_path(package["manifest_path"])
    elif isinstance(source, str) and source.startswith("path+file:"):
        from urllib.parse import urlparse
        from urllib.request import url2pathname

        parsed = urlparse(source[len("path+") :])
        path = url2pathname(parsed.path)
        if parsed.netloc:
            path = "//" + parsed.netloc + path
        source_identity = "path:" + normalized_path(path)
    else:
        source_identity = str(source)
    return f'{package["name"]}@{package["version"]}[{source_identity}]'


def _metadata_sha256(root: Path, metadata: dict[str, Any]) -> str:
    packages = metadata["packages"]
    package_by_id = {package["id"]: package for package in packages}
    if len(package_by_id) != len(packages):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo package graph contains duplicate IDs")
    root_path = root.resolve(strict=True)

    def normalize_path(path_text: str) -> str:
        path = Path(path_text).resolve(strict=False)
        try:
            return "$ROOT/" + path.relative_to(root_path).as_posix()
        except ValueError:
            # An external path dependency is identity-bearing; keep its full
            # normalized path instead of collapsing packages by crate name.
            return "$EXTERNAL/" + path.as_posix()

    def source_identity(package: dict[str, Any]) -> str:
        source = package.get("source")
        if source is None:
            return "path:" + normalize_path(package["manifest_path"])
        if isinstance(source, str) and source.startswith("path+file:"):
            from urllib.parse import unquote, urlparse

            parsed = urlparse(source[len("path+") :])
            path = unquote(parsed.path)
            if parsed.netloc:
                path = "//" + parsed.netloc + path
            return "path:" + normalize_path(path)
        return str(source)

    def normalized_source(package: dict[str, Any]) -> str | None:
        source = package.get("source")
        if not isinstance(source, str) or not source.startswith("path+file:"):
            return source
        from urllib.parse import urlparse
        from urllib.request import url2pathname

        parsed = urlparse(source[len("path+") :])
        path = url2pathname(parsed.path)
        if parsed.netloc:
            path = "//" + parsed.netloc + path
        return "path+" + normalize_path(path)

    stable_by_id: dict[str, str] = {}
    seen_stable: set[str] = set()
    for package in packages:
        stable = _metadata_package_identity(root, package)
        if stable in seen_stable:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo package graph has colliding stable identities")
        stable_by_id[package["id"]] = stable
        seen_stable.add(stable)

    def stable_package_id(package_id: str | None) -> str | None:
        if package_id is None:
            return None
        try:
            return stable_by_id[package_id]
        except KeyError as exc:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo graph references an unknown package identity") from exc

    def normalize_target(target: dict[str, Any]) -> dict[str, Any]:
        result = dict(target)
        result["kind"] = sorted(target["kind"])
        result["crate_types"] = sorted(target["crate_types"])
        result["src_path"] = normalize_path(target["src_path"])
        if "required-features" in target:
            result["required-features"] = sorted(target["required-features"])
        return result

    normalized_packages: list[dict[str, Any]] = []
    for package in packages:
        normalized = dict(package)
        normalized["id"] = stable_package_id(package["id"])
        normalized["source"] = normalized_source(package)
        normalized["manifest_path"] = normalize_path(package["manifest_path"])
        normalized["targets"] = sorted(
            (normalize_target(target) for target in package["targets"]),
            key=_canonical_bytes,
        )
        normalized["features"] = {
            name: sorted(members) for name, members in sorted(package["features"].items())
        }
        dependencies = []
        for dependency in package["dependencies"]:
            if not isinstance(dependency, dict):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo dependency metadata is invalid")
            value = dict(dependency)
            if isinstance(value.get("features"), list):
                value["features"] = sorted(value["features"])
            dependencies.append(value)
        normalized["dependencies"] = sorted(dependencies, key=_canonical_bytes)
        normalized_packages.append(normalized)

    resolve = metadata["resolve"]
    normalized_resolve = dict(resolve)
    normalized_resolve["root"] = stable_package_id(resolve.get("root"))
    nodes = []
    for node in resolve["nodes"]:
        if not isinstance(node, dict):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo resolved dependency node is invalid")
        normalized_node = dict(node)
        normalized_node["id"] = stable_package_id(node["id"])
        normalized_node["features"] = sorted(set(node["features"]))
        normalized_node["dependencies"] = sorted(stable_package_id(item) for item in node["dependencies"])
        deps = []
        for dependency in node["deps"]:
            if not isinstance(dependency, dict) or not isinstance(dependency.get("pkg"), str):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo resolved dependency edge is invalid")
            edge = dict(dependency)
            edge["pkg"] = stable_package_id(dependency["pkg"])
            kinds = dependency.get("dep_kinds")
            if not isinstance(kinds, list) or not all(isinstance(item, dict) for item in kinds):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo resolved dependency kinds are invalid")
            edge["dep_kinds"] = sorted(kinds, key=_canonical_bytes)
            deps.append(edge)
        normalized_node["deps"] = sorted(deps, key=_canonical_bytes)
        nodes.append(normalized_node)
    normalized_resolve["nodes"] = sorted(nodes, key=lambda item: item["id"])

    payload = dict(metadata)
    payload["workspace_root"] = "$ROOT"
    payload["target_directory"] = "$TARGET"
    payload["workspace_members"] = sorted(stable_package_id(item) for item in metadata["workspace_members"])
    payload["workspace_default_members"] = sorted(stable_package_id(item) for item in metadata["workspace_default_members"])
    payload["packages"] = sorted(normalized_packages, key=lambda item: item["id"])
    payload["resolve"] = normalized_resolve
    return _sha256(_canonical_bytes(payload))


def _lex_rust(text: str) -> list[Token]:
    tokens: list[Token] = []
    index = 0
    line = 1
    length = len(text)

    def advance(segment: str) -> None:
        nonlocal line
        line += segment.count("\n")

    while index < length:
        char = text[index]
        if char.isspace():
            end = index + 1
            while end < length and text[end].isspace():
                end += 1
            advance(text[index:end])
            index = end
            continue
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            if end < 0:
                break
            advance(text[index : end + 1])
            index = end + 1
            continue
        if text.startswith("/*", index):
            depth = 1
            end = index + 2
            while end < length and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                raise InventoryError("MALFORMED_SOURCE", "unterminated block comment")
            advance(text[index:end])
            index = end
            continue
        if char == "'" and index + 1 < length and (text[index + 1].isalpha() or text[index + 1] == "_"):
            end = index + 2
            while end < length and (text[end].isalnum() or text[end] == "_"):
                end += 1
            if end > index + 2 or end >= length or text[end] != "'":
                # Rust lifetime or loop label (`'name`, `'static`, `'_`): an
                # apostrophe followed by an identifier start opens a lifetime,
                # not a character literal. Only the single-character form with
                # an immediate closing quote (`'x'`) falls through to the
                # character-literal scan below.
                tokens.append(Token("punct", "'", index, index + 1, line))
                tokens.append(Token("ident", text[index + 1 : end], index + 1, end, line))
                index = end
                continue
        if char in {'"', "'"} or (char in {"b", "c"} and index + 1 < length and text[index + 1] in {'"', "'"}):
            start = index
            if char in {"b", "c"}:
                index += 1
                char = text[index]
            index += 1
            escaped = False
            while index < length:
                current = text[index]
                index += 1
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == char:
                    break
            else:
                raise InventoryError("MALFORMED_SOURCE", "unterminated string or character literal")
            raw = text[start:index]
            tokens.append(Token("string", raw, start, index, line))
            advance(raw)
            continue
        raw_match = re.match(r'(?:b|c)?r(#{0,255})"', text[index:])
        if raw_match:
            start = index
            hashes = raw_match.group(1)
            index += raw_match.end()
            terminator = '"' + hashes
            end = text.find(terminator, index)
            if end < 0:
                raise InventoryError("MALFORMED_SOURCE", "unterminated raw string literal")
            index = end + len(terminator)
            raw = text[start:index]
            tokens.append(Token("string", raw, start, index, line))
            advance(raw)
            continue
        if (
            text.startswith("r#", index)
            and index + 2 < length
            and (text[index + 2].isalpha() or text[index + 2] == "_")
        ):
            start = index
            end = index + 3
            while end < length and (text[end].isalnum() or text[end] == "_"):
                end += 1
            tokens.append(Token("ident", text[index + 2:end], start, end, line))
            index = end
            continue
        if char.isalpha() or char == "_":
            end = index + 1
            while end < length and (text[end].isalnum() or text[end] == "_"):
                end += 1
            tokens.append(Token("ident", text[index:end], index, end, line))
            index = end
            continue
        if char.isdigit():
            end = index + 1
            while end < length and (text[end].isalnum() or text[end] in r"_\."):
                end += 1
            tokens.append(Token("number", text[index:end], index, end, line))
            index = end
            continue
        if text.startswith("::", index) or text.startswith("->", index) or text.startswith("=>", index):
            tokens.append(Token("punct", text[index : index + 2], index, index + 2, line))
            index += 2
            continue
        tokens.append(Token("punct", char, index, index + 1, line))
        index += 1
    return tokens


def _unescape_rust_str(s: str) -> str:
    def repl(m: re.Match[str]) -> str:
        esc = m.group(1)
        if esc == "n":
            return "\n"
        if esc == "r":
            return "\r"
        if esc == "t":
            return "\t"
        if esc == "\\":
            return "\\"
        if esc == "0":
            return "\0"
        if esc == '"':
            return '"'
        if esc == "'":
            return "'"
        return esc
    return re.sub(r"\\(.)", repl, s)


def _decode_reason(raw: str) -> str | None:
    # Only strings attached to ignore or disabled attributes carry a reason.
    targeted = re.findall(
        r'(?:ignore|disabled[a-z_]*|test_disabled)\b[^(="]*[=(]\s*(?:(?:note|reason)\s*=\s*)?(?:(?:b|c)?r(#{0,16})"(.*?)"\1|(?:b|c)?"((?:\\.|[^"\\])*)")',
        raw,
        re.DOTALL,
    )
    for _h, raw_val, esc_val in targeted:
        value = raw_val if raw_val else _unescape_rust_str(esc_val)
        if value.strip():
            return value.strip()[:1024]

    # No fallback: only reason-bearing attributes (ignore/disabled*/test_disabled
    # per the targeted rule above) may contribute a reason. Configuration strings
    # on sibling attributes (e.g. tokio::test flavor) must never become the row
    # reason; bare ignore/missing reason stays unclassified, never guessed.
    return None


_STRING_SPAN: Final = re.compile(r'(?:b|c)?r(#{0,16})".*?"\1|(?:b|c)?"(?:\\.|[^"\\])*"', re.DOTALL)


def _attribute_flags(raw: str) -> tuple[bool, bool, bool, str | None, str | None]:
    code = _STRING_SPAN.sub('""', raw)
    compact = re.sub(r"\s+", "", code)
    disabled = any(marker in compact for marker in ("disabled_test", "eliot_disabled_test", "test_disabled"))
    is_test = bool(re.search(r"(?:^|[:\[,])(?:test|tokio::test|async_std::test)(?:$|[\],(])", compact)) or disabled
    direct_ignore = bool(re.search(r"(?:^|[:\[,])ignore(?:=|$|[\],(])", compact))
    cfg_ignore = "cfg_attr" in compact and "ignore" in compact
    is_ignored = direct_ignore or cfg_ignore or disabled
    cfg = raw if "cfg" in compact else None
    return is_test, is_ignored, cfg_ignore or disabled, _decode_reason(raw), cfg


# `cargo test` compiles no `--test` harness for these kinds, so they can never
# yield a compiler-artifact with profile.test=true. Every other declared kind
# must produce at least one test executable, or the compiled denominator is
# incomplete over the complete declared target set (issue #905: an unavailable
# target is nonzero/incomplete, never invisible).
_TEST_ARTIFACT_EXEMPT_KINDS: Final = frozenset({"custom-build"})


def _candidate_source_files(
    root: Path, target: PackageTarget, exclude: frozenset[Path] = frozenset()
) -> list[Path]:
    # Seed the graph with only the Cargo-declared root. Descendants enter the
    # source denominator exclusively through resolved module declarations.
    resolved = _declared_repo_path(root, target.src_path)
    return [] if resolved in exclude else [resolved]


def _scan_file(
    root: Path,
    target: PackageTarget,
    path: Path,
    *,
    module_path: tuple[str, ...] | None = None,
    module_cfg_evidence: tuple[str, ...] = (),
    source_bytes: bytes | None = None,
    source_sha256: str | None = None,
) -> list[SourceTest]:
    try:
        resolved_root = root.resolve(strict=True)
        candidate = path if path.is_absolute() else root / path
        admitted = candidate.resolve(strict=False)
        admitted.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise InventoryError("PATH_ESCAPE", _redact_detail(f"path is outside repository root: {path}")) from exc
    if not admitted.is_file():
        raise InventoryError("SOURCE_NOT_FOUND", _redact_detail(f"Rust source is not a readable file: {path}"))
    try:
        data = source_bytes if source_bytes is not None else _bounded_read(admitted)
    except OSError as exc:
        raise InventoryError("SOURCE_READ_FAILED", _redact_detail(f"cannot read Rust source: {path}")) from exc
    if source_sha256 is None:
        source_sha256 = _sha256(data)
    path = admitted
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InventoryError("INVALID_SOURCE_ENCODING", _redact_detail(f"Rust source is not UTF-8: {path}")) from exc
    tokens = _lex_rust(text)
    seed_module_path = () if module_path is None else module_path
    module_stack: list[tuple[str, int, tuple[str, ...]]] = [(part, 0, ()) for part in seed_module_path]
    brace_depth = 0
    pending_attributes: list[str] = []
    pending_spans: list[tuple[int, int]] = []
    pending_module: str | None = None
    results: list[SourceTest] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.value == "#" and index + 1 < len(tokens) and tokens[index + 1].value == "[":
            start = token.start
            depth = 0
            cursor = index + 1
            while cursor < len(tokens):
                value = tokens[cursor].value
                if value == "[":
                    depth += 1
                elif value == "]":
                    depth -= 1
                    if depth == 0:
                        end = tokens[cursor].end
                        break
                cursor += 1
            else:
                raise InventoryError("MALFORMED_SOURCE", _redact_detail(f"unterminated attribute in {path}"))
            if end - start > BOUNDS.max_attribute_bytes:
                raise InventoryError("ATTRIBUTE_TOO_LARGE", _redact_detail(f"attribute exceeds bound in {path}"))
            pending_attributes.append(text[start:end])
            pending_spans.append((start, end))
            index = cursor + 1
            continue
        if token.value == "mod" and index + 1 < len(tokens) and tokens[index + 1].kind == "ident":
            pending_module = tokens[index + 1].value
        elif token.value == "fn" and index + 1 < len(tokens) and tokens[index + 1].kind == "ident":
            name_token = tokens[index + 1]
            flags = [_attribute_flags(raw) for raw in pending_attributes]
            is_test = any(item[0] for item in flags)
            is_ignored = any(item[1] for item in flags)
            if is_test and is_ignored:
                modules = [name for name, _, _ in module_stack]
                test_name = "::".join((*modules, name_token.value)) if modules else name_token.value
                # Only ignore-bearing attributes contribute a reason; a config
                # string on a sibling test attribute must never win by position.
                reason = next((item[3] for item in flags if item[1] and item[3]), None)
                inline_module_cfg = (
                    evidence
                    for _, _, module_evidence in module_stack
                    for evidence in module_evidence
                )
                cfg = tuple(
                    dict.fromkeys(
                        (
                            *module_cfg_evidence,
                            *inline_module_cfg,
                            *(item[4] for item in flags if item[4]),
                        )
                    )
                )
                attributes = "\n".join(pending_attributes)
                # W24: environment tokens derive ONLY from the bound ignore
                # reason. Sibling attribute text (#[doc] prose, cfg/feature
                # strings, flavor literals) must never manufacture a provider
                # class: cfg_evidence is preserved verbatim above as the
                # target/OS/cfg discriminator and never contributes
                # environment tokens, so unknown vocabulary stays UNCLASSIFIED.
                requirements = _requirements(reason or "")
                attribute_code = "\n".join(_STRING_SPAN.sub('""', raw) for raw in pending_attributes)
                isolation = _isolation(attribute_code, reason)
                relative = _relative(root, path)
                source_identity = {
                    "path": relative,
                    "line": name_token.line,
                    "test_name": test_name,
                    "attributes": attributes,
                    "source_file_sha256": source_sha256,
                    "module_path": seed_module_path,
                    "cfg_evidence": cfg,
                }
                results.append(
                    SourceTest(
                        package_id=target.package_id,
                        package_name=target.package_name,
                        target_name=target.target_name,
                        target_kind=target.target_kind,
                        test_name=test_name,
                        source_path=relative,
                        line=name_token.line,
                        attribute_text=attributes,
                        attribute_digest=_sha256(attributes.encode("utf-8")),
                        reason=reason,
                        cfg_evidence=cfg,
                        requirements=requirements,
                        source_digest=_sha256(_canonical_bytes(source_identity)),
                        isolation=isolation,
                        fn_span=(name_token.start, name_token.end),
                        attribute_span=(pending_spans[0][0], pending_spans[-1][1]) if pending_spans else None,
                    )
                )
            pending_attributes.clear()
            pending_spans.clear()
        elif token.value == "{":
            brace_depth += 1
            if pending_module is not None:
                module_flags = [_attribute_flags(raw) for raw in pending_attributes]
                inline_cfg = tuple(item[4] for item in module_flags if item[4])
                module_stack.append((pending_module, brace_depth, inline_cfg))
                pending_module = None
            pending_attributes.clear()
            pending_spans.clear()
        elif token.value == "}":
            while module_stack and module_stack[-1][1] == brace_depth:
                module_stack.pop()
            brace_depth = max(0, brace_depth - 1)
            pending_attributes.clear()
            pending_spans.clear()
            pending_module = None
        elif token.value == ";":
            pending_attributes.clear()
            pending_spans.clear()
            pending_module = None
        elif token.kind == "ident" and token.value not in {"pub", "async", "unsafe", "const", "extern", "crate", "self", "super"}:
            if token.value not in {"fn", "mod"} and pending_module is None:
                # Keep attributes while traversing visibility/qualifier tokens,
                # but discard them when another item begins.
                if token.value in {"struct", "enum", "trait", "impl", "type", "static", "use", "macro_rules"}:
                    pending_attributes.clear()
                    pending_spans.clear()
        index += 1
    return results


def _phrase_pattern(phrase: str) -> str:
    words = phrase.split(" ")
    if len(words) == 1:
        return r"\b" + re.escape(phrase) + r"\b"
    return r"\b" + r"\s+".join(re.escape(word) for word in words) + r"\b"


_STORE_PATTERNS: Final = tuple(
    _phrase_pattern(item)
    for item in ("surreal", "store", "database", "schema migration", "authenticated db")
) + (r"\bsurreal\w+",)
_RUNTIME_PATTERNS: Final = tuple(
    _phrase_pattern(item)
    for item in (
        "kernel", "governor", "host", "watchdog", "agent bridge",
        "named pipe", "windows pipe", "pipe", "acl", "session",
        "installation", "configuration", "config", "eliot_governor_config", "windows runtime",
    )
)
_GIT_PATTERNS: Final = tuple(
    _phrase_pattern(item) for item in ("git", "repository", "worktree", "commit identity")
)
_EXTERNAL_PATTERNS: Final = (
    _phrase_pattern("personal credential"),
    _phrase_pattern("external credential"),
    _phrase_pattern("credential"),
    _phrase_pattern("paid"),
    _phrase_pattern("api key"),
    _phrase_pattern("oauth"),
    r"\bmanual-only\b",
    _phrase_pattern("manual only"),
)
# Network class vocabulary (issue #905 row contract "credential/network
# class"). Word-boundary discipline throughout: bare "connection" is
# deliberately absent because declared Runtime phrases ("Host daemon
# connection", "named pipe connection") must not compose a network class.
_NETWORK_PATTERNS: Final = tuple(
    _phrase_pattern(item) for item in ("network", "egress", "ingress", "internet", "outbound")
)
_STORE_MATCHER: Final = re.compile("|".join(_STORE_PATTERNS))
_RUNTIME_MATCHER: Final = re.compile("|".join(_RUNTIME_PATTERNS))
_GIT_MATCHER: Final = re.compile("|".join(_GIT_PATTERNS))
_EXTERNAL_MATCHER: Final = re.compile("|".join(_EXTERNAL_PATTERNS))
_NETWORK_MATCHER: Final = re.compile("|".join(_NETWORK_PATTERNS))
_REQUIREMENT_MATCHERS: Final = (
    _STORE_MATCHER,
    _RUNTIME_MATCHER,
    _GIT_MATCHER,
    _EXTERNAL_MATCHER,
    _NETWORK_MATCHER,
)

# Literal words of the finite rule table (issue #905 W7/W24/W6). A leftover
# unit word the table itself names (e.g. "runtime" inside "windows runtime")
# is table vocabulary, never an unknown provider; anything else uncovered is.
_TABLE_LITERAL_WORDS: Final = frozenset(
    word
    for patterns in (
        _STORE_PATTERNS, _RUNTIME_PATTERNS, _GIT_PATTERNS,
        _EXTERNAL_PATTERNS, _NETWORK_PATTERNS,
    )
    for pattern in patterns
    for word in re.findall(r"[a-z_]+", re.sub(r"\\.", "", pattern))
)


# Negation remains local to the clause containing a recognized requirement
# token. The bounded prefix/suffix windows catch explicit forms such as "no
# network", "without local SurrealDB", and "network access not required";
# an unrelated earlier "no" cannot negate a later clause.
_NEGATION_CLAUSES: Final = re.compile(
    r"[;.!?\r\n]+|\b(?:but|however|although|whereas|while)\b"
)
_NEGATION_PREFIX: Final = re.compile(
    r"(?:^|\b)(?:no|without|never|not(?!\s+only)|"
    r"(?:is|are|was|were|do|does|did|has|have|had|can|could|will|would|must|should|need|needs|require|requires)\s+not)"
    r"(?:\s+\w+){0,3}\s*$"
)
_NEGATION_SUFFIX: Final = re.compile(
    r"^(?:\W+\w+){0,3}\W+(?:"
    r"not\s+(?:required|needed|necessary|used|available|requested|applicable|present|supported|provided|allowed|permitted)\b|"
    r"(?:is|are|was|were|do|does|did|has|have|had|can|could|will|would|must|should|need|needs|require|requires)\s+not\b|"
    r"(?:isn't|aren't|wasn't|weren't|don't|doesn't|didn't|haven't|hasn't|can't|cannot)\b|"
    r"unneeded\b|unnecessary\b)"
)


# Provider-position unknown-vocabulary guard (issue #905 W7/W24: conservative
# unknown dependency treatment, refuting comment 5981399706). A supported
# Store/Runtime/... word must not certify the whole row while the reason names
# another explicit provider the rule table does not know ("requires SurrealDB
# and Redis", "requires store with PostgreSQL"): the extra provider is an
# unleased dependency (I18.32:3), so the composed set keeps UNKNOWN and
# reconcile leaves the row UNCLASSIFIED. Proper nouns are providers and
# lowercase words are modifiers: every unit of a multi-provider enumeration
# (conjunction- or comma-separated, first unit included) accounts for each
# word (match span, glue, table literal, or lowercase descriptor), so
# all-known phrases are unaffected; single declarations keep matcher-only
# semantics. A capitalized leftover ("Redis" beside generic "database") is
# an explicit unknown name; lowercase leftovers ("local", "running") ride
# the unit's known anchor as modifiers.


def _has_unknown_provider(raw_text: str) -> bool:
    """An explicit additional provider the rule table does not cover.

    Every unit of a multi-provider enumeration (conjunction- or
    comma-separated, including the first) must account for each of its words:
    inside a known-phrase match span, verb/determiner glue, a literal word of
    the rule table itself, or a lowercase descriptor of the unit's known
    anchor. A capitalized leftover word (e.g. "Redis" beside generic
    "database") names an explicit dependency the table does not know: proper
    nouns are providers, lowercase words are modifiers. Single declarations
    keep matcher-only semantics, so all-known phrases are unaffected.
    """
    value = raw_text.casefold()
    units = [unit.strip() for unit in _PROVIDER_UNIT_SPLIT.split(value)]
    units = [unit for unit in units if unit]
    if len(units) < 2:
        return False
    raw_units = [unit.strip() for unit in _PROVIDER_UNIT_SPLIT_CI.split(raw_text)]
    raw_units = [unit for unit in raw_units if unit]
    if len(raw_units) != len(units):
        return True
    for unit, raw_unit in zip(units, raw_units):
        if len(unit) != len(raw_unit):
            return True
        covered: set[int] = set()
        for matcher in _REQUIREMENT_MATCHERS:
            for match in matcher.finditer(unit):
                covered.update(range(match.start(), match.end()))
        for token in re.finditer(r"\S+", unit):
            if set(range(token.start(), token.end())) <= covered:
                continue
            raw_word = raw_unit[token.start():token.end()]
            key = raw_word.strip(_WORD_STRIP_CHARS).casefold()
            if not key:
                continue
            if key in _PROVIDER_GLUE_WORDS or key in _TABLE_LITERAL_WORDS:
                continue
            if raw_word == raw_word.lower():
                continue
            return True
    return False


_PROVIDER_UNIT_SPLIT: Final = re.compile(r"\b(?:and|or|with|plus)\b|,")
_PROVIDER_NON_PROVIDER_WORDS: Final = frozenset({"a", "an", "the"})
_PROVIDER_GLUE_WORDS: Final = _PROVIDER_NON_PROVIDER_WORDS | frozenset({"requires", "require", "needs", "need"})
# Case-insensitive twin of the unit splitter: the same separators applied to
# the raw reason, so capitalized (proper-noun) words keep their case for the
# explicit-provider test below. Derived from the bound pattern, not new rules.
_PROVIDER_UNIT_SPLIT_CI = re.compile(_PROVIDER_UNIT_SPLIT.pattern, re.IGNORECASE)
# Leading/trailing punctuation stripped before glue/literal comparison, so a
# "requires:" verb or '"store",' token still reads as its word.
_WORD_STRIP_CHARS: Final = ".,:;!?()[]\"'"



# Versioned finite rule-table identity (issue #905: "versioned finite rule
# table"). RULE_TABLE_VERSION is the human identity; RULE_TABLE_SHA256 binds the
# exact pattern literals, so any rule edit changes the emitted header and
# aggregate digest even when no row's composed requirement set changes.
RULE_TABLE_VERSION: Final = "1.5.0"
RULE_TABLE_SHA256: Final = _sha256(
    _canonical_bytes(
        {
            "store": _STORE_PATTERNS,
            "runtime": _RUNTIME_PATTERNS,
            "git": _GIT_PATTERNS,
            "external": _EXTERNAL_PATTERNS,
            "network": _NETWORK_PATTERNS,
            "negation": {
                "clauses": _NEGATION_CLAUSES.pattern,
                "prefix": _NEGATION_PREFIX.pattern,
                "suffix": _NEGATION_SUFFIX.pattern,
            },
            "provider_conjunction": {
                "conjunction": _PROVIDER_UNIT_SPLIT.pattern,
                "non_provider_words": sorted(_PROVIDER_NON_PROVIDER_WORDS),
                "glue_words": sorted(_PROVIDER_GLUE_WORDS),
                "word_strip": _WORD_STRIP_CHARS,
            },
        }
    )
)


def _has_negated_requirement(text: str) -> bool:
    for clause in _NEGATION_CLAUSES.split(text.casefold()):
        for matcher in _REQUIREMENT_MATCHERS:
            for match in matcher.finditer(clause):
                prefix = clause[max(0, match.start() - 96) : match.start()].rsplit(",", 1)[-1]
                suffix = clause[match.end() : match.end() + 96]
                if _NEGATION_PREFIX.search(prefix) or _NEGATION_SUFFIX.match(suffix):
                    return True
    return False


def _requirements(text: str) -> tuple[str, ...]:
    value = text.casefold()
    if _has_negated_requirement(value):
        return (Requirement.UNKNOWN.value,)
    result: set[Requirement] = set()
    if _STORE_MATCHER.search(value):
        result.add(Requirement.STORE)
    if _RUNTIME_MATCHER.search(value):
        result.add(Requirement.RUNTIME)
    if _GIT_MATCHER.search(value):
        result.add(Requirement.GIT)
    if _NETWORK_MATCHER.search(value):
        result.add(Requirement.NETWORK)
    if _EXTERNAL_MATCHER.search(value):
        result.add(Requirement.EXTERNAL_CREDENTIALED_MANUAL_ONLY)
    if not result:
        result.add(Requirement.UNKNOWN)
    elif _has_unknown_provider(text):
        result.add(Requirement.UNKNOWN)
    return tuple(sorted(item.value for item in result))


# Finite isolation/serialization/reset/timeout declaration table (issue #905
# row contract). Attribute markers bind from string-stripped attribute code so
# a marker such as #[serial] binds without its strings being read as
# vocabulary; reason phrases bind from the bound ignore reason only, never
# from sibling attribute strings (W24). Anything undeclared binds nothing.
_ISOLATION_MARKERS: Final = ("parallel", "serial")
_ISOLATION_REASON_PATTERNS: Final = (
    ("isolated", (_phrase_pattern("isolated"), _phrase_pattern("isolation"))),
    ("serial", (_phrase_pattern("serial"), _phrase_pattern("serialization"))),
    ("timeout", (_phrase_pattern("timeout"),)),
    ("reset", (_phrase_pattern("reset"),)),
)
_ISOLATION_MARKER_MATCHERS: Final = tuple(
    (marker, re.compile(r"(?:^|[:\[,])" + re.escape(marker) + r"(?:$|[\],(])")) for marker in _ISOLATION_MARKERS
)
_ISOLATION_REASON_MATCHERS: Final = tuple(
    (token, re.compile("|".join(patterns))) for token, patterns in _ISOLATION_REASON_PATTERNS
)


def _isolation(attribute_code: str, reason: str | None) -> tuple[str, ...]:
    """Bind declared isolation/serialization/reset/timeout tokens."""
    found: set[str] = set()
    for marker, matcher in _ISOLATION_MARKER_MATCHERS:
        if matcher.search(attribute_code):
            found.add(marker)
    if reason:
        value = reason.casefold()
        for token, matcher in _ISOLATION_REASON_MATCHERS:
            if matcher.search(value):
                found.add(token)
    return tuple(sorted(found))


def _observe_source_file(root: Path, path: Path, deadline: float | None) -> tuple[bytes, dict[str, int], str]:
    import stat

    _reject_reparse_components(root, path, include_leaf=True)
    try:
        before = path.stat()
        if not stat.S_ISREG(before.st_mode):
            raise InventoryError("SOURCE_READ_FAILED", "Rust source is not a regular file")
        if before.st_size > BOUNDS.max_file_bytes:
            raise InventoryError("SOURCE_FILE_TOO_LARGE", _redact_detail(f"{path} exceeds {BOUNDS.max_file_bytes} bytes"))
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        length = 0
        with path.open("rb") as stream:
            while True:
                if deadline is not None and time.monotonic() >= deadline:
                    raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "inventory deadline expired while reading Rust source")
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                length += len(chunk)
                if length > BOUNDS.max_file_bytes:
                    raise InventoryError("SOURCE_FILE_TOO_LARGE", _redact_detail(f"{path} exceeds {BOUNDS.max_file_bytes} bytes"))
                chunks.append(chunk)
                digest.update(chunk)
        _reject_reparse_components(root, path, include_leaf=True)
        after = path.stat()
    except InventoryError:
        raise
    except OSError as exc:
        raise InventoryError("SOURCE_READ_FAILED", _redact_detail(f"cannot read Rust source: {path}")) from exc
    before_id = {"device": int(before.st_dev), "inode": int(before.st_ino), "size": int(before.st_size), "mtime_ns": int(before.st_mtime_ns)}
    after_id = {"device": int(after.st_dev), "inode": int(after.st_ino), "size": int(after.st_size), "mtime_ns": int(after.st_mtime_ns)}
    if before_id != after_id or length != before.st_size:
        raise InventoryError("SOURCE_READ_FAILED", _redact_detail(f"Rust source identity changed while reading: {path}"))
    return b"".join(chunks), before_id, digest.hexdigest()


def _rust_string_value(raw: str) -> str | None:
    if raw.startswith('"'):
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return value if isinstance(value, str) else None
    match = re.fullmatch(r'r(#{0,255})"(.*)"\1', raw, re.DOTALL)
    return None if match is None else match.group(2)


def _split_rust_arguments(text: str) -> list[str]:
    tokens = _lex_rust(text)
    parts: list[str] = []
    start = 0
    depth = 0
    for token in tokens:
        if token.value in {"(", "[", "{"}:
            depth += 1
        elif token.value in {")", "]", "}"}:
            depth = max(0, depth - 1)
        elif token.value == "," and depth == 0:
            parts.append(text[start:token.start].strip())
            start = token.end
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _cfg_value(expression: str, target: PackageTarget) -> bool | None:
    tokens = _lex_rust(expression)
    index = 0

    def parse_atom() -> bool | None:
        nonlocal index
        if index >= len(tokens) or tokens[index].kind != "ident":
            raise ValueError("invalid cfg expression")
        name = tokens[index].value
        index += 1
        if index < len(tokens) and tokens[index].value == "(":
            index += 1
            values: list[bool | None] = []
            while index < len(tokens) and tokens[index].value != ")":
                values.append(parse_atom())
                if index < len(tokens) and tokens[index].value == ",":
                    index += 1
                elif index < len(tokens) and tokens[index].value != ")":
                    raise ValueError("invalid cfg argument separator")
            if index >= len(tokens):
                raise ValueError("unterminated cfg predicate")
            index += 1
            if name == "all":
                return False if False in values else (None if None in values else True)
            if name == "any":
                return True if True in values else (None if None in values else False)
            if name == "not" and len(values) == 1:
                return None if values[0] is None else not values[0]
            return None
        if index < len(tokens) and tokens[index].value == "=":
            index += 1
            if index >= len(tokens) or tokens[index].kind != "string":
                raise ValueError("cfg value is not a string")
            value = _rust_string_value(tokens[index].value)
            index += 1
            if value is None:
                return None
            if name == "feature":
                if value in target.features:
                    return True
                if value not in target.available_features:
                    return None
                return False
            return None
        if name == "test":
            if target.test_profile_active is not None:
                return target.test_profile_active
            if not target.test_enabled or target.required_features_satisfied is False:
                return False
            return None
        return None

    try:
        value = parse_atom()
        if index != len(tokens):
            return None
        return value
    except (ValueError, InventoryError):
        return None


def _attribute_form(raw: str) -> tuple[str, str] | None:
    match = re.fullmatch(r"\s*#\[\s*(cfg|cfg_attr)\s*\((.*)\)\s*\]\s*", raw, re.DOTALL)
    return None if match is None else (match.group(1), match.group(2))


def _effective_module_attributes(
    attributes: Sequence[str], target: PackageTarget
) -> tuple[bool | None, tuple[str, ...], tuple[str, ...]]:
    state: bool | None = True
    evidence: list[str] = []
    active: list[str] = []

    def combine(value: bool | None) -> None:
        nonlocal state
        if value is False:
            state = False
        elif value is None and state is not False:
            state = None

    def apply_attribute(raw: str, depth: int) -> None:
        if depth > 64:
            evidence.append(raw)
            combine(None)
            return
        form = _attribute_form(raw)
        if form is None:
            active.append(raw)
            return
        kind, payload = form
        evidence.append(raw)
        if kind == "cfg":
            combine(_cfg_value(payload, target))
            active.append(raw)
            return
        arguments = _split_rust_arguments(payload)
        if len(arguments) < 2:
            combine(None)
            return
        condition = _cfg_value(arguments[0], target)
        if condition is False:
            return
        if condition is None:
            combine(None)
            return
        for argument in arguments[1:]:
            derived = "#[" + argument + "]"
            apply_attribute(derived, depth + 1)

    for raw in attributes:
        apply_attribute(raw, 0)
    return state, tuple(evidence), tuple(active)


def _path_override(attributes: Sequence[str]) -> tuple[str | None, bool]:
    values: list[str] = []
    for raw in attributes:
        match = re.fullmatch(r"\s*#\[\s*path\s*=\s*(.*?)\s*\]\s*", raw, re.DOTALL)
        if match is None:
            continue
        value = _rust_string_value(match.group(1).strip())
        if value is None:
            return None, True
        values.append(value)
    if len(values) > 1:
        return None, True
    return (values[0], False) if values else (None, False)


def _module_declarations(
    source: str,
    source_path: Path,
    target: PackageTarget,
    base_dir: Path,
    module_path: tuple[str, ...],
    inherited_cfg: tuple[str, ...],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    tokens = _lex_rust(source)
    modules: list[dict[str, Any]] = []
    includes: list[dict[str, Any]] = []

    def close_group(start: int, end: int) -> int | None:
        pairs = {"(": ")", "[": "]", "{": "}"}
        opening = tokens[start].value
        if opening not in pairs:
            return None
        stack = [pairs[opening]]
        for cursor in range(start + 1, end):
            value = tokens[cursor].value
            if value in pairs:
                stack.append(pairs[value])
            elif value in {")", "]", "}"}:
                if not stack or value != stack.pop():
                    return None
                if not stack:
                    return cursor
        return None

    def macro_invocation(start: int, end: int) -> tuple[str, str, int, int] | None:
        cursor = start
        if cursor < end and tokens[cursor].value == "::":
            cursor += 1
        if cursor >= end or tokens[cursor].kind != "ident":
            return None
        names = [tokens[cursor].value]
        cursor += 1
        while cursor + 1 < end and tokens[cursor].value == "::" and tokens[cursor + 1].kind == "ident":
            names.append(tokens[cursor + 1].value)
            cursor += 2
        if cursor + 1 >= end or tokens[cursor].value != "!" or tokens[cursor + 1].value not in {"(", "[", "{"}:
            return None
        closing = close_group(cursor + 1, end)
        if closing is None:
            return None
        return "::".join(names), tokens[cursor + 1].value, cursor + 1, closing

    def macro_rules_end(start: int, end: int) -> int | None:
        if start + 2 >= end or tokens[start].value != "macro_rules" or tokens[start + 1].value != "!":
            return None
        cursor = start + 2
        if cursor < end and tokens[cursor].kind == "ident":
            cursor += 1
        while cursor < end and tokens[cursor].value != "{":
            if tokens[cursor].value in {";", "}"}:
                return None
            if tokens[cursor].value in {"(", "["}:
                close = close_group(cursor, end)
                if close is None:
                    return None
                cursor = close + 1
            else:
                cursor += 1
        if cursor >= end:
            return None
        return close_group(cursor, end)

    def scope(start: int, end: int, current_base: Path, current_module: tuple[str, ...], cfg: tuple[str, ...]) -> None:
        cursor = start
        pending: list[str] = []
        pending_start: int | None = None
        item_start = True
        current_item_kind: str | None = None
        while cursor < end:
            token = tokens[cursor]
            if token.value == "#" and cursor + 1 < end and tokens[cursor + 1].value == "[":
                depth = 0
                close = cursor + 1
                while close < end:
                    if tokens[close].value == "[":
                        depth += 1
                    elif tokens[close].value == "]":
                        depth -= 1
                        if depth == 0:
                            break
                    close += 1
                if close >= end:
                    return
                if not pending:
                    pending_start = token.start
                pending.append(source[token.start:tokens[close].end])
                cursor = close + 1
                continue

            if item_start and token.value == "pub":
                cursor += 1
                if cursor < end and tokens[cursor].value == "(":
                    closing = close_group(cursor, end)
                    if closing is None:
                        return
                    visibility = tokens[cursor + 1:closing]
                    restricted = (
                        len(visibility) == 1
                        and visibility[0].kind == "ident"
                        and visibility[0].value in {"crate", "self", "super"}
                    )
                    if visibility and visibility[0].value == "in":
                        path = visibility[1:]
                        restricted = bool(path) and len(path) % 2 == 1 and all(
                            part.kind == "ident" if index % 2 == 0 else part.value == "::"
                            for index, part in enumerate(path)
                        )
                    if restricted:
                        cursor = closing + 1
                continue
            if item_start and token.value in {"unsafe", "async", "default", "auto", "extern"}:
                cursor += 1
                continue
            if item_start and token.value == "const" and cursor + 1 < end and tokens[cursor + 1].value == "fn":
                cursor += 1
                continue

            if token.value == "macro_rules" and cursor + 1 < end and tokens[cursor + 1].value == "!":
                closing = macro_rules_end(cursor, end)
                if closing is None:
                    return
                cursor = closing + 1
                if cursor < end and tokens[cursor].value == ";":
                    cursor += 1
                pending.clear()
                pending_start = None
                item_start = True
                current_item_kind = None
                continue

            if token.value == "mod" and cursor + 1 < end and tokens[cursor + 1].kind == "ident":
                name = tokens[cursor + 1].value
                delimiter = cursor + 2
                while delimiter < end and tokens[delimiter].value not in {"{", ";"}:
                    delimiter += 1
                if delimiter >= end:
                    return
                state, evidence, active_attributes = _effective_module_attributes(pending, target)
                module_cfg = tuple(dict.fromkeys((*cfg, *evidence)))
                path_value, invalid_path = _path_override(active_attributes)
                declaration_start = pending_start if pending_start is not None else tokens[cursor].start
                if tokens[delimiter].value == ";":
                    declarations.append(
                        {
                            "name": name,
                            "base_dir": current_base,
                            "module_path": current_module + (name,),
                            "cfg_state": state,
                            "cfg_evidence": module_cfg,
                            "path_override": path_value,
                            "invalid_path": invalid_path,
                            "declaration": source[declaration_start:tokens[delimiter].end].strip(),
                            "source_path": source_path,
                        }
                    )
                    pending.clear()
                    pending_start = None
                    cursor = delimiter + 1
                    item_start = True
                    current_item_kind = None
                    continue
                closing = close_group(delimiter, end)
                if closing is None:
                    return
                body_module = current_module + (name,)
                resolution = "inline" if state is True else ("inactive" if state is False else "unresolved")
                modules.append(
                    {
                        "module_path": body_module,
                        "declaration": source[declaration_start:tokens[closing].end].strip(),
                        "path": None,
                        "resolution": resolution,
                        "cfg_evidence": module_cfg,
                        "reason": None if state is not None else "unknown_cfg",
                    }
                )
                if state is True:
                    scope(delimiter + 1, closing, current_base / name, body_module, module_cfg)
                pending.clear()
                pending_start = None
                cursor = closing + 1
                item_start = True
                current_item_kind = None
                continue

            invocation = macro_invocation(cursor, end)
            if invocation is not None:
                macro_name, opening, group_start, closing = invocation
                if item_start:
                    state, evidence, _active_attributes = _effective_module_attributes(pending, target)
                    macro_cfg = tuple(dict.fromkeys((*cfg, *evidence)))
                    declaration_start = pending_start if pending_start is not None else token.start
                    declaration_end = tokens[closing].end
                    if closing + 1 < end and tokens[closing + 1].value == ";":
                        declaration_end = tokens[closing + 1].end
                    is_include = macro_name == "include" and opening == "("
                    literal: str | None = None
                    if is_include:
                        arguments = tokens[group_start + 1:closing]
                        if len(arguments) == 1 and arguments[0].kind == "string":
                            literal = _rust_string_value(arguments[0].value)
                    includes.append(
                        {
                            "kind": "include" if is_include else "macro",
                            "literal": literal,
                            "cfg_state": state,
                            "cfg_evidence": macro_cfg,
                            "declaration": source[declaration_start:declaration_end].strip(),
                            "module_path": current_module,
                            "source_path": source_path,
                            "base_dir": source_path.parent,
                        }
                    )
                    pending.clear()
                    pending_start = None
                    cursor = closing + 1
                    if cursor < end and tokens[cursor].value == ";":
                        cursor += 1
                    item_start = True
                    current_item_kind = None
                    continue
                cursor = closing + 1
                continue

            if token.value in {"(", "[", "{"}:
                closing = close_group(cursor, end)
                if closing is None:
                    return
                cursor = closing + 1
                pending.clear()
                pending_start = None
                if token.value == "{" and current_item_kind in {
                    "fn", "struct", "enum", "trait", "impl", "union", "macro",
                }:
                    item_start = True
                    current_item_kind = None
                continue
            if token.value == ";":
                pending.clear()
                pending_start = None
                item_start = True
                current_item_kind = None
                cursor += 1
                continue
            if item_start:
                current_item_kind = token.value if token.kind == "ident" else None
                item_start = False
            elif token.kind == "ident" and token.value in {
                "fn", "struct", "enum", "trait", "impl", "type", "static", "const", "use", "union",
            }:
                pending.clear()
                pending_start = None
            cursor += 1

    declarations: list[dict[str, Any]] = []
    scope(0, len(tokens), base_dir, module_path, inherited_cfg)
    return declarations, modules, includes


def discover_source(
    root: Path,
    targets: Sequence[PackageTarget],
    *,
    source_denominator_records: list[dict[str, Any]] | None = None,
    source_denominator_complete_out: list[bool] | None = None,
    test_profile_context: dict[tuple[str, str, str], bool] | None = None,
    deadline: float | None = None,
) -> list[SourceTest]:
    import stat

    result: list[SourceTest] = []
    denominator: list[dict[str, Any]] = []
    source_cache: dict[Path, tuple[bytes, dict[str, int], str]] = {}
    total_bytes = 0
    total_files = 0
    total_walk_nodes = 0
    complete = True
    for target in sorted(targets, key=lambda item: (item.package_id, item.target_kind, item.target_name)):
        context_key = (target.package_id, target.target_kind, target.target_name)
        if test_profile_context is not None and context_key in test_profile_context:
            target = dataclasses.replace(target, test_profile_active=test_profile_context[context_key])
        source_records: list[dict[str, Any]] = []
        module_records: list[dict[str, Any]] = []
        unresolved_records: list[dict[str, Any]] = []
        queue: list[
            tuple[Path, tuple[str, ...], tuple[str, ...], str, str | None, Path, dict[str, Any] | None]
        ] = [
            (path, (), (), "root", None, path.parent, None)
            for path in _candidate_source_files(root, target)
        ]
        visited: set[tuple[Path, tuple[str, ...]]] = set()
        while queue:
            if deadline is not None and time.monotonic() >= deadline:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "inventory deadline expired during Rust module traversal")
            path, logical_module, inherited_cfg, source_resolution, declaration, module_base, declared_by = queue.pop(0)
            path = _declared_repo_path(root, path)
            visit_key = (path, logical_module)
            if visit_key in visited:
                continue
            visited.add(visit_key)
            total_walk_nodes += 1
            if total_walk_nodes > BOUNDS.max_source_files:
                raise InventoryError("SOURCE_FILE_LIMIT", "source module graph exceeds configured file bound")
            try:
                if path not in source_cache:
                    data, file_identity, file_digest = _observe_source_file(root, path, deadline)
                    total_files += 1
                    total_bytes += len(data)
                    if total_files > BOUNDS.max_source_files:
                        raise InventoryError("SOURCE_FILE_LIMIT", "source module graph exceeds configured file bound")
                    if total_bytes > BOUNDS.max_source_bytes:
                        raise InventoryError("SOURCE_BYTE_LIMIT", "source module graph exceeds configured byte bound")
                    source_cache[path] = (data, file_identity, file_digest)
                data, file_identity, file_digest = source_cache[path]
                text = data.decode("utf-8")
            except (InventoryError, UnicodeDecodeError) as exc:
                if isinstance(exc, InventoryError) and exc.code not in {"SOURCE_READ_FAILED", "PATH_ESCAPE", "SOURCE_NOT_FOUND"}:
                    raise
                complete = False
                unresolved = {
                    "module_path": logical_module,
                    "declaration": declaration or "target root",
                    "path": None,
                    "cfg_evidence": inherited_cfg,
                    "reason": "source_unavailable",
                    "declaration_source_path": None if declared_by is None else declared_by["declaration_source_path"],
                    "declaration_source_sha256": None if declared_by is None else declared_by["declaration_source_sha256"],
                    "declaration_source_file_identity": None if declared_by is None else declared_by["declaration_source_file_identity"],
                }
                unresolved_records.append(unresolved)
                continue
            relative = path.relative_to(root.resolve(strict=True)).as_posix()
            declaration_source = {
                "declaration_source_path": relative,
                "declaration_source_sha256": file_digest,
                "declaration_source_file_identity": file_identity,
            }
            source_records.append(
                {
                    "path": relative,
                    "module_path": logical_module,
                    "declaration": declaration,
                    "resolution": source_resolution,
                    "cfg_evidence": inherited_cfg,
                    "file_identity": file_identity,
                    "sha256": file_digest,
                }
            )
            result.extend(
                _scan_file(
                    root,
                    target,
                    path,
                    module_path=logical_module,
                    module_cfg_evidence=inherited_cfg,
                    source_bytes=data,
                    source_sha256=file_digest,
                )
            )
            if len(result) > BOUNDS.max_source_tests:
                raise InventoryError("SOURCE_TEST_LIMIT", "source test denominator exceeds configured bound")
            declarations, inline_modules, includes = _module_declarations(
                text, path, target, module_base, logical_module, inherited_cfg
            )
            for inline in inline_modules:
                inline["path"] = relative
                inline["sha256"] = file_digest
                inline["file_identity"] = file_identity
                if inline["resolution"] == "unresolved":
                    complete = False
                    unresolved_records.append(
                        {
                            "module_path": inline["module_path"],
                            "declaration": inline["declaration"],
                            "path": None,
                            "cfg_evidence": inline["cfg_evidence"],
                            "reason": inline["reason"] or "unknown_cfg",
                            **declaration_source,
                        }
                    )
            module_records.extend(inline_modules)
            for item in declarations:
                module_path = item["module_path"]
                if item["cfg_state"] is False:
                    module_records.append(
                        {
                            "module_path": module_path,
                            "declaration": item["declaration"],
                            "path": None,
                            "resolution": "inactive",
                            "cfg_evidence": item["cfg_evidence"],
                            "reason": None,
                            **declaration_source,
                        }
                    )
                    continue
                if item["cfg_state"] is None or item["invalid_path"]:
                    complete = False
                    unresolved = {
                        "module_path": module_path,
                        "declaration": item["declaration"],
                        "path": None,
                        "cfg_evidence": item["cfg_evidence"],
                        "reason": "unknown_cfg" if item["cfg_state"] is None else "invalid_path_attribute",
                        **declaration_source,
                    }
                    module_records.append({**unresolved, "resolution": "unresolved"})
                    unresolved_records.append(unresolved)
                    continue
                base_dir = item["base_dir"]
                candidates = [base_dir / item["path_override"]] if item["path_override"] is not None else [base_dir / f'{item["name"]}.rs', base_dir / item["name"] / "mod.rs"]
                existing: list[Path] = []
                unsafe_candidate = False
                for candidate in candidates:
                    try:
                        admitted = _declared_repo_path(root, candidate)
                        _reject_reparse_components(root, candidate, include_leaf=True)
                        try:
                            info = candidate.stat()
                        except (FileNotFoundError, NotADirectoryError):
                            continue
                        except OSError:
                            unsafe_candidate = True
                            continue
                        if stat.S_ISREG(info.st_mode):
                            existing.append(admitted)
                        else:
                            unsafe_candidate = True
                    except InventoryError:
                        unsafe_candidate = True
                if unsafe_candidate or len(existing) != 1:
                    complete = False
                    reason = "unadmitted_module_path" if unsafe_candidate else ("missing_module" if not existing else "ambiguous_module")
                    unresolved = {
                        "module_path": module_path,
                        "declaration": item["declaration"],
                        "path": None,
                        "cfg_evidence": item["cfg_evidence"],
                        "reason": reason,
                        **declaration_source,
                    }
                    module_records.append({**unresolved, "resolution": "unresolved"})
                    unresolved_records.append(unresolved)
                    continue
                admitted = existing[0]
                module_records.append(
                    {
                        "module_path": module_path,
                        "declaration": item["declaration"],
                        "path": admitted.relative_to(root.resolve(strict=True)).as_posix(),
                        "resolution": "resolved",
                        "cfg_evidence": item["cfg_evidence"],
                        "reason": None,
                    }
                )
                child_base = admitted.parent if admitted.name == "mod.rs" else admitted.parent / admitted.stem
                queue.append(
                    (admitted, module_path, item["cfg_evidence"], "resolved", item["declaration"], child_base, declaration_source)
                )
            for item in includes:
                if item["cfg_state"] is False:
                    module_records.append(
                        {
                            "module_path": item["module_path"],
                            "declaration": item["declaration"],
                            "path": None,
                            "cfg_evidence": item["cfg_evidence"],
                            "resolution": "inactive",
                            "reason": "cfg_inactive",
                            **declaration_source,
                        }
                    )
                    continue
                if item["cfg_state"] is None or item["kind"] == "macro":
                    complete = False
                    unresolved = {
                        "module_path": item["module_path"],
                        "declaration": item["declaration"],
                        "path": None,
                        "cfg_evidence": item["cfg_evidence"],
                        "reason": "unknown_cfg" if item["cfg_state"] is None else "opaque_macro_expansion",
                        **declaration_source,
                    }
                    unresolved_records.append(unresolved)
                    module_records.append({**unresolved, "resolution": "unresolved"})
                    continue
                if item["literal"] is None:
                    complete = False
                    unresolved = {
                        "module_path": item["module_path"],
                        "declaration": item["declaration"],
                        "path": None,
                        "cfg_evidence": item["cfg_evidence"],
                        "reason": "dynamic_include",
                        **declaration_source,
                    }
                    unresolved_records.append(unresolved)
                    module_records.append({**unresolved, "resolution": "unresolved"})
                    continue
                try:
                    include_path = _declared_repo_path(root, item["base_dir"] / item["literal"])
                    _reject_reparse_components(root, item["base_dir"] / item["literal"], include_leaf=True)
                except InventoryError:
                    complete = False
                    unresolved = {
                        "module_path": item["module_path"],
                        "declaration": item["declaration"],
                        "path": None,
                        "cfg_evidence": item["cfg_evidence"],
                        "reason": "unadmitted_include_path",
                        **declaration_source,
                    }
                    unresolved_records.append(unresolved)
                    module_records.append({**unresolved, "resolution": "unresolved"})
                    continue
                try:
                    include_info = include_path.stat()
                except (FileNotFoundError, NotADirectoryError):
                    complete = False
                    unresolved = {
                        "module_path": item["module_path"],
                        "declaration": item["declaration"],
                        "path": None,
                        "cfg_evidence": item["cfg_evidence"],
                        "reason": "missing_include",
                        **declaration_source,
                    }
                    unresolved_records.append(unresolved)
                    module_records.append({**unresolved, "resolution": "unresolved"})
                    continue
                except OSError:
                    complete = False
                    unresolved = {
                        "module_path": item["module_path"],
                        "declaration": item["declaration"],
                        "path": None,
                        "cfg_evidence": item["cfg_evidence"],
                        "reason": "unreadable_include",
                        **declaration_source,
                    }
                    unresolved_records.append(unresolved)
                    module_records.append({**unresolved, "resolution": "unresolved"})
                    continue
                if not stat.S_ISREG(include_info.st_mode):
                    complete = False
                    unresolved = {
                        "module_path": item["module_path"],
                        "declaration": item["declaration"],
                        "path": None,
                        "cfg_evidence": item["cfg_evidence"],
                        "reason": "unreadable_include",
                        **declaration_source,
                    }
                    unresolved_records.append(unresolved)
                    module_records.append({**unresolved, "resolution": "unresolved"})
                    continue
                module_records.append(
                    {
                        "module_path": item["module_path"],
                        "declaration": item["declaration"],
                        "path": include_path.relative_to(root.resolve(strict=True)).as_posix(),
                        "resolution": "included",
                        "cfg_evidence": item["cfg_evidence"],
                        "reason": None,
                    }
                )
                queue.append(
                    (include_path, item["module_path"], item["cfg_evidence"], "included", item["declaration"], include_path.parent, declaration_source)
                )
        for source_record in source_records:
            denominator.append(
                {
                    "package_id": target.package_id,
                    "package_name": target.package_name,
                    "target_name": target.target_name,
                    "target_kind": target.target_kind,
                    "path": source_record["path"],
                    "module_path": source_record["module_path"],
                    "sha256": source_record["sha256"],
                    "file_identity": source_record["file_identity"],
                    "cfg_evidence": source_record["cfg_evidence"],
                    "resolution": "resolved",
                    "declaration": source_record["declaration"],
                }
            )
        for module in module_records:
            if module["resolution"] == "inline":
                denominator.append(
                    {
                        "package_id": target.package_id,
                        "package_name": target.package_name,
                        "target_name": target.target_name,
                        "target_kind": target.target_kind,
                        "path": module["path"],
                        "module_path": module["module_path"],
                        "sha256": module["sha256"],
                        "file_identity": module["file_identity"],
                        "cfg_evidence": module["cfg_evidence"],
                        "resolution": "resolved",
                        "declaration": module["declaration"],
                    }
                )
            elif module["resolution"] == "inactive":
                denominator.append(
                    {
                        "package_id": target.package_id,
                        "package_name": target.package_name,
                        "target_name": target.target_name,
                        "target_kind": target.target_kind,
                        "path": None,
                        "module_path": module["module_path"],
                        "sha256": None,
                        "file_identity": None,
                        "cfg_evidence": module["cfg_evidence"],
                        "resolution": "resolved",
                        "declaration": module["declaration"],
                        "reason": "cfg_inactive",
                        "declaration_source_path": module.get("declaration_source_path"),
                        "declaration_source_sha256": module.get("declaration_source_sha256"),
                        "declaration_source_file_identity": module.get("declaration_source_file_identity"),
                    }
                )
        for unresolved in unresolved_records:
            denominator.append(
                {
                    "package_id": target.package_id,
                    "package_name": target.package_name,
                    "target_name": target.target_name,
                    "target_kind": target.target_kind,
                    "path": None,
                    "module_path": unresolved["module_path"],
                    "sha256": None,
                    "file_identity": None,
                    "cfg_evidence": unresolved["cfg_evidence"],
                    "resolution": "unresolved",
                    "declaration": unresolved["declaration"],
                    "reason": unresolved["reason"],
                    "declaration_source_path": unresolved.get("declaration_source_path"),
                    "declaration_source_sha256": unresolved.get("declaration_source_sha256"),
                    "declaration_source_file_identity": unresolved.get("declaration_source_file_identity"),
                }
            )
    denominator.sort(
        key=lambda item: (
            item["package_id"], item["target_kind"], item["target_name"],
            item["path"] or "", item["module_path"], item["resolution"], item["declaration"] or "",
            item.get("declaration_source_path") or "", item.get("declaration_source_sha256") or "",
        )
    )
    if source_denominator_records is not None:
        source_denominator_records.extend(denominator)
    if source_denominator_complete_out is not None:
        source_denominator_complete_out.append(complete)
    return sorted(result, key=lambda item: item.identity() + (item.source_path, item.line))


def _metadata_target_index(metadata: dict[str, Any] | None) -> dict[tuple[str, str, str], dict[str, Any]]:
    result: dict[tuple[str, str, str], dict[str, Any]] = {}
    if metadata is None:
        return result
    for package in metadata.get("packages", []):
        for target in package.get("targets", []):
            kind = "+".join(sorted(target["kind"]))
            key = (package["id"], kind, target["name"])
            if key in result:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo metadata contains a duplicate package target")
            result[key] = {"package": package, "target": target}
    return result


def _validate_cargo_target(value: Any) -> None:
    if not isinstance(value, dict):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo message target is not an object")
    required = {"kind", "crate_types", "name", "src_path", "edition", "doc", "doctest", "test"}
    allowed = required | {"required-features"}
    if not required.issubset(value) or set(value) - allowed:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo message target schema is not recognized")
    if not all(isinstance(value.get(key), list) and value[key] and all(isinstance(item, str) for item in value[key]) for key in ("kind", "crate_types")):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo message target kinds are invalid")
    if not all(isinstance(value.get(key), str) for key in ("name", "src_path", "edition")):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo message target identity is invalid")
    if not all(isinstance(value.get(key), bool) for key in ("doc", "doctest", "test")):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo message target flags are invalid")
    required_features = value.get("required-features", [])
    if not isinstance(required_features, list) or not all(isinstance(item, str) for item in required_features):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo message required-features are invalid")


def _match_cargo_target(
    root: Path,
    package_id: str,
    target_value: dict[str, Any],
    index: dict[tuple[str, str, str], dict[str, Any]],
    *,
    require_metadata_match: bool = False,
) -> tuple[str, str, str]:
    _validate_cargo_target(target_value)
    kind = "+".join(sorted(target_value["kind"]))
    key = (package_id, kind, target_value["name"])
    expected = index.get(key)
    if expected is None:
        if require_metadata_match:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo message target is absent from cargo metadata")
        return key
    metadata_target = expected["target"]
    for field in ("kind", "crate_types", "name", "edition", "doc", "doctest", "test"):
        if field in ("kind", "crate_types"):
            if sorted(target_value[field]) != sorted(metadata_target[field]):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo message target differs from cargo metadata")
        elif target_value[field] != metadata_target[field]:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo message target differs from cargo metadata")
    if sorted(target_value.get("required-features", [])) != sorted(metadata_target.get("required-features", [])):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo message target feature requirements differ from metadata")
    try:
        if Path(target_value["src_path"]).resolve(strict=True) != Path(metadata_target["src_path"]).resolve(strict=True):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo message target source differs from cargo metadata")
    except OSError as exc:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo message target source path is unreadable") from exc
    return key


def _admitted_artifact_path(root: Path, target_root: Path, raw_path: str) -> Path:
    if not isinstance(raw_path, str) or not raw_path or not Path(raw_path).is_absolute():
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo artifact path is not absolute")
    candidate = Path(raw_path)
    try:
        _reject_reparse_components(target_root, candidate, include_leaf=True)
        resolved = candidate.resolve(strict=True)
        relative = resolved.relative_to(target_root.resolve(strict=False))
    except (OSError, ValueError, InventoryError) as exc:
        raise InventoryError("PATH_ESCAPE", "Cargo artifact path is outside the admitted target root or uses a reparse component") from exc
    if not relative.parts or not resolved.is_file():
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo artifact is not a regular file")
    return resolved


def _declared_repo_path(root: Path, path: Path) -> Path:
    """Resolve a Cargo-declared source path without requiring it to exist yet."""
    try:
        resolved_root = root.resolve(strict=True)
        candidate = path if path.is_absolute() else root / path
        resolved = Path(os.path.abspath(candidate))
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise InventoryError("PATH_ESCAPE", _redact_detail(f"declared source path is outside repository root: {path}")) from exc
    return resolved


def _admitted_build_directory(root: Path, target_root: Path, raw_path: str) -> Path:
    if not isinstance(raw_path, str) or not raw_path or not Path(raw_path).is_absolute():
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo build output directory is not absolute")
    candidate = Path(raw_path)
    try:
        _reject_reparse_components(target_root, candidate, include_leaf=True)
        resolved = candidate.resolve(strict=True)
        relative = resolved.relative_to(target_root.resolve(strict=False))
    except (OSError, ValueError, InventoryError) as exc:
        raise InventoryError("PATH_ESCAPE", "Cargo build output directory escapes the admitted target root") from exc
    if not relative.parts or not resolved.is_dir():
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo build output path is not a directory")
    return resolved


def _observe_executable(
    root: Path, target_root: Path, path: Path, *, deadline: float | None = None
) -> tuple[dict[str, int], str]:
    import hashlib

    _reject_reparse_components(target_root, path, include_leaf=True)
    try:
        before = path.stat()
        if not path.is_file():
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "compiled executable is not a regular file")
        digest = hashlib.sha256()
        bytes_read = 0
        with path.open("rb") as stream:
            while True:
                if deadline is not None and time.monotonic() >= deadline:
                    raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "inventory deadline expired while hashing a compiled executable")
                chunk = stream.read(128 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                bytes_read += len(chunk)
        _reject_reparse_components(target_root, path, include_leaf=True)
        after = path.stat()
    except InventoryError:
        raise
    except OSError as exc:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "compiled executable could not be read") from exc
    identity_before = {"device": int(before.st_dev), "inode": int(before.st_ino), "size": int(before.st_size), "mtime_ns": int(before.st_mtime_ns)}
    identity_after = {"device": int(after.st_dev), "inode": int(after.st_ino), "size": int(after.st_size), "mtime_ns": int(after.st_mtime_ns)}
    if identity_before != identity_after or bytes_read != before.st_size:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "compiled executable identity changed while being hashed")
    return identity_before, digest.hexdigest()


def _closed_json_object(raw: bytes) -> dict[str, Any]:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-JSON numeric constant is not allowed: {value}")

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique_pairs, parse_constant=reject_constant)
    if not isinstance(value, dict):
        raise ValueError("Cargo message is not an object")
    return value


def _validate_compiler_diagnostic(value: Any, depth: int = 0) -> None:
    if depth > 64 or not isinstance(value, dict):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo compiler diagnostic shape is invalid")
    required = {"message", "code", "level", "spans", "children"}
    allowed = required | {"rendered", "$message_type"}
    if not required.issubset(value) or set(value) - allowed:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo compiler diagnostic schema is not recognized")
    # Current rustc envelopes every JSON diagnostic with "$message_type":
    # "diagnostic". Admit exactly that value so the live toolchain validates,
    # while any other extra key or marker value stays refused (closed shape).
    if "$message_type" in value and value["$message_type"] != "diagnostic":
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo compiler diagnostic marker is invalid")
    if not isinstance(value["message"], str) or not isinstance(value["level"], str):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo compiler diagnostic text is invalid")
    code = value["code"]
    if code is not None:
        if not isinstance(code, dict) or "code" not in code or set(code) - {"code", "explanation"}:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo compiler diagnostic code is invalid")
        if not isinstance(code["code"], str) or (code.get("explanation") is not None and not isinstance(code["explanation"], str)):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo compiler diagnostic code identity is invalid")
    if value.get("rendered") is not None and not isinstance(value.get("rendered"), str):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo compiler diagnostic rendering is invalid")
    if not isinstance(value["spans"], list) or not isinstance(value["children"], list):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo compiler diagnostic collections are invalid")
    if depth > 0 and value["children"]:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo compiler diagnostic child records cannot contain nested children")
    span_fields = {
        "file_name", "byte_start", "byte_end", "line_start", "line_end",
        "column_start", "column_end", "is_primary", "text", "label",
        "suggested_replacement", "suggestion_applicability", "expansion",
    }

    def validate_span(span: Any, span_depth: int) -> None:
        if span_depth > 64 or not isinstance(span, dict) or set(span) != span_fields:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo diagnostic span schema is not recognized")
        if not isinstance(span["file_name"], str) or not all(
            isinstance(span[key], int) and not isinstance(span[key], bool)
            for key in ("byte_start", "byte_end", "line_start", "line_end", "column_start", "column_end")
        ):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo diagnostic span position is invalid")
        if not isinstance(span["is_primary"], bool) or not isinstance(span["text"], list):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo diagnostic span flags are invalid")
        if span["label"] is not None and not isinstance(span["label"], str):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo diagnostic span label is invalid")
        if span["suggested_replacement"] is not None and not isinstance(span["suggested_replacement"], str):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo diagnostic replacement is invalid")
        if span["suggestion_applicability"] is not None and not isinstance(span["suggestion_applicability"], str):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo diagnostic applicability is invalid")
        for segment in span["text"]:
            if not isinstance(segment, dict) or set(segment) != {"text", "highlight_start", "highlight_end"}:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo diagnostic source text schema is not recognized")
            if not isinstance(segment["text"], str) or not all(
                isinstance(segment[key], int) and not isinstance(segment[key], bool)
                for key in ("highlight_start", "highlight_end")
            ):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo diagnostic source text is invalid")
        expansion = span["expansion"]
        if expansion is not None:
            if not isinstance(expansion, dict) or not {"span", "macro_decl_name"}.issubset(expansion) or set(expansion) - {"span", "macro_decl_name", "def_site_span"}:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo diagnostic macro expansion schema is not recognized")
            if not isinstance(expansion["macro_decl_name"], str):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo diagnostic macro name is invalid")
            validate_span(expansion["span"], span_depth + 1)
            if expansion.get("def_site_span") is not None:
                validate_span(expansion["def_site_span"], span_depth + 1)

    for span in value["spans"]:
        validate_span(span, 0)
    for child in value["children"]:
        _validate_compiler_diagnostic(child, depth + 1)


def _canonical_cargo_build_record(
    root: Path,
    target_root: Path,
    value: dict[str, Any],
    package_keys: dict[str, str],
) -> dict[str, Any]:
    reason = value["reason"]
    package_id = value.get("package_id")
    stable_id = package_keys.get(package_id, package_id)
    if reason == "compiler-artifact":
        executable = value.get("executable")
        filenames = [_admitted_artifact_path(root, target_root, item) for item in value["filenames"]]
        return {
            "reason": reason,
            "package_id": stable_id,
            "target": {
                "name": value["target"]["name"],
                "kind": tuple(sorted(value["target"]["kind"])),
                "crate_types": tuple(sorted(value["target"]["crate_types"])),
                "edition": value["target"]["edition"],
            },
            "profile": {key: value["profile"][key] for key in sorted(_PROFILE_FIELDS)},
            "features": tuple(sorted(set(value["features"]))),
            "filenames": tuple(sorted(path.relative_to(target_root).as_posix() for path in filenames)),
            "executable": None if executable is None else _admitted_artifact_path(root, target_root, executable).relative_to(target_root).as_posix(),
        }
    if reason == "build-script-executed":
        out_dir = _admitted_build_directory(root, target_root, value["out_dir"])
        env_records = []
        for item in value["env"]:
            if isinstance(item, list) and len(item) == 2:
                key, env_value = item
            else:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo build-script environment record is invalid")
            if not isinstance(key, str) or not isinstance(env_value, str):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo build-script environment text is invalid")
            # This canonical preimage is retained only as an internal digest
            # input; raw build-script values never enter the emitted header.
            env_records.append((key, env_value))
        return {
            "reason": reason,
            "package_id": stable_id,
            "linked_libs": tuple(value["linked_libs"]),
            "linked_paths": tuple(value["linked_paths"]),
            "cfgs": tuple(sorted(value["cfgs"])),
            "env": tuple(env_records),
            "out_dir": out_dir.relative_to(target_root).as_posix(),
        }
    raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo message cannot contribute to the build identity")


def _validate_message_manifest(
    package_id: str,
    manifest_path: Any,
    metadata: dict[str, Any] | None,
    targets: Sequence[PackageTarget],
) -> None:
    if not isinstance(manifest_path, str) or not Path(manifest_path).is_absolute():
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo message manifest path is invalid")
    expected: Path | None = None
    if metadata is not None:
        for package in metadata["packages"]:
            if package["id"] == package_id:
                expected = Path(package["manifest_path"])
                break
    else:
        expected_target = next((item for item in targets if item.package_id == package_id), None)
        if expected_target is not None:
            expected = expected_target.manifest_dir / "Cargo.toml"
    if expected is None:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo message package manifest is absent from metadata")
    try:
        if Path(manifest_path).resolve(strict=True) != expected.resolve(strict=True):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo message manifest differs from package metadata")
    except OSError as exc:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo message manifest path is unreadable") from exc


def _collect_test_artifacts(
    root: Path,
    runner: Any = None,
    *,
    targets: Sequence[PackageTarget] = (),
    metadata: dict[str, Any] | None = None,
    test_profile_context_out: list[dict[tuple[str, str, str], bool]] | None = None,
    build_finished_success_out: list[bool] | None = None,
    deadline: float | None = None,
) -> tuple[list[Artifact], str]:
    target_root = _admitted_target_root(root)
    result = _run_cmd(
        runner,
        root,
        _CARGO_BUILD_ARGV,
        deadline=deadline,
        admitted_target_root=target_root,
    )
    if not result.stdout or not result.stdout.endswith(b"\n"):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo JSON stream is empty or truncated")
    metadata_index = _metadata_target_index(metadata)
    workspace_ids = set(metadata.get("workspace_members", [])) if metadata is not None else {item.package_id for item in targets}
    package_keys: dict[str, str] = {}
    package_names: dict[str, str] = {}
    if metadata is not None:
        for package in metadata["packages"]:
            package_id = package["id"]
            package_keys[package_id] = _metadata_package_identity(root, package)
            package_names[package_id] = package["name"]
    else:
        package_keys = {item.package_id: item.package_id for item in targets}
        package_names = {item.package_id: item.package_name for item in targets}
    artifacts: list[Artifact] = []
    build_hashes: list[str] = []
    artifact_messages: set[str] = set()
    test_profile_context: dict[tuple[str, str, str], bool] = {}
    terminal_seen = False
    for raw_line in result.stdout.splitlines():
        if deadline is not None and time.monotonic() >= deadline:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "inventory deadline expired while parsing Cargo output")
        if not raw_line:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo JSON stream contains a blank line")
        try:
            value = _closed_json_object(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo JSON stream contains a malformed message") from exc
        reason = value.get("reason")
        if not isinstance(reason, str) or reason not in _CARGO_MESSAGE_REASONS or terminal_seen:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo JSON stream contains unclassified output or data after completion")
        if reason == "build-finished":
            if set(value) != {"reason", "success"} or not isinstance(value["success"], bool) or not value["success"]:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo build-finished message is malformed or unsuccessful")
            terminal_seen = True
            continue
        if reason == "compiler-artifact":
            required = {"reason", "package_id", "manifest_path", "target", "profile", "features", "filenames", "executable", "fresh"}
            if set(value) != required:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo compiler-artifact schema is not recognized")
            package_id = value["package_id"]
            if not isinstance(package_id, str) or package_id not in package_keys and metadata is not None:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo compiler-artifact package identity is invalid")
            _validate_message_manifest(package_id, value["manifest_path"], metadata, targets)
            key = _match_cargo_target(root, package_id, value["target"], metadata_index, require_metadata_match=metadata is not None)
            profile = value["profile"]
            if not isinstance(profile, dict) or set(profile) != _PROFILE_FIELDS:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo compiler-artifact profile schema is not recognized")
            debuginfo = profile["debuginfo"]
            valid_debuginfo = (
                debuginfo is None
                or (isinstance(debuginfo, int) and not isinstance(debuginfo, bool) and debuginfo in {0, 1, 2})
                or (isinstance(debuginfo, str) and debuginfo in {"line-directives-only", "line-tables-only"})
            )
            if not isinstance(profile["opt_level"], str) or not valid_debuginfo:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo compiler-artifact profile values are invalid")
            if not all(isinstance(profile[field], bool) for field in ("debug_assertions", "overflow_checks", "test")):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo compiler-artifact profile flags are invalid")
            if package_id in workspace_ids:
                previous = test_profile_context.get(key)
                test_profile_context[key] = profile["test"] if previous is None else previous or profile["test"]
            features = value["features"]
            filenames = value["filenames"]
            executable = value["executable"]
            if not isinstance(features, list) or not all(isinstance(item, str) for item in features) or len(set(features)) != len(features):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo compiler-artifact features are invalid")
            if not isinstance(filenames, list) or not filenames or not all(isinstance(item, str) for item in filenames) or len(set(filenames)) != len(filenames):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo compiler-artifact filenames are invalid")
            if executable is not None and not isinstance(executable, str):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo compiler-artifact executable is invalid")
            if profile["test"] and executable is None:
                raise InventoryError(
                    "COMPILED_GRAPH_UNAVAILABLE",
                    "Cargo test-profile artifact has no executable",
                )
            if not isinstance(value["fresh"], bool):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo compiler-artifact freshness is invalid")
            canonical = _canonical_cargo_build_record(root, target_root, value, package_keys)
            message_hash = _sha256(_canonical_bytes(canonical))
            if message_hash in artifact_messages:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo JSON stream repeats a compiler-artifact message")
            artifact_messages.add(message_hash)
            build_hashes.append(message_hash)
            for filename in filenames:
                _admitted_artifact_path(root, target_root, filename)
            filename_paths = tuple(_admitted_artifact_path(root, target_root, item) for item in filenames)
            executable_path = None if executable is None else _admitted_artifact_path(root, target_root, executable)
            if executable_path is not None and executable_path not in filename_paths:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo executable is not one of its artifact filenames")
            if profile["test"] and executable is not None and (metadata is None and not targets or package_id in workspace_ids):
                assert executable_path is not None
                identity, digest = _observe_executable(root, target_root, executable_path, deadline=deadline)
                artifacts.append(
                    Artifact(
                        package_id=package_id,
                        target_name=key[2],
                        target_kind=key[1],
                        executable=executable_path,
                        profile={field: profile[field] for field in sorted(_PROFILE_FIELDS)},
                        features=tuple(sorted(features)),
                        filenames=tuple(sorted(filename_paths, key=lambda item: item.relative_to(target_root).as_posix())),
                        file_identity=identity,
                        executable_sha256=digest,
                        target_root=Path(os.path.abspath(target_root)),
                    )
                )
                if len(artifacts) > BOUNDS.max_test_binaries:
                    raise InventoryError("TEST_BINARY_LIMIT", "compiled test binary denominator exceeds bound")
        elif reason == "compiler-message":
            if set(value) != {"reason", "package_id", "manifest_path", "target", "message"} or not isinstance(value["package_id"], str):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo compiler-message schema is not recognized")
            _validate_message_manifest(value["package_id"], value["manifest_path"], metadata, targets)
            _match_cargo_target(root, value["package_id"], value["target"], metadata_index, require_metadata_match=metadata is not None)
            _validate_compiler_diagnostic(value["message"])
        elif reason == "build-script-executed":
            required = {"reason", "package_id", "linked_libs", "linked_paths", "cfgs", "env", "out_dir"}
            if set(value) != required or not isinstance(value["package_id"], str):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo build-script-executed schema is not recognized")
            if metadata is not None and value["package_id"] not in package_keys:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo build-script package is absent from metadata")
            if not all(isinstance(value[key], list) and all(isinstance(item, str) for item in value[key]) for key in ("linked_libs", "linked_paths", "cfgs")):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo build-script outputs are invalid")
            if not isinstance(value["env"], list) or not isinstance(value["out_dir"], str):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo build-script environment or output directory is invalid")
            canonical = _canonical_cargo_build_record(root, target_root, value, package_keys)
            build_hashes.append(_sha256(_canonical_bytes(canonical)))
        else:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo JSON reason is not classified")
    if not terminal_seen:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "Cargo JSON stream lacks a successful build-finished sentinel")
    if build_finished_success_out is not None:
        build_finished_success_out.append(True)
    artifacts.sort(key=lambda item: (item.package_id, item.target_kind, item.target_name, item.executable.relative_to(target_root).as_posix()))
    if test_profile_context_out is not None:
        test_profile_context_out.append(test_profile_context)
    return artifacts, _sha256(_canonical_bytes(sorted(build_hashes)))


def discover_compiled(
    root: Path,
    targets: Sequence[PackageTarget],
    runner: Any = None,
    *,
    metadata: dict[str, Any] | None = None,
    artifact_denominator_records: list[dict[str, Any]] | None = None,
    build_sha256_out: list[str] | None = None,
    compiled_graph_complete_out: list[bool] | None = None,
    test_profile_context_out: list[dict[tuple[str, str, str], bool]] | None = None,
    build_finished_success_out: list[bool] | None = None,
    deadline: float | None = None,
) -> list[CompiledTest]:
    target_map: dict[tuple[str, str, str], PackageTarget] = {}
    for item in targets:
        key = (item.package_id, item.target_kind, item.target_name)
        if key in target_map:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "metadata target denominator contains a duplicate target")
        target_map[key] = item
    result: list[CompiledTest] = []
    artifacts, build_sha256 = _collect_test_artifacts(
        root, runner=runner, targets=targets, metadata=metadata,
        test_profile_context_out=test_profile_context_out,
        build_finished_success_out=build_finished_success_out, deadline=deadline
    )
    if build_sha256_out is not None:
        build_sha256_out.append(build_sha256)
    graph_complete = all(item.required_features_satisfied is True for item in targets)
    covered = {(item.package_id, item.target_kind, item.target_name) for item in artifacts}
    missing = sorted(
        f"{target.package_id} [{target.target_kind}] {target.target_name}"
        for target in targets
        if _target_disposition(target) == "test_enabled"
        and target.required_features_satisfied is True
        and (target.package_id, target.target_kind, target.target_name) not in covered
    )
    if missing:
        raise InventoryError(
            "COMPILED_GRAPH_UNAVAILABLE",
            _redact_detail("declared test targets produced no test executable: " + "; ".join(missing)),
        )
    artifact_records: list[dict[str, Any]] = []
    for artifact in artifacts:
        target = target_map.get((artifact.package_id, artifact.target_kind, artifact.target_name))
        if target is None:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "compiled artifact has no workspace metadata target")
        target_root = artifact.target_root
        if target_root is None:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "compiled artifact lost its admitted target-root binding")
        identity_before, digest_before = _observe_executable(root, target_root, artifact.executable, deadline=deadline)
        if identity_before != artifact.file_identity or digest_before != artifact.executable_sha256:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "compiled executable changed after Cargo artifact admission")
        listing = _run_cmd(
            runner,
            root,
            (str(artifact.executable), *_LIBTEST_LIST_ARGS),
            deadline=deadline,
            admitted_executable=artifact.executable,
            admitted_target_root=target_root,
            admitted_artifact=artifact,
        )
        if listing.stdout and not listing.stdout.endswith(b"\n"):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "truncated ignored-test listing")
        try:
            text = listing.stdout.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "ignored-test listing encoding is invalid") from exc
        ignored_names: list[str] = []
        lines = text[:-1].split("\n") if text else []
        for line in lines:
            match = re.fullmatch(r"(.+): (test|benchmark)", line)
            if match is None:
                raise InventoryError(
                    "COMPILED_GRAPH_UNAVAILABLE",
                    _redact_detail(f"unparseable test listing line: {line[:200]}"),
                )
            name, test_type = match.groups()
            if (
                not name
                or name[0].isspace()
                or name[-1].isspace()
                or any(ord(char) < 32 or ord(char) == 127 for char in name)
            ):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "compiled test name is invalid")
            ignored_names.append(name)
            if len(set(ignored_names)) != len(ignored_names):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "ignored-test listing contains a duplicate name")
            result.append(
                CompiledTest(
                    package_id=artifact.package_id,
                    package_name=target.package_name,
                    target_name=artifact.target_name,
                    target_kind=artifact.target_kind,
                    executable=artifact.executable.relative_to(target_root).as_posix(),
                    executable_digest=artifact.executable_sha256,
                    test_name=name,
                )
            )
            if len(result) > BOUNDS.max_compiled_tests:
                raise InventoryError("COMPILED_TEST_LIMIT", "compiled ignored-test denominator exceeds bound")
        identity_after, digest_after = _observe_executable(root, target_root, artifact.executable, deadline=deadline)
        if identity_after != artifact.file_identity or digest_after != artifact.executable_sha256:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "compiled executable identity changed during listing")
        artifact_records.append(
            {
                "package_id": artifact.package_id,
                "package_name": target.package_name,
                "target_name": artifact.target_name,
                "target_kind": artifact.target_kind,
                "profile": artifact.profile,
                "features": artifact.features,
                "filenames": tuple(sorted(path.relative_to(target_root).as_posix() for path in artifact.filenames)),
                "executable": artifact.executable.relative_to(target_root).as_posix(),
                "file_identity": artifact.file_identity,
                "sha256": artifact.executable_sha256,
                "ignored_test_count": len(ignored_names),
            }
        )
    artifact_records.sort(key=lambda item: (item["package_id"], item["target_kind"], item["target_name"], item["executable"], item["features"]))
    if artifact_denominator_records is not None:
        artifact_denominator_records.extend(artifact_records)
    if compiled_graph_complete_out is not None:
        compiled_graph_complete_out.append(graph_complete)
    return sorted(result, key=lambda item: item.identity() + (item.executable,))


def _row(source: SourceTest | None, compiled: CompiledTest | None, state: RowState, owner: str) -> InventoryRow:
    item = source or compiled
    assert item is not None
    payload = {
        "state": state.value,
        "package_id": item.package_id,
        "package_name": item.package_name,
        "target_name": item.target_name,
        "target_kind": item.target_kind,
        "test_name": item.test_name,
        "source_path": source.source_path if source else None,
        "source_line": source.line if source else None,
        "source_digest": source.source_digest if source else None,
        "attribute_text": source.attribute_text if source else None,
        "attribute_digest": source.attribute_digest if source else None,
        "ignore_reason": source.reason if source else None,
        "cfg_evidence": source.cfg_evidence if source else (),
        "requirements": source.requirements if source else (Requirement.UNKNOWN.value,),
        "isolation": source.isolation if source else (),
        "fn_span": source.fn_span if source else None,
        "attribute_span": source.attribute_span if source else None,
        "executable": compiled.executable if compiled else None,
        "executable_digest": compiled.executable_digest if compiled else None,
        "remediation_owner": owner,
    }
    return InventoryRow(**payload, row_digest=_sha256(_canonical_bytes(payload)))


def reconcile(source: Sequence[SourceTest], compiled: Sequence[CompiledTest]) -> list[InventoryRow]:
    source_map: dict[tuple[str, str, str, str], list[SourceTest]] = {}
    compiled_map: dict[tuple[str, str, str, str], list[CompiledTest]] = {}
    for item in source:
        source_map.setdefault(item.identity(), []).append(item)
    for item in compiled:
        compiled_map.setdefault(item.identity(), []).append(item)
    rows: list[InventoryRow] = []
    for identity in sorted(set(source_map) | set(compiled_map)):
        sources = source_map.get(identity, [])
        binaries = compiled_map.get(identity, [])
        if len(sources) > 1 or len(binaries) > 1:
            for source_item in sources or [None]:
                for compiled_item in binaries or [None]:
                    rows.append(_row(source_item, compiled_item, RowState.DUPLICATE, "test-source-owner"))
            continue
        source_item = sources[0] if sources else None
        compiled_item = binaries[0] if binaries else None
        if source_item is None:
            rows.append(_row(None, compiled_item, RowState.COMPILED_ONLY, "build-test-graph-owner"))
        elif compiled_item is None:
            rows.append(_row(source_item, None, RowState.SOURCE_ONLY, "test-target-owner"))
        elif source_item.reason is None or Requirement.UNKNOWN.value in source_item.requirements:
            rows.append(_row(source_item, compiled_item, RowState.UNCLASSIFIED, "test-declaration-owner"))
        else:
            rows.append(_row(source_item, compiled_item, RowState.CLASSIFIED, "declared-environment-owner"))
    return sorted(rows, key=lambda item: (item.package_id, item.target_kind, item.target_name, item.test_name, item.row_digest))


_TOOLCHAIN_CHANNEL: Final = re.compile(r'(?m)^\s*channel\s*=\s*"([^"\n]+)"')


def _toolchain_identity(
    root: Path, runner: Any = None, *, deadline: float | None = None
) -> dict[str, Any]:
    """Bind the pinned rustc file and full compiler verbose identity."""
    channel: str | None = None
    toolchain_file_sha256: str | None = None
    try:
        pin_file = root / "rust-toolchain.toml"
        if pin_file.is_file():
            raw = _bounded_read(pin_file)
            toolchain_file_sha256 = _sha256(raw)
            match = _TOOLCHAIN_CHANNEL.search(raw.decode("utf-8", errors="replace"))
            if match is not None:
                channel = match.group(1)[:128]
            if not channel or channel.casefold() in {"unknown", "none"}:
                channel = None
    except (OSError, InventoryError):
        channel = None
        toolchain_file_sha256 = None
    rustc_version: str | None = None
    release: str | None = None
    host: str | None = None
    commit_hash: str | None = None
    rustc_verbose_sha256: str | None = None
    try:
        probe = _run_cmd(runner, root, ("rustc", "--version", "--verbose"), deadline=deadline)
        lines = probe.stdout.decode("utf-8", errors="strict").splitlines()
        if not lines:
            raise InventoryError("SOURCE_IDENTITY_INVALID", "rustc verbose identity has no version line")
        version_match = re.fullmatch(r"rustc (\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?)(?: \([^()\r\n]+\))?", lines[0])
        if version_match is None:
            raise InventoryError("SOURCE_IDENTITY_INVALID", "rustc verbose identity has an unresolved version")
        rustc_version = lines[0][:256]
        fields: dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line:
                raise InventoryError("SOURCE_IDENTITY_INVALID", "rustc verbose identity contains an unclassified line")
            key, value = line.split(":", 1)
            key = key.strip()
            if not key or key in fields:
                raise InventoryError("SOURCE_IDENTITY_INVALID", "rustc verbose identity contains duplicate fields")
            fields[key] = value.strip()
        release = fields.get("release")
        host = fields.get("host")
        commit_hash = fields.get("commit-hash")
        if (
            not release
            or release != version_match.group(1)
            or not re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?", release)
            or not host
            or host.casefold() in {"unknown", "none"}
            or re.fullmatch(r"[A-Za-z0-9_]+-[A-Za-z0-9_.-]+", host) is None
            or not commit_hash
            or commit_hash.casefold() in {"unknown", "none"}
            or re.fullmatch(r"[0-9a-fA-F]{7,64}", commit_hash) is None
        ):
            raise InventoryError("SOURCE_IDENTITY_INVALID", "rustc verbose identity lacks release, host, or commit hash")
        numeric_channel = re.fullmatch(r"(\d+\.\d+\.\d+)(?:-(.+))?", channel or "")
        if numeric_channel is not None:
            pinned_version, suffix = numeric_channel.groups()
            expected_release = pinned_version if suffix == host else channel
            if release != expected_release:
                raise InventoryError("SOURCE_IDENTITY_INVALID", "resolved rustc release differs from the pinned numeric toolchain")
        rustc_verbose_sha256 = _sha256(probe.stdout)
    except Exception:
        rustc_version = None
        release = None
        host = None
        commit_hash = None
        rustc_verbose_sha256 = None
    return {
        "rustc_version": rustc_version,
        "release": release,
        "host": host,
        "commit_hash": commit_hash,
        "rustc_verbose_sha256": rustc_verbose_sha256,
        "channel": channel,
        "toolchain_file_sha256": toolchain_file_sha256,
    }


def _git_identity(
    root: Path, runner: Any = None, *, deadline: float | None = None
) -> dict[str, Any]:
    unknown = {
        "head": None,
        "tracked_tree_clean": None,
        "untracked_tree_clean": None,
        "working_tree_clean": None,
    }
    try:
        head = _run_cmd(runner, root, ("git", "rev-parse", "HEAD"), deadline=deadline).stdout.decode("ascii", errors="strict").strip()
        status = _run_cmd(
            runner, root, ("git", "status", "--porcelain=v1", "--untracked-files=all"), deadline=deadline
        ).stdout.decode("utf-8", errors="strict")
    except Exception:
        return unknown
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        return unknown
    lines = status.splitlines()
    if any(len(line) < 2 or line[0] == " " and line[1] == " " for line in lines):
        return unknown
    untracked = any(line.startswith("??") for line in lines)
    tracked = any(not line.startswith("??") for line in lines)
    return {
        "head": head,
        "tracked_tree_clean": not tracked,
        "untracked_tree_clean": not untracked,
        "working_tree_clean": not lines,
    }


def build_inventory(root: Path, runner: Any = None) -> dict[str, Any]:
    deadline = time.monotonic() + BOUNDS.command_timeout_seconds
    initial_git = _git_identity(root, runner=runner, deadline=deadline)
    initial_toolchain = _toolchain_identity(root, runner=runner, deadline=deadline)
    try:
        initial_lock = _sha256(_bounded_read(root / "Cargo.lock")) if (root / "Cargo.lock").is_file() else None
        initial_lock_read_ok = True
    except (OSError, InventoryError):
        initial_lock = None
        initial_lock_read_ok = False
    metadata = _cargo_metadata(root, runner=runner, deadline=deadline)
    targets = _targets(root, metadata)
    metadata_sha256 = _metadata_sha256(root, metadata)
    target_denominator = _target_denominator(root, targets)
    artifact_denominator: list[dict[str, Any]] = []
    build_sha256_out: list[str] = []
    compiled_graph_complete_out: list[bool] = []
    test_profile_context_out: list[dict[tuple[str, str, str], bool]] = []
    build_finished_success_out: list[bool] = []
    compiled = discover_compiled(
        root,
        targets,
        runner=runner,
        metadata=metadata,
        artifact_denominator_records=artifact_denominator,
        build_sha256_out=build_sha256_out,
        compiled_graph_complete_out=compiled_graph_complete_out,
        test_profile_context_out=test_profile_context_out,
        build_finished_success_out=build_finished_success_out,
        deadline=deadline,
    )
    source_denominator: list[dict[str, Any]] = []
    source_denominator_complete_out: list[bool] = []
    source = discover_source(
        root,
        targets,
        source_denominator_records=source_denominator,
        source_denominator_complete_out=source_denominator_complete_out,
        test_profile_context=test_profile_context_out[0] if test_profile_context_out else {},
        deadline=deadline,
    )
    source_complete = source_denominator_complete_out[0] if source_denominator_complete_out else True
    # Re-observe every source file after discovery and build/list work so a
    # replacement during the run cannot leave an apparently stable digest.
    rechecked: set[str] = set()
    for record in source_denominator:
        if record["resolution"] != "resolved" or record["sha256"] is None or not record["path"]:
            continue
        key = record["path"]
        if key in rechecked:
            continue
        rechecked.add(key)
        if time.monotonic() >= deadline:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "inventory deadline expired during final source identity check")
        path = root / record["path"]
        try:
            _, identity, digest = _observe_source_file(root, path, deadline)
        except InventoryError:
            identity, digest = None, None
        if identity != record.get("file_identity") or digest != record["sha256"]:
            source_complete = False
            source_denominator.append(
                {
                    "package_id": record["package_id"],
                    "package_name": record["package_name"],
                    "target_name": record["target_name"],
                    "target_kind": record["target_kind"],
                    "path": None,
                    "module_path": record["module_path"],
                    "sha256": None,
                    "file_identity": None,
                    "cfg_evidence": record["cfg_evidence"],
                    "resolution": "unresolved",
                    "declaration": "final source identity recheck",
                    "reason": "source_identity_changed",
                    "declaration_source_path": record["path"],
                    "declaration_source_sha256": record["sha256"],
                    "declaration_source_file_identity": record["file_identity"],
                }
            )
    source_denominator.sort(
        key=lambda item: (
            item["package_id"], item["target_kind"], item["target_name"],
            item["path"] or "", item["module_path"], item["resolution"], item["declaration"] or "",
            item.get("declaration_source_path") or "", item.get("declaration_source_sha256") or "",
        )
    )
    rows = reconcile(source, compiled)
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.state] = counts.get(row.state, 0) + 1
    denominator = [dataclasses.asdict(row) for row in rows]
    try:
        final_lock = _sha256(_bounded_read(root / "Cargo.lock")) if (root / "Cargo.lock").is_file() else None
        final_lock_read_ok = True
    except (OSError, InventoryError):
        final_lock = None
        final_lock_read_ok = False
    final_git = _git_identity(root, runner=runner, deadline=deadline)
    final_toolchain = _toolchain_identity(root, runner=runner, deadline=deadline)
    git_stable = initial_git == final_git and initial_git.get("head") is not None
    toolchain_stable = initial_toolchain == final_toolchain and initial_toolchain.get("rustc_verbose_sha256") is not None
    lock_stable = (
        initial_lock_read_ok and final_lock_read_ok
        and initial_lock is not None and final_lock is not None and initial_lock == final_lock
    )
    identity_complete = (
        git_stable
        and initial_git.get("working_tree_clean") is True
        and final_git.get("working_tree_clean") is True
        and toolchain_stable
        and initial_toolchain.get("channel") is not None
        and initial_toolchain.get("toolchain_file_sha256") is not None
        and lock_stable
    )
    source_identity = dict(final_git)
    source_identity.update(
        {
            "initial_head": initial_git.get("head"),
            "initial_tracked_tree_clean": initial_git.get("tracked_tree_clean"),
            "initial_untracked_tree_clean": initial_git.get("untracked_tree_clean"),
            "stable": git_stable,
        }
    )
    toolchain = dict(final_toolchain)
    toolchain["initial"] = initial_toolchain
    toolchain["stable"] = toolchain_stable
    source_build_sha256 = build_sha256_out[0] if build_sha256_out else _sha256(_canonical_bytes([]))
    build_finished_success = build_finished_success_out[0] if build_finished_success_out else False
    compiled_graph_complete = bool(compiled_graph_complete_out and compiled_graph_complete_out[0] and build_finished_success)
    row_classification_complete = all(row.state == RowState.CLASSIFIED.value for row in rows)
    target_denominator_sha256 = _sha256(_canonical_bytes(target_denominator))
    source_denominator_sha256 = _sha256(_canonical_bytes(source_denominator))
    artifact_denominator_sha256 = _sha256(_canonical_bytes(artifact_denominator))
    header = {
        "schema": SCHEMA,
        "tool_version": TOOL_VERSION,
        "toolchain": toolchain,
        "rule_table": {"version": RULE_TABLE_VERSION, "sha256": RULE_TABLE_SHA256},
        "source_identity": source_identity,
        "command_profile": {
            "metadata_argv": list(_CARGO_METADATA_ARGV),
            "build_argv": list(_CARGO_BUILD_ARGV),
            "libtest_list_suffix": list(_LIBTEST_LIST_ARGS),
            "target_root": Path(*_TARGET_ROOT_PARTS).as_posix(),
        },
        "cargo_build_finished_success": build_finished_success,
        "cargo_lock_sha256": final_lock,
        "metadata_sha256": metadata_sha256,
        "cargo_build_sha256": source_build_sha256,
        "target_denominator": target_denominator,
        "target_denominator_sha256": target_denominator_sha256,
        "source_denominator": source_denominator,
        "source_denominator_sha256": source_denominator_sha256,
        "artifact_denominator": artifact_denominator,
        "artifact_denominator_sha256": artifact_denominator_sha256,
        "source_count": len(source),
        "compiled_count": len(compiled),
        "row_count": len(rows),
        "counts_by_state": dict(sorted(counts.items())),
        "proof_ceiling": "IGNORED_TEST_IDENTITY_AND_ENVIRONMENT_CLASSIFICATION_ONLY",
        "source_denominator_complete": source_complete,
        "compiled_graph_complete": compiled_graph_complete,
        "identity_complete": identity_complete,
        "row_classification_complete": row_classification_complete,
        "row_classification_status": "complete" if row_classification_complete else "incomplete",
        "complete": source_complete and compiled_graph_complete and identity_complete and row_classification_complete,
        "duration_observation_ms": None,
    }
    aggregate_input = {"header": header, "rows": denominator}
    header["aggregate_sha256"] = _sha256(_canonical_bytes(aggregate_input))
    return {"header": header, "rows": denominator}


def self_test() -> None:
    """Run internal unit self-tests without requiring external tools or repository mutations."""
    import tempfile

    # 1. Canonical bytes deterministic sorting
    c1 = _canonical_bytes({"b": 1, "a": [2, 3]})
    c2 = _canonical_bytes({"a": [2, 3], "b": 1})
    assert c1 == c2, "canonical bytes must sort keys deterministically"
    assert _sha256(c1) == _sha256(c2)

    # 2. Command validation
    _validate_command(("cargo", "metadata", "--locked", "--format-version", "1"))
    _validate_command(("cargo", "test", "--workspace", "--all-targets", "--locked", "--no-run", "--message-format=json"))
    _validate_command(("git", "rev-parse", "HEAD"))
    _validate_command(("git", "status", "--porcelain=v1", "--untracked-files=all"))
    _validate_command(("rustc", "--version", "--verbose"))
    try:
        _validate_command(("target/debug/deps/test.exe", "--list", "--ignored", "--format", "terse"))
        assert False, "an arbitrary list executable must be rejected"
    except InventoryError as exc:
        assert exc.code == "COMMAND_NOT_ALLOWED"
    with tempfile.TemporaryDirectory() as td:
        admitted_root = Path(td).resolve()
        admitted_executable = _admitted_target_root(admitted_root) / "debug" / "deps" / "test.exe"
        admitted_executable.parent.mkdir(parents=True)
        admitted_executable.write_bytes(b"synthetic executable identity")
        _validate_command(
            (str(admitted_executable), "--list", "--ignored", "--format", "terse"),
            admitted_root,
            admitted_executable=admitted_executable,
        )
    try:
        _validate_command(("cargo", "run"))
        assert False, "arbitrary command must be rejected"
    except InventoryError as exc:
        assert exc.code == "COMMAND_NOT_ALLOWED"

    # 3. Attribute flags & reason decoding
    is_t, is_i, is_cfg, reason, cfg = _attribute_flags('#[test]\n#[ignore = "requires store database"]')
    assert is_t and is_i and not is_cfg and reason == "requires store database" and cfg is None

    is_t, is_i, is_cfg, reason, cfg = _attribute_flags('#[tokio::test]\n#[ignore = r#"requires "raw" host"#]')
    assert is_t and is_i and not is_cfg and reason == 'requires "raw" host' and cfg is None

    is_t, is_i, is_cfg, reason, cfg = _attribute_flags('#[disabled_test = "requires kernel"]')
    assert is_t and is_i and is_cfg and reason == "requires kernel"

    is_t, is_i, is_cfg, reason, cfg = _attribute_flags('#[cfg_attr(windows, ignore = "requires windows pipe")]')
    assert not is_t and is_i and is_cfg and reason == "requires windows pipe" and cfg is not None

    # 4. Reason unescaping
    assert _decode_reason(r'#[ignore = "foo \"bar\" baz"]') == 'foo "bar" baz'
    assert _decode_reason(r'#[ignore = r#"raw "quotes" inside"#]') == 'raw "quotes" inside'

    # 5. Requirements mapping and composition
    assert _requirements("requires local authenticated surrealdb") == (Requirement.STORE.value,)
    assert _requirements("governor host runtime") == (Requirement.RUNTIME.value,)
    assert _requirements("windows pipe acl session") == (Requirement.RUNTIME.value,)
    assert _requirements("git repository worktree") == (Requirement.GIT.value,)
    assert _requirements("external personal credential api key") == (Requirement.EXTERNAL_CREDENTIALED_MANUAL_ONLY.value,)
    assert _requirements("requires local surrealdb and governor runtime") == (Requirement.RUNTIME.value, Requirement.STORE.value)
    assert _requirements("just a random test failure") == (Requirement.UNKNOWN.value,)

    # 6. Safe output validation
    with tempfile.TemporaryDirectory() as td:
        troot = Path(td).resolve()
        (troot / ".eliot").mkdir()
        safe_candidate = troot / ".eliot" / "sub" / "inventory.json"
        assert _safe_output(troot, safe_candidate) == safe_candidate

        try:
            _safe_output(troot, troot / "unsafe.json")
            assert False, "output outside .eliot must fail"
        except InventoryError as exc:
            assert exc.code == "UNSAFE_OUTPUT"

        existing = troot / ".eliot" / "existing.json"
        existing.write_bytes(b"{}")
        try:
            _safe_output(troot, existing, overwrite=False)
            assert False, "existing output without overwrite must fail"
        except InventoryError as exc:
            assert exc.code == "OUTPUT_EXISTS"
        assert _safe_output(troot, existing, overwrite=True) == existing

    # 7. Reconciliation state logic
    s1 = SourceTest("p1", "pname", "tname", "lib", "test_one", "src/lib.rs", 10, "#[test]", "h1", "requires store", (), ("STORE",), "sd1")
    c1 = CompiledTest("p1", "pname", "tname", "lib", "bin/test.exe", "ed1", "test_one")
    rows = reconcile([s1], [c1])
    assert len(rows) == 1 and rows[0].state == RowState.CLASSIFIED.value and rows[0].remediation_owner == "declared-environment-owner"

    rows_s = reconcile([s1], [])
    assert len(rows_s) == 1 and rows_s[0].state == RowState.SOURCE_ONLY.value and rows_s[0].remediation_owner == "test-target-owner"

    rows_c = reconcile([], [c1])
    assert len(rows_c) == 1 and rows_c[0].state == RowState.COMPILED_ONLY.value and rows_c[0].remediation_owner == "build-test-graph-owner"

    s_dup = SourceTest("p1", "pname", "tname", "lib", "test_one", "src/lib.rs", 20, "#[test]", "h2", "requires store", (), ("STORE",), "sd2")
    rows_dup = reconcile([s1, s_dup], [c1])
    assert all(r.state == RowState.DUPLICATE.value for r in rows_dup)


def run_self_tests() -> int:
    try:
        self_test()
    except Exception as exc:
        print(f"FAIL: ignored_test_inventory self-tests failed: {exc}", file=sys.stderr)
        return 1
    print("PASS: ignored_test_inventory self-tests passed")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=None, help="Path to repository root")
    parser.add_argument("--output", type=Path, default=None, help="Path to output JSON file (must be under .eliot)")
    parser.add_argument("--overwrite", action="store_true", help="Allow overwriting existing output")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-tests and exit")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.self_test:
        return run_self_tests()
    if args.repo_root is None or args.output is None:
        print(
            json.dumps(
                {"status": "error", "code": "INVALID_ARGUMENTS", "detail": "--repo-root and --output are required when not running --self-test"},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    try:
        root = args.repo_root.resolve(strict=True)
    except OSError:
        print(
            json.dumps(
                {"status": "error", "code": "INVALID_REPOSITORY_ROOT", "detail": "repository root is not accessible"},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    try:
        output = _safe_output(root, args.output, overwrite=args.overwrite)
        inventory = build_inventory(root)
        output.parent.mkdir(parents=True, exist_ok=True)
        if args.overwrite and output.exists():
            output.unlink()
        with output.open("xb") as handle:
            handle.write(_canonical_bytes(inventory))
            handle.write(b"\n")
    except InventoryError as exc:
        payload = {"status": "error", "code": exc.code, "detail": exc.detail}
        if hasattr(exc, "owner") and exc.owner:
            payload["owner"] = exc.owner
        print(json.dumps(payload, sort_keys=True), file=sys.stderr)
        return 2
    except OSError:
        print(
            json.dumps(
                {
                    "status": "error",
                    "code": "OUTPUT_WRITE_FAILED",
                    "detail": "failed to write inventory output",
                    "owner": "build-test-graph-owner",
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            {
                "status": "ok",
                "output": str(output),
                "rows": inventory["header"]["row_count"],
                "complete": inventory["header"]["complete"],
                "aggregate_sha256": inventory["header"]["aggregate_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0 if inventory["header"]["complete"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
