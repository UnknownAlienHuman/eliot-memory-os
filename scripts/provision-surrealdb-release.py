#!/usr/bin/env python3
"""Materialize the pinned SurrealDB evidence into project-local ignored state.

This command never writes the shared C:\\Tools installation. It downloads the
official release/source/tag and OSV snapshots selected by the tracked policy.
The selected-candidate OSV response is fetched on every invocation so a release
receipt can bind a fresh query to its exact response bytes. The verifier checks
the PE, source-tree, tag, and advisory bindings.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import os
import stat
import tempfile
import tomllib
from urllib.request import Request, urlopen


OFFICIAL_REPOSITORY = "https://github.com/surrealdb/surrealdb"
GITHUB_API_REPOSITORY = "https://api.github.com/repos/surrealdb/surrealdb"
OSV_ENDPOINT = "https://api.osv.dev/v1/query"
REPARSE_POINT = 0x400


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _path_identity(stat_result: os.stat_result) -> tuple[object, ...]:
    return (
        getattr(stat_result, "st_dev", None),
        getattr(stat_result, "st_ino", None),
        getattr(stat_result, "st_size", None),
        getattr(stat_result, "st_mtime_ns", None),
    )


def _relative_path(raw: object) -> Path:
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("local path is missing")
    relative = Path(raw)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"local path escapes repository: {raw}")
    normalized = str(relative).replace("\\", "/")
    if not normalized.startswith(".eliot/dependency-policy/surrealdb/"):
        raise ValueError(f"local path is outside the project-local evidence root: {raw}")
    return Path(normalized)


def _validate_components(root: Path, relative: Path) -> Path:
    root_resolved = root.resolve(strict=True)
    current = root_resolved
    parts = relative.parts
    for index, component in enumerate(parts):
        current = current / component
        try:
            stat_result = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise RuntimeError(f"cannot inspect project-local path component {current}: {exc}") from exc
        attributes = getattr(stat_result, "st_file_attributes", 0)
        if current.is_symlink() or attributes & REPARSE_POINT:
            raise RuntimeError(f"project-local path contains a symlink or reparse component: {current}")
        if index < len(parts) - 1 and not current.is_dir():
            raise RuntimeError(f"project-local path component is not a directory: {current}")
    try:
        resolved = (root_resolved / relative).resolve(strict=False)
        resolved.relative_to(root_resolved)
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"project-local path escapes repository: {relative}") from exc
    return resolved


def safe_local_path(root: Path, raw: object) -> tuple[Path, str]:
    relative = _relative_path(raw)
    return _validate_components(root, relative), str(relative).replace("\\", "/")


def _open_nofollow(path: Path) -> int:
    if os.name == "nt":
        import ctypes
        import msvcrt

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        kernel32.CreateFileW.restype = ctypes.c_void_p
        handle = kernel32.CreateFileW(
            str(path),
            0x80000000,
            0x00000001 | 0x00000002,
            None,
            3,
            0x00000080 | 0x00200000,
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if handle == invalid:
            error = ctypes.get_last_error()
            raise OSError(error, f"CreateFileW failed for {path}")
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | getattr(os, "O_BINARY", 0))

    return os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))


def _open_directory_nofollow(path: Path) -> int:
    if os.name == "nt":
        import ctypes
        import msvcrt

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        kernel32.CreateFileW.restype = ctypes.c_void_p
        handle = kernel32.CreateFileW(
            str(path),
            0x80000000,  # GENERIC_READ
            0x00000001 | 0x00000002,  # share read/write; deny delete/rename
            None,
            3,  # OPEN_EXISTING
            0x02000000 | 0x00200000,  # FILE_FLAG_BACKUP_SEMANTICS | OPEN_REPARSE_POINT
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if handle == invalid:
            error = ctypes.get_last_error()
            raise OSError(error, f"CreateFileW failed for directory {path}")
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    else:
        fd = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    try:
        stat_result = os.fstat(fd)
        if not stat.S_ISDIR(stat_result.st_mode) or getattr(stat_result, "st_file_attributes", 0) & REPARSE_POINT:
            raise RuntimeError(f"project-local parent is not a resident directory: {path}")
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_local(root: Path, raw: object) -> tuple[Path, str, bytes]:
    path, relative = safe_local_path(root, raw)
    if not path.is_file():
        raise RuntimeError(f"project-local evidence is not a regular file: {relative}")
    fd: int | None = None
    try:
        fd = _open_nofollow(path)
        before = os.fstat(fd)
        if getattr(before, "st_file_attributes", 0) & REPARSE_POINT:
            raise RuntimeError(f"project-local evidence is a reparse point: {relative}")
        chunks: list[bytes] = []
        while chunk := os.read(fd, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(fd)
    finally:
        if fd is not None:
            os.close(fd)
    if _path_identity(before) != _path_identity(after):
        raise RuntimeError(f"project-local evidence changed while being read: {relative}")
    if getattr(after, "st_file_attributes", 0) & REPARSE_POINT:
        raise RuntimeError(f"project-local evidence became a reparse point while being read: {relative}")
    revalidated, revalidated_relative = safe_local_path(root, raw)
    if revalidated_relative != relative or _path_identity(after) != _path_identity(revalidated.stat()):
        raise RuntimeError(f"project-local evidence path identity changed during read: {relative}")
    return revalidated, relative, b"".join(chunks)


@contextmanager
def _held_parent_directories(root: Path, relative: Path):
    """Hold every parent directory without delete sharing during a write."""

    root_resolved = root.resolve(strict=True)
    handles: list[int] = []
    current = root_resolved
    try:
        handles.append(_open_directory_nofollow(root_resolved))
        for component in relative.parts[:-1]:
            current = current / component
            try:
                current.lstat()
            except FileNotFoundError:
                current.mkdir()
            handles.append(_open_directory_nofollow(current))
        _validate_components(root, relative)
        yield
    finally:
        for fd in reversed(handles):
            try:
                os.close(fd)
            except OSError:
                pass


def materialize(
    root: Path,
    raw_path: object,
    payload: bytes,
    expected_sha256: str | None = None,
    replace_existing: bool = False,
) -> dict:
    relative = _relative_path(raw_path)
    actual = sha256_bytes(payload)
    if expected_sha256 and actual != expected_sha256.lower():
        raise RuntimeError(f"downloaded bytes for {relative} have SHA-256 {actual}, expected {expected_sha256}")

    with _held_parent_directories(root, relative):
        path, relative_text = safe_local_path(root, raw_path)
        reused = False
        if path.exists():
            _, _, existing = read_local(root, raw_path)
            existing_sha = sha256_bytes(existing)
            if existing_sha != actual and not replace_existing:
                raise RuntimeError(f"refusing to replace existing project-local evidence {path}: {existing_sha} != {actual}")
            if existing_sha == actual:
                payload = existing
                reused = True
            else:
                replace_existing = True
        else:
            replace_existing = True
        if replace_existing:
            fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                _validate_components(root, relative)
                os.replace(temporary_name, path)
            finally:
                if os.path.exists(temporary_name):
                    os.unlink(temporary_name)
            _, verified_relative, verified_payload = read_local(root, raw_path)
            if verified_relative != relative_text or sha256_bytes(verified_payload) != actual or len(verified_payload) != len(payload):
                raise RuntimeError(f"project-local write failed identity or byte revalidation: {relative_text}")
        return {"path": relative_text, "relative_path": relative_text, "bytes": len(payload), "sha256": actual, "reused": reused}


def fetch(url: str, *, data: bytes | None = None, accept: str = "application/octet-stream") -> bytes:
    request = Request(
        url,
        data=data,
        headers={"Accept": accept, "User-Agent": "eliot-dependency-policy-provisioner"},
        method="POST" if data is not None else "GET",
    )
    with urlopen(request, timeout=120) as response:
        return response.read()


def url_for_tag(tag: str) -> str:
    return f"{GITHUB_API_REPOSITORY}/git/ref/tags/{tag}"


def url_for_release(tag: str) -> str:
    return f"{GITHUB_API_REPOSITORY}/releases/tags/{tag}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    manifest = tomllib.loads((root / "config" / "dependency-policy.toml").read_text(encoding="utf-8"))
    surreal = manifest["external_executables"]["surrealdb"]
    evidence = surreal["distributed_binary_evidence"]
    candidate = surreal["patched_candidate"]
    records: list[dict] = []

    def require_canonical(configured: object, expected: str, label: str) -> None:
        if configured != expected:
            raise RuntimeError(f"{label} is not the derived official URL: {configured!r}")

    def fetch_to(
        raw_path: object,
        url: str,
        subject: str,
        expected: str | None = None,
        expected_bytes: int | None = None,
    ) -> None:
        _, relative = safe_local_path(root, raw_path)
        try:
            _, _, payload = read_local(root, raw_path)
        except RuntimeError as exc:
            if "not a regular file" not in str(exc) or _validate_components(root, _relative_path(raw_path)).exists():
                raise
            payload = fetch(url)
            materialized = materialize(root, raw_path, payload, expected)
            relative = materialized["relative_path"]
            reused = False
        else:
            actual = sha256_bytes(payload)
            if expected and actual != expected.lower():
                raise RuntimeError(f"existing bytes for {relative} have SHA-256 {actual}, expected {expected}")
            reused = True
        actual = sha256_bytes(payload)
        if expected and actual != expected.lower():
            raise RuntimeError(f"downloaded bytes for {relative} have SHA-256 {actual}, expected {expected}")
        if expected_bytes is not None and len(payload) != expected_bytes:
            raise RuntimeError(f"bytes for {relative} have length {len(payload)}, expected {expected_bytes}")
        records.append(
            {
                "subject": subject,
                "url": url,
                "path": relative,
                "relative_path": relative,
                "reused": reused,
                "bytes": len(payload),
                "sha256": actual,
                "expected_sha256": expected.lower() if expected else None,
                "expected_bytes": expected_bytes,
            }
        )

    candidate_tag = candidate["source_tag"]
    candidate_version = candidate["version"]
    require_canonical(candidate["release_source"], f"{OFFICIAL_REPOSITORY}/releases/tag/{candidate_tag}", "candidate release_source")
    candidate_asset = f"{OFFICIAL_REPOSITORY}/releases/download/{candidate_tag}/surreal-{candidate_tag}.windows-amd64.exe"
    require_canonical(candidate["release_asset"], candidate_asset, "candidate release_asset")
    require_canonical(surreal["advisory_source"], OSV_ENDPOINT, "advisory_source")
    if (
        candidate.get("advisory_package") != "surrealdb"
        or candidate.get("advisory_ecosystem") != "crates.io"
        or candidate.get("advisory_scope") != "rust-crate"
        or not isinstance(candidate.get("advisory_max_age_hours"), int)
        or isinstance(candidate.get("advisory_max_age_hours"), bool)
        or candidate["advisory_max_age_hours"] <= 0
    ):
        raise RuntimeError("candidate OSV scope and freshness policy are not canonical")
    if (
        candidate.get("advisory_query_path") == surreal.get("advisory_query_path")
        or candidate.get("advisory_response_path") == surreal.get("advisory_response_path")
    ):
        raise RuntimeError("candidate OSV evidence must be separate from the installed-version snapshot")
    old_tag = evidence["source_tag"]
    old_version = surreal["version"]
    require_canonical(surreal["release_source"], f"{OFFICIAL_REPOSITORY}/releases/tag/{old_tag}", "installed release_source")
    require_canonical(surreal["release_asset"], f"{OFFICIAL_REPOSITORY}/releases/download/{old_tag}/surreal-{old_tag}.windows-amd64.exe", "installed release_asset")

    fetch_to(
        candidate["artifact_path"],
        candidate_asset,
        f"surrealdb.release-asset.{candidate_tag}",
        candidate["sha256"],
        candidate["artifact_size"],
    )
    fetch_to(
        candidate["source_archive_path"],
        f"{OFFICIAL_REPOSITORY}/archive/refs/tags/{candidate_tag}.tar.gz",
        f"surrealdb.source-archive.{candidate_tag}",
        candidate["source_archive_sha256"],
    )
    fetch_to(
        candidate["release_metadata_path"],
        url_for_release(candidate_tag),
        f"surrealdb.release-metadata.{candidate_tag}",
    )
    fetch_to(
        candidate["source_tag_ref_path"],
        url_for_tag(candidate_tag),
        f"surrealdb.tag-ref.{candidate_tag}",
    )
    fetch_to(
        evidence["source_archive_path"],
        f"{OFFICIAL_REPOSITORY}/archive/refs/tags/{old_tag}.tar.gz",
        f"surrealdb.source-archive.{old_tag}",
        evidence["source_archive_sha256"],
    )
    fetch_to(
        evidence["source_tag_ref_path"],
        url_for_tag(old_tag),
        f"surrealdb.tag-ref.{old_tag}",
    )

    query = json.loads(surreal["advisory_query"])
    query_bytes = (json.dumps(query, separators=(",", ":"), ensure_ascii=False) + "\r\n").encode("utf-8")
    query_record = materialize(root, surreal["advisory_query_path"], query_bytes, surreal["advisory_query_sha256"])
    records.append({
        "subject": "osv.query.surrealdb",
        "url": OSV_ENDPOINT,
        "request": True,
        "reused": query_record["reused"],
        "expected_sha256": surreal["advisory_query_sha256"].lower(),
        "expected_bytes": None,
        **query_record,
    })
    try:
        _, response_relative, response_bytes = read_local(root, surreal["advisory_response_path"])
        response_reused = True
    except RuntimeError as exc:
        if "not a regular file" not in str(exc) or _validate_components(root, _relative_path(surreal["advisory_response_path"])).exists():
            raise
        response_bytes = fetch(OSV_ENDPOINT, data=query_bytes, accept="application/json")
        response_record = materialize(root, surreal["advisory_response_path"], response_bytes, surreal["advisory_response_digest"])
        response_relative = response_record["relative_path"]
        response_reused = False
    if response_reused:
        response_sha = sha256_bytes(response_bytes)
        if response_sha != str(surreal["advisory_response_digest"]).lower():
            raise RuntimeError(f"existing bytes for {response_relative} have SHA-256 {response_sha}, expected {surreal['advisory_response_digest']}")
        response_record = {"path": response_relative, "relative_path": response_relative, "bytes": len(response_bytes), "sha256": response_sha}
    records.append({
        "subject": "osv.response.surrealdb",
        "url": OSV_ENDPOINT,
        "request": False,
        "reused": response_reused,
        "expected_sha256": str(surreal["advisory_response_digest"]).lower(),
        "expected_bytes": None,
        **response_record,
    })

    candidate_query = {
        "package": {
            "ecosystem": candidate["advisory_ecosystem"],
            "name": candidate["advisory_package"],
        },
        "version": candidate_version,
    }
    candidate_query_bytes = (
        json.dumps(candidate_query, separators=(",", ":"), ensure_ascii=False) + "\r\n"
    ).encode("utf-8")
    candidate_query_record = materialize(
        root,
        candidate["advisory_query_path"],
        candidate_query_bytes,
        replace_existing=True,
    )
    records.append({
        "subject": f"osv.query.surrealdb.release-candidate.{candidate_tag}",
        "url": OSV_ENDPOINT,
        "request": True,
        "expected_sha256": candidate_query_record["sha256"],
        "expected_bytes": candidate_query_record["bytes"],
        **candidate_query_record,
    })

    candidate_response_bytes = fetch(
        OSV_ENDPOINT,
        data=candidate_query_bytes,
        accept="application/json",
    )
    try:
        candidate_response_data = json.loads(candidate_response_bytes.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"candidate OSV response is not valid JSON: {exc}") from exc
    if not isinstance(candidate_response_data, dict) or not isinstance(candidate_response_data.get("vulns"), list):
        raise RuntimeError("candidate OSV response must contain a vulns array")
    candidate_retrieved_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    candidate_response_record = materialize(
        root,
        candidate["advisory_response_path"],
        candidate_response_bytes,
        replace_existing=True,
    )
    records.append({
        "subject": f"osv.response.surrealdb.release-candidate.{candidate_tag}",
        "url": OSV_ENDPOINT,
        "request": False,
        "fetched": True,
        "retrieved_at_utc": candidate_retrieved_at,
        "expected_sha256": None,
        "expected_bytes": None,
        **candidate_response_record,
    })

    receipt = {
        "schema": "eliot.surrealdb-project-local-provisioning.v2",
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repository": OFFICIAL_REPOSITORY,
        "shared_installation_touched": False,
        "records": records,
    }
    receipt_payload = (json.dumps(receipt, indent=2) + "\n").encode("utf-8")
    materialize(root, ".eliot/dependency-policy/surrealdb/provisioning-receipt.json", receipt_payload, replace_existing=True)
    print(json.dumps(receipt, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
