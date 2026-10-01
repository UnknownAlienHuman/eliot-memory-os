#!/usr/bin/env python3
"""Materialize the exact pinned dependency-policy scanner into project-local state.

Issue #3004, with #1229/#1225 (external audit 5885520490, 5887267570): a clean
authorized runner must be able to reconstruct the declared dependency-policy
inputs without pre-existing workstation state. The scanner identity is never
"latest": the version, the release-archive digest and the executable digest all
come from ``config/dependency-policy.toml`` ``[scanner]``, and the downloaded
bytes must match them exactly.

This command provisions INPUTS and their PROVENANCE only. It never writes a
lockfile or a verdict, never repairs policy, and never turns a failed policy
result into PASS. A missing, substituted or digest-mismatched scanner is a
failure, because ``scripts/verify-dependency-policy.py`` resolves the scanner
through PATH and then admits only digest-matched bytes.

It does retain one OUTCOME record per invocation at
``.eliot/dependency-policy/cargo-deny/provisioning-outcome.json``
(issue #3004, external audit 5886158422). That record is written on the failure
path as well as the success path, and binds the exact fixed source, the declared
pinned identity, and either the digest-verified installed bytes or the typed
failure that prevented them. It exists so a failed or truncated acquisition
still leaves a retained result instead of exiting with no record at all. Its
``status`` reaches ``exact_pinned_scanner_materialized`` only after both the
downloaded archive and the installed executable have been re-read and compared
against the pinned digests over the bytes actually on disk; on any failure it is
``failed``, with ``scanner_available: false``. A transport fault - including the
``http.client.IncompleteRead`` a truncated body raises, which is not an
``OSError`` - is a typed ``AcquisitionFailure``, never an uncaught exit.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen


REPARSE_POINT = 0x400
LOCAL_ROOT = ".eliot/dependency-policy/cargo-deny/"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_SEMVER = re.compile(r"\d+\.\d+\.\d+")
USER_AGENT = "eliot-dependency-scanner-provisioner"

# The retained acquisition-outcome receipt. Issue #3004, external audit
# 5886158422: a failed or truncated acquisition must still leave a retained
# record for the exact fixed source, instead of dying with no receipt at all.
# The receipt is an OUTCOME record, never a pass receipt: `status` only ever
# reaches ``exact_pinned_scanner_materialized`` after the downloaded bytes and
# the installed executable have both been re-read and compared against the
# pinned digests over the bytes actually on disk.
OUTCOME_RECEIPT_RELATIVE = ".eliot/dependency-policy/cargo-deny/provisioning-outcome.json"
OUTCOME_SCHEMA = "eliot.dependency-policy-scanner-provisioning-outcome.v1"
AUDIT_REF = "5886158422"

STATUS_MATERIALIZED = "exact_pinned_scanner_materialized"
STATUS_FAILED = "failed"

# Every failure that must still leave a retained outcome record rather than a
# bare exit. RuntimeError is here so the typed AcquisitionFailure/ByteBoundFailure
# raised by fetch()/materialize() are retained; OSError and HTTPException are
# here because a truncated body raises http.client.IncompleteRead, which is a
# HTTPException and NOT an OSError, so an OSError-only guard misses it. Naming
# all three is what makes "failed stays failed AND is recorded" true.
TRANSPORT_FAILURES = (RuntimeError, OSError, http.client.HTTPException)


class AcquisitionFailure(RuntimeError):
    """A declared acquisition input could not be obtained as pinned bytes.

    Typed on purpose: a transport fault (including a truncated body) is not an
    authoring or policy error, and it must stay distinguishable from both a
    digest mismatch and a successful acquisition.
    """


class ByteBoundFailure(AcquisitionFailure):
    """The acquired body was not the declared byte length for this operation.

    ``declared_bytes`` is the length this run observed for the response it just
    read; ``expected_bytes`` is the pinned length, or None when policy declares
    no length. Comparing the length of THIS response against the pinned value
    is what makes a truncated body visible before it reaches the digest check.
    """


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
    """Confine every write to the project-local, git-ignored scanner evidence root."""
    if not isinstance(raw, str) or not raw.strip():
        raise RuntimeError("scanner artifact path is missing")
    relative = Path(raw)
    if relative.is_absolute() or ".." in relative.parts:
        raise RuntimeError(f"scanner artifact path escapes the repository: {raw}")
    normalized = str(relative).replace("\\", "/")
    if not normalized.startswith(LOCAL_ROOT):
        raise RuntimeError(f"scanner artifact path is outside the project-local evidence root: {raw}")
    return Path(normalized)


def _validate_components(root: Path, relative: Path) -> Path:
    """Refuse a symlink or reparse component anywhere on the destination path."""
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


def read_local(root: Path, raw: object) -> tuple[Path, str, bytes]:
    """Read project-local bytes through a no-follow handle and revalidate identity."""
    relative = _relative_path(raw)
    path = _validate_components(root, relative)
    if not path.is_file():
        raise RuntimeError(f"project-local evidence is not a regular file: {relative}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd: int | None = None
    try:
        fd = os.open(path, flags)
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
    revalidated, revalidated_relative = _validate_components(root, relative), str(relative).replace("\\", "/")
    if _path_identity(after) != _path_identity(revalidated.stat()):
        raise RuntimeError(f"project-local evidence path identity changed during read: {revalidated_relative}")
    return revalidated, revalidated_relative, b"".join(chunks)


def materialize(root: Path, raw_path: object, payload: bytes, expected_sha256: str) -> dict:
    """Write the verified bytes once, atomically, and revalidate the result."""
    relative = _relative_path(raw_path)
    actual = sha256_bytes(payload)
    if actual != expected_sha256.lower():
        raise RuntimeError(f"bytes for {relative} have SHA-256 {actual}, expected {expected_sha256}")
    path = _validate_components(root, relative)
    reused = False
    if path.exists():
        _, _, existing = read_local(root, raw_path)
        existing_sha = sha256_bytes(existing)
        if existing_sha == actual:
            return {"path": str(relative).replace("\\", "/"), "bytes": len(payload), "sha256": actual, "reused": True}
        raise RuntimeError(
            f"refusing to replace existing project-local scanner {existing_sha} with {actual}; "
            "remove it or repin the policy explicitly"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    _validate_components(root, relative)
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
    if sha256_bytes(verified_payload) != actual or len(verified_payload) != len(payload):
        raise RuntimeError(f"project-local scanner write failed identity revalidation: {verified_relative}")
    return {"path": verified_relative, "bytes": len(payload), "sha256": actual, "reused": reused}


def fetch(url: str, expected_bytes: int | None = None) -> bytes:
    """Read the whole declared body, failing typed on a transport fault.

    Issue #3004, external audit 5886158422: a truncated body raises
    ``http.client.IncompleteRead`` (a ``HTTPException``, not an ``OSError``),
    so it used to escape every guard and end the process with no retained
    record at all. Every transport fault is now a typed ``AcquisitionFailure``.

    The byte bound is compared against the bytes THIS response delivered. When
    the caller pins ``expected_bytes`` that is the authority; otherwise the
    response's own ``Content-Length`` is used, so a server that declares a
    length and then sends fewer bytes is rejected as truncated rather than
    silently digested. A response that declares no length is not length-checked
    and relies on the pinned digest alone - absence of a bound is never treated
    as a satisfied bound.
    """
    request = Request(url, headers={"Accept": "application/octet-stream", "User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=180) as response:
            declared = response.headers.get("Content-Length")
            payload = response.read()
    except http.client.HTTPException as exc:
        # Includes IncompleteRead: the body arrived short.
        raise AcquisitionFailure(f"transport failed while reading {url}: {exc}") from exc
    except OSError as exc:
        raise AcquisitionFailure(f"transport failed while reading {url}: {exc}") from exc
    bound = expected_bytes
    if bound is None and declared is not None:
        try:
            bound = int(declared)
        except ValueError:
            bound = None
    if bound is not None and len(payload) != bound:
        raise ByteBoundFailure(
            f"{url} delivered {len(payload)} bytes against a declared bound of {bound} "
            f"(Content-Length {declared or 'absent'}); a short body is not a complete acquisition"
        )
    return payload


def extract_member(archive: bytes, member: str) -> bytes:
    """Read exactly one declared regular-file member; never extract an archive tree."""
    with tempfile.TemporaryDirectory(prefix="eliot-scanner-archive-") as scratch:
        archive_path = Path(scratch) / "scanner.tar.gz"
        archive_path.write_bytes(archive)
        with tarfile.open(archive_path, "r:gz") as tar:
            try:
                info = tar.getmember(member)
            except KeyError as exc:
                available = sorted(item.name for item in tar.getmembers() if item.isfile())
                raise RuntimeError(f"scanner archive has no member {member!r}; it holds {available}") from exc
            if not info.isfile():
                raise RuntimeError(f"scanner archive member is not a regular file: {member}")
            handle = tar.extractfile(info)
            if handle is None:
                raise RuntimeError(f"scanner archive member cannot be read: {member}")
            with handle:
                return handle.read()


def scanner_identity(manifest: dict) -> dict:
    """Read the exact declared scanner identity, failing closed on any gap."""
    scanner = manifest.get("scanner")
    if not isinstance(scanner, dict):
        raise RuntimeError("config/dependency-policy.toml has no [scanner] table")
    required = (
        "tool",
        "version",
        "executable",
        "sha256",
        "release_source",
        "release_asset",
        "release_asset_sha256",
        "archive_member",
        "artifact_path",
    )
    for field in required:
        if not isinstance(scanner.get(field), str) or not scanner[field].strip():
            raise RuntimeError(f"[scanner].{field} must declare the exact pinned scanner identity")
    if scanner["tool"] != "cargo-deny":
        raise RuntimeError("[scanner].tool must be 'cargo-deny'")
    if scanner["executable"] not in {"cargo-deny", "cargo-deny.exe"}:
        raise RuntimeError("[scanner].executable must identify cargo-deny")
    if not _SEMVER.fullmatch(scanner["version"]):
        raise RuntimeError("[scanner].version must be an exact semantic version, never 'latest'")
    for field in ("sha256", "release_asset_sha256"):
        if not _HEX64.fullmatch(str(scanner[field]).lower()):
            raise RuntimeError(f"[scanner].{field} must be a 64-character lowercase hexadecimal digest")
    asset = urlparse(scanner["release_asset"])
    if asset.scheme != "https" or not asset.netloc:
        raise RuntimeError("[scanner].release_asset must be an absolute https URL")
    if asset.scheme + "://" + asset.netloc + "/" not in scanner["release_source"].rstrip("/") + "/":
        raise RuntimeError("[scanner].release_asset is not published by the declared [scanner].release_source")
    if scanner["version"] not in asset.path:
        raise RuntimeError("[scanner].release_asset does not carry the pinned [scanner].version")
    if scanner["archive_member"].startswith("/") or ".." in Path(scanner["archive_member"]).parts:
        raise RuntimeError("[scanner].archive_member must be a relative in-archive path")
    # The verifier resolves the scanner through PATH, so a Windows runner finds
    # the declared `cargo-deny` as `cargo-deny.exe` via PATHEXT. Admit exactly
    # that pair and nothing else.
    artifact_name = _relative_path(scanner["artifact_path"]).name
    if artifact_name not in {scanner["executable"], f"{scanner['executable']}.exe"}:
        raise RuntimeError("[scanner].artifact_path must name the declared scanner executable")
    return scanner


def source_sha(root: Path) -> str | None:
    """Bind the retained receipt to the exact fixed source that produced it."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    sha = proc.stdout.strip()
    return sha if proc.returncode == 0 and re.fullmatch(r"[0-9a-fA-F]{40}", sha) else None


def write_outcome_receipt(root: Path, outcome: dict) -> str | None:
    """Retain the acquisition outcome for the exact fixed source, always.

    Issue #3004, external audit 5886158422: this is the retention half of
    "retain a result for one fixed source". It is written on the failure path
    as well as the success path, so a truncated or substituted download leaves
    a record naming what was attempted and why it failed instead of leaving no
    record at all. A failed write is reported, never silently swallowed: the
    caller still exits nonzero.
    """
    payload = {
        "schema": OUTCOME_SCHEMA,
        "audit": AUDIT_REF,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_sha": source_sha(root),
        **outcome,
    }
    try:
        path = _validate_components(root, _relative_path(OUTCOME_RECEIPT_RELATIVE))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((json.dumps(payload, indent=2) + "\n").encode("utf-8"))
    except (OSError, RuntimeError) as exc:
        print(f"SCANNER_OUTCOME_RECEIPT: unwritable at {OUTCOME_RECEIPT_RELATIVE}: {exc}", file=sys.stderr)
        return None
    return OUTCOME_RECEIPT_RELATIVE


def provision(root: Path, scanner: dict) -> dict:
    """Materialize the pinned scanner, or fail typed. Returns the outcome body."""
    artifact_path = root / _validate_components(root, _relative_path(scanner["artifact_path"]))
    reused = False
    if artifact_path.is_file():
        try:
            _, _, existing = read_local(root, scanner["artifact_path"])
        except RuntimeError:
            existing = b""
        if sha256_bytes(existing) == scanner["sha256"].lower():
            reused = True

    archive = None
    if not reused:
        # Policy declares no archive byte length, so the bound is the length
        # THIS response declares for itself. fetch() compares the bytes it just
        # read against that bound, so a short body is rejected as truncated
        # before the pinned digest is even consulted.
        archive = fetch(scanner["release_asset"])
        archive_sha = sha256_bytes(archive)
        if archive_sha != scanner["release_asset_sha256"].lower():
            raise AcquisitionFailure(
                f"scanner release archive SHA-256 {archive_sha} does not match the pinned "
                f"[scanner].release_asset_sha256 {scanner['release_asset_sha256']}"
            )
        payload = extract_member(archive, scanner["archive_member"])
        materialize(root, scanner["artifact_path"], payload, scanner["sha256"])

    _, relative, installed = read_local(root, scanner["artifact_path"])
    installed_sha = sha256_bytes(installed)
    if installed_sha != scanner["sha256"].lower():
        raise AcquisitionFailure(
            f"installed scanner SHA-256 {installed_sha} does not match the pinned [scanner].sha256"
        )
    if stat.S_ISLNK(artifact_path.lstat().st_mode):
        raise AcquisitionFailure("installed scanner is a symbolic link")

    return {
        "tool": scanner["tool"],
        "version": scanner["version"],
        "executable": scanner["executable"],
        "configured_sha256": scanner["sha256"].lower(),
        "observed_sha256": installed_sha,
        "bytes": len(installed),
        "path": relative,
        "install_directory": str(Path(relative).parent).replace("\\", "/"),
        "release_asset": scanner["release_asset"],
        "release_asset_sha256": scanner["release_asset_sha256"].lower(),
        "archive_member": scanner["archive_member"],
        "archive_downloaded": archive is not None,
        "reused": reused,
        "status": STATUS_MATERIALIZED,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    manifest = tomllib.loads((root / "config" / "dependency-policy.toml").read_text(encoding="utf-8"))
    scanner = scanner_identity(manifest)

    # The declared identity every outcome is bound to, retained even when the
    # acquisition itself never happened (an undeclared or malformed identity is
    # a failure, but the record of the attempt is still the retained result).
    declared = {
        "tool": scanner["tool"],
        "version": scanner["version"],
        "executable": scanner["executable"],
        "configured_sha256": scanner["sha256"].lower(),
        "release_asset": scanner["release_asset"],
        "release_asset_sha256": scanner["release_asset_sha256"].lower(),
        "archive_member": scanner["archive_member"],
    }
    try:
        outcome = provision(root, scanner)
    except TRANSPORT_FAILURES as exc:
        # failed stays failed: the exit is nonzero, nothing is materialized
        # beyond the diagnostic record, and the record names the failure rather
        # than any substituted identity. TRANSPORT_FAILURES includes
        # http.client.HTTPException, so a truncated body reaching this guard
        # from any path still retains a receipt instead of dying with none.
        receipt = write_outcome_receipt(
            root,
            {
                **declared,
                "status": STATUS_FAILED,
                "scanner_available": False,
                "failure_kind": type(exc).__name__,
                "detail": str(exc)[:2000],
            },
        )
        print(
            f"SCANNER_PROVISIONING_FAILED: {exc}",
            file=sys.stderr,
        )
        if receipt:
            print(f"SCANNER_OUTCOME_RECEIPT: {receipt} status={STATUS_FAILED}", file=sys.stderr)
        return 1

    receipt = write_outcome_receipt(root, outcome)
    print(json.dumps(outcome, indent=2))
    if receipt:
        print(f"SCANNER_OUTCOME_RECEIPT: {receipt} status={outcome['status']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # fail closed: a provisioning gap is never a PASS
        # Unreachable for a declared-but-unprovisionable identity (those are
        # typed above); retained so an unexpected fault still exits nonzero.
        print(f"SCANNER_PROVISIONING_FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
