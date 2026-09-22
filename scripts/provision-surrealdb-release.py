#!/usr/bin/env python3
"""Materialize the pinned SurrealDB evidence into project-local ignored state.

This command never writes the shared C:\\Tools installation. It downloads the
official release/source/tag and OSV snapshot selected by the tracked policy,
refuses an existing byte mismatch, and leaves the verifier to validate PE,
source-tree, tag, and advisory bindings.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import os
import tempfile
import tomllib
from urllib.request import Request, urlopen


OFFICIAL_REPOSITORY = "https://github.com/surrealdb/surrealdb"
GITHUB_API_REPOSITORY = "https://api.github.com/repos/surrealdb/surrealdb"
OSV_ENDPOINT = "https://api.osv.dev/v1/query"


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def safe_local_path(root: Path, raw: object) -> Path:
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("local path is missing")
    relative = Path(raw)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"local path escapes repository: {raw}")
    normalized = str(relative).replace("\\", "/")
    if not normalized.startswith(".eliot/dependency-policy/surrealdb/"):
        raise ValueError(f"local path is outside the project-local evidence root: {raw}")
    return root / relative


def materialize(path: Path, payload: bytes, expected_sha256: str | None = None) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    actual = sha256_bytes(payload)
    if expected_sha256 and actual != expected_sha256.lower():
        raise RuntimeError(f"downloaded bytes for {path} have SHA-256 {actual}, expected {expected_sha256}")
    if path.exists():
        existing = path.read_bytes()
        existing_sha = sha256_bytes(existing)
        if existing_sha != actual:
            raise RuntimeError(f"refusing to replace existing project-local evidence {path}: {existing_sha} != {actual}")
        payload = existing
    else:
        fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, path)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)
    return {"path": str(path), "bytes": len(payload), "sha256": actual}


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

    def fetch_to(raw_path: object, url: str, expected: str | None = None) -> None:
        path = safe_local_path(root, raw_path)
        if path.exists():
            payload = path.read_bytes()
            actual = sha256_bytes(payload)
            if expected and actual != expected.lower():
                raise RuntimeError(f"existing bytes for {path} have SHA-256 {actual}, expected {expected}")
            records.append({"url": url, "reused": True, "path": str(path), "bytes": len(payload), "sha256": actual})
        else:
            records.append({"url": url, **materialize(path, fetch(url), expected)})

    fetch_to(
        candidate["artifact_path"],
        candidate["release_asset"],
        candidate["sha256"],
    )
    fetch_to(
        candidate["source_archive_path"],
        f"{OFFICIAL_REPOSITORY}/archive/refs/tags/{candidate['source_tag']}.tar.gz",
        candidate["source_archive_sha256"],
    )
    fetch_to(
        candidate["release_metadata_path"],
        url_for_release(candidate["source_tag"]),
    )
    fetch_to(
        candidate["source_tag_ref_path"],
        url_for_tag(candidate["source_tag"]),
    )
    fetch_to(
        evidence["source_archive_path"],
        f"{OFFICIAL_REPOSITORY}/archive/refs/tags/{evidence['source_tag']}.tar.gz",
        evidence["source_archive_sha256"],
    )
    fetch_to(
        evidence["source_tag_ref_path"],
        url_for_tag(evidence["source_tag"]),
    )

    query = json.loads(surreal["advisory_query"])
    query_bytes = (json.dumps(query, separators=(",", ":"), ensure_ascii=False) + "\r\n").encode("utf-8")
    query_path = safe_local_path(root, surreal["advisory_query_path"])
    records.append({"url": OSV_ENDPOINT, "request": True, **materialize(query_path, query_bytes, surreal["advisory_query_sha256"])})
    response_path = safe_local_path(root, surreal["advisory_response_path"])
    if response_path.exists():
        response_bytes = response_path.read_bytes()
        response_sha = sha256_bytes(response_bytes)
        if response_sha != str(surreal["advisory_response_digest"]).lower():
            raise RuntimeError(f"existing bytes for {response_path} have SHA-256 {response_sha}, expected {surreal['advisory_response_digest']}")
        response_record = {"reused": True, "path": str(response_path), "bytes": len(response_bytes), "sha256": response_sha}
    else:
        response_record = materialize(
            response_path,
            fetch(OSV_ENDPOINT, data=query_bytes, accept="application/json"),
            surreal["advisory_response_digest"],
        )
    records.append({"url": OSV_ENDPOINT, "request": False, **response_record})

    receipt = {
        "schema": "eliot.surrealdb-project-local-provisioning.v1",
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repository": OFFICIAL_REPOSITORY,
        "shared_installation_touched": False,
        "records": records,
    }
    receipt_path = root / ".eliot" / "dependency-policy" / "surrealdb" / "provisioning-receipt.json"
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
