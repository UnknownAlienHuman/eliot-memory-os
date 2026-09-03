"""Fail-closed canonical documentation shard size and topic-index checks."""

from __future__ import annotations

import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from .common import NavigationError, normalize_repo_path, read_json, read_toml

SCHEMA = "eliot-doc-shard-limits-v1"
CONFIG_PATH = "docs/code-navigation/shard-limits.toml"
MANIFESTS = (
    "docs/architecture/architecture/manifest.json",
    "docs/architecture/implementation/manifest.json",
)
TOPIC_INDEX = "docs/architecture/INDEX.md"
TOPIC_H1 = "# ELIOT canonical topic index"


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise NavigationError(f"{field} must be a positive integer")
    return value


def _config(root: Path) -> tuple[int, dict[str, int]]:
    payload = read_toml(root / CONFIG_PATH)
    if payload.get("schema_version") != SCHEMA:
        raise NavigationError(f"unsupported shard-limit schema in {CONFIG_PATH}")
    default_limit = _positive_int(
        payload.get("max_rendered_bytes"), "max_rendered_bytes"
    )
    raw = payload.get("exemption", [])
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise NavigationError("shard-limit exemption must be an array of tables")
    exemptions: dict[str, int] = {}
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise NavigationError(f"exemption[{index}] must be a table")
        path = normalize_repo_path(str(item.get("path", "")))
        if path in {"", "."} or not path.startswith("docs/architecture/"):
            raise NavigationError(
                f"exemption[{index}].path must identify a canonical shard"
            )
        if path in exemptions:
            raise NavigationError(f"duplicate shard-limit exemption: {path}")
        limit = _positive_int(
            item.get("max_rendered_bytes"),
            f"exemption[{index}].max_rendered_bytes",
        )
        if limit <= default_limit:
            raise NavigationError(
                f"shard-limit exemption does not exceed default ceiling: {path}"
            )
        reason = str(item.get("reason", "")).strip()
        if not reason:
            raise NavigationError(f"shard-limit exemption has no reason: {path}")
        exemptions[path] = limit
    return default_limit, exemptions


def check(root: Path) -> None:
    root = root.resolve()
    default_limit, exemptions = _config(root)
    present: set[str] = set()
    largest = 0
    count = 0
    for manifest_relative in MANIFESTS:
        manifest = read_json(root / manifest_relative)
        if manifest.get("schema_version") != "eliot-doc-shards-v1":
            raise NavigationError(
                f"unsupported documentation shard manifest: {manifest_relative}"
            )
        fragments = manifest.get("fragments")
        if not isinstance(fragments, list) or not fragments:
            raise NavigationError(
                f"documentation shard manifest has no fragments: {manifest_relative}"
            )
        for index, record in enumerate(fragments):
            if not isinstance(record, dict):
                raise NavigationError(
                    f"documentation shard record is not an object: {manifest_relative}[{index}]"
                )
            path = normalize_repo_path(str(record.get("path", "")))
            rendered = _positive_int(
                record.get("rendered_bytes"), f"fragment {path}.rendered_bytes"
            )
            target = root / PurePosixPath(path)
            if not target.is_file() or target.is_symlink():
                raise NavigationError(
                    f"documentation shard is missing/symlinked: {path}"
                )
            actual = target.stat().st_size
            if actual != rendered:
                raise NavigationError(
                    f"documentation shard byte count differs from manifest: "
                    f"{path} expected={rendered} actual={actual}"
                )
            limit = exemptions.get(path, default_limit)
            if rendered > limit:
                raise NavigationError(
                    f"documentation shard exceeds size ceiling: "
                    f"{path} bytes={rendered} limit={limit}"
                )
            largest = max(largest, rendered)
            count += 1
            present.add(path)

    stale = sorted(set(exemptions).difference(present))
    if stale:
        raise NavigationError(
            "stale shard-limit exemptions: " + ", ".join(stale)
        )
    unnecessary = sorted(
        path
        for path in exemptions
        if (root / PurePosixPath(path)).stat().st_size <= default_limit
    )
    if unnecessary:
        raise NavigationError(
            "unnecessary shard-limit exemptions: " + ", ".join(unnecessary)
        )

    topic = root / TOPIC_INDEX
    if not topic.is_file() or topic.is_symlink():
        raise NavigationError(
            f"canonical topic index is missing/symlinked: {TOPIC_INDEX}"
        )
    try:
        text = topic.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise NavigationError(f"cannot read canonical topic index: {exc}") from exc
    h1_count = sum(1 for line in text.splitlines() if line.strip() == TOPIC_H1)
    if h1_count != 1:
        raise NavigationError(
            f"canonical topic index must contain exactly one primary heading: "
            f"{TOPIC_INDEX} count={h1_count}"
        )

    print(
        "DOC_SHARD_LIMIT_CHECK: PASS "
        f"fragments={count} largest={largest} "
        f"default_limit={default_limit} exemptions={len(exemptions)}"
    )


def _fixture(root: Path, *, size: int, h1_count: int = 1) -> None:
    shard = root / "docs/architecture/implementation/I00-test.md"
    shard.parent.mkdir(parents=True, exist_ok=True)
    shard.write_bytes(b"x" * size)
    architecture = root / MANIFESTS[0]
    architecture.parent.mkdir(parents=True, exist_ok=True)
    architecture.write_text(
        '{"schema_version":"eliot-doc-shards-v1","fragments":['
        '{"path":"docs/architecture/implementation/I00-test.md",'
        f'"rendered_bytes":{size}}}'
        ']}\n',
        encoding="utf-8",
    )
    implementation = root / MANIFESTS[1]
    implementation.parent.mkdir(parents=True, exist_ok=True)
    implementation.write_text(
        '{"schema_version":"eliot-doc-shards-v1","fragments":['
        '{"path":"docs/architecture/implementation/I00-test.md",'
        f'"rendered_bytes":{size}}}'
        ']}\n',
        encoding="utf-8",
    )
    # The two fixture manifests intentionally reference the same byte-identical
    # shard; production manifests have disjoint paths and are checked normally.
    topic = root / TOPIC_INDEX
    topic.parent.mkdir(parents=True, exist_ok=True)
    topic.write_text((TOPIC_H1 + "\n") * h1_count, encoding="utf-8")
    config = root / CONFIG_PATH
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        f'schema_version = "{SCHEMA}"\nmax_rendered_bytes = 8\n',
        encoding="utf-8",
    )


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        _fixture(root, size=8)
        check(root)

        _fixture(root, size=9)
        try:
            check(root)
        except NavigationError as exc:
            if "exceeds size ceiling" not in str(exc):
                raise
        else:
            raise NavigationError("oversized documentation shard was accepted")

        _fixture(root, size=8, h1_count=2)
        try:
            check(root)
        except NavigationError as exc:
            if "exactly one primary heading" not in str(exc):
                raise
        else:
            raise NavigationError("duplicate topic-index H1 was accepted")
    print("DOC_SHARD_LIMIT_SELF_TEST: PASS cases=3")
