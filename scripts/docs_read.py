#!/usr/bin/env python3
"""Verify and render every required item from an ELIOT documentation route."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence

import docs_router

SCHEMA = "eliot-doc-read-v1"


class ReadError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_sha256(value: dict[str, Any]) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256_bytes(raw)


def changed_paths(root: Path, changed_from: str) -> list[str]:
    if not changed_from.strip():
        raise ReadError("--changed-from cannot be empty")
    command = [
        "git",
        "-C",
        str(root),
        "diff",
        "--name-only",
        "--diff-filter=ACMRTUXBD",
        f"{changed_from}...HEAD",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise ReadError(
            f"git diff failed for {changed_from}: {completed.stderr.strip()}"
        )
    paths = [
        docs_router.normalize_repo_path(line)
        for line in completed.stdout.splitlines()
        if line.strip()
    ]
    # An empty delta is a real, reportable outcome (the work is already done,
    # or the branch legitimately changes nothing), not a router failure. It is
    # returned to the caller so it can say so honestly instead of failing with
    # DOC_READ_FAIL and forcing a hand-built --path list to look like work.
    return sorted(set(paths))


EMPTY_DELTA_EXIT = 2


def report_empty_delta(changed_from: str) -> int:
    print(
        f"DOC_READ_EMPTY_DELTA: no changed paths from {changed_from} to HEAD; "
        "the branch has no delta, so there is no mutation to authorize and no "
        "reading evidence to produce. This is not a pass and not a failure: "
        "record the empty delta as the outcome. If this branch does mutate "
        "something, commit or stage it and re-run, or name the path family "
        "explicitly with --path.",
        file=sys.stderr,
    )
    return EMPTY_DELTA_EXIT


def verified_item(root: Path, item: dict[str, Any]) -> tuple[dict[str, Any], str]:
    relative = docs_router.normalize_repo_path(str(item.get("path", "")))
    if relative in docs_router.LEGACY_BOOKS:
        raise ReadError(f"legacy compatibility map cannot satisfy reading: {relative}")
    path = root / relative
    if not path.is_file():
        raise ReadError(f"required routed item does not exist: {relative}")
    raw = path.read_bytes()
    actual_sha = sha256_bytes(raw)
    actual_bytes = len(raw)
    expected_sha = str(item.get("sha256", ""))
    try:
        expected_bytes = int(item.get("bytes", -1))
    except (TypeError, ValueError) as exc:
        raise ReadError(f"invalid byte count in route item: {relative}") from exc
    if actual_sha != expected_sha:
        raise ReadError(
            f"required item hash mismatch: {relative}: "
            f"route={expected_sha} actual={actual_sha}"
        )
    if actual_bytes != expected_bytes:
        raise ReadError(
            f"required item byte mismatch: {relative}: "
            f"route={expected_bytes} actual={actual_bytes}"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReadError(f"required routed item is not UTF-8: {relative}") from exc
    record = {
        "kind": str(item.get("kind", "")),
        "path": relative,
        "sha256": actual_sha,
        "bytes": actual_bytes,
    }
    if item.get("handles"):
        record["handles"] = list(item["handles"])
    if item.get("anchors"):
        record["anchors"] = list(item["anchors"])
    return record, text


def assert_governing_fragments(
    root: Path, route: dict[str, Any], verified: Sequence[dict[str, Any]]
) -> list[str]:
    """Prove every title-named governing fragment is present in the bundle.

    The router resolves the governing fragment from the causal property's prose
    title and puts it in `required`. This re-derives that resolution from the
    handle index and fails closed unless each governing fragment is a REQUIRED
    item of the rendered bundle, at its indexed path, with the handle attached
    and the current on-disk hash. A silent gap becomes a loud one: a bundle that
    does not actually contain the fragment governing the requested topic cannot
    pass, whatever the route claims.
    """
    handles = docs_router.read_json(root / docs_router.DEFAULT_INDEX).get("handles", {})
    if not isinstance(handles, dict) or not handles:
        raise ReadError("handle index has no handles")
    expected = docs_router.governing_handles(handles, str(route.get("topic", "")))
    if not expected:
        return []
    required = {
        str(item["path"]): item for item in verified if item.get("kind") == "fragment"
    }
    absent: list[str] = []
    for handle in expected:
        record = handles[handle]
        index_path = str(record["path"])
        item = required.get(index_path)
        if item is None:
            absent.append(f"{handle} -> {index_path} (not a required bundle item)")
            continue
        if handle not in item.get("handles", ()):
            absent.append(
                f"{handle} -> {index_path} (required item carries handles "
                f"{item.get('handles', [])})"
            )
            continue
        if str(item["sha256"]) != str(record["fragment_sha256"]):
            absent.append(f"{handle} -> {index_path} (bundle hash is not the indexed hash)")
            continue
        if sha256_bytes((root / index_path).read_bytes()) != str(record["fragment_sha256"]):
            absent.append(f"{handle} -> {index_path} (stale on disk)")
    if absent:
        raise ReadError(
            "governing fragments named by the causal property are absent from the "
            "verified bundle; re-run the router or widen the causal property "
            "until each governs this work: " + "; ".join(absent)
        )
    return expected


def language_for(path: str) -> str:
    suffix = Path(path).suffix.casefold()
    return {
        ".json": "json",
        ".toml": "toml",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".py": "python",
        ".ps1": "powershell",
        ".rs": "rust",
        ".sh": "bash",
    }.get(suffix, "text")


def render_item(record: dict[str, Any], text: str) -> str:
    handles = record.get("handles", [])
    handle_note = f"; handles={','.join(handles)}" if handles else ""
    header = (
        f"\n---\n\n## Required item `{record['path']}`\n\n"
        f"SHA-256: `{record['sha256']}`; bytes: `{record['bytes']}`{handle_note}.\n\n"
    )
    if Path(record["path"]).suffix.casefold() in (".md", ".markdown"):
        return header + text.rstrip("\n") + "\n"
    fence = "````"
    return header + f"{fence}{language_for(record['path'])}\n{text.rstrip()}\n{fence}\n"


def build_read_bundle(root: Path, route: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    required = route.get("required")
    if not isinstance(required, list) or not required:
        raise ReadError("route contains no required items")
    verified: list[dict[str, Any]] = []
    chunks = [
        "# ELIOT verified documentation read bundle\n\n",
        f"Route receipt: `{route.get('receipt_id', '')}`\n\n",
        f"Normative pair: `{route.get('pair_key', '')}`\n\n",
        "> Every item below was verified against the route immediately before rendering.\n",
    ]
    for item in required:
        if not isinstance(item, dict):
            raise ReadError("route required item is not an object")
        record, text = verified_item(root, item)
        verified.append(record)
        chunks.append(render_item(record, text))
    bundle = "".join(chunks)
    governing = assert_governing_fragments(root, route, verified)
    receipt_core = {
        "schema_version": SCHEMA,
        "route_receipt_id": str(route.get("receipt_id", "")),
        "pair_key": str(route.get("pair_key", "")),
        "paths": list(route.get("paths", [])),
        "topic": str(route.get("topic", "")),
        "matched_routes": list(route.get("matched_routes", [])),
        "governing_handles": governing,
        "required": verified,
        "bundle_sha256": sha256_bytes(bundle.encode("utf-8")),
        "bundle_bytes": len(bundle.encode("utf-8")),
        "attestation_required": True,
    }
    receipt = dict(receipt_core)
    receipt["read_receipt_id"] = "sha256:" + canonical_sha256(receipt_core)
    return bundle, receipt


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")


def self_test() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        target = root / "docs/fragment.md"
        target.parent.mkdir(parents=True)
        target.write_text("# Fragment\nExact text.\n", encoding="utf-8", newline="")
        raw = target.read_bytes()
        # The governing-fragment self-check reads the handle index, so the
        # fixture must carry one before any bundle is built.
        index_path = root / docs_router.DEFAULT_INDEX
        index_path.parent.mkdir(parents=True, exist_ok=True)
        index_path.write_text(
            json.dumps(
                {
                    "schema_version": docs_router.INDEX_SCHEMA,
                    "handles": {
                        "I9.9": {
                            "title": "I9.9. Unrelated placeholder",
                            "path": "docs/unrelated.md",
                            "fragment_sha256": "0" * 64,
                            "fragment_bytes": 0,
                            "anchor": "i99",
                        }
                    },
                }
            ),
            encoding="utf-8",
            newline="",
        )
        item = {
            "kind": "fragment",
            "role": "required",
            "path": "docs/fragment.md",
            "sha256": sha256_bytes(raw),
            "bytes": len(raw),
            "handles": ["A1"],
            "anchors": ["a1"],
        }
        route = {
            "receipt_id": "sha256:" + "1" * 64,
            "pair_key": "sha256:" + "2" * 64,
            "paths": ["src/lib.rs"],
            "topic": "test",
            "matched_routes": ["test"],
            "required": [item],
        }
        first_bundle, first_receipt = build_read_bundle(root, route)
        second_bundle, second_receipt = build_read_bundle(root, route)
        if first_bundle != second_bundle or first_receipt != second_receipt:
            raise ReadError("read bundle or receipt is not deterministic")
        target.write_text("tampered\n", encoding="utf-8", newline="")
        try:
            build_read_bundle(root, route)
        except ReadError as exc:
            if "hash mismatch" not in str(exc) and "byte mismatch" not in str(exc):
                raise
        else:
            raise ReadError("tampered required item did not fail closed")
        legacy = dict(item)
        legacy["path"] = next(iter(docs_router.LEGACY_BOOKS))
        try:
            verified_item(root, legacy)
        except ReadError as exc:
            if "legacy compatibility map" not in str(exc):
                raise
        else:
            raise ReadError("legacy compatibility map was accepted")

        # The governing-fragment self-check must fire on a route that resolved
        # the governing handle but left it out of the required set (#929, #958,
        # #1730, #2970). A silent gap must be a loud failure.
        target.write_text("# Fragment\nExact text.\n", encoding="utf-8", newline="")
        raw = target.read_bytes()
        handles = {
            "I5.13": {
                "title": "I5.13. Backup and restore",
                "path": "docs/fragment.md",
                "fragment_sha256": sha256_bytes(raw),
                "fragment_bytes": len(raw),
                "anchor": "i513",
            }
        }
        index_path.write_text(
            json.dumps({"schema_version": docs_router.INDEX_SCHEMA, "handles": handles}),
            encoding="utf-8",
            newline="",
        )
        governing_item = dict(item)
        governing_item["handles"] = ["I5.13"]
        governing_item["anchors"] = ["i513"]
        governing_route = {
            "receipt_id": "sha256:" + "3" * 64,
            "pair_key": "sha256:" + "2" * 64,
            "paths": ["src/lib.rs"],
            "topic": "backup and restore of host state",
            "matched_routes": ["test"],
            "required": [governing_item],
        }
        # The satisfied route proves the governing fragment and passes.
        satisfied_bundle, satisfied_receipt = build_read_bundle(root, governing_route)
        if satisfied_receipt["governing_handles"] != ["I5.13"]:
            raise ReadError("governing handle was not recorded in the read receipt")
        if "docs/fragment.md" not in satisfied_bundle:
            raise ReadError("governing fragment was not rendered into the bundle")
        if docs_router.governing_handles(handles, "backup and restore of host state") != ["I5.13"]:
            raise ReadError("governing fragment resolution self-test failed")
        # The incomplete route required a fragment that is NOT the governing one.
        # This is the known-incomplete shape that previously passed silently.
        incomplete_route = dict(governing_route)
        incomplete_route["required"] = [
            {
                "kind": "file",
                "role": "required",
                "path": "AGENTS.md",
                "sha256": "0" * 64,
                "bytes": 0,
            }
        ]
        (root / "AGENTS.md").write_text("root\n", encoding="utf-8", newline="")
        try:
            assert_governing_fragments(root, incomplete_route, [
                {
                    "kind": "file",
                    "path": "AGENTS.md",
                    "sha256": "0" * 64,
                    "bytes": 4,
                }
            ])
        except ReadError as exc:
            if "absent from the verified bundle" not in str(exc):
                raise
        else:
            raise ReadError("missing governing fragment did not fail closed")
    print("DOC_READ_SELF_TEST: PASS cases=6")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    read_parser = sub.add_parser("read")
    read_parser.add_argument("--root", type=Path, default=Path("."))
    read_parser.add_argument("--path", action="append", default=[])
    read_parser.add_argument("--changed-from")
    read_parser.add_argument("--topic", default="")
    read_parser.add_argument("--output", type=Path)
    read_parser.add_argument("--receipt-out", type=Path)

    sub.add_parser("self-test")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "self-test":
            self_test()
            return 0
        root = args.root.resolve()
        paths = list(args.path)
        delta_empty = False
        if args.changed_from:
            delta = changed_paths(root, args.changed_from)
            if not delta:
                delta_empty = True
            paths.extend(delta)
        if not paths:
            # An empty delta with no explicit --path has no scope to route. Say
            # so precisely rather than raising the router's "at least one
            # --path" error, which reads as a configuration fault.
            if delta_empty:
                return report_empty_delta(args.changed_from)
            raise ReadError("no --path and no --changed-from scope was given")
        config = docs_router.load_config(root)
        route = docs_router.route_payload(root, config, paths, args.topic)
        bundle, receipt = build_read_bundle(root, route)
        if args.output:
            output = args.output if args.output.is_absolute() else root / args.output
            write_text(output, bundle)
        else:
            sys.stdout.write(bundle)
        if args.receipt_out:
            receipt_out = (
                args.receipt_out
                if args.receipt_out.is_absolute()
                else root / args.receipt_out
            )
            write_text(
                receipt_out,
                json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            )
        governing = receipt.get("governing_handles", [])
        print(
            f"DOC_READ: PASS receipt={receipt['read_receipt_id']} "
            f"route={receipt['route_receipt_id']} required={len(receipt['required'])} "
            f"governing={','.join(governing) if governing else '-'} "
            f"bundle_sha256={receipt['bundle_sha256']}",
            file=sys.stderr,
        )
        return 0
    except (ReadError, docs_router.RouteError, OSError) as exc:
        print(f"DOC_READ_FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
