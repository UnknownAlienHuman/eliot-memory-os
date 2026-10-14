#!/usr/bin/env python3
"""Hardened front door for the sharded-documentation verifier and generator.

The byte-preserving sharding implementation remains in ``docs_shards_core``.
This front door owns verified-reader navigation text, portable Markdown checks,
and the generated Decision Anchor projection derived from canonical A16.1.
"""

from __future__ import annotations

import argparse
import html
import os
import sys
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any, Sequence

import docs_shards_core as _core
from docs_shards_core import *  # noqa: F403
from docs_shards_lib import decision_anchors as _decision_anchors

DOC_LINK_EXACT_CASE_V1 = "eliot-doc-link-exact-case-v1"
LINK_SCAN_SKIP_PARTS = {
    ".git",
    ".idea",
    ".vscode",
    ".eliot",
    ".eliot-docs",
    ".codebase-memory",
    "__pycache__",
    "target",
    "dist",
    "node_modules",
    "obj",
    "bin",
}

_core_patch_navigation_surfaces = _core.patch_navigation_surfaces
_core_verify_generated_surfaces = _core.verify_generated_surfaces
_core_migrate = _core.migrate
_core_self_test = _core.self_test


def routing_block(
    relative_protocol: str = "docs/architecture/READING_PROTOCOL.md",
) -> str:
    if relative_protocol != "docs/architecture/READING_PROTOCOL.md":
        return f"""## Mandatory documentation reading

Follow the [verified reading protocol]({relative_protocol}). From the repository
root, read the owning Issue's `## Read` with the actual mutable paths:

```text
python scripts/docs_read.py read --issue <number> --path <repository/path> --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Open the verified bundle and read every required item before editing. Record its
route/read identities, hashes and reading attestation. Reroute when scope changes;
without an owning Issue, use the protocol's path/topic mode. Reading references
do not grant write scope. Do not substitute a legacy compatibility map for a read."""
    return f"""## Mandatory documentation routing

Every implementation Issue lists what to read in a `## Read` section: handle
selectors (`I5.19`, `I1.1..I1.8`, `A4.*`, `APPENDIX-L`) and repository files,
one per list item. Draft it with `python scripts/docs_router.py route --path
<repository/path> --format issue` and keep only what the change needs.

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_read.py read --issue <number> --path <repository/path> --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

With `--issue`, the required reading is the Decision Safety Floor, the items the
Issue declares and the nearest `AGENTS.md` files; path routes become optional
pointers. Without an Issue, use `--path <repository/path> --topic "<causal
property>"` for every mutable path family, or `--changed-from origin/main` for
the complete branch delta. Open the verified bundle and read every required
item before mutation. A route alone is navigation, not reading evidence.

An Issue-only read without paths is declaration-only navigation. Before editing,
supply the actual mutable `--path` families or `--changed-from` scope. Reading
references do not grant write scope. An offline `--issue-body` capture preserves
its exact body identity; it does not prove that the Issue is current.

Record the route receipt ID, read receipt ID, declared reading or matched
routes, required handles, fragment paths and SHA-256 values, verified bundle
SHA-256, and explicit reading attestation in the work unit or pull request.
Optional fragments are loaded only when the current decision crosses their
stated boundary. A legacy `ELIOT_*` compatibility map is never an acceptable
read receipt.

If the Issue has no `## Read` section, a declared item does not resolve, no
non-baseline route matches a path read without an Issue, a required item is
stale or missing, or scope expands beyond the receipt, stop and repair the Issue
or the route; silence is not permission. See [`{relative_protocol}`]({relative_protocol})."""


def patch_navigation_surfaces(root: Path) -> None:
    _core_patch_navigation_surfaces(root)

    for relative, protocol in (
        ("README.md", "docs/architecture/READING_PROTOCOL.md"),
        ("docs/README.md", "architecture/READING_PROTOCOL.md"),
        ("docs/PROJECT_MAP.md", "architecture/READING_PROTOCOL.md"),
    ):
        path = root / relative
        if not path.exists():
            continue
        block = (
            "## Documentation entry point\n\n"
            f"Start with the [mandatory verified-reading protocol]({protocol}), "
            "then run `python scripts/docs_read.py read ...` for the exact "
            "repository paths and causal property being changed. Open the "
            "verified bundle and record its read receipt before mutation. "
            "A route alone is navigation, not reading evidence. The stable "
            "`ELIOT_*` files are compatibility maps, not task prompts."
        )
        _core.write_utf8(
            path,
            _core.insert_or_replace_block(_core.read_utf8(path), block),
        )

    pr_template = root / ".github/pull_request_template.md"
    if pr_template.exists():
        block = """## Documentation read receipt

- Reader command:
- Route receipt ID:
- Read receipt ID:
- Matched route IDs:
- Required handles, fragment paths, and SHA-256 values read:
- Verified bundle SHA-256:
- Optional expansions opened and reason:
- Explicit reading attestation:
"""
        _core.write_utf8(
            pr_template,
            _core.insert_or_replace_block(
                _core.read_utf8(pr_template),
                block,
                after_first_heading=False,
            ),
        )


def render_reading_protocol(pair_key_value: str) -> str:
    return f"""{_core.GENERATED_MARKER}
# Mandatory agent documentation protocol

The documentation is a routed contract graph, not a book-shaped prompt.

## Required sequence

1. Resolve current repository authority through `AGENTS.md`, `WORKFLOW.md`, and
   `workstreams/ACTIVE.toml`.
2. The owning Issue lists what to read in a `## Read` (or `## Читать`)
   section: one handle selector (`I5.19`, `I1.1..I1.8`, `A4.*`, `APPENDIX-L`)
   or one repository file per list item, optionally followed by a comment.
   Draft it from the path routes and keep only what the change needs:

   ```text
   python scripts/docs_router.py route --path <repository/path> --format issue
   ```

3. Run the verified reader from the repository root:

   ```text
   python scripts/docs_read.py read --issue <number> --path <repository/path> --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
   ```

   With `--issue` (or `--issue-body <file>` offline), the required reading is
   the Decision Safety Floor, the items the Issue declares and the nearest
   `AGENTS.md` files; path routes become optional pointers. Without an Issue,
   repeat `--path` for every mutable path family with a `--topic`, or use
   `--changed-from origin/main` for the complete branch delta, including
   deletions.
   An Issue-only read with no paths is declaration-only navigation; before
   editing, supply the actual mutable paths. An offline body capture preserves
   exact bytes but does not establish current Issue authority.
4. Open the verified bundle and read every required file/fragment before
   mutation. A route alone is navigation, not reading evidence.
5. Inspect optional one-hop fragments only when the current decision crosses
   their boundary.
6. Record the route/read receipt IDs, declared reading or matched routes,
   required handles, fragment paths and SHA-256 values, verified bundle SHA-256,
   and explicit reading attestation in the work unit or pull request.
7. Re-run the reader when the Issue reading, changed path, causal property,
   authority boundary, or evidence scope changes.

Current normative pair: `{pair_key_value}`.

## Fail-closed cases

Do not mutate the repository when:

- the Issue has no `## Read` section or a declared item does not resolve;
- no non-baseline route matches a material path read without an Issue;
- a required handle cannot be resolved;
- a routed file/fragment hash or byte count differs from the read receipt;
- the verified bundle cannot be materialized;
- the shard manifest cannot reconstruct the adopted source hash;
- an incoming legacy anchor resolves only to a compatibility map and the
  canonical fragment was not opened;
- the task expands beyond the read receipt without a new reader invocation.

## Context discipline

The reader returns decision-sufficient fragments, not every related section.
The compatibility maps, full handle index, Decision Anchor index, and assembled
books are navigation or audit surfaces. They are prohibited as default agent
context.

Human routes summarize optional pointers by default. Use `--full-pointers` or
`--format json` only when inspecting an optional boundary; the reader bundle
contains required content only.

To inspect all changed paths at once:

```text
python scripts/docs_read.py read --changed-from origin/main --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

The generated bundle and receipts are local evidence and must not be committed.

To verify the documentation graph and reader implementation:

```text
python scripts/docs_shards.py verify --root .
python scripts/docs_router.py check --root .
python scripts/docs_read.py self-test
```
"""


def render_architecture_readme(pair_key_value: str) -> str:
    return f"""{_core.GENERATED_MARKER}
# ELIOT documentation router

Do not open the former monoliths as task context.

1. Read [`READING_PROTOCOL.md`](READING_PROTOCOL.md).
2. Run the verified reader for the exact path and causal property:

   ```text
   python scripts/docs_read.py read --path <repository/path> --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
   ```

3. Open the verified bundle and read every required item before mutation.
4. Record the route/read receipt IDs, verified bundle SHA-256, matched routes,
   required handles, and explicit reading attestation.

A route alone is navigation, not reading evidence. The local
`.eliot/docs-read-bundle.md` and read receipt are not committed.

## Navigation

- [Mandatory verified-reading protocol](READING_PROTOCOL.md)
- [Task/path route matrix](ROUTES.md)
- [Exact numeric-handle index](HANDLE_INDEX.md)
- [Decision Anchor index](DECISION_ANCHOR_INDEX.md)
- [Architecture bounded index](architecture/README.md)
- [Implementation bounded index](implementation/README.md)
- [Architecture authority](../ARCHITECTURE_CONTRACT.md)
- [Dependency policy](../DEPENDENCY_POLICY.md)
- [Pre-sharding navigation snapshots](navigation-history/)

Normative pair: `{pair_key_value}`.

`ELIOT_ARCHITECTURE.md` and `ELIOT_IMPLEMENTATION.md` remain only to preserve
incoming file and heading links. Their canonical content has moved to fragments.
"""


def render_topic_index(old_index: str) -> str:
    return _core.render_topic_index(old_index)


def _relative_parts(root: Path, requested: Path) -> tuple[str, ...] | None:
    root_absolute = Path(os.path.abspath(root))
    requested_absolute = Path(os.path.abspath(requested))
    try:
        return requested_absolute.relative_to(root_absolute).parts
    except ValueError:
        return None


def _case_resolution(root: Path, requested: Path) -> tuple[str, Path | None]:
    parts = _relative_parts(root, requested)
    if parts is None:
        return "outside", None
    current = Path(os.path.abspath(root))
    for part in parts:
        if not current.is_dir():
            return "missing", None
        entries = {entry.name: entry for entry in current.iterdir()}
        exact = entries.get(part)
        if exact is not None:
            current = exact
            continue
        folded = [
            entry
            for name, entry in entries.items()
            if name.casefold() == part.casefold()
        ]
        if folded:
            return "case_mismatch", folded[0]
        return "missing", None
    return "exact", current


def _skip_markdown_path(root: Path, path: Path) -> bool:
    parts = _relative_parts(root, path)
    return parts is None or any(part in LINK_SCAN_SKIP_PARTS for part in parts)


def verify_markdown_links(root: Path) -> dict[str, int]:
    root = root.resolve()
    markdown_files = sorted(
        path
        for path in root.rglob("*.md")
        if not _skip_markdown_path(root, path)
    )
    anchor_cache: dict[Path, set[str]] = {}
    checked = 0
    failures: list[str] = []

    for source in markdown_files:
        source_text = _core.read_utf8(source)
        for _, _, raw_dest in _core.find_link_destinations(source_text):
            dest, _ = _core.unwrap_destination(raw_dest)
            dest = html.unescape(dest)
            if _core.should_skip_destination(dest):
                continue
            parsed = urllib.parse.urlsplit(dest)
            if parsed.scheme or parsed.netloc:
                continue
            path_part = urllib.parse.unquote(parsed.path)
            fragment = urllib.parse.unquote(parsed.fragment)
            if path_part.startswith("/"):
                requested = root / path_part.lstrip("/")
            elif path_part:
                requested = source.parent / path_part
            else:
                requested = source

            status, resolved = _case_resolution(root, requested)
            checked += 1
            relative_source = source.relative_to(root)
            if status == "outside":
                failures.append(f"{relative_source} -> escapes repo: {dest}")
                continue
            if status == "case_mismatch":
                actual = (
                    resolved.relative_to(root).as_posix()
                    if resolved is not None
                    else "<unknown>"
                )
                failures.append(
                    f"{relative_source} -> case mismatch: {dest} "
                    f"(actual component: {actual})"
                )
                continue
            if status == "missing" or resolved is None:
                failures.append(f"{relative_source} -> missing: {dest}")
                continue
            target = resolved.resolve()
            try:
                target.relative_to(root)
            except ValueError:
                failures.append(f"{relative_source} -> escapes repo: {dest}")
                continue
            if (
                fragment
                and target.is_file()
                and target.suffix.lower() in (".md", ".markdown")
            ):
                anchors = anchor_cache.setdefault(
                    target,
                    _core.markdown_anchors(_core.read_utf8(target)),
                )
                if fragment not in anchors:
                    failures.append(
                        f"{relative_source} -> missing anchor "
                        f"{target.relative_to(root)}#{fragment}"
                    )

    if failures:
        preview = "\n".join(f"  - {failure}" for failure in failures[:100])
        suffix = (
            ""
            if len(failures) <= 100
            else f"\n  ... {len(failures) - 100} more"
        )
        raise DocsError(  # noqa: F405
            f"broken Markdown links ({len(failures)}):\n{preview}{suffix}"
        )
    return {"markdown_files": len(markdown_files), "links_checked": checked}


def verify_generated_surfaces(
    root: Path,
    manifests: dict[str, dict[str, Any]],
) -> None:
    _core_verify_generated_surfaces(root, manifests)
    try:
        _decision_anchors.verify_generated(root)
    except _decision_anchors.DecisionAnchorError as exc:
        raise DocsError(str(exc)) from exc  # noqa: F405


def migrate(root: Path) -> None:
    _core_migrate(root)
    try:
        _decision_anchors.write_generated(root)
    except _decision_anchors.DecisionAnchorError as exc:
        raise DocsError(str(exc)) from exc  # noqa: F405


def self_test() -> None:
    _core_self_test()
    _decision_anchors.self_test()

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        docs = root / "docs"
        docs.mkdir()
        (docs / "Target.md").write_text("# Target\n", encoding="utf-8")
        (root / "README.md").write_text(
            "[target](docs/Target.md#target)\n",
            encoding="utf-8",
        )
        generated = root / ".eliot"
        generated.mkdir()
        (generated / "generated.md").write_text(
            "[broken](missing.md)\n",
            encoding="utf-8",
        )
        result = verify_markdown_links(root)
        if result["markdown_files"] != 2:
            raise DocsError(  # noqa: F405
                "generated-directory exclusion self-test failed"
            )

        status, _ = _case_resolution(root, docs / "target.md")
        if status != "case_mismatch":
            raise DocsError("exact-case helper self-test failed")  # noqa: F405

        (root / "README.md").write_text(
            "[target](docs/target.md)\n",
            encoding="utf-8",
        )
        try:
            verify_markdown_links(root)
        except DocsError as exc:  # noqa: F405
            if "case mismatch" not in str(exc):
                raise
        else:
            raise DocsError("case-mismatch link self-test failed")  # noqa: F405

    print("DOC_SHARDS_HARDENING_SELF_TEST: PASS cases=7")


def _refresh_indexes(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="docs_shards.py refresh-indexes",
        description="Regenerate deterministic documentation indexes.",
    )
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(list(argv))
    try:
        if args.check:
            _decision_anchors.verify_generated(args.root)
            action = "CHECK"
        else:
            _decision_anchors.write_generated(args.root)
            _decision_anchors.verify_generated(args.root)
            action = "WRITE"
        print(
            "DOC_DECISION_ANCHOR_INDEX: PASS "
            f"action={action} schema={_decision_anchors.SCHEMA}"
        )
        return 0
    except _decision_anchors.DecisionAnchorError as exc:
        print(f"DOC_DECISION_ANCHOR_INDEX_FAIL: {exc}", file=sys.stderr)
        return 1


def sync_reading_protocol(root: Path, *, check: bool = False) -> list[str]:
    """Refresh managed reading instructions without migrating the books.

    The PR template carries a separate machine-evidence contract and is not a
    routing-block target. Historical navigation snapshots are not rewritten.
    """
    root = root.resolve()
    pair = _core.load_simple_toml(root / "docs/normative-pair.toml")
    pair_identity = _core.pair_key(
        str(pair["architecture_sha256"]), str(pair["implementation_sha256"])
    )
    if pair.get("pair_key") != pair_identity:
        raise DocsError("reading protocol requires the current normative pair")
    wanted: dict[Path, str] = {}
    for path in sorted(root.rglob("AGENTS.md")):
        relative = path.relative_to(root)
        if any(part in LINK_SCAN_SKIP_PARTS or part == "navigation-history" for part in relative.parts):
            continue
        if not path.resolve().is_relative_to(root):
            raise DocsError(f"reading instruction escapes repository: {relative}")
        old = path.read_bytes().decode("utf-8")
        if _core.ROUTING_START not in old:
            continue
        protocol = os.path.relpath(root / "docs/architecture/READING_PROTOCOL.md", path.parent).replace("\\", "/")
        wanted[path] = _core.insert_or_replace_block(old, routing_block(protocol))
    for name in ("WORKFLOW.md", "START.md"):
        path = root / name
        if path.is_file():
            old = path.read_bytes().decode("utf-8")
            if _core.ROUTING_START in old:
                wanted[path] = _core.insert_or_replace_block(old, routing_block())
    wanted[root / "docs/architecture/READING_PROTOCOL.md"] = render_reading_protocol(pair_identity)
    changed = [str(path.relative_to(root)).replace("\\", "/") for path, text in wanted.items()
               if path.read_bytes() != text.encode("utf-8")]
    if check and changed:
        raise DocsError("reading protocol surfaces are stale: " + ", ".join(changed))
    if not check:
        for path, text in wanted.items():
            if path.read_bytes() != text.encode("utf-8"):
                _core.write_utf8(path, text)
    return changed


def _sync_reading_protocol(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="docs_shards.py sync-reading-protocol")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(list(argv))
    try:
        changed = sync_reading_protocol(args.root, check=args.check)
        print("DOC_READING_PROTOCOL: PASS action=" + ("CHECK" if args.check else "WRITE")
              + f" changed={len(changed)}")
        return 0
    except (DocsError, OSError, UnicodeError, KeyError) as exc:
        print(f"DOC_READING_PROTOCOL_FAIL: {exc}", file=sys.stderr)
        return 1


_core.routing_block = routing_block
_core.patch_navigation_surfaces = patch_navigation_surfaces
_core.render_reading_protocol = render_reading_protocol
_core.render_architecture_readme = render_architecture_readme
_core.render_topic_index = render_topic_index
_core.verify_markdown_links = verify_markdown_links
_core.verify_generated_surfaces = verify_generated_surfaces
_core.migrate = migrate
_core.self_test = self_test


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "refresh-indexes":
        return _refresh_indexes(arguments[1:])
    if arguments and arguments[0] == "sync-reading-protocol":
        return _sync_reading_protocol(arguments[1:])
    return _core.main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
