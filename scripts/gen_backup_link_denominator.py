#!/usr/bin/env python3
"""Regenerate the measured identities in the #974 backup-link denominator.

The frozen evidence at ``scripts/testdata/work-unit-gate/backup-link/`` is
committed, and its ``manifest_identities`` member records what each affected
manifest hashed to at the time the fixture was last written. Every later commit
that touches one of those manifests therefore makes the recorded
``current_blob_sha256`` stale, and ``test_01_denominator`` in
``scripts/tests/test_backup_dependency_link.py`` fails on a clean checkout
because it compares the recorded digest against the live tree. Until now there
was no sanctioned way to refresh those digests, so the only way to make the gate
green was to hand-edit them, which is precisely what a frozen-evidence
instrument must not require. This script is that path.

It is deliberately narrow. It may rewrite these measured fields and nothing
else:

* ``manifest_identities[*].current_blob_sha256``
* ``manifest_identities[*].byte_identical_since_base``
* ``dependency_edges[*].line``
* ``denominator_digest``

Every other member -- ``issue``, ``base``, ``frozen_base``, ``cases``,
``affected_manifests``, the identity of each edge, and ``unchanged_since_base``
-- is scope, admission and edge evidence, and a regeneration that changed any of
them would be a different and much larger decision. The script refuses to write
when anything else would move, and it refuses to write when a recorded
``base_blob_sha256`` no longer matches the frozen base commit, because that
means the base itself moved and the whole denominator needs re-admission rather
than a refresh.

A recorded ``line`` is measured the same way a digest is: it is re-derived by
locating the edge's own ``declaration`` text in the live manifest, and the
regeneration aborts unless that declaration occurs exactly once, so the number
can only ever follow the declaration it is an anchor for. It is never a
hand-counted line. Note that the gate module's own docstring argues source
anchors should bind to declaration text rather than to line numbers, while case
1 still compares against the recorded number; re-measuring the number keeps the
recorded value true without narrowing or removing that comparison, which is a
root decision this script does not touch.

The digest that gets recorded is taken over the committed blob
(``git cat-file blob HEAD:<path>``), not over the working-tree bytes. The gate
itself measures ``path.read_bytes()``, and for a file governed by
``core.autocrlf`` those two differ on a CRLF checkout, so a fixture value
captured from a working tree is a property of the machine that wrote it: the
committed Cargo.lock identity in this fixture is the CRLF-form digest of a
``Cargo.lock`` blob from several commits earlier, which matches no committed
tree state on any platform. Recording the committed blob is reproducible on any
checkout and is a digest of an actual tree state, which is what committed
evidence has to be. On a checkout that normalises line endings (CI, and any
clone with ``core.autocrlf=false``) the working tree equals the blob and the
gate compares like with like; on a CRLF checkout of a ``text=auto`` file the
gate stays red, which is a true report about that working tree.

Proof ceiling: regenerates measured manifest digests for the #974 backup-link
denominator fixture only. It asserts no dependency, edge, boundary or
implementation property, and it never edits a manifest, the lockfile, or a test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "scripts" / "testdata" / "work-unit-gate" / "backup-link" / "denominator.json"
GIT_TIMEOUT = 300

# Members a regeneration may not touch. Anything outside this set, plus the
# measured identity fields, the measured edge line and the digest, is admission
# evidence. ``dependency_edges`` is guarded field by field in
# ``assert_only_identities_moved`` rather than listed here, because its ``line``
# is measured while the edge it anchors is not.
FROZEN_MEMBERS = (
    "issue",
    "base",
    "frozen_base",
    "cases",
    "affected_manifests",
    "unchanged_since_base",
)


class RegenerationRefused(RuntimeError):
    """Raised when a refresh would move something other than identity data."""


def sha256_hex(data: bytes) -> str:
    """Return the hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def git_blob(relative: str, rev: str) -> bytes:
    """Return the committed bytes of ``relative`` at ``rev``."""
    proc = subprocess.run(
        ["git", "cat-file", "blob", f"{rev}:{relative}"],
        cwd=ROOT,
        capture_output=True,
        timeout=GIT_TIMEOUT,
    )
    if proc.returncode != 0:
        raise RegenerationRefused(
            f"cannot read {relative!r} at {rev}; the recorded identity has no "
            "readable source, so refreshing it would invent a digest",
        )
    return proc.stdout


def canonical_denominator_bytes(obj: dict) -> bytes:
    """Return the canonical serialisation ``denominator_digest`` is taken over.

    Restated here rather than imported so this script stays independent of the
    gate module it maintains: if the two ever disagree, the gate is the
    authority and this script must fail loudly, not quietly re-emit its own
    idea of the rule. The rule is the one the gate documents -- drop the
    ``denominator_digest`` member, then encode the rest as UTF-8 JSON with
    sorted keys, no whitespace and no non-ASCII escaping.
    """
    payload = {k: v for k, v in obj.items() if k != "denominator_digest"}
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def refreshed(fixture: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Return the fixture with re-measured identities, and what changed."""
    base = str(fixture["base"])
    updated = json.loads(json.dumps(fixture))  # deep copy, order preserved
    changes: list[str] = []

    for entry in updated["manifest_identities"]:
        relative = str(entry["manifest"])
        base_digest = sha256_hex(git_blob(relative, base))
        current_digest = sha256_hex(git_blob(relative, "HEAD"))
        identical = base_digest == current_digest

        if entry["base_blob_sha256"] != base_digest:
            raise RegenerationRefused(
                f"recorded base digest for {relative} is "
                f"{entry['base_blob_sha256']} but {base}:{relative} hashes to "
                f"{base_digest}; the frozen base moved, so this denominator "
                "needs re-admission, not a refresh",
            )
        if entry["current_blob_sha256"] != current_digest:
            changes.append(
                f"{relative}: current_blob_sha256 "
                f"{entry['current_blob_sha256']} -> {current_digest}",
            )
            entry["current_blob_sha256"] = current_digest
        if entry["byte_identical_since_base"] is not identical:
            changes.append(
                f"{relative}: byte_identical_since_base "
                f"{entry['byte_identical_since_base']} -> {identical}",
            )
            entry["byte_identical_since_base"] = identical

    for edge in updated["dependency_edges"]:
        relative = str(edge["manifest"])
        declaration = str(edge["declaration"])
        lines = git_blob(relative, "HEAD").decode("utf-8").splitlines()
        occurrences = [
            index + 1 for index, text in enumerate(lines)
            if text.strip() == declaration
        ]
        if len(occurrences) != 1:
            raise RegenerationRefused(
                f"{relative} holds {declaration!r} {len(occurrences)} times at "
                "HEAD; a line number cannot anchor an ambiguous declaration, so "
                "refusing to record one",
            )
        if edge["line"] != occurrences[0]:
            changes.append(
                f"{relative}::{edge['dependency']}: line "
                f"{edge['line']} -> {occurrences[0]}",
            )
            edge["line"] = occurrences[0]

    digest = sha256_hex(canonical_denominator_bytes(updated))
    if updated["denominator_digest"] != digest:
        changes.append(
            f"denominator_digest {updated['denominator_digest']} -> {digest}",
        )
        updated["denominator_digest"] = digest
    return updated, changes


def assert_only_identities_moved(original: dict, updated: dict) -> None:
    """Refuse a refresh that moved scope, admission or edge evidence.

    ``line`` is excluded from the edge comparison because re-measuring it is the
    point; every other field of every edge is the admitted edge itself, so this
    fails if a regeneration ever added, dropped, reordered or re-described an
    edge rather than re-anchoring one.
    """
    for member in FROZEN_MEMBERS:
        if original[member] != updated[member]:
            raise RegenerationRefused(
                f"refusing to write: regeneration changed {member!r}, which is "
                "admission evidence and not a measured identity",
            )
    if set(original) != set(updated):
        raise RegenerationRefused(
            "refusing to write: regeneration added or dropped a denominator member",
        )
    if len(original["manifest_identities"]) != len(updated["manifest_identities"]):
        raise RegenerationRefused(
            "refusing to write: regeneration changed the identity count",
        )
    for before, after in zip(
        original["manifest_identities"], updated["manifest_identities"],
    ):
        if before["manifest"] != after["manifest"]:
            raise RegenerationRefused(
                "refusing to write: regeneration reordered the identities",
            )
    if len(original["dependency_edges"]) != len(updated["dependency_edges"]):
        raise RegenerationRefused(
            "refusing to write: regeneration changed the dependency edge count",
        )
    for before, after in zip(
        original["dependency_edges"], updated["dependency_edges"],
    ):
        stripped = {k: v for k, v in after.items() if k != "line"}
        if {k: v for k, v in before.items() if k != "line"} != stripped:
            raise RegenerationRefused(
                "refusing to write: regeneration changed an edge other than its "
                f"measured line ({before.get('manifest')}::"
                f"{before.get('dependency')})",
            )


def render(fixture: dict) -> bytes:
    """Serialise a denominator exactly as the committed fixture is written.

    Written as bytes with explicit LF terminators on purpose: a text-mode write
    translates every newline to CRLF on Windows, and ``*.json`` is pinned to
    ``eol=lf`` by ``.gitattributes``, so a text-mode write would leave the
    working tree disagreeing with what gets committed and would make the
    committed bytes depend on the machine that ran the refresh.
    """
    text = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    return text.encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="gen_backup_link_denominator.py",
        description=(
            "Re-measure the #974 backup-link denominator manifest identities. "
            "Default is --check, which reports staleness and writes nothing."
        ),
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="rewrite the fixture with the re-measured identities",
    )
    arguments = parser.parse_args(argv)

    original_bytes = FIXTURE.read_bytes()
    original = json.loads(original_bytes.decode("utf-8"))

    try:
        updated, changes = refreshed(original)
        assert_only_identities_moved(original, updated)
    except RegenerationRefused as refusal:
        print(f"BACKUP_LINK_DENOMINATOR_REFUSED: {refusal}", file=sys.stderr)
        return 2

    if not changes:
        print("BACKUP_LINK_DENOMINATOR_OK: every recorded identity is current")
        return 0

    for change in changes:
        print(f"stale: {change}")
    if not arguments.write:
        print(
            "BACKUP_LINK_DENOMINATOR_STALE: the committed identities do not "
            f"describe HEAD; regenerate with `python scripts/"
            f"{Path(__file__).name} --write`",
        )
        return 1

    rendered = render(updated)
    if rendered == original_bytes:
        print("BACKUP_LINK_DENOMINATOR_OK: nothing to write")
        return 0
    FIXTURE.write_bytes(rendered)
    print(
        f"BACKUP_LINK_DENOMINATOR_REFRESHED: rewrote {len(changes)} measured "
        f"field(s) in {FIXTURE.relative_to(ROOT).as_posix()}",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
