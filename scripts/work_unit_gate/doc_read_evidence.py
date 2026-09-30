#!/usr/bin/env python3
"""Executable pre-merge contract for documentation read evidence (#2965).

This module is the SINGLE authority that decides whether a pull request carries
current, non-empty, reproducibly verifiable documentation routing/read evidence
for the FINAL merge candidate. It reuses the existing deterministic algorithms as
the only matching/reader implementations and never re-implements route matching,
handle expansion, canonicalization or receipt hashing:

* ``docs_router`` (the hardened front door over ``docs_router_core``) supplies
  ``load_config``, ``route_payload``, ``normalize_repo_path`` and
  ``sha256_file``.
* ``docs_read`` supplies ``build_read_bundle``, which verifies the current
  required bytes and produces the deterministic ``eliot-doc-read-v1`` receipt
  (route/read receipt IDs, bundle SHA-256 and byte count).

A body-supplied ID is NEVER accepted without recomputing it here against the
final merge candidate. Prose cannot make an empty, fabricated, stale,
partial-path, duplicate-block or placeholder envelope pass.

The conditional work-unit/checklist state (issue #2965 item 10) is a SEPARATE,
four-valued condition: ``not_required``, ``required_verified``,
``required_missing`` and ``stale``. Whether a checklist is required is a fact of
the committed assignment contract, decided from that contract's active rows and
never guessed from a filesystem path; the contract's active issue set is also the
independent expected set the recorded state is judged against, never a set the
envelope itself supplied. A missing required checklist blocks the merge with the
checklist cause alone and is never conflated with a documentation-read failure.

The OUTER envelope is versioned ``eliot-doc-read-pr-evidence-v2``; commit
semantics are never silently added to ``eliot-doc-read-v1``. Every recorded
field is compared against a fresh recomputation for the given base/candidate.

No receipt registry, cloud service, second router, second documentation
registry or committed ``.eliot`` state is introduced. Diagnostics name bounded
paths/field classes and expected/actual digests; they never dump full normative
contents.

Merge-boundary integration (issue #2965 item 12/13): the real root/controller
merge action must invoke

    python -m scripts.work_unit_gate doc-read-evidence \\
        --base <sha> --candidate <sha-or-tree> --pr-body <file>

on the FINAL merge candidate and refuse a nonzero exit. This repository
supplies that single stable command. Whether the root/controller merge action
that must consume it lives inside this repository or in the controller
checkout is resolved by :func:`merge_integration_status`; when it is external,
its exact integration/config version is a blocking owner action and part of
acceptance. It is never simulated here, and no second GitHub-Action-only
verifier with different semantics is introduced.
"""
from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "scripts"))

import docs_read as _read  # noqa: E402
import docs_router as _router  # noqa: E402

OUTER_SCHEMA = "eliot-doc-read-pr-evidence-v2"
INNER_SCHEMA = "eliot-doc-read-v1"
READER_CONTRACT = "scripts/docs_read.py@" + INNER_SCHEMA
ROUTER_CONTRACT = "scripts/docs_router.py+scripts/docs_router_core.py@eliot-doc-routes-v1"
ROUTE_RULES_PATH = "docs/architecture/route-rules.toml"
HANDLE_INDEX_PATH = "docs/architecture/handle-index.json"
PAIR_RECEIPT_PATH = "docs/normative-pair.toml"
COHORT_LOCK_PATH = ".github/work-unit-cohort.toml"

# The single merge-boundary command the root/controller merge action must run.
SHARED_COMMAND = (
    "python -m scripts.work_unit_gate doc-read-evidence "
    "--base <sha> --candidate <sha-or-tree> --pr-body <file>"
)

# Exactly one fenced canonical-JSON marker block is required. Duplicate,
# overlapping or missing markers are typed failures, never "best effort".
BLOCK_START = "<!-- eliot-doc-read-evidence:v2:start -->"
BLOCK_END = "<!-- eliot-doc-read-evidence:v2:end -->"

# Placeholder prose must never stand in for evidence (issue #2965 item 6).
# Whether a value counts as a placeholder depends on the FIELD'S MEANING, not
# on substring coincidence (audit 5919739325 defect 1): descriptive text
# (topic, attestation statement, optional-expansion reason) may legitimately
# discuss placeholders, Rust generics ("Vec<T>") or defects, while a machine
# identity, repository path or digest can never legitimately contain them.
# Identities, hashes, changed paths and the final-candidate comparison stay
# strict by type and recomputation (exact digests, closed schemas,
# final-tree/path/route comparison); only the prose reading of a value is
# scoped to whole-value evasion. There is one validator (_text), not two, and
# no blanket text exemption: a descriptive field that IS the placeholder still
# fails with the same typed code.
_PLACEHOLDER_TOKENS = (
    "see receipt",
    "as listed above",
    "see above",
    "read manually",
    "manually read",
    "not applicable",
    "none recorded",
    "to be determined",
    "placeholder",
    "tbd",
)
_SENTINEL_TOKENS = ("<path>", "<sha>", "<digest>", "<issue title>", "<topic>")
# Whole-value evasions: the value IS the placeholder instead of the evidence.
# The plural "see receipts" is the punctuated whole-value form that the
# singular substring token alone would miss under whole-value comparison.
_WHOLE_VALUE_EVASIONS = _PLACEHOLDER_TOKENS + ("see receipts",)
_TRAILING_EVASION_PUNCTUATION = ".!?:;,"
_WHOLE_SLOT_RE = re.compile(r"\A<[^<>]*>\Z")
_SHA256_HEX = re.compile(r"\A[0-9a-f]{64}\Z")
_SHA256_PREFIXED = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_FULL_COMMIT = re.compile(r"\A[0-9a-f]{40}\Z")
_LOOSE_REV = re.compile(r"\A[0-9a-fA-F]{7,64}\Z")

MAX_ITEMS = 512
MAX_TEXT = 4096
MAX_DIAGNOSTIC_PATHS = 40
GIT_TIMEOUT_S = 60

# Honest proof ceiling (issue #2965 "Proof ceiling"). A pass proves the final
# candidate deterministically resolves to a particular current route/read
# bundle and that the PR records that exact evidence. It does NOT prove that a
# human or model understood the text.
PROOF_CEILING = (
    "VERIFIED_CURRENT_DOCUMENTATION_EVIDENCE_PLUS_ATTRIBUTED_READING_ATTESTATION; "
    "this gate cannot observe comprehension; the reading attestation is a "
    "separate attributed claim made after machine validation."
)


class EvidenceFailure(str, Enum):
    """Stable typed failure codes (issue #2965 item 11). Exact, never renamed."""

    EMPTY_DOCUMENTATION_EVIDENCE = "EMPTY_DOCUMENTATION_EVIDENCE"
    MALFORMED_EVIDENCE_BLOCK = "MALFORMED_EVIDENCE_BLOCK"
    UNKNOWN_OR_DUPLICATE_BLOCK = "UNKNOWN_OR_DUPLICATE_BLOCK"
    BASE_OR_CANDIDATE_MISMATCH = "BASE_OR_CANDIDATE_MISMATCH"
    STALE_SOURCE_TREE = "STALE_SOURCE_TREE"
    UNCOVERED_CHANGED_PATH = "UNCOVERED_CHANGED_PATH"
    ROUTE_RECEIPT_MISMATCH = "ROUTE_RECEIPT_MISMATCH"
    READ_RECEIPT_MISMATCH = "READ_RECEIPT_MISMATCH"
    PAIR_KEY_MISMATCH = "PAIR_KEY_MISMATCH"
    ROUTE_SET_MISMATCH = "ROUTE_SET_MISMATCH"
    REQUIRED_ITEM_MISMATCH = "REQUIRED_ITEM_MISMATCH"
    BUNDLE_DIGEST_MISMATCH = "BUNDLE_DIGEST_MISMATCH"
    ROUTER_INPUT_MISMATCH = "ROUTER_INPUT_MISMATCH"
    ATTESTATION_MISSING = "ATTESTATION_MISSING"
    CHECKLIST_REQUIRED_MISSING = "CHECKLIST_REQUIRED_MISSING"
    LOCAL_EVIDENCE_COMMITTED = "LOCAL_EVIDENCE_COMMITTED"


class ChecklistState(str, Enum):
    """Conditional work-unit/checklist state (issue #2965 item 10).

    The four values are exhaustive and mutually exclusive; every work unit lands
    in exactly one of them:

    ``not_required``
        The committed assignment contract declares no active row that would
        require a checklist record for the delivered work unit.
    ``required_verified``
        The contract requires one, the envelope names exactly that issue, and the
        record is bound to the FINAL candidate tree. Established by verification
        against the contract, never by the presence of a record.
    ``required_missing``
        The contract requires one and the envelope supplies no record verified
        against the final candidate tree (unrecorded, unbound, or no work unit
        identified at all while the contract carries an active row).
    ``stale``
        The contract requires one, the envelope records it, and the record is
        bound to a different candidate tree than the final one.

    Whether a checklist is required is a fact of the committed assignment
    contract, never a guess from a filesystem path. This state is a SEPARATE
    cause from any documentation-read failure: it is decided from contract rows
    and is reported as its own typed code.
    """

    NOT_REQUIRED = "not_required"
    REQUIRED_VERIFIED = "required_verified"
    REQUIRED_MISSING = "required_missing"
    STALE = "stale"


class EvidenceError(Exception):
    """Typed failure carrying a stable code and a bounded diagnostic."""

    def __init__(self, code: EvidenceFailure, detail: str = "") -> None:
        if type(code) is not EvidenceFailure:
            code = EvidenceFailure.MALFORMED_EVIDENCE_BLOCK
        self.code = code
        self.detail = str(detail)[:MAX_TEXT]
        super().__init__(f"{code.value}: {self.detail}" if self.detail else code.value)


def _fail(code: EvidenceFailure, detail: str = "") -> None:
    raise EvidenceError(code, detail)


# ---------------------------------------------------------------------------
# Bounded typed field helpers.
# ---------------------------------------------------------------------------

def _folded_whole_value(text: str) -> str:
    """Normalize a field value for whole-value evasion comparison."""
    return " ".join(text.casefold().split()).strip(_TRAILING_EVASION_PUNCTUATION)


def _is_whole_value_evasion(text: str) -> bool:
    """True when the value, taken as a whole, offers no content of its own."""
    core = _folded_whole_value(text)
    if not core or core in ("...", "…"):
        return True
    if core in _WHOLE_VALUE_EVASIONS or core in _SENTINEL_TOKENS:
        return True
    if _WHOLE_SLOT_RE.fullmatch(core):
        return True
    return False


def _is_placeholder(text: str) -> bool:
    """Strict predicate for machine-meaning fields (paths, identities, commits).

    A whole-value evasion ("see receipts", "TBD", "<path>") stands in for
    evidence. Angle slots and ellipses can never legitimately appear in a
    machine identity or repository path, so any occurrence refuses. Bare token
    *substrings* no longer refuse on their own: a genuine path may mention a
    placeholder, and set membership plus digest recomputation decides it.
    """
    if _is_whole_value_evasion(text):
        return True
    if ("<" in text and ">" in text) or "…" in text or "..." in text:
        return True
    return False


def _is_placeholder_prose(text: str) -> bool:
    """Predicate for descriptive fields (topic, attestation statement, reason).

    Only a whole-value evasion refuses: the recorded causal property,
    attestation or reason IS the placeholder instead of the real text. Longer
    prose that merely discusses placeholders, generics ("Vec<T>") or defects
    passes; blank values are still rejected by _text before this runs.
    """
    return _is_whole_value_evasion(text)


def _text(value: Any, field: str, code: EvidenceFailure, *, allow_empty: bool = False,
          descriptive: bool = False) -> str:
    if type(value) is not str:
        _fail(code, f"{field} must be a string")
    if not value.strip() and not allow_empty:
        _fail(code, f"{field} is blank")
    if len(value) > MAX_TEXT:
        _fail(code, f"{field} exceeds {MAX_TEXT} bytes")
    evasive = _is_placeholder_prose(value) if descriptive else _is_placeholder(value)
    if evasive:
        _fail(code, f"{field} is placeholder prose, not evidence")
    return value


def _sha256(value: Any, field: str, code: EvidenceFailure, *, prefixed: bool = True) -> str:
    if type(value) is not str:
        _fail(code, f"{field} must be a string sha256")
    if prefixed:
        if not _SHA256_PREFIXED.fullmatch(value):
            _fail(code, f"{field} must be sha256:<64 hex>")
    elif not _SHA256_HEX.fullmatch(value):
        _fail(code, f"{field} must be <64 hex>")
    return value


def _count(value: Any, field: str, code: EvidenceFailure) -> int:
    if type(value) is not int or value < 0 or value > (1 << 63) - 1:
        _fail(code, f"{field} must be a non-negative integer")
    return value


def _closed(value: Any, keys: tuple[str, ...], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(keys):
        _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, f"{label} must be a closed object {list(keys)}")
    return value


# ---------------------------------------------------------------------------
# Git observation: fixed, read-only, bounded. Only validated revisions reach git.
# ---------------------------------------------------------------------------

def _git(root: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments],
            capture_output=True, text=True, check=False, timeout=GIT_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        _fail(EvidenceFailure.BASE_OR_CANDIDATE_MISMATCH, f"git unavailable ({type(exc).__name__})")
    if completed.returncode != 0:
        lines = (completed.stderr or "").strip().splitlines()
        tail = lines[-1] if lines else "unknown git error"
        _fail(EvidenceFailure.BASE_OR_CANDIDATE_MISMATCH, f"git failed: {tail[:200]}")
    return (completed.stdout or "").strip()


def _resolve_tree(root: Path, revision: str, field: str) -> str:
    """Resolve a commit or tree revision to its exact full tree object id."""
    if not revision or not _LOOSE_REV.fullmatch(revision):
        _fail(EvidenceFailure.BASE_OR_CANDIDATE_MISMATCH, f"{field} is not a hexadecimal git revision")
    kind = _git(root, "cat-file", "-t", revision)
    if kind == "commit":
        tree = _git(root, "rev-parse", f"{revision}^{{tree}}")
    elif kind == "tree":
        tree = _git(root, "rev-parse", revision)
    else:
        _fail(EvidenceFailure.BASE_OR_CANDIDATE_MISMATCH, f"{field} is not a commit or tree object")
    if not re.fullmatch(r"[0-9a-f]{40}", tree):
        _fail(EvidenceFailure.BASE_OR_CANDIDATE_MISMATCH, f"{field} tree is not a full object id")
    return tree


def _changed_paths(root: Path, base_tree: str, candidate_tree: str) -> list[str]:
    """Enumerate the final changed paths with the router's deletion-aware filter.

    The diff filter is byte-for-byte the one the router front door uses
    (``--diff-filter=ACMRTUXBD``), so deletions and renames participate in the
    denominator; every emitted name goes through the router's own
    ``normalize_repo_path`` and the router's own sorted-set contract.
    """
    output = _git(
        root, "diff", "--name-only", "--diff-filter=ACMRTUXBD", "-M", base_tree, candidate_tree,
    )
    return sorted({_router.normalize_repo_path(line) for line in output.splitlines() if line.strip()})


def _materialize_full_tree(root: Path, candidate_tree: str) -> Path:
    """Export the exact candidate tree so file reads come from final-candidate bytes."""
    directory = tempfile.mkdtemp(prefix="eliot-doc-read-candidate-")
    target = Path(directory)
    with tempfile.TemporaryDirectory() as scratch:
        archive = Path(scratch) / "candidate.tar"
        try:
            with archive.open("wb") as handle:
                subprocess.run(
                    ["git", "-C", str(root), "archive", "--format=tar", candidate_tree],
                    stdout=handle, stderr=subprocess.PIPE, check=True, timeout=GIT_TIMEOUT_S,
                )
        except (subprocess.CalledProcessError, OSError, subprocess.SubprocessError) as exc:
            shutil.rmtree(target, ignore_errors=True)
            _fail(EvidenceFailure.BASE_OR_CANDIDATE_MISMATCH, f"cannot export candidate tree ({type(exc).__name__})")
        try:
            with tarfile.open(archive, "r:") as tar:
                for member in tar.getmembers():
                    name = member.name.replace("\\", "/")
                    if name.startswith("/") or ".." in Path(name).parts:
                        shutil.rmtree(target, ignore_errors=True)
                        _fail(EvidenceFailure.BASE_OR_CANDIDATE_MISMATCH, "candidate archive escapes root")
                tar.extractall(target)
        except (tarfile.TarError, OSError) as exc:
            shutil.rmtree(target, ignore_errors=True)
            _fail(EvidenceFailure.BASE_OR_CANDIDATE_MISMATCH, f"cannot extract candidate ({type(exc).__name__})")
    return target


# ---------------------------------------------------------------------------
# Bounded candidate projection with a same-tree cache (audit 5919739325
# defect 3, secondary).
#
# Filesystem closure the SOLE algorithms touch on a candidate root, enumerated
# from docs_router_core/route_payload and docs_read/build_read_bundle (no
# other reader input exists on that root):
# * the route config, handle index and normative pair, read through
#   _router.DEFAULT_CONFIG/_router.DEFAULT_INDEX/_router.DEFAULT_RECEIPT and
#   _contract_inputs;
# * the assignment contract (.github/work-unit-cohort.toml);
# * AGENTS.md EXISTENCE at the repository root and at every ancestor directory
#   of each changed path (ancestor_agent_files checks is_file only; file
#   contents are never read);
# * required/optional FILE bytes and sizes named by the baseline config lists,
#   the matched routes' config lists and the ancestor AGENTS.md set
#   (file_record during route_payload);
# * required item bytes named by route["required"] (verified_item during
#   build_read_bundle). Optional fragments and changed-path bytes are never
#   read; route matching itself is pure string comparison.
#
# The projection serves exactly that closure with real bytes taken from the
# immutable candidate TREE object: never the mutable worktree, never a
# caller-authored allowlist. AGENTS.md files are enumerated from `git ls-tree`,
# declared files come from the REAL load_config parse narrowed by the REAL
# matched_routes call, and required bytes come from the REAL route_payload
# output. A tree-absent path stays absent, so genuine "does not exist" errors
# fire identically. Anything unprovable — an unlistable tree, an unreadable
# blob, an un-normalizable path, a budget overflow, or a route/read error
# inside the phased runs — raises _ProjectionGap, and the caller falls back to
# the full tree export, which is byte-for-byte today's behavior. A projection
# is never shipped on an unproven fast path.
# ---------------------------------------------------------------------------

# Optimization bounds, not policy: exceeding them selects the full export.
_MAX_PROJECTED_FILES = 1024
_MAX_PROJECTED_BYTES = 16 * 1024 * 1024
# Same-tree materialization cache bound (immutable key: tree + topic + paths).
_MAX_CACHED_CANDIDATES = 4


class _ProjectionGap(Exception):
    """Internal: the bounded projection cannot prove equivalence; full export."""


_CANDIDATE_CACHE: OrderedDict[str, Path] = OrderedDict()
_PROJECTED_ROOTS: set[str] = set()


def _evict_all_candidates() -> None:
    while _CANDIDATE_CACHE:
        _, path = _CANDIDATE_CACHE.popitem(last=False)
        _PROJECTED_ROOTS.discard(str(path))
        shutil.rmtree(path, ignore_errors=True)


atexit.register(_evict_all_candidates)


def _cache_key(candidate_tree: str, paths: Sequence[str], topic: str) -> str:
    digest = hashlib.sha256()
    digest.update(candidate_tree.encode("utf-8"))
    digest.update(b"\0")
    digest.update(topic.encode("utf-8"))
    digest.update(b"\0")
    for entry in paths:
        digest.update(entry.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def _remember_candidate(key: str, path: Path, projected: bool) -> Path:
    while len(_CANDIDATE_CACHE) >= _MAX_CACHED_CANDIDATES:
        _, old = _CANDIDATE_CACHE.popitem(last=False)
        _PROJECTED_ROOTS.discard(str(old))
        shutil.rmtree(old, ignore_errors=True)
    _CANDIDATE_CACHE[key] = path
    if projected:
        _PROJECTED_ROOTS.add(str(path))
    return path


def _release_candidate(path: Path) -> None:
    """Release a materialized candidate root.

    Cached entries persist under their immutable key (FIFO eviction and exit
    cleanup own them); anything else is removed, preserving today's hygiene
    for non-cached materializations.
    """
    if any(path == cached for cached in _CANDIDATE_CACHE.values()):
        return
    _PROJECTED_ROOTS.discard(str(path))
    shutil.rmtree(path, ignore_errors=True)


def _used_projection(path: Path) -> bool:
    return str(path) in _PROJECTED_ROOTS


def _candidate_tree_names(root: Path, candidate_tree: str) -> set[str]:
    """Every blob path in the candidate tree, from the immutable object store."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "ls-tree", "-r", "--name-only", "-z", candidate_tree],
            capture_output=True, text=False, check=False, timeout=GIT_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise _ProjectionGap(f"cannot list candidate tree ({type(exc).__name__})") from exc
    if completed.returncode != 0:
        raise _ProjectionGap("cannot list candidate tree")
    return {entry for entry in completed.stdout.decode("utf-8", "replace").split("\0") if entry}


def _extract_tree_paths(
    root: Path, candidate_tree: str, wanted: Sequence[str], target: Path, budget_spent: int = 0
) -> int:
    """Extract exactly the wanted tree blobs into target; return the new spent total."""
    if not wanted:
        return budget_spent
    scratch: str | None = None
    try:
        scratch = tempfile.mkdtemp(prefix="eliot-doc-read-archive-")
        archive = Path(scratch) / "projection.tar"
        with archive.open("wb") as handle:
            subprocess.run(
                ["git", "-C", str(root), "archive", "--format=tar", candidate_tree, "--", *wanted],
                stdout=handle, stderr=subprocess.PIPE, check=True, timeout=GIT_TIMEOUT_S,
            )
        with tarfile.open(archive, "r:") as tar:
            members = tar.getmembers()
            spent = budget_spent
            for member in members:
                if member.isfile():
                    spent += member.size
                    if spent > _MAX_PROJECTED_BYTES:
                        raise _ProjectionGap("projection exceeds the byte bound")
            for member in members:
                name = member.name.replace("\\", "/")
                if name.startswith("/") or ".." in Path(name).parts:
                    raise _ProjectionGap("candidate archive escapes root")
            tar.extractall(target)
    except (subprocess.CalledProcessError, OSError, subprocess.SubprocessError, tarfile.TarError) as exc:
        raise _ProjectionGap(f"cannot extract projection ({type(exc).__name__})") from exc
    finally:
        if scratch is not None:
            shutil.rmtree(scratch, ignore_errors=True)
    return spent


def _projection_fixed_inputs() -> list[str]:
    """The algorithms' own declared fixed inputs (their constants, not a list)."""
    return [
        _router.DEFAULT_CONFIG,
        _router.DEFAULT_INDEX,
        _router.DEFAULT_RECEIPT,
        COHORT_LOCK_PATH,
    ]


def _project_candidate(root: Path, candidate_tree: str, paths: Sequence[str], topic: str) -> Path:
    """Materialize the bounded projection; raise _ProjectionGap when unprovable."""
    names = _candidate_tree_names(root, candidate_tree)
    directory = tempfile.mkdtemp(prefix="eliot-doc-read-candidate-")
    target = Path(directory)
    try:
        fixed = [entry for entry in _projection_fixed_inputs() if entry in names]
        agents = sorted(name for name in names if PurePosixPath(name).name == "AGENTS.md")
        phase1 = sorted(set(fixed) | set(agents))
        if len(phase1) > _MAX_PROJECTED_FILES:
            raise _ProjectionGap("projection exceeds the file bound")
        spent = _extract_tree_paths(root, candidate_tree, phase1, target)
        try:
            config = _router.load_config(target)
        except _router.RouteError as exc:
            raise _ProjectionGap(f"projection cannot parse route config: {exc}") from exc
        try:
            matched = _router.matched_routes(config, list(paths), topic)
        except _router.RouteError as exc:
            raise _ProjectionGap(f"projection cannot reproduce route matching: {exc}") from exc
        declared: set[str] = set(config.baseline_files) | set(config.baseline_optional_files)
        for route in matched:
            declared |= set(route.required_files) | set(route.optional_files)
        try:
            wanted_files = sorted(
                _router.normalize_repo_path(entry) for entry in declared if entry.strip()
            )
        except _router.RouteError as exc:
            raise _ProjectionGap(f"projection cannot normalize declared files: {exc}") from exc
        phase1b = sorted({entry for entry in wanted_files if entry in names})
        if len(phase1) + len(phase1b) > _MAX_PROJECTED_FILES:
            raise _ProjectionGap("projection exceeds the file bound")
        spent = _extract_tree_paths(root, candidate_tree, phase1b, target, spent)
        try:
            route = _router.route_payload(target, config, list(paths), topic)
        except _router.RouteError as exc:
            raise _ProjectionGap(f"projection cannot reproduce routing: {exc}") from exc
        required: list[str] = []
        for item in route.get("required", []):
            if not isinstance(item, dict):
                raise _ProjectionGap("projection met a non-object required item")
            try:
                required.append(_router.normalize_repo_path(str(item.get("path", ""))))
            except _router.RouteError as exc:
                raise _ProjectionGap(f"projection cannot normalize required path: {exc}") from exc
        phase2 = sorted({entry for entry in required if entry in names})
        if len(phase1) + len(phase1b) + len(phase2) > _MAX_PROJECTED_FILES:
            raise _ProjectionGap("projection exceeds the file bound")
        _extract_tree_paths(root, candidate_tree, phase2, target, spent)
        return target
    except BaseException:
        shutil.rmtree(target, ignore_errors=True)
        raise


def _materialize_candidate(
    root: Path, candidate_tree: str,
    paths: Sequence[str] | None = None, topic: str | None = None,
) -> Path:
    """Export final-candidate bytes for the SOLE router/reader algorithms.

    Prefers the bounded Git-tree-backed projection (real bytes from the
    immutable candidate tree object, never the mutable worktree), cached under
    the immutable (tree, topic, paths) key so repeating the same check repeats
    no export. Falls back to the full tree export whenever equivalence is
    unprovable. Callers release the result with _release_candidate, never with
    rmtree.
    """
    materialized = list(paths) if paths is not None else []
    key: str | None = None
    if materialized and topic is not None:
        key = _cache_key(candidate_tree, materialized, topic)
        cached = _CANDIDATE_CACHE.get(key)
        if cached is not None and cached.is_dir():
            return cached
        try:
            projected = _project_candidate(root, candidate_tree, materialized, topic)
        except _ProjectionGap:
            projected = None
        if projected is not None:
            return _remember_candidate(key, projected, True)
    full = _materialize_full_tree(root, candidate_tree)
    if key is not None:
        return _remember_candidate(key, full, False)
    return full


def _recompute_final(
    root: Path, candidate_tree: str, changed: Sequence[str], topic: str
) -> tuple[Path, Recomputed]:
    """Materialize (projection preferred, full export on gap) and recompute.

    When the projection serves an error the full tree would not serve — or a
    different one — the full export is re-run and THAT outcome is reported,
    which is byte-for-byte today's behavior. A projection success is
    equivalent by construction (see the closure note above): every filesystem
    query the sole algorithms issue is answered with identical bytes or
    identical absence, through the same router/reader algorithms, with the
    final-candidate identity checks kept.
    """
    candidate_root = _materialize_candidate(root, candidate_tree, changed, topic)
    try:
        return candidate_root, _recompute(candidate_root, list(changed), topic)
    except EvidenceError:
        if not _used_projection(candidate_root):
            raise
        _release_candidate(candidate_root)
        full_root = _materialize_full_tree(root, candidate_tree)
        _remember_candidate(_cache_key(candidate_tree, list(changed), topic), full_root, False)
        try:
            return full_root, _recompute(full_root, list(changed), topic)
        except BaseException:
            _release_candidate(full_root)
            raise


# ---------------------------------------------------------------------------
# Local evidence stays out of Git (issue #2965 item 14).
# ---------------------------------------------------------------------------

# Mirror of the `.eliot*/` families `.gitignore` keeps out of Git. A gitignore
# pattern without a slash matches at any depth, so any such path segment in
# the final candidate tree is rejected. `.gitignore` alone is advisory
# (`git add -f` bypasses it); the merge boundary enforces it here.
_LOCAL_EVIDENCE_SEGMENTS = (".eliot", ".eliot-dev", ".eliot-governor")


def _reject_committed_local_evidence(root: Path, candidate_tree: str) -> None:
    """Fail when the final candidate tree carries committed local evidence.

    `.eliot/docs-read-bundle.md` and local receipts remain ignored; only the
    compact PR evidence travels with the PR.
    """
    output = _git(root, "ls-tree", "-r", "--name-only", candidate_tree)
    offenders = sorted(
        {
            entry
            for entry in (line.strip() for line in output.splitlines())
            if entry and any(segment in _LOCAL_EVIDENCE_SEGMENTS for segment in entry.split("/"))
        }
    )
    if offenders:
        preview = ", ".join(offenders[:MAX_DIAGNOSTIC_PATHS])
        more = "" if len(offenders) <= MAX_DIAGNOSTIC_PATHS else f" (+{len(offenders) - MAX_DIAGNOSTIC_PATHS} more)"
        _fail(
            EvidenceFailure.LOCAL_EVIDENCE_COMMITTED,
            f"candidate commits local evidence that must remain ignored: {preview}{more}",
        )


# ---------------------------------------------------------------------------
# Recomputation through the sole algorithms.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Recomputed:
    route: dict[str, Any]
    read_receipt: dict[str, Any]


def _recompute(candidate_root: Path, paths: Sequence[str], topic: str) -> Recomputed:
    try:
        config = _router.load_config(candidate_root)
        route = _router.route_payload(candidate_root, config, list(paths), topic)
    except _router.RouteError as exc:
        _fail(EvidenceFailure.ROUTER_INPUT_MISMATCH, f"route recomputation rejected: {exc}")
    try:
        _bundle, read_receipt = _read.build_read_bundle(candidate_root, route)
    except _read.ReadError as exc:
        _fail(EvidenceFailure.STALE_SOURCE_TREE, f"read bundle recomputation rejected: {exc}")
    return Recomputed(route=route, read_receipt=read_receipt)


def _contract_inputs(candidate_root: Path) -> dict[str, str]:
    """Current digests of the immutable routing/reader inputs, from the candidate."""

    def digest(relative: str) -> str:
        path = candidate_root / relative
        if not path.is_file():
            _fail(EvidenceFailure.STALE_SOURCE_TREE, f"routing input missing in candidate: {relative}")
        return _router.sha256_file(path)

    return {
        "route_rules_path": ROUTE_RULES_PATH,
        "route_rules_sha256": digest(ROUTE_RULES_PATH),
        "handle_index_path": HANDLE_INDEX_PATH,
        "handle_index_sha256": digest(HANDLE_INDEX_PATH),
        "normative_pair_path": PAIR_RECEIPT_PATH,
        "normative_pair_sha256": digest(PAIR_RECEIPT_PATH),
        "reader_contract": READER_CONTRACT,
        "router_contract": ROUTER_CONTRACT,
    }


# ---------------------------------------------------------------------------
# PR body extraction: exactly one closed marker block.
# ---------------------------------------------------------------------------

_OUTER_FIELDS = (
    "schema_version", "repository", "base_sha", "candidate", "changed_paths",
    "topic", "route_receipt_id", "read_receipt_id", "pair_key", "matched_routes",
    "required_items", "bundle", "optional_expansions", "contract_inputs",
    "attestation", "checklist",
)


def _extract_envelope(pr_body: str) -> dict[str, Any]:
    starts = pr_body.count(BLOCK_START)
    ends = pr_body.count(BLOCK_END)
    if starts == 0 and ends == 0:
        _fail(
            EvidenceFailure.EMPTY_DOCUMENTATION_EVIDENCE,
            "no machine-readable documentation evidence block in the PR body",
        )
    if starts != 1 or ends != 1:
        _fail(
            EvidenceFailure.UNKNOWN_OR_DUPLICATE_BLOCK,
            f"expected exactly one evidence block, found {starts} start / {ends} end markers",
        )
    if pr_body.index(BLOCK_END) < pr_body.index(BLOCK_START):
        _fail(EvidenceFailure.UNKNOWN_OR_DUPLICATE_BLOCK, "overlapping evidence block markers")
    inner = pr_body[pr_body.index(BLOCK_START) + len(BLOCK_START):pr_body.index(BLOCK_END)]
    fences = re.findall(r"```[ \t]*([A-Za-z0-9_+-]*)[ \t]*\r?\n(.*?)```", inner, re.DOTALL)
    if len(fences) != 1:
        _fail(
            EvidenceFailure.MALFORMED_EVIDENCE_BLOCK,
            f"evidence block must contain exactly one fenced payload, found {len(fences)}",
        )
    if fences[0][0] not in ("", "json"):
        _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, "evidence fence must be canonical JSON")
    try:
        envelope = json.loads(fences[0][1])
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, f"evidence block is not valid JSON: {exc}")
    if type(envelope) is not dict:
        _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, "evidence block is not a JSON object")
    return envelope


def _shape(envelope: dict[str, Any]) -> dict[str, Any]:
    if envelope.get("schema_version") != OUTER_SCHEMA:
        _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, f"schema_version must be {OUTER_SCHEMA}")
    missing = [key for key in _OUTER_FIELDS if key not in envelope]
    if missing:
        _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, f"missing field(s): {','.join(missing)}")
    unknown = sorted(set(envelope) - set(_OUTER_FIELDS))
    if unknown:
        _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, f"unknown field(s): {','.join(unknown)}")
    return envelope


# ---------------------------------------------------------------------------
# Field comparison against the fresh recomputation.
# ---------------------------------------------------------------------------

def _compare(
    envelope: dict[str, Any],
    recomputed: Recomputed,
    base_tree: str,
    candidate_tree: str,
    changed: Sequence[str],
    candidate_root: Path,
    work_issue: int | None = None,
) -> tuple[ChecklistState, dict[int, bool]]:
    _compare_identity(envelope, base_tree, candidate_tree, changed, candidate_root)
    _compare_router_input(envelope, recomputed)
    _compare_required(envelope["required_items"], recomputed)
    _compare_bundle(envelope["bundle"], recomputed)
    _compare_optional(envelope["optional_expansions"], recomputed)
    _compare_contract_inputs(envelope["contract_inputs"], candidate_root)
    _compare_attestation(envelope["attestation"])
    state = _checklist_state(envelope["checklist"], candidate_root, candidate_tree, work_issue)
    return state, _assignment_contract(candidate_root)


def _compare_identity(
    envelope: dict[str, Any],
    base_tree: str,
    candidate_tree: str,
    changed: Sequence[str],
    candidate_root: Path,
) -> None:
    repository = _closed(envelope["repository"], ("owner", "name"), "repository")
    owner = _text(repository["owner"], "repository.owner", EvidenceFailure.BASE_OR_CANDIDATE_MISMATCH)
    name = _text(repository["name"], "repository.name", EvidenceFailure.BASE_OR_CANDIDATE_MISMATCH)
    expected_name = _candidate_repository(candidate_root)
    if expected_name and f"{owner}/{name}" != expected_name:
        _fail(
            EvidenceFailure.BASE_OR_CANDIDATE_MISMATCH,
            f"repository identity {owner}/{name} is not this checkout ({expected_name})",
        )

    recorded_base = _sha256(envelope["base_sha"], "base_sha", EvidenceFailure.BASE_OR_CANDIDATE_MISMATCH)
    if recorded_base != _tree_digest(base_tree):
        _fail(
            EvidenceFailure.BASE_OR_CANDIDATE_MISMATCH,
            f"base tree digest mismatch: recorded={recorded_base} actual={_tree_digest(base_tree)}",
        )

    candidate = _closed(envelope["candidate"], ("commit", "tree"), "candidate")
    recorded_tree = _sha256(candidate["tree"], "candidate.tree", EvidenceFailure.BASE_OR_CANDIDATE_MISMATCH)
    if recorded_tree != _tree_digest(candidate_tree):
        _fail(
            EvidenceFailure.BASE_OR_CANDIDATE_MISMATCH,
            f"candidate tree digest mismatch: recorded={recorded_tree} actual={_tree_digest(candidate_tree)}",
        )
    if candidate["commit"] is not None:
        commit = _text(candidate["commit"], "candidate.commit", EvidenceFailure.BASE_OR_CANDIDATE_MISMATCH)
        if not _FULL_COMMIT.fullmatch(commit):
            _fail(EvidenceFailure.BASE_OR_CANDIDATE_MISMATCH, "candidate.commit must be a full 40-hex commit id")

    recorded_paths = envelope["changed_paths"]
    if type(recorded_paths) is not list or not recorded_paths or len(recorded_paths) > MAX_ITEMS:
        _fail(EvidenceFailure.UNCOVERED_CHANGED_PATH, "changed_paths must be a non-empty list")
    if not all(type(entry) is str and entry.strip() for entry in recorded_paths):
        _fail(EvidenceFailure.UNCOVERED_CHANGED_PATH, "changed_paths entries must be non-empty strings")
    try:
        normalized = [_router.normalize_repo_path(entry) for entry in recorded_paths]
    except _router.RouteError as exc:
        _fail(EvidenceFailure.UNCOVERED_CHANGED_PATH, f"changed_paths entry is not repository-relative: {exc}")
    if len(set(normalized)) != len(normalized):
        _fail(EvidenceFailure.UNCOVERED_CHANGED_PATH, "changed_paths contains duplicate entries")
    uncovered = [path for path in changed if path not in set(normalized)]
    if uncovered:
        preview = ", ".join(uncovered[:MAX_DIAGNOSTIC_PATHS])
        more = "" if len(uncovered) <= MAX_DIAGNOSTIC_PATHS else f" (+{len(uncovered) - MAX_DIAGNOSTIC_PATHS} more)"
        _fail(EvidenceFailure.UNCOVERED_CHANGED_PATH, f"final changed path(s) not covered: {preview}{more}")


def _tree_digest(tree: str) -> str:
    return "sha256:" + hashlib.sha256(tree.encode("utf-8")).hexdigest()


def _candidate_repository(candidate_root: Path) -> str:
    """Repository identity from the candidate's committed assignment contract."""
    lock = candidate_root / COHORT_LOCK_PATH
    if not lock.is_file():
        return ""
    try:
        with lock.open("rb") as stream:
            document = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError):
        return ""
    repository = document.get("repository")
    if type(repository) is not dict:
        return ""
    owner, name = repository.get("owner"), repository.get("name")
    if type(owner) is str and type(name) is str and owner and name:
        return f"{owner}/{name}"
    return ""


def _compare_router_input(envelope: dict[str, Any], recomputed: Recomputed) -> None:
    topic = _text(envelope["topic"], "topic", EvidenceFailure.ROUTER_INPUT_MISMATCH, descriptive=True)
    if topic != recomputed.route["topic"]:
        _fail(
            EvidenceFailure.ROUTER_INPUT_MISMATCH,
            f"topic mismatch: recorded={topic!r} routed={recomputed.route['topic']!r}",
        )
    pair_key = _sha256(envelope["pair_key"], "pair_key", EvidenceFailure.PAIR_KEY_MISMATCH)
    if pair_key != recomputed.route["pair_key"]:
        _fail(
            EvidenceFailure.PAIR_KEY_MISMATCH,
            f"pair key mismatch: recorded={pair_key} routed={recomputed.route['pair_key']}",
        )
    routes = envelope["matched_routes"]
    if type(routes) is not list or not routes or not all(type(route) is str and route for route in routes):
        _fail(EvidenceFailure.ROUTE_SET_MISMATCH, "matched_routes must be a non-empty list of route ids")
    # Exact ordered equality: the router's own route order is part of the
    # recomputed payload, so a reordered or altered set cannot pass.
    if routes != list(recomputed.route["matched_routes"]):
        _fail(
            EvidenceFailure.ROUTE_SET_MISMATCH,
            f"route set mismatch: recorded={routes} actual={list(recomputed.route['matched_routes'])}",
        )
    route_receipt = _sha256(envelope["route_receipt_id"], "route_receipt_id", EvidenceFailure.ROUTE_RECEIPT_MISMATCH)
    if route_receipt != recomputed.route["receipt_id"]:
        _fail(
            EvidenceFailure.ROUTE_RECEIPT_MISMATCH,
            f"route receipt mismatch: recorded={route_receipt} recomputed={recomputed.route['receipt_id']}",
        )
    read_receipt = _sha256(envelope["read_receipt_id"], "read_receipt_id", EvidenceFailure.READ_RECEIPT_MISMATCH)
    if read_receipt != recomputed.read_receipt["read_receipt_id"]:
        _fail(
            EvidenceFailure.READ_RECEIPT_MISMATCH,
            f"read receipt mismatch: recorded={read_receipt} recomputed={recomputed.read_receipt['read_receipt_id']}",
        )


def _required_projection(recomputed: Recomputed) -> dict[str, dict[str, Any]]:
    projection: dict[str, dict[str, Any]] = {}
    for item in recomputed.read_receipt["required"]:
        projection[str(item["path"])] = {
            "sha256": str(item["sha256"]),
            "bytes": int(item["bytes"]),
            "handles": sorted(str(handle) for handle in item.get("handles", [])),
        }
    return projection


def _compare_required(recorded: Any, recomputed: Recomputed) -> None:
    if type(recorded) is not list or not recorded or len(recorded) > MAX_ITEMS:
        _fail(EvidenceFailure.REQUIRED_ITEM_MISMATCH, "required_items must be a non-empty list")
    actual = _required_projection(recomputed)
    seen: set[str] = set()
    for item in recorded:
        if type(item) is not dict:
            _fail(EvidenceFailure.REQUIRED_ITEM_MISMATCH, "required item must be an object")
        keys = set(item)
        if not keys <= {"path", "sha256", "bytes", "handles"} or "path" not in keys:
            _fail(EvidenceFailure.REQUIRED_ITEM_MISMATCH, "required item has unknown or missing fields")
        path = _text(item["path"], "required.path", EvidenceFailure.REQUIRED_ITEM_MISMATCH)
        if path in seen:
            _fail(EvidenceFailure.REQUIRED_ITEM_MISMATCH, f"duplicate required path: {path}")
        seen.add(path)
        expected = actual.get(path)
        if expected is None:
            _fail(EvidenceFailure.REQUIRED_ITEM_MISMATCH, f"required path is not in the recomputed set: {path}")
        digest = _sha256(item.get("sha256"), f"required[{path}].sha256", EvidenceFailure.REQUIRED_ITEM_MISMATCH, prefixed=False)
        size = _count(item.get("bytes"), f"required[{path}].bytes", EvidenceFailure.REQUIRED_ITEM_MISMATCH)
        handles = item.get("handles", [])
        if type(handles) is not list or not all(type(handle) is str and handle for handle in handles):
            _fail(EvidenceFailure.REQUIRED_ITEM_MISMATCH, f"required[{path}].handles must be a list of handle ids")
        if (digest, size, sorted(handles)) != (expected["sha256"], expected["bytes"], expected["handles"]):
            _fail(
                EvidenceFailure.REQUIRED_ITEM_MISMATCH,
                f"required[{path}] mismatch: recorded sha/bytes/handles differ from the current candidate",
            )
    omitted = sorted(set(actual) - seen)
    if omitted:
        preview = ", ".join(omitted[:MAX_DIAGNOSTIC_PATHS])
        more = "" if len(omitted) <= MAX_DIAGNOSTIC_PATHS else f" (+{len(omitted) - MAX_DIAGNOSTIC_PATHS} more)"
        _fail(EvidenceFailure.REQUIRED_ITEM_MISMATCH, f"required item(s) omitted: {preview}{more}")


def _compare_bundle(recorded: Any, recomputed: Recomputed) -> None:
    bundle = _closed(recorded, ("sha256", "bytes"), "bundle")
    digest = _sha256(bundle["sha256"], "bundle.sha256", EvidenceFailure.BUNDLE_DIGEST_MISMATCH, prefixed=False)
    size = _count(bundle["bytes"], "bundle.bytes", EvidenceFailure.BUNDLE_DIGEST_MISMATCH)
    actual_digest = str(recomputed.read_receipt["bundle_sha256"])
    actual_size = int(recomputed.read_receipt["bundle_bytes"])
    if digest != actual_digest or size != actual_size:
        _fail(
            EvidenceFailure.BUNDLE_DIGEST_MISMATCH,
            f"bundle digest mismatch: recorded={digest}:{size} recomputed={actual_digest}:{actual_size}",
        )


def _compare_optional(recorded: Any, recomputed: Recomputed) -> None:
    """`none` means no optional item is claimed as read.

    Required items are verified separately; a claimed optional expansion needs
    its exact current hash and reason.
    """
    optional = {str(item["path"]): item for item in recomputed.route.get("optional", [])}
    if recorded == "none":
        return
    if type(recorded) is not list or len(recorded) > MAX_ITEMS:
        _fail(EvidenceFailure.REQUIRED_ITEM_MISMATCH, "optional_expansions must be 'none' or a list")
    claimed: set[str] = set()
    for entry in recorded:
        if type(entry) is not dict or set(entry) != {"path", "sha256", "reason"}:
            _fail(EvidenceFailure.REQUIRED_ITEM_MISMATCH, "optional expansion must be {path, sha256, reason}")
        path = _text(entry["path"], "optional.path", EvidenceFailure.REQUIRED_ITEM_MISMATCH)
        _text(entry["reason"], f"optional[{path}].reason", EvidenceFailure.REQUIRED_ITEM_MISMATCH,
              descriptive=True)
        digest = _sha256(entry["sha256"], f"optional[{path}].sha256", EvidenceFailure.REQUIRED_ITEM_MISMATCH, prefixed=False)
        if path in claimed:
            _fail(EvidenceFailure.REQUIRED_ITEM_MISMATCH, f"duplicate optional expansion: {path}")
        claimed.add(path)
        expected = optional.get(path)
        if expected is None:
            _fail(EvidenceFailure.REQUIRED_ITEM_MISMATCH, f"optional path is not in the routed optional set: {path}")
        if digest != str(expected["sha256"]):
            _fail(
                EvidenceFailure.REQUIRED_ITEM_MISMATCH,
                f"optional[{path}] hash is not the current hash: recorded={digest} current={expected['sha256']}",
            )


def _compare_contract_inputs(recorded: Any, candidate_root: Path) -> None:
    expected = _contract_inputs(candidate_root)
    if type(recorded) is not dict:
        _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, "contract_inputs must be an object")
    unknown = sorted(set(recorded) - set(expected))
    if unknown:
        _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, f"unknown contract_inputs field(s): {','.join(unknown)}")
    for key, value in expected.items():
        if key not in recorded:
            _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, f"contract_inputs missing {key}")
        if value.startswith("sha256:"):
            observed = _sha256(recorded[key], f"contract_inputs.{key}", EvidenceFailure.STALE_SOURCE_TREE)
        else:
            observed = _text(recorded[key], f"contract_inputs.{key}", EvidenceFailure.STALE_SOURCE_TREE)
        if observed != value:
            _fail(
                EvidenceFailure.STALE_SOURCE_TREE,
                f"contract_inputs.{key} mismatch: recorded={observed} current={value}",
            )


def _compare_attestation(recorded: Any) -> None:
    attestation = _closed(recorded, ("read_by", "statement"), "attestation")
    _text(attestation["read_by"], "attestation.read_by", EvidenceFailure.ATTESTATION_MISSING)
    _text(attestation["statement"], "attestation.statement", EvidenceFailure.ATTESTATION_MISSING,
          descriptive=True)


# ---------------------------------------------------------------------------
# Checklist state from the committed assignment contract (item 10).
# ---------------------------------------------------------------------------

_ACTIVE_DISPOSITIONS = ("assigned", "planned", "blocked")


def _checklist_state(
    recorded: Any, candidate_root: Path, candidate_tree: str, work_issue: int | None = None
) -> ChecklistState:
    """The four-valued conditional checklist state, decided by the contract.

    Requirement is a fact of the committed assignment contract
    (:func:`_assignment_contract`), never a guess from a filesystem path: the
    contract is read first, for its own declared rows, and only its declared
    dispositions decide whether a record is required. A body-supplied number
    never decides requirement and never selects which rule applies.

    Four mutually exclusive outcomes, in the only order that never reports a
    weaker state than the facts support:

    * the contract requires no record for the identified work unit ->
      ``not_required``;
    * no work unit is identified at all while the contract declares rows, the
      contract has no row for the named work unit, or a required record is not
      bound to the final candidate tree -> ``required_missing``;
    * a required record is bound to a different tree -> ``stale``;
    * a required record is recorded and bound to the final candidate tree ->
      ``required_verified``, established by that verification and never by the
      mere presence of a record.

    An unassigned number is not a way out: a body cannot name an issue outside
    the contract and thereby declare its own checklist unnecessary. That is
    exactly the substitution ``not_required`` is forbidden to make.
    """
    checklist = _closed(recorded, ("issue", "recorded", "bound_candidate_tree"), "checklist")
    issue = checklist["issue"]
    if issue is not None and (type(issue) is not int or issue <= 0):
        _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, "checklist.issue must be a positive integer or null")
    if type(checklist["recorded"]) is not bool:
        _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, "checklist.recorded must be a boolean")
    bound_tree = checklist["bound_candidate_tree"]
    if bound_tree is not None:
        _sha256(bound_tree, "checklist.bound_candidate_tree", EvidenceFailure.CHECKLIST_REQUIRED_MISSING)
    if work_issue is not None:
        if type(work_issue) is not int or work_issue <= 0:
            _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, "trusted work-issue must be a positive integer")
        if issue != work_issue:
            _fail(
                EvidenceFailure.CHECKLIST_REQUIRED_MISSING,
                f"checklist.issue {issue!r} does not match the trusted work-issue {work_issue}",
            )
        issue = work_issue

    contract = _assignment_contract(candidate_root)
    if not contract:
        # No contract declares any row, so it requires no record.
        return ChecklistState.NOT_REQUIRED
    if issue is None:
        # No work unit is identified, so the contract cannot be asked whether
        # this delivery requires a record. While the contract declares active
        # rows, a withheld selector must never manufacture not_required.
        return ChecklistState.REQUIRED_MISSING
    if issue not in contract:
        # The body names a work unit the contract does not declare. Absence of
        # a row is not permission: the body cannot clear its own checklist by
        # pointing at an issue the contract never assigned.
        return ChecklistState.REQUIRED_MISSING
    if not contract[issue]:
        return ChecklistState.NOT_REQUIRED
    if not checklist["recorded"] or bound_tree is None:
        return ChecklistState.REQUIRED_MISSING
    if bound_tree != _tree_digest(candidate_tree):
        return ChecklistState.STALE
    return ChecklistState.REQUIRED_VERIFIED


def _assignment_contract(candidate_root: Path) -> dict[int, bool]:
    """Each issue the committed contract declares, mapped to requirement.

    The value is whether that row's own disposition makes a checklist/work-unit
    record required. The mapping is read from the contract rows themselves, so
    it is the independent expected set a recorded state is judged against,
    never a set the envelope supplied.

    A repository whose candidate commits no contract, or an unreadable one,
    declares no rows and therefore no requirement: that is a fact about the
    contract, not an inference from a path. Delivering a cohort whose contract
    row is not committed needs the merge controller's trusted work-issue
    (see :func:`merge_integration_status`), which is a controller action this
    module never invents.
    """
    lock = candidate_root / COHORT_LOCK_PATH
    if not lock.is_file():
        return {}
    try:
        with lock.open("rb") as stream:
            document = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    rows = document.get("row")
    if type(rows) is not list:
        return {}
    declared: dict[int, bool] = {}
    for entry in rows:
        if type(entry) is not dict:
            continue
        number = entry.get("issue")
        if type(number) is not int or number <= 0:
            continue
        disposition = entry.get("disposition")
        declared[number] = (
            type(disposition) is str and disposition in _ACTIVE_DISPOSITIONS
        )
    return declared


# ---------------------------------------------------------------------------
# Same-reader provenance refresh (audit 5919739325 defect 2).
#
# route_payload hashes optional items and the full topic into the route ID, and
# build_read_bundle embeds that route ID into the bundle and read receipt. An
# unopened optional-file-only change — or equivalent topic wording — therefore
# changes route/read/bundle provenance even though every required item is
# byte-identical. The OLD envelope still fails (it is regenerated, never
# accepted); but TASK item 5 requires renewed reading/attestation only when
# REQUIRED content changes, so the same reader on the same attempt refreshes
# provenance without re-reading unchanged required text:
# * reading_delta (pure, no I/O) reports the required/read-optional delta
#   between a prior envelope and the current recomputation;
# * refresh_provenance regenerates the exact current outer evidence
#   deterministically, retaining current provenance and the earlier reading's
#   attribution.
# Refusals stay typed: changed required/selected content, changed routing
# obligations (routes, pair key, contract inputs) or a DIFFERENT reader fail
# STALE_SOURCE_TREE — renewed reading is required and the diagnostic presents
# the changed material. Receipt IDs are never redefined silently (the prior
# and current route IDs are both named in the refreshed attestation);
# required_delta=0 is reported as a fact and is never product acceptance (the
# refreshed envelope must still pass verify()). A new reader never inherits
# another model's comprehension claim.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ReadingDelta:
    """Required/read-optional delta: prior envelope versus current recompute."""

    required_added: tuple[str, ...]
    required_removed: tuple[str, ...]
    required_changed: tuple[str, ...]
    required_unchanged: tuple[str, ...]
    claimed_optional_stale: tuple[str, ...]
    claimed_optional_current: tuple[str, ...]
    topic_changed: bool
    routes_changed: bool
    pair_key_changed: bool

    @property
    def required_changed_any(self) -> bool:
        return bool(self.required_added or self.required_removed or self.required_changed)

    @property
    def selected_content_changed(self) -> bool:
        return self.required_changed_any or bool(self.claimed_optional_stale)


def reading_delta(prior_envelope: dict[str, Any], topic: str, recomputed: Recomputed) -> ReadingDelta:
    """Pure required/read-optional delta (no I/O, no acceptance claim).

    Compares the prior envelope's recorded required items (path, SHA-256,
    bytes, handles — the same tuple _compare_required enforces) against
    _required_projection(recomputed), and its claimed optional expansions
    against the recomputed routed optional set.
    """
    if type(prior_envelope) is not dict:
        _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, "prior envelope must be an object")
    prior_required = prior_envelope.get("required_items")
    if type(prior_required) is not list:
        _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, "prior required_items must be a list")
    prior_paths: dict[str, tuple[str, int, tuple[str, ...]]] = {}
    for item in prior_required:
        if type(item) is not dict or type(item.get("path")) is not str:
            _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, "prior required item must carry a path")
        handles = item.get("handles", [])
        if type(handles) is not list or not all(type(entry) is str for entry in handles):
            _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, "prior required handles must be strings")
        raw_bytes = item.get("bytes")
        prior_paths[item["path"]] = (
            str(item.get("sha256", "")),
            raw_bytes if type(raw_bytes) is int else -1,
            tuple(sorted(handles)),
        )
    current = _required_projection(recomputed)
    added = sorted(set(current) - set(prior_paths))
    removed = sorted(set(prior_paths) - set(current))
    changed = sorted(
        path for path in set(current) & set(prior_paths)
        if (
            current[path]["sha256"],
            current[path]["bytes"],
            tuple(current[path]["handles"]),
        ) != prior_paths[path]
    )
    unchanged = sorted(
        path for path in set(current) & set(prior_paths)
        if (
            current[path]["sha256"],
            current[path]["bytes"],
            tuple(current[path]["handles"]),
        ) == prior_paths[path]
    )
    optional_now = {
        str(item["path"]): str(item.get("sha256", ""))
        for item in recomputed.route.get("optional", [])
        if isinstance(item, dict) and type(item.get("path")) is str
    }
    claimed = prior_envelope.get("optional_expansions")
    stale: list[str] = []
    current_claims: list[str] = []
    if claimed != "none":
        if type(claimed) is not list:
            _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, "prior optional_expansions must be 'none' or a list")
        for entry in claimed:
            if type(entry) is not dict or type(entry.get("path")) is not str:
                _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, "prior optional expansion must carry a path")
            path = entry["path"]
            if optional_now.get(path) != str(entry.get("sha256", "")):
                stale.append(path)
            else:
                current_claims.append(path)
    prior_topic = prior_envelope.get("topic")
    if type(prior_topic) is not str:
        _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, "prior topic must be a string")
    prior_routes = prior_envelope.get("matched_routes")
    if type(prior_routes) is not list or not all(type(entry) is str for entry in prior_routes):
        _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, "prior matched_routes must be a list of route ids")
    prior_pair = prior_envelope.get("pair_key")
    if type(prior_pair) is not str:
        _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, "prior pair_key must be a string")
    return ReadingDelta(
        required_added=tuple(added),
        required_removed=tuple(removed),
        required_changed=tuple(changed),
        required_unchanged=tuple(unchanged),
        claimed_optional_stale=tuple(sorted(stale)),
        claimed_optional_current=tuple(sorted(current_claims)),
        topic_changed=prior_topic != topic,
        routes_changed=list(prior_routes) != list(recomputed.route["matched_routes"]),
        pair_key_changed=prior_pair != recomputed.route["pair_key"],
    )


def refresh_provenance(
    root: Path, base: str, candidate: str, prior_body: str, *, topic: str, read_by: str
) -> str:
    """Regenerate the exact current outer evidence for the SAME reader/attempt.

    Recomputes the changed-path denominator, routing and read bundle for the
    final candidate with the SOLE algorithms, then either refuses or returns
    the canonical fenced envelope body:
    * STALE_SOURCE_TREE when required items, claimed optional material,
      matched routes, the pair key or the contract inputs changed, or when
      `read_by` is not the prior attestation's reader — renewed reading is
      required and the diagnostic presents the changed material;
    * otherwise the regenerated envelope: current machine fields (base and
      candidate trees, changed paths, topic, route/read/pair/bundle provenance,
      contract inputs), the prior optional claims verbatim (every one proven
      current), the prior checklist verbatim (never rebound here — verify()
      judges it), and the earlier reading's attribution carried forward with
      both the prior and the current route IDs named.
    The returned body is not acceptance: required_delta=0 is a fact about the
    delta, and the envelope must still pass verify().
    """
    root = root.resolve()
    base_tree = _resolve_tree(root, base, "base")
    candidate_tree = _resolve_tree(root, candidate, "candidate")
    prior = _shape(_extract_envelope(prior_body))
    _reject_committed_local_evidence(root, candidate_tree)
    changed = _changed_paths(root, base_tree, candidate_tree)
    if not changed:
        _fail(EvidenceFailure.UNCOVERED_CHANGED_PATH, "base and candidate differ in no tracked path")
    current_topic = _text(topic, "topic", EvidenceFailure.ROUTER_INPUT_MISMATCH, descriptive=True)
    current_reader = _text(read_by, "read_by", EvidenceFailure.ATTESTATION_MISSING)
    candidate_root, recomputed = _recompute_final(root, candidate_tree, changed, current_topic)
    try:
        _compare_contract_inputs(prior["contract_inputs"], candidate_root)
        _compare_attestation(prior["attestation"])
        if str(prior["attestation"]["read_by"]) != current_reader:
            _fail(
                EvidenceFailure.STALE_SOURCE_TREE,
                f"earlier reading is attributed to {prior['attestation']['read_by']!r}, "
                f"not {current_reader!r}; a new reader cannot inherit it",
            )
        delta = reading_delta(prior, current_topic, recomputed)
        if delta.selected_content_changed or delta.routes_changed or delta.pair_key_changed:
            changed_material = sorted(
                set(delta.required_added)
                | set(delta.required_removed)
                | set(delta.required_changed)
                | set(delta.claimed_optional_stale)
            )
            preview = ", ".join(changed_material[:MAX_DIAGNOSTIC_PATHS])
            more = (
                "" if len(changed_material) <= MAX_DIAGNOSTIC_PATHS
                else f" (+{len(changed_material) - MAX_DIAGNOSTIC_PATHS} more)"
            )
            obligations = []
            if delta.routes_changed:
                obligations.append("matched routes")
            if delta.pair_key_changed:
                obligations.append("normative pair key")
            scope = f"changed routing obligation(s): {', '.join(obligations)}; " if obligations else ""
            _fail(
                EvidenceFailure.STALE_SOURCE_TREE,
                f"renewed reading required for the final candidate: {scope}"
                f"changed selected material: {preview}{more}",
            )
        kind = _git(root, "cat-file", "-t", candidate)
        commit_value = _git(root, "rev-parse", candidate) if kind == "commit" else None
        prior_route_id = str(prior.get("route_receipt_id", ""))
        envelope = {
            "schema_version": OUTER_SCHEMA,
            "repository": prior["repository"],
            "base_sha": _tree_digest(base_tree),
            "candidate": {"commit": commit_value, "tree": _tree_digest(candidate_tree)},
            "changed_paths": list(changed),
            "topic": current_topic,
            "route_receipt_id": recomputed.route["receipt_id"],
            "read_receipt_id": recomputed.read_receipt["read_receipt_id"],
            "pair_key": recomputed.route["pair_key"],
            "matched_routes": list(recomputed.route["matched_routes"]),
            "required_items": [
                {
                    "path": item["path"],
                    "sha256": item["sha256"],
                    "bytes": item["bytes"],
                    "handles": sorted(item.get("handles", [])),
                }
                for item in recomputed.read_receipt["required"]
            ],
            "bundle": {
                "sha256": recomputed.read_receipt["bundle_sha256"],
                "bytes": recomputed.read_receipt["bundle_bytes"],
            },
            "optional_expansions": prior["optional_expansions"],
            "contract_inputs": _contract_inputs(candidate_root),
            "attestation": {
                "read_by": current_reader,
                "statement": (
                    "Earlier reading retained without re-read: every required item is "
                    "byte-identical (path, SHA-256, bytes, handles) to the prior envelope "
                    "and no claimed optional material changed. Outer provenance regenerated "
                    "deterministically for the current candidate: prior route "
                    f"{prior_route_id} -> current route {recomputed.route['receipt_id']}. "
                    "Required-item delta is zero; this envelope is not acceptance and must "
                    "still pass the documentation-read gate."
                ),
            },
            "checklist": prior["checklist"],
        }
    finally:
        _release_candidate(candidate_root)
    payload = json.dumps(envelope, indent=2, sort_keys=True)
    return f"{BLOCK_START}\n```json\n{payload}\n```\n{BLOCK_END}\n"


# ---------------------------------------------------------------------------
# Merge-boundary integration visibility (issue #2965 item 12/13).
# ---------------------------------------------------------------------------

def merge_integration_status(root: Path) -> dict[str, Any]:
    """Report whether a root/controller merge action in this repository consumes
    the shared command, and name the external integration when it does not.

    The verifier command is the single authority either way; this only reports
    where the merge action lives so an external one is never silently assumed
    to be wired.
    """
    candidates = (
        root / "Justfile",
        root / "scripts" / "verify.ps1",
        root / ".github" / "workflows",
    )
    observed = [
        str(path.relative_to(root)).replace("\\", "/")
        for path in candidates
        if path.exists()
    ]
    consumers = []
    for relative in observed:
        path = root / relative
        if path.is_dir():
            files = sorted(path.glob("*.yml")) + sorted(path.glob("*.yaml"))
        else:
            files = [path]
        for item in files:
            try:
                text = item.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if "doc-read-evidence" in text:
                consumers.append(item.relative_to(root).as_posix())
    return {
        "shared_command": SHARED_COMMAND,
        "in_repository_merge_consumers": consumers,
        "external_merge_action_required": not consumers,
        "external_owner_action": (
            "The root/controller merge action is not invoked from this repository. "
            "Wiring that external merge action to this shared command, and recording "
            "its exact integration/config version, is a blocking owner action and "
            "part of acceptance; it is not simulated by this module."
        ) if not consumers else "",
    }


# ---------------------------------------------------------------------------
# Verification entrypoint.
# ---------------------------------------------------------------------------

def verify(
    root: Path, base: str, candidate: str, pr_body: str, work_issue: int | None = None
) -> dict[str, Any]:
    """Recompute every envelope field for the final merge candidate and compare.

    Raises :class:`EvidenceError` with a stable typed code on any failure.
    """
    root = root.resolve()
    base_tree = _resolve_tree(root, base, "base")
    candidate_tree = _resolve_tree(root, candidate, "candidate")

    # Shape is checked before any repository work so an absent or malformed
    # envelope is EMPTY/MALFORMED and no prose attestation can rescue it.
    envelope = _shape(_extract_envelope(pr_body))

    # Item 14 precedes all content comparison: a candidate that commits local
    # evidence can never pass, however exact its envelope otherwise is.
    _reject_committed_local_evidence(root, candidate_tree)

    changed = _changed_paths(root, base_tree, candidate_tree)
    if not changed:
        _fail(EvidenceFailure.UNCOVERED_CHANGED_PATH, "base and candidate differ in no tracked path")

    topic = _text(envelope["topic"], "topic", EvidenceFailure.ROUTER_INPUT_MISMATCH, descriptive=True)
    candidate_root, recomputed = _recompute_final(root, candidate_tree, changed, topic)
    try:
        checklist_state, assignment_contract = _compare(
            envelope, recomputed, base_tree, candidate_tree, changed, candidate_root,
            work_issue,
        )
    finally:
        _release_candidate(candidate_root)

    if checklist_state is ChecklistState.REQUIRED_MISSING:
        _fail(
            EvidenceFailure.CHECKLIST_REQUIRED_MISSING,
            "the assignment contract requires a checklist/work-unit record for this issue and none is recorded",
        )
    if checklist_state is ChecklistState.STALE:
        _fail(
            EvidenceFailure.CHECKLIST_REQUIRED_MISSING,
            "the recorded checklist is bound to a different candidate tree; regenerate it for the final candidate",
        )

    return {
        "schema_version": OUTER_SCHEMA,
        "result": "PASS",
        "base_tree": _tree_digest(base_tree),
        "candidate_tree": _tree_digest(candidate_tree),
        "route_receipt_id": recomputed.route["receipt_id"],
        "read_receipt_id": recomputed.read_receipt["read_receipt_id"],
        "pair_key": recomputed.route["pair_key"],
        "matched_routes": list(recomputed.route["matched_routes"]),
        "required_items": len(recomputed.read_receipt["required"]),
        "changed_paths": list(changed),
        "bundle_sha256": str(recomputed.read_receipt["bundle_sha256"]),
        # The four-valued conditional checklist state, and the independent
        # contract rows it was decided from, reported separately from the
        # documentation-read result above. A missing required checklist blocks
        # the result with the checklist cause alone; it is never folded into a
        # documentation-read failure, and a documentation-read failure is never
        # reported as a checklist state.
        "checklist_state": checklist_state.value,
        "assignment_contract": sorted(assignment_contract),
        "proof_ceiling": PROOF_CEILING,
        "merge_integration": merge_integration_status(root),
    }


# ---------------------------------------------------------------------------
# Acceptance demonstration.
#
# The negative cases are demonstrated against a REAL final merge candidate, not
# against a recorded digest. `run_acceptance` builds a hermetic, sanitized git
# repository from the committed seed fixtures below (a minimal normative pair,
# handle index, route rules and a few tiny fragments — no real normative text,
# no secrets, no document bodies), makes one multi-route change that also
# includes a DELETION, a RENAME and a GENERATED file, and then computes a
# genuinely valid `eliot-doc-read-pr-evidence-v2` envelope for that exact
# candidate with the sole router/reader algorithms. Each negative case is that
# valid envelope with exactly one bounded defect, so every typed failure is
# demonstrated against an otherwise correct envelope.
#
# This is the module's own verification entrypoint, not a test framework: there
# is no test module, no test function and no test runner. The committed samples
# under `fixtures/` are the sanitized input corpus it reads.
# ---------------------------------------------------------------------------

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MAX_FIXTURE_BYTES = 262_144


def fixture_text(name: str) -> str:
    """Read one sanitized evidence sample (bounded, never a real PR body dump)."""
    path = FIXTURES / name
    try:
        raw = path.read_bytes()
    except OSError as exc:
        _fail(EvidenceFailure.EMPTY_DOCUMENTATION_EVIDENCE, f"fixture unavailable: {name} ({type(exc).__name__})")
    if len(raw) > MAX_FIXTURE_BYTES:
        _fail(EvidenceFailure.EMPTY_DOCUMENTATION_EVIDENCE, f"fixture exceeds the bounded size: {name}")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, f"fixture is not UTF-8: {name}")


def _write_seed(root: Path) -> None:
    """Materialize the sanitized acceptance repository skeleton."""
    (root / "docs" / "architecture").mkdir(parents=True, exist_ok=True)
    (root / "scripts" / "work_unit_gate").mkdir(parents=True, exist_ok=True)
    (root / "src" / "core").mkdir(parents=True, exist_ok=True)
    (root / "generated").mkdir(parents=True, exist_ok=True)
    (root / ".github").mkdir(parents=True, exist_ok=True)
    (root / "AGENTS.md").write_text("# Acceptance agents\n\nSanitized seed. No normative text.\n", encoding="utf-8", newline="\n")
    (root / "src" / "core" / "mod.rs").write_text("pub fn seed() {}\n", encoding="utf-8", newline="\n")
    (root / "src" / "core" / "legacy.rs").write_text("pub fn removed() {}\n", encoding="utf-8", newline="\n")
    (root / "docs" / "note.md").write_text("# Note\n\nSeed.\n", encoding="utf-8", newline="\n")
    (root / "docs" / "architecture" / "A00-01-seed.md").write_text(
        "## A0.1. Seed handle\n\nSanitized acceptance fragment. No normative content.\n",
        encoding="utf-8", newline="\n",
    )
    (root / "docs" / "architecture" / "A00-02-seed.md").write_text(
        "## A0.2. Second seed handle\n\nSanitized acceptance fragment. No normative content.\n",
        encoding="utf-8", newline="\n",
    )
    (root / "docs" / "architecture" / "I00-01-seed.md").write_text(
        "## I0.1. Implementation seed handle\n\nSanitized acceptance fragment. No normative content.\n",
        encoding="utf-8", newline="\n",
    )
    # A one-hash handle index plus a one-route rule table, both derived from the
    # fragment bytes above so the router's own hashes are internally consistent.
    fragments = {
        "A0.1": "docs/architecture/A00-01-seed.md",
        "A0.2": "docs/architecture/A00-02-seed.md",
        "I0.1": "docs/architecture/I00-01-seed.md",
    }
    handles = {}
    for handle, relative in fragments.items():
        raw = (root / relative).read_bytes()
        handles[handle] = {
            "path": relative,
            "anchor": handle.casefold().replace(".", "-"),
            "source_anchor": handle.casefold().replace(".", "-"),
            "fragment_sha256": hashlib.sha256(raw).hexdigest(),
            "fragment_bytes": len(raw),
        }
    (root / "docs" / "architecture" / "handle-index.json").write_text(
        json.dumps({"schema_version": "eliot-handle-index-v1", "handles": handles}, indent=2) + "\n",
        encoding="utf-8", newline="\n",
    )
    (root / "docs" / "architecture" / "route-rules.toml").write_text(
        'schema_version = "eliot-doc-routes-v1"\n'
        'pair_schema = "eliot-normative-pair-v2-sharded"\n'
        "\n"
        "[baseline]\n"
        'required_handles = ["A0.1", "I0.1"]\n'
        'required_files = ["AGENTS.md"]\n'
        "optional_handles = []\n"
        'optional_files = ["docs/note.md"]\n'
        "max_required_bytes = 393216\n"
        "\n"
        "[[route]]\n"
        'id = "seed-source"\n'
        'description = "Sanitized acceptance source route."\n'
        'path_globs = ["src/**"]\n'
        'topic_keywords = ["seed source"]\n'
        'required_handles = ["A0.2"]\n'
        'optional_handles = []\n'
        "required_files = []\n"
        'optional_files = ["docs/note.md"]\n'
        "max_required_bytes = 393216\n"
        "\n"
        "[[route]]\n"
        'id = "seed-generated"\n'
        'description = "Sanitized acceptance generated-output route."\n'
        'path_globs = ["generated/**"]\n'
        'topic_keywords = ["seed generated"]\n'
        'required_handles = ["A0.2"]\n'
        'optional_handles = []\n'
        "required_files = []\n"
        "optional_files = []\n"
        "max_required_bytes = 393216\n",
        encoding="utf-8", newline="\n",
    )
    # The pair receipt carries the pair key the router recomputes; the reader and
    # router validate the declared schema and the sha256: prefix form only, so a
    # sanitized placeholder key is a genuine router input, not a mock.
    (root / "docs" / "normative-pair.toml").write_text(
        'schema_version = "eliot-normative-pair-v2-sharded"\n'
        'pair_key = "sha256:' + "0" * 64 + '"\n',
        encoding="utf-8", newline="\n",
    )
    # A committed assignment contract whose active rows make a checklist record
    # required for the seeded issues, and whose terminal rows make none required;
    # the reader/gate reads requirement from these rows, never from a path guess.
    (root / ".github" / "work-unit-cohort.toml").write_text(
        'schema_version = "eliot-work-unit-cohort-v1"\n'
        "\n"
        "[repository]\n"
        'owner = "sanitized"\n'
        'name = "acceptance"\n'
        "\n"
        "[[row]]\n"
        "issue = 2965\n"
        'unit = "SEED-UNIT"\n'
        'body_sha256 = "' + hashlib.sha256(b"seed-body").hexdigest() + '"\n'
        'disposition = "assigned"\n'
        "prerequisites = []\n"
        "\n"
        "[[row]]\n"
        "issue = 4000\n"
        'unit = "SEED-TERMINAL-UNIT"\n'
        'body_sha256 = "' + hashlib.sha256(b"terminal-body").hexdigest() + '"\n'
        'disposition = "superseded"\n'
        "prerequisites = []\n",
        encoding="utf-8", newline="\n",
    )


def _git_seed(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *arguments], check=True,
        capture_output=True, timeout=GIT_TIMEOUT_S,
    )


def _build_acceptance_repo() -> tuple[Path, str, str, str]:
    """Build the hermetic sanitized repository and its base/candidate revisions.

    The candidate change is deliberately multi-route and deliberately includes a
    modification, a DELETION, a RENAME and a GENERATED file, so every one of
    them participates in the changed-path denominator.
    """
    directory = tempfile.mkdtemp(prefix="eliot-doc-read-acceptance-")
    root = Path(directory)
    _write_seed(root)
    _git_seed(root, "init", "-b", "main")
    _git_seed(root, "config", "user.name", "ELIOT Acceptance")
    _git_seed(root, "config", "user.email", "acceptance@example.invalid")
    _git_seed(root, "config", "commit.gpgsign", "false")
    # Pin byte-exact blobs: an inherited autocrlf/eol conversion would rewrite
    # the very bytes the envelope is computed over.
    _git_seed(root, "config", "core.autocrlf", "false")
    _git_seed(root, "config", "core.eol", "lf")
    _git_seed(root, "add", "-A")
    _git_seed(root, "commit", "-m", "seed")
    base = _git(root, "rev-parse", "HEAD")

    # The candidate: an added source module (route seed-source), a generated
    # output (route seed-generated), a deleted tracked file, and a rename.
    (root / "src" / "core" / "added.rs").write_text("pub fn added() {}\n", encoding="utf-8", newline="\n")
    (root / "generated" / "schema.json").write_text('{"generated": true}\n', encoding="utf-8", newline="\n")
    (root / "src" / "core" / "legacy.rs").unlink()
    (root / "src" / "core" / "mod.rs").rename(root / "src" / "core" / "lib.rs")
    _git_seed(root, "add", "-A")
    _git_seed(root, "commit", "-m", "candidate")
    candidate = _git(root, "rev-parse", "HEAD")
    return root, base, candidate, candidate


def _valid_envelope(root: Path, base: str, candidate: str, topic: str) -> str:
    """Compute a genuinely valid envelope body for the seeded candidate."""
    base_tree = _resolve_tree(root, base, "base")
    candidate_tree = _resolve_tree(root, candidate, "candidate")
    changed = _changed_paths(root, base_tree, candidate_tree)
    candidate_root, recomputed = _recompute_final(root, candidate_tree, changed, topic)
    try:
        required = [
            {
                "path": item["path"],
                "sha256": item["sha256"],
                "bytes": item["bytes"],
                "handles": sorted(item.get("handles", [])),
            }
            for item in recomputed.read_receipt["required"]
        ]
        optional = [
            {
                "path": item["path"],
                "sha256": item["sha256"],
                "reason": "seeded optional one-hop expansion",
            }
            for item in recomputed.route.get("optional", [])
        ]
        envelope = {
            "schema_version": OUTER_SCHEMA,
            "repository": {"owner": "sanitized", "name": "acceptance"},
            "base_sha": _tree_digest(base_tree),
            "candidate": {"commit": candidate, "tree": _tree_digest(candidate_tree)},
            "changed_paths": changed,
            "topic": topic,
            "route_receipt_id": recomputed.route["receipt_id"],
            "read_receipt_id": recomputed.read_receipt["read_receipt_id"],
            "pair_key": recomputed.route["pair_key"],
            "matched_routes": list(recomputed.route["matched_routes"]),
            "required_items": required,
            "bundle": {
                "sha256": recomputed.read_receipt["bundle_sha256"],
                "bytes": recomputed.read_receipt["bundle_bytes"],
            },
            "optional_expansions": optional or "none",
            "contract_inputs": _contract_inputs(candidate_root),
            "attestation": {
                "read_by": "sanitized acceptance runner",
                "statement": "Every required item in this envelope was opened and read before mutation.",
            },
            "checklist": {
                "issue": 2965,
                "recorded": True,
                "bound_candidate_tree": _tree_digest(candidate_tree),
            },
        }
    finally:
        _release_candidate(candidate_root)
    payload = json.dumps(envelope, indent=2, sort_keys=True)
    return f"{BLOCK_START}\n```json\n{payload}\n```\n{BLOCK_END}\n"


ACCEPTANCE_TOPIC = "seed source and seed generated acceptance routing"

ACCEPTANCE_CASES: tuple[tuple[str, str, EvidenceFailure | None, str], ...] = (
    ("empty", "pr_2963_empty.md", EvidenceFailure.EMPTY_DOCUMENTATION_EVIDENCE,
     "the exact #2963 free-text block plus its prose attestation cannot pass"),
    ("duplicate-block", "pr_duplicate_block.md", EvidenceFailure.UNKNOWN_OR_DUPLICATE_BLOCK,
     "duplicate/ambiguous marker blocks fail"),
    ("placeholder", "pr_placeholder_prose.md", EvidenceFailure.ROUTER_INPUT_MISMATCH,
     "placeholder prose standing in for the recorded causal property is rejected"),
)


def _apply_mutation(valid_body: str, mutation: str) -> str:
    """Return the valid envelope body with exactly one bounded defect applied."""
    if mutation == "valid":
        return valid_body
    envelope = _extract_envelope(valid_body)
    mutated = json.loads(json.dumps(envelope))
    if mutation == "fabricated_receipts":
        mutated["route_receipt_id"] = "sha256:" + "a1" * 32
        mutated["read_receipt_id"] = "sha256:" + "b2" * 32
    elif mutation == "stale_base":
        mutated["base_sha"] = "sha256:" + "0" * 64
    elif mutation == "stale_tree":
        mutated["candidate"]["tree"] = "sha256:" + "0" * 64
    elif mutation == "partial_paths":
        mutated["changed_paths"] = mutated["changed_paths"][:1]
    elif mutation == "drop_route":
        mutated["matched_routes"] = mutated["matched_routes"][:1]
    elif mutation == "drop_required_item":
        mutated["required_items"] = mutated["required_items"][:-1]
    elif mutation == "break_pair_key":
        mutated["pair_key"] = "sha256:" + "1" * 64
    elif mutation == "break_bundle":
        mutated["bundle"]["sha256"] = "f" * 64
    elif mutation == "blank_attestation":
        mutated["attestation"]["read_by"] = ""
    elif mutation == "unrecord_checklist":
        mutated["checklist"]["recorded"] = False
        mutated["checklist"]["bound_candidate_tree"] = None
    elif mutation == "withhold_checklist_issue":
        # The owner's #2965 counterexample: the body withholds the number that
        # selects the contract row. The contract still requires a record, so
        # this is required_missing, never not_required.
        mutated["checklist"]["issue"] = None
        mutated["checklist"]["recorded"] = False
        mutated["checklist"]["bound_candidate_tree"] = None
    elif mutation == "unassigned_checklist_issue":
        # Identical outcome with an unassigned number substituted for null.
        mutated["checklist"]["issue"] = 999999
        mutated["checklist"]["recorded"] = False
        mutated["checklist"]["bound_candidate_tree"] = None
    elif mutation == "terminal_checklist_issue":
        # The contract declares no active row for this issue, so a missing
        # record does not block: this is the not_required state.
        mutated["checklist"]["issue"] = 4000
        mutated["checklist"]["recorded"] = False
        mutated["checklist"]["bound_candidate_tree"] = None
    elif mutation == "rebind_checklist_tree":
        mutated["checklist"]["bound_candidate_tree"] = "sha256:" + "0" * 64
    elif mutation == "optional_none":
        mutated["optional_expansions"] = "none"
    elif mutation == "unknown_field":
        mutated["reviewer_note"] = "an unknown field must be rejected"
    else:  # pragma: no cover - the mutation table is closed
        _fail(EvidenceFailure.MALFORMED_EVIDENCE_BLOCK, f"unknown acceptance mutation: {mutation}")
    payload = json.dumps(mutated, indent=2, sort_keys=True)
    return f"{BLOCK_START}\n```json\n{payload}\n```\n{BLOCK_END}\n"


def _verify_mutation(root: Path, base: str, candidate: str, valid_body: str,
                     mutation: str) -> tuple[EvidenceFailure | None, dict[str, Any] | None]:
    try:
        return None, verify(root, base, candidate, _apply_mutation(valid_body, mutation))
    except EvidenceError as exc:
        return exc.code, None


def run_acceptance(_live_root: Path) -> int:
    """Demonstrate every #2965 acceptance case over a real sanitized candidate.

    ``_live_root`` is unused: the demonstration is hermetic by design so it does
    not depend on the current branch state of the repository it runs in. It is
    retained in the signature so the controller can pass its own root.

    Prints the exact typed failure code (or PASS) per case. Exits nonzero only
    when a case did not behave as the issue requires.
    """
    del _live_root
    root, base, candidate, _ = _build_acceptance_repo()
    try:
        valid_body = _valid_envelope(root, base, candidate, ACCEPTANCE_TOPIC)
        expectations: tuple[tuple[str, str, EvidenceFailure | None, str], ...] = (
            ("valid-multi-route", "valid", None,
             "a valid multi-route envelope with every required item and exact current digest passes"),
            ("fabricated", "fabricated_receipts", EvidenceFailure.ROUTE_RECEIPT_MISMATCH,
             "plausible but fabricated route/read IDs fail deterministic recomputation"),
            ("stale-base", "stale_base", EvidenceFailure.BASE_OR_CANDIDATE_MISMATCH,
             "an envelope produced for an earlier base fails after the candidate moved"),
            ("stale-tree", "stale_tree", EvidenceFailure.BASE_OR_CANDIDATE_MISMATCH,
             "an envelope produced for an earlier candidate tree fails after the tree moved"),
            ("partial-path", "partial_paths", EvidenceFailure.UNCOVERED_CHANGED_PATH,
             "a subset of the final changed paths fails and names the uncovered path"),
            ("route-set", "drop_route", EvidenceFailure.ROUTE_SET_MISMATCH,
             "a changed route set fails closed"),
            ("required-item", "drop_required_item", EvidenceFailure.REQUIRED_ITEM_MISMATCH,
             "an omitted required handle/fragment fails closed"),
            ("pair-key", "break_pair_key", EvidenceFailure.PAIR_KEY_MISMATCH,
             "a changed normative pair key fails closed"),
            ("bundle-digest", "break_bundle", EvidenceFailure.BUNDLE_DIGEST_MISMATCH,
             "a plausible but nonmatching bundle digest fails closed"),
            ("attestation", "blank_attestation", EvidenceFailure.ATTESTATION_MISSING,
             "a missing explicit reading attestation fails; an attestation never substitutes for machine fields"),
            ("checklist-missing", "unrecord_checklist", EvidenceFailure.CHECKLIST_REQUIRED_MISSING,
             "a missing checklist blocks a MET claim only when the assignment contract requires one"),
            ("checklist-issue-null", "withhold_checklist_issue", EvidenceFailure.CHECKLIST_REQUIRED_MISSING,
             "a null checklist.issue cannot skip an active contract row and report not_required"),
            ("checklist-issue-unassigned", "unassigned_checklist_issue", EvidenceFailure.CHECKLIST_REQUIRED_MISSING,
             "an unassigned checklist.issue number cannot skip an active contract row either"),
            ("checklist-stale-tree", "rebind_checklist_tree", EvidenceFailure.CHECKLIST_REQUIRED_MISSING,
             "a checklist bound to a different candidate tree is stale, a separate state from missing"),
            ("checklist-not-required", "terminal_checklist_issue", None,
             "a missing checklist does not block when the contract requires none"),
            ("optional-none", "optional_none", None,
             "optional 'none' is valid when routing offered optional material the author did not open"),
            ("unknown-field", "unknown_field", EvidenceFailure.MALFORMED_EVIDENCE_BLOCK,
             "an unknown envelope field is rejected"),
        )
        surprising: list[str] = []
        # The three committed free-text/body-parser samples are verified verbatim.
        for name, fixture, expect, note in ACCEPTANCE_CASES:
            try:
                verify(root, base, candidate, fixture_text(fixture))
            except EvidenceError as exc:
                if exc.code is expect:
                    print(f"  {name}: FAIL-CLOSED {exc.code.value} ({note})")
                else:
                    surprising.append(f"{name}: got {exc.code.value}, want {expect.value}")
                    print(f"  {name}: WRONG-CODE {exc.code.value} != {expect.value} ({note})")
            else:
                surprising.append(f"{name}: unexpectedly passed")
                print(f"  {name}: UNEXPECTED-PASS ({note})")
        for name, mutation, expect, note in expectations:
            code, result = _verify_mutation(root, base, candidate, valid_body, mutation)
            if expect is None:
                if code is None and result is not None:
                    print(
                        f"  {name}: PASS routes={','.join(result['matched_routes'])} "
                        f"required={result['required_items']} paths={len(result['changed_paths'])} "
                        f"checklist={result['checklist_state']} ({note})"
                    )
                else:
                    surprising.append(f"{name}: unexpected failure {code}")
                    print(f"  {name}: UNEXPECTED-FAIL {code} ({note})")
            elif code is expect:
                print(f"  {name}: FAIL-CLOSED {code.value} ({note})")
            else:
                surprising.append(f"{name}: got {code}, want {expect.value}")
                print(f"  {name}: WRONG-CODE {code} != {expect.value} ({note})")
        total = len(ACCEPTANCE_CASES) + len(expectations)
        if surprising:
            print(f"DOC_READ_EVIDENCE_ACCEPTANCE: FAIL cases={total}: {'; '.join(surprising)}")
            return 1
        print(f"DOC_READ_EVIDENCE_ACCEPTANCE: PASS cases={total}")
        return 0
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.work_unit_gate doc-read-evidence",
        description=(
            "Executable pre-merge contract for documentation read evidence (#2965). "
            "Recomputes routing and the verified read bundle over the FINAL merge candidate "
            "using the single docs_router/docs_read algorithms and compares every field of "
            "the one versioned eliot-doc-read-pr-evidence-v2 envelope. The real "
            "root/controller merge action must run this command on the final merge candidate "
            "and refuse a nonzero exit."
        ),
        epilog=(
            "Exits: 0 valid current evidence for the final candidate; 1 typed "
            "documentation/checklist failure (see DOC_READ_EVIDENCE_FAIL <CODE>); "
            "2 usage/configuration failure."
        ),
    )
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument(
        "--base", help="final base commit or tree the candidate will merge onto",
    )
    selection.add_argument(
        "--acceptance", action="store_true",
        help="demonstrate the sanitized acceptance fixtures (NOT a test framework)",
    )
    parser.add_argument(
        "--candidate", help="final candidate commit or tree (the merge result to gate)",
    )
    parser.add_argument("--pr-body", help="path to the pull request body markdown file")
    parser.add_argument("--root", default=".", help="repository root holding the candidate history")
    parser.add_argument(
        "--work-issue", default=None,
        help="trusted assigned work-issue ID from the merge controller; when supplied, "
        "the checklist requirement lookup uses it and the body checklist.issue must match it",
    )
    parser.add_argument("--json", action="store_true", help="emit the JSON projection instead of the human one")
    return parser


def _emit(result: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    print("DOC_READ_EVIDENCE: PASS")
    print(f"  base_tree={result['base_tree']}")
    print(f"  candidate_tree={result['candidate_tree']}")
    print(f"  route_receipt={result['route_receipt_id']}")
    print(f"  read_receipt={result['read_receipt_id']}")
    print(f"  pair_key={result['pair_key']}")
    print(f"  matched_routes={','.join(result['matched_routes'])}")
    print(f"  required_items={result['required_items']}")
    print(f"  changed_paths={len(result['changed_paths'])}")
    print(f"  bundle_sha256={result['bundle_sha256']}")
    print(f"  checklist_state={result['checklist_state']}")
    contract = ",".join(str(issue) for issue in result["assignment_contract"]) or "none"
    print(f"  assignment_contract={contract}")
    print(f"  proof_ceiling={result['proof_ceiling']}")
    merge = result["merge_integration"]
    print(f"  merge_in_repository_consumers={','.join(merge['in_repository_merge_consumers']) or 'none'}")
    if merge["external_merge_action_required"]:
        print("  external_merge_action_required=True (blocking owner action, not simulated)")


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for `python -m scripts.work_unit_gate doc-read-evidence`."""
    parser = _build_parser()
    try:
        parsed = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    except SystemExit as exc:  # argparse already printed usage/problem
        return int(exc.code) if isinstance(exc.code, int) else 2
    try:
        if parsed.acceptance:
            return run_acceptance(Path(parsed.root).resolve())
        if not parsed.candidate or not parsed.pr_body:
            print(
                "DOC_READ_EVIDENCE_FAIL: usage/configuration failure: "
                "--candidate and --pr-body are both required with --base",
                file=sys.stderr,
            )
            return 2
        root = Path(parsed.root).resolve()
        work_issue: int | None = None
        if parsed.work_issue is not None:
            try:
                work_issue = int(str(parsed.work_issue), 10)
            except (TypeError, ValueError):
                work_issue = None
            if work_issue is None or work_issue <= 0:
                print(
                    "DOC_READ_EVIDENCE_FAIL: usage/configuration failure: "
                    "--work-issue must be a positive integer when supplied",
                    file=sys.stderr,
                )
                return 2
        try:
            body = Path(parsed.pr_body).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            print(
                f"DOC_READ_EVIDENCE_FAIL: {EvidenceFailure.EMPTY_DOCUMENTATION_EVIDENCE.value}: "
                f"--pr-body unreadable ({type(exc).__name__})",
                file=sys.stderr,
            )
            return 1
        _emit(verify(root, parsed.base, parsed.candidate, body, work_issue), parsed.json)
        return 0
    except EvidenceError as exc:
        print(f"DOC_READ_EVIDENCE_FAIL: {exc.code.value}: {exc.detail}", file=sys.stderr)
        return 1
    except Exception as exc:  # pragma: no cover - bounded internal failure
        print(
            f"DOC_READ_EVIDENCE_FAIL: {EvidenceFailure.MALFORMED_EVIDENCE_BLOCK.value}: "
            f"internal failure ({type(exc).__name__})",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
