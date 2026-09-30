"""Deterministic backup dependency-link readiness tests (issue #974).

Declared denominator: 14 cases, exactly 1..14. Frozen fixtures live under
``scripts/testdata/work-unit-gate/backup-link/`` and are owned alongside this
module. Base commit: 9cddf1752596faf971e7c718df76da3a9f2dff00, which every
base-to-current comparison below reads through ``git cat-file blob`` after
proving the base is an ancestor of ``HEAD``.

Scope is preparation-only readiness: manifest edges, symbol justification,
lockfile binding, and single-writer/record-keeping guards. This file is not
implementation proof.

One frozen schema, four files. Every member is validated, and a missing or
stale member blocks instead of falling back to a value this module builds for
itself:

* ``denominator.json`` -- ``issue``, ``base``, ``cases`` (exactly 1..14),
  ``affected_manifests``, ``manifest_identities`` (per affected path: the base
  blob digest, the working-tree digest, and whether the two are
  byte-identical), ``dependency_edges`` (consumer, dependency, manifest,
  line, symbol, and the exact manifest declaration), ``unchanged_since_base``
  (the edges whose declaration is byte-identical at the base blob and in the
  working tree), ``frozen_base``, and ``denominator_digest``.
* ``edge-symbols.json`` -- ``base`` and ``edges`` (package, dependency,
  ``imported_public_symbol``, ``symbol_file``, ``symbol_declaration``, and
  ``consumer_file``).
* ``lock-delta.json`` -- ``base``, ``delta``, ``frozen_lock_edges``,
  ``frozen_packages``, ``kernel_lock_includes``, and ``forbidden``.
* ``malformed.raw.json`` -- syntactically valid JSON that violates the
  denominator schema, so the malformed path feeds the real validator instead
  of a parser error.

``denominator_digest`` is the SHA-256 of the denominator's own canonical
serialisation: every member except ``denominator_digest`` itself, encoded as
UTF-8 JSON with sorted keys, ``,`` and ``:`` separators with no whitespace,
and no non-ASCII escaping. Case 1 recomputes it and compares, so an edited
member without a recomputed digest fails.

Whole-file identity between the base and the working tree is measured, not
assumed, and it is recorded per manifest. Most affected manifests have moved
since the frozen base, because other admitted issues added their own edges in
the same files; the claim this work unit actually has to support is narrower
and is proven per edge instead. Each of the ten frozen edge declarations is
byte-identical in the base blob and in the working tree and appears exactly
once in each, and every frozen edge's dependency is present in the parsed
manifest at the base as well as in the working tree. That is what "existing
dependency lines are verified no-ops, not rewritten" means here; whole-file or
whole-table equality would be both false -- root ``Cargo.toml`` gained six
workspace aliases and two members and lost one member between the base and
the working tree, all through other admitted issues -- and stronger than the
work unit is entitled to claim. The per-fact claims are stated per case: case
7 pins the versions and the six aliases it reads, case 8 pins the storage
members, the five aliases the admitted edges consume, and ``default-members``,
``exclude`` and ``resolver``.

``affected_manifests`` is the affected-MANIFEST denominator: every manifest
that declares one of the ten admitted edges, not only the manifests this work
unit happens to edit. Three of those ten edges live in
``crates/storage/eliot-backup/Cargo.toml`` and
``crates/storage/eliot-blob/Cargo.toml``, so both manifests are inside the
denominator and both carry measured ``manifest_identities``. They are recorded
as affected instead of being moved out of the frozen edge set and left to the
edge-symbols and lock fixtures alone, because those two manifests are the
subject of cases 2, 4 and 5, and narrowing the denominator would have deleted
exactly the dependency evidence this gate exists to hold while satisfying the
case 1 completeness check -- "every frozen edge's manifest is in the
denominator" -- only by deleting the edges that check was written to police.
The completeness check is the point of case 1, so the denominator covers the
edges instead of the edges being dropped to fit the denominator.

Source anchors bind to declaration text, not to line numbers. A line number
is not a stable identity for a source location, and this repository's own
delivery doctrine anchors evidence on ``path::symbol`` for that reason.
``edge-symbols.json`` therefore records the exact ``pub`` declaration that
justifies an edge; each case requires that declaration to still be declared by
the named owner file and requires the named consumer to still reference both
the symbol and the crate.

Completeness is measured against the independent expected sets declared in
this module -- :data:`EXPECTED_AFFECTED_MANIFESTS`, :data:`EXPECTED_FROZEN_EDGES`
and :data:`EXPECTED_FROZEN_LOCK_EDGES` -- never against a copy of the same
fixture list.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback
    import tomli as tomllib  # type: ignore[no-redef]

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_DIR = REPO_ROOT / "scripts" / "tests"
FIXTURE_DIR = REPO_ROOT / "scripts" / "testdata" / "work-unit-gate" / "backup-link"
FROZEN_FIXTURES = (
    "denominator.json",
    "edge-symbols.json",
    "lock-delta.json",
    "malformed.raw.json",
)

BASE_COMMIT = "9cddf1752596faf971e7c718df76da3a9f2dff00"
DENOMINATOR_CASES = list(range(1, 15))
GIT_TIMEOUT = 300

ROOT_MANIFEST = REPO_ROOT / "Cargo.toml"
ROOT_LOCK = REPO_ROOT / "Cargo.lock"
BOUNDARY_CONFIG = REPO_ROOT / "config" / "architecture-boundaries.toml"
KERNEL_MANIFEST = REPO_ROOT / "bins" / "eliot-kernel" / "Cargo.toml"
WATCHDOG_MANIFEST = REPO_ROOT / "bins" / "eliot-watchdog" / "Cargo.toml"
ENDPOINT_MANIFEST = (
    REPO_ROOT / "crates" / "kernel" / "eliot-host-control-endpoint" / "Cargo.toml"
)
HOST_SERVICE_MANIFEST = (
    REPO_ROOT / "crates" / "kernel" / "eliot-host-service" / "Cargo.toml"
)
BACKUP_MANIFEST = REPO_ROOT / "crates" / "storage" / "eliot-backup" / "Cargo.toml"

KERNEL_BACKUP_RS = REPO_ROOT / "bins" / "eliot-kernel" / "src" / "backup_restore.rs"
KERNEL_PORTS_RS = (
    REPO_ROOT / "bins" / "eliot-kernel" / "src" / "backup_restore_ports.rs"
)
BACKUP_LIB_RS = REPO_ROOT / "crates" / "storage" / "eliot-backup" / "src" / "lib.rs"
ENDPOINT_LIB_RS = (
    REPO_ROOT
    / "crates"
    / "kernel"
    / "eliot-host-control-endpoint"
    / "src"
    / "lib.rs"
)
HOST_RUNTIME_CONTROL_RS = (
    REPO_ROOT / "crates" / "kernel" / "eliot-host-service" / "src" / "runtime_control.rs"
)
WATCHDOG_SRC_DIR = REPO_ROOT / "bins" / "eliot-watchdog" / "src"
KERNEL_SRC_DIR = REPO_ROOT / "bins" / "eliot-kernel" / "src"

# The issue's affected-MANIFEST denominator: every manifest that declares one
# of the ten admitted edges below, whether or not this work unit edits it.
# This is an independent expected set: case 1 requires the frozen denominator
# to cover exactly these paths, so the fixture can neither omit one nor
# quietly grow the denominator, and -- just as load-bearing -- every frozen
# edge's manifest has to appear here. The two storage manifests are in this
# set because three admitted edges are declared in them; see the module
# docstring for why the denominator grew rather than the edge set shrinking.
EXPECTED_AFFECTED_MANIFESTS = (
    "bins/eliot-kernel/Cargo.toml",
    "bins/eliot-watchdog/Cargo.toml",
    "crates/kernel/eliot-host-control-endpoint/Cargo.toml",
    "crates/kernel/eliot-host-service/Cargo.toml",
    "crates/storage/eliot-backup/Cargo.toml",
    "crates/storage/eliot-blob/Cargo.toml",
    "Cargo.toml",
    "Cargo.lock",
)

# The admitted (consumer, dependency) pairs this work unit prepares, and the
# (package, dependency) pairs it expects the lock to resolve. Both tuples are
# the expected sets; the fixtures are the recorded evidence and must match.
EXPECTED_FROZEN_EDGES = (
    ("bins/eliot-kernel/Cargo.toml", "eliot-backup"),
    ("bins/eliot-kernel/Cargo.toml", "eliot-ipc"),
    ("bins/eliot-kernel/Cargo.toml", "eliot-protocol"),
    ("bins/eliot-kernel/Cargo.toml", "eliot-store-api"),
    ("crates/kernel/eliot-host-control-endpoint/Cargo.toml", "eliot-host-service"),
    ("crates/kernel/eliot-host-control-endpoint/Cargo.toml", "eliot-ipc"),
    ("crates/kernel/eliot-host-service/Cargo.toml", "eliot-protocol"),
    ("crates/storage/eliot-backup/Cargo.toml", "eliot-blob-api"),
    ("crates/storage/eliot-backup/Cargo.toml", "eliot-store-api"),
    ("crates/storage/eliot-blob/Cargo.toml", "eliot-blob-api"),
)

# The `[workspace.dependencies]` aliases the ten admitted edges consume. Each
# edge above that is declared as `X.workspace = true` resolves through one of
# these; `eliot-backup` is absent because its kernel edge is an explicit path
# and version pin, not an alias. Case 8 compares exactly these across the two
# ends, because they are the aliasing facts this work unit freezes.
FROZEN_WORKSPACE_ALIASES = (
    "eliot-blob-api",
    "eliot-host-service",
    "eliot-ipc",
    "eliot-protocol",
    "eliot-store-api",
)

EXPECTED_FROZEN_LOCK_EDGES = (
    ("eliot-kernel", "eliot-backup"),
    ("eliot-kernel", "eliot-ipc"),
    ("eliot-kernel", "eliot-protocol"),
    ("eliot-kernel", "eliot-store-api"),
    ("eliot-host-control-endpoint", "eliot-host-service"),
    ("eliot-host-control-endpoint", "eliot-ipc"),
    ("eliot-host-service", "eliot-protocol"),
    ("eliot-backup", "eliot-blob-api"),
    ("eliot-backup", "eliot-store-api"),
    ("eliot-blob", "eliot-blob-api"),
)

EXPECTED_FROZEN_PACKAGES = (
    "eliot-backup",
    "eliot-blob-api",
    "eliot-kernel",
    "eliot-store-api",
)

# Change kinds the frozen lock delta declares out of bounds. Each is checked
# against the real base-to-current lock movement, not merely listed.
FORBIDDEN_LOCK_CHANGE_KINDS = (
    "version-upgrade",
    "registry-source",
    "checksum-added",
    "unrelated-alias",
    "members-change",
    "default-members-change",
)

# The exact locked checks this gate runs. Case 11 is "the unchanged affected
# packages and the workspace compile", so it runs the real commands and
# requires a zero exit status. The budget is generous because a cold
# all-targets workspace check is genuinely expensive; exceeding it fails the
# case, because a check that never finished is not a passing check.
COMPILE_COMMANDS = (
    [
        "cargo", "check", "--locked",
        "-p", "eliot-kernel",
        "-p", "eliot-watchdog",
        "-p", "eliot-host-control-endpoint",
        "-p", "eliot-host-service",
        "--all-targets",
    ],
    ["cargo", "check", "--locked", "--workspace", "--all-targets"],
)
CARGO_TIMEOUT_SECONDS = 3600

# Single-writer / ownership markers. These are extracted once so the negative
# probe at case 12 can remove one and observe the same predicate go red,
# rather than asserting a marker is both present and absent.
SINGLE_WRITER_MARKERS = ("S-CONC-ACCEPT", "#994", "eliot-store-memory")
WATCHDOG_OWNERSHIP_MARKERS = (
    "SAFETY-OWNERSHIP",
    "0014-unsafe-ownership-and-exceptions",
)
# The token a gate file must carry to claim this work unit's single-writer
# scope. Exactly one test file may carry it.
SINGLE_WRITER_SCOPE_TOKEN = "backup_dependency_link"

# Backup orchestration and provider crates. The watchdog binary is not a
# backup consumer, so these must stay out of its manifest and out of its
# sources. `eliot-ipc` and `eliot-protocol` are owner-neutral contract edges
# the watchdog genuinely declares and uses, so they are asserted positively
# instead.
BACKUP_ORCHESTRATION_EDGES = ("eliot-backup", "eliot-blob-api", "eliot-blob")
WATCHDOG_RUNTIME_ROOT = "eliot-watchdog"
BOUNDARY_DECLARATION_KINDS = (
    "struct", "enum", "trait", "type", "fn", "const", "static", "mod", "union",
)

# Forbidden phrases are built obliquely so this file's own source never
# literally contains a completion claim that case 13 forbids.
FORBIDDEN_IMPLEMENTATION_CLAIMS = (
    "cap" + "ture complete",
    "rest" + "ore complete",
    "cut" + "over complete",
    "produc" + "tion cutover",
    "live re" + "store",
    "cut" + "over execut",
    "rest" + "ore execut",
    "back" + "up execut",
    "implementa" + "tion complete",
)


# --------------------------------------------------------------------------
# base reading
# --------------------------------------------------------------------------
def require_base_ancestor(case: int) -> None:
    """Fail the case unless the frozen base is an ancestor of ``HEAD``.

    Without this, a base-to-current comparison has no meaning: a base that is
    not in this branch's history describes a different repository state, and
    every equality the cases derive from it would be comparing unrelated
    bytes.
    """
    proc = subprocess.run(
        ["git", "merge-base", "--is-ancestor", BASE_COMMIT, "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"974/{case}: frozen base {BASE_COMMIT} is not an ancestor of HEAD, "
            "so the recorded base-to-current evidence does not describe this "
            "branch; stale dependency evidence blocks dispatch",
        )


def git_blob(relative: str, rev: str = BASE_COMMIT) -> bytes:
    """Return the exact bytes of ``relative`` at ``rev``."""
    proc = subprocess.run(
        ["git", "cat-file", "blob", f"{rev}:{relative}"],
        cwd=REPO_ROOT,
        capture_output=True,
        timeout=GIT_TIMEOUT,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"974: cannot read {relative!r} at {rev}; the frozen base blob is "
            "unavailable, so base-to-current evidence blocks dispatch",
        )
    return proc.stdout


def base_text(relative: str) -> str:
    """Return ``relative`` as UTF-8 text at the frozen base commit."""
    return git_blob(relative).decode("utf-8")


def base_manifest_dependencies(relative: str) -> dict:
    """Return the ``[dependencies]`` table of a manifest at the base commit."""
    return load_toml_bytes(git_blob(relative)).get("dependencies", {})


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------
def load_toml(path: Path) -> dict:
    """Parse a TOML file from disk."""
    return load_toml_bytes(path.read_bytes())


def load_toml_bytes(data: bytes) -> dict:
    """Parse TOML from raw bytes."""
    return tomllib.loads(data.decode("utf-8"))


def read_text(path: Path) -> str:
    """Read a text file as UTF-8."""
    return path.read_text(encoding="utf-8")


def load_fixture_json(name: str) -> tuple[str, object | None]:
    """Load a frozen JSON fixture; return (raw_text, parsed) or ("", None)."""
    fixture = FIXTURE_DIR / name
    if not fixture.is_file():
        return "", None
    raw = fixture.read_text(encoding="utf-8")
    return raw, json.loads(raw)


def require_fixture_json(case: int, name: str) -> tuple[str, object]:
    """Load a frozen JSON fixture and fail the case when it is absent.

    The frozen bundle is the evidence this gate reasons about, so a missing
    or unreadable fixture must block dispatch instead of degrading the case
    to a live-only probe. Returning ``None`` here and branching on it would
    let the whole denominator report OK with zero dependency evidence, which
    is the exact false-ready state acceptance item 14 forbids.
    """
    raw, parsed = load_fixture_json(name)
    if parsed is None:
        raise AssertionError(
            f"974/{case}: frozen evidence {name} is missing or unreadable under "
            f"{FIXTURE_DIR.name}/; stale or absent evidence blocks dispatch",
        )
    return raw, parsed


def sha256_hex(data: bytes) -> str:
    """Return the hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# denominator schema
# --------------------------------------------------------------------------
def canonical_denominator_bytes(obj: dict) -> bytes:
    """Return the canonical serialisation a denominator digest is taken over.

    Rule, restated so the digest is reproducible by a reader: drop the
    ``denominator_digest`` member itself, then encode the remaining members
    as UTF-8 JSON with sorted keys, ``,``/``:`` separators, no whitespace and
    no non-ASCII escaping.
    """
    payload = {k: v for k, v in obj.items() if k != "denominator_digest"}
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def denominator_digest(obj: dict) -> str:
    """Compute the real digest of a denominator's own members."""
    return sha256_hex(canonical_denominator_bytes(obj))


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _is_edge_record(value: object, fields: tuple[str, ...]) -> str | None:
    """Return the first missing/blank field of an edge record, else ``None``."""
    if not isinstance(value, dict):
        return "is not an object"
    for field in fields:
        if not str(value.get(field, "")).strip():
            return f"omits {field}"
    return None


def validate_denominator(obj: object) -> list[str]:
    """Validate a committed denominator object against the frozen schema.

    Every member is checked here, including the digest: a denominator whose
    recorded digest does not describe its own members is not evidence, and
    this is the same validator case 14 feeds the malformed fixture to.
    """
    errors: list[str] = []
    if not isinstance(obj, dict):
        return ["denominator must be a JSON object"]
    if obj.get("issue") != 974:
        errors.append(f"issue must be 974, got {obj.get('issue')!r}")
    if obj.get("base") != BASE_COMMIT:
        errors.append(f"base must be {BASE_COMMIT}, got {obj.get('base')!r}")
    if obj.get("frozen_base") != BASE_COMMIT:
        errors.append(
            f"frozen_base must be {BASE_COMMIT}, got {obj.get('frozen_base')!r}",
        )
    if obj.get("cases") != DENOMINATOR_CASES:
        errors.append(f"cases must be exactly 1..14, got {obj.get('cases')!r}")

    manifests = obj.get("affected_manifests")
    if not isinstance(manifests, list) or not manifests:
        errors.append("affected_manifests must be a non-empty list")
    else:
        for entry in manifests:
            if not isinstance(entry, str) or not entry.strip():
                errors.append(f"affected_manifests has a blank entry: {entry!r}")

    identities = obj.get("manifest_identities")
    if not isinstance(identities, list) or not identities:
        errors.append("manifest_identities must be a non-empty list")
    else:
        for entry in identities:
            if not isinstance(entry, dict):
                errors.append("a manifest identity is not an object")
                continue
            if not str(entry.get("manifest", "")).strip():
                errors.append("a manifest identity omits manifest")
            for field in ("base_blob_sha256", "current_blob_sha256"):
                if not _is_digest(entry.get(field)):
                    errors.append(
                        f"manifest identity {entry.get('manifest')!r} has no {field}",
                    )
            if not isinstance(entry.get("byte_identical_since_base"), bool):
                errors.append(
                    f"manifest identity {entry.get('manifest')!r} does not record "
                    "byte_identical_since_base as a boolean",
                )

    edges = obj.get("dependency_edges")
    if not isinstance(edges, list) or not edges:
        errors.append("dependency_edges must be a non-empty list")
    else:
        for entry in edges:
            problem = _is_edge_record(
                entry, ("consumer", "dependency", "manifest", "symbol", "declaration"),
            )
            if problem:
                errors.append(f"a frozen edge {problem}")
            elif not isinstance(entry.get("line"), int):
                errors.append(
                    f"frozen edge {entry['manifest']}::{entry['dependency']} has no line",
                )

    unchanged = obj.get("unchanged_since_base")
    if not isinstance(unchanged, list) or not unchanged:
        errors.append("unchanged_since_base must be a non-empty list")
    else:
        for entry in unchanged:
            problem = _is_edge_record(entry, ("manifest", "dependency", "declaration"))
            if problem:
                errors.append(f"an unchanged_since_base entry {problem}")

    if not _is_digest(obj.get("denominator_digest")):
        errors.append("denominator_digest is not a SHA-256 hex digest")
    elif obj["denominator_digest"] != denominator_digest(obj):
        errors.append(
            "denominator_digest does not describe its own members; recompute it "
            "over the canonical serialisation",
        )
    return errors


def validate_denominator_text(raw: str) -> list[str]:
    """Validate denominator evidence that is still in its serialized form.

    Frozen evidence arrives as text, and evidence that cannot be read is not
    a denominator. Text that does not parse is therefore itself the
    validator's error list, so a caller can ask the same question of bytes
    and of a parsed value without special-casing the failure.
    """
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as error:
        return [f"denominator is not valid JSON: {error}"]
    return validate_denominator(parsed)


# --------------------------------------------------------------------------
# edge-symbols schema
# --------------------------------------------------------------------------
def validate_edge_symbols(case: int, fixture: object) -> list[str]:
    """Validate the frozen edge/symbol bundle against the frozen schema."""
    errors: list[str] = []
    if not isinstance(fixture, dict):
        return ["edge symbols must be a JSON object"]
    if fixture.get("base") != BASE_COMMIT:
        errors.append(f"base must be {BASE_COMMIT}, got {fixture.get('base')!r}")
    edges = fixture.get("edges")
    if not isinstance(edges, list) or not edges:
        return errors + ["edges must be a non-empty list"]
    for entry in edges:
        problem = _is_edge_record(
            entry,
            (
                "package",
                "dependency",
                "imported_public_symbol",
                "symbol_file",
                "symbol_declaration",
                "consumer_file",
            ),
        )
        if problem:
            errors.append(f"a frozen symbol edge {problem}")
    return errors


# --------------------------------------------------------------------------
# lock-delta schema
# --------------------------------------------------------------------------
def validate_lock_delta(case: int, fixture: object) -> list[str]:
    """Validate the frozen lock-delta bundle against the frozen schema."""
    errors: list[str] = []
    if not isinstance(fixture, dict):
        return ["lock delta must be a JSON object"]
    if fixture.get("base") != BASE_COMMIT:
        errors.append(f"base must be {BASE_COMMIT}, got {fixture.get('base')!r}")
    if not str(fixture.get("delta", "")).strip():
        errors.append("delta must be a non-empty explained statement")
    for field in ("frozen_lock_edges", "frozen_packages", "kernel_lock_includes",
                  "forbidden"):
        value = fixture.get(field)
        if not isinstance(value, list) or not value:
            errors.append(f"{field} must be a non-empty list")
    forbidden = fixture.get("forbidden")
    if isinstance(forbidden, list) and forbidden:
        unknown = [k for k in forbidden if k not in FORBIDDEN_LOCK_CHANGE_KINDS]
        if unknown:
            errors.append(f"forbidden names unknown change kinds: {unknown}")
    for entry in fixture.get("frozen_lock_edges", []) or []:
        problem = _is_edge_record(entry, ("package", "dependency"))
        if problem:
            errors.append(f"a frozen lock edge {problem}")
    return errors


# --------------------------------------------------------------------------
# content helpers
# --------------------------------------------------------------------------
def manifest_dependencies(manifest_path: Path) -> dict:
    """Return the [dependencies] table of a Cargo manifest."""
    manifest = load_toml(manifest_path)
    dependencies = manifest.get("dependencies", {})
    assert isinstance(dependencies, dict), f"bad [dependencies] in {manifest_path}"
    return dependencies


def unidentified_manifests(affected: object, identities: object) -> list[str]:
    """Return the affected manifests that carry no measured manifest identity.

    ``manifest_identities`` is what carries the base and working-tree digests,
    so an affected manifest with no identity entry is a path the denominator
    claims while nothing measures it. Used once for the verdict and once for the
    negative probe below.
    """
    if not isinstance(affected, list) or not isinstance(identities, list):
        return ["affected_manifests or manifest_identities is not a list"]
    measured = {
        str(entry.get("manifest", "")) for entry in identities if isinstance(entry, dict)
    }
    return sorted({str(path) for path in affected} - measured)


def changed_aliases(
    base_dependencies: dict,
    current_dependencies: dict,
    aliases: tuple[str, ...],
) -> list[str]:
    """Return the named aliases that are absent at or altered between two ends.

    Used once for the verdict and once for the negative probe, so the check
    that reports an unchanged alias table is the same check that reports an
    edited one. A missing alias at either end counts as changed: an alias that
    was deleted is exactly the alias movement this predicate exists to catch.
    """
    return [
        alias
        for alias in aliases
        if base_dependencies.get(alias) is None
        or current_dependencies.get(alias) is None
        or base_dependencies[alias] != current_dependencies[alias]
    ]


def uses_crate(rs_text: str, crate_name: str) -> bool:
    """Check for a real ``use`` of a Rust crate (``use x`` or ``x::``)."""
    return f"use {crate_name}" in rs_text or f"{crate_name}::" in rs_text


def declares_public_symbol(rs_text: str, symbol: str) -> bool:
    """Check that ``symbol`` is declared as a public item of a real kind."""
    pattern = (
        r"^[^\n]*\bpub(?:\([^\)]*\))?\s+(?:"
        + "|".join(BOUNDARY_DECLARATION_KINDS)
        + r")\s+"
        + re.escape(symbol)
        + r"\b"
    )
    return re.search(pattern, rs_text, re.MULTILINE) is not None


def references_symbol(rs_text: str, symbol: str) -> bool:
    """Check that ``symbol`` appears as a whole word in the source."""
    return re.search(r"\b" + re.escape(symbol) + r"\b", rs_text) is not None


def missing_markers(text: str, markers: tuple[str, ...]) -> list[str]:
    """Return the markers of ``markers`` that ``text`` does not contain."""
    return [marker for marker in markers if marker not in text]


def scope_claimant_names(candidates: object) -> list[str]:
    """Return the sorted candidate names that claim this work unit's scope.

    Used for the verdict and for the negative probe alike, so the probe shows
    the duplicate detector reacting rather than restating the expectation.
    """
    if not isinstance(candidates, (list, tuple)):
        return []
    return sorted(
        str(name) for name in candidates if SINGLE_WRITER_SCOPE_TOKEN in str(name)
    )


def multi_version_index(lock: dict) -> dict[str, dict[str, dict]]:
    """Index a lock's packages by name and version.

    Several third-party names in this workspace resolve at more than one
    version, so every base-to-current comparison keys on the pair. Keying on
    the name alone would let a sweep inspect one of the two entries and report
    a result it never established.
    """
    entries = lock.get("package", [])
    assert isinstance(entries, list) and entries, "Cargo.lock has no packages"
    index: dict[str, dict[str, dict]] = {}
    for entry in entries:
        index.setdefault(str(entry["name"]), {})[str(entry["version"])] = entry
    return index


def unambiguous_index(index: dict[str, dict[str, dict]]) -> dict[str, dict]:
    """Reduce a (name, version) index to the names that resolve exactly once.

    A name-keyed map cannot represent a name that resolves twice, so those
    names are left out instead of being silently overwritten by whichever
    entry happened to come last. Every name this gate inspects by name is one
    of the workspace path crates, which resolve once, and the assertion below
    keeps that assumption honest rather than assumed.
    """
    return {name: next(iter(versions.values())) for name, versions in index.items()
            if len(versions) == 1}


def lock_packages() -> dict[str, dict]:
    """Parse Cargo.lock into {package name: entry} for unambiguous names."""
    return unambiguous_index(multi_version_index(load_toml(ROOT_LOCK)))


def lock_resolves(index: dict[str, dict[str, dict]], package: str, dependency: str) -> bool:
    """Check whether any resolved version of ``package`` lists ``dependency``.

    Lock dependency entries may carry a version suffix (``sha2 0.10.9``), so
    the match is on the name boundary rather than a raw prefix.
    """
    return any(
        dep == dependency or dep.startswith(dependency + " ")
        for entry in index.get(package, {}).values()
        for dep in entry.get("dependencies", [])
    )


def runtime_root_boundaries(package: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return ``(forbidden_exact, forbidden_prefix)`` for a runtime root.

    Read from ``config/architecture-boundaries.toml`` rather than restated as
    literals here: a hand-copied forbidden list is exactly how a guard drifts
    away from the boundary it claims to enforce. A missing entry, or one with
    no forbidden values at all, is a failure -- an empty boundary would make
    every check below vacuous.
    """
    config = load_toml(BOUNDARY_CONFIG)
    for entry in config.get("runtime_root", []):
        if entry.get("package") == package:
            exact = tuple(entry.get("forbidden_exact", ()))
            prefix = tuple(entry.get("forbidden_prefix", ()))
            if not exact and not prefix:
                raise AssertionError(
                    f"974: runtime root {package!r} declares no forbidden values, so "
                    "the boundary check would pass for any dependency at all",
                )
            return exact, prefix
    raise AssertionError(
        f"974: config/architecture-boundaries.toml has no runtime_root entry for "
        f"{package!r}; the boundary this case enforces is undefined",
    )


def boundary_violations(
    dependencies: object,
    exact: tuple[str, ...],
    prefix: tuple[str, ...],
) -> list[str]:
    """Return the declared dependencies a runtime-root boundary forbids."""
    if not isinstance(dependencies, dict):
        return []
    return sorted(
        name
        for name in dependencies
        if name in exact or any(name.startswith(item) for item in prefix)
    )


def has_cycle(graph: dict[str, set[str]]) -> bool:
    """Detect any dependency cycle in ``graph`` (node -> direct deps)."""
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> bool:
        if node in visited:
            return False
        if node in visiting:
            return True
        visiting.add(node)
        for dep in graph.get(node, set()):
            if visit(dep):
                return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(visit(node) for node in graph)


def cargo_failure_detail(proc: subprocess.CompletedProcess) -> str:
    """Summarise a failed cargo run: the failing packages and the stderr tail."""
    stderr = proc.stderr or ""
    packages = sorted(set(re.findall(r"could not compile `([^`]+)`", stderr)))
    errors = re.findall(r"^error(?:\[[^\]]+\])?: (.+)$", stderr, re.MULTILINE)
    tail = "\n".join(stderr.strip().splitlines()[-25:])
    parts: list[str] = []
    if packages:
        parts.append("failing package(s): " + ", ".join(packages))
    if errors:
        parts.append("reported error(s): " + " | ".join(errors[:5]))
    parts.append(f"exit status: {proc.returncode}")
    parts.append("stderr tail:\n" + tail)
    return "\n".join(parts)


def implementation_claims_found(text: str) -> list[str]:
    """Return the forbidden implementation-claim phrases present in ``text``."""
    lowered = text.lower()
    return [claim for claim in FORBIDDEN_IMPLEMENTATION_CLAIMS if claim in lowered]


class BackupDependencyLinkTests(unittest.TestCase):
    """Readiness tests for the backup dependency-link work unit (#974)."""

    fixtures_available: bool = False

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        # The frozen bundle IS the dependency evidence for this gate. Its
        # absence must fail the whole class rather than be recorded and
        # ignored: every case below is a claim about a frozen denominator, and
        # a claim with no evidence behind it is a false readiness report. The
        # flag stays a real, asserted invariant that each evidence case reads
        # before it compares fixture content, so it can never become a
        # write-only field again.
        missing = [
            name for name in FROZEN_FIXTURES if not (FIXTURE_DIR / name).is_file()
        ]
        if missing:
            raise AssertionError(
                "frozen dependency evidence is missing: "
                f"{sorted(missing)} under {FIXTURE_DIR.name}/; "
                "stale or absent evidence blocks dispatch",
            )
        cls.fixtures_available = True

    # WORK_UNIT_CASE: 974/1
    def test_01_denominator(self) -> None:
        """Denominator declares exactly cases 1..14 against the base commit."""
        module_doc = read_text(Path(__file__).resolve())
        self.assertIn("14 cases", module_doc)
        self.assertIn(BASE_COMMIT, module_doc)
        _raw, fixture = require_fixture_json(1, "denominator.json")
        self.assertTrue(self.fixtures_available)
        # The committed fixture is validated by the real schema validator.
        # Validating a value this module builds for itself would only prove
        # the builder agrees with the validator.
        self.assertEqual(validate_denominator(fixture), [])
        assert isinstance(fixture, dict)
        require_base_ancestor(1)

        # Scope completeness against an independent expected set.
        self.assertEqual(
            sorted(str(m) for m in fixture["affected_manifests"]),
            sorted(EXPECTED_AFFECTED_MANIFESTS),
            "the frozen affected-manifest denominator must equal this work "
            "unit's granted mutable scope, exactly",
        )
        frozen_edges = [
            (str(edge["manifest"]), str(edge["dependency"]))
            for edge in fixture["dependency_edges"]
        ]
        self.assertEqual(
            sorted(frozen_edges),
            sorted(EXPECTED_FROZEN_EDGES),
            "the frozen dependency denominator must equal the admitted edge set, "
            "exactly",
        )
        self.assertEqual(
            sorted(
                (str(e["manifest"]), str(e["dependency"]))
                for e in fixture["unchanged_since_base"]
            ),
            sorted(EXPECTED_FROZEN_EDGES),
            "every admitted edge must be recorded as verified against the base",
        )
        for edge in fixture["dependency_edges"]:
            self.assertIn(
                str(edge["manifest"]),
                {str(m) for m in fixture["affected_manifests"]},
                f"edge {edge['manifest']} lies outside the frozen denominator",
            )
        # Every affected manifest must carry a measured identity. Without this,
        # adding a path to `affected_manifests` would opt it straight out of the
        # base/current digest comparison below while still satisfying the
        # scope check -- the same hole this case exists to close.
        self.assertEqual(
            unidentified_manifests(
                fixture["affected_manifests"], fixture["manifest_identities"],
            ),
            [],
            "an affected manifest carries no measured base/current identity",
        )

        # The manifests exist and the recorded identity is the real one.
        for entry in fixture["manifest_identities"]:
            relative = str(entry["manifest"])
            path = REPO_ROOT / relative
            self.assertTrue(path.is_file(), f"affected manifest {relative} is absent")
            base_digest = sha256_hex(git_blob(relative))
            current_digest = sha256_hex(path.read_bytes())
            self.assertEqual(
                entry["base_blob_sha256"], base_digest,
                f"recorded base digest for {relative} is wrong",
            )
            self.assertEqual(
                entry["current_blob_sha256"], current_digest,
                f"recorded working-tree digest for {relative} is stale",
            )
            self.assertEqual(
                entry["byte_identical_since_base"], base_digest == current_digest,
                f"byte_identical_since_base for {relative} does not match the "
                "measured base-to-current state",
            )

        # Each recorded declaration is byte-identical at the base blob and in
        # the working tree, at the recorded line. This is what proves the
        # prepared edges were verified no-ops instead of assuming it.
        for edge in fixture["dependency_edges"]:
            relative, declaration = str(edge["manifest"]), str(edge["declaration"])
            current = read_text(REPO_ROOT / relative)
            base = base_text(relative)
            self.assertEqual(
                current.splitlines()[int(edge["line"]) - 1].strip(), declaration,
                f"{relative} line {edge['line']} no longer holds {declaration!r}",
            )
            for label, text in (("working tree", current), ("base", base)):
                self.assertEqual(
                    text.count(declaration), 1,
                    f"{relative} {label} does not hold {declaration!r} exactly once",
                )
            self.assertIn(
                str(edge["dependency"]),
                base_manifest_dependencies(relative),
                f"{relative} does not declare {edge['dependency']} at the base",
            )

        # The digest is recomputed over the same bytes, not pattern-matched.
        self.assertEqual(
            str(fixture["denominator_digest"]), denominator_digest(fixture),
        )

        # Negatives: the same validator must reject a short case list, a wrong
        # base, an edited member with a stale digest, and a dropped member.
        tampered = copy.deepcopy(fixture)
        tampered["cases"] = list(range(1, 14))
        self.assertTrue(validate_denominator(tampered), "13-case denominator accepted")
        tampered_base = copy.deepcopy(fixture)
        tampered_base["base"] = "0" * 40
        self.assertTrue(
            validate_denominator(tampered_base), "wrong-base denominator accepted",
        )
        tampered_digest = copy.deepcopy(fixture)
        tampered_digest["dependency_edges"] = tampered_digest["dependency_edges"][:5]
        self.assertTrue(
            validate_denominator(tampered_digest),
            "denominator with a dropped edge and a stale digest accepted",
        )
        tampered_shape = copy.deepcopy(fixture)
        del tampered_shape["unchanged_since_base"]
        self.assertTrue(
            validate_denominator(tampered_shape), "denominator missing a member accepted",
        )
        # Negative: dropping one identity entry must be reported by the same
        # predicate the identity-completeness verdict above uses.
        dropped = str(fixture["affected_manifests"][0])
        self.assertEqual(
            unidentified_manifests(
                fixture["affected_manifests"],
                [
                    entry for entry in fixture["manifest_identities"]
                    if str(entry["manifest"]) != dropped
                ],
            ),
            [dropped],
            "an affected manifest with no measured identity is not reported",
        )

    # WORK_UNIT_CASE: 974/2
    def test_02_edge_symbols(self) -> None:
        """Declared dependency edges exist in manifests and Rust sources."""
        kernel_deps = manifest_dependencies(KERNEL_MANIFEST)
        self.assertIn("eliot-backup", kernel_deps)
        kernel_text = read_text(KERNEL_BACKUP_RS) + read_text(KERNEL_PORTS_RS)
        self.assertTrue(uses_crate(kernel_text, "eliot_backup"))
        self.assertIn("BackupBlob", kernel_text)
        backup_deps = manifest_dependencies(BACKUP_MANIFEST)
        self.assertIn("eliot-blob-api", backup_deps)
        self.assertIn("eliot-store-api", backup_deps)
        backup_text = read_text(BACKUP_LIB_RS)
        self.assertTrue(uses_crate(backup_text, "eliot_blob_api"))
        self.assertIn("BackupBlob", backup_text)
        self.assertIn("BackupBundle", backup_text)
        self.assertIn("RestoreJournalAdmission", backup_text)
        endpoint_deps = manifest_dependencies(ENDPOINT_MANIFEST)
        self.assertIn("eliot-host-service", endpoint_deps)
        self.assertIn("eliot-ipc", endpoint_deps)
        endpoint_text = read_text(ENDPOINT_LIB_RS)
        self.assertTrue(uses_crate(endpoint_text, "eliot_host_service"))
        self.assertTrue(uses_crate(endpoint_text, "eliot_ipc"))
        host_deps = manifest_dependencies(HOST_SERVICE_MANIFEST)
        self.assertIn("eliot-protocol", host_deps)
        self.assertTrue(
            uses_crate(read_text(HOST_RUNTIME_CONTROL_RS), "eliot_protocol"),
        )
        # Negative: kernel must not claim a direct blob-api edge.
        self.assertNotIn("eliot-blob-api", kernel_deps)
        self.assertNotIn("eliot_blob_api", read_text(KERNEL_BACKUP_RS))

        _raw, fixture = require_fixture_json(2, "edge-symbols.json")
        self.assertTrue(self.fixtures_available)
        self.assertEqual(validate_edge_symbols(2, fixture), [])
        assert isinstance(fixture, dict)
        require_base_ancestor(2)
        # Completeness against the module's independent expected set.
        self.assertEqual(
            sorted(
                (str(e["package"]), str(e["dependency"])) for e in fixture["edges"]
            ),
            sorted(EXPECTED_FROZEN_LOCK_EDGES),
            "the frozen symbol bundle must justify exactly the admitted edge set",
        )
        # Resolved against the live tree rather than matched as raw text: a
        # substring check stays green for a bundle that names no edge at all.
        for edge in fixture["edges"]:
            with self.subTest(
                package=edge["package"], dependency=edge["dependency"],
            ):
                symbol_file = REPO_ROOT / str(edge["symbol_file"])
                consumer_file = REPO_ROOT / str(edge["consumer_file"])
                for path in (symbol_file, consumer_file):
                    self.assertTrue(
                        path.is_file(),
                        f"frozen edge names source {path.name}, which is absent; "
                        "stale dependency evidence blocks dispatch",
                    )
                owner_text = read_text(symbol_file)
                self.assertTrue(
                    declares_public_symbol(owner_text, str(edge["imported_public_symbol"])),
                    f"{edge['symbol_file']} no longer declares "
                    f"{edge['symbol_declaration']!r}; stale dependency evidence "
                    "blocks dispatch",
                )
                self.assertIn(
                    str(edge["symbol_declaration"]), owner_text,
                    "the recorded declaration text is not the one in the owner file",
                )
                consumer_text = read_text(consumer_file)
                crate = str(edge["dependency"]).replace("-", "_")
                self.assertTrue(
                    uses_crate(consumer_text, crate),
                    f"{edge['consumer_file']} no longer imports {crate}",
                )
                self.assertTrue(
                    references_symbol(consumer_text, str(edge["imported_public_symbol"])),
                    f"{edge['consumer_file']} no longer references "
                    f"{edge['imported_public_symbol']}",
                )
        # Negative: a bundle whose justification is not a real declaration is
        # rejected by the same predicate the positive path just used.
        self.assertFalse(
            declares_public_symbol(read_text(BACKUP_LIB_RS), "NotAnAdmittedSymbol"),
        )
        self.assertFalse(
            declares_public_symbol(read_text(BACKUP_LIB_RS), "BackupBundleReceipt"),
        )

    # WORK_UNIT_CASE: 974/3
    def test_03_noop(self) -> None:
        """Kernel backup edge is a preserved path+version no-op edge."""
        kernel_deps = manifest_dependencies(KERNEL_MANIFEST)
        edge = kernel_deps["eliot-backup"]
        self.assertIsInstance(edge, dict)
        self.assertEqual(edge.get("path"), "../../crates/storage/eliot-backup")
        self.assertEqual(edge.get("version"), "0.1.0")
        self.assertNotIn("workspace", edge, "path edge must not become a workspace alias")
        tampered = {"workspace": True}
        self.assertNotIn("path", tampered, "workspace-only edge hides the path pin")
        self.assertNotEqual(tampered, edge)
        declaration = 'eliot-backup = { path = "../../crates/storage/eliot-backup", '\
                     'version = "0.1.0" }'
        for label, text in (
            ("working tree", read_text(KERNEL_MANIFEST)),
            ("base", base_text(KERNEL_MANIFEST.relative_to(REPO_ROOT).as_posix())),
        ):
            self.assertIn(declaration, text)
            self.assertEqual(text.count(declaration), 1)
        self.assertEqual(
            base_manifest_dependencies("bins/eliot-kernel/Cargo.toml")["eliot-backup"],
            edge,
            "the kernel backup edge is not identical at the base, so it is a "
            "rewrite rather than a verified no-op",
        )

    # WORK_UNIT_CASE: 974/4
    def test_04_admitted(self) -> None:
        """Every admitted edge is justified by a real ``use`` in sources."""
        admitted = [
            (KERNEL_MANIFEST, "eliot-backup", [KERNEL_BACKUP_RS, KERNEL_PORTS_RS]),
            (BACKUP_MANIFEST, "eliot-blob-api", [BACKUP_LIB_RS]),
            (BACKUP_MANIFEST, "eliot-store-api", [BACKUP_LIB_RS]),
            (ENDPOINT_MANIFEST, "eliot-host-service", [ENDPOINT_LIB_RS]),
            (ENDPOINT_MANIFEST, "eliot-ipc", [ENDPOINT_LIB_RS]),
            (HOST_SERVICE_MANIFEST, "eliot-protocol", [HOST_RUNTIME_CONTROL_RS]),
        ]
        for manifest_path, dep, sources in admitted:
            with self.subTest(manifest=manifest_path.name, dep=dep):
                self.assertIn(dep, manifest_dependencies(manifest_path))
                combined = "".join(read_text(src) for src in sources)
                crate = dep.replace("-", "_")
                self.assertTrue(
                    uses_crate(combined, crate),
                    f"{dep} has no `use` justification in {[s.name for s in sources]}",
                )

        # The watchdog binary is not a backup consumer, so it must hold no
        # backup orchestration or provider edge. The remaining negatives come
        # from the boundary configuration itself rather than from a list
        # restated here, because a hand-copied forbidden set is how a guard
        # stops matching the boundary it claims to enforce.
        exact, prefix = runtime_root_boundaries(WATCHDOG_RUNTIME_ROOT)
        watchdog_deps = manifest_dependencies(WATCHDOG_MANIFEST)
        self.assertEqual(
            boundary_violations(watchdog_deps, exact, prefix), [],
            f"{WATCHDOG_RUNTIME_ROOT} declares a dependency its own runtime-root "
            "boundary forbids",
        )
        for forbidden in BACKUP_ORCHESTRATION_EDGES:
            self.assertNotIn(
                forbidden, watchdog_deps,
                f"the watchdog binary must not claim a {forbidden} edge",
            )
        # Both contract edges the watchdog genuinely owns are asserted
        # positively: a bare workspace alias rejects a path pin, a version pin,
        # a provider source and a features edit, and the source scan proves
        # the declaration is actually consumed. That is strictly stronger
        # than an absence check, which a stale negative also satisfies.
        for contract_edge in ("eliot-protocol", "eliot-ipc"):
            with self.subTest(contract_edge=contract_edge):
                self.assertEqual(
                    watchdog_deps.get(contract_edge), {"workspace": True},
                    f"the watchdog {contract_edge} edge must remain an unmodified "
                    "workspace alias",
                )
        # The symbol scan must be recursive. A non-recursive glob sees only the
        # direct children of `src/` and would pass vacuously while a nested
        # module used one of the forbidden crates.
        watchdog_sources = sorted(WATCHDOG_SRC_DIR.rglob("*.rs"))
        self.assertTrue(watchdog_sources, "watchdog has no Rust sources to inspect")
        watchdog_text = "".join(read_text(src) for src in watchdog_sources)
        self.assertTrue(watchdog_text, "watchdog source scan produced no text")
        for contract_crate in ("eliot_ipc", "eliot_protocol"):
            self.assertIn(
                contract_crate, watchdog_text,
                f"the recursive watchdog scan found no {contract_crate} use, so the "
                "positive edge assertion has no consumer behind it",
            )
            self.assertTrue(
                uses_crate(watchdog_text, contract_crate),
                f"the watchdog declares {contract_crate.replace('_', '-')} but no "
                "recursive source file imports it",
            )
        for symbol in ("eliot_backup", "eliot_blob"):
            self.assertNotIn(
                symbol, watchdog_text,
                f"a recursive watchdog source file references {symbol}; the "
                "watchdog is not a backup consumer",
            )
        # Negative: the boundary predicate really rejects a forbidden exact
        # name and a forbidden prefix, and accepts a contract edge. Without
        # this, an empty or mis-parsed boundary would satisfy the loop above.
        probe = {**watchdog_deps, exact[0]: {"workspace": True}}
        self.assertEqual(boundary_violations(probe, exact, prefix), [exact[0]])
        prefix_probe = {prefix[0] + "anything": {"workspace": True}}
        self.assertEqual(
            boundary_violations(prefix_probe, exact, prefix), [prefix[0] + "anything"],
        )
        self.assertEqual(
            boundary_violations({"eliot-ipc": {"workspace": True}}, exact, prefix), [],
        )
        # Negative: the same manifest-edge check the loop above performs must
        # fire on a watchdog manifest that carries a backup edge.
        tampered = dict(watchdog_deps)
        tampered[BACKUP_ORCHESTRATION_EDGES[0]] = {"workspace": True}
        caught = [
            forbidden for forbidden in BACKUP_ORCHESTRATION_EDGES
            if forbidden in tampered
        ]
        self.assertEqual(
            caught, [BACKUP_ORCHESTRATION_EDGES[0]],
            "adding a backup edge to the watchdog manifest is not detected",
        )

    # WORK_UNIT_CASE: 974/5
    def test_05_no_provider(self) -> None:
        """Kernel takes no direct blob/provider edge; backup takes no provider."""
        kernel_text = read_text(KERNEL_MANIFEST)
        self.assertNotIn("eliot-blob-api", kernel_text)
        self.assertNotIn("eliot-blob ", kernel_text)
        self.assertNotIn("eliot-blob =", kernel_text)
        kernel_src = "".join(
            # Recursive for the same reason the watchdog scan is: a
            # non-recursive glob reads only the direct children of `src/` and
            # would pass vacuously while a nested module used the crate.
            read_text(src) for src in sorted(KERNEL_SRC_DIR.rglob("*.rs"))
        )
        self.assertTrue(kernel_src, "kernel source scan produced no text")
        self.assertNotIn("eliot_blob_api", kernel_src)
        backup_deps = manifest_dependencies(BACKUP_MANIFEST)
        self.assertNotIn("eliot-blob", backup_deps)
        self.assertFalse(
            any("surreal" in key for key in backup_deps),
            "backup must not depend on a Surreal provider crate",
        )
        self.assertFalse(
            any("redb" in key for key in backup_deps),
            "backup must not depend on a redb provider crate",
        )
        # Negative: re-adding a provider key would violate this case.
        tampered = dict(backup_deps)
        tampered["eliot-blob"] = {"workspace": True}
        self.assertIn("eliot-blob", tampered)

    # WORK_UNIT_CASE: 974/6
    def test_06_no_cycles(self) -> None:
        """No dependency cycle passes through eliot-backup."""
        manifests = [
            KERNEL_MANIFEST,
            WATCHDOG_MANIFEST,
            ENDPOINT_MANIFEST,
            HOST_SERVICE_MANIFEST,
            BACKUP_MANIFEST,
        ]
        graph: dict[str, set[str]] = {}
        for manifest_path in manifests:
            name = load_toml(manifest_path)["package"]["name"]
            graph[name] = set(manifest_dependencies(manifest_path))
        self.assertIn("eliot-backup", graph["eliot-kernel"])
        self.assertFalse(has_cycle(graph), f"cycle in {graph}")
        self.assertNotIn("eliot-kernel", graph["eliot-backup"])
        self.assertNotIn("eliot-watchdog", graph["eliot-backup"])
        # Negative: the detector rejects a fabricated back-edge cycle.
        cyclic = {"eliot-backup": {"eliot-kernel"}, "eliot-kernel": {"eliot-backup"}}
        self.assertTrue(has_cycle(cyclic), "cycle detector missed a back edge")
        acyclic = {"eliot-backup": {"eliot-blob-api"}, "eliot-kernel": {"eliot-backup"}}
        self.assertFalse(has_cycle(acyclic))

    # WORK_UNIT_CASE: 974/7
    def test_07_versions(self) -> None:
        """Pinned versions match the workspace and member manifests."""
        root = load_toml(ROOT_MANIFEST)
        workspace_version = root["workspace"]["package"]["version"]
        self.assertEqual(workspace_version, "0.1.0")
        kernel_edge = manifest_dependencies(KERNEL_MANIFEST)["eliot-backup"]
        assert isinstance(kernel_edge, dict)
        self.assertEqual(kernel_edge["version"], workspace_version)
        backup_package = load_toml(BACKUP_MANIFEST)["package"]
        self.assertTrue(backup_package["version"].get("workspace", False))
        workspace_deps = root["workspace"]["dependencies"]
        for alias in ("eliot-blob-api", "eliot-blob", "eliot-protocol", "eliot-ipc"):
            with self.subTest(alias=alias):
                entry = workspace_deps[alias]
                self.assertIsInstance(entry, dict)
                self.assertEqual(entry["version"], workspace_version)
                self.assertIn("path", entry)
        self.assertNotIn("eliot-backup", workspace_deps)
        # The frozen aliases must be identical at the base, so "preserved"
        # is a comparison and not an assumption.
        base_workspace = load_toml_bytes(git_blob("Cargo.toml"))["workspace"]
        for alias in ("eliot-blob-api", "eliot-blob", "eliot-protocol", "eliot-ipc",
                      "eliot-store-api", "eliot-host-service"):
            with self.subTest(alias=alias):
                self.assertEqual(
                    base_workspace["dependencies"].get(alias),
                    workspace_deps.get(alias),
                    f"the {alias} workspace alias changed since the frozen base",
                )
        self.assertEqual(base_workspace["package"]["version"], workspace_version)
        # Negative: a bumped pin no longer matches the workspace version.
        self.assertNotEqual("0.2.0", workspace_version)

    # WORK_UNIT_CASE: 974/8
    def test_08_no_members(self) -> None:
        """The workspace facts this work unit freezes are unchanged base..current.

        The claim is per fact, never per table. The root manifest is shared with
        other admitted issues, so a whole-table equality would be false: root
        ``Cargo.toml`` gained six workspace aliases and two members and lost
        one member between BASE_COMMIT and the working tree. What this case
        freezes is the storage member set, the five workspace aliases the ten
        admitted edges consume, and the ``default-members``, ``exclude`` and
        ``resolver`` keys -- each compared at the base and in the working tree.
        """
        require_base_ancestor(8)
        root = load_toml(ROOT_MANIFEST)
        workspace = root["workspace"]
        base_workspace = load_toml_bytes(git_blob("Cargo.toml"))["workspace"]
        members = workspace["members"]
        base_members = base_workspace["members"]
        for required in (
            "crates/storage/eliot-backup",
            "crates/storage/eliot-blob-api",
            "crates/storage/eliot-blob",
        ):
            self.assertIn(required, members)
            self.assertIn(required, base_members)
        default_members = workspace.get("default-members", [])
        self.assertEqual(
            sorted(default_members),
            sorted(
                [
                    "bins/eliot",
                    "bins/eliot-host",
                    "bins/eliot-kernel",
                    "bins/eliot-store-surreal",
                    "bins/eliot-watchdog",
                    "bins/eliotd",
                ],
            ),
        )
        self.assertNotIn("crates/storage/eliot-backup", default_members)
        # The storage members this work unit depends on must be exactly the
        # set the base already carried: a new one would be a members change,
        # which the frozen lock delta declares out of bounds.
        storage = {m for m in members if m.startswith("crates/storage/")}
        base_storage = {m for m in base_members if m.startswith("crates/storage/")}
        self.assertEqual(
            storage,
            {
                "crates/storage/eliot-store-api",
                "crates/storage/eliot-store-memory",
                "crates/storage/eliot-store-surreal-adapter",
                "crates/storage/eliot-blob-api",
                "crates/storage/eliot-blob",
                "crates/storage/eliot-backup",
                "crates/storage/eliot-ecxf",
            },
        )
        self.assertEqual(
            storage, base_storage,
            "the storage workspace members changed since the frozen base",
        )
        self.assertEqual(
            {m for m in storage if m not in base_storage}, set(),
            "this work unit must not add a storage workspace member",
        )
        self.assertEqual(
            {m for m in base_storage if m not in storage}, set(),
            "this work unit must not drop a storage workspace member",
        )
        # These three keys carry no per-edge claim, so each is compared across
        # the two ends in full rather than sampled.
        self.assertEqual(
            base_workspace.get("default-members", []), default_members,
            "default-members changed since the frozen base",
        )
        self.assertEqual(
            base_workspace.get("exclude", []), workspace.get("exclude", []),
            "the workspace exclude list changed since the frozen base",
        )
        self.assertEqual(
            base_workspace.get("resolver"), workspace.get("resolver"),
            "the workspace resolver changed since the frozen base",
        )
        # The aliases the admitted edges resolve through, compared by value and
        # not by presence: a bare alias replacing a pinned path+version entry is
        # a rewrite, and a presence check would call it preserved.
        self.assertEqual(
            changed_aliases(
                base_workspace["dependencies"],
                workspace["dependencies"],
                FROZEN_WORKSPACE_ALIASES,
            ),
            [],
            "a workspace alias the admitted edges consume changed since the "
            "frozen base",
        )
        # Negative: the same predicate reports an alias edited at one end, and
        # an alias dropped at one end, so the verdict above is not vacuous.
        for label, tampered_aliases_probe in (
            (
                "edited",
                {**workspace["dependencies"], "eliot-blob-api": {"workspace": True}},
            ),
            ("dropped", {
                alias: value
                for alias, value in workspace["dependencies"].items()
                if alias != "eliot-store-api"
            }),
        ):
            with self.subTest(tamper=label):
                self.assertEqual(
                    changed_aliases(
                        base_workspace["dependencies"],
                        tampered_aliases_probe,
                        FROZEN_WORKSPACE_ALIASES,
                    ),
                    ["eliot-blob-api"] if label == "edited" else ["eliot-store-api"],
                    f"a {label} frozen workspace alias is not reported",
                )
        # Negative: dropping the backup member breaks admission.
        tampered = [m for m in members if m != "crates/storage/eliot-backup"]
        self.assertNotIn("crates/storage/eliot-backup", tampered)

    # WORK_UNIT_CASE: 974/9
    def test_09_lock_delta(self) -> None:
        """Cargo.lock binds the admitted edges and only those edges."""
        packages = lock_packages()
        backup = packages["eliot-backup"]
        self.assertEqual(backup["version"], "0.1.0")
        self.assertIn("eliot-blob-api", backup["dependencies"])
        self.assertIn("eliot-store-api", backup["dependencies"])
        kernel = packages["eliot-kernel"]
        self.assertIn("eliot-backup", kernel["dependencies"])
        self.assertNotIn("eliot-blob-api", kernel["dependencies"])
        self.assertNotIn("eliot-blob", kernel["dependencies"])
        # Negative: a lock entry without the backup edge fails the delta.
        tampered = dict(kernel)
        tampered["dependencies"] = [
            d for d in kernel["dependencies"] if d != "eliot-backup"
        ]
        self.assertNotIn("eliot-backup", tampered["dependencies"])

        _raw, fixture = require_fixture_json(9, "lock-delta.json")
        self.assertTrue(self.fixtures_available)
        self.assertEqual(validate_lock_delta(9, fixture), [])
        assert isinstance(fixture, dict)
        self.assertEqual(
            sorted(str(k) for k in fixture["forbidden"]),
            sorted(FORBIDDEN_LOCK_CHANGE_KINDS),
            "the frozen delta must declare exactly the understood out-of-bounds "
            "change kinds, so a new kind cannot be introduced unchecked",
        )
        self.assertEqual(
            sorted(
                (str(e["package"]), str(e["dependency"]))
                for e in fixture["frozen_lock_edges"]
            ),
            sorted(EXPECTED_FROZEN_LOCK_EDGES),
        )
        self.assertEqual(
            sorted(str(p) for p in fixture["frozen_packages"]),
            sorted(EXPECTED_FROZEN_PACKAGES),
        )
        self.assertEqual(
            sorted(str(p) for p in fixture["kernel_lock_includes"]),
            sorted(EXPECTED_FROZEN_PACKAGES),
        )

        # The real base-to-current lock movement, not the fixture's word for
        # it. Both ends are parsed, keyed on (name, version) because several
        # names in this workspace resolve more than once.
        require_base_ancestor(9)
        base_multi = multi_version_index(load_toml_bytes(git_blob("Cargo.lock")))
        current_multi = multi_version_index(load_toml(ROOT_LOCK))
        base_lock = unambiguous_index(base_multi)
        current_lock = unambiguous_index(current_multi)
        for package, dependency in EXPECTED_FROZEN_LOCK_EDGES:
            with self.subTest(package=package, dependency=dependency):
                self.assertTrue(
                    lock_resolves(base_multi, package, dependency),
                    f"{package} -> {dependency} does not resolve at the frozen "
                    "base, so the edge was not a verified no-op",
                )
                self.assertTrue(
                    lock_resolves(current_multi, package, dependency),
                    f"{package} -> {dependency} does not resolve in the current "
                    "lock",
                )
        # version-upgrade: nothing that existed at the base may move.
        for name in sorted(set(base_multi) & set(current_multi)):
            self.assertEqual(
                sorted(base_multi[name]), sorted(current_multi[name]),
                f"{name} changed version since the frozen base, which is the "
                "upgrade the frozen delta forbids",
            )
        # registry-source / checksum-added: no package may become a fetched
        # registry dependency, which is how a path edge turns into an upgrade.
        for name in sorted(set(base_multi) & set(current_multi)):
            for version in sorted(current_multi[name]):
                was = base_multi[name].get(version, {})
                now = current_multi[name][version]
                self.assertEqual(
                    "source" in now, "source" in was,
                    f"{name} {version} gained or lost a registry source since the "
                    "frozen base",
                )
                self.assertEqual(
                    "checksum" in now, "checksum" in was,
                    f"{name} {version} gained or lost a registry checksum since "
                    "the frozen base",
                )
        for name in EXPECTED_FROZEN_PACKAGES:
            with self.subTest(frozen_package=name):
                for label, index in (("base", base_lock), ("current", current_lock)):
                    self.assertIn(
                        name, index,
                        f"frozen package {name} does not resolve to a single entry "
                        f"at {label}; a name-keyed check would be reading a guess",
                    )
                    entry = index[name]
                    self.assertEqual(entry["version"], "0.1.0")
                    self.assertNotIn("source", entry, f"{name} gained a source at {label}")
                    self.assertNotIn("checksum", entry, f"{name} gained a checksum at {label}")
                self.assertEqual(
                    base_lock[name]["version"], current_lock[name]["version"],
                    f"frozen package {name} changed version between the ends",
                )
        # unrelated-alias / members-change / default-members-change.
        base_workspace = load_toml_bytes(git_blob("Cargo.toml"))["workspace"]
        current_workspace = load_toml(ROOT_MANIFEST)["workspace"]
        for alias in EXPECTED_FROZEN_PACKAGES + ("eliot-protocol", "eliot-ipc",
                                                 "eliot-host-service"):
            with self.subTest(alias=alias):
                self.assertEqual(
                    base_workspace["dependencies"].get(alias),
                    current_workspace["dependencies"].get(alias),
                    f"the {alias} root alias changed since the frozen base",
                )
        for member in ("crates/storage/eliot-backup", "crates/storage/eliot-blob-api",
                       "crates/storage/eliot-blob"):
            self.assertIn(member, base_workspace["members"])
            self.assertIn(member, current_workspace["members"])
        self.assertEqual(
            base_workspace.get("default-members", []),
            current_workspace.get("default-members", []),
        )

    # WORK_UNIT_CASE: 974/10
    def test_10_locked_metadata(self) -> None:
        """Locked metadata is exact: versions pinned, path crates sourceless."""
        packages = lock_packages()
        for name in ("eliot-backup", "eliot-blob-api", "eliot-blob", "eliot-kernel"):
            with self.subTest(package=name):
                entry = packages[name]
                self.assertEqual(entry["version"], "0.1.0")
                self.assertNotIn("source", entry, f"{name} must be a path crate")
                self.assertNotIn("checksum", entry, f"{name} must be a path crate")
        blob_api = packages["eliot-blob-api"]
        self.assertNotIn("eliot-backup", blob_api.get("dependencies", []))
        # Negative: a registry source on a path crate is rejected.
        tampered = dict(packages["eliot-backup"])
        tampered["source"] = "registry+https://github.com/rust-lang/crates.io-index"
        self.assertIn("source", tampered)

    # WORK_UNIT_CASE: 974/11
    def test_11_compile(self) -> None:
        """The unchanged affected packages and the workspace actually compile."""
        self.assertTrue(
            shutil.which("cargo") is not None,
            "cargo is not on PATH, so the compile case cannot be discharged",
        )
        proc = subprocess.run(
            ["cargo", "--version"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT,
        )
        self.assertEqual(proc.returncode, 0, cargo_failure_detail(proc))
        self.assertRegex(proc.stdout.strip(), r"^cargo 1\.\d+")

        # The package names must be the real ones before the checks are worth
        # running: a renamed or invented name would make the command resolve
        # nothing while still exiting zero on a subset of the workspace.
        expected = {
            "eliot-kernel": KERNEL_MANIFEST,
            "eliot-watchdog": WATCHDOG_MANIFEST,
            "eliot-backup": BACKUP_MANIFEST,
            "eliot-host-control-endpoint": ENDPOINT_MANIFEST,
            "eliot-host-service": HOST_SERVICE_MANIFEST,
        }
        for name, manifest_path in expected.items():
            with self.subTest(package=name):
                manifest = load_toml(manifest_path)
                self.assertEqual(manifest["package"]["name"], name)
                self.assertTrue(
                    (manifest_path.parent / "src" / "lib.rs").is_file()
                    or (manifest_path.parent / "src" / "main.rs").is_file(),
                    f"{name} has no Rust source entry point",
                )
        self.assertNotIn("eliot-backup-fake", expected)

        for command in COMPILE_COMMANDS:
            printable = " ".join(command)
            with self.subTest(command=printable):
                try:
                    check = subprocess.run(
                        command,
                        cwd=REPO_ROOT,
                        capture_output=True,
                        text=True,
                        timeout=CARGO_TIMEOUT_SECONDS,
                    )
                except subprocess.TimeoutExpired as expired:
                    partial = expired.stderr or expired.stdout or ""
                    if isinstance(partial, bytes):
                        partial = partial.decode("utf-8", errors="replace")
                    self.fail(
                        f"974/11: `{printable}` did not finish within "
                        f"{CARGO_TIMEOUT_SECONDS}s. A check that never finished is "
                        f"not a passing check; it blocks dispatch. Partial "
                        f"output:\n{partial}",
                    )
                self.assertEqual(
                    check.returncode, 0,
                    f"`{printable}` did not succeed.\n"
                    + cargo_failure_detail(check),
                )
                # Belt and braces on the exit status: a diagnostic line is an
                # error even if some future cargo still exits zero. Only
                # lines that begin a diagnostic are matched, so ordinary
                # build-script chatter cannot make a green build look red.
                diagnostics = [
                    line for line in (check.stderr or "").splitlines()
                    if re.match(r"^error(\[[^\]]+\])?:", line)
                ]
                self.assertEqual(
                    diagnostics, [],
                    f"`{printable}` reported diagnostics:\n"
                    + "\n".join(diagnostics[:20]),
                )

    # WORK_UNIT_CASE: 974/12
    def test_12_single_writer(self) -> None:
        """Single-writer markers intact; no duplicate test scope exists."""
        kernel_text = read_text(KERNEL_MANIFEST)
        # One predicate, used once for the verdict and once for the negative
        # probe below. Asserting a marker is present and then absent in the
        # same text can never both hold, so the verdict is computed once and
        # the probe removes one marker to show the predicate reacts.
        self.assertEqual(
            missing_markers(kernel_text, SINGLE_WRITER_MARKERS), [],
            "the kernel manifest lost a single-writer marker",
        )
        watchdog_text = read_text(WATCHDOG_MANIFEST)
        self.assertEqual(
            missing_markers(watchdog_text, WATCHDOG_OWNERSHIP_MARKERS), [],
            "the watchdog manifest lost an ownership marker",
        )
        self.assertEqual(
            load_toml(WATCHDOG_MANIFEST)["lints"]["rust"]["unsafe_code"], "allow",
        )
        hits = sorted(
            path.name
            for path in TESTS_DIR.glob("test_*.py")
            if SINGLE_WRITER_SCOPE_TOKEN in read_text(path)
        )
        self.assertEqual(hits, ["test_backup_dependency_link.py"])
        # Negative 1: removing the acceptance token from the real kernel text
        # must make the very same predicate report it missing.
        for marker in SINGLE_WRITER_MARKERS:
            with self.subTest(marker=marker):
                tampered = kernel_text.replace(marker, "REMOVED-BY-TAMPER")
                self.assertNotEqual(tampered, kernel_text)
                self.assertIn(marker, missing_markers(tampered, SINGLE_WRITER_MARKERS))
        for marker in WATCHDOG_OWNERSHIP_MARKERS:
            with self.subTest(marker=marker):
                tampered = watchdog_text.replace(marker, "REMOVED-BY-TAMPER")
                self.assertNotEqual(tampered, watchdog_text)
                self.assertIn(marker, missing_markers(tampered, WATCHDOG_OWNERSHIP_MARKERS))
        # Negative 2: a second gate claiming this scope must be reported by the
        # same predicate the verdict above uses, so a duplicate cannot hide
        # behind a scan that only ever sees one file.
        self.assertEqual(
            scope_claimant_names(
                ["test_backup_dependency_link.py", "test_backup_dependency_link_retry.py"],
            ),
            ["test_backup_dependency_link.py", "test_backup_dependency_link_retry.py"],
            "a second gate claiming this scope is not reported",
        )
        self.assertEqual(
            scope_claimant_names(hits), ["test_backup_dependency_link.py"],
        )
        self.assertEqual(scope_claimant_names(["test_unrelated_gate.py"]), [])
        self.assertGreater(len(hits), 0, "the scope scan found no file at all")

    # WORK_UNIT_CASE: 974/13
    def test_13_readiness_only(self) -> None:
        """Readiness file makes no capture/restore/cutover completion claims."""
        own_text = read_text(Path(__file__).resolve())
        self.assertEqual(implementation_claims_found(own_text), [])
        self.assertIn("preparation-only", own_text.lower())
        self.assertIn("not implementation proof", own_text.lower())
        # Negative: the predicate catches a forbidden completion claim.
        tampered = "The produc" + "tion cutover finished ahead of schedule."
        self.assertEqual(
            implementation_claims_found(tampered), ["produc" + "tion cutover"],
        )
        self.assertEqual(implementation_claims_found("plain readiness note"), [])

    # WORK_UNIT_CASE: 974/14
    def test_14_malformed_blocks(self) -> None:
        """Malformed fixture cannot validate; root manifest hash stays stable."""
        before = (ROOT_MANIFEST).read_bytes()
        digest_before = sha256_hex(before)
        self.assertRegex(digest_before, re.compile(r"^[0-9a-f]{64}$"))
        fixture_path = FIXTURE_DIR / "malformed.raw.json"
        self.assertTrue(
            self.fixtures_available,
            "frozen malformed evidence is absent, so the case proves nothing",
        )
        self.assertTrue(
            fixture_path.is_file(),
            f"frozen malformed evidence {fixture_path.name} is missing; "
            "absent evidence blocks dispatch",
        )
        raw = fixture_path.read_text(encoding="utf-8")
        # The frozen malformed evidence is fed to the real validator, not to an
        # identity check on a local variable. Asserting that a failed parse
        # produced `None` proves nothing about the gate; what must be proven is
        # that this text can never be accepted as a denominator, whether it
        # fails to parse or parses into something the validator rejects. The
        # validator returns its error list, so acceptance is the empty list.
        self.assertNotEqual(
            [],
            validate_denominator_text(raw),
            "malformed fixture was accepted as a denominator",
        )
        try:
            parsed: object | None = json.loads(raw)
        except json.JSONDecodeError:
            parsed = None
        if parsed is not None:
            self.assertNotEqual(
                [],
                validate_denominator(parsed),
                "malformed fixture validated as a denominator",
            )
        after = (ROOT_MANIFEST).read_bytes()
        self.assertEqual(sha256_hex(after), digest_before)
        tampered = before + b"\n# tamper\n"
        self.assertNotEqual(sha256_hex(tampered), digest_before)


if __name__ == "__main__":
    unittest.main()
