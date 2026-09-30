#!/usr/bin/env python3
"""Generate a deterministic support-neutral Cargo package reachability inventory.

The inventory is evidence, not authority. It never builds or runs repository
code, mutates Issues, or promotes package presence to implementation/runtime
support. It executes only fixed Git/Cargo/toolchain identity commands and reads
tracked manifests and bounded Rust source below one repository root.

Issue: https://github.com/UnknownAlienHuman/eliot-memory-os/issues/1133

The workspace denominator is reconciled against the root `members`/`exclude` arrays
read from the root manifest and the member manifests on disk, never against this
tool's own package rows, so a package that was never scanned is a fail-closed
`INCOMPLETE_DENOMINATOR` error rather than a row this tool silently omits.

A disposition expiry is compared against the registry's own owner evaluation date
(`revision`), not against the wall clock, so "non-expired" depends on a reviewed
owner record instead of when the tool happened to run.

The same checked-in registry also carries the second, disjoint CrateExtractionDecision
denominator (issue #1721): the I2.23 "Canonical extraction decision" for every package
an admission wave promoted out of the root `exclude` list, with `disposition` drawn from
the six verbs I2.23 closes with. That layer is compared field by field against the crate
each record names - the contour must exist and hold the package, the proof entrypoint
must be a real symbol inside the package, and the record must carry either a real
external consumer reached through a real Cargo edge or an unexpired migration expiry
over a consumer the crate's own manifest declares. Its denominator is read from the
tracked `module.toml` files, so deleting a record cannot shrink it.
"""

from __future__ import annotations

import argparse
import dataclasses
import enum
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import tomllib
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import date
from pathlib import Path
from typing import Any, Final, Protocol

SCHEMA: Final = "eliot.crate-reachability-inventory.v1"
TOOL_VERSION: Final = "0.2.0"
OUTPUT_ROOT: Final = ".eliot"

# Issue #1720 extends the #1133 inventory with a checked CrateExtractionDecision
# classification layer. The dispositions are POLICY, so they are never inferred from
# source statistics; they are read from a declared, versioned, checked-in data file.
DECISION_SCHEMA: Final = "eliot.crate-extraction-decision.v1"
DECISION_DATA_RELPATH: Final = "scripts/testdata/crate-reachability/crate_extraction_decisions.toml"

# Issue #1721 records the second, disjoint CrateExtractionDecision denominator in the
# same canonical registry file: the I2.23 "Canonical extraction decision" for a package
# an admission wave promoted out of the root `exclude` list. I2.23 fixes the record's
# field names and I2.21 fixes the outcome vocabulary, which collapses onto exactly six
# `disposition` values. The denominator is a different one from the `decision` array
# above (an excluded package is not an unreachable workspace member, and four of the
# packages below now have a real binary or service consumer), so the two layers get
# their own arrays in one file rather than two registries beside each other.
ADMISSION_DATA_KEY: Final = "admission_decision"
ADMISSION_SCHEMA: Final = "eliot.crate-extraction-decision.i2.23"
ADMISSION_FIELDS: Final[tuple[str, ...]] = (
    "affected_functional_cells_and_lifecycle_owners",
    "current_source_dependency_and_change_closure",
    "proposed_package_boundary",
    "public_contract_and_independent_test_entrypoint",
    "first_real_consumer_or_time_bounded_migration_facade",
    "source_maintenance_owner_and_vendor_type_boundary",
    "dependency_security_license_and_build_isolation",
    "expected_agent_workset_context_and_reverse_fanout_delta",
    "expected_compile_test_integration_and_release_cost_delta",
    "migration_reexport_rollback_removal_and_expiry",
    "counter_risks_merge_or_rejoin_condition",
    "evidence_status_and_review_owner",
)
# The admission waves issue #1721 resolves. A package enters the denominator when its own
# `module.toml` records one of these as the wave that promoted it into membership, so
# the denominator is derived from the tree and a record can never shrink it.
ADMISSION_WAVE_RE: Final = re.compile(r"admitted via (#966|#967|#968)\b")
# I2.3 names `/workspace/core` as the root production workspace carrying the daily
# `default-members`; every contour below is resolved from a real manifest on disk.
ROOT_CONTOUR: Final = "workspace/core"
# Fallback gap owner for the A11 reconciliation map: issue #1720's own Scope and
# owner line names the Workspace topology and C4 composition owners.
ISSUE_1720_OWNER: Final = "Workspace topology and C4 composition owners (issue #1720)"
# A `path::symbol` reference, the only proof and consumer form this gate accepts.
SYMBOL_REF_RE: Final = re.compile(
    r"(?P<path>[A-Za-z0-9_][A-Za-z0-9_./-]*\.rs)::(?P<symbol>[A-Za-z_][A-Za-z0-9_]*)"
)


class InventoryError(RuntimeError):
    """Stable fail-closed error carrying a machine-readable reason code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclasses.dataclass(frozen=True)
class Bounds:
    max_manifests: int = 2_000
    max_metadata_graphs: int = 512
    max_command_output_bytes: int = 128 * 1024 * 1024
    command_timeout_seconds: int = 900
    max_source_files: int = 30_000
    max_source_bytes: int = 768 * 1024 * 1024
    max_source_file_bytes: int = 8 * 1024 * 1024
    max_findings: int = 250_000
    max_source_consumers_per_package: int = 2_000


BOUNDS: Final = Bounds()


class ManifestClass(str, enum.Enum):
    WORKSPACE_ROOT = "WORKSPACE_ROOT"
    WORKSPACE_MEMBER = "WORKSPACE_MEMBER"
    LOCAL_NON_MEMBER_DEPENDENCY = "LOCAL_NON_MEMBER_DEPENDENCY"
    EXCLUDED_PACKAGE = "EXCLUDED_PACKAGE"
    STANDALONE_PACKAGE = "STANDALONE_PACKAGE"


class Reachability(str, enum.Enum):
    BINARY_ENTRYPOINT = "BINARY_ENTRYPOINT"
    PRODUCTION_CONSUMER = "PRODUCTION_CONSUMER"
    BUILD_ONLY = "BUILD_ONLY"
    TEST_ONLY = "TEST_ONLY"
    UNRESOLVED_DYNAMIC = "UNRESOLVED_DYNAMIC"
    NO_CONSUMER = "NO_CONSUMER"


class SourceScope(str, enum.Enum):
    PRODUCTION = "PRODUCTION"
    BUILD = "BUILD"
    TEST = "TEST"
    EXAMPLE = "EXAMPLE"
    BENCH = "BENCH"
    UNKNOWN = "UNKNOWN"


class CrateExtractionDecision(str, enum.Enum):
    """The only four admitted dispositions for an unreachable package (#1720)."""

    CONNECT = "Connect"
    CONTRACT_ONLY = "ContractOnly"
    MIGRATION_FACADE = "MigrationFacade"
    OPTIONAL_CONTOUR = "OptionalContour"


class CrateAdmissionDisposition(str, enum.Enum):
    """The I2.23 admission dispositions for a wave-admitted package (#1721).

    I2.21 lists the outcomes of a ``CrateScaleReview`` as keep, split, merge, extract
    contract, move a heavy dependency to an adapter/workspace, create a thin facade,
    mark a migration legacy with an expiry, and run an experiment before changing.
    I2.23 closes its canonical record with exactly these six names.
    """

    KEEP = "keep"
    SPLIT = "split"
    MERGE = "merge"
    EXTRACT_CONTRACT = "extract_contract"
    ISOLATE_DEPENDENCY = "isolate_dependency"
    EXPERIMENT = "experiment"


class AdmissionDefect(str, enum.Enum):
    """Reasons a package is not legitimately admitted.

    ``UNCLASSIFIED`` is the issue's "treat any remaining unclassified package as an
    admission defect" rule. The other codes are the machine-checkable ways a
    recorded disposition fails to hold against the computed graph.
    """

    UNCLASSIFIED = "UNCLASSIFIED"
    FACADE_OWNER_MISSING = "FACADE_OWNER_MISSING"
    FACADE_EXPIRY_MISSING = "FACADE_EXPIRY_MISSING"
    FACADE_EXPIRED = "FACADE_EXPIRED"
    FACADE_REMOVAL_CONDITION_MISSING = "FACADE_REMOVAL_CONDITION_MISSING"
    FACADE_SUCCESSOR_MISSING = "FACADE_SUCCESSOR_MISSING"
    DISPOSITION_CONTRADICTS_REACHABILITY = "DISPOSITION_CONTRADICTS_REACHABILITY"
    DECLARED_CONSUMER_ABSENT = "DECLARED_CONSUMER_ABSENT"
    DECLARED_BUNDLE_ABSENT = "DECLARED_BUNDLE_ABSENT"
    DECLARED_CONTOUR_ABSENT = "DECLARED_CONTOUR_ABSENT"
    DECLARED_ENTRYPOINT_ABSENT = "DECLARED_ENTRYPOINT_ABSENT"
    DUPLICATE_DECISION_IDENTITY = "DUPLICATE_DECISION_IDENTITY"
    DECISION_FOR_UNKNOWN_PACKAGE = "DECISION_FOR_UNKNOWN_PACKAGE"
    ADMISSION_RECORD_MISSING = "ADMISSION_RECORD_MISSING"
    ADMISSION_RECORD_FOR_UNKNOWN_PACKAGE = "ADMISSION_RECORD_FOR_UNKNOWN_PACKAGE"
    ADMISSION_CONTOUR_ABSENT = "ADMISSION_CONTOUR_ABSENT"
    ADMISSION_ENTRYPOINT_ABSENT = "ADMISSION_ENTRYPOINT_ABSENT"
    ADMISSION_CONSUMER_ABSENT = "ADMISSION_CONSUMER_ABSENT"
    ADMISSION_MIGRATION_UNBOUNDED = "ADMISSION_MIGRATION_UNBOUNDED"
    ADMISSION_MIGRATION_PREMISE_FALSE = "ADMISSION_MIGRATION_PREMISE_FALSE"
    ADMISSION_FIELD_MISMATCH = "ADMISSION_FIELD_MISMATCH"


class Runner(Protocol):
    def run(self, root: Path, argv: Sequence[str]) -> bytes:
        """Run one internally fixed command and return bounded stdout."""


@dataclasses.dataclass(frozen=True)
class SubprocessRunner:
    bounds: Bounds = BOUNDS

    def run(self, root: Path, argv: Sequence[str]) -> bytes:
        allowed = {
            ("git", "ls-files"),
            ("git", "rev-parse"),
            ("git", "status"),
            ("cargo", "metadata"),
            ("cargo", "-Vv"),
            ("rustc", "-Vv"),
        }
        prefix = tuple(argv[:2])
        if prefix not in allowed:
            raise InventoryError("COMMAND_NOT_ALLOWED", f"command is not fixed/allowed: {argv!r}")
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "USERPROFILE": os.environ.get("USERPROFILE", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "WINDIR": os.environ.get("WINDIR", ""),
            "TEMP": os.environ.get("TEMP", os.environ.get("TMP", "")),
            "TMP": os.environ.get("TMP", os.environ.get("TEMP", "")),
            "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", ""),
            "CARGO_HOME": os.environ.get("CARGO_HOME", ""),
            "CARGO_TERM_COLOR": "never",
            "RUST_BACKTRACE": "0",
        }
        env = {key: value for key, value in env.items() if value}
        try:
            completed = subprocess.run(
                list(argv),
                cwd=root,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.bounds.command_timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise InventoryError("COMMAND_FAILED", f"{argv[0]} could not run: {exc}") from exc
        total = len(completed.stdout) + len(completed.stderr)
        if total > self.bounds.max_command_output_bytes:
            raise InventoryError(
                "COMMAND_OUTPUT_TOO_LARGE",
                f"command output exceeded {self.bounds.max_command_output_bytes} bytes: {argv!r}",
            )
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace")[-4096:]
            raise InventoryError(
                "COMMAND_FAILED",
                f"command exited {completed.returncode}: {argv!r}: {detail}",
            )
        return completed.stdout


@dataclasses.dataclass(frozen=True)
class MetadataGraph:
    graph_id: str
    manifest_path: str
    workspace_root: str
    workspace_members: tuple[str, ...]
    workspace_default_members: tuple[str, ...]
    packages: tuple[Mapping[str, Any], ...]
    resolve: Mapping[str, Any] | None
    # True when resolved under --locked against a pre-existing adjacent lockfile.
    # An unlocked graph resolved against ambient registry cache, which is not a
    # bound evidence input; the flag keeps that resolution mode visible (A10).
    locked: bool


@dataclasses.dataclass(frozen=True)
class SourceFileEvidence:
    package_key: str
    package_name: str
    path: str
    scope: str
    sha256: str
    nonblank_loc: int
    public_items: int
    test_attributes: int
    identifiers: tuple[str, ...]
    # Identifiers including comment/``doc``/string bodies. A token present here but
    # absent from ``identifiers`` is referenced by documentation or a string only and
    # is therefore not a source-level construction of the capability.
    raw_identifiers: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        """Project evidence for the report.

        ``raw_identifiers`` stays internal: it exists only to separate documentation
        references from code constructions and would otherwise dominate the output.
        """
        return {
            "package_key": self.package_key,
            "package_name": self.package_name,
            "path": self.path,
            "scope": self.scope,
            "sha256": self.sha256,
            "nonblank_loc": self.nonblank_loc,
            "public_items": self.public_items,
            "test_attributes": self.test_attributes,
            "identifiers": list(self.identifiers),
        }


TEXT_INDICATORS: Final[tuple[tuple[str, str], ...]] = (
    ("NOT_IMPLEMENTED", "NOT_IMPLEMENTED_MARKER"),
    ("KERNEL_ADMISSION_REQUIRED", "FAIL_CLOSED_ADMISSION_MARKER"),
    ("PLAN_GAP", "PLAN_GAP_MARKER"),
    ("placeholder", "PLACEHOLDER_LANGUAGE"),
    ("skeleton", "SKELETON_LANGUAGE"),
    ("contract-only", "CONTRACT_ONLY_LANGUAGE"),
    ("not yet implemented", "NOT_IMPLEMENTED_LANGUAGE"),
)

CODE_INDICATORS: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    (re.compile(r"\btodo\s*!\s*\("), "TODO_MACRO"),
    (re.compile(r"\bunimplemented\s*!\s*\("), "UNIMPLEMENTED_MACRO"),
    (re.compile(r"\b(?:std\s*::\s*process\s*::\s*)?Command\s*::\s*new\s*\("), "DIRECT_PROCESS_COMMAND"),
    (re.compile(r"\bunsafe\b"), "UNSAFE_CODE"),
    (re.compile(r"#!?\s*\[\s*allow\s*\(\s*dead_code\s*\)\s*\]"), "DEAD_CODE_ALLOW"),
    (re.compile(r"\bserde_json\s*::\s*Value\b"), "GENERIC_JSON_VALUE"),
    (re.compile(r"\boperation\s*:\s*String\b"), "GENERIC_STRING_OPERATION"),
    (re.compile(r"\bprocess\s*::\s*exit\s*\(\s*78\s*\)"), "EXPLICIT_ADMISSION_EXIT"),
)

PUBLIC_ITEM_RE: Final = re.compile(
    r"\bpub(?:\s*\([^)]*\))?\s+(?:async\s+|unsafe\s+|const\s+)*"
    r"(?:struct|enum|trait|fn|type|const|static|mod)\b"
)
TEST_ATTRIBUTE_RE: Final = re.compile(r"#\s*\[\s*(?:tokio\s*::\s*)?test(?:\s*\([^]]*\))?\s*\]")
IDENTIFIER_RE: Final = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
ISO_DATE_RE: Final = re.compile(r"\d{4}-\d{2}-\d{2}")
_CHAR_PATTERN: Final = re.compile(
    r"^(?:b)?'(?:\\x[0-9a-fA-F]{2}|\\u\{[0-9a-fA-F_]{1,6}\}|\\[\\'\"0ntre]|[^\\'\n\r])'"
)
_LIFETIME_PATTERN: Final = re.compile(r"^'[a-zA-Z_][a-zA-Z0-9_]*")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _bounded_text(value: Any, limit: int = 4096) -> str:
    text = str(value).replace("\x00", "\\0")
    return text if len(text) <= limit else text[:limit] + "…"


def _root(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise InventoryError("REPOSITORY_UNAVAILABLE", f"repository root is unavailable: {path}") from exc
    if not (resolved / "Cargo.toml").is_file() or not (resolved / ".git").exists():
        raise InventoryError("NOT_A_REPOSITORY", f"expected Git/Cargo repository root: {resolved}")
    return resolved


def _inside(root: Path, path: Path, *, must_exist: bool = True) -> Path:
    try:
        resolved = path.resolve(strict=must_exist)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise InventoryError("PATH_ESCAPE", f"path is outside repository root: {path}") from exc
    return resolved


def _relative(root: Path, path: Path) -> str:
    return _inside(root, path).relative_to(root).as_posix()


def _safe_output(root: Path, output: Path, overwrite: bool = False) -> Path:
    candidate = output if output.is_absolute() else root / output
    parent = _inside(root, candidate.parent, must_exist=True)
    relative = parent.relative_to(root)
    if not relative.parts or relative.parts[0] != OUTPUT_ROOT:
        raise InventoryError("UNSAFE_OUTPUT", "output must be below the repository .eliot directory")
    if candidate.exists() and not overwrite:
        raise InventoryError("OUTPUT_EXISTS", f"refusing to overwrite existing output: {candidate}")
    return candidate


def _read_bytes(root: Path, path: Path, *, max_bytes: int) -> bytes:
    resolved = _inside(root, path)
    if resolved.is_symlink() or not resolved.is_file():
        raise InventoryError("SOURCE_NOT_REGULAR_FILE", f"expected a regular non-symlink file: {resolved}")
    size = resolved.stat().st_size
    if size > max_bytes:
        raise InventoryError("SOURCE_FILE_TOO_LARGE", f"{_relative(root, resolved)} exceeds {max_bytes} bytes")
    return resolved.read_bytes()


def _json_object(raw: bytes, *, source: str) -> Mapping[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryError("MALFORMED_JSON", f"malformed JSON from {source}") from exc
    if not isinstance(value, dict):
        raise InventoryError("MALFORMED_JSON", f"expected JSON object from {source}")
    return value


@dataclasses.dataclass(frozen=True)
class DecisionRecord:
    """One checked, policy-declared CrateExtractionDecision disposition."""

    package: str
    disposition: CrateExtractionDecision
    rationale: str
    owner: str | None
    expires: str | None
    successor: str | None
    removal_condition: str | None
    declared_consumer: str | None
    declared_bundle: str | None
    declared_contour: str | None
    contour_excluded_from_default_path: bool | None
    proof_entrypoint: str | None
    review_owner: str | None
    source_ref: str

    def to_json(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "disposition": self.disposition.value,
            "rationale": self.rationale,
            "owner": self.owner,
            "expires": self.expires,
            "successor": self.successor,
            "removal_condition": self.removal_condition,
            "declared_consumer": self.declared_consumer,
            "declared_bundle": self.declared_bundle,
            "declared_contour": self.declared_contour,
            "contour_excluded_from_default_path": self.contour_excluded_from_default_path,
            "proof_entrypoint": self.proof_entrypoint,
            "review_owner": self.review_owner,
            "source_ref": self.source_ref,
        }


@dataclasses.dataclass(frozen=True)
class AdmissionDecisionRecord:
    """One I2.23 canonical extraction decision for a wave-admitted package (#1721).

    The field names are I2.23's own. Nothing here is inferred: `check_admission_decisions`
    compares every one of them against the crate the record names.
    """

    package: str
    disposition: CrateAdmissionDisposition
    affected_functional_cells_and_lifecycle_owners: str
    current_source_dependency_and_change_closure: str
    proposed_package_boundary: str
    public_contract_and_independent_test_entrypoint: str
    first_real_consumer_or_time_bounded_migration_facade: str
    source_maintenance_owner_and_vendor_type_boundary: str
    dependency_security_license_and_build_isolation: str
    expected_agent_workset_context_and_reverse_fanout_delta: str
    expected_compile_test_integration_and_release_cost_delta: str
    migration_reexport_rollback_removal_and_expiry: str
    counter_risks_merge_or_rejoin_condition: str
    evidence_status_and_review_owner: str

    def to_json(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "disposition": self.disposition.value,
            **{field: getattr(self, field) for field in ADMISSION_FIELDS},
        }


def _require_str(value: Any, field: str, package: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InventoryError("MALFORMED_DECISION_DATA", f"{package}: field '{field}' must be a non-empty string")
    return value.strip()


def _optional_str(value: Any, field: str, package: str) -> str | None:
    if value is None:
        return None
    return _require_str(value, field, package)


def _require_bool(value: Any, field: str, package: str) -> bool:
    if not isinstance(value, bool):
        raise InventoryError("MALFORMED_DECISION_DATA", f"{package}: field '{field}' must be a boolean")
    return value


def _parse_iso_date(value: str, field: str, package: str) -> date:
    if not ISO_DATE_RE.fullmatch(value):
        raise InventoryError("MALFORMED_DECISION_DATA", f"{package}: field '{field}' must be an ISO-8601 date, got {value!r}")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise InventoryError("MALFORMED_DECISION_DATA", f"{package}: field '{field}' is not a real date: {value!r}") from exc


def revision_date(revision: str) -> date:
    """The owner evaluation date carried by the registry's own ``revision``.

    "Non-expired" is only a claim when the expiry is compared against a date a
    named owner chose. The registry revision is that choice: the owner writes and
    bumps it whenever the dispositions are re-reviewed, its bytes are already bound
    into the aggregate digest, and it is the date the registry's own MEASURED notes
    are written against. A revision that carries no ISO-8601 date fails closed
    instead of degrading to the wall clock, which would make a facade's expiry
    depend on when this tool happened to be run and would make "unexpired"
    unprovable rather than merely unreviewed.
    """
    return _parse_iso_date(revision.split(".", 1)[0].strip(), "revision", DECISION_DATA_RELPATH)


def _decision_document(root: Path) -> tuple[str, dict[str, Any]]:
    """Read and parse the one canonical registry file, once, for both layers."""
    data_path = _inside(root, root / DECISION_DATA_RELPATH)
    raw = _read_bytes(root, data_path, max_bytes=BOUNDS.max_source_file_bytes)
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise InventoryError("MALFORMED_DECISION_DATA", f"{DECISION_DATA_RELPATH} is not valid UTF-8 TOML") from exc
    schema = document.get("schema")
    if schema != DECISION_SCHEMA:
        raise InventoryError(
            "MALFORMED_DECISION_DATA",
            f"{DECISION_DATA_RELPATH}: expected schema {DECISION_SCHEMA!r}, got {schema!r}",
        )
    return _sha256(raw), document


def load_decision_records(document: Mapping[str, Any], decision_sha: str) -> tuple[str, str, tuple[DecisionRecord, ...]]:
    """Read the declared CrateExtractionDecision registry.

    The registry is the explicit record required by #1720. It is never synthesized
    from source statistics: absent records simply stay unclassified and are reported
    as admission defects. Malformed data fails closed.
    """
    revision = _require_str(document.get("revision"), "revision", DECISION_DATA_RELPATH)
    entries = document.get("decision")
    if not isinstance(entries, list):
        raise InventoryError("MALFORMED_DECISION_DATA", f"{DECISION_DATA_RELPATH}: 'decision' must be an array")
    records: list[DecisionRecord] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise InventoryError("MALFORMED_DECISION_DATA", "each 'decision' entry must be a table")
        package = _require_str(entry.get("package"), "package", "<entry>")
        if package in seen:
            raise InventoryError("DUPLICATE_DECISION_IDENTITY", f"{DECISION_DATA_RELPATH}: duplicate decision for {package!r}")
        seen.add(package)
        raw_disposition = _require_str(entry.get("disposition"), "disposition", package)
        try:
            disposition = CrateExtractionDecision(raw_disposition)
        except ValueError as exc:
            allowed = ", ".join(item.value for item in CrateExtractionDecision)
            raise InventoryError(
                "MALFORMED_DECISION_DATA",
                f"{package}: disposition must be one of [{allowed}], got {raw_disposition!r}",
            ) from exc
        owner = _optional_str(entry.get("owner"), "owner", package)
        expires = _optional_str(entry.get("expires"), "expires", package)
        if expires is not None:
            _parse_iso_date(expires, "expires", package)
        records.append(
            DecisionRecord(
                package=package,
                disposition=disposition,
                rationale=_require_str(entry.get("rationale"), "rationale", package),
                owner=owner,
                expires=expires,
                successor=_optional_str(entry.get("successor"), "successor", package),
                removal_condition=_optional_str(entry.get("removal_condition"), "removal_condition", package),
                declared_consumer=_optional_str(entry.get("declared_consumer"), "declared_consumer", package),
                declared_bundle=_optional_str(entry.get("declared_bundle"), "declared_bundle", package),
                declared_contour=_optional_str(entry.get("declared_contour"), "declared_contour", package),
                contour_excluded_from_default_path=(
                    _require_bool(entry["contour_excluded_from_default_path"], "contour_excluded_from_default_path", package)
                    if "contour_excluded_from_default_path" in entry
                    else None
                ),
                proof_entrypoint=_optional_str(entry.get("proof_entrypoint"), "proof_entrypoint", package),
                review_owner=_optional_str(entry.get("review_owner"), "review_owner", package),
                source_ref=_require_str(entry.get("source_ref"), "source_ref", package),
            )
        )
    return decision_sha, revision, tuple(sorted(records, key=lambda item: item.package))


def load_admission_records(document: Mapping[str, Any]) -> tuple[AdmissionDecisionRecord, ...]:
    """Read the I2.23 canonical admission decisions for the wave-admitted packages.

    Every field name below is the one I2.23 fixes, and `disposition` must be one of
    the six verbs it closes with. A missing or misspelled field is malformed data and
    fails closed rather than degrading into an unchecked record.
    """
    entries = document.get(ADMISSION_DATA_KEY, [])
    if not isinstance(entries, list):
        raise InventoryError("MALFORMED_DECISION_DATA", f"{DECISION_DATA_RELPATH}: '{ADMISSION_DATA_KEY}' must be an array")
    records: list[AdmissionDecisionRecord] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise InventoryError("MALFORMED_DECISION_DATA", f"each '{ADMISSION_DATA_KEY}' entry must be a table")
        package = _require_str(entry.get("package"), "package", "<admission entry>")
        if package in seen:
            raise InventoryError(
                "DUPLICATE_DECISION_IDENTITY",
                f"{DECISION_DATA_RELPATH}: duplicate admission decision for {package!r}",
            )
        seen.add(package)
        raw_disposition = _require_str(entry.get("disposition"), "disposition", package)
        try:
            disposition = CrateAdmissionDisposition(raw_disposition)
        except ValueError as exc:
            allowed = ", ".join(item.value for item in CrateAdmissionDisposition)
            raise InventoryError(
                "MALFORMED_DECISION_DATA",
                f"{package}: I2.23 disposition must be one of [{allowed}], got {raw_disposition!r}",
            ) from exc
        undeclared = sorted(set(entry) - {"package", "disposition", *ADMISSION_FIELDS})
        if undeclared:
            raise InventoryError(
                "MALFORMED_DECISION_DATA",
                f"{package}: I2.23 record names fields it does not define: {undeclared}",
            )
        records.append(
            AdmissionDecisionRecord(
                package=package,
                disposition=disposition,
                **{
                    field: _require_str(entry.get(field), field, package)
                    for field in ADMISSION_FIELDS
                },
            )
        )
    return tuple(sorted(records, key=lambda item: item.package))


def _tracked_manifests(root: Path, runner: Runner) -> tuple[str, ...]:
    raw = runner.run(root, ("git", "ls-files", "-z", "--", "Cargo.toml", ":(glob)**/Cargo.toml"))
    paths: list[str] = []
    for item in raw.split(b"\x00"):
        if not item:
            continue
        try:
            relative = item.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InventoryError("INVALID_GIT_PATH", "tracked manifest path is not UTF-8") from exc
        path = _inside(root, root / relative)
        if path.name != "Cargo.toml":
            raise InventoryError("INVALID_MANIFEST_PATH", f"unexpected manifest path: {relative}")
        paths.append(path.relative_to(root).as_posix())
    unique = tuple(sorted(set(paths)))
    if "Cargo.toml" not in unique:
        raise InventoryError("ROOT_MANIFEST_MISSING", "tracked root Cargo.toml is missing")
    if len(unique) > BOUNDS.max_manifests:
        raise InventoryError("MANIFEST_LIMIT", f"manifest denominator exceeds {BOUNDS.max_manifests}")
    return unique


def _remove_created_lockfile(lock_path: Path, *, existed_before: bool) -> None:
    """Delete a Cargo.lock created as a side effect of unlocked metadata.

    `cargo metadata` without `--locked` resolves and writes the adjacent
    lockfile. The inventory is read-only evidence (A12): a lockfile that did
    not exist before the call must not survive it. A pre-existing lockfile,
    symlink, or directory is never touched.
    """
    if existed_before:
        return
    if lock_path.is_symlink() or not lock_path.is_file():
        return
    try:
        lock_path.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise InventoryError(
            "LOCKFILE_CLEANUP_FAILED",
            f"cannot remove cargo-created lockfile: {lock_path}",
        ) from exc


def _metadata(root: Path, runner: Runner, manifest: str | None = None) -> MetadataGraph:
    manifest_dir = (root / manifest).parent if manifest is not None else root
    lock_path = manifest_dir / "Cargo.lock"
    lockfile_exists = lock_path.exists()
    argv: list[str] = ["cargo", "metadata"]
    if lockfile_exists:
        argv.append("--locked")
    argv.extend(("--offline", "--all-features", "--format-version", "1"))
    if manifest is not None:
        argv.extend(("--manifest-path", manifest))
    try:
        raw = runner.run(root, tuple(argv))
    finally:
        _remove_created_lockfile(lock_path, existed_before=lockfile_exists)
    value = _json_object(raw, source="cargo metadata")
    packages = value.get("packages")
    members = value.get("workspace_members")
    defaults = value.get("workspace_default_members", [])
    workspace_root = value.get("workspace_root")
    if not isinstance(packages, list) or not isinstance(members, list) or not isinstance(defaults, list):
        raise InventoryError("MALFORMED_METADATA", "cargo metadata package/member arrays are missing")
    if not isinstance(workspace_root, str):
        raise InventoryError("MALFORMED_METADATA", "cargo metadata workspace_root is missing")
    graph_manifest = manifest or "Cargo.toml"
    return MetadataGraph(
        graph_id=_sha256(_canonical_bytes({"manifest": graph_manifest, "workspace_root": workspace_root})),
        manifest_path=graph_manifest.replace("\\", "/"),
        workspace_root=workspace_root,
        workspace_members=tuple(str(item) for item in members),
        workspace_default_members=tuple(str(item) for item in defaults),
        packages=tuple(item for item in packages if isinstance(item, dict)),
        resolve=value.get("resolve") if isinstance(value.get("resolve"), dict) else None,
        locked=lockfile_exists,
    )


def _load_root_workspace(root: Path) -> tuple[tuple[str, ...], tuple[str, ...]]:
    raw = _read_bytes(root, root / "Cargo.toml", max_bytes=BOUNDS.max_source_file_bytes)
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise InventoryError("MALFORMED_MANIFEST", "root Cargo.toml is malformed") from exc
    workspace = value.get("workspace", {})
    if not isinstance(workspace, dict):
        return (), ()
    members = workspace.get("members", [])
    exclude = workspace.get("exclude", [])
    if not isinstance(members, list) or not isinstance(exclude, list):
        raise InventoryError("MALFORMED_MANIFEST", "workspace members/exclude must be arrays")
    return tuple(str(item) for item in members), tuple(str(item) for item in exclude)


def _member_package_name(root: Path, member: str) -> str:
    """The package name one root ``members`` entry declares, read from its manifest.

    The name is read from the member's own ``Cargo.toml`` on disk, never from the
    metadata graph this tool built. A member that was never scanned therefore cannot
    be satisfied by the scanner's own output, which is the whole point of comparing
    the denominator against the manifest.
    """
    if any(char in member for char in "*?["):
        raise InventoryError(
            "MALFORMED_MANIFEST",
            f"root workspace member is a pattern, not a literal package path: {member!r}",
        )
    manifest = _inside(root, _inside(root, root / member) / "Cargo.toml")
    name = str((_read_toml(root, manifest).get("package") or {}).get("name") or "")
    if not name:
        raise InventoryError(
            "MALFORMED_MANIFEST",
            f"root workspace member declares no package name: {member}",
        )
    return name


def workspace_denominator(
    root: Path,
    member_paths: Sequence[str],
    exclude_patterns: Sequence[str],
    tracked_manifests: Sequence[str],
    packages: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Reconcile the scanned package set against the root manifest's own arrays.

    The expected member set comes from the root ``members`` array and each member's
    own manifest on disk. The observed set comes from the cargo-metadata rows this
    run produced. They are compared against each other, so a member the scan never
    reached, a duplicate entry, a member/exclusion overlap, or an ``exclude`` entry
    that excludes nothing are all discrepancies instead of a clean row.

    Returns a report whose ``complete`` field is the computed comparison result, and
    whose ``discrepancies`` are the exact reasons it is not. A caller that wants an
    empty clean inventory must fail closed on a non-empty ``discrepancies`` list.
    """
    discrepancies: list[str] = []
    for label, entries in (("member", member_paths), ("exclusion", exclude_patterns)):
        duplicates = sorted({item for item in entries if list(entries).count(item) > 1})
        if duplicates:
            discrepancies.append(f"duplicate root workspace {label} entries: {duplicates}")
    overlap = sorted(set(member_paths) & set(exclude_patterns))
    if overlap:
        discrepancies.append(f"root workspace member/exclusion overlap: {overlap}")

    expected_members: dict[str, str] = {}
    for member in member_paths:
        name = _member_package_name(root, member)
        if name in expected_members:
            discrepancies.append(
                f"two root workspace members declare the package {name!r}: "
                f"{expected_members[name]!r} and {member!r}"
            )
        expected_members[name] = member

    # An `exclude` entry that matches no tracked manifest excludes nothing, so the
    # array claims an exclusion the tree does not have.
    unmatched_exclude = [
        pattern
        for pattern in exclude_patterns
        if not any(_matches_pattern(manifest, (pattern,)) for manifest in tracked_manifests)
    ]
    for pattern in sorted(unmatched_exclude):
        discrepancies.append(f"root workspace exclusion matches no tracked manifest: {pattern!r}")

    observed = {
        str(item["name"])
        for item in packages
        if item.get("workspace_member") and item.get("source") is None
    }
    for name in sorted(set(expected_members) - observed):
        discrepancies.append(
            f"root workspace member was never scanned as a package: {name!r} ({expected_members[name]})"
        )
    for name in sorted(observed - set(expected_members)):
        discrepancies.append(f"scanned workspace member is absent from the root members array: {name!r}")

    return {
        "root_workspace_members": len(member_paths),
        "root_workspace_exclusions": len(exclude_patterns),
        "expected_member_packages": len(expected_members),
        "scanned_member_packages": len(observed),
        "expected_member_names_sha256": _sha256(_canonical_bytes(sorted(expected_members))),
        "scanned_member_names_sha256": _sha256(_canonical_bytes(sorted(observed))),
        "unmatched_exclude_patterns": sorted(unmatched_exclude),
        "discrepancies": discrepancies,
        "complete": not discrepancies,
    }


def _matches_pattern(manifest: str, patterns: Sequence[str]) -> bool:
    package_dir = str(Path(manifest).parent).replace("\\", "/")
    for pattern in patterns:
        normalized = pattern.rstrip("/")
        if fnmatch.fnmatchcase(package_dir, normalized) or fnmatch.fnmatchcase(manifest, normalized):
            return True
        if normalized and fnmatch.fnmatchcase(package_dir + "/", normalized.rstrip("/") + "/"):
            return True
    return False


def _manifest_paths_from_graph(root: Path, graph: MetadataGraph) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for package in graph.packages:
        manifest_path = package.get("manifest_path")
        package_id = package.get("id")
        if not isinstance(manifest_path, str) or not isinstance(package_id, str):
            raise InventoryError("MALFORMED_METADATA", "package id/manifest_path is missing")
        path = Path(manifest_path)
        try:
            relative = _inside(root, path).relative_to(root).as_posix()
        except InventoryError:
            continue
        if relative in result:
            raise InventoryError("DUPLICATE_MANIFEST_IDENTITY", f"duplicate package manifest: {relative}")
        result[relative] = package
    return result


def _collect_graphs(root: Path, runner: Runner, manifests: Sequence[str]) -> tuple[MetadataGraph, ...]:
    graphs: list[MetadataGraph] = []
    covered: set[str] = set()
    root_graph = _metadata(root, runner)
    graphs.append(root_graph)
    covered.update(_manifest_paths_from_graph(root, root_graph))
    for manifest in manifests:
        if manifest == "Cargo.toml" or manifest in covered:
            continue
        if len(graphs) >= BOUNDS.max_metadata_graphs:
            raise InventoryError("METADATA_GRAPH_LIMIT", f"metadata graph count exceeds {BOUNDS.max_metadata_graphs}")
        graph = _metadata(root, runner, manifest)
        graph_paths = _manifest_paths_from_graph(root, graph)
        if manifest not in graph_paths:
            raise InventoryError("UNACCOUNTED_MANIFEST", f"metadata graph did not account for {manifest}")
        graphs.append(graph)
        covered.update(graph_paths)
    missing = sorted(set(manifests) - covered - {"Cargo.toml"})
    if missing:
        raise InventoryError("UNACCOUNTED_MANIFEST", f"tracked manifests absent from metadata graphs: {missing[:20]}")
    return tuple(graphs)


def _package_key(graph: MetadataGraph, package_id: str) -> str:
    return f"{graph.graph_id}:{package_id}"


def _dependency_edges(graph: MetadataGraph) -> list[dict[str, Any]]:
    if graph.resolve is None:
        return []
    nodes = graph.resolve.get("nodes")
    if not isinstance(nodes, list):
        raise InventoryError("MALFORMED_METADATA", "resolve.nodes is missing")
    edges: list[dict[str, Any]] = []
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            raise InventoryError("MALFORMED_METADATA", "resolve node id is missing")
        source_id = node["id"]
        deps = node.get("deps", [])
        if not isinstance(deps, list):
            raise InventoryError("MALFORMED_METADATA", "resolve node deps is malformed")
        for dep in deps:
            if not isinstance(dep, dict) or not isinstance(dep.get("pkg"), str):
                raise InventoryError("MALFORMED_METADATA", "resolve dependency package is missing")
            dep_kinds = dep.get("dep_kinds", [])
            if not isinstance(dep_kinds, list) or not dep_kinds:
                dep_kinds = [{"kind": None, "target": None}]
            for dep_kind in dep_kinds:
                if not isinstance(dep_kind, dict):
                    raise InventoryError("MALFORMED_METADATA", "dependency kind is malformed")
                kind = dep_kind.get("kind") or "normal"
                target = dep_kind.get("target")
                edges.append(
                    {
                        "graph_id": graph.graph_id,
                        "from_package": _package_key(graph, source_id),
                        "to_package": _package_key(graph, dep["pkg"]),
                        "dependency_name": _bounded_text(dep.get("name", ""), 256),
                        "kind": str(kind),
                        "target": str(target) if target is not None else None,
                    }
                )
    return sorted(
        edges,
        key=lambda item: (
            item["from_package"],
            item["to_package"],
            item["kind"],
            item["target"] or "",
            item["dependency_name"],
        ),
    )


def _source_scope(manifest_dir: Path, path: Path) -> SourceScope:
    relative = path.relative_to(manifest_dir).as_posix()
    if relative == "build.rs":
        return SourceScope.BUILD
    if relative.startswith("tests/"):
        return SourceScope.TEST
    if relative.startswith("benches/"):
        return SourceScope.BENCH
    if relative.startswith("examples/"):
        return SourceScope.EXAMPLE
    if relative.startswith("src/"):
        return SourceScope.PRODUCTION
    return SourceScope.UNKNOWN


def _mask_rust(text: str) -> str:
    """Replace Rust comments and literal bodies with spaces while preserving lines."""

    chars = list(text)
    length = len(chars)
    index = 0

    def blank(start: int, end: int) -> None:
        for pos in range(start, end):
            if chars[pos] not in "\r\n":
                chars[pos] = " "

    while index < length:
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            if end < 0:
                end = length
            blank(index, end)
            index = end
            continue
        if text.startswith("/*", index):
            depth = 1
            cursor = index + 2
            while cursor < length and depth:
                if text.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif text.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            if depth:
                raise InventoryError("MALFORMED_RUST_SOURCE", "unterminated block comment")
            blank(index, cursor)
            index = cursor
            continue
        raw_match = re.match(r'(?:b|c)?r(#{0,255})"', text[index:])
        if raw_match:
            hashes = raw_match.group(1)
            body_start = index + raw_match.end()
            terminator = '"' + hashes
            end = text.find(terminator, body_start)
            if end < 0:
                raise InventoryError("MALFORMED_RUST_SOURCE", "unterminated raw string")
            end += len(terminator)
            blank(index, end)
            index = end
            continue
        if text.startswith("'", index) or text.startswith("b'", index):
            cm = _CHAR_PATTERN.match(text[index:])
            if cm:
                blank(index, index + cm.end())
                index += cm.end()
                continue
            lm = _LIFETIME_PATTERN.match(text[index:])
            if lm:
                index += lm.end()
                continue
        prefix = 1 if text[index:index + 1] in {"b", "c"} and text[index + 1:index + 2] == '"' else 0
        quote_pos = index + prefix
        if quote_pos < length and text[quote_pos] == '"':
            cursor = quote_pos + 1
            escaped = False
            while cursor < length:
                current = text[cursor]
                cursor += 1
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == '"':
                    break
            else:
                raise InventoryError("MALFORMED_RUST_SOURCE", "unterminated string literal")
            blank(index, cursor)
            index = cursor
            continue
        index += 1
    return "".join(chars)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _line_excerpt(text: str, line: int) -> str:
    lines = text.splitlines()
    if line < 1 or line > len(lines):
        return ""
    return _bounded_text(lines[line - 1].strip(), 320)


def _nearest_instructions(root: Path, manifest_dir: Path) -> str | None:
    current = manifest_dir
    while True:
        candidate = current / "AGENTS.md"
        if candidate.is_file() and not candidate.is_symlink():
            return candidate.relative_to(root).as_posix()
        if current == root:
            return None
        try:
            current = current.parent
            current.relative_to(root)
        except ValueError:
            return None


def _owner_issues(root: Path, manifest_dir: Path) -> tuple[int, ...]:
    instructions = _nearest_instructions(root, manifest_dir)
    if instructions is None:
        return ()
    raw = _read_bytes(root, root / instructions, max_bytes=BOUNDS.max_source_file_bytes)
    text = raw.decode("utf-8", errors="replace")
    return tuple(sorted({int(value) for value in re.findall(r"(?:issues/|#)(\d{1,7})", text)}))


def _scan_sources(
    root: Path,
    package_key: str,
    package_name: str,
    manifest_dir: Path,
) -> tuple[list[SourceFileEvidence], list[dict[str, Any]]]:
    files: list[Path] = []
    for relative in ("src", "tests", "examples", "benches"):
        directory = manifest_dir / relative
        if not directory.exists():
            continue
        for path in directory.rglob("*.rs"):
            resolved = _inside(root, path)
            if resolved.is_symlink() or not resolved.is_file():
                continue
            files.append(resolved)
    build_rs = manifest_dir / "build.rs"
    if build_rs.is_file() and not build_rs.is_symlink():
        files.append(_inside(root, build_rs))
    files = sorted(set(files))
    if len(files) > BOUNDS.max_source_files:
        raise InventoryError("SOURCE_FILE_LIMIT", f"source file count exceeds {BOUNDS.max_source_files}")

    total_bytes = 0
    evidence: list[SourceFileEvidence] = []
    findings: list[dict[str, Any]] = []
    for path in files:
        raw = _read_bytes(root, path, max_bytes=BOUNDS.max_source_file_bytes)
        total_bytes += len(raw)
        if total_bytes > BOUNDS.max_source_bytes:
            raise InventoryError("SOURCE_BYTE_LIMIT", f"source bytes exceed {BOUNDS.max_source_bytes}")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InventoryError("INVALID_RUST_ENCODING", f"Rust source is not UTF-8: {_relative(root, path)}") from exc
        try:
            masked = _mask_rust(text)
        except InventoryError as exc:
            raise InventoryError(exc.code, f"{_relative(root, path)}: {exc.detail}") from exc
        scope = _source_scope(manifest_dir, path)
        identifiers = tuple(sorted(set(IDENTIFIER_RE.findall(masked))))
        evidence.append(
            SourceFileEvidence(
                package_key=package_key,
                package_name=package_name,
                path=_relative(root, path),
                scope=scope.value,
                sha256=_sha256(raw),
                nonblank_loc=sum(1 for line in text.splitlines() if line.strip()),
                public_items=len(PUBLIC_ITEM_RE.findall(masked)),
                test_attributes=len(TEST_ATTRIBUTE_RE.findall(masked)),
                identifiers=identifiers,
                raw_identifiers=tuple(sorted(set(IDENTIFIER_RE.findall(text)))),
            )
        )
        for token, category in TEXT_INDICATORS:
            start = 0
            lowered = text.casefold()
            needle = token.casefold()
            while True:
                index = lowered.find(needle, start)
                if index < 0:
                    break
                line = _line_number(text, index)
                findings.append(
                    {
                        "package_key": package_key,
                        "path": _relative(root, path),
                        "line": line,
                        "scope": scope.value,
                        "category": category,
                        "token": token,
                        "excerpt": _line_excerpt(text, line),
                        "source_sha256": _sha256(raw),
                        "contextual_disposition": "REVIEW_REQUIRED",
                    }
                )
                start = index + len(needle)
        for pattern, category in CODE_INDICATORS:
            for match in pattern.finditer(masked):
                line = _line_number(masked, match.start())
                findings.append(
                    {
                        "package_key": package_key,
                        "path": _relative(root, path),
                        "line": line,
                        "scope": scope.value,
                        "category": category,
                        "token": _bounded_text(match.group(0), 128),
                        "excerpt": _line_excerpt(text, line),
                        "source_sha256": _sha256(raw),
                        "contextual_disposition": "REVIEW_REQUIRED",
                    }
                )
        if len(findings) > BOUNDS.max_findings:
            raise InventoryError("FINDING_LIMIT", f"finding count exceeds {BOUNDS.max_findings}")
    return evidence, findings


def _package_rows(
    root: Path,
    graphs: Sequence[MetadataGraph],
    tracked_manifests: Sequence[str],
    excluded_patterns: Sequence[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[SourceFileEvidence], list[dict[str, Any]]]:
    root_graph = graphs[0]
    root_member_ids = set(root_graph.workspace_members)
    root_default_ids = set(root_graph.workspace_default_members)
    root_packages_by_manifest = _manifest_paths_from_graph(root, root_graph)
    root_package_ids = {str(package.get("id")) for package in root_packages_by_manifest.values()}

    manifest_class: dict[str, ManifestClass] = {"Cargo.toml": ManifestClass.WORKSPACE_ROOT}
    for manifest, package in root_packages_by_manifest.items():
        package_id = str(package.get("id"))
        manifest_class[manifest] = (
            ManifestClass.WORKSPACE_MEMBER
            if package_id in root_member_ids
            else ManifestClass.LOCAL_NON_MEMBER_DEPENDENCY
        )
    for manifest in tracked_manifests:
        if manifest in manifest_class:
            continue
        manifest_class[manifest] = (
            ManifestClass.EXCLUDED_PACKAGE
            if _matches_pattern(manifest, excluded_patterns)
            else ManifestClass.STANDALONE_PACKAGE
        )

    rows: list[dict[str, Any]] = []
    all_edges: list[dict[str, Any]] = []
    source_files: list[SourceFileEvidence] = []
    findings: list[dict[str, Any]] = []
    package_by_key: dict[str, Mapping[str, Any]] = {}
    graph_by_key: dict[str, MetadataGraph] = {}
    manifest_by_key: dict[str, str] = {}

    for graph in graphs:
        all_edges.extend(_dependency_edges(graph))
        for package in graph.packages:
            package_id = package.get("id")
            manifest_path = package.get("manifest_path")
            if not isinstance(package_id, str) or not isinstance(manifest_path, str):
                raise InventoryError("MALFORMED_METADATA", "package identity is incomplete")
            try:
                manifest = _inside(root, Path(manifest_path)).relative_to(root).as_posix()
            except InventoryError:
                continue
            key = _package_key(graph, package_id)
            if key in package_by_key:
                raise InventoryError("DUPLICATE_PACKAGE_KEY", f"duplicate package key: {key}")
            package_by_key[key] = package
            graph_by_key[key] = graph
            manifest_by_key[key] = manifest

    reverse_edges: dict[str, list[dict[str, Any]]] = defaultdict(list)
    forward_edges: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in all_edges:
        reverse_edges[edge["to_package"]].append(edge)
        forward_edges[edge["from_package"]].append(edge)

    token_consumers: dict[str, set[tuple[str, str]]] = defaultdict(set)
    doc_only_consumers: dict[str, set[tuple[str, str]]] = defaultdict(set)
    source_by_package: dict[str, list[SourceFileEvidence]] = defaultdict(list)
    findings_by_package: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for key, package in package_by_key.items():
        manifest_dir = (root / manifest_by_key[key]).parent
        package_name = str(package.get("name", ""))
        evidence, package_findings = _scan_sources(root, key, package_name, manifest_dir)
        source_files.extend(evidence)
        findings.extend(package_findings)
        source_by_package[key].extend(evidence)
        findings_by_package[key].extend(package_findings)
        for file in evidence:
            code_only = set(file.identifiers)
            # Documentation/string-only references are tracked separately and must
            # never be promoted to a production construction of the capability.
            for identifier in set(file.raw_identifiers) - code_only:
                doc_only_consumers[identifier].add((key, file.scope))
            if file.scope not in {SourceScope.PRODUCTION.value, SourceScope.BUILD.value}:
                continue
            for identifier in code_only:
                token_consumers[identifier].add((key, file.scope))

    for key, package in sorted(package_by_key.items()):
        graph = graph_by_key[key]
        manifest = manifest_by_key[key]
        package_name = str(package.get("name", ""))
        crate_identifier = package_name.replace("-", "_")
        source_consumers: list[dict[str, str]] = []
        documentation_only_consumers: list[dict[str, str]] = []
        for consumer_key, scope in sorted(token_consumers.get(crate_identifier, set())):
            if consumer_key == key:
                continue
            source_consumers.append({"package_key": consumer_key, "scope": scope})
            if len(source_consumers) > BOUNDS.max_source_consumers_per_package:
                raise InventoryError(
                    "SOURCE_CONSUMER_LIMIT",
                    f"source consumer count exceeds {BOUNDS.max_source_consumers_per_package}: {package_name}",
                )
        for consumer_key, scope in sorted(doc_only_consumers.get(crate_identifier, set())):
            if consumer_key == key:
                continue
            documentation_only_consumers.append({"package_key": consumer_key, "scope": scope})
        rev = sorted(
            reverse_edges.get(key, []),
            key=lambda item: (item["from_package"], item["kind"], item["target"] or ""),
        )
        targets_raw = package.get("targets", [])
        if not isinstance(targets_raw, list):
            raise InventoryError("MALFORMED_METADATA", f"targets are malformed: {package_name}")
        targets: list[dict[str, Any]] = []
        has_binary = False
        for target in targets_raw:
            if not isinstance(target, dict):
                raise InventoryError("MALFORMED_METADATA", f"target is malformed: {package_name}")
            kinds = target.get("kind", [])
            crate_types = target.get("crate_types", [])
            if not isinstance(kinds, list) or not isinstance(crate_types, list):
                raise InventoryError("MALFORMED_METADATA", f"target kind is malformed: {package_name}")
            has_binary = has_binary or "bin" in kinds
            src_path = target.get("src_path")
            target_context = (
                f"package {package_name!r} ({package.get('id')!r}), "
                f"target {target.get('name')!r} (kind={kinds!r})"
            )
            if (
                not isinstance(src_path, str)
                or not src_path.strip()
                or not Path(src_path).is_absolute()
            ):
                raise InventoryError(
                    "MALFORMED_METADATA",
                    f"{target_context}: src_path must be a non-empty absolute string",
                )
            try:
                relative_src = _inside(root, Path(src_path)).relative_to(root).as_posix()
            except InventoryError as exc:
                raise InventoryError(
                    exc.code,
                    f"{target_context}: invalid src_path {src_path!r}: {exc.detail}",
                ) from exc
            targets.append(
                {
                    "name": _bounded_text(target.get("name", ""), 256),
                    "kind": tuple(sorted(str(item) for item in kinds)),
                    "crate_types": tuple(sorted(str(item) for item in crate_types)),
                    "edition": _bounded_text(target.get("edition", ""), 32),
                    "src_path": relative_src,
                    "required_features": tuple(sorted(str(item) for item in target.get("required-features", []) or [])),
                    "doctest": bool(target.get("doctest", False)),
                    "test": bool(target.get("test", False)),
                    "bench": bool(target.get("bench", False)),
                }
            )
        dependency_kinds = {edge["kind"] for edge in rev}
        source_prod_consumers = [item for item in source_consumers if item["scope"] == SourceScope.PRODUCTION.value]
        source_build_consumers = [item for item in source_consumers if item["scope"] == SourceScope.BUILD.value]
        normal_consumers = [edge for edge in rev if edge["kind"] == "normal"]
        build_consumers = [edge for edge in rev if edge["kind"] == "build"]
        dev_consumers = [edge for edge in rev if edge["kind"] == "dev"]
        if has_binary:
            reachability = Reachability.BINARY_ENTRYPOINT
        elif normal_consumers or source_prod_consumers:
            reachability = Reachability.PRODUCTION_CONSUMER
        elif build_consumers or source_build_consumers:
            reachability = Reachability.BUILD_ONLY
        elif dev_consumers:
            reachability = Reachability.TEST_ONLY
        elif package.get("links") or ((package.get("metadata") or {}).get("eliot") or {}).get("dynamic_registration"):
            reachability = Reachability.UNRESOLVED_DYNAMIC
        else:
            reachability = Reachability.NO_CONSUMER

        files = source_by_package.get(key, [])
        package_findings = findings_by_package.get(key, [])
        manifest_dir = (root / manifest).parent
        instructions = _nearest_instructions(root, manifest_dir)
        owner_issues = _owner_issues(root, manifest_dir)
        row = {
            "package_key": key,
            "graph_id": graph.graph_id,
            "package_id": str(package.get("id")),
            "name": package_name,
            "version": _bounded_text(package.get("version", ""), 128),
            "source": package.get("source"),
            "manifest_path": manifest,
            "manifest_class": manifest_class.get(manifest, ManifestClass.STANDALONE_PACKAGE).value,
            "workspace_member": str(package.get("id")) in root_member_ids,
            "workspace_default_member": str(package.get("id")) in root_default_ids,
            "targets": sorted(targets, key=lambda item: (item["name"], item["kind"], item["src_path"] or "")),
            "dependency_edges": sorted(
                forward_edges.get(key, []),
                key=lambda item: (item["to_package"], item["kind"], item["target"] or ""),
            ),
            "reverse_dependency_edges": rev,
            "source_consumers": source_consumers,
            "documentation_only_consumers": documentation_only_consumers,
            "capability_construction": (
                # The crate identifier appearing as a *code* identifier is the only
                # signal that the public capability is constructed/called. A bare
                # dependency edge never reaches this state.
                "PRODUCTION_CONSTRUCTED"
                if source_prod_consumers
                else (
                    "BUILD_CONSTRUCTED"
                    if source_build_consumers
                    else (
                        "TEST_ONLY"
                        if any(item["scope"] == SourceScope.TEST.value for item in source_consumers)
                        else (
                            "DOCUMENTATION_ONLY"
                            if documentation_only_consumers
                            else "NOWHERE"
                        )
                    )
                )
            ),
            "reachability": reachability.value,
            "source_summary": {
                "files": len(files),
                "nonblank_loc": sum(file.nonblank_loc for file in files),
                "public_items": sum(file.public_items for file in files),
                "owned_test_attributes": sum(file.test_attributes for file in files),
                "production_files": sum(file.scope == SourceScope.PRODUCTION.value for file in files),
                "build_files": sum(file.scope == SourceScope.BUILD.value for file in files),
                "test_files": sum(file.scope == SourceScope.TEST.value for file in files),
                "example_files": sum(file.scope == SourceScope.EXAMPLE.value for file in files),
                "bench_files": sum(file.scope == SourceScope.BENCH.value for file in files),
            },
            "finding_counts": dict(
                sorted(
                    (
                        category,
                        sum(item["category"] == category for item in package_findings),
                    )
                    for category in {item["category"] for item in package_findings}
                )
            ),
            "nearest_instructions": instructions,
            "owner_issue_refs_from_instructions": owner_issues,
            "support_axes": {
                "contract_maturity": "UNKNOWN_FROM_THIS_INVENTORY",
                "implementation_support": "SOURCE_SHAPE_OBSERVED_ONLY",
                "evidence_execution_status": "NOT_EXECUTED_BY_THIS_INVENTORY",
                "runtime_support": "UNKNOWN_FROM_THIS_INVENTORY",
                "product_support": "UNKNOWN_FROM_THIS_INVENTORY",
            },
            "review_state": (
                "REVIEW_REQUIRED"
                if reachability in {Reachability.NO_CONSUMER, Reachability.UNRESOLVED_DYNAMIC}
                or package_findings
                else "NO_STATIC_GAP_DETECTED"
            ),
            "blind_boundaries": (
                "dynamic registration, generated code, runtime feature selection, and platform-only construction are not proven by static token evidence",
            ),
        }
        row["row_sha256"] = _sha256(_canonical_bytes(row))
        rows.append(row)

    manifest_rows = [
        {
            "manifest_path": manifest,
            "class": manifest_class[manifest].value,
            "sha256": _sha256(_read_bytes(root, root / manifest, max_bytes=BOUNDS.max_source_file_bytes)),
        }
        for manifest in sorted(manifest_class)
    ]
    return (
        sorted(rows, key=lambda item: (item["manifest_path"], item["package_id"], item["graph_id"])),
        manifest_rows,
        sorted(source_files, key=lambda item: (item.package_key, item.scope, item.path)),
        sorted(findings, key=lambda item: (item["package_key"], item["path"], item["line"], item["category"])),
    )


def _package_names_by_key(packages: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    return {str(item["package_key"]): str(item["name"]) for item in packages}


def _workspace_package_names(packages: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                str(item["name"])
                for item in packages
                if item.get("workspace_member") and item.get("source") is None
            }
        )
    )


def _record_defects(record: DecisionRecord, as_of: date) -> list[str]:
    """Facade obligations are machine-checkable, not prose."""
    if record.disposition is not CrateExtractionDecision.MIGRATION_FACADE:
        return []
    defects: list[str] = []
    if record.owner is None:
        defects.append(AdmissionDefect.FACADE_OWNER_MISSING.value)
    if record.expires is None:
        defects.append(AdmissionDefect.FACADE_EXPIRY_MISSING.value)
    else:
        try:
            expiry = _parse_iso_date(record.expires, "expires", record.package)
        except InventoryError:
            defects.append(AdmissionDefect.FACADE_EXPIRY_MISSING.value)
        else:
            if expiry < as_of:
                defects.append(AdmissionDefect.FACADE_EXPIRED.value)
    if record.removal_condition is None:
        defects.append(AdmissionDefect.FACADE_REMOVAL_CONDITION_MISSING.value)
    if record.successor is None:
        defects.append(AdmissionDefect.FACADE_SUCCESSOR_MISSING.value)
    return sorted(defects)


def _name_set(values: Iterable[str | None]) -> set[str]:
    return {value for value in values if isinstance(value, str) and value}


def classify_unreachable_packages(
    root: Path,
    packages: Sequence[dict[str, Any]],
    records: Sequence[DecisionRecord],
    *,
    as_of: date,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Classify every production-admitted, binary-unreachable workspace package.

    Returns ``(classifications, admission_defects, orphan_decisions)``. A package
    that is both production-admitted and unreachable from every binary/service
    consumer and has no valid, non-expired disposition is an admission defect.

    ``root`` is required rather than optional: every name a disposition promises is
    checked against the packages this run actually scanned and against the contours
    and symbols that exist on disk, so a record cannot be discharged by naming a
    crate, a contour or an entrypoint that is not there.
    """
    name_by_key = _package_names_by_key(packages)
    workspace_names = set(_workspace_package_names(packages))
    packages_by_name: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for item in packages:
        packages_by_name[str(item["name"])].append(item)
    known_names = set(packages_by_name)
    package_dir = {
        str(item["name"]): str(Path(str(item["manifest_path"])).parent.as_posix())
        for item in packages
        if item.get("workspace_member")
    }
    contours = _named_contours(root)
    contour_names = {name: _contour_package_names(root, manifest) for name, manifest in contours.items()}

    unreachable_names = {
        str(item["name"])
        for item in packages
        if item.get("workspace_member")
        and item.get("source") is None
        and item["reachability"]
        in {Reachability.NO_CONSUMER.value, Reachability.UNRESOLVED_DYNAMIC.value, Reachability.TEST_ONLY.value}
    }

    record_by_package: dict[str, DecisionRecord] = {}
    for record in records:
        if record.package in record_by_package:
            raise InventoryError("DUPLICATE_DECISION_IDENTITY", f"duplicate decision for {record.package!r}")
        if not isinstance(record.disposition, CrateExtractionDecision):
            try:
                record = dataclasses.replace(record, disposition=CrateExtractionDecision(record.disposition))
            except ValueError as exc:
                raise InventoryError(
                    "MALFORMED_DECISION_DATA",
                    f"{record.package}: disposition must be one of "
                    f"{[item.value for item in CrateExtractionDecision]}, got {record.disposition!r}",
                ) from exc
        record_by_package[record.package] = record

    orphan_decisions = [
        {
            "package": record.package,
            "disposition": record.disposition.value,
            "defect": AdmissionDefect.DECISION_FOR_UNKNOWN_PACKAGE.value,
        }
        for record in record_by_package.values()
        if record.package not in known_names
    ]

    classifications: list[dict[str, Any]] = []
    admission_defects: list[dict[str, Any]] = []

    for name in sorted(unreachable_names):
        candidates = [
            item
            for item in packages_by_name[name]
            if item["reachability"]
            in {Reachability.NO_CONSUMER.value, Reachability.UNRESOLVED_DYNAMIC.value, Reachability.TEST_ONLY.value}
        ]
        # Duplicate package identity across metadata graphs is already a fail-closed
        # error upstream; here the same name may appear in several graphs.
        row = min(candidates, key=lambda item: str(item["package_key"]))
        record = record_by_package.get(name)
        defects: list[str] = []
        declared_consumer = record.declared_consumer if record is not None else None

        if record is None:
            defects.append(AdmissionDefect.UNCLASSIFIED.value)
        else:
            defects.extend(_record_defects(record, as_of))
            if record.disposition is CrateExtractionDecision.CONNECT:
                # A Connect disposition names the owning bundle/binary the package
                # will be wired into, and the consumer that will construct it. Both
                # names are checked against the packages this run actually scanned,
                # so the promise cannot be discharged by naming a crate that does
                # not exist here.
                if record.declared_bundle is None:
                    defects.append(AdmissionDefect.DECLARED_BUNDLE_ABSENT.value)
                elif record.declared_bundle not in known_names:
                    defects.append(AdmissionDefect.DECLARED_BUNDLE_ABSENT.value)
                if declared_consumer is not None and declared_consumer not in known_names:
                    defects.append(AdmissionDefect.DECLARED_CONSUMER_ABSENT.value)
                elif declared_consumer is None and not any(
                    item.get("scope") == SourceScope.PRODUCTION.value
                    for item in row["source_consumers"]
                ):
                    # The bundle exists but nothing constructs the capability yet:
                    # the promised edge is still unwired. A test, bench or example
                    # mention is not the production construction this verb claims,
                    # so a fixture cannot stand in for the wire.
                    defects.append(AdmissionDefect.DECLARED_CONSUMER_ABSENT.value)
            elif record.disposition is CrateExtractionDecision.CONTRACT_ONLY:
                if record.declared_consumer is None:
                    defects.append(AdmissionDefect.DECLARED_CONSUMER_ABSENT.value)
                elif record.declared_consumer not in known_names:
                    defects.append(AdmissionDefect.DECLARED_CONSUMER_ABSENT.value)
            elif record.disposition is CrateExtractionDecision.OPTIONAL_CONTOUR:
                if record.declared_contour is None:
                    defects.append(AdmissionDefect.DECLARED_CONTOUR_ABSENT.value)
                elif name not in contour_names.get(record.declared_contour, set()):
                    # The record claims the package was moved to a federated
                    # contour. The contour must exist on disk and really hold this
                    # package, not merely be spelled plausibly.
                    defects.append(AdmissionDefect.DECLARED_CONTOUR_ABSENT.value)
                if record.proof_entrypoint is None:
                    defects.append(AdmissionDefect.DECLARED_ENTRYPOINT_ABSENT.value)
                else:
                    proof = _declared_symbols(record.proof_entrypoint)
                    if len(proof) != 1:
                        defects.append(AdmissionDefect.DECLARED_ENTRYPOINT_ABSENT.value)
                    else:
                        proof_path, proof_symbol = proof[0]
                        own_dir = package_dir.get(name, "")
                        proof_file = root / proof_path
                        if (
                            # The entrypoint must be a real file inside the package
                            # that really defines the symbol. Existence is checked
                            # here so a record naming a path that is not there is a
                            # defect on that record, not a run-wide path error.
                            not (proof_path == own_dir or proof_path.startswith(own_dir + "/"))
                            or proof_file.is_symlink()
                            or not proof_file.is_file()
                            or not _defines_function(root, proof_path, proof_symbol)
                        ):
                            defects.append(AdmissionDefect.DECLARED_ENTRYPOINT_ABSENT.value)
                if row.get("workspace_default_member"):
                    # The disposition claims exclusion from the root daily path, but
                    # declared workspace metadata puts the package on it.
                    defects.append(AdmissionDefect.DECLARED_CONTOUR_ABSENT.value)
                if record.contour_excluded_from_default_path is not True:
                    # Absent is not true: an omitted field is not an assertion that
                    # the package left the root daily path.
                    defects.append(AdmissionDefect.DECLARED_CONTOUR_ABSENT.value)
            elif record.disposition is CrateExtractionDecision.MIGRATION_FACADE:
                # A facade is admitted only while it is still unexpired; an expired
                # facade is exactly the admission defect the issue describes. The
                # expiry is compared in `_record_defects` against the owner
                # evaluation date, never against a wall clock.
                pass

        if record is not None:
            classification = {
                "package": name,
                "package_key": str(row["package_key"]),
                "manifest_path": str(row["manifest_path"]),
                "reachability": str(row["reachability"]),
                "capability_construction": str(row["capability_construction"]),
                "classification": record.disposition.value,
                "admitted": not defects,
                "defects": sorted(set(defects)),
                "record": record.to_json(),
            }
        else:
            classification = {
                "package": name,
                "package_key": str(row["package_key"]),
                "manifest_path": str(row["manifest_path"]),
                "reachability": str(row["reachability"]),
                "capability_construction": str(row["capability_construction"]),
                "classification": None,
                "admitted": False,
                "defects": sorted(set(defects)),
                "record": None,
            }
        classifications.append(classification)
        if classification["defects"]:
            admission_defects.append(
                {
                    "package": name,
                    "manifest_path": classification["manifest_path"],
                    "reachability": classification["reachability"],
                    "capability_construction": classification["capability_construction"],
                    "classification": classification["classification"],
                    "defects": classification["defects"],
                }
            )

    return (
        sorted(classifications, key=lambda item: item["package"]),
        sorted(admission_defects, key=lambda item: item["package"]),
        sorted(orphan_decisions, key=lambda item: item["package"]),
    )


def reconciliation_map(inventory: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Map every admission gap to exactly one owner and one bounded issue spec.

    Issue #1720 A11: a reviewed inventory drives bounded Issues/PRs without
    duplicate ownership. This function emits the gap -> owner map as local
    evidence (A10): it never files, closes, labels or mutates any issue, PR,
    branch or workflow, which the governing assignment forbids. Filing remains
    the human review act; what this guarantees mechanically is that every gap
    names exactly one owner, so two lanes can never claim the same gap.

    Owner precedence per gap is fixed: the row's own ``owner``, else its
    ``review_owner`` (or the #1721 ``evidence_status_and_review_owner``), else
    the issue owner. One gap, one owner, no inference from source statistics.
    """
    extraction = inventory.get("extraction_classification") or {}
    admission = inventory.get("capability_admission") or {}
    by_package = {item.get("package"): item for item in extraction.get("classifications", [])}
    items: list[dict[str, Any]] = []
    for defect in extraction.get("admission_defects", []):
        name = str(defect.get("package"))
        row = by_package.get(name, {})
        record = row.get("record") or {}
        owner = record.get("owner") or record.get("review_owner") or ISSUE_1720_OWNER
        if row.get("classification") is None and not record:
            gap = "UNCLASSIFIED: no decision row"
        else:
            gap = "DEFECTIVE_ROW: " + ", ".join(sorted(set(defect.get("defects", []))))
        items.append(_reconcile_item(name, "1720", gap, owner, record, defect))
    for orphan in extraction.get("orphan_decisions", []):
        name = str(orphan.get("package"))
        items.append(
            _reconcile_item(
                name, "1720", "ORPHAN_ROW: " + str(orphan.get("defect")), ISSUE_1720_OWNER, {}, orphan
            )
        )
    for defect in admission.get("admission_defects", []):
        name = str(defect.get("package"))
        record = defect.get("record") or {}
        owner = (
            record.get("evidence_status_and_review_owner") or ISSUE_1720_OWNER
        )
        items.append(
            _reconcile_item(
                name,
                "1721",
                "ADMISSION_DEFECT: " + ", ".join(sorted(set(defect.get("defects", [])))),
                owner,
                record,
                defect,
            )
        )
    return sorted(items, key=lambda item: (item["layer"], item["package"]))


def _reconcile_item(
    package: str,
    layer: str,
    gap: str,
    owner: str,
    record: Mapping[str, Any],
    defect: Mapping[str, Any],
) -> dict[str, Any]:
    """One gap, exactly one owner, one bounded issue specification."""
    disposition = record.get("disposition") or defect.get("classification")
    return {
        "package": package,
        "layer": layer,
        "gap": gap,
        "owner": owner,
        "promised_disposition": disposition,
        "bounded_issue": {
            "title": f"[1720-reconcile] {package}: {gap}",
            "acceptance": (
                "scripts/crate_reachability_inventory.py re-run shows this "
                f"package admitted with no defects (layer {layer})"
            ),
        },
    }


def _read_toml(root: Path, path: Path) -> dict[str, Any]:
    raw = _read_bytes(root, path, max_bytes=BOUNDS.max_source_file_bytes)
    try:
        return tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise InventoryError("MALFORMED_DECISION_DATA", f"{_relative(root, path)} is not valid UTF-8 TOML") from exc


def admission_denominator(root: Path, runner: Runner) -> dict[str, dict[str, Any]]:
    """The tree-derived set of packages issue #1721 requires a decision for.

    A package is in the denominator when its own ``module.toml`` records admission
    wave #966, #967 or #968 as the wave that promoted it into root workspace
    membership. The denominator is therefore read from the repository, never from the
    registry, so deleting a record cannot shrink it and a record cannot invent a member.
    """
    raw = runner.run(root, ("git", "ls-files", "-z", "--", "module.toml", ":(glob)**/module.toml"))
    denominator: dict[str, dict[str, Any]] = {}
    for item in raw.split(b"\x00"):
        if not item:
            continue
        relative = item.decode("utf-8")
        document = _read_toml(root, _inside(root, root / relative))
        admission = str((document.get("agent_task") or {}).get("workspace_admission") or "")
        wave = ADMISSION_WAVE_RE.match(admission)
        if wave is None:
            continue
        package = _require_str(document.get("crate"), "crate", relative)
        denominator[package] = {
            "module_path": relative,
            "admission_wave": wave.group(1),
            "workspace_admission": admission,
            "lifecycle_owner": _require_str(document.get("lifecycle_owner"), "lifecycle_owner", relative),
            "consumers": [str(item) for item in document.get("consumers") or []],
            "integration_owner": _require_str(
                (document.get("agent_task") or {}).get("integration_owner"),
                "agent_task.integration_owner",
                relative,
            ),
        }
    return denominator


def _named_contours(root: Path) -> dict[str, Path]:
    """Workspace contours that physically exist, mapped to their own manifest.

    I2.3 names ``/workspace/core`` as the root production workspace and requires the
    other contours to appear only as their first real consumer does, so a contour that
    has no ``[workspace]`` table on disk is not a contour this gate will accept.
    """
    contours: dict[str, Path] = {ROOT_CONTOUR: root / "Cargo.toml"}
    directory = root / "workspace"
    if directory.is_dir():
        for manifest in sorted(directory.glob("*/Cargo.toml")):
            if "workspace" in _read_toml(root, _inside(root, manifest)):
                contours[_relative(root, manifest.parent)] = manifest
    return contours


def _contour_package_names(root: Path, manifest: Path) -> set[str]:
    members = (_read_toml(root, manifest).get("workspace") or {}).get("members") or []
    names: set[str] = set()
    for member in members:
        member_manifest = root / str(member) / "Cargo.toml"
        if not member_manifest.is_file():
            continue
        names.add(str(_read_toml(root, member_manifest).get("package", {}).get("name", "")))
    return {name for name in names if name}


def _defines_function(root: Path, relative: str, symbol: str) -> bool:
    path = _inside(root, root / relative)
    if path.is_symlink() or not path.is_file():
        return False
    text = path.read_text(encoding="utf-8", errors="replace")
    return re.search(rf"\bfn\s+{re.escape(symbol)}\s*\(", text) is not None


def _declared_symbols(value: str) -> list[tuple[str, str]]:
    return [(match.group("path"), match.group("symbol")) for match in SYMBOL_REF_RE.finditer(value)]


def _future_date(value: str, as_of: date) -> date | None:
    """The first real, unexpired ISO-8601 date in ``value``, if it carries one."""
    for candidate in ISO_DATE_RE.findall(value):
        try:
            parsed = date.fromisoformat(candidate)
        except ValueError:
            continue
        if parsed >= as_of:
            return parsed
    return None


def measure_consumer_evidence(
    package: str,
    packages: Sequence[Mapping[str, Any]],
    source_files: Sequence[SourceFileEvidence],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Measure a package's Cargo reverse fan-out and production call sites.

    I2.23 licenses the time-bounded migration-facade form only for a package
    admitted *without* a real consumer or test seam, so the premise every
    migration record asserts ("no first real consumer") is re-measured here
    from the resolved Cargo graph and the scanned source tree. The measurement
    never reads the record that asserts it: a record cannot vouch for itself.

    Returns ``(dependents, production_call_sites)`` as sorted tuples of package
    name and ``path::`` file path. The crate identifier is matched against
    ``SourceFileEvidence.identifiers``, which excludes comment, doc and string
    bodies, so a documentation-only mention is never a construction.
    """
    crate_identifier = package.replace("-", "_")
    names = {str(item["package_key"]): str(item["name"]) for item in packages}
    dependents: set[str] = set()
    for item in packages:
        if str(item["name"]) != package:
            continue
        for edge in item["reverse_dependency_edges"]:
            dependent = names.get(str(edge["from_package"]))
            if dependent is not None and dependent != package:
                dependents.add(dependent)
    call_sites = {
        item.path
        for item in source_files
        if item.package_name != package
        and item.scope == SourceScope.PRODUCTION.value
        and crate_identifier in item.identifiers
    }
    return tuple(sorted(dependents)), tuple(sorted(call_sites))


def check_admission_decisions(
    root: Path,
    runner: Runner,
    records: Sequence[AdmissionDecisionRecord],
    packages: Sequence[Mapping[str, Any]],
    source_files: Sequence[SourceFileEvidence],
    *,
    as_of: date,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Compare every recorded admission decision against the crate it names.

    Returns ``(classifications, admission_defects)``. A record is not admitted by
    existing: its target contour must be a real contour holding the package, its proof
    entrypoint must be a real symbol inside the package, and it must carry either a
    real external consumer reached through a real Cargo edge or an unexpired migration
    expiry over a consumer the crate's own manifest declares. A migration expiry is
    additionally re-measured against the tree, so a package that really has a Cargo
    dependent or a production call site cannot buy the expiry arm with a false premise.
    """
    member_names = {str(item["name"]) for item in packages if item.get("workspace_member")}
    package_dir = {
        str(item["name"]): str(Path(str(item["manifest_path"])).parent.as_posix())
        for item in packages
        if item.get("workspace_member")
    }
    owner_of_path = {item.path: item.package_name for item in source_files}
    name_by_key = {str(item["package_key"]): str(item["name"]) for item in packages}
    edges_by_package = {
        str(item["name"]): {
            name_by_key[str(edge["to_package"])]
            for edge in item["dependency_edges"]
            if str(edge["to_package"]) in name_by_key
        }
        for item in packages
    }
    contours = _named_contours(root)
    contour_names = {name: _contour_package_names(root, manifest) for name, manifest in contours.items()}
    denominator = admission_denominator(root, runner)
    record_by_package = {record.package: record for record in records}

    classifications: list[dict[str, Any]] = []
    admission_defects: list[dict[str, Any]] = []
    for package in sorted(denominator):
        declared = denominator[package]
        record = record_by_package.get(package)
        defects: list[str] = []
        entrypoint = None
        consumer = None
        if record is None:
            defects.append(AdmissionDefect.ADMISSION_RECORD_MISSING.value)
        elif package not in member_names:
            defects.append(AdmissionDefect.ADMISSION_CONTOUR_ABSENT.value)
        else:
            boundary = record.proposed_package_boundary
            contour, separator, boundary_package = boundary.partition(" :: ")
            if (
                not separator
                or contour not in contours
                or boundary_package.strip() != package
                or package not in contour_names[contour]
            ):
                defects.append(AdmissionDefect.ADMISSION_CONTOUR_ABSENT.value)

            proof = _declared_symbols(record.public_contract_and_independent_test_entrypoint.split(";")[0])
            if len(proof) != 1:
                defects.append(AdmissionDefect.ADMISSION_ENTRYPOINT_ABSENT.value)
            else:
                proof_path, proof_symbol = proof[0]
                entrypoint = f"{proof_path}::{proof_symbol}"
                if not _defines_function(root, proof_path, proof_symbol) or not (
                    proof_path == package_dir[package] or proof_path.startswith(package_dir[package] + "/")
                ):
                    defects.append(AdmissionDefect.ADMISSION_ENTRYPOINT_ABSENT.value)

            consumers = _declared_symbols(record.first_real_consumer_or_time_bounded_migration_facade)
            if consumers:
                for consumer_path, consumer_symbol in consumers:
                    if (
                        not _defines_function(root, consumer_path, consumer_symbol)
                        or owner_of_path.get(consumer_path) == package
                        or package not in edges_by_package.get(owner_of_path.get(consumer_path, ""), set())
                    ):
                        defects.append(AdmissionDefect.ADMISSION_CONSUMER_ABSENT.value)
                consumer = ", ".join(f"{path}::{symbol}" for path, symbol in consumers)
            else:
                expiry = _future_date(record.first_real_consumer_or_time_bounded_migration_facade, as_of)
                if expiry is None or not any(
                    name in record.first_real_consumer_or_time_bounded_migration_facade
                    for name in declared["consumers"]
                ):
                    defects.append(AdmissionDefect.ADMISSION_MIGRATION_UNBOUNDED.value)
                # The migration arm is only licensed without a real consumer, so the
                # premise that selects it is measured against the tree here. Without
                # this a record could claim a false "no first real consumer" and the
                # check above, which only reads the record, could not see the lie.
                dependents, call_sites = measure_consumer_evidence(package, packages, source_files)
                if dependents or call_sites:
                    defects.append(AdmissionDefect.ADMISSION_MIGRATION_PREMISE_FALSE.value)

            functional_cell = str(
                ((_read_toml(root, root / package_dir[package] / "Cargo.toml").get("package") or {}).get("metadata") or {})
                .get("eliot", {})
                .get("functional_cell", "")
            )
            for field, expected in (
                ("affected_functional_cells_and_lifecycle_owners", (functional_cell, declared["lifecycle_owner"])),
                ("source_maintenance_owner_and_vendor_type_boundary", (declared["integration_owner"],)),
            ):
                if not expected[0] or any(name not in getattr(record, field) for name in expected):
                    defects.append(AdmissionDefect.ADMISSION_FIELD_MISMATCH.value)

        classification = {
            "package": package,
            "module_path": declared["module_path"],
            "admission_wave": declared["admission_wave"],
            "contour": record.proposed_package_boundary.partition(" :: ")[0] if record else None,
            "disposition": record.disposition.value if record else None,
            "proof_entrypoint": entrypoint,
            "first_consumer": consumer,
            "admitted": not defects,
            "defects": sorted(set(defects)),
            "record": record.to_json() if record else None,
        }
        classifications.append(classification)
        if defects:
            admission_defects.append(
                {
                    "package": package,
                    "admission_wave": declared["admission_wave"],
                    "disposition": classification["disposition"],
                    "defects": classification["defects"],
                }
            )

    for record in records:
        if record.package not in denominator:
            orphan = {
                "package": record.package,
                "admission_wave": None,
                "disposition": record.disposition.value,
                "defects": [AdmissionDefect.ADMISSION_RECORD_FOR_UNKNOWN_PACKAGE.value],
            }
            classifications.append(
                {
                    "package": record.package,
                    "module_path": None,
                    "admission_wave": None,
                    "contour": None,
                    "disposition": record.disposition.value,
                    "proof_entrypoint": None,
                    "first_consumer": None,
                    "admitted": False,
                    "defects": orphan["defects"],
                    "record": record.to_json(),
                }
            )
            admission_defects.append(orphan)

    return classifications, admission_defects


def build_inventory(root: Path, runner: Runner | None = None, *, as_of: date | None = None) -> dict[str, Any]:
    root = _root(root)
    runner = runner or SubprocessRunner()
    started = time.monotonic()
    tracked_manifests = _tracked_manifests(root, runner)
    member_paths, excluded_patterns = _load_root_workspace(root)
    graphs = _collect_graphs(root, runner, tracked_manifests)
    packages, manifests, source_files, findings = _package_rows(
        root,
        graphs,
        tracked_manifests,
        excluded_patterns,
    )
    # The workspace denominator is reconciled before anything is classified, against
    # the root manifest's own `members`/`exclude` arrays. A discrepancy is fail-closed:
    # an inventory that cannot name every workspace package is incomplete output, not
    # a clean inventory with fewer rows (issue #1720 A1, I0.5).
    denominator = workspace_denominator(
        root,
        member_paths,
        excluded_patterns,
        tracked_manifests,
        packages,
    )
    if denominator["discrepancies"]:
        raise InventoryError(
            "INCOMPLETE_DENOMINATOR",
            "workspace denominator is incomplete: " + "; ".join(denominator["discrepancies"][:20]),
        )
    head = runner.run(root, ("git", "rev-parse", "HEAD")).decode("ascii", errors="strict").strip()
    status = runner.run(root, ("git", "status", "--porcelain=v1", "--untracked-files=no"))
    cargo_version = runner.run(root, ("cargo", "-Vv")).decode("utf-8", errors="replace").strip()
    rustc_version = runner.run(root, ("rustc", "-Vv")).decode("utf-8", errors="replace").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", head):
        raise InventoryError("INVALID_SOURCE_IDENTITY", "git HEAD is not a full commit identity")
    lock_path = root / "Cargo.lock"
    lock_sha = _sha256(_read_bytes(root, lock_path, max_bytes=128 * 1024 * 1024)) if lock_path.is_file() else None
    # The decision registry is part of the evidence surface: binding its hash into
    # the aggregate means any edit to a disposition invalidates every row.
    decision_sha, decision_document = _decision_document(root)
    decision_sha, decision_revision, records = load_decision_records(decision_document, decision_sha)
    admission_records = load_admission_records(decision_document)
    # The expiry comparison runs against the owner evaluation date carried by the
    # registry revision, not the wall clock. `revision_date` fails closed when the
    # owner has written no date, so a facade expiry is never silently uncompared.
    as_of = as_of or revision_date(decision_revision)
    classifications, admission_defects, orphan_decisions = classify_unreachable_packages(
        root,
        packages,
        records,
        as_of=as_of,
    )
    admission_classifications, admission_wave_defects = check_admission_decisions(
        root,
        runner,
        admission_records,
        packages,
        source_files,
        as_of=as_of,
    )
    semantic = {
        "schema": SCHEMA,
        "tool_version": TOOL_VERSION,
        "source_identity": {
            "git_head": head.lower(),
            "tracked_tree_clean": not bool(status),
            "cargo_lock_sha256": lock_sha,
            "cargo_version": cargo_version,
            "rustc_version": rustc_version,
        },
        "bounds": dataclasses.asdict(BOUNDS),
        "manifest_rows": manifests,
        "workspace_denominator": denominator,
        "metadata_graphs": [
            {
                "graph_id": graph.graph_id,
                "manifest_path": graph.manifest_path,
                "workspace_root": graph.workspace_root,
                "workspace_members": graph.workspace_members,
                "workspace_default_members": graph.workspace_default_members,
                "locked": graph.locked,
            }
            for graph in sorted(graphs, key=lambda item: (item.manifest_path, item.graph_id))
        ],
        "packages": packages,
        "extraction_classification": {
            "schema": DECISION_SCHEMA,
            "decision_data_path": DECISION_DATA_RELPATH,
            "decision_data_sha256": decision_sha,
            "revision": decision_revision,
            "as_of": as_of.isoformat(),
            "classifications": classifications,
            "admission_defects": admission_defects,
            "orphan_decisions": orphan_decisions,
            "count_by_disposition": {
                disposition.value: sum(item["classification"] == disposition.value for item in classifications)
                for disposition in CrateExtractionDecision
            },
        },
        "capability_admission": {
            "schema": ADMISSION_SCHEMA,
            "record_shape": "I2.23 canonical extraction decision",
            "decision_data_path": DECISION_DATA_RELPATH,
            "as_of": as_of.isoformat(),
            "classifications": admission_classifications,
            "admission_defects": admission_wave_defects,
            "count_by_disposition": {
                disposition.value: sum(item["disposition"] == disposition.value for item in admission_classifications)
                for disposition in CrateAdmissionDisposition
            },
        },
        "source_files": [item.to_json() for item in source_files],
        "findings": findings,
        "summary": {
            "tracked_manifests": len(manifests),
            "metadata_graphs": len(graphs),
            "unlocked_metadata_graphs": sum(not graph.locked for graph in graphs),
            "packages": len(packages),
            "source_files": len(source_files),
            "findings": len(findings),
            "packages_without_consumer": sum(item["reachability"] == Reachability.NO_CONSUMER.value for item in packages),
            "packages_with_binary_entrypoint": sum(item["reachability"] == Reachability.BINARY_ENTRYPOINT.value for item in packages),
            "packages_requiring_review": sum(item["review_state"] == "REVIEW_REQUIRED" for item in packages),
            # Computed by comparing the scanned package set against the root
            # manifest's own `members`/`exclude` arrays, never a literal.
            "complete_denominator": denominator["complete"],
            "unreachable_classified": sum(item["admitted"] for item in classifications),
            "admission_defects": len(admission_defects),
            "unclassified_unreachable": sum(
                AdmissionDefect.UNCLASSIFIED.value in item["defects"] for item in classifications
            ),
            "admitted_wave_packages": sum(item["admitted"] for item in admission_classifications),
            "admission_wave_defects": len(admission_wave_defects),
            "proof_ceiling": "CRATE_REACHABILITY_CLASSIFICATION_AND_SOURCE_SHAPE_EVIDENCE_ONLY",
        },
    }
    semantic["aggregate_sha256"] = _sha256(_canonical_bytes(semantic))
    semantic["observation"] = {
        "duration_ms": int((time.monotonic() - started) * 1000),
        "note": "duration is excluded from aggregate_sha256 and is not support evidence",
    }
    return semantic


def run_self_tests() -> int:
    """Run internal unit/fixture self-tests without spawning slow external tools."""
    sample = """
    // single line comment
    /* block
       comment */
    fn foo<'a>(x: &'static str) -> char {
        let c = 'a';
        let byte_c = b'\\n';
        let quote = '"';
        let s = "hello \\"world\\"";
        let raw = r#"raw "string" here"#;
        todo!();
        c
    }
    """
    masked = _mask_rust(sample)
    assert "// single line comment" not in masked
    assert "/* block" not in masked
    assert "hello" not in masked
    assert 'raw "string"' not in masked
    assert "'a'" not in masked
    assert "fn foo" in masked
    assert "todo!" in masked

    try:
        _mask_rust("/* unclosed")
        assert False, "should fail on unclosed comment"
    except InventoryError as exc:
        assert exc.code == "MALFORMED_RUST_SOURCE"

    try:
        _mask_rust('let s = "unclosed;')
        assert False, "should fail on unclosed string"
    except InventoryError as exc:
        assert exc.code == "MALFORMED_RUST_SOURCE"

    h1 = _sha256(_canonical_bytes({"b": 2, "a": [1, 2, 3]}))
    h2 = _sha256(_canonical_bytes({"a": [1, 2, 3], "b": 2}))
    assert h1 == h2, "canonical bytes must sort keys deterministically"

    with tempfile.TemporaryDirectory() as td:
        troot = Path(td).resolve()
        (troot / ".eliot").mkdir()
        try:
            _safe_output(troot, troot / "unsafe.json")
            assert False, "should reject output outside .eliot"
        except InventoryError as exc:
            assert exc.code == "UNSAFE_OUTPUT"

        safe_out = _safe_output(troot, troot / ".eliot" / "out.json")
        assert safe_out == troot / ".eliot" / "out.json"

        safe_out.write_text("existing", encoding="utf-8")
        try:
            _safe_output(troot, troot / ".eliot" / "out.json", overwrite=False)
            assert False, "should reject existing output"
        except InventoryError as exc:
            assert exc.code == "OUTPUT_EXISTS"

        safe_out_ow = _safe_output(troot, troot / ".eliot" / "out.json", overwrite=True)
        assert safe_out_ow == safe_out

    print("PASS: crate_reachability_inventory self-tests completed successfully")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--overwrite", action="store_true", help="allow overwriting existing output")
    parser.add_argument("--self-test", action="store_true", help="run internal self-tests")
    parser.add_argument(
        "--as-of",
        type=str,
        default=None,
        help=(
            "evaluate disposition expiry as of this ISO-8601 date; the default is the "
            "owner evaluation date in the registry's own 'revision' field"
        ),
    )
    parser.add_argument(
        "--allow-admission-defects",
        action="store_true",
        help="exit 0 even when unclassified unreachable packages remain",
    )
    parser.add_argument(
        "--reconcile",
        type=Path,
        default=None,
        help=(
            "write the A11 gap->owner reconciliation map (one owner and one "
            "bounded issue spec per admission gap) as local evidence; never files anything"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.self_test:
        return run_self_tests()
    if args.output is None:
        print(
            json.dumps(
                {"status": "error", "code": "MISSING_OUTPUT", "detail": "--output is required when not running --self-test"},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    try:
        as_of = _parse_iso_date(args.as_of, "--as-of", "<argv>") if args.as_of is not None else None
        root = _root(args.repo_root)
        output = _safe_output(root, args.output, overwrite=args.overwrite)
        inventory = build_inventory(root, as_of=as_of)
        output.parent.mkdir(parents=True, exist_ok=True)
        if args.overwrite and output.exists():
            output.unlink()
        with output.open("xb") as handle:
            handle.write(_canonical_bytes(inventory))
            handle.write(b"\n")
        reconcile_output = None
        reconcile_items: list[dict[str, Any]] = []
        if args.reconcile is not None:
            # A11 driver output: the gap->owner map as local evidence. Filing the
            # bounded issues remains the human review act; this file only assigns
            # exactly one owner per gap so ownership can never duplicate.
            reconcile_items = reconciliation_map(inventory)
            reconcile_output = _safe_output(root, args.reconcile, overwrite=args.overwrite)
            reconcile_output.parent.mkdir(parents=True, exist_ok=True)
            if args.overwrite and reconcile_output.exists():
                reconcile_output.unlink()
            with reconcile_output.open("xb") as handle:
                handle.write(_canonical_bytes({"gaps": reconcile_items}))
                handle.write(b"\n")
    except InventoryError as exc:
        print(
            json.dumps(
                {"status": "error", "code": exc.code, "detail": exc.detail},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    summary = inventory["summary"]
    print(
        json.dumps(
            {
                "status": "ok"
                if not summary["admission_defects"] and not summary["admission_wave_defects"]
                else "admission_defects",
                "output": str(output),
                "packages": summary["packages"],
                "manifests": summary["tracked_manifests"],
                "findings": summary["findings"],
                "unreachable_classified": summary["unreachable_classified"],
                "admission_defects": summary["admission_defects"],
                "unclassified_unreachable": summary["unclassified_unreachable"],
                "count_by_disposition": inventory["extraction_classification"]["count_by_disposition"],
                "admission_defect_packages": [
                    {"package": item["package"], "defects": item["defects"]}
                    for item in inventory["extraction_classification"]["admission_defects"]
                ],
                "admitted_wave_packages": summary["admitted_wave_packages"],
                "admission_wave_defects": summary["admission_wave_defects"],
                "admission_count_by_disposition": inventory["capability_admission"]["count_by_disposition"],
                "admission_defect_packages": [
                    {"package": item["package"], "defects": item["defects"]}
                    for item in inventory["capability_admission"]["admission_defects"]
                ],
                "aggregate_sha256": inventory["aggregate_sha256"],
                "proof_ceiling": summary["proof_ceiling"],
                "reconcile_output": str(reconcile_output) if reconcile_output else None,
                "reconcile_gaps": len(reconcile_items),
            },
            sort_keys=True,
        )
    )
    if (summary["admission_defects"] or summary["admission_wave_defects"]) and not args.allow_admission_defects:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
