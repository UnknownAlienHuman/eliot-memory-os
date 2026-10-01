#!/usr/bin/env python3
"""Capture the complete untruncated all-target Clippy JSON diagnostic stream.

Issue: https://github.com/UnknownAlienHuman/eliot-memory-os/issues/838

This is the single producer of the #838 Clippy diagnostic evidence artifact. It
executes exactly the command the issue names

    cargo clippy --locked --workspace --all-targets --message-format=json

itself, writes the complete raw stdout byte stream to disk without re-encoding,
truncation, sampling or record filtering, and derives one evidence document from
those bytes plus the source/tool identity and the declared target denominator
observed in the same run.

What it records (the four properties W1 names):

  1. the complete untruncated ``--message-format=json`` stream, byte for byte,
     with a truncation proof (newline-terminated tail, terminating
     ``build-finished`` record, every non-empty line parsed, on-disk digest
     equal to the captured digest);
  2. the current source revision plus the digests of the manifests and lockfile
     that decide what Clippy sees;
  3. the tool identity that actually ran: ``rustc -V --verbose``,
     ``rustc --print=cfg``, ``cargo -V --verbose``, ``cargo clippy -V`` and
     ``clippy-driver -V``, against the pinned ``rust-toolchain.toml`` channel;
  4. the COMPLETE target denominator: every target ``cargo metadata`` declares
     for every workspace member, the subset this run emitted a
     ``compiler-artifact`` for, and the declared-but-absent remainder named
     explicitly with its kind, src_path and required-features.

The cfg-elision half of property 4 is what makes "a cfg-elided Windows item is
not tested by Linux" observable instead of silent. A run without ``--target``
compiles exactly one target triple, so ``rustc --print=cfg`` is that run's own
authoritative cfg set. Every ``#[cfg(..)]``/``#![cfg(..)]`` predicate in tracked
Rust source whose result depends only on target/platform cfgs is evaluated
against exactly that set: a false predicate is reported as
``target_cfg_false_in_this_run`` with its file and line, so a ``#[cfg(windows)]``
item appears in the evidence as NOT compiled by this run instead of being
absent. Predicates that depend on crate features, ``cfg(test)`` or build-script
cfgs are not decided by the host target set; they are reported separately as
``coverage_not_decided_at_capture_scope`` with their locations and are never
counted as covered. No occurrence is sampled or dropped.

Proof ceiling: SOURCE_CAPTURE_ONLY. The artifact is an exact record of one local
Clippy run. It is not a lint-cleanliness claim, not a build-success claim, not
runtime/store/product evidence, and not the acceptance disposition of any
diagnostic, which stays with its own owner. This script never edits Rust
sources, manifests, lint configuration or workflows, never passes
``-D warnings`` (so it can neither widen nor narrow an existing lint gate), and
never writes inside the tracked tree: every artifact goes to ``--out-dir``,
which defaults to the ignored local state directory.

Standalone and root-excluded crates are NOT compiled by a ``--workspace`` run.
Their manifests are discovered through the existing
``scripts/verify-standalone-crates.py --list`` producer and recorded as an
explicit out-of-workspace remainder, so the denominator states what this command
did not reach instead of implying the workspace is the whole tree.

Usage:
  python scripts/capture_clippy_diagnostics.py --root .
      --out-dir .eliot/clippy-diagnostics
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "eliot.clippy-diagnostic-evidence.v1"
ISSUE = 838
TOOL_VERSION = "0.1.0"
PROOF_CEILING = "SOURCE_CAPTURE_ONLY"

# The command the issue names, verbatim and closed. No flag is added and none is
# removed; in particular there is no `-D warnings`, so this run records
# diagnostics and never acts as a lint gate.
CAPTURE_COMMAND = (
    "cargo",
    "clippy",
    "--locked",
    "--workspace",
    "--all-targets",
    "--message-format=json",
)

# Locked workspace metadata is the declared side of the denominator. `--no-deps`
# keeps it to workspace members, which is exactly what `--workspace` selects;
# this capture repeats the shared lane's existing choice (issue #750) instead of
# inventing a second metadata identity.
METADATA_COMMAND = (
    "cargo",
    "metadata",
    "--locked",
    "--no-deps",
    "--format-version",
    "1",
)

STANDALONE_PRODUCER = ("scripts/verify-standalone-crates.py", "--list")

# `cargo clippy --all-targets` builds lib, bin, test, bench and example targets.
# It does not build build-script units and never runs doctests, so those kinds
# are excluded from the compared denominator with a recorded reason instead of
# silently disappearing from it.
ALL_TARGET_KINDS = frozenset({"lib", "bin", "example", "test", "bench"})
KIND_EXCLUSION_REASON = {
    "custom-build": "cargo-clippy-all-targets-does-not-build-build-script-units",
    "dylib": "not-a-cargo-metadata-target-kind",
    "cdylib": "not-a-cargo-metadata-target-kind",
    "staticlib": "not-a-cargo-metadata-target-kind",
}

# Diagnostic context class, derived from the target kind cargo reports on the
# message itself.
TARGET_CLASS = {"test": "test", "bench": "test", "example": "example", "custom-build": "build"}

# Cfgs whose value the compiled target triple decides uniformly for every target
# in one `--workspace` run. `rustc --print=cfg` is exactly the set rustc defines
# for this run's target, so only predicates built from these are evaluated.
TARGET_CFG_BARE_NAMES = frozenset({"unix", "windows"})
TARGET_CFG_PREFIXES = ("target_",)

# Guard against a pathological single stream being held in memory twice.
MAX_STREAM_BYTES = 1024 * 1024 * 1024

CFG_ATTRIBUTE_RE = re.compile(r"#!?\[\s*cfg\s*\(")
CFG_TOKEN_RE = re.compile(
    r"""\s*(?:
        (?P<lparen>\()
      | (?P<rparen>\))
      | (?P<comma>,)
      | (?P<eq>=)
      | (?P<string>"[^"]*")
      | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
    )""",
    re.VERBOSE,
)


class CaptureError(RuntimeError):
    """Fail-closed capture error carrying a machine-readable reason code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# process and identity helpers
# ---------------------------------------------------------------------------


def run(argv, *, cwd: Path, timeout: int):
    """Run one command with its output captured exactly as delivered.

    No shell and no text decoding: stdout bytes reach the caller untouched, so
    the stored stream is the emitted stream.
    """
    try:
        return subprocess.run(
            list(argv), cwd=str(cwd), capture_output=True, timeout=timeout, shell=False
        )
    except FileNotFoundError as exc:
        raise CaptureError("TOOLCHAIN_MISSING", f"{argv[0]} is not executable: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise CaptureError("TOOLCHAIN_TIMEOUT", f"{' '.join(argv)} exceeded {timeout}s") from exc


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_output(root: Path, args, *, timeout: int = 300) -> str:
    completed = run(("git", "-C", str(root)) + tuple(args), cwd=root, timeout=timeout)
    if completed.returncode != 0:
        raise CaptureError(
            "GIT_QUERY_FAILED",
            f"git {' '.join(args)} exited {completed.returncode}: "
            f"{completed.stderr.decode('utf-8', 'replace').strip()[:300]}",
        )
    return completed.stdout.decode("utf-8", "replace").strip()


def file_digest(root: Path, relative: str) -> dict:
    path = root / relative
    if not path.is_file():
        return {"path": relative, "present": False, "sha256": None, "bytes": None}
    data = path.read_bytes()
    return {"path": relative, "present": True, "sha256": sha256_hex(data), "bytes": len(data)}


def source_identity(root: Path) -> dict:
    """The exact source revision and the inputs that decide what Clippy sees."""
    revision = git_output(root, ("rev-parse", "HEAD"))
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise CaptureError("SOURCE_REVISION_UNRESOLVED", f"HEAD is not a full sha: {revision!r}")
    status = git_output(root, ("status", "--porcelain=v1"))
    return {
        "revision": revision,
        "branch": git_output(root, ("rev-parse", "--abbrev-ref", "HEAD")),
        "merge_base_with_origin_main": git_output(root, ("merge-base", "HEAD", "origin/main")),
        "dirty": bool(status.strip()),
        "dirty_path_count": len([line for line in status.splitlines() if line.strip()]),
        "inputs": [
            file_digest(root, "Cargo.toml"),
            file_digest(root, "Cargo.lock"),
            file_digest(root, "clippy.toml"),
            file_digest(root, "rust-toolchain.toml"),
        ],
    }


def pinned_toolchain_channel(root: Path):
    """The channel pinned by rust-toolchain.toml, or None when it pins none."""
    path = root / "rust-toolchain.toml"
    if not path.is_file():
        return None
    match = re.search(
        r'^\s*channel\s*=\s*"([^"]+)"',
        path.read_text(encoding="utf-8", errors="replace"),
        flags=re.M,
    )
    return match.group(1) if match else None


def parse_verbose_version_fields(raw: str) -> dict:
    fields = {}
    for line in raw.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            fields[key.strip()] = value.strip()
    return fields


def tool_identity(root: Path, timeout: int) -> dict:
    """The tool identity that actually produced this run's stream.

    A compiler-help URL printed by a failing run identifies none of these, so
    each tool is queried directly. A driver that is not separately resolvable is
    recorded as unresolved rather than inferred from another tool's version.
    """

    def probe(argv):
        completed = run(argv, cwd=root, timeout=timeout)
        text = completed.stdout.decode("utf-8", "replace").strip()
        resolved = completed.returncode == 0 and bool(text)
        return {
            "argv": list(argv),
            "resolved": resolved,
            "output": text if resolved else (text or completed.stderr.decode("utf-8", "replace").strip())[:512],
        }

    rustc = probe(("rustc", "-V", "--verbose"))
    rustc_fields = parse_verbose_version_fields(rustc["output"]) if rustc["resolved"] else {}
    print_cfg = probe(("rustc", "--print=cfg"))
    cfg_entries = []
    if print_cfg["resolved"]:
        for line in print_cfg["output"].splitlines():
            token = line.strip()
            if "=" not in token:
                continue
            key, _, value = token.partition("=")
            cfg_entries.append({"key": key.strip(), "value": value.strip().strip('"')})

    channel = pinned_toolchain_channel(root)
    release = rustc_fields.get("release", "")
    return {
        "rustc": {**rustc, "fields": rustc_fields},
        "cargo": probe(("cargo", "-V", "--verbose")),
        "clippy": probe(("cargo", "clippy", "-V")),
        "clippy_driver": probe(("clippy-driver", "-V")),
        "host_target_triple": rustc_fields.get("host", ""),
        "target_specified_by_this_run": False,
        "rust_print_cfg": {**print_cfg, "entries": cfg_entries},
        "pinned_toolchain": {
            "channel": channel,
            "file": file_digest(root, "rust-toolchain.toml"),
            "matches_running_rustc": (
                None
                if (channel is None or not release)
                else channel.split(".")[0] == release.split(".")[0]
            ),
        },
    }


# ---------------------------------------------------------------------------
# stream parsing
# ---------------------------------------------------------------------------


def target_key(package_id: str, target_name: str) -> str:
    return f"{package_id}#{target_name}"


def primary_span(message: dict) -> dict:
    """The primary span: the item and exact lines the diagnostic binds to."""
    for span in message.get("spans") or []:
        if isinstance(span, dict) and span.get("is_primary"):
            return {
                "file_name": span.get("file_name"),
                "line_start": span.get("line_start"),
                "line_end": span.get("line_end"),
                "column_start": span.get("column_start"),
                "column_end": span.get("column_end"),
            }
    return {
        "file_name": None,
        "line_start": None,
        "line_end": None,
        "column_start": None,
        "column_end": None,
    }


def diagnostic_row(record: dict) -> dict:
    message = record.get("message") or {}
    target = record.get("target") or {}
    kind = target.get("kind")
    kinds = [kind] if isinstance(kind, str) else [str(item) for item in (kind or [])]
    code = (message.get("code") or {}).get("code")
    context_class = "production"
    for item in kinds:
        if item in TARGET_CLASS:
            context_class = TARGET_CLASS[item]
            break
    children = [child for child in (message.get("children") or []) if isinstance(child, dict)]
    return {
        "target_name": target.get("name"),
        "target_kind": kinds,
        "target_src_path": target.get("src_path"),
        "context_class": context_class,
        "level": message.get("level"),
        "code": code,
        "kind_of_diagnostic": "lint_diagnostic" if code else "compiler_diagnostic",
        "message": message.get("message"),
        "span": primary_span(message),
        "child_diagnostic_count": len(children),
        "notes": [
            child.get("message")
            for child in children
            if child.get("level") in ("note", "help", "warning")
        ],
    }


def artifact_row(record: dict) -> dict:
    target = record.get("target") or {}
    kind = target.get("kind")
    kinds = [kind] if isinstance(kind, str) else [str(item) for item in (kind or [])]
    return {
        "target_key": target_key(str(record.get("package_id")), str(target.get("name"))),
        "package_id": record.get("package_id"),
        "target_name": target.get("name"),
        "target_kind": kinds,
        "target_src_path": target.get("src_path"),
        "profile_test": (record.get("profile") or {}).get("test"),
        "required_features": sorted(str(item) for item in (target.get("required-features") or [])),
    }


def parse_stream(raw: bytes) -> dict:
    """Parse the complete captured stream and prove it was not truncated.

    Compiler diagnostics and non-diagnostic records are separated by ``reason``
    rather than merged: only ``compiler-message`` rows become diagnostics and
    every other reason is counted separately. A record this parser cannot read is
    a capture failure, never a silently dropped row.
    """
    if len(raw) > MAX_STREAM_BYTES:
        raise CaptureError("STREAM_TOO_LARGE", f"captured {len(raw)} bytes")
    if not raw:
        raise CaptureError("EMPTY_STREAM", "cargo clippy produced no structured stdout")
    if not raw.endswith(b"\n"):
        raise CaptureError(
            "STREAM_NOT_NEWLINE_TERMINATED",
            "captured stdout does not end on a record boundary; the output was clipped",
        )
    if not raw.rstrip(b"\n").endswith(b"}"):
        raise CaptureError("STREAM_TAIL_NOT_A_RECORD", "the final record is not a complete JSON object")

    reasons: dict[str, int] = {}
    unparsable: list[dict] = []
    diagnostics: list[dict] = []
    artifacts: list[dict] = []
    finished: list[dict] = []
    line_count = 0

    for index, line in enumerate(raw.split(b"\n"), start=1):
        if not line.strip():
            continue
        line_count += 1
        try:
            record = json.loads(line.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            if len(unparsable) < 8:
                unparsable.append({"line": index, "detail": str(exc)[:200]})
            continue
        if not isinstance(record, dict) or not isinstance(record.get("reason"), str):
            if len(unparsable) < 8:
                unparsable.append({"line": index, "detail": "record has no string reason"})
            continue
        reason = record["reason"]
        reasons[reason] = reasons.get(reason, 0) + 1
        if reason == "compiler-message":
            diagnostics.append(diagnostic_row(record))
        elif reason == "compiler-artifact":
            artifacts.append(artifact_row(record))
        elif reason == "build-finished":
            finished.append(record)

    if unparsable:
        raise CaptureError(
            "STREAM_HAS_UNPARSABLE_RECORDS",
            f"{len(unparsable)} record(s) could not be read; first: {unparsable[0]}",
        )
    if len(finished) != 1:
        raise CaptureError(
            "STREAM_WITHOUT_SINGLE_TERMINATOR",
            f"expected exactly one build-finished record, found {len(finished)}",
        )

    non_diagnostic = {key: value for key, value in sorted(reasons.items()) if key != "compiler-message"}
    levels: dict[str, int] = {}
    codes: dict[str, int] = {}
    for row in diagnostics:
        levels[str(row["level"])] = levels.get(str(row["level"]), 0) + 1
        if row["code"]:
            codes[row["code"]] = codes.get(row["code"], 0) + 1
    return {
        "line_count": line_count,
        "record_reasons": dict(sorted(reasons.items())),
        "non_diagnostic_record_reasons": non_diagnostic,
        "non_diagnostic_record_count": sum(non_diagnostic.values()),
        "diagnostic_record_count": len(diagnostics),
        "diagnostic_levels": dict(sorted(levels.items())),
        "diagnostic_codes": dict(sorted(codes.items())),
        "terminated_by_single_build_finished_record": True,
        "build_finished": finished[0],
        "diagnostics": diagnostics,
        "artifacts": artifacts,
    }


# ---------------------------------------------------------------------------
# declared target denominator
# ---------------------------------------------------------------------------


def relative_to_root(root: Path, absolute: str) -> str:
    if not absolute:
        return absolute
    try:
        return os.path.relpath(absolute, str(root)).replace("\\", "/")
    except ValueError:
        return absolute.replace("\\", "/")


def declared_targets(metadata_raw: bytes, root: Path) -> dict:
    """Every target cargo metadata declares for every workspace member."""
    try:
        metadata = json.loads(metadata_raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise CaptureError("METADATA_UNPARSABLE", f"cargo metadata output is not JSON: {exc}") from exc
    packages = metadata.get("packages")
    if not isinstance(packages, list) or not packages:
        raise CaptureError("METADATA_WITHOUT_PACKAGES", "cargo metadata declared no packages")

    declared: list[dict] = []
    excluded: list[dict] = []
    for package in sorted(packages, key=lambda item: str(item.get("id"))):
        package_id = str(package.get("id"))
        manifest = relative_to_root(root, str(package.get("manifest_path") or ""))
        for target in package.get("targets") or []:
            raw_kind = target.get("kind") or []
            kinds = [raw_kind] if isinstance(raw_kind, str) else [str(item) for item in raw_kind]
            record = {
                "target_key": target_key(package_id, str(target.get("name"))),
                "package_id": package_id,
                "package_name": package.get("name"),
                "package_version": package.get("version"),
                "manifest_path": manifest,
                "target_name": target.get("name"),
                "target_kind": kinds,
                "target_src_path": relative_to_root(root, str(target.get("src_path") or "")),
                "required_features": sorted(str(item) for item in (target.get("required-features") or [])),
                "doc": bool(target.get("doc", True)),
                "doctest": bool(target.get("doctest", False)),
                "test": bool(target.get("test", True)),
                "bench": bool(target.get("bench", True)),
            }
            if any(kind in ALL_TARGET_KINDS for kind in kinds):
                declared.append(record)
            else:
                excluded.append(
                    {
                        **record,
                        "exclusion_reason": KIND_EXCLUSION_REASON.get(
                            kinds[0] if kinds else "", "not-built-by-cargo-clippy-all-targets"
                        ),
                    }
                )

    return {
        "command": list(METADATA_COMMAND),
        "workspace_package_count": len(packages),
        "workspace_member_ids": sorted({str(package.get("id")) for package in packages}),
        "declared_targets": declared,
        "declared_target_count": len(declared),
        "excluded_from_all_targets": excluded,
        "excluded_from_all_targets_count": len(excluded),
    }


def reconcile_denominator(declared: dict, artifacts: list[dict]) -> dict:
    """Split the declared denominator into covered and declared-but-absent.

    The covered side is the set of targets this run emitted a compiler artifact
    for. Everything declared and not covered stays in the artifact as a named
    row, which is what stops a cfg-elided Windows target from being silently
    missing between "declared in Cargo.toml" and "tested by this run".
    """
    covered_by_key: dict[str, dict] = {}
    for artifact in artifacts:
        covered_by_key.setdefault(artifact["target_key"], artifact)

    covered = []
    not_covered = []
    for record in declared["declared_targets"]:
        artifact = covered_by_key.pop(record["target_key"], None)
        if artifact is None:
            not_covered.append(
                {
                    **record,
                    "absence_evidence": "declared-by-cargo-metadata-absent-from-this-run",
                    "command_passed_features_or_all_features": False,
                }
            )
        else:
            covered.append(
                {
                    **record,
                    "profile_test": artifact["profile_test"],
                    "emitted_target_kind": artifact["target_kind"],
                }
            )

    member_ids = set(declared["workspace_member_ids"])
    outside = sorted(
        {
            (str(artifact["package_id"]), str(artifact["target_name"]))
            for artifact in artifacts
            if str(artifact["package_id"]) not in member_ids
        }
    )
    return {
        "compared_target_kinds": sorted(ALL_TARGET_KINDS),
        "covered_targets": covered,
        "covered_target_count": len(covered),
        "not_covered_targets": not_covered,
        "not_covered_target_count": len(not_covered),
        "artifacts_outside_workspace_members": [
            {"package_id": package_id, "target_name": target_name} for package_id, target_name in outside
        ],
        "artifacts_outside_workspace_member_count": len(outside),
    }


def out_of_workspace_remainder(root: Path, timeout: int) -> dict:
    """Name the crates a `--workspace` run cannot reach.

    Standalone and root-excluded crates sit outside the workspace, so the
    issue's command never compiles them. They are listed with that note instead
    of being left to look covered by the workspace denominator.
    """
    argv = [sys.executable or "python", str(root / STANDALONE_PRODUCER[0]), "--root", str(root)]
    argv.extend(STANDALONE_PRODUCER[1:])
    completed = run(argv, cwd=root, timeout=timeout)
    if completed.returncode != 0:
        raise CaptureError(
            "STANDALONE_DISCOVERY_FAILED",
            f"{' '.join(argv)} exited {completed.returncode}: "
            f"{completed.stderr.decode('utf-8', 'replace').strip()[:300]}",
        )
    manifests = []
    for line in completed.stdout.decode("utf-8", "replace").splitlines():
        row = line.strip()
        if not row:
            continue
        excluded = row.startswith("exclude:")
        manifests.append(
            {
                "manifest_path": f"{row[9:].strip() if excluded else row}/Cargo.toml",
                "excluded_from_workspace": excluded,
            }
        )
    return {
        "producer": [
            part[len(str(root)) + 1:].replace("\\", "/") if part.startswith(str(root) + os.sep) else part
            for part in argv
        ],
        "manifest_count": len(manifests),
        "manifests": sorted(manifests, key=lambda item: item["manifest_path"]),
        "coverage_note": (
            "cargo clippy --workspace does not select these manifests; this artifact "
            "records their discovery so the denominator cannot be read as covering them"
        ),
    }


# ---------------------------------------------------------------------------
# cfg-elision visibility
# ---------------------------------------------------------------------------


def cfg_set(print_cfg_entries: list[dict]) -> set:
    entries: set = set()
    for entry in print_cfg_entries:
        entries.add(entry["key"])
        entries.add(f'{entry["key"]}="{entry["value"]}"')
    return entries


def is_target_cfg(name: str) -> bool:
    return name.startswith(TARGET_CFG_PREFIXES) or name in TARGET_CFG_BARE_NAMES


def tokenize_predicate(text: str) -> list:
    tokens = []
    position = 0
    while position < len(text):
        match = CFG_TOKEN_RE.match(text, position)
        if match is None:
            break
        position = match.end()
        kind = match.lastgroup
        tokens.append((kind, match.group(kind)))
    return tokens


class CfgPredicate:
    """Recursive-descent evaluator for one `#[cfg(..)]` predicate.

    Only target/platform cfgs are decidable here, because only they are decided
    by the single target triple this run compiled. A crate feature, `cfg(test)`
    or a build-script cfg returns None: undecided is never reported as covered.
    """

    def __init__(self, tokens: list, active: set) -> None:
        self.tokens = tokens
        self.position = 0
        self.active = active

    def peek(self):
        if self.position < len(self.tokens):
            return self.tokens[self.position]
        return (None, None)

    def take(self, kind=None):
        current = self.peek()
        if current[0] is None:
            raise ValueError("predicate ended early")
        self.position += 1
        if kind is not None and current[0] != kind:
            raise ValueError(f"expected {kind}, found {current[0]}")
        return current[1]

    def parse(self):
        kind, value = self.peek()
        if kind == "ident" and value in ("all", "any", "not"):
            self.take("ident")
            self.take("lparen")
            results = [self.parse()]
            while self.peek()[0] == "comma":
                self.take("comma")
                results.append(self.parse())
            self.take("rparen")
            if value == "not":
                return None if results[0] is None else not results[0]
            if value == "all":
                if any(item is False for item in results):
                    return False
                return None if any(item is None for item in results) else True
            if any(item is True for item in results):
                return True
            return None if any(item is None for item in results) else False
        if kind == "ident":
            self.take("ident")
            if self.peek()[0] == "eq":
                self.take("eq")
                literal = self.take("string")[1:-1]
                return (f'{value}="{literal}"' in self.active) if is_target_cfg(value) else None
            return (value in self.active) if is_target_cfg(value) else None
        if kind == "string":
            self.take("string")
            return None
        raise ValueError(f"unexpected token {kind}")

    def evaluate(self):
        # A top-level comma list is an implicit `any(..)`, exactly as in Rust.
        results = [self.parse()]
        while self.peek()[0] == "comma":
            self.take("comma")
            results.append(self.parse())
        if self.peek()[0] is not None:
            raise ValueError("trailing tokens after predicate")
        if len(results) == 1:
            return results[0]
        if any(item is True for item in results):
            return True
        if any(item is None for item in results):
            return None
        return False


def evaluate_predicate(text: str, active: set):
    """True, False, or None when this capture cannot decide the predicate."""
    try:
        return CfgPredicate(tokenize_predicate(text), active).evaluate()
    except ValueError:
        return None


def balanced_predicate(text: str, open_index: int) -> str:
    depth = 0
    in_string = False
    for index in range(open_index, len(text)):
        char = text[index]
        if in_string:
            in_string = char != '"'
        elif char == '"':
            in_string = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_index + 1:index]
    return ""


def scan_cfg_elision(root: Path, active: set) -> dict:
    """Report every cfg-gated item and whether this run compiled it.

    Occurrences are never sampled, capped or truncated. Each tracked
    ``#[cfg(..)]`` predicate lands in exactly one of three reported lists, so a
    reader can tell "not compiled by this run" apart from "not looked at":

    ``target_cfg_true_in_this_run``
        the predicate holds under this run's compiled target triple;
    ``target_cfg_false_in_this_run``
        the predicate does not hold, so the gated item was NOT compiled;
    ``coverage_not_decided_at_capture_scope``
        the predicate depends on something this capture cannot observe (a crate
        feature, ``cfg(test)`` or a build-script cfg), so its item is neither
        claimed covered nor claimed elided.
    """
    completed = run(("git", "-C", str(root), "ls-files", "--", "*.rs"), cwd=root, timeout=300)
    if completed.returncode != 0:
        raise CaptureError(
            "TRACKED_SOURCE_LIST_FAILED",
            f"git ls-files exited {completed.returncode}: "
            f"{completed.stderr.decode('utf-8', 'replace').strip()[:200]}",
        )
    paths = [line.strip() for line in completed.stdout.decode("utf-8", "replace").splitlines() if line.strip()]

    compiled: list[dict] = []
    elided: list[dict] = []
    undecided: list[dict] = []
    occurrence_count = 0
    for relative in paths:
        source_path = root / relative
        if not source_path.is_file():
            continue
        text = source_path.read_text(encoding="utf-8", errors="replace")
        for match in CFG_ATTRIBUTE_RE.finditer(text):
            predicate = balanced_predicate(text, text.index("(", match.start(), match.end()))
            if not predicate.strip():
                continue
            occurrence_count += 1
            row = {
                "source_path": relative,
                "line": text.count("\n", 0, match.start()) + 1,
                "column": match.start() - (text.rfind("\n", 0, match.start()) + 1) + 1,
                "predicate": " ".join(predicate.split()),
            }
            verdict = evaluate_predicate(predicate, active)
            if verdict is False:
                elided.append({**row, "classification": "target_cfg_false_in_this_run"})
            elif verdict is True:
                compiled.append({**row, "classification": "target_cfg_true_in_this_run"})
            else:
                undecided.append(
                    {**row, "classification": "coverage_not_decided_at_capture_scope"}
                )
    return {
        "scanned_tracked_rust_file_count": len(paths),
        "cfg_attribute_occurrence_count": occurrence_count,
        "classified_occurrence_count": len(compiled) + len(elided) + len(undecided),
        "target_cfg_true_in_this_run": compiled,
        "target_cfg_true_in_this_run_count": len(compiled),
        "target_cfg_false_in_this_run": elided,
        "target_cfg_false_in_this_run_count": len(elided),
        "coverage_not_decided_at_capture_scope": undecided,
        "coverage_not_decided_at_capture_scope_count": len(undecided),
        "evaluation_rule": (
            "only target/platform predicates are evaluated, against rustc --print=cfg "
            "for this run's single compiled target triple; a false predicate means the "
            "gated item was not compiled by this run"
        ),
    }


# ---------------------------------------------------------------------------
# artifact
# ---------------------------------------------------------------------------


def write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_evidence(*, root, out_dir, timeout, started_utc, completed_utc, capture) -> dict:
    stream = parse_stream(capture.stdout)
    source = source_identity(root)
    tools = tool_identity(root, timeout)
    metadata = run(METADATA_COMMAND, cwd=root, timeout=timeout)
    if metadata.returncode != 0:
        raise CaptureError(
            "METADATA_FAILED",
            f"{' '.join(METADATA_COMMAND)} exited {metadata.returncode}: "
            f"{metadata.stderr.decode('utf-8', 'replace').strip()[:300]}",
        )
    declared = declared_targets(metadata.stdout, root)
    reconciliation = reconcile_denominator(declared, stream["artifacts"])
    remainder = out_of_workspace_remainder(root, timeout)
    cfg_elision = scan_cfg_elision(root, cfg_set(tools["rust_print_cfg"]["entries"]))

    stream_path = out_dir / "clippy-stream.jsonl"
    stderr_path = out_dir / "clippy-stderr.txt"
    write_atomic(stream_path, capture.stdout)
    write_atomic(stderr_path, capture.stderr)
    if sha256_hex(stream_path.read_bytes()) != sha256_hex(capture.stdout):
        raise CaptureError(
            "STORED_STREAM_DIFFERS",
            "the stored stream does not match the captured bytes; it would not be this run",
        )

    diagnostics = stream.pop("diagnostics")
    artifact_count = len(stream.pop("artifacts"))
    return {
        "schema": SCHEMA,
        "issue": ISSUE,
        "produced_by": "scripts/capture_clippy_diagnostics.py",
        "tool_version": TOOL_VERSION,
        "proof_ceiling": PROOF_CEILING,
        "started_utc": started_utc,
        "completed_utc": completed_utc,
        "command": list(CAPTURE_COMMAND),
        "clippy_exit_code": capture.returncode,
        "source": source,
        "toolchain": tools,
        "stream": {
            "path": stream_path.name,
            "sha256": sha256_hex(capture.stdout),
            "byte_length": len(capture.stdout),
            "stderr_path": stderr_path.name,
            "stderr_byte_length": len(capture.stderr),
            "stderr_sha256": sha256_hex(capture.stderr),
            "stderr_used_for_diagnostics": False,
            "untruncation_proof": {
                "newline_terminated": True,
                "terminated_by_single_build_finished_record": stream[
                    "terminated_by_single_build_finished_record"
                ],
                "every_non_empty_line_parsed_as_json": True,
                "stored_bytes_match_captured_bytes": True,
            },
            **stream,
        },
        "target_denominator": {
            "declared": declared,
            "reconciliation": reconciliation,
            "out_of_workspace_remainder": remainder,
        },
        "cfg_elision": cfg_elision,
        "diagnostics": diagnostics,
        "diagnostic_artifact_count": artifact_count,
    }


def summarize(evidence: dict) -> str:
    stream = evidence["stream"]
    reconciliation = evidence["target_denominator"]["reconciliation"]
    remainder = evidence["target_denominator"]["out_of_workspace_remainder"]
    cfg = evidence["cfg_elision"]
    return (
        f"revision={evidence['source']['revision'][:12]} "
        f"clippy_exit={evidence['clippy_exit_code']} "
        f"stream_bytes={stream['byte_length']} "
        f"stream_sha256={stream['sha256'][:12]} "
        f"diagnostics={stream['diagnostic_record_count']} "
        f"non_diagnostic_records={stream['non_diagnostic_record_count']} "
        f"declared_targets={evidence['target_denominator']['declared']['declared_target_count']} "
        f"covered_targets={reconciliation['covered_target_count']} "
        f"not_covered_targets={reconciliation['not_covered_target_count']} "
        f"cfg_elided_by_target_cfg={cfg['target_cfg_false_in_this_run_count']} "
        f"cfg_undecided={cfg['coverage_not_decided_at_capture_scope_count']} "
        f"out_of_workspace_manifests={remainder['manifest_count']}"
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run the issue's locked all-target Clippy command once and store the "
            "complete untruncated JSON stream with its source/tool identity and the "
            "complete declared target denominator."
        )
    )
    parser.add_argument("--root", default=".", help="repository root (default: .)")
    parser.add_argument(
        "--out-dir",
        default=os.path.join(".eliot", "clippy-diagnostics"),
        help="artifact directory (default: .eliot/clippy-diagnostics)",
    )
    parser.add_argument(
        "--timeout", type=int, default=7200, help="per-command timeout in seconds (default: 7200)"
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = root / out_dir
    if not root.is_dir():
        sys.stderr.write(f"CLIPPY_DIAGNOSTIC_CAPTURE_FAIL: REPOSITORY_ROOT_MISSING {root}\n")
        return 2

    started_utc = utc_now()
    try:
        capture = run(CAPTURE_COMMAND, cwd=root, timeout=args.timeout)
        evidence = build_evidence(
            root=root,
            out_dir=out_dir,
            timeout=args.timeout,
            started_utc=started_utc,
            completed_utc=utc_now(),
            capture=capture,
        )
    except CaptureError as exc:
        sys.stderr.write(f"CLIPPY_DIAGNOSTIC_CAPTURE_FAIL: {exc.code} {exc.detail}\n")
        return 2

    write_atomic(
        out_dir / "clippy-evidence.json",
        (json.dumps(evidence, indent=2) + "\n").encode("utf-8"),
    )
    sys.stdout.write(f"CLIPPY_DIAGNOSTIC_CAPTURE_PASS: {summarize(evidence)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())