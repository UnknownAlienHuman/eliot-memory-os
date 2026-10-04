#!/usr/bin/env python3
"""Audit ELIOT source/build boundaries without creating architecture authority.

The scanner consumes Cargo manifests, production Rust source, and the explicit
`config/architecture-boundaries.toml` policy. It reports three dispositions:

- HARD_VIOLATION: an untracked contradiction that must fail integration;
- TRACKED_DEBT: an exact temporary exception with owning issue and removal rule;
- AUDIT_SIGNAL: evidence that needs human review but is not an authority rule.

A clean result is static source evidence only. It is never runtime or Product
Proof.

Dependency evidence is typed: every Cargo declaration is retained as an edge
carrying consumer, section, alias, package, kind (normal/dev/build), target
condition, feature and resolution state. Source/vendor rules evaluate the
source-wide declaration inventory, which is labelled source-wide /
source-possible and is never presented as selected runtime evidence.

Runtime-root rules evaluate a RESOLVER-SELECTED projection. Exactly one bounded
resolver input is accepted: `cargo metadata --locked --offline
--format-version 1 --all-features --filter-platform <triple>` together with the
host/target triple, the requested feature selection, the resolver version and
the toolchain. That projection binds root target, host triple, target triple,
feature selection, resolver, toolchain, source identity and the resolved
package graph. When it cannot be obtained the descriptor says so explicitly and
completeness stays incomplete: unbound metadata never claims a selected scope.

Traversal is resolution-aware. An edge is RESOLVED only when the locked
resolver reports the exact declared (crate name, kind) pair for the owning
package; unresolved, degraded, unsupported, ambiguous and external frontiers
produce typed INCOMPLETE evidence and can never be promoted to a resolved hard
runtime path. Traversal also models compilation-unit context (target-runtime,
host-build-script, host-proc-macro, test), so a proc-macro closure is never
reported as target runtime and a nested build dependency is never dropped.

Static selection is never executed-binary proof.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import tomllib
from collections import Counter, deque
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Iterable

SKIP_DIRS = {
    ".git",
    ".eliot",
    ".codebase-memory",
    "target",
    "dist",
    "reports",
    "research",
    "swarm",
}

PROCESS_PATTERNS = (
    re.compile(r"\bstd\s*::\s*process\s*::\s*Command\b"),
    re.compile(r"\btokio\s*::\s*process\s*::\s*Command\b"),
    re.compile(r"\buse\s+std\s*::\s*process\s*::\s*Command\b"),
    re.compile(r"\buse\s+std\s*::\s*process\s*::\s*\{[^}]*\bCommand\b", re.S),
    re.compile(r"\buse\s+tokio\s*::\s*process\s*::\s*Command\b"),
)

PLACEHOLDER_PATTERNS = (
    ("todo_macro", re.compile(r"\btodo\s*!\s*\(")),
    ("unimplemented_macro", re.compile(r"\bunimplemented\s*!\s*\(")),
)

SURRREAL_SOURCE_PATTERN = re.compile(r"\bsurrealdb\s*::")
CFG_TEST_PATTERN = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")

# --- D-CLIPPY-POLICY (#748) oracle gap coverage + clippy.toml handoff seam ---
#
# Pinned-toolchain probe evidence (rustc/clippy 1.97.1/0.1.97, binary std-only
# fixtures, `disallowed-methods` with `std::process::Command::{new,spawn,
# output}` + `std::process::abort` + an extern-block stub):
#   caught: direct `Command::new`; short/long `as` aliases (`Proc::new`,
#     `ProcessCommand::new`); `Command::new` at a `macro_rules!` definition
#     site; `.spawn()`/`.output()` on an injected `Command`; free `std` fns in
#     safe AND unsafe blocks.
#   MISSED: a call through an extern-block declaration (`CreateProcessW_stub()`
#     with a resolving `crate::` path produced no diagnostic).
# Consequence: aliases, wrappers and in-tree macros are the compiler lint's
# proven job once root clippy.toml lands (controller handoff); this oracle
# does NOT re-implement alias resolution. It owns the two classes the text
# layer demonstrably loses: (1) production constructors hidden after ANY
# `#[cfg(test)]` attribute by whole-file truncation (e.g. a test-only `use`
# discarding the rest of the file), and (2) raw Win32 launch APIs, which are
# extern free-function calls the pinned lint demonstrably misses.
#
# SEAM: root clippy.toml lands with this change (#748 worker scope) and is
# cross-checked both directions by _audit_process_lint_config: every
# PROCESS_LINT_METHODS path must be configured and no unsupported path may
# be listed (method paths only -- raw extern APIs stay oracle-owned per the
# probe). Exception records below carry exact item/cfg/operation/class
# fields so the clippy.toml per-item expectations mirror them 1:1. While
# the file is absent, an explicit AUDIT_SIGNAL is emitted instead of
# claiming lint coverage. Unknown parse/attribution state fails explicitly
# via `process_attribution_unknown`, never empty-success.
#
# Second pinned-toolchain probe (clippy 0.1.97, default lint levels, no
# [lints] overrides, scratch workspace outside the repo): all eight
# std/tokio new/spawn/output/status paths fire, including through `as`
# aliases; a nested member two levels below clippy.toml fires (upward
# discovery); tokio entries are inert -- not errors -- in crates without a
# tokio dependency; item-level #[allow(clippy::disallowed_methods)]
# suppresses. The lint therefore activates on landing at default levels;
# full `-D warnings` clearance awaits the controller-owned item annotations.
PROCESS_LINT_METHODS = (
    "std::process::Command::new",
    "std::process::Command::spawn",
    "std::process::Command::output",
    "std::process::Command::status",
    "tokio::process::Command::new",
    "tokio::process::Command::spawn",
    "tokio::process::Command::output",
    "tokio::process::Command::status",
)

RAW_PROCESS_PATTERNS = (
    ("raw-launch", re.compile(r"\bCreateProcess[AW]?\s*\(")),
    ("raw-launch", re.compile(r"\bShellExecute(Ex)?[AW]?\s*\(")),
)

# Optional narrow fields on a direct_process_launch tracked_debt record. A
# record without them keeps exact-path semantics; a record with them additionally
# requires every launch site in the file to match. Unknown fields are rejected
# by validate_policy -- new policy meaning is never silently ignored.
PROCESS_EXCEPTION_OPERATIONS = ("construct", "raw-launch")
PROCESS_EXCEPTION_CLASSES = ("executor", "bootstrap", "platform", "build", "test")

_CFG_ATTR_PATTERN = re.compile(r"#\s*\[\s*cfg\s*\((?P<body>[^\]]*)\)\s*\]")
_TEST_ATTR_PATTERN = re.compile(r"#\s*\[\s*(?P<kind>test|tokio::test)\s*(\([^]]*\))?\s*\]")
_FN_PATTERN = re.compile(
    r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:unsafe\s+)?(?:async\s+)?fn\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_MOD_PATTERN = re.compile(
    r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*[{;]"
)
_USE_ALIAS_PATTERN = re.compile(
    r"^\s*use\s+(?P<base>std\s*::\s*process|tokio\s*::\s*process)\s*::\s*"
    r"(?:\{(?P<group>[^}]*)\}|(?P<single>[A-Za-z_][A-Za-z0-9_]*)(?:\s+as\s+(?P<alias>[A-Za-z_][A-Za-z0-9_]*))?)"
    r"\s*;"
)
_USE_MODULE_PATTERN = re.compile(
    r"^\s*use\s+(?P<base>std\s*::\s*process|tokio\s*::\s*process)\s*;"
)
_FOREIGN_COMMAND_IMPORT = re.compile(r"^\s*use\s+(?!std\s*::\s*process|tokio\s*::\s*process)\S*\bCommand\b")


@dataclass(frozen=True)
class ProcessLaunchSite:
    line: int
    kind: str  # "construct" (std/tokio Command::new) or "raw-launch" (Win32 API)
    item: str | None  # enclosing fn name, None when unattributable/file scope
    is_test: bool
    cfg_tokens: tuple[str, ...]
    text: str


def _strip_rust_noise(content: str) -> tuple[str, bool]:
    """Blank comments/strings/chars with spaces, preserving newlines/offsets.

    Returns (cleaned, unterminated) where unterminated is True when a block
    comment, string, char or raw string never closes. Callers must treat
    unterminated state as explicit unknown, never as clean.
    """
    out = list(content)
    i = 0
    n = len(content)
    unterminated = False

    def blank(start: int, end: int) -> None:
        for k in range(start, end):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        two = content[i : i + 2]
        if two == "//":
            end = content.find("\n", i)
            if end == -1:
                end = n
            blank(i, end)
            i = end
        elif two == "/*":
            depth = 0
            j = i
            while j < n:
                if content[j : j + 2] == "/*":
                    depth += 1
                    j += 2
                elif content[j : j + 2] == "*/":
                    depth -= 1
                    j += 2
                    if depth == 0:
                        break
                else:
                    j += 1
            if depth != 0:
                unterminated = True
                blank(i, n)
                i = n
            else:
                blank(i, j)
                i = j
        elif content[i] == '"':
            j = i + 1
            closed = False
            # Plain strings may span physical lines (rustc accepts raw
            # newlines inside "...", and backslash+newline is a continuation
            # escape); only EOF without a closing quote is unterminated.
            # Treating a raw newline as failure wiped the rest of
            # crates/eliot-engine/src/host.rs and hid its real launch.
            while j < n:
                if content[j] == "\\":
                    j += 2
                elif content[j] == '"':
                    closed = True
                    j += 1
                    break
                else:
                    j += 1
            if not closed:
                unterminated = True
                blank(i, n)
                i = n
            else:
                blank(i, j)
                i = j
        elif content[i] == "r" and i + 1 < n and content[i + 1] in ("#", '"'):
            j = i + 1
            hashes = 0
            while j < n and content[j] == "#":
                hashes += 1
                j += 1
            if j < n and content[j] == '"':
                j += 1
                closer = '"' + "#" * hashes
                end = content.find(closer, j)
                if end == -1:
                    unterminated = True
                    blank(i, n)
                    i = n
                else:
                    blank(i, end + len(closer))
                    i = end + len(closer)
            else:
                i += 1
        elif content[i] == "'":
            # Char literal `'x'`/`'\n'` vs lifetime `'a`: only blank the
            # closed-on-one-line char shape; lifetimes are left intact.
            end = content.find("\n", i)
            if end == -1:
                end = n
            segment = content[i:end]
            match = re.match(r"'(?:\\.|[^'\\])'", segment)
            if match:
                blank(i, i + len(match.group(0)))
                i += len(match.group(0))
            else:
                i += 1
        else:
            i += 1
    return "".join(out), unterminated


def _cfg_tokens(body: str) -> tuple[str, ...]:
    return tuple(sorted(set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", body))))


def _discover_process_launch_sites(
    content: str,
) -> tuple[list[ProcessLaunchSite], bool]:
    """Find std/tokio constructor + raw Win32 launch sites with item attribution.

    Returns (sites, attribution_ok). attribution_ok is False when the cleaned
    source has unbalanced braces or unterminated literals, meaning per-site
    item/cfg claims are UNKNOWN and must fail explicitly downstream.
    """
    cleaned, unterminated = _strip_rust_noise(content)
    lines = cleaned.splitlines()
    raw_lines = content.splitlines()

    ctor_aliases: set[str] = set()
    module_bases: set[str] = set()  # {"std", "tokio"} when `use X::process;`
    foreign_command = False
    for line in lines:
        alias_match = _USE_ALIAS_PATTERN.match(line)
        if alias_match is not None:
            group = alias_match.group("group")
            if group is not None:
                for member in group.split(","):
                    member = member.strip()
                    if not member or member.startswith("self"):
                        continue
                    parts = re.split(r"\s+as\s+", member)
                    name = parts[-1].strip()
                    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                        ctor_aliases.add(name)
            else:
                single = alias_match.group("single")
                alias = alias_match.group("alias")
                ctor_aliases.add(alias or single)
            continue
        module_match = _USE_MODULE_PATTERN.match(line)
        if module_match is not None:
            base = "std" if module_match.group("base").startswith("std") else "tokio"
            module_bases.add(base)
            continue
        if _FOREIGN_COMMAND_IMPORT.match(line) is not None:
            foreign_command = True

    # Join multi-line attributes so `#[allow(..., reason = "...")]` shapes do
    # not desynchronize the pending-attribute buffer.
    logical: list[tuple[int, str]] = []
    index = 0
    while index < len(lines):
        lineno = index + 1
        text = lines[index]
        stripped = text.strip()
        if stripped.startswith("#[") and "]" not in stripped:
            merged = [text]
            while "]" not in lines[index] and index + 1 < len(lines):
                index += 1
                merged.append(lines[index])
            logical.append((lineno, " ".join(part.strip() for part in merged)))
        else:
            logical.append((lineno, text))
        index += 1

    sites: list[ProcessLaunchSite] = []
    attribution_ok = not unterminated
    # Stack frames: [kind, name, depth_at_entry, cfg_test, test_attr, cfg_tokens]
    stack: list[list[Any]] = []
    pending_cfg_test = False
    pending_test_attr = False
    pending_cfg_tokens: tuple[str, ...] = ()
    pending_entry: tuple[str, str | None, bool, bool, tuple[str, ...]] | None = None
    crate_tokens: tuple[str, ...] = ()
    crate_test = False
    depth = 0

    ctor_name_pattern = (
        r"(?:std\s*::\s*process\s*::\s*Command|tokio\s*::\s*process\s*::\s*Command"
        + ("".join(rf"|{re.escape(name)}" for name in sorted(ctor_aliases)) if ctor_aliases else "")
        + ")"
    )
    ctor_pattern = re.compile(rf"\b(?:{ctor_name_pattern})\s*::\s*new\b")

    for lineno, line in logical:
        stripped = line.strip()
        code = stripped
        if stripped.startswith("#"):
            is_crate_attr = stripped.startswith("#![")
            for attr in _CFG_ATTR_PATTERN.finditer(line):
                body = attr.group("body")
                tokens = _cfg_tokens(body)
                if is_crate_attr:
                    crate_tokens = tuple(sorted(set(crate_tokens) | set(tokens)))
                    if re.search(r"\btest\b", body):
                        crate_test = True
                else:
                    pending_cfg_tokens = tuple(
                        sorted(set(pending_cfg_tokens) | set(tokens))
                    )
                    if re.search(r"\btest\b", body):
                        pending_cfg_test = True
            if _TEST_ATTR_PATTERN.search(line):
                if is_crate_attr:
                    crate_test = True
                else:
                    pending_test_attr = True
            # Strip leading attribute segments so same-line items
            # (`#[cfg(test)] fn foo() {`) still register their frame.
            rest = stripped
            while True:
                seg = re.match(r"^#\s*!\s*\[", rest) or re.match(r"^#\s*\[", rest)
                if seg is None:
                    break
                depth_scan = 0
                pos = seg.end() - 1
                while pos < len(rest):
                    if rest[pos] == "[":
                        depth_scan += 1
                    elif rest[pos] == "]":
                        depth_scan -= 1
                        if depth_scan == 0:
                            break
                    pos += 1
                rest = rest[pos + 1 :].strip() if pos < len(rest) else ""
            code = rest
            if not code:
                continue

        frame_cfg_test = pending_cfg_test
        frame_test_attr = pending_test_attr
        frame_tokens = pending_cfg_tokens
        pending_cfg_test = False
        pending_test_attr = False
        pending_cfg_tokens = ()

        fn_match = _FN_PATTERN.match(code)
        mod_match = _MOD_PATTERN.match(code)
        is_impl = mod_match is None and fn_match is None and re.match(r"^\s*impl\b", code)
        entry_kind: str | None = None
        entry_name: str | None = None
        if fn_match is not None:
            entry_kind, entry_name = "fn", fn_match.group("name")
        elif mod_match is not None:
            entry_kind, entry_name = "mod", mod_match.group("name")
        elif is_impl:
            entry_kind, entry_name = "impl", None

        opens = line.count("{") - line.count("}")
        if entry_kind is not None:
            if "{" in line:
                stack.append(
                    [entry_kind, entry_name, depth, frame_cfg_test, frame_test_attr, frame_tokens]
                )
                pending_entry = None
            elif ";" not in line:
                # Multiline signature: carry the entry until its `{`; a `;`
                # (declaration without body) cancels it instead.
                pending_entry = (entry_kind, entry_name, frame_cfg_test, frame_test_attr, frame_tokens)
            else:
                pending_entry = None
        elif pending_entry is not None:
            if "{" in line:
                kind, name, cfg_test, test_attr, tokens = pending_entry
                stack.append([kind, name, depth, cfg_test, test_attr, tokens])
                pending_entry = None
            if ";" in line:
                pending_entry = None
        depth += opens
        if depth < 0:
            attribution_ok = False
            depth = 0
        while stack and depth <= stack[-1][2]:
            stack.pop()

        enclosing_fn: str | None = None
        site_test = crate_test
        site_tokens: set[str] = set(crate_tokens)
        for frame in stack:
            if frame[0] == "fn" and enclosing_fn is None:
                enclosing_fn = frame[1]
            if frame[3] or frame[4]:
                site_test = True
            site_tokens.update(frame[5])

        text_sites: list[tuple[str, int]] = []
        if ctor_pattern.search(line):
            # A bare `Command::new` is ambiguous when another crate's Command
            # is also imported (e.g. clap); only claim it when std/tokio is
            # the sole Command source, otherwise leave it to the compiler lint.
            bare_only = (
                re.search(r"(?<![:\w])Command\s*::\s*new\b", line) is not None
                and "std" not in line
                and "tokio" not in line
            )
            if not (bare_only and foreign_command):
                text_sites.append(("construct", line.find("new")))
        for base in sorted(module_bases):
            if re.search(rf"\b{base}\s*::\s*process\s*::\s*Command\s*::\s*new\b", line):
                text_sites.append(("construct", 0))
                break
        for kind, pattern in RAW_PROCESS_PATTERNS:
            match = pattern.search(line)
            if match is not None:
                text_sites.append((kind, match.start()))

        for kind, _ in text_sites:
            raw_text = raw_lines[lineno - 1].strip() if lineno - 1 < len(raw_lines) else ""
            sites.append(
                ProcessLaunchSite(
                    line=lineno,
                    kind=kind,
                    item=enclosing_fn,
                    is_test=site_test,
                    cfg_tokens=tuple(sorted(site_tokens)),
                    text=raw_text[:160],
                )
            )

    if depth != 0:
        attribution_ok = False
    return sites, attribution_ok


# --- Typed dependency evidence (#2614) ---
#
# Every Cargo declaration is retained as a DependencyEdge. Two declarations of
# the same package under different kinds/conditions stay distinct edges; they
# are never collapsed into a set of names. Target conditions are preserved
# verbatim and never evaluated here: cfg/feature resolution belongs to Cargo's
# resolver (see verify-dependency-policy.py), not to regex in this scanner.

DEPENDENCY_SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")

DEPENDENCY_KIND_BY_SECTION = {
    "dependencies": "normal",
    "dev-dependencies": "dev",
    "build-dependencies": "build",
}

_KIND_ORDER = {"normal": 0, "dev": 1, "build": 2}

# Declaration-resolution states. A declaration reaches RESOLVER_SELECTED only
# when the locked resolver bound it; every other state is explicit incomplete
# evidence, never a silent drop and never an arbitrary identity guess.
RESOLUTION_DIRECT = "direct"
RESOLUTION_WORKSPACE_INHERITED = "workspace-inherited"
RESOLUTION_RESOLVER_SELECTED = "resolver-selected"
RESOLUTION_UNRESOLVED_WORKSPACE = "unresolved-workspace"
RESOLUTION_UNSUPPORTED_DECLARATION = "unsupported-declaration"
RESOLUTION_DEGRADED_METADATA = "degraded-metadata"
RESOLUTION_UNRESOLVED_EXTERNAL = "unresolved-external"
RESOLUTION_UNRESOLVED_NOT_IN_GRAPH = "unresolved-not-in-graph"

# Source-side declaration states: the identity of the declaration is known, so
# the declaration itself is interpretable. Whether the locked resolver SELECTED
# it for this triple/feature set is a separate question answered by
# _edge_resolved_in.
_SOURCE_RESOLVED_EDGE = (RESOLUTION_DIRECT, RESOLUTION_WORKSPACE_INHERITED)

# Target-condition applicability as decided by the locked resolver. There is no
# regex cfg evaluation anywhere in this module: when no resolver ran, target
# applicability stays unresolved instead of being guessed from the expression.
APPLICABLE_YES = "yes"
APPLICABLE_NO = "no"
APPLICABLE_UNRESOLVED = "unresolved"

_RESOLUTION_REASONS = {
    RESOLUTION_UNRESOLVED_WORKSPACE: (
        "workspace=true but no owning [workspace.dependencies] definition"
    ),
    RESOLUTION_UNSUPPORTED_DECLARATION: (
        "unsupported declaration shape or invalid workspace marker"
    ),
    RESOLUTION_DEGRADED_METADATA: (
        "malformed version/feature/flag metadata preserved as declared"
    ),
    RESOLUTION_UNRESOLVED_EXTERNAL: (
        "dependency does not resolve to any package in the selected graph"
    ),
    RESOLUTION_UNRESOLVED_NOT_IN_GRAPH: (
        "declaring package is outside the selected workspace/feature graph"
    ),
}

# Projections. Each names its evidence class explicitly so a reader can never
# confuse a source-wide declaration inventory with resolver-selected runtime
# evidence. A resolver-selected projection without resolver inputs is
# incomplete by construction, never silently unbound (defect 1).
PROFILE_SOURCE_RUNTIME = "source-runtime"
PROFILE_SOURCE_TEST = "source-test"
PROFILE_SOURCE_BUILD = "source-build"
# The host/tooling projection is the one defect 2 requires: it starts in a
# target unit and reports the closure reachable once traversal crosses into a
# proc-macro or build-script unit. Without it, a host closure reached through a
# proc-macro would be invisible, and the same closure relabelled as
# `source-runtime` would be a lie.
PROFILE_SOURCE_HOST_TOOLING = "source-host-tooling"
PROFILE_SOURCE_WIDE = "source-wide"

_SOURCE_PROFILES = (
    PROFILE_SOURCE_RUNTIME,
    PROFILE_SOURCE_TEST,
    PROFILE_SOURCE_BUILD,
    PROFILE_SOURCE_HOST_TOOLING,
    PROFILE_SOURCE_WIDE,
)

# Evidence classes. `source-wide` is the declaration inventory: everything any
# manifest declares, regardless of kind, target, optionality or feature.
# `resolver-selected` is what the locked resolver actually bound for the
# recorded triple and feature selection.
EVIDENCE_SOURCE_WIDE = "source-wide-possible"
EVIDENCE_SELECTED = "resolver-selected"

# Compilation-unit context. A path is only target-runtime evidence while every
# hop stayed in a TARGET compilation unit; crossing a proc-macro or build
# boundary moves the remaining closure into a HOST compilation unit.
UNIT_TARGET_RUNTIME = "target-runtime"
UNIT_HOST_BUILD_SCRIPT = "host-build-script"
UNIT_HOST_PROC_MACRO = "host-proc-macro"
UNIT_TEST = "test"

_HOST_UNIT = (UNIT_HOST_BUILD_SCRIPT, UNIT_HOST_PROC_MACRO)

UNIT_CONTEXTS = (UNIT_TARGET_RUNTIME, UNIT_HOST_BUILD_SCRIPT, UNIT_HOST_PROC_MACRO, UNIT_TEST)

_UNIT_EXECUTED_ON = {
    UNIT_TARGET_RUNTIME: "target",
    UNIT_HOST_BUILD_SCRIPT: "host",
    UNIT_HOST_PROC_MACRO: "host",
    UNIT_TEST: "host",
}

# How a projection may change a compilation unit across one edge.
TRANSITION_RUNTIME_STAYS_RUNTIME = "runtime-stays-runtime"
TRANSITION_RUNTIME_TO_HOST_PROC_MACRO = "runtime-to-host-proc-macro"
TRANSITION_RUNTIME_TO_HOST_BUILD = "runtime-to-host-build-script"
TRANSITION_HOST_STAYS_HOST = "host-stays-host"
TRANSITION_ROOT_TO_TEST_UNIT = "root-to-test-unit"
TRANSITION_HOST_TO_TEST_UNIT = "host-to-test-unit"
TRANSITION_TEST_STAYS_TEST = "test-stays-test"
TRANSITION_REJECTED = "rejected"

# Bounded `cargo metadata` projection. The invocation is fixed and offline; only
# the triple and the optional cached JSON path vary.
_METADATA_TIMEOUT_SECONDS = 300
_METADATA_MAX_BYTES = 512 * 1024 * 1024
_METADATA_ARGS = (
    "metadata",
    "--locked",
    "--offline",
    "--format-version",
    "1",
    "--all-features",
)
_METADATA_ARGS_NO_FEATURES = (
    "metadata",
    "--locked",
    "--offline",
    "--format-version",
    "1",
)
_DEFAULT_METADATA_SOURCE = "locked-offline-all-features"
METADATA_SOURCE_CACHED = "cached-locked-offline-all-features"
METADATA_SOURCE_ABSENT = "absent"
METADATA_SOURCE_UNPARSEABLE = "unparseable"
METADATA_SOURCE_ERROR = "error"



def _normalise_path_key(value: str) -> str:
    return value.replace("\\", "/").rstrip("/").casefold()


def _normalise_repo_key(value: str, root: Path) -> str:
    try:
        relative = Path(value).resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return _normalise_path_key(value)
    return relative.as_posix()


# Bounded traversal so one hostile or cyclic graph cannot hang the audit.
_TYPED_PATH_MAX_HOPS = 64
_TYPED_PATH_MAX_NODES = 4096

_RUNTIME_ROOT_KNOWN_KEYS = frozenset(
    {"package", "issue", "forbidden_exact", "forbidden_prefix"}
)

# Completeness is derived, never asserted. Every witness reports the exact
# reason it is not complete.
COMPLETENESS_SELECTED = "resolver-selected-complete"
COMPLETENESS_SELECTED_INCOMPLETE = "resolver-selected-incomplete"
COMPLETENESS_SOURCE_ONLY = "source-only-incomplete"

_COMPLETENESS_REASONS = {
    RESOLUTION_UNRESOLVED_WORKSPACE: "unresolved-workspace-declaration",
    RESOLUTION_UNSUPPORTED_DECLARATION: "unsupported-declaration",
    RESOLUTION_DEGRADED_METADATA: "degraded-declaration-metadata",
    RESOLUTION_UNRESOLVED_EXTERNAL: "externally-resolved-dependency",
    RESOLUTION_UNRESOLVED_NOT_IN_GRAPH: "declaring-package-outside-selected-graph",
}


def _edge_resolved_in(resolution: str, source: ResolverProjection, edge: DependencyEdge) -> str:
    """Upgrade a source-resolved declaration when the locked resolver bound it.

    This is the resolution-awareness mechanism: an edge is selected evidence
    only when the resolver agrees with the declaration for its exact (crate name,
    kind) pair. When no resolver projection is bound, the source resolution is
    kept and the descriptor reports the missing metadata, so no witness can claim
    selected scope.
    """
    if resolution not in _SOURCE_RESOLVED_EDGE:
        return resolution
    if source.bound and source.selects(edge.manifest, edge.crate_name, edge.kind):
        return RESOLUTION_RESOLVER_SELECTED
    return resolution



@dataclass(frozen=True)
class ResolverProjection:
    """The ONE accepted bounded resolver input, threaded into every witness.

    `bound` is the honesty gate: when it is False nothing may be described as
    resolver-selected, because no resolver ran. When it is True the descriptor
    reports exactly which invocation produced the graph, under which triple,
    feature selection, resolver version, toolchain and source identity.
    """

    bound: bool = False
    source: str = METADATA_SOURCE_ABSENT
    detail: str = "no locked offline cargo metadata projection was requested"
    root_target: str = "unbound"
    host_triple: str = "unbound"
    target_triple: str = "unbound"
    feature_selection: str = "unbound"
    resolver: str = "unbound"
    toolchain: str = "unbound"
    invocation: tuple[str, ...] = ()
    metadata_version: int | None = None
    source_identity: str = "unbound"
    workspace_root: str = "unbound"
    digest: str = "unbound"
    workspace_resolver: str = "unbound"
    packages_total: int = 0
    workspace_members: int = 0
    workspace_roots: tuple[str, ...] = ()
    # manifest path (repo-relative, forward slashes) -> package name
    members_by_manifest: dict[str, str] = field(default_factory=dict)
    # manifest path -> frozenset of "crate_name|kind" pairs the resolver selected
    selected_deps: dict[str, frozenset[str]] = field(default_factory=dict)
    # package name -> True when some target in the resolved graph is proc-macro
    proc_macro_packages: frozenset[str] = frozenset()
    # package name -> owning manifest path (repo-relative) when known
    package_manifest: dict[str, str] = field(default_factory=dict)

    def selects(self, manifest: str, crate_name: str, kind: str) -> bool:
        """Exact (crate name, kind) join against the locked resolver graph."""
        return f"{crate_name}|{kind}" in self.selected_deps.get(manifest, frozenset())

    def descriptor(self) -> dict[str, Any]:
        return {
            "name": "resolver-projection",
            "source": self.source,
            "detail": self.detail,
            "root_target": self.root_target,
            "host_triple": self.host_triple,
            "target_triple": self.target_triple,
            "feature_selection": self.feature_selection,
            "resolver": self.resolver,
            "workspace_resolver": self.workspace_resolver,
            "toolchain": self.toolchain,
            "metadata": self.source,
            "source_identity": self.source_identity,
            "workspace_root": self.workspace_root,
            "invocation": list(self.invocation),
            "metadata_version": self.metadata_version,
            "digest": self.digest,
            "packages_total": self.packages_total,
            "workspace_members": self.workspace_members,
            "workspace_roots": list(self.workspace_roots),
        }


@dataclass(frozen=True)
class DependencyEdge:
    """One Cargo dependency declaration with its kind and target intact."""

    consumer: str
    manifest: str
    section: str
    alias: str
    package: str
    crate_name: str
    kind: str
    target: str
    version: str | None
    path: str | None
    source: str
    optional: bool
    default_features: bool
    inherited_features: tuple[str, ...]
    member_features: tuple[str, ...]
    features: tuple[str, ...]
    resolution: str
    # Target-condition applicability decided by the locked resolver (or
    # unresolved when no resolver ran). This is never a regex guess.
    applicable: str = APPLICABLE_UNRESOLVED

    @property
    def resolved(self) -> bool:
        return self.resolution == RESOLUTION_RESOLVER_SELECTED

    def enters_host_closure(
        self, manifests: dict[str, "Manifest"], projection: ResolverProjection
    ) -> bool:
        """True when crossing this edge leaves target-runtime compilation.

        A proc-macro is a host artifact even when declared `normal`: rustc loads
        it on the host to expand macros, so its own closure is host/tooling code
        and never target runtime. A `build` edge compiles and runs on the host
        too. Proc-macro identity comes from the declaring manifest when it is
        in-tree and from the bound resolver projection otherwise -- never from
        the dependency kind, which says nothing about the unit.
        """
        if self.kind == "build":
            return True
        if self.kind == "dev":
            return False
        target = manifests.get(self.package)
        if target is not None and target.proc_macro:
            return True
        if target is None and projection.bound:
            return self.package in projection.proc_macro_packages
        return False



@dataclass(frozen=True)
class TraversalFrontier:
    """Complete, retained evidence for one bounded search (defect 5).

    Every counter is reported with the witness it belongs to, so a reader never
    has to infer a denominator from the root manifest alone, and a search that
    ran out of bounds says so instead of returning no finding.
    """

    root: str
    profile: str
    # Denominator: the searched graph, not just the root manifest.
    graph_nodes_available: int
    root_declared_edges: int
    selected_edges: int
    conditional_edges: int
    # Work actually performed.
    visited_nodes: int
    expanded_nodes: int
    selected_edges_visited: int
    # Frontiers that stopped traversal.
    unresolved_frontier: int
    unresolved_packages: tuple[str, ...]
    external_frontier: int
    ambiguous_frontier: int
    not_in_graph_frontier: int
    # Bounds and whether they were hit.
    truncated: bool
    truncated_at_hop_bound: int
    truncated_at_node_bound: int
    max_hops: int
    max_nodes: int
    found: bool

    @property
    def exhausted(self) -> bool:
        return not self.found and self.truncated

    def evidence(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "profile": self.profile,
            "denominator": {
                "graph_nodes_available": self.graph_nodes_available,
                "root_declared_edges": self.root_declared_edges,
                "selected_edges": self.selected_edges,
                "conditional_edges": self.conditional_edges,
            },
            "work": {
                "visited_nodes": self.visited_nodes,
                "expanded_nodes": self.expanded_nodes,
                "selected_edges_visited": self.selected_edges_visited,
            },
            "frontiers": {
                "unresolved": self.unresolved_frontier,
                "unresolved_packages": list(self.unresolved_packages),
                "external": self.external_frontier,
                "ambiguous": self.ambiguous_frontier,
                "not_in_selected_graph": self.not_in_graph_frontier,
            },
            "bounds": {
                "max_hops": self.max_hops,
                "max_nodes": self.max_nodes,
                "truncated": self.truncated,
                "truncated_at_hop_bound": self.truncated_at_hop_bound,
                "truncated_at_node_bound": self.truncated_at_node_bound,
            },
            "found": self.found,
            "exhausted": self.exhausted,
        }


@dataclass(frozen=True)
class TypedPath:
    """One ordered edge path plus the context that qualifies it."""

    edges: tuple[DependencyEdge, ...]
    conditional_hops: tuple[int, ...]
    host_hops: tuple[int, ...]
    truncated: bool
    # Compilation-unit context of every hop, and the context of the unit the
    # path terminates in. A path is target-runtime evidence only when the
    # terminal unit is a target unit.
    unit_contexts: tuple[str, ...] = ()
    terminal_unit: str = UNIT_TARGET_RUNTIME
    # Traversal frontier for this exact path: what was selected, what stopped
    # traversal and why. Retained rather than discarded (defect 5).
    frontier: "TraversalFrontier | None" = None


@dataclass(frozen=True)
class Manifest:
    name: str
    path: str
    # Source-wide declared-name projection (compatibility only; never a
    # runtime claim -- runtime/test/build evidence uses dependency_edges).
    dependencies: tuple[str, ...]
    dependency_edges: tuple[DependencyEdge, ...] = ()
    proc_macro: bool = False
    # Workspace membership as Cargo itself reports it. Cargo-equivalent
    # workspace-inheritance resolution reads this, never the filesystem layout.
    workspace_member: bool = False
    # Manifest directory of an owning [workspace] table when that manifest
    # declares one, or None. Used ONLY by an explicit [package].workspace
    # pointer, never by ancestor guessing.
    own_workspace_dir: str | None = None


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    path: str
    package: str | None
    detail: str
    issue: int | None = None
    removal_condition: str | None = None
    witness: dict[str, Any] | None = None


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _walk(root: Path, filename: str | None = None) -> Iterable[Path]:
    for current, dirs, files in os.walk(root):
        dirs[:] = [directory for directory in dirs if directory not in SKIP_DIRS]
        base = Path(current)
        for file_name in files:
            if filename is None or file_name == filename:
                yield base / file_name


# --- The one accepted resolver projection (defect 1) ---
#
# A single bounded, offline, locked `cargo metadata` invocation is the only
# resolver input this audit accepts. It binds the root target, the host and
# target triples, the requested feature selection, the resolver version, the
# toolchain, the source identity and the resolved package graph. When it cannot
# be obtained, the descriptor records exactly that and every completeness value
# stays incomplete -- it never degrades into a silent "unbound" that is then
# described as selected runtime evidence.
#
# There is deliberately no regex cfg/feature evaluation anywhere: target
# applicability is whatever the resolver reported for this triple, or unresolved
# when no resolver ran.


def _metadata_command(
    root: Path, target_triple: str, *, features: bool = True, frozen: bool = True
) -> tuple[str, ...]:
    argv = ["cargo", *(_METADATA_ARGS if features else _METADATA_ARGS_NO_FEATURES)]
    if frozen:
        argv.append("--frozen")
    argv.extend(("--manifest-path", (root / "Cargo.toml").as_posix()))
    argv.extend(("--filter-platform", target_triple))
    return tuple(argv)


def _run_metadata(root: Path, argv: tuple[str, ...]) -> bytes | None:
    """Run the fixed offline invocation. Returns stdout, or None on any failure."""
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            list(argv),
            cwd=root,
            capture_output=True,
            timeout=_METADATA_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    stdout = completed.stdout or b""
    if len(stdout) > _METADATA_MAX_BYTES:
        return None
    return stdout


def _workspace_resolver_version(root: Path) -> str:
    """Cargo's declared resolver for the root manifest, read from the manifest."""
    try:
        data = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return "unbound"
    workspace = data.get("workspace")
    resolver = workspace.get("resolver") if isinstance(workspace, dict) else None
    if isinstance(resolver, str) and resolver.strip():
        return f"cargo-resolver-{resolver.strip()}"
    # Edition 2021+ defaults to resolver 2 when the manifest omits it.
    package = data.get("package")
    edition = package.get("edition") if isinstance(package, dict) else None
    if isinstance(edition, str) and edition.strip() >= "2021":
        return "cargo-resolver-2(default)"
    return "cargo-resolver-1(default)"


def _read_toolchain(root: Path) -> str:
    """Pinned toolchain channel when the repository declares one."""
    for name in ("rust-toolchain.toml", "rust-toolchain"):
        path = root / name
        if not path.is_file():
            continue
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError):
            return "unreadable"
        channel = data.get("channel") if isinstance(data.get("toolchain"), dict) else None
        if isinstance(channel, str) and channel.strip():
            return channel.strip()
    return "unbound"


def _host_triple() -> str:
    """Host triple from the local rustc, falling back to the platform triple.

    This is a fact about the machine the audit runs on, not about the audited
    repository, so it is recorded as provenance in the descriptor and a failure
    to read it is reported rather than silently defaulted.
    """
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["rustc", "-vV"], capture_output=True, timeout=60
        )
    except (OSError, subprocess.SubprocessError):
        return "unbound"
    if completed.returncode != 0:
        return "unbound"
    for line in (completed.stdout or b"").decode("utf-8", errors="replace").splitlines():
        if line.startswith("host: "):
            return line.split(":", 1)[1].strip() or "unbound"
    return "unbound"


def _identity_digest(manifest_path: str, lock_path: Path) -> str:
    """Stable identity of the inputs that produced a projection."""
    parts: list[str] = []
    for candidate in (manifest_path, str(lock_path)):
        try:
            parts.append(hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:12])
        except (OSError, UnicodeError):
            parts.append("unreadable")
    lock_digest = "no-lockfile"
    try:
        lock_digest = hashlib.sha256(lock_path.read_bytes()).hexdigest()[:12]
    except (OSError, UnicodeError):
        pass
    return f"manifest:{parts[0] if parts else 'unbound'} lock:{lock_digest}"


def _projection_from_metadata(
    root: Path, payload: dict[str, Any], *, source: str, invocation: tuple[str, ...]
) -> ResolverProjection:
    """Build a bound ResolverProjection from a parsed cargo metadata payload."""
    workspace_root = payload.get("workspace_root")
    workspace_root_text = (
        workspace_root if isinstance(workspace_root, str) else "unbound"
    )
    member_ids = {
        value
        for value in payload.get("workspace_members", [])
        if isinstance(value, str)
    }
    members_by_manifest: dict[str, str] = {}
    package_manifest: dict[str, str] = {}
    proc_macro_packages: set[str] = set()
    packages_total = 0
    for package in payload.get("packages", []):
        if not isinstance(package, dict):
            continue
        packages_total += 1
        name = package.get("name")
        if not isinstance(name, str):
            continue
        manifest_path = package.get("manifest_path")
        targets = package.get("targets")
        if isinstance(targets, list):
            for target in targets:
                if isinstance(target, dict) and "proc-macro" in (
                    target.get("kind") or []
                ):
                    proc_macro_packages.add(name)
                    break
        if not isinstance(manifest_path, str):
            continue
        key = _normalise_repo_key(manifest_path, root)
        package_manifest.setdefault(name, key)
        identifier = package.get("id")
        if isinstance(identifier, str) and identifier in member_ids:
            members_by_manifest[key] = name

    selected_deps: dict[str, frozenset[str]] = {}
    resolve = payload.get("resolve")
    nodes = resolve.get("nodes") if isinstance(resolve, dict) else None
    if isinstance(nodes, list):
        id_to_manifest = {
            package.get("id"): _normalise_repo_key(str(package.get("manifest_path")), root)
            for package in payload.get("packages", [])
            if isinstance(package, dict)
            and isinstance(package.get("manifest_path"), str)
        }
        for node in nodes:
            if not isinstance(node, dict):
                continue
            identifier = node.get("id")
            owner = id_to_manifest.get(identifier)
            if owner is None:
                continue
            selected: set[str] = set()
            deps = node.get("deps")
            if isinstance(deps, list):
                for dep in deps:
                    if not isinstance(dep, dict):
                        continue
                    dep_name = dep.get("name")
                    if not isinstance(dep_name, str):
                        continue
                    dep_kinds = dep.get("dep_kinds")
                    kinds = dep_kinds if isinstance(dep_kinds, list) else []
                    for dep_kind in kinds:
                        kind = (
                            dep_kind.get("kind")
                            if isinstance(dep_kind, dict)
                            else None
                        )
                        selected.add(
                            f"{dep_name}|{kind if isinstance(kind, str) else 'normal'}"
                        )
            selected_deps[owner] = frozenset(selected)

    # Cargo does not report an owning `workspace_root` per package (the field is
    # absent/null in `cargo metadata` output), so ownership comes from the ONE
    # workspace this invocation resolved: the repository root, keyed by the empty
    # string, which is exactly how `_workspace_tables` stores a root `[workspace]`
    # table. Deriving the set from each member's own parent directory -- which is
    # what this did before -- made every member directory a "root", so the
    # ancestor lookup could never reach the real workspace table and every
    # `workspace = true` dependency was reported unresolved. A nested standalone
    # workspace supplies its own `[workspace]` table, which the lookup in
    # `_inheritable_workspace_dependencies` already prefers over this root.
    workspace_roots: tuple[str, ...] = ("",)
    lock_path = root / "Cargo.lock"
    return ResolverProjection(
        bound=True,
        source=source,
        detail=(
            "locked offline cargo metadata with the workspace root target; "
            "no network access and no unlocked resolution"
        ),
        root_target=_normalise_repo_key(workspace_root_text, root)
        if workspace_root_text != "unbound"
        else "unbound",
        host_triple=_host_triple(),
        target_triple=(
            invocation[invocation.index("--filter-platform") + 1]
            if "--filter-platform" in invocation
            else "unbound"
        ),
        feature_selection="all-features",
        resolver=(
            f"cargo-metadata-format-v{payload.get('version')}"
            if isinstance(payload.get("version"), int)
            else "cargo-metadata"
        ),
        workspace_resolver=_workspace_resolver_version(root),
        toolchain=_read_toolchain(root),
        invocation=invocation,
        metadata_version=payload.get("version")
        if isinstance(payload.get("version"), int)
        else None,
        source_identity=_identity_digest(
            (root / "Cargo.toml").as_posix(), lock_path
        ),
        workspace_root=_normalise_repo_key(workspace_root_text, root)
        if workspace_root_text != "unbound"
        else "unbound",
        digest=_identity_digest(
            (root / "Cargo.toml").as_posix(), lock_path
        ),
        workspace_members=len(members_by_manifest),
        workspace_roots=workspace_roots,
        packages_total=packages_total,
        members_by_manifest=members_by_manifest,
        selected_deps=selected_deps,
        proc_macro_packages=frozenset(proc_macro_packages),
        package_manifest=dict(package_manifest),
    )


def load_resolver_projection(
    root: Path,
    *,
    target_triple: str | None = None,
    metadata_cache: Path | None = None,
    allow_run: bool = True,
) -> ResolverProjection:
    """Obtain the one accepted resolver projection, or report why it is absent.

    Resolution order, all offline and all locked:
      1. a caller-supplied cached `cargo metadata` JSON projection;
      2. the fixed locked offline invocation against the repository root.

    Anything else -- cargo missing, a non-zero exit, an unparseable payload --
    returns an UNBOUND projection whose detail says so. There is no third path
    that produces a "clean pass".
    """
    if target_triple:
        host = _host_triple()
        unbound = ResolverProjection(
            bound=False,
            source=METADATA_SOURCE_ABSENT,
            detail="an explicit target triple was requested but no resolver ran",
            target_triple=target_triple,
            host_triple=host,
        )
    else:
        unbound = ResolverProjection(bound=False)

    if metadata_cache is not None:
        if not metadata_cache.is_file():
            return replace(
                unbound,
                source=METADATA_SOURCE_ERROR,
                detail=(
                    "the requested cargo metadata cache "
                    f"{metadata_cache.as_posix()} does not exist"
                ),
            )
        try:
            payload = json.loads(metadata_cache.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError) as error:
            return replace(
                unbound,
                source=METADATA_SOURCE_UNPARSEABLE,
                detail=f"the cargo metadata cache cannot be parsed: {error}",
            )
        if not isinstance(payload, dict):
            return replace(
                unbound,
                source=METADATA_SOURCE_UNPARSEABLE,
                detail="the cargo metadata cache is not a JSON object",
            )
        return _projection_from_metadata(
            root,
            payload,
            source=METADATA_SOURCE_CACHED,
            invocation=("cache", metadata_cache.as_posix()),
        )

    if not allow_run:
        return replace(
            unbound,
            detail=(
                "resolver execution was disabled; only the source-wide "
                "declaration inventory is available"
            ),
        )

    argv = _metadata_command(root, target_triple or _host_triple())
    stdout = _run_metadata(root, argv)
    if stdout is None:
        return replace(
            unbound,
            source=METADATA_SOURCE_ERROR,
            detail=(
                "cargo metadata --locked --offline did not produce a projection; "
                "resolver inputs stay unbound and no runtime claim is made"
            ),
        )
    try:
        payload = json.loads(stdout.decode("utf-8", errors="strict"))
    except (ValueError, UnicodeError) as error:
        return replace(
            unbound,
            source=METADATA_SOURCE_UNPARSEABLE,
            detail=f"cargo metadata output is not parseable JSON: {error}",
        )
    return _projection_from_metadata(
        root, payload, source=_DEFAULT_METADATA_SOURCE, invocation=argv
    )


def _dependency_name(key: str, value: Any) -> str:
    if isinstance(value, dict):
        package = value.get("package")
        if isinstance(package, str) and package.strip():
            return package.strip()
    return key.replace("_", "-")


def _collect_dependency_table(table: Any) -> list[str]:
    if not isinstance(table, dict):
        return []
    return [_dependency_name(key, value) for key, value in table.items()]


def _manifest_dependencies(data: dict[str, Any]) -> tuple[str, ...]:
    dependencies: list[str] = []
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        dependencies.extend(_collect_dependency_table(data.get(key)))

    target = data.get("target")
    if isinstance(target, dict):
        for target_table in target.values():
            if not isinstance(target_table, dict):
                continue
            for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                dependencies.extend(_collect_dependency_table(target_table.get(key)))

    return tuple(sorted(set(dependencies)))


def _edge_crate_name(alias: str) -> str:
    return alias.replace("-", "_")


def _edge_order(edge: DependencyEdge) -> tuple[Any, ...]:
    return (
        edge.package.casefold(),
        _KIND_ORDER.get(edge.kind, 9),
        0 if (edge.target == "all" and not edge.optional) else 1,
        edge.alias.casefold(),
        edge.section,
        edge.target.casefold(),
    )


def _resolve_edge_spec(
    alias: str, spec: Any, workspace_dependencies: dict[str, Any]
) -> tuple[Any, list[Any], list[Any], str, bool]:
    """Resolve workspace inheritance with Cargo's additive feature semantics.

    Mirrors the source-side inheritance in verify-dependency-policy.py: member
    features add to (never replace) inherited features, and uninterpretable
    inputs keep an explicit degraded resolution instead of a silent fix.
    """
    if isinstance(spec, dict) and "workspace" in spec:
        if spec.get("workspace") is not True:
            return spec, [], [], RESOLUTION_UNSUPPORTED_DECLARATION, True
        inherited = workspace_dependencies.get(alias)
        if isinstance(inherited, str):
            effective: Any = {"version": inherited}
        elif isinstance(inherited, dict):
            effective = dict(inherited)
        else:
            member_only = spec.get("features", [])
            member_raw = member_only if isinstance(member_only, list) else []
            return spec, [], member_raw, RESOLUTION_UNRESOLVED_WORKSPACE, True
        overrides = {key: value for key, value in spec.items() if key != "workspace"}
        inherited_features = effective.get("features", [])
        member_features = overrides.pop("features", [])
        degraded = False
        if isinstance(inherited_features, list) and isinstance(member_features, list):
            effective["features"] = [*inherited_features, *member_features]
        else:
            degraded = True
            effective["features"] = (
                member_features
                if isinstance(inherited_features, list)
                else inherited_features
            )
        effective.update(overrides)
        resolution = (
            RESOLUTION_DEGRADED_METADATA if degraded else RESOLUTION_WORKSPACE_INHERITED
        )
        inherited_raw = inherited_features if isinstance(inherited_features, list) else []
        member_raw = member_features if isinstance(member_features, list) else []
        return effective, inherited_raw, member_raw, resolution, degraded
    if isinstance(spec, str):
        return spec, [], [], RESOLUTION_DIRECT, False
    if isinstance(spec, dict):
        return spec, [], [], RESOLUTION_DIRECT, False
    return spec, [], [], RESOLUTION_UNSUPPORTED_DECLARATION, True


def _normalized_features(raw: Any) -> tuple[tuple[str, ...], bool]:
    if raw is None:
        return (), False
    if isinstance(raw, list):
        clean = tuple(sorted({item for item in raw if isinstance(item, str)}))
        return clean, any(not isinstance(item, str) for item in raw)
    return (), True


def _build_edge(
    *,
    consumer: str,
    manifest: str,
    section: str,
    alias: str,
    target: str,
    spec: Any,
    workspace_dependencies: dict[str, Any],
    projection: ResolverProjection,
) -> DependencyEdge:
    effective, inherited_raw, member_raw, resolution, degraded = _resolve_edge_spec(
        alias, spec, workspace_dependencies
    )
    declared = effective if isinstance(effective, dict) else {}
    if isinstance(spec, dict):
        if resolution == RESOLUTION_DIRECT:
            member_raw = spec.get("features", [])
        elif not member_raw:
            fallback = spec.get("features", [])
            member_raw = fallback if isinstance(fallback, list) else []
    inherited_features, bad_inherited = _normalized_features(inherited_raw)
    member_features, bad_member = _normalized_features(member_raw)
    degraded = degraded or bad_inherited or bad_member
    features = tuple(sorted(set(inherited_features) | set(member_features)))

    optional = declared.get("optional", False)
    if not isinstance(optional, bool):
        degraded = True
        optional = False
    default_features = declared.get("default-features", True)
    if not isinstance(default_features, bool):
        degraded = True
        default_features = True

    if isinstance(effective, str):
        version: str | None = effective
        edge_path: str | None = None
        edge_source = "registry"
    else:
        version = declared.get("version")
        if version is not None and not isinstance(version, str):
            degraded = True
            version = None
        raw_path = declared.get("path")
        if raw_path is None:
            edge_path = None
        elif isinstance(raw_path, str):
            edge_path = raw_path
        else:
            degraded = True
            edge_path = None
        edge_source = (
            "path"
            if "path" in declared
            else "git"
            if "git" in declared
            else "registry"
            if "version" in declared or "registry" in declared
            else "unspecified"
        )

    if degraded and resolution in _SOURCE_RESOLVED_EDGE:
        resolution = RESOLUTION_DEGRADED_METADATA
    package = _dependency_name(
        alias, effective if isinstance(effective, dict) else alias
    )
    edge = DependencyEdge(
        consumer=consumer,
        manifest=manifest,
        section=section,
        alias=alias,
        package=package,
        crate_name=_edge_crate_name(alias),
        kind=DEPENDENCY_KIND_BY_SECTION[section],
        target=target,
        version=version,
        path=edge_path,
        source=edge_source,
        optional=optional,
        default_features=default_features,
        inherited_features=inherited_features,
        member_features=member_features,
        features=features,
        resolution=resolution,
    )
    edge = replace(edge, resolution=_edge_resolved_in(resolution, projection, edge))
    return replace(edge, applicable=_edge_applicability(edge, target, projection))



def _manifest_dependency_edges(
    data: dict[str, Any],
    *,
    consumer: str,
    manifest: str,
    workspace_dependencies: dict[str, Any],
    projection: ResolverProjection | None = None,
) -> tuple[tuple[DependencyEdge, ...], tuple[str, ...]]:
    """Parse every dependency table into typed edges.

    Target-table keys are preserved verbatim as conditions; whether a condition
    applies is decided later by the bound resolver projection, never by
    inspecting the expression text here. Malformed tables are reported as
    structural problems (explicit incomplete evidence), never silently skipped.
    """
    projection = projection or ResolverProjection()
    edges: list[DependencyEdge] = []
    problems: list[str] = []

    def add_table(table: Any, section: str, target: str) -> None:
        if table is None:
            return
        if not isinstance(table, dict):
            problems.append(f"{section} table for target {target!r} must be a table")
            return
        for alias, spec in table.items():
            if not isinstance(alias, str):
                problems.append(
                    f"{section} entry for target {target!r} has a non-string alias"
                )
                continue
            edges.append(
                _build_edge(
                    consumer=consumer,
                    manifest=manifest,
                    section=section,
                    alias=alias,
                    target=target,
                    spec=spec,
                    workspace_dependencies=workspace_dependencies,
                    projection=projection,
                )
            )


    for section in DEPENDENCY_SECTIONS:
        add_table(data.get(section), section, "all")
    target_groups = data.get("target")
    if isinstance(target_groups, dict):
        for expression, group in target_groups.items():
            label = expression if isinstance(expression, str) else str(expression)
            if not isinstance(group, dict):
                problems.append(f"target dependency group {label!r} must be a table")
                continue
            for section in DEPENDENCY_SECTIONS:
                add_table(group.get(section), section, label)
    elif target_groups is not None:
        problems.append("target dependency groups must be a table")

    edges.sort(key=_edge_order)
    return tuple(edges), tuple(problems)


def _workspace_tables(
    parsed: list[tuple[str, dict[str, Any]]],
) -> dict[str, dict[str, Any]]:
    """In-tree [workspace] tables keyed by the manifest directory that owns them.

    The root manifest's directory is the empty string (its own directory), which
    is why a pointer that names the repository root must normalise to the empty
    key rather than to ".".
    """
    tables: dict[str, dict[str, Any]] = {}
    for relative, data in parsed:
        workspace = data.get("workspace")
        if isinstance(workspace, dict):
            tables[relative.rpartition("/")[0]] = workspace
    return tables


def _workspace_pointer_dir(
    *, path: Path, root: Path, pointer: str
) -> str | None:
    """Repo-relative directory an explicit [package].workspace pointer names.

    `Path('.').as_posix()` is ".", while the root workspace's table key is the
    empty string, so a VALID explicit pointer to the repository root used to miss
    the root table and mark every `workspace = true` dependency unresolved. Both
    spellings normalise to the same key here.
    """
    try:
        resolved = (path.parent / pointer.strip()).resolve()
    except (OSError, ValueError):
        return None
    try:
        relative = resolved.relative_to(root.resolve())
    except ValueError:
        return None
    text = relative.as_posix()
    return "" if text in (".", "") else text


def _inheritable_workspace_dependencies(
    *,
    relative: str,
    path: Path,
    root: Path,
    data: dict[str, Any],
    tables: dict[str, dict[str, Any]],
    projection: ResolverProjection,
    member: bool,
) -> dict[str, Any]:
    """Owning [workspace.dependencies] table for one manifest, Cargo-equivalent.

    Cargo binds `workspace = true` to the workspace that OWNS the package, not to
    whatever [workspace] table happens to sit above it on disk. So:

    1. an explicit `[package].workspace = "..."` pointer resolves directly, with
       the root-pointer normalisation fixed;
    2. otherwise the package must be a member of a workspace, and that
       workspace's own manifest supplies the table;
    3. a package that is NOT a member of any owning workspace resolves nothing,
       even when a root [workspace.dependencies] table sits physically above it.
       Cargo would not inherit for it, so neither do we.

    With no resolver projection, membership falls back to a declared
    `[workspace]` ancestor of the package's OWN manifest only (self or parent
    directory), which is the one ancestor relation Cargo itself always honours.
    A bare physical ancestor is never enough.
    """
    package = data.get("package")
    pointer = package.get("workspace") if isinstance(package, dict) else None
    if isinstance(pointer, str) and pointer.strip():
        pointer_dir = _workspace_pointer_dir(path=path, root=root, pointer=pointer)
        if pointer_dir is None:
            return {}
        table = tables.get(pointer_dir)
        dependencies = table.get("dependencies") if isinstance(table, dict) else None
        return dependencies if isinstance(dependencies, dict) else {}

    if not member:
        return {}

    directory = relative.rpartition("/")[0]
    owning = tables.get(directory)
    if owning is None and projection.bound:
        # A member without an own [workspace] table is owned by the workspace
        # Cargo actually bound it to; ask the projection rather than the tree.
        # Several owning roots may be ancestors, so pick the LONGEST matching one:
        # the nearest workspace is the one Cargo resolves against, and taking the
        # first sorted match could inherit a table from an outer workspace that
        # does not own this member.
        # The repository root is keyed by the EMPTY string, so the ordinary
        # `candidate_root + "/"` prefix test degenerates to `startswith("/")`
        # and never matches a nested member directory. Test the root case
        # explicitly, otherwise no member below the root can ever inherit.
        candidates = [
            candidate_root
            for candidate_root in projection.workspace_roots
            if not candidate_root
            or directory == candidate_root
            or directory.startswith(candidate_root + "/")
        ]
        for candidate_root in sorted(candidates, key=len, reverse=True):
            owning = tables.get(candidate_root)
            if owning is not None:
                break
    dependencies = owning.get("dependencies") if isinstance(owning, dict) else None
    return dependencies if isinstance(dependencies, dict) else {}


def _unit_transition(
    profile: str,
    edge: DependencyEdge,
    unit: str,
    *,
    root_hop: bool,
    manifests: dict[str, Manifest] | None = None,
    projection: ResolverProjection | None = None,
) -> str:
    """How one edge changes the compilation-unit context (defect 2).

    The compilation unit is what actually decides whether a dependency is target
    runtime code. Modelling it explicitly is what stops a proc-macro closure from
    being reported as a target-runtime path, and what keeps a nested build
    dependency visible instead of silently dropped:

    - TARGET-RUNTIME --normal--> proc-macro  => HOST-PROC-MACRO (crossing into a
      host artifact; its whole closure is host/tooling code)
    - TARGET-RUNTIME --normal--> normal      => stays TARGET-RUNTIME
    - HOST-*        --normal/--build--> *    => stays HOST-* (the host closure
      stays visible, so a build-helper's OWN build dependency is traversed)
    - TEST           --normal/--build--> *    => stays TEST
    - a `build` edge out of a TARGET unit    => HOST-BUILD-SCRIPT
    - a `dev` edge is admitted only as the root hop of the test projection, and
      only into the root's own test unit.

    The `PROFILE_SOURCE_BUILD` projection is what makes a NESTED build dependency
    traversable: it seeds traversal in HOST-BUILD-SCRIPT, so the old
    `(root_hop and build) or (not root_hop and normal)` filter -- which refused
    to look at a build-helper's own build dependencies at all -- is gone.
    """
    if edge.kind == "dev":
        if profile == PROFILE_SOURCE_TEST and root_hop:
            return TRANSITION_ROOT_TO_TEST_UNIT
        return TRANSITION_REJECTED
    if unit in _HOST_UNIT:
        return TRANSITION_HOST_STAYS_HOST
    if unit == UNIT_TEST:
        return TRANSITION_TEST_STAYS_TEST
    # unit == UNIT_TARGET_RUNTIME
    if edge.kind == "build":
        return TRANSITION_RUNTIME_TO_HOST_BUILD
    if manifests is not None and edge.enters_host_closure(
        manifests, projection or ResolverProjection()
    ):
        # A proc-macro declared `normal` is still a host artifact.
        return TRANSITION_RUNTIME_TO_HOST_PROC_MACRO
    return TRANSITION_RUNTIME_STAYS_RUNTIME


def _unit_after(
    profile: str,
    edge: DependencyEdge,
    unit: str,
    *,
    root_hop: bool,
    manifests: dict[str, Manifest] | None = None,
    projection: ResolverProjection | None = None,
) -> str | None:
    """Resulting compilation unit, or None when the edge is not traversable."""
    transition = _unit_transition(
        profile, edge, unit, root_hop=root_hop, manifests=manifests,
        projection=projection,
    )
    if transition == TRANSITION_REJECTED:
        return None
    if transition == TRANSITION_ROOT_TO_TEST_UNIT:
        return UNIT_TEST
    if transition == TRANSITION_HOST_STAYS_HOST:
        return unit
    if transition == TRANSITION_TEST_STAYS_TEST:
        return UNIT_TEST
    if transition == TRANSITION_RUNTIME_TO_HOST_BUILD:
        return UNIT_HOST_BUILD_SCRIPT
    if transition == TRANSITION_RUNTIME_TO_HOST_PROC_MACRO:
        return UNIT_HOST_PROC_MACRO
    return UNIT_TARGET_RUNTIME


def _profile_allows(
    profile: str,
    edge: DependencyEdge,
    *,
    unit: str,
    root_hop: bool,
    manifests: dict[str, Manifest] | None = None,
    projection: ResolverProjection | None = None,
) -> bool:
    """Traversal filter for one projection, expressed as a unit transition.

    Kept as a named predicate so existing readers of the module still find it;
    it now answers "can this edge be traversed from this compilation unit" and
    delegates the kind/unit decision to _unit_transition.
    """
    return (
        _unit_after(
            profile,
            edge,
            unit,
            root_hop=root_hop,
            manifests=manifests,
            projection=projection,
        )
        is not None
    )



def _edge_applicability(
    edge: DependencyEdge, target: str, projection: ResolverProjection
) -> str:
    """Target-condition applicability, decided by the resolver or left unresolved.

    An unconditional declaration carries no condition, so it is applicable by
    the absence of a condition -- that is not a cfg guess. A conditional
    declaration (a `[target.'cfg(..)']` table, or an optional dependency that
    only exists once a feature activates it) is applicable only when the locked
    resolver bound this exact (crate name, kind) pair for the bound triple. With
    no resolver bound it stays UNRESOLVED rather than being guessed from the
    expression text, which is what keeps a conditional edge out of a hard
    runtime claim.
    """
    if target == "all" and not edge.optional:
        return APPLICABLE_YES
    if not projection.bound:
        return APPLICABLE_UNRESOLVED
    if projection.selects(edge.manifest, edge.crate_name, edge.kind):
        return APPLICABLE_YES
    # The declaring package participates in the selected graph and the resolver
    # did not bind this conditional pair: the condition is not satisfied for the
    # bound triple. If the declaring package is not itself selected, this stays
    # unresolved because the absence is not evidence about the condition.
    if projection.members_by_manifest.get(edge.manifest) is not None:
        return APPLICABLE_NO
    return APPLICABLE_UNRESOLVED


def _edge_is_conditional(edge: DependencyEdge) -> bool:
    """True when the declaration itself carries a condition.

    Optionality counts: an optional dependency only applies when a feature
    activates it, so it is conditional on the recorded feature selection.
    """
    return edge.target != "all" or edge.optional


def _profile_descriptor(
    profile: str, projection: ResolverProjection | None = None
) -> dict[str, Any]:
    """Descriptor for one projection, carrying the real resolver inputs.

    The descriptor no longer hardcodes "unbound". When a resolver projection is
    bound it reports the exact triple, feature selection, resolver version,
    toolchain and source identity that produced the selected graph; when it is
    not bound it says WHY, so the witness cannot be read as selected runtime
    evidence. `evidence_class` states which of the two inventories this is.
    """
    if projection is None:
        projection = ResolverProjection()
    evidence_class = (
        EVIDENCE_SELECTED if projection.bound else EVIDENCE_SOURCE_WIDE
    )
    descriptor: dict[str, Any] = {
        "name": profile,
        "evidence_class": evidence_class,
        "resolver_bound": projection.bound,
    }
    descriptor.update(projection.descriptor())
    return descriptor


def _finish_typed_path(
    manifests: dict[str, Manifest],
    edges: tuple[DependencyEdge, ...],
    stats: dict[str, int] | TraversalFrontier,
    *,
    unit_contexts: tuple[str, ...] = (),
    projection: ResolverProjection | None = None,
) -> TypedPath:
    """Annotate an ordered edge path with the context that qualifies it."""
    conditional = tuple(
        index for index, edge in enumerate(edges) if _edge_is_conditional(edge)
    )
    projection = projection or ResolverProjection()
    host_hops = tuple(
        index
        for index, edge in enumerate(edges)
        if edge.enters_host_closure(manifests, projection)
    )
    truncated = (
        stats.truncated
        if isinstance(stats, TraversalFrontier)
        else bool(stats["truncated"])
    )
    frontier = stats if isinstance(stats, TraversalFrontier) else None
    if not unit_contexts:
        unit_contexts = _replay_contexts(manifests, edges, projection=projection)
    terminal = unit_contexts[-1] if unit_contexts else UNIT_TARGET_RUNTIME
    return TypedPath(
        edges=edges,
        conditional_hops=conditional,
        host_hops=host_hops,
        truncated=truncated,
        unit_contexts=unit_contexts,
        terminal_unit=terminal,
        frontier=frontier,
    )


def _replay_contexts(
    manifests: dict[str, Manifest],
    edges: tuple[DependencyEdge, ...],
    *,
    projection: ResolverProjection | None = None,
    start_unit: str = UNIT_TARGET_RUNTIME,
) -> tuple[str, ...]:
    """Replay unit transitions along a concrete path.

    Independent of the search that produced it, so a single-edge or source-wide
    witness reports the same compilation-unit context a searched one would. A path
    that crosses a proc-macro or build boundary is HOST from that hop onward,
    never target runtime again.
    """
    unit = start_unit
    contexts = [unit]
    for index, edge in enumerate(edges):
        nxt = _unit_after(
            PROFILE_SOURCE_RUNTIME,
            edge,
            unit,
            root_hop=(index == 0),
            manifests=manifests,
            projection=projection,
        )
        unit = nxt if nxt is not None else unit
        contexts.append(unit)
    return tuple(contexts)


def _single_edge_path(
    manifests: dict[str, Manifest],
    edge: DependencyEdge,
    *,
    projection: ResolverProjection | None = None,
) -> TypedPath:
    return _finish_typed_path(
        manifests, (edge,), {"truncated": 0}, projection=projection
    )


def _frontier_counters(
    manifests: dict[str, Manifest],
    profile: str,
    start: str,
    projection: ResolverProjection,
) -> dict[str, int]:
    """Denominator counters for the whole searched graph (defect 5).

    These describe the graph the search COULD traverse, not just the root
    manifest's own declarations, so the witness's denominator is honest about
    what was searched.
    """
    nodes = 0
    selected = 0
    conditional = 0
    for name in sorted(manifests):
        manifest = manifests[name]
        nodes += 1
        unit = UNIT_TARGET_RUNTIME
        for edge in manifest.dependency_edges:
            nxt = _unit_after(
                profile,
                edge,
                unit,
                root_hop=(name == start),
                manifests=manifests,
                projection=projection,
            )
            if nxt is None:
                continue
            selected += 1
            if _edge_is_conditional(edge):
                conditional += 1
            unit = nxt
    return {
        "graph_nodes_available": nodes,
        "selected_edges": selected,
        "conditional_edges": conditional,
    }


def _typed_dependency_path(
    manifests: dict[str, Manifest],
    ambiguous: frozenset[str],
    start: str,
    predicate: Any,
    profile: str,
    *,
    start_unit: str = UNIT_TARGET_RUNTIME,
    projection: ResolverProjection | None = None,
) -> tuple[TypedPath | None, TraversalFrontier]:
    """Shortest multi-hop typed path to a forbidden package in one projection.

    Deterministic breadth-first search over pre-sorted edges with an explicit
    compilation-unit context (defect 2). An edge is traversable only when the
    locked resolver marked it resolved (defect 3); every frontier that stops
    traversal -- unresolved, degraded, unsupported, external, ambiguous or
    not-in-graph -- is RETAINED and returned even when no path is found
    (defect 5). When the hop or node bound is hit without a path, the returned
    frontier reports exhaustion so the caller can emit an explicit
    incomplete-audit result instead of exiting clean.
    """
    projection = projection or ResolverProjection()
    counters = _frontier_counters(manifests, profile, start, projection)
    state = {
        "visited": 1,
        "expanded": 0,
        "edges_visited": 0,
        "unresolved": 0,
        "unresolved_packages": set(),
        "external": 0,
        "ambiguous": 0,
        "not_in_graph": 0,
        "truncated": False,
        "hop_bound": 0,
        "node_bound": 0,
    }

    def build(found: bool) -> TraversalFrontier:
        root_manifest = manifests.get(start)
        return TraversalFrontier(
            root=start,
            profile=profile,
            graph_nodes_available=counters["graph_nodes_available"],
            root_declared_edges=(
                len(root_manifest.dependency_edges) if root_manifest else 0
            ),
            selected_edges=counters["selected_edges"],
            conditional_edges=counters["conditional_edges"],
            visited_nodes=state["visited"],
            expanded_nodes=state["expanded"],
            selected_edges_visited=state["edges_visited"],
            unresolved_frontier=state["unresolved"],
            unresolved_packages=tuple(sorted(state["unresolved_packages"])),
            external_frontier=state["external"],
            ambiguous_frontier=state["ambiguous"],
            not_in_graph_frontier=state["not_in_graph"],
            truncated=state["truncated"],
            truncated_at_hop_bound=state["hop_bound"],
            truncated_at_node_bound=state["node_bound"],
            max_hops=_TYPED_PATH_MAX_HOPS,
            max_nodes=_TYPED_PATH_MAX_NODES,
            found=found,
        )

    # Queue entries carry the edge path AND the compilation-unit context of the
    # node the path reached, so transitions are explicit state, not a boolean.
    queue: deque[tuple[tuple[DependencyEdge, ...], str]] = deque([((), start_unit)])
    visited: set[tuple[str, str]] = {(start, start_unit)}
    counted: set[tuple[str, str]] = set()

    while queue:
        path, unit = queue.popleft()
        node = start if not path else path[-1].package
        if len(path) >= _TYPED_PATH_MAX_HOPS:
            state["truncated"] = True
            state["hop_bound"] += 1
            continue
        manifest = manifests.get(node)
        if manifest is None:
            continue
        state["expanded"] += 1
        for edge in manifest.dependency_edges:
            root_hop = not path
            next_unit = _unit_after(
                profile,
                edge,
                unit,
                root_hop=root_hop,
                manifests=manifests,
                projection=projection,
            )
            if next_unit is None:
                continue
            state["edges_visited"] += 1
            target = edge.package
            key = (target, next_unit)
            if key in visited:
                continue
            next_path = (*path, edge)
            # Resolution-awareness: a path is only EVIDENCE when every edge on it
            # is resolver-selected. An unresolved/degraded/unsupported edge is
            # still reported as a typed incomplete frontier, but it is never
            # walked through and never promoted into a resolved path.
            resolved_edge = edge.resolved
            if predicate(target) and len(next_path) > 1:
                contexts = _replay_contexts(
                    manifests,
                    next_path,
                    projection=projection,
                    start_unit=start_unit,
                )
                frontier = build(found=resolved_edge)
                return (
                    _finish_typed_path(
                        manifests,
                        next_path,
                        frontier,
                        unit_contexts=contexts,
                        projection=projection,
                    ),
                    frontier,
                )
            if key in counted:
                continue
            counted.add(key)
            if target in ambiguous:
                state["ambiguous"] += 1
                visited.add(key)
                continue
            if not resolved_edge:
                # Report the frontier, do not traverse it.
                state["unresolved"] += 1
                state["unresolved_packages"].add(target)
                visited.add(key)
                continue
            if target not in manifests:
                # Resolver bound the declaration but the target is not an
                # in-tree package: a registry/git dependency whose own closure
                # is not audited here. External frontier, never traversed.
                state["external"] += 1
                visited.add(key)
                continue
            if state["visited"] >= _TYPED_PATH_MAX_NODES:
                state["truncated"] = True
                state["node_bound"] += 1
                visited.add(key)
                continue
            visited.add(key)
            state["visited"] += 1
            queue.append((next_path, next_unit))
    return None, build(found=False)


def _edge_evidence(
    edge: DependencyEdge,
    manifests: dict[str, Manifest] | None = None,
    projection: ResolverProjection | None = None,
) -> dict[str, Any]:
    # `host_closure` is a property of the EDGE plus the unit it lands in, not a
    # stored field: proc-macro identity comes from the declaring manifest or the
    # bound projection. It is reported here so a witness states which of its
    # declarations left target-runtime compilation instead of leaving the reader
    # to infer it from the path.
    host_closure = None
    if manifests is not None and projection is not None:
        host_closure = edge.enters_host_closure(manifests, projection)
    return {
        "consumer": edge.consumer,
        "manifest": edge.manifest,
        "section": edge.section,
        "alias": edge.alias,
        "package": edge.package,
        "crate_name": edge.crate_name,
        "kind": edge.kind,
        "target": edge.target,
        "version": edge.version,
        "path": edge.path,
        "source": edge.source,
        "optional": edge.optional,
        "default_features": edge.default_features,
        "inherited_features": list(edge.inherited_features),
        "member_features": list(edge.member_features),
        "features": list(edge.features),
        "resolution": edge.resolution,
        "resolved": edge.resolved,
        "applicable": edge.applicable,
        "host_closure": host_closure,
    }


def _format_leg(edge: DependencyEdge, *, unit: str = UNIT_TARGET_RUNTIME) -> str:
    flags = (
        f"{edge.kind}|{edge.section}|alias={edge.alias}"
        f"|target={edge.target}|{edge.resolution}"
    )
    if edge.optional:
        flags += "|optional"
    if not edge.default_features:
        flags += "|no-default-features"
    flags += f"|unit={unit}"
    return f"{edge.consumer} --[{flags}]--> {edge.package}"



def _target_identity(
    manifests: dict[str, Manifest], ambiguous: frozenset[str], package: str
) -> dict[str, Any]:
    manifest = manifests.get(package)
    if manifest is None:
        return {
            "package": package,
            "in_tree": False,
            "manifest": None,
            "proc_macro": False,
            "ambiguous": False,
        }
    return {
        "package": package,
        "in_tree": True,
        "manifest": manifest.path,
        "proc_macro": manifest.proc_macro,
        "ambiguous": package in ambiguous,
    }


def _dependency_counts(
    root_manifest: Manifest,
    profile: str,
    *,
    projection: ResolverProjection | None = None,
    start: str | None = None,
) -> dict[str, Any]:
    """Root-manifest counts PLUS the searched-graph denominator (defect 5).

    The old counts described only the root manifest's own declarations, so a
    witness could claim `unresolved:0` while its path crossed an unresolved
    declaration three hops down. The graph denominator and the resolver identity
    now travel with every count.
    """
    projection = projection or ResolverProjection()
    root_name = start or root_manifest.name
    declared = len(root_manifest.dependency_edges)
    if profile == PROFILE_SOURCE_WIDE:
        selected = declared
    else:
        selected = sum(
            1
            for edge in root_manifest.dependency_edges
            if _unit_after(profile, edge, UNIT_TARGET_RUNTIME, root_hop=True)
            is not None
        )
    unresolved = sum(
        1 for edge in root_manifest.dependency_edges if not edge.resolved
    )
    return {
        "declared_edges": declared,
        "selected_edges": selected,
        "unresolved_edges": unresolved,
        "resolver_bound": projection.bound,
        "denominator": (
            f"{declared} declared edges of {root_name}; "
            f"{selected} selected in {profile}; {unresolved} unresolved; "
            f"resolver={projection.source if projection.bound else 'unbound'}"
        ),
    }


def _path_resolution(
    manifests: dict[str, Manifest],
    ambiguous: frozenset[str],
    edges: tuple[DependencyEdge, ...],
) -> str:
    """Resolution class of a whole path, from its edges (defect 3).

    This used to look only at whether the ENDPOINT package existed in tree, so a
    path through an `unresolved-workspace` declaration could still be labelled
    `resolved-in-tree`. Every edge's own resolution class is now considered and
    the weakest one wins.
    """
    if not edges:
        return "no-path"
    if any(edge.package in ambiguous for edge in edges):
        return "ambiguous-package"
    if any(edge.package not in manifests for edge in edges):
        return "external-unresolved"
    states = {edge.resolution for edge in edges}
    if RESOLUTION_RESOLVER_SELECTED in states:
        unresolved_states = states - {RESOLUTION_RESOLVER_SELECTED}
        if unresolved_states:
            return "resolved-with-unresolved-edges"
        return "resolved-in-tree"
    # `states` is a set and `_SOURCE_RESOLVED_EDGE` is a tuple, so this test must
    # be set-to-set: comparing a set against a tuple is never true, which would
    # silently skip the "declared but unconfirmed" classification entirely.
    if states <= set(_SOURCE_RESOLVED_EDGE):
        # No resolver bound: the declaration identities are known, but the link
        # was never confirmed by a resolver. This is NOT a clean resolution.
        return "declared-only-unconfirmed-by-resolver"
    for state in sorted(states):
        if state not in _SOURCE_RESOLVED_EDGE:
            return state
    return "declared-only-unconfirmed-by-resolver"


def _path_completeness(
    path: TypedPath | None,
    edges: tuple[DependencyEdge, ...],
    *,
    projection: ResolverProjection,
    frontier: TraversalFrontier | None,
) -> tuple[str, tuple[str, ...]]:
    """Derive completeness from the evidence; never assert it."""
    reasons: list[str] = []
    if not projection.bound:
        reasons.append("no-resolver-projection-bound")
    for edge in edges:
        if edge.resolution not in (RESOLUTION_RESOLVER_SELECTED,):
            reason = _COMPLETENESS_REASONS.get(edge.resolution)
            if reason and reason not in reasons:
                reasons.append(reason)
        if edge.applicable == APPLICABLE_UNRESOLVED:
            if "conditional-unit-unresolved" not in reasons:
                reasons.append("conditional-unit-unresolved")
    if any(_edge_is_conditional(edge) for edge in edges):
        if "conditional-unit-present" not in reasons:
            reasons.append("conditional-unit-present")
    if frontier is not None:
        if frontier.truncated:
            reasons.append("traversal-truncated-at-bound")
        if frontier.unresolved_frontier:
            if "unresolved-frontier-present" not in reasons:
                reasons.append("unresolved-frontier-present")
        if frontier.external_frontier:
            if "external-frontier-present" not in reasons:
                reasons.append("external-frontier-present")
    if not reasons:
        return COMPLETENESS_SELECTED, ()
    if projection.bound:
        return COMPLETENESS_SELECTED_INCOMPLETE, tuple(sorted(reasons))
    return COMPLETENESS_SOURCE_ONLY, tuple(sorted(reasons))


def _dependency_witness(
    *,
    rule: str,
    rule_scope: str,
    profile: str,
    path: TypedPath | None,
    manifests: dict[str, Manifest],
    ambiguous: frozenset[str],
    counts: dict[str, Any],
    violations: int,
    projection: ResolverProjection | None = None,
) -> dict[str, Any]:
    """Assemble the complete evidence record for one dependency claim."""
    projection = projection or ResolverProjection()
    edges = path.edges if path is not None else ()
    host_hops = set(path.host_hops) if path is not None else set()
    unit_contexts = (
        list(path.unit_contexts) if path is not None and path.unit_contexts else []
    )
    if not unit_contexts and edges:
        replay = _replay_contexts(UNIT_TARGET_RUNTIME, edges)
        unit_contexts = list(replay[:-1])
    terminal_unit = (
        path.terminal_unit if path is not None and path.terminal_unit else UNIT_TARGET_RUNTIME
    )
    frontier = path.frontier if path is not None else None
    completeness, reasons = _path_completeness(
        path, edges, projection=projection, frontier=frontier
    )
    return {
        "rule": rule,
        "rule_scope": rule_scope,
        "evidence_class": (
            EVIDENCE_SELECTED
            if (projection.bound and completeness == COMPLETENESS_SELECTED)
            else EVIDENCE_SOURCE_WIDE
        ),
        "profile": _profile_descriptor(profile, projection),
        "declarations": [
            _edge_evidence(edge, manifests, projection) for edge in edges
        ],
        "path": [
            _format_leg(
                edge,
                unit=(
                    unit_contexts[index]
                    if index < len(unit_contexts)
                    else UNIT_TARGET_RUNTIME
                ),
            )
            for index, edge in enumerate(edges)
        ],
        "unit_contexts": unit_contexts,
        "terminal_unit": terminal_unit,
        "host_hops": sorted(host_hops),
        "conditional_hops": list(path.conditional_hops) if path is not None else [],
        "target_identity": (
            _target_identity(manifests, ambiguous, edges[-1].package) if edges else None
        ),
        "resolution": _path_resolution(manifests, ambiguous, edges),
        "completeness": completeness,
        "completeness_reasons": list(reasons),
        "counts": {**counts, "violations": violations},
        "frontier": frontier.evidence() if frontier is not None else None,
        "truncated": path.truncated if path is not None else False,
    }


def _witness_suffix(witness: dict[str, Any]) -> str:
    legs = " | ".join(witness["path"]) if witness["path"] else "no-path"
    counts = witness["counts"]
    profile = witness["profile"]
    resolver = profile.get("source", "unbound")
    triple = profile.get("target_triple", "unbound")
    terminal = witness.get("terminal_unit", UNIT_TARGET_RUNTIME)
    reasons = witness.get("completeness_reasons") or []
    reason_text = f" reasons={','.join(reasons)}" if reasons else ""
    return (
        f"[rule={witness['rule']} scope={witness['rule_scope']} "
        f"profile={profile['name']}(resolver={resolver},target={triple}) "
        f"evidence={witness['evidence_class']} terminal-unit={terminal} "
        f"path={legs} completeness={witness['completeness']}{reason_text} "
        f"counts=declared:{counts['declared_edges']} "
        f"selected:{counts['selected_edges']} "
        f"violations:{counts['violations']} "
        f"unresolved:{counts['unresolved_edges']}]"
    )



def load_manifests(
    root: Path, projection: ResolverProjection | None = None
) -> tuple[dict[str, Manifest], list[Finding], frozenset[str]]:
    projection = projection or ResolverProjection()
    manifests: dict[str, Manifest] = {}
    findings: list[Finding] = []
    ambiguous: set[str] = set()

    collected: list[tuple[str, Path, dict[str, Any]]] = []
    for path in _walk(root, "Cargo.toml"):
        relative = _relative(root, path)
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "manifest_unreadable",
                    relative,
                    None,
                    f"Cargo manifest cannot be parsed: {error}",
                )
            )
            continue
        collected.append((relative, path, data))
    # Deterministic order: a duplicate name keeps its lowest-sorted manifest
    # and the name is additionally recorded as ambiguous, so traversal never
    # silently picks an arbitrary winner for path claims.
    collected.sort(key=lambda item: item[0])
    tables = _workspace_tables([(relative, data) for relative, _, data in collected])
    global manifests_names_cache
    manifests_names_cache = set()

    for relative, path, data in collected:
        package = data.get("package")
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        if not isinstance(name, str) or not name.strip():
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "package_name_missing",
                    relative,
                    None,
                    "[package].name is missing or empty.",
                )
            )
            continue

        consumer = name.strip()
        # Workspace membership as Cargo reports it, from the projection. With no
        # bound projection, a manifest that declares its OWN [workspace] table is
        # its own workspace root; everything else is treated as not-member so
        # ancestor filesystem proximity never grants workspace inheritance.
        member = projection.members_by_manifest.get(relative)
        if projection.bound:
            is_member = member is not None
        else:
            is_member = relative.rpartition("/")[0] in tables
        own_workspace_dir = (
            relative.rpartition("/")[0]
            if relative.rpartition("/")[0] in tables
            else None
        )
        workspace_dependencies = _inheritable_workspace_dependencies(
            relative=relative,
            path=path,
            root=root,
            data=data,
            tables=tables,
            projection=projection,
            member=is_member,
        )
        edges, problems = _manifest_dependency_edges(
            data,
            consumer=consumer,
            manifest=relative,
            workspace_dependencies=workspace_dependencies,
            projection=projection,
        )
        # A manifest whose package is not a workspace member and not its own
        # workspace root cannot have its dependencies resolved by this audit's
        # resolver projection, so every declaration it makes stays explicitly
        # unresolved (defect 4). Its own explicit pointer still resolves.
        if not is_member:
            edges = [
                replace(edge, resolution=RESOLUTION_UNRESOLVED_NOT_IN_GRAPH)
                if edge.resolution in _SOURCE_RESOLVED_EDGE
                else edge
                for edge in edges
            ]
        lib = data.get("lib")
        manifest = Manifest(
            name=consumer,
            path=relative,
            dependencies=_manifest_dependencies(data),
            dependency_edges=tuple(edges),
            proc_macro=isinstance(lib, dict) and lib.get("proc-macro") is True,
            workspace_member=is_member,
            own_workspace_dir=own_workspace_dir,
        )
        manifests_names_cache.add(consumer)

        for problem in problems:
            witness = _dependency_witness(
                rule="manifest-parse",
                rule_scope="resolution-incomplete",
                profile=PROFILE_SOURCE_WIDE,
                path=None,
                manifests={},
                ambiguous=frozenset(),
                counts=_dependency_counts(manifest, PROFILE_SOURCE_WIDE),
                violations=1,
            )
            findings.append(
                Finding(
                    "AUDIT_SIGNAL",
                    "dependency_resolution_incomplete",
                    relative,
                    consumer,
                    f"Cargo dependency table is not interpretable ({problem}); "
                    f"evidence is incomplete, not absent. {_witness_suffix(witness)}",
                    witness=witness,
                )
            )
        previous = manifests.get(manifest.name)
        if previous is not None:
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "duplicate_package_name",
                    relative,
                    manifest.name,
                    f"Package name also declared by {previous.path}.",
                )
            )
            ambiguous.add(manifest.name)
            continue
        manifests[manifest.name] = manifest

    return manifests, findings, frozenset(ambiguous)


def load_policy(path: Path) -> dict[str, Any]:
    try:
        policy = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ValueError(f"cannot load boundary policy {path}: {error}") from error

    if policy.get("schema") != "eliot.architecture-boundaries.v1":
        raise ValueError("unsupported or missing architecture-boundary schema")
    return policy


def validate_policy(root: Path, policy: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    debt_keys: set[tuple[str, str]] = set()

    for item in policy.get("tracked_debt", []):
        if not isinstance(item, dict):
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "tracked_debt_malformed",
                    "config/architecture-boundaries.toml",
                    None,
                    "tracked_debt entry must be a TOML table.",
                )
            )
            continue

        kind = str(item.get("kind", "")).strip()
        path = str(item.get("path", "")).strip().replace("\\", "/")
        reason = str(item.get("reason", "")).strip()
        removal = str(item.get("remove_when", "")).strip()
        issue = item.get("issue")
        key = (kind, path)

        if not kind or not path or any(token in path for token in ("*", "?", "[")):
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "tracked_debt_not_exact",
                    "config/architecture-boundaries.toml",
                    None,
                    f"Debt entry must use an exact kind/path: {key!r}.",
                )
            )
        if key in debt_keys:
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "tracked_debt_duplicate",
                    "config/architecture-boundaries.toml",
                    None,
                    f"Duplicate debt entry: {key!r}.",
                )
            )
        debt_keys.add(key)

        if not isinstance(issue, int) or issue <= 0 or not reason or not removal:
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "tracked_debt_unowned",
                    "config/architecture-boundaries.toml",
                    None,
                    f"Debt {key!r} requires positive issue, reason and remove_when.",
                )
            )

        if kind == "direct_process_launch":
            allowed = {"kind", "path", "issue", "reason", "remove_when",
                       "items", "operation", "cfg", "class"}
            unknown = sorted(set(item) - allowed)
            if unknown:
                findings.append(
                    Finding(
                        "HARD_VIOLATION",
                        "tracked_debt_unknown_field",
                        "config/architecture-boundaries.toml",
                        None,
                        f"Debt {key!r} has unsupported fields {unknown}; "
                        "new process-exception meaning is never silently ignored.",
                    )
                )
            items = item.get("items")
            if items is not None and (
                not isinstance(items, list)
                or not items
                or any(not isinstance(name, str) or not name.strip() for name in items)
            ):
                findings.append(
                    Finding(
                        "HARD_VIOLATION",
                        "tracked_debt_not_exact",
                        "config/architecture-boundaries.toml",
                        None,
                        f"Debt {key!r} items must be a non-empty list of exact fn names.",
                    )
                )
            operation = item.get("operation")
            if operation is not None and operation not in PROCESS_EXCEPTION_OPERATIONS:
                findings.append(
                    Finding(
                        "HARD_VIOLATION",
                        "tracked_debt_not_exact",
                        "config/architecture-boundaries.toml",
                        None,
                        f"Debt {key!r} operation must be one of "
                        f"{list(PROCESS_EXCEPTION_OPERATIONS)}.",
                    )
                )
            cfg = item.get("cfg")
            if cfg is not None and (not isinstance(cfg, str) or not cfg.strip()):
                findings.append(
                    Finding(
                        "HARD_VIOLATION",
                        "tracked_debt_not_exact",
                        "config/architecture-boundaries.toml",
                        None,
                        f"Debt {key!r} cfg must be a non-empty cfg token.",
                    )
                )
            class_ = item.get("class")
            if class_ is not None and class_ not in PROCESS_EXCEPTION_CLASSES:
                findings.append(
                    Finding(
                        "HARD_VIOLATION",
                        "tracked_debt_not_exact",
                        "config/architecture-boundaries.toml",
                        None,
                        f"Debt {key!r} class must be one of "
                        f"{list(PROCESS_EXCEPTION_CLASSES)}.",
                    )
                )

        if path and not (root / path).is_file():
            findings.append(
                Finding(
                    "AUDIT_SIGNAL",
                    "tracked_debt_path_missing",
                    path,
                    None,
                    "Debt path no longer exists; remove or update the entry.",
                    issue if isinstance(issue, int) else None,
                    removal or None,
                )
            )

    for item in policy.get("process_owner", []):
        if not isinstance(item, dict):
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "process_owner_malformed",
                    "config/architecture-boundaries.toml",
                    None,
                    "process_owner entry must be a TOML table.",
                )
            )
            continue
        path = str(item.get("path", "")).strip().replace("\\", "/").rstrip("/")
        issue = item.get("issue")
        reason = str(item.get("reason", "")).strip()
        if not path or any(token in path for token in ("*", "?", "[")):
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "process_owner_not_exact",
                    "config/architecture-boundaries.toml",
                    None,
                    f"Process owner path is not exact: {path!r}.",
                )
            )
        if not isinstance(issue, int) or issue <= 0 or not reason:
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "process_owner_unowned",
                    "config/architecture-boundaries.toml",
                    None,
                    f"Process owner {path!r} requires issue and reason.",
                )
            )
        if path and not (root / path).is_dir():
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "process_owner_path_missing",
                    path,
                    None,
                    "Declared process-owner directory does not exist.",
                    issue if isinstance(issue, int) else None,
                )
            )

    return findings


def build_graph(manifests: dict[str, Manifest]) -> dict[str, set[str]]:
    """Source-wide in-tree name adjacency (compatibility projection).

    SOURCE-WIDE ONLY. This untyped name graph must not back runtime claims:
    runtime/test/build evidence uses the typed DependencyEdge projections via
    _typed_dependency_path. Retained so existing name-graph readers keep
    working while they migrate to typed edges.
    """
    names = set(manifests)
    return {
        package: {dependency for dependency in manifest.dependencies if dependency in names}
        for package, manifest in manifests.items()
    }


def _forbidden(name: str, exact: set[str], prefixes: tuple[str, ...]) -> bool:
    return name in exact or any(name.startswith(prefix) for prefix in prefixes)


def _dependency_path(
    graph: dict[str, set[str]], start: str, predicate: Any
) -> list[str] | None:
    """Source-wide name path (compatibility helper; not a runtime claim)."""
    queue: deque[list[str]] = deque([[start]])
    visited = {start}
    while queue:
        path = queue.popleft()
        for dependency in sorted(graph.get(path[-1], set())):
            if dependency in visited:
                continue
            next_path = [*path, dependency]
            if predicate(dependency):
                return next_path
            visited.add(dependency)
            queue.append(next_path)
    return None


def audit_dependencies(
    manifests: dict[str, Manifest],
    policy: dict[str, Any],
    ambiguous: frozenset[str] = frozenset(),
    unresolved_manifests: frozenset[str] = frozenset(),
    projection: ResolverProjection | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    ambiguous = frozenset(ambiguous)
    unresolved_manifests = frozenset(unresolved_manifests)
    projection = projection or ResolverProjection()

    # Every non-dev path ends in a normal/build declaration, so scanning each
    # manifest catches transitive routes at their final edge too.
    for manifest in sorted(manifests.values(), key=lambda item: item.name):
        for edge in manifest.dependency_edges:
            if (
                edge.package != "eliot-test-support"
                or edge.kind not in {"normal", "build"}
            ):
                continue
            witness = _dependency_witness(
                rule="test-support-production-boundary",
                rule_scope="non-dev-declaration",
                profile=PROFILE_SOURCE_WIDE,
                path=_single_edge_path(manifests, edge),
                manifests=manifests,
                ambiguous=ambiguous,
                counts=_dependency_counts(
                    manifest, PROFILE_SOURCE_WIDE, projection=projection, start=manifest.name
                ),
                violations=1,
                projection=projection,
            )
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "test_support_production_dependency",
                    manifest.path,
                    manifest.name,
                    f"Non-dev {edge.kind} dependency on 'eliot-test-support' "
                    "violates the test-support boundary. "
                    f"{_witness_suffix(witness)}",
                    1146,
                    witness=witness,
                )
            )

    # An uninterpretable dependency table can hide a normal/build edge,
    # so for the test-support boundary an unresolved configuration is a
    # hard rejection, never a clean pass.
    for manifest in sorted(manifests.values(), key=lambda item: item.name):
        if manifest.path not in unresolved_manifests:
            continue
        witness = _dependency_witness(
            rule="test-support-production-boundary",
            rule_scope="unresolved-configuration",
            profile=PROFILE_SOURCE_WIDE,
            path=None,
            manifests=manifests,
            ambiguous=ambiguous,
            counts=_dependency_counts(
                manifest, PROFILE_SOURCE_WIDE, projection=projection, start=manifest.name
            ),
            violations=1,
            projection=projection,
        )
        findings.append(
            Finding(
                "HARD_VIOLATION",
                "test_support_boundary_unresolved",
                manifest.path,
                manifest.name,
                f"Cargo dependency tables for {manifest.name!r} are not "
                "interpretable, so a normal/build path to "
                "'eliot-test-support' cannot be excluded. "
                f"{_witness_suffix(witness)}",
                1146,
                witness=witness,
            )
        )

    store_table = policy.get("store_vendor", {})
    allowed_store_packages = set(store_table.get("allowed_packages", []))
    for manifest in sorted(manifests.values(), key=lambda item: item.name):
        leaks = [
            edge for edge in manifest.dependency_edges if edge.package == "surrealdb"
        ]
        if leaks and manifest.name not in allowed_store_packages:
            counts = _dependency_counts(
                manifest, PROFILE_SOURCE_WIDE, projection=projection, start=manifest.name
            )
            witness = _dependency_witness(
                rule="store_vendor",
                rule_scope="source-wide",
                profile=PROFILE_SOURCE_WIDE,
                path=_finish_typed_path(manifests, tuple(leaks), {"truncated": 0}),
                manifests=manifests,
                ambiguous=ambiguous,
                counts=counts,
                violations=len(leaks),
                projection=projection,
            )
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "surrealdb_dependency_leak",
                    manifest.path,
                    manifest.name,
                    "SurrealDB dependency is outside the admitted store contour. "
                    f"{_witness_suffix(witness)}",
                    19,
                    witness=witness,
                )
            )

    for index, item in enumerate(policy.get("runtime_root", [])):
        if not isinstance(item, dict):
            continue
        package = str(item.get("package", "")).strip()
        issue = item.get("issue") if isinstance(item.get("issue"), int) else None
        unknown_keys = sorted(set(item) - _RUNTIME_ROOT_KNOWN_KEYS)
        if unknown_keys:
            findings.append(
                Finding(
                    "AUDIT_SIGNAL",
                    "runtime_root_scope_unresolved",
                    "config/architecture-boundaries.toml",
                    package or None,
                    f"Runtime-root entry #{index} for {package!r} carries "
                    f"unresolved rule scope keys {unknown_keys}; edges under this "
                    "entry are evaluated against the declared exact/prefix sets "
                    "only, and the unknown scope is not allowed.",
                    issue,
                )
            )
        manifest = manifests.get(package)
        if manifest is None:
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "runtime_root_missing",
                    "config/architecture-boundaries.toml",
                    package or None,
                    "Declared runtime root package is absent from current Cargo metadata.",
                    issue,
                )
            )
            continue

        exact = set(str(value) for value in item.get("forbidden_exact", []))
        prefixes = tuple(str(value) for value in item.get("forbidden_prefix", []))
        predicate = lambda name: _forbidden(name, exact, prefixes)
        if issue is None:
            rule = f"runtime_root:package={package}"
        else:
            rule = f"runtime_root:package={package}#{issue}"

        # Direct declarations: each edge is judged in its own kind, condition
        # and resolution scope, so a dev path to a package can never mask a real
        # normal path to the same package (and vice versa). A direct edge is a
        # runtime HARD_VIOLATION only when it is BOTH selected by the locked
        # resolver AND unconditional AND resolved; every other combination is
        # reported as the incomplete evidence it actually is (defects 1 and 3).
        for edge in manifest.dependency_edges:
            if not predicate(edge.package):
                continue
            profile = PROFILE_SOURCE_RUNTIME
            if edge.kind == "normal":
                profile = PROFILE_SOURCE_RUNTIME
            elif edge.kind == "dev":
                profile = PROFILE_SOURCE_TEST
            else:
                profile = PROFILE_SOURCE_BUILD

            if edge.kind == "dev":
                scope = "test-unit-declaration"
                severity = "AUDIT_SIGNAL"
                code = "runtime_root_forbidden_test_dependency"
                detail = (
                    f"Test-scoped dev dependency {edge.package!r} is recorded in "
                    "the test projection, not as a runtime-root selected edge."
                )
            elif edge.kind == "build":
                scope = "host-build-unit-declaration"
                severity = "AUDIT_SIGNAL"
                code = "runtime_root_forbidden_build_dependency"
                detail = (
                    f"Build-scoped dependency {edge.package!r} is recorded in "
                    "the build/tooling projection, not as target-runtime code."
                )
            elif not edge.resolved:
                # The declaration exists and is unconditional and normal, but no
                # locked resolver confirmed the link. That is incomplete
                # evidence, not a selected runtime violation.
                scope = "unresolved-declaration"
                severity = "AUDIT_SIGNAL"
                code = "runtime_root_forbidden_unresolved_dependency"
                detail = (
                    f"Direct normal dependency {edge.package!r} matches the "
                    f"forbidden set but resolves as {edge.resolution}; the "
                    "runtime-root boundary cannot be adjudicated from an "
                    "unresolved declaration."
                )
            elif edge.applicable == APPLICABLE_UNRESOLVED:
                scope = "conditional-unresolved"
                severity = "AUDIT_SIGNAL"
                code = "runtime_root_forbidden_conditional_dependency"
                detail = (
                    f"Conditional normal dependency {edge.package!r} "
                    f"(target={edge.target} optional={edge.optional}) may violate "
                    "the runtime-root boundary; applicability is unresolved "
                    "without resolver evidence."
                )
            elif edge.applicable == APPLICABLE_NO:
                scope = "condition-not-applicable"
                severity = "AUDIT_SIGNAL"
                code = "runtime_root_forbidden_non_applicable_dependency"
                detail = (
                    f"Normal dependency {edge.package!r} is declared under a "
                    f"condition the locked resolver did not satisfy for the "
                    f"bound target; it is not part of this target's runtime graph."
                )
            elif projection is not None and edge.enters_host_closure(manifests, projection):
                # A proc-macro declared `normal` compiles and loads on the host.
                scope = "host-proc-macro-unit-declaration"
                severity = "AUDIT_SIGNAL"
                code = "runtime_root_forbidden_host_dependency"
                detail = (
                    f"Direct dependency {edge.package!r} resolves to a proc-macro, "
                    "which executes as a host build component rather than "
                    "target-runtime code."
                )
            else:
                scope = "selected-runtime-unit"
                severity = "HARD_VIOLATION"
                code = "runtime_root_forbidden_direct_dependency"
                detail = (
                    f"Direct dependency {edge.package!r} violates the "
                    "runtime-root boundary."
                )
            witness = _dependency_witness(
                rule=rule,
                rule_scope=scope,
                profile=profile,
                path=_single_edge_path(manifests, edge),
                manifests=manifests,
                ambiguous=ambiguous,
                counts=_dependency_counts(
                    manifest, profile, projection=projection, start=package
                ),
                violations=1,
                projection=projection,
            )
            findings.append(
                Finding(
                    severity,
                    code,
                    manifest.path,
                    package,
                    f"{detail} {_witness_suffix(witness)}",
                    issue,
                    witness=witness,
                )
            )

        # Transitive closures, one per projection. Each projection keeps its own
        # name and scope: a host/tooling closure reached through a proc-macro or
        # a build script is never relabelled as target runtime (defect 2).
        projections = (
            (
                PROFILE_SOURCE_RUNTIME,
                UNIT_TARGET_RUNTIME,
                "selected-runtime-unit",
                "runtime_root_forbidden_transitive_dependency",
                "Transitive closure reaches a forbidden owner",
            ),
            (
                PROFILE_SOURCE_TEST,
                UNIT_TARGET_RUNTIME,
                "test-unit-declaration",
                "runtime_root_forbidden_test_dependency",
                "Test projection reaches a forbidden owner",
            ),
            (
                PROFILE_SOURCE_BUILD,
                UNIT_TARGET_RUNTIME,
                "host-build-unit-declaration",
                "runtime_root_forbidden_build_dependency",
                "Build/tooling projection reaches a forbidden owner",
            ),
            (
                PROFILE_SOURCE_HOST_TOOLING,
                UNIT_TARGET_RUNTIME,
                "host-tooling-unit",
                "runtime_root_forbidden_host_dependency",
                "Host/tooling projection reaches a forbidden owner",
            ),
        )
        for profile, start_unit, base_scope, code, label in projections:
            path, frontier = _typed_dependency_path(
                manifests,
                ambiguous,
                package,
                predicate,
                profile,
                start_unit=start_unit,
            )
            if path is not None and len(path.edges) > 1:
                chain = " -> ".join(
                    [package, *(edge.package for edge in path.edges)]
                )
                if path.conditional_hops:
                    scope = "conditional-unresolved"
                elif path.terminal_unit != UNIT_TARGET_RUNTIME:
                    # The closure left target-runtime compilation; name the unit
                    # it ended in instead of calling it runtime.
                    scope = f"{base_scope}:{path.terminal_unit}"
                elif not all(edge.resolved for edge in path.edges):
                    scope = "unresolved-frontier"
                else:
                    scope = base_scope
                witness = _dependency_witness(
                    rule=rule,
                    rule_scope=scope,
                    profile=profile,
                    path=path,
                    manifests=manifests,
                    ambiguous=ambiguous,
                    counts=_dependency_counts(
                        manifest, profile, projection=projection, start=package
                    ),
                    violations=1,
                    projection=projection,
                )
                findings.append(
                    Finding(
                        "AUDIT_SIGNAL",
                        code,
                        manifest.path,
                        package,
                        f"{label}: {chain}. {_witness_suffix(witness)}",
                        issue,
                        witness=witness,
                    )
                )
            elif frontier.exhausted:
                # Bounds reached with no path: an explicit incomplete-audit
                # result, never a clean exit (defect 5).
                witness = _dependency_witness(
                    rule=rule,
                    rule_scope="incomplete-audit-bounds-reached",
                    profile=profile,
                    path=None,
                    manifests=manifests,
                    ambiguous=ambiguous,
                    counts=_dependency_counts(
                        manifest, profile, projection=projection, start=package
                    ),
                    violations=0,
                    projection=projection,
                )
                witness["frontier"] = frontier.evidence()
                findings.append(
                    Finding(
                        "AUDIT_SIGNAL",
                        "runtime_root_closure_incomplete",
                        manifest.path,
                        package,
                        f"Bounded {profile} closure search for {package!r} hit its "
                        f"bound ({frontier.truncated_at_hop_bound} at the "
                        f"{frontier.max_hops}-hop limit, "
                        f"{frontier.truncated_at_node_bound} at the "
                        f"{frontier.max_nodes}-node limit) without a verdict, so "
                        "this projection is an incomplete audit, not a clean pass."
                        f" {_witness_suffix(witness)}",
                        issue,
                        witness=witness,
                    )
                )

    for manifest in sorted(manifests.values(), key=lambda item: item.name):
        for edge in manifest.dependency_edges:
            if edge.resolved:
                continue
            reason = _RESOLUTION_REASONS.get(
                edge.resolution, f"resolution {edge.resolution!r}"
            )
            witness = _dependency_witness(
                rule="manifest-parse",
                rule_scope="resolution-incomplete",
                profile=PROFILE_SOURCE_WIDE,
                path=_single_edge_path(manifests, edge),
                manifests=manifests,
                ambiguous=ambiguous,
                counts=_dependency_counts(
                    manifest, PROFILE_SOURCE_WIDE, projection=projection, start=manifest.name
                ),
                violations=1,
                projection=projection,
            )
            findings.append(
                Finding(
                    "AUDIT_SIGNAL",
                    "dependency_resolution_incomplete",
                    manifest.path,
                    manifest.name,
                    f"Dependency declaration {edge.alias!r} in {edge.section} "
                    f"cannot be resolved ({reason}); evidence is incomplete, "
                    f"not absent. {_witness_suffix(witness)}",
                    witness=witness,
                )
            )

    return findings


def _production_prefix(content: str) -> str:
    match = CFG_TEST_PATTERN.search(content)
    return content if match is None else content[: match.start()]


def _contains_direct_process_launch(content: str) -> bool:
    if not any(pattern.search(content) for pattern in PROCESS_PATTERNS):
        return False
    return "Command::new" in content or "Command :: new" in content


def _owning_package(path: Path, root: Path, manifests_by_dir: dict[Path, str]) -> str | None:
    current = path.parent
    while current != root and root in current.parents:
        package = manifests_by_dir.get(current)
        if package is not None:
            return package
        current = current.parent
    return manifests_by_dir.get(root)


def _matches_owner(relative: str, policy: dict[str, Any]) -> bool:
    for item in policy.get("process_owner", []):
        if not isinstance(item, dict):
            continue
        prefix = str(item.get("path", "")).strip().replace("\\", "/").rstrip("/")
        if relative == prefix or relative.startswith(prefix + "/"):
            return True
    return False


def _debt_map(policy: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for item in policy.get("tracked_debt", []):
        if not isinstance(item, dict):
            continue
        key = (
            str(item.get("kind", "")).strip(),
            str(item.get("path", "")).strip().replace("\\", "/"),
        )
        result[key] = item
    return result


def _narrowed_process_record(record: dict[str, Any] | None) -> bool:
    return record is not None and any(
        record.get(field) is not None for field in ("items", "operation", "cfg", "class")
    )


def _check_process_exception_scope(
    relative: str,
    package: str | None,
    record: dict[str, Any],
    sites: list[ProcessLaunchSite],
) -> list[Finding]:
    """Enforce exact item/cfg/operation/class scoping for a narrowed record."""
    findings: list[Finding] = []
    items = record.get("items")
    allowed_items = set(items) if isinstance(items, list) else None
    operation = record.get("operation")
    cfg = record.get("cfg")
    class_ = record.get("class")
    seen_items: set[str | None] = set()
    for site in sites:
        seen_items.add(site.item)
        reasons: list[str] = []
        if allowed_items is not None and site.item not in allowed_items:
            reasons.append(
                f"item {site.item!r} is not in excepted items {sorted(allowed_items)}"
            )
        if operation is not None and site.kind != operation:
            reasons.append(f"operation {site.kind!r} is outside excepted {operation!r}")
        if cfg is not None and cfg not in site.cfg_tokens:
            reasons.append(f"cfg {cfg!r} not present at site (has {list(site.cfg_tokens)})")
        if class_ == "test" and not site.is_test:
            reasons.append("record class is test-only but the site is not test-gated")
        if class_ == "build" and not (
            relative == "build.rs" or relative.endswith("/build.rs")
        ):
            reasons.append("record class is build-only but the file is not build.rs")
        if reasons:
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "process_launch_outside_excepted_item",
                    relative,
                    package,
                    f"Process launch at line {site.line} ({site.kind}, "
                    f"item={site.item!r}): " + "; ".join(reasons) + ".",
                    int(record["issue"]),
                )
            )
    if allowed_items is not None:
        unseen = sorted(name for name in allowed_items if name not in seen_items)
        if unseen:
            findings.append(
                Finding(
                    "AUDIT_SIGNAL",
                    "tracked_debt_not_observed",
                    relative,
                    None,
                    "Exact process-exception items no longer observed: "
                    f"{unseen}; review/remove the debt entry.",
                    int(record["issue"]),
                    str(record.get("remove_when", "")),
                )
            )
    return findings


def _audit_process_launch_gaps(
    relative: str,
    content: str,
    production: str,
    package: str | None,
    policy: dict[str, Any],
    debt: dict[tuple[str, str], dict[str, Any]],
    seen_debt: set[tuple[str, str]],
    findings: list[Finding],
) -> None:
    """Cover the demonstrated oracle gaps without weakening the legacy gate.

    The legacy file-level constructor check is untouched. This block adds
    verdicts ONLY for sites it can newly see: raw Win32 launch APIs (never
    covered) and constructors hidden from the legacy gate by `#[cfg(test)]`
    truncation or non-`Command` alias spellings. Same finding codes are
    reused so existing consumers keep their meaning.
    """
    if _matches_owner(relative, policy):
        return
    sites, attribution_ok = _discover_process_launch_sites(content)
    if not attribution_ok:
        # Unknown parse state blocks clearance even when no site could be
        # attributed: an unparseable file must fail explicitly rather than
        # report empty success as a cleared process boundary.
        first = ", ".join(f"line {site.line} ({site.kind})" for site in sites[:5])
        scope_note = (
            f"sites at {first}. " if first else "no site could be attributed. "
        )
        findings.append(
            Finding(
                "HARD_VIOLATION",
                "process_attribution_unknown",
                relative,
                package,
                "Process-launch evidence cannot be attributed to an item/cfg "
                f"scope (unbalanced or unparseable source); {scope_note}"
                "Unknown parse state blocks clearance instead of passing empty.",
            )
        )
        return
    if not sites:
        return
    key = ("direct_process_launch", relative)
    record = debt.get(key)
    legacy_hit = _contains_direct_process_launch(_strip_rust_noise(production)[0])
    if legacy_hit and record is None:
        # File is already hard-blocked by the legacy gate; raw sites in the
        # same file add no new disposition.
        gap_sites: list[ProcessLaunchSite] = []
    elif legacy_hit:
        gap_sites = [site for site in sites if site.kind == "raw-launch"]
    else:
        gap_sites = list(sites)
    if gap_sites:
        if record is None:
            def _site_label(site: ProcessLaunchSite) -> str:
                scope = "test-gated" if site.is_test else "production"
                cfg = f", cfg={list(site.cfg_tokens)}" if site.cfg_tokens else ""
                return (
                    f"line {site.line} ({site.kind}, {scope}{cfg}, "
                    f"item={site.item!r}): {site.text}"
                )

            detail = "; ".join(_site_label(site) for site in gap_sites[:5])
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "untracked_direct_process_launch",
                    relative,
                    package,
                    "Direct process launch outside a declared process owner "
                    "missed by the legacy constructor gate has no exact debt "
                    f"record: {detail}.",
                )
            )
        else:
            seen_debt.add(key)
            if not legacy_hit:
                findings.append(
                    Finding(
                        "TRACKED_DEBT",
                        "direct_process_launch",
                        relative,
                        package,
                        str(record.get("reason", "")),
                        int(record["issue"]),
                        str(record.get("remove_when", "")),
                    )
                )
    if _narrowed_process_record(record):
        findings.extend(_check_process_exception_scope(relative, package, record, sites))


def _audit_process_lint_config(root: Path) -> list[Finding]:
    """Cross-check root clippy.toml when present; never require it.

    The compiler-lint half of D-CLIPPY-POLICY arrives via a later controller
    handoff. While absent, enforcement rests on this source oracle alone and
    that is reported explicitly, not claimed as lint coverage.
    """
    path = root / "clippy.toml"
    if not path.is_file():
        return [
            Finding(
                "AUDIT_SIGNAL",
                "process_lint_config_pending",
                "clippy.toml",
                None,
                "Root clippy.toml is absent (controller handoff pending); "
                "compiler-lint coverage is not claimed and this report's "
                "source-oracle gap coverage stands alone.",
            )
        ]
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        return [
            Finding(
                "HARD_VIOLATION",
                "process_lint_config_unreadable",
                "clippy.toml",
                None,
                f"Root clippy.toml cannot be parsed: {error}",
            )
        ]
    entries = data.get("disallowed-methods", [])
    if not isinstance(entries, list):
        return [
            Finding(
                "HARD_VIOLATION",
                "process_lint_config_unreadable",
                "clippy.toml",
                None,
                "disallowed-methods must be a list of method paths.",
            )
        ]
    configured: set[str] = set()
    for entry in entries:
        if isinstance(entry, str):
            configured.add(entry.strip())
        elif isinstance(entry, dict) and isinstance(entry.get("path"), str):
            configured.add(str(entry["path"]).strip())
    missing = [method for method in PROCESS_LINT_METHODS if method not in configured]
    if missing:
        return [
            Finding(
                "HARD_VIOLATION",
                "process_lint_policy_drift",
                "clippy.toml",
                None,
                "Root clippy.toml omits canonical process-lint methods "
                f"declared by the boundary oracle: {missing}.",
            )
        ]
    canonical = set(PROCESS_LINT_METHODS)
    unsupported = sorted(path for path in configured if path not in canonical)
    if unsupported:
        return [
            Finding(
                "HARD_VIOLATION",
                "process_lint_policy_drift",
                "clippy.toml",
                None,
                "Root clippy.toml lists disallowed-methods outside the "
                "canonical oracle set (raw extern APIs stay oracle-owned): "
                f"{unsupported}.",
            )
        ]
    return []


def audit_source(
    root: Path, manifests: dict[str, Manifest], policy: dict[str, Any]
) -> list[Finding]:
    findings: list[Finding] = []
    manifest_dirs = {
        (root / manifest.path).parent.resolve(): manifest.name
        for manifest in manifests.values()
    }
    allowed_store_packages = set(policy.get("store_vendor", {}).get("allowed_packages", []))
    debt = _debt_map(policy)
    seen_debt: set[tuple[str, str]] = set()

    for path in _walk(root):
        if path.suffix != ".rs" or "src" not in path.parts:
            continue
        relative = _relative(root, path)
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "source_unreadable",
                    relative,
                    None,
                    f"Rust source cannot be read: {error}",
                )
            )
            continue

        package = _owning_package(path.resolve(), root.resolve(), manifest_dirs)
        production = _production_prefix(content)

        if SURRREAL_SOURCE_PATTERN.search(production) and package not in allowed_store_packages:
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "surrealdb_source_leak",
                    relative,
                    package,
                    "SurrealDB SDK use is outside the admitted storage contour.",
                    19,
                )
            )

        if _contains_direct_process_launch(_strip_rust_noise(production)[0]) and not _matches_owner(relative, policy):
            key = ("direct_process_launch", relative)
            tracked = debt.get(key)
            if tracked is None:
                findings.append(
                    Finding(
                        "HARD_VIOLATION",
                        "untracked_direct_process_launch",
                        relative,
                        package,
                        "Direct std/tokio process launch is outside a declared process owner and has no exact debt record.",
                    )
                )
            else:
                seen_debt.add(key)
                findings.append(
                    Finding(
                        "TRACKED_DEBT",
                        "direct_process_launch",
                        relative,
                        package,
                        str(tracked.get("reason", "")),
                        int(tracked["issue"]),
                        str(tracked.get("remove_when", "")),
                    )
                )

        _audit_process_launch_gaps(
            relative, content, production, package, policy, debt, seen_debt, findings
        )

        for kind, pattern in PLACEHOLDER_PATTERNS:
            if pattern.search(production):
                key = (kind, relative)
                tracked = debt.get(key)
                if tracked is None:
                    findings.append(
                        Finding(
                            "HARD_VIOLATION",
                            kind,
                            relative,
                            package,
                            "Production source contains an implementation placeholder without exact tracked debt.",
                        )
                    )
                else:
                    seen_debt.add(key)
                    findings.append(
                        Finding(
                            "TRACKED_DEBT",
                            kind,
                            relative,
                            package,
                            str(tracked.get("reason", "")),
                            int(tracked["issue"]),
                            str(tracked.get("remove_when", "")),
                        )
                    )

        if relative.startswith("bins/"):
            logical_lines = sum(
                1
                for line in content.splitlines()
                if line.strip() and not line.lstrip().startswith("//")
            )
            if logical_lines > 2500:
                findings.append(
                    Finding(
                        "AUDIT_SIGNAL",
                        "large_composition_source",
                        relative,
                        package,
                        f"Composition source has {logical_lines} nonblank/non-comment lines; split only at a causal owner/proof seam.",
                    )
                )
            if CFG_TEST_PATTERN.search(content):
                findings.append(
                    Finding(
                        "AUDIT_SIGNAL",
                        "embedded_composition_tests",
                        relative,
                        package,
                        "Composition source contains an in-file cfg(test) cluster; verify that independent proofs live at the owning cell boundary.",
                    )
                )

    for key, item in debt.items():
        if key in seen_debt:
            continue
        path = key[1]
        if (root / path).is_file():
            findings.append(
                Finding(
                    "AUDIT_SIGNAL",
                    "tracked_debt_not_observed",
                    path,
                    None,
                    "Exact debt record exists but the scanner did not observe the corresponding source pattern; review/remove the debt entry.",
                    int(item["issue"]),
                    str(item.get("remove_when", "")),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# I12.14 hot-path manifest binding
# ---------------------------------------------------------------------------

HOT_PATH_MANIFEST_RELPATHS = {
    "eliot-kernel": "bins/eliot-kernel/hot-path.toml",
    "eliotd": "bins/eliotd/hot-path.toml",
}
HOT_PATH_CONTRACT_OWNER = "eliot-runtime-contracts"


def _hot_path_manifest_owner(manifest: dict[str, Any]) -> str | None:
    declared = manifest.get("owning_service")
    return str(declared) if isinstance(declared, str) else None


# The operation-id literal syntaxes that are real dispatch sites. Each pattern
# matches one closed position in Rust that names the id the surrounding code
# actually serves, so a declaration can only bind an id the source dispatches.
#
# The accepted positions are deliberately closed, because an open "any quoted
# string on its own line" rule collects the whole vocabulary of the service:
# measured against current source, an open line-prefix rule accepts 317 ids in
# `bins/eliot-kernel` and 161 in `bins/eliotd` (including `password`,
# `api_key`, `powershell`, `os.system` and `console.log`), against 67 and 34
# for the closed rules. An open rule therefore makes the S4/A4 registered
# comparison unable to fail for any id a reader could invent, which is the
# weaker check this binding exists to prevent.
_HOT_PATH_JSON_PAYLOAD_OPERATION = re.compile(
    r'"operation"\s*:\s*"([a-z][A-Za-z0-9_.]*)"'
)
_HOT_PATH_TRANSACT_OPERATION = re.compile(
    r'\btransact_async\s*\(\s*"([a-z][A-Za-z0-9_.]*)"'
)
# A closed `match` arm, such as `"local_read_claim" => "local_read_claim",`.
_HOT_PATH_DISPATCH_ARM = re.compile(r'^\s*"([a-z][A-Za-z0-9_.]*)"\s*=>')
# One alternative of a closed allow-list, such as `| "local_read_result"`.
_HOT_PATH_ALLOW_ARM = re.compile(r'^\s*\|\s*"([a-z][A-Za-z0-9_.]*)"\s*,?\s*$')


def _registered_operation_ids(root: Path, relpath: str) -> set[str]:
    """The operation ids the owning service's production source actually dispatches.

    This is the authoritative side of the S4/A4 comparison: the ids come from
    the production source that dispatches them, never from the declaration.
    Four closed dispatch shapes all count, because all four are the code that
    actually serves the id: a single-`operation`-key payload such as
    `{"operation": "local_read_claim"}`, a closed dispatch match arm, the
    closed allow-list alternative the frame admission admits, and the outbound
    IPC leg that names the id as the first positional argument of the Kernel
    transaction client (`transact_async("local_read_result", ..)`). The
    transaction shape is load-bearing for the daemon half: `eliotd` dispatches
    `local_read_result` nowhere in a match arm, so without it a correct
    declaration would fail against an id its own source really serves.

    Test-only code is excluded, so an id that only a test dispatches is not
    registered.
    """
    source_dir = (root / relpath).parent
    registered: set[str] = set()
    for path in sorted(source_dir.rglob("*.rs")):
        try:
            content = _production_prefix(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        if not content:
            continue
        for pattern in (_HOT_PATH_JSON_PAYLOAD_OPERATION, _HOT_PATH_TRANSACT_OPERATION):
            registered.update(match.group(1) for match in pattern.finditer(content))
        for line in content.splitlines():
            for pattern in (_HOT_PATH_DISPATCH_ARM, _HOT_PATH_ALLOW_ARM):
                match = pattern.match(line)
                if match is not None:
                    registered.add(match.group(1))
                    break
    return registered


def _manifest_source_for_closure(root: Path, crate_name: str) -> Path | None:
    for candidate in sorted(root.glob(f"crates/**/{crate_name}/Cargo.toml")) + sorted(
        root.glob(f"bins/**/{crate_name}/Cargo.toml")
    ):
        return candidate
    return None


def audit_hot_path_manifests(
    root: Path, manifests: dict[str, Manifest]
) -> list[Finding]:
    """Binds each I12.14 service manifest to the running build's real inputs.

    Four distinct bindings, each with a different authoritative side:

    1. every `supported_operations` row must name an operation the owning
       service's production source actually dispatches (source/build side);
    2. every `entrypoint` must resolve to a real file and a real `fn` in it,
       so a declared entrypoint cannot be a plausible-looking invented path;
    3. every `crate_closure` entry must be a real workspace package that
       declares a non-dev production edge from the owning service, so the
       declared in-process closure is a subset of the real production target
       graph rather than a list of names;
    4. every `unsupported_operations` row must NOT appear in that registered
       set, so an operation the source refuses cannot simultaneously be
       declared unsupported and be listed as a working row elsewhere.

    This is static source/build evidence. It never claims a dynamic callback
    graph is proved: the closure check is a declared-edge subset over Cargo's
    static DAG, and the operation check is a dispatch-marker read, not an
    executed trace.
    """
    findings: list[Finding] = []

    for service, relpath in sorted(HOT_PATH_MANIFEST_RELPATHS.items()):
        path = root / relpath
        if not path.is_file():
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "hot_path_manifest_absent",
                    relpath,
                    service,
                    "The service-local I12.14 hot-path manifest is absent; the "
                    "service has no authoritative declaration source.",
                )
            )
            continue
        try:
            manifest = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "hot_path_manifest_unreadable",
                    relpath,
                    service,
                    f"The hot-path manifest does not parse: {error}",
                )
            )
            continue

        owner = _hot_path_manifest_owner(manifest)
        if owner != service:
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "hot_path_manifest_owner_mismatch",
                    relpath,
                    service,
                    f"Manifest declares owning_service {owner!r} under the "
                    f"{service!r} service manifest path.",
                )
            )

        # Authority side 1: the ids the service's own source dispatches.
        registered = _registered_operation_ids(root, relpath)

        supported = manifest.get("supported_operations") or []
        unsupported = manifest.get("unsupported_operations") or []
        if not supported:
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "hot_path_manifest_no_supported_operation",
                    relpath,
                    service,
                    "The hot-path manifest declares no supported operation.",
                )
            )
        if not isinstance(supported, list) or not isinstance(unsupported, list):
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "hot_path_manifest_operation_shape",
                    relpath,
                    service,
                    "supported_operations/unsupported_operations must both be arrays of tables.",
                )
            )
            continue

        seen_supported: set[str] = set()
        for index, row in enumerate(supported):
            if not isinstance(row, dict):
                findings.append(
                    Finding(
                        "HARD_VIOLATION",
                        "hot_path_manifest_operation_shape",
                        relpath,
                        service,
                        f"supported_operations[{index}] is not a table.",
                    )
                )
                continue
            operation = str(row.get("operation", ""))
            if operation in seen_supported:
                findings.append(
                    Finding(
                        "HARD_VIOLATION",
                        "hot_path_manifest_duplicate_operation",
                        relpath,
                        service,
                        f"Operation {operation!r} is declared more than once.",
                    )
                )
            seen_supported.add(operation)
            if operation and operation not in registered:
                findings.append(
                    Finding(
                        "HARD_VIOLATION",
                        "hot_path_operation_unregistered",
                        relpath,
                        service,
                        f"Declared operation {operation!r} is not dispatched by the "
                        "owning service's production source.",
                    )
                )

            entrypoint = str(row.get("entrypoint", ""))
            if not entrypoint:
                findings.append(
                    Finding(
                        "HARD_VIOLATION",
                        "hot_path_entrypoint_absent",
                        relpath,
                        service,
                        f"Operation {operation!r} declares no entrypoint.",
                    )
                )
            elif "::" not in entrypoint:
                findings.append(
                    Finding(
                        "HARD_VIOLATION",
                        "hot_path_entrypoint_malformed",
                        relpath,
                        service,
                        f"Operation {operation!r} entrypoint {entrypoint!r} is not "
                        "a path.rs::symbol reference.",
                    )
                )
            else:
                entry_path, entry_symbol = entrypoint.rsplit("::", 1)
                owner_file = root / entry_path
                if not owner_file.is_file():
                    findings.append(
                        Finding(
                            "HARD_VIOLATION",
                            "hot_path_entrypoint_unresolved",
                            relpath,
                            service,
                            f"Operation {operation!r} entrypoint file {entry_path!r} "
                            "does not exist.",
                        )
                    )
                else:
                    entry_content = owner_file.read_text(
                        encoding="utf-8", errors="replace"
                    )
                    if not re.search(
                        r"\bfn\s+" + re.escape(entry_symbol) + r"\b", entry_content
                    ):
                        findings.append(
                            Finding(
                                "HARD_VIOLATION",
                                "hot_path_entrypoint_unresolved",
                                relpath,
                                service,
                                f"Operation {operation!r} entrypoint symbol "
                                f"{entry_symbol!r} is absent from {entry_path!r}.",
                            )
                        )

            # Authority side 3: the production target/feature graph. Each
            # declared closure crate must exist as a workspace package and must
            # be reachable from the service by non-dev Cargo declarations. The
            # service's own package is its closure root, so it is admitted by
            # being the owner rather than by a self-edge that cannot exist.
            closure = row.get("crate_closure") or []
            if not isinstance(closure, list) or not closure:
                findings.append(
                    Finding(
                        "HARD_VIOLATION",
                        "hot_path_closure_absent",
                        relpath,
                        service,
                        f"Operation {operation!r} declares no in-process crate closure.",
                    )
                )
                continue
            if service not in [str(name) for name in closure]:
                findings.append(
                    Finding(
                        "HARD_VIOLATION",
                        "hot_path_closure_root_absent",
                        relpath,
                        service,
                        f"Operation {operation!r} declares a crate closure that does "
                        f"not include its own owning package {service!r}.",
                    )
                )
            service_manifest = manifests.get(service)
            for crate_name in closure:
                crate_name = str(crate_name)
                if _manifest_source_for_closure(root, crate_name) is None:
                    findings.append(
                        Finding(
                            "HARD_VIOLATION",
                            "hot_path_closure_crate_absent",
                            relpath,
                            service,
                            f"Operation {operation!r} names closure crate "
                            f"{crate_name!r}, which is not a workspace package.",
                        )
                    )
                    continue
                # The owning package is trivially in its own closure: it is the
                # closure root, admitted by being the owner rather than by a
                # self-edge that cannot exist. The exception is exactly the
                # owning package -- every other named crate, however internal it
                # is meant to be, must show a real production edge, so declaring
                # a crate internal cannot make it pass. An unresolvable owner is
                # itself a hard violation rather than a reason to skip the check.
                if crate_name == service:
                    continue
                if service_manifest is None:
                    findings.append(
                        Finding(
                            "HARD_VIOLATION",
                            "hot_path_closure_owner_unresolved",
                            relpath,
                            service,
                            f"Operation {operation!r} declares a crate closure, but the "
                            f"owning package {service!r} is absent from current Cargo "
                            "metadata, so no production edge can be checked.",
                        )
                    )
                    break
                if not any(
                    edge.package == crate_name and edge.kind in {"normal", "build"}
                    for edge in service_manifest.dependency_edges
                ):
                    findings.append(
                        Finding(
                            "HARD_VIOLATION",
                            "hot_path_closure_edge_absent",
                            relpath,
                            service,
                            f"Operation {operation!r} names closure crate "
                            f"{crate_name!r}, which has no production dependency "
                            f"edge from {service!r} in the production target graph.",
                        )
                    )

        for index, row in enumerate(unsupported):
            if not isinstance(row, dict):
                findings.append(
                    Finding(
                        "HARD_VIOLATION",
                        "hot_path_manifest_operation_shape",
                        relpath,
                        service,
                        f"unsupported_operations[{index}] is not a table.",
                    )
                )
                continue
            operation = str(row.get("operation", ""))
            if not operation:
                findings.append(
                    Finding(
                        "HARD_VIOLATION",
                        "hot_path_unsupported_operation_absent",
                        relpath,
                        service,
                        f"unsupported_operations[{index}] names no operation.",
                    )
                )
            elif operation in seen_supported:
                findings.append(
                    Finding(
                        "HARD_VIOLATION",
                        "hot_path_operation_support_conflict",
                        relpath,
                        service,
                        f"Operation {operation!r} is both supported and unsupported.",
                    )
                )
            if operation in seen_supported and operation in registered:
                findings.append(
                    Finding(
                        "AUDIT_SIGNAL",
                        "hot_path_unsupported_operation_dispatched",
                        relpath,
                        service,
                        f"Operation {operation!r} is declared unsupported but the "
                        "owning source still dispatches it; review the declaration.",
                    )
                )

    # Authority side 2: the contract crate that owns the schema must itself be
    # a workspace package, so a manifest can never be validated against a schema
    # that no package builds.
    if _manifest_source_for_closure(root, HOT_PATH_CONTRACT_OWNER) is None:
        findings.append(
            Finding(
                "HARD_VIOLATION",
                "hot_path_contract_owner_absent",
                "crates/foundation/eliot-runtime-contracts",
                HOT_PATH_CONTRACT_OWNER,
                "The hot-path declaration contract owner is not a workspace package.",
            )
        )

    return findings


def audit(
    root: Path,
    policy_path: Path,
    *,
    projection: ResolverProjection | None = None,
) -> tuple[list[Finding], ResolverProjection]:
    policy = load_policy(policy_path)
    if projection is None:
        projection = load_resolver_projection(root)
    manifests, findings, ambiguous = load_manifests(root, projection)
    if not projection.bound:
        # Missing resolver inputs are reported, never silently absorbed into a
        # "source-only" pass that still reads as selected runtime evidence.
        witness = _dependency_witness(
            rule="resolver-projection",
            rule_scope="source-only-inventory",
            profile=PROFILE_SOURCE_WIDE,
            path=None,
            manifests=manifests,
            ambiguous=ambiguous,
            counts={
                "declared_edges": sum(
                    len(manifest.dependency_edges) for manifest in manifests.values()
                ),
                "selected_edges": 0,
                "unresolved_edges": sum(
                    1
                    for manifest in manifests.values()
                    for edge in manifest.dependency_edges
                    if not edge.resolved
                ),
                "resolver_bound": False,
                "denominator": (
                    "no locked offline resolver projection was bound; every "
                    "witness below is a source-wide declaration inventory"
                ),
            },
            violations=0,
            projection=projection,
        )
        findings.append(
            Finding(
                "AUDIT_SIGNAL",
                "resolver_projection_unavailable",
                "config/architecture-boundaries.toml",
                None,
                "No locked offline cargo metadata projection could be bound "
                f"({projection.detail}); runtime-root evidence is the "
                "source-wide declaration inventory and every completeness value "
                "stays incomplete. "
                f"{_witness_suffix(witness)}",
                witness=witness,
            )
        )
    findings.extend(validate_policy(root, policy))
    findings.extend(_audit_process_lint_config(root))
    unresolved_manifests = frozenset(
        finding.path
        for finding in findings
        if finding.code == "dependency_resolution_incomplete"
    )
    findings.extend(
        audit_dependencies(
            manifests, policy, ambiguous, unresolved_manifests, projection
        )
    )
    findings.extend(audit_source(root, manifests, policy))
    findings.extend(audit_hot_path_manifests(root, manifests))
    return (
        sorted(
            findings,
            key=lambda finding: (
                {"HARD_VIOLATION": 0, "TRACKED_DEBT": 1, "AUDIT_SIGNAL": 2}.get(
                    finding.severity, 9
                ),
                finding.code,
                finding.path,
                finding.detail,
            ),
        ),
        projection,
    )


def print_human(findings: list[Finding], projection: ResolverProjection | None = None) -> None:
    counts = Counter(finding.severity for finding in findings)
    print(
        "ARCHITECTURE_BOUNDARY_AUDIT: "
        f"hard={counts['HARD_VIOLATION']} "
        f"debt={counts['TRACKED_DEBT']} "
        f"signals={counts['AUDIT_SIGNAL']}"
    )
    if projection is not None:
        print(
            "ARCHITECTURE_BOUNDARY_RESOLVER: "
            f"bound={str(projection.bound).lower()} "
            f"source={projection.source} "
            f"metadata={projection.source} "
            f"root_target={projection.root_target} "
            f"host_triple={projection.host_triple} "
            f"target_triple={projection.target_triple} "
            f"feature_selection={projection.feature_selection} "
            f"resolver={projection.resolver} "
            f"workspace_resolver={projection.workspace_resolver} "
            f"toolchain={projection.toolchain} "
            f"source_identity={projection.source_identity} "
            f"digest={projection.digest} "
            f"packages={projection.packages_total} "
            f"workspace_members={projection.workspace_members}"
        )
        print(f"ARCHITECTURE_BOUNDARY_RESOLVER_DETAIL: {projection.detail}")
    for finding in findings:
        issue = f" issue=#{finding.issue}" if finding.issue is not None else ""
        package = f" package={finding.package}" if finding.package else ""
        print(
            f"{finding.severity}: {finding.code}: {finding.path}{package}{issue}: "
            f"{finding.detail}"
        )
        if finding.removal_condition:
            print(f"  remove_when: {finding.removal_condition}")


def write_json(
    path: Path,
    findings: list[Finding],
    projection: ResolverProjection | None = None,
) -> None:
    counts = Counter(finding.severity for finding in findings)
    payload = {
        "schema": "eliot.architecture-boundary-audit.v1",
        "proof_ceiling": "STATIC_SOURCE_BUILD_BOUNDARY_ONLY",
        "resolver_projection": (
            _profile_descriptor(PROFILE_SOURCE_WIDE, projection)
            if projection is not None
            else None
        ),
        "summary": {
            "hard_violations": counts["HARD_VIOLATION"],
            "tracked_debt": counts["TRACKED_DEBT"],
            "audit_signals": counts["AUDIT_SIGNAL"],
            "by_rule": dict(
                sorted(Counter(finding.code for finding in findings).items())
            ),
            "resolver_bound": bool(projection is not None and projection.bound),
        },
        "findings": [asdict(finding) for finding in findings],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="eliot-architecture-audit-") as temporary:
        root = Path(temporary)
        _write(
            root / "config/architecture-boundaries.toml",
            """
            schema = "eliot.architecture-boundaries.v1"
            [store_vendor]
            allowed_packages = ["store-owner"]
            [[runtime_root]]
            package = "root-bin"
            issue = 1
            forbidden_exact = ["eliot-app", "surrealdb"]
            forbidden_prefix = ["eliot-dreamer"]
            [[tracked_debt]]
            kind = "direct_process_launch"
            path = "raw-gap/src/lib.rs"
            issue = 748
            reason = "Self-test narrowed exception: only boot owns the raw launch."
            remove_when = "Self-test fixture only."
            items = ["boot"]
            operation = "raw-launch"
            class = "platform"
            """,
        )
        _write(
            root / "Cargo.toml",
            """
            [workspace]
            members = ["root-bin", "eliot-app", "surreal-leak", "cfg-hidden", "raw-gap"]
            resolver = "2"
            """,
        )
        _write(
            root / "root-bin/Cargo.toml",
            """
            [package]
            name = "root-bin"
            version = "0.1.0"
            edition = "2024"
            [dependencies]
            eliot-app = { path = "../eliot-app" }
            """,
        )
        _write(root / "root-bin/src/main.rs", "fn main() { todo!() }\n")
        _write(
            root / "eliot-app/Cargo.toml",
            """
            [package]
            name = "eliot-app"
            version = "0.1.0"
            edition = "2024"
            """,
        )
        _write(root / "eliot-app/src/lib.rs", "pub fn legacy() {}\n")
        _write(
            root / "surreal-leak/Cargo.toml",
            """
            [package]
            name = "surreal-leak"
            version = "0.1.0"
            edition = "2024"
            [dependencies]
            surrealdb = "3"
            """,
        )
        _write(
            root / "surreal-leak/src/lib.rs",
            "use std::process::Command;\npub fn bad() { let _ = Command::new(\"x\"); }\n",
        )
        # 748/T1: production constructor hidden after a test-only `use` must
        # still be discovered, while the cfg(test)-gated launch stays excluded.
        _write(
            root / "cfg-hidden/Cargo.toml",
            """
            [package]
            name = "cfg-hidden"
            version = "0.1.0"
            edition = "2024"
            """,
        )
        _write(
            root / "cfg-hidden/src/lib.rs",
            "#[cfg(test)]\n"
            "use std::io::Read;\n"
            "use std::process::Command;\n"
            "pub fn prod_launch() {\n"
            '    let _ = Command::new("prod-hidden");\n'
            "}\n"
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    use super::*;\n"
            "    #[test]\n"
            "    fn gated() {\n"
            '        let _ = Command::new("test-gated");\n'
            "    }\n"
            "}\n",
        )
        # 748/T2: raw Win32 launch covered by the oracle; a narrowed exception
        # accepts the exact item and rejects the same launch elsewhere.
        _write(
            root / "raw-gap/Cargo.toml",
            """
            [package]
            name = "raw-gap"
            version = "0.1.0"
            edition = "2024"
            """,
        )
        _write(
            root / "raw-gap/src/lib.rs",
            "pub fn boot() {\n"
            "    unsafe { CreateProcessW(None); }\n"
            "}\n"
            "pub fn other() {\n"
            "    unsafe { CreateProcessW(None); }\n"
            "}\n",
        )

        findings, projection = audit(
            root, root / "config/architecture-boundaries.toml"
        )
        if projection.bound:
            raise AssertionError(
                "self-test: the synthetic fixture must not bind a resolver "
                f"projection: {projection.detail}"
            )
        codes = {finding.code for finding in findings if finding.severity == "HARD_VIOLATION"}
        expected = {
            "surrealdb_dependency_leak",
            "untracked_direct_process_launch",
            "todo_macro",
        }
        missing = expected - codes
        if missing:
            raise AssertionError(f"self-test missed hard findings: {sorted(missing)}")
        # A forbidden runtime-root dependency in this fixture is reported as
        # INCOMPLETE evidence, not a hard violation, because the fixture
        # deliberately binds no resolver (asserted just above). Claiming a
        # selected-runtime hard violation from an unselected declaration is the
        # defect this audit removed, so the hard set must NOT contain it and the
        # typed incomplete finding must be present instead.
        all_codes = {finding.code for finding in findings}
        incomplete_codes = {
            "runtime_root_forbidden_unresolved_dependency",
            "runtime_root_forbidden_conditional_dependency",
        }
        if "runtime_root_forbidden_direct_dependency" in codes:
            raise AssertionError(
                "self-test: an unbound fixture must not yield a selected-runtime "
                "hard violation for a forbidden direct dependency"
            )
        if not (incomplete_codes & all_codes):
            raise AssertionError(
                "self-test: an unbound fixture must still report the forbidden "
                f"direct dependency as typed incomplete evidence; saw {sorted(all_codes)}"
            )
        by_path = lambda code, path: [
            finding
            for finding in findings
            if finding.code == code and finding.path == path
        ]
        hidden = by_path("untracked_direct_process_launch", "cfg-hidden/src/lib.rs")
        if len(hidden) != 1 or "prod-hidden" not in hidden[0].detail:
            raise AssertionError(
                "self-test 748/T1: cfg-elided production launch not discovered "
                f"exactly once: {[finding.detail for finding in hidden]}"
            )
        debt = by_path("direct_process_launch", "raw-gap/src/lib.rs")
        if len(debt) != 1 or debt[0].severity != "TRACKED_DEBT":
            raise AssertionError(
                "self-test 748/T2: narrowed raw-launch exception not honored "
                f"as tracked debt: {[(finding.severity, finding.detail) for finding in debt]}"
            )
        narrow = by_path("process_launch_outside_excepted_item", "raw-gap/src/lib.rs")
        if len(narrow) != 1 or "'other'" not in narrow[0].detail:
            raise AssertionError(
                "self-test 748/T2: same raw launch outside the excepted item "
                f"not rejected: {[finding.detail for finding in narrow]}"
            )
        if "process_attribution_unknown" in codes:
            raise AssertionError("self-test: unexpected attribution-unknown state")
    print("ARCHITECTURE_BOUNDARY_SELF_TEST: PASS")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root (default: inferred from this script).",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=None,
        help="Boundary TOML (default: <root>/config/architecture-boundaries.toml).",
    )
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    # The bounded resolver input. `--target-triple` is the ROOT TARGET the
    # projection is selected for; it defaults to the local host triple. The
    # metadata cache lets a caller supply an already-obtained locked offline
    # `cargo metadata` payload without the audit running cargo itself.
    parser.add_argument(
        "--target-triple",
        default=None,
        help=(
            "Root target triple for the resolver projection "
            "(default: the local host triple)."
        ),
    )
    parser.add_argument(
        "--cargo-metadata",
        type=Path,
        default=None,
        dest="cargo_metadata",
        help=(
            "Path to a pre-obtained locked offline `cargo metadata` JSON "
            "projection to use instead of running cargo."
        ),
    )
    parser.add_argument(
        "--no-resolver",
        action="store_true",
        help=(
            "Do not run cargo metadata; report the source-wide declaration "
            "inventory as explicitly incomplete."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        self_test()
        return 0

    root = args.root.resolve()
    policy_path = (
        args.policy.resolve()
        if args.policy is not None
        else root / "config/architecture-boundaries.toml"
    )
    projection = load_resolver_projection(
        root,
        target_triple=args.target_triple,
        metadata_cache=args.cargo_metadata.resolve()
        if args.cargo_metadata is not None
        else None,
        allow_run=not args.no_resolver,
    )
    try:
        findings, projection = audit(root, policy_path, projection=projection)
    except ValueError as error:
        print(f"HARD_VIOLATION: policy_error: {error}", file=sys.stderr)
        return 2

    print_human(findings, projection)
    if args.json_out is not None:
        write_json(args.json_out.resolve(), findings, projection)

    return 1 if any(finding.severity == "HARD_VIOLATION" for finding in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
