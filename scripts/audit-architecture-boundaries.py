#!/usr/bin/env python3
"""Audit ELIOT source/build boundaries without creating architecture authority.

The scanner consumes Cargo manifests, production Rust source, and the explicit
`config/architecture-boundaries.toml` policy. It reports three dispositions:

- HARD_VIOLATION: an untracked contradiction that must fail integration;
- TRACKED_DEBT: an exact temporary exception with owning issue and removal rule;
- AUDIT_SIGNAL: evidence that needs human review but is not an authority rule.

A clean result is static source evidence only. It is never runtime or Product
Proof.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import textwrap
import tomllib
from collections import Counter, deque
from dataclasses import asdict, dataclass
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
# SEAM: root clippy.toml does not exist yet (out of lane for this change) and
# is never required here. Exception records below carry exact item/cfg/
# operation/class fields so the future clippy.toml per-item expectations can
# mirror them 1:1. When that file exists, _audit_process_lint_config
# cross-checks its `disallowed-methods` set against PROCESS_LINT_METHODS
# (method paths only -- raw extern APIs stay oracle-owned per the probe);
# while absent, an explicit AUDIT_SIGNAL is emitted instead of claiming lint
# coverage. Unknown parse/attribution state fails explicitly via
# `process_attribution_unknown`, never empty-success.
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
            while j < n:
                if content[j] == "\\":
                    j += 2
                elif content[j] == '"':
                    closed = True
                    j += 1
                    break
                elif content[j] == "\n":
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


@dataclass(frozen=True)
class Manifest:
    name: str
    path: str
    dependencies: tuple[str, ...]


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    path: str
    package: str | None
    detail: str
    issue: int | None = None
    removal_condition: str | None = None


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _walk(root: Path, filename: str | None = None) -> Iterable[Path]:
    for current, dirs, files in os.walk(root):
        dirs[:] = [directory for directory in dirs if directory not in SKIP_DIRS]
        base = Path(current)
        for file_name in files:
            if filename is None or file_name == filename:
                yield base / file_name


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


def load_manifests(root: Path) -> tuple[dict[str, Manifest], list[Finding]]:
    manifests: dict[str, Manifest] = {}
    findings: list[Finding] = []

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

        manifest = Manifest(
            name=name.strip(),
            path=relative,
            dependencies=_manifest_dependencies(data),
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
            continue
        manifests[manifest.name] = manifest

    return manifests, findings


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
    manifests: dict[str, Manifest], policy: dict[str, Any]
) -> list[Finding]:
    findings: list[Finding] = []
    graph = build_graph(manifests)

    store_table = policy.get("store_vendor", {})
    allowed_store_packages = set(store_table.get("allowed_packages", []))
    for manifest in manifests.values():
        if "surrealdb" in manifest.dependencies and manifest.name not in allowed_store_packages:
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "surrealdb_dependency_leak",
                    manifest.path,
                    manifest.name,
                    "SurrealDB dependency is outside the admitted store contour.",
                    19,
                )
            )

    for item in policy.get("runtime_root", []):
        if not isinstance(item, dict):
            continue
        package = str(item.get("package", "")).strip()
        issue = item.get("issue") if isinstance(item.get("issue"), int) else None
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

        for dependency in manifest.dependencies:
            if predicate(dependency):
                findings.append(
                    Finding(
                        "HARD_VIOLATION",
                        "runtime_root_forbidden_direct_dependency",
                        manifest.path,
                        package,
                        f"Direct dependency {dependency!r} violates the runtime-root boundary.",
                        issue,
                    )
                )

        path = _dependency_path(graph, package, predicate)
        if path is not None and len(path) > 2:
            findings.append(
                Finding(
                    "AUDIT_SIGNAL",
                    "runtime_root_forbidden_transitive_dependency",
                    manifest.path,
                    package,
                    "Transitive closure reaches a forbidden owner: " + " -> ".join(path),
                    issue,
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
    if not sites:
        return
    key = ("direct_process_launch", relative)
    record = debt.get(key)
    if not attribution_ok:
        first = ", ".join(f"line {site.line} ({site.kind})" for site in sites[:5])
        findings.append(
            Finding(
                "HARD_VIOLATION",
                "process_attribution_unknown",
                relative,
                package,
                "Process-launch evidence cannot be attributed to an item/cfg "
                f"scope (unbalanced or unparseable source); sites at {first}. "
                "Unknown parse state blocks clearance instead of passing empty.",
            )
        )
        return
    legacy_hit = _contains_direct_process_launch(production)
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

        if _contains_direct_process_launch(production) and not _matches_owner(relative, policy):
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


def audit(root: Path, policy_path: Path) -> list[Finding]:
    policy = load_policy(policy_path)
    manifests, findings = load_manifests(root)
    findings.extend(validate_policy(root, policy))
    findings.extend(_audit_process_lint_config(root))
    findings.extend(audit_dependencies(manifests, policy))
    findings.extend(audit_source(root, manifests, policy))
    return sorted(
        findings,
        key=lambda finding: (
            {"HARD_VIOLATION": 0, "TRACKED_DEBT": 1, "AUDIT_SIGNAL": 2}.get(
                finding.severity, 9
            ),
            finding.code,
            finding.path,
        ),
    )


def print_human(findings: list[Finding]) -> None:
    counts = Counter(finding.severity for finding in findings)
    print(
        "ARCHITECTURE_BOUNDARY_AUDIT: "
        f"hard={counts['HARD_VIOLATION']} "
        f"debt={counts['TRACKED_DEBT']} "
        f"signals={counts['AUDIT_SIGNAL']}"
    )
    for finding in findings:
        issue = f" issue=#{finding.issue}" if finding.issue is not None else ""
        package = f" package={finding.package}" if finding.package else ""
        print(
            f"{finding.severity}: {finding.code}: {finding.path}{package}{issue}: "
            f"{finding.detail}"
        )
        if finding.removal_condition:
            print(f"  remove_when: {finding.removal_condition}")


def write_json(path: Path, findings: list[Finding]) -> None:
    counts = Counter(finding.severity for finding in findings)
    payload = {
        "schema": "eliot.architecture-boundary-audit.v1",
        "proof_ceiling": "STATIC_SOURCE_BUILD_BOUNDARY_ONLY",
        "summary": {
            "hard_violations": counts["HARD_VIOLATION"],
            "tracked_debt": counts["TRACKED_DEBT"],
            "audit_signals": counts["AUDIT_SIGNAL"],
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

        findings = audit(root, root / "config/architecture-boundaries.toml")
        codes = {finding.code for finding in findings if finding.severity == "HARD_VIOLATION"}
        expected = {
            "runtime_root_forbidden_direct_dependency",
            "surrealdb_dependency_leak",
            "untracked_direct_process_launch",
            "todo_macro",
        }
        missing = expected - codes
        if missing:
            raise AssertionError(f"self-test missed hard findings: {sorted(missing)}")
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
    try:
        findings = audit(root, policy_path)
    except ValueError as error:
        print(f"HARD_VIOLATION: policy_error: {error}", file=sys.stderr)
        return 2

    print_human(findings)
    if args.json_out is not None:
        write_json(args.json_out, findings)

    return 1 if any(finding.severity == "HARD_VIOLATION" for finding in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
