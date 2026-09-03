#!/usr/bin/env python3
"""Report production-source hygiene risks in ELIOT runtime roots.

This companion to `audit-architecture-boundaries.py` intentionally separates
heuristic code-quality signals from hard architecture ownership rules. It scans
only declared runtime-root packages and composition binaries, masks comments and
string/character literals, and removes exactly the items annotated
`#[cfg(test)]` — not the whole file suffix after the first such marker.

A clean result is static source evidence only. It is not runtime, store or
Product Proof, and metrics never create an owner or mandate a split by LOC.
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
from collections import Counter
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
}

CFG_TEST = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")

PATTERNS: dict[str, re.Pattern[str]] = {
    "unsafe": re.compile(r"\bunsafe\s+(?:async\s+)?(?:fn\b|impl\b|trait\b|extern\b)|\bunsafe\s*\{"),
    "panic": re.compile(r"\bpanic\s*!\s*\("),
    "unwrap": re.compile(r"\.\s*unwrap\s*\(\s*\)"),
    "expect": re.compile(r"\.\s*expect\s*\("),
    "ambient_env": re.compile(
        r"\b(?:std\s*::\s*)?env\s*::\s*(?:var|var_os|vars|vars_os|current_dir|set_current_dir|temp_dir)\s*\("
    ),
    "unbounded_output": re.compile(
        r"\b(?:wait_with_output|read_to_end|read_to_string)\s*\(|"
        r"\.\s*(?:stdout|stderr)\s*\(\s*(?:std\s*::\s*process\s*::\s*)?Stdio\s*::\s*null\s*\("
    ),
    "blocking_sleep": re.compile(r"\b(?:std\s*::\s*)?thread\s*::\s*sleep\s*\("),
}


@dataclass(frozen=True)
class SourceMetric:
    package: str
    path: str
    production_lines: int
    cfg_test_present: bool
    forbids_unsafe: bool
    unsafe_count: int
    panic_count: int
    unwrap_count: int
    expect_count: int
    ambient_env_count: int
    unbounded_output_count: int
    blocking_sleep_count: int


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    package: str
    path: str
    count: int
    detail: str
    issue: int | None = None


def walk(root: Path, filename: str | None = None) -> Iterable[Path]:
    for current, dirs, files in os.walk(root):
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS]
        base = Path(current)
        for name in files:
            if filename is None or name == filename:
                yield base / name


def relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def load_policy(path: Path) -> dict[str, Any]:
    try:
        policy = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ValueError(f"cannot load architecture-boundary policy: {error}") from error
    if policy.get("schema") != "eliot.architecture-boundaries.v1":
        raise ValueError("unsupported architecture-boundary policy schema")
    return policy


def package_manifests(root: Path) -> tuple[dict[str, Path], dict[Path, str]]:
    by_name: dict[str, Path] = {}
    by_dir: dict[Path, str] = {}
    for path in walk(root, "Cargo.toml"):
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError):
            continue
        package = data.get("package")
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        directory = path.parent.resolve()
        by_name[name.strip()] = directory
        by_dir[directory] = name.strip()
    return by_name, by_dir


def owning_package(path: Path, root: Path, by_dir: dict[Path, str]) -> str | None:
    current = path.parent.resolve()
    resolved_root = root.resolve()
    while True:
        package = by_dir.get(current)
        if package is not None:
            return package
        if current == resolved_root or resolved_root not in current.parents:
            return None
        current = current.parent


def _end_of_annotated_item(masked: str, start: int) -> int:
    """Return the offset just past the item that begins at or after `start`.

    An item ends at its matching closing brace (`mod tests { … }`, `fn helper()
    { … }`) or at the first top-level semicolon (`mod tests;`, `use super::*;`).
    Further attributes stacked on the same item are skipped first. `masked` must
    come from `mask_non_code`, so braces inside strings, chars and comments are
    already blanked and cannot unbalance the scan.
    """
    index = start
    length = len(masked)
    while index < length:
        char = masked[index]
        if char.isspace():
            index += 1
            continue
        if char == "#":  # another attribute on the same item
            depth = 0
            while index < length:
                if masked[index] == "[":
                    depth += 1
                elif masked[index] == "]":
                    depth -= 1
                    if depth == 0:
                        index += 1
                        break
                index += 1
            continue
        break

    depth = 0
    while index < length:
        char = masked[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
        elif char == ";" and depth == 0:
            return index + 1
        index += 1
    return length


def production_source(content: str) -> tuple[str, bool]:
    """Return the source with `#[cfg(test)]` items removed, and whether any existed.

    The previous implementation returned only the prefix before the first
    `#[cfg(test)]` marker, so every later item in the file was discarded whether
    or not it was test code. Measured on this tree that hid 183 files and
    167 434 lines from every hygiene signal, including 588 `pub fn` and 233
    `unsafe` blocks — 143 of them in `eliot-platform-windows/src/lib.rs` alone.
    `forbid(unsafe_code)` was therefore only ever verified in a file's prefix.
    """
    masked = mask_non_code(content)
    kept: list[str] = []
    cursor = 0
    found = False
    for match in CFG_TEST.finditer(masked):
        if match.start() < cursor:
            continue
        found = True
        kept.append(content[cursor : match.start()])
        cursor = _end_of_annotated_item(masked, match.end())
    kept.append(content[cursor:])
    return "".join(kept), found


def _raw_string_start(text: str, index: int) -> tuple[int, int] | None:
    """Return (content_start, hash_count) for r###"..."### or br###"..."###."""
    cursor = index
    if text.startswith("br", cursor):
        cursor += 2
    elif text.startswith("r", cursor):
        cursor += 1
    else:
        return None
    hashes = 0
    while cursor < len(text) and text[cursor] == "#":
        hashes += 1
        cursor += 1
    if cursor < len(text) and text[cursor] == '"':
        return cursor + 1, hashes
    return None


def mask_non_code(text: str) -> str:
    """Replace comments and literals with spaces while preserving newlines."""
    chars = list(text)
    output = ["\n" if char == "\n" else " " for char in chars]
    i = 0
    block_depth = 0
    state = "code"
    raw_hashes = 0

    while i < len(chars):
        char = chars[i]
        nxt = chars[i + 1] if i + 1 < len(chars) else ""

        if state == "line_comment":
            if char == "\n":
                output[i] = "\n"
                state = "code"
            i += 1
            continue

        if state == "block_comment":
            if char == "/" and nxt == "*":
                block_depth += 1
                i += 2
                continue
            if char == "*" and nxt == "/":
                block_depth -= 1
                i += 2
                if block_depth == 0:
                    state = "code"
                continue
            i += 1
            continue

        if state == "string":
            if char == "\\":
                i += 2
                continue
            if char == '"':
                state = "code"
            i += 1
            continue

        if state == "char":
            if char == "\\":
                i += 2
                continue
            if char == "'":
                state = "code"
            i += 1
            continue

        if state == "raw":
            if char == '"' and text.startswith("#" * raw_hashes, i + 1):
                i += 1 + raw_hashes
                state = "code"
            i += 1
            continue

        # code
        if char == "/" and nxt == "/":
            state = "line_comment"
            i += 2
            continue
        if char == "/" and nxt == "*":
            state = "block_comment"
            block_depth = 1
            i += 2
            continue

        raw = _raw_string_start(text, i)
        if raw is not None:
            content_start, raw_hashes = raw
            i = content_start
            state = "raw"
            continue

        if char == '"':
            state = "string"
            i += 1
            continue
        if char == "'":
            # Lifetimes are followed by an identifier and have no closing quote.
            if nxt and (nxt.isalpha() or nxt == "_"):
                output[i] = char
                i += 1
                continue
            state = "char"
            i += 1
            continue

        output[i] = char
        i += 1

    return "".join(output)


def count_patterns(code: str) -> dict[str, int]:
    return {name: len(pattern.findall(code)) for name, pattern in PATTERNS.items()}


def runtime_packages(policy: dict[str, Any]) -> dict[str, int]:
    packages: dict[str, int] = {}
    for item in policy.get("runtime_root", []):
        if not isinstance(item, dict):
            continue
        name = str(item.get("package", "")).strip()
        issue = item.get("issue")
        if name:
            packages[name] = int(issue) if isinstance(issue, int) else 0
    return packages


def scan(root: Path, policy_path: Path) -> tuple[list[SourceMetric], list[Finding]]:
    policy = load_policy(policy_path)
    roots = runtime_packages(policy)
    _, by_dir = package_manifests(root)
    metrics: list[SourceMetric] = []
    findings: list[Finding] = []

    for path in walk(root):
        if path.suffix != ".rs" or "src" not in path.parts:
            continue
        package = owning_package(path, root, by_dir)
        rel = relative(root, path)
        is_composition = rel.startswith("bins/")
        if package not in roots and not is_composition:
            continue

        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "source_unreadable",
                    package or "<unknown>",
                    rel,
                    1,
                    str(error),
                    roots.get(package or ""),
                )
            )
            continue

        production, has_cfg_test = production_source(content)
        code = mask_non_code(production)
        counts = count_patterns(code)
        forbids_unsafe = bool(re.search(r"#!\s*\[\s*forbid\s*\(\s*unsafe_code\s*\)\s*\]", production))
        production_lines = sum(1 for line in production.splitlines() if line.strip())
        package_name = package or "<unknown>"
        issue = roots.get(package_name)

        metric = SourceMetric(
            package=package_name,
            path=rel,
            production_lines=production_lines,
            cfg_test_present=has_cfg_test,
            forbids_unsafe=forbids_unsafe,
            unsafe_count=counts["unsafe"],
            panic_count=counts["panic"],
            unwrap_count=counts["unwrap"],
            expect_count=counts["expect"],
            ambient_env_count=counts["ambient_env"],
            unbounded_output_count=counts["unbounded_output"],
            blocking_sleep_count=counts["blocking_sleep"],
        )
        metrics.append(metric)

        if is_composition and counts["unsafe"]:
            findings.append(
                Finding(
                    "HARD_VIOLATION",
                    "unsafe_in_composition_root",
                    package_name,
                    rel,
                    counts["unsafe"],
                    "Composition binaries must delegate unsafe OS/FFI mechanics to an admitted owner crate.",
                    issue,
                )
            )
        elif counts["unsafe"]:
            findings.append(
                Finding(
                    "AUDIT_SIGNAL",
                    "unsafe_runtime_source",
                    package_name,
                    rel,
                    counts["unsafe"],
                    "Review SAFETY invariants, owner, platform confinement and negative proof.",
                    issue,
                )
            )

        if is_composition and not forbids_unsafe:
            findings.append(
                Finding(
                    "AUDIT_SIGNAL",
                    "composition_does_not_forbid_unsafe",
                    package_name,
                    rel,
                    1,
                    "Composition source does not declare `#![forbid(unsafe_code)]`; actual unsafe remains a hard violation.",
                    issue,
                )
            )

        signal_details = {
            "panic": "Production panic path requires typed failure/terminal disposition review.",
            "unwrap": "Production unwrap requires an explicit invariant or typed error path.",
            "expect": "Production expect requires an explicit invariant or typed error path.",
            "ambient_env": "Ambient environment/current-directory input requires typed configuration, identity and privacy review.",
            "unbounded_output": "Potentially unbounded or discarded output requires limits, omission evidence and terminal-state review.",
            "blocking_sleep": "Blocking sleep in a runtime root requires scheduling/control-reserve and shutdown review.",
        }
        for name, detail in signal_details.items():
            if counts[name]:
                findings.append(
                    Finding(
                        "AUDIT_SIGNAL",
                        f"runtime_{name}",
                        package_name,
                        rel,
                        counts[name],
                        detail,
                        issue,
                    )
                )

    metrics.sort(key=lambda item: (item.package, item.path))
    rank = {"HARD_VIOLATION": 0, "AUDIT_SIGNAL": 1}
    findings.sort(key=lambda item: (rank.get(item.severity, 9), item.code, item.package, item.path))
    return metrics, findings


def print_human(metrics: list[SourceMetric], findings: list[Finding]) -> None:
    counts = Counter(item.severity for item in findings)
    print(
        "RUNTIME_SOURCE_HYGIENE: "
        f"hard={counts['HARD_VIOLATION']} signals={counts['AUDIT_SIGNAL']} files={len(metrics)}"
    )
    for item in findings:
        issue = f" issue=#{item.issue}" if item.issue else ""
        print(
            f"{item.severity}: {item.code}: {item.path} package={item.package} count={item.count}{issue}: {item.detail}"
        )


def write_json(path: Path, metrics: list[SourceMetric], findings: list[Finding]) -> None:
    counts = Counter(item.severity for item in findings)
    totals = Counter()
    for metric in metrics:
        for field in (
            "production_lines",
            "unsafe_count",
            "panic_count",
            "unwrap_count",
            "expect_count",
            "ambient_env_count",
            "unbounded_output_count",
            "blocking_sleep_count",
        ):
            totals[field] += int(getattr(metric, field))
    payload = {
        "schema": "eliot.runtime-source-hygiene.v1",
        "proof_ceiling": "STATIC_SOURCE_QUALITY_SIGNAL_ONLY",
        "summary": {
            "hard_violations": counts["HARD_VIOLATION"],
            "audit_signals": counts["AUDIT_SIGNAL"],
            "files_scanned": len(metrics),
            "totals": dict(sorted(totals.items())),
        },
        "metrics": [asdict(item) for item in metrics],
        "findings": [asdict(item) for item in findings],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_fixture(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="eliot-runtime-hygiene-") as temporary:
        root = Path(temporary)
        write_fixture(
            root / "config/architecture-boundaries.toml",
            """
            schema = "eliot.architecture-boundaries.v1"
            [[runtime_root]]
            package = "runtime-bin"
            issue = 9
            """,
        )
        write_fixture(
            root / "bins/runtime-bin/Cargo.toml",
            """
            [package]
            name = "runtime-bin"
            version = "0.1.0"
            edition = "2024"
            """,
        )
        write_fixture(
            root / "bins/runtime-bin/src/main.rs",
            r'''
            // unsafe { panic!("comment") }
            const TEXT: &str = "panic!( unwrap() unsafe {";
            fn main() {
                unsafe { foreign(); }
                let _ = std::env::var("X").unwrap();
                panic!("boom");
            }
            unsafe fn foreign() {}
            #[cfg(test)]
            mod tests { #[test] fn ignored() { panic!("test"); } }
            ''',
        )
        metrics, findings = scan(root, root / "config/architecture-boundaries.toml")
        hard = {item.code for item in findings if item.severity == "HARD_VIOLATION"}
        signals = {item.code for item in findings if item.severity == "AUDIT_SIGNAL"}
        assert "unsafe_in_composition_root" in hard
        assert {"runtime_panic", "runtime_unwrap", "runtime_ambient_env"} <= signals
        assert len(metrics) == 1
        assert metrics[0].panic_count == 1
        assert metrics[0].unsafe_count == 2

    # Regression fixtures for the three defects this scanner shipped with.
    # Each one passed before the repair and fails without it.
    with tempfile.TemporaryDirectory(prefix="eliot-runtime-hygiene-tail-") as temporary:
        root = Path(temporary)
        write_fixture(
            root / "config/architecture-boundaries.toml",
            """
            schema = "eliot.architecture-boundaries.v1"
            [[runtime_root]]
            package = "tail-bin"
            issue = 9
            """,
        )
        write_fixture(
            root / "bins/tail-bin/Cargo.toml",
            """
            [package]
            name = "tail-bin"
            version = "0.1.0"
            edition = "2024"
            """,
        )
        # Production code after a `#[cfg(test)]` item, plus `unsafe async fn`.
        # Prefix splitting discarded everything from the marker onward, so both
        # the trailing `unsafe` and the trailing `panic!` were invisible.
        write_fixture(
            root / "bins/tail-bin/src/main.rs",
            r'''
            fn main() { unsafe { first(); } }
            #[cfg(test)]
            mod tests { #[test] fn ignored() { panic!("test"); unsafe { hidden(); } } }
            unsafe fn first() {}
            pub unsafe async fn second() { panic!("production tail"); }
            ''',
        )
        metrics, findings = scan(root, root / "config/architecture-boundaries.toml")
        assert len(metrics) == 1, metrics
        # `unsafe {` in main, `unsafe fn first`, `unsafe async fn second`.
        # The `unsafe {` inside the test module is excluded.
        assert metrics[0].unsafe_count == 3, metrics[0].unsafe_count
        # Only the `panic!` after the test module; the one inside it is excluded.
        assert metrics[0].panic_count == 1, metrics[0].panic_count
        assert metrics[0].cfg_test_present is True

    # `research` and `swarm` were skipped wholesale, hiding real source.
    assert "research" not in SKIP_DIRS
    assert "swarm" not in SKIP_DIRS
    # `unsafe async fn` was not matched by the previous pattern.
    assert PATTERNS["unsafe"].search("pub unsafe async fn f() {}") is not None
    print("RUNTIME_SOURCE_HYGIENE_SELF_TEST: PASS")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    root = args.root.resolve()
    policy = args.policy.resolve() if args.policy else root / "config/architecture-boundaries.toml"
    try:
        metrics, findings = scan(root, policy)
    except ValueError as error:
        print(f"HARD_VIOLATION: policy_error: {error}", file=sys.stderr)
        return 2
    print_human(metrics, findings)
    if args.json_out:
        write_json(args.json_out, metrics, findings)
    return 1 if any(item.severity == "HARD_VIOLATION" for item in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
