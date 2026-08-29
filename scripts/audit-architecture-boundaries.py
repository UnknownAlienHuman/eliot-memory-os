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
            """,
        )
        _write(
            root / "Cargo.toml",
            """
            [workspace]
            members = ["root-bin", "eliot-app", "surreal-leak"]
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
