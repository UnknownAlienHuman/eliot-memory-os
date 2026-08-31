#!/usr/bin/env python3
"""Check configured repository documentation/source conformance rules.

The checker is deliberately small and deterministic. Configuration owns the
roots, extensions, markers, and narrowly scoped negative-policy allowances.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
import tempfile
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence

SCHEMA = "eliot-doc-code-conformance-v1"
SKIP_PARTS = {
    ".git",
    ".eliot",
    ".codebase-memory",
    "__pycache__",
    "target",
    "dist",
    "node_modules",
    "obj",
}
DEFAULT_CONFIG = Path("config/doc-code-conformance.toml")


class AuditError(RuntimeError):
    """Raised when conformance configuration or source cannot be audited."""


@dataclass(frozen=True, order=True)
class Finding:
    """One stable, path-addressable conformance diagnostic."""

    finding_id: str
    path: str
    line: int
    message: str


def norm(value: str) -> str:
    """Normalize a repository-relative path without changing its case."""

    value = re.sub(r"/+", "/", value.strip().replace("\\", "/"))
    while value.startswith("./"):
        value = value[2:]
    if value in {"", "."}:
        return "."
    path = PurePosixPath(value)
    if path.is_absolute() or re.match(r"^[A-Za-z]:", value) or ".." in path.parts:
        raise AuditError(f"path must be repository-relative: {value!r}")
    return path.as_posix()


def relative(root: Path, path: Path) -> str:
    """Return an exact, portable repository path."""

    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise AuditError(f"path escapes repository root: {path}") from exc


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise AuditError(f"cannot read UTF-8 text {path}: {exc}") from exc


def read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            value = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise AuditError(f"cannot read TOML {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise AuditError(f"TOML root must be a table: {path}")
    return value


def strings(value: Any, field: str) -> list[str]:
    if not isinstance(value, (list, tuple)) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise AuditError(f"{field} must be an array of non-empty strings")
    return [item.strip() for item in value]


def unique_sorted(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


def extensions(value: Any, field: str) -> tuple[str, ...]:
    """Normalize configured extensions, including entries missing a dot."""

    normalized = []
    for item in strings(value, field):
        item = item.casefold()
        if not item.startswith("."):
            item = "." + item
        if "/" in item or item == ".":
            raise AuditError(f"{field} contains an invalid extension: {item!r}")
        normalized.append(item)
    return unique_sorted(normalized)


def configured_roots(value: Any, field: str) -> tuple[str, ...]:
    return unique_sorted(norm(item) for item in strings(value, field))


def normalized_allowances(value: Any, field: str) -> frozenset[tuple[str, str]]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        raise AuditError(f"{field} must be an array of tables or path/token pairs")
    allowances: set[tuple[str, str]] = set()
    for index, item in enumerate(value):
        if isinstance(item, dict):
            path_value = item.get("path")
            token_value = item.get("token")
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            path_value, token_value = item
        else:
            raise AuditError(f"{field}[{index}] must be a table or path/token pair")
        if not isinstance(path_value, str) or not path_value.strip():
            raise AuditError(f"{field}[{index}] requires a path")
        if not isinstance(token_value, str) or not token_value.strip():
            raise AuditError(f"{field}[{index}] requires a token")
        allowances.add((norm(path_value), token_value.strip()))
    return frozenset(allowances)


def normalized_config(config: dict[str, Any]) -> dict[str, Any]:
    """Apply the same normalization to loaded and self-test configurations."""

    return {
        "roots": configured_roots(config["roots"], "retired_references.scan_roots"),
        "extensions": extensions(config["extensions"], "retired_references.extensions"),
        "markers": unique_sorted(strings(config["markers"], "retired_references.tokens")),
        "ignore_globs": unique_sorted(
            norm(item)
            for item in strings(config.get("ignore_globs", []), "retired_references.ignore_globs")
        ),
        "allow": normalized_allowances(config.get("allow", ()), "retired_references.allow"),
    }


def load_config(path: Path) -> dict[str, Any]:
    config = read_toml(path)
    if config.get("schema_version") != SCHEMA:
        raise AuditError(f"unsupported schema: {config.get('schema_version')!r}")
    section = config.get("retired_references")
    if not isinstance(section, dict):
        raise AuditError("configuration is missing [retired_references]")
    roots = configured_roots(section.get("scan_roots"), "retired_references.scan_roots")
    suffixes = extensions(section.get("extensions"), "retired_references.extensions")
    markers = unique_sorted(strings(section.get("tokens"), "retired_references.tokens"))
    if not roots or not suffixes or not markers:
        raise AuditError("retired_references roots, extensions, and tokens are required")
    ignores = unique_sorted(
        norm(item)
        for item in strings(section.get("ignore_globs", []), "retired_references.ignore_globs")
    )
    raw_allow = section.get("allow", [])
    if not isinstance(raw_allow, list):
        raise AuditError("retired_references.allow must be an array of tables")
    for index, item in enumerate(raw_allow):
        if not isinstance(item, dict):
            raise AuditError(f"retired_references.allow[{index}] must be a table")
        reason_value = item.get("reason")
        if not isinstance(reason_value, str) or not reason_value.strip():
            raise AuditError(f"retired_references.allow[{index}] requires a reason")
    return {
        "roots": roots,
        "extensions": suffixes,
        "markers": markers,
        "ignore_globs": ignores,
        "allow": normalized_allowances(raw_allow, "retired_references.allow"),
    }


def files_under(root: Path) -> list[Path]:
    """List files in stable order while excluding generated/local directories."""

    if not root.exists():
        return []
    if root.is_file():
        return [root]
    return [
        path
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix())
        if path.is_file() and not any(part in SKIP_PARTS for part in path.parts)
    ]


def configured_files(root: Path, roots: Sequence[str]) -> tuple[list[Path], list[str]]:
    """Expand configured roots and return missing roots instead of skipping them."""

    selected: dict[Path, Path] = {}
    missing: list[str] = []
    for raw in roots:
        configured = norm(raw)
        path = root / configured
        if not path.exists():
            missing.append(configured)
            continue
        for candidate in files_under(path):
            selected[candidate.resolve()] = candidate
    return [selected[key] for key in sorted(selected, key=lambda item: item.as_posix())], sorted(set(missing))


def selected_files(root: Path, roots: Sequence[str]) -> Iterable[Path]:
    """Compatibility helper exposing deterministic configured-root expansion."""

    selected, missing = configured_files(root, roots)
    if missing:
        raise AuditError("configured roots are missing: " + ", ".join(missing))
    return selected


def line_number(value: str, offset: int) -> int:
    return value.count("\n", 0, offset) + 1


def ignored(path: str, globs: Sequence[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in globs)


def legacy_reference_findings(
    root: Path, config: dict[str, Any]
) -> tuple[list[Finding], dict[str, int]]:
    """Find every configured marker in every selected, supported file."""

    config = normalized_config(config)
    selected, missing = configured_files(root, config["roots"])
    findings = [
        Finding(
            "DCC-003",
            path,
            0,
            "configured scan root is missing",
        )
        for path in missing
    ]
    files_checked = 0
    occurrences = 0
    affected_files = 0
    for path in selected:
        relative_path = relative(root, path)
        if path.suffix.casefold() not in config["extensions"] or ignored(
            relative_path, config["ignore_globs"]
        ):
            continue
        files_checked += 1
        value = read_text(path)
        matches: list[tuple[int, str]] = []
        for marker in config["markers"]:
            if (relative_path, marker) in config["allow"]:
                continue
            for match in re.finditer(re.escape(marker), value):
                matches.append((line_number(value, match.start()), marker))
        if matches:
            affected_files += 1
            occurrences += len(matches)
            details = ", ".join(
                f"{marker}@{line}" for line, marker in sorted(set(matches), key=lambda item: (item[0], item[1]))
            )
            findings.append(
                Finding(
                    "DCC-003",
                    relative_path,
                    min(line for line, _ in matches),
                    "legacy marker remains: " + details,
                )
            )
    metrics = {
        "configured_roots": len(config["roots"]),
        "missing_roots": len(missing),
        "files_checked": files_checked,
        "legacy_marker_files": affected_files,
        "legacy_marker_occurrences": occurrences,
    }
    return sorted(set(findings)), metrics


# Keep the checker name aligned with the policy vocabulary used by callers.
retired_reference_findings = legacy_reference_findings


def audit(root: Path, config: dict[str, Any]) -> tuple[list[Finding], dict[str, int]]:
    if not isinstance(config, dict) or config.get("roots") is None:
        raise AuditError("invalid loaded conformance configuration")
    return legacy_reference_findings(root.resolve(), config)


def fixture_config() -> dict[str, Any]:
    return {
        "roots": ("src", "notes", "src/ignored", "src/one.rs"),
        "extensions": (".rs", ".txt"),
        "markers": ("legacy-a", "legacy-b"),
        "ignore_globs": ("src/ignored/**",),
        "allow": frozenset({("notes/policy.txt", "legacy-a")}),
    }


def self_test() -> None:
    """Exercise inclusion, exclusion, normalization, ordering, and 26-gap behavior."""

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "src/ignored").mkdir(parents=True)
        (root / "notes").mkdir()
        (root / "src/one.rs").write_text("legacy-a\n", encoding="utf-8")
        (root / "src/two.RS").write_text("legacy-b\n", encoding="utf-8")
        (root / "src/ignored/hidden.rs").write_text("legacy-a\n", encoding="utf-8")
        (root / "notes/policy.txt").write_text("legacy-a\nlegacy-b\n", encoding="utf-8")
        config = fixture_config()
        findings, metrics = audit(root, config)
        if [item.path for item in findings] != ["notes/policy.txt", "src/one.rs", "src/two.RS"]:
            raise AuditError(f"inclusion/exclusion self-test failed: {findings}")
        if metrics["legacy_marker_files"] != 3 or metrics["legacy_marker_occurrences"] != 3:
            raise AuditError(f"marker count self-test failed: {metrics}")

        reordered = dict(config)
        reordered["roots"] = ("src/one.rs", "src", "notes")
        reordered["extensions"] = (".TXT", "RS")
        reordered["ignore_globs"] = ()
        reordered["allow"] = frozenset()
        reordered_findings, _ = audit(root, reordered)
        if [item.path for item in reordered_findings] != ["notes/policy.txt", "src/ignored/hidden.rs", "src/one.rs", "src/two.RS"]:
            raise AuditError("duplicate/order or extension normalization self-test failed")

        missing_config = dict(config)
        missing_config["roots"] = ("missing",)
        missing, missing_metrics = audit(root, missing_config)
        if missing != [Finding("DCC-003", "missing", 0, "configured scan root is missing")]:
            raise AuditError(f"missing-root self-test failed: {missing}")
        if missing_metrics["missing_roots"] != 1:
            raise AuditError("missing-root metric self-test failed")

        malformed = dict(config)
        malformed["allow"] = ((1, "legacy-a"),)
        try:
            audit(root, malformed)
        except AuditError:
            pass
        else:
            raise AuditError("malformed-allowance self-test failed")

        gap_root = root / "gaps"
        gap_root.mkdir()
        for index in range(26):
            (gap_root / f"gap-{index:02d}.rs").write_text("legacy-a\n", encoding="utf-8")
        gap_config = {
            "roots": ("gaps", "gaps/gap-00.rs", "gaps"),
            "extensions": ("RS", ".rs"),
            "markers": ("legacy-a",),
            "ignore_globs": (),
            "allow": frozenset(),
        }
        gap_findings, gap_metrics = audit(root, gap_config)
        if len(gap_findings) != 26 or gap_metrics["legacy_marker_files"] != 26:
            raise AuditError(f"exact 26-gap self-test failed: {gap_metrics}")

    print("DOC_CODE_CONFORMANCE_SELF_TEST: PASS cases=5")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.self_test:
            self_test()
            return 0
        root = args.root.resolve()
        config_path = args.config if args.config.is_absolute() else root / args.config
        findings, metrics = audit(root, load_config(config_path))
        payload = {
            "schema_version": SCHEMA,
            "status": "PASS" if not findings else "FAIL",
            "metrics": metrics,
            "findings": [asdict(item) for item in findings],
        }
        if args.json_out:
            output = args.json_out if args.json_out.is_absolute() else root / args.json_out
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        for item in findings:
            location = item.path + (f":{item.line}" if item.line else "")
            print(f"{item.finding_id} {location}: {item.message}", file=sys.stderr)
        status = "PASS" if not findings else "FAIL"
        print(
            "DOC_CODE_CONFORMANCE: "
            + status
            + " "
            + " ".join(f"{key}={value}" for key, value in sorted(metrics.items())),
            file=sys.stderr if findings else sys.stdout,
        )
        return 0 if not findings else 1
    except (AuditError, KeyError, TypeError, ValueError) as exc:
        print(f"DOC_CODE_CONFORMANCE_ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
