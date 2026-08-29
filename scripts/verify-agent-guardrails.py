#!/usr/bin/env python3
"""Verify nearest-path agent guardrails for core and daemon source.

The files are routing/control-plane projections. This verifier proves only that
required nearest-path instructions exist, remain bounded, identify their current
owner issues, preserve the repository work discipline, and avoid obvious support
or authority overclaims. It does not prove source or runtime conformance.
"""

from __future__ import annotations

import argparse
import tempfile
from dataclasses import dataclass
from pathlib import Path

MIN_BYTES = 240
MAX_BYTES = 12_000


@dataclass(frozen=True)
class GuardrailSpec:
    path: str
    required_issue_refs: tuple[str, ...]


SPECS = (
    GuardrailSpec("bins/AGENTS.md", ("#11", "#13", "#14", "#15", "#24")),
    GuardrailSpec("crates/governor/AGENTS.md", ("#13", "#18")),
    GuardrailSpec("crates/instrument/AGENTS.md", ("#11", "#13", "#20", "#100")),
    GuardrailSpec("crates/kernel/AGENTS.md", ("#11", "#13", "#14", "#15", "#100")),
    GuardrailSpec("crates/meta/AGENTS.md", ("#11", "#13", "#17")),
    GuardrailSpec("crates/modules/AGENTS.md", ("#13", "#21", "#22", "#100")),
    GuardrailSpec("crates/research/AGENTS.md", ("#24", "#100")),
    GuardrailSpec("crates/storage/AGENTS.md", ("#10", "#19")),
    GuardrailSpec("crates/supervision/AGENTS.md", ("#11", "#13", "#16")),
    GuardrailSpec("crates/surfaces/AGENTS.md", ("#13", "#23", "#77")),
)

COMMON_MARKERS = (
    "current `main`",
    "issue-numbered branch",
    "one pr",
    "one mutable path",
    "proof",
    "stop",
)

CANONICAL_BOUNDARY_MARKERS = (
    "canonical write",
    "canonical store",
    "canonical transition",
)

FORBIDDEN_OVERCLAIMS = (
    "current_verified",
    "product verified",
    "production ready",
    "grants authority",
    "proves conformance",
)


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    detail: str


def normalized_markdown_text(text: str) -> str:
    """Case-fold simple guardrail prose and ignore Markdown line wrapping."""
    return " ".join(text.lower().split())


def has_canonical_boundary(normalized: str) -> bool:
    if any(marker in normalized for marker in CANONICAL_BOUNDARY_MARKERS):
        return True
    return "semantic admission" in normalized and "preparedtransition" in normalized


def verify(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    expected_paths = {spec.path for spec in SPECS}

    for spec in SPECS:
        path = root / spec.path
        if not path.is_file():
            findings.append(Finding("guardrail_missing", spec.path, "required nearest-path instructions are absent"))
            continue

        try:
            payload = path.read_bytes()
            text = payload.decode("utf-8")
        except (OSError, UnicodeError) as error:
            findings.append(Finding("guardrail_unreadable", spec.path, str(error)))
            continue

        size = len(payload)
        if size < MIN_BYTES:
            findings.append(Finding("guardrail_too_small", spec.path, f"{size} bytes cannot carry the required routing boundary"))
        if size > MAX_BYTES:
            findings.append(Finding("guardrail_too_large", spec.path, f"{size} bytes exceeds the bounded routing-file ceiling {MAX_BYTES}"))
        if not text.startswith("# "):
            findings.append(Finding("guardrail_title_missing", spec.path, "file must begin with one Markdown title"))

        normalized = normalized_markdown_text(text)
        for marker in COMMON_MARKERS:
            if marker not in normalized:
                findings.append(Finding("guardrail_workflow_missing", spec.path, f"missing required marker: {marker}"))
        for issue_ref in spec.required_issue_refs:
            if issue_ref not in text:
                findings.append(Finding("guardrail_owner_issue_missing", spec.path, f"missing current owner/integration issue {issue_ref}"))
        for phrase in FORBIDDEN_OVERCLAIMS:
            if phrase in normalized:
                findings.append(Finding("guardrail_overclaim", spec.path, f"forbidden support/authority claim: {phrase}"))

        if not has_canonical_boundary(normalized):
            findings.append(Finding("guardrail_canonical_boundary_missing", spec.path, "canonical ownership/write boundary is not stated"))
        if "authority" not in normalized:
            findings.append(Finding("guardrail_authority_boundary_missing", spec.path, "authority boundary is not stated"))

    guardrail_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("AGENTS.md")
        if path.relative_to(root).as_posix() in expected_paths
    }
    missing_from_scan = expected_paths - guardrail_paths
    for path in sorted(missing_from_scan):
        if not any(finding.path == path and finding.code == "guardrail_missing" for finding in findings):
            findings.append(Finding("guardrail_scan_gap", path, "required path was not discoverable by repository scan"))

    return sorted(findings, key=lambda finding: (finding.path, finding.code, finding.detail))


def print_findings(findings: list[Finding]) -> None:
    for finding in findings:
        print(f"HARD_VIOLATION: {finding.code}: {finding.path}: {finding.detail}")


def valid_fixture(spec: GuardrailSpec) -> str:
    issues = " ".join(spec.required_issue_refs)
    return f"""# Fixture guardrail

Owners and current issues: {issues}.

## Work discipline

Start from current `main`, use one open owning issue, one issue-numbered branch,
one PR, and one mutable path writer.

## Hard boundaries

This path creates no authority and no canonical write path. It cannot become a
canonical store owner.

## Proof and stop condition

Run the bounded proof. Stop when ownership or the proof boundary is unclear.
"""


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="eliot-guardrail-self-test-") as temp:
        root = Path(temp)
        for spec in SPECS:
            path = root / spec.path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(valid_fixture(spec), encoding="utf-8")

        clean = verify(root)
        if clean:
            raise AssertionError(f"valid guardrail fixture failed: {clean}")

        missing_spec = SPECS[0]
        (root / missing_spec.path).unlink()
        missing = verify(root)
        if not any(item.code == "guardrail_missing" and item.path == missing_spec.path for item in missing):
            raise AssertionError("missing-file fixture did not fail")
        (root / missing_spec.path).write_text(valid_fixture(missing_spec), encoding="utf-8")

        overclaim_spec = SPECS[1]
        path = root / overclaim_spec.path
        path.write_text(valid_fixture(overclaim_spec) + "\nProduction ready.\n", encoding="utf-8")
        overclaim = verify(root)
        if not any(item.code == "guardrail_overclaim" and item.path == overclaim_spec.path for item in overclaim):
            raise AssertionError("support-overclaim fixture did not fail")
        path.write_text(valid_fixture(overclaim_spec), encoding="utf-8")

        large_spec = SPECS[2]
        path = root / large_spec.path
        path.write_text(valid_fixture(large_spec) + ("x" * MAX_BYTES), encoding="utf-8")
        too_large = verify(root)
        if not any(item.code == "guardrail_too_large" and item.path == large_spec.path for item in too_large):
            raise AssertionError("oversized guardrail fixture did not fail")
        path.write_text(valid_fixture(large_spec), encoding="utf-8")

        wrapped_spec = SPECS[3]
        path = root / wrapped_spec.path
        wrapped = valid_fixture(wrapped_spec).replace("one mutable path", "one\nmutable path")
        path.write_text(wrapped, encoding="utf-8")
        wrapped_findings = [item for item in verify(root) if item.path == wrapped_spec.path]
        if wrapped_findings:
            raise AssertionError(f"wrapped marker fixture failed: {wrapped_findings}")
        path.write_text(valid_fixture(wrapped_spec), encoding="utf-8")

        transition_spec = SPECS[4]
        path = root / transition_spec.path
        transition_only = valid_fixture(transition_spec).replace(
            "no canonical write path. It cannot become a\ncanonical store owner",
            "no alternate canonical transition path",
        )
        path.write_text(transition_only, encoding="utf-8")
        transition_findings = [item for item in verify(root) if item.path == transition_spec.path]
        if transition_findings:
            raise AssertionError(f"canonical-transition fixture failed: {transition_findings}")
        path.write_text(valid_fixture(transition_spec), encoding="utf-8")

        prepared_spec = SPECS[5]
        path = root / prepared_spec.path
        prepared_transition = valid_fixture(prepared_spec).replace(
            "This path creates no authority and no canonical write path. It cannot become a\ncanonical store owner.",
            "Semantic admission emits one `PreparedTransition`; this path creates no authority.",
        )
        path.write_text(prepared_transition, encoding="utf-8")
        prepared_findings = [item for item in verify(root) if item.path == prepared_spec.path]
        if prepared_findings:
            raise AssertionError(f"PreparedTransition fixture failed: {prepared_findings}")
        path.write_text(valid_fixture(prepared_spec), encoding="utf-8")

        no_canonical_spec = SPECS[6]
        path = root / no_canonical_spec.path
        no_canonical = valid_fixture(no_canonical_spec).replace(
            "no canonical write path. It cannot become a\ncanonical store owner",
            "no durable mutation path",
        )
        path.write_text(no_canonical, encoding="utf-8")
        no_canonical_findings = verify(root)
        if not any(
            item.code == "guardrail_canonical_boundary_missing"
            and item.path == no_canonical_spec.path
            for item in no_canonical_findings
        ):
            raise AssertionError("missing-canonical-boundary fixture did not fail")

    print("AGENT_GUARDRAILS_SELF_TEST: PASS cases=8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root",
    )
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0

    root = args.root.resolve()
    findings = verify(root)
    if findings:
        print_findings(findings)
        return 1
    print(f"AGENT_GUARDRAILS_VERIFY: PASS files={len(SPECS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
