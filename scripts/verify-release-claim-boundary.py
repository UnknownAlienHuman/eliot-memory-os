#!/usr/bin/env python3
"""Verify the build-success claim boundary (issue #1855).

Release/status reporting owner only. A successful nine-binary compilation is
build/assembly evidence bound to its exact source/build identity. It never
emits installed-runtime, verifier, acceptance, or release-eligibility claims,
and a build pass with unchanged product outcome raises the I17.5 Mechanism
Review trigger instead of promoting the product claim.

Proof ceiling: STATIC_RELEASE_CLAIM_POLICY_ONLY. Not runtime, store, or
Product Proof.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

EXPECTED_NINE_BINARIES = (
    "eliot",
    "eliot-host",
    "eliot-watchdog",
    "eliot-kernel",
    "eliot-store-surreal",
    "eliotd",
    "eliot-doctor",
    "eliot-testd",
    "eliot-native-worker",
)

CLAIM_TYPES = (
    "build",
    "assembly",
    "installed-runtime",
    "verifier",
    "acceptance",
    "release-eligibility",
)

PRESENTATION_LABELS = {
    "build": "BUILD_PASS",
    "assembly": "ASSEMBLY_COMPLETE",
    "installed-runtime": "INSTALLED_RUNTIME_UNKNOWN",
    "verifier": "VERIFIER_NOT_EXECUTED",
    "acceptance": "NOT_ACCEPTED",
    "release-eligibility": "RELEASE_NOT_ELIGIBLE_TARGET",
}

PRODUCT_STATUS = "NOT_ACCEPTED / UNVERIFIED"

DOWNSTREAM_FROM_BUILD = {
    "installed-runtime": "UNKNOWN",
    "verifier": "NOT_EXECUTED",
    "acceptance": "TARGET",
    "release-eligibility": "TARGET",
}

FORBIDDEN_BUILD_LABELS = (
    "release-ready",
    "RELEASE_READY",
    "RELEASE_ELIGIBLE",
    "complete",
    "COMPLETE",
    "certified",
    "CERTIFIED",
    "architecture-complete",
    "ARCHITECTURE_COMPLETE",
)

MECHANISM_REVIEW_TRIGGER = "local PASS with unchanged product outcome"

DOC_RELATIVE = "docs/release/CLAIM_BOUNDARY.md"
BUILD_SCRIPT_RELATIVE = "scripts/build-eliot-windows-x64-release.ps1"


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    detail: str


def emit_build_claim(
    source_commit: str,
    binaries: tuple[str, ...],
    product_changed: bool,
    installed_spine_proof: bool = False,
) -> dict[str, object]:
    """Emit the only claim a successful compilation may produce."""
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit or ""):
        raise ValueError("source_commit must be a 40-hex commit SHA")
    if tuple(binaries) != EXPECTED_NINE_BINARIES:
        raise ValueError("nine-binary build identity must match exactly")
    claim: dict[str, object] = {
        "claims": ["build", "assembly"],
        "presentation": ["BUILD_PASS", "ASSEMBLY_COMPLETE"],
        "source_commit": source_commit,
        "binaries": list(binaries),
        "product_status": PRODUCT_STATUS,
        "downstream": dict(DOWNSTREAM_FROM_BUILD),
        "release_ready": False,
        "complete": False,
        "certified": False,
        "architecture_complete": False,
        "mechanism_review_required": (not product_changed),
        "mechanism_review_trigger": (
            MECHANISM_REVIEW_TRIGGER if not product_changed else ""
        ),
    }
    if installed_spine_proof:
        raise ValueError(
            "installed spine proof is never supplied by compilation; "
            "it requires identity-bound installed Windows spine evidence"
        )
    return claim


def check_claim_shape(claim: dict[str, object]) -> list[Finding]:
    findings: list[Finding] = []
    if claim.get("claims") != ["build", "assembly"]:
        findings.append(
            Finding("claim_overreach", "claims", "build may emit build+assembly only")
        )
    if claim.get("presentation") != ["BUILD_PASS", "ASSEMBLY_COMPLETE"]:
        findings.append(
            Finding(
                "claim_overreach",
                "presentation",
                "build presentation must be BUILD_PASS/ASSEMBLY_COMPLETE only",
            )
        )
    if claim.get("product_status") != PRODUCT_STATUS:
        findings.append(
            Finding(
                "product_overclaim",
                "product_status",
                f"product must stay {PRODUCT_STATUS} without installed spine proof",
            )
        )
    for key in ("release_ready", "complete", "certified", "architecture_complete"):
        if claim.get(key):
            findings.append(
                Finding(
                    "release_overclaim",
                    key,
                    f"{key} cannot derive from compilation",
                )
            )
    downstream = claim.get("downstream")
    if downstream != DOWNSTREAM_FROM_BUILD:
        findings.append(
            Finding(
                "downstream_mislabel",
                "downstream",
                "downstream must be UNKNOWN/NOT_EXECUTED/TARGET from build alone",
            )
        )
    labels = [
        str(item)
        for item in (
            list(claim.get("presentation", []))
            if isinstance(claim.get("presentation"), list)
            else []
        )
        + (
            list(claim.get("claims", []))
            if isinstance(claim.get("claims"), list)
            else []
        )
    ]
    for forbidden in FORBIDDEN_BUILD_LABELS:
        if forbidden == "COMPLETE":
            continue  # ASSEMBLY_COMPLETE is the allowed assembly label.
        if forbidden == "complete":
            continue  # Dict keys are snake_case; presentation is upper-case.
        if forbidden in labels:
            findings.append(
                Finding(
                    "release_overclaim",
                    "presentation",
                    f"forbidden build-derived status: {forbidden}",
                )
            )
            break
    return findings


def self_test() -> None:
    commit = "e4b292afc029406d691323bb4ffe255ffe5438ba"
    # 1. Nine-binary build emits build+assembly only, product stays unaccepted.
    claim = emit_build_claim(commit, EXPECTED_NINE_BINARIES, product_changed=False)
    assert claim["claims"] == ["build", "assembly"]
    assert claim["presentation"] == ["BUILD_PASS", "ASSEMBLY_COMPLETE"]
    assert claim["product_status"] == PRODUCT_STATUS
    assert claim["release_ready"] is False
    assert claim["complete"] is False
    assert claim["mechanism_review_required"] is True
    assert claim["mechanism_review_trigger"] == MECHANISM_REVIEW_TRIGGER
    assert check_claim_shape(claim) == []
    print("CLAIM_FIXTURE: nine-binary build emits build+assembly only: PASS")

    # 2. Same surface retains NOT_ACCEPTED/UNVERIFIED without spine proof.
    assert "NOT_ACCEPTED" in str(claim["product_status"])
    assert "UNVERIFIED" in str(claim["product_status"])
    try:
        emit_build_claim(
            commit, EXPECTED_NINE_BINARIES, product_changed=False,
            installed_spine_proof=True,
        )
        raise AssertionError("compilation must not accept an installed spine proof")
    except ValueError:
        print("CLAIM_FIXTURE: compilation cannot supply installed spine proof: PASS")

    # 3. No release-ready or complete status derivable from compilation.
    forged = dict(claim)
    forged["release_ready"] = True
    assert any(f.code == "release_overclaim" for f in check_claim_shape(forged))
    forged2 = dict(claim)
    forged2["presentation"] = ["BUILD_PASS", "RELEASE_READY"]
    assert any(f.code == "release_overclaim" for f in check_claim_shape(forged2))
    print("CLAIM_FIXTURE: no release-ready/complete from compilation: PASS")

    # 4. Wrong binary set is rejected (assembly identity is exact).
    try:
        emit_build_claim(commit, EXPECTED_NINE_BINARIES[:8], product_changed=False)
        raise AssertionError("short binary set must be rejected")
    except ValueError:
        print("CLAIM_FIXTURE: non-nine binary set rejected: PASS")

    # 5. Product change clears the Mechanism Review trigger but not the boundary.
    changed = emit_build_claim(commit, EXPECTED_NINE_BINARIES, product_changed=True)
    assert changed["mechanism_review_required"] is False
    assert changed["product_status"] == PRODUCT_STATUS
    assert check_claim_shape(changed) == []
    print("CLAIM_FIXTURE: mechanism review on build-pass product-unchanged: PASS")

    print("RELEASE_CLAIM_BOUNDARY_SELF_TEST: PASS cases=5")


def verify(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    doc = root / DOC_RELATIVE
    try:
        text = doc.read_text(encoding="utf-8")
    except OSError as error:
        return [Finding("claim_doc_missing", DOC_RELATIVE, str(error))]
    required_tokens = (
        list(EXPECTED_NINE_BINARIES)
        + ["BUILD_PASS", "ASSEMBLY_COMPLETE", "NOT_ACCEPTED / UNVERIFIED",
           "NOT_EXECUTED", "UNKNOWN", "TARGET", "STALE",
           "MECHANISM_REVIEW_REQUIRED", MECHANISM_REVIEW_TRIGGER,
           "release-ready", "architecture-complete"]
        + list(CLAIM_TYPES)
    )
    for token in required_tokens:
        if token not in text:
            findings.append(
                Finding("claim_doc_drift", DOC_RELATIVE, f"missing token: {token}")
            )
    build_script = root / BUILD_SCRIPT_RELATIVE
    try:
        script_text = build_script.read_text(encoding="utf-8")
    except OSError as error:
        return findings + [
            Finding("build_script_missing", BUILD_SCRIPT_RELATIVE, str(error))
        ]
    for binary in EXPECTED_NINE_BINARIES:
        if binary not in script_text:
            findings.append(
                Finding(
                    "build_identity_drift",
                    BUILD_SCRIPT_RELATIVE,
                    f"nine-binary build definition missing: {binary}",
                )
            )
    # The executable boundary itself must hold on the exact nine set.
    try:
        claim = emit_build_claim(
            "e4b292afc029406d691323bb4ffe255ffe5438ba",
            EXPECTED_NINE_BINARIES,
            product_changed=False,
        )
    except ValueError as error:
        return findings + [Finding("claim_shape", "emit_build_claim", str(error))]
    findings.extend(check_claim_shape(claim))
    return sorted(findings, key=lambda item: (item.code, item.path, item.detail))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    findings = verify(args.root.resolve())
    if findings:
        for finding in findings:
            print(f"HARD_VIOLATION: {finding.code}: {finding.path}: {finding.detail}")
        return 1
    print(
        "RELEASE_CLAIM_BOUNDARY_VERIFY: PASS "
        "build+assembly only; product NOT_ACCEPTED / UNVERIFIED; "
        "mechanism review on build-pass product-unchanged"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
