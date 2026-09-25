#!/usr/bin/env python3
"""Reproducible-digest readback for the #223 Wave 1 static field contract freeze.

Cause served
------------
`crates/smart/cognitive-rev12-contract-schema-freeze.toml` is delivered at
`proof_ceiling = "STATIC_FIELD_CONTRACT_ONLY"`: it carries the exact closed
public types, denominators, scope/fence bindings and version rules the W9
consumer cells build against, and its own `[readback].rule` promises that the
"Reproducible digest is sha256 over these exact file bytes. Any byte change
creates a new freeze candidate; verdicts bound to the prior digest are
invalidated, not edited." A promise with no recorded digest and no reader is not
a readback: nothing could observe a silent byte edit or a substituted file, so a
verdict could outlive the contract bytes it was bound to.

This is the reader that closes that gap for the freeze it guards,
`cognitive-rev12-contract-schema-freeze-2026-09-22-r6`. It is the same
"read the owning artifact, never a hand-copy" shape as the compile-time
WIT/toolchain pinning in `crates/smart/eliot-context-compiler-wasm/src/
descriptor.rs`, moved to the review lane where the whole byte sequence and the
out-of-band recorded value are both observable.

I2.20 makes the public contract digest and the proof ceiling part of the module
contract kit / effective micro-module manifest, and I12.24 holds the frozen
layer fixed for the exact campaign revision whose verdict depends on it. A0.3
requires a false proof claim to fail closed, and A14.8 forbids weakening an
oracle in the same work unit that changes behaviour: the expected digest is
therefore never taken from the file being checked.

Why the expected digest comes from the handoff row, not from the freeze
-------------------------------------------------------------------
A digest of a file's exact bytes cannot live inside those bytes, so recording it
there is unsatisfiable. `crates/smart/cognitive-contract-challenges.toml` is a
different artifact, which makes the
`[[challenge]] id = "CC-W9-REV12-HANDOFF"` `resolution_evidence` row the home of
the recorded value, and that row is this script's primary mechanism: the
recorded value is the single source of truth, so the row and this reader cannot
drift apart unnoticed. `--expected` pins a digest explicitly for a one-off
re-check and is the secondary mechanism; when it is supplied the row is not read
at all.

A PASS proves only that these exact bytes hash to the recorded value, that their
length matches the recorded length, and that the handoff row names this freeze
id. It proves no Module Proof, no provider/consumer Edge Proof and no Product
Pulse: that row keeps those at TEST-PHASE / NOT_EXECUTED. A missing input, an
unparseable recorded digest, and a digest mismatch all exit non-zero; there is
no "could not check" exit 0.
"""

from __future__ import annotations

import argparse
import re
import tomllib
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FREEZE_REL = "crates/smart/cognitive-rev12-contract-schema-freeze.toml"
REGISTRY_REL = "crates/smart/cognitive-contract-challenges.toml"
HANDOFF_ID = "CC-W9-REV12-HANDOFF"
DIGEST_RE = re.compile(r"sha256:(?P<hex>[0-9a-f]{64})")
FREEZE_ID_RE = re.compile(r'^freeze_id = "(?P<id>[^"\n]+)"$', re.MULTILINE)
BYTE_LENGTH_RE = re.compile(r"(?P<len>[0-9]+) exact bytes")


class VerificationError(RuntimeError):
    """A stable freeze readback failure."""


def fail(message: str) -> None:
    raise VerificationError(f"FREEZE_DIGEST_FAIL: {message}")


def read_bytes(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        fail(f"{label} is unreadable: {path}: {error}")


def freeze_identity(source: bytes, path: Path) -> str:
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"freeze is not valid UTF-8 and cannot carry a freeze_id: {path}: {error}")
    matches = FREEZE_ID_RE.findall(text)
    if len(matches) != 1:
        fail(f"freeze declares {len(matches)} top-level freeze_id lines: {path}")
    return matches[0]


def load_handoff_row(registry: Path) -> dict:
    try:
        with registry.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"challenge registry is unreadable: {registry}: {error}")
    rows = data.get("challenge")
    if not isinstance(rows, list):
        fail(f"challenge registry carries no [[challenge]] rows: {registry}")
    for row in rows:
        if isinstance(row, dict) and row.get("id") == HANDOFF_ID:
            return row
    fail(f"challenge registry carries no [[challenge]] id={HANDOFF_ID}: {registry}")


def evidence_strings(row: dict, field: str) -> list[str]:
    value = row.get(field)
    if not isinstance(value, list) or not value:
        fail(f"{HANDOFF_ID} {field} is absent or empty")
    if not all(isinstance(item, str) for item in value):
        fail(f"{HANDOFF_ID} {field} carries a non-string entry")
    return value


def single(values: set, label: str) -> object:
    if len(values) != 1:
        fail(f"{HANDOFF_ID} records {len(values)} distinct {label}; exactly one is required")
    return next(iter(values))


def recorded_binding(row: dict) -> tuple[str, int, str]:
    evidence = evidence_strings(row, "resolution_evidence")
    missing_contract = row.get("missing_contract")
    if not isinstance(missing_contract, str):
        fail(f"{HANDOFF_ID} missing_contract is absent or not a string")
    joined = "\n".join([*evidence, missing_contract])
    digest = single({f"sha256:{match}" for match in DIGEST_RE.findall(joined)}, "digests")
    length = single({int(match) for match in BYTE_LENGTH_RE.findall(joined)}, "byte lengths")
    return str(digest), int(length), joined


def normalized_digest(value: str) -> str:
    match = DIGEST_RE.fullmatch(value.strip())
    if match is None:
        fail(f"expected digest is malformed: {value!r}; want sha256:<64 lowercase hex>")
    return f"sha256:{match.group('hex')}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Readback the recorded r6 freeze digest.")
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--freeze", type=Path, help="freeze file; defaults to the repo-relative path")
    parser.add_argument(
        "--registry",
        type=Path,
        help=f"challenge registry; defaults to the repo-relative path carrying {HANDOFF_ID}",
    )
    parser.add_argument(
        "--expected",
        help="expected digest to pin explicitly; skips the recorded handoff row",
    )
    args = parser.parse_args()

    repo = args.repo.resolve()
    freeze = args.freeze if args.freeze is not None else repo / FREEZE_REL
    registry = args.registry if args.registry is not None else repo / REGISTRY_REL

    source = read_bytes(freeze, "freeze")
    observed = f"sha256:{sha256(source).hexdigest()}"
    length = len(source)
    identity = freeze_identity(source, freeze)

    if args.expected is not None:
        expected = normalized_digest(args.expected)
        origin = "--expected"
        recorded_length: int | None = None
        named = None
    else:
        row = load_handoff_row(registry)
        expected, recorded_length, named = recorded_binding(row)
        origin = f"{registry} [[challenge]] {HANDOFF_ID} resolution_evidence"

    print(f"OBSERVED_FREEZE: {freeze}")
    print(f"OBSERVED_FREEZE_ID: {identity}")
    print(f"OBSERVED_BYTES: {length}")
    print(f"OBSERVED_DIGEST: {observed}")
    print(f"EXPECTED_DIGEST: {expected}")
    print(f"EXPECTED_SOURCE: {origin}")
    if recorded_length is not None:
        print(f"RECORDED_BYTES: {recorded_length}")
    if named is not None and identity not in named:
        fail(f"{HANDOFF_ID} does not name the observed freeze id {identity}")

    if expected != observed:
        fail(f"digest mismatch: expected {expected}, observed {observed}")
    if recorded_length is not None and recorded_length != length:
        fail(f"byte length mismatch: recorded {recorded_length}, observed {length}")

    print(
        "FREEZE_DIGEST_READBACK: PASS "
        f"freeze_id={identity} bytes={length} digest={observed} "
        f"expected_source={'explicit' if args.expected is not None else HANDOFF_ID} "
        "proof_ceiling=STATIC_FIELD_CONTRACT_ONLY"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(error)
        raise SystemExit(1)
