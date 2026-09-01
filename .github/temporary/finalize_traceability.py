#!/usr/bin/env python3
"""Finalize issue #530 without changing Rust executable tokens.

This one-shot helper is removed before the verified candidate commit is created.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / ".eliot/issue-530-finalizer.json"
CONFIG = ROOT / "config/doc-code-conformance.toml"

HEADERS = {
    "crates/kernel/eliot-platform-windows/src/directory_publication.rs": """//! Handle-bound create-new directory publication for the Windows platform contour.
//!
//! Current documentation authority:
//! - `docs/architecture/ELIOT_ARCHITECTURE.md`: `A2.3`, `A12.1`, `A13.1`,
//!   `A13.6`, and `A13.9`.
//! - `docs/architecture/A16-01-decision-anchors.md`: `ARCH-MOD-02`,
//!   `ARCH-SEC-01`, `ARCH-RES-01`, and `ARCH-ORD-01`.
//! - `docs/architecture/ELIOT_IMPLEMENTATION.md`: `I2.15`, `I2.23`,
//!   `I3.15`, and `I5.23`.
//! - precedence: `docs/ARCHITECTURE_CONTRACT.md`.
//!
//! This module owns one independently understandable physical publication
//! capability: retained no-follow parent handles, create-new staging,
//! identity fences, handle-relative no-replace rename, and typed post-commit
//! reconciliation. It owns no installer, package-policy, process, secret,
//! canonical-state, or semantic-transition authority.
""",
    "crates/kernel/eliot-platform-windows/src/kernel_front_door_server.rs": """//! Kernel front-door server proof and authentication.
//!
//! Current documentation authority:
//! - `docs/architecture/ELIOT_ARCHITECTURE.md`: `A12.2` and `A12.3`.
//! - `docs/architecture/A16-01-decision-anchors.md`: `ARCH-AUTH-01`,
//!   `ARCH-SEC-01`, and `ARCH-SEC-02`.
//! - `docs/architecture/ELIOT_IMPLEMENTATION.md`: `I2.23`, `I7.5`, and
//!   `I7.14`.
//! - precedence: `docs/ARCHITECTURE_CONTRACT.md`.
//!
//! This module owns only OS-observed front-door proof and fail-closed
//! authentication mechanics. Listener creation, generic ACL construction,
//! expectation policy, process admission, handshake/session orchestration,
//! semantic results, Store authority, and Governor authority remain elsewhere.
""",
    "crates/kernel/eliot-platform-windows/src/named_pipe_peer_auth.rs": """//! Named-pipe client admission through live impersonation and OS-observed identity.
//!
//! Current documentation authority:
//! - `docs/architecture/ELIOT_ARCHITECTURE.md`: `A2.3`, `A12.2`, and `A12.3`.
//! - `docs/architecture/A16-01-decision-anchors.md`: `ARCH-AUTH-01`,
//!   `ARCH-SEC-01`, and `ARCH-SEC-02`.
//! - `docs/architecture/ELIOT_IMPLEMENTATION.md`: `I2.23`, `I7.5`, `I7.14`,
//!   and `I15.2`.
//! - precedence: `docs/ARCHITECTURE_CONTRACT.md`.
//!
//! This module owns live named-pipe peer authentication evidence only. It
//! does not own listener creation, wire sessions, semantic authority,
//! canonical writes, service lifecycle, or caller policy.
""",
    "crates/kernel/eliot-platform-windows/src/tests.rs": """//! Test-oracle-only module for `eliot-platform-windows`.
//!
//! The test topology mirrors current production modules in `lib.rs` and sibling
//! modules. This file owns tests only; it has no production, semantic, or
//! authority ownership.
//!
//! Current documentation authority:
//! - `docs/architecture/ELIOT_ARCHITECTURE.md`: `A2.3` and `A12.2`.
//! - `docs/architecture/ELIOT_IMPLEMENTATION.md`: `I2.23`.
//! - precedence: `docs/ARCHITECTURE_CONTRACT.md`.
//!
//! No wildcard imports or new lint allowances are introduced.
""",
}

LEADING_DOCS = re.compile(r"\A(?://!.*(?:\r?\n|\Z))+")
INVALID = {
    "i2_2": re.compile(r"(?<![A-Za-z0-9])I2\.2(?![0-9])"),
    "legacy_project": re.compile(r"eliot-architecture-docs-fa941135"),
    "legacy_graph": re.compile(r"eliot-memory-os-[0-9a-f]{7,}(?:-[a-z0-9-]+)?"),
    "docs_normative": re.compile(r"docs/normative/"),
    "architecture_lines": re.compile(r"ELIOT_ARCHITECTURE\.md:\d+"),
    "implementation_lines": re.compile(r"ELIOT_IMPLEMENTATION\.md:\d+"),
}
ALLOW_BLOCK = re.compile(
    r"(?ms)^\[\[retired_references\.allow\]\]\r?\n.*?(?=^\[\[|\Z)"
)


def git(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=ROOT, text=True, capture_output=True, check=False
    )
    if completed.returncode:
        raise RuntimeError(
            f"git {' '.join(args)} failed ({completed.returncode}):\n"
            f"{completed.stdout}{completed.stderr}"
        )
    return completed.stdout


def projection(text: str) -> str:
    match = LEADING_DOCS.match(text)
    return text[match.end():] if match else text


def replace_headers() -> list[dict[str, object]]:
    changed: list[dict[str, object]] = []
    for relative, header in HEADERS.items():
        path = ROOT / relative
        before = path.read_text(encoding="utf-8")
        match = LEADING_DOCS.match(before)
        if match is None:
            raise RuntimeError(f"missing leading module docs: {relative}")
        body = before[match.end():]
        after = header.rstrip() + "\n\n" + body.lstrip("\r\n")
        if projection(before) != projection(after):
            raise RuntimeError(f"Rust body changed while replacing header: {relative}")
        path.write_text(after, encoding="utf-8", newline="")
        changed.append(
            {
                "path": relative,
                "before_sha256": hashlib.sha256(before.encode()).hexdigest(),
                "after_sha256": hashlib.sha256(after.encode()).hexdigest(),
                "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
            }
        )
    return changed


def remove_satisfied_allowances() -> list[dict[str, str]]:
    value = CONFIG.read_text(encoding="utf-8")
    removed: list[dict[str, str]] = []

    def keep_or_remove(match: re.Match[str]) -> str:
        block = match.group(0)
        parsed = tomllib.loads(block)
        entry = parsed.get("retired_references", {}).get("allow", [])
        if len(entry) != 1 or not isinstance(entry[0], dict):
            raise RuntimeError("invalid retired-reference allowance block")
        record = entry[0]
        relative = str(record.get("path", "")).replace("\\", "/")
        token = str(record.get("token", ""))
        if not relative.endswith(".rs"):
            return block
        source = ROOT / relative
        if source.is_file() and token and token not in source.read_text(encoding="utf-8"):
            removed.append({"path": relative, "token": token})
            return ""
        return block

    updated = ALLOW_BLOCK.sub(keep_or_remove, value)
    updated = re.sub(r"\n{3,}", "\n\n", updated).rstrip() + "\n"
    CONFIG.write_text(updated, encoding="utf-8", newline="")
    return removed


def verify_operational_rust() -> dict[str, list[str]]:
    residuals: dict[str, list[str]] = {}
    for raw in git("ls-files", "-z", "--", "*.rs").split("\0"):
        if not raw:
            continue
        path = ROOT / raw
        text = path.read_text(encoding="utf-8")
        hits = [name for name, pattern in INVALID.items() if pattern.search(text)]
        if hits:
            residuals[raw] = hits
    return residuals


def main() -> int:
    changed = replace_headers()
    removed = remove_satisfied_allowances()
    residuals = verify_operational_rust()
    if residuals:
        raise RuntimeError(
            "obsolete traceability remains:\n"
            + json.dumps(residuals, ensure_ascii=False, indent=2)
        )
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        json.dumps(
            {
                "schema_version": "eliot-issue-530-finalizer-v1",
                "changed_headers": changed,
                "removed_allowances": removed,
                "residuals": residuals,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
        newline="",
    )
    print(
        "ISSUE_530_FINALIZER: PASS "
        f"headers={len(changed)} allowances_removed={len(removed)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
