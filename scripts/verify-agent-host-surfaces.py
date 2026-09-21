#!/usr/bin/env python3
"""One manual verification entrypoint for all agent host surfaces (issue #250).

Runs the exact ordered command manifest for the Codex, OpenCode, Claude,
Antigravity, host-bundle, model-selector, and swarm checks, plus the
Claude/OpenCode dynamic tests. This is manual source/fake-runtime integration
verification only: no provider execution, credentials, user-profile
installation, route admission, task authority, or support promotion.

Fail-closed rules (never PASS-on-skip):

- missing Node or a missing manifest script is an explicit FAIL;
- any nonzero exit fails the aggregate;
- any per-command timeout fails the aggregate;
- the run stops at the first failure with the exact command identity;
- success emits one JSON receipt with the source root, command digests,
  dispositions, durations, and the proof ceiling.

Standard library only. Usage:

    python scripts/verify-agent-host-surfaces.py --receipt-out <path>
    python scripts/verify-agent-host-surfaces.py --list
    python scripts/verify-agent-host-surfaces.py --self-test
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MANIFEST_SCHEMA = "eliot.agent-host-surface-verify.v1"
RECEIPT_SCHEMA = "eliot.agent-host-surface-verify-receipt.v1"
PROOF_CEILING = "MANUAL_SOURCE_FAKE_RUNTIME_ONLY"
ISSUE = 250

TAIL_MAX_CHARS = 6000
TAIL_MAX_LINES = 80
PREFLIGHT_TIMEOUT_S = 30


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _argv_digest(argv: list[str]) -> str:
    return _sha256_bytes(json.dumps(argv, separators=(",", ":")).encode("utf-8"))


def _bounded_tail(text: str) -> tuple[str, bool]:
    lines = text.splitlines()
    truncated = False
    if len(lines) > TAIL_MAX_LINES:
        lines = lines[-TAIL_MAX_LINES:]
        truncated = True
    tail = "\n".join(lines)
    if len(tail) > TAIL_MAX_CHARS:
        tail = tail[-TAIL_MAX_CHARS:]
        truncated = True
    return tail, truncated


def _find_exe(name: str) -> str | None:
    return shutil.which(name)


def load_manifest(path: Path) -> dict:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError(f"manifest unreadable: {path}: {error}") from error
    if not isinstance(raw, dict):
        raise ValueError(f"manifest must be an object: {path}")
    if raw.get("schema_version") != MANIFEST_SCHEMA:
        raise ValueError(f"manifest schema mismatch: {path}")
    if raw.get("proof_ceiling") != PROOF_CEILING:
        raise ValueError(f"manifest proof ceiling mismatch: {path}")
    commands = raw.get("commands")
    if not isinstance(commands, list) or not commands:
        raise ValueError(f"manifest has no commands: {path}")
    seen: set[str] = set()
    for entry in commands:
        if not isinstance(entry, dict):
            raise ValueError(f"manifest command must be an object: {entry!r}")
        command_id = entry.get("id")
        argv = entry.get("argv")
        timeout_s = entry.get("timeout_s")
        if not isinstance(command_id, str) or not command_id:
            raise ValueError(f"manifest command id must be a nonblank string: {entry!r}")
        if command_id in seen:
            raise ValueError(f"duplicate manifest command id: {command_id}")
        seen.add(command_id)
        if not isinstance(argv, list) or not argv or not all(
            isinstance(item, str) and item for item in argv
        ):
            raise ValueError(f"command {command_id}: argv must be a non-empty string list")
        if not isinstance(timeout_s, int) or isinstance(timeout_s, bool) or timeout_s <= 0:
            raise ValueError(f"command {command_id}: timeout_s must be a positive integer")
    return raw


def preflight() -> dict:
    python_version = sys.version.splitlines()[0] if sys.version else "unknown"
    node_path = _find_exe("node")
    node_version: str | None = None
    node_ok = False
    if node_path is not None:
        try:
            completed = subprocess.run(
                [node_path, "--version"],
                capture_output=True,
                text=True,
                timeout=PREFLIGHT_TIMEOUT_S,
            )
            if completed.returncode == 0:
                node_version = completed.stdout.strip() or completed.stderr.strip() or "unknown"
                node_ok = True
            else:
                node_version = f"node --version exited {completed.returncode}"
        except (OSError, subprocess.SubprocessError) as error:
            node_version = f"node preflight failed: {error}"
    return {
        "python_version": python_version,
        "python_ok": True,
        "node_path": node_path,
        "node_version": node_version,
        "node_ok": node_ok,
    }


def _resolve_argv(argv: list[str], root: Path) -> tuple[list[str] | None, str | None]:
    """Resolve a manifest argv to an executable argument list.

    Returns (resolved_argv, missing_reason). missing_reason is None on success.
    A missing interpreter or a missing repo-relative script is an explicit
    missing reason, never a silent skip.
    """
    head = argv[0]
    if head in ("python", "python3"):
        resolved_head = sys.executable
    elif "/" in head or "\\" in head:
        candidate = root / Path(head)
        if not candidate.is_file():
            return None, f"missing-script: {head}"
        resolved_head = str(candidate)
    else:
        found = _find_exe(head)
        if found is None:
            return None, f"missing-executable: {head}"
        resolved_head = found
    resolved = [resolved_head]
    for item in argv[1:]:
        if item in (".", "--root") or item.startswith("--"):
            resolved.append(item)
            continue
        if item.startswith("scripts/") or item.startswith("integrations/"):
            candidate = root / Path(item)
            if not candidate.is_file():
                return None, f"missing-script: {item}"
            resolved.append(item)
            continue
        resolved.append(item)
    return resolved, None


def _git_head(root: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=PREFLIGHT_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip()
    return value or None


def run_commands(
    manifest: dict,
    root: Path,
    manifest_rel: str,
    manifest_sha256: str,
    runner_sha256: str,
    node_ok: bool,
    node_detail: str | None,
) -> dict:
    started = _utc_now()
    records: list[dict] = []
    failure: dict | None = None
    if not node_ok:
        failure = {
            "command_id": None,
            "reason": f"node-missing: {node_detail or 'node not found on PATH'}",
        }
        for entry in manifest["commands"]:
            records.append(
                {
                    "id": entry["id"],
                    "argv": entry["argv"],
                    "argv_sha256": _argv_digest(entry["argv"]),
                    "timeout_s": entry["timeout_s"],
                    "disposition": "NOT_RUN",
                    "exit_code": None,
                    "duration_s": 0.0,
                    "tail": "",
                    "tail_truncated": False,
                }
            )
    else:
        for entry in manifest["commands"]:
            command_id = entry["id"]
            argv = entry["argv"]
            timeout_s = entry["timeout_s"]
            resolved, missing = _resolve_argv(argv, root)
            if missing is not None:
                records.append(
                    {
                        "id": command_id,
                        "argv": argv,
                        "argv_sha256": _argv_digest(argv),
                        "timeout_s": timeout_s,
                        "disposition": "MISSING",
                        "exit_code": None,
                        "duration_s": 0.0,
                        "tail": missing,
                        "tail_truncated": False,
                    }
                )
                failure = {"command_id": command_id, "reason": missing}
                break
            assert resolved is not None
            begin = time.monotonic()
            try:
                completed = subprocess.run(
                    resolved,
                    cwd=root,
                    capture_output=True,
                    text=True,
                    timeout=timeout_s,
                )
                duration = time.monotonic() - begin
                combined = ""
                if completed.stdout:
                    combined += completed.stdout
                    if not combined.endswith("\n"):
                        combined += "\n"
                if completed.stderr:
                    combined += completed.stderr
                tail, truncated = _bounded_tail(combined.rstrip("\n"))
                if completed.returncode == 0:
                    records.append(
                        {
                            "id": command_id,
                            "argv": argv,
                            "argv_sha256": _argv_digest(argv),
                            "timeout_s": timeout_s,
                            "disposition": "PASS",
                            "exit_code": 0,
                            "duration_s": round(duration, 3),
                            "tail": tail,
                            "tail_truncated": truncated,
                        }
                    )
                else:
                    records.append(
                        {
                            "id": command_id,
                            "argv": argv,
                            "argv_sha256": _argv_digest(argv),
                            "timeout_s": timeout_s,
                            "disposition": "FAIL",
                            "exit_code": completed.returncode,
                            "duration_s": round(duration, 3),
                            "tail": tail,
                            "tail_truncated": truncated,
                        }
                    )
                    failure = {
                        "command_id": command_id,
                        "reason": f"nonzero-exit: {completed.returncode}",
                    }
                    break
            except subprocess.TimeoutExpired as error:
                duration = time.monotonic() - begin
                partial = ""
                if error.stdout:
                    partial += error.stdout.decode("utf-8", "replace") if isinstance(
                        error.stdout, bytes
                    ) else str(error.stdout)
                if error.stderr:
                    partial += error.stderr.decode("utf-8", "replace") if isinstance(
                        error.stderr, bytes
                    ) else str(error.stderr)
                tail, truncated = _bounded_tail(
                    (partial.rstrip("\n") + f"\nTIMEOUT after {timeout_s}s").strip()
                )
                records.append(
                    {
                        "id": command_id,
                        "argv": argv,
                        "argv_sha256": _argv_digest(argv),
                        "timeout_s": timeout_s,
                        "disposition": "TIMEOUT",
                        "exit_code": None,
                        "duration_s": round(duration, 3),
                        "tail": tail,
                        "tail_truncated": truncated,
                    }
                )
                failure = {"command_id": command_id, "reason": f"timeout-after-{timeout_s}s"}
                break
            except OSError as error:
                duration = time.monotonic() - begin
                records.append(
                    {
                        "id": command_id,
                        "argv": argv,
                        "argv_sha256": _argv_digest(argv),
                        "timeout_s": timeout_s,
                        "disposition": "FAIL",
                        "exit_code": None,
                        "duration_s": round(duration, 3),
                        "tail": f"execution failed: {error}",
                        "tail_truncated": False,
                    }
                )
                failure = {"command_id": command_id, "reason": f"execution-failed: {error}"}
                break
        executed_ids = {record["id"] for record in records}
        for entry in manifest["commands"]:
            if entry["id"] not in executed_ids:
                records.append(
                    {
                        "id": entry["id"],
                        "argv": entry["argv"],
                        "argv_sha256": _argv_digest(entry["argv"]),
                        "timeout_s": entry["timeout_s"],
                        "disposition": "NOT_RUN",
                        "exit_code": None,
                        "duration_s": 0.0,
                        "tail": "",
                        "tail_truncated": False,
                    }
                )
    finished = _utc_now()
    return {
        "schema_version": RECEIPT_SCHEMA,
        "issue": ISSUE,
        "entrypoint": "scripts/verify-agent-host-surfaces.py",
        "manifest_path": manifest_rel,
        "manifest_sha256": manifest_sha256,
        "runner_sha256": runner_sha256,
        "source_root": str(root),
        "git_head": _git_head(root),
        "proof_ceiling": PROOF_CEILING,
        "started_at_utc": started,
        "finished_at_utc": finished,
        "aggregate": "PASS" if failure is None else "FAIL",
        "failure": failure,
        "commands": records,
    }


def _write_receipt(receipt: dict, path: Path) -> None:
    payload = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")


def _run_single(manifest_commands: list[dict], root: Path) -> dict:
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "proof_ceiling": PROOF_CEILING,
        "commands": manifest_commands,
    }
    return run_commands(
        manifest=manifest,
        root=root,
        manifest_rel="<self-test-synthetic>",
        manifest_sha256=_argv_digest([c["id"] for c in manifest_commands]),
        runner_sha256="self-test",
        node_ok=True,
        node_detail=None,
    )


def self_test(root: Path) -> int:
    cases = 0

    receipt = _run_single(
        [{"id": "synthetic-pass", "argv": ["python", "-c", "print('synthetic-pass-ok')"], "timeout_s": 60}],
        root,
    )
    assert receipt["aggregate"] == "PASS", receipt
    assert receipt["commands"][0]["disposition"] == "PASS", receipt
    assert receipt["proof_ceiling"] == PROOF_CEILING, receipt
    cases += 1

    receipt = _run_single(
        [
            {"id": "synthetic-pass", "argv": ["python", "-c", "print('ok')"], "timeout_s": 60},
            {
                "id": "synthetic-nonzero",
                "argv": ["python", "-c", "import sys; print('boom-tail-marker'); sys.exit(3)"],
                "timeout_s": 60,
            },
            {"id": "synthetic-never", "argv": ["python", "-c", "print('never')"], "timeout_s": 60},
        ],
        root,
    )
    assert receipt["aggregate"] == "FAIL", receipt
    assert receipt["failure"] == {
        "command_id": "synthetic-nonzero",
        "reason": "nonzero-exit: 3",
    }, receipt
    by_id = {item["id"]: item for item in receipt["commands"]}
    assert by_id["synthetic-nonzero"]["disposition"] == "FAIL", receipt
    assert by_id["synthetic-nonzero"]["exit_code"] == 3, receipt
    assert "boom-tail-marker" in by_id["synthetic-nonzero"]["tail"], receipt
    assert by_id["synthetic-never"]["disposition"] == "NOT_RUN", receipt
    cases += 1

    receipt = _run_single(
        [
            {
                "id": "synthetic-timeout",
                "argv": ["python", "-c", "import time; time.sleep(30)"],
                "timeout_s": 1,
            }
        ],
        root,
    )
    assert receipt["aggregate"] == "FAIL", receipt
    assert receipt["commands"][0]["disposition"] == "TIMEOUT", receipt
    assert receipt["failure"] == {
        "command_id": "synthetic-timeout",
        "reason": "timeout-after-1s",
    }, receipt
    cases += 1

    receipt = _run_single(
        [{"id": "synthetic-missing-script", "argv": ["python", "scripts/does-not-exist-250.py"], "timeout_s": 60}],
        root,
    )
    assert receipt["aggregate"] == "FAIL", receipt
    assert receipt["commands"][0]["disposition"] == "MISSING", receipt
    assert receipt["failure"] == {
        "command_id": "synthetic-missing-script",
        "reason": "missing-script: scripts/does-not-exist-250.py",
    }, receipt
    cases += 1

    receipt = _run_single(
        [{"id": "synthetic-missing-exe", "argv": ["definitely-not-a-real-exe-250", "--version"], "timeout_s": 60}],
        root,
    )
    assert receipt["aggregate"] == "FAIL", receipt
    assert receipt["commands"][0]["disposition"] == "MISSING", receipt
    assert receipt["failure"] == {
        "command_id": "synthetic-missing-exe",
        "reason": "missing-executable: definitely-not-a-real-exe-250",
    }, receipt
    cases += 1

    global _find_exe
    original_find_exe = _find_exe
    try:
        _find_exe = lambda name: None if name == "node" else original_find_exe(name)  # noqa: E731
        manifest = {
            "schema_version": MANIFEST_SCHEMA,
            "proof_ceiling": PROOF_CEILING,
            "commands": [
                {"id": "synthetic-node", "argv": ["node", "--version"], "timeout_s": 60},
            ],
        }
        receipt = run_commands(
            manifest=manifest,
            root=root,
            manifest_rel="<self-test-synthetic>",
            manifest_sha256="self-test",
            runner_sha256="self-test",
            node_ok=False,
            node_detail="node not found on PATH",
        )
        assert receipt["aggregate"] == "FAIL", receipt
        assert receipt["failure"] == {
            "command_id": None,
            "reason": "node-missing: node not found on PATH",
        }, receipt
        assert receipt["commands"][0]["disposition"] == "NOT_RUN", receipt
    finally:
        _find_exe = original_find_exe
    cases += 1

    receipt = _run_single(
        [{"id": "synthetic-digest", "argv": ["python", "-c", "print('digest')"], "timeout_s": 60}],
        root,
    )
    record = receipt["commands"][0]
    assert record["argv_sha256"] == _argv_digest(["python", "-c", "print('digest')"]), receipt
    assert isinstance(record["duration_s"], float) and record["duration_s"] >= 0.0, receipt
    required_keys = {
        "schema_version",
        "issue",
        "entrypoint",
        "manifest_path",
        "manifest_sha256",
        "runner_sha256",
        "source_root",
        "git_head",
        "proof_ceiling",
        "started_at_utc",
        "finished_at_utc",
        "aggregate",
        "failure",
        "commands",
    }
    assert required_keys.issubset(receipt.keys()), receipt
    with tempfile.TemporaryDirectory(prefix="eliot-host-surfaces-self-test-") as directory:
        out = Path(directory) / "receipt.json"
        _write_receipt(receipt, out)
        reloaded = json.loads(out.read_text(encoding="utf-8"))
        assert reloaded == receipt, "receipt round-trip mismatch"
    cases += 1

    print(f"VERIFY_AGENT_HOST_SURFACES_SELF_TEST: PASS cases={cases}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Manual verification entrypoint for all agent host surfaces (issue #250)."
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).resolve().parent / "verify-agent-host-surfaces.manifest.json",
        help="ordered command manifest",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (commands run with this working directory)",
    )
    parser.add_argument("--receipt-out", type=Path, help="write the JSON receipt to this path")
    parser.add_argument("--list", action="store_true", help="list ordered manifest command ids")
    parser.add_argument("--self-test", action="store_true", help="run synthetic fail-closed self-test")
    arguments = parser.parse_args()

    root = arguments.root.resolve()
    if arguments.self_test:
        return self_test(root)

    try:
        manifest_path = arguments.manifest.resolve()
        manifest = load_manifest(manifest_path)
    except ValueError as error:
        print(f"AGENT_HOST_SURFACES_VERIFY: FAIL reason=invalid-manifest: {error}", file=sys.stderr)
        return 1

    if arguments.list:
        for entry in manifest["commands"]:
            print(entry["id"])
        return 0

    try:
        manifest_rel = str(manifest_path.relative_to(root)).replace("\\", "/")
    except ValueError:
        manifest_rel = str(manifest_path)
    manifest_sha256 = _sha256_file(manifest_path)
    runner_sha256 = _sha256_file(Path(__file__).resolve())

    flight = preflight()
    receipt = run_commands(
        manifest=manifest,
        root=root,
        manifest_rel=manifest_rel,
        manifest_sha256=manifest_sha256,
        runner_sha256=runner_sha256,
        node_ok=bool(flight["node_ok"]),
        node_detail=None if flight["node_ok"] else (flight["node_version"] or "node not found on PATH"),
    )
    receipt["preflight"] = flight

    if arguments.receipt_out is not None:
        _write_receipt(receipt, arguments.receipt_out.resolve())
        detail = f" receipt={arguments.receipt_out.resolve()}"
    else:
        print(json.dumps(receipt, indent=2, sort_keys=True))
        detail = ""

    if receipt["aggregate"] == "PASS":
        print(
            f"AGENT_HOST_SURFACES_VERIFY: PASS commands={len(receipt['commands'])}{detail}"
        )
        return 0
    failure = receipt["failure"] or {}
    print(
        "AGENT_HOST_SURFACES_VERIFY: FAIL "
        f"failed={failure.get('command_id')} reason={failure.get('reason')}{detail}"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
