#!/usr/bin/env python3
"""Zero-model executable/help preflight for Antigravity route candidates.

The probe fingerprints only executable, version, and help surfaces. It does not
start a workspace, run a model, supply provider credentials, or admit a route.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CONTRACT_PATH = Path("integrations/antigravity/runtime-preflight.contract.json")
CONTRACT_VERSION = "eliot.antigravity-runtime-preflight.v1"
RECEIPT_VERSION = "eliot.antigravity-runtime-preflight-receipt.v1"
CREDENTIAL_FRAGMENTS = ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "APIKEY", "CREDENTIAL", "PRIVATE_KEY")


class AntigravityPreflightError(RuntimeError):
    """Stable preflight failure without raw protected output."""


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_contract(root: Path, path: Path = CONTRACT_PATH) -> dict[str, Any]:
    try:
        value = json.loads((root / path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AntigravityPreflightError("Antigravity preflight contract is unreadable") from error
    if not isinstance(value, dict):
        raise AntigravityPreflightError("Antigravity preflight contract root must be an object")
    validate_contract(value)
    return value


def validate_contract(contract: dict[str, Any]) -> None:
    if contract.get("schema_version") != CONTRACT_VERSION:
        raise AntigravityPreflightError("Antigravity preflight contract schema mismatch")
    if contract.get("receipt_schema") != RECEIPT_VERSION:
        raise AntigravityPreflightError("Antigravity preflight receipt schema mismatch")
    if contract.get("provider_credentials_in_probe") is not False:
        raise AntigravityPreflightError("provider credentials are forbidden in the zero-model probe")
    if contract.get("model_calls") != 0:
        raise AntigravityPreflightError("preflight may not execute a model")
    if contract.get("fixed_model_id") is not None:
        raise AntigravityPreflightError("fixed universal model ID is forbidden")
    if contract.get("route_admitted") is not False:
        raise AntigravityPreflightError("preflight may not admit the route")
    runtimes = contract.get("candidate_runtimes")
    if not isinstance(runtimes, list) or len(runtimes) != 2:
        raise AntigravityPreflightError("exactly two runtime candidates are required")
    seen_ids: set[str] = set()
    seen_roles: set[str] = set()
    for runtime in runtimes:
        if not isinstance(runtime, dict):
            raise AntigravityPreflightError("runtime candidate is invalid")
        runtime_id = runtime.get("runtime_id")
        role = runtime.get("route_role")
        if not isinstance(runtime_id, str) or not runtime_id or runtime_id in seen_ids:
            raise AntigravityPreflightError("runtime identity is missing or duplicated")
        if role not in {"primary_candidate", "read_only_fallback"} or role in seen_roles:
            raise AntigravityPreflightError("runtime role is missing or duplicated")
        seen_ids.add(runtime_id)
        seen_roles.add(role)
        programs = runtime.get("program_candidates")
        if not isinstance(programs, list) or not programs or not all(isinstance(item, str) and item for item in programs):
            raise AntigravityPreflightError("runtime program candidates are invalid")
        for field in ("version_argv", "help_argv", "required_help_markers", "optional_help_markers"):
            values = runtime.get(field)
            if not isinstance(values, list) or not all(isinstance(item, str) and item for item in values):
                raise AntigravityPreflightError(f"runtime {field} is invalid")
        if runtime.get("execution_allowed") is not False:
            raise AntigravityPreflightError("zero-model preflight may not execute a runtime attempt")
    if seen_roles != {"primary_candidate", "read_only_fallback"}:
        raise AntigravityPreflightError("runtime role set drifted")
    allowlist = contract.get("environment_allowlist")
    if not isinstance(allowlist, list) or not allowlist:
        raise AntigravityPreflightError("environment allowlist is invalid")
    if any(any(fragment in key.upper() for fragment in CREDENTIAL_FRAGMENTS) for key in allowlist):
        raise AntigravityPreflightError("credential-like variable entered the environment allowlist")
    bounds = contract.get("bounds")
    if not isinstance(bounds, dict):
        raise AntigravityPreflightError("preflight bounds are missing")
    for field in (
        "version_timeout_ms",
        "help_timeout_ms",
        "max_version_bytes",
        "max_help_bytes",
        "max_stderr_bytes",
    ):
        if not isinstance(bounds.get(field), int) or bounds[field] <= 0:
            raise AntigravityPreflightError(f"invalid preflight bound: {field}")
    fallback = contract.get("fallback")
    expected_fallback = {
        "runtime_id": "antigravity.agy-readonly",
        "fresh_only": True,
        "resume": False,
        "native_subagents": False,
        "worktree_mutation": False,
        "output_authority": "candidate_unified_diff_only",
        "unknown_outcome_redispatch": False,
        "task_completion_authority": False,
    }
    if fallback != expected_fallback:
        raise AntigravityPreflightError("read-only fallback contract drifted")
    requirements = contract.get("primary_admission_requires")
    required_requirements = {
        "exact_executable_sha256",
        "exact_version_receipt",
        "exact_help_sha256",
        "required_help_markers",
        "observed_request_event_schema",
        "current_account_model_catalogue",
        "provider_interrupt_and_terminal_reconciliation",
        "process_tree_containment",
        "descendant_closure",
        "bounded_product_pulse",
    }
    if not isinstance(requirements, list) or set(requirements) != required_requirements:
        raise AntigravityPreflightError("primary admission requirements drifted")


def _allowlisted_environment(contract: dict[str, Any], source: dict[str, str] | None = None) -> dict[str, str]:
    source = os.environ if source is None else source
    return {
        key: source[key]
        for key in contract["environment_allowlist"]
        if key in source and isinstance(source[key], str)
    }


@dataclass(frozen=True)
class ProgramOverride:
    program: Path
    prefix: tuple[str, ...] = ()


class StreamCollector:
    def __init__(self, stream: Any, maximum: int) -> None:
        self.stream = stream
        self.maximum = maximum
        self.data = bytearray()
        self.total_bytes = 0
        self.digest = hashlib.sha256()
        self.overflow = threading.Event()
        self.complete = threading.Event()
        self.read_failed = threading.Event()
        self.thread = threading.Thread(target=self._run, name="eliot-antigravity-preflight-drain", daemon=True)
        self.thread.start()

    def _run(self) -> None:
        try:
            while True:
                block = self.stream.read(8192)
                if not block:
                    self.complete.set()
                    return
                self.total_bytes += len(block)
                self.digest.update(block)
                remaining = max(0, self.maximum + 1 - len(self.data))
                if remaining:
                    self.data.extend(block[:remaining])
                if self.total_bytes > self.maximum:
                    self.overflow.set()
        except Exception:
            self.read_failed.set()
            self.complete.set()

    def receipt(self) -> dict[str, Any]:
        return {
            "sha256": self.digest.hexdigest(),
            "total_bytes": self.total_bytes,
            "retained_bytes": min(len(self.data), self.maximum),
            "truncated": self.total_bytes > self.maximum,
            "complete": self.complete.is_set() and not self.thread.is_alive(),
            "read_failed": self.read_failed.is_set(),
        }


def _terminate(process: subprocess.Popen[bytes]) -> tuple[int | None, str]:
    if process.poll() is not None:
        return process.returncode, "already_exited"
    try:
        process.terminate()
        process.wait(timeout=1.0)
        return process.returncode, "terminated"
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=1.0)
            return process.returncode, "killed"
        except subprocess.TimeoutExpired:
            return None, "reap_unconfirmed"
    except OSError:
        return process.poll(), "termination_error"


def run_bounded(
    command: list[str],
    environment: dict[str, str],
    timeout_ms: int,
    max_stdout: int,
    max_stderr: int,
) -> tuple[bytes, dict[str, Any], dict[str, Any], int]:
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            shell=False,
            start_new_session=(os.name != "nt"),
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0,
        )
    except OSError as error:
        raise AntigravityPreflightError("runtime probe process could not start") from error
    if process.stdout is None or process.stderr is None:
        _terminate(process)
        raise AntigravityPreflightError("runtime probe pipes are unavailable")
    stdout = StreamCollector(process.stdout, max_stdout)
    stderr = StreamCollector(process.stderr, max_stderr)
    deadline = time.monotonic() + timeout_ms / 1000
    failure: str | None = None
    while process.poll() is None:
        if stdout.overflow.is_set() or stderr.overflow.is_set():
            failure = "runtime probe output exceeded its bound"
            break
        if time.monotonic() >= deadline:
            failure = "runtime probe timed out"
            break
        time.sleep(0.01)
    if failure is not None:
        _terminate(process)
    else:
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            failure = "runtime probe exit could not be confirmed"
            _terminate(process)
    stdout.thread.join(1.0)
    stderr.thread.join(1.0)
    stdout_receipt = stdout.receipt()
    stderr_receipt = stderr.receipt()
    if stdout_receipt["read_failed"] or stderr_receipt["read_failed"]:
        raise AntigravityPreflightError("runtime probe stream read failed")
    if not stdout_receipt["complete"] or not stderr_receipt["complete"]:
        raise AntigravityPreflightError("runtime probe stream drain is incomplete")
    if failure is not None:
        raise AntigravityPreflightError(failure)
    if process.returncode != 0:
        raise AntigravityPreflightError("runtime probe exited nonzero")
    return bytes(stdout.data[:max_stdout]), stdout_receipt, stderr_receipt, int(process.returncode)


def _resolve_program(runtime: dict[str, Any], override: ProgramOverride | None) -> tuple[Path, tuple[str, ...]] | None:
    if override is not None:
        path = override.program
        prefix = override.prefix
    else:
        resolved = next((shutil.which(candidate) for candidate in runtime["program_candidates"] if shutil.which(candidate)), None)
        if resolved is None:
            return None
        path = Path(resolved)
        prefix = ()
    try:
        if path.is_symlink() or not path.is_file():
            raise AntigravityPreflightError("runtime executable must be a regular non-symlink file")
        resolved_path = path.resolve(strict=True)
    except OSError as error:
        raise AntigravityPreflightError("runtime executable identity could not be resolved") from error
    return resolved_path, prefix


def _normalize_help_tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9][a-z0-9_.:-]*", text.lower()))


def _probe_runtime(
    contract: dict[str, Any],
    runtime: dict[str, Any],
    environment: dict[str, str],
    override: ProgramOverride | None,
) -> dict[str, Any]:
    resolved = _resolve_program(runtime, override)
    if resolved is None:
        return {
            "runtime_id": runtime["runtime_id"],
            "route_role": runtime["route_role"],
            "status": "absent",
            "executable_path": None,
            "route_admitted": False,
            "execution_calls": 0,
            "model_calls": 0,
        }
    executable, prefix = resolved
    bounds = contract["bounds"]
    version_stdout, version_out_receipt, version_err_receipt, version_exit = run_bounded(
        [str(executable), *prefix, *runtime["version_argv"]],
        environment,
        bounds["version_timeout_ms"],
        bounds["max_version_bytes"],
        bounds["max_stderr_bytes"],
    )
    help_stdout, help_out_receipt, help_err_receipt, help_exit = run_bounded(
        [str(executable), *prefix, *runtime["help_argv"]],
        environment,
        bounds["help_timeout_ms"],
        bounds["max_help_bytes"],
        bounds["max_stderr_bytes"],
    )
    try:
        version_text = version_stdout.decode("utf-8").strip()
        help_text = help_stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AntigravityPreflightError("runtime version/help output is not UTF-8") from error
    if not version_text:
        raise AntigravityPreflightError("runtime version output is empty")
    tokens = _normalize_help_tokens(help_text)
    required = {
        marker: marker.lower() in tokens
        for marker in runtime["required_help_markers"]
    }
    optional = {
        marker: marker.lower() in tokens
        for marker in runtime["optional_help_markers"]
    }
    all_required = all(required.values())
    status = "observed_help_candidate" if all_required else "observed_help_incomplete"
    if runtime["route_role"] == "read_only_fallback":
        status = "observed_read_only_fallback"
    return {
        "runtime_id": runtime["runtime_id"],
        "route_role": runtime["route_role"],
        "status": status,
        "executable_path": str(executable),
        "executable_sha256": sha256_file(executable),
        "version_text": version_text[:4096],
        "version_stdout": version_out_receipt,
        "version_stderr": version_err_receipt,
        "version_exit_code": version_exit,
        "help_stdout": help_out_receipt,
        "help_stderr": help_err_receipt,
        "help_exit_code": help_exit,
        "help_sha256": sha256_bytes(help_stdout),
        "required_help_markers": required,
        "optional_help_markers": optional,
        "all_required_help_markers_observed": all_required,
        "route_admitted": False,
        "execution_calls": 0,
        "model_calls": 0,
    }


def run_preflight(
    root: Path,
    contract: dict[str, Any],
    *,
    overrides: dict[str, ProgramOverride] | None = None,
    environment_source: dict[str, str] | None = None,
) -> dict[str, Any]:
    validate_contract(contract)
    environment = _allowlisted_environment(contract, environment_source)
    runtime_receipts = [
        _probe_runtime(
            contract,
            runtime,
            environment,
            None if overrides is None else overrides.get(runtime["runtime_id"]),
        )
        for runtime in contract["candidate_runtimes"]
    ]
    primary = next(item for item in runtime_receipts if item["route_role"] == "primary_candidate")
    fallback = next(item for item in runtime_receipts if item["route_role"] == "read_only_fallback")
    missing_admission = list(contract["primary_admission_requires"])
    if primary.get("status") == "observed_help_candidate":
        for proved in (
            "exact_executable_sha256",
            "exact_version_receipt",
            "exact_help_sha256",
            "required_help_markers",
        ):
            missing_admission.remove(proved)
    return {
        "schema_version": RECEIPT_VERSION,
        "contract_sha256": sha256_bytes(canonical_json_bytes(contract)),
        "environment_keys": sorted(environment),
        "runtimes": runtime_receipts,
        "primary_status": primary["status"],
        "fallback_status": fallback["status"],
        "primary_missing_admission_requirements": missing_admission,
        "fallback_contract": contract["fallback"],
        "provider_credentials_used": False,
        "execution_calls": 0,
        "model_calls": 0,
        "route_admitted": False,
        "proof_ceiling": "ZERO_MODEL_EXECUTABLE_AND_HELP_FINGERPRINT_ONLY",
    }
