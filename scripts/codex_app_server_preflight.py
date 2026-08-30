#!/usr/bin/env python3
"""Bounded zero-model Codex App Server preflight.

The preflight performs only initialize -> initialized -> model/list. It never
starts a thread or turn and cannot admit the route by itself.
"""
from __future__ import annotations

import hashlib
import json
import os
import queue
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

CONTRACT_PATH = Path("integrations/codex/app-server-preflight.contract.json")
CONTRACT_VERSION = "eliot.codex-app-server-preflight.v1"
RECEIPT_VERSION = "eliot.codex-app-server-preflight-receipt.v1"


class CodexPreflightError(RuntimeError):
    """A stable diagnostic preflight failure without protected payloads."""


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
        raise CodexPreflightError("contract is unreadable") from error
    if not isinstance(value, dict):
        raise CodexPreflightError("contract root must be an object")
    validate_contract(value)
    return value


def _walk_fields(value: Any) -> set[str]:
    fields: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            fields.add(str(key))
            fields.update(_walk_fields(child))
    elif isinstance(value, list):
        for child in value:
            fields.update(_walk_fields(child))
    return fields


def validate_contract(contract: dict[str, Any]) -> None:
    if contract.get("schema_version") != CONTRACT_VERSION:
        raise CodexPreflightError("contract schema mismatch")
    if contract.get("receipt_schema") != RECEIPT_VERSION:
        raise CodexPreflightError("receipt schema mismatch")
    if contract.get("transport") != "stdio_jsonl":
        raise CodexPreflightError("only stdio JSONL is admitted")
    if contract.get("model_execution_allowed") is not False:
        raise CodexPreflightError("preflight may not execute a model")
    if contract.get("experimental_api_allowed") is not False:
        raise CodexPreflightError("preflight may not enable experimental API")
    if contract.get("fixed_model_id") is not None:
        raise CodexPreflightError("fixed universal model ID is forbidden")
    program = contract.get("program")
    argv = contract.get("argv")
    if not isinstance(program, str) or not program.strip() or not isinstance(argv, list):
        raise CodexPreflightError("launch contract is invalid")
    if not all(isinstance(item, str) and item for item in argv):
        raise CodexPreflightError("launch argv is invalid")
    requests = contract.get("requests")
    if not isinstance(requests, list) or len(requests) != 3:
        raise CodexPreflightError("exactly three stable preflight messages are required")
    methods = [item.get("method") if isinstance(item, dict) else None for item in requests]
    if methods != ["initialize", "initialized", "model/list"]:
        raise CodexPreflightError("stable preflight message order drifted")
    if requests[0].get("kind") != "request" or requests[0].get("id") != 1:
        raise CodexPreflightError("initialize request identity drifted")
    if requests[1].get("kind") != "notification" or "id" in requests[1]:
        raise CodexPreflightError("initialized must be a notification")
    if requests[2].get("kind") != "request" or requests[2].get("id") != 2:
        raise CodexPreflightError("model/list request identity drifted")
    capabilities = requests[0].get("params", {}).get("capabilities", {})
    if capabilities.get("experimentalApi") is not False:
        raise CodexPreflightError("experimental API must be explicitly disabled")
    forbidden_methods = contract.get("forbidden_methods")
    if not isinstance(forbidden_methods, list) or any(method in forbidden_methods for method in methods):
        raise CodexPreflightError("forbidden method entered stable preflight")
    fields = _walk_fields(requests)
    if any(field in fields for field in contract.get("forbidden_wire_fields", [])):
        raise CodexPreflightError("stale wire field entered stable preflight")
    allowlist = contract.get("environment_allowlist")
    if not isinstance(allowlist, list) or not allowlist or not all(isinstance(item, str) and item for item in allowlist):
        raise CodexPreflightError("environment allowlist is invalid")
    if any("KEY" in item or "TOKEN" in item or "SECRET" in item or "PASSWORD" in item for item in allowlist):
        raise CodexPreflightError("provider credential variable entered environment allowlist")
    bounds = contract.get("bounds")
    if not isinstance(bounds, dict):
        raise CodexPreflightError("preflight bounds are missing")
    for field in (
        "operation_timeout_ms",
        "version_timeout_ms",
        "max_line_bytes",
        "max_total_stdout_bytes",
        "max_stderr_bytes",
        "max_catalogue_pages",
        "max_models",
    ):
        if not isinstance(bounds.get(field), int) or bounds[field] <= 0:
            raise CodexPreflightError(f"invalid bound: {field}")


def stable_messages(contract: dict[str, Any]) -> list[dict[str, Any]]:
    validate_contract(contract)
    return [
        {key: value for key, value in message.items() if key != "kind"}
        for message in contract["requests"]
    ]


def _allowlisted_environment(contract: dict[str, Any], source: dict[str, str] | None = None) -> dict[str, str]:
    source = os.environ if source is None else source
    return {
        key: source[key]
        for key in contract["environment_allowlist"]
        if key in source and isinstance(source[key], str)
    }


@dataclass
class StreamDigest:
    total_bytes: int = 0
    retained: bytearray | None = None
    digest: Any = None
    truncated: bool = False

    def __post_init__(self) -> None:
        if self.retained is None:
            self.retained = bytearray()
        if self.digest is None:
            self.digest = hashlib.sha256()

    def update(self, data: bytes, limit: int) -> None:
        self.total_bytes += len(data)
        self.digest.update(data)
        remaining = max(0, limit - len(self.retained))
        if remaining:
            self.retained.extend(data[:remaining])
        if len(data) > remaining:
            self.truncated = True

    def receipt(self) -> dict[str, Any]:
        return {
            "sha256": self.digest.hexdigest(),
            "total_bytes": self.total_bytes,
            "retained_bytes": len(self.retained),
            "truncated": self.truncated,
        }


class JsonlReader:
    def __init__(self, stream: BinaryIO, max_line_bytes: int, max_total_bytes: int) -> None:
        self._stream = stream
        self._max_line_bytes = max_line_bytes
        self._max_total_bytes = max_total_bytes
        self._queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._thread = threading.Thread(target=self._run, name="eliot-codex-jsonl-reader", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        total = 0
        try:
            while True:
                line = self._stream.readline(self._max_line_bytes + 2)
                if not line:
                    self._queue.put(("eof", None))
                    return
                total += len(line)
                if len(line) > self._max_line_bytes or total > self._max_total_bytes:
                    self._queue.put(("error", "stdout bound exceeded"))
                    return
                self._queue.put(("line", line))
        except Exception:
            self._queue.put(("error", "stdout read failed"))

    def read_json(self, deadline: float) -> dict[str, Any]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CodexPreflightError("App Server response timeout")
        try:
            kind, payload = self._queue.get(timeout=remaining)
        except queue.Empty as error:
            raise CodexPreflightError("App Server response timeout") from error
        if kind == "eof":
            raise CodexPreflightError("App Server closed stdout before required response")
        if kind == "error":
            raise CodexPreflightError(str(payload))
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CodexPreflightError("App Server returned malformed JSONL") from error
        if not isinstance(value, dict):
            raise CodexPreflightError("App Server response root is not an object")
        if "jsonrpc" in value:
            raise CodexPreflightError("stale JSON-RPC envelope was observed")
        return value


class StderrReader:
    def __init__(self, stream: BinaryIO, retain_limit: int) -> None:
        self._stream = stream
        self._retain_limit = retain_limit
        self._digest = StreamDigest()
        self._thread = threading.Thread(target=self._run, name="eliot-codex-stderr-reader", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            while True:
                data = self._stream.read(8192)
                if not data:
                    return
                self._digest.update(data, self._retain_limit)
        except Exception:
            self._digest.update(b"<stderr-read-error>", self._retain_limit)

    def join(self, timeout_seconds: float) -> dict[str, Any]:
        self._thread.join(timeout_seconds)
        receipt = self._digest.receipt()
        receipt["complete"] = not self._thread.is_alive()
        return receipt


def _write_message(stdin: BinaryIO, message: dict[str, Any]) -> None:
    data = canonical_json_bytes(message) + b"\n"
    try:
        stdin.write(data)
        stdin.flush()
    except (OSError, ValueError) as error:
        raise CodexPreflightError("App Server stdin write failed") from error


def _response_result(response: dict[str, Any], expected_id: int) -> dict[str, Any]:
    if response.get("id") != expected_id:
        raise CodexPreflightError("App Server response ID mismatch")
    if response.get("error") is not None:
        raise CodexPreflightError("App Server returned a typed error")
    result = response.get("result")
    if not isinstance(result, dict):
        raise CodexPreflightError("App Server response result is missing")
    return result


def _normalize_models(result: dict[str, Any], seen: set[str], maximum: int) -> tuple[list[dict[str, Any]], str | None]:
    data = result.get("data")
    if not isinstance(data, list):
        raise CodexPreflightError("model/list result.data is not an array")
    normalized: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            raise CodexPreflightError("model/list item is not an object")
        model_id = item.get("id")
        if not isinstance(model_id, str) or not model_id.strip():
            raise CodexPreflightError("model/list item has no stable ID")
        model_id = model_id.strip()
        if model_id in seen:
            raise CodexPreflightError("model/list returned duplicate model ID")
        seen.add(model_id)
        if len(seen) > maximum:
            raise CodexPreflightError("model catalogue exceeds bound")
        display_name = item.get("displayName")
        if display_name is not None and not isinstance(display_name, str):
            raise CodexPreflightError("model displayName has invalid type")
        reasoning = item.get("supportedReasoningEfforts", [])
        modalities = item.get("inputModalities", [])
        if not isinstance(reasoning, list) or not all(isinstance(value, str) for value in reasoning):
            raise CodexPreflightError("model reasoning efforts are invalid")
        if not isinstance(modalities, list) or not all(isinstance(value, str) for value in modalities):
            raise CodexPreflightError("model input modalities are invalid")
        normalized.append(
            {
                "id": model_id,
                "display_name": display_name,
                "is_default": item.get("isDefault") is True,
                "hidden": item.get("hidden") is True,
                "supported_reasoning_efforts": sorted(set(reasoning)),
                "input_modalities": sorted(set(modalities)),
            }
        )
    cursor = result.get("nextCursor")
    if cursor is not None and (not isinstance(cursor, str) or not cursor):
        raise CodexPreflightError("model/list nextCursor is invalid")
    return normalized, cursor


def _creation_flags() -> int:
    if os.name == "nt":
        return getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    return 0


def _terminate_child(process: subprocess.Popen[bytes]) -> tuple[int | None, str]:
    if process.poll() is not None:
        return process.returncode, "already_exited"
    try:
        process.terminate()
        process.wait(timeout=1.5)
        return process.returncode, "terminated_after_preflight"
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=1.5)
            return process.returncode, "killed_after_preflight"
        except subprocess.TimeoutExpired:
            return None, "direct_child_reap_unconfirmed"
    except OSError:
        return process.poll(), "direct_child_termination_error"


def _version_receipt(executable: Path, contract: dict[str, Any], environment: dict[str, str]) -> dict[str, Any]:
    timeout_seconds = contract["bounds"]["version_timeout_ms"] / 1000
    try:
        completed = subprocess.run(
            [str(executable), "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            shell=False,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CodexPreflightError("codex version probe failed") from error
    if completed.returncode != 0:
        raise CodexPreflightError("codex version probe exited nonzero")
    stdout = completed.stdout[:4096]
    try:
        text = stdout.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise CodexPreflightError("codex version output is not UTF-8") from error
    if not text:
        raise CodexPreflightError("codex version output is empty")
    return {
        "text": text,
        "stdout_sha256": sha256_bytes(completed.stdout),
        "stderr_sha256": sha256_bytes(completed.stderr),
        "exit_code": completed.returncode,
    }


def run_preflight(
    root: Path,
    contract: dict[str, Any],
    *,
    program_override: Path | None = None,
    argv_override: list[str] | None = None,
    environment_source: dict[str, str] | None = None,
    skip_version_probe: bool = False,
) -> dict[str, Any]:
    validate_contract(contract)
    program = program_override or (Path(resolved) if (resolved := shutil.which(contract["program"])) else None)
    if program is None or not program.is_file():
        raise CodexPreflightError("codex executable is unavailable")
    program = program.resolve()
    environment = _allowlisted_environment(contract, environment_source)
    version = (
        {"text": "FAKE_TEST_RUNTIME", "stdout_sha256": sha256_bytes(b"FAKE_TEST_RUNTIME"), "stderr_sha256": sha256_bytes(b""), "exit_code": 0}
        if skip_version_probe
        else _version_receipt(program, contract, environment)
    )
    argv = [str(program), *(argv_override if argv_override is not None else contract["argv"])]
    deadline = time.monotonic() + contract["bounds"]["operation_timeout_ms"] / 1000
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            shell=False,
            creationflags=_creation_flags(),
            start_new_session=(os.name != "nt"),
        )
    except OSError as error:
        raise CodexPreflightError("Codex App Server launch failed") from error
    if process.stdin is None or process.stdout is None or process.stderr is None:
        _terminate_child(process)
        raise CodexPreflightError("Codex App Server pipe setup failed")

    stdout = JsonlReader(
        process.stdout,
        contract["bounds"]["max_line_bytes"],
        contract["bounds"]["max_total_stdout_bytes"],
    )
    stderr = StderrReader(process.stderr, contract["bounds"]["max_stderr_bytes"])
    methods_sent: list[str] = []
    models: list[dict[str, Any]] = []
    seen_models: set[str] = set()
    pages = 0
    failure: Exception | None = None
    try:
        initialize, initialized, first_model_list = stable_messages(contract)
        _write_message(process.stdin, initialize)
        methods_sent.append("initialize")
        _response_result(stdout.read_json(deadline), 1)

        _write_message(process.stdin, initialized)
        methods_sent.append("initialized")

        request_id = 2
        request = first_model_list
        while True:
            pages += 1
            if pages > contract["bounds"]["max_catalogue_pages"]:
                raise CodexPreflightError("model catalogue page bound exceeded")
            _write_message(process.stdin, request)
            methods_sent.append("model/list")
            result = _response_result(stdout.read_json(deadline), request_id)
            page_models, cursor = _normalize_models(result, seen_models, contract["bounds"]["max_models"])
            models.extend(page_models)
            if cursor is None:
                break
            request_id += 1
            request = {
                "id": request_id,
                "method": "model/list",
                "params": {"cursor": cursor, "limit": first_model_list["params"]["limit"]},
            }
    except Exception as error:  # cleanup below must always run
        failure = error
    finally:
        try:
            process.stdin.close()
        except OSError:
            pass
        exit_code, termination = _terminate_child(process)
        stderr_receipt = stderr.join(1.0)

    if failure is not None:
        if isinstance(failure, CodexPreflightError):
            raise failure
        raise CodexPreflightError("unexpected App Server preflight failure") from failure
    if termination == "direct_child_reap_unconfirmed":
        raise CodexPreflightError("Codex App Server direct child reap was not confirmed")
    if any(method in contract["forbidden_methods"] for method in methods_sent):
        raise CodexPreflightError("forbidden method was sent")

    models.sort(key=lambda item: item["id"])
    default_models = [item["id"] for item in models if item["is_default"]]
    if len(default_models) > 1:
        raise CodexPreflightError("model catalogue reported multiple defaults")
    return {
        "schema_version": RECEIPT_VERSION,
        "contract_sha256": sha256_bytes(canonical_json_bytes(contract)),
        "executable_path": str(program),
        "executable_sha256": sha256_file(program),
        "version": version,
        "launch_argv": argv[1:],
        "environment_keys": sorted(environment),
        "methods_sent": methods_sent,
        "catalogue_pages": pages,
        "model_count": len(models),
        "default_model_id": default_models[0] if default_models else None,
        "models": models,
        "stderr": stderr_receipt,
        "process_exit_code": exit_code,
        "termination_disposition": termination,
        "process_tree_containment": "DIRECT_CHILD_ONLY_DIAGNOSTIC",
        "model_calls": 0,
        "thread_calls": 0,
        "turn_calls": 0,
        "experimental_api": False,
        "route_admitted": False,
        "proof_ceiling": "ZERO_MODEL_DIAGNOSTIC_PREFLIGHT_ONLY",
    }
