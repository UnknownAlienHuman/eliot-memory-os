#!/usr/bin/env python3
"""Bounded zero-model OpenCode loopback server preflight."""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CONTRACT_PATH = Path("integrations/opencode/http-sse-preflight.contract.json")
CONTRACT_VERSION = "eliot.opencode-http-sse-preflight.v1"
RECEIPT_VERSION = "eliot.opencode-http-sse-preflight-receipt.v1"
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}


class OpenCodePreflightError(RuntimeError):
    """Stable preflight failure without response/credential payloads."""


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
        raise OpenCodePreflightError("OpenCode preflight contract is unreadable") from error
    if not isinstance(value, dict):
        raise OpenCodePreflightError("OpenCode preflight contract root must be an object")
    validate_contract(value)
    return value


def validate_contract(contract: dict[str, Any]) -> None:
    if contract.get("schema_version") != CONTRACT_VERSION:
        raise OpenCodePreflightError("OpenCode preflight contract schema mismatch")
    if contract.get("receipt_schema") != RECEIPT_VERSION:
        raise OpenCodePreflightError("OpenCode preflight receipt schema mismatch")
    expected_false = (
        "model_execution_allowed",
        "session_creation_allowed",
        "event_stream_connection_allowed",
        "route_admitted",
    )
    if any(contract.get(field) is not False for field in expected_false):
        raise OpenCodePreflightError("OpenCode preflight crossed its zero-model/read-only ceiling")
    if contract.get("fixed_model_id") is not None:
        raise OpenCodePreflightError("fixed universal model ID is forbidden")
    if contract.get("process_tree_containment") != "DIRECT_CHILD_ONLY_DIAGNOSTIC":
        raise OpenCodePreflightError("diagnostic process proof ceiling drifted")
    launch = contract.get("launch")
    if not isinstance(launch, dict):
        raise OpenCodePreflightError("OpenCode launch contract is missing")
    if launch.get("shell") is not False or launch.get("hostname") != "127.0.0.1":
        raise OpenCodePreflightError("OpenCode launch must be shell-free and loopback-only")
    prefix = launch.get("argv_prefix")
    if prefix != ["serve", "--hostname", "127.0.0.1", "--port"]:
        raise OpenCodePreflightError("OpenCode serve argv prefix drifted")
    if launch.get("credential_environment_variable") != "OPENCODE_SERVER_PASSWORD":
        raise OpenCodePreflightError("OpenCode credential environment binding drifted")
    allowlist = launch.get("environment_allowlist")
    if not isinstance(allowlist, list) or not allowlist:
        raise OpenCodePreflightError("OpenCode environment allowlist is invalid")
    if any(any(fragment in key.upper() for fragment in ("TOKEN", "SECRET", "PASSWORD", "API_KEY")) for key in allowlist):
        raise OpenCodePreflightError("provider credential variable entered ambient allowlist")
    endpoints = contract.get("endpoints")
    if not isinstance(endpoints, dict):
        raise OpenCodePreflightError("OpenCode endpoint contract is missing")
    for name in ("health", "openapi", "providers"):
        values = endpoints.get(name)
        if not isinstance(values, list) or not values or not all(isinstance(value, str) and value.startswith("/") for value in values):
            raise OpenCodePreflightError(f"OpenCode {name} endpoint candidates are invalid")
    required = contract.get("required_openapi_capabilities")
    if not isinstance(required, dict) or set(required) != {
        "session_create", "session_prompt", "session_abort", "event_stream", "provider_catalogue"
    }:
        raise OpenCodePreflightError("OpenCode required capability set drifted")
    for name, candidates in required.items():
        if not isinstance(candidates, list) or not candidates or not all(isinstance(item, str) and " " in item for item in candidates):
            raise OpenCodePreflightError(f"OpenCode capability candidates are invalid: {name}")
    bounds = contract.get("bounds")
    if not isinstance(bounds, dict):
        raise OpenCodePreflightError("OpenCode bounds are missing")
    for field in (
        "startup_timeout_ms", "request_timeout_ms", "version_timeout_ms", "poll_interval_ms",
        "max_health_bytes", "max_openapi_bytes", "max_provider_bytes",
        "max_stdout_retained_bytes", "max_stderr_retained_bytes", "max_providers", "max_models",
    ):
        if not isinstance(bounds.get(field), int) or bounds[field] <= 0:
            raise OpenCodePreflightError(f"invalid OpenCode bound: {field}")


def _allowlisted_environment(contract: dict[str, Any], password: str, source: dict[str, str] | None) -> dict[str, str]:
    source = os.environ if source is None else source
    environment = {
        key: source[key]
        for key in contract["launch"]["environment_allowlist"]
        if key in source and isinstance(source[key], str)
    }
    environment[contract["launch"]["credential_environment_variable"]] = password
    return environment


def _read_password_file(path: Path) -> str:
    if not path.is_absolute():
        raise OpenCodePreflightError("OpenCode password file must be absolute")
    try:
        status = path.lstat()
    except OSError as error:
        raise OpenCodePreflightError("OpenCode password file is unavailable") from error
    if path.is_symlink() or not path.is_file() or status.st_size <= 0 or status.st_size > 4096:
        raise OpenCodePreflightError("OpenCode password file failed bounded validation")
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as error:
        raise OpenCodePreflightError("OpenCode password file could not be read") from error
    if not value or len(value.encode("utf-8")) > 4096:
        raise OpenCodePreflightError("OpenCode password is invalid")
    return value


def reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


@dataclass
class StreamDrain:
    stream: Any
    retain_limit: int

    def __post_init__(self) -> None:
        self.retained = bytearray()
        self.digest = hashlib.sha256()
        self.total_bytes = 0
        self.complete = False
        self.thread = threading.Thread(target=self._run, name="eliot-opencode-stream-drain", daemon=True)
        self.thread.start()

    def _run(self) -> None:
        try:
            while True:
                data = self.stream.read(8192)
                if not data:
                    self.complete = True
                    return
                self.total_bytes += len(data)
                self.digest.update(data)
                remaining = max(0, self.retain_limit - len(self.retained))
                if remaining:
                    self.retained.extend(data[:remaining])
        except Exception:
            self.digest.update(b"<stream-read-error>")

    def receipt(self, join_seconds: float = 1.0) -> dict[str, Any]:
        self.thread.join(join_seconds)
        return {
            "sha256": self.digest.hexdigest(),
            "total_bytes": self.total_bytes,
            "retained_bytes": len(self.retained),
            "truncated": self.total_bytes > len(self.retained),
            "complete": self.complete and not self.thread.is_alive(),
        }


def _basic_authorization(username: str, password: str) -> str:
    encoded = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"


def _http_get(port: int, path: str, username: str, password: str, timeout_ms: int, max_bytes: int) -> tuple[int, bytes, str | None]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout_ms / 1000)
    try:
        connection.request("GET", path, headers={
            "Authorization": _basic_authorization(username, password),
            "Accept": "application/json",
            "Host": f"127.0.0.1:{port}",
        })
        response = connection.getresponse()
        length = response.getheader("Content-Length")
        if length is not None:
            try:
                if int(length) > max_bytes:
                    raise OpenCodePreflightError("OpenCode HTTP response exceeded declared bound")
            except ValueError as error:
                raise OpenCodePreflightError("OpenCode HTTP Content-Length is invalid") from error
        data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise OpenCodePreflightError("OpenCode HTTP response exceeded bound")
        return response.status, data, response.getheader("Content-Type")
    except (OSError, http.client.HTTPException, socket.timeout) as error:
        raise OpenCodePreflightError("OpenCode loopback HTTP request failed") from error
    finally:
        connection.close()


def _get_first_json(port: int, candidates: list[str], username: str, password: str, timeout_ms: int, max_bytes: int, label: str) -> tuple[str, dict[str, Any], bytes]:
    last_status: int | None = None
    for path in candidates:
        status, data, _ = _http_get(port, path, username, password, timeout_ms, max_bytes)
        last_status = status
        if status == 404:
            continue
        if status in (401, 403):
            raise OpenCodePreflightError(f"OpenCode {label} authentication failed")
        if status < 200 or status >= 300:
            raise OpenCodePreflightError(f"OpenCode {label} endpoint returned non-success")
        try:
            value = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise OpenCodePreflightError(f"OpenCode {label} endpoint returned malformed JSON") from error
        if not isinstance(value, dict):
            raise OpenCodePreflightError(f"OpenCode {label} JSON root is not an object")
        return path, value, data
    raise OpenCodePreflightError(f"OpenCode {label} endpoint is unavailable (last status {last_status})")


def _wait_for_health(port: int, contract: dict[str, Any], password: str, process: subprocess.Popen[bytes]) -> tuple[str, dict[str, Any], bytes]:
    deadline = time.monotonic() + contract["bounds"]["startup_timeout_ms"] / 1000
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise OpenCodePreflightError("OpenCode server exited before health readiness")
        try:
            path, health, data = _get_first_json(
                port,
                contract["endpoints"]["health"],
                contract["launch"]["username"],
                password,
                contract["bounds"]["request_timeout_ms"],
                contract["bounds"]["max_health_bytes"],
                "health",
            )
            if health.get("healthy") is not True:
                raise OpenCodePreflightError("OpenCode health response is not healthy")
            if not isinstance(health.get("version"), str) or not health["version"].strip():
                raise OpenCodePreflightError("OpenCode health response has no version")
            return path, health, data
        except OpenCodePreflightError as error:
            last_error = error
            time.sleep(contract["bounds"]["poll_interval_ms"] / 1000)
    raise OpenCodePreflightError("OpenCode server did not become healthy before timeout") from last_error


def normalize_openapi_path(path: str) -> str:
    parts = []
    for part in path.split("/"):
        if part.startswith("{") and part.endswith("}"):
            name = part[1:-1].lower()
            if "session" in name or name in {"id", "sessionid"}:
                parts.append("{sessionID}")
            else:
                parts.append("{" + name + "}")
        else:
            parts.append(part)
    return "/".join(parts)


def openapi_operations(document: dict[str, Any]) -> list[dict[str, str | None]]:
    version = document.get("openapi")
    if not isinstance(version, str) or not version.startswith("3."):
        raise OpenCodePreflightError("OpenCode document is not OpenAPI 3.x")
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise OpenCodePreflightError("OpenCode OpenAPI paths are missing")
    operations: list[dict[str, str | None]] = []
    for raw_path, entry in paths.items():
        if not isinstance(raw_path, str) or not raw_path.startswith("/") or not isinstance(entry, dict):
            continue
        path = normalize_openapi_path(raw_path)
        for method, operation in entry.items():
            method_lower = str(method).lower()
            if method_lower not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            operation_id = operation.get("operationId")
            operations.append({
                "method": method_lower.upper(),
                "path": path,
                "operation_id": operation_id if isinstance(operation_id, str) else None,
            })
    operations.sort(key=lambda item: (str(item["method"]), str(item["path"]), str(item["operation_id"])))
    return operations


def _resolve_capabilities(contract: dict[str, Any], operations: list[dict[str, str | None]]) -> tuple[dict[str, str], dict[str, str | None]]:
    available = {f"{item['method']} {item['path']}" for item in operations}
    required: dict[str, str] = {}
    for name, candidates in contract["required_openapi_capabilities"].items():
        match = next((candidate for candidate in candidates if candidate in available), None)
        if match is None:
            raise OpenCodePreflightError(f"OpenCode OpenAPI lacks required capability: {name}")
        required[name] = match
    optional: dict[str, str | None] = {}
    for name, candidates in contract.get("optional_openapi_capabilities", {}).items():
        optional[name] = next((candidate for candidate in candidates if candidate in available), None)
    return required, optional


def _provider_list(value: dict[str, Any]) -> tuple[list[Any], set[str], dict[str, str]]:
    providers = value.get("all")
    if not isinstance(providers, list):
        providers = value.get("providers")
    if not isinstance(providers, list):
        raise OpenCodePreflightError("OpenCode provider catalogue has no provider array")
    connected_raw = value.get("connected", [])
    connected = {item for item in connected_raw if isinstance(item, str)} if isinstance(connected_raw, list) else set()
    defaults_raw = value.get("default", {})
    defaults = {str(key): val for key, val in defaults_raw.items() if isinstance(val, str)} if isinstance(defaults_raw, dict) else {}
    return providers, connected, defaults


def normalize_provider_catalogue(value: dict[str, Any], max_providers: int, max_models: int) -> tuple[list[dict[str, Any]], int]:
    providers, connected_ids, defaults = _provider_list(value)
    if len(providers) > max_providers:
        raise OpenCodePreflightError("OpenCode provider count exceeds bound")
    normalized: list[dict[str, Any]] = []
    seen_providers: set[str] = set()
    seen_models: set[tuple[str, str]] = set()
    model_count = 0
    for provider in providers:
        if not isinstance(provider, dict):
            raise OpenCodePreflightError("OpenCode provider entry is invalid")
        provider_id = provider.get("id")
        if not isinstance(provider_id, str) or not provider_id.strip():
            raise OpenCodePreflightError("OpenCode provider has no stable ID")
        provider_id = provider_id.strip()
        if provider_id in seen_providers:
            raise OpenCodePreflightError("OpenCode provider catalogue contains duplicate provider ID")
        seen_providers.add(provider_id)
        models_raw = provider.get("models", {})
        model_entries: list[tuple[str | None, Any]]
        if isinstance(models_raw, dict):
            model_entries = [(key if isinstance(key, str) else None, model) for key, model in models_raw.items()]
        elif isinstance(models_raw, list):
            model_entries = [(None, model) for model in models_raw]
        else:
            raise OpenCodePreflightError("OpenCode provider models have invalid shape")
        models: list[dict[str, Any]] = []
        for fallback_id, model in model_entries:
            if not isinstance(model, dict):
                raise OpenCodePreflightError("OpenCode model entry is invalid")
            model_id = model.get("id", fallback_id)
            if not isinstance(model_id, str) or not model_id.strip():
                raise OpenCodePreflightError("OpenCode model has no stable ID")
            model_id = model_id.strip()
            identity = (provider_id, model_id)
            if identity in seen_models:
                raise OpenCodePreflightError("OpenCode catalogue contains duplicate model identity")
            seen_models.add(identity)
            model_count += 1
            if model_count > max_models:
                raise OpenCodePreflightError("OpenCode model count exceeds bound")
            limit = model.get("limit", {})
            context = model.get("contextLimit", model.get("context_limit"))
            output = model.get("outputLimit", model.get("output_limit"))
            if isinstance(limit, dict):
                context = limit.get("context", context)
                output = limit.get("output", output)
            models.append({
                "id": model_id,
                "name": model.get("name") if isinstance(model.get("name"), str) else None,
                "context_limit": context if isinstance(context, int) and context > 0 else None,
                "output_limit": output if isinstance(output, int) and output > 0 else None,
                "is_default": defaults.get(provider_id) == model_id,
            })
        models.sort(key=lambda item: item["id"])
        normalized.append({
            "id": provider_id,
            "name": provider.get("name") if isinstance(provider.get("name"), str) else None,
            "connected": provider.get("connected") is True or provider_id in connected_ids,
            "models": models,
        })
    normalized.sort(key=lambda item: item["id"])
    return normalized, model_count


def _version_receipt(executable: Path, contract: dict[str, Any], environment: dict[str, str]) -> dict[str, Any]:
    base_environment = dict(environment)
    base_environment.pop(contract["launch"]["credential_environment_variable"], None)
    try:
        completed = subprocess.run(
            [str(executable), "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=base_environment,
            shell=False,
            timeout=contract["bounds"]["version_timeout_ms"] / 1000,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise OpenCodePreflightError("OpenCode version probe failed") from error
    if completed.returncode != 0:
        raise OpenCodePreflightError("OpenCode version probe exited nonzero")
    try:
        text = completed.stdout[:4096].decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise OpenCodePreflightError("OpenCode version output is not UTF-8") from error
    if not text:
        raise OpenCodePreflightError("OpenCode version output is empty")
    return {
        "text": text,
        "stdout_sha256": sha256_bytes(completed.stdout),
        "stderr_sha256": sha256_bytes(completed.stderr),
        "exit_code": completed.returncode,
    }


def _creation_flags() -> int:
    return getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0


def _terminate(process: subprocess.Popen[bytes]) -> tuple[int | None, str]:
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


def run_preflight(
    root: Path,
    contract: dict[str, Any],
    password_file: Path,
    *,
    program_override: Path | None = None,
    argv_override_factory: Any = None,
    environment_source: dict[str, str] | None = None,
    skip_version_probe: bool = False,
) -> dict[str, Any]:
    validate_contract(contract)
    password = _read_password_file(password_file)
    resolved = shutil.which(contract["program"])
    executable = program_override or (Path(resolved) if resolved else None)
    if executable is None or not executable.is_file():
        raise OpenCodePreflightError("OpenCode executable is unavailable")
    executable = executable.resolve()
    port = reserve_loopback_port()
    environment = _allowlisted_environment(contract, password, environment_source)
    version = (
        {"text": "FAKE_TEST_RUNTIME", "stdout_sha256": sha256_bytes(b"FAKE_TEST_RUNTIME"), "stderr_sha256": sha256_bytes(b""), "exit_code": 0}
        if skip_version_probe
        else _version_receipt(executable, contract, environment)
    )
    args = (
        argv_override_factory(port) if argv_override_factory is not None
        else [*contract["launch"]["argv_prefix"], str(port)]
    )
    command = [str(executable), *args]
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            shell=False,
            creationflags=_creation_flags(),
            start_new_session=(os.name != "nt"),
        )
    except OSError as error:
        raise OpenCodePreflightError("OpenCode server launch failed") from error
    if process.stdout is None or process.stderr is None:
        _terminate(process)
        raise OpenCodePreflightError("OpenCode server stream setup failed")
    stdout = StreamDrain(process.stdout, contract["bounds"]["max_stdout_retained_bytes"])
    stderr = StreamDrain(process.stderr, contract["bounds"]["max_stderr_retained_bytes"])
    failure: Exception | None = None
    receipt_data: dict[str, Any] | None = None
    try:
        health_path, health, health_raw = _wait_for_health(port, contract, password, process)
        openapi_path, openapi, openapi_raw = _get_first_json(
            port, contract["endpoints"]["openapi"], contract["launch"]["username"], password,
            contract["bounds"]["request_timeout_ms"], contract["bounds"]["max_openapi_bytes"], "OpenAPI"
        )
        operations = openapi_operations(openapi)
        required, optional = _resolve_capabilities(contract, operations)
        provider_path, providers_raw, provider_bytes = _get_first_json(
            port, contract["endpoints"]["providers"], contract["launch"]["username"], password,
            contract["bounds"]["request_timeout_ms"], contract["bounds"]["max_provider_bytes"], "provider catalogue"
        )
        providers, model_count = normalize_provider_catalogue(
            providers_raw, contract["bounds"]["max_providers"], contract["bounds"]["max_models"]
        )
        receipt_data = {
            "health_path": health_path,
            "health": {"healthy": True, "version": health["version"]},
            "health_raw_sha256": sha256_bytes(health_raw),
            "openapi_path": openapi_path,
            "openapi_version": openapi["openapi"],
            "openapi_raw_sha256": sha256_bytes(openapi_raw),
            "openapi_canonical_sha256": sha256_bytes(canonical_json_bytes(openapi)),
            "operation_count": len(operations),
            "required_capabilities": required,
            "optional_capabilities": optional,
            "provider_path": provider_path,
            "provider_raw_sha256": sha256_bytes(provider_bytes),
            "providers": providers,
            "provider_count": len(providers),
            "model_count": model_count,
            "catalogue_status": "nonempty" if model_count else "empty",
        }
    except Exception as error:
        failure = error
    finally:
        exit_code, termination = _terminate(process)
        stdout_receipt = stdout.receipt()
        stderr_receipt = stderr.receipt()
    if failure is not None:
        if isinstance(failure, OpenCodePreflightError):
            raise failure
        raise OpenCodePreflightError("unexpected OpenCode server preflight failure") from failure
    if termination == "direct_child_reap_unconfirmed":
        raise OpenCodePreflightError("OpenCode server direct child reap was not confirmed")
    assert receipt_data is not None
    return {
        "schema_version": RECEIPT_VERSION,
        "contract_sha256": sha256_bytes(canonical_json_bytes(contract)),
        "executable_path": str(executable),
        "executable_sha256": sha256_file(executable),
        "version": version,
        "launch_argv": args,
        "hostname": "127.0.0.1",
        "port": port,
        "credential_source": "bounded_absolute_password_file",
        "credential_value_recorded": False,
        "environment_keys": sorted(environment),
        **receipt_data,
        "stdout": stdout_receipt,
        "stderr": stderr_receipt,
        "process_exit_code": exit_code,
        "termination_disposition": termination,
        "process_tree_containment": "DIRECT_CHILD_ONLY_DIAGNOSTIC",
        "session_calls": 0,
        "model_calls": 0,
        "event_stream_connections": 0,
        "route_admitted": False,
        "proof_ceiling": "ZERO_MODEL_SERVER_PREFLIGHT_ONLY",
    }
