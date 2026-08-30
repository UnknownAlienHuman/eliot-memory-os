#!/usr/bin/env python3
"""Persistent, bounded local Claude Agent SDK sidecar for ELIOT.

The sidecar executes at most one provider attempt at a time. It owns neither
ELIOT Task/AgentAttempt state nor finish, recovery, route admission, or swarm
coordination. Provider output remains a candidate until the ELIOT control plane
admits it.
"""
from __future__ import annotations

import asyncio
import hashlib
import importlib
import importlib.metadata
import inspect
import json
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

PROTOCOL_VERSION = "eliot.claude-agent-sdk-sidecar.v2"
RESPONSE_VERSION = "eliot.claude-agent-sdk-sidecar.response.v2"
EVENT_VERSION = "eliot.claude-agent-sdk-sidecar.event.v2"
MAX_FRAME_BYTES = 1_048_576
MAX_PROMPT_BYTES = 262_144
MAX_EVENT_BYTES = 262_144
MAX_RESULT_BYTES = 524_288
MAX_TURNS = 128
MAX_BUDGET_USD = 100.0
CANCEL_SETTLE_SECONDS = 5.0
SHUTDOWN_SETTLE_SECONDS = 5.0
PERMISSION_MODES = {"default", "acceptEdits", "plan", "dontAsk"}

PROTECTED_KEY_FRAGMENTS = (
    "password",
    "passwd",
    "secret",
    "credential",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "authorization",
    "cookie",
    "private_key",
    "raw_mcp",
    "mcp_servers",
    "mcp_command",
    "plugin_path",
    "skill_body",
)
SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)
IDENTITY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}$")
PROFILE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}$")

HELLO_FIELDS = {"protocol_version", "request_id", "type"}
PROBE_FIELDS = {"protocol_version", "request_id", "type"}
START_FIELDS = {
    "protocol_version",
    "request_id",
    "type",
    "task_id",
    "work_item_id",
    "attempt_id",
    "model_selection_receipt_ref",
    "model",
    "fallback_model",
    "prompt",
    "permission_mode",
    "max_turns",
    "max_budget_usd",
    "mcp_profile_ref",
    "skill_profile_ref",
    "plugin_profile_ref",
    "setting_sources",
    "native_subagents",
}
CANCEL_FIELDS = {"protocol_version", "request_id", "type", "attempt_id"}
SHUTDOWN_FIELDS = {"protocol_version", "request_id", "type"}


class SidecarError(RuntimeError):
    """Typed bounded sidecar failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class SdkFacade(Protocol):
    """Exact execution seam used by the sidecar controller."""

    def probe(self) -> dict[str, Any]: ...

    def run(
        self,
        request: dict[str, Any],
        emit: Callable[[str, dict[str, Any]], None],
        cancel_requested: threading.Event,
    ) -> dict[str, Any]: ...

    def interrupt(self, attempt_id: str) -> bool: ...


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def nonblank_identity(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise SidecarError("INVALID_REQUEST", f"{field_name} must be a string")
    value = value.strip()
    if not value or not IDENTITY_PATTERN.fullmatch(value):
        raise SidecarError("INVALID_REQUEST", f"{field_name} is invalid")
    return value


def optional_identity(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    return nonblank_identity(value, field_name)


def optional_profile(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not PROFILE_PATTERN.fullmatch(value.strip()):
        raise SidecarError("INVALID_REQUEST", f"{field_name} is invalid")
    return value.strip()


def reject_protected_input(value: Any, location: str = "$") -> None:
    if isinstance(value, dict):
        for raw_key, child in value.items():
            key = str(raw_key).lower().replace("-", "_")
            if any(fragment in key for fragment in PROTECTED_KEY_FRAGMENTS):
                raise SidecarError("PROTECTED_INPUT", f"protected input is forbidden at {location}")
            reject_protected_input(child, f"{location}.{raw_key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_protected_input(child, f"{location}[{index}]")


def redact_text(value: str, maximum: int) -> str:
    value = value[:maximum]
    for pattern in SECRET_PATTERNS:
        value = pattern.sub("[REDACTED]", value)
    return value


def redact_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 8:
        return "[OMITTED_DEPTH]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for raw_key, child in list(value.items())[:128]:
            key = str(raw_key)
            normalized = key.lower().replace("-", "_")
            if any(fragment in normalized for fragment in PROTECTED_KEY_FRAGMENTS):
                result[key] = "[REDACTED]"
            else:
                result[key] = redact_value(child, depth=depth + 1)
        return result
    if isinstance(value, list):
        return [redact_value(child, depth=depth + 1) for child in value[:128]]
    if isinstance(value, str):
        return redact_text(value, 65_536)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(type(value).__name__)


def bounded_document(value: dict[str, Any], maximum: int, label: str) -> dict[str, Any]:
    redacted = redact_value(value)
    if not isinstance(redacted, dict):
        raise SidecarError("INTERNAL_CONTRACT", f"{label} is not an object")
    if len(canonical_json_bytes(redacted)) > maximum:
        raise SidecarError("OUTPUT_BOUND_EXCEEDED", f"{label} exceeded its bound")
    return redacted


def parse_request_bytes(frame: bytes) -> dict[str, Any]:
    if not frame or len(frame) > MAX_FRAME_BYTES:
        raise SidecarError("FRAME_BOUND_EXCEEDED", "request frame is empty or oversized")
    try:
        value = json.loads(frame.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SidecarError("MALFORMED_JSON", "request frame is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise SidecarError("INVALID_REQUEST", "request root must be an object")
    return value


def validate_request(request: dict[str, Any]) -> dict[str, Any]:
    if request.get("protocol_version") != PROTOCOL_VERSION:
        raise SidecarError("PROTOCOL_MISMATCH", "sidecar protocol version is incompatible")
    request_id = nonblank_identity(request.get("request_id"), "request_id")
    kind = request.get("type")
    if kind not in {"hello", "probe", "start", "cancel", "shutdown"}:
        raise SidecarError("UNKNOWN_REQUEST", "request type is unsupported")
    allowed = {
        "hello": HELLO_FIELDS,
        "probe": PROBE_FIELDS,
        "start": START_FIELDS,
        "cancel": CANCEL_FIELDS,
        "shutdown": SHUTDOWN_FIELDS,
    }[kind]
    if set(request) - allowed:
        raise SidecarError("UNKNOWN_FIELD", "request contains undeclared fields")
    request = dict(request)
    request["request_id"] = request_id
    if kind in {"hello", "probe", "shutdown"}:
        return request
    if kind == "cancel":
        request["attempt_id"] = nonblank_identity(request.get("attempt_id"), "attempt_id")
        return request

    request["task_id"] = nonblank_identity(request.get("task_id"), "task_id")
    request["work_item_id"] = nonblank_identity(request.get("work_item_id"), "work_item_id")
    request["attempt_id"] = nonblank_identity(request.get("attempt_id"), "attempt_id")
    request["model_selection_receipt_ref"] = nonblank_identity(
        request.get("model_selection_receipt_ref"), "model_selection_receipt_ref"
    )
    request["model"] = nonblank_identity(request.get("model"), "model")
    request["fallback_model"] = optional_identity(request.get("fallback_model"), "fallback_model")
    prompt = request.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        raise SidecarError("INVALID_REQUEST", "prompt must be a nonblank string")
    if len(prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
        raise SidecarError("PROMPT_BOUND_EXCEEDED", "prompt exceeded its bound")
    request["prompt"] = prompt
    permission_mode = request.get("permission_mode", "default")
    if permission_mode not in PERMISSION_MODES:
        raise SidecarError("PERMISSION_MODE_FORBIDDEN", "permission mode is not admitted")
    request["permission_mode"] = permission_mode
    max_turns = request.get("max_turns", 32)
    if not isinstance(max_turns, int) or max_turns <= 0 or max_turns > MAX_TURNS:
        raise SidecarError("INVALID_REQUEST", "max_turns is outside the admitted bound")
    request["max_turns"] = max_turns
    max_budget = request.get("max_budget_usd", 10.0)
    if not isinstance(max_budget, (int, float)) or max_budget <= 0 or float(max_budget) > MAX_BUDGET_USD:
        raise SidecarError("INVALID_REQUEST", "max_budget_usd is outside the admitted bound")
    request["max_budget_usd"] = float(max_budget)
    request["mcp_profile_ref"] = optional_profile(request.get("mcp_profile_ref"), "mcp_profile_ref")
    request["skill_profile_ref"] = optional_profile(request.get("skill_profile_ref"), "skill_profile_ref")
    request["plugin_profile_ref"] = optional_profile(request.get("plugin_profile_ref"), "plugin_profile_ref")
    if request.get("setting_sources", []) != []:
        raise SidecarError("AMBIENT_SETTINGS_FORBIDDEN", "setting_sources must remain empty")
    request["setting_sources"] = []
    if request.get("native_subagents", False) is not False:
        raise SidecarError("NATIVE_SUBAGENTS_FORBIDDEN", "native subagents are not admitted")
    request["native_subagents"] = False
    # Scan caller-controlled values after removing the allowed registry references
    # and the explicitly empty ambient-settings field.
    protected_scan = {
        key: value
        for key, value in request.items()
        if key not in {"mcp_profile_ref", "skill_profile_ref", "plugin_profile_ref", "setting_sources"}
    }
    reject_protected_input(protected_scan)
    return request


def request_digest(request: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(request))


def response_document(
    request_id: str,
    *,
    ok: bool,
    result: dict[str, Any] | None = None,
    error: SidecarError | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": RESPONSE_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "request_id": request_id,
        "ok": ok,
    }
    if ok:
        value["result"] = result or {}
    else:
        assert error is not None
        value["error"] = {"code": error.code, "message": error.message}
    return bounded_document(value, MAX_EVENT_BYTES, "sidecar response")


class RealClaudeSdkFacade:
    """Best-effort exact-version adapter. Live compatibility remains unproved."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active: dict[str, tuple[asyncio.AbstractEventLoop, Any]] = {}

    def probe(self) -> dict[str, Any]:
        try:
            version = importlib.metadata.version("claude-agent-sdk")
            module = importlib.import_module("claude_agent_sdk")
        except (importlib.metadata.PackageNotFoundError, ImportError):
            return {
                "sdk_installed": False,
                "package": "claude-agent-sdk",
                "package_version": None,
                "module_sha256": None,
                "required_symbols": {
                    "ClaudeSDKClient": False,
                    "ClaudeAgentOptions": False,
                },
                "provider_execution": False,
                "model_catalogue_supported": False,
                "route_admitted": False,
            }
        module_file = getattr(module, "__file__", None)
        module_hash = None
        if isinstance(module_file, str):
            try:
                module_hash = sha256_bytes(Path(module_file).read_bytes())
            except OSError:
                module_hash = None
        return {
            "sdk_installed": True,
            "package": "claude-agent-sdk",
            "package_version": version,
            "module_sha256": module_hash,
            "required_symbols": {
                "ClaudeSDKClient": hasattr(module, "ClaudeSDKClient"),
                "ClaudeAgentOptions": hasattr(module, "ClaudeAgentOptions"),
            },
            "provider_execution": False,
            "model_catalogue_supported": False,
            "route_admitted": False,
        }

    @staticmethod
    def _options(module: Any, request: dict[str, Any]) -> Any:
        options_type = getattr(module, "ClaudeAgentOptions", None)
        if options_type is None:
            raise SidecarError("SDK_INCOMPATIBLE", "ClaudeAgentOptions is unavailable")
        if any(request.get(field) is not None for field in ("mcp_profile_ref", "skill_profile_ref", "plugin_profile_ref")):
            raise SidecarError(
                "PROFILE_RESOLUTION_UNAVAILABLE",
                "ELIOT registry profile resolution is not implemented in this sidecar slice",
            )
        try:
            signature = inspect.signature(options_type)
        except (TypeError, ValueError) as error:
            raise SidecarError("SDK_INCOMPATIBLE", "ClaudeAgentOptions signature is unavailable") from error
        available = set(signature.parameters)
        required = {"model", "permission_mode", "setting_sources"}
        if not required.issubset(available):
            raise SidecarError("SDK_INCOMPATIBLE", "required ClaudeAgentOptions fields are unavailable")
        values: dict[str, Any] = {
            "model": request["model"],
            "permission_mode": request["permission_mode"],
            "setting_sources": [],
        }
        optional = {
            "fallback_model": request.get("fallback_model"),
            "max_turns": request["max_turns"],
            "max_budget_usd": request["max_budget_usd"],
        }
        for key, value in optional.items():
            if key in available and value is not None:
                values[key] = value
        try:
            return options_type(**values)
        except Exception as error:
            raise SidecarError("SDK_INCOMPATIBLE", "ClaudeAgentOptions construction failed") from error

    @staticmethod
    def _project_message(message: Any, emit: Callable[[str, dict[str, Any]], None]) -> dict[str, Any] | None:
        name = type(message).__name__
        if name == "UserMessage":
            return None
        if name == "AssistantMessage":
            content = getattr(message, "content", [])
            if not isinstance(content, list):
                content = []
            for block in content[:256]:
                block_name = type(block).__name__
                if block_name == "TextBlock":
                    text = getattr(block, "text", "")
                    if isinstance(text, str):
                        emit("assistant.text", {"text": redact_text(text, 65_536)})
                elif block_name == "ToolUseBlock":
                    tool_input = getattr(block, "input", {})
                    input_keys = sorted(str(key) for key in tool_input)[:128] if isinstance(tool_input, dict) else []
                    emit(
                        "tool.requested",
                        {
                            "tool_use_id": redact_text(str(getattr(block, "id", "unknown")), 256),
                            "tool_name": redact_text(str(getattr(block, "name", "unknown")), 256),
                            "input_keys": input_keys,
                            "input_values_omitted": True,
                        },
                    )
                elif block_name == "ToolResultBlock":
                    emit(
                        "tool.result",
                        {
                            "tool_use_id": redact_text(str(getattr(block, "tool_use_id", "unknown")), 256),
                            "is_error": bool(getattr(block, "is_error", False)),
                            "content_omitted": True,
                        },
                    )
            return None
        if name == "ResultMessage":
            raw_result = getattr(message, "result", None)
            result_text = redact_text(raw_result, 262_144) if isinstance(raw_result, str) else None
            provider_session = getattr(message, "session_id", None)
            return {
                "provider_session_id": optional_identity(provider_session, "provider_session_id")
                if provider_session is not None
                else None,
                "result": result_text,
                "subtype": redact_text(str(getattr(message, "subtype", "unknown")), 128),
                "is_error": bool(getattr(message, "is_error", False)),
                "num_turns": getattr(message, "num_turns", None)
                if isinstance(getattr(message, "num_turns", None), int)
                else None,
                "total_cost_usd": getattr(message, "total_cost_usd", None)
                if isinstance(getattr(message, "total_cost_usd", None), (int, float))
                else None,
            }
        return None

    def run(
        self,
        request: dict[str, Any],
        emit: Callable[[str, dict[str, Any]], None],
        cancel_requested: threading.Event,
    ) -> dict[str, Any]:
        return asyncio.run(self._run_async(request, emit, cancel_requested))

    async def _run_async(
        self,
        request: dict[str, Any],
        emit: Callable[[str, dict[str, Any]], None],
        cancel_requested: threading.Event,
    ) -> dict[str, Any]:
        try:
            module = importlib.import_module("claude_agent_sdk")
        except ImportError as error:
            raise SidecarError("SDK_UNAVAILABLE", "claude-agent-sdk is not installed") from error
        client_type = getattr(module, "ClaudeSDKClient", None)
        if client_type is None:
            raise SidecarError("SDK_INCOMPATIBLE", "ClaudeSDKClient is unavailable")
        options = self._options(module, request)
        try:
            client = client_type(options=options)
        except Exception as error:
            raise SidecarError("SDK_INCOMPATIBLE", "ClaudeSDKClient construction failed") from error
        loop = asyncio.get_running_loop()
        attempt_id = request["attempt_id"]
        with self._lock:
            self._active[attempt_id] = (loop, client)
        result: dict[str, Any] | None = None
        try:
            await client.connect()
            await client.query(request["prompt"])
            async for message in client.receive_response():
                if cancel_requested.is_set():
                    try:
                        await client.interrupt()
                    except Exception:
                        pass
                projected = self._project_message(message, emit)
                if projected is not None:
                    result = projected
            if result is None:
                raise SidecarError("SDK_PROTOCOL", "provider stream ended without ResultMessage")
            return result
        except SidecarError:
            raise
        except Exception as error:
            emit("provider.error", {"error_type": type(error).__name__, "recoverable": False})
            raise SidecarError("PROVIDER_FAILURE", "Claude Agent SDK execution failed") from error
        finally:
            try:
                await client.disconnect()
            except Exception:
                pass
            with self._lock:
                self._active.pop(attempt_id, None)

    def interrupt(self, attempt_id: str) -> bool:
        with self._lock:
            active = self._active.get(attempt_id)
        if active is None:
            return False
        loop, client = active
        try:
            future = asyncio.run_coroutine_threadsafe(client.interrupt(), loop)
            future.result(timeout=CANCEL_SETTLE_SECONDS)
            return True
        except Exception:
            return False


@dataclass
class ActiveAttempt:
    request: dict[str, Any]
    cancel_requested: threading.Event = field(default_factory=threading.Event)
    terminal: threading.Event = field(default_factory=threading.Event)
    cleanup: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None
    terminal_kind: str | None = None


class SidecarController:
    """One-attempt controller with exact request replay and event ordering."""

    def __init__(self, facade: SdkFacade | None = None, writer: Callable[[dict[str, Any]], None] | None = None) -> None:
        self.facade = facade or RealClaudeSdkFacade()
        self.writer = writer or (lambda value: None)
        self._lock = threading.RLock()
        self._write_lock = threading.Lock()
        self._request_cache: dict[str, tuple[str, dict[str, Any]]] = {}
        self._active: ActiveAttempt | None = None
        self._sequence = 0
        self._shutdown = False

    def _write(self, value: dict[str, Any], maximum: int = MAX_EVENT_BYTES) -> None:
        document = bounded_document(value, maximum, "sidecar output")
        with self._write_lock:
            self.writer(document)

    def _event(self, attempt_id: str, kind: str, payload: dict[str, Any]) -> None:
        with self._lock:
            self._sequence += 1
            sequence = self._sequence
        event = {
            "schema_version": EVENT_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "event_id": f"claude:{attempt_id}:{sequence}",
            "sequence": sequence,
            "emitted_at_unix_ms": int(time.time() * 1000),
            "attempt_id": attempt_id,
            "event_kind": kind,
            "payload": redact_value(payload),
        }
        maximum = MAX_RESULT_BYTES if kind == "attempt.result" else MAX_EVENT_BYTES
        self._write(event, maximum)

    def _emit_error(self, request_id: str, error: SidecarError) -> dict[str, Any]:
        response = response_document(request_id, ok=False, error=error)
        self._write(response)
        return response

    def process(self, raw_request: dict[str, Any]) -> dict[str, Any]:
        request_id = str(raw_request.get("request_id") or "invalid-request")[:256]
        try:
            request = validate_request(raw_request)
            request_id = request["request_id"]
        except SidecarError as error:
            return self._emit_error(request_id, error)

        digest = request_digest(request)
        with self._lock:
            cached = self._request_cache.get(request_id)
            if cached is not None:
                cached_digest, cached_response = cached
                if cached_digest != digest:
                    return self._emit_error(
                        request_id,
                        SidecarError("IDENTITY_CONFLICT", "request_id was reused with different canonical bytes"),
                    )
                self._write(cached_response)
                return cached_response

        try:
            result, post_action = self._dispatch(request)
            response = response_document(request_id, ok=True, result=result)
        except SidecarError as error:
            response = response_document(request_id, ok=False, error=error)
            post_action = None

        with self._lock:
            self._request_cache[request_id] = (digest, response)
        self._write(response)
        if post_action is not None:
            post_action()
        return response

    def _dispatch(self, request: dict[str, Any]) -> tuple[dict[str, Any], Callable[[], None] | None]:
        kind = request["type"]
        if kind == "hello":
            return (
                {
                    "protocol_version": PROTOCOL_VERSION,
                    "requests": ["hello", "probe", "start", "cancel", "shutdown"],
                    "events": [
                        "attempt.started",
                        "assistant.text",
                        "tool.requested",
                        "tool.result",
                        "provider.error",
                        "attempt.result",
                        "attempt.cancelled",
                        "attempt.failed",
                        "attempt.cleanup",
                    ],
                    "one_active_attempt": True,
                    "native_subagents": False,
                    "ambient_settings": False,
                    "model_catalogue_supported": False,
                    "route_admitted": False,
                },
                None,
            )
        if kind == "probe":
            probe = bounded_document(self.facade.probe(), MAX_EVENT_BYTES, "SDK probe")
            probe.update(
                {
                    "protocol_version": PROTOCOL_VERSION,
                    "provider_execution": False,
                    "model_catalogue_supported": False,
                    "route_admitted": False,
                    "proof_ceiling": "FAKE_SDK_AND_PROTOCOL_BEHAVIOR_ONLY",
                }
            )
            return probe, None
        if kind == "start":
            return self._start(request)
        if kind == "cancel":
            return self._cancel(request), None
        if kind == "shutdown":
            return self._shutdown_request(), None
        raise SidecarError("UNKNOWN_REQUEST", "unsupported request")

    def _start(self, request: dict[str, Any]) -> tuple[dict[str, Any], Callable[[], None]]:
        with self._lock:
            if self._shutdown:
                raise SidecarError("SHUTTING_DOWN", "sidecar is shutting down")
            if self._active is not None and not self._active.cleanup.is_set():
                raise SidecarError("ACTIVE_ATTEMPT_EXISTS", "sidecar already owns an active attempt")
            active = ActiveAttempt(request=dict(request))
            thread = threading.Thread(
                target=self._run_attempt,
                args=(active,),
                name=f"eliot-claude-{request['attempt_id'][:48]}",
                daemon=True,
            )
            active.thread = thread
            self._active = active
        response = {
            "status": "accepted_candidate_attempt",
            "attempt_id": request["attempt_id"],
            "task_id": request["task_id"],
            "work_item_id": request["work_item_id"],
            "model": request["model"],
            "fallback_model": request.get("fallback_model"),
            "model_selection_receipt_ref": request["model_selection_receipt_ref"],
            "candidate_only": True,
            "authority": "none",
            "native_subagents": False,
            "setting_sources": [],
            "route_admitted": False,
        }
        return response, thread.start

    def _run_attempt(self, active: ActiveAttempt) -> None:
        request = active.request
        attempt_id = request["attempt_id"]
        self._event(
            attempt_id,
            "attempt.started",
            {
                "task_id": request["task_id"],
                "work_item_id": request["work_item_id"],
                "model": request["model"],
                "fallback_model": request.get("fallback_model"),
                "model_selection_receipt_ref": request["model_selection_receipt_ref"],
                "prompt_omitted": True,
                "native_subagents": False,
                "setting_sources": [],
                "profiles": {
                    "mcp": request.get("mcp_profile_ref"),
                    "skill": request.get("skill_profile_ref"),
                    "plugin": request.get("plugin_profile_ref"),
                },
            },
        )
        try:
            result = self.facade.run(
                request,
                lambda kind, payload: self._event(attempt_id, kind, payload),
                active.cancel_requested,
            )
            if active.cancel_requested.is_set():
                active.terminal_kind = "attempt.cancelled"
                self._event(
                    attempt_id,
                    "attempt.cancelled",
                    {
                        "provider_interrupt_requested": True,
                        "terminal_confirmation": "provider_stream_closed_after_cancel",
                        "candidate_result_admitted": False,
                    },
                )
            else:
                active.terminal_kind = "attempt.result"
                self._event(
                    attempt_id,
                    "attempt.result",
                    {
                        "result": bounded_document(result, MAX_RESULT_BYTES // 2, "candidate result"),
                        "candidate_only": True,
                        "authority": "none",
                        "task_complete": False,
                        "route_admitted": False,
                    },
                )
        except SidecarError as error:
            active.terminal_kind = "attempt.failed"
            self._event(
                attempt_id,
                "attempt.failed",
                {
                    "code": error.code,
                    "message": error.message,
                    "candidate_result_admitted": False,
                },
            )
        except Exception as error:
            active.terminal_kind = "attempt.failed"
            self._event(
                attempt_id,
                "attempt.failed",
                {
                    "code": "UNEXPECTED_FAILURE",
                    "message": "sidecar execution failed",
                    "error_type": type(error).__name__,
                    "candidate_result_admitted": False,
                },
            )
        finally:
            active.terminal.set()
            self._event(
                attempt_id,
                "attempt.cleanup",
                {
                    "provider_client_closed": True,
                    "native_descendants_admitted": 0,
                    "terminal_kind": active.terminal_kind,
                    "cleanup_complete": True,
                },
            )
            active.cleanup.set()

    def _cancel(self, request: dict[str, Any]) -> dict[str, Any]:
        attempt_id = request["attempt_id"]
        with self._lock:
            active = self._active
        if active is None or active.request["attempt_id"] != attempt_id:
            raise SidecarError("ATTEMPT_NOT_FOUND", "cancel target is not the active attempt")
        active.cancel_requested.set()
        interrupt_confirmed = self.facade.interrupt(attempt_id)
        terminal = active.terminal.wait(CANCEL_SETTLE_SECONDS)
        cleanup = active.cleanup.wait(CANCEL_SETTLE_SECONDS)
        if not terminal or not cleanup:
            raise SidecarError("CANCEL_OUTCOME_UNKNOWN", "provider cancellation did not reconcile before timeout")
        return {
            "attempt_id": attempt_id,
            "interrupt_confirmed": interrupt_confirmed,
            "terminal_confirmed": terminal,
            "cleanup_confirmed": cleanup,
            "terminal_kind": active.terminal_kind,
            "unknown_live_descendants": False,
        }

    def _shutdown_request(self) -> dict[str, Any]:
        with self._lock:
            self._shutdown = True
            active = self._active
        if active is not None and not active.cleanup.is_set():
            active.cancel_requested.set()
            self.facade.interrupt(active.request["attempt_id"])
            if not active.cleanup.wait(SHUTDOWN_SETTLE_SECONDS):
                raise SidecarError("SHUTDOWN_OUTCOME_UNKNOWN", "active attempt cleanup was not confirmed")
        return {
            "status": "shutdown_complete",
            "active_attempt_closed": active is None or active.cleanup.is_set(),
            "unknown_live_descendants": False,
        }


class LockedStdoutWriter:
    def __init__(self) -> None:
        self._lock = threading.Lock()

    def __call__(self, value: dict[str, Any]) -> None:
        encoded = canonical_json_bytes(value)
        if len(encoded) > MAX_RESULT_BYTES:
            raise SidecarError("OUTPUT_BOUND_EXCEEDED", "stdio frame exceeded its bound")
        with self._lock:
            sys.stdout.buffer.write(encoded + b"\n")
            sys.stdout.buffer.flush()


def serve_stdio(facade: SdkFacade | None = None) -> int:
    writer = LockedStdoutWriter()
    controller = SidecarController(facade=facade, writer=writer)
    while True:
        frame = sys.stdin.buffer.readline(MAX_FRAME_BYTES + 2)
        if not frame:
            return 0
        if len(frame) > MAX_FRAME_BYTES or not frame.endswith(b"\n"):
            writer(
                response_document(
                    "invalid-request",
                    ok=False,
                    error=SidecarError("FRAME_BOUND_EXCEEDED", "stdin frame exceeded its bound"),
                )
            )
            return 2
        try:
            request = parse_request_bytes(frame[:-1])
        except SidecarError as error:
            writer(response_document("invalid-request", ok=False, error=error))
            continue
        response = controller.process(request)
        if request.get("type") == "shutdown" and response.get("ok") is True:
            return 0


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--probe"]:
        value = RealClaudeSdkFacade().probe()
        value.update(
            {
                "protocol_version": PROTOCOL_VERSION,
                "provider_execution": False,
                "model_catalogue_supported": False,
                "route_admitted": False,
                "proof_ceiling": "ZERO_MODEL_SDK_PACKAGE_PROBE_ONLY",
            }
        )
        print(json.dumps(bounded_document(value, MAX_EVENT_BYTES, "probe"), sort_keys=True))
        return 0
    if arguments:
        print("usage: eliot_claude_sidecar.py [--probe]", file=sys.stderr)
        return 2
    return serve_stdio()


if __name__ == "__main__":
    raise SystemExit(main())
