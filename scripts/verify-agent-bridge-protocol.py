#!/usr/bin/env python3
"""Verify the public ELIOT agent-bridge host-request boundary.

This is a deterministic source-policy check. It prevents regression to
caller-supplied canonical Frame/RequestIdentity ingress and verifies the
current typed invoke/cancel correlation boundary. It does not prove a live
Kernel endpoint, runtime forwarding, canonical effects, or Product support.
"""

from __future__ import annotations

import argparse
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

MAIN_PATH = "bins/eliot-agent-bridge/src/main.rs"
CORE_PATH = "crates/surfaces/eliot-agent-bridge-core/src/lib.rs"
BRIDGE_LIB_PATH = "bins/eliot-agent-bridge/src/lib.rs"
HOST_PATH = "crates/surfaces/eliot-mcp/src/host.rs"
GATEWAY_PATH = "crates/surfaces/eliot-mcp/src/host_gateway.rs"

FORBIDDEN_HOST_FIELDS = (
    "request_identity",
    "principal",
    "session_binding",
    "task_id",
    "work_scope",
    "state_fence",
    "authority_epoch",
    "idempotency_key",
    "cancellation_id",
    "deadline_unix_ms",
    "effect_ceiling",
)


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    detail: str


def read_text(root: Path, relative: str, findings: list[Finding]) -> str | None:
    path = root / relative
    if not path.is_file():
        findings.append(Finding("required_file_missing", relative, "required protocol source is absent"))
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        findings.append(Finding("required_file_unreadable", relative, str(error)))
        return None


def production_prefix(text: str) -> str:
    marker = "#[cfg(test)]"
    position = text.find(marker)
    return text if position < 0 else text[:position]


def strip_cfg_test_gated(text: str) -> str:
    """Remove only #[cfg(test)]-gated items, preserving later production code.

    #342: bins/eliot-agent-bridge/src/main.rs:12-13 is a test-only import
    before the production enum Request (:39-69) and production
    HostRequestGateway uses (:14-17, :188, :410, :421). Cutting at the first
    marker hides production and is stale. Like BRIDGE_LIB_PATH owner-block
    inspection below, strip only gated items instead of truncating.
    See also PR #1273 (real port cutover since 666526cf), PR #1248, and
    workstreams/surfaces/assignments/077-agent-bridge-kernel-port.toml:24,51.
    """
    marker = "#[cfg(test)]"
    output_parts: list[str] = []
    cursor = 0
    while True:
        marker_start = text.find(marker, cursor)
        if marker_start < 0:
            output_parts.append(text[cursor:])
            break
        output_parts.append(text[cursor:marker_start])
        scan = marker_start + len(marker)
        while scan < len(text) and text[scan] in " \t\r\n":
            scan += 1
        while text.startswith("#[", scan):
            close = text.find("]", scan + 2)
            if close < 0:
                break
            scan = close + 1
            while scan < len(text) and text[scan] in " \t\r\n":
                scan += 1
        semi = text.find(";", scan)
        brace = text.find("{", scan)
        if brace < 0 or (semi >= 0 and semi < brace):
            if semi < 0:
                cursor = len(text)
            else:
                cursor = semi + 1
        else:
            depth = 0
            in_string = False
            string_quote = ""
            escaped = False
            line_comment = False
            block_comment_depth = 0
            index = brace
            end = -1
            while index < len(text):
                char = text[index]
                nxt = text[index + 1] if index + 1 < len(text) else ""
                if line_comment:
                    if char == "\n":
                        line_comment = False
                    index += 1
                    continue
                if block_comment_depth:
                    if char == "/" and nxt == "*":
                        block_comment_depth += 1
                        index += 2
                        continue
                    if char == "*" and nxt == "/":
                        block_comment_depth -= 1
                        index += 2
                        continue
                    index += 1
                    continue
                if in_string:
                    if escaped:
                        escaped = False
                    elif char == "\\":
                        escaped = True
                    elif char == string_quote:
                        in_string = False
                    index += 1
                    continue
                if char == "/" and nxt == "/":
                    line_comment = True
                    index += 2
                    continue
                if char == "/" and nxt == "*":
                    block_comment_depth = 1
                    index += 2
                    continue
                if char in ('"', "'"):
                    in_string = True
                    string_quote = char
                    index += 1
                    continue
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        end = index + 1
                        break
                index += 1
            if end < 0:
                cursor = len(text)
            else:
                cursor = end
    return "".join(output_parts)


def is_directly_cfg_test_gated(text: str, marker: str) -> bool:
    """Check whether marker is directly gated by #[cfg(test)].

    Looks only at attribute lines immediately preceding the marker, stopping
    at the first non-attribute code line. Prevents a previous item's gate
    (e.g. the struct's gate) from masking an ungated impl.
    Cited for #342 test-only Unavailable port (main.rs:117,121).
    """
    pos = text.find(marker)
    if pos < 0:
        return False
    window_start = max(0, pos - 800)
    snippet = text[window_start:pos]
    lines = snippet.splitlines()
    for line in reversed(lines):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#["):
            if "cfg(test)" in stripped.replace(" ", ""):
                return True
            continue
        if stripped.startswith("///") or stripped.startswith("//"):
            continue
        # First non-attribute code line stops the attached-attribute scan.
        return False
    return False


def extract_braced_block(text: str, marker: str) -> str | None:
    start = text.find(marker)
    if start < 0:
        return None
    opening = text.find("{", start + len(marker))
    if opening < 0:
        return None
    depth = 0
    in_string = False
    string_quote = ""
    escaped = False
    line_comment = False
    block_comment_depth = 0
    index = opening
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""

        if line_comment:
            if char == "\n":
                line_comment = False
            index += 1
            continue
        if block_comment_depth:
            if char == "/" and nxt == "*":
                block_comment_depth += 1
                index += 2
                continue
            if char == "*" and nxt == "/":
                block_comment_depth -= 1
                index += 2
                continue
            index += 1
            continue
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == string_quote:
                in_string = False
            index += 1
            continue
        if char == "/" and nxt == "/":
            line_comment = True
            index += 2
            continue
        if char == "/" and nxt == "*":
            block_comment_depth = 1
            index += 2
            continue
        if char in ('"', "'"):
            in_string = True
            string_quote = char
            index += 1
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
        index += 1
    return None


def attribute_prefix(text: str, marker: str, width: int = 640) -> str:
    start = text.find(marker)
    if start < 0:
        return ""
    previous_block_end = text.rfind("}", 0, start)
    lower_bound = max(0, start - width, previous_block_end + 1)
    return text[lower_bound:start]


def require_contains(
    findings: list[Finding], path: str, text: str, needle: str, code: str, detail: str
) -> None:
    if needle not in text:
        findings.append(Finding(code, path, detail))


def verify(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    main_text = read_text(root, MAIN_PATH, findings)
    core_text = read_text(root, CORE_PATH, findings)
    bridge_lib_text = read_text(root, BRIDGE_LIB_PATH, findings)
    host_text = read_text(root, HOST_PATH, findings)
    gateway_text = read_text(root, GATEWAY_PATH, findings)
    if (
        main_text is None
        or core_text is None
        or bridge_lib_text is None
        or host_text is None
        or gateway_text is None
    ):
        return sorted(findings, key=lambda item: (item.path, item.code, item.detail))

    # #342 MAIN prefix fix: main.rs:12-13 is a test-only import before the
    # production enum Request (:39-69) and production HostRequestGateway uses
    # (:14-17, :188, :410, :421). Truncating at the first #[cfg(test)] hides
    # production. Strip only gated items instead, mirroring the BRIDGE_LIB_PATH
    # owner-block approach below. See also PR #1273, PR #1248, and
    # workstreams/surfaces/assignments/077-agent-bridge-kernel-port.toml:24,51.
    main_prod = strip_cfg_test_gated(main_text)
    request_block = extract_braced_block(main_prod, "enum Request")
    if request_block is None:
        findings.append(Finding("public_request_enum_missing", MAIN_PATH, "enum Request cannot be resolved"))
    else:
        # #342: production enum Request (:39-69) spells Invoke/Cancel across
        # multiple lines (e.g. `Invoke {\n request: HostInvocationRequest,\n }`).
        # Match whitespace-tolerantly without weakening the typed shape.
        # See also PR #1273, PR #1248.
        if not re.search(
            r"Invoke\s*\{\s*request\s*:\s*HostInvocationRequest\s*,?\s*\}", request_block
        ):
            findings.append(
                Finding(
                    "typed_invoke_missing",
                    MAIN_PATH,
                    "public stdin protocol must expose typed Invoke",
                )
            )
        if not re.search(
            r"Cancel\s*\{\s*request\s*:\s*HostCancellationRequest\s*,?\s*\}", request_block
        ):
            findings.append(
                Finding(
                    "typed_cancel_missing",
                    MAIN_PATH,
                    "public stdin protocol must expose typed Cancel",
                )
            )
        if "ForwardFrame" in request_block or "forward_frame" in request_block:
            findings.append(
                Finding(
                    "raw_frame_ingress",
                    MAIN_PATH,
                    "public request enum must not expose raw canonical Frame forwarding",
                )
            )
        enum_attrs = attribute_prefix(main_prod, "enum Request")
        if "deny_unknown_fields" not in enum_attrs:
            findings.append(
                Finding(
                    "strict_serde_missing",
                    MAIN_PATH,
                    "public request enum must reject unknown fields",
                )
            )

    # EventEnvelope is allowed; the canonical Frame type is not public ingress.
    if re.search(r"\bFrame\b", main_prod):
        findings.append(
            Finding(
                "raw_frame_type_imported",
                MAIN_PATH,
                "production public bridge source must not import or name canonical Frame",
            )
        )

    core_prod = production_prefix(core_text)
    if "forward_frame" in core_prod:
        findings.append(
            Finding(
                "internal_raw_frame_forwarding_api",
                CORE_PATH,
                "bridge core must not expose raw Frame forwarding",
            )
        )
    if re.search(r"\bFrame\b", core_prod):
        findings.append(
            Finding(
                "internal_raw_frame_type_surface",
                CORE_PATH,
                "bridge core must not expose the canonical Frame type",
            )
        )

    # The bridge library has cfg(test) imports before production impls, so
    # inspect only the named production owner blocks below instead of cutting
    # at the first test attribute.
    bridge_lib_prod = bridge_lib_text
    for marker, label in (
        (
            "impl McpForwardingPort for KernelMcpForwardingPort",
            "KernelMcpForwardingPort",
        ),
        ("impl BridgeRunner", "BridgeRunner"),
    ):
        owner_block = extract_braced_block(bridge_lib_prod, marker)
        if owner_block is None:
            findings.append(
                Finding(
                    "internal_owner_surface_unresolved",
                    BRIDGE_LIB_PATH,
                    f"{label} raw-forwarding owner surface cannot be resolved",
                )
            )
        elif re.search(r"\bFrame\b|\bforward_frame\b", owner_block):
            findings.append(
                Finding(
                    "internal_raw_frame_forwarding_api",
                    BRIDGE_LIB_PATH,
                    f"{label} must not expose raw Frame forwarding",
                )
            )

    require_contains(
        findings,
        MAIN_PATH,
        main_prod,
        "HostRequestGateway",
        "host_gateway_missing",
        "typed ingress must use HostRequestGateway",
    )
    # #342 / #1273 real-port cutover: production composes the real
    # KernelHostRequestClient via kernel_ports_with_declaration
    # (main.rs:168-175 -> bins/eliot-agent-bridge/src/lib.rs:176-275 ->
    # kernel_host_request_client.rs:593 impl KernelHostRequestPort for
    # KernelHostRequestClient, merged #1273, cutover 666526cf).
    # Production already composes real KernelHostRequestClient since 666526cf
    # (PR #1273 MERGED body). See also PR #1248 and
    # workstreams/surfaces/assignments/077-agent-bridge-kernel-port.toml:24,51.
    require_contains(
        findings,
        MAIN_PATH,
        main_prod,
        "kernel_ports_with_declaration",
        "production_kernel_port_missing",
        "production must compose the real Kernel port via kernel_ports_with_declaration",
    )
    require_contains(
        findings,
        BRIDGE_LIB_PATH,
        bridge_lib_text,
        "kernel_ports_with_declaration",
        "production_kernel_port_missing",
        "bridge library must expose kernel_ports_with_declaration composing the real port",
    )
    require_contains(
        findings,
        BRIDGE_LIB_PATH,
        bridge_lib_text,
        "KernelHostRequestClient",
        "real_kernel_port_missing",
        "bridge library must compose the real KernelHostRequestClient (cutover 666526cf)",
    )
    # UnavailableKernelHostRequestPort is a #[cfg(test)]-only fixture
    # (main.rs:117,121, returns Err PortFailure::PlanGap, never fabricates
    # success). Expect it gated, absent from stripped production, with typed
    # PlanGap and no fabricated success. See #342, PR #1273, PR #1248, and
    # workstreams/surfaces/assignments/077-agent-bridge-kernel-port.toml:24,51.
    if "impl KernelHostRequestPort for UnavailableKernelHostRequestPort" not in main_text:
        findings.append(
            Finding(
                "unavailable_kernel_port_missing",
                MAIN_PATH,
                "test-only Kernel gap fixture must remain as #[cfg(test)]-gated typed port",
            )
        )
        unavailable_block = None
    else:
        if not is_directly_cfg_test_gated(
            main_text, "impl KernelHostRequestPort for UnavailableKernelHostRequestPort"
        ):
            findings.append(
                Finding(
                    "unavailable_kernel_port_not_test_only",
                    MAIN_PATH,
                    "UnavailableKernelHostRequestPort impl must remain #[cfg(test)]-only "
                    "(production uses KernelHostRequestClient)",
                )
            )
        if "UnavailableKernelHostRequestPort" in main_prod:
            findings.append(
                Finding(
                    "unavailable_kernel_port_in_production",
                    MAIN_PATH,
                    "UnavailableKernelHostRequestPort must not appear in production "
                    "(strip test gates); production uses kernel_ports_with_declaration",
                )
            )
        unavailable_block = extract_braced_block(
            main_text, "impl KernelHostRequestPort for UnavailableKernelHostRequestPort"
        )
        if unavailable_block is None:
            findings.append(
                Finding(
                    "unavailable_kernel_port_unresolved",
                    MAIN_PATH,
                    "typed unavailable Kernel port implementation cannot be resolved",
                )
            )
    if unavailable_block is not None:
        if "PortFailure::PlanGap" not in unavailable_block:
            findings.append(
                Finding(
                    "typed_plan_gap_missing",
                    MAIN_PATH,
                    "unavailable Kernel binding must return typed PlanGap",
                )
            )
        if re.search(
            r"Host(?:Invocation|Cancellation)PortOutcome::(?:Accepted|Responded)",
            unavailable_block,
        ):
            findings.append(
                Finding(
                    "fabricated_kernel_success",
                    MAIN_PATH,
                    "unavailable port must not fabricate accepted/responded outcomes",
                )
            )

    invocation_block = extract_braced_block(host_text, "pub struct HostInvocationRequest")
    cancellation_block = extract_braced_block(host_text, "pub struct HostCancellationRequest")
    for marker, block, label in (
        ("pub struct HostInvocationRequest", invocation_block, "HostInvocationRequest"),
        ("pub struct HostCancellationRequest", cancellation_block, "HostCancellationRequest"),
    ):
        if block is None:
            findings.append(
                Finding("host_contract_missing", HOST_PATH, f"{label} cannot be resolved")
            )
            continue
        if "deny_unknown_fields" not in attribute_prefix(host_text, marker):
            findings.append(
                Finding(
                    "strict_serde_missing",
                    HOST_PATH,
                    f"{label} must reject unknown authority fields",
                )
            )
        lowered = block.lower()
        for field in FORBIDDEN_HOST_FIELDS:
            if re.search(rf"\bpub\s+{re.escape(field)}\s*:", lowered):
                findings.append(
                    Finding(
                        "host_authority_field",
                        HOST_PATH,
                        f"{label} exposes forbidden Kernel/Governor field {field}",
                    )
                )

    if invocation_block is not None:
        for field in (
            "protocol_version",
            "correlation_id",
            "client_capabilities",
            "tool",
            "deadline_preference_ms",
            "observed_context",
        ):
            if not re.search(rf"\bpub\s+{field}\s*:", invocation_block):
                findings.append(
                    Finding(
                        "host_invoke_field_missing",
                        HOST_PATH,
                        f"HostInvocationRequest is missing inert field {field}",
                    )
                )

    if cancellation_block is not None:
        for field in (
            "protocol_version",
            "correlation_id",
            "operation_handle",
            "deadline_preference_ms",
            "observed_context",
        ):
            if not re.search(rf"\bpub\s+{field}\s*:", cancellation_block):
                findings.append(
                    Finding(
                        "host_cancel_field_missing",
                        HOST_PATH,
                        f"HostCancellationRequest is missing inert field {field}",
                    )
                )
        if not re.search(r"\bpub\s+reason\s*:\s*Option\s*<\s*String\s*>", cancellation_block):
            findings.append(
                Finding(
                    "cancellation_reason_mandatory",
                    HOST_PATH,
                    "cancellation reason must remain optional",
                )
            )
        reason_position = cancellation_block.find("pub reason")
        reason_prefix = cancellation_block[max(0, reason_position - 160) : reason_position]
        if reason_position < 0 or "serde(default)" not in reason_prefix:
            findings.append(
                Finding(
                    "cancellation_reason_default_missing",
                    HOST_PATH,
                    "omitted cancellation prose must deserialize as None",
                )
            )

    # #342 / PR #1248 GATEWAY delegate fix: host_gateway.rs:305-312 is a thin
    # `pub fn invoke` delegate forwarding to invoke_with_receipt (:310-311).
    # Real logic lives in invoke_with_receipt :320-350: request.validate()?;
    # (:325) before port.invoke (:328), correlation_id capture (:326) before
    # dispatch, HostInvocationResult {correlation_id, outcome} (:344-347).
    # Resolve the invoke surface as combined delegate+impl (mirroring the
    # inlined fixture shape). See also PR #1273 and
    # workstreams/surfaces/assignments/077-agent-bridge-kernel-port.toml:24,51.
    # Cancel path already passes; its checks below are unchanged.
    invoke_delegate_block = extract_braced_block(
        gateway_text, "pub fn invoke<P: KernelHostRequestPort + ?Sized>"
    )
    invoke_impl_block = extract_braced_block(
        gateway_text, "pub fn invoke_with_receipt<P: KernelHostRequestPort + ?Sized>"
    )
    cancel_gateway = extract_braced_block(
        gateway_text, "pub fn cancel<P: KernelHostRequestPort + ?Sized>"
    )
    if invoke_delegate_block is None:
        findings.append(
            Finding("gateway_invoke_missing", GATEWAY_PATH, "gateway invoke function is absent")
        )
        invoke_gateway = None
    else:
        invoke_gateway = invoke_delegate_block + "\n" + (invoke_impl_block or "")
        validate_index = invoke_gateway.find("request.validate()?;")
        port_index = invoke_gateway.find("port.invoke(request)")
        correlation_index = invoke_gateway.find("request.correlation_id.clone()")
        if validate_index < 0 or port_index < 0 or validate_index > port_index:
            findings.append(
                Finding(
                    "validation_order",
                    GATEWAY_PATH,
                    "invoke must validate before calling the trusted port",
                )
            )
        if correlation_index < 0 or correlation_index > port_index:
            findings.append(
                Finding(
                    "correlation_not_preserved",
                    GATEWAY_PATH,
                    "invoke must capture caller correlation before provider dispatch",
                )
            )
        if "HostInvocationResult" not in invoke_gateway or "correlation_id" not in invoke_gateway:
            findings.append(
                Finding(
                    "correlated_result_missing",
                    GATEWAY_PATH,
                    "invoke result must restore caller correlation",
                )
            )

    if cancel_gateway is None:
        findings.append(
            Finding("gateway_cancel_missing", GATEWAY_PATH, "gateway cancel function is absent")
        )
    else:
        validate_index = cancel_gateway.find("request.validate()?;")
        port_index = cancel_gateway.find("port.cancel(request)")
        correlation_index = cancel_gateway.find("request.correlation_id.clone()")
        operation_index = cancel_gateway.find("request.operation_handle.clone()")
        if validate_index < 0 or port_index < 0 or validate_index > port_index:
            findings.append(
                Finding(
                    "validation_order",
                    GATEWAY_PATH,
                    "cancel must validate before calling the trusted port",
                )
            )
        if correlation_index < 0 or correlation_index > port_index:
            findings.append(
                Finding(
                    "correlation_not_preserved",
                    GATEWAY_PATH,
                    "cancel must capture caller correlation before provider dispatch",
                )
            )
        if operation_index < 0 or operation_index > port_index:
            findings.append(
                Finding(
                    "cancellation_target_not_preserved",
                    GATEWAY_PATH,
                    "cancel must capture the caller's exact operation handle before dispatch",
                )
            )
        if "HostCancellationResult" not in cancel_gateway or "operation_handle" not in cancel_gateway:
            findings.append(
                Finding(
                    "cancellation_result_target_missing",
                    GATEWAY_PATH,
                    "cancel result must echo the caller's exact operation handle",
                )
            )

    return sorted(findings, key=lambda item: (item.path, item.code, item.detail))


def print_findings(findings: list[Finding]) -> None:
    for finding in findings:
        print(f"HARD_VIOLATION: {finding.code}: {finding.path}: {finding.detail}")


def fixture_main() -> str:
    # Fixture mirrors production shape for #342: a #[cfg(test)]-only import
    # precedes production (main.rs:12-13 before enum Request :39-69), the
    # Unavailable port is #[cfg(test)]-only, and production composes the real
    # port via kernel_ports_with_declaration. See PR #1273, PR #1248, and
    # workstreams/surfaces/assignments/077-agent-bridge-kernel-port.toml:24,51.
    return '''#![forbid(unsafe_code)]
#[cfg(test)]
use eliot_mcp::{HostCancellationPortOutcome, HostInvocationPortOutcome, PortFailure};
use eliot_mcp::{HostCancellationRequest, HostInvocationRequest, HostRequestGateway,
    KernelHostRequestPort, PortFailure, HostInvocationPortOutcome,
    HostCancellationPortOutcome};
use eliot_agent_bridge::{kernel_ports_with_declaration, BridgeRunner};
use eliot_protocol::EventEnvelope;
#[derive(Debug)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Invoke { request: HostInvocationRequest },
    Cancel { request: HostCancellationRequest },
    ForwardEvent { event: EventEnvelope },
}
#[cfg(test)]
struct UnavailableKernelHostRequestPort;
#[cfg(test)]
impl KernelHostRequestPort for UnavailableKernelHostRequestPort {
    fn invoke(&mut self, _request: &HostInvocationRequest)
        -> Result<HostInvocationPortOutcome, PortFailure> {
        Err(PortFailure::PlanGap { missing_capability: "bind".into(), reason: "missing".into() })
    }
    fn cancel(&mut self, _request: &HostCancellationRequest)
        -> Result<HostCancellationPortOutcome, PortFailure> {
        Err(PortFailure::PlanGap { missing_capability: "cancel".into(), reason: "missing".into() })
    }
}
fn main() { let _gateway = HostRequestGateway; let _ = kernel_ports_with_declaration; }
#[cfg(test)]
mod tests {}
'''


def fixture_core() -> str:
    return '''
pub trait McpForwardingPort {
    fn forward_hook(&mut self);
}
pub struct AgentBridgeCore;
impl AgentBridgeCore {
    pub fn forward_event(&mut self) {}
}
'''


def fixture_bridge_lib() -> str:
    # Fixture mirrors production composition for #342/#1273: the real
    # KernelHostRequestClient composed via kernel_ports_with_declaration
    # (cutover 666526cf). See PR #1248 and
    # workstreams/surfaces/assignments/077-agent-bridge-kernel-port.toml:24,51.
    return '''
use kernel_host_request_client::KernelHostRequestClient;
pub fn kernel_ports_with_declaration() { let _ = KernelHostRequestClient; }
struct KernelMcpForwardingPort;
impl McpForwardingPort for KernelMcpForwardingPort {
    fn forward_hook(&mut self) {}
}
pub struct BridgeRunner;
impl BridgeRunner {
    pub fn forward_event(&mut self) {}
}
'''


def fixture_host() -> str:
    return '''
#[derive(Clone)]
#[serde(deny_unknown_fields)]
pub struct HostInvocationRequest {
    pub protocol_version: String,
    pub correlation_id: String,
    pub client_capabilities: String,
    pub tool: String,
    pub deadline_preference_ms: Option<u64>,
    pub observed_context: String,
}
#[derive(Clone)]
#[serde(deny_unknown_fields)]
pub struct HostCancellationRequest {
    pub protocol_version: String,
    pub correlation_id: String,
    pub operation_handle: String,
    #[serde(default)]
    pub reason: Option<String>,
    pub deadline_preference_ms: Option<u64>,
    pub observed_context: String,
}
'''


def fixture_gateway() -> str:
    # Fixture mirrors production delegate+impl shape for #342/PR #1248:
    # host_gateway.rs:305-312 thin `invoke` delegate forwarding to
    # invoke_with_receipt :320-350 which holds validate/port/correlation.
    # See also PR #1273 and
    # workstreams/surfaces/assignments/077-agent-bridge-kernel-port.toml:24,51.
    return '''
impl HostRequestGateway {
    pub fn invoke<P: KernelHostRequestPort + ?Sized>(
        &self, port: &mut P, request: &HostInvocationRequest,
    ) -> Result<HostInvocationResult, HostGatewayError> {
        self.invoke_with_receipt(port, request)
            .map(|paired| paired.0)
    }
    pub fn invoke_with_receipt<P: KernelHostRequestPort + ?Sized>(
        &self, port: &mut P, request: &HostInvocationRequest,
    ) -> Result<(HostInvocationResult, HostCorrelationReceipt), HostGatewayError> {
        request.validate()?;
        let correlation_id = request.correlation_id.clone();
        let outcome = match port.invoke(request) { _ => todo!() };
        Ok((HostInvocationResult { correlation_id, outcome }, todo!()))
    }
    pub fn cancel<P: KernelHostRequestPort + ?Sized>(
        &self, port: &mut P, request: &HostCancellationRequest,
    ) -> Result<HostCancellationResult, HostGatewayError> {
        request.validate()?;
        let correlation_id = request.correlation_id.clone();
        let operation_handle = request.operation_handle.clone();
        let outcome = match port.cancel(request) { _ => todo!() };
        Ok(HostCancellationResult { correlation_id, operation_handle, outcome })
    }
}
'''


def write_fixtures(root: Path) -> None:
    files = {
        MAIN_PATH: fixture_main(),
        CORE_PATH: fixture_core(),
        BRIDGE_LIB_PATH: fixture_bridge_lib(),
        HOST_PATH: fixture_host(),
        GATEWAY_PATH: fixture_gateway(),
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def assert_finding(root: Path, code: str, case: str) -> None:
    findings = verify(root)
    if not any(item.code == code for item in findings):
        raise AssertionError(f"{case} did not produce {code}: {findings}")


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="eliot-agent-bridge-policy-") as temp:
        root = Path(temp)
        write_fixtures(root)
        clean = verify(root)
        if clean:
            raise AssertionError(f"valid fixture failed: {clean}")

        main_path = root / MAIN_PATH
        host_path = root / HOST_PATH
        gateway_path = root / GATEWAY_PATH

        main_path.write_text(
            fixture_main().replace(
                "Cancel { request: HostCancellationRequest },",
                "Cancel { request: HostCancellationRequest },\n    ForwardFrame { frame: Frame },",
            ),
            encoding="utf-8",
        )
        assert_finding(root, "raw_frame_ingress", "raw Frame ingress")
        write_fixtures(root)

        core_path = root / CORE_PATH
        core_path.write_text(
            fixture_core().replace(
                "fn forward_hook(&mut self);",
                "fn forward_frame(&mut self, frame: &Frame);",
            ),
            encoding="utf-8",
        )
        assert_finding(root, "internal_raw_frame_forwarding_api", "core raw Frame forwarding")
        write_fixtures(root)

        bridge_lib_path = root / BRIDGE_LIB_PATH
        bridge_lib_path.write_text(
            fixture_bridge_lib().replace(
                "fn forward_hook(&mut self) {}",
                "fn forward_frame(&mut self, frame: &Frame) {}",
            ),
            encoding="utf-8",
        )
        assert_finding(root, "internal_raw_frame_forwarding_api", "wrapper raw Frame forwarding")
        write_fixtures(root)

        host_path.write_text(
            fixture_host().replace(
                "pub tool: String,", "pub tool: String,\n    pub request_identity: String,"
            ),
            encoding="utf-8",
        )
        assert_finding(root, "host_authority_field", "host authority field")
        write_fixtures(root)

        host_path.write_text(
            fixture_host().replace(
                "#[serde(deny_unknown_fields)]\npub struct HostCancellationRequest",
                "pub struct HostCancellationRequest",
            ),
            encoding="utf-8",
        )
        assert_finding(root, "strict_serde_missing", "missing strict Serde")
        write_fixtures(root)

        gateway_path.write_text(
            fixture_gateway().replace(
                "request.validate()?;\n        let correlation_id = request.correlation_id.clone();\n        let outcome = match port.invoke(request)",
                "let outcome = match port.invoke(request)\n            { _ => todo!() };\n        request.validate()?;\n        let correlation_id = request.correlation_id.clone();\n        let outcome = match port.invoke(request)",
            ),
            encoding="utf-8",
        )
        assert_finding(root, "validation_order", "validation after port call")
        write_fixtures(root)

        host_path.write_text(
            fixture_host().replace("pub reason: Option<String>,", "pub reason: String,"),
            encoding="utf-8",
        )
        assert_finding(root, "cancellation_reason_mandatory", "mandatory cancellation prose")

    print("AGENT_BRIDGE_PROTOCOL_SELF_TEST: PASS cases=8")


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
    findings = verify(args.root.resolve())
    if findings:
        print_findings(findings)
        return 1
    print("AGENT_BRIDGE_PROTOCOL_VERIFY: PASS files=5")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
