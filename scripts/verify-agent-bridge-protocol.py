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

    main_prod = production_prefix(main_text)
    request_block = extract_braced_block(main_prod, "enum Request")
    if request_block is None:
        findings.append(Finding("public_request_enum_missing", MAIN_PATH, "enum Request cannot be resolved"))
    else:
        require_contains(
            findings,
            MAIN_PATH,
            request_block,
            "Invoke { request: HostInvocationRequest }",
            "typed_invoke_missing",
            "public stdin protocol must expose typed Invoke",
        )
        require_contains(
            findings,
            MAIN_PATH,
            request_block,
            "Cancel { request: HostCancellationRequest }",
            "typed_cancel_missing",
            "public stdin protocol must expose typed Cancel",
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
    require_contains(
        findings,
        MAIN_PATH,
        main_prod,
        "impl KernelHostRequestPort for UnavailableKernelHostRequestPort",
        "unavailable_kernel_port_missing",
        "temporary Kernel gap must be represented by a typed port",
    )
    unavailable_block = extract_braced_block(
        main_prod, "impl KernelHostRequestPort for UnavailableKernelHostRequestPort"
    )
    if unavailable_block is None:
        findings.append(
            Finding(
                "unavailable_kernel_port_unresolved",
                MAIN_PATH,
                "typed unavailable Kernel port implementation cannot be resolved",
            )
        )
    else:
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

    invoke_gateway = extract_braced_block(
        gateway_text, "pub fn invoke<P: KernelHostRequestPort + ?Sized>"
    )
    cancel_gateway = extract_braced_block(
        gateway_text, "pub fn cancel<P: KernelHostRequestPort + ?Sized>"
    )
    if invoke_gateway is None:
        findings.append(
            Finding("gateway_invoke_missing", GATEWAY_PATH, "gateway invoke function is absent")
        )
    else:
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
    return '''#![forbid(unsafe_code)]
use eliot_mcp::{HostCancellationRequest, HostInvocationRequest, HostRequestGateway,
    KernelHostRequestPort, PortFailure, HostInvocationPortOutcome,
    HostCancellationPortOutcome};
use eliot_protocol::EventEnvelope;
#[derive(Debug)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Invoke { request: HostInvocationRequest },
    Cancel { request: HostCancellationRequest },
    ForwardEvent { event: EventEnvelope },
}
struct UnavailableKernelHostRequestPort;
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
fn main() { let _gateway = HostRequestGateway; }
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
    return '''
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
    return '''
impl HostRequestGateway {
    pub fn invoke<P: KernelHostRequestPort + ?Sized>(
        &self, port: &mut P, request: &HostInvocationRequest,
    ) -> Result<HostInvocationResult, HostGatewayError> {
        request.validate()?;
        let correlation_id = request.correlation_id.clone();
        let outcome = match port.invoke(request) { _ => todo!() };
        Ok(HostInvocationResult { correlation_id, outcome })
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
